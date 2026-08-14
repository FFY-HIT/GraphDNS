from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Iterable

from exp2.ablation import Method, evaluate_method
from exp2.model import Case, Record, Trace, normalize_domain


PathSignature = tuple[str, tuple[str, ...], str]
NodeRef = tuple[str, str, str]


@dataclass(frozen=True)
class RecordDelta:
    operation: str
    old: Record | None
    new: Record | None


@dataclass
class PaperRSG:
    """The explicit owner--RR-->rdata graph described in VeriDNS Section 3.1."""

    nodes: set[NodeRef] = field(default_factory=set)
    edges: list[tuple[NodeRef, str, NodeRef, str]] = field(default_factory=list)
    outgoing: dict[NodeRef, set[NodeRef]] = field(
        default_factory=lambda: defaultdict(set)
    )
    incoming: dict[NodeRef, set[NodeRef]] = field(
        default_factory=lambda: defaultdict(set)
    )

    @staticmethod
    def node(record: Record, value: str) -> NodeRef:
        return record.server, record.zone, normalize_domain(value)

    @classmethod
    def from_case(cls, case: Case) -> "PaperRSG":
        graph = cls()
        for record in case.records:
            src = cls.node(record, record.owner)
            if record.type in {"A", "AAAA"}:
                dst = (record.server, record.zone, record.value)
            else:
                dst = cls.node(record, record.value)
            graph.nodes.update((src, dst))
            graph.edges.append((src, record.type, dst, record.id))
            graph.outgoing[src].add(dst)
            graph.incoming[dst].add(src)
        return graph


def record_deltas(before: Case, after: Case) -> tuple[RecordDelta, ...]:
    before_by_id = {record.id: record for record in before.records}
    after_by_id = {record.id: record for record in after.records}
    deltas: list[RecordDelta] = []

    for record_id in sorted(before_by_id.keys() | after_by_id.keys()):
        old = before_by_id.get(record_id)
        new = after_by_id.get(record_id)
        if old is None:
            deltas.append(RecordDelta("ADD", None, new))
        elif new is None:
            deltas.append(RecordDelta("DELETE", old, None))
        elif old != new:
            deltas.append(RecordDelta("MODIFY", old, new))
    return tuple(deltas)


def _record_nodes(record: Record) -> tuple[NodeRef, NodeRef]:
    src = PaperRSG.node(record, record.owner)
    if record.type in {"A", "AAAA"}:
        dst = (record.server, record.zone, record.value)
    else:
        dst = PaperRSG.node(record, record.value)
    return src, dst


def paper_affected_nodes(
    before: Case,
    after: Case,
    deltas: Iterable[RecordDelta],
) -> set[NodeRef]:
    """Apply VeriDNS's delta-endpoint backward/forward impact traversal.

    The union of pre- and post-update explicit RSG edges is deliberately used.
    This is conservative for deletion and modification: predecessor paths that
    existed only before the change remain available to impact analysis.
    """

    old_graph = PaperRSG.from_case(before)
    new_graph = PaperRSG.from_case(after)
    outgoing: dict[NodeRef, set[NodeRef]] = defaultdict(set)
    incoming: dict[NodeRef, set[NodeRef]] = defaultdict(set)
    for graph in (old_graph, new_graph):
        for src, targets in graph.outgoing.items():
            outgoing[src].update(targets)
        for dst, sources in graph.incoming.items():
            incoming[dst].update(sources)

    seeds: set[NodeRef] = set()
    for delta in deltas:
        if delta.old is not None:
            seeds.update(_record_nodes(delta.old))
        if delta.new is not None:
            seeds.update(_record_nodes(delta.new))

    affected = set(seeds)
    queue = deque(seeds)
    while queue:
        node = queue.popleft()
        for neighbor in outgoing.get(node, set()) | incoming.get(node, set()):
            if neighbor not in affected:
                affected.add(neighbor)
                queue.append(neighbor)
    return affected


def _record_ids(path: tuple[str, ...]) -> set[str]:
    result: set[str] = set()
    for label in path:
        if ":" in label:
            result.add(label.rsplit(":", 1)[0])
    return result


def _paths_by_query(paths: set[PathSignature]) -> dict[str, set[PathSignature]]:
    grouped: dict[str, set[PathSignature]] = defaultdict(set)
    for path in paths:
        grouped[path[0]].add(path)
    return grouped


def veridns_full_paths(traces: tuple[Trace, ...]) -> set[PathSignature]:
    """Materialize the paper RSG without alpha/beta binding.

    Experiment 02's alpha-only quotient is a conservative realization of the
    RSG: states with the same DNS entity are merged and edge witnesses are not
    required to keep one symbolic assignment across the path.
    """

    _, result = evaluate_method(traces, Method.ALPHA_ONLY)
    return result.predicted


def veridns_static_graph(traces: tuple[Trace, ...]):
    return evaluate_method(traces, Method.ALPHA_ONLY)


def veridns_incremental_paths(
    before: Case,
    after: Case,
    before_paths: set[PathSignature],
    full_after_paths: set[PathSignature],
) -> tuple[set[PathSignature], set[str], set[NodeRef]]:
    """Revalidate only queries connected to the paper's explicit affected RSG.

    Revalidated queries are evaluated against the complete post-update RSG.
    This is more generous than restricting DFS to the affected subgraph, so a
    remaining mismatch is caused by missing dependency discovery rather than
    by an artificially narrow traversal implementation.
    """

    deltas = record_deltas(before, after)
    affected_nodes = paper_affected_nodes(before, after, deltas)
    before_records = {record.id: record for record in before.records}
    before_by_query = _paths_by_query(before_paths)
    after_by_query = _paths_by_query(full_after_paths)
    affected_queries: set[str] = set()

    for query, paths in before_by_query.items():
        query_refs = {
            (before.start_server, before.start_zone, normalize_domain(query))
        }
        if query_refs & affected_nodes:
            affected_queries.add(query)
            continue
        for path in paths:
            for record_id in _record_ids(path[1]):
                record = before_records.get(record_id)
                if record is None:
                    continue
                if set(_record_nodes(record)) & affected_nodes:
                    affected_queries.add(query)
                    break
            if query in affected_queries:
                break

    incremental: set[PathSignature] = set()
    all_queries = before_by_query.keys() | after_by_query.keys()
    for query in all_queries:
        source = after_by_query if query in affected_queries else before_by_query
        incremental.update(source.get(query, set()))
    return incremental, affected_queries, affected_nodes
