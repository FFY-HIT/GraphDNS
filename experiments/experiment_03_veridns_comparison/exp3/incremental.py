from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from exp2.ablation import Method, evaluate_method
from exp2.model import (
    Case,
    Record,
    Trace,
    is_descendant_or_same,
    is_strict_descendant,
    normalize_domain,
)

from .veridns import PathSignature, record_deltas


@dataclass
class IncrementalComparison:
    method: str
    pair_id: str
    total_queries: int
    affected_queries: set[str]
    incremental_paths: set[PathSignature]
    full_paths: set[PathSignature]

    @property
    def stale_paths(self) -> set[PathSignature]:
        return self.incremental_paths - self.full_paths

    @property
    def missed_paths(self) -> set[PathSignature]:
        return self.full_paths - self.incremental_paths

    @property
    def consistent(self) -> bool:
        return not self.stale_paths and not self.missed_paths


def graphdns_full_paths(traces: tuple[Trace, ...]) -> set[PathSignature]:
    _, result = evaluate_method(traces, Method.FULL)
    return result.predicted


def graphdns_static_graph(traces: tuple[Trace, ...]):
    return evaluate_method(traces, Method.FULL)


def _paths_by_query(paths: set[PathSignature]) -> dict[str, set[PathSignature]]:
    grouped: dict[str, set[PathSignature]] = defaultdict(set)
    for path in paths:
        grouped[path[0]].add(path)
    return grouped


def _is_immediate_wildcard_match(query: str, owner: str) -> bool:
    owner = normalize_domain(owner)
    if not owner.startswith("*."):
        return False
    suffix = owner[2:]
    query = normalize_domain(query)
    if not is_strict_descendant(query, suffix):
        return False
    query_labels = [label for label in query.split(".") if label]
    suffix_labels = [label for label in suffix.split(".") if label]
    return len(query_labels) == len(suffix_labels) + 1


def _record_can_change_selection(record: Record, query: str) -> bool:
    query = normalize_domain(query)
    owner = normalize_domain(record.owner)
    if record.type == "DNAME":
        return is_strict_descendant(query, owner)
    if record.type == "NS" and owner != normalize_domain(record.zone):
        return is_descendant_or_same(query, owner)
    if owner.startswith("*."):
        return _is_immediate_wildcard_match(query, owner)
    return query == owner


def graphdns_affected_queries(
    before: Case,
    before_traces: tuple[Trace, ...],
    after: Case,
) -> set[str]:
    """Collect the finite queries touched by GraphDNS semantic dependencies.

    The collector mirrors the production design at the experiment's finite
    query boundary: exact/wildcard coverage, DNAME suffix coverage, delegation
    cuts, and changed forward records are all dependencies, even when no
    explicit owner--rdata RSG edge connects them.
    """

    deltas = record_deltas(before, after)
    changed_records = [
        record
        for delta in deltas
        for record in (delta.old, delta.new)
        if record is not None
    ]
    changed_ids = {record.id for record in changed_records}
    affected: set[str] = set()

    for trace in before_traces:
        query = trace.query.name
        if any(event.record_id in changed_ids for event in trace.events):
            affected.add(query)
            continue
        state_queries = {state.query for state in trace.states if state.query}
        if any(
            _record_can_change_selection(record, state_query)
            for record in changed_records
            for state_query in state_queries
        ):
            affected.add(query)
            continue
        # A changed rewrite target can alter a semantic successor selected by a
        # pre-existing forward record even if the target is not an RR owner.
        if any(
            record.type in {"CNAME", "DNAME", "NS"}
            and any(
                is_descendant_or_same(state_query, record.value)
                or is_descendant_or_same(record.value, state_query)
                for state_query in state_queries
            )
            for record in changed_records
        ):
            affected.add(query)
    return affected


def graphdns_incremental_paths(
    before: Case,
    after: Case,
    before_traces: tuple[Trace, ...],
    before_paths: set[PathSignature],
    full_after_paths: set[PathSignature],
) -> tuple[set[PathSignature], set[str]]:
    affected = graphdns_affected_queries(before, before_traces, after)
    before_by_query = _paths_by_query(before_paths)
    after_by_query = _paths_by_query(full_after_paths)
    incremental: set[PathSignature] = set()

    for query in before_by_query.keys() | after_by_query.keys():
        source = after_by_query if query in affected else before_by_query
        incremental.update(source.get(query, set()))
    return incremental, affected
