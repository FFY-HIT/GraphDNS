from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

from .model import Trace, TraceEvent, TraceState, is_strict_descendant, normalize_domain


class Method(str, Enum):
    CONCRETE = "Concrete"
    ALPHA_ONLY = "alpha-only"
    ALPHA_BETA_UNBOUND = "alpha+beta, no binding"
    FULL = "Full GraphDNS"


@dataclass(frozen=True)
class NodeKey:
    server: str
    zone: str
    kind: str
    name: str


@dataclass
class AbstractNode:
    id: int
    key: NodeKey
    terminal: bool = False
    outcome: str = ""


@dataclass(frozen=True)
class Witness:
    alpha_binding: str
    beta_binding: str | None
    before_query: str
    after_query: str


@dataclass
class AbstractEdge:
    id: int
    src: int
    dst: int
    label: str
    action: str
    owner: str
    target: str
    witnesses: set[Witness] = field(default_factory=set)


@dataclass
class AbstractGraph:
    method: Method
    nodes: list[AbstractNode] = field(default_factory=list)
    edges: list[AbstractEdge] = field(default_factory=list)
    outgoing: dict[int, list[int]] = field(default_factory=lambda: defaultdict(list))
    start_by_query: dict[str, int] = field(default_factory=dict)


@dataclass
class MethodResult:
    method: Method
    node_count: int
    edge_count: int
    predicted: set[tuple[str, tuple[str, ...], str]]
    true_positive: int
    false_positive: int
    false_negative: int

    @property
    def precision(self) -> float:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else 1.0

    @property
    def recall(self) -> float:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else 1.0


def _node_key(state: TraceState, method: Method) -> NodeKey:
    if method == Method.CONCRETE:
        name = state.outcome + "|" + state.query if state.terminal else state.query
        return NodeKey(state.server, state.zone, state.kind, name)

    if state.terminal:
        return NodeKey(state.server, state.zone, "terminal", state.outcome)

    kind = state.kind
    if method == Method.ALPHA_ONLY and kind in {"alpha", "beta"}:
        kind = "alpha"
    name = state.query if kind == "concrete" else state.suffix
    return NodeKey(state.server, state.zone, kind, name)


def build_graph(traces: tuple[Trace, ...], method: Method) -> AbstractGraph:
    graph = AbstractGraph(method=method)
    node_ids: dict[NodeKey, int] = {}
    edge_ids: dict[tuple[int, int, str, str], int] = {}

    def ensure_node(state: TraceState) -> int:
        key = _node_key(state, method)
        existing = node_ids.get(key)
        if existing is not None:
            return existing
        node_id = len(graph.nodes)
        node_ids[key] = node_id
        graph.nodes.append(
            AbstractNode(
                id=node_id,
                key=key,
                terminal=state.terminal,
                outcome=state.outcome,
            )
        )
        return node_id

    for trace in traces:
        if len(trace.states) != len(trace.events) + 1:
            raise ValueError(f"malformed trace for {trace.query.name}")
        state_ids = [ensure_node(state) for state in trace.states]
        graph.start_by_query[trace.query.name] = state_ids[0]

        for index, event in enumerate(trace.events):
            src = state_ids[index]
            dst = state_ids[index + 1]
            key = (src, dst, event.label, event.action)
            edge_id = edge_ids.get(key)
            if edge_id is None:
                edge_id = len(graph.edges)
                edge_ids[key] = edge_id
                graph.edges.append(
                    AbstractEdge(
                        id=edge_id,
                        src=src,
                        dst=dst,
                        label=event.label,
                        action=event.action,
                        owner=event.owner,
                        target=event.target,
                    )
                )
                graph.outgoing[src].append(edge_id)
            graph.edges[edge_id].witnesses.add(
                Witness(
                    alpha_binding=trace.query.alpha_binding,
                    beta_binding=trace.states[index].beta_binding,
                    before_query=event.before_query,
                    after_query=event.after_query,
                )
            )

    return graph


def _unbound_next_query(
    graph: AbstractGraph,
    edge: AbstractEdge,
    current_query: str,
) -> str | None:
    src = graph.nodes[edge.src]
    if graph.method == Method.ALPHA_BETA_UNBOUND and src.key.kind == "beta":
        if not is_strict_descendant(current_query, src.key.name):
            return None

    if edge.action == "CNAME":
        return normalize_domain(edge.target)
    if edge.action == "DNAME":
        if (
            graph.method == Method.ALPHA_BETA_UNBOUND
            and not is_strict_descendant(current_query, edge.owner)
        ):
            return None
        # The unbound variants retain the local beta/non-empty rule but select
        # an arbitrary edge witness instead of preserving one binding across
        # the complete path.
        return min(witness.after_query for witness in edge.witnesses)
    return current_query


def enumerate_paths(
    graph: AbstractGraph,
    traces: tuple[Trace, ...],
    max_steps: int = 24,
) -> set[tuple[str, tuple[str, ...], str]]:
    predicted: set[tuple[str, tuple[str, ...], str]] = set()

    for trace in traces:
        query = trace.query
        start = graph.start_by_query[query.name]
        # node, current q, beta binding, labels, used edges
        stack: list[tuple[int, str, str | None, tuple[str, ...], frozenset[int]]] = [
            (start, query.name, None, tuple(), frozenset())
        ]

        while stack:
            node_id, current_q, beta_binding, labels, used = stack.pop()
            node = graph.nodes[node_id]
            if node.terminal:
                predicted.add((query.name, labels, node.outcome))
                continue
            if len(labels) >= max_steps:
                continue

            for edge_id in graph.outgoing.get(node_id, []):
                if edge_id in used:
                    continue
                edge = graph.edges[edge_id]

                if graph.method in {Method.CONCRETE, Method.FULL}:
                    for witness in edge.witnesses:
                        if witness.alpha_binding != query.alpha_binding:
                            continue
                        if witness.before_query != current_q:
                            continue
                        if (
                            beta_binding is not None
                            and witness.beta_binding is not None
                            and beta_binding != witness.beta_binding
                        ):
                            continue
                        next_beta = beta_binding
                        if next_beta is None and witness.beta_binding is not None:
                            next_beta = witness.beta_binding
                        stack.append(
                            (
                                edge.dst,
                                witness.after_query,
                                next_beta,
                                labels + (edge.label,),
                                used | {edge_id},
                            )
                        )
                else:
                    next_q = _unbound_next_query(graph, edge, current_q)
                    if next_q is None:
                        continue
                    stack.append(
                        (
                            edge.dst,
                            next_q,
                            None,
                            labels + (edge.label,),
                            used | {edge_id},
                        )
                    )

    return predicted


def evaluate_method(
    traces: tuple[Trace, ...],
    method: Method,
) -> tuple[AbstractGraph, MethodResult]:
    oracle = {trace.signature for trace in traces}
    graph = build_graph(traces, method)
    predicted = enumerate_paths(graph, traces)
    return graph, MethodResult(
        method=method,
        node_count=len(graph.nodes),
        edge_count=len(graph.edges),
        predicted=predicted,
        true_positive=len(predicted & oracle),
        false_positive=len(predicted - oracle),
        false_negative=len(oracle - predicted),
    )
