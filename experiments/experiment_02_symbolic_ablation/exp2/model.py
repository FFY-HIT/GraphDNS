from __future__ import annotations

import itertools
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    return value if value.endswith(".") else value + "."


def is_descendant_or_same(name: str, suffix: str) -> bool:
    name = normalize_domain(name)
    suffix = normalize_domain(suffix)
    return name == suffix or name.endswith("." + suffix)


def is_strict_descendant(name: str, suffix: str) -> bool:
    return normalize_domain(name) != normalize_domain(suffix) and is_descendant_or_same(
        name, suffix
    )


def relative_prefix(name: str, suffix: str) -> str | None:
    name = normalize_domain(name)
    suffix = normalize_domain(suffix)
    if name == suffix:
        return ""
    marker = "." + suffix
    if not name.endswith(marker):
        return None
    return name[: -len(marker)]


def label_count(name: str) -> int:
    return len([part for part in normalize_domain(name).split(".") if part])


@dataclass(frozen=True)
class Record:
    id: str
    server: str
    zone: str
    owner: str
    type: str
    value: str


@dataclass(frozen=True)
class Query:
    name: str
    symbol_suffix: str

    @property
    def alpha_binding(self) -> str:
        prefix = relative_prefix(self.name, self.symbol_suffix)
        if prefix is None:
            raise ValueError(
                f"query {self.name} is outside symbolic suffix {self.symbol_suffix}"
            )
        return prefix


@dataclass(frozen=True)
class Case:
    id: str
    description: str
    pair_id: str
    snapshot: str
    start_server: str
    start_zone: str
    authorities: dict[str, str]
    records: tuple[Record, ...]
    queries: tuple[Query, ...]


@dataclass(frozen=True)
class TraceState:
    server: str
    zone: str
    query: str
    kind: str
    suffix: str
    alpha_binding: str
    beta_binding: str | None = None
    terminal: bool = False
    outcome: str = ""


@dataclass(frozen=True)
class TraceEvent:
    label: str
    record_id: str
    action: str
    owner: str
    target: str
    before_query: str
    after_query: str
    outcome: str = ""


@dataclass(frozen=True)
class Trace:
    case_id: str
    query: Query
    states: tuple[TraceState, ...]
    events: tuple[TraceEvent, ...]
    outcome: str

    @property
    def signature(self) -> tuple[str, tuple[str, ...], str]:
        return (
            self.query.name,
            tuple(event.label for event in self.events),
            self.outcome,
        )


def _record(raw: dict[str, Any]) -> Record:
    record_type = str(raw["type"]).upper()
    value = str(raw["value"]).strip()
    if record_type in {"NS", "CNAME", "DNAME"}:
        value = normalize_domain(value)
    return Record(
        id=str(raw["id"]),
        server=normalize_domain(str(raw["server"])),
        zone=normalize_domain(str(raw["zone"])),
        owner=normalize_domain(str(raw["owner"])),
        type=record_type,
        value=value,
    )


def _queries(raw: dict[str, Any]) -> tuple[Query, ...]:
    labels = [str(label).lower() for label in raw.get("labels", [])]
    generated: dict[str, Query] = {}

    for template in raw.get("query_templates", []):
        suffix = normalize_domain(str(template["suffix"]))
        min_depth = int(template.get("min_depth", 1))
        max_depth = int(template.get("max_depth", min_depth))
        if min_depth < 0 or max_depth < min_depth:
            raise ValueError(f"invalid query depth range for {suffix}")
        for depth in range(min_depth, max_depth + 1):
            if depth == 0:
                generated[suffix] = Query(suffix, suffix)
                continue
            if not labels:
                raise ValueError(f"query template {suffix} requires a non-empty label set")
            for prefix in itertools.product(labels, repeat=depth):
                name = normalize_domain(".".join(prefix) + "." + suffix)
                generated[name] = Query(name, suffix)

    for item in raw.get("explicit_queries", []):
        if isinstance(item, str):
            name = normalize_domain(item)
            suffix = normalize_domain(raw["start_zone"])
        else:
            name = normalize_domain(str(item["name"]))
            suffix = normalize_domain(str(item.get("symbol_suffix", raw["start_zone"])))
        generated[name] = Query(name, suffix)

    return tuple(generated[name] for name in sorted(generated))


def load_cases(path: Path) -> tuple[Case, ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases: list[Case] = []
    seen_ids: set[str] = set()

    for raw in payload["cases"]:
        case_id = str(raw["id"])
        if case_id in seen_ids:
            raise ValueError(f"duplicate case id: {case_id}")
        seen_ids.add(case_id)

        authorities = {
            normalize_domain(zone): normalize_domain(server)
            for zone, server in raw["authorities"].items()
        }
        records = tuple(_record(item) for item in raw["records"])
        record_ids = [record.id for record in records]
        if len(record_ids) != len(set(record_ids)):
            raise ValueError(f"duplicate record id in case {case_id}")

        queries = _queries(raw)
        if not queries:
            raise ValueError(f"case {case_id} has no concrete queries")

        cases.append(
            Case(
                id=case_id,
                description=str(raw["description"]),
                pair_id=str(raw.get("pair_id", "")),
                snapshot=str(raw.get("snapshot", "base")),
                start_server=normalize_domain(str(raw["start_server"])),
                start_zone=normalize_domain(str(raw["start_zone"])),
                authorities=authorities,
                records=records,
                queries=queries,
            )
        )

    return tuple(cases)
