from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from exp2.model import Case, Query, Record, load_cases, normalize_domain

from .veridns import record_deltas


DOMAIN_RDATA_TYPES = {"NS", "CNAME", "DNAME"}


@dataclass(frozen=True)
class CensusControlledSuite:
    cases: tuple[Case, ...]
    expectations: dict[str, Any]
    updates: tuple[dict[str, Any], ...]
    description: str
    validity_scope: dict[str, Any]


def _record(raw: dict[str, Any]) -> Record:
    record_type = str(raw["type"]).upper()
    value = str(raw["value"]).strip()
    if record_type in DOMAIN_RDATA_TYPES:
        value = normalize_domain(value)
    return Record(
        id=str(raw["id"]),
        server=normalize_domain(str(raw["server"])),
        zone=normalize_domain(str(raw["zone"])),
        owner=normalize_domain(str(raw["owner"])),
        type=record_type,
        value=value,
    )


def _queries(raw_queries: list[dict[str, Any]], start_zone: str) -> tuple[Query, ...]:
    result: list[Query] = []
    seen: set[str] = set()
    for raw in raw_queries:
        name = normalize_domain(str(raw["name"]))
        suffix = normalize_domain(str(raw.get("symbol_suffix", start_zone)))
        if name in seen:
            raise ValueError(f"duplicate controlled query: {name}")
        seen.add(name)
        result.append(Query(name=name, symbol_suffix=suffix))
    if not result:
        raise ValueError("a controlled update requires at least one query")
    return tuple(result)


def _ensure_unique_records(
    base: Case,
    shared: tuple[Record, ...],
    changed: tuple[Record, ...],
    pair_id: str,
) -> None:
    base_ids = {record.id for record in base.records}
    shared_ids = [record.id for record in shared]
    changed_ids = [record.id for record in changed]
    control_ids = set((*shared_ids, *changed_ids))
    collisions = base_ids & control_ids
    if collisions:
        raise ValueError(
            f"{pair_id} control IDs collide with Census records: "
            + ", ".join(sorted(collisions))
        )
    if len(shared_ids) != len(set(shared_ids)):
        raise ValueError(f"{pair_id} contains duplicate shared record IDs")
    if set(shared_ids) & set(changed_ids):
        raise ValueError(f"{pair_id} reuses a shared record ID for its delta")
    if len(changed) == 2 and changed[0].id != changed[1].id:
        raise ValueError(f"{pair_id} MODIFY must preserve the record ID")


def _make_case(
    base: Case,
    pair_id: str,
    snapshot: str,
    description: str,
    start_server: str,
    start_zone: str,
    authorities: dict[str, str],
    records: tuple[Record, ...],
    queries: tuple[Query, ...],
) -> Case:
    return Case(
        id=f"{pair_id}_{snapshot}",
        description=description,
        pair_id=pair_id,
        snapshot=snapshot,
        start_server=start_server,
        start_zone=start_zone,
        authorities=authorities,
        records=records,
        queries=queries,
    )


def load_census_controlled_suite(
    spec_path: Path,
    base_dataset_path: Path,
) -> CensusControlledSuite:
    payload = json.loads(spec_path.read_text(encoding="utf-8"))
    base_cases = {case.id: case for case in load_cases(base_dataset_path)}
    cases: list[Case] = []
    metadata: list[dict[str, Any]] = []
    seen_pairs: set[str] = set()

    for raw in payload["updates"]:
        pair_id = str(raw["pair_id"])
        if pair_id in seen_pairs:
            raise ValueError(f"duplicate controlled update pair: {pair_id}")
        seen_pairs.add(pair_id)

        base_case_id = str(raw["base_case_id"])
        try:
            base = base_cases[base_case_id]
        except KeyError as exc:
            raise ValueError(
                f"{pair_id} references unknown Census case {base_case_id}"
            ) from exc

        shared = tuple(_record(item) for item in raw.get("shared_records", []))
        change = raw["change"]
        operation = str(change["operation"]).upper()
        old = _record(change["old_record"]) if change.get("old_record") else None
        new = _record(change["new_record"]) if change.get("new_record") else None
        if operation == "ADD" and (old is not None or new is None):
            raise ValueError(f"{pair_id} has an invalid ADD")
        if operation == "DELETE" and (old is None or new is not None):
            raise ValueError(f"{pair_id} has an invalid DELETE")
        if operation == "MODIFY" and (old is None or new is None):
            raise ValueError(f"{pair_id} has an invalid MODIFY")
        if operation not in {"ADD", "DELETE", "MODIFY"}:
            raise ValueError(f"{pair_id} has unsupported operation {operation}")

        changed = tuple(record for record in (old, new) if record is not None)
        _ensure_unique_records(base, shared, changed, pair_id)
        start_zone = normalize_domain(str(raw.get("start_zone", base.start_zone)))
        start_server = normalize_domain(
            str(raw.get("start_server", base.start_server))
        )
        queries = _queries(raw["explicit_queries"], start_zone)

        authorities = dict(base.authorities)
        authorities.update(
            {
                normalize_domain(str(zone)): normalize_domain(str(server))
                for zone, server in raw.get("authority_overrides", {}).items()
            }
        )
        common = (*base.records, *shared)
        before_records = (*common, *((old,) if old is not None else ()))
        after_records = (*common, *((new,) if new is not None else ()))
        description = str(raw["description"])
        before = _make_case(
            base,
            pair_id,
            "before",
            f"Census background before controlled update: {description}",
            start_server,
            start_zone,
            authorities,
            before_records,
            queries,
        )
        after = _make_case(
            base,
            pair_id,
            "after",
            f"Census background after controlled update: {description}",
            start_server,
            start_zone,
            authorities,
            after_records,
            queries,
        )
        deltas = record_deltas(before, after)
        if len(deltas) != 1 or deltas[0].operation != operation:
            raise ValueError(
                f"{pair_id} must produce exactly one {operation} delta, got {deltas}"
            )

        cases.extend((before, after))
        changed_record = new if new is not None else old
        assert changed_record is not None
        metadata.append(
            {
                "pair_id": pair_id,
                "base_case_id": base_case_id,
                "source_region": str(raw["source_region"]),
                "start_server": start_server,
                "start_zone": start_zone,
                "operation": operation,
                "changed_owner": changed_record.owner,
                "changed_type": changed_record.type,
                "old_value": old.value if old is not None else "",
                "new_value": new.value if new is not None else "",
                "base_records": len(base.records),
                "shared_control_records": len(shared),
                "before_records": len(before.records),
                "after_records": len(after.records),
                "queries": len(queries),
                "description": description,
            }
        )

    return CensusControlledSuite(
        cases=tuple(cases),
        expectations=dict(payload.get("expectations", {})),
        updates=tuple(metadata),
        description=str(payload.get("description", "")),
        validity_scope=dict(payload.get("validity_scope", {})),
    )
