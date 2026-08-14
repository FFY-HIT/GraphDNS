#!/usr/bin/env python3
"""Audit a GraphDNS/GRoot comparison run without changing either result set."""

from __future__ import annotations

import argparse
import csv
import json
import math
import sqlite3
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


SHARED_KINDS = {"LD", "DI", "MG", "CZD", "RL", "RB", "ML"}


def normalize_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    return text if text.endswith(".") else text + "."


def is_strict_descendant(name: str, ancestor: str) -> bool:
    name = normalize_name(name)
    ancestor = normalize_name(ancestor)
    return bool(name and ancestor and name != ancestor and name.endswith("." + ancestor))


def is_descendant_or_same(name: str, ancestor: str) -> bool:
    name = normalize_name(name)
    ancestor = normalize_name(ancestor)
    return bool(
        name
        and ancestor
        and (name == ancestor or name.endswith("." + ancestor))
    )


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def finding_of(row: dict[str, Any]) -> dict[str, Any]:
    value = row.get("finding")
    return value if isinstance(value, dict) else row


def cycle_zones(row: dict[str, Any]) -> tuple[str, ...]:
    finding = finding_of(row)
    raw = finding.get("raw", "")
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        parsed = {}
    values = parsed.get("cycle_zones", []) if isinstance(parsed, dict) else []
    if not values:
        key = str(row.get("case_key", finding.get("case_key", "")))
        marker = "CZD|zones="
        if key.startswith(marker):
            values = key[len(marker) :].split("|")
    return tuple(sorted({normalize_name(value) for value in values if value}))


def semantic_key(row: dict[str, Any]) -> str:
    finding = finding_of(row)
    kind = str(row.get("kind", finding.get("kind", ""))).upper()
    if kind in {"LD", "CZD"}:
        if kind == "LD":
            cuts = (normalize_name(finding.get("zone_cut")),)
        else:
            cuts = cycle_zones(row)
        return "DELEGATION_FAILURE|cuts=" + "|".join(cut for cut in cuts if cut)
    if kind == "DI":
        return "DI|cut=" + normalize_name(finding.get("zone_cut"))
    if kind == "MG":
        return (
            "MG|cut="
            + normalize_name(finding.get("zone_cut"))
            + "|ns="
            + normalize_name(finding.get("nameserver"))
        )
    if kind in {"RB", "ML"}:
        return (
            kind
            + "|start="
            + normalize_name(finding.get("start_name") or finding.get("start"))
            + "|target="
            + normalize_name(finding.get("target"))
        )
    if kind == "RL":
        return "RL|start=" + normalize_name(
            finding.get("start_name") or finding.get("start")
        )
    return str(row.get("case_key", finding.get("case_key", "")))


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def runtime_summary(database: Path) -> dict[str, Any]:
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        "SELECT system, wall_seconds, details_json FROM executions "
        "WHERE status='ok' ORDER BY system, region_id"
    ).fetchall()
    connection.close()

    by_system: dict[str, list[float]] = defaultdict(list)
    preprocess: list[float] = []
    for row in rows:
        system = str(row["system"])
        by_system[system].append(float(row["wall_seconds"]))
        if system == "graphdns":
            try:
                details = json.loads(row["details_json"])
            except json.JSONDecodeError:
                details = {}
            preprocess.append(float(details.get("preprocess_seconds", 0.0) or 0.0))

    result: dict[str, Any] = {}
    for system, values in sorted(by_system.items()):
        total = sum(values)
        if system == "graphdns":
            total += sum(preprocess)
        result[system] = {
            "regions": len(values),
            "semantic_or_wrapper_wall_seconds": sum(values),
            "preprocess_wall_seconds": sum(preprocess) if system == "graphdns" else 0.0,
            "end_to_end_wall_seconds": total,
            "median_region_seconds": statistics.median(values) if values else 0.0,
            "p95_region_seconds": percentile(values, 0.95),
        }
    if "graphdns" in result and "groot" in result:
        graphdns_total = result["graphdns"]["end_to_end_wall_seconds"]
        result["groot_over_graphdns_end_to_end_ratio"] = (
            result["groot"]["end_to_end_wall_seconds"] / graphdns_total
            if graphdns_total
            else None
        )
    return result


def compare_semantics(
    graphdns_rows: Iterable[dict[str, Any]],
    groot_rows: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    graphdns = {
        (str(row.get("region_name", "")), semantic_key(row))
        for row in graphdns_rows
        if str(row.get("kind", "")).upper() in SHARED_KINDS
    }
    groot = {
        (str(row.get("region_name", "")), semantic_key(row))
        for row in groot_rows
        if str(row.get("kind", "")).upper() in SHARED_KINDS
    }
    intersection = graphdns & groot
    union = graphdns | groot
    return {
        "graphdns_cases": len(graphdns),
        "groot_cases": len(groot),
        "intersection": len(intersection),
        "graphdns_only": len(graphdns - groot),
        "groot_only": len(groot - graphdns),
        "union": len(union),
        "jaccard": len(intersection) / len(union) if union else 1.0,
    }


def classify_disagreements(
    graphdns_rows: list[dict[str, Any]],
    groot_rows: list[dict[str, Any]],
    server_view_mode: str,
) -> tuple[Counter[str], list[dict[str, Any]]]:
    graphdns_semantic = {
        (str(row.get("region_name", "")), semantic_key(row)) for row in graphdns_rows
    }
    groot_semantic = {
        (str(row.get("region_name", "")), semantic_key(row)) for row in groot_rows
    }
    counts: Counter[str] = Counter()
    unresolved: list[dict[str, Any]] = []

    for side, rows, other in (
        ("graphdns_only", graphdns_rows, groot_semantic),
        ("groot_only", groot_rows, graphdns_semantic),
    ):
        for row in rows:
            finding = finding_of(row)
            kind = str(row.get("kind", finding.get("kind", ""))).upper()
            key = (str(row.get("region_name", "")), semantic_key(row))
            if key in other:
                counts["same_failure_different_taxonomy_or_granularity"] += 1
                continue
            if kind == "STALE" and side == "graphdns_only":
                counts["graphdns_record_level_property_outside_groot_scope"] += 1
                continue
            if kind == "LD" and side == "groot_only" and server_view_mode == "sampled":
                counts["closed_world_lame_delegation_outside_sampled_scope"] += 1
                continue
            if kind == "CZD" and side == "groot_only":
                zones = cycle_zones(row)
                if len(zones) == 1:
                    counts[
                        "single_zone_cycle_from_child_apex_ns_modeling"
                    ] += 1
                    continue
            if kind == "MG" and side == "groot_only":
                cut = normalize_name(finding.get("zone_cut"))
                nameserver = normalize_name(finding.get("nameserver"))
                region_apex = normalize_name(row.get("region_name"))
                if cut == region_apex:
                    counts[
                        "apex_ns_address_outside_delegation_glue_scope"
                    ] += 1
                    continue
                if not is_descendant_or_same(nameserver, cut):
                    counts["groot_glue_nameserver_outside_delegated_bailiwick"] += 1
                    continue
            unresolved.append(
                {
                    "region_name": row.get("region_name", ""),
                    "side": side,
                    "kind": kind,
                    "case_key": row.get("case_key", ""),
                    "reason": finding.get("reason", ""),
                }
            )
            counts["requires_case_review"] += 1
    return counts, unresolved


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument(
        "--server-views",
        choices=("complete", "sampled"),
        required=True,
        help="GraphDNS server-view assumption used by the run",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_dir = args.run_dir.resolve()
    reports = run_dir / "reports"
    graphdns_rows = read_jsonl(reports / "graphdns_findings.jsonl")
    groot_rows = read_jsonl(reports / "groot_findings.jsonl")
    graphdns_only = read_jsonl(reports / "graphdns_only.jsonl")
    groot_only = read_jsonl(reports / "groot_only.jsonl")

    counts, unresolved = classify_disagreements(
        graphdns_only, groot_only, args.server_views
    )
    result = {
        "run_dir": str(run_dir),
        "server_view_mode": args.server_views,
        "runtime": runtime_summary(run_dir / "results.sqlite3"),
        "semantic_comparison": compare_semantics(graphdns_rows, groot_rows),
        "disagreement_classification": dict(sorted(counts.items())),
        "unresolved_cases": len(unresolved),
    }
    output = reports / "supplemental_audit.json"
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_csv(
        reports / "supplemental_unresolved_cases.csv",
        unresolved,
        ["region_name", "side", "kind", "case_key", "reason"],
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
