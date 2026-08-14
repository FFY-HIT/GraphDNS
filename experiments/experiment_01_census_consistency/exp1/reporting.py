from __future__ import annotations

import csv
import hashlib
import json
import math
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


REVIEW_COLUMNS = (
    "review_status",
    "adjudication",
    "root_cause",
    "reviewer",
    "notes",
)
ALLOWED_ADJUDICATIONS = (
    "graphdns_true_groot_missed",
    "groot_true_graphdns_missed",
    "graphdns_false_positive",
    "groot_false_positive",
    "both_correct_different_granularity",
    "model_scope_difference",
    "parser_or_case_key_mismatch",
    "input_or_tool_failure",
    "both_incorrect",
    "undetermined",
)
GRAPHDNS_BUG_KINDS = ("LD", "DI", "MG", "CZD", "RL", "RB", "ML", "STALE")


def _percentage(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else 100.0 * numerator / denominator


def _fmt_pct(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.2f}%"


def _write_csv(path: Path, rows: Iterable[Mapping[str, Any]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(dict(row), ensure_ascii=False, sort_keys=True) + "\n")


def _finding_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "region_rank": row["sample_rank"],
        "region_name": row["region_name"],
        "region_path": row["region_path"],
        "system": row["system"],
        "ordinal": row["ordinal"],
        "kind": row["kind"],
        "case_key": row["case_key"],
        "key_quality": row["key_quality"],
        "fingerprint": row["fingerprint"],
        "zone_cut": row["zone_cut"],
        "nameserver": row["nameserver"],
        "start_name": row["start_name"],
        "query": row["query"],
        "target": row["target"],
        "server": row["server"],
        "zone": row["zone"],
        "subject": row["subject"],
        "reason": row["reason"],
        "path": row["path"],
        "raw": row["raw"],
    }


def _load_existing_reviews(path: Path) -> dict[str, dict[str, str]]:
    if not path.is_file():
        return {}
    with path.open("r", newline="", encoding="utf-8") as handle:
        return {
            row["case_id"]: {column: row.get(column, "") for column in REVIEW_COLUMNS}
            for row in csv.DictReader(handle)
            if row.get("case_id")
        }


def _case_id(region_name: str, side: str, kind: str, case_key: str) -> str:
    payload = "\0".join((region_name, side, kind, case_key))
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:20]


def generate_reports(
    connection: sqlite3.Connection,
    reports_dir: Path,
    shared_kinds: Sequence[str],
    expected_systems: Sequence[str] = ("graphdns", "groot"),
) -> dict[str, Any]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    shared = set(shared_kinds)
    expected = tuple(dict.fromkeys(expected_systems))
    if not expected or any(system not in {"graphdns", "groot"} for system in expected):
        raise ValueError(f"invalid expected systems: {expected!r}")
    comparison_mode = set(expected) == {"graphdns", "groot"}

    execution_rows = connection.execute(
        "SELECT r.id AS region_id, r.sample_rank, r.name AS region_name, r.path AS region_path, "
        "e.system, e.status, e.return_code, e.wall_seconds, e.record_count, e.finding_count, "
        "e.unique_case_count, e.details_json, e.error, e.output_tail "
        "FROM regions r LEFT JOIN executions e ON e.region_id=r.id "
        "ORDER BY r.sample_rank, e.system"
    ).fetchall()
    executions: dict[int, dict[str, sqlite3.Row]] = defaultdict(dict)
    region_info: dict[int, sqlite3.Row] = {}
    for row in execution_rows:
        region_info[row["region_id"]] = row
        if row["system"]:
            executions[row["region_id"]][row["system"]] = row

    paired_region_ids = {
        region_id
        for region_id, systems in executions.items()
        if systems.get("graphdns") is not None
        and systems.get("groot") is not None
        and systems["graphdns"]["status"] == "ok"
        and systems["groot"]["status"] == "ok"
    }

    finding_rows = connection.execute(
        "SELECT f.*, r.sample_rank, r.name AS region_name, r.path AS region_path "
        "FROM findings f JOIN regions r ON r.id=f.region_id "
        "ORDER BY r.sample_rank, f.system, f.ordinal"
    ).fetchall()
    graphdns_all = [_finding_dict(row) for row in finding_rows if row["system"] == "graphdns"]
    groot_all = [_finding_dict(row) for row in finding_rows if row["system"] == "groot"]
    _write_jsonl(reports_dir / "graphdns_findings.jsonl", graphdns_all)
    _write_jsonl(reports_dir / "groot_findings.jsonl", groot_all)

    raw_by_region_system_kind: Counter[tuple[int, str, str]] = Counter()
    representatives: dict[tuple[int, str, str, str], dict[str, Any]] = {}
    raw_case_counts: Counter[tuple[int, str, str, str]] = Counter()
    cases: dict[tuple[int, str], set[tuple[str, str]]] = defaultdict(set)
    for row in finding_rows:
        region_id = int(row["region_id"])
        system = row["system"]
        kind = row["kind"]
        case_key = row["case_key"]
        raw_by_region_system_kind[(region_id, system, kind)] += 1
        raw_case_counts[(region_id, system, kind, case_key)] += 1
        cases[(region_id, system)].add((kind, case_key))
        representatives.setdefault(
            (region_id, system, kind, case_key), _finding_dict(row)
        )

    all_kinds = sorted({row["kind"] for row in finding_rows}.union(shared))
    per_kind_rows: list[dict[str, Any]] = []
    totals_by_kind: dict[str, Counter[str]] = {kind: Counter() for kind in all_kinds}
    per_region_rows: list[dict[str, Any]] = []
    intersections: list[dict[str, Any]] = []
    graphdns_only: list[dict[str, Any]] = []
    groot_only: list[dict[str, Any]] = []
    graphdns_region_rows: list[dict[str, Any]] = []

    for region_id in sorted(region_info, key=lambda value: region_info[value]["sample_rank"]):
        info = region_info[region_id]
        systems = executions.get(region_id, {})
        graph_status = systems.get("graphdns")["status"] if systems.get("graphdns") else "not_run"
        groot_status = systems.get("groot")["status"] if systems.get("groot") else "not_run"
        graph_cases_all = cases.get((region_id, "graphdns"), set())
        groot_cases_all = cases.get((region_id, "groot"), set())
        paired = region_id in paired_region_ids
        graph_cases = graph_cases_all if paired else set()
        groot_cases = groot_cases_all if paired else set()
        both = graph_cases & groot_cases
        graph_only_set = graph_cases - groot_cases
        groot_only_set = groot_cases - graph_cases
        union = graph_cases | groot_cases
        shared_graph_all = {case for case in graph_cases_all if case[0] in shared}
        shared_groot_all = {case for case in groot_cases_all if case[0] in shared}
        shared_graph = {case for case in graph_cases if case[0] in shared}
        shared_groot = {case for case in groot_cases if case[0] in shared}
        shared_both = shared_graph & shared_groot
        shared_union = shared_graph | shared_groot
        graph_execution = systems.get("graphdns")
        graph_details: dict[str, Any] = {}
        if graph_execution is not None:
            try:
                graph_details = json.loads(graph_execution["details_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                graph_details = {}
        graph_summary = graph_details.get("summary", {})
        graph_bug_counts = {
            kind: raw_by_region_system_kind[(region_id, "graphdns", kind)]
            for kind in GRAPHDNS_BUG_KINDS
        }
        graphdns_region_rows.append(
            {
                "region_rank": info["sample_rank"],
                "region_name": info["region_name"],
                "nodes": graph_summary.get("nodes", ""),
                "edges": graph_summary.get("edges", ""),
                "paths": graph_summary.get("paths", ""),
                **graph_bug_counts,
                "total_bugs": graph_summary.get(
                    "bugs", sum(graph_bug_counts.values())
                ),
                "status": graph_status,
            }
        )
        per_region_rows.append(
            {
                "region_rank": info["sample_rank"],
                "region_name": info["region_name"],
                "region_path": info["region_path"],
                "graphdns_status": graph_status,
                "groot_status": groot_status,
                "graphdns_raw_reports": sum(
                    raw_by_region_system_kind[(region_id, "graphdns", kind)] for kind in all_kinds
                ),
                "groot_raw_reports": sum(
                    raw_by_region_system_kind[(region_id, "groot", kind)] for kind in all_kinds
                ),
                "graphdns_unique_cases": len(graph_cases_all),
                "groot_unique_cases": len(groot_cases_all),
                "paired_comparison": paired,
                "intersection": len(both),
                "graphdns_only": len(graph_only_set),
                "groot_only": len(groot_only_set),
                "union": len(union),
                "jaccard_pct": _percentage(len(both), len(union)),
                "shared_graphdns_cases": len(shared_graph_all),
                "shared_groot_cases": len(shared_groot_all),
                "shared_intersection": len(shared_both),
                "shared_union": len(shared_union),
                "shared_jaccard_pct": _percentage(len(shared_both), len(shared_union)),
            }
        )

        for kind in all_kinds:
            graph_kind_all = {
                case_key for case_kind, case_key in graph_cases_all if case_kind == kind
            }
            groot_kind_all = {
                case_key for case_kind, case_key in groot_cases_all if case_kind == kind
            }
            graph_kind = graph_kind_all if paired else set()
            groot_kind = groot_kind_all if paired else set()
            kind_both = graph_kind & groot_kind
            kind_union = graph_kind | groot_kind
            row = {
                "region_rank": info["sample_rank"],
                "region_name": info["region_name"],
                "kind": kind,
                "shared_scope": kind in shared,
                "paired_comparison": paired,
                "graphdns_raw_reports": raw_by_region_system_kind[(region_id, "graphdns", kind)],
                "groot_raw_reports": raw_by_region_system_kind[(region_id, "groot", kind)],
                "graphdns_unique_cases": len(graph_kind_all),
                "groot_unique_cases": len(groot_kind_all),
                "intersection": len(kind_both),
                "graphdns_only": len(graph_kind - groot_kind),
                "groot_only": len(groot_kind - graph_kind),
                "union": len(kind_union),
                "jaccard_pct": _percentage(len(kind_both), len(kind_union)),
            }
            if any(
                row[key]
                for key in (
                    "graphdns_raw_reports",
                    "groot_raw_reports",
                    "graphdns_unique_cases",
                    "groot_unique_cases",
                )
            ):
                per_kind_rows.append(row)
            if not paired:
                continue
            totals = totals_by_kind[kind]
            totals["graphdns_raw_reports"] += row["graphdns_raw_reports"]
            totals["groot_raw_reports"] += row["groot_raw_reports"]
            totals["graphdns_unique_cases"] += row["graphdns_unique_cases"]
            totals["groot_unique_cases"] += row["groot_unique_cases"]
            totals["intersection"] += row["intersection"]
            totals["graphdns_only"] += row["graphdns_only"]
            totals["groot_only"] += row["groot_only"]
            totals["union"] += row["union"]
            totals["exact_region_agreement"] += int(graph_kind == groot_kind)

        if not paired:
            continue
        for kind, case_key in sorted(both):
            graph_rep = representatives[(region_id, "graphdns", kind, case_key)]
            groot_rep = representatives[(region_id, "groot", kind, case_key)]
            intersections.append(
                {
                    "region_rank": info["sample_rank"],
                    "region_name": info["region_name"],
                    "region_path": info["region_path"],
                    "kind": kind,
                    "case_key": case_key,
                    "shared_scope": kind in shared,
                    "graphdns_raw_witnesses": raw_case_counts[(region_id, "graphdns", kind, case_key)],
                    "groot_raw_witnesses": raw_case_counts[(region_id, "groot", kind, case_key)],
                    "graphdns": graph_rep,
                    "groot": groot_rep,
                }
            )
        for kind, case_key in sorted(graph_only_set):
            rep = representatives[(region_id, "graphdns", kind, case_key)]
            graphdns_only.append(
                {
                    "region_rank": info["sample_rank"],
                    "region_name": info["region_name"],
                    "region_path": info["region_path"],
                    "kind": kind,
                    "case_key": case_key,
                    "shared_scope": kind in shared,
                    "raw_witnesses": raw_case_counts[(region_id, "graphdns", kind, case_key)],
                    "finding": rep,
                }
            )
        for kind, case_key in sorted(groot_only_set):
            rep = representatives[(region_id, "groot", kind, case_key)]
            groot_only.append(
                {
                    "region_rank": info["sample_rank"],
                    "region_name": info["region_name"],
                    "region_path": info["region_path"],
                    "kind": kind,
                    "case_key": case_key,
                    "shared_scope": kind in shared,
                    "raw_witnesses": raw_case_counts[(region_id, "groot", kind, case_key)],
                    "finding": rep,
                }
            )

    agreement_rows: list[dict[str, Any]] = []
    for kind in all_kinds:
        totals = totals_by_kind[kind]
        agreement_rows.append(
            {
                "kind": kind,
                "shared_scope": kind in shared,
                "graphdns_raw_reports": totals["graphdns_raw_reports"],
                "groot_raw_reports": totals["groot_raw_reports"],
                "graphdns_unique_cases": totals["graphdns_unique_cases"],
                "groot_unique_cases": totals["groot_unique_cases"],
                "intersection": totals["intersection"],
                "graphdns_only": totals["graphdns_only"],
                "groot_only": totals["groot_only"],
                "union": totals["union"],
                "jaccard_pct": _percentage(totals["intersection"], totals["union"]),
                "graphdns_coverage_of_groot_pct": _percentage(
                    totals["intersection"], totals["groot_unique_cases"]
                ),
                "groot_coverage_of_graphdns_pct": _percentage(
                    totals["intersection"], totals["graphdns_unique_cases"]
                ),
                "exact_region_agreement_pct": _percentage(
                    totals["exact_region_agreement"], len(paired_region_ids)
                ),
            }
        )

    region_fields = [
        "region_rank",
        "region_name",
        "region_path",
        "graphdns_status",
        "groot_status",
        "graphdns_raw_reports",
        "groot_raw_reports",
        "graphdns_unique_cases",
        "groot_unique_cases",
        "paired_comparison",
        "intersection",
        "graphdns_only",
        "groot_only",
        "union",
        "jaccard_pct",
        "shared_graphdns_cases",
        "shared_groot_cases",
        "shared_intersection",
        "shared_union",
        "shared_jaccard_pct",
    ]
    _write_csv(reports_dir / "per_region_totals.csv", per_region_rows, region_fields)
    graphdns_region_fields = [
        "region_rank",
        "region_name",
        "nodes",
        "edges",
        "paths",
        *GRAPHDNS_BUG_KINDS,
        "total_bugs",
        "status",
    ]
    _write_csv(
        reports_dir / "graphdns_per_region.csv",
        graphdns_region_rows,
        graphdns_region_fields,
    )
    per_kind_fields = [
        "region_rank",
        "region_name",
        "kind",
        "shared_scope",
        "paired_comparison",
        "graphdns_raw_reports",
        "groot_raw_reports",
        "graphdns_unique_cases",
        "groot_unique_cases",
        "intersection",
        "graphdns_only",
        "groot_only",
        "union",
        "jaccard_pct",
    ]
    _write_csv(reports_dir / "per_region_by_kind.csv", per_kind_rows, per_kind_fields)
    agreement_fields = [
        "kind",
        "shared_scope",
        "graphdns_raw_reports",
        "groot_raw_reports",
        "graphdns_unique_cases",
        "groot_unique_cases",
        "intersection",
        "graphdns_only",
        "groot_only",
        "union",
        "jaccard_pct",
        "graphdns_coverage_of_groot_pct",
        "groot_coverage_of_graphdns_pct",
        "exact_region_agreement_pct",
    ]
    _write_csv(reports_dir / "agreement_by_kind.csv", agreement_rows, agreement_fields)
    _write_jsonl(reports_dir / "intersection.jsonl", intersections)
    _write_jsonl(reports_dir / "graphdns_only.jsonl", graphdns_only)
    _write_jsonl(reports_dir / "groot_only.jsonl", groot_only)

    failures: list[dict[str, Any]] = []
    for region_id, systems in executions.items():
        info = region_info[region_id]
        for system in expected:
            row = systems.get(system)
            if row is None or row["status"] != "ok":
                failures.append(
                    {
                        "region_rank": info["sample_rank"],
                        "region_name": info["region_name"],
                        "region_path": info["region_path"],
                        "system": system,
                        "status": row["status"] if row else "not_run",
                        "return_code": row["return_code"] if row else "",
                        "error": row["error"] if row else "",
                        "output_tail": row["output_tail"] if row else "",
                    }
                )
    _write_csv(
        reports_dir / "run_failures.csv",
        failures,
        ["region_rank", "region_name", "region_path", "system", "status", "return_code", "error", "output_tail"],
    )

    review_path = reports_dir / "manual_review.csv"
    previous_reviews = _load_existing_reviews(review_path)
    review_rows: list[dict[str, Any]] = []
    for side, mismatch_rows in (("graphdns_only", graphdns_only), ("groot_only", groot_only)):
        for mismatch in mismatch_rows:
            finding = mismatch["finding"]
            case_id = _case_id(
                mismatch["region_name"], side, mismatch["kind"], mismatch["case_key"]
            )
            row = {
                "case_id": case_id,
                "region_rank": mismatch["region_rank"],
                "region_name": mismatch["region_name"],
                "region_path": mismatch["region_path"],
                "side": side,
                "kind": mismatch["kind"],
                "shared_scope": mismatch["shared_scope"],
                "case_key": mismatch["case_key"],
                "key_quality": finding["key_quality"],
                "raw_witnesses": mismatch["raw_witnesses"],
                "reason": finding["reason"],
                "path": finding["path"],
                "raw": finding["raw"],
                "allowed_adjudications": "|".join(ALLOWED_ADJUDICATIONS),
                "review_status": "pending",
                "adjudication": "",
                "root_cause": "",
                "reviewer": "",
                "notes": "",
            }
            row.update(previous_reviews.get(case_id, {}))
            review_rows.append(row)
    review_fields = [
        "case_id",
        "region_rank",
        "region_name",
        "region_path",
        "side",
        "kind",
        "shared_scope",
        "case_key",
        "key_quality",
        "raw_witnesses",
        "reason",
        "path",
        "raw",
        "allowed_adjudications",
        *REVIEW_COLUMNS,
    ]
    _write_csv(review_path, review_rows, review_fields)

    shared_rows = [row for row in agreement_rows if row["shared_scope"]]
    shared_totals = Counter()
    for row in shared_rows:
        for field in (
            "graphdns_raw_reports",
            "groot_raw_reports",
            "graphdns_unique_cases",
            "groot_unique_cases",
            "intersection",
            "graphdns_only",
            "groot_only",
            "union",
        ):
            shared_totals[field] += int(row[field])
    system_totals: dict[str, dict[str, Any]] = {}
    for system in ("graphdns", "groot"):
        system_representatives = [
            (kind, finding)
            for (region_id, row_system, kind, case_key), finding in representatives.items()
            if row_system == system
        ]
        raw_counts = Counter(
            row["kind"] for row in finding_rows if row["system"] == system
        )
        unique_counts = Counter(kind for kind, finding in system_representatives)
        system_totals[system] = {
            "raw_reports": sum(raw_counts.values()),
            "unique_cases": len(system_representatives),
            "raw_reports_by_kind": dict(sorted(raw_counts.items())),
            "unique_cases_by_kind": dict(sorted(unique_counts.items())),
            "successful_regions": sum(
                systems.get(system) is not None and systems[system]["status"] == "ok"
                for systems in executions.values()
            ),
        }

    failed_by_system = {
        system: sum(
            executions.get(region_id, {}).get(system) is None
            or executions[region_id][system]["status"] != "ok"
            for region_id in region_info
        )
        for system in expected
    }
    unpaired_regions = len(region_info) - len(paired_region_ids) if comparison_mode else 0
    failed_or_unpaired = (
        unpaired_regions
        if comparison_mode
        else sum(failed_by_system.values())
    )
    if comparison_mode:
        summary = {
            "run_mode": "comparison",
            "sampled_regions": len(region_info),
            "paired_successful_regions": len(paired_region_ids),
            "failed_regions_by_system": failed_by_system,
            "unpaired_regions": unpaired_regions,
            "failed_or_unpaired_regions": failed_or_unpaired,
            "shared_kinds": list(shared_kinds),
            "system_totals": system_totals,
            "shared_scope": {
                **dict(shared_totals),
                "jaccard_pct": _percentage(shared_totals["intersection"], shared_totals["union"]),
                "graphdns_coverage_of_groot_pct": _percentage(
                    shared_totals["intersection"], shared_totals["groot_unique_cases"]
                ),
                "groot_coverage_of_graphdns_pct": _percentage(
                    shared_totals["intersection"], shared_totals["graphdns_unique_cases"]
                ),
            },
            "all_kinds": {
                "intersection": len(intersections),
                "graphdns_only": len(graphdns_only),
                "groot_only": len(groot_only),
                "union": len(intersections) + len(graphdns_only) + len(groot_only),
            },
            "normalization": {
                "graphdns_weak_unique_cases": sum(
                    1
                    for (region_id, system, kind, case_key), finding in representatives.items()
                    if system == "graphdns" and finding["key_quality"] == "weak"
                ),
                "groot_weak_unique_cases": sum(
                    1
                    for (region_id, system, kind, case_key), finding in representatives.items()
                    if system == "groot" and finding["key_quality"] == "weak"
                ),
            },
            "manual_review": {
                "total_disagreements": len(review_rows),
                "completed": sum(
                    row["review_status"].strip().lower() == "completed"
                    for row in review_rows
                ),
                "pending": sum(
                    row["review_status"].strip().lower() != "completed"
                    for row in review_rows
                ),
            },
        }
        summary["normalization"]["comparison_ready"] = (
            summary["normalization"]["graphdns_weak_unique_cases"] == 0
            and summary["normalization"]["groot_weak_unique_cases"] == 0
        )
    else:
        graphdns_successful = system_totals["graphdns"]["successful_regions"]
        regions_with_reports = len(
            {
                int(row["region_id"])
                for row in finding_rows
                if row["system"] == "graphdns"
            }
        )
        summary = {
            "run_mode": "graphdns_only",
            "sampled_regions": len(region_info),
            "comparison_available": False,
            "graphdns": {
                **system_totals["graphdns"],
                "failed_regions": failed_by_system.get("graphdns", 0),
                "regions_with_reports": regions_with_reports,
                "regions_without_reports": max(
                    0, graphdns_successful - regions_with_reports
                ),
            },
        }
    (reports_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
    )

    lines = [
        (
            "# Census GraphDNS/GRoot Consistency Report"
            if comparison_mode
            else "# Census GraphDNS Validation Report"
        ),
        "",
        f"- Sampled complete regions: **{summary['sampled_regions']:,}**",
        f"- GraphDNS raw reports / unique cases: **{system_totals['graphdns']['raw_reports']:,} / {system_totals['graphdns']['unique_cases']:,}**",
        f"- GraphDNS successful regions: **{system_totals['graphdns']['successful_regions']:,}**",
        f"- GraphDNS failed regions: **{failed_by_system.get('graphdns', 0):,}**",
    ]
    if comparison_mode:
        lines.extend(
            [
                f"- GRoot raw reports / unique cases: **{system_totals['groot']['raw_reports']:,} / {system_totals['groot']['unique_cases']:,}**",
                f"- Paired successful regions: **{summary['paired_successful_regions']:,}**",
                f"- Failed or unpaired regions: **{summary['failed_or_unpaired_regions']:,}**",
                f"- Shared-scope intersection: **{shared_totals['intersection']:,}**",
                f"- Shared-scope GraphDNS-only: **{shared_totals['graphdns_only']:,}**",
                f"- Shared-scope GRoot-only: **{shared_totals['groot_only']:,}**",
                f"- Shared-scope Jaccard agreement: **{_fmt_pct(summary['shared_scope']['jaccard_pct'])}**",
                f"- Weak GraphDNS/GRoot case keys: **{summary['normalization']['graphdns_weak_unique_cases']:,} / {summary['normalization']['groot_weak_unique_cases']:,}**",
                f"- Disagreements awaiting human review: **{summary['manual_review']['pending']:,}**",
                "",
                "## Agreement by vulnerability kind",
                "",
                "| Kind | Shared | GraphDNS | GRoot | Intersection | GraphDNS only | GRoot only | Jaccard |",
                "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for row in agreement_rows:
            lines.append(
                f"| {row['kind']} | {'yes' if row['shared_scope'] else 'no'} | "
                f"{row['graphdns_unique_cases']:,} | {row['groot_unique_cases']:,} | "
                f"{row['intersection']:,} | {row['graphdns_only']:,} | {row['groot_only']:,} | "
                f"{_fmt_pct(row['jaccard_pct'])} |"
            )
        lines.extend(
            [
                "",
                "## Interpretation guardrails",
                "",
                "- Counts above use unique canonical cases. Raw witness counts are retained separately.",
                "- Only regions where both tools completed successfully enter the intersection denominator.",
                "- STALE and other one-system extensions are not included in the shared-scope headline.",
                "- No disagreement is classified as a false positive or false negative before manual review.",
                "- All case keys must be strong before the comparison is considered complete.",
                "- A final paper table must not be produced while `manual_review.pending` is non-zero.",
                "",
            ]
        )
    else:
        graphdns_raw_by_kind = system_totals["graphdns"]["raw_reports_by_kind"]
        graphdns_unique_by_kind = system_totals["graphdns"]["unique_cases_by_kind"]
        kinds = sorted(set(graphdns_raw_by_kind).union(graphdns_unique_by_kind))
        lines.extend(
            [
                f"- Regions with at least one report: **{summary['graphdns']['regions_with_reports']:,}**",
                f"- Successful regions without reports: **{summary['graphdns']['regions_without_reports']:,}**",
                "",
                "## GraphDNS findings by vulnerability kind",
                "",
                "| Kind | Raw reports | Unique cases |",
                "| --- | ---: | ---: |",
            ]
        )
        if kinds:
            for kind in kinds:
                lines.append(
                    f"| {kind} | {graphdns_raw_by_kind.get(kind, 0):,} | "
                    f"{graphdns_unique_by_kind.get(kind, 0):,} |"
                )
        else:
            lines.append("| None | 0 | 0 |")
        lines.extend(
            [
                "",
                "## Interpretation guardrails",
                "",
                "- This run contains GraphDNS results only; no GraphDNS/GRoot agreement claim is available.",
                "- Raw witnesses and canonical unique cases are both retained.",
                "- A region is successful only when GraphDNS emits parseable Summary, BugStats, and individual reports with consistent counts.",
                "",
            ]
        )
    (reports_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")
    return summary


def summarize_manual_review(
    review_path: Path,
    output_dir: Path,
    require_complete: bool = False,
) -> tuple[dict[str, Any], int]:
    if not review_path.is_file():
        raise FileNotFoundError(f"manual review file does not exist: {review_path}")
    with review_path.open("r", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    invalid: list[str] = []
    pending: list[str] = []
    counts: Counter[tuple[str, str, str]] = Counter()
    for row in rows:
        completed = row.get("review_status", "").strip().lower() == "completed"
        adjudication = row.get("adjudication", "").strip()
        if not completed:
            pending.append(row.get("case_id", ""))
            continue
        if adjudication not in ALLOWED_ADJUDICATIONS:
            invalid.append(row.get("case_id", ""))
            continue
        counts[(row.get("kind", ""), row.get("side", ""), adjudication)] += 1

    summary_rows = [
        {"kind": kind, "side": side, "adjudication": adjudication, "count": count}
        for (kind, side, adjudication), count in sorted(counts.items())
    ]
    _write_csv(
        output_dir / "manual_review_summary.csv",
        summary_rows,
        ["kind", "side", "adjudication", "count"],
    )
    summary = {
        "total": len(rows),
        "completed": len(rows) - len(pending) - len(invalid),
        "pending": len(pending),
        "invalid": len(invalid),
        "invalid_case_ids": invalid,
        "pending_case_ids": pending,
    }
    lines = [
        "# Manual Disagreement Review",
        "",
        f"- Total disagreements: **{summary['total']:,}**",
        f"- Completed valid reviews: **{summary['completed']:,}**",
        f"- Pending: **{summary['pending']:,}**",
        f"- Invalid annotations: **{summary['invalid']:,}**",
        "",
        "| Kind | Side | Adjudication | Count |",
        "| --- | --- | --- | ---: |",
    ]
    for row in summary_rows:
        lines.append(
            f"| {row['kind']} | {row['side']} | {row['adjudication']} | {row['count']:,} |"
        )
    (output_dir / "manual_review_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    exit_code = 1 if require_complete and (pending or invalid) else 0
    return summary, exit_code
