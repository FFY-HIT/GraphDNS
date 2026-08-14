from __future__ import annotations

import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


def _csv_value(value: Any) -> Any:
    if isinstance(value, (list, dict, tuple, set)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    if value is None:
        return ""
    return value


def write_csv(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    materialized = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not materialized:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    seen: set[str] = set()
    for row in materialized:
        for key in row:
            if key not in seen:
                fields.append(key)
                seen.add(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in materialized:
            writer.writerow({key: _csv_value(row.get(key)) for key in fields})


def _mean(values: Iterable[float | None]) -> float | None:
    present = [float(value) for value in values if value is not None]
    return statistics.fmean(present) if present else None


def _ratio(numerator: int | float, denominator: int | float) -> float | None:
    return float(numerator) / float(denominator) if denominator else None


def summarize(
    region_rows: list[dict[str, Any]],
    candidate_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    evaluated = [row for row in candidate_rows if row.get("status") == "ok"]
    accurate = [row for row in evaluated if row.get("accurate")]
    native = [row for row in evaluated if row.get("native_executable")]
    native_accurate = [row for row in native if row.get("accurate")]
    equivalent = [
        row for row in evaluated if row.get("incremental_full_equivalent")
    ]
    report_equivalent = [
        row
        for row in evaluated
        if row.get(
            "report_set_equivalent",
            row.get("incremental_full_equivalent"),
        )
    ]

    def component_equivalent(field: str) -> list[dict[str, Any]]:
        return [
            row
            for row in evaluated
            if row.get(field, row.get("incremental_full_equivalent"))
        ]

    repairable_reports = sum(int(row["repairable_reports"]) for row in region_rows)
    groups = sum(int(row["root_cause_groups"]) for row in region_rows)

    by_kind: dict[str, dict[str, Any]] = {}
    kind_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in candidate_rows:
        kind_rows[str(row.get("kind", "UNKNOWN"))].append(row)
    for kind, rows in sorted(kind_rows.items()):
        kind_evaluated = [row for row in rows if row.get("status") == "ok"]
        kind_accurate = [row for row in kind_evaluated if row.get("accurate")]
        kind_equivalent = [
            row
            for row in kind_evaluated
            if row.get("incremental_full_equivalent")
        ]
        by_kind[kind] = {
            "generated_candidates": len(rows),
            "evaluated_candidates": len(kind_evaluated),
            "accurate_candidates": len(kind_accurate),
            "candidate_accuracy": _ratio(
                len(kind_accurate), len(kind_evaluated)
            ),
            "equivalent_candidates": len(kind_equivalent),
            "equivalence_rate": _ratio(
                len(kind_equivalent), len(kind_evaluated)
            ),
        }

    incremental_graph_update = sum(
        float(row.get("incremental_graph_update_seconds", 0.0))
        for row in evaluated
    )
    incremental_traversal = sum(
        float(row.get("incremental_local_traversal_seconds", 0.0))
        for row in evaluated
    )
    incremental_graph_traversal = sum(
        float(row.get("incremental_graph_traversal_seconds", 0.0))
        for row in evaluated
    )
    full_graph_build = sum(
        float(row.get("full_graph_build_seconds", 0.0)) for row in evaluated
    )
    full_traversal = sum(
        float(row.get("full_traversal_seconds", 0.0)) for row in evaluated
    )
    full_graph_traversal = sum(
        float(row.get("full_graph_traversal_seconds", 0.0))
        for row in evaluated
    )
    return {
        "selection": {
            "selected_regions": len(region_rows),
            "regions_with_evaluable_candidates": sum(
                int(row.get("evaluated_candidates", 0)) > 0
                for row in region_rows
            ),
            "total_records": sum(int(row.get("records", 0)) for row in region_rows),
            "total_bug_reports": sum(int(row.get("bugs", 0)) for row in region_rows),
        },
        "root_cause_grouping": {
            "repairable_reports": repairable_reports,
            "root_cause_groups": groups,
            "overall_merge_rate_micro": (
                1.0 - groups / repairable_reports if repairable_reports else None
            ),
            "mean_merge_rate_macro": _mean(
                row.get("root_cause_merge_rate") for row in region_rows
            ),
            "reports_per_group": _ratio(repairable_reports, groups),
            "groups_with_accurate_candidate": sum(
                int(row.get("groups_with_accurate_candidate", 0))
                for row in region_rows
            ),
            "group_fix_coverage": _ratio(
                sum(
                    int(row.get("groups_with_accurate_candidate", 0))
                    for row in region_rows
                ),
                groups,
            ),
        },
        "candidate_accuracy": {
            "generated_candidates": len(candidate_rows),
            "evaluated_candidates": len(evaluated),
            "accurate_candidates": len(accurate),
            "overall_accuracy_micro": _ratio(len(accurate), len(evaluated)),
            "mean_region_accuracy_macro": _mean(
                row.get("candidate_accuracy") for row in region_rows
            ),
            "native_executable_candidates": len(native),
            "native_accurate_candidates": len(native_accurate),
            "native_accuracy_micro": _ratio(
                len(native_accurate), len(native)
            ),
            "unresolved_placeholder_candidates": sum(
                row.get("status") == "unresolved_placeholder"
                for row in candidate_rows
            ),
            "candidates_introducing_severe_reports": sum(
                int(row.get("new_severe_reports", 0)) > 0 for row in evaluated
            ),
            "by_kind": by_kind,
        },
        "incremental_equivalence": {
            "equivalent_candidates": len(equivalent),
            "evaluated_candidates": len(evaluated),
            "full_state_equivalence_rate": _ratio(
                len(equivalent), len(evaluated)
            ),
            "report_set_equivalence_rate": _ratio(
                len(report_equivalent), len(evaluated)
            ),
            "reachable_edge_set_equivalence_rate": _ratio(
                len(component_equivalent("reachable_edge_set_equivalent")),
                len(evaluated),
            ),
            "cached_edge_set_equivalence_rate": _ratio(
                len(component_equivalent("cached_edge_set_equivalent")),
                len(evaluated),
            ),
            "path_set_equivalence_rate": _ratio(
                len(component_equivalent("path_set_equivalent")),
                len(evaluated),
            ),
            "terminal_state_set_equivalence_rate": _ratio(
                len(component_equivalent("terminal_state_set_equivalent")),
                len(evaluated),
            ),
            "fully_equivalent_regions": sum(
                row.get("incremental_full_equivalence_rate") == 1.0
                for row in region_rows
            ),
            "regions_with_evaluated_candidates": sum(
                int(row.get("evaluated_candidates", 0)) > 0
                for row in region_rows
            ),
            "stale_incremental_reports": sum(
                int(row.get("stale_incremental_reports", 0))
                for row in evaluated
            ),
            "missed_incremental_reports": sum(
                int(row.get("missed_incremental_reports", 0))
                for row in evaluated
            ),
        },
        "timing": {
            "incremental_graph_update_seconds": incremental_graph_update,
            "incremental_local_traversal_seconds": incremental_traversal,
            "incremental_graph_traversal_seconds": incremental_graph_traversal,
            "full_graph_build_seconds": full_graph_build,
            "full_traversal_seconds": full_traversal,
            "full_graph_traversal_seconds": full_graph_traversal,
            "graph_traversal_speedup": (
                full_graph_traversal / incremental_graph_traversal
                if incremental_graph_traversal
                else None
            ),
        },
    }


def _format_rate(value: Any) -> str:
    return "N/A" if value is None else f"{100.0 * float(value):.2f}%"


def write_report(path: Path, summary: dict[str, Any]) -> None:
    selection = summary["selection"]
    grouping = summary["root_cause_grouping"]
    accuracy = summary["candidate_accuracy"]
    equivalence = summary["incremental_equivalence"]
    timing = summary["timing"]
    lines = [
        "# Experiment 04 Report",
        "",
        "## Scope",
        "",
        (
            f"The run selected {selection['selected_regions']} complete Census regions "
            "that each contained at least one repairable GraphDNS report and one "
            "generated repair candidate."
        ),
        (
            f"The selected inputs contain {selection['total_records']} normalized "
            f"records and {selection['total_bug_reports']} baseline reports."
        ),
        "",
        "## Root-cause grouping",
        "",
        (
            f"- Repairable reports: {grouping['repairable_reports']}"
        ),
        f"- Root-cause groups: {grouping['root_cause_groups']}",
        (
            "- Overall merge rate (micro): "
            + _format_rate(grouping["overall_merge_rate_micro"])
        ),
        (
            "- Mean per-region merge rate (macro): "
            + _format_rate(grouping["mean_merge_rate_macro"])
        ),
        (
            "- Root-cause groups with at least one accurate candidate: "
            f"{grouping['groups_with_accurate_candidate']} "
            f"({_format_rate(grouping['group_fix_coverage'])})"
        ),
        "",
        "The merge rate is `1 - root_cause_groups / repairable_reports`; it is "
        "computed only over LD, DI, MG, CZD, RL, RB, ML, and STALE reports.",
        "",
        "## Candidate accuracy",
        "",
        f"- Generated candidates: {accuracy['generated_candidates']}",
        f"- Dry-run evaluated candidates: {accuracy['evaluated_candidates']}",
        f"- Accurate candidates: {accuracy['accurate_candidates']}",
        (
            "- Overall candidate accuracy (micro): "
            + _format_rate(accuracy["overall_accuracy_micro"])
        ),
        (
            "- Mean per-region candidate accuracy (macro): "
            + _format_rate(accuracy["mean_region_accuracy_macro"])
        ),
        (
            "- Native, fully instantiated candidate accuracy: "
            + _format_rate(accuracy["native_accuracy_micro"])
        ),
        (
            "- Candidates rejected for new severe reports: "
            f"{accuracy['candidates_introducing_severe_reports']}"
        ),
        "",
        "A candidate is accurate only when a fresh full rebuild removes its "
        "original root-cause group and introduces no new severe LD, MG, CZD, "
        "RL, RB, or ML report. TEST-NET addresses are used only to validate the "
        "structure of `<TODO_IP>` actions; native accuracy excludes all such "
        "substitutions.",
        "",
        "## Incremental/full equivalence",
        "",
        (
            "- Full edge/path/state/report equivalence: "
            + _format_rate(equivalence["full_state_equivalence_rate"])
        ),
        (
            "- Reachable-edge-set equivalence: "
            + _format_rate(
                equivalence["reachable_edge_set_equivalence_rate"]
            )
        ),
        (
            "- Internal candidate-edge-cache equivalence (diagnostic only): "
            + _format_rate(equivalence["cached_edge_set_equivalence_rate"])
        ),
        (
            "- Complete-path-set equivalence: "
            + _format_rate(equivalence["path_set_equivalence_rate"])
        ),
        (
            "- Terminal-symbolic-state-set equivalence: "
            + _format_rate(
                equivalence["terminal_state_set_equivalence_rate"]
            )
        ),
        (
            "- Vulnerability-report-set equivalence: "
            + _format_rate(equivalence["report_set_equivalence_rate"])
        ),
        f"- Stale reports in incremental output: {equivalence['stale_incremental_reports']}",
        f"- Reports missed by incremental output: {equivalence['missed_incremental_reports']}",
        "",
        "Equivalence applies the same action sequence to the incremental graph "
        "and an independently rebuilt graph. Reachable SRAG edges, complete DFS "
        "paths, and terminal symbolic states are compared through deterministic "
        "canonical-set digests; report identities are also compared exactly "
        "and exclude only the witness path. The candidate-edge cache includes "
        "dormant r=0 edges and is reported separately because it is not part of "
        "the represented SRAG.",
        "",
        "## Timing",
        "",
        (
            f"- Incremental graph update: "
            f"{timing['incremental_graph_update_seconds']:.6f} s"
        ),
        (
            f"- Incremental local traversal: "
            f"{timing['incremental_local_traversal_seconds']:.6f} s"
        ),
        (
            f"- Incremental graph update plus local traversal: "
            f"{timing['incremental_graph_traversal_seconds']:.6f} s"
        ),
        f"- Full graph build: {timing['full_graph_build_seconds']:.6f} s",
        f"- Full traversal: {timing['full_traversal_seconds']:.6f} s",
        (
            f"- Full graph build plus traversal: "
            f"{timing['full_graph_traversal_seconds']:.6f} s"
        ),
        (
            "- Graph-and-traversal speedup: "
            + (
                "N/A"
                if timing["graph_traversal_speedup"] is None
                else f"{timing['graph_traversal_speedup']:.2f}x"
            )
        ),
        "",
        "Only graph construction/update and DFS traversal are timed. Vulnerability "
        "detection and report refresh are still executed for equivalence checking "
        "but excluded from this comparison, as are subprocess startup, file "
        "staging, and output serialization.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def generate_outputs(
    run_dir: Path,
    region_rows: list[dict[str, Any]],
    candidate_rows: list[dict[str, Any]],
    group_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    write_csv(run_dir / "region_results.csv", region_rows)
    write_csv(run_dir / "candidate_results.csv", candidate_rows)
    write_csv(run_dir / "root_cause_groups.csv", group_rows)
    mismatch_rows = [
        row
        for row in candidate_rows
        if row.get("status") == "ok"
        and not row.get("incremental_full_equivalent")
    ]
    with (run_dir / "equivalence_mismatches.jsonl").open(
        "w", encoding="utf-8"
    ) as handle:
        for row in mismatch_rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    summary = summarize(region_rows, candidate_rows)
    (run_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    write_report(run_dir / "report.md", summary)
    return summary
