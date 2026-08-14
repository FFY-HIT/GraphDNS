#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def is_true(value: str | None) -> bool:
    return value == "True"


def percentile(values: Iterable[float], fraction: float) -> float | None:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return None
    position = fraction * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def describe(values: Iterable[float]) -> dict[str, float | int | None]:
    materialized = [float(value) for value in values]
    return {
        "count": len(materialized),
        "min": min(materialized) if materialized else None,
        "q1": percentile(materialized, 0.25),
        "median": statistics.median(materialized) if materialized else None,
        "q3": percentile(materialized, 0.75),
        "max": max(materialized) if materialized else None,
        "mean": statistics.fmean(materialized) if materialized else None,
    }


def candidate_breakdown(
    rows: list[dict[str, str]], field: str
) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[row.get(field, "UNKNOWN")].append(row)
    result: dict[str, dict[str, Any]] = {}
    for key, group in sorted(grouped.items()):
        accurate = sum(is_true(row.get("accurate")) for row in group)
        result[key] = {
            "candidates": len(group),
            "accurate": accurate,
            "accuracy": accurate / len(group) if group else None,
            "does_not_fix_original_group": sum(
                not is_true(row.get("fixes_original_group")) for row in group
            ),
            "introduces_severe_report": sum(
                not is_true(row.get("no_new_severe_reports")) for row in group
            ),
        }
    return result


def analyze(run_dir: Path) -> dict[str, Any]:
    candidates = [
        row
        for row in read_csv(run_dir / "candidate_results.csv")
        if row.get("status") == "ok"
    ]
    regions = read_csv(run_dir / "region_results.csv")
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))

    speedups = [
        float(row["graph_traversal_speedup"])
        for row in candidates
        if row.get("graph_traversal_speedup")
    ]
    records = [int(row.get("records", 0)) for row in regions]
    candidate_counts = [
        int(row.get("generated_candidates", 0)) for row in regions
    ]
    merge_rates = [
        float(row.get("root_cause_merge_rate", 0.0)) for row in regions
    ]
    region_metadata = {row["region"]: row for row in regions}
    local_dfs_paths = [
        float(row.get("affected_paths", 0.0)) for row in candidates
    ]
    local_work_ratios: list[float] = []
    local_work_ratios_by_kind: dict[str, list[float]] = defaultdict(list)
    for row in candidates:
        region_paths = int(region_metadata.get(row["region"], {}).get("paths", 0))
        if region_paths <= 0:
            continue
        ratio = 100.0 * float(row.get("affected_paths", 0.0)) / region_paths
        local_work_ratios.append(ratio)
        local_work_ratios_by_kind[row.get("kind", "UNKNOWN")].append(ratio)

    candidates_by_region: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in candidates:
        candidates_by_region[row["region"]].append(row)
    region_timing: list[dict[str, Any]] = []
    for region, group in candidates_by_region.items():
        incremental = sum(
            float(row.get("incremental_graph_traversal_seconds", 0.0))
            for row in group
        )
        full = sum(
            float(row.get("full_graph_traversal_seconds", 0.0))
            for row in group
        )
        metadata = region_metadata.get(region, {})
        region_timing.append(
            {
                "region": region,
                "records": int(metadata.get("records", 0)),
                "candidates": len(group),
                "incremental_seconds": incremental,
                "full_seconds": full,
                "speedup": full / incremental if incremental else None,
            }
        )

    return {
        "run_dir": str(run_dir),
        "selection": {
            "regions": len(regions),
            "records": describe(records),
            "candidates_per_region": describe(candidate_counts),
        },
        "candidate_diagnostics": {
            "total": len(candidates),
            "accurate": sum(
                is_true(row.get("accurate")) for row in candidates
            ),
            "does_not_fix_original_group": sum(
                not is_true(row.get("fixes_original_group"))
                for row in candidates
            ),
            "introduces_severe_report": sum(
                not is_true(row.get("no_new_severe_reports"))
                for row in candidates
            ),
            "by_kind": candidate_breakdown(candidates, "kind"),
            "by_risk": candidate_breakdown(candidates, "risk"),
        },
        "root_cause_grouping": {
            **summary["root_cause_grouping"],
            "regions_with_nonzero_merge": sum(
                rate > 0.0 for rate in merge_rates
            ),
            "max_region_merge_rate": max(merge_rates) if merge_rates else None,
        },
        "incremental_equivalence": summary["incremental_equivalence"],
        "incremental_locality": {
            "local_dfs_path_executions": describe(local_dfs_paths),
            "local_dfs_work_as_percentage_of_baseline_unique_paths": describe(
                local_work_ratios
            ),
            "local_dfs_work_percentage_by_kind": {
                kind: describe(values)
                for kind, values in sorted(local_work_ratios_by_kind.items())
            },
            "ratio_note": (
                "The numerator counts local DFS path executions from all affected "
                "starts, whereas the denominator is the region's unique baseline "
                "path count. Repeated execution can therefore make this diagnostic "
                "exceed 100%; it is not a set-based affected-path fraction."
            ),
        },
        "timing": {
            **summary["timing"],
            "candidate_speedup_distribution": describe(speedups),
            "candidates_where_incremental_is_faster": sum(
                speedup > 1.0 for speedup in speedups
            ),
            "incremental_faster_rate": (
                sum(speedup > 1.0 for speedup in speedups) / len(speedups)
                if speedups
                else None
            ),
            "slowest_incremental_regions": sorted(
                region_timing,
                key=lambda row: row["incremental_seconds"],
                reverse=True,
            )[:10],
            "worst_region_speedups": sorted(
                region_timing,
                key=lambda row: (
                    float("inf")
                    if row["speedup"] is None
                    else row["speedup"]
                ),
            )[:10],
        },
        "actions": {
            "single_action_candidates": sum(
                int(row.get("action_count", 0)) == 1 for row in candidates
            ),
            "multi_action_candidates": sum(
                int(row.get("action_count", 0)) > 1 for row in candidates
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize an Experiment 04 result directory."
    )
    parser.add_argument("run_dir", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        help="output JSON path; defaults to RUN_DIR/detailed_analysis.json",
    )
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    output = args.output or (run_dir / "detailed_analysis.json")
    result = analyze(run_dir)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    print(f"[result] {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
