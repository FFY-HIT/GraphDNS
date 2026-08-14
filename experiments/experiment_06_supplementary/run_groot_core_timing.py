#!/usr/bin/env python3
"""Measure official GRoot core timings on the paired Census sample.

The experiment reuses GraphDNS timings already stored by Experiment 01 and
reruns only the official GRoot binary with ``--stats``.  Container-launch and
adapter overhead are recorded separately from GRoot's own build/check timers.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sqlite3
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from statistics import median
from typing import Any

from groot_jsonl_wrapper import SHARED_PROPERTIES, host_to_container, normalize_name


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_RE = re.compile(
    r"Time to build label graph and zone graphs:\s*([0-9.eE+-]+)s"
)
CHECK_RE = re.compile(r"Time to check all user jobs:\s*([0-9.eE+-]+)s")
GRAPHDNS_TIMING_RE = re.compile(r"^Timing:\s+(.+)$", re.MULTILINE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pair official GRoot --stats timings with GraphDNS core timings."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--results-db", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--sample-size", type=int, default=1000)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument(
        "--reuse-groot-csv",
        type=Path,
        help="reuse official GRoot timings from a previous per-region CSV",
    )
    parser.add_argument("--container", default="graphdns-groot-baseline")
    parser.add_argument("--census-root", type=Path, default=Path("/path/to/census"))
    parser.add_argument(
        "--container-census-root", type=Path, default=Path("/data")
    )
    parser.add_argument("--host-workspace", type=Path, default=REPO_ROOT)
    parser.add_argument(
        "--container-workspace", type=Path, default=Path("/workspace")
    )
    parser.add_argument(
        "--groot-bin", default="/home/groot/groot/build/bin/groot"
    )
    parser.add_argument(
        "--preprocess-bin",
        type=Path,
        default=REPO_ROOT / "experiments" / "bin" / "preprocess",
    )
    parser.add_argument(
        "--semantic-bin",
        type=Path,
        default=REPO_ROOT / "experiments" / "bin" / "semantic_graph",
    )
    parser.add_argument(
        "--server-views",
        choices=("complete", "sampled"),
        default="sampled",
    )
    return parser.parse_args()


def parse_groot_stats(text: str) -> tuple[float, float]:
    build = BUILD_RE.search(text)
    check = CHECK_RE.search(text)
    if build is None or check is None:
        raise ValueError("official GRoot output is missing --stats build/check timers")
    return float(build.group(1)), float(check.group(1))


def parse_graphdns_timing(text: str) -> dict[str, float]:
    match = GRAPHDNS_TIMING_RE.search(text)
    if match is None:
        raise ValueError("GraphDNS output is missing the Timing line")
    values: dict[str, float] = {}
    for token in match.group(1).split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        values[key] = float(value)
    required = {
        "load_facts",
        "build_base",
        "build_semantic",
        "build_invariants",
        "compute_reach",
        "traverse_dfs",
        "detect_bugs",
        "total",
    }
    missing = sorted(required - values.keys())
    if missing:
        raise ValueError(
            "GraphDNS Timing line is missing: " + ", ".join(missing)
        )
    return values


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return math.nan
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def load_manifest(path: Path, sample_size: int) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if sample_size <= 0 or sample_size > len(rows):
        raise ValueError(f"sample-size must be in [1, {len(rows)}]")
    return rows[:sample_size]


def load_graphdns(path: Path) -> dict[str, dict[str, Any]]:
    connection = sqlite3.connect(path)
    try:
        rows = connection.execute(
            """
            SELECT r.name, e.wall_seconds, e.record_count, e.details_json
            FROM executions e
            JOIN regions r ON r.id = e.region_id
            WHERE e.system = 'graphdns' AND e.status = 'ok'
            """
        ).fetchall()
    finally:
        connection.close()
    result: dict[str, dict[str, Any]] = {}
    for name, wall_seconds, record_count, details_json in rows:
        details = json.loads(details_json)
        timing = details.get("timing", {})
        result[str(name)] = {
            "wall_seconds": float(wall_seconds),
            "record_count": int(record_count),
            "preprocess_seconds": float(details.get("preprocess_seconds", 0.0)),
            "semantic_total_seconds": float(
                timing.get("semantic_total_seconds", 0.0)
            ),
            "load_facts_seconds": float(timing.get("load_facts_seconds", 0.0)),
            "build_base_seconds": float(timing.get("build_base_seconds", 0.0)),
            "build_semantic_seconds": float(
                timing.get("build_semantic_seconds", 0.0)
            ),
            "build_invariants_seconds": float(
                timing.get("build_invariants_seconds", 0.0)
            ),
            "compute_reach_seconds": float(
                timing.get("compute_reach_seconds", 0.0)
            ),
            "traverse_dfs_seconds": float(
                timing.get(
                    "traverse_dfs_seconds",
                    timing.get("traverse_core_seconds", 0.0),
                )
            ),
            "detect_bugs_seconds": float(timing.get("detect_bugs_seconds", 0.0)),
        }
    return result


def load_reused_groot(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    return {
        str(row["region"]): row
        for row in rows
        if row.get("status") == "ok"
    }


def run_graphdns_core(
    region: Path,
    workdir: Path,
    args: argparse.Namespace,
) -> dict[str, Any]:
    facts_path = workdir / "ZoneRecord.facts"
    preprocess_started = time.perf_counter()
    preprocess = subprocess.run(
        [str(args.preprocess_bin), str(region)],
        cwd=workdir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=args.timeout,
        check=False,
    )
    preprocess_wall = time.perf_counter() - preprocess_started
    if preprocess.returncode != 0 or not facts_path.is_file():
        raise RuntimeError(
            "GraphDNS preprocessing failed: " + preprocess.stdout[-1000:]
        )

    output_path = workdir / "graphdns_timing.txt"
    semantic_started = time.perf_counter()
    semantic = subprocess.run(
        [
            str(args.semantic_bin),
            str(facts_path),
            "--reports-only",
            "--timing",
            "--threads",
            "1",
            "--server-views",
            args.server_views,
            "-o",
            str(output_path),
        ],
        cwd=workdir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=args.timeout,
        check=False,
    )
    semantic_wall = time.perf_counter() - semantic_started
    if semantic.returncode != 0 or not output_path.is_file():
        raise RuntimeError(
            "GraphDNS semantic analysis failed: " + semantic.stdout[-1000:]
        )
    timing = parse_graphdns_timing(
        output_path.read_text(encoding="utf-8", errors="replace")
    )
    return {
        "wall_seconds": semantic_wall,
        "preprocess_seconds": preprocess_wall,
        "semantic_total_seconds": timing["total"],
        "load_facts_seconds": timing["load_facts"],
        "build_base_seconds": timing["build_base"],
        "build_semantic_seconds": timing["build_semantic"],
        "build_invariants_seconds": timing["build_invariants"],
        "compute_reach_seconds": timing["compute_reach"],
        "traverse_dfs_seconds": timing["traverse_dfs"],
        "detect_bugs_seconds": timing["detect_bugs"],
    }


def run_one(
    row: dict[str, str],
    graphdns: dict[str, Any],
    args: argparse.Namespace,
    reused_groot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    name = row["name"]
    region = Path(row["path"]).resolve()
    workdir = (args.output_dir / "work" / f"{int(row['sample_rank']):05d}").resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        graphdns = {
            **graphdns,
            **run_graphdns_core(region, workdir, args),
        }
    except (RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        return {
            "sample_rank": int(row["sample_rank"]),
            "region": name,
            "status": "graphdns_error",
            "error": str(exc),
            **graphdns,
        }

    if reused_groot is not None:
        groot_build = float(reused_groot["groot_build_seconds"])
        groot_check = float(reused_groot["groot_check_seconds"])
        groot_core = groot_build + groot_check
        graphdns_core = graphdns["semantic_total_seconds"]
        return {
            "sample_rank": int(row["sample_rank"]),
            "region": name,
            "status": "ok",
            **graphdns,
            "groot_build_seconds": groot_build,
            "groot_check_seconds": groot_check,
            "groot_core_seconds": groot_core,
            "groot_wrapper_wall_seconds": float(
                reused_groot["groot_wrapper_wall_seconds"]
            ),
            "paired_core_ratio_groot_over_graphdns": (
                groot_core / graphdns_core if graphdns_core > 0.0 else math.nan
            ),
            "error": "",
        }

    jobs_path = workdir / "jobs.json"
    raw_path = workdir / "raw.json"
    jobs_path.write_text(
        json.dumps(
            [
                {
                    "Domain": normalize_name(name),
                    "SubDomain": True,
                    "Properties": SHARED_PROPERTIES,
                }
            ],
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    container_region = args.container_census_root / region.relative_to(
        args.census_root.resolve()
    )
    container_workdir = host_to_container(
        workdir, args.host_workspace, args.container_workspace
    )
    container_jobs = host_to_container(
        jobs_path, args.host_workspace, args.container_workspace
    )
    container_raw = host_to_container(
        raw_path, args.host_workspace, args.container_workspace
    )
    command = [
        "docker",
        "exec",
        "--workdir",
        str(container_workdir),
        args.container,
        args.groot_bin,
        str(container_region),
        f"--jobs={container_jobs}",
        f"--output={container_raw}",
        "--stats",
    ]
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=args.timeout,
            check=False,
        )
        wall = time.perf_counter() - started
    except subprocess.TimeoutExpired as exc:
        return {
            "sample_rank": int(row["sample_rank"]),
            "region": name,
            "status": "timeout",
            "error": f"timeout after {args.timeout}s",
            **graphdns,
        }
    if completed.returncode != 0:
        return {
            "sample_rank": int(row["sample_rank"]),
            "region": name,
            "status": "error",
            "error": completed.stdout[-1000:],
            "groot_wrapper_wall_seconds": wall,
            **graphdns,
        }
    try:
        groot_build, groot_check = parse_groot_stats(completed.stdout)
    except ValueError as exc:
        return {
            "sample_rank": int(row["sample_rank"]),
            "region": name,
            "status": "error",
            "error": str(exc),
            "groot_wrapper_wall_seconds": wall,
            **graphdns,
        }
    graphdns_core = graphdns["semantic_total_seconds"]
    groot_core = groot_build + groot_check
    return {
        "sample_rank": int(row["sample_rank"]),
        "region": name,
        "status": "ok",
        **graphdns,
        "groot_build_seconds": groot_build,
        "groot_check_seconds": groot_check,
        "groot_core_seconds": groot_core,
        "groot_wrapper_wall_seconds": wall,
        "paired_core_ratio_groot_over_graphdns": (
            groot_core / graphdns_core if graphdns_core > 0.0 else math.nan
        ),
        "error": "",
    }


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    successful = [row for row in rows if row["status"] == "ok"]
    fields = (
        "graphdns_wall_seconds",
        "preprocess_seconds",
        "semantic_total_seconds",
        "groot_build_seconds",
        "groot_check_seconds",
        "groot_core_seconds",
        "groot_wrapper_wall_seconds",
        "paired_core_ratio_groot_over_graphdns",
    )
    summary: dict[str, Any] = {
        "requested_regions": len(rows),
        "successful_regions": len(successful),
        "failed_regions": len(rows) - len(successful),
        "timing_scope": {
            "graphdns_core": "semantic_total_seconds from GraphDNS Timing output; preprocessing excluded",
            "groot_core": "official --stats build-label/zone-graphs plus check-user-jobs timers",
            "wrapper_wall": "docker exec, process startup, I/O, and adapter overhead included",
        },
    }
    for field in fields:
        source = (
            "wall_seconds"
            if field == "graphdns_wall_seconds"
            else field
        )
        values = [
            float(row[source])
            for row in successful
            if source in row and math.isfinite(float(row[source]))
        ]
        summary[field] = {
            "sum": sum(values),
            "median": median(values) if values else math.nan,
            "p95": percentile(values, 0.95),
        }
    graphdns_sum = summary["semantic_total_seconds"]["sum"]
    groot_sum = summary["groot_core_seconds"]["sum"]
    summary["aggregate_core_ratio_groot_over_graphdns"] = (
        groot_sum / graphdns_sum if graphdns_sum > 0.0 else math.nan
    )
    return summary


def main() -> int:
    args = parse_args()
    args.output_dir = args.output_dir.resolve()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest = load_manifest(args.manifest.resolve(), args.sample_size)
    graphdns_by_region = load_graphdns(args.results_db.resolve())
    reused_groot = load_reused_groot(
        args.reuse_groot_csv.resolve() if args.reuse_groot_csv else None
    )
    missing = [row["name"] for row in manifest if row["name"] not in graphdns_by_region]
    if missing:
        raise RuntimeError(
            f"{len(missing)} sampled regions have no successful GraphDNS timing"
        )

    rows: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {
            executor.submit(
                run_one,
                row,
                graphdns_by_region[row["name"]],
                args,
                reused_groot.get(row["name"]),
            ): row
            for row in manifest
        }
        for completed, future in enumerate(as_completed(futures), start=1):
            rows.append(future.result())
            if completed % 50 == 0 or completed == len(futures):
                print(f"[progress] regions={completed}/{len(futures)}", flush=True)

    rows.sort(key=lambda row: int(row["sample_rank"]))
    fieldnames = sorted({key for row in rows for key in row})
    with (args.output_dir / "per_region_timing.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    summary = summarize(rows)
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        f"[done] successful={summary['successful_regions']}/"
        f"{summary['requested_regions']}",
        flush=True,
    )
    print(f"[result] {args.output_dir}", flush=True)
    return 0 if summary["failed_regions"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
