#!/usr/bin/env python3
"""Measure SRAG scalability on nested Census region sets.

Each scale is preprocessed into one facts file and analyzed by one
semantic_graph process. Peak RSS is sampled from the actual preprocess and
semantic_graph process trees. Region subsets are nested and reproducible.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

import psutil


SUMMARY_RE = re.compile(
    r"\b(?P<key>servers|zones|nodes|edges|paths|bugs)=(?P<value>[0-9]+)"
)
TIMING_RE = re.compile(r"\b(?P<key>[A-Za-z_]+)=(?P<value>[0-9.eE+-]+)")


@dataclass
class ScaleResult:
    target_regions: int
    selected_regions: int
    is_full_census: bool
    records: int
    nodes: int
    edges: int
    paths: int
    edge_node_ratio: float
    graph_build_seconds: float
    traverse_dfs_seconds: float
    semantic_total_seconds: float
    preprocess_wall_seconds: float
    semantic_wall_seconds: float
    preprocess_peak_rss_mb: float
    semantic_peak_rss_mb: float
    pipeline_peak_rss_mb: float
    status: str
    error: str


def parse_counts(text: str) -> list[int | str]:
    values: list[int | str] = []
    for item in text.split(","):
        item = item.strip().lower().replace("_", "")
        if not item:
            continue
        if item == "full":
            values.append("full")
            continue
        value = int(item)
        if value <= 0:
            raise argparse.ArgumentTypeError("region counts must be positive")
        values.append(value)
    if not values:
        raise argparse.ArgumentTypeError("at least one region count is required")
    return values


def discover_regions(census_dir: Path) -> list[Path]:
    regions: list[Path] = []
    with os.scandir(census_dir) as entries:
        for entry in entries:
            if not entry.is_dir(follow_symlinks=False):
                continue
            path = Path(entry.path)
            if (path / "metadata.json").is_file():
                regions.append(path)
    regions.sort(key=lambda path: path.name)
    return regions


def write_csv(path: Path, rows: Iterable[ScaleResult]) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        if not rows:
            return
        writer = csv.DictWriter(handle, fieldnames=list(asdict(rows[0]).keys()))
        writer.writeheader()
        writer.writerows(asdict(row) for row in rows)


def count_lines(path: Path) -> int:
    count = 0
    with path.open("rb") as handle:
        while chunk := handle.read(8 * 1024 * 1024):
            count += chunk.count(b"\n")
    return count


def process_tree_rss(process: psutil.Process) -> int:
    rss = 0
    processes = [process]
    try:
        processes.extend(process.children(recursive=True))
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    for current in processes:
        try:
            rss += current.memory_info().rss
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return rss


def run_monitored(
    command: list[str],
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
    env: dict[str, str],
    sample_interval: float,
) -> tuple[int, float, float]:
    started = time.perf_counter()
    peak_rss = 0
    with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open(
        "w", encoding="utf-8"
    ) as stderr:
        child = subprocess.Popen(
            command,
            cwd=cwd,
            stdout=stdout,
            stderr=stderr,
            env=env,
            text=True,
        )
        monitored = psutil.Process(child.pid)
        while child.poll() is None:
            peak_rss = max(peak_rss, process_tree_rss(monitored))
            time.sleep(sample_interval)
        peak_rss = max(peak_rss, process_tree_rss(monitored))
        return_code = child.wait()
    wall_seconds = time.perf_counter() - started
    return return_code, wall_seconds, peak_rss / (1024.0 * 1024.0)


def parse_semantic_output(path: Path) -> tuple[dict[str, int], dict[str, float]]:
    summary: dict[str, int] = {}
    timing: dict[str, float] = {}
    if not path.exists():
        return summary, timing
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("Summary:"):
            summary = {
                match.group("key"): int(match.group("value"))
                for match in SUMMARY_RE.finditer(line)
            }
        elif line.startswith("Timing:"):
            timing = {
                match.group("key"): float(match.group("value"))
                for match in TIMING_RE.finditer(line)
            }
    return summary, timing


def ensure_links(stage_dir: Path, regions: list[Path], linked: int, target: int) -> int:
    stage_dir.mkdir(parents=True, exist_ok=True)
    for index in range(linked, target):
        region = regions[index]
        link = stage_dir / f"{index:06d}_{region.name}"
        if not link.exists():
            link.symlink_to(region, target_is_directory=True)
        if (index + 1) % 10_000 == 0:
            print(f"[stage] linked={index + 1:,}/{target:,}", flush=True)
    return target


def build_binaries(repo_root: Path, preprocess_bin: Path, semantic_bin: Path) -> None:
    preprocess_bin.parent.mkdir(parents=True, exist_ok=True)
    commands = [
        [
            "g++",
            "-O3",
            "-std=c++17",
            "-fopenmp",
            str(repo_root / "src" / "preprocess.cpp"),
            "-o",
            str(preprocess_bin),
        ],
        [
            "g++",
            "-O3",
            "-std=c++17",
            "-fopenmp",
            str(repo_root / "src" / "semantic_graph.cpp"),
            "-o",
            str(semantic_bin),
        ],
    ]
    for command in commands:
        print("[build]", " ".join(command), flush=True)
        subprocess.run(command, cwd=repo_root, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--census-dir", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument(
        "--counts",
        type=parse_counts,
        default=parse_counts("1000,5000,10000,50000,100000,full"),
    )
    parser.add_argument("--seed", type=int, default=20260729)
    parser.add_argument("--threads", type=int, default=16)
    parser.add_argument("--sample-interval", type=float, default=0.01)
    parser.add_argument("--work-dir", type=Path, default=None)
    parser.add_argument("--preprocess-bin", type=Path, default=None)
    parser.add_argument("--semantic-bin", type=Path, default=None)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--keep-facts", action="store_true")
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    census_dir = args.census_dir.resolve()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    work_dir = (
        args.work_dir.resolve()
        if args.work_dir
        else repo_root / "experiments" / "runs" / f"exp07_scalability_{timestamp}"
    )
    work_dir.mkdir(parents=True, exist_ok=True)
    preprocess_bin = (
        args.preprocess_bin.resolve()
        if args.preprocess_bin
        else repo_root / "experiments" / "bin" / "preprocess"
    )
    semantic_bin = (
        args.semantic_bin.resolve()
        if args.semantic_bin
        else repo_root / "experiments" / "bin" / "semantic_graph"
    )
    if args.build:
        build_binaries(repo_root, preprocess_bin, semantic_bin)
    if not preprocess_bin.is_file() or not semantic_bin.is_file():
        raise FileNotFoundError("preprocess/semantic_graph binary is missing; use --build")

    print(f"[scan] census={census_dir}", flush=True)
    regions = discover_regions(census_dir)
    if not regions:
        raise RuntimeError("no complete Census regions found")
    random.Random(args.seed).shuffle(regions)
    total_regions = len(regions)
    requested = [
        total_regions if value == "full" else int(value) for value in args.counts
    ]
    counts = sorted(set(value for value in requested if value <= total_regions))
    if total_regions not in counts and "full" in args.counts:
        counts.append(total_regions)
    print(f"[scan] complete_regions={total_regions:,} counts={counts}", flush=True)

    (work_dir / "selected_regions.txt").write_text(
        "\n".join(str(path) for path in regions) + "\n", encoding="utf-8"
    )
    manifest = {
        "created_at": timestamp,
        "census_dir": str(census_dir),
        "complete_regions": total_regions,
        "counts": counts,
        "seed": args.seed,
        "threads": args.threads,
        "sample_interval_seconds": args.sample_interval,
        "measurement": (
            "One combined facts file and one semantic_graph process per scale; "
            "peak RSS is the maximum sampled resident memory of each process tree."
        ),
    }
    (work_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    results_path = work_dir / "scalability.csv"
    completed: dict[int, ScaleResult] = {}
    if results_path.exists():
        with results_path.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                if row.get("status") != "ok":
                    continue
                completed[int(row["target_regions"])] = ScaleResult(
                    target_regions=int(row["target_regions"]),
                    selected_regions=int(row["selected_regions"]),
                    is_full_census=row["is_full_census"].lower() == "true",
                    records=int(row["records"]),
                    nodes=int(row["nodes"]),
                    edges=int(row["edges"]),
                    paths=int(row["paths"]),
                    edge_node_ratio=float(row["edge_node_ratio"]),
                    graph_build_seconds=float(row["graph_build_seconds"]),
                    traverse_dfs_seconds=float(row["traverse_dfs_seconds"]),
                    semantic_total_seconds=float(row["semantic_total_seconds"]),
                    preprocess_wall_seconds=float(row["preprocess_wall_seconds"]),
                    semantic_wall_seconds=float(row["semantic_wall_seconds"]),
                    preprocess_peak_rss_mb=float(row["preprocess_peak_rss_mb"]),
                    semantic_peak_rss_mb=float(row["semantic_peak_rss_mb"]),
                    pipeline_peak_rss_mb=float(row["pipeline_peak_rss_mb"]),
                    status=row["status"],
                    error=row["error"],
                )

    env = os.environ.copy()
    env["OMP_NUM_THREADS"] = str(args.threads)
    stage_dir = work_dir / "_region_links"
    linked = 0
    rows: list[ScaleResult] = list(completed.values())
    for count in counts:
        if count in completed:
            linked = ensure_links(stage_dir, regions, linked, min(count, total_regions - 1))
            print(f"[skip] regions={count:,}", flush=True)
            continue

        is_full = count == total_regions
        if is_full:
            input_dir = census_dir
        else:
            linked = ensure_links(stage_dir, regions, linked, count)
            input_dir = stage_dir

        case_dir = work_dir / f"regions_{count}"
        case_dir.mkdir(parents=True, exist_ok=True)
        facts_path = case_dir / "ZoneRecord.facts"
        semantic_output = case_dir / "semantic_output.txt"
        print(f"[run] regions={count:,} full={is_full}", flush=True)

        pp_rc, pp_wall, pp_rss = run_monitored(
            [str(preprocess_bin), str(input_dir)],
            case_dir,
            case_dir / "preprocess.stdout.log",
            case_dir / "preprocess.stderr.log",
            env,
            args.sample_interval,
        )
        records = count_lines(facts_path) if facts_path.exists() else 0
        if pp_rc != 0 or records == 0:
            result = ScaleResult(
                count,
                count,
                is_full,
                records,
                0,
                0,
                0,
                0.0,
                0.0,
                0.0,
                0.0,
                pp_wall,
                0.0,
                pp_rss,
                0.0,
                pp_rss,
                "error",
                f"preprocess rc={pp_rc}",
            )
            rows.append(result)
            write_csv(results_path, sorted(rows, key=lambda item: item.target_regions))
            print(f"[error] {result.error}", flush=True)
            break

        semantic_command = [
            str(semantic_bin),
            str(facts_path),
            "--summary-only",
            "--timing",
            "--threads",
            str(args.threads),
            "-o",
            str(semantic_output),
        ]
        sem_rc, sem_wall, sem_rss = run_monitored(
            semantic_command,
            case_dir,
            case_dir / "semantic.stdout.log",
            case_dir / "semantic.stderr.log",
            env,
            args.sample_interval,
        )
        summary, timing = parse_semantic_output(semantic_output)
        graph_build = sum(
            timing.get(key, 0.0)
            for key in (
                "load_facts",
                "build_base",
                "build_semantic",
                "build_invariants",
            )
        )
        nodes = summary.get("nodes", 0)
        edges = summary.get("edges", 0)
        result = ScaleResult(
            target_regions=count,
            selected_regions=count,
            is_full_census=is_full,
            records=records,
            nodes=nodes,
            edges=edges,
            paths=summary.get("paths", 0),
            edge_node_ratio=edges / nodes if nodes else 0.0,
            graph_build_seconds=graph_build,
            traverse_dfs_seconds=timing.get("traverse_dfs", 0.0),
            semantic_total_seconds=timing.get("total", 0.0),
            preprocess_wall_seconds=pp_wall,
            semantic_wall_seconds=sem_wall,
            preprocess_peak_rss_mb=pp_rss,
            semantic_peak_rss_mb=sem_rss,
            pipeline_peak_rss_mb=max(pp_rss, sem_rss),
            status="ok" if sem_rc == 0 and nodes > 0 else "error",
            error="" if sem_rc == 0 else f"semantic_graph rc={sem_rc}",
        )
        rows.append(result)
        rows.sort(key=lambda item: item.target_regions)
        write_csv(results_path, rows)
        print(
            f"[done] regions={count:,} records={records:,} nodes={nodes:,} "
            f"edges={edges:,} build={graph_build:.3f}s "
            f"traverse={result.traverse_dfs_seconds:.3f}s "
            f"peak={result.semantic_peak_rss_mb:.1f}MB status={result.status}",
            flush=True,
        )
        if not args.keep_facts:
            try:
                facts_path.unlink()
            except FileNotFoundError:
                pass
        if result.status != "ok":
            break

    print(f"[result] {results_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
