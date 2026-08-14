#!/usr/bin/env python3
"""
Run large-scale GraphDNS validation on complete census regions.

For each benchmark case, the script selects a number of complete region
directories from the census dataset.  Each selected region is preprocessed and
validated independently.  The reported total_validation_seconds is the sum of
semantic_graph internal validation time only; preprocess time and script/output
overhead are not included.  Graph scale and build-stage details are parsed from
semantic_graph output after validation and are reported as separate columns.
"""

from __future__ import annotations

import argparse
import csv
import json
import platform
import random
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple


DEFAULT_REGION_COUNTS = [1, 5, 10, 50, 100, 500, 1_000, 10_000]
TIMING_TOTAL_RE = re.compile(r"Timing:.*\btotal=(?P<total>[0-9.eE+-]+)")
TIMING_FIELD_RE = re.compile(r"\b(?P<key>[A-Za-z_]+)=(?P<value>[0-9.eE+-]+)")
SUMMARY_FIELD_RE = re.compile(r"\b(?P<key>servers|zones|nodes|edges|paths|bugs)=(?P<value>[0-9]+)")
SEMANTIC_STATS_FIELD_RE = re.compile(r"\b(?P<key>[A-Za-z_]+)=(?P<value>[0-9]+)")
BUG_STATS_FIELD_RE = re.compile(r"\b(?P<key>[A-Za-z_]+)=(?P<value>[0-9]+)")
VALIDATION_TIMING_FIELDS = ("compute_reach", "traverse_dfs", "detect_bugs")


@dataclass
class RegionInfo:
    name: str
    path: str
    txt_files: int
    bytes: int


@dataclass
class RegionValidationResult:
    records: int
    validation_seconds: float
    wall_seconds: float
    ok: bool
    servers: int = 0
    zones: int = 0
    nodes: int = 0
    edges: int = 0
    paths: int = 0
    bugs: int = 0
    stale_records: int = 0
    load_facts_seconds: float = 0.0
    build_base_seconds: float = 0.0
    build_semantic_seconds: float = 0.0
    build_invariants_seconds: float = 0.0
    compute_reach_seconds: float = 0.0
    traverse_dfs_seconds: float = 0.0
    detect_bugs_seconds: float = 0.0
    semantic_total_seconds: float = 0.0
    semantic_owner_nodes: int = 0
    semantic_base_ns: int = 0
    semantic_base_cname: int = 0
    semantic_base_dname: int = 0
    del_candidates_checked: int = 0
    crew_candidates_checked: int = 0
    drew_candidates_checked: int = 0
    del_edges_added: int = 0
    crew_edges_added: int = 0
    drew_edges_added: int = 0
    error: str = ""


@dataclass
class AggregateResult:
    target_regions: int
    selected_regions: int
    total_records: int
    total_validation_seconds: float
    validation_wall_seconds: float
    total_servers: int
    total_zones: int
    total_nodes: int
    total_edges: int
    total_paths: int
    total_bugs: int
    total_stale_records: int
    load_facts_seconds: float
    build_base_seconds: float
    build_semantic_seconds: float
    build_invariants_seconds: float
    graph_build_seconds: float
    compute_reach_seconds: float
    traverse_dfs_seconds: float
    detect_bugs_seconds: float
    semantic_total_seconds: float
    semantic_owner_nodes: int
    semantic_base_ns: int
    semantic_base_cname: int
    semantic_base_dname: int
    del_candidates_checked: int
    crew_candidates_checked: int
    drew_candidates_checked: int
    del_edges_added: int
    crew_edges_added: int
    drew_edges_added: int
    failed_regions: int
    status: str
    case_dir: str = ""
    error: str = ""


@dataclass
class RegionResultRow:
    target_regions: int
    region_rank: int
    region_name: str
    region_path: str
    records: int
    validation_seconds: float
    wall_seconds: float
    status: str
    servers: int
    zones: int
    nodes: int
    edges: int
    paths: int
    bugs: int
    stale_records: int
    load_facts_seconds: float
    build_base_seconds: float
    build_semantic_seconds: float
    build_invariants_seconds: float
    graph_build_seconds: float
    compute_reach_seconds: float
    traverse_dfs_seconds: float
    detect_bugs_seconds: float
    semantic_total_seconds: float
    semantic_owner_nodes: int
    semantic_base_ns: int
    semantic_base_cname: int
    semantic_base_dname: int
    del_candidates_checked: int
    crew_candidates_checked: int
    drew_candidates_checked: int
    del_edges_added: int
    crew_edges_added: int
    drew_edges_added: int
    scratch_dir: str
    facts_path: str
    semantic_output_path: str
    error: str = ""


def parse_counts(value: str) -> List[int]:
    counts: List[int] = []
    for part in value.split(","):
        part = part.strip().replace("_", "")
        if not part:
            continue
        n = int(part)
        if n <= 0:
            raise argparse.ArgumentTypeError("counts must be positive")
        counts.append(n)
    if not counts:
        raise argparse.ArgumentTypeError("at least one count is required")
    return sorted(set(counts))


def discover_regions(census_dir: Path) -> List[RegionInfo]:
    if not census_dir.exists():
        raise FileNotFoundError(f"census directory does not exist: {census_dir}")

    regions: List[RegionInfo] = []
    for child in sorted(census_dir.iterdir(), key=lambda p: p.name):
        if not child.is_dir():
            continue
        if not (child / "metadata.json").exists():
            continue
        txt_files = list(child.rglob("*.txt"))
        if not txt_files:
            continue
        total_bytes = sum(p.stat().st_size for p in txt_files if p.exists())
        regions.append(
            RegionInfo(
                name=child.name,
                path=str(child.resolve()),
                txt_files=len(txt_files),
                bytes=total_bytes,
            )
        )
    return regions


def executable_name(base: str) -> str:
    return base + ".exe" if platform.system().lower().startswith("win") else base


def resolve_executable(repo_root: Path, explicit: Optional[str], base: str) -> Path:
    if explicit:
        return Path(explicit).resolve()
    candidates = [
        repo_root / executable_name(base),
        repo_root / base,
        repo_root / "src" / executable_name(base),
        repo_root / "src" / base,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return (repo_root / executable_name(base)).resolve()


def binary_is_stale(binary: Path, sources: Sequence[Path]) -> bool:
    if not binary.exists():
        return True
    try:
        binary_mtime = binary.stat().st_mtime
    except OSError:
        return True
    for source in sources:
        try:
            if source.stat().st_mtime > binary_mtime:
                return True
        except OSError:
            return True
    return False


def build_binaries(repo_root: Path, preprocess_bin: Path, semantic_bin: Path) -> None:
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
    for cmd in commands:
        print("[build]", " ".join(cmd), flush=True)
        subprocess.run(cmd, cwd=str(repo_root), check=True)


def run_command(
    cmd: Sequence[str],
    cwd: Path,
    log_path: Path,
    timeout: Optional[float],
) -> Tuple[int, float]:
    start = time.perf_counter()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8", errors="replace") as log:
        log.write("$ " + " ".join(cmd) + "\n\n")
        log.flush()
        try:
            proc = subprocess.run(
                list(cmd),
                cwd=str(cwd),
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
            )
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            log.write(f"\nTIMEOUT after {timeout} seconds\n")
            rc = 124
        except Exception as exc:
            log.write(f"\nERROR: {exc}\n")
            rc = 125
    return rc, time.perf_counter() - start


def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        return sum(1 for _ in f)


def safe_region_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)


def parse_timing_fields(output_path: Path) -> dict[str, float]:
    if not output_path.exists():
        return {}
    text = output_path.read_text(encoding="utf-8", errors="ignore")
    timing_line = ""
    for line in text.splitlines():
        if line.startswith("Timing:"):
            timing_line = line
            break
    if not timing_line:
        return {}
    return {m.group("key"): float(m.group("value")) for m in TIMING_FIELD_RE.finditer(timing_line)}


def parse_summary_fields(output_path: Path) -> dict[str, int]:
    if not output_path.exists():
        return {}
    text = output_path.read_text(encoding="utf-8", errors="ignore")
    summary_line = ""
    for line in text.splitlines():
        if line.startswith("Summary:"):
            summary_line = line
            break
    if not summary_line:
        return {}
    return {m.group("key"): int(m.group("value")) for m in SUMMARY_FIELD_RE.finditer(summary_line)}


def parse_semantic_build_stats(output_path: Path) -> dict[str, int]:
    if not output_path.exists():
        return {}
    text = output_path.read_text(encoding="utf-8", errors="ignore")
    stats_line = ""
    for line in text.splitlines():
        if line.startswith("SemanticBuildStats:"):
            stats_line = line
            break
    if not stats_line:
        return {}
    return {m.group("key"): int(m.group("value")) for m in SEMANTIC_STATS_FIELD_RE.finditer(stats_line)}


def parse_bug_stats(output_path: Path) -> dict[str, int]:
    if not output_path.exists():
        return {}
    text = output_path.read_text(encoding="utf-8", errors="ignore")
    stats_line = ""
    for line in text.splitlines():
        if line.startswith("BugStats:"):
            stats_line = line
            break
    if not stats_line or "<none>" in stats_line:
        return {}
    return {m.group("key"): int(m.group("value")) for m in BUG_STATS_FIELD_RE.finditer(stats_line)}


def parse_validation_seconds(output_path: Path, metric: str) -> Optional[float]:
    timing = parse_timing_fields(output_path)
    if not timing:
        return None
    if metric == "total":
        return timing.get("total")
    if metric == "traverse":
        return timing.get("traverse_dfs")
    if metric == "validation":
        return sum(timing.get(key, 0.0) for key in VALIDATION_TIMING_FIELDS)
    return timing.get("total")


def write_csv(path: Path, rows: Iterable[AggregateResult]) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(rows[0]).keys()) if rows else [])
        if rows:
            writer.writeheader()
            for row in rows:
                writer.writerow(asdict(row))


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_graph_build_summary(path: Path, rows: Sequence[AggregateResult]) -> None:
    fieldnames = [
        "target_regions",
        "selected_regions",
        "total_records",
        "total_servers",
        "total_zones",
        "total_nodes",
        "total_edges",
        "total_paths",
        "total_bugs",
        "total_stale_records",
        "load_facts_seconds",
        "build_base_seconds",
        "build_semantic_seconds",
        "build_invariants_seconds",
        "graph_build_seconds",
        "compute_reach_seconds",
        "traverse_dfs_seconds",
        "detect_bugs_seconds",
        "total_validation_seconds",
        "semantic_total_seconds",
        "semantic_owner_nodes",
        "semantic_base_ns",
        "semantic_base_cname",
        "semantic_base_dname",
        "del_candidates_checked",
        "crew_candidates_checked",
        "drew_candidates_checked",
        "del_edges_added",
        "crew_edges_added",
        "drew_edges_added",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            data = asdict(row)
            writer.writerow({key: data.get(key, "") for key in fieldnames})


def write_region_results(path: Path, rows: Sequence[RegionResultRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        fieldnames = list(asdict(rows[0]).keys()) if rows else [
            field.name for field in RegionResultRow.__dataclass_fields__.values()
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def make_region_result_row(
    target_regions: int,
    rank: int,
    region: RegionInfo,
    result: RegionValidationResult,
    scratch_root: Path,
) -> RegionResultRow:
    scratch_dir = scratch_root / safe_region_name(region.name)
    return RegionResultRow(
        target_regions=target_regions,
        region_rank=rank,
        region_name=region.name,
        region_path=region.path,
        records=result.records,
        validation_seconds=result.validation_seconds,
        wall_seconds=result.wall_seconds,
        status="ok" if result.ok else "error",
        servers=result.servers,
        zones=result.zones,
        nodes=result.nodes,
        edges=result.edges,
        paths=result.paths,
        bugs=result.bugs,
        stale_records=result.stale_records,
        load_facts_seconds=result.load_facts_seconds,
        build_base_seconds=result.build_base_seconds,
        build_semantic_seconds=result.build_semantic_seconds,
        build_invariants_seconds=result.build_invariants_seconds,
        graph_build_seconds=(
            result.load_facts_seconds +
            result.build_base_seconds +
            result.build_semantic_seconds +
            result.build_invariants_seconds
        ),
        compute_reach_seconds=result.compute_reach_seconds,
        traverse_dfs_seconds=result.traverse_dfs_seconds,
        detect_bugs_seconds=result.detect_bugs_seconds,
        semantic_total_seconds=result.semantic_total_seconds,
        semantic_owner_nodes=result.semantic_owner_nodes,
        semantic_base_ns=result.semantic_base_ns,
        semantic_base_cname=result.semantic_base_cname,
        semantic_base_dname=result.semantic_base_dname,
        del_candidates_checked=result.del_candidates_checked,
        crew_candidates_checked=result.crew_candidates_checked,
        drew_candidates_checked=result.drew_candidates_checked,
        del_edges_added=result.del_edges_added,
        crew_edges_added=result.crew_edges_added,
        drew_edges_added=result.drew_edges_added,
        scratch_dir=str(scratch_dir),
        facts_path=str(scratch_dir / "ZoneRecord.facts"),
        semantic_output_path=str(scratch_dir / "semantic_output.txt"),
        error=result.error,
    )


def validate_one_region(
    region: RegionInfo,
    scratch_dir: Path,
    preprocess_bin: Path,
    semantic_bin: Path,
    threads: int,
    timeout: Optional[float],
    time_metric: str,
) -> RegionValidationResult:
    scratch_dir.mkdir(parents=True, exist_ok=True)
    facts_path = scratch_dir / "ZoneRecord.facts"
    semantic_output = scratch_dir / "semantic_output.txt"
    for old_file in (
        facts_path,
        semantic_output,
        scratch_dir / "preprocess.log",
        scratch_dir / "semantic_graph.log",
    ):
        try:
            old_file.unlink()
        except FileNotFoundError:
            pass

    pp_rc, _ = run_command(
        [str(preprocess_bin), region.path],
        cwd=scratch_dir,
        log_path=scratch_dir / "preprocess.log",
        timeout=timeout,
    )
    records = count_lines(facts_path)
    if pp_rc != 0 or records == 0:
        return RegionValidationResult(
            records=records,
            validation_seconds=0.0,
            wall_seconds=0.0,
            ok=False,
            error=f"preprocess rc={pp_rc}",
        )

    semantic_cmd = [
        str(semantic_bin),
        str(facts_path),
        "--summary-only",
        "--timing",
        "-o",
        str(semantic_output),
    ]
    if threads > 0:
        semantic_cmd.extend(["--threads", str(threads)])

    sem_rc, wall_seconds = run_command(
        semantic_cmd,
        cwd=scratch_dir,
        log_path=scratch_dir / "semantic_graph.log",
        timeout=timeout,
    )
    validation_seconds = parse_validation_seconds(semantic_output, time_metric)
    if validation_seconds is None:
        validation_seconds = wall_seconds
    summary = parse_summary_fields(semantic_output)
    timing = parse_timing_fields(semantic_output)
    stats = parse_semantic_build_stats(semantic_output)
    bug_stats = parse_bug_stats(semantic_output)
    return RegionValidationResult(
        records=records,
        validation_seconds=validation_seconds,
        wall_seconds=wall_seconds,
        ok=sem_rc == 0,
        servers=summary.get("servers", 0),
        zones=summary.get("zones", 0),
        nodes=summary.get("nodes", 0),
        edges=summary.get("edges", 0),
        paths=summary.get("paths", 0),
        bugs=summary.get("bugs", 0),
        stale_records=bug_stats.get("STALE", 0),
        load_facts_seconds=timing.get("load_facts", 0.0),
        build_base_seconds=timing.get("build_base", 0.0),
        build_semantic_seconds=timing.get("build_semantic", 0.0),
        build_invariants_seconds=timing.get("build_invariants", 0.0),
        compute_reach_seconds=timing.get("compute_reach", 0.0),
        traverse_dfs_seconds=timing.get("traverse_dfs", 0.0),
        detect_bugs_seconds=timing.get("detect_bugs", 0.0),
        semantic_total_seconds=timing.get("total", 0.0),
        semantic_owner_nodes=stats.get("owner_nodes", 0),
        semantic_base_ns=stats.get("base_ns", 0),
        semantic_base_cname=stats.get("base_cname", 0),
        semantic_base_dname=stats.get("base_dname", 0),
        del_candidates_checked=stats.get("del_candidates_checked", 0),
        crew_candidates_checked=stats.get("crew_candidates_checked", 0),
        drew_candidates_checked=stats.get("drew_candidates_checked", 0),
        del_edges_added=stats.get("del_edges_added", 0),
        crew_edges_added=stats.get("crew_edges_added", 0),
        drew_edges_added=stats.get("drew_edges_added", 0),
        error="" if sem_rc == 0 else f"semantic_graph rc={sem_rc}",
    )


def validate_region_task(
    region: RegionInfo,
    scratch_root: Path,
    preprocess_bin: Path,
    semantic_bin: Path,
    threads: int,
    timeout: Optional[float],
    time_metric: str,
) -> tuple[str, RegionValidationResult]:
    scratch_dir = scratch_root / safe_region_name(region.name)
    return region.path, validate_one_region(
        region,
        scratch_dir,
        preprocess_bin,
        semantic_bin,
        threads,
        timeout,
        time_metric,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate selected census regions independently and aggregate validation time."
    )
    parser.add_argument("--census-dir", default="./census", help="census dataset root")
    parser.add_argument("--work-dir", default="", help="benchmark output directory")
    parser.add_argument("--region-counts", type=parse_counts, default=DEFAULT_REGION_COUNTS,
                        help="comma-separated complete region-folder counts")
    parser.add_argument("--regions-limit", type=int, default=0,
                        help="maximum number of region directories to use; 0 means unlimited")
    parser.add_argument("--shuffle", action="store_true", help="shuffle regions before selecting")
    parser.add_argument("--seed", type=int, default=1, help="shuffle seed")
    parser.add_argument("--build", action="store_true", help="force compile preprocess and semantic_graph first")
    parser.add_argument("--no-auto-build", action="store_true",
                        help="do not rebuild binaries when sources are newer than executables")
    parser.add_argument("--preprocess-bin", default="", help="path to preprocess executable")
    parser.add_argument("--semantic-bin", default="", help="path to semantic_graph executable")
    parser.add_argument("--threads", type=int, default=0,
                        help="semantic_graph internal worker threads per region; 0 uses semantic_graph default")
    parser.add_argument("--workers", type=int, default=1,
                        help="number of region folders to validate concurrently; keep --threads small when workers > 1")
    parser.add_argument("--progress-every", type=int, default=100,
                        help="print progress every N newly validated regions")
    parser.add_argument("--timeout", type=float, default=0,
                        help="per-command timeout in seconds; 0 disables timeout")
    parser.add_argument("--time-metric", choices=["validation", "traverse", "total"], default="validation",
                        help=("time reported as total_validation_seconds: validation=sum(compute_reach,"
                              "traverse_dfs,detect_bugs), traverse=traverse_dfs only, total=semantic_graph internal total"))
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[1]
    census_dir = (repo_root / args.census_dir).resolve() if not Path(args.census_dir).is_absolute() else Path(args.census_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    work_dir = Path(args.work_dir) if args.work_dir else repo_root / "benchmark_runs" / f"census_region_validate_{timestamp}"
    if not work_dir.is_absolute():
        work_dir = (repo_root / work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    preprocess_bin = resolve_executable(repo_root, args.preprocess_bin or None, "preprocess")
    semantic_bin = resolve_executable(repo_root, args.semantic_bin or None, "semantic_graph")
    preprocess_src = repo_root / "src" / "preprocess.cpp"
    semantic_src = repo_root / "src" / "semantic_graph.cpp"
    needs_auto_build = (
        not args.no_auto_build and
        (binary_is_stale(preprocess_bin, [preprocess_src]) or
         binary_is_stale(semantic_bin, [semantic_src]))
    )
    if args.build or needs_auto_build:
        build_binaries(repo_root, preprocess_bin, semantic_bin)

    if not preprocess_bin.exists():
        raise FileNotFoundError(f"preprocess binary not found: {preprocess_bin}")
    if not semantic_bin.exists():
        raise FileNotFoundError(f"semantic_graph binary not found: {semantic_bin}")

    regions = discover_regions(census_dir)
    if args.shuffle:
        rnd = random.Random(args.seed)
        rnd.shuffle(regions)
    if args.regions_limit > 0:
        regions = regions[:args.regions_limit]
    if not regions:
        raise RuntimeError(f"no census regions found under {census_dir}")

    run_counts = [n for n in args.region_counts if n <= len(regions)]
    if not run_counts:
        raise RuntimeError("all --region-counts values exceed available regions")

    manifest = {
        "created_at": timestamp,
        "repo_root": str(repo_root),
        "census_dir": str(census_dir),
        "region_counts": args.region_counts,
        "preprocess_bin": str(preprocess_bin),
        "semantic_bin": str(semantic_bin),
        "threads": args.threads,
        "workers": args.workers,
        "time_metric": args.time_metric,
        "time_metric_definition": (
            "validation=sum(compute_reach,traverse_dfs,detect_bugs); "
            "traverse=traverse_dfs; total=semantic_graph internal total"
        ),
    }
    write_json(work_dir / "manifest.json", manifest)

    timeout = None if args.timeout <= 0 else args.timeout
    results: List[AggregateResult] = []
    region_rows: List[RegionResultRow] = []
    scratch_dir = work_dir / "_scratch"
    region_cache: dict[str, RegionValidationResult] = {}

    for target_regions in run_counts:
        selected = regions[:target_regions]
        new_regions = [region for region in selected if region.path not in region_cache]
        total_records = 0
        total_validation_seconds = 0.0
        validation_wall_seconds = 0.0
        total_servers = 0
        total_zones = 0
        total_nodes = 0
        total_edges = 0
        total_paths = 0
        total_bugs = 0
        total_stale_records = 0
        load_facts_seconds = 0.0
        build_base_seconds = 0.0
        build_semantic_seconds = 0.0
        build_invariants_seconds = 0.0
        compute_reach_seconds = 0.0
        traverse_dfs_seconds = 0.0
        detect_bugs_seconds = 0.0
        semantic_total_seconds = 0.0
        semantic_owner_nodes = 0
        semantic_base_ns = 0
        semantic_base_cname = 0
        semantic_base_dname = 0
        del_candidates_checked = 0
        crew_candidates_checked = 0
        drew_candidates_checked = 0
        del_edges_added = 0
        crew_edges_added = 0
        drew_edges_added = 0
        failed_regions = 0

        print(
            f"[run] regions={target_regions} cached={len(selected) - len(new_regions)} "
            f"new={len(new_regions)} workers={args.workers}",
            flush=True,
        )

        completed_new = 0
        progress_every = max(args.progress_every, 1)
        if new_regions:
            if args.workers <= 1:
                for region in new_regions:
                    region_cache[region.path] = validate_one_region(
                        region,
                        scratch_dir / safe_region_name(region.name),
                        preprocess_bin,
                        semantic_bin,
                        args.threads,
                        timeout,
                        args.time_metric,
                    )
                    completed_new += 1
                    if completed_new % progress_every == 0 or completed_new == len(new_regions):
                        print(
                            f"[progress] regions={target_regions} "
                            f"validated_new={completed_new}/{len(new_regions)}",
                            flush=True,
                        )
            else:
                with ThreadPoolExecutor(max_workers=args.workers) as pool:
                    futures = [
                        pool.submit(
                            validate_region_task,
                            region,
                            scratch_dir,
                            preprocess_bin,
                            semantic_bin,
                            args.threads,
                            timeout,
                            args.time_metric,
                        )
                        for region in new_regions
                    ]
                    for future in as_completed(futures):
                        region_path, region_result = future.result()
                        region_cache[region_path] = region_result
                        completed_new += 1
                        if completed_new % progress_every == 0 or completed_new == len(new_regions):
                            print(
                                f"[progress] regions={target_regions} "
                                f"validated_new={completed_new}/{len(new_regions)}",
                                flush=True,
                            )

        for region in selected:
            region_result = region_cache[region.path]
            total_records += region_result.records
            total_validation_seconds += region_result.validation_seconds
            validation_wall_seconds += region_result.wall_seconds
            total_servers += region_result.servers
            total_zones += region_result.zones
            total_nodes += region_result.nodes
            total_edges += region_result.edges
            total_paths += region_result.paths
            total_bugs += region_result.bugs
            total_stale_records += region_result.stale_records
            load_facts_seconds += region_result.load_facts_seconds
            build_base_seconds += region_result.build_base_seconds
            build_semantic_seconds += region_result.build_semantic_seconds
            build_invariants_seconds += region_result.build_invariants_seconds
            compute_reach_seconds += region_result.compute_reach_seconds
            traverse_dfs_seconds += region_result.traverse_dfs_seconds
            detect_bugs_seconds += region_result.detect_bugs_seconds
            semantic_total_seconds += region_result.semantic_total_seconds
            semantic_owner_nodes += region_result.semantic_owner_nodes
            semantic_base_ns += region_result.semantic_base_ns
            semantic_base_cname += region_result.semantic_base_cname
            semantic_base_dname += region_result.semantic_base_dname
            del_candidates_checked += region_result.del_candidates_checked
            crew_candidates_checked += region_result.crew_candidates_checked
            drew_candidates_checked += region_result.drew_candidates_checked
            del_edges_added += region_result.del_edges_added
            crew_edges_added += region_result.crew_edges_added
            drew_edges_added += region_result.drew_edges_added
            if not region_result.ok:
                failed_regions += 1
                print(f"[warn] failed region={region.name}: {region_result.error}", flush=True)

        status = "ok" if failed_regions == 0 else "error"
        result = AggregateResult(
            target_regions=target_regions,
            selected_regions=len(selected),
            total_records=total_records,
            total_validation_seconds=total_validation_seconds,
            validation_wall_seconds=validation_wall_seconds,
            total_servers=total_servers,
            total_zones=total_zones,
            total_nodes=total_nodes,
            total_edges=total_edges,
            total_paths=total_paths,
            total_bugs=total_bugs,
            total_stale_records=total_stale_records,
            load_facts_seconds=load_facts_seconds,
            build_base_seconds=build_base_seconds,
            build_semantic_seconds=build_semantic_seconds,
            build_invariants_seconds=build_invariants_seconds,
            graph_build_seconds=(
                load_facts_seconds +
                build_base_seconds +
                build_semantic_seconds +
                build_invariants_seconds
            ),
            compute_reach_seconds=compute_reach_seconds,
            traverse_dfs_seconds=traverse_dfs_seconds,
            detect_bugs_seconds=detect_bugs_seconds,
            semantic_total_seconds=semantic_total_seconds,
            semantic_owner_nodes=semantic_owner_nodes,
            semantic_base_ns=semantic_base_ns,
            semantic_base_cname=semantic_base_cname,
            semantic_base_dname=semantic_base_dname,
            del_candidates_checked=del_candidates_checked,
            crew_candidates_checked=crew_candidates_checked,
            drew_candidates_checked=drew_candidates_checked,
            del_edges_added=del_edges_added,
            crew_edges_added=crew_edges_added,
            drew_edges_added=drew_edges_added,
            failed_regions=failed_regions,
            status=status,
            case_dir=str(work_dir),
            error="" if status == "ok" else f"{failed_regions} region(s) failed",
        )
        results.append(result)
        case_region_rows = [
            make_region_result_row(
                target_regions,
                rank,
                region,
                region_cache[region.path],
                scratch_dir,
            )
            for rank, region in enumerate(selected, start=1)
        ]
        region_rows.extend(case_region_rows)
        write_csv(work_dir / "results.csv", results)
        write_json(work_dir / "results.json", [asdict(r) for r in results])
        write_graph_build_summary(work_dir / "graph_build_summary.csv", results)
        write_region_results(work_dir / "region_results.csv", region_rows)
        write_json(work_dir / "region_results.json", [asdict(r) for r in region_rows])

        print(
            f"[done] regions={target_regions} total_records={total_records} "
            f"nodes={total_nodes} edges={total_edges} paths={total_paths} "
            f"bugs={total_bugs} stale={total_stale_records} "
            f"build_graph={result.graph_build_seconds:.6f}s "
            f"total_validation={total_validation_seconds:.6f}s status={status}",
            flush=True,
        )

    print("\n[graph-build-summary]", flush=True)
    print(
        "regions\trecords\tservers\tzones\tnodes\tedges\tpaths\tbugs\t"
        "stale\tgraph_build_s\tvalidation_s",
        flush=True,
    )
    for row in results:
        print(
            f"{row.selected_regions}\t{row.total_records}\t{row.total_servers}\t"
            f"{row.total_zones}\t{row.total_nodes}\t{row.total_edges}\t"
            f"{row.total_paths}\t{row.total_bugs}\t"
            f"{row.total_stale_records}\t{row.graph_build_seconds:.6f}\t"
            f"{row.total_validation_seconds:.6f}",
            flush=True,
        )

    print(f"[result] {work_dir / 'results.csv'}")
    print(f"[result] {work_dir / 'results.json'}")
    print(f"[result] {work_dir / 'graph_build_summary.csv'}")
    print(f"[result] {work_dir / 'region_results.csv'}")
    print(f"[result] {work_dir / 'region_results.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
