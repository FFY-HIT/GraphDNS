#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any


EXPERIMENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXPERIMENT_DIR.parents[1]
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp1 import DEFAULT_SHARED_KINDS  # noqa: E402
from exp1.reporting import generate_reports  # noqa: E402
from exp1.sampling import sample_complete_regions, write_sample_manifest  # noqa: E402
from exp1.storage import ExecutionResult, add_regions, connect, load_regions, save_execution, set_metadata  # noqa: E402
from exp1.workflow import (  # noqa: E402
    build_graphdns,
    resolve_path,
    run_region,
    validate_graphdns_binary,
)


DEFAULTS: dict[str, Any] = {
    "sample_size": 100000,
    "seed": 20260724,
    "workers": 8,
    "batch_size": 128,
    "progress_every": 200,
    "timeout_seconds": 1800,
    "preprocess_threads": 1,
    "graphdns_threads": 1,
    "shared_kinds": list(DEFAULT_SHARED_KINDS),
    "graphdns": {
        "preprocess_bin": "experiments/bin/preprocess",
        "semantic_graph_bin": "experiments/bin/semantic_graph",
    },
    "groot": {
        "command": [],
        "format": "jsonl",
        "empty_output_means_zero": True,
        "require_strong_keys": True,
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare GraphDNS and GRoot on a random sample of complete Census regions."
    )
    parser.add_argument("--config", required=True, type=Path, help="JSON experiment configuration")
    parser.add_argument("--run-dir", type=Path, help="new or resumable run directory")
    parser.add_argument("--resume", action="store_true", help="resume completed regions from SQLite")
    parser.add_argument("--build", action="store_true", help="build preprocess and semantic_graph")
    parser.add_argument("--sample-size", type=int, help="override configured region sample size")
    parser.add_argument("--seed", type=int, help="override configured random seed")
    parser.add_argument("--workers", type=int, help="number of regions executed concurrently")
    parser.add_argument("--batch-size", type=int, help="maximum submitted regions per batch")
    parser.add_argument(
        "--graphdns-only",
        action="store_true",
        help="debug GraphDNS without GRoot; no consistency claim can be generated",
    )
    return parser.parse_args()


def deep_merge(base: dict[str, Any], update: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in update.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: Path, args: argparse.Namespace) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("configuration root must be a JSON object")
    config = deep_merge(DEFAULTS, raw)
    for argument, key in (
        (args.sample_size, "sample_size"),
        (args.seed, "seed"),
        (args.workers, "workers"),
        (args.batch_size, "batch_size"),
    ):
        if argument is not None:
            config[key] = argument
    if int(config["sample_size"]) <= 0:
        raise ValueError("sample_size must be positive")
    if int(config["workers"]) <= 0 or int(config["batch_size"]) <= 0:
        raise ValueError("workers and batch_size must be positive")
    if not config.get("census_dir"):
        raise ValueError("configuration must define census_dir")
    if not args.graphdns_only and not config.get("groot", {}).get("command"):
        raise ValueError(
            "configuration must define groot.command; use --graphdns-only only for smoke testing"
        )
    return config


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(
    run_dir: Path,
    config: dict[str, Any],
    config_path: Path,
    preprocess_bin: Path,
    semantic_bin: Path,
    scan_stats: dict[str, Any] | None,
) -> None:
    manifest = {
        "experiment": "experiment_01_census_consistency",
        "created_at": datetime.now().astimezone().isoformat(),
        "config_path": str(config_path.resolve()),
        "config": config,
        "graphdns_sources": {
            "preprocess.cpp": file_sha256(REPO_ROOT / "src" / "preprocess.cpp"),
            "semantic_graph.cpp": file_sha256(REPO_ROOT / "src" / "semantic_graph.cpp"),
        },
        "binaries": {
            "preprocess": str(preprocess_bin),
            "semantic_graph": str(semantic_bin),
            "preprocess_sha256": file_sha256(preprocess_bin),
            "semantic_graph_sha256": file_sha256(semantic_bin),
        },
        "scan_stats": scan_stats,
        "comparison_unit": "unique canonical case within one region and vulnerability kind",
        "shared_kinds": config["shared_kinds"],
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
    )


def validate_resume_manifest(
    manifest_path: Path,
    config: dict[str, Any],
    preprocess_bin: Path,
    semantic_bin: Path,
) -> None:
    if not manifest_path.is_file():
        raise FileNotFoundError(f"resume requested, but manifest is missing: {manifest_path}")
    previous = json.loads(manifest_path.read_text(encoding="utf-8"))
    previous_config = previous.get("config", {})
    immutable_keys = (
        "census_dir",
        "sample_size",
        "seed",
        "preprocess_threads",
        "graphdns_threads",
        "shared_kinds",
        "graphdns",
        "groot",
    )
    changed = [key for key in immutable_keys if previous_config.get(key) != config.get(key)]
    if changed:
        raise ValueError(
            "resume would mix incompatible protocols; start a new run because these fields changed: "
            + ", ".join(changed)
        )
    previous_sources = previous.get("graphdns_sources", {})
    current_sources = {
        "preprocess.cpp": file_sha256(REPO_ROOT / "src" / "preprocess.cpp"),
        "semantic_graph.cpp": file_sha256(REPO_ROOT / "src" / "semantic_graph.cpp"),
    }
    if previous_sources != current_sources:
        raise ValueError("GraphDNS source changed since this run began; start a new run")
    binaries = previous.get("binaries", {})
    if binaries.get("preprocess_sha256") != file_sha256(preprocess_bin):
        raise ValueError("preprocess binary changed since this run began; start a new run")
    if binaries.get("semantic_graph_sha256") != file_sha256(semantic_bin):
        raise ValueError("semantic_graph binary changed since this run began; start a new run")


def completed_map(connection) -> dict[str, set[str]]:
    rows = connection.execute(
        "SELECT r.name, e.system FROM executions e JOIN regions r ON r.id=e.region_id "
        "WHERE e.status='ok'"
    ).fetchall()
    result: dict[str, set[str]] = {}
    for row in rows:
        result.setdefault(row["name"], set()).add(row["system"])
    return result


def failure_result(system: str, exc: BaseException) -> ExecutionResult:
    return ExecutionResult(
        system=system,
        status="worker_error",
        return_code=125,
        wall_seconds=0.0,
        record_count=0,
        findings=[],
        details={},
        error=f"{type(exc).__name__}: {exc}",
    )


def main() -> int:
    args = parse_args()
    config_path = args.config.resolve()
    config = load_config(config_path, args)
    config["_repo_root"] = str(REPO_ROOT)
    config["run_mode"] = "graphdns_only" if args.graphdns_only else "comparison"
    census_dir = resolve_path(REPO_ROOT, str(config["census_dir"]))
    config["census_dir"] = str(census_dir)
    preprocess_bin = resolve_path(REPO_ROOT, config["graphdns"]["preprocess_bin"])
    semantic_bin = resolve_path(REPO_ROOT, config["graphdns"]["semantic_graph_bin"])

    if args.build:
        build_graphdns(REPO_ROOT, preprocess_bin, semantic_bin)
    for path, label in ((preprocess_bin, "preprocess"), (semantic_bin, "semantic_graph")):
        if not path.is_file():
            raise FileNotFoundError(f"{label} binary does not exist: {path}; run with --build")
    print("[probe] validating GraphDNS compact report output", flush=True)
    validate_graphdns_binary(
        semantic_bin,
        min(120.0, float(config.get("timeout_seconds", 1800))),
    )
    print("[probe] GraphDNS report output is compatible", flush=True)

    if args.run_dir:
        run_dir = args.run_dir.resolve()
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = (REPO_ROOT / "experiments" / "runs" / f"exp01_{timestamp}").resolve()
    if run_dir.exists() and not args.resume:
        raise FileExistsError(f"run directory already exists; pass --resume: {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=True)
    scratch_root = run_dir / ".scratch"
    reports_dir = run_dir / "reports"
    database_path = run_dir / "results.sqlite3"
    manifest_path = run_dir / "sample_manifest.csv"

    if args.resume:
        validate_resume_manifest(
            run_dir / "manifest.json", config, preprocess_bin, semantic_bin
        )

    connection = connect(database_path)
    try:
        existing_regions = load_regions(connection)
        scan_stats_dict: dict[str, Any] | None = None
        if existing_regions:
            if len(existing_regions) != int(config["sample_size"]):
                raise ValueError(
                    "resume configuration sample_size differs from the stored sample: "
                    f"{config['sample_size']} != {len(existing_regions)}"
                )
            regions = existing_regions
            print(f"[sample] reusing {len(regions):,} stored regions", flush=True)
        else:
            print(
                f"[sample] selecting {int(config['sample_size']):,} complete regions "
                f"from {census_dir} with seed={config['seed']}",
                flush=True,
            )
            regions, scan_stats = sample_complete_regions(
                census_dir,
                int(config["sample_size"]),
                int(config["seed"]),
                progress=print,
            )
            scan_stats_dict = vars(scan_stats)
            write_sample_manifest(manifest_path, regions)
            add_regions(connection, regions)
            set_metadata(connection, "sample_size", config["sample_size"])
            set_metadata(connection, "seed", config["seed"])
            connection.commit()
        if not (args.resume and (run_dir / "manifest.json").is_file()):
            write_manifest(
                run_dir,
                config,
                config_path,
                preprocess_bin,
                semantic_bin,
                scan_stats_dict,
            )

        required_systems = {"graphdns"} if args.graphdns_only else {"graphdns", "groot"}
        completed = completed_map(connection) if args.resume else {}
        pending = [
            (region, required_systems - completed.get(region.name, set()))
            for region in regions
            if required_systems - completed.get(region.name, set())
        ]
        print(
            f"[run] selected={len(regions):,} pending={len(pending):,} "
            f"workers={config['workers']} batch_size={config['batch_size']}",
            flush=True,
        )
        processed = len(regions) - len(pending)
        batch_size = int(config["batch_size"])
        workers = int(config["workers"])
        progress_every = max(1, int(config.get("progress_every", 200)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            for offset in range(0, len(pending), batch_size):
                batch = pending[offset : offset + batch_size]
                futures = {
                    executor.submit(
                        run_region,
                        region,
                        systems,
                        config,
                        preprocess_bin,
                        semantic_bin,
                        scratch_root,
                    ): (region, systems)
                    for region, systems in batch
                }
                for future in as_completed(futures):
                    region, systems = futures[future]
                    try:
                        _, results = future.result()
                    except BaseException as exc:
                        results = [failure_result(system, exc) for system in sorted(systems)]
                    for result in results:
                        save_execution(connection, region.name, result)
                    processed += 1
                    if processed % progress_every == 0 or processed == len(regions):
                        print(
                            f"[progress] regions={processed:,}/{len(regions):,}", flush=True
                        )

        expected_systems = ("graphdns",) if args.graphdns_only else ("graphdns", "groot")
        summary = generate_reports(
            connection,
            reports_dir,
            config["shared_kinds"],
            expected_systems=expected_systems,
        )
        print(f"[result] run_dir={run_dir}", flush=True)
        if args.graphdns_only:
            graphdns_totals = summary["graphdns"]
            print(
                f"[result] graphdns_successful_regions={graphdns_totals['successful_regions']:,} "
                f"regions_with_reports={graphdns_totals['regions_with_reports']:,} "
                f"raw_reports={graphdns_totals['raw_reports']:,} "
                f"unique_cases={graphdns_totals['unique_cases']:,}",
                flush=True,
            )
            graphdns_failures = connection.execute(
                "SELECT COUNT(*) AS n FROM executions WHERE system='graphdns' AND status!='ok'"
            ).fetchone()["n"]
            return 0 if graphdns_failures == 0 else 2
        print(f"[result] paired_regions={summary['paired_successful_regions']:,}", flush=True)
        print(
            f"[result] intersection={summary['shared_scope']['intersection']:,} "
            f"graphdns_only={summary['shared_scope']['graphdns_only']:,} "
            f"groot_only={summary['shared_scope']['groot_only']:,}",
            flush=True,
        )
        print(
            f"[review] pending={summary['manual_review']['pending']:,} "
            f"file={reports_dir / 'manual_review.csv'}",
            flush=True,
        )
        return 0 if summary["failed_or_unpaired_regions"] == 0 else 2
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
