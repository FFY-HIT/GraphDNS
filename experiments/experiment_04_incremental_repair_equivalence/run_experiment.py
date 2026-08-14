#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any


EXPERIMENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXPERIMENT_DIR.parents[1]
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp4.model import parse_graphdns_output  # noqa: E402
from exp4 import SUPPORTED_REPAIR_KINDS  # noqa: E402
from exp4.reporting import generate_outputs, write_csv  # noqa: E402
from exp4.sampling import Region, sample_complete_regions  # noqa: E402
from exp4.workflow import (  # noqa: E402
    build_graphdns,
    evaluate_region,
    file_sha256,
    probe_graphdns,
    screen_region,
    serializable_screening,
)


DEFAULTS: dict[str, Any] = {
    "census_dir": "/path/to/census",
    "target_regions": 100,
    "screening_pool_size": 20000,
    "min_repairable_reports_per_region": 1,
    "seed": 20260725,
    "workers": 8,
    "candidate_workers": 1,
    "screening_batch_size": 64,
    "progress_every": 10,
    "timeout_seconds": 1800,
    "max_zone_files_per_region": 200,
    "max_records_per_region": 5000,
    "max_generated_candidates_per_region": 100,
    "server_view_coverage": "sampled",
    "di_is_severe": False,
    "max_candidates_per_region": 0,
    "preprocess_bin": "experiments/bin/preprocess",
    "semantic_graph_bin": "experiments/bin/semantic_graph",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate repair accuracy, root-cause grouping, and incremental/full "
            "report-set equivalence on vulnerability-bearing Census regions."
        )
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=EXPERIMENT_DIR / "config.example.json",
        help="experiment JSON configuration",
    )
    parser.add_argument("--run-dir", type=Path, help="new or resumable run directory")
    parser.add_argument("--resume", action="store_true", help="resume region checkpoints")
    parser.add_argument("--build", action="store_true", help="rebuild GraphDNS binaries")
    parser.add_argument("--regions", type=int, help="number of eligible regions")
    parser.add_argument("--screening-pool", type=int, help="random complete-region pool size")
    parser.add_argument(
        "--min-repairable-reports",
        type=int,
        help="minimum LD/DI/MG/CZD/RL/RB/ML/STALE reports required in each region",
    )
    parser.add_argument(
        "--max-zone-files",
        type=int,
        help="exclude regions containing more zone files than this limit",
    )
    parser.add_argument(
        "--max-records",
        type=int,
        help="exclude regions whose preprocessed facts exceed this limit",
    )
    parser.add_argument(
        "--max-generated-candidates",
        type=int,
        help=(
            "exclude regions whose complete generated candidate set exceeds "
            "this limit; candidates are never truncated"
        ),
    )
    parser.add_argument("--workers", type=int, help="concurrent region workers")
    parser.add_argument(
        "--candidate-workers",
        type=int,
        help=(
            "candidate workers inside each region; total GraphDNS concurrency "
            "is approximately workers * candidate-workers"
        ),
    )
    parser.add_argument("--seed", type=int, help="sampling seed")
    parser.add_argument(
        "--max-candidates-per-region",
        type=int,
        help="0 evaluates every candidate; positive values are for diagnostics",
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="allow fewer than 100 regions for a quick pipeline check",
    )
    return parser.parse_args()


def load_config(path: Path, args: argparse.Namespace) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("configuration root must be a JSON object")
    config = {**DEFAULTS, **raw}
    overrides = {
        "target_regions": args.regions,
        "screening_pool_size": args.screening_pool,
        "min_repairable_reports_per_region": args.min_repairable_reports,
        "workers": args.workers,
        "candidate_workers": args.candidate_workers,
        "seed": args.seed,
        "max_candidates_per_region": args.max_candidates_per_region,
        "max_zone_files_per_region": args.max_zone_files,
        "max_records_per_region": args.max_records,
        "max_generated_candidates_per_region": args.max_generated_candidates,
    }
    for key, value in overrides.items():
        if value is not None:
            config[key] = value
    target = int(config["target_regions"])
    if target <= 0:
        raise ValueError("target_regions must be positive")
    if target < 100 and not args.smoke:
        raise ValueError(
            "the paper protocol requires at least 100 regions; use --smoke only "
            "for a diagnostic run"
        )
    if int(config["screening_pool_size"]) < target:
        raise ValueError("screening_pool_size must be >= target_regions")
    if int(config["min_repairable_reports_per_region"]) <= 0:
        raise ValueError("min_repairable_reports_per_region must be positive")
    if int(config["workers"]) <= 0:
        raise ValueError("workers must be positive")
    if int(config["candidate_workers"]) <= 0:
        raise ValueError("candidate_workers must be positive")
    if int(config["max_zone_files_per_region"]) <= 0:
        raise ValueError("max_zone_files_per_region must be positive")
    if int(config["max_records_per_region"]) <= 0:
        raise ValueError("max_records_per_region must be positive")
    if int(config["max_generated_candidates_per_region"]) <= 0:
        raise ValueError(
            "max_generated_candidates_per_region must be positive"
        )
    if config["server_view_coverage"] not in {"complete", "sampled"}:
        raise ValueError("server_view_coverage must be complete or sampled")
    return config


def resolve_path(value: str | Path) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (REPO_ROOT / path).resolve()


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return slug[:100] or "region"


def default_run_dir() -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return REPO_ROOT / "experiments" / "runs" / f"exp04_{timestamp}"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def selected_from_csv(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in read_csv(path):
        region = Region(
            sample_rank=int(row["sample_rank"]),
            name=row["name"],
            path=row["path"],
            sample_score=row["sample_score"],
            zone_file_count=int(row["zone_file_count"]),
        )
        rows.append(
            {
                "selection_rank": int(row["selection_rank"]),
                "region": region,
                "facts_path": row["facts_path"],
                "baseline_path": row["baseline_path"],
            }
        )
    return rows


def write_checkpoint(
    path: Path,
    region_row: dict[str, Any],
    candidate_rows: list[dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(
            {"region": region_row, "candidates": candidate_rows},
            ensure_ascii=False,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    temporary.replace(path)


def load_checkpoint(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    return dict(value["region"]), list(value["candidates"])


def create_selection(
    config: dict[str, Any],
    run_dir: Path,
    preprocess_bin: Path,
    semantic_bin: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    census_dir = resolve_path(config["census_dir"])
    pool_size = int(config["screening_pool_size"])
    target = int(config["target_regions"])
    print(
        f"[sample] selecting a deterministic random pool of {pool_size:,} "
        f"complete regions from {census_dir}",
        flush=True,
    )
    pool = sample_complete_regions(census_dir, pool_size, int(config["seed"]), print)

    selected: list[dict[str, Any]] = []
    screening_rows: list[dict[str, Any]] = []
    max_zone_files = int(config["max_zone_files_per_region"])
    max_records = int(config["max_records_per_region"])
    max_candidates = int(config["max_generated_candidates_per_region"])
    size_pool: list[Region] = []
    for region in pool:
        if region.zone_file_count <= max_zone_files:
            size_pool.append(region)
            continue
        screening_rows.append(
            {
                **region.__dict__,
                "status": "excluded_zone_file_limit",
                "eligible": False,
                "error": "",
                "records": 0,
                "bugs": 0,
                "repairable_reports": 0,
                "root_cause_groups": 0,
                "candidates": 0,
                "meets_minimum_reports": False,
                "meets_record_limit": False,
                "meets_candidate_limit": False,
                "selected_eligible": False,
            }
        )
    print(
        f"[sample] zone-file limit <= {max_zone_files}: "
        f"kept={len(size_pool):,} excluded={len(pool) - len(size_pool):,}",
        flush=True,
    )
    inputs_dir = run_dir / "inputs"
    baselines_dir = run_dir / "baselines"
    inputs_dir.mkdir(parents=True, exist_ok=True)
    baselines_dir.mkdir(parents=True, exist_ok=True)
    scratch_root = run_dir / "scratch"
    workers = int(config["workers"])
    batch_size = max(workers, int(config["screening_batch_size"]))

    screened_count = 0
    for begin in range(0, len(size_pool), batch_size):
        batch = size_pool[begin : begin + batch_size]
        completed: dict[int, Any] = {}
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {
                executor.submit(
                    screen_region,
                    region,
                    preprocess_bin,
                    semantic_bin,
                    scratch_root,
                    float(config["timeout_seconds"]),
                    max_records,
                    str(config["server_view_coverage"]),
                ): region
                for region in batch
            }
            for future in as_completed(future_map):
                result = future.result()
                completed[result.region.sample_rank] = result

        for region in batch:
            result = completed[region.sample_rank]
            screening_row = serializable_screening(result)
            screening_row["meets_minimum_reports"] = (
                int(screening_row["repairable_reports"])
                >= int(config["min_repairable_reports_per_region"])
            )
            screening_row["meets_record_limit"] = (
                int(screening_row["records"]) <= max_records
            )
            screening_row["meets_candidate_limit"] = (
                int(screening_row["candidates"]) <= max_candidates
            )
            screening_row["selected_eligible"] = bool(
                result.eligible
                and screening_row["meets_minimum_reports"]
                and screening_row["meets_record_limit"]
                and screening_row["meets_candidate_limit"]
            )
            screening_rows.append(screening_row)
            screened_count += 1
            if not screening_row["selected_eligible"] or len(selected) >= target:
                continue
            selection_rank = len(selected) + 1
            stem = f"{selection_rank:04d}_{slugify(region.name)}"
            facts_path = inputs_dir / f"{stem}.facts"
            baseline_path = baselines_dir / f"{stem}.txt"
            facts_path.write_text(result.facts_text, encoding="utf-8")
            baseline_path.write_text(result.baseline_output, encoding="utf-8")
            selected.append(
                {
                    "selection_rank": selection_rank,
                    "region": region,
                    "facts_path": str(facts_path.relative_to(run_dir)),
                    "baseline_path": str(baseline_path.relative_to(run_dir)),
                }
            )
        print(
            f"[screen] checked={screened_count:,}/{len(size_pool):,} "
            f"eligible_selected={len(selected):,}/{target:,}",
            flush=True,
        )
        if len(selected) >= target:
            break

    write_csv(run_dir / "screening_results.csv", screening_rows)
    if len(selected) < target:
        raise RuntimeError(
            f"only {len(selected)} eligible regions were found in a pool of "
            f"{pool_size}; increase screening_pool_size or relax the configured "
            "zone-file, record, or generated-candidate limits"
        )
    manifest_rows = [
        {
            "selection_rank": entry["selection_rank"],
            **entry["region"].__dict__,
            "facts_path": entry["facts_path"],
            "baseline_path": entry["baseline_path"],
        }
        for entry in selected
    ]
    write_csv(run_dir / "selected_regions.csv", manifest_rows)
    return selected, screening_rows


def evaluate_selected(
    config: dict[str, Any],
    run_dir: Path,
    selected: list[dict[str, Any]],
    semantic_bin: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    checkpoint_dir = run_dir / "checkpoints"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    scratch_root = run_dir / "scratch"
    region_rows: list[dict[str, Any]] = []
    candidate_rows: list[dict[str, Any]] = []
    pending: list[tuple[dict[str, Any], Path]] = []

    for entry in selected:
        checkpoint = checkpoint_dir / f"{entry['selection_rank']:04d}.json"
        if checkpoint.is_file():
            region_row, rows = load_checkpoint(checkpoint)
            if region_row.get("status") == "error":
                pending.append((entry, checkpoint))
            else:
                region_rows.append(region_row)
                candidate_rows.extend(rows)
        else:
            pending.append((entry, checkpoint))

    print(
        f"[evaluate] cached={len(selected) - len(pending):,} "
        f"pending={len(pending):,} region_workers={config['workers']} "
        f"candidate_workers={config['candidate_workers']}",
        flush=True,
    )
    completed_count = len(selected) - len(pending)
    with ThreadPoolExecutor(max_workers=int(config["workers"])) as executor:
        future_map = {}
        for entry, checkpoint in pending:
            region: Region = entry["region"]
            future = executor.submit(
                evaluate_region,
                region,
                run_dir / entry["facts_path"],
                run_dir / entry["baseline_path"],
                semantic_bin,
                scratch_root,
                float(config["timeout_seconds"]),
                str(config["server_view_coverage"]),
                bool(config["di_is_severe"]),
                int(config["max_candidates_per_region"]),
                int(config["candidate_workers"]),
            )
            future_map[future] = (entry, checkpoint)

        for future in as_completed(future_map):
            entry, checkpoint = future_map[future]
            region: Region = entry["region"]
            try:
                region_row, rows = future.result()
            except Exception as exc:
                region_row = {
                    "sample_rank": region.sample_rank,
                    "region": region.name,
                    "region_path": region.path,
                    "status": "error",
                    "error": f"{type(exc).__name__}: {exc}",
                    "repairable_reports": 0,
                    "root_cause_groups": 0,
                    "bugs": 0,
                    "records": 0,
                    "evaluated_candidates": 0,
                }
                rows = []
            write_checkpoint(checkpoint, region_row, rows)
            region_rows.append(region_row)
            candidate_rows.extend(rows)
            completed_count += 1
            if (
                completed_count % int(config["progress_every"]) == 0
                or completed_count == len(selected)
            ):
                print(
                    f"[progress] evaluated_regions={completed_count:,}/"
                    f"{len(selected):,}",
                    flush=True,
                )

    region_rows.sort(key=lambda row: int(row.get("sample_rank", 0)))
    candidate_rows.sort(
        key=lambda row: (
            int(row.get("region_rank", 0)),
            int(row.get("output_rank", 0)),
        )
    )
    return region_rows, candidate_rows


def collect_group_rows(
    run_dir: Path,
    selected: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for entry in selected:
        parsed = parse_graphdns_output(
            (run_dir / entry["baseline_path"]).read_text(
                encoding="utf-8", errors="replace"
            )
        )
        region: Region = entry["region"]
        for group in parsed.groups:
            rows.append(
                {
                    "selection_rank": entry["selection_rank"],
                    "sample_rank": region.sample_rank,
                    "region": region.name,
                    "kind": group.kind,
                    "repair_supported": group.kind in SUPPORTED_REPAIR_KINDS,
                    "group_key": group.key,
                    "grouped_reports": group.grouped_reports,
                    "representative": group.representative,
                }
            )
    return rows


def write_manifest(
    run_dir: Path,
    config: dict[str, Any],
    preprocess_bin: Path,
    semantic_bin: Path,
) -> None:
    manifest = {
        "experiment": "experiment_04_incremental_repair_equivalence",
        "created_at": datetime.now().astimezone().isoformat(),
        "config": config,
        "selection_condition": (
            "complete Census region with the configured minimum number of "
            "supported repairable reports, >=1 root-cause group, >=1 "
            "dry-run-evaluable candidate, at most "
            f"{config['max_zone_files_per_region']} zone files, at most "
            f"{config['max_records_per_region']} preprocessed records, and at "
            f"most {config['max_generated_candidates_per_region']} generated "
            "candidates"
        ),
        "candidate_accuracy_definition": (
            "original root-cause group absent after full rebuild and no new "
            "severe LD/MG/CZD/RL/RB/ML report"
        ),
        "timing_scope": {
            "incremental": "graph_update + local_traversal",
            "full": (
                "build_base + build_semantic + build_invariants + "
                "compute_reach + traverse_core"
            ),
            "excluded": (
                "report detection/refresh, process startup, file staging, "
                "and output serialization"
            ),
        },
        "report_identity": (
            "kind, zoneCut, nameserver, start, query, target, server, zone, reason"
        ),
        "equivalence_audit": (
            "exact report-key comparison plus deterministic canonical-set "
            "digests for active/reachable edges, complete DFS paths, and "
            "terminal symbolic states; post-update audit traversal is outside "
            "the measured incremental timing"
        ),
        "source_sha256": {
            "preprocess.cpp": file_sha256(REPO_ROOT / "src" / "preprocess.cpp"),
            "semantic_graph.cpp": file_sha256(
                REPO_ROOT / "src" / "semantic_graph.cpp"
            ),
        },
        "binary_sha256": {
            "preprocess": file_sha256(preprocess_bin),
            "semantic_graph": file_sha256(semantic_bin),
        },
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def validate_resume_manifest(
    run_dir: Path,
    config: dict[str, Any],
    preprocess_bin: Path,
    semantic_bin: Path,
) -> None:
    path = run_dir / "manifest.json"
    if not path.is_file():
        raise FileNotFoundError(f"resume manifest is missing: {path}")
    previous = json.loads(path.read_text(encoding="utf-8"))
    old_config = previous.get("config", {})
    protocol_keys = (
        "census_dir",
        "target_regions",
        "screening_pool_size",
        "seed",
        "min_repairable_reports_per_region",
        "max_zone_files_per_region",
        "max_records_per_region",
        "max_generated_candidates_per_region",
        "server_view_coverage",
        "di_is_severe",
        "max_candidates_per_region",
    )
    changed = [
        key for key in protocol_keys if old_config.get(key) != config.get(key)
    ]
    if changed:
        raise ValueError(
            "resume would mix incompatible protocols: " + ", ".join(changed)
        )
    expected = previous.get("binary_sha256", {})
    current = {
        "preprocess": file_sha256(preprocess_bin),
        "semantic_graph": file_sha256(semantic_bin),
    }
    if expected != current:
        raise ValueError(
            "GraphDNS binaries changed since the run started; use a new run directory"
        )


def main() -> int:
    args = parse_args()
    config = load_config(args.config.resolve(), args)
    run_dir = (args.run_dir or default_run_dir()).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    preprocess_bin = resolve_path(config["preprocess_bin"])
    semantic_bin = resolve_path(config["semantic_graph_bin"])

    if args.build:
        build_graphdns(REPO_ROOT, preprocess_bin, semantic_bin)
    if not preprocess_bin.is_file() or not semantic_bin.is_file():
        raise FileNotFoundError(
            "GraphDNS binaries are missing; rerun with --build"
        )
    print("[probe] checking repair-group and multi-action interfaces", flush=True)
    probe_graphdns(semantic_bin, min(float(config["timeout_seconds"]), 120.0))

    selected_path = run_dir / "selected_regions.csv"
    if args.resume:
        if not selected_path.is_file():
            raise FileNotFoundError(
                f"resume requested but selection is missing: {selected_path}"
            )
        validate_resume_manifest(run_dir, config, preprocess_bin, semantic_bin)
        selected = selected_from_csv(selected_path)
    else:
        if selected_path.exists():
            raise FileExistsError(
                f"run directory already contains a selection: {run_dir}; "
                "use --resume or choose a new --run-dir"
            )
        selected, _ = create_selection(
            config, run_dir, preprocess_bin, semantic_bin
        )
        write_manifest(run_dir, config, preprocess_bin, semantic_bin)

    region_rows, candidate_rows = evaluate_selected(
        config, run_dir, selected, semantic_bin
    )
    group_rows = collect_group_rows(run_dir, selected)
    summary = generate_outputs(run_dir, region_rows, candidate_rows, group_rows)
    region_errors = sum(row.get("status") == "error" for row in region_rows)
    print(
        "[done] regions={regions} generated={generated} evaluated={evaluated} "
        "region_errors={region_errors} accuracy={accuracy} "
        "equivalence={equivalence}".format(
            regions=summary["selection"]["selected_regions"],
            generated=summary["candidate_accuracy"]["generated_candidates"],
            evaluated=summary["candidate_accuracy"]["evaluated_candidates"],
            region_errors=region_errors,
            accuracy=summary["candidate_accuracy"]["overall_accuracy_micro"],
            equivalence=summary["incremental_equivalence"][
                "report_set_equivalence_rate"
            ],
        ),
        flush=True,
    )
    print(f"[result] {run_dir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
