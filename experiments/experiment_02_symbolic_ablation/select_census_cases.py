#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import asdict
from pathlib import Path
from typing import Iterable, Iterator


EXPERIMENT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp2.census import (  # noqa: E402
    CensusRegion,
    dataset_payload,
    load_census_region,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Select complete DNAME-bearing Census regions and export bounded "
            "real-world cases for Experiment 02."
        )
    )
    parser.add_argument("--census-dir", type=Path, required=True)
    parser.add_argument(
        "--sample-manifest",
        type=Path,
        help="Optional Experiment 01 sample_manifest.csv; scans only those regions.",
    )
    parser.add_argument(
        "--region-path",
        type=Path,
        action="append",
        default=[],
        help="Select an explicit complete region; may be repeated.",
    )
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument(
        "--skip-regions",
        type=int,
        default=0,
        help="Skip this many input directories before scanning.",
    )
    parser.add_argument(
        "--max-regions",
        type=int,
        default=0,
        help="Maximum directories to inspect; 0 means all input directories.",
    )
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument(
        "--max-zone-files",
        type=int,
        default=200,
        help="Skip aggregate regions containing more zone files; 0 disables the limit.",
    )
    parser.add_argument(
        "--max-region-mib",
        type=int,
        default=20,
        help="Skip regions whose listed zone files exceed this size; 0 disables the limit.",
    )
    parser.add_argument("--label-limit", type=int, default=6)
    parser.add_argument("--max-prefix-depth", type=int, default=1)
    parser.add_argument("--progress-every", type=int, default=1000)
    parser.add_argument(
        "--output",
        type=Path,
        default=EXPERIMENT_DIR / "dataset" / "census_real_cases.json",
    )
    parser.add_argument(
        "--selection-report",
        type=Path,
        default=EXPERIMENT_DIR / "dataset" / "census_real_selection.csv",
    )
    return parser.parse_args()


def _manifest_paths(path: Path) -> Iterator[Path]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            raw = row.get("path")
            if raw:
                yield Path(raw)


def _directory_paths(root: Path) -> Iterator[Path]:
    for entry in root.iterdir():
        if entry.is_dir():
            yield entry


def _bounded(paths: Iterable[Path], skip: int, maximum: int) -> Iterator[Path]:
    emitted = 0
    for index, path in enumerate(paths):
        if index < skip:
            continue
        if maximum and emitted >= maximum:
            return
        emitted += 1
        yield path


def _scan(
    paths: Iterable[Path],
    workers: int,
    progress_every: int,
    max_zone_files: int,
    max_total_bytes: int,
) -> tuple[list[CensusRegion], int]:
    candidates: list[CensusRegion] = []
    scanned = 0
    iterator = iter(paths)
    pending: set[Future[CensusRegion | None]] = set()
    max_pending = max(workers * 4, 1)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for _ in range(max_pending):
            try:
                path = next(iterator)
            except StopIteration:
                break
            pending.add(
                executor.submit(
                    load_census_region,
                    path,
                    True,
                    max_zone_files,
                    max_total_bytes,
                )
            )

        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                scanned += 1
                region = future.result()
                if region is not None:
                    candidates.append(region)
                    print(
                        f"[candidate] {region.name}: "
                        f"dname={region.features.dname} "
                        f"records={region.features.records} "
                        f"score={region.features.score}",
                        flush=True,
                    )
                if progress_every and scanned % progress_every == 0:
                    print(
                        f"[scan] regions={scanned:,} "
                        f"dname_candidates={len(candidates):,}",
                        flush=True,
                    )
                try:
                    path = next(iterator)
                except StopIteration:
                    continue
                pending.add(
                    executor.submit(
                        load_census_region,
                        path,
                        True,
                        max_zone_files,
                        max_total_bytes,
                    )
                )
    return candidates, scanned


def _write_selection(path: Path, regions: list[CensusRegion]) -> None:
    fields = [
        "rank",
        "region",
        "path",
        "score",
        "zone_files",
        "records",
        "dname",
        "cname",
        "wildcard",
        "non_apex_ns",
        "exact_below_dname_target",
        "wildcard_below_dname_target",
        "cname_into_dname",
        "delegation_dname_overlap",
        "chained_dname",
        "source_files",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for rank, region in enumerate(regions, start=1):
            feature_values = asdict(region.features)
            writer.writerow(
                {
                    "rank": rank,
                    "region": region.name,
                    "path": region.path,
                    "score": region.features.score,
                    **feature_values,
                    "source_files": "|".join(region.source_files),
                }
            )


def main() -> int:
    args = parse_args()
    census_dir = args.census_dir.resolve()
    if not census_dir.is_dir():
        raise FileNotFoundError(census_dir)
    if args.limit <= 0:
        raise ValueError("--limit must be positive")
    if args.skip_regions < 0:
        raise ValueError("--skip-regions cannot be negative")
    if args.workers <= 0:
        raise ValueError("--workers must be positive")
    if args.max_zone_files < 0:
        raise ValueError("--max-zone-files cannot be negative")
    if args.max_region_mib < 0:
        raise ValueError("--max-region-mib cannot be negative")
    if args.max_prefix_depth < 1:
        raise ValueError("--max-prefix-depth must be at least 1")

    if args.region_path:
        source = (path.resolve() for path in args.region_path)
        source_name = "explicit:" + ",".join(
            str(path.resolve()) for path in args.region_path
        )
    elif args.sample_manifest:
        source = _manifest_paths(args.sample_manifest.resolve())
        source_name = str(args.sample_manifest.resolve())
    else:
        source = _directory_paths(census_dir)
        source_name = str(census_dir)

    candidates, scanned = _scan(
        _bounded(source, args.skip_regions, args.max_regions),
        workers=args.workers,
        progress_every=args.progress_every,
        max_zone_files=args.max_zone_files,
        max_total_bytes=args.max_region_mib * 1024 * 1024,
    )
    selected = sorted(
        candidates,
        key=lambda region: (
            -region.features.score,
            region.features.records,
            region.name,
        ),
    )[: args.limit]
    if not selected:
        raise RuntimeError(
            "no complete DNAME-bearing region was found in the scanned input"
        )

    payload = dataset_payload(
        selected,
        label_limit=args.label_limit,
        max_prefix_depth=args.max_prefix_depth,
    )
    payload["provenance"] = {
        "census_dir": str(census_dir),
        "selection_source": source_name,
        "regions_scanned": scanned,
        "regions_skipped": args.skip_regions,
        "dname_candidates": len(candidates),
        "selected_regions": [region.name for region in selected],
        "max_zone_files": args.max_zone_files,
        "max_region_mib": args.max_region_mib,
    }

    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    report = args.selection_report.resolve()
    _write_selection(report, selected)

    print(
        f"[done] scanned={scanned:,} candidates={len(candidates):,} "
        f"selected={len(selected):,} cases={len(payload['cases']):,}"
    )
    print(f"[result] dataset={output}")
    print(f"[result] selection={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
