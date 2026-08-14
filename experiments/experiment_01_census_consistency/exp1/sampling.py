from __future__ import annotations

import csv
import hashlib
import heapq
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable


@dataclass(frozen=True)
class Region:
    sample_rank: int
    name: str
    path: str
    sample_score: str
    zone_file_count: int


@dataclass
class ScanStats:
    directory_entries: int = 0
    directory_regions: int = 0
    candidate_regions_checked: int = 0
    complete_regions: int = 0
    missing_metadata: int = 0
    invalid_metadata: int = 0
    incomplete_zone_files: int = 0


def _complete_region(path: Path) -> tuple[bool, int, str]:
    metadata_path = path / "metadata.json"
    if not metadata_path.is_file():
        return False, 0, "missing_metadata"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False, 0, "invalid_metadata"
    zone_files = metadata.get("ZoneFiles")
    if not isinstance(zone_files, list) or not zone_files:
        return False, 0, "invalid_metadata"
    names: list[str] = []
    for entry in zone_files:
        if not isinstance(entry, dict) or not isinstance(entry.get("FileName"), str):
            return False, 0, "invalid_metadata"
        names.append(entry["FileName"])
    if any(not (path / name).is_file() for name in names):
        return False, len(names), "incomplete_zone_files"
    return True, len(names), ""


def _sample_score(seed: int, relative_name: str) -> int:
    payload = f"{seed}\0{relative_name}".encode("utf-8", errors="surrogatepass")
    return int.from_bytes(hashlib.blake2b(payload, digest_size=16).digest(), "big")


def sample_complete_regions(
    census_dir: Path,
    sample_size: int,
    seed: int,
    progress: Callable[[str], None] | None = None,
) -> tuple[list[Region], ScanStats]:
    if sample_size <= 0:
        raise ValueError("sample_size must be positive")
    census_dir = census_dir.resolve()
    if not census_dir.is_dir():
        raise FileNotFoundError(f"Census directory does not exist: {census_dir}")

    # First sample directory names without opening metadata files. We then check
    # candidates in hash order and stop after sample_size complete folders. If
    # the pool contains too many partial folders, it is enlarged and rescanned.
    # The result is still the sample_size lowest hashes among complete regions.
    pool_size = max(sample_size * 2, sample_size + 1000)
    selected: list[tuple[int, str, str, int]] = []
    stats = ScanStats()
    while True:
        heap: list[tuple[int, str, str]] = []
        directory_entries = 0
        directory_regions = 0
        with os.scandir(census_dir) as entries:
            for entry in entries:
                directory_entries += 1
                if not entry.is_dir(follow_symlinks=False):
                    continue
                directory_regions += 1
                score = _sample_score(seed, entry.name)
                item = (-score, entry.name, str(Path(entry.path).resolve()))
                if len(heap) < pool_size:
                    heapq.heappush(heap, item)
                elif item[0] > heap[0][0]:
                    heapq.heapreplace(heap, item)
                if progress and directory_entries % 100000 == 0:
                    progress(
                        f"[sample] scanned={directory_entries} candidate_pool={len(heap)}"
                    )

        stats = ScanStats(
            directory_entries=directory_entries,
            directory_regions=directory_regions,
        )
        selected = []
        candidates = sorted(
            ((-negative_score, name, path) for negative_score, name, path in heap),
            key=lambda item: (item[0], item[1]),
        )
        for score, name, path_string in candidates:
            stats.candidate_regions_checked += 1
            complete, file_count, reason = _complete_region(Path(path_string))
            if not complete:
                setattr(stats, reason, getattr(stats, reason) + 1)
                continue
            stats.complete_regions += 1
            selected.append((score, name, path_string, file_count))
            if len(selected) == sample_size:
                break
        if len(selected) == sample_size:
            break
        if pool_size >= directory_regions:
            raise RuntimeError(
                f"requested {sample_size} complete regions, but found only {len(selected)}"
            )
        pool_size = min(directory_regions, pool_size * 2)
        if progress:
            progress(
                f"[sample] only {len(selected)} complete candidates; expanding pool to {pool_size}"
            )

    regions = [
        Region(
            sample_rank=index,
            name=name,
            path=path,
            sample_score=f"{score:032x}",
            zone_file_count=file_count,
        )
        for index, (score, name, path, file_count) in enumerate(selected, start=1)
    ]
    return regions, stats


def write_sample_manifest(path: Path, regions: Iterable[Region]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = ["sample_rank", "name", "path", "sample_score", "zone_file_count"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for region in regions:
            writer.writerow(asdict(region))


def read_sample_manifest(path: Path) -> list[Region]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        return [
            Region(
                sample_rank=int(row["sample_rank"]),
                name=row["name"],
                path=row["path"],
                sample_score=row["sample_score"],
                zone_file_count=int(row["zone_file_count"]),
            )
            for row in csv.DictReader(handle)
        ]
