from __future__ import annotations

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


def _complete_region(path: Path) -> tuple[bool, int]:
    metadata_path = path / "metadata.json"
    if not metadata_path.is_file():
        return False, 0
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False, 0
    zone_files = metadata.get("ZoneFiles")
    if not isinstance(zone_files, list) or not zone_files:
        return False, 0
    names: list[str] = []
    for entry in zone_files:
        if not isinstance(entry, dict) or not isinstance(entry.get("FileName"), str):
            return False, 0
        names.append(entry["FileName"])
    return (all((path / name).is_file() for name in names), len(names))


def _score(seed: int, name: str) -> int:
    payload = f"{seed}\0{name}".encode("utf-8", errors="surrogatepass")
    return int.from_bytes(hashlib.blake2b(payload, digest_size=16).digest(), "big")


def sample_complete_regions(
    census_dir: Path,
    sample_size: int,
    seed: int,
    progress: Callable[[str], None] | None = None,
) -> list[Region]:
    """Return a deterministic random sample without copying Census folders."""
    census_dir = census_dir.resolve()
    if sample_size <= 0:
        raise ValueError("sample_size must be positive")
    if not census_dir.is_dir():
        raise FileNotFoundError(f"Census directory does not exist: {census_dir}")

    pool_size = max(sample_size * 2, sample_size + 1000)
    while True:
        heap: list[tuple[int, str, str]] = []
        directory_count = 0
        with os.scandir(census_dir) as entries:
            for entry in entries:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                directory_count += 1
                score = _score(seed, entry.name)
                item = (-score, entry.name, str(Path(entry.path).resolve()))
                if len(heap) < pool_size:
                    heapq.heappush(heap, item)
                elif item[0] > heap[0][0]:
                    heapq.heapreplace(heap, item)
                if progress and directory_count % 100000 == 0:
                    progress(
                        f"[sample] scanned={directory_count:,} pool={len(heap):,}"
                    )

        selected: list[tuple[int, str, str, int]] = []
        candidates = sorted(
            ((-negative, name, path) for negative, name, path in heap),
            key=lambda item: (item[0], item[1]),
        )
        for score, name, path in candidates:
            complete, file_count = _complete_region(Path(path))
            if not complete:
                continue
            selected.append((score, name, path, file_count))
            if len(selected) == sample_size:
                break
        if len(selected) == sample_size:
            return [
                Region(
                    sample_rank=index,
                    name=name,
                    path=path,
                    sample_score=f"{score:032x}",
                    zone_file_count=file_count,
                )
                for index, (score, name, path, file_count) in enumerate(
                    selected, start=1
                )
            ]
        if pool_size >= directory_count:
            raise RuntimeError(
                f"requested {sample_size} complete regions, found {len(selected)}"
            )
        pool_size = min(directory_count, pool_size * 2)
        if progress:
            progress(f"[sample] expanding candidate pool to {pool_size:,}")


def region_dicts(regions: Iterable[Region]) -> list[dict[str, object]]:
    return [asdict(region) for region in regions]
