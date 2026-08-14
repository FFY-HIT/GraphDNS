from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from .model import is_descendant_or_same, is_strict_descendant, normalize_domain


SUPPORTED_TYPES = {"A", "AAAA", "NS", "CNAME", "DNAME"}
DOMAIN_RDATA_TYPES = {"NS", "CNAME", "DNAME"}
_DNAME_TOKEN = re.compile(r"(?:^|\s)DNAME(?:\s|$)", re.IGNORECASE)
_SAFE_ID = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class CensusRecord:
    id: str
    server: str
    zone: str
    owner: str
    type: str
    value: str
    source_file: str
    source_line: int


@dataclass(frozen=True)
class RegionFeatures:
    zone_files: int
    records: int
    dname: int
    cname: int
    wildcard: int
    non_apex_ns: int
    exact_below_dname_target: int
    wildcard_below_dname_target: int
    cname_into_dname: int
    delegation_dname_overlap: int
    chained_dname: int

    @property
    def score(self) -> int:
        return (
            self.dname * 100
            + self.chained_dname * 45
            + self.cname_into_dname * 35
            + self.delegation_dname_overlap * 30
            + self.wildcard_below_dname_target * 25
            + self.exact_below_dname_target * 15
            + min(self.wildcard, 10)
            + min(self.non_apex_ns, 10)
        )


@dataclass(frozen=True)
class CensusRegion:
    name: str
    path: str
    records: tuple[CensusRecord, ...]
    authorities: dict[str, str]
    source_files: tuple[str, ...]
    features: RegionFeatures


def _strip_comment(line: str) -> str:
    quoted = False
    escaped = False
    result: list[str] = []
    for char in line:
        if escaped:
            result.append(char)
            escaped = False
            continue
        if char == "\\":
            result.append(char)
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            result.append(char)
            continue
        if char == ";" and not quoted:
            break
        result.append(char)
    return "".join(result).strip()


def _absolute_name(value: str, zone: str) -> str:
    value = value.strip().lower()
    if value == "@":
        return normalize_domain(zone)
    if value.endswith("."):
        return normalize_domain(value)
    return normalize_domain(f"{value}.{zone}")


def _infer_zone(file_name: str, text: str) -> str:
    for raw_line in text.splitlines():
        line = _strip_comment(raw_line)
        if not line:
            continue
        tokens = line.split()
        upper = [token.upper() for token in tokens]
        if "SOA" in upper:
            return normalize_domain(tokens[0])

    name = file_name
    if name.lower().endswith(".txt"):
        name = name[:-4]
    return normalize_domain(name.rstrip("."))


def _parse_zone_file(
    path: Path,
    server: str,
) -> tuple[str, list[CensusRecord]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    zone = _infer_zone(path.name, text)
    records: list[CensusRecord] = []

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw_line)
        if not line or line.startswith("$"):
            continue
        tokens = line.split()
        upper = [token.upper() for token in tokens]
        try:
            class_index = upper.index("IN")
        except ValueError:
            continue
        if class_index + 2 >= len(tokens):
            continue

        record_type = upper[class_index + 1]
        if record_type not in SUPPORTED_TYPES:
            continue

        owner = _absolute_name(tokens[0], zone)
        value = tokens[class_index + 2]
        if record_type in DOMAIN_RDATA_TYPES:
            value = _absolute_name(value, zone)

        records.append(
            CensusRecord(
                id=f"{path.stem}:{line_number}",
                server=normalize_domain(server),
                zone=zone,
                owner=owner,
                type=record_type,
                value=value,
                source_file=path.name,
                source_line=line_number,
            )
        )
    return zone, records


def _has_dname(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return "DNAME" in text.upper() and _DNAME_TOKEN.search(text) is not None


def _compute_features(
    records: tuple[CensusRecord, ...],
    zone_file_count: int,
) -> RegionFeatures:
    dnames = [record for record in records if record.type == "DNAME"]
    cnames = [record for record in records if record.type == "CNAME"]
    ns_records = [record for record in records if record.type == "NS"]
    wildcards = [record for record in records if record.owner.startswith("*.")]
    exact_owners = {
        record.owner for record in records if not record.owner.startswith("*.")
    }

    exact_below_target = 0
    wildcard_below_target = 0
    cname_into_dname = 0
    delegation_overlap = 0
    chained_dname = 0

    for dname in dnames:
        exact_below_target += sum(
            1
            for owner in exact_owners
            if is_strict_descendant(owner, dname.value)
        )
        wildcard_below_target += sum(
            1
            for record in wildcards
            if is_descendant_or_same(record.owner[2:], dname.value)
        )
        cname_into_dname += sum(
            1
            for cname in cnames
            if is_strict_descendant(cname.value, dname.owner)
        )
        delegation_overlap += sum(
            1
            for ns in ns_records
            if ns.owner != ns.zone
            and (
                is_descendant_or_same(ns.owner, dname.owner)
                or is_descendant_or_same(ns.owner, dname.value)
                or is_descendant_or_same(dname.owner, ns.owner)
                or is_descendant_or_same(dname.value, ns.owner)
            )
        )
        chained_dname += sum(
            1
            for other in dnames
            if other.id != dname.id
            and is_descendant_or_same(dname.value, other.owner)
        )

    return RegionFeatures(
        zone_files=zone_file_count,
        records=len(records),
        dname=len(dnames),
        cname=len(cnames),
        wildcard=len(wildcards),
        non_apex_ns=sum(1 for record in ns_records if record.owner != record.zone),
        exact_below_dname_target=exact_below_target,
        wildcard_below_dname_target=wildcard_below_target,
        cname_into_dname=cname_into_dname,
        delegation_dname_overlap=delegation_overlap,
        chained_dname=chained_dname,
    )


def load_census_region(
    region_path: Path,
    require_dname: bool = True,
    max_zone_files: int = 0,
    max_total_bytes: int = 0,
) -> CensusRegion | None:
    metadata_path = region_path / "metadata.json"
    if not metadata_path.is_file():
        return None
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None

    entries = metadata.get("ZoneFiles")
    if not isinstance(entries, list) or not entries:
        return None
    if max_zone_files and len(entries) > max_zone_files:
        return None

    zone_paths: list[tuple[Path, str]] = []
    total_bytes = 0
    for entry in entries:
        if not isinstance(entry, dict):
            return None
        file_name = entry.get("FileName")
        server = entry.get("NameServer")
        if not isinstance(file_name, str) or not isinstance(server, str):
            return None
        path = region_path / file_name
        if not path.is_file():
            return None
        try:
            total_bytes += path.stat().st_size
        except OSError:
            return None
        if max_total_bytes and total_bytes > max_total_bytes:
            return None
        zone_paths.append((path, server))

    if require_dname and not any(_has_dname(path) for path, _ in zone_paths):
        return None

    authorities: dict[str, str] = {}
    records: list[CensusRecord] = []
    for path, server in zone_paths:
        try:
            zone, parsed = _parse_zone_file(path, server)
        except OSError:
            return None
        authorities.setdefault(zone, normalize_domain(server))
        records.extend(parsed)

    record_tuple = tuple(records)
    features = _compute_features(record_tuple, len(zone_paths))
    if require_dname and features.dname == 0:
        return None

    return CensusRegion(
        name=region_path.name,
        path=str(region_path.resolve()),
        records=record_tuple,
        authorities=authorities,
        source_files=tuple(path.name for path, _ in zone_paths),
        features=features,
    )


def _safe_identifier(value: str) -> str:
    return _SAFE_ID.sub("_", value.lower()).strip("_")


def _query_labels(
    records: Iterable[CensusRecord],
    dnames: Iterable[CensusRecord],
    limit: int,
) -> list[str]:
    observed: list[str] = []
    dname_list = list(dnames)
    for record in records:
        for dname in dname_list:
            for suffix in (dname.owner, dname.value):
                if not is_strict_descendant(record.owner, suffix):
                    continue
                prefix = record.owner[: -(len(suffix) + 1)]
                label = prefix.split(".")[-1]
                if label and label != "*" and label not in observed:
                    observed.append(label)

    for label in ("www", "api", "mail", "x"):
        if label not in observed:
            observed.append(label)
    return observed[:limit]


def region_to_cases(
    region: CensusRegion,
    label_limit: int = 6,
    max_prefix_depth: int = 1,
) -> list[dict[str, Any]]:
    by_zone: dict[str, list[CensusRecord]] = {}
    for record in region.records:
        by_zone.setdefault(record.zone, []).append(record)

    cases: list[dict[str, Any]] = []
    for zone, zone_records in sorted(by_zone.items()):
        dnames = [record for record in zone_records if record.type == "DNAME"]
        if not dnames:
            continue
        start_server = region.authorities.get(zone, dnames[0].server)
        labels = _query_labels(region.records, dnames, label_limit)
        query_templates = [
            {
                "suffix": dname.owner,
                "min_depth": 0,
                "max_depth": max_prefix_depth,
            }
            for dname in dnames
        ]
        case_id = f"census_{_safe_identifier(region.name)}_{_safe_identifier(zone)}"
        cases.append(
            {
                "id": case_id,
                "description": (
                    f"Real Census region {region.name}; DNAME-bearing zone {zone}."
                ),
                "source": {
                    "dataset": "Census",
                    "region": region.name,
                    "region_path": region.path,
                    "zone_files": list(region.source_files),
                    "features": {
                        **asdict(region.features),
                        "score": region.features.score,
                    },
                },
                "start_server": start_server,
                "start_zone": zone,
                "authorities": region.authorities,
                "labels": labels,
                "query_templates": query_templates,
                "records": [
                    {
                        "id": record.id,
                        "server": record.server,
                        "zone": record.zone,
                        "owner": record.owner,
                        "type": record.type,
                        "value": record.value,
                    }
                    for record in region.records
                ],
            }
        )
    return cases


def dataset_payload(
    regions: Iterable[CensusRegion],
    label_limit: int = 6,
    max_prefix_depth: int = 1,
) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    for region in regions:
        cases.extend(
            region_to_cases(
                region,
                label_limit=label_limit,
                max_prefix_depth=max_prefix_depth,
            )
        )
    return {
        "description": (
            "Bounded real-world Census cases selected for the alpha/beta and "
            "dynamic-binding ablation."
        ),
        "ablation_expectations": {
            "concrete_oracle_is_safe": False,
            "unbound_must_have_false_paths": False,
            "unbound_must_have_false_vulnerabilities": False,
        },
        "selection_scope": {
            "complete_region_directories": True,
            "requires_dname": True,
            "label_limit": label_limit,
            "max_prefix_depth": max_prefix_depth,
        },
        "cases": cases,
    }
