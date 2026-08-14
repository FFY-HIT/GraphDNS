#!/usr/bin/env python3
"""Run the official GRoot binary and emit canonical JSONL findings.

This adapter deliberately does not reimplement GRoot.  It invokes the binary
from the official ``dnsgt/groot`` image in a persistent container, preserves
the raw JSON/lint output next to the canonical output, and only normalizes the
fields needed by experiment 01.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]


SHARED_PROPERTIES = [
    {"PropertyName": "DelegationConsistency"},
    {"PropertyName": "LameDelegation"},
    {"PropertyName": "RewriteBlackholing"},
    {"PropertyName": "DNAMESubstitutionCheck"},
    # GRoot terminates cyclic rewrites using its rewrite bound.  A violation of
    # this deliberately high bound is normalized as an RL witness below.
    {"PropertyName": "Rewrites", "Value": 16},
]


def normalize_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if text.startswith("~{ }."):
        text = text[len("~{ }.") :]
    return text if text.endswith(".") else text + "."


def host_to_container(path: Path, host_root: Path, container_root: Path) -> Path:
    try:
        relative = path.resolve().relative_to(host_root.resolve())
    except ValueError as exc:
        raise ValueError(f"path {path} is outside mounted host root {host_root}") from exc
    return container_root / relative


def is_subdomain(name: str, suffix: str) -> bool:
    name = normalize_name(name)
    suffix = normalize_name(suffix)
    return name == suffix or name.endswith("." + suffix)


class DelegationIndex:
    """Small independent index used only to canonicalize GRoot cycle witnesses."""

    def __init__(self, region: Path) -> None:
        self.entries: list[tuple[str, str]] = []
        metadata_path = region / "metadata.json"
        if not metadata_path.is_file():
            return
        metadata = json.loads(metadata_path.read_text(encoding="utf-8", errors="replace"))
        for item in metadata.get("ZoneFiles", []):
            if not isinstance(item, dict):
                continue
            zone_path = region / str(item.get("FileName", ""))
            if not zone_path.is_file():
                continue
            for raw_line in zone_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw_line.split(";", 1)[0].strip()
                if not line:
                    continue
                fields = line.split()
                upper = [field.upper() for field in fields]
                try:
                    ns_index = upper.index("NS")
                except ValueError:
                    continue
                if ns_index == 0 or ns_index + 1 >= len(fields):
                    continue
                owner = normalize_name(fields[0])
                target = normalize_name(fields[ns_index + 1])
                self.entries.append((owner, target))

    def cut_for(self, query: str, nameserver: str) -> str:
        candidates = [
            owner
            for owner, target in self.entries
            if target == normalize_name(nameserver) and is_subdomain(query, owner)
        ]
        if not candidates:
            return normalize_name(query)
        return max(candidates, key=lambda name: (name.count("."), len(name)))


def canonical_from_property(
    item: dict[str, Any], delegation_index: DelegationIndex | None = None
) -> dict[str, Any] | None:
    prop = str(item.get("Property", "")).strip()
    violation = item.get("Violation")
    violation = violation if isinstance(violation, dict) else {}
    query = normalize_name(item.get("Query"))

    if prop == "Delegation Consistency":
        return {
            "kind": "DI",
            "zone_cut": query,
            "reason": f"GRoot delegation inconsistency: {violation.get('InconsistencyType', '')}",
        }
    if prop == "Lame Delegation":
        nameserver = normalize_name(violation.get("Nameserver2"))
        zone_cut = (
            delegation_index.cut_for(query, nameserver)
            if delegation_index is not None
            else query
        )
        return {
            "kind": "LD",
            "zone_cut": zone_cut,
            "nameserver": nameserver,
            "reason": "GRoot child nameserver returned REFUSED",
        }
    if prop == "Rewrite Blackholing":
        target = normalize_name(violation.get("RewriteTarget"))
        return {
            "kind": "RB",
            "start": query,
            "target": target,
            "reason": "GRoot rewrite path terminates with NX",
        }
    if prop == "DNAME Substitution exceeds length":
        target = normalize_name(violation.get("RewriteTarget"))
        return {
            "kind": "ML",
            "start": query,
            "target": target,
            "reason": "GRoot DNAME substitution exceeds the DNS name-length bound",
        }
    if prop == "Rewrites" and int(violation.get("ActualRewrites", 0) or 0) > 16:
        # GRoot does not expose the repeated state in this report.  Its bounded
        # rewrite witness is therefore keyed by the starting equivalence class.
        return {
            "kind": "RL",
            "start": query,
            "target": query,
            "case_key": f"RL|start={query}|repeat={query}",
            "reason": "GRoot path exceeds the 16-rewrite loop guard",
        }
    if prop == "Cyclic Zone Dependency":
        loop = item.get("Loop")
        loop = loop if isinstance(loop, list) else []
        has_rewrite = any(
            isinstance(node, dict) and int(node.get("AnswerTag", -1)) == 1
            for node in loop
        )
        if has_rewrite:
            starts = [
                normalize_name(node.get("Query"))
                for node in loop
                if isinstance(node, dict) and node.get("Query")
            ]
            start = starts[0] if starts else ""
            return {
                "kind": "RL",
                "start": start,
                "target": start,
                "case_key": f"RL|start={start}|repeat={start}",
                "reason": "GRoot interpretation-graph cycle contains a rewrite",
            }
        zones = []
        for node in loop:
            if not isinstance(node, dict) or not node.get("Query"):
                continue
            query_name = normalize_name(node.get("Query"))
            nameserver = normalize_name(node.get("NS"))
            cut = (
                delegation_index.cut_for(query_name, nameserver)
                if delegation_index is not None
                else query_name
            )
            zones.append(cut)
        zones = sorted(set(zones))
        return {
            "kind": "CZD",
            "cycle_zones": zones,
            "case_key": "CZD|zones=" + "|".join(zones),
            "reason": "GRoot interpretation graph contains a zone-dependency cycle",
        }
    return None


NS_RECORD_RE = re.compile(r"^\s*(\S+)\s+NS\s+(\S+)\s*$", re.IGNORECASE)


def canonical_from_lint(item: dict[str, Any]) -> dict[str, Any] | None:
    if str(item.get("Violation", "")).strip() != "Missing Glue Record":
        return None
    record = str(item.get("Resource Record", "")).strip()
    match = NS_RECORD_RE.match(record)
    if not match:
        return None
    zone_cut = normalize_name(match.group(1))
    nameserver = normalize_name(match.group(2))
    return {
        "kind": "MG",
        "zone_cut": zone_cut,
        "nameserver": nameserver,
        "server": normalize_name(item.get("Server")),
        "zone": normalize_name(item.get("Zone")),
        "reason": "GRoot lint reports an in-bailiwick NS without glue",
    }


def load_json_array(path: Path) -> list[dict[str, Any]]:
    if not path.is_file() or not path.read_text(encoding="utf-8", errors="replace").strip():
        return []
    value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(value, list):
        raise ValueError(f"expected a JSON array in {path}")
    return [item for item in value if isinstance(item, dict)]


def deduplicate(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for row in rows:
        identity = json.dumps(row, sort_keys=True, ensure_ascii=False)
        if identity in seen:
            continue
        seen.add(identity)
        result.append(row)
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", type=Path, required=True)
    parser.add_argument("--region-name", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--container", default="graphdns-groot-baseline")
    parser.add_argument("--census-root", type=Path, default=Path("/path/to/census"))
    parser.add_argument("--container-census-root", type=Path, default=Path("/data"))
    parser.add_argument("--host-workspace", type=Path, default=REPO_ROOT)
    parser.add_argument("--container-workspace", type=Path, default=Path("/workspace"))
    parser.add_argument("--groot-bin", default="/home/groot/groot/build/bin/groot")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    region = args.region.resolve()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    jobs_path = output.parent / "groot_jobs.json"
    raw_path = output.parent / "groot_raw.json"
    lint_path = output.parent / "lint.json"
    stdout_path = output.parent / "groot_stdout.txt"
    domain = normalize_name(args.region_name)
    jobs_path.write_text(
        json.dumps(
            [{"Domain": domain, "SubDomain": True, "Properties": SHARED_PROPERTIES}],
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    container_region = args.container_census_root / region.relative_to(args.census_root.resolve())
    container_workdir = host_to_container(
        output.parent, args.host_workspace, args.container_workspace
    )
    container_jobs = host_to_container(jobs_path, args.host_workspace, args.container_workspace)
    container_raw = host_to_container(raw_path, args.host_workspace, args.container_workspace)

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
        "--lint",
        "--stats",
    ]
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        return completed.returncode

    rows: list[dict[str, Any]] = []
    delegation_index = DelegationIndex(region)
    rows.extend(
        row
        for item in load_json_array(raw_path)
        if (row := canonical_from_property(item, delegation_index)) is not None
    )
    rows.extend(
        row
        for item in load_json_array(lint_path)
        if (row := canonical_from_lint(item)) is not None
    )
    rows = deduplicate(rows)
    output.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
