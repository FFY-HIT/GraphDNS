#!/usr/bin/env python3
"""Audit GraphDNS experiment-1 findings against the sampled zone snapshot.

This script does not claim Internet-wide ground truth.  It checks whether each
report has the evidence required by the selected Census region and separates
snapshot-confirmed findings from reports that require an unavailable child or
authoritative-server view.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SUPPORTED_TYPES = {"NS", "A", "AAAA", "CNAME", "DNAME", "MX", "TXT"}
REWRITE_EDGE_RE = re.compile(
    r"\]\s+(\S+)\s+--(CNAME|DNAME)/reach=1-->\s+(\S+)"
)


def dns_name(value: str) -> str:
    value = value.strip().lower()
    if not value:
        return ""
    return value if value.endswith(".") else value + "."


def is_descendant_or_same(name: str, suffix: str) -> bool:
    name = dns_name(name)
    suffix = dns_name(suffix)
    return name == suffix or name.endswith("." + suffix)


def wildcard_matches(owner: str, name: str) -> bool:
    owner = dns_name(owner)
    name = dns_name(name)
    if not owner.startswith("*."):
        return False
    suffix = owner[2:]
    if not name.endswith("." + suffix):
        return False
    prefix = name[: -(len(suffix) + 1)]
    return bool(prefix) and "." not in prefix


@dataclass(frozen=True)
class Fact:
    server: str
    zone: str
    owner: str
    rrtype: str
    rdata: str


class RegionFacts:
    def __init__(self, facts: Iterable[Fact]) -> None:
        self.records = list(facts)
        self.by_context_owner: dict[
            tuple[str, str, str], list[Fact]
        ] = defaultdict(list)
        self.by_zone_owner: dict[tuple[str, str], list[Fact]] = defaultdict(list)
        self.ns_by_context: dict[tuple[str, str], list[Fact]] = defaultdict(list)
        self.dname_by_context: dict[tuple[str, str], list[Fact]] = defaultdict(list)

        for fact in self.records:
            self.by_context_owner[(fact.server, fact.zone, fact.owner)].append(fact)
            self.by_zone_owner[(fact.zone, fact.owner)].append(fact)
            if fact.rrtype == "NS":
                self.ns_by_context[(fact.server, fact.zone)].append(fact)
            elif fact.rrtype == "DNAME":
                self.dname_by_context[(fact.server, fact.zone)].append(fact)

    def owner_records(self, server: str, zone: str, owner: str) -> list[Fact]:
        return self.by_context_owner.get(
            (dns_name(server), dns_name(zone), dns_name(owner)), []
        )

    def zone_owner_records(self, zone: str, owner: str) -> list[Fact]:
        return self.by_zone_owner.get((dns_name(zone), dns_name(owner)), [])

    def delegation_ancestors(
        self, server: str, zone: str, owner: str
    ) -> list[Fact]:
        context = (dns_name(server), dns_name(zone))
        zone_name = context[1]
        return [
            fact
            for fact in self.ns_by_context.get(context, [])
            if fact.owner != zone_name
            and is_descendant_or_same(owner, fact.owner)
        ]

    def dname_ancestors(
        self, server: str, zone: str, owner: str
    ) -> list[Fact]:
        context = (dns_name(server), dns_name(zone))
        return [
            fact
            for fact in self.dname_by_context.get(context, [])
            if dns_name(owner) != fact.owner
            and is_descendant_or_same(owner, fact.owner)
        ]


def parse_facts(path: Path) -> RegionFacts:
    facts: list[Fact] = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            fields = line.rstrip("\n").split("\t", 4)
            if len(fields) != 5:
                continue
            server, zone, owner, rrtype, rdata = fields
            rrtype = rrtype.upper()
            if rrtype not in SUPPORTED_TYPES:
                continue
            facts.append(
                Fact(
                    dns_name(server),
                    dns_name(zone),
                    dns_name(owner),
                    rrtype,
                    dns_name(rdata.split("\t", 1)[0]),
                )
            )
    return RegionFacts(facts)


def metadata_zones(region_path: Path) -> set[str]:
    metadata = json.loads((region_path / "metadata.json").read_text())
    zones: set[str] = set()
    for entry in metadata.get("ZoneFiles", []):
        filename = str(entry.get("FileName", ""))
        if filename.endswith(".txt"):
            filename = filename[:-4]
        zones.add(dns_name(filename.rstrip(".")))
    return zones


def preprocess_region(
    preprocess_bin: Path,
    region_path: Path,
    cache_root: Path,
) -> RegionFacts:
    cache_dir = cache_root / region_path.name
    cache_dir.mkdir(parents=True, exist_ok=True)
    facts_path = cache_dir / "ZoneRecord.facts"
    if not facts_path.exists():
        result = subprocess.run(
            [str(preprocess_bin), str(region_path)],
            cwd=cache_dir,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0 or not facts_path.exists():
            raise RuntimeError(
                f"preprocess failed for {region_path}: "
                f"{result.stderr or result.stdout}"
            )
    return parse_facts(facts_path)


def record_type_from_report(report: dict[str, object]) -> str:
    query = str(report.get("query", ""))
    fields = query.split()
    return fields[1].upper() if len(fields) >= 2 else ""


def classify_report(
    report: dict[str, object],
    facts: RegionFacts,
    child_zones: set[str],
    mg_keys: set[tuple[str, str, str]],
) -> tuple[str, str]:
    kind = str(report.get("kind", ""))
    region = str(report.get("region_name", ""))
    zone = dns_name(str(report.get("zone", "")))
    server = dns_name(str(report.get("server", "")))
    owner = dns_name(str(report.get("start_name", "")))
    target = dns_name(str(report.get("target", "")))
    cut = dns_name(str(report.get("zone_cut", "")))
    nameserver = dns_name(str(report.get("nameserver", "")))
    reason = str(report.get("reason", ""))

    if kind == "DI":
        if reason == "child-side NS missing":
            if cut not in child_zones:
                return (
                    "indeterminate",
                    "delegated child zone is absent from the sampled input",
                )
            return (
                "snapshot-confirmed",
                "child zone is present but has no collected apex NS view",
            )
        if "glue differs" in reason:
            key = (region, cut, nameserver)
            if key in mg_keys:
                return (
                    "snapshot-confirmed-overlap",
                    "same missing parent glue is also reported as MG",
                )
            return (
                "snapshot-confirmed",
                "provided parent and child address sets differ",
            )
        return (
            "snapshot-confirmed",
            "provided parent and child NS sets differ",
        )

    if kind == "MG":
        parent_ns = [
            fact
            for fact in facts.zone_owner_records(zone, cut)
            if fact.rrtype == "NS" and fact.rdata == nameserver
        ]
        parent_addr = [
            fact
            for fact in facts.zone_owner_records(zone, nameserver)
            if fact.rrtype in {"A", "AAAA"}
        ]
        if parent_ns and not parent_addr and is_descendant_or_same(nameserver, cut):
            return (
                "snapshot-confirmed",
                "in-bailiwick NS is present and parent-side glue is absent",
            )
        return (
            "implementation-mismatch",
            "report prerequisites are not reproduced from the sampled facts",
        )

    if kind == "RL":
        rewrites = REWRITE_EDGE_RE.findall(str(report.get("path", "")))
        if not rewrites:
            return (
                "implementation-mismatch",
                "reported path contains no base CNAME/DNAME rewrite",
            )
        seen: set[str] = set()
        for src, _, dst in rewrites:
            src_name, dst_name = dns_name(src), dns_name(dst)
            if not seen:
                seen.add(src_name)
            if dst_name in seen:
                return (
                    "snapshot-confirmed",
                    "base rewrite sequence repeats a previously queried name",
                )
            seen.add(dst_name)
        if len(rewrites) == 1:
            return (
                "false-positive",
                "NS rdata owner was incorrectly executed as a rewrite of the delegated query",
            )
        return (
            "implementation-mismatch",
            "reported rewrite sequence does not repeat a query name",
        )

    if kind == "RB":
        target_records = facts.zone_owner_records(zone, target)
        if any(
            fact.rrtype in {"A", "AAAA", "CNAME", "DNAME"}
            for fact in target_records
        ):
            return (
                "implementation-mismatch",
                "target has an answer or rewrite record in the sampled zone",
            )

        wildcard_or_dname = [
            fact
            for fact in facts.records
            if fact.zone == zone
            and (
                (
                    fact.owner.startswith("*.")
                    and wildcard_matches(fact.owner, target)
                    and fact.rrtype in {"A", "AAAA", "CNAME"}
                )
                or (
                    fact.rrtype == "DNAME"
                    and fact.owner != target
                    and is_descendant_or_same(target, fact.owner)
                )
            )
        ]
        if wildcard_or_dname:
            return (
                "implementation-mismatch",
                "target has a wildcard or ancestor-DNAME continuation in the sampled zone",
            )

        delegated = []
        for (fact_server, fact_zone), ns_records in facts.ns_by_context.items():
            if fact_zone != zone:
                continue
            delegated.extend(
                fact
                for fact in ns_records
                if fact.owner != fact_zone
                and is_descendant_or_same(target, fact.owner)
            )
        if delegated:
            return (
                "indeterminate",
                "target lies below a delegation whose child view may be absent",
            )
        return (
            "snapshot-confirmed",
            "rewritten target is in a known zone and has no terminal or continuation record",
        )

    if kind == "STALE":
        rrtype = record_type_from_report(report)
        if owner == zone:
            return (
                "false-positive",
                "zone-apex records remain authoritative in their own zone",
            )

        dname_ancestors = facts.dname_ancestors(server, zone, owner)
        if dname_ancestors:
            return (
                "snapshot-confirmed",
                "record is below an ancestor DNAME",
            )

        delegations = facts.delegation_ancestors(server, zone, owner)
        if delegations:
            is_glue = rrtype in {"A", "AAAA"} and any(
                ns.rdata == owner for ns in delegations
            )
            if is_glue:
                return (
                    "false-positive",
                    "address record is required as glue for the blocking delegation",
                )
            return (
                "snapshot-confirmed",
                "record is at or below a parent-zone delegation cut",
            )

        if owner.startswith("*."):
            return (
                "needs-review",
                "wildcard applicability is query-specific and cannot be rejected globally",
            )
        return (
            "needs-review",
            "no explicit ancestor NS or DNAME blocker was reconstructed",
        )

    if kind in {"LD", "CZD", "ML"}:
        return ("needs-review", "no reports of this kind were expected in this run")

    return ("needs-review", "unsupported report kind")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--preprocess-bin", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    reports = [
        json.loads(line)
        for line in args.findings.read_text().splitlines()
        if line.strip()
    ]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    cache_root = args.output_dir / "facts_cache"
    cache_root.mkdir(exist_ok=True)

    mg_keys = {
        (
            str(report.get("region_name", "")),
            dns_name(str(report.get("zone_cut", ""))),
            dns_name(str(report.get("nameserver", ""))),
        )
        for report in reports
        if report.get("kind") == "MG"
    }

    facts_cache: dict[str, RegionFacts] = {}
    zones_cache: dict[str, set[str]] = {}
    audited: list[dict[str, object]] = []

    for index, report in enumerate(reports, 1):
        region_path = Path(str(report["region_path"]))
        cache_key = str(region_path)
        if cache_key not in facts_cache:
            facts_cache[cache_key] = preprocess_region(
                args.preprocess_bin, region_path, cache_root
            )
            zones_cache[cache_key] = metadata_zones(region_path)
        status, evidence = classify_report(
            report,
            facts_cache[cache_key],
            zones_cache[cache_key],
            mg_keys,
        )
        audited.append(
            {
                "region_name": report.get("region_name", ""),
                "kind": report.get("kind", ""),
                "case_key": report.get("case_key", ""),
                "status": status,
                "evidence": evidence,
                "reason": report.get("reason", ""),
                "raw": report.get("raw", ""),
            }
        )
        if index % 1000 == 0:
            print(f"[audit] {index:,}/{len(reports):,}")

    csv_path = args.output_dir / "finding_audit.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(audited[0]))
        writer.writeheader()
        writer.writerows(audited)

    by_status = Counter(str(row["status"]) for row in audited)
    by_kind_status: dict[str, Counter[str]] = defaultdict(Counter)
    for row in audited:
        by_kind_status[str(row["kind"])][str(row["status"])] += 1

    summary = {
        "reports": len(audited),
        "by_status": dict(sorted(by_status.items())),
        "by_kind_status": {
            kind: dict(sorted(counts.items()))
            for kind, counts in sorted(by_kind_status.items())
        },
        "scope_note": (
            "snapshot-confirmed means supported by the selected Census files; "
            "it is not live-DNS or cross-authoritative-server ground truth"
        ),
    }
    summary_path = args.output_dir / "finding_audit_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    print(f"[result] {csv_path}")
    print(f"[result] {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
