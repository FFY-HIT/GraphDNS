#!/usr/bin/env python3
"""Adjudicate the unresolved GraphDNS/GRoot Census comparison cases.

The audit uses the copied Census zone snapshot. It distinguishes:

* the same root cause reported under different vulnerability labels;
* a finding supported or contradicted by the supplied records; and
* cases whose relevant zone is not loadable under basic BIND/RFC constraints.

This is a snapshot audit. It does not infer unavailable external server views.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import shlex
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    import dns.zone
except ImportError:  # pragma: no cover - the fallback checks remain available
    dns = None


RR_TYPES = {
    "SOA",
    "NS",
    "A",
    "AAAA",
    "CNAME",
    "DNAME",
    "MX",
    "TXT",
}
NAME_RDATA_TYPES = {"NS", "CNAME", "DNAME"}
REWRITE_RE = re.compile(
    r"\]\s+(\S+)\s+--(CNAME|DNAME)/reach=1-->\s+(\S+)",
    re.IGNORECASE,
)


def dns_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    return text if text.endswith(".") else text + "."


def is_below_or_equal(name: str, suffix: str) -> bool:
    name = dns_name(name)
    suffix = dns_name(suffix)
    return name == suffix or name.endswith("." + suffix)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ]


def finding_of(row: dict[str, Any]) -> dict[str, Any]:
    finding = row.get("finding")
    return finding if isinstance(finding, dict) else row


@dataclass(frozen=True)
class Record:
    zone: str
    server: str
    owner: str
    rrtype: str
    rdata: str
    source: str
    line: int


class RegionSnapshot:
    def __init__(self, region_dir: Path) -> None:
        self.region_dir = region_dir
        metadata = json.loads(
            (region_dir / "metadata.json").read_text(
                encoding="utf-8", errors="replace"
            )
        )
        self.records: list[Record] = []
        self.zones: set[str] = set()
        self.by_zone_owner: dict[tuple[str, str], list[Record]] = defaultdict(list)
        self.zone_files: dict[str, Path] = {}
        self._zone_load_issues: dict[str, list[str]] = {}

        for entry in metadata.get("ZoneFiles", []):
            if not isinstance(entry, dict):
                continue
            filename = str(entry.get("FileName", ""))
            path = region_dir / filename
            if not path.is_file():
                continue
            zone = dns_name(filename[:-4] if filename.endswith(".txt") else filename)
            server = dns_name(entry.get("NameServer"))
            self.zones.add(zone)
            self.zone_files[zone] = path
            for record in parse_zone_file(path, zone, server):
                self.records.append(record)
                self.by_zone_owner[(record.zone, record.owner)].append(record)

    def owner_records(self, zone: str, owner: str) -> list[Record]:
        return self.by_zone_owner.get((dns_name(zone), dns_name(owner)), [])

    def all_owner_records(self, owner: str) -> list[Record]:
        owner = dns_name(owner)
        return [record for record in self.records if record.owner == owner]

    def longest_zone(self, name: str) -> str:
        candidates = [zone for zone in self.zones if is_below_or_equal(name, zone)]
        return max(candidates, key=lambda value: (value.count("."), len(value))) if candidates else ""

    def zones_defining_owner(self, owner: str, rrtype: str = "") -> list[str]:
        owner = dns_name(owner)
        rrtype = rrtype.upper()
        return sorted(
            {
                record.zone
                for record in self.records
                if record.owner == owner
                and (not rrtype or record.rrtype == rrtype)
            }
        )

    def parent_delegations(self, cut: str, nameserver: str = "") -> list[Record]:
        cut = dns_name(cut)
        nameserver = dns_name(nameserver)
        return [
            record
            for record in self.records
            if record.rrtype == "NS"
            and record.owner == cut
            and record.zone != cut
            and (not nameserver or record.rdata == nameserver)
        ]

    def parent_glue(self, cut: str, nameserver: str) -> list[Record]:
        delegations = self.parent_delegations(cut, nameserver)
        parent_zones = {record.zone for record in delegations}
        return [
            record
            for record in self.records
            if record.zone in parent_zones
            and record.owner == dns_name(nameserver)
            and record.rrtype in {"A", "AAAA"}
        ]

    def continuation_records(self, name: str) -> list[Record]:
        name = dns_name(name)
        zone = self.longest_zone(name)
        if not zone:
            return []
        exact = [
            record
            for record in self.owner_records(zone, name)
            if record.rrtype in {"A", "AAAA", "CNAME", "DNAME"}
        ]
        if exact:
            return exact
        dnames = [
            record
            for record in self.records
            if record.zone == zone
            and record.rrtype == "DNAME"
            and record.owner != name
            and is_below_or_equal(name, record.owner)
        ]
        if dnames:
            return dnames
        wildcard = wildcard_owner(name, zone)
        return [
            record
            for record in self.owner_records(zone, wildcard)
            if record.rrtype in {"A", "AAAA", "CNAME"}
        ]

    def zone_issues(self, zone: str) -> list[str]:
        zone = dns_name(zone)
        if zone in self._zone_load_issues:
            return self._zone_load_issues[zone]

        path = self.zone_files.get(zone)
        if path is None:
            return [f"zone file for {zone} is absent"]

        if dns is not None:
            try:
                dns.zone.from_file(
                    str(path),
                    origin=zone,
                    relativize=False,
                    check_origin=True,
                )
            except Exception as error:  # dnspython exposes the BIND-relevant cause
                issues = [f"{type(error).__name__}: {error}"]
                self._zone_load_issues[zone] = issues
                return issues
            self._zone_load_issues[zone] = []
            return []

        issues: list[str] = []
        apex_types = {record.rrtype for record in self.owner_records(zone, zone)}
        if "SOA" not in apex_types:
            issues.append("missing apex SOA")
        if "NS" not in apex_types:
            issues.append("missing apex NS")
        owners: dict[str, set[str]] = defaultdict(set)
        for record in self.records:
            if record.zone == zone:
                owners[record.owner].add(record.rrtype)
        for owner, types in sorted(owners.items()):
            if "CNAME" in types and len(types) > 1:
                issues.append(
                    f"CNAME coexists with {','.join(sorted(types - {'CNAME'}))} at {owner}"
                )
        self._zone_load_issues[zone] = issues
        return issues


def absolute_name(value: str, zone: str) -> str:
    value = value.strip().lower()
    if value == "@":
        return dns_name(zone)
    if value.endswith("."):
        return dns_name(value)
    return dns_name(f"{value}.{dns_name(zone)}")


def parse_zone_file(path: Path, zone: str, server: str) -> Iterable[Record]:
    for line_number, raw in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        text = raw.split(";", 1)[0].strip()
        if not text or text.startswith("$"):
            continue
        try:
            fields = shlex.split(text, comments=False, posix=True)
        except ValueError:
            fields = text.split()
        if len(fields) < 2:
            continue
        rr_index = next(
            (index for index, field in enumerate(fields) if field.upper() in RR_TYPES),
            -1,
        )
        if rr_index <= 0 or rr_index + 1 >= len(fields):
            continue
        rrtype = fields[rr_index].upper()
        owner = absolute_name(fields[0], zone)
        if rrtype == "MX":
            rdata_index = rr_index + 2
        else:
            rdata_index = rr_index + 1
        if rdata_index >= len(fields):
            continue
        rdata = fields[rdata_index]
        if rrtype in NAME_RDATA_TYPES or rrtype == "MX":
            rdata = absolute_name(rdata, zone)
        yield Record(
            zone=dns_name(zone),
            server=dns_name(server),
            owner=owner,
            rrtype=rrtype,
            rdata=rdata,
            source=path.name,
            line=line_number,
        )


def wildcard_owner(name: str, zone: str) -> str:
    name = dns_name(name)
    zone = dns_name(zone)
    labels = name.rstrip(".").split(".")
    zone_labels = zone.rstrip(".").split(".")
    if len(labels) <= len(zone_labels):
        return ""
    return dns_name("*." + ".".join(labels[1:]))


def cycle_zones(case_key: str) -> list[str]:
    marker = "CZD|zones="
    if not case_key.startswith(marker):
        return []
    return [dns_name(value) for value in case_key[len(marker) :].split("|") if value]


def rewrite_edges(path: str) -> list[tuple[str, str, str]]:
    return [
        (dns_name(src), rrtype.upper(), dns_name(dst))
        for src, rrtype, dst in REWRITE_RE.findall(path or "")
    ]


def evidence_records(records: Iterable[Record]) -> str:
    values = [
        f"{record.source}:{record.line} "
        f"{record.owner} {record.rrtype} {record.rdata}"
        for record in records
    ]
    return " | ".join(values)


def canonical_cycle(
    edges: Iterable[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    cycle = tuple(edges)
    if not cycle:
        return ()
    rotations = tuple(cycle[index:] + cycle[:index] for index in range(len(cycle)))
    return min(rotations)


def bind_status(
    snapshot: RegionSnapshot, zones: Iterable[str]
) -> tuple[str, str]:
    normalized = sorted({dns_name(zone) for zone in zones if zone})
    if not normalized:
        return "not_applicable", ""
    issues = [
        f"{zone}: {issue}"
        for zone in normalized
        for issue in snapshot.zone_issues(zone)
    ]
    if issues:
        return "structurally_invalid", " | ".join(issues)
    return "loadable", ""


def load_snapshots(root: Path, region_names: Iterable[str]) -> dict[str, RegionSnapshot]:
    snapshots: dict[str, RegionSnapshot] = {}
    for name in sorted(set(region_names)):
        path = root / name
        if path.is_dir():
            snapshots[name] = RegionSnapshot(path)
    return snapshots


def find_report(
    rows: list[dict[str, Any]], region: str, kind: str, case_key: str
) -> dict[str, Any]:
    for row in rows:
        if (
            str(row.get("region_name", "")) == region
            and str(row.get("kind", "")).upper() == kind
            and str(row.get("case_key", "")) == case_key
        ):
            return finding_of(row)
    raise KeyError((region, kind, case_key))


def relevant_rewrite_zones(
    snapshot: RegionSnapshot, edges: list[tuple[str, str, str]]
) -> set[str]:
    zones: set[str] = set()
    for owner, rrtype, target in edges:
        for record in snapshot.records:
            if (
                record.owner == owner
                and record.rrtype == rrtype
                and record.rdata == target
            ):
                zones.add(record.zone)
    return zones


def cname_cycle_signature(
    snapshot: RegionSnapshot, start: str, limit: int = 32
) -> tuple[tuple[str, str], ...]:
    current = dns_name(start)
    sequence: list[tuple[str, str]] = []
    seen: dict[str, int] = {}
    for _ in range(limit):
        if current in seen:
            return canonical_cycle(tuple(sequence[seen[current] :]))
        seen[current] = len(sequence)
        candidates = [
            record
            for record in snapshot.all_owner_records(current)
            if record.rrtype == "CNAME"
        ]
        if not candidates:
            return ()
        target = candidates[0].rdata
        sequence.append((current, target))
        current = target
    return ()


def adjudicate(
    unresolved: list[dict[str, str]],
    graphdns_rows: list[dict[str, Any]],
    groot_rows: list[dict[str, Any]],
    snapshots: dict[str, RegionSnapshot],
) -> list[dict[str, str]]:
    graphdns_mg = {
        (
            str(row.get("region_name", "")),
            dns_name(finding_of(row).get("zone_cut")),
            dns_name(finding_of(row).get("nameserver")),
        )
        for row in graphdns_rows
        if str(row.get("kind", "")).upper() == "MG"
    }
    groot_mg_by_cut: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in groot_rows:
        if str(row.get("kind", "")).upper() == "MG":
            finding = finding_of(row)
            groot_mg_by_cut[
                (
                    str(row.get("region_name", "")),
                    dns_name(finding.get("zone_cut")),
                )
            ].add(dns_name(finding.get("nameserver")))

    groot_rl_signatures: dict[str, set[tuple[tuple[str, str], ...]]] = defaultdict(set)
    for row in groot_rows:
        if str(row.get("kind", "")).upper() != "RL":
            continue
        region = str(row.get("region_name", ""))
        snapshot = snapshots.get(region)
        if snapshot is None:
            continue
        signature = cname_cycle_signature(
            snapshot,
            finding_of(row).get("start_name")
            or finding_of(row).get("start")
            or "",
        )
        if signature:
            groot_rl_signatures[region].add(signature)

    results: list[dict[str, str]] = []
    for item in unresolved:
        region = item["region_name"]
        side = item["side"]
        kind = item["kind"].upper()
        case_key = item["case_key"]
        snapshot = snapshots[region]
        source_rows = graphdns_rows if side == "graphdns_only" else groot_rows
        finding = find_report(source_rows, region, kind, case_key)

        snapshot_verdict = "needs_review"
        snapshot_winner = ""
        rationale = ""
        evidence = ""
        normalized_root = case_key
        relevant_zones: set[str] = set()
        underlying_root_status = ""

        if side == "graphdns_only" and kind == "DI":
            cut = dns_name(finding.get("zone_cut"))
            graph_nameservers = {
                nameserver
                for row_region, row_cut, nameserver in graphdns_mg
                if row_region == region and row_cut == cut
            }
            common = graph_nameservers & groot_mg_by_cut.get((region, cut), set())
            if common:
                snapshot_verdict = "same_root_different_taxonomy"
                snapshot_winner = "both"
                rationale = (
                    "GraphDNS DI aggregates a parent/child glue mismatch already "
                    "reported by both tools as MG."
                )
                evidence = ", ".join(sorted(common))
                normalized_root = (
                    f"MGSET|cut={cut}|nameservers={','.join(sorted(common))}"
                )
                underlying_root_status = "reported_by_both"
            relevant_zones.add(cut)
            relevant_zones.update(
                record.zone for record in snapshot.parent_delegations(cut)
            )

        elif side == "graphdns_only" and kind == "RL":
            edges = rewrite_edges(str(finding.get("path", "")))
            start = dns_name(finding.get("start_name") or finding.get("start"))
            signature = cname_cycle_signature(snapshot, start)
            relevant_zones = relevant_rewrite_zones(snapshot, edges)
            normalized_root = (
                "RL|cycle="
                + "|".join(f"{owner}->{target}" for owner, target in signature)
            )
            if signature and signature in groot_rl_signatures.get(region, set()):
                snapshot_verdict = "same_root_different_witness"
                snapshot_winner = "both"
                rationale = (
                    "Both tools reach the same CNAME cycle but use different "
                    "starting queries as the case key."
                )
                evidence = evidence_records(
                    record
                    for record in snapshot.records
                    if (record.owner, record.rdata) in set(signature)
                    and record.rrtype == "CNAME"
                )
                underlying_root_status = "reported_by_both"
            else:
                snapshot_verdict = "graphdns_supported_groot_miss"
                snapshot_winner = "graphdns"
                rationale = "The supplied CNAME records form a repeated query-name cycle."
                evidence = evidence_records(
                    record
                    for record in snapshot.records
                    if any(
                        record.owner == owner
                        and record.rrtype == rrtype
                        and record.rdata == target
                        for owner, rrtype, target in edges
                    )
                )
                underlying_root_status = "graphdns_supported_groot_miss"

        elif side == "graphdns_only" and kind == "RB":
            start = dns_name(finding.get("start_name") or finding.get("start"))
            target = dns_name(finding.get("target"))
            source_zones = snapshot.zones_defining_owner(start, "CNAME")
            target_zone = snapshot.longest_zone(target)
            relevant_zones = set(source_zones)
            if target_zone:
                relevant_zones.add(target_zone)
            normalized_root = f"RB|start={start}|target={target}"
            continuations = snapshot.continuation_records(target)
            if continuations:
                snapshot_verdict = "graphdns_false_positive"
                snapshot_winner = "groot"
                rationale = "The rewritten target has a terminal or rewrite continuation."
                evidence = evidence_records(continuations)
                underlying_root_status = "graphdns_false_positive"
            else:
                snapshot_verdict = "graphdns_supported_groot_miss"
                snapshot_winner = "graphdns"
                rationale = (
                    "The CNAME target lies in a supplied authoritative zone but "
                    "has no A/AAAA or rewrite continuation."
                )
                source = [
                    record
                    for record in snapshot.all_owner_records(start)
                    if record.rrtype == "CNAME" and record.rdata == target
                ]
                evidence = evidence_records(source)
                underlying_root_status = "graphdns_supported_groot_miss"

        elif side == "groot_only" and kind == "CZD":
            zones = cycle_zones(case_key)
            relevant_zones = {
                snapshot.longest_zone(zone) for zone in zones
            } - {""}
            matched = [
                (row_cut, nameserver)
                for row_region, row_cut, nameserver in graphdns_mg
                if row_region == region and nameserver in zones
            ]
            if matched:
                snapshot_verdict = "same_root_different_taxonomy"
                snapshot_winner = "both"
                rationale = (
                    "GRoot labels the circular nameserver-address dependency as "
                    "CZD; GraphDNS reports the same missing parent glue as MG."
                )
                evidence = " | ".join(
                    f"cut={cut} nameserver={nameserver}"
                    for cut, nameserver in sorted(matched)
                )
                normalized_root = "|".join(
                    f"MG|cut={cut}|nameserver={nameserver}"
                    for cut, nameserver in sorted(matched)
                )
                underlying_root_status = "reported_by_both"
            else:
                zone_set = set(zones)
                candidates = [
                    record
                    for record in snapshot.records
                    if record.rrtype == "NS"
                    and record.owner in zone_set
                    and record.rdata in zone_set
                    and record.zone != record.owner
                    and is_below_or_equal(record.rdata, record.owner)
                    and not snapshot.parent_glue(record.owner, record.rdata)
                ]
                if candidates:
                    snapshot_verdict = "same_root_different_taxonomy"
                    snapshot_winner = "groot"
                    rationale = (
                        "This CZD is a second label for a GRoot MG finding: an "
                        "in-bailiwick delegated nameserver has no parent-side address. "
                        "The underlying MG root is absent from GraphDNS."
                    )
                    evidence = evidence_records(candidates)
                    normalized_root = "|".join(
                        f"MG|cut={record.owner}|nameserver={record.rdata}"
                        for record in candidates
                    )
                    underlying_root_status = "groot_supported_graphdns_miss"
                else:
                    snapshot_verdict = "groot_false_positive"
                    snapshot_winner = "graphdns"
                    rationale = "No delegation cycle or missing-glue dependency is reproduced."
                    evidence = ", ".join(zones)
                    underlying_root_status = "groot_false_positive"

        elif side == "groot_only" and kind == "MG":
            cut = dns_name(finding.get("zone_cut"))
            nameserver = dns_name(finding.get("nameserver"))
            normalized_root = f"MG|cut={cut}|nameserver={nameserver}"
            relevant_zones.add(cut)
            relevant_zones.update(
                record.zone
                for record in snapshot.parent_delegations(cut, nameserver)
            )
            glue = snapshot.parent_glue(cut, nameserver)
            if not is_below_or_equal(nameserver, cut):
                snapshot_verdict = "groot_false_positive"
                snapshot_winner = "graphdns"
                rationale = (
                    "The nameserver is outside the delegated subtree, so the "
                    "parent is not required to provide glue."
                )
                evidence = evidence_records(
                    snapshot.parent_delegations(cut, nameserver)
                )
                underlying_root_status = "groot_false_positive"
            elif glue:
                snapshot_verdict = "groot_false_positive"
                snapshot_winner = "graphdns"
                rationale = "The parent zone contains A/AAAA glue for this delegated nameserver."
                evidence = evidence_records(glue)
                underlying_root_status = "groot_false_positive"
            else:
                snapshot_verdict = "groot_supported_graphdns_miss"
                snapshot_winner = "groot"
                rationale = "The parent delegation is in-bailiwick and lacks A/AAAA glue."
                evidence = evidence_records(snapshot.parent_delegations(cut, nameserver))
                underlying_root_status = "groot_supported_graphdns_miss"

        elif side == "groot_only" and kind == "DI":
            cut = dns_name(finding.get("zone_cut"))
            normalized_root = f"DI|cut={cut}"
            relevant_zones.add(cut)
            relevant_zones.update(
                record.zone for record in snapshot.parent_delegations(cut)
            )
            parent_ns = {
                record.rdata for record in snapshot.parent_delegations(cut)
            }
            child_ns = {
                record.rdata
                for record in snapshot.owner_records(cut, cut)
                if record.rrtype == "NS"
            }
            mismatches: list[str] = []
            if parent_ns != child_ns:
                mismatches.append("parent and child NS sets differ")
            for nameserver in sorted(parent_ns & child_ns):
                if not is_below_or_equal(nameserver, cut):
                    continue
                parent_addr = {
                    record.rdata
                    for record in snapshot.parent_glue(cut, nameserver)
                }
                child_addr = {
                    record.rdata
                    for record in snapshot.owner_records(cut, nameserver)
                    if record.rrtype in {"A", "AAAA"}
                }
                if parent_addr != child_addr:
                    mismatches.append(f"address sets differ for {nameserver}")
            if mismatches:
                snapshot_verdict = "groot_supported_graphdns_miss"
                snapshot_winner = "groot"
                rationale = "; ".join(mismatches)
                underlying_root_status = "groot_supported_graphdns_miss"
            else:
                snapshot_verdict = "groot_false_positive"
                snapshot_winner = "graphdns"
                rationale = (
                    "Parent and child NS sets agree, and all in-bailiwick "
                    "nameserver address sets agree."
                )
                underlying_root_status = "groot_false_positive"
            evidence = evidence_records(
                record
                for record in snapshot.records
                if record.owner == cut
                and record.rrtype == "NS"
                or (
                    record.owner in parent_ns
                    and record.rrtype in {"A", "AAAA"}
                )
            )

        elif side == "groot_only" and kind == "RB":
            start = dns_name(finding.get("start_name") or finding.get("start"))
            target = dns_name(finding.get("target"))
            source_zones = snapshot.zones_defining_owner(start, "CNAME")
            target_zone = snapshot.longest_zone(target)
            relevant_zones = set(source_zones)
            if target_zone:
                relevant_zones.add(target_zone)
            normalized_root = f"RB|start={start}|target={target}"
            continuations = snapshot.continuation_records(target)
            if continuations:
                snapshot_verdict = "groot_false_positive"
                snapshot_winner = "graphdns"
                rationale = "The reported NX target has a supplied terminal or rewrite record."
                evidence = evidence_records(continuations)
                underlying_root_status = "groot_false_positive"
            else:
                snapshot_verdict = "groot_supported_graphdns_miss"
                snapshot_winner = "groot"
                rationale = "The rewritten target has no terminal or continuation record."
                underlying_root_status = "groot_supported_graphdns_miss"

        load_status, load_reason = bind_status(snapshot, relevant_zones)
        results.append(
            {
                "region_name": region,
                "side": side,
                "kind": kind,
                "case_key": case_key,
                "normalized_root": normalized_root,
                "snapshot_verdict": snapshot_verdict,
                "snapshot_winner": snapshot_winner,
                "bind_status": load_status,
                "bind_reason": load_reason,
                "underlying_root_status": underlying_root_status,
                "rationale": rationale,
                "evidence": evidence,
            }
        )
    return results


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def build_full_difference_audit(
    graphdns_only: list[dict[str, Any]],
    groot_only: list[dict[str, Any]],
    graphdns_rows: list[dict[str, Any]],
    adjudicated: list[dict[str, str]],
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    adjudication = {
        (
            row["region_name"],
            row["side"],
            row["kind"],
            row["case_key"],
        ): row
        for row in adjudicated
    }
    graphdns_mg_names = {
        (
            str(row.get("region_name", "")),
            dns_name(finding_of(row).get("nameserver")),
        )
        for row in graphdns_rows
        if str(row.get("kind", "")).upper() == "MG"
    }

    groot_mg_status: dict[tuple[str, str], str] = {}
    groot_supported_mg_names: set[tuple[str, str]] = set()
    for row in groot_only:
        if str(row.get("kind", "")).upper() != "MG":
            continue
        finding = finding_of(row)
        region = str(row.get("region_name", ""))
        cut = dns_name(finding.get("zone_cut"))
        nameserver = dns_name(finding.get("nameserver"))
        key = (region, str(row.get("case_key", "")))
        audited = adjudication.get((region, "groot_only", "MG", key[1]))
        if cut == dns_name(region):
            status = "groot_report_unsupported_by_snapshot"
        elif nameserver == cut:
            status = "groot_supported_graphdns_miss"
        elif not is_below_or_equal(nameserver, cut):
            status = "groot_report_unsupported_by_snapshot"
        elif audited:
            status = (
                "groot_report_unsupported_by_snapshot"
                if audited["snapshot_verdict"] == "groot_false_positive"
                else audited["underlying_root_status"]
            )
        else:
            status = "needs_review"
        groot_mg_status[key] = status
        if status == "groot_supported_graphdns_miss":
            groot_supported_mg_names.add((region, nameserver))

    rows: list[dict[str, str]] = []

    def append(
        row: dict[str, Any],
        side: str,
        category: str,
        detail: str,
    ) -> None:
        rows.append(
            {
                "region_name": str(row.get("region_name", "")),
                "side": side,
                "kind": str(row.get("kind", "")).upper(),
                "case_key": str(row.get("case_key", "")),
                "category": category,
                "detail": detail,
            }
        )

    for row in graphdns_only:
        region = str(row.get("region_name", ""))
        kind = str(row.get("kind", "")).upper()
        case_key = str(row.get("case_key", ""))
        if kind == "STALE":
            append(
                row,
                "graphdns_only",
                "scope_difference",
                "GraphDNS record-level shadow-record property is outside GRoot's scope.",
            )
            continue
        audited = adjudication.get((region, "graphdns_only", kind, case_key))
        if not audited:
            append(row, "graphdns_only", "needs_review", "No detailed audit row.")
        elif audited["snapshot_verdict"].startswith("same_root_"):
            append(
                row,
                "graphdns_only",
                "same_root_extra_report",
                audited["rationale"],
            )
        elif audited["snapshot_verdict"] == "graphdns_supported_groot_miss":
            append(
                row,
                "graphdns_only",
                "graphdns_supported_groot_miss",
                audited["rationale"],
            )
        else:
            append(
                row,
                "graphdns_only",
                audited["snapshot_verdict"],
                audited["rationale"],
            )

    for row in groot_only:
        region = str(row.get("region_name", ""))
        kind = str(row.get("kind", "")).upper()
        case_key = str(row.get("case_key", ""))
        if kind == "LD":
            append(
                row,
                "groot_only",
                "incomplete_server_view",
                "The sampled folder does not contain the external authoritative view.",
            )
        elif kind == "MG":
            category = groot_mg_status[(region, case_key)]
            append(
                row,
                "groot_only",
                category,
                "Classified by delegation cut, nameserver bailiwick, and copied evidence.",
            )
        elif kind == "CZD":
            zones = set(cycle_zones(case_key))
            if any((region, zone) in graphdns_mg_names for zone in zones):
                append(
                    row,
                    "groot_only",
                    "same_root_extra_report",
                    "The same missing-glue root is already reported by both tools as MG.",
                )
            elif any((region, zone) in groot_supported_mg_names for zone in zones):
                append(
                    row,
                    "groot_only",
                    "same_root_extra_report",
                    "This CZD duplicates a supported GRoot-only MG root.",
                )
            else:
                append(
                    row,
                    "groot_only",
                    "groot_report_unsupported_by_snapshot",
                    "The reported zone cycle has no corresponding missing-glue root.",
                )
        else:
            audited = adjudication.get((region, "groot_only", kind, case_key))
            if not audited:
                append(row, "groot_only", "needs_review", "No detailed audit row.")
            elif audited["snapshot_verdict"].startswith("same_root_"):
                append(
                    row,
                    "groot_only",
                    "same_root_extra_report",
                    audited["rationale"],
                )
            elif audited["snapshot_verdict"] == "groot_false_positive":
                append(
                    row,
                    "groot_only",
                    "groot_report_unsupported_by_snapshot",
                    audited["rationale"],
                )
            else:
                append(
                    row,
                    "groot_only",
                    audited["underlying_root_status"]
                    or audited["snapshot_verdict"],
                    audited["rationale"],
                )

    counts = Counter(row["category"] for row in rows)
    by_side_kind_category: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        by_side_kind_category[f"{row['side']}:{row['kind']}"][
            row["category"]
        ] += 1
    graphdns_roots = {
        (row["region_name"], row["normalized_root"])
        for row in adjudicated
        if row["underlying_root_status"] == "graphdns_supported_groot_miss"
    }
    groot_roots = {
        (region, case_key)
        for (region, case_key), status in groot_mg_status.items()
        if status == "groot_supported_graphdns_miss"
    }
    summary = {
        "difference_entries": len(rows),
        "by_category": dict(sorted(counts.items())),
        "by_side_kind_category": {
            key: dict(sorted(values.items()))
            for key, values in sorted(by_side_kind_category.items())
        },
        "independent_supported_graphdns_only_roots": len(graphdns_roots),
        "independent_supported_groot_only_roots": len(groot_roots),
    }
    return rows, summary


def write_report(path: Path, summary: dict[str, Any]) -> None:
    verdict_labels = {
        "same_root_different_taxonomy": "同一根因，不同漏洞类别",
        "same_root_different_witness": "同一根因，不同证据起点",
        "graphdns_supported_groot_miss": "快照支持 GraphDNS，GRoot 漏报",
        "groot_supported_graphdns_miss": "快照支持 GRoot，GraphDNS 漏报",
        "graphdns_false_positive": "静态快照不支持 GraphDNS 报告",
        "groot_false_positive": "静态快照不支持 GRoot 报告",
        "needs_review": "仍需人工复核",
    }
    lines = [
        "# 197 条待审差异的逐案裁决",
        "",
        "## 审计口径",
        "",
        "每条差异均回溯到复制的 Census zone files。静态裁决只判断报告是否"
        "满足本文定义的权威配置语义；`bind_status` 单独记录相关 zone 是否满足"
        " SOA、apex NS 和 CNAME 独占性等基础加载约束，不反向覆盖静态裁决。",
        "",
        "## 逐案例汇总",
        "",
        "| 裁决 | 案例数 |",
        "|---|---:|",
    ]
    for verdict, count in summary["by_snapshot_verdict"].items():
        lines.append(f"| {verdict_labels.get(verdict, verdict)} | {count} |")
    lines.extend(
        [
            f"| **合计** | **{summary['cases']}** |",
            "",
            "## BIND 结构约束",
            "",
            "| 状态 | 案例数 |",
            "|---|---:|",
        ]
    )
    for status, count in summary["by_bind_status"].items():
        lines.append(f"| {status} | {count} |")
    lines.extend(
        [
            "",
            "## 解释",
            "",
            "- “同一根因”案例不应继续计入跨工具独有根因；差异来自类别或 witness 规范化不足。",
            "- “快照支持”表示记录关系可在当前静态输入中重建，不代表已确认运营者意图。",
            "- `structurally_invalid` 案例可用于检查静态分析器对脏数据的行为，但应从 BIND 运行时准确率中排除。",
            "- 完整证据、相关文件和行号见 `unresolved_case_adjudication.csv`。",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def write_full_report(path: Path, summary: dict[str, Any]) -> None:
    labels = {
        "scope_difference": "检测范围差异（GraphDNS SR）",
        "incomplete_server_view": "服务器视图不完整，无法裁决 LD",
        "same_root_extra_report": "同一根因的额外类别或 witness",
        "graphdns_supported_groot_miss": "快照支持 GraphDNS，GRoot 未报告",
        "groot_supported_graphdns_miss": "快照支持 GRoot，GraphDNS 未报告",
        "groot_report_unsupported_by_snapshot": "静态快照不支持 GRoot 报告",
        "graphdns_report_unsupported_by_snapshot": "静态快照不支持 GraphDNS 报告",
        "needs_review": "仍需复核",
    }
    lines = [
        "# 10,000 区域跨工具差异的最终证据分类",
        "",
        "| 分类 | 差异条目数 |",
        "|---|---:|",
    ]
    for category, count in summary["by_category"].items():
        lines.append(f"| {labels.get(category, category)} | {count} |")
    lines.extend(
        [
            f"| **合计** | **{summary['difference_entries']}** |",
            "",
            "跨类别和不同起点产生的条目已单列，不能作为独立根因重复计数。"
            f"在当前静态快照中，GraphDNS-only 得到 "
            f"{summary['independent_supported_graphdns_only_roots']} 个独立受支持根因，"
            f"GRoot-only 得到 "
            f"{summary['independent_supported_groot_only_roots']} 个独立受支持根因。",
            "",
            "## 按工具与漏洞类型分解",
            "",
            "| 工具侧 | 类型 | 分类 | 数量 |",
            "|---|---|---|---:|",
        ]
    )
    for key, categories in summary["by_side_kind_category"].items():
        side, kind = key.split(":", 1)
        for category, count in categories.items():
            lines.append(
                f"| {side} | {kind} | {labels.get(category, category)} | {count} |"
            )
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--regions-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    run_dir = args.run_dir.resolve()
    reports_dir = run_dir / "reports"
    regions_dir = (
        args.regions_dir.resolve()
        if args.regions_dir
        else run_dir / "unresolved_regions"
    )
    output_dir = (
        args.output_dir.resolve()
        if args.output_dir
        else reports_dir / "adjudication"
    )

    unresolved = list(
        csv.DictReader(
            (reports_dir / "supplemental_unresolved_cases.csv").open(
                encoding="utf-8"
            )
        )
    )
    graphdns_rows = read_jsonl(reports_dir / "graphdns_findings.jsonl")
    groot_rows = read_jsonl(reports_dir / "groot_findings.jsonl")
    graphdns_only = read_jsonl(reports_dir / "graphdns_only.jsonl")
    groot_only = read_jsonl(reports_dir / "groot_only.jsonl")
    snapshots = load_snapshots(
        regions_dir, (row["region_name"] for row in unresolved)
    )
    missing = sorted(
        {row["region_name"] for row in unresolved} - set(snapshots)
    )
    if missing:
        raise SystemExit(f"missing copied regions: {', '.join(missing)}")

    adjudicated = adjudicate(unresolved, graphdns_rows, groot_rows, snapshots)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(output_dir / "unresolved_case_adjudication.csv", adjudicated)

    by_verdict = Counter(row["snapshot_verdict"] for row in adjudicated)
    by_bind_status = Counter(row["bind_status"] for row in adjudicated)
    by_side_kind_verdict: dict[str, Counter[str]] = defaultdict(Counter)
    for row in adjudicated:
        by_side_kind_verdict[f"{row['side']}:{row['kind']}"][
            row["snapshot_verdict"]
        ] += 1
    summary = {
        "cases": len(adjudicated),
        "by_snapshot_verdict": dict(sorted(by_verdict.items())),
        "by_bind_status": dict(sorted(by_bind_status.items())),
        "by_side_kind_snapshot_verdict": {
            key: dict(sorted(counts.items()))
            for key, counts in sorted(by_side_kind_verdict.items())
        },
        "method_note": (
            "snapshot verdicts are based on the copied Census records; "
            "cross-type/witness cases are normalization differences rather than "
            "independent roots; bind_status is reported separately"
        ),
    }
    (output_dir / "unresolved_case_adjudication_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_report(output_dir / "unresolved_case_adjudication_report_zh.md", summary)

    full_rows, full_summary = build_full_difference_audit(
        graphdns_only,
        groot_only,
        graphdns_rows,
        adjudicated,
    )
    write_csv(output_dir / "all_difference_adjudication.csv", full_rows)
    (output_dir / "all_difference_adjudication_summary.json").write_text(
        json.dumps(full_summary, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    write_full_report(
        output_dir / "all_difference_adjudication_report_zh.md",
        full_summary,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    print(json.dumps(full_summary, ensure_ascii=False, indent=2, sort_keys=True))
    print(f"[result] {output_dir / 'unresolved_case_adjudication.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
