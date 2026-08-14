from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from exp2.model import Case, Record, Trace, normalize_domain


SUPPORTED_TYPES = {"A", "AAAA", "NS", "CNAME", "DNAME"}
DOMAIN_RDATA_TYPES = {"NS", "CNAME", "DNAME"}
STATUS_RE = re.compile(r"status:\s*([A-Z]+)", re.IGNORECASE)


@dataclass(frozen=True)
class DigObservation:
    status: str
    final_name: str
    outcome: str
    answer_records: tuple[tuple[str, str, str], ...]


@dataclass(frozen=True)
class ZoneProjection:
    records: tuple[Record, ...]
    excluded: tuple[str, ...]


def expected_runtime_outcome(trace: Trace) -> str:
    outcome = trace.outcome
    if outcome == "LOOP":
        return "LOOP"
    if outcome.startswith(("A:", "AAAA:", "NX:", "NODATA:")):
        return outcome
    if outcome.startswith("REFUSED:"):
        return "SERVFAIL"
    raise ValueError(f"unsupported GraphDNS runtime outcome: {outcome}")


def parse_dig_response(text: str, query_name: str) -> DigObservation:
    status_match = STATUS_RE.search(text)
    if status_match is None:
        raise ValueError("dig response does not contain a DNS status")
    status = status_match.group(1).upper()

    answer_records: list[tuple[str, str, str]] = []
    section = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line == ";; ANSWER SECTION:":
            section = "answer"
            continue
        if line.startswith(";;") and line.endswith("SECTION:"):
            section = ""
            continue
        if section != "answer" or not line or line.startswith(";"):
            continue
        fields = line.split()
        if len(fields) < 5:
            continue
        owner = normalize_domain(fields[0])
        record_type = fields[3].upper()
        value = " ".join(fields[4:])
        if record_type in DOMAIN_RDATA_TYPES:
            value = normalize_domain(value)
        answer_records.append((owner, record_type, value))

    final_name = normalize_domain(query_name)
    for _, record_type, value in answer_records:
        if record_type == "CNAME":
            final_name = normalize_domain(value)

    if status == "SERVFAIL":
        outcome = "LOOP"
    elif status == "NXDOMAIN":
        outcome = f"NX:{final_name}"
    else:
        addresses = [
            (record_type, value)
            for _, record_type, value in answer_records
            if record_type in {"A", "AAAA"}
        ]
        if addresses:
            record_type, value = addresses[-1]
            outcome = f"{record_type}:{value}"
        elif status == "NOERROR":
            outcome = f"NODATA:{final_name}"
        else:
            outcome = status

    return DigObservation(
        status=status,
        final_name=final_name,
        outcome=outcome,
        answer_records=tuple(answer_records),
    )


def project_bind_zone(case: Case, server: str, zone: str) -> ZoneProjection:
    """Return the complete BIND-loadable authority view for one server/zone.

    Census snapshots can contain an owner with both CNAME and other data. BIND
    correctly rejects such an RFC-invalid zone. The experiment preserves the
    resolver model's CNAME priority by retaining the CNAME and recording every
    excluded conflicting RR in the result manifest.
    """

    server = normalize_domain(server)
    zone = normalize_domain(zone)
    selected = [
        record
        for record in case.records
        if record.server == server
        and record.zone == zone
        and record.type in SUPPORTED_TYPES
    ]

    by_owner: dict[str, list[Record]] = {}
    for record in selected:
        by_owner.setdefault(record.owner, []).append(record)

    kept: list[Record] = []
    excluded: list[str] = []
    for owner in sorted(by_owner):
        records = by_owner[owner]
        cnames = [record for record in records if record.type == "CNAME"]
        if cnames and len({record.type for record in records}) > 1:
            chosen = sorted(cnames, key=lambda record: (record.value, record.id))[0]
            kept.append(chosen)
            excluded.extend(
                record.id for record in records if record.id != chosen.id
            )
            continue

        seen_rrs: set[tuple[str, str]] = set()
        for record in sorted(records, key=lambda item: (item.type, item.value, item.id)):
            key = (record.type, record.value)
            if key in seen_rrs:
                excluded.append(record.id)
                continue
            seen_rrs.add(key)
            kept.append(record)

    return ZoneProjection(records=tuple(kept), excluded=tuple(sorted(excluded)))


def write_bind_zone(
    path: Path,
    zone: str,
    records: tuple[Record, ...],
    authority_ip: str,
    serial: int,
    infrastructure_records: tuple[tuple[str, str, str], ...] = (),
) -> None:
    zone = normalize_domain(zone)
    ns_name = normalize_domain(f"ns.graphdns-runtime.{zone}")
    hostmaster = normalize_domain(f"hostmaster.graphdns-runtime.{zone}")
    lines = [
        "$TTL 60",
        (
            f"{zone} 60 IN SOA {ns_name} {hostmaster} "
            f"( {serial} 60 60 3600 60 )"
        ),
        f"{zone} 60 IN NS {ns_name}",
        f"{ns_name} 60 IN A {authority_ip}",
    ]

    for record in records:
        lines.append(
            f"{record.owner} 60 IN {record.type} {record.value}"
        )
    for owner, record_type, value in infrastructure_records:
        lines.append(
            f"{normalize_domain(owner)} 60 IN {record_type.upper()} {value}"
        )

    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def outcomes_match(expected: str, observed: str) -> bool:
    return expected == observed
