from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Iterable


REPORT_HEADER_RE = re.compile(r"^\[([A-Z][A-Z_]*)\](.*)$")
HEADER_FIELD_RE = re.compile(
    r"(?:^|\s)(zoneCut|nameserver|start|query|target|server|zone)="
)
NUMBER_RE = re.compile(r"\b([A-Za-z_]+)=([0-9.eE+-]+)")


def _clean(value: str) -> str:
    return " ".join(value.strip().split())


def _header_fields(text: str) -> dict[str, str]:
    matches = list(HEADER_FIELD_RE.finditer(text))
    result: dict[str, str] = {}
    for index, match in enumerate(matches):
        begin = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        result[match.group(1)] = text[begin:end].strip()
    return result


@dataclass(frozen=True)
class BugReport:
    kind: str
    zone_cut: str = ""
    nameserver: str = ""
    start_name: str = ""
    query: str = ""
    target: str = ""
    server: str = ""
    zone: str = ""
    reason: str = ""
    path: str = ""

    @property
    def key(self) -> str:
        # Mirrors IncrementalValidator::reportKey. The witness path is
        # intentionally excluded from report identity.
        return "|".join(
            (
                self.kind,
                self.zone_cut,
                self.nameserver,
                self.start_name,
                self.query,
                self.target,
                self.server,
                self.zone,
                self.reason,
            )
        )

    def to_dict(self) -> dict[str, str]:
        result = asdict(self)
        result["key"] = self.key
        return result


@dataclass(frozen=True)
class DNSRecord:
    server: str
    zone: str
    owner: str
    type: str
    rdata: str

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        record_type = self.type.upper()
        rdata = self.rdata.strip()
        if record_type in {"NS", "CNAME", "DNAME", "MX"}:
            rdata = rdata.lower()
        return (
            self.server.strip().lower(),
            self.zone.strip().lower(),
            self.owner.strip().lower(),
            record_type,
            rdata,
        )

    def to_fields(self) -> list[str]:
        return [self.server, self.zone, self.owner, self.type, self.rdata]

    def to_facts_line(self) -> str:
        return "\t".join(self.to_fields())


@dataclass(frozen=True)
class RepairAction:
    operation: str
    old_record: DNSRecord | None = None
    new_record: DNSRecord | None = None

    @property
    def contains_placeholder(self) -> bool:
        records = (self.old_record, self.new_record)
        return any(
            record is not None and "<TODO_" in record.rdata.upper()
            for record in records
        )

    def to_tsv(self) -> str:
        if self.operation == "ADD" and self.new_record:
            return "\t".join(["ADD", *self.new_record.to_fields()])
        if self.operation == "DELETE" and self.old_record:
            return "\t".join(["DELETE", *self.old_record.to_fields()])
        if self.operation == "MODIFY" and self.old_record and self.new_record:
            return "\t".join(
                [
                    "MODIFY",
                    *self.old_record.to_fields(),
                    *self.new_record.to_fields(),
                ]
            )
        raise ValueError(f"incomplete repair action: {self}")


@dataclass(frozen=True)
class RepairGroup:
    key: str
    kind: str
    grouped_reports: int
    representative: str


@dataclass
class RepairCandidate:
    candidate_id: str
    output_rank: int
    group_rank: int
    group_key: str
    bug: str
    priority: int
    risk: str
    grouped_reports: int
    actions: list[RepairAction] = field(default_factory=list)
    rationale: str = ""
    expected_effect: str = ""

    @property
    def contains_placeholder(self) -> bool:
        return any(action.contains_placeholder for action in self.actions)


@dataclass
class ParsedRun:
    report_sections: list[list[BugReport]]
    groups: list[RepairGroup]
    candidates: list[RepairCandidate]
    summary: dict[str, int]
    timing: dict[str, float]
    incremental_timing: dict[str, float]
    graph_state_digests: list[dict[str, str]]

    @property
    def reports(self) -> list[BugReport]:
        return self.report_sections[0] if self.report_sections else []

    @property
    def all_reports_after(self) -> list[BugReport]:
        return self.report_sections[-1] if len(self.report_sections) >= 4 else []

    def graph_state_digest(self, phase: str) -> dict[str, str]:
        for digest in reversed(self.graph_state_digests):
            if digest.get("phase") == phase:
                return digest
        return {}


def parse_bug_sections(text: str) -> list[list[BugReport]]:
    sections: list[list[BugReport]] = []
    for segment in text.split("=== Bug Reports ===")[1:]:
        reports: list[BugReport] = []
        current: dict[str, str] | None = None

        def flush() -> None:
            nonlocal current
            if current is None:
                return
            reports.append(
                BugReport(
                    kind=current["kind"],
                    zone_cut=current.get("zoneCut", ""),
                    nameserver=current.get("nameserver", ""),
                    start_name=current.get("start", ""),
                    query=current.get("query", ""),
                    target=current.get("target", ""),
                    server=current.get("server", ""),
                    zone=current.get("zone", ""),
                    reason=current.get("reason", ""),
                    path=current.get("path", ""),
                )
            )
            current = None

        for raw in segment.splitlines():
            line = raw.strip()
            match = REPORT_HEADER_RE.match(line)
            if match and match.group(1) in {
                "LD",
                "DI",
                "MG",
                "CZD",
                "RL",
                "RB",
                "ML",
                "STALE",
            }:
                flush()
                current = {"kind": match.group(1)}
                current.update(_header_fields(match.group(2)))
            elif current is not None and line.startswith("reason="):
                current["reason"] = _clean(line[len("reason=") :])
            elif current is not None and line.startswith("path="):
                current["path"] = _clean(line[len("path=") :])
            elif current is not None and (
                line.startswith("Summary:")
                or line.startswith("BugStats:")
                or line.startswith("[Repair")
            ):
                flush()
        flush()
        sections.append(reports)
    return sections


def _parse_record(fields: list[str], offset: int) -> DNSRecord:
    return DNSRecord(
        server=fields[offset],
        zone=fields[offset + 1],
        owner=fields[offset + 2],
        type=fields[offset + 3],
        rdata=fields[offset + 4],
    )


def parse_action_tsv(value: str) -> RepairAction:
    fields = value.rstrip("\r\n").split("\t")
    if fields[0] == "ADD" and len(fields) == 6:
        return RepairAction("ADD", new_record=_parse_record(fields, 1))
    if fields[0] == "DELETE" and len(fields) == 6:
        return RepairAction("DELETE", old_record=_parse_record(fields, 1))
    if fields[0] == "MODIFY" and len(fields) == 11:
        return RepairAction(
            "MODIFY",
            old_record=_parse_record(fields, 1),
            new_record=_parse_record(fields, 6),
        )
    raise ValueError(f"invalid action_tsv line: {value!r}")


def parse_repair_groups(text: str) -> list[RepairGroup]:
    groups: list[RepairGroup] = []
    for block in text.split("[RepairGroup]")[1:]:
        values: dict[str, str] = {}
        for raw in block.splitlines():
            line = raw.strip()
            if line.startswith("[Repair") or line.startswith("==="):
                break
            if " = " in line:
                key, value = line.split(" = ", 1)
                values[key] = value
        if values.get("group_key"):
            groups.append(
                RepairGroup(
                    key=values["group_key"],
                    kind=values.get("kind", ""),
                    grouped_reports=int(values.get("grouped_reports", "0")),
                    representative=values.get("representative", ""),
                )
            )
    return groups


def parse_repair_candidates(text: str) -> list[RepairCandidate]:
    candidates: list[RepairCandidate] = []
    group_ranks: dict[str, int] = {}
    for output_rank, block in enumerate(text.split("[RepairCandidate]")[1:], start=1):
        values: dict[str, str] = {}
        actions: list[RepairAction] = []
        for raw in block.splitlines():
            line = raw.rstrip("\r\n")
            stripped = line.strip()
            if stripped.startswith("[Repair") or stripped.startswith("==="):
                break
            if line.startswith("action_tsv = "):
                actions.append(parse_action_tsv(line[len("action_tsv = ") :]))
            elif " = " in stripped:
                key, value = stripped.split(" = ", 1)
                values[key] = value.strip('"')
        group_key = values.get("group_key", "")
        if not group_key:
            continue
        group_ranks[group_key] = group_ranks.get(group_key, 0) + 1
        payload = group_key + "\0" + "\n".join(action.to_tsv() for action in actions)
        candidate_id = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
        candidates.append(
            RepairCandidate(
                candidate_id=candidate_id,
                output_rank=output_rank,
                group_rank=group_ranks[group_key],
                group_key=group_key,
                bug=values.get("bug", ""),
                priority=int(values.get("priority", "100")),
                risk=values.get("risk", "unknown"),
                grouped_reports=int(values.get("grouped_reports", "1")),
                actions=actions,
                rationale=values.get("rationale", ""),
                expected_effect=values.get("expected_effect", ""),
            )
        )
    return candidates


def _parse_numeric_line(text: str, prefix: str) -> dict[str, float]:
    for line in text.splitlines():
        if line.startswith(prefix):
            return {key: float(value) for key, value in NUMBER_RE.findall(line)}
    return {}


def _parse_graph_state_digests(text: str) -> list[dict[str, str]]:
    digests: list[dict[str, str]] = []
    prefix = "GraphStateDigest:"
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith(prefix):
            continue
        values: dict[str, str] = {}
        for field in line[len(prefix) :].strip().split():
            if "=" not in field:
                continue
            key, value = field.split("=", 1)
            values[key] = value
        if values:
            digests.append(values)
    return digests


def parse_graphdns_output(text: str) -> ParsedRun:
    summary: dict[str, int] = {}
    for line in text.splitlines():
        if line.startswith("Summary:"):
            summary = {
                key: int(float(value)) for key, value in NUMBER_RE.findall(line)
            }
            break
    return ParsedRun(
        report_sections=parse_bug_sections(text),
        groups=parse_repair_groups(text),
        candidates=parse_repair_candidates(text),
        summary=summary,
        timing=_parse_numeric_line(text, "Timing:"),
        incremental_timing=_parse_numeric_line(text, "IncrementalTiming:"),
        graph_state_digests=_parse_graph_state_digests(text),
    )


def report_key_set(reports: Iterable[BugReport]) -> set[str]:
    return {report.key for report in reports}
