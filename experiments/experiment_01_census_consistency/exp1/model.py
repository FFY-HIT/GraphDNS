from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import re
import unicodedata
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping, Sequence


KIND_ALIASES = {
    "LD": "LD",
    "LAMEDELEGATION": "LD",
    "DI": "DI",
    "DELEGATIONINCONSISTENCY": "DI",
    "MG": "MG",
    "MISSINGGLUE": "MG",
    "MISSINGGLUERECORD": "MG",
    "MISSINGGLUERECORDS": "MG",
    "CZD": "CZD",
    "CYCLICZONEDEPENDENCY": "CZD",
    "RL": "RL",
    "REWRITELOOP": "RL",
    "REWRITINGLOOP": "RL",
    "RB": "RB",
    "REWRITEBLACKHOLING": "RB",
    "ML": "ML",
    "MAXIMUMLENGTH": "ML",
    "QUERYEXCEEDSMAXIMUMLENGTH": "ML",
    "STALE": "STALE",
    "STALERECORD": "STALE",
    "STALERECORDS": "STALE",
    "SR": "STALE",
    "NX": "NX",
    "NONEXISTENTDOMAINFORSERVICE": "NX",
    "AI": "AI",
    "ANSWERINCONSISTENCY": "AI",
    "ZTTL": "ZTTL",
    "ZEROTIMETOLIVE": "ZTTL",
}

KNOWN_KINDS = frozenset(KIND_ALIASES.values())
HEADER_FIELD_RE = re.compile(
    r"(?:^|\s)(zoneCut|zone_cut|nameserver|start|start_name|query|target|"
    r"rewrittenName|rewritten_name|server|zone|subject|case_key|canonical_key)="
)


def normalize_kind(value: str) -> str:
    token = re.sub(r"[^A-Za-z0-9]", "", value).upper()
    return KIND_ALIASES.get(token, token)


def normalize_space(value: Any) -> str:
    return " ".join(str(value or "").strip().split())


def normalize_dns_name(value: Any) -> str:
    text = unicodedata.normalize("NFKC", normalize_space(value)).lower()
    if not text:
        return ""
    for prefix in ("α.", "β.", "alpha.", "beta."):
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    try:
        ipaddress.ip_address(text.rstrip("."))
        return text.rstrip(".")
    except ValueError:
        pass
    if " " in text or text.startswith("<") or text.startswith('"'):
        return text
    if re.fullmatch(r"(?:\*|_|[a-z0-9_-]+)(?:\.(?:\*|_|[a-z0-9_-]+))*\.?", text):
        return text if text.endswith(".") else text + "."
    return text


def _mapping_value(data: Mapping[str, Any], *keys: str) -> Any:
    lowered = {str(k).lower(): v for k, v in data.items()}
    for key in keys:
        if key.lower() in lowered:
            return lowered[key.lower()]
    return ""


@dataclass
class Finding:
    kind: str
    zone_cut: str = ""
    nameserver: str = ""
    start_name: str = ""
    query: str = ""
    target: str = ""
    server: str = ""
    zone: str = ""
    subject: str = ""
    reason: str = ""
    path: str = ""
    raw: str = ""
    external_case_key: str = ""
    cycle_zones: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        self.kind = normalize_kind(self.kind)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], raw: str = "") -> "Finding":
        kind = normalize_kind(str(_mapping_value(data, "kind", "type", "dimension", "bug")))
        if not kind:
            raise ValueError("finding has no kind/type/dimension field")
        cycle_value = _mapping_value(data, "cycle_zones", "cycleZones")
        if isinstance(cycle_value, str):
            cycle_zones = tuple(
                normalize_dns_name(part)
                for part in re.split(r"[,;|]", cycle_value)
                if normalize_space(part)
            )
        elif isinstance(cycle_value, Sequence):
            cycle_zones = tuple(normalize_dns_name(part) for part in cycle_value if part)
        else:
            cycle_zones = ()
        return cls(
            kind=kind,
            zone_cut=normalize_dns_name(_mapping_value(data, "zone_cut", "zoneCut", "zonecut")),
            nameserver=normalize_dns_name(_mapping_value(data, "nameserver", "name_server", "ns")),
            start_name=normalize_dns_name(_mapping_value(data, "start_name", "startName", "start")),
            query=normalize_dns_name(_mapping_value(data, "query", "qname")),
            target=normalize_dns_name(
                _mapping_value(data, "target", "rewritten_name", "rewrittenName", "new_query")
            ),
            server=normalize_dns_name(_mapping_value(data, "server")),
            zone=normalize_dns_name(_mapping_value(data, "zone")),
            subject=normalize_dns_name(_mapping_value(data, "subject", "entity", "owner")),
            reason=normalize_space(_mapping_value(data, "reason", "message", "msg")),
            path=normalize_space(_mapping_value(data, "path", "witness")),
            raw=raw or json.dumps(dict(data), ensure_ascii=False, sort_keys=True),
            external_case_key=normalize_space(_mapping_value(data, "case_key", "canonical_key")),
            cycle_zones=cycle_zones,
        )

    def case_key_and_quality(self) -> tuple[str, str]:
        if self.external_case_key:
            return self.external_case_key, "explicit"

        def first(*values: str) -> str:
            return next((value for value in values if value), "")

        if self.kind in {"LD", "MG"}:
            zone_cut = first(self.zone_cut, self.zone, self.subject)
            key = f"{self.kind}|zone_cut={zone_cut}|nameserver={self.nameserver}"
            return key, "strong" if zone_cut and self.nameserver else "weak"
        if self.kind == "DI":
            zone_cut = first(self.zone_cut, self.zone, self.subject)
            return f"DI|zone_cut={zone_cut}", "strong" if zone_cut else "weak"
        if self.kind == "CZD":
            if self.zone_cut:
                return f"CZD|zone_cut={self.zone_cut}", "strong"
            zones = sorted(set(self.cycle_zones))
            if not zones:
                zones = sorted(set(filter(None, (self.zone_cut, self.zone, self.subject))))
            return f"CZD|zones={'|'.join(zones)}", "strong" if zones else "weak"
        if self.kind == "RL":
            start = first(self.start_name, self.query, self.subject)
            repeated = first(self.target, self.query)
            return (
                f"RL|start={start}|repeat={repeated}",
                "strong" if start and repeated else "weak",
            )
        if self.kind in {"RB", "ML"}:
            start = first(self.start_name, self.query, self.subject)
            target = first(self.target, self.query)
            key = f"{self.kind}|start={start}|target={target}"
            return key, "strong" if start and target else "weak"
        if self.kind == "STALE":
            owner = first(self.start_name, self.subject)
            return f"STALE|owner={owner}|record={self.query}", "strong" if owner else "weak"

        subject = first(self.subject, self.start_name, self.zone_cut, self.query, self.target)
        return f"{self.kind}|subject={subject}", "strong" if subject else "weak"

    @property
    def case_key(self) -> str:
        return self.case_key_and_quality()[0]

    @property
    def key_quality(self) -> str:
        return self.case_key_and_quality()[1]

    @property
    def fingerprint(self) -> str:
        payload = "\0".join((self.case_key, self.reason, self.path, self.raw))
        return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["cycle_zones"] = list(self.cycle_zones)
        result["case_key"] = self.case_key
        result["key_quality"] = self.key_quality
        result["fingerprint"] = self.fingerprint
        return result


def parse_header_fields(text: str) -> dict[str, str]:
    matches = list(HEADER_FIELD_RE.finditer(text))
    result: dict[str, str] = {}
    for index, match in enumerate(matches):
        value_start = match.end()
        value_end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        result[match.group(1)] = text[value_start:value_end].strip()
    return result


def parse_graphdns_reports(text: str) -> list[Finding]:
    findings: list[Finding] = []
    current: list[str] = []

    def flush() -> None:
        nonlocal current
        if not current:
            return
        header = current[0].strip()
        match = re.match(r"^\[([^\]]+)\](.*)$", header)
        if not match:
            current = []
            return
        kind = normalize_kind(match.group(1))
        if kind not in KNOWN_KINDS:
            current = []
            return
        data: dict[str, Any] = {"kind": kind}
        data.update(parse_header_fields(match.group(2)))
        for line in current[1:]:
            if line.startswith("reason="):
                data["reason"] = line[len("reason=") :].strip()
            elif line.startswith("path="):
                data["path"] = line[len("path=") :].strip()
        findings.append(Finding.from_mapping(data, raw="\n".join(current).strip()))
        current = []

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r\n")
        if re.match(r"^\[[^\]]+\]", line.strip()):
            flush()
            current = [line.strip()]
        elif current and (line.startswith("reason=") or line.startswith("path=")):
            current.append(line.strip())
        elif current and not line.strip():
            flush()
        elif current and (line.startswith("Summary:") or line.startswith("BugStats:")):
            flush()
    flush()
    return findings


def parse_jsonl_reports(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            value = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL at line {line_number}: {exc}") from exc
        if not isinstance(value, Mapping):
            raise ValueError(f"JSONL line {line_number} is not an object")
        findings.append(Finding.from_mapping(value, raw=stripped))
    return findings


def parse_tsv_reports(text: str) -> list[Finding]:
    reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    if not reader.fieldnames:
        return []
    normalized_headers = {header.lower() for header in reader.fieldnames if header}
    if not normalized_headers.intersection({"kind", "type", "dimension", "bug"}):
        raise ValueError("TSV output has no kind/type/dimension/bug column")
    findings: list[Finding] = []
    for row in reader:
        if not any(normalize_space(value) for value in row.values()):
            continue
        raw = "\t".join(str(row.get(header, "")) for header in reader.fieldnames)
        findings.append(Finding.from_mapping(row, raw=raw))
    return findings


_SIMPLE_LABELS = sorted(
    {
        "Lame Delegation",
        "Delegation Inconsistency",
        "Missing Glue Records",
        "Cyclic Zone Dependency",
        "Rewrite Loop",
        "Rewriting Loop",
        "Rewrite Blackholing",
        "Maximum Length",
        "Query Exceeds Maximum Length",
        "Non-Existent Domain for Service",
        "Answer Inconsistency",
        "Zero Time To Live",
    },
    key=len,
    reverse=True,
)
_SIMPLE_RE = re.compile(
    r"^(?:\[)?(" + "|".join(re.escape(label) for label in _SIMPLE_LABELS) + r"|LD|DI|MG|CZD|RL|RB|ML)(?:\])?\s*[:\t-]\s*(.*)$",
    re.IGNORECASE,
)


def parse_simple_groot_reports(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        stripped = line.strip()
        match = _SIMPLE_RE.match(stripped)
        if not match:
            continue
        data: dict[str, Any] = {"kind": match.group(1), "subject": match.group(2)}
        data.update(parse_header_fields(match.group(2)))
        findings.append(Finding.from_mapping(data, raw=stripped))
    return findings


def parse_reports(text: str, output_format: str, empty_output_means_zero: bool = False) -> list[Finding]:
    fmt = output_format.lower()
    stripped = text.strip()
    if not stripped:
        if empty_output_means_zero:
            return []
        raise ValueError("tool produced empty output; cannot distinguish zero findings from failure")
    if fmt == "graphdns-text":
        findings = parse_graphdns_reports(text)
    elif fmt == "jsonl":
        findings = parse_jsonl_reports(text)
    elif fmt == "tsv":
        findings = parse_tsv_reports(text)
    elif fmt == "groot-text":
        findings = parse_simple_groot_reports(text)
    elif fmt == "auto":
        if stripped.startswith("{"):
            findings = parse_jsonl_reports(text)
        elif re.search(r"^\[[A-Za-z]+\]", text, re.MULTILINE):
            findings = parse_graphdns_reports(text)
        elif "\t" in stripped.splitlines()[0]:
            findings = parse_tsv_reports(text)
        else:
            findings = parse_simple_groot_reports(text)
    else:
        raise ValueError(f"unsupported report format: {output_format}")

    if not findings and not empty_output_means_zero:
        zero_markers = ("<none>", "bugs=0", "0 findings", "no bugs", "no errors")
        if not any(marker in stripped.lower() for marker in zero_markers):
            raise ValueError(
                "no individual findings were parsed; aggregate-only output is invalid for case intersection"
            )
    return findings


def unique_cases(findings: Iterable[Finding]) -> dict[tuple[str, str], Finding]:
    cases: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        cases.setdefault((finding.kind, finding.case_key), finding)
    return cases
