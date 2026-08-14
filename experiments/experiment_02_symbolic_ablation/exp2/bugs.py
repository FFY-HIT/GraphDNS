from __future__ import annotations

from dataclasses import dataclass

from .model import Case, normalize_domain, relative_prefix


PathSignature = tuple[str, tuple[str, ...], str]


@dataclass(frozen=True)
class BugFinding:
    kind: str
    query: str
    path: tuple[str, ...]
    outcome: str
    reason: str

    @property
    def key(self) -> tuple[str, str, tuple[str, ...]]:
        return self.kind, self.query, self.path


def _violates_dns_length(name: str) -> bool:
    normalized = normalize_domain(name)
    labels = [label for label in normalized.split(".") if label]
    return any(len(label.encode("utf-8")) > 63 for label in labels) or len(
        normalized[:-1].encode("utf-8")
    ) > 253


def detect_path_bugs(
    case: Case,
    signatures: set[PathSignature],
) -> set[BugFinding]:
    records = {record.id: record for record in case.records}
    findings: set[BugFinding] = set()

    for initial_query, path, outcome in signatures:
        current_query = initial_query
        seen_queries = {current_query}
        rewritten = False
        invalid_transition = False

        for label in path:
            if ":" not in label:
                continue
            record_id, action = label.rsplit(":", 1)
            record = records.get(record_id)
            if record is None:
                continue

            next_query = current_query
            if action == "CNAME":
                next_query = normalize_domain(record.value)
                rewritten = True
            elif action == "DNAME":
                prefix = relative_prefix(current_query, record.owner)
                if prefix is None or prefix == "":
                    invalid_transition = True
                    break
                next_query = normalize_domain(prefix + "." + record.value)
                rewritten = True

            if action in {"CNAME", "DNAME"}:
                if _violates_dns_length(next_query):
                    findings.add(
                        BugFinding(
                            kind="ML",
                            query=initial_query,
                            path=path,
                            outcome=outcome,
                            reason="combined rewrite path exceeds DNS name limits",
                        )
                    )
                if next_query in seen_queries:
                    findings.add(
                        BugFinding(
                            kind="RL",
                            query=initial_query,
                            path=path,
                            outcome=outcome,
                            reason=(
                                "combined rewrite path repeats a query name; "
                                "the concrete bindings are incompatible"
                            ),
                        )
                    )
                seen_queries.add(next_query)
                current_query = next_query

        if (
            not invalid_transition
            and rewritten
            and (outcome.startswith("NX:") or outcome.startswith("NODATA:"))
        ):
            findings.add(
                BugFinding(
                    kind="RB",
                    query=initial_query,
                    path=path,
                    outcome=outcome,
                    reason="combined rewrite path terminates without an address answer",
                )
            )

    return findings
