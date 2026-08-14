from __future__ import annotations

from collections import defaultdict

from .model import (
    Case,
    Query,
    Record,
    Trace,
    TraceEvent,
    TraceState,
    is_descendant_or_same,
    is_strict_descendant,
    label_count,
    normalize_domain,
    relative_prefix,
)


class ConcreteResolver:
    """Finite static-authoritative oracle for the experiment's record types."""

    def __init__(self, case: Case, max_steps: int = 24) -> None:
        self.case = case
        self.max_steps = max_steps
        self.by_zone: dict[str, list[Record]] = defaultdict(list)
        self.by_zone_owner: dict[tuple[str, str], list[Record]] = defaultdict(list)
        for record in case.records:
            self.by_zone[record.zone].append(record)
            self.by_zone_owner[(record.zone, record.owner)].append(record)

    @staticmethod
    def _most_specific(records: list[Record]) -> Record | None:
        if not records:
            return None
        return max(records, key=lambda record: label_count(record.owner))

    def _delegation(self, zone: str, query: str) -> Record | None:
        candidates = [
            record
            for record in self.by_zone.get(zone, [])
            if record.type == "NS"
            and record.owner != zone
            and is_descendant_or_same(query, record.owner)
        ]
        return self._most_specific(candidates)

    def _dname(self, zone: str, query: str) -> Record | None:
        candidates = [
            record
            for record in self.by_zone.get(zone, [])
            if record.type == "DNAME"
            and is_strict_descendant(query, record.owner)
        ]
        return self._most_specific(candidates)

    def _wildcard(self, zone: str, query: str) -> Record | None:
        candidates = []
        for record in self.by_zone.get(zone, []):
            if not record.owner.startswith("*."):
                continue
            suffix = record.owner[2:]
            if is_strict_descendant(query, suffix):
                candidates.append(record)
        return self._most_specific(candidates)

    @staticmethod
    def _state(
        server: str,
        zone: str,
        query: str,
        kind: str,
        suffix: str,
        alpha_binding: str,
        beta_binding: str | None,
    ) -> TraceState:
        return TraceState(
            server=server,
            zone=zone,
            query=query,
            kind=kind,
            suffix=suffix,
            alpha_binding=alpha_binding,
            beta_binding=beta_binding,
        )

    @staticmethod
    def _terminal(
        server: str,
        zone: str,
        query: str,
        alpha_binding: str,
        beta_binding: str | None,
        outcome: str,
    ) -> TraceState:
        return TraceState(
            server=server,
            zone=zone,
            query=query,
            kind="terminal",
            suffix=outcome,
            alpha_binding=alpha_binding,
            beta_binding=beta_binding,
            terminal=True,
            outcome=outcome,
        )

    def resolve(self, query_spec: Query) -> Trace:
        query = query_spec.name
        server = self.case.start_server
        zone = self.case.start_zone
        alpha_binding = query_spec.alpha_binding
        beta_binding: str | None = None
        kind = "alpha"
        suffix = query_spec.symbol_suffix
        states = [
            self._state(
                server,
                zone,
                query,
                kind,
                suffix,
                alpha_binding,
                beta_binding,
            )
        ]
        events: list[TraceEvent] = []
        seen: set[tuple[str, str, str]] = set()

        for _ in range(self.max_steps):
            loop_key = (server, zone, query)
            if loop_key in seen:
                outcome = "LOOP"
                events.append(
                    TraceEvent(
                        label=f"LOOP@{zone}",
                        record_id=f"LOOP@{zone}",
                        action="LOOP",
                        owner=query,
                        target=query,
                        before_query=query,
                        after_query=query,
                        outcome=outcome,
                    )
                )
                states.append(
                    self._terminal(
                        server,
                        zone,
                        query,
                        alpha_binding,
                        beta_binding,
                        outcome,
                    )
                )
                break
            seen.add(loop_key)

            delegation = self._delegation(zone, query)
            if delegation is not None:
                child_zone = delegation.owner
                child_server = self.case.authorities.get(child_zone)
                if child_server is None:
                    outcome = f"REFUSED:{child_zone}"
                    events.append(
                        TraceEvent(
                            label=f"{delegation.id}:Del",
                            record_id=delegation.id,
                            action="Del",
                            owner=delegation.owner,
                            target=delegation.value,
                            before_query=query,
                            after_query=query,
                            outcome=outcome,
                        )
                    )
                    states.append(
                        self._terminal(
                            server,
                            zone,
                            query,
                            alpha_binding,
                            beta_binding,
                            outcome,
                        )
                    )
                    break

                events.append(
                    TraceEvent(
                        label=f"{delegation.id}:Del",
                        record_id=delegation.id,
                        action="Del",
                        owner=delegation.owner,
                        target=delegation.value,
                        before_query=query,
                        after_query=query,
                    )
                )
                server = child_server
                zone = child_zone
                kind = "alpha"
                suffix = child_zone
                states.append(
                    self._state(
                        server,
                        zone,
                        query,
                        kind,
                        suffix,
                        alpha_binding,
                        beta_binding,
                    )
                )
                continue

            dname = self._dname(zone, query)
            if dname is not None:
                prefix = relative_prefix(query, dname.owner)
                if prefix is None or prefix == "":
                    raise AssertionError("DNAME selected without a non-empty prefix")
                rewritten = normalize_domain(prefix + "." + dname.value)
                events.append(
                    TraceEvent(
                        label=f"{dname.id}:DNAME",
                        record_id=dname.id,
                        action="DNAME",
                        owner=dname.owner,
                        target=dname.value,
                        before_query=query,
                        after_query=rewritten,
                    )
                )
                query = rewritten
                beta_binding = prefix
                kind = "beta"
                suffix = dname.value
                states.append(
                    self._state(
                        server,
                        zone,
                        query,
                        kind,
                        suffix,
                        alpha_binding,
                        beta_binding,
                    )
                )
                continue

            exact = self.by_zone_owner.get((zone, query), [])
            cname = next((record for record in exact if record.type == "CNAME"), None)
            if cname is not None:
                events.append(
                    TraceEvent(
                        label=f"{cname.id}:CNAME",
                        record_id=cname.id,
                        action="CNAME",
                        owner=cname.owner,
                        target=cname.value,
                        before_query=query,
                        after_query=cname.value,
                    )
                )
                query = cname.value
                kind = "concrete"
                suffix = query
                states.append(
                    self._state(
                        server,
                        zone,
                        query,
                        kind,
                        suffix,
                        alpha_binding,
                        beta_binding,
                    )
                )
                continue

            # Experiment queries are A queries. Prefer A when an owner also
            # carries AAAA so the finite reference matches the BIND protocol.
            address = next(
                (record for record in exact if record.type == "A"),
                None,
            )
            if address is None:
                address = next(
                    (record for record in exact if record.type == "AAAA"),
                    None,
                )
            if address is None:
                wildcard = self._wildcard(zone, query)
                if wildcard is not None and wildcard.type in {"A", "AAAA"}:
                    address = wildcard
                elif wildcard is not None and wildcard.type == "CNAME":
                    events.append(
                        TraceEvent(
                            label=f"{wildcard.id}:CNAME",
                            record_id=wildcard.id,
                            action="CNAME",
                            owner=wildcard.owner,
                            target=wildcard.value,
                            before_query=query,
                            after_query=wildcard.value,
                        )
                    )
                    query = wildcard.value
                    kind = "concrete"
                    suffix = query
                    states.append(
                        self._state(
                            server,
                            zone,
                            query,
                            kind,
                            suffix,
                            alpha_binding,
                            beta_binding,
                        )
                    )
                    continue

            if address is not None:
                outcome = f"{address.type}:{address.value}"
                events.append(
                    TraceEvent(
                        label=f"{address.id}:{address.type}",
                        record_id=address.id,
                        action=address.type,
                        owner=address.owner,
                        target=address.value,
                        before_query=query,
                        after_query=query,
                        outcome=outcome,
                    )
                )
                states.append(
                    self._terminal(
                        server,
                        zone,
                        query,
                        alpha_binding,
                        beta_binding,
                        outcome,
                    )
                )
                break

            terminal_kind = "NODATA" if exact else "NX"
            outcome = f"{terminal_kind}:{query}"
            events.append(
                TraceEvent(
                    label=f"{terminal_kind}@{zone}",
                    record_id=f"{terminal_kind}@{zone}",
                    action=terminal_kind,
                    owner=query,
                    target="",
                    before_query=query,
                    after_query=query,
                    outcome=outcome,
                )
            )
            states.append(
                self._terminal(
                    server,
                    zone,
                    query,
                    alpha_binding,
                    beta_binding,
                    outcome,
                )
            )
            break
        else:
            raise RuntimeError(
                f"resolution exceeded {self.max_steps} steps in {self.case.id}: "
                f"{query_spec.name}"
            )

        return Trace(
            case_id=self.case.id,
            query=query_spec,
            states=tuple(states),
            events=tuple(events),
            outcome=states[-1].outcome,
        )

    def resolve_all(self) -> tuple[Trace, ...]:
        return tuple(self.resolve(query) for query in self.case.queries)
