from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence

from . import SEVERE_KINDS, SUPPORTED_REPAIR_KINDS
from .model import (
    DNSRecord,
    ParsedRun,
    RepairAction,
    RepairCandidate,
    parse_graphdns_output,
    report_key_set,
)
from .sampling import Region


@dataclass
class CommandResult:
    return_code: int
    wall_seconds: float
    output: str


@dataclass
class ScreeningResult:
    region: Region
    status: str
    error: str
    facts_text: str
    baseline_output: str
    parsed: ParsedRun | None

    @property
    def eligible(self) -> bool:
        if self.status != "ok" or self.parsed is None:
            return False
        repairable = sum(
            report.kind in SUPPORTED_REPAIR_KINDS for report in self.parsed.reports
        )
        directly_evaluable = any(
            all(
                record is None
                or "<TODO_" not in record.rdata.upper()
                or "<TODO_IP>" in record.rdata.upper()
                or "<TODO_IPV6>" in record.rdata.upper()
                for action in candidate.actions
                for record in (action.old_record, action.new_record)
            )
            for candidate in self.parsed.candidates
        )
        return (
            repairable > 0
            and bool(self.parsed.groups)
            and bool(self.parsed.candidates)
            and directly_evaluable
        )


def build_graphdns(
    repo_root: Path,
    preprocess_bin: Path,
    semantic_bin: Path,
) -> None:
    preprocess_bin.parent.mkdir(parents=True, exist_ok=True)
    semantic_bin.parent.mkdir(parents=True, exist_ok=True)
    compiler = os.environ.get("CXX", "g++")
    commands = (
        [
            compiler,
            "-O3",
            "-std=c++17",
            "-fopenmp",
            str(repo_root / "src" / "preprocess.cpp"),
            "-o",
            str(preprocess_bin),
        ],
        [
            compiler,
            "-O3",
            "-std=c++17",
            "-fopenmp",
            str(repo_root / "src" / "semantic_graph.cpp"),
            "-o",
            str(semantic_bin),
        ],
    )
    for command in commands:
        print("[build] " + " ".join(command), flush=True)
        subprocess.run(command, cwd=repo_root, check=True)


def run_command(
    command: Sequence[str],
    cwd: Path,
    timeout_seconds: float,
    threads: int = 1,
) -> CommandResult:
    env = os.environ.copy()
    env["OMP_NUM_THREADS"] = str(max(1, threads))
    start = time.perf_counter()
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            env=env,
            check=False,
        )
        return CommandResult(
            completed.returncode,
            time.perf_counter() - start,
            completed.stdout,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return CommandResult(
            124,
            time.perf_counter() - start,
            output + f"\nTIMEOUT after {timeout_seconds}s",
        )


def graphdns_command(
    semantic_bin: Path,
    facts_path: Path,
    server_views: str,
    extra: Sequence[str],
) -> list[str]:
    return [
        str(semantic_bin),
        str(facts_path),
        "--reports-only",
        "--timing",
        "--threads",
        "1",
        "--server-views",
        server_views,
        *extra,
    ]


def _validate_parsed_run(parsed: ParsedRun, require_candidates: bool = False) -> None:
    if not parsed.summary:
        raise ValueError("GraphDNS output has no Summary line")
    if int(parsed.summary.get("bugs", -1)) != len(parsed.reports):
        raise ValueError(
            "GraphDNS report count mismatch: "
            f"summary={parsed.summary.get('bugs')} parsed={len(parsed.reports)}"
        )
    if require_candidates and parsed.groups and not parsed.candidates:
        # Some bug kinds legitimately have no generated candidates. This is
        # only an error when no supported report explains the empty result.
        supported = any(
            report.kind in SUPPORTED_REPAIR_KINDS for report in parsed.reports
        )
        if supported:
            raise ValueError("supported bug reports produced no repair candidates")


def probe_graphdns(semantic_bin: Path, timeout_seconds: float) -> None:
    # Do not depend on --example containing a repairable report. This compact
    # parent/child fixture deterministically creates a DI glue mismatch.
    probe_facts = "\n".join(
        (
            "a.gtld-server.net.\tcom.\texample.com.\tNS\tns1.example.com.",
            "a.gtld-server.net.\tcom.\tns1.example.com.\tA\t192.0.2.1",
            "ns1.example.com.\texample.com.\texample.com.\tNS\tns1.example.com.",
            "ns1.example.com.\texample.com.\tns1.example.com.\tA\t192.0.2.2",
            "",
        )
    )

    with tempfile.TemporaryDirectory(prefix="graphdns_exp04_probe_") as temp:
        workdir = Path(temp)
        facts_path = workdir / "probe.facts"
        facts_path.write_text(probe_facts, encoding="utf-8")

        result = run_command(
            graphdns_command(
                semantic_bin,
                facts_path,
                "complete",
                ["--repairs"],
            ),
            workdir,
            timeout_seconds,
        )
        if result.return_code != 0:
            raise RuntimeError(f"GraphDNS repair probe failed:\n{result.output[-4000:]}")

        required_markers = ("=== Repair Groups ===", "action_tsv = ")
        missing_markers = [
            marker for marker in required_markers if marker not in result.output
        ]
        if missing_markers:
            raise RuntimeError(
                "GraphDNS binary lacks the Experiment 04 machine-readable "
                f"interface ({', '.join(missing_markers)} missing). Ensure the "
                "WSL src/semantic_graph.cpp contains --inc-actions, "
                "--repair-groups-only, Repair Groups, and action_tsv support, "
                "then rebuild it with --build.\n"
                f"Probe output tail:\n{result.output[-4000:]}"
            )

        parsed = parse_graphdns_output(result.output)
        _validate_parsed_run(parsed)
        if not parsed.groups or not parsed.candidates:
            raise RuntimeError(
                "GraphDNS exposed the machine-readable interface but generated "
                "no repair group/candidate for the deterministic DI fixture. "
                "This indicates a repair detection or synthesis regression, "
                "rather than a Census sampling problem.\n"
                f"Probe output tail:\n{result.output[-4000:]}"
            )
        if not all(candidate.actions for candidate in parsed.candidates):
            raise RuntimeError(
                "GraphDNS candidates do not contain complete action_tsv records"
            )

        action_path = workdir / "actions.tsv"
        action_path.write_text(
            "\n".join(action.to_tsv() for action in parsed.candidates[0].actions)
            + "\n",
            encoding="utf-8",
        )
        incremental = run_command(
            graphdns_command(
                semantic_bin,
                facts_path,
                "complete",
                [
                    "--inc-actions",
                    str(action_path),
                    "--equivalence-digest",
                ],
            ),
            workdir,
            timeout_seconds,
        )
        if incremental.return_code != 0:
            raise RuntimeError(
                "GraphDNS --inc-actions probe failed:\n"
                f"{incremental.output[-4000:]}"
            )
        incremental_markers = (
            "IncrementalTiming:",
            "all_reports_after:",
            "GraphStateDigest: phase=post_update",
        )
        missing_incremental = [
            marker
            for marker in incremental_markers
            if marker not in incremental.output
        ]
        if missing_incremental:
            raise RuntimeError(
                "GraphDNS --inc-actions output is not machine-readable "
                f"({', '.join(missing_incremental)} missing).\n"
                f"Probe output tail:\n{incremental.output[-4000:]}"
            )

        incremental_parsed = parse_graphdns_output(incremental.output)
        if (
            len(incremental_parsed.report_sections) < 4
            or not incremental_parsed.incremental_timing
            or not incremental_parsed.graph_state_digest("post_update")
        ):
            raise RuntimeError(
                "GraphDNS --inc-actions output could not be parsed into "
                "before/new/fixed/after report sets and incremental timings"
            )


def screen_region(
    region: Region,
    preprocess_bin: Path,
    semantic_bin: Path,
    scratch_root: Path,
    timeout_seconds: float,
    max_records: int,
    server_views: str,
) -> ScreeningResult:
    scratch_root.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(
            prefix=f"screen_{region.sample_rank:06d}_", dir=scratch_root
        ) as temp:
            workdir = Path(temp)
            preprocess = run_command(
                [str(preprocess_bin), region.path],
                workdir,
                timeout_seconds,
            )
            facts_path = workdir / "ZoneRecord.facts"
            if preprocess.return_code != 0 or not facts_path.is_file():
                return ScreeningResult(
                    region,
                    "preprocess_error",
                    preprocess.output[-4000:],
                    "",
                    "",
                    None,
                )
            facts_text = facts_path.read_text(
                encoding="utf-8", errors="replace"
            )
            record_count = len(facts_text.splitlines())
            if record_count > max_records:
                return ScreeningResult(
                    region,
                    "excluded_record_limit",
                    f"{record_count} records exceed limit {max_records}",
                    facts_text,
                    "",
                    None,
                )
            graphdns = run_command(
                graphdns_command(
                    semantic_bin,
                    facts_path,
                    server_views,
                    ["--repairs"],
                ),
                workdir,
                timeout_seconds,
            )
            if graphdns.return_code != 0:
                return ScreeningResult(
                    region,
                    "graphdns_error",
                    graphdns.output[-4000:],
                    "",
                    graphdns.output,
                    None,
                )
            parsed = parse_graphdns_output(graphdns.output)
            _validate_parsed_run(parsed)
            return ScreeningResult(
                region,
                "ok",
                "",
                facts_text,
                graphdns.output,
                parsed,
            )
    except Exception as exc:
        return ScreeningResult(
            region,
            "error",
            f"{type(exc).__name__}: {exc}",
            "",
            "",
            None,
        )


def read_facts(path: Path) -> list[DNSRecord]:
    supported_types = {"NS", "A", "AAAA", "CNAME", "DNAME", "MX", "TXT"}
    records: list[DNSRecord] = []
    for raw in path.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        if not raw:
            continue
        fields = raw.split("\t")
        # Match GraphBuilder::loadFacts: records whose rdata still contains
        # tabs (notably SOA) are outside the modeled RR set and are skipped.
        if len(fields) != 5:
            continue
        if fields[3].upper() not in supported_types:
            continue
        records.append(DNSRecord(*fields))
    return records


def write_facts(path: Path, records: Sequence[DNSRecord]) -> None:
    path.write_text(
        "".join(record.to_facts_line() + "\n" for record in records),
        encoding="utf-8",
    )


def _safe_address_owner(
    records: Sequence[DNSRecord],
    server: str,
    zone: str,
    excluded_owner: str,
) -> str | None:
    exact_context = [
        record.owner
        for record in records
        if record.type.upper() in {"A", "AAAA"}
        and record.server.lower() == server.lower()
        and record.zone.lower() == zone.lower()
        and record.owner.lower() != excluded_owner.lower()
    ]
    fallback = [
        record.owner
        for record in records
        if record.type.upper() in {"A", "AAAA"}
        and record.owner.lower() != excluded_owner.lower()
    ]
    choices = exact_context or fallback
    return min(set(choices), key=lambda value: (len(value), value)) if choices else None


def _out_of_cycle_ns(
    records: Sequence[DNSRecord],
    zone: str,
    excluded: str,
) -> str | None:
    suffix = zone.lower().rstrip(".") + "."
    choices = {
        record.rdata
        for record in records
        if record.type.upper() == "NS"
        and record.rdata.lower() != excluded.lower()
        and not record.rdata.lower().endswith(suffix)
    }
    return min(choices, key=lambda value: (len(value), value)) if choices else None


def instantiate_candidate(
    candidate: RepairCandidate,
    records: Sequence[DNSRecord],
) -> tuple[list[RepairAction] | None, str, bool]:
    """Resolve placeholders for structural dry-run validation.

    TEST-NET values validate the selected owner/type/zone but are not presented
    as operator-ready addresses. Target-name placeholders require an existing
    addressable or out-of-cycle name; otherwise the candidate is not evaluated.
    """
    digest = int(candidate.candidate_id[:8], 16)
    ipv4 = f"192.0.2.{1 + digest % 254}"
    ipv6 = f"2001:db8::{1 + digest % 65534:x}"
    instantiated = False

    def replace(record: DNSRecord | None, peer: DNSRecord | None) -> DNSRecord | None:
        nonlocal instantiated
        if record is None or "<TODO_" not in record.rdata.upper():
            return record
        token = record.rdata.upper().rstrip(".")
        value: str | None
        if "<TODO_IPV6>" in token:
            value = ipv6
        elif "<TODO_IP>" in token:
            value = ipv4
        elif "<TODO_SAFE_TARGET>" in token or "<TODO_SHORT_TARGET>" in token:
            value = _safe_address_owner(
                records, record.server, record.zone, record.owner
            )
        elif "<TODO_OUT_OF_CYCLE_NS>" in token:
            value = _out_of_cycle_ns(
                records,
                record.zone,
                peer.rdata if peer is not None else "",
            )
        else:
            value = None
        if value is None:
            raise LookupError(f"cannot instantiate {record.rdata}")
        instantiated = True
        return DNSRecord(
            record.server,
            record.zone,
            record.owner,
            record.type,
            value,
        )

    try:
        actions: list[RepairAction] = []
        for action in candidate.actions:
            old_record = replace(action.old_record, action.new_record)
            new_record = replace(action.new_record, action.old_record)
            actions.append(
                RepairAction(action.operation, old_record, new_record)
            )
        return actions, "", instantiated
    except LookupError as exc:
        return None, str(exc), instantiated


def apply_actions(
    records: Sequence[DNSRecord],
    actions: Sequence[RepairAction],
) -> list[DNSRecord]:
    updated = list(records)

    def remove_record(record: DNSRecord) -> None:
        # GraphBuilder materializes duplicate identical facts as one logical
        # base edge. Removing that edge therefore removes every duplicate row
        # from the full-rebuild input.
        updated[:] = [existing for existing in updated if existing.key != record.key]

    def add_one(record: DNSRecord) -> None:
        if not any(existing.key == record.key for existing in updated):
            updated.append(record)

    for action in actions:
        if action.operation == "ADD" and action.new_record:
            add_one(action.new_record)
        elif action.operation == "DELETE" and action.old_record:
            remove_record(action.old_record)
        elif (
            action.operation == "MODIFY"
            and action.old_record
            and action.new_record
        ):
            remove_record(action.old_record)
            add_one(action.new_record)
        else:
            raise ValueError(f"incomplete action: {action}")
    return updated


def _full_graph_seconds(timing: dict[str, float]) -> float:
    return sum(
        timing.get(key, 0.0)
        for key in (
            "build_base",
            "build_semantic",
            "build_invariants",
            "compute_reach",
        )
    )


def _full_traversal_seconds(timing: dict[str, float]) -> float:
    return timing.get("traverse_core", timing.get("traverse_dfs", 0.0))


def _full_graph_traversal_seconds(timing: dict[str, float]) -> float:
    return _full_graph_seconds(timing) + _full_traversal_seconds(timing)


def _parse_affected_paths(text: str) -> int:
    for line in text.splitlines():
        if line.startswith("affected_paths="):
            return int(line.split("=", 1)[1])
    return 0


def validate_candidate(
    region: Region,
    candidate: RepairCandidate,
    records: Sequence[DNSRecord],
    baseline: ParsedRun,
    semantic_bin: Path,
    workdir: Path,
    timeout_seconds: float,
    server_views: str,
    di_is_severe: bool,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "region_rank": region.sample_rank,
        "region": region.name,
        "candidate_id": candidate.candidate_id,
        "group_key": candidate.group_key,
        "kind": candidate.group_key.split("|", 1)[0],
        "bug": candidate.bug,
        "output_rank": candidate.output_rank,
        "group_rank": candidate.group_rank,
        "priority": candidate.priority,
        "risk": candidate.risk,
        "grouped_reports": candidate.grouped_reports,
        "action_count": len(candidate.actions),
        "actions_tsv": [action.to_tsv() for action in candidate.actions],
        "rationale": candidate.rationale,
        "expected_effect": candidate.expected_effect,
        "contains_placeholder": candidate.contains_placeholder,
        "status": "pending",
        "error": "",
    }
    actions, unresolved, instantiated = instantiate_candidate(candidate, records)
    row["placeholder_instantiated"] = instantiated
    row["native_executable"] = not candidate.contains_placeholder
    if actions is None:
        row.update(status="unresolved_placeholder", error=unresolved)
        return row
    row["executed_actions_tsv"] = [action.to_tsv() for action in actions]

    candidate_dir = workdir / candidate.candidate_id
    candidate_dir.mkdir(parents=True, exist_ok=True)
    baseline_facts = candidate_dir / "before.facts"
    after_facts = candidate_dir / "after.facts"
    action_path = candidate_dir / "actions.tsv"
    write_facts(baseline_facts, records)
    write_facts(after_facts, apply_actions(records, actions))
    action_path.write_text(
        "".join(action.to_tsv() + "\n" for action in actions),
        encoding="utf-8",
    )

    incremental = run_command(
        graphdns_command(
            semantic_bin,
            baseline_facts,
            server_views,
            [
                "--inc-actions",
                str(action_path),
                "--equivalence-digest",
            ],
        ),
        candidate_dir,
        timeout_seconds,
    )
    if incremental.return_code != 0:
        row.update(
            status="incremental_error",
            error=incremental.output[-4000:],
        )
        return row
    full = run_command(
        graphdns_command(
            semantic_bin,
            after_facts,
            server_views,
            ["--repair-groups-only", "--equivalence-digest"],
        ),
        candidate_dir,
        timeout_seconds,
    )
    if full.return_code != 0:
        row.update(status="full_error", error=full.output[-4000:])
        return row

    try:
        incremental_parsed = parse_graphdns_output(incremental.output)
        full_parsed = parse_graphdns_output(full.output)
        _validate_parsed_run(full_parsed)
        if len(incremental_parsed.report_sections) < 4:
            raise ValueError(
                "incremental output has no all_reports_after report section"
            )
    except Exception as exc:
        row.update(status="parse_error", error=f"{type(exc).__name__}: {exc}")
        return row

    baseline_keys = report_key_set(baseline.reports)
    incremental_keys = report_key_set(incremental_parsed.all_reports_after)
    full_keys = report_key_set(full_parsed.reports)
    stale = incremental_keys - full_keys
    missed = full_keys - incremental_keys
    incremental_digest = incremental_parsed.graph_state_digest("post_update")
    full_digest = full_parsed.graph_state_digest("baseline")
    if not incremental_digest or not full_digest:
        row.update(
            status="parse_error",
            error="missing incremental or full GraphStateDigest",
        )
        return row

    def digest_component_equal(*keys: str) -> bool:
        return all(
            incremental_digest.get(key) == full_digest.get(key)
            for key in keys
        )

    reachable_edge_set_equivalent = digest_component_equal(
        "reachable_edges", "edge_set"
    )
    cached_edge_set_equivalent = digest_component_equal(
        "active_edges", "active_edge_set"
    )
    path_set_equivalent = digest_component_equal("paths", "path_set")
    state_set_equivalent = digest_component_equal(
        "terminal_states", "state_set"
    )
    digest_report_set_equivalent = digest_component_equal(
        "reports", "report_set"
    )
    report_set_equivalent = not stale and not missed
    fully_equivalent = (
        reachable_edge_set_equivalent
        and path_set_equivalent
        and state_set_equivalent
        and digest_report_set_equivalent
        and report_set_equivalent
    )
    after_group_keys = {group.key for group in full_parsed.groups}
    severe = set(SEVERE_KINDS)
    if di_is_severe:
        severe.add("DI")
    new_severe = {
        report.key
        for report in full_parsed.reports
        if report.kind in severe and report.key not in baseline_keys
    }
    new_reports = full_keys - baseline_keys
    fixed_reports = baseline_keys - full_keys
    fixes_original_group = candidate.group_key not in after_group_keys
    safe = not new_severe
    accurate = fixes_original_group and safe

    incremental_timing = incremental_parsed.incremental_timing
    full_timing = full_parsed.timing
    incremental_graph = incremental_timing.get("graph_update", 0.0)
    incremental_traversal = incremental_timing.get("local_traversal", 0.0)
    full_graph = _full_graph_seconds(full_timing)
    full_traversal = _full_traversal_seconds(full_timing)
    incremental_graph_traversal = incremental_graph + incremental_traversal
    full_graph_traversal = _full_graph_traversal_seconds(full_timing)
    row.update(
        status="ok",
        accurate=accurate,
        fixes_original_group=fixes_original_group,
        no_new_severe_reports=safe,
        new_severe_reports=len(new_severe),
        new_reports=len(new_reports),
        fixed_reports=len(fixed_reports),
        incremental_full_equivalent=fully_equivalent,
        report_set_equivalent=report_set_equivalent,
        reachable_edge_set_equivalent=reachable_edge_set_equivalent,
        cached_edge_set_equivalent=cached_edge_set_equivalent,
        active_edge_set_equivalent=reachable_edge_set_equivalent,
        path_set_equivalent=path_set_equivalent,
        terminal_state_set_equivalent=state_set_equivalent,
        digest_report_set_equivalent=digest_report_set_equivalent,
        incremental_after_reports=len(incremental_keys),
        full_after_reports=len(full_keys),
        stale_incremental_reports=len(stale),
        missed_incremental_reports=len(missed),
        affected_paths=_parse_affected_paths(incremental.output),
        incremental_graph_update_seconds=incremental_graph,
        incremental_local_traversal_seconds=incremental_traversal,
        incremental_graph_traversal_seconds=incremental_graph_traversal,
        full_graph_build_seconds=full_graph,
        full_traversal_seconds=full_traversal,
        full_graph_traversal_seconds=full_graph_traversal,
        stale_report_keys=sorted(stale),
        missed_report_keys=sorted(missed),
        new_severe_report_keys=sorted(new_severe),
        new_report_keys=sorted(new_reports),
        fixed_report_keys=sorted(fixed_reports),
        incremental_graph_state_digest=incremental_digest,
        full_graph_state_digest=full_digest,
    )
    row["graph_traversal_speedup"] = (
        full_graph_traversal / incremental_graph_traversal
        if incremental_graph_traversal > 0
        else None
    )
    return row


def evaluate_region(
    region: Region,
    facts_path: Path,
    baseline_path: Path,
    semantic_bin: Path,
    scratch_root: Path,
    timeout_seconds: float,
    server_views: str,
    di_is_severe: bool,
    max_candidates: int,
    candidate_workers: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    baseline = parse_graphdns_output(
        baseline_path.read_text(encoding="utf-8", errors="replace")
    )
    records = read_facts(facts_path)
    candidates = baseline.candidates
    if max_candidates > 0:
        candidates = candidates[:max_candidates]

    scratch_root.mkdir(parents=True, exist_ok=True)
    checkpoint_root = (
        scratch_root.parent
        / "candidate_checkpoints"
        / f"{region.sample_rank:06d}"
    )
    checkpoint_root.mkdir(parents=True, exist_ok=True)
    rows_by_rank: dict[int, dict[str, Any]] = {}
    pending: list[tuple[RepairCandidate, Path]] = []
    for candidate in candidates:
        checkpoint = checkpoint_root / (
            f"{candidate.output_rank:06d}_{candidate.candidate_id}.json"
        )
        if checkpoint.is_file():
            try:
                row = json.loads(checkpoint.read_text(encoding="utf-8"))
                if (
                    row.get("candidate_id") == candidate.candidate_id
                    and row.get("group_key") == candidate.group_key
                ):
                    rows_by_rank[candidate.output_rank] = row
                    continue
            except (OSError, ValueError, TypeError):
                pass
        pending.append((candidate, checkpoint))

    print(
        f"[candidates] region={region.name} total={len(candidates):,} "
        f"cached={len(rows_by_rank):,} pending={len(pending):,} "
        f"workers={candidate_workers}",
        flush=True,
    )
    completed = len(rows_by_rank)
    progress_every = max(1, min(100, max(10, len(candidates) // 20)))

    with tempfile.TemporaryDirectory(
        prefix=f"eval_{region.sample_rank:06d}_", dir=scratch_root
    ) as temp:
        workdir = Path(temp)
        with ThreadPoolExecutor(max_workers=max(1, candidate_workers)) as executor:
            future_map = {
                executor.submit(
                    validate_candidate,
                    region,
                    candidate,
                    records,
                    baseline,
                    semantic_bin,
                    workdir,
                    timeout_seconds,
                    server_views,
                    di_is_severe,
                ): (candidate, checkpoint)
                for candidate, checkpoint in pending
            }
            for future in as_completed(future_map):
                candidate, checkpoint = future_map[future]
                try:
                    row = future.result()
                except Exception as exc:
                    row = {
                        "region_rank": region.sample_rank,
                        "region": region.name,
                        "candidate_id": candidate.candidate_id,
                        "group_key": candidate.group_key,
                        "kind": candidate.group_key.split("|", 1)[0],
                        "bug": candidate.bug,
                        "output_rank": candidate.output_rank,
                        "group_rank": candidate.group_rank,
                        "priority": candidate.priority,
                        "risk": candidate.risk,
                        "grouped_reports": candidate.grouped_reports,
                        "action_count": len(candidate.actions),
                        "actions_tsv": [
                            action.to_tsv() for action in candidate.actions
                        ],
                        "status": "error",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                temporary = checkpoint.with_suffix(".tmp")
                temporary.write_text(
                    json.dumps(row, ensure_ascii=False, sort_keys=True),
                    encoding="utf-8",
                )
                temporary.replace(checkpoint)
                rows_by_rank[candidate.output_rank] = row
                completed += 1
                if (
                    completed % progress_every == 0
                    or completed == len(candidates)
                ):
                    print(
                        f"[candidate-progress] region={region.name} "
                        f"completed={completed:,}/{len(candidates):,}",
                        flush=True,
                    )

    rows = [
        rows_by_rank[candidate.output_rank]
        for candidate in candidates
        if candidate.output_rank in rows_by_rank
    ]

    repairable_reports = sum(
        report.kind in SUPPORTED_REPAIR_KINDS for report in baseline.reports
    )
    supported_groups = [
        group for group in baseline.groups if group.kind in SUPPORTED_REPAIR_KINDS
    ]
    grouped_report_total = sum(group.grouped_reports for group in supported_groups)
    if grouped_report_total != repairable_reports:
        raise ValueError(
            "repair-group accounting mismatch: "
            f"reports={repairable_reports} grouped={grouped_report_total}"
        )
    group_count = len(supported_groups)
    merge_rate = (
        1.0 - group_count / repairable_reports if repairable_reports else 0.0
    )
    evaluated = [row for row in rows if row["status"] == "ok"]
    accurate = [row for row in evaluated if row.get("accurate")]
    accurate_group_keys = {
        str(row["group_key"]) for row in accurate if row.get("group_key")
    }
    native = [row for row in evaluated if row.get("native_executable")]
    native_accurate = [row for row in native if row.get("accurate")]
    equivalent = [
        row for row in evaluated if row.get("incremental_full_equivalent")
    ]

    region_row: dict[str, Any] = {
        "sample_rank": region.sample_rank,
        "region": region.name,
        "region_path": region.path,
        "zone_file_count": region.zone_file_count,
        "records": len(records),
        "nodes": baseline.summary.get("nodes", 0),
        "edges": baseline.summary.get("edges", 0),
        "paths": baseline.summary.get("paths", 0),
        "bugs": len(baseline.reports),
        "repairable_reports": repairable_reports,
        "root_cause_groups": group_count,
        "root_cause_merge_rate": merge_rate,
        "reports_per_group": (
            repairable_reports / group_count if group_count else 0.0
        ),
        "generated_candidates": len(baseline.candidates),
        "selected_candidates": len(candidates),
        "evaluated_candidates": len(evaluated),
        "accurate_candidates": len(accurate),
        "candidate_accuracy": (
            len(accurate) / len(evaluated) if evaluated else None
        ),
        "native_executable_candidates": len(native),
        "native_accurate_candidates": len(native_accurate),
        "native_candidate_accuracy": (
            len(native_accurate) / len(native) if native else None
        ),
        "groups_with_accurate_candidate": len(accurate_group_keys),
        "group_fix_coverage": (
            len(accurate_group_keys) / group_count if group_count else None
        ),
        "unresolved_candidates": sum(
            row["status"] == "unresolved_placeholder" for row in rows
        ),
        "equivalent_candidates": len(equivalent),
        "incremental_full_equivalence_rate": (
            len(equivalent) / len(evaluated) if evaluated else None
        ),
        "incremental_graph_update_seconds": sum(
            float(row.get("incremental_graph_update_seconds", 0.0))
            for row in evaluated
        ),
        "incremental_local_traversal_seconds": sum(
            float(row.get("incremental_local_traversal_seconds", 0.0))
            for row in evaluated
        ),
        "incremental_graph_traversal_seconds": sum(
            float(row.get("incremental_graph_traversal_seconds", 0.0))
            for row in evaluated
        ),
        "full_graph_build_seconds": sum(
            float(row.get("full_graph_build_seconds", 0.0))
            for row in evaluated
        ),
        "full_traversal_seconds": sum(
            float(row.get("full_traversal_seconds", 0.0))
            for row in evaluated
        ),
        "full_graph_traversal_seconds": sum(
            float(row.get("full_graph_traversal_seconds", 0.0))
            for row in evaluated
        ),
        "failed_candidates": len(rows) - len(evaluated),
        "status": "ok" if evaluated else "no_evaluable_candidates",
    }
    incremental_graph_traversal = float(
        region_row["incremental_graph_traversal_seconds"]
    )
    region_row["graph_traversal_speedup"] = (
        float(region_row["full_graph_traversal_seconds"])
        / incremental_graph_traversal
        if incremental_graph_traversal > 0
        else None
    )
    return region_row, rows


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def serializable_screening(result: ScreeningResult) -> dict[str, Any]:
    parsed = result.parsed
    return {
        **asdict(result.region),
        "status": result.status,
        "eligible": result.eligible,
        "error": result.error,
        "records": len(result.facts_text.splitlines()) if result.facts_text else 0,
        "bugs": len(parsed.reports) if parsed else 0,
        "repairable_reports": (
            sum(report.kind in SUPPORTED_REPAIR_KINDS for report in parsed.reports)
            if parsed
            else 0
        ),
        "root_cause_groups": len(parsed.groups) if parsed else 0,
        "candidates": len(parsed.candidates) if parsed else 0,
    }
