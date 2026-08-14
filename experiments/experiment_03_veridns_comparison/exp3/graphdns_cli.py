from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from exp2.model import Case, Record

from .veridns import record_deltas


@dataclass
class CliConsistencyResult:
    pair_id: str
    before_reports: int
    incremental_after_reports: int
    full_after_reports: int
    stale_reports: int
    missed_reports: int
    consistent: bool
    error: str = ""


def build_graphdns(source: Path, binary: Path) -> None:
    binary.parent.mkdir(parents=True, exist_ok=True)
    compiler = os.environ.get("CXX", "g++")
    command = [
        compiler,
        "-O3",
        "-std=c++17",
        "-fopenmp",
        str(source),
        "-o",
        str(binary),
    ]
    print("[build] " + " ".join(command))
    subprocess.run(command, check=True)


def write_facts(case: Case, path: Path) -> None:
    rows = [
        "\t".join(
            (record.server, record.zone, record.owner, record.type, record.value)
        )
        for record in case.records
    ]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def _run(command: list[str]) -> str:
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stderr.strip()}"
        )
    return completed.stdout


def _report_blocks(text: str) -> list[set[str]]:
    lines = text.splitlines()
    blocks: list[set[str]] = []
    index = 0
    while index < len(lines):
        if lines[index].strip() != "=== Bug Reports ===":
            index += 1
            continue
        index += 1
        reports: set[str] = set()
        current: list[str] = []
        while index < len(lines):
            line = lines[index].rstrip()
            stripped = line.strip()
            if stripped.startswith("===") or stripped in {
                "fixed_reports:",
                "new_reports:",
            }:
                break
            if re.match(r"^\[[A-Z][A-Z_]*\]", stripped):
                if current:
                    reports.add("\n".join(current))
                current = [stripped]
            elif current and (
                stripped.startswith("reason=") or stripped.startswith("path=")
            ):
                current.append(stripped)
            index += 1
        if current:
            reports.add("\n".join(current))
        blocks.append(reports)
    return blocks


def _record_args(record: Record) -> list[str]:
    return [
        record.server,
        record.zone,
        record.owner,
        record.type,
        record.value,
    ]


def _incremental_command(binary: Path, facts: Path, before: Case, after: Case) -> list[str]:
    deltas = record_deltas(before, after)
    if len(deltas) != 1:
        raise ValueError(
            f"{before.pair_id} must contain exactly one RR change for CLI validation"
        )
    delta = deltas[0]
    command = [str(binary), str(facts), "--reports-only", "--threads", "1"]
    if delta.operation == "ADD" and delta.new is not None:
        command.extend(["--inc-add", *_record_args(delta.new)])
    elif delta.operation == "DELETE" and delta.old is not None:
        command.extend(["--inc-delete", *_record_args(delta.old)])
    elif delta.operation == "MODIFY" and delta.old is not None and delta.new is not None:
        command.extend(
            [
                "--inc-modify",
                *_record_args(delta.old),
                *_record_args(delta.new),
            ]
        )
    else:
        raise ValueError(f"unsupported delta for {before.pair_id}: {delta}")
    return command


def check_graphdns_cli_pair(
    binary: Path,
    before: Case,
    after: Case,
    case_dir: Path,
) -> CliConsistencyResult:
    case_dir.mkdir(parents=True, exist_ok=True)
    before_facts = case_dir / "before.facts"
    after_facts = case_dir / "after.facts"
    write_facts(before, before_facts)
    write_facts(after, after_facts)

    try:
        incremental_text = _run(
            _incremental_command(binary, before_facts, before, after)
        )
        full_text = _run(
            [
                str(binary),
                str(after_facts),
                "--reports-only",
                "--threads",
                "1",
            ]
        )
        (case_dir / "incremental.txt").write_text(
            incremental_text, encoding="utf-8"
        )
        (case_dir / "full_after.txt").write_text(full_text, encoding="utf-8")

        incremental_blocks = _report_blocks(incremental_text)
        full_blocks = _report_blocks(full_text)
        if len(incremental_blocks) < 3 or not full_blocks:
            raise RuntimeError(
                "could not parse GraphDNS report blocks "
                f"(incremental={len(incremental_blocks)}, full={len(full_blocks)})"
            )
        before_reports, new_reports, fixed_reports = incremental_blocks[:3]
        full_after_reports = full_blocks[0]
        incremental_after = (before_reports - fixed_reports) | new_reports
        stale = incremental_after - full_after_reports
        missed = full_after_reports - incremental_after
        return CliConsistencyResult(
            pair_id=before.pair_id,
            before_reports=len(before_reports),
            incremental_after_reports=len(incremental_after),
            full_after_reports=len(full_after_reports),
            stale_reports=len(stale),
            missed_reports=len(missed),
            consistent=not stale and not missed,
        )
    except Exception as exc:  # Preserve every pair in the experiment output.
        return CliConsistencyResult(
            pair_id=before.pair_id,
            before_reports=0,
            incremental_after_reports=0,
            full_after_reports=0,
            stale_reports=0,
            missed_reports=0,
            consistent=False,
            error=str(exc),
        )
