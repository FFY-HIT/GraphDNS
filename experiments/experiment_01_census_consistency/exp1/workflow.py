from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence

from .model import parse_reports
from .sampling import Region
from .storage import ExecutionResult


SUMMARY_RE = re.compile(r"\b(servers|zones|nodes|edges|paths|bugs)=([0-9]+)")
TIMING_RE = re.compile(r"\b([A-Za-z_]+)=([0-9.eE+-]+)")
BUG_STATS_RE = re.compile(r"\b([A-Za-z_]+)=([0-9]+)")


def resolve_path(repo_root: Path, value: str) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (repo_root / path).resolve()


def build_graphdns(repo_root: Path, preprocess_bin: Path, semantic_bin: Path) -> None:
    preprocess_bin.parent.mkdir(parents=True, exist_ok=True)
    semantic_bin.parent.mkdir(parents=True, exist_ok=True)
    commands = [
        [
            "g++",
            "-O3",
            "-std=c++17",
            "-fopenmp",
            str(repo_root / "src" / "preprocess.cpp"),
            "-o",
            str(preprocess_bin),
        ],
        [
            "g++",
            "-O3",
            "-std=c++17",
            "-fopenmp",
            str(repo_root / "src" / "semantic_graph.cpp"),
            "-o",
            str(semantic_bin),
        ],
    ]
    for command in commands:
        print("[build]", " ".join(command), flush=True)
        try:
            subprocess.run(command, cwd=repo_root, check=True)
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                "GraphDNS build failed. On Ubuntu install build-essential and "
                "nlohmann-json3-dev, then rerun with --build."
            ) from exc


def _run_command(
    command: Sequence[str],
    cwd: Path,
    timeout_seconds: float,
    env_overrides: dict[str, str] | None = None,
) -> tuple[int, float, str]:
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)
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
        return completed.returncode, time.perf_counter() - start, completed.stdout
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        return 124, time.perf_counter() - start, partial + f"\nTIMEOUT after {timeout_seconds}s"
    except Exception as exc:  # preserve failure for the reviewable run database
        return 125, time.perf_counter() - start, f"ERROR: {type(exc).__name__}: {exc}"


def _line_count(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open("rb") as handle:
        return sum(1 for _ in handle)


def _graphdns_details(text: str) -> dict[str, Any]:
    details: dict[str, Any] = {}
    for line in text.splitlines():
        if line.startswith("Summary:"):
            details["summary"] = {key: int(value) for key, value in SUMMARY_RE.findall(line)}
        elif line.startswith("BugStats:"):
            details["bug_stats"] = {key: int(value) for key, value in BUG_STATS_RE.findall(line)}
        elif line.startswith("Timing:"):
            details["timing"] = {key: float(value) for key, value in TIMING_RE.findall(line)}
    return details


def _graphdns_integrity_error(
    text: str,
    details: dict[str, Any],
    findings: Sequence[Any],
) -> str:
    missing = [
        label
        for label, key in (
            ("Summary", "summary"),
            ("BugStats", "bug_stats"),
            ("Timing", "timing"),
        )
        if key not in details
    ]
    if missing:
        return (
            "GraphDNS output is incomplete: missing "
            + ", ".join(missing)
            + ". Rebuild src/semantic_graph.cpp with --reports-only support."
        )
    if "=== Edges ===" in text or "=== DFS Paths ===" in text:
        return (
            "GraphDNS ignored --reports-only and emitted the verbose graph/path dump. "
            "Rebuild the current semantic_graph.cpp before running the experiment."
        )

    summary = details["summary"]
    if "bugs" not in summary:
        return "GraphDNS Summary line does not contain bugs=<count>"
    summary_bugs = int(summary["bugs"])
    parsed_bugs = len(findings)
    bug_stats = Counter({key: int(value) for key, value in details["bug_stats"].items()})
    parsed_stats = Counter(finding.kind for finding in findings)
    if summary_bugs != parsed_bugs:
        return (
            "GraphDNS report count mismatch: "
            f"Summary.bugs={summary_bugs}, parsed_reports={parsed_bugs}"
        )
    if sum(bug_stats.values()) != summary_bugs:
        return (
            "GraphDNS BugStats count mismatch: "
            f"BugStats.total={sum(bug_stats.values())}, Summary.bugs={summary_bugs}"
        )
    if bug_stats != parsed_stats:
        return (
            "GraphDNS per-kind count mismatch: "
            f"BugStats={dict(sorted(bug_stats.items()))}, "
            f"parsed={dict(sorted(parsed_stats.items()))}"
        )
    return ""


def validate_graphdns_binary(semantic_bin: Path, timeout_seconds: float = 60.0) -> None:
    """Fail before a large run if the binary cannot emit compact parseable reports."""
    with tempfile.TemporaryDirectory(prefix="graphdns_probe_") as temp:
        workdir = Path(temp)
        output_path = workdir / "probe_output.txt"
        command = [
            str(semantic_bin),
            "--example",
            "--reports-only",
            "--timing",
            "--threads",
            "1",
            "-o",
            str(output_path),
        ]
        return_code, _, stdout = _run_command(
            command,
            workdir,
            timeout_seconds,
            {"OMP_NUM_THREADS": "1"},
        )
        if return_code != 0:
            raise RuntimeError(
                "GraphDNS compatibility probe failed with return code "
                f"{return_code}: {stdout[-2000:]}"
            )
        if not output_path.is_file():
            raise RuntimeError(
                "GraphDNS compatibility probe produced no output file; "
                "rebuild the current semantic_graph.cpp"
            )
        output = output_path.read_text(encoding="utf-8", errors="replace")
        details = _graphdns_details(output)
        try:
            findings = parse_reports(
                output,
                "graphdns-text",
                empty_output_means_zero=False,
            )
        except ValueError as exc:
            raise RuntimeError(f"GraphDNS compatibility probe is not parseable: {exc}") from exc
        integrity_error = _graphdns_integrity_error(output, details, findings)
        if integrity_error:
            raise RuntimeError(f"GraphDNS compatibility probe failed: {integrity_error}")


def _run_graphdns(
    semantic_bin: Path,
    facts_path: Path,
    workdir: Path,
    timeout_seconds: float,
    graphdns_threads: int,
    preprocess_seconds: float,
    preprocess_output: str,
    server_view_coverage: str = "complete",
) -> ExecutionResult:
    output_path = workdir / "graphdns_reports.txt"
    command = [
        str(semantic_bin),
        str(facts_path),
        "--reports-only",
        "--timing",
        "--threads",
        str(max(1, graphdns_threads)),
        "--server-views",
        server_view_coverage,
        "-o",
        str(output_path),
    ]
    return_code, wall_seconds, stdout = _run_command(
        command,
        workdir,
        timeout_seconds,
        {"OMP_NUM_THREADS": str(max(1, graphdns_threads))},
    )
    output = (
        output_path.read_text(encoding="utf-8", errors="replace")
        if output_path.is_file()
        else ""
    )
    details = _graphdns_details(output)
    details["preprocess_seconds"] = preprocess_seconds
    if return_code != 0:
        return ExecutionResult(
            system="graphdns",
            status="error",
            return_code=return_code,
            wall_seconds=wall_seconds,
            record_count=_line_count(facts_path),
            findings=[],
            details=details,
            error="GraphDNS semantic validation failed",
            output_tail=(
                preprocess_output[-2000:]
                + "\n"
                + stdout[-2000:]
                + "\n"
                + output[-4000:]
            ),
        )
    if not output_path.is_file():
        return ExecutionResult(
            system="graphdns",
            status="parse_error",
            return_code=return_code,
            wall_seconds=wall_seconds,
            record_count=_line_count(facts_path),
            findings=[],
            details=details,
            error=(
                "GraphDNS returned success but produced no report file. "
                "Rebuild the current semantic_graph.cpp."
            ),
            output_tail=stdout[-8000:],
        )
    try:
        findings = parse_reports(output, "graphdns-text", empty_output_means_zero=False)
    except ValueError as exc:
        return ExecutionResult(
            system="graphdns",
            status="parse_error",
            return_code=return_code,
            wall_seconds=wall_seconds,
            record_count=_line_count(facts_path),
            findings=[],
            details=details,
            error=str(exc),
            output_tail=output[-8000:],
        )
    integrity_error = _graphdns_integrity_error(output, details, findings)
    if integrity_error:
        return ExecutionResult(
            system="graphdns",
            status="parse_error",
            return_code=return_code,
            wall_seconds=wall_seconds,
            record_count=_line_count(facts_path),
            findings=[],
            details=details,
            error=integrity_error,
            output_tail=stdout[-2000:] + "\n" + output[-6000:],
        )
    weak_findings = [finding for finding in findings if finding.key_quality == "weak"]
    if weak_findings:
        return ExecutionResult(
            system="graphdns",
            status="parse_error",
            return_code=return_code,
            wall_seconds=wall_seconds,
            record_count=_line_count(facts_path),
            findings=[],
            details=details,
            error=(
                "GraphDNS emitted findings without the fields required for strong case keys: "
                + ", ".join(sorted({finding.kind for finding in weak_findings}))
            ),
            output_tail=output[-8000:],
        )
    return ExecutionResult(
        system="graphdns",
        status="ok",
        return_code=return_code,
        wall_seconds=wall_seconds,
        record_count=_line_count(facts_path),
        findings=findings,
        details=details,
        output_tail="",
    )


def _format_groot_command(
    command_template: Sequence[str],
    region: Region,
    workdir: Path,
    output_path: Path,
    facts_path: Path,
    repo_root: str,
) -> list[str]:
    substitutions = {
        "region": region.path,
        "region_name": region.name,
        "workdir": str(workdir),
        "output": str(output_path),
        "facts": str(facts_path),
        "repo": repo_root,
    }
    try:
        return [part.format(**substitutions) for part in command_template]
    except KeyError as exc:
        raise ValueError(f"unknown GRoot command placeholder: {exc}") from exc


def _run_groot(
    groot_config: dict[str, Any],
    region: Region,
    workdir: Path,
    facts_path: Path,
    record_count: int,
    timeout_seconds: float,
) -> ExecutionResult:
    output_path = workdir / "groot_findings.jsonl"
    command = _format_groot_command(
        groot_config.get("command", []),
        region,
        workdir,
        output_path,
        facts_path,
        str(groot_config.get("_repo_root", "")),
    )
    if not command:
        return ExecutionResult(
            system="groot",
            status="configuration_error",
            return_code=2,
            wall_seconds=0.0,
            record_count=record_count,
            findings=[],
            details={},
            error="GRoot command is empty",
        )
    return_code, wall_seconds, stdout = _run_command(
        command,
        workdir,
        timeout_seconds,
        {str(k): str(v) for k, v in groot_config.get("environment", {}).items()},
    )
    if return_code != 0:
        return ExecutionResult(
            system="groot",
            status="error",
            return_code=return_code,
            wall_seconds=wall_seconds,
            record_count=record_count,
            findings=[],
            details={"command": command},
            error="GRoot validation failed",
            output_tail=stdout[-8000:],
        )
    if output_path.exists():
        output = output_path.read_text(encoding="utf-8", errors="replace")
    else:
        output = stdout
    try:
        findings = parse_reports(
            output,
            str(groot_config.get("format", "jsonl")),
            bool(groot_config.get("empty_output_means_zero", False)),
        )
    except ValueError as exc:
        return ExecutionResult(
            system="groot",
            status="parse_error",
            return_code=return_code,
            wall_seconds=wall_seconds,
            record_count=record_count,
            findings=[],
            details={"command": command},
            error=str(exc),
            output_tail=output[-8000:],
        )
    weak_findings = [finding for finding in findings if finding.key_quality == "weak"]
    if bool(groot_config.get("require_strong_keys", True)) and weak_findings:
        kinds = sorted({finding.kind for finding in weak_findings})
        return ExecutionResult(
            system="groot",
            status="parse_error",
            return_code=return_code,
            wall_seconds=wall_seconds,
            record_count=record_count,
            findings=[],
            details={},
            error=(
                "GRoot emitted findings without the fields required for strong case keys: "
                + ", ".join(kinds)
            ),
            output_tail=output[-8000:],
        )
    return ExecutionResult(
        system="groot",
        status="ok",
        return_code=return_code,
        wall_seconds=wall_seconds,
        record_count=record_count,
        findings=findings,
        details={},
        output_tail="",
    )


def run_region(
    region: Region,
    systems: set[str],
    config: dict[str, Any],
    preprocess_bin: Path,
    semantic_bin: Path,
    scratch_root: Path,
) -> tuple[Region, list[ExecutionResult]]:
    timeout_seconds = float(config.get("timeout_seconds", 300))
    preprocess_threads = max(1, int(config.get("preprocess_threads", 1)))
    graphdns_threads = max(1, int(config.get("graphdns_threads", 1)))
    server_view_coverage = str(config.get("server_view_coverage", "complete"))
    if server_view_coverage not in {"complete", "sampled"}:
        raise ValueError(
            "server_view_coverage must be either 'complete' or 'sampled'"
        )
    groot_config = dict(config.get("groot", {}))
    groot_config["_repo_root"] = str(config.get("_repo_root", ""))
    groot_uses_facts = any("{facts}" in part for part in groot_config.get("command", []))
    need_preprocess = "graphdns" in systems or ("groot" in systems and groot_uses_facts)

    scratch_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"r{region.sample_rank:06d}_", dir=scratch_root) as temp:
        workdir = Path(temp)
        facts_path = workdir / "ZoneRecord.facts"
        preprocess_rc = 0
        preprocess_seconds = 0.0
        preprocess_output = ""
        if need_preprocess:
            preprocess_rc, preprocess_seconds, preprocess_output = _run_command(
                [str(preprocess_bin), region.path],
                workdir,
                timeout_seconds,
                {"OMP_NUM_THREADS": str(preprocess_threads)},
            )
        results: list[ExecutionResult] = []
        record_count = _line_count(facts_path)
        if "graphdns" in systems:
            if preprocess_rc != 0 or not facts_path.is_file():
                results.append(
                    ExecutionResult(
                        system="graphdns",
                        status="preprocess_error",
                        return_code=preprocess_rc or 2,
                        wall_seconds=preprocess_seconds,
                        record_count=record_count,
                        findings=[],
                        details={"preprocess_seconds": preprocess_seconds},
                        error="GraphDNS preprocessing failed or produced no ZoneRecord.facts",
                        output_tail=preprocess_output[-8000:],
                    )
                )
            else:
                results.append(
                    _run_graphdns(
                        semantic_bin,
                        facts_path,
                        workdir,
                        timeout_seconds,
                        graphdns_threads,
                        preprocess_seconds,
                        preprocess_output,
                        server_view_coverage,
                    )
                )
        if "groot" in systems:
            if groot_uses_facts and (preprocess_rc != 0 or not facts_path.is_file()):
                results.append(
                    ExecutionResult(
                        system="groot",
                        status="preprocess_error",
                        return_code=preprocess_rc or 2,
                        wall_seconds=preprocess_seconds,
                        record_count=record_count,
                        findings=[],
                        details={"preprocess_seconds": preprocess_seconds},
                        error="GRoot wrapper requested {facts}, but GraphDNS preprocessing failed",
                        output_tail=preprocess_output[-8000:],
                    )
                )
            else:
                results.append(
                    _run_groot(
                        groot_config,
                        region,
                        workdir,
                        facts_path,
                        record_count,
                        timeout_seconds,
                    )
                )
        return region, results
