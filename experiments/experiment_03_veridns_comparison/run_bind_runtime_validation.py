#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


EXPERIMENT_DIR = Path(__file__).resolve().parent
EVAL1_DIR = EXPERIMENT_DIR.parent
ROOT = EVAL1_DIR.parent
EXP2_DIR = EVAL1_DIR / "experiment_02_symbolic_ablation"
sys.path.insert(0, str(EXP2_DIR))
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp2.model import Case, Record, normalize_domain  # noqa: E402
from exp2.resolver import ConcreteResolver  # noqa: E402
from exp3.bind_runtime import (  # noqa: E402
    expected_runtime_outcome,
    outcomes_match,
    parse_dig_response,
    project_bind_zone,
    write_bind_zone,
)
from exp3.census_updates import load_census_controlled_suite  # noqa: E402


PARENT_IP = "127.0.0.1"
CHILD_IP = "192.0.2.53"
RESOLVER_IP = "127.0.0.1"
RESOLVER_PORT = 5300


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate Experiment 03 before/after outcomes with authoritative "
            "BIND zones and one fresh zero-cache recursive resolver per query."
        )
    )
    parser.add_argument(
        "--controlled-update-spec",
        type=Path,
        default=EXPERIMENT_DIR / "dataset" / "census_controlled_updates.json",
    )
    parser.add_argument(
        "--census-base-dataset",
        type=Path,
        default=EXP2_DIR / "dataset" / "census_real_cases.json",
    )
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--timeout", type=float, default=5.0)
    return parser.parse_args()


def require_runtime() -> None:
    if os.name != "posix":
        raise RuntimeError("the BIND runtime experiment must run on Linux/WSL")
    if os.geteuid() != 0:
        raise RuntimeError("run as root so named can bind authoritative port 53")
    missing = [
        command
        for command in ("named", "named-checkconf", "named-checkzone", "dig", "ip")
        if shutil.which(command) is None
    ]
    if missing:
        raise RuntimeError("missing BIND commands: " + ", ".join(missing))


def case_pairs(cases: tuple[Case, ...]) -> list[tuple[Case, Case]]:
    grouped: dict[str, dict[str, Case]] = defaultdict(dict)
    for case in cases:
        grouped[case.pair_id][case.snapshot] = case
    result: list[tuple[Case, Case]] = []
    for pair_id in sorted(grouped):
        snapshots = grouped[pair_id]
        if set(snapshots) != {"before", "after"}:
            raise ValueError(f"{pair_id} does not have before/after snapshots")
        result.append((snapshots["before"], snapshots["after"]))
    return result


def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def ensure_child_loopback() -> bool:
    completed = subprocess.run(
        ["ip", "-4", "address", "show", "dev", "lo"],
        check=True,
        capture_output=True,
        text=True,
    )
    marker = f"{CHILD_IP}/32"
    if marker in completed.stdout:
        return False
    subprocess.run(
        ["ip", "address", "add", marker, "dev", "lo"],
        check=True,
    )
    return True


def remove_child_loopback() -> None:
    subprocess.run(
        ["ip", "address", "del", f"{CHILD_IP}/32", "dev", "lo"],
        check=False,
        capture_output=True,
        text=True,
    )


def wait_for_tcp(ip: str, port: int, process: subprocess.Popen[str]) -> None:
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError(f"named exited early with {process.returncode}")
        try:
            with socket.create_connection((ip, port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"DNS process did not listen on {ip}:{port}")


def named_options(directory: Path, ip: str, recursion: bool, port: int) -> str:
    recursion_text = "yes" if recursion else "no"
    extra = ""
    if recursion:
        extra = """
    allow-recursion { 127.0.0.0/8; };
    empty-zones-enable no;
    max-cache-ttl 0;
    max-ncache-ttl 0;
"""
    return f"""
options {{
    directory "{directory}";
    listen-on port {port} {{ {ip}; }};
    listen-on-v6 {{ none; }};
    recursion {recursion_text};
    allow-query {{ any; }};
    allow-transfer {{ none; }};
    dnssec-validation no;
    pid-file "{directory / 'named.pid'}";
    session-keyfile "{directory / 'session.key'}";
{extra}}};

controls {{ }};
"""


def write_authority_config(
    directory: Path,
    ip: str,
    zones: list[tuple[str, Path]],
) -> Path:
    config = named_options(directory, ip, recursion=False, port=53)
    for zone, zone_path in zones:
        config += f"""
zone "{zone}" {{
    type primary;
    file "{zone_path}";
}};
"""
    path = directory / "named.conf"
    path.write_text(config, encoding="ascii")
    return path


def write_resolver_config(directory: Path, zone: str) -> Path:
    config = named_options(
        directory, RESOLVER_IP, recursion=True, port=RESOLVER_PORT
    )
    config += f"""
zone "{zone}" {{
    type static-stub;
    server-addresses {{ {PARENT_IP}; }};
}};
"""
    path = directory / "named.conf"
    path.write_text(config, encoding="ascii")
    return path


def start_named(config: Path, log_path: Path, ip: str, port: int) -> subprocess.Popen[str]:
    subprocess.run(["named-checkconf", str(config)], check=True)
    log_handle = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        ["named", "-g", "-u", "root", "-c", str(config)],
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    process._graphdns_log_handle = log_handle  # type: ignore[attr-defined]
    try:
        wait_for_tcp(ip, port, process)
    except Exception:
        stop_process(process)
        log_handle.close()
        raise
    return process


def stop_named(process: subprocess.Popen[str] | None) -> None:
    if process is None:
        return
    stop_process(process)
    handle = getattr(process, "_graphdns_log_handle", None)
    if handle is not None:
        handle.close()


def run_uncached_query(
    snapshot_dir: Path,
    zone: str,
    query: str,
    sequence: int,
    timeout: float,
) -> str:
    resolver_dir = snapshot_dir / f"resolver_{sequence:02d}"
    resolver_dir.mkdir(parents=True)
    config = write_resolver_config(resolver_dir, zone)
    process: subprocess.Popen[str] | None = None
    try:
        process = start_named(
            config,
            resolver_dir / "named.log",
            RESOLVER_IP,
            RESOLVER_PORT,
        )
        completed = subprocess.run(
            [
                "dig",
                f"@{RESOLVER_IP}",
                "-p",
                str(RESOLVER_PORT),
                query,
                "A",
                f"+time={max(1, int(timeout))}",
                "+tries=1",
                "+tcp",
                "+noquestion",
                "+comments",
                "+answer",
                "+authority",
                "+additional",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout + 2,
        )
        response = completed.stdout + completed.stderr
        (resolver_dir / "dig.txt").write_text(response, encoding="utf-8")
        if completed.returncode != 0:
            raise RuntimeError(
                f"dig failed for {query} with return code {completed.returncode}"
            )
        return response
    finally:
        stop_named(process)


def validate_zone(zone: str, path: Path) -> None:
    subprocess.run(
        ["named-checkzone", "-i", "none", zone, str(path)],
        check=True,
        capture_output=True,
        text=True,
    )


def prepare_snapshot(
    case: Case,
    snapshot_dir: Path,
    serial: int,
) -> tuple[Path, Path | None, list[str]]:
    snapshot_dir.mkdir(parents=True)
    parent_dir = snapshot_dir / "parent"
    child_dir = snapshot_dir / "child"
    parent_dir.mkdir()

    parent_projection = project_bind_zone(
        case, case.start_server, case.start_zone
    )
    exclusions = list(parent_projection.excluded)
    parent_zone_path = parent_dir / "db.zone"

    relevant_names = {query.name for query in case.queries}
    for trace in ConcreteResolver(case).resolve_all():
        relevant_names.update(state.query for state in trace.states)
        relevant_names.update(
            event.after_query for event in trace.events if event.after_query
        )

    selected_child_zones: set[str] = set()
    for name in relevant_names:
        matching = [
            zone
            for zone in case.authorities
            if zone != case.start_zone
            and (name == zone or name.endswith("." + zone))
        ]
        if matching:
            selected_child_zones.add(
                max(matching, key=lambda zone: len(zone.split(".")))
            )

    child_zones: list[tuple[str, str, Any]] = []
    infrastructure_records: set[tuple[str, str, str]] = set()
    for child_zone in sorted(selected_child_zones):
        child_server = case.authorities[child_zone]
        child_projection = project_bind_zone(case, child_server, child_zone)
        if not child_projection.records:
            continue
        child_zones.append((child_zone, child_server, child_projection))
        local_ns = normalize_domain(f"ns.graphdns-runtime.{child_zone}")
        infrastructure_records.add((local_ns, "A", CHILD_IP))
    infrastructure = tuple(sorted(infrastructure_records))

    # Keep the runtime fully isolated. Census parent zones retain the original
    # public NS set, so an unmodified delegation can make the resolver contact
    # a live authoritative server instead of the projected child fixture.
    local_child_zones = {zone for zone, _, _ in child_zones}
    parent_records: list[Record] = []
    for record in parent_projection.records:
        if record.type == "NS" and record.owner in local_child_zones:
            exclusions.append(record.id)
            continue
        parent_records.append(record)
    for child_zone in sorted(local_child_zones):
        local_ns = normalize_domain(f"ns.graphdns-runtime.{child_zone}")
        parent_records.append(
            Record(
                id=f"runtime-delegation:{child_zone}",
                server=case.start_server,
                zone=case.start_zone,
                owner=child_zone,
                type="NS",
                value=local_ns,
            )
        )

    write_bind_zone(
        parent_zone_path,
        case.start_zone,
        tuple(parent_records),
        PARENT_IP,
        serial,
        infrastructure,
    )
    validate_zone(case.start_zone, parent_zone_path)
    parent_config = write_authority_config(
        parent_dir,
        PARENT_IP,
        [(case.start_zone, parent_zone_path)],
    )

    child_config: Path | None = None
    if child_zones:
        child_dir.mkdir()
        child_zone_files: list[tuple[str, Path]] = []
        for index, (child_zone, _child_server, child_projection) in enumerate(
            child_zones, start=1
        ):
            child_zone_path = child_dir / f"db.zone.{index}"
            write_bind_zone(
                child_zone_path,
                child_zone,
                child_projection.records,
                CHILD_IP,
                serial + index,
            )
            validate_zone(child_zone, child_zone_path)
            child_zone_files.append((child_zone, child_zone_path))
            exclusions.extend(child_projection.excluded)
        child_config = write_authority_config(
            child_dir,
            CHILD_IP,
            child_zone_files,
        )

    return parent_config, child_config, sorted(exclusions)


def run_snapshot(
    case: Case,
    snapshot_dir: Path,
    serial: int,
    timeout: float,
) -> list[dict[str, Any]]:
    parent_config, child_config, exclusions = prepare_snapshot(
        case, snapshot_dir, serial
    )
    parent: subprocess.Popen[str] | None = None
    child: subprocess.Popen[str] | None = None
    try:
        parent = start_named(
            parent_config,
            snapshot_dir / "parent" / "named.log",
            PARENT_IP,
            53,
        )
        if child_config is not None:
            child = start_named(
                child_config,
                snapshot_dir / "child" / "named.log",
                CHILD_IP,
                53,
            )

        traces = {
            trace.query.name: trace for trace in ConcreteResolver(case).resolve_all()
        }
        rows: list[dict[str, Any]] = []
        for sequence, query in enumerate(case.queries, start=1):
            response = run_uncached_query(
                snapshot_dir,
                case.start_zone,
                query.name,
                sequence,
                timeout,
            )
            observation = parse_dig_response(response, query.name)
            expected = expected_runtime_outcome(traces[query.name])
            rows.append(
                {
                    "pair_id": case.pair_id,
                    "snapshot": case.snapshot,
                    "query": query.name,
                    "graphdns_outcome": expected,
                    "bind_status": observation.status,
                    "bind_final_name": observation.final_name,
                    "bind_outcome": observation.outcome,
                    "match": outcomes_match(expected, observation.outcome),
                    "resolver_process": f"resolver_{sequence:02d}",
                    "cache_policy": "fresh process; max-cache-ttl=0; max-ncache-ttl=0",
                    "authority_records_excluded": len(exclusions),
                    "excluded_record_ids": ";".join(exclusions),
                    "answer_records": json.dumps(
                        observation.answer_records, ensure_ascii=True
                    ),
                }
            )
        return rows
    finally:
        stop_named(child)
        stop_named(parent)


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = list(rows[0]) if rows else []
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_report(path: Path, rows: list[dict[str, Any]]) -> None:
    matched = sum(bool(row["match"]) for row in rows)
    pair_matches: dict[str, list[bool]] = defaultdict(list)
    for row in rows:
        pair_matches[str(row["pair_id"])].append(bool(row["match"]))
    transitions = sum(all(values) for values in pair_matches.values())

    lines = [
        "# Experiment 03 BIND Runtime Cross-Validation",
        "",
        "Each row is one real recursive DNS query. Before every query, the",
        "experiment starts a fresh BIND resolver process with",
        "`max-cache-ttl=0` and `max-ncache-ttl=0`; the process is stopped",
        "immediately after that query.",
        "",
        f"- Runtime queries agreeing with GraphDNS: **{matched}/{len(rows)}**",
        (
            "- Before/after update pairs with complete runtime agreement: "
            f"**{transitions}/{len(pair_matches)}**"
        ),
        "",
        "| Update | Snapshot | Query | GraphDNS | BIND | Match |",
        "| --- | --- | --- | --- | --- | ---: |",
    ]
    for row in rows:
        lines.append(
            "| {pair_id} | {snapshot} | `{query}` | `{graphdns_outcome}` | "
            "`{bind_outcome}` | {match} |".format(**row)
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    require_runtime()
    spec = args.controlled_update_spec.resolve()
    base = args.census_base_dataset.resolve()
    suite = load_census_controlled_suite(spec, base)
    output_dir = (
        args.output_dir.resolve()
        if args.output_dir
        else (
            EVAL1_DIR
            / "runs"
            / f"exp03_bind_runtime_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
    )
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    serial = int(datetime.now().strftime("%Y%m%d%H"))
    added_child_loopback = ensure_child_loopback()
    try:
        for before, after in case_pairs(suite.cases):
            print(f"[runtime] {before.pair_id}", flush=True)
            for case in (before, after):
                snapshot_dir = output_dir / "runtime" / case.pair_id / case.snapshot
                snapshot_rows = run_snapshot(
                    case, snapshot_dir, serial, args.timeout
                )
                rows.extend(snapshot_rows)
                print(
                    f"  {case.snapshot}: "
                    f"{sum(row['match'] for row in snapshot_rows)}/"
                    f"{len(snapshot_rows)} queries agree",
                    flush=True,
                )
                serial += 1
    finally:
        if added_child_loopback:
            remove_child_loopback()

    write_csv(output_dir / "bind_runtime_queries.csv", rows)
    write_report(output_dir / "report.md", rows)
    summary = {
        "queries": len(rows),
        "matching_queries": sum(bool(row["match"]) for row in rows),
        "update_pairs": len({row["pair_id"] for row in rows}),
        "matching_update_pairs": sum(
            all(bool(row["match"]) for row in rows if row["pair_id"] == pair_id)
            for pair_id in {row["pair_id"] for row in rows}
        ),
        "cache_policy": {
            "fresh_resolver_per_query": True,
            "max_cache_ttl": 0,
            "max_negative_cache_ttl": 0,
        },
        "authoritative_runtime": "BIND named",
        "comparison_target": "GraphDNS bounded concrete outcome",
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        f"[done] queries={summary['matching_queries']}/{summary['queries']} "
        f"pairs={summary['matching_update_pairs']}/{summary['update_pairs']}"
    )
    print(f"[result] {output_dir}")
    return 0 if summary["matching_queries"] == summary["queries"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
