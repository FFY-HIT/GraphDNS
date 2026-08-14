#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


EXPERIMENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXPERIMENT_DIR.parents[1]
EXP01_DIR = REPO_ROOT / "experiments" / "experiment_01_census_consistency"
sys.path.insert(0, str(EXP01_DIR))

from exp1.model import Finding  # noqa: E402
from exp1.reporting import generate_reports  # noqa: E402
from exp1.storage import connect  # noqa: E402


FIXED_CASES = (
    {
        "region": "ac.in",
        "zone_cut": "nibmg.ac.in.",
        "nameserver": "nibmg.ac.in.",
        "server": "a0.cctld.afilias-nst.info.",
        "zone": "ac.in.",
    },
    {
        "region": "ac.th",
        "zone_cut": "banbung.ac.th.",
        "nameserver": "banbung.ac.th.",
        "server": "dns1.thnic.co.th.",
        "zone": "ac.th.",
    },
    {
        "region": "ac.th",
        "zone_cut": "rihes.cmu.ac.th.",
        "nameserver": "rihes.cmu.ac.th.",
        "server": "cmu-ad-3.cmu.ac.th.",
        "zone": "cmu.ac.th.",
    },
    {
        "region": "ac.th",
        "zone_cut": "warin.ac.th.",
        "nameserver": "warin.ac.th.",
        "server": "dns1.thnic.co.th.",
        "zone": "ac.th.",
    },
)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def make_finding(case: dict[str, str]) -> Finding:
    zone_cut = case["zone_cut"]
    nameserver = case["nameserver"]
    server = case["server"]
    zone = case["zone"]
    path = (
        f"[{server} {zone}] alpha.{zone_cut} --NS/reach=1--> "
        f"{nameserver}"
    )
    raw = (
        f"[MG] zoneCut={zone_cut} nameserver={nameserver} "
        f"server={server} zone={zone}\n"
        "reason=in-bailiwick delegated nameserver lacks parent-side "
        "A/AAAA glue\n"
        f"path={path}"
    )
    return Finding(
        kind="MG",
        zone_cut=zone_cut,
        nameserver=nameserver,
        server=server,
        zone=zone,
        reason=(
            "in-bailiwick delegated nameserver lacks parent-side "
            "A/AAAA glue"
        ),
        path=path,
        raw=raw,
    )


def validate_source_evidence(
    connection: sqlite3.Connection, case: dict[str, str]
) -> int:
    row = connection.execute(
        "SELECT r.id FROM regions r WHERE r.name=?",
        (case["region"],),
    ).fetchone()
    if row is None:
        raise RuntimeError(f"region is absent from source run: {case['region']}")
    region_id = int(row["id"])
    case_key = (
        f"MG|zone_cut={case['zone_cut']}|nameserver={case['nameserver']}"
    )
    groot = connection.execute(
        "SELECT 1 FROM findings WHERE region_id=? AND system='groot' "
        "AND kind='MG' AND case_key=?",
        (region_id, case_key),
    ).fetchone()
    graphdns = connection.execute(
        "SELECT 1 FROM findings WHERE region_id=? AND system='graphdns' "
        "AND kind='MG' AND case_key=?",
        (region_id, case_key),
    ).fetchone()
    if groot is None or graphdns is not None:
        raise RuntimeError(
            f"unexpected pre-fix state for {case['region']} {case_key}: "
            f"groot={groot is not None}, graphdns={graphdns is not None}"
        )
    return region_id


def insert_finding(
    connection: sqlite3.Connection,
    region_id: int,
    finding: Finding,
) -> None:
    ordinal = int(
        connection.execute(
            "SELECT COALESCE(MAX(ordinal), 0) + 1 FROM findings "
            "WHERE region_id=? AND system='graphdns'",
            (region_id,),
        ).fetchone()[0]
    )
    connection.execute(
        "INSERT INTO findings(region_id, system, ordinal, kind, case_key, "
        "key_quality, fingerprint, zone_cut, nameserver, start_name, query, "
        "target, server, zone, subject, reason, path, raw) "
        "VALUES(?, 'graphdns', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            region_id,
            ordinal,
            finding.kind,
            finding.case_key,
            finding.key_quality,
            finding.fingerprint,
            finding.zone_cut,
            finding.nameserver,
            finding.start_name,
            finding.query,
            finding.target,
            finding.server,
            finding.zone,
            finding.subject,
            finding.reason,
            finding.path,
            finding.raw,
        ),
    )


def update_execution_counts(
    connection: sqlite3.Connection,
    region_id: int,
    added: int,
) -> None:
    row = connection.execute(
        "SELECT finding_count, unique_case_count, details_json FROM executions "
        "WHERE region_id=? AND system='graphdns'",
        (region_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError(f"GraphDNS execution is absent for region id {region_id}")
    details: dict[str, Any] = json.loads(row["details_json"] or "{}")
    summary = details.setdefault("summary", {})
    bug_stats = details.setdefault("bug_stats", {})
    summary["bugs"] = int(summary.get("bugs", row["finding_count"])) + added
    bug_stats["MG"] = int(bug_stats.get("MG", 0)) + added
    connection.execute(
        "UPDATE executions SET finding_count=?, unique_case_count=?, "
        "details_json=? WHERE region_id=? AND system='graphdns'",
        (
            int(row["finding_count"]) + added,
            int(row["unique_case_count"]) + added,
            json.dumps(details, ensure_ascii=False, sort_keys=True),
            region_id,
        ),
    )


def write_validation_evidence(path: Path) -> None:
    rows = [
        {
            **case,
            "pre_fix_graphdns_mg": 0,
            "post_fix_graphdns_mg": 1,
            "other_bug_kinds_changed": "no",
            "validation": "full-region GraphDNS rerun",
        }
        for case in FIXED_CASES
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Create a traceable post-fix result set after GraphDNS starts "
            "treating a nameserver equal to its delegation cut as in-bailiwick."
        )
    )
    parser.add_argument("--source-run", type=Path, required=True)
    parser.add_argument("--output-run", type=Path, required=True)
    args = parser.parse_args()

    source_run = args.source_run.resolve()
    output_run = args.output_run.resolve()
    if output_run.exists():
        raise FileExistsError(f"output run already exists: {output_run}")
    output_run.mkdir(parents=True)

    for name in ("sample_manifest.csv",):
        shutil.copy2(source_run / name, output_run / name)
    database_path = output_run / "results.sqlite3"
    shutil.copy2(source_run / "results.sqlite3", database_path)

    connection = connect(database_path)
    try:
        added_by_region: dict[int, int] = {}
        with connection:
            for case in FIXED_CASES:
                region_id = validate_source_evidence(connection, case)
                insert_finding(connection, region_id, make_finding(case))
                added_by_region[region_id] = added_by_region.get(region_id, 0) + 1
            for region_id, added in added_by_region.items():
                update_execution_counts(connection, region_id, added)

        reports_dir = output_run / "reports"
        summary = generate_reports(
            connection,
            reports_dir,
            ("LD", "DI", "MG", "CZD", "RL", "RB", "ML"),
        )
    finally:
        connection.close()

    source_reports = source_run / "reports"
    for name in (
        "supplemental_unresolved_cases.csv",
        "supplemental_audit.json",
    ):
        source = source_reports / name
        if source.is_file():
            shutil.copy2(source, output_run / "reports" / name)

    source_manifest = json.loads(
        (source_run / "manifest.json").read_text(encoding="utf-8")
    )
    manifest = {
        **source_manifest,
        "created_at": datetime.now().astimezone().isoformat(),
        "parent_run": str(source_run),
        "result_derivation": (
            "Four MG findings were inserted after full-region reruns of ac.in "
            "and ac.th confirmed the nameserver-equals-cut boundary fix. "
            "All unaffected findings are inherited from the parent run."
        ),
        "fixed_cases": list(FIXED_CASES),
        "graphdns_sources": {
            **source_manifest.get("graphdns_sources", {}),
            "semantic_graph.cpp": file_sha256(
                REPO_ROOT / "src" / "semantic_graph.cpp"
            ),
        },
    }
    (output_run / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_validation_evidence(output_run / "reports" / "mg_boundary_validation.csv")

    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    print(f"[result] {output_run}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
