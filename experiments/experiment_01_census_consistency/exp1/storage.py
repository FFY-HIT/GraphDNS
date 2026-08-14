from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .model import Finding
from .sampling import Region


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS regions (
    id INTEGER PRIMARY KEY,
    sample_rank INTEGER NOT NULL UNIQUE,
    name TEXT NOT NULL UNIQUE,
    path TEXT NOT NULL,
    sample_score TEXT NOT NULL,
    zone_file_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS executions (
    region_id INTEGER NOT NULL,
    system TEXT NOT NULL,
    status TEXT NOT NULL,
    return_code INTEGER NOT NULL,
    wall_seconds REAL NOT NULL,
    record_count INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    unique_case_count INTEGER NOT NULL DEFAULT 0,
    details_json TEXT NOT NULL DEFAULT '{}',
    error TEXT NOT NULL DEFAULT '',
    output_tail TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (region_id, system),
    FOREIGN KEY (region_id) REFERENCES regions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    region_id INTEGER NOT NULL,
    system TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    kind TEXT NOT NULL,
    case_key TEXT NOT NULL,
    key_quality TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    zone_cut TEXT NOT NULL,
    nameserver TEXT NOT NULL,
    start_name TEXT NOT NULL,
    query TEXT NOT NULL,
    target TEXT NOT NULL,
    server TEXT NOT NULL,
    zone TEXT NOT NULL,
    subject TEXT NOT NULL,
    reason TEXT NOT NULL,
    path TEXT NOT NULL,
    raw TEXT NOT NULL,
    UNIQUE(region_id, system, ordinal),
    FOREIGN KEY (region_id) REFERENCES regions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_system_kind_key
ON findings(system, kind, case_key);

CREATE INDEX IF NOT EXISTS idx_findings_region_system
ON findings(region_id, system);
"""


@dataclass
class ExecutionResult:
    system: str
    status: str
    return_code: int
    wall_seconds: float
    record_count: int
    findings: list[Finding]
    details: dict[str, Any]
    error: str = ""
    output_tail: str = ""


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA)
    return connection


def set_metadata(connection: sqlite3.Connection, key: str, value: Any) -> None:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True)
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, encoded),
    )


def add_regions(connection: sqlite3.Connection, regions: Iterable[Region]) -> None:
    connection.executemany(
        "INSERT OR IGNORE INTO regions(sample_rank, name, path, sample_score, zone_file_count) "
        "VALUES(?, ?, ?, ?, ?)",
        [
            (r.sample_rank, r.name, r.path, r.sample_score, r.zone_file_count)
            for r in regions
        ],
    )
    connection.commit()


def load_regions(connection: sqlite3.Connection) -> list[Region]:
    rows = connection.execute(
        "SELECT sample_rank, name, path, sample_score, zone_file_count "
        "FROM regions ORDER BY sample_rank"
    ).fetchall()
    return [
        Region(
            sample_rank=row["sample_rank"],
            name=row["name"],
            path=row["path"],
            sample_score=row["sample_score"],
            zone_file_count=row["zone_file_count"],
        )
        for row in rows
    ]


def successful_systems(connection: sqlite3.Connection, region_name: str) -> set[str]:
    rows = connection.execute(
        "SELECT e.system FROM executions e JOIN regions r ON r.id=e.region_id "
        "WHERE r.name=? AND e.status='ok'",
        (region_name,),
    ).fetchall()
    return {row["system"] for row in rows}


def save_execution(
    connection: sqlite3.Connection,
    region_name: str,
    result: ExecutionResult,
) -> None:
    row = connection.execute("SELECT id FROM regions WHERE name=?", (region_name,)).fetchone()
    if row is None:
        raise KeyError(f"region is absent from database: {region_name}")
    region_id = int(row["id"])
    unique_cases = len({(finding.kind, finding.case_key) for finding in result.findings})
    with connection:
        connection.execute(
            "DELETE FROM findings WHERE region_id=? AND system=?",
            (region_id, result.system),
        )
        connection.execute(
            "INSERT INTO executions(region_id, system, status, return_code, wall_seconds, "
            "record_count, finding_count, unique_case_count, details_json, error, output_tail) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(region_id, system) DO UPDATE SET "
            "status=excluded.status, return_code=excluded.return_code, "
            "wall_seconds=excluded.wall_seconds, record_count=excluded.record_count, "
            "finding_count=excluded.finding_count, unique_case_count=excluded.unique_case_count, "
            "details_json=excluded.details_json, error=excluded.error, output_tail=excluded.output_tail",
            (
                region_id,
                result.system,
                result.status,
                result.return_code,
                result.wall_seconds,
                result.record_count,
                len(result.findings),
                unique_cases,
                json.dumps(result.details, ensure_ascii=False, sort_keys=True),
                result.error,
                result.output_tail[-8000:],
            ),
        )
        connection.executemany(
            "INSERT INTO findings(region_id, system, ordinal, kind, case_key, key_quality, "
            "fingerprint, zone_cut, nameserver, start_name, query, target, server, zone, "
            "subject, reason, path, raw) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    region_id,
                    result.system,
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
                )
                for ordinal, finding in enumerate(result.findings, start=1)
            ],
        )
