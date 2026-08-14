#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp1 import DEFAULT_SHARED_KINDS  # noqa: E402
from exp1.reporting import generate_reports  # noqa: E402
from exp1.storage import connect  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate Experiment 01 reports from SQLite.")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument(
        "--shared-kinds",
        default=",".join(DEFAULT_SHARED_KINDS),
        help="comma-separated kinds included in the fair shared-scope comparison",
    )
    parser.add_argument(
        "--graphdns-only",
        action="store_true",
        help="regenerate a GraphDNS-only report without treating absent GRoot runs as failures",
    )
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    shared_kinds = [part.strip().upper() for part in args.shared_kinds.split(",") if part.strip()]
    manifest_path = run_dir / "manifest.json"
    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest_path.is_file()
        else {}
    )
    run_mode = manifest.get("config", {}).get("run_mode", "")
    graphdns_only = args.graphdns_only or run_mode == "graphdns_only"
    connection = connect(run_dir / "results.sqlite3")
    try:
        summary = generate_reports(
            connection,
            run_dir / "reports",
            shared_kinds,
            expected_systems=("graphdns",) if graphdns_only else ("graphdns", "groot"),
        )
    finally:
        connection.close()
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
