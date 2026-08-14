#!/usr/bin/env python3
"""Cross-check the expanded static DNAME query suite with uncached BIND."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


EXPERIMENT_DIR = Path(__file__).resolve().parent
EVAL1_DIR = EXPERIMENT_DIR.parent
EXP2_DIR = EVAL1_DIR / "experiment_02_symbolic_ablation"
EXP3_DIR = EVAL1_DIR / "experiment_03_veridns_comparison"
sys.path.insert(0, str(EXP2_DIR))
sys.path.insert(0, str(EXP3_DIR))

from exp2.model import load_cases  # noqa: E402
from run_bind_runtime_validation import (  # noqa: E402
    ensure_child_loopback,
    remove_child_loopback,
    require_runtime,
    run_snapshot,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run every query in an Experiment 02 dataset against isolated "
            "authoritative BIND servers and a fresh zero-cache resolver."
        )
    )
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    return parser.parse_args()


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = list(rows[0]) if rows else []
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    args = parse_args()
    require_runtime()
    cases = load_cases(args.dataset.resolve())
    output_dir = args.output_dir.resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    case_errors: list[dict[str, str]] = []
    serial = int(datetime.now().strftime("%Y%m%d%H"))
    added_child_loopback = ensure_child_loopback()
    try:
        for index, case in enumerate(cases, start=1):
            print(
                f"[runtime] case={case.id} queries={len(case.queries)}",
                flush=True,
            )
            try:
                case_rows = run_snapshot(
                    case,
                    output_dir / "runtime" / case.id,
                    serial,
                    args.timeout,
                )
            except (subprocess.CalledProcessError, RuntimeError) as exc:
                case_errors.append(
                    {
                        "case_id": case.id,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                print(
                    f"[excluded] case={case.id} reason={case_errors[-1]['error']}",
                    flush=True,
                )
                serial += 10
                continue
            for row in case_rows:
                row["case_id"] = case.id
            rows.extend(case_rows)
            write_csv(output_dir / "bind_static_queries.csv", rows)
            print(
                f"[progress] case={index}/{len(cases)} "
                f"agree={sum(bool(row['match']) for row in case_rows)}/"
                f"{len(case_rows)}",
                flush=True,
            )
            serial += 10
    finally:
        if added_child_loopback:
            remove_child_loopback()

    write_csv(output_dir / "bind_static_queries.csv", rows)
    matching = sum(bool(row["match"]) for row in rows)
    summary = {
        "cases": len(cases),
        "loadable_cases": len(cases) - len(case_errors),
        "excluded_cases": case_errors,
        "queries": len(rows),
        "matching_queries": matching,
        "agreement": matching / len(rows) if rows else None,
        "cache_policy": {
            "fresh_resolver_per_query": True,
            "max_cache_ttl": 0,
            "max_negative_cache_ttl": 0,
        },
        "authoritative_runtime": "BIND named",
        "comparison_target": "bounded concrete resolution outcome",
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (output_dir / "report.md").write_text(
        "\n".join(
            (
                "# Static DNAME BIND Cross-Validation",
                "",
                f"- Cases: **{len(cases)}**",
                f"- Queries: **{len(rows)}**",
                f"- Matching BIND observations: **{matching}/{len(rows)}**",
                "- Resolver policy: one fresh process per query; positive and "
                "negative cache TTLs set to zero.",
                "",
            )
        ),
        encoding="utf-8",
    )
    print(f"[done] matching={matching}/{len(rows)}")
    print(f"[result] {output_dir}")
    return 0 if matching == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
