#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp1.reporting import summarize_manual_review  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and summarize all mismatch annotations.")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    reports_dir = args.run_dir.resolve() / "reports"
    summary, exit_code = summarize_manual_review(
        reports_dir / "manual_review.csv", reports_dir, args.require_complete
    )
    comparison_summary_path = reports_dir / "summary.json"
    if comparison_summary_path.is_file():
        comparison_summary = json.loads(comparison_summary_path.read_text(encoding="utf-8"))
        comparison_ready = comparison_summary.get("normalization", {}).get(
            "comparison_ready", False
        )
        summary["strong_case_keys_complete"] = comparison_ready
        if args.require_complete and not comparison_ready:
            exit_code = 1
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
