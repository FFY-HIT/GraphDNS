#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp1.model import parse_reports  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate one GRoot adapter output file.")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--format", choices=("jsonl", "tsv", "groot-text", "auto"), default="jsonl")
    parser.add_argument("--empty-output-means-zero", action="store_true")
    args = parser.parse_args()
    text = args.input.read_text(encoding="utf-8", errors="replace")
    findings = parse_reports(text, args.format, args.empty_output_means_zero)
    weak = [finding for finding in findings if finding.key_quality == "weak"]
    summary = {
        "findings": len(findings),
        "unique_cases": len({(finding.kind, finding.case_key) for finding in findings}),
        "by_kind": dict(sorted(Counter(finding.kind for finding in findings).items())),
        "weak_case_keys": len(weak),
        "weak_examples": [finding.to_dict() for finding in weak[:5]],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if not weak else 2


if __name__ == "__main__":
    raise SystemExit(main())
