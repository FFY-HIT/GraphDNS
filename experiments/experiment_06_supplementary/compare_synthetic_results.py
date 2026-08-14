#!/usr/bin/env python3
"""Compare GraphDNS and official GRoot findings on a controlled complete input."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


EXPERIMENT_DIR = Path(__file__).resolve().parent
EXP1_DIR = EXPERIMENT_DIR.parent / "experiment_01_census_consistency"
sys.path.insert(0, str(EXP1_DIR))

from exp1.model import Finding, parse_reports  # noqa: E402


SHARED_KINDS = {"LD", "DI", "MG", "CZD", "RL", "RB", "ML"}


def normalized_key(finding: Finding) -> str:
    if finding.kind in {"LD", "CZD"}:
        cut = finding.zone_cut
        if not cut and finding.case_key.startswith("CZD|zones="):
            cut = finding.case_key[len("CZD|zones=") :].split("|", 1)[0]
        return f"DELEGATION_FAILURE|cut={cut}"
    if finding.kind == "DI":
        return f"DI|cut={finding.zone_cut}"
    if finding.kind == "MG":
        return f"MG|cut={finding.zone_cut}|ns={finding.nameserver}"
    if finding.kind == "RB":
        return f"RB|start={finding.start_name}|target={finding.target}"
    if finding.kind == "RL":
        return f"RL|start={finding.start_name}"
    if finding.kind == "ML":
        return f"ML|start={finding.start_name}|target={finding.target}"
    return finding.case_key


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--graphdns", type=Path, required=True)
    parser.add_argument("--groot", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    graphdns_all = parse_reports(
        args.graphdns.read_text(encoding="utf-8", errors="replace"),
        "graphdns-text",
        empty_output_means_zero=False,
    )
    groot_all = parse_reports(
        args.groot.read_text(encoding="utf-8", errors="replace"),
        "jsonl",
        empty_output_means_zero=True,
    )
    graphdns = [finding for finding in graphdns_all if finding.kind in SHARED_KINDS]
    groot = [finding for finding in groot_all if finding.kind in SHARED_KINDS]

    graphdns_keys = {(finding.kind, finding.case_key) for finding in graphdns}
    groot_keys = {(finding.kind, finding.case_key) for finding in groot}
    graphdns_semantic = {normalized_key(finding) for finding in graphdns}
    groot_semantic = {normalized_key(finding) for finding in groot}

    kinds = sorted(SHARED_KINDS)
    per_kind: list[dict[str, Any]] = []
    for kind in kinds:
        graphdns_kind = {
            finding.case_key for finding in graphdns if finding.kind == kind
        }
        groot_kind = {finding.case_key for finding in groot if finding.kind == kind}
        per_kind.append(
            {
                "kind": kind,
                "graphdns_raw": sum(finding.kind == kind for finding in graphdns),
                "groot_raw": sum(finding.kind == kind for finding in groot),
                "graphdns_unique": len(graphdns_kind),
                "groot_unique": len(groot_kind),
                "intersection": len(graphdns_kind & groot_kind),
                "graphdns_only": len(graphdns_kind - groot_kind),
                "groot_only": len(groot_kind - graphdns_kind),
            }
        )

    summary = {
        "graphdns_raw_by_kind": dict(Counter(finding.kind for finding in graphdns)),
        "groot_raw_by_kind": dict(Counter(finding.kind for finding in groot)),
        "exact": {
            "graphdns_unique": len(graphdns_keys),
            "groot_unique": len(groot_keys),
            "intersection": len(graphdns_keys & groot_keys),
            "graphdns_only": len(graphdns_keys - groot_keys),
            "groot_only": len(groot_keys - graphdns_keys),
        },
        "semantic": {
            "graphdns_unique": len(graphdns_semantic),
            "groot_unique": len(groot_semantic),
            "intersection": len(graphdns_semantic & groot_semantic),
            "graphdns_only": len(graphdns_semantic - groot_semantic),
            "groot_only": len(groot_semantic - graphdns_semantic),
        },
        "graphdns_record_level_findings": len(graphdns_all) - len(graphdns),
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with (args.output_dir / "agreement_by_kind.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(per_kind[0]))
        writer.writeheader()
        writer.writerows(per_kind)

    differences: list[dict[str, str]] = []
    for side, findings, other in (
        ("graphdns_only", graphdns, groot_semantic),
        ("groot_only", groot, graphdns_semantic),
    ):
        for finding in findings:
            key = normalized_key(finding)
            if key in other:
                continue
            differences.append(
                {
                    "side": side,
                    "kind": finding.kind,
                    "case_key": finding.case_key,
                    "semantic_key": key,
                    "reason": finding.reason,
                    "path": finding.path,
                }
            )
    with (args.output_dir / "semantic_differences.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        fieldnames = ["side", "kind", "case_key", "semantic_key", "reason", "path"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(differences)

    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
