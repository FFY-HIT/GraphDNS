#!/usr/bin/env python3
"""Evaluate repair root-cause grouping against a controlled ground truth."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXPERIMENT_DIR.parents[1]
EXP4_DIR = REPO_ROOT / "experiments" / "experiment_04_incremental_repair_equivalence"
sys.path.insert(0, str(EXP4_DIR))

from exp4.model import parse_graphdns_output  # noqa: E402


RB_REASON = "path rewrites to target in known zone but target lacks A/AAAA"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--semantic-bin",
        type=Path,
        default=REPO_ROOT / "experiments" / "bin" / "semantic_graph",
    )
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--roots-per-multiplicity", type=int, default=6)
    return parser.parse_args()


def build_facts(roots_per_multiplicity: int) -> tuple[str, dict[str, int]]:
    if roots_per_multiplicity <= 0:
        raise ValueError("--roots-per-multiplicity must be positive")
    server = "ns.grouping.example."
    zone = "grouping.example."
    lines = [
        f"{server}\t{zone}\t{zone}\tNS\t{server}",
        f"{server}\t{zone}\t{server}\tA\t192.0.2.53",
    ]
    expected: dict[str, int] = {}
    root_index = 0
    for multiplicity in (1, 2, 4, 8, 16):
        for _ in range(roots_per_multiplicity):
            root_index += 1
            target = f"missing-{root_index}.{zone}"
            expected[target] = multiplicity
            for witness in range(1, multiplicity + 1):
                owner = f"alias-{root_index}-{witness}.{zone}"
                lines.append(
                    f"{server}\t{zone}\t{owner}\tCNAME\t{target}"
                )
    return "\n".join(lines) + "\n", expected


def pair_count(group_sizes: list[int]) -> int:
    return sum(size * (size - 1) // 2 for size in group_sizes)


def main() -> int:
    args = parse_args()
    output_dir = (
        args.output_dir.resolve()
        if args.output_dir
        else REPO_ROOT
        / "experiments"
        / "runs"
        / f"exp06_grouping_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    output_dir.mkdir(parents=True, exist_ok=False)
    facts, expected = build_facts(args.roots_per_multiplicity)
    facts_path = output_dir / "grouping_stress.facts"
    output_path = output_dir / "graphdns.txt"
    facts_path.write_text(facts, encoding="utf-8")

    command = [
        str(args.semantic_bin.resolve()),
        str(facts_path),
        "--reports-only",
        "--repair-groups-only",
        "--threads",
        "1",
        "--server-views",
        "complete",
    ]
    completed = subprocess.run(
        command,
        cwd=output_dir,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    output_path.write_text(completed.stdout, encoding="utf-8")
    if completed.returncode != 0:
        raise RuntimeError(completed.stdout[-4000:])

    parsed = parse_graphdns_output(completed.stdout)
    rb_reports = [report for report in parsed.reports if report.kind == "RB"]
    actual: dict[str, int] = {}
    rows: list[dict[str, object]] = []
    for group in parsed.groups:
        if group.kind != "RB":
            continue
        fields = group.key.split("|")
        target = fields[1] if len(fields) > 1 else ""
        actual[target] = group.grouped_reports

    all_targets = sorted(set(expected) | set(actual))
    for target in all_targets:
        rows.append(
            {
                "target": target,
                "expected_witnesses": expected.get(target, 0),
                "observed_witnesses": actual.get(target, 0),
                "exact": expected.get(target) == actual.get(target),
            }
        )
    with (output_dir / "groups.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    true_pairs = pair_count(list(expected.values()))
    predicted_pairs = pair_count(list(actual.values()))
    matched_pairs = (
        true_pairs
        if expected == actual
        else sum(
            min(expected.get(target, 0), actual.get(target, 0))
            * (min(expected.get(target, 0), actual.get(target, 0)) - 1)
            // 2
            for target in all_targets
        )
    )
    summary = {
        "records": len(facts.splitlines()),
        "rb_reports": len(rb_reports),
        "true_root_cause_groups": len(expected),
        "predicted_root_cause_groups": len(actual),
        "exact_groups": sum(row["exact"] is True for row in rows),
        "all_groups_exact": expected == actual,
        "merge_rate": 1.0 - len(actual) / len(rb_reports),
        "pairwise_precision": (
            matched_pairs / predicted_pairs if predicted_pairs else 1.0
        ),
        "pairwise_recall": matched_pairs / true_pairs if true_pairs else 1.0,
        "group_purity": 1.0 if expected == actual else None,
        "multiplicity_distribution": dict(
            sorted(Counter(expected.values()).items())
        ),
        "command": command,
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        "Root-cause grouping: "
        f"reports={summary['rb_reports']} "
        f"groups={summary['predicted_root_cause_groups']} "
        f"pair_precision={summary['pairwise_precision']:.4f} "
        f"pair_recall={summary['pairwise_recall']:.4f}"
    )
    print(f"[result] {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
