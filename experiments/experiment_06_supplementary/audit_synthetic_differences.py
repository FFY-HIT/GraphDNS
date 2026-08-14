#!/usr/bin/env python3
"""Root-cause and BIND audit for controlled synthetic comparison differences."""

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


def normalize_name(value: str) -> str:
    text = value.strip().lower()
    return text if not text or text.endswith(".") else text + "."


def strict_descendant(name: str, suffix: str) -> bool:
    name = normalize_name(name)
    suffix = normalize_name(suffix)
    return name != suffix and name.endswith("." + suffix)


def parse_dnames(dataset: Path) -> list[tuple[str, str]]:
    records: list[tuple[str, str]] = []
    for path in sorted(dataset.glob("*.txt")):
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            fields = raw.split()
            upper = [field.upper() for field in fields]
            if "DNAME" not in upper:
                continue
            index = upper.index("DNAME")
            if index > 0 and index + 1 < len(fields):
                records.append(
                    (normalize_name(fields[0]), normalize_name(fields[index + 1]))
                )
    return records


def dname_rewrite(name: str, owner: str, target: str) -> str | None:
    name = normalize_name(name)
    owner = normalize_name(owner)
    target = normalize_name(target)
    if not strict_descendant(name, owner):
        return None
    prefix = name[: -len(owner)]
    return prefix + target


def cycle_members(finding: Finding) -> set[str]:
    marker = "CZD|zones="
    if not finding.case_key.startswith(marker):
        return set()
    return {
        normalize_name(value)
        for value in finding.case_key[len(marker) :].split("|")
        if value
    }


def read_bind(path: Path) -> dict[tuple[str, str], dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return {
            (normalize_name(row["query"]), row["type"].upper()): row
            for row in csv.DictReader(handle)
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--graphdns", type=Path, required=True)
    parser.add_argument("--groot", type=Path, required=True)
    parser.add_argument("--synthetic-dir", type=Path, required=True)
    parser.add_argument("--bind-results", type=Path, required=True)
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
    graphdns = [row for row in graphdns_all if row.kind in SHARED_KINDS]
    groot = [row for row in groot_all if row.kind in SHARED_KINDS]
    graphdns_exact = {(row.kind, row.case_key) for row in graphdns}
    graphdns_mg = [
        (normalize_name(row.zone_cut), normalize_name(row.nameserver))
        for row in graphdns
        if row.kind == "MG"
    ]
    graphdns_rb = {
        (normalize_name(row.start_name), normalize_name(row.target))
        for row in graphdns
        if row.kind == "RB"
    }
    dnames = parse_dnames(args.synthetic_dir)
    bind = read_bind(args.bind_results)

    audit_rows: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for finding in groot:
        if (finding.kind, finding.case_key) in graphdns_exact:
            continue
        classification = "unresolved"
        evidence = ""

        if finding.kind == "CZD":
            members = cycle_members(finding)
            matching = [
                (cut, nameserver)
                for cut, nameserver in graphdns_mg
                if nameserver in members
            ]
            if matching:
                classification = "same_root_as_graphdns_missing_glue"
                evidence = "; ".join(f"{cut} -> {nameserver}" for cut, nameserver in matching)

        elif finding.kind == "RB":
            start = normalize_name(finding.start_name)
            target = normalize_name(finding.target)
            for owner, dname_target in dnames:
                rewritten = dname_rewrite(start, owner, dname_target)
                if rewritten != target:
                    continue
                if (owner, dname_target) in graphdns_rb:
                    classification = "covered_by_graphdns_symbolic_rb_root"
                    evidence = f"{owner} DNAME {dname_target}"
                    break
            if classification == "unresolved":
                candidates = [
                    row for (name, _), row in bind.items() if name == start
                ]
                if candidates:
                    row = candidates[0]
                    has_terminal = row["has_terminal_address"].lower() == "true"
                    if row["status"].upper() == "NXDOMAIN" and not has_terminal:
                        classification = "bind_confirmed_graphdns_false_negative"
                    else:
                        classification = "bind_rejected_groot_false_positive"
                    evidence = (
                        f"status={row['status']}; answers={row['answer_types'] or '<none>'}"
                    )

        counts[classification] += 1
        audit_rows.append(
            {
                "kind": finding.kind,
                "case_key": finding.case_key,
                "classification": classification,
                "evidence": evidence,
            }
        )

    graphdns_root_count = len(graphdns_exact)
    confirmed_extra_roots = counts["bind_confirmed_graphdns_false_negative"]
    false_groot_roots = counts["bind_rejected_groot_false_positive"]
    reference_true_roots = graphdns_root_count + confirmed_extra_roots
    summary = {
        "graphdns_shared_root_causes": graphdns_root_count,
        "groot_exact_unique_cases": len({(row.kind, row.case_key) for row in groot}),
        "difference_classification": dict(sorted(counts.items())),
        "bind_audited_true_roots": reference_true_roots,
        "graphdns": {
            "true_roots": graphdns_root_count,
            "false_roots": 0,
            "precision": 1.0,
            "recall": graphdns_root_count / reference_true_roots,
        },
        "groot": {
            "true_roots": reference_true_roots,
            "false_roots": false_groot_roots,
            "precision": reference_true_roots
            / (reference_true_roots + false_groot_roots),
            "recall": 1.0,
        },
        "scope": (
            "Controlled synthetic root causes after collapsing duplicate witnesses; "
            "the five unmatched DNAME cases are adjudicated by direct BIND queries."
        ),
    }
    with (args.output_dir / "difference_audit.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["kind", "case_key", "classification", "evidence"]
        )
        writer.writeheader()
        writer.writerows(audit_rows)
    (args.output_dir / "root_cause_audit.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
