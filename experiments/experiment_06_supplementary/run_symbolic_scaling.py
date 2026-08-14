#!/usr/bin/env python3
"""Measure concrete-query and SRAG graph growth as the label set expands."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parent
EVAL1_DIR = EXPERIMENT_DIR.parent
EXP2_DIR = EVAL1_DIR / "experiment_02_symbolic_ablation"
sys.path.insert(0, str(EXP2_DIR))

from exp2.ablation import Method, evaluate_method  # noqa: E402
from exp2.model import Case, Query, Record, normalize_domain  # noqa: E402
from exp2.resolver import ConcreteResolver  # noqa: E402


K_VALUES = (1, 2, 4, 8, 16, 32, 64)


def make_case(k: int) -> Case:
    labels = [f"l{index:02d}" for index in range(k)]
    suffix = "old.scale.test."
    queries = [Query(suffix, suffix)]
    for first in labels:
        queries.append(Query(normalize_domain(f"{first}.{suffix}"), suffix))
        for second in labels:
            queries.append(
                Query(normalize_domain(f"{first}.{second}.{suffix}"), suffix)
            )
    query_by_name = {query.name: query for query in queries}
    records = (
        Record(
            "scale_dname_1",
            "ns.scale.test.",
            "scale.test.",
            "old.scale.test.",
            "DNAME",
            "mid.scale.test.",
        ),
        Record(
            "scale_dname_2",
            "ns.scale.test.",
            "scale.test.",
            "mid.scale.test.",
            "DNAME",
            "final.scale.test.",
        ),
        Record(
            "scale_wildcard",
            "ns.scale.test.",
            "scale.test.",
            "*.final.scale.test.",
            "A",
            "192.0.2.200",
        ),
    )
    return Case(
        id=f"symbolic_scaling_k{k}",
        description="Two DNAME rewrites followed by a wildcard terminal",
        pair_id="",
        snapshot="base",
        start_server="ns.scale.test.",
        start_zone="scale.test.",
        authorities={"scale.test.": "ns.scale.test."},
        records=records,
        queries=tuple(query_by_name[name] for name in sorted(query_by_name)),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=EVAL1_DIR / "runs" / "exp06_symbolic_scaling",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, int | float]] = []

    for k in K_VALUES:
        case = make_case(k)
        traces = ConcreteResolver(case).resolve_all()
        concrete_graph, concrete = evaluate_method(traces, Method.CONCRETE)
        srag_graph, srag = evaluate_method(traces, Method.FULL)
        if concrete.false_positive or concrete.false_negative:
            raise AssertionError(f"concrete graph disagrees with its traces for k={k}")
        if srag.false_positive or srag.false_negative:
            raise AssertionError(f"SRAG disagrees with concrete traces for k={k}")
        row = {
            "k": k,
            "queries": len(case.queries),
            "concrete_nodes": len(concrete_graph.nodes),
            "concrete_edges": len(concrete_graph.edges),
            "srag_nodes": len(srag_graph.nodes),
            "srag_edges": len(srag_graph.edges),
            "node_reduction_pct": 100.0
            * (1.0 - len(srag_graph.nodes) / len(concrete_graph.nodes)),
            "edge_reduction_pct": 100.0
            * (1.0 - len(srag_graph.edges) / len(concrete_graph.edges)),
        }
        rows.append(row)
        print(
            f"[k={k:>2}] queries={row['queries']:,} "
            f"nodes={row['concrete_nodes']:,}/{row['srag_nodes']:,} "
            f"edges={row['concrete_edges']:,}/{row['srag_edges']:,}",
            flush=True,
        )

    csv_path = output_dir / "symbolic_scaling.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "experiment": "bounded_symbolic_scaling",
        "k_values": list(K_VALUES),
        "prefix_depth": 2,
        "records": 3,
        "largest": rows[-1],
        "correctness_guard": "SRAG precision=recall=1 for every k",
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "# Symbolic Graph Scaling",
        "",
        "The workload contains two consecutive DNAME rewrites and one wildcard",
        "terminal.  For each label-set size k, it enumerates the apex query, k",
        "one-label names, and k^2 two-label names.  SRAG is built from the same",
        "traces and must retain precision=recall=1.",
        "",
        "| k | Queries | Concrete nodes | SRAG nodes | Concrete edges | SRAG edges |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            f"| {row['k']} | {row['queries']:,} | {row['concrete_nodes']:,} | "
            f"{row['srag_nodes']:,} | {row['concrete_edges']:,} | {row['srag_edges']:,} |"
        )
    (output_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[result] {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
