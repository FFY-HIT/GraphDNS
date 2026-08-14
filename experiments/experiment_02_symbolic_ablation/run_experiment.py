#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


EXPERIMENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXPERIMENT_DIR.parents[1]
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp2.ablation import Method, evaluate_method  # noqa: E402
from exp2.bugs import detect_path_bugs  # noqa: E402
from exp2.model import load_cases  # noqa: E402
from exp2.resolver import ConcreteResolver  # noqa: E402


METHODS = (
    Method.CONCRETE,
    Method.ALPHA_ONLY,
    Method.ALPHA_BETA_UNBOUND,
    Method.FULL,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Measure graph compression and path soundness for Concrete, "
            "alpha-only, alpha+beta without binding, and Full GraphDNS."
        )
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=EXPERIMENT_DIR / "dataset" / "rfc_symbolic_cases.json",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Output directory (default: experiments/runs/exp02_<timestamp>).",
    )
    return parser.parse_args()


def _signature_json(
    case_id: str,
    signature: tuple[str, tuple[str, ...], str],
    method: str,
    classification: str,
) -> dict[str, Any]:
    query, path, outcome = signature
    return {
        "case_id": case_id,
        "method": method,
        "classification": classification,
        "query": query,
        "path": list(path),
        "outcome": outcome,
    }


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _format_pct(value: float) -> str:
    return f"{value * 100:.2f}%"


def _write_report(
    path: Path,
    aggregate_rows: list[dict[str, Any]],
    per_case_rows: list[dict[str, Any]],
    query_count: int,
    record_count: int,
    case_count: int,
) -> None:
    concrete = next(row for row in aggregate_rows if row["method"] == Method.CONCRETE.value)
    full = next(row for row in aggregate_rows if row["method"] == Method.FULL.value)
    unbound = next(
        row
        for row in aggregate_rows
        if row["method"] == Method.ALPHA_BETA_UNBOUND.value
    )
    unbound_false_vulnerabilities = unbound["false_vulnerabilities"]
    node_reduction = 1.0 - full["nodes"] / concrete["nodes"]
    edge_reduction = 1.0 - full["edges"] / concrete["edges"]

    lines = [
        "# Experiment 02: Symbolic Abstraction and Dynamic Binding",
        "",
        "## Scope",
        "",
        (
            f"The bounded oracle evaluates {query_count} concrete queries over "
            f"{case_count} configurations containing {record_count} records."
        ),
        "",
        "## Aggregate results",
        "",
        "| Method | Nodes | Edges | Predicted paths | False paths | Precision | Recall | Missed paths | Reported vulnerabilities | False vulnerabilities |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in aggregate_rows:
        lines.append(
            "| {method} | {nodes} | {edges} | {predicted_paths} | "
            "{false_paths} | {precision:.4f} | {recall:.4f} | "
            "{missed_paths} | {reported_vulnerabilities} | "
            "{false_vulnerabilities} |".format(**row)
        )

    lines.extend(
        [
            "",
            "## Main observations",
            "",
            (
                f"- Full GraphDNS reduces nodes by {_format_pct(node_reduction)} and "
                f"edges by {_format_pct(edge_reduction)} relative to bounded concrete "
                "enumeration."
            ),
            (
                f"- The alpha+beta graph has the same size with and without dynamic "
                f"binding, but binding removes {unbound['false_paths']} spurious paths."
            ),
            (
                f"- Full GraphDNS has {full['false_paths']} false paths and "
                f"{full['missed_paths']} missed paths on this bounded oracle, "
                f"and preserves all {concrete['reported_vulnerabilities']} "
                "oracle vulnerability reports."
            ),
            (
                f"- Dropping dynamic binding produces "
                f"{unbound_false_vulnerabilities} additional vulnerability "
                "reports relative to the concrete oracle."
            ),
            "",
            "## Per-configuration checks",
            "",
            "| Case | Method | Queries | Nodes | Edges | False paths | Precision | Recall | Missed paths | Vulnerabilities | False vulnerabilities |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in per_case_rows:
        lines.append(
            "| {case_id} | {method} | {queries} | {nodes} | {edges} | "
            "{false_paths} | {precision:.4f} | {recall:.4f} | "
            "{missed_paths} | {reported_vulnerabilities} | "
            "{false_vulnerabilities} |".format(**row)
        )

    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            (
                "Concrete is an oracle only for the finite label alphabet and maximum "
                "prefix depth declared by the dataset. The experiment isolates the "
                "effect of alpha/beta quotienting and cross-edge binding; it is not a "
                "claim that the DNS namespace itself is finite."
            ),
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    args = parse_args()
    dataset_path = args.dataset.resolve()
    if not dataset_path.is_file():
        raise FileNotFoundError(dataset_path)

    output_dir = (
        args.output_dir.resolve()
        if args.output_dir
        else REPO_ROOT
        / "experiments"
        / "runs"
        / f"exp02_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    output_dir.mkdir(parents=True, exist_ok=False)

    dataset_payload = json.loads(dataset_path.read_text(encoding="utf-8"))
    expectations = dataset_payload.get("ablation_expectations", {})
    concrete_oracle_is_safe = bool(
        expectations.get("concrete_oracle_is_safe", True)
    )
    unbound_must_have_false_paths = bool(
        expectations.get("unbound_must_have_false_paths", True)
    )
    unbound_must_have_false_vulnerabilities = bool(
        expectations.get("unbound_must_have_false_vulnerabilities", True)
    )
    cases = load_cases(dataset_path)
    per_case_rows: list[dict[str, Any]] = []
    detail_rows: list[dict[str, Any]] = []
    aggregate: dict[Method, dict[str, Any]] = {
        method: {
            "nodes": 0,
            "edges": 0,
            "predicted": set(),
            "oracle": set(),
            "bugs": set(),
        }
        for method in METHODS
    }
    query_count = 0
    record_count = 0

    for case in cases:
        traces = ConcreteResolver(case).resolve_all()
        oracle = {trace.signature for trace in traces}
        oracle_bugs = detect_path_bugs(case, oracle)
        oracle_bug_keys = {bug.key for bug in oracle_bugs}
        query_count += len(traces)
        record_count += len(case.records)
        print(
            f"[case] {case.id}: records={len(case.records)} "
            f"queries={len(traces)} oracle_paths={len(oracle)}"
        )

        for method in METHODS:
            graph, result = evaluate_method(traces, method)
            false_paths = result.predicted - oracle
            missed_paths = oracle - result.predicted
            bugs = detect_path_bugs(case, result.predicted)
            bug_keys = {bug.key for bug in bugs}
            bugs_by_key = {
                bug.key: bug
                for bug in sorted(
                    bugs,
                    key=lambda item: (
                        item.kind,
                        item.query,
                        item.path,
                        item.outcome,
                        item.reason,
                    ),
                )
            }
            true_vulnerabilities = len(bug_keys & oracle_bug_keys)
            false_vulnerabilities = len(bug_keys - oracle_bug_keys)
            missed_vulnerabilities = len(oracle_bug_keys - bug_keys)
            bugs_by_kind = {
                kind: sum(1 for bug_key in bug_keys if bug_key[0] == kind)
                for kind in ("RL", "RB", "ML")
            }
            per_case_rows.append(
                {
                    "case_id": case.id,
                    "pair_id": case.pair_id,
                    "snapshot": case.snapshot,
                    "method": method.value,
                    "records": len(case.records),
                    "queries": len(traces),
                    "oracle_paths": len(oracle),
                    "nodes": result.node_count,
                    "edges": result.edge_count,
                    "predicted_paths": len(result.predicted),
                    "true_paths": result.true_positive,
                    "false_paths": result.false_positive,
                    "missed_paths": result.false_negative,
                    "precision": result.precision,
                    "recall": result.recall,
                    "reported_vulnerabilities": len(bug_keys),
                    "true_vulnerabilities": true_vulnerabilities,
                    "false_vulnerabilities": false_vulnerabilities,
                    "missed_vulnerabilities": missed_vulnerabilities,
                    "reported_RL": bugs_by_kind["RL"],
                    "reported_RB": bugs_by_kind["RB"],
                    "reported_ML": bugs_by_kind["ML"],
                }
            )

            bucket = aggregate[method]
            bucket["nodes"] += len(graph.nodes)
            bucket["edges"] += len(graph.edges)
            bucket["oracle"].update((case.id, *signature) for signature in oracle)
            bucket["predicted"].update(
                (case.id, *signature) for signature in result.predicted
            )
            bucket["bugs"].update(
                (case.id, bug.kind, bug.query, bug.path) for bug in bugs
            )

            detail_rows.extend(
                _signature_json(case.id, signature, method.value, "false_path")
                for signature in sorted(false_paths)
            )
            detail_rows.extend(
                _signature_json(case.id, signature, method.value, "missed_path")
                for signature in sorted(missed_paths)
            )
            detail_rows.extend(
                {
                    "case_id": case.id,
                    "method": method.value,
                    "classification": (
                        "oracle_vulnerability"
                        if bug.key in oracle_bug_keys
                        else "false_vulnerability"
                    ),
                    "kind": bug.kind,
                    "query": bug.query,
                    "path": list(bug.path),
                    "outcome": bug.outcome,
                    "reason": bug.reason,
                }
                for bug in bugs_by_key.values()
            )

    aggregate_rows: list[dict[str, Any]] = []
    oracle_bugs = aggregate[Method.CONCRETE]["bugs"]
    for method in METHODS:
        bucket = aggregate[method]
        predicted = bucket["predicted"]
        oracle = bucket["oracle"]
        true_positive = len(predicted & oracle)
        false_positive = len(predicted - oracle)
        false_negative = len(oracle - predicted)
        bugs = bucket["bugs"]
        true_vulnerabilities = len(bugs & oracle_bugs)
        false_vulnerabilities = len(bugs - oracle_bugs)
        missed_vulnerabilities = len(oracle_bugs - bugs)
        bugs_by_kind = {
            kind: sum(1 for bug in bugs if bug[1] == kind)
            for kind in ("RL", "RB", "ML")
        }
        precision = (
            true_positive / (true_positive + false_positive)
            if true_positive + false_positive
            else 1.0
        )
        recall = (
            true_positive / (true_positive + false_negative)
            if true_positive + false_negative
            else 1.0
        )
        aggregate_rows.append(
            {
                "method": method.value,
                "nodes": bucket["nodes"],
                "edges": bucket["edges"],
                "oracle_paths": len(oracle),
                "predicted_paths": len(predicted),
                "true_paths": true_positive,
                "false_paths": false_positive,
                "missed_paths": false_negative,
                "precision": precision,
                "recall": recall,
                "reported_vulnerabilities": len(bugs),
                "true_vulnerabilities": true_vulnerabilities,
                "false_vulnerabilities": false_vulnerabilities,
                "missed_vulnerabilities": missed_vulnerabilities,
                "reported_RL": bugs_by_kind["RL"],
                "reported_RB": bugs_by_kind["RB"],
                "reported_ML": bugs_by_kind["ML"],
            }
        )

    by_method = {row["method"]: row for row in aggregate_rows}
    concrete = by_method[Method.CONCRETE.value]
    unbound = by_method[Method.ALPHA_BETA_UNBOUND.value]
    full = by_method[Method.FULL.value]
    if concrete["false_paths"] or concrete["missed_paths"]:
        raise AssertionError("Concrete graph must reproduce the concrete oracle")
    if full["false_paths"] or full["missed_paths"]:
        raise AssertionError("Full GraphDNS must reproduce the concrete oracle")
    if full["nodes"] >= concrete["nodes"] or full["edges"] >= concrete["edges"]:
        raise AssertionError("symbolic graph did not reduce graph size")
    if (
        full["nodes"] != unbound["nodes"]
        or full["edges"] != unbound["edges"]
    ):
        raise AssertionError("binding ablation unexpectedly changed graph structure")
    if unbound["false_paths"] == 0:
        if unbound_must_have_false_paths:
            raise AssertionError("dataset failed to expose unbound pseudo paths")
    if concrete_oracle_is_safe and concrete["reported_vulnerabilities"]:
        raise AssertionError("safe concrete configurations produced a real vulnerability")
    if full["false_vulnerabilities"] or full["missed_vulnerabilities"]:
        raise AssertionError("Full GraphDNS changed concrete vulnerability reports")
    if (
        unbound_must_have_false_vulnerabilities
        and unbound["false_vulnerabilities"] == 0
    ):
        raise AssertionError(
            "dataset failed to expose a false vulnerability without binding"
        )

    _write_csv(
        output_dir / "summary.csv",
        aggregate_rows,
        [
            "method",
            "nodes",
            "edges",
            "oracle_paths",
            "predicted_paths",
            "true_paths",
            "false_paths",
            "missed_paths",
            "precision",
            "recall",
            "reported_vulnerabilities",
            "true_vulnerabilities",
            "false_vulnerabilities",
            "missed_vulnerabilities",
            "reported_RL",
            "reported_RB",
            "reported_ML",
        ],
    )
    _write_csv(
        output_dir / "per_case.csv",
        per_case_rows,
        [
            "case_id",
            "pair_id",
            "snapshot",
            "method",
            "records",
            "queries",
            "oracle_paths",
            "nodes",
            "edges",
            "predicted_paths",
            "true_paths",
            "false_paths",
            "missed_paths",
            "precision",
            "recall",
            "reported_vulnerabilities",
            "true_vulnerabilities",
            "false_vulnerabilities",
            "missed_vulnerabilities",
            "reported_RL",
            "reported_RB",
            "reported_ML",
        ],
    )
    with (output_dir / "path_differences.jsonl").open(
        "w", encoding="utf-8"
    ) as handle:
        for row in detail_rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    manifest = {
        "experiment": "symbolic_abstraction_and_binding_ablation",
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "dataset": str(dataset_path),
        "dataset_sha256": __import__("hashlib").sha256(
            dataset_path.read_bytes()
        ).hexdigest(),
        "case_count": len(cases),
        "record_count": record_count,
        "query_count": query_count,
        "methods": [method.value for method in METHODS],
        "query_bound": (
            "Finite labels and per-template prefix depth declared in the dataset."
        ),
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    _write_report(
        output_dir / "report.md",
        aggregate_rows,
        per_case_rows,
        query_count,
        record_count,
        len(cases),
    )

    print(
        "\nMethod                         Nodes   Edges   False  "
        "Precision  Recall  Missed  Vulns  FalseV"
    )
    for row in aggregate_rows:
        print(
            f"{row['method']:<30} {row['nodes']:>6} {row['edges']:>7} "
            f"{row['false_paths']:>7} {row['precision']:>10.4f} "
            f"{row['recall']:>7.4f} {row['missed_paths']:>7} "
            f"{row['reported_vulnerabilities']:>6} "
            f"{row['false_vulnerabilities']:>7}"
        )
    print(f"\n[result] {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
