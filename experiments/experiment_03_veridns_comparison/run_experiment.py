#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


EXPERIMENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXPERIMENT_DIR.parents[1]
EXP2_DIR = REPO_ROOT / "experiments" / "experiment_02_symbolic_ablation"
sys.path.insert(0, str(EXPERIMENT_DIR))
sys.path.insert(0, str(EXP2_DIR))

from exp2.bugs import BugFinding, detect_path_bugs  # noqa: E402
from exp2.model import Case, load_cases  # noqa: E402
from exp2.resolver import ConcreteResolver  # noqa: E402
from exp3.graphdns_cli import (  # noqa: E402
    build_graphdns,
    check_graphdns_cli_pair,
)
from exp3.census_updates import load_census_controlled_suite  # noqa: E402
from exp3.incremental import (  # noqa: E402
    IncrementalComparison,
    graphdns_full_paths,
    graphdns_incremental_paths,
    graphdns_static_graph,
)
from exp3.veridns import (  # noqa: E402
    PathSignature,
    record_deltas,
    veridns_full_paths,
    veridns_incremental_paths,
    veridns_static_graph,
)


METHOD_VERIDNS = "VeriDNS-RSG reproduction"
METHOD_GRAPHDNS = "Full GraphDNS"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare a paper-faithful VeriDNS RSG reproduction with GraphDNS "
            "for path soundness and incremental/full-rebuild consistency."
        )
    )
    parser.add_argument(
        "--static-dataset",
        type=Path,
        default=EXP2_DIR / "dataset" / "census_real_cases.json",
        help=(
            "Bounded static dataset (default: Experiment 02's real Census "
            "cases)."
        ),
    )
    parser.add_argument(
        "--incremental-dataset",
        type=Path,
        help=(
            "Legacy expanded before/after dataset. When supplied, it "
            "overrides the default Census-controlled update workload."
        ),
    )
    parser.add_argument(
        "--controlled-update-spec",
        type=Path,
        default=EXPERIMENT_DIR / "dataset" / "census_controlled_updates.json",
        help="Compact specification of controlled changes on Census cases.",
    )
    parser.add_argument(
        "--census-base-dataset",
        type=Path,
        default=EXP2_DIR / "dataset" / "census_real_cases.json",
        help="Complete Census cases used as each controlled update background.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Output directory (default: experiments/runs/exp03_<timestamp>).",
    )
    parser.add_argument(
        "--build",
        action="store_true",
        help="Build and run the production C++ GraphDNS consistency check.",
    )
    parser.add_argument(
        "--graphdns-binary",
        type=Path,
        help="Existing GraphDNS binary for the production consistency check.",
    )
    parser.add_argument(
        "--skip-cpp-check",
        action="store_true",
        help="Run only the bounded semantic experiment.",
    )
    parser.add_argument(
        "--allow-unexpected",
        action="store_true",
        help="Write results instead of failing when declared expectations differ.",
    )
    return parser.parse_args()


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _bug_key(bug: BugFinding) -> tuple[str, str, tuple[str, ...]]:
    # Match the detector's report identity: terminal text is witness detail,
    # not a distinct root report for the same kind/query/path.
    return bug.kind, bug.query, bug.path


def _case_pairs(cases: tuple[Case, ...]) -> list[tuple[Case, Case]]:
    grouped: dict[str, dict[str, Case]] = defaultdict(dict)
    for case in cases:
        if not case.pair_id:
            raise ValueError(f"incremental case has no pair_id: {case.id}")
        if case.snapshot in grouped[case.pair_id]:
            raise ValueError(
                f"duplicate {case.snapshot} snapshot for {case.pair_id}"
            )
        grouped[case.pair_id][case.snapshot] = case

    result: list[tuple[Case, Case]] = []
    for pair_id in sorted(grouped):
        snapshots = grouped[pair_id]
        if set(snapshots) != {"before", "after"}:
            raise ValueError(
                f"{pair_id} requires before/after snapshots, got {sorted(snapshots)}"
            )
        result.append((snapshots["before"], snapshots["after"]))
    return result


def _run_static(
    cases: tuple[Case, ...],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    per_case: list[dict[str, Any]] = []
    details: list[dict[str, Any]] = []
    aggregate: dict[str, dict[str, Any]] = {
        METHOD_VERIDNS: {
            "nodes": 0,
            "edges": 0,
            "oracle": set(),
            "predicted": set(),
            "bugs": set(),
        },
        METHOD_GRAPHDNS: {
            "nodes": 0,
            "edges": 0,
            "oracle": set(),
            "predicted": set(),
            "bugs": set(),
        },
    }

    for case in cases:
        traces = ConcreteResolver(case).resolve_all()
        oracle = {trace.signature for trace in traces}
        oracle_bugs = detect_path_bugs(case, oracle)
        oracle_bug_keys = {_bug_key(bug) for bug in oracle_bugs}
        evaluations = (
            (METHOD_VERIDNS, veridns_static_graph(traces)),
            (METHOD_GRAPHDNS, graphdns_static_graph(traces)),
        )

        print(
            f"[static] {case.id}: records={len(case.records)} "
            f"queries={len(case.queries)} oracle_paths={len(oracle)}"
        )
        for method_name, (graph, result) in evaluations:
            predicted = result.predicted
            bugs = detect_path_bugs(case, predicted)
            bug_keys = {_bug_key(bug) for bug in bugs}
            false_paths = predicted - oracle
            missed_paths = oracle - predicted
            false_bugs = bug_keys - oracle_bug_keys
            missed_bugs = oracle_bug_keys - bug_keys
            row = {
                "case_id": case.id,
                "method": method_name,
                "records": len(case.records),
                "queries": len(case.queries),
                "nodes": len(graph.nodes),
                "edges": len(graph.edges),
                "oracle_paths": len(oracle),
                "predicted_paths": len(predicted),
                "false_paths": len(false_paths),
                "missed_paths": len(missed_paths),
                "precision": result.precision,
                "recall": result.recall,
                "reported_vulnerabilities": len(bug_keys),
                "false_vulnerabilities": len(false_bugs),
                "missed_vulnerabilities": len(missed_bugs),
            }
            per_case.append(row)

            bucket = aggregate[method_name]
            bucket["nodes"] += len(graph.nodes)
            bucket["edges"] += len(graph.edges)
            bucket["oracle"].update((case.id, *path) for path in oracle)
            bucket["predicted"].update((case.id, *path) for path in predicted)
            bucket["bugs"].update((case.id, *key) for key in bug_keys)

            for classification, paths in (
                ("pseudo_path", false_paths),
                ("missed_path", missed_paths),
            ):
                for query, path, outcome in sorted(paths):
                    details.append(
                        {
                            "section": "static",
                            "case_id": case.id,
                            "method": method_name,
                            "classification": classification,
                            "query": query,
                            "path": list(path),
                            "outcome": outcome,
                        }
                    )
            for bug in sorted(
                bugs,
                key=lambda item: (item.kind, item.query, item.path, item.outcome),
            ):
                if _bug_key(bug) not in oracle_bug_keys:
                    details.append(
                        {
                            "section": "static",
                            "case_id": case.id,
                            "method": method_name,
                            "classification": "false_vulnerability",
                            "kind": bug.kind,
                            "query": bug.query,
                            "path": list(bug.path),
                            "outcome": bug.outcome,
                        }
                    )

    oracle_bugs = aggregate[METHOD_GRAPHDNS]["bugs"]
    summary: list[dict[str, Any]] = []
    for method_name in (METHOD_VERIDNS, METHOD_GRAPHDNS):
        bucket = aggregate[method_name]
        oracle = bucket["oracle"]
        predicted = bucket["predicted"]
        true_paths = len(oracle & predicted)
        false_paths = len(predicted - oracle)
        missed_paths = len(oracle - predicted)
        denominator = true_paths + false_paths
        recall_denominator = true_paths + missed_paths
        summary.append(
            {
                "method": method_name,
                "nodes": bucket["nodes"],
                "edges": bucket["edges"],
                "oracle_paths": len(oracle),
                "predicted_paths": len(predicted),
                "false_paths": false_paths,
                "missed_paths": missed_paths,
                "precision": true_paths / denominator if denominator else 1.0,
                "recall": (
                    true_paths / recall_denominator if recall_denominator else 1.0
                ),
                "reported_vulnerabilities": len(bucket["bugs"]),
                "false_vulnerabilities": len(bucket["bugs"] - oracle_bugs),
                "missed_vulnerabilities": len(oracle_bugs - bucket["bugs"]),
            }
        )
    return summary, per_case, details


def _comparison_row(
    comparison: IncrementalComparison,
    full_bugs: set[BugFinding],
    incremental_bugs: set[BugFinding],
) -> dict[str, Any]:
    full_bug_keys = {_bug_key(bug) for bug in full_bugs}
    incremental_bug_keys = {_bug_key(bug) for bug in incremental_bugs}
    return {
        "pair_id": comparison.pair_id,
        "method": comparison.method,
        "queries": comparison.total_queries,
        "affected_queries": len(comparison.affected_queries),
        "incremental_paths": len(comparison.incremental_paths),
        "full_rebuild_paths": len(comparison.full_paths),
        "stale_paths": len(comparison.stale_paths),
        "missed_paths": len(comparison.missed_paths),
        "incremental_reports": len(incremental_bug_keys),
        "full_rebuild_reports": len(full_bug_keys),
        "stale_reports": len(incremental_bug_keys - full_bug_keys),
        "missed_reports": len(full_bug_keys - incremental_bug_keys),
        "consistent": comparison.consistent
        and incremental_bug_keys == full_bug_keys,
    }


def _run_incremental(
    pairs: list[tuple[Case, Case]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    per_pair: list[dict[str, Any]] = []
    details: list[dict[str, Any]] = []

    for before, after in pairs:
        before_traces = ConcreteResolver(before).resolve_all()
        after_traces = ConcreteResolver(after).resolve_all()
        veridns_before = veridns_full_paths(before_traces)
        veridns_after = veridns_full_paths(after_traces)
        veridns_incremental, veridns_affected, affected_nodes = (
            veridns_incremental_paths(
                before, after, veridns_before, veridns_after
            )
        )
        graphdns_before = graphdns_full_paths(before_traces)
        graphdns_after = graphdns_full_paths(after_traces)
        graphdns_incremental, graphdns_affected = graphdns_incremental_paths(
            before,
            after,
            before_traces,
            graphdns_before,
            graphdns_after,
        )

        comparisons = (
            IncrementalComparison(
                method=METHOD_VERIDNS,
                pair_id=before.pair_id,
                total_queries=len(before.queries),
                affected_queries=veridns_affected,
                incremental_paths=veridns_incremental,
                full_paths=veridns_after,
            ),
            IncrementalComparison(
                method=METHOD_GRAPHDNS,
                pair_id=before.pair_id,
                total_queries=len(before.queries),
                affected_queries=graphdns_affected,
                incremental_paths=graphdns_incremental,
                full_paths=graphdns_after,
            ),
        )

        print(
            f"[update] {before.pair_id}: queries={len(before.queries)} "
            f"VeriDNS-affected={len(veridns_affected)} "
            f"GraphDNS-affected={len(graphdns_affected)} "
            f"paper-RSG-nodes={len(affected_nodes)}"
        )
        for comparison in comparisons:
            full_bugs = detect_path_bugs(after, comparison.full_paths)
            incremental_bugs = detect_path_bugs(
                after, comparison.incremental_paths
            )
            per_pair.append(
                _comparison_row(comparison, full_bugs, incremental_bugs)
            )
            for classification, paths in (
                ("stale_path_after_update", comparison.stale_paths),
                ("missed_path_after_update", comparison.missed_paths),
            ):
                for query, path, outcome in sorted(paths):
                    details.append(
                        {
                            "section": "incremental",
                            "pair_id": before.pair_id,
                            "method": comparison.method,
                            "classification": classification,
                            "query": query,
                            "path": list(path),
                            "outcome": outcome,
                        }
                    )

    summary: list[dict[str, Any]] = []
    for method in (METHOD_VERIDNS, METHOD_GRAPHDNS):
        rows = [row for row in per_pair if row["method"] == method]
        summary.append(
            {
                "method": method,
                "update_pairs": len(rows),
                "consistent_pairs": sum(bool(row["consistent"]) for row in rows),
                "inconsistent_pairs": sum(
                    not bool(row["consistent"]) for row in rows
                ),
                "affected_queries": sum(int(row["affected_queries"]) for row in rows),
                "stale_paths": sum(int(row["stale_paths"]) for row in rows),
                "missed_paths": sum(int(row["missed_paths"]) for row in rows),
                "stale_reports": sum(int(row["stale_reports"]) for row in rows),
                "missed_reports": sum(int(row["missed_reports"]) for row in rows),
            }
        )
    return summary, per_pair, details


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _write_report(
    path: Path,
    static_summary: list[dict[str, Any]],
    incremental_summary: list[dict[str, Any]],
    incremental_rows: list[dict[str, Any]],
    cli_rows: list[dict[str, Any]],
    static_cases: int,
    update_pairs: int,
    incremental_mode: str,
    update_metadata: list[dict[str, Any]],
) -> None:
    lines = [
        "# Experiment 03: VeriDNS and GraphDNS",
        "",
        "## Scope",
        "",
        (
            f"The static experiment evaluates {static_cases} bounded DNS "
            "configurations. The update experiment evaluates "
            f"{update_pairs} single-record changes."
        ),
        "",
        (
            "Incremental workload: "
            + (
                "controlled interventions superimposed on complete real "
                "Census region configurations. Fixture records are identical "
                "in both snapshots; each pair differs by one RR change. These "
                "changes are not claimed to be observed historical updates."
                if incremental_mode == "census-controlled"
                else "an explicitly supplied expanded before/after dataset."
            )
        ),
        "",
        (
            "The VeriDNS baseline is a clean-room reproduction of the RSG and "
            "incremental impact algorithm described in Sections 3.1--3.3 of "
            "the paper. The paper's GitHub URL returned 404 when this artifact "
            "was prepared, so these results must not be presented as a run of "
            "the unavailable official implementation."
        ),
        "",
        "## Static path soundness",
        "",
        "| Method | Nodes | Edges | Oracle paths | Predicted | Pseudo | Missed | Precision | Recall | Vulnerabilities | False vulnerabilities |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in static_summary:
        lines.append(
            "| {method} | {nodes} | {edges} | {oracle_paths} | "
            "{predicted_paths} | {false_paths} | {missed_paths} | "
            "{precision:.4f} | {recall:.4f} | "
            "{reported_vulnerabilities} | {false_vulnerabilities} |".format(**row)
        )

    lines.extend(
        [
            "",
            "## Incremental consistency",
            "",
            "| Method | Updates | Consistent | Inconsistent | Affected queries | Stale paths | Missed paths | Stale reports | Missed reports |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in incremental_summary:
        lines.append(
            "| {method} | {update_pairs} | {consistent_pairs} | "
            "{inconsistent_pairs} | {affected_queries} | {stale_paths} | "
            "{missed_paths} | {stale_reports} | {missed_reports} |".format(**row)
        )

    lines.extend(
        [
            "",
            "### Per-update result",
            "",
            "| Update | Census background | Operation | Method | Affected/total queries | Local paths | Full paths | Stale | Missed | Consistent |",
            "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for row in incremental_rows:
        lines.append(
            "| {pair_id} | {source_region} | {operation} | {method} | "
            "{affected_queries}/{queries} | "
            "{incremental_paths} | {full_rebuild_paths} | {stale_paths} | "
            "{missed_paths} | {consistent} |".format(**row)
        )

    if update_metadata:
        lines.extend(
            [
                "",
                "### Controlled-update provenance",
                "",
                "| Update | Base case | Base RRs | Shared fixture RRs | Delta | Changed record |",
                "| --- | --- | ---: | ---: | --- | --- |",
            ]
        )
        for row in update_metadata:
            value_change = (
                f"`{row['old_value']}` -> `{row['new_value']}`"
                if row["operation"] == "MODIFY"
                else (
                    f"`{row['new_value']}`"
                    if row["operation"] == "ADD"
                    else f"`{row['old_value']}`"
                )
            )
            lines.append(
                f"| {row['pair_id']} | {row['base_case_id']} | "
                f"{row['base_records']} | {row['shared_control_records']} | "
                f"{row['operation']} | `{row['changed_owner']}` "
                f"{row['changed_type']} {value_change} |"
            )

    lines.extend(
        [
            "",
            "## Production GraphDNS executable check",
            "",
        ]
    )
    if not cli_rows:
        lines.append(
            "Not run. Use `--build`, or pass `--graphdns-binary`, to compare "
            "the C++ incremental report set with a fresh C++ rebuild."
        )
    else:
        lines.extend(
            [
                "| Update | Before reports | Incremental after | Full after | Stale | Missed | Consistent | Error |",
                "| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |",
            ]
        )
        for row in cli_rows:
            lines.append(
                "| {pair_id} | {before_reports} | "
                "{incremental_after_reports} | {full_after_reports} | "
                "{stale_reports} | {missed_reports} | {consistent} | "
                "{error} |".format(**row)
            )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            (
                "Static pseudo paths are measured against the declared finite "
                "concrete-query oracle. Incremental omissions are measured "
                "against each method's own full post-update rebuild; therefore "
                "they are not caused by differences between GraphDNS and "
                "VeriDNS's static abstractions."
            ),
            "",
            (
                "The controlled updates change DNS record-selection priority "
                "(DNAME shadowing, wildcard activation, and delegation cuts) "
                "without necessarily creating an explicit owner--rdata path "
                "from the old result to the changed RSG edge. GraphDNS also "
                "indexes these semantic coverage dependencies."
            ),
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def _validate_expectations(
    static_summary: list[dict[str, Any]],
    incremental_rows: list[dict[str, Any]],
    expectations: dict[str, Any],
    cli_rows: list[dict[str, Any]],
) -> None:
    static = {row["method"]: row for row in static_summary}
    graphdns = static[METHOD_GRAPHDNS]
    veridns = static[METHOD_VERIDNS]
    if graphdns["false_paths"] or graphdns["missed_paths"]:
        raise AssertionError("Full GraphDNS differs from the bounded oracle")
    if veridns["false_paths"] == 0:
        raise AssertionError("the dataset did not expose a VeriDNS pseudo path")

    by_key = {
        (row["pair_id"], row["method"]): row for row in incremental_rows
    }
    for pair_id in expectations.get("veridns_mismatch_pairs", []):
        if by_key[(pair_id, METHOD_VERIDNS)]["consistent"]:
            raise AssertionError(f"expected a VeriDNS mismatch for {pair_id}")
    for pair_id in expectations.get("veridns_consistent_pairs", []):
        if not by_key[(pair_id, METHOD_VERIDNS)]["consistent"]:
            raise AssertionError(f"unexpected VeriDNS mismatch for {pair_id}")
    if expectations.get("graphdns_all_consistent", False):
        mismatches = [
            row["pair_id"]
            for row in incremental_rows
            if row["method"] == METHOD_GRAPHDNS and not row["consistent"]
        ]
        if mismatches:
            raise AssertionError(
                "GraphDNS local/full mismatch: " + ", ".join(mismatches)
            )
    if cli_rows:
        failures = [
            row["pair_id"]
            for row in cli_rows
            if not row["consistent"] or row["error"]
        ]
        if failures:
            raise AssertionError(
                "C++ GraphDNS incremental/full report mismatch: "
                + ", ".join(failures)
            )


def main() -> int:
    args = parse_args()
    static_dataset = args.static_dataset.resolve()
    if not static_dataset.is_file():
        raise FileNotFoundError(static_dataset)

    incremental_dataset: Path | None = None
    controlled_update_spec: Path | None = None
    census_base_dataset: Path | None = None
    incremental_mode: str
    update_metadata: list[dict[str, Any]]
    if args.incremental_dataset:
        incremental_mode = "expanded"
        incremental_dataset = args.incremental_dataset.resolve()
        if not incremental_dataset.is_file():
            raise FileNotFoundError(incremental_dataset)
        incremental_cases = load_cases(incremental_dataset)
        payload = json.loads(incremental_dataset.read_text(encoding="utf-8"))
        expectations = payload.get("expectations", {})
        update_metadata = []
    else:
        incremental_mode = "census-controlled"
        controlled_update_spec = args.controlled_update_spec.resolve()
        census_base_dataset = args.census_base_dataset.resolve()
        for dataset in (controlled_update_spec, census_base_dataset):
            if not dataset.is_file():
                raise FileNotFoundError(dataset)
        suite = load_census_controlled_suite(
            controlled_update_spec,
            census_base_dataset,
        )
        incremental_cases = suite.cases
        expectations = suite.expectations
        update_metadata = list(suite.updates)

    output_dir = (
        args.output_dir.resolve()
        if args.output_dir
        else REPO_ROOT
        / "experiments"
        / "runs"
        / f"exp03_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    output_dir.mkdir(parents=True, exist_ok=False)

    static_cases = load_cases(static_dataset)
    pairs = _case_pairs(incremental_cases)
    if not update_metadata:
        for before, after in pairs:
            deltas = record_deltas(before, after)
            delta = deltas[0] if len(deltas) == 1 else None
            changed = (
                (delta.new if delta and delta.new is not None else delta.old)
                if delta
                else None
            )
            update_metadata.append(
                {
                    "pair_id": before.pair_id,
                    "base_case_id": "custom",
                    "source_region": "custom",
                    "operation": delta.operation if delta else "SEQUENCE",
                    "changed_owner": changed.owner if changed else "",
                    "changed_type": changed.type if changed else "",
                    "old_value": (
                        delta.old.value if delta and delta.old is not None else ""
                    ),
                    "new_value": (
                        delta.new.value if delta and delta.new is not None else ""
                    ),
                    "base_records": min(len(before.records), len(after.records)),
                    "shared_control_records": 0,
                    "before_records": len(before.records),
                    "after_records": len(after.records),
                    "queries": len(before.queries),
                    "description": before.description,
                }
            )

    static_summary, static_rows, static_details = _run_static(static_cases)
    incremental_summary, incremental_rows, incremental_details = (
        _run_incremental(pairs)
    )
    metadata_by_pair = {row["pair_id"]: row for row in update_metadata}
    for row in incremental_rows:
        metadata = metadata_by_pair[row["pair_id"]]
        row.update(
            {
                "base_case_id": metadata["base_case_id"],
                "source_region": metadata["source_region"],
                "start_server": metadata.get("start_server", ""),
                "start_zone": metadata.get("start_zone", ""),
                "operation": metadata["operation"],
                "changed_owner": metadata["changed_owner"],
                "changed_type": metadata["changed_type"],
                "base_records": metadata["base_records"],
                "shared_control_records": metadata["shared_control_records"],
            }
        )

    cli_rows: list[dict[str, Any]] = []
    binary: Path | None = None
    if not args.skip_cpp_check:
        if args.graphdns_binary:
            binary = args.graphdns_binary.resolve()
        elif args.build:
            suffix = ".exe" if sys.platform.startswith("win") else ""
            binary = REPO_ROOT / "experiments" / "bin" / f"semantic_graph{suffix}"
            build_graphdns(REPO_ROOT / "src" / "semantic_graph.cpp", binary)
        if binary is not None:
            if not binary.is_file():
                raise FileNotFoundError(binary)
            for before, after in pairs:
                result = check_graphdns_cli_pair(
                    binary,
                    before,
                    after,
                    output_dir / "graphdns_cpp" / before.pair_id,
                )
                cli_rows.append(vars(result))

    _write_csv(
        output_dir / "static_summary.csv",
        static_summary,
        [
            "method",
            "nodes",
            "edges",
            "oracle_paths",
            "predicted_paths",
            "false_paths",
            "missed_paths",
            "precision",
            "recall",
            "reported_vulnerabilities",
            "false_vulnerabilities",
            "missed_vulnerabilities",
        ],
    )
    _write_csv(
        output_dir / "static_per_case.csv",
        static_rows,
        [
            "case_id",
            "method",
            "records",
            "queries",
            "nodes",
            "edges",
            "oracle_paths",
            "predicted_paths",
            "false_paths",
            "missed_paths",
            "precision",
            "recall",
            "reported_vulnerabilities",
            "false_vulnerabilities",
            "missed_vulnerabilities",
        ],
    )
    _write_csv(
        output_dir / "incremental_summary.csv",
        incremental_summary,
        [
            "method",
            "update_pairs",
            "consistent_pairs",
            "inconsistent_pairs",
            "affected_queries",
            "stale_paths",
            "missed_paths",
            "stale_reports",
            "missed_reports",
        ],
    )
    _write_csv(
        output_dir / "incremental_per_case.csv",
        incremental_rows,
        [
            "pair_id",
            "base_case_id",
            "source_region",
            "start_server",
            "start_zone",
            "operation",
            "changed_owner",
            "changed_type",
            "base_records",
            "shared_control_records",
            "method",
            "queries",
            "affected_queries",
            "incremental_paths",
            "full_rebuild_paths",
            "stale_paths",
            "missed_paths",
            "incremental_reports",
            "full_rebuild_reports",
            "stale_reports",
            "missed_reports",
            "consistent",
        ],
    )
    _write_csv(
        output_dir / "controlled_update_provenance.csv",
        update_metadata,
        [
            "pair_id",
            "base_case_id",
            "source_region",
            "start_server",
            "start_zone",
            "operation",
            "changed_owner",
            "changed_type",
            "old_value",
            "new_value",
            "base_records",
            "shared_control_records",
            "before_records",
            "after_records",
            "queries",
            "description",
        ],
    )
    if cli_rows:
        _write_csv(
            output_dir / "graphdns_cpp_consistency.csv",
            cli_rows,
            [
                "pair_id",
                "before_reports",
                "incremental_after_reports",
                "full_after_reports",
                "stale_reports",
                "missed_reports",
                "consistent",
                "error",
            ],
        )
    _write_jsonl(
        output_dir / "differences.jsonl",
        static_details + incremental_details,
    )
    _write_report(
        output_dir / "report.md",
        static_summary,
        incremental_summary,
        incremental_rows,
        cli_rows,
        len(static_cases),
        len(pairs),
        incremental_mode,
        update_metadata,
    )

    manifest = {
        "experiment": "veridns_graphdns_comparison",
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "paper": {
            "title": "VeriDNS: incremental distributed verification of DNS configurations",
            "doi": "10.1016/j.comnet.2025.111929",
            "reproduction_basis": "Sections 3.1--3.3 of the paper",
            "official_repository_url": "https://github.com/KaiQiangHu996/VeriDNS",
            "official_repository_status": "404/unavailable when prepared",
        },
        "static_dataset": str(static_dataset),
        "static_dataset_sha256": hashlib.sha256(
            static_dataset.read_bytes()
        ).hexdigest(),
        "incremental_mode": incremental_mode,
        "incremental_dataset": str(incremental_dataset or ""),
        "incremental_dataset_sha256": (
            hashlib.sha256(incremental_dataset.read_bytes()).hexdigest()
            if incremental_dataset
            else ""
        ),
        "controlled_update_spec": str(controlled_update_spec or ""),
        "controlled_update_spec_sha256": (
            hashlib.sha256(controlled_update_spec.read_bytes()).hexdigest()
            if controlled_update_spec
            else ""
        ),
        "census_base_dataset": str(census_base_dataset or ""),
        "census_base_dataset_sha256": (
            hashlib.sha256(census_base_dataset.read_bytes()).hexdigest()
            if census_base_dataset
            else ""
        ),
        "controlled_update_provenance": update_metadata,
        "static_cases": len(static_cases),
        "update_pairs": len(pairs),
        "graphdns_cpp_check": bool(cli_rows),
        "graphdns_binary": str(binary) if binary else "",
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    if not args.allow_unexpected:
        _validate_expectations(
            static_summary,
            incremental_rows,
            expectations,
            cli_rows,
        )

    print(
        "\nMethod                         Nodes   Edges   Pseudo  "
        "Precision  Recall  FalseV"
    )
    for row in static_summary:
        print(
            f"{row['method']:<30} {row['nodes']:>6} {row['edges']:>7} "
            f"{row['false_paths']:>8} {row['precision']:>10.4f} "
            f"{row['recall']:>7.4f} {row['false_vulnerabilities']:>7}"
        )
    print("\nIncremental consistency")
    for row in incremental_summary:
        print(
            f"{row['method']:<30} consistent={row['consistent_pairs']}/"
            f"{row['update_pairs']} stale={row['stale_paths']} "
            f"missed={row['missed_paths']}"
        )
    if cli_rows:
        print(
            "C++ GraphDNS report consistency: "
            f"{sum(bool(row['consistent']) for row in cli_rows)}/{len(cli_rows)}"
        )
    print(f"\n[result] {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
