#!/usr/bin/env python3
"""Generate standalone publication figures for the current evaluation chapter."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RQ1_RUN = (
    ROOT / "experiments" / "runs" / "exp06_groot_10000_v3_mg_boundary_fix"
)
DEFAULT_EVIDENCE = ROOT / "experiments" / "runs" / "final_evidence"
DEFAULT_FINDING_AUDIT = (
    ROOT
    / "experiments"
    / "runs"
    / "exp01_20260726_113450"
    / "audit"
    / "finding_audit.csv"
)
DEFAULT_OUT = Path(__file__).resolve().parent / "output"
DEFAULT_SOURCE = Path(__file__).resolve().parent / "source_data"

# Standalone figures use a 16:8 (2:1) canvas by default.  The dense zone-level
# distribution uses a wider 22:8 canvas so every zone label remains legible.
STANDARD_FIGSIZE = (8.0, 4.0)
ZONE_DISTRIBUTION_FIGSIZE = (11.0, 4.0)
FULL_WIDTH = STANDARD_FIGSIZE[0]
SINGLE_WIDTH = STANDARD_FIGSIZE[0]

COLORS = {
    "blue": "#4E79A7",
    "orange": "#F28E2B",
    "red": "#E15759",
    "teal": "#76B7B2",
    "green": "#59A14F",
    "yellow": "#EDC948",
    "purple": "#B07AA1",
    "gray": "#A7A9AC",
    "light_gray": "#D9D9D9",
    "dark": "#333333",
}

BUG_COLORS = {
    "DI": COLORS["teal"],
    "LD": "#B8B8B8",
    "MG": COLORS["orange"],
    "CZD": "#D0D0D0",
    "RL": COLORS["red"],
    "RB": COLORS["purple"],
    "ML": "#969696",
    "SR": COLORS["green"],
}

METHOD_COLORS = {
    "Concrete": COLORS["gray"],
    "alpha-only": COLORS["orange"],
    "alpha+beta, no binding": COLORS["teal"],
    "Full GraphDNS": COLORS["blue"],
    "VeriDNS-RSG reproduction": COLORS["orange"],
}

CURRENT_STEMS = {
    "rq1_detection_overview",
    "rq1_finding_type_counts",
    "rq1_shadow_record_causes",
    "rq1_region_distribution_all",
    "rq1_groot_overlap_by_type",
    "rq1_difference_audit",
    "rq2_graph_size_ablation",
    "rq2_pseudo_path_ablation",
    "rq2_path_precision_recall",
    "rq2_false_finding_ablation",
    "rq2_symbolic_scaling_nodes",
    "rq2_symbolic_scaling_edges",
    "rq3_update_consistency",
    "rq3_update_precision_recall",
    "rq3_update_errors",
    "rq4_incremental_equivalence",
    "rq4_local_dfs_distribution",
    "rq4_local_dfs_by_kind",
    "rq5_grouping_reduction",
    "rq5_grouping_stress",
    "rq5_candidate_coverage",
    "rq5_repair_candidate_validity",
    "rq5_repair_rejection_reasons",
    "rq5_candidate_validity_by_risk",
    "rq6_core_runtime",
    "rq6_core_speedup_distribution",
    "rq6_validation_runtime",
    "rq6_candidate_speedup_distribution",
    "rq6_scalability_runtime",
    "rq6_scalability_graph_size",
    "rq6_scalability_memory",
    "rq6_edge_node_ratio_distribution",
}

CURRENT_SOURCE_FILES = {
    "rq1_finding_types.csv",
    "rq1_shadow_causes.csv",
    "rq1_region_findings.csv",
    "rq1_groot_overlap.csv",
    "rq1_difference_audit.csv",
    "rq2_symbolic_ablation.csv",
    "rq2_symbolic_scaling.csv",
    "rq3_update_consistency.csv",
    "rq3_update_precision_recall.csv",
    "rq3_update_errors.csv",
    "rq4_incremental_equivalence.csv",
    "rq4_local_dfs_executions.csv",
    "rq5_grouping_reduction.csv",
    "rq5_grouping_stress.csv",
    "rq5_candidate_coverage.csv",
    "rq5_candidate_outcomes.csv",
    "rq5_candidate_risk.csv",
    "rq6_core_runtime.csv",
    "rq6_core_speedups.csv",
    "rq6_validation_runtime.csv",
    "rq6_candidate_speedups.csv",
    "rq6_scalability.csv",
    "rq6_edge_node_ratios.csv",
}


def configure_style() -> None:
    mpl.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans", "sans-serif"],
            "font.size": 8.5,
            "axes.labelsize": 9.5,
            "xtick.labelsize": 8.0,
            "ytick.labelsize": 8.0,
            "legend.fontsize": 8.0,
            "axes.linewidth": 0.75,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": False,
            "legend.frameon": False,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.facecolor": "white",
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "svg.fonttype": "none",
            "lines.linewidth": 1.25,
            "patch.linewidth": 0,
        }
    )


def y_grid(ax: plt.Axes) -> None:
    ax.grid(axis="y", color="#D8D8D8", linewidth=0.55, linestyle="--", alpha=0.8)
    ax.set_axisbelow(True)


def x_grid(ax: plt.Axes) -> None:
    ax.grid(axis="x", color="#D8D8D8", linewidth=0.55, linestyle="--", alpha=0.8)
    ax.set_axisbelow(True)


def save_figure(
    fig: plt.Figure,
    stem: str,
    out_dir: Path,
    figsize: tuple[float, float] = STANDARD_FIGSIZE,
) -> None:
    if len(fig.axes) != 1:
        raise RuntimeError(f"{stem} must contain exactly one axes")
    out_dir.mkdir(parents=True, exist_ok=True)
    fig.set_size_inches(*figsize, forward=True)
    fig.tight_layout(pad=0.9)
    fig.savefig(out_dir / f"{stem}.pdf")
    fig.savefig(out_dir / f"{stem}.svg")
    fig.savefig(out_dir / f"{stem}.png", dpi=300)
    fig.savefig(
        out_dir / f"{stem}.tiff",
        dpi=600,
        pil_kwargs={"compression": "tiff_lzw"},
    )
    plt.close(fig)


def clean_generated_files(out_dir: Path, source_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    source_dir.mkdir(parents=True, exist_ok=True)
    for path in out_dir.iterdir():
        if path.is_file() and path.suffix.lower() in {".pdf", ".svg", ".png", ".tiff"}:
            if path.stem not in CURRENT_STEMS:
                path.unlink()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def ensure_paths(paths: dict[str, Path]) -> None:
    missing = [f"{name}: {path}" for name, path in paths.items() if not path.exists()]
    if missing:
        raise FileNotFoundError("Missing experiment inputs:\n" + "\n".join(missing))


def bool_series(series: pd.Series) -> pd.Series:
    return series.astype(str).str.lower().isin({"true", "1", "yes"})


def display_method(method: str) -> str:
    return {
        "Concrete": "Concrete",
        "alpha-only": "Alpha only",
        "alpha+beta, no binding": "Alpha + beta\n(no binding)",
        "Full GraphDNS": "GraphDNS",
        "VeriDNS-RSG reproduction": "VeriDNS\nreproduction",
    }.get(method, method)


def format_count(value: float) -> str:
    return f"{int(round(value)):,}"


def format_decimal(value: float) -> str:
    if value >= 1000:
        return f"{value:,.0f}"
    if value >= 10:
        return f"{value:.1f}"
    if value >= 1:
        return f"{value:.2f}"
    return f"{value:.3f}"


def annotate_bars(
    ax: plt.Axes,
    bars,
    values,
    *,
    formatter=format_count,
    fontsize: float = 6.0,
    rotation: float = 0,
) -> None:
    # Values belong in the source-data table and caption, not above every bar.
    return None


def annotate_barh(ax: plt.Axes, bars, values, *, fontsize: float = 6.0) -> None:
    return None


def ecdf(values: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    x = np.sort(values.astype(float))
    y = np.arange(1, len(x) + 1, dtype=float) / len(x)
    return x, y


UPDATE_KEYS = [
    "delete_exact_activates_wildcard",
    "add_dname_shadows_descendant",
    "delete_dname_reactivates_descendant",
    "add_wildcard_activates_answer",
    "modify_dname_target",
    "add_delegation_shadows_parent",
    "add_dname_introduces_loop",
]

UPDATE_LABELS = {
    "delete_exact_activates_wildcard": "Delete exact A",
    "add_dname_shadows_descendant": "Add ancestor\nDNAME",
    "delete_dname_reactivates_descendant": "Delete ancestor\nDNAME",
    "add_wildcard_activates_answer": "Add wildcard\nCNAME",
    "modify_dname_target": "Modify DNAME\ntarget",
    "add_delegation_shadows_parent": "Add delegation\nNS",
    "add_dname_introduces_loop": "Add self-target\nDNAME",
}


def update_template(pair_id: str) -> str:
    value = pair_id.removeprefix("census_")
    value = re.sub(r"_c\d+$", "", value)
    if value not in UPDATE_KEYS:
        raise ValueError(f"Unknown update template: {pair_id}")
    return value


def load_data(rq1_run: Path, evidence: Path, finding_audit: Path) -> dict[str, object]:
    paths = {
        "RQ1 summary": rq1_run / "reports" / "summary.json",
        "RQ1 per-region reports": rq1_run / "reports" / "graphdns_per_region.csv",
        "RQ1 overlap": rq1_run / "reports" / "agreement_by_kind.csv",
        "RQ1 adjudication": (
            rq1_run
            / "reports"
            / "adjudication"
            / "all_difference_adjudication_summary.json"
        ),
        "RQ1 finding audit": finding_audit,
        "RQ2 ablation": evidence / "rq2_dname" / "summary.csv",
        "RQ2 scaling": evidence / "symbolic_scaling" / "symbolic_scaling.csv",
        "RQ3 updates": evidence / "rq3_updates_112" / "incremental_per_case.csv",
        "RQ3 update summary": evidence / "rq3_updates_112" / "incremental_summary.csv",
        "RQ3 BIND summary": evidence / "rq3_bind_updates" / "summary.json",
        "RQ4 repair summary": evidence / "rq4_repair_250" / "summary.json",
        "RQ4 repair detail": evidence / "rq4_repair_250" / "detailed_analysis.json",
        "RQ4 candidates": evidence / "rq4_repair_250" / "candidate_results.csv",
        "RQ4 regions": evidence / "rq4_repair_250" / "region_results.csv",
        "RQ5 grouping summary": evidence / "rq5_grouping_stress" / "summary.json",
        "RQ5 grouping groups": evidence / "rq5_grouping_stress" / "groups.csv",
        "RQ6 core summary": evidence / "rq6_groot_core" / "summary.json",
        "RQ6 core timings": evidence / "rq6_groot_core" / "per_region_timing.csv",
        "RQ6 scalability": evidence / "rq7_scalability" / "scalability.csv",
    }
    ensure_paths(paths)

    rq1_summary = read_json(paths["RQ1 summary"])
    rq1_regions = pd.read_csv(paths["RQ1 per-region reports"])
    rq1_overlap = pd.read_csv(paths["RQ1 overlap"])
    rq1_adjudication = read_json(paths["RQ1 adjudication"])
    finding_audit_df = pd.read_csv(paths["RQ1 finding audit"])

    kinds = ["DI", "LD", "MG", "CZD", "RL", "RB", "ML", "SR"]
    raw = rq1_summary["system_totals"]["graphdns"]["raw_reports_by_kind"]
    finding_types = pd.DataFrame(
        {
            "kind": kinds,
            "reports": [int(raw.get("STALE" if k == "SR" else k, 0)) for k in kinds],
        }
    )

    sr_rows = finding_audit_df[finding_audit_df["kind"] == "STALE"].copy()
    sr_causes = (
        sr_rows.groupby("evidence", as_index=False)
        .size()
        .rename(columns={"size": "reports"})
    )
    cause_names = {
        "record is at or below a parent-zone delegation cut": "Delegation cut",
        "record is below an ancestor DNAME": "Ancestor DNAME",
    }
    sr_causes["cause"] = sr_causes["evidence"].map(cause_names).fillna(
        sr_causes["evidence"]
    )

    affected_regions = rq1_regions[rq1_regions["total_bugs"] > 0].copy()
    affected_regions = affected_regions.sort_values("total_bugs", ascending=False)

    overlap = rq1_overlap[bool_series(rq1_overlap["shared_scope"])].copy()
    overlap["kind"] = pd.Categorical(overlap["kind"], kinds[:-1], ordered=True)
    overlap = overlap.sort_values("kind")

    diff_labels = {
        "scope_difference": "SR outside GRoot scope",
        "incomplete_server_view": "LD missing target view",
        "same_root_extra_report": "Same cause, extra report",
        "groot_report_unsupported_by_snapshot": "GRoot report lacks evidence",
        "graphdns_supported_groot_miss": "GraphDNS-only with evidence",
    }
    difference_audit = pd.DataFrame(
        [
            {
                "category": diff_labels[key],
                "entries": int(rq1_adjudication["by_category"].get(key, 0)),
            }
            for key in diff_labels
        ]
    )

    ablation = pd.read_csv(paths["RQ2 ablation"])
    scaling = pd.read_csv(paths["RQ2 scaling"])

    updates = pd.read_csv(paths["RQ3 updates"])
    updates["template"] = updates["pair_id"].map(update_template)
    updates["consistent_bool"] = bool_series(updates["consistent"])
    update_consistency = (
        updates.groupby(["template", "method"], as_index=False)
        .agg(total=("pair_id", "nunique"), consistent=("consistent_bool", "sum"))
    )
    update_consistency["agreement_pct"] = (
        100.0 * update_consistency["consistent"] / update_consistency["total"]
    )

    update_summary = pd.read_csv(paths["RQ3 update summary"])
    update_pr_rows = []
    for row in update_summary.itertuples(index=False):
        true_selected = int(row.consistent_pairs)
        selected = int(row.affected_queries)
        reference = int(row.update_pairs)
        update_pr_rows.extend(
            [
                {
                    "method": row.method,
                    "metric": "Precision",
                    "value": true_selected / selected if selected else 0.0,
                },
                {
                    "method": row.method,
                    "metric": "Recall",
                    "value": true_selected / reference if reference else 0.0,
                },
            ]
        )
    update_precision_recall = pd.DataFrame(update_pr_rows)
    update_errors = update_summary[
        ["method", "stale_paths", "missed_paths", "missed_reports"]
    ].copy()
    bind_update_summary = read_json(paths["RQ3 BIND summary"])

    repair_summary = read_json(paths["RQ4 repair summary"])
    repair_detail = read_json(paths["RQ4 repair detail"])
    candidates = pd.read_csv(paths["RQ4 candidates"])
    regions = pd.read_csv(paths["RQ4 regions"])
    candidates["accurate_bool"] = bool_series(candidates["accurate"])
    candidates["kind_display"] = candidates["kind"].replace({"STALE": "SR"})
    candidates["outcome"] = np.where(
        candidates["accurate_bool"],
        "Valid",
        np.where(
            candidates["new_severe_reports"].astype(int) > 0,
            "Introduced new vulnerability",
            "Did not fix original",
        ),
    )
    candidate_outcomes = (
        candidates.groupby(["kind_display", "outcome"], as_index=False)
        .size()
        .rename(columns={"size": "candidates"})
    )
    candidate_risk = (
        candidates.groupby("risk", as_index=False)
        .agg(candidates=("candidate_id", "size"), valid=("accurate_bool", "sum"))
    )
    candidate_risk["validity_pct"] = (
        100.0 * candidate_risk["valid"] / candidate_risk["candidates"]
    )

    equivalence = repair_summary["incremental_equivalence"]
    incremental_equivalence = pd.DataFrame(
        {
            "object": ["Reachable edges", "Complete paths", "Terminal states", "Reports"],
            "equivalence_pct": [
                100.0 * equivalence["reachable_edge_set_equivalence_rate"],
                100.0 * equivalence["path_set_equivalence_rate"],
                100.0 * equivalence["terminal_state_set_equivalence_rate"],
                100.0 * equivalence["report_set_equivalence_rate"],
            ],
            "candidates": [int(equivalence["evaluated_candidates"])] * 4,
        }
    )
    local_dfs = candidates[
        ["candidate_id", "region", "kind_display", "affected_paths"]
    ].rename(columns={"kind_display": "kind", "affected_paths": "dfs_executions"})

    grouping = repair_summary["root_cause_grouping"]
    grouping_stress_summary = read_json(paths["RQ5 grouping summary"])
    grouping_stress = pd.read_csv(paths["RQ5 grouping groups"])
    grouping_reduction = pd.DataFrame(
        {
            "workload": ["Census repairs", "Controlled stress test"],
            "reports": [
                int(grouping["repairable_reports"]),
                int(grouping_stress_summary["rb_reports"]),
            ],
            "root_cause_groups": [
                int(grouping["root_cause_groups"]),
                int(grouping_stress_summary["predicted_root_cause_groups"]),
            ],
        }
    )
    candidate_coverage = pd.DataFrame(
        {
            "status": ["At least one valid candidate", "No valid candidate"],
            "root_cause_groups": [
                int(grouping["groups_with_accurate_candidate"]),
                int(grouping["root_cause_groups"] - grouping["groups_with_accurate_candidate"]),
            ],
        }
    )

    core_summary = read_json(paths["RQ6 core summary"])
    core_timings = pd.read_csv(paths["RQ6 core timings"])
    core_runtime = pd.DataFrame(
        {
            "metric": ["Cumulative", "Median per region", "95th percentile"],
            "GraphDNS": [
                1000.0 * core_summary["semantic_total_seconds"]["sum"],
                1000.0 * core_summary["semantic_total_seconds"]["median"],
                1000.0 * core_summary["semantic_total_seconds"]["p95"],
            ],
            "GRoot": [
                1000.0 * core_summary["groot_core_seconds"]["sum"],
                1000.0 * core_summary["groot_core_seconds"]["median"],
                1000.0 * core_summary["groot_core_seconds"]["p95"],
            ],
        }
    )
    core_speedups = core_timings[
        ["region", "paired_core_ratio_groot_over_graphdns"]
    ].rename(columns={"paired_core_ratio_groot_over_graphdns": "speedup"})
    timing = repair_summary["timing"]
    validation_runtime = pd.DataFrame(
        {
            "method": ["Incremental", "Full rebuild"],
            "graph_seconds": [
                timing["incremental_graph_update_seconds"],
                timing["full_graph_build_seconds"],
            ],
            "traversal_seconds": [
                timing["incremental_local_traversal_seconds"],
                timing["full_traversal_seconds"],
            ],
        }
    )
    candidate_speedups = candidates[
        ["candidate_id", "region", "kind_display", "graph_traversal_speedup"]
    ].rename(
        columns={"kind_display": "kind", "graph_traversal_speedup": "speedup"}
    )
    scalability = pd.read_csv(paths["RQ6 scalability"])
    edge_node_ratios = rq1_regions.loc[
        rq1_regions["nodes"].astype(float) > 0,
        ["region_name", "nodes", "edges"],
    ].copy()
    edge_node_ratios["edge_node_ratio"] = (
        edge_node_ratios["edges"].astype(float)
        / edge_node_ratios["nodes"].astype(float)
    )

    return {
        "rq1_summary": rq1_summary,
        "finding_types": finding_types,
        "sr_causes": sr_causes[["cause", "reports"]],
        "affected_regions": affected_regions,
        "overlap": overlap,
        "difference_audit": difference_audit,
        "ablation": ablation,
        "scaling": scaling,
        "update_consistency": update_consistency,
        "update_precision_recall": update_precision_recall,
        "update_errors": update_errors,
        "bind_update_summary": bind_update_summary,
        "repair_summary": repair_summary,
        "repair_detail": repair_detail,
        "candidates": candidates,
        "regions": regions,
        "candidate_outcomes": candidate_outcomes,
        "candidate_risk": candidate_risk,
        "incremental_equivalence": incremental_equivalence,
        "local_dfs": local_dfs,
        "grouping_reduction": grouping_reduction,
        "grouping_stress_summary": grouping_stress_summary,
        "grouping_stress": grouping_stress,
        "candidate_coverage": candidate_coverage,
        "core_runtime": core_runtime,
        "core_speedups": core_speedups,
        "validation_runtime": validation_runtime,
        "candidate_speedups": candidate_speedups,
        "scalability": scalability,
        "edge_node_ratios": edge_node_ratios,
    }


def load_source_data(source_dir: Path) -> dict[str, object]:
    """Load the frozen, non-sensitive tables committed with the artifact."""
    paths = {name: source_dir / name for name in CURRENT_SOURCE_FILES}
    ensure_paths({name: path for name, path in sorted(paths.items())})

    def csv(name: str) -> pd.DataFrame:
        return pd.read_csv(paths[name])

    affected_regions = csv("rq1_region_findings.csv").rename(
        columns={"SR": "STALE"}
    )
    return {
        "finding_types": csv("rq1_finding_types.csv"),
        "sr_causes": csv("rq1_shadow_causes.csv"),
        "affected_regions": affected_regions,
        "overlap": csv("rq1_groot_overlap.csv"),
        "difference_audit": csv("rq1_difference_audit.csv"),
        "ablation": csv("rq2_symbolic_ablation.csv"),
        "scaling": csv("rq2_symbolic_scaling.csv"),
        "update_consistency": csv("rq3_update_consistency.csv"),
        "update_precision_recall": csv("rq3_update_precision_recall.csv"),
        "update_errors": csv("rq3_update_errors.csv"),
        "incremental_equivalence": csv("rq4_incremental_equivalence.csv"),
        "local_dfs": csv("rq4_local_dfs_executions.csv"),
        "grouping_reduction": csv("rq5_grouping_reduction.csv"),
        "grouping_stress": csv("rq5_grouping_stress.csv"),
        "candidate_coverage": csv("rq5_candidate_coverage.csv"),
        "candidate_outcomes": csv("rq5_candidate_outcomes.csv"),
        "candidate_risk": csv("rq5_candidate_risk.csv"),
        "core_runtime": csv("rq6_core_runtime.csv"),
        "core_speedups": csv("rq6_core_speedups.csv"),
        "validation_runtime": csv("rq6_validation_runtime.csv"),
        "candidate_speedups": csv("rq6_candidate_speedups.csv"),
        "scalability": csv("rq6_scalability.csv"),
        "edge_node_ratios": csv("rq6_edge_node_ratios.csv"),
    }


def write_source_data(data: dict[str, object], source_dir: Path) -> None:
    source_dir.mkdir(parents=True, exist_ok=True)
    data["finding_types"].to_csv(source_dir / "rq1_finding_types.csv", index=False)
    data["sr_causes"].to_csv(source_dir / "rq1_shadow_causes.csv", index=False)
    region_columns = [
        "region_name", "DI", "LD", "MG", "CZD", "RL", "RB", "ML", "STALE", "total_bugs"
    ]
    data["affected_regions"][region_columns].rename(columns={"STALE": "SR"}).to_csv(
        source_dir / "rq1_region_findings.csv", index=False
    )
    data["overlap"].to_csv(source_dir / "rq1_groot_overlap.csv", index=False)
    data["difference_audit"].to_csv(
        source_dir / "rq1_difference_audit.csv", index=False
    )
    data["ablation"].to_csv(source_dir / "rq2_symbolic_ablation.csv", index=False)
    data["scaling"].to_csv(source_dir / "rq2_symbolic_scaling.csv", index=False)
    data["update_consistency"].to_csv(
        source_dir / "rq3_update_consistency.csv", index=False
    )
    data["update_precision_recall"].to_csv(
        source_dir / "rq3_update_precision_recall.csv", index=False
    )
    data["update_errors"].to_csv(source_dir / "rq3_update_errors.csv", index=False)
    data["incremental_equivalence"].to_csv(
        source_dir / "rq4_incremental_equivalence.csv", index=False
    )
    data["local_dfs"].to_csv(
        source_dir / "rq4_local_dfs_executions.csv", index=False
    )
    data["grouping_reduction"].to_csv(
        source_dir / "rq5_grouping_reduction.csv", index=False
    )
    data["grouping_stress"].to_csv(
        source_dir / "rq5_grouping_stress.csv", index=False
    )
    data["candidate_coverage"].to_csv(
        source_dir / "rq5_candidate_coverage.csv", index=False
    )
    data["candidate_outcomes"].to_csv(
        source_dir / "rq5_candidate_outcomes.csv", index=False
    )
    data["candidate_risk"].to_csv(
        source_dir / "rq5_candidate_risk.csv", index=False
    )
    data["core_runtime"].to_csv(source_dir / "rq6_core_runtime.csv", index=False)
    data["core_speedups"].to_csv(
        source_dir / "rq6_core_speedups.csv", index=False
    )
    data["validation_runtime"].to_csv(
        source_dir / "rq6_validation_runtime.csv", index=False
    )
    data["candidate_speedups"].to_csv(
        source_dir / "rq6_candidate_speedups.csv", index=False
    )
    data["scalability"].to_csv(
        source_dir / "rq6_scalability.csv", index=False
    )
    data["edge_node_ratios"].to_csv(
        source_dir / "rq6_edge_node_ratios.csv", index=False
    )


def plot_rq1(data: dict[str, object], out_dir: Path) -> None:
    types = data["finding_types"]
    total = int(types["reports"].sum())
    sr = int(types.loc[types["kind"] == "SR", "reports"].iloc[0])
    other = total - sr

    fig, ax = plt.subplots(figsize=(SINGLE_WIDTH, 2.45))
    values = [sr, other]
    bars = ax.bar(
        ["Shadow records", "Path vulnerabilities"],
        values,
        color=[COLORS["green"], COLORS["blue"]],
        width=0.62,
    )
    annotate_bars(ax, bars, values)
    ax.set_ylabel("Reports")
    ax.set_ylim(0, max(values) * 1.18)
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq1_detection_overview", out_dir)

    fig, ax = plt.subplots(figsize=(FULL_WIDTH, 2.65))
    values = types["reports"].to_numpy(dtype=float)
    bars = ax.bar(
        types["kind"],
        values,
        color=[BUG_COLORS[k] for k in types["kind"]],
        width=0.68,
    )
    annotate_bars(ax, bars, values)
    ax.set_ylabel("Reports")
    ax.set_ylim(0, max(values) * 1.18)
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq1_finding_type_counts", out_dir)

    causes = data["sr_causes"].sort_values("reports", ascending=False)
    fig, ax = plt.subplots(figsize=(SINGLE_WIDTH, 2.45))
    values = causes["reports"].to_numpy(dtype=float)
    bars = ax.bar(causes["cause"], values, color=[COLORS["green"], COLORS["teal"]])
    annotate_bars(ax, bars, values)
    ax.set_ylabel("Shadow records")
    ax.set_ylim(0, max(values) * 1.18)
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq1_shadow_record_causes", out_dir)

    regions = data["affected_regions"].copy()
    n = len(regions)
    fig, ax = plt.subplots(figsize=ZONE_DISTRIBUTION_FIGSIZE)
    x = np.arange(n)
    left = np.zeros(n, dtype=float)
    region_kinds = ["DI", "LD", "MG", "CZD", "RL", "RB", "ML", "STALE"]
    for kind in region_kinds:
        values = regions[kind].to_numpy(dtype=float)
        if not np.any(values):
            continue
        label = "SR" if kind == "STALE" else kind
        ax.bar(
            x,
            values,
            bottom=left,
            width=0.82,
            color=BUG_COLORS[label],
            label=label,
        )
        left += values
    ax.set_xticks(x)
    ax.set_xticklabels(
        regions["region_name"].astype(str),
        rotation=90,
        ha="center",
        va="top",
        fontsize=4.6,
    )
    ax.tick_params(axis="x", pad=1.0)
    ax.set_yscale("symlog", linthresh=2)
    ax.set_ylabel("Anomaly reports")
    ax.legend(ncol=5, loc="upper right")
    y_grid(ax)
    fig.tight_layout(pad=0.35)
    save_figure(
        fig,
        "rq1_region_distribution_all",
        out_dir,
        figsize=ZONE_DISTRIBUTION_FIGSIZE,
    )

    overlap = data["overlap"]
    x = np.arange(len(overlap))
    width = 0.24
    series = [
        ("GraphDNS", "graphdns_unique_cases", COLORS["blue"]),
        ("GRoot", "groot_unique_cases", COLORS["orange"]),
        ("Shared", "intersection", COLORS["green"]),
    ]
    fig, ax = plt.subplots(figsize=(FULL_WIDTH, 2.95))
    for index, (label, column, color) in enumerate(series):
        values = overlap[column].to_numpy(dtype=float)
        bars = ax.bar(x + (index - 1) * width, values, width, color=color, label=label)
        annotate_bars(ax, bars, values, fontsize=5.2)
    ax.set_xticks(x, overlap["kind"].astype(str))
    ax.set_ylabel("Deduplicated reports (symlog scale)")
    ax.set_yscale("symlog", linthresh=1)
    ax.set_ylim(0, max(overlap["groot_unique_cases"].max(), 1) * 3.0)
    ax.legend(ncol=3, loc="upper left")
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq1_groot_overlap_by_type", out_dir)

    audit = data["difference_audit"].sort_values("entries", ascending=True)
    fig, ax = plt.subplots(figsize=(FULL_WIDTH, 2.8))
    values = audit["entries"].to_numpy(dtype=float)
    bars = ax.barh(audit["category"], values, color=COLORS["blue"], height=0.62)
    annotate_barh(ax, bars, values)
    ax.set_xscale("log")
    ax.set_xlabel("Difference entries (log scale)")
    ax.set_xlim(10, max(values) * 2.2)
    x_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq1_difference_audit", out_dir)


def plot_rq2(data: dict[str, object], out_dir: Path) -> None:
    df = data["ablation"].copy()
    labels = [display_method(v) for v in df["method"]]
    x = np.arange(len(df))
    width = 0.34

    fig, ax = plt.subplots(figsize=(FULL_WIDTH, 2.8))
    nodes = df["nodes"].to_numpy(dtype=float)
    edges = df["edges"].to_numpy(dtype=float)
    bars1 = ax.bar(x - width / 2, nodes, width, color=COLORS["blue"], label="Nodes")
    bars2 = ax.bar(x + width / 2, edges, width, color=COLORS["teal"], label="Edges")
    annotate_bars(ax, bars1, nodes)
    annotate_bars(ax, bars2, edges)
    ax.set_xticks(x, labels)
    ax.set_ylabel("Graph elements")
    ax.set_ylim(0, max(nodes.max(), edges.max()) * 1.22)
    ax.legend(ncol=2, loc="upper right")
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq2_graph_size_ablation", out_dir)

    fig, ax = plt.subplots(figsize=(FULL_WIDTH, 2.55))
    values = df["false_paths"].to_numpy(dtype=float)
    bars = ax.bar(x, values, color=[METHOD_COLORS[m] for m in df["method"]], width=0.65)
    annotate_bars(ax, bars, values)
    ax.set_xticks(x, labels)
    ax.set_ylabel("Pseudo paths")
    ax.set_ylim(0, max(values) * 1.18)
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq2_pseudo_path_ablation", out_dir)

    fig, ax = plt.subplots(figsize=(FULL_WIDTH, 2.75))
    precision = 100.0 * df["precision"].to_numpy(dtype=float)
    recall = 100.0 * df["recall"].to_numpy(dtype=float)
    bars1 = ax.bar(x - width / 2, precision, width, color=COLORS["blue"], label="Precision")
    bars2 = ax.bar(x + width / 2, recall, width, color=COLORS["green"], label="Recall")
    annotate_bars(ax, bars1, precision, formatter=lambda v: f"{v:.1f}%")
    annotate_bars(ax, bars2, recall, formatter=lambda v: f"{v:.1f}%")
    ax.set_xticks(x, labels)
    ax.set_ylabel("Path metric (%)")
    ax.set_ylim(0, 112)
    ax.legend(ncol=2, loc="lower right")
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq2_path_precision_recall", out_dir)

    fig, ax = plt.subplots(figsize=(FULL_WIDTH, 2.55))
    values = df["false_vulnerabilities"].to_numpy(dtype=float)
    bars = ax.bar(x, values, color=[METHOD_COLORS[m] for m in df["method"]], width=0.65)
    annotate_bars(ax, bars, values)
    ax.set_xticks(x, labels)
    ax.set_ylabel("False vulnerability reports")
    ax.set_ylim(0, max(values.max() * 1.25, 1))
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq2_false_finding_ablation", out_dir)

    scaling = data["scaling"]
    for concrete_column, srag_column, ylabel, object_name, stem in [
        (
            "concrete_nodes",
            "srag_nodes",
            "Graph nodes",
            "node",
            "rq2_symbolic_scaling_nodes",
        ),
        (
            "concrete_edges",
            "srag_edges",
            "Graph edges",
            "edge",
            "rq2_symbolic_scaling_edges",
        ),
    ]:
        fig, ax = plt.subplots(figsize=(SINGLE_WIDTH, 2.8))
        ax.plot(
            scaling["k"],
            scaling[concrete_column],
            marker="o",
            markersize=3.4,
            linewidth=1.2,
            color=COLORS["gray"],
            label="Concrete",
        )
        ax.plot(
            scaling["k"],
            scaling[srag_column],
            marker="s",
            markersize=3.2,
            linewidth=1.2,
            linestyle="--",
            color=COLORS["blue"],
            label="Full GraphDNS",
        )
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_xlabel("Labels enumerated per symbolic position, k")
        ax.set_ylabel(ylabel)
        ax.set_xticks(scaling["k"], [str(v) for v in scaling["k"]])
        ax.set_xlim(0.85, 90)
        graphdns_value = float(scaling[srag_column].iloc[-1])
        concrete_value = float(scaling[concrete_column].iloc[-1])
        ax.set_ylim(graphdns_value * 0.72, concrete_value * 1.85)
        ax.legend(loc="upper left")
        y_grid(ax)
        fig.tight_layout()
        save_figure(fig, stem, out_dir)


def plot_rq3(data: dict[str, object], out_dir: Path) -> None:
    consistency = data["update_consistency"]
    x = np.arange(len(UPDATE_KEYS))
    width = 0.34
    methods = ["VeriDNS-RSG reproduction", "Full GraphDNS"]
    fig, ax = plt.subplots(figsize=(FULL_WIDTH, 3.05))
    for idx, method in enumerate(methods):
        subset = consistency[consistency["method"] == method].set_index("template")
        values = np.array([subset.loc[key, "agreement_pct"] for key in UPDATE_KEYS])
        bars = ax.bar(
            x + (idx - 0.5) * width,
            values,
            width,
            color=METHOD_COLORS[method],
            label=display_method(method).replace("\n", " "),
        )
        annotate_bars(ax, bars, values, formatter=lambda v: f"{v:.0f}%", fontsize=5.3)
    ax.set_xticks(x, [UPDATE_LABELS[key] for key in UPDATE_KEYS])
    ax.set_ylabel("Agreement with full rebuild (%)")
    ax.set_ylim(0, 115)
    ax.legend(ncol=2, loc="lower left")
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq3_update_consistency", out_dir)

    pr = data["update_precision_recall"]
    metrics = ["Precision", "Recall"]
    x = np.arange(len(metrics))
    fig, ax = plt.subplots(figsize=(SINGLE_WIDTH, 2.6))
    for idx, method in enumerate(methods):
        subset = pr[pr["method"] == method].set_index("metric")
        values = 100.0 * np.array([subset.loc[m, "value"] for m in metrics])
        bars = ax.bar(
            x + (idx - 0.5) * width,
            values,
            width,
            color=METHOD_COLORS[method],
            label=display_method(method).replace("\n", " "),
        )
        annotate_bars(ax, bars, values, formatter=lambda v: f"{v:.1f}%", fontsize=5.5)
    ax.set_xticks(x, metrics)
    ax.set_ylabel("Affected-query metric (%)")
    ax.set_ylim(0, 112)
    ax.legend(loc="lower left")
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq3_update_precision_recall", out_dir)

    errors = data["update_errors"]
    error_columns = ["stale_paths", "missed_paths", "missed_reports"]
    error_labels = ["Stale paths", "Missed paths", "Missed reports"]
    x = np.arange(len(error_columns))
    fig, ax = plt.subplots(figsize=(SINGLE_WIDTH, 2.6))
    for idx, method in enumerate(methods):
        row = errors[errors["method"] == method].iloc[0]
        values = np.array([row[column] for column in error_columns], dtype=float)
        bars = ax.bar(
            x + (idx - 0.5) * width,
            values,
            width,
            color=METHOD_COLORS[method],
            label=display_method(method).replace("\n", " "),
        )
        annotate_bars(ax, bars, values, fontsize=5.5)
    ax.set_xticks(x, error_labels)
    ax.set_ylabel("Errors across 112 updates")
    ax.set_ylim(0, max(errors[error_columns].to_numpy().max() * 1.2, 1))
    ax.legend(loc="upper right")
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq3_update_errors", out_dir)


def plot_rq4(data: dict[str, object], out_dir: Path) -> None:
    equivalence = data["incremental_equivalence"]
    fig, ax = plt.subplots(figsize=(FULL_WIDTH, 2.55))
    values = equivalence["equivalence_pct"].to_numpy(dtype=float)
    bars = ax.bar(equivalence["object"], values, color=COLORS["blue"], width=0.62)
    annotate_bars(ax, bars, values, formatter=lambda v: f"{v:.0f}%")
    ax.set_ylabel("Incremental/full equivalence (%)")
    ax.set_ylim(0, 112)
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq4_incremental_equivalence", out_dir)

    values = data["local_dfs"]["dfs_executions"].to_numpy(dtype=float)
    x, y = ecdf(values)
    q1 = float(np.quantile(values, 0.25))
    q3 = float(np.quantile(values, 0.75))
    fig, ax = plt.subplots(figsize=(SINGLE_WIDTH, 2.65))
    ax.step(x, y, where="post", color=COLORS["blue"])
    ax.axvspan(q1, q3, color=COLORS["blue"], alpha=0.12, linewidth=0)
    ax.set_xscale("log")
    ax.set_xlabel("Local DFS traversals per candidate")
    ax.set_ylabel("CDF")
    ax.set_ylim(0, 1.02)
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq4_local_dfs_distribution", out_dir)

    local_dfs = data["local_dfs"]
    kind_order = ["DI", "MG", "RB", "RL", "SR"]
    fig, ax = plt.subplots(figsize=(FULL_WIDTH, 2.9))
    rng = np.random.default_rng(20260729)
    for index, kind in enumerate(kind_order):
        subset = local_dfs.loc[local_dfs["kind"] == kind, "dfs_executions"].to_numpy(
            dtype=float
        )
        jitter = rng.uniform(-0.16, 0.16, size=len(subset))
        ax.scatter(
            np.full(len(subset), index) + jitter,
            subset,
            s=8,
            color=BUG_COLORS[kind],
            alpha=0.28,
            linewidths=0,
            rasterized=True,
        )
        lower = float(np.quantile(subset, 0.25))
        center = float(np.median(subset))
        upper = float(np.quantile(subset, 0.75))
        ax.vlines(
            index,
            lower,
            upper,
            color=BUG_COLORS[kind],
            linewidth=7,
            alpha=0.75,
            zorder=3,
        )
        ax.hlines(
            center,
            index - 0.14,
            index + 0.14,
            color=COLORS["dark"],
            linewidth=1.4,
            zorder=4,
        )
    ax.set_yscale("log")
    ax.set_xticks(np.arange(len(kind_order)), kind_order)
    ax.set_ylabel("Local DFS traversals per candidate")
    ax.set_ylim(0.75, 230)
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq4_local_dfs_by_kind", out_dir)


def plot_rq5(data: dict[str, object], out_dir: Path) -> None:
    grouping = data["grouping_reduction"]
    x = np.arange(len(grouping))
    width = 0.34
    fig, ax = plt.subplots(figsize=(SINGLE_WIDTH, 2.65))
    reports = grouping["reports"].to_numpy(dtype=float)
    groups = grouping["root_cause_groups"].to_numpy(dtype=float)
    bars1 = ax.bar(x - width / 2, reports, width, color=COLORS["gray"], label="Reports")
    bars2 = ax.bar(x + width / 2, groups, width, color=COLORS["blue"], label="Root-cause groups")
    annotate_bars(ax, bars1, reports, fontsize=5.5)
    annotate_bars(ax, bars2, groups, fontsize=5.5)
    ax.set_xticks(x, ["Census\nrepairs", "Controlled\nstress test"])
    ax.set_ylabel("Count")
    ax.set_ylim(0, max(reports) * 1.2)
    ax.legend(ncol=2, loc="upper left")
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq5_grouping_reduction", out_dir)

    stress = data["grouping_stress"]
    distribution = (
        stress.groupby("expected_witnesses", as_index=False)
        .size()
        .rename(columns={"size": "root_cause_groups"})
    )
    fig, ax = plt.subplots(figsize=(SINGLE_WIDTH, 2.55))
    values = distribution["root_cause_groups"].to_numpy(dtype=float)
    bars = ax.bar(
        distribution["expected_witnesses"].astype(str),
        values,
        color=COLORS["blue"],
        width=0.62,
    )
    annotate_bars(ax, bars, values)
    ax.set_xlabel("Reports generated per root cause")
    ax.set_ylabel("Root causes")
    ax.set_ylim(0, max(values) * 1.35)
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq5_grouping_stress", out_dir)

    coverage = data["candidate_coverage"]
    fig, ax = plt.subplots(figsize=(SINGLE_WIDTH, 2.45))
    values = coverage["root_cause_groups"].to_numpy(dtype=float)
    bars = ax.bar(
        ["With valid\ncandidate", "Without valid\ncandidate"],
        values,
        color=[COLORS["green"], COLORS["red"]],
        width=0.62,
    )
    annotate_bars(ax, bars, values)
    ax.set_ylabel("Root-cause groups")
    ax.set_ylim(0, max(values) * 1.18)
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq5_candidate_coverage", out_dir)

    outcomes = data["candidate_outcomes"]
    kind_order = ["DI", "MG", "RB", "RL", "SR"]
    x = np.arange(len(kind_order))
    valid = (
        outcomes[outcomes["outcome"] == "Valid"]
        .set_index("kind_display")["candidates"]
        .reindex(kind_order, fill_value=0)
        .to_numpy(dtype=float)
    )
    generated = (
        outcomes.groupby("kind_display")["candidates"]
        .sum()
        .reindex(kind_order, fill_value=0)
        .to_numpy(dtype=float)
    )
    width = 0.34
    fig, ax = plt.subplots(figsize=(FULL_WIDTH, 2.75))
    bars1 = ax.bar(x - width / 2, generated, width, color=COLORS["gray"], label="Generated")
    bars2 = ax.bar(x + width / 2, valid, width, color=COLORS["green"], label="Valid")
    annotate_bars(ax, bars1, generated)
    annotate_bars(ax, bars2, valid)
    ax.set_xticks(x, kind_order)
    ax.set_ylabel("Repair candidates")
    ax.set_ylim(0, max(generated) * 1.2)
    ax.legend(ncol=2, loc="upper left")
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq5_repair_candidate_validity", out_dir)

    did_not_fix = (
        outcomes[outcomes["outcome"] == "Did not fix original"]
        .set_index("kind_display")["candidates"]
        .reindex(kind_order, fill_value=0)
        .to_numpy(dtype=float)
    )
    introduced = (
        outcomes[outcomes["outcome"] == "Introduced new vulnerability"]
        .set_index("kind_display")["candidates"]
        .reindex(kind_order, fill_value=0)
        .to_numpy(dtype=float)
    )
    fig, ax = plt.subplots(figsize=(FULL_WIDTH, 2.65))
    bars1 = ax.bar(x - width / 2, did_not_fix, width, color=COLORS["orange"], label="Did not fix original")
    bars2 = ax.bar(x + width / 2, introduced, width, color=COLORS["red"], label="Introduced new vulnerability")
    annotate_bars(ax, bars1, did_not_fix)
    annotate_bars(ax, bars2, introduced)
    ax.set_xticks(x, kind_order)
    ax.set_ylabel("Rejected candidates")
    ax.set_ylim(0, max(did_not_fix.max(), introduced.max()) * 1.25)
    ax.legend(ncol=2, loc="upper left")
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq5_repair_rejection_reasons", out_dir)

    risk = data["candidate_risk"].copy()
    risk_order = ["low", "medium", "high"]
    risk["risk"] = pd.Categorical(risk["risk"], risk_order, ordered=True)
    risk = risk.sort_values("risk")
    fig, ax = plt.subplots(figsize=(SINGLE_WIDTH, 2.55))
    values = risk["validity_pct"].to_numpy(dtype=float)
    bars = ax.bar(
        [str(v).title() for v in risk["risk"]],
        values,
        color=[COLORS["green"], COLORS["orange"], COLORS["red"]],
        width=0.62,
    )
    ax.set_xlabel("Candidate risk class")
    ax.set_ylabel("Validation pass rate (%)")
    ax.set_ylim(0, 112)
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq5_candidate_validity_by_risk", out_dir)


def plot_rq6(data: dict[str, object], out_dir: Path) -> None:
    runtime = data["core_runtime"]
    x = np.arange(len(runtime))
    width = 0.34
    fig, ax = plt.subplots(figsize=(FULL_WIDTH, 2.85))
    graphdns = runtime["GraphDNS"].to_numpy(dtype=float)
    groot = runtime["GRoot"].to_numpy(dtype=float)
    bars1 = ax.bar(x - width / 2, graphdns, width, color=COLORS["blue"], label="GraphDNS")
    bars2 = ax.bar(x + width / 2, groot, width, color=COLORS["orange"], label="GRoot")
    annotate_bars(ax, bars1, graphdns, formatter=format_decimal, fontsize=5.5)
    annotate_bars(ax, bars2, groot, formatter=format_decimal, fontsize=5.5)
    ax.set_xticks(x, runtime["metric"])
    ax.set_yscale("log")
    ax.set_ylabel("Core analysis time (ms, log scale)")
    ax.legend(ncol=2, loc="upper left")
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq6_core_runtime", out_dir)

    values = data["core_speedups"]["speedup"].to_numpy(dtype=float)
    x_ecdf, y_ecdf = ecdf(values)
    fig, ax = plt.subplots(figsize=(SINGLE_WIDTH, 2.65))
    ax.step(x_ecdf, y_ecdf, where="post", color=COLORS["blue"])
    ax.set_xscale("log")
    ax.set_xlabel("Per-region speedup (GRoot / GraphDNS)")
    ax.set_ylabel("CDF")
    ax.set_ylim(0, 1.02)
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq6_core_speedup_distribution", out_dir)

    phases = data["validation_runtime"]
    fig, ax = plt.subplots(figsize=(SINGLE_WIDTH, 2.7))
    graph = phases["graph_seconds"].to_numpy(dtype=float)
    traversal = phases["traversal_seconds"].to_numpy(dtype=float)
    bars1 = ax.bar(phases["method"], graph, color=COLORS["blue"], label="Graph update/build")
    bars2 = ax.bar(
        phases["method"],
        traversal,
        bottom=graph,
        color=COLORS["teal"],
        label="DFS traversal",
    )
    totals = graph + traversal
    ax.set_ylabel("Cumulative time for 1,019 candidates (s)")
    ax.set_ylim(0, max(totals) * 1.2)
    ax.legend(loc="upper left")
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq6_validation_runtime", out_dir)

    values = data["candidate_speedups"]["speedup"].to_numpy(dtype=float)
    x_ecdf, y_ecdf = ecdf(values)
    q1 = float(np.quantile(values, 0.25))
    q3 = float(np.quantile(values, 0.75))
    fig, ax = plt.subplots(figsize=(SINGLE_WIDTH, 2.8))
    ax.step(x_ecdf, y_ecdf, where="post", color=COLORS["blue"])
    ax.axvspan(q1, q3, color=COLORS["blue"], alpha=0.12, linewidth=0)
    ax.axvline(1.0, color=COLORS["gray"], linestyle=":", linewidth=0.9)
    ax.set_xscale("log")
    ax.set_xlabel("Per-candidate speedup (full / incremental)")
    ax.set_ylabel("CDF")
    ax.set_ylim(0, 1.02)
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq6_candidate_speedup_distribution", out_dir)

    scalability = data["scalability"].copy()
    successful = scalability[
        scalability["status"].astype(str).str.lower() == "ok"
    ].sort_values("target_regions")
    failed = scalability[
        scalability["status"].astype(str).str.lower() == "oom"
    ].sort_values("target_regions")
    region_ticks = successful["target_regions"].to_numpy(dtype=float)
    region_labels = [
        f"{int(value / 1000)}K" if value < 1_000_000 else f"{value / 1_000_000:.1f}M"
        for value in region_ticks
    ]

    fig, ax = plt.subplots(figsize=(FULL_WIDTH, 2.75))
    ax.plot(
        successful["target_regions"],
        successful["graph_build_seconds"],
        marker="o",
        markersize=3.8,
        color=COLORS["blue"],
        label="Graph construction",
    )
    ax.plot(
        successful["target_regions"],
        successful["traverse_dfs_seconds"],
        marker="s",
        markersize=3.6,
        color=COLORS["orange"],
        label="Path traversal",
    )
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xticks(region_ticks, region_labels)
    ax.tick_params(axis="x", labelrotation=0)
    ax.set_xlabel("Census regions")
    ax.set_ylabel("Time (s, log scale)")
    ax.legend(ncol=2, loc="upper left")
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq6_scalability_runtime", out_dir)

    fig, ax = plt.subplots(figsize=(FULL_WIDTH, 2.75))
    ax.plot(
        successful["target_regions"],
        successful["nodes"],
        marker="o",
        markersize=3.8,
        color=COLORS["blue"],
        label="Nodes",
    )
    ax.plot(
        successful["target_regions"],
        successful["edges"],
        marker="s",
        markersize=3.6,
        color=COLORS["teal"],
        label="Edges",
    )
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xticks(region_ticks, region_labels)
    ax.tick_params(axis="x", labelrotation=0)
    ax.set_xlabel("Census regions")
    ax.set_ylabel("Graph objects (log scale)")
    ax.legend(ncol=2, loc="upper left")
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq6_scalability_graph_size", out_dir)

    fig, ax = plt.subplots(figsize=(FULL_WIDTH, 2.75))
    successful_memory_gib = (
        successful["semantic_peak_rss_mb"].to_numpy(dtype=float) / 1024.0
    )
    ax.plot(
        successful["target_regions"],
        successful_memory_gib,
        marker="o",
        markersize=3.8,
        color=COLORS["blue"],
        label="Completed run",
    )
    memory_ticks = list(region_ticks)
    memory_labels = list(region_labels)
    if not failed.empty:
        failed_x = failed["target_regions"].to_numpy(dtype=float)
        failed_y = failed["semantic_peak_rss_mb"].to_numpy(dtype=float) / 1024.0
        ax.scatter(
            failed_x,
            failed_y,
            marker="X",
            s=34,
            color=COLORS["red"],
            label="Memory limit reached",
            zorder=4,
        )
        memory_ticks.extend(failed_x.tolist())
        memory_labels.extend(
            [f"{int(value / 1000)}K" for value in failed_x]
        )
    tick_order = np.argsort(np.asarray(memory_ticks, dtype=float))
    ax.set_xscale("log")
    ax.set_xticks(
        np.asarray(memory_ticks, dtype=float)[tick_order],
        np.asarray(memory_labels, dtype=object)[tick_order],
    )
    ax.tick_params(axis="x", labelrotation=0)
    ax.set_xlabel("Census regions")
    ax.set_ylabel("Peak analysis RSS (GiB)")
    ax.set_ylim(bottom=0)
    ax.legend(ncol=2, loc="upper left")
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq6_scalability_memory", out_dir)

    ratios = data["edge_node_ratios"]["edge_node_ratio"].to_numpy(dtype=float)
    ratio_x, ratio_y = ecdf(ratios)
    fig, ax = plt.subplots(figsize=(SINGLE_WIDTH, 2.65))
    ax.step(ratio_x, ratio_y, where="post", color=COLORS["blue"])
    ax.set_xlabel("Edges per node")
    ax.set_ylabel("CDF")
    ax.set_xlim(left=0)
    ax.set_ylim(0, 1.02)
    y_grid(ax)
    fig.tight_layout()
    save_figure(fig, "rq6_edge_node_ratio_distribution", out_dir)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate all standalone figures for the current GraphDNS evaluation"
    )
    parser.add_argument("--rq1-run", type=Path, default=DEFAULT_RQ1_RUN)
    parser.add_argument("--evidence-dir", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--finding-audit", type=Path, default=DEFAULT_FINDING_AUDIT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--source-dir", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument(
        "--refresh-source-data",
        action="store_true",
        help="rebuild frozen CSV tables from raw experiment run directories",
    )
    args = parser.parse_args()

    configure_style()
    out_dir = args.output_dir.resolve()
    source_dir = args.source_dir.resolve()
    clean_generated_files(out_dir, source_dir)
    if args.refresh_source_data:
        data = load_data(
            args.rq1_run.resolve(),
            args.evidence_dir.resolve(),
            args.finding_audit.resolve(),
        )
        write_source_data(data, source_dir)
    else:
        data = load_source_data(source_dir)
    plot_rq1(data, out_dir)
    plot_rq2(data, out_dir)
    plot_rq3(data, out_dir)
    plot_rq4(data, out_dir)
    plot_rq5(data, out_dir)
    plot_rq6(data, out_dir)
    print(f"[done] generated {len(CURRENT_STEMS)} standalone figures in {out_dir}")
    print(f"[source] {source_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
