#!/usr/bin/env python3
"""Create publication-ready figures for Experiment 04."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.sans-serif"] = ["Arial", "DejaVu Sans", "Liberation Sans"]
plt.rcParams["svg.fonttype"] = "none"
plt.rcParams["pdf.fonttype"] = 42
plt.rcParams["font.size"] = 7
plt.rcParams["axes.linewidth"] = 0.8
plt.rcParams["axes.spines.top"] = False
plt.rcParams["axes.spines.right"] = False
plt.rcParams["xtick.major.width"] = 0.7
plt.rcParams["ytick.major.width"] = 0.7


GENERATED_COLOR = "#9CB6D8"
VALID_COLOR = "#2F6FB0"
GRID_COLOR = "#D9D9D9"
TEXT_COLOR = "#222222"
KIND_ORDER = ("DI", "MG", "RB", "RL", "STALE")
RISK_ORDER = ("low", "medium", "high")
DISPLAY_KIND = {"STALE": "SR"}
DISPLAY_RISK = {"low": "Low", "medium": "Medium", "high": "High"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plot repair grouping and candidate-validation results."
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        required=True,
        help="Experiment 04 run directory containing summary.json.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory for figures, source data, and figure notes.",
    )
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def save_figure(fig: plt.Figure, output_base: Path) -> None:
    output_base.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_base.with_suffix(".svg"), bbox_inches="tight")
    fig.savefig(output_base.with_suffix(".pdf"), bbox_inches="tight")
    fig.savefig(output_base.with_suffix(".png"), dpi=600, bbox_inches="tight")
    fig.savefig(
        output_base.with_suffix(".tiff"),
        dpi=600,
        bbox_inches="tight",
        pil_kwargs={"compression": "tiff_lzw"},
    )
    plt.close(fig)


def style_axis(ax: plt.Axes, ylabel: str) -> None:
    ax.set_ylabel(ylabel)
    ax.grid(axis="y", color=GRID_COLOR, linewidth=0.55, zorder=0)
    ax.tick_params(axis="x", length=0, pad=4)
    ax.set_axisbelow(True)


def label_count(
    ax: plt.Axes,
    x: float,
    value: int,
    offset: float,
    suffix: str = "",
) -> None:
    ax.text(
        x,
        value + offset,
        f"{value:,}{suffix}",
        ha="center",
        va="bottom",
        fontsize=6.2,
        color=TEXT_COLOR,
    )


def candidate_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    by_kind = summary["candidate_accuracy"]["by_kind"]
    rows: list[dict[str, Any]] = []
    for kind in KIND_ORDER:
        if kind not in by_kind:
            continue
        item = by_kind[kind]
        generated = int(item["generated_candidates"])
        valid = int(item["accurate_candidates"])
        rows.append(
            {
                "kind": DISPLAY_KIND.get(kind, kind),
                "generated": generated,
                "valid": valid,
                "validity_percent": 100.0 * valid / generated if generated else 0.0,
            }
        )
    return rows


def risk_rows(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    by_risk = analysis["candidate_diagnostics"]["by_risk"]
    rows: list[dict[str, Any]] = []
    for risk in RISK_ORDER:
        item = by_risk[risk]
        generated = int(item["candidates"])
        valid = int(item["accurate"])
        rows.append(
            {
                "risk": DISPLAY_RISK[risk],
                "generated": generated,
                "valid": valid,
                "validity_percent": 100.0 * valid / generated if generated else 0.0,
            }
        )
    return rows


def plot_candidate_validity(rows: list[dict[str, Any]], output_dir: Path) -> None:
    x = list(range(len(rows)))
    width = 0.34
    generated = [row["generated"] for row in rows]
    valid = [row["valid"] for row in rows]
    max_generated = max(generated)
    ymax = max_generated * 1.24

    fig, ax = plt.subplots(figsize=(6.4, 3.25))
    ax.bar(
        [value - width / 2 for value in x],
        generated,
        width=width,
        color=GENERATED_COLOR,
        edgecolor="none",
        label="Generated",
        zorder=2,
    )
    ax.bar(
        [value + width / 2 for value in x],
        valid,
        width=width,
        color=VALID_COLOR,
        edgecolor="none",
        label="Validated",
        zorder=2,
    )
    style_axis(ax, "Repair candidates")
    ax.set_xlabel("Vulnerability type")
    ax.set_xticks(x)
    ax.set_xticklabels([row["kind"] for row in rows])
    ax.set_ylim(0, ymax)
    ax.legend(frameon=False, ncol=2, loc="upper left")

    offset = max_generated * 0.018
    stagger = max_generated * 0.055
    for index, row in enumerate(rows):
        label_count(ax, index - width / 2, row["generated"], offset)
        valid_offset = offset
        if abs(row["generated"] - row["valid"]) <= max_generated * 0.06:
            valid_offset += stagger
        label_count(
            ax,
            index + width / 2,
            row["valid"],
            valid_offset,
            f"\n{row['validity_percent']:.1f}%",
        )

    fig.subplots_adjust(left=0.11, right=0.99, top=0.97, bottom=0.18)
    save_figure(fig, output_dir / "repair_candidate_validity_by_kind")


def plot_root_cause_grouping(
    summary: dict[str, Any],
    output_dir: Path,
) -> None:
    grouping = summary["root_cause_grouping"]
    reports = int(grouping["repairable_reports"])
    groups = int(grouping["root_cause_groups"])
    covered = int(grouping["groups_with_accurate_candidate"])
    labels = ("Repairable\nreports", "Root-cause\ngroups", "Groups with a\nvalidated candidate")
    values = (reports, groups, covered)
    colors = ("#A9B7C6", "#668CB8", "#2F6FB0")
    x = list(range(3))

    fig, ax = plt.subplots(figsize=(5.5, 3.2))
    ax.bar(x, values, width=0.58, color=colors, edgecolor="none", zorder=2)
    style_axis(ax, "Count")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, max(values) * 1.16)
    offset = max(values) * 0.018
    for index, value in enumerate(values):
        label_count(ax, index, value, offset)

    merge_rate = 100.0 * float(grouping["overall_merge_rate_micro"])
    coverage = 100.0 * float(grouping["group_fix_coverage"])
    ax.text(
        0.5,
        0.96,
        f"Merge rate: {merge_rate:.1f}%   Group coverage: {coverage:.1f}%",
        transform=ax.transAxes,
        ha="center",
        va="top",
        fontsize=6.4,
        color=TEXT_COLOR,
    )

    fig.subplots_adjust(left=0.12, right=0.99, top=0.97, bottom=0.22)
    save_figure(fig, output_dir / "repair_root_cause_grouping")


def plot_candidate_validity_by_risk(
    rows: list[dict[str, Any]],
    output_dir: Path,
) -> None:
    x = list(range(len(rows)))
    width = 0.34
    generated = [row["generated"] for row in rows]
    valid = [row["valid"] for row in rows]
    max_generated = max(generated)
    ymax = max_generated * 1.24

    fig, ax = plt.subplots(figsize=(5.5, 3.2))
    ax.bar(
        [value - width / 2 for value in x],
        generated,
        width=width,
        color=GENERATED_COLOR,
        edgecolor="none",
        label="Generated",
        zorder=2,
    )
    ax.bar(
        [value + width / 2 for value in x],
        valid,
        width=width,
        color=VALID_COLOR,
        edgecolor="none",
        label="Validated",
        zorder=2,
    )
    style_axis(ax, "Repair candidates")
    ax.set_xlabel("Assigned risk level")
    ax.set_xticks(x)
    ax.set_xticklabels([row["risk"] for row in rows])
    ax.set_ylim(0, ymax)
    ax.legend(frameon=False, ncol=2, loc="upper right")

    offset = max_generated * 0.018
    stagger = max_generated * 0.055
    for index, row in enumerate(rows):
        label_count(ax, index - width / 2, row["generated"], offset)
        valid_offset = offset
        if abs(row["generated"] - row["valid"]) <= max_generated * 0.06:
            valid_offset += stagger
        label_count(
            ax,
            index + width / 2,
            row["valid"],
            valid_offset,
            f"\n{row['validity_percent']:.1f}%",
        )

    fig.subplots_adjust(left=0.12, right=0.99, top=0.97, bottom=0.19)
    save_figure(fig, output_dir / "repair_candidate_validity_by_risk")


def write_source_data(
    output_dir: Path,
    candidates: list[dict[str, Any]],
    risks: list[dict[str, Any]],
    summary: dict[str, Any],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for filename, rows in (
        ("source_data_candidate_validity_by_kind.csv", candidates),
        ("source_data_candidate_validity_by_risk.csv", risks),
    ):
        with (output_dir / filename).open(
            "w", newline="", encoding="utf-8"
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=tuple(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    grouping = summary["root_cause_grouping"]
    with (output_dir / "source_data_root_cause_grouping.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(("stage", "count"))
        writer.writerow(("repairable_reports", grouping["repairable_reports"]))
        writer.writerow(("root_cause_groups", grouping["root_cause_groups"]))
        writer.writerow(
            (
                "groups_with_validated_candidate",
                grouping["groups_with_accurate_candidate"],
            )
        )


def write_notes(output_dir: Path, summary: dict[str, Any]) -> None:
    grouping = summary["root_cause_grouping"]
    accuracy = summary["candidate_accuracy"]
    notes = f"""# Figure notes

## Repair candidate validity by vulnerability type

**Conclusion.** Candidate validity depends on the repair rule: DI, MG, and SR
candidates are almost always validated in this sample, whereas rewrite repairs
for RB and RL require semantic filtering.

**Caption.** Generated and independently validated repair candidates across
100 complete Census regions. A candidate is validated only if a fresh full
rebuild removes its root-cause group and introduces no severe vulnerability.
Percentages above the dark bars are within-type validation rates.

## Root-cause grouping

**Conclusion.** Root-cause normalization reduces
{grouping['repairable_reports']} reports to {grouping['root_cause_groups']}
groups; {grouping['groups_with_accurate_candidate']} groups have at least one
validated candidate.

**Caption.** Report consolidation and repair coverage. The merge rate is
{100.0 * grouping['overall_merge_rate_micro']:.1f}%, and root-cause group
coverage is {100.0 * grouping['group_fix_coverage']:.1f}%.

## Candidate validity by assigned risk

**Scope note.** Assigned risk estimates potential operational impact, not the
probability that a candidate fixes its original report. High-risk candidates
in this sample are dominated by deletion of already-shadowed SR records, so
their validation rate must not be interpreted as evidence of low impact.

## Statistical scope

These are descriptive counts from a deterministically selected sample.
Overall candidate validity is {100.0 * accuracy['overall_accuracy_micro']:.1f}%.
No confidence intervals or Internet-wide prevalence claims are made.
"""
    (output_dir / "figure_notes.md").write_text(notes, encoding="utf-8")


def main() -> int:
    args = parse_args()
    run_dir = args.run_dir.resolve()
    output_dir = args.output_dir.resolve()
    summary = load_json(run_dir / "summary.json")
    analysis_path = run_dir / "detailed_analysis.json"
    if not analysis_path.exists():
        raise FileNotFoundError(
            f"{analysis_path} is missing; run analyze_run.py before plotting"
        )
    analysis = load_json(analysis_path)

    candidates = candidate_rows(summary)
    risks = risk_rows(analysis)
    write_source_data(output_dir, candidates, risks, summary)
    plot_candidate_validity(candidates, output_dir)
    plot_root_cause_grouping(summary, output_dir)
    plot_candidate_validity_by_risk(risks, output_dir)
    write_notes(output_dir, summary)

    print(f"[done] figures={output_dir}")
    print(
        f"[data] candidates={summary['candidate_accuracy']['generated_candidates']} "
        f"validated={summary['candidate_accuracy']['accurate_candidates']} "
        f"groups={summary['root_cause_grouping']['root_cause_groups']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
