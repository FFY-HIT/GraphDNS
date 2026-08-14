#!/usr/bin/env python3
"""Create publication-ready figures for the Census detection experiment."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch


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


BUG_KINDS = ("LD", "DI", "MG", "CZD", "RL", "RB", "ML", "STALE")
DISPLAY_KIND = {kind: ("SR" if kind == "STALE" else kind) for kind in BUG_KINDS}
BLUE = "#3B6FB6"
GRID = "#D9D9D9"
BUG_COLORS = {
    "LD": "#9A9A9A",
    "DI": "#3B6FB6",
    "MG": "#E2B447",
    "CZD": "#D08045",
    "RL": "#C95C54",
    "RB": "#4C9D98",
    "ML": "#6FA45F",
    "STALE": "#8A6AA8",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Plot the per-region vulnerability distribution and unique cases "
            "by vulnerability type."
        )
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        required=True,
        help="Experiment reports directory containing graphdns_per_region.csv and summary.json.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory for figures and source-data tables.",
    )
    return parser.parse_args()


def load_region_counts(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            if row.get("status") != "ok":
                continue
            count = int(row.get("total_bugs") or 0)
            if count <= 0:
                continue
            rows.append(
                {
                    "region_rank": int(row["region_rank"]),
                    "region_name": row["region_name"],
                    "reports": count,
                    **{kind: int(row.get(kind) or 0) for kind in BUG_KINDS},
                }
            )

    for row in rows:
        breakdown_total = sum(int(row[kind]) for kind in BUG_KINDS)
        if breakdown_total != row["reports"]:
            raise ValueError(
                f"per-kind mismatch for {row['region_name']}: "
                f"types={breakdown_total}, total={row['reports']}"
            )
    rows.sort(key=lambda row: (-row["reports"], row["region_name"]))
    return rows


def load_summary(path: Path) -> dict[str, Any]:
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


def write_source_data(
    output_dir: Path,
    region_rows: list[dict[str, Any]],
    counts_by_kind: dict[str, int],
) -> None:
    with (output_dir / "source_data_region_distribution.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        display_kinds = tuple(DISPLAY_KIND[kind] for kind in BUG_KINDS)
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "plot_order",
                "region_rank",
                "region_name",
                *display_kinds,
                "reports",
            ),
        )
        writer.writeheader()
        for index, row in enumerate(region_rows, start=1):
            writer.writerow(
                {
                    "plot_order": index,
                    "region_rank": row["region_rank"],
                    "region_name": row["region_name"],
                    **{
                        DISPLAY_KIND[kind]: row[kind]
                        for kind in BUG_KINDS
                    },
                    "reports": row["reports"],
                }
            )

    with (output_dir / "source_data_vulnerability_types.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=("vulnerability_type", "unique_cases"))
        writer.writeheader()
        for kind in BUG_KINDS:
            writer.writerow(
                {
                    "vulnerability_type": DISPLAY_KIND[kind],
                    "unique_cases": counts_by_kind[kind],
                }
            )


def plot_region_distribution(
    rows: list[dict[str, Any]],
    output_dir: Path,
) -> None:
    top_n = min(8, len(rows))
    display_rows = [dict(row) for row in rows[:top_n]]
    remainder = rows[top_n:]
    if remainder:
        display_rows.append(
            {
                "region_name": f"Other {len(remainder)} regions",
                "reports": sum(int(row["reports"]) for row in remainder),
                **{
                    kind: sum(int(row[kind]) for row in remainder)
                    for kind in BUG_KINDS
                },
            }
        )

    y = list(range(len(display_rows)))
    labels = [row["region_name"] for row in display_rows]
    observed_kinds = [
        kind
        for kind in BUG_KINDS
        if any(int(row[kind]) > 0 for row in display_rows)
    ]

    fig, ax = plt.subplots(figsize=(6.8, 3.75))
    cumulative = [0] * len(display_rows)
    for kind in observed_kinds:
        values = [int(row[kind]) for row in display_rows]
        ax.barh(
            y,
            values,
            left=cumulative,
            height=0.68,
            color=BUG_COLORS[kind],
            edgecolor="none",
            zorder=2,
        )
        cumulative = [base + value for base, value in zip(cumulative, values)]

    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlabel("Vulnerability reports")
    ax.set_ylabel("Affected region")
    ax.grid(axis="x", color=GRID, linewidth=0.55, zorder=0)
    ax.tick_params(axis="y", length=0, pad=4)
    max_total = max(int(row["reports"]) for row in display_rows)
    ax.set_xlim(0, max_total * 1.12)

    legend_handles = [
        Patch(
            facecolor=BUG_COLORS[kind],
            edgecolor="none",
            label=DISPLAY_KIND[kind],
        )
        for kind in observed_kinds
    ]
    ax.legend(
        handles=legend_handles,
        loc="lower right",
        ncol=len(legend_handles),
        frameon=False,
        fontsize=6.2,
        handlelength=1.2,
        columnspacing=1.0,
        borderaxespad=0.2,
    )

    for index, row in enumerate(display_rows):
        ax.text(
            int(row["reports"]) + max_total * 0.012,
            index,
            f"{row['reports']:,}",
            ha="left",
            va="center",
            fontsize=6.0,
            color="#222222",
        )

    fig.subplots_adjust(left=0.24, right=0.985, top=0.98, bottom=0.16)
    save_figure(fig, output_dir / "census_vulnerability_distribution_stacked_bar")


def _draw_break_marks(ax_top: plt.Axes, ax_bottom: plt.Axes) -> None:
    size = 0.009
    kwargs = {"color": "#333333", "clip_on": False, "linewidth": 0.8}
    ax_top.plot((-size, +size), (-size, +size), transform=ax_top.transAxes, **kwargs)
    ax_top.plot((1 - size, 1 + size), (-size, +size), transform=ax_top.transAxes, **kwargs)
    ax_bottom.plot(
        (-size, +size), (1 - size, 1 + size), transform=ax_bottom.transAxes, **kwargs
    )
    ax_bottom.plot(
        (1 - size, 1 + size),
        (1 - size, 1 + size),
        transform=ax_bottom.transAxes,
        **kwargs,
    )


def plot_vulnerability_types(
    counts_by_kind: dict[str, int],
    output_dir: Path,
) -> None:
    values = [counts_by_kind[kind] for kind in BUG_KINDS]
    x = list(range(len(BUG_KINDS)))

    fig, (ax_top, ax_bottom) = plt.subplots(
        2,
        1,
        sharex=True,
        figsize=(6.2, 3.55),
        gridspec_kw={"height_ratios": (1.15, 2.3), "hspace": 0.06},
    )
    for ax in (ax_top, ax_bottom):
        ax.bar(x, values, width=0.66, color=BLUE, edgecolor="none", zorder=2)
        ax.grid(axis="y", color=GRID, linewidth=0.55, zorder=0)
        ax.tick_params(axis="y", labelsize=6.5)

    ax_top.set_ylim(4400, 5300)
    ax_top.set_yticks((4500, 5000))
    ax_bottom.set_ylim(0, 230)
    ax_bottom.set_yticks((0, 50, 100, 150, 200))
    ax_top.spines["bottom"].set_visible(False)
    ax_bottom.spines["top"].set_visible(False)
    ax_top.tick_params(axis="x", bottom=False, labelbottom=False)
    ax_bottom.set_xticks(x)
    ax_bottom.set_xticklabels([DISPLAY_KIND[kind] for kind in BUG_KINDS])
    ax_bottom.tick_params(axis="x", length=0, pad=4)
    ax_bottom.set_xlabel("Vulnerability type")
    fig.supylabel("Unique vulnerability cases", x=0.015, fontsize=7)
    _draw_break_marks(ax_top, ax_bottom)

    for index, value in enumerate(values):
        if value > 4400:
            ax_top.text(
                index,
                value + 45,
                f"{value:,}",
                ha="center",
                va="bottom",
                fontsize=6.3,
                color="#222222",
            )
        else:
            offset = 6 if value > 0 else 4
            ax_bottom.text(
                index,
                value + offset,
                f"{value:,}",
                ha="center",
                va="bottom",
                fontsize=6.3,
                color="#222222",
            )

    fig.subplots_adjust(left=0.12, right=0.99, top=0.97, bottom=0.18)
    save_figure(fig, output_dir / "census_vulnerability_type_counts")


def write_notes(
    output_dir: Path,
    sampled_regions: int,
    affected_regions: int,
    total_unique_cases: int,
) -> None:
    notes = f"""# Figure notes

## Census vulnerability distribution

**Conclusion.** Vulnerability reports are concentrated in a small subset
of the sampled regions.

**Caption.** Distribution and composition of GraphDNS vulnerability reports
in a fixed-seed sample of {sampled_regions:,} complete Census regions. The eight
regions with the most reports are shown individually; the remaining
{max(0, affected_regions - 8):,} affected regions are aggregated. Colors
distinguish vulnerability types, and regions without reports are omitted.

## Vulnerability types

**Conclusion.** SR accounts for most type-specific unique cases; MG, RB, RL,
and DI occur less frequently, while LD, CZD, and ML are absent from this sample.

**Caption.** Number of unique GraphDNS cases by vulnerability type
({total_unique_cases:,} cases in total; the total is not plotted). The broken
linear y-axis preserves zero counts and makes both high- and low-frequency
categories visible. The omitted interval is 230--4,400 cases.

## Statistical scope

These figures are descriptive counts from one fixed-seed sample. They contain
no error bars or inferential statistics and should not be interpreted as
Internet-wide prevalence estimates.
"""
    (output_dir / "figure_notes.md").write_text(notes, encoding="utf-8")


def main() -> int:
    args = parse_args()
    reports_dir = args.reports_dir.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    region_rows = load_region_counts(reports_dir / "graphdns_per_region.csv")
    summary = load_summary(reports_dir / "summary.json")
    graphdns = summary["graphdns"]
    counts_by_kind = {
        kind: int(graphdns["unique_cases_by_kind"].get(kind, 0)) for kind in BUG_KINDS
    }
    sampled_regions = int(summary["sampled_regions"])
    expected_affected = int(graphdns["regions_with_reports"])
    total_unique_cases = int(graphdns["unique_cases"])

    if len(region_rows) != expected_affected:
        raise ValueError(
            f"affected-region mismatch: CSV={len(region_rows)}, "
            f"summary={expected_affected}"
        )
    raw_reports = int(graphdns["raw_reports"])
    if sum(row["reports"] for row in region_rows) != raw_reports:
        raise ValueError("per-region report counts do not match summary.json")
    if sum(counts_by_kind.values()) != total_unique_cases:
        raise ValueError("per-kind unique-case counts do not match summary.json")

    write_source_data(output_dir, region_rows, counts_by_kind)
    plot_region_distribution(region_rows, output_dir)
    plot_vulnerability_types(counts_by_kind, output_dir)
    write_notes(output_dir, sampled_regions, len(region_rows), total_unique_cases)

    print(f"[done] figures={output_dir}")
    print(
        f"[data] sampled_regions={sampled_regions} "
        f"affected_regions={len(region_rows)} unique_cases={total_unique_cases}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
