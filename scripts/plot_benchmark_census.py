#!/usr/bin/env python3
"""Plot Graph-DNS census benchmark results.

Input is a benchmark run directory produced by scripts/benchmark_census.py.
The script reads results.csv and writes publication-style PNG/PDF figures under
<run_dir>/figures by default.
"""

from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path
from typing import Iterable, Sequence

import matplotlib.pyplot as plt
from matplotlib.ticker import LogLocator, NullFormatter, ScalarFormatter


OKABE_ITO = {
    "blue": "#4C78A8",
    "orange": "#E88C30",
    "green": "#5DAE8B",
    "red": "#D86A5D",
    "purple": "#B279A2",
    "sky": "#72B7B2",
    "yellow": "#F2C14E",
    "black": "#303030",
}


def apply_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans", "sans-serif"],
            "font.size": 7.5,
            "axes.labelsize": 8.0,
            "axes.titlesize": 8.0,
            "xtick.labelsize": 7.2,
            "ytick.labelsize": 7.2,
            "legend.fontsize": 7.2,
            "axes.linewidth": 0.75,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "grid.color": "#B8B8B8",
            "grid.linewidth": 0.45,
            "grid.linestyle": "--",
            "grid.alpha": 0.28,
            "figure.dpi": 160,
            "savefig.dpi": 600,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "svg.fonttype": "none",
            "legend.frameon": False,
        }
    )


def read_rows(path: Path) -> list[dict[str, float | str]]:
    rows: list[dict[str, float | str]] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            parsed: dict[str, float | str] = {}
            for key, value in row.items():
                if value is None or value == "":
                    parsed[key] = ""
                    continue
                try:
                    parsed[key] = float(value)
                except ValueError:
                    parsed[key] = value
            rows.append(parsed)
    return rows


def col(rows: Sequence[dict[str, float | str]], key: str) -> list[float]:
    values: list[float] = []
    for row in rows:
        value = row.get(key, 0.0)
        if isinstance(value, str):
            values.append(float(value) if value else 0.0)
        else:
            values.append(float(value))
    return values


def fmt_num(value: float) -> str:
    if value == 0:
        return "0"
    if abs(value) >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if abs(value) >= 1_000:
        return f"{value / 1_000:.1f}k"
    if abs(value) >= 10:
        return f"{value:.0f}"
    if abs(value) >= 1:
        return f"{value:.2f}"
    return f"{value:.3f}"


def annotate_points(ax, x: Sequence[float], y: Sequence[float], every: int = 1) -> None:
    for i, (xi, yi) in enumerate(zip(x, y)):
        if i % every != 0 and i != len(x) - 1:
            continue
        if yi <= 0:
            continue
        ax.annotate(
            fmt_num(yi),
            (xi, yi),
            textcoords="offset points",
            xytext=(0, 5),
            ha="center",
            va="bottom",
            fontsize=7,
        )


def setup_log_axes(ax, xlabel: str, ylabel: str) -> None:
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.grid(True, which="major", axis="both")
    ax.grid(True, which="minor", axis="y", alpha=0.35)
    ax.xaxis.set_major_locator(LogLocator(base=10))
    ax.yaxis.set_major_locator(LogLocator(base=10))
    ax.yaxis.set_minor_formatter(NullFormatter())


def save(fig, out_dir: Path, name: str, formats: Iterable[str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    for fmt in formats:
        fig.savefig(out_dir / f"{name}.{fmt}", dpi=600, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def plot_runtime_scaling(rows: Sequence[dict[str, float | str]], out_dir: Path, formats: Iterable[str]) -> None:
    records = col(rows, "total_records")
    validation = col(rows, "total_validation_seconds")
    build = col(rows, "graph_build_seconds")

    fig, ax = plt.subplots(figsize=(4.8, 3.1))
    ax.plot(records, validation, marker="o", linewidth=1.8, markersize=4.0,
            color=OKABE_ITO["blue"], label="Core validation")
    ax.plot(records, build, marker="s", linewidth=1.8, markersize=4.0,
            color=OKABE_ITO["orange"], label="Graph construction")
    setup_log_axes(ax, "Resource records", "Time (s)")
    ax.legend(frameon=False)
    save(fig, out_dir, "benchmark_runtime_scaling", formats)


def plot_graph_scale(rows: Sequence[dict[str, float | str]], out_dir: Path, formats: Iterable[str]) -> None:
    records = col(rows, "total_records")
    nodes = col(rows, "total_nodes")
    edges = col(rows, "total_edges")
    paths = col(rows, "total_paths")
    bugs = [max(v, 0.5) for v in col(rows, "total_bugs")]

    fig, ax = plt.subplots(figsize=(4.8, 3.1))
    ax.plot(records, nodes, marker="o", linewidth=1.8, markersize=4.0,
            color=OKABE_ITO["blue"], label="Nodes")
    ax.plot(records, edges, marker="s", linewidth=1.8, markersize=4.0,
            color=OKABE_ITO["orange"], label="Edges")
    ax.plot(records, paths, marker="^", linewidth=1.8, markersize=4.0,
            color=OKABE_ITO["green"], label="Paths")
    if any(v > 0.5 for v in bugs):
        ax.plot(records, bugs, marker="D", linewidth=1.6, markersize=3.8,
                color=OKABE_ITO["red"], label="Bugs")
    setup_log_axes(ax, "Resource records", "Count")
    ax.legend(frameon=False, ncol=2)
    save(fig, out_dir, "benchmark_graph_scale", formats)


def stacked_bar(
    rows: Sequence[dict[str, float | str]],
    fields: Sequence[tuple[str, str, str]],
    ylabel: str,
    title: str,
    name: str,
    out_dir: Path,
    formats: Iterable[str],
) -> None:
    labels = [str(int(v)) for v in col(rows, "selected_regions")]
    x = list(range(len(rows)))
    bottoms = [0.0] * len(rows)

    fig_width = max(5.2, min(9.0, 0.52 * len(rows) + 2.2))
    fig, ax = plt.subplots(figsize=(fig_width, 3.1))
    for field, label, color in fields:
        values = col(rows, field)
        ax.bar(x, values, bottom=bottoms, width=0.72, label=label, color=color, linewidth=0)
        bottoms = [a + b for a, b in zip(bottoms, values)]

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=0, ha="center")
    ax.set_xlabel("Number of regions")
    ax.set_ylabel(ylabel)
    ax.grid(True, axis="y")
    ax.legend(frameon=False, ncol=2)
    max_total = max(bottoms) if bottoms else 0
    if max_total > 0:
        ax.set_ylim(0, max_total * 1.18)
        offset = max_total * 0.018
        for xi, total in zip(x, bottoms):
            ax.text(xi, total + offset, fmt_num(total), ha="center", va="bottom", fontsize=7)
    save(fig, out_dir, name, formats)


def plot_time_breakdowns(rows: Sequence[dict[str, float | str]], out_dir: Path, formats: Iterable[str]) -> None:
    stacked_bar(
        rows,
        [
            ("compute_reach_seconds", "Reachability labeling", OKABE_ITO["red"]),
            ("traverse_dfs_seconds", "Path exploration", OKABE_ITO["blue"]),
            ("detect_bugs_seconds", "Violation checking", OKABE_ITO["orange"]),
        ],
        "Time (s)",
        "Core validation time breakdown",
        "benchmark_validation_breakdown",
        out_dir,
        formats,
    )
    stacked_bar(
        rows,
        [
            ("load_facts_seconds", "Load facts", OKABE_ITO["sky"]),
            ("build_base_seconds", "Base edges", OKABE_ITO["blue"]),
            ("build_semantic_seconds", "Semantic edges", OKABE_ITO["orange"]),
            ("build_invariants_seconds", "Invariants", OKABE_ITO["green"]),
        ],
        "Time (s)",
        "Graph construction time breakdown",
        "benchmark_graph_build_breakdown",
        out_dir,
        formats,
    )


def plot_semantic_edges(rows: Sequence[dict[str, float | str]], out_dir: Path, formats: Iterable[str]) -> None:
    records = col(rows, "total_records")
    checked = [
        a + b + c
        for a, b, c in zip(
            col(rows, "del_candidates_checked"),
            col(rows, "crew_candidates_checked"),
            col(rows, "drew_candidates_checked"),
        )
    ]
    added = [
        a + b + c
        for a, b, c in zip(
            col(rows, "del_edges_added"),
            col(rows, "crew_edges_added"),
            col(rows, "drew_edges_added"),
        )
    ]
    ns = col(rows, "semantic_base_ns")
    cname = col(rows, "semantic_base_cname")

    fig, ax = plt.subplots(figsize=(4.8, 3.1))
    ax.plot(records, checked, marker="o", linewidth=1.8, markersize=4.0,
            color=OKABE_ITO["blue"], label="Semantic candidates checked")
    ax.plot(records, added, marker="s", linewidth=1.8, markersize=4.0,
            color=OKABE_ITO["orange"], label="Semantic edges added")
    ax.plot(records, ns, marker="^", linewidth=1.6, markersize=3.8,
            color=OKABE_ITO["green"], label="NS base records")
    if any(v > 0 for v in cname):
        ax.plot(records, cname, marker="D", linewidth=1.6, markersize=3.8,
                color=OKABE_ITO["red"], label="CNAME base records")
    setup_log_axes(ax, "Resource records", "Count")
    ax.legend(frameon=False)
    save(fig, out_dir, "benchmark_semantic_edge_stats", formats)


def write_readme(out_dir: Path, run_dir: Path, figure_names: Sequence[str], formats: Sequence[str]) -> None:
    lines = [
        "# Census Benchmark Figures",
        "",
        f"Source run: `{run_dir}`",
        "",
        "Generated figures:",
        "",
    ]
    for name in figure_names:
        files = ", ".join(f"`{name}.{fmt}`" for fmt in formats)
        lines.append(f"- `{name}`: {files}")
    lines.extend(
        [
            "",
            "Figure meanings:",
            "",
            "- `benchmark_runtime_scaling`: core validation time and graph construction time versus record count.",
            "- `benchmark_graph_scale`: nodes, edges, paths, and bugs versus record count.",
            "- `benchmark_validation_breakdown`: reachability labeling, path exploration, and violation checking time.",
            "- `benchmark_graph_build_breakdown`: fact loading, base-edge construction, semantic-edge construction, and invariant construction time.",
            "- `benchmark_semantic_edge_stats`: semantic candidate checks and induced semantic edges.",
            "",
        ]
    )
    (out_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Plot benchmark_census.py results.")
    parser.add_argument(
        "run_dir",
        nargs="?",
        default="",
        help="benchmark run directory; default: latest benchmark_runs/*/results.csv",
    )
    parser.add_argument("--out-dir", default="", help="output directory; default: <run_dir>/figures")
    parser.add_argument("--formats", default="pdf,png", help="comma-separated formats, e.g. pdf,png,svg")
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[1]
    if args.run_dir:
        run_dir = Path(args.run_dir)
        if not run_dir.is_absolute():
            run_dir = (repo_root / run_dir).resolve()
    else:
        candidates = sorted(
            (repo_root / "benchmark_runs").glob("*/results.csv"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not candidates:
            raise FileNotFoundError("no benchmark_runs/*/results.csv found")
        run_dir = candidates[0].parent

    results_path = run_dir / "results.csv"
    if not results_path.exists():
        raise FileNotFoundError(f"results.csv not found: {results_path}")

    out_dir = Path(args.out_dir) if args.out_dir else run_dir / "figures"
    if not out_dir.is_absolute():
        out_dir = (repo_root / out_dir).resolve()
    formats = [part.strip().lower() for part in args.formats.split(",") if part.strip()]

    apply_style()
    rows = [row for row in read_rows(results_path) if row.get("status", "ok") == "ok"]
    if not rows:
        raise RuntimeError(f"no successful rows found in {results_path}")

    plot_runtime_scaling(rows, out_dir, formats)
    plot_graph_scale(rows, out_dir, formats)
    plot_time_breakdowns(rows, out_dir, formats)
    plot_semantic_edges(rows, out_dir, formats)

    figure_names = [
        "benchmark_runtime_scaling",
        "benchmark_graph_scale",
        "benchmark_validation_breakdown",
        "benchmark_graph_build_breakdown",
        "benchmark_semantic_edge_stats",
    ]
    write_readme(out_dir, run_dir, figure_names, formats)
    print(f"[figures] {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
