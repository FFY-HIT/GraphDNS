#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib.pyplot as plt


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def load_rows(path: Path) -> list[dict[str, float]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return [
            {key: float(value) for key, value in row.items()}
            for row in csv.DictReader(handle)
        ]


def draw(rows: list[dict[str, float]], metric: str, ylabel: str, output: Path) -> None:
    x = [row["k"] for row in rows]
    concrete = [row[f"concrete_{metric}"] for row in rows]
    srag = [row[f"srag_{metric}"] for row in rows]
    fig, ax = plt.subplots(figsize=(5.2, 3.15))
    ax.plot(x, concrete, marker="o", linewidth=1.8, color="#C44E52", label="Concrete enumeration")
    ax.plot(x, srag, marker="s", linewidth=1.8, color="#4C72B0", label="SRAG")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xticks(x, [str(int(value)) for value in x])
    ax.set_xlabel("Labels per symbolic position, k")
    ax.set_ylabel(ylabel)
    ax.grid(axis="y", linestyle="--", linewidth=0.6, alpha=0.5)
    ax.legend(frameon=False)
    fig.tight_layout()
    for suffix in ("pdf", "png", "svg"):
        fig.savefig(output.with_suffix(f".{suffix}"), dpi=300, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    args = parse_args()
    rows = load_rows(args.input)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    draw(rows, "nodes", "Graph nodes", args.output_dir / "rq2_symbolic_scaling_nodes")
    draw(rows, "edges", "Graph edges", args.output_dir / "rq2_symbolic_scaling_edges")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
