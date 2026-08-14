# GraphDNS paper figures

This directory regenerates the figures used by the evaluation. By default, the
script reads the frozen, non-sensitive CSV tables committed under
`source_data/`; no local run directory is required.

## Generate all figures

From the repository root:

```bash
python experiments/paper_figures/plot_all.py
```

The script writes:

- `output/*.pdf`: manuscript-ready vector figures;
- `output/*.svg`: editable vector figures;
- `output/*.png`: 300 dpi previews;
- `output/*.tiff`: 600 dpi submission exports;
- `source_data/*.csv`: source data corresponding to each figure.

To rebuild the CSV tables from raw experiment outputs, pass
`--refresh-source-data` together with `--rq1-run`, `--evidence-dir`, and
`--finding-audit`. Raw runs remain external because they contain large Census
artifacts and machine-specific paths.

## Figure placement

Every output contains exactly one axes/chart. No file uses subplots or panel
labels.

| Prefix | Evaluation section | Figures |
| --- | --- | --- |
| `rq1_` | 5.2 | Detection overview, all vulnerability types including SR, SR causes, and all affected regions in one chart |
| `rq2_` | 5.3 | Graph size, pseudo paths, path precision/recall, and false findings |
| `rq3_` | 5.4 | Controlled-update consistency, affected-query precision/recall, and update errors |
| `rq4_` | 5.5 | Incremental/full-rebuild equivalence and local DFS scope |
| `rq5_` | 5.6 | Root-cause grouping, candidate coverage, validity, and rejection reasons |
| `rq6_` | 5.7 | GraphDNS/GRoot runtime, incremental validation, Census scalability, memory, and graph sparsity |

The output directory contains independent, single-panel figures grouped by the
RQ prefixes above.

## Interpretation notes

- Census reports are snapshot-confirmed configuration findings, not live-DNS
  prevalence estimates.
- The VeriDNS baseline is a clean-room reproduction.
- The BIND comparison covers 112 controlled updates and 384 queries.
- Candidate-level distributions contain one observation per repair candidate
  (`n = 1,019`).
- The GraphDNS/GRoot runtime comparison uses 1,000 matched Census regions.
- The combined-graph scalability run completed through 50,000 regions. The
  100,000-region point reached the 8 GB host's memory limit, and the full
  270,021-region point was consequently not run. The figures mark these
  outcomes explicitly instead of extrapolating successful measurements.
- The edge-to-node ratio distribution uses all 10,000 regions in the corrected
  Census run.
