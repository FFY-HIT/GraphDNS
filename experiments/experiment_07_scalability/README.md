# Experiment 07: Census scalability

This experiment constructs one combined SRAG for each nested Census subset and
records graph construction time, DFS traversal time, graph size, and sampled
peak RSS.

Run from the repository root in WSL:

```bash
python3 experiments/experiment_07_scalability/run_experiment.py \
  --census-dir /path/to/census \
  --counts 1000,5000,10000,50000,100000,full \
  --threads 16 \
  --build
```

The script uses directory symlinks for sampled subsets and does not copy Census
files. The full-Census point reads the original Census directory directly.
Subsets are nested and use seed `20260729` by default.

Peak RSS is sampled from the actual `preprocess` and `semantic_graph` process
trees. `semantic_peak_rss_mb` is the analysis-stage memory measurement used in
the paper figure; `pipeline_peak_rss_mb` is the larger of preprocessing and
analysis peaks.

## Current 8 GB host result

The nested run completed 1K, 5K, 10K, and 50K regions. At 100K regions the
combined facts input contained 24,544,156 records; `semantic_graph` reached
7,310.4 MB sampled RSS and terminated before producing a graph summary. The
full set of 270,021 complete regions was therefore not attempted. This is a
measured resource limit, not a successful full-Census data point.

The paper plotting script connects only the completed measurements and marks
the 100K failure and full-Census non-run explicitly.
