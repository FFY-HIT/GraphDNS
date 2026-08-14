# Experiment 06: Evaluation TODO Supplement

This directory contains supplemental experiments requested by the evaluation
audit.  It reuses the datasets and canonical case definitions from experiments
01--04 and keeps official baseline output alongside normalized results.

## Official GRoot comparison

Start one persistent container so that a 10,000-region run does not pay image
startup cost for every region:

```bash
cd /path/to/graphdns

docker rm -f graphdns-groot-baseline 2>/dev/null || true
docker run -d --name graphdns-groot-baseline --user root \
  -v /path/to/census:/data:ro \
  -v "$(pwd)":/workspace \
  dnsgt/groot:latest sleep infinity
```

Run a 10-region compatibility test:

```bash
python3 experiments/experiment_01_census_consistency/run_experiment.py \
  --config experiments/experiment_06_supplementary/config.groot_comparison.json \
  --sample-size 10 \
  --workers 2 \
  --build
```

Run the full comparison using the same seed and 10,000-region sample as RQ1:

```bash
python3 experiments/experiment_01_census_consistency/run_experiment.py \
  --config experiments/experiment_06_supplementary/config.groot_comparison.json \
  --sample-size 10000 \
  --workers 4 \
  --build
```

The wrapper invokes `/home/groot/groot/build/bin/groot` from the official
`dnsgt/groot:latest` image.  `groot_raw.json`, `lint.json`, and GRoot stdout are
retained in each temporary work directory while the experiment is running;
canonical findings and timing are persisted in experiment 01's SQLite result
database.  Only the seven shared path-vulnerability classes enter agreement
metrics.  GraphDNS-only shadow records are excluded from the denominator.

## Difference adjudication

After copying the source folders named by
`reports/supplemental_unresolved_cases.csv` into
`<run-dir>/unresolved_regions`, run:

```bash
python3 experiments/experiment_06_supplementary/adjudicate_unresolved_cases.py \
  --run-dir experiments/runs/exp06_groot_10000_v2
```

The audit emits:

```text
reports/adjudication/unresolved_case_adjudication.csv
reports/adjudication/unresolved_case_adjudication_summary.json
reports/adjudication/all_difference_adjudication.csv
reports/adjudication/all_difference_adjudication_summary.json
reports/adjudication/all_difference_adjudication_report_zh.md
```

The first pair contains evidence for the 197 cases that required record-level
inspection.  The `bind_status` field is separate from the static verdict:
malformed zones remain useful for testing the static model but are excluded
from BIND runtime accuracy claims.  The full audit also collapses a CZD/MG
pair or two witnesses of the same rewrite cycle into one underlying root.

## Nameserver-equals-cut MG boundary fix

RFC bailiwick includes a delegated nameserver whose name is exactly equal to
the delegation cut.  After rebuilding GraphDNS with the corrected predicate,
the regression fixture can be checked with:

```bash
g++ -O3 -std=c++17 -fopenmp src/semantic_graph.cpp \
  -o experiments/bin/semantic_graph

experiments/bin/semantic_graph \
  experiments/experiment_06_supplementary/fixtures/mg_bailiwick_boundary.facts \
  --reports-only --server-views sampled
```

The expected result is two MG reports: one nameserver equals its cut and one
is strictly below its cut.  The out-of-bailiwick nameserver must not be
reported.

The four affected Census cases were then rerun in their complete `ac.in` and
`ac.th` region contexts.  To derive a traceable corrected comparison while
preserving the original run, execute:

```bash
python3 \
  experiments/experiment_06_supplementary/apply_mg_boundary_fix_results.py \
  --source-run experiments/runs/exp06_groot_10000_v2 \
  --output-run experiments/runs/exp06_groot_10000_v3_mg_boundary_fix

python3 \
  experiments/experiment_06_supplementary/adjudicate_unresolved_cases.py \
  --run-dir experiments/runs/exp06_groot_10000_v3_mg_boundary_fix \
  --regions-dir experiments/runs/exp06_groot_10000_v2/unresolved_regions
```

The corrected result contains 203 GraphDNS MG cases, of which all 203 are in
the GRoot intersection.  The post-fix manifest records that unaffected
findings are inherited from the original 10,000-region run.

## Tests

```bash
python3 -m unittest discover \
  -s experiments/experiment_06_supplementary/tests -v
```

## Symbolic scaling

```bash
python3 experiments/experiment_06_supplementary/run_symbolic_scaling.py \
  --output-dir experiments/runs/exp06_symbolic_scaling

python3 experiments/experiment_06_supplementary/plot_symbolic_scaling.py \
  --input experiments/runs/exp06_symbolic_scaling/symbolic_scaling.csv \
  --output-dir experiments/runs/exp06_symbolic_scaling/figures
```

The workload contains two consecutive DNAME rewrites.  It enumerates all
one- and two-label prefixes over label sets of size 1, 2, 4, 8, 16, 32, and
64.  Concrete and SRAG graphs are built from exactly the same resolution
traces; the script fails if either graph loses or adds a trace.

## Expanded DNAME ablation

Select complete DNAME-bearing Census regions, use ten labels and prefixes of
depth zero to two, then run all four ablation variants:

```bash
python3 experiments/experiment_02_symbolic_ablation/select_census_cases.py \
  --census-dir /path/to/census \
  --limit 100 \
  --workers 8 \
  --label-limit 10 \
  --max-prefix-depth 2 \
  --output experiments/runs/exp06_dname_all/dataset.json \
  --selection-report experiments/runs/exp06_dname_all/selection.csv

python3 experiments/experiment_02_symbolic_ablation/run_experiment.py \
  --dataset experiments/runs/exp06_dname_all/dataset.json \
  --output-dir experiments/runs/exp06_dname_all/results

sudo python3 experiments/experiment_06_supplementary/run_bind_static_validation.py \
  --dataset experiments/runs/exp06_dname_all/dataset.json \
  --output-dir experiments/runs/exp06_dname_all/bind
```

The BIND step reports and excludes zone contexts that cannot be loaded by
`named-checkzone`; it does not silently count them as matches.

## Expanded controlled updates

Create 16 name-disjoint copies of each of the seven update templates:

```bash
python3 experiments/experiment_06_supplementary/expand_controlled_updates.py \
  --input experiments/experiment_03_veridns_comparison/dataset/census_controlled_updates.json \
  --output experiments/experiment_06_supplementary/dataset/census_controlled_updates_112.json \
  --copies 16

python3 experiments/experiment_03_veridns_comparison/run_experiment.py \
  --controlled-update-spec \
    experiments/experiment_06_supplementary/dataset/census_controlled_updates_112.json \
  --census-base-dataset \
    experiments/experiment_02_symbolic_ablation/dataset/census_real_cases.json \
  --output-dir experiments/runs/exp06_updates_112 \
  --build

sudo python3 experiments/experiment_03_veridns_comparison/run_bind_runtime_validation.py \
  --controlled-update-spec \
    experiments/experiment_06_supplementary/dataset/census_controlled_updates_112.json \
  --census-base-dataset \
    experiments/experiment_02_symbolic_ablation/dataset/census_real_cases.json \
  --output-dir experiments/runs/exp06_bind_updates_112
```

The BIND harness starts a fresh resolver for every query and redirects the
tested child delegations to isolated local authoritative servers.

## Incremental/full equivalence on repair candidates

```bash
python3 experiments/experiment_04_incremental_repair_equivalence/run_experiment.py \
  --config experiments/experiment_04_incremental_repair_equivalence/config.example.json \
  --regions 250 \
  --screening-pool 70000 \
  --workers 8 \
  --run-dir experiments/runs/exp04_250_equivalence \
  --build

python3 experiments/experiment_04_incremental_repair_equivalence/analyze_run.py \
  experiments/runs/exp04_250_equivalence
```

The equivalence check compares canonical sets of reachable SRAG edges,
complete paths, terminal symbolic states, and vulnerability reports.
Dormant `r=0` candidate edges are reported only as an internal cache
diagnostic.

## Root-cause grouping stress test

```bash
python3 experiments/experiment_06_supplementary/run_grouping_stress.py \
  --semantic-bin experiments/bin/semantic_graph \
  --roots-per-multiplicity 40 \
  --output-dir experiments/runs/exp06_grouping_stress_1240
```

This creates 40 ground-truth roots at each report multiplicity
`1, 2, 4, 8, 16`, for 1,240 reports and 200 known root causes.

## Official GRoot core timing

After completing the official GRoot comparison, pair its sample manifest and
Experiment 01 database with the timers printed by GRoot `--stats`:

```bash
python3 experiments/experiment_06_supplementary/run_groot_core_timing.py \
  --manifest experiments/runs/exp06_groot_10000_v2/sample_manifest.csv \
  --results-db experiments/runs/exp06_groot_10000_v2/results.sqlite3 \
  --sample-size 1000 \
  --workers 4 \
  --output-dir experiments/runs/exp06_groot_core_1000
```

The core comparison excludes GraphDNS preprocessing, Docker/process startup,
adapter I/O, and result serialization.  Wrapper wall time is retained
separately and must not be presented as an algorithm-only speedup.

## Fixed paper evidence

The exact result summaries used by the revised evaluation chapter are copied
to:

```text
experiments/runs/final_evidence/
```

See `experiments/runs/final_evidence/README.md` for provenance and interpretation
boundaries.
