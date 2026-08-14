# Evaluation artifact

Each experiment is self-contained, writes generated data to one run directory,
and reads source datasets in place. The default output root is
`experiments/runs/`, which is excluded from version control.

## Paper mapping

| Paper question | Directory | Main result |
| --- | --- | --- |
| RQ1: large-scale detection and GRoot comparison | `experiment_01_census_consistency/` and `experiment_06_supplementary/` | Per-zone findings, overlap, disagreement audit, and GRoot core timing |
| RQ2: symbolic abstraction and dynamic binding | `experiment_02_symbolic_ablation/` | Graph size, path precision/recall, pseudo paths, and false reports |
| RQ3: RFC fidelity and update correctness | `experiment_03_veridns_comparison/` and `experiment_06_supplementary/` | BIND checks, VeriDNS-style baseline, and controlled updates |
| RQ4/RQ5: incremental validation and repair quality | `experiment_04_incremental_repair_equivalence/` | Root-cause groups, candidate outcomes, local/full equivalence, and timing |
| RQ6: scalability | `experiment_07_scalability/` and `experiment_06_supplementary/` | Stage timing, graph size, peak memory, and edge/node ratios |

Detailed assumptions, input schemas, and output files are documented in each
experiment directory.

## 1. Census detection

Copy the example configuration and set `census_dir` to the local Census root:

```bash
cp experiments/experiment_01_census_consistency/config.graphdns_only.example.json \
   experiments/experiment_01_census_consistency/config.local.json
python3 experiments/experiment_01_census_consistency/run_experiment.py \
  --config experiments/experiment_01_census_consistency/config.local.json \
  --graphdns-only --sample-size 10000 --workers 16 --build
```

For the paired official GRoot run, start the container as described in
`experiment_06_supplementary/README.md`, then use:

```bash
python3 experiments/experiment_01_census_consistency/run_experiment.py \
  --config experiments/experiment_06_supplementary/config.groot_comparison.json \
  --sample-size 10000 --build
```

## 2. Symbolic abstraction

Run the bundled RFC-oriented fixtures:

```bash
python3 experiments/experiment_02_symbolic_ablation/run_experiment.py
```

Run the selected Census cases stored in the artifact:

```bash
python3 experiments/experiment_02_symbolic_ablation/run_experiment.py \
  --dataset experiments/experiment_02_symbolic_ablation/dataset/census_real_cases.json
```

## 3. VeriDNS-style comparison and BIND validation

```bash
python3 experiments/experiment_03_veridns_comparison/run_experiment.py --build
```

The cache-disabled BIND experiment requires `bind9` and root privileges:

```bash
sudo python3 experiments/experiment_03_veridns_comparison/run_bind_runtime_validation.py \
  --dataset experiments/experiment_06_supplementary/dataset/census_controlled_updates_112.json \
  --static-dataset experiments/experiment_02_symbolic_ablation/dataset/census_real_cases.json
```

## 4. Repair and incremental equivalence

Set `census_dir` in the example configuration, then run:

```bash
python3 experiments/experiment_04_incremental_repair_equivalence/run_experiment.py \
  --config experiments/experiment_04_incremental_repair_equivalence/config.example.json \
  --regions 250 --screening-pool 20000 --workers 8 --build
```

## 5. Scalability

```bash
python3 experiments/experiment_07_scalability/run_experiment.py \
  --census-dir /path/to/census \
  --counts 1000,5000,10000,50000,100000 \
  --build
```

## 6. Supplementary protocols

`experiment_06_supplementary/` contains the exact drivers for the official
GRoot adapter, disagreement adjudication, 112 controlled updates, BIND checks,
symbolic scaling, grouping stress test, and core runtime comparison. These
commands depend on the relevant external datasets and are listed in that
directory's README.

## 7. Figures

```bash
python3 experiments/paper_figures/plot_all.py \
  --source-dir experiments/paper_figures/source_data \
  --output-dir experiments/paper_figures/output
```

The committed CSV files are frozen source tables for the paper figures. They
are not substitutes for raw Census data or run logs; provenance is documented
in `paper_figures/README.md`.
