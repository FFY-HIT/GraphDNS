# GraphDNS

GraphDNS analyzes static authoritative DNS configurations without issuing live
DNS queries. It compiles zone-file records into a Symbolic Resolution Action
Graph (SRAG), traverses symbolically feasible resolution paths, detects DNS
configuration defects, groups reports by root cause, and validates candidate
repairs with local graph updates.

This repository is the reproducibility artifact for the GraphDNS paper. It
contains the implementation, experiment drivers, small fixtures, unit tests,
and the source data used to regenerate the paper figures. Census and production
datasets are intentionally not redistributed.

## Repository layout

```text
src/
  preprocess.cpp                 Zone files -> normalized facts
  semantic_graph.cpp             SRAG construction, analysis, and repair
experiments/
  experiment_01_census_consistency/
  experiment_02_symbolic_ablation/
  experiment_03_veridns_comparison/
  experiment_04_incremental_repair_equivalence/
  experiment_06_supplementary/
  experiment_07_scalability/
  paper_figures/
```

See [experiments/README.md](experiments/README.md) for the mapping from these
directories to the paper's research questions and for complete commands.

## Requirements

The artifact is tested on Ubuntu 22.04/24.04 and WSL with Python 3.10 or newer.

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake nlohmann-json3-dev python3 python3-pip
python3 -m pip install -r requirements.txt
```

The GRoot comparison additionally requires Docker and the official
`dnsgt/groot` image. BIND validation requires `bind9`, `bind9-utils`, and root
privileges for isolated local authoritative servers.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

The experiment configurations expect binaries under `experiments/bin/`. Build
there directly with:

```bash
mkdir -p experiments/bin
g++ -O3 -std=c++17 -fopenmp src/preprocess.cpp -o experiments/bin/preprocess
g++ -O3 -std=c++17 -fopenmp src/semantic_graph.cpp -o experiments/bin/semantic_graph
```

## Quick start

Run the built-in graph example:

```bash
./experiments/bin/semantic_graph --example --reports-only
```

The normalized fact format is tab-separated:

```text
server    zone    owner    type    rdata
```

Supported record types are `NS`, `A`, `AAAA`, `CNAME`, `DNAME`, `MX`, and
`TXT`. The analyzer reports `DI`, `LD`, `MG`, `CZD`, `RL`, `RB`, `ML`, and
shadow records (`SR`).

Bounded RFC-oriented fixtures and selected Census cases for smoke testing are
provided under `experiments/experiment_02_symbolic_ablation/dataset/`.

## Reproducing the paper figures

Frozen, non-sensitive source tables are stored under
`experiments/paper_figures/source_data/`. Regenerate all figures with:

```bash
python3 experiments/paper_figures/plot_all.py \
  --source-dir experiments/paper_figures/source_data \
  --output-dir experiments/paper_figures/output
```

## Data policy

The public artifact does not contain Census, production, or locally selected
zone files. Pass their locations through each experiment's configuration or
command-line arguments. Generated binaries, SQLite checkpoints, logs, reports,
and plots are written under `experiments/runs/` or another user-selected output
directory and are ignored by Git.

## Tests

```bash
python3 -m unittest discover -s experiments/experiment_01_census_consistency/tests -v
python3 -m unittest discover -s experiments/experiment_02_symbolic_ablation/tests -v
python3 -m unittest discover -s experiments/experiment_03_veridns_comparison/tests -v
python3 -m unittest discover -s experiments/experiment_04_incremental_repair_equivalence/tests -v
python3 -m unittest discover -s experiments/experiment_06_supplementary/tests -v
```

## Scope

GraphDNS models static authoritative DNS behavior represented by the supplied
zone files. It does not model resolver caches, TTL evolution, packet loss,
retry policies, DNSSEC validation, or unavailable external authority data.
