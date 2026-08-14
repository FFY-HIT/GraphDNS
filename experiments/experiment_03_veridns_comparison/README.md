# Experiment 03: VeriDNS vs. GraphDNS

## Purpose

This experiment evaluates two separate claims:

1. whether the explicit Resolution State Graph (RSG) described by VeriDNS can
   compose paths that no concrete DNS query can execute; and
2. whether endpoint-only incremental impact analysis misses changes to DNS
   record-selection priority, while GraphDNS's semantic dependency update
   agrees with a complete rebuild.

The experiment follows the organization of Experiment 02, but reports only
`VeriDNS-RSG reproduction` and `Full GraphDNS`. A bounded concrete resolver is
used as the path oracle and is not presented as a competing system.

## Reproduction boundary

The implementation is a clean-room reproduction of Sections 3.1--3.3 of:

> H. Du et al., "VeriDNS: incremental distributed verification of DNS
> configurations," *Computer Networks*, 275:111929, 2026.

The reproduced baseline implements the mechanisms stated in the paper:

- one RSG vertex per DNS entity and one `owner --TYPE--> rdata` edge per RR;
- DFS over the RSG without GraphDNS alpha/beta binding;
- an RR change translated to graph-edge deltas;
- backward and forward traversal from delta endpoints;
- revalidation of paths connected to the resulting affected subgraph.

The source URL printed in the paper,
`https://github.com/KaiQiangHu996/VeriDNS`, returned HTTP 404 while this
artifact was prepared. Therefore, results are labelled **paper reproduction**,
not **official VeriDNS implementation**. This distinction must be retained in
the paper. See `PAPER_MAPPING.md` for the statement-by-statement mapping and
the conservative choices made in favor of the baseline.

## Static experiment

The default static input is
`../experiment_02_symbolic_ablation/dataset/census_real_cases.json`. It
contains bounded query contexts over the complete selected `bme.hu` and
`cmu.edu` Census region configurations. Concrete resolution enumerates the
declared finite query set. The two compared methods are:

| Method | State representation | Path condition |
| --- | --- | --- |
| VeriDNS-RSG reproduction | DNS entities connected by RR transitions | no cross-edge alpha/beta assignment |
| Full GraphDNS | alpha/beta semantic graph | current query and bindings must remain consistent across the complete path |

For each method the experiment reports nodes, edges, pseudo paths, missed
paths, Precision, Recall, and false RL/RB/ML reports.

## Incremental experiment

The default incremental workload is defined compactly in
`dataset/census_controlled_updates.json`. For each pair, the loader:

1. copies every RR from one complete Experiment 02 Census case;
2. adds a small set of fixture records that is identical in both snapshots;
3. applies exactly one controlled `ADD`, `DELETE`, or `MODIFY`; and
4. retains the real Census authority map and selected authoritative entry.

The workload therefore measures controlled interventions on real Census
configuration backgrounds. It does **not** claim that the injected changes
were observed historical updates. The seven changes are:

| Change | Purpose |
| --- | --- |
| delete exact A | control: the deleted edge lies on the old path |
| add ancestor DNAME | shadows a descendant and introduces RB without an explicit RSG adjacency |
| delete ancestor DNAME | control: the deleted edge lies on the old path |
| add wildcard CNAME | introduces RB for a previously unmatched concrete name |
| modify DNAME target | control: the changed edge lies on the old path |
| add delegation cut | shadows parent-side descendants through suffix coverage |
| add DNAME self-rewrite | introduces RL below the DNAME owner |

Four changes use the complete 1,422-RR `bme.hu` background and three use the
complete 1,835-RR `cmu.edu` background. The `cmu.edu` interventions start at
the real `cmu.edu` apex rather than the Experiment 02 `west.cmu.edu` DNAME
entry, so the injected wildcard, delegation, and DNAME updates are semantically
effective rather than already shadowed.

For each method:

```text
incremental mismatch =
    incremental_after_paths symmetric_difference full_rebuild_after_paths
```

The VeriDNS comparison is against a **full rebuild of the same reproduced
VeriDNS model**, not against GraphDNS. This isolates incremental dependency
omissions from differences in static graph semantics.

GraphDNS collects exact/wildcard coverage, DNAME suffix coverage, delegation
cut coverage, and forward-record dependencies. Only affected finite queries are
recomputed; the others reuse their pre-change result.

## Run

Ubuntu, including the production C++ GraphDNS consistency check:

```bash
cd /path/to/graphdns
python3 experiments/experiment_03_veridns_comparison/run_experiment.py --build
```

Run only the bounded semantic reproduction:

```bash
python3 experiments/experiment_03_veridns_comparison/run_experiment.py \
  --skip-cpp-check
```

Use an existing GraphDNS binary:

```bash
python3 experiments/experiment_03_veridns_comparison/run_experiment.py \
  --graphdns-binary ./semantic_graph
```

Override the default static input with the RFC micro-configurations from
Experiment 02:

```bash
python3 experiments/experiment_03_veridns_comparison/run_experiment.py \
  --static-dataset \
    experiments/experiment_02_symbolic_ablation/dataset/rfc_symbolic_cases.json \
  --skip-cpp-check
```

Run the earlier purely synthetic update workload for regression comparison:

```bash
python3 experiments/experiment_03_veridns_comparison/run_experiment.py \
  --incremental-dataset \
    experiments/experiment_03_veridns_comparison/dataset/incremental_cases.json \
  --skip-cpp-check
```

Use different Census cases or a different controlled-update specification:

```bash
python3 experiments/experiment_03_veridns_comparison/run_experiment.py \
  --census-base-dataset /path/to/census_real_cases.json \
  --controlled-update-spec /path/to/controlled_updates.json \
  --build
```

Windows PowerShell:

```powershell
cd C:\path\to\graphdns
python experiments\experiment_03_veridns_comparison\run_experiment.py --build
```

Choose a fixed output directory:

```bash
python3 experiments/experiment_03_veridns_comparison/run_experiment.py \
  --build \
  --output-dir experiments/runs/exp03_reproduction
```

Run unit tests:

```bash
python3 -m unittest discover \
  -s experiments/experiment_03_veridns_comparison/tests -v
```

### Independent BIND runtime cross-validation

The seven controlled updates can also be validated against real DNS software.
The runtime experiment materializes the complete relevant `bme.hu.` or
`cmu.edu.` authority view as a BIND zone, applies the same single-record
before/after change, and issues every declared A query through a recursive
BIND resolver.

Every query uses a newly started resolver process. Its configuration sets
both `max-cache-ttl` and `max-ncache-ttl` to zero, and the process exits
immediately after the query. Thus, neither positive nor negative state is
reused between queries.

Ubuntu/WSL, as root:

```bash
cd /path/to/graphdns
python3 \
  experiments/experiment_03_veridns_comparison/run_bind_runtime_validation.py
```

Choose a fixed output directory:

```bash
python3 \
  experiments/experiment_03_veridns_comparison/run_bind_runtime_validation.py \
  --output-dir experiments/runs/exp03_bind_runtime
```

The script requires `named`, `named-checkconf`, `named-checkzone`, and `dig`.
It writes one raw `dig` response and resolver log per query, plus
`bind_runtime_queries.csv`, `summary.json`, and a paper-oriented `report.md`.
If a Census snapshot contains an RFC-invalid CNAME/other-data conflict that
BIND refuses to load, the BIND projection retains the CNAME (matching the
experiment resolver's selection order) and records every excluded RR ID in
the CSV rather than silently dropping it.

## Outputs

Each run creates one `experiments/runs/exp03_<timestamp>/` directory:

| File | Meaning |
| --- | --- |
| `manifest.json` | paper, dataset hashes, implementation boundary, and run metadata |
| `static_summary.csv` | aggregate path soundness for VeriDNS reproduction and GraphDNS |
| `static_per_case.csv` | static metrics for every controlled configuration |
| `incremental_summary.csv` | local/full consistency aggregated by method |
| `incremental_per_case.csv` | Census background, delta, affected queries, and path/report differences for every update |
| `controlled_update_provenance.csv` | base case, RR counts, changed owner/type/value, and update description |
| `differences.jsonl` | every pseudo, stale, and missed path |
| `graphdns_cpp_consistency.csv` | production C++ GraphDNS report-set comparison, when enabled |
| `graphdns_cpp/<case>/` | before/after facts and raw C++ outputs |
| `report.md` | paper-oriented tables and interpretation |

## Claim boundary

The supported claims are:

- the paper-specified unbound RSG abstraction produces pseudo paths on the
  declared finite query domain;
- explicit RSG endpoint reachability is insufficient for selected DNS
  priority-changing updates;
- GraphDNS's semantic local update matches full rebuilding on all supplied
  update cases; and
- when `--build` is used, the production C++ GraphDNS incremental bug-report
  set is also compared with a fresh C++ rebuild.

The experiment does not claim that an unavailable version of the authors'
implementation necessarily has every behavior observed in the clean-room
reproduction.

## Verified reference results

With the Experiment 02 real Census static cases and seven Census-background
controlled updates, the current implementation produces:

| Method | Pseudo paths | Precision | Recall | False vulnerabilities | Incremental consistency | Stale paths | Missed paths | Missed reports |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| VeriDNS-RSG reproduction | 168 | 0.1429 | 1.0000 | 9 | 3/7 | 8 | 8 | 4 |
| Full GraphDNS | 0 | 1.0000 | 1.0000 | 0 | 7/7 | 0 | 0 | 0 |

The production C++ GraphDNS check also reconstructs the post-update report set
from `before - fixed_reports + new_reports` and compares it with a fresh facts
file rebuild. All seven supplied updates currently agree.

The independent BIND 9.18.39 runtime experiment additionally produces:

| Runtime evidence | Agreement with GraphDNS |
| --- | ---: |
| Fresh-resolver queries over before/after snapshots | 24/24 |
| Single-record update pairs | 7/7 |
| Positive/negative cache state reused between queries | 0 |

The observed transitions include exact-to-wildcard answer replacement,
DNAME shadowing and reactivation, DNAME target modification, parent-to-child
delegation, wildcard CNAME activation, and a self-targeting DNAME that BIND
terminates with `SERVFAIL`. Raw `dig` responses and resolver logs are retained
under `experiments/runs/exp03_bind_runtime_20260726_v2/`.
