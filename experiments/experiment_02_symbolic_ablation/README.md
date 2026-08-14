# Experiment 02: Symbolic Abstraction and Dynamic Binding

## Research questions

This experiment isolates two design choices in GraphDNS:

1. Do alpha/beta symbolic nodes reduce graph size relative to bounded concrete
   query enumeration?
2. Does cross-edge dynamic binding prevent paths assembled from incompatible
   symbolic assignments?

The primary controlled experiment uses small, inspectable RFC-oriented
configurations because DNAME is sparse in Census. A companion real-case mode
selects complete DNAME-bearing Census regions and runs the same four variants.
The controlled and real results are reported separately.

## Compared methods

| Method | Graph representation | Traversal rule |
| --- | --- | --- |
| `Concrete` | One state for every concrete query/context | Exact finite oracle |
| `alpha-only` | All variable-prefix states use an unbound alpha node | Ignores cross-edge assignments |
| `alpha+beta, no binding` | Alpha permits zero or more labels; beta requires a non-empty prefix | Enforces the local beta constraint but does not preserve one assignment across edges |
| `Full GraphDNS` | Same alpha+beta graph as the preceding variant | Propagates `q`, alpha binding, and beta binding and rejects inconsistent transitions |

The third and fourth methods intentionally have identical graph nodes and
edges. Their difference is exclusively the traversal state, which makes the
effect of dynamic binding measurable without a graph-size confounder.

## Dataset

The file `dataset/rfc_symbolic_cases.json` contains ten configurations:

| Case | Property exercised |
| --- | --- |
| `dname_concrete_wildcard` | DNAME target with exact and wildcard successors |
| `multi_layer_dname` | Prefix preservation across two DNAME rewrites |
| `cname_then_dname` | CNAME entering a DNAME subtree |
| `beta_multiple_successors` | One beta state with several candidate successors |
| `zone_cut_dname_overlap` | DNAME target beneath a delegation cut |
| `delete_concrete_before/after` | Wildcard activation after deleting an exact owner |
| `delete_dname_before/after` | Shadowed record activation after deleting DNAME |
| `binding_guard_prevents_false_rl` | Two safe DNAME paths that form a false rewrite loop only when `β=www` and `β=api` are combined |

The label alphabet and maximum prefix depth are declared in each case. The
default dataset contains 39 records and 390 concrete queries.

### Concrete oracle semantics

For every bounded query, the independent resolver applies the following static
authoritative order:

1. the closest non-apex NS cut delegates the query;
2. the closest strict-ancestor DNAME rewrites the suffix while retaining a
   non-empty prefix;
3. an exact CNAME rewrites the complete name;
4. an exact A/AAAA record terminates the path;
5. otherwise, a matching wildcard A/AAAA or CNAME is selected;
6. if the owner exists but has no address/CNAME answer, the path terminates
   with NODATA; if the name does not exist, it terminates with NX.

This scope matches the records needed by the ablation. It deliberately excludes
cache state, retries, TTL, DNSSEC, and network failures.

## Graph construction and path comparison

`Concrete` enumerates the bounded query set and constructs its concrete
resolution-state graph. The other versions quotient that same graph by their
node abstraction. Every quotient edge retains the concrete assignments that
witness it:

```text
guard = (alpha_binding, beta_binding, before_q, after_q)
```

The unbound variants walk the quotient graph without intersecting guards from
successive edges. Full GraphDNS carries the binding environment and current
query across the path. All resulting paths are materialized back into:

```text
(initial_query, ordered_record_actions, terminal_outcome)
```

The concrete set is the oracle. Therefore:

```text
TP = |Predicted intersect Oracle|
FP = |Predicted - Oracle|
FN = |Oracle - Predicted|
Precision = TP / (TP + FP)
Recall = TP / (TP + FN)
```

`FP` is the number of pseudo paths and `FN` is the number of missed paths.

### False vulnerability reports

The experiment additionally runs path-level RL, RB, and ML predicates over each
method's materialized paths. Every concrete path in the supplied dataset is
safe. Two mechanisms nevertheless make the unbound variants report bugs:

1. in `zone_cut_dname_overlap`, an incompatible zero-prefix terminal is joined
   to a rewritten path, producing eight false RB reports;
2. in `binding_guard_prevents_false_rl`, the safe paths with `β=www` and
   `β=api` are combined into `old.s8.test. <-> new.s8.test.`, producing two
   false RL reports.

Full GraphDNS rejects both combinations because their alpha/beta assignments
cannot be unified across the complete path.

## Run

No third-party Python packages are required.

Ubuntu:

```bash
cd /path/to/graphdns
python3 experiments/experiment_02_symbolic_ablation/run_experiment.py
```

Windows PowerShell:

```powershell
cd C:\path\to\graphdns
python experiments\experiment_02_symbolic_ablation\run_experiment.py
```

Specify a dataset or output directory when needed:

```bash
python3 experiments/experiment_02_symbolic_ablation/run_experiment.py \
  --dataset experiments/experiment_02_symbolic_ablation/dataset/rfc_symbolic_cases.json \
  --output-dir experiments/runs/exp02_reproduction
```

Run the semantic and ablation tests:

```bash
python3 -m unittest discover \
  -s experiments/experiment_02_symbolic_ablation/tests -v
```

## Select real Census cases

The selector reads each region in place; it does not copy Census data. A region
is eligible only when `metadata.json` exists and every file listed by
`ZoneFiles` is present. Eligible DNAME regions are ranked using only structural
features relevant to this ablation: DNAME chains, CNAME-to-DNAME transitions,
exact/wildcard records below a DNAME target, and delegation/DNAME overlap.

Reusing the deterministic 100,000-region manifest from Experiment 01 avoids a
new full-directory sample:

```bash
cd /path/to/graphdns
python3 experiments/experiment_02_symbolic_ablation/select_census_cases.py \
  --census-dir /path/to/census \
  --sample-manifest \
    experiments/runs/exp01_20260724_191245/sample_manifest.csv \
  --limit 5 \
  --workers 8 \
  --max-zone-files 200 \
  --max-region-mib 20 \
  --output experiments/experiment_02_symbolic_ablation/dataset/census_real_cases.json \
  --selection-report \
    experiments/experiment_02_symbolic_ablation/dataset/census_real_selection.csv
```

Run the four-way ablation on the selected real cases:

```bash
python3 experiments/experiment_02_symbolic_ablation/run_experiment.py \
  --dataset \
    experiments/experiment_02_symbolic_ablation/dataset/census_real_cases.json
```

Without `--sample-manifest`, the selector scans the immediate region
directories under `--census-dir`. `--max-regions N` can be used for a bounded
pilot, and `--skip-regions N` starts a later non-overlapping scan segment.
Once candidate names are known, a stable dataset can be rebuilt without
rescanning:

```bash
python3 experiments/experiment_02_symbolic_ablation/select_census_cases.py \
  --census-dir /path/to/census \
  --region-path /path/to/census/bme.hu \
  --region-path /path/to/census/cmu.edu \
  --limit 2 \
  --output \
    experiments/experiment_02_symbolic_ablation/dataset/census_real_cases.json \
  --selection-report \
    experiments/experiment_02_symbolic_ablation/dataset/census_real_selection.csv
```

Aggregate directories above `--max-zone-files` or `--max-region-mib`
are skipped because they are unsuitable as inspectable case studies. These
limits do not truncate a region: a selected region is always imported in full.
The generated JSON stores the source region, source zone files, and selection
features for every case.

### Selected real cases

The current local selection contains two complete Census regions and three
DNAME-bearing starting contexts:

| Region | Zone files | Supported records | DNAME records | DNAME-bearing contexts | Relevant structures |
| --- | ---: | ---: | ---: | ---: | --- |
| `bme.hu` | 75 | 1,422 | 3 | 2 | multiple DNAME records, CNAME entering a DNAME subtree, and delegation/DNAME overlap |
| `cmu.edu` | 91 | 1,835 | 1 | 1 | DNAME target subtree and delegation/DNAME overlap |

The observed mappings include `hvt.bme.hu. DNAME mht.bme.hu.`,
`kte.bme.hu. DNAME kkft.bme.hu.`, `vemt.bme.hu. DNAME kkft.bme.hu.`,
and `west.cmu.edu. DNAME sv.cmu.edu.`. Their exact source files and feature
counts are recorded in `dataset/census_real_selection.csv`.

On the bounded 28-query real-case oracle, the current implementation produces:

| Method | Nodes | Edges | Pseudo paths | Precision | Recall | Missed paths | Reported vulnerabilities | False vulnerabilities |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Concrete | 86 | 60 | 0 | 1.0000 | 1.0000 | 0 | 17 | 0 |
| alpha-only | 36 | 35 | 168 | 0.1429 | 1.0000 | 0 | 26 | 9 |
| alpha+beta, no binding | 36 | 35 | 144 | 0.1628 | 1.0000 | 0 | 26 | 9 |
| Full GraphDNS | 36 | 35 | 0 | 1.0000 | 1.0000 | 0 | 17 | 0 |

Thus, the full abstraction reduces nodes by 58.14% and edges by 41.67% in
these real contexts. Dynamic binding removes 144 pseudo paths and nine
additional vulnerability reports while preserving every oracle path and
oracle report.

Here, a *false vulnerability* means a report absent from the bounded Concrete
oracle. The 17 Concrete/Full findings are outputs of the experiment's RL/RB/ML
predicates, not manually confirmed operational vulnerabilities. This
distinction prevents the real-case ablation from being misreported as a
ground-truth vulnerability study.

## Outputs

Each run creates one `experiments/runs/exp02_<timestamp>/` directory:

| File | Meaning |
| --- | --- |
| `manifest.json` | Dataset hash, method list, query bound, and run metadata |
| `summary.csv` | Aggregate nodes, edges, path counts, Precision/Recall, and RL/RB/ML counts |
| `per_case.csv` | The same path and vulnerability metrics for each configuration, including false/missed vulnerability counts relative to Concrete |
| `path_differences.jsonl` | Every pseudo path, missed path, and reported vulnerability |
| `report.md` | Paper-oriented aggregate and per-case tables |

## Reference result

With the supplied dataset, the current implementation produces:

| Method | Nodes | Edges | Pseudo paths | Precision | Recall | Missed paths | Reported vulnerabilities |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Concrete | 1,234 | 852 | 0 | 1.0000 | 1.0000 | 0 | 0 |
| alpha-only | 53 | 46 | 794 | 0.3294 | 1.0000 | 0 | 10 |
| alpha+beta, no binding | 54 | 47 | 781 | 0.3330 | 1.0000 | 0 | 10 |
| Full GraphDNS | 54 | 47 | 0 | 1.0000 | 1.0000 | 0 | 0 |

Thus, Full GraphDNS reduces nodes by 95.62% and edges by 94.48% relative
to bounded concrete enumeration. Dynamic binding removes 781 pseudo paths and
10 false vulnerability reports without changing the alpha+beta graph structure.

## Interpretation boundary

The result demonstrates the abstraction on the declared finite query domain.
It is not an empirical enumeration of the infinite DNS namespace. The main
paper should report the label alphabet, depth bound, all cases, and the complete
`path_differences.jsonl` artifact together with the aggregate table.

Real Census cases establish external validity for the selected DNS structures,
but they do not replace the controlled cases: sparse observational data cannot
guarantee coverage of every binding conflict or update corner case.
