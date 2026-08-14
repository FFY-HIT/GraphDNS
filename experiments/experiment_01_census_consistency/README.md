# Experiment 01: Census Consistency with GRoot

## Research question

On the same complete Census regions, do GraphDNS and GRoot report the same
logical DNS vulnerabilities? The experiment samples **100,000 whole region
directories**, runs both systems independently for every region, and compares
their normalized, case-level findings.

The experiment reports:

1. the GraphDNS/GRoot intersection;
2. GraphDNS-only and GRoot-only cases;
3. raw and unique finding counts for every region and every bug kind;
4. per-kind Jaccard agreement and two directional coverage rates; and
5. a review sheet containing every disagreement. Final claims are blocked until
   every disagreement has a human annotation.

## Directory layout

```text
experiment_01_census_consistency/
  config.example.json       Reproducible run configuration
  run_experiment.py         Sampling, execution, checkpointing, and reporting
  analyze_results.py        Regenerate comparison reports from SQLite
  review_disagreements.py   Validate/summarize human adjudication
  validate_groot_output.py  Check the external GRoot adapter contract
  exp1/                     Experiment implementation
  tests/                    Parser and comparison tests
```

A run creates only the following organized output:

```text
experiments/runs/exp01_<timestamp>/
  manifest.json             Immutable protocol and tool configuration
  sample_manifest.csv       The 100,000 selected complete regions
  results.sqlite3           Checkpointed executions and individual findings
  reports/
    summary.json
    report.md
    per_region_totals.csv
    per_region_by_kind.csv
    agreement_by_kind.csv
    graphdns_findings.jsonl
    groot_findings.jsonl
    intersection.jsonl
    graphdns_only.jsonl
    groot_only.jsonl
    run_failures.csv
    manual_review.csv
```

No Census directory or zone file is copied. Temporary facts and tool outputs are
deleted after their parsed results have been committed to SQLite.

## Fair-comparison contract

Both systems receive the same region directory. GraphDNS is run as:

```text
preprocess <region-directory>
semantic_graph ZoneRecord.facts --reports-only --server-views sampled
```

`server_view_coverage` controls whether the input exhaustively contains every
authoritative `(nameserver, zone)` copy. Use `sampled` for Census: a missing copy
then means "not observed" and is not sufficient evidence for LD. Use `complete`
only for controlled inputs whose server/zone inventory is exhaustive; in that
mode, a known delegated server that lacks the child zone is reported as LD.

GRoot is external to this repository. Its command is configured as an argument
vector and must produce one JSON object per finding. Aggregate counts are not
sufficient for an intersection experiment and are therefore rejected.

The GRoot wrapper must use the same static-authoritative assumptions, supported
record types, and shared vulnerability definitions as GraphDNS. Cases outside
that common scope must be retained and labeled `model_scope_difference` during
manual review rather than silently removed.

Required GRoot JSONL field:

```json
{"kind":"MG"}
```

Recommended fields:

```json
{
  "kind": "MG",
  "zone_cut": "example.com.",
  "nameserver": "ns1.example.com.",
  "start_name": "",
  "query": "",
  "target": "",
  "server": "",
  "zone": "com.",
  "reason": "missing in-bailiwick glue",
  "path": "..."
}
```

Fields needed for a strong comparable key are:

| Kind | Required GRoot fields |
| --- | --- |
| LD, MG | `zone_cut`, `nameserver` |
| DI | `zone_cut` |
| CZD | `zone_cut` (or `cycle_zones` when neither tool has a cut anchor) |
| RL | `start_name`, plus the repeated query in `target` |
| RB, ML | `start_name`, `target` |

The GRoot command may use these placeholders:

| Placeholder | Meaning |
| --- | --- |
| `{region}` | absolute path to the selected Census directory |
| `{region_name}` | Census directory name |
| `{workdir}` | isolated temporary directory for this run |
| `{output}` | path where GRoot should write JSONL |
| `{facts}` | GraphDNS `ZoneRecord.facts`, if a wrapper needs it |
| `{repo}` | absolute path to this GraphDNS repository |

If the native GRoot output differs, write a thin wrapper that converts each
finding to the schema above. Do not infer case-level intersections from summary
counts.

Validate the wrapper on one region before launching the 100,000-region run:

```bash
python3 experiments/experiment_01_census_consistency/validate_groot_output.py \
  --input /tmp/groot_findings.jsonl \
  --format jsonl
```

The command must report `weak_case_keys: 0` and exit successfully.

## Configuration

Create a local configuration from `config.example.json` and set the GRoot
command. Paths may be absolute or relative to the repository root.

The supplied Census configurations set `"server_view_coverage": "sampled"`.
Do not change it to `complete` unless every delegated nameserver view is present
in each selected region.

On Ubuntu, install the GraphDNS build dependencies first:

```bash
sudo apt update
sudo apt install -y build-essential nlohmann-json3-dev python3
```

```bash
cp experiments/experiment_01_census_consistency/config.example.json \
   experiments/experiment_01_census_consistency/config.local.json
```

## Complete Ubuntu run

```bash
python3 experiments/experiment_01_census_consistency/run_experiment.py \
  --config experiments/experiment_01_census_consistency/config.local.json \
  --build
```

To run GraphDNS alone on 100,000 regions without GRoot:

```bash
cp experiments/experiment_01_census_consistency/config.graphdns_only.example.json \
   experiments/experiment_01_census_consistency/config.graphdns_only.json

python3 experiments/experiment_01_census_consistency/run_experiment.py \
  --config experiments/experiment_01_census_consistency/config.graphdns_only.json \
  --graphdns-only \
  --workers 8 \
  --build
```

The GraphDNS-only configuration uses a fixed seed, samples 100,000 complete
directories, runs eight regions concurrently, and gives an individual region
up to 1,800 seconds. The larger timeout is needed for Census directories such
as country-code second-level domains that may contain more than one million
records.

Before sampling starts, the driver runs a compatibility probe against the
built-in GraphDNS example. A run is rejected unless the binary:

1. supports `--reports-only`;
2. emits `Summary`, `BugStats`, and `Timing`; and
3. reports counts consistent with the individually parsed bug reports.

This prevents a missing or redirected GraphDNS output from being recorded as
"zero vulnerabilities".

The default sample size in the example configuration is 100,000 and the seed is
fixed. Resume an interrupted GraphDNS-only run by passing its directory:

```bash
python3 experiments/experiment_01_census_consistency/run_experiment.py \
  --config experiments/experiment_01_census_consistency/config.graphdns_only.json \
  --graphdns-only \
  --run-dir experiments/runs/exp01_YYYYMMDD_HHMMSS \
  --resume
```

Do not pass `--build` when resuming. A changed source or binary intentionally
invalidates the old run manifest; after rebuilding GraphDNS, start a new run.

The main GraphDNS-only outputs are:

| File | Meaning |
| --- | --- |
| `reports/graphdns_per_region.csv` | One row per region: nodes, edges, paths, and counts for LD/DI/MG/CZD/RL/RB/ML/STALE |
| `reports/graphdns_findings.jsonl` | Every individual GraphDNS report and witness |
| `reports/per_region_totals.csv` | Total raw reports and unique cases per region |
| `reports/per_region_by_kind.csv` | Per-region counts split by vulnerability kind |
| `reports/summary.json` | GraphDNS totals, per-kind counts, and regions with findings |
| `reports/report.md` | Human-readable GraphDNS-only summary |
| `reports/run_failures.csv` | Only GraphDNS regions that timed out or failed |

## Audit GraphDNS findings

A completed report is evidence under the selected Census snapshot, not by
itself live-DNS ground truth.  In particular, `--server-views sampled` must not
turn an absent delegated-child file into a deterministic DI/LD finding.

Audit every report against the normalized records used by the run:

```bash
python3 experiments/experiment_01_census_consistency/audit_graphdns_findings.py \
  --findings experiments/runs/exp01_YYYYMMDD_HHMMSS/reports/graphdns_findings.jsonl \
  --preprocess-bin experiments/bin/preprocess \
  --output-dir experiments/runs/exp01_YYYYMMDD_HHMMSS/audit
```

The command writes:

| File | Meaning |
| --- | --- |
| `audit/finding_audit.csv` | Per-report status and the concrete supporting or conflicting evidence |
| `audit/finding_audit_summary.json` | Counts by vulnerability kind and audit status |
| `audit/facts_cache/` | Reusable normalized facts for affected regions |

The status `snapshot-confirmed` means that the selected zone files contain the
records needed to reproduce the predicate. `indeterminate` means that a
required child or server view is absent. `false-positive` identifies a
contradiction in the modeled path. `snapshot-confirmed-overlap` is a valid
predicate that shares its root cause with another report, such as DI glue
mismatch caused by the same missing glue already reported as MG. Publication
claims should additionally use manual review or an independent DNS snapshot;
do not describe every snapshot-confirmed case as a live operational fault.

## Plot the Census detection results

Generate two independent publication figures from a completed GraphDNS-only
run:

```bash
python3 experiments/experiment_01_census_consistency/plot_detection_results.py \
  --reports-dir experiments/runs/exp01_YYYYMMDD_HHMMSS/reports \
  --output-dir experiments/runs/exp01_YYYYMMDD_HHMMSS/figures
```

The vulnerability-type figure uses deduplicated canonical cases. The regional
figure uses raw reports because it visualizes witness concentration. It
produces:

| File prefix | Meaning |
| --- | --- |
| `census_vulnerability_distribution_stacked_bar` | Raw reports for the eight most affected regions plus an aggregate of the remaining affected regions |
| `census_vulnerability_type_counts` | Unique cases for LD/DI/MG/CZD/RL/RB/ML/SR; the total is excluded |

Each figure is exported as editable SVG, PDF, 600-dpi PNG, and 600-dpi TIFF.
The output directory also contains the exact source-data CSV files and
`figure_notes.md` with suggested captions and interpretation guardrails.

`graphdns_only.jsonl`, `intersection.jsonl`, and the agreement fields are
comparison outputs. They are not GraphDNS finding files and are intentionally
empty when GRoot is not run.

For a smoke test, override the sample size without editing the configuration:

```bash
python3 experiments/experiment_01_census_consistency/run_experiment.py \
  --config experiments/experiment_01_census_consistency/config.local.json \
  --sample-size 10 \
  --workers 2 \
  --build
```

## Agreement metrics

Comparison is performed on unique canonical cases, while all raw witness reports
remain available in the JSONL files.

For bug kind `k`:

```text
Jaccard(k) = |GraphDNS(k) intersect GRoot(k)| / |GraphDNS(k) union GRoot(k)|
GRoot coverage = intersection / |GRoot(k)|
GraphDNS coverage = intersection / |GraphDNS(k)|
```

The primary shared scope is `LD, DI, MG, CZD, RL, RB, ML`. GraphDNS-only
extensions such as `STALE` are retained but excluded from the shared-scope
agreement headline.

Canonical case identities are deliberately coarser than witness paths:

| Kind | Case identity within one Census region |
| --- | --- |
| LD, MG | zone cut + nameserver |
| DI | zone cut |
| CZD | zone-cut anchor; cycle-zone set is the fallback |
| RL | start name + repeated query |
| RB, ML | start name + rewritten target |
| STALE | owner + resource record text |

Every original witness remains in `*_findings.jsonl`. A weak key caused by
missing GRoot fields is marked `key_quality=weak`. With the default
`require_strong_keys=true`, such GRoot output is rejected before comparison;
the final completion gate also requires zero weak keys.

## Manual analysis of every disagreement

Open `reports/manual_review.csv` and complete these columns for every row:

- `review_status=completed`
- `adjudication`
- `root_cause`
- `reviewer`
- `notes`

Allowed adjudications are listed in the CSV and include false positives,
different report granularity, scope differences, and parser/key mismatches.
Then run:

```bash
python3 experiments/experiment_01_census_consistency/review_disagreements.py \
  --run-dir experiments/runs/exp01_YYYYMMDD_HHMMSS \
  --require-complete
```

This produces `manual_review_summary.csv` and `manual_review_report.md`. With
`--require-complete`, the command exits non-zero if even one disagreement has
not been reviewed.

The evidence rules and adjudication taxonomy are specified in
`MANUAL_REVIEW_PROTOCOL.md`.

## Tests

```bash
python3 -m unittest discover \
  -s experiments/experiment_01_census_consistency/tests \
  -v
```
