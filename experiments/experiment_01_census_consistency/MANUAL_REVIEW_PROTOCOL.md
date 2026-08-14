# Manual Review Protocol for Disagreements

## Scope

Review every row in `reports/manual_review.csv`. The unit is one unique
canonical vulnerability case in one Census region, not one duplicate witness
path. Raw witnesses remain available in `graphdns_findings.jsonl` and
`groot_findings.jsonl`.

The ground truth is the static authoritative DNS model shared by the two tools.
Do not use live DNS answers, caches, TTL evolution, retries, DNSSEC validation,
or network failures to adjudicate these cases.

## Review procedure

For each case:

1. Confirm that both executions have `status=ok` in `per_region_totals.csv`.
2. Inspect `case_key`, `key_quality`, and the raw outputs. First rule out a
   parser or report-granularity mismatch.
3. Open the complete source region at `region_path`; inspect the owner, target,
   NS/glue records, and all involved zone files. Do not inspect an extracted
   subset.
4. Reconstruct the relevant delegation or rewrite path under the paper's static
   semantics and decide whether the reported vulnerability exists.
5. Fill `review_status`, `adjudication`, `root_cause`, `reviewer`, and `notes`.
   `root_cause` must name the decisive record relation, not merely repeat the
   vulnerability label.

Recommended practice is independent review by two DNS-aware reviewers followed
by adjudication of disagreements. The final CSV should contain the adjudicated
label and reviewer identities.

## Adjudication labels

| Label | Meaning |
| --- | --- |
| `graphdns_true_groot_missed` | GraphDNS case exists under the shared model; GRoot omitted it |
| `groot_true_graphdns_missed` | GRoot case exists under the shared model; GraphDNS omitted it |
| `graphdns_false_positive` | GraphDNS-only case does not exist |
| `groot_false_positive` | GRoot-only case does not exist |
| `both_correct_different_granularity` | Both describe the same condition with different case aggregation |
| `model_scope_difference` | Difference is caused by a feature outside the declared shared scope |
| `parser_or_case_key_mismatch` | Raw reports agree, but normalization failed |
| `input_or_tool_failure` | Inputs or executions were not comparable despite an apparent success |
| `both_incorrect` | Neither report matches the source configuration |
| `undetermined` | Evidence is insufficient; explain why in `notes` |

## Completion gate

```bash
python3 experiments/experiment_01_census_consistency/review_disagreements.py \
  --run-dir experiments/runs/exp01_YYYYMMDD_HHMMSS \
  --require-complete
```

The experiment is not complete while this command exits non-zero. Report both
pre-adjudication set differences and post-adjudication causes; do not silently
discard parser, scope, or granularity differences.
