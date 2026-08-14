from __future__ import annotations

import sys
import unittest
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = EXPERIMENT_DIR.parents[1]
EXP2_DIR = REPO_ROOT / "experiments" / "experiment_02_symbolic_ablation"
sys.path.insert(0, str(EXPERIMENT_DIR))
sys.path.insert(0, str(EXP2_DIR))

from exp2.ablation import Method, evaluate_method  # noqa: E402
from exp2.model import load_cases  # noqa: E402
from exp2.resolver import ConcreteResolver  # noqa: E402
from exp3.census_updates import load_census_controlled_suite  # noqa: E402
from exp3.incremental import (  # noqa: E402
    graphdns_full_paths,
    graphdns_incremental_paths,
)
from exp3.veridns import (  # noqa: E402
    record_deltas,
    veridns_full_paths,
    veridns_incremental_paths,
)


class VeriDNSComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.static_dataset = (
            EXP2_DIR / "dataset" / "rfc_symbolic_cases.json"
        )
        cls.census_dataset = (
            EXP2_DIR / "dataset" / "census_real_cases.json"
        )
        cls.update_spec = (
            EXPERIMENT_DIR / "dataset" / "census_controlled_updates.json"
        )

    def test_static_rsg_has_pseudo_paths_but_graphdns_matches_oracle(self) -> None:
        veridns_false = 0
        graphdns_false = 0
        graphdns_missed = 0
        for case in load_cases(self.static_dataset):
            traces = ConcreteResolver(case).resolve_all()
            oracle = {trace.signature for trace in traces}
            _, veridns = evaluate_method(traces, Method.ALPHA_ONLY)
            _, graphdns = evaluate_method(traces, Method.FULL)
            veridns_false += len(veridns.predicted - oracle)
            graphdns_false += len(graphdns.predicted - oracle)
            graphdns_missed += len(oracle - graphdns.predicted)
        self.assertGreater(veridns_false, 0)
        self.assertEqual(graphdns_false, 0)
        self.assertEqual(graphdns_missed, 0)

    def test_incremental_expectations(self) -> None:
        suite = load_census_controlled_suite(
            self.update_spec,
            self.census_dataset,
        )
        expectations = suite.expectations
        cases = suite.cases
        grouped: dict[str, dict[str, object]] = {}
        for case in cases:
            grouped.setdefault(case.pair_id, {})[case.snapshot] = case

        observed_veridns_mismatch: set[str] = set()
        observed_veridns_consistent: set[str] = set()
        for pair_id, snapshots in grouped.items():
            before = snapshots["before"]
            after = snapshots["after"]
            self.assertEqual(len(record_deltas(before, after)), 1)
            self.assertGreater(len(before.records), 1000)
            before_traces = ConcreteResolver(before).resolve_all()
            after_traces = ConcreteResolver(after).resolve_all()

            veridns_before = veridns_full_paths(before_traces)
            veridns_after = veridns_full_paths(after_traces)
            veridns_local, _, _ = veridns_incremental_paths(
                before, after, veridns_before, veridns_after
            )
            if veridns_local == veridns_after:
                observed_veridns_consistent.add(pair_id)
            else:
                observed_veridns_mismatch.add(pair_id)

            graphdns_before = graphdns_full_paths(before_traces)
            graphdns_after = graphdns_full_paths(after_traces)
            graphdns_local, _ = graphdns_incremental_paths(
                before,
                after,
                before_traces,
                graphdns_before,
                graphdns_after,
            )
            self.assertEqual(graphdns_local, graphdns_after, pair_id)

        self.assertEqual(
            observed_veridns_mismatch,
            set(expectations["veridns_mismatch_pairs"]),
        )
        self.assertTrue(
            set(expectations["veridns_consistent_pairs"])
            <= observed_veridns_consistent
        )

    def test_controlled_updates_retain_census_background(self) -> None:
        suite = load_census_controlled_suite(
            self.update_spec,
            self.census_dataset,
        )
        base_counts = {
            case.id: len(case.records) for case in load_cases(self.census_dataset)
        }
        for metadata in suite.updates:
            self.assertIn(metadata["source_region"], {"bme.hu", "cmu.edu"})
            self.assertEqual(
                metadata["base_records"],
                base_counts[metadata["base_case_id"]],
            )
            self.assertEqual(
                abs(metadata["after_records"] - metadata["before_records"]),
                0 if metadata["operation"] == "MODIFY" else 1,
            )


if __name__ == "__main__":
    unittest.main()
