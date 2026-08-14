from __future__ import annotations

import sys
import unittest
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp4.reporting import summarize  # noqa: E402
from exp4 import SUPPORTED_REPAIR_KINDS  # noqa: E402


class ReportingTests(unittest.TestCase):
    def test_stale_reports_are_repair_supported(self) -> None:
        self.assertIn("STALE", SUPPORTED_REPAIR_KINDS)

    def test_micro_metrics(self) -> None:
        regions = [
            {
                "repairable_reports": 4,
                "root_cause_groups": 2,
                "root_cause_merge_rate": 0.5,
                "candidate_accuracy": 0.5,
                "records": 10,
                "bugs": 4,
                "evaluated_candidates": 2,
                "incremental_full_equivalence_rate": 1.0,
            }
        ]
        candidates = [
            {
                "kind": "RB",
                "status": "ok",
                "accurate": True,
                "native_executable": True,
                "incremental_full_equivalent": True,
                "incremental_graph_update_seconds": 1.0,
                "incremental_local_traversal_seconds": 1.0,
                "incremental_graph_traversal_seconds": 2.0,
                "full_graph_build_seconds": 4.0,
                "full_traversal_seconds": 2.0,
                "full_graph_traversal_seconds": 6.0,
            },
            {
                "kind": "RB",
                "status": "ok",
                "accurate": False,
                "native_executable": True,
                "incremental_full_equivalent": True,
                "incremental_graph_update_seconds": 1.0,
                "incremental_local_traversal_seconds": 1.0,
                "incremental_graph_traversal_seconds": 2.0,
                "full_graph_build_seconds": 4.0,
                "full_traversal_seconds": 2.0,
                "full_graph_traversal_seconds": 6.0,
            },
        ]
        summary = summarize(regions, candidates)
        self.assertEqual(
            summary["root_cause_grouping"]["overall_merge_rate_micro"], 0.5
        )
        self.assertEqual(
            summary["candidate_accuracy"]["overall_accuracy_micro"], 0.5
        )
        self.assertEqual(
            summary["incremental_equivalence"]["report_set_equivalence_rate"], 1.0
        )
        self.assertEqual(
            summary["incremental_equivalence"]["full_state_equivalence_rate"],
            1.0,
        )
        self.assertEqual(
            summary["incremental_equivalence"][
                "reachable_edge_set_equivalence_rate"
            ],
            1.0,
        )
        self.assertEqual(summary["timing"]["graph_traversal_speedup"], 3.0)


if __name__ == "__main__":
    unittest.main()
