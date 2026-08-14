from __future__ import annotations

import sys
import unittest
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT_DIR))

from run_groot_core_timing import (  # noqa: E402
    parse_graphdns_timing,
    parse_groot_stats,
    percentile,
)


class GRootCoreTimingTests(unittest.TestCase):
    def test_parse_official_stats(self) -> None:
        build, check = parse_groot_stats(
            "Time to build label graph and zone graphs: 0.000553839s\n"
            "Time to check all user jobs: 0.001714444s\n"
        )
        self.assertAlmostEqual(build, 0.000553839)
        self.assertAlmostEqual(check, 0.001714444)

    def test_percentile_interpolates(self) -> None:
        self.assertEqual(percentile([1.0, 2.0, 3.0], 0.5), 2.0)
        self.assertAlmostEqual(percentile([1.0, 3.0], 0.95), 2.9)

    def test_parse_graphdns_timing(self) -> None:
        values = parse_graphdns_timing(
            "Timing: load_facts=0.01 build_base=0.02 build_semantic=0.03 "
            "build_invariants=0.04 compute_reach=0.05 traverse_dfs=0.06 "
            "traverse_core=0.05 detect_inline=0.01 detect_bugs=0.07 total=0.28\n"
        )
        self.assertEqual(values["total"], 0.28)
        self.assertEqual(values["build_semantic"], 0.03)


if __name__ == "__main__":
    unittest.main()
