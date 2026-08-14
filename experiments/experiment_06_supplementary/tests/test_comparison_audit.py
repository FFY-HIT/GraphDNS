from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "analyze_groot_comparison.py"
SPEC = importlib.util.spec_from_file_location("analyze_groot_comparison", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ComparisonAuditTests(unittest.TestCase):
    def test_rfc_glue_scope_includes_delegated_cut(self) -> None:
        self.assertTrue(
            MODULE.is_descendant_or_same(
                "ns.child.example.", "child.example."
            )
        )
        self.assertTrue(
            MODULE.is_descendant_or_same(
                "child.example.", "child.example."
            )
        )
        self.assertFalse(
            MODULE.is_descendant_or_same("ns.example.", "child.example.")
        )

    def test_ld_and_single_cut_czd_share_semantic_key(self) -> None:
        ld = {
            "kind": "LD",
            "finding": {"kind": "LD", "zone_cut": "child.example."},
        }
        czd = {
            "kind": "CZD",
            "case_key": "CZD|zones=child.example.",
            "finding": {
                "kind": "CZD",
                "case_key": "CZD|zones=child.example.",
            },
        }
        self.assertEqual(MODULE.semantic_key(ld), MODULE.semantic_key(czd))

    def test_single_zone_czd_and_apex_mg_are_scope_classified(self) -> None:
        czd = {
            "region_name": "example.com",
            "kind": "CZD",
            "case_key": "CZD|zones=www.example.com.",
            "finding": {
                "kind": "CZD",
                "case_key": "CZD|zones=www.example.com.",
            },
        }
        mg = {
            "region_name": "example.com",
            "kind": "MG",
            "case_key": "MG|zone_cut=example.com.|nameserver=ns.example.com.",
            "finding": {
                "kind": "MG",
                "zone_cut": "example.com.",
                "nameserver": "ns.example.com.",
            },
        }
        counts, unresolved = MODULE.classify_disagreements(
            [], [czd, mg], "sampled"
        )
        self.assertEqual(
            counts["single_zone_cycle_from_child_apex_ns_modeling"], 1
        )
        self.assertEqual(
            counts["apex_ns_address_outside_delegation_glue_scope"], 1
        )
        self.assertEqual(unresolved, [])


if __name__ == "__main__":
    unittest.main()
