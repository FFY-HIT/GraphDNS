from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
import tempfile
import json


MODULE_PATH = Path(__file__).resolve().parents[1] / "groot_jsonl_wrapper.py"
SPEC = importlib.util.spec_from_file_location("groot_jsonl_wrapper", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class GRootWrapperTests(unittest.TestCase):
    def test_shared_property_mapping(self) -> None:
        row = MODULE.canonical_from_property(
            {
                "Property": "Rewrite Blackholing",
                "Query": "www.example.",
                "Violation": {"RewriteTarget": "missing.example."},
            }
        )
        self.assertEqual(row["kind"], "RB")
        self.assertEqual(row["start"], "www.example.")
        self.assertEqual(row["target"], "missing.example.")

    def test_missing_glue_mapping(self) -> None:
        row = MODULE.canonical_from_lint(
            {
                "Server": "ns.parent.",
                "Zone": "parent.",
                "Violation": "Missing Glue Record",
                "Resource Record": "child.parent.   NS   ns.child.parent.",
            }
        )
        self.assertEqual(row["kind"], "MG")
        self.assertEqual(row["zone_cut"], "child.parent.")
        self.assertEqual(row["nameserver"], "ns.child.parent.")

    def test_symbolic_query_is_normalized(self) -> None:
        self.assertEqual(MODULE.normalize_name("~{ }.child.example."), "child.example.")

    def test_rewrite_cycle_maps_to_rl(self) -> None:
        row = MODULE.canonical_from_property(
            {
                "Property": "Cyclic Zone Dependency",
                "Loop": [
                    {"AnswerTag": 1, "NS": "ns.example.", "Query": "x.example."}
                ],
            }
        )
        self.assertEqual(row["kind"], "RL")

    def test_lame_query_is_mapped_back_to_delegation_cut(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            region = Path(temporary)
            (region / "metadata.json").write_text(
                json.dumps(
                    {
                        "ZoneFiles": [
                            {
                                "FileName": "parent.txt",
                                "NameServer": "ns.parent.example.",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (region / "parent.txt").write_text(
                "child.example. IN NS ns.child.example.\n",
                encoding="utf-8",
            )
            index = MODULE.DelegationIndex(region)
            row = MODULE.canonical_from_property(
                {
                    "Property": "Lame Delegation",
                    "Query": "www.child.example.",
                    "Violation": {"Nameserver2": "ns.child.example."},
                },
                index,
            )
        self.assertEqual(row["zone_cut"], "child.example.")


if __name__ == "__main__":
    unittest.main()
