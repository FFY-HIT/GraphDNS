from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


expand_module = load_module(
    "expand_controlled_updates",
    ROOT / "expand_controlled_updates.py",
)
group_module = load_module(
    "run_grouping_stress",
    ROOT / "run_grouping_stress.py",
)


class ExpansionAndGroupingTests(unittest.TestCase):
    def test_expansion_preserves_one_change_per_case(self) -> None:
        payload = {
            "expectations": {
                "veridns_mismatch_pairs": ["add_dname"],
                "veridns_consistent_pairs": [],
                "graphdns_all_consistent": True,
            },
            "updates": [
                {
                    "pair_id": "add_dname",
                    "description": "template",
                    "explicit_queries": [
                        {
                            "name": "x.graphdns-exp-dname.example.",
                            "symbol_suffix": "example.",
                        }
                    ],
                    "shared_records": [],
                    "change": {
                        "operation": "ADD",
                        "new_record": {
                            "id": "exp3_dname",
                            "server": "ns.example.",
                            "zone": "example.",
                            "owner": "graphdns-exp-dname.example.",
                            "type": "DNAME",
                            "value": "target.example.",
                        },
                    },
                }
            ],
        }
        expanded = expand_module.expand(payload, 3)
        self.assertEqual(len(expanded["updates"]), 3)
        self.assertEqual(
            len(expanded["expectations"]["veridns_mismatch_pairs"]), 3
        )
        self.assertTrue(
            all("change" in update for update in expanded["updates"])
        )

    def test_grouping_fixture_has_declared_multiplicities(self) -> None:
        facts, expected = group_module.build_facts(2)
        self.assertEqual(len(expected), 10)
        self.assertEqual(sorted(expected.values()), [1, 1, 2, 2, 4, 4, 8, 8, 16, 16])
        self.assertEqual(
            sum(expected.values()),
            sum("CNAME" in line for line in facts.splitlines()),
        )


if __name__ == "__main__":
    unittest.main()
