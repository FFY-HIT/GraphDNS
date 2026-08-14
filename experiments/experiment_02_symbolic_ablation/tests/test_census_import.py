from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp2.census import dataset_payload, load_census_region  # noqa: E402
from exp2.model import load_cases  # noqa: E402
from exp2.resolver import ConcreteResolver  # noqa: E402


class CensusImportTests(unittest.TestCase):
    def test_complete_dname_region_is_imported_with_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            region = Path(temporary) / "real.example"
            region.mkdir()
            (region / "metadata.json").write_text(
                json.dumps(
                    {
                        "ZoneFiles": [
                            {
                                "FileName": "real.example..txt",
                                "NameServer": "ns.real.example.",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (region / "real.example..txt").write_text(
                "\n".join(
                    [
                        "real.example. IN SOA ns.real.example. hostmaster.real.example. 1 2 3 4 5",
                        "legacy.real.example. IN DNAME active.real.example.",
                        "www.active.real.example. IN A 192.0.2.1",
                        "*.active.real.example. IN A 192.0.2.2",
                        "child.active.real.example. IN NS ns.child.real.example.",
                    ]
                ),
                encoding="utf-8",
            )

            parsed = load_census_region(region)
            self.assertIsNotNone(parsed)
            assert parsed is not None
            self.assertEqual(parsed.features.dname, 1)
            self.assertEqual(parsed.features.wildcard_below_dname_target, 1)
            self.assertEqual(parsed.features.exact_below_dname_target, 2)
            self.assertEqual(parsed.features.delegation_dname_overlap, 1)

            payload = dataset_payload([parsed], label_limit=4, max_prefix_depth=1)
            dataset = Path(temporary) / "cases.json"
            dataset.write_text(json.dumps(payload), encoding="utf-8")
            cases = load_cases(dataset)
            self.assertEqual(len(cases), 1)
            traces = ConcreteResolver(cases[0]).resolve_all()
            self.assertTrue(any(":DNAME" in event.label for trace in traces for event in trace.events))

    def test_incomplete_region_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            region = Path(temporary) / "partial.example"
            region.mkdir()
            (region / "metadata.json").write_text(
                json.dumps(
                    {
                        "ZoneFiles": [
                            {
                                "FileName": "missing.txt",
                                "NameServer": "ns.partial.example.",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            self.assertIsNone(load_census_region(region))
