from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp4.sampling import sample_complete_regions  # noqa: E402


class SamplingTests(unittest.TestCase):
    def test_deterministic_complete_region_sampling(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for index in range(8):
                region = root / f"r{index}.example"
                region.mkdir()
                metadata = {
                    "ZoneFiles": [
                        {
                            "FileName": "zone.txt",
                            "NameServer": "ns.example.",
                        }
                    ]
                }
                (region / "metadata.json").write_text(
                    json.dumps(metadata), encoding="utf-8"
                )
                if index != 7:
                    (region / "zone.txt").write_text(
                        "example. IN A 192.0.2.1\n", encoding="utf-8"
                    )
            first = sample_complete_regions(root, 4, 17)
            second = sample_complete_regions(root, 4, 17)
            self.assertEqual(first, second)
            self.assertEqual(len(first), 4)
            self.assertNotIn("r7.example", {region.name for region in first})


if __name__ == "__main__":
    unittest.main()
