from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp1.sampling import sample_complete_regions  # noqa: E402


class SamplingTest(unittest.TestCase):
    def _region(self, root: Path, name: str, complete: bool = True) -> None:
        region = root / name
        region.mkdir()
        metadata = {
            "ZoneFiles": [
                {"FileName": f"{name}.txt", "NameServer": f"ns.{name}."}
            ]
        }
        (region / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
        if complete:
            (region / f"{name}.txt").write_text(
                f"{name}. IN A 192.0.2.1\n", encoding="utf-8"
            )

    def test_sampling_is_deterministic_and_skips_partial_folders(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for index in range(8):
                self._region(root, f"r{index}.example")
            self._region(root, "partial.example", complete=False)
            first, first_stats = sample_complete_regions(root, 4, 17)
            second, second_stats = sample_complete_regions(root, 4, 17)
            self.assertEqual([r.name for r in first], [r.name for r in second])
            self.assertNotIn("partial.example", {r.name for r in first})
            self.assertEqual(first_stats.directory_regions, 9)
            self.assertEqual(second_stats.complete_regions, 4)


if __name__ == "__main__":
    unittest.main()
