from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class MissingGlueBailiwickBoundaryTest(unittest.TestCase):
    def test_nameserver_equal_to_cut_requires_glue(self) -> None:
        compiler = shutil.which("g++")
        if compiler is None:
            self.skipTest("g++ is not available")

        repo_root = Path(__file__).resolve().parents[3]
        source = repo_root / "src" / "semantic_graph.cpp"
        fixture = (
            repo_root
            / "experiments"
            / "experiment_06_supplementary"
            / "fixtures"
            / "mg_bailiwick_boundary.facts"
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            binary = Path(temporary_directory) / "semantic_graph"
            subprocess.run(
                [
                    compiler,
                    "-O2",
                    "-std=c++17",
                    "-fopenmp",
                    str(source),
                    "-o",
                    str(binary),
                ],
                check=True,
                cwd=repo_root,
                timeout=120,
            )
            result = subprocess.run(
                [
                    str(binary),
                    str(fixture),
                    "--reports-only",
                    "--server-views",
                    "sampled",
                ],
                check=True,
                cwd=repo_root,
                capture_output=True,
                text=True,
                timeout=30,
            )

        output = result.stdout
        self.assertIn(
            "[MG] zoneCut=child.parent.example. "
            "nameserver=child.parent.example.",
            output,
        )
        self.assertIn(
            "[MG] zoneCut=deep.parent.example. "
            "nameserver=ns.deep.parent.example.",
            output,
        )
        self.assertNotIn("nameserver=ns.external.example.", output)
        self.assertIn("BugStats: MG=2", output)


if __name__ == "__main__":
    unittest.main()
