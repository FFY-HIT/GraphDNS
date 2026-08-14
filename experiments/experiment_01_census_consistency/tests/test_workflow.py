from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


EXPERIMENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp1.sampling import Region  # noqa: E402
from exp1.workflow import _run_graphdns, _run_groot  # noqa: E402


class GRootAdapterTest(unittest.TestCase):
    def test_jsonl_command_contract(self) -> None:
        fixture = Path(__file__).resolve().parent / "fake_groot.py"
        with tempfile.TemporaryDirectory() as temp:
            workdir = Path(temp)
            region_dir = workdir / "region"
            region_dir.mkdir()
            region = Region(1, "child.example", str(region_dir), "00", 1)
            result = _run_groot(
                {
                    "command": [sys.executable, str(fixture), "{output}"],
                    "format": "jsonl",
                    "empty_output_means_zero": True,
                },
                region,
                workdir,
                workdir / "ZoneRecord.facts",
                3,
                30,
            )
            self.assertEqual(result.status, "ok")
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.findings[0].kind, "MG")


class GraphDNSOutputTest(unittest.TestCase):
    def _run_with_output(self, output: str):
        with tempfile.TemporaryDirectory() as temp:
            workdir = Path(temp)
            facts = workdir / "ZoneRecord.facts"
            facts.write_text("server\tzone\towner\tA\t192.0.2.1\n", encoding="utf-8")

            def fake_run(command, cwd, timeout, env):
                Path(command[-1]).write_text(output, encoding="utf-8")
                return 0, 0.01, "Output written\n"

            with patch("exp1.workflow._run_command", side_effect=fake_run):
                return _run_graphdns(
                    Path("/fake/semantic_graph"),
                    facts,
                    workdir,
                    30,
                    1,
                    0.001,
                    "",
                )

    def test_accepts_consistent_zero_bug_output(self) -> None:
        result = self._run_with_output(
            "=== Bug Reports ===\n"
            "Summary: servers=1 zones=1 nodes=2 edges=1 paths=1 bugs=0\n"
            "BugStats: <none>\n"
            "Timing: load_facts=0.1 total=0.2\n"
        )
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.findings, [])

    def test_rejects_output_without_summary(self) -> None:
        result = self._run_with_output(
            "=== Bug Reports ===\n"
            "BugStats: <none>\n"
            "Timing: load_facts=0.1 total=0.2\n"
        )
        self.assertEqual(result.status, "parse_error")
        self.assertIn("missing Summary", result.error)

    def test_rejects_report_count_mismatch(self) -> None:
        result = self._run_with_output(
            "[MG] zoneCut=child.example. nameserver=ns.child.example.\n"
            "reason=missing glue\n"
            "path=x\n\n"
            "Summary: servers=1 zones=1 nodes=2 edges=1 paths=1 bugs=2\n"
            "BugStats: MG=2\n"
            "Timing: load_facts=0.1 total=0.2\n"
        )
        self.assertEqual(result.status, "parse_error")
        self.assertIn("report count mismatch", result.error)

    def test_passes_sampled_server_view_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workdir = Path(temp)
            facts = workdir / "ZoneRecord.facts"
            facts.write_text(
                "server\tzone\towner\tA\t192.0.2.1\n",
                encoding="utf-8",
            )
            observed_command: list[str] = []

            def fake_run(command, cwd, timeout, env):
                observed_command.extend(command)
                Path(command[-1]).write_text(
                    "=== Bug Reports ===\n"
                    "Summary: servers=1 zones=1 nodes=2 edges=1 paths=1 bugs=0\n"
                    "BugStats: <none>\n"
                    "Timing: load_facts=0.1 total=0.2\n",
                    encoding="utf-8",
                )
                return 0, 0.01, "Output written\n"

            with patch("exp1.workflow._run_command", side_effect=fake_run):
                result = _run_graphdns(
                    Path("/fake/semantic_graph"),
                    facts,
                    workdir,
                    30,
                    1,
                    0.001,
                    "",
                    "sampled",
                )

            self.assertEqual(result.status, "ok")
            mode_index = observed_command.index("--server-views")
            self.assertEqual(observed_command[mode_index + 1], "sampled")


if __name__ == "__main__":
    unittest.main()
