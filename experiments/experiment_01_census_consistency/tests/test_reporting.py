from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp1.model import Finding  # noqa: E402
from exp1.reporting import generate_reports, summarize_manual_review  # noqa: E402
from exp1.sampling import Region  # noqa: E402
from exp1.storage import ExecutionResult, add_regions, connect, save_execution  # noqa: E402


class ReportingTest(unittest.TestCase):
    def test_graphdns_only_keeps_per_region_case_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            connection = connect(root / "results.sqlite3")
            region = Region(1, "solo.example", "/data/solo.example", "00", 1)
            add_regions(connection, [region])
            finding = Finding(
                kind="RB",
                start_name="alias.solo.example.",
                target="missing.solo.example.",
            )
            save_execution(
                connection,
                region.name,
                ExecutionResult(
                    "graphdns",
                    "ok",
                    0,
                    0.1,
                    4,
                    [finding],
                    {
                        "summary": {
                            "servers": 1,
                            "zones": 1,
                            "nodes": 9,
                            "edges": 11,
                            "paths": 7,
                            "bugs": 1,
                        }
                    },
                ),
            )
            reports = root / "reports"
            summary = generate_reports(
                connection,
                reports,
                ["RB"],
                expected_systems=("graphdns",),
            )
            connection.close()
            self.assertEqual(summary["run_mode"], "graphdns_only")
            self.assertFalse(summary["comparison_available"])
            self.assertEqual(summary["graphdns"]["failed_regions"], 0)
            self.assertEqual(summary["graphdns"]["regions_with_reports"], 1)
            self.assertEqual(summary["graphdns"]["unique_cases"], 1)
            with (reports / "per_region_totals.csv").open(
                "r", newline="", encoding="utf-8"
            ) as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row["graphdns_unique_cases"], "1")
            self.assertEqual(row["paired_comparison"], "False")
            with (reports / "run_failures.csv").open(
                "r", newline="", encoding="utf-8"
            ) as handle:
                self.assertEqual(list(csv.DictReader(handle)), [])
            with (reports / "graphdns_per_region.csv").open(
                "r", newline="", encoding="utf-8"
            ) as handle:
                graph_row = next(csv.DictReader(handle))
            self.assertEqual(graph_row["nodes"], "9")
            self.assertEqual(graph_row["edges"], "11")
            self.assertEqual(graph_row["paths"], "7")
            self.assertEqual(graph_row["RB"], "1")
            self.assertEqual(graph_row["total_bugs"], "1")
            self.assertEqual(graph_row["status"], "ok")

    def test_intersection_difference_and_manual_review_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            connection = connect(root / "results.sqlite3")
            region = Region(1, "example.com", "/data/example.com", "00", 1)
            add_regions(connection, [region])
            common_graph = Finding(kind="MG", zone_cut="child.example.", nameserver="ns.child.example.")
            common_groot = Finding(kind="Missing Glue Records", zone_cut="child.example.", nameserver="ns.child.example.")
            graph_only = Finding(kind="RB", start_name="alias.example.", target="missing.example.")
            save_execution(
                connection,
                region.name,
                ExecutionResult("graphdns", "ok", 0, 0.1, 10, [common_graph, graph_only], {}),
            )
            save_execution(
                connection,
                region.name,
                ExecutionResult("groot", "ok", 0, 0.2, 10, [common_groot], {}),
            )
            reports = root / "reports"
            summary = generate_reports(connection, reports, ["MG", "RB"])
            connection.close()
            self.assertEqual(summary["shared_scope"]["intersection"], 1)
            self.assertEqual(summary["shared_scope"]["graphdns_only"], 1)
            self.assertEqual(summary["system_totals"]["graphdns"]["raw_reports"], 2)
            self.assertEqual(summary["system_totals"]["graphdns"]["unique_cases"], 2)
            self.assertEqual(summary["manual_review"]["pending"], 1)
            _, exit_code = summarize_manual_review(
                reports / "manual_review.csv", reports, require_complete=True
            )
            self.assertEqual(exit_code, 1)

            with (reports / "manual_review.csv").open(
                "r", newline="", encoding="utf-8"
            ) as handle:
                reader = csv.DictReader(handle)
                rows = list(reader)
                fieldnames = list(reader.fieldnames or [])
            rows[0]["review_status"] = "completed"
            rows[0]["adjudication"] = "graphdns_true_groot_missed"
            rows[0]["root_cause"] = "GRoot did not enumerate the rewrite target"
            rows[0]["reviewer"] = "tester"
            with (reports / "manual_review.csv").open(
                "w", newline="", encoding="utf-8"
            ) as handle:
                writer = csv.DictWriter(handle, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            reviewed, exit_code = summarize_manual_review(
                reports / "manual_review.csv", reports, require_complete=True
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(reviewed["completed"], 1)


if __name__ == "__main__":
    unittest.main()
