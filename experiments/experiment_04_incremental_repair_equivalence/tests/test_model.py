from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


EXPERIMENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp4.model import (  # noqa: E402
    DNSRecord,
    RepairAction,
    parse_graphdns_output,
)
from exp4.sampling import Region  # noqa: E402
from exp4.workflow import (  # noqa: E402
    CommandResult,
    _full_traversal_seconds,
    apply_actions,
    evaluate_region,
    instantiate_candidate,
    read_facts,
    screen_region,
)
from exp4.model import RepairCandidate  # noqa: E402


SAMPLE_OUTPUT = """
=== Bug Reports ===
[RB] start=a.example. query=missing.example. target=missing.example. server=ns.example. zone=example.
reason=path rewrites to target in known zone but target lacks A/AAAA
path=a.example. --CNAME/reach=1--> missing.example.

Summary: servers=1 zones=1 nodes=3 edges=2 paths=1 bugs=1
BugStats: RB=1
Timing: load_facts=0.1 build_base=0.2 build_semantic=0.3 build_invariants=0.0 compute_reach=0.1 traverse_dfs=0.4 detect_bugs=0.2 total=1.3

=== Repair Groups ===
[RepairGroup]
group_key = RB|missing.example.|ns.example.|example.|blackhole
kind = RB
grouped_reports = 3
representative = RB(a.example.)

=== Repair Candidates ===
[RepairCandidate]
bug = RB(a.example.)
priority = 1
risk = low
valid = true
grouped_reports = 3
group_key = RB|missing.example.|ns.example.|example.|blackhole
actions:
  ADD missing.example. A <TODO_IP>
target = ns.example. / example.
action_tsv = ADD\tns.example.\texample.\tmissing.example.\tA\t<TODO_IP>
rationale = "add address"
expected_effect = "terminate"
"""


class ModelTests(unittest.TestCase):
    def test_full_traversal_prefers_core_timing(self) -> None:
        self.assertEqual(
            _full_traversal_seconds(
                {"traverse_dfs": 3.0, "traverse_core": 2.0}
            ),
            2.0,
        )
        self.assertEqual(
            _full_traversal_seconds({"traverse_dfs": 3.0}),
            3.0,
        )

    def test_screening_skips_graphdns_after_record_limit(self) -> None:
        region = Region(
            sample_rank=1,
            name="large.example",
            path="/unused/large.example",
            sample_score="score",
            zone_file_count=1,
        )

        def fake_run_command(args, workdir, timeout_seconds):
            del args, timeout_seconds
            (workdir / "ZoneRecord.facts").write_text(
                "s.\tz.\ta.\tA\t192.0.2.1\n"
                "s.\tz.\tb.\tA\t192.0.2.2\n"
                "s.\tz.\tc.\tA\t192.0.2.3\n",
                encoding="utf-8",
            )
            return CommandResult(0, 0.0, "")

        with tempfile.TemporaryDirectory() as temp:
            with patch(
                "exp4.workflow.run_command",
                side_effect=fake_run_command,
            ) as mocked:
                result = screen_region(
                    region,
                    Path("preprocess"),
                    Path("semantic_graph"),
                    Path(temp),
                    1.0,
                    2,
                    "sampled",
                )
        self.assertEqual(result.status, "excluded_record_limit")
        self.assertEqual(mocked.call_count, 1)

    def test_parse_groups_candidates_and_reports(self) -> None:
        parsed = parse_graphdns_output(SAMPLE_OUTPUT)
        self.assertEqual(len(parsed.reports), 1)
        self.assertEqual(len(parsed.groups), 1)
        self.assertEqual(parsed.groups[0].grouped_reports, 3)
        self.assertEqual(len(parsed.candidates), 1)
        self.assertEqual(parsed.candidates[0].actions[0].operation, "ADD")
        self.assertTrue(parsed.candidates[0].contains_placeholder)

    def test_placeholder_and_facts_application(self) -> None:
        parsed = parse_graphdns_output(SAMPLE_OUTPUT)
        candidate: RepairCandidate = parsed.candidates[0]
        records = [
            DNSRecord("ns.example.", "example.", "example.", "NS", "ns.example.")
        ]
        actions, error, instantiated = instantiate_candidate(candidate, records)
        self.assertEqual(error, "")
        self.assertTrue(instantiated)
        self.assertIsNotNone(actions)
        updated = apply_actions(records, actions or [])
        self.assertEqual(len(updated), 2)
        self.assertTrue(updated[-1].rdata.startswith("192.0.2."))

    def test_modify_matches_incremental_no_duplicate_semantics(self) -> None:
        old = DNSRecord("ns.", "example.", "www.example.", "A", "192.0.2.1")
        new = DNSRecord("ns.", "example.", "www.example.", "A", "192.0.2.2")
        updated = apply_actions([old, old], [RepairAction("MODIFY", old, new)])
        self.assertEqual(updated, [new])

    def test_read_facts_matches_cpp_loader_for_multifield_soa(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            facts = Path(temp) / "ZoneRecord.facts"
            facts.write_text(
                "ns.example.\texample.\texample.\tSOA\tns.example."
                "\thostmaster.example.\t1\t3600\t600\t86400\t300\n"
                "ns.example.\texample.\texample.\tA\t192.0.2.1\n",
                encoding="utf-8",
            )
            self.assertEqual(
                read_facts(facts),
                [
                    DNSRecord(
                        "ns.example.",
                        "example.",
                        "example.",
                        "A",
                        "192.0.2.1",
                    )
                ],
            )

    def test_candidate_checkpoint_is_reused_after_interruption(self) -> None:
        baseline_text = SAMPLE_OUTPUT.replace(
            "grouped_reports = 3", "grouped_reports = 1"
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            facts = root / "before.facts"
            baseline = root / "baseline.txt"
            facts.write_text(
                "ns.example.\texample.\texample.\tNS\tns.example.\n",
                encoding="utf-8",
            )
            baseline.write_text(baseline_text, encoding="utf-8")
            region = Region(7, "example", str(root), "score", 1)
            candidate_row = {
                "region_rank": 7,
                "region": "example",
                "candidate_id": parse_graphdns_output(
                    baseline_text
                ).candidates[0].candidate_id,
                "group_key": "RB|missing.example.|ns.example.|example.|blackhole",
                "kind": "RB",
                "status": "ok",
                "accurate": True,
                "native_executable": False,
                "incremental_full_equivalent": True,
            }
            with patch(
                "exp4.workflow.validate_candidate",
                return_value=candidate_row,
            ) as validate:
                first_region, first_rows = evaluate_region(
                    region,
                    facts,
                    baseline,
                    root / "semantic_graph",
                    root / "scratch",
                    10.0,
                    "sampled",
                    False,
                    0,
                    2,
                )
                self.assertEqual(validate.call_count, 1)
                self.assertEqual(first_region["evaluated_candidates"], 1)
                self.assertEqual(len(first_rows), 1)

            with patch("exp4.workflow.validate_candidate") as validate:
                second_region, second_rows = evaluate_region(
                    region,
                    facts,
                    baseline,
                    root / "semantic_graph",
                    root / "scratch",
                    10.0,
                    "sampled",
                    False,
                    0,
                    2,
                )
                validate.assert_not_called()
                self.assertEqual(second_region["evaluated_candidates"], 1)
                self.assertEqual(second_rows, first_rows)

    def test_incremental_after_section_and_timing(self) -> None:
        text = """
=== Bug Reports ===
[RB] start=a.example. target=missing.example.
reason=blackhole
path=<none>
Summary: servers=1 zones=1 nodes=2 edges=1 paths=1 bugs=1
BugStats: RB=1
Timing: build_base=0.2 build_semantic=0.1 compute_reach=0.1 traverse_dfs=0.2 detect_bugs=0.1 total=0.7
IncrementalTiming: prepare=0.01 graph_update=0.02 local_traversal=0.03 report_refresh=0.04 total=0.10
new_reports:
=== Bug Reports ===
<none>
fixed_reports:
=== Bug Reports ===
[RB] start=a.example. target=missing.example.
reason=blackhole
path=<none>
all_reports_after:
=== Bug Reports ===
<none>
GraphStateDigest: phase=baseline active_edges=2 reachable_edges=1 active_edge_set=0000 edge_set=aaaa paths=1 path_set=bbbb terminal_states=1 state_set=cccc reports=1 report_set=dddd
GraphStateDigest: phase=post_update active_edges=3 reachable_edges=2 active_edge_set=9999 edge_set=eeee paths=2 path_set=ffff terminal_states=2 state_set=1111 reports=0 report_set=2222
"""
        parsed = parse_graphdns_output(text)
        self.assertEqual([len(section) for section in parsed.report_sections], [1, 0, 1, 0])
        self.assertEqual(parsed.incremental_timing["graph_update"], 0.02)
        self.assertEqual(parsed.all_reports_after, [])
        self.assertEqual(
            parsed.graph_state_digest("post_update")["edge_set"], "eeee"
        )
        self.assertEqual(
            parsed.graph_state_digest("baseline")["terminal_states"], "1"
        )


if __name__ == "__main__":
    unittest.main()
