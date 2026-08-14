from __future__ import annotations

import sys
import unittest
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp2.ablation import Method, evaluate_method  # noqa: E402
from exp2.bugs import detect_path_bugs  # noqa: E402
from exp2.model import load_cases  # noqa: E402
from exp2.resolver import ConcreteResolver  # noqa: E402


DATASET = EXPERIMENT_DIR / "dataset" / "rfc_symbolic_cases.json"


class ConcreteSemanticsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = {case.id: case for case in load_cases(DATASET)}

    def test_exact_owner_overrides_wildcard_after_dname(self) -> None:
        traces = {
            trace.query.name: trace
            for trace in ConcreteResolver(
                self.cases["dname_concrete_wildcard"]
            ).resolve_all()
        }
        self.assertEqual(
            traces["www.old.s1.test."].outcome,
            "A:192.0.2.1",
        )
        self.assertEqual(
            traces["api.old.s1.test."].outcome,
            "A:192.0.2.2",
        )
        self.assertTrue(traces["old.s1.test."].outcome.startswith("NODATA:"))

    def test_deleting_concrete_activates_wildcard(self) -> None:
        before = {
            trace.query.name: trace.outcome
            for trace in ConcreteResolver(
                self.cases["delete_concrete_before"]
            ).resolve_all()
        }
        after = {
            trace.query.name: trace.outcome
            for trace in ConcreteResolver(
                self.cases["delete_concrete_after"]
            ).resolve_all()
        }
        self.assertEqual(before["www.old.s6.test."], "A:192.0.2.51")
        self.assertEqual(after["www.old.s6.test."], "A:192.0.2.52")

    def test_deleting_dname_reactivates_shadowed_address(self) -> None:
        before = ConcreteResolver(
            self.cases["delete_dname_before"]
        ).resolve_all()[0]
        after = ConcreteResolver(
            self.cases["delete_dname_after"]
        ).resolve_all()[0]
        self.assertEqual(before.outcome, "A:192.0.2.62")
        self.assertEqual(after.outcome, "A:192.0.2.61")


class AblationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = load_cases(DATASET)

    def test_full_matches_concrete_oracle_for_every_case(self) -> None:
        for case in self.cases:
            traces = ConcreteResolver(case).resolve_all()
            _, result = evaluate_method(traces, Method.FULL)
            self.assertEqual(result.false_positive, 0, case.id)
            self.assertEqual(result.false_negative, 0, case.id)

    def test_binding_changes_paths_not_graph_size(self) -> None:
        unbound_false = 0
        for case in self.cases:
            traces = ConcreteResolver(case).resolve_all()
            unbound_graph, unbound = evaluate_method(
                traces, Method.ALPHA_BETA_UNBOUND
            )
            full_graph, full = evaluate_method(traces, Method.FULL)
            self.assertEqual(len(unbound_graph.nodes), len(full_graph.nodes))
            self.assertEqual(len(unbound_graph.edges), len(full_graph.edges))
            unbound_false += unbound.false_positive
            self.assertEqual(full.false_positive, 0)
        self.assertGreater(unbound_false, 0)

    def test_symbolic_graph_is_smaller_than_concrete_graph(self) -> None:
        concrete_nodes = concrete_edges = full_nodes = full_edges = 0
        for case in self.cases:
            traces = ConcreteResolver(case).resolve_all()
            concrete_graph, _ = evaluate_method(traces, Method.CONCRETE)
            full_graph, _ = evaluate_method(traces, Method.FULL)
            concrete_nodes += len(concrete_graph.nodes)
            concrete_edges += len(concrete_graph.edges)
            full_nodes += len(full_graph.nodes)
            full_edges += len(full_graph.edges)
        self.assertLess(full_nodes, concrete_nodes)
        self.assertLess(full_edges, concrete_edges)

    def test_binding_prevents_false_rewrite_loop_report(self) -> None:
        case = next(
            case
            for case in self.cases
            if case.id == "binding_guard_prevents_false_rl"
        )
        traces = ConcreteResolver(case).resolve_all()
        _, concrete = evaluate_method(traces, Method.CONCRETE)
        _, unbound = evaluate_method(traces, Method.ALPHA_BETA_UNBOUND)
        _, full = evaluate_method(traces, Method.FULL)

        self.assertEqual(detect_path_bugs(case, concrete.predicted), set())
        self.assertEqual(detect_path_bugs(case, full.predicted), set())
        unbound_bugs = detect_path_bugs(case, unbound.predicted)
        self.assertGreater(
            sum(1 for finding in unbound_bugs if finding.kind == "RL"),
            0,
        )

    def test_binding_prevents_false_rewrite_blackhole_report(self) -> None:
        case = next(
            case for case in self.cases if case.id == "zone_cut_dname_overlap"
        )
        traces = ConcreteResolver(case).resolve_all()
        _, unbound = evaluate_method(traces, Method.ALPHA_BETA_UNBOUND)
        _, full = evaluate_method(traces, Method.FULL)

        self.assertEqual(detect_path_bugs(case, full.predicted), set())
        unbound_bugs = detect_path_bugs(case, unbound.predicted)
        self.assertEqual(
            sum(1 for finding in unbound_bugs if finding.kind == "RB"),
            8,
        )


if __name__ == "__main__":
    unittest.main()
