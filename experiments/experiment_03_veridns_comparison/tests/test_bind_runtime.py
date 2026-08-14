from __future__ import annotations

import sys
import unittest
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parents[1]
EXP2_DIR = EXPERIMENT_DIR.parent / "experiment_02_symbolic_ablation"
sys.path.insert(0, str(EXP2_DIR))
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp3.bind_runtime import parse_dig_response  # noqa: E402


class BindRuntimeTests(unittest.TestCase):
    def test_parse_address_after_dname(self) -> None:
        response = """
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; ANSWER SECTION:
www.legacy.example. 60 IN DNAME blue.example.
www.legacy.example. 60 IN CNAME www.blue.example.
www.blue.example. 60 IN A 192.0.2.1
"""
        parsed = parse_dig_response(response, "www.legacy.example.")
        self.assertEqual(parsed.outcome, "A:192.0.2.1")
        self.assertEqual(parsed.final_name, "www.blue.example.")

    def test_parse_nxdomain_after_cname(self) -> None:
        response = """
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 2
;; ANSWER SECTION:
www.example. 60 IN CNAME missing.example.
"""
        parsed = parse_dig_response(response, "www.example.")
        self.assertEqual(parsed.outcome, "NX:missing.example.")

    def test_parse_servfail_as_loop(self) -> None:
        response = """
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 3
"""
        parsed = parse_dig_response(response, "loop.example.")
        self.assertEqual(parsed.outcome, "LOOP")


if __name__ == "__main__":
    unittest.main()
