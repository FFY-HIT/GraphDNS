from __future__ import annotations

import sys
import unittest
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT_DIR))

from exp1.model import parse_graphdns_reports, parse_jsonl_reports, unique_cases  # noqa: E402


class FindingParserTest(unittest.TestCase):
    def test_graphdns_and_groot_jsonl_share_case_key(self) -> None:
        graphdns_text = """
=== Bug Reports ===
[MG] zoneCut=example.com. nameserver=ns1.example.com. zone=com.
reason=in-bailiwick NS lacks parent-side A/AAAA glue
path=[ns.parent. com.] alpha.example.com. --NS/reach=1--> ns1.example.com.

Summary: servers=2 zones=2 nodes=5 edges=4 paths=1 bugs=1
BugStats: MG=1
"""
        groot_text = (
            '{"kind":"Missing Glue Records","zone_cut":"EXAMPLE.COM",'
            '"nameserver":"NS1.EXAMPLE.COM"}\n'
        )
        graphdns = parse_graphdns_reports(graphdns_text)
        groot = parse_jsonl_reports(groot_text)
        self.assertEqual(len(graphdns), 1)
        self.assertEqual(graphdns[0].case_key, groot[0].case_key)
        self.assertEqual(graphdns[0].kind, "MG")

    def test_raw_witnesses_collapse_to_one_logical_case(self) -> None:
        text = """
[DI] zoneCut=child.example.
reason=child-side NS missing
path=first witness

[DI] zoneCut=child.example.
reason=child-side NS missing
path=second witness
"""
        findings = parse_graphdns_reports(text)
        self.assertEqual(len(findings), 2)
        self.assertEqual(len(unique_cases(findings)), 1)


if __name__ == "__main__":
    unittest.main()
