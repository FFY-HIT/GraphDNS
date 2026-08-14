#!/usr/bin/env python3
"""Expand the seven RFC update templates into a larger controlled matrix."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--copies", type=int, default=16)
    return parser.parse_args()


def transform_string(value: str, copy_index: int) -> str:
    marker = f"graphdns-exp-c{copy_index:02d}-"
    value = value.replace("graphdns-exp-", marker)
    if value.startswith("exp3_"):
        value = f"exp3_c{copy_index:02d}_" + value[len("exp3_") :]
    return value


def transform_value(value: Any, copy_index: int) -> Any:
    if isinstance(value, str):
        return transform_string(value, copy_index)
    if isinstance(value, list):
        return [transform_value(item, copy_index) for item in value]
    if isinstance(value, dict):
        return {
            transform_string(str(key), copy_index): transform_value(
                item, copy_index
            )
            for key, item in value.items()
        }
    return value


def expand(payload: dict[str, Any], copies: int) -> dict[str, Any]:
    if copies <= 0:
        raise ValueError("--copies must be positive")
    original_updates = payload.get("updates", [])
    if not isinstance(original_updates, list) or not original_updates:
        raise ValueError("input has no controlled updates")

    mismatch = set(
        payload.get("expectations", {}).get("veridns_mismatch_pairs", [])
    )
    consistent = set(
        payload.get("expectations", {}).get("veridns_consistent_pairs", [])
    )

    updates: list[dict[str, Any]] = []
    mismatch_expanded: list[str] = []
    consistent_expanded: list[str] = []
    for copy_index in range(1, copies + 1):
        for original in original_updates:
            cloned = transform_value(copy.deepcopy(original), copy_index)
            original_id = str(original["pair_id"])
            pair_id = f"{original_id}_c{copy_index:02d}"
            cloned["pair_id"] = pair_id
            cloned["description"] = (
                f"Controlled matrix copy {copy_index}: "
                + str(original.get("description", ""))
            )
            updates.append(cloned)
            if original_id in mismatch:
                mismatch_expanded.append(pair_id)
            if original_id in consistent:
                consistent_expanded.append(pair_id)

    result = {
        "description": (
            f"{len(updates)} controlled single-record updates expanded from "
            f"{len(original_updates)} RFC boundary templates."
        ),
        "validity_scope": payload.get("validity_scope", {}),
        "expectations": {
            "veridns_mismatch_pairs": mismatch_expanded,
            "veridns_consistent_pairs": consistent_expanded,
            "graphdns_all_consistent": True,
        },
        "matrix": {
            "template_count": len(original_updates),
            "copies_per_template": copies,
            "update_count": len(updates),
        },
        "updates": updates,
    }
    return result


def main() -> int:
    args = parse_args()
    payload = json.loads(args.input.read_text(encoding="utf-8"))
    expanded = expand(payload, args.copies)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(expanded, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    query_count = sum(
        len(update.get("explicit_queries", []))
        for update in expanded["updates"]
    )
    print(
        f"[done] updates={len(expanded['updates'])} "
        f"queries_per_snapshot={query_count} "
        f"bind_queries={2 * query_count}"
    )
    print(f"[result] {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
