#!/usr/bin/env python3
"""Validate the five GRoot-only synthetic DNAME findings with BIND."""

from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
import time
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parent
ZONE_SOURCE = EXPERIMENT_DIR / "bind_dname_audit" / "ai.techuni.edu.zone"
STATUS_RE = re.compile(r"status:\s*([A-Z]+)", re.IGNORECASE)


QUERIES = [
    ("api.old-lab.ai.techuni.edu.", "A"),
    ("db.old-lab.ai.techuni.edu.", "AAAA"),
    ("train.legacy-ml.ai.techuni.edu.", "A"),
    ("legacy-ml.ai.techuni.edu.", "A"),
    ("project1.legacy-ml.ai.techuni.edu.", "A"),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, default=15365)
    return parser.parse_args()


def wait_for_server(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        completed = subprocess.run(
            [
                "dig",
                "@127.0.0.1",
                "-p",
                str(port),
                "ai.techuni.edu.",
                "SOA",
                "+norecurse",
                "+time=1",
                "+tries=1",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        if completed.returncode == 0 and "status: NOERROR" in completed.stdout:
            return
        time.sleep(0.05)
    raise TimeoutError("BIND did not start before the timeout")


def answer_types(output: str) -> list[str]:
    types: list[str] = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[2].upper() == "IN":
            types.append(fields[3].upper())
    return types


def main() -> int:
    args = parse_args()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    zone_path = output_dir / "ai.techuni.edu.zone"
    shutil.copyfile(ZONE_SOURCE, zone_path)
    named_conf = output_dir / "named.conf"
    named_conf.write_text(
        "\n".join(
            [
                "options {",
                f'  directory "{output_dir}";',
                f"  listen-on port {args.port} {{ 127.0.0.1; }};",
                "  listen-on-v6 { none; };",
                "  recursion no;",
                f'  pid-file "{output_dir / "named.pid"}";',
                f'  session-keyfile "{output_dir / "session.key"}";',
                "};",
                'zone "ai.techuni.edu." IN {',
                "  type primary;",
                f'  file "{zone_path}";',
                "};",
                "",
            ]
        ),
        encoding="utf-8",
    )

    log_path = output_dir / "named.log"
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            ["named", "-c", str(named_conf), "-g"],
            cwd=output_dir,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            wait_for_server(args.port)
            rows: list[dict[str, object]] = []
            for index, (name, rrtype) in enumerate(QUERIES, start=1):
                completed = subprocess.run(
                    [
                        "dig",
                        "@127.0.0.1",
                        "-p",
                        str(args.port),
                        name,
                        rrtype,
                        "+norecurse",
                        "+noall",
                        "+comments",
                        "+answer",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    check=False,
                )
                raw_path = output_dir / f"query_{index:02d}.txt"
                raw_path.write_text(completed.stdout, encoding="utf-8")
                match = STATUS_RE.search(completed.stdout)
                types = answer_types(completed.stdout)
                rows.append(
                    {
                        "query": name,
                        "type": rrtype,
                        "status": match.group(1).upper() if match else "UNKNOWN",
                        "answer_types": ",".join(types),
                        "has_terminal_address": any(
                            value in {"A", "AAAA"} for value in types
                        ),
                        "return_code": completed.returncode,
                    }
                )
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    with (output_dir / "bind_dname_audit.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    summary = {
        "bind_version": subprocess.run(
            ["named", "-v"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        ).stdout.strip(),
        "authoritative_server": f"127.0.0.1:{args.port}",
        "cache": "not applicable; queries are sent directly to the authoritative server",
        "queries": rows,
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
