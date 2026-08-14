from __future__ import annotations

import json
import sys
from pathlib import Path


output = Path(sys.argv[1])
output.write_text(
    json.dumps(
        {
            "kind": "Missing Glue Records",
            "zone_cut": "child.example.",
            "nameserver": "ns.child.example.",
        }
    )
    + "\n",
    encoding="utf-8",
)
