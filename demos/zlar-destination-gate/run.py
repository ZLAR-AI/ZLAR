#!/usr/bin/env python3
"""Fail-closed historical Product Cut 0.1 runner.

Git history at 9dab89ec16edd6009dc34f973361502eda35b73c preserves the
reproducible Product Cut 0.1 route. Current main has one outward Demo 1 surface:
demo1.mjs. Keeping this runner executable would leave a second live consequence
path, so it now refuses without importing or executing Candidate 005.
"""

from __future__ import annotations

import json
import sys


def main() -> int:
    print(json.dumps({
        "status": "REFUSED_HISTORICAL_NON_ROUTING",
        "effect_delta": 0,
        "current_entrypoint": "demos/zlar-destination-gate/demo1.mjs",
        "historical_commit": "9dab89ec16edd6009dc34f973361502eda35b73c",
    }, sort_keys=True), file=sys.stderr)
    return 42


if __name__ == "__main__":
    raise SystemExit(main())
