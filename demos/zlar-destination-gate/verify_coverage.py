#!/usr/bin/env python3
"""Packaged read-only coverage regeneration verifier."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from product_identity import CANDIDATE_ROOTS, ENGINE_RELATIVE, repository_root, verify_manifest
from product_surface import tree_projection


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Product Cut 0.1 coverage regeneration verifier")
    parser.add_argument("--campaign-root", required=True)
    args = parser.parse_args()
    try:
        root = repository_root()
        campaign = Path(args.campaign_root)
        verify_manifest(root)
        candidate_before = tuple(tree_projection(root / relative) for relative in CANDIDATE_ROOTS)
        campaign_before = tree_projection(campaign)
        environment = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"}
        completed = subprocess.run(
            [sys.executable, "-B", str(root / ENGINE_RELATIVE / "coverage_regenerate.py"), "--campaign-root", str(campaign)],
            check=False, capture_output=True, env=environment,
        )
        if completed.returncode != 0:
            raise RuntimeError("engine_coverage_verifier_refused:" + completed.stderr.decode("utf-8", errors="replace"))
        engine_result = json.loads(completed.stdout.decode("utf-8"))
        if engine_result.get("writes") != 0 or engine_result.get("verdict") != "PASS_CANDIDATE_005_COVERAGE_REGENERATION":
            raise RuntimeError("engine_coverage_verdict")
        verify_manifest(root)
        candidate_after = tuple(tree_projection(root / relative) for relative in CANDIDATE_ROOTS)
        campaign_after = tree_projection(campaign)
        if candidate_before != candidate_after or campaign_before != campaign_after:
            raise RuntimeError("packaged_coverage_verifier_wrote_state")
    except Exception as exc:
        print(json.dumps({"reason": str(exc), "status": "REFUSED_NO_PASS"}, sort_keys=True), file=sys.stderr)
        return 42
    print(json.dumps({
        "exact_canonical_bytes_equal": engine_result["exact_canonical_bytes_equal"],
        "regenerated_raw_sha256": engine_result["regenerated_raw_sha256"],
        "row_count": engine_result["row_count"],
        "verdict": "PASS_PRODUCT_CUT_0_1_COVERAGE_REGENERATION", "writes": 0,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
