#!/usr/bin/env python3
"""Packaged read-only receipt-chain and human-view verifier."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from product_identity import CANDIDATE_ROOTS, repository_root, verify_manifest
from product_surface import derive_verified_view, tree_projection


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Product Cut 0.1 receipt-chain verifier")
    parser.add_argument("--campaign-root", required=True)
    args = parser.parse_args()
    try:
        root = repository_root()
        campaign = Path(args.campaign_root)
        verify_manifest(root)
        candidate_before = tuple(tree_projection(root / relative) for relative in CANDIDATE_ROOTS)
        campaign_before = tree_projection(campaign)
        view = derive_verified_view(campaign)
        verify_manifest(root)
        candidate_after = tuple(tree_projection(root / relative) for relative in CANDIDATE_ROOTS)
        campaign_after = tree_projection(campaign)
        if candidate_before != candidate_after or campaign_before != campaign_after:
            raise RuntimeError("packaged_offline_verifier_wrote_state")
    except Exception as exc:
        print(json.dumps({"reason": str(exc), "status": "REFUSED_NO_PASS"}, sort_keys=True), file=sys.stderr)
        return 42
    print(json.dumps({
        "accepted": view["accepted"], "assertions": view["offline_assertions"], "case_count": view["case_count"],
        "recognized_consumptions": view["crossing"]["consumptions"], "recognized_protected_mutations": view["crossing"]["mutations"],
        "refused": view["refused"], "verdict": "PASS_PRODUCT_CUT_0_1_OFFLINE_RECEIPT_CHAIN", "writes": 0,
        "zero_counters": view["zero_counters"],
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
