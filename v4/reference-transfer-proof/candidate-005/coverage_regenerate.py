#!/usr/bin/env python3
"""Read-only isolated coverage regeneration and exact-byte comparison."""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
from pathlib import Path

from canonical import canonical_bytes, read_json, sha256_bytes
from contract import COVERAGE_REGENERATOR_ID
from crypto_rsa import parse_public_evidence
from evidence import verify_envelope
from offline_verify import _regenerate_coverage, _tree_projection


def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate Candidate 005 coverage without writing")
    parser.add_argument("--campaign-root", required=True)
    args = parser.parse_args()
    root = Path(args.campaign_root)
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise SystemExit("coverage_root_invalid")
    before = _tree_projection(root)
    public_key = read_json(root / "public-key.json")
    modulus, _, _ = parse_public_evidence(public_key, require_bits=2048)
    if modulus.bit_length() != 2048:
        raise SystemExit("public_key_modulus_bits")
    runtime = read_json(root / "runtime-inventory.json")
    registry = read_json(root / "destination-registry.json")
    matrix = read_json(root / "matrix-evidence.json")
    baseline = read_json(root / "noncoverage-baseline.json")
    saved = read_json(root / "coverage-map.json")
    regenerated = _regenerate_coverage(runtime, registry, matrix, baseline)
    saved_raw = canonical_bytes(saved) + b"\n"
    regenerated_raw = canonical_bytes(regenerated) + b"\n"
    if saved_raw != regenerated_raw:
        raise SystemExit("coverage_exact_bytes_mismatch")
    coverage_receipt = verify_envelope(
        read_json(root / "coverage-envelope.json"), public_key, expected_type="coverage"
    )
    if coverage_receipt["coverage_map_raw_sha256"] != sha256_bytes(regenerated_raw):
        raise SystemExit("coverage_receipt_mismatch")
    after = _tree_projection(root)
    if before != after:
        raise SystemExit("coverage_regenerator_wrote_state")
    result = {
        "actual_public_modulus_bits": modulus.bit_length(),
        "exact_canonical_bytes_equal": True,
        "regenerated_raw_sha256": sha256_bytes(regenerated_raw),
        "regenerator_id": COVERAGE_REGENERATOR_ID,
        "row_count": regenerated["row_count"],
        "verdict": "PASS_CANDIDATE_005_COVERAGE_REGENERATION",
        "writes": 0,
    }
    sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
