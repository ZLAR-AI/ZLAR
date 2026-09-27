#!/usr/bin/env python3
"""Subject-side two-axis coverage derivation."""

from __future__ import annotations

from collections import Counter
from typing import Any

from canonical import canonical_bytes, sha256_bytes
from contract import CANDIDATE_ID, DECLARED_ROUTES, EVALUATION_EPOCH, MANDATORY_NONCOVERAGE


def _binding(value: object) -> str:
    return sha256_bytes(canonical_bytes(value) + b"\n")


def generate(
    runtime_inventory: dict[str, Any],
    matrix: dict[str, Any],
    route_registry: dict[str, Any],
    noncoverage: dict[str, Any],
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    observed_terminal = matrix["totals"]["recognized_crossings"] == 1
    for route in DECLARED_ROUTES:
        terminal = route["surface_id"].startswith("terminal.")
        rows.append(
            {
                "derivation_basis": ["declarative_route_registry", "runtime_inventory", "adversarial_matrix"],
                "observed_outcome": "one_settlement_observed" if terminal and observed_terminal else "no_consequence_observed",
                "recognition_point": route["recognition_point"],
                "route_id": route["route_id"],
                "surface_disposition": "governed" if terminal else "consequence_incapable",
                "surface_id": route["surface_id"],
            }
        )
    for surface_id, required in MANDATORY_NONCOVERAGE:
        rows.append(
            {
                "derivation_basis": ["mandatory_noncoverage_baseline"],
                "observed_outcome": "not_exercised",
                "recognition_point": None,
                "route_id": None,
                "surface_disposition": required,
                "surface_id": "side-door." + surface_id,
            }
        )
    rows.sort(key=lambda row: row["surface_id"].encode("utf-8"))
    if len({row["surface_id"] for row in rows}) != len(rows):
        raise ValueError("coverage_duplicate_surface")
    return {
        "candidate_id": CANDIDATE_ID,
        "disposition_counts": dict(sorted(Counter(row["surface_disposition"] for row in rows).items())),
        "generated_at_epoch": EVALUATION_EPOCH,
        "input_bindings": {
            "matrix": _binding(matrix),
            "noncoverage": _binding(noncoverage),
            "route_registry": _binding(route_registry),
            "runtime_inventory": _binding(runtime_inventory),
        },
        "observed_outcome_counts": dict(sorted(Counter(row["observed_outcome"] for row in rows).items())),
        "row_count": len(rows),
        "rows": rows,
        "schema_version": "zlar.protected-promotion.two-axis-coverage.v1",
    }
