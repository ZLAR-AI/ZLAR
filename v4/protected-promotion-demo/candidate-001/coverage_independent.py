#!/usr/bin/env python3
"""Independent coverage regeneration; deliberately does not import subject code."""

from __future__ import annotations

from collections import Counter
from typing import Any

from canonical import canonical_bytes, sha256_bytes
from contract import CANDIDATE_ID, DECLARED_ROUTES, EVALUATION_EPOCH, MANDATORY_NONCOVERAGE


def regenerate(
    runtime_inventory: dict[str, Any],
    matrix: dict[str, Any],
    route_registry: dict[str, Any],
    noncoverage: dict[str, Any],
) -> dict[str, Any]:
    input_bindings = {}
    for name, value in (
        ("matrix", matrix),
        ("noncoverage", noncoverage),
        ("route_registry", route_registry),
        ("runtime_inventory", runtime_inventory),
    ):
        input_bindings[name] = sha256_bytes(canonical_bytes(value) + b"\n")
    regenerated: list[dict[str, Any]] = []
    crossing_seen = matrix.get("totals", {}).get("recognized_crossings") == 1
    for declaration in DECLARED_ROUTES:
        is_effect_route = declaration["consequence_class"] == "synthetic.deployment.promote"
        regenerated.append(
            {
                "derivation_basis": ["declarative_route_registry", "runtime_inventory", "adversarial_matrix"],
                "observed_outcome": "one_settlement_observed" if is_effect_route and crossing_seen else "no_consequence_observed",
                "recognition_point": declaration["recognition_point"],
                "route_id": declaration["route_id"],
                "surface_disposition": "governed" if is_effect_route else "consequence_incapable",
                "surface_id": declaration["surface_id"],
            }
        )
    for name, disposition in MANDATORY_NONCOVERAGE:
        regenerated.append(
            {
                "derivation_basis": ["mandatory_noncoverage_baseline"],
                "observed_outcome": "not_exercised",
                "recognition_point": None,
                "route_id": None,
                "surface_disposition": disposition,
                "surface_id": "side-door." + name,
            }
        )
    regenerated.sort(key=lambda row: row["surface_id"].encode("utf-8"))
    dispositions = Counter()
    outcomes = Counter()
    for row in regenerated:
        dispositions[row["surface_disposition"]] += 1
        outcomes[row["observed_outcome"]] += 1
    return {
        "candidate_id": CANDIDATE_ID,
        "disposition_counts": dict(sorted(dispositions.items())),
        "generated_at_epoch": EVALUATION_EPOCH,
        "input_bindings": input_bindings,
        "observed_outcome_counts": dict(sorted(outcomes.items())),
        "row_count": len(regenerated),
        "rows": regenerated,
        "schema_version": "zlar.protected-promotion.two-axis-coverage.v1",
    }
