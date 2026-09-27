#!/usr/bin/env python3
"""Subject coverage generator. Offline tools carry separate regeneration code."""

from __future__ import annotations

from collections import Counter
from typing import Any

from canonical import CANONICALIZATION_ID, canonical_bytes, sha256_bytes
from contract import (
    ACTION,
    CANDIDATE_ID,
    COLLECTOR_ID,
    COVERAGE_GENERATOR_ID,
    DESTINATION_ID,
    FIXED_EVALUATION_EPOCH,
    OFFLINE_VERIFIER_ID,
    PROTOCOL_PROFILE_ID,
    SERVER_ID,
    TOOL_CONTRACT_DIGEST,
)


def _raw_sha(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value) + b"\n")


def generate_coverage(
    runtime_inventory: dict[str, Any],
    destination_registry: dict[str, Any],
    matrix_evidence: dict[str, Any],
    noncoverage_baseline: dict[str, Any],
) -> dict[str, Any]:
    package_id = runtime_inventory["package_id"]
    source_id = runtime_inventory["source_id"]
    matrix_payload = matrix_evidence["payload"]
    evidence_id = matrix_payload["receipt_id"]
    input_bindings = {
        "destination_registry": {
            "producer_id": destination_registry["producer_id"],
            "raw_sha256": _raw_sha(destination_registry),
            "schema_version": destination_registry["schema_version"],
        },
        "matrix_evidence": {
            "producer_id": SERVER_ID,
            "raw_sha256": _raw_sha(matrix_evidence),
            "schema_version": matrix_evidence["schema_version"],
        },
        "noncoverage_baseline": {
            "producer_id": noncoverage_baseline["producer_id"],
            "raw_sha256": _raw_sha(noncoverage_baseline),
            "schema_version": noncoverage_baseline["schema_version"],
        },
        "runtime_inventory": {
            "producer_id": runtime_inventory["collector_id"],
            "raw_sha256": _raw_sha(runtime_inventory),
            "schema_version": runtime_inventory["schema_version"],
        },
    }

    def common(surface_id: str) -> dict[str, Any]:
        return {
            "candidate_id": CANDIDATE_ID,
            "collector_id": COLLECTOR_ID,
            "collector_version": "1",
            "coverage_generator_id": COVERAGE_GENERATOR_ID,
            "coverage_generator_version": "1",
            "evaluator_run_id": "candidate-005-builder-frozen-campaign",
            "evidence_identity": evidence_id,
            "observed_at_epoch": FIXED_EVALUATION_EPOCH,
            "offline_verifier_id": OFFLINE_VERIFIER_ID,
            "offline_verifier_version": "1",
            "package_id": package_id,
            "protocol_profile_id": PROTOCOL_PROFILE_ID,
            "source_id": source_id,
            "surface_id": surface_id,
            "tool_contract_digest": TOOL_CONTRACT_DIGEST,
        }

    rows: list[dict[str, Any]] = []
    rows.append(
        {
            **common("mcp.method.initialize"),
            "action": "initialize",
            "bypass_or_limitation": "bounded profile initialization only",
            "consequence_class": "none",
            "derivation_basis": ["runtime_inventory", "session_observations", "matrix_zero_mutation"],
            "destination_id": DESTINATION_ID,
            "governance_mechanism": "protocol_shape_validation",
            "method": "initialize",
            "observed_outcome": "no_effect_observed",
            "recognition_point": "not_applicable",
            "route_id": "mcp.route.initialize",
            "surface_disposition": "consequence_incapable",
            "supporting_evidence": [input_bindings["runtime_inventory"]["raw_sha256"], evidence_id],
            "tool_name": None,
        }
    )
    rows.append(
        {
            **common("mcp.method.tools-list"),
            "action": "tools/list",
            "bypass_or_limitation": "inventory observation only",
            "consequence_class": "none",
            "derivation_basis": ["runtime_inventory", "two_equal_tools_list_observations", "matrix_zero_mutation"],
            "destination_id": DESTINATION_ID,
            "governance_mechanism": "frozen_tool_contract_digest",
            "method": "tools/list",
            "observed_outcome": "no_effect_observed",
            "recognition_point": "not_applicable",
            "route_id": "mcp.route.tools-list",
            "surface_disposition": "consequence_incapable",
            "supporting_evidence": [input_bindings["runtime_inventory"]["raw_sha256"], evidence_id],
            "tool_name": None,
        }
    )
    rows.append(
        {
            **common("mcp.tool.deployment-promote"),
            "action": ACTION,
            "bypass_or_limitation": "governed only inside frozen local stdio candidate route",
            "consequence_class": "synthetic.deployment.promote",
            "derivation_basis": [
                "runtime_inventory",
                "destination_registry_declaration",
                "complete_negative_matrix",
                "recognized_crossing",
                "replay_refusal",
                "linked_settlement",
            ],
            "destination_id": DESTINATION_ID,
            "governance_mechanism": "signed_single_use_authorization_and_destination_recognition",
            "method": "tools/call",
            "observed_outcome": "effect_committed",
            "recognition_point": "inside_destination_immediately_before_commit",
            "route_id": "mcp.route.tools-call.deployment-promote",
            "surface_disposition": "governed",
            "supporting_evidence": [
                input_bindings["runtime_inventory"]["raw_sha256"],
                input_bindings["destination_registry"]["raw_sha256"],
                evidence_id,
            ],
            "tool_name": ACTION,
        }
    )
    rows.append(
        {
            **common("destination.direct-promotion-entry"),
            "action": ACTION,
            "bypass_or_limitation": "same-user source owner can import or modify destination code",
            "consequence_class": "synthetic.deployment.promote",
            "derivation_basis": ["destination_registry_declaration_only", "mandatory_noncoverage_baseline"],
            "destination_id": DESTINATION_ID,
            "governance_mechanism": None,
            "method": None,
            "observed_outcome": "not_exercised",
            "recognition_point": None,
            "route_id": "destination.route.direct-internal-entry",
            "surface_disposition": "open",
            "supporting_evidence": [
                input_bindings["destination_registry"]["raw_sha256"],
                input_bindings["noncoverage_baseline"]["raw_sha256"],
            ],
            "tool_name": None,
        }
    )
    probed_outcomes = {
        "alternate_request_forms": "refused_pre_destination",
        "unknown_methods": "refused_pre_destination",
        "unknown_tools": "refused_pre_destination",
    }
    for baseline in noncoverage_baseline["surfaces"]:
        surface_id = baseline["surface_id"]
        disposition = baseline["required_disposition"]
        rows.append(
            {
                **common("side-door." + surface_id),
                "action": None,
                "bypass_or_limitation": baseline["uncertainty_reason"],
                "consequence_class": "unknown_or_outside_frozen_terminal",
                "derivation_basis": [
                    "mandatory_noncoverage_baseline",
                    "protocol_probe" if surface_id in probed_outcomes else "not_exercised",
                ],
                "destination_id": None,
                "governance_mechanism": None,
                "method": None,
                "observed_outcome": probed_outcomes.get(surface_id, "not_exercised"),
                "recognition_point": None,
                "route_id": None,
                "surface_disposition": disposition,
                "supporting_evidence": [
                    input_bindings["noncoverage_baseline"]["raw_sha256"],
                    evidence_id if surface_id in probed_outcomes else input_bindings["noncoverage_baseline"]["raw_sha256"],
                ],
                "tool_name": None,
            }
        )
    rows.sort(key=lambda row: row["surface_id"].encode("utf-8"))
    if len(rows) != 43 or len({row["surface_id"] for row in rows}) != 43:
        raise ValueError("coverage_row_cardinality")
    disposition_counts = dict(sorted(Counter(row["surface_disposition"] for row in rows).items()))
    outcome_counts = dict(sorted(Counter(row["observed_outcome"] for row in rows).items()))
    derivation_counts = dict(
        sorted(Counter(basis for row in rows for basis in row["derivation_basis"]).items())
    )
    return {
        "candidate_id": CANDIDATE_ID,
        "canonicalization_id": CANONICALIZATION_ID,
        "coverage_generator_id": COVERAGE_GENERATOR_ID,
        "coverage_generator_version": "1",
        "derivation_basis_counts": derivation_counts,
        "disposition_counts": disposition_counts,
        "generated_at_epoch": FIXED_EVALUATION_EPOCH,
        "input_bindings": input_bindings,
        "observed_outcome_counts": outcome_counts,
        "package_id": package_id,
        "protocol_profile_id": PROTOCOL_PROFILE_ID,
        "row_count": len(rows),
        "rows": rows,
        "schema_version": "zlar.star4.two-axis-coverage.v1",
        "source_id": source_id,
        "tool_contract_digest": TOOL_CONTRACT_DIGEST,
    }
