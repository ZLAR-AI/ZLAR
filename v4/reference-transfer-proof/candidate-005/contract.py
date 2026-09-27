#!/usr/bin/env python3
"""Frozen Candidate 005 identities, MCP contract, proof plan, and side doors."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from canonical import CANONICALIZATION_ID, canonical_bytes, sha256_bytes, sha256_json
from evidence import EVIDENCE_SCHEMA_VERSION, FIELD_REGISTRY_ID


CANDIDATE_ID = "v4-star4-candidate-005"
PROTOCOL_PROFILE_ID = "zlar.local-stdio-mcp.deployment-promote.v1"
MCP_PROTOCOL_VERSION = "2025-06-18"
JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
SERVER_ID = "zlar.star4.candidate-005.mcp-server.v1"
COLLECTOR_ID = "zlar.star4.candidate-005.runtime-collector.v1"
COVERAGE_GENERATOR_ID = "zlar.star4.candidate-005.coverage-generator.v1"
OFFLINE_VERIFIER_ID = "zlar.star4.candidate-005.offline-verifier.v1"
COVERAGE_REGENERATOR_ID = "zlar.star4.candidate-005.coverage-regenerator.v1"
RECOGNITION_PROFILE_ID = "zlar.star4.candidate-005.destination-recognition.v1"
RECOGNITION_SCHEMA_VERSION = "zlar.star4.recognition-profile.v1"
RECOGNITION_PROFILE_VERSION = "1"
AUTHORITY_DOMAIN = "zlar.star4.synthetic-promotion.local-disposable"
DESTINATION_ID = "zlar.star4.synthetic-deployment-destination.candidate-005"
AUDIENCE = "zlar.star4.candidate-005.destination-recognition-service"
RESOURCE = "zlar.star4.synthetic-promotion-domain.active-slot"
ACTION = "deployment.promote"
PURPOSE = "bounded_star4_synthetic_promotion_proof"
SLOT = "active"
INITIAL_ARTIFACT_ID = "synthetic-artifact.initial.v1"
STAGED_ARTIFACT_ID = "synthetic-artifact.staged.v2"
INITIAL_GENERATION = 7
FIXED_EVALUATION_EPOCH = 1784572800
AUTH_ISSUED_AT = 1784572740
AUTH_EXPIRES_AT = 1784576400
AUTH_NONCE = "candidate-005-single-use-promotion-nonce-001"


TOOL_INPUT_SCHEMA = {
    "$schema": JSON_SCHEMA_DIALECT,
    "additionalProperties": False,
    "properties": {
        "authorization": {"type": "object"},
        "request": {
            "additionalProperties": False,
            "properties": {
                "expected_generation": {"type": "integer"},
                "slot": {"const": SLOT},
                "staged_artifact_id": {"const": STAGED_ARTIFACT_ID},
            },
            "required": ["expected_generation", "slot", "staged_artifact_id"],
            "type": "object",
        },
    },
    "required": ["authorization", "request"],
    "type": "object",
}

TOOL_OUTPUT_SCHEMA = {
    "$schema": JSON_SCHEMA_DIALECT,
    "additionalProperties": False,
    "properties": {
        "decision": {"type": "object"},
        "effect": {"type": ["object", "null"]},
        "refusal": {"type": ["object", "null"]},
        "state": {"type": "object"},
    },
    "required": ["decision", "effect", "refusal", "state"],
    "type": "object",
}

TOOL_CONTRACT = {
    "capabilities": {"tools": {"listChanged": False}},
    "json_schema_dialect": JSON_SCHEMA_DIALECT,
    "protocol_profile_id": PROTOCOL_PROFILE_ID,
    "protocol_version": MCP_PROTOCOL_VERSION,
    "tools": [
        {
            "description": "Promote one fixed staged synthetic artifact into one fixed active slot.",
            "inputSchema": TOOL_INPUT_SCHEMA,
            "metadata": {
                "consequence_capable": True,
                "consequence_class": "synthetic.deployment.promote",
                "destination_recognition_required": True,
            },
            "name": ACTION,
            "outputSchema": TOOL_OUTPUT_SCHEMA,
        }
    ],
}
TOOL_CONTRACT_DIGEST = sha256_bytes(canonical_bytes(TOOL_CONTRACT))

CANONICAL_REQUEST = {
    "expected_generation": INITIAL_GENERATION,
    "slot": SLOT,
    "staged_artifact_id": STAGED_ARTIFACT_ID,
}

ROLE_BINDINGS = {
    "accountable_owner": {"presence": "explicitly_unbound", "reason": "unbound_by_star4"},
    "agent_or_workload": {"presence": "explicitly_unbound", "reason": "unbound_by_star4"},
    "authorization_issuer": {
        "identity_type": "issuer_qualified_uri",
        "presence": "bound",
        "value": "zlar-issuer://candidate-005/ephemeral-local-proof",
    },
    "destination": {"identity_type": "zlar_destination_id", "presence": "bound", "value": DESTINATION_ID},
    "human_principal": {"presence": "explicitly_unbound", "reason": "unbound_by_star4"},
    "mcp_client": {"presence": "explicitly_unbound", "reason": "unbound_by_star4"},
    "mcp_server": {"identity_type": "zlar_mcp_server_id", "presence": "bound", "value": SERVER_ID},
    "verifier": {
        "identity_type": "zlar_verifier_id",
        "presence": "bound",
        "value": OFFLINE_VERIFIER_ID,
    },
}

AUTH_REQUIRED_FIELDS = {
    "action",
    "audience",
    "authority_domain",
    "candidate_id",
    "canonical_request",
    "canonicalization_id",
    "delegation_chain",
    "delegation_mode",
    "destination",
    "evidence_schema_version",
    "expires_at",
    "field_registry_id",
    "issued_at",
    "issuer",
    "max_uses",
    "nonce",
    "package_id",
    "purpose",
    "receipt_consumption_semantics",
    "recognition_profile",
    "resource",
    "revoked",
    "roles",
    "server_id",
    "slot",
    "source_id",
    "staged_artifact_id",
    "tool_contract_digest",
    "tool_name",
}


BASE_CASES: list[tuple[str, str]] = [
    ("AUTH-001-missing-authorization", "missing_authorization"),
    ("AUTH-002-malformed-authorization", "malformed_authorization"),
    ("AUTH-003-unsigned-authorization", "unsigned_authorization"),
    ("AUTH-004-invalid-signature", "invalid_signature"),
    ("AUTH-005-stale-authorization", "stale_authorization"),
    ("AUTH-006-revoked-authorization", "revoked_authorization"),
    ("AUTH-007-unknown-issuer", "unknown_issuer"),
    ("AUTH-008-delegated-authorization", "delegation_not_permitted"),
    ("AUTH-009-exhausted-authorization", "authorization_exhausted"),
    ("AUTH-010-wrong-issuer", "wrong_issuer"),
    ("AUTH-011-wrong-identity-type", "wrong_identity_type"),
    ("AUTH-012-wrong-key", "wrong_public_key_identity"),
    ("AUTH-013-wrong-audience", "wrong_audience"),
    ("AUTH-014-wrong-resource", "wrong_resource"),
    ("AUTH-015-wrong-action", "wrong_action"),
    ("AUTH-016-wrong-destination", "wrong_destination"),
    ("AUTH-017-wrong-purpose", "wrong_purpose"),
    ("AUTH-018-wrong-schema", "wrong_evidence_schema_version"),
    ("AUTH-019-wrong-profile", "wrong_recognition_profile"),
    ("AUTH-020-wrong-package", "wrong_package_id"),
    ("AUTH-021-wrong-server", "wrong_server_id"),
    ("AUTH-022-wrong-source", "wrong_source_id"),
    ("AUTH-023-wrong-tool-contract", "wrong_tool_contract_digest"),
    ("AUTH-024-wrong-tool", "wrong_tool_name"),
    ("AUTH-025-wrong-authority-domain", "wrong_authority_domain"),
    ("AUTH-026-wrong-slot", "wrong_slot"),
    ("AUTH-027-wrong-artifact", "wrong_staged_artifact_id"),
    ("AUTH-028-wrong-generation", "wrong_canonical_request"),
    ("AUTH-029-wrong-request", "wrong_canonical_request"),
    ("AUTH-030-wrong-nonce", "wrong_nonce"),
    ("AUTH-031-wrong-expiry", "wrong_expiry"),
    ("AUTH-032-wrong-max-uses", "wrong_max_uses"),
    ("AUTH-033-absent-audience", "absent_audience"),
    ("AUTH-034-multiple-audience", "multiple_audience"),
    ("AUTH-035-wildcard-audience", "wildcard_audience"),
    ("AUTH-036-conflicting-audience", "conflicting_audience"),
    ("AUTH-037-noncanonical-audience", "noncanonical_audience"),
    ("AUTH-038-absent-resource", "absent_resource"),
    ("AUTH-039-multiple-resource", "multiple_resource"),
    ("AUTH-040-wildcard-resource", "wildcard_resource"),
    ("AUTH-041-conflicting-resource", "conflicting_resource"),
    ("AUTH-042-noncanonical-resource", "noncanonical_resource"),
    ("AUTH-043-absent-destination", "absent_destination"),
    ("AUTH-044-multiple-destination", "multiple_destination"),
    ("AUTH-045-wildcard-destination", "wildcard_destination"),
    ("AUTH-046-conflicting-destination", "conflicting_destination"),
    ("AUTH-047-noncanonical-destination", "noncanonical_destination"),
    ("AUTH-048-unknown-presence", "unknown_presence_semantics"),
    ("AUTH-049-not-collected-presence", "not_collected_presence_semantics"),
    ("AUTH-050-missing-required-field", "missing_required_field"),
    ("AUTH-051-null-required-field", "null_required_field"),
    ("AUTH-052-empty-required-field", "empty_required_field"),
]

PROTOCOL_CASES: list[tuple[str, str]] = [
    ("PROTO-001-caller-recognition-policy", "caller_supplied_recognition_policy"),
    ("PROTO-002-caller-public-key", "caller_supplied_public_key"),
    ("PROTO-003-caller-destination-config", "caller_supplied_destination_configuration"),
    ("PROTO-004-caller-state", "caller_supplied_state"),
    ("PROTO-005-caller-path", "caller_supplied_path"),
    ("PROTO-006-caller-effect-adapter", "caller_supplied_effect_adapter"),
    ("PROTO-007-caller-bearer-token", "caller_supplied_bearer_token"),
    ("PROTO-008-caller-receipt-status", "caller_supplied_receipt_status"),
    ("PROTO-009-unknown-method", "unknown_method"),
    ("PROTO-010-unknown-tool", "unknown_tool"),
    ("PROTO-011-duplicate-json-key", "duplicate_json_key"),
    ("PROTO-012-byte-ambiguity", "byte_ambiguity"),
    ("PROTO-013-forbidden-extra-field", "forbidden_extra_field"),
    ("PROTO-014-list-changed", "tools_list_changed"),
    ("PROTO-015-inconsistent-second-list", "inconsistent_second_tools_list"),
    ("PROTO-016-unsupported-schema-dialect", "unsupported_schema_dialect"),
    ("PROTO-017-capability-drift", "capability_drift"),
    ("PROTO-018-metadata-drift", "metadata_drift"),
    ("PROTO-019-input-schema-drift", "input_schema_drift"),
    ("PROTO-020-output-schema-drift", "output_schema_drift"),
    ("PROTO-021-package-drift", "package_drift"),
    ("PROTO-022-source-drift", "source_drift"),
    ("PROTO-023-tool-contract-drift", "tool_contract_drift"),
    ("PROTO-024-protected-state-drift", "protected_state_drift"),
    ("PROTO-025-alternate-request-form", "alternate_request_form"),
    ("PROTO-026-malformed-json", "malformed_json"),
    ("PROTO-027-tools-call-before-initialize", "session_not_initialized"),
]

COLLISION_CASE = ("COLLISION-001-pre-existing-output", "pre_existing_output_collision")
CROSSING_CASE = ("CROSSING-001-recognized-promotion", "recognized")
REPLAY_CASE = ("REPLAY-001-consumed-authorization", "authorization_replayed")
POST_CASES: list[tuple[str, str]] = [
    ("POST-001-state-generation-drift", "protected_state_drift"),
    ("POST-002-second-artifact-attempt", "wrong_canonical_request"),
    ("POST-003-fresh-nonce-old-generation", "protected_state_drift"),
    ("POST-004-revoked-after-acceptance", "revoked_authorization"),
]

CLASS_SUBTOTALS = {
    "base_authorization_negative": 52,
    "post_acceptance": 4,
    "pre_existing_output_collision": 1,
    "protocol_probe": 27,
    "recognized_crossing": 1,
    "replay": 1,
}
TOTAL_CASES = 86

CAMPAIGN_OUTPUT_PATHS = [
    "attempt-inputs.json",
    "authorization.json",
    "collision-preexisting",
    "consumption-receipt.json",
    "coverage-envelope.json",
    "coverage-map.json",
    "decision-receipts/",
    "destination-registry.json",
    "effect-receipt.json",
    "matrix-evidence.json",
    "noncoverage-baseline.json",
    "output-manifest.json",
    "proof-summary.json",
    "public-key.json",
    "recognition-profile.json",
    "refusal-receipts/",
    "run-plan.json",
    "runner-matrix.json",
    "runtime-inventory.json",
    "session-observations.json",
    "state-final.json",
]


MANDATORY_NONCOVERAGE: list[tuple[str, str]] = [
    ("source_owner_imports", "open"),
    ("source_owner_modification", "open"),
    ("debugger_access", "open"),
    ("process_memory_access", "open"),
    ("same_user_state_access", "open"),
    ("direct_filesystem_mutation", "open"),
    ("direct_destination_mutation", "open"),
    ("alternate_clients", "unknown"),
    ("alternate_servers", "unknown"),
    ("alternate_transports", "unknown"),
    ("alternate_tools", "unknown"),
    ("alternate_adapters", "unknown"),
    ("shell_paths", "open"),
    ("browser_paths", "unknown"),
    ("application_paths", "unknown"),
    ("network_paths", "unknown"),
    ("host_integrity", "unknown"),
    ("runtime_integrity", "unknown"),
    ("kernel_integrity", "unknown"),
    ("filesystem_integrity", "unknown"),
    ("codex_execution_bridge_integrity", "unknown"),
    ("crash_atomicity", "unknown"),
    ("power_loss_atomicity", "unknown"),
    ("parallel_calls", "unknown"),
    ("cross_process_serialization", "unknown"),
    ("durable_exactly_once", "unknown"),
    ("recovery_behavior", "unknown"),
    ("receipt_retention", "unknown"),
    ("external_receipt_custody", "unknown"),
    ("operational_revocation", "unknown"),
    ("key_custody", "unknown"),
    ("accountable_human_authority", "unknown"),
    ("institutional_recognition", "unknown"),
    ("external_domain_recognition", "unknown"),
    ("production_recognition", "unknown"),
    ("public_recognition", "unknown"),
    ("alternate_request_forms", "unknown"),
    ("unknown_methods", "unknown"),
    ("unknown_tools", "unknown"),
]


def base_authorization_payload(package_id: str, source_id: str, public_key_id: str) -> dict[str, Any]:
    return {
        "action": ACTION,
        "audience": AUDIENCE,
        "authority_domain": AUTHORITY_DOMAIN,
        "candidate_id": CANDIDATE_ID,
        "canonical_request": deepcopy(CANONICAL_REQUEST),
        "canonicalization_id": CANONICALIZATION_ID,
        "delegation_chain": [],
        "delegation_mode": "no_delegation",
        "destination": DESTINATION_ID,
        "evidence_schema_version": EVIDENCE_SCHEMA_VERSION,
        "expires_at": AUTH_EXPIRES_AT,
        "field_registry_id": FIELD_REGISTRY_ID,
        "issued_at": AUTH_ISSUED_AT,
        "issuer": {
            "identity_type": "issuer_qualified_uri",
            "issuer_id": "zlar-issuer://candidate-005/ephemeral-local-proof",
            "public_key_id": public_key_id,
        },
        "max_uses": 1,
        "nonce": AUTH_NONCE,
        "package_id": package_id,
        "purpose": PURPOSE,
        "receipt_consumption_semantics": "destination_atomic_single_use_before_effect",
        "recognition_profile": {
            "identity": RECOGNITION_PROFILE_ID,
            "profile_version": RECOGNITION_PROFILE_VERSION,
            "schema_version": RECOGNITION_SCHEMA_VERSION,
        },
        "resource": RESOURCE,
        "revoked": False,
        "roles": deepcopy(ROLE_BINDINGS),
        "server_id": SERVER_ID,
        "slot": SLOT,
        "source_id": source_id,
        "staged_artifact_id": STAGED_ARTIFACT_ID,
        "tool_contract_digest": TOOL_CONTRACT_DIGEST,
        "tool_name": ACTION,
    }


def recognition_profile(package_id: str, source_id: str, public_key_id: str) -> dict[str, Any]:
    payload = base_authorization_payload(package_id, source_id, public_key_id)
    return {
        "accepted_authorization": payload,
        "accepted_public_key_id": public_key_id,
        "immutable": True,
        "profile_identity": RECOGNITION_PROFILE_ID,
        "profile_version": RECOGNITION_PROFILE_VERSION,
        "schema_version": RECOGNITION_SCHEMA_VERSION,
    }


def _case(case_id: str, case_class: str, expected_reason: str, expected_result: str = "refused") -> dict[str, Any]:
    return {
        "case_class": case_class,
        "case_id": case_id,
        "expected_consumptions": 1 if expected_result == "accepted" else 0,
        "expected_mutations": 1 if expected_result == "accepted" else 0,
        "expected_reason": expected_reason,
        "expected_result": expected_result,
    }


def ordered_case_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    preinit = PROTOCOL_CASES[-1]
    rows.append(_case(preinit[0], "protocol_probe", preinit[1]))
    rows.extend(_case(case_id, "base_authorization_negative", reason) for case_id, reason in BASE_CASES)
    rows.extend(_case(case_id, "protocol_probe", reason) for case_id, reason in PROTOCOL_CASES[:-1])
    rows.append(_case(COLLISION_CASE[0], "pre_existing_output_collision", COLLISION_CASE[1]))
    rows.append(_case(CROSSING_CASE[0], "recognized_crossing", CROSSING_CASE[1], "accepted"))
    rows.append(_case(REPLAY_CASE[0], "replay", REPLAY_CASE[1]))
    rows.extend(_case(case_id, "post_acceptance", reason) for case_id, reason in POST_CASES)
    return rows


def make_run_plan(package_id: str, source_id: str, attempt_hashes: dict[str, str]) -> dict[str, Any]:
    cases = ordered_case_rows()
    for row in cases:
        row["attempt_input_sha256"] = attempt_hashes[row["case_id"]]
    plan = {
        "campaign_output_paths": CAMPAIGN_OUTPUT_PATHS,
        "candidate_id": CANDIDATE_ID,
        "case_class_map": {row["case_id"]: row["case_class"] for row in cases},
        "cases": cases,
        "class_subtotals": CLASS_SUBTOTALS,
        "expected_consumption_budget": 1,
        "expected_mutation_budget": 1,
        "package_id": package_id,
        "plan_schema_version": "zlar.star4.run-plan.v1",
        "source_id": source_id,
        "tool_contract_digest": TOOL_CONTRACT_DIGEST,
        "total_cases": TOTAL_CASES,
    }
    validate_run_plan(plan, attempt_hashes=attempt_hashes)
    plan["plan_body_sha256"] = sha256_json(plan)
    return plan


def validate_run_plan(
    plan: object,
    attempt_hashes: dict[str, str] | None = None,
    matrix_rows: list[dict[str, Any]] | None = None,
) -> dict[str, bool]:
    if not isinstance(plan, dict):
        raise ValueError("run_plan_not_object")
    cases = plan.get("cases")
    if not isinstance(cases, list):
        raise ValueError("run_plan_cases")
    ids = [row.get("case_id") for row in cases if isinstance(row, dict)]
    if len(ids) != len(cases) or any(not isinstance(item, str) for item in ids):
        raise ValueError("run_plan_case_id")
    if len(set(ids)) != len(ids):
        raise ValueError("run_plan_duplicate_row")
    expected_rows = ordered_case_rows()
    expected_ids = [row["case_id"] for row in expected_rows]
    if ids != expected_ids:
        raise ValueError("run_plan_missing_extra_or_renamed_row")
    if len(ids) != TOTAL_CASES or plan.get("total_cases") != TOTAL_CASES:
        raise ValueError("run_plan_total")
    actual_subtotals: dict[str, int] = {}
    for row in cases:
        case_class = row.get("case_class")
        actual_subtotals[case_class] = actual_subtotals.get(case_class, 0) + 1
    if actual_subtotals != CLASS_SUBTOTALS or plan.get("class_subtotals") != CLASS_SUBTOTALS:
        raise ValueError("run_plan_class_subtotals")
    case_map = {row["case_id"]: row["case_class"] for row in cases}
    if plan.get("case_class_map") != case_map:
        raise ValueError("run_plan_class_map")
    if set(plan.get("campaign_output_paths", [])) != set(CAMPAIGN_OUTPUT_PATHS):
        raise ValueError("run_plan_output_paths")
    if COLLISION_CASE[0] not in ids or case_map[COLLISION_CASE[0]] != "pre_existing_output_collision":
        raise ValueError("collision_row_hidden_outside_plan")
    if attempt_hashes is not None:
        if set(attempt_hashes) != set(ids):
            raise ValueError("run_plan_attempt_set_mismatch")
        for row in cases:
            if row.get("attempt_input_sha256") != attempt_hashes[row["case_id"]]:
                raise ValueError("run_plan_attempt_hash_mismatch")
    if matrix_rows is not None:
        matrix_ids = [row.get("case_id") for row in matrix_rows]
        if matrix_ids != ids:
            raise ValueError("matrix_plan_set_mismatch")
        matrix_map = {row.get("case_id"): row.get("case_class") for row in matrix_rows}
        if matrix_map != case_map:
            raise ValueError("matrix_plan_class_mismatch")
    return {
        "case_class_map_equal": True,
        "class_subtotals_equal": True,
        "collision_inside_plan": True,
        "enumerated_size_equals_total": True,
        "ordered_case_set_equal": True,
        "plan_attempt_set_equal": attempt_hashes is not None,
        "plan_matrix_set_equal": matrix_rows is not None,
    }


def make_noncoverage_baseline(package_id: str, source_id: str) -> dict[str, Any]:
    return {
        "baseline_id": "adr-v4-007-revision-001-mandatory-noncoverage",
        "candidate_id": CANDIDATE_ID,
        "canonicalization_id": CANONICALIZATION_ID,
        "package_id": package_id,
        "producer_id": "accepted-adr-v4-007-revision-001",
        "schema_version": "zlar.star4.noncoverage-baseline.v1",
        "source_id": source_id,
        "surfaces": [
            {
                "required_disposition": disposition,
                "surface_id": surface_id,
                "uncertainty_reason": "outside_frozen_candidate_proof_boundary",
            }
            for surface_id, disposition in MANDATORY_NONCOVERAGE
        ],
    }


def make_runtime_inventory(package_id: str, source_id: str) -> dict[str, Any]:
    return {
        "candidate_id": CANDIDATE_ID,
        "canonicalization_id": CANONICALIZATION_ID,
        "collector_id": COLLECTOR_ID,
        "collector_version": "1",
        "methods": ["initialize", "tools/list", "tools/call"],
        "package_id": package_id,
        "protocol_profile_id": PROTOCOL_PROFILE_ID,
        "schema_version": "zlar.star4.runtime-inventory.v1",
        "source_id": source_id,
        "tool_contract": deepcopy(TOOL_CONTRACT),
        "tool_contract_digest": TOOL_CONTRACT_DIGEST,
    }


def make_destination_registry(package_id: str, source_id: str) -> dict[str, Any]:
    return {
        "candidate_id": CANDIDATE_ID,
        "canonicalization_id": CANONICALIZATION_ID,
        "declaration_only": True,
        "destination_id": DESTINATION_ID,
        "package_id": package_id,
        "producer_id": SERVER_ID,
        "routes": [
            {
                "action": ACTION,
                "consequence_class": "synthetic.deployment.promote",
                "recognition_point": "inside_destination_immediately_before_commit",
                "route_id": "destination.route.deployment-promote",
                "tool_name": ACTION,
            }
        ],
        "schema_version": "zlar.star4.destination-registry.v1",
        "source_id": source_id,
    }
