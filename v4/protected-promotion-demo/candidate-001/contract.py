#!/usr/bin/env python3
"""Frozen semantic contract for Protected Promotion Candidate 001."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from canonical import CANONICALIZATION_ID, canonical_bytes, sha256_bytes, sha256_json
from evidence import FIELD_REGISTRY_ID, SCHEMA_VERSION


CANDIDATE_ID = "v4.protected-promotion-demo.candidate-001"
PACKAGE_SCHEMA_VERSION = "zlar.protected-promotion.package-manifest.v1"
RUN_IDENTITY_SCHEMA = "zlar.protected-promotion.run-identity.v1"
PROTOCOL_VERSION = "zlar.protected-promotion.local-jsonl.v1"
RECOGNITION_PROFILE_ID = "zlar.protected-promotion.destination-recognition.v1"
RECOGNITION_PROFILE_VERSION = "1"
TOOL_NAME = "deployment.promote"
DESTINATION_ID = "zlar.synthetic.deployment-destination.release-slot-A"
SERVER_ID = "zlar.protected-promotion.destination-process.v1"
AUTHORITY_ID = "zlar.local-demo-authority.operator-identity-unproven.v1"
AUDIENCE = SERVER_ID
RESOURCE = "zlar.synthetic.release-slot-A"
PURPOSE = "bounded_protected_promotion_local_evaluation"
SLOT = "release-slot-A"
INITIAL_GENERATION = 7
FINAL_GENERATION = 8
INITIAL_ARTIFACT = "synthetic-artifact.release-v7"
STAGED_ARTIFACT = "synthetic-artifact.release-v8"
EVALUATION_EPOCH = 1784678400
ISSUED_AT = EVALUATION_EPOCH - 60
EXPIRES_AT = EVALUATION_EPOCH + 3600
DECISION_TIME = EVALUATION_EPOCH + 1
AUTH_NONCE = "protected-promotion-candidate-001-one-use-nonce"

ALLOWED_CAMPAIGN_BASENAMES = {
    "zlar-protected-promotion-builder-campaign-001",
    "zlar-protected-promotion-builder-campaign-002",
    "zlar-protected-promotion-builder-campaign-003",
    "zlar-protected-promotion-verifier-campaign-001",
}

ROLE_BINDINGS = {
    "accountable_owner": {"presence": "explicitly_unbound"},
    "agent_workload": {"presence": "explicitly_unbound"},
    "human_principal": {"presence": "explicitly_unbound"},
    "mcp_client_identity": {"presence": "explicitly_unbound"},
}

CANONICAL_REQUEST = {
    "expected_generation": INITIAL_GENERATION,
    "slot": SLOT,
    "staged_artifact": STAGED_ARTIFACT,
}

TOOL_CONTRACT = {
    "capabilities": {"single_sequential_request_stream": True, "tools_list_changed": False},
    "input_schema": {
        "additionalProperties": False,
        "properties": {
            "authorization_credential": {"type": ["object", "null"]},
            "request": {
                "additionalProperties": False,
                "properties": {
                    "expected_generation": {"const": INITIAL_GENERATION},
                    "slot": {"const": SLOT},
                    "staged_artifact": {"const": STAGED_ARTIFACT},
                },
                "required": ["expected_generation", "slot", "staged_artifact"],
                "type": "object",
            },
        },
        "required": ["authorization_credential", "request"],
        "type": "object",
    },
    "metadata": {
        "consequence_capable": True,
        "consequence_class": "synthetic.deployment.promote",
        "destination_recognition_required": True,
    },
    "name": TOOL_NAME,
    "output_schema": {
        "additionalProperties": False,
        "required": ["decision", "refusal", "settlement", "state"],
        "type": "object",
    },
    "protocol": PROTOCOL_VERSION,
    "schema_dialect": "https://json-schema.org/draft/2020-12/schema",
}
TOOL_CONTRACT_DIGEST = sha256_bytes(canonical_bytes(TOOL_CONTRACT))

INITIAL_STATE = {
    "active_artifact": INITIAL_ARTIFACT,
    "consumed_authorization_ids": [],
    "consumed_nonces": [],
    "effect_id": None,
    "generation": INITIAL_GENERATION,
    "settlement_ledger": [],
    "slot": SLOT,
}
INITIAL_STATE_DIGEST = sha256_json(INITIAL_STATE)

RECOGNITION_FIELDS = [
    "action",
    "audience",
    "authority_id",
    "authority_public_key_id",
    "candidate_id",
    "canonical_request",
    "canonicalization_id",
    "decision_event_id",
    "decision_time",
    "delegation",
    "destination_id",
    "destination_public_key_id",
    "evaluation_epoch",
    "evidence_schema_version",
    "expires_at",
    "field_registry_id",
    "issued_at",
    "max_uses",
    "nonce",
    "package_id",
    "pre_state_digest",
    "proposal_id",
    "purpose",
    "recognition_profile_id",
    "recognition_profile_version",
    "resource",
    "roles",
    "run_identity_digest",
    "server_id",
    "slot",
    "source_id",
    "staged_artifact",
    "tool_contract",
    "tool_contract_digest",
    "tool_name",
]

FORBIDDEN_CALLER_FIELDS = {
    "argv": "caller_supplied_argv",
    "bearer_token": "caller_supplied_bearer_token",
    "descriptor": "caller_supplied_descriptor",
    "destination_configuration": "caller_supplied_destination_configuration",
    "effect_adapter": "caller_supplied_effect_adapter",
    "environment": "caller_supplied_environment",
    "filesystem_path": "caller_supplied_filesystem_path",
    "mutable_state": "caller_supplied_mutable_state",
    "policy": "caller_supplied_policy",
    "private_key": "caller_supplied_private_key",
    "public_key": "caller_supplied_public_key",
    "receipt_status": "caller_supplied_receipt_status",
    "secret": "caller_supplied_secret",
    "state": "caller_supplied_state",
    "target": "caller_supplied_target",
}

MANDATORY_NONCOVERAGE = [
    ("source_owner_imports", "open"),
    ("source_owner_modification", "open"),
    ("process_memory", "open"),
    ("debugger", "open"),
    ("host_filesystem_control", "open"),
    ("same_user_interference", "open"),
    ("direct_filesystem_mutation", "open"),
    ("alternate_destination", "open"),
    ("shell_routes", "open"),
    ("browser_routes", "unknown"),
    ("application_routes", "unknown"),
    ("network_routes", "unknown"),
    ("kernel_integrity", "unknown"),
    ("runtime_integrity", "unknown"),
    ("clock_integrity", "unknown"),
    ("randomness_integrity", "unknown"),
    ("crash_atomicity", "unknown"),
    ("power_loss_atomicity", "unknown"),
    ("concurrent_exactly_once", "unknown"),
    ("recovery_behavior", "unknown"),
    ("durable_exactly_once", "unknown"),
    ("human_identity", "unknown"),
    ("accountable_authority", "unknown"),
    ("institutional_recognition", "unknown"),
    ("production_key_custody", "unknown"),
    ("operational_revocation", "unknown"),
    ("external_attestation", "unknown"),
    ("real_deployment", "unknown"),
    ("live_claude_or_codex", "unknown"),
]

DECLARED_ROUTES = [
    {
        "consequence_class": "synthetic.deployment.promote",
        "recognition_point": "destination_immediately_before_process_local_commit",
        "route_id": "destination.route.deployment-promote",
        "surface_id": "terminal.deployment-promote.release-slot-A",
        "tool_name": TOOL_NAME,
    },
    {
        "consequence_class": "none",
        "recognition_point": "not_applicable",
        "route_id": "authority.route.issue-one",
        "surface_id": "authority.issue-one-credential",
        "tool_name": None,
    },
    {
        "consequence_class": "none",
        "recognition_point": "not_applicable",
        "route_id": "verifier.route.read-only",
        "surface_id": "verifier.offline-read-only",
        "tool_name": None,
    },
]


def make_run_identity(
    package_id: str,
    source_id: str,
    campaign_id: str,
    launch_nonce: str,
    authority_public_key: dict[str, Any],
    destination_public_key: dict[str, Any],
) -> dict[str, Any]:
    authority_key_id = authority_public_key["public_key_id"]
    destination_key_id = destination_public_key["public_key_id"]
    if authority_key_id == destination_key_id:
        raise ValueError("shared_signer_key")
    return {
        "authority_public_key": deepcopy(authority_public_key),
        "authority_public_key_id": authority_key_id,
        "campaign_id": campaign_id,
        "candidate_id": CANDIDATE_ID,
        "destination_id": DESTINATION_ID,
        "destination_public_key": deepcopy(destination_public_key),
        "destination_public_key_id": destination_key_id,
        "evaluation_epoch": EVALUATION_EPOCH,
        "launch_nonce": launch_nonce,
        "package_id": package_id,
        "process_roles": {"authority": "authority", "destination": "destination"},
        "schema_version": RUN_IDENTITY_SCHEMA,
        "server_id": SERVER_ID,
        "source_id": source_id,
        "tool_contract_digest": TOOL_CONTRACT_DIGEST,
        "tool_name": TOOL_NAME,
    }


def make_proposal(run_identity_digest: str, package_id: str, source_id: str) -> dict[str, Any]:
    core = {
        "candidate_id": CANDIDATE_ID,
        "canonical_request": deepcopy(CANONICAL_REQUEST),
        "destination_id": DESTINATION_ID,
        "evaluation_epoch": EVALUATION_EPOCH,
        "package_id": package_id,
        "pre_state_digest": INITIAL_STATE_DIGEST,
        "purpose": PURPOSE,
        "run_identity_digest": run_identity_digest,
        "source_id": source_id,
        "tool_contract_digest": TOOL_CONTRACT_DIGEST,
    }
    return {**core, "proposal_id": "proposal-sha256:" + sha256_json(core)}


def make_credential_body(
    run_identity: dict[str, Any],
    proposal_id: str,
    decision_event_id: str,
) -> dict[str, Any]:
    return {
        "action": TOOL_NAME,
        "audience": AUDIENCE,
        "authority_id": AUTHORITY_ID,
        "authority_public_key_id": run_identity["authority_public_key_id"],
        "candidate_id": CANDIDATE_ID,
        "canonical_request": deepcopy(CANONICAL_REQUEST),
        "canonicalization_id": CANONICALIZATION_ID,
        "decision_event_id": decision_event_id,
        "decision_time": DECISION_TIME,
        "delegation": {"chain": [], "mode": "none"},
        "destination_id": DESTINATION_ID,
        "destination_public_key_id": run_identity["destination_public_key_id"],
        "evaluation_epoch": EVALUATION_EPOCH,
        "evidence_schema_version": SCHEMA_VERSION,
        "expires_at": EXPIRES_AT,
        "field_registry_id": FIELD_REGISTRY_ID,
        "issued_at": ISSUED_AT,
        "max_uses": 1,
        "nonce": AUTH_NONCE,
        "package_id": run_identity["package_id"],
        "pre_state_digest": INITIAL_STATE_DIGEST,
        "proposal_id": proposal_id,
        "purpose": PURPOSE,
        "recognition_profile_id": RECOGNITION_PROFILE_ID,
        "recognition_profile_version": RECOGNITION_PROFILE_VERSION,
        "resource": RESOURCE,
        "roles": deepcopy(ROLE_BINDINGS),
        "run_identity_digest": sha256_json(run_identity),
        "server_id": SERVER_ID,
        "slot": SLOT,
        "source_id": run_identity["source_id"],
        "staged_artifact": STAGED_ARTIFACT,
        "tool_contract": deepcopy(TOOL_CONTRACT),
        "tool_contract_digest": TOOL_CONTRACT_DIGEST,
        "tool_name": TOOL_NAME,
    }


def make_request(credential: object) -> dict[str, Any]:
    return {
        "authorization_credential": credential,
        "method": TOOL_NAME,
        "protocol": PROTOCOL_VERSION,
        "request": deepcopy(CANONICAL_REQUEST),
        "tool_contract_digest": TOOL_CONTRACT_DIGEST,
    }
