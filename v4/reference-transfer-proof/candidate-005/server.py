#!/usr/bin/env python3
"""Bounded stdio JSON-RPC/MCP destination for Candidate 005."""

from __future__ import annotations

import os
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

from canonical import CanonicalError, canonical_bytes, sha256_json, strict_loads
from contract import (
    ACTION,
    AUTH_EXPIRES_AT,
    AUTH_NONCE,
    AUTH_REQUIRED_FIELDS,
    CANONICAL_REQUEST,
    CANDIDATE_ID,
    DESTINATION_ID,
    FIXED_EVALUATION_EPOCH,
    INITIAL_ARTIFACT_ID,
    INITIAL_GENERATION,
    MCP_PROTOCOL_VERSION,
    PURPOSE,
    RECOGNITION_PROFILE_ID,
    RESOURCE,
    SERVER_ID,
    SLOT,
    STAGED_ARTIFACT_ID,
    TOOL_CONTRACT,
    TOOL_CONTRACT_DIGEST,
)
from crypto_rsa import PrivateKey, PublicKeyError, parse_public_evidence
from evidence import EvidenceError, sign_envelope, verify_envelope


class DestinationServer:
    def __init__(self, bootstrap: dict[str, Any], private_key: PrivateKey):
        self.bootstrap = deepcopy(bootstrap)
        self.private_key = private_key
        self.public_key = deepcopy(bootstrap["public_key"])
        parse_public_evidence(self.public_key)
        self.expected_authorization = deepcopy(bootstrap["expected_authorization"])
        self.recognition_profile = deepcopy(bootstrap["recognition_profile"])
        self.package_id = bootstrap["package_id"]
        self.source_id = bootstrap["source_id"]
        self.collision_path = Path(bootstrap["collision_path"])
        self.fault_request_ids = dict(bootstrap["fault_request_ids"])
        self.initialized = False
        self.list_observation_count = 0
        self.protected_mutations = 0
        self.recognized_consumptions = 0
        self.state: dict[str, Any] = {
            "active_artifact_id": INITIAL_ARTIFACT_ID,
            "active_slot": SLOT,
            "consumed_authorization_nonces": [],
            "effect_receipt_id": None,
            "generation": INITIAL_GENERATION,
            "settlement_ledger": [],
            "staged_artifact_id": STAGED_ARTIFACT_ID,
        }

    def _state_snapshot(self) -> dict[str, Any]:
        return deepcopy(self.state)

    def _decision_payload(
        self,
        attempt_id: str,
        outcome: str,
        reason: str,
        authorization_id: str | None,
        state_before: dict[str, Any],
        state_after: dict[str, Any],
        settlement_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "attempt_id": attempt_id,
            "authorization_receipt_id": authorization_id,
            "candidate_id": CANDIDATE_ID,
            "decision_point": "destination_recognition_immediately_before_commit",
            "destination_id": DESTINATION_ID,
            "observed_at_epoch": FIXED_EVALUATION_EPOCH,
            "outcome": outcome,
            "package_id": self.package_id,
            "protected_mutations_after": self.protected_mutations + (1 if outcome == "accepted" else 0),
            "reason": reason,
            "recognized_consumptions_after": self.recognized_consumptions + (1 if outcome == "accepted" else 0),
            "server_id": SERVER_ID,
            "settlement_id": settlement_id,
            "source_id": self.source_id,
            "state_after_digest": sha256_json(state_after),
            "state_before_digest": sha256_json(state_before),
            "tool_contract_digest": TOOL_CONTRACT_DIGEST,
        }

    def _refuse(self, attempt_id: str, reason: str, authorization_id: str | None = None) -> dict[str, Any]:
        state = self._state_snapshot()
        decision = sign_envelope(
            "decision",
            self._decision_payload(attempt_id, "refused", reason, authorization_id, state, state),
            self.private_key,
        )
        refusal = sign_envelope(
            "refusal",
            {
                "attempt_id": attempt_id,
                "authorization_receipt_id": authorization_id,
                "candidate_id": CANDIDATE_ID,
                "decision_receipt_id": decision["payload"]["receipt_id"],
                "destination_id": DESTINATION_ID,
                "protected_mutations": self.protected_mutations,
                "reason": reason,
                "recognized_consumptions": self.recognized_consumptions,
                "state_digest": sha256_json(state),
            },
            self.private_key,
        )
        return {
            "decision": decision,
            "effect": None,
            "refusal": refusal,
            "state": state,
        }

    def _recognize(self, authorization: object) -> tuple[str | None, str | None]:
        if authorization is None:
            return None, "missing_authorization"
        if not isinstance(authorization, dict):
            return None, "malformed_authorization"
        if "signature" not in authorization:
            return None, "unsigned_authorization"
        try:
            parse_public_evidence(self.public_key)
        except PublicKeyError:
            return None, "public_key_modulus_bits"
        try:
            payload = verify_envelope(authorization, self.public_key, expected_type="authorization")
        except EvidenceError as exc:
            if str(exc) == "signature_invalid":
                return None, "invalid_signature"
            return None, "malformed_authorization"
        authorization_id = payload["receipt_id"]
        body = {key: value for key, value in payload.items() if key != "receipt_id"}
        missing = AUTH_REQUIRED_FIELDS - set(body)
        extra = set(body) - AUTH_REQUIRED_FIELDS
        if missing:
            return authorization_id, "missing_required_field"
        if extra:
            return authorization_id, "forbidden_extra_field"
        if any(value is None for value in body.values()):
            return authorization_id, "null_required_field"
        if any(value == "" for value in body.values()):
            return authorization_id, "empty_required_field"
        roles = body.get("roles")
        if isinstance(roles, dict):
            for role in ("human_principal", "accountable_owner", "agent_or_workload", "mcp_client"):
                record = roles.get(role)
                if isinstance(record, dict) and record.get("presence") == "unknown":
                    return authorization_id, "unknown_presence_semantics"
                if isinstance(record, dict) and record.get("presence") == "not_collected":
                    return authorization_id, "not_collected_presence_semantics"
        if body.get("delegation_mode") != "no_delegation" or body.get("delegation_chain") != []:
            return authorization_id, "delegation_not_permitted"
        if body.get("revoked") is True:
            return authorization_id, "revoked_authorization"
        if body.get("max_uses") == 0:
            return authorization_id, "authorization_exhausted"
        if body.get("expires_at", 0) <= FIXED_EVALUATION_EPOCH:
            return authorization_id, "stale_authorization"
        issuer = body.get("issuer")
        if not isinstance(issuer, dict):
            return authorization_id, "wrong_identity_type"
        if issuer.get("identity_type") != "issuer_qualified_uri":
            return authorization_id, "wrong_identity_type"
        issuer_id = issuer.get("issuer_id")
        if issuer_id == "zlar-issuer://unregistered":
            return authorization_id, "unknown_issuer"
        if issuer_id != self.expected_authorization["issuer"]["issuer_id"]:
            return authorization_id, "wrong_issuer"
        if issuer.get("public_key_id") != self.expected_authorization["issuer"]["public_key_id"]:
            return authorization_id, "wrong_public_key_identity"
        for field, label in (("audience", "audience"), ("resource", "resource"), ("destination", "destination")):
            value = body.get(field)
            if isinstance(value, dict) and value.get("presence") == "explicitly_unbound":
                return authorization_id, f"absent_{label}"
            if isinstance(value, list):
                return authorization_id, f"multiple_{label}"
            if value == "*":
                return authorization_id, f"wildcard_{label}"
            if isinstance(value, dict):
                return authorization_id, f"conflicting_{label}"
            if isinstance(value, str) and value != value.strip():
                return authorization_id, f"noncanonical_{label}"
        exact_checks = [
            ("audience", "wrong_audience"),
            ("resource", "wrong_resource"),
            ("action", "wrong_action"),
            ("destination", "wrong_destination"),
            ("purpose", "wrong_purpose"),
            ("evidence_schema_version", "wrong_evidence_schema_version"),
            ("recognition_profile", "wrong_recognition_profile"),
            ("package_id", "wrong_package_id"),
            ("server_id", "wrong_server_id"),
            ("source_id", "wrong_source_id"),
            ("tool_contract_digest", "wrong_tool_contract_digest"),
            ("tool_name", "wrong_tool_name"),
            ("authority_domain", "wrong_authority_domain"),
            ("slot", "wrong_slot"),
            ("staged_artifact_id", "wrong_staged_artifact_id"),
            ("canonical_request", "wrong_canonical_request"),
            ("nonce", "wrong_nonce"),
            ("expires_at", "wrong_expiry"),
            ("max_uses", "wrong_max_uses"),
            ("roles", "wrong_roles"),
            ("canonicalization_id", "wrong_canonicalization_id"),
            ("field_registry_id", "wrong_field_registry_id"),
            ("receipt_consumption_semantics", "wrong_consumption_semantics"),
        ]
        for field, reason in exact_checks:
            if body.get(field) != self.expected_authorization[field]:
                return authorization_id, reason
        if body["nonce"] in self.state["consumed_authorization_nonces"]:
            return authorization_id, "authorization_replayed"
        if self.state["generation"] != body["canonical_request"]["expected_generation"]:
            return authorization_id, "protected_state_drift"
        return authorization_id, None

    def _accept(self, attempt_id: str, authorization: dict[str, Any]) -> dict[str, Any]:
        authorization_id = authorization["payload"]["receipt_id"]
        state_before = self._state_snapshot()
        settlement_id = "settlement-sha256:" + sha256_json(
            {"attempt_id": attempt_id, "authorization_receipt_id": authorization_id, "state_before": state_before}
        )
        state_after_core = {
            **state_before,
            "active_artifact_id": STAGED_ARTIFACT_ID,
            "consumed_authorization_nonces": state_before["consumed_authorization_nonces"] + [AUTH_NONCE],
            "generation": state_before["generation"] + 1,
        }
        decision = sign_envelope(
            "decision",
            self._decision_payload(
                attempt_id,
                "accepted",
                "recognized",
                authorization_id,
                state_before,
                state_after_core,
                settlement_id,
            ),
            self.private_key,
        )
        effect = sign_envelope(
            "effect",
            {
                "active_artifact_after": STAGED_ARTIFACT_ID,
                "active_artifact_before": INITIAL_ARTIFACT_ID,
                "attempt_id": attempt_id,
                "authorization_receipt_id": authorization_id,
                "candidate_id": CANDIDATE_ID,
                "decision_receipt_id": decision["payload"]["receipt_id"],
                "destination_id": DESTINATION_ID,
                "generation_after": state_before["generation"] + 1,
                "generation_before": state_before["generation"],
                "protected_mutation_count": 1,
                "settlement_id": settlement_id,
                "tool_contract_digest": TOOL_CONTRACT_DIGEST,
            },
            self.private_key,
        )
        consumption = sign_envelope(
            "consumption",
            {
                "attempt_id": attempt_id,
                "authorization_receipt_id": authorization_id,
                "candidate_id": CANDIDATE_ID,
                "decision_receipt_id": decision["payload"]["receipt_id"],
                "effect_receipt_id": effect["payload"]["receipt_id"],
                "nonce": AUTH_NONCE,
                "recognized_consumption_count": 1,
                "settlement_id": settlement_id,
            },
            self.private_key,
        )
        final_state = {
            **state_after_core,
            "effect_receipt_id": effect["payload"]["receipt_id"],
            "settlement_ledger": state_before["settlement_ledger"]
            + [
                {
                    "authorization_receipt_id": authorization_id,
                    "consumption_receipt_id": consumption["payload"]["receipt_id"],
                    "decision_receipt_id": decision["payload"]["receipt_id"],
                    "effect_receipt_id": effect["payload"]["receipt_id"],
                    "settlement_id": settlement_id,
                }
            ],
        }
        # The only protected commit in the bounded destination process.
        self.state = final_state
        self.protected_mutations += 1
        self.recognized_consumptions += 1
        return {
            "consumption": consumption,
            "decision": decision,
            "effect": effect,
            "refusal": None,
            "state": self._state_snapshot(),
        }

    def handle_raw(self, raw: bytes) -> dict[str, Any]:
        attempt_id = _extract_attempt_id(raw)
        try:
            request = strict_loads(raw)
        except CanonicalError as exc:
            message = str(exc)
            if message.startswith("duplicate_json_key"):
                reason = "duplicate_json_key"
            elif message.startswith("byte_ambiguity"):
                reason = "byte_ambiguity"
            else:
                reason = "malformed_json"
            return _rpc_result(attempt_id, self._refuse(attempt_id, reason))
        if not isinstance(request, dict):
            return _rpc_result(attempt_id, self._refuse(attempt_id, "alternate_request_form"))
        attempt_id = request.get("id") if isinstance(request.get("id"), str) else attempt_id
        if set(request) != {"id", "jsonrpc", "method", "params"}:
            return _rpc_result(attempt_id, self._refuse(attempt_id, "forbidden_extra_field"))
        if request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
            return _rpc_result(attempt_id, self._refuse(attempt_id, "alternate_request_form"))
        if attempt_id in self.fault_request_ids:
            return _rpc_result(attempt_id, self._refuse(attempt_id, self.fault_request_ids[attempt_id]))
        method = request["method"]
        params = request["params"]
        if method == "initialize":
            if params != {"capabilities": {}, "protocolVersion": MCP_PROTOCOL_VERSION}:
                return _rpc_result(attempt_id, self._refuse(attempt_id, "protocol_initialization_mismatch"))
            self.initialized = True
            return _rpc_result(
                attempt_id,
                {
                    "capabilities": deepcopy(TOOL_CONTRACT["capabilities"]),
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "serverInfo": {"name": SERVER_ID, "version": "1"},
                },
            )
        if method == "tools/list":
            if not self.initialized:
                return _rpc_result(attempt_id, self._refuse(attempt_id, "session_not_initialized"))
            if params != {}:
                return _rpc_result(attempt_id, self._refuse(attempt_id, "alternate_request_form"))
            self.list_observation_count += 1
            return _rpc_result(
                attempt_id,
                {
                    "jsonSchemaDialect": TOOL_CONTRACT["json_schema_dialect"],
                    "tools": deepcopy(TOOL_CONTRACT["tools"]),
                    "toolContractDigest": TOOL_CONTRACT_DIGEST,
                },
            )
        if method != "tools/call":
            return _rpc_result(attempt_id, self._refuse(attempt_id, "unknown_method"))
        if not self.initialized:
            return _rpc_result(attempt_id, self._refuse(attempt_id, "session_not_initialized"))
        if not isinstance(params, dict) or set(params) != {"arguments", "name"}:
            return _rpc_result(attempt_id, self._refuse(attempt_id, "alternate_request_form"))
        if params.get("name") != ACTION:
            return _rpc_result(attempt_id, self._refuse(attempt_id, "unknown_tool"))
        arguments = params.get("arguments")
        if not isinstance(arguments, dict):
            return _rpc_result(attempt_id, self._refuse(attempt_id, "alternate_request_form"))
        forbidden_caller_fields = {
            "recognition_policy": "caller_supplied_recognition_policy",
            "public_key": "caller_supplied_public_key",
            "destination_configuration": "caller_supplied_destination_configuration",
            "state": "caller_supplied_state",
            "path": "caller_supplied_path",
            "effect_adapter": "caller_supplied_effect_adapter",
            "bearer_token": "caller_supplied_bearer_token",
            "receipt_status": "caller_supplied_receipt_status",
        }
        for field, reason in forbidden_caller_fields.items():
            if field in arguments:
                return _rpc_result(attempt_id, self._refuse(attempt_id, reason))
        if set(arguments) - {"authorization", "request"}:
            return _rpc_result(attempt_id, self._refuse(attempt_id, "forbidden_extra_field"))
        if "request" not in arguments or arguments["request"] != CANONICAL_REQUEST:
            return _rpc_result(attempt_id, self._refuse(attempt_id, "wrong_canonical_request"))
        if attempt_id == "COLLISION-001-pre-existing-output":
            try:
                os.lstat(self.collision_path)
            except FileNotFoundError:
                return _rpc_result(attempt_id, self._refuse(attempt_id, "expected_collision_missing"))
            return _rpc_result(attempt_id, self._refuse(attempt_id, "pre_existing_output_collision"))
        authorization = arguments.get("authorization")
        authorization_id, refusal_reason = self._recognize(authorization)
        if refusal_reason is not None:
            return _rpc_result(attempt_id, self._refuse(attempt_id, refusal_reason, authorization_id))
        assert isinstance(authorization, dict)
        return _rpc_result(attempt_id, self._accept(attempt_id, authorization))


def _extract_attempt_id(raw: bytes) -> str:
    match = re.search(rb'"id"\s*:\s*"([A-Za-z0-9._-]+)"', raw[:1024])
    if match is None:
        return "unidentified-protocol-attempt"
    return match.group(1).decode("ascii", errors="strict")


def _rpc_result(request_id: str, result: dict[str, Any]) -> dict[str, Any]:
    return {"id": request_id, "jsonrpc": "2.0", "result": result}


def serve(read_fd: int, write_fd: int, bootstrap: dict[str, Any], private_key: PrivateKey) -> int:
    server = DestinationServer(bootstrap, private_key)
    with os.fdopen(read_fd, "rb", buffering=0) as reader, os.fdopen(write_fd, "wb", buffering=0) as writer:
        while True:
            raw = reader.readline()
            if raw == b"":
                return 0
            try:
                response = server.handle_raw(raw.rstrip(b"\n"))
            except Exception:
                # Product uncertainty is structured refusal. Private key material is never interpolated.
                attempt_id = _extract_attempt_id(raw)
                response = _rpc_result(attempt_id, server._refuse(attempt_id, "internal_uncertainty"))
            writer.write(canonical_bytes(response) + b"\n")
            writer.flush()


if __name__ == "__main__":
    raise SystemExit("server.py is started only by the bounded proof runner through inherited in-memory state")
