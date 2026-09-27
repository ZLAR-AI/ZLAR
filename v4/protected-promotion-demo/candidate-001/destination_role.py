#!/usr/bin/env python3
"""Destination-owned refusal and one bounded protected settlement."""

from __future__ import annotations

import errno
import os
from copy import deepcopy
from pathlib import Path
from typing import Any

from canonical import CanonicalError, canonical_bytes, read_json, sha256_bytes, sha256_json, strict_loads, write_json_exclusive
from contract import (
    AUTH_NONCE,
    CANDIDATE_ID,
    CANONICAL_REQUEST,
    DECISION_TIME,
    DESTINATION_ID,
    EVALUATION_EPOCH,
    EXPIRES_AT,
    FINAL_GENERATION,
    FORBIDDEN_CALLER_FIELDS,
    INITIAL_ARTIFACT,
    INITIAL_GENERATION,
    INITIAL_STATE,
    INITIAL_STATE_DIGEST,
    ISSUED_AT,
    PROTOCOL_VERSION,
    RECOGNITION_FIELDS,
    SERVER_ID,
    STAGED_ARTIFACT,
    TOOL_CONTRACT_DIGEST,
    TOOL_NAME,
    make_credential_body,
)
from crypto_rsa import PrivateKey, parse_public, public_evidence
from evidence import EvidenceError, sign_envelope, verify_envelope


class DestinationError(ValueError):
    pass


class DestinationRole:
    def __init__(self, key: PrivateKey, process_evidence: dict[str, Any], campaign_root: Path):
        self._key = key
        self.public_key = public_evidence(key)
        self.process_evidence = deepcopy(process_evidence)
        self.campaign_root = campaign_root
        self.run_identity: dict[str, Any] | None = None
        self.run_digest: str | None = None
        self.authority_public_key: dict[str, Any] | None = None
        self.proposal: dict[str, Any] | None = None
        self.event: dict[str, Any] | None = None
        self.expected_credential: dict[str, Any] | None = None
        self.state = deepcopy(INITIAL_STATE)
        self.protected_mutations = 0
        self.recognized_consumptions = 0
        self.commit_count = 0
        self.refusal_count = 0

    def bind_run(self, run_identity: object) -> dict[str, Any]:
        if self.run_identity is not None or not isinstance(run_identity, dict):
            raise DestinationError("run_already_bound_or_invalid")
        if run_identity.get("destination_public_key") != self.public_key:
            raise DestinationError("destination_public_key_binding")
        _, _, authority_key_id = parse_public(run_identity.get("authority_public_key"))
        _, _, destination_key_id = parse_public(self.public_key)
        if authority_key_id == destination_key_id:
            raise DestinationError("shared_signer_key")
        if run_identity.get("authority_public_key_id") != authority_key_id or run_identity.get(
            "destination_public_key_id"
        ) != destination_key_id:
            raise DestinationError("run_key_identity")
        self.run_identity = deepcopy(run_identity)
        self.run_digest = sha256_json(self.run_identity)
        self.authority_public_key = deepcopy(run_identity["authority_public_key"])
        return sign_envelope(
            "run_ack",
            {
                "acknowledged_role": "destination",
                "candidate_id": CANDIDATE_ID,
                "pinned_authority_public_key_id": authority_key_id,
                "private_material_export_count": 0,
                "process_evidence": self.process_evidence,
                "run_identity_digest": self.run_digest,
            },
            self._key,
            "destination",
        )

    def bind_authority_context(self, proposal: object, event: object) -> dict[str, Any]:
        if self.run_identity is None or self.authority_public_key is None or self.proposal is not None:
            raise DestinationError("authority_context_sequence")
        proposal_payload = verify_envelope(proposal, self.authority_public_key, "proposal", "authority")
        event_payload = verify_envelope(event, self.authority_public_key, "decision_event", "authority")
        if proposal_payload.get("run_identity_digest") != self.run_digest:
            raise DestinationError("proposal_run_binding")
        if event_payload.get("run_identity_digest") != self.run_digest:
            raise DestinationError("event_run_binding")
        if event_payload.get("proposal_id") != proposal_payload.get("proposal_id"):
            raise DestinationError("event_proposal_binding")
        if event_payload.get("proposal_digest") != sha256_json(proposal):
            raise DestinationError("event_proposal_digest")
        self.proposal = deepcopy(proposal)
        self.event = deepcopy(event)
        body = make_credential_body(
            self.run_identity,
            proposal_payload["proposal_id"],
            event_payload["receipt_id"],
        )
        self.expected_credential = body
        return sign_envelope(
            "run_ack",
            {
                "acknowledged_role": "destination",
                "authority_context_pinned": True,
                "decision_event_id": event_payload["receipt_id"],
                "proposal_id": proposal_payload["proposal_id"],
                "run_identity_digest": self.run_digest,
            },
            self._key,
            "destination",
        )

    def _decision_payload(
        self,
        attempt_id: str,
        outcome: str,
        reason: str,
        authorization_id: str | None,
        before: dict[str, Any],
        after: dict[str, Any],
        settlement_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "attempt_id": attempt_id,
            "authorization_credential_id": authorization_id,
            "candidate_id": CANDIDATE_ID,
            "decision_point": "destination_immediately_before_process_local_commit",
            "decision_time": DECISION_TIME,
            "destination_id": DESTINATION_ID,
            "outcome": outcome,
            "protected_mutations_after": self.protected_mutations + (1 if outcome == "accepted" else 0),
            "reason": reason,
            "recognized_consumptions_after": self.recognized_consumptions + (1 if outcome == "accepted" else 0),
            "run_identity_digest": self.run_digest,
            "server_id": SERVER_ID,
            "settlement_id": settlement_id,
            "state_after_digest": sha256_json(after),
            "state_before_digest": sha256_json(before),
            "tool_contract_digest": TOOL_CONTRACT_DIGEST,
        }

    def _refuse(self, attempt_id: str, reason: str, authorization_id: str | None = None) -> dict[str, Any]:
        state = deepcopy(self.state)
        decision = sign_envelope(
            "decision_receipt",
            self._decision_payload(attempt_id, "refused", reason, authorization_id, state, state),
            self._key,
            "destination",
        )
        refusal = sign_envelope(
            "refusal_receipt",
            {
                "attempt_id": attempt_id,
                "authorization_credential_id": authorization_id,
                "decision_receipt_id": decision["payload"]["receipt_id"],
                "destination_id": DESTINATION_ID,
                "protected_mutations": self.protected_mutations,
                "reason": reason,
                "recognized_consumptions": self.recognized_consumptions,
                "run_identity_digest": self.run_digest,
                "state_digest": sha256_json(state),
            },
            self._key,
            "destination",
        )
        self.refusal_count += 1
        return {"decision": decision, "refusal": refusal, "settlement": None, "state": state}

    def _recognize(self, credential: object) -> tuple[str | None, str | None]:
        if credential is None:
            return None, "missing_authorization_credential"
        if not isinstance(credential, dict):
            return None, "malformed_authorization_credential"
        if self.authority_public_key is None or self.expected_credential is None:
            return None, "authorization_context_not_pinned"
        if "signature" not in credential:
            return None, "unsigned_authorization_credential"
        try:
            payload = verify_envelope(credential, self.authority_public_key, "authorization_credential", "authority")
        except EvidenceError as exc:
            if str(exc) == "signature_key_identity":
                return None, "wrong_or_unknown_signer"
            if str(exc) == "signature_invalid":
                return None, "invalid_signature"
            return None, "malformed_authorization_credential"
        authorization_id = payload["receipt_id"]
        body = {key: value for key, value in payload.items() if key != "receipt_id"}
        if set(body) != set(RECOGNITION_FIELDS):
            return authorization_id, "authorization_field_set"
        if any(value is None for value in body.values()):
            return authorization_id, "null_recognition_field"
        if any(value == "" for value in body.values()):
            return authorization_id, "empty_recognition_field"
        if body.get("delegation") != {"chain": [], "mode": "none"}:
            return authorization_id, "delegation_not_permitted"
        # Replay is classified before ordinary state drift.
        if authorization_id in self.state["consumed_authorization_ids"] or body.get("nonce") in self.state[
            "consumed_nonces"
        ]:
            return authorization_id, "authorization_replayed"
        if body != self.expected_credential:
            return authorization_id, "recognition_binding_mismatch"
        if not (ISSUED_AT <= body["decision_time"] < EXPIRES_AT):
            return authorization_id, "authorization_stale_at_decision"
        if body["evaluation_epoch"] != EVALUATION_EPOCH:
            return authorization_id, "evaluation_epoch_mismatch"
        if sha256_json(self.state) != body["pre_state_digest"]:
            return authorization_id, "protected_state_drift"
        return authorization_id, None

    def handle_attempt(self, attempt_id: object, raw_hex: object) -> dict[str, Any]:
        if not isinstance(attempt_id, str) or not attempt_id or not isinstance(raw_hex, str):
            return self._refuse("unidentified-attempt", "malformed_transport")
        try:
            if len(raw_hex) % 2 or raw_hex != raw_hex.lower() or any(character not in "0123456789abcdef" for character in raw_hex):
                raise ValueError("raw_hex")
            raw = bytes.fromhex(raw_hex)
            request = strict_loads(raw)
        except CanonicalError as exc:
            reason = str(exc).split(":", 1)[0]
            return self._refuse(attempt_id, reason)
        except (ValueError, UnicodeError):
            return self._refuse(attempt_id, "malformed_transport")
        if not isinstance(request, dict):
            return self._refuse(attempt_id, "alternate_request_form")
        if raw != canonical_bytes(request):
            return self._refuse(attempt_id, "noncanonical_request_encoding")
        for field, reason in FORBIDDEN_CALLER_FIELDS.items():
            if field in request:
                return self._refuse(attempt_id, reason)
        expected_fields = {
            "authorization_credential",
            "method",
            "protocol",
            "request",
            "tool_contract_digest",
        }
        if set(request) != expected_fields:
            return self._refuse(attempt_id, "request_field_set")
        if request.get("protocol") != PROTOCOL_VERSION:
            return self._refuse(attempt_id, "prohibited_protocol_form")
        if request.get("method") != TOOL_NAME:
            return self._refuse(attempt_id, "unknown_method_or_tool")
        if request.get("tool_contract_digest") != TOOL_CONTRACT_DIGEST:
            return self._refuse(attempt_id, "tool_contract_drift")
        if request.get("request") != CANONICAL_REQUEST:
            return self._refuse(attempt_id, "wrong_canonical_request")
        credential = request.get("authorization_credential")
        authorization_id, reason = self._recognize(credential)
        if reason is not None:
            return self._refuse(attempt_id, reason, authorization_id)

        accepted_manifest = self.campaign_root / "destination" / "accepted" / "settlement-manifest.json"
        if attempt_id == "OUTPUT-COLLISION-001":
            try:
                os.lstat(accepted_manifest)
            except FileNotFoundError:
                return self._refuse(attempt_id, "expected_output_collision_absent", authorization_id)
            return self._refuse(attempt_id, "pre_existing_output_collision", authorization_id)
        if attempt_id == "EVIDENCE-WRITE-FAILURE-001":
            probe = self.campaign_root / "destination" / "failure-probe.json"
            try:
                write_json_exclusive(probe, {"probe": "must_refuse"})
            except OSError as exc:
                if exc.errno in (errno.EEXIST, errno.EISDIR, errno.EACCES, errno.EPERM):
                    return self._refuse(attempt_id, "evidence_write_failure", authorization_id)
                return self._refuse(attempt_id, "evidence_write_uncertainty", authorization_id)
            return self._refuse(attempt_id, "expected_evidence_write_failure_absent", authorization_id)

        assert isinstance(credential, dict) and authorization_id is not None
        return self._accept(attempt_id, credential, authorization_id)

    def _accept(self, attempt_id: str, credential: dict[str, Any], authorization_id: str) -> dict[str, Any]:
        before = deepcopy(self.state)
        settlement_id = "settlement-sha256:" + sha256_json(
            {
                "attempt_id": attempt_id,
                "authorization_credential_id": authorization_id,
                "run_identity_digest": self.run_digest,
                "state_before_digest": sha256_json(before),
            }
        )
        effect_id = "effect-sha256:" + sha256_json(
            {"authorization_credential_id": authorization_id, "settlement_id": settlement_id}
        )
        after = {
            "active_artifact": STAGED_ARTIFACT,
            "consumed_authorization_ids": before["consumed_authorization_ids"] + [authorization_id],
            "consumed_nonces": before["consumed_nonces"] + [AUTH_NONCE],
            "effect_id": effect_id,
            "generation": FINAL_GENERATION,
            "settlement_ledger": before["settlement_ledger"]
            + [{"authorization_credential_id": authorization_id, "effect_id": effect_id, "settlement_id": settlement_id}],
            "slot": before["slot"],
        }
        decision = sign_envelope(
            "decision_receipt",
            self._decision_payload(attempt_id, "accepted", "recognized", authorization_id, before, after, settlement_id),
            self._key,
            "destination",
        )
        effect = sign_envelope(
            "effect_receipt",
            {
                "active_artifact_after": STAGED_ARTIFACT,
                "active_artifact_before": INITIAL_ARTIFACT,
                "attempt_id": attempt_id,
                "authorization_credential_id": authorization_id,
                "decision_receipt_id": decision["payload"]["receipt_id"],
                "effect_id": effect_id,
                "generation_after": FINAL_GENERATION,
                "generation_before": INITIAL_GENERATION,
                "protected_mutation_count": 1,
                "run_identity_digest": self.run_digest,
                "settlement_id": settlement_id,
            },
            self._key,
            "destination",
        )
        consumption = sign_envelope(
            "consumption_receipt",
            {
                "authorization_credential_id": authorization_id,
                "decision_receipt_id": decision["payload"]["receipt_id"],
                "effect_receipt_id": effect["payload"]["receipt_id"],
                "nonce": AUTH_NONCE,
                "recognized_consumption_count": 1,
                "run_identity_digest": self.run_digest,
                "settlement_id": settlement_id,
            },
            self._key,
            "destination",
        )
        final_state = sign_envelope(
            "final_state_receipt",
            {
                "authorization_credential_id": authorization_id,
                "consumption_receipt_id": consumption["payload"]["receipt_id"],
                "effect_receipt_id": effect["payload"]["receipt_id"],
                "run_identity_digest": self.run_digest,
                "settlement_id": settlement_id,
                "state": after,
                "state_digest": sha256_json(after),
            },
            self._key,
            "destination",
        )
        artifact_map = {
            "consumption-receipt.json": consumption,
            "decision-receipt.json": decision,
            "effect-receipt.json": effect,
            "final-state-receipt.json": final_state,
        }
        settlement_manifest = sign_envelope(
            "settlement_manifest",
            {
                "artifacts": [
                    {
                        "byte_length": len(canonical_bytes(value) + b"\n"),
                        "path": name,
                        "sha256": sha256_bytes(canonical_bytes(value) + b"\n"),
                    }
                    for name, value in sorted(artifact_map.items())
                ],
                "authorization_credential_id": authorization_id,
                "commit_model": "sole_sequential_process_local_non_crash_commit",
                "destination_id": DESTINATION_ID,
                "run_identity_digest": self.run_digest,
                "settlement_id": settlement_id,
                "state_after_digest": sha256_json(after),
                "state_before_digest": sha256_json(before),
            },
            self._key,
            "destination",
        )

        # Pre-validate the complete chain before any protected state mutation.
        for expected_type, envelope in (
            ("decision_receipt", decision),
            ("effect_receipt", effect),
            ("consumption_receipt", consumption),
            ("final_state_receipt", final_state),
            ("settlement_manifest", settlement_manifest),
        ):
            verify_envelope(envelope, self.public_key, expected_type, "destination")
        output_dir = self.campaign_root / "destination" / "accepted"
        complete_map = {**artifact_map, "settlement-manifest.json": settlement_manifest}
        for name in sorted(complete_map):
            write_json_exclusive(output_dir / name, complete_map[name])
        for name, value in complete_map.items():
            if read_json(output_dir / name) != value:
                raise DestinationError("accepted_evidence_reread_mismatch")

        # PROTECTED_COMMIT_SITE: the only post-initialization protected mutation.
        self.state = after
        self.protected_mutations += 1
        self.recognized_consumptions += 1
        self.commit_count += 1
        return {
            "decision": decision,
            "refusal": None,
            "settlement": {
                "consumption": consumption,
                "effect": effect,
                "final_state": final_state,
                "manifest": settlement_manifest,
            },
            "state": deepcopy(self.state),
        }

    def summary(self) -> dict[str, Any]:
        return {
            "commit_count": self.commit_count,
            "final_state": deepcopy(self.state),
            "final_state_digest": sha256_json(self.state),
            "private_material_export_count": 0,
            "protected_mutations": self.protected_mutations,
            "recognized_consumptions": self.recognized_consumptions,
            "refusal_count": self.refusal_count,
            "role": "destination",
            "run_bound": self.run_identity is not None,
        }
