#!/usr/bin/env python3
"""Role-bound signed evidence envelopes."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from canonical import CANONICALIZATION_ID, canonical_bytes, sha256_json
from crypto_rsa import PrivateKey, parse_public, public_evidence, sign, verify


SCHEMA_VERSION = "zlar.protected-promotion.evidence-envelope.v1"
FIELD_REGISTRY_ID = "zlar.protected-promotion.field-registry.v1"

AUTHORITY_TYPES = {"run_ack", "proposal", "decision_event", "authorization_credential"}
DESTINATION_TYPES = {
    "run_ack",
    "decision_receipt",
    "refusal_receipt",
    "effect_receipt",
    "consumption_receipt",
    "final_state_receipt",
    "settlement_manifest",
}
ALL_TYPES = AUTHORITY_TYPES | DESTINATION_TYPES


class EvidenceError(ValueError):
    pass


def sign_envelope(evidence_type: str, payload: dict[str, Any], key: PrivateKey, signer_role: str) -> dict[str, Any]:
    if evidence_type not in ALL_TYPES:
        raise EvidenceError("unknown_evidence_type")
    allowed = AUTHORITY_TYPES if signer_role == "authority" else DESTINATION_TYPES if signer_role == "destination" else set()
    if evidence_type not in allowed:
        raise EvidenceError("signer_role_not_permitted")
    clean = deepcopy(payload)
    if "receipt_id" in clean:
        raise EvidenceError("caller_supplied_receipt_id")
    clean["receipt_id"] = f"{evidence_type}-sha256:{sha256_json(clean)}"
    core = {
        "canonicalization_id": CANONICALIZATION_ID,
        "evidence_type": evidence_type,
        "field_registry_id": FIELD_REGISTRY_ID,
        "payload": clean,
        "schema_version": SCHEMA_VERSION,
        "signer_role": signer_role,
    }
    return {
        **core,
        "signature": {
            "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
            "key_id": public_evidence(key)["public_key_id"],
            "value": sign(key, canonical_bytes(core)),
        },
    }


def verify_envelope(
    envelope: object,
    public_key: object,
    expected_type: str | None = None,
    expected_role: str | None = None,
) -> dict[str, Any]:
    required = {
        "canonicalization_id",
        "evidence_type",
        "field_registry_id",
        "payload",
        "schema_version",
        "signature",
        "signer_role",
    }
    if not isinstance(envelope, dict) or set(envelope) != required:
        raise EvidenceError("envelope_field_set")
    evidence_type = envelope["evidence_type"]
    role = envelope["signer_role"]
    if evidence_type not in ALL_TYPES or (expected_type is not None and evidence_type != expected_type):
        raise EvidenceError("evidence_type")
    if role not in ("authority", "destination") or (expected_role is not None and role != expected_role):
        raise EvidenceError("signer_role")
    allowed = AUTHORITY_TYPES if role == "authority" else DESTINATION_TYPES
    if evidence_type not in allowed:
        raise EvidenceError("role_type_binding")
    if (
        envelope["canonicalization_id"] != CANONICALIZATION_ID
        or envelope["field_registry_id"] != FIELD_REGISTRY_ID
        or envelope["schema_version"] != SCHEMA_VERSION
    ):
        raise EvidenceError("envelope_contract")
    payload = envelope["payload"]
    if not isinstance(payload, dict) or not isinstance(payload.get("receipt_id"), str):
        raise EvidenceError("payload")
    body = {key: value for key, value in payload.items() if key != "receipt_id"}
    if payload["receipt_id"] != f"{evidence_type}-sha256:{sha256_json(body)}":
        raise EvidenceError("receipt_identity")
    signature = envelope["signature"]
    if not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "value"}:
        raise EvidenceError("signature_record")
    _, _, key_id = parse_public(public_key)
    if signature["algorithm"] != "RSASSA-PKCS1-v1_5-SHA256" or signature["key_id"] != key_id:
        raise EvidenceError("signature_key_identity")
    core = {key: envelope[key] for key in required if key != "signature"}
    if not verify(public_key, canonical_bytes(core), signature["value"]):
        raise EvidenceError("signature_invalid")
    return payload
