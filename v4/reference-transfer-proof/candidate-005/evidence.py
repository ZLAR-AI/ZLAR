#!/usr/bin/env python3
"""Versioned signed evidence envelopes shared by the runner and destination."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from canonical import CANONICALIZATION_ID, canonical_bytes, sha256_json
from crypto_rsa import PrivateKey, sign_bytes, verify_bytes


EVIDENCE_SCHEMA_VERSION = "zlar.star4.evidence-envelope.v1"
FIELD_REGISTRY_ID = "zlar.star4.field-registry.v1"
EXTENSION_RULE = "additive_fields_must_not_change_existing_semantics"
EVIDENCE_TYPES = {
    "authorization",
    "decision",
    "effect",
    "refusal",
    "consumption",
    "coverage",
    "matrix",
    "output_manifest",
}


class EvidenceError(ValueError):
    pass


def _receipt_id(evidence_type: str, payload_without_id: dict[str, Any]) -> str:
    return f"{evidence_type}-sha256:{sha256_json(payload_without_id)}"


def sign_envelope(evidence_type: str, payload: dict[str, Any], private_key: PrivateKey) -> dict[str, Any]:
    if evidence_type not in EVIDENCE_TYPES:
        raise EvidenceError("unknown_evidence_type")
    clean_payload = deepcopy(payload)
    if "receipt_id" in clean_payload:
        raise EvidenceError("caller_supplied_receipt_id")
    clean_payload["receipt_id"] = _receipt_id(evidence_type, clean_payload)
    core = {
        "canonicalization_id": CANONICALIZATION_ID,
        "evidence_type": evidence_type,
        "extension_rule": EXTENSION_RULE,
        "field_registry_id": FIELD_REGISTRY_ID,
        "payload": clean_payload,
        "schema_version": EVIDENCE_SCHEMA_VERSION,
    }
    signature = sign_bytes(private_key, canonical_bytes(core))
    return {
        **core,
        "signature": {
            "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
            "key_id": private_key_public_id(private_key),
            "value": signature,
        },
    }


def private_key_public_id(private_key: PrivateKey) -> str:
    from crypto_rsa import public_evidence

    return str(public_evidence(private_key)["public_key_id"])


def verify_envelope(envelope: object, public_key: object, expected_type: str | None = None) -> dict[str, Any]:
    if not isinstance(envelope, dict):
        raise EvidenceError("envelope_not_object")
    required = {
        "canonicalization_id",
        "evidence_type",
        "extension_rule",
        "field_registry_id",
        "payload",
        "schema_version",
        "signature",
    }
    if set(envelope) != required:
        raise EvidenceError("envelope_field_set")
    evidence_type = envelope["evidence_type"]
    if evidence_type not in EVIDENCE_TYPES or (expected_type is not None and evidence_type != expected_type):
        raise EvidenceError("evidence_type")
    if envelope["canonicalization_id"] != CANONICALIZATION_ID:
        raise EvidenceError("canonicalization_id")
    if envelope["schema_version"] != EVIDENCE_SCHEMA_VERSION:
        raise EvidenceError("evidence_schema_version")
    if envelope["field_registry_id"] != FIELD_REGISTRY_ID or envelope["extension_rule"] != EXTENSION_RULE:
        raise EvidenceError("field_registry")
    payload = envelope["payload"]
    if not isinstance(payload, dict) or not isinstance(payload.get("receipt_id"), str):
        raise EvidenceError("payload_or_receipt_id")
    payload_without_id = {key: value for key, value in payload.items() if key != "receipt_id"}
    if payload["receipt_id"] != _receipt_id(evidence_type, payload_without_id):
        raise EvidenceError("receipt_identity")
    signature = envelope["signature"]
    if not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "value"}:
        raise EvidenceError("signature_record")
    if signature["algorithm"] != "RSASSA-PKCS1-v1_5-SHA256":
        raise EvidenceError("signature_algorithm")
    from crypto_rsa import parse_public_evidence

    _, _, expected_key_id = parse_public_evidence(public_key)
    if signature["key_id"] != expected_key_id:
        raise EvidenceError("signature_key_identity")
    core = {key: envelope[key] for key in required if key != "signature"}
    if not verify_bytes(public_key, canonical_bytes(core), signature["value"]):
        raise EvidenceError("signature_invalid")
    return payload
