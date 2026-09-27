#!/usr/bin/env python3
"""Evidence-proven status labels. Presentation state never creates success."""

from __future__ import annotations

from typing import Any

from canonical import sha256_json
from evidence import EvidenceError, verify_envelope


UNAVAILABLE = "DESTINATION UNAVAILABLE — NO DESTINATION DECISION"
REFUSED = "REFUSED BY RECEIVING SYSTEM"
PENDING = "DESTINATION REPORTED COMMIT — VERIFICATION PENDING"
VERIFIED = "VERIFIED BOUNDED RESULT"


def derive(result: object, destination_public_key: object, verifier_established: bool = False) -> dict[str, Any]:
    unavailable = {"exit_nonzero": True, "label": UNAVAILABLE, "provenance": "campaign-derived"}
    if not isinstance(result, dict):
        return unavailable
    try:
        decision = result.get("decision")
        decision_payload = verify_envelope(decision, destination_public_key, "decision_receipt", "destination")
        state = result.get("state")
        if not isinstance(state, dict):
            return unavailable
        if decision_payload.get("state_after_digest") != sha256_json(state):
            return unavailable
        if decision_payload.get("outcome") == "refused":
            refusal = result.get("refusal")
            refusal_payload = verify_envelope(refusal, destination_public_key, "refusal_receipt", "destination")
            if (
                refusal_payload.get("decision_receipt_id") != decision_payload.get("receipt_id")
                or refusal_payload.get("state_digest") != decision_payload.get("state_before_digest")
                or decision_payload.get("state_before_digest") != decision_payload.get("state_after_digest")
            ):
                return unavailable
            return {"exit_nonzero": False, "label": REFUSED, "provenance": "destination-signed"}
        if decision_payload.get("outcome") == "accepted":
            settlement = result.get("settlement")
            if not isinstance(settlement, dict):
                return unavailable
            for key, evidence_type in (
                ("effect", "effect_receipt"),
                ("consumption", "consumption_receipt"),
                ("final_state", "final_state_receipt"),
                ("manifest", "settlement_manifest"),
            ):
                verify_envelope(settlement.get(key), destination_public_key, evidence_type, "destination")
            return {
                "exit_nonzero": False,
                "label": VERIFIED if verifier_established else PENDING,
                "provenance": "verifier-established" if verifier_established else "destination-signed",
            }
    except (EvidenceError, ValueError, TypeError):
        return unavailable
    return unavailable
