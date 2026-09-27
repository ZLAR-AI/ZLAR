#!/usr/bin/env python3
"""Fresh-exec local demo authority. It never exports private key material."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from canonical import sha256_json
from contract import AUTHORITY_ID, CANDIDATE_ID, make_credential_body, make_proposal
from crypto_rsa import PrivateKey, parse_public, public_evidence
from evidence import sign_envelope


class AuthorityError(ValueError):
    pass


class AuthorityRole:
    def __init__(self, key: PrivateKey, process_evidence: dict[str, Any]):
        self._key = key
        self.public_key = public_evidence(key)
        self.process_evidence = deepcopy(process_evidence)
        self.run_identity: dict[str, Any] | None = None
        self.run_digest: str | None = None
        self.proposal: dict[str, Any] | None = None
        self.event: dict[str, Any] | None = None
        self.credential: dict[str, Any] | None = None

    def bind_run(self, run_identity: object) -> dict[str, Any]:
        if self.run_identity is not None or not isinstance(run_identity, dict):
            raise AuthorityError("run_already_bound_or_invalid")
        if run_identity.get("authority_public_key") != self.public_key:
            raise AuthorityError("authority_public_key_binding")
        authority_id = self.public_key["public_key_id"]
        destination_public = run_identity.get("destination_public_key")
        _, _, destination_id = parse_public(destination_public)
        if authority_id == destination_id:
            raise AuthorityError("shared_signer_key")
        if run_identity.get("authority_public_key_id") != authority_id or run_identity.get(
            "destination_public_key_id"
        ) != destination_id:
            raise AuthorityError("run_key_identity")
        self.run_identity = deepcopy(run_identity)
        self.run_digest = sha256_json(self.run_identity)
        return sign_envelope(
            "run_ack",
            {
                "acknowledged_role": "authority",
                "candidate_id": CANDIDATE_ID,
                "private_material_export_count": 0,
                "process_evidence": self.process_evidence,
                "run_identity_digest": self.run_digest,
            },
            self._key,
            "authority",
        )

    def create_proposal(self) -> dict[str, Any]:
        if self.run_identity is None or self.run_digest is None or self.proposal is not None:
            raise AuthorityError("proposal_sequence")
        proposal_body = make_proposal(
            self.run_digest,
            self.run_identity["package_id"],
            self.run_identity["source_id"],
        )
        self.proposal = sign_envelope("proposal", proposal_body, self._key, "authority")
        return deepcopy(self.proposal)

    def record_event(self, proposal_digest: object, event_nonce: object) -> dict[str, Any]:
        if self.proposal is None or self.event is not None:
            raise AuthorityError("event_sequence")
        if proposal_digest != sha256_json(self.proposal):
            raise AuthorityError("proposal_digest_mismatch")
        if (
            not isinstance(event_nonce, str)
            or len(event_nonce) != 64
            or event_nonce != event_nonce.lower()
            or any(character not in "0123456789abcdef" for character in event_nonce)
        ):
            raise AuthorityError("event_nonce_contract")
        payload = {
            "authority_id": AUTHORITY_ID,
            "event_meaning": "synthetic_local_decision_event_operator_identity_unproven",
            "event_nonce": event_nonce,
            "human_identity": "explicitly_unbound",
            "institutional_authority": "explicitly_unbound",
            "proposal_digest": proposal_digest,
            "proposal_id": self.proposal["payload"]["proposal_id"],
            "run_identity_digest": self.run_digest,
        }
        self.event = sign_envelope("decision_event", payload, self._key, "authority")
        return deepcopy(self.event)

    def issue_once(self) -> dict[str, Any]:
        if self.run_identity is None or self.proposal is None or self.event is None or self.credential is not None:
            raise AuthorityError("issuance_sequence_or_duplicate")
        body = make_credential_body(
            self.run_identity,
            self.proposal["payload"]["proposal_id"],
            self.event["payload"]["receipt_id"],
        )
        self.credential = sign_envelope("authorization_credential", body, self._key, "authority")
        return deepcopy(self.credential)

    def summary(self) -> dict[str, Any]:
        return {
            "credential_issue_count": 1 if self.credential is not None else 0,
            "event_record_count": 1 if self.event is not None else 0,
            "private_material_export_count": 0,
            "proposal_count": 1 if self.proposal is not None else 0,
            "role": "authority",
            "run_bound": self.run_identity is not None,
        }
