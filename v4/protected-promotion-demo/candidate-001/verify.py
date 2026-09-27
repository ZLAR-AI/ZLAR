#!/usr/bin/env python3
"""The single read-only user-facing verifier command."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from canonical import canonical_bytes, read_json, sha256_json
from contract import (
    AUTH_NONCE,
    CANDIDATE_ID,
    DECISION_TIME,
    EVALUATION_EPOCH,
    EXPIRES_AT,
    FINAL_GENERATION,
    INITIAL_GENERATION,
    INITIAL_STATE_DIGEST,
    ISSUED_AT,
    MANDATORY_NONCOVERAGE,
    RECOGNITION_FIELDS,
    STAGED_ARTIFACT,
    make_credential_body,
)
from coverage_independent import regenerate
from crypto_rsa import parse_public
from evidence import verify_envelope
from manifest import CAMPAIGN_MANIFEST_NAME, campaign_identity, collect_regular_files, complete_identity
from process_evidence import validate_observation
from renderer import PENDING, REFUSED, UNAVAILABLE, VERIFIED, derive


class VerificationError(RuntimeError):
    pass


class Checks:
    def __init__(self) -> None:
        self.count = 0

    def require(self, condition: bool, label: str) -> None:
        self.count += 1
        if not condition:
            raise VerificationError(label)


def _tree_snapshot(root: Path) -> list[dict[str, Any]]:
    return collect_regular_files(root)


def _read(root: Path, relative: str) -> Any:
    return read_json(root / relative)


def verify_campaign(candidate_root: Path, campaign_root: Path, pre_status: bool = False) -> dict[str, Any]:
    checks = Checks()
    before_candidate = _tree_snapshot(candidate_root)
    before_campaign = _tree_snapshot(campaign_root)
    identity = complete_identity(candidate_root)
    recorded_identity = _read(campaign_root, "candidate-identity.json")
    checks.require(recorded_identity == identity, "candidate_identity")
    checks.require(recorded_identity["package_id"].startswith("package-sha256:"), "package_identity_shape")
    checks.require(recorded_identity["source_id"].startswith("source-sha256:"), "source_identity_shape")

    run_identity = _read(campaign_root, "run-identity.json")
    run_digest = sha256_json(run_identity)
    authority_public = _read(campaign_root, "authority-public-key.json")
    destination_public = _read(campaign_root, "destination-public-key.json")
    _, _, authority_key_id = parse_public(authority_public)
    _, _, destination_key_id = parse_public(destination_public)
    checks.require(authority_key_id != destination_key_id, "signer_key_inequality")
    checks.require(run_identity["authority_public_key"] == authority_public, "run_authority_public")
    checks.require(run_identity["destination_public_key"] == destination_public, "run_destination_public")
    checks.require(run_identity["authority_public_key_id"] == authority_key_id, "run_authority_key_id")
    checks.require(run_identity["destination_public_key_id"] == destination_key_id, "run_destination_key_id")
    checks.require(run_identity["package_id"] == identity["package_id"], "run_package")
    checks.require(run_identity["source_id"] == identity["source_id"], "run_source")
    checks.require(run_identity["candidate_id"] == CANDIDATE_ID, "run_candidate")

    hellos = _read(campaign_root, "process-hellos.json")
    for role, public in (("authority", authority_public), ("destination", destination_public)):
        hello = hellos[role]
        checks.require(hello["role"] == role, f"hello_role:{role}")
        checks.require(hello["public_key"] == public, f"hello_public:{role}")
        checks.require(hello["generation"]["actual_modulus_bits"] == 2048, f"hello_modulus:{role}")
        checks.require(hello["private_material_export_count"] == 0, f"hello_private_export:{role}")
        validate_observation(hello["process_evidence"], role)
        checks.require(True, f"process_observation:{role}")

    acks = _read(campaign_root, "run-acks.json")
    authority_ack = verify_envelope(acks["authority"], authority_public, "run_ack", "authority")
    destination_ack = verify_envelope(acks["destination"], destination_public, "run_ack", "destination")
    checks.require(authority_ack["run_identity_digest"] == run_digest, "authority_ack_run")
    checks.require(destination_ack["run_identity_digest"] == run_digest, "destination_ack_run")
    checks.require(destination_ack["pinned_authority_public_key_id"] == authority_key_id, "destination_pin")

    proposal = _read(campaign_root, "authority/proposal.json")
    event = _read(campaign_root, "authority/decision-event.json")
    credential = _read(campaign_root, "authority/authorization-credential.json")
    proposal_payload = verify_envelope(proposal, authority_public, "proposal", "authority")
    event_payload = verify_envelope(event, authority_public, "decision_event", "authority")
    credential_payload = verify_envelope(credential, authority_public, "authorization_credential", "authority")
    checks.require(proposal_payload["run_identity_digest"] == run_digest, "proposal_run")
    checks.require(event_payload["run_identity_digest"] == run_digest, "event_run")
    checks.require(event_payload["proposal_id"] == proposal_payload["proposal_id"], "event_proposal")
    checks.require(event_payload["proposal_digest"] == sha256_json(proposal), "event_proposal_digest")
    expected_credential = make_credential_body(run_identity, proposal_payload["proposal_id"], event_payload["receipt_id"])
    credential_body = {key: value for key, value in credential_payload.items() if key != "receipt_id"}
    checks.require(set(credential_body) == set(RECOGNITION_FIELDS), "credential_field_set")
    checks.require(credential_body == expected_credential, "credential_exact_binding")
    checks.require(credential_body["max_uses"] == 1 and credential_body["nonce"] == AUTH_NONCE, "credential_one_use")
    checks.require(ISSUED_AT <= DECISION_TIME < EXPIRES_AT, "historical_time_validity")
    checks.require(credential_body["evaluation_epoch"] == EVALUATION_EPOCH, "credential_epoch")
    context_ack = verify_envelope(
        _read(campaign_root, "authority-context-ack.json"),
        destination_public,
        "run_ack",
        "destination",
    )
    checks.require(context_ack["authority_context_pinned"] is True, "authority_context_pin")

    missing = _read(campaign_root, "missing-refusal.json")
    missing_decision = verify_envelope(missing["decision"], destination_public, "decision_receipt", "destination")
    missing_refusal = verify_envelope(missing["refusal"], destination_public, "refusal_receipt", "destination")
    checks.require(missing_decision["reason"] == "missing_authorization_credential", "missing_reason")
    checks.require(missing_decision["state_before_digest"] == INITIAL_STATE_DIGEST, "missing_state_before")
    checks.require(missing_decision["state_after_digest"] == INITIAL_STATE_DIGEST, "missing_state_after")
    checks.require(missing_decision["protected_mutations_after"] == 0, "missing_mutation")
    checks.require(missing_decision["recognized_consumptions_after"] == 0, "missing_consumption")
    checks.require(missing_refusal["decision_receipt_id"] == missing_decision["receipt_id"], "missing_link")
    checks.require(derive(missing, destination_public)["label"] == REFUSED, "missing_renderer")

    matrix = _read(campaign_root, "matrix.json")
    rows = matrix["rows"]
    checks.require(len(rows) == matrix["totals"]["case_count"], "matrix_count")
    checks.require(len({row["case_id"] for row in rows}) == len(rows), "matrix_unique")
    accepted_rows = [row for row in rows if row["outcome"] == "accepted"]
    action_refusals = [row for row in rows if row["outcome"] == "refused"]
    checks.require(len(accepted_rows) == 1, "one_accepted_row")
    checks.require(matrix["totals"]["recognized_crossings"] == 1, "one_crossing")
    checks.require(matrix["totals"]["protected_mutations"] == 1, "one_mutation")
    checks.require(matrix["totals"]["recognized_consumptions"] == 1, "one_consumption")
    checks.require(matrix["totals"]["negative_or_replay_mutations"] == 0, "negative_mutations_zero")
    checks.require(matrix["totals"]["negative_or_replay_consumptions"] == 0, "negative_consumptions_zero")
    for row in action_refusals:
        response = _read(campaign_root, row["response_path"])
        decision = verify_envelope(response["decision"], destination_public, "decision_receipt", "destination")
        refusal = verify_envelope(response["refusal"], destination_public, "refusal_receipt", "destination")
        checks.require(decision["outcome"] == "refused", f"row_outcome:{row['case_id']}")
        checks.require(decision["reason"] == row["reason"], f"row_reason:{row['case_id']}")
        checks.require(refusal["decision_receipt_id"] == decision["receipt_id"], f"row_link:{row['case_id']}")
        checks.require(decision["state_before_digest"] == decision["state_after_digest"], f"row_state:{row['case_id']}")
        checks.require(row["additional_protected_mutations"] == 0, f"row_mutation:{row['case_id']}")
        checks.require(row["additional_recognized_consumptions"] == 0, f"row_consumption:{row['case_id']}")

    accepted = _read(campaign_root, accepted_rows[0]["response_path"])
    accepted_decision = verify_envelope(accepted["decision"], destination_public, "decision_receipt", "destination")
    checks.require(accepted_decision["outcome"] == "accepted", "accepted_outcome")
    checks.require(accepted_decision["state_before_digest"] == INITIAL_STATE_DIGEST, "accepted_before")
    settlement = accepted["settlement"]
    effect = verify_envelope(settlement["effect"], destination_public, "effect_receipt", "destination")
    consumption = verify_envelope(settlement["consumption"], destination_public, "consumption_receipt", "destination")
    final_state = verify_envelope(settlement["final_state"], destination_public, "final_state_receipt", "destination")
    settlement_manifest = verify_envelope(settlement["manifest"], destination_public, "settlement_manifest", "destination")
    checks.require(effect["decision_receipt_id"] == accepted_decision["receipt_id"], "effect_decision_link")
    checks.require(consumption["effect_receipt_id"] == effect["receipt_id"], "consumption_effect_link")
    checks.require(final_state["consumption_receipt_id"] == consumption["receipt_id"], "state_consumption_link")
    checks.require(final_state["state"]["generation"] == FINAL_GENERATION, "final_generation")
    checks.require(final_state["state"]["active_artifact"] == STAGED_ARTIFACT, "final_artifact")
    checks.require(final_state["state_digest"] == sha256_json(final_state["state"]), "final_state_digest")
    checks.require(settlement_manifest["state_after_digest"] == final_state["state_digest"], "manifest_state")
    checks.require(derive(accepted, destination_public, False)["label"] == PENDING, "accepted_pending_renderer")
    checks.require(derive(accepted, destination_public, True)["label"] == VERIFIED, "accepted_verified_renderer")
    for name, key in (
        ("decision-receipt.json", "decision"),
        ("effect-receipt.json", "effect"),
        ("consumption-receipt.json", "consumption"),
        ("final-state-receipt.json", "final_state"),
        ("settlement-manifest.json", "manifest"),
    ):
        checks.require(_read(campaign_root, "destination/accepted/" + name) == (accepted[key] if key == "decision" else settlement[key]), f"accepted_disk:{name}")

    replay_rows = [row for row in rows if row["case_class"] == "replay"]
    checks.require(len(replay_rows) >= 2, "replay_rows")
    for row in replay_rows:
        checks.require(row["reason"] == "authorization_replayed", f"replay_reason:{row['case_id']}")
        checks.require(row["additional_protected_mutations"] == 0, f"replay_mutation:{row['case_id']}")
        checks.require(row["additional_recognized_consumptions"] == 0, f"replay_consumption:{row['case_id']}")

    static_surface = _read(campaign_root, "static-surface.json")
    checks.require(static_surface["checks"]["exactly_one_protected_commit_site"] is True, "static_commit")
    checks.require(static_surface["checks"]["exactly_one_child_spawn_site"] is True, "static_spawn")
    checks.require(static_surface["checks"]["live_agent_adapter_absent"] is True, "static_live_absent")
    checks.require(static_surface["network_imports"] == [], "static_network_absent")
    runtime_inventory = _read(campaign_root, "runtime-inventory.json")
    checks.require(runtime_inventory["live_agent_adapter"] == "absent", "dynamic_live_absent")
    checks.require(runtime_inventory["signer_process_count"] == 2, "runtime_signer_count")
    checks.require(runtime_inventory["private_material_export_count"] == 0, "runtime_private_export")
    checks.require(runtime_inventory["descriptor_allowlists_passed"] is True, "runtime_descriptors")
    lifecycle = _read(campaign_root, "process-lifecycle.json")
    for role in ("authority", "destination"):
        checks.require(lifecycle[role]["lifecycle"]["normal_exit"] is True, f"lifecycle_exit:{role}")
        checks.require(lifecycle[role]["lifecycle"]["stderr_byte_length"] == 0, f"lifecycle_stderr:{role}")
    checks.require(lifecycle["authority"]["summary"]["credential_issue_count"] == 1, "authority_issue_count")
    checks.require(lifecycle["destination"]["summary"]["commit_count"] == 1, "destination_commit_count")
    checks.require(lifecycle["destination"]["summary"]["protected_mutations"] == 1, "destination_mutations")
    checks.require(lifecycle["destination"]["summary"]["recognized_consumptions"] == 1, "destination_consumptions")

    route_registry = _read(campaign_root, "route-registry.json")
    noncoverage = _read(campaign_root, "noncoverage.json")
    checks.require(len(noncoverage["surfaces"]) == len(MANDATORY_NONCOVERAGE), "noncoverage_cardinality")
    coverage = _read(campaign_root, "coverage-map.json")
    regenerated = regenerate(runtime_inventory, matrix, route_registry, noncoverage)
    checks.require(coverage == regenerated, "independent_coverage_equal")
    checks.require(coverage["disposition_counts"].get("governed") == 1, "one_governed_surface")
    checks.require(coverage["disposition_counts"].get("open", 0) > 0, "open_routes_named")
    checks.require(coverage["disposition_counts"].get("unknown", 0) > 0, "unknown_routes_named")

    ui_matrix = _read(campaign_root, "ui-matrix.json")
    expected_ui = {
        "accepted_before_verification": PENDING,
        "accepted_after_verification": VERIFIED,
        "cached_or_untrusted": UNAVAILABLE,
        "destination_loss": UNAVAILABLE,
        "missing_evidence": UNAVAILABLE,
        "partial_evidence": UNAVAILABLE,
        "signed_missing_credential": REFUSED,
        "tampered_evidence": UNAVAILABLE,
    }
    checks.require(ui_matrix["labels"] == expected_ui, "ui_failure_matrix")
    checks.require(ui_matrix["positive_from_cache_partial_or_loss"] is False, "ui_no_false_positive")

    proof = _read(campaign_root, "proof-summary.json")
    checks.require(proof["candidate_id"] == CANDIDATE_ID, "proof_candidate")
    checks.require(proof["outcome"] == "PASS_PENDING_READ_ONLY_VERIFICATION", "proof_pre_verification_outcome")
    checks.require(proof["claim_ceiling_id"] == "CLAIM-CEILING.md", "proof_claim_ceiling")
    checks.require(proof["human_identity"] == "explicitly_unbound", "proof_human_unbound")
    checks.require(proof["institutional_authority"] == "explicitly_unbound", "proof_institution_unbound")

    if not pre_status:
        observation = _read(campaign_root, "verification-observation.json")
        checks.require(observation["result"] == "PASS", "verification_observation")
        status = _read(campaign_root, "status-final.json")
        checks.require(status["label"] == VERIFIED, "final_status")
        checks.require(status["provenance"] == "verifier-established", "final_status_provenance")
        stored_campaign_manifest = _read(campaign_root, CAMPAIGN_MANIFEST_NAME)
        checks.require(stored_campaign_manifest == campaign_identity(campaign_root), "campaign_tree_identity")

    after_candidate = _tree_snapshot(candidate_root)
    after_campaign = _tree_snapshot(campaign_root)
    checks.require(before_candidate == after_candidate, "verifier_candidate_read_only")
    checks.require(before_campaign == after_campaign, "verifier_campaign_read_only")
    return {
        "assertions": checks.count,
        "campaign_id": run_identity["campaign_id"],
        "candidate_file_count": identity["file_count"],
        "candidate_package_id": identity["package_id"],
        "coverage_rows": coverage["row_count"],
        "mode": "pre-status" if pre_status else "complete",
        "result": "PASS",
        "verifier_writes": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Protected Promotion verifier")
    parser.add_argument("--candidate-root", required=True)
    parser.add_argument("--campaign-root", required=True)
    parser.add_argument("--pre-status", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        result = verify_campaign(
            Path(args.candidate_root).resolve(strict=True),
            Path(args.campaign_root).resolve(strict=True),
            pre_status=args.pre_status,
        )
    except Exception as exc:
        result = {"error": f"{type(exc).__name__}:{str(exc)}", "result": "REFUSE", "verifier_writes": 0}
        sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
        return 42
    sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
