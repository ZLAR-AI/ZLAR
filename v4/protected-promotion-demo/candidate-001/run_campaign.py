#!/usr/bin/env python3
"""Deterministic technical campaign for one disposable Protected Promotion terminal."""

from __future__ import annotations

import argparse
import copy
import os
import secrets
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from canonical import canonical_bytes, read_json, sha256_file, sha256_json, write_json_exclusive
from contract import (
    ALLOWED_CAMPAIGN_BASENAMES,
    CANDIDATE_ID,
    DECLARED_ROUTES,
    EVALUATION_EPOCH,
    FORBIDDEN_CALLER_FIELDS,
    MANDATORY_NONCOVERAGE,
    RECOGNITION_FIELDS,
    make_request,
    make_run_identity,
)
from coverage_subject import generate as generate_coverage
from evidence import verify_envelope
from manifest import campaign_identity, complete_identity
from process_channel import SignerChannel
from renderer import PENDING, REFUSED, UNAVAILABLE, VERIFIED, derive
from static_check import run as static_run
from verify import verify_campaign


class CampaignError(RuntimeError):
    pass


class CampaignWriter:
    def __init__(self, root: Path):
        self.root = root
        self.write_count = 0

    def json(self, relative: str, value: Any) -> None:
        write_json_exclusive(self.root / relative, value)
        self.write_count += 1


def _request_raw(credential: object) -> bytes:
    return canonical_bytes(make_request(credential))


def _tamper_credential(credential: dict[str, Any], field: str, mode: str = "change") -> dict[str, Any]:
    value = copy.deepcopy(credential)
    payload = value["payload"]
    if mode == "remove":
        payload.pop(field, None)
    elif mode == "null":
        payload[field] = None
    elif mode == "wildcard":
        payload[field] = "*"
    elif mode == "multiple":
        payload[field] = [payload.get(field), "second"]
    elif mode == "conflicting":
        payload[field] = {"first": payload.get(field), "second": "conflict"}
    elif mode == "noncanonical":
        payload[field] = " noncanonical "
    else:
        current = payload.get(field)
        if isinstance(current, int) and not isinstance(current, bool):
            payload[field] = current + 1
        elif isinstance(current, list):
            payload[field] = current + ["tampered"]
        elif isinstance(current, dict):
            payload[field] = {**current, "tampered": True}
        else:
            payload[field] = "tampered"
    return value


def _adversarial_inputs(
    credential: dict[str, Any], destination_key_id: str
) -> list[tuple[str, str, bytes]]:
    rows: list[tuple[str, str, bytes]] = []

    def add(case_id: str, case_class: str, request: object) -> None:
        rows.append((case_id, case_class, canonical_bytes(request)))

    add("AUTH-002-MALFORMED", "authorization", make_request("not-an-envelope"))
    add("AUTH-003-UNSIGNED", "authorization", make_request(credential["payload"]))
    invalid = copy.deepcopy(credential)
    invalid["signature"]["value"] = "AA"
    add("AUTH-004-INVALID-SIGNATURE", "authorization", make_request(invalid))
    wrong_signer = copy.deepcopy(credential)
    wrong_signer["signature"]["key_id"] = destination_key_id
    add("AUTH-005-WRONG-SIGNER", "authorization", make_request(wrong_signer))
    for index, field in enumerate(RECOGNITION_FIELDS, start=1):
        add(f"BIND-{index:03d}-{field.upper().replace('_', '-')}", "recognition_binding", make_request(_tamper_credential(credential, field)))
    add("FIELD-001-MISSING", "field_grammar", make_request(_tamper_credential(credential, "audience", "remove")))
    extra = copy.deepcopy(credential)
    extra["payload"]["unexpected"] = "forbidden"
    add("FIELD-002-EXTRA", "field_grammar", make_request(extra))
    add("FIELD-003-NULL", "field_grammar", make_request(_tamper_credential(credential, "resource", "null")))
    add("FIELD-004-WILDCARD", "field_grammar", make_request(_tamper_credential(credential, "audience", "wildcard")))
    add("FIELD-005-MULTIPLE", "field_grammar", make_request(_tamper_credential(credential, "destination_id", "multiple")))
    add("FIELD-006-CONFLICTING", "field_grammar", make_request(_tamper_credential(credential, "resource", "conflicting")))
    add("FIELD-007-NONCANONICAL", "field_grammar", make_request(_tamper_credential(credential, "audience", "noncanonical")))
    for index, (field, _) in enumerate(sorted(FORBIDDEN_CALLER_FIELDS.items()), start=1):
        request = make_request(credential)
        request[field] = "caller-controlled"
        add(f"CALLER-{index:03d}-{field.upper().replace('_', '-')}", "caller_prohibited", request)
    request_missing = make_request(credential)
    request_missing.pop("tool_contract_digest")
    add("PROTO-001-MISSING-FIELD", "protocol", request_missing)
    request_extra = make_request(credential)
    request_extra["extra"] = True
    add("PROTO-002-EXTRA-FIELD", "protocol", request_extra)
    request_protocol = make_request(credential)
    request_protocol["protocol"] = "unknown-protocol"
    add("PROTO-003-PROHIBITED-FORM", "protocol", request_protocol)
    request_method = make_request(credential)
    request_method["method"] = "unknown.method"
    add("PROTO-004-UNKNOWN-METHOD", "protocol", request_method)
    request_tool = make_request(credential)
    request_tool["method"] = "deployment.delete"
    add("PROTO-005-UNKNOWN-TOOL", "protocol", request_tool)
    request_contract = make_request(credential)
    request_contract["tool_contract_digest"] = "0" * 64
    add("PROTO-006-TOOL-CONTRACT-DRIFT", "protocol", request_contract)
    request_state = make_request(credential)
    request_state["request"]["expected_generation"] = 6
    add("PROTO-007-STATE-DRIFT", "protocol", request_state)
    add("PROTO-008-ALTERNATE-REQUEST", "protocol", ["not", "an", "object"])
    rows.append(("PROTO-009-DUPLICATE-JSON-KEY", "protocol", b'{"method":"a","method":"b"}'))
    rows.append(("PROTO-010-MALFORMED-JSON", "protocol", b'{"method":'))
    rows.append(("PROTO-011-BYTE-AMBIGUITY", "protocol", b'{"value":NaN}'))
    rows.append(("PROTO-012-INVALID-UTF8", "protocol", b'{"value":"\xff"}'))
    rows.append(("PROTO-013-NONCANONICAL-ENCODING", "protocol", _request_raw(credential) + b" "))
    rows.append(("OUTPUT-COLLISION-001", "evidence_collision", _request_raw(credential)))
    rows.append(("EVIDENCE-WRITE-FAILURE-001", "evidence_failure", _request_raw(credential)))
    return rows


def _subprocess_verifier(candidate_root: Path, campaign_root: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-E",
            "-s",
            "-B",
            str(candidate_root / "verify.py"),
            "--candidate-root",
            str(candidate_root),
            "--campaign-root",
            str(campaign_root),
            "--pre-status",
        ],
        cwd=candidate_root,
        env={},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0 or completed.stderr:
        raise CampaignError("pre_status_verifier_refused:" + completed.stdout.decode("utf-8", errors="replace")[:400])
    from canonical import strict_loads

    result = strict_loads(completed.stdout)
    if not isinstance(result, dict) or result.get("result") != "PASS" or result.get("verifier_writes") != 0:
        raise CampaignError("pre_status_verifier_result")
    return result


def run(output_root: Path) -> dict[str, Any]:
    candidate_root = ROOT.resolve(strict=True)
    identity = complete_identity(candidate_root)
    output_text = str(output_root)
    if not output_root.is_absolute() or output_text != os.path.abspath(output_text):
        raise CampaignError("output_root_not_canonical_absolute")
    if output_root.name not in ALLOWED_CAMPAIGN_BASENAMES or output_root.parent != Path("/private/tmp"):
        raise CampaignError("output_root_not_allowlisted")
    try:
        os.lstat(output_root)
    except FileNotFoundError:
        pass
    else:
        raise CampaignError("output_root_collision")
    os.mkdir(output_root, 0o700)
    writer = CampaignWriter(output_root)
    writer.json("candidate-identity.json", identity)
    static_surface = static_run(candidate_root, require_manifest=True)
    writer.json("static-surface.json", static_surface)
    campaign_id = output_root.name
    run_plan = {
        "campaign_id": campaign_id,
        "evaluation_epoch": EVALUATION_EPOCH,
        "live_agent_adapter": "absent",
        "one_user_facing_verifier": "verify.py",
        "ordered_phases": [
            "verify_candidate",
            "fresh_exec_signers",
            "bind_run_identity",
            "missing_credential_refusal",
            "record_local_event_and_issue_once",
            "closed_adversarial_matrix",
            "one_recognized_settlement",
            "replay_refusals",
            "coverage_reconciliation",
            "read_only_verification",
        ],
        "schema_version": "zlar.protected-promotion.run-plan.v1",
    }
    writer.json("run-plan.json", run_plan)

    authority = SignerChannel("authority", candidate_root, output_root)
    destination = SignerChannel("destination", candidate_root, output_root)
    try:
        authority_public = authority.hello["public_key"]
        destination_public = destination.hello["public_key"]
        writer.json("authority-public-key.json", authority_public)
        writer.json("destination-public-key.json", destination_public)
        writer.json("process-hellos.json", {"authority": authority.hello, "destination": destination.hello})
        launch_nonce = secrets.token_hex(32)
        run_identity = make_run_identity(
            identity["package_id"],
            identity["source_id"],
            campaign_id,
            launch_nonce,
            authority_public,
            destination_public,
        )
        writer.json("run-identity.json", run_identity)
        authority_ack = authority.command("bind_run", {"run_identity": run_identity})
        destination_ack = destination.command("bind_run", {"run_identity": run_identity})
        verify_envelope(authority_ack, authority_public, "run_ack", "authority")
        verify_envelope(destination_ack, destination_public, "run_ack", "destination")
        writer.json("run-acks.json", {"authority": authority_ack, "destination": destination_ack})

        matrix_rows: list[dict[str, Any]] = []
        attempt_inputs: list[dict[str, Any]] = []
        current_mutations = 0
        current_consumptions = 0

        def attempt(case_id: str, case_class: str, raw: bytes, response_path: str) -> dict[str, Any]:
            nonlocal current_mutations, current_consumptions
            result = destination.command("attempt", {"attempt_id": case_id, "raw_hex": raw.hex()}, timeout=30.0)
            writer.json(response_path, result)
            attempt_inputs.append(
                {
                    "case_class": case_class,
                    "case_id": case_id,
                    "raw_byte_length": len(raw),
                    "raw_sha256": sha256_json({"hex": raw.hex()}),
                    "response_path": response_path,
                }
            )
            decision_payload = verify_envelope(result["decision"], destination_public, "decision_receipt", "destination")
            outcome = decision_payload["outcome"]
            after_mutations = decision_payload["protected_mutations_after"]
            after_consumptions = decision_payload["recognized_consumptions_after"]
            additional_mutations = after_mutations - current_mutations
            additional_consumptions = after_consumptions - current_consumptions
            if outcome == "accepted":
                current_mutations = after_mutations
                current_consumptions = after_consumptions
            else:
                verify_envelope(result["refusal"], destination_public, "refusal_receipt", "destination")
            matrix_rows.append(
                {
                    "additional_protected_mutations": additional_mutations,
                    "additional_recognized_consumptions": additional_consumptions,
                    "case_class": case_class,
                    "case_id": case_id,
                    "outcome": outcome,
                    "reason": decision_payload["reason"],
                    "response_path": response_path,
                }
            )
            return result

        missing = attempt(
            "AUTH-001-MISSING-CREDENTIAL",
            "authorization",
            _request_raw(None),
            "missing-refusal.json",
        )
        if derive(missing, destination_public)["label"] != REFUSED:
            raise CampaignError("missing_refusal_renderer")

        proposal = authority.command("create_proposal", {})
        event = authority.command(
            "record_event",
            {"event_nonce": secrets.token_hex(32), "proposal_digest": sha256_json(proposal)},
        )
        credential = authority.command("issue_once", {})
        writer.json("authority/proposal.json", proposal)
        writer.json("authority/decision-event.json", event)
        writer.json("authority/authorization-credential.json", credential)
        context_ack = destination.command("bind_authority_context", {"event": event, "proposal": proposal})
        writer.json("authority-context-ack.json", context_ack)

        collision_path = output_root / "destination" / "accepted" / "settlement-manifest.json"
        write_json_exclusive(collision_path, {"synthetic_collision": True})
        collision_before = os.lstat(collision_path)
        failure_probe = output_root / "destination" / "failure-probe.json"
        os.mkdir(failure_probe, 0o700)
        adversarial = _adversarial_inputs(credential, destination_public["public_key_id"])
        collision_seen = False
        for case_id, case_class, raw in adversarial:
            response = attempt(case_id, case_class, raw, f"refusals/{case_id}.json")
            row = matrix_rows[-1]
            if row["outcome"] != "refused" or row["additional_protected_mutations"] != 0 or row[
                "additional_recognized_consumptions"
            ] != 0:
                raise CampaignError("negative_mutation_or_consumption:" + case_id)
            if case_id == "OUTPUT-COLLISION-001":
                if row["reason"] != "pre_existing_output_collision":
                    raise CampaignError("collision_not_refused")
                collision_after = os.lstat(collision_path)
                if (collision_before.st_dev, collision_before.st_ino, collision_before.st_size) != (
                    collision_after.st_dev,
                    collision_after.st_ino,
                    collision_after.st_size,
                ):
                    raise CampaignError("collision_sentinel_drift")
                os.unlink(collision_path)
                try:
                    os.lstat(collision_path)
                except FileNotFoundError:
                    collision_seen = True
                else:
                    raise CampaignError("collision_sentinel_cleanup")
        writer.json(
            "collision-observation.json",
            {
                "collision_refused": collision_seen,
                "removed_exact_synthetic_sentinel_only": collision_seen,
                "sentinel_device": collision_before.st_dev,
                "sentinel_inode": collision_before.st_ino,
                "sentinel_size": collision_before.st_size,
            },
        )

        accepted = attempt(
            "CROSSING-001-RECOGNIZED",
            "recognized_crossing",
            _request_raw(credential),
            "accepted-response.json",
        )
        if matrix_rows[-1]["outcome"] != "accepted" or current_mutations != 1 or current_consumptions != 1:
            raise CampaignError("recognized_crossing_counts")
        if derive(accepted, destination_public, False)["label"] != PENDING:
            raise CampaignError("accepted_pending_renderer")
        for replay_id in ("REPLAY-001-CONCURRENT-CONTENDER", "REPLAY-002-POST-SUCCESS"):
            attempt(replay_id, "replay", _request_raw(credential), f"refusals/{replay_id}.json")
            row = matrix_rows[-1]
            if row["reason"] != "authorization_replayed" or row["additional_protected_mutations"] != 0 or row[
                "additional_recognized_consumptions"
            ] != 0:
                raise CampaignError("replay_mutation_or_classification")

        authority_close = authority.close()
        destination_close = destination.close()
        writer.json("process-lifecycle.json", {"authority": authority_close, "destination": destination_close})
    except BaseException:
        authority.abort()
        destination.abort()
        raise

    writer.json("attempt-inputs.json", {"cases": attempt_inputs, "schema_version": "zlar.protected-promotion.attempt-inputs.v1"})
    matrix = {
        "rows": matrix_rows,
        "schema_version": "zlar.protected-promotion.closed-adversarial-matrix.v1",
        "totals": {
            "case_count": len(matrix_rows),
            "negative_or_replay_consumptions": sum(
                row["additional_recognized_consumptions"] for row in matrix_rows if row["outcome"] != "accepted"
            ),
            "negative_or_replay_mutations": sum(
                row["additional_protected_mutations"] for row in matrix_rows if row["outcome"] != "accepted"
            ),
            "protected_mutations": current_mutations,
            "recognized_consumptions": current_consumptions,
            "recognized_crossings": sum(row["outcome"] == "accepted" for row in matrix_rows),
            "refusals": sum(row["outcome"] == "refused" for row in matrix_rows),
        },
    }
    writer.json("matrix.json", matrix)
    route_registry = {
        "candidate_id": CANDIDATE_ID,
        "routes": DECLARED_ROUTES,
        "schema_version": "zlar.protected-promotion.route-registry.v1",
    }
    noncoverage = {
        "candidate_id": CANDIDATE_ID,
        "schema_version": "zlar.protected-promotion.noncoverage.v1",
        "surfaces": [
            {"required_disposition": disposition, "surface_id": name, "status": "explicitly_not_closed"}
            for name, disposition in MANDATORY_NONCOVERAGE
        ],
    }
    runtime_inventory = {
        "descriptor_allowlists_passed": True,
        "empty_active_child_environments": True,
        "startup_child_environments_allowlisted": True,
        "ipc_edges": ["driver->authority-jsonl", "authority->driver-jsonl", "driver->destination-jsonl", "destination->driver-jsonl"],
        "live_agent_adapter": "absent",
        "methods": ["bind_run", "create_proposal", "record_event", "issue_once", "bind_authority_context", "attempt", "shutdown"],
        "private_material_export_count": 0,
        "process_roles": ["campaign_driver", "authority_signer", "destination_signer", "read_only_verifier"],
        "signer_process_count": 2,
        "tool_name": "deployment.promote",
    }
    writer.json("route-registry.json", route_registry)
    writer.json("noncoverage.json", noncoverage)
    writer.json("runtime-inventory.json", runtime_inventory)
    coverage = generate_coverage(runtime_inventory, matrix, route_registry, noncoverage)
    writer.json("coverage-map.json", coverage)

    tampered = copy.deepcopy(accepted)
    tampered["decision"]["signature"]["value"] = "AA"
    partial = {"decision": accepted["decision"], "state": accepted["state"]}
    ui_labels = {
        "accepted_after_verification": derive(accepted, destination_public, True)["label"],
        "accepted_before_verification": derive(accepted, destination_public, False)["label"],
        "cached_or_untrusted": derive(accepted, authority_public, True)["label"],
        "destination_loss": derive(None, destination_public)["label"],
        "missing_evidence": derive({}, destination_public)["label"],
        "partial_evidence": derive(partial, destination_public)["label"],
        "signed_missing_credential": derive(missing, destination_public)["label"],
        "tampered_evidence": derive(tampered, destination_public)["label"],
    }
    expected_labels = {
        "accepted_after_verification": VERIFIED,
        "accepted_before_verification": PENDING,
        "cached_or_untrusted": UNAVAILABLE,
        "destination_loss": UNAVAILABLE,
        "missing_evidence": UNAVAILABLE,
        "partial_evidence": UNAVAILABLE,
        "signed_missing_credential": REFUSED,
        "tampered_evidence": UNAVAILABLE,
    }
    if ui_labels != expected_labels:
        raise CampaignError("ui_matrix")
    writer.json(
        "ui-matrix.json",
        {
            "labels": ui_labels,
            "positive_from_cache_partial_or_loss": False,
            "provenance_labels": ["authority-signed", "campaign-derived", "client-observed", "destination-signed", "verifier-established"],
            "schema_version": "zlar.protected-promotion.ui-matrix.v1",
        },
    )
    proof_summary = {
        "candidate_id": CANDIDATE_ID,
        "campaign_id": campaign_id,
        "claim_ceiling_id": "CLAIM-CEILING.md",
        "evidence_writes_before_verification": writer.write_count + 5,
        "human_identity": "explicitly_unbound",
        "institutional_authority": "explicitly_unbound",
        "live_agent_adapter": "absent",
        "negative_or_replay_mutations": 0,
        "outcome": "PASS_PENDING_READ_ONLY_VERIFICATION",
        "protected_mutations": 1,
        "recognized_consumptions": 1,
        "recognized_crossings": 1,
        "refusal_count": matrix["totals"]["refusals"],
        "settlement_model": "sole_sequential_process_local_non_crash_commit",
    }
    writer.json("proof-summary.json", proof_summary)
    pre_status_result = _subprocess_verifier(candidate_root, output_root)
    writer.json("verification-observation.json", pre_status_result)
    final_status = derive(accepted, destination_public, verifier_established=True)
    if final_status["label"] != VERIFIED:
        raise CampaignError("final_status_derivation")
    writer.json("status-final.json", final_status)
    writer.json("campaign-tree.json", campaign_identity(output_root))
    complete_result = verify_campaign(candidate_root, output_root, pre_status=False)
    return {
        "campaign_manifest_sha256": sha256_file(output_root / "campaign-tree.json"),
        "campaign_root": str(output_root),
        "case_count": len(matrix_rows),
        "complete_verifier": complete_result,
        "refusal_count": matrix["totals"]["refusals"],
        "result": "PASS",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one disposable Protected Promotion campaign")
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args()
    try:
        result = run(Path(args.output_root))
    except Exception as exc:
        result = {"error": f"{type(exc).__name__}:{str(exc)}", "result": "REFUSE"}
        sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
        return 42
    sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
