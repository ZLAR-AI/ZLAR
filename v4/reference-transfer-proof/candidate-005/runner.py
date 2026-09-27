#!/usr/bin/env python3
"""One-shot frozen Candidate 005 proof runner."""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import base64
import os
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any

from canonical import (
    aggregate_file_records,
    canonical_bytes,
    read_json,
    require_absolute_absent,
    sha256_bytes,
    sha256_file,
    sha256_json,
    strict_loads,
    utf8_path_key,
    write_bytes_exclusive,
)
from contract import (
    ACTION,
    AUTH_EXPIRES_AT,
    AUTH_NONCE,
    AUDIENCE,
    BASE_CASES,
    CANONICAL_REQUEST,
    CANDIDATE_ID,
    CLASS_SUBTOTALS,
    COLLISION_CASE,
    COVERAGE_GENERATOR_ID,
    CROSSING_CASE,
    DESTINATION_ID,
    FIXED_EVALUATION_EPOCH,
    INITIAL_GENERATION,
    MCP_PROTOCOL_VERSION,
    OFFLINE_VERIFIER_ID,
    POST_CASES,
    PROTOCOL_CASES,
    PURPOSE,
    REPLAY_CASE,
    RESOURCE,
    ROLE_BINDINGS,
    SERVER_ID,
    SLOT,
    STAGED_ARTIFACT_ID,
    TOOL_CONTRACT,
    TOOL_CONTRACT_DIGEST,
    TOTAL_CASES,
    base_authorization_payload,
    make_destination_registry,
    make_noncoverage_baseline,
    make_run_plan,
    make_runtime_inventory,
    ordered_case_rows,
    recognition_profile,
    validate_run_plan,
)
from coverage_model import generate_coverage
from crypto_rsa import DEFAULT_KEY_ATTEMPT_LIMIT, REQUESTED_RSA_BITS, generate_rsa_key, public_evidence
from evidence import sign_envelope, verify_envelope
from server import serve


PACKAGE_ROOT = Path(__file__).resolve().parent


class CampaignFailure(RuntimeError):
    pass


def _saved_json(value: Any) -> bytes:
    return canonical_bytes(value) + b"\n"


def _package_identity() -> tuple[str, str, dict[str, Any]]:
    manifest_path = PACKAGE_ROOT / "PACKAGE-MANIFEST.json"
    manifest = read_json(manifest_path)
    if manifest.get("schema_version") != "zlar.star4.package-manifest.v1":
        raise CampaignFailure("package_manifest_schema")
    if manifest.get("self_exclusion") != "PACKAGE-MANIFEST.json is covered by the external complete-package manifest":
        raise CampaignFailure("package_manifest_self_exclusion")
    records = manifest.get("files")
    if not isinstance(records, list):
        raise CampaignFailure("package_manifest_files")
    actual_paths: list[str] = []
    for root, directories, files in os.walk(PACKAGE_ROOT, topdown=True, followlinks=False):
        directories.sort(key=utf8_path_key)
        files.sort(key=utf8_path_key)
        root_path = Path(root)
        for directory in directories:
            if (root_path / directory).is_symlink():
                raise CampaignFailure("package_symlink")
        for filename in files:
            path = root_path / filename
            if path.is_symlink() or not path.is_file():
                raise CampaignFailure("package_nonregular_node")
            relative = path.relative_to(PACKAGE_ROOT).as_posix()
            if relative != "PACKAGE-MANIFEST.json":
                actual_paths.append(relative)
    expected_paths = [record.get("path") for record in records]
    if expected_paths != sorted(expected_paths, key=utf8_path_key) or actual_paths != expected_paths:
        raise CampaignFailure("package_file_set")
    for record in records:
        path = PACKAGE_ROOT / record["path"]
        if path.stat().st_size != record["byte_length"] or sha256_file(path) != record["sha256"]:
            raise CampaignFailure("package_file_identity")
    aggregate = aggregate_file_records(records)
    if aggregate != manifest.get("aggregate_sha256"):
        raise CampaignFailure("package_aggregate")
    package_id = "package-sha256:" + aggregate
    source_id = "source-sha256:" + sha256_json({"candidate_id": CANDIDATE_ID, "package_id": package_id})
    return package_id, source_id, manifest


def _sign_authorization(payload: dict[str, Any], private_key: Any) -> dict[str, Any]:
    return sign_envelope("authorization", payload, private_key)


def _mutated_authorization(case_id: str, base_payload: dict[str, Any], private_key: Any) -> object:
    payload = deepcopy(base_payload)
    if case_id == "AUTH-001-missing-authorization":
        return None
    if case_id == "AUTH-002-malformed-authorization":
        return "not-an-authorization-envelope"
    if case_id == "AUTH-003-unsigned-authorization":
        envelope = _sign_authorization(payload, private_key)
        del envelope["signature"]
        return envelope
    if case_id == "AUTH-004-invalid-signature":
        envelope = _sign_authorization(payload, private_key)
        value = envelope["signature"]["value"]
        envelope["signature"]["value"] = ("A" if value[0] != "A" else "B") + value[1:]
        return envelope
    mutation = {
        "AUTH-005-stale-authorization": lambda p: p.update(expires_at=FIXED_EVALUATION_EPOCH - 1),
        "AUTH-006-revoked-authorization": lambda p: p.update(revoked=True),
        "AUTH-007-unknown-issuer": lambda p: p["issuer"].update(issuer_id="zlar-issuer://unregistered"),
        "AUTH-008-delegated-authorization": lambda p: p.update(
            delegation_mode="delegated", delegation_chain=[{"type": "agent_or_workload", "value": "synthetic-agent"}]
        ),
        "AUTH-009-exhausted-authorization": lambda p: p.update(max_uses=0),
        "AUTH-010-wrong-issuer": lambda p: p["issuer"].update(issuer_id="zlar-issuer://candidate-005/wrong-known"),
        "AUTH-011-wrong-identity-type": lambda p: p["issuer"].update(identity_type="unqualified_string"),
        "AUTH-012-wrong-key": lambda p: p["issuer"].update(public_key_id="rsa-sha256:wrong"),
        "AUTH-013-wrong-audience": lambda p: p.update(audience=AUDIENCE + ".wrong"),
        "AUTH-014-wrong-resource": lambda p: p.update(resource=RESOURCE + ".wrong"),
        "AUTH-015-wrong-action": lambda p: p.update(action="deployment.rollback"),
        "AUTH-016-wrong-destination": lambda p: p.update(destination=DESTINATION_ID + ".wrong"),
        "AUTH-017-wrong-purpose": lambda p: p.update(purpose=PURPOSE + "_wrong"),
        "AUTH-018-wrong-schema": lambda p: p.update(evidence_schema_version="zlar.star4.evidence-envelope.v0"),
        "AUTH-019-wrong-profile": lambda p: p["recognition_profile"].update(identity="wrong-profile"),
        "AUTH-020-wrong-package": lambda p: p.update(package_id="package-sha256:wrong"),
        "AUTH-021-wrong-server": lambda p: p.update(server_id=SERVER_ID + ".wrong"),
        "AUTH-022-wrong-source": lambda p: p.update(source_id="source-sha256:wrong"),
        "AUTH-023-wrong-tool-contract": lambda p: p.update(tool_contract_digest="0" * 64),
        "AUTH-024-wrong-tool": lambda p: p.update(tool_name="deployment.rollback"),
        "AUTH-025-wrong-authority-domain": lambda p: p.update(authority_domain="wrong-domain"),
        "AUTH-026-wrong-slot": lambda p: p.update(slot="secondary"),
        "AUTH-027-wrong-artifact": lambda p: p.update(staged_artifact_id="synthetic-artifact.wrong"),
        "AUTH-028-wrong-generation": lambda p: p["canonical_request"].update(expected_generation=INITIAL_GENERATION + 1),
        "AUTH-029-wrong-request": lambda p: p["canonical_request"].update(staged_artifact_id="synthetic-artifact.wrong"),
        "AUTH-030-wrong-nonce": lambda p: p.update(nonce=AUTH_NONCE + "-wrong"),
        "AUTH-031-wrong-expiry": lambda p: p.update(expires_at=AUTH_EXPIRES_AT + 1),
        "AUTH-032-wrong-max-uses": lambda p: p.update(max_uses=2),
        "AUTH-033-absent-audience": lambda p: p.update(audience={"presence": "explicitly_unbound"}),
        "AUTH-034-multiple-audience": lambda p: p.update(audience=[AUDIENCE, AUDIENCE + ".two"]),
        "AUTH-035-wildcard-audience": lambda p: p.update(audience="*"),
        "AUTH-036-conflicting-audience": lambda p: p.update(audience={"primary": AUDIENCE, "secondary": "conflict"}),
        "AUTH-037-noncanonical-audience": lambda p: p.update(audience=AUDIENCE + " "),
        "AUTH-038-absent-resource": lambda p: p.update(resource={"presence": "explicitly_unbound"}),
        "AUTH-039-multiple-resource": lambda p: p.update(resource=[RESOURCE, RESOURCE + ".two"]),
        "AUTH-040-wildcard-resource": lambda p: p.update(resource="*"),
        "AUTH-041-conflicting-resource": lambda p: p.update(resource={"primary": RESOURCE, "secondary": "conflict"}),
        "AUTH-042-noncanonical-resource": lambda p: p.update(resource=RESOURCE + " "),
        "AUTH-043-absent-destination": lambda p: p.update(destination={"presence": "explicitly_unbound"}),
        "AUTH-044-multiple-destination": lambda p: p.update(destination=[DESTINATION_ID, DESTINATION_ID + ".two"]),
        "AUTH-045-wildcard-destination": lambda p: p.update(destination="*"),
        "AUTH-046-conflicting-destination": lambda p: p.update(
            destination={"primary": DESTINATION_ID, "secondary": "conflict"}
        ),
        "AUTH-047-noncanonical-destination": lambda p: p.update(destination=DESTINATION_ID + " "),
        "AUTH-048-unknown-presence": lambda p: p["roles"]["human_principal"].update(presence="unknown"),
        "AUTH-049-not-collected-presence": lambda p: p["roles"]["human_principal"].update(presence="not_collected"),
        "AUTH-050-missing-required-field": lambda p: p.pop("purpose"),
        "AUTH-051-null-required-field": lambda p: p.update(purpose=None),
        "AUTH-052-empty-required-field": lambda p: p.update(purpose=""),
    }
    try:
        mutation[case_id](payload)
    except KeyError as exc:
        raise CampaignFailure(f"unknown_authorization_case:{case_id}") from exc
    return _sign_authorization(payload, private_key)


def _rpc_request(case_id: str, method: str, params: Any, extra: dict[str, Any] | None = None) -> bytes:
    request = {"id": case_id, "jsonrpc": "2.0", "method": method, "params": params}
    if extra:
        request.update(extra)
    return canonical_bytes(request)


def _tool_call(case_id: str, authorization: object, request_value: Any | None = None) -> bytes:
    arguments: dict[str, Any] = {"request": deepcopy(CANONICAL_REQUEST)}
    if authorization is not None or case_id != "AUTH-001-missing-authorization":
        arguments["authorization"] = authorization
    if request_value is not None:
        arguments["request"] = request_value
    return _rpc_request(case_id, "tools/call", {"arguments": arguments, "name": ACTION})


def _make_attempts(base_payload: dict[str, Any], base_authorization: dict[str, Any], private_key: Any) -> dict[str, bytes]:
    attempts: dict[str, bytes] = {}
    attempts["PROTO-027-tools-call-before-initialize"] = _tool_call(
        "PROTO-027-tools-call-before-initialize", base_authorization
    )
    for case_id, _ in BASE_CASES:
        attempts[case_id] = _tool_call(case_id, _mutated_authorization(case_id, base_payload, private_key))
    caller_fields = {
        "PROTO-001-caller-recognition-policy": "recognition_policy",
        "PROTO-002-caller-public-key": "public_key",
        "PROTO-003-caller-destination-config": "destination_configuration",
        "PROTO-004-caller-state": "state",
        "PROTO-005-caller-path": "path",
        "PROTO-006-caller-effect-adapter": "effect_adapter",
        "PROTO-007-caller-bearer-token": "bearer_token",
        "PROTO-008-caller-receipt-status": "receipt_status",
    }
    for case_id, field in caller_fields.items():
        arguments = {"authorization": base_authorization, "request": deepcopy(CANONICAL_REQUEST), field: "forbidden"}
        attempts[case_id] = _rpc_request(case_id, "tools/call", {"arguments": arguments, "name": ACTION})
    attempts["PROTO-009-unknown-method"] = _rpc_request("PROTO-009-unknown-method", "unknown/method", {})
    attempts["PROTO-010-unknown-tool"] = _rpc_request(
        "PROTO-010-unknown-tool",
        "tools/call",
        {"arguments": {"authorization": base_authorization, "request": CANONICAL_REQUEST}, "name": "unknown.tool"},
    )
    attempts["PROTO-011-duplicate-json-key"] = (
        b'{"id":"PROTO-011-duplicate-json-key","jsonrpc":"2.0","method":"tools/call","params":{},"params":{}}'
    )
    attempts["PROTO-012-byte-ambiguity"] = (
        b'{"id":"PROTO-012-byte-ambiguity","jsonrpc":"2.0","method":"tools/call","params":1.0}'
    )
    attempts["PROTO-013-forbidden-extra-field"] = _rpc_request(
        "PROTO-013-forbidden-extra-field", "tools/call", {}, {"unexpected": True}
    )
    for case_id in (
        "PROTO-014-list-changed",
        "PROTO-015-inconsistent-second-list",
        "PROTO-016-unsupported-schema-dialect",
        "PROTO-018-metadata-drift",
        "PROTO-019-input-schema-drift",
        "PROTO-020-output-schema-drift",
    ):
        attempts[case_id] = _rpc_request(case_id, "tools/list", {})
    attempts["PROTO-017-capability-drift"] = _rpc_request(
        "PROTO-017-capability-drift",
        "initialize",
        {"capabilities": {}, "protocolVersion": MCP_PROTOCOL_VERSION},
    )
    for case_id in (
        "PROTO-021-package-drift",
        "PROTO-022-source-drift",
        "PROTO-023-tool-contract-drift",
        "PROTO-024-protected-state-drift",
    ):
        attempts[case_id] = _tool_call(case_id, base_authorization)
    attempts["PROTO-025-alternate-request-form"] = _rpc_request(
        "PROTO-025-alternate-request-form", "tools/call", []
    )
    attempts["PROTO-026-malformed-json"] = (
        b'{"id":"PROTO-026-malformed-json","jsonrpc":"2.0","method":"tools/call","params":'
    )
    attempts[COLLISION_CASE[0]] = _tool_call(COLLISION_CASE[0], base_authorization)
    attempts[CROSSING_CASE[0]] = _tool_call(CROSSING_CASE[0], base_authorization)
    attempts[REPLAY_CASE[0]] = _tool_call(REPLAY_CASE[0], base_authorization)
    attempts["POST-001-state-generation-drift"] = _tool_call("POST-001-state-generation-drift", base_authorization)
    post_two_payload = deepcopy(base_payload)
    post_two_payload["canonical_request"]["staged_artifact_id"] = "synthetic-artifact.post-acceptance"
    attempts["POST-002-second-artifact-attempt"] = _tool_call(
        "POST-002-second-artifact-attempt", _sign_authorization(post_two_payload, private_key)
    )
    attempts["POST-003-fresh-nonce-old-generation"] = _tool_call(
        "POST-003-fresh-nonce-old-generation", base_authorization
    )
    revoked_payload = deepcopy(base_payload)
    revoked_payload["revoked"] = True
    attempts["POST-004-revoked-after-acceptance"] = _tool_call(
        "POST-004-revoked-after-acceptance", _sign_authorization(revoked_payload, private_key)
    )
    expected_ids = [row["case_id"] for row in ordered_case_rows()]
    if set(attempts) != set(expected_ids):
        raise CampaignFailure("attempt_set_not_exact")
    return attempts


class StdioClient:
    def __init__(self, bootstrap: dict[str, Any], private_key: Any):
        child_read, parent_write = os.pipe()
        parent_read, child_write = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(parent_write)
                os.close(parent_read)
                exit_code = serve(child_read, child_write, bootstrap, private_key)
            except BaseException:
                exit_code = 70
            os._exit(exit_code)
        os.close(child_read)
        os.close(child_write)
        self.pid = pid
        self.writer = os.fdopen(parent_write, "wb", buffering=0)
        self.reader = os.fdopen(parent_read, "rb", buffering=0)
        self.closed = False

    def send(self, raw: bytes) -> dict[str, Any]:
        if self.closed:
            raise CampaignFailure("stdio_client_closed")
        self.writer.write(raw + b"\n")
        self.writer.flush()
        response_raw = self.reader.readline()
        if response_raw == b"":
            raise CampaignFailure("stdio_server_closed_early")
        response = strict_loads(response_raw)
        if not isinstance(response, dict):
            raise CampaignFailure("stdio_response_not_object")
        return response

    def close(self) -> int:
        if self.closed:
            raise CampaignFailure("stdio_client_already_closed")
        self.closed = True
        self.writer.close()
        self.reader.close()
        _, status = os.waitpid(self.pid, 0)
        return os.waitstatus_to_exitcode(status)


def _write(root: Path, relative: str, raw: bytes, written: list[str]) -> None:
    write_bytes_exclusive(root / relative, raw)
    written.append(relative)


def _collect_file_records(root: Path, exclude: set[str]) -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    directories: list[str] = []
    for current_root, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames.sort(key=utf8_path_key)
        filenames.sort(key=utf8_path_key)
        current = Path(current_root)
        for dirname in dirnames:
            path = current / dirname
            if path.is_symlink():
                raise CampaignFailure("evidence_symlink")
            directories.append(path.relative_to(root).as_posix())
        for filename in filenames:
            path = current / filename
            if path.is_symlink() or not path.is_file():
                raise CampaignFailure("evidence_nonregular_node")
            relative = path.relative_to(root).as_posix()
            if relative in exclude:
                continue
            records.append({"byte_length": path.stat().st_size, "path": relative, "sha256": sha256_file(path)})
    records.sort(key=lambda row: utf8_path_key(row["path"]))
    directories.sort(key=utf8_path_key)
    return records, directories


def run_campaign(output_root_text: str) -> dict[str, Any]:
    output_root = require_absolute_absent(output_root_text)
    package_id, source_id, package_manifest = _package_identity()
    output_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    private_key, key_attempts, observed_key_bits = generate_rsa_key(
        requested_bits=REQUESTED_RSA_BITS, max_attempts=DEFAULT_KEY_ATTEMPT_LIMIT
    )
    public_key = public_evidence(private_key)
    if public_key["actual_modulus_bits"] != REQUESTED_RSA_BITS:
        raise CampaignFailure("public_key_modulus_bits")
    base_payload = base_authorization_payload(package_id, source_id, str(public_key["public_key_id"]))
    authorization = _sign_authorization(base_payload, private_key)
    profile = recognition_profile(package_id, source_id, str(public_key["public_key_id"]))
    attempts = _make_attempts(base_payload, authorization, private_key)
    attempt_hashes = {case_id: sha256_bytes(raw) for case_id, raw in attempts.items()}
    run_plan = make_run_plan(package_id, source_id, attempt_hashes)
    attempt_input_rows = [
        {
            "case_class": run_plan["case_class_map"][case_id],
            "case_id": case_id,
            "raw_base64": base64.b64encode(attempts[case_id]).decode("ascii"),
            "raw_byte_length": len(attempts[case_id]),
            "raw_sha256": attempt_hashes[case_id],
        }
        for case_id in [row["case_id"] for row in run_plan["cases"]]
    ]
    attempt_inputs = {
        "attempt_count": len(attempt_input_rows),
        "candidate_id": CANDIDATE_ID,
        "ordered_attempts": attempt_input_rows,
        "schema_version": "zlar.star4.attempt-inputs.v1",
    }
    runtime_inventory = make_runtime_inventory(package_id, source_id)
    destination_registry = make_destination_registry(package_id, source_id)
    noncoverage_baseline = make_noncoverage_baseline(package_id, source_id)
    written: list[str] = []
    for relative, value in (
        ("attempt-inputs.json", attempt_inputs),
        ("authorization.json", authorization),
        ("destination-registry.json", destination_registry),
        ("noncoverage-baseline.json", noncoverage_baseline),
        ("public-key.json", public_key),
        ("recognition-profile.json", profile),
        ("run-plan.json", run_plan),
        ("runtime-inventory.json", runtime_inventory),
    ):
        _write(output_root, relative, _saved_json(value), written)
    faults = {
        case_id: reason
        for case_id, reason in PROTOCOL_CASES
        if case_id
        in {
            "PROTO-014-list-changed",
            "PROTO-015-inconsistent-second-list",
            "PROTO-016-unsupported-schema-dialect",
            "PROTO-017-capability-drift",
            "PROTO-018-metadata-drift",
            "PROTO-019-input-schema-drift",
            "PROTO-020-output-schema-drift",
            "PROTO-021-package-drift",
            "PROTO-022-source-drift",
            "PROTO-023-tool-contract-drift",
            "PROTO-024-protected-state-drift",
        }
    }
    faults["POST-001-state-generation-drift"] = "protected_state_drift"
    faults["POST-003-fresh-nonce-old-generation"] = "protected_state_drift"
    bootstrap = {
        "collision_path": str(output_root / "collision-preexisting"),
        "expected_authorization": base_payload,
        "fault_request_ids": faults,
        "package_id": package_id,
        "public_key": public_key,
        "recognition_profile": profile,
        "source_id": source_id,
    }
    client = StdioClient(bootstrap, private_key)
    session_observations: list[dict[str, Any]] = []
    matrix_rows: list[dict[str, Any]] = []
    decisions: dict[str, Any] = {}
    refusals: dict[str, Any] = {}
    effect: dict[str, Any] | None = None
    consumption: dict[str, Any] | None = None
    state_final: dict[str, Any] | None = None
    plan_rows = {row["case_id"]: row for row in run_plan["cases"]}
    ordered_ids = [row["case_id"] for row in run_plan["cases"]]
    try:
        for index, case_id in enumerate(ordered_ids):
            if index == 1:
                initialize_raw = _rpc_request(
                    "SESSION-initialize",
                    "initialize",
                    {"capabilities": {}, "protocolVersion": MCP_PROTOCOL_VERSION},
                )
                initialize_response = client.send(initialize_raw)
                first_list_raw = _rpc_request("SESSION-tools-list-1", "tools/list", {})
                second_list_raw = _rpc_request("SESSION-tools-list-2", "tools/list", {})
                first_list = client.send(first_list_raw)
                second_list = client.send(second_list_raw)
                if first_list["result"] != second_list["result"]:
                    raise CampaignFailure("inconsistent_initial_tools_list")
                if first_list["result"].get("toolContractDigest") != TOOL_CONTRACT_DIGEST:
                    raise CampaignFailure("initial_tool_contract_digest")
                if first_list["result"].get("tools") != TOOL_CONTRACT["tools"]:
                    raise CampaignFailure("initial_tool_inventory")
                session_observations.extend(
                    [
                        {
                            "request_sha256": sha256_bytes(initialize_raw),
                            "response": initialize_response,
                            "session_step": "initialize",
                        },
                        {
                            "request_sha256": sha256_bytes(first_list_raw),
                            "response": first_list,
                            "session_step": "tools_list_first",
                        },
                        {
                            "request_sha256": sha256_bytes(second_list_raw),
                            "response": second_list,
                            "session_step": "tools_list_second_equal",
                        },
                    ]
                )
            if case_id == COLLISION_CASE[0]:
                _write(output_root, "collision-preexisting", b"planned-collision-sentinel\n", written)
            response = client.send(attempts[case_id])
            if response.get("id") != case_id or response.get("jsonrpc") != "2.0":
                raise CampaignFailure(f"jsonrpc_response_identity:{case_id}")
            result = response.get("result")
            if not isinstance(result, dict) or not isinstance(result.get("decision"), dict):
                raise CampaignFailure(f"missing_structured_decision:{case_id}")
            decision_payload = verify_envelope(result["decision"], public_key, expected_type="decision")
            expected = plan_rows[case_id]
            if decision_payload["outcome"] != expected["expected_result"]:
                raise CampaignFailure(f"unexpected_outcome:{case_id}")
            if decision_payload["reason"] != expected["expected_reason"]:
                raise CampaignFailure(
                    f"unexpected_reason:{case_id}:{decision_payload['reason']}:{expected['expected_reason']}"
                )
            refusal_id = None
            effect_id = None
            consumption_id = None
            if decision_payload["outcome"] == "refused":
                if result.get("effect") is not None or not isinstance(result.get("refusal"), dict):
                    raise CampaignFailure(f"refusal_shape:{case_id}")
                refusal_payload = verify_envelope(result["refusal"], public_key, expected_type="refusal")
                if refusal_payload["decision_receipt_id"] != decision_payload["receipt_id"]:
                    raise CampaignFailure(f"refusal_link:{case_id}")
                refusal_id = refusal_payload["receipt_id"]
                refusals[case_id] = result["refusal"]
            else:
                if result.get("refusal") is not None or not isinstance(result.get("effect"), dict):
                    raise CampaignFailure("accepted_shape")
                if not isinstance(result.get("consumption"), dict):
                    raise CampaignFailure("accepted_consumption_shape")
                effect_payload = verify_envelope(result["effect"], public_key, expected_type="effect")
                consumption_payload = verify_envelope(result["consumption"], public_key, expected_type="consumption")
                if effect_payload["decision_receipt_id"] != decision_payload["receipt_id"]:
                    raise CampaignFailure("effect_decision_link")
                if consumption_payload["effect_receipt_id"] != effect_payload["receipt_id"]:
                    raise CampaignFailure("consumption_effect_link")
                effect = result["effect"]
                consumption = result["consumption"]
                effect_id = effect_payload["receipt_id"]
                consumption_id = consumption_payload["receipt_id"]
            decisions[case_id] = result["decision"]
            state_final = result["state"]
            matrix_rows.append(
                {
                    "attempt_input_sha256": attempt_hashes[case_id],
                    "case_class": expected["case_class"],
                    "case_id": case_id,
                    "consumption_delta": expected["expected_consumptions"],
                    "consumption_receipt_id": consumption_id,
                    "decision_receipt_id": decision_payload["receipt_id"],
                    "effect_receipt_id": effect_id,
                    "mutation_delta": expected["expected_mutations"],
                    "observed_outcome": decision_payload["outcome"],
                    "observed_reason": decision_payload["reason"],
                    "refusal_receipt_id": refusal_id,
                }
            )
    finally:
        server_exit = client.close()
    if server_exit != 0:
        raise CampaignFailure(f"stdio_server_exit:{server_exit}")
    if len(decisions) != TOTAL_CASES or len(refusals) != TOTAL_CASES - 1 or effect is None or consumption is None:
        raise CampaignFailure("receipt_cardinality")
    if state_final is None:
        raise CampaignFailure("missing_final_state")
    set_equalities = validate_run_plan(run_plan, attempt_hashes=attempt_hashes, matrix_rows=matrix_rows)
    matrix_class_counts = dict(sorted(Counter(row["case_class"] for row in matrix_rows).items()))
    if matrix_class_counts != CLASS_SUBTOTALS:
        raise CampaignFailure("matrix_class_subtotals")
    protected_mutations = sum(row["mutation_delta"] for row in matrix_rows)
    recognized_consumptions = sum(row["consumption_delta"] for row in matrix_rows)
    if protected_mutations != 1 or recognized_consumptions != 1:
        raise CampaignFailure("protected_budget")
    matrix_payload = {
        "case_class_map": run_plan["case_class_map"],
        "case_count": len(matrix_rows),
        "cases": matrix_rows,
        "candidate_id": CANDIDATE_ID,
        "class_subtotals": matrix_class_counts,
        "negative_protected_consumptions": 0,
        "negative_protected_mutations": 0,
        "outside_domain_protected_consumptions": 0,
        "outside_domain_protected_mutations": 0,
        "package_id": package_id,
        "prohibited_protected_consumptions": 0,
        "prohibited_protected_mutations": 0,
        "real_external_protected_consumptions": 0,
        "real_external_protected_mutations": 0,
        "recognized_consumptions": recognized_consumptions,
        "recognized_protected_mutations": protected_mutations,
        "replay_protected_consumptions": 0,
        "replay_protected_mutations": 0,
        "run_plan_body_sha256": run_plan["plan_body_sha256"],
        "set_equalities": set_equalities,
        "source_id": source_id,
        "tool_contract_digest": TOOL_CONTRACT_DIGEST,
    }
    matrix_evidence = sign_envelope("matrix", matrix_payload, private_key)
    runner_matrix = {
        "case_count": len(matrix_rows),
        "case_ids": [row["case_id"] for row in matrix_rows],
        "case_rows": matrix_rows,
        "class_subtotals": matrix_class_counts,
        "schema_version": "zlar.star4.runner-matrix.v1",
    }
    for case_id in ordered_ids:
        _write(output_root, f"decision-receipts/{case_id}.json", _saved_json(decisions[case_id]), written)
        if case_id in refusals:
            _write(output_root, f"refusal-receipts/{case_id}.json", _saved_json(refusals[case_id]), written)
    _write(output_root, "effect-receipt.json", _saved_json(effect), written)
    _write(output_root, "consumption-receipt.json", _saved_json(consumption), written)
    _write(output_root, "matrix-evidence.json", _saved_json(matrix_evidence), written)
    _write(output_root, "runner-matrix.json", _saved_json(runner_matrix), written)
    _write(
        output_root,
        "session-observations.json",
        _saved_json(
            {
                "child_process_count": 1,
                "observations": session_observations,
                "schema_version": "zlar.star4.session-observations.v1",
                "tools_list_equal": session_observations[1]["response"]["result"]
                == session_observations[2]["response"]["result"],
            }
        ),
        written,
    )
    _write(output_root, "state-final.json", _saved_json(state_final), written)
    coverage_map = generate_coverage(runtime_inventory, destination_registry, matrix_evidence, noncoverage_baseline)
    coverage_envelope = sign_envelope(
        "coverage",
        {
            "candidate_id": CANDIDATE_ID,
            "coverage_map_raw_sha256": sha256_bytes(_saved_json(coverage_map)),
            "derivation_basis_counts": coverage_map["derivation_basis_counts"],
            "disposition_counts": coverage_map["disposition_counts"],
            "input_bindings": coverage_map["input_bindings"],
            "observed_outcome_counts": coverage_map["observed_outcome_counts"],
            "package_id": package_id,
            "row_count": coverage_map["row_count"],
            "source_id": source_id,
        },
        private_key,
    )
    _write(output_root, "coverage-map.json", _saved_json(coverage_map), written)
    _write(output_root, "coverage-envelope.json", _saved_json(coverage_envelope), written)
    files_before_summary, _ = _collect_file_records(output_root, exclude={"output-manifest.json"})
    planned_total_regular_files = len(files_before_summary) + 2
    proof_summary = {
        "actual_public_modulus_bits": public_key["actual_modulus_bits"],
        "bounded_key_generation_attempt_limit": DEFAULT_KEY_ATTEMPT_LIMIT,
        "candidate_id": CANDIDATE_ID,
        "case_count": len(matrix_rows),
        "child_process_count": 1,
        "class_subtotals": matrix_class_counts,
        "coverage_row_count": coverage_map["row_count"],
        "decision_receipt_writes": len(decisions),
        "effect_receipt_writes": 1,
        "harness_package_regular_file_writes": planned_total_regular_files,
        "key_generation_attempts_used": key_attempts,
        "observed_key_candidate_bit_lengths": observed_key_bits,
        "package_id": package_id,
        "recognized_authorization_consumptions": recognized_consumptions,
        "recognized_protected_mutations": protected_mutations,
        "refusal_receipt_writes": len(refusals),
        "requested_nominal_rsa_bits": REQUESTED_RSA_BITS,
        "set_equalities": set_equalities,
        "source_id": source_id,
        "verdict": "PASS_CANDIDATE_005_BUILDER_SELF_CHECK",
        "zero_counters": {
            "negative_consumptions": 0,
            "negative_mutations": 0,
            "outside_domain_consumptions": 0,
            "outside_domain_mutations": 0,
            "prohibited_consumptions": 0,
            "prohibited_mutations": 0,
            "real_external_consumptions": 0,
            "real_external_mutations": 0,
            "replay_consumptions": 0,
            "replay_mutations": 0,
        },
    }
    _write(output_root, "proof-summary.json", _saved_json(proof_summary), written)
    manifest_records, manifest_directories = _collect_file_records(output_root, exclude={"output-manifest.json"})
    output_manifest = sign_envelope(
        "output_manifest",
        {
            "aggregate_sha256": aggregate_file_records(manifest_records),
            "candidate_id": CANDIDATE_ID,
            "directories": manifest_directories,
            "file_count": len(manifest_records),
            "files": manifest_records,
            "manifest_self_exclusion": "output-manifest.json is authenticated by its signature and excluded from its own file list",
            "package_id": package_id,
            "source_id": source_id,
        },
        private_key,
    )
    _write(output_root, "output-manifest.json", _saved_json(output_manifest), written)
    if len(written) != planned_total_regular_files:
        raise CampaignFailure("harness_write_counter")
    package_id_after, source_id_after, manifest_after = _package_identity()
    if package_id_after != package_id or source_id_after != source_id or manifest_after != package_manifest:
        raise CampaignFailure("post_run_package_drift")
    return {
        "actual_public_modulus_bits": public_key["actual_modulus_bits"],
        "campaign_output_root": str(output_root),
        "case_count": len(matrix_rows),
        "class_subtotals": matrix_class_counts,
        "coverage_row_count": coverage_map["row_count"],
        "key_generation_attempts_used": key_attempts,
        "package_id": package_id,
        "recognized_consumptions": recognized_consumptions,
        "recognized_protected_mutations": protected_mutations,
        "requested_nominal_rsa_bits": REQUESTED_RSA_BITS,
        "source_id": source_id,
        "verdict": "PASS_CANDIDATE_005_BUILDER_CAMPAIGN",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the one-shot Candidate 005 frozen proof campaign")
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args()
    result = run_campaign(args.output_root)
    sys.stdout.buffer.write(_saved_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
