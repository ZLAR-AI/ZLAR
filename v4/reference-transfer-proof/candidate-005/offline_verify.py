#!/usr/bin/env python3
"""Separate read-only verifier for a saved Candidate 005 campaign."""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import base64
import os
from collections import Counter
from pathlib import Path
from typing import Any

from canonical import (
    CANONICALIZATION_ID,
    aggregate_file_records,
    canonical_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    utf8_path_key,
)
from contract import (
    ACTION,
    CANDIDATE_ID,
    CLASS_SUBTOTALS,
    COLLECTOR_ID,
    COVERAGE_GENERATOR_ID,
    DESTINATION_ID,
    FIXED_EVALUATION_EPOCH,
    INITIAL_GENERATION,
    MANDATORY_NONCOVERAGE,
    MCP_PROTOCOL_VERSION,
    OFFLINE_VERIFIER_ID,
    PROTOCOL_PROFILE_ID,
    SERVER_ID,
    TOOL_CONTRACT,
    TOOL_CONTRACT_DIGEST,
    TOTAL_CASES,
    validate_run_plan,
)
from crypto_rsa import REQUESTED_RSA_BITS, parse_public_evidence
from evidence import verify_envelope


class VerificationFailure(RuntimeError):
    pass


class Checker:
    def __init__(self) -> None:
        self.assertions = 0

    def require(self, condition: bool, label: str) -> None:
        self.assertions += 1
        if not condition:
            raise VerificationFailure(label)


def _saved_json(value: Any) -> bytes:
    return canonical_bytes(value) + b"\n"


def _tree_projection(root: Path) -> list[dict[str, Any]]:
    projection: list[dict[str, Any]] = []
    for current_root, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames.sort(key=utf8_path_key)
        filenames.sort(key=utf8_path_key)
        current = Path(current_root)
        for dirname in dirnames:
            path = current / dirname
            if path.is_symlink():
                raise VerificationFailure("evidence_symlink")
            projection.append({"path": path.relative_to(root).as_posix(), "type": "directory"})
        for filename in filenames:
            path = current / filename
            if path.is_symlink() or not path.is_file():
                raise VerificationFailure("evidence_nonregular_node")
            projection.append(
                {
                    "byte_length": path.stat().st_size,
                    "path": path.relative_to(root).as_posix(),
                    "sha256": sha256_file(path),
                    "type": "file",
                }
            )
    return projection


def _raw_sha(value: Any) -> str:
    return sha256_bytes(_saved_json(value))


def _regenerate_coverage(
    runtime_inventory: dict[str, Any],
    destination_registry: dict[str, Any],
    matrix_evidence: dict[str, Any],
    noncoverage_baseline: dict[str, Any],
) -> dict[str, Any]:
    """Independent implementation: deliberately imports no subject generator."""
    package_id = runtime_inventory["package_id"]
    source_id = runtime_inventory["source_id"]
    evidence_id = matrix_evidence["payload"]["receipt_id"]
    bindings = {
        "destination_registry": {
            "producer_id": destination_registry["producer_id"],
            "raw_sha256": _raw_sha(destination_registry),
            "schema_version": destination_registry["schema_version"],
        },
        "matrix_evidence": {
            "producer_id": SERVER_ID,
            "raw_sha256": _raw_sha(matrix_evidence),
            "schema_version": matrix_evidence["schema_version"],
        },
        "noncoverage_baseline": {
            "producer_id": noncoverage_baseline["producer_id"],
            "raw_sha256": _raw_sha(noncoverage_baseline),
            "schema_version": noncoverage_baseline["schema_version"],
        },
        "runtime_inventory": {
            "producer_id": runtime_inventory["collector_id"],
            "raw_sha256": _raw_sha(runtime_inventory),
            "schema_version": runtime_inventory["schema_version"],
        },
    }

    def common(surface_id: str) -> dict[str, Any]:
        return {
            "candidate_id": CANDIDATE_ID,
            "collector_id": COLLECTOR_ID,
            "collector_version": "1",
            "coverage_generator_id": COVERAGE_GENERATOR_ID,
            "coverage_generator_version": "1",
            "evaluator_run_id": "candidate-005-builder-frozen-campaign",
            "evidence_identity": evidence_id,
            "observed_at_epoch": FIXED_EVALUATION_EPOCH,
            "offline_verifier_id": OFFLINE_VERIFIER_ID,
            "offline_verifier_version": "1",
            "package_id": package_id,
            "protocol_profile_id": PROTOCOL_PROFILE_ID,
            "source_id": source_id,
            "surface_id": surface_id,
            "tool_contract_digest": TOOL_CONTRACT_DIGEST,
        }

    rows: list[dict[str, Any]] = [
        {
            **common("mcp.method.initialize"),
            "action": "initialize",
            "bypass_or_limitation": "bounded profile initialization only",
            "consequence_class": "none",
            "derivation_basis": ["runtime_inventory", "session_observations", "matrix_zero_mutation"],
            "destination_id": DESTINATION_ID,
            "governance_mechanism": "protocol_shape_validation",
            "method": "initialize",
            "observed_outcome": "no_effect_observed",
            "recognition_point": "not_applicable",
            "route_id": "mcp.route.initialize",
            "surface_disposition": "consequence_incapable",
            "supporting_evidence": [bindings["runtime_inventory"]["raw_sha256"], evidence_id],
            "tool_name": None,
        },
        {
            **common("mcp.method.tools-list"),
            "action": "tools/list",
            "bypass_or_limitation": "inventory observation only",
            "consequence_class": "none",
            "derivation_basis": ["runtime_inventory", "two_equal_tools_list_observations", "matrix_zero_mutation"],
            "destination_id": DESTINATION_ID,
            "governance_mechanism": "frozen_tool_contract_digest",
            "method": "tools/list",
            "observed_outcome": "no_effect_observed",
            "recognition_point": "not_applicable",
            "route_id": "mcp.route.tools-list",
            "surface_disposition": "consequence_incapable",
            "supporting_evidence": [bindings["runtime_inventory"]["raw_sha256"], evidence_id],
            "tool_name": None,
        },
        {
            **common("mcp.tool.deployment-promote"),
            "action": ACTION,
            "bypass_or_limitation": "governed only inside frozen local stdio candidate route",
            "consequence_class": "synthetic.deployment.promote",
            "derivation_basis": [
                "runtime_inventory",
                "destination_registry_declaration",
                "complete_negative_matrix",
                "recognized_crossing",
                "replay_refusal",
                "linked_settlement",
            ],
            "destination_id": DESTINATION_ID,
            "governance_mechanism": "signed_single_use_authorization_and_destination_recognition",
            "method": "tools/call",
            "observed_outcome": "effect_committed",
            "recognition_point": "inside_destination_immediately_before_commit",
            "route_id": "mcp.route.tools-call.deployment-promote",
            "surface_disposition": "governed",
            "supporting_evidence": [
                bindings["runtime_inventory"]["raw_sha256"],
                bindings["destination_registry"]["raw_sha256"],
                evidence_id,
            ],
            "tool_name": ACTION,
        },
        {
            **common("destination.direct-promotion-entry"),
            "action": ACTION,
            "bypass_or_limitation": "same-user source owner can import or modify destination code",
            "consequence_class": "synthetic.deployment.promote",
            "derivation_basis": ["destination_registry_declaration_only", "mandatory_noncoverage_baseline"],
            "destination_id": DESTINATION_ID,
            "governance_mechanism": None,
            "method": None,
            "observed_outcome": "not_exercised",
            "recognition_point": None,
            "route_id": "destination.route.direct-internal-entry",
            "surface_disposition": "open",
            "supporting_evidence": [
                bindings["destination_registry"]["raw_sha256"],
                bindings["noncoverage_baseline"]["raw_sha256"],
            ],
            "tool_name": None,
        },
    ]
    probed = {
        "alternate_request_forms": "refused_pre_destination",
        "unknown_methods": "refused_pre_destination",
        "unknown_tools": "refused_pre_destination",
    }
    for baseline in noncoverage_baseline["surfaces"]:
        sid = baseline["surface_id"]
        rows.append(
            {
                **common("side-door." + sid),
                "action": None,
                "bypass_or_limitation": baseline["uncertainty_reason"],
                "consequence_class": "unknown_or_outside_frozen_terminal",
                "derivation_basis": ["mandatory_noncoverage_baseline", "protocol_probe" if sid in probed else "not_exercised"],
                "destination_id": None,
                "governance_mechanism": None,
                "method": None,
                "observed_outcome": probed.get(sid, "not_exercised"),
                "recognition_point": None,
                "route_id": None,
                "surface_disposition": baseline["required_disposition"],
                "supporting_evidence": [
                    bindings["noncoverage_baseline"]["raw_sha256"],
                    evidence_id if sid in probed else bindings["noncoverage_baseline"]["raw_sha256"],
                ],
                "tool_name": None,
            }
        )
    rows.sort(key=lambda row: row["surface_id"].encode("utf-8"))
    return {
        "candidate_id": CANDIDATE_ID,
        "canonicalization_id": CANONICALIZATION_ID,
        "coverage_generator_id": COVERAGE_GENERATOR_ID,
        "coverage_generator_version": "1",
        "derivation_basis_counts": dict(
            sorted(Counter(basis for row in rows for basis in row["derivation_basis"]).items())
        ),
        "disposition_counts": dict(sorted(Counter(row["surface_disposition"] for row in rows).items())),
        "generated_at_epoch": FIXED_EVALUATION_EPOCH,
        "input_bindings": bindings,
        "observed_outcome_counts": dict(sorted(Counter(row["observed_outcome"] for row in rows).items())),
        "package_id": package_id,
        "protocol_profile_id": PROTOCOL_PROFILE_ID,
        "row_count": len(rows),
        "rows": rows,
        "schema_version": "zlar.star4.two-axis-coverage.v1",
        "source_id": source_id,
        "tool_contract_digest": TOOL_CONTRACT_DIGEST,
    }


def verify_campaign(root_text: str) -> dict[str, Any]:
    root = Path(root_text)
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise VerificationFailure("campaign_root")
    before = _tree_projection(root)
    check = Checker()
    public_key = read_json(root / "public-key.json")
    modulus, exponent, public_key_id = parse_public_evidence(public_key, require_bits=REQUESTED_RSA_BITS)
    check.require(modulus.bit_length() == 2048, "public_key_modulus_bits")
    check.require(public_key["requested_nominal_bits"] == 2048, "requested_nominal_bits")
    check.require(exponent == 65537, "public_key_exponent")
    manifest_envelope = read_json(root / "output-manifest.json")
    manifest = verify_envelope(manifest_envelope, public_key, expected_type="output_manifest")
    check.require(manifest_envelope["signature"]["key_id"] == public_key_id, "manifest_key_id")
    actual_files = [
        {"byte_length": row["byte_length"], "path": row["path"], "sha256": row["sha256"]}
        for row in before
        if row["type"] == "file" and row["path"] != "output-manifest.json"
    ]
    actual_dirs = [row["path"] for row in before if row["type"] == "directory"]
    actual_files.sort(key=lambda row: utf8_path_key(row["path"]))
    actual_dirs.sort(key=utf8_path_key)
    records = manifest["files"]
    check.require(records == actual_files, "output_manifest_exact_file_set")
    check.require(manifest["directories"] == actual_dirs, "output_manifest_exact_directory_set")
    check.require(manifest["file_count"] == len(records), "output_manifest_file_count")
    check.require(manifest["aggregate_sha256"] == aggregate_file_records(records), "output_manifest_aggregate")
    for record in records:
        path = root / record["path"]
        check.require(path.stat().st_size == record["byte_length"], "output_file_length")
        check.require(sha256_file(path) == record["sha256"], "output_file_sha256")
    authorization = read_json(root / "authorization.json")
    authorization_payload = verify_envelope(authorization, public_key, expected_type="authorization")
    check.require(authorization_payload["issuer"]["public_key_id"] == public_key_id, "authorization_key_link")
    check.require(authorization_payload["tool_contract_digest"] == TOOL_CONTRACT_DIGEST, "authorization_tool_contract")
    check.require(authorization_payload["delegation_mode"] == "no_delegation", "authorization_no_delegation")
    check.require(authorization_payload["delegation_chain"] == [], "authorization_empty_delegation_chain")
    for role in ("human_principal", "accountable_owner", "agent_or_workload", "mcp_client"):
        check.require(
            authorization_payload["roles"][role]
            == {"presence": "explicitly_unbound", "reason": "unbound_by_star4"},
            f"role_presence:{role}",
        )
    run_plan = read_json(root / "run-plan.json")
    attempt_inputs = read_json(root / "attempt-inputs.json")
    attempts = attempt_inputs["ordered_attempts"]
    attempt_hashes: dict[str, str] = {}
    for row in attempts:
        raw = base64.b64decode(row["raw_base64"], validate=True)
        check.require(len(raw) == row["raw_byte_length"], "attempt_byte_length")
        check.require(sha256_bytes(raw) == row["raw_sha256"], "attempt_raw_sha256")
        attempt_hashes[row["case_id"]] = row["raw_sha256"]
    check.require(attempt_inputs["attempt_count"] == TOTAL_CASES, "attempt_count")
    plan_equalities = validate_run_plan(run_plan, attempt_hashes=attempt_hashes)
    check.require(
        all(value for key, value in plan_equalities.items() if key != "plan_matrix_set_equal"),
        "run_plan_equalities",
    )
    check.require(plan_equalities["plan_matrix_set_equal"] is False, "matrix_check_not_premature")
    runner_matrix = read_json(root / "runner-matrix.json")
    matrix_envelope = read_json(root / "matrix-evidence.json")
    matrix = verify_envelope(matrix_envelope, public_key, expected_type="matrix")
    matrix_rows = matrix["cases"]
    validate_run_plan(run_plan, attempt_hashes=attempt_hashes, matrix_rows=matrix_rows)
    check.require(matrix["case_count"] == TOTAL_CASES, "signed_matrix_case_count")
    check.require(len(matrix_rows) == TOTAL_CASES, "signed_matrix_cases_length")
    check.require(runner_matrix["case_count"] == TOTAL_CASES, "runner_matrix_case_count")
    check.require(runner_matrix["case_rows"] == matrix_rows, "runner_signed_matrix_equality")
    check.require(runner_matrix["class_subtotals"] == CLASS_SUBTOTALS, "runner_class_subtotals")
    check.require(matrix["class_subtotals"] == CLASS_SUBTOTALS, "signed_class_subtotals")
    check.require(matrix["case_class_map"] == run_plan["case_class_map"], "signed_case_class_map")
    decisions: dict[str, dict[str, Any]] = {}
    refusal_count = 0
    accepted_rows = 0
    for row in matrix_rows:
        case_id = row["case_id"]
        decision_envelope = read_json(root / "decision-receipts" / f"{case_id}.json")
        decision = verify_envelope(decision_envelope, public_key, expected_type="decision")
        decisions[case_id] = decision
        check.require(decision["receipt_id"] == row["decision_receipt_id"], "matrix_decision_link")
        check.require(decision["outcome"] == row["observed_outcome"], "matrix_decision_outcome")
        check.require(decision["reason"] == row["observed_reason"], "matrix_decision_reason")
        check.require(row["attempt_input_sha256"] == attempt_hashes[case_id], "matrix_attempt_link")
        if decision["outcome"] == "refused":
            refusal = verify_envelope(
                read_json(root / "refusal-receipts" / f"{case_id}.json"), public_key, expected_type="refusal"
            )
            check.require(refusal["receipt_id"] == row["refusal_receipt_id"], "matrix_refusal_link")
            check.require(refusal["decision_receipt_id"] == decision["receipt_id"], "refusal_decision_link")
            check.require(row["mutation_delta"] == 0 and row["consumption_delta"] == 0, "refusal_zero_delta")
            refusal_count += 1
        else:
            check.require(case_id == "CROSSING-001-recognized-promotion", "only_recognized_crossing_accepts")
            check.require(row["mutation_delta"] == 1 and row["consumption_delta"] == 1, "accepted_exact_delta")
            accepted_rows += 1
    check.require(refusal_count == 85 and accepted_rows == 1, "matrix_outcome_cardinality")
    effect = verify_envelope(read_json(root / "effect-receipt.json"), public_key, expected_type="effect")
    consumption = verify_envelope(read_json(root / "consumption-receipt.json"), public_key, expected_type="consumption")
    state = read_json(root / "state-final.json")
    crossing = decisions["CROSSING-001-recognized-promotion"]
    check.require(effect["decision_receipt_id"] == crossing["receipt_id"], "effect_decision_link")
    check.require(consumption["decision_receipt_id"] == crossing["receipt_id"], "consumption_decision_link")
    check.require(consumption["effect_receipt_id"] == effect["receipt_id"], "consumption_effect_link")
    check.require(state["effect_receipt_id"] == effect["receipt_id"], "state_effect_link")
    check.require(state["generation"] == INITIAL_GENERATION + 1, "state_generation")
    check.require(state["active_artifact_id"] == "synthetic-artifact.staged.v2", "state_artifact")
    check.require(state["consumed_authorization_nonces"] == [authorization_payload["nonce"]], "state_consumption")
    check.require(len(state["settlement_ledger"]) == 1, "settlement_ledger_count")
    ledger = state["settlement_ledger"][0]
    check.require(ledger["decision_receipt_id"] == crossing["receipt_id"], "ledger_decision_link")
    check.require(ledger["effect_receipt_id"] == effect["receipt_id"], "ledger_effect_link")
    check.require(ledger["consumption_receipt_id"] == consumption["receipt_id"], "ledger_consumption_link")
    derived_mutations = sum(row["mutation_delta"] for row in matrix_rows)
    derived_consumptions = sum(row["consumption_delta"] for row in matrix_rows)
    check.require(derived_mutations == 1, "derived_protected_mutations")
    check.require(derived_consumptions == 1, "derived_recognized_consumptions")
    for counter in (
        "negative_protected_consumptions",
        "negative_protected_mutations",
        "outside_domain_protected_consumptions",
        "outside_domain_protected_mutations",
        "prohibited_protected_consumptions",
        "prohibited_protected_mutations",
        "real_external_protected_consumptions",
        "real_external_protected_mutations",
        "replay_protected_consumptions",
        "replay_protected_mutations",
    ):
        check.require(matrix[counter] == 0, f"zero_counter:{counter}")
    runtime_inventory = read_json(root / "runtime-inventory.json")
    destination_registry = read_json(root / "destination-registry.json")
    noncoverage_baseline = read_json(root / "noncoverage-baseline.json")
    check.require(runtime_inventory["methods"] == ["initialize", "tools/list", "tools/call"], "runtime_methods")
    check.require(runtime_inventory["tool_contract"] == TOOL_CONTRACT, "runtime_tool_contract")
    check.require(len(runtime_inventory["tool_contract"]["tools"]) == 1, "one_tool")
    check.require(runtime_inventory["tool_contract"]["tools"][0]["name"] == ACTION, "one_consequence_tool")
    check.require(destination_registry["declaration_only"] is True, "registry_declaration_only")
    check.require(len(destination_registry["routes"]) == 1, "registry_one_route")
    baseline_pairs = [(row["surface_id"], row["required_disposition"]) for row in noncoverage_baseline["surfaces"]]
    check.require(baseline_pairs == MANDATORY_NONCOVERAGE, "mandatory_noncoverage_exact")
    coverage_saved = read_json(root / "coverage-map.json")
    coverage_regenerated = _regenerate_coverage(
        runtime_inventory, destination_registry, matrix_envelope, noncoverage_baseline
    )
    check.require(_saved_json(coverage_saved) == _saved_json(coverage_regenerated), "coverage_exact_regeneration")
    coverage_receipt = verify_envelope(
        read_json(root / "coverage-envelope.json"), public_key, expected_type="coverage"
    )
    check.require(
        coverage_receipt["coverage_map_raw_sha256"] == sha256_bytes(_saved_json(coverage_regenerated)),
        "coverage_receipt_raw_link",
    )
    rows = coverage_regenerated["rows"]
    check.require(len(rows) == 43 and len({row["surface_id"] for row in rows}) == 43, "coverage_row_mapping")
    allowed_dispositions = {"governed", "open", "unknown", "consequence_incapable"}
    allowed_outcomes = {
        "effect_committed",
        "refused_pre_destination",
        "refused_at_destination",
        "no_effect_observed",
        "not_exercised",
        "not_applicable",
        "indeterminate",
    }
    check.require(all(row["surface_disposition"] in allowed_dispositions for row in rows), "coverage_dispositions")
    check.require(all(row["observed_outcome"] in allowed_outcomes for row in rows), "coverage_outcomes")
    governed = [row for row in rows if row["surface_disposition"] == "governed"]
    check.require(len(governed) == 1 and governed[0]["surface_id"] == "mcp.tool.deployment-promote", "one_governed_surface")
    check.require(
        all(row["surface_disposition"] != "governed" for row in rows if row["surface_id"].startswith("side-door.")),
        "no_refusal_promoted_to_governed",
    )
    inventory_surface_ids = {
        "mcp.method.initialize",
        "mcp.method.tools-list",
        "mcp.tool.deployment-promote",
    }
    check.require(inventory_surface_ids.issubset({row["surface_id"] for row in rows}), "inventory_one_to_one_mapping")
    sessions = read_json(root / "session-observations.json")
    check.require(sessions["child_process_count"] == 1, "child_process_count")
    check.require(len(sessions["observations"]) == 3, "session_observation_count")
    check.require(
        sessions["observations"][1]["response"]["result"]
        == sessions["observations"][2]["response"]["result"],
        "tools_list_response_equality",
    )
    after = _tree_projection(root)
    check.require(before == after, "offline_verifier_zero_write")
    return {
        "actual_public_modulus_bits": modulus.bit_length(),
        "assertions": check.assertions,
        "case_count": len(matrix_rows),
        "class_subtotals": matrix["class_subtotals"],
        "coverage_disposition_counts": coverage_regenerated["disposition_counts"],
        "coverage_observed_outcome_counts": coverage_regenerated["observed_outcome_counts"],
        "coverage_row_count": len(rows),
        "derived_recognized_consumptions": derived_consumptions,
        "derived_recognized_protected_mutations": derived_mutations,
        "requested_nominal_rsa_bits": public_key["requested_nominal_bits"],
        "verdict": "PASS_CANDIDATE_005_OFFLINE_VERIFICATION",
        "writes": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Candidate 005 offline verifier")
    parser.add_argument("--campaign-root", required=True)
    args = parser.parse_args()
    result = verify_campaign(args.campaign_root)
    sys.stdout.buffer.write(_saved_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
