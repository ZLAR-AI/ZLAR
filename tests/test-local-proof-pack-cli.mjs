#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalize } from '../lib/canonicalize.mjs';
import {
  LOCAL_PROOF_PACK_ARTIFACT_TYPE,
  LOCAL_PROOF_PACK_ARTIFACT_VERIFICATION_TYPE,
  LOCAL_PROOF_PACK_TYPE,
  assertLocalProofPackArtifact,
  assertLocalProofPack,
} from '../lib/local-proof-pack.mjs';
import {
  REQUIRED_PROFILE_PREFLIGHT_CASES as PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES,
} from '../lib/protected-records-service-profile.mjs';
import {
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY,
} from '../lib/claude-code-hook-contract-replay-proof.mjs';

let PASS = 0;
let FAIL = 0;
let TOTAL = 0;

function assert(label, condition, detail = '') {
  TOTAL++;
  if (condition) {
    PASS++;
    console.log(`  PASS: ${label}`);
  } else {
    FAIL++;
    console.log(`  FAIL: ${label}${detail ? ` -- ${detail}` : ''}`);
  }
}

function assertEqual(label, expected, actual) {
  assert(label, expected === actual, `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
}

function section(title) {
  console.log(`\n-- ${title} --`);
}

const ZLAR_BIN = join(process.cwd(), 'bin', 'zlar');
const SAMPLE_ARTIFACT_PATH = join(process.cwd(), 'tests', 'fixtures', 'local-proof-pack-artifact-v1.json');
const SAMPLE_ARTIFACT_SHA256 = 'e24adc1735216e20dfb321db473cd58f6ca1b817c93d75e8b83ccf02a9622186';
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;
const scratch = mkdtempSync(join(tmpdir(), 'zlar-local-proof-pack-cli-'));
process.on('exit', () => rmSync(scratch, { recursive: true, force: true }));

function runZlar(args, options = {}) {
  return spawnSync(ZLAR_BIN, args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    input: options.input,
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

function coherentlyResealAttackerChosenArtifact(sourceArtifact) {
  const artifact = structuredClone(sourceArtifact);
  const keyState = artifact.payload.components.find((item) =>
    item.component === 'key_state_report'
  );
  keyState.policy_software_pins_aligned = !keyState.policy_software_pins_aligned;
  artifact.component_manifest = artifact.payload.components.map((item) => {
    const existing = artifact.component_manifest.find((entry) =>
      entry.component === item.component
    );
    return {
      ...existing,
      component_sha256: createHash('sha256')
        .update(canonicalize(item), 'utf8')
        .digest('hex'),
    };
  });
  const { integrity, ...body } = artifact;
  artifact.integrity = {
    ...integrity,
    body_sha256: createHash('sha256')
      .update(canonicalize(body), 'utf8')
      .digest('hex'),
  };
  return artifact;
}

section('text summary command');
const textRun = runZlar(['local-proof-pack']);
assertEqual('text command exits zero', 0, textRun.status);
assertEqual('text command emits no stderr', '', textRun.stderr);
assert('text summary title present', textRun.stdout.includes('ZLAR Local Proof Pack v1'));
assert('text summary includes coverage', textRun.stdout.includes('- coverage: governed='));
assert('text summary includes exact terminal identity', textRun.stdout.includes('- coverage_terminal_identity: body_sha256=') && textRun.stdout.includes('identity_sha256_matched=true; outer_metadata_bound=true; recognized_source_bound=true; signature_valid=true; fixture_rightful_issuance=true'));
assert('text summary includes downstream refusal', textRun.stdout.includes('- downstream_refusal: recognized_boarded=true'));
assert('text summary includes downstream marker boundary', textRun.stdout.includes('recognized_marker_count_delta=1') && textRun.stdout.includes('all_refusal_marker_count_deltas_zero=true'));
assert('text summary includes human authorization', textRun.stdout.includes('- human_authorization: pending_boarded=false; authorized_boarded=true; denied_boarded=false'));
assert('text summary includes approval transport', textRun.stdout.includes('- approval_transport: reference_transport_healthy=true; telegram_required_for_fixture=false'));
assert('text summary includes issuer status', textRun.stdout.includes('- issuer_status: active_boarded=true; retired_refused=true; compromised_refused=true; missing_status_refused=true; unknown_refused=true; missing_key_refused=true'));
assert('text summary includes trusted registry recognition', textRun.stdout.includes('- trusted_issuer_registry_recognition: verdict=RECOGNIZED; registry_type=trusted-receipt-issuers-v2; evidence_model=bundled-local-fixture-no-secret-registry-contract; live_probing=false'));
assert('text summary includes trusted registry nonclaims', textRun.stdout.includes('trusted_issuer_registry_recognition_non_claims: live_trust_registry_state=false; live_issuer_status_proven=false') && textRun.stdout.includes('real_non_operator_review=false') && textRun.stdout.includes('current_machine_governance_proven=false'));
assert('text summary includes key-state report', textRun.stdout.includes('- key_state_report: command=zlar key-state --sample --json; report_type=zlar-key-state-report-v1'));
assert('text summary includes key-state nonclaims', textRun.stdout.includes('private_key_material_read=false') && textRun.stdout.includes('current_machine_governance_proven=false'));
assert('text summary includes receipt verifier boundary', textRun.stdout.includes('- receipt_verifier_boundary: command=zlar-verify <receipt.json> --pubkey <key.pub> --json; valid=VALID/0; unknown_signer=UNKNOWN-SIGNER/3; invalid=INVALID/1'));
assert('text summary includes receipt verifier identity', textRun.stdout.includes('receipt_sha256_present=true; provided_pubkey_sha256_present=true') && textRun.stdout.includes('legacy_v0_required_identity_refused=true'));
assert('text summary includes receipt verifier nonclaims', textRun.stdout.includes('issuer_recognition_proven=false; key_custody_proven=false; revocation_state_proven=false; downstream_recognition_proven=false'));
assert('text summary includes protected records profile', textRun.stdout.includes('- protected_records: profile=protected-records-terminal; action_class=records.write; downstream_boundary=protected-records-terminal-fixture'));
assert('text summary includes protected records adapter profile', textRun.stdout.includes('adapter_profile=protected-records-adapter-profile-v1; adapter_route=receipt-recognition-before-ledger-append'));
assert('text summary includes protected records adapter closure', textRun.stdout.includes('adapter_direct_write_path_available=false; adapter_live_records_adapter=false'));
assert('text summary includes protected records adapter action', textRun.stdout.includes('adapter_action=zlar protected-records-write --input <file|->; adapter_action_result_type=protected-records-write-result-v1'));
assert('text summary includes adapter conformance', textRun.stdout.includes('- protected_records_adapter_conformance: profile=protected-records-cli-process-conformance; action_class=records.write'));
assert('text summary includes adapter conformance replay', textRun.stdout.includes('replay_refused=true; replay_reason=receipt_replay; replay_ledger_delta=0; replay_separate_process=true'));
assert('text summary includes adapter conformance open boundary', textRun.stdout.includes('direct_filesystem_write_to_fixture_paths_closed=false; live_records_adapter=false'));
assert('text summary includes downstream service', textRun.stdout.includes('- protected_records_downstream_service: profile=protected-records-downstream-service-fixture; action_class=records.write'));
assert('text summary includes service preflight run', textRun.stdout.includes('preflight_run_in_proof_pack=true'));
assert('text summary includes service preflight cases', textRun.stdout.includes(`preflight_cases=${PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length}/${PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length}`));
assert('text summary includes service preflight direct api receipt refusal', textRun.stdout.includes('preflight_direct_api_without_receipt_refused=true; preflight_direct_api_with_receipt_refused=true'));
assert('text summary includes service preflight no activation', textRun.stdout.includes('preflight_live_profile_installed=false; preflight_runtime_activation_checked=false'));
assert('text summary includes service replay', textRun.stdout.includes('replay_refused=true; replay_reason=receipt_replay; replay_state_delta=0; replay_separate_process=true'));
assert('text summary includes service invalid refusal', textRun.stdout.includes('invalid_receipt_refused=true; invalid_receipt_state_delta=0'));
assert('text summary includes service unknown issuer refusal', textRun.stdout.includes('unknown_issuer_refused=true; unknown_issuer_state_delta=0'));
assert('text summary includes service stale refusal', textRun.stdout.includes('stale_receipt_refused=true; stale_receipt_state_delta=0'));
assert('text summary includes service direct api refusal', textRun.stdout.includes('direct_api_without_receipt_refused=true; direct_api_state_delta=0; direct_api_attempted=true'));
assert('text summary includes service open boundary', textRun.stdout.includes('direct_filesystem_write_to_fixture_paths_closed=false; live_records_service=false'));
assert('text summary includes runtime preflight identity', textRun.stdout.includes('- protected_records_runtime_profile_preflight_identity: profile=protected-records-runtime-fixture-profile'));
assert('text summary includes runtime preflight not run', textRun.stdout.includes('preflight_run_in_proof_pack=false; proof_run_in_proof_pack=false'));
assert('text summary includes runtime preflight grant witness', textRun.stdout.includes('consumed_authority_grant_store=persistent-single-use-authority-grant-contract-sha256-store') && textRun.stdout.includes('consumed_store_witness=launcher-owned-local-store-hash-witness; joint_rollback_detection=false'));
assert('text summary includes runtime activation preflight', textRun.stdout.includes('- protected_records_runtime_activation_preflight: plan=protected-records-runtime-fixture-activation-plan'));
assert('text summary includes runtime activation sha match', textRun.stdout.includes('sha_matches_plan=true'));
assert('text summary includes runtime activation run', textRun.stdout.includes('activation_preflight_run_in_proof_pack=true; runtime_profile_proof_run_in_proof_pack=true'));
assert('text summary includes runtime activation nested proof counts', textRun.stdout.includes('runtime_profile_cases=39/39'));
assert('text summary includes runtime activation proof refusals', textRun.stdout.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true') && textRun.stdout.includes('missing_grant_refused=true; mismatched_grant_refused=true; revoked_grant_refused=true; expired_grant_refused=true; request_grant_refused=true'));
assert('text summary includes runtime activation identity policy', textRun.stdout.includes('protected_records_runtime_activation_preflight_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('text summary includes runtime activation witness limits', textRun.stdout.includes('witness_commit_failure_refused=true; joint_rollback_refused=true; joint_rollback_detection=false; joint_rollback_reopens_grant_reuse=true'));
assert('text summary includes runtime activation no install', textRun.stdout.includes('persistent_runtime_profile_installed=false'));
assert('text summary includes runtime activation burn window', textRun.stdout.includes('partial_grant_commit_burn_window_named=true'));
assert('text summary includes runtime activation claim boundary', textRun.stdout.includes('fixture_rightful_issuance=true; rightful_issuance=false; consequence_lifecycle_closed=false'));
assert('text summary includes runtime local activation', textRun.stdout.includes('- protected_records_runtime_local_activation: plan=protected-records-runtime-local-activation-fixture-plan'));
assert('text summary includes runtime local activation active profile selection', textRun.stdout.includes('active_profile_selected=true; local_activation_run_in_proof_pack=true'));
assert('text summary includes runtime local activation route', textRun.stdout.includes('route=receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation'));
assert('text summary includes runtime local activation grant refusals', textRun.stdout.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true') && textRun.stdout.includes('missing_grant_refused=true; mismatched_grant_refused=true; revoked_grant_refused=true; expired_grant_refused=true; request_grant_refused=true'));
assert('text summary includes runtime local activation identity policy', textRun.stdout.includes('protected_records_runtime_local_activation_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('text summary includes runtime local activation applied', textRun.stdout.includes('local_activation_applied=true; persistent_runtime_profile_installed=false'));
assert('text summary includes runtime local activation witness limits', textRun.stdout.includes('witness_commit_failure_refused=true; joint_rollback_refused=true; joint_rollback_detection=false; joint_rollback_reopens_grant_reuse=true'));
assert('text summary includes runtime local activation claim boundary', textRun.stdout.includes('fixture_rightful_issuance=true; rightful_issuance=false; portable_rightful_issuance=false; live_authority=false; production_rightful_issuance=false; current_machine_governance=false; consequence_lifecycle_closed=false'));
assert('text summary includes runtime profile installation', textRun.stdout.includes('- protected_records_runtime_profile_installation: plan=protected-records-runtime-profile-installation-fixture-plan'));
assert('text summary includes runtime profile installation selection', textRun.stdout.includes('disposable_root_created=true; selected_from_install_root=true'));
assert('text summary includes runtime profile installation guard', textRun.stdout.includes('request_guard_refused=true'));
assert('text summary includes runtime profile installation grant refusals', textRun.stdout.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true') && textRun.stdout.includes('missing_grant_refused=true; mismatched_grant_refused=true; revoked_grant_refused=true; expired_grant_refused=true; request_grant_refused=true'));
assert('text summary includes runtime profile installation identity policy', textRun.stdout.includes('protected_records_runtime_profile_installation_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('text summary includes runtime profile installation nonclaims', textRun.stdout.includes('fixture_rightful_issuance=true; rightful_issuance=false; portable_rightful_issuance=false; live_authority=false; production_rightful_issuance=false; current_machine_governance=false; consequence_lifecycle_closed=false'));
assert(
  'text summary includes Claude hook replay',
  textRun.stdout.includes('- claude_code_hook_contract_replay: command=zlar claude-code-hook-contract-replay-proof; evidence_model=local-fixture-hook-contract-replay') &&
    textRun.stdout.includes('adapter_source=repo')
);
assert('text summary includes Claude hook replay cases', textRun.stdout.includes('allow_json=true; deny_json=true; denied_effect_not_executed=true; tool_input_not_executed=true'));
assert('text summary includes Claude hook replay contract hash', textRun.stdout.includes('contract_sha256='));
assert('text summary includes Claude hook replay source boundary', textRun.stdout.includes(`source_state_boundary=${CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY}`));
assert('text summary includes Claude hook replay fail closed', textRun.stdout.includes('missing_gate_failed_closed=true; blank_gate_response_failed_closed=true; malformed_output_refused=true; non_pretooluse_payload_denied_by_fixture_gate=true'));
assert('text summary includes Claude hook replay nonclaims', textRun.stdout.includes('live_claude_invoked=false; live_claude_app_passage_proven=false; app_originated_hook_crossing_proven=false') && textRun.stdout.includes('current_machine_governance_proven=false') && textRun.stdout.includes('side_door_closure_proven=false'));
assert('text summary includes protected records contract route', textRun.stdout.includes('contract_route=receipt-recognition-before-record-write'));
assert('text summary includes protected records replay policy', textRun.stdout.includes('replay_policy=single-use-receipt-id-per-terminal-ledger'));
assert('text summary includes protected records receipt fields', textRun.stdout.includes('required_receipt_fields=v,id,kid'));
assert('text summary includes protected records refusal count', textRun.stdout.includes('refused_write_count=11; refusal_record_delta_total=0'));
assert('text summary includes protected records ungoverned boundaries', textRun.stdout.includes('ungoverned_boundaries=live_records_system,production_records_adapter,unrouted_records_paths'));
assert('text summary states non-claims', textRun.stdout.includes('does not prove production deployment'));
assert('text summary states Telegram non-claim', textRun.stdout.includes('does not use Telegram'));
assert('text summary is privacy safe', !unsafeOutputPattern.test(textRun.stdout));

section('json command');
const jsonRun = runZlar(['local-proof-pack', '--json']);
assertEqual('json command exits zero', 0, jsonRun.status);
assertEqual('json command emits no stderr', '', jsonRun.stderr);
assert('json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report passes proof-pack validation', assertLocalProofPack(report));
assertEqual('json proof pack type', LOCAL_PROOF_PACK_TYPE, report.proof_pack_type);
assertEqual('json live probing false', false, report.live_probing);
assertEqual('json component count', 16, report.components.length);
assert('json includes coverage command', jsonRun.stdout.includes('zlar coverage --input'));
assert('json includes human authorization command', jsonRun.stdout.includes('zlar human-authorization-proof'));
assert('json includes approval transport command', jsonRun.stdout.includes('zlar approval-transport-proof'));
assert('json includes issuer status command', jsonRun.stdout.includes('zlar issuer-status-proof'));
assert('json includes trusted registry component', jsonRun.stdout.includes('"component": "trusted_issuer_registry_recognition"'));
assert('json includes trusted registry verdict', jsonRun.stdout.includes('"verdict": "RECOGNIZED"'));
assert('json includes trusted registry nonclaim', jsonRun.stdout.includes('"live_trust_registry_state": false'));
assert('json includes key-state component', jsonRun.stdout.includes('"component": "key_state_report"'));
assert('json includes key-state command', jsonRun.stdout.includes('"command": "zlar key-state --sample --json"'));
assert('json includes key-state nonclaim', jsonRun.stdout.includes('"key_custody_proven": false'));
assert('json includes Claude hook replay source boundary', jsonRun.stdout.includes(`"source_state_boundary": "${CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY}"`));
assert('json includes receipt verifier component', jsonRun.stdout.includes('"component": "receipt_verifier_boundary"'));
assert('json includes receipt verifier command', jsonRun.stdout.includes('"command": "zlar-verify <receipt.json> --pubkey <key.pub> --json"'));
assert('json includes receipt verifier valid verdict', jsonRun.stdout.includes('"valid_verdict": "VALID"'));
assert('json includes receipt verifier unknown signer verdict', jsonRun.stdout.includes('"unknown_signer_verdict": "UNKNOWN-SIGNER"'));
assert('json includes receipt verifier invalid verdict', jsonRun.stdout.includes('"invalid_verdict": "INVALID"'));
assert('json includes receipt verifier nonclaim', jsonRun.stdout.includes('"issuer_recognition_proven": false'));
assert('json includes protected records profile', jsonRun.stdout.includes('"deployment_profile": "protected-records-terminal"'));
assert('json includes protected records action class', jsonRun.stdout.includes('"action_class": "records.write"'));
assert('json includes protected records adapter profile', jsonRun.stdout.includes('"adapter_profile_type": "protected-records-adapter-profile-v1"'));
assert('json includes protected records adapter route', jsonRun.stdout.includes('"adapter_authoritative_route": "receipt-recognition-before-ledger-append"'));
assert('json includes protected records adapter direct write closure', jsonRun.stdout.includes('"adapter_direct_write_path_available": false'));
assert('json includes protected records live adapter non-claim', jsonRun.stdout.includes('"adapter_live_records_adapter": false'));
assert('json includes protected records adapter action command', jsonRun.stdout.includes('"adapter_action_command": "zlar protected-records-write --input <file|->"'));
assert('json includes protected records adapter action result type', jsonRun.stdout.includes('"adapter_action_result_type": "protected-records-write-result-v1"'));
assert('json includes protected records adapter action fixture mode', jsonRun.stdout.includes('"adapter_action_fixture_mode_required": true'));
assert('json includes protected records adapter conformance command', jsonRun.stdout.includes('"command": "zlar protected-records-adapter-conformance"'));
assert('json includes protected records adapter conformance profile', jsonRun.stdout.includes('"profile_id": "protected-records-cli-process-conformance"'));
assert('json includes protected records adapter conformance process boundary', jsonRun.stdout.includes('"adapter_process_boundary": "separate-cli-process"'));
assert('json includes protected records adapter conformance replay refusal', jsonRun.stdout.includes('"replay_reason": "receipt_replay"'));
assert('json includes protected records adapter conformance filesystem non-closure', jsonRun.stdout.includes('"direct_filesystem_write_to_fixture_paths_closed": false'));
assert('json includes protected records downstream service command', jsonRun.stdout.includes('"command": "zlar protected-records-service-proof"'));
assert('json includes protected records downstream service profile', jsonRun.stdout.includes('"profile_id": "protected-records-downstream-service-fixture"'));
assert('json includes protected records service preflight profile', jsonRun.stdout.includes('"service_profile_preflight_profile_id": "protected-records-service-fixture-profile"'));
assert('json includes protected records service preflight status', jsonRun.stdout.includes('"service_profile_preflight_profile_status": "sample_not_active"'));
assert('json includes protected records service preflight run', jsonRun.stdout.includes('"service_profile_preflight_run_in_proof_pack": true'));
assert('json includes protected records service preflight type', jsonRun.stdout.includes('"service_profile_preflight_type": "zlar-protected-records-service-profile-preflight-v1"'));
assert('json includes protected records service preflight case count', jsonRun.stdout.includes(`"service_profile_preflight_case_count": ${PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length}`));
assert('json includes protected records service preflight direct api receipt-present case', jsonRun.stdout.includes('"direct_api_profile_receipt_present_refused_before_service_mutation"'));
assert('json includes protected records service preflight direct api receipt refusal', jsonRun.stdout.includes('"service_profile_preflight_direct_api_with_receipt_refused": true'));
assert('json includes protected records service preflight no runtime activation', jsonRun.stdout.includes('"service_profile_preflight_runtime_profile_activation_checked": false'));
assert('json includes protected records service preflight no external attestation', jsonRun.stdout.includes('"service_profile_preflight_external_attestation": false'));
assert('json includes protected records downstream service process boundary', jsonRun.stdout.includes('"service_process_boundary": "separate-cli-process"'));
assert('json includes protected records downstream service direct api refusal', jsonRun.stdout.includes('"direct_api_without_receipt_refused": true'));
assert('json includes protected records downstream service filesystem non-closure', jsonRun.stdout.includes('"direct_filesystem_write_to_fixture_paths_closed": false'));
assert('json includes runtime profile preflight identity component', jsonRun.stdout.includes('"component": "protected_records_runtime_profile_preflight_identity"'));
assert('json includes runtime profile preflight command', jsonRun.stdout.includes('"preflight_command": "zlar protected-records-runtime-profile-preflight --profile profiles/protected-records-runtime-fixture.profile.json"'));
assert('json includes runtime preflight not run', jsonRun.stdout.includes('"runtime_profile_preflight_run_in_proof_pack": false'));
assert('json includes runtime proof not run', jsonRun.stdout.includes('"runtime_profile_proof_run_in_proof_pack": false'));
assert('json includes runtime preflight anchor', jsonRun.stdout.includes('"consumed_store_anchor": "launcher-owned-local-store-hash-anchor"'));
assert('json includes runtime preflight witness', jsonRun.stdout.includes('"consumed_store_witness": "launcher-owned-local-store-hash-witness"'));
assert('json includes runtime preflight joint rollback non-claim', jsonRun.stdout.includes('"store_anchor_and_witness_joint_rollback_detection": false'));
assert('json includes runtime activation preflight component', jsonRun.stdout.includes('"component": "protected_records_runtime_activation_preflight"'));
assert('json includes runtime activation preflight command', jsonRun.stdout.includes('"preflight_command": "zlar protected-records-runtime-activation-preflight --plan profiles/protected-records-runtime-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json"'));
assert('json includes runtime activation profile sha match', jsonRun.stdout.includes('"runtime_profile_sha_matches_plan": true'));
assert('json includes runtime activation preflight run', jsonRun.stdout.includes('"runtime_activation_preflight_run_in_proof_pack": true'));
assert('json includes runtime activation runtime preflight run', jsonRun.stdout.includes('"runtime_profile_preflight_run_in_proof_pack": true'));
assert('json includes runtime activation runtime proof run', jsonRun.stdout.includes('"runtime_profile_proof_run_in_proof_pack": true'));
assert('json includes runtime activation runtime proof count', jsonRun.stdout.includes('"runtime_profile_proof_case_count": 39'));
assert('json includes runtime activation runtime boundary count', jsonRun.stdout.includes('"runtime_profile_boundary_observation_count": 2'));
assert('json includes runtime activation grant rollback refusal', jsonRun.stdout.includes('"consumed_authority_grant_store_rollback_refused": true'));
assert('json includes runtime activation replay split', jsonRun.stdout.includes('"same_process_signed_payload_replay_refused": true') && jsonRun.stdout.includes('"restart_consumed_authority_grant_refused": true'));
assert('json includes runtime activation grant refusals', jsonRun.stdout.includes('"missing_authority_grant_appointment_refused": true') && jsonRun.stdout.includes('"mismatched_authority_grant_appointment_refused": true') && jsonRun.stdout.includes('"revoked_authority_grant_refused": true') && jsonRun.stdout.includes('"expired_authority_grant_refused": true'));
assert('json includes runtime activation fixture rightful issuance only', jsonRun.stdout.includes('"fixture_rightful_issuance_path_evidenced": true') && jsonRun.stdout.includes('"rightful_issuance_proven": false') && jsonRun.stdout.includes('"consequence_lifecycle_closed": false'));
assert('json includes runtime activation authority material refusal', jsonRun.stdout.includes('"agent_supplied_authority_material_refused": true'));
assert('json includes runtime activation identity policy', jsonRun.stdout.includes('"runtime_profile_identity_authority_source": "launcher-owned-service-config"') && jsonRun.stdout.includes('"omitted_runtime_profile_id_uses_launcher_config": true'));
assert('json includes runtime activation no activation applied', jsonRun.stdout.includes('"activation_applied": false'));
assert('json includes runtime activation no runtime config write', jsonRun.stdout.includes('"writes_runtime_config": false'));
assert('json includes runtime activation no hook config write', jsonRun.stdout.includes('"writes_hook_configuration": false'));
assert('json includes runtime activation no persistent profile install', jsonRun.stdout.includes('"persistent_runtime_profile_installed": false'));
assert('json includes runtime activation explicit install', jsonRun.stdout.includes('"requires_explicit_human_install": true'));
assert('json includes runtime activation no latest selection', jsonRun.stdout.includes('"selects_latest_profile": false'));
assert('json includes runtime activation external attestation false', jsonRun.stdout.includes('"external_attestation": false'));
assert('json includes runtime local activation component', jsonRun.stdout.includes('"component": "protected_records_runtime_local_activation"'));
assert('json includes runtime local activation command', jsonRun.stdout.includes('"local_activation_command": "zlar protected-records-runtime-local-activation --plan profiles/protected-records-runtime-local-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json"'));
assert('json includes runtime local activation active profile selection', jsonRun.stdout.includes('"active_profile_selection"'));
assert('json includes runtime local activation active profile selected', jsonRun.stdout.includes('"selected": true'));
assert('json includes runtime local activation active profile scope', jsonRun.stdout.includes('"selection_scope": "local-disposable-proof-harness"'));
assert('json includes runtime local activation active profile status', jsonRun.stdout.includes('"profile_status_before_selection": "sample_not_active"'));
assert('json includes runtime local activation active profile no latest', jsonRun.stdout.includes('"selects_latest_profile": false'));
assert('json includes runtime local activation active profile no live check', jsonRun.stdout.includes('"live_runtime_profile_checked": false'));
assert('json includes runtime local activation run', jsonRun.stdout.includes('"runtime_local_activation_run_in_proof_pack": true'));
assert('json includes runtime local activation applied', jsonRun.stdout.includes('"local_activation_applied": true'));
assert('json includes runtime local activation disposable config', jsonRun.stdout.includes('"disposable_runtime_config_written": true'));
assert('json includes runtime local activation no persistent config', jsonRun.stdout.includes('"persistent_runtime_config_written": false'));
assert('json includes runtime local activation no hook config', jsonRun.stdout.includes('"hook_configuration_written": false'));
assert('json includes runtime local activation service started', jsonRun.stdout.includes('"runtime_service_started": true'));
assert('json includes runtime local activation identity policy', jsonRun.stdout.includes('"runtime_profile_identity_request_stream_policy": "runtime_profile_id_may_be_omitted_but_if_supplied_must_match_config"') && jsonRun.stdout.includes('"supplied_mismatched_runtime_profile_id_refused": true'));
assert('json includes runtime local activation no production service', jsonRun.stdout.includes('"production_records_service_checked": false'));
assert('json includes runtime profile installation component', jsonRun.stdout.includes('"component": "protected_records_runtime_profile_installation"'));
assert('json includes runtime profile installation command', jsonRun.stdout.includes('"installation_command": "zlar protected-records-runtime-profile-installation --plan profiles/protected-records-runtime-profile-installation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json"'));
assert('json includes runtime profile installation selection', jsonRun.stdout.includes('"disposable_profile_selection"'));
assert('json includes runtime profile installation selected from root', jsonRun.stdout.includes('"profile_selected_from_install_root": true'));
assert('json includes runtime profile installation no latest', jsonRun.stdout.includes('"selects_latest_profile": false'));
assert('json includes runtime profile installation guard', jsonRun.stdout.includes('"request_authority_guard_summary"'));
assert('json includes runtime profile installation runtime config refused', jsonRun.stdout.includes('"runtime_config_refused": true'));
assert('json includes runtime profile installation identity policy', jsonRun.stdout.includes('"request_runtime_profile_id_required": false') && jsonRun.stdout.includes('"omitted_request_runtime_profile_id_present": false'));
assert('json includes runtime profile installation no hook config', jsonRun.stdout.includes('"hook_configuration_written": false'));
assert('json includes Claude hook replay component', jsonRun.stdout.includes('"component": "claude_code_hook_contract_replay"'));
assert('json includes Claude hook replay command', jsonRun.stdout.includes('"command": "zlar claude-code-hook-contract-replay-proof"'));
assert('json includes Claude hook replay evidence model', jsonRun.stdout.includes('"evidence_model": "local-fixture-hook-contract-replay"'));
assert('json includes Claude hook replay decisions', jsonRun.stdout.includes('"permission_decisions_observed"') && jsonRun.stdout.includes('"allow": true') && jsonRun.stdout.includes('"deny": true'));
assert('json includes Claude hook replay contract hash', jsonRun.stdout.includes('"hook_replay_contract_sha256":'));
assert('json includes Claude hook replay fail closed', jsonRun.stdout.includes('"missing_gate_failed_closed": true') && jsonRun.stdout.includes('"non_pretooluse_payload_denied_by_fixture_gate": true'));
assert('json includes Claude hook replay no live claim', jsonRun.stdout.includes('"live_claude_app_passage_proven": false') && jsonRun.stdout.includes('"app_originated_hook_crossing_proven": false') && jsonRun.stdout.includes('"current_machine_governance_proven": false'));
assert('json includes protected records contract route', jsonRun.stdout.includes('"profile_contract_route": "receipt-recognition-before-record-write"'));
assert('json includes protected records replay policy', jsonRun.stdout.includes('"receipt_replay_policy": "single-use-receipt-id-per-terminal-ledger"'));
assert('json includes protected records replay refusal', jsonRun.stdout.includes('"receipt_replay"'));
assert('json includes protected records required receipt field', jsonRun.stdout.includes('"payload.detail_hash"'));
assert('json includes protected records ungoverned boundary', jsonRun.stdout.includes('"unrouted_records_paths"'));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonRun.stdout));

section('artifact command');
const artifactPath = join(scratch, 'local-proof-pack-artifact.json');
const artifactRun = runZlar(['local-proof-pack', '--artifact', artifactPath]);
assertEqual('artifact command exits zero', 0, artifactRun.status);
assertEqual('artifact command emits no stderr', '', artifactRun.stderr);
assert('artifact command keeps text summary', artifactRun.stdout.includes('ZLAR Local Proof Pack v1'));
assert('artifact command prints artifact checksum', artifactRun.stdout.includes('Portable artifact:'));
assert('artifact command output is privacy safe', !unsafeOutputPattern.test(artifactRun.stdout));
const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
assert('artifact file passes validation', assertLocalProofPackArtifact(artifact));
assertEqual('artifact file type', LOCAL_PROOF_PACK_ARTIFACT_TYPE, artifact.artifact_type);
assert('artifact file has sha256', /^[a-f0-9]{64}$/.test(artifact.integrity.body_sha256));
assertEqual('artifact file has component manifest', 16, artifact.component_manifest.length);
assertEqual('artifact file has claim binding count', 11, artifact.claim_binding.non_claim_count);

const artifactStdoutRun = runZlar(['local-proof-pack', '--artifact', '-']);
assertEqual('artifact stdout command exits zero', 0, artifactStdoutRun.status);
assertEqual('artifact stdout command emits no stderr', '', artifactStdoutRun.stderr);
assert('artifact stdout output is privacy safe', !unsafeOutputPattern.test(artifactStdoutRun.stdout));
const stdoutArtifact = JSON.parse(artifactStdoutRun.stdout);
assert('artifact stdout passes validation', assertLocalProofPackArtifact(stdoutArtifact));
assertEqual('artifact stdout type', LOCAL_PROOF_PACK_ARTIFACT_TYPE, stdoutArtifact.artifact_type);

section('artifact verify command');
const verifyRun = runZlar(['local-proof-pack', 'verify', '--input', artifactPath]);
assertEqual('verify command exits zero', 0, verifyRun.status);
assertEqual('verify command emits no stderr', '', verifyRun.stderr);
assert('verify summary names command', verifyRun.stdout.includes('ZLAR Local Proof Pack Artifact Verification v1'));
assert('verify summary says verified', verifyRun.stdout.includes('verified=true'));
assert('verify summary includes artifact sha', verifyRun.stdout.includes(artifact.integrity.body_sha256));
assert('verify summary includes component manifest', verifyRun.stdout.includes('component_manifest_hash_scope=canonical payload components in artifact order') && verifyRun.stdout.includes('claude_code_hook_contract_replay:'));
assert('verify summary includes claim binding', verifyRun.stdout.includes('claim_binding: non_claim_count=11; safe_claim_ceiling_sha256='));
assert('verify summary states artifact-only boundary', verifyRun.stdout.includes('artifact_verification_model=self-contained-artifact-integrity-and-embedded-boundary-validation') && verifyRun.stdout.includes('fresh_proof_pack_run_performed=false; source_freshness_proven=false'));
assert('verify summary states structural-only identity posture', verifyRun.stdout.includes('expected_sha256_supplied=false; identity_sha256_matched=false') && verifyRun.stdout.includes('verification_scope=structural-local-proof-pack-artifact-self-integrity-and-schema-only'));
assert('verify summary withholds exact-terminal positive projection', verifyRun.stdout.includes('terminal_claim_projection_allowed=false') && verifyRun.stdout.includes('identity_sha256_matched=false; outer_metadata_bound=false; recognized_source_bound=false; signature_valid=false; fixture_rightful_issuance=false'));
assert('verify summary includes key-state run', verifyRun.stdout.includes('key_state_report_run_in_proof_pack=true'));
assert('verify summary includes key-state privacy', verifyRun.stdout.includes('private_key_material_read=false') && verifyRun.stdout.includes('legacy_software_signing_key_present=false'));
assert('verify summary includes key-state nonclaims', verifyRun.stdout.includes('current_machine_governance_proven=false') && verifyRun.stdout.includes('production_trust_registry_proven=false'));
assert('verify summary includes receipt verifier run', verifyRun.stdout.includes('receipt_verifier_boundary_run_in_proof_pack=true'));
assert('verify summary includes receipt verifier verdicts', verifyRun.stdout.includes('receipt_verifier_boundary_verdicts: valid=VALID/0; unknown_signer=UNKNOWN-SIGNER/3; invalid=INVALID/1; distinguishes_unknown_signer_from_invalid=true'));
assert('verify summary includes receipt verifier nonclaims', verifyRun.stdout.includes('issuer_recognition_proven=false; key_custody_proven=false; revocation_state_proven=false; downstream_recognition_proven=false'));
assert('verify summary includes trusted registry run', verifyRun.stdout.includes('trusted_issuer_registry_recognition_run_in_proof_pack=true'));
assert('verify summary includes trusted registry facts', verifyRun.stdout.includes('trusted_issuer_registry_recognition_summary: verdict=RECOGNIZED') && verifyRun.stdout.includes('malformed_registry_fail_closed_before_verdict=true'));
assert('verify summary includes trusted registry nonclaims', verifyRun.stdout.includes('trusted_issuer_registry_recognition_non_claims: live_trust_registry_state=false; live_issuer_status_proven=false') && verifyRun.stdout.includes('production_authority=false') && verifyRun.stdout.includes('real_non_operator_review=false') && verifyRun.stdout.includes('current_machine_governance_proven=false'));
assert('verify summary includes human authorization run', verifyRun.stdout.includes('human_authorization_run_in_proof_pack=true'));
assert('verify summary includes human authorization boarding', verifyRun.stdout.includes('human_authorization_summary: proof_type=human-authorization-proof-v1; evidence_model=local-hermetic-fixture; live_probing=false; approval_channel=simulated-human-fixture; pending_boarded=false; authorized_boarded=true; denied_boarded=false'));
assert('verify summary includes service preflight run', verifyRun.stdout.includes('service_profile_preflight_run_in_proof_pack=true'));
assert('verify summary includes service preflight cases', verifyRun.stdout.includes(`service_profile_preflight_cases=${PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length}/${PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length}`));
assert('verify summary includes request stream authority reason', verifyRun.stdout.includes('service_profile_preflight_request_stream_authority: launcher_owned_config_required=true; authority_material_allowed=false; authority_material_refused=true; reason=request_stream_authority_material; state_delta=0'));
assert('verify summary includes direct api receipt-present reason', verifyRun.stdout.includes('service_profile_preflight_direct_api_receipt_present: reason=request_stream_forbidden_fields; state_delta=0; direct_api_attempted=true'));
assert('verify summary includes service preflight no live records check', verifyRun.stdout.includes('live_records_system_checked=false'));
assert('verify summary includes runtime local activation run', verifyRun.stdout.includes('runtime_local_activation_run_in_proof_pack=true'));
assert('verify summary includes runtime local activation active profile selection', verifyRun.stdout.includes('runtime_local_activation_active_profile_selection: selected=true; scope=local-disposable-proof-harness; profile=protected-records-disposable-runtime-profile'));
assert('verify summary includes runtime local activation active profile nonclaims', verifyRun.stdout.includes('live_runtime_profile_checked=false; selects_latest_profile=false'));
assert('verify summary includes runtime local activation identity policy', verifyRun.stdout.includes('runtime_local_activation_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('verify summary includes runtime local activation applied', verifyRun.stdout.includes('local_activation_applied=true; disposable_runtime_config_written=true; persistent_runtime_config_written=false'));
assert('verify summary includes runtime local activation authority', verifyRun.stdout.includes('runtime_local_activation_authority: route=receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation') && verifyRun.stdout.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true') && verifyRun.stdout.includes('missing_grant_refused=true; mismatched_grant_refused=true; revoked_grant_refused=true; expired_grant_refused=true; request_grant_refused=true'));
assert('verify summary includes runtime profile installation run', verifyRun.stdout.includes('runtime_profile_installation_run_in_proof_pack=true'));
assert('verify summary includes runtime profile installation selection', verifyRun.stdout.includes('selected_from_install_root=true; selected_by_id_and_sha=true; selects_latest_profile=false'));
assert('verify summary includes runtime profile installation guard', verifyRun.stdout.includes('runtime_config_refused=true; runtime_profile_refused=true; recognition_rule_refused=true; authority_grant_refused=true; all_refused_before_mutation=true'));
assert('verify summary includes runtime profile installation identity policy', verifyRun.stdout.includes('runtime_profile_installation_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('verify summary includes runtime profile installation authority', verifyRun.stdout.includes('runtime_profile_installation_authority: route=receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation') && verifyRun.stdout.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true') && verifyRun.stdout.includes('missing_grant_refused=true; mismatched_grant_refused=true; revoked_grant_refused=true; expired_grant_refused=true; request_grant_refused=true'));
assert('verify summary withholds runtime profile installation fixture rightful projection', verifyRun.stdout.includes('runtime_profile_installation_non_claims: fixture_rightful_issuance=false; rightful_issuance=false') && verifyRun.stdout.includes('current_machine_governance=false; consequence_lifecycle_closed=false'));
assert('verify summary includes Claude hook replay run', verifyRun.stdout.includes('claude_hook_contract_replay_run_in_proof_pack=true'));
assert('verify summary includes Claude hook replay cases', verifyRun.stdout.includes('claude_hook_contract_replay_summary: proof_type=zlar-claude-code-hook-contract-replay-proof-v1; evidence_model=local-fixture-hook-contract-replay; live_probing=false') && verifyRun.stdout.includes('allow_json=true; deny_json=true'));
assert('verify summary includes Claude hook replay nonclaims', verifyRun.stdout.includes('claude_hook_contract_replay_non_claims: live_claude_invoked=false; live_claude_app_passage_proven=false; app_originated_hook_crossing_proven=false') && verifyRun.stdout.includes('current_machine_governance_proven=false') && verifyRun.stdout.includes('side_door_closure_proven=false'));
assert('verify summary is privacy safe', !unsafeOutputPattern.test(verifyRun.stdout));

const verifyRequiredShaRun = runZlar(['local-proof-pack', 'verify', '--input', artifactPath, '--require-sha', artifact.integrity.body_sha256]);
assertEqual('verify required sha command exits zero', 0, verifyRequiredShaRun.status);
assertEqual('verify required sha command emits no stderr', '', verifyRequiredShaRun.stderr);
assert('verify required sha says verified', verifyRequiredShaRun.stdout.includes('verified=true'));
assert('verify required sha includes artifact sha', verifyRequiredShaRun.stdout.includes(artifact.integrity.body_sha256));
assert('verify required sha reports required artifact sha', verifyRequiredShaRun.stdout.includes(`required_body_sha256=${artifact.integrity.body_sha256}`));
assert('verify required sha reports required artifact sha matched', verifyRequiredShaRun.stdout.includes('required_body_sha256_matched=true'));
assert('verify required sha permits exact-terminal positive projection', verifyRequiredShaRun.stdout.includes('terminal_claim_projection_allowed=true') && verifyRequiredShaRun.stdout.includes('identity_sha256_matched=true; outer_metadata_bound=true; recognized_source_bound=true; signature_valid=true; fixture_rightful_issuance=true'));
assert('verify required sha is privacy safe', !unsafeOutputPattern.test(verifyRequiredShaRun.stdout));

const verifyJsonRun = runZlar(['local-proof-pack', 'verify', '--input', artifactPath, '--json']);
assertEqual('verify json command exits zero', 0, verifyJsonRun.status);
assertEqual('verify json command emits no stderr', '', verifyJsonRun.stderr);
assert('verify json output is privacy safe', !unsafeOutputPattern.test(verifyJsonRun.stdout));
const verification = JSON.parse(verifyJsonRun.stdout);
assertEqual('verify json type', LOCAL_PROOF_PACK_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
assertEqual('verify json verified true', true, verification.verified);
assertEqual('verify json structural self-integrity true', true, verification.structural_self_integrity_verified);
assertEqual('verify json expected SHA not supplied', false, verification.artifact_identity_expected_sha256_supplied);
assertEqual('verify json identity not matched', false, verification.artifact_identity_sha256_matched);
assertEqual('verify json required SHA absent', null, verification.required_body_sha256);
assertEqual('verify json terminal projection withheld', false, verification.coverage.terminal_claim_projection_allowed);
assertEqual('verify json terminal identity withheld', false, verification.coverage.terminal_artifact_identity_sha256_matched);
assertEqual('verify json terminal source withheld', false, verification.coverage.terminal_recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256);
assertEqual('verify json terminal signature withheld', false, verification.coverage.terminal_trusted_issuer_registry_signature_valid);
assertEqual('verify json terminal fixture rightful path withheld', false, verification.coverage.terminal_fixture_rightful_issuance_path_evidenced);
assertEqual('verify json artifact-only model', 'self-contained-artifact-integrity-and-embedded-boundary-validation', verification.artifact_verification_model);
assertEqual('verify json sha matches artifact', artifact.integrity.body_sha256, verification.body_sha256);
assertEqual('verify json live probing false', false, verification.live_probing);
assertEqual('verify json no fresh run', false, verification.fresh_proof_pack_run_performed);
assertEqual('verify json no source freshness', false, verification.source_freshness_proven);
assertEqual('verify json component manifest count', 16, verification.component_manifest.length);
assertEqual('verify json component manifest hook identity', 'proof_type', verification.component_manifest.find((item) => item.component === 'claude_code_hook_contract_replay').identity_type);
assertEqual('verify json claim binding count', 11, verification.claim_binding.non_claim_count);
assertEqual('verify json key-state summary type', 'zlar-local-proof-pack-key-state-verification-summary-v1', verification.key_state_report.summary_type);
assertEqual('verify json key-state run', true, verification.key_state_report.run_in_proof_pack);
assertEqual('verify json key-state private key material read false', false, verification.key_state_report.private_key_material_read);
assertEqual('verify json key-state no key custody', false, verification.key_state_report.key_custody_proven);
assertEqual('verify json key-state no current-machine governance', false, verification.key_state_report.current_machine_governance_proven);
assertEqual('verify json receipt verifier summary type', 'zlar-local-proof-pack-receipt-verifier-boundary-verification-summary-v1', verification.receipt_verifier_boundary.summary_type);
assertEqual('verify json receipt verifier run', true, verification.receipt_verifier_boundary.run_in_proof_pack);
assertEqual('verify json receipt verifier valid verdict', 'VALID', verification.receipt_verifier_boundary.valid_verdict);
assertEqual('verify json receipt verifier receipt sha present', true, verification.receipt_verifier_boundary.valid_receipt_sha256_present);
assertEqual('verify json receipt verifier pubkey sha present', true, verification.receipt_verifier_boundary.valid_provided_pubkey_sha256_present);
assertEqual('verify json receipt verifier required identity verdict', 'VALID', verification.receipt_verifier_boundary.required_identity_verdict);
assertEqual('verify json receipt verifier required receipt sha matched', true, verification.receipt_verifier_boundary.required_identity_receipt_sha256_matched);
assertEqual('verify json receipt verifier required pubkey sha matched', true, verification.receipt_verifier_boundary.required_identity_pubkey_sha256_matched);
assertEqual('verify json receipt verifier legacy v0 refused', true, verification.receipt_verifier_boundary.legacy_v0_required_identity_refused);
assertEqual('verify json receipt verifier unknown signer verdict', 'UNKNOWN-SIGNER', verification.receipt_verifier_boundary.unknown_signer_verdict);
assertEqual('verify json receipt verifier invalid verdict', 'INVALID', verification.receipt_verifier_boundary.invalid_verdict);
assertEqual('verify json receipt verifier distinguishes unknown signer', true, verification.receipt_verifier_boundary.distinguishes_unknown_signer_from_invalid);
assertEqual('verify json receipt verifier no issuer recognition', false, verification.receipt_verifier_boundary.issuer_recognition_proven);
assertEqual('verify json trusted registry summary type', 'zlar-local-proof-pack-trusted-issuer-registry-recognition-verification-summary-v2', verification.trusted_issuer_registry_recognition.summary_type);
assertEqual('verify json trusted registry verdict', 'RECOGNIZED', verification.trusted_issuer_registry_recognition.verdict);
assertEqual('verify json trusted registry fixture evaluated', true, verification.trusted_issuer_registry_recognition.registry_fixture_evaluated);
assertEqual('verify json trusted registry rule path evaluated', true, verification.trusted_issuer_registry_recognition.registry_to_recognition_rule_evaluated);
assertEqual('verify json trusted registry evaluator result type', 'downstream-recognition-rule-v1', verification.trusted_issuer_registry_recognition.registry_evaluation_result_type);
assertEqual('verify json trusted registry issuer count', 1, verification.trusted_issuer_registry_recognition.registry_trusted_issuer_count);
assertEqual('verify json trusted registry malformed fail closed', true, verification.trusted_issuer_registry_recognition.malformed_registry_fail_closed_before_verdict);
assertEqual('verify json trusted registry no live registry', false, verification.trusted_issuer_registry_recognition.live_trust_registry_state);
assertEqual('verify json trusted registry no current-machine governance', false, verification.trusted_issuer_registry_recognition.current_machine_governance_proven);
assertEqual('verify json human authorization summary type', 'zlar-local-proof-pack-human-authorization-verification-summary-v1', verification.human_authorization.summary_type);
assertEqual('verify json human authorization run', true, verification.human_authorization.run_in_proof_pack);
assertEqual('verify json human authorization channel simulated', 'simulated-human-fixture', verification.human_authorization.approval_channel);
assertEqual('verify json human authorization pending not boarded', false, verification.human_authorization.pending_boarded);
assertEqual('verify json human authorization authorized boarded', true, verification.human_authorization.authorized_boarded);
assertEqual('verify json human authorization denied not boarded', false, verification.human_authorization.denied_boarded);
assertEqual('verify json service preflight summary type', 'zlar-local-proof-pack-service-profile-preflight-verification-summary-v1', verification.service_profile_preflight.summary_type);
assertEqual('verify json service preflight run', true, verification.service_profile_preflight.run_in_proof_pack);
assertEqual('verify json service preflight cases', PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length, verification.service_profile_preflight.case_count);
assertEqual('verify json service preflight direct api with receipt refused', true, verification.service_profile_preflight.direct_api_with_receipt_refused);
const verificationDirectApiReceiptSummary = verification.service_profile_preflight.case_summaries.find((item) =>
  item.case_id === 'direct_api_profile_receipt_present_refused_before_service_mutation'
);
assertEqual('verify json service preflight request stream authority refused', true, verification.service_profile_preflight.request_stream_authority_material_refused);
assertEqual('verify json service preflight request stream authority reason', 'request_stream_authority_material', verification.service_profile_preflight.request_stream_authority_material_reason);
assertEqual('verify json service preflight direct api receipt reason', 'request_stream_forbidden_fields', verificationDirectApiReceiptSummary.reason_code);
assertEqual('verify json service preflight direct api receipt state delta', 0, verificationDirectApiReceiptSummary.state_entry_count_delta);
assertEqual('verify json service preflight no production service check', false, verification.service_profile_preflight.production_records_service_checked);
assertEqual('verify json runtime local activation summary type', 'zlar-local-proof-pack-runtime-local-activation-verification-summary-v1', verification.runtime_local_activation.summary_type);
assertEqual('verify json runtime local activation run', true, verification.runtime_local_activation.run_in_proof_pack);
assertEqual('verify json runtime local activation active profile selected', true, verification.runtime_local_activation.active_profile_selection.selected);
assertEqual('verify json runtime local activation active profile scope', 'local-disposable-proof-harness', verification.runtime_local_activation.active_profile_selection.selection_scope);
assertEqual('verify json runtime local activation active profile no latest', false, verification.runtime_local_activation.active_profile_selection.selects_latest_profile);
assertEqual('verify json runtime local activation active profile no live check', false, verification.runtime_local_activation.active_profile_selection.live_runtime_profile_checked);
assertEqual('verify json runtime local activation active profile no persistent install', false, verification.runtime_local_activation.active_profile_selection.persistent_runtime_profile_installed);
assertEqual('verify json runtime local activation identity authority', 'launcher-owned-service-config', verification.runtime_local_activation.runtime_profile_identity_authority_source);
assertEqual('verify json runtime local activation omitted id uses launcher config', true, verification.runtime_local_activation.omitted_runtime_profile_id_uses_launcher_config);
assertEqual('verify json runtime local activation supplied mismatch refused', true, verification.runtime_local_activation.supplied_mismatched_runtime_profile_id_refused);
assertEqual('verify json runtime local activation applied', true, verification.runtime_local_activation.local_activation_applied);
assertEqual('verify json runtime local activation disposable config', true, verification.runtime_local_activation.disposable_runtime_config_written);
assertEqual('verify json runtime local activation no persistent config', false, verification.runtime_local_activation.persistent_runtime_config_written);
assertEqual('verify json runtime local activation no hook config', false, verification.runtime_local_activation.hook_configuration_written);
assertEqual('verify json runtime local activation service started', true, verification.runtime_local_activation.runtime_service_started);
assertEqual('verify json runtime local activation route', 'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation', verification.runtime_local_activation.mutation_authoritative_route);
assertEqual('verify json runtime local activation same-process replay refused', true, verification.runtime_local_activation.same_process_signed_payload_replay_refused);
assertEqual('verify json runtime local activation restart grant replay refused', true, verification.runtime_local_activation.restart_consumed_authority_grant_refused);
assertEqual('verify json runtime local activation request grant refused', true, verification.runtime_local_activation.request_supplied_authority_grant_refused);
assertEqual('verify json runtime local activation fixture rightful issuance withheld', false, verification.runtime_local_activation.fixture_rightful_issuance_path_evidenced);
assertEqual('verify json runtime local activation generic rightful issuance false', false, verification.runtime_local_activation.rightful_issuance_proven);
assertEqual('verify json runtime local activation lifecycle closure false', false, verification.runtime_local_activation.consequence_lifecycle_closed);
assertEqual('verify json runtime local activation missing receipt refused', true, verification.runtime_local_activation.missing_receipt_refused);
assertEqual('verify json runtime local activation wrong runtime profile id refused', true, verification.runtime_local_activation.wrong_runtime_profile_id_refused);
assertEqual('verify json runtime local activation wrong audit event refused', true, verification.runtime_local_activation.wrong_audit_event_refused);
assertEqual('verify json runtime local activation direct api with receipt refused', true, verification.runtime_local_activation.direct_api_with_receipt_refused);
assertEqual('verify json runtime local activation no production service', false, verification.runtime_local_activation.production_records_service_checked);
assertEqual('verify json runtime profile installation summary type', 'zlar-local-proof-pack-runtime-profile-installation-verification-summary-v1', verification.runtime_profile_installation.summary_type);
assertEqual('verify json runtime profile installation run', true, verification.runtime_profile_installation.run_in_proof_pack);
assertEqual('verify json runtime profile installation selected from root', true, verification.runtime_profile_installation.disposable_profile_selection.profile_selected_from_install_root);
assertEqual('verify json runtime profile installation no latest', false, verification.runtime_profile_installation.disposable_profile_selection.selects_latest_profile);
assertEqual('verify json runtime profile installation request guard refused', true, verification.runtime_profile_installation.request_authority_guard_summary.all_refused_before_mutation);
assertEqual('verify json runtime profile installation authority grant refused', true, verification.runtime_profile_installation.request_authority_guard_summary.authority_grant_refused);
assertEqual('verify json runtime profile installation identity authority', 'launcher-owned-service-config', verification.runtime_profile_installation.runtime_profile_identity_authority_source);
assertEqual('verify json runtime profile installation omitted id uses launcher config', true, verification.runtime_profile_installation.omitted_runtime_profile_id_uses_launcher_config);
assertEqual('verify json runtime profile installation supplied mismatch refused', true, verification.runtime_profile_installation.supplied_mismatched_runtime_profile_id_refused);
assertEqual('verify json runtime profile installation applied', true, verification.runtime_profile_installation.disposable_profile_installation_applied);
assertEqual('verify json runtime profile installation no hook config', false, verification.runtime_profile_installation.hook_configuration_written);
assertEqual('verify json runtime profile installation route', 'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation', verification.runtime_profile_installation.mutation_authoritative_route);
assertEqual('verify json runtime profile installation same-process replay refused', true, verification.runtime_profile_installation.same_process_signed_payload_replay_refused);
assertEqual('verify json runtime profile installation restart grant replay refused', true, verification.runtime_profile_installation.restart_consumed_authority_grant_refused);
assertEqual('verify json runtime profile installation request grant refused', true, verification.runtime_profile_installation.request_supplied_authority_grant_refused);
assertEqual('verify json runtime profile installation fixture rightful issuance withheld', false, verification.runtime_profile_installation.fixture_rightful_issuance_path_evidenced);
assertEqual('verify json runtime profile installation generic rightful issuance false', false, verification.runtime_profile_installation.rightful_issuance_proven);
assertEqual('verify json runtime profile installation lifecycle closure false', false, verification.runtime_profile_installation.consequence_lifecycle_closed);
assertEqual('verify json runtime profile installation missing receipt refused', true, verification.runtime_profile_installation.missing_receipt_refused);
assertEqual('verify json runtime profile installation wrong runtime profile id refused', true, verification.runtime_profile_installation.wrong_runtime_profile_id_refused);
assertEqual('verify json runtime profile installation wrong audit event refused', true, verification.runtime_profile_installation.wrong_audit_event_refused);
assertEqual('verify json runtime profile installation no production service', false, verification.runtime_profile_installation.production_records_service_checked);
assertEqual('verify json Claude hook replay summary type', 'zlar-local-proof-pack-claude-hook-contract-replay-verification-summary-v1', verification.claude_hook_contract_replay.summary_type);
assertEqual('verify json Claude hook replay run', true, verification.claude_hook_contract_replay.run_in_proof_pack);
assertEqual('verify json Claude hook replay source boundary', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY, verification.claude_hook_contract_replay.source_state_boundary);
assertEqual('verify json Claude hook replay allow JSON', true, verification.claude_hook_contract_replay.permission_decisions_observed.allow);
assertEqual('verify json Claude hook replay deny JSON', true, verification.claude_hook_contract_replay.permission_decisions_observed.deny);
assertEqual('verify json Claude hook replay denied effect not executed', true, verification.claude_hook_contract_replay.denied_effect_not_executed);
assertEqual('verify json Claude hook replay no live app passage', false, verification.claude_hook_contract_replay.live_claude_app_passage_proven);
assertEqual('verify json Claude hook replay no current-machine governance', false, verification.claude_hook_contract_replay.current_machine_governance_proven);

const verifyRequiredShaJsonRun = runZlar(['local-proof-pack', 'verify', '--input', artifactPath, '--require-sha', artifact.integrity.body_sha256, '--json']);
assertEqual('verify required sha json command exits zero', 0, verifyRequiredShaJsonRun.status);
assertEqual('verify required sha json command emits no stderr', '', verifyRequiredShaJsonRun.stderr);
const verifyRequiredShaJson = JSON.parse(verifyRequiredShaJsonRun.stdout);
assertEqual('verify required sha json body sha', artifact.integrity.body_sha256, verifyRequiredShaJson.body_sha256);
assertEqual('verify required sha json required body sha', artifact.integrity.body_sha256, verifyRequiredShaJson.required_body_sha256);
assertEqual('verify required sha json required body sha matched', true, verifyRequiredShaJson.required_body_sha256_matched);
assertEqual('verify required sha json identity matched', true, verifyRequiredShaJson.artifact_identity_sha256_matched);
assertEqual('verify required sha json terminal projection allowed', true, verifyRequiredShaJson.coverage.terminal_claim_projection_allowed);
assertEqual('verify required sha json terminal identity matched', true, verifyRequiredShaJson.coverage.terminal_artifact_identity_sha256_matched);
assertEqual('verify required sha json terminal source bound', true, verifyRequiredShaJson.coverage.terminal_recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256);
assertEqual('verify required sha json terminal signature valid', true, verifyRequiredShaJson.coverage.terminal_trusted_issuer_registry_signature_valid);
assertEqual('verify required sha json terminal fixture rightful path evidenced', true, verifyRequiredShaJson.coverage.terminal_fixture_rightful_issuance_path_evidenced);
assert('verify required sha json is privacy safe', !unsafeOutputPattern.test(verifyRequiredShaJsonRun.stdout));

const verifyStdinRun = runZlar(['local-proof-pack', 'verify', '--input', '-'], {
  input: JSON.stringify(artifact, null, 2),
});
assertEqual('verify stdin command exits zero', 0, verifyStdinRun.status);
assertEqual('verify stdin command emits no stderr', '', verifyStdinRun.stderr);
assert('verify stdin says verified', verifyStdinRun.stdout.includes('verified=true'));
assert('verify stdin is privacy safe', !unsafeOutputPattern.test(verifyStdinRun.stdout));

section('committed sample artifact verify command');
const sampleVerifyRun = runZlar(['local-proof-pack', 'verify', '--input', SAMPLE_ARTIFACT_PATH]);
assertEqual('sample verify command exits zero', 0, sampleVerifyRun.status);
assertEqual('sample verify command emits no stderr', '', sampleVerifyRun.stderr);
assert('sample verify says verified', sampleVerifyRun.stdout.includes('verified=true'));
assert('sample verify includes stable sha', sampleVerifyRun.stdout.includes(SAMPLE_ARTIFACT_SHA256));
assert('sample verify includes service preflight run', sampleVerifyRun.stdout.includes('service_profile_preflight_run_in_proof_pack=true'));
assert('sample verify includes runtime local activation run', sampleVerifyRun.stdout.includes('runtime_local_activation_run_in_proof_pack=true'));
assert('sample verify includes runtime profile installation run', sampleVerifyRun.stdout.includes('runtime_profile_installation_run_in_proof_pack=true'));
assert('sample verify includes key-state run', sampleVerifyRun.stdout.includes('key_state_report_run_in_proof_pack=true'));
assert('sample verify includes receipt verifier run', sampleVerifyRun.stdout.includes('receipt_verifier_boundary_run_in_proof_pack=true'));
assert('sample verify includes trusted registry run', sampleVerifyRun.stdout.includes('trusted_issuer_registry_recognition_run_in_proof_pack=true'));
assert('sample verify includes downstream refusal run', sampleVerifyRun.stdout.includes('downstream_refusal_run_in_proof_pack=true'));
assert('sample verify includes downstream marker boundary', sampleVerifyRun.stdout.includes('recognized_marker_count_delta=1') && sampleVerifyRun.stdout.includes('all_refusal_marker_count_deltas_zero=true'));
assert('sample verify includes human authorization run', sampleVerifyRun.stdout.includes('human_authorization_run_in_proof_pack=true'));
assert('sample verify includes Claude hook replay run', sampleVerifyRun.stdout.includes('claude_hook_contract_replay_run_in_proof_pack=true'));
assert('sample verify withholds terminal positive projection without required SHA', sampleVerifyRun.stdout.includes('terminal_claim_projection_allowed=false') && sampleVerifyRun.stdout.includes('recognized_source_bound=false; signature_valid=false; fixture_rightful_issuance=false'));
assert('sample verify is privacy safe', !unsafeOutputPattern.test(sampleVerifyRun.stdout));

const sampleVerifyJsonRun = runZlar(['local-proof-pack', 'verify', '--input', SAMPLE_ARTIFACT_PATH, '--json']);
assertEqual('sample verify json command exits zero', 0, sampleVerifyJsonRun.status);
const sampleVerification = JSON.parse(sampleVerifyJsonRun.stdout);
assertEqual('sample verify json type', LOCAL_PROOF_PACK_ARTIFACT_VERIFICATION_TYPE, sampleVerification.verification_type);
assertEqual('sample verify json sha matches fixture', SAMPLE_ARTIFACT_SHA256, sampleVerification.body_sha256);
assertEqual('sample verify json live probing false', false, sampleVerification.live_probing);
assertEqual('sample verify json no fresh run', false, sampleVerification.fresh_proof_pack_run_performed);
assertEqual('sample verify json no source freshness', false, sampleVerification.source_freshness_proven);
assertEqual('sample verify json identity not matched without expected SHA', false, sampleVerification.artifact_identity_sha256_matched);
assertEqual('sample verify json terminal projection withheld', false, sampleVerification.coverage.terminal_claim_projection_allowed);
assertEqual('sample verify json terminal fixture rightful path withheld', false, sampleVerification.coverage.terminal_fixture_rightful_issuance_path_evidenced);
assertEqual('sample verify json component manifest count', 16, sampleVerification.component_manifest.length);
assertEqual('sample verify json claim binding count', 11, sampleVerification.claim_binding.non_claim_count);
assertEqual('sample verify json key-state run', true, sampleVerification.key_state_report.run_in_proof_pack);
assertEqual('sample verify json key-state no key custody', false, sampleVerification.key_state_report.key_custody_proven);
assertEqual('sample verify json receipt verifier run', true, sampleVerification.receipt_verifier_boundary.run_in_proof_pack);
assertEqual('sample verify json receipt verifier valid verdict', 'VALID', sampleVerification.receipt_verifier_boundary.valid_verdict);
assertEqual('sample verify json receipt verifier identity bound', true, sampleVerification.receipt_verifier_boundary.required_identity_receipt_sha256_matched);
assertEqual('sample verify json receipt verifier legacy v0 refused', true, sampleVerification.receipt_verifier_boundary.legacy_v0_required_identity_refused);
assertEqual('sample verify json receipt verifier unknown signer verdict', 'UNKNOWN-SIGNER', sampleVerification.receipt_verifier_boundary.unknown_signer_verdict);
assertEqual('sample verify json receipt verifier invalid verdict', 'INVALID', sampleVerification.receipt_verifier_boundary.invalid_verdict);
assertEqual('sample verify json trusted registry verdict', 'RECOGNIZED', sampleVerification.trusted_issuer_registry_recognition.verdict);
assertEqual('sample verify json trusted registry fixture evaluated', true, sampleVerification.trusted_issuer_registry_recognition.registry_fixture_evaluated);
assertEqual('sample verify json trusted registry evaluator result type', 'downstream-recognition-rule-v1', sampleVerification.trusted_issuer_registry_recognition.registry_evaluation_result_type);
assertEqual('sample verify json trusted registry no live registry', false, sampleVerification.trusted_issuer_registry_recognition.live_trust_registry_state);
assertEqual('sample verify json trusted registry no current-machine governance', false, sampleVerification.trusted_issuer_registry_recognition.current_machine_governance_proven);
assertEqual('sample verify json downstream refusal run', true, sampleVerification.downstream_refusal.run_in_proof_pack);
assertEqual('sample verify json downstream recognized marker delta', 1, sampleVerification.downstream_refusal.recognized_marker_count_delta);
assertEqual('sample verify json downstream final marker count', 1, sampleVerification.downstream_refusal.final_marker_count);
assertEqual('sample verify json downstream refusal case count', 11, sampleVerification.downstream_refusal.refusal_case_count);
assertEqual('sample verify json downstream refusal marker deltas zero', true, sampleVerification.downstream_refusal.all_refusal_marker_count_deltas_zero);
assertEqual('sample verify json human authorization run', true, sampleVerification.human_authorization.run_in_proof_pack);
assertEqual('sample verify json human authorization authorized boarded', true, sampleVerification.human_authorization.authorized_boarded);
assertEqual('sample verify json human authorization denied not boarded', false, sampleVerification.human_authorization.denied_boarded);
assertEqual('sample verify json service preflight run', true, sampleVerification.service_profile_preflight.run_in_proof_pack);
assertEqual('sample verify json service preflight cases', PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length, sampleVerification.service_profile_preflight.case_count);
assertEqual('sample verify json runtime local activation run', true, sampleVerification.runtime_local_activation.run_in_proof_pack);
assertEqual('sample verify json runtime local activation active profile selected', true, sampleVerification.runtime_local_activation.active_profile_selection.selected);
assertEqual('sample verify json runtime local activation active profile no latest', false, sampleVerification.runtime_local_activation.active_profile_selection.selects_latest_profile);
assertEqual('sample verify json runtime local activation identity authority', 'launcher-owned-service-config', sampleVerification.runtime_local_activation.runtime_profile_identity_authority_source);
assertEqual('sample verify json runtime local activation applied', true, sampleVerification.runtime_local_activation.local_activation_applied);
assertEqual('sample verify json runtime local activation wrong runtime profile id refused', true, sampleVerification.runtime_local_activation.wrong_runtime_profile_id_refused);
assertEqual('sample verify json runtime local activation wrong audit event refused', true, sampleVerification.runtime_local_activation.wrong_audit_event_refused);
assertEqual('sample verify json runtime profile installation run', true, sampleVerification.runtime_profile_installation.run_in_proof_pack);
assertEqual('sample verify json runtime profile installation selected', true, sampleVerification.runtime_profile_installation.disposable_profile_selection.profile_selected_from_install_root);
assertEqual('sample verify json runtime profile installation guard refused', true, sampleVerification.runtime_profile_installation.request_authority_guard_summary.all_refused_before_mutation);
assertEqual('sample verify json runtime profile installation identity authority', 'launcher-owned-service-config', sampleVerification.runtime_profile_installation.runtime_profile_identity_authority_source);
assertEqual('sample verify json Claude hook replay run', true, sampleVerification.claude_hook_contract_replay.run_in_proof_pack);
assertEqual('sample verify json Claude hook replay source boundary', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY, sampleVerification.claude_hook_contract_replay.source_state_boundary);
assertEqual('sample verify json Claude hook replay allow JSON', true, sampleVerification.claude_hook_contract_replay.permission_decisions_observed.allow);
assertEqual('sample verify json Claude hook replay no live app passage', false, sampleVerification.claude_hook_contract_replay.live_claude_app_passage_proven);
assertEqual('sample verify json Claude hook replay no current-machine governance', false, sampleVerification.claude_hook_contract_replay.current_machine_governance_proven);
assert('sample verify json service preflight has direct api receipt reason', sampleVerification.service_profile_preflight.case_summaries.some((item) =>
  item.case_id === 'direct_api_profile_receipt_present_refused_before_service_mutation' &&
  item.reason_code === 'request_stream_forbidden_fields' &&
  item.state_entry_count_delta === 0
));

const sampleOptionVerifyRun = runZlar(['local-proof-pack', 'verify', '--sample']);
assertEqual('sample option verify command exits zero', 0, sampleOptionVerifyRun.status);
assertEqual('sample option verify command emits no stderr', '', sampleOptionVerifyRun.stderr);
assert('sample option verify says verified', sampleOptionVerifyRun.stdout.includes('verified=true'));
assert('sample option verify includes stable sha', sampleOptionVerifyRun.stdout.includes(SAMPLE_ARTIFACT_SHA256));
assert('sample option verify states artifact-only boundary', sampleOptionVerifyRun.stdout.includes('fresh_proof_pack_run_performed=false; source_freshness_proven=false'));
assert('sample option verify includes key-state run', sampleOptionVerifyRun.stdout.includes('key_state_report_run_in_proof_pack=true'));
assert('sample option verify includes receipt verifier run', sampleOptionVerifyRun.stdout.includes('receipt_verifier_boundary_run_in_proof_pack=true'));
assert('sample option verify includes trusted registry run', sampleOptionVerifyRun.stdout.includes('trusted_issuer_registry_recognition_run_in_proof_pack=true'));
assert('sample option verify includes downstream refusal run', sampleOptionVerifyRun.stdout.includes('downstream_refusal_run_in_proof_pack=true'));
assert('sample option verify includes human authorization run', sampleOptionVerifyRun.stdout.includes('human_authorization_run_in_proof_pack=true'));
assert('sample option verify includes runtime local activation run', sampleOptionVerifyRun.stdout.includes('runtime_local_activation_run_in_proof_pack=true'));
assert('sample option verify includes runtime profile installation run', sampleOptionVerifyRun.stdout.includes('runtime_profile_installation_run_in_proof_pack=true'));
assert('sample option verify includes Claude hook replay run', sampleOptionVerifyRun.stdout.includes('claude_hook_contract_replay_run_in_proof_pack=true'));
assert('sample option verify withholds terminal positive projection', sampleOptionVerifyRun.stdout.includes('terminal_claim_projection_allowed=false') && sampleOptionVerifyRun.stdout.includes('fixture_rightful_issuance=false'));
assert('sample option verify is privacy safe', !unsafeOutputPattern.test(sampleOptionVerifyRun.stdout));

const sampleOptionVerifyRequiredShaRun = runZlar(['local-proof-pack', 'verify', '--sample', '--require-sha', SAMPLE_ARTIFACT_SHA256]);
assertEqual('sample option verify required sha command exits zero', 0, sampleOptionVerifyRequiredShaRun.status);
assertEqual('sample option verify required sha command emits no stderr', '', sampleOptionVerifyRequiredShaRun.stderr);
assert('sample option verify required sha says verified', sampleOptionVerifyRequiredShaRun.stdout.includes('verified=true'));
assert('sample option verify required sha includes stable sha', sampleOptionVerifyRequiredShaRun.stdout.includes(SAMPLE_ARTIFACT_SHA256));
assert('sample option verify required sha reports required artifact sha', sampleOptionVerifyRequiredShaRun.stdout.includes(`required_body_sha256=${SAMPLE_ARTIFACT_SHA256}`));
assert('sample option verify required sha reports required artifact sha matched', sampleOptionVerifyRequiredShaRun.stdout.includes('required_body_sha256_matched=true'));
assert('sample option verify required sha permits terminal positive projection', sampleOptionVerifyRequiredShaRun.stdout.includes('terminal_claim_projection_allowed=true') && sampleOptionVerifyRequiredShaRun.stdout.includes('recognized_source_bound=true; signature_valid=true; fixture_rightful_issuance=true'));
assert('sample option verify required sha is privacy safe', !unsafeOutputPattern.test(sampleOptionVerifyRequiredShaRun.stdout));

const sampleOptionVerifyJsonRun = runZlar(['local-proof-pack', 'verify', '--sample', '--json']);
assertEqual('sample option verify json command exits zero', 0, sampleOptionVerifyJsonRun.status);
assertEqual('sample option verify json command emits no stderr', '', sampleOptionVerifyJsonRun.stderr);
const sampleOptionVerification = JSON.parse(sampleOptionVerifyJsonRun.stdout);
assertEqual('sample option verify json type', LOCAL_PROOF_PACK_ARTIFACT_VERIFICATION_TYPE, sampleOptionVerification.verification_type);
assertEqual('sample option verify json sha matches fixture', SAMPLE_ARTIFACT_SHA256, sampleOptionVerification.body_sha256);
assertEqual('sample option verify json no fresh run', false, sampleOptionVerification.fresh_proof_pack_run_performed);
assertEqual('sample option verify json no source freshness', false, sampleOptionVerification.source_freshness_proven);
assertEqual('sample option verify json terminal projection withheld', false, sampleOptionVerification.coverage.terminal_claim_projection_allowed);
assertEqual('sample option verify json trusted registry verdict', 'RECOGNIZED', sampleOptionVerification.trusted_issuer_registry_recognition.verdict);
assertEqual('sample option verify json trusted registry fixture evaluated', true, sampleOptionVerification.trusted_issuer_registry_recognition.registry_fixture_evaluated);
assertEqual('sample option verify json trusted registry evaluator result type', 'downstream-recognition-rule-v1', sampleOptionVerification.trusted_issuer_registry_recognition.registry_evaluation_result_type);
assertEqual('sample option verify json live probing false', false, sampleOptionVerification.live_probing);
assertEqual('sample option verify json downstream marker delta', 1, sampleOptionVerification.downstream_refusal.recognized_marker_count_delta);
assertEqual('sample option verify json downstream refusal marker deltas zero', true, sampleOptionVerification.downstream_refusal.all_refusal_marker_count_deltas_zero);
assertEqual('sample option verify json key-state run', true, sampleOptionVerification.key_state_report.run_in_proof_pack);
assertEqual('sample option verify json key-state no current-machine governance', false, sampleOptionVerification.key_state_report.current_machine_governance_proven);
assertEqual('sample option verify json receipt verifier run', true, sampleOptionVerification.receipt_verifier_boundary.run_in_proof_pack);
assertEqual('sample option verify json receipt verifier identity bound', true, sampleOptionVerification.receipt_verifier_boundary.required_identity_receipt_sha256_matched);
assertEqual('sample option verify json receipt verifier legacy v0 refused', true, sampleOptionVerification.receipt_verifier_boundary.legacy_v0_required_identity_refused);
assertEqual('sample option verify json receipt verifier unknown signer verdict', 'UNKNOWN-SIGNER', sampleOptionVerification.receipt_verifier_boundary.unknown_signer_verdict);
assertEqual('sample option verify json human authorization run', true, sampleOptionVerification.human_authorization.run_in_proof_pack);
assertEqual('sample option verify json human authorization pending not boarded', false, sampleOptionVerification.human_authorization.pending_boarded);
assertEqual('sample option verify json human authorization authorized boarded', true, sampleOptionVerification.human_authorization.authorized_boarded);
assertEqual('sample option verify json service preflight run', true, sampleOptionVerification.service_profile_preflight.run_in_proof_pack);
assertEqual('sample option verify json service preflight cases', PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length, sampleOptionVerification.service_profile_preflight.case_count);
assertEqual('sample option verify json runtime local activation run', true, sampleOptionVerification.runtime_local_activation.run_in_proof_pack);
assertEqual('sample option verify json runtime local activation active profile selected', true, sampleOptionVerification.runtime_local_activation.active_profile_selection.selected);
assertEqual('sample option verify json runtime local activation active profile no latest', false, sampleOptionVerification.runtime_local_activation.active_profile_selection.selects_latest_profile);
assertEqual('sample option verify json runtime local activation identity authority', 'launcher-owned-service-config', sampleOptionVerification.runtime_local_activation.runtime_profile_identity_authority_source);
assertEqual('sample option verify json runtime local activation applied', true, sampleOptionVerification.runtime_local_activation.local_activation_applied);
assertEqual('sample option verify json runtime local activation wrong runtime profile id refused', true, sampleOptionVerification.runtime_local_activation.wrong_runtime_profile_id_refused);
assertEqual('sample option verify json runtime local activation wrong audit event refused', true, sampleOptionVerification.runtime_local_activation.wrong_audit_event_refused);
assertEqual('sample option verify json runtime profile installation run', true, sampleOptionVerification.runtime_profile_installation.run_in_proof_pack);
assertEqual('sample option verify json runtime profile installation selected', true, sampleOptionVerification.runtime_profile_installation.disposable_profile_selection.profile_selected_from_install_root);
assertEqual('sample option verify json runtime profile installation identity authority', 'launcher-owned-service-config', sampleOptionVerification.runtime_profile_installation.runtime_profile_identity_authority_source);
assertEqual('sample option verify json Claude hook replay run', true, sampleOptionVerification.claude_hook_contract_replay.run_in_proof_pack);
assertEqual('sample option verify json Claude hook replay allow JSON', true, sampleOptionVerification.claude_hook_contract_replay.permission_decisions_observed.allow);
assertEqual('sample option verify json Claude hook replay no current-machine governance', false, sampleOptionVerification.claude_hook_contract_replay.current_machine_governance_proven);
assert('sample option verify json service preflight has direct api receipt reason', sampleOptionVerification.service_profile_preflight.case_summaries.some((item) =>
  item.case_id === 'direct_api_profile_receipt_present_refused_before_service_mutation' &&
  item.reason_code === 'request_stream_forbidden_fields' &&
  item.state_entry_count_delta === 0
));

const sampleOptionVerifyRequiredShaJsonRun = runZlar(['local-proof-pack', 'verify', '--sample', '--require-sha', SAMPLE_ARTIFACT_SHA256, '--json']);
assertEqual('sample option verify required sha json command exits zero', 0, sampleOptionVerifyRequiredShaJsonRun.status);
assertEqual('sample option verify required sha json command emits no stderr', '', sampleOptionVerifyRequiredShaJsonRun.stderr);
const sampleOptionVerifyRequiredShaJson = JSON.parse(sampleOptionVerifyRequiredShaJsonRun.stdout);
assertEqual('sample option verify required sha json body sha', SAMPLE_ARTIFACT_SHA256, sampleOptionVerifyRequiredShaJson.body_sha256);
assertEqual('sample option verify required sha json required body sha', SAMPLE_ARTIFACT_SHA256, sampleOptionVerifyRequiredShaJson.required_body_sha256);
assertEqual('sample option verify required sha json required body sha matched', true, sampleOptionVerifyRequiredShaJson.required_body_sha256_matched);
assertEqual('sample option verify required sha json artifact identity matched', true, sampleOptionVerifyRequiredShaJson.artifact_identity_sha256_matched);
assertEqual('sample option verify required sha json terminal projection allowed', true, sampleOptionVerifyRequiredShaJson.coverage.terminal_claim_projection_allowed);
assertEqual('sample option verify required sha json terminal identity matched', true, sampleOptionVerifyRequiredShaJson.coverage.terminal_artifact_identity_sha256_matched);
assertEqual('sample option verify required sha json terminal source bound', true, sampleOptionVerifyRequiredShaJson.coverage.terminal_recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256);
assertEqual('sample option verify required sha json terminal signature valid', true, sampleOptionVerifyRequiredShaJson.coverage.terminal_trusted_issuer_registry_signature_valid);
assertEqual('sample option verify required sha json terminal fixture rightful path evidenced', true, sampleOptionVerifyRequiredShaJson.coverage.terminal_fixture_rightful_issuance_path_evidenced);
assert('sample option verify required sha json is privacy safe', !unsafeOutputPattern.test(sampleOptionVerifyRequiredShaJsonRun.stdout));

section('help and fail closed command handling');
const helpRun = runZlar(['local-proof-pack', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assert('help names usage', helpRun.stderr.includes('Usage: zlar local-proof-pack [--json] [--artifact <file|->]'));
assert('help names verify usage', helpRun.stderr.includes('zlar local-proof-pack verify (--input <file|->|--sample) [--json] [--require-sha <body_sha256>]'));
assert('help describes artifact', helpRun.stderr.includes('portable checksummed proof artifact'));
assert('help names key-state sample component', helpRun.stderr.includes('deterministic key-state sample summary'));
assert('help names receipt verifier boundary component', helpRun.stderr.includes('receipt verifier boundary'));
assert('help names adapter conformance component', helpRun.stderr.includes('protected records adapter conformance'));
assert('help names downstream service component', helpRun.stderr.includes('protected records downstream service'));
assert('help names local activation component', helpRun.stderr.includes('local disposable runtime activation evidence'));
assert('help names Claude hook replay component', helpRun.stderr.includes('local Claude-shaped hook-contract replay evidence'));
assert('help states no live Claude passage', helpRun.stderr.includes('prove live Claude app passage'));
assert('help describes verify', helpRun.stderr.includes('verify a supplied proof-pack artifact'));
assert('help describes required sha', helpRun.stderr.includes('refuse a valid artifact whose body hash is not the expected artifact identity'));
assert('help names structural-only detached verification', helpRun.stderr.includes('without --require-sha is structural-only'));
assert('help names withheld exact-terminal projection', helpRun.stderr.includes('withholds embedded fixture-rightful and exact-terminal identity, signature, and source-positive projection'));
assert('help describes sample option', helpRun.stderr.includes('verify --sample'));
assert('help names sample artifact', helpRun.stderr.includes('tests/fixtures/local-proof-pack-artifact-v1.json'));
assert('help states no live probing', helpRun.stderr.includes('does not live probe'));
assertEqual('help emits no stdout', '', helpRun.stdout);

const unsupported = runZlar(['local-proof-pack', '--latest']);
assert('unsupported option exits usage error', unsupported.status !== 0);
assert('unsupported option emits no report', unsupported.stdout === '');
assert('unsupported option names unsupported option', unsupported.stderr.includes('Unsupported option'));
assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

const missingArtifactValue = runZlar(['local-proof-pack', '--artifact']);
assert('missing artifact value exits usage error', missingArtifactValue.status !== 0);
assert('missing artifact value emits no report', missingArtifactValue.stdout === '');
assert('missing artifact value names missing value', missingArtifactValue.stderr.includes('Missing value for --artifact'));

const artifactJsonConflict = runZlar(['local-proof-pack', '--json', '--artifact', '-']);
assert('artifact stdout json conflict exits usage error', artifactJsonConflict.status !== 0);
assert('artifact stdout json conflict emits no report', artifactJsonConflict.stdout === '');
assert('artifact stdout json conflict names conflict', artifactJsonConflict.stderr.includes('Cannot combine --json'));

const missingVerifyInput = runZlar(['local-proof-pack', 'verify']);
assert('missing verify input exits usage error', missingVerifyInput.status !== 0);
assert('missing verify input emits no report', missingVerifyInput.stdout === '');
assert('missing verify input names input or sample', missingVerifyInput.stderr.includes('Missing required --input <file|-> or --sample'));
assert('missing verify input is privacy safe', !unsafeOutputPattern.test(missingVerifyInput.stderr));

const verifyInputSampleConflict = runZlar(['local-proof-pack', 'verify', '--input', SAMPLE_ARTIFACT_PATH, '--sample']);
assert('verify input sample conflict exits usage error', verifyInputSampleConflict.status !== 0);
assert('verify input sample conflict emits no report', verifyInputSampleConflict.stdout === '');
assert('verify input sample conflict names conflict', verifyInputSampleConflict.stderr.includes('Cannot combine --input with --sample'));
assert('verify input sample conflict is privacy safe', !unsafeOutputPattern.test(verifyInputSampleConflict.stderr));

const unsupportedVerify = runZlar(['local-proof-pack', 'verify', '--latest']);
assert('unsupported verify option exits usage error', unsupportedVerify.status !== 0);
assert('unsupported verify option emits no report', unsupportedVerify.stdout === '');
assert('unsupported verify option names unsupported verify option', unsupportedVerify.stderr.includes('Unsupported verify option'));
assert('unsupported verify option is privacy safe', !unsafeOutputPattern.test(unsupportedVerify.stderr));

const missingRequiredSha = runZlar(['local-proof-pack', 'verify', '--input', artifactPath, '--require-sha']);
assert('missing required sha exits usage error', missingRequiredSha.status !== 0);
assert('missing required sha emits no report', missingRequiredSha.stdout === '');
assert('missing required sha names missing value', missingRequiredSha.stderr.includes('Missing value for --require-sha'));
assert('missing required sha is privacy safe', !unsafeOutputPattern.test(missingRequiredSha.stderr));

const malformedRequiredSha = runZlar(['local-proof-pack', 'verify', '--input', artifactPath, '--require-sha', 'abc']);
assert('malformed required sha exits usage error', malformedRequiredSha.status !== 0);
assert('malformed required sha emits no report', malformedRequiredSha.stdout === '');
assert('malformed required sha names malformed sha', malformedRequiredSha.stderr.includes('64-character lowercase SHA-256 hex digest'));
assert('malformed required sha is privacy safe', !unsafeOutputPattern.test(malformedRequiredSha.stderr));

const malformedRequiredShaBeforeInput = runZlar(['local-proof-pack', 'verify', '--input', '/Users/example/secret-proof-pack.json', '--require-sha', 'abc']);
assert('malformed required sha fails before input read', malformedRequiredShaBeforeInput.status !== 0);
assert('malformed required sha before input emits no report', malformedRequiredShaBeforeInput.stdout === '');
assert('malformed required sha before input names malformed sha', malformedRequiredShaBeforeInput.stderr.includes('64-character lowercase SHA-256 hex digest'));
assert('malformed required sha before input does not leak path', !malformedRequiredShaBeforeInput.stderr.includes('/Users/example/secret-proof-pack.json'));
assert('malformed required sha before input is privacy safe', !unsafeOutputPattern.test(malformedRequiredShaBeforeInput.stderr));

const mismatchedRequiredSha = runZlar(['local-proof-pack', 'verify', '--input', artifactPath, '--require-sha', '0'.repeat(64)]);
assert('mismatched required sha exits nonzero', mismatchedRequiredSha.status !== 0);
assert('mismatched required sha emits no report', mismatchedRequiredSha.stdout === '');
assert('mismatched required sha names mismatch', mismatchedRequiredSha.stderr.includes('does not match required --require-sha value'));
assert('mismatched required sha is privacy safe', !unsafeOutputPattern.test(mismatchedRequiredSha.stderr));

const attackerChosenResealedArtifact = coherentlyResealAttackerChosenArtifact(artifact);
assert('coherently resealed attacker-chosen artifact is structurally valid', assertLocalProofPackArtifact(attackerChosenResealedArtifact));
assert('coherently resealed attacker-chosen artifact has distinct SHA', attackerChosenResealedArtifact.integrity.body_sha256 !== artifact.integrity.body_sha256);
const attackerChosenArtifactPath = join(scratch, 'attacker-chosen-resealed-artifact.json');
writeFileSync(
  attackerChosenArtifactPath,
  `${JSON.stringify(attackerChosenResealedArtifact, null, 2)}\n`
);
const attackerStructuralRun = runZlar([
  'local-proof-pack',
  'verify',
  '--input',
  attackerChosenArtifactPath,
  '--json',
]);
assertEqual('coherently resealed attacker artifact structural verify exits zero', 0, attackerStructuralRun.status);
const attackerStructuralVerification = JSON.parse(attackerStructuralRun.stdout);
assertEqual('coherently resealed attacker artifact structural self-integrity true', true, attackerStructuralVerification.structural_self_integrity_verified);
assertEqual('coherently resealed attacker artifact identity unmatched', false, attackerStructuralVerification.artifact_identity_sha256_matched);
assertEqual('coherently resealed attacker artifact terminal identity withheld', false, attackerStructuralVerification.coverage.terminal_artifact_identity_sha256_matched);
assertEqual('coherently resealed attacker artifact terminal source withheld', false, attackerStructuralVerification.coverage.terminal_recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256);
assertEqual('coherently resealed attacker artifact terminal signature withheld', false, attackerStructuralVerification.coverage.terminal_trusted_issuer_registry_signature_valid);
assertEqual('coherently resealed attacker artifact fixture rightful path withheld', false, attackerStructuralVerification.coverage.terminal_fixture_rightful_issuance_path_evidenced);
const attackerPinnedToOriginalRun = runZlar([
  'local-proof-pack',
  'verify',
  '--input',
  attackerChosenArtifactPath,
  '--require-sha',
  artifact.integrity.body_sha256,
  '--json',
]);
assert('coherently resealed attacker artifact refuses original expected SHA', attackerPinnedToOriginalRun.status !== 0);
assert('coherently resealed attacker artifact emits no pinned projection', attackerPinnedToOriginalRun.stdout === '');
assert('coherently resealed attacker artifact names required SHA mismatch', attackerPinnedToOriginalRun.stderr.includes('does not match required --require-sha value'));

const invalidJsonPath = join(scratch, 'invalid-artifact.json');
writeFileSync(invalidJsonPath, '{');
const invalidJsonRun = runZlar(['local-proof-pack', 'verify', '--input', invalidJsonPath]);
assert('invalid json verify exits nonzero', invalidJsonRun.status !== 0);
assert('invalid json verify emits no report', invalidJsonRun.stdout === '');
assert('invalid json verify names invalid json', invalidJsonRun.stderr.includes('not valid JSON'));
assert('invalid json verify is privacy safe', !unsafeOutputPattern.test(invalidJsonRun.stderr));

const tamperedArtifactPath = join(scratch, 'tampered-artifact.json');
const tamperedArtifact = structuredClone(artifact);
tamperedArtifact.integrity.body_sha256 = '0'.repeat(64);
writeFileSync(tamperedArtifactPath, `${JSON.stringify(tamperedArtifact, null, 2)}\n`);
const tamperedRun = runZlar(['local-proof-pack', 'verify', '--input', tamperedArtifactPath]);
assert('tampered verify exits nonzero', tamperedRun.status !== 0);
assert('tampered verify emits no report', tamperedRun.stdout === '');
assert('tampered verify names sha mismatch', tamperedRun.stderr.includes('SHA-256 mismatch'));
assert('tampered verify is privacy safe', !unsafeOutputPattern.test(tamperedRun.stderr));

const helpList = runZlar(['help']);
assertEqual('main help exits zero', 0, helpList.status);
assert('main help lists local proof pack', helpList.stdout.includes('local-proof-pack'));

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
