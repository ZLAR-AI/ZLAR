#!/usr/bin/env node

// Historical positive fixture-authority suite. The v1 smoke schema does not
// bind the exact authority-grant contract SHA and may never be reactivated by
// changing a current-grant constant. Current refusal coverage lives in
// test-protected-records-fixture-authority-exhausted-routing.mjs.
console.log('SKIP: proof-smoke v1 is historical under the exhausted fixture authority grant');
process.exit(77);

import { closeSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  assertProofSmokeReport,
  consequenceLifecycleMapSampleProjectionSha256,
  localProofPackSampleArtifactBodySha256,
  proofSmokeReportSha256,
} from '../lib/proof-smoke-report.mjs';

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

const EXPECTED_RECOGNITION_REFUSAL_GROUP_CASE_IDS = {
  no_usable_recognized_receipt_authority: [
    'missing_receipt_refused_before_runtime_mutation',
    'invalid_receipt_refused_before_runtime_mutation',
    'unknown_issuer_refused_before_runtime_mutation',
    'retired_issuer_refused_before_runtime_mutation',
    'missing_issuer_status_refused_before_runtime_mutation',
    'stale_receipt_refused_before_runtime_mutation',
  ],
  recognized_receipt_scope_mismatch: [
    'wrong_policy_refused_before_runtime_mutation',
    'wrong_domain_refused_before_runtime_mutation',
    'wrong_tool_refused_before_runtime_mutation',
    'wrong_audit_event_refused_before_runtime_mutation',
    'wrong_detail_refused_before_runtime_mutation',
    'non_boarding_outcome_refused_before_runtime_mutation',
  ],
  route_or_request_authority_material_refused: [
    'wrong_runtime_profile_id_refused_before_runtime_mutation',
    'direct_api_without_receipt_refused_before_runtime_mutation',
    'direct_api_with_receipt_refused_before_runtime_mutation',
    'agent_supplied_recognition_rule_refused_before_runtime_mutation',
    'agent_supplied_fixture_mode_refused_before_runtime_mutation',
    'unsupported_request_field_refused_before_runtime_mutation',
  ],
};
const EXPECTED_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASE_IDS = [
  'stale_deployment_profile_runtime_sha_refused_before_service_proof',
  'runtime_profile_id_mismatch_refused_before_service_proof',
  'preflight_profile_sha_mismatch_refused_before_service_proof',
  'preflight_latest_selection_refused_before_service_proof',
  'preflight_request_authority_material_refused_before_service_proof',
];

function runZlar(args, input) {
  const stdoutDir = mkdtempSync(join(tmpdir(), 'zlar-proof-smoke-cli-test-'));
  const stdoutPath = join(stdoutDir, 'stdout');
  const stdinPath = join(stdoutDir, 'stdin');
  let stdoutFd = openSync(stdoutPath, 'w');
  let stdinFd = null;
  try {
    if (input !== undefined) {
      writeFileSync(stdinPath, input);
      stdinFd = openSync(stdinPath, 'r');
    }
    const result = spawnSync(join(process.cwd(), 'bin', 'zlar'), args, {
      cwd: process.cwd(),
      encoding: 'utf8',
      stdio: [stdinFd === null ? 'ignore' : stdinFd, stdoutFd, 'pipe'],
      env: {
        ...process.env,
        NO_COLOR: '1',
      },
    });
    closeSync(stdoutFd);
    stdoutFd = null;
    if (stdinFd !== null) {
      closeSync(stdinFd);
      stdinFd = null;
    }
    result.stdout = readFileSync(stdoutPath, 'utf8');
    return result;
  } finally {
    if (stdoutFd !== null) closeSync(stdoutFd);
    if (stdinFd !== null) closeSync(stdinFd);
    rmSync(stdoutDir, { recursive: true, force: true });
  }
}

const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;

console.log('\n-- proof smoke command --');
const smoke = runZlar(['proof-smoke']);
assertEqual('proof smoke exits zero', 0, smoke.status);
assertEqual('proof smoke emits no stderr', '', smoke.stderr);
assert('proof smoke title present', smoke.stdout.includes('ZLAR Committed Fixture Smoke Test v1'));
assert('proof smoke states fixture model', smoke.stdout.includes('Evidence model: committed local fixtures; live probing=false'));
assert('proof smoke includes sample artifact verification', smoke.stdout.includes('[sample artifact verification]'));
assert('proof smoke verifies sample artifact', smoke.stdout.includes('verified=true'));
assert('proof smoke sample verification reports required artifact hash', smoke.stdout.includes(`required_body_sha256=${localProofPackSampleArtifactBodySha256()}`));
assert('proof smoke sample verification reports required artifact hash match', smoke.stdout.includes('required_body_sha256_matched=true'));
assert('proof smoke includes service preflight sample verification', smoke.stdout.includes('[service-profile preflight sample artifact verification]'));
assert('proof smoke verifies service preflight sample artifact', smoke.stdout.includes('ZLAR Protected Records Service Profile Preflight Artifact Verification v1'));
assert('proof smoke includes activation preflight sample verification', smoke.stdout.includes('[activation preflight sample artifact verification]'));
assert('proof smoke verifies activation preflight sample artifact', smoke.stdout.includes('ZLAR Protected Records Runtime Activation Preflight Artifact Verification v1'));
assert('proof smoke includes runtime local activation sample verification', smoke.stdout.includes('[runtime local activation sample artifact verification]'));
assert('proof smoke verifies runtime local activation sample artifact', smoke.stdout.includes('ZLAR Protected Records Runtime Local Activation Artifact Verification v1'));
assert('proof smoke includes runtime profile installation sample verification', smoke.stdout.includes('[runtime profile installation sample artifact verification]'));
assert('proof smoke verifies runtime profile installation sample artifact', smoke.stdout.includes('ZLAR Protected Records Runtime Profile Installation Artifact Verification v1'));
assert('proof smoke includes installed runtime profile preflight sample verification', smoke.stdout.includes('[installed runtime profile preflight sample artifact verification]'));
assert('proof smoke verifies installed runtime profile preflight sample artifact', smoke.stdout.includes('ZLAR Protected Records Installed Runtime Profile Preflight Artifact Verification v1'));
assert('proof smoke includes installed runtime profile recognition proof', smoke.stdout.includes('[installed runtime profile recognition proof]'));
assert('proof smoke verifies installed runtime profile recognition proof', smoke.stdout.includes('ZLAR Protected Records Installed Runtime Profile Recognition Proof v1'));
assert('proof smoke includes installed runtime profile service proof', smoke.stdout.includes('[installed runtime profile service proof]'));
assert('proof smoke verifies installed runtime profile service proof', smoke.stdout.includes('ZLAR Protected Records Installed Runtime Profile Service Proof v1'));
assert('proof smoke includes installed runtime profile service proof artifact verification', smoke.stdout.includes('[installed runtime profile service proof artifact verification]'));
assert('proof smoke verifies installed runtime profile service proof artifact', smoke.stdout.includes('ZLAR Protected Records Installed Runtime Profile Service Proof Artifact Verification v1'));
assert('proof smoke includes installed runtime profile terminal chain', smoke.stdout.includes('[installed runtime profile terminal chain]'));
assert('proof smoke verifies installed runtime profile terminal chain', smoke.stdout.includes('ZLAR Protected Records Installed Runtime Profile Terminal Chain v1'));
assert('proof smoke includes installed runtime profile terminal chain artifact verification', smoke.stdout.includes('[installed runtime profile terminal chain artifact verification]'));
assert('proof smoke verifies installed runtime profile terminal chain artifact', smoke.stdout.includes('ZLAR Protected Records Installed Runtime Profile Terminal Chain Artifact Verification v1'));
assert('proof smoke includes configured recognition replay-store proof', smoke.stdout.includes('[configured recognition consumer replay-store proof]'));
assert('proof smoke verifies configured recognition replay-store proof', smoke.stdout.includes('ZLAR configured-recognition consumer replay-store proof'));
assert('proof smoke includes source bridge window authority sample', smoke.stdout.includes('[source bridge window authority sample]'));
assert('proof smoke verifies source bridge window authority sample', smoke.stdout.includes('Source bridge window authority: accepted'));
assert('proof smoke includes coverage map', smoke.stdout.includes('[fixture-input coverage map]'));
assert('proof smoke reports governed coverage fixture', smoke.stdout.includes('Counts: governed=6/6'));
assert('proof smoke reports pass', smoke.stdout.includes('Result: passed'));
assert('proof smoke includes non-claims', smoke.stdout.includes('does not prove production deployment'));
assert('proof smoke says no fresh base proof generation', smoke.stdout.includes('does not run the proof pack or generate fresh proof-pack, key-state, receipt-verifier, service-profile preflight, activation-preflight, runtime-local-activation, or runtime-profile-installation evidence'));
assert('proof smoke says recognition service and terminal proofs are sample-input evidence', smoke.stdout.includes('runs fresh local disposable installed-runtime-profile recognition, local disposable child-service, and local disposable installed-terminal-chain proofs plus artifact verification from committed sample plan/profile input only'));
assert('proof smoke says no current-machine key-state', smoke.stdout.includes('does not inspect operator home key material'));
assert('proof smoke is privacy safe', !unsafeOutputPattern.test(smoke.stdout));

console.log('\n-- proof smoke json command --');
const smokeJson = runZlar(['proof-smoke', '--json']);
assertEqual('proof smoke json exits zero', 0, smokeJson.status);
assertEqual('proof smoke json emits no stderr', '', smokeJson.stderr);
assert('proof smoke json is privacy safe', !unsafeOutputPattern.test(smokeJson.stdout));
const smokeReport = JSON.parse(smokeJson.stdout);
assert('proof smoke json passes report validation', assertProofSmokeReport(smokeReport));
assertEqual('proof smoke json report type', 'zlar-proof-smoke-v1', smokeReport.report_type);
assertEqual('proof smoke json result passed', 'passed', smokeReport.result);
assertEqual('proof smoke json fixture evidence model', 'committed-local-fixtures', smokeReport.evidence_model);
assertEqual('proof smoke json live probing false', false, smokeReport.live_probing);
assertEqual('proof smoke json has fifteen steps', 15, smokeReport.steps.length);
assertEqual('proof smoke json consequence map step', 'consequence_lifecycle_map_projection', smokeReport.steps[14].step);
assertEqual('proof smoke json consequence map projection hash', consequenceLifecycleMapSampleProjectionSha256(), smokeReport.counts.consequence_lifecycle_map_projection_sha256);
assertEqual('proof smoke json consequence map evidenced count', 13, smokeReport.counts.consequence_lifecycle_map_evidenced_obligation_count);
assertEqual('proof smoke json consequence map open count', 7, smokeReport.counts.consequence_lifecycle_map_not_evidenced_obligation_count);
assertEqual('proof smoke json consequence map outside count', 2, smokeReport.counts.consequence_lifecycle_map_outside_coverage_obligation_count);
assertEqual('proof smoke json consequence map evidence refs', 63, smokeReport.counts.consequence_lifecycle_map_evidence_reference_count);
assertEqual('proof smoke json consequence map evidence refs resolved', true, smokeReport.counts.consequence_lifecycle_map_all_evidence_references_resolved);
assertEqual('proof smoke json local rightful path true', true, smokeReport.counts.local_fixture_rightful_issuance_path_evidenced);
for (const field of [
  'generic_rightful_issuance_proven',
  'portable_rightful_issuance_proven',
  'live_rightful_issuance_proven',
  'production_rightful_issuance_proven',
  'current_machine_rightful_issuance_proven',
  'consequence_lifecycle_closed',
]) {
  assertEqual(`proof smoke json ${field} false`, false, smokeReport.counts[field]);
}
assertEqual('proof smoke json sample verified', true, smokeReport.steps[0].verification.verified);
assertEqual('proof smoke json sample required hash', localProofPackSampleArtifactBodySha256(), smokeReport.steps[0].verification.required_body_sha256);
assertEqual('proof smoke json sample required hash matched', true, smokeReport.steps[0].verification.required_body_sha256_matched);
assertEqual('proof smoke json key-state summary verified', true, smokeReport.counts.key_state_report_summary_verified);
assertEqual('proof smoke json key-state private material read false', false, smokeReport.counts.key_state_private_key_material_read);
assertEqual('proof smoke json key-state no custody proof', false, smokeReport.counts.key_state_key_custody_proven);
assertEqual('proof smoke json key-state no current-machine governance', false, smokeReport.counts.key_state_current_machine_governance_proven);
assertEqual('proof smoke json downstream refusal summary verified', true, smokeReport.counts.downstream_refusal_summary_verified);
assertEqual('proof smoke json downstream recognized marker delta', 1, smokeReport.counts.downstream_refusal_recognized_marker_count_delta);
assertEqual('proof smoke json downstream final marker count', 1, smokeReport.counts.downstream_refusal_final_marker_count);
assertEqual('proof smoke json downstream refusal case count', 11, smokeReport.counts.downstream_refusal_case_count);
assertEqual('proof smoke json downstream refusal marker deltas zero', true, smokeReport.counts.downstream_refusal_marker_deltas_zero);
assertEqual('proof smoke json configured recognition replay-store verified', true, smokeReport.counts.configured_recognition_replay_store_proof_verified);
assertEqual('proof smoke json configured recognition replay-store cases', 3, smokeReport.counts.configured_recognition_replay_store_case_count);
assertEqual('proof smoke json configured recognition replay-store first call persisted', true, smokeReport.counts.configured_recognition_replay_store_first_call_persisted);
assertEqual('proof smoke json configured recognition replay-store replay refused', true, smokeReport.counts.configured_recognition_replay_store_replay_refused_before_callback);
assertEqual('proof smoke json configured recognition replay-store no real downstream', false, smokeReport.counts.configured_recognition_replay_store_real_downstream);
assertEqual('proof smoke json configured recognition replay-store no production trust', false, smokeReport.counts.configured_recognition_replay_store_production_trust);
assertEqual('proof smoke json source bridge authority verified', true, smokeReport.counts.source_bridge_window_authority_verified);
assertEqual('proof smoke json source bridge authority safe for control tower', true, smokeReport.counts.source_bridge_window_authority_safe_for_control_tower_use);
assertEqual('proof smoke json source bridge authority can push under window', true, smokeReport.counts.source_bridge_window_authority_can_push_under_window);
assertEqual('proof smoke json source bridge authority forbidden consequences present', true, smokeReport.counts.source_bridge_window_authority_forbidden_consequences_present);
assertEqual('proof smoke json source bridge authority stop conditions present', true, smokeReport.counts.source_bridge_window_authority_stop_conditions_present);
assertEqual('proof smoke json source bridge authority does not read private key material', false, smokeReport.counts.source_bridge_window_authority_reads_private_key_material);
assertEqual('proof smoke json source bridge authority does not read token material', false, smokeReport.counts.source_bridge_window_authority_reads_token_material);
assertEqual('proof smoke json source bridge authority does not mint credentials', false, smokeReport.counts.source_bridge_window_authority_mints_credentials);
assertEqual('proof smoke json source bridge authority does not call GitHub', false, smokeReport.counts.source_bridge_window_authority_calls_github);
assertEqual('proof smoke json source bridge authority does not read remote refs', false, smokeReport.counts.source_bridge_window_authority_reads_remote_refs);
assertEqual('proof smoke json source bridge authority does not push source', false, smokeReport.counts.source_bridge_window_authority_pushes_source);
assertEqual('proof smoke json source bridge authority does not change config', false, smokeReport.counts.source_bridge_window_authority_changes_configuration);
assertEqual('proof smoke json source bridge authority step accepted', 'accepted', smokeReport.steps[12].authority.authority_status);
assertEqual('proof smoke json source bridge authority sample fixed clock seconds', 45000, smokeReport.steps[12].authority.window.expires_in_seconds);
assertEqual('proof smoke json key-state run', true, smokeReport.steps[0].verification.key_state_report.run_in_proof_pack);
assertEqual('proof smoke json key-state report type', 'zlar-key-state-report-v1', smokeReport.steps[0].verification.key_state_report.report_type);
assertEqual('proof smoke json key-state private key material read false', false, smokeReport.steps[0].verification.key_state_report.private_key_material_read);
assertEqual('proof smoke json key-state no key custody', false, smokeReport.steps[0].verification.key_state_report.key_custody_proven);
assertEqual('proof smoke json downstream refusal run', true, smokeReport.steps[0].verification.downstream_refusal.run_in_proof_pack);
assertEqual('proof smoke json downstream refusal marker delta', 1, smokeReport.steps[0].verification.downstream_refusal.recognized_marker_count_delta);
assertEqual('proof smoke json downstream refusal marker deltas zero', true, smokeReport.steps[0].verification.downstream_refusal.all_refusal_marker_count_deltas_zero);
assertEqual('proof smoke json receipt verifier summary verified', true, smokeReport.counts.receipt_verifier_boundary_summary_verified);
assertEqual('proof smoke json receipt verifier v1 identity verified', true, smokeReport.counts.receipt_verifier_v1_identity_verified);
assertEqual('proof smoke json receipt verifier legacy v0 identity refused', true, smokeReport.counts.receipt_verifier_legacy_v0_required_identity_refused);
assertEqual('proof smoke json receipt verifier unknown signer distinguished', true, smokeReport.counts.receipt_verifier_unknown_signer_distinguished);
assertEqual('proof smoke json receipt verifier run', true, smokeReport.steps[0].verification.receipt_verifier_boundary.run_in_proof_pack);
assertEqual('proof smoke json receipt verifier valid verdict', 'VALID', smokeReport.steps[0].verification.receipt_verifier_boundary.valid_verdict);
assertEqual('proof smoke json receipt verifier required receipt sha matched', true, smokeReport.steps[0].verification.receipt_verifier_boundary.required_identity_receipt_sha256_matched);
assertEqual('proof smoke json receipt verifier legacy v0 refused', true, smokeReport.steps[0].verification.receipt_verifier_boundary.legacy_v0_required_identity_refused);
assertEqual('proof smoke json receipt verifier unknown signer verdict', 'UNKNOWN-SIGNER', smokeReport.steps[0].verification.receipt_verifier_boundary.unknown_signer_verdict);
assertEqual('proof smoke json receipt verifier invalid verdict', 'INVALID', smokeReport.steps[0].verification.receipt_verifier_boundary.invalid_verdict);
assertEqual('proof smoke json receipt verifier no issuer recognition', false, smokeReport.steps[0].verification.receipt_verifier_boundary.issuer_recognition_proven);
assertEqual('proof smoke json trusted registry summary verified', true, smokeReport.counts.trusted_issuer_registry_recognition_summary_verified);
assertEqual('proof smoke json trusted registry observed', true, smokeReport.counts.trusted_issuer_registry_recognition_observed);
assertEqual('proof smoke json trusted registry fixture evaluated count', true, smokeReport.counts.trusted_issuer_registry_fixture_evaluated);
assertEqual('proof smoke json trusted registry evaluator result type count', 'downstream-recognition-rule-v1', smokeReport.counts.trusted_issuer_registry_evaluation_result_type);
assertEqual('proof smoke json trusted registry malformed refused', true, smokeReport.counts.trusted_issuer_registry_malformed_fixture_refused);
assertEqual('proof smoke json trusted registry no live registry', false, smokeReport.counts.trusted_issuer_registry_live_state_proven);
assertEqual('proof smoke json trusted registry no key custody', false, smokeReport.counts.trusted_issuer_registry_key_custody_proven);
assertEqual('proof smoke json trusted registry no current-machine governance', false, smokeReport.counts.trusted_issuer_registry_current_machine_governance_proven);
assertEqual('proof smoke json trusted registry run', true, smokeReport.steps[0].verification.trusted_issuer_registry_recognition.run_in_proof_pack);
assertEqual('proof smoke json trusted registry verdict', 'RECOGNIZED', smokeReport.steps[0].verification.trusted_issuer_registry_recognition.verdict);
assertEqual('proof smoke json trusted registry fixture evaluated', true, smokeReport.steps[0].verification.trusted_issuer_registry_recognition.registry_fixture_evaluated);
assertEqual('proof smoke json trusted registry evaluator result type', 'downstream-recognition-rule-v1', smokeReport.steps[0].verification.trusted_issuer_registry_recognition.registry_evaluation_result_type);
assertEqual('proof smoke json human authorization summary verified', true, smokeReport.counts.human_authorization_summary_verified);
assertEqual('proof smoke json human authorization pending not boarded', false, smokeReport.counts.human_authorization_pending_boarded);
assertEqual('proof smoke json human authorization authorized boarded', true, smokeReport.counts.human_authorization_authorized_boarded);
assertEqual('proof smoke json human authorization denied not boarded', false, smokeReport.counts.human_authorization_denied_boarded);
assertEqual('proof smoke json human authorization run', true, smokeReport.steps[0].verification.human_authorization.run_in_proof_pack);
assertEqual('proof smoke json human authorization channel simulated', 'simulated-human-fixture', smokeReport.steps[0].verification.human_authorization.approval_channel);
assertEqual('proof smoke json service preflight sample verified', true, smokeReport.steps[1].verification.verified);
assertEqual('proof smoke json service preflight sample type', 'zlar-protected-records-service-profile-preflight-artifact-verification-v1', smokeReport.steps[1].verification.verification_type);
assertEqual('proof smoke json service preflight sample cases', 11, smokeReport.steps[1].verification.case_count);
assertEqual('proof smoke json service preflight sample direct api with receipt refused', true, smokeReport.steps[1].verification.direct_api_with_receipt_refused);
assertEqual('proof smoke json service preflight sample request stream authority refused', true, smokeReport.steps[1].verification.request_stream_authority_material_refused);
assertEqual('proof smoke json service preflight sample wrong policy refused', true, smokeReport.steps[1].verification.wrong_policy_refused);
assertEqual('proof smoke json service preflight sample wrong policy reason', 'policy_not_recognized', smokeReport.steps[1].verification.wrong_policy_reason);
assertEqual('proof smoke json service preflight sample wrong policy state delta', 0, smokeReport.steps[1].verification.wrong_policy_state_delta);
assertEqual('proof smoke json service preflight sample request stream authority reason', 'request_stream_authority_material', smokeReport.steps[1].verification.request_stream_authority_material_reason);
assertEqual('proof smoke json service preflight sample direct api reason', 'request_stream_forbidden_fields', smokeReport.steps[1].verification.direct_api_receipt_present_reason);
assertEqual('proof smoke json service preflight sample direct api state delta', 0, smokeReport.steps[1].verification.direct_api_receipt_present_state_delta);
assertEqual('proof smoke json service preflight summary verified', true, smokeReport.counts.service_profile_preflight_summary_verified);
assertEqual('proof smoke json service preflight sample artifact verified', true, smokeReport.counts.service_profile_preflight_sample_artifact_verified);
assertEqual('proof smoke json service preflight cases', 11, smokeReport.counts.service_profile_preflight_cases);
assertEqual('proof smoke json service preflight run', true, smokeReport.steps[0].verification.service_profile_preflight.run_in_proof_pack);
assertEqual('proof smoke json service preflight direct api with receipt refused', true, smokeReport.steps[0].verification.service_profile_preflight.direct_api_with_receipt_refused);
assertEqual('proof smoke json service preflight request stream authority refused', true, smokeReport.steps[0].verification.service_profile_preflight.request_stream_authority_material_refused);
assertEqual('proof smoke json service preflight wrong policy refused', true, smokeReport.steps[0].verification.service_profile_preflight.wrong_policy_refused);
assertEqual('proof smoke json service preflight wrong policy reason', 'policy_not_recognized', smokeReport.steps[0].verification.service_profile_preflight.wrong_policy_reason);
assertEqual('proof smoke json service preflight wrong policy state delta', 0, smokeReport.steps[0].verification.service_profile_preflight.wrong_policy_state_delta);
assertEqual('proof smoke json embedded runtime local activation run', true, smokeReport.steps[0].verification.runtime_local_activation.run_in_proof_pack);
assertEqual('proof smoke json embedded active profile selected', true, smokeReport.steps[0].verification.runtime_local_activation.active_profile_selection.selected);
assertEqual('proof smoke json embedded active profile scope', 'local-disposable-proof-harness', smokeReport.steps[0].verification.runtime_local_activation.active_profile_selection.selection_scope);
assertEqual('proof smoke json embedded active profile no latest', false, smokeReport.steps[0].verification.runtime_local_activation.active_profile_selection.selects_latest_profile);
assertEqual('proof smoke json embedded active profile no live check', false, smokeReport.steps[0].verification.runtime_local_activation.active_profile_selection.live_runtime_profile_checked);
assertEqual('proof smoke json embedded active profile no persistent install', false, smokeReport.steps[0].verification.runtime_local_activation.active_profile_selection.persistent_runtime_profile_installed);
assertEqual('proof smoke json embedded runtime local activation identity authority', 'launcher-owned-service-config', smokeReport.steps[0].verification.runtime_local_activation.runtime_profile_identity_authority_source);
assertEqual('proof smoke json embedded runtime local activation omitted id uses launcher config', true, smokeReport.steps[0].verification.runtime_local_activation.omitted_runtime_profile_id_uses_launcher_config);
assertEqual('proof smoke json embedded runtime local activation applied', true, smokeReport.steps[0].verification.runtime_local_activation.local_activation_applied);
assertEqual('proof smoke json embedded runtime local activation persistent config false', false, smokeReport.steps[0].verification.runtime_local_activation.persistent_runtime_config_written);
assertEqual('proof smoke json embedded runtime local activation hook config false', false, smokeReport.steps[0].verification.runtime_local_activation.hook_configuration_written);
assertEqual('proof smoke json embedded runtime local activation service started true', true, smokeReport.steps[0].verification.runtime_local_activation.runtime_service_started);
assert('proof smoke json service preflight has direct api receipt reason', smokeReport.steps[0].verification.service_profile_preflight.case_summaries.some((item) =>
  item.case_id === 'direct_api_profile_receipt_present_refused_before_service_mutation' &&
  item.reason_code === 'request_stream_forbidden_fields' &&
  item.state_entry_count_delta === 0
));
assertEqual('proof smoke json activation preflight sample verified', true, smokeReport.steps[2].verification.verified);
assertEqual('proof smoke json activation preflight sample type', 'zlar-protected-records-runtime-activation-preflight-artifact-verification-v1', smokeReport.steps[2].verification.verification_type);
assertEqual('proof smoke json activation preflight identity authority', 'launcher-owned-service-config', smokeReport.steps[2].verification.runtime_profile_identity_authority_source);
assertEqual('proof smoke json activation preflight omitted id uses launcher config', true, smokeReport.steps[2].verification.omitted_runtime_profile_id_uses_launcher_config);
assertEqual('proof smoke json runtime local activation sample verified', true, smokeReport.steps[3].verification.verified);
assertEqual('proof smoke json runtime local activation sample type', 'zlar-protected-records-runtime-local-activation-artifact-verification-v1', smokeReport.steps[3].verification.verification_type);
assertEqual('proof smoke json runtime local activation identity authority', 'launcher-owned-service-config', smokeReport.steps[3].verification.runtime_profile_identity_authority_source);
assertEqual('proof smoke json runtime local activation omitted id uses launcher config', true, smokeReport.steps[3].verification.omitted_runtime_profile_id_uses_launcher_config);
assertEqual('proof smoke json runtime local activation applied', true, smokeReport.steps[3].verification.local_activation_applied);
assertEqual('proof smoke json runtime local activation persistent config false', false, smokeReport.steps[3].verification.persistent_runtime_config_written);
assertEqual('proof smoke json runtime local activation hook config false', false, smokeReport.steps[3].verification.hook_configuration_written);
assertEqual('proof smoke json runtime local activation missing receipt refused', true, smokeReport.steps[3].verification.missing_receipt_refused);
assertEqual('proof smoke json runtime local activation wrong runtime profile id refused', true, smokeReport.steps[3].verification.wrong_runtime_profile_id_refused);
assertEqual('proof smoke json runtime profile installation sample verified', true, smokeReport.steps[4].verification.verified);
assertEqual('proof smoke json runtime profile installation sample type', 'zlar-protected-records-runtime-profile-installation-artifact-verification-v1', smokeReport.steps[4].verification.verification_type);
assertEqual('proof smoke json runtime profile installation identity authority', 'launcher-owned-service-config', smokeReport.steps[4].verification.runtime_profile_identity_authority_source);
assertEqual('proof smoke json runtime profile installation omitted id uses launcher config', true, smokeReport.steps[4].verification.omitted_runtime_profile_id_uses_launcher_config);
assertEqual('proof smoke json runtime profile installation applied', true, smokeReport.steps[4].verification.disposable_profile_installation_applied);
assertEqual('proof smoke json runtime profile installation selected', true, smokeReport.steps[4].verification.profile_selected_from_install_root);
assertEqual('proof smoke json runtime profile installation request guard refused', true, smokeReport.steps[4].verification.request_authority_guard_refused);
assertEqual('proof smoke json runtime profile installation wrong runtime profile id refused', true, smokeReport.steps[4].verification.wrong_runtime_profile_id_refused);
assertEqual('proof smoke json runtime profile installation no latest', false, smokeReport.steps[4].verification.selects_latest_profile);
assertEqual('proof smoke json runtime profile installation no persistent install', false, smokeReport.steps[4].verification.persistent_runtime_profile_installed);
assertEqual('proof smoke json runtime profile installation no hook config', false, smokeReport.steps[4].verification.hook_configuration_written);
assertEqual('proof smoke json installed runtime profile preflight sample verified', true, smokeReport.steps[5].verification.verified);
assertEqual('proof smoke json installed runtime profile preflight sample type', 'zlar-protected-records-installed-runtime-profile-preflight-artifact-verification-v1', smokeReport.steps[5].verification.verification_type);
assertEqual('proof smoke json installed runtime profile preflight read only', true, smokeReport.steps[5].verification.read_only);
assertEqual('proof smoke json installed runtime profile preflight selected', true, smokeReport.steps[5].verification.profile_selected_from_install_root);
assertEqual('proof smoke json installed runtime profile preflight selected by id sha', true, smokeReport.steps[5].verification.selected_by_explicit_id_and_sha);
assertEqual('proof smoke json installed runtime profile preflight no latest', false, smokeReport.steps[5].verification.selects_latest_profile);
assertEqual('proof smoke json installed runtime profile preflight no install', false, smokeReport.steps[5].verification.runtime_profile_installation_performed);
assertEqual('proof smoke json installed runtime profile preflight no activation', false, smokeReport.steps[5].verification.runtime_profile_activation_performed);
assertEqual('proof smoke json installed runtime profile preflight no hook config', false, smokeReport.steps[5].verification.hook_configuration_written);
assertEqual('proof smoke json installed runtime profile preflight recognition contract preserved', true, smokeReport.steps[5].verification.recognition_contract_preserved);
assertEqual('proof smoke json installed runtime profile preflight recognition boundary', 'service-configured-recognition-rule', smokeReport.steps[5].verification.recognition_boundary);
assertEqual('proof smoke json installed runtime profile preflight mutation route', 'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation', smokeReport.steps[5].verification.mutation_authoritative_route);
assertEqual('proof smoke json installed runtime profile preflight recognition rule not agent supplied', false, smokeReport.steps[5].verification.recognition_rule_supplied_by_agent);
assertEqual('proof smoke json installed runtime profile preflight no downstream refusal proof', false, smokeReport.steps[5].verification.downstream_refusal_proven);
assertEqual('proof smoke json installed runtime profile preflight no current-machine governance', false, smokeReport.steps[5].verification.current_machine_governance_proven);
assertEqual('proof smoke json installed runtime profile recognition proof type', 'zlar-protected-records-installed-runtime-profile-recognition-proof-v1', smokeReport.steps[6].proof.proof_type);
assertEqual('proof smoke json installed runtime profile recognition proof live false', false, smokeReport.steps[6].proof.live_probing);
assertEqual('proof smoke json installed runtime profile recognition boarded', true, smokeReport.steps[6].proof.recognized_boarding.boarded);
assertEqual('proof smoke json installed runtime profile recognition refusal cases', 18, smokeReport.steps[6].proof.refusal_cases.length);
assertEqual('proof smoke json installed runtime profile recognition source preflight no downstream proof', false, smokeReport.steps[6].proof.source_preflight.downstream_refusal_proven);
assertEqual('proof smoke json installed runtime profile recognition marker final count', 1, smokeReport.steps[6].proof.marker.final_state_entry_count);
assertEqual('proof smoke json installed runtime profile recognition no runtime service', false, smokeReport.steps[6].proof.proof_boundary.runtime_service_started);
assertEqual('proof smoke json installed runtime profile recognition no current-machine governance', false, smokeReport.steps[6].proof.proof_boundary.current_machine_governance_proven);
assertEqual('proof smoke json installed runtime profile service proof type', 'zlar-protected-records-installed-runtime-profile-service-proof-v1', smokeReport.steps[7].proof.proof_type);
assertEqual('proof smoke json installed runtime profile service proof live false', false, smokeReport.steps[7].proof.live_probing);
assertEqual('proof smoke json installed runtime profile service boarded', true, smokeReport.steps[7].proof.recognized_boarding.boarded);
assertEqual('proof smoke json installed runtime profile service refusal cases', 18, smokeReport.steps[7].proof.refusal_cases.length);
assertEqual('proof smoke json installed runtime profile service source preflight no downstream proof', false, smokeReport.steps[7].proof.source_preflight.downstream_refusal_proven);
assertEqual('proof smoke json installed runtime profile service marker primary count', 1, smokeReport.steps[7].proof.marker.primary_recognized_state_append_count);
assertEqual('proof smoke json installed runtime profile service runtime service started', true, smokeReport.steps[7].proof.service_boundary.runtime_service_started);
assertEqual('proof smoke json installed runtime profile service no persistent runtime config', false, smokeReport.steps[7].proof.service_boundary.persistent_runtime_config_written);
assertEqual('proof smoke json installed runtime profile service no current-machine governance', false, smokeReport.steps[7].proof.proof_boundary.current_machine_governance_proven);
assertEqual('proof smoke json installed runtime profile service proof artifact verification type', 'zlar-protected-records-installed-runtime-profile-service-proof-artifact-verification-v1', smokeReport.steps[8].verification.verification_type);
assertEqual('proof smoke json installed runtime profile service proof artifact verification verified', true, smokeReport.steps[8].verification.verified);
assertEqual('proof smoke json installed runtime profile service proof artifact verification payload', smokeReport.steps[7].proof.proof_type, smokeReport.steps[8].verification.payload_type);
assertEqual('proof smoke json installed runtime profile service proof artifact verification restart consumed-grant replay', true, smokeReport.steps[8].verification.restart_consumed_authority_grant_refused);
assertEqual('proof smoke json installed runtime profile service proof artifact verification current-machine false', false, smokeReport.steps[8].verification.current_machine_governance_proven);
assertEqual('proof smoke json runtime local activation count applied', true, smokeReport.counts.runtime_local_activation_applied);
assertEqual('proof smoke json runtime local activation count missing receipt refused', true, smokeReport.counts.runtime_local_activation_missing_receipt_refused);
assertEqual('proof smoke json runtime profile installation count applied', true, smokeReport.counts.runtime_profile_installation_applied);
assertEqual('proof smoke json runtime profile installation guard count refused', true, smokeReport.counts.runtime_profile_installation_request_authority_guard_refused);
assertEqual('proof smoke json runtime profile installation no latest count', false, smokeReport.counts.runtime_profile_installation_selects_latest);
assertEqual('proof smoke json runtime profile installation no persistent install count', false, smokeReport.counts.runtime_profile_installation_persistent_profile_installed);
assertEqual('proof smoke json runtime profile installation no hook count', false, smokeReport.counts.runtime_profile_installation_hook_configuration_written);
assertEqual('proof smoke json installed runtime profile preflight count verified', true, smokeReport.counts.installed_runtime_profile_preflight_sample_artifact_verified);
assertEqual('proof smoke json installed runtime profile preflight count read only', true, smokeReport.counts.installed_runtime_profile_preflight_read_only);
assertEqual('proof smoke json installed runtime profile preflight count selected', true, smokeReport.counts.installed_runtime_profile_preflight_selected);
assertEqual('proof smoke json installed runtime profile preflight count no latest', false, smokeReport.counts.installed_runtime_profile_preflight_selects_latest);
assertEqual('proof smoke json installed runtime profile preflight count no install', false, smokeReport.counts.installed_runtime_profile_preflight_installation_performed);
assertEqual('proof smoke json installed runtime profile preflight count no activation', false, smokeReport.counts.installed_runtime_profile_preflight_activation_performed);
assertEqual('proof smoke json installed runtime profile preflight count recognition contract preserved', true, smokeReport.counts.installed_runtime_profile_preflight_recognition_contract_preserved);
assertEqual('proof smoke json installed runtime profile preflight count no downstream refusal proof', false, smokeReport.counts.installed_runtime_profile_preflight_downstream_refusal_proven);
assertEqual('proof smoke json installed runtime profile preflight count no current-machine governance', false, smokeReport.counts.installed_runtime_profile_preflight_current_machine_governance_proven);
assertEqual('proof smoke json installed runtime profile recognition count verified', true, smokeReport.counts.installed_runtime_profile_recognition_proof_verified);
assertEqual('proof smoke json installed runtime profile recognition count boarded', true, smokeReport.counts.installed_runtime_profile_recognition_recognized_write_boarded);
assertEqual('proof smoke json installed runtime profile recognition count refusal cases', 18, smokeReport.counts.installed_runtime_profile_recognition_refusal_case_count);
assertEqual('proof smoke json installed runtime profile recognition count refusals before mutation', true, smokeReport.counts.installed_runtime_profile_recognition_all_refusals_before_mutation);
assertEqual('proof smoke json installed runtime profile recognition count source preflight downstream false', false, smokeReport.counts.installed_runtime_profile_recognition_source_preflight_downstream_refusal_proven);
assertEqual('proof smoke json installed runtime profile recognition count no runtime service', false, smokeReport.counts.installed_runtime_profile_recognition_runtime_service_started);
assertEqual('proof smoke json installed runtime profile recognition count no current-machine governance', false, smokeReport.counts.installed_runtime_profile_recognition_current_machine_governance_proven);
assertEqual('proof smoke json installed runtime profile recognition count no production downstream', false, smokeReport.counts.installed_runtime_profile_recognition_production_downstream_recognition);
assertEqual('proof smoke json installed runtime profile service count verified', true, smokeReport.counts.installed_runtime_profile_service_proof_verified);
assertEqual('proof smoke json installed runtime profile service count runtime service started', true, smokeReport.counts.installed_runtime_profile_service_runtime_service_started);
assertEqual('proof smoke json installed runtime profile service count disposable config', true, smokeReport.counts.installed_runtime_profile_service_disposable_runtime_config_written);
assertEqual('proof smoke json installed runtime profile service count persistent config false', false, smokeReport.counts.installed_runtime_profile_service_persistent_runtime_config_written);
assertEqual('proof smoke json installed runtime profile service count boarded', true, smokeReport.counts.installed_runtime_profile_service_recognized_write_boarded);
assertEqual('proof smoke json installed runtime profile service count refusal cases', 18, smokeReport.counts.installed_runtime_profile_service_refusal_case_count);
assertEqual('proof smoke json installed runtime profile service count refusals before mutation', true, smokeReport.counts.installed_runtime_profile_service_all_refusals_before_mutation);
assertEqual('proof smoke json installed runtime profile service count source preflight downstream false', false, smokeReport.counts.installed_runtime_profile_service_source_preflight_downstream_refusal_proven);
assertEqual('proof smoke json installed runtime profile service count no current-machine governance', false, smokeReport.counts.installed_runtime_profile_service_current_machine_governance_proven);
assertEqual('proof smoke json installed runtime profile service count no production downstream', false, smokeReport.counts.installed_runtime_profile_service_production_downstream_recognition);
assertEqual('proof smoke json service recognition refusal split', 18, smokeReport.counts.installed_runtime_profile_service_recognition_refusal_case_count);
assertEqual('proof smoke json service authority refusal split', 5, smokeReport.counts.installed_runtime_profile_service_authority_refusal_case_count);
assertEqual('proof smoke json service signed-payload replay refused', true, smokeReport.counts.installed_runtime_profile_service_same_process_signed_payload_replay_refused);
assertEqual('proof smoke json service consumed-grant replay refused', true, smokeReport.counts.installed_runtime_profile_service_restart_consumed_authority_grant_refused);
assertEqual('proof smoke json service replay identities separate', true, smokeReport.counts.installed_runtime_profile_service_replay_identities_separate);
assertEqual('proof smoke json service state-append burn observed', true, smokeReport.counts.installed_runtime_profile_service_state_append_after_grant_commit_burn_observed);
assertEqual('proof smoke json service metadata burn observed', true, smokeReport.counts.installed_runtime_profile_service_metadata_partial_commit_burn_observed);
assertEqual('proof smoke json service joint rollback remains open', false, smokeReport.counts.installed_runtime_profile_service_store_anchor_and_witness_joint_rollback_detection);
assertEqual('proof smoke json installed runtime profile service artifact verification count verified', true, smokeReport.counts.installed_runtime_profile_service_artifact_verification_verified);
assertEqual('proof smoke json installed runtime profile service artifact verification count restart replay', true, smokeReport.counts.installed_runtime_profile_service_artifact_verification_restart_replay_refused);
assertEqual('proof smoke json installed runtime profile service artifact verification count taxonomy hash bound', smokeReport.steps[8].verification.recognition_refusal_taxonomy_sha256, smokeReport.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256);
assertEqual('proof smoke json installed runtime profile service artifact verification count no current-machine governance', false, smokeReport.counts.installed_runtime_profile_service_artifact_verification_current_machine_governance_proven);
assertEqual('proof smoke json installed runtime profile service artifact verification count no production downstream', false, smokeReport.counts.installed_runtime_profile_service_artifact_verification_production_downstream_recognition);
assertEqual('proof smoke json installed runtime profile terminal chain type', 'zlar-protected-records-installed-runtime-profile-terminal-chain-v1', smokeReport.steps[9].chain.chain_type);
assertEqual('proof smoke json installed runtime profile terminal chain model', 'fresh-local-disposable-installed-runtime-profile-terminal-chain', smokeReport.steps[9].chain.evidence_model);
assertEqual('proof smoke json installed runtime profile terminal chain generated root preflighted', true, smokeReport.steps[9].chain.terminal_chain.generated_installed_root_preflighted);
assertEqual('proof smoke json installed runtime profile terminal chain generated preflight consumed', true, smokeReport.steps[9].chain.terminal_chain.generated_preflight_artifact_consumed_by_service_proof);
assertEqual('proof smoke json installed runtime profile terminal chain service artifact verified', true, smokeReport.steps[9].chain.terminal_chain.generated_service_proof_artifact_verified);
assertEqual('proof smoke json installed runtime profile terminal chain proof bound', true, smokeReport.steps[9].chain.terminal_chain.service_proof_bound_to_generated_preflight);
assertEqual('proof smoke json installed runtime profile terminal chain artifact bound', true, smokeReport.steps[9].chain.terminal_chain.service_artifact_verification_bound_to_service_proof);
assertEqual('proof smoke json installed runtime profile terminal chain recognized write boarded', true, smokeReport.steps[9].chain.terminal_chain.recognized_write_boarded);
assertEqual('proof smoke json installed runtime profile terminal chain missing receipt refused', true, smokeReport.steps[9].chain.terminal_chain.missing_receipt_refused_before_mutation);
assertEqual('proof smoke json installed runtime profile terminal chain invalid receipt refused', true, smokeReport.steps[9].chain.terminal_chain.invalid_receipt_refused_before_mutation);
assertEqual('proof smoke json installed runtime profile terminal chain recognition refusals before mutation', true, smokeReport.steps[9].chain.terminal_chain.all_required_recognition_refusals_before_mutation);
assertEqual('proof smoke json installed runtime profile terminal chain authority refusals before consumption', true, smokeReport.steps[9].chain.terminal_chain.all_required_authority_refusals_before_consumption_and_mutation);
assertEqual('proof smoke json installed runtime profile terminal chain refusal taxonomy hash bound', smokeReport.steps[9].chain.generated_service_proof.recognition_refusal_taxonomy_sha256, smokeReport.steps[9].chain.terminal_chain.recognition_refusal_taxonomy_sha256);
assert('proof smoke json installed runtime profile terminal chain refusal taxonomy sha present', /^[a-f0-9]{64}$/.test(smokeReport.steps[9].chain.terminal_chain.recognition_refusal_taxonomy_sha256));
assertEqual('proof smoke json installed runtime profile terminal chain named refusals hash bound', smokeReport.steps[9].chain.generated_service_proof.named_receipt_refusals_sha256, smokeReport.steps[9].chain.terminal_chain.named_receipt_refusals_sha256);
assert('proof smoke json installed runtime profile terminal chain named refusals sha present', /^[a-f0-9]{64}$/.test(smokeReport.steps[9].chain.terminal_chain.named_receipt_refusals_sha256));
assertEqual('proof smoke json installed runtime profile terminal chain recognition refusal groups hash bound', smokeReport.steps[9].chain.generated_service_proof.recognition_refusal_groups_sha256, smokeReport.steps[9].chain.terminal_chain.recognition_refusal_groups_sha256);
assert('proof smoke json installed runtime profile terminal chain recognition refusal groups sha present', /^[a-f0-9]{64}$/.test(smokeReport.steps[9].chain.terminal_chain.recognition_refusal_groups_sha256));
assertEqual('proof smoke json installed runtime profile terminal chain no usable authority group', true, smokeReport.steps[9].chain.terminal_chain.recognition_refusal_groups.no_usable_recognized_receipt_authority.all_refused_before_mutation);
assertEqual('proof smoke json installed runtime profile terminal chain scope mismatch group', true, smokeReport.steps[9].chain.terminal_chain.recognition_refusal_groups.recognized_receipt_scope_mismatch.all_refused_before_mutation);
assertEqual('proof smoke json installed runtime profile terminal chain route/request authority group', true, smokeReport.steps[9].chain.terminal_chain.recognition_refusal_groups.route_or_request_authority_material_refused.all_refused_before_mutation);
assertEqual('proof smoke json installed runtime profile terminal chain recognition group count', 3, smokeReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_count);
assertEqual('proof smoke json installed runtime profile terminal chain recognition group case count', 18, smokeReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count);
assertEqual(
  'proof smoke json installed runtime profile terminal chain recognition group case IDs',
  JSON.stringify(EXPECTED_RECOGNITION_REFUSAL_GROUP_CASE_IDS),
  JSON.stringify(smokeReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids)
);
assertEqual('proof smoke json installed runtime profile terminal chain deployment-profile authority mirror preserved', true, smokeReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved);
assertEqual('proof smoke json installed runtime profile terminal chain deployment-profile authority mirror profile sha matches', true, smokeReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_profile_sha_matches);
assertEqual('proof smoke json installed runtime profile terminal chain deployment-profile authority case count', 5, smokeReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count);
assertEqual(
  'proof smoke json installed runtime profile terminal chain deployment-profile authority case IDs',
  JSON.stringify(EXPECTED_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASE_IDS),
  JSON.stringify(smokeReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids)
);
assertEqual('proof smoke json installed runtime profile terminal chain deployment-profile authority before service proof', true, smokeReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof);
assertEqual('proof smoke json installed runtime profile terminal chain deployment-profile authority service proof not started', false, smokeReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started);
assertEqual('proof smoke json installed runtime profile terminal chain stale named refusal', true, smokeReport.steps[9].chain.terminal_chain.named_receipt_refusals.stale.refused_before_mutation);
assertEqual('proof smoke json installed runtime profile terminal chain stale-or-expired named refusal', true, smokeReport.steps[9].chain.terminal_chain.named_receipt_refusals.stale_or_expired.refused_before_mutation);
assertEqual('proof smoke json installed runtime profile terminal chain wrong domain named refusal', true, smokeReport.steps[9].chain.terminal_chain.named_receipt_refusals.wrong_domain.refused_before_mutation);
assertEqual('proof smoke json installed runtime profile terminal chain observed recognition taxonomy count', 18, smokeReport.steps[9].chain.generated_service_proof.observed_recognition_refusal_cases.length);
assertEqual('proof smoke json installed runtime profile terminal chain no persistent install', false, smokeReport.steps[9].chain.side_door_report.persistent_runtime_profile_installed);
assertEqual('proof smoke json installed runtime profile terminal chain no activation', false, smokeReport.steps[9].chain.side_door_report.runtime_profile_activation_performed);
assertEqual('proof smoke json installed runtime profile terminal chain no current-machine governance', false, smokeReport.steps[9].chain.side_door_report.current_machine_governance_proven);
assertEqual('proof smoke json installed runtime profile terminal chain artifact verification type', 'zlar-protected-records-installed-runtime-profile-terminal-chain-artifact-verification-v1', smokeReport.steps[10].verification.verification_type);
assertEqual('proof smoke json installed runtime profile terminal chain artifact verification verified', true, smokeReport.steps[10].verification.verified);
assertEqual('proof smoke json terminal artifact structural integrity verified', true, smokeReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_structural_self_integrity_verified);
assertEqual('proof smoke json terminal artifact identity requires expected sha', true, smokeReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_identity_match_requires_expected_sha256);
assertEqual('proof smoke json terminal artifact expected sha matched', true, smokeReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_expected_body_sha256_matched);
assertEqual('proof smoke json terminal artifact embedded service structural integrity verified', true, smokeReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_structural_self_integrity_verified);
assertEqual('proof smoke json terminal artifact embedded service expected sha matched', true, smokeReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_expected_body_sha256_matched);
assertEqual('proof smoke json terminal artifact host TOCTOU remains open', false, smokeReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_host_filesystem_path_toctou_closed);
assertEqual('proof smoke json installed runtime profile terminal chain artifact verification recognition refusals before mutation', true, smokeReport.steps[10].verification.all_required_recognition_refusals_before_mutation);
assertEqual('proof smoke json installed runtime profile terminal chain artifact verification authority refusals before consumption', true, smokeReport.steps[10].verification.all_required_authority_refusals_before_consumption_and_mutation);
assertEqual('proof smoke json installed runtime profile terminal chain artifact verification taxonomy hash bound', smokeReport.steps[9].chain.terminal_chain.recognition_refusal_taxonomy_sha256, smokeReport.steps[10].verification.recognition_refusal_taxonomy_sha256);
assertEqual('proof smoke json installed runtime profile terminal chain artifact verification named refusals hash bound', smokeReport.steps[9].chain.terminal_chain.named_receipt_refusals_sha256, smokeReport.steps[10].verification.named_receipt_refusals_sha256);
assertEqual('proof smoke json installed runtime profile terminal chain artifact verification recognition refusal groups hash bound', smokeReport.steps[9].chain.terminal_chain.recognition_refusal_groups_sha256, smokeReport.steps[10].verification.recognition_refusal_groups_sha256);
assertEqual('proof smoke json installed runtime profile terminal chain artifact verification no current-machine governance', false, smokeReport.steps[10].verification.current_machine_governance_proven);
assertEqual('proof smoke json installed runtime profile terminal chain count verified', true, smokeReport.counts.installed_runtime_profile_terminal_chain_verified);
assertEqual('proof smoke json installed runtime profile terminal chain count missing receipt refused', true, smokeReport.counts.installed_runtime_profile_terminal_chain_missing_receipt_refused_before_mutation);
assertEqual('proof smoke json installed runtime profile terminal chain count invalid receipt refused', true, smokeReport.counts.installed_runtime_profile_terminal_chain_invalid_receipt_refused_before_mutation);
assertEqual('proof smoke json installed runtime profile terminal chain count taxonomy hash bound', smokeReport.steps[9].chain.terminal_chain.recognition_refusal_taxonomy_sha256, smokeReport.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256);
assertEqual('proof smoke json installed runtime profile terminal chain count named refusals hash bound', smokeReport.steps[9].chain.terminal_chain.named_receipt_refusals_sha256, smokeReport.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256);
assertEqual('proof smoke json installed runtime profile terminal chain count recognition refusal groups hash bound', smokeReport.steps[9].chain.terminal_chain.recognition_refusal_groups_sha256, smokeReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256);
assertEqual('proof smoke json installed runtime profile terminal chain count no current-machine governance', false, smokeReport.counts.installed_runtime_profile_terminal_chain_current_machine_governance_proven);
assertEqual('proof smoke json installed runtime profile terminal chain artifact verification count verified', true, smokeReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_verified);
assertEqual('proof smoke json installed runtime profile terminal chain artifact verification count taxonomy hash bound', smokeReport.steps[10].verification.recognition_refusal_taxonomy_sha256, smokeReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256);
assertEqual('proof smoke json installed runtime profile terminal chain artifact verification count named refusals hash bound', smokeReport.steps[10].verification.named_receipt_refusals_sha256, smokeReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256);
assertEqual('proof smoke json installed runtime profile terminal chain artifact verification count recognition refusal groups hash bound', smokeReport.steps[10].verification.recognition_refusal_groups_sha256, smokeReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256);
assertEqual('proof smoke json installed runtime profile terminal chain artifact verification recognition group count', 3, smokeReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count);
assertEqual('proof smoke json installed runtime profile terminal chain artifact verification recognition group case count', 18, smokeReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count);
assertEqual(
  'proof smoke json installed runtime profile terminal chain artifact verification recognition group case IDs',
  JSON.stringify(EXPECTED_RECOGNITION_REFUSAL_GROUP_CASE_IDS),
  JSON.stringify(smokeReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids)
);
assertEqual('proof smoke json installed runtime profile terminal chain artifact verification deployment-profile authority mirror preserved', true, smokeReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_preserved);
assertEqual(
  'proof smoke json installed runtime profile terminal chain artifact verification deployment-profile authority case IDs',
  JSON.stringify(EXPECTED_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASE_IDS),
  JSON.stringify(smokeReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids)
);
assertEqual('proof smoke json installed runtime profile terminal chain artifact verification count no current-machine governance', false, smokeReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_current_machine_governance_proven);
assertEqual('proof smoke json active profile selection count verified', true, smokeReport.counts.active_profile_selection_verified);
assertEqual('proof smoke json active profile selected count', true, smokeReport.counts.active_profile_selected);
assertEqual('proof smoke json active profile no latest count', false, smokeReport.counts.active_profile_selects_latest);
assertEqual('proof smoke json active profile no live check count', false, smokeReport.counts.active_profile_live_runtime_profile_checked);
assertEqual('proof smoke json active profile no persistent install count', false, smokeReport.counts.active_profile_persistent_runtime_profile_installed);
assertEqual('proof smoke json governed lanes', 6, smokeReport.counts.governed_lanes);
assertEqual('proof smoke json counted lanes', 6, smokeReport.counts.counted_lanes);
assert('proof smoke json includes production non-claim', smokeReport.non_claims.some((claim) => claim.includes('production deployment')));
assert('proof smoke json includes no fresh base evidence non-claim', smokeReport.non_claims.some((claim) => claim.includes('generate fresh proof-pack, key-state, receipt-verifier, service-profile preflight, activation-preflight, runtime-local-activation, or runtime-profile-installation evidence')));
assert('proof smoke json includes recognition/service/terminal sample non-claim', smokeReport.non_claims.some((claim) => claim.includes('runs fresh local disposable installed-runtime-profile recognition, local disposable child-service, and local disposable installed-terminal-chain proofs plus artifact verification from committed sample plan/profile input only')));
assert('proof smoke json includes profile selection non-claim', smokeReport.non_claims.some((claim) => claim.includes('embedded active-profile selection, disposable installed-profile selection')));
assert('proof smoke json includes installed preflight recognition/service/terminal non-claim', smokeReport.non_claims.some((claim) => claim.includes('read-only local disposable installed-runtime-profile preflight selection, local hermetic installed-profile recognition refusal, local disposable installed-profile child-service refusal, child-service proof artifact verification, fresh local disposable installed-terminal-chain refusal, and terminal-chain artifact verification only')));
assert('proof smoke json includes key-state non-claim', smokeReport.non_claims.some((claim) => claim.includes('operator home key material')));

console.log('\n-- proof smoke report verification command --');
const fixturePath = 'tests/fixtures/proof-smoke-v1-report.json';
const fixtureText = readFileSync(join(process.cwd(), fixturePath), 'utf8');
const fixtureReportSha256 = proofSmokeReportSha256(JSON.parse(fixtureText));

const verifyFixture = runZlar(['proof-smoke', 'verify', '--input', fixturePath]);
assertEqual('proof smoke verify exits zero', 0, verifyFixture.status);
assertEqual('proof smoke verify emits no stderr', '', verifyFixture.stderr);
assert('proof smoke verify reports verified', verifyFixture.stdout.includes('verified=true'));
assert('proof smoke verify reports sha', verifyFixture.stdout.includes(`report_sha256=${fixtureReportSha256}`));
assert('proof smoke verify names report type', verifyFixture.stdout.includes('report_type=zlar-proof-smoke-v1'));
assert('proof smoke verify keeps live probing false', verifyFixture.stdout.includes('live_probing=false'));
assert('proof smoke verify reports governed counts', verifyFixture.stdout.includes('counts: governed=6/6'));
assert('proof smoke verify is privacy safe', !unsafeOutputPattern.test(verifyFixture.stdout));

const verifyRequiredSha = runZlar(['proof-smoke', 'verify', '--input', fixturePath, '--require-sha', fixtureReportSha256]);
assertEqual('proof smoke verify required sha exits zero', 0, verifyRequiredSha.status);
assertEqual('proof smoke verify required sha emits no stderr', '', verifyRequiredSha.stderr);
assert('proof smoke verify required sha reports verified', verifyRequiredSha.stdout.includes('verified=true'));
assert('proof smoke verify required sha reports required sha', verifyRequiredSha.stdout.includes(`required_report_sha256=${fixtureReportSha256}`));
assert('proof smoke verify required sha reports match', verifyRequiredSha.stdout.includes('required_report_sha256_matched=true'));
assert('proof smoke verify required sha is privacy safe', !unsafeOutputPattern.test(verifyRequiredSha.stdout));

const verifyJson = runZlar(['proof-smoke', 'verify', '--input', fixturePath, '--json']);
assertEqual('proof smoke verify json exits zero', 0, verifyJson.status);
assertEqual('proof smoke verify json emits no stderr', '', verifyJson.stderr);
assert('proof smoke verify json is privacy safe', !unsafeOutputPattern.test(verifyJson.stdout));
const verifyReport = JSON.parse(verifyJson.stdout);
assertEqual('proof smoke verify json type', 'zlar-proof-smoke-report-verification-v1', verifyReport.verification_type);
assertEqual('proof smoke verify json verified', true, verifyReport.verified);
assertEqual('proof smoke verify json report sha', fixtureReportSha256, verifyReport.report_sha256);
assertEqual('proof smoke verify json required sha absent', null, verifyReport.required_report_sha256);
assertEqual('proof smoke verify json required sha match absent', null, verifyReport.required_report_sha256_matched);
assertEqual('proof smoke verify json report type', 'zlar-proof-smoke-v1', verifyReport.report_type);
assertEqual('proof smoke verify json evidence model', 'committed-local-fixtures', verifyReport.evidence_model);
assertEqual('proof smoke verify json live probing false', false, verifyReport.live_probing);
assertEqual('proof smoke verify json key-state summary verified', true, verifyReport.counts.key_state_report_summary_verified);
assertEqual('proof smoke verify json key-state no custody proof', false, verifyReport.counts.key_state_key_custody_proven);
assertEqual('proof smoke verify json downstream refusal summary verified', true, verifyReport.counts.downstream_refusal_summary_verified);
assertEqual('proof smoke verify json downstream refusal marker deltas zero', true, verifyReport.counts.downstream_refusal_marker_deltas_zero);
assertEqual('proof smoke verify json configured recognition replay-store verified', true, verifyReport.counts.configured_recognition_replay_store_proof_verified);
assertEqual('proof smoke verify json configured recognition replay-store replay refused', true, verifyReport.counts.configured_recognition_replay_store_replay_refused_before_callback);
assertEqual('proof smoke verify json configured recognition replay-store no production trust', false, verifyReport.counts.configured_recognition_replay_store_production_trust);
assertEqual('proof smoke verify json source bridge authority verified', true, verifyReport.counts.source_bridge_window_authority_verified);
assertEqual('proof smoke verify json source bridge authority does not push source', false, verifyReport.counts.source_bridge_window_authority_pushes_source);
assertEqual('proof smoke verify json source bridge authority does not call GitHub', false, verifyReport.counts.source_bridge_window_authority_calls_github);
assertEqual('proof smoke verify json receipt verifier summary verified', true, verifyReport.counts.receipt_verifier_boundary_summary_verified);
assertEqual('proof smoke verify json receipt verifier v1 identity verified', true, verifyReport.counts.receipt_verifier_v1_identity_verified);
assertEqual('proof smoke verify json receipt verifier legacy v0 identity refused', true, verifyReport.counts.receipt_verifier_legacy_v0_required_identity_refused);
assertEqual('proof smoke verify json receipt verifier unknown signer distinguished', true, verifyReport.counts.receipt_verifier_unknown_signer_distinguished);
assertEqual('proof smoke verify json trusted registry summary verified', true, verifyReport.counts.trusted_issuer_registry_recognition_summary_verified);
assertEqual('proof smoke verify json trusted registry observed', true, verifyReport.counts.trusted_issuer_registry_recognition_observed);
assertEqual('proof smoke verify json trusted registry no live registry', false, verifyReport.counts.trusted_issuer_registry_live_state_proven);
assertEqual('proof smoke verify json trusted registry no current-machine governance', false, verifyReport.counts.trusted_issuer_registry_current_machine_governance_proven);
assertEqual('proof smoke verify json trusted registry fixture evaluated count', true, verifyReport.counts.trusted_issuer_registry_fixture_evaluated);
assertEqual('proof smoke verify json trusted registry evaluator result type count', 'downstream-recognition-rule-v1', verifyReport.counts.trusted_issuer_registry_evaluation_result_type);
assertEqual('proof smoke verify json human authorization summary verified', true, verifyReport.counts.human_authorization_summary_verified);
assertEqual('proof smoke verify json human authorization authorized boarded', true, verifyReport.counts.human_authorization_authorized_boarded);
assertEqual('proof smoke verify json human authorization denied not boarded', false, verifyReport.counts.human_authorization_denied_boarded);
assertEqual('proof smoke verify json active profile selection verified', true, verifyReport.counts.active_profile_selection_verified);
assertEqual('proof smoke verify json active profile no latest', false, verifyReport.counts.active_profile_selects_latest);
assertEqual('proof smoke verify json runtime profile installation guard refused', true, verifyReport.counts.runtime_profile_installation_request_authority_guard_refused);
assertEqual('proof smoke verify json runtime profile installation no latest', false, verifyReport.counts.runtime_profile_installation_selects_latest);
assertEqual('proof smoke verify json installed runtime profile preflight verified', true, verifyReport.counts.installed_runtime_profile_preflight_sample_artifact_verified);
assertEqual('proof smoke verify json installed runtime profile preflight read only', true, verifyReport.counts.installed_runtime_profile_preflight_read_only);
assertEqual('proof smoke verify json installed runtime profile preflight selected', true, verifyReport.counts.installed_runtime_profile_preflight_selected);
assertEqual('proof smoke verify json installed runtime profile preflight recognition contract preserved', true, verifyReport.counts.installed_runtime_profile_preflight_recognition_contract_preserved);
assertEqual('proof smoke verify json installed runtime profile preflight no current-machine governance', false, verifyReport.counts.installed_runtime_profile_preflight_current_machine_governance_proven);
assertEqual('proof smoke verify json installed runtime profile recognition verified', true, verifyReport.counts.installed_runtime_profile_recognition_proof_verified);
assertEqual('proof smoke verify json installed runtime profile recognition refusals before mutation', true, verifyReport.counts.installed_runtime_profile_recognition_all_refusals_before_mutation);
assertEqual('proof smoke verify json installed runtime profile recognition no current-machine governance', false, verifyReport.counts.installed_runtime_profile_recognition_current_machine_governance_proven);
assertEqual('proof smoke verify json installed runtime profile service verified', true, verifyReport.counts.installed_runtime_profile_service_proof_verified);
assertEqual('proof smoke verify json installed runtime profile service runtime service started', true, verifyReport.counts.installed_runtime_profile_service_runtime_service_started);
assertEqual('proof smoke verify json installed runtime profile service refusals before mutation', true, verifyReport.counts.installed_runtime_profile_service_all_refusals_before_mutation);
assertEqual('proof smoke verify json installed runtime profile service no current-machine governance', false, verifyReport.counts.installed_runtime_profile_service_current_machine_governance_proven);
assertEqual('proof smoke verify json terminal-chain deployment-profile authority mirror preserved', true, verifyReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved);
assertEqual('proof smoke verify json terminal-chain artifact deployment-profile authority mirror preserved', true, verifyReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_preserved);
assertEqual(
  'proof smoke verify json terminal-chain deployment-profile authority case IDs',
  JSON.stringify(EXPECTED_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASE_IDS),
  JSON.stringify(verifyReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids)
);
assertEqual('proof smoke verify json governed lanes', 6, verifyReport.counts.governed_lanes);

const verifySample = runZlar(['proof-smoke', 'verify', '--sample']);
assertEqual('proof smoke verify sample exits zero', 0, verifySample.status);
assertEqual('proof smoke verify sample emits no stderr', '', verifySample.stderr);
assert('proof smoke verify sample reports verified', verifySample.stdout.includes('verified=true'));
assert('proof smoke verify sample reports sha', verifySample.stdout.includes(`report_sha256=${fixtureReportSha256}`));
assert('proof smoke verify sample is privacy safe', !unsafeOutputPattern.test(verifySample.stdout));

const verifySampleRequiredSha = runZlar(['proof-smoke', 'verify', '--sample', '--require-sha', fixtureReportSha256]);
assertEqual('proof smoke verify sample required sha exits zero', 0, verifySampleRequiredSha.status);
assertEqual('proof smoke verify sample required sha emits no stderr', '', verifySampleRequiredSha.stderr);
assert('proof smoke verify sample required sha reports verified', verifySampleRequiredSha.stdout.includes('verified=true'));
assert('proof smoke verify sample required sha reports match', verifySampleRequiredSha.stdout.includes('required_report_sha256_matched=true'));
assert('proof smoke verify sample required sha is privacy safe', !unsafeOutputPattern.test(verifySampleRequiredSha.stdout));

const verifySampleJson = runZlar(['proof-smoke', 'verify', '--sample', '--json']);
assertEqual('proof smoke verify sample json exits zero', 0, verifySampleJson.status);
assertEqual('proof smoke verify sample json emits no stderr', '', verifySampleJson.stderr);
assertEqual('proof smoke verify sample json matches file verification', verifyJson.stdout, verifySampleJson.stdout);
assert('proof smoke verify sample json is privacy safe', !unsafeOutputPattern.test(verifySampleJson.stdout));

const verifyStdin = runZlar(['proof-smoke', 'verify', '--input', '-', '--json'], fixtureText);
assertEqual('proof smoke verify stdin exits zero', 0, verifyStdin.status);
assertEqual('proof smoke verify stdin emits no stderr', '', verifyStdin.stderr);
assertEqual('proof smoke verify stdin matches file verification', verifyJson.stdout, verifyStdin.stdout);

const verifyStdinRequiredSha = runZlar(['proof-smoke', 'verify', '--input', '-', '--json', '--require-sha', fixtureReportSha256], fixtureText);
assertEqual('proof smoke verify stdin required sha exits zero', 0, verifyStdinRequiredSha.status);
assertEqual('proof smoke verify stdin required sha emits no stderr', '', verifyStdinRequiredSha.stderr);
const verifyStdinRequiredShaReport = JSON.parse(verifyStdinRequiredSha.stdout);
assertEqual('proof smoke verify stdin required sha json reports sha', fixtureReportSha256, verifyStdinRequiredShaReport.report_sha256);
assertEqual('proof smoke verify stdin required sha json reports required sha', fixtureReportSha256, verifyStdinRequiredShaReport.required_report_sha256);
assertEqual('proof smoke verify stdin required sha json reports match', true, verifyStdinRequiredShaReport.required_report_sha256_matched);

const invalidVerify = runZlar(['proof-smoke', 'verify', '--input', '-'], '{"report_type":"zlar-proof-smoke-v1","live_probing":true}');
assert('proof smoke verify invalid report exits nonzero', invalidVerify.status !== 0);
assertEqual('proof smoke verify invalid report emits no stdout', '', invalidVerify.stdout);
assert('proof smoke verify invalid report names failure', invalidVerify.stderr.includes('Proof smoke report verification failed'));
assert('proof smoke verify invalid report is privacy safe', !unsafeOutputPattern.test(invalidVerify.stderr));

const missingInput = runZlar(['proof-smoke', 'verify']);
assert('proof smoke verify missing input exits usage error', missingInput.status !== 0);
assertEqual('proof smoke verify missing input emits no stdout', '', missingInput.stdout);
assert('proof smoke verify missing input names requirement', missingInput.stderr.includes('verify requires --input <file|-> or --sample'));

const inputSampleConflict = runZlar(['proof-smoke', 'verify', '--input', fixturePath, '--sample']);
assert('proof smoke verify input/sample conflict exits usage error', inputSampleConflict.status !== 0);
assertEqual('proof smoke verify input/sample conflict emits no stdout', '', inputSampleConflict.stdout);
assert('proof smoke verify input/sample conflict names conflict', inputSampleConflict.stderr.includes('verify accepts only one input source'));
assert('proof smoke verify input/sample conflict is privacy safe', !unsafeOutputPattern.test(inputSampleConflict.stderr));

const missingRequiredSha = runZlar(['proof-smoke', 'verify', '--input', fixturePath, '--require-sha']);
assert('proof smoke verify missing required sha exits usage error', missingRequiredSha.status !== 0);
assertEqual('proof smoke verify missing required sha emits no stdout', '', missingRequiredSha.stdout);
assert('proof smoke verify missing required sha names missing value', missingRequiredSha.stderr.includes('Missing value for --require-sha'));
assert('proof smoke verify missing required sha is privacy safe', !unsafeOutputPattern.test(missingRequiredSha.stderr));

const malformedRequiredSha = runZlar(['proof-smoke', 'verify', '--input', fixturePath, '--require-sha', 'abc']);
assert('proof smoke verify malformed required sha exits usage error', malformedRequiredSha.status !== 0);
assertEqual('proof smoke verify malformed required sha emits no stdout', '', malformedRequiredSha.stdout);
assert('proof smoke verify malformed required sha names malformed sha', malformedRequiredSha.stderr.includes('64-character lowercase SHA-256 hex digest'));
assert('proof smoke verify malformed required sha is privacy safe', !unsafeOutputPattern.test(malformedRequiredSha.stderr));

const malformedRequiredShaBeforeInput = runZlar(['proof-smoke', 'verify', '--input', '/Users/example/secret-proof-smoke.json', '--require-sha', 'abc']);
assert('proof smoke verify malformed required sha fails before input read', malformedRequiredShaBeforeInput.status !== 0);
assertEqual('proof smoke verify malformed required sha before input emits no stdout', '', malformedRequiredShaBeforeInput.stdout);
assert('proof smoke verify malformed required sha before input names malformed sha', malformedRequiredShaBeforeInput.stderr.includes('64-character lowercase SHA-256 hex digest'));
assert('proof smoke verify malformed required sha before input does not leak path', !malformedRequiredShaBeforeInput.stderr.includes('/Users/example/secret-proof-smoke.json'));
assert('proof smoke verify malformed required sha before input is privacy safe', !unsafeOutputPattern.test(malformedRequiredShaBeforeInput.stderr));

const mismatchedRequiredSha = runZlar(['proof-smoke', 'verify', '--input', fixturePath, '--require-sha', '0'.repeat(64)]);
assert('proof smoke verify mismatched required sha exits nonzero', mismatchedRequiredSha.status !== 0);
assertEqual('proof smoke verify mismatched required sha emits no stdout', '', mismatchedRequiredSha.stdout);
assert('proof smoke verify mismatched required sha names mismatch', mismatchedRequiredSha.stderr.includes('does not match required --require-sha value'));
assert('proof smoke verify mismatched required sha is privacy safe', !unsafeOutputPattern.test(mismatchedRequiredSha.stderr));

const mismatchedRequiredShaJson = runZlar(['proof-smoke', 'verify', '--input', fixturePath, '--json', '--require-sha', '0'.repeat(64)]);
assert('proof smoke verify json mismatched required sha exits nonzero', mismatchedRequiredShaJson.status !== 0);
assertEqual('proof smoke verify json mismatched required sha emits no stdout', '', mismatchedRequiredShaJson.stdout);
assert('proof smoke verify json mismatched required sha names mismatch', mismatchedRequiredShaJson.stderr.includes('does not match required --require-sha value'));
assert('proof smoke verify json mismatched required sha is privacy safe', !unsafeOutputPattern.test(mismatchedRequiredShaJson.stderr));

console.log('\n-- help and fail closed command handling --');
const help = runZlar(['proof-smoke', '--help']);
assertEqual('help exits zero', 0, help.status);
assert('help names usage', help.stderr.includes('Usage: zlar proof-smoke [--json]'));
assert('help names verify usage', help.stderr.includes('zlar proof-smoke verify (--input <file|->|--sample) [--json] [--require-sha <report_sha256>]'));
assert('help describes sample verification', help.stderr.includes('supplied or committed-sample zlar-proof-smoke-v1 report'));
assert('help describes required sha', help.stderr.includes('refuse a valid report whose canonical report hash is not the expected report identity'));
assert('help names key-state summary', help.stderr.includes('embedded key-state'));
assert('help names receipt verifier boundary', help.stderr.includes('receipt-verifier boundary summaries'));
assert('help states no live probing', help.stderr.includes('does not live probe'));
assertEqual('help emits no stdout', '', help.stdout);

const unsupported = runZlar(['proof-smoke', '--latest']);
assert('unsupported option exits usage error', unsupported.status !== 0);
assertEqual('unsupported option emits no stdout', '', unsupported.stdout);
assert('unsupported option names unsupported option', unsupported.stderr.includes('Unsupported option provided.'));
assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

const mainHelp = runZlar(['help']);
assertEqual('main help exits zero', 0, mainHelp.status);
assert('main help lists proof smoke', mainHelp.stdout.includes('proof-smoke'));

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
