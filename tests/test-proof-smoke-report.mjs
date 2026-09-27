#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  PROOF_SMOKE_REPORT_TYPE,
  PROOF_SMOKE_SAMPLE_REPORT_PATH,
  assertProofSmokeReport,
  buildProofSmokeReport,
  consequenceLifecycleMapSampleProjectionSha256,
  localProofPackSampleArtifactBodySha256,
  parseProofSmokeReportText,
  proofSmokeReportSha256,
} from '../lib/proof-smoke-report.mjs';
import {
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY,
  claudeCodeHookContractReplayContractSha256,
  claudeCodeHookContractReplayRepoAdapterSha256,
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

function assertThrows(label, fn, expectedMessage) {
  TOTAL++;
  try {
    fn();
    FAIL++;
    console.log(`  FAIL: ${label} -- expected throw`);
  } catch (err) {
    if (!expectedMessage || err.message.includes(expectedMessage)) {
      PASS++;
      console.log(`  PASS: ${label}`);
    } else {
      FAIL++;
      console.log(`  FAIL: ${label} -- wrong error: ${err.message}`);
    }
  }
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function stripProofSmokeOneRunTerminalChainIdentity(report) {
  const counts = report.counts || {};
  delete counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256;
  delete counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256;
  delete counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256;

  const terminalChain = report.steps?.[9]?.chain?.terminal_chain;
  if (terminalChain) {
    delete terminalChain.recognized_receipt_path_evidence;
    delete terminalChain.recognized_receipt_path_evidence_sha256;
    delete terminalChain.trusted_issuer_registry_recognition_binding_sha256;
    if (terminalChain.trusted_issuer_registry_recognition_binding) {
      delete terminalChain.trusted_issuer_registry_recognition_binding.binding_sha256;
      delete terminalChain.trusted_issuer_registry_recognition_binding.registry_evidence_model;
      delete terminalChain.trusted_issuer_registry_recognition_binding.registry_contract_evidence;
      delete terminalChain.trusted_issuer_registry_recognition_binding.registry_fixture_contract_sha256;
      delete terminalChain.trusted_issuer_registry_recognition_binding.registry_public_safe_summary_sha256;
    }
  }

  return report;
}

function coverageSurface(report, surfaceId) {
  return report.steps[13].coverage_map.surfaces.find(
    (item) => item.surface_id === surfaceId
  );
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
const EXPECTED_TRUSTED_ISSUER_REGISTRY_REFUSAL_CASE_IDS = [
  'unrecognized_terminal_chain_registry_scope_refused',
  'registry_receipt_contract_mismatch_refused',
];
const EXPECTED_TRUSTED_ISSUER_REGISTRY_REFUSAL_REASON_CODES = [
  'scope_not_found',
  'detail_hash_mismatch',
];
const EXPECTED_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASE_IDS = [
  'stale_deployment_profile_runtime_sha_refused_before_service_proof',
  'runtime_profile_id_mismatch_refused_before_service_proof',
  'preflight_profile_sha_mismatch_refused_before_service_proof',
  'preflight_latest_selection_refused_before_service_proof',
  'preflight_request_authority_material_refused_before_service_proof',
];

function runZlar(args) {
  const stdoutDir = mkdtempSync(join(tmpdir(), 'zlar-proof-smoke-test-'));
  const stdoutPath = join(stdoutDir, 'stdout');
  let stdoutFd = openSync(stdoutPath, 'w');
  try {
    const result = spawnSync(join(process.cwd(), 'bin', 'zlar'), args, {
      cwd: process.cwd(),
      encoding: 'utf8',
      stdio: ['ignore', stdoutFd, 'pipe'],
      env: {
        ...process.env,
        NO_COLOR: '1',
      },
    });
    closeSync(stdoutFd);
    stdoutFd = null;
    result.stdout = readFileSync(stdoutPath, 'utf8');
    return result;
  } finally {
    if (stdoutFd !== null) closeSync(stdoutFd);
    rmSync(stdoutDir, { recursive: true, force: true });
  }
}

const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;

console.log('\n-- committed proof smoke report fixture --');
const fixturePath = join(process.cwd(), PROOF_SMOKE_SAMPLE_REPORT_PATH);
const fixtureText = readFileSync(fixturePath, 'utf8');
const fixtureReport = parseProofSmokeReportText(fixtureText);
assert('fixture report passes validation', assertProofSmokeReport(fixtureReport));
assertEqual('fixture report type', PROOF_SMOKE_REPORT_TYPE, fixtureReport.report_type);
assertEqual('fixture report result', 'passed', fixtureReport.result);
assertEqual('fixture report live probing false', false, fixtureReport.live_probing);
assertEqual('fixture has fifteen steps', 15, fixtureReport.steps.length);
assertEqual('fixture local proof-pack exact hash', localProofPackSampleArtifactBodySha256(), fixtureReport.counts.local_proof_pack_artifact_body_sha256);
assertEqual('fixture activation preflight exact hash', fixtureReport.steps[2].verification.body_sha256, fixtureReport.counts.activation_preflight_artifact_body_sha256);
assertEqual('fixture runtime local activation exact hash', fixtureReport.steps[3].verification.body_sha256, fixtureReport.counts.runtime_local_activation_artifact_body_sha256);
assertEqual('fixture runtime installation exact hash', fixtureReport.steps[4].verification.body_sha256, fixtureReport.counts.runtime_profile_installation_artifact_body_sha256);
assertEqual('fixture installed preflight exact hash', fixtureReport.steps[5].verification.body_sha256, fixtureReport.counts.installed_runtime_profile_preflight_artifact_body_sha256);
assertEqual('fixture service artifact exact hash', fixtureReport.steps[8].verification.body_sha256, fixtureReport.counts.installed_runtime_profile_service_proof_artifact_body_sha256);
assertEqual('fixture terminal artifact exact hash', fixtureReport.steps[10].verification.body_sha256, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_body_sha256);
assertEqual('fixture consequence map step', 'consequence_lifecycle_map_projection', fixtureReport.steps[14].step);
assertEqual('fixture consequence map exact projection hash', consequenceLifecycleMapSampleProjectionSha256(), fixtureReport.counts.consequence_lifecycle_map_projection_sha256);
assertEqual('fixture consequence map evidenced count', 13, fixtureReport.counts.consequence_lifecycle_map_evidenced_obligation_count);
assertEqual('fixture consequence map open count', 7, fixtureReport.counts.consequence_lifecycle_map_not_evidenced_obligation_count);
assertEqual('fixture consequence map outside count', 2, fixtureReport.counts.consequence_lifecycle_map_outside_coverage_obligation_count);
assertEqual('fixture consequence map evidence refs', 63, fixtureReport.counts.consequence_lifecycle_map_evidence_reference_count);
assertEqual('fixture consequence map evidence refs resolved', true, fixtureReport.counts.consequence_lifecycle_map_all_evidence_references_resolved);
assertEqual('fixture local rightful issuance true', true, fixtureReport.counts.local_fixture_rightful_issuance_path_evidenced);
for (const field of [
  'generic_rightful_issuance_proven',
  'portable_rightful_issuance_proven',
  'live_rightful_issuance_proven',
  'production_rightful_issuance_proven',
  'current_machine_rightful_issuance_proven',
  'consequence_lifecycle_closed',
]) {
  assertEqual(`fixture ${field} false`, false, fixtureReport.counts[field]);
}
assert('fixture canonical report hash present', /^[a-f0-9]{64}$/.test(proofSmokeReportSha256(fixtureReport)));
assertEqual('fixture sample verified', true, fixtureReport.counts.sample_artifact_verified);
assertEqual(
  'fixture sample verification uses required artifact hash',
  `zlar local-proof-pack verify --sample --require-sha ${localProofPackSampleArtifactBodySha256()} --json`,
  fixtureReport.steps[0].command
);
assertEqual('fixture sample verification required hash bound', localProofPackSampleArtifactBodySha256(), fixtureReport.steps[0].verification.required_body_sha256);
assertEqual('fixture sample verification required hash matched', true, fixtureReport.steps[0].verification.required_body_sha256_matched);
assertEqual('fixture key-state summary verified', true, fixtureReport.counts.key_state_report_summary_verified);
assertEqual('fixture key-state private key material read false', false, fixtureReport.counts.key_state_private_key_material_read);
assertEqual('fixture key-state no custody proof', false, fixtureReport.counts.key_state_key_custody_proven);
assertEqual('fixture key-state no current-machine governance', false, fixtureReport.counts.key_state_current_machine_governance_proven);
assertEqual('fixture downstream refusal summary verified', true, fixtureReport.counts.downstream_refusal_summary_verified);
assertEqual('fixture downstream recognized marker delta', 1, fixtureReport.counts.downstream_refusal_recognized_marker_count_delta);
assertEqual('fixture downstream final marker count', 1, fixtureReport.counts.downstream_refusal_final_marker_count);
assertEqual('fixture downstream refusal case count', 11, fixtureReport.counts.downstream_refusal_case_count);
assertEqual('fixture downstream refusal marker deltas zero', true, fixtureReport.counts.downstream_refusal_marker_deltas_zero);
assertEqual('fixture receipt verifier summary verified', true, fixtureReport.counts.receipt_verifier_boundary_summary_verified);
assertEqual('fixture receipt verifier v1 identity verified', true, fixtureReport.counts.receipt_verifier_v1_identity_verified);
assertEqual('fixture receipt verifier legacy v0 required identity refused', true, fixtureReport.counts.receipt_verifier_legacy_v0_required_identity_refused);
assertEqual('fixture receipt verifier unknown signer distinguished', true, fixtureReport.counts.receipt_verifier_unknown_signer_distinguished);
assertEqual('fixture trusted registry summary verified', true, fixtureReport.counts.trusted_issuer_registry_recognition_summary_verified);
assertEqual('fixture trusted registry observed', true, fixtureReport.counts.trusted_issuer_registry_recognition_observed);
assertEqual('fixture trusted registry fixture validated count', true, fixtureReport.counts.trusted_issuer_registry_fixture_validated);
assertEqual('fixture trusted registry fixture evaluated count', true, fixtureReport.counts.trusted_issuer_registry_fixture_evaluated);
assertEqual('fixture trusted registry rule path evaluated count', true, fixtureReport.counts.trusted_issuer_registry_to_recognition_rule_evaluated);
assertEqual('fixture trusted registry evaluator result type count', 'downstream-recognition-rule-v1', fixtureReport.counts.trusted_issuer_registry_evaluation_result_type);
assertEqual('fixture trusted registry issuer count', 1, fixtureReport.counts.trusted_issuer_registry_trusted_issuer_count);
assertEqual('fixture trusted registry malformed fixture refused', true, fixtureReport.counts.trusted_issuer_registry_malformed_fixture_refused);
for (const field of [
  'trusted_issuer_registry_live_state_proven',
  'trusted_issuer_registry_live_issuer_status_proven',
  'trusted_issuer_registry_key_custody_proven',
  'trusted_issuer_registry_revocation_truth_proven',
  'trusted_issuer_registry_production_trust_registry_proven',
  'trusted_issuer_registry_production_downstream_recognition_proven',
  'trusted_issuer_registry_production_authority',
  'trusted_issuer_registry_public_external_attestation',
  'trusted_issuer_registry_real_non_operator_review',
  'trusted_issuer_registry_sovereign_recognition',
  'trusted_issuer_registry_current_machine_governance_proven',
]) {
  assertEqual(`fixture trusted registry ${field} false`, false, fixtureReport.counts[field]);
}
assertEqual('fixture human authorization summary verified', true, fixtureReport.counts.human_authorization_summary_verified);
assertEqual('fixture human authorization pending not boarded', false, fixtureReport.counts.human_authorization_pending_boarded);
assertEqual('fixture human authorization authorized boarded', true, fixtureReport.counts.human_authorization_authorized_boarded);
assertEqual('fixture human authorization denied not boarded', false, fixtureReport.counts.human_authorization_denied_boarded);
assertEqual('fixture service preflight sample artifact verified', true, fixtureReport.counts.service_profile_preflight_sample_artifact_verified);
assertEqual('fixture service preflight sample type', 'zlar-protected-records-service-profile-preflight-artifact-verification-v1', fixtureReport.steps[1].verification.verification_type);
assertEqual('fixture service preflight sample cases', 11, fixtureReport.steps[1].verification.case_count);
assertEqual('fixture service preflight sample direct api with receipt refused', true, fixtureReport.steps[1].verification.direct_api_with_receipt_refused);
assertEqual('fixture service preflight sample request stream authority refused', true, fixtureReport.steps[1].verification.request_stream_authority_material_refused);
assertEqual('fixture service preflight sample wrong policy refused', true, fixtureReport.steps[1].verification.wrong_policy_refused);
assertEqual('fixture service preflight sample wrong policy reason', 'policy_not_recognized', fixtureReport.steps[1].verification.wrong_policy_reason);
assertEqual('fixture service preflight sample request stream authority reason', 'request_stream_authority_material', fixtureReport.steps[1].verification.request_stream_authority_material_reason);
assertEqual('fixture service preflight sample direct api reason', 'request_stream_forbidden_fields', fixtureReport.steps[1].verification.direct_api_receipt_present_reason);
assertEqual('fixture service preflight sample direct api state delta', 0, fixtureReport.steps[1].verification.direct_api_receipt_present_state_delta);
assertEqual('fixture service preflight summary verified', true, fixtureReport.counts.service_profile_preflight_summary_verified);
assertEqual('fixture service preflight cases', 11, fixtureReport.counts.service_profile_preflight_cases);
assertEqual('fixture activation preflight sample verified', true, fixtureReport.counts.activation_preflight_sample_artifact_verified);
assertEqual('fixture runtime local activation sample verified', true, fixtureReport.counts.runtime_local_activation_sample_artifact_verified);
assertEqual('fixture runtime local activation applied', true, fixtureReport.counts.runtime_local_activation_applied);
assertEqual('fixture runtime local activation missing receipt refused', true, fixtureReport.counts.runtime_local_activation_missing_receipt_refused);
assertEqual('fixture runtime profile installation sample verified', true, fixtureReport.counts.runtime_profile_installation_sample_artifact_verified);
assertEqual('fixture runtime profile installation applied', true, fixtureReport.counts.runtime_profile_installation_applied);
assertEqual('fixture runtime profile installation request guard refused', true, fixtureReport.counts.runtime_profile_installation_request_authority_guard_refused);
assertEqual('fixture runtime profile installation no latest', false, fixtureReport.counts.runtime_profile_installation_selects_latest);
assertEqual('fixture runtime profile installation no persistent install', false, fixtureReport.counts.runtime_profile_installation_persistent_profile_installed);
assertEqual('fixture runtime profile installation no hook config', false, fixtureReport.counts.runtime_profile_installation_hook_configuration_written);
assertEqual('fixture installed runtime profile preflight sample verified', true, fixtureReport.counts.installed_runtime_profile_preflight_sample_artifact_verified);
assertEqual('fixture installed runtime profile preflight read only', true, fixtureReport.counts.installed_runtime_profile_preflight_read_only);
assertEqual('fixture installed runtime profile preflight selected', true, fixtureReport.counts.installed_runtime_profile_preflight_selected);
assertEqual('fixture installed runtime profile preflight no latest', false, fixtureReport.counts.installed_runtime_profile_preflight_selects_latest);
assertEqual('fixture installed runtime profile preflight no install', false, fixtureReport.counts.installed_runtime_profile_preflight_installation_performed);
assertEqual('fixture installed runtime profile preflight no activation', false, fixtureReport.counts.installed_runtime_profile_preflight_activation_performed);
assertEqual('fixture installed runtime profile preflight no hook config', false, fixtureReport.counts.installed_runtime_profile_preflight_hook_configuration_written);
assertEqual('fixture installed runtime profile preflight recognition contract preserved', true, fixtureReport.counts.installed_runtime_profile_preflight_recognition_contract_preserved);
assertEqual('fixture installed runtime profile preflight no downstream refusal proof', false, fixtureReport.counts.installed_runtime_profile_preflight_downstream_refusal_proven);
assertEqual('fixture installed runtime profile preflight no current-machine governance', false, fixtureReport.counts.installed_runtime_profile_preflight_current_machine_governance_proven);
assertEqual('fixture active profile selection verified', true, fixtureReport.counts.active_profile_selection_verified);
assertEqual('fixture active profile selected', true, fixtureReport.counts.active_profile_selected);
assertEqual('fixture active profile no latest', false, fixtureReport.counts.active_profile_selects_latest);
assertEqual('fixture active profile no live check', false, fixtureReport.counts.active_profile_live_runtime_profile_checked);
assertEqual('fixture active profile no persistent install', false, fixtureReport.counts.active_profile_persistent_runtime_profile_installed);
assertEqual('fixture governed lanes', 6, fixtureReport.counts.governed_lanes);
const fixtureTerminalChainCoverageSurface = coverageSurface(
  fixtureReport,
  'protected-records.installed-runtime-profile.terminal-chain.records.write'
);
assert('fixture terminal chain coverage surface present', Boolean(fixtureTerminalChainCoverageSurface));
assertEqual(
  'fixture terminal chain coverage trusted registry verdict',
  'RECOGNIZED',
  fixtureTerminalChainCoverageSurface?.evidence?.trusted_issuer_registry?.verdict
);
assertEqual(
  'fixture terminal chain coverage trusted registry binding hash matched',
  true,
  fixtureTerminalChainCoverageSurface?.evidence?.trusted_issuer_registry?.binding_sha_matches_summary
);
assertEqual(
  'fixture terminal chain coverage trusted registry no live registry',
  false,
  fixtureTerminalChainCoverageSurface?.evidence?.trusted_issuer_registry?.live_trust_registry_state
);
assertEqual(
  'fixture terminal chain coverage trusted registry no production authority',
  false,
  fixtureTerminalChainCoverageSurface?.evidence?.trusted_issuer_registry?.production_authority
);
assertEqual(
  'fixture terminal chain coverage trusted registry no current-machine governance',
  false,
  fixtureTerminalChainCoverageSurface?.evidence?.trusted_issuer_registry?.current_machine_governance_proven
);
assertEqual('fixture key-state run in proof pack', true, fixtureReport.steps[0].verification.key_state_report.run_in_proof_pack);
assertEqual('fixture key-state report type', 'zlar-key-state-report-v1', fixtureReport.steps[0].verification.key_state_report.report_type);
assertEqual('fixture key-state private key material read false', false, fixtureReport.steps[0].verification.key_state_report.private_key_material_read);
assertEqual('fixture key-state no custody proof', false, fixtureReport.steps[0].verification.key_state_report.key_custody_proven);
assertEqual('fixture key-state no current-machine governance', false, fixtureReport.steps[0].verification.key_state_report.current_machine_governance_proven);
assertEqual('fixture downstream refusal run in proof pack', true, fixtureReport.steps[0].verification.downstream_refusal.run_in_proof_pack);
assertEqual('fixture downstream refusal recognized marker delta', 1, fixtureReport.steps[0].verification.downstream_refusal.recognized_marker_count_delta);
assertEqual('fixture downstream refusal marker deltas zero', true, fixtureReport.steps[0].verification.downstream_refusal.all_refusal_marker_count_deltas_zero);
assertEqual('fixture receipt verifier run in proof pack', true, fixtureReport.steps[0].verification.receipt_verifier_boundary.run_in_proof_pack);
assertEqual('fixture receipt verifier valid verdict', 'VALID', fixtureReport.steps[0].verification.receipt_verifier_boundary.valid_verdict);
assertEqual('fixture receipt verifier valid receipt sha present', true, fixtureReport.steps[0].verification.receipt_verifier_boundary.valid_receipt_sha256_present);
assertEqual('fixture receipt verifier valid pubkey sha present', true, fixtureReport.steps[0].verification.receipt_verifier_boundary.valid_provided_pubkey_sha256_present);
assertEqual('fixture receipt verifier required identity verdict', 'VALID', fixtureReport.steps[0].verification.receipt_verifier_boundary.required_identity_verdict);
assertEqual('fixture receipt verifier required receipt sha matched', true, fixtureReport.steps[0].verification.receipt_verifier_boundary.required_identity_receipt_sha256_matched);
assertEqual('fixture receipt verifier required pubkey sha matched', true, fixtureReport.steps[0].verification.receipt_verifier_boundary.required_identity_pubkey_sha256_matched);
assertEqual('fixture receipt verifier required v1-only matched', true, fixtureReport.steps[0].verification.receipt_verifier_boundary.required_identity_v1_only_matched);
assertEqual('fixture receipt verifier legacy v0 identity refused', true, fixtureReport.steps[0].verification.receipt_verifier_boundary.legacy_v0_required_identity_refused);
assertEqual('fixture receipt verifier unknown signer verdict', 'UNKNOWN-SIGNER', fixtureReport.steps[0].verification.receipt_verifier_boundary.unknown_signer_verdict);
assertEqual('fixture receipt verifier invalid verdict', 'INVALID', fixtureReport.steps[0].verification.receipt_verifier_boundary.invalid_verdict);
assertEqual('fixture receipt verifier distinguishes unknown signer', true, fixtureReport.steps[0].verification.receipt_verifier_boundary.distinguishes_unknown_signer_from_invalid);
assertEqual('fixture receipt verifier no issuer recognition', false, fixtureReport.steps[0].verification.receipt_verifier_boundary.issuer_recognition_proven);
assertEqual('fixture trusted registry run in proof pack', true, fixtureReport.steps[0].verification.trusted_issuer_registry_recognition.run_in_proof_pack);
assertEqual('fixture trusted registry verdict', 'RECOGNIZED', fixtureReport.steps[0].verification.trusted_issuer_registry_recognition.verdict);
assertEqual('fixture trusted registry fixture evaluated', true, fixtureReport.steps[0].verification.trusted_issuer_registry_recognition.registry_fixture_evaluated);
assertEqual('fixture trusted registry rule path evaluated', true, fixtureReport.steps[0].verification.trusted_issuer_registry_recognition.registry_to_recognition_rule_evaluated);
assertEqual('fixture trusted registry evaluator result type', 'downstream-recognition-rule-v1', fixtureReport.steps[0].verification.trusted_issuer_registry_recognition.registry_evaluation_result_type);
assertEqual('fixture trusted registry issuer count', 1, fixtureReport.steps[0].verification.trusted_issuer_registry_recognition.registry_trusted_issuer_count);
assertEqual('fixture trusted registry malformed fail closed', true, fixtureReport.steps[0].verification.trusted_issuer_registry_recognition.malformed_registry_fail_closed_before_verdict);
assertEqual('fixture trusted registry no live registry', false, fixtureReport.steps[0].verification.trusted_issuer_registry_recognition.live_trust_registry_state);
assertEqual('fixture trusted registry no key custody', false, fixtureReport.steps[0].verification.trusted_issuer_registry_recognition.key_custody_proven);
assertEqual('fixture trusted registry no current-machine governance', false, fixtureReport.steps[0].verification.trusted_issuer_registry_recognition.current_machine_governance_proven);
assertEqual('fixture human authorization run in proof pack', true, fixtureReport.steps[0].verification.human_authorization.run_in_proof_pack);
assertEqual('fixture human authorization summary type', 'zlar-local-proof-pack-human-authorization-verification-summary-v1', fixtureReport.steps[0].verification.human_authorization.summary_type);
assertEqual('fixture human authorization channel simulated', 'simulated-human-fixture', fixtureReport.steps[0].verification.human_authorization.approval_channel);
assertEqual('fixture human authorization pending not boarded', false, fixtureReport.steps[0].verification.human_authorization.pending_boarded);
assertEqual('fixture human authorization authorized boarded', true, fixtureReport.steps[0].verification.human_authorization.authorized_boarded);
assertEqual('fixture human authorization denied not boarded', false, fixtureReport.steps[0].verification.human_authorization.denied_boarded);
assertEqual('fixture service preflight run in proof pack', true, fixtureReport.steps[0].verification.service_profile_preflight.run_in_proof_pack);
assertEqual('fixture service preflight evidence model', 'local-disposable-config-backed-profile-preflight-fixture', fixtureReport.steps[0].verification.service_profile_preflight.evidence_model);
assertEqual('fixture service preflight direct api with receipt refused', true, fixtureReport.steps[0].verification.service_profile_preflight.direct_api_with_receipt_refused);
assertEqual('fixture service preflight request stream authority refused', true, fixtureReport.steps[0].verification.service_profile_preflight.request_stream_authority_material_refused);
assertEqual('fixture service preflight wrong policy refused', true, fixtureReport.steps[0].verification.service_profile_preflight.wrong_policy_refused);
assertEqual('fixture service preflight wrong policy reason', 'policy_not_recognized', fixtureReport.steps[0].verification.service_profile_preflight.wrong_policy_reason);
const fixtureDirectApiReceiptSummary = fixtureReport.steps[0].verification.service_profile_preflight.case_summaries.find((item) =>
  item.case_id === 'direct_api_profile_receipt_present_refused_before_service_mutation'
);
assertEqual('fixture service preflight direct api receipt reason', 'request_stream_forbidden_fields', fixtureDirectApiReceiptSummary.reason_code);
assertEqual('fixture service preflight direct api receipt state delta', 0, fixtureDirectApiReceiptSummary.state_entry_count_delta);
assertEqual('fixture service preflight direct api receipt attempted', true, fixtureDirectApiReceiptSummary.direct_api_attempted);
assertEqual('fixture Claude hook replay contract hash bound', claudeCodeHookContractReplayContractSha256(), fixtureReport.steps[0].verification.claude_hook_contract_replay.hook_replay_contract_sha256);
assertEqual('fixture Claude hook replay source boundary exact', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY, fixtureReport.steps[0].verification.claude_hook_contract_replay.source_state_boundary);
assertEqual('fixture Claude hook replay adapter hash bound', claudeCodeHookContractReplayRepoAdapterSha256(), fixtureReport.steps[0].verification.claude_hook_contract_replay.adapter_sha256);
assert('fixture Claude hook replay case evidence hash present', /^[a-f0-9]{64}$/.test(fixtureReport.steps[0].verification.claude_hook_contract_replay.case_evidence_sha256));
assertEqual('fixture Claude hook replay no live passage', false, fixtureReport.steps[0].verification.claude_hook_contract_replay.live_claude_app_passage_proven);
assertEqual('fixture Claude hook replay no current-machine governance', false, fixtureReport.steps[0].verification.claude_hook_contract_replay.current_machine_governance_proven);
assertEqual('fixture activation preflight identity authority', 'launcher-owned-service-config', fixtureReport.steps[2].verification.runtime_profile_identity_authority_source);
assertEqual('fixture activation preflight omitted id uses launcher config', true, fixtureReport.steps[2].verification.omitted_runtime_profile_id_uses_launcher_config);
assertEqual('fixture activation preflight supplied mismatch refused', true, fixtureReport.steps[2].verification.supplied_mismatched_runtime_profile_id_refused);
assertEqual('fixture runtime local activation sample type', 'zlar-protected-records-runtime-local-activation-artifact-verification-v1', fixtureReport.steps[3].verification.verification_type);
assertEqual('fixture runtime local activation evidence model', 'local-disposable-runtime-activation-fixture', fixtureReport.steps[3].verification.evidence_model);
assertEqual('fixture runtime local activation identity authority', 'launcher-owned-service-config', fixtureReport.steps[3].verification.runtime_profile_identity_authority_source);
assertEqual('fixture runtime local activation omitted id uses launcher config', true, fixtureReport.steps[3].verification.omitted_runtime_profile_id_uses_launcher_config);
assertEqual('fixture runtime local activation supplied mismatch refused', true, fixtureReport.steps[3].verification.supplied_mismatched_runtime_profile_id_refused);
assertEqual('fixture runtime local activation applied true', true, fixtureReport.steps[3].verification.local_activation_applied);
assertEqual('fixture runtime local activation disposable config true', true, fixtureReport.steps[3].verification.disposable_runtime_config_written);
assertEqual('fixture runtime local activation persistent config false', false, fixtureReport.steps[3].verification.persistent_runtime_config_written);
assertEqual('fixture runtime local activation hook config false', false, fixtureReport.steps[3].verification.hook_configuration_written);
assertEqual('fixture runtime local activation service started true', true, fixtureReport.steps[3].verification.runtime_service_started);
assertEqual('fixture runtime local activation missing receipt refused true', true, fixtureReport.steps[3].verification.missing_receipt_refused);
assertEqual('fixture runtime local activation wrong runtime profile id refused true', true, fixtureReport.steps[3].verification.wrong_runtime_profile_id_refused);
assertEqual('fixture runtime local activation direct api with receipt refused true', true, fixtureReport.steps[3].verification.direct_api_with_receipt_refused);
assertEqual('fixture embedded runtime local activation run', true, fixtureReport.steps[0].verification.runtime_local_activation.run_in_proof_pack);
assertEqual('fixture embedded runtime local activation active profile selected', true, fixtureReport.steps[0].verification.runtime_local_activation.active_profile_selection.selected);
assertEqual('fixture embedded runtime local activation active profile scope', 'local-disposable-proof-harness', fixtureReport.steps[0].verification.runtime_local_activation.active_profile_selection.selection_scope);
assertEqual('fixture embedded runtime local activation active profile status before selection', 'sample_not_active', fixtureReport.steps[0].verification.runtime_local_activation.active_profile_selection.profile_status_before_selection);
assertEqual('fixture embedded runtime local activation active profile no latest', false, fixtureReport.steps[0].verification.runtime_local_activation.active_profile_selection.selects_latest_profile);
assertEqual('fixture embedded runtime local activation active profile no live check', false, fixtureReport.steps[0].verification.runtime_local_activation.active_profile_selection.live_runtime_profile_checked);
assertEqual('fixture embedded runtime local activation active profile no persistent install', false, fixtureReport.steps[0].verification.runtime_local_activation.active_profile_selection.persistent_runtime_profile_installed);
assertEqual('fixture embedded runtime local activation identity authority', 'launcher-owned-service-config', fixtureReport.steps[0].verification.runtime_local_activation.runtime_profile_identity_authority_source);
assertEqual('fixture embedded runtime local activation omitted id uses launcher config', true, fixtureReport.steps[0].verification.runtime_local_activation.omitted_runtime_profile_id_uses_launcher_config);
assertEqual('fixture embedded runtime local activation applied', true, fixtureReport.steps[0].verification.runtime_local_activation.local_activation_applied);
assertEqual('fixture embedded runtime local activation disposable config true', true, fixtureReport.steps[0].verification.runtime_local_activation.disposable_runtime_config_written);
assertEqual('fixture embedded runtime local activation persistent config false', false, fixtureReport.steps[0].verification.runtime_local_activation.persistent_runtime_config_written);
assertEqual('fixture embedded runtime local activation hook config false', false, fixtureReport.steps[0].verification.runtime_local_activation.hook_configuration_written);
assertEqual('fixture embedded runtime local activation service started true', true, fixtureReport.steps[0].verification.runtime_local_activation.runtime_service_started);
assertEqual('fixture embedded runtime local activation missing receipt refused true', true, fixtureReport.steps[0].verification.runtime_local_activation.missing_receipt_refused);
assertEqual('fixture embedded runtime local activation wrong runtime profile id refused true', true, fixtureReport.steps[0].verification.runtime_local_activation.wrong_runtime_profile_id_refused);
assertEqual('fixture embedded runtime profile installation run', true, fixtureReport.steps[0].verification.runtime_profile_installation.run_in_proof_pack);
assertEqual('fixture embedded runtime profile installation selected', true, fixtureReport.steps[0].verification.runtime_profile_installation.disposable_profile_selection.profile_selected_from_install_root);
assertEqual('fixture embedded runtime profile installation selected by id and sha', true, fixtureReport.steps[0].verification.runtime_profile_installation.disposable_profile_selection.selected_by_explicit_id_and_sha);
assertEqual('fixture embedded runtime profile installation no latest', false, fixtureReport.steps[0].verification.runtime_profile_installation.disposable_profile_selection.selects_latest_profile);
assertEqual('fixture embedded runtime profile installation request guard refused', true, fixtureReport.steps[0].verification.runtime_profile_installation.request_authority_guard_summary.all_refused_before_mutation);
assertEqual('fixture embedded runtime profile installation state delta zero', 0, fixtureReport.steps[0].verification.runtime_profile_installation.request_authority_guard_summary.state_entry_count_delta_total);
assertEqual('fixture embedded runtime profile installation identity authority', 'launcher-owned-service-config', fixtureReport.steps[0].verification.runtime_profile_installation.runtime_profile_identity_authority_source);
assertEqual('fixture embedded runtime profile installation omitted id uses launcher config', true, fixtureReport.steps[0].verification.runtime_profile_installation.omitted_runtime_profile_id_uses_launcher_config);
assertEqual('fixture embedded runtime profile installation applied', true, fixtureReport.steps[0].verification.runtime_profile_installation.disposable_profile_installation_applied);
assertEqual('fixture embedded runtime profile installation no persistent install', false, fixtureReport.steps[0].verification.runtime_profile_installation.persistent_runtime_profile_installed);
assertEqual('fixture embedded runtime profile installation no hook config', false, fixtureReport.steps[0].verification.runtime_profile_installation.hook_configuration_written);
assertEqual('fixture runtime profile installation sample type', 'zlar-protected-records-runtime-profile-installation-artifact-verification-v1', fixtureReport.steps[4].verification.verification_type);
assertEqual('fixture runtime profile installation evidence model', 'local-disposable-runtime-profile-installation-fixture', fixtureReport.steps[4].verification.evidence_model);
assertEqual('fixture runtime profile installation identity authority', 'launcher-owned-service-config', fixtureReport.steps[4].verification.runtime_profile_identity_authority_source);
assertEqual('fixture runtime profile installation omitted id uses launcher config', true, fixtureReport.steps[4].verification.omitted_runtime_profile_id_uses_launcher_config);
assertEqual('fixture runtime profile installation supplied mismatch refused', true, fixtureReport.steps[4].verification.supplied_mismatched_runtime_profile_id_refused);
assertEqual('fixture runtime profile installation applied true', true, fixtureReport.steps[4].verification.disposable_profile_installation_applied);
assertEqual('fixture runtime profile installation selected true', true, fixtureReport.steps[4].verification.profile_selected_from_install_root);
assertEqual('fixture runtime profile installation selected by id and sha true', true, fixtureReport.steps[4].verification.selected_by_explicit_id_and_sha);
assertEqual('fixture runtime profile installation request guard refused true', true, fixtureReport.steps[4].verification.request_authority_guard_refused);
assertEqual('fixture runtime profile installation wrong runtime profile id refused true', true, fixtureReport.steps[4].verification.wrong_runtime_profile_id_refused);
assertEqual('fixture runtime profile installation no latest true', false, fixtureReport.steps[4].verification.selects_latest_profile);
assertEqual('fixture runtime profile installation no persistent install true', false, fixtureReport.steps[4].verification.persistent_runtime_profile_installed);
assertEqual('fixture runtime profile installation no hook config true', false, fixtureReport.steps[4].verification.hook_configuration_written);
assertEqual('fixture installed runtime profile preflight sample type', 'zlar-protected-records-installed-runtime-profile-preflight-artifact-verification-v1', fixtureReport.steps[5].verification.verification_type);
assertEqual('fixture installed runtime profile preflight evidence model', 'supplied-installed-runtime-profile-root-read-only', fixtureReport.steps[5].verification.evidence_model);
assertEqual('fixture installed runtime profile preflight read only true', true, fixtureReport.steps[5].verification.read_only);
assertEqual('fixture installed runtime profile preflight installed profile read true', true, fixtureReport.steps[5].verification.installed_profile_read);
assertEqual('fixture installed runtime profile preflight selected true', true, fixtureReport.steps[5].verification.profile_selected_from_install_root);
assertEqual('fixture installed runtime profile preflight selected by id and sha true', true, fixtureReport.steps[5].verification.selected_by_explicit_id_and_sha);
assertEqual('fixture installed runtime profile preflight no latest true', false, fixtureReport.steps[5].verification.selects_latest_profile);
assertEqual('fixture installed runtime profile preflight no install true', false, fixtureReport.steps[5].verification.runtime_profile_installation_performed);
assertEqual('fixture installed runtime profile preflight no activation true', false, fixtureReport.steps[5].verification.runtime_profile_activation_performed);
assertEqual('fixture installed runtime profile preflight recognition contract preserved true', true, fixtureReport.steps[5].verification.recognition_contract_preserved);
assertEqual('fixture installed runtime profile preflight recognition boundary', 'service-configured-recognition-rule', fixtureReport.steps[5].verification.recognition_boundary);
assertEqual('fixture installed runtime profile preflight mutation route', 'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation', fixtureReport.steps[5].verification.mutation_authoritative_route);
assertEqual('fixture installed runtime profile preflight recognition rule not agent supplied', false, fixtureReport.steps[5].verification.recognition_rule_supplied_by_agent);
assertEqual('fixture installed runtime profile preflight no downstream refusal true', false, fixtureReport.steps[5].verification.downstream_refusal_proven);
assertEqual('fixture installed runtime profile preflight no current machine governance true', false, fixtureReport.steps[5].verification.current_machine_governance_proven);
assertEqual('fixture installed runtime profile recognition proof verified', true, fixtureReport.counts.installed_runtime_profile_recognition_proof_verified);
assertEqual('fixture installed runtime profile recognition boarded', true, fixtureReport.counts.installed_runtime_profile_recognition_recognized_write_boarded);
assertEqual('fixture installed runtime profile recognition refusal cases', 18, fixtureReport.counts.installed_runtime_profile_recognition_refusal_case_count);
assertEqual('fixture installed runtime profile recognition refusals before mutation', true, fixtureReport.counts.installed_runtime_profile_recognition_all_refusals_before_mutation);
assertEqual('fixture installed runtime profile recognition source preflight no downstream proof', false, fixtureReport.counts.installed_runtime_profile_recognition_source_preflight_downstream_refusal_proven);
assertEqual('fixture installed runtime profile recognition no install', false, fixtureReport.counts.installed_runtime_profile_recognition_install_performed);
assertEqual('fixture installed runtime profile recognition no activation', false, fixtureReport.counts.installed_runtime_profile_recognition_activation_performed);
assertEqual('fixture installed runtime profile recognition no runtime service start', false, fixtureReport.counts.installed_runtime_profile_recognition_runtime_service_started);
assertEqual('fixture installed runtime profile recognition no current-machine governance', false, fixtureReport.counts.installed_runtime_profile_recognition_current_machine_governance_proven);
assertEqual('fixture installed runtime profile recognition no production downstream', false, fixtureReport.counts.installed_runtime_profile_recognition_production_downstream_recognition);
assertEqual('fixture installed runtime profile recognition proof type', 'zlar-protected-records-installed-runtime-profile-recognition-proof-v1', fixtureReport.steps[6].proof.proof_type);
assertEqual('fixture installed runtime profile recognition proof evidence model', 'local-hermetic-installed-runtime-profile-recognition-fixture', fixtureReport.steps[6].proof.evidence_model);
assertEqual('fixture installed runtime profile recognition proof live false', false, fixtureReport.steps[6].proof.live_probing);
assertEqual('fixture installed runtime profile recognition source preflight verified', true, fixtureReport.steps[6].proof.source_preflight.verified);
assertEqual('fixture installed runtime profile recognition source preflight no downstream proof', false, fixtureReport.steps[6].proof.source_preflight.downstream_refusal_proven);
assertEqual('fixture installed runtime profile recognition source preflight no current-machine governance', false, fixtureReport.steps[6].proof.source_preflight.current_machine_governance_proven);
assertEqual('fixture installed runtime profile recognition boarded exactly once', true, fixtureReport.steps[6].proof.recognized_boarding.boarded);
assertEqual('fixture installed runtime profile recognition marker final count', 1, fixtureReport.steps[6].proof.marker.final_state_entry_count);
assertEqual('fixture installed runtime profile recognition refusal delta total', 0, fixtureReport.steps[6].proof.marker.refusal_state_entry_count_delta_total);
assertEqual('fixture installed runtime profile recognition proof no runtime service start', false, fixtureReport.steps[6].proof.proof_boundary.runtime_service_started);
assertEqual('fixture installed runtime profile recognition proof no current-machine governance', false, fixtureReport.steps[6].proof.proof_boundary.current_machine_governance_proven);
assertEqual('fixture installed runtime profile recognition proof no production downstream', false, fixtureReport.steps[6].proof.proof_boundary.production_downstream_recognition);
assertEqual('fixture installed runtime profile service proof verified', true, fixtureReport.counts.installed_runtime_profile_service_proof_verified);
assertEqual('fixture installed runtime profile service runtime service started', true, fixtureReport.counts.installed_runtime_profile_service_runtime_service_started);
assertEqual('fixture installed runtime profile service disposable config written', true, fixtureReport.counts.installed_runtime_profile_service_disposable_runtime_config_written);
assertEqual('fixture installed runtime profile service persistent config false', false, fixtureReport.counts.installed_runtime_profile_service_persistent_runtime_config_written);
assertEqual('fixture installed runtime profile service config path not exposed', false, fixtureReport.counts.installed_runtime_profile_service_config_path_exposed_to_request_stream);
assertEqual('fixture installed runtime profile service recognition bound', true, fixtureReport.counts.installed_runtime_profile_service_recognition_rule_bound_to_selected_profile);
assert('fixture installed runtime profile recognition contract digest sha present', /^[a-f0-9]{64}$/.test(fixtureReport.counts.installed_runtime_profile_preflight_recognition_contract_sha256));
assertEqual('fixture service recognition contract digest bound to preflight', fixtureReport.counts.installed_runtime_profile_preflight_recognition_contract_sha256, fixtureReport.counts.installed_runtime_profile_service_recognition_contract_sha256);
assertEqual('fixture installed runtime profile service boarded', true, fixtureReport.counts.installed_runtime_profile_service_recognized_write_boarded);
assertEqual('fixture installed runtime profile service replay cases', 2, fixtureReport.counts.installed_runtime_profile_service_replay_case_count);
assertEqual('fixture installed runtime profile service same-process replay refused', true, fixtureReport.counts.installed_runtime_profile_service_same_process_replay_refused);
assertEqual('fixture installed runtime profile service restart replay refused', true, fixtureReport.counts.installed_runtime_profile_service_restart_replay_refused);
assertEqual('fixture installed runtime profile service replay before mutation', true, fixtureReport.counts.installed_runtime_profile_service_all_replay_refusals_before_mutation);
assertEqual('fixture installed runtime profile service partial-commit cases', 2, fixtureReport.counts.installed_runtime_profile_service_consumed_store_integrity_case_count);
assertEqual('fixture installed runtime profile service consumed-store proven', true, fixtureReport.counts.installed_runtime_profile_service_consumed_store_integrity_refusals_proven);
assertEqual('fixture installed runtime profile service consumed-store before mutation', true, fixtureReport.counts.installed_runtime_profile_service_all_consumed_store_integrity_refusals_before_mutation);
assertEqual('fixture installed runtime profile service single-host rollback true', true, fixtureReport.counts.installed_runtime_profile_service_single_host_consumed_store_rollback_detection);
assertEqual('fixture installed runtime profile service witness source', 'launcher-owned-local-proof-witness', fixtureReport.counts.installed_runtime_profile_service_consumed_store_witness_source);
assertEqual('fixture installed runtime profile service store-anchor rollback cases', 1, fixtureReport.counts.installed_runtime_profile_service_store_and_anchor_rollback_case_count);
assertEqual('fixture installed runtime profile service store-anchor rollback proven', true, fixtureReport.counts.installed_runtime_profile_service_store_and_anchor_joint_rollback_refusals_proven);
assertEqual('fixture installed runtime profile service store-anchor rollback before mutation', true, fixtureReport.counts.installed_runtime_profile_service_all_store_and_anchor_rollback_refusals_before_mutation);
assertEqual('fixture installed runtime profile service joint store-anchor rollback true', true, fixtureReport.counts.installed_runtime_profile_service_store_and_anchor_joint_rollback_detection);
assertEqual('fixture installed runtime profile service joint store-anchor-witness rollback false', false, fixtureReport.counts.installed_runtime_profile_service_store_anchor_and_witness_joint_rollback_detection);
assertEqual('fixture installed runtime profile service recognition refusals split', 18, fixtureReport.counts.installed_runtime_profile_service_recognition_refusal_case_count);
assertEqual('fixture installed runtime profile service authority refusals split', 5, fixtureReport.counts.installed_runtime_profile_service_authority_refusal_case_count);
assertEqual('fixture installed runtime profile service signed-payload replay refused', true, fixtureReport.counts.installed_runtime_profile_service_same_process_signed_payload_replay_refused);
assertEqual('fixture installed runtime profile service consumed-grant replay refused', true, fixtureReport.counts.installed_runtime_profile_service_restart_consumed_authority_grant_refused);
assertEqual('fixture installed runtime profile service replay identities separate', true, fixtureReport.counts.installed_runtime_profile_service_replay_identities_separate);
assertEqual('fixture installed runtime profile service state-append burn observed', true, fixtureReport.counts.installed_runtime_profile_service_state_append_after_grant_commit_burn_observed);
assertEqual('fixture installed runtime profile service metadata burn observed', true, fixtureReport.counts.installed_runtime_profile_service_metadata_partial_commit_burn_observed);
assertEqual('fixture installed runtime profile service witness-ahead rollback refused', true, fixtureReport.counts.installed_runtime_profile_service_store_and_anchor_rollback_refused_while_witness_ahead);
assertEqual('fixture installed runtime profile service joint rollback reopens reuse', true, fixtureReport.counts.installed_runtime_profile_service_joint_rollback_reopened_authority_grant_reuse);
assertEqual('fixture installed runtime profile service local rightful path', true, fixtureReport.counts.installed_runtime_profile_service_fixture_rightful_issuance_path_evidenced);
assertEqual('fixture installed runtime profile service refusal cases', 18, fixtureReport.counts.installed_runtime_profile_service_refusal_case_count);
assertEqual('fixture installed runtime profile service refusals before mutation', true, fixtureReport.counts.installed_runtime_profile_service_all_refusals_before_mutation);
assertEqual('fixture installed runtime profile service source preflight no downstream proof', false, fixtureReport.counts.installed_runtime_profile_service_source_preflight_downstream_refusal_proven);
assertEqual('fixture installed runtime profile service no install', false, fixtureReport.counts.installed_runtime_profile_service_install_performed);
assertEqual('fixture installed runtime profile service no activation', false, fixtureReport.counts.installed_runtime_profile_service_activation_performed);
assertEqual('fixture installed runtime profile service no current-machine governance', false, fixtureReport.counts.installed_runtime_profile_service_current_machine_governance_proven);
assertEqual('fixture installed runtime profile service no production downstream', false, fixtureReport.counts.installed_runtime_profile_service_production_downstream_recognition);
assertEqual('fixture installed runtime profile service artifact verification verified', true, fixtureReport.counts.installed_runtime_profile_service_artifact_verification_verified);
assert('fixture installed runtime profile service artifact verification sha present', /^[a-f0-9]{64}$/.test(fixtureReport.counts.installed_runtime_profile_service_artifact_verification_body_sha256));
assert('fixture installed runtime profile service artifact verification taxonomy sha present', /^[a-f0-9]{64}$/.test(fixtureReport.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256));
assertEqual('fixture service artifact verification recognition contract digest bound', fixtureReport.counts.installed_runtime_profile_service_recognition_contract_sha256, fixtureReport.counts.installed_runtime_profile_service_artifact_verification_recognition_contract_sha256);
assertEqual('fixture installed runtime profile service artifact verification payload type', 'zlar-protected-records-installed-runtime-profile-service-proof-v1', fixtureReport.counts.installed_runtime_profile_service_artifact_verification_payload_type);
assertEqual('fixture installed runtime profile service artifact verification runtime service started', true, fixtureReport.counts.installed_runtime_profile_service_artifact_verification_runtime_service_started);
assertEqual('fixture installed runtime profile service artifact verification boarded', true, fixtureReport.counts.installed_runtime_profile_service_artifact_verification_recognized_write_boarded);
assertEqual('fixture installed runtime profile service artifact verification restart replay refused', true, fixtureReport.counts.installed_runtime_profile_service_artifact_verification_restart_replay_refused);
assertEqual('fixture installed runtime profile service artifact verification partial-commit cases', 2, fixtureReport.counts.installed_runtime_profile_service_artifact_verification_consumed_store_integrity_case_count);
assertEqual('fixture installed runtime profile service artifact verification store-anchor cases', 1, fixtureReport.counts.installed_runtime_profile_service_artifact_verification_store_and_anchor_rollback_case_count);
assertEqual('fixture installed runtime profile service artifact verification joint store-anchor rollback true', true, fixtureReport.counts.installed_runtime_profile_service_artifact_verification_store_and_anchor_joint_rollback_detection);
assertEqual('fixture installed runtime profile service artifact verification joint store-anchor-witness rollback false', false, fixtureReport.counts.installed_runtime_profile_service_artifact_verification_store_anchor_and_witness_joint_rollback_detection);
assertEqual('fixture installed runtime profile service artifact verification refusals before mutation', true, fixtureReport.counts.installed_runtime_profile_service_artifact_verification_all_refusals_before_mutation);
assertEqual('fixture installed runtime profile service artifact verification no current-machine governance', false, fixtureReport.counts.installed_runtime_profile_service_artifact_verification_current_machine_governance_proven);
assertEqual('fixture installed runtime profile service artifact verification no production downstream', false, fixtureReport.counts.installed_runtime_profile_service_artifact_verification_production_downstream_recognition);
assertEqual('fixture service artifact recognition refusals split', 18, fixtureReport.counts.installed_runtime_profile_service_artifact_verification_recognition_refusal_case_count);
assertEqual('fixture service artifact authority refusals split', 5, fixtureReport.counts.installed_runtime_profile_service_artifact_verification_authority_refusal_case_count);
assertEqual('fixture installed runtime profile service proof type', 'zlar-protected-records-installed-runtime-profile-service-proof-v1', fixtureReport.steps[7].proof.proof_type);
assertEqual('fixture installed runtime profile service proof evidence model', 'local-disposable-installed-runtime-profile-service-proof', fixtureReport.steps[7].proof.evidence_model);
assertEqual('fixture installed runtime profile service proof live false', false, fixtureReport.steps[7].proof.live_probing);
assertEqual('fixture installed runtime profile service source preflight verified', true, fixtureReport.steps[7].proof.source_preflight.verified);
assertEqual('fixture installed runtime profile service source preflight no downstream proof', false, fixtureReport.steps[7].proof.source_preflight.downstream_refusal_proven);
assertEqual('fixture installed runtime profile service source preflight no current-machine governance', false, fixtureReport.steps[7].proof.source_preflight.current_machine_governance_proven);
assertEqual('fixture installed runtime profile service boarded exactly once', true, fixtureReport.steps[7].proof.recognized_boarding.boarded);
assertEqual('fixture installed runtime profile service primary state append count', 1, fixtureReport.steps[7].proof.marker.primary_recognized_state_append_count);
assertEqual('fixture installed runtime profile service recognition refusal state appends', 0, fixtureReport.steps[7].proof.marker.recognition_refusal_state_append_count);
assertEqual('fixture installed runtime profile service authority refusal state appends', 0, fixtureReport.steps[7].proof.marker.authority_refusal_state_append_count);
assertEqual('fixture installed runtime profile service replay refusal state appends', 0, fixtureReport.steps[7].proof.marker.replay_refusal_state_append_count);
assertEqual('fixture installed runtime profile service partial commit state appends', 0, fixtureReport.steps[7].proof.marker.partial_commit_state_append_count);
assertEqual('fixture installed runtime profile service proof runtime service start', true, fixtureReport.steps[7].proof.service_boundary.runtime_service_started);
assertEqual('fixture installed runtime profile service proof same-process signed-payload replay refused', true, fixtureReport.steps[7].proof.proof_boundary.same_process_signed_payload_replay_refused);
assertEqual('fixture installed runtime profile service proof restart consumed-grant refused', true, fixtureReport.steps[7].proof.proof_boundary.restart_consumed_authority_grant_refused);
assertEqual('fixture installed runtime profile service proof partial-commit cases', 2, fixtureReport.steps[7].proof.partial_commit_cases.length);
assertEqual('fixture installed runtime profile service proof store-anchor rollback case present', 'store_and_anchor_joint_rollback_refused_by_witness_before_runtime_mutation', fixtureReport.steps[7].proof.joint_rollback_case.store_and_anchor_only.case_id);
assertEqual('fixture installed runtime profile service proof store-anchor rollback refused while witness ahead', true, fixtureReport.steps[7].proof.proof_boundary.store_and_anchor_rollback_refused_while_witness_ahead);
assertEqual('fixture installed runtime profile service proof joint store-anchor-witness rollback false', false, fixtureReport.steps[7].proof.proof_boundary.store_anchor_and_witness_joint_rollback_detection);
assertEqual('fixture installed runtime profile service proof no persistent runtime config', false, fixtureReport.steps[7].proof.service_boundary.persistent_runtime_config_written);
assertEqual('fixture installed runtime profile service proof no current-machine governance', false, fixtureReport.steps[7].proof.proof_boundary.current_machine_governance_proven);
assertEqual('fixture installed runtime profile service proof no production downstream', false, fixtureReport.steps[7].proof.proof_boundary.production_downstream_recognition);
assertEqual('fixture installed runtime profile service artifact verification type', 'zlar-protected-records-installed-runtime-profile-service-proof-artifact-verification-v1', fixtureReport.steps[8].verification.verification_type);
assertEqual('fixture installed runtime profile service artifact verification verified true', true, fixtureReport.steps[8].verification.verified);
assertEqual('fixture installed runtime profile service artifact verification payload matches proof', fixtureReport.steps[7].proof.proof_type, fixtureReport.steps[8].verification.payload_type);
assertEqual('fixture installed runtime profile service artifact verification structural integrity', true, fixtureReport.steps[8].verification.structural_self_integrity_verified);
assertEqual('fixture installed runtime profile service artifact verification taxonomy hash bound', fixtureReport.steps[8].verification.recognition_refusal_taxonomy_sha256, fixtureReport.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256);
assertEqual('fixture installed runtime profile service artifact verification recognition cases', 18, fixtureReport.steps[8].verification.recognition_refusal_case_count);
assertEqual('fixture installed runtime profile service artifact verification authority cases', 5, fixtureReport.steps[8].verification.authority_refusal_case_count);
assertEqual('fixture installed runtime profile service artifact verification current-machine false', false, fixtureReport.steps[8].verification.current_machine_governance_proven);
assertEqual('fixture installed runtime profile service artifact verification production downstream false', false, fixtureReport.steps[8].verification.production_downstream_recognition);
assertEqual('fixture installed runtime profile terminal chain type', 'zlar-protected-records-installed-runtime-profile-terminal-chain-v1', fixtureReport.steps[9].chain.chain_type);
assertEqual('fixture installed runtime profile terminal chain fresh model', 'fresh-local-disposable-installed-runtime-profile-terminal-chain', fixtureReport.steps[9].chain.evidence_model);
assertEqual('fixture installed runtime profile terminal chain root preflighted', true, fixtureReport.steps[9].chain.terminal_chain.generated_installed_root_preflighted);
assertEqual('fixture installed runtime profile terminal chain generated preflight consumed', true, fixtureReport.steps[9].chain.terminal_chain.generated_preflight_artifact_consumed_by_service_proof);
assertEqual('fixture installed runtime profile terminal chain service proof bound', true, fixtureReport.steps[9].chain.terminal_chain.service_proof_bound_to_generated_preflight);
assertEqual('fixture installed runtime profile terminal chain boarded', true, fixtureReport.steps[9].chain.terminal_chain.recognized_write_boarded);
assertEqual('fixture installed runtime profile terminal chain missing receipt refused', true, fixtureReport.steps[9].chain.terminal_chain.missing_receipt_refused_before_mutation);
assertEqual('fixture installed runtime profile terminal chain recognition refusals before mutation', true, fixtureReport.steps[9].chain.terminal_chain.all_required_recognition_refusals_before_mutation);
assertEqual('fixture installed runtime profile terminal chain authority refusals before consumption', true, fixtureReport.steps[9].chain.terminal_chain.all_required_authority_refusals_before_consumption_and_mutation);
assertEqual('fixture terminal chain recognition refusals split', 18, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_case_count);
assertEqual('fixture terminal chain authority refusals split', 5, fixtureReport.counts.installed_runtime_profile_terminal_chain_authority_refusal_case_count);
assertEqual('fixture terminal chain signed-payload replay refused', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_same_process_signed_payload_replay_refused);
assertEqual('fixture terminal chain consumed-grant replay refused', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_restart_consumed_authority_grant_refused);
assertEqual('fixture terminal chain replay identities separate', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_replay_identities_separate);
assertEqual('fixture terminal chain state-append burn observed', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_state_append_after_grant_commit_burn_observed);
assertEqual('fixture terminal chain metadata burn observed', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_metadata_partial_commit_burn_observed);
assertEqual('fixture terminal chain joint rollback remains undetected', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_store_anchor_and_witness_joint_rollback_detection);
assertEqual('fixture terminal chain local rightful path', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_fixture_rightful_issuance_path_evidenced);
assertEqual('fixture installed runtime profile terminal chain refusal taxonomy hash bound', fixtureReport.steps[9].chain.generated_service_proof.recognition_refusal_taxonomy_sha256, fixtureReport.steps[9].chain.terminal_chain.recognition_refusal_taxonomy_sha256);
assert('fixture installed runtime profile terminal chain refusal taxonomy sha present', /^[a-f0-9]{64}$/.test(fixtureReport.steps[9].chain.terminal_chain.recognition_refusal_taxonomy_sha256));
assertEqual('fixture installed runtime profile terminal chain named refusals hash bound', fixtureReport.steps[9].chain.generated_service_proof.named_receipt_refusals_sha256, fixtureReport.steps[9].chain.terminal_chain.named_receipt_refusals_sha256);
assert('fixture installed runtime profile terminal chain named refusals sha present', /^[a-f0-9]{64}$/.test(fixtureReport.steps[9].chain.terminal_chain.named_receipt_refusals_sha256));
assertEqual('fixture installed runtime profile terminal chain recognition refusal groups hash bound', fixtureReport.steps[9].chain.generated_service_proof.recognition_refusal_groups_sha256, fixtureReport.steps[9].chain.terminal_chain.recognition_refusal_groups_sha256);
assert('fixture installed runtime profile terminal chain recognition refusal groups sha present', /^[a-f0-9]{64}$/.test(fixtureReport.steps[9].chain.terminal_chain.recognition_refusal_groups_sha256));
assertEqual('fixture installed runtime profile terminal chain no usable authority group', true, fixtureReport.steps[9].chain.terminal_chain.recognition_refusal_groups.no_usable_recognized_receipt_authority.all_refused_before_mutation);
assertEqual('fixture installed runtime profile terminal chain scope mismatch group', true, fixtureReport.steps[9].chain.terminal_chain.recognition_refusal_groups.recognized_receipt_scope_mismatch.all_refused_before_mutation);
assertEqual('fixture installed runtime profile terminal chain route/request authority group', true, fixtureReport.steps[9].chain.terminal_chain.recognition_refusal_groups.route_or_request_authority_material_refused.all_refused_before_mutation);
assertEqual('fixture installed runtime profile terminal chain deployment-profile authority mirror preserved', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved);
assertEqual('fixture installed runtime profile terminal chain deployment-profile authority mirror profile sha matches', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_profile_sha_matches);
assertEqual('fixture installed runtime profile terminal chain deployment-profile authority case count', 5, fixtureReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count);
assertEqual(
  'fixture installed runtime profile terminal chain deployment-profile authority case IDs',
  JSON.stringify(EXPECTED_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASE_IDS),
  JSON.stringify(fixtureReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids)
);
assertEqual('fixture installed runtime profile terminal chain deployment-profile authority before service proof', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof);
assertEqual('fixture installed runtime profile terminal chain deployment-profile authority service proof not started', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started);
assertEqual('fixture installed runtime profile terminal chain deployment-profile authority no production authority', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority);
assertEqual('fixture installed runtime profile terminal chain trusted registry binding preserved', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved);
assertEqual('fixture installed runtime profile terminal chain trusted registry verdict', 'RECOGNIZED', fixtureReport.steps[9].chain.terminal_chain.trusted_issuer_registry_recognition_binding.verdict);
assertEqual('fixture installed runtime profile terminal chain trusted registry rule evaluated', true, fixtureReport.steps[9].chain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_to_recognition_rule_evaluated);
assert('fixture installed runtime profile terminal chain trusted registry fixture contract sha present', /^[a-f0-9]{64}$/.test(fixtureReport.steps[9].chain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_fixture_contract_sha256));
assert('fixture installed runtime profile terminal chain trusted registry receipt contract sha present', /^[a-f0-9]{64}$/.test(fixtureReport.steps[9].chain.terminal_chain.trusted_issuer_registry_recognition_binding.receipt_payload_contract_sha256));
assertEqual('fixture installed runtime profile terminal chain trusted registry receipt contract hash bound', true, fixtureReport.steps[9].chain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_contract_hash_bound);
assertEqual('fixture installed runtime profile terminal chain trusted registry no public key material embedded', false, fixtureReport.steps[9].chain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_public_key_material_included);
assertEqual('fixture installed runtime profile terminal chain trusted registry no receipt envelope embedded', false, fixtureReport.steps[9].chain.terminal_chain.trusted_issuer_registry_recognition_binding.receipt_envelope_included);
assertEqual('fixture installed runtime profile terminal chain trusted registry no artifact-only crypto reconstruction', false, fixtureReport.steps[9].chain.terminal_chain.trusted_issuer_registry_recognition_binding.cryptographic_evidence_reproducible_from_artifact);
assertEqual('fixture installed runtime profile terminal chain trusted registry binding hash bound', fixtureReport.steps[9].chain.terminal_chain.trusted_issuer_registry_recognition_binding_sha256, fixtureReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256);
assertEqual('fixture installed runtime profile terminal chain trusted registry refusal count', 2, fixtureReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count);
assertEqual('fixture installed runtime profile terminal chain trusted registry all refusals refused', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused);
assertEqual(
  'fixture installed runtime profile terminal chain trusted registry refusal case IDs',
  JSON.stringify(EXPECTED_TRUSTED_ISSUER_REGISTRY_REFUSAL_CASE_IDS),
  JSON.stringify(fixtureReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids)
);
assertEqual(
  'fixture installed runtime profile terminal chain trusted registry refusal reason codes',
  JSON.stringify(EXPECTED_TRUSTED_ISSUER_REGISTRY_REFUSAL_REASON_CODES),
  JSON.stringify(fixtureReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes)
);
assertEqual(
  'fixture installed runtime profile terminal chain trusted registry refusal hash bound',
  fixtureReport.steps[9].chain.terminal_chain.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals_sha256,
  fixtureReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256
);
assert('fixture installed runtime profile terminal chain trusted registry refusal sha present', /^[a-f0-9]{64}$/.test(fixtureReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256));
assertEqual('fixture installed runtime profile terminal chain trusted registry no live registry', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_state_proven);
assertEqual('fixture installed runtime profile terminal chain trusted registry no key custody', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_key_custody_proven);
assertEqual('fixture installed runtime profile terminal chain trusted registry no revocation truth', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_revocation_truth_proven);
assertEqual('fixture installed runtime profile terminal chain trusted registry no production authority', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_authority);
assertEqual('fixture installed runtime profile terminal chain trusted registry no current-machine governance', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_current_machine_governance_proven);
assertEqual('fixture installed runtime profile terminal chain receipt path evidence preserved', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_preserved);
assertEqual('fixture installed runtime profile terminal chain receipt path sha bound', fixtureReport.steps[9].chain.terminal_chain.recognized_receipt_path_evidence_sha256, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256);
assert('fixture installed runtime profile terminal chain receipt path sha present', /^[a-f0-9]{64}$/.test(fixtureReport.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256));
assertEqual('fixture installed runtime profile terminal chain receipt path source binding', fixtureReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256);
assertEqual('fixture installed runtime profile terminal chain receipt path source binding matches registry', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_matches_trusted_registry_binding);
assertEqual('fixture installed runtime profile terminal chain receipt path selected profile bound', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_selected_profile_hash_bound);
assertEqual('fixture installed runtime profile terminal chain receipt path recognition contract bound', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_recognition_contract_hash_bound);
assertEqual('fixture installed runtime profile terminal chain receipt path service artifact bound', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_service_artifact_hash_bound);
assertEqual('fixture installed runtime profile terminal chain receipt path no public key material embedded', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_public_key_material_included);
assertEqual('fixture installed runtime profile terminal chain receipt path no receipt envelope embedded', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_receipt_envelope_included);
assertEqual('fixture installed runtime profile terminal chain receipt path no live registry', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_live_registry_state);
assertEqual('fixture installed runtime profile terminal chain receipt path no key custody', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_key_custody_proven);
assertEqual('fixture installed runtime profile terminal chain receipt path no revocation truth', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_revocation_truth_proven);
assertEqual('fixture installed runtime profile terminal chain receipt path no production recognition', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_production_downstream_recognition_proven);
assertEqual('fixture installed runtime profile terminal chain receipt path no public attestation', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_public_external_attestation);
assertEqual('fixture installed runtime profile terminal chain receipt path no current-machine governance', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_current_machine_governance_proven);
assertEqual('fixture installed runtime profile terminal chain nested binding preserved', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved);
assertEqual('fixture installed runtime profile terminal chain nested preflight type', 'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1', fixtureReport.counts.installed_runtime_profile_terminal_chain_nested_preflight_artifact_type);
assertEqual('fixture installed runtime profile terminal chain nested service type', 'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1', fixtureReport.counts.installed_runtime_profile_terminal_chain_nested_service_proof_artifact_type);
assertEqual('fixture installed runtime profile terminal chain nested binding preflight hash bound', true, fixtureReport.steps[9].chain.terminal_chain.nested_artifact_binding.preflight_artifact_hash_bound);
assertEqual('fixture installed runtime profile terminal chain nested binding service hash bound', true, fixtureReport.steps[9].chain.terminal_chain.nested_artifact_binding.service_artifact_hash_bound);
assertEqual('fixture installed runtime profile terminal chain recognition group count', 3, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_count);
assertEqual('fixture installed runtime profile terminal chain recognition group case count', 18, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count);
assertEqual(
  'fixture installed runtime profile terminal chain recognition group case IDs',
  JSON.stringify(EXPECTED_RECOGNITION_REFUSAL_GROUP_CASE_IDS),
  JSON.stringify(fixtureReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids)
);
assertEqual('fixture installed runtime profile terminal chain stale named refusal', true, fixtureReport.steps[9].chain.terminal_chain.named_receipt_refusals.stale.refused_before_mutation);
assertEqual('fixture installed runtime profile terminal chain stale-or-expired named refusal', true, fixtureReport.steps[9].chain.terminal_chain.named_receipt_refusals.stale_or_expired.refused_before_mutation);
assertEqual('fixture installed runtime profile terminal chain wrong tool named refusal', true, fixtureReport.steps[9].chain.terminal_chain.named_receipt_refusals.wrong_tool.refused_before_mutation);
assertEqual('fixture installed runtime profile terminal chain observed recognition taxonomy count', 18, fixtureReport.steps[9].chain.generated_service_proof.observed_recognition_refusal_cases.length);
assertEqual('fixture installed runtime profile terminal chain no persistent install', false, fixtureReport.steps[9].chain.side_door_report.persistent_runtime_profile_installed);
assertEqual('fixture installed runtime profile terminal chain no activation', false, fixtureReport.steps[9].chain.side_door_report.runtime_profile_activation_performed);
assertEqual('fixture installed runtime profile terminal chain no current-machine governance', false, fixtureReport.steps[9].chain.side_door_report.current_machine_governance_proven);
assertEqual('fixture installed runtime profile terminal chain artifact verification type', 'zlar-protected-records-installed-runtime-profile-terminal-chain-artifact-verification-v1', fixtureReport.steps[10].verification.verification_type);
assertEqual('fixture installed runtime profile terminal chain artifact verification verified', true, fixtureReport.steps[10].verification.verified);
assertEqual('fixture terminal artifact structural self-integrity verified', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_structural_self_integrity_verified);
assertEqual('fixture terminal artifact identity requires expected sha', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_identity_match_requires_expected_sha256);
assertEqual('fixture terminal artifact expected sha matched', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_expected_body_sha256_matched);
assertEqual('fixture embedded service structural self-integrity verified', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_structural_self_integrity_verified);
assertEqual('fixture embedded service identity requires expected sha', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_identity_match_requires_expected_sha256);
assertEqual('fixture embedded service expected sha bound to terminal artifact verification', fixtureReport.steps[10].verification.embedded_service_artifact_expected_body_sha256, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_expected_body_sha256);
assertEqual('fixture embedded service expected sha matched', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_expected_body_sha256_matched);
assertEqual('fixture terminal artifact host TOCTOU remains open', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_host_filesystem_path_toctou_closed);
assertEqual('fixture installed runtime profile terminal chain artifact verification recognition refusals before mutation', true, fixtureReport.steps[10].verification.all_required_recognition_refusals_before_mutation);
assertEqual('fixture installed runtime profile terminal chain artifact verification authority refusals before consumption', true, fixtureReport.steps[10].verification.all_required_authority_refusals_before_consumption_and_mutation);
assertEqual('fixture installed runtime profile terminal chain artifact verification taxonomy hash bound', fixtureReport.steps[9].chain.terminal_chain.recognition_refusal_taxonomy_sha256, fixtureReport.steps[10].verification.recognition_refusal_taxonomy_sha256);
assertEqual('fixture installed runtime profile terminal chain artifact verification named refusals hash bound', fixtureReport.steps[9].chain.terminal_chain.named_receipt_refusals_sha256, fixtureReport.steps[10].verification.named_receipt_refusals_sha256);
assertEqual('fixture installed runtime profile terminal chain artifact verification recognition refusal groups hash bound', fixtureReport.steps[9].chain.terminal_chain.recognition_refusal_groups_sha256, fixtureReport.steps[10].verification.recognition_refusal_groups_sha256);
assertEqual('fixture installed runtime profile terminal chain artifact verification deployment-profile authority mirror preserved', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_preserved);
assertEqual('fixture installed runtime profile terminal chain artifact verification deployment-profile authority mirror profile sha matches', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_profile_sha_matches);
assertEqual(
  'fixture installed runtime profile terminal chain artifact verification deployment-profile authority case IDs',
  JSON.stringify(EXPECTED_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASE_IDS),
  JSON.stringify(fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids)
);
assertEqual('fixture installed runtime profile terminal chain artifact verification deployment-profile authority before service proof', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof);
assertEqual('fixture installed runtime profile terminal chain artifact verification deployment-profile authority service proof not started', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started);
assertEqual('fixture installed runtime profile terminal chain artifact verification deployment-profile authority no production authority', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_authority);
assertEqual('fixture installed runtime profile terminal chain artifact verification trusted registry binding preserved', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_preserved);
assertEqual('fixture installed runtime profile terminal chain artifact verification trusted registry receipt contract hash bound', true, fixtureReport.steps[10].verification.trusted_issuer_registry_recognition_binding.registry_receipt_contract_hash_bound);
assertEqual('fixture installed runtime profile terminal chain artifact verification trusted registry no public key material embedded', false, fixtureReport.steps[10].verification.trusted_issuer_registry_recognition_binding.registry_public_key_material_included);
assertEqual('fixture installed runtime profile terminal chain artifact verification trusted registry no receipt envelope embedded', false, fixtureReport.steps[10].verification.trusted_issuer_registry_recognition_binding.receipt_envelope_included);
assertEqual('fixture installed runtime profile terminal chain artifact verification trusted registry no artifact-only crypto reconstruction', false, fixtureReport.steps[10].verification.trusted_issuer_registry_recognition_binding.cryptographic_evidence_reproducible_from_artifact);
assertEqual('fixture installed runtime profile terminal chain artifact verification trusted registry binding hash bound', fixtureReport.steps[10].verification.trusted_issuer_registry_recognition_binding_sha256, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256);
assertEqual('fixture installed runtime profile terminal chain artifact verification receipt path evidence preserved', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_preserved);
assertEqual(
  'fixture installed runtime profile terminal chain artifact verification receipt path sha bound',
  fixtureReport.steps[10].verification.recognized_receipt_path_evidence_sha256,
  fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_sha256
);
assertEqual('fixture installed runtime profile terminal chain artifact verification receipt path artifact-body bound', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_bound_to_artifact_body);
assertEqual('fixture installed runtime profile terminal chain artifact verification receipt path source binding', fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_sha256);
assertEqual('fixture installed runtime profile terminal chain artifact verification receipt path source matches terminal chain', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_matches_terminal_chain);
assertEqual('fixture installed runtime profile terminal chain artifact verification receipt path source matches registry', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_matches_trusted_registry_binding);
assertEqual('fixture installed runtime profile terminal chain artifact verification receipt path no public key material embedded', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_public_key_material_included);
assertEqual('fixture installed runtime profile terminal chain artifact verification receipt path no receipt envelope embedded', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_receipt_envelope_included);
assertEqual('fixture installed runtime profile terminal chain artifact verification receipt path no live registry', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_live_registry_state);
assertEqual('fixture installed runtime profile terminal chain artifact verification receipt path no key custody', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_key_custody_proven);
assertEqual('fixture installed runtime profile terminal chain artifact verification receipt path no revocation truth', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_revocation_truth_proven);
assertEqual('fixture installed runtime profile terminal chain artifact verification receipt path no production recognition', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_production_downstream_recognition_proven);
assertEqual('fixture installed runtime profile terminal chain artifact verification receipt path no public attestation', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_public_external_attestation);
assertEqual('fixture installed runtime profile terminal chain artifact verification receipt path no current-machine governance', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_current_machine_governance_proven);
assertEqual('fixture installed runtime profile terminal chain artifact verification trusted registry refusal count', 2, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count);
assertEqual('fixture installed runtime profile terminal chain artifact verification trusted registry all refusals refused', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused);
assertEqual(
  'fixture installed runtime profile terminal chain artifact verification trusted registry refusal case IDs',
  JSON.stringify(EXPECTED_TRUSTED_ISSUER_REGISTRY_REFUSAL_CASE_IDS),
  JSON.stringify(fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids)
);
assertEqual(
  'fixture installed runtime profile terminal chain artifact verification trusted registry refusal reason codes',
  JSON.stringify(EXPECTED_TRUSTED_ISSUER_REGISTRY_REFUSAL_REASON_CODES),
  JSON.stringify(fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes)
);
assertEqual(
  'fixture installed runtime profile terminal chain artifact verification trusted registry refusal hash bound',
  fixtureReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256,
  fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256
);
assertEqual('fixture installed runtime profile terminal chain artifact verification trusted registry no production authority', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_authority);
assertEqual('fixture installed runtime profile terminal chain artifact verification recognition group count', 3, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count);
assertEqual('fixture installed runtime profile terminal chain artifact verification recognition group case count', 18, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count);
assertEqual('fixture installed runtime profile terminal chain artifact verification nested binding preserved', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved);
assertEqual('fixture installed runtime profile terminal chain artifact verification nested preflight type', 'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1', fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_preflight_artifact_type);
assertEqual('fixture installed runtime profile terminal chain artifact verification nested service type', 'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1', fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_service_proof_artifact_type);
assertEqual('fixture installed runtime profile terminal chain artifact verification nested binding preflight hash bound', true, fixtureReport.steps[10].verification.nested_artifact_binding.preflight_artifact_hash_bound);
assertEqual('fixture installed runtime profile terminal chain artifact verification nested binding service hash bound', true, fixtureReport.steps[10].verification.nested_artifact_binding.service_artifact_hash_bound);
assertEqual(
  'fixture installed runtime profile terminal chain artifact verification recognition group case IDs',
  JSON.stringify(EXPECTED_RECOGNITION_REFUSAL_GROUP_CASE_IDS),
  JSON.stringify(fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids)
);
assertEqual('fixture installed runtime profile terminal chain artifact verification current-machine false', false, fixtureReport.steps[10].verification.current_machine_governance_proven);
assertEqual('fixture installed runtime profile terminal chain count verified', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_verified);
assertEqual('fixture installed runtime profile terminal chain count boarded', true, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognized_write_boarded);
assertEqual('fixture installed runtime profile terminal chain count taxonomy hash bound', fixtureReport.steps[9].chain.terminal_chain.recognition_refusal_taxonomy_sha256, fixtureReport.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256);
assertEqual('fixture installed runtime profile terminal chain count named refusals hash bound', fixtureReport.steps[9].chain.terminal_chain.named_receipt_refusals_sha256, fixtureReport.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256);
assertEqual('fixture installed runtime profile terminal chain count recognition refusal groups hash bound', fixtureReport.steps[9].chain.terminal_chain.recognition_refusal_groups_sha256, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256);
assertEqual('fixture terminal chain recognition contract digest bound', fixtureReport.counts.installed_runtime_profile_service_artifact_verification_recognition_contract_sha256, fixtureReport.counts.installed_runtime_profile_terminal_chain_recognition_contract_sha256);
assertEqual('fixture installed runtime profile terminal chain artifact count taxonomy hash bound', fixtureReport.steps[10].verification.recognition_refusal_taxonomy_sha256, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256);
assertEqual('fixture installed runtime profile terminal chain artifact count named refusals hash bound', fixtureReport.steps[10].verification.named_receipt_refusals_sha256, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256);
assertEqual('fixture installed runtime profile terminal chain artifact count recognition refusal groups hash bound', fixtureReport.steps[10].verification.recognition_refusal_groups_sha256, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256);
assertEqual('fixture terminal chain artifact recognition contract digest bound', fixtureReport.counts.installed_runtime_profile_terminal_chain_recognition_contract_sha256, fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_contract_sha256);
assertEqual('fixture installed runtime profile terminal chain count no production downstream', false, fixtureReport.counts.installed_runtime_profile_terminal_chain_production_downstream_recognition);
assertEqual('fixture configured recognition replay-store proof type', 'zlar-configured-recognition-consumer-replay-store-proof-v0', fixtureReport.steps[11].proof.proof_type);
assertEqual('fixture configured recognition replay-store proof passed', 'passed', fixtureReport.steps[11].proof.proof_status);
assertEqual('fixture configured recognition replay-store proof local only', true, fixtureReport.steps[11].proof.local_fixture_only);
assertEqual('fixture configured recognition replay-store first call persisted', true, fixtureReport.counts.configured_recognition_replay_store_first_call_persisted);
assertEqual('fixture configured recognition replay-store first call effect written', true, fixtureReport.counts.configured_recognition_replay_store_first_call_effect_written);
assertEqual('fixture configured recognition replay-store replay refused before callback', true, fixtureReport.counts.configured_recognition_replay_store_replay_refused_before_callback);
assertEqual('fixture configured recognition replay-store invalid store failed closed', true, fixtureReport.counts.configured_recognition_replay_store_invalid_store_failed_closed_before_callback);
assertEqual('fixture configured recognition replay-store case count', 3, fixtureReport.counts.configured_recognition_replay_store_case_count);
assertEqual('fixture configured recognition replay-store no real downstream', false, fixtureReport.counts.configured_recognition_replay_store_real_downstream);
assertEqual('fixture configured recognition replay-store no real receipt', false, fixtureReport.counts.configured_recognition_replay_store_real_receipt);
assertEqual('fixture configured recognition replay-store no production trust', false, fixtureReport.counts.configured_recognition_replay_store_production_trust);
assertEqual('fixture configured recognition replay-store output redacted', true, fixtureReport.counts.configured_recognition_replay_store_path_redacted);
assertEqual('fixture source bridge window authority accepted', 'accepted', fixtureReport.steps[12].authority.authority_status);
assertEqual('fixture source bridge window authority safe for control tower', true, fixtureReport.counts.source_bridge_window_authority_safe_for_control_tower_use);
assertEqual('fixture source bridge window authority can push under window', true, fixtureReport.counts.source_bridge_window_authority_can_push_under_window);
assertEqual('fixture source bridge window authority forbidden consequences present', true, fixtureReport.counts.source_bridge_window_authority_forbidden_consequences_present);
assertEqual('fixture source bridge window authority stop conditions present', true, fixtureReport.counts.source_bridge_window_authority_stop_conditions_present);
assertEqual('fixture source bridge window authority does not read private key material', false, fixtureReport.counts.source_bridge_window_authority_reads_private_key_material);
assertEqual('fixture source bridge window authority does not read token material', false, fixtureReport.counts.source_bridge_window_authority_reads_token_material);
assertEqual('fixture source bridge window authority does not mint credentials', false, fixtureReport.counts.source_bridge_window_authority_mints_credentials);
assertEqual('fixture source bridge window authority does not call GitHub', false, fixtureReport.counts.source_bridge_window_authority_calls_github);
assertEqual('fixture source bridge window authority does not read remote refs', false, fixtureReport.counts.source_bridge_window_authority_reads_remote_refs);
assertEqual('fixture source bridge window authority does not push source', false, fixtureReport.counts.source_bridge_window_authority_pushes_source);
assertEqual('fixture source bridge window authority does not change config', false, fixtureReport.counts.source_bridge_window_authority_changes_configuration);
assert('fixture is privacy safe', !unsafeOutputPattern.test(fixtureText));

console.log('\n-- command output matches fixture --');
const commandRun = runZlar(['proof-smoke', '--json']);
assertEqual('proof smoke json exits zero', 0, commandRun.status);
assertEqual('proof smoke json emits no stderr', '', commandRun.stderr);
const commandReport = parseProofSmokeReportText(commandRun.stdout);
assert('proof smoke json output passes validation', assertProofSmokeReport(commandReport));
assertEqual(
  'proof smoke json output preserves pinned terminal artifact identity',
  fixtureReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_expected_body_sha256,
  commandReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_expected_body_sha256
);
assertEqual(
  'proof smoke json output preserves consequence map projection identity',
  fixtureReport.counts.consequence_lifecycle_map_projection_sha256,
  commandReport.counts.consequence_lifecycle_map_projection_sha256
);
assertEqual('proof smoke json output preserves 13 evidenced obligations', 13, commandReport.counts.consequence_lifecycle_map_evidenced_obligation_count);
assertEqual('proof smoke json output preserves 7 open obligations', 7, commandReport.counts.consequence_lifecycle_map_not_evidenced_obligation_count);
assertEqual('proof smoke json output preserves 2 outside obligations', 2, commandReport.counts.consequence_lifecycle_map_outside_coverage_obligation_count);

console.log('\n-- builder contract --');
const rebuiltReport = buildProofSmokeReport({
  sampleVerification: fixtureReport.steps[0].verification,
  serviceProfilePreflightSampleVerification: fixtureReport.steps[1].verification,
  activationPreflightSampleVerification: fixtureReport.steps[2].verification,
  runtimeLocalActivationSampleVerification: fixtureReport.steps[3].verification,
  runtimeProfileInstallationSampleVerification: fixtureReport.steps[4].verification,
  installedRuntimeProfilePreflightSampleVerification: fixtureReport.steps[5].verification,
  installedRuntimeProfileRecognitionProof: fixtureReport.steps[6].proof,
  installedRuntimeProfileServiceProof: fixtureReport.steps[7].proof,
  installedRuntimeProfileServiceProofArtifactVerification: fixtureReport.steps[8].verification,
  installedRuntimeProfileTerminalChain: fixtureReport.steps[9].chain,
  installedRuntimeProfileTerminalChainArtifactVerification: fixtureReport.steps[10].verification,
  configuredRecognitionReplayStoreProof: fixtureReport.steps[11].proof,
  sourceBridgeWindowAuthority: fixtureReport.steps[12].authority,
  coverageMap: fixtureReport.steps[13].coverage_map,
});
assert('rebuilt report passes validation', assertProofSmokeReport(rebuiltReport));
assertEqual('rebuilt report matches fixture', JSON.stringify(fixtureReport), JSON.stringify(rebuiltReport));

console.log('\n-- fail closed report drift --');
const liveProbeClaim = clone(fixtureReport);
liveProbeClaim.live_probing = true;
assertThrows('live probing claim fails', () => assertProofSmokeReport(liveProbeClaim), 'must not perform live probing');

const wrongResult = clone(fixtureReport);
wrongResult.result = 'warning';
assertThrows('wrong result fails', () => assertProofSmokeReport(wrongResult), 'result must be passed');

const extraField = clone(fixtureReport);
extraField.production_authority = true;
assertThrows('extra field fails', () => assertProofSmokeReport(extraField), 'unexpected fields');

const missingNonClaim = clone(fixtureReport);
missingNonClaim.non_claims = missingNonClaim.non_claims.slice(0, -1);
assertThrows('missing non-claim fails', () => assertProofSmokeReport(missingNonClaim), 'non-claims drifted');

const driftedLifecycleMapCount = clone(fixtureReport);
driftedLifecycleMapCount.counts.consequence_lifecycle_map_evidenced_obligation_count = 12;
assertThrows('consequence lifecycle map count drift fails', () => assertProofSmokeReport(driftedLifecycleMapCount), 'consequence lifecycle map aggregation drifted');

const driftedGenericRightfulClaim = clone(fixtureReport);
driftedGenericRightfulClaim.counts.generic_rightful_issuance_proven = true;
assertThrows('generic rightful issuance overclaim fails', () => assertProofSmokeReport(driftedGenericRightfulClaim), 'rightful-issuance claim ceiling drifted');

const driftedLifecycleClosureClaim = clone(fixtureReport);
driftedLifecycleClosureClaim.counts.consequence_lifecycle_closed = true;
assertThrows('consequence lifecycle closure overclaim fails', () => assertProofSmokeReport(driftedLifecycleClosureClaim), 'rightful-issuance claim ceiling drifted');

const driftedPinnedTerminalIdentity = clone(fixtureReport);
driftedPinnedTerminalIdentity.counts.installed_runtime_profile_terminal_chain_artifact_verification_expected_body_sha256_matched = false;
assertThrows('pinned terminal identity mismatch fails', () => assertProofSmokeReport(driftedPinnedTerminalIdentity), 'terminal structural-versus-pinned identity drifted');

const driftedPinnedEmbeddedServiceIdentity = clone(fixtureReport);
driftedPinnedEmbeddedServiceIdentity.counts.installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_expected_body_sha256 = '0'.repeat(64);
assertThrows('pinned embedded service identity mismatch fails', () => assertProofSmokeReport(driftedPinnedEmbeddedServiceIdentity), 'terminal structural-versus-pinned identity drifted');

const driftedTerminalToctouClaim = clone(fixtureReport);
driftedTerminalToctouClaim.counts.installed_runtime_profile_terminal_chain_artifact_verification_host_filesystem_path_toctou_closed = true;
assertThrows('terminal TOCTOU closure overclaim fails', () => assertProofSmokeReport(driftedTerminalToctouClaim), 'terminal artifact lifecycle aggregation drifted');

const collapsedReplayIdentity = clone(fixtureReport);
collapsedReplayIdentity.counts.installed_runtime_profile_service_replay_identities_separate = false;
assertThrows('signed-payload and consumed-grant replay collapse fails', () => assertProofSmokeReport(collapsedReplayIdentity), 'service rightful-issuance lifecycle aggregation drifted');

const staleClaudeHookReplayAdapterHash = clone(fixtureReport);
staleClaudeHookReplayAdapterHash.steps[0].verification.claude_hook_contract_replay.adapter_sha256 = '0'.repeat(64);
assertThrows('Claude hook replay stale adapter hash fails', () => assertProofSmokeReport(staleClaudeHookReplayAdapterHash), 'Claude hook-contract replay summary drifted');

const staleClaudeHookReplayContractHash = clone(fixtureReport);
staleClaudeHookReplayContractHash.steps[0].verification.claude_hook_contract_replay.hook_replay_contract_sha256 = '0'.repeat(64);
assertThrows('Claude hook replay stale contract hash fails', () => assertProofSmokeReport(staleClaudeHookReplayContractHash), 'Claude hook-contract replay summary drifted');

const driftedSampleArtifactVerificationHash = clone(fixtureReport);
driftedSampleArtifactVerificationHash.steps[0].verification.body_sha256 = '0'.repeat(64);
assertThrows('sample artifact verification hash drift fails', () => assertProofSmokeReport(driftedSampleArtifactVerificationHash), 'does not match committed sample');

const driftedRequiredSampleArtifactVerificationHash = clone(fixtureReport);
driftedRequiredSampleArtifactVerificationHash.steps[0].verification.required_body_sha256 = '0'.repeat(64);
assertThrows('sample artifact required hash drift fails', () => assertProofSmokeReport(driftedRequiredSampleArtifactVerificationHash), 'required SHA-256 drifted');

const unmatchedRequiredSampleArtifactVerificationHash = clone(fixtureReport);
unmatchedRequiredSampleArtifactVerificationHash.steps[0].verification.required_body_sha256_matched = false;
assertThrows('sample artifact required hash mismatch fails', () => assertProofSmokeReport(unmatchedRequiredSampleArtifactVerificationHash), 'required SHA-256 was not matched');

const summaryOnlySampleArtifactVerification = clone(fixtureReport);
summaryOnlySampleArtifactVerification.steps[0].command = 'zlar local-proof-pack verify --sample --json';
assertThrows('summary-only sample artifact verification command fails', () => assertProofSmokeReport(summaryOnlySampleArtifactVerification), 'command drifted');

const driftedConfiguredRecognitionReplayStoreProof = clone(fixtureReport);
driftedConfiguredRecognitionReplayStoreProof.steps[11].proof.real_downstream = true;
assertThrows('configured recognition replay-store overclaim fails', () => assertProofSmokeReport(driftedConfiguredRecognitionReplayStoreProof), 'crossed its claim boundary');

const driftedSourceBridgeWindowAuthority = clone(fixtureReport);
driftedSourceBridgeWindowAuthority.steps[12].authority.no_secret_boundary.pushes_source = true;
assertThrows('source bridge window authority overclaim fails', () => assertProofSmokeReport(driftedSourceBridgeWindowAuthority), 'no-secret boundary drifted');

const staleClaudeHookReplayCaseEvidenceHash = clone(fixtureReport);
staleClaudeHookReplayCaseEvidenceHash.steps[0].verification.claude_hook_contract_replay.case_evidence_sha256 = '0'.repeat(64);
assertThrows('Claude hook replay stale case evidence hash fails', () => assertProofSmokeReport(staleClaudeHookReplayCaseEvidenceHash), 'case evidence SHA-256 does not match committed sample');

const wrongCount = clone(fixtureReport);
wrongCount.counts.governed_lanes = 1;
assertThrows('wrong governed count fails', () => assertProofSmokeReport(wrongCount), 'governed lane count drifted');

const missingReceiptPathCount = clone(fixtureReport);
delete missingReceiptPathCount.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_preserved;
assertThrows('missing receipt path count fails', () => assertProofSmokeReport(missingReceiptPathCount), 'unexpected fields');

const tamperedReceiptPathSha = clone(fixtureReport);
tamperedReceiptPathSha.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256 =
  '0'.repeat(64);
assertThrows('tampered receipt path sha count fails', () => assertProofSmokeReport(tamperedReceiptPathSha), 'recognized receipt path count drifted');

const mismatchedReceiptPathSourceBinding = clone(fixtureReport);
mismatchedReceiptPathSourceBinding.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_matches_terminal_chain = false;
assertThrows('receipt path source-binding mismatch fails', () => assertProofSmokeReport(mismatchedReceiptPathSourceBinding), 'artifact verification count drifted');

const receiptPathPublicKeyFlip = clone(fixtureReport);
receiptPathPublicKeyFlip.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_public_key_material_included = true;
assertThrows('receipt path public key material count fails', () => assertProofSmokeReport(receiptPathPublicKeyFlip), 'recognized receipt path count drifted');

const receiptPathProductionFlip = clone(fixtureReport);
receiptPathProductionFlip.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_production_downstream_recognition_proven = true;
assertThrows('receipt path production recognition count fails', () => assertProofSmokeReport(receiptPathProductionFlip), 'artifact verification count drifted');

const unverifiedSample = clone(fixtureReport);
unverifiedSample.steps[0].verification.verified = false;
assertThrows('unverified sample fails', () => assertProofSmokeReport(unverifiedSample), 'sample artifact must verify');

const humanAuthorizationBoardsPending = clone(fixtureReport);
humanAuthorizationBoardsPending.steps[0].verification.human_authorization.pending_boarded = true;
assertThrows('human authorization pending boarding fails', () => assertProofSmokeReport(humanAuthorizationBoardsPending), 'human authorization boarding summary drifted');

const humanAuthorizationCountDrift = clone(fixtureReport);
humanAuthorizationCountDrift.counts.human_authorization_authorized_boarded = false;
assertThrows('human authorization count drift fails', () => assertProofSmokeReport(humanAuthorizationCountDrift), 'human authorization count drifted');

const unverifiedServicePreflightSample = clone(fixtureReport);
unverifiedServicePreflightSample.steps[1].verification.verified = false;
assertThrows('unverified service preflight sample fails', () => assertProofSmokeReport(unverifiedServicePreflightSample), 'service profile preflight sample artifact must verify');

const driftedServicePreflightSampleReason = clone(fixtureReport);
driftedServicePreflightSampleReason.steps[1].verification.direct_api_receipt_present_reason = 'recognized';
assertThrows('service preflight sample reason drift fails', () => assertProofSmokeReport(driftedServicePreflightSampleReason), 'service profile preflight sample refusal summary drifted');

const missingServicePreflight = clone(fixtureReport);
delete missingServicePreflight.steps[0].verification.service_profile_preflight;
assertThrows('missing service preflight summary fails', () => assertProofSmokeReport(missingServicePreflight), 'unexpected fields');

const missingReceiptVerifier = clone(fixtureReport);
delete missingReceiptVerifier.steps[0].verification.receipt_verifier_boundary;
assertThrows('missing receipt verifier summary fails', () => assertProofSmokeReport(missingReceiptVerifier), 'unexpected fields');

const missingKeyState = clone(fixtureReport);
delete missingKeyState.steps[0].verification.key_state_report;
assertThrows('missing key-state summary fails', () => assertProofSmokeReport(missingKeyState), 'unexpected fields');

const driftedKeyStateCustody = clone(fixtureReport);
driftedKeyStateCustody.steps[0].verification.key_state_report.key_custody_proven = true;
assertThrows('key-state custody claim fails', () => assertProofSmokeReport(driftedKeyStateCustody), 'key-state privacy/non-claim summary drifted');

const driftedKeyStateCount = clone(fixtureReport);
driftedKeyStateCount.counts.key_state_key_custody_proven = true;
assertThrows('key-state count drift fails', () => assertProofSmokeReport(driftedKeyStateCount), 'key-state custody count must be false');

const driftedReceiptVerifierVerdict = clone(fixtureReport);
driftedReceiptVerifierVerdict.steps[0].verification.receipt_verifier_boundary.unknown_signer_verdict = 'INVALID';
assertThrows('receipt verifier verdict drift fails', () => assertProofSmokeReport(driftedReceiptVerifierVerdict), 'receipt verifier boundary identity summary drifted');

const driftedReceiptVerifierIdentity = clone(fixtureReport);
driftedReceiptVerifierIdentity.steps[0].verification.receipt_verifier_boundary.required_identity_receipt_sha256_matched = false;
assertThrows('receipt verifier identity drift fails', () => assertProofSmokeReport(driftedReceiptVerifierIdentity), 'receipt verifier boundary identity summary drifted');

const driftedReceiptVerifierV0Refusal = clone(fixtureReport);
driftedReceiptVerifierV0Refusal.steps[0].verification.receipt_verifier_boundary.legacy_v0_required_identity_refused = false;
assertThrows('receipt verifier v0 refusal drift fails', () => assertProofSmokeReport(driftedReceiptVerifierV0Refusal), 'receipt verifier boundary identity summary drifted');

const driftedReceiptVerifierIdentityCount = clone(fixtureReport);
driftedReceiptVerifierIdentityCount.counts.receipt_verifier_v1_identity_verified = false;
assertThrows('receipt verifier identity count drift fails', () => assertProofSmokeReport(driftedReceiptVerifierIdentityCount), 'v1 identity count drifted');

const driftedReceiptVerifierClaim = clone(fixtureReport);
driftedReceiptVerifierClaim.steps[0].verification.receipt_verifier_boundary.issuer_recognition_proven = true;
assertThrows('receipt verifier issuer recognition claim fails', () => assertProofSmokeReport(driftedReceiptVerifierClaim), 'issuer_recognition_proven must be false');

const missingTrustedRegistry = clone(fixtureReport);
delete missingTrustedRegistry.steps[0].verification.trusted_issuer_registry_recognition;
assertThrows('missing trusted registry summary fails', () => assertProofSmokeReport(missingTrustedRegistry), 'unexpected fields');

const driftedTrustedRegistryVerdict = clone(fixtureReport);
driftedTrustedRegistryVerdict.steps[0].verification.trusted_issuer_registry_recognition.verdict = 'NOT_RECOGNIZED';
assertThrows('trusted registry verdict drift fails', () => assertProofSmokeReport(driftedTrustedRegistryVerdict), 'trusted issuer registry recognition facts drifted');

const driftedTrustedRegistryEvaluator = clone(fixtureReport);
driftedTrustedRegistryEvaluator.steps[0].verification.trusted_issuer_registry_recognition.registry_evaluation_result_type = 'synthetic-summary';
assertThrows('trusted registry evaluator drift fails', () => assertProofSmokeReport(driftedTrustedRegistryEvaluator), 'trusted issuer registry recognition evidence boundary drifted');

const driftedTrustedRegistryClaim = clone(fixtureReport);
driftedTrustedRegistryClaim.steps[0].verification.trusted_issuer_registry_recognition.live_trust_registry_state = true;
assertThrows('trusted registry live-state claim fails', () => assertProofSmokeReport(driftedTrustedRegistryClaim), 'live_trust_registry_state must be false');

const driftedTrustedRegistryCount = clone(fixtureReport);
driftedTrustedRegistryCount.counts.trusted_issuer_registry_key_custody_proven = true;
assertThrows('trusted registry count drift fails', () => assertProofSmokeReport(driftedTrustedRegistryCount), 'trusted_issuer_registry_key_custody_proven count must be false');

const driftedTrustedRegistryEvaluatorCount = clone(fixtureReport);
driftedTrustedRegistryEvaluatorCount.counts.trusted_issuer_registry_evaluation_result_type =
  'synthetic-summary';
assertThrows('trusted registry evaluator count drift fails', () => assertProofSmokeReport(driftedTrustedRegistryEvaluatorCount), 'evaluator count drifted');

const driftedServicePreflight = clone(fixtureReport);
driftedServicePreflight.steps[0].verification.service_profile_preflight.run_in_proof_pack = false;
assertThrows('service preflight not run fails', () => assertProofSmokeReport(driftedServicePreflight), 'must run in proof pack');

const driftedEmbeddedRuntimeLocalActivation = clone(fixtureReport);
driftedEmbeddedRuntimeLocalActivation.steps[0].verification.runtime_local_activation.local_activation_applied = false;
assertThrows('embedded runtime local activation drift fails', () => assertProofSmokeReport(driftedEmbeddedRuntimeLocalActivation), 'runtime local activation embedded summary drifted');

const driftedActiveProfileSelection = clone(fixtureReport);
driftedActiveProfileSelection.steps[0].verification.runtime_local_activation.active_profile_selection.selects_latest_profile = true;
assertThrows('embedded active profile latest selection drift fails', () => assertProofSmokeReport(driftedActiveProfileSelection), 'active profile selection drifted');

const driftedActiveProfileCount = clone(fixtureReport);
driftedActiveProfileCount.counts.active_profile_selects_latest = true;
assertThrows('active profile latest selection count drift fails', () => assertProofSmokeReport(driftedActiveProfileCount), 'latest-selection count drifted');

const driftedServicePreflightReason = clone(fixtureReport);
driftedServicePreflightReason.steps[0].verification.service_profile_preflight.case_summaries.find((item) =>
  item.case_id === 'direct_api_profile_receipt_present_refused_before_service_mutation'
).reason_code = 'recognized';
assertThrows('service preflight reason drift fails', () => assertProofSmokeReport(driftedServicePreflightReason), 'direct API receipt-present summary drifted');

const driftedServicePreflightWrongPolicy = clone(fixtureReport);
driftedServicePreflightWrongPolicy.steps[0].verification.service_profile_preflight.case_summaries.find((item) =>
  item.case_id === 'wrong_policy_profile_refused_before_service_mutation'
).reason_code = 'recognized';
assertThrows('service preflight wrong-policy drift fails', () => assertProofSmokeReport(driftedServicePreflightWrongPolicy), 'wrong-policy summary drifted');

const unverifiedActivationSample = clone(fixtureReport);
unverifiedActivationSample.steps[2].verification.verified = false;
assertThrows('unverified activation sample fails', () => assertProofSmokeReport(unverifiedActivationSample), 'activation preflight sample artifact must verify');

const unverifiedRuntimeLocalActivationSample = clone(fixtureReport);
unverifiedRuntimeLocalActivationSample.steps[3].verification.verified = false;
assertThrows('unverified runtime local activation sample fails', () => assertProofSmokeReport(unverifiedRuntimeLocalActivationSample), 'runtime local activation sample artifact must verify');

const driftedRuntimeLocalActivationBoundary = clone(fixtureReport);
driftedRuntimeLocalActivationBoundary.steps[3].verification.persistent_runtime_config_written = true;
assertThrows('runtime local activation persistent config drift fails', () => assertProofSmokeReport(driftedRuntimeLocalActivationBoundary), 'runtime local activation sample boundary summary drifted');

const driftedRuntimeLocalActivationRefusal = clone(fixtureReport);
driftedRuntimeLocalActivationRefusal.steps[3].verification.missing_receipt_refused = false;
assertThrows('runtime local activation missing receipt drift fails', () => assertProofSmokeReport(driftedRuntimeLocalActivationRefusal), 'runtime local activation sample boundary summary drifted');

const unverifiedRuntimeProfileInstallationSample = clone(fixtureReport);
unverifiedRuntimeProfileInstallationSample.steps[4].verification.verified = false;
assertThrows('unverified runtime profile installation sample fails', () => assertProofSmokeReport(unverifiedRuntimeProfileInstallationSample), 'runtime profile installation sample artifact must verify');

const driftedEmbeddedRuntimeProfileInstallation = clone(fixtureReport);
driftedEmbeddedRuntimeProfileInstallation.steps[0].verification.runtime_profile_installation.disposable_profile_installation_applied = false;
assertThrows('embedded runtime profile installation drift fails', () => assertProofSmokeReport(driftedEmbeddedRuntimeProfileInstallation), 'runtime profile installation embedded summary drifted');

const driftedRuntimeProfileInstallationGuard = clone(fixtureReport);
driftedRuntimeProfileInstallationGuard.steps[4].verification.request_authority_guard_refused = false;
assertThrows('runtime profile installation guard drift fails', () => assertProofSmokeReport(driftedRuntimeProfileInstallationGuard), 'runtime profile installation sample boundary summary drifted');

const driftedRuntimeProfileInstallationCount = clone(fixtureReport);
driftedRuntimeProfileInstallationCount.counts.runtime_profile_installation_selects_latest = true;
assertThrows('runtime profile installation latest-selection count drift fails', () => assertProofSmokeReport(driftedRuntimeProfileInstallationCount), 'runtime profile installation latest-selection count drifted');

const unverifiedInstalledRuntimeProfilePreflightSample = clone(fixtureReport);
unverifiedInstalledRuntimeProfilePreflightSample.steps[5].verification.verified = false;
assertThrows('unverified installed runtime profile preflight sample fails', () => assertProofSmokeReport(unverifiedInstalledRuntimeProfilePreflightSample), 'installed runtime profile preflight sample artifact must verify');

const driftedInstalledRuntimeProfilePreflightActivation = clone(fixtureReport);
driftedInstalledRuntimeProfilePreflightActivation.steps[5].verification.runtime_profile_activation_performed = true;
assertThrows('installed runtime profile preflight activation drift fails', () => assertProofSmokeReport(driftedInstalledRuntimeProfilePreflightActivation), 'installed runtime profile preflight sample boundary summary drifted');

const driftedInstalledRuntimeProfilePreflightTarget = clone(fixtureReport);
driftedInstalledRuntimeProfilePreflightTarget.steps[5].verification.target_handle =
  'zlar-target:v1:logical-fixture:' + '0'.repeat(64);
assertThrows('installed runtime profile preflight target drift fails', () => assertProofSmokeReport(driftedInstalledRuntimeProfilePreflightTarget), 'installed runtime profile preflight sample boundary summary drifted');

const driftedInstalledRuntimeProfilePreflightLifecycleClaim = clone(fixtureReport);
driftedInstalledRuntimeProfilePreflightLifecycleClaim.steps[5].verification.consequence_lifecycle_closed = true;
assertThrows('installed runtime profile preflight lifecycle overclaim fails', () => assertProofSmokeReport(driftedInstalledRuntimeProfilePreflightLifecycleClaim), 'installed runtime profile preflight sample boundary summary drifted');

const driftedInstalledRuntimeProfilePreflightCount = clone(fixtureReport);
driftedInstalledRuntimeProfilePreflightCount.counts.installed_runtime_profile_preflight_current_machine_governance_proven = true;
assertThrows('installed runtime profile preflight current-machine count drift fails', () => assertProofSmokeReport(driftedInstalledRuntimeProfilePreflightCount), 'installed runtime profile preflight current-machine-governance count drifted');

const driftedInstalledRuntimeProfileRecognitionCount = clone(fixtureReport);
driftedInstalledRuntimeProfileRecognitionCount.counts.installed_runtime_profile_preflight_recognition_contract_preserved = false;
assertThrows('installed runtime profile preflight recognition count drift fails', () => assertProofSmokeReport(driftedInstalledRuntimeProfileRecognitionCount), 'installed runtime profile preflight recognition-contract count drifted');

const weakenedInstalledRuntimeProfileRecognitionCases = clone(fixtureReport);
weakenedInstalledRuntimeProfileRecognitionCases.steps[5].verification.required_refusal_case_count = 1;
assertThrows('installed runtime profile preflight weakened recognition taxonomy fails', () => assertProofSmokeReport(weakenedInstalledRuntimeProfileRecognitionCases), 'installed runtime profile preflight sample boundary summary drifted');

const driftedInstalledRuntimeProfileRecognitionProofBoarding = clone(fixtureReport);
driftedInstalledRuntimeProfileRecognitionProofBoarding.steps[6].proof.recognized_boarding.boarded = false;
assertThrows('installed runtime profile recognition proof boarding drift fails', () => assertProofSmokeReport(driftedInstalledRuntimeProfileRecognitionProofBoarding), 'Installed recognition positive case drifted');

const driftedInstalledRuntimeProfileRecognitionProofCount = clone(fixtureReport);
driftedInstalledRuntimeProfileRecognitionProofCount.counts.installed_runtime_profile_recognition_all_refusals_before_mutation = false;
assertThrows('installed runtime profile recognition proof count drift fails', () => assertProofSmokeReport(driftedInstalledRuntimeProfileRecognitionProofCount), 'refusal-before-mutation count drifted');

const driftedInstalledRuntimeProfileRecognitionProofBoundary = clone(fixtureReport);
driftedInstalledRuntimeProfileRecognitionProofBoundary.steps[6].proof.proof_boundary.runtime_service_started = true;
assertThrows('installed runtime profile recognition proof runtime-service boundary fails', () => assertProofSmokeReport(driftedInstalledRuntimeProfileRecognitionProofBoundary), 'Installed recognition claim boundary drifted');

const driftedInstalledRuntimeProfileServiceProofBoarding = clone(fixtureReport);
driftedInstalledRuntimeProfileServiceProofBoarding.steps[7].proof.recognized_boarding.boarded = false;
assertThrows('installed runtime profile service proof boarding drift fails', () => assertProofSmokeReport(driftedInstalledRuntimeProfileServiceProofBoarding), 'Installed service proof recognized boarding drifted');

const driftedInstalledRuntimeProfileServiceProofCount = clone(fixtureReport);
driftedInstalledRuntimeProfileServiceProofCount.counts.installed_runtime_profile_service_all_refusals_before_mutation = false;
assertThrows('installed runtime profile service proof count drift fails', () => assertProofSmokeReport(driftedInstalledRuntimeProfileServiceProofCount), 'service refusal-before-mutation count drifted');

const driftedInstalledRuntimeProfileServiceProofReplayCount = clone(fixtureReport);
driftedInstalledRuntimeProfileServiceProofReplayCount.counts.installed_runtime_profile_service_restart_replay_refused = false;
assertThrows('installed runtime profile service proof restart replay count drift fails', () => assertProofSmokeReport(driftedInstalledRuntimeProfileServiceProofReplayCount), 'restart replay count drifted');

const driftedInstalledRuntimeProfileServiceProofBoundary = clone(fixtureReport);
driftedInstalledRuntimeProfileServiceProofBoundary.steps[7].proof.proof_boundary.current_machine_governance_proven = true;
assertThrows('installed runtime profile service proof current-machine boundary fails', () => assertProofSmokeReport(driftedInstalledRuntimeProfileServiceProofBoundary), 'Installed service claim boundary drifted');

const driftedInstalledRuntimeProfileServiceProofArtifactVerification = clone(fixtureReport);
driftedInstalledRuntimeProfileServiceProofArtifactVerification.steps[8].verification.current_machine_governance_proven = true;
assertThrows(
  'installed runtime profile service proof artifact verification current-machine boundary fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileServiceProofArtifactVerification),
  'Installed service proof verification current_machine_governance_proven drifted'
);

const driftedInstalledRuntimeProfileServiceProofArtifactVerificationCount = clone(fixtureReport);
driftedInstalledRuntimeProfileServiceProofArtifactVerificationCount.counts.installed_runtime_profile_service_artifact_verification_restart_replay_refused = false;
assertThrows(
  'installed runtime profile service proof artifact verification count drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileServiceProofArtifactVerificationCount),
  'artifact verification restart replay count drifted'
);

const driftedInstalledRuntimeProfileServiceProofArtifactVerificationHash = clone(fixtureReport);
driftedInstalledRuntimeProfileServiceProofArtifactVerificationHash.steps[8].verification.body_sha256 = '1'.repeat(64);
driftedInstalledRuntimeProfileServiceProofArtifactVerificationHash.counts.installed_runtime_profile_service_artifact_verification_body_sha256 = '1'.repeat(64);
assertThrows(
  'installed runtime profile service proof artifact verification proof hash binding fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileServiceProofArtifactVerificationHash),
  'installed runtime profile service proof artifact verification artifact SHA-256 does not match committed sample'
);

const driftedInstalledRuntimeProfileServiceProofArtifactVerificationTaxonomy = clone(fixtureReport);
driftedInstalledRuntimeProfileServiceProofArtifactVerificationTaxonomy.steps[8].verification.recognition_refusal_case_count = 17;
assertThrows(
  'installed runtime profile service proof artifact verification taxonomy drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileServiceProofArtifactVerificationTaxonomy),
  'recognition_refusal_case_count'
);

const driftedInstalledRuntimeProfileServiceProofArtifactVerificationTaxonomyCount = clone(fixtureReport);
driftedInstalledRuntimeProfileServiceProofArtifactVerificationTaxonomyCount.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256 = '2'.repeat(64);
assertThrows(
  'installed runtime profile service proof artifact verification taxonomy count drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileServiceProofArtifactVerificationTaxonomyCount),
  'artifact verification refusal taxonomy drifted'
);

const driftedInstalledRuntimeProfileTerminalChainBoundary = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainBoundary.steps[9].chain.side_door_report.current_machine_governance_proven = true;
assertThrows(
  'installed runtime profile terminal chain current-machine boundary fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainBoundary),
  'terminal chain side-door drifted'
);

const driftedInstalledRuntimeProfileTerminalChainTaxonomy = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainTaxonomy.steps[9].chain.generated_service_proof.observed_recognition_refusal_cases[0].reason_code =
  'receipt_invalid';
assertThrows(
  'installed runtime profile terminal chain taxonomy drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainTaxonomy),
  'refusal taxonomy'
);

const driftedInstalledRuntimeProfileTerminalChainTaxonomyCount = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainTaxonomyCount.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256 =
  '1'.repeat(64);
assertThrows(
  'installed runtime profile terminal chain taxonomy count drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainTaxonomyCount),
  'refusal count drifted'
);

const driftedInstalledRuntimeProfileTerminalChainNamedRefusalsCount = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainNamedRefusalsCount.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256 =
  '1'.repeat(64);
assertThrows(
  'installed runtime profile terminal chain named refusals count drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainNamedRefusalsCount),
  'refusal count drifted'
);

const driftedInstalledRuntimeProfileTerminalChainRecognitionGroupsCount = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainRecognitionGroupsCount.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256 =
  '1'.repeat(64);
assertThrows(
  'installed runtime profile terminal chain recognition refusal groups count drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainRecognitionGroupsCount),
  'refusal count drifted'
);

const driftedInstalledRuntimeProfileTerminalChainDeploymentProfileAuthorityCase = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainDeploymentProfileAuthorityCase.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids[0] =
  'wrong_case_id';
assertThrows(
  'installed runtime profile terminal chain deployment-profile authority case drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainDeploymentProfileAuthorityCase),
  'deployment-profile authority refusal mirror count drifted'
);

const driftedInstalledRuntimeProfileTerminalChainDeploymentProfileAuthorityBoundary = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainDeploymentProfileAuthorityBoundary.steps[9].chain.terminal_chain.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_service_proof_started = true;
assertThrows(
  'installed runtime profile terminal chain deployment-profile authority service-proof drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainDeploymentProfileAuthorityBoundary),
  'deployment-profile authority refusal mirror'
);

const driftedInstalledRuntimeProfileTerminalChainTrustedRegistryCount = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainTrustedRegistryCount.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256 =
  '1'.repeat(64);
assertThrows(
  'installed runtime profile terminal chain trusted registry count drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainTrustedRegistryCount),
  'trusted issuer registry binding count drifted'
);

const driftedInstalledRuntimeProfileTerminalChainTrustedRegistryRefusalCase = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainTrustedRegistryRefusalCase.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids[0] =
  'wrong_refusal_case';
assertThrows(
  'installed runtime profile terminal chain trusted registry refusal case drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainTrustedRegistryRefusalCase),
  'trusted issuer registry binding count drifted'
);

const driftedInstalledRuntimeProfileTerminalChainTrustedRegistryRefusalHash = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainTrustedRegistryRefusalHash.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256 =
  '1'.repeat(64);
assertThrows(
  'installed runtime profile terminal chain trusted registry refusal hash drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainTrustedRegistryRefusalHash),
  'artifact verification count drifted'
);

const driftedInstalledRuntimeProfileTerminalChainTrustedRegistryClaim = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainTrustedRegistryClaim.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_authority = true;
assertThrows(
  'installed runtime profile terminal chain trusted registry claim drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainTrustedRegistryClaim),
  'trusted issuer registry binding count drifted'
);

const missingInstalledRuntimeProfileTerminalChainReceiptPathEvidence = clone(fixtureReport);
delete missingInstalledRuntimeProfileTerminalChainReceiptPathEvidence.steps[9].chain.terminal_chain.recognized_receipt_path_evidence;
assertThrows(
  'installed runtime profile terminal chain missing receipt path evidence fails',
  () => assertProofSmokeReport(missingInstalledRuntimeProfileTerminalChainReceiptPathEvidence)
);

const summaryShapedInstalledRuntimeProfileTerminalChainReceiptPathEvidence = clone(fixtureReport);
summaryShapedInstalledRuntimeProfileTerminalChainReceiptPathEvidence.steps[9].chain.terminal_chain.recognized_receipt_path_evidence = {
  summary: 'recognized',
};
assertThrows(
  'installed runtime profile terminal chain summary-shaped receipt path evidence fails',
  () => assertProofSmokeReport(summaryShapedInstalledRuntimeProfileTerminalChainReceiptPathEvidence)
);

const mismatchedInstalledRuntimeProfileTerminalChainReceiptPathSource = clone(fixtureReport);
mismatchedInstalledRuntimeProfileTerminalChainReceiptPathSource.steps[9].chain.terminal_chain.recognized_receipt_path_evidence.source_binding_sha256 =
  '1'.repeat(64);
assertThrows(
  'installed runtime profile terminal chain receipt path source binding drift fails',
  () => assertProofSmokeReport(mismatchedInstalledRuntimeProfileTerminalChainReceiptPathSource)
);

const driftedInstalledRuntimeProfileTerminalChainNestedBindingCount = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainNestedBindingCount.counts.installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved = false;
assertThrows(
  'installed runtime profile terminal chain nested binding count drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainNestedBindingCount),
  'binding count drifted'
);

const driftedInstalledRuntimeProfileTerminalChainRecognitionGroupCaseId = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainRecognitionGroupCaseId.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids.no_usable_recognized_receipt_authority[0] =
  'wrong_case_id';
assertThrows(
  'installed runtime profile terminal chain recognition refusal group case ID drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainRecognitionGroupCaseId),
  'refusal count drifted'
);

const driftedInstalledRuntimeProfileTerminalChainRecognitionGroupCaseCount = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainRecognitionGroupCaseCount.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count = 17;
assertThrows(
  'installed runtime profile terminal chain recognition refusal group case count drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainRecognitionGroupCaseCount),
  'refusal count drifted'
);

const driftedInstalledRuntimeProfileTerminalChainArtifactVerificationHash = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainArtifactVerificationHash.steps[10].verification.body_sha256 = '1'.repeat(64);
driftedInstalledRuntimeProfileTerminalChainArtifactVerificationHash.counts.installed_runtime_profile_terminal_chain_artifact_verification_body_sha256 = '1'.repeat(64);
assertThrows(
  'installed runtime profile terminal chain artifact verification hash binding fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainArtifactVerificationHash),
  'installed runtime profile terminal chain artifact verification artifact SHA-256 does not match committed sample'
);

const driftedInstalledRuntimeProfileTerminalChainArtifactVerificationTaxonomyCount = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainArtifactVerificationTaxonomyCount.counts.installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256 =
  '1'.repeat(64);
assertThrows(
  'installed runtime profile terminal chain artifact verification taxonomy count drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainArtifactVerificationTaxonomyCount),
  'artifact verification count drifted'
);

const driftedInstalledRuntimeProfileTerminalChainArtifactVerificationRecognitionGroupsCount = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainArtifactVerificationRecognitionGroupsCount.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256 =
  '1'.repeat(64);
assertThrows(
  'installed runtime profile terminal chain artifact verification recognition refusal groups count drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainArtifactVerificationRecognitionGroupsCount),
  'artifact verification count drifted'
);

const driftedInstalledRuntimeProfileTerminalChainArtifactVerificationDeploymentProfileAuthorityCase = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainArtifactVerificationDeploymentProfileAuthorityCase.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids[4] =
  'wrong_case_id';
assertThrows(
  'installed runtime profile terminal chain artifact verification deployment-profile authority case drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainArtifactVerificationDeploymentProfileAuthorityCase),
  'artifact verification deployment-profile authority refusal mirror count drifted'
);

const driftedInstalledRuntimeProfileTerminalChainArtifactVerificationNestedBindingCount = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainArtifactVerificationNestedBindingCount.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved = false;
assertThrows(
  'installed runtime profile terminal chain artifact verification nested binding count drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainArtifactVerificationNestedBindingCount),
  'artifact verification count drifted'
);

const driftedInstalledRuntimeProfileTerminalChainArtifactVerificationRecognitionGroupCaseId = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainArtifactVerificationRecognitionGroupCaseId.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids.route_or_request_authority_material_refused[5] =
  'wrong_case_id';
assertThrows(
  'installed runtime profile terminal chain artifact verification recognition refusal group case ID drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainArtifactVerificationRecognitionGroupCaseId),
  'artifact verification count drifted'
);

const driftedInstalledRuntimeProfileTerminalChainArtifactVerificationRecognitionGroupCount = clone(fixtureReport);
driftedInstalledRuntimeProfileTerminalChainArtifactVerificationRecognitionGroupCount.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count = 2;
assertThrows(
  'installed runtime profile terminal chain artifact verification recognition refusal group count drift fails',
  () => assertProofSmokeReport(driftedInstalledRuntimeProfileTerminalChainArtifactVerificationRecognitionGroupCount),
  'artifact verification count drifted'
);

const driftedRecognitionContractDigestCount = clone(fixtureReport);
driftedRecognitionContractDigestCount.counts.installed_runtime_profile_service_recognition_contract_sha256 =
  '2'.repeat(64);
assertThrows(
  'installed runtime profile service recognition contract digest drift fails',
  () => assertProofSmokeReport(driftedRecognitionContractDigestCount),
  'service recognition-contract digest drifted'
);

assertThrows('invalid json parse fails', () => parseProofSmokeReportText('{'), 'not valid JSON');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
