#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import {
  RUNTIME_LOCAL_ACTIVATION_NON_CLAIMS,
} from '../lib/protected-records-runtime-local-activation.mjs';
import {
  RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_SCOPE,
  RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_TYPE,
  RECORDS_WRITE_DOWNSTREAM_REFUSAL_CONTRACT_TYPE,
  RECORDS_WRITE_TERMINAL_AIRPORT_SENTENCE,
  RECORDS_WRITE_TERMINAL_CHECKPOINT,
  RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY,
  RECORDS_WRITE_TERMINAL_PROOF_TYPE,
  RECORDS_WRITE_TERMINAL_ROUTE,
  REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS,
  assertRecordsWriteTerminalProof,
  buildRecordsWriteTerminalProof,
  formatRecordsWriteTerminalProofSummary,
} from '../lib/records-write-terminal-proof.mjs';

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

function assertThrows(label, fn, expectedMessageFragment) {
  TOTAL++;
  try {
    fn();
    FAIL++;
    console.log(`  FAIL: ${label} -- expected throw`);
  } catch (err) {
    if (!expectedMessageFragment || String(err.message).includes(expectedMessageFragment)) {
      PASS++;
      console.log(`  PASS: ${label}`);
    } else {
      FAIL++;
      console.log(`  FAIL: ${label} -- ${err.message}`);
    }
  }
}

function refusalCase(proof, caseId) {
  return proof.downstream_refusal_contract.refusal_cases.find((item) => item.case_id === caseId);
}

const PLAN_PATH = 'profiles/protected-records-runtime-local-activation-plan.fixture.json';
const PROFILE_PATH = 'profiles/protected-records-runtime-fixture.profile.json';
const SAMPLE_ARTIFACT_SHA256 = 'dbf2b182501a38c870377984d58c92ae28cfc857afa86fc9686dd90a64bd846b';
const SAMPLE_PLAN_SHA256 = '40a8703eea4ab0066574e87870bfecd4a5dc87a77a9d71d54a3ac9435ddd480a';
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;

const plan = JSON.parse(readFileSync(PLAN_PATH, 'utf8'));
const profile = JSON.parse(readFileSync(PROFILE_PATH, 'utf8'));
const proof = buildRecordsWriteTerminalProof(plan, profile);

assert('terminal proof validates', assertRecordsWriteTerminalProof(proof));
assertEqual('proof type', RECORDS_WRITE_TERMINAL_PROOF_TYPE, proof.proof_type);
assertEqual('command', 'zlar records-write-terminal-proof', proof.command);
assertEqual('action class', 'records.write', proof.action_class);
assertEqual('evidence model', 'local-disposable-runtime-activation-fixture', proof.evidence_model);
assertEqual('live probing false', false, proof.live_probing);
assertEqual('terminal id', 'protected-records.runtime.records.write', proof.terminal.terminal_id);
assertEqual('terminal checkpoint', RECORDS_WRITE_TERMINAL_CHECKPOINT, proof.terminal.checkpoint);
assertEqual('terminal downstream boundary', RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY, proof.terminal.downstream_boundary);
assertEqual('airport sentence exact', RECORDS_WRITE_TERMINAL_AIRPORT_SENTENCE, proof.terminal.airport_sentence);
assertEqual('active profile selection type', RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_TYPE, proof.active_profile_selection.selection_type);
assertEqual('active profile selection scope', RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_SCOPE, proof.active_profile_selection.selection_scope);
assertEqual('active profile selected', true, proof.active_profile_selection.selected);
assertEqual('active profile source explicit', 'explicit-plan-and-profile-inputs', proof.active_profile_selection.selection_source);
assertEqual('active profile action class', 'records.write', proof.active_profile_selection.action_class);
assertEqual('active profile route', RECORDS_WRITE_TERMINAL_ROUTE, proof.active_profile_selection.route);
assertEqual('active profile downstream boundary', RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY, proof.active_profile_selection.downstream_boundary);
assertEqual('active profile profile id', 'protected-records-runtime-fixture-profile', proof.active_profile_selection.profile_id);
assertEqual('active runtime profile id', 'protected-records-disposable-runtime-profile', proof.active_profile_selection.runtime_profile_id);
assertEqual('active profile starts sample not active', 'sample_not_active', proof.active_profile_selection.profile_status_before_selection);
assertEqual('active profile sha matches plan', true, proof.active_profile_selection.runtime_profile_sha_matches_plan);
assertEqual('active profile does not select latest', false, proof.active_profile_selection.selects_latest_profile);
assertEqual('active profile not persistently installed', false, proof.active_profile_selection.persistent_runtime_profile_installed);
assertEqual('active profile no live runtime check', false, proof.active_profile_selection.live_runtime_profile_checked);
assertEqual('active profile hook config false', false, proof.active_profile_selection.hook_configuration_written);
assertEqual('artifact verified', true, proof.evidence.artifact_verified);
assertEqual('artifact sha stable', SAMPLE_ARTIFACT_SHA256, proof.evidence.artifact_sha256);
assertEqual('plan sha stable', SAMPLE_PLAN_SHA256, proof.evidence.plan_sha256);
assertEqual('profile sha matches plan', true, proof.evidence.runtime_profile_sha_matches_plan);
assertEqual('recognized write accepted', true, proof.outcomes.recognized_write_accepted);
assertEqual('same-process signed payload replay refused', true, proof.outcomes.same_process_signed_payload_replay_refused_before_mutation);
assertEqual('restart consumed grant refused', true, proof.outcomes.restart_consumed_authority_grant_refused_before_mutation);
assertEqual('missing grant refused', true, proof.outcomes.missing_authority_grant_appointment_refused_before_mutation);
assertEqual('mismatched grant refused', true, proof.outcomes.mismatched_authority_grant_appointment_refused_before_mutation);
assertEqual('revoked grant refused', true, proof.outcomes.revoked_authority_grant_refused_before_mutation);
assertEqual('expired grant refused', true, proof.outcomes.expired_authority_grant_refused_before_mutation);
assertEqual('request grant refused', true, proof.outcomes.request_supplied_authority_grant_refused_before_mutation);
assertEqual('missing receipt refused', true, proof.outcomes.missing_receipt_refused_before_mutation);
assertEqual('unknown issuer refused', true, proof.outcomes.unknown_issuer_refused_before_mutation);
assertEqual('retired issuer refused', true, proof.outcomes.retired_issuer_refused_before_mutation);
assertEqual('missing issuer status refused', true, proof.outcomes.missing_issuer_status_refused_before_mutation);
assertEqual('wrong policy refused', true, proof.outcomes.wrong_policy_refused_before_mutation);
assertEqual('wrong domain refused', true, proof.outcomes.wrong_domain_refused_before_mutation);
assertEqual('wrong tool refused', true, proof.outcomes.wrong_tool_refused_before_mutation);
assertEqual('wrong audit event refused', true, proof.outcomes.wrong_audit_event_refused_before_mutation);
assertEqual('wrong detail refused', true, proof.outcomes.wrong_detail_refused_before_mutation);
assertEqual('non-boarding outcome refused', true, proof.outcomes.non_boarding_outcome_refused_before_mutation);
assertEqual('unrecognized receipt refused', true, proof.outcomes.unrecognized_receipt_refused_before_mutation);
assertEqual('direct api with receipt refused', true, proof.outcomes.direct_api_with_receipt_refused_before_mutation);
assertEqual('authority material refused', true, proof.outcomes.agent_supplied_authority_material_refused_before_mutation);
assertEqual('downstream refusal contract type', RECORDS_WRITE_DOWNSTREAM_REFUSAL_CONTRACT_TYPE, proof.downstream_refusal_contract.contract_type);
assertEqual('downstream refusal contract boundary', RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY, proof.downstream_refusal_contract.downstream_boundary);
assertEqual('downstream refusal contract source', 'zlar-protected-records-runtime-local-activation-proof-v1', proof.downstream_refusal_contract.evidence_source);
assertEqual('downstream refusal required count', REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS.length, proof.downstream_refusal_contract.required_case_count);
assertEqual('downstream refusal case count', REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS.length, proof.downstream_refusal_contract.case_count);
assertEqual('downstream refusal cases present', true, proof.downstream_refusal_contract.all_required_cases_present);
assertEqual('downstream refusal reason codes match', true, proof.downstream_refusal_contract.all_expected_reason_codes_match);
assertEqual('downstream refusal before mutation', true, proof.downstream_refusal_contract.all_refused_before_mutation);
assertEqual('downstream refusal zero state delta', true, proof.downstream_refusal_contract.all_zero_state_delta);
assertEqual('direct api attempts refused', true, proof.downstream_refusal_contract.direct_api_attempts_refused);
assertEqual('recognized receipt and authority grant required to mutate', true, proof.downstream_refusal_contract.recognized_receipt_and_authority_grant_required_to_mutate);
for (const expected of REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS) {
  const item = refusalCase(proof, expected.case_id);
  assert(`downstream refusal case present: ${expected.case_id}`, Boolean(item));
  assertEqual(`downstream refusal class: ${expected.case_id}`, expected.refusal_class, item.refusal_class);
  assertEqual(`downstream refusal expected reason: ${expected.case_id}`, expected.reason_code, item.expected_reason_code);
  assertEqual(`downstream refusal observed reason: ${expected.case_id}`, expected.reason_code, item.observed_reason_code);
  assertEqual(`downstream refusal before mutation: ${expected.case_id}`, true, item.refused_before_mutation);
  assertEqual(`downstream refusal zero delta: ${expected.case_id}`, 0, item.state_entry_count_delta);
}
assertEqual('missing receipt reason code', 'receipt_missing', refusalCase(proof, 'missing_receipt_refused_before_runtime_mutation').observed_reason_code);
assertEqual('invalid receipt reason code', 'receipt_invalid', refusalCase(proof, 'invalid_receipt_refused_before_runtime_mutation').observed_reason_code);
assertEqual('stale or expired reason code', 'receipt_stale', refusalCase(proof, 'stale_receipt_refused_before_runtime_mutation').observed_reason_code);
assertEqual('wrong policy reason code', 'policy_not_recognized', refusalCase(proof, 'wrong_policy_refused_before_runtime_mutation').observed_reason_code);
assertEqual('out of scope domain reason code', 'domain_out_of_scope', refusalCase(proof, 'wrong_domain_refused_before_runtime_mutation').observed_reason_code);
assertEqual('out of scope tool reason code', 'tool_out_of_scope', refusalCase(proof, 'wrong_tool_refused_before_runtime_mutation').observed_reason_code);
assertEqual('direct api with receipt direct marker', true, refusalCase(proof, 'direct_api_with_receipt_refused_before_runtime_mutation').direct_api_attempted);
assertEqual('missing grant reason code', 'authority_grant_missing', refusalCase(proof, 'missing_authority_grant_appointment_refused_before_consumption').observed_reason_code);
assertEqual('mismatched grant reason code', 'authority_grant_contract_mismatch', refusalCase(proof, 'mismatched_authority_grant_appointment_refused_before_consumption').observed_reason_code);
assertEqual('revoked grant reason code', 'authority_grant_revoked', refusalCase(proof, 'revoked_authority_grant_refused_before_consumption').observed_reason_code);
assertEqual('expired grant reason code', 'authority_grant_expired', refusalCase(proof, 'expired_authority_grant_refused_before_consumption').observed_reason_code);
assertEqual('request grant reason code', 'agent_supplied_authority_material', refusalCase(proof, 'agent_supplied_authority_grant_refused_before_runtime_mutation').observed_reason_code);
assertEqual('fixture rightful issuance carried', true, proof.authority_boundary.fixture_rightful_issuance_path_evidenced);
assertEqual('grant consumption identity', 'authority-grant-contract-sha256', proof.authority_boundary.consumption_identity);
assertEqual('signed payload replay identity', 'verified-signed-payload-sha256', proof.authority_boundary.signed_payload_replay_identity);
assertEqual('request stream authority false', false, proof.authority_boundary.request_stream_authority_material_accepted);
assertEqual('state append burn named', true, proof.storage_boundary.state_append_failure_burned_one_use_grant_without_mutation);
assertEqual('witness commit burn named', true, proof.storage_boundary.witness_commit_failed_after_authority_grant_store_commit);
assertEqual('partial grant burn window named', true, proof.storage_boundary.partial_grant_commit_burn_window_named);
assertEqual('joint rollback detection false', false, proof.storage_boundary.store_anchor_and_witness_joint_rollback_detection);
assertEqual('joint rollback reopens grant reuse', true, proof.storage_boundary.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse);
assertEqual('exactly once false', false, proof.storage_boundary.exactly_once_effect_semantics);
assertEqual('fixture rightful claim true', true, proof.claim_boundary.fixture_rightful_issuance_path_evidenced);
assertEqual('generic rightful claim false', false, proof.claim_boundary.rightful_issuance_proven);
assertEqual('portable rightful claim false', false, proof.claim_boundary.portable_rightful_issuance_proven);
assertEqual('live authority claim false', false, proof.claim_boundary.live_authority_proven);
assertEqual('production rightful claim false', false, proof.claim_boundary.production_rightful_issuance_proven);
assertEqual('current machine claim false', false, proof.claim_boundary.current_machine_governance_proven);
assertEqual('lifecycle closure false', false, proof.claim_boundary.consequence_lifecycle_closed);
assertEqual('downstream recognition required', true, proof.mutation_boundary.downstream_recognition_required);
assertEqual('missing/unrecognized receipt refused required', true, proof.mutation_boundary.missing_or_unrecognized_receipt_refused);
assertEqual('local activation applied', true, proof.mutation_boundary.local_activation_applied);
assertEqual('disposable config written', true, proof.mutation_boundary.disposable_runtime_config_written);
assertEqual('persistent config not written', false, proof.mutation_boundary.persistent_runtime_config_written);
assertEqual('hook config not written', false, proof.mutation_boundary.hook_configuration_written);
assertEqual('runtime service started', true, proof.mutation_boundary.runtime_service_started);
assert('open boundaries include local only', proof.open_boundaries.includes('local_activation_only'));
assert('open boundaries include current-machine non-proof', proof.open_boundaries.includes('current_machine_governance'));
assertEqual('non-claims exact count', RUNTIME_LOCAL_ACTIVATION_NON_CLAIMS.length, proof.non_claims.length);
assert('json is privacy safe', !unsafeOutputPattern.test(JSON.stringify(proof, null, 2)));

const summary = formatRecordsWriteTerminalProofSummary(proof);
assert('summary title present', summary.includes('ZLAR Records.Write One-Terminal Proof v1'));
assert('summary includes airport sentence', summary.includes(RECORDS_WRITE_TERMINAL_AIRPORT_SENTENCE));
assert('summary includes checkpoint', summary.includes(RECORDS_WRITE_TERMINAL_CHECKPOINT));
assert('summary includes active profile selection', summary.includes(`scope=${RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_SCOPE}`));
assert('summary includes active profile non-install', summary.includes('persistent_runtime_profile_installed=false'));
assert('summary includes recognized accepted', summary.includes('recognized_write_accepted=true'));
assert('summary includes missing refusal', summary.includes('missing_receipt_refused_before_mutation=true'));
assert('summary includes unrecognized refusal', summary.includes('unrecognized_receipt_refused_before_mutation=true'));
assert('summary includes downstream refusal contract', summary.includes(`Downstream refusal contract: type=${RECORDS_WRITE_DOWNSTREAM_REFUSAL_CONTRACT_TYPE}`));
assert('summary includes refusal count', summary.includes(`cases=${REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS.length}/${REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS.length}`));
assert('summary includes reason-code binding', summary.includes('reason_codes_match=true'));
assert('summary includes zero mutation contract', summary.includes('zero_state_delta=true'));
assert('summary includes fixture rightful issuance', summary.includes('fixture_rightful_issuance_path_evidenced=true'));
assert('summary includes grant refusals', summary.includes('missing_grant=true; mismatched_grant=true; revoked_grant=true; expired_grant=true; request_supplied_grant=true'));
assert('summary includes burn window', summary.includes('burn_window_named=true'));
assert('summary includes joint rollback side door', summary.includes('joint_rollback_reopens_grant_reuse=true'));
assert('summary includes generic rightful ceiling', summary.includes('generic_rightful_issuance=false'));
assert('summary includes lifecycle ceiling', summary.includes('consequence_lifecycle_closed=false'));
assert('summary includes hook non-write', summary.includes('hook_configuration_written=false'));
assert('summary includes non-claim', summary.includes('not a persistent install or production deployment'));
assert('summary is privacy safe', !unsafeOutputPattern.test(summary));

const widened = structuredClone(proof);
widened.live_probing = true;
assertThrows('live probing claim fails', () => assertRecordsWriteTerminalProof(widened), 'top-level contract drifted');

const missingRefusal = structuredClone(proof);
missingRefusal.outcomes.missing_receipt_refused_before_mutation = false;
assertThrows('missing receipt non-refusal fails', () => assertRecordsWriteTerminalProof(missingRefusal), 'outcome missing_receipt_refused_before_mutation drifted');

const mutatedRefusalContract = structuredClone(proof);
mutatedRefusalContract.downstream_refusal_contract.all_zero_state_delta = false;
assertThrows('zero mutation contract fails', () => assertRecordsWriteTerminalProof(mutatedRefusalContract), 'downstream refusal contract drifted');

const changedReasonCode = structuredClone(proof);
changedReasonCode.downstream_refusal_contract.refusal_cases[0].observed_reason_code = 'accepted_anyway';
assertThrows('refusal reason-code drift fails', () => assertRecordsWriteTerminalProof(changedReasonCode), 'downstream refusal case');

const productionClaim = structuredClone(proof);
productionClaim.mutation_boundary.persistent_runtime_config_written = true;
assertThrows('persistent config claim fails', () => assertRecordsWriteTerminalProof(productionClaim), 'mutation boundary drifted');

const persistentProfileClaim = structuredClone(proof);
persistentProfileClaim.active_profile_selection.persistent_runtime_profile_installed = true;
assertThrows('persistent active profile claim fails', () => assertRecordsWriteTerminalProof(persistentProfileClaim), 'active profile selection drifted');

const latestProfileClaim = structuredClone(proof);
latestProfileClaim.active_profile_selection.selects_latest_profile = true;
assertThrows('latest active profile claim fails', () => assertRecordsWriteTerminalProof(latestProfileClaim), 'active profile selection drifted');

const genericRightfulClaim = structuredClone(proof);
genericRightfulClaim.claim_boundary.rightful_issuance_proven = true;
assertThrows('generic rightful issuance overclaim fails', () => assertRecordsWriteTerminalProof(genericRightfulClaim), 'claim boundary drifted');

console.log(`\nResults: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) {
  process.exit(1);
}
console.log('ALL PASS');
