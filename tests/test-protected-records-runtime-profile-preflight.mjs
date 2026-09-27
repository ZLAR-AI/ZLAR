#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import {
  REQUIRED_RUNTIME_PROFILE_CASES,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from '../lib/protected-records-runtime-profile.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_PREFLIGHT_PROFILE_TYPE,
  PROTECTED_RECORDS_RUNTIME_PROFILE_PREFLIGHT_TYPE,
  REQUIRED_RUNTIME_PROFILE_BOUNDARY_OBSERVATIONS,
  REQUIRED_RUNTIME_PROFILE_OPEN_BOUNDARIES,
  RUNTIME_PROFILE_PREFLIGHT_NON_CLAIMS,
  RUNTIME_PROFILE_PREFLIGHT_SAFE_CLAIM_CEILING,
  assertProtectedRecordsRuntimePreflightProfile,
  assertProtectedRecordsRuntimeProfilePreflight,
  formatProtectedRecordsRuntimeProfilePreflightSummary,
  runProtectedRecordsRuntimeProfilePreflight,
  runtimeProfileSha256,
} from '../lib/protected-records-runtime-profile-preflight.mjs';

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

function section(title) {
  console.log(`\n-- ${title} --`);
}

const profile = JSON.parse(readFileSync('profiles/protected-records-runtime-fixture.profile.json', 'utf8'));

section('runtime preflight profile contract');
assert('profile passes validation', assertProtectedRecordsRuntimePreflightProfile(profile));
assertEqual('profile type', PROTECTED_RECORDS_RUNTIME_PREFLIGHT_PROFILE_TYPE, profile.profile_type);
assertEqual('profile id', 'protected-records-runtime-fixture-profile', profile.profile_id);
assertEqual('profile status sample not active', 'sample_not_active', profile.profile_status);
assertEqual('deployment posture preflight only', 'runtime_profile_preflight_only', profile.deployment_posture);
assertEqual('runtime profile id', 'protected-records-disposable-runtime-profile', profile.runtime_profile_id);
assertEqual('service command', 'zlar protected-records-runtime-service --config <file>', profile.service_command);
assertEqual('proof command', 'zlar protected-records-runtime-profile-proof', profile.proof_command);
assertEqual('mutation route exact', 'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation', profile.mutation_authoritative_route);
assertEqual('consumed authority grant store exact', 'persistent-single-use-authority-grant-contract-sha256-store', profile.consumed_authority_grant_store);
assertEqual('consumption identity exact', 'authority-grant-contract-sha256', profile.consumption_identity);
assertEqual('signed payload replay identity exact', 'verified-signed-payload-sha256', profile.signed_payload_replay_identity);
assertEqual('consumed store validation exact', 'exact-schema-unique-grant-contract-sha256s', profile.consumed_store_validation);
assertEqual('consumed store witness exact', 'launcher-owned-local-store-hash-witness', profile.consumed_store_witness);
assertEqual('launcher config required', true, profile.authority_boundary.config_supplied_by_launcher);
assertEqual('launcher grant contract required', true, profile.authority_boundary.authority_grant_contract_required_from_launcher);
assertEqual('launcher grant appointment required', true, profile.authority_boundary.authority_grant_appointment_required_from_launcher);
assertEqual('launcher issuance decision required', true, profile.authority_boundary.authority_grant_issuance_decision_required_from_launcher);
assertEqual('launcher authorized update required', true, profile.authority_boundary.authorized_record_update_required_from_launcher);
assertEqual('source profile authority grant absent', false, profile.authority_boundary.source_profile_authority_grant_present);
assertEqual('request authority material refused', false, profile.authority_boundary.request_stream_authority_material_accepted);
assertEqual('consumed grants path hidden from agent', false, profile.authority_boundary.consumed_grants_path_exposed_to_agent);
assertEqual('consumed grant anchor path hidden from agent', false, profile.authority_boundary.consumed_grant_store_anchor_path_exposed_to_agent);
assertEqual('consumed grant witness path hidden from agent', false, profile.authority_boundary.consumed_grant_store_witness_path_exposed_to_agent);
assertEqual('launcher witness true', true, profile.storage_boundary.local_witness_owned_by_launcher);
assertEqual('single host rollback detection true', true, profile.storage_boundary.single_host_rollback_detection);
assertEqual('store and anchor rollback refused while witness ahead', true, profile.storage_boundary.store_and_anchor_joint_rollback_refused_while_witness_ahead);
assertEqual('joint store anchor witness rollback detection false', false, profile.storage_boundary.store_anchor_and_witness_joint_rollback_detection);
assertEqual('production anti rollback false', false, profile.storage_boundary.production_grade_anti_rollback);
assert('retired receipt-store profile key absent', !Object.prototype.hasOwnProperty.call(profile, 'consumed_receipt_store'));
assert('retired receipt path authority key absent', !Object.prototype.hasOwnProperty.call(profile.authority_boundary, 'consumed_receipts_path_exposed_to_agent'));
assert('retired receipt storage boundary key absent', !Object.prototype.hasOwnProperty.call(profile.storage_boundary, 'persistent_consumed_receipt_store'));
assert('profile hash is sha256', /^[a-f0-9]{64}$/.test(runtimeProfileSha256(profile)));
for (const caseId of REQUIRED_RUNTIME_PROFILE_CASES) {
  assert(`profile required case present: ${caseId}`, profile.required_cases.includes(caseId));
}
for (const observation of REQUIRED_RUNTIME_PROFILE_BOUNDARY_OBSERVATIONS) {
  assert(`profile boundary observation present: ${observation}`, profile.required_boundary_observations.includes(observation));
}
for (const boundary of REQUIRED_RUNTIME_PROFILE_OPEN_BOUNDARIES) {
  assert(`profile open boundary present: ${boundary}`, profile.known_open_boundaries.includes(boundary));
}
for (const claim of RUNTIME_PROFILE_PREFLIGHT_NON_CLAIMS) {
  assert(`profile non-claim present: ${claim}`, profile.non_claims.includes(claim));
}
assert('profile text is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(profile)));

section('runtime profile preflight report');
const report = runProtectedRecordsRuntimeProfilePreflight(profile);
assert('preflight report passes validation', assertProtectedRecordsRuntimeProfilePreflight(report, profile));
assertEqual('preflight type', PROTECTED_RECORDS_RUNTIME_PROFILE_PREFLIGHT_TYPE, report.preflight_type);
assertEqual('safe claim ceiling exact', RUNTIME_PROFILE_PREFLIGHT_SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('evidence model', 'local-disposable-runtime-profile-preflight-fixture', report.evidence_model);
assertEqual('no live probing', false, report.live_probing);
assertEqual('profile sha binds input profile', runtimeProfileSha256(profile), report.profile.profile_sha256);
assertEqual('runtime profile id binds profile', profile.runtime_profile_id, report.profile.runtime_profile_id);
assertEqual('proof run in preflight', true, report.proof_summary.proof_run_in_preflight);
assertEqual('proof case count', REQUIRED_RUNTIME_PROFILE_CASES.length, report.proof_summary.proof_case_count);
assertEqual('required case count', REQUIRED_RUNTIME_PROFILE_CASES.length, report.proof_summary.proof_required_case_count);
assertEqual('proof boundary observation count', REQUIRED_RUNTIME_PROFILE_BOUNDARY_OBSERVATIONS.length, report.proof_summary.proof_boundary_observation_count);
assertEqual('required boundary observation count', REQUIRED_RUNTIME_PROFILE_BOUNDARY_OBSERVATIONS.length, report.proof_summary.proof_required_boundary_observation_count);
assertEqual('recognized write accepted', true, report.proof_summary.recognized_write_accepted);
assertEqual('replay after restart refused', true, report.proof_summary.replay_after_restart_refused);
assertEqual('invalid consumed store refused', true, report.proof_summary.invalid_consumed_store_refused);
assertEqual('invalid consumed store anchor refused', true, report.proof_summary.invalid_consumed_store_anchor_refused);
assertEqual('rollback refused', true, report.proof_summary.consumed_store_rollback_refused);
assertEqual('deletion refused', true, report.proof_summary.consumed_store_deletion_refused);
assertEqual('replacement refused', true, report.proof_summary.consumed_store_replacement_refused);
assertEqual('store and anchor rollback refused against witness', true, report.proof_summary.store_and_anchor_joint_rollback_refused_against_witness);
assertEqual('missing grant appointment refused', true, report.proof_summary.missing_authority_grant_appointment_refused);
assertEqual('mismatched grant appointment refused', true, report.proof_summary.mismatched_authority_grant_appointment_refused);
assertEqual('revoked grant refused', true, report.proof_summary.revoked_authority_grant_refused);
assertEqual('expired grant refused', true, report.proof_summary.expired_authority_grant_refused);
assertEqual('request supplied grant refused', true, report.proof_summary.request_supplied_authority_grant_refused);
assertEqual('authority material refused', true, report.proof_summary.agent_supplied_authority_material_refused);
assertEqual('omitted profile consumes one authority grant', 1, report.proof_summary.omitted_runtime_profile_id_consumed_authority_grant_count);
assertEqual('store and anchor rollback refused while witness ahead', true, report.proof_summary.store_and_anchor_joint_rollback_refused_while_witness_ahead);
assertEqual('joint store anchor witness rollback detection false', false, report.proof_summary.store_anchor_and_witness_joint_rollback_detection);
assertEqual('joint rollback reopens authority grant reuse', true, report.proof_summary.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse);

section('open-boundary honesty');
assertEqual('state path hidden', false, report.side_door_report.state_path_exposed_to_agent);
assertEqual('consumed grants path hidden', false, report.side_door_report.consumed_grants_path_exposed_to_agent);
assertEqual('grant anchor path hidden', false, report.side_door_report.consumed_grant_store_anchor_path_exposed_to_agent);
assertEqual('grant witness path hidden', false, report.side_door_report.consumed_grant_store_witness_path_exposed_to_agent);
assertEqual('recognition rule not agent supplied', false, report.side_door_report.recognition_rule_supplied_by_agent);
assertEqual('agent supplied authority refused', true, report.side_door_report.agent_supplied_authority_material_refused);
assertEqual('request supplied grant refused', true, report.side_door_report.request_supplied_authority_grant_refused);
assertEqual('persistent grant store true', true, report.side_door_report.persistent_consumed_authority_grant_store);
assertEqual('anchor present true', true, report.side_door_report.consumed_store_anchor_present);
assertEqual('witness present true', true, report.side_door_report.consumed_store_witness_present);
assertEqual('single host rollback detection true', true, report.side_door_report.single_host_consumed_store_rollback_detection);
assertEqual('store and anchor rollback refused while witness ahead', true, report.side_door_report.store_and_anchor_joint_rollback_refused_while_witness_ahead);
assertEqual('joint rollback detection false', false, report.side_door_report.store_anchor_and_witness_joint_rollback_detection);
assertEqual('joint rollback reopens grant reuse', true, report.side_door_report.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse);
assertEqual('exactly once false', false, report.side_door_report.exactly_once_effect_semantics);
assertEqual('persistent runtime profile not installed', false, report.side_door_report.persistent_runtime_profile_installed);
assertEqual('production service unchecked', false, report.side_door_report.production_records_service_checked);
assertEqual('live records unchecked', false, report.side_door_report.live_records_system_checked);
assertEqual('live approval unchecked', false, report.side_door_report.live_approval_channel_health_checked);
assertEqual('external attestation false', false, report.side_door_report.external_attestation);
assertEqual('sovereign recognition false', false, report.side_door_report.sovereign_recognition);
for (const boundary of REQUIRED_RUNTIME_PROFILE_OPEN_BOUNDARIES) {
  assert(`preflight open boundary present: ${boundary}`, report.known_open_boundaries.includes(boundary));
}
for (const claim of RUNTIME_PROFILE_PREFLIGHT_NON_CLAIMS) {
  assert(`preflight non-claim present: ${claim}`, report.non_claims.includes(claim));
}

section('safe output formatting');
const summary = formatProtectedRecordsRuntimeProfilePreflightSummary(report, profile);
assert('summary title present', summary.includes('ZLAR Protected Records Runtime Profile Preflight v1'));
assert('summary includes profile id', summary.includes('Profile: id=protected-records-runtime-fixture-profile'));
assert('summary includes launcher boundary', summary.includes('launcher_config=true'));
assert('summary includes proof cases', summary.includes(`cases=${REQUIRED_RUNTIME_PROFILE_CASES.length}/${REQUIRED_RUNTIME_PROFILE_CASES.length}`));
assert('summary includes grant consumption identity', summary.includes('consumption_identity=authority-grant-contract-sha256'));
assert('summary includes signed payload replay identity', summary.includes('signed_payload_replay_identity=verified-signed-payload-sha256'));
assert('summary includes launcher grant requirements', summary.includes('grant_contract_required=true; grant_appointment_required=true; issuance_decision_required=true; authorized_record_update_required=true'));
assert('summary includes rollback refusal', summary.includes('rollback_refused=true; deletion_refused=true; replacement_refused=true'));
assert('summary includes grant refusals', summary.includes('missing_appointment_refused=true; mismatched_appointment_refused=true; revoked_refused=true; expired_refused=true; request_supplied_grant_refused=true'));
assert('summary includes witness rollback boundary', summary.includes('store_and_anchor_joint_rollback_refused_while_witness_ahead=true; store_anchor_and_witness_joint_rollback_detection=false; store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse=true'));
assert('summary includes non-claim', summary.includes('not an active or installed runtime profile'));
assert('summary output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(summary));
const jsonText = JSON.stringify(report, null, 2);
assert('json output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(jsonText));
assert('json omits raw record id', !jsonText.includes('runtime-record-001'));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonText));
assert('json omits private and temp paths', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(jsonText));

section('fail closed validation');
const wrongCommand = structuredClone(profile);
wrongCommand.service_command = 'zlar protected-records-runtime-service --latest';
assertThrows('wrong service command fails profile validation', () => assertProtectedRecordsRuntimePreflightProfile(wrongCommand), 'contract drifted');

const liveProfile = structuredClone(profile);
liveProfile.profile_status = 'active';
assertThrows('active profile claim fails', () => assertProtectedRecordsRuntimePreflightProfile(liveProfile), 'contract drifted');

const agentAnchorPath = structuredClone(profile);
agentAnchorPath.authority_boundary.consumed_grant_store_anchor_path_exposed_to_agent = true;
assertThrows('agent anchor path exposure fails', () => assertProtectedRecordsRuntimePreflightProfile(agentAnchorPath), 'authority boundary drifted');

const agentWitnessPath = structuredClone(profile);
agentWitnessPath.authority_boundary.consumed_grant_store_witness_path_exposed_to_agent = true;
assertThrows('agent witness path exposure fails', () => assertProtectedRecordsRuntimePreflightProfile(agentWitnessPath), 'authority boundary drifted');

const retiredStoreKey = structuredClone(profile);
retiredStoreKey.consumed_receipt_store = retiredStoreKey.consumed_authority_grant_store;
delete retiredStoreKey.consumed_authority_grant_store;
assertThrows('retired consumed receipt store key fails', () => assertProtectedRecordsRuntimePreflightProfile(retiredStoreKey), 'unexpected fields');

const retiredAuthorityPathKey = structuredClone(profile);
retiredAuthorityPathKey.authority_boundary.consumed_receipts_path_exposed_to_agent = false;
delete retiredAuthorityPathKey.authority_boundary.consumed_grants_path_exposed_to_agent;
assertThrows('retired consumed receipts path key fails', () => assertProtectedRecordsRuntimePreflightProfile(retiredAuthorityPathKey), 'unexpected fields');

const retiredStorageBoundaryKey = structuredClone(profile);
retiredStorageBoundaryKey.storage_boundary.persistent_consumed_receipt_store = true;
delete retiredStorageBoundaryKey.storage_boundary.persistent_consumed_authority_grant_store;
assertThrows('retired persistent receipt store key fails', () => assertProtectedRecordsRuntimePreflightProfile(retiredStorageBoundaryKey), 'unexpected fields');

const productionAntiRollback = structuredClone(profile);
productionAntiRollback.storage_boundary.production_grade_anti_rollback = true;
assertThrows('production anti rollback claim fails', () => assertProtectedRecordsRuntimePreflightProfile(productionAntiRollback), 'storage boundary drifted');

const missingCase = structuredClone(profile);
missingCase.required_cases = missingCase.required_cases.filter((item) => item !== 'valid_consumed_store_rollback_refused_before_runtime_mutation');
assertThrows('missing runtime case fails', () => assertProtectedRecordsRuntimePreflightProfile(missingCase), 'required cases drifted');

const liveProbeReport = structuredClone(report);
liveProbeReport.live_probing = true;
assertThrows('live probing report fails', () => assertProtectedRecordsRuntimeProfilePreflight(liveProbeReport, profile), 'top-level contract drifted');

const noProofRun = structuredClone(report);
noProofRun.proof_summary.proof_run_in_preflight = false;
assertThrows('missing proof run fails', () => assertProtectedRecordsRuntimeProfilePreflight(noProofRun, profile), 'proof summary drifted');

const rollbackBoards = structuredClone(report);
rollbackBoards.proof_summary.consumed_store_rollback_refused = false;
assertThrows('rollback non-refusal fails', () => assertProtectedRecordsRuntimeProfilePreflight(rollbackBoards, profile), 'proof summary drifted');

const storeAnchorClosed = structuredClone(report);
storeAnchorClosed.proof_summary.store_anchor_and_witness_joint_rollback_detection = true;
assertThrows('joint store anchor witness rollback closure claim fails', () => assertProtectedRecordsRuntimeProfilePreflight(storeAnchorClosed, profile), 'proof summary drifted');

const productionClaim = structuredClone(report);
productionClaim.side_door_report.production_records_service_checked = true;
assertThrows('production service check claim fails', () => assertProtectedRecordsRuntimeProfilePreflight(productionClaim, profile), 'side-door report drifted');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
