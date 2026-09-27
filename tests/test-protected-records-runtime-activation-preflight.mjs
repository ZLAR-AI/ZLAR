#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import {
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from '../lib/protected-records-runtime-profile.mjs';
import {
  REQUIRED_RUNTIME_PROFILE_CASES,
} from '../lib/protected-records-runtime-profile.mjs';
import {
  REQUIRED_RUNTIME_PROFILE_BOUNDARY_OBSERVATIONS,
  runtimeProfileSha256,
} from '../lib/protected-records-runtime-profile-preflight.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_ACTIVATION_PLAN_TYPE,
  PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_TYPE,
  PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE,
  PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_TYPE,
  REQUIRED_RUNTIME_ACTIVATION_OPEN_BOUNDARIES,
  REQUIRED_RUNTIME_ACTIVATION_OPERATOR_REQUIREMENTS,
  RUNTIME_ACTIVATION_PREFLIGHT_NON_CLAIMS,
  RUNTIME_ACTIVATION_PREFLIGHT_SAFE_CLAIM_CEILING,
  assertProtectedRecordsRuntimeActivationPreflightArtifact,
  assertProtectedRecordsRuntimeActivationPlan,
  assertProtectedRecordsRuntimeActivationPreflight,
  buildProtectedRecordsRuntimeActivationPreflightArtifact,
  formatProtectedRecordsRuntimeActivationPreflightArtifactSummary,
  formatProtectedRecordsRuntimeActivationPreflightArtifactVerification,
  formatProtectedRecordsRuntimeActivationPreflightSummary,
  parseProtectedRecordsRuntimeActivationPreflightArtifactText,
  runProtectedRecordsRuntimeActivationPreflight,
  runtimeActivationPlanSha256,
  verifyProtectedRecordsRuntimeActivationPreflightArtifact,
} from '../lib/protected-records-runtime-activation-preflight.mjs';

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

function assertRuntimeProfileIdentitySummary(prefix, summary) {
  assertEqual(`${prefix} identity authority source`, 'launcher-owned-service-config', summary.runtime_profile_identity_authority_source);
  assertEqual(`${prefix} identity request-stream policy`, 'runtime_profile_id_may_be_omitted_but_if_supplied_must_match_config', summary.runtime_profile_identity_request_stream_policy);
  assertEqual(`${prefix} request runtime profile id not required`, false, summary.request_runtime_profile_id_required);
  assertEqual(`${prefix} omitted request runtime profile id absent`, false, summary.omitted_request_runtime_profile_id_present);
  assertEqual(`${prefix} omitted runtime profile id uses launcher config`, true, summary.omitted_runtime_profile_id_uses_launcher_config);
  assertEqual(`${prefix} omitted runtime profile id grant reason`, 'fixture_authority_grant_effect_satisfied', summary.omitted_runtime_profile_id_reason_code);
  assertEqual(`${prefix} omitted runtime profile id mutates once`, 1, summary.omitted_runtime_profile_id_state_entry_count_delta);
  assertEqual(`${prefix} omitted runtime profile id consumes one authority grant`, 1, summary.omitted_runtime_profile_id_consumed_authority_grant_count);
  assertEqual(`${prefix} supplied mismatched runtime profile id refused`, true, summary.supplied_mismatched_runtime_profile_id_refused);
  assertEqual(`${prefix} supplied mismatched runtime profile id reason`, 'agent_supplied_authority_material', summary.supplied_mismatch_reason_code);
  assertEqual(`${prefix} supplied mismatched runtime profile id state delta zero`, 0, summary.supplied_mismatch_state_entry_count_delta);
}

const plan = JSON.parse(readFileSync('profiles/protected-records-runtime-activation-plan.fixture.json', 'utf8'));
const profile = JSON.parse(readFileSync('profiles/protected-records-runtime-fixture.profile.json', 'utf8'));
const profileSha = runtimeProfileSha256(profile);
const SAMPLE_ARTIFACT_PATH = 'tests/fixtures/protected-records-runtime-activation-preflight-artifact-v1.json';
const SAMPLE_ARTIFACT_SHA256 = '1bc7b61e0b0f9e18d3a2bbdf8f7bfa9f1417e60cba027d20807ae893bce60c48';

section('runtime activation plan contract');
assert('plan passes validation', assertProtectedRecordsRuntimeActivationPlan(plan));
assertEqual('plan type', PROTECTED_RECORDS_RUNTIME_ACTIVATION_PLAN_TYPE, plan.plan_type);
assertEqual('plan id', 'protected-records-runtime-fixture-activation-plan', plan.plan_id);
assertEqual('plan status sample not active', 'sample_not_active', plan.plan_status);
assertEqual('deployment posture activation preflight only', 'activation_plan_preflight_only', plan.deployment_posture);
assertEqual('runtime profile id', 'protected-records-disposable-runtime-profile', plan.runtime_profile_id);
assertEqual('runtime profile source explicit', 'profiles/protected-records-runtime-fixture.profile.json', plan.runtime_profile_source);
assertEqual('runtime profile sha matches fixture', profileSha, plan.runtime_profile_sha256);
assert('plan hash is sha256', /^[a-f0-9]{64}$/.test(runtimeActivationPlanSha256(plan)));
assertEqual('activation not applied', false, plan.activation_boundary.activation_applied);
assertEqual('does not write runtime config', false, plan.activation_boundary.writes_runtime_config);
assertEqual('does not write hook config', false, plan.activation_boundary.writes_hook_configuration);
assertEqual('does not start runtime service', false, plan.activation_boundary.starts_runtime_service);
assertEqual('requires explicit human install', true, plan.activation_boundary.requires_explicit_human_install);
assertEqual('does not select latest', false, plan.activation_boundary.selects_latest_profile);
assertEqual('request authority material refused', false, plan.activation_boundary.request_stream_authority_material_accepted);
assertEqual('launcher supplies config', true, plan.activation_contract.launcher_supplies_config);
assertEqual('config path not agent supplied', false, plan.activation_contract.config_path_agent_supplied);
assertEqual('grant store path not agent supplied', false, plan.activation_contract.consumed_grants_path_agent_supplied);
assertEqual('grant anchor path not agent supplied', false, plan.activation_contract.consumed_grant_store_anchor_path_agent_supplied);
assertEqual('grant witness path not agent supplied', false, plan.activation_contract.consumed_grant_store_witness_path_agent_supplied);
assertEqual('launcher grant contract required', true, plan.activation_contract.authority_grant_contract_required_from_launcher);
assertEqual('request supplied grant refused', true, plan.activation_contract.request_supplied_authority_grant_refused);
assertEqual('downstream recognition required', true, plan.activation_contract.downstream_recognition_required);
assertEqual('missing receipt refused required', true, plan.activation_contract.missing_or_unrecognized_receipt_refused);
for (const requirement of REQUIRED_RUNTIME_ACTIVATION_OPERATOR_REQUIREMENTS) {
  assert(`operator requirement present: ${requirement}`, plan.operator_install_requirements.includes(requirement));
}
for (const boundary of REQUIRED_RUNTIME_ACTIVATION_OPEN_BOUNDARIES) {
  assert(`open boundary present: ${boundary}`, plan.known_open_boundaries.includes(boundary));
}
for (const claim of RUNTIME_ACTIVATION_PREFLIGHT_NON_CLAIMS) {
  assert(`non-claim present: ${claim}`, plan.non_claims.includes(claim));
}
assert('plan text is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(plan)));

section('runtime activation preflight report');
const report = runProtectedRecordsRuntimeActivationPreflight(plan, profile);
assert('activation preflight report passes validation', assertProtectedRecordsRuntimeActivationPreflight(report, plan, profile));
assertEqual('preflight type', PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_TYPE, report.preflight_type);
assertEqual('safe claim ceiling exact', RUNTIME_ACTIVATION_PREFLIGHT_SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('evidence model', 'local-runtime-activation-plan-preflight-fixture', report.evidence_model);
assertEqual('no live probing', false, report.live_probing);
assertEqual('plan sha binds input plan', runtimeActivationPlanSha256(plan), report.plan.plan_sha256);
assertEqual('profile sha binds input profile', profileSha, report.runtime_profile.profile_sha256);
assertEqual('profile sha matches plan', true, report.runtime_profile.profile_sha_matches_plan);
assertEqual('runtime profile preflight type', 'zlar-protected-records-runtime-profile-preflight-v1', report.runtime_profile_preflight_summary.preflight_type);
assertEqual('runtime profile preflight run', true, report.runtime_profile_preflight_summary.preflight_run);
assertEqual('runtime profile proof run', true, report.runtime_profile_preflight_summary.proof_run_in_preflight);
assertEqual('runtime profile proof case count', REQUIRED_RUNTIME_PROFILE_CASES.length, report.runtime_profile_preflight_summary.proof_case_count);
assertEqual('runtime profile required case count', REQUIRED_RUNTIME_PROFILE_CASES.length, report.runtime_profile_preflight_summary.proof_required_case_count);
assertEqual('runtime profile boundary observation count', REQUIRED_RUNTIME_PROFILE_BOUNDARY_OBSERVATIONS.length, report.runtime_profile_preflight_summary.proof_boundary_observation_count);
assertEqual('runtime profile required boundary observation count', REQUIRED_RUNTIME_PROFILE_BOUNDARY_OBSERVATIONS.length, report.runtime_profile_preflight_summary.proof_required_boundary_observation_count);
assertEqual('recognized write accepted', true, report.runtime_profile_preflight_summary.recognized_write_accepted);
assertEqual('same-process signed-payload replay refused', true, report.runtime_profile_preflight_summary.same_process_signed_payload_replay_refused);
assertEqual('restart consumed authority grant refused', true, report.runtime_profile_preflight_summary.restart_consumed_authority_grant_refused);
assertEqual('grant store rollback refused', true, report.runtime_profile_preflight_summary.consumed_authority_grant_store_rollback_refused);
assertEqual('grant store deletion refused', true, report.runtime_profile_preflight_summary.consumed_authority_grant_store_deletion_refused);
assertEqual('grant store replacement refused', true, report.runtime_profile_preflight_summary.consumed_authority_grant_store_replacement_refused);
assertEqual('missing grant refused', true, report.runtime_profile_preflight_summary.missing_authority_grant_appointment_refused);
assertEqual('mismatched grant refused', true, report.runtime_profile_preflight_summary.mismatched_authority_grant_appointment_refused);
assertEqual('revoked grant refused', true, report.runtime_profile_preflight_summary.revoked_authority_grant_refused);
assertEqual('expired grant refused', true, report.runtime_profile_preflight_summary.expired_authority_grant_refused);
assertEqual('request supplied grant refused', true, report.runtime_profile_preflight_summary.request_supplied_authority_grant_refused);
assertEqual('witness commit burn observed', true, report.runtime_profile_preflight_summary.witness_commit_failed_after_authority_grant_store_commit);
assertEqual('witness commit burn reason', 'consumed_store_write_failed_after_grant_commit', report.runtime_profile_preflight_summary.witness_commit_failure_reason_code);
assertEqual('authority material refused', true, report.runtime_profile_preflight_summary.agent_supplied_authority_material_refused);
assertRuntimeProfileIdentitySummary('runtime profile preflight summary', report.runtime_profile_preflight_summary);

section('open-boundary honesty');
assertEqual('activation applied false', false, report.side_door_report.activation_applied);
assertEqual('runtime config written false', false, report.side_door_report.runtime_config_written);
assertEqual('hook configuration written false', false, report.side_door_report.hook_configuration_written);
assertEqual('runtime service started false', false, report.side_door_report.runtime_service_started);
assertEqual('persistent runtime profile installed false', false, report.side_door_report.persistent_runtime_profile_installed);
assertEqual('latest profile selected false', false, report.side_door_report.latest_profile_selected);
assertEqual('request authority material accepted false', false, report.side_door_report.request_stream_authority_material_accepted);
assertEqual('live records unchecked', false, report.side_door_report.live_records_system_checked);
assertEqual('production service unchecked', false, report.side_door_report.production_records_service_checked);
assertEqual('live MCP unchecked', false, report.side_door_report.live_mcp_coverage_checked);
assertEqual('live approval unchecked', false, report.side_door_report.live_approval_channel_health_checked);
assertEqual('external attestation false', false, report.side_door_report.external_attestation);
assertEqual('sovereign recognition false', false, report.side_door_report.sovereign_recognition);
assertEqual('store and anchor refused while witness ahead', true, report.side_door_report.store_and_anchor_joint_rollback_refused_while_witness_ahead);
assertEqual('joint store anchor witness rollback detection false', false, report.side_door_report.store_anchor_and_witness_joint_rollback_detection);
assertEqual('joint rollback reopens grant reuse', true, report.side_door_report.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse);
assertEqual('store anchor witness commit non-atomic', false, report.side_door_report.atomic_store_anchor_witness_commit);
assertEqual('burn window named', true, report.side_door_report.partial_grant_commit_burn_window_named);
assertEqual('host path TOCTOU open', false, report.side_door_report.host_filesystem_path_toctou_closed);
assertEqual('unrouted records unchecked', false, report.side_door_report.unrouted_records_paths_checked);
for (const boundary of REQUIRED_RUNTIME_ACTIVATION_OPEN_BOUNDARIES) {
  assert(`preflight open boundary present: ${boundary}`, report.known_open_boundaries.includes(boundary));
}
for (const claim of RUNTIME_ACTIVATION_PREFLIGHT_NON_CLAIMS) {
  assert(`preflight non-claim present: ${claim}`, report.non_claims.includes(claim));
}

section('safe output formatting');
const summary = formatProtectedRecordsRuntimeActivationPreflightSummary(report, plan, profile);
assert('summary title present', summary.includes('ZLAR Protected Records Runtime Activation Preflight v1'));
assert('summary includes plan id', summary.includes('Plan: id=protected-records-runtime-fixture-activation-plan'));
assert('summary includes profile sha match', summary.includes('sha_matches_plan=true'));
assert('summary includes no activation writes', summary.includes('applied=false; writes_runtime_config=false; writes_hook_configuration=false'));
assert('summary includes explicit human install', summary.includes('requires_explicit_human_install=true'));
assert('summary includes runtime preflight run', summary.includes('run=true; proof_run=true'));
assert('summary includes runtime profile identity policy', summary.includes('Runtime profile identity policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('summary includes storage identities', summary.includes('consumption_identity=authority-grant-contract-sha256; signed_payload_replay_identity=verified-signed-payload-sha256'));
assert('summary includes replay split', summary.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true'));
assert('summary includes grant refusals', summary.includes('missing_grant_refused=true; mismatched_grant_refused=true; revoked_grant_refused=true; expired_grant_refused=true; request_supplied_grant_refused=true'));
assert('summary includes burn and rollback boundaries', summary.includes('atomic_store_anchor_witness_commit=false; burn_window_named=true; witness_ahead_refusal=true; joint_rollback_detection=false; joint_rollback_reopens_grant_reuse=true; host_path_toctou_closed=false'));
assert('summary includes no install side door', summary.includes('activation_applied=false; persistent_runtime_profile_installed=false'));
assert('summary includes operator requirements', summary.includes('human_explicit_install_command'));
assert('summary includes non-claim', summary.includes('not an active or installed runtime profile'));
assert('summary output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(summary));
const jsonText = JSON.stringify(report, null, 2);
assert('json output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(jsonText));
assert('json omits private and temp paths', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(jsonText));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonText));

section('portable artifact and verification');
const artifact = buildProtectedRecordsRuntimeActivationPreflightArtifact(plan, profile, report);
assert('artifact passes validation', assertProtectedRecordsRuntimeActivationPreflightArtifact(artifact));
assertEqual('artifact type', PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_TYPE, artifact.artifact_type);
assertEqual('artifact canonicalization', 'zlar-canonical-json-v1', artifact.canonicalization);
assertEqual('artifact generator', 'zlar protected-records-runtime-activation-preflight --artifact', artifact.generator);
assertEqual('artifact hash scope', 'canonical artifact body without integrity', artifact.hash_scope);
assert('artifact sha is sha256', /^[a-f0-9]{64}$/.test(artifact.integrity.body_sha256));
assertEqual('artifact embeds exact plan sha', runtimeActivationPlanSha256(plan), artifact.payload.preflight.plan.plan_sha256);
assertEqual('artifact embeds profile sha match', true, artifact.payload.preflight.runtime_profile.profile_sha_matches_plan);
assertEqual('artifact embeds no activation', false, artifact.payload.preflight.side_door_report.activation_applied);
assert('artifact text is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(artifact, null, 2)));

const parsedArtifact = parseProtectedRecordsRuntimeActivationPreflightArtifactText(JSON.stringify(artifact, null, 2));
assert('parsed artifact passes validation', assertProtectedRecordsRuntimeActivationPreflightArtifact(parsedArtifact));
assertEqual('parsed artifact sha stable', artifact.integrity.body_sha256, parsedArtifact.integrity.body_sha256);

const verification = verifyProtectedRecordsRuntimeActivationPreflightArtifact(parsedArtifact);
assertEqual('verification type', PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
assertEqual('verification verified true', true, verification.verified);
assertEqual('verification sha matches artifact', artifact.integrity.body_sha256, verification.body_sha256);
assertEqual('verification payload type', PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_TYPE, verification.payload_type);
assertEqual('verification live probing false', false, verification.live_probing);
assertEqual('verification plan sha matches', runtimeActivationPlanSha256(plan), verification.plan_sha256);
assertEqual('verification profile sha matches', profileSha, verification.runtime_profile_sha256);
assertEqual('verification profile sha matches plan', true, verification.runtime_profile_sha_matches_plan);
assertEqual('verification runtime preflight run', true, verification.runtime_profile_preflight_run);
assertEqual('verification runtime proof run', true, verification.runtime_profile_proof_run);
assertEqual('verification activation false', false, verification.activation_applied);
assertEqual('verification runtime config write false', false, verification.runtime_config_written);
assertEqual('verification hook config write false', false, verification.hook_configuration_written);
assertEqual('verification service start false', false, verification.runtime_service_started);
assertRuntimeProfileIdentitySummary('verification', verification);
assert('verification output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(verification, null, 2)));

const artifactSummary = formatProtectedRecordsRuntimeActivationPreflightArtifactSummary(artifact);
assert('artifact summary names portable artifact', artifactSummary.includes('Portable activation preflight artifact:'));
assert('artifact summary includes checksum', artifactSummary.includes(artifact.integrity.body_sha256));
assert('artifact summary is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(artifactSummary));

const verificationSummary = formatProtectedRecordsRuntimeActivationPreflightArtifactVerification(verification);
assert('verification summary title present', verificationSummary.includes('ZLAR Protected Records Runtime Activation Preflight Artifact Verification v1'));
assert('verification summary says verified', verificationSummary.includes('verified=true'));
assert('verification summary includes claim boundary', verificationSummary.includes('embedded local runtime activation preflight boundaries only'));
assert('verification summary includes identity policy', verificationSummary.includes('runtime_profile_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('verification summary keeps no-activation boundary', verificationSummary.includes('activation_applied=false; runtime_config_written=false'));
assert('verification summary is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(verificationSummary));

section('committed sample artifact');
const sampleArtifactText = readFileSync(SAMPLE_ARTIFACT_PATH, 'utf8');
assert('sample artifact text is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(sampleArtifactText));
const sampleArtifact = parseProtectedRecordsRuntimeActivationPreflightArtifactText(sampleArtifactText);
assert('sample artifact passes validation', assertProtectedRecordsRuntimeActivationPreflightArtifact(sampleArtifact));
assertEqual('sample artifact hash is stable', SAMPLE_ARTIFACT_SHA256, sampleArtifact.integrity.body_sha256);
assertEqual('sample artifact embeds same plan sha', runtimeActivationPlanSha256(plan), sampleArtifact.payload.preflight.plan.plan_sha256);
assertEqual('sample artifact embeds same profile sha', profileSha, sampleArtifact.payload.preflight.runtime_profile.profile_sha256);
const sampleVerification = verifyProtectedRecordsRuntimeActivationPreflightArtifact(sampleArtifact);
assertEqual('sample artifact verifies true', true, sampleVerification.verified);
assertEqual('sample verification sha matches fixture', SAMPLE_ARTIFACT_SHA256, sampleVerification.body_sha256);
assertEqual('sample verification live probing false', false, sampleVerification.live_probing);
assertRuntimeProfileIdentitySummary('sample verification', sampleVerification);

section('fail closed validation');
const activePlan = structuredClone(plan);
activePlan.plan_status = 'active';
assertThrows('active plan claim fails', () => assertProtectedRecordsRuntimeActivationPlan(activePlan), 'contract drifted');

const appliesActivation = structuredClone(plan);
appliesActivation.activation_boundary.activation_applied = true;
assertThrows('activation applied claim fails', () => assertProtectedRecordsRuntimeActivationPlan(appliesActivation), 'activation boundary drifted');

const writesConfig = structuredClone(plan);
writesConfig.activation_boundary.writes_runtime_config = true;
assertThrows('runtime config write claim fails', () => assertProtectedRecordsRuntimeActivationPlan(writesConfig), 'activation boundary drifted');

const selectsLatest = structuredClone(plan);
selectsLatest.activation_boundary.selects_latest_profile = true;
assertThrows('latest profile selection claim fails', () => assertProtectedRecordsRuntimeActivationPlan(selectsLatest), 'activation boundary drifted');

const missingRequirement = structuredClone(plan);
missingRequirement.operator_install_requirements = missingRequirement.operator_install_requirements.filter((item) => item !== 'human_explicit_install_command');
assertThrows('missing human install requirement fails', () => assertProtectedRecordsRuntimeActivationPlan(missingRequirement), 'operator install requirements drifted');

const shaMismatch = structuredClone(plan);
shaMismatch.runtime_profile_sha256 = '0'.repeat(64);
assertThrows('profile sha mismatch fails preflight', () => runProtectedRecordsRuntimeActivationPreflight(shaMismatch, profile), 'profile SHA mismatch');

const liveProbeReport = structuredClone(report);
liveProbeReport.live_probing = true;
assertThrows('live probing report fails', () => assertProtectedRecordsRuntimeActivationPreflight(liveProbeReport, plan, profile), 'top-level contract drifted');

const preflightNotRun = structuredClone(report);
preflightNotRun.runtime_profile_preflight_summary.preflight_run = false;
assertThrows('runtime profile preflight not run fails', () => assertProtectedRecordsRuntimeActivationPreflight(preflightNotRun, plan, profile), 'profile preflight summary drifted');

const runtimeProfileIdentityPolicyDrift = structuredClone(report);
runtimeProfileIdentityPolicyDrift.runtime_profile_preflight_summary.omitted_runtime_profile_id_uses_launcher_config = false;
assertThrows('runtime profile identity policy drift fails', () => assertProtectedRecordsRuntimeActivationPreflight(runtimeProfileIdentityPolicyDrift, plan, profile), 'profile preflight summary drifted');

const activationReport = structuredClone(report);
activationReport.side_door_report.activation_applied = true;
assertThrows('activation side-door claim fails', () => assertProtectedRecordsRuntimeActivationPreflight(activationReport, plan, profile), 'side-door report drifted');

const hookWriteReport = structuredClone(report);
hookWriteReport.side_door_report.hook_configuration_written = true;
assertThrows('hook write side-door claim fails', () => assertProtectedRecordsRuntimeActivationPreflight(hookWriteReport, plan, profile), 'side-door report drifted');

const storeAnchorClosed = structuredClone(report);
storeAnchorClosed.side_door_report.store_anchor_and_witness_joint_rollback_detection = true;
assertThrows('joint store anchor witness rollback closure claim fails', () => assertProtectedRecordsRuntimeActivationPreflight(storeAnchorClosed, plan, profile), 'side-door report drifted');

const tamperedArtifactHash = structuredClone(artifact);
tamperedArtifactHash.integrity.body_sha256 = '0'.repeat(64);
assertThrows('tampered artifact hash fails', () => assertProtectedRecordsRuntimeActivationPreflightArtifact(tamperedArtifactHash), 'SHA-256 mismatch');

const tamperedArtifactActivation = structuredClone(artifact);
tamperedArtifactActivation.payload.preflight.side_door_report.activation_applied = true;
assertThrows('tampered artifact activation claim fails', () => assertProtectedRecordsRuntimeActivationPreflightArtifact(tamperedArtifactActivation), 'side-door report drifted');

const tamperedArtifactPayload = structuredClone(artifact);
tamperedArtifactPayload.payload.extra = true;
assertThrows('artifact extra payload field fails', () => assertProtectedRecordsRuntimeActivationPreflightArtifact(tamperedArtifactPayload), 'payload contains unexpected fields');

assertThrows('invalid artifact json fails', () => parseProtectedRecordsRuntimeActivationPreflightArtifactText('{'), 'not valid JSON');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
