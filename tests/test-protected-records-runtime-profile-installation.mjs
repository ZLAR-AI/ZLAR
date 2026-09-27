#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import {
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from '../lib/protected-records-runtime-profile.mjs';
import {
  runtimeProfileSha256,
} from '../lib/protected-records-runtime-profile-preflight.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_TYPE,
  PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_VERIFICATION_TYPE,
  PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_PLAN_TYPE,
  PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_PROOF_TYPE,
  REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPEN_BOUNDARIES,
  REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPERATOR_REQUIREMENTS,
  RUNTIME_PROFILE_INSTALLATION_NON_CLAIMS,
  RUNTIME_PROFILE_INSTALLATION_SAFE_CLAIM_CEILING,
  assertProtectedRecordsRuntimeProfileInstallationArtifact,
  assertProtectedRecordsRuntimeProfileInstallationPlan,
  assertProtectedRecordsRuntimeProfileInstallationProof,
  buildProtectedRecordsRuntimeProfileInstallationArtifact,
  formatProtectedRecordsRuntimeProfileInstallationArtifactSummary,
  formatProtectedRecordsRuntimeProfileInstallationArtifactVerification,
  formatProtectedRecordsRuntimeProfileInstallationProofSummary,
  parseProtectedRecordsRuntimeProfileInstallationArtifactText,
  runProtectedRecordsRuntimeProfileInstallationProof,
  runtimeProfileInstallationPlanSha256,
  verifyProtectedRecordsRuntimeProfileInstallationArtifact,
} from '../lib/protected-records-runtime-profile-installation.mjs';

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

function caseSummary(report, caseId) {
  return report.case_summaries.find((item) => item.case_id === caseId);
}

function assertRuntimeProfileIdentitySummary(prefix, summary) {
  assertEqual(`${prefix} identity authority source`, 'launcher-owned-service-config', summary.runtime_profile_identity_authority_source);
  assertEqual(`${prefix} identity request-stream policy`, 'runtime_profile_id_may_be_omitted_but_if_supplied_must_match_config', summary.runtime_profile_identity_request_stream_policy);
  assertEqual(`${prefix} request runtime profile id not required`, false, summary.request_runtime_profile_id_required);
  assertEqual(`${prefix} omitted request runtime profile id absent`, false, summary.omitted_request_runtime_profile_id_present);
  assertEqual(`${prefix} omitted runtime profile id uses launcher config`, true, summary.omitted_runtime_profile_id_uses_launcher_config);
  assertEqual(`${prefix} omitted runtime profile id grant reason`, 'fixture_authority_grant_effect_satisfied', summary.omitted_runtime_profile_id_reason_code);
  assertEqual(`${prefix} omitted runtime profile id mutates once`, 1, summary.omitted_runtime_profile_id_state_entry_count_delta);
  assertEqual(`${prefix} omitted runtime profile id consumes one grant`, 1, summary.omitted_runtime_profile_id_consumed_authority_grant_count);
  assertEqual(`${prefix} supplied mismatched runtime profile id refused`, true, summary.supplied_mismatched_runtime_profile_id_refused);
  assertEqual(`${prefix} supplied mismatched runtime profile id reason`, 'agent_supplied_authority_material', summary.supplied_mismatch_reason_code);
  assertEqual(`${prefix} supplied mismatched runtime profile id state delta zero`, 0, summary.supplied_mismatch_state_entry_count_delta);
}

const PLAN_PATH = 'profiles/protected-records-runtime-profile-installation-plan.fixture.json';
const PROFILE_PATH = 'profiles/protected-records-runtime-fixture.profile.json';
const SAMPLE_ARTIFACT_PATH = 'tests/fixtures/protected-records-runtime-profile-installation-artifact-v1.json';
const SAMPLE_ARTIFACT_SHA256 = '5512d12a7320417f6499630557ec3c5993ffb88474ba2822891fb67e4f9bf88f';
const SAMPLE_PLAN_SHA256 = '03db9e980a4061af769b13f29a548f33cdea076cfb3d049750c0d1b478557f26';
const plan = JSON.parse(readFileSync(PLAN_PATH, 'utf8'));
const profile = JSON.parse(readFileSync(PROFILE_PATH, 'utf8'));
const profileSha = runtimeProfileSha256(profile);

section('runtime profile installation plan contract');
assert('plan passes validation', assertProtectedRecordsRuntimeProfileInstallationPlan(plan));
assertEqual('plan type', PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_PLAN_TYPE, plan.plan_type);
assertEqual('plan id', 'protected-records-runtime-profile-installation-fixture-plan', plan.plan_id);
assertEqual('plan status local disposable', 'sample_local_disposable_only', plan.plan_status);
assertEqual('deployment posture local disposable', 'local_disposable_profile_installation_only', plan.deployment_posture);
assertEqual('runtime profile source explicit', PROFILE_PATH, plan.runtime_profile_source);
assertEqual('runtime profile sha matches fixture', profileSha, plan.runtime_profile_sha256);
assertEqual('plan hash stable', SAMPLE_PLAN_SHA256, runtimeProfileInstallationPlanSha256(plan));
assertEqual('disposable install root created', true, plan.installation_boundary.local_disposable_install_root_created);
assertEqual('profile copied to install root', true, plan.installation_boundary.profile_copied_to_install_root);
assertEqual('active profile index written', true, plan.installation_boundary.active_profile_index_written);
assertEqual('profile selected from install root', true, plan.installation_boundary.profile_selected_from_install_root);
assertEqual('persistent runtime profile not installed', false, plan.installation_boundary.persistent_runtime_profile_installed);
assertEqual('hook config not written', false, plan.installation_boundary.writes_hook_configuration);
assertEqual('user config not written', false, plan.installation_boundary.writes_user_config);
assertEqual('machine config not written', false, plan.installation_boundary.writes_machine_config);
assertEqual('does not select latest', false, plan.installation_boundary.selects_latest_profile);
assertEqual('request authority material refused', false, plan.installation_boundary.request_stream_authority_material_accepted);
assertEqual('launcher supplies config', true, plan.activation_contract.launcher_supplies_config);
assertEqual('launcher supplies grant contract', true, plan.activation_contract.launcher_supplies_authority_grant_contract);
assertEqual('launcher supplies grant appointment', true, plan.activation_contract.launcher_supplies_authority_grant_appointment);
assertEqual('launcher supplies issuance decision', true, plan.activation_contract.launcher_supplies_authority_grant_issuance_decision);
assertEqual('request grant material refused', false, plan.activation_contract.authority_grant_material_agent_supplied);
assertEqual('recognition required', true, plan.activation_contract.downstream_recognition_required);
assertEqual('missing receipt refused required', true, plan.activation_contract.missing_or_unrecognized_receipt_refused);
for (const requirement of REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPERATOR_REQUIREMENTS) {
  assert(`operator requirement present: ${requirement}`, plan.operator_requirements.includes(requirement));
}
for (const boundary of REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPEN_BOUNDARIES) {
  assert(`open boundary present: ${boundary}`, plan.known_open_boundaries.includes(boundary));
}
for (const claim of RUNTIME_PROFILE_INSTALLATION_NON_CLAIMS) {
  assert(`non-claim present: ${claim}`, plan.non_claims.includes(claim));
}
assert('plan text is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(plan)));

section('runtime profile installation proof report');
const report = runProtectedRecordsRuntimeProfileInstallationProof(plan, profile);
assert('proof report passes validation', assertProtectedRecordsRuntimeProfileInstallationProof(report, plan, profile));
assertEqual('proof type', PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_PROOF_TYPE, report.proof_type);
assertEqual('safe claim ceiling exact', RUNTIME_PROFILE_INSTALLATION_SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('evidence model', 'local-disposable-runtime-profile-installation-fixture', report.evidence_model);
assertEqual('no live probing', false, report.live_probing);
assertEqual('plan sha binds input plan', SAMPLE_PLAN_SHA256, report.plan.plan_sha256);
assertEqual('profile sha binds input profile', profileSha, report.runtime_profile.profile_sha256);
assertEqual('profile sha matches plan', true, report.runtime_profile.profile_sha_matches_plan);
assertEqual('install root kind', 'launcher-owned-disposable-proof-root', report.installation.install_root_kind);
assertEqual('install root path omitted', null, report.installation.install_root_path_in_report);
assertEqual('profile copy written', true, report.installation.profile_copy_written);
assertEqual('active index written', true, report.installation.active_profile_index_written);
assertEqual('selected by explicit id and sha', true, report.installation.selected_by_explicit_id_and_sha);
assertEqual('does not select latest profile', false, report.installation.selects_latest_profile);
assertEqual('selected profile sha verified', true, report.installation.profile_sha_verified_before_selection);
assertEqual('installed profile status bounded', 'installed_in_disposable_proof_root', report.installation.installed_profile_status);
assertEqual('request guard installed profile state refused', true, report.request_authority_guard_summary.installed_profile_state_refused);
assertEqual('request guard runtime config refused', true, report.request_authority_guard_summary.runtime_config_refused);
assertEqual('request guard runtime profile refused', true, report.request_authority_guard_summary.runtime_profile_refused);
assertEqual('request guard recognition rule refused', true, report.request_authority_guard_summary.recognition_rule_refused);
assertEqual('request guard authority grant refused', true, report.request_authority_guard_summary.authority_grant_refused);
assertEqual('request guard all refused', true, report.request_authority_guard_summary.all_refused_before_mutation);
assertEqual('request guard state delta zero', 0, report.request_authority_guard_summary.state_entry_count_delta_total);
assertEqual('runtime proof run', true, report.runtime_proof_summary.proof_run);
assertEqual('runtime proof command', 'zlar protected-records-runtime-profile-proof', report.runtime_proof_summary.proof_command);
assertEqual('runtime service command', 'zlar protected-records-runtime-service --config <launcher-owned-disposable-config>', report.runtime_proof_summary.service_command);
assertEqual('recognized write accepted', true, report.runtime_proof_summary.recognized_write_accepted);
assertEqual('replay after restart refused', true, report.runtime_proof_summary.replay_after_restart_refused);
assertEqual('missing receipt refused', true, report.runtime_proof_summary.missing_receipt_refused);
assertEqual('invalid receipt refused', true, report.runtime_proof_summary.invalid_receipt_refused);
assertEqual('unknown issuer refused', true, report.runtime_proof_summary.unknown_issuer_refused);
assertEqual('retired issuer refused', true, report.runtime_proof_summary.retired_issuer_refused);
assertEqual('missing issuer status refused', true, report.runtime_proof_summary.missing_issuer_status_refused);
assertEqual('stale receipt refused', true, report.runtime_proof_summary.stale_receipt_refused);
assertEqual('wrong policy refused', true, report.runtime_proof_summary.wrong_policy_refused);
assertEqual('wrong domain refused', true, report.runtime_proof_summary.wrong_domain_refused);
assertEqual('wrong tool refused', true, report.runtime_proof_summary.wrong_tool_refused);
assertEqual('wrong runtime profile id refused', true, report.runtime_proof_summary.wrong_runtime_profile_id_refused);
assertEqual('wrong audit event refused', true, report.runtime_proof_summary.wrong_audit_event_refused);
assertEqual('wrong detail refused', true, report.runtime_proof_summary.wrong_detail_refused);
assertEqual('non-boarding outcome refused', true, report.runtime_proof_summary.non_boarding_outcome_refused);
assertEqual('direct api without receipt refused', true, report.runtime_proof_summary.direct_api_without_receipt_refused);
assertEqual('direct api with receipt refused', true, report.runtime_proof_summary.direct_api_with_receipt_refused);
assertEqual('authority material refused', true, report.runtime_proof_summary.agent_supplied_authority_material_refused);
assertEqual('fixture rightful issuance evidenced', true, report.runtime_proof_summary.fixture_rightful_issuance_path_evidenced);
assertEqual('same-process signed-payload replay refused', true, report.runtime_proof_summary.same_process_signed_payload_replay_refused);
assertEqual('restart consumed grant refused', true, report.runtime_proof_summary.restart_consumed_authority_grant_refused);
assertEqual('missing grant refused', true, report.runtime_proof_summary.missing_authority_grant_appointment_refused);
assertEqual('mismatched grant refused', true, report.runtime_proof_summary.mismatched_authority_grant_appointment_refused);
assertEqual('revoked grant refused', true, report.runtime_proof_summary.revoked_authority_grant_refused);
assertEqual('expired grant refused', true, report.runtime_proof_summary.expired_authority_grant_refused);
assertEqual('request-supplied grant refused', true, report.runtime_proof_summary.request_supplied_authority_grant_refused);
assertRuntimeProfileIdentitySummary('runtime proof summary', report.runtime_proof_summary);
assertEqual('case summaries count', profile.required_cases.length, report.case_summaries.length);
for (const caseId of profile.required_cases) {
  assert(`case summary present: ${caseId}`, Boolean(caseSummary(report, caseId)));
}
assertEqual('accepted write summary accepted', true, caseSummary(report, 'recognized_runtime_write_first_request').service_write_accepted);
assertEqual('wrong audit event summary reason', 'audit_event_mismatch', caseSummary(report, 'wrong_audit_event_refused_before_runtime_mutation').reason_code);
assertEqual('wrong runtime profile id reason', 'agent_supplied_authority_material', caseSummary(report, 'wrong_runtime_profile_id_refused_before_runtime_mutation').reason_code);
assertEqual('direct api with receipt reason', 'direct_api_receipt_present', caseSummary(report, 'direct_api_with_receipt_refused_before_runtime_mutation').reason_code);

section('open-boundary honesty');
assertEqual('side-door disposable installation true', true, report.side_door_report.disposable_profile_installation_applied);
assertEqual('side-door root created true', true, report.side_door_report.local_disposable_install_root_created);
assertEqual('side-door profile copied true', true, report.side_door_report.profile_copied_to_install_root);
assertEqual('side-door active index true', true, report.side_door_report.active_profile_index_written);
assertEqual('side-door selected from install root true', true, report.side_door_report.profile_selected_from_install_root);
assertEqual('side-door persistent runtime profile false', false, report.side_door_report.persistent_runtime_profile_installed);
assertEqual('side-door hook config false', false, report.side_door_report.hook_configuration_written);
assertEqual('side-door user config false', false, report.side_door_report.user_config_written);
assertEqual('side-door machine config false', false, report.side_door_report.machine_config_written);
assertEqual('side-door latest false', false, report.side_door_report.latest_profile_selected);
assertEqual('side-door live runtime profile unchecked', false, report.side_door_report.live_runtime_profile_checked);
assertEqual('side-door live records unchecked', false, report.side_door_report.live_records_system_checked);
assertEqual('side-door production unchecked', false, report.side_door_report.production_records_service_checked);
assertEqual('side-door external attestation false', false, report.side_door_report.external_attestation);
assertEqual('side-door sovereign recognition false', false, report.side_door_report.sovereign_recognition);
assertEqual('side-door unrouted records unchecked', false, report.side_door_report.unrouted_records_paths_checked);
assertEqual('side-door multi-file commit non-atomic', false, report.side_door_report.atomic_store_anchor_witness_commit);
assertEqual('side-door partial grant burn named', true, report.side_door_report.partial_grant_commit_burn_window_named);
assertEqual('side-door joint rollback not detected', false, report.side_door_report.store_anchor_and_witness_joint_rollback_detection);
assertEqual('side-door host path TOCTOU open', false, report.side_door_report.host_filesystem_path_toctou_closed);
assert('json output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report, null, 2)));
assert('json omits private and temp paths', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(JSON.stringify(report)));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(JSON.stringify(report)));

section('safe output formatting');
const summary = formatProtectedRecordsRuntimeProfileInstallationProofSummary(report, plan, profile);
assert('summary title present', summary.includes('ZLAR Protected Records Runtime Profile Installation Proof v1'));
assert('summary includes disposable install', summary.includes('disposable_root_created=true; profile_copy_written=true'));
assert('summary includes selected by id and sha', summary.includes('selected_by_id_and_sha=true'));
assert('summary includes request authority guard', summary.includes('installed_profile_state_refused=true; runtime_config_refused=true'));
assert('summary includes runtime profile identity policy', summary.includes('Runtime profile identity policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('summary includes wrong runtime profile id refusal', summary.includes('wrong_runtime_profile_id_refused=true'));
assert('summary includes wrong audit event refusal', summary.includes('wrong_audit_event_refused=true'));
assert('summary includes no persistent profile install', summary.includes('persistent_runtime_profile_installed=false'));
assert('summary includes non-claim', summary.includes('launcher-owned disposable proof root'));
assert('summary output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(summary));

section('portable artifact and verification');
const artifact = buildProtectedRecordsRuntimeProfileInstallationArtifact(plan, profile, report);
assert('artifact passes validation', assertProtectedRecordsRuntimeProfileInstallationArtifact(artifact));
assertEqual('artifact type', PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_TYPE, artifact.artifact_type);
assertEqual('artifact canonicalization', 'zlar-canonical-json-v1', artifact.canonicalization);
assertEqual('artifact generator', 'zlar protected-records-runtime-profile-installation --artifact', artifact.generator);
assertEqual('artifact hash scope', 'canonical artifact body without integrity', artifact.hash_scope);
assertEqual('artifact sha stable', SAMPLE_ARTIFACT_SHA256, artifact.integrity.body_sha256);
assertEqual('artifact embeds exact plan sha', SAMPLE_PLAN_SHA256, artifact.payload.proof.plan.plan_sha256);
assertEqual('artifact embeds selected from install root', true, artifact.payload.proof.installation.profile_selected_from_install_root);
assert('artifact text is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(artifact, null, 2)));

const parsedArtifact = parseProtectedRecordsRuntimeProfileInstallationArtifactText(JSON.stringify(artifact, null, 2));
assert('parsed artifact passes validation', assertProtectedRecordsRuntimeProfileInstallationArtifact(parsedArtifact));
assertEqual('parsed artifact sha stable', artifact.integrity.body_sha256, parsedArtifact.integrity.body_sha256);

const verification = verifyProtectedRecordsRuntimeProfileInstallationArtifact(parsedArtifact);
assertEqual('verification type', PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
assertEqual('verification verified true', true, verification.verified);
assertEqual('verification sha matches artifact', SAMPLE_ARTIFACT_SHA256, verification.body_sha256);
assertEqual('verification payload type', PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_PROOF_TYPE, verification.payload_type);
assertEqual('verification live probing false', false, verification.live_probing);
assertEqual('verification plan sha matches', SAMPLE_PLAN_SHA256, verification.plan_sha256);
assertEqual('verification profile sha matches', profileSha, verification.runtime_profile_sha256);
assertEqual('verification request guard refused', true, verification.request_authority_guard_refused);
assertEqual('verification disposable install true', true, verification.disposable_profile_installation_applied);
assertEqual('verification persistent profile false', false, verification.persistent_runtime_profile_installed);
assertEqual('verification hook config false', false, verification.hook_configuration_written);
assertEqual('verification runtime service true', true, verification.runtime_service_started);
assertEqual('verification missing receipt refused true', true, verification.missing_receipt_refused);
assertEqual('verification invalid receipt refused true', true, verification.invalid_receipt_refused);
assertEqual('verification unknown issuer refused true', true, verification.unknown_issuer_refused);
assertEqual('verification retired issuer refused true', true, verification.retired_issuer_refused);
assertEqual('verification missing issuer status refused true', true, verification.missing_issuer_status_refused);
assertEqual('verification stale receipt refused true', true, verification.stale_receipt_refused);
assertEqual('verification wrong policy refused true', true, verification.wrong_policy_refused);
assertEqual('verification wrong domain refused true', true, verification.wrong_domain_refused);
assertEqual('verification wrong tool refused true', true, verification.wrong_tool_refused);
assertEqual('verification wrong runtime profile id refused true', true, verification.wrong_runtime_profile_id_refused);
assertEqual('verification wrong audit event refused true', true, verification.wrong_audit_event_refused);
assertEqual('verification wrong detail refused true', true, verification.wrong_detail_refused);
assertEqual('verification non-boarding outcome refused true', true, verification.non_boarding_outcome_refused);
assert('verification output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(verification, null, 2)));
assertRuntimeProfileIdentitySummary('verification', verification);

const artifactSummary = formatProtectedRecordsRuntimeProfileInstallationArtifactSummary(artifact);
assert('artifact summary names portable artifact', artifactSummary.includes('Portable runtime profile installation artifact:'));
assert('artifact summary includes checksum', artifactSummary.includes(SAMPLE_ARTIFACT_SHA256));
assert('artifact summary is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(artifactSummary));

const verificationSummary = formatProtectedRecordsRuntimeProfileInstallationArtifactVerification(verification);
assert('verification summary title present', verificationSummary.includes('ZLAR Protected Records Runtime Profile Installation Artifact Verification v1'));
assert('verification summary says verified', verificationSummary.includes('verified=true'));
assert('verification summary includes request authority guard', verificationSummary.includes('request_authority_guard_refused=true'));
assert('verification summary includes claim boundary', verificationSummary.includes('embedded local disposable runtime profile installation proof boundaries only'));
assert('verification summary includes identity policy', verificationSummary.includes('runtime_profile_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('verification summary includes wrong runtime profile id refusal', verificationSummary.includes('wrong_runtime_profile_id_refused=true'));
assert('verification summary is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(verificationSummary));

section('committed sample artifact');
const sampleArtifactText = readFileSync(SAMPLE_ARTIFACT_PATH, 'utf8');
assert('sample artifact text is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(sampleArtifactText));
const sampleArtifact = parseProtectedRecordsRuntimeProfileInstallationArtifactText(sampleArtifactText);
assert('sample artifact passes validation', assertProtectedRecordsRuntimeProfileInstallationArtifact(sampleArtifact));
assertEqual('sample artifact hash is stable', SAMPLE_ARTIFACT_SHA256, sampleArtifact.integrity.body_sha256);
assertEqual('sample artifact embeds same plan sha', SAMPLE_PLAN_SHA256, sampleArtifact.payload.proof.plan.plan_sha256);
assertEqual('sample artifact embeds same profile sha', profileSha, sampleArtifact.payload.proof.runtime_profile.profile_sha256);
const sampleVerification = verifyProtectedRecordsRuntimeProfileInstallationArtifact(sampleArtifact);
assertEqual('sample artifact verifies true', true, sampleVerification.verified);
assertEqual('sample verification sha matches fixture', SAMPLE_ARTIFACT_SHA256, sampleVerification.body_sha256);
assertEqual('sample verification live probing false', false, sampleVerification.live_probing);
assertRuntimeProfileIdentitySummary('sample verification', sampleVerification);

section('fail closed validation');
const stalePlan = structuredClone(plan);
stalePlan.plan_status = 'active';
assertThrows('active plan status fails', () => assertProtectedRecordsRuntimeProfileInstallationPlan(stalePlan), 'contract drifted');

const shaMismatchPlan = structuredClone(plan);
shaMismatchPlan.runtime_profile_sha256 = '0'.repeat(64);
assertThrows('plan/profile sha mismatch fails', () => runProtectedRecordsRuntimeProfileInstallationProof(shaMismatchPlan, profile), 'profile SHA mismatch');

const persistentInstallPlan = structuredClone(plan);
persistentInstallPlan.installation_boundary.persistent_runtime_profile_installed = true;
assertThrows('persistent install claim fails', () => assertProtectedRecordsRuntimeProfileInstallationPlan(persistentInstallPlan), 'installation boundary drifted');

const latestPlan = structuredClone(plan);
latestPlan.installation_boundary.selects_latest_profile = true;
assertThrows('latest selection claim fails', () => assertProtectedRecordsRuntimeProfileInstallationPlan(latestPlan), 'installation boundary drifted');

const reportWithHookWrite = structuredClone(report);
reportWithHookWrite.side_door_report.hook_configuration_written = true;
assertThrows('hook write claim fails', () => assertProtectedRecordsRuntimeProfileInstallationProof(reportWithHookWrite, plan, profile), 'side-door report drifted');

const reportWithGuardBypass = structuredClone(report);
reportWithGuardBypass.request_authority_guard_summary.runtime_config_refused = false;
assertThrows('runtime config guard bypass fails', () => assertProtectedRecordsRuntimeProfileInstallationProof(reportWithGuardBypass, plan, profile), 'request authority guard drifted');

const runtimeProfileIdentityPolicyDrift = structuredClone(report);
runtimeProfileIdentityPolicyDrift.runtime_proof_summary.omitted_runtime_profile_id_uses_launcher_config = false;
assertThrows('runtime profile identity policy drift fails', () => assertProtectedRecordsRuntimeProfileInstallationProof(runtimeProfileIdentityPolicyDrift, plan, profile), 'proof summary drifted');

const tamperedArtifact = structuredClone(artifact);
tamperedArtifact.payload.proof.installation.selected_by_explicit_id_and_sha = false;
assertThrows('tampered artifact fails', () => assertProtectedRecordsRuntimeProfileInstallationArtifact(tamperedArtifact), 'selection drifted');

const badHashArtifact = structuredClone(artifact);
badHashArtifact.integrity.body_sha256 = '0'.repeat(64);
assertThrows('artifact hash mismatch fails', () => assertProtectedRecordsRuntimeProfileInstallationArtifact(badHashArtifact), 'SHA-256 mismatch');

console.log(`\nResults: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) {
  process.exit(1);
}
console.log('ALL PASS');
