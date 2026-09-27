#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import {
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from '../lib/protected-records-runtime-profile.mjs';
import {
  runtimeProfileSha256,
} from '../lib/protected-records-runtime-profile-preflight.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_TYPE,
  PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_VERIFICATION_TYPE,
  PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PLAN_TYPE,
  PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PROOF_TYPE,
  REQUIRED_RUNTIME_LOCAL_ACTIVATION_OPEN_BOUNDARIES,
  REQUIRED_RUNTIME_LOCAL_ACTIVATION_OPERATOR_REQUIREMENTS,
  RUNTIME_LOCAL_ACTIVATION_NON_CLAIMS,
  RUNTIME_LOCAL_ACTIVATION_SAFE_CLAIM_CEILING,
  assertProtectedRecordsRuntimeLocalActivationArtifact,
  assertProtectedRecordsRuntimeLocalActivationPlan,
  assertProtectedRecordsRuntimeLocalActivationProof,
  buildProtectedRecordsRuntimeLocalActivationArtifact,
  formatProtectedRecordsRuntimeLocalActivationArtifactSummary,
  formatProtectedRecordsRuntimeLocalActivationArtifactVerification,
  formatProtectedRecordsRuntimeLocalActivationProofSummary,
  parseProtectedRecordsRuntimeLocalActivationArtifactText,
  runProtectedRecordsRuntimeLocalActivationProof,
  runtimeLocalActivationPlanSha256,
  verifyProtectedRecordsRuntimeLocalActivationArtifact,
} from '../lib/protected-records-runtime-local-activation.mjs';

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
  assertEqual(`${prefix} omitted runtime profile id consumes one authority grant`, 1, summary.omitted_runtime_profile_id_consumed_authority_grant_count);
  assertEqual(`${prefix} supplied mismatched runtime profile id refused`, true, summary.supplied_mismatched_runtime_profile_id_refused);
  assertEqual(`${prefix} supplied mismatched runtime profile id reason`, 'agent_supplied_authority_material', summary.supplied_mismatch_reason_code);
  assertEqual(`${prefix} supplied mismatched runtime profile id state delta zero`, 0, summary.supplied_mismatch_state_entry_count_delta);
}

const PLAN_PATH = 'profiles/protected-records-runtime-local-activation-plan.fixture.json';
const PROFILE_PATH = 'profiles/protected-records-runtime-fixture.profile.json';
const SAMPLE_ARTIFACT_PATH = 'tests/fixtures/protected-records-runtime-local-activation-artifact-v1.json';
const SAMPLE_ARTIFACT_SHA256 = 'dbf2b182501a38c870377984d58c92ae28cfc857afa86fc9686dd90a64bd846b';
const SAMPLE_PLAN_SHA256 = '40a8703eea4ab0066574e87870bfecd4a5dc87a77a9d71d54a3ac9435ddd480a';
const plan = JSON.parse(readFileSync(PLAN_PATH, 'utf8'));
const profile = JSON.parse(readFileSync(PROFILE_PATH, 'utf8'));
const profileSha = runtimeProfileSha256(profile);

section('runtime local activation plan contract');
assert('plan passes validation', assertProtectedRecordsRuntimeLocalActivationPlan(plan));
assertEqual('plan type', PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PLAN_TYPE, plan.plan_type);
assertEqual('plan id', 'protected-records-runtime-local-activation-fixture-plan', plan.plan_id);
assertEqual('plan status local disposable', 'sample_local_disposable_only', plan.plan_status);
assertEqual('deployment posture local disposable', 'local_disposable_activation_only', plan.deployment_posture);
assertEqual('runtime profile id', 'protected-records-disposable-runtime-profile', plan.runtime_profile_id);
assertEqual('runtime profile source explicit', PROFILE_PATH, plan.runtime_profile_source);
assertEqual('runtime profile sha matches fixture', profileSha, plan.runtime_profile_sha256);
assertEqual('plan hash stable', SAMPLE_PLAN_SHA256, runtimeLocalActivationPlanSha256(plan));
assertEqual('local activation applied', true, plan.activation_boundary.local_activation_applied);
assertEqual('disposable runtime config written', true, plan.activation_boundary.disposable_runtime_config_written);
assertEqual('persistent runtime config not written', false, plan.activation_boundary.persistent_runtime_config_written);
assertEqual('hook config not written', false, plan.activation_boundary.writes_hook_configuration);
assertEqual('starts runtime service', true, plan.activation_boundary.starts_runtime_service);
assertEqual('persistent runtime profile not installed', false, plan.activation_boundary.persistent_runtime_profile_installed);
assertEqual('requires explicit local command', true, plan.activation_boundary.requires_explicit_local_command);
assertEqual('does not select latest', false, plan.activation_boundary.selects_latest_profile);
assertEqual('request authority material refused', false, plan.activation_boundary.request_stream_authority_material_accepted);
assertEqual('launcher supplies config', true, plan.activation_contract.launcher_supplies_config);
assertEqual('config path not agent supplied', false, plan.activation_contract.config_path_agent_supplied);
assertEqual('state path not agent supplied', false, plan.activation_contract.state_path_agent_supplied);
assertEqual('grant store path not agent supplied', false, plan.activation_contract.consumed_grants_path_agent_supplied);
assertEqual('grant anchor path not agent supplied', false, plan.activation_contract.consumed_grant_store_anchor_path_agent_supplied);
assertEqual('grant witness path not agent supplied', false, plan.activation_contract.consumed_grant_store_witness_path_agent_supplied);
assertEqual('launcher grant contract required', true, plan.activation_contract.authority_grant_contract_required_from_launcher);
assertEqual('launcher grant appointment required', true, plan.activation_contract.authority_grant_appointment_required_from_launcher);
assertEqual('launcher grant issuance decision required', true, plan.activation_contract.authority_grant_issuance_decision_required_from_launcher);
assertEqual('launcher authorized record update required', true, plan.activation_contract.authorized_record_update_required_from_launcher);
assertEqual('request supplied grant refused', true, plan.activation_contract.request_supplied_authority_grant_refused);
assertEqual('recognition required', true, plan.activation_contract.downstream_recognition_required);
assertEqual('missing receipt refused required', true, plan.activation_contract.missing_or_unrecognized_receipt_refused);
for (const requirement of REQUIRED_RUNTIME_LOCAL_ACTIVATION_OPERATOR_REQUIREMENTS) {
  assert(`operator requirement present: ${requirement}`, plan.operator_requirements.includes(requirement));
}
for (const boundary of REQUIRED_RUNTIME_LOCAL_ACTIVATION_OPEN_BOUNDARIES) {
  assert(`open boundary present: ${boundary}`, plan.known_open_boundaries.includes(boundary));
}
for (const claim of RUNTIME_LOCAL_ACTIVATION_NON_CLAIMS) {
  assert(`non-claim present: ${claim}`, plan.non_claims.includes(claim));
}
assert('plan text is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(plan)));

section('runtime local activation proof report');
const report = runProtectedRecordsRuntimeLocalActivationProof(plan, profile);
assert('proof report passes validation', assertProtectedRecordsRuntimeLocalActivationProof(report, plan, profile));
assertEqual('proof type', PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PROOF_TYPE, report.proof_type);
assertEqual('safe claim ceiling exact', RUNTIME_LOCAL_ACTIVATION_SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('evidence model', 'local-disposable-runtime-activation-fixture', report.evidence_model);
assertEqual('no live probing', false, report.live_probing);
assertEqual('plan sha binds input plan', SAMPLE_PLAN_SHA256, report.plan.plan_sha256);
assertEqual('profile sha binds input profile', profileSha, report.runtime_profile.profile_sha256);
assertEqual('profile sha matches plan', true, report.runtime_profile.profile_sha_matches_plan);
assertEqual('runtime proof run', true, report.runtime_proof_summary.proof_run);
assertEqual('runtime proof command', 'zlar protected-records-runtime-profile-proof', report.runtime_proof_summary.proof_command);
assertEqual('runtime service command', 'zlar protected-records-runtime-service --config <launcher-owned-disposable-config>', report.runtime_proof_summary.service_command);
assertEqual('runtime proof case count', profile.required_cases.length, report.runtime_proof_summary.case_count);
assertEqual('runtime proof required count', profile.required_cases.length, report.runtime_proof_summary.required_case_count);
assertEqual('runtime boundary count', profile.required_boundary_observations.length, report.runtime_proof_summary.boundary_observation_count);
assertEqual('mutation route exact', 'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation', report.runtime_proof_summary.mutation_authoritative_route);
assertEqual('grant store identity exact', 'persistent-single-use-authority-grant-contract-sha256-store', report.runtime_proof_summary.consumed_authority_grant_store);
assertEqual('grant consumption identity exact', 'authority-grant-contract-sha256', report.runtime_proof_summary.consumption_identity);
assertEqual('signed-payload replay identity exact', 'verified-signed-payload-sha256', report.runtime_proof_summary.signed_payload_replay_identity);
assertEqual('grant store witness exact', 'launcher-owned-local-store-hash-witness', report.runtime_proof_summary.consumed_store_witness);
assertEqual('grant store write model exact', 'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness', report.runtime_proof_summary.consumed_store_write_model);
assertEqual('recognized write accepted', true, report.runtime_proof_summary.recognized_write_accepted);
assertEqual('same-process signed-payload replay refused', true, report.runtime_proof_summary.same_process_signed_payload_replay_refused);
assertEqual('restart consumed authority grant refused', true, report.runtime_proof_summary.restart_consumed_authority_grant_refused);
assertEqual('witness commit burn observed', true, report.runtime_proof_summary.witness_commit_failed_after_authority_grant_store_commit);
assertEqual('witness commit burn reason', 'consumed_store_write_failed_after_grant_commit', report.runtime_proof_summary.witness_commit_failure_reason_code);
assertEqual('witness commit burns one authority grant', 1, report.runtime_proof_summary.witness_commit_failure_consumed_authority_grant_count);
assertEqual('witness-ahead joint store-anchor rollback refused', true, report.runtime_proof_summary.store_and_anchor_joint_rollback_refused_against_witness);
assertEqual('missing grant appointment refused', true, report.runtime_proof_summary.missing_authority_grant_appointment_refused);
assertEqual('mismatched grant appointment refused', true, report.runtime_proof_summary.mismatched_authority_grant_appointment_refused);
assertEqual('revoked grant refused', true, report.runtime_proof_summary.revoked_authority_grant_refused);
assertEqual('expired grant refused', true, report.runtime_proof_summary.expired_authority_grant_refused);
assertEqual('request supplied grant refused', true, report.runtime_proof_summary.request_supplied_authority_grant_refused);
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
assertRuntimeProfileIdentitySummary('runtime proof summary', report.runtime_proof_summary);
assertEqual('witness-ahead rollback refusal true', true, report.runtime_proof_summary.store_and_anchor_joint_rollback_refused_while_witness_ahead);
assertEqual('joint store-anchor-witness rollback not detected', false, report.runtime_proof_summary.store_anchor_and_witness_joint_rollback_detection);
assertEqual('joint rollback reopens grant reuse', true, report.runtime_proof_summary.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse);
assertEqual('case summaries count', profile.required_cases.length, report.case_summaries.length);
for (const caseId of profile.required_cases) {
  assert(`case summary present: ${caseId}`, Boolean(caseSummary(report, caseId)));
}
assertEqual('accepted write summary accepted', true, caseSummary(report, 'recognized_runtime_write_first_request').service_write_accepted);
assertEqual('replay summary refused', false, caseSummary(report, 'replay_runtime_write_refused_after_service_restart').service_write_accepted);
assertEqual('wrong audit event summary reason', 'audit_event_mismatch', caseSummary(report, 'wrong_audit_event_refused_before_runtime_mutation').reason_code);
assertEqual('wrong runtime profile id reason', 'agent_supplied_authority_material', caseSummary(report, 'wrong_runtime_profile_id_refused_before_runtime_mutation').reason_code);
assertEqual('direct api with receipt reason', 'direct_api_receipt_present', caseSummary(report, 'direct_api_with_receipt_refused_before_runtime_mutation').reason_code);

section('open-boundary honesty');
assertEqual('side-door local activation true', true, report.side_door_report.local_activation_applied);
assertEqual('side-door disposable config true', true, report.side_door_report.disposable_runtime_config_written);
assertEqual('side-door persistent config false', false, report.side_door_report.persistent_runtime_config_written);
assertEqual('side-door hook config false', false, report.side_door_report.hook_configuration_written);
assertEqual('side-door runtime service true', true, report.side_door_report.runtime_service_started);
assertEqual('side-door persistent runtime profile false', false, report.side_door_report.persistent_runtime_profile_installed);
assertEqual('side-door request supplied grant refused', true, report.side_door_report.request_supplied_authority_grant_refused);
assertEqual('side-door persistent grant store true', true, report.side_door_report.persistent_consumed_authority_grant_store);
assertEqual('side-door grant store anchor true', true, report.side_door_report.consumed_store_anchor_present);
assertEqual('side-door grant store witness true', true, report.side_door_report.consumed_store_witness_present);
assertEqual('side-door live records unchecked', false, report.side_door_report.live_records_system_checked);
assertEqual('side-door production service unchecked', false, report.side_door_report.production_records_service_checked);
assertEqual('side-door live MCP unchecked', false, report.side_door_report.live_mcp_coverage_checked);
assertEqual('side-door live approval unchecked', false, report.side_door_report.live_approval_channel_health_checked);
assertEqual('side-door exactly-once semantics false', false, report.side_door_report.exactly_once_effect_semantics);
assertEqual('side-door witness-ahead refusal true', true, report.side_door_report.store_and_anchor_joint_rollback_refused_while_witness_ahead);
assertEqual('side-door joint rollback detection false', false, report.side_door_report.store_anchor_and_witness_joint_rollback_detection);
assertEqual('side-door joint rollback reopens grant reuse', true, report.side_door_report.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse);
assertEqual('side-door store-anchor-witness commit non-atomic', false, report.side_door_report.atomic_store_anchor_witness_commit);
assertEqual('side-door burn window named', true, report.side_door_report.partial_grant_commit_burn_window_named);
assertEqual('side-door missing witness partial commit observed', true, report.side_door_report.partial_commit_witness_missing_observed);
assertEqual('side-door host path TOCTOU open', false, report.side_door_report.host_filesystem_path_toctou_closed);
assertEqual('side-door external attestation false', false, report.side_door_report.external_attestation);
assertEqual('side-door sovereign recognition false', false, report.side_door_report.sovereign_recognition);
assertEqual('side-door unrouted records unchecked', false, report.side_door_report.unrouted_records_paths_checked);
assert('json output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report, null, 2)));
assert('json omits private and temp paths', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(JSON.stringify(report)));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(JSON.stringify(report)));

section('safe output formatting');
const summary = formatProtectedRecordsRuntimeLocalActivationProofSummary(report, plan, profile);
assert('summary title present', summary.includes('ZLAR Protected Records Runtime Local Activation Proof v1'));
assert('summary includes local activation true', summary.includes('applied=true; disposable_runtime_config_written=true; persistent_runtime_config_written=false'));
assert('summary includes runtime service start', summary.includes('starts_runtime_service=true'));
assert('summary includes runtime proof counts', summary.includes(`cases=${profile.required_cases.length}/${profile.required_cases.length}`));
assert('summary includes runtime profile identity policy', summary.includes('Runtime profile identity policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('summary includes storage identities', summary.includes('consumed_authority_grant_store=persistent-single-use-authority-grant-contract-sha256-store; consumption_identity=authority-grant-contract-sha256; signed_payload_replay_identity=verified-signed-payload-sha256'));
assert('summary includes replay split', summary.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true'));
assert('summary includes grant refusals', summary.includes('missing_grant_refused=true; mismatched_grant_refused=true; revoked_grant_refused=true; expired_grant_refused=true; request_supplied_grant_refused=true'));
assert('summary includes burn and rollback boundaries', summary.includes('atomic_store_anchor_witness_commit=false; burn_window_named=true; witness_ahead_refusal=true; joint_rollback_detection=false; joint_rollback_reopens_grant_reuse=true; host_path_toctou_closed=false'));
assert('summary includes receipt refusal checks', summary.includes('missing_receipt_refused=true; invalid_receipt_refused=true'));
assert('summary includes wrong runtime profile id refusal', summary.includes('wrong_runtime_profile_id_refused=true'));
assert('summary includes wrong audit event refusal', summary.includes('wrong_audit_event_refused=true'));
assert('summary includes non-claim', summary.includes('not a persistent install or production deployment'));
assert('summary output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(summary));

section('portable artifact and verification');
const artifact = buildProtectedRecordsRuntimeLocalActivationArtifact(plan, profile, report);
assert('artifact passes validation', assertProtectedRecordsRuntimeLocalActivationArtifact(artifact));
assertEqual('artifact type', PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_TYPE, artifact.artifact_type);
assertEqual('artifact canonicalization', 'zlar-canonical-json-v1', artifact.canonicalization);
assertEqual('artifact generator', 'zlar protected-records-runtime-local-activation --artifact', artifact.generator);
assertEqual('artifact hash scope', 'canonical artifact body without integrity', artifact.hash_scope);
assertEqual('artifact sha stable', SAMPLE_ARTIFACT_SHA256, artifact.integrity.body_sha256);
assertEqual('artifact embeds exact plan sha', SAMPLE_PLAN_SHA256, artifact.payload.proof.plan.plan_sha256);
assertEqual('artifact embeds profile sha match', true, artifact.payload.proof.runtime_profile.profile_sha_matches_plan);
assertEqual('artifact embeds local activation', true, artifact.payload.proof.side_door_report.local_activation_applied);
assert('artifact text is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(artifact, null, 2)));

const parsedArtifact = parseProtectedRecordsRuntimeLocalActivationArtifactText(JSON.stringify(artifact, null, 2));
assert('parsed artifact passes validation', assertProtectedRecordsRuntimeLocalActivationArtifact(parsedArtifact));
assertEqual('parsed artifact sha stable', artifact.integrity.body_sha256, parsedArtifact.integrity.body_sha256);

const verification = verifyProtectedRecordsRuntimeLocalActivationArtifact(parsedArtifact);
assertEqual('verification type', PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
assertEqual('verification verified true', true, verification.verified);
assertEqual('verification sha matches artifact', SAMPLE_ARTIFACT_SHA256, verification.body_sha256);
assertEqual('verification payload type', PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PROOF_TYPE, verification.payload_type);
assertEqual('verification live probing false', false, verification.live_probing);
assertEqual('verification plan sha matches', SAMPLE_PLAN_SHA256, verification.plan_sha256);
assertEqual('verification profile sha matches', profileSha, verification.runtime_profile_sha256);
assertEqual('verification local activation true', true, verification.local_activation_applied);
assertEqual('verification disposable config true', true, verification.disposable_runtime_config_written);
assertEqual('verification persistent config false', false, verification.persistent_runtime_config_written);
assertEqual('verification hook config false', false, verification.hook_configuration_written);
assertEqual('verification runtime service true', true, verification.runtime_service_started);
assertEqual('verification accepted write true', true, verification.recognized_write_accepted);
assertEqual('verification grant store identity exact', 'persistent-single-use-authority-grant-contract-sha256-store', verification.consumed_authority_grant_store);
assertEqual('verification grant consumption identity exact', 'authority-grant-contract-sha256', verification.consumption_identity);
assertEqual('verification signed-payload replay identity exact', 'verified-signed-payload-sha256', verification.signed_payload_replay_identity);
assertEqual('verification same-process signed-payload replay refused', true, verification.same_process_signed_payload_replay_refused);
assertEqual('verification restart consumed authority grant refused', true, verification.restart_consumed_authority_grant_refused);
assertEqual('verification missing grant refused', true, verification.missing_authority_grant_appointment_refused);
assertEqual('verification mismatched grant refused', true, verification.mismatched_authority_grant_appointment_refused);
assertEqual('verification revoked grant refused', true, verification.revoked_authority_grant_refused);
assertEqual('verification expired grant refused', true, verification.expired_authority_grant_refused);
assertEqual('verification request supplied grant refused', true, verification.request_supplied_authority_grant_refused);
assertEqual('verification witness commit burn observed', true, verification.witness_commit_failed_after_authority_grant_store_commit);
assertEqual('verification witness commit burn reason', 'consumed_store_write_failed_after_grant_commit', verification.witness_commit_failure_reason_code);
assertEqual('verification store-anchor-witness commit non-atomic', false, verification.atomic_store_anchor_witness_commit);
assertEqual('verification burn window named', true, verification.partial_grant_commit_burn_window_named);
assertEqual('verification witness-ahead refusal true', true, verification.store_and_anchor_joint_rollback_refused_while_witness_ahead);
assertEqual('verification joint rollback detection false', false, verification.store_anchor_and_witness_joint_rollback_detection);
assertEqual('verification joint rollback reopens grant reuse', true, verification.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse);
assertEqual('verification host path TOCTOU open', false, verification.host_filesystem_path_toctou_closed);
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
assertEqual('verification direct api with receipt refused true', true, verification.direct_api_with_receipt_refused);
assertRuntimeProfileIdentitySummary('verification', verification);
assert('verification output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(verification, null, 2)));

const artifactSummary = formatProtectedRecordsRuntimeLocalActivationArtifactSummary(artifact);
assert('artifact summary names portable artifact', artifactSummary.includes('Portable local activation artifact:'));
assert('artifact summary includes checksum', artifactSummary.includes(SAMPLE_ARTIFACT_SHA256));
assert('artifact summary is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(artifactSummary));

const verificationSummary = formatProtectedRecordsRuntimeLocalActivationArtifactVerification(verification);
assert('verification summary title present', verificationSummary.includes('ZLAR Protected Records Runtime Local Activation Artifact Verification v1'));
assert('verification summary says verified', verificationSummary.includes('verified=true'));
assert('verification summary includes claim boundary', verificationSummary.includes('embedded local disposable runtime activation proof boundaries only'));
assert('verification summary keeps local activation boundary', verificationSummary.includes('local_activation_applied=true; disposable_runtime_config_written=true; persistent_runtime_config_written=false'));
assert('verification summary includes identity policy', verificationSummary.includes('runtime_profile_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('verification summary includes storage identities', verificationSummary.includes('consumed_authority_grant_store=persistent-single-use-authority-grant-contract-sha256-store; consumption_identity=authority-grant-contract-sha256; signed_payload_replay_identity=verified-signed-payload-sha256'));
assert('verification summary includes replay split', verificationSummary.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true'));
assert('verification summary includes grant refusals', verificationSummary.includes('missing_grant_refused=true; mismatched_grant_refused=true; revoked_grant_refused=true; expired_grant_refused=true; request_supplied_grant_refused=true'));
assert('verification summary includes burn and rollback boundaries', verificationSummary.includes('atomic_store_anchor_witness_commit=false; burn_window_named=true; witness_ahead_refusal=true; joint_rollback_detection=false; joint_rollback_reopens_grant_reuse=true; host_path_toctou_closed=false'));
assert('verification summary includes wrong runtime profile id refusal', verificationSummary.includes('wrong_runtime_profile_id_refused=true'));
assert('verification summary is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(verificationSummary));

section('committed sample artifact');
const sampleArtifactText = readFileSync(SAMPLE_ARTIFACT_PATH, 'utf8');
assert('sample artifact text is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(sampleArtifactText));
const sampleArtifact = parseProtectedRecordsRuntimeLocalActivationArtifactText(sampleArtifactText);
assert('sample artifact passes validation', assertProtectedRecordsRuntimeLocalActivationArtifact(sampleArtifact));
assertEqual('sample artifact hash is stable', SAMPLE_ARTIFACT_SHA256, sampleArtifact.integrity.body_sha256);
assertEqual('sample artifact embeds same plan sha', SAMPLE_PLAN_SHA256, sampleArtifact.payload.proof.plan.plan_sha256);
assertEqual('sample artifact embeds same profile sha', profileSha, sampleArtifact.payload.proof.runtime_profile.profile_sha256);
const sampleVerification = verifyProtectedRecordsRuntimeLocalActivationArtifact(sampleArtifact);
assertEqual('sample artifact verifies true', true, sampleVerification.verified);
assertEqual('sample verification sha matches fixture', SAMPLE_ARTIFACT_SHA256, sampleVerification.body_sha256);
assertEqual('sample verification live probing false', false, sampleVerification.live_probing);
assertRuntimeProfileIdentitySummary('sample verification', sampleVerification);

section('fail closed validation');
const stalePlan = structuredClone(plan);
stalePlan.plan_status = 'active';
assertThrows('active plan status fails', () => assertProtectedRecordsRuntimeLocalActivationPlan(stalePlan), 'contract drifted');

const shaMismatchPlan = structuredClone(plan);
shaMismatchPlan.runtime_profile_sha256 = '0'.repeat(64);
assertThrows('plan/profile sha mismatch fails', () => runProtectedRecordsRuntimeLocalActivationProof(shaMismatchPlan, profile), 'profile SHA mismatch');

const reportWithHookWrite = structuredClone(report);
reportWithHookWrite.side_door_report.hook_configuration_written = true;
assertThrows('hook write claim fails', () => assertProtectedRecordsRuntimeLocalActivationProof(reportWithHookWrite, plan, profile), 'side-door report drifted');

const reportWithProductionClaim = structuredClone(report);
reportWithProductionClaim.side_door_report.production_records_service_checked = true;
assertThrows('production check claim fails', () => assertProtectedRecordsRuntimeLocalActivationProof(reportWithProductionClaim, plan, profile), 'side-door report drifted');

const runtimeProfileIdentityPolicyDrift = structuredClone(report);
runtimeProfileIdentityPolicyDrift.runtime_proof_summary.omitted_runtime_profile_id_uses_launcher_config = false;
assertThrows('runtime profile identity policy drift fails', () => assertProtectedRecordsRuntimeLocalActivationProof(runtimeProfileIdentityPolicyDrift, plan, profile), 'proof summary drifted');

const tamperedArtifact = structuredClone(artifact);
tamperedArtifact.payload.proof.runtime_proof_summary.missing_receipt_refused = false;
assertThrows('tampered artifact fails', () => assertProtectedRecordsRuntimeLocalActivationArtifact(tamperedArtifact), 'proof summary drifted');

const badHashArtifact = structuredClone(artifact);
badHashArtifact.integrity.body_sha256 = '0'.repeat(64);
assertThrows('artifact hash mismatch fails', () => assertProtectedRecordsRuntimeLocalActivationArtifact(badHashArtifact), 'SHA-256 mismatch');

console.log(`\nResults: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) {
  process.exit(1);
}
console.log('ALL PASS');
