#!/usr/bin/env node

import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_TYPE,
  PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_VERIFICATION_TYPE,
  assertProtectedRecordsRuntimeLocalActivationArtifact,
  assertProtectedRecordsRuntimeLocalActivationProof,
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

function section(title) {
  console.log(`\n-- ${title} --`);
}

const ZLAR_BIN = join(process.cwd(), 'bin', 'zlar');
const PLAN_PATH = 'profiles/protected-records-runtime-local-activation-plan.fixture.json';
const PROFILE_PATH = 'profiles/protected-records-runtime-fixture.profile.json';
const SAMPLE_ARTIFACT_PATH = 'tests/fixtures/protected-records-runtime-local-activation-artifact-v1.json';
const SAMPLE_ARTIFACT_SHA256 = 'dbf2b182501a38c870377984d58c92ae28cfc857afa86fc9686dd90a64bd846b';
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;
const scratch = mkdtempSync(join(tmpdir(), 'zlar-protected-records-runtime-local-activation-cli-'));

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

const plan = JSON.parse(readFileSync(PLAN_PATH, 'utf8'));
const profile = JSON.parse(readFileSync(PROFILE_PATH, 'utf8'));

try {
  section('text local activation command');
  const textRun = runZlar(['protected-records-runtime-local-activation', '--plan', PLAN_PATH, '--profile', PROFILE_PATH]);
  assertEqual('text command exits zero', 0, textRun.status);
  assertEqual('text command emits no stderr', '', textRun.stderr);
  assert('text summary title present', textRun.stdout.includes('ZLAR Protected Records Runtime Local Activation Proof v1'));
  assert('text summary includes plan id', textRun.stdout.includes('Plan: id=protected-records-runtime-local-activation-fixture-plan'));
  assert('text summary includes profile sha match', textRun.stdout.includes('sha_matches_plan=true'));
  assert('text summary includes local activation true', textRun.stdout.includes('applied=true; disposable_runtime_config_written=true; persistent_runtime_config_written=false'));
  assert('text summary includes hook non-write', textRun.stdout.includes('writes_hook_configuration=false'));
  assert('text summary includes runtime service start', textRun.stdout.includes('starts_runtime_service=true'));
  assert('text summary includes runtime proof run', textRun.stdout.includes('run=true; service_command=zlar protected-records-runtime-service --config <launcher-owned-disposable-config>'));
  assert('text summary includes identity policy', textRun.stdout.includes('Runtime profile identity policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
  assert('text summary includes storage identities', textRun.stdout.includes('consumed_authority_grant_store=persistent-single-use-authority-grant-contract-sha256-store; consumption_identity=authority-grant-contract-sha256; signed_payload_replay_identity=verified-signed-payload-sha256'));
  assert('text summary includes replay split', textRun.stdout.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true'));
  assert('text summary includes grant refusals', textRun.stdout.includes('missing_grant_refused=true; mismatched_grant_refused=true; revoked_grant_refused=true; expired_grant_refused=true; request_supplied_grant_refused=true'));
  assert('text summary includes burn and rollback boundaries', textRun.stdout.includes('atomic_store_anchor_witness_commit=false; burn_window_named=true; witness_ahead_refusal=true; joint_rollback_detection=false; joint_rollback_reopens_grant_reuse=true; host_path_toctou_closed=false'));
  assert('text summary includes receipt refusal checks', textRun.stdout.includes('missing_receipt_refused=true; invalid_receipt_refused=true'));
  assert('text summary includes production non-claim', textRun.stdout.includes('not a persistent install or production deployment'));
  assert('text summary is privacy safe', !unsafeOutputPattern.test(textRun.stdout));

  section('json local activation command');
  const jsonRun = runZlar(['protected-records-runtime-local-activation', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--json']);
  assertEqual('json command exits zero', 0, jsonRun.status);
  assertEqual('json command emits no stderr', '', jsonRun.stderr);
  assert('json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
  const report = JSON.parse(jsonRun.stdout);
  assert('json report passes validation', assertProtectedRecordsRuntimeLocalActivationProof(report, plan, profile));
  assertEqual('json proof type', 'zlar-protected-records-runtime-local-activation-proof-v1', report.proof_type);
  assertEqual('json live probing false', false, report.live_probing);
  assertEqual('json profile sha matches plan', true, report.runtime_profile.profile_sha_matches_plan);
  assertEqual('json local activation applied', true, report.activation_boundary.local_activation_applied);
  assertEqual('json persistent config false', false, report.activation_boundary.persistent_runtime_config_written);
  assertEqual('json hook write false', false, report.activation_boundary.writes_hook_configuration);
  assertEqual('json runtime service started', true, report.activation_boundary.starts_runtime_service);
  assertEqual('json proof run', true, report.runtime_proof_summary.proof_run);
  assertEqual('json recognized write accepted', true, report.runtime_proof_summary.recognized_write_accepted);
  assertEqual('json grant store identity exact', 'persistent-single-use-authority-grant-contract-sha256-store', report.runtime_proof_summary.consumed_authority_grant_store);
  assertEqual('json grant consumption identity exact', 'authority-grant-contract-sha256', report.runtime_proof_summary.consumption_identity);
  assertEqual('json signed-payload replay identity exact', 'verified-signed-payload-sha256', report.runtime_proof_summary.signed_payload_replay_identity);
  assertEqual('json same-process signed-payload replay refused', true, report.runtime_proof_summary.same_process_signed_payload_replay_refused);
  assertEqual('json restart consumed authority grant refused', true, report.runtime_proof_summary.restart_consumed_authority_grant_refused);
  assertEqual('json missing grant refused', true, report.runtime_proof_summary.missing_authority_grant_appointment_refused);
  assertEqual('json mismatched grant refused', true, report.runtime_proof_summary.mismatched_authority_grant_appointment_refused);
  assertEqual('json revoked grant refused', true, report.runtime_proof_summary.revoked_authority_grant_refused);
  assertEqual('json expired grant refused', true, report.runtime_proof_summary.expired_authority_grant_refused);
  assertEqual('json request supplied grant refused', true, report.runtime_proof_summary.request_supplied_authority_grant_refused);
  assertEqual('json witness commit burn observed', true, report.runtime_proof_summary.witness_commit_failed_after_authority_grant_store_commit);
  assertEqual('json witness commit burn reason', 'consumed_store_write_failed_after_grant_commit', report.runtime_proof_summary.witness_commit_failure_reason_code);
  assertEqual('json identity authority source', 'launcher-owned-service-config', report.runtime_proof_summary.runtime_profile_identity_authority_source);
  assertEqual('json omitted runtime profile id uses launcher config', true, report.runtime_proof_summary.omitted_runtime_profile_id_uses_launcher_config);
  assertEqual('json supplied mismatched runtime profile id refused', true, report.runtime_proof_summary.supplied_mismatched_runtime_profile_id_refused);
  assertEqual('json wrong audit event refused', true, report.runtime_proof_summary.wrong_audit_event_refused);
  assertEqual('json wrong runtime profile id refused', true, report.runtime_proof_summary.wrong_runtime_profile_id_refused);
  assertEqual('json direct api with receipt refused', true, report.runtime_proof_summary.direct_api_with_receipt_refused);
  assertEqual('json witness-ahead rollback refusal true', true, report.side_door_report.store_and_anchor_joint_rollback_refused_while_witness_ahead);
  assertEqual('json joint rollback detection false', false, report.side_door_report.store_anchor_and_witness_joint_rollback_detection);
  assertEqual('json joint rollback reopens grant reuse', true, report.side_door_report.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse);
  assertEqual('json store-anchor-witness commit non-atomic', false, report.side_door_report.atomic_store_anchor_witness_commit);
  assertEqual('json burn window named', true, report.side_door_report.partial_grant_commit_burn_window_named);
  assertEqual('json host path TOCTOU open', false, report.side_door_report.host_filesystem_path_toctou_closed);
  assertEqual('json external attestation false', false, report.side_door_report.external_attestation);

  section('stdin input forms');
  const stdinPlan = runZlar(['protected-records-runtime-local-activation', '--plan', '-', '--profile', PROFILE_PATH, '--json'], {
    input: JSON.stringify(plan),
  });
  assertEqual('stdin plan exits zero', 0, stdinPlan.status);
  assertEqual('stdin plan emits no stderr', '', stdinPlan.stderr);
  assert('stdin plan output is privacy safe', !unsafeOutputPattern.test(stdinPlan.stdout));
  const stdinPlanReport = JSON.parse(stdinPlan.stdout);
  assertEqual('stdin plan profile sha match', true, stdinPlanReport.runtime_profile.profile_sha_matches_plan);

  const stdinProfile = runZlar(['protected-records-runtime-local-activation', '--plan', PLAN_PATH, '--profile', '-', '--json'], {
    input: JSON.stringify(profile),
  });
  assertEqual('stdin profile exits zero', 0, stdinProfile.status);
  assertEqual('stdin profile emits no stderr', '', stdinProfile.stderr);
  const stdinProfileReport = JSON.parse(stdinProfile.stdout);
  assertEqual('stdin profile local activation true', true, stdinProfileReport.activation_boundary.local_activation_applied);

  section('artifact command and verify command');
  const artifactPath = join(scratch, 'runtime-local-activation-artifact.json');
  const artifactRun = runZlar(['protected-records-runtime-local-activation', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--artifact', artifactPath]);
  assertEqual('artifact command exits zero', 0, artifactRun.status);
  assertEqual('artifact command emits no stderr', '', artifactRun.stderr);
  assert('artifact command keeps text summary', artifactRun.stdout.includes('Portable local activation artifact:'));
  assert('artifact command prints artifact checksum', artifactRun.stdout.includes(SAMPLE_ARTIFACT_SHA256));
  assert('artifact command output is privacy safe', !unsafeOutputPattern.test(artifactRun.stdout));
  const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
  assert('artifact file passes validation', assertProtectedRecordsRuntimeLocalActivationArtifact(artifact));
  assertEqual('artifact file type', PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_TYPE, artifact.artifact_type);
  assertEqual('artifact file stable sha', SAMPLE_ARTIFACT_SHA256, artifact.integrity.body_sha256);

  const artifactStdoutRun = runZlar(['protected-records-runtime-local-activation', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--artifact', '-']);
  assertEqual('artifact stdout command exits zero', 0, artifactStdoutRun.status);
  assertEqual('artifact stdout command emits no stderr', '', artifactStdoutRun.stderr);
  assert('artifact stdout output is privacy safe', !unsafeOutputPattern.test(artifactStdoutRun.stdout));
  const artifactStdout = JSON.parse(artifactStdoutRun.stdout);
  assert('artifact stdout passes validation', assertProtectedRecordsRuntimeLocalActivationArtifact(artifactStdout));
  assertEqual('artifact stdout stable sha', SAMPLE_ARTIFACT_SHA256, artifactStdout.integrity.body_sha256);

  const verifyRun = runZlar(['protected-records-runtime-local-activation', 'verify', '--input', artifactPath]);
  assertEqual('verify command exits zero', 0, verifyRun.status);
  assertEqual('verify command emits no stderr', '', verifyRun.stderr);
  assert('verify summary names command', verifyRun.stdout.includes('ZLAR Protected Records Runtime Local Activation Artifact Verification v1'));
  assert('verify summary says verified', verifyRun.stdout.includes('verified=true'));
  assert('verify summary includes artifact sha', verifyRun.stdout.includes(SAMPLE_ARTIFACT_SHA256));
  assert('verify summary includes local activation', verifyRun.stdout.includes('local_activation_applied=true; disposable_runtime_config_written=true'));
  assert('verify summary includes identity policy', verifyRun.stdout.includes('runtime_profile_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
  assert('verify summary includes storage identities', verifyRun.stdout.includes('consumed_authority_grant_store=persistent-single-use-authority-grant-contract-sha256-store; consumption_identity=authority-grant-contract-sha256; signed_payload_replay_identity=verified-signed-payload-sha256'));
  assert('verify summary includes replay split', verifyRun.stdout.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true'));
  assert('verify summary includes grant refusals', verifyRun.stdout.includes('missing_grant_refused=true; mismatched_grant_refused=true; revoked_grant_refused=true; expired_grant_refused=true; request_supplied_grant_refused=true'));
  assert('verify summary includes burn and rollback boundaries', verifyRun.stdout.includes('atomic_store_anchor_witness_commit=false; burn_window_named=true; witness_ahead_refusal=true; joint_rollback_detection=false; joint_rollback_reopens_grant_reuse=true; host_path_toctou_closed=false'));
  assert('verify summary is privacy safe', !unsafeOutputPattern.test(verifyRun.stdout));

  const verifyJsonRun = runZlar(['protected-records-runtime-local-activation', 'verify', '--input', artifactPath, '--json']);
  assertEqual('verify json command exits zero', 0, verifyJsonRun.status);
  assertEqual('verify json command emits no stderr', '', verifyJsonRun.stderr);
  assert('verify json output is privacy safe', !unsafeOutputPattern.test(verifyJsonRun.stdout));
  const verification = JSON.parse(verifyJsonRun.stdout);
  assertEqual('verify json type', PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
  assertEqual('verify json verified true', true, verification.verified);
  assertEqual('verify json sha matches artifact', SAMPLE_ARTIFACT_SHA256, verification.body_sha256);
  assertEqual('verify json live probing false', false, verification.live_probing);
  assertEqual('verify json local activation true', true, verification.local_activation_applied);
  assertEqual('verify json persistent config false', false, verification.persistent_runtime_config_written);
  assertEqual('verify json hook config false', false, verification.hook_configuration_written);
  assertEqual('verify json runtime service true', true, verification.runtime_service_started);
  assertEqual('verify json identity authority source', 'launcher-owned-service-config', verification.runtime_profile_identity_authority_source);
  assertEqual('verify json omitted runtime profile id uses launcher config', true, verification.omitted_runtime_profile_id_uses_launcher_config);
  assertEqual('verify json supplied mismatched runtime profile id refused', true, verification.supplied_mismatched_runtime_profile_id_refused);
  assertEqual('verify json grant store identity exact', 'persistent-single-use-authority-grant-contract-sha256-store', verification.consumed_authority_grant_store);
  assertEqual('verify json consumption identity exact', 'authority-grant-contract-sha256', verification.consumption_identity);
  assertEqual('verify json signed-payload replay identity exact', 'verified-signed-payload-sha256', verification.signed_payload_replay_identity);
  assertEqual('verify json same-process replay refused', true, verification.same_process_signed_payload_replay_refused);
  assertEqual('verify json restart grant replay refused', true, verification.restart_consumed_authority_grant_refused);
  assertEqual('verify json missing grant refused', true, verification.missing_authority_grant_appointment_refused);
  assertEqual('verify json mismatched grant refused', true, verification.mismatched_authority_grant_appointment_refused);
  assertEqual('verify json revoked grant refused', true, verification.revoked_authority_grant_refused);
  assertEqual('verify json expired grant refused', true, verification.expired_authority_grant_refused);
  assertEqual('verify json request supplied grant refused', true, verification.request_supplied_authority_grant_refused);
  assertEqual('verify json witness commit burn observed', true, verification.witness_commit_failed_after_authority_grant_store_commit);
  assertEqual('verify json store-anchor-witness commit non-atomic', false, verification.atomic_store_anchor_witness_commit);
  assertEqual('verify json burn window named', true, verification.partial_grant_commit_burn_window_named);
  assertEqual('verify json witness-ahead rollback refusal true', true, verification.store_and_anchor_joint_rollback_refused_while_witness_ahead);
  assertEqual('verify json joint rollback detection false', false, verification.store_anchor_and_witness_joint_rollback_detection);
  assertEqual('verify json joint rollback reopens grant reuse', true, verification.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse);
  assertEqual('verify json host path TOCTOU open', false, verification.host_filesystem_path_toctou_closed);
  assertEqual('verify json missing receipt refused', true, verification.missing_receipt_refused);
  assertEqual('verify json wrong runtime profile id refused', true, verification.wrong_runtime_profile_id_refused);
  assertEqual('verify json wrong audit event refused', true, verification.wrong_audit_event_refused);

  const verifyStdinRun = runZlar(['protected-records-runtime-local-activation', 'verify', '--input', '-'], {
    input: readFileSync(artifactPath, 'utf8'),
  });
  assertEqual('verify stdin command exits zero', 0, verifyStdinRun.status);
  assertEqual('verify stdin command emits no stderr', '', verifyStdinRun.stderr);
  assert('verify stdin says verified', verifyStdinRun.stdout.includes('verified=true'));
  assert('verify stdin is privacy safe', !unsafeOutputPattern.test(verifyStdinRun.stdout));

  section('committed sample artifact verify command');
  const sampleVerifyRun = runZlar(['protected-records-runtime-local-activation', 'verify', '--input', SAMPLE_ARTIFACT_PATH]);
  assertEqual('sample verify command exits zero', 0, sampleVerifyRun.status);
  assertEqual('sample verify command emits no stderr', '', sampleVerifyRun.stderr);
  assert('sample verify says verified', sampleVerifyRun.stdout.includes('verified=true'));
  assert('sample verify includes stable sha', sampleVerifyRun.stdout.includes(SAMPLE_ARTIFACT_SHA256));
  assert('sample verify is privacy safe', !unsafeOutputPattern.test(sampleVerifyRun.stdout));

  const sampleVerifyJsonRun = runZlar(['protected-records-runtime-local-activation', 'verify', '--input', SAMPLE_ARTIFACT_PATH, '--json']);
  assertEqual('sample verify json command exits zero', 0, sampleVerifyJsonRun.status);
  assertEqual('sample verify json command emits no stderr', '', sampleVerifyJsonRun.stderr);
  const sampleVerification = JSON.parse(sampleVerifyJsonRun.stdout);
  assertEqual('sample verify json type', PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_VERIFICATION_TYPE, sampleVerification.verification_type);
  assertEqual('sample verify json sha matches fixture', SAMPLE_ARTIFACT_SHA256, sampleVerification.body_sha256);
  assertEqual('sample verify json live probing false', false, sampleVerification.live_probing);
  assertEqual('sample verify json runtime service true', true, sampleVerification.runtime_service_started);

  const sampleOptionVerifyRun = runZlar(['protected-records-runtime-local-activation', 'verify', '--sample']);
  assertEqual('sample option verify command exits zero', 0, sampleOptionVerifyRun.status);
  assertEqual('sample option verify command emits no stderr', '', sampleOptionVerifyRun.stderr);
  assert('sample option verify says verified', sampleOptionVerifyRun.stdout.includes('verified=true'));
  assert('sample option verify includes stable sha', sampleOptionVerifyRun.stdout.includes(SAMPLE_ARTIFACT_SHA256));
  assert('sample option verify is privacy safe', !unsafeOutputPattern.test(sampleOptionVerifyRun.stdout));

  const sampleOptionVerifyJsonRun = runZlar(['protected-records-runtime-local-activation', 'verify', '--sample', '--json']);
  assertEqual('sample option verify json command exits zero', 0, sampleOptionVerifyJsonRun.status);
  assertEqual('sample option verify json command emits no stderr', '', sampleOptionVerifyJsonRun.stderr);
  const sampleOptionVerification = JSON.parse(sampleOptionVerifyJsonRun.stdout);
  assertEqual('sample option verify json type', PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_VERIFICATION_TYPE, sampleOptionVerification.verification_type);
  assertEqual('sample option verify json sha matches fixture', SAMPLE_ARTIFACT_SHA256, sampleOptionVerification.body_sha256);

  section('help and fail closed command handling');
  const helpRun = runZlar(['protected-records-runtime-local-activation', '--help']);
  assertEqual('help exits zero', 0, helpRun.status);
  assert('help names usage', helpRun.stderr.includes('Usage: zlar protected-records-runtime-local-activation --plan <file|-> --profile <file|-> [--json] [--artifact <file|->]'));
  assert('help names verify usage', helpRun.stderr.includes('zlar protected-records-runtime-local-activation verify (--input <file|->|--sample) [--json] [--require-sha <artifact_body_sha256>]'));
  assert('help describes local activation', helpRun.stderr.includes('local disposable protected-records runtime activation proof'));
  assert('help names sample artifact', helpRun.stderr.includes(SAMPLE_ARTIFACT_PATH));
  assert('help states no live probing', helpRun.stderr.includes('does not live probe'));
  assertEqual('help emits no stdout', '', helpRun.stdout);

  const missingInputs = runZlar(['protected-records-runtime-local-activation']);
  assert('missing inputs exits usage error', missingInputs.status !== 0);
  assertEqual('missing inputs emits no report', '', missingInputs.stdout);
  assert('missing inputs names plan/profile', missingInputs.stderr.includes('--plan and --profile are required'));

  const unsupported = runZlar(['protected-records-runtime-local-activation', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--latest']);
  assert('unsupported option exits usage error', unsupported.status !== 0);
  assertEqual('unsupported option emits no report', '', unsupported.stdout);
  assert('unsupported option names unsupported option', unsupported.stderr.includes('Unsupported option provided'));
  assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

  const missingArtifactValue = runZlar(['protected-records-runtime-local-activation', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--artifact']);
  assert('missing artifact value exits usage error', missingArtifactValue.status !== 0);
  assertEqual('missing artifact value emits no report', '', missingArtifactValue.stdout);
  assert('missing artifact value names missing value', missingArtifactValue.stderr.includes('Missing value for --artifact'));

  const artifactJsonConflict = runZlar(['protected-records-runtime-local-activation', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--json', '--artifact', '-']);
  assert('artifact stdout json conflict exits usage error', artifactJsonConflict.status !== 0);
  assertEqual('artifact stdout json conflict emits no report', '', artifactJsonConflict.stdout);
  assert('artifact stdout json conflict names conflict', artifactJsonConflict.stderr.includes('Cannot combine --json with --artifact -'));

  const missingVerifyInput = runZlar(['protected-records-runtime-local-activation', 'verify']);
  assert('missing verify input exits usage error', missingVerifyInput.status !== 0);
  assertEqual('missing verify input emits no report', '', missingVerifyInput.stdout);
  assert('missing verify input names input or sample', missingVerifyInput.stderr.includes('Missing required --input <file|-> or --sample'));
  assert('missing verify input is privacy safe', !unsafeOutputPattern.test(missingVerifyInput.stderr));

  const verifyInputSampleConflict = runZlar(['protected-records-runtime-local-activation', 'verify', '--input', SAMPLE_ARTIFACT_PATH, '--sample']);
  assert('verify input sample conflict exits usage error', verifyInputSampleConflict.status !== 0);
  assertEqual('verify input sample conflict emits no report', '', verifyInputSampleConflict.stdout);
  assert('verify input sample conflict names conflict', verifyInputSampleConflict.stderr.includes('Cannot combine --input with --sample'));

  const unsupportedVerify = runZlar(['protected-records-runtime-local-activation', 'verify', '--latest']);
  assert('unsupported verify option exits usage error', unsupportedVerify.status !== 0);
  assertEqual('unsupported verify option emits no report', '', unsupportedVerify.stdout);
  assert('unsupported verify option names unsupported verify option', unsupportedVerify.stderr.includes('Unsupported verify option provided'));
  assert('unsupported verify option is privacy safe', !unsafeOutputPattern.test(unsupportedVerify.stderr));

  const bothStdin = runZlar(['protected-records-runtime-local-activation', '--plan', '-', '--profile', '-'], {
    input: `${JSON.stringify(plan)}\n${JSON.stringify(profile)}`,
  });
  assert('both stdin exits usage error', bothStdin.status !== 0);
  assertEqual('both stdin emits no report', '', bothStdin.stdout);
  assert('both stdin names stdin conflict', bothStdin.stderr.includes('--plan - and --profile - cannot both read from stdin'));

  const stalePlan = structuredClone(plan);
  stalePlan.plan_status = 'active';
  const stalePath = join(scratch, 'stale-plan.json');
  writeFileSync(stalePath, `${JSON.stringify(stalePlan, null, 2)}\n`);
  const staleRun = runZlar(['protected-records-runtime-local-activation', '--plan', stalePath, '--profile', PROFILE_PATH]);
  assert('stale plan exits nonzero', staleRun.status !== 0);
  assertEqual('stale plan emits no report', '', staleRun.stdout);
  assert('stale plan failure is sanitized', staleRun.stderr.includes('contract drifted'));

  const shaMismatchPlan = structuredClone(plan);
  shaMismatchPlan.runtime_profile_sha256 = '0'.repeat(64);
  const shaMismatchPath = join(scratch, 'sha-mismatch-plan.json');
  writeFileSync(shaMismatchPath, `${JSON.stringify(shaMismatchPlan, null, 2)}\n`);
  const shaMismatchRun = runZlar(['protected-records-runtime-local-activation', '--plan', shaMismatchPath, '--profile', PROFILE_PATH]);
  assert('sha mismatch exits nonzero', shaMismatchRun.status !== 0);
  assertEqual('sha mismatch emits no report', '', shaMismatchRun.stdout);
  assert('sha mismatch names mismatch', shaMismatchRun.stderr.includes('profile SHA mismatch'));

  const invalidJsonRun = runZlar(['protected-records-runtime-local-activation', '--plan', '-', '--profile', PROFILE_PATH], {
    input: '{"plan_type":',
  });
  assert('invalid json exits nonzero', invalidJsonRun.status !== 0);
  assertEqual('invalid json emits no report', '', invalidJsonRun.stdout);
  assert('invalid json names parse failure', invalidJsonRun.stderr.includes('Could not parse protected records runtime local activation plan JSON'));

  const invalidArtifactPath = join(scratch, 'invalid-artifact.json');
  writeFileSync(invalidArtifactPath, '{"artifact_type":"wrong"}\n');
  const invalidArtifactRun = runZlar(['protected-records-runtime-local-activation', 'verify', '--input', invalidArtifactPath]);
  assert('invalid artifact exits nonzero', invalidArtifactRun.status !== 0);
  assertEqual('invalid artifact emits no report', '', invalidArtifactRun.stdout);
  assert('invalid artifact names wrong type', invalidArtifactRun.stderr.includes('wrong artifact type'));
  assert('invalid artifact is privacy safe', !unsafeOutputPattern.test(invalidArtifactRun.stderr));

  const tamperedArtifactPath = join(scratch, 'tampered-artifact.json');
  const tamperedArtifact = structuredClone(artifact);
  tamperedArtifact.integrity.body_sha256 = '0'.repeat(64);
  writeFileSync(tamperedArtifactPath, `${JSON.stringify(tamperedArtifact, null, 2)}\n`);
  const tamperedRun = runZlar(['protected-records-runtime-local-activation', 'verify', '--input', tamperedArtifactPath]);
  assert('tampered verify exits nonzero', tamperedRun.status !== 0);
  assertEqual('tampered verify emits no report', '', tamperedRun.stdout);
  assert('tampered verify names sha mismatch', tamperedRun.stderr.includes('SHA-256 mismatch'));
  assert('tampered verify is privacy safe', !unsafeOutputPattern.test(tamperedRun.stderr));

  const mainHelp = runZlar(['help']);
  assertEqual('main help exits zero', 0, mainHelp.status);
  assert('main help lists local activation', mainHelp.stdout.includes('protected-records-runtime-local-activation'));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(`\nResults: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) {
  process.exit(1);
}
console.log('ALL PASS');
