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
  PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_TYPE,
  PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE,
  assertProtectedRecordsRuntimeActivationPreflightArtifact,
  assertProtectedRecordsRuntimeActivationPreflight,
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

function section(title) {
  console.log(`\n-- ${title} --`);
}

const ZLAR_BIN = join(process.cwd(), 'bin', 'zlar');
const PLAN_PATH = 'profiles/protected-records-runtime-activation-plan.fixture.json';
const PROFILE_PATH = 'profiles/protected-records-runtime-fixture.profile.json';
const SAMPLE_ARTIFACT_PATH = 'tests/fixtures/protected-records-runtime-activation-preflight-artifact-v1.json';
const SAMPLE_ARTIFACT_SHA256 = '1bc7b61e0b0f9e18d3a2bbdf8f7bfa9f1417e60cba027d20807ae893bce60c48';
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;
const scratch = mkdtempSync(join(tmpdir(), 'zlar-protected-records-runtime-activation-preflight-cli-'));

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

section('text activation preflight command');
const textRun = runZlar(['protected-records-runtime-activation-preflight', '--plan', PLAN_PATH, '--profile', PROFILE_PATH]);
assertEqual('text command exits zero', 0, textRun.status);
assertEqual('text command emits no stderr', '', textRun.stderr);
assert('text summary title present', textRun.stdout.includes('ZLAR Protected Records Runtime Activation Preflight v1'));
assert('text summary includes plan id', textRun.stdout.includes('Plan: id=protected-records-runtime-fixture-activation-plan'));
assert('text summary includes profile sha match', textRun.stdout.includes('sha_matches_plan=true'));
assert('text summary includes no activation writes', textRun.stdout.includes('applied=false; writes_runtime_config=false; writes_hook_configuration=false'));
assert('text summary includes human install boundary', textRun.stdout.includes('requires_explicit_human_install=true'));
assert('text summary includes runtime preflight run', textRun.stdout.includes('run=true; proof_run=true'));
assert('text summary includes identity policy', textRun.stdout.includes('Runtime profile identity policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('text summary includes runtime storage identities', textRun.stdout.includes('consumption_identity=authority-grant-contract-sha256; signed_payload_replay_identity=verified-signed-payload-sha256'));
assert('text summary includes replay split', textRun.stdout.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true'));
assert('text summary includes grant refusals', textRun.stdout.includes('missing_grant_refused=true; mismatched_grant_refused=true; revoked_grant_refused=true; expired_grant_refused=true; request_supplied_grant_refused=true'));
assert('text summary includes burn and rollback boundaries', textRun.stdout.includes('joint_rollback_detection=false; joint_rollback_reopens_grant_reuse=true; host_path_toctou_closed=false'));
assert('text summary includes side-door non-install', textRun.stdout.includes('activation_applied=false; persistent_runtime_profile_installed=false'));
assert('text summary is privacy safe', !unsafeOutputPattern.test(textRun.stdout));

section('json activation preflight command');
const jsonRun = runZlar(['protected-records-runtime-activation-preflight', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--json']);
assertEqual('json command exits zero', 0, jsonRun.status);
assertEqual('json command emits no stderr', '', jsonRun.stderr);
assert('json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report passes validation', assertProtectedRecordsRuntimeActivationPreflight(report, plan, profile));
assertEqual('json preflight type', 'zlar-protected-records-runtime-activation-preflight-v1', report.preflight_type);
assertEqual('json live probing false', false, report.live_probing);
assertEqual('json profile sha matches plan', true, report.runtime_profile.profile_sha_matches_plan);
assertEqual('json activation not applied', false, report.activation_boundary.activation_applied);
assertEqual('json runtime profile preflight run', true, report.runtime_profile_preflight_summary.preflight_run);
assertEqual('json runtime proof case count', 39, report.runtime_profile_preflight_summary.proof_case_count);
assertEqual('json identity authority source', 'launcher-owned-service-config', report.runtime_profile_preflight_summary.runtime_profile_identity_authority_source);
assertEqual('json omitted runtime profile id uses launcher config', true, report.runtime_profile_preflight_summary.omitted_runtime_profile_id_uses_launcher_config);
assertEqual('json supplied mismatched runtime profile id refused', true, report.runtime_profile_preflight_summary.supplied_mismatched_runtime_profile_id_refused);
assertEqual('json same-process signed-payload replay refused', true, report.runtime_profile_preflight_summary.same_process_signed_payload_replay_refused);
assertEqual('json restart consumed grant refused', true, report.runtime_profile_preflight_summary.restart_consumed_authority_grant_refused);
assertEqual('json missing grant refused', true, report.runtime_profile_preflight_summary.missing_authority_grant_appointment_refused);
assertEqual('json witness commit burn observed', true, report.runtime_profile_preflight_summary.witness_commit_failed_after_authority_grant_store_commit);
assertEqual('json joint rollback detection false', false, report.side_door_report.store_anchor_and_witness_joint_rollback_detection);
assertEqual('json host path TOCTOU open', false, report.side_door_report.host_filesystem_path_toctou_closed);
assertEqual('json persistent runtime profile not installed', false, report.side_door_report.persistent_runtime_profile_installed);
assertEqual('json hook config not written', false, report.side_door_report.hook_configuration_written);
assert('json includes no latest selection', jsonRun.stdout.includes('"latest_profile_selected": false'));
assert('json includes no live records check', jsonRun.stdout.includes('"live_records_system_checked": false'));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonRun.stdout));

section('stdin commands');
const stdinPlan = runZlar(['protected-records-runtime-activation-preflight', '--plan', '-', '--profile', PROFILE_PATH, '--json'], {
  input: readFileSync(PLAN_PATH, 'utf8'),
});
assertEqual('stdin plan command exits zero', 0, stdinPlan.status);
assertEqual('stdin plan command emits no stderr', '', stdinPlan.stderr);
assert('stdin plan report passes validation', assertProtectedRecordsRuntimeActivationPreflight(JSON.parse(stdinPlan.stdout), plan, profile));

const stdinProfile = runZlar(['protected-records-runtime-activation-preflight', '--plan', PLAN_PATH, '--profile', '-', '--json'], {
  input: readFileSync(PROFILE_PATH, 'utf8'),
});
assertEqual('stdin profile command exits zero', 0, stdinProfile.status);
assertEqual('stdin profile command emits no stderr', '', stdinProfile.stderr);
assert('stdin profile report passes validation', assertProtectedRecordsRuntimeActivationPreflight(JSON.parse(stdinProfile.stdout), plan, profile));

section('artifact command');
const artifactPath = join(scratch, 'runtime-activation-preflight-artifact.json');
const artifactRun = runZlar(['protected-records-runtime-activation-preflight', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--artifact', artifactPath]);
assertEqual('artifact command exits zero', 0, artifactRun.status);
assertEqual('artifact command emits no stderr', '', artifactRun.stderr);
assert('artifact command keeps text summary', artifactRun.stdout.includes('ZLAR Protected Records Runtime Activation Preflight v1'));
assert('artifact command prints checksum', artifactRun.stdout.includes('Portable activation preflight artifact:'));
assert('artifact command output is privacy safe', !unsafeOutputPattern.test(artifactRun.stdout));
const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
assert('artifact file passes validation', assertProtectedRecordsRuntimeActivationPreflightArtifact(artifact));
assertEqual('artifact file type', PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_TYPE, artifact.artifact_type);
assert('artifact file has sha256', /^[a-f0-9]{64}$/.test(artifact.integrity.body_sha256));
assertEqual('artifact embeds activation report type', 'zlar-protected-records-runtime-activation-preflight-v1', artifact.payload.preflight.preflight_type);
assertEqual('artifact embeds no activation', false, artifact.payload.preflight.side_door_report.activation_applied);

const artifactStdoutRun = runZlar(['protected-records-runtime-activation-preflight', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--artifact', '-']);
assertEqual('artifact stdout command exits zero', 0, artifactStdoutRun.status);
assertEqual('artifact stdout command emits no stderr', '', artifactStdoutRun.stderr);
assert('artifact stdout output is privacy safe', !unsafeOutputPattern.test(artifactStdoutRun.stdout));
const stdoutArtifact = JSON.parse(artifactStdoutRun.stdout);
assert('artifact stdout passes validation', assertProtectedRecordsRuntimeActivationPreflightArtifact(stdoutArtifact));
assertEqual('artifact stdout type', PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_TYPE, stdoutArtifact.artifact_type);

section('artifact verify command');
const verifyRun = runZlar(['protected-records-runtime-activation-preflight', 'verify', '--input', artifactPath]);
assertEqual('verify command exits zero', 0, verifyRun.status);
assertEqual('verify command emits no stderr', '', verifyRun.stderr);
assert('verify summary title present', verifyRun.stdout.includes('ZLAR Protected Records Runtime Activation Preflight Artifact Verification v1'));
assert('verify summary says verified', verifyRun.stdout.includes('verified=true'));
assert('verify summary includes artifact sha', verifyRun.stdout.includes(artifact.integrity.body_sha256));
assert('verify summary includes identity policy', verifyRun.stdout.includes('runtime_profile_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('verify summary includes storage identities', verifyRun.stdout.includes('runtime_storage_identities: consumed_authority_grant_store=persistent-single-use-authority-grant-contract-sha256-store'));
assert('verify summary includes replay split', verifyRun.stdout.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true'));
assert('verify summary includes burn boundary', verifyRun.stdout.includes('witness_commit_failure_reason=consumed_store_write_failed_after_grant_commit'));
assert('verify summary includes no activation writes', verifyRun.stdout.includes('activation_applied=false; runtime_config_written=false'));
assert('verify summary is privacy safe', !unsafeOutputPattern.test(verifyRun.stdout));

const verifyJsonRun = runZlar(['protected-records-runtime-activation-preflight', 'verify', '--input', artifactPath, '--json']);
assertEqual('verify json command exits zero', 0, verifyJsonRun.status);
assertEqual('verify json command emits no stderr', '', verifyJsonRun.stderr);
assert('verify json output is privacy safe', !unsafeOutputPattern.test(verifyJsonRun.stdout));
const verification = JSON.parse(verifyJsonRun.stdout);
assertEqual('verify json type', PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
assertEqual('verify json verified true', true, verification.verified);
assertEqual('verify json sha matches artifact', artifact.integrity.body_sha256, verification.body_sha256);
assertEqual('verify json live probing false', false, verification.live_probing);
assertEqual('verify json identity authority source', 'launcher-owned-service-config', verification.runtime_profile_identity_authority_source);
assertEqual('verify json omitted runtime profile id uses launcher config', true, verification.omitted_runtime_profile_id_uses_launcher_config);
assertEqual('verify json supplied mismatched runtime profile id refused', true, verification.supplied_mismatched_runtime_profile_id_refused);
assertEqual('verify json same-process replay refused', true, verification.same_process_signed_payload_replay_refused);
assertEqual('verify json restart consumed grant refused', true, verification.restart_consumed_authority_grant_refused);
assertEqual('verify json missing grant refused', true, verification.missing_authority_grant_appointment_refused);
assertEqual('verify json witness burn reason', 'consumed_store_write_failed_after_grant_commit', verification.witness_commit_failure_reason_code);
assertEqual('verify json joint rollback detection false', false, verification.store_anchor_and_witness_joint_rollback_detection);
assertEqual('verify json activation false', false, verification.activation_applied);

const verifyStdinRun = runZlar(['protected-records-runtime-activation-preflight', 'verify', '--input', '-'], {
  input: JSON.stringify(artifact, null, 2),
});
assertEqual('verify stdin command exits zero', 0, verifyStdinRun.status);
assertEqual('verify stdin command emits no stderr', '', verifyStdinRun.stderr);
assert('verify stdin says verified', verifyStdinRun.stdout.includes('verified=true'));
assert('verify stdin is privacy safe', !unsafeOutputPattern.test(verifyStdinRun.stdout));

section('committed sample artifact verify command');
const sampleVerifyRun = runZlar(['protected-records-runtime-activation-preflight', 'verify', '--input', SAMPLE_ARTIFACT_PATH]);
assertEqual('sample verify command exits zero', 0, sampleVerifyRun.status);
assertEqual('sample verify command emits no stderr', '', sampleVerifyRun.stderr);
assert('sample verify says verified', sampleVerifyRun.stdout.includes('verified=true'));
assert('sample verify includes stable sha', sampleVerifyRun.stdout.includes(SAMPLE_ARTIFACT_SHA256));
assert('sample verify is privacy safe', !unsafeOutputPattern.test(sampleVerifyRun.stdout));

const sampleVerifyJsonRun = runZlar(['protected-records-runtime-activation-preflight', 'verify', '--input', SAMPLE_ARTIFACT_PATH, '--json']);
assertEqual('sample verify json command exits zero', 0, sampleVerifyJsonRun.status);
assertEqual('sample verify json command emits no stderr', '', sampleVerifyJsonRun.stderr);
const sampleVerification = JSON.parse(sampleVerifyJsonRun.stdout);
assertEqual('sample verify json type', PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE, sampleVerification.verification_type);
assertEqual('sample verify json sha matches fixture', SAMPLE_ARTIFACT_SHA256, sampleVerification.body_sha256);
assertEqual('sample verify json live probing false', false, sampleVerification.live_probing);

const sampleOptionVerifyRun = runZlar(['protected-records-runtime-activation-preflight', 'verify', '--sample']);
assertEqual('sample option verify command exits zero', 0, sampleOptionVerifyRun.status);
assertEqual('sample option verify command emits no stderr', '', sampleOptionVerifyRun.stderr);
assert('sample option verify says verified', sampleOptionVerifyRun.stdout.includes('verified=true'));
assert('sample option verify includes stable sha', sampleOptionVerifyRun.stdout.includes(SAMPLE_ARTIFACT_SHA256));
assert('sample option verify is privacy safe', !unsafeOutputPattern.test(sampleOptionVerifyRun.stdout));

const sampleOptionVerifyJsonRun = runZlar(['protected-records-runtime-activation-preflight', 'verify', '--sample', '--json']);
assertEqual('sample option verify json command exits zero', 0, sampleOptionVerifyJsonRun.status);
assertEqual('sample option verify json command emits no stderr', '', sampleOptionVerifyJsonRun.stderr);
const sampleOptionVerification = JSON.parse(sampleOptionVerifyJsonRun.stdout);
assertEqual('sample option verify json type', PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE, sampleOptionVerification.verification_type);
assertEqual('sample option verify json sha matches fixture', SAMPLE_ARTIFACT_SHA256, sampleOptionVerification.body_sha256);
assertEqual('sample option verify json live probing false', false, sampleOptionVerification.live_probing);

section('help and fail closed command handling');
const helpRun = runZlar(['protected-records-runtime-activation-preflight', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assert('help names usage', helpRun.stderr.includes('Usage: zlar protected-records-runtime-activation-preflight --plan <file|-> --profile <file|-> [--json] [--artifact <file|->]'));
assert('help names verify usage', helpRun.stderr.includes('zlar protected-records-runtime-activation-preflight verify (--input <file|->|--sample) [--json] [--require-sha <artifact_body_sha256>]'));
assert('help describes artifact', helpRun.stderr.includes('portable checksummed activation-preflight artifact'));
assert('help describes verify', helpRun.stderr.includes('verify a supplied activation-preflight artifact'));
assert('help describes sample option', helpRun.stderr.includes('verify --sample'));
assert('help names sample artifact', helpRun.stderr.includes(SAMPLE_ARTIFACT_PATH));
assert('help states no live probing', helpRun.stderr.includes('does not live probe'));
assert('help states no install', helpRun.stderr.includes('install a runtime profile'));
assert('help states no live config writes', helpRun.stderr.includes('write hook or runtime configuration'));
assertEqual('help emits no stdout', '', helpRun.stdout);

const missingInputs = runZlar(['protected-records-runtime-activation-preflight']);
assert('missing inputs exits usage error', missingInputs.status !== 0);
assertEqual('missing inputs emits no stdout', '', missingInputs.stdout);
assert('missing inputs refuses latest profile', missingInputs.stderr.includes('does not select a live, latest, or current-machine runtime profile'));

const unsupported = runZlar(['protected-records-runtime-activation-preflight', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--latest']);
assert('unsupported option exits usage error', unsupported.status !== 0);
assertEqual('unsupported option emits no stdout', '', unsupported.stdout);
assert('unsupported option names unsupported option', unsupported.stderr.includes('Unsupported option provided.'));
assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

const missingArtifactValue = runZlar(['protected-records-runtime-activation-preflight', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--artifact']);
assert('missing artifact value exits usage error', missingArtifactValue.status !== 0);
assertEqual('missing artifact value emits no stdout', '', missingArtifactValue.stdout);
assert('missing artifact value names missing value', missingArtifactValue.stderr.includes('Missing value for --artifact'));
assert('missing artifact value is privacy safe', !unsafeOutputPattern.test(missingArtifactValue.stderr));

const artifactJsonConflict = runZlar(['protected-records-runtime-activation-preflight', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--json', '--artifact', '-']);
assert('artifact stdout json conflict exits usage error', artifactJsonConflict.status !== 0);
assertEqual('artifact stdout json conflict emits no stdout', '', artifactJsonConflict.stdout);
assert('artifact stdout json conflict names conflict', artifactJsonConflict.stderr.includes('Cannot combine --json with --artifact -'));
assert('artifact stdout json conflict is privacy safe', !unsafeOutputPattern.test(artifactJsonConflict.stderr));

const missingVerifyInput = runZlar(['protected-records-runtime-activation-preflight', 'verify']);
assert('missing verify input exits usage error', missingVerifyInput.status !== 0);
assertEqual('missing verify input emits no stdout', '', missingVerifyInput.stdout);
assert('missing verify input names input or sample', missingVerifyInput.stderr.includes('Missing required --input <file|-> or --sample'));
assert('missing verify input is privacy safe', !unsafeOutputPattern.test(missingVerifyInput.stderr));

const verifyInputSampleConflict = runZlar(['protected-records-runtime-activation-preflight', 'verify', '--input', SAMPLE_ARTIFACT_PATH, '--sample']);
assert('verify input sample conflict exits usage error', verifyInputSampleConflict.status !== 0);
assertEqual('verify input sample conflict emits no stdout', '', verifyInputSampleConflict.stdout);
assert('verify input sample conflict names conflict', verifyInputSampleConflict.stderr.includes('Cannot combine --input with --sample'));
assert('verify input sample conflict is privacy safe', !unsafeOutputPattern.test(verifyInputSampleConflict.stderr));

const unsupportedVerify = runZlar(['protected-records-runtime-activation-preflight', 'verify', '--latest']);
assert('unsupported verify option exits usage error', unsupportedVerify.status !== 0);
assertEqual('unsupported verify option emits no stdout', '', unsupportedVerify.stdout);
assert('unsupported verify option names unsupported verify option', unsupportedVerify.stderr.includes('Unsupported verify option provided.'));
assert('unsupported verify option is privacy safe', !unsafeOutputPattern.test(unsupportedVerify.stderr));

const bothStdin = runZlar(['protected-records-runtime-activation-preflight', '--plan', '-', '--profile', '-'], {
  input: `${JSON.stringify(plan)}\n`,
});
assert('both stdin exits usage error', bothStdin.status !== 0);
assertEqual('both stdin emits no stdout', '', bothStdin.stdout);
assert('both stdin names conflict', bothStdin.stderr.includes('cannot both read from stdin'));

const driftedPlan = structuredClone(plan);
driftedPlan.activation_boundary.activation_applied = true;
const driftedPath = join(scratch, 'drifted-runtime-activation-plan.json');
writeFileSync(driftedPath, `${JSON.stringify(driftedPlan, null, 2)}\n`);
const driftedRun = runZlar(['protected-records-runtime-activation-preflight', '--plan', driftedPath, '--profile', PROFILE_PATH]);
assert('drifted activation claim fails', driftedRun.status !== 0);
assertEqual('drifted activation emits no stdout', '', driftedRun.stdout);
assert('drifted activation reports sanitized failure', driftedRun.stderr.includes('activation boundary drifted') || driftedRun.stderr.includes('private path or credential details were suppressed'));
assert('drifted activation stderr is privacy safe', !unsafeOutputPattern.test(driftedRun.stderr));

const shaMismatch = structuredClone(plan);
shaMismatch.runtime_profile_sha256 = '0'.repeat(64);
const shaMismatchPath = join(scratch, 'sha-mismatch-plan.json');
writeFileSync(shaMismatchPath, `${JSON.stringify(shaMismatch, null, 2)}\n`);
const shaMismatchRun = runZlar(['protected-records-runtime-activation-preflight', '--plan', shaMismatchPath, '--profile', PROFILE_PATH]);
assert('sha mismatch exits nonzero', shaMismatchRun.status !== 0);
assertEqual('sha mismatch emits no stdout', '', shaMismatchRun.stdout);
assert('sha mismatch names profile sha mismatch', shaMismatchRun.stderr.includes('profile SHA mismatch'));
assert('sha mismatch stderr is privacy safe', !unsafeOutputPattern.test(shaMismatchRun.stderr));

const invalidJsonRun = runZlar(['protected-records-runtime-activation-preflight', '--plan', '-', '--profile', PROFILE_PATH], {
  input: '{not-json}\n',
});
assert('invalid json exits nonzero', invalidJsonRun.status !== 0);
assertEqual('invalid json emits no stdout', '', invalidJsonRun.stdout);
assert('invalid json names parse failure', invalidJsonRun.stderr.includes('Could not parse protected records runtime activation plan JSON'));

const invalidArtifactPath = join(scratch, 'invalid-artifact.json');
writeFileSync(invalidArtifactPath, '{');
const invalidArtifactRun = runZlar(['protected-records-runtime-activation-preflight', 'verify', '--input', invalidArtifactPath]);
assert('invalid artifact json exits nonzero', invalidArtifactRun.status !== 0);
assertEqual('invalid artifact json emits no stdout', '', invalidArtifactRun.stdout);
assert('invalid artifact json names invalid json', invalidArtifactRun.stderr.includes('not valid JSON'));
assert('invalid artifact json is privacy safe', !unsafeOutputPattern.test(invalidArtifactRun.stderr));

const tamperedArtifactPath = join(scratch, 'tampered-artifact.json');
const tamperedArtifact = structuredClone(artifact);
tamperedArtifact.integrity.body_sha256 = '0'.repeat(64);
writeFileSync(tamperedArtifactPath, `${JSON.stringify(tamperedArtifact, null, 2)}\n`);
const tamperedRun = runZlar(['protected-records-runtime-activation-preflight', 'verify', '--input', tamperedArtifactPath]);
assert('tampered artifact verify exits nonzero', tamperedRun.status !== 0);
assertEqual('tampered artifact verify emits no stdout', '', tamperedRun.stdout);
assert('tampered artifact verify names sha mismatch', tamperedRun.stderr.includes('SHA-256 mismatch'));
assert('tampered artifact verify is privacy safe', !unsafeOutputPattern.test(tamperedRun.stderr));

const mainHelp = runZlar(['help']);
assertEqual('main help exits zero', 0, mainHelp.status);
assert('main help lists activation preflight', mainHelp.stdout.includes('protected-records-runtime-activation-preflight'));

rmSync(scratch, { recursive: true, force: true });

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
