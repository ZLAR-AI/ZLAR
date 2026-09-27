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
  PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_TYPE,
  PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_VERIFICATION_TYPE,
  assertProtectedRecordsRuntimeProfileInstallationArtifact,
  assertProtectedRecordsRuntimeProfileInstallationProof,
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

function section(title) {
  console.log(`\n-- ${title} --`);
}

const ZLAR_BIN = join(process.cwd(), 'bin', 'zlar');
const PLAN_PATH = 'profiles/protected-records-runtime-profile-installation-plan.fixture.json';
const PROFILE_PATH = 'profiles/protected-records-runtime-fixture.profile.json';
const SAMPLE_ARTIFACT_PATH = 'tests/fixtures/protected-records-runtime-profile-installation-artifact-v1.json';
const SAMPLE_ARTIFACT_SHA256 = '5512d12a7320417f6499630557ec3c5993ffb88474ba2822891fb67e4f9bf88f';
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;
const scratch = mkdtempSync(join(tmpdir(), 'zlar-protected-records-runtime-profile-installation-cli-'));

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
  section('text profile installation command');
  const textRun = runZlar(['protected-records-runtime-profile-installation', '--plan', PLAN_PATH, '--profile', PROFILE_PATH]);
  assertEqual('text command exits zero', 0, textRun.status);
  assertEqual('text command emits no stderr', '', textRun.stderr);
  assert('text summary title present', textRun.stdout.includes('ZLAR Protected Records Runtime Profile Installation Proof v1'));
  assert('text summary includes plan id', textRun.stdout.includes('Plan: id=protected-records-runtime-profile-installation-fixture-plan'));
  assert('text summary includes disposable install', textRun.stdout.includes('disposable_root_created=true; profile_copy_written=true'));
  assert('text summary includes selected by id and sha', textRun.stdout.includes('selected_by_id_and_sha=true'));
  assert('text summary includes authority guard', textRun.stdout.includes('installed_profile_state_refused=true; runtime_config_refused=true'));
  assert('text summary includes fixture rightful issuance', textRun.stdout.includes('fixture_rightful_issuance_path_evidenced=true'));
  assert('text summary names non-atomic persistence boundary', textRun.stdout.includes('atomic_store_anchor_witness_commit=false'));
  assert('text summary includes no persistent install', textRun.stdout.includes('persistent_runtime_profile_installed=false'));
  assert('text summary includes runtime proof run', textRun.stdout.includes('run=true; service_command=zlar protected-records-runtime-service --config <launcher-owned-disposable-config>'));
  assert('text summary includes identity policy', textRun.stdout.includes('Runtime profile identity policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
  assert('text summary includes production non-claim', textRun.stdout.includes('not a persistent install or production deployment'));
  assert('text summary is privacy safe', !unsafeOutputPattern.test(textRun.stdout));

  section('json profile installation command');
  const jsonRun = runZlar(['protected-records-runtime-profile-installation', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--json']);
  assertEqual('json command exits zero', 0, jsonRun.status);
  assertEqual('json command emits no stderr', '', jsonRun.stderr);
  assert('json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
  const report = JSON.parse(jsonRun.stdout);
  assert('json report passes validation', assertProtectedRecordsRuntimeProfileInstallationProof(report, plan, profile));
  assertEqual('json proof type', 'zlar-protected-records-runtime-profile-installation-proof-v1', report.proof_type);
  assertEqual('json live probing false', false, report.live_probing);
  assertEqual('json profile sha matches plan', true, report.runtime_profile.profile_sha_matches_plan);
  assertEqual('json selected from install root', true, report.installation.profile_selected_from_install_root);
  assertEqual('json selected by id and sha', true, report.installation.selected_by_explicit_id_and_sha);
  assertEqual('json no latest', false, report.installation.selects_latest_profile);
  assertEqual('json request guard refused', true, report.request_authority_guard_summary.all_refused_before_mutation);
  assertEqual('json request guard state delta zero', 0, report.request_authority_guard_summary.state_entry_count_delta_total);
  assertEqual('json persistent profile false', false, report.side_door_report.persistent_runtime_profile_installed);
  assertEqual('json hook write false', false, report.side_door_report.hook_configuration_written);
  assertEqual('json user config false', false, report.side_door_report.user_config_written);
  assertEqual('json machine config false', false, report.side_door_report.machine_config_written);
  assertEqual('json identity authority source', 'launcher-owned-service-config', report.runtime_proof_summary.runtime_profile_identity_authority_source);
  assertEqual('json omitted runtime profile id uses launcher config', true, report.runtime_proof_summary.omitted_runtime_profile_id_uses_launcher_config);
  assertEqual('json supplied mismatched runtime profile id refused', true, report.runtime_proof_summary.supplied_mismatched_runtime_profile_id_refused);
  assertEqual('json recognized write accepted', true, report.runtime_proof_summary.recognized_write_accepted);
  assertEqual('json fixture rightful issuance evidenced', true, report.runtime_proof_summary.fixture_rightful_issuance_path_evidenced);
  assertEqual('json restart consumed grant refused', true, report.runtime_proof_summary.restart_consumed_authority_grant_refused);
  assertEqual('json partial grant burn named', true, report.side_door_report.partial_grant_commit_burn_window_named);
  assertEqual('json wrong runtime profile id refused', true, report.runtime_proof_summary.wrong_runtime_profile_id_refused);
  assertEqual('json direct api with receipt refused', true, report.runtime_proof_summary.direct_api_with_receipt_refused);

  section('stdin input forms');
  const stdinPlan = runZlar(['protected-records-runtime-profile-installation', '--plan', '-', '--profile', PROFILE_PATH, '--json'], {
    input: JSON.stringify(plan),
  });
  assertEqual('stdin plan exits zero', 0, stdinPlan.status);
  assertEqual('stdin plan emits no stderr', '', stdinPlan.stderr);
  const stdinPlanReport = JSON.parse(stdinPlan.stdout);
  assertEqual('stdin plan selected from root', true, stdinPlanReport.installation.profile_selected_from_install_root);

  const stdinProfile = runZlar(['protected-records-runtime-profile-installation', '--plan', PLAN_PATH, '--profile', '-', '--json'], {
    input: JSON.stringify(profile),
  });
  assertEqual('stdin profile exits zero', 0, stdinProfile.status);
  assertEqual('stdin profile emits no stderr', '', stdinProfile.stderr);
  const stdinProfileReport = JSON.parse(stdinProfile.stdout);
  assertEqual('stdin profile request guard refused', true, stdinProfileReport.request_authority_guard_summary.all_refused_before_mutation);

  section('artifact command and verify command');
  const artifactPath = join(scratch, 'runtime-profile-installation-artifact.json');
  const artifactRun = runZlar(['protected-records-runtime-profile-installation', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--artifact', artifactPath]);
  assertEqual('artifact command exits zero', 0, artifactRun.status);
  assertEqual('artifact command emits no stderr', '', artifactRun.stderr);
  assert('artifact command keeps text summary', artifactRun.stdout.includes('Portable runtime profile installation artifact:'));
  assert('artifact command prints artifact checksum', artifactRun.stdout.includes(SAMPLE_ARTIFACT_SHA256));
  assert('artifact command output is privacy safe', !unsafeOutputPattern.test(artifactRun.stdout));
  const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
  assert('artifact file passes validation', assertProtectedRecordsRuntimeProfileInstallationArtifact(artifact));
  assertEqual('artifact file type', PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_TYPE, artifact.artifact_type);
  assertEqual('artifact file stable sha', SAMPLE_ARTIFACT_SHA256, artifact.integrity.body_sha256);

  const artifactStdoutRun = runZlar(['protected-records-runtime-profile-installation', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--artifact', '-']);
  assertEqual('artifact stdout command exits zero', 0, artifactStdoutRun.status);
  assertEqual('artifact stdout command emits no stderr', '', artifactStdoutRun.stderr);
  assert('artifact stdout output is privacy safe', !unsafeOutputPattern.test(artifactStdoutRun.stdout));
  const artifactStdout = JSON.parse(artifactStdoutRun.stdout);
  assert('artifact stdout passes validation', assertProtectedRecordsRuntimeProfileInstallationArtifact(artifactStdout));
  assertEqual('artifact stdout stable sha', SAMPLE_ARTIFACT_SHA256, artifactStdout.integrity.body_sha256);

  const verifyRun = runZlar(['protected-records-runtime-profile-installation', 'verify', '--input', artifactPath]);
  assertEqual('verify command exits zero', 0, verifyRun.status);
  assertEqual('verify command emits no stderr', '', verifyRun.stderr);
  assert('verify summary names command', verifyRun.stdout.includes('ZLAR Protected Records Runtime Profile Installation Artifact Verification v1'));
  assert('verify summary says verified', verifyRun.stdout.includes('verified=true'));
  assert('verify summary includes artifact sha', verifyRun.stdout.includes(SAMPLE_ARTIFACT_SHA256));
  assert('verify summary includes authority guard', verifyRun.stdout.includes('request_authority_guard_refused=true'));
  assert('verify summary includes install boundary', verifyRun.stdout.includes('installation_applied=true; profile_copied=true'));
  assert('verify summary includes identity policy', verifyRun.stdout.includes('runtime_profile_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
  assert('verify summary is privacy safe', !unsafeOutputPattern.test(verifyRun.stdout));

  const verifyJsonRun = runZlar(['protected-records-runtime-profile-installation', 'verify', '--input', artifactPath, '--json']);
  assertEqual('verify json command exits zero', 0, verifyJsonRun.status);
  assertEqual('verify json command emits no stderr', '', verifyJsonRun.stderr);
  assert('verify json output is privacy safe', !unsafeOutputPattern.test(verifyJsonRun.stdout));
  const verification = JSON.parse(verifyJsonRun.stdout);
  assertEqual('verify json type', PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
  assertEqual('verify json verified true', true, verification.verified);
  assertEqual('verify json sha matches artifact', SAMPLE_ARTIFACT_SHA256, verification.body_sha256);
  assertEqual('verify json live probing false', false, verification.live_probing);
  assertEqual('verify json request guard refused', true, verification.request_authority_guard_refused);
  assertEqual('verify json wrong runtime profile id refused', true, verification.wrong_runtime_profile_id_refused);
  assertEqual('verify json persistent profile false', false, verification.persistent_runtime_profile_installed);
  assertEqual('verify json identity authority source', 'launcher-owned-service-config', verification.runtime_profile_identity_authority_source);
  assertEqual('verify json omitted runtime profile id uses launcher config', true, verification.omitted_runtime_profile_id_uses_launcher_config);
  assertEqual('verify json supplied mismatched runtime profile id refused', true, verification.supplied_mismatched_runtime_profile_id_refused);
  assertEqual('verify json runtime service true', true, verification.runtime_service_started);

  const verifyStdinRun = runZlar(['protected-records-runtime-profile-installation', 'verify', '--input', '-'], {
    input: readFileSync(artifactPath, 'utf8'),
  });
  assertEqual('verify stdin command exits zero', 0, verifyStdinRun.status);
  assertEqual('verify stdin command emits no stderr', '', verifyStdinRun.stderr);
  assert('verify stdin says verified', verifyStdinRun.stdout.includes('verified=true'));
  assert('verify stdin is privacy safe', !unsafeOutputPattern.test(verifyStdinRun.stdout));

  section('committed sample artifact verify command');
  const sampleVerifyRun = runZlar(['protected-records-runtime-profile-installation', 'verify', '--input', SAMPLE_ARTIFACT_PATH]);
  assertEqual('sample verify command exits zero', 0, sampleVerifyRun.status);
  assertEqual('sample verify command emits no stderr', '', sampleVerifyRun.stderr);
  assert('sample verify says verified', sampleVerifyRun.stdout.includes('verified=true'));
  assert('sample verify includes stable sha', sampleVerifyRun.stdout.includes(SAMPLE_ARTIFACT_SHA256));
  assert('sample verify is privacy safe', !unsafeOutputPattern.test(sampleVerifyRun.stdout));

  const sampleOptionVerifyRun = runZlar(['protected-records-runtime-profile-installation', 'verify', '--sample']);
  assertEqual('sample option verify command exits zero', 0, sampleOptionVerifyRun.status);
  assertEqual('sample option verify emits no stderr', '', sampleOptionVerifyRun.stderr);
  assert('sample option verify says verified', sampleOptionVerifyRun.stdout.includes('verified=true'));
  assert('sample option verify includes stable sha', sampleOptionVerifyRun.stdout.includes(SAMPLE_ARTIFACT_SHA256));

  const sampleOptionVerifyJsonRun = runZlar(['protected-records-runtime-profile-installation', 'verify', '--sample', '--json']);
  assertEqual('sample option verify json exits zero', 0, sampleOptionVerifyJsonRun.status);
  assertEqual('sample option verify json emits no stderr', '', sampleOptionVerifyJsonRun.stderr);
  const sampleOptionVerification = JSON.parse(sampleOptionVerifyJsonRun.stdout);
  assertEqual('sample option verify json type', PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_VERIFICATION_TYPE, sampleOptionVerification.verification_type);
  assertEqual('sample option verify json sha matches fixture', SAMPLE_ARTIFACT_SHA256, sampleOptionVerification.body_sha256);

  section('help and fail closed command handling');
  const helpRun = runZlar(['protected-records-runtime-profile-installation', '--help']);
  assertEqual('help exits zero', 0, helpRun.status);
  assert('help names usage', helpRun.stderr.includes('Usage: zlar protected-records-runtime-profile-installation --plan <file|-> --profile <file|-> [--json] [--artifact <file|->]'));
  assert('help names verify usage', helpRun.stderr.includes('zlar protected-records-runtime-profile-installation verify (--input <file|->|--sample) [--json] [--require-sha <artifact_body_sha256>]'));
  assert('help describes disposable installation', helpRun.stderr.includes('local disposable protected-records runtime profile installation proof'));
  assert('help states proof-only', helpRun.stderr.includes('proof-only local disposable protected-records runtime profile installation proof'));
  assert('help names first safe sample run', helpRun.stderr.includes('Use verify --sample as the first safe run'));
  assert('help names sample artifact', helpRun.stderr.includes(SAMPLE_ARTIFACT_PATH));
  assert('help states no latest', helpRun.stderr.includes('choose --latest'));
  assert('help states no current-machine governance proof', helpRun.stderr.includes('prove current-machine governance'));
  assertEqual('help emits no stdout', '', helpRun.stdout);

  const missingInputs = runZlar(['protected-records-runtime-profile-installation']);
  assert('missing inputs exits usage error', missingInputs.status !== 0);
  assertEqual('missing inputs emits no report', '', missingInputs.stdout);
  assert('missing inputs names plan/profile', missingInputs.stderr.includes('--plan and --profile are required'));

  const unsupported = runZlar(['protected-records-runtime-profile-installation', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--latest']);
  assert('unsupported option exits usage error', unsupported.status !== 0);
  assertEqual('unsupported option emits no report', '', unsupported.stdout);
  assert('unsupported option names unsupported option', unsupported.stderr.includes('Unsupported option provided'));
  assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

  const artifactJsonConflict = runZlar(['protected-records-runtime-profile-installation', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--json', '--artifact', '-']);
  assert('artifact stdout json conflict exits usage error', artifactJsonConflict.status !== 0);
  assertEqual('artifact stdout json conflict emits no report', '', artifactJsonConflict.stdout);
  assert('artifact stdout json conflict names conflict', artifactJsonConflict.stderr.includes('Cannot combine --json with --artifact -'));

  const missingVerifyInput = runZlar(['protected-records-runtime-profile-installation', 'verify']);
  assert('missing verify input exits usage error', missingVerifyInput.status !== 0);
  assertEqual('missing verify input emits no report', '', missingVerifyInput.stdout);
  assert('missing verify input names input or sample', missingVerifyInput.stderr.includes('Missing required --input <file|-> or --sample'));
  assert('missing verify input is privacy safe', !unsafeOutputPattern.test(missingVerifyInput.stderr));

  const verifyInputSampleConflict = runZlar(['protected-records-runtime-profile-installation', 'verify', '--input', SAMPLE_ARTIFACT_PATH, '--sample']);
  assert('verify input sample conflict exits usage error', verifyInputSampleConflict.status !== 0);
  assertEqual('verify input sample conflict emits no report', '', verifyInputSampleConflict.stdout);
  assert('verify input sample conflict names conflict', verifyInputSampleConflict.stderr.includes('Cannot combine --input with --sample'));

  const bothStdin = runZlar(['protected-records-runtime-profile-installation', '--plan', '-', '--profile', '-'], {
    input: `${JSON.stringify(plan)}\n${JSON.stringify(profile)}`,
  });
  assert('both stdin exits usage error', bothStdin.status !== 0);
  assertEqual('both stdin emits no report', '', bothStdin.stdout);
  assert('both stdin names stdin conflict', bothStdin.stderr.includes('--plan - and --profile - cannot both read from stdin'));

  const stalePlan = structuredClone(plan);
  stalePlan.plan_status = 'active';
  const stalePath = join(scratch, 'stale-plan.json');
  writeFileSync(stalePath, `${JSON.stringify(stalePlan, null, 2)}\n`);
  const staleRun = runZlar(['protected-records-runtime-profile-installation', '--plan', stalePath, '--profile', PROFILE_PATH]);
  assert('stale plan exits nonzero', staleRun.status !== 0);
  assertEqual('stale plan emits no report', '', staleRun.stdout);
  assert('stale plan failure is sanitized', staleRun.stderr.includes('contract drifted'));

  const shaMismatchPlan = structuredClone(plan);
  shaMismatchPlan.runtime_profile_sha256 = '0'.repeat(64);
  const shaMismatchPath = join(scratch, 'sha-mismatch-plan.json');
  writeFileSync(shaMismatchPath, `${JSON.stringify(shaMismatchPlan, null, 2)}\n`);
  const shaMismatchRun = runZlar(['protected-records-runtime-profile-installation', '--plan', shaMismatchPath, '--profile', PROFILE_PATH]);
  assert('sha mismatch exits nonzero', shaMismatchRun.status !== 0);
  assertEqual('sha mismatch emits no report', '', shaMismatchRun.stdout);
  assert('sha mismatch names mismatch', shaMismatchRun.stderr.includes('profile SHA mismatch'));

  const invalidJsonRun = runZlar(['protected-records-runtime-profile-installation', '--plan', '-', '--profile', PROFILE_PATH], {
    input: '{"plan_type":',
  });
  assert('invalid json exits nonzero', invalidJsonRun.status !== 0);
  assertEqual('invalid json emits no report', '', invalidJsonRun.stdout);
  assert('invalid json names parse failure', invalidJsonRun.stderr.includes('Could not parse'));

  const tamperedArtifact = structuredClone(artifact);
  tamperedArtifact.payload.proof.side_door_report.persistent_runtime_profile_installed = true;
  tamperedArtifact.integrity.body_sha256 = '0'.repeat(64);
  const tamperedPath = join(scratch, 'tampered-artifact.json');
  writeFileSync(tamperedPath, `${JSON.stringify(tamperedArtifact, null, 2)}\n`);
  const tamperedRun = runZlar(['protected-records-runtime-profile-installation', 'verify', '--input', tamperedPath]);
  assert('tampered artifact exits nonzero', tamperedRun.status !== 0);
  assertEqual('tampered artifact emits no verification', '', tamperedRun.stdout);
  assert('tampered artifact failure is sanitized', tamperedRun.stderr.includes('side-door report drifted') || tamperedRun.stderr.includes('SHA-256 mismatch'));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(`\nResults: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) {
  process.exit(1);
}
console.log('ALL PASS');
