#!/usr/bin/env node

import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_VERIFICATION_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_TYPE,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES,
  assertProtectedRecordsInstalledRuntimeProfileServiceProof,
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact,
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification,
} from '../lib/protected-records-installed-runtime-profile-service-proof.mjs';
import {
  REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
} from '../lib/protected-records-installed-runtime-profile-preflight.mjs';

let PASS = 0;
let FAIL = 0;
let TOTAL = 0;

function assert(label, condition, detail = '') {
  TOTAL += 1;
  if (condition) {
    PASS += 1;
    console.log(`  PASS: ${label}`);
  } else {
    FAIL += 1;
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
const PREFLIGHT_PATH =
  'tests/fixtures/protected-records-installed-runtime-profile-preflight-artifact-v1.json';
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|BEGIN (?:PUBLIC|PRIVATE) KEY|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]/i;

function runZlar(args, options = {}) {
  return spawnSync(ZLAR_BIN, args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    input: options.input,
    env: { ...process.env, NO_COLOR: '1' },
  });
}

section('text sample command');
const textRun = runZlar(['protected-records-installed-runtime-profile-service-proof', '--sample']);
assertEqual('text command exits zero', 0, textRun.status);
assertEqual('text command stderr empty', '', textRun.stderr);
assert('text title present', textRun.stdout.includes('ZLAR Protected Records Installed Runtime Profile Service Proof v1'));
assert('text fixture rightful path true', textRun.stdout.includes('fixture_rightful_issuance_path_evidenced=true'));
assert('text generic rightful false', textRun.stdout.includes('rightful_issuance_proven=false'));
assert('text ordered binding exact', textRun.stdout.includes('ordered_transition_binding_type=protected-records-runtime-ordered-single-lock-transition-binding-v1'));
assert('text signed-payload replay reason', textRun.stdout.includes('same_process_signed_payload_replay_reason=receipt_replay'));
assert('text restart consumed-grant reason', textRun.stdout.includes('restart_consumed_grant_reason=authority_grant_already_consumed'));
assert('text state append burn observed', textRun.stdout.includes('state_append_after_grant_commit_burn_observed=true'));
assert('text metadata burn observed', textRun.stdout.includes('metadata_partial_commit_burn_observed=true'));
assert('text three-file rollback detection false', textRun.stdout.includes('store_anchor_and_witness_joint_rollback_detection=false'));
assert('text joint rollback reuse true', textRun.stdout.includes('joint_rollback_reopened_authority_grant_reuse=true'));
assert('text recognition cases 18', textRun.stdout.includes('recognition_refusal_cases=18'));
assert('text authority cases 5', textRun.stdout.includes('authority_refusal_cases=5'));
for (const caseId of REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES) {
  assert(`text recognition refusal ${caseId}`, textRun.stdout.includes(caseId));
}
for (const caseId of REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES) {
  assert(`text authority refusal ${caseId}`, textRun.stdout.includes(caseId));
}
assert('text output privacy safe', !unsafeOutputPattern.test(textRun.stdout));

section('json sample command');
const jsonRun = runZlar(['protected-records-installed-runtime-profile-service-proof', '--sample', '--json']);
assertEqual('json command exits zero', 0, jsonRun.status);
assertEqual('json command stderr empty', '', jsonRun.stderr);
assert('json output privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report validates', assertProtectedRecordsInstalledRuntimeProfileServiceProof(report));
assertEqual('json report type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_TYPE, report.proof_type);
assertEqual('json recognized boards', true, report.recognized_boarding.boarded);
assertEqual('json fixture path true', true, report.proof_boundary.fixture_rightful_issuance_path_evidenced);
assertEqual('json generic rightful false', false, report.proof_boundary.rightful_issuance_proven);
assertEqual('json ordered binding exact', 'protected-records-runtime-ordered-single-lock-transition-binding-v1', report.accepted_runtime_transition_binding.binding_type);
assertEqual('json recognition count', 18, report.refusal_cases.length);
assertEqual('json authority count', 5, report.authority_refusal_cases.length);
assertEqual('json same-process replay reason', 'receipt_replay', report.service_replay_cases[0].reason_code);
assertEqual('json restart replay reason', 'authority_grant_already_consumed', report.service_replay_cases[1].reason_code);
assertEqual('json partial commit cases', 2, report.partial_commit_cases.length);
assertEqual('json joint rollback reopens', true, report.joint_rollback_case.store_anchor_and_witness.service_write_accepted);

section('input file and stdin');
const inputRun = runZlar([
  'protected-records-installed-runtime-profile-service-proof',
  '--input',
  PREFLIGHT_PATH,
  '--json',
]);
assertEqual('input file exits zero', 0, inputRun.status);
assertEqual('input file stderr empty', '', inputRun.stderr);
const inputReport = JSON.parse(inputRun.stdout);
assert('input report validates', assertProtectedRecordsInstalledRuntimeProfileServiceProof(inputReport));
assertEqual('input grant contract stable', report.authority_contract.public_safe_grant_summary.authority_grant_contract_sha256, inputReport.authority_contract.public_safe_grant_summary.authority_grant_contract_sha256);

const stdinRun = runZlar([
  'protected-records-installed-runtime-profile-service-proof',
  '--input',
  '-',
  '--json',
], { input: readFileSync(PREFLIGHT_PATH, 'utf8') });
assertEqual('stdin exits zero', 0, stdinRun.status);
assertEqual('stdin stderr empty', '', stdinRun.stderr);
const stdinReport = JSON.parse(stdinRun.stdout);
assert('stdin report validates', assertProtectedRecordsInstalledRuntimeProfileServiceProof(stdinReport));
assertEqual('stdin grant contract stable', report.authority_contract.public_safe_grant_summary.authority_grant_contract_sha256, stdinReport.authority_contract.public_safe_grant_summary.authority_grant_contract_sha256);

section('artifact generation and verification');
const scratch = mkdtempSync(join(tmpdir(), 'zlar-service-authority-cli-'));
try {
  const artifactPath = join(scratch, 'service-proof-artifact.json');
  const artifactRun = runZlar([
    'protected-records-installed-runtime-profile-service-proof',
    '--sample',
    '--artifact',
    artifactPath,
  ]);
  assertEqual('artifact file command exits zero', 0, artifactRun.status);
  assertEqual('artifact file command stderr empty', '', artifactRun.stderr);
  assert('artifact command prints portable summary', artifactRun.stdout.includes('Portable installed runtime profile service proof artifact:'));
  const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
  assert('artifact validates', assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(artifact));
  assertEqual('artifact type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_TYPE, artifact.artifact_type);
  assert('artifact output privacy safe', !unsafeOutputPattern.test(artifactRun.stdout));

  const artifactStdoutRun = runZlar([
    'protected-records-installed-runtime-profile-service-proof',
    '--sample',
    '--artifact',
    '-',
  ]);
  assertEqual('artifact stdout exits zero', 0, artifactStdoutRun.status);
  assertEqual('artifact stdout stderr empty', '', artifactStdoutRun.stderr);
  const artifactStdout = JSON.parse(artifactStdoutRun.stdout);
  assert('artifact stdout validates', assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(artifactStdout));
  assert('artifact stdout privacy safe', !unsafeOutputPattern.test(artifactStdoutRun.stdout));

  const verifyTextRun = runZlar([
    'protected-records-installed-runtime-profile-service-proof',
    'verify',
    '--input',
    artifactPath,
  ]);
  assertEqual('verify text exits zero', 0, verifyTextRun.status);
  assertEqual('verify text stderr empty', '', verifyTextRun.stderr);
  assert('verify text says verified', verifyTextRun.stdout.includes('verified=true'));
  assert('verify text limits verification to structural integrity', verifyTextRun.stdout.includes('structural_self_integrity_verified=true'));
  assert('verify text requires expected sha for identity', verifyTextRun.stdout.includes('match_requires_expected_sha256=true'));
  assert('verify text names structural scope', verifyTextRun.stdout.includes('verification_scope=structural-self-integrity-only'));
  assert('verify text artifact identity unmatched', verifyTextRun.stdout.includes('sha256_matched=false'));
  assert('verify text fixture path false without expected identity', verifyTextRun.stdout.includes('fixture_rightful_issuance_path_evidenced=false'));
  assert('verify text generic rightful false', verifyTextRun.stdout.includes('rightful_issuance_proven=false'));
  assert('verify text names authority refusals', verifyTextRun.stdout.includes('authority_refusal_cases=5'));
  assert('verify text names recognition refusals', verifyTextRun.stdout.includes('recognition_refusal_cases=18'));
  assert('verify text names joint rollback side door', verifyTextRun.stdout.includes('joint_rollback_reopened_authority_grant_reuse=true'));
  assert('verify text privacy safe', !unsafeOutputPattern.test(verifyTextRun.stdout));

  const verifyJsonRun = runZlar([
    'protected-records-installed-runtime-profile-service-proof',
    'verify',
    '--input',
    artifactPath,
    '--json',
  ]);
  assertEqual('verify json exits zero', 0, verifyJsonRun.status);
  assertEqual('verify json stderr empty', '', verifyJsonRun.stderr);
  const verification = JSON.parse(verifyJsonRun.stdout);
  assert('verification validates', assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification(verification));
  assertEqual('verification type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
  assertEqual('verification artifact sha', artifact.integrity.body_sha256, verification.body_sha256);
  assertEqual('verification structural integrity true', true, verification.structural_self_integrity_verified);
  assertEqual('verification identity requires expected sha', true, verification.artifact_identity_match_requires_expected_sha256);
  assertEqual('verification structural scope exact', 'structural-self-integrity-only', verification.verification_scope);
  assertEqual('verification without expected sha has no identity match field', false, Object.hasOwn(verification, 'required_body_sha256_matched'));
  assertEqual('verification artifact identity false without pin', false, verification.artifact_identity_sha256_matched);
  assertEqual('verification source identity unbound without pin', false, verification.source_preflight_identity_bound_to_expected_artifact_sha256);
  assertEqual('verification signed envelope identity unbound without pin', false, verification.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256);
  assertEqual('verification fixture path false without pin', false, verification.fixture_rightful_issuance_path_evidenced);
  assertEqual('verification ordered binding', 'protected-records-runtime-ordered-single-lock-transition-binding-v1', verification.ordered_transition_binding_type);
  assertEqual('verification restart grant refusal', true, verification.restart_consumed_authority_grant_refused);
  assertEqual('verification metadata burn', true, verification.metadata_partial_commit_burn_observed);
  assertEqual('verification joint rollback reuse', true, verification.joint_rollback_reopened_authority_grant_reuse);

  const requiredShaRun = runZlar([
    'protected-records-installed-runtime-profile-service-proof',
    'verify',
    '--input',
    artifactPath,
    '--require-sha',
    artifact.integrity.body_sha256,
    '--json',
  ]);
  assertEqual('required sha match exits zero', 0, requiredShaRun.status);
  const requiredShaVerification = JSON.parse(requiredShaRun.stdout);
  assertEqual('required sha exact identity echoed', artifact.integrity.body_sha256, requiredShaVerification.required_body_sha256);
  assertEqual('required sha matched true', true, requiredShaVerification.required_body_sha256_matched);
  assertEqual('required sha artifact identity matched', true, requiredShaVerification.artifact_identity_sha256_matched);
  assertEqual('required sha source identity bound', true, requiredShaVerification.source_preflight_identity_bound_to_expected_artifact_sha256);
  assertEqual('required sha signed envelope identity bound', true, requiredShaVerification.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256);
  assertEqual('required sha fixture path true', true, requiredShaVerification.fixture_rightful_issuance_path_evidenced);

  const badRequiredShaRun = runZlar([
    'protected-records-installed-runtime-profile-service-proof',
    'verify',
    '--input',
    artifactPath,
    '--require-sha',
    '0'.repeat(64),
  ]);
  assert('required sha mismatch refuses', badRequiredShaRun.status !== 0);
  assert('required sha mismatch is privacy safe', !unsafeOutputPattern.test(badRequiredShaRun.stderr));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

section('argument refusals and help');
const helpRun = runZlar(['protected-records-installed-runtime-profile-service-proof', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assert('help names usage', helpRun.stderr.includes('Usage: zlar protected-records-installed-runtime-profile-service-proof'));
const missingInput = runZlar(['protected-records-installed-runtime-profile-service-proof']);
assert('missing input refuses', missingInput.status !== 0);
const latest = runZlar(['protected-records-installed-runtime-profile-service-proof', '--latest']);
assert('latest refuses', latest.status !== 0);
const combined = runZlar([
  'protected-records-installed-runtime-profile-service-proof',
  '--sample',
  '--input',
  PREFLIGHT_PATH,
]);
assert('sample plus input refuses', combined.status !== 0);
const invalidJson = runZlar([
  'protected-records-installed-runtime-profile-service-proof',
  '--input',
  '-',
], { input: '{' });
assert('invalid input JSON refuses', invalidJson.status !== 0);
assert('refusal errors privacy safe', !unsafeOutputPattern.test(missingInput.stderr + latest.stderr + combined.stderr + invalidJson.stderr));

console.log(`\n=== Results: ${PASS}/${TOTAL} passed, ${FAIL} failed ===`);
if (FAIL > 0) process.exit(1);
