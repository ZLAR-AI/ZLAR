#!/usr/bin/env node

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
} from '../lib/protected-records-installed-runtime-profile-preflight.mjs';
import {
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_VERIFICATION_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_TYPE,
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProof,
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact,
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactVerification,
} from '../lib/protected-records-installed-runtime-profile-recognition-proof.mjs';

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
const RECOGNITION_ARTIFACT_PATH =
  'tests/fixtures/protected-records-installed-runtime-profile-recognition-proof-artifact-v1.json';
const committedArtifact = JSON.parse(readFileSync(RECOGNITION_ARTIFACT_PATH, 'utf8'));
const committedSha = committedArtifact.integrity.body_sha256;
const committedSourcePreflightSha =
  committedArtifact.payload.proof.source_preflight.body_sha256;
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
const textRun = runZlar(['protected-records-installed-runtime-profile-recognition-proof', '--sample']);
assertEqual('text exits zero', 0, textRun.status);
assertEqual('text stderr empty', '', textRun.stderr);
assert('text title present', textRun.stdout.includes('ZLAR Protected Records Installed Runtime Profile Recognition Proof v1'));
assert('text new route exact', textRun.stdout.includes('receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation'));
assert('text 18 refusals', textRun.stdout.includes('required_refusal_cases=18'));
assert('text fixture authority domain', textRun.stdout.includes('domain=protected-records.local-disposable-fixture'));
assert('text safe power replacement', textRun.stdout.includes('issue_replacement_authority_grant'));
assert('text request supplied authority false', textRun.stdout.includes('request_supplied_authority_accepted=false'));
assert('text ordered binding exact', textRun.stdout.includes('ordered_transition_binding_type=protected-records-runtime-ordered-single-lock-transition-binding-v1'));
assert('text signed payload identity', textRun.stdout.includes('signed_payload_replay_identity=verified-signed-payload-sha256'));
assert('text grant identity', textRun.stdout.includes('authority_grant_consumption_identity=authority-grant-contract-sha256'));
assert('text fixture rightful true', textRun.stdout.includes('fixture_rightful_issuance_path_evidenced=true'));
assert('text generic rightful false', textRun.stdout.includes('rightful_issuance_proven=false'));
assert('text portable rightful false', textRun.stdout.includes('portable_rightful_issuance_proven=false'));
assert('text production rightful false', textRun.stdout.includes('production_rightful_issuance_proven=false'));
assert('text lifecycle false', textRun.stdout.includes('consequence_lifecycle_closed=false'));
for (const caseId of REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES) {
  assert(`text refusal ${caseId}`, textRun.stdout.includes(caseId));
}
assert('text privacy safe', !unsafeOutputPattern.test(textRun.stdout));

section('json sample command');
const jsonRun = runZlar(['protected-records-installed-runtime-profile-recognition-proof', '--sample', '--json']);
assertEqual('json exits zero', 0, jsonRun.status);
assertEqual('json stderr empty', '', jsonRun.stderr);
assert('json privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report validates', assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(report));
assertEqual('json proof type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_TYPE, report.proof_type);
assertEqual('json positive boards', true, report.recognized_boarding.boarded);
assertEqual('json positive grant satisfied', true, report.recognized_boarding.authority_grant_satisfied);
assertEqual('json refusal count', 18, report.refusal_cases.length);
assert('json all refusals mutate zero', report.refusal_cases.every((item) => item.state_entry_count_delta === 0));
assertEqual('json ordered binding', 'protected-records-runtime-ordered-single-lock-transition-binding-v1', report.accepted_runtime_transition_binding.binding_type);
assertEqual('json signed payload identity', 'verified-signed-payload-sha256', report.runtime_identity_boundary.signed_payload_replay_identity);
assertEqual('json grant consumption identity', 'authority-grant-contract-sha256', report.runtime_identity_boundary.authority_grant_consumption_identity);
assertEqual('json fixture rightful true', true, report.proof_boundary.fixture_rightful_issuance_path_evidenced);
assertEqual('json generic rightful false', false, report.proof_boundary.rightful_issuance_proven);
assertEqual('json lifecycle false', false, report.proof_boundary.consequence_lifecycle_closed);

section('input file and stdin');
const inputRun = runZlar([
  'protected-records-installed-runtime-profile-recognition-proof',
  '--input',
  PREFLIGHT_PATH,
  '--json',
]);
assertEqual('input exits zero', 0, inputRun.status);
assertEqual('input stderr empty', '', inputRun.stderr);
const inputReport = JSON.parse(inputRun.stdout);
assert('input report validates', assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(inputReport));
assertEqual('input grant contract stable', report.fixture_authority.public_safe_grant_summary.authority_grant_contract_sha256, inputReport.fixture_authority.public_safe_grant_summary.authority_grant_contract_sha256);

const stdinRun = runZlar([
  'protected-records-installed-runtime-profile-recognition-proof',
  '--input',
  '-',
  '--json',
], { input: readFileSync(PREFLIGHT_PATH, 'utf8') });
assertEqual('stdin exits zero', 0, stdinRun.status);
assertEqual('stdin stderr empty', '', stdinRun.stderr);
const stdinReport = JSON.parse(stdinRun.stdout);
assert('stdin report validates', assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(stdinReport));
assertEqual('stdin refusal count', 18, stdinReport.refusal_cases.length);

section('artifact generation and supplied verification');
const scratch = mkdtempSync(join(tmpdir(), 'zlar-recognition-authority-cli-'));
try {
  const artifactPath = join(scratch, 'recognition-artifact.json');
  const artifactRun = runZlar([
    'protected-records-installed-runtime-profile-recognition-proof',
    '--sample',
    '--artifact',
    artifactPath,
  ]);
  assertEqual('artifact file exits zero', 0, artifactRun.status);
  assertEqual('artifact file stderr empty', '', artifactRun.stderr);
  assert('artifact summary present', artifactRun.stdout.includes('Portable installed runtime profile recognition proof artifact:'));
  const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
  assert('generated artifact validates', assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(artifact));
  assertEqual('generated artifact type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_TYPE, artifact.artifact_type);
  assert('artifact output privacy safe', !unsafeOutputPattern.test(artifactRun.stdout));

  const artifactStdoutRun = runZlar([
    'protected-records-installed-runtime-profile-recognition-proof',
    '--sample',
    '--artifact',
    '-',
  ]);
  assertEqual('artifact stdout exits zero', 0, artifactStdoutRun.status);
  assertEqual('artifact stdout stderr empty', '', artifactStdoutRun.stderr);
  const artifactStdout = JSON.parse(artifactStdoutRun.stdout);
  assert('artifact stdout validates', assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(artifactStdout));
  assert('artifact stdout privacy safe', !unsafeOutputPattern.test(artifactStdoutRun.stdout));

  const verifyTextRun = runZlar([
    'protected-records-installed-runtime-profile-recognition-proof',
    'verify',
    '--input',
    artifactPath,
  ]);
  assertEqual('verify input text exits zero', 0, verifyTextRun.status);
  assertEqual('verify input text stderr empty', '', verifyTextRun.stderr);
  assert('verify input says verified', verifyTextRun.stdout.includes('verified=true'));
  assert('verify input structural self-integrity true', verifyTextRun.stdout.includes('structural_self_integrity_verified=true'));
  assert('verify input scope structural only', verifyTextRun.stdout.includes('verification_scope=structural-self-integrity-only'));
  assert('verify input route exact', verifyTextRun.stdout.includes('source_preflight_route=receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation'));
  assert('verify input refusal count 18', verifyTextRun.stdout.includes('refusal_cases=18'));
  assert('verify input safe powers', verifyTextRun.stdout.includes('revoke_authority_grant'));
  assert('verify input ordered binding', verifyTextRun.stdout.includes('ordered_transition_binding_type=protected-records-runtime-ordered-single-lock-transition-binding-v1'));
  assert('verify input fixture rightful false without pins', verifyTextRun.stdout.includes('fixture_rightful_issuance_path_evidenced=false'));
  assert('verify input generic rightful false', verifyTextRun.stdout.includes('rightful_issuance_proven=false'));
  assert('verify input privacy safe', !unsafeOutputPattern.test(verifyTextRun.stdout));

  const verifyJsonRun = runZlar([
    'protected-records-installed-runtime-profile-recognition-proof',
    'verify',
    '--input',
    artifactPath,
    '--json',
  ]);
  assertEqual('verify input json exits zero', 0, verifyJsonRun.status);
  assertEqual('verify input json stderr empty', '', verifyJsonRun.stderr);
  const verification = JSON.parse(verifyJsonRun.stdout);
  assert('verify input validates', assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactVerification(verification));
  assertEqual('verification type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
  assertEqual('verification body sha', artifact.integrity.body_sha256, verification.body_sha256);
  assertEqual('verification refusal count', 18, verification.refusal_case_count);
  assertEqual('verification request authority false', false, verification.request_supplied_authority_accepted);
  assertEqual('verification artifact identity unmatched', false, verification.artifact_identity_sha256_matched);
  assertEqual('verification source identity unmatched', false, verification.source_preflight_body_sha256_matched);
  assertEqual('verification fixture rightful false', false, verification.fixture_rightful_issuance_path_evidenced);
  assertEqual('verification signed-payload identity unbound', false, verification.signed_payload_identity_bound_to_expected_artifact_and_source_sha256);
  assertEqual('verification generic rightful false', false, verification.rightful_issuance_proven);

  const tampered = JSON.parse(JSON.stringify(artifact));
  tampered.payload.proof.proof_boundary.rightful_issuance_proven = true;
  const tamperedPath = join(scratch, 'tampered-recognition-artifact.json');
  writeFileSync(tamperedPath, `${JSON.stringify(tampered, null, 2)}\n`);
  const tamperedRun = runZlar([
    'protected-records-installed-runtime-profile-recognition-proof',
    'verify',
    '--input',
    tamperedPath,
  ]);
  assert('tampered artifact refuses', tamperedRun.status !== 0);
  assert('tamper refusal privacy safe', !unsafeOutputPattern.test(tamperedRun.stderr));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

section('committed sample verification');
assert('committed artifact validates in process', assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(committedArtifact));
const sampleVerifyText = runZlar([
  'protected-records-installed-runtime-profile-recognition-proof',
  'verify',
  '--sample',
]);
assertEqual('verify sample text exits zero', 0, sampleVerifyText.status);
assertEqual('verify sample text stderr empty', '', sampleVerifyText.stderr);
assert('verify sample names committed sha', sampleVerifyText.stdout.includes(committedSha));
assert('verify sample fixture rightful false without pins', sampleVerifyText.stdout.includes('fixture_rightful_issuance_path_evidenced=false'));
assert('verify sample privacy safe', !unsafeOutputPattern.test(sampleVerifyText.stdout));

const sampleVerifyJson = runZlar([
  'protected-records-installed-runtime-profile-recognition-proof',
  'verify',
  '--sample',
  '--require-sha',
  committedSha,
  '--require-source-preflight-sha',
  committedSourcePreflightSha,
  '--json',
]);
assertEqual('verify sample json exits zero', 0, sampleVerifyJson.status);
assertEqual('verify sample json stderr empty', '', sampleVerifyJson.stderr);
const sampleVerification = JSON.parse(sampleVerifyJson.stdout);
assertEqual('verify sample required sha matched', true, sampleVerification.required_body_sha256_matched);
assertEqual('verify sample body sha', committedSha, sampleVerification.body_sha256);
assertEqual('verify sample artifact identity matched', true, sampleVerification.artifact_identity_sha256_matched);
assertEqual('verify sample source identity matched', true, sampleVerification.source_preflight_body_sha256_matched);
assertEqual('verify sample fixture rightful true with both pins', true, sampleVerification.fixture_rightful_issuance_path_evidenced);
assertEqual('verify sample ordered binding', 'protected-records-runtime-ordered-single-lock-transition-binding-v1', sampleVerification.ordered_transition_binding_type);

const wrongSha = runZlar([
  'protected-records-installed-runtime-profile-recognition-proof',
  'verify',
  '--sample',
  '--require-sha',
  '0'.repeat(64),
]);
assert('wrong required sha refuses', wrongSha.status !== 0);
assert('wrong sha refusal privacy safe', !unsafeOutputPattern.test(wrongSha.stderr));

const artifactOnlyPin = runZlar([
  'protected-records-installed-runtime-profile-recognition-proof',
  'verify',
  '--sample',
  '--require-sha',
  committedSha,
  '--json',
]);
assertEqual('artifact-only pin exits zero', 0, artifactOnlyPin.status);
const artifactOnlyVerification = JSON.parse(artifactOnlyPin.stdout);
assertEqual('artifact-only pin matches artifact identity', true, artifactOnlyVerification.artifact_identity_sha256_matched);
assertEqual('artifact-only pin cannot claim fixture rightful', false, artifactOnlyVerification.fixture_rightful_issuance_path_evidenced);

const wrongSourceSha = runZlar([
  'protected-records-installed-runtime-profile-recognition-proof',
  'verify',
  '--sample',
  '--require-sha',
  committedSha,
  '--require-source-preflight-sha',
  '0'.repeat(64),
]);
assert('wrong required source preflight sha refuses', wrongSourceSha.status !== 0);
assert('wrong source sha refusal privacy safe', !unsafeOutputPattern.test(wrongSourceSha.stderr));

section('argument refusals and help');
const helpRun = runZlar(['protected-records-installed-runtime-profile-recognition-proof', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assert('help names usage', helpRun.stderr.includes('Usage: zlar protected-records-installed-runtime-profile-recognition-proof'));
assert('help names source preflight identity pin', helpRun.stderr.includes('--require-source-preflight-sha <source_preflight_body_sha256>'));
const missingInput = runZlar(['protected-records-installed-runtime-profile-recognition-proof']);
assert('missing input refuses', missingInput.status !== 0);
const latest = runZlar(['protected-records-installed-runtime-profile-recognition-proof', '--latest']);
assert('latest refuses', latest.status !== 0);
const combined = runZlar([
  'protected-records-installed-runtime-profile-recognition-proof',
  '--sample',
  '--input',
  PREFLIGHT_PATH,
]);
assert('sample and input refuses', combined.status !== 0);
const invalidJson = runZlar([
  'protected-records-installed-runtime-profile-recognition-proof',
  '--input',
  '-',
], { input: '{' });
assert('invalid JSON refuses', invalidJson.status !== 0);
const missingSourceSha = runZlar([
  'protected-records-installed-runtime-profile-recognition-proof',
  'verify',
  '--sample',
  '--require-source-preflight-sha',
]);
assert('missing source preflight sha refuses', missingSourceSha.status !== 0);
assert('argument refusal privacy safe', !unsafeOutputPattern.test(missingInput.stderr + latest.stderr + combined.stderr + invalidJson.stderr + missingSourceSha.stderr));

console.log(`\n=== Results: ${PASS}/${TOTAL} passed, ${FAIL} failed ===`);
if (FAIL > 0) process.exit(1);
