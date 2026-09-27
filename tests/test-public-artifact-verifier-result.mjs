#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  assertNoUnsafePublicArtifactVerifierResultText,
  assertNoUnsafePublicArtifactVerifierTranscriptText,
  assertPublicArtifactVerifierResult,
  buildPublicArtifactVerifierResultFromTranscript,
  buildPublicArtifactVerifierResultVerification,
  formatPublicArtifactVerifierResultVerification,
  samplePublicArtifactVerifierResult,
  samplePublicArtifactVerifierTranscript,
} from '../lib/public-artifact-verifier-result.mjs';

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

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function sha256(text) {
  return createHash('sha256').update(text).digest('hex');
}

function runZlar(args, input = '') {
  return spawnSync('./bin/zlar', args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    input,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

console.log('\n-- public artifact verifier result --');

const sample = samplePublicArtifactVerifierResult();
const sampleText = `${JSON.stringify(sample, null, 2)}\n`;
const redactedV3459FixtureText = readFileSync(
  new URL('fixtures/public-artifact-verifier-result-v3459-redacted-v1.json', import.meta.url),
  'utf8'
);
const redactedV3459Fixture = JSON.parse(redactedV3459FixtureText);

assert('sample validates', assertPublicArtifactVerifierResult(sample));
const verification = buildPublicArtifactVerifierResultVerification(sample, { resultText: sampleText });
assertEqual('verification type', 'zlar-public-artifact-verifier-result-verification-v1', verification.verification_type);
assertEqual('verification verified', true, verification.verified);
assertEqual('verification result sha', sha256(sampleText), verification.result_sha256);
assertEqual('verification hash consistency signal', true, verification.public_artifact_hash_consistency_signal);
assertEqual('verification reachability signal', true, verification.public_artifact_reachability_signal);
assertEqual('verification public attestation false', false, verification.claim_boundary.public_external_attestation);
assertEqual('verification non-operator false', false, verification.claim_boundary.non_operator_review_proven);
assertEqual('verification private source review false', false, verification.claim_boundary.private_source_review);
assert('formatted output privacy safe', assertNoUnsafePublicArtifactVerifierResultText(formatPublicArtifactVerifierResultVerification(verification)));

assert('redacted v3.4.59 public-artifact fixture validates', assertPublicArtifactVerifierResult(redactedV3459Fixture));
const redactedV3459Verification = buildPublicArtifactVerifierResultVerification(redactedV3459Fixture, {
  resultText: redactedV3459FixtureText,
});
assertEqual('redacted v3.4.59 fixture verification true', true, redactedV3459Verification.verified);
assertEqual(
  'redacted v3.4.59 fixture tarball hash',
  '930bb18e1d871c498ac47a5cdf2c78ef22d127773f805cefa4fe5fabdc73c6b7',
  redactedV3459Verification.observed.verifier_kit_tarball_sha256,
);
assertEqual('redacted v3.4.59 fixture hash consistency signal true', true, redactedV3459Verification.public_artifact_hash_consistency_signal);
assertEqual('redacted v3.4.59 fixture reachability signal true', true, redactedV3459Verification.public_artifact_reachability_signal);
assertEqual('redacted v3.4.59 fixture public attestation false', false, redactedV3459Verification.claim_boundary.public_external_attestation);
assertEqual('redacted v3.4.59 fixture public attribution false', false, redactedV3459Verification.claim_boundary.public_attribution);
assertEqual('redacted v3.4.59 fixture non-operator review claim false', false, redactedV3459Verification.claim_boundary.non_operator_review_proven);
assertEqual('redacted v3.4.59 fixture private source review false', false, redactedV3459Verification.claim_boundary.private_source_review);
assertEqual('redacted v3.4.59 fixture production authority false', false, redactedV3459Verification.claim_boundary.production_authority);
assertEqual('redacted v3.4.59 fixture enterprise readiness false', false, redactedV3459Verification.claim_boundary.enterprise_readiness);
assertEqual('redacted v3.4.59 fixture current-machine governance false', false, redactedV3459Verification.claim_boundary.current_machine_governance);
assertEqual('redacted v3.4.59 fixture all-surface governance false', false, redactedV3459Verification.claim_boundary.all_surface_governance);
assertEqual('redacted v3.4.59 fixture key custody false', false, redactedV3459Verification.claim_boundary.key_custody);
assertEqual('redacted v3.4.59 fixture revocation truth false', false, redactedV3459Verification.claim_boundary.revocation_truth);
assertEqual('redacted v3.4.59 fixture side door closure false', false, redactedV3459Verification.claim_boundary.side_door_closure);
assert('redacted v3.4.59 fixture text privacy safe', assertNoUnsafePublicArtifactVerifierResultText(redactedV3459FixtureText));

const wrongVersion = clone(sample);
wrongVersion.target.version = 'v3.4.60';
assertThrows('wrong target version fails', () => assertPublicArtifactVerifierResult(wrongVersion), 'target.version');

const wrongUrl = clone(sample);
wrongUrl.target.release_json_url = 'https://example.com/release.json';
assertThrows('wrong release URL fails', () => assertPublicArtifactVerifierResult(wrongUrl), 'target.release_json_url');

const sourceAccess = clone(sample);
sourceAccess.observed.source_access_used = true;
assertThrows('source access use fails', () => assertPublicArtifactVerifierResult(sourceAccess), 'observed.source_access_used');

const githubAccess = clone(sample);
githubAccess.observed.github_access_used = true;
assertThrows('GitHub access use fails', () => assertPublicArtifactVerifierResult(githubAccess), 'observed.github_access_used');

const credentialUse = clone(sample);
credentialUse.observed.credentials_used = true;
assertThrows('credential use fails', () => assertPublicArtifactVerifierResult(credentialUse), 'observed.credentials_used');

const deployKeyUse = clone(sample);
deployKeyUse.observed.deploy_key_used = true;
assertThrows('deploy key use fails', () => assertPublicArtifactVerifierResult(deployKeyUse), 'observed.deploy_key_used');

const publicAttestation = clone(sample);
publicAttestation.claim_boundary.public_external_attestation = true;
assertThrows('public attestation claim fails', () => assertPublicArtifactVerifierResult(publicAttestation), 'claim_boundary.public_external_attestation');

const nonOperator = clone(sample);
nonOperator.claim_boundary.non_operator_review_proven = true;
assertThrows('non-operator public claim fails', () => assertPublicArtifactVerifierResult(nonOperator), 'claim_boundary.non_operator_review_proven');

const sidecarMismatch = clone(sample);
sidecarMismatch.observed.sidecar_text = `${'5'.repeat(64)}  zlar-verifier-kit-v0.1.0.tar.gz\n`;
assertThrows('sidecar mismatch fails', () => assertPublicArtifactVerifierResult(sidecarMismatch), 'sidecar_text hash must match');

const sidecarWrongName = clone(sample);
sidecarWrongName.observed.sidecar_text = `${sample.observed.verifier_kit_tarball_sha256}  other.tar.gz\n`;
assertThrows('sidecar wrong filename fails', () => assertPublicArtifactVerifierResult(sidecarWrongName), 'must name zlar-verifier-kit-v0.1.0.tar.gz');

const missingNonClaim = clone(sample);
missingNonClaim.non_claims = missingNonClaim.non_claims.slice(1);
assertThrows('missing non-claim fails', () => assertPublicArtifactVerifierResult(missingNonClaim), 'non_claims must exactly match');

const extraOverclaimNonClaim = clone(sample);
extraOverclaimNonClaim.non_claims = [
  ...extraOverclaimNonClaim.non_claims,
  'This public artifact proves enterprise readiness.',
];
assertThrows(
  'extra overclaim non-claim fails',
  () => assertPublicArtifactVerifierResult(extraOverclaimNonClaim),
  'non_claims must exactly match'
);

const sidecarSecretSecondLine = clone(sample);
sidecarSecretSecondLine.observed.sidecar_text = `${sample.observed.verifier_kit_tarball_sha256}  zlar-verifier-kit-v0.1.0.tar.gz\ntoken=abc123\n`;
assertThrows(
  'sidecar second line fails closed',
  () => assertPublicArtifactVerifierResult(sidecarSecretSecondLine),
  'observed.sidecar_text must contain exactly one non-empty line'
);

const extraField = clone(sample);
extraField.target.latest = true;
assertThrows('extra target field fails', () => assertPublicArtifactVerifierResult(extraField), 'target contains unexpected fields');

const privatePathLabel = clone(sample);
privatePathLabel.verifier_label = '/Users/vincent/private';
assertThrows('private path leakage fails', () => assertPublicArtifactVerifierResult(privatePathLabel), 'verifier_label');

assertThrows(
  'raw email header residue fails result safety check',
  () => assertNoUnsafePublicArtifactVerifierResultText('Subject: ZLAR public artifact check\n'),
  'email header residue'
);

assertThrows(
  'mailbox address residue fails result safety check',
  () => assertNoUnsafePublicArtifactVerifierResultText('verifier@example.com'),
  'mailbox address residue'
);

console.log('\n-- public artifact transcript normalizer --');

const sampleTranscript = samplePublicArtifactVerifierTranscript();
const transcriptReport = buildPublicArtifactVerifierResultFromTranscript(sampleTranscript);
assert('sample transcript normalizes', assertPublicArtifactVerifierResult(transcriptReport));
assertEqual('transcript report type', 'zlar-public-artifact-verifier-result-v1', transcriptReport.report_type);
assertEqual('transcript tarball hash extracted', '4'.repeat(64), transcriptReport.observed.verifier_kit_tarball_sha256);
assertEqual('transcript keeps source access false', false, transcriptReport.observed.source_access_used);
assertEqual('transcript keeps public attestation false', false, transcriptReport.claim_boundary.public_external_attestation);

assertThrows(
  'transcript missing proof-pack marker fails',
  () => buildPublicArtifactVerifierResultFromTranscript(sampleTranscript.replace('proof-pack-manifest.json', '')),
  'transcript missing required public artifact marker: proof-pack-manifest.json'
);

assertThrows(
  'transcript checksum failure fails',
  () => buildPublicArtifactVerifierResultFromTranscript(sampleTranscript.replace('zlar-verifier-kit-v0.1.0.tar.gz: OK', 'zlar-verifier-kit-v0.1.0.tar.gz: FAILED')),
  'checksum failure or warning'
);

assertThrows(
  'transcript credential residue fails',
  () => buildPublicArtifactVerifierResultFromTranscript(`${sampleTranscript}token=abc123\n`),
  'unsafe public artifact verifier transcript contains assignment-shaped secret'
);

assertThrows(
  'transcript email header residue fails',
  () => assertNoUnsafePublicArtifactVerifierTranscriptText('From: verifier@example.com\n'),
  'email header residue'
);

console.log('\n-- cli --');

const sampleJson = runZlar(['public-artifact-verifier-result', 'verify', '--sample', '--json']);
assertEqual('sample json exits zero', 0, sampleJson.status);
assertEqual('sample json emits no stderr', '', sampleJson.stderr);
const sampleJsonOutput = JSON.parse(sampleJson.stdout);
assertEqual('sample json verified', true, sampleJsonOutput.verified);
assertEqual('sample json public attestation false', false, sampleJsonOutput.claim_boundary.public_external_attestation);
assertEqual('sample json source access false', false, sampleJsonOutput.observed.source_access_used);

const sampleTextRun = runZlar(['public-artifact-verifier-result', 'verify', '--sample']);
assertEqual('sample text exits zero', 0, sampleTextRun.status);
assertEqual('sample text emits no stderr', '', sampleTextRun.stderr);
assert('sample text title present', sampleTextRun.stdout.includes('ZLAR Public Artifact Verifier Result Verification v1'));
assert('sample text includes public attestation false', sampleTextRun.stdout.includes('public_external_attestation=false'));
assert('sample text privacy safe', !/\/Users\/|BEGIN .*PRIVATE KEY|github_pat_|ghp_/.test(sampleTextRun.stdout));

const stdinJson = runZlar(['public-artifact-verifier-result', 'verify', '--input', '-', '--json'], sampleText);
assertEqual('stdin json exits zero', 0, stdinJson.status);
assertEqual('stdin json emits no stderr', '', stdinJson.stderr);
assertEqual('stdin result sha matches sample text', sha256(sampleText), JSON.parse(stdinJson.stdout).result_sha256);

const badInput = clone(sample);
badInput.observed.sidecar_check_passed = false;
const badRun = runZlar(['public-artifact-verifier-result', 'verify', '--input', '-'], `${JSON.stringify(badInput)}\n`);
assert('bad input exits nonzero', badRun.status !== 0);
assert('bad input names sidecar check', badRun.stderr.includes('sidecar_check_passed'));

const transcriptJson = runZlar(['public-artifact-verifier-result', 'from-transcript', '--sample-transcript', '--json']);
assertEqual('transcript json exits zero', 0, transcriptJson.status);
assertEqual('transcript json emits no stderr', '', transcriptJson.stderr);
const transcriptJsonOutput = JSON.parse(transcriptJson.stdout);
assertEqual('transcript json report type', 'zlar-public-artifact-verifier-result-v1', transcriptJsonOutput.report_type);
assertEqual('transcript json source access false', false, transcriptJsonOutput.observed.source_access_used);

const transcriptVerify = runZlar(
  ['public-artifact-verifier-result', 'verify', '--input', '-', '--json'],
  transcriptJson.stdout
);
assertEqual('transcript output verifies', 0, transcriptVerify.status);
assertEqual('transcript output verify stderr empty', '', transcriptVerify.stderr);
assertEqual('transcript output verification true', true, JSON.parse(transcriptVerify.stdout).verified);

const help = runZlar(['public-artifact-verifier-result', '--help']);
assertEqual('help exits zero', 0, help.status);
assert('help names usage', help.stderr.includes('Usage: zlar public-artifact-verifier-result verify'));

const mainHelp = runZlar(['help']);
assertEqual('main help exits zero', 0, mainHelp.status);
assert('main help lists command', mainHelp.stdout.includes('public-artifact-verifier-result'));

console.log(`\n${PASS} passed, ${FAIL} failed, ${TOTAL} total`);
if (FAIL > 0) process.exit(1);
