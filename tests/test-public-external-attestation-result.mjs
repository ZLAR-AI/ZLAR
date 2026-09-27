#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import {
  PUBLIC_EXTERNAL_ATTESTATION_RESULT_NON_CLAIMS,
  assertNoUnsafePublicExternalAttestationResultText,
  assertPublicExternalAttestationResult,
  buildPublicExternalAttestationSignedPayload,
  canonicalPublicExternalAttestationJson,
  buildPublicExternalAttestationResultVerification,
  formatPublicExternalAttestationResultVerification,
} from '../lib/public-external-attestation-result.mjs';

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

function signedReport(overrides = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const target = {
    release_tag: 'v3.4.59',
    commit_sha: '5c89e6bb51a1442528ba5a2b41bdeb127211aba4',
    source_access_path: 'public_release_assets_only',
    artifact_set_sha256: '1'.repeat(64),
    readiness_report_sha256: '2'.repeat(64),
    proof_bundle_sha256: '3'.repeat(64),
    ...(overrides.target || {}),
  };
  const attestationText = [
    `I verified ZLAR ${target.release_tag} at ${target.commit_sha}.`,
    `Source access path: ${target.source_access_path}.`,
    `Artifact set SHA-256: ${target.artifact_set_sha256}.`,
    `Readiness report SHA-256: ${target.readiness_report_sha256}.`,
    `Proof bundle SHA-256: ${target.proof_bundle_sha256}.`,
    'This bounded public external attestation does not prove production authority.',
    'This bounded public external attestation does not prove enterprise readiness.',
    'This bounded public external attestation does not prove sovereign recognition.',
    'Named limits: public artifact target only; no current-machine governance; no all-surface closure.',
    '',
  ].join('\n');
  const report = {
    report_type: 'zlar-public-external-attestation-result-v1',
    schema_version: 1,
    attestation_class: 'public_signed_or_published_external_attestation',
    verifier: {
      verifier_label: 'arms-length-public-verifier-v3459-001',
      relationship_disclosure_class: 'arms_length_external',
      public_attribution_approved: true,
      public_identity_url: 'https://example.org/zlar-verifier',
      public_identity_redacted_in_private_ledger: true,
      public_key_pem_sha256: sha256(publicKeyPem),
      ...(overrides.verifier || {}),
    },
    target,
    attestation: {
      mode: 'detached_ed25519_signature',
      attestation_text: attestationText,
      attestation_text_sha256: sha256(attestationText),
      public_key_pem: publicKeyPem,
      signature_base64: '',
      signed_payload_canonical_json: '',
      signed_payload_sha256: '',
      named_limits_present: true,
      target_binding_present: true,
      non_claims_present: true,
      signed_or_published_by_verifier: true,
      attestation_preserved_for_future_checking: true,
      ...(overrides.attestation || {}),
    },
    claim_boundary: {
      public_external_attestation: true,
      public_attribution: true,
      non_operator_review_proven: true,
      private_source_review: false,
      production_authority: false,
      enterprise_readiness: false,
      sovereign_recognition: false,
      current_machine_governance: false,
      all_surface_governance: false,
      key_custody: false,
      revocation_truth: false,
      production_downstream_recognition: false,
      side_door_closure: false,
      ...(overrides.claim_boundary || {}),
    },
    non_claims: [...PUBLIC_EXTERNAL_ATTESTATION_RESULT_NON_CLAIMS],
  };
  const signedPayloadCanonicalJson = canonicalPublicExternalAttestationJson(
    buildPublicExternalAttestationSignedPayload(report)
  );
  report.attestation.signed_payload_canonical_json = signedPayloadCanonicalJson;
  report.attestation.signed_payload_sha256 = sha256(signedPayloadCanonicalJson);
  report.attestation.signature_base64 = sign(null, Buffer.from(signedPayloadCanonicalJson), privateKey).toString('base64');
  return report;
}

console.log('\n-- public external attestation result --');

const valid = signedReport();
const validText = `${JSON.stringify(valid, null, 2)}\n`;

assert('valid signed report validates', assertPublicExternalAttestationResult(valid));
const verification = buildPublicExternalAttestationResultVerification(valid, { resultText: validText });
assertEqual('verification type', 'zlar-public-external-attestation-result-verification-v1', verification.verification_type);
assertEqual('verification verified', true, verification.verified);
assertEqual('verification result sha', sha256(validText), verification.result_sha256);
assertEqual('verification public external attestation true', true, verification.claim_boundary.public_external_attestation);
assertEqual('verification non operator true', true, verification.claim_boundary.non_operator_review_proven);
assertEqual('verification production false', false, verification.claim_boundary.production_authority);
assertEqual('verification enterprise false', false, verification.claim_boundary.enterprise_readiness);
assert('formatted output privacy safe', assertNoUnsafePublicExternalAttestationResultText(formatPublicExternalAttestationResultVerification(verification)));

const tamperedSignature = clone(valid);
tamperedSignature.attestation.attestation_text = tamperedSignature.attestation.attestation_text.replace('verified', 'looked at');
tamperedSignature.attestation.attestation_text_sha256 = sha256(tamperedSignature.attestation.attestation_text);
assertThrows('tampered text fails signed envelope binding', () => assertPublicExternalAttestationResult(tamperedSignature), 'signed_payload_canonical_json');

const wrongHash = clone(valid);
wrongHash.attestation.attestation_text_sha256 = '0'.repeat(64);
assertThrows('attestation text hash mismatch fails', () => assertPublicExternalAttestationResult(wrongHash), 'attestation.attestation_text_sha256');

const artifactHashSubstitution = clone(valid);
artifactHashSubstitution.target.artifact_set_sha256 = '4'.repeat(64);
artifactHashSubstitution.attestation.attestation_text = artifactHashSubstitution.attestation.attestation_text.replace(
  '1'.repeat(64),
  '4'.repeat(64)
);
artifactHashSubstitution.attestation.attestation_text_sha256 = sha256(artifactHashSubstitution.attestation.attestation_text);
assertThrows(
  'post-signature artifact hash substitution fails',
  () => assertPublicExternalAttestationResult(artifactHashSubstitution),
  'signed_payload_canonical_json'
);

const identityUrlSubstitution = clone(valid);
identityUrlSubstitution.verifier.public_identity_url = 'https://example.com/different-verifier';
assertThrows(
  'post-signature public identity substitution fails',
  () => assertPublicExternalAttestationResult(identityUrlSubstitution),
  'signed_payload_canonical_json'
);

const nonClaimSubstitution = clone(valid);
nonClaimSubstitution.non_claims[0] = 'This report proves a broader public external attestation than the named target.';
assertThrows(
  'post-signature non-claim substitution fails',
  () => assertPublicExternalAttestationResult(nonClaimSubstitution),
  'non_claims'
);

const publicKeyFingerprintSubstitution = clone(valid);
publicKeyFingerprintSubstitution.verifier.public_key_pem_sha256 = '9'.repeat(64);
assertThrows(
  'post-signature public key fingerprint substitution fails',
  () => assertPublicExternalAttestationResult(publicKeyFingerprintSubstitution),
  'public_key_pem_sha256'
);

const missingTargetText = signedReport();
missingTargetText.target.commit_sha = 'a'.repeat(40);
assertThrows('missing target binding fails', () => assertPublicExternalAttestationResult(missingTargetText), 'commit SHA');

const missingNamedLimit = signedReport();
missingNamedLimit.attestation.attestation_text = missingNamedLimit.attestation.attestation_text.replace('does not prove sovereign recognition.', 'keeps named limits.');
missingNamedLimit.attestation.attestation_text_sha256 = sha256(missingNamedLimit.attestation.attestation_text);
const { privateKey: limitPrivate, publicKey: limitPublic } = generateKeyPairSync('ed25519');
missingNamedLimit.attestation.public_key_pem = limitPublic.export({ type: 'spki', format: 'pem' });
missingNamedLimit.verifier.public_key_pem_sha256 = sha256(missingNamedLimit.attestation.public_key_pem);
missingNamedLimit.attestation.signed_payload_canonical_json = canonicalPublicExternalAttestationJson(
  buildPublicExternalAttestationSignedPayload(missingNamedLimit)
);
missingNamedLimit.attestation.signed_payload_sha256 = sha256(missingNamedLimit.attestation.signed_payload_canonical_json);
missingNamedLimit.attestation.signature_base64 = sign(
  null,
  Buffer.from(missingNamedLimit.attestation.signed_payload_canonical_json),
  limitPrivate
).toString('base64');
assertThrows('missing named limit fails', () => assertPublicExternalAttestationResult(missingNamedLimit), 'sovereign recognition');

const personallyConnected = clone(valid);
personallyConnected.verifier.relationship_disclosure_class = 'personally_connected_private';
assertThrows('personally connected class fails', () => assertPublicExternalAttestationResult(personallyConnected), 'relationship_disclosure_class');

const attributionNotApproved = clone(valid);
attributionNotApproved.verifier.public_attribution_approved = false;
assertThrows('public attribution not approved fails', () => assertPublicExternalAttestationResult(attributionNotApproved), 'public_attribution_approved');

const nonHttpsIdentity = clone(valid);
nonHttpsIdentity.verifier.public_identity_url = 'http://example.org/zlar-verifier';
assertThrows('non-https public identity fails', () => assertPublicExternalAttestationResult(nonHttpsIdentity), 'public_identity_url');

const latestTarget = signedReport({ target: { release_tag: 'latest' } });
assertThrows('latest target fails', () => assertPublicExternalAttestationResult(latestTarget), 'release tag');

const movingCommit = signedReport({ target: { commit_sha: 'HEAD' } });
assertThrows('moving commit fails', () => assertPublicExternalAttestationResult(movingCommit), 'commit SHA');

const privateSourceAccess = clone(valid);
privateSourceAccess.target.source_access_path = 'private_repo_read_access_separately_authorized';
assertThrows('private source access fails initial contract', () => assertPublicExternalAttestationResult(privateSourceAccess), 'source_access_path');

const productionClaim = clone(valid);
productionClaim.claim_boundary.production_authority = true;
assertThrows('production authority claim fails', () => assertPublicExternalAttestationResult(productionClaim), 'production_authority');

const enterpriseClaim = clone(valid);
enterpriseClaim.claim_boundary.enterprise_readiness = true;
assertThrows('enterprise readiness claim fails', () => assertPublicExternalAttestationResult(enterpriseClaim), 'enterprise_readiness');

const noExternalClaim = clone(valid);
noExternalClaim.claim_boundary.public_external_attestation = false;
assertThrows('class 3 without public attestation fails', () => assertPublicExternalAttestationResult(noExternalClaim), 'public_external_attestation');

const extraField = clone(valid);
extraField.target.branch = 'main';
assertThrows('extra target field fails', () => assertPublicExternalAttestationResult(extraField), 'target contains unexpected fields');

const privatePathLeak = clone(valid);
privatePathLeak.verifier.verifier_label = '/Users/vincent/private';
assertThrows('private path leakage fails', () => assertPublicExternalAttestationResult(privatePathLeak), 'verifier_label');

const privateKeyLeak = clone(valid);
privateKeyLeak.attestation.public_key_pem = '-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n';
privateKeyLeak.verifier.public_key_pem_sha256 = sha256(privateKeyLeak.attestation.public_key_pem);
privateKeyLeak.attestation.signed_payload_canonical_json = canonicalPublicExternalAttestationJson(
  buildPublicExternalAttestationSignedPayload(privateKeyLeak)
);
privateKeyLeak.attestation.signed_payload_sha256 = sha256(privateKeyLeak.attestation.signed_payload_canonical_json);
assertThrows('private key leakage fails', () => assertPublicExternalAttestationResult(privateKeyLeak), 'public key PEM');

const missingNonClaim = clone(valid);
missingNonClaim.non_claims = missingNonClaim.non_claims.slice(1);
assertThrows('missing non-claim fails', () => assertPublicExternalAttestationResult(missingNonClaim), 'non_claims');

console.log('\n-- cli --');

const stdinJson = runZlar(['public-external-attestation-result', 'verify', '--input', '-', '--json'], validText);
assertEqual('stdin json exits zero', 0, stdinJson.status);
assertEqual('stdin json emits no stderr', '', stdinJson.stderr);
const stdinOutput = JSON.parse(stdinJson.stdout);
assertEqual('stdin json verified', true, stdinOutput.verified);
assertEqual('stdin result sha matches', sha256(validText), stdinOutput.result_sha256);
assertEqual('stdin json public external attestation true', true, stdinOutput.claim_boundary.public_external_attestation);

const textRun = runZlar(['public-external-attestation-result', 'verify', '--input', '-'], validText);
assertEqual('text output exits zero', 0, textRun.status);
assertEqual('text output emits no stderr', '', textRun.stderr);
assert('text output title present', textRun.stdout.includes('ZLAR Public External Attestation Result Verification v1'));
assert('text output public attestation true', textRun.stdout.includes('public_external_attestation=true'));
assert('text output privacy safe', !/\/Users\/|BEGIN .*PRIVATE KEY|github_pat_|ghp_/.test(textRun.stdout));

const badRun = runZlar(
  ['public-external-attestation-result', 'verify', '--input', '-'],
  `${JSON.stringify(productionClaim, null, 2)}\n`
);
assert('bad input exits nonzero', badRun.status !== 0);
assert('bad input emits no stdout', badRun.stdout === '');
assert('bad input names production boundary', badRun.stderr.includes('production_authority'));
assert('bad input privacy safe', !/\/Users\/|BEGIN .*PRIVATE KEY|github_pat_|ghp_/.test(badRun.stderr));

const help = runZlar(['public-external-attestation-result', '--help']);
assertEqual('help exits zero', 0, help.status);
assert('help names usage', help.stderr.includes('Usage: zlar public-external-attestation-result verify'));

const mainHelp = runZlar(['help']);
assertEqual('main help exits zero', 0, mainHelp.status);
assert('main help lists command', mainHelp.stdout.includes('public-external-attestation-result'));

console.log(`\n${PASS} passed, ${FAIL} failed, ${TOTAL} total`);
if (FAIL > 0) process.exit(1);
