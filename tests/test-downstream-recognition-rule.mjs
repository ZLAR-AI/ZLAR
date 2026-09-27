#!/usr/bin/env node

import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  createReceiptV1FromEvent,
  decodePayloadV1,
  pubkeyFingerprint,
  signReceiptV1,
} from '../lib/receipt.mjs';
import {
  DOWNSTREAM_RECOGNITION_RULE_TYPE,
  SAFE_CLAIM_CEILING,
  assertRecognized,
  assertRefused,
  evaluateDownstreamRecognition,
} from '../lib/downstream-recognition-rule.mjs';

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

function isoSecondsAgo(seconds) {
  return new Date(Date.now() - (seconds * 1000)).toISOString();
}

function isoSecondsFromEpoch(epochSeconds, offsetSeconds) {
  return new Date((epochSeconds + offsetSeconds) * 1000).toISOString();
}

const tempDir = mkdtempSync(join(tmpdir(), 'zlar-downstream-recognition-'));
process.on('exit', () => {
  try { rmSync(tempDir, { recursive: true, force: true }); } catch {}
});

function keyFixture(label) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  const publicPath = join(tempDir, `${label}.pub`);
  writeFileSync(publicPath, publicPem);
  const kid = pubkeyFingerprint(publicPath);
  return { privatePem, publicPem, kid };
}

const primaryKey = keyFixture('primary');
const otherKey = keyFixture('other');
const nowEpoch = Math.floor(Date.now() / 1000);

function eventFixture(overrides = {}) {
  return {
    id: overrides.id || 'downstream-action-001',
    ts: overrides.ts || isoSecondsAgo(5),
    action: overrides.action || 'deploy.release',
    domain: overrides.domain || 'deploy',
    detail: overrides.detail || {
      deployment_id: 'fixture-deploy-001',
      target: 'fake-downstream',
    },
    outcome: overrides.outcome || 'allow',
    rule: overrides.rule || 'RDEPLOY_ALLOW',
    authorizer: overrides.authorizer || 'policy',
    policy_version: overrides.policy_version || 'recognition-policy-v1',
    prev_hash: overrides.prev_hash || '0'.repeat(64),
  };
}

function signedReceipt(overrides = {}, signingKey = primaryKey) {
  const receipt = createReceiptV1FromEvent(eventFixture(overrides));
  return signReceiptV1(receipt, signingKey.privatePem, signingKey.kid);
}

const acceptedReceipt = signedReceipt();
const acceptedPayload = decodePayloadV1(acceptedReceipt);

function recognitionRule(overrides = {}) {
  return {
    deployment_scope: 'fixture-deploy-terminal',
    accepted_issuers: [
      {
        kid: primaryKey.kid,
        public_key_pem: primaryKey.publicPem,
        status: 'active',
      },
    ],
    accepted_policy_versions: ['recognition-policy-v1'],
    accepted_domains: ['deploy'],
    accepted_tools: ['deploy.release'],
    accepted_outcomes: ['allow', 'authorized'],
    max_age_seconds: 120,
    required_audit_event_id: 'downstream-action-001',
    required_detail_hash: acceptedPayload.detail_hash,
    ...overrides,
  };
}

function decisionFor(receipt, rule = recognitionRule()) {
  return evaluateDownstreamRecognition({
    receipt,
    recognition_rule: rule,
    now_epoch: nowEpoch,
  });
}

section('recognized boarding credential');
const accepted = decisionFor(acceptedReceipt);
assert('accepted receipt recognized', assertRecognized(accepted));
assertEqual('result type', DOWNSTREAM_RECOGNITION_RULE_TYPE, accepted.result_type);
assertEqual('safe claim ceiling', SAFE_CLAIM_CEILING, accepted.safe_claim_ceiling);
assertEqual('recognized decision', 'accept', accepted.decision);
assertEqual('recognized reason', 'recognized', accepted.reason_code);
assertEqual('signature valid evidence', true, accepted.evidence.signature_valid);
assertEqual('issuer known evidence', true, accepted.evidence.issuer_known);
assertEqual('policy evidence', 'recognition-policy-v1', accepted.evidence.payload.policy_version);
assertEqual('receipt id evidence', acceptedReceipt.id, accepted.evidence.receipt_id);
assert(
  'verified signed payload identity propagated after verification',
  /^[a-f0-9]{64}$/.test(accepted.evidence.verified_signed_payload_sha256)
);

const aliasKid = 'primary-key-alias';
const aliasEnvelopeDecision = decisionFor(
  { ...acceptedReceipt, kid: aliasKid },
  recognitionRule({
    accepted_issuers: [
      { kid: primaryKey.kid, public_key_pem: primaryKey.publicPem, status: 'active' },
      { kid: aliasKid, public_key_pem: primaryKey.publicPem, status: 'active' },
    ],
  })
);
assert('same-key kid alias remains recognized', assertRecognized(aliasEnvelopeDecision));
assertEqual(
  'same-key kid alias preserves verified signed payload identity',
  accepted.evidence.verified_signed_payload_sha256,
  aliasEnvelopeDecision.evidence.verified_signed_payload_sha256
);

section('fail closed: missing and malformed receipt');
assert('missing receipt refused', assertRefused(decisionFor(null), 'receipt_missing'));
assert('non-object receipt refused', assertRefused(decisionFor('not-json'), 'receipt_not_object'));
assert('unsupported receipt format refused', assertRefused(decisionFor({ receipt_version: '0.1.0' }), 'unsupported_receipt_format'));

section('fail closed: issuer and signature');
const unknownIssuerReceipt = signedReceipt({}, otherKey);
const unknownIssuerDecision = decisionFor(unknownIssuerReceipt);
assert('unknown issuer refused', assertRefused(unknownIssuerDecision, 'unknown_issuer'));
assert(
  'unknown issuer exposes no verified signed payload identity',
  !('verified_signed_payload_sha256' in unknownIssuerDecision.evidence)
);

const retiredIssuerDecision = evaluateDownstreamRecognition({
  receipt: acceptedReceipt,
  recognition_rule: recognitionRule({
    accepted_issuers: [
      { kid: primaryKey.kid, public_key_pem: primaryKey.publicPem, status: 'retired' },
    ],
  }),
  now_epoch: nowEpoch,
});
assert('retired issuer refused', assertRefused(retiredIssuerDecision, 'issuer_not_active'));

const compromisedIssuerDecision = evaluateDownstreamRecognition({
  receipt: acceptedReceipt,
  recognition_rule: recognitionRule({
    accepted_issuers: [
      { kid: primaryKey.kid, public_key_pem: primaryKey.publicPem, status: 'compromised' },
    ],
  }),
  now_epoch: nowEpoch,
});
assert('compromised issuer refused distinctly', assertRefused(compromisedIssuerDecision, 'issuer_compromised'));
assertEqual('compromised issuer status evidence', 'compromised', compromisedIssuerDecision.evidence.issuer_status);

const revokedIssuerDecision = evaluateDownstreamRecognition({
  receipt: acceptedReceipt,
  recognition_rule: recognitionRule({
    accepted_issuers: [
      { kid: primaryKey.kid, public_key_pem: primaryKey.publicPem, status: 'revoked' },
    ],
  }),
  now_epoch: nowEpoch,
});
assert('revoked issuer refused distinctly', assertRefused(revokedIssuerDecision, 'issuer_revoked'));
assertEqual('revoked issuer status evidence', 'revoked', revokedIssuerDecision.evidence.issuer_status);

const missingStatusDecision = evaluateDownstreamRecognition({
  receipt: acceptedReceipt,
  recognition_rule: recognitionRule({
    accepted_issuers: [
      { kid: primaryKey.kid, public_key_pem: primaryKey.publicPem },
    ],
  }),
  now_epoch: nowEpoch,
});
assert('missing issuer status refused', assertRefused(missingStatusDecision, 'issuer_status_missing'));
assertEqual('missing issuer status evidence null', null, missingStatusDecision.evidence.issuer_status);

const trustAnchorOnlyDecision = evaluateDownstreamRecognition({
  receipt: acceptedReceipt,
  recognition_rule: recognitionRule({
    accepted_issuers: [
      { kid: primaryKey.kid, public_key_pem: null, trust_anchor_sha256: 'a'.repeat(64), status: 'active' },
    ],
  }),
  now_epoch: nowEpoch,
});
assert('trust-anchor-only issuer refused by public-key verifier', assertRefused(trustAnchorOnlyDecision, 'issuer_key_missing'));
assertEqual('trust anchor presence recorded', true, trustAnchorOnlyDecision.evidence.trust_anchor_present);

const tamperedReceipt = {
  ...acceptedReceipt,
  payload: acceptedReceipt.payload.slice(0, -2) + 'xx',
};
const tamperedDecision = decisionFor(tamperedReceipt);
assert('tampered receipt refused', assertRefused(tamperedDecision, 'receipt_invalid'));
assert(
  'invalid receipt exposes no verified signed payload identity',
  !('verified_signed_payload_sha256' in tamperedDecision.evidence)
);

section('fail closed: recognition-rule mismatch');
const wrongPolicy = signedReceipt({ policy_version: 'recognition-policy-old' });
const wrongPolicyDecision = decisionFor(wrongPolicy);
assert('wrong policy refused', assertRefused(wrongPolicyDecision, 'policy_not_recognized'));
assert(
  'verified but unrecognized receipt retains verified signed payload identity',
  /^[a-f0-9]{64}$/.test(wrongPolicyDecision.evidence.verified_signed_payload_sha256)
);

const wrongDomain = signedReceipt({ domain: 'records', action: 'deploy.release' });
assert('out-of-scope domain refused', assertRefused(decisionFor(wrongDomain), 'domain_out_of_scope'));

const wrongTool = signedReceipt({ action: 'deploy.rollback' });
assert('out-of-scope tool refused', assertRefused(decisionFor(wrongTool), 'tool_out_of_scope'));

const denyReceipt = signedReceipt({ outcome: 'deny' });
assert('deny receipt does not board', assertRefused(decisionFor(denyReceipt), 'outcome_not_boarding'));

const wrongAuditId = signedReceipt({ id: 'other-audit-event' });
assert('wrong audit event refused', assertRefused(decisionFor(wrongAuditId), 'audit_event_mismatch'));

const wrongDetail = signedReceipt({ detail: { deployment_id: 'different', target: 'fake-downstream' } });
assert('wrong detail hash refused', assertRefused(decisionFor(wrongDetail), 'detail_hash_mismatch'));

const staleReceipt = signedReceipt({ ts: isoSecondsAgo(600) });
const staleDecision = decisionFor(staleReceipt);
assert('stale receipt refused', assertRefused(staleDecision, 'receipt_stale'));
assert('stale age exceeds rule max', staleDecision.evidence.payload.age_seconds > staleDecision.evidence.rule.max_age_seconds);

const futureWithinSemanticSkewReceipt = signedReceipt({ ts: isoSecondsFromEpoch(nowEpoch, 60) });
const futureWithinSemanticSkewDecision = decisionFor(futureWithinSemanticSkewReceipt);
assert('future-within-semantic-skew receipt refused downstream', assertRefused(futureWithinSemanticSkewDecision, 'receipt_stale'));
assert('future-within-skew evidence age is negative', futureWithinSemanticSkewDecision.evidence.payload.age_seconds < 0);
assertEqual('future-within-skew signature valid', true, futureWithinSemanticSkewDecision.evidence.signature_valid);

section('multiple reasons preserve first refusal and evidence');
const multiMismatch = decisionFor(
  signedReceipt({
    action: 'deploy.rollback',
    domain: 'records',
    policy_version: 'recognition-policy-old',
    outcome: 'deny',
  })
);
assertEqual('first mismatch reason is policy', 'policy_not_recognized', multiMismatch.reason_code);
assert('multiple mismatch reasons are preserved', multiMismatch.reasons.length >= 4);
assertEqual('multi mismatch still refuses', 'refuse', multiMismatch.decision);
assertEqual('multi mismatch signature still valid', true, multiMismatch.evidence.signature_valid);

section('non-claims');
const nonClaimText = JSON.stringify(accepted.non_claims);
assert('non-claims reject production deployment claim', nonClaimText.includes('does not prove production deployment'));
assert('non-claims reject external attestation claim', nonClaimText.includes('does not prove external attestation'));
assert('non-claims reject Worker Receipt issuer confusion', nonClaimText.includes('does not make Worker Receipts into issuer credentials'));

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
