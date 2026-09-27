#!/usr/bin/env node

import { createHash, generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  createProtectedRecordsBoardingDecisionState,
  evaluateProtectedRecordsBoardingDecision,
} from '../lib/protected-records-boarding-decision.mjs';
import {
  createReceipt,
  createReceiptV1,
  decodePayloadV1,
  signReceipt,
  signReceiptV1,
} from '../lib/receipt.mjs';

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

function kidFor(publicPem) {
  return createHash('sha256').update(Buffer.from(publicPem, 'utf8')).digest('hex').slice(0, 16);
}

function keyFixture() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  return {
    privatePem,
    publicPem,
    kid: kidFor(publicPem),
  };
}

function isoSecondsAgo(nowEpoch, seconds) {
  return new Date((nowEpoch - seconds) * 1000).toISOString();
}

const nowEpoch = 1782840000;
const actionDetail = {
  record_id: 'local-boarding-helper-record',
  operation: 'append_controlled_status',
};

function signedReceipt(key, overrides = {}) {
  return signReceiptV1(
    createReceiptV1({
      id: overrides.receipt_id,
      tool: overrides.action || 'records.write',
      domain: overrides.domain || 'records',
      detail: overrides.detail || actionDetail,
      outcome: overrides.outcome || 'allow',
      rule: overrides.rule || 'RRECORDS_LOCAL_BOARDING_ALLOW',
      authorizer: overrides.authorizer || 'policy',
      timestamp: overrides.ts || isoSecondsAgo(nowEpoch, 5),
      policy_version: overrides.policy_version || 'recognition-policy-v1',
      audit_event_id: overrides.audit_event_id || 'protected-records-helper-write-001',
      audit_prev_hash: overrides.prev_hash || '0'.repeat(64),
      prev_receipt_hash: overrides.prev_receipt_hash ?? null,
    }),
    key.privatePem,
    key.kid
  );
}

function signedLegacyV0Receipt(key, overrides = {}) {
  return signReceipt(
    createReceipt({
      id: overrides.receipt_id,
      tool: overrides.action || 'records.write',
      domain: overrides.domain || 'records',
      detail: overrides.detail || actionDetail,
      outcome: overrides.outcome || 'allow',
      rule: overrides.rule || 'RRECORDS_LOCAL_BOARDING_ALLOW',
      authorizer: overrides.authorizer || 'policy',
      timestamp: overrides.ts || isoSecondsAgo(nowEpoch, 5),
      policy_version: overrides.policy_version || 'recognition-policy-v1',
      audit_event_id: overrides.audit_event_id || 'protected-records-helper-write-001',
      audit_prev_hash: overrides.prev_hash || '0'.repeat(64),
      prev_receipt_hash: overrides.prev_receipt_hash ?? null,
    }),
    key.privatePem,
    key.kid
  );
}

const active = keyFixture();
const inactive = keyFixture();
const unknown = keyFixture();
const activeKidAlias = 'active-public-key-alias';
const recognizedReceipt = signedReceipt(active, { receipt_id: `${'a'.repeat(12)}${'1'.repeat(32)}` });
const recognizedPayload = decodePayloadV1(recognizedReceipt);
const invalidReceiptBase = signedReceipt(active, { receipt_id: `${'b'.repeat(12)}${'2'.repeat(32)}` });
const invalidReceipt = {
  ...invalidReceiptBase,
  sig: `${invalidReceiptBase.sig.slice(0, -2)}xx`,
};
const recognitionRule = {
  deployment_scope: 'protected-records-helper.records.write.fixture-v1',
  accepted_issuers: [
    {
      kid: active.kid,
      public_key_pem: active.publicPem,
      status: 'active',
    },
    {
      kid: activeKidAlias,
      public_key_pem: active.publicPem,
      status: 'active',
    },
    {
      kid: inactive.kid,
      public_key_pem: inactive.publicPem,
      status: 'inactive',
    },
  ],
  accepted_policy_versions: ['recognition-policy-v1'],
  accepted_domains: ['records'],
  accepted_tools: ['records.write'],
  accepted_outcomes: ['allow', 'authorized'],
  max_age_seconds: 120,
  required_audit_event_id: 'protected-records-helper-write-001',
  required_detail_hash: recognizedPayload.detail_hash,
};

function decision({
  caseId,
  receipt,
  receiptClass,
  expectedReasonCode,
  state,
}) {
  return evaluateProtectedRecordsBoardingDecision({
    actionClass: 'records.write',
    caseId,
    effectType: 'protected-records-helper-effect-v1',
    expectedReasonCode,
    nowEpoch,
    receipt,
    receiptClass,
    recognitionRule,
    replayScope: 'protected-records-helper.records.write.fixture-v1',
    state,
  });
}

function assertRefusal(label, result, reasonCode, beforeCount = 0) {
  assertEqual(`${label} decision`, 'refuse', result.decision);
  assertEqual(`${label} reason`, reasonCode, result.observed_reason_code);
  assertEqual(`${label} effect count before`, beforeCount, result.effect_count_before);
  assertEqual(`${label} effect count after`, beforeCount, result.effect_count_after);
  assertEqual(`${label} effect delta`, 0, result.effect_count_delta);
  assertEqual(`${label} refused before effect`, true, result.refused_before_effect);
  assertEqual(`${label} accepted marker`, false, result.accepted_once_marker);
}

section('skinny helper state contract');
assertThrows(
  'missing state fails closed',
  () => evaluateProtectedRecordsBoardingDecision({ receipt: null, recognitionRule, nowEpoch }),
  'requires in-memory destination state'
);
assertThrows(
  'bad effects sink fails closed',
  () => createProtectedRecordsBoardingDecisionState({ effects: {}, replayCache: new Set() }),
  'effects sink must be an array'
);
assertThrows(
  'bad replay cache fails closed',
  () => createProtectedRecordsBoardingDecisionState({ effects: [], replayCache: [] }),
  'replay cache must be a Set'
);

section('skinny helper refusal matrix');
const state = createProtectedRecordsBoardingDecisionState();
assertRefusal(
  'no receipt',
  decision({
    caseId: 'no_receipt_refused',
    receipt: null,
    receiptClass: 'missing',
    expectedReasonCode: 'receipt_missing',
    state,
  }),
  'receipt_missing'
);
assertRefusal(
  'invalid receipt',
  decision({
    caseId: 'invalid_receipt_refused',
    receipt: invalidReceipt,
    receiptClass: 'invalid_signature',
    expectedReasonCode: 'receipt_invalid',
    state,
  }),
  'receipt_invalid'
);
assertRefusal(
  'unknown issuer',
  decision({
    caseId: 'unknown_issuer_refused',
    receipt: signedReceipt(unknown, { receipt_id: `${'c'.repeat(12)}${'3'.repeat(32)}` }),
    receiptClass: 'unknown_issuer',
    expectedReasonCode: 'unknown_issuer',
    state,
  }),
  'unknown_issuer'
);
assertRefusal(
  'inactive issuer',
  decision({
    caseId: 'inactive_issuer_refused',
    receipt: signedReceipt(inactive, { receipt_id: `${'d'.repeat(12)}${'4'.repeat(32)}` }),
    receiptClass: 'inactive_issuer',
    expectedReasonCode: 'issuer_not_active',
    state,
  }),
  'issuer_not_active'
);
assertRefusal(
  'wrong destination',
  decision({
    caseId: 'wrong_destination_refused',
    receipt: signedReceipt(active, {
      receipt_id: `${'e'.repeat(12)}${'5'.repeat(32)}`,
      domain: 'records-other',
    }),
    receiptClass: 'wrong_destination',
    expectedReasonCode: 'domain_out_of_scope',
    state,
  }),
  'domain_out_of_scope'
);
assertRefusal(
  'wrong action',
  decision({
    caseId: 'wrong_action_refused',
    receipt: signedReceipt(active, {
      receipt_id: `${'f'.repeat(12)}${'6'.repeat(32)}`,
      action: 'records.delete',
    }),
    receiptClass: 'wrong_action',
    expectedReasonCode: 'tool_out_of_scope',
    state,
  }),
  'tool_out_of_scope'
);
assertRefusal(
  'wrong policy',
  decision({
    caseId: 'wrong_policy_refused',
    receipt: signedReceipt(active, {
      receipt_id: `${'1'.repeat(12)}${'7'.repeat(32)}`,
      policy_version: 'unrecognized-recognition-policy-v1',
    }),
    receiptClass: 'wrong_policy',
    expectedReasonCode: 'policy_not_recognized',
    state,
  }),
  'policy_not_recognized'
);
assertRefusal(
  'stale receipt',
  decision({
    caseId: 'stale_receipt_refused',
    receipt: signedReceipt(active, {
      receipt_id: `${'2'.repeat(12)}${'8'.repeat(32)}`,
      ts: isoSecondsAgo(nowEpoch, 3600),
    }),
    receiptClass: 'stale_receipt',
    expectedReasonCode: 'receipt_stale',
    state,
  }),
  'receipt_stale'
);
assertRefusal(
  'wrong detail',
  decision({
    caseId: 'wrong_detail_refused',
    receipt: signedReceipt(active, {
      receipt_id: `${'3'.repeat(12)}${'9'.repeat(32)}`,
      detail: {
        record_id: 'local-boarding-helper-record-other',
        operation: 'append_controlled_status',
      },
    }),
    receiptClass: 'wrong_detail',
    expectedReasonCode: 'detail_hash_mismatch',
    state,
  }),
  'detail_hash_mismatch'
);
assertRefusal(
  'legacy v0',
  decision({
    caseId: 'legacy_v0_unsupported_refused',
    receipt: signedLegacyV0Receipt(active, { receipt_id: `${'4'.repeat(12)}${'0'.repeat(32)}` }),
    receiptClass: 'legacy_v0_receipt',
    expectedReasonCode: 'unsupported_receipt_format',
    state,
  }),
  'unsupported_receipt_format'
);

section('skinny helper accepted once and replay refused');
const accepted = decision({
  caseId: 'recognized_receipt_accepted_once',
  receipt: recognizedReceipt,
  receiptClass: 'recognized_receipt',
  expectedReasonCode: 'recognized',
  state,
});
assertEqual('accepted decision', 'accept', accepted.decision);
assertEqual('accepted reason', 'recognized', accepted.observed_reason_code);
assertEqual('accepted recognized', true, accepted.recognized);
assertEqual('accepted effect before', 0, accepted.effect_count_before);
assertEqual('accepted effect after', 1, accepted.effect_count_after);
assertEqual('accepted effect delta', 1, accepted.effect_count_delta);
assertEqual('accepted marker', true, accepted.accepted_once_marker);
assertEqual('state has one effect', 1, state.effects.length);
assertEqual('effect action class', 'records.write', state.effects[0].action_class);
assertEqual('effect type', 'protected-records-helper-effect-v1', state.effects[0].effect_type);
assertEqual('replay cache has one entry', 1, state.replayCache.size);

assertRefusal(
  'replay',
  decision({
    caseId: 'replay_refused',
    receipt: recognizedReceipt,
    receiptClass: 'recognized_receipt_replay',
    expectedReasonCode: 'receipt_replay',
    state,
  }),
  'receipt_replay',
  1
);
assertEqual('replay does not add second effect', 1, state.effects.length);

section('unsigned envelope rewrites cannot evade signed-payload replay identity');
const rewrittenIdReplay = decision({
  caseId: 'rewritten_envelope_id_replay_refused',
  receipt: { ...recognizedReceipt, id: `${'9'.repeat(12)}${'8'.repeat(32)}` },
  receiptClass: 'recognized_receipt_rewritten_envelope_id',
  expectedReasonCode: 'receipt_replay',
  state,
});
assertRefusal('rewritten envelope id replay', rewrittenIdReplay, 'receipt_replay', 1);
assert(
  'rewritten envelope id hash changes only display metadata',
  rewrittenIdReplay.receipt_id_hash !== accepted.receipt_id_hash
);

assertRefusal(
  'rewritten envelope iat replay',
  decision({
    caseId: 'rewritten_envelope_iat_replay_refused',
    receipt: { ...recognizedReceipt, iat: recognizedReceipt.iat + 3600 },
    receiptClass: 'recognized_receipt_rewritten_envelope_iat',
    expectedReasonCode: 'receipt_replay',
    state,
  }),
  'receipt_replay',
  1
);

assertRefusal(
  'rewritten envelope prev replay',
  decision({
    caseId: 'rewritten_envelope_prev_replay_refused',
    receipt: { ...recognizedReceipt, prev: 'rewritten-envelope-prev' },
    receiptClass: 'recognized_receipt_rewritten_envelope_prev',
    expectedReasonCode: 'receipt_replay',
    state,
  }),
  'receipt_replay',
  1
);

assertRefusal(
  'same-key kid alias replay',
  decision({
    caseId: 'same_key_kid_alias_replay_refused',
    receipt: { ...recognizedReceipt, kid: activeKidAlias },
    receiptClass: 'recognized_receipt_same_key_kid_alias',
    expectedReasonCode: 'receipt_replay',
    state,
  }),
  'receipt_replay',
  1
);
assertEqual('envelope rewrites do not add a second effect', 1, state.effects.length);
assertEqual('envelope rewrites do not create additional replay keys', 1, state.replayCache.size);

section('static helper import boundary');
const helperSource = readFileSync('lib/protected-records-boarding-decision.mjs', 'utf8');
const importLines = helperSource
  .split('\n')
  .filter((line) => line.startsWith('import '))
  .join('\n');
assert('helper imports canonicalizer', importLines.includes('./canonicalize.mjs'));
assert('helper imports downstream recognition', importLines.includes('./downstream-recognition-rule.mjs'));
assert('helper imports receipt hashing only', importLines.includes('./receipt.mjs'));
for (const forbidden of [
  'local-proof-pack',
  'proof-smoke',
  'product-proof',
  'Product Proof Path',
  'CURRENT-STATE',
  'ZLAR_Website',
  'release.json',
  'github',
  'GitHub',
  'remote',
  'execFileSync',
  'spawnSync',
  'rev-parse',
  'status --porcelain',
  'sourceState',
  '.zlar',
  '.claude',
  'formatProtectedRecordsLocalBoardingProofSummary',
  'assertProtectedRecordsLocalBoardingProof',
  'runProtectedRecordsLocalBoardingProof',
]) {
  assert(`helper does not reference ${forbidden}`, !helperSource.includes(forbidden));
}

console.log(`\nResults: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) {
  process.exit(1);
}
