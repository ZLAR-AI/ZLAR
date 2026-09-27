#!/usr/bin/env node
import assert from 'node:assert/strict';

import {
  CONFIGURED_RECOGNITION_VERIFIER_TYPE,
  DEFAULT_REQUIRED_NON_CLAIMS,
  assertConfiguredRecognitionAllowed,
  assertConfiguredRecognitionRefused,
  computeAttemptHash,
  computeConfiguredCredentialHash,
  computeRecognitionRuleHash,
  evaluateConfiguredRecognition,
  finalizeConfiguredRecognitionCredential,
  hashCanonical,
} from '../lib/zlar-configured-recognition-verifier.mjs';

const EVALUATED_AT = '2026-07-05T19:45:00Z';
const ISSUED_AT = '2026-07-05T19:44:30Z';
const EXPIRES_AT = '2026-07-05T19:46:00Z';
const GENESIS_HASH = '0'.repeat(64);
const TARGET_PAYLOAD = {
  object_ref: 'scratch://configured-recognition/target.json',
  value: 'recognized',
};
const TARGET_HASH = hashCanonical(TARGET_PAYLOAD);

let pass = 0;
let fail = 0;

function test(name, fn) {
  try {
    fn();
    pass++;
    console.log(`PASS ${name}`);
  } catch (error) {
    fail++;
    console.log(`FAIL ${name}`);
    console.log(error?.stack || error);
  }
}

function ruleFixture(overrides = {}) {
  const body = {
    rule_id: 'configured-recognition.fake-rule.v0',
    rule_version: '0.1.0',
    issuer_id: 'fake-independent-rule-issuer',
    issuer_trust_class: 'scratch-independent-rule',
    credential_envelope: 'zlar.fake.configured-recognition.v1',
    action_class: 'fake_downstream.write_marker',
    policy_id: 'fake-policy.configured-recognition.v1',
    target_ref: 'proof://configured-recognition/recognized-target',
    target_hash: TARGET_HASH,
    max_age_seconds: 120,
    max_ttl_seconds: 180,
    expected_previous_receipt_hash: GENESIS_HASH,
    required_non_claims: [...DEFAULT_REQUIRED_NON_CLAIMS],
    forbidden_claims: [
      'real_downstream_recognition',
      'real_downstream_refusal',
      'production_trust',
    ],
    ...overrides,
  };
  return {
    ...body,
    rule_source_hash: computeRecognitionRuleHash(body),
  };
}

function credentialFixture(overrides = {}) {
  return finalizeConfiguredRecognitionCredential({
    envelope: 'zlar.fake.configured-recognition.v1',
    status: 'active',
    issuer_id: 'fake-independent-rule-issuer',
    issuer_trust_class: 'scratch-independent-rule',
    action_class: 'fake_downstream.write_marker',
    target_ref: 'proof://configured-recognition/recognized-target',
    target_hash: TARGET_HASH,
    decision: 'allow',
    policy_id: 'fake-policy.configured-recognition.v1',
    issued_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    sequence: 1,
    previous_receipt_hash: GENESIS_HASH,
    nonce: 'nonce-001',
    proof_scope: 'scratch-only',
    non_claims: [...DEFAULT_REQUIRED_NON_CLAIMS],
    claims: ['scratch_fake_configured_recognition_only'],
    ...overrides,
  });
}

function attemptFixture(overrides = {}) {
  return {
    action_class: 'fake_downstream.write_marker',
    target_ref: 'proof://configured-recognition/recognized-target',
    payload: TARGET_PAYLOAD,
    consequence_class: 'scratch_fake_effect_marker',
    request_id: 'attempt-001',
    ...overrides,
  };
}

function decisionFor({
  rule = ruleFixture(),
  credential = credentialFixture(),
  attempt = attemptFixture(),
  replay_state = undefined,
  evaluated_at = EVALUATED_AT,
  clock_source = 'fixture-clock',
} = {}) {
  return evaluateConfiguredRecognition({
    rule,
    credential,
    attempt,
    replay_state,
    evaluated_at,
    clock_source,
  });
}

function refused(name, expectedCode, overrides) {
  test(name, () => {
    const decision = decisionFor(overrides);
    assertConfiguredRecognitionRefused(decision, expectedCode);
    assert.equal(decision.evidence.replay_state_changed, false);
  });
}

test('accepts one in-scope configured fake credential', () => {
  const credential = credentialFixture();
  const attempt = attemptFixture();
  const rule = ruleFixture();
  const decision = decisionFor({ rule, credential, attempt });
  assertConfiguredRecognitionAllowed(decision);
  assert.equal(decision.result_type, CONFIGURED_RECOGNITION_VERIFIER_TYPE);
  assert.equal(decision.reason_code, 'recognized');
  assert.equal(decision.evidence.rule_source_hash, decision.evidence.rule_hash);
  assert.equal(decision.evidence.credential_hash, credential.credential_hash);
  assert.equal(decision.evidence.attempt_hash, computeAttemptHash(attempt));
  assert.equal(decision.evidence.replay_state_changed, true);
  assert.deepEqual(decision.next_replay_state.used_credential_ids, [credential.credential_id]);
  assert.deepEqual(decision.next_replay_state.used_credential_hashes, [credential.credential_hash]);
  assert.deepEqual(decision.next_replay_state.used_nonces, [credential.nonce]);
  assert.equal(
    decision.next_replay_state.last_receipt_hash_by_issuer[credential.issuer_id],
    credential.receipt_hash,
  );
});

refused('missing rule refuses', 'rule_not_object', { rule: null });
refused('missing credential refuses', 'credential_not_object', { credential: null });
refused('malformed credential refuses', 'credential_not_object', { credential: 'not-json' });
refused('missing attempt refuses', 'attempt_not_object', { attempt: null });

test('top-level null input returns bounded refusal', () => {
  const decision = evaluateConfiguredRecognition(null);
  assertConfiguredRecognitionRefused(decision, 'rule_not_object');
});

refused('rule source hash mismatch refuses', 'rule_source_hash_mismatch', {
  rule: { ...ruleFixture(), rule_source_hash: 'f'.repeat(64) },
});

refused('extra malformed rule hash-labeled field refuses', 'rule_hash_field_invalid', {
  rule: ruleFixture({ extra_hash: 'not-a-sha256' }),
});

refused('extra null rule hash-labeled field refuses', 'rule_hash_field_invalid', {
  rule: ruleFixture({ extra_hash: null }),
});

refused('rule operational field cannot carry forbidden marker', 'rule_forbidden_claim_present', {
  rule: ruleFixture({ rule_id: 'real_receipt' }),
});

refused('rule operational value cannot hide forbidden marker with underscores', 'rule_forbidden_claim_present', {
  rule: ruleFixture({ metadata: { hidden_production_trust_marker: true } }),
});

refused('rule required non-claims must be strings', 'rule_array_field_invalid', {
  rule: ruleFixture({ required_non_claims: [...DEFAULT_REQUIRED_NON_CLAIMS, { nested: 'production_trust' }] }),
});

refused('rule forbidden claims must be strings', 'rule_array_field_invalid', {
  rule: ruleFixture({ forbidden_claims: ['production_trust', { nested: 'real_receipt' }] }),
});

refused('credential hash mismatch refuses', 'credential_hash_mismatch', {
  credential: { ...credentialFixture(), credential_hash: 'e'.repeat(64) },
});

refused('extra malformed credential hash-labeled field refuses', 'credential_hash_field_invalid', {
  credential: credentialFixture({ extra_hash: 'not-a-sha256' }),
});

refused('extra null credential hash-labeled field refuses', 'credential_hash_field_invalid', {
  credential: credentialFixture({ extra_hash: null }),
});

refused('receipt hash mismatch refuses', 'credential_hash_mismatch', {
  credential: { ...credentialFixture(), receipt_hash: 'd'.repeat(64) },
});

refused('credential id mismatch refuses', 'credential_id_mismatch', {
  credential: { ...credentialFixture(), credential_id: 'fake-credential:wrong' },
});

refused('credential id replay refuses', 'credential_id_replayed', {
  replay_state: {
    used_credential_ids: [credentialFixture().credential_id],
  },
});

refused('credential hash replay refuses', 'credential_hash_replayed', {
  replay_state: {
    used_credential_hashes: [credentialFixture().credential_hash],
  },
});

refused('nonce replay refuses', 'nonce_replayed', {
  credential: credentialFixture({
    sequence: 2,
    nonce: 'nonce-001',
    previous_receipt_hash: credentialFixture().receipt_hash,
  }),
  replay_state: {
    used_nonces: ['nonce-001'],
  },
});

refused('wrong envelope refuses', 'envelope_mismatch', {
  credential: credentialFixture({ envelope: 'other-envelope' }),
});

refused('inactive status refuses', 'status_not_active', {
  credential: credentialFixture({ status: 'revoked' }),
});

refused('wrong issuer refuses', 'issuer_mismatch', {
  credential: credentialFixture({ issuer_id: 'other-issuer' }),
});

refused('wrong issuer trust class refuses', 'issuer_trust_class_mismatch', {
  credential: credentialFixture({ issuer_trust_class: 'producer-owned-fixture' }),
});

refused('wrong policy refuses', 'policy_mismatch', {
  credential: credentialFixture({ policy_id: 'other-policy' }),
});

refused('decision not allow refuses', 'decision_not_allow', {
  credential: credentialFixture({ decision: 'deny' }),
});

refused('expired credential refuses', 'credential_expired', {
  credential: credentialFixture({ expires_at: '2026-07-05T19:44:59Z' }),
});

refused('future-issued credential refuses', 'issued_in_future', {
  credential: credentialFixture({
    issued_at: '2026-07-05T19:45:30Z',
    expires_at: '2026-07-05T19:46:30Z',
  }),
});

refused('credential outside freshness window refuses', 'credential_too_old', {
  rule: ruleFixture({ max_age_seconds: 30, max_ttl_seconds: 500 }),
  credential: credentialFixture({
    issued_at: '2026-07-05T19:43:00Z',
    expires_at: '2026-07-05T19:46:00Z',
  }),
});

refused('malformed max age refuses as rule error', 'rule_numeric_field_invalid', {
  rule: ruleFixture({ max_age_seconds: '30' }),
});

refused('float max age refuses as rule error', 'rule_numeric_field_invalid', {
  rule: { ...ruleFixture(), max_age_seconds: 1.5 },
});

refused('null max age refuses as rule error', 'rule_numeric_field_invalid', {
  rule: ruleFixture({ max_age_seconds: null }),
});

refused('empty max age refuses as rule error', 'rule_numeric_field_invalid', {
  rule: ruleFixture({ max_age_seconds: '' }),
});

refused('negative max age refuses as rule error', 'rule_numeric_field_invalid', {
  rule: ruleFixture({ max_age_seconds: -1 }),
});

refused('credential ttl too long refuses', 'ttl_too_long', {
  credential: credentialFixture({
    issued_at: '2026-07-05T19:44:00Z',
    expires_at: '2026-07-05T19:50:00Z',
  }),
});

refused('malformed max ttl refuses as rule error', 'rule_numeric_field_invalid', {
  rule: ruleFixture({ max_ttl_seconds: '180' }),
});

refused('float max ttl refuses as rule error', 'rule_numeric_field_invalid', {
  rule: { ...ruleFixture(), max_ttl_seconds: 1.5 },
});

refused('null max ttl refuses as rule error', 'rule_numeric_field_invalid', {
  rule: ruleFixture({ max_ttl_seconds: null }),
});

refused('empty max ttl refuses as rule error', 'rule_numeric_field_invalid', {
  rule: ruleFixture({ max_ttl_seconds: '' }),
});

refused('negative max ttl refuses as rule error', 'rule_numeric_field_invalid', {
  rule: ruleFixture({ max_ttl_seconds: -1 }),
});

refused('backward sequence refuses', 'sequence_not_forward', {
  credential: credentialFixture({ sequence: 4 }),
  replay_state: {
    last_sequence_by_issuer: {
      'fake-independent-rule-issuer': 5,
    },
  },
});

refused('malformed replay sequence refuses as replay error', 'replay_state_numeric_field_invalid', {
  credential: credentialFixture({ sequence: 4 }),
  replay_state: {
    last_sequence_by_issuer: {
      'fake-independent-rule-issuer': '5',
    },
  },
});

refused('float replay sequence cursor refuses as replay error', 'replay_state_numeric_field_invalid', {
  credential: credentialFixture({ sequence: 4 }),
  replay_state: {
    last_sequence_by_issuer: {
      'fake-independent-rule-issuer': 1.5,
    },
  },
});

refused('unsafe replay sequence cursor refuses as replay error', 'replay_state_numeric_field_invalid', {
  credential: credentialFixture({ sequence: 4 }),
  replay_state: {
    last_sequence_by_issuer: {
      other: 9007199254740992,
    },
  },
});

refused('malformed replay sequence map refuses as replay error', 'replay_state_cursor_field_invalid', {
  credential: credentialFixture({ sequence: 4 }),
  replay_state: {
    last_sequence_by_issuer: [],
  },
});

refused('non-ascii replay sequence cursor key refuses as replay error', 'replay_state_cursor_field_invalid', {
  replay_state: {
    last_sequence_by_issuer: {
      'issuér': 1,
    },
  },
});

refused('empty replay sequence cursor key refuses as replay error', 'replay_state_cursor_field_invalid', {
  replay_state: {
    last_sequence_by_issuer: {
      '': 1,
    },
  },
});

refused('null replay sequence cursor refuses as replay error', 'replay_state_numeric_field_invalid', {
  credential: credentialFixture({ sequence: 4 }),
  replay_state: {
    last_sequence_by_issuer: {
      'fake-independent-rule-issuer': null,
    },
  },
});

refused('empty replay sequence cursor refuses as replay error', 'replay_state_numeric_field_invalid', {
  credential: credentialFixture({ sequence: 4 }),
  replay_state: {
    last_sequence_by_issuer: {
      'fake-independent-rule-issuer': '',
    },
  },
});

refused('malformed replay receipt map refuses as replay error', 'replay_state_cursor_field_invalid', {
  replay_state: {
    last_receipt_hash_by_issuer: [],
  },
});

refused('null replay receipt cursor refuses as replay error', 'replay_state_cursor_field_invalid', {
  replay_state: {
    last_receipt_hash_by_issuer: {
      'fake-independent-rule-issuer': null,
    },
  },
});

refused('empty replay receipt cursor refuses as replay error', 'replay_state_cursor_field_invalid', {
  replay_state: {
    last_receipt_hash_by_issuer: {
      'fake-independent-rule-issuer': '',
    },
  },
});

refused('malformed replay receipt hash cursor refuses before recognition', 'credential_hash_field_invalid', {
  credential: credentialFixture({
    sequence: 2,
    previous_receipt_hash: 'not-a-hash',
  }),
  replay_state: {
    last_sequence_by_issuer: {
      'fake-independent-rule-issuer': 1,
    },
    last_receipt_hash_by_issuer: {
      'fake-independent-rule-issuer': 'not-a-hash',
    },
  },
});

refused('non-ascii replay receipt cursor key refuses as replay error', 'replay_state_cursor_field_invalid', {
  replay_state: {
    last_receipt_hash_by_issuer: {
      'issuér': '2'.repeat(64),
    },
  },
});

refused('empty replay receipt cursor key refuses as replay error', 'replay_state_cursor_field_invalid', {
  replay_state: {
    last_receipt_hash_by_issuer: {
      '': '2'.repeat(64),
    },
  },
});

refused('negative replay sequence cursor refuses as replay error', 'replay_state_numeric_field_invalid', {
  credential: credentialFixture({ sequence: 4 }),
  replay_state: {
    last_sequence_by_issuer: {
      'fake-independent-rule-issuer': -1,
    },
  },
});

refused('boolean sequence refuses as malformed', 'sequence_invalid', {
  credential: credentialFixture({ sequence: true }),
});

refused('numeric-string sequence refuses as malformed', 'sequence_invalid', {
  credential: credentialFixture({ sequence: '2' }),
});

refused('negative sequence refuses as malformed', 'sequence_invalid', {
  credential: credentialFixture({ sequence: -1 }),
});

refused('float credential field returns bounded canonical refusal', 'credential_canonical_shape_invalid', {
  credential: { ...credentialFixture(), sequence: 1.5 },
});

refused('malformed credential previous receipt hash refuses', 'credential_hash_field_invalid', {
  credential: credentialFixture({ previous_receipt_hash: 'not-a-sha256' }),
});

refused('previous hash mismatch refuses', 'previous_hash_mismatch', {
  credential: credentialFixture({ sequence: 2, previous_receipt_hash: GENESIS_HASH }),
  replay_state: {
    last_sequence_by_issuer: {
      'fake-independent-rule-issuer': 1,
    },
    last_receipt_hash_by_issuer: {
      'fake-independent-rule-issuer': '1'.repeat(64),
    },
  },
});

refused('malformed rule expected previous hash refuses', 'rule_hash_field_invalid', {
  rule: ruleFixture({ expected_previous_receipt_hash: 'not-a-sha256' }),
  credential: credentialFixture({
    sequence: 2,
    previous_receipt_hash: 'not-a-sha256',
  }),
});

refused('out-of-scope credential action refuses', 'action_class_mismatch', {
  credential: credentialFixture({ action_class: 'fake_downstream.delete_marker' }),
});

refused('out-of-scope attempted action refuses', 'action_class_mismatch', {
  attempt: attemptFixture({ action_class: 'fake_downstream.delete_marker' }),
});

refused('exact target ref mismatch refuses', 'target_ref_mismatch', {
  credential: credentialFixture({ target_ref: 'proof://configured-recognition/other-target' }),
});

refused('attempt target ref mismatch refuses', 'target_ref_mismatch', {
  attempt: attemptFixture({ target_ref: 'proof://configured-recognition/other-target' }),
});

refused('target hash mismatch refuses', 'target_hash_mismatch', {
  credential: credentialFixture({ target_hash: hashCanonical({ value: 'other' }) }),
});

refused('malformed configured target hash refuses', 'rule_hash_field_invalid', {
  rule: ruleFixture({ target_hash: 'not-a-sha256' }),
  credential: credentialFixture({ target_hash: 'not-a-sha256' }),
  attempt: attemptFixture({ payload_hash: 'not-a-sha256' }),
});

refused('wrong payload with self-consistent credential refuses', 'target_hash_mismatch', {
  attempt: attemptFixture({ payload: { object_ref: 'scratch://configured-recognition/target.json', value: 'forged' } }),
});

refused('malformed attempt shape refuses before allow', 'attempt_canonical_shape_invalid', {
  attempt: attemptFixture({ extra_float: 1.5 }),
});

refused('extra malformed attempt hash-labeled field refuses', 'attempt_hash_field_invalid', {
  attempt: attemptFixture({ extra_hash: 'not-a-sha256' }),
});

refused('extra null attempt hash-labeled field refuses', 'attempt_hash_field_invalid', {
  attempt: attemptFixture({ extra_hash: null }),
});

refused('attempt without payload hash or payload refuses', 'attempt_payload_hash_missing', {
  attempt: {
    action_class: 'fake_downstream.write_marker',
    target_ref: 'proof://configured-recognition/recognized-target',
    consequence_class: 'scratch_fake_effect_marker',
    request_id: 'attempt-001',
  },
});

test('absolute local target ref refuses without leaking path', () => {
  const privatePath = '/operator-private/example.txt';
  const rule = ruleFixture({ target_ref: privatePath });
  const credential = credentialFixture({ target_ref: privatePath });
  const attempt = attemptFixture({ target_ref: privatePath });
  const decision = decisionFor({ rule, credential, attempt });
  assertConfiguredRecognitionRefused(decision, 'absolute_target_ref_refused');
  assert.equal(JSON.stringify(decision).includes(privatePath), false);
  assert.equal(decision.evidence.target_ref_redacted, true);
});

refused('production claim refuses', 'forbidden_claim_present', {
  credential: credentialFixture({ production_claim: true }),
});

refused('production trust hidden in proof scope substring refuses', 'forbidden_claim_present', {
  credential: credentialFixture({ proof_scope: 'scratch-only production_trust marker' }),
});

refused('production trust hidden in object key refuses', 'forbidden_claim_present', {
  credential: credentialFixture({ metadata: { production_trust: true } }),
});

refused('production trust hidden with underscore marker refuses', 'forbidden_claim_present', {
  credential: credentialFixture({ metadata: { has_production_trust: true } }),
});

refused('production trust hidden in nested credential non-claims refuses', 'forbidden_claim_present', {
  credential: credentialFixture({ metadata: { non_claims: ['production_trust'] } }),
});

refused('non-string credential non-claims refuse', 'credential_array_field_invalid', {
  credential: credentialFixture({ non_claims: [...DEFAULT_REQUIRED_NON_CLAIMS, { nested: 'production_trust' }] }),
});

refused('extra production marker inside non-claims refuses', 'unrecognized_non_claim_present', {
  credential: credentialFixture({
    non_claims: [...DEFAULT_REQUIRED_NON_CLAIMS, 'production_trust'],
  }),
});

refused('rule cannot require forbidden marker as non-claim', 'rule_required_non_claim_forbidden', {
  rule: ruleFixture({
    required_non_claims: [...DEFAULT_REQUIRED_NON_CLAIMS, 'production_trust'],
  }),
  credential: credentialFixture({
    non_claims: [...DEFAULT_REQUIRED_NON_CLAIMS, 'production_trust'],
  }),
});

refused('rule nested non-claims cannot carry forbidden marker', 'rule_forbidden_claim_present', {
  rule: ruleFixture({
    metadata: { non_claims: ['production_trust'] },
  }),
});

refused('explicit forbidden claim refuses', 'forbidden_claim_present', {
  credential: credentialFixture({ claims: ['scratch_fake_configured_recognition_only', 'real_downstream_recognition'] }),
});

refused('missing required non-claim refuses', 'required_non_claim_missing', {
  credential: credentialFixture({ non_claims: DEFAULT_REQUIRED_NON_CLAIMS.filter((item) => item !== 'not_governance') }),
});

test('refusal does not mutate replay state object', () => {
  const replayState = {
    used_credential_ids: [],
    used_credential_hashes: [],
    used_nonces: [],
  };
  const beforeHash = hashCanonical(replayState);
  const decision = decisionFor({
    credential: credentialFixture({ decision: 'deny' }),
    replay_state: replayState,
  });
  assertConfiguredRecognitionRefused(decision, 'decision_not_allow');
  assert.equal(hashCanonical(replayState), beforeHash);
  assert.equal(decision.evidence.replay_state_changed, false);
});

test('absolute local path in credential id is redacted on refusal', () => {
  const privatePath = '/operator-private/id';
  const decision = decisionFor({
    credential: {
      ...credentialFixture({ decision: 'deny' }),
      credential_id: privatePath,
    },
  });
  assertConfiguredRecognitionRefused(decision, 'credential_id_mismatch');
  const decisionJson = JSON.stringify(decision);
  assert.equal(decisionJson.includes(privatePath), false);
  assert.match(decision.evidence.credential_id, /^redacted-evidence-string:/);
});

test('absolute local path in replay-state key is redacted everywhere', () => {
  const privatePath = '/operator-private/replay-key';
  const decision = decisionFor({
    replay_state: {
      last_sequence_by_issuer: {
        [privatePath]: 99,
      },
      last_receipt_hash_by_issuer: {
        [privatePath]: '2'.repeat(64),
      },
    },
  });
  assertConfiguredRecognitionAllowed(decision);
  assert.equal(JSON.stringify(decision).includes(privatePath), false);
});

test('computed credential hash ignores only identity fields', () => {
  const credential = credentialFixture();
  const recomputed = computeConfiguredCredentialHash({
    ...credential,
    credential_hash: 'changed',
    credential_id: 'changed',
    receipt_hash: 'changed',
    receipt_id: 'changed',
  });
  assert.equal(recomputed, credential.credential_hash);
  const changedBody = computeConfiguredCredentialHash({ ...credential, policy_id: 'changed' });
  assert.notEqual(changedBody, credential.credential_hash);
});

test('allow decision has no null emitted hashes', () => {
  const decision = decisionFor();
  assertConfiguredRecognitionAllowed(decision);
  for (const key of [
    'rule_hash',
    'credential_hash',
    'presented_credential_hash',
    'attempt_hash',
    'target_hash',
    'replay_state_before_hash',
    'replay_state_after_hash',
  ]) {
    assert.notEqual(decision.evidence[key], null, `${key} must not be null on allow`);
  }
});

console.log(`\nResults: ${pass}/${pass + fail} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
console.log('ALL PASS');
