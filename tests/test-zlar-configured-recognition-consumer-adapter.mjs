#!/usr/bin/env node
import assert from 'node:assert/strict';

import {
  FAKE_LOCAL_CONSUMER_EFFECT_OBSERVATION_TYPE,
  FAKE_LOCAL_CONSUMER_EFFECT_SCOPE,
  FAKE_LOCAL_CONSUMER_EFFECT_REF_PREFIX,
  FAKE_LOCAL_CONSUMER_EFFECT_TYPE,
  FAKE_LOCAL_CONSUMER_MARKER_TYPE,
  assertConfiguredRecognitionConsumerEffectWritten,
  assertConfiguredRecognitionConsumerRefused,
  runConfiguredRecognitionConsumer,
} from '../lib/zlar-configured-recognition-consumer-adapter.mjs';
import {
  DEFAULT_FORBIDDEN_CLAIMS,
  DEFAULT_REQUIRED_NON_CLAIMS,
  computeRecognitionRuleHash,
  evaluateConfiguredRecognition,
  finalizeConfiguredRecognitionCredential,
  hashCanonical,
} from '../lib/zlar-configured-recognition-verifier.mjs';

const EVALUATED_AT = '2026-07-05T21:40:00Z';
const ISSUED_AT = '2026-07-05T21:39:30Z';
const EXPIRES_AT = '2026-07-05T21:41:00Z';
const GENESIS_HASH = '0'.repeat(64);
const TARGET_PAYLOAD = {
  object_ref: 'scratch://configured-consumer-adapter/target.json',
  value: 'consumer-adapter',
};
const TARGET_HASH = hashCanonical(TARGET_PAYLOAD);

let pass = 0;
let fail = 0;

async function test(name, fn) {
  try {
    await fn();
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
    rule_id: 'configured-recognition.consumer-adapter-rule.v0',
    rule_version: '0.1.0',
    issuer_id: 'fake-consumer-adapter-issuer',
    issuer_trust_class: 'scratch-configured-rule',
    credential_envelope: 'zlar.fake.configured-recognition.v1',
    action_class: 'fake_downstream.write_marker',
    policy_id: 'fake-policy.consumer-adapter.v1',
    target_ref: 'proof://consumer-adapter/recognized-target',
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
    issuer_id: 'fake-consumer-adapter-issuer',
    issuer_trust_class: 'scratch-configured-rule',
    action_class: 'fake_downstream.write_marker',
    target_ref: 'proof://consumer-adapter/recognized-target',
    target_hash: TARGET_HASH,
    decision: 'allow',
    policy_id: 'fake-policy.consumer-adapter.v1',
    issued_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    sequence: 1,
    previous_receipt_hash: GENESIS_HASH,
    nonce: 'consumer-adapter-nonce-001',
    proof_scope: 'scratch-only',
    non_claims: [...DEFAULT_REQUIRED_NON_CLAIMS],
    claims: ['scratch_fake_configured_recognition_only'],
    ...overrides,
  });
}

function attemptFixture(overrides = {}) {
  return {
    action_class: 'fake_downstream.write_marker',
    target_ref: 'proof://consumer-adapter/recognized-target',
    payload: TARGET_PAYLOAD,
    consequence_class: 'scratch_fake_effect_marker',
    request_id: 'consumer-adapter-attempt-001',
    ...overrides,
  };
}

async function consumerResult({
  rule = ruleFixture(),
  credential = credentialFixture(),
  attempt = attemptFixture(),
  replay_state = undefined,
  effect_callback = undefined,
  effect_observer = validEffectObserver,
  evaluate = undefined,
} = {}) {
  return runConfiguredRecognitionConsumer({
    rule,
    credential,
    attempt,
    replay_state,
    evaluated_at: EVALUATED_AT,
    clock_source: 'fixture-clock',
    effect_callback,
    effect_observer,
    evaluate,
  });
}

function assertNoPrivatePath(value) {
  const text = JSON.stringify(value);
  assert.equal(text.includes('/Users/example'), false);
  assert.equal(text.includes('/Volumes/'), false);
}

function validEffectAttestation({ decision_hash, next_replay_state }, overrides = {}) {
  return {
    effect_written: true,
    effect_type: FAKE_LOCAL_CONSUMER_EFFECT_TYPE,
    effect_ref: `${FAKE_LOCAL_CONSUMER_EFFECT_REF_PREFIX}${decision_hash}`,
    decision_hash,
    next_replay_state_hash: hashCanonical(next_replay_state),
    effect_scope: FAKE_LOCAL_CONSUMER_EFFECT_SCOPE,
    transactional_truth: false,
    real_downstream: false,
    ...overrides,
  };
}

function validEffectObservation({ decision_hash, effect_result }, overrides = {}) {
  const effectResultHash = hashCanonical(effect_result);
  return {
    effect_observed: true,
    observation_type: FAKE_LOCAL_CONSUMER_EFFECT_OBSERVATION_TYPE,
    effect_ref: effect_result.effect_ref,
    decision_hash,
    effect_result_hash: effectResultHash,
    observed_effect: {
      marker_type: FAKE_LOCAL_CONSUMER_MARKER_TYPE,
      effect_ref: effect_result.effect_ref,
      decision_hash,
      effect_result_hash: effectResultHash,
      effect_scope: FAKE_LOCAL_CONSUMER_EFFECT_SCOPE,
      transactional_truth: false,
      real_downstream: false,
    },
    effect_scope: FAKE_LOCAL_CONSUMER_EFFECT_SCOPE,
    transactional_truth: false,
    real_downstream: false,
    ...overrides,
  };
}

async function validEffectObserver(effectInput) {
  return validEffectObservation(effectInput);
}

function replayAfterForCredential(replayBefore, credential) {
  const replayAfter = JSON.parse(JSON.stringify(replayBefore));
  for (const [field, value] of [
    ['used_credential_hashes', credential.credential_hash],
    ['used_credential_ids', credential.credential_id],
    ['used_nonces', credential.nonce],
  ]) {
    if (!replayAfter[field].includes(value)) replayAfter[field].push(value);
  }
  replayAfter.last_sequence_by_issuer[credential.issuer_id] = credential.sequence;
  replayAfter.last_receipt_hash_by_issuer[credential.issuer_id] = credential.receipt_hash;
  return replayAfter;
}

await test('allow calls effect callback exactly once', async () => {
  let calls = 0;
  const result = await consumerResult({
    effect_callback: async (effectInput) => {
      calls += 1;
      assert.equal(typeof effectInput.decision_hash, 'string');
      assert.equal(Array.isArray(effectInput.next_replay_state.used_credential_ids), true);
      return validEffectAttestation(effectInput);
    },
  });
  assert.equal(calls, 1);
  assertConfiguredRecognitionConsumerEffectWritten(result);
  assert.equal(result.reason_code, 'effect_written_after_configured_recognition_allow');
  assert.equal(result.effect_result.effect_ref, `${FAKE_LOCAL_CONSUMER_EFFECT_REF_PREFIX}${result.verifier_decision_hash}`);
  assert.equal(result.effect_observation.effect_ref, result.effect_result.effect_ref);
  assert.equal(result.effect_observation.effect_result_hash, result.effect_result_hash);
  assert.equal(result.evidence.verifier_allowed, true);
  assert.equal(result.evidence.replay_state_changed, true);
});

await test('replay refusal does not call effect callback', async () => {
  let calls = 0;
  const credential = credentialFixture();
  const result = await consumerResult({
    credential,
    replay_state: {
      used_credential_hashes: [],
      used_credential_ids: [credential.credential_id],
      used_nonces: [],
      last_sequence_by_issuer: {},
      last_receipt_hash_by_issuer: {},
    },
    effect_callback: async () => {
      calls += 1;
    },
  });
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'credential_id_replayed');
});

await test('missing credential refusal does not call effect callback', async () => {
  let calls = 0;
  const result = await consumerResult({
    credential: null,
    effect_callback: async () => {
      calls += 1;
    },
  });
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'credential_not_object');
});

await test('wrong payload refusal does not call effect callback', async () => {
  let calls = 0;
  const result = await consumerResult({
    credential: credentialFixture({
      sequence: 2,
      nonce: 'consumer-adapter-nonce-wrong-payload',
    }),
    attempt: attemptFixture({
      request_id: 'consumer-adapter-attempt-wrong-payload',
      payload: {
        object_ref: 'scratch://configured-consumer-adapter/target.json',
        value: 'wrong',
      },
    }),
    effect_callback: async () => {
      calls += 1;
    },
  });
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'target_hash_mismatch');
});

await test('unknown issuer refusal does not call effect callback', async () => {
  let calls = 0;
  const result = await consumerResult({
    credential: credentialFixture({
      issuer_id: 'unknown-fake-issuer',
      sequence: 2,
      nonce: 'consumer-adapter-nonce-unknown-issuer',
    }),
    effect_callback: async () => {
      calls += 1;
    },
  });
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'issuer_mismatch');
});

await test('forbidden production claim refusal does not call effect callback', async () => {
  let calls = 0;
  const result = await consumerResult({
    credential: credentialFixture({
      sequence: 2,
      nonce: 'consumer-adapter-nonce-production-claim',
      claims: ['production_trust'],
    }),
    effect_callback: async () => {
      calls += 1;
    },
  });
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'forbidden_claim_present');
});

await test('malformed verifier response fails closed', async () => {
  let calls = 0;
  const result = await consumerResult({
    evaluate: async () => ({ decision: 'allow', configured_recognition: 'true' }),
    effect_callback: async () => {
      calls += 1;
    },
  });
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'verifier_result_not_allow');
});

await test('forged two-field allow verifier result fails closed', async () => {
  let calls = 0;
  const result = await consumerResult({
    evaluate: async () => ({ decision: 'allow', configured_recognition: true }),
    effect_callback: async () => {
      calls += 1;
    },
  });
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'verifier_result_type_invalid');
});

await test('forged allow verifier result missing forbidden claims fails closed', async () => {
  let calls = 0;
  const verifierDecision = evaluateConfiguredRecognition({
    rule: ruleFixture(),
    credential: credentialFixture(),
    attempt: attemptFixture(),
    replay_state: {},
    evaluated_at: EVALUATED_AT,
    clock_source: 'fixture-clock',
  });
  const result = await consumerResult({
    evaluate: async () => ({ ...verifierDecision, forbidden_claims: [] }),
    effect_callback: async () => {
      calls += 1;
    },
  });
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'verifier_forbidden_claim_missing');
});

await test('stale full-shaped allow decision is bound to current replay state', async () => {
  let calls = 0;
  const verifierDecision = evaluateConfiguredRecognition({
    rule: ruleFixture(),
    credential: credentialFixture(),
    attempt: attemptFixture(),
    replay_state: {},
    evaluated_at: EVALUATED_AT,
    clock_source: 'fixture-clock',
  });
  const result = await consumerResult({
    replay_state: verifierDecision.next_replay_state,
    evaluate: async () => verifierDecision,
    effect_callback: async () => {
      calls += 1;
      return { effect_written: true };
    },
  });
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'credential_id_replayed');
});

await test('full-shaped allow decision is bound to current credential input', async () => {
  let calls = 0;
  const verifierDecision = evaluateConfiguredRecognition({
    rule: ruleFixture(),
    credential: credentialFixture(),
    attempt: attemptFixture(),
    replay_state: {},
    evaluated_at: EVALUATED_AT,
    clock_source: 'fixture-clock',
  });
  const result = await consumerResult({
    credential: credentialFixture({ nonce: 'different-current-input' }),
    evaluate: async () => verifierDecision,
    effect_callback: async () => {
      calls += 1;
      return { effect_written: true };
    },
  });
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'verifier_credential_hash_mismatch');
});

await test('full-shaped allow with non-consuming replay after fails closed', async () => {
  let calls = 0;
  const verifierDecision = evaluateConfiguredRecognition({
    rule: ruleFixture(),
    credential: credentialFixture(),
    attempt: attemptFixture(),
    replay_state: {},
    evaluated_at: EVALUATED_AT,
    clock_source: 'fixture-clock',
  });
  const nonConsumingReplay = {
    used_credential_hashes: [],
    used_credential_ids: [],
    used_nonces: [],
    last_sequence_by_issuer: {},
    last_receipt_hash_by_issuer: {},
  };
  const forgedDecision = {
    ...verifierDecision,
    evidence: {
      ...verifierDecision.evidence,
      replay_state_after_hash: hashCanonical(nonConsumingReplay),
      replay_state_changed: true,
    },
    next_replay_state: nonConsumingReplay,
  };
  const result = await consumerResult({
    evaluate: async () => forgedDecision,
    effect_callback: async () => {
      calls += 1;
      return { effect_written: true };
    },
  });
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'verifier_replay_after_state_mismatch');
});

await test('full-shaped allow with already-consumed replay state fails closed', async () => {
  let calls = 0;
  const credential = credentialFixture();
  const consumedReplay = {
    used_credential_hashes: [credential.credential_hash],
    used_credential_ids: [credential.credential_id],
    used_nonces: [credential.nonce],
    last_sequence_by_issuer: {
      [credential.issuer_id]: credential.sequence,
    },
    last_receipt_hash_by_issuer: {
      [credential.issuer_id]: credential.receipt_hash,
    },
  };
  const verifierDecision = evaluateConfiguredRecognition({
    rule: ruleFixture(),
    credential,
    attempt: attemptFixture(),
    replay_state: {},
    evaluated_at: EVALUATED_AT,
    clock_source: 'fixture-clock',
  });
  const forgedDecision = {
    ...verifierDecision,
    evidence: {
      ...verifierDecision.evidence,
      replay_state_before_hash: hashCanonical(consumedReplay),
      replay_state_after_hash: hashCanonical(consumedReplay),
      replay_state_changed: true,
    },
    next_replay_state: consumedReplay,
  };
  const result = await consumerResult({
    credential,
    replay_state: consumedReplay,
    evaluate: async () => forgedDecision,
    effect_callback: async () => {
      calls += 1;
      return { effect_written: true };
    },
  });
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'credential_id_replayed');
});

await test('partial replay-before forged allow is refused by local verifier semantics', async () => {
  let calls = 0;
  let evaluatorCalls = 0;
  const credential = credentialFixture();
  const partialReplay = {
    used_credential_hashes: [],
    used_credential_ids: [credential.credential_id],
    used_nonces: [],
    last_sequence_by_issuer: {},
    last_receipt_hash_by_issuer: {},
  };
  const replayAfter = replayAfterForCredential(partialReplay, credential);
  const verifierDecision = evaluateConfiguredRecognition({
    rule: ruleFixture(),
    credential,
    attempt: attemptFixture(),
    replay_state: {},
    evaluated_at: EVALUATED_AT,
    clock_source: 'fixture-clock',
  });
  const forgedDecision = {
    ...verifierDecision,
    evidence: {
      ...verifierDecision.evidence,
      replay_state_before_hash: hashCanonical(partialReplay),
      replay_state_after_hash: hashCanonical(replayAfter),
      replay_state_changed: true,
    },
    next_replay_state: replayAfter,
  };
  const result = await consumerResult({
    credential,
    replay_state: partialReplay,
    evaluate: async () => {
      evaluatorCalls += 1;
      return forgedDecision;
    },
    effect_callback: async () => {
      calls += 1;
      return { effect_written: true };
    },
  });
  assert.equal(evaluatorCalls, 0);
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'credential_id_replayed');
});

await test('semantic mismatch forged allow is refused by local verifier semantics', async () => {
  let calls = 0;
  let evaluatorCalls = 0;
  const credential = credentialFixture({
    issuer_id: 'unknown-fake-issuer',
    sequence: 2,
    nonce: 'consumer-adapter-nonce-issuer-forgery',
  });
  const emptyReplay = {
    used_credential_hashes: [],
    used_credential_ids: [],
    used_nonces: [],
    last_sequence_by_issuer: {},
    last_receipt_hash_by_issuer: {},
  };
  const replayAfter = replayAfterForCredential(emptyReplay, credential);
  const verifierDecision = evaluateConfiguredRecognition({
    rule: ruleFixture(),
    credential: credentialFixture(),
    attempt: attemptFixture(),
    replay_state: {},
    evaluated_at: EVALUATED_AT,
    clock_source: 'fixture-clock',
  });
  const forgedDecision = {
    ...verifierDecision,
    evidence: {
      ...verifierDecision.evidence,
      credential_hash: credential.credential_hash,
      presented_credential_hash: credential.credential_hash,
      replay_state_after_hash: hashCanonical(replayAfter),
      replay_state_changed: true,
    },
    next_replay_state: replayAfter,
  };
  const result = await consumerResult({
    credential,
    replay_state: emptyReplay,
    evaluate: async () => {
      evaluatorCalls += 1;
      return forgedDecision;
    },
    effect_callback: async () => {
      calls += 1;
      return { effect_written: true };
    },
  });
  assert.equal(evaluatorCalls, 0);
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'issuer_mismatch');
});

await test('mutating evaluator cannot rewrite call-boundary input binding', async () => {
  let calls = 0;
  const result = await consumerResult({
    evaluate: async (verifierInput) => {
      const mutatedPayload = {
        object_ref: 'scratch://configured-consumer-adapter/target.json',
        value: 'mutated-consumer-adapter',
      };
      verifierInput.attempt.payload = mutatedPayload;
      verifierInput.attempt.request_id = 'consumer-adapter-attempt-mutated';
      const mutatedTargetHash = hashCanonical(mutatedPayload);
      verifierInput.rule.target_hash = mutatedTargetHash;
      verifierInput.rule.rule_source_hash = computeRecognitionRuleHash(verifierInput.rule);
      verifierInput.credential = finalizeConfiguredRecognitionCredential({
        ...verifierInput.credential,
        target_hash: mutatedTargetHash,
        nonce: 'consumer-adapter-nonce-mutated',
      });
      return evaluateConfiguredRecognition(verifierInput);
    },
    effect_callback: async () => {
      calls += 1;
      return { effect_written: true };
    },
  });
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'verifier_rule_hash_mismatch');
});

await test('malformed replay arrays fail closed before normalization', async () => {
  let calls = 0;
  const result = await consumerResult({
    replay_state: {
      used_credential_ids: 'not-an-array',
    },
    effect_callback: async () => {
      calls += 1;
      return { effect_written: true };
    },
  });
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'replay_state_array_field_invalid');
});

await test('malformed refusal still preserves default claim boundary markers', async () => {
  const result = await consumerResult({
    evaluate: async () => ({
      decision: 'refuse',
      configured_recognition: false,
      reason_code: 'malformed_refusal',
      non_claims: [],
      forbidden_claims: [],
    }),
    effect_callback: async () => {
      throw new Error('must not be called');
    },
  });
  assertConfiguredRecognitionConsumerRefused(result, 'malformed_refusal');
  for (const marker of DEFAULT_REQUIRED_NON_CLAIMS) {
    assert.equal(result.non_claims.includes(marker), true);
  }
  for (const marker of DEFAULT_FORBIDDEN_CLAIMS) {
    assert.equal(result.forbidden_claims.includes(marker), true);
  }
});

await test('verifier exception fails closed', async () => {
  let calls = 0;
  const result = await consumerResult({
    evaluate: async () => {
      throw new Error('/Users/example/local/verifier-error');
    },
    effect_callback: async () => {
      calls += 1;
    },
  });
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'verifier_exception');
  assertNoPrivatePath(result);
});

await test('unclonable replay state fails closed before effect', async () => {
  let calls = 0;
  const replayState = {};
  replayState.self = replayState;
  const result = await consumerResult({
    replay_state: replayState,
    effect_callback: async () => {
      calls += 1;
    },
  });
  assert.equal(calls, 0);
  assertConfiguredRecognitionConsumerRefused(result, 'replay_state_clone_failed');
});

await test('effect callback throw reports failure without rewriting verifier decision', async () => {
  let calls = 0;
  let attemptedEffect = false;
  const result = await consumerResult({
    effect_callback: async () => {
      calls += 1;
      attemptedEffect = true;
      throw new Error('/Users/example/local/effect-error');
    },
  });
  assert.equal(calls, 1);
  assert.equal(attemptedEffect, true);
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_failed');
  assert.equal(result.effect_called, true);
  assert.equal(result.effect_written, false);
  assert.equal(result.evidence.replay_state_changed, true);
  assert.equal(result.verifier_decision.decision, 'allow');
  assert.equal(result.verifier_decision.configured_recognition, true);
  assertNoPrivatePath(result);
});

await test('missing effect callback does not turn allow into effect', async () => {
  const result = await consumerResult();
  assert.equal(result.consumer_decision, 'effect_failed');
  assert.equal(result.reason_code, 'effect_callback_missing');
  assert.equal(result.effect_called, false);
  assert.equal(result.effect_written, false);
  assert.equal(result.verifier_decision.decision, 'allow');
});

await test('missing effect observer does not call effect callback', async () => {
  let calls = 0;
  const result = await consumerResult({
    effect_observer: null,
    effect_callback: async (effectInput) => {
      calls += 1;
      return validEffectAttestation(effectInput);
    },
  });
  assert.equal(calls, 0);
  assert.equal(result.consumer_decision, 'effect_failed');
  assert.equal(result.reason_code, 'effect_observer_missing');
  assert.equal(result.effect_called, false);
  assert.equal(result.effect_written, false);
});

await test('refusal does not mutate caller replay state', async () => {
  const credential = credentialFixture();
  const replayState = {
    used_credential_hashes: [],
    used_credential_ids: [credential.credential_id],
    used_nonces: [],
    last_sequence_by_issuer: {},
    last_receipt_hash_by_issuer: {},
  };
  const before = JSON.stringify(replayState);
  const result = await consumerResult({ credential, replay_state: replayState, effect_callback: async () => {} });
  assertConfiguredRecognitionConsumerRefused(result, 'credential_id_replayed');
  assert.equal(JSON.stringify(replayState), before);
});

await test('evidence output redacts absolute local paths from effect result', async () => {
  const result = await consumerResult({
    effect_callback: async (effectInput) => ({
      ...validEffectAttestation(effectInput),
      local_path: '/Users/example/local/marker.txt',
      nested: {
        '/Volumes/Example/opaque.pem': '/Users/example/local/value',
      },
    }),
  });
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_attestation_field_unrecognized');
  assert.equal(result.effect_written, false);
  assertNoPrivatePath(result);
});

await test('secret-shaped effect result is redacted safely', async () => {
  const apiTokenKey = ['api', 'tok' + 'en'].join('_');
  const apiKey = ['api', 'Key'].join('');
  const passwordKey = ['pass', 'word'].join('');
  const privateKeyKey = ['private', 'key'].join('_');
  const clientSecretKey = ['client', 'Secret'].join('');
  const hmacKey = 'h' + 'mac';
  const bearerValue = ['Authorization:', 'Bearer', 'EXAMPLE'].join(' ');
  const privateKeyValue = ['BEGIN', 'EXAMPLE', 'PRIVATE', 'KEY'].join(' ');
  const skValue = ['sk_', 'live', '_example'].join('');
  const result = await consumerResult({
    effect_callback: async (effectInput) => ({
      ...validEffectAttestation(effectInput),
      [apiTokenKey]: 'example-value',
      [apiKey]: skValue,
      [passwordKey]: 'plain-example',
      [privateKeyKey]: privateKeyValue,
      [clientSecretKey]: '~/private/example.txt',
      nested: {
        [hmacKey]: bearerValue,
      },
    }),
  });
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_attestation_field_unrecognized');
  assert.equal(result.effect_written, false);
  const text = JSON.stringify(result);
  assert.equal(text.includes('example-value'), false);
  assert.equal(text.includes(apiTokenKey), false);
  assert.equal(text.includes(apiKey), false);
  assert.equal(text.includes(passwordKey), false);
  assert.equal(text.includes(privateKeyKey), false);
  assert.equal(text.includes(clientSecretKey), false);
  assert.equal(text.includes(privateKeyValue), false);
  assert.equal(text.includes(bearerValue), false);
  assert.equal(text.includes(skValue), false);
  assert.equal(text.includes('plain-example'), false);
  assert.equal(text.includes('~/private/example.txt'), false);
});

await test('callback-reported no-write does not overstate effect', async () => {
  let calls = 0;
  const result = await consumerResult({
    effect_callback: async () => {
      calls += 1;
      return { effect_written: false, marker_ref: 'effects/not-written.txt' };
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_write_attestation_missing');
  assert.equal(result.effect_called, true);
  assert.equal(result.effect_written, false);
  assert.equal(result.evidence.replay_state_changed, true);
});

await test('callback without positive write attestation does not overstate effect', async () => {
  let calls = 0;
  const result = await consumerResult({
    effect_callback: async () => {
      calls += 1;
      return { marker_ref: 'effects/no-attestation.txt' };
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_write_attestation_missing');
  assert.equal(result.effect_written, false);
});

await test('effect written without structured type does not overstate effect', async () => {
  let calls = 0;
  const result = await consumerResult({
    effect_callback: async () => {
      calls += 1;
      return { effect_written: true };
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_effect_type_invalid');
  assert.equal(result.effect_written, false);
});

await test('effect attestation with wrong decision hash does not overstate effect', async () => {
  let calls = 0;
  const result = await consumerResult({
    effect_callback: async (effectInput) => {
      calls += 1;
      return validEffectAttestation(effectInput, {
        decision_hash: 'f'.repeat(64),
      });
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_decision_hash_mismatch');
  assert.equal(result.effect_written, false);
});

await test('effect attestation with wrong replay hash does not overstate effect', async () => {
  let calls = 0;
  const result = await consumerResult({
    effect_callback: async (effectInput) => {
      calls += 1;
      return validEffectAttestation(effectInput, {
        next_replay_state_hash: 'e'.repeat(64),
      });
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_replay_hash_mismatch');
  assert.equal(result.effect_written, false);
});

await test('private effect ref does not overstate effect', async () => {
  let calls = 0;
  const result = await consumerResult({
    effect_callback: async (effectInput) => {
      calls += 1;
      return validEffectAttestation(effectInput, {
        effect_ref: '/Users/example/local/effect-marker.txt',
      });
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_effect_ref_unsafe');
  assert.equal(result.effect_written, false);
  assertNoPrivatePath(result);
});

await test('effect ref outside fake adapter namespace does not overstate effect', async () => {
  let calls = 0;
  const result = await consumerResult({
    effect_callback: async (effectInput) => {
      calls += 1;
      return validEffectAttestation(effectInput, {
        effect_ref: 'effect://other-consumer/allow-marker',
      });
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_effect_ref_invalid');
  assert.equal(result.effect_written, false);
});

await test('bare fake adapter effect ref does not overstate effect', async () => {
  let calls = 0;
  const result = await consumerResult({
    effect_callback: async (effectInput) => {
      calls += 1;
      return validEffectAttestation(effectInput, {
        effect_ref: FAKE_LOCAL_CONSUMER_EFFECT_REF_PREFIX,
      });
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_effect_ref_invalid');
  assert.equal(result.effect_written, false);
});

await test('real-shaped suffix under fake adapter namespace does not overstate effect', async () => {
  let calls = 0;
  const result = await consumerResult({
    effect_callback: async (effectInput) => {
      calls += 1;
      return validEffectAttestation(effectInput, {
        effect_ref: `${FAKE_LOCAL_CONSUMER_EFFECT_REF_PREFIX}production-downstream`,
      });
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_effect_ref_invalid');
  assert.equal(result.effect_written, false);
});

await test('real downstream marker does not overstate fake local effect', async () => {
  let calls = 0;
  const result = await consumerResult({
    effect_callback: async (effectInput) => {
      calls += 1;
      return validEffectAttestation(effectInput, {
        real_downstream: true,
      });
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_real_downstream_invalid');
  assert.equal(result.effect_written, false);
});

await test('extra attestation fields do not overstate fake local effect', async () => {
  let calls = 0;
  const result = await consumerResult({
    effect_callback: async (effectInput) => {
      calls += 1;
      return validEffectAttestation(effectInput, {
        production_trust: true,
      });
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_attestation_field_unrecognized');
  assert.equal(result.effect_written, false);
});

await test('effect result snapshot blocks proxy field mutation after validation', async () => {
  let ownKeysCalls = 0;
  const result = await consumerResult({
    effect_callback: async (effectInput) => {
      const target = validEffectAttestation(effectInput);
      return new Proxy(target, {
        ownKeys(proxyTarget) {
          ownKeysCalls += 1;
          const keys = Reflect.ownKeys(proxyTarget);
          return ownKeysCalls === 1 ? keys : [...keys, 'production_trust'];
        },
        getOwnPropertyDescriptor(proxyTarget, property) {
          if (property === 'production_trust') {
            return { configurable: true, enumerable: true };
          }
          return Reflect.getOwnPropertyDescriptor(proxyTarget, property);
        },
        get(proxyTarget, property, receiver) {
          if (property === 'production_trust') return true;
          return Reflect.get(proxyTarget, property, receiver);
        },
      });
    },
  });
  assert.equal(ownKeysCalls >= 1, true);
  assertConfiguredRecognitionConsumerEffectWritten(result);
  assert.equal(JSON.stringify(result.effect_result).includes('production_trust'), false);
});

await test('observed fake marker mutation can satisfy effect observer', async () => {
  const markerStore = new Map();
  let observedHash = null;
  const result = await consumerResult({
    effect_callback: async (effectInput) => {
      const marker = {
        marker_type: FAKE_LOCAL_CONSUMER_MARKER_TYPE,
        effect_ref: `${FAKE_LOCAL_CONSUMER_EFFECT_REF_PREFIX}${effectInput.decision_hash}`,
        decision_hash: effectInput.decision_hash,
        effect_result_hash: hashCanonical(validEffectAttestation(effectInput)),
        effect_scope: FAKE_LOCAL_CONSUMER_EFFECT_SCOPE,
        transactional_truth: false,
        real_downstream: false,
      };
      markerStore.set('consumer-adapter-fixture-marker', JSON.parse(JSON.stringify(marker)));
      return validEffectAttestation(effectInput);
    },
    effect_observer: async (observerInput) => {
      const marker = markerStore.get('consumer-adapter-fixture-marker');
      assert.equal(marker.effect_ref, observerInput.effect_result.effect_ref);
      assert.equal(marker.decision_hash, observerInput.decision_hash);
      observedHash = hashCanonical(marker);
      return validEffectObservation(observerInput, {
        observed_effect: marker,
      });
    },
  });
  assertConfiguredRecognitionConsumerEffectWritten(result);
  assert.equal(markerStore.has('consumer-adapter-fixture-marker'), true);
  assert.equal(hashCanonical(result.effect_observation.observed_effect), observedHash);
  assert.equal(result.effect_observation.real_downstream, false);
  assert.equal(result.effect_observation.transactional_truth, false);
});

await test('effect observer failure does not overstate fake local effect', async () => {
  let callbackCalls = 0;
  const result = await consumerResult({
    effect_callback: async (effectInput) => {
      callbackCalls += 1;
      return validEffectAttestation(effectInput);
    },
    effect_observer: async () => {
      throw new Error('/Users/example/local/observer-error');
    },
  });
  assert.equal(callbackCalls, 1);
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_observer_failed');
  assert.equal(result.effect_written, false);
  assert.equal(result.evidence.replay_state_changed, true);
  assertNoPrivatePath(result);
});

await test('effect observer extra field does not overstate fake local effect', async () => {
  const result = await consumerResult({
    effect_callback: async (effectInput) => validEffectAttestation(effectInput),
    effect_observer: async (observerInput) => validEffectObservation(observerInput, {
      production_trust: true,
    }),
  });
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_observer_field_unrecognized');
  assert.equal(result.effect_written, false);
});

await test('effect observer real downstream marker does not overstate fake local effect', async () => {
  const result = await consumerResult({
    effect_callback: async (effectInput) => validEffectAttestation(effectInput),
    effect_observer: async (observerInput) => validEffectObservation(observerInput, {
      real_downstream: true,
    }),
  });
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_observer_real_downstream_invalid');
  assert.equal(result.effect_written, false);
});

await test('effect observer mismatch does not overstate fake local effect', async () => {
  const result = await consumerResult({
    effect_callback: async (effectInput) => validEffectAttestation(effectInput),
    effect_observer: async (observerInput) => validEffectObservation(observerInput, {
      effect_result_hash: 'a'.repeat(64),
    }),
  });
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_observer_result_hash_mismatch');
  assert.equal(result.effect_written, false);
});

await test('effect observer observed effect mismatch does not overstate fake local effect', async () => {
  const result = await consumerResult({
    effect_callback: async (effectInput) => validEffectAttestation(effectInput),
    effect_observer: async (observerInput) => validEffectObservation(observerInput, {
      observed_effect: {
        ...validEffectObservation(observerInput).observed_effect,
        decision_hash: 'b'.repeat(64),
      },
    }),
  });
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_observer_observed_effect_decision_hash_mismatch');
  assert.equal(result.effect_written, false);
});

await test('effect observer observed effect closed form is fully validated', async () => {
  const cases = [
    [
      'marker_type',
      () => 'wrong-marker-type',
      'effect_observer_observed_effect_type_invalid',
    ],
    [
      'effect_ref',
      () => 'effect://configured-consumer-adapter/wrong-ref',
      'effect_observer_observed_effect_ref_mismatch',
    ],
    [
      'decision_hash',
      () => 'c'.repeat(64),
      'effect_observer_observed_effect_decision_hash_mismatch',
    ],
    [
      'effect_result_hash',
      () => 'd'.repeat(64),
      'effect_observer_observed_effect_result_hash_mismatch',
    ],
    [
      'effect_scope',
      () => 'production',
      'effect_observer_observed_effect_scope_invalid',
    ],
    [
      'transactional_truth',
      () => true,
      'effect_observer_observed_effect_transactional_truth_invalid',
    ],
    [
      'real_downstream',
      () => true,
      'effect_observer_observed_effect_real_downstream_invalid',
    ],
    [
      'extra_nested_field',
      () => 'extra',
      'effect_observer_observed_effect_field_unrecognized',
    ],
  ];
  for (const [field, valueFn, expectedCode] of cases) {
    const result = await consumerResult({
      effect_callback: async (effectInput) => validEffectAttestation(effectInput),
      effect_observer: async (observerInput) => {
        const observation = validEffectObservation(observerInput);
        if (field === 'extra_nested_field') {
          observation.observed_effect.extra_nested_field = valueFn();
        } else {
          observation.observed_effect[field] = valueFn(observerInput);
        }
        return observation;
      },
    });
    assert.equal(result.consumer_decision, 'effect_untrusted');
    assert.equal(result.reason_code, expectedCode);
    assert.equal(result.effect_written, false);
  }
});

await test('effect observer snapshot blocks proxy field mutation after validation', async () => {
  let ownKeysCalls = 0;
  const result = await consumerResult({
    effect_callback: async (effectInput) => validEffectAttestation(effectInput),
    effect_observer: async (observerInput) => {
      const target = validEffectObservation(observerInput);
      return new Proxy(target, {
        ownKeys(proxyTarget) {
          ownKeysCalls += 1;
          const keys = Reflect.ownKeys(proxyTarget);
          return ownKeysCalls === 1 ? keys : [...keys, 'production_trust'];
        },
        getOwnPropertyDescriptor(proxyTarget, property) {
          if (property === 'production_trust') {
            return { configurable: true, enumerable: true };
          }
          return Reflect.getOwnPropertyDescriptor(proxyTarget, property);
        },
        get(proxyTarget, property, receiver) {
          if (property === 'production_trust') return true;
          return Reflect.get(proxyTarget, property, receiver);
        },
      });
    },
  });
  assert.equal(ownKeysCalls >= 1, true);
  assertConfiguredRecognitionConsumerEffectWritten(result);
  assert.equal(JSON.stringify(result.effect_observation).includes('production_trust'), false);
});

await test('transactional truth marker does not overstate fake local effect', async () => {
  let calls = 0;
  const result = await consumerResult({
    effect_callback: async (effectInput) => {
      calls += 1;
      return validEffectAttestation(effectInput, {
        transactional_truth: true,
      });
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_transactional_truth_invalid');
  assert.equal(result.effect_written, false);
});

await test('wrong effect scope does not overstate fake local effect', async () => {
  let calls = 0;
  const result = await consumerResult({
    effect_callback: async (effectInput) => {
      calls += 1;
      return validEffectAttestation(effectInput, {
        effect_scope: 'production',
      });
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_effect_scope_invalid');
  assert.equal(result.effect_written, false);
});

await test('invalid attestation consumes replay after callback invocation', async () => {
  const credential = credentialFixture({
    sequence: 3,
    nonce: 'consumer-adapter-nonce-invalid-consuming',
  });
  const result = await consumerResult({
    credential,
    effect_callback: async (effectInput) => validEffectAttestation(effectInput, {
      next_replay_state_hash: 'd'.repeat(64),
    }),
  });
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_replay_hash_mismatch');
  assert.equal(result.effect_written, false);
  assert.equal(result.evidence.replay_state_changed, true);
  assert.equal(result.next_replay_state.used_credential_ids.includes(credential.credential_id), true);
});

await test('effect result circular shape is redacted safely', async () => {
  const result = await consumerResult({
    effect_callback: async (effectInput) => {
      const circular = validEffectAttestation(effectInput);
      circular.self = circular;
      return circular;
    },
  });
  assert.equal(result.consumer_decision, 'effect_untrusted');
  assert.equal(result.reason_code, 'effect_callback_result_snapshot_failed');
  assert.equal(result.effect_written, false);
  assert.equal(result.effect_result.self, '[circular]');
});

await test('non-claims and forbidden claims are preserved', async () => {
  const result = await consumerResult({
    effect_callback: async (effectInput) => validEffectAttestation(effectInput),
  });
  for (const marker of DEFAULT_REQUIRED_NON_CLAIMS) {
    assert.equal(result.non_claims.includes(marker), true);
  }
  assert.equal(result.forbidden_claims.includes('real_downstream_recognition'), true);
  assert.equal(result.forbidden_claims.includes('production_trust'), true);
});

console.log(`${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
