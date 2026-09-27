#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  FAKE_LOCAL_CONSUMER_EFFECT_OBSERVATION_TYPE,
  FAKE_LOCAL_CONSUMER_EFFECT_SCOPE,
  FAKE_LOCAL_CONSUMER_EFFECT_REF_PREFIX,
  FAKE_LOCAL_CONSUMER_EFFECT_TYPE,
  FAKE_LOCAL_CONSUMER_MARKER_TYPE,
  assertConfiguredRecognitionConsumerEffectWritten,
  assertConfiguredRecognitionConsumerRefused,
} from '../lib/zlar-configured-recognition-consumer-adapter.mjs';
import {
  CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_TYPE,
  assertConfiguredRecognitionConsumerReplayStoreFailClosed,
  assertConfiguredRecognitionConsumerReplayStorePersisted,
  runConfiguredRecognitionConsumerWithReplayStore,
} from '../lib/zlar-configured-recognition-consumer-replay-store.mjs';
import {
  DEFAULT_REQUIRED_NON_CLAIMS,
  computeRecognitionRuleHash,
  finalizeConfiguredRecognitionCredential,
  hashCanonical,
} from '../lib/zlar-configured-recognition-verifier.mjs';

const EVALUATED_AT = '2026-07-05T21:40:00Z';
const ISSUED_AT = '2026-07-05T21:39:30Z';
const EXPIRES_AT = '2026-07-05T21:41:00Z';
const GENESIS_HASH = '0'.repeat(64);
const TARGET_PAYLOAD = {
  object_ref: 'scratch://configured-consumer-replay-store/target.json',
  value: 'consumer-replay-store',
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

function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'zlar-consumer-replay-store-'));
  return Promise.resolve()
    .then(() => fn(dir))
    .finally(() => {
      rmSync(dir, { recursive: true, force: true });
    });
}

function ruleFixture(overrides = {}) {
  const body = {
    rule_id: 'configured-recognition.consumer-replay-store-rule.v0',
    rule_version: '0.1.0',
    issuer_id: 'fake-consumer-replay-store-issuer',
    issuer_trust_class: 'scratch-configured-rule',
    credential_envelope: 'zlar.fake.configured-recognition.v1',
    action_class: 'fake_downstream.write_marker',
    policy_id: 'fake-policy.consumer-replay-store.v1',
    target_ref: 'proof://consumer-replay-store/recognized-target',
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
    issuer_id: 'fake-consumer-replay-store-issuer',
    issuer_trust_class: 'scratch-configured-rule',
    action_class: 'fake_downstream.write_marker',
    target_ref: 'proof://consumer-replay-store/recognized-target',
    target_hash: TARGET_HASH,
    decision: 'allow',
    policy_id: 'fake-policy.consumer-replay-store.v1',
    issued_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    sequence: 1,
    previous_receipt_hash: GENESIS_HASH,
    nonce: 'consumer-replay-store-nonce-001',
    proof_scope: 'scratch-only',
    non_claims: [...DEFAULT_REQUIRED_NON_CLAIMS],
    claims: ['scratch_fake_configured_recognition_only'],
    ...overrides,
  });
}

function attemptFixture(overrides = {}) {
  return {
    action_class: 'fake_downstream.write_marker',
    target_ref: 'proof://consumer-replay-store/recognized-target',
    payload: TARGET_PAYLOAD,
    consequence_class: 'scratch_fake_effect_marker',
    request_id: 'consumer-replay-store-attempt-001',
    ...overrides,
  };
}

async function replayStoreResult({
  replay_store_path,
  rule = ruleFixture(),
  credential = credentialFixture(),
  attempt = attemptFixture(),
  effect_callback = undefined,
  effect_observer = validEffectObserver,
  evaluate = undefined,
} = {}) {
  return runConfiguredRecognitionConsumerWithReplayStore({
    replay_store_path,
    rule,
    credential,
    attempt,
    evaluated_at: EVALUATED_AT,
    clock_source: 'fixture-clock',
    effect_callback,
    effect_observer,
    evaluate,
  });
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

function assertNoRawPath(value, rawPath) {
  const text = JSON.stringify(value);
  assert.equal(text.includes(rawPath), false);
  assert.equal(text.includes('/Users/example'), false);
  assert.equal(text.includes('/Volumes/'), false);
}

function readStore(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

await test('missing store starts empty and valid effect persists replay state', async () => {
  await withTempDir(async (dir) => {
    const storePath = join(dir, 'replay-store.json');
    let calls = 0;
    const result = await replayStoreResult({
      replay_store_path: storePath,
      effect_callback: async (effectInput) => {
        calls += 1;
        return validEffectAttestation(effectInput);
      },
    });

    assert.equal(calls, 1);
    assertConfiguredRecognitionConsumerReplayStorePersisted(result);
    assertConfiguredRecognitionConsumerEffectWritten(result.consumer_result);
    assert.equal(result.reason_code, 'consumer_replay_state_persisted');
    assert.equal(result.store_present_before, false);
    assert.equal(result.store_present_after, true);
    assert.equal(existsSync(storePath), true);
    assertNoRawPath(result, storePath);
    assertNoRawPath(result, dir);

    const stored = readStore(storePath);
    const credential = credentialFixture();
    assert.equal(stored.store_type, CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_TYPE);
    assert.deepEqual(stored.replay_state.used_credential_ids, [credential.credential_id]);
    assert.deepEqual(stored.replay_state.used_credential_hashes, [credential.credential_hash]);
    assert.deepEqual(stored.replay_state.used_nonces, [credential.nonce]);
    assert.equal(stored.replay_state.last_sequence_by_issuer[credential.issuer_id], credential.sequence);
    assert.equal(
      stored.replay_state.last_receipt_hash_by_issuer[credential.issuer_id],
      credential.receipt_hash,
    );
  });
});

await test('persisted replay state refuses immediate replay before callback', async () => {
  await withTempDir(async (dir) => {
    const storePath = join(dir, 'replay-store.json');
    let firstCalls = 0;
    const first = await replayStoreResult({
      replay_store_path: storePath,
      effect_callback: async (effectInput) => {
        firstCalls += 1;
        return validEffectAttestation(effectInput);
      },
    });
    assert.equal(firstCalls, 1);
    assertConfiguredRecognitionConsumerReplayStorePersisted(first);

    let secondCalls = 0;
    const second = await replayStoreResult({
      replay_store_path: storePath,
      effect_callback: async (effectInput) => {
        secondCalls += 1;
        return validEffectAttestation(effectInput);
      },
    });

    assert.equal(secondCalls, 0);
    assert.equal(second.store_written, false);
    assert.equal(second.reason_code, 'consumer_replay_state_not_persisted');
    assertConfiguredRecognitionConsumerRefused(second.consumer_result, 'credential_id_replayed');
    assertNoRawPath(second, storePath);
  });
});

await test('invalid store fails closed before consumer callback', async () => {
  await withTempDir(async (dir) => {
    const storePath = join(dir, 'replay-store.json');
    writeFileSync(storePath, '{"store_type":true}\n', 'utf8');
    let calls = 0;
    const result = await replayStoreResult({
      replay_store_path: storePath,
      effect_callback: async (effectInput) => {
        calls += 1;
        return validEffectAttestation(effectInput);
      },
    });

    assert.equal(calls, 0);
    assertConfiguredRecognitionConsumerReplayStoreFailClosed(result, 'replay_store_type_invalid');
    assert.equal(result.consumer_result, null);
    assertNoRawPath(result, storePath);
  });
});

await test('unparseable store fails closed before consumer callback', async () => {
  await withTempDir(async (dir) => {
    const storePath = join(dir, 'replay-store.json');
    writeFileSync(storePath, '{"store_type":', 'utf8');
    let calls = 0;
    const result = await replayStoreResult({
      replay_store_path: storePath,
      effect_callback: async (effectInput) => {
        calls += 1;
        return validEffectAttestation(effectInput);
      },
    });

    assert.equal(calls, 0);
    assertConfiguredRecognitionConsumerReplayStoreFailClosed(result, 'replay_store_parse_failed');
    assert.equal(result.consumer_result, null);
    assertNoRawPath(result, storePath);
  });
});

await test('wrong store version fails closed before consumer callback', async () => {
  await withTempDir(async (dir) => {
    const storePath = join(dir, 'replay-store.json');
    writeFileSync(storePath, JSON.stringify({
      store_type: CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_TYPE,
      store_version: '9.9.9',
      replay_state: {
        used_credential_hashes: [],
        used_credential_ids: [],
        used_nonces: [],
        last_sequence_by_issuer: {},
        last_receipt_hash_by_issuer: {},
      },
    }), 'utf8');
    let calls = 0;
    const result = await replayStoreResult({
      replay_store_path: storePath,
      effect_callback: async (effectInput) => {
        calls += 1;
        return validEffectAttestation(effectInput);
      },
    });

    assert.equal(calls, 0);
    assertConfiguredRecognitionConsumerReplayStoreFailClosed(result, 'replay_store_version_invalid');
  });
});

await test('malformed replay state store fails closed before consumer callback', async () => {
  await withTempDir(async (dir) => {
    const storePath = join(dir, 'replay-store.json');
    writeFileSync(storePath, JSON.stringify({
      store_type: CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_TYPE,
      store_version: '0.1.0',
      replay_state: {
        used_credential_hashes: [],
        used_credential_ids: 'not-an-array',
        used_nonces: [],
        last_sequence_by_issuer: {},
        last_receipt_hash_by_issuer: {},
      },
    }), 'utf8');
    let calls = 0;
    const result = await replayStoreResult({
      replay_store_path: storePath,
      effect_callback: async (effectInput) => {
        calls += 1;
        return validEffectAttestation(effectInput);
      },
    });

    assert.equal(calls, 0);
    assertConfiguredRecognitionConsumerReplayStoreFailClosed(
      result,
      'replay_state_array_field_invalid',
    );
  });
});

await test('malformed cursor store fails closed before consumer callback', async () => {
  await withTempDir(async (dir) => {
    const storePath = join(dir, 'replay-store.json');
    writeFileSync(storePath, JSON.stringify({
      store_type: CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_TYPE,
      store_version: '0.1.0',
      replay_state: {
        used_credential_hashes: [],
        used_credential_ids: [],
        used_nonces: [],
        last_sequence_by_issuer: {
          'fake-consumer-replay-store-issuer': -1,
        },
        last_receipt_hash_by_issuer: {},
      },
    }), 'utf8');
    let calls = 0;
    const result = await replayStoreResult({
      replay_store_path: storePath,
      effect_callback: async (effectInput) => {
        calls += 1;
        return validEffectAttestation(effectInput);
      },
    });

    assert.equal(calls, 0);
    assertConfiguredRecognitionConsumerReplayStoreFailClosed(
      result,
      'replay_state_numeric_field_invalid',
    );
  });
});

await test('pre-effect verifier refusal does not create or write a replay store', async () => {
  await withTempDir(async (dir) => {
    const storePath = join(dir, 'replay-store.json');
    let calls = 0;
    const result = await replayStoreResult({
      replay_store_path: storePath,
      credential: credentialFixture({
        issuer_id: 'unknown-fake-issuer',
        sequence: 2,
        nonce: 'consumer-replay-store-unknown-issuer',
      }),
      effect_callback: async (effectInput) => {
        calls += 1;
        return validEffectAttestation(effectInput);
      },
    });

    assert.equal(calls, 0);
    assert.equal(result.store_written, false);
    assert.equal(existsSync(storePath), false);
    assertConfiguredRecognitionConsumerRefused(result.consumer_result, 'issuer_mismatch');
  });
});

await test('callback invocation consumes replay state even when effect is untrusted', async () => {
  await withTempDir(async (dir) => {
    const storePath = join(dir, 'replay-store.json');
    let firstCalls = 0;
    const first = await replayStoreResult({
      replay_store_path: storePath,
      effect_callback: async () => {
        firstCalls += 1;
        throw new Error('/Users/example/local/effect-maybe-happened');
      },
    });

    assert.equal(firstCalls, 1);
    assertConfiguredRecognitionConsumerReplayStorePersisted(first);
    assert.equal(first.consumer_result.consumer_decision, 'effect_untrusted');
    assert.equal(first.consumer_result.reason_code, 'effect_callback_failed');
    assert.equal(first.consumer_result.effect_called, true);
    assertNoRawPath(first, storePath);
    assertNoRawPath(first, dir);

    let secondCalls = 0;
    const second = await replayStoreResult({
      replay_store_path: storePath,
      effect_callback: async (effectInput) => {
        secondCalls += 1;
        return validEffectAttestation(effectInput);
      },
    });
    assert.equal(secondCalls, 0);
    assertConfiguredRecognitionConsumerRefused(second.consumer_result, 'credential_id_replayed');
  });
});

await test('raw path in callback output is redacted at wrapper boundary', async () => {
  await withTempDir(async (dir) => {
    const storePath = join(dir, 'replay-store.json');
    let calls = 0;
    const result = await replayStoreResult({
      replay_store_path: storePath,
      effect_callback: async (effectInput) => {
        calls += 1;
        return {
          ...validEffectAttestation(effectInput),
          local_path: storePath,
          nested: {
            [join(dir, 'private-key.pem')]: '/Users/example/private-key.pem',
          },
        };
      },
    });

    assert.equal(calls, 1);
    assertConfiguredRecognitionConsumerReplayStorePersisted(result);
    assert.equal(result.consumer_result.consumer_decision, 'effect_untrusted');
    assert.equal(result.consumer_result.reason_code, 'effect_callback_attestation_field_unrecognized');
    assertNoRawPath(result, storePath);
    assertNoRawPath(result, dir);
  });
});

await test('relative replay store path echoed from callback is redacted at wrapper boundary', async () => {
  await withTempDir(async (dir) => {
    const previousCwd = process.cwd();
    process.chdir(dir);
    try {
      const storePath = 'relative-replay-store.json';
      const result = await replayStoreResult({
        replay_store_path: storePath,
        effect_callback: async (effectInput) => ({
          ...validEffectAttestation(effectInput),
          local_path: storePath,
        }),
      });

      assertConfiguredRecognitionConsumerReplayStorePersisted(result);
      assert.equal(result.consumer_result.consumer_decision, 'effect_untrusted');
      assert.equal(
        result.consumer_result.reason_code,
        'effect_callback_attestation_field_unrecognized',
      );
      assertNoRawPath(result, storePath);
      assert.equal(result.consumer_result_hash, hashCanonical(result.consumer_result));
    } finally {
      process.chdir(previousCwd);
    }
  });
});

await test('missing replay store path fails closed without consumer result', async () => {
  const result = await replayStoreResult({
    effect_callback: async () => {
      throw new Error('must not be called');
    },
  });
  assertConfiguredRecognitionConsumerReplayStoreFailClosed(result, 'replay_store_path_missing');
  assert.equal(result.consumer_result, null);
});

await test('result claim ceiling stays local fixture and no-secret', async () => {
  await withTempDir(async (dir) => {
    const result = await replayStoreResult({
      replay_store_path: join(dir, 'replay-store.json'),
      effect_callback: async (effectInput) => validEffectAttestation(effectInput),
    });

    assertConfiguredRecognitionConsumerReplayStorePersisted(result);
    assert.match(result.safe_claim_ceiling, /local no-secret/);
    for (const forbidden of [
      'production_durable_replay_persistence',
      'tamper_resistant_replay_store',
      'multi_host_replay_coordination',
      'real_downstream_effect',
      'receipt_backed_authority',
      'production_trust',
    ]) {
      assert.equal(result.forbidden_claims.includes(forbidden), true);
    }
  });
});

console.log(`${pass} passed, ${fail} failed`);
if (fail > 0) {
  process.exitCode = 1;
}
