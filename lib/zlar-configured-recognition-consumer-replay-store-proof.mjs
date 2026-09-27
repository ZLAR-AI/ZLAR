import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  FAKE_LOCAL_CONSUMER_EFFECT_OBSERVATION_TYPE,
  FAKE_LOCAL_CONSUMER_EFFECT_SCOPE,
  FAKE_LOCAL_CONSUMER_EFFECT_REF_PREFIX,
  FAKE_LOCAL_CONSUMER_EFFECT_TYPE,
  FAKE_LOCAL_CONSUMER_MARKER_TYPE,
} from './zlar-configured-recognition-consumer-adapter.mjs';
import {
  CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_TYPE,
  runConfiguredRecognitionConsumerWithReplayStore,
} from './zlar-configured-recognition-consumer-replay-store.mjs';
import {
  DEFAULT_REQUIRED_NON_CLAIMS,
  computeRecognitionRuleHash,
  finalizeConfiguredRecognitionCredential,
  hashCanonical,
} from './zlar-configured-recognition-verifier.mjs';

export const CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_TYPE =
  'zlar-configured-recognition-consumer-replay-store-proof-v0';
export const CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_VERSION = '0.1.0';
export const CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_MODEL =
  'local-no-secret-configured-recognition-consumer-replay-store-fixture';
export const CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_SAFE_CLAIM =
  'ZLAR can locally prove a fake configured-recognition consumer replay store persists one consumed fixture credential and refuses immediate replay before callback invocation.';
export const CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_FORBIDDEN_CLAIMS = Object.freeze([
  'production_durable_replay_persistence',
  'tamper_resistant_replay_store',
  'multi_host_replay_coordination',
  'crash_safe_or_transactional_replay_persistence',
  'real_receipt_validity',
  'real_downstream_recognition',
  'real_downstream_refusal',
  'real_downstream_effect',
  'registry_activation',
  'production_trust',
  'current_machine_governance',
  'source_movement_governance',
  'durable_source_transport',
  'external_attestation',
  'website_or_public_alignment',
  'side_door_closure',
  'all_surface_governance',
  'absolute_human_intention',
]);

const EVALUATED_AT = '2026-07-05T21:40:00Z';
const ISSUED_AT = '2026-07-05T21:39:30Z';
const EXPIRES_AT = '2026-07-05T21:41:00Z';
const GENESIS_HASH = '0'.repeat(64);
const TARGET_PAYLOAD = {
  object_ref: 'scratch://configured-consumer-replay-store-proof/target.json',
  value: 'consumer-replay-store-proof',
};
const TARGET_HASH = hashCanonical(TARGET_PAYLOAD);

function ruleFixture(overrides = {}) {
  const body = {
    rule_id: 'configured-recognition.consumer-replay-store-proof-rule.v0',
    rule_version: '0.1.0',
    issuer_id: 'fake-consumer-replay-store-proof-issuer',
    issuer_trust_class: 'scratch-configured-rule',
    credential_envelope: 'zlar.fake.configured-recognition.v1',
    action_class: 'fake_downstream.write_marker',
    policy_id: 'fake-policy.consumer-replay-store-proof.v1',
    target_ref: 'proof://consumer-replay-store-proof/recognized-target',
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
    issuer_id: 'fake-consumer-replay-store-proof-issuer',
    issuer_trust_class: 'scratch-configured-rule',
    action_class: 'fake_downstream.write_marker',
    target_ref: 'proof://consumer-replay-store-proof/recognized-target',
    target_hash: TARGET_HASH,
    decision: 'allow',
    policy_id: 'fake-policy.consumer-replay-store-proof.v1',
    issued_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    sequence: 1,
    previous_receipt_hash: GENESIS_HASH,
    nonce: 'consumer-replay-store-proof-nonce-001',
    proof_scope: 'scratch-only',
    non_claims: [...DEFAULT_REQUIRED_NON_CLAIMS],
    claims: ['scratch_fake_configured_recognition_only'],
    ...overrides,
  });
}

function attemptFixture(overrides = {}) {
  return {
    action_class: 'fake_downstream.write_marker',
    target_ref: 'proof://consumer-replay-store-proof/recognized-target',
    payload: TARGET_PAYLOAD,
    consequence_class: 'scratch_fake_effect_marker',
    request_id: 'consumer-replay-store-proof-attempt-001',
    ...overrides,
  };
}

function validEffectAttestation({ decision_hash, next_replay_state }) {
  return {
    effect_written: true,
    effect_type: FAKE_LOCAL_CONSUMER_EFFECT_TYPE,
    effect_ref: `${FAKE_LOCAL_CONSUMER_EFFECT_REF_PREFIX}${decision_hash}`,
    decision_hash,
    next_replay_state_hash: hashCanonical(next_replay_state),
    effect_scope: FAKE_LOCAL_CONSUMER_EFFECT_SCOPE,
    transactional_truth: false,
    real_downstream: false,
  };
}

function validEffectObservation({ decision_hash, effect_result }) {
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
  };
}

function evidenceFlag(value) {
  return value === true;
}

function deriveBoundaryFlags(result) {
  const consumer = result.consumer_result || {};
  const effectResult = consumer.effect_result || {};
  const effectObservation = consumer.effect_observation || {};
  const observedEffect = effectObservation.observed_effect || {};
  const verifierDecision = consumer.verifier_decision || {};
  return {
    real_downstream:
      evidenceFlag(effectResult.real_downstream) ||
      evidenceFlag(effectObservation.real_downstream) ||
      evidenceFlag(observedEffect.real_downstream),
    real_receipt:
      evidenceFlag(verifierDecision.real_receipt) ||
      evidenceFlag(verifierDecision.receipt_valid) ||
      evidenceFlag(consumer.real_receipt),
    production_trust:
      evidenceFlag(verifierDecision.production_trust) ||
      evidenceFlag(effectResult.production_trust) ||
      evidenceFlag(effectObservation.production_trust) ||
      evidenceFlag(consumer.production_trust),
  };
}

function readStore(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function outputTextIsSafe(value) {
  try {
    assertNoUnsafeConfiguredRecognitionReplayStoreProofText(JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

function caseHasNoRealDownstream(caseResult) {
  return (
    caseResult.real_downstream === false &&
    caseResult.real_receipt === false &&
    caseResult.production_trust === false
  );
}

function safeCase(name, result, extra = {}) {
  const boundaryFlags = deriveBoundaryFlags(result);
  const safeSummary = {
    case_id: name,
    wrapper_decision: result.wrapper_decision,
    reason_code: result.reason_code,
    store_written: result.store_written,
    store_present_before: result.store_present_before,
    store_present_after: result.store_present_after,
    consumer_decision: result.consumer_result?.consumer_decision ?? null,
    consumer_reason_code: result.consumer_result?.reason_code ?? null,
    effect_called: result.consumer_result?.effect_called ?? false,
    effect_written: result.consumer_result?.effect_written ?? false,
    real_downstream: boundaryFlags.real_downstream,
    real_receipt: boundaryFlags.real_receipt,
    production_trust: boundaryFlags.production_trust,
    ...extra,
  };
  return {
    ...safeSummary,
    result_hash: hashCanonical(safeSummary),
  };
}

function proofStatus(summary) {
  return (
    summary.first_call_persisted === true &&
    summary.first_call_effect_written === true &&
    summary.replay_refused_before_callback === true &&
    summary.invalid_store_failed_closed_before_callback === true &&
    summary.no_real_downstream === true &&
    summary.no_secret_material === true
  ) ? 'passed' : 'failed';
}

export async function runConfiguredRecognitionConsumerReplayStoreProof() {
  const scratchDir = mkdtempSync(join(tmpdir(), 'zlar-configured-replay-store-proof-'));
  try {
    const storePath = join(scratchDir, 'replay-store.json');
    const invalidStorePath = join(scratchDir, 'invalid-replay-store.json');
    const rule = ruleFixture();
    const credential = credentialFixture();
    const attempt = attemptFixture();
    let firstCallbackCalls = 0;
    const first = await runConfiguredRecognitionConsumerWithReplayStore({
      replay_store_path: storePath,
      rule,
      credential,
      attempt,
      evaluated_at: EVALUATED_AT,
      clock_source: 'fixture-clock',
      effect_callback: async (effectInput) => {
        firstCallbackCalls += 1;
        return validEffectAttestation(effectInput);
      },
      effect_observer: async (effectInput) => validEffectObservation(effectInput),
    });

    const persistedStore = readStore(storePath);
    const persistedReplayStateHash = hashCanonical(persistedStore.replay_state);
    const returnedReplayStateHash = hashCanonical(first.consumer_result.next_replay_state);
    const persistedReplayStateMatchesReturned = persistedReplayStateHash === returnedReplayStateHash;

    let replayCallbackCalls = 0;
    const replay = await runConfiguredRecognitionConsumerWithReplayStore({
      replay_store_path: storePath,
      rule,
      credential,
      attempt,
      evaluated_at: EVALUATED_AT,
      clock_source: 'fixture-clock',
      effect_callback: async (effectInput) => {
        replayCallbackCalls += 1;
        return validEffectAttestation(effectInput);
      },
      effect_observer: async (effectInput) => validEffectObservation(effectInput),
    });

    writeFileSync(invalidStorePath, JSON.stringify({
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

    let invalidCallbackCalls = 0;
    const invalid = await runConfiguredRecognitionConsumerWithReplayStore({
      replay_store_path: invalidStorePath,
      rule,
      credential,
      attempt,
      evaluated_at: EVALUATED_AT,
      clock_source: 'fixture-clock',
      effect_callback: async (effectInput) => {
        invalidCallbackCalls += 1;
        return validEffectAttestation(effectInput);
      },
      effect_observer: async (effectInput) => validEffectObservation(effectInput),
    });

    const cases = [
      safeCase('first_call_persists_replay_state_after_effect', first, {
        callback_calls: firstCallbackCalls,
        persisted_store_type: persistedStore.store_type,
        persisted_replay_state_hash: persistedReplayStateHash,
        returned_replay_state_hash: returnedReplayStateHash,
        persisted_replay_state_matches_returned: persistedReplayStateMatchesReturned,
      }),
      safeCase('second_call_refuses_replay_before_callback', replay, {
        callback_calls: replayCallbackCalls,
      }),
      safeCase('invalid_store_fails_closed_before_callback', invalid, {
        callback_calls: invalidCallbackCalls,
      }),
    ];

    const noRealDownstream = cases.every(caseHasNoRealDownstream);
    const noSecretMaterial = outputTextIsSafe({
      cases,
      safe_claim: CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_SAFE_CLAIM,
      forbidden_claims: CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_FORBIDDEN_CLAIMS,
    });

    const summary = {
      first_call_persisted:
        first.wrapper_decision === 'ok' &&
        first.reason_code === 'consumer_replay_state_persisted' &&
        first.store_written === true &&
        persistedReplayStateMatchesReturned === true,
      first_call_effect_written:
        first.consumer_result?.consumer_decision === 'effect_written' &&
        first.consumer_result?.effect_written === true &&
        firstCallbackCalls === 1,
      replay_refused_before_callback:
        replay.consumer_result?.consumer_decision === 'refuse' &&
        replay.consumer_result?.reason_code === 'credential_id_replayed' &&
        replay.consumer_result?.effect_called === false &&
        replayCallbackCalls === 0,
      invalid_store_failed_closed_before_callback:
        invalid.wrapper_decision === 'fail_closed' &&
        invalid.reason_code === 'replay_state_array_field_invalid' &&
        invalid.consumer_result === null &&
        invalidCallbackCalls === 0,
      persisted_replay_state_matches_returned: persistedReplayStateMatchesReturned,
      persisted_replay_state_hash: persistedReplayStateHash,
      returned_replay_state_hash: returnedReplayStateHash,
      no_real_downstream: noRealDownstream,
      no_secret_material: noSecretMaterial,
    };

    return {
      proof_type: CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_TYPE,
      proof_version: CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_VERSION,
      evidence_model: CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_MODEL,
      proof_status: proofStatus(summary),
      local_fixture_only: true,
      no_secret_material: noSecretMaterial,
      live_probe: false,
      real_downstream: !noRealDownstream,
      real_receipt: false,
      production_trust: false,
      store_path_redacted: true,
      evaluated_at: EVALUATED_AT,
      case_count: cases.length,
      cases,
      summary,
      safe_claim: CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_SAFE_CLAIM,
      non_claims: [...DEFAULT_REQUIRED_NON_CLAIMS],
      forbidden_claims: [...CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_FORBIDDEN_CLAIMS],
    };
  } finally {
    rmSync(scratchDir, { recursive: true, force: true });
  }
}

export function assertConfiguredRecognitionConsumerReplayStoreProof(report) {
  if (!report || report.proof_type !== CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_TYPE) {
    throw new Error('Configured recognition replay-store proof has the wrong proof type');
  }
  if (report.proof_status !== 'passed') {
    throw new Error('Configured recognition replay-store proof did not pass');
  }
  if (
    report.local_fixture_only !== true ||
    report.no_secret_material !== true ||
    report.live_probe !== false ||
    report.real_downstream !== false ||
    report.real_receipt !== false ||
    report.production_trust !== false
  ) {
    throw new Error('Configured recognition replay-store proof crossed its claim boundary');
  }
  return true;
}

export function assertNoUnsafeConfiguredRecognitionReplayStoreProofText(text) {
  const value = String(text);
  for (const marker of [
    '/Users/',
    '/Volumes/',
    'BEGIN PRIVATE KEY',
    'BEGIN PUBLIC KEY',
    'Authorization: Bearer',
    'private_key',
    'access_token',
    'refresh_token',
    'client_secret',
  ]) {
    if (value.includes(marker)) {
      throw new Error(`configured recognition replay-store proof output contains ${marker}`);
    }
  }
  return true;
}

export function formatConfiguredRecognitionConsumerReplayStoreProof(report) {
  return [
    'ZLAR configured-recognition consumer replay-store proof',
    `Status: ${report.proof_status}`,
    `Evidence model: ${report.evidence_model}`,
    `Cases: ${report.case_count}`,
    `First call persisted: ${report.summary.first_call_persisted}`,
    `First call effect written: ${report.summary.first_call_effect_written}`,
    `Replay refused before callback: ${report.summary.replay_refused_before_callback}`,
    `Invalid store failed closed before callback: ${report.summary.invalid_store_failed_closed_before_callback}`,
    `Real downstream: ${report.real_downstream}`,
    `Real receipt: ${report.real_receipt}`,
    `Production trust: ${report.production_trust}`,
    `Safe claim: ${report.safe_claim}`,
    '',
  ].join('\n');
}
