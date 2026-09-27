import {
  CONFIGURED_RECOGNITION_VERIFIER_TYPE,
  DEFAULT_FORBIDDEN_CLAIMS,
  DEFAULT_REQUIRED_NON_CLAIMS,
  SAFE_CLAIM_CEILING,
  computeAttemptHash,
  computeConfiguredCredentialHash,
  computeRecognitionRuleHash,
  evaluateConfiguredRecognition,
  hashCanonical,
} from './zlar-configured-recognition-verifier.mjs';

export const CONFIGURED_RECOGNITION_CONSUMER_ADAPTER_TYPE =
  'zlar-configured-recognition-consumer-adapter-v0';
export const CONFIGURED_RECOGNITION_CONSUMER_ADAPTER_VERSION = '0.1.0';
export const CONSUMER_ADAPTER_SAFE_CLAIM_CEILING =
  'ZLAR can count one local fake consumer effect on exact configured-recognition allow plus closed-form fake attestation and observer results.';
export const FAKE_LOCAL_CONSUMER_EFFECT_TYPE = 'fake_local_consumer_effect_v0';
export const FAKE_LOCAL_CONSUMER_EFFECT_SCOPE = 'scratch_or_fixture_only';
export const FAKE_LOCAL_CONSUMER_EFFECT_REF_PREFIX = 'effect://configured-consumer-adapter/';
export const FAKE_LOCAL_CONSUMER_EFFECT_OBSERVATION_TYPE =
  'fake_local_consumer_effect_observation_v0';
export const FAKE_LOCAL_CONSUMER_MARKER_TYPE = 'fake_local_consumer_marker_v0';
const EFFECT_ATTESTATION_FIELDS = new Set([
  'effect_written',
  'effect_type',
  'effect_ref',
  'decision_hash',
  'next_replay_state_hash',
  'effect_scope',
  'transactional_truth',
  'real_downstream',
]);
const EFFECT_OBSERVATION_FIELDS = new Set([
  'effect_observed',
  'observation_type',
  'effect_ref',
  'decision_hash',
  'effect_result_hash',
  'observed_effect',
  'effect_scope',
  'transactional_truth',
  'real_downstream',
]);
const OBSERVED_EFFECT_FIELDS = new Set([
  'marker_type',
  'effect_ref',
  'decision_hash',
  'effect_result_hash',
  'effect_scope',
  'transactional_truth',
  'real_downstream',
]);

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function safeClone(value) {
  try {
    return { ok: true, value: clone(value), error: null };
  } catch (error) {
    return { ok: false, value: null, error };
  }
}

function safeHashCanonical(value) {
  try {
    return hashCanonical(value);
  } catch {
    return null;
  }
}

function stringOrNull(value) {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function stringArrayOrEmpty(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((item) => typeof item === 'string' && item.length > 0);
}

function normalizedReplayState(replayState = {}) {
  const source = isObject(replayState) ? replayState : {};
  return {
    used_credential_hashes: stringArrayOrEmpty(source.used_credential_hashes),
    used_credential_ids: stringArrayOrEmpty(source.used_credential_ids),
    used_nonces: stringArrayOrEmpty(source.used_nonces),
    last_sequence_by_issuer: isObject(source.last_sequence_by_issuer)
      ? { ...source.last_sequence_by_issuer }
      : {},
    last_receipt_hash_by_issuer: isObject(source.last_receipt_hash_by_issuer)
      ? { ...source.last_receipt_hash_by_issuer }
      : {},
  };
}

function canonicalKey(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (value.charCodeAt(index) > 127) return false;
  }
  return true;
}

function validateRawReplayStateShape(replayState) {
  if (replayState === undefined) return { ok: true };
  if (!isObject(replayState)) return { ok: false, code: 'replay_state_not_object' };
  for (const field of ['used_credential_hashes', 'used_credential_ids', 'used_nonces']) {
    if (Object.prototype.hasOwnProperty.call(replayState, field)) {
      const value = replayState[field];
      if (!Array.isArray(value) || !value.every((item) => typeof item === 'string' && item.length > 0)) {
        return { ok: false, code: 'replay_state_array_field_invalid' };
      }
    }
  }
  if (Object.prototype.hasOwnProperty.call(replayState, 'last_sequence_by_issuer')) {
    if (!isObject(replayState.last_sequence_by_issuer)) {
      return { ok: false, code: 'replay_state_cursor_field_invalid' };
    }
    for (const [key, value] of Object.entries(replayState.last_sequence_by_issuer)) {
      if (!canonicalKey(key)) return { ok: false, code: 'replay_state_cursor_field_invalid' };
      if (typeof value !== 'number' || !Number.isInteger(value) || !Number.isSafeInteger(value) || value < 0) {
        return { ok: false, code: 'replay_state_numeric_field_invalid' };
      }
    }
  }
  if (Object.prototype.hasOwnProperty.call(replayState, 'last_receipt_hash_by_issuer')) {
    if (!isObject(replayState.last_receipt_hash_by_issuer)) {
      return { ok: false, code: 'replay_state_cursor_field_invalid' };
    }
    for (const [key, value] of Object.entries(replayState.last_receipt_hash_by_issuer)) {
      if (!canonicalKey(key) || !sha256Like(value)) {
        return { ok: false, code: 'replay_state_cursor_field_invalid' };
      }
    }
  }
  return { ok: true };
}

function targetRefLooksPrivate(value) {
  if (typeof value !== 'string') return false;
  return value.startsWith('/')
    || value.startsWith('~/')
    || value.startsWith('file:')
    || value.includes('/Users/')
    || value.includes('/Volumes/');
}

function looksSensitiveMarker(value) {
  if (typeof value !== 'string') return false;
  const compact = value.replace(/[^A-Za-z0-9]/g, '').toLowerCase();
  return [
    'apikey',
    'apitoken',
    'accesstoken',
    'refreshtoken',
    'clientsecret',
    'password',
    'passwd',
    'privatekey',
    'secret',
    'token',
    'hmac',
    'signing',
    'authorization',
    'bearer',
  ].some((marker) => compact.includes(marker))
    || /^sk_(live|test)_[A-Za-z0-9_]+/.test(value)
    || /BEGIN [A-Z ]*PRIVATE KEY/i.test(value)
    || /Authorization:\s*Bearer/i.test(value);
}

function redactPrivateString(value, label = 'consumer-string') {
  if (looksSensitiveMarker(value)) return `redacted-sensitive-${label}`;
  if (!targetRefLooksPrivate(value)) return value ?? null;
  return `redacted-${label}:${safeHashCanonical(value)}`;
}

function redactEvidenceValue(value, seen = new WeakSet()) {
  if (typeof value === 'string') return redactPrivateString(value);
  if (typeof value === 'bigint') return '[unsupported-bigint]';
  if (typeof value === 'function') return '[unsupported-function]';
  if (typeof value === 'symbol') return '[unsupported-symbol]';
  if (Array.isArray(value)) {
    if (seen.has(value)) return '[circular]';
    seen.add(value);
    return value.map((item) => redactEvidenceValue(item, seen));
  }
  if (isObject(value)) {
    if (seen.has(value)) return '[circular]';
    seen.add(value);
    const output = {};
    for (const key of Object.keys(value)) {
      const sensitiveKey = looksSensitiveMarker(key);
      const redactedKey = sensitiveKey
        ? `redacted-sensitive-consumer-key:${safeHashCanonical(key)}`
        : targetRefLooksPrivate(key)
        ? redactPrivateString(key, 'consumer-key')
        : key;
      output[redactedKey] = sensitiveKey
        ? 'redacted-sensitive-consumer-value'
        : redactEvidenceValue(value[key], seen);
    }
    return output;
  }
  return value;
}

function safeRedactEvidenceValue(value) {
  try {
    return redactEvidenceValue(value);
  } catch {
    return '[unavailable-effect-result]';
  }
}

function snapshotEffectResult(value) {
  const snapshot = safeClone(value);
  if (snapshot.ok) {
    return { ok: true, value: snapshot.value, error: null };
  }
  return {
    ok: false,
    value: safeRedactEvidenceValue(value),
    error: snapshot.error,
  };
}

function decisionHash(decision) {
  return safeHashCanonical(decision);
}

function replayHash(replayState) {
  return safeHashCanonical(replayState || {});
}

function mergeMarkerArray(defaults, provided) {
  const output = [...defaults];
  if (Array.isArray(provided)) {
    for (const marker of provided) {
      if (typeof marker === 'string' && marker.length > 0 && !output.includes(marker)) {
        output.push(marker);
      }
    }
  }
  return output;
}

function stringArray(value) {
  return Array.isArray(value) && value.every((item) => typeof item === 'string' && item.length > 0);
}

function sha256Like(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function appendUnique(array, value) {
  if (typeof value === 'string' && value.length > 0 && !array.includes(value)) {
    array.push(value);
  }
}

function positiveSafeInteger(value) {
  return typeof value === 'number'
    && Number.isInteger(value)
    && Number.isSafeInteger(value)
    && value > 0;
}

function payloadHashForAttempt(attempt) {
  if (!isObject(attempt)) return null;
  if (sha256Like(attempt.payload_hash)) return attempt.payload_hash;
  if (Object.prototype.hasOwnProperty.call(attempt, 'payload')) return safeHashCanonical(attempt.payload);
  return null;
}

function computeInputBindingHashes({ rule, credential, attempt }) {
  try {
    return {
      ok: true,
      rule_hash: isObject(rule) ? computeRecognitionRuleHash(rule) : null,
      credential_hash: isObject(credential) ? computeConfiguredCredentialHash(credential) : null,
      attempt_hash: isObject(attempt) ? computeAttemptHash(attempt) : null,
      target_hash: payloadHashForAttempt(attempt),
    };
  } catch {
    return {
      ok: false,
      rule_hash: null,
      credential_hash: null,
      attempt_hash: null,
      target_hash: null,
    };
  }
}

function validateEffectAttestation(effectResult, verifierDecision) {
  if (!isObject(effectResult)) return 'effect_callback_write_attestation_missing';
  if (effectResult.effect_written !== true) return 'effect_callback_write_attestation_missing';
  for (const field of Object.keys(effectResult)) {
    if (!EFFECT_ATTESTATION_FIELDS.has(field)) return 'effect_callback_attestation_field_unrecognized';
  }
  if (effectResult.effect_type !== FAKE_LOCAL_CONSUMER_EFFECT_TYPE) return 'effect_callback_effect_type_invalid';
  const effectRef = stringOrNull(effectResult.effect_ref);
  if (!effectRef) return 'effect_callback_effect_ref_missing';
  if (targetRefLooksPrivate(effectRef) || looksSensitiveMarker(effectRef)) return 'effect_callback_effect_ref_unsafe';
  const expectedEffectRef = `${FAKE_LOCAL_CONSUMER_EFFECT_REF_PREFIX}${decisionHash(verifierDecision)}`;
  if (effectRef !== expectedEffectRef) return 'effect_callback_effect_ref_invalid';
  if (effectResult.decision_hash !== decisionHash(verifierDecision)) {
    return 'effect_callback_decision_hash_mismatch';
  }
  if (effectResult.next_replay_state_hash !== replayHash(verifierDecision.next_replay_state)) {
    return 'effect_callback_replay_hash_mismatch';
  }
  if (effectResult.effect_scope !== FAKE_LOCAL_CONSUMER_EFFECT_SCOPE) {
    return 'effect_callback_effect_scope_invalid';
  }
  if (effectResult.transactional_truth !== false) return 'effect_callback_transactional_truth_invalid';
  if (effectResult.real_downstream !== false) return 'effect_callback_real_downstream_invalid';
  return null;
}

function validateEffectObservation(effectObservation, effectResult, verifierDecision) {
  if (!isObject(effectObservation)) return 'effect_observer_observation_missing';
  if (effectObservation.effect_observed !== true) return 'effect_observer_observation_missing';
  for (const field of Object.keys(effectObservation)) {
    if (!EFFECT_OBSERVATION_FIELDS.has(field)) return 'effect_observer_field_unrecognized';
  }
  if (effectObservation.observation_type !== FAKE_LOCAL_CONSUMER_EFFECT_OBSERVATION_TYPE) {
    return 'effect_observer_type_invalid';
  }
  if (effectObservation.effect_ref !== effectResult.effect_ref) return 'effect_observer_ref_mismatch';
  if (effectObservation.decision_hash !== decisionHash(verifierDecision)) {
    return 'effect_observer_decision_hash_mismatch';
  }
  const effectResultHash = safeHashCanonical(effectResult);
  if (effectObservation.effect_result_hash !== effectResultHash) {
    return 'effect_observer_result_hash_mismatch';
  }
  if (!isObject(effectObservation.observed_effect)) return 'effect_observer_observed_effect_missing';
  for (const field of Object.keys(effectObservation.observed_effect)) {
    if (!OBSERVED_EFFECT_FIELDS.has(field)) return 'effect_observer_observed_effect_field_unrecognized';
  }
  if (effectObservation.observed_effect.marker_type !== FAKE_LOCAL_CONSUMER_MARKER_TYPE) {
    return 'effect_observer_observed_effect_type_invalid';
  }
  if (effectObservation.observed_effect.effect_ref !== effectResult.effect_ref) {
    return 'effect_observer_observed_effect_ref_mismatch';
  }
  if (effectObservation.observed_effect.decision_hash !== decisionHash(verifierDecision)) {
    return 'effect_observer_observed_effect_decision_hash_mismatch';
  }
  if (effectObservation.observed_effect.effect_result_hash !== effectResultHash) {
    return 'effect_observer_observed_effect_result_hash_mismatch';
  }
  if (effectObservation.observed_effect.effect_scope !== FAKE_LOCAL_CONSUMER_EFFECT_SCOPE) {
    return 'effect_observer_observed_effect_scope_invalid';
  }
  if (effectObservation.observed_effect.transactional_truth !== false) {
    return 'effect_observer_observed_effect_transactional_truth_invalid';
  }
  if (effectObservation.observed_effect.real_downstream !== false) {
    return 'effect_observer_observed_effect_real_downstream_invalid';
  }
  if (effectObservation.effect_scope !== FAKE_LOCAL_CONSUMER_EFFECT_SCOPE) {
    return 'effect_observer_scope_invalid';
  }
  if (effectObservation.transactional_truth !== false) return 'effect_observer_transactional_truth_invalid';
  if (effectObservation.real_downstream !== false) return 'effect_observer_real_downstream_invalid';
  return null;
}

function expectedReplayAfterState(replayStateBefore, credential) {
  if (!isObject(credential)) return { ok: false, value: null };
  const issuerId = stringOrNull(credential.issuer_id);
  const credentialHash = stringOrNull(credential.credential_hash);
  const credentialId = stringOrNull(credential.credential_id);
  const nonce = stringOrNull(credential.nonce);
  const receiptHash = stringOrNull(credential.receipt_hash);
  if (
    !issuerId ||
    !canonicalKey(issuerId) ||
    !sha256Like(credentialHash) ||
    !credentialId ||
    !nonce ||
    !sha256Like(receiptHash) ||
    !positiveSafeInteger(credential.sequence)
  ) {
    return { ok: false, value: null };
  }
  const replayAfter = clone(replayStateBefore);
  appendUnique(replayAfter.used_credential_hashes, credentialHash);
  appendUnique(replayAfter.used_credential_ids, credentialId);
  appendUnique(replayAfter.used_nonces, nonce);
  replayAfter.last_sequence_by_issuer[issuerId] = credential.sequence;
  replayAfter.last_receipt_hash_by_issuer[issuerId] = receiptHash;
  return { ok: true, value: replayAfter };
}

function snapshotInput(value, code) {
  const snapshot = safeClone(value);
  if (!snapshot.ok) return { ok: false, code, boundary: null, evaluator: null };
  const evaluatorSnapshot = safeClone(snapshot.value);
  if (!evaluatorSnapshot.ok) return { ok: false, code, boundary: null, evaluator: null };
  return {
    ok: true,
    code: null,
    boundary: snapshot.value,
    evaluator: evaluatorSnapshot.value,
  };
}

function validateAllowVerifierDecisionShape(
  verifierDecision,
  replayStateBefore,
  inputBindings,
  credentialBoundary,
) {
  if (!isObject(verifierDecision)) return 'verifier_result_not_object';
  if (verifierDecision.result_type !== CONFIGURED_RECOGNITION_VERIFIER_TYPE) return 'verifier_result_type_invalid';
  if (verifierDecision.verifier_version !== '0.1.0') return 'verifier_version_invalid';
  if (verifierDecision.safe_claim_ceiling !== SAFE_CLAIM_CEILING) return 'verifier_safe_claim_ceiling_invalid';
  if (verifierDecision.decision !== 'allow') return verifierDecision.reason_code || 'verifier_result_not_allow';
  if (verifierDecision.configured_recognition !== true) return 'verifier_result_not_allow';
  if (verifierDecision.reason_code !== 'recognized') return 'verifier_reason_invalid';
  if (!isObject(verifierDecision.evidence)) return 'verifier_evidence_missing';
  for (const field of [
    'rule_hash',
    'credential_hash',
    'presented_credential_hash',
    'attempt_hash',
    'target_hash',
    'replay_state_before_hash',
    'replay_state_after_hash',
  ]) {
    if (!sha256Like(verifierDecision.evidence[field])) return 'verifier_evidence_hash_invalid';
  }
  if (!inputBindings.ok) return 'verifier_input_binding_unavailable';
  if (verifierDecision.evidence.rule_hash !== inputBindings.rule_hash) return 'verifier_rule_hash_mismatch';
  if (verifierDecision.evidence.credential_hash !== inputBindings.credential_hash) return 'verifier_credential_hash_mismatch';
  if (verifierDecision.evidence.presented_credential_hash !== inputBindings.credential_hash) {
    return 'verifier_presented_credential_hash_mismatch';
  }
  if (verifierDecision.evidence.attempt_hash !== inputBindings.attempt_hash) return 'verifier_attempt_hash_mismatch';
  if (verifierDecision.evidence.target_hash !== inputBindings.target_hash) return 'verifier_target_hash_mismatch';
  if (verifierDecision.evidence.privacy_checked !== true) return 'verifier_privacy_unchecked';
  if (verifierDecision.evidence.replay_state_changed !== true) return 'verifier_replay_state_unchanged';
  if (!isObject(verifierDecision.next_replay_state)) return 'verifier_next_replay_state_missing';
  if (verifierDecision.evidence.replay_state_before_hash !== replayHash(replayStateBefore)) {
    return 'verifier_replay_before_hash_mismatch';
  }
  if (verifierDecision.evidence.replay_state_after_hash !== replayHash(verifierDecision.next_replay_state)) {
    return 'verifier_replay_after_hash_mismatch';
  }
  const expectedReplayAfter = expectedReplayAfterState(replayStateBefore, credentialBoundary);
  if (!expectedReplayAfter.ok) return 'verifier_replay_after_state_unavailable';
  const replayBeforeHash = replayHash(replayStateBefore);
  const expectedReplayAfterHash = replayHash(expectedReplayAfter.value);
  if (expectedReplayAfterHash === replayBeforeHash) return 'verifier_replay_after_state_unchanged';
  if (
    verifierDecision.evidence.replay_state_after_hash !== expectedReplayAfterHash ||
    replayHash(verifierDecision.next_replay_state) !== expectedReplayAfterHash
  ) {
    return 'verifier_replay_after_state_mismatch';
  }
  if (!stringArray(verifierDecision.non_claims)) return 'verifier_non_claims_invalid';
  if (!stringArray(verifierDecision.forbidden_claims)) return 'verifier_forbidden_claims_invalid';
  for (const marker of DEFAULT_REQUIRED_NON_CLAIMS) {
    if (!verifierDecision.non_claims.includes(marker)) return 'verifier_required_non_claim_missing';
  }
  for (const marker of DEFAULT_FORBIDDEN_CLAIMS) {
    if (!verifierDecision.forbidden_claims.includes(marker)) return 'verifier_forbidden_claim_missing';
  }
  return null;
}

function baseResult({
  verifierDecision,
  replayStateBefore,
  replayStateAfter,
  consumerDecision,
  reasonCode,
  effectCalled,
  effectWritten,
  effectResult = null,
  effectObservation = null,
  effectError = null,
}) {
  const verifierDecisionHash = decisionHash(verifierDecision);
  const safeEffectResult = redactEvidenceValue(effectResult);
  const safeEffectObservation = redactEvidenceValue(effectObservation);
  const safeEffectError = effectError
    ? {
        name: redactPrivateString(effectError.name || 'Error', 'effect-error-name'),
        message: redactPrivateString(effectError.message || 'effect_callback_failed', 'effect-error-message'),
      }
    : null;

  return redactEvidenceValue({
    result_type: CONFIGURED_RECOGNITION_CONSUMER_ADAPTER_TYPE,
    adapter_version: CONFIGURED_RECOGNITION_CONSUMER_ADAPTER_VERSION,
    consumer_decision: consumerDecision,
    reason_code: reasonCode,
    effect_called: effectCalled,
    effect_written: effectWritten,
    effect_result_hash: safeEffectResult === null ? null : safeHashCanonical(safeEffectResult),
    effect_result: safeEffectResult,
    effect_observation_hash: safeEffectObservation === null ? null : safeHashCanonical(safeEffectObservation),
    effect_observation: safeEffectObservation,
    effect_error: safeEffectError,
    verifier_decision_hash: verifierDecisionHash,
    verifier_decision: verifierDecision ? redactEvidenceValue(verifierDecision) : null,
    evidence: {
      gate_condition:
        "verifier allow + closed-form fake effect attestation + closed-form fake effect observation",
      verifier_allowed:
        verifierDecision?.decision === 'allow' && verifierDecision?.configured_recognition === true,
      verifier_reason_code: stringOrNull(verifierDecision?.reason_code),
      rule_hash: stringOrNull(verifierDecision?.evidence?.rule_hash),
      credential_hash: stringOrNull(verifierDecision?.evidence?.credential_hash),
      attempt_hash: stringOrNull(verifierDecision?.evidence?.attempt_hash),
      replay_state_before_hash: replayHash(replayStateBefore),
      replay_state_after_hash: replayHash(replayStateAfter),
      replay_state_changed: replayHash(replayStateBefore) !== replayHash(replayStateAfter),
      privacy_checked: true,
    },
    next_replay_state: replayStateAfter,
    safe_claim_ceiling: CONSUMER_ADAPTER_SAFE_CLAIM_CEILING,
    non_claims: mergeMarkerArray(DEFAULT_REQUIRED_NON_CLAIMS, verifierDecision?.non_claims),
    forbidden_claims: mergeMarkerArray(DEFAULT_FORBIDDEN_CLAIMS, verifierDecision?.forbidden_claims),
  });
}

function refusedResult({
  verifierDecision,
  replayStateBefore,
  reasonCode,
}) {
  return baseResult({
    verifierDecision,
    replayStateBefore,
    replayStateAfter: replayStateBefore,
    consumerDecision: 'refuse',
    reasonCode,
    effectCalled: false,
    effectWritten: false,
  });
}

export async function runConfiguredRecognitionConsumer(input = {}) {
  const {
    rule,
    recognition_rule: recognitionRule,
    credential,
    presented_credential: presentedCredential,
    attempt,
    attempted_action: attemptedAction,
    replay_state: replayStateInput,
    replayState: camelReplayState,
    evaluated_at: evaluatedAt,
    clock_source: clockSource,
    effect_callback: effectCallbackInput,
    effectCallback: camelEffectCallback,
    effect_observer: effectObserverInput,
    effectObserver: camelEffectObserver,
    evaluate: evaluateInput,
    verifier: verifierInput,
  } = isObject(input) ? input : {};

  const replayClone = safeClone(
    replayStateInput !== undefined ? replayStateInput : camelReplayState,
  );
  if (!replayClone.ok) {
    return baseResult({
      verifierDecision: {
        decision: 'refuse',
        configured_recognition: false,
        reason_code: 'replay_state_clone_failed',
        error: {
          name: replayClone.error?.name || 'Error',
          message: replayClone.error?.message || 'replay_state_clone_failed',
        },
      },
      replayStateBefore: {},
      replayStateAfter: {},
      consumerDecision: 'refuse',
      reasonCode: 'replay_state_clone_failed',
      effectCalled: false,
      effectWritten: false,
    });
  }

  const rawReplayShape = validateRawReplayStateShape(replayClone.value);
  if (!rawReplayShape.ok) {
    return baseResult({
      verifierDecision: {
        decision: 'refuse',
        configured_recognition: false,
        reason_code: rawReplayShape.code,
      },
      replayStateBefore: {},
      replayStateAfter: {},
      consumerDecision: 'refuse',
      reasonCode: rawReplayShape.code,
      effectCalled: false,
      effectWritten: false,
    });
  }

  const effectiveReplayState = normalizedReplayState(replayClone.value);
  const evaluator = evaluateInput || verifierInput || null;
  const effectCallback = effectCallbackInput || camelEffectCallback;
  const effectObserver = effectObserverInput || camelEffectObserver;
  const effectiveRule = rule || recognitionRule;
  const effectiveCredential = credential || presentedCredential;
  const effectiveAttempt = attempt || attemptedAction;
  const ruleSnapshot = snapshotInput(effectiveRule, 'rule_snapshot_failed');
  const credentialSnapshot = snapshotInput(effectiveCredential, 'credential_snapshot_failed');
  const attemptSnapshot = snapshotInput(effectiveAttempt, 'attempt_snapshot_failed');
  for (const snapshot of [ruleSnapshot, credentialSnapshot, attemptSnapshot]) {
    if (!snapshot.ok) {
      return baseResult({
        verifierDecision: {
          decision: 'refuse',
          configured_recognition: false,
          reason_code: snapshot.code,
        },
        replayStateBefore: effectiveReplayState,
        replayStateAfter: effectiveReplayState,
        consumerDecision: 'refuse',
        reasonCode: snapshot.code,
        effectCalled: false,
        effectWritten: false,
      });
    }
  }
  const inputBindings = computeInputBindingHashes({
    rule: ruleSnapshot.boundary,
    credential: credentialSnapshot.boundary,
    attempt: attemptSnapshot.boundary,
  });

  let localVerifierDecision;
  try {
    localVerifierDecision = evaluateConfiguredRecognition({
      rule: ruleSnapshot.boundary,
      credential: credentialSnapshot.boundary,
      attempt: attemptSnapshot.boundary,
      replay_state: clone(effectiveReplayState),
      evaluated_at: evaluatedAt,
      clock_source: clockSource,
    });
  } catch (error) {
    return baseResult({
      verifierDecision: {
        decision: 'refuse',
        configured_recognition: false,
        reason_code: 'local_verifier_exception',
        error: {
          name: error?.name || 'Error',
          message: error?.message || 'local_verifier_exception',
        },
      },
      replayStateBefore: effectiveReplayState,
      replayStateAfter: effectiveReplayState,
      consumerDecision: 'refuse',
      reasonCode: 'local_verifier_exception',
      effectCalled: false,
      effectWritten: false,
    });
  }

  if (
    !isObject(localVerifierDecision) ||
    localVerifierDecision.decision !== 'allow' ||
    localVerifierDecision.configured_recognition !== true
  ) {
    return refusedResult({
      verifierDecision: localVerifierDecision,
      replayStateBefore: effectiveReplayState,
      reasonCode: localVerifierDecision?.reason_code || 'local_verifier_result_not_allow',
    });
  }

  let verifierDecision = localVerifierDecision;
  try {
    if (evaluator) {
      verifierDecision = await evaluator({
        rule: ruleSnapshot.evaluator,
        credential: credentialSnapshot.evaluator,
        attempt: attemptSnapshot.evaluator,
        replay_state: clone(effectiveReplayState),
        evaluated_at: evaluatedAt,
        clock_source: clockSource,
      });
    }
  } catch (error) {
    return baseResult({
      verifierDecision: {
        decision: 'refuse',
        configured_recognition: false,
        reason_code: 'verifier_exception',
        error: {
          name: error?.name || 'Error',
          message: error?.message || 'verifier_exception',
        },
      },
      replayStateBefore: effectiveReplayState,
      replayStateAfter: effectiveReplayState,
      consumerDecision: 'refuse',
      reasonCode: 'verifier_exception',
      effectCalled: false,
      effectWritten: false,
    });
  }

  if (
    !isObject(verifierDecision) ||
    verifierDecision.decision !== 'allow' ||
    verifierDecision.configured_recognition !== true
  ) {
    return refusedResult({
      verifierDecision,
      replayStateBefore: effectiveReplayState,
      reasonCode: verifierDecision?.reason_code || 'verifier_result_not_allow',
    });
  }
  const allowShapeRefusal = validateAllowVerifierDecisionShape(
    verifierDecision,
    effectiveReplayState,
    inputBindings,
    credentialSnapshot.boundary,
  );
  if (allowShapeRefusal) {
    return refusedResult({
      verifierDecision,
      replayStateBefore: effectiveReplayState,
      reasonCode: allowShapeRefusal,
    });
  }
  if (decisionHash(verifierDecision) !== decisionHash(localVerifierDecision)) {
    return refusedResult({
      verifierDecision,
      replayStateBefore: effectiveReplayState,
      reasonCode: 'verifier_local_decision_mismatch',
    });
  }

  if (typeof effectCallback !== 'function') {
    return baseResult({
      verifierDecision,
      replayStateBefore: effectiveReplayState,
      replayStateAfter: effectiveReplayState,
      consumerDecision: 'effect_failed',
      reasonCode: 'effect_callback_missing',
      effectCalled: false,
      effectWritten: false,
    });
  }

  if (typeof effectObserver !== 'function') {
    return baseResult({
      verifierDecision,
      replayStateBefore: effectiveReplayState,
      replayStateAfter: effectiveReplayState,
      consumerDecision: 'effect_failed',
      reasonCode: 'effect_observer_missing',
      effectCalled: false,
      effectWritten: false,
    });
  }

  let effectResult;
  try {
    effectResult = await effectCallback({
      verifier_decision: clone(verifierDecision),
      decision_hash: decisionHash(verifierDecision),
      next_replay_state: clone(verifierDecision.next_replay_state),
    });
  } catch (error) {
    return baseResult({
      verifierDecision,
      replayStateBefore: effectiveReplayState,
      replayStateAfter: verifierDecision.next_replay_state || effectiveReplayState,
      consumerDecision: 'effect_untrusted',
      reasonCode: 'effect_callback_failed',
      effectCalled: true,
      effectWritten: false,
      effectError: error,
    });
  }

  const effectSnapshot = snapshotEffectResult(effectResult);
  if (!effectSnapshot.ok) {
    return baseResult({
      verifierDecision,
      replayStateBefore: effectiveReplayState,
      replayStateAfter: verifierDecision.next_replay_state || effectiveReplayState,
      consumerDecision: 'effect_untrusted',
      reasonCode: 'effect_callback_result_snapshot_failed',
      effectCalled: true,
      effectWritten: false,
      effectResult: effectSnapshot.value,
      effectError: effectSnapshot.error,
    });
  }

  const effectAttestationRefusal = validateEffectAttestation(effectSnapshot.value, verifierDecision);
  if (effectAttestationRefusal) {
    return baseResult({
      verifierDecision,
      replayStateBefore: effectiveReplayState,
      replayStateAfter: verifierDecision.next_replay_state || effectiveReplayState,
      consumerDecision: 'effect_untrusted',
      reasonCode: effectAttestationRefusal,
      effectCalled: true,
      effectWritten: false,
      effectResult: effectSnapshot.value,
    });
  }

  let effectObservation;
  try {
    effectObservation = await effectObserver({
      verifier_decision: clone(verifierDecision),
      decision_hash: decisionHash(verifierDecision),
      next_replay_state: clone(verifierDecision.next_replay_state),
      effect_result: clone(effectSnapshot.value),
      effect_result_hash: safeHashCanonical(effectSnapshot.value),
    });
  } catch (error) {
    return baseResult({
      verifierDecision,
      replayStateBefore: effectiveReplayState,
      replayStateAfter: verifierDecision.next_replay_state || effectiveReplayState,
      consumerDecision: 'effect_untrusted',
      reasonCode: 'effect_observer_failed',
      effectCalled: true,
      effectWritten: false,
      effectResult: effectSnapshot.value,
      effectError: error,
    });
  }

  const effectObservationSnapshot = snapshotEffectResult(effectObservation);
  if (!effectObservationSnapshot.ok) {
    return baseResult({
      verifierDecision,
      replayStateBefore: effectiveReplayState,
      replayStateAfter: verifierDecision.next_replay_state || effectiveReplayState,
      consumerDecision: 'effect_untrusted',
      reasonCode: 'effect_observer_result_snapshot_failed',
      effectCalled: true,
      effectWritten: false,
      effectResult: effectSnapshot.value,
      effectObservation: effectObservationSnapshot.value,
      effectError: effectObservationSnapshot.error,
    });
  }

  const effectObservationRefusal = validateEffectObservation(
    effectObservationSnapshot.value,
    effectSnapshot.value,
    verifierDecision,
  );
  if (effectObservationRefusal) {
    return baseResult({
      verifierDecision,
      replayStateBefore: effectiveReplayState,
      replayStateAfter: verifierDecision.next_replay_state || effectiveReplayState,
      consumerDecision: 'effect_untrusted',
      reasonCode: effectObservationRefusal,
      effectCalled: true,
      effectWritten: false,
      effectResult: effectSnapshot.value,
      effectObservation: effectObservationSnapshot.value,
    });
  }

  return baseResult({
    verifierDecision,
    replayStateBefore: effectiveReplayState,
    replayStateAfter: verifierDecision.next_replay_state || effectiveReplayState,
    consumerDecision: 'effect_written',
    reasonCode: 'effect_written_after_configured_recognition_allow',
    effectCalled: true,
    effectWritten: true,
    effectResult: effectSnapshot.value,
    effectObservation: effectObservationSnapshot.value,
  });
}

export function assertConfiguredRecognitionConsumerEffectWritten(result) {
  if (!result || result.result_type !== CONFIGURED_RECOGNITION_CONSUMER_ADAPTER_TYPE) {
    throw new Error('Configured recognition consumer result has the wrong result type');
  }
  if (
    result.consumer_decision !== 'effect_written' ||
    result.effect_called !== true ||
    result.effect_written !== true
  ) {
    throw new Error(`Configured recognition consumer did not write effect: ${result.reason_code || 'unknown'}`);
  }
  return true;
}

export function assertConfiguredRecognitionConsumerRefused(result, expectedCode = null) {
  if (!result || result.result_type !== CONFIGURED_RECOGNITION_CONSUMER_ADAPTER_TYPE) {
    throw new Error('Configured recognition consumer result has the wrong result type');
  }
  if (result.consumer_decision !== 'refuse' || result.effect_called !== false || result.effect_written !== false) {
    throw new Error('Configured recognition consumer did not refuse before effect');
  }
  if (expectedCode && result.reason_code !== expectedCode) {
    throw new Error(`Expected consumer refusal ${expectedCode}, got ${result.reason_code}`);
  }
  return true;
}
