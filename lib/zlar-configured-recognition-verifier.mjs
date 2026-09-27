import { createHash } from 'node:crypto';
import { canonicalize } from './canonicalize.mjs';

export const CONFIGURED_RECOGNITION_VERIFIER_TYPE = 'zlar-configured-recognition-verifier-v0';
export const CONFIGURED_RECOGNITION_VERIFIER_VERSION = '0.1.0';
export const SAFE_CLAIM_CEILING =
  'ZLAR can make a no-secret local decision about whether one presented fake credential matches one configured recognition rule before any separate consumer effect.';

export const DEFAULT_REQUIRED_NON_CLAIMS = Object.freeze([
  'not_real_receipt',
  'not_registry',
  'not_governance',
  'not_production_trust',
]);

export const DEFAULT_FORBIDDEN_CLAIMS = Object.freeze([
  'real_receipt',
  'real_downstream_recognition',
  'real_downstream_refusal',
  'registry_activation',
  'personal_machine_governance',
  'production_trust',
]);

const IDENTITY_FIELDS = new Set([
  'credential_hash',
  'credential_id',
  'receipt_hash',
  'receipt_id',
]);

const RULE_HASH_FIELDS = new Set([
  'rule_hash',
  'rule_source_hash',
]);
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function stringOrNull(value) {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function integerOrNull(value) {
  if (value === null || value === undefined || value === '') return null;
  return typeof value === 'number' && Number.isInteger(value) && Number.isSafeInteger(value) ? value : null;
}

function hasOwn(value, key) {
  return isObject(value) && Object.prototype.hasOwnProperty.call(value, key);
}

function canonicalKey(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (value.charCodeAt(index) > 127) return false;
  }
  return true;
}

function looksLikeSha256Hex(value) {
  return typeof value === 'string' && SHA256_HEX_RE.test(value);
}

function optionalInteger(value) {
  if (value === undefined) {
    return { ok: true, value: null };
  }
  if (typeof value === 'number' && Number.isInteger(value)) {
    if (!Number.isSafeInteger(value)) return { ok: false, value: null };
    return { ok: true, value };
  }
  return { ok: false, value: null };
}

function containsForbiddenMarker(value, forbiddenClaims) {
  if (typeof value !== 'string') return false;
  return forbiddenClaims.some((claim) => {
    if (value === claim) return true;
    if (value === `not_${claim}`) return false;
    return value.includes(claim);
  });
}

function arrayOfStrings(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((item) => typeof item === 'string' && item.length > 0);
}

function strictStringArray(value) {
  if (!Array.isArray(value)) return { ok: false, value: [] };
  const strings = [];
  for (const item of value) {
    if (typeof item !== 'string' || item.length === 0) return { ok: false, value: [] };
    strings.push(item);
  }
  return { ok: true, value: strings };
}

function configuredStringArray(source, field, defaultValue = []) {
  if (!hasOwn(source, field)) return { ok: true, value: [...defaultValue] };
  const parsed = strictStringArray(source[field]);
  if (!parsed.ok) return parsed;
  return {
    ok: true,
    value: parsed.value.length > 0 ? parsed.value : [...defaultValue],
  };
}

function secondsFromIso(value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  const millis = Date.parse(value);
  if (!Number.isFinite(millis)) return null;
  return Math.floor(millis / 1000);
}

function sha256Hex(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export function hashCanonical(value) {
  return sha256Hex(canonicalize(value));
}

function safeHashCanonical(value) {
  try {
    return { ok: true, value: hashCanonical(value), error: null };
  } catch (error) {
    return { ok: false, value: null, error: error?.message || 'canonicalization_failed' };
  }
}

function omitTopLevelFields(value, omittedFields) {
  if (!isObject(value)) return value;
  const output = {};
  for (const key of Object.keys(value)) {
    if (!omittedFields.has(key)) output[key] = value[key];
  }
  return output;
}

export function computeConfiguredCredentialHash(credential) {
  return hashCanonical(omitTopLevelFields(credential, IDENTITY_FIELDS));
}

export function expectedConfiguredCredentialId(credentialHash) {
  return `fake-credential:${credentialHash}`;
}

export function finalizeConfiguredRecognitionCredential(credential) {
  const credentialHash = computeConfiguredCredentialHash(credential);
  const credentialId = expectedConfiguredCredentialId(credentialHash);
  return {
    ...credential,
    credential_hash: credentialHash,
    credential_id: credentialId,
    receipt_hash: credentialHash,
    receipt_id: credentialId,
  };
}

export function computeRecognitionRuleHash(rule) {
  return hashCanonical(omitTopLevelFields(rule, RULE_HASH_FIELDS));
}

export function computeAttemptHash(attempt) {
  return hashCanonical(attempt);
}

function normalizedReplayState(replayState = {}) {
  const source = isObject(replayState) ? replayState : {};
  return {
    used_credential_hashes: arrayOfStrings(source.used_credential_hashes),
    used_credential_ids: arrayOfStrings(source.used_credential_ids),
    used_nonces: arrayOfStrings(source.used_nonces),
    last_sequence_by_issuer: isObject(source.last_sequence_by_issuer)
      ? { ...source.last_sequence_by_issuer }
      : {},
    last_receipt_hash_by_issuer: isObject(source.last_receipt_hash_by_issuer)
      ? { ...source.last_receipt_hash_by_issuer }
      : {},
  };
}

function validateReplayStateShape(replayState) {
  if (replayState === undefined) return { ok: true };
  if (!isObject(replayState)) return { ok: false, code: 'replay_state_not_object' };

  for (const field of ['used_credential_hashes', 'used_credential_ids', 'used_nonces']) {
    if (hasOwn(replayState, field) && !strictStringArray(replayState[field]).ok) {
      return { ok: false, code: 'replay_state_array_field_invalid' };
    }
  }

  if (hasOwn(replayState, 'last_sequence_by_issuer')) {
    if (!isObject(replayState.last_sequence_by_issuer)) {
      return { ok: false, code: 'replay_state_cursor_field_invalid' };
    }
    for (const [key, value] of Object.entries(replayState.last_sequence_by_issuer)) {
      if (!canonicalKey(key)) {
        return { ok: false, code: 'replay_state_cursor_field_invalid' };
      }
      if (typeof value !== 'number' || !Number.isInteger(value) || !Number.isSafeInteger(value) || value < 0) {
        return { ok: false, code: 'replay_state_numeric_field_invalid' };
      }
    }
  }

  if (hasOwn(replayState, 'last_receipt_hash_by_issuer')) {
    if (!isObject(replayState.last_receipt_hash_by_issuer)) {
      return { ok: false, code: 'replay_state_cursor_field_invalid' };
    }
    for (const [key, value] of Object.entries(replayState.last_receipt_hash_by_issuer)) {
      if (!canonicalKey(key)) {
        return { ok: false, code: 'replay_state_cursor_field_invalid' };
      }
      if (!looksLikeSha256Hex(value)) {
        return { ok: false, code: 'replay_state_cursor_field_invalid' };
      }
    }
  }

  return { ok: true };
}

function validateRuleShape(rule) {
  for (const field of ['max_age_seconds', 'max_ttl_seconds']) {
    if (!hasOwn(rule, field)) continue;
    const result = optionalInteger(rule[field]);
    if (!result.ok || result.value === null || result.value < 0) {
      return { ok: false, code: 'rule_numeric_field_invalid' };
    }
  }
  for (const field of ['forbidden_claims', 'required_non_claims']) {
    if (hasOwn(rule, field) && !strictStringArray(rule[field]).ok) {
      return { ok: false, code: 'rule_array_field_invalid' };
    }
  }
  for (const field of ['target_hash', 'expected_previous_receipt_hash']) {
    if (hasOwn(rule, field) && !looksLikeSha256Hex(rule[field])) {
      return { ok: false, code: 'rule_hash_field_invalid' };
    }
  }
  return { ok: true };
}

function validateHashLabeledFields(value) {
  if (Array.isArray(value)) {
    for (const item of value) {
      const nested = validateHashLabeledFields(item);
      if (!nested.ok) return nested;
    }
    return { ok: true };
  }
  if (!isObject(value)) return { ok: true };
  for (const [key, nestedValue] of Object.entries(value)) {
    if (key.endsWith('_hash') && !looksLikeSha256Hex(nestedValue)) {
      return { ok: false, code: 'hash_labeled_field_invalid' };
    }
    const nested = validateHashLabeledFields(nestedValue);
    if (!nested.ok) return nested;
  }
  return { ok: true };
}

function appendUnique(array, value) {
  if (value && !array.includes(value)) array.push(value);
}

function addReason(reasons, code, message) {
  reasons.push({ code, message });
}

function targetRefLooksAbsolute(value) {
  if (typeof value !== 'string') return false;
  return value.startsWith('/') || value.startsWith('file:') || value.includes('/Users/');
}

function redactPrivateString(value, label = 'evidence-string') {
  if (!targetRefLooksAbsolute(value)) return value ?? null;
  return `redacted-${label}:${sha256Hex(value)}`;
}

function redactEvidenceValue(value) {
  if (typeof value === 'string') return redactPrivateString(value);
  if (Array.isArray(value)) return value.map(redactEvidenceValue);
  if (isObject(value)) {
    const output = {};
    for (const key of Object.keys(value)) {
      const redactedKey = targetRefLooksAbsolute(key)
        ? redactPrivateString(key, 'evidence-key')
        : key;
      output[redactedKey] = redactEvidenceValue(value[key]);
    }
    return output;
  }
  return value;
}

function payloadHashForAttempt(attempt) {
  if (!isObject(attempt)) return null;
  if (typeof attempt?.payload_hash === 'string' && attempt.payload_hash.length > 0) {
    return looksLikeSha256Hex(attempt.payload_hash) ? attempt.payload_hash : null;
  }
  if ('payload' in attempt) {
    return safeHashCanonical(attempt.payload).value;
  }
  return null;
}

function credentialClaimStrings(credential) {
  const claims = collectClaimStrings(credential, [], { skipTopLevelNonClaims: true });
  if (credential.production_claim === true) claims.push('production_trust');
  return claims;
}

function ruleClaimStrings(rule) {
  const scanTarget = {};
  for (const key of Object.keys(rule || {})) {
    if (key === 'forbidden_claims' || key === 'required_non_claims') continue;
    scanTarget[key] = rule[key];
  }
  return collectClaimStrings(scanTarget);
}

function collectClaimStrings(value, output = [], options = {}, depth = 0) {
  if (typeof value === 'string' && value.length > 0) {
    output.push(value);
    return output;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectClaimStrings(item, output, options, depth + 1);
    return output;
  }
  if (isObject(value)) {
    for (const key of Object.keys(value)) {
      output.push(key);
      if (options.skipTopLevelNonClaims === true && depth === 0 && key === 'non_claims') continue;
      collectClaimStrings(value[key], output, options, depth + 1);
    }
  }
  return output;
}

function baseDecision({
  rule,
  credential,
  attempt,
  evaluatedAt,
  clockSource,
  replayBefore,
  replayAfter,
  decision,
  reasons,
  computed = {},
}) {
  const ruleHash = computed.ruleHash || (isObject(rule)
    ? safeHashCanonical(omitTopLevelFields(rule, RULE_HASH_FIELDS)).value
    : null);
  const credentialHash = computed.credentialHash || (isObject(credential)
    ? safeHashCanonical(omitTopLevelFields(credential, IDENTITY_FIELDS)).value
    : null);
  const attemptHash = isObject(attempt) ? safeHashCanonical(attempt).value : null;
  const targetRef = stringOrNull(attempt?.target_ref) || stringOrNull(credential?.target_ref) || stringOrNull(rule?.target_ref);
  const targetHash = payloadHashForAttempt(attempt) || stringOrNull(credential?.target_hash) || stringOrNull(rule?.target_hash);
  const replayBeforeHash = safeHashCanonical(replayBefore).value;
  const replayAfterHash = safeHashCanonical(replayAfter).value;
  const reason = reasons[0] || {
    code: decision === 'allow' ? 'recognized' : 'refused',
    message: decision === 'allow'
      ? 'Credential matched the configured recognition rule.'
      : 'Credential was refused by the configured recognition verifier.',
  };

  return redactEvidenceValue({
    result_type: CONFIGURED_RECOGNITION_VERIFIER_TYPE,
    verifier_version: CONFIGURED_RECOGNITION_VERIFIER_VERSION,
    configured_recognition: decision === 'allow',
    decision,
    reason_code: reason.code,
    reasons,
    evidence: {
      rule_id: stringOrNull(rule?.rule_id),
      rule_version: stringOrNull(rule?.rule_version),
      rule_hash: ruleHash,
      rule_source_hash: stringOrNull(rule?.rule_source_hash),
      credential_id: stringOrNull(credential?.credential_id) || stringOrNull(credential?.receipt_id),
      credential_hash: credentialHash,
      presented_credential_hash: stringOrNull(credential?.credential_hash) || stringOrNull(credential?.receipt_hash),
      attempt_hash: attemptHash,
      action_class: stringOrNull(attempt?.action_class) || stringOrNull(credential?.action_class) || stringOrNull(rule?.action_class),
      target_ref: redactPrivateString(targetRef, 'target-ref'),
      target_ref_redacted: targetRefLooksAbsolute(targetRef),
      target_hash: targetHash,
      evaluated_at: evaluatedAt,
      clock_source: clockSource,
      replay_state_before_hash: replayBeforeHash,
      replay_state_after_hash: replayAfterHash,
      replay_state_changed: replayBeforeHash !== replayAfterHash,
      privacy_checked: true,
    },
    next_replay_state: replayAfter,
    safe_claim_ceiling: SAFE_CLAIM_CEILING,
    non_claims: [...DEFAULT_REQUIRED_NON_CLAIMS],
    forbidden_claims: [
      ...new Set([
        ...DEFAULT_FORBIDDEN_CLAIMS,
        ...arrayOfStrings(rule?.forbidden_claims),
      ]),
    ],
  });
}

function refuse(params, code, message) {
  return baseDecision({
    ...params,
    decision: 'refuse',
    reasons: [{ code, message }],
    replayAfter: params.replayBefore,
  });
}

export function evaluateConfiguredRecognition(input = {}) {
  const {
  rule,
  recognition_rule: recognitionRule,
  credential,
  presented_credential: presentedCredential,
  attempt,
  attempted_action: attemptedAction,
  replay_state: replayStateInput,
  replayState: camelReplayState,
  evaluated_at: evaluatedAtInput,
  evaluatedAt: camelEvaluatedAt,
  clock_source: clockSourceInput,
  clockSource: camelClockSource,
  } = isObject(input) ? input : {};
  const effectiveRule = rule || recognitionRule;
  const effectiveCredential = credential || presentedCredential;
  const effectiveAttempt = attempt || attemptedAction;
  const rawReplayState = replayStateInput !== undefined ? replayStateInput : camelReplayState;
  const replayBefore = normalizedReplayState(rawReplayState);
  const evaluatedAt = stringOrNull(evaluatedAtInput || camelEvaluatedAt) || new Date().toISOString();
  const clockSource = stringOrNull(clockSourceInput || camelClockSource) || 'system-clock';
  const params = {
    rule: effectiveRule,
    credential: effectiveCredential,
    attempt: effectiveAttempt,
    evaluatedAt,
    clockSource,
    replayBefore,
    computed: {},
  };

  if (!isObject(effectiveRule)) {
    return refuse(params, 'rule_not_object', 'Recognition rule must be a JSON object.');
  }
  if (!isObject(effectiveCredential)) {
    return refuse(params, 'credential_not_object', 'Presented credential must be a JSON object.');
  }
  if (!isObject(effectiveAttempt)) {
    return refuse(params, 'attempt_not_object', 'Attempted action must be a JSON object.');
  }
  for (const [value, code] of [
    [effectiveRule, 'rule_hash_field_invalid'],
    [effectiveCredential, 'credential_hash_field_invalid'],
    [effectiveAttempt, 'attempt_hash_field_invalid'],
  ]) {
    const hashFields = validateHashLabeledFields(value);
    if (!hashFields.ok) {
      return refuse(params, code, 'Hash-labeled fields must be lowercase SHA-256 hex strings.');
    }
  }
  const replayStateShape = validateReplayStateShape(rawReplayState);
  if (!replayStateShape.ok) {
    return refuse(params, replayStateShape.code, 'Replay state has an invalid shape.');
  }

  const requiredRuleFields = [
    'rule_id',
    'rule_version',
    'rule_source_hash',
    'issuer_id',
    'issuer_trust_class',
    'credential_envelope',
    'action_class',
    'policy_id',
    'target_ref',
    'target_hash',
  ];
  for (const field of requiredRuleFields) {
    if (!stringOrNull(effectiveRule[field])) {
      return refuse(params, 'rule_required_field_missing', `Recognition rule is missing required field: ${field}.`);
    }
  }

  const ruleShape = validateRuleShape(effectiveRule);
  if (!ruleShape.ok) {
    return refuse(params, ruleShape.code, 'Recognition rule has an invalid configured shape.');
  }

  let computedRuleHash;
  try {
    computedRuleHash = computeRecognitionRuleHash(effectiveRule);
  } catch {
    return refuse(params, 'rule_canonical_shape_invalid', 'Recognition rule must be canonical JSON-safe.');
  }
  params.computed.ruleHash = computedRuleHash;
  if (effectiveRule.rule_source_hash !== computedRuleHash) {
    return refuse(params, 'rule_source_hash_mismatch', 'Recognition rule source hash does not match the configured rule body.');
  }
  const forbiddenClaimsInput = configuredStringArray(effectiveRule, 'forbidden_claims');
  if (!forbiddenClaimsInput.ok) {
    return refuse(params, 'rule_array_field_invalid', 'Recognition rule forbidden_claims must be an array of strings when present.');
  }
  const forbiddenClaims = [
    ...DEFAULT_FORBIDDEN_CLAIMS,
    ...forbiddenClaimsInput.value,
  ];
  const ruleClaims = ruleClaimStrings(effectiveRule);
  for (const forbiddenClaim of forbiddenClaims) {
    if (ruleClaims.some((claim) => containsForbiddenMarker(claim, [forbiddenClaim]))) {
      return refuse(params, 'rule_forbidden_claim_present', 'Recognition rule contains a forbidden claim marker.');
    }
  }

  const requiredCredentialFields = [
    'credential_id',
    'credential_hash',
    'receipt_id',
    'receipt_hash',
    'envelope',
    'status',
    'issuer_id',
    'issuer_trust_class',
    'action_class',
    'target_ref',
    'target_hash',
    'decision',
    'policy_id',
    'issued_at',
    'expires_at',
    'sequence',
    'previous_receipt_hash',
    'nonce',
    'proof_scope',
    'non_claims',
  ];
  for (const field of requiredCredentialFields) {
    if (effectiveCredential[field] === undefined || effectiveCredential[field] === null || effectiveCredential[field] === '') {
      return refuse(params, 'credential_required_field_missing', `Presented credential is missing required field: ${field}.`);
    }
  }

  let computedCredentialHash;
  try {
    computedCredentialHash = computeConfiguredCredentialHash(effectiveCredential);
  } catch {
    return refuse(params, 'credential_canonical_shape_invalid', 'Presented credential must be canonical JSON-safe.');
  }
  params.computed.credentialHash = computedCredentialHash;
  const expectedCredentialId = expectedConfiguredCredentialId(computedCredentialHash);
  if (effectiveCredential.credential_hash !== computedCredentialHash || effectiveCredential.receipt_hash !== computedCredentialHash) {
    return refuse(params, 'credential_hash_mismatch', 'Presented credential hash does not match the canonical credential body.');
  }
  if (effectiveCredential.credential_id !== expectedCredentialId || effectiveCredential.receipt_id !== expectedCredentialId) {
    return refuse(params, 'credential_id_mismatch', 'Presented credential id does not match the canonical credential hash.');
  }

  if (replayBefore.used_credential_ids.includes(effectiveCredential.credential_id)) {
    return refuse(params, 'credential_id_replayed', 'Presented credential id has already been consumed.');
  }
  if (replayBefore.used_credential_hashes.includes(effectiveCredential.credential_hash)) {
    return refuse(params, 'credential_hash_replayed', 'Presented credential hash has already been consumed.');
  }
  if (replayBefore.used_nonces.includes(effectiveCredential.nonce)) {
    return refuse(params, 'nonce_replayed', 'Presented credential nonce has already been consumed.');
  }

  if (effectiveCredential.envelope !== effectiveRule.credential_envelope) {
    return refuse(params, 'envelope_mismatch', 'Presented credential envelope is not recognized by the configured rule.');
  }
  if (effectiveCredential.status !== 'active') {
    return refuse(params, 'status_not_active', 'Presented credential status is not active.');
  }
  if (effectiveCredential.issuer_id !== effectiveRule.issuer_id) {
    return refuse(params, 'issuer_mismatch', 'Presented credential issuer does not match the configured rule.');
  }
  if (effectiveCredential.issuer_trust_class !== effectiveRule.issuer_trust_class) {
    return refuse(params, 'issuer_trust_class_mismatch', 'Presented credential issuer trust class does not match the configured rule.');
  }
  if (effectiveCredential.policy_id !== effectiveRule.policy_id) {
    return refuse(params, 'policy_mismatch', 'Presented credential policy id does not match the configured rule.');
  }
  if (effectiveCredential.decision !== 'allow') {
    return refuse(params, 'decision_not_allow', 'Presented credential decision is not allow.');
  }

  const evaluatedEpoch = secondsFromIso(evaluatedAt);
  const issuedEpoch = secondsFromIso(effectiveCredential.issued_at);
  const expiresEpoch = secondsFromIso(effectiveCredential.expires_at);
  if (evaluatedEpoch === null || issuedEpoch === null || expiresEpoch === null) {
    return refuse(params, 'timestamp_invalid', 'Evaluation, issued, and expiry timestamps must be valid ISO strings.');
  }
  if (issuedEpoch > evaluatedEpoch) {
    return refuse(params, 'issued_in_future', 'Presented credential was issued after the evaluation time.');
  }
  if (expiresEpoch < evaluatedEpoch) {
    return refuse(params, 'credential_expired', 'Presented credential expired before the evaluation time.');
  }

  const maxAgeSecondsResult = optionalInteger(effectiveRule.max_age_seconds);
  if (!maxAgeSecondsResult.ok || (maxAgeSecondsResult.value !== null && maxAgeSecondsResult.value < 0)) {
    return refuse(params, 'rule_numeric_field_invalid', 'Recognition rule max_age_seconds must be a non-negative integer when present.');
  }
  const maxAgeSeconds = maxAgeSecondsResult.value;
  if (maxAgeSeconds !== null && evaluatedEpoch - issuedEpoch > maxAgeSeconds) {
    return refuse(params, 'credential_too_old', 'Presented credential is outside the configured freshness window.');
  }
  const maxTtlSecondsResult = optionalInteger(effectiveRule.max_ttl_seconds);
  if (!maxTtlSecondsResult.ok || (maxTtlSecondsResult.value !== null && maxTtlSecondsResult.value < 0)) {
    return refuse(params, 'rule_numeric_field_invalid', 'Recognition rule max_ttl_seconds must be a non-negative integer when present.');
  }
  const maxTtlSeconds = maxTtlSecondsResult.value;
  if (maxTtlSeconds !== null && expiresEpoch - issuedEpoch > maxTtlSeconds) {
    return refuse(params, 'ttl_too_long', 'Presented credential validity window is longer than the configured maximum.');
  }

  const sequence = integerOrNull(effectiveCredential.sequence);
  if (sequence === null) {
    return refuse(params, 'sequence_invalid', 'Presented credential sequence must be an integer.');
  }
  if (sequence < 1) {
    return refuse(params, 'sequence_invalid', 'Presented credential sequence must be a positive integer.');
  }
  const issuerId = effectiveCredential.issuer_id;
  const lastSequenceResult = optionalInteger(replayBefore.last_sequence_by_issuer[issuerId]);
  if (
    hasOwn(replayBefore.last_sequence_by_issuer, issuerId) &&
    (!lastSequenceResult.ok || lastSequenceResult.value === null || lastSequenceResult.value < 0)
  ) {
    return refuse(params, 'replay_state_numeric_field_invalid', 'Replay state last sequence must be a non-negative integer when present.');
  }
  const lastSequence = lastSequenceResult.value;
  if (lastSequence !== null && sequence <= lastSequence) {
    return refuse(params, 'sequence_not_forward', 'Presented credential sequence does not move forward for this issuer.');
  }
  const requiredPrevious = stringOrNull(replayBefore.last_receipt_hash_by_issuer[issuerId])
    || stringOrNull(effectiveRule.expected_previous_receipt_hash);
  if (requiredPrevious && effectiveCredential.previous_receipt_hash !== requiredPrevious) {
    return refuse(params, 'previous_hash_mismatch', 'Presented credential previous receipt hash does not match configured replay state.');
  }

  if (effectiveCredential.action_class !== effectiveRule.action_class || effectiveAttempt.action_class !== effectiveRule.action_class) {
    return refuse(params, 'action_class_mismatch', 'Presented credential or attempted action is outside the configured action class.');
  }
  if (targetRefLooksAbsolute(effectiveCredential.target_ref) || targetRefLooksAbsolute(effectiveAttempt.target_ref) || targetRefLooksAbsolute(effectiveRule.target_ref)) {
    return refuse(params, 'absolute_target_ref_refused', 'Absolute local target refs are refused by this no-secret verifier.');
  }
  if (effectiveCredential.target_ref !== effectiveRule.target_ref || effectiveAttempt.target_ref !== effectiveRule.target_ref) {
    return refuse(params, 'target_ref_mismatch', 'Presented credential or attempted action target ref does not exactly match the configured rule.');
  }

  const attemptPayloadHash = payloadHashForAttempt(effectiveAttempt);
  if (!attemptPayloadHash) {
    return refuse(params, 'attempt_payload_hash_missing', 'Attempted action must supply a payload hash or payload.');
  }
  const attemptShapeHash = safeHashCanonical(effectiveAttempt);
  if (!attemptShapeHash.ok) {
    return refuse(params, 'attempt_canonical_shape_invalid', 'Attempted action must be canonical JSON-safe.');
  }
  if (
    effectiveCredential.target_hash !== effectiveRule.target_hash ||
    attemptPayloadHash !== effectiveRule.target_hash
  ) {
    return refuse(params, 'target_hash_mismatch', 'Presented credential or attempted action payload hash does not match the configured rule.');
  }

  const requiredNonClaimsInput = configuredStringArray(effectiveRule, 'required_non_claims', DEFAULT_REQUIRED_NON_CLAIMS);
  if (!requiredNonClaimsInput.ok) {
    return refuse(params, 'rule_array_field_invalid', 'Recognition rule required_non_claims must be an array of strings when present.');
  }
  const requiredNonClaims = requiredNonClaimsInput.value;
  for (const requiredNonClaim of requiredNonClaims) {
    if (containsForbiddenMarker(requiredNonClaim, forbiddenClaims)) {
      return refuse(params, 'rule_required_non_claim_forbidden', 'Recognition rule cannot require a forbidden claim marker as a non-claim.');
    }
  }
  const credentialNonClaimsInput = strictStringArray(effectiveCredential.non_claims);
  if (!credentialNonClaimsInput.ok) {
    return refuse(params, 'credential_array_field_invalid', 'Presented credential non_claims must be an array of strings.');
  }
  const credentialNonClaims = credentialNonClaimsInput.value;
  for (const requiredNonClaim of requiredNonClaims) {
    if (!credentialNonClaims.includes(requiredNonClaim)) {
      return refuse(params, 'required_non_claim_missing', 'Presented credential is missing a required non-claim marker.');
    }
  }
  for (const credentialNonClaim of credentialNonClaims) {
    if (!requiredNonClaims.includes(credentialNonClaim)) {
      return refuse(params, 'unrecognized_non_claim_present', 'Presented credential contains an unrecognized non-claim marker.');
    }
  }

  const presentedClaims = credentialClaimStrings(effectiveCredential);
  for (const forbiddenClaim of forbiddenClaims) {
    if (presentedClaims.some((claim) => containsForbiddenMarker(claim, [forbiddenClaim]))) {
      return refuse(params, 'forbidden_claim_present', 'Presented credential contains a forbidden claim marker.');
    }
  }

  const replayAfter = clone(replayBefore);
  appendUnique(replayAfter.used_credential_hashes, effectiveCredential.credential_hash);
  appendUnique(replayAfter.used_credential_ids, effectiveCredential.credential_id);
  appendUnique(replayAfter.used_nonces, effectiveCredential.nonce);
  replayAfter.last_sequence_by_issuer[issuerId] = sequence;
  replayAfter.last_receipt_hash_by_issuer[issuerId] = effectiveCredential.receipt_hash;

  return baseDecision({
    rule: effectiveRule,
    credential: effectiveCredential,
    attempt: effectiveAttempt,
    evaluatedAt,
    clockSource,
    replayBefore,
    replayAfter,
    decision: 'allow',
    reasons: [{ code: 'recognized', message: 'Credential matched the configured recognition rule.' }],
    computed: params.computed,
  });
}

export function assertConfiguredRecognitionAllowed(decision) {
  if (!decision || decision.result_type !== CONFIGURED_RECOGNITION_VERIFIER_TYPE) {
    throw new Error('Configured recognition decision has the wrong result type');
  }
  if (decision.decision !== 'allow' || decision.configured_recognition !== true) {
    throw new Error(`Configured recognition did not allow: ${decision.reason_code || 'unknown'}`);
  }
  return true;
}

export function assertConfiguredRecognitionRefused(decision, expectedCode = null) {
  if (!decision || decision.result_type !== CONFIGURED_RECOGNITION_VERIFIER_TYPE) {
    throw new Error('Configured recognition decision has the wrong result type');
  }
  if (decision.decision !== 'refuse' || decision.configured_recognition !== false) {
    throw new Error('Configured recognition decision did not refuse');
  }
  if (expectedCode && decision.reason_code !== expectedCode) {
    throw new Error(`Expected refusal ${expectedCode}, got ${decision.reason_code}`);
  }
  return true;
}
