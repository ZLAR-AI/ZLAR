import { canonicalize } from './canonicalize.mjs';
import { evaluateDownstreamRecognition } from './downstream-recognition-rule.mjs';
import { sha256hex } from './receipt.mjs';

export const PROTECTED_RECORDS_BOARDING_DECISION_HELPER =
  'evaluateProtectedRecordsBoardingDecision';
export const PROTECTED_RECORDS_BOARDING_DECISION_DEFAULT_SCOPE =
  'protected-records.records.write.local-destination';
export const PROTECTED_RECORDS_BOARDING_DECISION_DEFAULT_EFFECT_TYPE =
  'protected-records-local-boarding-effect-v1';

function hashOrNull(value) {
  return typeof value === 'string' && value.length > 0 ? sha256hex(value) : null;
}

function replayKey({
  replayScope,
  verifiedSignedPayloadSha256,
}) {
  return sha256hex(canonicalize({
    destination_scope: replayScope,
    verified_signed_payload_sha256: verifiedSignedPayloadSha256,
  }));
}

function replayDecision({
  receiptId,
  replayScope,
  verifiedSignedPayloadSha256,
}) {
  return {
    result_type: 'protected-records-local-boarding-replay-rule-v1',
    recognized: false,
    decision: 'refuse',
    reason_code: 'receipt_replay',
    reasons: [
      {
        code: 'receipt_replay',
        message: 'Receipt was already consumed by this local boarding destination.',
      },
    ],
    evidence: {
      replay_policy: 'single-use-scoped-receipt-binding-per-local-boarding-destination',
      replay_scope: replayScope,
      replay_key_sha256: replayKey({
        replayScope,
        verifiedSignedPayloadSha256,
      }),
      replay_identity_source: 'verified-signed-payload-sha256',
      verified_signed_payload_sha256: verifiedSignedPayloadSha256,
      // The envelope id is unsigned metadata retained for display only. It is
      // deliberately excluded from the replay key.
      receipt_id_hash: hashOrNull(receiptId),
    },
  };
}

function sanitizedRecognition(decision) {
  return {
    result_type: decision.result_type,
    recognized: decision.recognized,
    decision: decision.decision,
    reason_code: decision.reason_code,
    reasons: decision.reasons,
    evidence: {
      receipt_present: decision.evidence?.receipt_present ?? null,
      kid_hash: hashOrNull(decision.evidence?.kid),
      issuer_known: decision.evidence?.issuer_known ?? null,
      issuer_status: decision.evidence?.issuer_status ?? null,
      signature_valid: decision.evidence?.signature_valid ?? null,
      receipt_id_hash: hashOrNull(decision.evidence?.receipt_id),
      receipt_type: decision.evidence?.receipt_type ?? null,
      receipt_version: decision.evidence?.receipt_version ?? null,
      payload: {
        tool: decision.evidence?.payload?.tool ?? null,
        domain: decision.evidence?.payload?.domain ?? null,
        outcome: decision.evidence?.payload?.outcome ?? null,
        rule: decision.evidence?.payload?.rule ?? null,
        authorizer: decision.evidence?.payload?.authorizer ?? null,
        policy_version: decision.evidence?.payload?.policy_version ?? null,
        audit_event_id: decision.evidence?.payload?.audit_event_id ?? null,
        detail_hash: decision.evidence?.payload?.detail_hash ?? null,
        age_seconds: decision.evidence?.payload?.age_seconds ?? null,
      },
    },
  };
}

export function createProtectedRecordsBoardingDecisionState({
  effects = [],
  replayCache = new Set(),
} = {}) {
  if (!Array.isArray(effects)) {
    throw new Error('Protected records boarding decision effects sink must be an array');
  }
  if (!(replayCache instanceof Set)) {
    throw new Error('Protected records boarding decision replay cache must be a Set');
  }
  return { effects, replayCache };
}

export function evaluateProtectedRecordsBoardingDecision({
  actionClass = 'records.write',
  caseId = null,
  effectType = PROTECTED_RECORDS_BOARDING_DECISION_DEFAULT_EFFECT_TYPE,
  expectedReasonCode = null,
  nowEpoch,
  receipt,
  receiptClass = null,
  recognitionRule,
  replayScope = PROTECTED_RECORDS_BOARDING_DECISION_DEFAULT_SCOPE,
  state,
} = {}) {
  if (!state || !Array.isArray(state.effects) || !(state.replayCache instanceof Set)) {
    throw new Error('Protected records boarding decision requires in-memory destination state');
  }
  const effectCountBefore = state.effects.length;
  const recognitionDecision = evaluateDownstreamRecognition({
    receipt,
    recognition_rule: recognitionRule,
    now_epoch: nowEpoch,
  });
  let observedDecision = recognitionDecision;
  let acceptedOnceMarker = false;

  if (recognitionDecision.recognized === true) {
    const receiptId = recognitionDecision.evidence?.receipt_id || '';
    const verifiedSignedPayloadSha256 =
      recognitionDecision.evidence?.verified_signed_payload_sha256 || '';
    const key = replayKey({
      replayScope,
      verifiedSignedPayloadSha256,
    });

    if (state.replayCache.has(key)) {
      observedDecision = replayDecision({
        receiptId,
        replayScope,
        verifiedSignedPayloadSha256,
      });
    } else {
      state.replayCache.add(key);
      acceptedOnceMarker = true;
      state.effects.push({
        effect_type: effectType,
        action_class: actionClass,
        audit_event_id: recognitionDecision.evidence.payload.audit_event_id,
        detail_hash: recognitionDecision.evidence.payload.detail_hash,
        // Display-only envelope metadata; replay consumption is keyed by the
        // verified signed payload identity above.
        receipt_id_hash: hashOrNull(receiptId),
        transition: 'recognized_receipt_boarded',
      });
    }
  }

  const effectCountAfter = state.effects.length;
  const effectDelta = effectCountAfter - effectCountBefore;
  const decision = observedDecision.decision;
  const reasonCode = observedDecision.reason_code;
  return {
    case_id: caseId,
    receipt_class: receiptClass,
    expected_reason_code: expectedReasonCode,
    observed_reason_code: reasonCode,
    decision,
    recognized: observedDecision.recognized,
    effect_count_before: effectCountBefore,
    effect_count_after: effectCountAfter,
    effect_count_delta: effectDelta,
    refused_before_effect: decision === 'refuse' && effectDelta === 0,
    accepted_once_marker: acceptedOnceMarker,
    // Display-only envelope metadata; never an acceptance or replay key.
    receipt_id_hash: hashOrNull(receipt?.id),
    recognition: sanitizedRecognition(observedDecision),
  };
}
