import { verifyReceiptV1 } from './receipt.mjs';

export const DOWNSTREAM_RECOGNITION_RULE_TYPE = 'downstream-recognition-rule-v1';
export const SAFE_CLAIM_CEILING =
  'ZLAR can evaluate whether a supplied signed v1 receipt is recognized by one configured downstream recognition rule.';

export const DEFAULT_NON_CLAIMS = Object.freeze([
  'This helper does not prove production deployment.',
  'This helper does not prove external attestation or sovereign recognition.',
  'This helper does not prove coverage of unrouted paths.',
  'This helper does not make Worker Receipts into issuer credentials.',
]);

const DEFAULT_ACCEPTED_OUTCOMES = Object.freeze(['allow', 'authorized']);

function arrayOfStrings(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((item) => typeof item === 'string' && item.length > 0);
}

function stringOrNull(value) {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function numberOrNull(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function acceptedIssuers(rule) {
  const issuers = rule.accepted_issuers || rule.acceptedIssuers || [];
  if (!Array.isArray(issuers)) return [];
  return issuers
    .filter((issuer) => issuer && typeof issuer === 'object')
    .map((issuer) => ({
      kid: stringOrNull(issuer.kid || issuer.key_id || issuer.keyId),
      public_key_pem: stringOrNull(issuer.public_key_pem || issuer.publicKeyPem || issuer.public_key || issuer.publicKey),
      trust_anchor_sha256: stringOrNull(issuer.trust_anchor_sha256 || issuer.trustAnchorSha256),
      status: stringOrNull(issuer.status),
    }))
    .filter((issuer) => issuer.kid);
}

function activeIssuerFor(receipt, rule) {
  const kid = stringOrNull(receipt?.kid);
  const issuer = acceptedIssuers(rule).find((candidate) => candidate.kid === kid) || null;
  return { kid, issuer };
}

function ageSeconds(payload, nowEpoch) {
  const ts = new Date(payload.ts);
  if (Number.isNaN(ts.getTime())) return null;
  return Math.floor(nowEpoch - (ts.getTime() / 1000));
}

function addReason(reasons, code, message) {
  reasons.push({ code, message });
}

function refuse(reason, evidence = {}) {
  return {
    result_type: DOWNSTREAM_RECOGNITION_RULE_TYPE,
    recognized: false,
    decision: 'refuse',
    reason_code: reason.code,
    reasons: [reason],
    evidence,
    safe_claim_ceiling: SAFE_CLAIM_CEILING,
    non_claims: [...DEFAULT_NON_CLAIMS],
  };
}

function decisionFromReasons(reasons, evidence) {
  const recognized = reasons.length === 0;
  return {
    result_type: DOWNSTREAM_RECOGNITION_RULE_TYPE,
    recognized,
    decision: recognized ? 'accept' : 'refuse',
    reason_code: recognized ? 'recognized' : reasons[0].code,
    reasons: recognized
      ? [{ code: 'recognized', message: 'Receipt matched the configured downstream recognition rule.' }]
      : reasons,
    evidence,
    safe_claim_ceiling: SAFE_CLAIM_CEILING,
    non_claims: [...DEFAULT_NON_CLAIMS],
  };
}

export function evaluateDownstreamRecognition({
  receipt,
  recognition_rule: recognitionRule,
  recognitionRule: camelRecognitionRule,
  now_epoch: nowEpochInput,
  nowEpoch: camelNowEpoch,
} = {}) {
  const rule = recognitionRule || camelRecognitionRule || {};
  const nowEpoch = numberOrNull(nowEpochInput ?? camelNowEpoch) ?? Math.floor(Date.now() / 1000);

  if (!receipt) {
    return refuse(
      { code: 'receipt_missing', message: 'No receipt was supplied to the downstream recognition rule.' },
      { receipt_present: false }
    );
  }
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    return refuse(
      { code: 'receipt_not_object', message: 'Receipt must be a JSON object.' },
      { receipt_present: true }
    );
  }
  if (receipt.v !== 1 || receipt.type !== 'governed-action') {
    return refuse(
      { code: 'unsupported_receipt_format', message: 'Only signed governed-action v1 receipts are recognized by this helper.' },
      {
        receipt_present: true,
        receipt_version: receipt.v ?? null,
        receipt_type: receipt.type ?? null,
      }
    );
  }

  const { kid, issuer } = activeIssuerFor(receipt, rule);
  if (!kid || !issuer) {
    return refuse(
      { code: 'unknown_issuer', message: 'Receipt kid is not recognized by the configured downstream rule.' },
      { receipt_present: true, kid: kid || null, issuer_known: false }
    );
  }
  if (!issuer.status) {
    return refuse(
      { code: 'issuer_status_missing', message: 'Recognized issuer is missing an explicit status.' },
      { receipt_present: true, kid, issuer_known: true, issuer_status: null }
    );
  }
  if (issuer.status === 'compromised') {
    return refuse(
      { code: 'issuer_compromised', message: 'Receipt issuer is known but marked compromised.' },
      { receipt_present: true, kid, issuer_known: true, issuer_status: issuer.status }
    );
  }
  if (issuer.status === 'revoked') {
    return refuse(
      { code: 'issuer_revoked', message: 'Receipt issuer is known but marked revoked.' },
      { receipt_present: true, kid, issuer_known: true, issuer_status: issuer.status }
    );
  }
  if (issuer.status !== 'active') {
    return refuse(
      { code: 'issuer_not_active', message: 'Receipt issuer is known but not active.' },
      { receipt_present: true, kid, issuer_known: true, issuer_status: issuer.status }
    );
  }
  if (!issuer.public_key_pem) {
    return refuse(
      { code: 'issuer_key_missing', message: 'Recognized issuer is missing a downstream-verifiable public key.' },
      {
        receipt_present: true,
        kid,
        issuer_known: true,
        issuer_status: issuer.status,
        trust_anchor_present: Boolean(issuer.trust_anchor_sha256),
      }
    );
  }

  const verified = verifyReceiptV1(receipt, issuer.public_key_pem);
  if (!verified.valid) {
    return refuse(
      { code: 'receipt_invalid', message: verified.reason },
      {
        receipt_present: true,
        kid,
        issuer_known: true,
        issuer_status: issuer.status,
        signature_valid: false,
      }
    );
  }

  const payload = verified.payload || {};
  const reasons = [];
  const acceptedPolicyVersions = arrayOfStrings(rule.accepted_policy_versions || rule.acceptedPolicyVersions);
  const acceptedDomains = arrayOfStrings(rule.accepted_domains || rule.acceptedDomains);
  const acceptedTools = arrayOfStrings(rule.accepted_tools || rule.acceptedTools);
  const acceptedOutcomes = arrayOfStrings(rule.accepted_outcomes || rule.acceptedOutcomes);
  const effectiveAcceptedOutcomes = acceptedOutcomes.length > 0
    ? acceptedOutcomes
    : [...DEFAULT_ACCEPTED_OUTCOMES];

  if (acceptedPolicyVersions.length > 0 && !acceptedPolicyVersions.includes(payload.policy_version)) {
    addReason(reasons, 'policy_not_recognized', 'Receipt policy_version is not recognized by the downstream rule.');
  }
  if (acceptedDomains.length > 0 && !acceptedDomains.includes(payload.domain)) {
    addReason(reasons, 'domain_out_of_scope', 'Receipt domain is outside the downstream recognition scope.');
  }
  if (acceptedTools.length > 0 && !acceptedTools.includes(payload.tool)) {
    addReason(reasons, 'tool_out_of_scope', 'Receipt tool is outside the downstream recognition scope.');
  }
  if (!effectiveAcceptedOutcomes.includes(payload.outcome)) {
    addReason(reasons, 'outcome_not_boarding', 'Receipt outcome is not an accepted boarding outcome.');
  }

  const requiredAuditEventId = stringOrNull(rule.required_audit_event_id || rule.requiredAuditEventId);
  if (requiredAuditEventId && payload.audit_event_id !== requiredAuditEventId) {
    addReason(reasons, 'audit_event_mismatch', 'Receipt audit_event_id does not match the downstream action requirement.');
  }

  const requiredDetailHash = stringOrNull(rule.required_detail_hash || rule.requiredDetailHash);
  if (requiredDetailHash && payload.detail_hash !== requiredDetailHash) {
    addReason(reasons, 'detail_hash_mismatch', 'Receipt detail_hash does not match the downstream action requirement.');
  }

  const maxAgeSeconds = numberOrNull(rule.max_age_seconds ?? rule.maxAgeSeconds);
  const computedAgeSeconds = ageSeconds(payload, nowEpoch);
  if (maxAgeSeconds !== null) {
    if (computedAgeSeconds === null || computedAgeSeconds < 0 || computedAgeSeconds > maxAgeSeconds) {
      addReason(reasons, 'receipt_stale', 'Receipt is outside the downstream freshness window.');
    }
  }

  return decisionFromReasons(reasons, {
    receipt_present: true,
    kid,
    issuer_known: true,
    issuer_status: issuer.status,
    signature_valid: true,
    verified_signed_payload_sha256: verified.verified_signed_payload_sha256,
    receipt_id: stringOrNull(receipt.id),
    receipt_type: receipt.type,
    receipt_version: receipt.v,
    payload: {
      tool: stringOrNull(payload.tool),
      domain: stringOrNull(payload.domain),
      outcome: stringOrNull(payload.outcome),
      rule: stringOrNull(payload.rule),
      authorizer: stringOrNull(payload.authorizer),
      policy_version: stringOrNull(payload.policy_version),
      audit_event_id: stringOrNull(payload.audit_event_id),
      detail_hash: stringOrNull(payload.detail_hash),
      ts: stringOrNull(payload.ts),
      age_seconds: computedAgeSeconds,
    },
    rule: {
      deployment_scope: stringOrNull(rule.deployment_scope || rule.deploymentScope),
      accepted_policy_versions: acceptedPolicyVersions,
      accepted_domains: acceptedDomains,
      accepted_tools: acceptedTools,
      accepted_outcomes: effectiveAcceptedOutcomes,
      max_age_seconds: maxAgeSeconds,
      required_audit_event_id: requiredAuditEventId,
      required_detail_hash: requiredDetailHash,
    },
  });
}

export function assertRecognized(decision) {
  if (!decision || decision.result_type !== DOWNSTREAM_RECOGNITION_RULE_TYPE) {
    throw new Error('Downstream recognition decision has the wrong result type');
  }
  if (decision.recognized !== true || decision.decision !== 'accept') {
    const code = decision.reason_code || 'unknown';
    throw new Error(`Downstream receipt was not recognized: ${code}`);
  }
  return true;
}

export function assertRefused(decision, expectedCode = null) {
  if (!decision || decision.result_type !== DOWNSTREAM_RECOGNITION_RULE_TYPE) {
    throw new Error('Downstream recognition decision has the wrong result type');
  }
  if (decision.recognized !== false || decision.decision !== 'refuse') {
    throw new Error('Downstream recognition decision did not refuse');
  }
  if (expectedCode && decision.reason_code !== expectedCode) {
    throw new Error(`Expected refusal ${expectedCode}, got ${decision.reason_code}`);
  }
  return true;
}
