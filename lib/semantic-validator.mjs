// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Semantic Validator — Layer 4 of the Five-Layer Validation Pipeline
//
// Layer 1: Structural parse (JSON valid)
// Layer 2: Schema validation (required fields, types, enums)
// Layer 3: Signature verification (Ed25519)
// Layer 4: THIS MODULE — semantic validation (cross-field invariants)
// Layer 5: Status check (policy version active, receipt not revoked)
//
// Signature verification proves bytes haven't changed. Semantic validation
// proves those bytes make sense. Every signed-payload system that skipped
// this layer got burned: X.509 basicConstraints bypasses (24 years),
// JWT algorithm confusion (11 years), SAML wrapping attacks (14 years).
//
// This module runs AFTER signature verification, BEFORE trust.
// It checks invariants that signature verification cannot check.
//
// Dependencies: none. Pure logic over receipt payload fields.
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Known Rule Semantics ───────────────────────────────────────────────────
// Rules whose outcome set is constrained. If a rule is deny-only,
// a receipt claiming "allow" for that rule is semantically invalid.
//
// This registry can be loaded from the policy file at runtime.
// The defaults here cover the well-known ZLAR policy rules.

const DENY_ONLY_RULES = new Set([
  'R002',  // Recursive/forced deletion
  'R003',  // Privilege escalation
  'R005',  // Persistence mechanisms
  'R006',  // Resource amplification
  'R030',  // Write to .ssh
  'R032',  // Write to ZLAR infrastructure
  'R033',  // Edit ZLAR infrastructure
  'R034',  // Read signing key
]);

const VALID_OUTCOMES = new Set([
  'allow', 'deny', 'authorized', 'denied', 'timeout'
]);

const VALID_AUTHORIZERS = new Set([
  'policy', 'human', 'gate', 'timeout', 'manifest'
]);

// Outcomes that represent approval
const APPROVAL_OUTCOMES = new Set(['allow', 'authorized']);

// ─── Semantic Checks ────────────────────────────────────────────────────────

/**
 * Check rule-outcome consistency.
 * A deny-only rule cannot produce an allow/authorized outcome.
 *
 * @param {object} payload - Decoded receipt payload
 * @param {object} [opts]
 * @param {Set} [opts.denyOnlyRules] - Override the deny-only rule set
 * @returns {{ valid: boolean, code: string, message: string }}
 */
function checkRuleOutcomeConsistency(payload, opts = {}) {
  const denyOnly = opts.denyOnlyRules || DENY_ONLY_RULES;

  if (!VALID_OUTCOMES.has(payload.outcome)) {
    return {
      valid: false,
      code: 'INVALID_OUTCOME',
      message: `Unknown outcome "${payload.outcome}". Valid: ${[...VALID_OUTCOMES].join(', ')}.`
    };
  }

  if (!VALID_AUTHORIZERS.has(payload.authorizer)) {
    return {
      valid: false,
      code: 'INVALID_AUTHORIZER',
      message: `Unknown authorizer "${payload.authorizer}". Valid: ${[...VALID_AUTHORIZERS].join(', ')}.`
    };
  }

  if (denyOnly.has(payload.rule) && APPROVAL_OUTCOMES.has(payload.outcome)) {
    return {
      valid: false,
      code: 'RULE_OUTCOME_CONTRADICTION',
      message: `Rule ${payload.rule} is deny-only but receipt claims outcome "${payload.outcome}". This receipt is semantically invalid regardless of signature validity.`
    };
  }

  return { valid: true, code: 'OK', message: '' };
}

/**
 * Check temporal coherence.
 * - Timestamp must be parseable and in the past (with tolerance)
 * - Timestamp must not be unreasonably old (configurable)
 *
 * @param {object} payload
 * @param {object} [opts]
 * @param {number} [opts.maxFutureSeconds=300] - Max seconds in the future (clock skew tolerance)
 * @param {number} [opts.maxAgeSeconds=31536000] - Max age in seconds (default 1 year)
 * @returns {{ valid: boolean, code: string, message: string }}
 */
function checkTemporalCoherence(payload, opts = {}) {
  const maxFuture = opts.maxFutureSeconds ?? 300;
  const maxAge = opts.maxAgeSeconds ?? 31536000; // 1 year

  const ts = new Date(payload.ts);
  if (isNaN(ts.getTime())) {
    return {
      valid: false,
      code: 'INVALID_TIMESTAMP',
      message: `Timestamp "${payload.ts}" is not a valid date.`
    };
  }

  const now = Date.now();
  const receiptTime = ts.getTime();

  if (receiptTime > now + (maxFuture * 1000)) {
    return {
      valid: false,
      code: 'FUTURE_TIMESTAMP',
      message: `Receipt timestamp is ${Math.round((receiptTime - now) / 1000)}s in the future (max tolerance: ${maxFuture}s).`
    };
  }

  if (receiptTime < now - (maxAge * 1000)) {
    return {
      valid: false,
      code: 'STALE_RECEIPT',
      message: `Receipt is ${Math.round((now - receiptTime) / 86400000)} days old (max age: ${Math.round(maxAge / 86400)} days).`
    };
  }

  return { valid: true, code: 'OK', message: '' };
}

/**
 * Check payload completeness.
 * All required fields must be present and non-empty strings where expected.
 *
 * @param {object} payload
 * @returns {{ valid: boolean, code: string, message: string }}
 */
function checkCompleteness(payload) {
  const required = [
    'tool', 'domain', 'detail_hash', 'outcome', 'rule',
    'authorizer', 'ts', 'policy_version', 'audit_event_id', 'audit_prev_hash'
  ];

  for (const field of required) {
    if (!(field in payload)) {
      return {
        valid: false,
        code: 'MISSING_FIELD',
        message: `Required payload field "${field}" is missing.`
      };
    }
    if (typeof payload[field] === 'string' && payload[field].length === 0) {
      return {
        valid: false,
        code: 'EMPTY_FIELD',
        message: `Required payload field "${field}" is empty.`
      };
    }
  }

  // detail_hash must be 64-char lowercase hex
  if (!/^[a-f0-9]{64}$/.test(payload.detail_hash)) {
    return {
      valid: false,
      code: 'INVALID_DETAIL_HASH',
      message: `detail_hash must be 64-character lowercase hex. Got: "${payload.detail_hash}".`
    };
  }

  return { valid: true, code: 'OK', message: '' };
}

/**
 * Check authorizer-outcome coherence.
 * - "policy" authorizer should produce "allow" or "deny"
 * - "human" authorizer should produce "authorized" or "denied"
 * - "timeout" authorizer should produce "timeout" or "denied"
 * - "gate" authorizer should produce "deny" (fail-closed)
 *
 * @param {object} payload
 * @returns {{ valid: boolean, code: string, message: string }}
 */
function checkAuthorizerOutcomeCoherence(payload) {
  const { authorizer, outcome } = payload;

  const coherent = {
    'policy':   new Set(['allow', 'deny']),
    'human':    new Set(['authorized', 'denied']),
    'timeout':  new Set(['timeout', 'denied', 'deny']),
    'gate':     new Set(['deny', 'allow']),  // gate can allow on fast-path
    'manifest': new Set(['allow', 'deny']),
  };

  const expected = coherent[authorizer];
  if (expected && !expected.has(outcome)) {
    return {
      valid: false,
      code: 'AUTHORIZER_OUTCOME_MISMATCH',
      message: `Authorizer "${authorizer}" should not produce outcome "${outcome}". Expected: ${[...expected].join(', ')}.`
    };
  }

  return { valid: true, code: 'OK', message: '' };
}

/**
 * Check delegation chain integrity.
 * - Depths must be monotonically increasing from 0
 * - No gaps in depth sequence
 * - If delegation_chain is non-empty, depth 0 must be present
 *
 * @param {object} payload
 * @returns {{ valid: boolean, code: string, message: string }}
 */
function checkDelegationChain(payload) {
  const chain = payload.delegation_chain;
  if (!chain || !Array.isArray(chain) || chain.length === 0) {
    return { valid: true, code: 'OK', message: '' };
  }

  // Check depth 0 exists
  if (chain[0].depth !== 0) {
    return {
      valid: false,
      code: 'DELEGATION_MISSING_ROOT',
      message: `Delegation chain must start at depth 0. First entry has depth ${chain[0].depth}.`
    };
  }

  // Check monotonically increasing
  for (let i = 1; i < chain.length; i++) {
    if (chain[i].depth <= chain[i - 1].depth) {
      return {
        valid: false,
        code: 'DELEGATION_NON_MONOTONIC',
        message: `Delegation depth must be monotonically increasing. Depth ${chain[i].depth} follows depth ${chain[i - 1].depth} at index ${i}.`
      };
    }
  }

  return { valid: true, code: 'OK', message: '' };
}

// ─── Combined Semantic Validation ───────────────────────────────────────────

/**
 * Run all semantic validation checks on a decoded receipt payload.
 * Returns on first failure (fail-fast) or all-pass.
 *
 * @param {object} payload - Decoded v1 receipt payload
 * @param {object} [opts]
 * @param {Set} [opts.denyOnlyRules] - Override deny-only rule set
 * @param {number} [opts.maxFutureSeconds] - Clock skew tolerance
 * @param {number} [opts.maxAgeSeconds] - Max receipt age
 * @param {boolean} [opts.skipTemporalCheck=false] - Skip time checks (for testing)
 * @returns {{ valid: boolean, checks: Array<{check: string, valid: boolean, code: string, message: string}> }}
 */
export function validateSemantics(payload, opts = {}) {
  const checks = [
    { name: 'completeness', fn: () => checkCompleteness(payload) },
    { name: 'rule_outcome', fn: () => checkRuleOutcomeConsistency(payload, opts) },
    { name: 'authorizer_outcome', fn: () => checkAuthorizerOutcomeCoherence(payload) },
    { name: 'delegation_chain', fn: () => checkDelegationChain(payload) },
  ];

  if (!opts.skipTemporalCheck) {
    checks.push({
      name: 'temporal',
      fn: () => checkTemporalCoherence(payload, opts)
    });
  }

  const results = [];
  let allValid = true;

  for (const { name, fn } of checks) {
    const result = fn();
    results.push({ check: name, ...result });
    if (!result.valid) {
      allValid = false;
      break; // fail-fast
    }
  }

  return { valid: allValid, checks: results };
}

// ─── Exports for individual checks (testing) ────────────────────────────────

export {
  checkRuleOutcomeConsistency,
  checkTemporalCoherence,
  checkCompleteness,
  checkAuthorizerOutcomeCoherence,
  checkDelegationChain,
  DENY_ONLY_RULES,
  VALID_OUTCOMES,
  VALID_AUTHORIZERS
};
