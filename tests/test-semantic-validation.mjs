// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Semantic Validation — Test Suite
//
// Tests Layer 4 of the five-layer validation pipeline.
// Every check from the Cassandra's Gap research: rule-outcome consistency,
// authorizer-outcome coherence, temporal coherence, completeness,
// delegation chain integrity.
// ═══════════════════════════════════════════════════════════════════════════════

import {
  validateSemantics,
  checkRuleOutcomeConsistency,
  checkTemporalCoherence,
  checkCompleteness,
  checkAuthorizerOutcomeCoherence,
  checkDelegationChain,
  DENY_ONLY_RULES
} from '../lib/semantic-validator.mjs';

let pass = 0;
let fail = 0;
let total = 0;

function assert(label, expected, actual) {
  total++;
  if (expected === actual) {
    pass++;
  } else {
    fail++;
    console.log(`  FAIL: ${label}`);
    console.log(`    expected: ${JSON.stringify(expected)}`);
    console.log(`    actual:   ${JSON.stringify(actual)}`);
  }
}

// ─── Valid baseline payload ─────────────────────────────────────────────────

function validPayload(overrides = {}) {
  return {
    tool: 'Bash',
    domain: 'file',
    detail_hash: 'a'.repeat(64),
    outcome: 'deny',
    rule: 'R002',
    authorizer: 'policy',
    ts: new Date().toISOString(),
    policy_version: '2.6.0',
    manifest_agent_id: null,
    manifest_principal: null,
    delegation_chain: [],
    audit_event_id: 'test-001',
    audit_prev_hash: 'b'.repeat(64),
    ...overrides
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== Rule-Outcome Consistency ===');
console.log();

// Deny-only rules should reject allow outcomes
for (const rule of ['R002', 'R003', 'R005', 'R006', 'R030', 'R032', 'R033', 'R034']) {
  const r = checkRuleOutcomeConsistency({ outcome: 'allow', rule, authorizer: 'policy' });
  assert(`${rule} + allow = contradiction`, false, r.valid);
  assert(`${rule} contradiction code`, 'RULE_OUTCOME_CONTRADICTION', r.code);
}

// Deny-only rules should accept deny outcomes
const r1 = checkRuleOutcomeConsistency({ outcome: 'deny', rule: 'R002', authorizer: 'policy' });
assert('R002 + deny = valid', true, r1.valid);

// Non-deny-only rules should accept allow
const r2 = checkRuleOutcomeConsistency({ outcome: 'allow', rule: 'R001', authorizer: 'policy' });
assert('R001 + allow = valid', true, r2.valid);

// Unknown outcome rejected
const r3 = checkRuleOutcomeConsistency({ outcome: 'maybe', rule: 'R001', authorizer: 'policy' });
assert('unknown outcome rejected', false, r3.valid);
assert('unknown outcome code', 'INVALID_OUTCOME', r3.code);

// Unknown authorizer rejected
const r4 = checkRuleOutcomeConsistency({ outcome: 'allow', rule: 'R001', authorizer: 'skynet' });
assert('unknown authorizer rejected', false, r4.valid);

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== Authorizer-Outcome Coherence ===');
console.log();

assert('policy+allow = coherent', true, checkAuthorizerOutcomeCoherence({ authorizer: 'policy', outcome: 'allow' }).valid);
assert('policy+deny = coherent', true, checkAuthorizerOutcomeCoherence({ authorizer: 'policy', outcome: 'deny' }).valid);
assert('policy+authorized = incoherent', false, checkAuthorizerOutcomeCoherence({ authorizer: 'policy', outcome: 'authorized' }).valid);
assert('human+authorized = coherent', true, checkAuthorizerOutcomeCoherence({ authorizer: 'human', outcome: 'authorized' }).valid);
assert('human+denied = coherent', true, checkAuthorizerOutcomeCoherence({ authorizer: 'human', outcome: 'denied' }).valid);
assert('human+allow = incoherent', false, checkAuthorizerOutcomeCoherence({ authorizer: 'human', outcome: 'allow' }).valid);
assert('timeout+timeout = coherent', true, checkAuthorizerOutcomeCoherence({ authorizer: 'timeout', outcome: 'timeout' }).valid);
assert('timeout+allow = incoherent', false, checkAuthorizerOutcomeCoherence({ authorizer: 'timeout', outcome: 'allow' }).valid);
assert('manifest+deny = coherent', true, checkAuthorizerOutcomeCoherence({ authorizer: 'manifest', outcome: 'deny' }).valid);

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== Temporal Coherence ===');
console.log();

// Current time is valid
const tNow = checkTemporalCoherence({ ts: new Date().toISOString() });
assert('current timestamp valid', true, tNow.valid);

// 1 hour ago is valid
const t1h = checkTemporalCoherence({ ts: new Date(Date.now() - 3600000).toISOString() });
assert('1 hour ago valid', true, t1h.valid);

// Far future is invalid
const tFuture = checkTemporalCoherence({ ts: new Date(Date.now() + 600000).toISOString() });
assert('10 min future invalid', false, tFuture.valid);
assert('future code', 'FUTURE_TIMESTAMP', tFuture.code);

// Very old is invalid (default max 1 year)
const tOld = checkTemporalCoherence({ ts: '2020-01-01T00:00:00.000Z' });
assert('6 years old invalid', false, tOld.valid);
assert('stale code', 'STALE_RECEIPT', tOld.code);

// Invalid date string
const tBad = checkTemporalCoherence({ ts: 'not-a-date' });
assert('invalid date rejected', false, tBad.valid);
assert('invalid date code', 'INVALID_TIMESTAMP', tBad.code);

// Custom max age
const tCustom = checkTemporalCoherence(
  { ts: new Date(Date.now() - 86400000 * 10).toISOString() },
  { maxAgeSeconds: 86400 * 7 }
);
assert('10 days old with 7-day max = invalid', false, tCustom.valid);

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== Completeness ===');
console.log();

assert('valid payload = complete', true, checkCompleteness(validPayload()).valid);

// Missing required fields
for (const field of ['tool', 'domain', 'detail_hash', 'outcome', 'rule', 'authorizer', 'ts', 'policy_version', 'audit_event_id', 'audit_prev_hash']) {
  const p = validPayload();
  delete p[field];
  const r = checkCompleteness(p);
  assert(`missing ${field} = incomplete`, false, r.valid);
  assert(`missing ${field} code`, 'MISSING_FIELD', r.code);
}

// Empty required string
const pEmpty = validPayload({ tool: '' });
assert('empty tool = incomplete', false, checkCompleteness(pEmpty).valid);

// Invalid detail_hash
const pBadHash = validPayload({ detail_hash: 'not-a-hash' });
assert('bad detail_hash rejected', false, checkCompleteness(pBadHash).valid);
assert('bad hash code', 'INVALID_DETAIL_HASH', checkCompleteness(pBadHash).code);

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== Delegation Chain ===');
console.log();

assert('empty chain = valid', true, checkDelegationChain({ delegation_chain: [] }).valid);
assert('null chain = valid', true, checkDelegationChain({ delegation_chain: null }).valid);

assert('single entry depth 0 = valid', true, checkDelegationChain({
  delegation_chain: [{ agent_id: 'a', depth: 0 }]
}).valid);

assert('monotonic 0->1->2 = valid', true, checkDelegationChain({
  delegation_chain: [{ agent_id: 'a', depth: 0 }, { agent_id: 'b', depth: 1 }, { agent_id: 'c', depth: 2 }]
}).valid);

assert('non-monotonic 0->1->1 = invalid', false, checkDelegationChain({
  delegation_chain: [{ agent_id: 'a', depth: 0 }, { agent_id: 'b', depth: 1 }, { agent_id: 'c', depth: 1 }]
}).valid);

assert('missing root (starts at 1) = invalid', false, checkDelegationChain({
  delegation_chain: [{ agent_id: 'a', depth: 1 }]
}).valid);

assert('decreasing depth = invalid', false, checkDelegationChain({
  delegation_chain: [{ agent_id: 'a', depth: 0 }, { agent_id: 'b', depth: 2 }, { agent_id: 'c', depth: 1 }]
}).valid);

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== Combined validateSemantics ===');
console.log();

// Valid payload passes all checks
const vAll = validateSemantics(validPayload(), { skipTemporalCheck: true });
assert('valid payload passes', true, vAll.valid);
assert('4 checks ran', 4, vAll.checks.length);

// Rule contradiction caught by combined validator
const vContradiction = validateSemantics(validPayload({ outcome: 'allow', rule: 'R002' }), { skipTemporalCheck: true });
assert('contradiction caught', false, vContradiction.valid);
assert('contradiction check name', 'rule_outcome', vContradiction.checks.find(c => !c.valid).check);

// Authorizer mismatch caught
const vAuth = validateSemantics(validPayload({ authorizer: 'human', outcome: 'allow' }), { skipTemporalCheck: true });
assert('authorizer mismatch caught', false, vAuth.valid);

// Missing field caught
const pMissing = validPayload();
delete pMissing.tool;
const vMissing = validateSemantics(pMissing, { skipTemporalCheck: true });
assert('missing field caught', false, vMissing.valid);
assert('missing field check name', 'completeness', vMissing.checks.find(c => !c.valid).check);

// Bad delegation caught
const vDeleg = validateSemantics(validPayload({
  delegation_chain: [{ agent_id: 'a', depth: 1 }]
}), { skipTemporalCheck: true });
assert('bad delegation caught', false, vDeleg.valid);

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== Deny-Only Rule Coverage ===');
console.log();

// Verify all deny-only rules are in the set
const expectedDenyOnly = ['R002', 'R003', 'R005', 'R006', 'R030', 'R032', 'R033', 'R034'];
for (const r of expectedDenyOnly) {
  assert(`${r} in DENY_ONLY_RULES`, true, DENY_ONLY_RULES.has(r));
}

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== Prefixed Authorizers (MCP gate emits these) ===');
console.log();

// standing:<id> → allow is coherent
const vStandingAllow = validateSemantics(
  validPayload({ authorizer: 'standing:sa_abc123', outcome: 'allow', rule: 'R095' }),
  { skipTemporalCheck: true });
assert('standing:<id> allow accepted', true, vStandingAllow.valid);

// standing:<id> with deny is NOT coherent (standing approvals only auto-allow)
const vStandingDeny = validateSemantics(
  validPayload({ authorizer: 'standing:sa_abc123', outcome: 'deny', rule: 'R002' }),
  { skipTemporalCheck: true });
assert('standing:<id> deny rejected', false, vStandingDeny.valid);

// gate:<reason> deny is coherent
const vGatePrefix = validateSemantics(
  validPayload({ authorizer: 'gate:human_H14_exceeded', outcome: 'deny', rule: 'R002' }),
  { skipTemporalCheck: true });
assert('gate:<reason> deny accepted', true, vGatePrefix.valid);

// human:<chat_id> authorized is coherent
const vHumanPrefix = validateSemantics(
  validPayload({ authorizer: 'human:1234567890', outcome: 'authorized', rule: 'R095' }),
  { skipTemporalCheck: true });
assert('human:<id> authorized accepted', true, vHumanPrefix.valid);

// Unknown base still rejected
const vUnknown = validateSemantics(
  validPayload({ authorizer: 'bogus:whatever', outcome: 'allow' }),
  { skipTemporalCheck: true });
assert('unknown authorizer base rejected', false, vUnknown.valid);

// Empty-string authorizer rejected
const vEmpty = validateSemantics(
  validPayload({ authorizer: '' }),
  { skipTemporalCheck: true });
assert('empty authorizer rejected', false, vEmpty.valid);

// ═══════════════════════════════════════════════════════════════════════════════
// Summary
console.log();
console.log(`=== Results: ${pass}/${total} passed, ${fail} failed ===`);
if (fail > 0) process.exit(1);
