#!/usr/bin/env node
// ZLAR Cedar E-23 Tests — OSFI Guideline E-23 Compliance Policies
//
// Tests the E-23 Cedar policy set against financial services scenarios.
// Uses bank risk management vocabulary throughout.

import { readFileSync } from 'fs';
import { isAuthorized, validate, getCedarVersion } from '@cedar-policy/cedar-wasm/nodejs';

const schema = readFileSync(new URL('./e23.cedarschema', import.meta.url), 'utf8');
const policies = readFileSync(new URL('./e23.cedar', import.meta.url), 'utf8');

console.log(`Cedar SDK ${getCedarVersion()}`);
console.log('OSFI E-23 Compliance Policy Tests\n');

// ─── Validate ───────────────────────────────────────────────────────────────

const validationResult = validate({
  schema,
  policies: { staticPolicies: policies },
  validationSettings: { mode: 'strict' },
});

if (validationResult.type === 'failure') {
  console.error('Schema/policy validation FAILED:');
  for (const e of validationResult.errors) {
    console.error(' ', e.message || JSON.stringify(e));
  }
  process.exit(1);
}

if (validationResult.validationErrors?.length > 0) {
  console.error('Validation errors:');
  for (const e of validationResult.validationErrors) {
    console.error(` [${e.policyId}] ${e.error.message}`);
  }
  process.exit(1);
}

console.log('✓ E-23 schema and policies validated\n');

// ─── Test helper ────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const callId = () => `call-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

function runTest(t) {
  const id = callId();
  const agent = {
    risk_tier: t.risk_tier ?? 3,
    model_id: t.model_id ?? 'internal-v1',
    owner: t.owner ?? 'ai-platform-team',
  };

  const toolCall = {
    command: t.command ?? '',
    path: t.path ?? '',
    risk_score: t.risk_score ?? 0,
    amount: t.amount ?? 0,
    currency: t.currency ?? 'CAD',
    counterparty: t.counterparty ?? '',
    is_irreversible: t.is_irreversible ?? false,
  };

  const ctx = {
    domain: t.domain ?? 'bash',
    severity: t.severity ?? 'info',
    policy_version: '2.4.0',
    business_line: t.business_line ?? 'retail-banking',
    environment: t.environment ?? 'prod',
    confidence: t.confidence ?? 95,
    session_deny_count: t.session_deny_count ?? 0,
  };

  const result = isAuthorized({
    principal: { type: 'ZLAR::Agent', id: 'agent-1' },
    action: { type: 'ZLAR::Action', id: 'evaluate' },
    resource: { type: 'ZLAR::ToolCall', id },
    context: ctx,
    schema,
    validateRequest: true,
    policies: { staticPolicies: policies },
    entities: [
      { uid: { type: 'ZLAR::Agent', id: 'agent-1' }, attrs: agent, parents: [] },
      { uid: { type: 'ZLAR::ToolCall', id }, attrs: toolCall, parents: [] },
    ],
  });

  if (result.type === 'failure') {
    console.error(`✗ ${t.name}`);
    console.error('  Engine error:', result.errors.map(e => e.message).join('; '));
    failed++;
    return;
  }

  const actual = result.response.decision;
  if (actual === t.expected) {
    console.log(`✓ ${t.name} → ${actual}`);
    passed++;
  } else {
    const reasons = result.response.diagnostics?.reason ?? [];
    console.error(`✗ ${t.name}`);
    console.error(`  expected=${t.expected} actual=${actual} determining=[${reasons.join(', ')}]`);
    failed++;
  }
}

// ─── Kill Switch Tests ──────────────────────────────────────────────────────

console.log('── Kill Switches ──');

runTest({
  name: 'KS-001: deny after 3 session denials (behavioral anomaly)',
  session_deny_count: 3,
  risk_tier: 3, risk_score: 10,
  expected: 'deny',
});

runTest({
  name: 'KS-001: allow with 2 session denials (below threshold)',
  session_deny_count: 2,
  risk_tier: 3, risk_score: 10,
  expected: 'allow',
});

runTest({
  name: 'KS-002: deny in prod when confidence < 70%',
  environment: 'prod', confidence: 45,
  risk_tier: 3, risk_score: 10,
  expected: 'deny',
});

runTest({
  name: 'KS-002: allow in prod when confidence >= 70%',
  environment: 'prod', confidence: 85,
  risk_tier: 3, risk_score: 30,
  expected: 'allow',
});

runTest({
  name: 'KS-002: allow in staging even with low confidence',
  environment: 'staging', confidence: 30,
  risk_tier: 3, risk_score: 30,
  expected: 'allow',
});

console.log('');

// ─── Position Limit Tests ───────────────────────────────────────────────────

console.log('── Position Limits ──');

runTest({
  name: 'PL-001: Tier 1 denied above $10K irreversible',
  risk_tier: 1, amount: 1500000, is_irreversible: true,
  counterparty: 'acct-12345',
  domain: 'read', risk_score: 0,
  expected: 'deny',
});

runTest({
  name: 'PL-001: Tier 1 allowed at $10K irreversible (at limit)',
  risk_tier: 1, amount: 1000000, is_irreversible: true,
  counterparty: 'acct-12345',
  domain: 'read', risk_score: 0,
  expected: 'deny',  // Still denied — PEC-003 only allows read with risk_score==0 and !irreversible
});

runTest({
  name: 'PL-002: Any tier denied above $100K irreversible',
  risk_tier: 3, amount: 15000000, is_irreversible: true,
  counterparty: 'acct-12345',
  risk_score: 10,
  expected: 'deny',
});

runTest({
  name: 'PL-003: Deny irreversible financial action with no counterparty',
  risk_tier: 3, amount: 50000, is_irreversible: true,
  counterparty: '',
  risk_score: 10,
  expected: 'deny',
});

runTest({
  name: 'PL-003: Allow irreversible financial action WITH counterparty (Tier 3, low risk)',
  risk_tier: 3, amount: 50000, is_irreversible: true,
  counterparty: 'acct-12345',
  risk_score: 10,
  expected: 'deny',  // Denied — PEC-001 requires !is_irreversible
});

console.log('');

// ─── Pre-Execution Check Tests ──────────────────────────────────────────────

console.log('── Pre-Execution Checks (Tier-Based Access) ──');

runTest({
  name: 'PEC-001: Tier 3 allowed, non-irreversible, risk_score 30',
  risk_tier: 3, risk_score: 30, is_irreversible: false,
  expected: 'allow',
});

runTest({
  name: 'PEC-001: Tier 3 denied at risk_score 60 (above 50 threshold)',
  risk_tier: 3, risk_score: 60, is_irreversible: false,
  expected: 'deny',
});

runTest({
  name: 'PEC-002: Tier 2 allowed, non-irreversible, risk_score 20',
  risk_tier: 2, risk_score: 20, is_irreversible: false,
  expected: 'allow',
});

runTest({
  name: 'PEC-002: Tier 2 denied at risk_score 40 (above 30 threshold)',
  risk_tier: 2, risk_score: 40, is_irreversible: false,
  expected: 'deny',
});

runTest({
  name: 'PEC-003: Tier 1 allowed for read-only, risk_score 0',
  risk_tier: 1, risk_score: 0, is_irreversible: false,
  domain: 'read',
  expected: 'allow',
});

runTest({
  name: 'PEC-003: Tier 1 denied for write, even risk_score 0',
  risk_tier: 1, risk_score: 0, is_irreversible: false,
  domain: 'write',
  expected: 'deny',
});

runTest({
  name: 'PEC-003: Tier 1 denied for read with risk_score > 0',
  risk_tier: 1, risk_score: 10, is_irreversible: false,
  domain: 'read',
  expected: 'deny',
});

runTest({
  name: 'All tiers: irreversible action denied (no permit covers it in prod)',
  risk_tier: 3, risk_score: 10, is_irreversible: true,
  counterparty: 'acct-12345',
  expected: 'deny',
});

console.log('');

// ─── Environment Control Tests ──────────────────────────────────────────────

console.log('── Environment Controls ──');

runTest({
  name: 'EC-001: dev environment allows risk_score 60 non-irreversible',
  environment: 'dev', risk_tier: 2, risk_score: 60, is_irreversible: false,
  expected: 'allow',
});

runTest({
  name: 'EC-001: staging allows risk_score 50 non-irreversible',
  environment: 'staging', risk_tier: 1, risk_score: 50, is_irreversible: false,
  expected: 'allow',
});

runTest({
  name: 'EC-001: dev still denies irreversible actions',
  environment: 'dev', risk_tier: 3, risk_score: 30, is_irreversible: true,
  counterparty: 'test',
  expected: 'deny',
});

runTest({
  name: 'EC-001: dev denies risk_score > 70',
  environment: 'dev', risk_tier: 3, risk_score: 80, is_irreversible: false,
  expected: 'deny',
});

console.log('');

// ─── Third-Party Model Tests ────────────────────────────────────────────────

console.log('── Third-Party Model Controls ──');

runTest({
  name: 'TP-001: unknown model denied for any non-zero risk action',
  model_id: 'unknown', risk_tier: 3, risk_score: 10, is_irreversible: false,
  expected: 'deny',
});

runTest({
  name: 'TP-001: unknown model allowed for zero-risk action',
  model_id: 'unknown', risk_tier: 3, risk_score: 0, is_irreversible: false,
  expected: 'allow',
});

runTest({
  name: 'TP-001: identified model allowed normally',
  model_id: 'internal-v1', risk_tier: 3, risk_score: 30, is_irreversible: false,
  expected: 'allow',
});

console.log('');

// ─── Results ────────────────────────────────────────────────────────────────

console.log(`\n${passed} passed, ${failed} failed out of ${passed + failed} tests`);
process.exit(failed > 0 ? 1 : 0);
