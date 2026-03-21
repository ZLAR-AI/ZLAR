#!/usr/bin/env node
// ZLAR Cedar PoC — Test Harness
// Evaluates Cedar policies against real gate scenarios and verifies
// decisions match the bash gate's behavior.

import { readFileSync } from 'fs';
import { isAuthorized, validate, getCedarVersion } from '@cedar-policy/cedar-wasm/nodejs';

const schema = readFileSync(new URL('./zlar.cedarschema', import.meta.url), 'utf8');
const policies = readFileSync(new URL('./zlar.cedar', import.meta.url), 'utf8');

console.log(`Cedar SDK ${getCedarVersion()}\n`);

// ─── Validate schema + policies ─────────────────────────────────────────────

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

console.log('✓ Schema and policies validated\n');

// ─── Test cases ──────────────────────────────────────────────────────────────
// Each test: { name, command, domain, expectedDecision, matchRule }
// expectedDecision: "allow" or "deny"

const tests = [
  // R012 — gate self-protection (deny)
  {
    name: 'R012: bash command touching gate binary',
    command: 'tail -3 /Users/vincentnijjar/Desktop/ZLAR/repo/var/log/audit.jsonl',
    domain: 'bash',
    expected: 'deny',
    rule: 'R012',
  },
  {
    name: 'R012: command referencing zlar-gate',
    command: 'cat /Users/vincentnijjar/Desktop/ZLAR/repo/bin/zlar-gate',
    domain: 'bash',
    expected: 'deny',
    rule: 'R012',
  },
  {
    name: 'R012: command touching policy.json',
    command: 'jq . /etc/policies/active.policy.json',
    domain: 'bash',
    expected: 'deny',
    rule: 'R012',
  },
  {
    name: 'R012: command referencing hooks',
    command: 'cat ~/.claude/hooks.json',
    domain: 'bash',
    expected: 'deny',
    rule: 'R012',
  },

  // R001 — safe read-only shell (allow)
  {
    name: 'R001: simple ls command',
    command: 'ls /Users/vincentnijjar/Desktop/ZLAR/repo/',
    domain: 'bash',
    expected: 'allow',
    rule: 'R001',
  },
  {
    name: 'R001: pwd',
    command: 'pwd',
    domain: 'bash',
    expected: 'allow',
    rule: 'R001',
  },
  {
    name: 'R001: git status',
    command: 'git status',
    domain: 'bash',
    expected: 'allow',
    rule: 'R001',
  },
  {
    name: 'R001: git diff',
    command: 'git diff HEAD',
    domain: 'bash',
    expected: 'allow',
    rule: 'R001',
  },

  // R001 compound guard — safe command WITH shell operators → deny
  {
    name: 'R001 guard: ls with pipe (blocked by unless)',
    command: 'ls /tmp | wc -l',
    domain: 'bash',
    expected: 'deny',
    rule: 'R001-guard',
  },
  {
    name: 'R001 guard: pwd with semicolon',
    command: 'pwd; whoami',
    domain: 'bash',
    expected: 'deny',
    rule: 'R001-guard',
  },

  // R014 — git push (deny / would be ask in real gate)
  {
    name: 'R014: git push',
    command: 'git push origin main',
    domain: 'bash',
    expected: 'deny',
    rule: 'R014',
  },
  {
    name: 'R014: git push with force',
    command: 'git push --force origin main',
    domain: 'bash',
    expected: 'deny',
    rule: 'R014',
  },

  // Default deny — unknown command, no matching rule
  {
    name: 'Default deny: npm install (no permit rule)',
    command: 'npm install lodash',
    domain: 'bash',
    expected: 'deny',
    rule: 'default',
  },

  // Non-bash domain — no rules match, default deny
  {
    name: 'Default deny: read domain (no rules for read)',
    command: '',
    domain: 'read',
    expected: 'deny',
    rule: 'default',
  },
];

// ─── Run tests ───────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

for (const t of tests) {
  const result = isAuthorized({
    principal: { type: 'ZLAR::Agent', id: 'claude-code' },
    action: { type: 'ZLAR::Action', id: 'evaluate' },
    resource: {
      type: 'ZLAR::ToolCall',
      id: `call-${Date.now()}`,
    },
    context: {
      domain: t.domain,
      severity: 'info',
      policy_version: '2.4.0',
    },
    schema,
    validateRequest: true,
    policies: { staticPolicies: policies },
    entities: [
      {
        uid: { type: 'ZLAR::Agent', id: 'claude-code' },
        attrs: {},
        parents: [],
      },
      {
        uid: { type: 'ZLAR::ToolCall', id: `call-${Date.now()}` },
        attrs: {
          command: t.command,
          path: '',
          risk_score: 0,
        },
        parents: [],
      },
    ],
  });

  if (result.type === 'failure') {
    console.error(`✗ ${t.name}`);
    console.error('  Engine error:', result.errors.map(e => e.message).join('; '));
    failed++;
    continue;
  }

  const actual = result.response.decision;
  const ok = actual === t.expected;

  if (ok) {
    console.log(`✓ ${t.name} → ${actual}`);
    passed++;
  } else {
    const reasons = result.response.diagnostics.reason;
    console.error(`✗ ${t.name}`);
    console.error(`  expected=${t.expected} actual=${actual} determining=[${reasons.join(', ')}]`);
    failed++;
  }
}

console.log(`\n${passed} passed, ${failed} failed out of ${tests.length} tests`);
process.exit(failed > 0 ? 1 : 0);
