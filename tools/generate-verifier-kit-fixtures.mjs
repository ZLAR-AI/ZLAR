#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// generate-verifier-kit-fixtures.mjs — build-time helper for build-verifier-kit.sh.
//
// Writes three README-quick-start samples into the kit bundle:
//   examples/sample-receipt.json  — Annex A V1 envelope extracted from the
//                                   bundled spec markdown. Verifies against
//                                   spec/test-key.pub.
//   examples/sample-chain.jsonl   — 5-event synthetic CC-shape audit chain
//                                   with deterministic prev_hash links.
//   examples/trusted-receipt-issuers-v1.json
//                                — local trusted issuer registry fixture for
//                                  verify-recognition.mjs.
//
// Both samples are deterministic given identical inputs (the spec markdown +
// the constants below), so the MANIFEST SHA-256 stays reproducible across
// builds.
//
// Usage:
//   node tools/generate-verifier-kit-fixtures.mjs <kit-dir>
// ═══════════════════════════════════════════════════════════════════════════════

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

const kitDir = process.argv[2];
if (!kitDir) {
  process.stderr.write('ERROR: kit directory argument required\n');
  process.exit(2);
}

// ─── Sample receipt ──────────────────────────────────────────────────────────
// Extract Annex A V1 envelope from spec/governed-action-receipt-v1.md. V1 is
// the first "Complete signed envelope" block in the spec; it is the positive
// SIG-VALID + SEMANTIC-VALID vector used as the canonical example throughout
// the conformance profile.

const specPath = join(kitDir, 'spec', 'governed-action-receipt-v1.md');
const md = readFileSync(specPath, 'utf8');

// Regex written without literal backticks (bash-quoting hostile); use a fence
// constant built from a single non-special character class.
const fence = '`'.repeat(3);
const re = new RegExp(
  '\\*\\*Complete signed envelope\\*\\*:\\s*' + fence + 'json\\s*([\\s\\S]*?)\\s*' + fence,
  'g'
);
const m = re.exec(md);
if (!m) {
  process.stderr.write('ERROR: no "Complete signed envelope" block found in spec markdown\n');
  process.exit(1);
}
const envelope = JSON.parse(m[1]);
const payload = JSON.parse(Buffer.from(envelope.payload, 'base64url').toString('utf8'));

mkdirSync(join(kitDir, 'examples'), { recursive: true });
writeFileSync(
  join(kitDir, 'examples', 'sample-receipt.json'),
  JSON.stringify(envelope) + '\n'
);

// ─── Trusted receipt issuer registry fixture ────────────────────────────────
// A portable, local fixture registry that recognizes exactly the bundled
// sample receipt. This lets an external runner prove the scanner path without
// pretending there is a live trust registry, revocation service, custody proof,
// production downstream deployment, external attestation, or sovereign
// recognition.

const testKeyPub = readFileSync(join(kitDir, 'spec', 'test-key.pub'), 'utf8');
const registry = {
  registry_type: 'trusted-receipt-issuers-v1',
  version: 1,
  evidence_model: 'bundled-local-fixture',
  live_probing: false,
  deployment_scope: 'verifier-kit-sample',
  trusted_issuers: [
    {
      kid: envelope.kid,
      public_key_pem: testKeyPub,
      status: 'active',
    },
  ],
  accepted_policy_versions: [payload.policy_version],
  accepted_domains: [payload.domain],
  accepted_tools: [payload.tool],
  accepted_outcomes: [payload.outcome],
  required_audit_event_id: payload.audit_event_id,
  required_detail_hash: payload.detail_hash,
  non_claims: [
    'This fixture does not inspect a live or production trust registry.',
    'This fixture does not prove key custody, hardware possession, revocation truth, compromise response, or production signing identity.',
    'This fixture does not prove routed coverage, live downstream deployment recognition, production authority, external attestation, sovereign recognition, or coverage of unrouted surfaces.',
  ],
};
writeFileSync(
  join(kitDir, 'examples', 'trusted-receipt-issuers-v1.json'),
  JSON.stringify(registry, null, 2) + '\n'
);

// ─── Sample chain ────────────────────────────────────────────────────────────
// 5-event synthetic CC-shape audit JSONL. prev_hash = SHA-256(previous raw
// line); genesis prev_hash = literal string "genesis". Mirrors the chain
// fixture the test harness builds at T-KIT-8.

const sha = s => createHash('sha256').update(s, 'utf8').digest('hex');
const lines = [];
let prev = 'genesis';
for (let i = 0; i < 5; i++) {
  const ev = {
    id: 'evt-' + String(i + 1).padStart(3, '0'),
    ts: '2026-01-01T00:00:0' + i + '.000Z',
    action: 'Bash',
    domain: 'general',
    outcome: 'allow',
    rule: 'R001',
    authorizer: 'policy',
    prev_hash: prev
  };
  const line = JSON.stringify(ev);
  lines.push(line);
  prev = sha(line);
}
writeFileSync(
  join(kitDir, 'examples', 'sample-chain.jsonl'),
  lines.join('\n') + '\n'
);

process.stdout.write('Sample fixtures written: examples/sample-receipt.json, examples/sample-chain.jsonl, examples/trusted-receipt-issuers-v1.json\n');
