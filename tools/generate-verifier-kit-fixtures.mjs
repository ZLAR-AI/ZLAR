#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// generate-verifier-kit-fixtures.mjs — build-time helper for build-verifier-kit.sh.
//
// Writes two README-quick-start samples into the kit bundle:
//   examples/sample-receipt.json  — Annex A V1 envelope extracted from the
//                                   bundled spec markdown. Verifies against
//                                   spec/test-key.pub.
//   examples/sample-chain.jsonl   — 5-event synthetic CC-shape audit chain
//                                   with deterministic prev_hash links.
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

mkdirSync(join(kitDir, 'examples'), { recursive: true });
writeFileSync(
  join(kitDir, 'examples', 'sample-receipt.json'),
  JSON.stringify(envelope) + '\n'
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

process.stdout.write('Sample fixtures written: examples/sample-receipt.json, examples/sample-chain.jsonl\n');
