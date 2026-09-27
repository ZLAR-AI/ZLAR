// Characterization tests — what v1 actually does with its unsigned envelope.
//
// These are NOT aspirational. Every assertion here records BEHAVIOUR OBSERVED on
// 2026-08-17 against the published kit and the published sample receipt. They
// pass today because they assert the defect, not the fix.
//
// When v2 lands, these tests will start failing. That is the point: someone must
// then consciously come here and change an assertion, which is a far better
// outcome than a silent regression in either direction.
//
// ── Why these exist ─────────────────────────────────────────────────────────
//
// The published spec ships nine test vectors, four of them negative. Every one
// tests PAYLOAD SEMANTICS — incoherent authorizer/outcome pairs, deny rules with
// approval outcomes, timeout mismatches, delegation depth. Not one tests the
// ENVELOPE.
//
// That is why four defects survived to 2026-08-17: the suite was structurally
// incapable of catching them. Coverage concentrated where it was cheap to write
// and was absent where consequence lived — the same lesson as the thirty-one
// installer successors, in a different domain.
//
// ── The root cause ──────────────────────────────────────────────────────────
//
// §6 of the spec signs the payload in steps 1-6 and assembles the envelope in
// step 7 — AFTER signing. So v, id, kid, iat, type and prev are all outside the
// signature. `prev` is the chain link. The published chain is therefore not
// integrity-protected.

import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const KIT = join(REPO, 'dist/zlar-verifier-kit-v0.1.0');

let pass = 0, fail = 0, skip = 0;
const props = [];
const records = (p, fn) => {
  try { fn(); pass++; props.push(['RECORDED', p]); }
  catch (e) { fail++; props.push(['CHANGED ', `${p}  → ${e.message}`]); }
};

if (!existsSync(join(KIT, 'verify.mjs'))) {
  console.log('\n  SKIP — no built kit. Run tools/build-verifier-kit.sh first.\n');
  process.exit(77);
}

const work = mkdtempSync(join(tmpdir(), 'v1-envelope-'));
const sample = JSON.parse(readFileSync(join(KIT, 'examples/sample-receipt.json'), 'utf8'));

// Returns the verifier's verdict for a receipt object.
function verdict(receipt) {
  const f = join(work, `r-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(f, JSON.stringify(receipt));
  try {
    const out = execFileSync('node', ['verify.mjs', f, '--pubkey', 'spec/test-key.pub'],
      { cwd: KIT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return out.includes('VALID') ? 'VALID' : out.trim().split('\n')[0];
  } catch (e) {
    const out = `${e.stdout ?? ''}${e.stderr ?? ''}`.trim();
    return out.split('\n').filter(Boolean).pop() ?? 'ERROR';
  }
}

const eq = (a, b, m) => { if (a !== b) throw new Error(`${m}: expected "${b}", got "${a}"`); };

// ── Baseline ───────────────────────────────────────────────────────────────

records('the unmodified published sample verifies', () => {
  eq(verdict(sample), 'VALID', 'baseline');
});

// ── The defect class ───────────────────────────────────────────────────────

records('DEFECT: the chain link `prev` can be rewritten and the receipt still verifies', () => {
  eq(verdict({ ...sample, prev: '0'.repeat(64) }), 'VALID',
     'a fabricated chain link should currently be accepted');
});

records('DEFECT: the issuance time `iat` can be rewritten and the receipt still verifies', () => {
  eq(verdict({ ...sample, iat: 1 }), 'VALID',
     'an iat rewritten to 1970 should currently be accepted');
});

records('DEFECT: `id` can be rewritten and the receipt still verifies', () => {
  eq(verdict({ ...sample, id: 'f'.repeat(44) }), 'VALID',
     'a rewritten receipt identifier should currently be accepted');
});

// ── The accident that is currently holding ─────────────────────────────────

records('type is protected BY ALLOWLIST, not by signature — and only while one value is legal', () => {
  const v = verdict({ ...sample, type: 'destination-consequence' });
  if (v === 'VALID') throw new Error('an unknown type was accepted');
  if (!/[Uu]nknown receipt type/.test(v)) throw new Error(`unexpected rejection: ${v}`);
  // The rejection comes from a hardcoded check on the single legal value, NOT
  // from the signature. v1 is therefore safe here by accident. The moment a
  // second legal type exists, relabelling between two valid types becomes
  // undetectable — which is why "every field inside the signature" is frozen
  // property one in the v2 draft.
});

// ── What IS protected ──────────────────────────────────────────────────────

records('the payload IS protected — altering signed content is caught', () => {
  const tampered = Buffer.from(JSON.stringify({ tampered: true })).toString('base64url');
  const v = verdict({ ...sample, payload: tampered });
  if (v === 'VALID') throw new Error('payload tampering was accepted');
});

// ── Report ─────────────────────────────────────────────────────────────────

console.log('\n  V1 ENVELOPE INTEGRITY — characterization of observed behaviour\n');
for (const [tag, text] of props) console.log(`  ${tag}  ${text}`);
console.log(`\n  ${pass} behaviours recorded, ${fail} changed, ${skip} skipped`);
if (fail === 0) {
  console.log('\n  All recorded behaviours still hold. The envelope remains unsigned.');
  console.log('  These assertions describe a DEFECT. When v2 fixes it, they must be');
  console.log('  updated deliberately — that is what this file is for.\n');
} else {
  console.log('\n  Behaviour has CHANGED since 2026-08-17. Confirm the change was');
  console.log('  intended, then update these assertions with the reason.\n');
}
console.log(`  Results: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
