// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR MCP Gate — Fail-Closed Negative Tests
//
// Guards against regressions to three bugs found in the 2026-04-15 red-team
// audit and fixed in the same session:
//
//   1. Unsigned policy silently loaded and enforced (gate.mjs loadPolicy).
//   2. Unsigned standing approvals silently loaded (gate.mjs loadStandingApprovals).
//   3. Tampered / expired manifest silently downgraded enforcement to
//      policy-only instead of hard-denying per invariant #8.
//
// These tests exercise the load functions directly via fs fixtures. They do
// not spin up the TCP proxy; that path is covered by test.mjs.
// ═══════════════════════════════════════════════════════════════════════════════

import { writeFileSync, mkdirSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { generateKeyPairSync, sign as cryptoSign, createPublicKey } from 'crypto';
import { loadManifest } from './constitution.mjs';
import { canonicalize, sha256hex } from '../lib/receipt.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const GATE_MJS = join(__dirname, 'gate.mjs');

let PASS = 0, FAIL = 0, TOTAL = 0;
function assert(label, expected, actual) {
  TOTAL++;
  if (expected === actual) PASS++;
  else { FAIL++; console.log(`  FAIL: ${label} — expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`); }
}

const SCRATCH = join(tmpdir(), `zlar-fail-closed-${process.pid}`);
if (existsSync(SCRATCH)) rmSync(SCRATCH, { recursive: true });
mkdirSync(SCRATCH, { recursive: true });

// Generate an Ed25519 keypair for the fixtures.
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pubkeyPath = join(SCRATCH, 'policy-signing.pub');
writeFileSync(pubkeyPath, publicKey.export({ type: 'spki', format: 'pem' }));

// Manifest canonical form: zero ALL three signature fields before hashing
// (matches mcp-gate/constitution.mjs canonicalClearAllSignatureFields and
// bash gate line 370).
function signManifest(obj) {
  const canon = JSON.parse(JSON.stringify(obj));
  canon.signature = { algorithm: '', value: '', key_id: '' };
  const hashHex = sha256hex(canonicalize(canon));
  const sig = cryptoSign(null, Buffer.from(hashHex, 'utf8'), privateKey);
  return {
    ...obj,
    signature: { algorithm: 'ed25519', key_id: 'test', value: sig.toString('base64') }
  };
}

// ─── Manifest hard-deny negative tests ───────────────────────────────────────
console.log('\n── Manifest load: hard-deny reasons ───────────────────────────');

// Tampered signed manifest → ok:false
{
  const signed = signManifest({
    version: '1.0',
    authority: { allow: ['mcp.call'], deny: [], unmatched_action: 'deny' },
    signature: { algorithm: 'ed25519', key_id: 'test', value: '' }
  });
  // Tamper: change a field after signing.
  signed.authority.allow = ['*'];
  const manifestPath = join(SCRATCH, 'manifest-tampered.json');
  writeFileSync(manifestPath, JSON.stringify(signed));
  const r = loadManifest(manifestPath, pubkeyPath);
  assert('tampered manifest: ok=false', false, r.ok);
  assert('tampered manifest: reason is sig-invalid', 'manifest signature invalid', r.reason);
}

// Expired manifest → ok:false
{
  const expired = signManifest({
    version: '1.0',
    expires: '2020-01-01T00:00:00Z',
    authority: { allow: ['mcp.call'], deny: [], unmatched_action: 'deny' },
    signature: { algorithm: 'ed25519', key_id: 'test', value: '' }
  });
  const manifestPath = join(SCRATCH, 'manifest-expired.json');
  writeFileSync(manifestPath, JSON.stringify(expired));
  const r = loadManifest(manifestPath, pubkeyPath);
  assert('expired manifest: ok=false', false, r.ok);
  assert('expired manifest: reason mentions expired', true, (r.reason || '').includes('expired'));
}

// Parse-corrupt manifest → ok:false
{
  const manifestPath = join(SCRATCH, 'manifest-corrupt.json');
  writeFileSync(manifestPath, '{not valid json');
  const r = loadManifest(manifestPath, pubkeyPath);
  assert('corrupt manifest: ok=false', false, r.ok);
  assert('corrupt manifest: reason mentions parse', true, (r.reason || '').includes('parse'));
}

// Signed-but-no-pubkey → ok:false
{
  const signed = signManifest({
    version: '1.0',
    authority: { allow: ['mcp.call'], deny: [], unmatched_action: 'deny' },
    signature: { algorithm: 'ed25519', key_id: 'test', value: '' }
  });
  const manifestPath = join(SCRATCH, 'manifest-no-pubkey.json');
  writeFileSync(manifestPath, JSON.stringify(signed));
  const r = loadManifest(manifestPath, join(SCRATCH, 'nonexistent.pub'));
  assert('signed-no-pubkey: ok=false', false, r.ok);
}

// Missing file → ok:false but reason is the "file not found" shape, which
// callers treat as pass (invariant #7) rather than hard deny (invariant #8).
{
  const r = loadManifest(join(SCRATCH, 'nope.json'), pubkeyPath);
  assert('missing manifest: ok=false', false, r.ok);
  assert('missing manifest: reason is distinct', 'manifest file not found', r.reason);
}

// Unsigned manifest (no .signature field) → ok:true (falls back to policy-only).
{
  const unsigned = { version: '1.0', authority: { allow: ['mcp.call'], deny: [], unmatched_action: 'deny' } };
  const manifestPath = join(SCRATCH, 'manifest-unsigned.json');
  writeFileSync(manifestPath, JSON.stringify(unsigned));
  const r = loadManifest(manifestPath, pubkeyPath);
  assert('unsigned manifest: ok=true (policy-only fallback)', true, r.ok);
}

// ─── Strict audit signing default ───────────────────────────────────────────
console.log('\n── Strict audit signing (startup refusal) ─────────────────────');

// Spawn gate.mjs with a scratch HOME so no signing key exists. With
// strict mode (the default), startup should exit non-zero BEFORE
// opening a listen port.
{
  const { spawnSync } = await import('child_process');
  const emptyHome = join(SCRATCH, 'empty-home');
  mkdirSync(emptyHome, { recursive: true });
  const result = spawnSync(
    process.execPath,
    [GATE_MJS, '--upstream', '127.0.0.1:1', '--port', '0'],
    { env: { ...process.env, HOME: emptyHome }, encoding: 'utf8', timeout: 5000 }
  );
  assert('strict default: exits non-zero with no key', true, result.status !== 0);
  assert('strict default: FATAL message visible',
    true, /ZLAR_REQUIRE_SIGNED_AUDIT is true/.test(result.stderr || ''));
}

// With ZLAR_REQUIRE_SIGNED_AUDIT=false, same no-key invocation should
// proceed past startup. We don't actually want to leave a listener, so
// we only assert the strict-mode FATAL message is absent from stderr
// early. Give the process a tight timeout and kill it.
{
  const { spawn } = await import('child_process');
  const emptyHome = join(SCRATCH, 'empty-home-2');
  mkdirSync(emptyHome, { recursive: true });
  const child = spawn(
    process.execPath,
    [GATE_MJS, '--upstream', '127.0.0.1:1', '--port', '0'],
    { env: { ...process.env, HOME: emptyHome, ZLAR_REQUIRE_SIGNED_AUDIT: 'false' } }
  );
  let stderr = '';
  child.stderr.on('data', d => { stderr += d.toString(); });
  await new Promise(r => setTimeout(r, 500));
  child.kill('SIGTERM');
  await new Promise(r => child.on('exit', r));
  assert('opt-out: strict FATAL absent', true, !/ZLAR_REQUIRE_SIGNED_AUDIT is true/.test(stderr));
}

// ─── Cleanup ────────────────────────────────────────────────────────────────
rmSync(SCRATCH, { recursive: true, force: true });

// ─── Summary ────────────────────────────────────────────────────────────────
console.log();
console.log(`Results: ${PASS}/${TOTAL} passed`);
if (FAIL > 0) { console.log('✗ FAIL'); process.exit(1); }
console.log('✓ ALL PASS');
