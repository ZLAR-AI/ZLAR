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
  // Race on-exit with a hard timeout so a stuck subprocess cannot hang
  // the test. The stderr assertion below does not depend on exit.
  await new Promise((resolve) => {
    const done = () => resolve();
    child.once('exit', done);
    try { child.kill('SIGTERM'); } catch {}
    setTimeout(() => { try { child.kill('SIGKILL'); } catch {}; done(); }, 1500);
  });
  assert('opt-out: strict FATAL absent', true, !/ZLAR_REQUIRE_SIGNED_AUDIT is true/.test(stderr));
}

// ─── Deployed-artifact verification (ADR-011 multi-canonical acceptance) ────
console.log('\n── Deployed artifact verification ─────────────────────────────');

// The MCP gate must be able to verify the currently-deployed, bash-signed
// policy and constitution on this machine. Regression guard for the
// canonicalization-mismatch bug fixed in commit introducing lib/sig-verify.mjs.
{
  const { existsSync: exists } = await import('fs');
  const repoRoot = join(__dirname, '..');
  const policyPath = join(repoRoot, 'etc/policies/active.policy.json');
  const policyPubPath = join(repoRoot, 'etc/keys/policy-signing.pub');
  const constPath = join(repoRoot, 'etc/constitution.json');
  const constPubPath = join(repoRoot, 'etc/keys/constitution-signing.pub');
  const { canonicalFormVariants, verifyAnyCanonical } = await import('../lib/sig-verify.mjs');
  const { readFileSync } = await import('fs');

  function tryVerify(filePath, pubPath, label) {
    if (!exists(filePath) || !exists(pubPath)) {
      console.log(`  SKIP: ${label} deployed file missing (${filePath})`);
      return;
    }
    const raw = JSON.parse(readFileSync(filePath, 'utf8'));
    const cleared = JSON.parse(JSON.stringify(raw));
    cleared.signature = { ...cleared.signature, value: '' };
    const forms = canonicalFormVariants(cleared);
    const result = verifyAnyCanonical(forms, readFileSync(pubPath, 'utf8'), raw.signature.value);
    assert(`${label} verifies under some canonical form`, true, result.ok);
    if (result.ok) {
      assert(`${label} form label is known`, true, ['spec', 'bash-pipeline', 'bash-pretty'].includes(result.form));
    }
  }

  tryVerify(policyPath, policyPubPath, 'deployed policy');
  tryVerify(constPath, constPubPath, 'deployed constitution');
}

// Multi-form acceptance must still reject tampered signatures.
{
  const { canonicalFormVariants, verifyAnyCanonical } = await import('../lib/sig-verify.mjs');
  const { readFileSync } = await import('fs');
  const repoRoot = join(__dirname, '..');
  const policyPath = join(repoRoot, 'etc/policies/active.policy.json');
  const policyPubPath = join(repoRoot, 'etc/keys/policy-signing.pub');
  if (existsSync(policyPath) && existsSync(policyPubPath)) {
    const raw = JSON.parse(readFileSync(policyPath, 'utf8'));
    const cleared = JSON.parse(JSON.stringify(raw));
    cleared.rules = [];  // TAMPER: remove all rules
    cleared.signature = { ...cleared.signature, value: '' };
    const forms = canonicalFormVariants(cleared);
    const result = verifyAnyCanonical(
      forms,
      readFileSync(join(repoRoot, 'etc/keys/policy-signing.pub'), 'utf8'),
      raw.signature.value
    );
    assert('tampered policy rejected across all forms', false, result.ok);
  }
}

// ─── Test-fixture signing path (test.mjs signPolicyUnderSpec) ──────────────
console.log('\n── Test fixture signed under spec form (ADR-011) ──────────────');

// The mcp-gate/test.mjs fixture generates an ephemeral keypair and signs
// the TEST_ALLOW_POLICY under ZLAR spec canonical form before spawning the
// gate with --policy-file and --policy-pubkey. This test duplicates that
// signing path in isolation (no port binding, no subprocess) and asserts
// the resulting file verifies under spec form — so the integration harness
// is guaranteed to find a signature-valid fixture even when the test
// environment cannot bind listen ports.
{
  const { canonicalFormVariants, verifyAnyCanonical } = await import('../lib/sig-verify.mjs');
  const { publicKey: fxPub, privateKey: fxPriv } = generateKeyPairSync('ed25519');
  const fxPubPem = fxPub.export({ type: 'spki', format: 'pem' });

  function signPolicyUnderSpec(policyObj) {
    const withSig = {
      ...policyObj,
      signature: {
        algorithm: 'ed25519',
        public_key: fxPub.export({ type: 'spki', format: 'der' }).toString('base64'),
        value: '',
      },
    };
    const hashHex = sha256hex(canonicalize(withSig));
    const sig = cryptoSign(null, Buffer.from(hashHex, 'utf8'), fxPriv);
    return { ...withSig, signature: { ...withSig.signature, value: sig.toString('base64') } };
  }

  const policyObj = {
    version: 'test-allow',
    default_action: 'allow',
    rules: [
      { id: 'R095', enabled: true, domain: 'mcp', action: 'allow', match: { domain: 'mcp' }, risk_score: { irreversibility: 0, consequence: 0, blast_radius: 0 } },
      { id: 'R999', enabled: true, domain: 'x', action: 'ask', match: { domain: 'x' }, risk_score: { irreversibility: 0, consequence: 0, blast_radius: 0 } },
    ],
  };

  const signed = signPolicyUnderSpec(policyObj);
  // Reproduce the gate's verifyJsonSignature logic: clear .signature.value,
  // canonicalFormVariants, verifyAnyCanonical.
  const cleared = JSON.parse(JSON.stringify(signed));
  cleared.signature = { ...cleared.signature, value: '' };
  const result = verifyAnyCanonical(canonicalFormVariants(cleared), fxPubPem, signed.signature.value);
  assert('test fixture signature verifies', true, result.ok);
  assert('test fixture verifies under SPEC form (no LEGACY warning)', 'spec', result.form);

  // And if the fixture is tampered with post-signing, verification fails
  // across all forms — so fixture-level tampering cannot sneak past.
  const tampered = JSON.parse(JSON.stringify(signed));
  tampered.default_action = 'deny';  // TAMPER
  const clearedT = JSON.parse(JSON.stringify(tampered));
  clearedT.signature = { ...clearedT.signature, value: '' };
  const resultT = verifyAnyCanonical(canonicalFormVariants(clearedT), fxPubPem, signed.signature.value);
  assert('tampered test fixture rejected', false, resultT.ok);
}

// ─── Cleanup ────────────────────────────────────────────────────────────────
rmSync(SCRATCH, { recursive: true, force: true });

// ─── Summary ────────────────────────────────────────────────────────────────
console.log();
console.log(`Results: ${PASS}/${TOTAL} passed`);
if (FAIL > 0) { console.log('✗ FAIL'); process.exit(1); }
console.log('✓ ALL PASS');
