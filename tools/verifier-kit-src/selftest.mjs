// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Verifier Kit v0.1 — Bundle Self-Test
//
// Runs at the start of every verify.mjs / verify-chain.mjs invocation.
// Fail-fast. Cannot be silenced via flag in v0.1.
//
// Steps (in order):
//   S1. Locate kit root (caller passes).
//   S2. Read MANIFEST.json.
//   S3. Read MANIFEST.sig.
//   S4. Verify MANIFEST.sig (Ed25519) against MANIFEST.json under embedded
//       publisher pubkey.
//   S5. Cross-check kit-publisher.pub on disk against embedded const.
//   S6. Recompute SHA-256 of every file in MANIFEST; compare entries.
//   S7. Run verify-test-vectors.mjs against bundled Annex A vectors.
//
// Any failure → returns { ok: false, reason, detail }. Caller exits 4.
// ═══════════════════════════════════════════════════════════════════════════════

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createHash, verify as cryptoVerify } from 'node:crypto';
import { spawnSync } from 'node:child_process';

export function runSelfTest({ kitRoot, publisherPubkeyPem }) {
  // S2. Read MANIFEST.json
  const manifestPath = join(kitRoot, 'MANIFEST.json');
  if (!existsSync(manifestPath)) {
    return { ok: false, reason: 'MANIFEST.json missing from kit root.', detail: kitRoot };
  }
  let manifestBytes;
  let manifest;
  try {
    manifestBytes = readFileSync(manifestPath);
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch (e) {
    return { ok: false, reason: 'MANIFEST.json unreadable or invalid JSON.', detail: e.message };
  }

  // S3. Read MANIFEST.sig
  const sigPath = join(kitRoot, 'MANIFEST.sig');
  if (!existsSync(sigPath)) {
    return { ok: false, reason: 'MANIFEST.sig missing from kit root.', detail: sigPath };
  }
  let sigB64;
  try {
    sigB64 = readFileSync(sigPath, 'utf8').trim();
  } catch (e) {
    return { ok: false, reason: 'MANIFEST.sig unreadable.', detail: e.message };
  }
  let sigBytes;
  try {
    sigBytes = Buffer.from(sigB64, 'base64');
  } catch (e) {
    return { ok: false, reason: 'MANIFEST.sig is not valid base64.', detail: e.message };
  }

  // S4. Verify MANIFEST.sig against MANIFEST.json bytes (verbatim, not
  // re-canonicalized — the build script signs exactly what is on disk).
  let sigOk;
  try {
    sigOk = cryptoVerify(null, manifestBytes, publisherPubkeyPem, sigBytes);
  } catch (e) {
    return { ok: false, reason: 'MANIFEST.sig verification raised: ' + e.message, detail: null };
  }
  if (!sigOk) {
    return {
      ok: false,
      reason: 'MANIFEST signature invalid — bundle does not match the publisher key embedded in this verifier.',
      detail: `publisher_kid=${manifest.publisher_kid || '<unknown>'}`
    };
  }

  // S5. Cross-check kit-publisher.pub on disk against embedded const.
  // Belt-and-suspenders: protects against a tampered kit-publisher.pub.
  const pubPath = join(kitRoot, 'kit-publisher.pub');
  if (existsSync(pubPath)) {
    const diskPem = readFileSync(pubPath, 'utf8');
    if (diskPem.replace(/\r\n/g, '\n').trim() !== publisherPubkeyPem.replace(/\r\n/g, '\n').trim()) {
      return {
        ok: false,
        reason: 'kit-publisher.pub on disk does not match the publisher key embedded in this verifier.',
        detail: 'Either the entry-point source or kit-publisher.pub has been edited.'
      };
    }
  }
  // If kit-publisher.pub absent: S5 is advisory; embedded const remains
  // authoritative. v0.1 build script ships the file; absence is non-fatal
  // to keep the kit usable if an operator removes it.

  // S6. Recompute SHA-256 of every file in MANIFEST.
  if (!Array.isArray(manifest.files)) {
    return { ok: false, reason: 'MANIFEST.files missing or not an array.', detail: null };
  }
  for (const entry of manifest.files) {
    const p = join(kitRoot, entry.path);
    if (!existsSync(p)) {
      return { ok: false, reason: `Manifest entry missing on disk: ${entry.path}`, detail: null };
    }
    const got = createHash('sha256').update(readFileSync(p)).digest('hex');
    if (got !== entry.sha256) {
      return {
        ok: false,
        reason: `SHA-256 mismatch on ${entry.path}`,
        detail: `expected ${entry.sha256.slice(0, 16)}..., got ${got.slice(0, 16)}...`
      };
    }
  }

  // S7. Run verify-test-vectors.mjs subprocess (quiet mode).
  const testVectorsPath = join(kitRoot, 'verify-test-vectors.mjs');
  if (!existsSync(testVectorsPath)) {
    return { ok: false, reason: 'verify-test-vectors.mjs missing from kit root.', detail: null };
  }
  const proc = spawnSync(process.execPath, [testVectorsPath, '--quiet'], {
    cwd: kitRoot,
    encoding: 'utf8',
    timeout: 10_000
  });
  if (proc.status !== 0) {
    const tail = (proc.stdout || '').split('\n').slice(-10).join('\n');
    return {
      ok: false,
      reason: 'Annex A test-vector replay failed inside self-test.',
      detail: tail || (proc.stderr || '')
    };
  }

  return {
    ok: true,
    publisher_kid: manifest.publisher_kid,
    files_verified: manifest.files.length,
    test_vectors_ok: true
  };
}

export function selfTestReport(r) {
  if (r.ok) {
    return `self-test OK\n  publisher_kid: ${r.publisher_kid}\n  files_verified: ${r.files_verified}\n  test_vectors_ok: ${r.test_vectors_ok}`;
  }
  return `self-test FAIL\n  reason: ${r.reason}\n  detail: ${r.detail || ''}`;
}
