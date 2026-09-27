// ═══════════════════════════════════════════════════════════════════════════════
// zlar-verify CLI — verifier boundary tests
//
// Tests the standalone CLI boundary that humans and relying parties see:
// VALID, INVALID, and UNKNOWN-SIGNER must stay distinct.
// ═══════════════════════════════════════════════════════════════════════════════

import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const projectDir = join(__dirname, '..');
const verifyBin = join(projectDir, 'bin', 'zlar-verify');
const libPath = join(projectDir, 'lib', 'receipt.mjs');

const {
  createReceiptV1FromEvent,
  receiptHashV1,
  signReceiptV1,
  pubkeyFingerprint
} = await import(libPath);

let pass = 0;
let fail = 0;
let total = 0;

function assert(label, expected, actual) {
  total++;
  if (expected === actual) {
    pass++;
    return;
  }
  fail++;
  console.log(`  FAIL: ${label}`);
  console.log(`    expected: ${JSON.stringify(expected)}`);
  console.log(`    actual:   ${JSON.stringify(actual)}`);
}

function assertIncludes(label, haystack, needle) {
  total++;
  if (haystack.includes(needle)) {
    pass++;
    return;
  }
  fail++;
  console.log(`  FAIL: ${label}`);
  console.log(`    missing: ${JSON.stringify(needle)}`);
}

function assertNotIncludes(label, haystack, needle) {
  total++;
  if (!haystack.includes(needle)) {
    pass++;
    return;
  }
  fail++;
  console.log(`  FAIL: ${label}`);
  console.log(`    unexpected: ${JSON.stringify(needle)}`);
}

function runVerify(args, input = null) {
  return spawnSync(process.execPath, [verifyBin, ...args], {
    input,
    encoding: 'utf8'
  });
}

function jsonFrom(run) {
  try {
    return JSON.parse(run.stdout);
  } catch (err) {
    throw new Error(`stdout was not JSON: ${run.stdout}`);
  }
}

function keyPair(prefix) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  const privatePath = join(tmpDir, `${prefix}.key`);
  const publicPath = join(tmpDir, `${prefix}.pub`);
  writeFileSync(privatePath, privatePem);
  writeFileSync(publicPath, publicPem);
  return {
    privatePem,
    publicPem,
    privatePath,
    publicPath,
    kid: pubkeyFingerprint(publicPath)
  };
}

function kidFromPem(pem) {
  return createHash('sha256').update(pem).digest('hex').slice(0, 16);
}

function pubkeyShaFromPem(pem) {
  return createHash('sha256').update(pem).digest('hex');
}

function assertFailsClosed(label, run, expectedStatus, stderrNeedle) {
  assert(`${label} exits ${expectedStatus}`, expectedStatus, run.status);
  assert(`${label} emits no stdout`, '', run.stdout);
  assertIncludes(`${label} names refusal`, run.stderr, stderrNeedle);
}

const tmpDir = mkdtempSync(join(tmpdir(), 'zlar-verify-cli-'));

try {
  const goodKey = keyPair('good');
  const wrongKey = keyPair('wrong');
  assert('fixture kid construction matches verifier construction', goodKey.kid, kidFromPem(goodKey.publicPem));
  assert('wrong fixture kid construction matches verifier construction', wrongKey.kid, kidFromPem(wrongKey.publicPem));

  const receipt = signReceiptV1(
    createReceiptV1FromEvent({
      id: 'zlar-verify-cli-event-001',
      ts: new Date().toISOString(),
      action: 'Bash',
      domain: 'file',
      detail: { command: 'printf safe' },
      outcome: 'deny',
      rule: 'R002',
      authorizer: 'policy',
      policy_version: '3.3.53',
      prev_hash: '0'.repeat(64)
    }),
    goodKey.privatePem,
    goodKey.kid
  );
  const receiptPath = join(tmpDir, 'receipt.json');
  writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));
  const receiptSha = receiptHashV1(receipt);
  const goodPubkeySha = pubkeyShaFromPem(goodKey.publicPem);
  const wrongPubkeySha = pubkeyShaFromPem(wrongKey.publicPem);

  console.log('=== VALID ===');
  const validRun = runVerify([receiptPath, '--pubkey', goodKey.publicPath, '--json']);
  assert('valid exits 0', 0, validRun.status);
  assert('valid stderr empty', '', validRun.stderr);
  const validJson = jsonFrom(validRun);
  assert('valid verdict', 'VALID', validJson.verdict);
  assert('valid receipt sha', receiptSha, validJson.receipt_sha256);
  assert('valid receipt kid', goodKey.kid, validJson.receipt_kid);
  assert('valid provided kid', goodKey.kid, validJson.provided_kid);
  assert('valid provided pubkey sha', goodPubkeySha, validJson.provided_pubkey_sha256);
  assert('valid kid match', true, validJson.kid_match);
  assert('valid command posture allow_v0 false', false, validJson.command_posture.allow_v0);
  assert('valid command posture detected format', 'v1', validJson.command_posture.detected_format);
  assert('valid required identity command posture', 'receipt-verifier-v1-default', validJson.required_identity.command_posture);
  const validTextRun = runVerify([receiptPath, '--pubkey', goodKey.publicPath]);
  assert('valid text exits 0', 0, validTextRun.status);
  assert('valid text stderr empty', '', validTextRun.stderr);
  assertIncludes('valid text frames local verifier result', validTextRun.stdout, 'Local verifier result: receipt bytes verify under the supplied public key and pass local receipt checks.');
  assertIncludes('valid text has issuer boundary', validTextRun.stdout, 'does not prove issuer status');
  assertIncludes('valid text has downstream boundary', validTextRun.stdout, 'downstream recognition');
  assertIncludes('valid text has live receipt boundary', validTextRun.stdout, 'live receipt emission');
  assertNotIncludes('valid text does not claim trusted receipt', validTextRun.stdout, 'trusted receipt');
  assertNotIncludes('valid text does not claim downstream acceptance', validTextRun.stdout, 'downstream acceptance');
  const validVerboseRun = runVerify([receiptPath, '--pubkey', goodKey.publicPath, '--verbose']);
  assert('valid verbose exits 0', 0, validVerboseRun.status);
  assert('valid verbose stderr empty', '', validVerboseRun.stderr);
  assertIncludes('valid verbose names local identity boundary', validVerboseRun.stdout, '--- Local Identity Boundary ---');
  assertIncludes('valid verbose names supplied pubkey sha', validVerboseRun.stdout, 'Supplied public key SHA-256');
  assertIncludes('valid verbose names command posture', validVerboseRun.stdout, 'Command posture: receipt-verifier-v1-default');
  assertIncludes('valid verbose names claims not proven', validVerboseRun.stdout, 'Claims not proven: issuer_status,key_custody,revocation_truth,downstream_recognition,live_receipt_emission,current_machine_governance');

  console.log('=== REQUIRED IDENTITY ===');
  const requiredArgs = [
    receiptPath,
    '--pubkey',
    goodKey.publicPath,
    '--json',
    '--require-receipt-id',
    receipt.id,
    '--require-receipt-sha',
    receiptSha,
    '--require-kid',
    goodKey.kid,
    '--require-pubkey-sha',
    goodPubkeySha,
    '--require-format',
    'v1',
    '--require-v1-only',
  ];
  const requiredRun = runVerify(requiredArgs);
  assert('required identity exits 0', 0, requiredRun.status);
  assert('required identity stderr empty', '', requiredRun.stderr);
  const requiredJson = jsonFrom(requiredRun);
  assert('required identity verdict', 'VALID', requiredJson.verdict);
  assert('required identity receipt id required', true, requiredJson.required_identity.receipt_id_required);
  assert('required identity receipt id matched', true, requiredJson.required_identity.receipt_id_matched);
  assert('required identity receipt sha required', true, requiredJson.required_identity.receipt_sha256_required);
  assert('required identity receipt sha matched', true, requiredJson.required_identity.receipt_sha256_matched);
  assert('required identity kid required', true, requiredJson.required_identity.kid_required);
  assert('required identity kid matched', true, requiredJson.required_identity.kid_matched);
  assert('required identity pubkey sha required', true, requiredJson.required_identity.pubkey_sha256_required);
  assert('required identity pubkey sha matched', true, requiredJson.required_identity.pubkey_sha256_matched);
  assert('required identity format required', true, requiredJson.required_identity.format_required);
  assert('required identity format matched', true, requiredJson.required_identity.format_matched);
  assert('required identity v1 only required', true, requiredJson.required_identity.v1_only_required);
  assert('required identity v1 only matched', true, requiredJson.required_identity.v1_only_matched);
  assert('required identity command posture', 'receipt-verifier-v1-only-required', requiredJson.required_identity.command_posture);
  assert('required identity command posture allow_v0 false', false, requiredJson.command_posture.allow_v0);
  assert('required identity command posture v1 only required', true, requiredJson.command_posture.v1_only_required);

  const stdinRequiredRun = runVerify([
    '--pubkey',
    goodKey.publicPath,
    '--json',
    '--require-receipt-id',
    receipt.id,
    '--require-receipt-sha',
    receiptSha,
    '--require-kid',
    goodKey.kid,
    '--require-pubkey-sha',
    goodPubkeySha,
    '--require-format',
    'v1',
    '--require-v1-only',
  ], JSON.stringify(receipt));
  assert('stdin required identity exits 0', 0, stdinRequiredRun.status);
  assert('stdin required identity stderr empty', '', stdinRequiredRun.stderr);
  assert('stdin required identity receipt sha', receiptSha, jsonFrom(stdinRequiredRun).receipt_sha256);

  assertFailsClosed(
    'wrong required receipt id',
    runVerify([...requiredArgs.slice(0, requiredArgs.indexOf('--require-receipt-id') + 1), 'wrong-id', ...requiredArgs.slice(requiredArgs.indexOf('--require-receipt-id') + 2)]),
    1,
    'Required identity mismatch: --require-receipt-id'
  );
  assertFailsClosed(
    'wrong required receipt sha',
    runVerify([...requiredArgs.slice(0, requiredArgs.indexOf('--require-receipt-sha') + 1), '0'.repeat(64), ...requiredArgs.slice(requiredArgs.indexOf('--require-receipt-sha') + 2)]),
    1,
    'Required identity mismatch: --require-receipt-sha'
  );
  assertFailsClosed(
    'wrong required kid',
    runVerify([...requiredArgs.slice(0, requiredArgs.indexOf('--require-kid') + 1), wrongKey.kid, ...requiredArgs.slice(requiredArgs.indexOf('--require-kid') + 2)]),
    1,
    'Required identity mismatch: --require-kid'
  );
  assertFailsClosed(
    'wrong required pubkey sha',
    runVerify([...requiredArgs.slice(0, requiredArgs.indexOf('--require-pubkey-sha') + 1), wrongPubkeySha, ...requiredArgs.slice(requiredArgs.indexOf('--require-pubkey-sha') + 2)]),
    1,
    'Required identity mismatch: --require-pubkey-sha'
  );

  const legacyFormatPath = join(tmpDir, 'legacy-format.json');
  writeFileSync(legacyFormatPath, JSON.stringify({ receipt_version: '0.1.0', id: 'legacy-format' }));
  assertFailsClosed(
    'wrong required format',
    runVerify([legacyFormatPath, '--pubkey', goodKey.publicPath, '--require-format', 'v1']),
    1,
    'Required identity mismatch: --require-format'
  );
  assertFailsClosed(
    'legacy v0 required identity refused in stage 1',
    runVerify([legacyFormatPath, '--pubkey', goodKey.publicPath, '--allow-v0', '--require-receipt-id', 'legacy-format']),
    1,
    'Required identity mismatch: required identity is v1-only in this verifier stage'
  );
  assertFailsClosed(
    'malformed required receipt sha',
    runVerify(['/Users/example/secret-receipt.json', '--pubkey', goodKey.publicPath, '--require-receipt-sha', 'abc']),
    2,
    '--require-receipt-sha must be a 64-character lowercase SHA-256 hex digest'
  );
  assertNotIncludes('malformed required receipt sha does not leak path', runVerify(['/Users/example/secret-receipt.json', '--pubkey', goodKey.publicPath, '--require-receipt-sha', 'abc']).stderr, '/Users/example/secret-receipt.json');
  assertFailsClosed(
    'malformed required kid',
    runVerify([receiptPath, '--pubkey', goodKey.publicPath, '--require-kid', 'abc']),
    2,
    '--require-kid must be a 16-character lowercase hex digest'
  );
  assertFailsClosed(
    'unsupported required format',
    runVerify([receiptPath, '--pubkey', goodKey.publicPath, '--require-format', 'v0']),
    2,
    '--require-format supports v1 only in this verifier stage'
  );
  assertFailsClosed(
    'v1 only rejects allow v0 posture',
    runVerify([receiptPath, '--pubkey', goodKey.publicPath, '--allow-v0', '--require-v1-only']),
    2,
    '--require-v1-only cannot be combined with --allow-v0'
  );

  console.log('=== UNKNOWN-SIGNER ===');
  const unknownRun = runVerify([receiptPath, '--pubkey', wrongKey.publicPath, '--json']);
  assert('unknown signer exits 3', 3, unknownRun.status);
  assert('unknown signer stderr empty', '', unknownRun.stderr);
  const unknownJson = jsonFrom(unknownRun);
  assert('unknown signer verdict', 'UNKNOWN-SIGNER', unknownJson.verdict);
  assert('unknown signer reason', 'Receipt kid does not match provided public key.', unknownJson.reason);
  assert('unknown signer receipt kid', goodKey.kid, unknownJson.receipt_kid);
  assert('unknown signer provided kid', wrongKey.kid, unknownJson.provided_kid);
  assert('unknown signer receipt sha', receiptSha, unknownJson.receipt_sha256);
  assert('unknown signer provided pubkey sha', wrongPubkeySha, unknownJson.provided_pubkey_sha256);
  assert('unknown signer kid match false', false, unknownJson.kid_match);

  const unknownRequiredRun = runVerify([
    receiptPath,
    '--pubkey',
    wrongKey.publicPath,
    '--json',
    '--require-receipt-id',
    receipt.id,
    '--require-receipt-sha',
    receiptSha,
    '--require-kid',
    goodKey.kid,
    '--require-format',
    'v1',
    '--require-v1-only',
  ]);
  assert('unknown signer with receipt identity exits 3', 3, unknownRequiredRun.status);
  assert('unknown signer with receipt identity stderr empty', '', unknownRequiredRun.stderr);
  const unknownRequiredJson = jsonFrom(unknownRequiredRun);
  assert('unknown signer with receipt identity verdict', 'UNKNOWN-SIGNER', unknownRequiredJson.verdict);
  assert('unknown signer with receipt identity receipt sha matched', true, unknownRequiredJson.required_identity.receipt_sha256_matched);
  assert('unknown signer with receipt identity kid matched', true, unknownRequiredJson.required_identity.kid_matched);
  assert('unknown signer with receipt identity pubkey sha not required', false, unknownRequiredJson.required_identity.pubkey_sha256_required);
  assert('unknown signer with receipt identity kid match false', false, unknownRequiredJson.kid_match);

  const unknownTextRun = runVerify([receiptPath, '--pubkey', wrongKey.publicPath]);
  assert('unknown signer text exits 3', 3, unknownTextRun.status);
  assertIncludes('unknown signer text verdict', unknownTextRun.stdout, 'UNKNOWN-SIGNER');
  assertIncludes('unknown signer text frames local verifier result', unknownTextRun.stdout, 'Local verifier result: receipt kid does not match the supplied public key.');
  assertIncludes('unknown signer text names key mismatch boundary', unknownTextRun.stdout, 'This is a key mismatch, not revocation truth or live issuer-status truth.');
  assertIncludes('unknown signer text has governance boundary', unknownTextRun.stdout, 'current-machine governance');
  assertIncludes('unknown signer text names receipt kid', unknownTextRun.stdout, goodKey.kid);
  assertIncludes('unknown signer text names provided kid', unknownTextRun.stdout, wrongKey.kid);

  console.log('=== INVALID ===');
  const tampered = { ...receipt, sig: `${receipt.sig.slice(0, -2)}xx` };
  const tamperedPath = join(tmpDir, 'tampered.json');
  writeFileSync(tamperedPath, JSON.stringify(tampered, null, 2));
  const invalidRun = runVerify([tamperedPath, '--pubkey', goodKey.publicPath, '--json']);
  assert('invalid exits 1', 1, invalidRun.status);
  assert('invalid stderr empty', '', invalidRun.stderr);
  const invalidJson = jsonFrom(invalidRun);
  assert('invalid verdict', 'INVALID', invalidJson.verdict);
  assert('invalid kid still matches', true, invalidJson.kid_match);
  assert('invalid receipt sha is tampered object sha', receiptHashV1(tampered), invalidJson.receipt_sha256);
  const invalidTextRun = runVerify([tamperedPath, '--pubkey', goodKey.publicPath]);
  assert('invalid text exits 1', 1, invalidTextRun.status);
  assert('invalid text stderr empty', '', invalidTextRun.stderr);
  assertIncludes('invalid text frames local verifier result', invalidTextRun.stdout, 'Local verifier result: signature, semantic, or structural verification failed.');
  assertIncludes('invalid text has issuer boundary', invalidTextRun.stdout, 'does not prove issuer status');
  assertNotIncludes('invalid text does not claim revoked key', invalidTextRun.stdout, 'revoked key');

  console.log('=== HELP BOUNDARY ===');
  const helpRun = runVerify(['--help']);
  assert('help exits 0', 0, helpRun.status);
  assertIncludes('help names UNKNOWN-SIGNER', helpRun.stdout, 'UNKNOWN-SIGNER');
  assertIncludes('help names require receipt sha', helpRun.stdout, '--require-receipt-sha');
  assertIncludes('help names require v1 only', helpRun.stdout, '--require-v1-only');
  assertIncludes('help has does-not-prove section', helpRun.stdout, 'WHAT THIS DOES NOT PROVE');
  assertIncludes('help names issuer status boundary', helpRun.stdout, 'active issuer status');
  assertIncludes('help names downstream recognition boundary', helpRun.stdout, 'downstream recognition');
  assertIncludes('help names live receipt emission boundary', helpRun.stdout, 'live receipt emission');
  assertNotIncludes('help does not claim action truth', helpRun.stdout, 'A specific action was attempted');
  assertNotIncludes('help does not claim audit-chain anchoring', helpRun.stdout, 'anchored to the ZLAR audit chain');
} finally {
  rmSync(tmpDir, { recursive: true, force: true });
}

console.log();
console.log(`=== Results: ${pass}/${total} passed, ${fail} failed ===`);
if (fail > 0) {
  process.exit(1);
}
