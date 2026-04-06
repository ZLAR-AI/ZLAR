// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Governed Action Receipt — Test Suite
//
// Tests receipt generation, signing, verification, canonicalization,
// delegation chains, and cross-gate compatibility.
//
// Usage: node mcp-gate/test-receipt.mjs
// ═══════════════════════════════════════════════════════════════════════════════

import { createHash, generateKeyPairSync } from 'node:crypto';
import { writeFileSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import { execSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PROJECT_DIR = join(__dirname, '..');

import {
  canonicalize,
  sha256hex,
  createReceipt,
  createReceiptFromEvent,
  signReceipt,
  signReceiptFromFiles,
  verifyReceipt,
  verifyReceiptFromFile,
  pubkeyFingerprint,
  signablePayload,
  receiptHash
} from '../lib/receipt.mjs';

// ─── Test Harness ────────────────────────────────────────────────────────────

let PASS = 0;
let FAIL = 0;
let TOTAL = 0;

function assert(label, expected, actual) {
  TOTAL++;
  if (expected === actual) {
    PASS++;
  } else {
    FAIL++;
    console.log(`  FAIL: ${label} — expected "${expected}", got "${actual}"`);
  }
}

function assertTruthy(label, value) {
  TOTAL++;
  if (value) {
    PASS++;
  } else {
    FAIL++;
    console.log(`  FAIL: ${label} — expected truthy, got "${value}"`);
  }
}

function assertFalsy(label, value) {
  TOTAL++;
  if (!value) {
    PASS++;
  } else {
    FAIL++;
    console.log(`  FAIL: ${label} — expected falsy, got "${value}"`);
  }
}

// ─── Test Keys ───────────────────────────────────────────────────────────────

const TEMP_DIR = mkdtempSync(join(tmpdir(), 'zlar-receipt-test-'));

// Generate Ed25519 keypair for testing
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });

const privKeyPath = join(TEMP_DIR, 'test.key');
const pubKeyPath = join(TEMP_DIR, 'test.pub');
writeFileSync(privKeyPath, privateKeyPem);
writeFileSync(pubKeyPath, publicKeyPem);

// Generate a second keypair (for wrong-key tests)
const { privateKey: wrongPriv, publicKey: wrongPub } = generateKeyPairSync('ed25519');
const wrongPubPem = wrongPub.export({ type: 'spki', format: 'pem' });

// ─── Mock Data ───────────────────────────────────────────────────────────────

const MOCK_DETAIL = { command: 'rm -rf /tmp/test', path: '/tmp/test' };
const MOCK_TIMESTAMP = '2026-04-05T20:00:00.000Z';

const MOCK_PARAMS = {
  tool: 'Bash',
  domain: 'file',
  detail: MOCK_DETAIL,
  outcome: 'deny',
  rule: 'R002',
  authorizer: 'policy',
  timestamp: MOCK_TIMESTAMP,
  policy_version: '1.7.0',
  audit_event_id: '019577a8c0001234567890abcdef1234',
  audit_prev_hash: 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456'
};

const MOCK_EVENT = {
  id: '019577a8c0001234567890abcdef1234',
  ts: MOCK_TIMESTAMP,
  seq: 42,
  source: 'gate',
  host: 'macbook',
  user: 'vince',
  agent_id: 'claude-code',
  session_id: 'sess-001',
  domain: 'file',
  action: 'Bash',
  outcome: 'deny',
  risk_score: 9,
  detail: MOCK_DETAIL,
  rule: 'R002',
  policy_version: '1.7.0',
  severity: 'critical',
  prev_hash: 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
  authorizer: 'policy',
  signature_algorithm: 'Ed25519',
  hash_algorithm: 'SHA-256',
  public_key_id: 'abc123def4567890',
  signature: 'base64sig=='
};

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

console.log('=== Canonicalization ===');
console.log();

// jq -S -c sorts keys recursively. Our canonicalize must match.
assert('simple object sorted', '{"a":1,"b":2}', canonicalize({ b: 2, a: 1 }));
assert('nested object sorted', '{"a":{"x":1,"y":2},"b":3}', canonicalize({ b: 3, a: { y: 2, x: 1 } }));
assert('array preserves order', '[3,1,2]', canonicalize([3, 1, 2]));
assert('null handled', 'null', canonicalize(null));
assert('string handled', '"hello"', canonicalize('hello'));
assert('deeply nested sorted',
  '{"a":{"b":{"c":1,"d":2}}}',
  canonicalize({ a: { b: { d: 2, c: 1 } } })
);

console.log();
console.log('=== SHA-256 Hex ===');
console.log();

// Known test vector
assert('sha256 empty string', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', sha256hex(''));
assert('sha256 hello', '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', sha256hex('hello'));

console.log();
console.log('=== Receipt Creation ===');
console.log();

const receipt = createReceipt(MOCK_PARAMS);
assert('receipt version', '0.1.0', receipt.receipt_version);
assertTruthy('receipt has id', receipt.id);
assert('receipt tool', 'Bash', receipt.governed_action.tool);
assert('receipt domain', 'file', receipt.governed_action.domain);
assertTruthy('receipt has detail_hash', receipt.governed_action.detail_hash.length === 64);
assert('receipt outcome', 'deny', receipt.decision.outcome);
assert('receipt rule', 'R002', receipt.decision.rule);
assert('receipt authorizer', 'policy', receipt.decision.authorizer);
assert('receipt timestamp', MOCK_TIMESTAMP, receipt.decision.timestamp);
assert('receipt policy_version', '1.7.0', receipt.evidence.policy_version);
assert('receipt manifest null', null, receipt.evidence.manifest_version);
assert('receipt delegation empty', 0, receipt.evidence.delegation_chain.length);
assert('receipt signature null', null, receipt.signature);
assert('receipt prev_hash null', null, receipt.prev_receipt_hash);

console.log();
console.log('=== Receipt from Audit Event ===');
console.log();

const eventReceipt = createReceiptFromEvent(MOCK_EVENT, {
  manifest_version: '0.1.0',
  manifest_agent_id: 'zlar:agent:claude-code',
  manifest_principal: 'zlar:human:vince-nijjar'
});
assert('event receipt tool', 'Bash', eventReceipt.governed_action.tool);
assert('event receipt domain', 'file', eventReceipt.governed_action.domain);
assert('event receipt outcome', 'deny', eventReceipt.decision.outcome);
assert('event receipt manifest_version', '0.1.0', eventReceipt.evidence.manifest_version);
assert('event receipt manifest_agent_id', 'zlar:agent:claude-code', eventReceipt.evidence.manifest_agent_id);
assert('event receipt manifest_principal', 'zlar:human:vince-nijjar', eventReceipt.evidence.manifest_principal);
assert('event receipt audit_event_id', MOCK_EVENT.id, eventReceipt.evidence.audit_event_id);

console.log();
console.log('=== Detail Hash ===');
console.log();

// detail_hash should be SHA-256 of canonical detail JSON
const expectedDetailHash = sha256hex(canonicalize(MOCK_DETAIL));
assert('detail hash from object', expectedDetailHash, receipt.governed_action.detail_hash);

// Pre-computed hash should pass through
const precomputed = createReceipt({ ...MOCK_PARAMS, detail: 'abcd1234'.repeat(8) });
assert('detail hash passthrough', 'abcd1234'.repeat(8), precomputed.governed_action.detail_hash);

console.log();
console.log('=== Signing ===');
console.log();

const keyId = pubkeyFingerprint(pubKeyPath);
assertTruthy('key fingerprint 16 chars', keyId.length === 16);

const signed = signReceipt(receipt, privateKeyPem, keyId);
assertTruthy('signed receipt has signature', signed.signature !== null);
assert('signature algorithm', 'Ed25519', signed.signature.algorithm);
assert('signature hash_algorithm', 'SHA-256', signed.signature.hash_algorithm);
assert('signature key_id', keyId, signed.signature.key_id);
assertTruthy('signature value non-empty', signed.signature.value.length > 0);

// Sign from files
const signedFromFiles = signReceiptFromFiles(receipt, privKeyPath, pubKeyPath);
assertTruthy('sign from files has signature', signedFromFiles.signature !== null);
assert('sign from files key_id matches', keyId, signedFromFiles.signature.key_id);

console.log();
console.log('=== Verification (Valid) ===');
console.log();

const validResult = verifyReceipt(signed, publicKeyPem);
assert('valid signature', true, validResult.valid);
assertTruthy('valid reason mentions action', validResult.reason.includes('Bash'));

const validFromFile = verifyReceiptFromFile(signed, pubKeyPath);
assert('valid from file', true, validFromFile.valid);

console.log();
console.log('=== Verification (Invalid Signature) ===');
console.log();

const wrongKeyResult = verifyReceipt(signed, wrongPubPem);
assert('wrong key invalid', false, wrongKeyResult.valid);
assertTruthy('wrong key reason mentions tamper', wrongKeyResult.reason.includes('tampered'));

console.log();
console.log('=== Verification (Tampered Receipt) ===');
console.log();

const tampered = JSON.parse(JSON.stringify(signed));
tampered.decision.outcome = 'allow'; // Tamper: change deny to allow
const tamperedResult = verifyReceipt(tampered, publicKeyPem);
assert('tampered receipt invalid', false, tamperedResult.valid);

const tampered2 = JSON.parse(JSON.stringify(signed));
tampered2.governed_action.tool = 'Edit'; // Tamper: change tool name
const tampered2Result = verifyReceipt(tampered2, publicKeyPem);
assert('tampered tool invalid', false, tampered2Result.valid);

const tampered3 = JSON.parse(JSON.stringify(signed));
tampered3.evidence.audit_prev_hash = '0'.repeat(64); // Tamper: break chain link
const tampered3Result = verifyReceipt(tampered3, publicKeyPem);
assert('tampered chain link invalid', false, tampered3Result.valid);

console.log();
console.log('=== Verification (Missing/Broken Fields) ===');
console.log();

const noSig = { ...signed, signature: null };
const noSigResult = verifyReceipt(noSig, publicKeyPem);
assert('no signature invalid', false, noSigResult.valid);
assertTruthy('no sig reason', noSigResult.reason.includes('no signature'));

const badVersion = { ...signed, receipt_version: '99.0.0' };
const badVersionResult = verifyReceipt(badVersion, publicKeyPem);
assert('bad version invalid', false, badVersionResult.valid);

const notObject = verifyReceipt('not an object', publicKeyPem);
assert('string input invalid', false, notObject.valid);

const nullInput = verifyReceipt(null, publicKeyPem);
assert('null input invalid', false, nullInput.valid);

console.log();
console.log('=== Delegation Chain Receipt ===');
console.log();

const delegatedReceipt = createReceipt({
  ...MOCK_PARAMS,
  manifest_version: '0.1.0',
  manifest_agent_id: 'zlar:agent:child-001',
  manifest_principal: 'zlar:human:vince-nijjar',
  delegation_chain: [
    { agent_id: 'zlar:agent:claude-code', depth: 0, manifest_id: 'manifest-root-001' },
    { agent_id: 'zlar:agent:child-001', depth: 1, manifest_id: 'manifest-child-001' }
  ]
});

assert('delegation chain length', 2, delegatedReceipt.evidence.delegation_chain.length);
assert('delegation root agent', 'zlar:agent:claude-code', delegatedReceipt.evidence.delegation_chain[0].agent_id);
assert('delegation root depth', 0, delegatedReceipt.evidence.delegation_chain[0].depth);
assert('delegation child agent', 'zlar:agent:child-001', delegatedReceipt.evidence.delegation_chain[1].agent_id);
assert('delegation child depth', 1, delegatedReceipt.evidence.delegation_chain[1].depth);

const signedDelegated = signReceipt(delegatedReceipt, privateKeyPem, keyId);
const delegatedValid = verifyReceipt(signedDelegated, publicKeyPem);
assert('delegated receipt valid', true, delegatedValid.valid);

console.log();
console.log('=== Receipt Chain Linking ===');
console.log();

// Receipt 1
const r1 = signReceipt(
  createReceipt({ ...MOCK_PARAMS, id: 'receipt-001' }),
  privateKeyPem, keyId
);
const r1Hash = receiptHash(r1);
assertTruthy('receipt hash 64 chars', r1Hash.length === 64);

// Receipt 2 links to receipt 1
const r2 = signReceipt(
  createReceipt({ ...MOCK_PARAMS, id: 'receipt-002', prev_receipt_hash: r1Hash }),
  privateKeyPem, keyId
);
assert('r2 prev_hash matches r1', r1Hash, r2.prev_receipt_hash);
const r2Valid = verifyReceipt(r2, publicKeyPem);
assert('chained receipt valid', true, r2Valid.valid);

// Tamper with r2's prev_receipt_hash
const r2Tampered = JSON.parse(JSON.stringify(r2));
r2Tampered.prev_receipt_hash = '0'.repeat(64);
const r2TamperedResult = verifyReceipt(r2Tampered, publicKeyPem);
assert('tampered chain link invalid', false, r2TamperedResult.valid);

console.log();
console.log('=== Signable Payload Determinism ===');
console.log();

// Same receipt content must always produce same payload
const payload1 = signablePayload(signed);
const payload2 = signablePayload(signed);
assert('payload deterministic', payload1, payload2);

// Different signature values must not affect payload (signature is stripped)
const resignedReceipt = signReceipt(receipt, privateKeyPem, keyId);
const payload3 = signablePayload(resignedReceipt);
const payload4 = signablePayload(signed);
assert('payload independent of signature value', payload3, payload4);

console.log();
console.log('=== Schema Validation ===');
console.log();

// Check all required schema fields are present
const schemaRequired = ['receipt_version', 'id', 'governed_action', 'decision', 'evidence', 'signature'];
for (const field of schemaRequired) {
  assertTruthy(`signed receipt has ${field}`, field in signed);
}

const actionRequired = ['tool', 'domain', 'detail_hash'];
for (const field of actionRequired) {
  assertTruthy(`governed_action has ${field}`, field in signed.governed_action);
}

const decisionRequired = ['outcome', 'rule', 'authorizer', 'timestamp'];
for (const field of decisionRequired) {
  assertTruthy(`decision has ${field}`, field in signed.decision);
}

const evidenceRequired = ['policy_version', 'audit_event_id', 'audit_prev_hash'];
for (const field of evidenceRequired) {
  assertTruthy(`evidence has ${field}`, field in signed.evidence);
}

const sigRequired = ['algorithm', 'hash_algorithm', 'value', 'key_id'];
for (const field of sigRequired) {
  assertTruthy(`signature has ${field}`, field in signed.signature);
}

console.log();
console.log('=== Cross-Gate Compatibility (Node ↔ Bash) ===');
console.log();

// Test that jq -S -c produces the same output as our canonicalize
// This is the critical cross-gate compatibility check
try {
  const testObj = { z: 1, a: { m: true, b: 'hello' }, k: [3, 1, 2] };
  const nodeCanonical = canonicalize(testObj);
  const bashCanonical = execSync(
    `printf '%s' '${JSON.stringify(testObj)}' | jq -S -c '.'`,
    { encoding: 'utf8' }
  ).trim();
  assert('canonical matches jq -S -c', bashCanonical, nodeCanonical);
} catch (e) {
  console.log(`  SKIP: jq not available for cross-gate test (${e.message})`);
}

// Test that SHA-256 hex matches shasum
try {
  const testData = '{"hello":"world"}';
  const nodeHash = sha256hex(testData);
  const bashHash = execSync(
    `printf '%s' '${testData}' | shasum -a 256 | awk '{print $1}'`,
    { encoding: 'utf8' }
  ).trim();
  assert('sha256 matches shasum', bashHash, nodeHash);
} catch (e) {
  console.log(`  SKIP: shasum not available for cross-gate test (${e.message})`);
}

// Write a receipt and verify with the bash verifier
try {
  const receiptPath = join(TEMP_DIR, 'test-receipt.json');
  writeFileSync(receiptPath, JSON.stringify(signed, null, 2));

  const verifyResult = execSync(
    `node ${join(PROJECT_DIR, 'bin', 'zlar-verify')} ${receiptPath} --pubkey ${pubKeyPath} --json`,
    { encoding: 'utf8' }
  );
  const parsed = JSON.parse(verifyResult);
  assert('node-generated receipt verifiable by bin/zlar-verify', 'VALID', parsed.verdict);
} catch (e) {
  console.log(`  SKIP: zlar-verify not runnable (${e.message})`);
}

// ─── Cleanup ─────────────────────────────────────────────────────────────────

try {
  rmSync(TEMP_DIR, { recursive: true, force: true });
} catch (_) {}

// ─── Results ─────────────────────────────────────────────────────────────────

console.log();
process.stdout.write(`Results: ${PASS}/${TOTAL} passed`);
if (FAIL > 0) {
  console.log(` (${FAIL} FAILED)`);
  process.exit(1);
} else {
  console.log(' \u2713');
}
