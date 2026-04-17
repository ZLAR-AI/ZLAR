// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Receipt v1 (Envelope) — Test Suite
//
// Tests: v1 creation, signing, verification, cross-format compatibility,
// tampering detection, payload decoding, edge cases.
//
// Viktor's rule: if v1 signing has a bug, something must catch it.
// ═══════════════════════════════════════════════════════════════════════════════

import { createHash, generateKeyPairSync } from 'node:crypto';
import { writeFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const libPath = join(__dirname, '..', 'lib', 'receipt.mjs');

const {
  createReceiptV1,
  createReceiptV1FromEvent,
  signReceiptV1,
  signReceiptV1FromFiles,
  verifyReceiptV1,
  verifyReceiptV1FromFile,
  verifyReceiptAny,
  decodePayloadV1,
  receiptHashV1,
  pubkeyFingerprint,
  // v0 functions for cross-format test
  createReceipt,
  signReceipt,
  verifyReceipt
} = await import(libPath);

let pass = 0;
let fail = 0;
let total = 0;

function assert(label, expected, actual) {
  total++;
  if (expected === actual) {
    pass++;
  } else {
    fail++;
    console.log(`  FAIL: ${label}`);
    console.log(`    expected: ${JSON.stringify(expected)}`);
    console.log(`    actual:   ${JSON.stringify(actual)}`);
  }
}

function assertTruthy(label, val) {
  total++;
  if (val) { pass++; } else { fail++; console.log(`  FAIL: ${label} — expected truthy, got ${val}`); }
}

function assertFalsy(label, val) {
  total++;
  if (!val) { pass++; } else { fail++; console.log(`  FAIL: ${label} — expected falsy, got ${val}`); }
}

// ─── Generate test keypair ──────────────────────────────────────────────────

const tmpDir = mkdtempSync(join(tmpdir(), 'zlar-v1-test-'));
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
const privPath = join(tmpDir, 'test.key');
const pubPath = join(tmpDir, 'test.pub');
writeFileSync(privPath, privPem);
writeFileSync(pubPath, pubPem);
const keyId = pubkeyFingerprint(pubPath);

// ─── Test event ─────────────────────────────────────────────────────────────

const testEvent = {
  id: 'test-event-v1-001',
  ts: '2026-04-06T14:00:00.000Z',
  action: 'Bash',
  domain: 'file',
  detail: { command: 'rm -rf /', cwd: '/home/user' },
  outcome: 'deny',
  rule: 'R002',
  authorizer: 'policy',
  policy_version: '2.6.0',
  prev_hash: '0000000000000000000000000000000000000000000000000000000000000000'
};

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== v1 Receipt Creation ===');
console.log();

const receipt = createReceiptV1FromEvent(testEvent);
assert('v field is integer 1', 1, receipt.v);
assertTruthy('id is non-empty', receipt.id.length > 0);
assert('kid is empty before signing', '', receipt.kid);
assert('type is governed-action', 'governed-action', receipt.type);
assertTruthy('iat is positive integer', Number.isInteger(receipt.iat) && receipt.iat > 0);
assertTruthy('payload is non-empty base64url', receipt.payload.length > 0);
assert('sig is empty before signing', '', receipt.sig);
assert('prev is null', null, receipt.prev);

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== v1 Payload Decoding ===');
console.log();

const payload = decodePayloadV1(receipt);
assert('payload.tool', 'Bash', payload.tool);
assert('payload.domain', 'file', payload.domain);
assert('payload.outcome', 'deny', payload.outcome);
assert('payload.rule', 'R002', payload.rule);
assert('payload.authorizer', 'policy', payload.authorizer);
assert('payload.ts', '2026-04-06T14:00:00.000Z', payload.ts);
assert('payload.policy_version', '2.6.0', payload.policy_version);
assertTruthy('payload.detail_hash is 64-char hex', /^[a-f0-9]{64}$/.test(payload.detail_hash));
assert('payload.manifest_agent_id', null, payload.manifest_agent_id);
assert('payload.manifest_principal', null, payload.manifest_principal);
assert('payload.delegation_chain is empty', 0, payload.delegation_chain.length);
assert('payload.audit_event_id', 'test-event-v1-001', payload.audit_event_id);

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== v1 Signing ===');
console.log();

const signed = signReceiptV1(receipt, privPem, keyId);
assert('signed.v is 1', 1, signed.v);
assert('signed.kid matches', keyId, signed.kid);
assertTruthy('signed.sig is non-empty', signed.sig.length > 0);
assertTruthy('signed.sig is base64url (no +/=)', !/[+/=]/.test(signed.sig));
assert('signed.payload unchanged', receipt.payload, signed.payload);

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== v1 Verification ===');
console.log();

const result = verifyReceiptV1(signed, pubPem);
assert('verification succeeds', true, result.valid);
assertTruthy('reason mentions tool', result.reason.includes('Bash'));
assertTruthy('payload returned on success', result.payload !== undefined);
assert('payload.tool from verification', 'Bash', result.payload.tool);

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== v1 Signing from Files ===');
console.log();

const signedFromFiles = signReceiptV1FromFiles(receipt, privPath, pubPath);
const resultFiles = verifyReceiptV1FromFile(signedFromFiles, pubPath);
assert('file-based sign+verify succeeds', true, resultFiles.valid);

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== v1 Tamper Detection ===');
console.log();

// Tamper with payload — decode, mutate, re-encode without resigning
const tamperedPayloadObj = decodePayloadV1(signed);
tamperedPayloadObj.outcome = 'allow'; // flip deny to allow
const tamperedPayloadJson = JSON.stringify(tamperedPayloadObj);
const tamperedPayloadB64 = Buffer.from(tamperedPayloadJson, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const tampered1 = { ...signed, payload: tamperedPayloadB64 };
const tampResult1 = verifyReceiptV1(tampered1, pubPem);
assert('tampered payload detected', false, tampResult1.valid);

// Tamper with sig
const tampered2 = { ...signed, sig: signed.sig.slice(0, -4) + 'XXXX' };
const tampResult2 = verifyReceiptV1(tampered2, pubPem);
assert('tampered signature detected', false, tampResult2.valid);

// Remove sig
const tampered3 = { ...signed, sig: '' };
const tampResult3 = verifyReceiptV1(tampered3, pubPem);
assert('missing signature detected', false, tampResult3.valid);

// Wrong key
const { publicKey: wrongPub } = generateKeyPairSync('ed25519');
const wrongPubPem = wrongPub.export({ type: 'spki', format: 'pem' });
const tampResult4 = verifyReceiptV1(signed, wrongPubPem);
assert('wrong key detected', false, tampResult4.valid);

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== v1 Structural Validation ===');
console.log();

assert('null receipt rejected', false, verifyReceiptV1(null, pubPem).valid);
assert('non-object rejected', false, verifyReceiptV1('string', pubPem).valid);
assert('wrong version rejected', false, verifyReceiptV1({ v: 2, payload: 'x', sig: 'x', id: '1', kid: '1', iat: 1, type: 'governed-action' }, pubPem).valid);
assert('missing payload rejected', false, verifyReceiptV1({ v: 1, sig: 'x', id: '1', kid: '1', iat: 1, type: 'governed-action' }, pubPem).valid);
assert('wrong type rejected', false, verifyReceiptV1({ v: 1, payload: 'x', sig: 'x', id: '1', kid: '1', iat: 1, type: 'unknown' }, pubPem).valid);

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== Universal Verifier (verifyReceiptAny) ===');
console.log();

// v1 through universal
const anyV1 = verifyReceiptAny(signed, pubPem);
assert('universal: v1 valid', true, anyV1.valid);
assert('universal: v1 version detected', 'v1', anyV1.version);

// v0 through universal
const v0Receipt = createReceipt({
  tool: 'Bash', domain: 'file', detail: { command: 'ls' },
  outcome: 'allow', rule: 'R001', authorizer: 'policy',
  timestamp: '2026-04-06T14:00:00.000Z', policy_version: '2.6.0',
  audit_event_id: 'v0-test', audit_prev_hash: 'genesis'
});
const v0Signed = signReceipt(v0Receipt, privPem, keyId);

// v0 is OFF by default at Published v1.0. Caller must opt in.
const anyV0Default = verifyReceiptAny(v0Signed, pubPem);
assert('universal: v0 rejected without allowV0', false, anyV0Default.valid);
assert('universal: v0 version reported even when rejected', 'v0', anyV0Default.version);

const anyV0 = verifyReceiptAny(v0Signed, pubPem, { allowV0: true });
assert('universal: v0 valid with allowV0', true, anyV0.valid);
assert('universal: v0 version detected', 'v0', anyV0.version);

// unknown version
const anyUnknown = verifyReceiptAny({ something: 'else' }, pubPem);
assert('universal: unknown rejected', false, anyUnknown.valid);

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== v1 Receipt Chain ===');
console.log();

const hash1 = receiptHashV1(signed);
assertTruthy('receipt hash is 64-char hex', /^[a-f0-9]{64}$/.test(hash1));

const receipt2 = createReceiptV1FromEvent({ ...testEvent, id: 'test-event-v1-002' }, { prev_receipt_hash: hash1 });
assert('receipt2 prev links to receipt1', hash1, receipt2.prev);

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== v1 with Manifest Fields ===');
console.log();

const receiptManifest = createReceiptV1FromEvent(testEvent, {
  manifest_agent_id: 'zlar:agent:claude-code',
  manifest_principal: 'zlar:human:vince-nijjar',
  delegation_chain: [{ agent_id: 'claude-code', depth: 0 }]
});
const payloadManifest = decodePayloadV1(receiptManifest);
assert('manifest_agent_id present', 'zlar:agent:claude-code', payloadManifest.manifest_agent_id);
assert('manifest_principal present', 'zlar:human:vince-nijjar', payloadManifest.manifest_principal);
assert('delegation_chain has 1 entry', 1, payloadManifest.delegation_chain.length);
assert('delegation depth 0', 0, payloadManifest.delegation_chain[0].depth);

// ═══════════════════════════════════════════════════════════════════════════════
console.log('=== v1 with Agent Config Identity (cryptographic layer) ===');
console.log();

// The three fields added for Governed Action Receipt v1 (per-receipt
// cryptographic identity of the governing config artifact).

// Null pathway — when no governing artifact is present, all three fields
// default to null. Receipts remain valid.
const receiptNoIdentity = createReceiptV1FromEvent(testEvent, {});
const payloadNoIdentity = decodePayloadV1(receiptNoIdentity);
assert('no-identity: agent_config_hash is null', null, payloadNoIdentity.agent_config_hash);
assert('no-identity: agent_config_source is null', null, payloadNoIdentity.agent_config_source);
assert('no-identity: agent_fingerprint is null', null, payloadNoIdentity.agent_fingerprint);

// Populated pathway via opts
const hashFull = 'a'.repeat(64);
const receiptWithIdentity = createReceiptV1FromEvent(testEvent, {
  agent_config_hash: hashFull,
  agent_config_source: 'project_claude_md',
  agent_fingerprint: '0123456789abcdef'
});
const payloadWithIdentity = decodePayloadV1(receiptWithIdentity);
assert('opts: agent_config_hash flows through', hashFull, payloadWithIdentity.agent_config_hash);
assert('opts: agent_config_source flows through', 'project_claude_md', payloadWithIdentity.agent_config_source);
assert('opts: agent_fingerprint flows through', '0123456789abcdef', payloadWithIdentity.agent_fingerprint);

// Event-field pathway — identity fields come from the audit event directly
// (this is the bash gate and MCP gate flow: gate computes identity, writes
// it onto the audit entry, receipt builder inherits from event).
const eventWithIdentity = {
  ...testEvent,
  id: 'test-event-identity-from-event',
  agent_config_hash: 'b'.repeat(64),
  agent_config_source: 'user_claude_md',
  agent_fingerprint: 'fedcba9876543210'
};
const receiptFromEvent = createReceiptV1FromEvent(eventWithIdentity);
const payloadFromEvent = decodePayloadV1(receiptFromEvent);
assert('event: agent_config_hash from event', 'b'.repeat(64), payloadFromEvent.agent_config_hash);
assert('event: agent_config_source from event', 'user_claude_md', payloadFromEvent.agent_config_source);
assert('event: agent_fingerprint from event', 'fedcba9876543210', payloadFromEvent.agent_fingerprint);

// opts override event — explicit opts take precedence over event fields
const receiptOverride = createReceiptV1FromEvent(eventWithIdentity, {
  agent_config_hash: 'c'.repeat(64),
  agent_config_source: 'project_soul_md',
  agent_fingerprint: '1111222233334444'
});
const payloadOverride = decodePayloadV1(receiptOverride);
assert('override: opts.agent_config_hash wins', 'c'.repeat(64), payloadOverride.agent_config_hash);
assert('override: opts.agent_config_source wins', 'project_soul_md', payloadOverride.agent_config_source);
assert('override: opts.agent_fingerprint wins', '1111222233334444', payloadOverride.agent_fingerprint);

// Round-trip with signing — identity fields survive canonicalization + signing
const signedIdentity = signReceiptV1(receiptWithIdentity, privPem, keyId);
const verifiedIdentity = verifyReceiptV1(signedIdentity, pubPem);
assert('signed+verified: identity round-trip valid', true, verifiedIdentity.valid);
const payloadVerified = decodePayloadV1(signedIdentity);
assert('signed: agent_config_hash preserved', hashFull, payloadVerified.agent_config_hash);
assert('signed: agent_config_source preserved', 'project_claude_md', payloadVerified.agent_config_source);
assert('signed: agent_fingerprint preserved', '0123456789abcdef', payloadVerified.agent_fingerprint);

// ═══════════════════════════════════════════════════════════════════════════════
// Cleanup
try { unlinkSync(privPath); unlinkSync(pubPath); } catch {}

// Summary
console.log();
console.log(`=== Results: ${pass}/${total} passed, ${fail} failed ===`);
if (fail > 0) process.exit(1);
