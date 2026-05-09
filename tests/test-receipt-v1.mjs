// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Receipt v1 (Envelope) — Test Suite
//
// Tests: v1 creation, signing, verification, cross-format compatibility,
// tampering detection, payload decoding, edge cases.
//
// v1 signing-bug catcher: if v1 signing has a bug, something must catch it.
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
  canonicalize,
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
console.log('=== v1 Canary Audit Fields (Element D) ===');
console.log();

// Default emission — all 5 canary fields present with default values.
const receiptCanaryDefault = createReceiptV1FromEvent(testEvent);
const payloadCanaryDefault = decodePayloadV1(receiptCanaryDefault);
assertTruthy('default: h15_elapsed_seconds key present', 'h15_elapsed_seconds' in payloadCanaryDefault);
assertTruthy('default: h15_floor_seconds key present', 'h15_floor_seconds' in payloadCanaryDefault);
assertTruthy('default: h15_below_floor key present', 'h15_below_floor' in payloadCanaryDefault);
assertTruthy('default: h14_alert_tier key present', 'h14_alert_tier' in payloadCanaryDefault);
assertTruthy('default: h14_alert_ack_receipt_id key present', 'h14_alert_ack_receipt_id' in payloadCanaryDefault);
assert('default: h15_elapsed_seconds is null', null, payloadCanaryDefault.h15_elapsed_seconds);
assert('default: h15_floor_seconds is null', null, payloadCanaryDefault.h15_floor_seconds);
assert('default: h15_below_floor is null', null, payloadCanaryDefault.h15_below_floor);
assert('default: h14_alert_tier is 0 (no alert)', 0, payloadCanaryDefault.h14_alert_tier);
assert('default: h14_alert_ack_receipt_id is null', null, payloadCanaryDefault.h14_alert_ack_receipt_id);

// Population via opts — all 5 fields flow through. Integer seconds per ZLAR
// canonicalization spec (no floats); see lib/canonicalize.mjs.
const receiptCanaryOpts = createReceiptV1FromEvent(testEvent, {
  h15_elapsed_seconds: 2,
  h15_floor_seconds: 10,
  h15_below_floor: true,
  h14_alert_tier: 1,
  h14_alert_ack_receipt_id: '0123456789abdeadbeef0011'
});
const payloadCanaryOpts = decodePayloadV1(receiptCanaryOpts);
assert('opts: h15_elapsed_seconds flows through', 2, payloadCanaryOpts.h15_elapsed_seconds);
assert('opts: h15_floor_seconds flows through', 10, payloadCanaryOpts.h15_floor_seconds);
assert('opts: h15_below_floor flows through', true, payloadCanaryOpts.h15_below_floor);
assert('opts: h14_alert_tier flows through', 1, payloadCanaryOpts.h14_alert_tier);
assert('opts: h14_alert_ack_receipt_id flows through', '0123456789abdeadbeef0011', payloadCanaryOpts.h14_alert_ack_receipt_id);

// Population via event — fields flow from event when not given via opts.
const eventWithCanary = {
  ...testEvent,
  id: 'test-event-canary-from-event',
  h15_elapsed_seconds: 1,
  h15_floor_seconds: 3,
  h15_below_floor: true,
  h14_alert_tier: 1,
  h14_alert_ack_receipt_id: 'aabbccddeeff00112233'
};
const receiptCanaryFromEvent = createReceiptV1FromEvent(eventWithCanary);
const payloadCanaryFromEvent = decodePayloadV1(receiptCanaryFromEvent);
assert('event: h15_elapsed_seconds from event', 1, payloadCanaryFromEvent.h15_elapsed_seconds);
assert('event: h15_floor_seconds from event', 3, payloadCanaryFromEvent.h15_floor_seconds);
assert('event: h15_below_floor from event', true, payloadCanaryFromEvent.h15_below_floor);
assert('event: h14_alert_tier from event', 1, payloadCanaryFromEvent.h14_alert_tier);
assert('event: h14_alert_ack_receipt_id from event', 'aabbccddeeff00112233', payloadCanaryFromEvent.h14_alert_ack_receipt_id);

// opts override event — parallel to existing agent_config_* override pattern.
const receiptCanaryOverride = createReceiptV1FromEvent(eventWithCanary, {
  h14_alert_tier: 2,
  h14_alert_ack_receipt_id: 'fedcba0987654321aabb'
});
const payloadCanaryOverride = decodePayloadV1(receiptCanaryOverride);
assert('override: opts.h14_alert_tier wins', 2, payloadCanaryOverride.h14_alert_tier);
assert('override: opts.h14_alert_ack_receipt_id wins', 'fedcba0987654321aabb', payloadCanaryOverride.h14_alert_ack_receipt_id);
assert('override: h15_elapsed_seconds falls through from event', 1, payloadCanaryOverride.h15_elapsed_seconds);

// Round-trip — fields survive sign + verify.
const signedCanary = signReceiptV1(receiptCanaryOpts, privPem, keyId);
const verifiedCanary = verifyReceiptV1(signedCanary, pubPem);
assert('canary round-trip: signature valid', true, verifiedCanary.valid);
assert('canary round-trip: h14_alert_tier preserved', 1, verifiedCanary.payload.h14_alert_tier);
assert('canary round-trip: h15_elapsed_seconds preserved', 2, verifiedCanary.payload.h15_elapsed_seconds);
assert('canary round-trip: h15_below_floor preserved', true, verifiedCanary.payload.h15_below_floor);
assert('canary round-trip: h14_alert_ack_receipt_id preserved', '0123456789abdeadbeef0011', verifiedCanary.payload.h14_alert_ack_receipt_id);

// Schema sanity — load the schema and confirm Element D fields are properties,
// are NOT in required (backward compat), and h14_alert_tier has the 0..3 bound.
const { readFileSync: readFS } = await import('node:fs');
const schemaPath = join(__dirname, '..', 'etc', 'receipt-v1-payload.schema.json');
const schema = JSON.parse(readFS(schemaPath, 'utf8'));
assertTruthy('schema: h15_elapsed_seconds in properties', 'h15_elapsed_seconds' in schema.properties);
assertTruthy('schema: h15_floor_seconds in properties', 'h15_floor_seconds' in schema.properties);
assertTruthy('schema: h15_below_floor in properties', 'h15_below_floor' in schema.properties);
assertTruthy('schema: h14_alert_tier in properties', 'h14_alert_tier' in schema.properties);
assertTruthy('schema: h14_alert_ack_receipt_id in properties', 'h14_alert_ack_receipt_id' in schema.properties);
assertFalsy('schema: h15_elapsed_seconds NOT required (backward compat)', schema.required.includes('h15_elapsed_seconds'));
assertFalsy('schema: h15_floor_seconds NOT required', schema.required.includes('h15_floor_seconds'));
assertFalsy('schema: h15_below_floor NOT required', schema.required.includes('h15_below_floor'));
assertFalsy('schema: h14_alert_tier NOT required', schema.required.includes('h14_alert_tier'));
assertFalsy('schema: h14_alert_ack_receipt_id NOT required', schema.required.includes('h14_alert_ack_receipt_id'));
assert('schema: h14_alert_tier minimum is 0', 0, schema.properties.h14_alert_tier.minimum);
assert('schema: h14_alert_tier maximum is 3', 3, schema.properties.h14_alert_tier.maximum);

// All Element D fields are emitted and present in schema.properties.
// (Scoped to Element D — broader payload/schema cleanliness is out of scope here.)
const elementDFields = [
  'h15_elapsed_seconds',
  'h15_floor_seconds',
  'h15_below_floor',
  'h14_alert_tier',
  'h14_alert_ack_receipt_id'
];
const schemaProperties = new Set(Object.keys(schema.properties));
let elementDMissingFromSchema = null;
let elementDMissingFromPayload = null;
for (const k of elementDFields) {
  if (!schemaProperties.has(k)) { elementDMissingFromSchema = k; break; }
  if (!(k in payloadCanaryOpts)) { elementDMissingFromPayload = k; break; }
}
assert('schema: all Element D fields present in schema.properties', null, elementDMissingFromSchema);
assert('payload: all Element D fields present in emitted payload', null, elementDMissingFromPayload);

// All schema-required fields present in emitted payload.
let missingRequired = null;
for (const r of schema.required) {
  if (!(r in payloadCanaryOpts) || payloadCanaryOpts[r] === undefined) { missingRequired = r; break; }
}
assert('schema: all required fields present in emitted payload', null, missingRequired);

// Backward compatibility — legacy payload (pre-Element-D shape, no canary
// fields) signs and verifies cleanly. Proves that pre-Element-D receipts on
// disk continue to verify after Element D ships.
const legacyPayload = {
  tool: 'Bash',
  domain: 'file',
  detail_hash: 'a'.repeat(64),
  outcome: 'allow',
  rule: 'R001',
  authorizer: 'policy',
  ts: '2026-04-06T14:00:00.000Z',
  policy_version: '2.6.0',
  manifest_agent_id: null,
  manifest_principal: null,
  agent_config_hash: null,
  agent_config_source: null,
  agent_fingerprint: null,
  delegation_chain: [],
  audit_event_id: 'legacy-event-pre-element-d',
  audit_prev_hash: 'genesis',
  escalation_source: null
  // No h15_*/h14_* fields — pre-Element-D shape.
};
const legacyCanonical = canonicalize(legacyPayload);
const legacyB64 = Buffer.from(legacyCanonical, 'utf8').toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const legacyEnvelope = {
  v: 1,
  id: '0123456789abcdef00112233',
  kid: '',
  iat: 1759765200,
  type: 'governed-action',
  payload: legacyB64,
  sig: '',
  prev: null
};
const legacySigned = signReceiptV1(legacyEnvelope, privPem, keyId);
const legacyVerified = verifyReceiptV1(legacySigned, pubPem);
assert('backward-compat: legacy payload (no canary fields) signs+verifies', true, legacyVerified.valid);
const legacyDecoded = decodePayloadV1(legacySigned);
assertFalsy('backward-compat: legacy payload has no h15_elapsed_seconds key', 'h15_elapsed_seconds' in legacyDecoded);
assertFalsy('backward-compat: legacy payload has no h14_alert_tier key', 'h14_alert_tier' in legacyDecoded);

// ═══════════════════════════════════════════════════════════════════════════════
// Cleanup
try { unlinkSync(privPath); unlinkSync(pubPath); } catch {}

// Summary
console.log();
console.log(`=== Results: ${pass}/${total} passed, ${fail} failed ===`);
if (fail > 0) process.exit(1);
