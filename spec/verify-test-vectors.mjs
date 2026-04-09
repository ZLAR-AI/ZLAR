#!/usr/bin/env node
// Cross-validate the test vectors embedded in governed-action-receipt-v1.md
// (Annex A) against the public key in test-key.pub.
//
// This script implements the §7 verification procedure from the v1 spec from
// scratch — it does NOT import lib/receipt.mjs. Its purpose is to prove the
// spec is implementable on its own, with no dependency on the rest of the
// ZLAR codebase.
//
// Run: node spec/verify-test-vectors.mjs

import { createHash, verify as cryptoVerify, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const publicKeyPem = readFileSync(join(__dirname, 'test-key.pub'), 'utf8');
const expectedKid = createHash('sha256').update(publicKeyPem).digest('hex').slice(0, 16);

// Parse the test vectors out of the spec's Annex A
const md = readFileSync(join(__dirname, 'governed-action-receipt-v1.md'), 'utf8');

// Find every "Complete signed envelope" code block in the spec
const envelopeRegex = /\*\*Complete signed envelope\*\*:\s*```json\s*([\s\S]*?)\s*```/g;
const envelopes = [];
let match;
while ((match = envelopeRegex.exec(md)) !== null) {
  envelopes.push(JSON.parse(match[1]));
}

console.log(`Found ${envelopes.length} envelopes in governed-action-receipt-v1.md`);
console.log(`Pinned kid: ${expectedKid}\n`);

function base64urlDecode(str) {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  return Buffer.from(b64, 'base64');
}

function sha256hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

const VALID_OUTCOMES = new Set(['allow', 'deny', 'authorized', 'denied', 'timeout']);
const VALID_AUTHORIZERS = new Set(['policy', 'human', 'gate', 'timeout', 'manifest']);
const APPROVAL_OUTCOMES = new Set(['allow', 'authorized']);
const DENY_ONLY_RULES = new Set(['R002', 'R003', 'R005', 'R006', 'R030', 'R032', 'R033', 'R034']);

const COHERENT_OUTCOMES = {
  policy:   new Set(['allow', 'deny']),
  human:    new Set(['authorized', 'denied']),
  timeout:  new Set(['timeout', 'denied', 'deny']),
  gate:     new Set(['deny', 'allow']),
  manifest: new Set(['allow', 'deny']),
};

function semanticValidate(payload) {
  // Completeness
  const required = ['tool', 'domain', 'detail_hash', 'outcome', 'rule', 'authorizer', 'ts', 'policy_version', 'audit_event_id', 'audit_prev_hash'];
  for (const f of required) {
    if (!(f in payload)) return { valid: false, code: 'MISSING_FIELD', field: f };
    if (typeof payload[f] === 'string' && payload[f].length === 0) return { valid: false, code: 'EMPTY_FIELD', field: f };
  }
  if (!/^[a-f0-9]{64}$/.test(payload.detail_hash)) return { valid: false, code: 'INVALID_DETAIL_HASH' };

  // Outcome / authorizer enums
  if (!VALID_OUTCOMES.has(payload.outcome)) return { valid: false, code: 'INVALID_OUTCOME', value: payload.outcome };
  if (!VALID_AUTHORIZERS.has(payload.authorizer)) return { valid: false, code: 'INVALID_AUTHORIZER', value: payload.authorizer };

  // Coherence
  const expected = COHERENT_OUTCOMES[payload.authorizer];
  if (expected && !expected.has(payload.outcome)) {
    return { valid: false, code: 'AUTHORIZER_OUTCOME_MISMATCH', authorizer: payload.authorizer, outcome: payload.outcome };
  }

  // Deny-only rule consistency
  if (DENY_ONLY_RULES.has(payload.rule) && APPROVAL_OUTCOMES.has(payload.outcome)) {
    return { valid: false, code: 'RULE_OUTCOME_CONTRADICTION', rule: payload.rule, outcome: payload.outcome };
  }

  // Delegation chain
  if (Array.isArray(payload.delegation_chain) && payload.delegation_chain.length > 0) {
    const chain = payload.delegation_chain;
    if (chain[0].depth !== 0) return { valid: false, code: 'DELEGATION_MISSING_ROOT' };
    for (let i = 1; i < chain.length; i++) {
      if (chain[i].depth <= chain[i - 1].depth) return { valid: false, code: 'DELEGATION_NON_MONOTONIC' };
    }
  }

  return { valid: true };
}

function verifyEnvelope(env, idx) {
  const result = { idx, id: env.id, sigOk: false, semanticOk: false, code: null };

  // Step 1-4: Envelope structure
  if (env.v !== 1) return { ...result, error: `bad version: ${env.v}` };
  if (env.type !== 'governed-action') return { ...result, error: `bad type: ${env.type}` };
  if (!env.payload || !env.sig || !env.kid || !env.id || env.iat == null) {
    return { ...result, error: 'missing envelope fields' };
  }
  if (env.kid !== expectedKid) {
    return { ...result, error: `kid mismatch: expected ${expectedKid}, got ${env.kid}` };
  }

  // Step 6-9: Decode payload, compute hash, verify signature
  const P = base64urlDecode(env.payload);
  const hashHex = sha256hex(P);
  const sigBytes = base64urlDecode(env.sig);
  const pubKey = createPublicKey(publicKeyPem);

  const sigOk = cryptoVerify(null, Buffer.from(hashHex, 'utf8'), pubKey, sigBytes);
  result.sigOk = sigOk;
  if (!sigOk) return { ...result, error: 'signature verification failed' };

  // Step 10-11: Parse payload, run semantic validation
  let payload;
  try {
    payload = JSON.parse(P.toString('utf8'));
  } catch (e) {
    return { ...result, error: 'payload not valid JSON' };
  }

  const sem = semanticValidate(payload);
  result.semanticOk = sem.valid;
  result.code = sem.code || 'OK';
  if (!sem.valid) {
    result.semanticDetail = sem;
  }

  return result;
}

console.log('Per-vector verification results:');
console.log('================================\n');
const results = envelopes.map((env, i) => verifyEnvelope(env, i + 1));

for (const r of results) {
  const sigStatus = r.sigOk ? '✓ SIG VALID' : '✗ SIG INVALID';
  const semStatus = r.semanticOk ? '✓ SEMANTIC VALID' : `✗ SEMANTIC ${r.code}`;
  console.log(`Vector ${r.idx}: ${sigStatus}  ${semStatus}`);
  if (r.error) console.log(`  Error: ${r.error}`);
  if (r.semanticDetail && !r.semanticDetail.valid) {
    console.log(`  Detail: ${JSON.stringify(r.semanticDetail)}`);
  }
}

// Expected outcomes (from spec):
// V1: sig valid, semantic valid (positive: minimal allow)
// V2: sig valid, semantic valid (positive: human authorized)
// V3: sig valid, semantic valid (positive: delegation chain depth 2)
// V4: sig valid, semantic INVALID with RULE_OUTCOME_CONTRADICTION (negative: R003+allow)
// V5: sig valid, semantic INVALID with AUTHORIZER_OUTCOME_MISMATCH (negative: policy+authorized)

console.log('\nExpected per spec:');
console.log('Vector 1: sig valid, semantic valid');
console.log('Vector 2: sig valid, semantic valid');
console.log('Vector 3: sig valid, semantic valid');
console.log('Vector 4: sig valid, semantic INVALID (RULE_OUTCOME_CONTRADICTION)');
console.log('Vector 5: sig valid, semantic INVALID (AUTHORIZER_OUTCOME_MISMATCH)');

const allMatch =
  results[0]?.sigOk && results[0]?.semanticOk &&
  results[1]?.sigOk && results[1]?.semanticOk &&
  results[2]?.sigOk && results[2]?.semanticOk &&
  results[3]?.sigOk && !results[3]?.semanticOk && results[3]?.code === 'RULE_OUTCOME_CONTRADICTION' &&
  results[4]?.sigOk && !results[4]?.semanticOk && results[4]?.code === 'AUTHORIZER_OUTCOME_MISMATCH';

console.log(`\n${allMatch ? '✓ ALL VECTORS MATCH SPEC EXPECTATIONS' : '✗ MISMATCH — vectors do not match spec'}`);
process.exit(allMatch ? 0 : 1);
