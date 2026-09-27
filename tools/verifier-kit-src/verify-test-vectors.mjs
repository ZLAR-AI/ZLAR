#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Verifier Kit v0.1 — Annex A Test-Vector Replay
//
// Cross-validates every Annex A test vector embedded in
// spec/governed-action-receipt-v1.md against the public key in
// spec/test-key.pub. Implements §7 of the v1 spec from scratch — no
// import from lib/. Its purpose is to prove the spec is implementable
// independent of lib/receipt.mjs.
//
// Invoked automatically by selftest.mjs on every verifier startup, and
// can be invoked directly:
//   node verify-test-vectors.mjs           # human output
//   node verify-test-vectors.mjs --quiet   # exit-code only, no per-vector lines
//
// Exit:
//   0 if all vectors match spec expectations
//   1 if any vector deviates
// ═══════════════════════════════════════════════════════════════════════════════

import { createHash, verify as cryptoVerify, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const QUIET = process.argv.includes('--quiet');

const publicKeyPem = readFileSync(join(__dirname, 'spec', 'test-key.pub'), 'utf8');
const expectedKid = createHash('sha256').update(publicKeyPem).digest('hex').slice(0, 16);

const md = readFileSync(join(__dirname, 'spec', 'governed-action-receipt-v1.md'), 'utf8');

const envelopeRegex = /\*\*Complete signed envelope\*\*:\s*```json\s*([\s\S]*?)\s*```/g;
const envelopes = [];
let match;
while ((match = envelopeRegex.exec(md)) !== null) {
  envelopes.push(JSON.parse(match[1]));
}

if (!QUIET) {
  process.stdout.write(`Found ${envelopes.length} envelopes in spec/governed-action-receipt-v1.md\n`);
  process.stdout.write(`Pinned kid: ${expectedKid}\n\n`);
}

function base64urlDecode(str) {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  return Buffer.from(b64, 'base64');
}

function sha256hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

const VALID_OUTCOMES = new Set(['allow', 'deny', 'authorized', 'denied', 'timeout']);
const VALID_AUTHORIZER_BASES = new Set(['policy', 'human', 'gate', 'timeout', 'manifest', 'standing']);
const APPROVAL_OUTCOMES = new Set(['allow', 'authorized']);
const DENY_ONLY_RULES = new Set(['R002', 'R003', 'R005', 'R006', 'R030', 'R032', 'R033', 'R034']);

function authorizerBase(a) {
  if (typeof a !== 'string' || a.length === 0) return null;
  const i = a.indexOf(':');
  return i === -1 ? a : a.substring(0, i);
}

const COHERENT_OUTCOMES = {
  policy:   new Set(['allow', 'deny']),
  human:    new Set(['authorized', 'denied']),
  timeout:  new Set(['timeout', 'denied', 'deny']),
  gate:     new Set(['deny', 'allow']),
  manifest: new Set(['allow', 'deny']),
  standing: new Set(['allow']),
};

function semanticValidate(payload) {
  const required = ['tool', 'domain', 'detail_hash', 'outcome', 'rule', 'authorizer', 'ts', 'policy_version', 'audit_event_id', 'audit_prev_hash'];
  for (const f of required) {
    if (!(f in payload)) return { valid: false, code: 'MISSING_FIELD', field: f };
    if (typeof payload[f] === 'string' && payload[f].length === 0) return { valid: false, code: 'EMPTY_FIELD', field: f };
  }
  if (!/^[a-f0-9]{64}$/.test(payload.detail_hash)) return { valid: false, code: 'INVALID_DETAIL_HASH' };
  if (!VALID_OUTCOMES.has(payload.outcome)) return { valid: false, code: 'INVALID_OUTCOME', value: payload.outcome };
  const authzBase = authorizerBase(payload.authorizer);
  if (!authzBase || !VALID_AUTHORIZER_BASES.has(authzBase)) return { valid: false, code: 'INVALID_AUTHORIZER', value: payload.authorizer };
  const expected = COHERENT_OUTCOMES[authzBase];
  if (expected && !expected.has(payload.outcome)) {
    return { valid: false, code: 'AUTHORIZER_OUTCOME_MISMATCH', authorizer: payload.authorizer, outcome: payload.outcome };
  }
  if (DENY_ONLY_RULES.has(payload.rule) && APPROVAL_OUTCOMES.has(payload.outcome)) {
    return { valid: false, code: 'RULE_OUTCOME_CONTRADICTION', rule: payload.rule, outcome: payload.outcome };
  }
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
  if (env.v !== 1) return { ...result, error: `bad version: ${env.v}` };
  if (env.type !== 'governed-action') return { ...result, error: `bad type: ${env.type}` };
  if (!env.payload || !env.sig || !env.kid || !env.id || env.iat == null) {
    return { ...result, error: 'missing envelope fields' };
  }
  if (env.kid !== expectedKid) {
    return { ...result, error: `kid mismatch: expected ${expectedKid}, got ${env.kid}` };
  }
  const P = base64urlDecode(env.payload);
  const hashHex = sha256hex(P);
  const sigBytes = base64urlDecode(env.sig);
  const pubKey = createPublicKey(publicKeyPem);
  const sigOk = cryptoVerify(null, Buffer.from(hashHex, 'utf8'), pubKey, sigBytes);
  result.sigOk = sigOk;
  if (!sigOk) return { ...result, error: 'signature verification failed' };
  let payload;
  try {
    payload = JSON.parse(P.toString('utf8'));
  } catch (e) {
    return { ...result, error: 'payload not valid JSON' };
  }
  const sem = semanticValidate(payload);
  result.semanticOk = sem.valid;
  result.code = sem.code || 'OK';
  if (!sem.valid) result.semanticDetail = sem;
  return result;
}

const results = envelopes.map((env, i) => verifyEnvelope(env, i + 1));

if (!QUIET) {
  process.stdout.write('Per-vector verification results:\n');
  process.stdout.write('================================\n\n');
  for (const r of results) {
    const sigStatus = r.sigOk ? 'SIG VALID  ' : 'SIG INVALID';
    const semStatus = r.semanticOk ? 'SEMANTIC VALID' : `SEMANTIC ${r.code}`;
    process.stdout.write(`Vector ${r.idx}: ${sigStatus}  ${semStatus}\n`);
    if (r.error) process.stdout.write(`  Error: ${r.error}\n`);
    if (r.semanticDetail && !r.semanticDetail.valid) {
      process.stdout.write(`  Detail: ${JSON.stringify(r.semanticDetail)}\n`);
    }
  }
}

// Expected outcomes (from spec Annex A — kept in sync with spec ceremony):
const expected = [
  { sig: true, sem: true,  code: 'OK' },                              // V1
  { sig: true, sem: true,  code: 'OK' },                              // V2
  { sig: true, sem: true,  code: 'OK' },                              // V3
  { sig: true, sem: false, code: 'RULE_OUTCOME_CONTRADICTION' },      // V4
  { sig: true, sem: false, code: 'AUTHORIZER_OUTCOME_MISMATCH' },     // V5
  { sig: true, sem: true,  code: 'OK' },                              // V6
  { sig: true, sem: true,  code: 'OK' },                              // V7
  { sig: true, sem: false, code: 'AUTHORIZER_OUTCOME_MISMATCH' },     // V8
  { sig: true, sem: false, code: 'DELEGATION_MISSING_ROOT' },         // V9
];

const allMatch = expected.length === results.length && expected.every((e, i) => {
  const r = results[i];
  return r && r.sigOk === e.sig && r.semanticOk === e.sem && r.code === e.code;
});

if (!QUIET) {
  process.stdout.write('\nExpected per spec: V1-V3 valid; V4 RULE_OUTCOME_CONTRADICTION; V5 AUTHORIZER_OUTCOME_MISMATCH;\n');
  process.stdout.write('V6-V7 valid; V8 AUTHORIZER_OUTCOME_MISMATCH; V9 DELEGATION_MISSING_ROOT.\n');
  process.stdout.write(`\n${allMatch ? 'ALL VECTORS MATCH SPEC EXPECTATIONS' : 'MISMATCH — vectors do not match spec'}\n`);
}

process.exit(allMatch ? 0 : 1);
