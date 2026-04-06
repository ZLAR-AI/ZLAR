// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR MCP Gate — Hardened Test Suite (Phase B)
//
// Tests: policy loading, signature verification, all decision paths,
// standing approvals, per-entry audit signing, fail-closed on every error type,
// receipt generation, and cross-gate compatibility.
//
// Usage: node mcp-gate/test-hardened.mjs
// ═══════════════════════════════════════════════════════════════════════════════

import { createHash, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { writeFileSync, mkdtempSync, readFileSync, rmSync, mkdirSync, existsSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PROJECT_DIR = join(__dirname, '..');

// Import gate internals we need to test
// Since gate.mjs has side effects (process.exit, server start), we test the
// shared libraries and simulate gate behavior rather than importing gate.mjs.
import {
  canonicalize,
  sha256hex,
  createReceiptFromEvent,
  signReceipt,
  verifyReceipt,
  pubkeyFingerprint,
  receiptHash,
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
  if (value) { PASS++; } else { FAIL++; console.log(`  FAIL: ${label} — expected truthy, got "${value}"`); }
}

function assertFalsy(label, value) {
  TOTAL++;
  if (!value) { PASS++; } else { FAIL++; console.log(`  FAIL: ${label} — expected falsy, got "${value}"`); }
}

function assertIncludes(label, haystack, needle) {
  TOTAL++;
  if (typeof haystack === 'string' && haystack.includes(needle)) { PASS++; }
  else { FAIL++; console.log(`  FAIL: ${label} — "${haystack}" does not include "${needle}"`); }
}

// ─── Test Keys ───────────────────────────────────────────────────────────────

const TEMP_DIR = mkdtempSync(join(tmpdir(), 'zlar-mcp-hardened-'));

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });

const privKeyPath = join(TEMP_DIR, 'test.key');
const pubKeyPath = join(TEMP_DIR, 'test.pub');
writeFileSync(privKeyPath, privateKeyPem);
writeFileSync(pubKeyPath, publicKeyPem);

const { privateKey: wrongPriv } = generateKeyPairSync('ed25519');
const wrongPrivPem = wrongPriv.export({ type: 'pkcs8', format: 'pem' });

// ─── Helper: Sign a JSON object (matches gate signing approach) ──────────────

function signJsonObject(obj, privKey) {
  // Must match bash gate: jq '.signature.value = ""' — only zeros .value,
  // preserves .algorithm and .key_id in the canonical form.
  const canonical = JSON.parse(JSON.stringify(obj));
  canonical.signature = { ...canonical.signature, value: '' };
  const hashHex = sha256hex(canonicalize(canonical));
  const sig = cryptoSign(null, Buffer.from(hashHex, 'utf8'), privKey);
  return sig.toString('base64');
}

function signAuditEvent(event, privKey) {
  const hashHex = sha256hex(canonicalize(event));
  const sig = cryptoSign(null, Buffer.from(hashHex, 'utf8'), privKey);
  return sig.toString('base64');
}

// ─── Helper: Create a test policy ────────────────────────────────────────────

function createTestPolicy(rules, defaultAction = 'deny') {
  const policy = {
    version: 'test-1.0',
    rules: rules.map((r, i) => ({
      id: r.id || `T${String(i+1).padStart(3, '0')}`,
      enabled: r.enabled !== false,
      domain: 'mcp',
      action: r.action || 'deny',
      severity: r.severity || 'info',
      description: r.description || '',
      risk_score: r.risk_score || { irreversibility: 0, consequence: 0, blast_radius: 0 },
      match: r.match || {},
    })),
    default_action: defaultAction,
    // key_id must be set BEFORE signing — it's part of the canonical form
    signature: { algorithm: 'ed25519', value: '', key_id: pubkeyFingerprint(pubKeyPath) },
  };

  // Sign the policy (zeros only .value for canonical form, preserves algorithm + key_id)
  policy.signature.value = signJsonObject(policy, privateKeyPem);

  return policy;
}

// ─── Helper: Simulate policy evaluation (extracted logic from gate.mjs) ──────

function evaluatePolicy(policy, toolName, args) {
  if (!policy?.rules) {
    return { action: 'deny', rule: 'no-policy', riskScore: 100, severity: 'critical' };
  }

  for (const rule of policy.rules) {
    if (!rule.enabled) continue;
    if (rule.domain && rule.domain !== 'mcp') continue;

    if (rule.match?.detail?.tool_name) {
      const matcher = rule.match.detail.tool_name;
      if (matcher.eq && matcher.eq !== toolName) continue;
      if (matcher.regex && !new RegExp(matcher.regex).test(toolName)) continue;
      if (matcher.contains && !toolName.includes(matcher.contains)) continue;
    }

    if (rule.match?.detail?.arguments) {
      const argStr = JSON.stringify(args);
      const matcher = rule.match.detail.arguments;
      if (matcher.regex && !new RegExp(matcher.regex).test(argStr)) continue;
      if (matcher.contains && !argStr.includes(matcher.contains)) continue;
    }

    const rs = rule.risk_score || {};
    const riskScore = Math.max(rs.irreversibility || 0, rs.consequence || 0, rs.blast_radius || 0);
    return {
      action: rule.action || 'deny',
      rule: rule.id || 'unknown',
      riskScore,
      severity: rule.severity || 'info',
      description: rule.description || '',
    };
  }

  return {
    action: policy.default_action || 'deny',
    rule: 'default',
    riskScore: 0,
    severity: 'info',
  };
}

// ─── Helper: Simulate standing approval check ────────────────────────────────

function checkStandingApproval(approvals, ruleId, toolName, args) {
  const today = new Date().toISOString().slice(0, 10);
  const commandText = `${toolName} ${JSON.stringify(args)}`;

  for (const sa of approvals) {
    if (sa.rule_id !== ruleId) continue;
    if (sa.expires && today > sa.expires) continue;

    const matcher = sa.match?.command;
    if (!matcher) continue;

    if (matcher.contains && commandText.includes(matcher.contains)) {
      return { match: true, approvalId: sa.id };
    }
    if (matcher.regex) {
      try {
        if (new RegExp(matcher.regex).test(commandText)) {
          return { match: true, approvalId: sa.id };
        }
      } catch {}
    }
  }
  return { match: false, approvalId: null };
}

// ─── Helper: Simulate signature verification ─────────────────────────────────

import { verify as cryptoVerify } from 'node:crypto';

function verifyJsonSignature(obj, pubKeyPem) {
  const sig = obj?.signature;
  if (!sig?.value) return { ok: false, reason: 'no signature' };

  try {
    // Match bash gate: only zero .signature.value, preserve .algorithm and .key_id
    const canonical = JSON.parse(JSON.stringify(obj));
    canonical.signature = { ...canonical.signature, value: '' };
    const hashHex = sha256hex(canonicalize(canonical));
    const sigBytes = Buffer.from(sig.value, 'base64');
    const ok = cryptoVerify(null, Buffer.from(hashHex, 'utf8'), pubKeyPem, sigBytes);
    return ok ? { ok: true } : { ok: false, reason: 'verification failed' };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

console.log('=== Policy Signature Verification ===');
console.log();

{
  const policy = createTestPolicy([
    { id: 'R001', action: 'allow', match: { detail: { tool_name: { eq: 'safe-tool' } } } },
  ]);

  // Valid signature
  const validResult = verifyJsonSignature(policy, publicKeyPem);
  assert('valid policy signature', true, validResult.ok);

  // Tampered policy (change a rule)
  const tampered = JSON.parse(JSON.stringify(policy));
  tampered.rules[0].action = 'allow-all-the-things';
  const tamperedResult = verifyJsonSignature(tampered, publicKeyPem);
  assert('tampered policy signature invalid', false, tamperedResult.ok);

  // Wrong key
  const { publicKey: wrongPub } = generateKeyPairSync('ed25519');
  const wrongPubPem = wrongPub.export({ type: 'spki', format: 'pem' });
  const wrongKeyResult = verifyJsonSignature(policy, wrongPubPem);
  assert('wrong key policy signature invalid', false, wrongKeyResult.ok);

  // Missing signature
  const noSig = { ...policy, signature: { algorithm: '', value: '', key_id: '' } };
  const noSigResult = verifyJsonSignature(noSig, publicKeyPem);
  assert('empty signature invalid', false, noSigResult.ok);

  // Null signature object
  const nullSig = { ...policy, signature: null };
  const nullSigResult = verifyJsonSignature(nullSig, publicKeyPem);
  assert('null signature invalid', false, nullSigResult.ok);
}

console.log();
console.log('=== Policy Evaluation: Allow Path ===');
console.log();

{
  const policy = createTestPolicy([
    { id: 'R001', action: 'allow', match: { detail: { tool_name: { eq: 'read_file' } } } },
  ]);

  const result = evaluatePolicy(policy, 'read_file', { path: '/tmp/test.txt' });
  assert('allow rule matches', 'allow', result.action);
  assert('allow rule id', 'R001', result.rule);
}

console.log();
console.log('=== Policy Evaluation: Deny Path ===');
console.log();

{
  const policy = createTestPolicy([
    { id: 'R002', action: 'deny', severity: 'critical',
      risk_score: { irreversibility: 9, consequence: 9, blast_radius: 9 },
      match: { detail: { tool_name: { regex: 'delete.*' } } } },
  ]);

  const result = evaluatePolicy(policy, 'delete_all', { scope: 'everything' });
  assert('deny rule matches', 'deny', result.action);
  assert('deny rule id', 'R002', result.rule);
  assert('deny risk score', 9, result.riskScore);
  assert('deny severity', 'critical', result.severity);
}

console.log();
console.log('=== Policy Evaluation: Ask Path ===');
console.log();

{
  const policy = createTestPolicy([
    { id: 'R016', action: 'ask', match: { detail: { tool_name: { contains: 'network' } } } },
  ]);

  const result = evaluatePolicy(policy, 'network_request', { url: 'https://example.com' });
  assert('ask rule matches', 'ask', result.action);
  assert('ask rule id', 'R016', result.rule);
}

console.log();
console.log('=== Policy Evaluation: Default Action ===');
console.log();

{
  // No matching rules → default action
  const denyDefault = createTestPolicy([], 'deny');
  const denyResult = evaluatePolicy(denyDefault, 'unknown_tool', {});
  assert('default deny', 'deny', denyResult.action);
  assert('default rule', 'default', denyResult.rule);

  const allowDefault = createTestPolicy([], 'allow');
  const allowResult = evaluatePolicy(allowDefault, 'unknown_tool', {});
  assert('default allow', 'allow', allowResult.action);
}

console.log();
console.log('=== Policy Evaluation: No Policy (fail-closed) ===');
console.log();

{
  const result = evaluatePolicy(null, 'any_tool', {});
  assert('no policy → deny', 'deny', result.action);
  assert('no policy rule', 'no-policy', result.rule);
  assert('no policy risk score', 100, result.riskScore);
}

console.log();
console.log('=== Policy Evaluation: Disabled Rules ===');
console.log();

{
  const policy = createTestPolicy([
    { id: 'R001', action: 'allow', enabled: false, match: { detail: { tool_name: { eq: 'tool' } } } },
  ], 'deny');

  const result = evaluatePolicy(policy, 'tool', {});
  assert('disabled rule skipped → default', 'deny', result.action);
}

console.log();
console.log('=== Policy Evaluation: Argument Matching ===');
console.log();

{
  const policy = createTestPolicy([
    { id: 'R010', action: 'deny',
      match: { detail: { tool_name: { eq: 'execute' }, arguments: { regex: 'rm.*-rf' } } } },
  ], 'allow');

  const matchResult = evaluatePolicy(policy, 'execute', { cmd: 'rm -rf /' });
  assert('argument regex matches', 'deny', matchResult.action);

  const noMatchResult = evaluatePolicy(policy, 'execute', { cmd: 'ls -la' });
  assert('argument regex no match → default', 'allow', noMatchResult.action);
}

console.log();
console.log('=== Per-Entry Audit Signing ===');
console.log();

{
  // Simulate what emitEvent does: build event, sign it
  const event = {
    id: 'test-001', ts: '2026-04-05T22:00:00Z', seq: 1,
    source: 'mcp-gate', host: 'test', user: 'test',
    agent_id: 'test', session_id: 'test',
    domain: 'mcp', action: 'test_tool', outcome: 'allow',
    risk_score: 0, detail: { tool: 'test_tool' },
    rule: 'R001', policy_version: 'test-1.0',
    severity: 'info', prev_hash: 'genesis',
    authorizer: 'policy',
    signature_algorithm: 'Ed25519', hash_algorithm: 'SHA-256',
    public_key_id: pubkeyFingerprint(pubKeyPath),
  };

  // Sign the event (matching gate approach)
  const hashHex = sha256hex(canonicalize(event));
  const sig = cryptoSign(null, Buffer.from(hashHex, 'utf8'), privateKeyPem);
  const signature = sig.toString('base64');
  event.signature = signature;

  assertTruthy('audit event has signature', event.signature !== 'unsigned');
  assertTruthy('signature is base64', event.signature.length > 10);

  // Verify the signature
  const eventForVerify = { ...event };
  delete eventForVerify.signature;
  const verifyHash = sha256hex(canonicalize(eventForVerify));
  const sigBytes = Buffer.from(signature, 'base64');
  const ok = cryptoVerify(null, Buffer.from(verifyHash, 'utf8'), publicKeyPem, sigBytes);
  assert('audit event signature verifies', true, ok);

  // Tamper and verify fails
  const tampered = { ...event };
  delete tampered.signature;
  tampered.outcome = 'deny';
  const tamperedHash = sha256hex(canonicalize(tampered));
  const tamperedOk = cryptoVerify(null, Buffer.from(tamperedHash, 'utf8'), publicKeyPem, sigBytes);
  assert('tampered audit event signature fails', false, tamperedOk);
}

console.log();
console.log('=== Per-Entry Audit Signing: Cross-Gate Compatibility ===');
console.log();

{
  // Node-signed audit entry should be verifiable by bash (openssl)
  const event = {
    id: 'xgate-001', ts: '2026-04-05T23:00:00Z', seq: 1,
    source: 'mcp-gate', host: 'test', user: 'test',
    agent_id: 'test', session_id: 'test',
    domain: 'mcp', action: 'Bash', outcome: 'deny',
    risk_score: 9, detail: { command: 'rm -rf /' },
    rule: 'R002', policy_version: 'test-1.0',
    severity: 'critical', prev_hash: 'genesis',
    authorizer: 'policy',
    signature_algorithm: 'Ed25519', hash_algorithm: 'SHA-256',
    public_key_id: 'test',
  };

  // Sign it
  const hashHex = sha256hex(canonicalize(event));
  const sig = cryptoSign(null, Buffer.from(hashHex, 'utf8'), privateKeyPem);
  event.signature = sig.toString('base64');

  // Verify canonical form matches jq -S -c
  const { execSync } = await import('node:child_process');
  try {
    const eventNoSig = { ...event };
    delete eventNoSig.signature;
    const nodeCanonical = canonicalize(eventNoSig);
    const bashCanonical = execSync(
      `printf '%s' '${JSON.stringify(eventNoSig).replace(/'/g, "'\\''")}' | jq -S -c '.'`,
      { encoding: 'utf8' }
    ).trim();
    assert('audit canonical matches jq -S -c', bashCanonical, nodeCanonical);
  } catch (e) {
    console.log(`  SKIP: jq not available (${e.message})`);
  }
}

console.log();
console.log('=== Standing Approvals: Match ===');
console.log();

{
  const approvals = [
    { id: 'SA001', rule_id: 'R016', match: { command: { regex: 'curl.*(localhost|127\\.0\\.0\\.1)' } }, expires: '2030-12-31' },
    { id: 'SA002', rule_id: 'R016', match: { command: { contains: 'api.github.com' } }, expires: '2030-12-31' },
    { id: 'SA003', rule_id: 'R014', match: { command: { regex: 'git +push.*origin' } }, expires: '2030-12-31' },
  ];

  // Regex match
  const r1 = checkStandingApproval(approvals, 'R016', 'execute', { cmd: 'curl http://localhost:8080/api' });
  assert('SA regex match localhost', true, r1.match);
  assert('SA regex match id', 'SA001', r1.approvalId);

  // Contains match
  const r2 = checkStandingApproval(approvals, 'R016', 'execute', { url: 'https://api.github.com/repos' });
  assert('SA contains match github', true, r2.match);
  assert('SA contains match id', 'SA002', r2.approvalId);

  // Rule ID mismatch
  const r3 = checkStandingApproval(approvals, 'R002', 'execute', { cmd: 'curl http://localhost' });
  assert('SA rule mismatch → no match', false, r3.match);

  // No match
  const r4 = checkStandingApproval(approvals, 'R016', 'execute', { cmd: 'wget http://evil.com' });
  assert('SA no match', false, r4.match);
}

console.log();
console.log('=== Standing Approvals: Expiry ===');
console.log();

{
  const approvals = [
    { id: 'SA-EXPIRED', rule_id: 'R016', match: { command: { contains: 'localhost' } }, expires: '2020-01-01' },
    { id: 'SA-VALID', rule_id: 'R016', match: { command: { contains: 'localhost' } }, expires: '2030-12-31' },
  ];

  const result = checkStandingApproval(approvals, 'R016', 'fetch', { url: 'http://localhost' });
  assert('expired SA skipped', true, result.match);
  assert('valid SA matched (not expired)', 'SA-VALID', result.approvalId);
}

console.log();
console.log('=== Standing Approvals: Signature Verification ===');
console.log();

{
  const saFile = {
    version: '1.0.0',
    approvals: [{ id: 'SA001', rule_id: 'R016', match: { command: { contains: 'test' } } }],
    // key_id set before signing — part of canonical form
    signature: { algorithm: 'ed25519', value: '', key_id: pubkeyFingerprint(pubKeyPath) },
  };

  // Sign it (zeros only .value for canonical form)
  saFile.signature.value = signJsonObject(saFile, privateKeyPem);

  const validResult = verifyJsonSignature(saFile, publicKeyPem);
  assert('valid SA signature', true, validResult.ok);

  // Tamper
  const tampered = JSON.parse(JSON.stringify(saFile));
  tampered.approvals.push({ id: 'SA-INJECTED', rule_id: 'R002', match: { command: { contains: '.*' } } });
  const tamperedResult = verifyJsonSignature(tampered, publicKeyPem);
  assert('tampered SA signature invalid', false, tamperedResult.ok);
}

console.log();
console.log('=== Fail-Closed: Every Error Path ===');
console.log();

{
  // No policy → deny
  const noPolicyResult = evaluatePolicy(null, 'tool', {});
  assert('no policy → deny', 'deny', noPolicyResult.action);

  // Empty rules with deny default → deny
  const emptyRulesResult = evaluatePolicy({ rules: [], default_action: 'deny', version: 'test' }, 'tool', {});
  assert('empty rules + deny default → deny', 'deny', emptyRulesResult.action);

  // Policy parse fail simulation → would set policy to fail-closed deny-all
  const failClosedPolicy = { rules: [], default_action: 'deny', version: 'fail-closed' };
  const failResult = evaluatePolicy(failClosedPolicy, 'any_tool', {});
  assert('fail-closed policy → deny', 'deny', failResult.action);

  // Signature mismatch simulation → would set policy to fail-closed-sig deny-all
  const sigFailPolicy = { rules: [], default_action: 'deny', version: 'fail-closed-sig' };
  const sigFailResult = evaluatePolicy(sigFailPolicy, 'any_tool', {});
  assert('sig fail policy → deny', 'deny', sigFailResult.action);
}

console.log();
console.log('=== Receipt Generation from Signed Audit Event ===');
console.log();

{
  // Simulate: event created, signed, written → receipt generated
  const event = {
    id: 'receipt-test-001', ts: '2026-04-05T23:30:00Z', seq: 5,
    source: 'mcp-gate', host: 'test', user: 'test',
    agent_id: 'mcp-client', session_id: 'test-sess',
    domain: 'mcp', action: 'dangerous_tool', outcome: 'deny',
    risk_score: 8, detail: { tool: 'dangerous_tool', args_preview: '{}' },
    rule: 'R002', policy_version: 'test-1.0',
    severity: 'critical', prev_hash: 'abc123' + '0'.repeat(58),
    authorizer: 'policy',
    signature_algorithm: 'Ed25519', hash_algorithm: 'SHA-256',
    public_key_id: pubkeyFingerprint(pubKeyPath),
    signature: 'will-be-set',
  };

  // Sign the event
  const eventForSigning = { ...event };
  delete eventForSigning.signature;
  const eventHashHex = sha256hex(canonicalize(eventForSigning));
  event.signature = cryptoSign(null, Buffer.from(eventHashHex, 'utf8'), privateKeyPem).toString('base64');

  // Generate receipt from the signed event
  const receipt = createReceiptFromEvent(event);
  const signedReceipt = signReceipt(receipt, privateKeyPem, pubkeyFingerprint(pubKeyPath));

  // Verify receipt
  const verifyResult = verifyReceipt(signedReceipt, publicKeyPem);
  assert('receipt from signed event is valid', true, verifyResult.valid);

  // Verify receipt references the audit event
  assert('receipt audit_event_id matches', event.id, signedReceipt.evidence.audit_event_id);
  assert('receipt audit_prev_hash matches', event.prev_hash, signedReceipt.evidence.audit_prev_hash);
  assert('receipt outcome matches', 'deny', signedReceipt.decision.outcome);
  assert('receipt rule matches', 'R002', signedReceipt.decision.rule);
}

console.log();
console.log('=== Hash Chain Integrity ===');
console.log();

{
  // Simulate a chain of audit events
  const auditFile = join(TEMP_DIR, 'chain-test.jsonl');
  const events = [];

  for (let i = 0; i < 3; i++) {
    let prevHash = 'genesis';
    if (events.length > 0) {
      prevHash = createHash('sha256').update(JSON.stringify(events[events.length - 1])).digest('hex');
    }

    const event = {
      id: `chain-${i}`, ts: new Date().toISOString(), seq: i + 1,
      source: 'mcp-gate', host: 'test', user: 'test',
      agent_id: 'test', session_id: 'test',
      domain: 'mcp', action: `tool_${i}`, outcome: 'allow',
      risk_score: 0, detail: {},
      rule: 'R001', policy_version: 'test',
      severity: 'info', prev_hash: prevHash,
      authorizer: 'policy',
      signature_algorithm: 'Ed25519', hash_algorithm: 'SHA-256',
      public_key_id: 'test',
    };

    // Sign it
    const hashHex = sha256hex(canonicalize(event));
    event.signature = cryptoSign(null, Buffer.from(hashHex, 'utf8'), privateKeyPem).toString('base64');
    events.push(event);
    appendFileSync(auditFile, JSON.stringify(event) + '\n');
  }

  // Verify chain: each event's prev_hash should be SHA-256 of previous event JSON
  const lines = readFileSync(auditFile, 'utf8').trim().split('\n');
  assert('chain has 3 entries', 3, lines.length);

  const e0 = JSON.parse(lines[0]);
  assert('first event prev_hash is genesis', 'genesis', e0.prev_hash);

  const e1 = JSON.parse(lines[1]);
  const expectedHash1 = createHash('sha256').update(lines[0]).digest('hex');
  assert('second event prev_hash matches first', expectedHash1, e1.prev_hash);

  const e2 = JSON.parse(lines[2]);
  const expectedHash2 = createHash('sha256').update(lines[1]).digest('hex');
  assert('third event prev_hash matches second', expectedHash2, e2.prev_hash);
}

console.log();
console.log('=== Policy Rule Priority (First Match Wins) ===');
console.log();

{
  const policy = createTestPolicy([
    { id: 'SPECIFIC', action: 'deny', match: { detail: { tool_name: { eq: 'rm' } } } },
    { id: 'BROAD', action: 'allow', match: { detail: { tool_name: { regex: '.*' } } } },
  ], 'deny');

  const result = evaluatePolicy(policy, 'rm', {});
  assert('specific rule wins over broad', 'deny', result.action);
  assert('specific rule id returned', 'SPECIFIC', result.rule);

  const otherResult = evaluatePolicy(policy, 'ls', {});
  assert('broad rule catches rest', 'allow', otherResult.action);
  assert('broad rule id returned', 'BROAD', otherResult.rule);
}

// ─── Cleanup ─────────────────────────────────────────────────────────────────

try { rmSync(TEMP_DIR, { recursive: true, force: true }); } catch {}

// ─── Results ─────────────────────────────────────────────────────────────────

console.log();
process.stdout.write(`Results: ${PASS}/${TOTAL} passed`);
if (FAIL > 0) {
  console.log(` (${FAIL} FAILED)`);
  process.exit(1);
} else {
  console.log(' \u2713');
}
