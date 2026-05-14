#!/usr/bin/env node
// Hermetic routed-MCP client proof harness.
//
// This uses a synthetic local MCP client so the reusable proof shape can be
// tested without installed clients, external services, or global MCP config.

import { createServer } from 'node:net';
import { spawn } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { canonicalize, sha256hex } from '../lib/receipt.mjs';
import {
  assertNoUnsafeReportText,
  assertRoutedMcpClientProofReport,
  buildRoutedMcpClientProofReport,
} from './routed-mcp-client-proof.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = join(__dirname, '..');

let PASS = 0;
let FAIL = 0;
let TOTAL = 0;

function assert(label, condition, detail = '') {
  TOTAL++;
  if (condition) {
    PASS++;
    console.log(`  PASS: ${label}`);
  } else {
    FAIL++;
    console.log(`  FAIL: ${label}${detail ? ` -- ${detail}` : ''}`);
  }
}

function assertEqual(label, expected, actual) {
  assert(label, expected === actual, `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
}

function assertThrows(label, fn, expectedMessageFragment) {
  TOTAL++;
  try {
    fn();
    FAIL++;
    console.log(`  FAIL: ${label} -- expected throw`);
  } catch (error) {
    if (!expectedMessageFragment || String(error.message).includes(expectedMessageFragment)) {
      PASS++;
      console.log(`  PASS: ${label}`);
    } else {
      FAIL++;
      console.log(`  FAIL: ${label} -- ${error.message}`);
    }
  }
}

function section(title) {
  console.log(`\n-- ${title} --`);
}

const UNSAFE_CREDENTIAL_FIXTURES = Object.freeze([
  'token=fake-proof-token-000000',
  'secret=fake-proof-secret-000000',
  'password=fake-proof-password-000000',
  'api_key=fake-proof-api-key-000000',
  'authorization: Bearer fakeBearerProof000000',
  'authorization=Basic fakeBasicProof000000',
  'Bearer fakeStandaloneBearer000000',
  'Basic fakeStandaloneBasic000000',
  'ghp_FAKEproofToken000000',
  'github_pat_FAKEproofToken000000',
  'xoxb-fake-proof-token-000000',
  'xoxp-fake-proof-token-000000',
  'xoxa-fake-proof-token-000000',
  'xoxr-fake-proof-token-000000',
  'xoxs-fake-proof-token-000000',
  'AKIAFAKE000000000000',
  'sk-fakeproofcredential000000',
  'pk-fakeproofcredential000000',
  'bot123456789:FAKE_bot_token_000000',
]);

const SCRATCH = mkdtempSync(join(tmpdir(), 'zlar-routed-mcp-client-proof-'));
const TMP_PROJECT = join(SCRATCH, 'project');
const TMP_HOME = join(SCRATCH, 'home');
const AUDIT_FILE = join(SCRATCH, 'proof.audit.jsonl');
const WORKER_RECEIPT_FILE = join(SCRATCH, 'proof.worker-receipts.jsonl');
const ROUTING_CONFIG = join(SCRATCH, 'upstreams.json');
const POLICY_PATH = join(SCRATCH, 'proof.policy.json');
const POLICY_PUB_PATH = join(SCRATCH, 'policy-signing.pub');

const children = [];
const servers = [];
const { publicKey: POLICY_PUBLIC_KEY, privateKey: POLICY_PRIVATE_KEY } = generateKeyPairSync('ed25519');

function signJson(obj) {
  const withSig = {
    ...obj,
    signature: {
      algorithm: 'ed25519',
      public_key: POLICY_PUBLIC_KEY.export({ type: 'spki', format: 'der' }).toString('base64'),
      value: '',
    },
  };
  const hashHex = sha256hex(canonicalize(withSig));
  const sig = cryptoSign(null, Buffer.from(hashHex, 'utf8'), POLICY_PRIVATE_KEY);
  return { ...withSig, signature: { ...withSig.signature, value: sig.toString('base64') } };
}

function copyGateProject() {
  mkdirSync(TMP_PROJECT, { recursive: true });
  cpSync(join(REPO_ROOT, 'mcp-gate'), join(TMP_PROJECT, 'mcp-gate'), { recursive: true });
  cpSync(join(REPO_ROOT, 'lib'), join(TMP_PROJECT, 'lib'), { recursive: true });
  mkdirSync(join(TMP_PROJECT, 'packages'), { recursive: true });
  cpSync(join(REPO_ROOT, 'packages', 'zlar-restore'), join(TMP_PROJECT, 'packages', 'zlar-restore'), { recursive: true });
  mkdirSync(join(TMP_PROJECT, 'etc', 'policies'), { recursive: true });
  mkdirSync(join(TMP_PROJECT, 'etc', 'keys'), { recursive: true });
  mkdirSync(join(TMP_PROJECT, 'var', 'log'), { recursive: true });
  writeFileSync(join(TMP_PROJECT, 'etc', 'gate.json'), JSON.stringify({
    telegram: { chat_id: 'routed-proof-human', timeout_s: 2 },
    canary: {
      enabled: true,
      min_approvals_before_trigger: 999,
      probability_percent: 0,
      cooldown_s: 999999,
    },
  }));
}

function writeAuditSigningKey() {
  mkdirSync(TMP_HOME, { recursive: true });
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(join(TMP_HOME, '.zlar-signing.key'), privateKey.export({ type: 'pkcs8', format: 'pem' }));
  writeFileSync(join(TMP_HOME, '.zlar-signing.pub'), publicKey.export({ type: 'spki', format: 'pem' }));
}

function writePolicy() {
  writeFileSync(POLICY_PUB_PATH, POLICY_PUBLIC_KEY.export({ type: 'spki', format: 'pem' }));
  writeFileSync(POLICY_PATH, JSON.stringify(signJson({
    version: 'routed-mcp-client-proof-1',
    default_action: 'deny',
    rules: [
      {
        id: 'RMCP_ALLOW',
        enabled: true,
        description: 'Routed MCP proof allow marker',
        domain: 'mcp',
        action: 'allow',
        severity: 'info',
        match: { domain: 'mcp', detail: { tool_name: { eq: 'proof.allow' } } },
        risk_score: { irreversibility: 0, consequence: 0, blast_radius: 0 },
      },
      {
        id: 'RMCP_DENY',
        enabled: true,
        description: 'Routed MCP proof deny marker',
        domain: 'mcp',
        action: 'deny',
        severity: 'critical',
        match: { domain: 'mcp', detail: { tool_name: { eq: 'proof.deny' } } },
        risk_score: { irreversibility: 100, consequence: 100, blast_radius: 100 },
      },
    ],
  })));
}

function writeRoutingConfig(upstreamPort) {
  writeFileSync(ROUTING_CONFIG, JSON.stringify([
    {
      server_name: 'routed-proof',
      transport: 'tcp',
      host: '127.0.0.1',
      port: upstreamPort,
    },
  ]));
}

async function startFakeUpstream() {
  const state = { calls: [], markerExecutions: [] };
  const server = createServer((socket) => {
    let buffer = '';
    socket.on('data', (data) => {
      buffer += data.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        if (!line.trim()) continue;
        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          continue;
        }
        state.calls.push(msg);
        if (msg.method === 'initialize') {
          socket.write(`${JSON.stringify({
            jsonrpc: '2.0',
            id: msg.id,
            result: {
              protocolVersion: msg.params?.protocolVersion || '2024-11-05',
              capabilities: { tools: {} },
              serverInfo: { name: 'routed-proof-fake-upstream', version: '0.0.1' },
            },
          })}\n`);
        } else if (msg.method === 'tools/list') {
          socket.write(`${JSON.stringify({
            jsonrpc: '2.0',
            id: msg.id,
            result: {
              tools: [
                { name: 'proof.allow', inputSchema: { type: 'object' } },
                { name: 'proof.deny', inputSchema: { type: 'object' } },
              ],
            },
          })}\n`);
        } else if (msg.method === 'tools/call') {
          state.markerExecutions.push(msg.params?.name || 'unknown');
          socket.write(`${JSON.stringify({
            jsonrpc: '2.0',
            id: msg.id,
            result: { content: [{ type: 'text', text: `fake upstream executed ${msg.params?.name}` }] },
          })}\n`);
        } else {
          socket.write(`${JSON.stringify({
            jsonrpc: '2.0',
            id: msg.id,
            result: { ok: true, method: msg.method },
          })}\n`);
        }
      }
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  servers.push(server);
  return { port: server.address().port, state };
}

function spawnGate() {
  const child = spawn(process.execPath, [
    join(TMP_PROJECT, 'mcp-gate', 'gate.mjs'),
    '--stdio',
    '--config', ROUTING_CONFIG,
    '--audit-file', AUDIT_FILE,
    '--policy-file', POLICY_PATH,
    '--policy-pubkey', POLICY_PUB_PATH,
    '--manifest-file', join(SCRATCH, 'missing-manifest.json'),
    '--constitution-presence-file', join(SCRATCH, 'missing-constitution-presence'),
    '--restore-config-file', join(SCRATCH, 'missing-restore-config.json'),
    '--agent-id', 'routed-proof-agent',
    '--session-id', 'routed-proof-session',
    '--no-telegram',
  ], {
    cwd: TMP_PROJECT,
    env: {
      ...process.env,
      HOME: TMP_HOME,
      ZLAR_REQUIRE_SIGNED_AUDIT: 'true',
      ZLAR_WORKER_RECEIPT_FILE: WORKER_RECEIPT_FILE,
      ZLAR_CANARY_MIN_APPROVALS: '999',
      ZLAR_CANARY_COOLDOWN: '999999',
      ZLAR_CANARY_STATE_DIR: join(SCRATCH, 'canary'),
      ZLAR_CC_INBOX_DIR: join(SCRATCH, 'cc-inbox'),
      ZLAR_MCP_INBOX_DIR: join(SCRATCH, 'mcp-inbox'),
      ZLAR_HUMAN_STATE_HMAC_KEY_FILE: join(SCRATCH, 'missing-human-hmac.key'),
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  children.push(child);
  return child;
}

function collectProcess(child) {
  const state = { stdout: '', stderr: '', jsonLines: [], nonJsonStdout: [] };
  child.stdout.on('data', (data) => {
    state.stdout += data.toString();
    for (const line of data.toString().split('\n').filter(Boolean)) {
      try {
        state.jsonLines.push(JSON.parse(line));
      } catch {
        state.nonJsonStdout.push(line);
      }
    }
  });
  child.stderr.on('data', (data) => {
    state.stderr += data.toString();
  });
  return state;
}

function readJsonl(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function readAudit() {
  return readJsonl(AUDIT_FILE);
}

function readWorkerReceipts() {
  return readJsonl(WORKER_RECEIPT_FILE);
}

async function waitFor(predicate, timeoutMs = 1500) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const value = predicate();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return null;
}

async function waitForJsonLine(state, predicate) {
  const found = await waitFor(() => state.jsonLines.find(predicate));
  if (!found) throw new Error('timed out waiting for JSON-RPC response');
  return found;
}

function sendRpc(child, msg) {
  child.stdin.write(`${JSON.stringify(msg)}\n`);
}

async function stopChild(child) {
  if (!child || child.killed) return;
  await new Promise((resolve) => {
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch {}
      resolve();
    }, 1000);
    child.once('exit', () => {
      clearTimeout(timer);
      resolve();
    });
    try { child.kill('SIGTERM'); } catch { resolve(); }
  });
}

async function withGate(fn) {
  const child = spawnGate();
  const state = collectProcess(child);
  child.stdin.on('error', () => {});
  try {
    return await fn({ child, state });
  } finally {
    await stopChild(child);
  }
}

async function runTests() {
  copyGateProject();
  writeAuditSigningKey();
  writePolicy();
  const upstream = await startFakeUpstream();
  writeRoutingConfig(upstream.port);

  section('routed MCP client proof path');
  await withGate(async ({ child, state }) => {
    sendRpc(child, {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'synthetic-routed-proof-client', version: '0.0.1' } },
    });
    const initResp = await waitForJsonLine(state, (line) => line.id === 1);
    assert('client initialize receives routed response', !!initResp.result);
    assert('initialize reaches fake upstream', upstream.state.calls.some((call) => call.method === 'initialize'));

    sendRpc(child, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
    const listResp = await waitForJsonLine(state, (line) => line.id === 2);
    const toolNames = listResp.result?.tools?.map((tool) => tool.name) || [];
    assert('tools/list reaches fake upstream through ZLAR route', upstream.state.calls.some((call) => call.method === 'tools/list'));
    assert('tools/list exposes fake proof tools', toolNames.includes('proof.allow') && toolNames.includes('proof.deny'));

    sendRpc(child, {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'proof.allow', arguments: { marker: 'allow' } },
    });
    const allowResp = await waitForJsonLine(state, (line) => line.id === 3);
    assert('allow call returns fake upstream result', /proof\.allow/.test(allowResp.result?.content?.[0]?.text || ''));
    assert('allow call reaches fake upstream', upstream.state.markerExecutions.includes('proof.allow'));
    const allowAudit = await waitFor(() => readAudit().find((event) => event.action === 'proof.allow' && event.outcome === 'allow'));
    assert('allow call emits mcp-gate audit row', !!allowAudit);
    assertEqual('allow audit transport', 'stdio', allowAudit?.transport);
    const allowReceipt = await waitFor(() => readWorkerReceipts().find((receipt) => receipt.event?.id === allowAudit?.id));
    assert('allow call emits Worker Receipt evidence', !!allowReceipt);

    const beforeDeny = upstream.state.markerExecutions.length;
    sendRpc(child, {
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: { name: 'proof.deny', arguments: { marker: 'deny' } },
    });
    const denyResp = await waitForJsonLine(state, (line) => line.id === 4);
    assert('deny call returns JSON-RPC error', !!denyResp.error);
    assert('deny call is blocked before fake upstream', upstream.state.markerExecutions.length === beforeDeny);
    const denyAudit = await waitFor(() => readAudit().find((event) => event.action === 'proof.deny' && event.outcome === 'deny'));
    assert('deny call emits mcp-gate audit row', !!denyAudit);
    assertEqual('deny audit transport', 'stdio', denyAudit?.transport);
    const denyReceipt = await waitFor(() => readWorkerReceipts().find((receipt) => receipt.event?.id === denyAudit?.id));
    assert('deny call emits Worker Receipt evidence', !!denyReceipt);

    const report = buildRoutedMcpClientProofReport({
      clientName: 'synthetic-routed-proof-client',
      clientInvocation: 'local JSON-RPC stdio client with isolated scratch config',
      route: {
        transport: 'stdio',
        description: 'synthetic client command launches the ZLAR MCP gate with --stdio and a scratch upstream config',
      },
      calls: [
        {
          toolName: 'proof.allow',
          expectedDecision: 'allow',
          clientObserved: { result: 'fake upstream executed proof.allow' },
          upstreamObserved: true,
          auditEvent: allowAudit,
          workerReceipt: allowReceipt,
        },
        {
          toolName: 'proof.deny',
          expectedDecision: 'deny',
          clientObserved: { error: 'blocked by ZLAR before fake upstream execution' },
          upstreamObserved: false,
          auditEvent: denyAudit,
          workerReceipt: denyReceipt,
        },
      ],
    });

    let reportError = '';
    try {
      assertRoutedMcpClientProofReport(report);
    } catch (error) {
      reportError = error.message;
    }
    assert('routed MCP proof report validates', reportError === '', reportError);
    assert('proof report separates governed calls from ungoverned surfaces',
      report.governed_routed_mcp_calls.length === 2 &&
      report.intentionally_ungoverned_surfaces.length >= 4);
    const reportText = JSON.stringify(report);
    assert('proof report omits raw MCP args',
      !reportText.includes('"marker":"allow"') && !reportText.includes('"marker":"deny"'));
    assert('proof report records no live external services',
      report.route.external_services === false && report.route.live_telegram === false);

    const mismatchedReceiptReport = JSON.parse(JSON.stringify(report));
    mismatchedReceiptReport.governed_routed_mcp_calls[0].worker_receipt.matches_audit_event = false;
    assertThrows('proof report rejects mismatched Worker Receipt evidence', () => {
      assertRoutedMcpClientProofReport(mismatchedReceiptReport);
    }, 'Worker Receipt must match');
  });

  section('routed MCP proof report privacy guards');
  const unsafeText = UNSAFE_CREDENTIAL_FIXTURES.join(' ');
  const unsafeInputReport = buildRoutedMcpClientProofReport({
    clientName: `synthetic client ${unsafeText}`,
    clientInvocation: `synthetic invocation ${unsafeText}`,
    route: {
      transport: 'stdio',
      description: `synthetic route ${unsafeText}`,
    },
    calls: [
      {
        toolName: `proof.allow ${unsafeText}`,
        expectedDecision: 'allow',
        clientObserved: {
          result: `synthetic result ${unsafeText}`,
          nested: { diagnostic: unsafeText },
        },
        upstreamObserved: true,
        auditEvent: {
          id: 'privacy-proof-allow',
          source: 'mcp-gate',
          action: `proof.allow ${unsafeText}`,
          outcome: 'allow',
          rule: `RMCP_ALLOW ${unsafeText}`,
          authorizer: `policy ${unsafeText}`,
          agent_id: `agent ${unsafeText}`,
          session_id: `session ${unsafeText}`,
          transport: 'stdio',
          detail: { args_hash: `hash ${unsafeText}` },
        },
        workerReceipt: {
          event: { id: 'privacy-proof-allow' },
          decision: { label: `Allowed by policy ${unsafeText}` },
          action: { summary: `MCP tool: proof.allow ${unsafeText}` },
        },
      },
      {
        toolName: 'proof.deny',
        expectedDecision: 'deny',
        clientObserved: { error: 'synthetic deny' },
        upstreamObserved: false,
        auditEvent: {
          id: 'privacy-proof-deny',
          source: 'mcp-gate',
          action: 'proof.deny',
          outcome: 'deny',
          rule: 'RMCP_DENY',
          authorizer: 'policy',
          agent_id: 'agent',
          session_id: 'session',
          transport: 'stdio',
        },
      },
    ],
  });
  const unsafeInputText = JSON.stringify(unsafeInputReport);
  assert('generated proof report redacts credential-like inputs',
    UNSAFE_CREDENTIAL_FIXTURES.every((value) => !unsafeInputText.includes(value)),
    unsafeInputText);
  assert('generated proof report includes redaction marker',
    unsafeInputText.includes('[REDACTED_CREDENTIAL]'));
  assert('generated proof report with redactions passes unsafe text guard', (() => {
    try {
      assertNoUnsafeReportText(unsafeInputReport);
      return true;
    } catch {
      return false;
    }
  })());

  for (const value of UNSAFE_CREDENTIAL_FIXTURES) {
    assertThrows(`unsafe report text rejected for ${value.split(/[=: ]/)[0]}`, () => {
      assertNoUnsafeReportText({ leak: value });
    }, 'proof report contains');
  }
}

try {
  await runTests();
} catch (error) {
  FAIL++;
  console.log(`\nFATAL: ${error.message}`);
  if (error.stack) console.log(error.stack);
} finally {
  for (const child of children) {
    try { child.kill('SIGKILL'); } catch {}
  }
  for (const server of servers) {
    try { server.close(); } catch {}
  }
  try {
    rmSync(SCRATCH, { recursive: true, force: true });
  } catch {}
}

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
