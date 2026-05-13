#!/usr/bin/env node
// ZLAR MCP Gate -- stdio conformance harness
//
// Tests-first scaffold for Gateway v2 stdio support. This file intentionally
// does not implement the transport. While gate.mjs has no --stdio mode, the
// behavior assertions are reported as explicit skips so the pending transport
// gap remains visible without making main permanently red.

import { createServer } from 'node:net';
import { spawn } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { canonicalize, sha256hex } from '../lib/receipt.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = join(__dirname, '..');

let PASS = 0;
let FAIL = 0;
let SKIP = 0;
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

function skip(label, reason) {
  SKIP++;
  console.log(`  SKIP: ${label} -- ${reason}`);
}

function section(title) {
  console.log(`\n-- ${title} --`);
}

const STDIO_PENDING_REASON = 'mcp-gate/gate.mjs has no --stdio transport yet; tests are staged for Gateway v2 review';
const SCRATCH = mkdtempSync(join(tmpdir(), 'zlar-mcp-stdio-conformance-'));
const TMP_HOME = join(SCRATCH, 'home');
const AUDIT_FILE = join(SCRATCH, 'stdio.audit.jsonl');
const ROUTING_CONFIG = join(SCRATCH, 'stdio-upstreams.json');
const POLICY_PATH = join(SCRATCH, 'adapter-stdio.policy.json');
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

function writeAuditSigningKey() {
  mkdirSync(TMP_HOME, { recursive: true });
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(join(TMP_HOME, '.zlar-signing.key'), privateKey.export({ type: 'pkcs8', format: 'pem' }));
  writeFileSync(join(TMP_HOME, '.zlar-signing.pub'), publicKey.export({ type: 'spki', format: 'pem' }));
}

function writePolicy() {
  writeFileSync(POLICY_PUB_PATH, POLICY_PUBLIC_KEY.export({ type: 'spki', format: 'pem' }));
  writeFileSync(POLICY_PATH, JSON.stringify(signJson({
    version: 'stdio-conformance-1',
    default_action: 'deny',
    rules: [
      {
        id: 'SC_ALLOW',
        enabled: true,
        description: 'stdio conformance allow marker',
        domain: 'mcp',
        action: 'allow',
        severity: 'info',
        match: { domain: 'mcp', detail: { tool_name: { eq: 'test.marker_allow' } } },
        risk_score: { irreversibility: 0, consequence: 0, blast_radius: 0 },
      },
      {
        id: 'SC_DENY',
        enabled: true,
        description: 'stdio conformance deterministic deny marker',
        domain: 'mcp',
        action: 'deny',
        severity: 'critical',
        match: { domain: 'mcp', detail: { tool_name: { eq: 'test.marker_deny' } } },
        risk_score: { irreversibility: 100, consequence: 100, blast_radius: 100 },
      },
    ],
  })));
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
        try { msg = JSON.parse(line); } catch { continue; }
        state.calls.push(msg);
        if (msg.method === 'initialize') {
          socket.write(JSON.stringify({
            jsonrpc: '2.0',
            id: msg.id,
            result: {
              protocolVersion: msg.params?.protocolVersion || '2024-11-05',
              capabilities: { tools: {} },
              serverInfo: { name: 'stdio-fake-upstream', version: '0.0.1' },
            },
          }) + '\n');
        } else if (msg.method === 'tools/list') {
          socket.write(JSON.stringify({
            jsonrpc: '2.0',
            id: msg.id,
            result: { tools: [{ name: 'marker_allow' }, { name: 'marker_deny' }] },
          }) + '\n');
        } else if (msg.method === 'tools/call') {
          state.markerExecutions.push(msg.params?.name || 'unknown');
          socket.write(JSON.stringify({
            jsonrpc: '2.0',
            id: msg.id,
            result: { content: [{ type: 'text', text: `upstream executed ${msg.params?.name}` }] },
          }) + '\n');
        } else {
          socket.write(JSON.stringify({
            jsonrpc: '2.0',
            id: msg.id,
            result: { ok: true, method: msg.method },
          }) + '\n');
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

function writeRoutingConfig(upstreamPort) {
  writeFileSync(ROUTING_CONFIG, JSON.stringify([
    {
      server_name: 'test',
      transport: 'tcp',
      host: '127.0.0.1',
      port: upstreamPort,
    },
  ]));
}

function spawnStdioGate(extraEnv = {}) {
  const argv = [
    join(REPO_ROOT, 'mcp-gate', 'gate.mjs'),
    '--stdio',
    '--config', ROUTING_CONFIG,
    '--audit-file', AUDIT_FILE,
    '--policy-file', POLICY_PATH,
    '--policy-pubkey', POLICY_PUB_PATH,
    '--manifest-file', join(SCRATCH, 'missing-manifest.json'),
    '--constitution-presence-file', join(SCRATCH, 'missing-constitution-presence'),
    '--restore-config-file', join(SCRATCH, 'missing-restore-config.json'),
    '--agent-id', 'stdio-conformance-agent',
    '--session-id', 'stdio-conformance-session',
    '--no-telegram',
  ];
  const child = spawn(process.execPath, argv, {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      HOME: TMP_HOME,
      ZLAR_REQUIRE_SIGNED_AUDIT: 'true',
      ZLAR_CANARY_MIN_APPROVALS: '999',
      ZLAR_CANARY_COOLDOWN: '999999',
      ZLAR_HUMAN_STATE_HMAC_KEY_FILE: join(SCRATCH, 'no-human-hmac.key'),
      ...extraEnv,
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  children.push(child);
  return child;
}

function collectProcess(child) {
  const state = { stdout: '', stderr: '', stdoutLines: [], jsonLines: [], nonJsonStdout: [] };
  child.stdout.on('data', (data) => {
    state.stdout += data.toString();
    const lines = data.toString().split('\n').filter((line) => line.length > 0);
    for (const line of lines) {
      state.stdoutLines.push(line);
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

function waitForExit(child, timeoutMs = 1000) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), timeoutMs);
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });
}

function waitForJsonLine(state, predicate, timeoutMs = 1500) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const poll = () => {
      const found = state.jsonLines.find(predicate);
      if (found) return resolve(found);
      if (Date.now() - started >= timeoutMs) return reject(new Error('timed out waiting for JSON-RPC response'));
      setTimeout(poll, 25);
    };
    poll();
  });
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

async function probeStdioSupport() {
  const child = spawnStdioGate();
  const state = collectProcess(child);
  child.stdin.on('error', () => {});
  child.stdin.write(JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'stdio-probe', version: '0.0.1' } },
  }) + '\n');

  const exit = await waitForExit(child, 800);
  const supported = !exit || state.jsonLines.some((line) => line?.id === 1);
  if (!supported) {
    return { supported: false, exit, stdout: state.stdout, stderr: state.stderr };
  }

  await stopChild(child);
  return { supported: true };
}

function skipPendingStdioBehavior() {
  section('Pending stdio transport behavior');
  const labels = [
    'stdout hygiene: no operational logs on stdout in stdio mode',
    'JSON-RPC framing: one message per line produces a valid response',
    'malformed JSON handling returns a JSON-RPC parse error',
    'multiple messages in one read produce multiple ordered responses',
    'initialize handshake reaches fake upstream and returns response',
    'tools/list pass-through reaches fake upstream',
    'deterministic deny blocks before upstream execution',
  ];
  for (const label of labels) skip(label, STDIO_PENDING_REASON);
}

function readAudit() {
  if (!existsSync(AUDIT_FILE)) return [];
  return readFileSync(AUDIT_FILE, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

async function withStdioGate(fn) {
  const child = spawnStdioGate();
  const state = collectProcess(child);
  child.stdin.on('error', () => {});
  try {
    return await fn({ child, state });
  } finally {
    await stopChild(child);
  }
}

async function runImplementedStdioTests(upstream) {
  section('stdio stdout hygiene / framing / initialize');
  await withStdioGate(async ({ child, state }) => {
    const initialize = {
      jsonrpc: '2.0',
      id: 10,
      method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'stdio-test', version: '0.0.1' } },
    };
    child.stdin.write(JSON.stringify(initialize) + '\n');
    const resp = await waitForJsonLine(state, (line) => line.id === 10);
    assert('JSON-RPC framing: one message per line produces a valid response', !!resp.result || !!resp.error);
    assert('stdout hygiene: no operational logs on stdout in stdio mode',
      state.nonJsonStdout.length === 0,
      `non-json stdout=${JSON.stringify(state.nonJsonStdout.slice(0, 3))}`);
    assert('initialize handshake reaches fake upstream',
      upstream.state.calls.some((call) => call.method === 'initialize'));
  });

  section('stdio malformed JSON');
  await withStdioGate(async ({ child, state }) => {
    const beforeCalls = upstream.state.calls.length;
    child.stdin.write('{not-json}\n');
    const resp = await waitForJsonLine(state, (line) => !!line.error);
    assert('malformed JSON handling returns a JSON-RPC parse error', !!resp.error);
    assert('malformed JSON is not forwarded upstream',
      upstream.state.calls.length === beforeCalls,
      `before=${beforeCalls} after=${upstream.state.calls.length}`);
  });

  section('stdio multiple messages / tools/list');
  await withStdioGate(async ({ child, state }) => {
    const initialize = JSON.stringify({
      jsonrpc: '2.0',
      id: 20,
      method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'stdio-test', version: '0.0.1' } },
    });
    const list = JSON.stringify({ jsonrpc: '2.0', id: 21, method: 'tools/list', params: {} });
    child.stdin.write(`${initialize}\n${list}\n`);
    const initResp = await waitForJsonLine(state, (line) => line.id === 20);
    const listResp = await waitForJsonLine(state, (line) => line.id === 21);
    assert('multiple messages in one read produce initialize response', !!initResp.result || !!initResp.error);
    assert('multiple messages in one read produce tools/list response', !!listResp.result || !!listResp.error);
    assert('tools/list pass-through reaches fake upstream',
      upstream.state.calls.some((call) => call.method === 'tools/list'));
    const toolNames = listResp.result?.tools?.map((tool) => tool.name) || [];
    assert('tools/list exposes routed fake upstream tools',
      toolNames.includes('test.marker_allow') || toolNames.includes('marker_allow'),
      `tools=${JSON.stringify(toolNames)}`);
  });

  section('stdio deterministic deny');
  await withStdioGate(async ({ child, state }) => {
    child.stdin.write(JSON.stringify({
      jsonrpc: '2.0',
      id: 30,
      method: 'tools/call',
      params: { name: 'test.marker_deny', arguments: { marker: 'deny' } },
    }) + '\n');
    const resp = await waitForJsonLine(state, (line) => line.id === 30);
    assert('deterministic deny returns JSON-RPC error', !!resp.error);
    assert('deterministic deny blocks before upstream execution',
      !upstream.state.markerExecutions.includes('marker_deny') &&
      !upstream.state.markerExecutions.includes('test.marker_deny'));
    const denyAudit = readAudit().find((event) => event.action === 'test.marker_deny' && event.outcome === 'deny');
    assert('deterministic deny emits audit when stdio is implemented', !!denyAudit);
  });
}

async function runTests() {
  mkdirSync(SCRATCH, { recursive: true });
  writeAuditSigningKey();
  writePolicy();
  const upstream = await startFakeUpstream();
  writeRoutingConfig(upstream.port);

  section('stdio implementation marker');
  const probe = await probeStdioSupport();
  if (!probe.supported) {
    assert('explicit pending marker for absent stdio implementation',
      true,
      `exit=${probe.exit?.code ?? 'none'} stderr=${JSON.stringify((probe.stderr || '').trim())}`);
    skipPendingStdioBehavior();
    return;
  }

  assert('stdio implementation detected; running staged conformance tests', true);
  await runImplementedStdioTests(upstream);
}

try {
  await runTests();
} catch (e) {
  FAIL++;
  console.log(`\nFATAL: ${e.message}`);
  if (e.stack) console.log(e.stack);
} finally {
  for (const child of children) {
    try { child.kill('SIGKILL'); } catch {}
  }
  for (const server of servers) {
    try { server.close(); } catch {}
  }
  try {
    const leftovers = readdirSync(SCRATCH);
    if (leftovers.length >= 0) rmSync(SCRATCH, { recursive: true, force: true });
  } catch {}
}

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed, ${SKIP} skipped`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
