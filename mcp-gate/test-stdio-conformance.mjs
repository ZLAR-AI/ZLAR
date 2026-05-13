#!/usr/bin/env node
// ZLAR MCP Gate -- stdio conformance harness
//
// Tests-first scaffold for Gateway v2 stdio support. This file intentionally
// does not implement the transport. While gate.mjs has no --stdio mode, the
// behavior assertions are reported as explicit skips so the pending transport
// gap remains visible without making main permanently red.

import { createServer } from 'node:net';
import { createServer as createHttpServer } from 'node:http';
import { spawn } from 'node:child_process';
import {
  cpSync,
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
import { createHmac, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
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

function assertEqual(label, expected, actual) {
  assert(label, expected === actual, `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
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
const TMP_PROJECT = join(SCRATCH, 'project');
const TMP_HOME = join(SCRATCH, 'home');
const AUDIT_FILE = join(SCRATCH, 'stdio.audit.jsonl');
const ROUTING_CONFIG = join(SCRATCH, 'stdio-upstreams.json');
const POLICY_PATH = join(SCRATCH, 'adapter-stdio.policy.json');
const POLICY_PUB_PATH = join(SCRATCH, 'policy-signing.pub');
const GATE_TIMEOUT_S = 2;

const children = [];
const servers = [];

const { publicKey: POLICY_PUBLIC_KEY, privateKey: POLICY_PRIVATE_KEY } = generateKeyPairSync('ed25519');

function copyGateProject() {
  mkdirSync(TMP_PROJECT, { recursive: true });
  cpSync(join(REPO_ROOT, 'mcp-gate'), join(TMP_PROJECT, 'mcp-gate'), { recursive: true });
  cpSync(join(REPO_ROOT, 'lib'), join(TMP_PROJECT, 'lib'), { recursive: true });
  mkdirSync(join(TMP_PROJECT, 'packages'), { recursive: true });
  cpSync(join(REPO_ROOT, 'packages', 'zlar-restore'), join(TMP_PROJECT, 'packages', 'zlar-restore'), { recursive: true });

  mkdirSync(join(TMP_PROJECT, 'etc', 'policies'), { recursive: true });
  mkdirSync(join(TMP_PROJECT, 'etc', 'keys'), { recursive: true });
  mkdirSync(join(TMP_PROJECT, 'var', 'log'), { recursive: true });

  writeGateConfig('stdio-conformance-human');
}

function writeGateConfig(humanId) {
  mkdirSync(join(TMP_PROJECT, 'etc'), { recursive: true });
  writeFileSync(join(TMP_PROJECT, 'etc', 'gate.json'), JSON.stringify({
    telegram: { chat_id: humanId, timeout_s: GATE_TIMEOUT_S },
    canary: {
      enabled: true,
      min_approvals_before_trigger: 999,
      probability_percent: 0,
      cooldown_s: 999999,
    },
  }));
}

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
      {
        id: 'SC_ASK',
        enabled: true,
        description: 'stdio conformance ask marker',
        domain: 'mcp',
        action: 'ask',
        severity: 'info',
        match: { domain: 'mcp', detail: { tool_name: { eq: 'test.marker_ask' } } },
        risk_score: { irreversibility: 20, consequence: 20, blast_radius: 20 },
      },
      {
        id: 'SC_TIMEOUT',
        enabled: true,
        description: 'stdio conformance timeout marker',
        domain: 'mcp',
        action: 'ask',
        severity: 'info',
        match: { domain: 'mcp', detail: { tool_name: { eq: 'test.marker_timeout' } } },
        risk_score: { irreversibility: 20, consequence: 20, blast_radius: 20 },
      },
    ],
  })));
}

function signManifest(manifestObj) {
  const canonical = JSON.parse(JSON.stringify(manifestObj));
  canonical.signature = { algorithm: '', value: '', key_id: '' };
  const hashHex = sha256hex(canonicalize(canonical));
  const sig = cryptoSign(null, Buffer.from(hashHex, 'utf8'), POLICY_PRIVATE_KEY);
  return {
    ...manifestObj,
    signature: { algorithm: 'Ed25519', value: sig.toString('base64'), key_id: 'stdio-conformance' },
  };
}

function writeManifest(name, authority) {
  const manifestPath = join(SCRATCH, `${name}.manifest.json`);
  const manifest = signManifest({
    manifest_version: 'stdio-conformance-1',
    identity: {
      agent_id: 'stdio-conformance',
      principal: 'synthetic-mcp-stdio-client',
      issued_at: '2026-05-13T00:00:00Z',
    },
    authority,
    escalation: { channel: 'test', timeout_seconds: GATE_TIMEOUT_S, timeout_action: 'deny' },
    sequence: 1,
    expires: '2099-01-01T00:00:00Z',
    signature: { algorithm: 'Ed25519', value: '', key_id: '' },
  });
  writeFileSync(manifestPath, JSON.stringify(manifest));
  return manifestPath;
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
            result: { tools: [{ name: 'marker_allow' }, { name: 'marker_deny' }, { name: 'marker_ask' }, { name: 'marker_timeout' }] },
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

async function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

async function startMockTelegram({ inboxDir, hmacSecretFile, hmacSecret }) {
  let mode = 'none';
  let messageId = 1000;
  const requests = [];
  mkdirSync(inboxDir, { recursive: true });
  writeFileSync(hmacSecretFile, hmacSecret);

  const server = createHttpServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      let body = {};
      try { body = JSON.parse(raw || '{}'); } catch {}
      requests.push(body);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, result: { message_id: ++messageId } }));

      const buttons = body?.reply_markup?.inline_keyboard?.[0] || [];
      const approve = buttons.find((button) => String(button.callback_data || '').startsWith('mcp:approve:'));
      const deny = buttons.find((button) => String(button.callback_data || '').startsWith('mcp:deny:'));
      const chosen = mode === 'approve' ? approve : mode === 'deny' ? deny : null;
      if (!chosen) return;

      const data = chosen.callback_data;
      const from = String(body.chat_id || 'stdio-conformance-human');
      const cbId = `cb-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      const hmac = createHmac('sha256', hmacSecret).update(`${data}|${from}|${cbId}`).digest('base64');
      setTimeout(() => {
        writeFileSync(join(inboxDir, `${cbId}.json`), JSON.stringify({
          data,
          from_id: from,
          callback_query_id: cbId,
          hmac,
        }));
      }, 650);
    });
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  servers.push(server);
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    requests,
    setMode(next) { mode = next; },
  };
}

function writeFastHumanState(dir, humanId) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${humanId}.json`), JSON.stringify({
    human_id: humanId,
    date: new Date().toISOString().slice(0, 10),
    decisions_today: 0,
    response_times: [],
    pending: [],
    last_ask_epoch: 0,
    last_ask_epoch_ms: 0,
    canary_tier: 0,
    canary_trip_count: 0,
    timing_observations: [],
    operator_profile_level: 0,
    trust_lane: 'fast',
    trust_lane_grant: { source: 'test', granted_at: Math.floor(Date.now() / 1000), reason: 'stdio conformance' },
    clean_run_count: 0,
    clean_run_started_epoch: 0,
    canary_approvals_since_last: 0,
    canary_last_epoch: 0,
    canary_pending_id: '',
    canary_pending_session_id: '',
    canary_pending_started_epoch: 0,
    canary_pending_msg_id: '',
    canary_pending_delivered_epoch: 0,
    canary_pending_artifact_hash: '',
  }));
}

function readHumanState(dir, humanId) {
  return JSON.parse(readFileSync(join(dir, `${humanId}.json`), 'utf8'));
}

function assertNoPendingAsk(label, dir, humanId) {
  const state = readHumanState(dir, humanId);
  assert(`${label} clears H13 pending ask state`,
    Array.isArray(state.pending) && state.pending.length === 0,
    `pending=${JSON.stringify(state.pending)}`);
}

function writeRoutingConfig(upstreamPort, routingConfig = ROUTING_CONFIG) {
  writeFileSync(routingConfig, JSON.stringify([
    {
      server_name: 'test',
      transport: 'tcp',
      host: '127.0.0.1',
      port: upstreamPort,
    },
  ]));
}

function spawnStdioGate({
  auditFile = AUDIT_FILE,
  routingConfig = ROUTING_CONFIG,
  manifestFile = join(SCRATCH, 'missing-manifest.json'),
  agentId = 'stdio-conformance-agent',
  sessionId = 'stdio-conformance-session',
  noTelegram = true,
  humanId = null,
  telegram = null,
  inboxDir = null,
  hmacSecretFile = null,
  humanStateDir = null,
  extraEnv = {},
} = {}) {
  const argv = [
    join(TMP_PROJECT, 'mcp-gate', 'gate.mjs'),
    '--stdio',
    '--config', routingConfig,
    '--audit-file', auditFile,
    '--policy-file', POLICY_PATH,
    '--policy-pubkey', POLICY_PUB_PATH,
    '--manifest-file', manifestFile,
    '--constitution-presence-file', join(SCRATCH, 'missing-constitution-presence'),
    '--restore-config-file', join(SCRATCH, 'missing-restore-config.json'),
    '--agent-id', agentId,
    '--session-id', sessionId,
  ];
  if (noTelegram) {
    argv.push('--no-telegram');
  } else if (humanId) {
    writeGateConfig(humanId);
  }
  const child = spawn(process.execPath, argv, {
    cwd: TMP_PROJECT,
    env: {
      ...process.env,
      HOME: TMP_HOME,
      ZLAR_REQUIRE_SIGNED_AUDIT: 'true',
      ZLAR_CANARY_MIN_APPROVALS: '999',
      ZLAR_CANARY_COOLDOWN: '999999',
      ZLAR_HUMAN_STATE_HMAC_KEY_FILE: join(SCRATCH, 'no-human-hmac.key'),
      ...(telegram ? {
        ZLAR_TELEGRAM_TOKEN: 'fake-token',
        ZLAR_TELEGRAM_API_BASE: telegram.url,
      } : {}),
      ...(inboxDir ? { ZLAR_MCP_INBOX_DIR: inboxDir } : {}),
      ...(hmacSecretFile ? { ZLAR_INBOX_HMAC_SECRET_FILE: hmacSecretFile } : {}),
      ...(humanStateDir ? { ZLAR_HUMAN_STATE_DIR: humanStateDir } : {}),
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
    'tools/call allow reaches fake upstream',
    'deterministic deny blocks before upstream execution',
    'ask-approved reaches upstream after fake human approval',
    'ask-denied blocks before upstream',
    'timeout blocks before upstream and audits gate:timeout',
    'upstream unavailable fails closed',
    'unmatched/default deny blocks before upstream',
    'manifest deny blocks before upstream',
    'stdio audit core fields match TCP adapter expectations',
  ];
  for (const label of labels) skip(label, STDIO_PENDING_REASON);
}

function readAudit(auditFile = AUDIT_FILE) {
  if (!existsSync(auditFile)) return [];
  return readFileSync(auditFile, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function findAudit(auditFile, predicate) {
  return readAudit(auditFile).find(predicate);
}

function assertAuditCore(label, event, {
  agentId = 'stdio-conformance-agent',
  sessionId = 'stdio-conformance-session',
  rule = null,
  authorizer = null,
} = {}) {
  assertEqual(`${label} audit source=mcp-gate`, 'mcp-gate', event?.source);
  assertEqual(`${label} audit agent_id`, agentId, event?.agent_id);
  assertEqual(`${label} audit session_id`, sessionId, event?.session_id);
  if (rule !== null) assertEqual(`${label} audit rule`, rule, event?.rule);
  if (authorizer !== null) assertEqual(`${label} audit authorizer`, authorizer, event?.authorizer);
}

function assertStdioTransportIndicator(label, event) {
  const transport = event?.transport || event?.detail?.transport || event?.detail?.mcp_transport;
  assertEqual(`${label} audit transport indicator`, 'stdio', transport);
}

async function withStdioGate(optsOrFn, maybeFn) {
  const opts = typeof optsOrFn === 'function' ? {} : optsOrFn;
  const fn = typeof optsOrFn === 'function' ? optsOrFn : maybeFn;
  const auditFile = opts?.auditFile || join(SCRATCH, `${opts?.auditName || 'stdio'}.audit.jsonl`);
  const child = spawnStdioGate({ ...opts, auditFile });
  const state = collectProcess(child);
  child.stdin.on('error', () => {});
  try {
    return await fn({ child, state, auditFile });
  } finally {
    await stopChild(child);
  }
}

function sendStdioRpc(child, msg) {
  child.stdin.write(JSON.stringify(msg) + '\n');
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

  section('stdio tools/call allow');
  {
    const agentId = 'stdio-allow-agent';
    const sessionId = 'stdio-allow-session';
    await withStdioGate({ auditName: 'allow', agentId, sessionId }, async ({ child, state, auditFile }) => {
      sendStdioRpc(child, {
        jsonrpc: '2.0',
        id: 30,
        method: 'tools/call',
        params: { name: 'test.marker_allow', arguments: { marker: 'allow' } },
      });
      const resp = await waitForJsonLine(state, (line) => line.id === 30);
      assert('tools/call allow returns upstream result', /test\.marker_allow/.test(resp.result?.content?.[0]?.text || ''));
      assert('tools/call allow reaches fake upstream',
        upstream.state.markerExecutions.includes('test.marker_allow'));
      const allowAudit = findAudit(auditFile, (event) => event.action === 'test.marker_allow' && event.outcome === 'allow');
      assert('tools/call allow emits audit', !!allowAudit);
      assertAuditCore('tools/call allow', allowAudit, { agentId, sessionId, rule: 'SC_ALLOW', authorizer: 'policy' });
      assertStdioTransportIndicator('tools/call allow', allowAudit);
    });
  }

  section('stdio deterministic deny');
  {
    const agentId = 'stdio-deny-agent';
    const sessionId = 'stdio-deny-session';
    await withStdioGate({ auditName: 'deterministic-deny', agentId, sessionId }, async ({ child, state, auditFile }) => {
      const before = upstream.state.markerExecutions.length;
      sendStdioRpc(child, {
        jsonrpc: '2.0',
        id: 31,
        method: 'tools/call',
        params: { name: 'test.marker_deny', arguments: { marker: 'deny' } },
      });
      const resp = await waitForJsonLine(state, (line) => line.id === 31);
      assert('deterministic deny returns JSON-RPC error', !!resp.error);
      assert('deterministic deny blocks before upstream execution',
        upstream.state.markerExecutions.length === before);
      const denyAudit = findAudit(auditFile, (event) => event.action === 'test.marker_deny' && event.outcome === 'deny');
      assert('deterministic deny emits audit when stdio is implemented', !!denyAudit);
      assertAuditCore('deterministic deny', denyAudit, { agentId, sessionId, rule: 'SC_DENY', authorizer: 'policy' });
      assertStdioTransportIndicator('deterministic deny', denyAudit);
    });
  }

  section('stdio policy and manifest boundary denies');
  {
    const agentId = 'stdio-default-deny-agent';
    const sessionId = 'stdio-default-deny-session';
    await withStdioGate({ auditName: 'default-deny', agentId, sessionId }, async ({ child, state, auditFile }) => {
      const before = upstream.state.markerExecutions.length;
      sendStdioRpc(child, {
        jsonrpc: '2.0',
        id: 40,
        method: 'tools/call',
        params: { name: 'test.marker_unmatched', arguments: { marker: 'default-deny' } },
      });
      const resp = await waitForJsonLine(state, (line) => line.id === 40);
      assert('unmatched/default deny returns JSON-RPC error', !!resp.error);
      assert('unmatched/default deny blocks before upstream execution',
        upstream.state.markerExecutions.length === before);
      const defaultAudit = findAudit(auditFile, (event) => event.action === 'test.marker_unmatched' && event.outcome === 'deny');
      assert('unmatched/default deny emits audit', !!defaultAudit);
      assertAuditCore('unmatched/default deny', defaultAudit, { agentId, sessionId, rule: 'default', authorizer: 'policy' });
      assertStdioTransportIndicator('unmatched/default deny', defaultAudit);
    });
  }

  {
    const manifestFile = writeManifest('stdio-deny-mcp-call', {
      deny: ['mcp.call'],
      allow: ['mcp.call'],
      unmatched_action: 'escalate',
    });
    const agentId = 'stdio-manifest-agent';
    const sessionId = 'stdio-manifest-session';
    await withStdioGate({ auditName: 'manifest-deny', agentId, sessionId, manifestFile }, async ({ child, state, auditFile }) => {
      const before = upstream.state.markerExecutions.length;
      sendStdioRpc(child, {
        jsonrpc: '2.0',
        id: 41,
        method: 'tools/call',
        params: { name: 'test.marker_allow', arguments: { marker: 'manifest-deny' } },
      });
      const resp = await waitForJsonLine(state, (line) => line.id === 41);
      assert('manifest deny returns JSON-RPC refusal', !!resp.error);
      assert('manifest deny error names manifest rule', /manifest:deny/.test(resp.error?.message || ''));
      assert('manifest deny blocks before upstream execution',
        upstream.state.markerExecutions.length === before);
      const manifestAudit = findAudit(auditFile, (event) => event.action === 'test.marker_allow' && event.outcome === 'deny');
      assert('manifest deny emits audit', !!manifestAudit);
      assertAuditCore('manifest deny', manifestAudit, { agentId, sessionId, rule: 'manifest:deny', authorizer: 'manifest' });
      assertEqual('manifest deny audit capability', 'mcp.call', manifestAudit?.detail?.cap);
      assertStdioTransportIndicator('manifest deny', manifestAudit);
    });
  }

  section('stdio Telegram ask decisions');
  {
    const upstreamBefore = upstream.state.markerExecutions.length;
    const inboxDir = join(SCRATCH, 'stdio-inbox-approve');
    const hmacSecretFile = join(SCRATCH, 'stdio-inbox-approve-secret');
    const telegram = await startMockTelegram({ inboxDir, hmacSecretFile, hmacSecret: 'stdio-hmac-approve' });
    telegram.setMode('approve');
    const humanId = 'stdio-human-approve';
    const humanStateDir = join(SCRATCH, 'stdio-human-approve');
    writeFastHumanState(humanStateDir, humanId);
    const agentId = 'stdio-ask-agent';
    const sessionId = 'stdio-ask-approved-session';

    await withStdioGate({
      auditName: 'ask-approved',
      agentId,
      sessionId,
      noTelegram: false,
      humanId,
      telegram,
      inboxDir,
      hmacSecretFile,
      humanStateDir,
    }, async ({ child, state, auditFile }) => {
      sendStdioRpc(child, {
        jsonrpc: '2.0',
        id: 50,
        method: 'tools/call',
        params: { name: 'test.marker_ask', arguments: { marker: 'ask-approved' } },
      });
      const resp = await waitForJsonLine(state, (line) => line.id === 50, 9000);
      assert('ask-approved returns upstream result', /test\.marker_ask/.test(resp.result?.content?.[0]?.text || ''));
      assert('ask-approved reaches upstream after fake human approval',
        upstream.state.markerExecutions.length === upstreamBefore + 1 &&
        upstream.state.markerExecutions.includes('test.marker_ask'));
      const askSent = findAudit(auditFile, (event) => event.action === 'ask_sent' && event.outcome === 'pending');
      assert('ask-approved emits ask_sent audit', !!askSent);
      const authorized = findAudit(auditFile, (event) => event.action === 'test.marker_ask' && event.outcome === 'authorized');
      assert('ask-approved emits authorized audit', !!authorized);
      assertAuditCore('ask-approved', authorized, { agentId, sessionId, rule: 'SC_ASK', authorizer: `human:${humanId}` });
      assertStdioTransportIndicator('ask-approved', authorized);
      assertNoPendingAsk('ask-approved', humanStateDir, humanId);
    });
  }

  {
    const inboxDir = join(SCRATCH, 'stdio-inbox-deny');
    const hmacSecretFile = join(SCRATCH, 'stdio-inbox-deny-secret');
    const telegram = await startMockTelegram({ inboxDir, hmacSecretFile, hmacSecret: 'stdio-hmac-deny' });
    telegram.setMode('deny');
    const humanId = 'stdio-human-deny';
    const humanStateDir = join(SCRATCH, 'stdio-human-deny');
    writeFastHumanState(humanStateDir, humanId);
    const agentId = 'stdio-ask-agent';
    const sessionId = 'stdio-ask-denied-session';

    await withStdioGate({
      auditName: 'ask-denied',
      agentId,
      sessionId,
      noTelegram: false,
      humanId,
      telegram,
      inboxDir,
      hmacSecretFile,
      humanStateDir,
    }, async ({ child, state, auditFile }) => {
      const before = upstream.state.markerExecutions.length;
      sendStdioRpc(child, {
        jsonrpc: '2.0',
        id: 51,
        method: 'tools/call',
        params: { name: 'test.marker_ask', arguments: { marker: 'ask-denied' } },
      });
      const resp = await waitForJsonLine(state, (line) => line.id === 51, 9000);
      assert('ask-denied returns JSON-RPC error', !!resp.error);
      assert('ask-denied blocks before upstream', upstream.state.markerExecutions.length === before);
      const denied = findAudit(auditFile, (event) => event.action === 'test.marker_ask' && event.outcome === 'denied');
      assert('ask-denied emits denied audit', !!denied);
      assertAuditCore('ask-denied', denied, { agentId, sessionId, rule: 'SC_ASK', authorizer: `human:${humanId}` });
      assertStdioTransportIndicator('ask-denied', denied);
      assertNoPendingAsk('ask-denied', humanStateDir, humanId);
    });
  }

  section('stdio timeout and upstream failure');
  {
    const inboxDir = join(SCRATCH, 'stdio-inbox-timeout');
    const hmacSecretFile = join(SCRATCH, 'stdio-inbox-timeout-secret');
    const telegram = await startMockTelegram({ inboxDir, hmacSecretFile, hmacSecret: 'stdio-hmac-timeout' });
    telegram.setMode('none');
    const humanId = 'stdio-human-timeout';
    const humanStateDir = join(SCRATCH, 'stdio-human-timeout');
    writeFastHumanState(humanStateDir, humanId);
    const agentId = 'stdio-timeout-agent';
    const sessionId = 'stdio-timeout-session';

    await withStdioGate({
      auditName: 'timeout',
      agentId,
      sessionId,
      noTelegram: false,
      humanId,
      telegram,
      inboxDir,
      hmacSecretFile,
      humanStateDir,
    }, async ({ child, state, auditFile }) => {
      const before = upstream.state.markerExecutions.length;
      sendStdioRpc(child, {
        jsonrpc: '2.0',
        id: 60,
        method: 'tools/call',
        params: { name: 'test.marker_timeout', arguments: { marker: 'timeout' } },
      });
      const resp = await waitForJsonLine(state, (line) => line.id === 60, (GATE_TIMEOUT_S + 5) * 1000);
      assert('timeout returns JSON-RPC error', !!resp.error);
      assert('timeout error mentions human wait', /waiting for human/.test(resp.error?.message || ''));
      assert('timeout blocks before upstream', upstream.state.markerExecutions.length === before);
      const timeoutAudit = findAudit(auditFile, (event) => event.action === 'test.marker_timeout' && event.authorizer === 'gate:timeout');
      assert('timeout emits gate:timeout audit', !!timeoutAudit);
      assertEqual('timeout audit outcome=denied', 'denied', timeoutAudit?.outcome);
      assertAuditCore('timeout', timeoutAudit, { agentId, sessionId, rule: 'SC_TIMEOUT', authorizer: 'gate:timeout' });
      assertStdioTransportIndicator('timeout', timeoutAudit);
      assertNoPendingAsk('timeout', humanStateDir, humanId);
    });
  }

  {
    const unavailablePort = await getFreePort();
    writeRoutingConfig(unavailablePort);
    const agentId = 'stdio-upstream-agent';
    const sessionId = 'stdio-upstream-session';

    await withStdioGate({ auditName: 'upstream-unavailable', agentId, sessionId }, async ({ child, state, auditFile }) => {
      sendStdioRpc(child, {
        jsonrpc: '2.0',
        id: 61,
        method: 'tools/call',
        params: { name: 'test.marker_allow', arguments: { marker: 'upstream-unavailable' } },
      });
      const resp = await waitForJsonLine(
        state,
        (line) => !!line.error && /Upstream unavailable/.test(line.error?.message || ''),
        3000,
      );
      assert('upstream unavailable returns JSON-RPC error', !!resp.error);
      assert('upstream unavailable fails closed', /Upstream unavailable/.test(resp.error?.message || ''));
      const upstreamAudit = findAudit(auditFile, (event) => event.action === 'upstream.error' && event.outcome === 'deny');
      assert('upstream unavailable emits upstream.error audit', !!upstreamAudit);
      assertAuditCore('upstream unavailable', upstreamAudit, { agentId, sessionId, rule: 'upstream.error', authorizer: 'gate' });
      assertStdioTransportIndicator('upstream unavailable', upstreamAudit);
    });
  }
}

async function runTests() {
  mkdirSync(SCRATCH, { recursive: true });
  copyGateProject();
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
