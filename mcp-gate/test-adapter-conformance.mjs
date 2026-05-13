#!/usr/bin/env node
// ZLAR MCP Gate -- Adapter Conformance Harness
//
// Synthetic MCP client + fake upstream MCP server. This proves the current
// TCP gateway behavior before any live Codex routing. The harness is
// intentionally local-only: no real MCP tools, no real writes, no live Codex.

import { createServer, createConnection } from 'node:net';
import { createServer as createHttpServer } from 'node:http';
import { execFileSync, spawn } from 'node:child_process';
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

const SCRATCH = mkdtempSync(join(tmpdir(), 'zlar-mcp-adapter-conformance-'));
const TMP_PROJECT = join(SCRATCH, 'project');
const TMP_HOME = join(SCRATCH, 'home');
const GATE_TIMEOUT_S = 2;

const children = [];
const servers = [];

function copyGateProject() {
  mkdirSync(TMP_PROJECT, { recursive: true });
  cpSync(join(REPO_ROOT, 'mcp-gate'), join(TMP_PROJECT, 'mcp-gate'), { recursive: true });
  cpSync(join(REPO_ROOT, 'lib'), join(TMP_PROJECT, 'lib'), { recursive: true });
  mkdirSync(join(TMP_PROJECT, 'packages'), { recursive: true });
  cpSync(join(REPO_ROOT, 'packages', 'zlar-restore'), join(TMP_PROJECT, 'packages', 'zlar-restore'), { recursive: true });

  mkdirSync(join(TMP_PROJECT, 'etc', 'policies'), { recursive: true });
  mkdirSync(join(TMP_PROJECT, 'etc', 'keys'), { recursive: true });
  mkdirSync(join(TMP_PROJECT, 'var', 'log'), { recursive: true });

  writeGateConfig('adapter-human');
}

function writeGateConfig(humanId) {
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

function writeAuditSigningKey() {
  mkdirSync(TMP_HOME, { recursive: true });
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(
    join(TMP_HOME, '.zlar-signing.key'),
    privateKey.export({ type: 'pkcs8', format: 'pem' }),
  );
  writeFileSync(
    join(TMP_HOME, '.zlar-signing.pub'),
    publicKey.export({ type: 'spki', format: 'pem' }),
  );
}

const { publicKey: POLICY_PUBLIC_KEY, privateKey: POLICY_PRIVATE_KEY } = generateKeyPairSync('ed25519');
const POLICY_PUB_PATH = join(TMP_PROJECT, 'etc', 'keys', 'policy-signing.pub');
const POLICY_PATH = join(TMP_PROJECT, 'etc', 'policies', 'adapter-conformance.policy.json');

function signPolicy(policyObj) {
  const withSig = {
    ...policyObj,
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

function writePolicy() {
  writeFileSync(POLICY_PUB_PATH, POLICY_PUBLIC_KEY.export({ type: 'spki', format: 'pem' }));
  const policy = signPolicy({
    version: 'adapter-conformance-1',
    default_action: 'deny',
    rules: [
      {
        id: 'AC_ALLOW',
        enabled: true,
        description: 'Adapter conformance allow marker',
        domain: 'mcp',
        action: 'allow',
        severity: 'info',
        match: { domain: 'mcp', detail: { tool_name: { eq: 'marker_allow' } } },
        risk_score: { irreversibility: 0, consequence: 0, blast_radius: 0 },
      },
      {
        id: 'AC_DENY',
        enabled: true,
        description: 'Adapter conformance deterministic deny marker',
        domain: 'mcp',
        action: 'deny',
        severity: 'critical',
        match: { domain: 'mcp', detail: { tool_name: { eq: 'marker_deny' } } },
        risk_score: { irreversibility: 100, consequence: 100, blast_radius: 100 },
      },
      {
        id: 'AC_ASK',
        enabled: true,
        description: 'Adapter conformance ask marker',
        domain: 'mcp',
        action: 'ask',
        severity: 'info',
        match: { domain: 'mcp', detail: { tool_name: { eq: 'marker_ask' } } },
        risk_score: { irreversibility: 20, consequence: 20, blast_radius: 20 },
      },
      {
        id: 'AC_ASK_DENY',
        enabled: true,
        description: 'Adapter conformance ask deny marker',
        domain: 'mcp',
        action: 'ask',
        severity: 'info',
        match: { domain: 'mcp', detail: { tool_name: { eq: 'marker_ask_deny' } } },
        risk_score: { irreversibility: 20, consequence: 20, blast_radius: 20 },
      },
      {
        id: 'AC_TIMEOUT',
        enabled: true,
        description: 'Adapter conformance timeout marker',
        domain: 'mcp',
        action: 'ask',
        severity: 'info',
        match: { domain: 'mcp', detail: { tool_name: { eq: 'marker_timeout' } } },
        risk_score: { irreversibility: 20, consequence: 20, blast_radius: 20 },
      },
      {
        id: 'AC_LOG',
        enabled: true,
        description: 'Adapter conformance log marker',
        domain: 'mcp',
        action: 'log',
        severity: 'info',
        match: { domain: 'mcp', detail: { tool_name: { eq: 'marker_log' } } },
        risk_score: { irreversibility: 0, consequence: 0, blast_radius: 0 },
      },
      {
        id: 'AC_PC02_PLACEHOLDER',
        enabled: true,
        description: 'Constitution placeholder ask rule that never matches',
        domain: 'test_never_matches',
        action: 'ask',
        severity: 'info',
        match: { domain: 'test_never_matches', detail: { tool_name: { eq: '__never__' } } },
        risk_score: { irreversibility: 0, consequence: 0, blast_radius: 0 },
      },
    ],
  });
  writeFileSync(POLICY_PATH, JSON.stringify(policy));
}

function signManifest(manifestObj) {
  const canonical = JSON.parse(JSON.stringify(manifestObj));
  canonical.signature = { algorithm: '', value: '', key_id: '' };
  const hashHex = sha256hex(canonicalize(canonical));
  const sig = cryptoSign(null, Buffer.from(hashHex, 'utf8'), POLICY_PRIVATE_KEY);
  return {
    ...manifestObj,
    signature: { algorithm: 'Ed25519', value: sig.toString('base64'), key_id: 'adapter-conformance' },
  };
}

function writeManifest(name, authority) {
  const manifestPath = join(SCRATCH, `${name}.manifest.json`);
  const manifest = signManifest({
    manifest_version: 'adapter-conformance-1',
    identity: {
      agent_id: 'adapter-conformance',
      principal: 'synthetic-mcp-client',
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

async function getFreePort() {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const port = s.address().port;
      s.close(() => resolve(port));
    });
  });
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
        if (msg.method === 'tools/call') {
          state.markerExecutions.push(msg.params?.name || 'unknown');
          socket.write(JSON.stringify({
            jsonrpc: '2.0',
            id: msg.id,
            result: { content: [{ type: 'text', text: `upstream executed ${msg.params?.name}` }] },
          }) + '\n');
        } else if (msg.method === 'tools/list') {
          socket.write(JSON.stringify({
            jsonrpc: '2.0',
            id: msg.id,
            result: { tools: [{ name: 'marker_allow' }, { name: 'marker_ask' }, { name: 'marker_ask_deny' }] },
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
  return { server, port: server.address().port, state };
}

async function startMockTelegram({ inboxDir, hmacSecretFile, hmacSecret, failSend = false }) {
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
      if (failSend) {
        res.end(JSON.stringify({ ok: false, description: 'synthetic send failure' }));
        return;
      }
      res.end(JSON.stringify({ ok: true, result: { message_id: ++messageId } }));

      const buttons = body?.reply_markup?.inline_keyboard?.[0] || [];
      const approve = buttons.find((b) => String(b.callback_data || '').startsWith('mcp:approve:'));
      const deny = buttons.find((b) => String(b.callback_data || '').startsWith('mcp:deny:'));
      const chosen = mode === 'approve' ? approve : mode === 'deny' ? deny : null;
      if (!chosen) return;

      const data = chosen.callback_data;
      const from = String(body.chat_id || 'adapter-human');
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

function latestMcpAskText(telegram) {
  const ask = [...telegram.requests].reverse().find((body) => {
    const buttons = body?.reply_markup?.inline_keyboard?.[0] || [];
    return buttons.some((b) => String(b.callback_data || '').startsWith('mcp:approve:'));
  });
  return String(ask?.text || '');
}

function readAudit(auditFile) {
  if (!existsSync(auditFile)) return [];
  return readFileSync(auditFile, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function findAudit(auditFile, predicate) {
  return readAudit(auditFile).find(predicate);
}

function readWorkerReceipts(workerReceiptFile) {
  if (!existsSync(workerReceiptFile)) return [];
  return readFileSync(workerReceiptFile, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function findWorkerReceipt(workerReceiptFile, predicate) {
  return readWorkerReceipts(workerReceiptFile).find(predicate);
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

function whyJson(workerReceiptFile, eventId) {
  return JSON.parse(execFileSync(process.execPath, [
    join(REPO_ROOT, 'bin', 'zlar-why'),
    eventId,
    '--json',
  ], {
    env: { ...process.env, ZLAR_WORKER_RECEIPT_FILE: workerReceiptFile },
    encoding: 'utf8',
  }));
}

async function startGate({
  upstreamPort,
  auditName,
  agentId,
  sessionId,
  manifestFile = join(SCRATCH, 'missing-manifest.json'),
  telegram = null,
  humanId = null,
  inboxDir = null,
  hmacSecretFile = null,
  humanStateDir = null,
  workerReceiptFile = null,
}) {
  const gatePort = await getFreePort();
  const auditFile = join(SCRATCH, `${auditName}.audit.jsonl`);
  const resolvedWorkerReceiptFile = workerReceiptFile || join(SCRATCH, `${auditName}.worker-receipts.jsonl`);
  const argv = [
    join(TMP_PROJECT, 'mcp-gate', 'gate.mjs'),
    '--port', String(gatePort),
    '--upstream', `127.0.0.1:${upstreamPort}`,
    '--audit-file', auditFile,
    '--policy-file', POLICY_PATH,
    '--policy-pubkey', POLICY_PUB_PATH,
    '--manifest-file', manifestFile,
    '--constitution-presence-file', join(SCRATCH, 'missing-constitution-presence'),
    '--restore-config-file', join(SCRATCH, 'missing-restore-config.json'),
    '--agent-id', agentId,
    '--session-id', sessionId,
  ];
  if (humanId) {
    writeGateConfig(humanId);
  } else {
    argv.push('--no-telegram');
  }

  const env = {
    ...process.env,
    HOME: TMP_HOME,
    ZLAR_REQUIRE_SIGNED_AUDIT: 'true',
    ZLAR_CANARY_MIN_APPROVALS: '999',
    ZLAR_CANARY_COOLDOWN: '999999',
    ZLAR_HUMAN_STATE_HMAC_KEY_FILE: join(SCRATCH, 'no-human-hmac.key'),
    ZLAR_WORKER_RECEIPT_FILE: resolvedWorkerReceiptFile,
    ...(telegram ? {
      ZLAR_TELEGRAM_TOKEN: 'fake-token',
      ZLAR_TELEGRAM_API_BASE: telegram.url,
    } : {}),
    ...(inboxDir ? { ZLAR_MCP_INBOX_DIR: inboxDir } : {}),
    ...(hmacSecretFile ? { ZLAR_INBOX_HMAC_SECRET_FILE: hmacSecretFile } : {}),
    ...(humanStateDir ? { ZLAR_HUMAN_STATE_DIR: humanStateDir } : {}),
  };

  const child = spawn(process.execPath, argv, {
    cwd: TMP_PROJECT,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.push(child);

  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (d) => { stdout += d.toString(); });
  child.stderr.on('data', (d) => { stderr += d.toString(); });

  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`gate did not start\nSTDOUT:\n${stdout}\nSTDERR:\n${stderr}`));
    }, 5000);
    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`gate exited during startup (${code})\nSTDOUT:\n${stdout}\nSTDERR:\n${stderr}`));
    });
    child.stdout.on('data', (d) => {
      if (d.toString().includes('listening')) {
        clearTimeout(timer);
        resolve();
      }
    });
  });

  return { child, port: gatePort, auditFile, workerReceiptFile: resolvedWorkerReceiptFile, stdout: () => stdout, stderr: () => stderr };
}

async function stopGate(gate) {
  if (!gate?.child || gate.child.killed) return;
  await new Promise((resolve) => {
    const timer = setTimeout(() => {
      try { gate.child.kill('SIGKILL'); } catch {}
      resolve();
    }, 1500);
    gate.child.once('exit', () => {
      clearTimeout(timer);
      resolve();
    });
    try { gate.child.kill('SIGTERM'); } catch { resolve(); }
  });
}

async function sendRpc(port, msg, timeoutMs = 7000) {
  return new Promise((resolve, reject) => {
    const client = createConnection(port, '127.0.0.1');
    let buffer = '';
    const timer = setTimeout(() => {
      client.destroy();
      reject(new Error(`timeout waiting for response to ${msg.method}`));
    }, timeoutMs);
    client.once('connect', () => {
      client.write(JSON.stringify(msg) + '\n');
    });
    client.on('data', (data) => {
      buffer += data.toString();
      const lines = buffer.split('\n').filter((l) => l.trim());
      if (lines.length > 0) {
        clearTimeout(timer);
        client.end();
        try { resolve(JSON.parse(lines[0])); }
        catch (e) { reject(e); }
      }
    });
    client.once('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    client.once('close', () => {
      if (!buffer.trim()) {
        clearTimeout(timer);
        reject(new Error(`connection closed before response to ${msg.method}`));
      }
    });
  });
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
    trust_lane_grant: { source: 'test', granted_at: Math.floor(Date.now() / 1000), reason: 'adapter conformance' },
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

async function withGate(opts, fn) {
  const gate = await startGate(opts);
  try {
    return await fn(gate);
  } finally {
    await stopGate(gate);
  }
}

async function runTests() {
  copyGateProject();
  writeAuditSigningKey();
  writePolicy();

  section('TCP gateway pass-through / allow / deny');
  {
    const upstream = await startFakeUpstream();
    await withGate({
      upstreamPort: upstream.port,
      auditName: 'basic',
      agentId: 'adapter-test-agent',
      sessionId: 'adapter-test-session',
    }, async (gate) => {
      const listResp = await sendRpc(gate.port, { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
      assert('non-tools/call tools/list passes through to upstream', Array.isArray(listResp.result?.tools));
      assertEqual('upstream observed tools/list', 'tools/list', upstream.state.calls.at(-1)?.method);
      assert('non-tools/call did not create policy audit event',
        !findAudit(gate.auditFile, (e) => e.action === 'tools/list'));
      assert('non-tools/call did not create Worker Receipt',
        readWorkerReceipts(gate.workerReceiptFile).length === 0);

      const allowResp = await sendRpc(gate.port, {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'marker_allow', arguments: { marker: 'allow' } },
      });
      assert('tools/call allow returns upstream result', /marker_allow/.test(allowResp.result?.content?.[0]?.text || ''));
      assert('allow marker executed upstream', upstream.state.markerExecutions.includes('marker_allow'));
      const allowAudit = findAudit(gate.auditFile, (e) => e.action === 'marker_allow' && e.outcome === 'allow');
      assert('allow audit emitted', !!allowAudit);
      assertEqual('allow audit source=mcp-gate', 'mcp-gate', allowAudit?.source);
      assertEqual('allow audit agent_id', 'adapter-test-agent', allowAudit?.agent_id);
      assertEqual('allow audit session_id', 'adapter-test-session', allowAudit?.session_id);
      assertEqual('allow audit rule', 'AC_ALLOW', allowAudit?.rule);
      const allowReceipt = findWorkerReceipt(gate.workerReceiptFile, (r) => r.event.id === allowAudit?.id);
      assert('allow emits Worker Receipt', !!allowReceipt);
      assertEqual('allow Worker Receipt surface', 'mcp-gate', allowReceipt?.event?.surface);
      assertEqual('allow Worker Receipt class', 'MCP tool call', allowReceipt?.action?.class);
      assertEqual('allow Worker Receipt summary', 'MCP tool: marker_allow', allowReceipt?.action?.summary);
      assert('allow Worker Receipt excludes raw args',
        !JSON.stringify(allowReceipt).includes('args_preview') && !JSON.stringify(allowReceipt).includes('"marker":"allow"'));
      const allowWhy = whyJson(gate.workerReceiptFile, allowAudit.id);
      assertEqual('zlar why reads emitted MCP allow receipt', allowAudit.id, allowWhy?.event?.id);

      const beforeDeny = upstream.state.markerExecutions.length;
      const denyResp = await sendRpc(gate.port, {
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: { name: 'marker_deny', arguments: { marker: 'deny' } },
      });
      assert('deterministic deny returns JSON-RPC error', !!denyResp.error);
      assert('deterministic deny happens before upstream execution',
        upstream.state.markerExecutions.length === beforeDeny);
      const denyAudit = findAudit(gate.auditFile, (e) => e.action === 'marker_deny' && e.outcome === 'deny');
      assert('deny audit emitted', !!denyAudit);
      assertEqual('deny audit source=mcp-gate', 'mcp-gate', denyAudit?.source);
      assertEqual('deny audit rule', 'AC_DENY', denyAudit?.rule);
      assertEqual('deny audit authorizer=policy', 'policy', denyAudit?.authorizer);
      const denyReceipt = findWorkerReceipt(gate.workerReceiptFile, (r) => r.event.id === denyAudit?.id);
      assert('deny emits Worker Receipt', !!denyReceipt);
      assertEqual('deny Worker Receipt decision', 'Denied by policy', denyReceipt?.decision?.label);
      assertEqual('deny Worker Receipt summary', 'MCP tool: marker_deny', denyReceipt?.action?.summary);

      const logResp = await sendRpc(gate.port, {
        jsonrpc: '2.0',
        id: 4,
        method: 'tools/call',
        params: { name: 'marker_log', arguments: { marker: 'log' } },
      });
      assert('logged tools/call returns upstream result', /marker_log/.test(logResp.result?.content?.[0]?.text || ''));
      const logAudit = findAudit(gate.auditFile, (e) => e.action === 'marker_log' && e.outcome === 'logged');
      assert('logged tools/call emits logged audit', !!logAudit);
      assert('logged audit does not emit Worker Receipt',
        !findWorkerReceipt(gate.workerReceiptFile, (r) => r.event.id === logAudit?.id));
    });
  }

  section('Policy and manifest boundary denies');
  {
    const upstream = await startFakeUpstream();
    await withGate({
      upstreamPort: upstream.port,
      auditName: 'default-deny',
      agentId: 'adapter-default-deny-agent',
      sessionId: 'adapter-default-deny-session',
    }, async (gate) => {
      const before = upstream.state.markerExecutions.length;
      const resp = await sendRpc(gate.port, {
        jsonrpc: '2.0',
        id: 5,
        method: 'tools/call',
        params: { name: 'marker_unmatched', arguments: { marker: 'default-deny' } },
      });
      assert('unmatched tool returns JSON-RPC error', !!resp.error);
      assert('unmatched tool is blocked before upstream execution', upstream.state.markerExecutions.length === before);
      const defaultAudit = findAudit(gate.auditFile, (e) => e.action === 'marker_unmatched' && e.outcome === 'deny');
      assert('unmatched tool emits default-deny audit', !!defaultAudit);
      assertEqual('unmatched audit source=mcp-gate', 'mcp-gate', defaultAudit?.source);
      assertEqual('unmatched audit rule=default', 'default', defaultAudit?.rule);
      assertEqual('unmatched audit authorizer=policy', 'policy', defaultAudit?.authorizer);
    });
  }

  {
    const upstream = await startFakeUpstream();
    const manifestFile = writeManifest('deny-mcp-call', {
      deny: ['mcp.call'],
      allow: ['mcp.call'],
      unmatched_action: 'escalate',
    });

    await withGate({
      upstreamPort: upstream.port,
      auditName: 'manifest-deny',
      agentId: 'adapter-manifest-agent',
      sessionId: 'adapter-manifest-session',
      manifestFile,
    }, async (gate) => {
      const listResp = await sendRpc(gate.port, { jsonrpc: '2.0', id: 5, method: 'tools/list', params: {} });
      assert('manifest fixture leaves non-tools/call pass-through unchanged', Array.isArray(listResp.result?.tools));
      assertEqual('manifest pass-through observed upstream tools/list', 'tools/list', upstream.state.calls.at(-1)?.method);
      assert('manifest pass-through does not create policy audit event',
        !findAudit(gate.auditFile, (e) => e.action === 'tools/list'));

      const before = upstream.state.markerExecutions.length;
      const resp = await sendRpc(gate.port, {
        jsonrpc: '2.0',
        id: 7,
        method: 'tools/call',
        params: { name: 'marker_allow', arguments: { marker: 'manifest-deny' } },
      });
      assert('manifest deny returns JSON-RPC refusal', !!resp.error);
      assert('manifest deny error names manifest rule', /manifest:deny/.test(resp.error?.message || ''));
      assert('manifest deny blocks upstream execution', upstream.state.markerExecutions.length === before);
      const manifestAudit = findAudit(gate.auditFile, (e) => e.action === 'marker_allow' && e.outcome === 'deny');
      assert('manifest deny emits audit', !!manifestAudit);
      assertEqual('manifest deny audit source=mcp-gate', 'mcp-gate', manifestAudit?.source);
      assertEqual('manifest deny audit rule', 'manifest:deny', manifestAudit?.rule);
      assertEqual('manifest deny audit authorizer=manifest', 'manifest', manifestAudit?.authorizer);
      assertEqual('manifest deny audit capability', 'mcp.call', manifestAudit?.detail?.cap);
    });
  }

  section('Telegram ask decisions');
  {
    const upstream = await startFakeUpstream();
    const inboxDir = join(SCRATCH, 'inbox-approve');
    const hmacSecretFile = join(SCRATCH, 'inbox-approve-secret');
    const telegram = await startMockTelegram({ inboxDir, hmacSecretFile, hmacSecret: 'adapter-hmac-approve' });
    telegram.setMode('approve');
    const humanId = 'adapter-human-approve';
    const humanStateDir = join(SCRATCH, 'human-approve');
    writeFastHumanState(humanStateDir, humanId);

    await withGate({
      upstreamPort: upstream.port,
      auditName: 'ask-approved',
      agentId: 'adapter-ask-agent',
      sessionId: 'adapter-ask-approved-session',
      telegram,
      humanId,
      inboxDir,
      hmacSecretFile,
      humanStateDir,
    }, async (gate) => {
      const resp = await sendRpc(gate.port, {
        jsonrpc: '2.0',
        id: 10,
        method: 'tools/call',
        params: { name: 'marker_ask', arguments: { marker: 'ask-approved' } },
      }, 9000);
      assert('ask-approved returns upstream result', /marker_ask/.test(resp.result?.content?.[0]?.text || ''));
      assert('ask-approved executes upstream after approval', upstream.state.markerExecutions.includes('marker_ask'));
      const askSent = findAudit(gate.auditFile, (e) => e.action === 'ask_sent' && e.outcome === 'pending');
      assert('ask-approved emits ask_sent audit', !!askSent);
      assert('ask_sent audit does not emit Worker Receipt',
        !findWorkerReceipt(gate.workerReceiptFile, (r) => r.event.id === askSent?.id));
      const askText = latestMcpAskText(telegram);
      assert('ask-approved card uses blue MCP marker',
        askText.includes('🔷') && !askText.includes('♦️'),
        `text=${JSON.stringify(askText)}`);
      const authorized = findAudit(gate.auditFile, (e) => e.action === 'marker_ask' && e.outcome === 'authorized');
      assert('ask-approved emits authorized audit', !!authorized);
      assertEqual('ask-approved audit source=mcp-gate', 'mcp-gate', authorized?.source);
      assertEqual('ask-approved audit authorizer=human', `human:${humanId}`, authorized?.authorizer);
      assertEqual('ask-approved audit rule', 'AC_ASK', authorized?.rule);
      const authorizedReceipt = findWorkerReceipt(gate.workerReceiptFile, (r) => r.event.id === authorized?.id);
      assert('human authorized emits Worker Receipt', !!authorizedReceipt);
      assertEqual('authorized Worker Receipt decision', 'Authorized by human', authorizedReceipt?.decision?.label);
      assertEqual('authorized Worker Receipt authorizer', 'human', authorizedReceipt?.decision?.authorizer);
      assertEqual('authorized Worker Receipt summary', 'MCP tool: marker_ask', authorizedReceipt?.action?.summary);
      assertNoPendingAsk('ask-approved', humanStateDir, humanId);
    });
  }

  {
    const upstream = await startFakeUpstream();
    const inboxDir = join(SCRATCH, 'inbox-deny');
    const hmacSecretFile = join(SCRATCH, 'inbox-deny-secret');
    const telegram = await startMockTelegram({ inboxDir, hmacSecretFile, hmacSecret: 'adapter-hmac-deny' });
    telegram.setMode('deny');
    const humanId = 'adapter-human-deny';
    const humanStateDir = join(SCRATCH, 'human-deny');
    writeFastHumanState(humanStateDir, humanId);

    await withGate({
      upstreamPort: upstream.port,
      auditName: 'ask-denied',
      agentId: 'adapter-ask-agent',
      sessionId: 'adapter-ask-denied-session',
      telegram,
      humanId,
      inboxDir,
      hmacSecretFile,
      humanStateDir,
    }, async (gate) => {
      const before = upstream.state.markerExecutions.length;
      const resp = await sendRpc(gate.port, {
        jsonrpc: '2.0',
        id: 11,
        method: 'tools/call',
        params: { name: 'marker_ask_deny', arguments: { marker: 'ask-denied' } },
      }, 9000);
      assert('ask-denied returns JSON-RPC error', !!resp.error);
      assert('ask-denied blocks upstream execution', upstream.state.markerExecutions.length === before);
      const askText = latestMcpAskText(telegram);
      assert('ask-denied card uses red MCP marker',
        askText.includes('♦️') && !askText.includes('🔷'),
        `text=${JSON.stringify(askText)}`);
      const denied = findAudit(gate.auditFile, (e) => e.action === 'marker_ask_deny' && e.outcome === 'denied');
      assert('ask-denied emits denied audit', !!denied);
      assertEqual('ask-denied audit source=mcp-gate', 'mcp-gate', denied?.source);
      assertEqual('ask-denied audit authorizer=human', `human:${humanId}`, denied?.authorizer);
      assertEqual('ask-denied audit rule', 'AC_ASK_DENY', denied?.rule);
      const deniedReceipt = findWorkerReceipt(gate.workerReceiptFile, (r) => r.event.id === denied?.id);
      assert('human denied emits Worker Receipt', !!deniedReceipt);
      assertEqual('denied Worker Receipt decision', 'Denied by human', deniedReceipt?.decision?.label);
      assertEqual('denied Worker Receipt authorizer', 'human', deniedReceipt?.decision?.authorizer);
      assertEqual('denied Worker Receipt summary', 'MCP tool: marker_ask_deny', deniedReceipt?.action?.summary);
      assertNoPendingAsk('ask-denied', humanStateDir, humanId);
    });
  }

  section('Timeout and upstream failure');
  {
    const upstream = await startFakeUpstream();
    const inboxDir = join(SCRATCH, 'inbox-timeout');
    const hmacSecretFile = join(SCRATCH, 'inbox-timeout-secret');
    const telegram = await startMockTelegram({ inboxDir, hmacSecretFile, hmacSecret: 'adapter-hmac-timeout' });
    telegram.setMode('none');
    const humanId = 'adapter-human-timeout';
    const humanStateDir = join(SCRATCH, 'human-timeout');
    writeFastHumanState(humanStateDir, humanId);

    await withGate({
      upstreamPort: upstream.port,
      auditName: 'timeout',
      agentId: 'adapter-timeout-agent',
      sessionId: 'adapter-timeout-session',
      telegram,
      humanId,
      inboxDir,
      hmacSecretFile,
      humanStateDir,
    }, async (gate) => {
      const before = upstream.state.markerExecutions.length;
      const resp = await sendRpc(gate.port, {
        jsonrpc: '2.0',
        id: 12,
        method: 'tools/call',
        params: { name: 'marker_timeout', arguments: { marker: 'timeout' } },
      }, (GATE_TIMEOUT_S + 4) * 1000);
      assert('timeout returns JSON-RPC error', !!resp.error);
      assert('timeout error mentions human wait', /waiting for human/.test(resp.error?.message || ''));
      assert('timeout blocks upstream execution', upstream.state.markerExecutions.length === before);
      const timeoutAudit = findAudit(gate.auditFile, (e) => e.action === 'marker_timeout' && e.authorizer === 'gate:timeout');
      assert('timeout emits gate:timeout audit', !!timeoutAudit);
      assertEqual('timeout audit outcome=denied', 'denied', timeoutAudit?.outcome);
      assertEqual('timeout audit source=mcp-gate', 'mcp-gate', timeoutAudit?.source);
      const timeoutReceipt = findWorkerReceipt(gate.workerReceiptFile, (r) => r.event.id === timeoutAudit?.id);
      assert('timeout denial emits Worker Receipt', !!timeoutReceipt);
      assertEqual('timeout Worker Receipt decision', 'Denied after approval timeout', timeoutReceipt?.decision?.label);
      assertEqual('timeout Worker Receipt authorizer', 'gate', timeoutReceipt?.decision?.authorizer);
      assertEqual('timeout Worker Receipt summary', 'MCP tool: marker_timeout', timeoutReceipt?.action?.summary);
      assertNoPendingAsk('timeout', humanStateDir, humanId);
    });
  }

  {
    const upstream = await startFakeUpstream();
    const inboxDir = join(SCRATCH, 'inbox-error');
    const hmacSecretFile = join(SCRATCH, 'inbox-error-secret');
    const telegram = await startMockTelegram({
      inboxDir,
      hmacSecretFile,
      hmacSecret: 'adapter-hmac-error',
      failSend: true,
    });
    const humanId = 'adapter-human-error';
    const humanStateDir = join(SCRATCH, 'human-error');
    writeFastHumanState(humanStateDir, humanId);

    await withGate({
      upstreamPort: upstream.port,
      auditName: 'telegram-error',
      agentId: 'adapter-error-agent',
      sessionId: 'adapter-error-session',
      telegram,
      humanId,
      inboxDir,
      hmacSecretFile,
      humanStateDir,
    }, async (gate) => {
      const before = upstream.state.markerExecutions.length;
      const resp = await sendRpc(gate.port, {
        jsonrpc: '2.0',
        id: 13,
        method: 'tools/call',
        params: { name: 'marker_ask', arguments: { marker: 'telegram-error' } },
      }, 7000);
      assert('Telegram send error returns JSON-RPC error', !!resp.error);
      assert('Telegram send error blocks upstream execution', upstream.state.markerExecutions.length === before);
      const errorAudit = findAudit(gate.auditFile, (e) => e.action === 'marker_ask' && e.authorizer === 'gate:error');
      assert('Telegram send error emits gate:error audit', !!errorAudit);
      assertEqual('Telegram send error audit outcome=denied', 'denied', errorAudit?.outcome);
      assertNoPendingAsk('Telegram send error', humanStateDir, humanId);
    });
  }

  {
    const unavailablePort = await getFreePort();
    await withGate({
      upstreamPort: unavailablePort,
      auditName: 'upstream-unavailable',
      agentId: 'adapter-upstream-agent',
      sessionId: 'adapter-upstream-session',
    }, async (gate) => {
      const resp = await sendRpc(gate.port, {
        jsonrpc: '2.0',
        id: 14,
        method: 'tools/call',
        params: { name: 'marker_allow', arguments: { marker: 'upstream-unavailable' } },
      }, 7000);
      assert('upstream unavailable returns JSON-RPC error', !!resp.error);
      assert('upstream unavailable error is fail-closed', /Upstream unavailable/.test(resp.error?.message || ''));
      const upstreamAudit = findAudit(gate.auditFile, (e) => e.action === 'upstream.error' && e.outcome === 'deny');
      assert('upstream unavailable emits upstream.error audit', !!upstreamAudit);
      assertEqual('upstream unavailable audit source=mcp-gate', 'mcp-gate', upstreamAudit?.source);
      assertEqual('upstream unavailable audit authorizer=gate', 'gate', upstreamAudit?.authorizer);
      assert('upstream.error audit does not emit Worker Receipt',
        !findWorkerReceipt(gate.workerReceiptFile, (r) => r.event.id === upstreamAudit?.id));
    });
  }

  section('Worker Receipt failure isolation');
  {
    const upstream = await startFakeUpstream();
    const badWorkerReceiptPath = join(SCRATCH, 'worker-receipt-as-directory');
    mkdirSync(badWorkerReceiptPath, { recursive: true });
    await withGate({
      upstreamPort: upstream.port,
      auditName: 'worker-receipt-failure',
      agentId: 'adapter-wr-failure-agent',
      sessionId: 'adapter-wr-failure-session',
      workerReceiptFile: badWorkerReceiptPath,
    }, async (gate) => {
      const resp = await sendRpc(gate.port, {
        jsonrpc: '2.0',
        id: 15,
        method: 'tools/call',
        params: { name: 'marker_allow', arguments: { marker: 'worker-receipt-failure' } },
      });
      assert('Worker Receipt append failure does not change allow RPC result',
        /marker_allow/.test(resp.result?.content?.[0]?.text || ''));
      assert('Worker Receipt append failure still emits audit',
        !!findAudit(gate.auditFile, (e) => e.action === 'marker_allow' && e.outcome === 'allow'));
      assert('Worker Receipt append failure logs warning',
        gate.stderr().includes('Worker Receipt generation failed'));
    });
  }

  section('Codex stdio transport gap');
  skip(
    'Codex/MCP stdio transport',
    'current mcp-gate/gate.mjs is a TCP proxy (--upstream host:port); Gateway v2 stdio support is not implemented in this harness',
  );
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
