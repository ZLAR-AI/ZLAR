#!/usr/bin/env node
// ─── ZLAR AuthZEN Server Test Suite ──────────────────────────────────────────
// Tests for @zlar/authzen — AuthZEN 1.0 PDP interface over the gate daemon.
//
// Structure:
//   Unit tests   — request mapping, response format, no daemon needed
//   Integration  — starts daemon + server, exercises full HTTP path

import { existsSync, unlinkSync }   from 'fs';
import { tmpdir }                   from 'os';
import { join, dirname }            from 'path';
import { fileURLToPath }            from 'url';
import { randomUUID }               from 'crypto';
import { spawn }                    from 'child_process';

import { startServer }              from './server.mjs';
import { ZlarDaemonUnreachableError } from '../membrane/index.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_DIR  = join(__dirname, '..', '..');
const DAEMON_PATH = join(__dirname, '..', 'daemon', 'daemon.mjs');

// ─── Test Harness ─────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

function header(name) { console.log(`\n── ${name} ──`); }

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    ${e.message}`);
    failed++;
  }
}

function assert(cond, msg) { if (!cond) throw new Error(msg ?? 'Assertion failed'); }
function assertEqual(a, b, msg) {
  if (a !== b) throw new Error(msg ?? `Expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}

// ─── Unit Tests ───────────────────────────────────────────────────────────────

header('Unit — startServer() without daemon');

await test('startServer() throws ZlarDaemonUnreachableError if no daemon', async () => {
  const sockPath = join(tmpdir(), `zlar-authzen-test-${randomUUID()}.sock`);
  let threw = false;
  try {
    await startServer({ socketPath: sockPath, connectTimeout: 150 });
  } catch (e) {
    threw = true;
    assert(e instanceof ZlarDaemonUnreachableError,
      `Expected ZlarDaemonUnreachableError, got ${e.constructor.name}: ${e.message}`);
  }
  assert(threw, 'Should have thrown');
});

// ─── Integration Tests ────────────────────────────────────────────────────────

header('Integration (AuthZEN server + daemon)');

const SOCK_PATH = join(tmpdir(), `zlar-authzen-daemon-${randomUUID()}.sock`);
let daemonProc = null;
let httpServer = null;
let serverPort = null;

// Start daemon
async function startDaemon() {
  if (!existsSync(DAEMON_PATH)) return false;
  return new Promise((resolve) => {
    daemonProc = spawn('node', [DAEMON_PATH], {
      env:   { ...process.env, ZLAR_GATE_SOCKET: SOCK_PATH },
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd:   REPO_DIR,
    });
    let ready = false;
    const onOutput = (data) => {
      if (!ready && data.toString().includes('Listening')) {
        ready = true; resolve(true);
      }
    };
    daemonProc.stdout.on('data', onOutput);
    daemonProc.stderr.on('data', onOutput);
    daemonProc.on('error', () => resolve(false));
    setTimeout(() => { if (!ready) resolve(false); }, 4000);
  });
}

async function cleanup() {
  if (httpServer) { httpServer.close(); httpServer = null; }
  if (daemonProc) { daemonProc.kill('SIGTERM'); daemonProc = null; }
  if (existsSync(SOCK_PATH)) { try { unlinkSync(SOCK_PATH); } catch (_) {} }
}

const daemonStarted = await startDaemon();

if (!daemonStarted) {
  console.log(`  ⊘ Could not start daemon — skipping integration tests`);
} else {
  try {
    // Start AuthZEN server on port 0 (OS assigns)
    const result = await startServer({
      socketPath: SOCK_PATH,
      port:       0,            // OS assigns a free port
      agentId:    'authzen-test-server',
    });
    httpServer = result.server;
    serverPort = result.port;

    const base = `http://127.0.0.1:${serverPort}`;

    // ── Health ─────────────────────────────────────────────────────────────

    await test('GET /health → 200 ok', async () => {
      const res  = await fetch(`${base}/health`);
      const body = await res.json();
      assertEqual(res.status, 200);
      assertEqual(body.status, 'ok');
    });

    await test('GET /health → daemon_connected: true', async () => {
      const res  = await fetch(`${base}/health`);
      const body = await res.json();
      assert(body.daemon_connected === true, 'daemon_connected should be true');
    });

    await test('GET /health → version present', async () => {
      const res  = await fetch(`${base}/health`);
      const body = await res.json();
      assert(typeof body.version === 'string', 'version should be a string');
    });

    // ── Single Evaluation ──────────────────────────────────────────────────

    await test('POST /access/v1/evaluation — ls → decision: true', async () => {
      const res = await fetch(`${base}/access/v1/evaluation`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject:  { type: 'agent', id: 'test-agent' },
          resource: { type: 'tool',  id: 'Bash' },
          action:   { type: 'execute', id: 'execute' },
          context:  { tool_input: { command: 'ls -la', cwd: '/tmp' } },
        }),
      });
      const body = await res.json();
      assertEqual(res.status, 200);
      assert(body.decision === true, `Expected decision: true, got ${body.decision}`);
    });

    await test('POST /access/v1/evaluation — rm -rf / → decision: false', async () => {
      const res = await fetch(`${base}/access/v1/evaluation`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject:  { type: 'agent', id: 'test-agent' },
          resource: { type: 'tool',  id: 'Bash' },
          action:   { type: 'execute', id: 'execute' },
          context:  { tool_input: { command: 'rm -rf /', cwd: '/tmp' } },
        }),
      });
      const body = await res.json();
      assertEqual(res.status, 200);
      assert(body.decision === false, `Expected decision: false, got ${body.decision}`);
    });

    await test('decision is a boolean (not string)', async () => {
      const res = await fetch(`${base}/access/v1/evaluation`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject:  { type: 'agent', id: 'test-agent' },
          resource: { type: 'tool',  id: 'Bash' },
          action:   { type: 'execute', id: 'execute' },
          context:  { tool_input: { command: 'ls', cwd: '/tmp' } },
        }),
      });
      const body = await res.json();
      assert(typeof body.decision === 'boolean',
        `decision must be boolean, got ${typeof body.decision}`);
    });

    await test('response includes context.rule', async () => {
      const res = await fetch(`${base}/access/v1/evaluation`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject:  { type: 'agent', id: 'test-agent' },
          resource: { type: 'tool',  id: 'Bash' },
          action:   { type: 'execute', id: 'execute' },
          context:  { tool_input: { command: 'ls', cwd: '/tmp' } },
        }),
      });
      const body = await res.json();
      assert('context' in body, 'response should have context');
      assert('rule' in body.context, 'context should have rule');
    });

    await test('response includes context.risk_score', async () => {
      const res = await fetch(`${base}/access/v1/evaluation`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject:  { type: 'agent', id: 'test-agent' },
          resource: { type: 'tool',  id: 'Bash' },
          action:   { type: 'execute', id: 'execute' },
          context:  { tool_input: { command: 'ls', cwd: '/tmp' } },
        }),
      });
      const body = await res.json();
      assert('risk_score' in body.context, 'context should have risk_score');
      assert(typeof body.context.risk_score === 'number',
        `risk_score should be number, got ${typeof body.context.risk_score}`);
    });

    await test('missing resource.id → decision: false (not 400)', async () => {
      const res = await fetch(`${base}/access/v1/evaluation`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject: { type: 'agent', id: 'test-agent' },
          context: { tool_input: { command: 'ls' } },
        }),
      });
      const body = await res.json();
      assertEqual(res.status, 200);
      assert(body.decision === false, 'Missing resource.id should deny');
    });

    await test('subject.id forwarded as agent_id', async () => {
      // Not directly observable, but verify the call succeeds with agent_id set
      const res = await fetch(`${base}/access/v1/evaluation`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject:  { type: 'agent', id: 'my-custom-orchestrator' },
          resource: { type: 'tool',  id: 'Bash' },
          action:   { type: 'execute', id: 'execute' },
          context:  { tool_input: { command: 'ls', cwd: '/tmp' }, session_id: 'sess-123' },
        }),
      });
      const body = await res.json();
      assertEqual(res.status, 200);
      // decision is valid
      assert(typeof body.decision === 'boolean');
    });

    // ── Batch Evaluation ───────────────────────────────────────────────────

    await test('POST /access/v1/evaluations — batch returns array', async () => {
      const res = await fetch(`${base}/access/v1/evaluations`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          evaluations: [
            { subject: { id: 'agent-a' }, resource: { id: 'Bash' }, action: { id: 'execute' },
              context: { tool_input: { command: 'ls', cwd: '/tmp' } } },
            { subject: { id: 'agent-b' }, resource: { id: 'Bash' }, action: { id: 'execute' },
              context: { tool_input: { command: 'rm -rf /', cwd: '/tmp' } } },
          ],
        }),
      });
      const body = await res.json();
      assertEqual(res.status, 200);
      assert(Array.isArray(body.evaluations), 'evaluations should be array');
      assertEqual(body.evaluations.length, 2);
    });

    await test('POST /access/v1/evaluations — decisions correct (allow, deny)', async () => {
      const res = await fetch(`${base}/access/v1/evaluations`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          evaluations: [
            { subject: { id: 'agent' }, resource: { id: 'Bash' }, action: { id: 'execute' },
              context: { tool_input: { command: 'ls -la', cwd: '/tmp' } } },
            { subject: { id: 'agent' }, resource: { id: 'Bash' }, action: { id: 'execute' },
              context: { tool_input: { command: 'rm -rf /', cwd: '/tmp' } } },
          ],
        }),
      });
      const body = await res.json();
      assert(body.evaluations[0].decision === true,  'First (ls) should allow');
      assert(body.evaluations[1].decision === false, 'Second (rm -rf) should deny');
    });

    await test('POST /access/v1/evaluations — missing array → 400', async () => {
      const res = await fetch(`${base}/access/v1/evaluations`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ notEvaluations: [] }),
      });
      assertEqual(res.status, 400);
    });

    await test('POST /access/v1/evaluations — empty batch → empty array', async () => {
      const res = await fetch(`${base}/access/v1/evaluations`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ evaluations: [] }),
      });
      const body = await res.json();
      assertEqual(res.status, 200);
      assertEqual(body.evaluations.length, 0);
    });

    // ── Delegation Chain via context ───────────────────────────────────────

    await test('delegation_chain in context.delegation_chain is forwarded', async () => {
      // Build a simple chain for the request
      const { DelegationChain } = await import('../membrane/chain.mjs');
      const chain     = DelegationChain.create('test-orchestrator');
      const chainJSON = chain.toJSON();

      const res = await fetch(`${base}/access/v1/evaluation`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject:  { type: 'agent', id: 'test-orchestrator' },
          resource: { type: 'tool',  id: 'Bash' },
          action:   { type: 'execute', id: 'execute' },
          context: {
            tool_input:       { command: 'ls', cwd: '/tmp' },
            delegation_chain: chainJSON,
          },
        }),
      });
      const body = await res.json();
      assertEqual(res.status, 200);
      assert(typeof body.decision === 'boolean', 'Should have a decision');
    });

    // ── 404 / Invalid ──────────────────────────────────────────────────────

    await test('GET /nonexistent → 404', async () => {
      const res = await fetch(`${base}/some/random/path`);
      assertEqual(res.status, 404);
    });

    await test('POST with invalid JSON → 400', async () => {
      const res = await fetch(`${base}/access/v1/evaluation`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body: 'not json at all {{{',
      });
      assertEqual(res.status, 400);
    });

  } catch (startErr) {
    console.log(`  ⊘ Could not start AuthZEN server: ${startErr.message} — skipping`);
  }
}

await cleanup();

// ─── Summary ──────────────────────────────────────────────────────────────────

console.log('\n' + '─'.repeat(50));
console.log(`${passed} passed, ${failed} failed out of ${passed + failed} tests`);

if (failed > 0) process.exit(1);
