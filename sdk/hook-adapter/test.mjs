#!/usr/bin/env node
// ─── ZLAR HTTP Hook Adapter Test Suite ──────────────────────────────────────
// Tests for @zlar/hook-adapter — Claude Code governance bridge.
//
// Structure:
//   Unit tests   — fail-closed behavior, no daemon needed
//   Integration  — starts daemon + hook adapter, exercises full HTTP path
//
// Key invariant under test: POST /hook ALWAYS returns HTTP 200.
// Non-2xx = fail-open in Claude Code. The adapter is fail-closed at HTTP level.

import { existsSync, unlinkSync }   from 'fs';
import { tmpdir }                   from 'os';
import { join, dirname }            from 'path';
import { fileURLToPath }            from 'url';
import { randomUUID }               from 'crypto';
import { spawn }                    from 'child_process';

import { startServer }                from './server.mjs';
import { ZlarDaemonUnreachableError } from '../membrane/index.mjs';

const __dirname   = dirname(fileURLToPath(import.meta.url));
const REPO_DIR    = join(__dirname, '..', '..');
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
  const sockPath = join(tmpdir(), `zlar-hook-test-${randomUUID()}.sock`);
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

// ─── Managed Settings Generator ───────────────────────────────────────────────

header('Unit — managed settings generator');

await test('generateManagedSettings() returns valid structure', async () => {
  const { generateManagedSettings } = await import('./managed-settings.mjs');
  const settings = generateManagedSettings();
  assert(settings.hooks,       'Should have hooks');
  assert(settings.hooks.PreToolUse,    'Should have PreToolUse hooks');
  assert(settings.hooks.SubagentStart, 'Should have SubagentStart hooks');
  assert(settings.permissions, 'Should have permissions');
  assert(Array.isArray(settings.permissions.deny), 'Should have deny array');
  assert(settings.allowManagedHooksOnly === true, 'Should lock hooks');
});

await test('generateManagedSettings() custom hookUrl is applied', async () => {
  const { generateManagedSettings } = await import('./managed-settings.mjs');
  const settings = generateManagedSettings({ hookUrl: 'https://zlar.example.com/hook' });
  const hookCfg = settings.hooks.PreToolUse[0].hooks[0];
  assertEqual(hookCfg.url, 'https://zlar.example.com/hook');
});

await test('generateManagedSettings() without static denies omits permissions', async () => {
  const { generateManagedSettings } = await import('./managed-settings.mjs');
  const settings = generateManagedSettings({ includeStaticDenyRules: false });
  assert(!settings.permissions, 'Should not have permissions when disabled');
});

// ─── Integration Tests ────────────────────────────────────────────────────────

header('Integration (hook adapter + daemon)');

const SOCK_PATH = join(tmpdir(), `zlar-hook-daemon-${randomUUID()}.sock`);
let daemonProc = null;
let httpServer = null;
let serverPort = null;

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
    const result = await startServer({
      socketPath: SOCK_PATH,
      port:       0,
      agentId:    'hook-test-server',
    });
    httpServer = result.server;
    serverPort = result.port;

    const base = `http://127.0.0.1:${serverPort}`;

    // Helper: POST to /hook
    async function hookPost(body) {
      const res = await fetch(`${base}/hook`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    typeof body === 'string' ? body : JSON.stringify(body),
      });
      return { status: res.status, body: await res.json() };
    }

    // ── Health ─────────────────────────────────────────────────────────────

    await test('GET /health → 200, status ok', async () => {
      const res  = await fetch(`${base}/health`);
      const body = await res.json();
      assertEqual(res.status, 200);
      assertEqual(body.status, 'ok');
    });

    await test('GET /health → daemon_connected: true', async () => {
      const res  = await fetch(`${base}/health`);
      const body = await res.json();
      assert(body.daemon_connected === true, `Expected true, got ${body.daemon_connected}`);
    });

    await test('GET /health → version present', async () => {
      const res  = await fetch(`${base}/health`);
      const body = await res.json();
      assert(typeof body.version === 'string', 'version should be string');
    });

    // ── PreToolUse — allow/deny ────────────────────────────────────────────

    await test('POST /hook: ls -la → permissionDecision: allow', async () => {
      const { status, body } = await hookPost({
        hook_event_name: 'PreToolUse',
        tool_name:       'Bash',
        tool_input:      { command: 'ls -la', cwd: '/tmp' },
        session_id:      'test-session',
      });
      assertEqual(status, 200);
      assertEqual(body.hookSpecificOutput.permissionDecision, 'allow');
    });

    await test('POST /hook: rm -rf / → permissionDecision: deny', async () => {
      const { status, body } = await hookPost({
        hook_event_name: 'PreToolUse',
        tool_name:       'Bash',
        tool_input:      { command: 'rm -rf /', cwd: '/tmp' },
        session_id:      'test-session',
      });
      assertEqual(status, 200);
      assertEqual(body.hookSpecificOutput.permissionDecision, 'deny');
    });

    await test('POST /hook: hookEventName is PreToolUse', async () => {
      const { body } = await hookPost({
        hook_event_name: 'PreToolUse',
        tool_name:       'Bash',
        tool_input:      { command: 'ls', cwd: '/tmp' },
      });
      assertEqual(body.hookSpecificOutput.hookEventName, 'PreToolUse');
    });

    await test('POST /hook: deny includes permissionDecisionReason', async () => {
      const { body } = await hookPost({
        hook_event_name: 'PreToolUse',
        tool_name:       'Bash',
        tool_input:      { command: 'rm -rf /', cwd: '/tmp' },
      });
      assert(typeof body.hookSpecificOutput.permissionDecisionReason === 'string',
        'Deny should include permissionDecisionReason');
      assert(body.hookSpecificOutput.permissionDecisionReason.length > 0,
        'Reason should not be empty');
    });

    await test('POST /hook: response is ALWAYS HTTP 200 (even deny)', async () => {
      const { status } = await hookPost({
        hook_event_name: 'PreToolUse',
        tool_name:       'Bash',
        tool_input:      { command: 'rm -rf /', cwd: '/tmp' },
      });
      assertEqual(status, 200, 'Deny must still be HTTP 200 (non-2xx = fail-open)');
    });

    await test('POST /hook: missing hook_event_name defaults to PreToolUse', async () => {
      const { body } = await hookPost({
        tool_name:  'Bash',
        tool_input: { command: 'ls', cwd: '/tmp' },
      });
      assertEqual(body.hookSpecificOutput.hookEventName, 'PreToolUse');
      assertEqual(body.hookSpecificOutput.permissionDecision, 'allow');
    });

    // ── SubagentStart ──────────────────────────────────────────────────────

    await test('POST /hook: SubagentStart returns valid response', async () => {
      const { status, body } = await hookPost({
        hook_event_name: 'SubagentStart',
        agent_type:      'general-purpose',
        prompt:          'Research task',
        session_id:      'test-session',
      });
      assertEqual(status, 200);
      assertEqual(body.hookSpecificOutput.hookEventName, 'SubagentStart');
      assert(['allow', 'deny'].includes(body.hookSpecificOutput.permissionDecision),
        `Decision should be allow or deny, got: ${body.hookSpecificOutput.permissionDecision}`);
    });

    // ── Fail-closed error handling ─────────────────────────────────────────
    // Non-2xx = fail-open in Claude Code. These MUST return 200 + deny.

    await test('POST /hook: malformed JSON → 200 + deny (NOT 400)', async () => {
      const { status, body } = await hookPost('this is not json {{{');
      assertEqual(status, 200, 'Malformed JSON must be HTTP 200 (non-2xx = fail-open)');
      assertEqual(body.hookSpecificOutput.permissionDecision, 'deny');
    });

    await test('POST /hook: empty body → 200 + deny', async () => {
      const res = await fetch(`${base}/hook`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    '',
      });
      assertEqual(res.status, 200);
      // empty string parses as {} by readBody, which has no tool_name
      const body = await res.json();
      assertEqual(body.hookSpecificOutput.permissionDecision, 'deny');
    });

    await test('POST /hook: missing tool_name → 200 + deny', async () => {
      const { status, body } = await hookPost({
        hook_event_name: 'PreToolUse',
        tool_input:      { command: 'ls' },
      });
      assertEqual(status, 200);
      assertEqual(body.hookSpecificOutput.permissionDecision, 'deny');
    });

    // ── Chain forwarding ───────────────────────────────────────────────────

    await test('POST /hook: delegation_chain forwarded to daemon', async () => {
      const { DelegationChain } = await import('../membrane/chain.mjs');
      const chain = DelegationChain.create('hook-test-agent');
      const { status, body } = await hookPost({
        hook_event_name:  'PreToolUse',
        tool_name:        'Bash',
        tool_input:       { command: 'ls', cwd: '/tmp' },
        delegation_chain: chain.toJSON(),
      });
      assertEqual(status, 200);
      // Self-signed chains are rejected by daemon verification
      // (daemon requires daemon-signed root). This proves the chain was forwarded.
      assertEqual(body.hookSpecificOutput.permissionDecision, 'deny',
        'Self-signed chain should be rejected by daemon chain verification');
    });

    // ── 404 ────────────────────────────────────────────────────────────────

    await test('GET /nonexistent → 404', async () => {
      const res = await fetch(`${base}/some/random/path`);
      assertEqual(res.status, 404);
    });

  } catch (startErr) {
    console.log(`  ⊘ Could not start hook adapter: ${startErr.message} — skipping`);
  }
}

await cleanup();

// ─── Summary ──────────────────────────────────────────────────────────────────

console.log('\n' + '─'.repeat(50));
console.log(`${passed} passed, ${failed} failed out of ${passed + failed} tests`);

if (failed > 0) process.exit(1);
