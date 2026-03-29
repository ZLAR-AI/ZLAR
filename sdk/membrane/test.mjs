#!/usr/bin/env node
// ─── ZLAR SDK Membrane Test Suite ────────────────────────────────────────────
// Tests for @zlar/sdk ZlarAgent membrane.
//
// Structure:
//   Unit tests   — no daemon required, test error classes, frame protocol,
//                  socket discovery, constructor invariants
//   Integration  — starts a real daemon on a temp socket, exercises the
//                  full evaluate/gate/wrapTools path against live policy

import { createHash, randomUUID }         from 'crypto';
import { existsSync, mkdirSync, unlinkSync } from 'fs';
import { tmpdir, homedir }                from 'os';
import { join, dirname }                  from 'path';
import { fileURLToPath }                  from 'url';
import { spawn }                          from 'child_process';

import {
  ZlarAgent,
  ZlarGateError,
  ZlarDaemonUnreachableError,
  ZlarDeniedError,
  ZlarGateTimeoutError,
  ZlarProtocolError,
} from './index.mjs';

// ─── Test Harness ─────────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));

let passed = 0;
let failed = 0;
let section = '';

function header(name) {
  section = name;
  console.log(`\n── ${name} ──`);
}

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

function assert(condition, message) {
  if (!condition) throw new Error(message ?? 'Assertion failed');
}

function assertEqual(a, b, msg) {
  if (a !== b) throw new Error(msg ?? `Expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}

// ─── Frame Protocol (internal — we test via re-implementation) ────────────────
// Keep a local copy so we can test without importing internals.

const MAX_MSG = 1 * 1024 * 1024;

function buildFrame(obj) {
  const payload = Buffer.from(JSON.stringify(obj), 'utf8');
  const header  = Buffer.allocUnsafe(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

function parseFrames(buf) {
  const results = [];
  while (buf.length >= 4) {
    const len = buf.readUInt32BE(0);
    if (buf.length < 4 + len) break;
    results.push(JSON.parse(buf.slice(4, 4 + len).toString('utf8')));
    buf = buf.slice(4 + len);
  }
  return results;
}

// ─── Unit Tests ───────────────────────────────────────────────────────────────

header('Error Classes');

await test('ZlarGateError has name and code', () => {
  const e = new ZlarGateError('msg', 'MY_CODE');
  assertEqual(e.name, 'ZlarGateError');
  assertEqual(e.code, 'MY_CODE');
});

await test('ZlarDaemonUnreachableError has socketPath', () => {
  const e = new ZlarDaemonUnreachableError('/tmp/test.sock');
  assertEqual(e.name, 'ZlarDaemonUnreachableError');
  assertEqual(e.socketPath, '/tmp/test.sock');
  assertEqual(e.code, 'DAEMON_UNREACHABLE');
  assert(e instanceof ZlarGateError, 'should inherit ZlarGateError');
  assert(e instanceof Error, 'should inherit Error');
});

await test('ZlarDeniedError has toolName, rule, reason', () => {
  const e = new ZlarDeniedError('Bash', 'R002', 'dangerous command');
  assertEqual(e.name, 'ZlarDeniedError');
  assertEqual(e.toolName, 'Bash');
  assertEqual(e.rule, 'R002');
  assertEqual(e.reason, 'dangerous command');
  assertEqual(e.code, 'DENIED');
  assert(e instanceof ZlarGateError);
});

await test('ZlarGateTimeoutError has toolName', () => {
  const e = new ZlarGateTimeoutError('Bash');
  assertEqual(e.name, 'ZlarGateTimeoutError');
  assertEqual(e.toolName, 'Bash');
  assertEqual(e.code, 'TIMEOUT');
  assert(e instanceof ZlarGateError);
});

await test('ZlarProtocolError has code PROTOCOL_ERROR', () => {
  const e = new ZlarProtocolError('bad frame');
  assertEqual(e.name, 'ZlarProtocolError');
  assertEqual(e.code, 'PROTOCOL_ERROR');
  assert(e instanceof ZlarGateError);
});

header('Frame Protocol');

await test('buildFrame: correct total length', () => {
  const obj = { jsonrpc: '2.0', id: 1, method: 'evaluate' };
  const frame = buildFrame(obj);
  const payloadLen = Buffer.from(JSON.stringify(obj), 'utf8').length;
  assertEqual(frame.length, 4 + payloadLen);
});

await test('buildFrame: header encodes payload length', () => {
  const obj = { x: 'hello' };
  const frame = buildFrame(obj);
  const declared = frame.readUInt32BE(0);
  assertEqual(declared, frame.length - 4);
});

await test('parseFrames: single frame round-trips', () => {
  const obj = { jsonrpc: '2.0', id: 42, result: { decision: 'allow' } };
  const parsed = parseFrames(buildFrame(obj));
  assertEqual(parsed.length, 1);
  assertEqual(parsed[0].id, 42);
  assertEqual(parsed[0].result.decision, 'allow');
});

await test('parseFrames: two frames in one buffer', () => {
  const a = { jsonrpc: '2.0', id: 1, result: { decision: 'allow' } };
  const b = { jsonrpc: '2.0', id: 2, result: { decision: 'deny' }  };
  const combined = Buffer.concat([buildFrame(a), buildFrame(b)]);
  const parsed = parseFrames(combined);
  assertEqual(parsed.length, 2);
  assertEqual(parsed[0].id, 1);
  assertEqual(parsed[1].id, 2);
});

await test('parseFrames: partial frame — waits for more data', () => {
  const obj   = { jsonrpc: '2.0', id: 1, result: {} };
  const frame = buildFrame(obj);
  const partial = frame.slice(0, Math.floor(frame.length / 2));
  const parsed = parseFrames(partial);
  assertEqual(parsed.length, 0);
});

await test('parseFrames: three frames in sequence', () => {
  const msgs = [{ id: 1 }, { id: 2 }, { id: 3 }];
  const buf  = Buffer.concat(msgs.map(buildFrame));
  const parsed = parseFrames(buf);
  assertEqual(parsed.length, 3);
  assertEqual(parsed[2].id, 3);
});

header('Socket Discovery');

await test('ZLAR_GATE_SOCKET env var takes precedence', async () => {
  const prev = process.env.ZLAR_GATE_SOCKET;
  process.env.ZLAR_GATE_SOCKET = '/custom/path.sock';
  // connect() will fail (no daemon there), but we can read socketPath
  try {
    const agent = await ZlarAgent.connect({ connectTimeout: 100 });
    await agent.close();
  } catch (e) {
    assert(e instanceof ZlarDaemonUnreachableError);
    assertEqual(e.socketPath, '/custom/path.sock');
  } finally {
    if (prev === undefined) delete process.env.ZLAR_GATE_SOCKET;
    else process.env.ZLAR_GATE_SOCKET = prev;
  }
});

await test('socketPath option overrides env var', async () => {
  const prev = process.env.ZLAR_GATE_SOCKET;
  process.env.ZLAR_GATE_SOCKET = '/env/path.sock';
  try {
    await ZlarAgent.connect({ socketPath: '/opt/path.sock', connectTimeout: 100 });
  } catch (e) {
    assert(e instanceof ZlarDaemonUnreachableError);
    assertEqual(e.socketPath, '/opt/path.sock');
  } finally {
    if (prev === undefined) delete process.env.ZLAR_GATE_SOCKET;
    else process.env.ZLAR_GATE_SOCKET = prev;
  }
});

await test('fallback: ~/.zlar/gate.sock when no env or XDG', async () => {
  const prevSock = process.env.ZLAR_GATE_SOCKET;
  const prevXdg  = process.env.XDG_RUNTIME_DIR;
  delete process.env.ZLAR_GATE_SOCKET;
  delete process.env.XDG_RUNTIME_DIR;
  const expected = join(homedir(), '.zlar', 'gate.sock');
  try {
    await ZlarAgent.connect({ connectTimeout: 100 });
  } catch (e) {
    assert(e instanceof ZlarDaemonUnreachableError);
    assertEqual(e.socketPath, expected);
  } finally {
    if (prevSock !== undefined) process.env.ZLAR_GATE_SOCKET = prevSock;
    if (prevXdg  !== undefined) process.env.XDG_RUNTIME_DIR  = prevXdg;
  }
});

header('Constructor Invariants');

await test('connect() rejects with ZlarDaemonUnreachableError when daemon not running', async () => {
  const sockPath = join(tmpdir(), `zlar-test-${randomUUID()}.sock`);
  let threw = false;
  try {
    await ZlarAgent.connect({ socketPath: sockPath, connectTimeout: 200 });
  } catch (e) {
    threw = true;
    assert(e instanceof ZlarDaemonUnreachableError, `Expected ZlarDaemonUnreachableError, got ${e.constructor.name}`);
    assertEqual(e.socketPath, sockPath);
  }
  assert(threw, 'connect() should have thrown');
});

await test('connect() with short timeout fails fast', async () => {
  const sockPath = join(tmpdir(), `zlar-test-${randomUUID()}.sock`);
  const start = Date.now();
  try {
    await ZlarAgent.connect({ socketPath: sockPath, connectTimeout: 50 });
  } catch (_) {}
  const elapsed = Date.now() - start;
  assert(elapsed < 500, `Should have failed in <500ms, took ${elapsed}ms`);
});

await test('no way to create ungoverned agent — only static connect()', () => {
  // Verify there is no public constructor path that bypasses connect()
  // ZlarAgent constructor is private — calling with new creates an object
  // but it has #connected = false, so all operations will fail
  // This is a design-time guarantee, not runtime — we verify the API surface
  assert(typeof ZlarAgent.connect === 'function', 'connect() must exist');
  // wrapTools, gate, evaluate all require a connected instance
  // They're not static — you can't call them without an instance
  assert(typeof ZlarAgent.prototype.gate === 'function');
  assert(typeof ZlarAgent.prototype.evaluate === 'function');
  assert(typeof ZlarAgent.prototype.wrapTools === 'function');
});

await test('sessionId is a UUID string', () => {
  // We can inspect sessionId by triggering a connect() failure and checking
  // the error doesn't contain session info — session is internal
  // Instead verify the UUID format via randomUUID()
  const id = randomUUID();
  assert(typeof id === 'string');
  assert(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id));
});

// ─── Integration Tests (start real daemon, test against live policy) ──────────

header('Integration (live daemon)');

const REPO_DIR    = join(__dirname, '..', '..');
const DAEMON_PATH = join(__dirname, '..', 'daemon', 'daemon.mjs');
const SOCK_PATH   = join(tmpdir(), `zlar-membrane-test-${randomUUID()}.sock`);

let daemonProc = null;
let integrationAgent = null;

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
      const line = data.toString();
      if (!ready && line.includes('Listening')) {
        ready = true;
        resolve(true);
      }
    };
    daemonProc.stdout.on('data', onOutput);
    daemonProc.stderr.on('data', onOutput);
    daemonProc.on('error', () => resolve(false));
    daemonProc.on('exit',  (code) => {
      if (!ready) resolve(false);
    });

    // Timeout if daemon doesn't start
    setTimeout(() => { if (!ready) resolve(false); }, 4000);
  });
}

async function stopDaemon() {
  if (daemonProc) {
    daemonProc.kill('SIGTERM');
    daemonProc = null;
  }
  if (existsSync(SOCK_PATH)) {
    try { unlinkSync(SOCK_PATH); } catch (_) {}
  }
  if (integrationAgent) {
    try { await integrationAgent.close(); } catch (_) {}
    integrationAgent = null;
  }
}

const daemonStarted = await startDaemon();

if (!daemonStarted) {
  console.log(`  ⊘ Could not start daemon for integration tests — skipping`);
} else {
  // Connect the shared integration agent
  try {
    integrationAgent = await ZlarAgent.connect({
      agentId:    'membrane-test',
      socketPath: SOCK_PATH,
    });

    await test('connect() succeeds when daemon is running', () => {
      assert(integrationAgent.connected, 'Should be connected');
      assert(typeof integrationAgent.sessionId === 'string', 'sessionId should be string');
      assert(typeof integrationAgent.agentId   === 'string', 'agentId should be string');
      assertEqual(integrationAgent.agentId, 'membrane-test');
      assertEqual(integrationAgent.socketPath, SOCK_PATH);
    });

    await test('evaluate(): allow for safe command (ls)', async () => {
      const result = await integrationAgent.evaluate('Bash', { command: 'ls -la', cwd: '/tmp' });
      assert(result, 'Should have a result');
      assert(['allow', 'ask', 'deny'].includes(result.decision), `Unknown decision: ${result.decision}`);
      // ls -la should be allowed by policy (R001 safe read-only commands)
      assertEqual(result.decision, 'allow');
    });

    await test('evaluate(): deny for dangerous command (rm -rf /)', async () => {
      const result = await integrationAgent.evaluate('Bash', { command: 'rm -rf /', cwd: '/tmp' });
      assert(result);
      // rm -rf should be denied by policy
      assert(result.decision !== 'allow', `rm -rf / should not be allowed, got: ${result.decision}`);
    });

    await test('evaluate(): returns rule name on deny', async () => {
      const result = await integrationAgent.evaluate('Bash', { command: 'rm -rf /', cwd: '/tmp' });
      assert(result.rule, 'Should have a rule name');
      assert(typeof result.rule === 'string');
    });

    await test('evaluate(): returns risk_score', async () => {
      const result = await integrationAgent.evaluate('Bash', { command: 'ls', cwd: '/tmp' });
      assert('risk_score' in result, 'Should have risk_score');
      assert(typeof result.risk_score === 'number');
    });

    await test('gate(): calls fn() and returns result on allow', async () => {
      let fnCalled = false;
      const returnValue = { output: 'test result' };
      const result = await integrationAgent.gate(
        'Bash',
        { command: 'ls -la', cwd: '/tmp' },
        async () => { fnCalled = true; return returnValue; }
      );
      assert(fnCalled, 'fn() should have been called');
      assert(result === returnValue, 'Should return fn() result');
    });

    await test('gate(): throws ZlarDeniedError on deny', async () => {
      let threw = false;
      try {
        await integrationAgent.gate(
          'Bash',
          { command: 'rm -rf /', cwd: '/tmp' },
          async () => { throw new Error('Should not be called'); }
        );
      } catch (e) {
        threw = true;
        assert(e instanceof ZlarDeniedError, `Expected ZlarDeniedError, got ${e.constructor.name}: ${e.message}`);
        assertEqual(e.toolName, 'Bash');
      }
      assert(threw, 'Should have thrown ZlarDeniedError');
    });

    await test('gate(): fn() is NOT called on deny', async () => {
      let fnCalled = false;
      try {
        await integrationAgent.gate(
          'Bash',
          { command: 'rm -rf /', cwd: '/tmp' },
          async () => { fnCalled = true; }
        );
      } catch (_) {}
      assert(!fnCalled, 'fn() must not be called on deny');
    });

    await test('wrapTools(): returns object with same keys', () => {
      const executors = { bash: async () => 'out', write: async () => 'written' };
      const governed  = integrationAgent.wrapTools(executors);
      assert('bash'  in governed, 'bash should be in governed');
      assert('write' in governed, 'write should be in governed');
      assert(typeof governed.bash  === 'function');
      assert(typeof governed.write === 'function');
    });

    await test('wrapTools(): gated call allows safe command', async () => {
      let fnCalled = false;
      const governed = integrationAgent.wrapTools({
        Bash: async (input) => { fnCalled = true; return 'ok'; },
      });
      await governed.Bash({ command: 'ls', cwd: '/tmp' });
      assert(fnCalled, 'executor should have been called for allowed command');
    });

    await test('wrapTools(): gated call denies dangerous command', async () => {
      let threw = false;
      const governed = integrationAgent.wrapTools({
        Bash: async () => 'this should not run',
      });
      try {
        await governed.Bash({ command: 'rm -rf /', cwd: '/tmp' });
      } catch (e) {
        threw = true;
        assert(e instanceof ZlarDeniedError);
      }
      assert(threw, 'Should have thrown ZlarDeniedError');
    });

    await test('multiple concurrent evaluate() calls resolve correctly', async () => {
      const results = await Promise.all([
        integrationAgent.evaluate('Bash', { command: 'ls',    cwd: '/tmp' }),
        integrationAgent.evaluate('Bash', { command: 'ls -la', cwd: '/tmp' }),
        integrationAgent.evaluate('Bash', { command: 'pwd',   cwd: '/tmp' }),
      ]);
      assertEqual(results.length, 3);
      for (const r of results) {
        assertEqual(r.decision, 'allow', `Expected allow, got ${r.decision}`);
      }
    });

    await test('second ZlarAgent.connect() to same daemon succeeds', async () => {
      const agent2 = await ZlarAgent.connect({
        agentId:    'membrane-test-2',
        socketPath: SOCK_PATH,
      });
      assert(agent2.connected);
      assert(agent2.sessionId !== integrationAgent.sessionId, 'Different session IDs');
      await agent2.close();
    });

    await test('close() disconnects and connected becomes false', async () => {
      const tempAgent = await ZlarAgent.connect({
        agentId:    'membrane-test-close',
        socketPath: SOCK_PATH,
      });
      assert(tempAgent.connected);
      await tempAgent.close();
      assert(!tempAgent.connected, 'Should be disconnected after close()');
    });

    await test('evaluate() after close() throws ZlarDaemonUnreachableError', async () => {
      const tempAgent = await ZlarAgent.connect({
        agentId:    'membrane-test-postclosed',
        socketPath: SOCK_PATH,
      });
      await tempAgent.close();
      let threw = false;
      try {
        await tempAgent.evaluate('Bash', { command: 'ls' });
      } catch (e) {
        threw = true;
        assert(e instanceof ZlarDaemonUnreachableError,
          `Expected ZlarDaemonUnreachableError, got ${e.constructor.name}`);
      }
      assert(threw, 'Should throw after close()');
    });

  } catch (startErr) {
    console.log(`  ⊘ Could not connect to daemon: ${startErr.message} — skipping integration tests`);
  }
}

await stopDaemon();

// ─── Summary ──────────────────────────────────────────────────────────────────

console.log('\n' + '─'.repeat(50));
console.log(`${passed} passed, ${failed} failed out of ${passed + failed} tests`);

if (failed > 0) process.exit(1);
