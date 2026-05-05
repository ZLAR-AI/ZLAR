#!/usr/bin/env node
// ZLAR MCP Gate — Test Harness
//
// Simulates MCP JSON-RPC messages and verifies the gate evaluates them
// correctly against policy. No real MCP server needed.

import { createServer, createConnection } from 'net';
import { readFileSync, existsSync, unlinkSync, writeFileSync, mkdirSync, rmSync, utimesSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { generateKeyPairSync, sign as cryptoSign, createHmac } from 'crypto';
import { canonicalize, sha256hex } from '../lib/receipt.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_DIR = join(__dirname, '..');

// Route all test artifacts through the system temp dir to avoid EPERM on
// mounted or read-only working directories, and to isolate the test run
// from live repo state (manifest, constitution, restore-config). Each path
// is test-scoped and cleaned up below.
const TEST_SCRATCH = join(tmpdir(), `zlar-mcp-gate-test-${process.pid}`);
if (existsSync(TEST_SCRATCH)) rmSync(TEST_SCRATCH, { recursive: true, force: true });
mkdirSync(TEST_SCRATCH, { recursive: true });

const TEST_AUDIT = join(TEST_SCRATCH, 'test-audit.jsonl');
const TEST_ALLOW_POLICY = join(TEST_SCRATCH, 'test-allow-policy.json');
const TEST_POLICY_PUBKEY = join(TEST_SCRATCH, 'test-policy-signing.pub');

// Nonexistent paths passed to the spawned gate. Because they do not exist,
// the gate enters graceful defaults:
//   - missing manifest        → policy-only enforcement (bash gate invariant #7)
//   - missing presence-file   → pre-constitutional mode
//   - missing restore-config  → restore disabled
// Without these flags the gate would read live etc/* and reject the test
// fixtures because they are signed under a different key.
const TEST_MANIFEST_FILE = join(TEST_SCRATCH, 'no-manifest.json');
const TEST_CONSTITUTION_PRESENCE = join(TEST_SCRATCH, 'no-presence');
const TEST_RESTORE_CONFIG = join(TEST_SCRATCH, 'no-restore-config.json');

// Clean up test files
if (existsSync(TEST_AUDIT)) unlinkSync(TEST_AUDIT);

// Generate an ephemeral Ed25519 keypair for test fixtures. The private half
// lives in memory only; the public half is written to a temp file and passed
// to the spawned gate via --policy-pubkey. This decouples the test from the
// machine's production signing keys and lets the fixture be signed under
// ZLAR spec canonical form (no LEGACY warnings for test fixtures).
const { publicKey: TEST_PUBKEY, privateKey: TEST_PRIVKEY } = generateKeyPairSync('ed25519');
writeFileSync(TEST_POLICY_PUBKEY, TEST_PUBKEY.export({ type: 'spki', format: 'pem' }));

// Sign the test policy under spec canonical form (see ADR-011).
// Zero .signature.value, canonicalize via lib/canonicalize.mjs (matches
// the MCP gate's spec-form verifier), SHA-256, Ed25519 sign the hex bytes.
function signPolicyUnderSpec(policyObj) {
  const withSig = {
    ...policyObj,
    signature: {
      algorithm: 'ed25519',
      public_key: TEST_PUBKEY.export({ type: 'spki', format: 'der' }).toString('base64'),
      value: '',
    },
  };
  const hashHex = sha256hex(canonicalize(withSig));
  const sig = cryptoSign(null, Buffer.from(hashHex, 'utf8'), TEST_PRIVKEY);
  return { ...withSig, signature: { ...withSig.signature, value: sig.toString('base64') } };
}

// Self-contained signed test policy.
// Structure satisfies PC-02 (at least one ask rule for human contestability)
// via a narrow dummy rule that cannot match test inputs, and PC-05a
// (default_action must be 'deny') by making R095 the explicit catch-all
// allow for the MCP domain. R095 fires before default_action ever matters,
// so the observable allow behavior for MCP tool calls is preserved.
const TEST_POLICY_OBJ = {
  version: 'test-allow',
  default_action: 'deny',
  rules: [
    {
      id: 'R095',
      enabled: true,
      description: 'MCP catch-all allow for testing',
      domain: 'mcp',
      action: 'allow',
      severity: 'info',
      match: { domain: 'mcp' },
      risk_score: { irreversibility: 0, consequence: 0, blast_radius: 0 },
    },
    {
      id: 'R999_PC02_SATISFIER',
      enabled: true,
      description: 'PC-02 placeholder — ask rule for test fixture constitutional compliance',
      domain: 'test_never_matches',
      action: 'ask',
      severity: 'info',
      match: { domain: 'test_never_matches', detail: { tool_name: '__never_matches__' } },
      risk_score: { irreversibility: 0, consequence: 0, blast_radius: 0 },
    },
  ],
};
writeFileSync(TEST_ALLOW_POLICY, JSON.stringify(signPolicyUnderSpec(TEST_POLICY_OBJ)));

// ─── Mock MCP Server ─────────────────────────────────────────────────────────

function startMockServer(port) {
  return new Promise((resolve) => {
    const server = createServer((socket) => {
      socket.on('data', (data) => {
        const lines = data.toString().split('\n').filter(l => l.trim());
        for (const line of lines) {
          try {
            const msg = JSON.parse(line);
            // Echo back a success response
            const response = {
              jsonrpc: '2.0',
              id: msg.id,
              result: { content: [{ type: 'text', text: `Executed: ${msg.params?.name || msg.method}` }] },
            };
            socket.write(JSON.stringify(response) + '\n');
          } catch {}
        }
      });
    });
    // Bind loopback-only. 0.0.0.0 triggers the macOS application firewall
    // for unsigned node binaries; 127.0.0.1 is sufficient for this in-process
    // test (the gate and client connect via 'localhost').
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

// ─── Test Runner ─────────────────────────────────────────────────────────────

async function sendMessage(port, msg) {
  return new Promise((resolve, reject) => {
    const client = createConnection(port, 'localhost', () => {
      client.write(JSON.stringify(msg) + '\n');
    });

    let buffer = '';
    client.on('data', (data) => {
      buffer += data.toString();
      const lines = buffer.split('\n').filter(l => l.trim());
      if (lines.length > 0) {
        try {
          const response = JSON.parse(lines[0]);
          client.end();
          resolve(response);
        } catch {}
      }
    });

    client.on('error', reject);
    setTimeout(() => { client.end(); reject(new Error('timeout')); }, 5000);
  });
}

async function runTests() {
  const MOCK_PORT = 3201;
  const GATE_PORT = 3101;

  console.log('ZLAR MCP Gate — Test Suite\n');

  // Start mock MCP server
  const mockServer = await startMockServer(MOCK_PORT);
  console.log(`✓ Mock MCP server on port ${MOCK_PORT}`);

  // Start the gate (import and run inline since it's async)
  const { spawn } = await import('child_process');
  const gate = spawn('node', [
    join(__dirname, 'gate.mjs'),
    '--port', String(GATE_PORT),
    '--upstream', `localhost:${MOCK_PORT}`,
    '--audit-file', TEST_AUDIT,
    '--policy-file', TEST_ALLOW_POLICY,
    '--policy-pubkey', TEST_POLICY_PUBKEY,
    '--manifest-file', TEST_MANIFEST_FILE,
    '--constitution-presence-file', TEST_CONSTITUTION_PRESENCE,
    '--restore-config-file', TEST_RESTORE_CONFIG,
    '--no-telegram',
    '--agent-id', 'test-agent',
  ], { stdio: ['pipe', 'pipe', 'pipe'] });

  // Wait for gate to start
  await new Promise((resolve) => {
    gate.stdout.on('data', (data) => {
      if (data.toString().includes('listening')) resolve();
    });
    setTimeout(resolve, 2000);
  });
  console.log(`✓ MCP Gate on port ${GATE_PORT}\n`);

  let passed = 0;
  let failed = 0;

  async function test(name, msg, expectError) {
    try {
      const response = await sendMessage(GATE_PORT, msg);

      if (expectError) {
        if (response.error) {
          console.log(`✓ ${name} → blocked: ${response.error.message.substring(0, 60)}`);
          passed++;
        } else {
          console.log(`✗ ${name} → expected deny, got allow`);
          failed++;
        }
      } else {
        if (response.result) {
          console.log(`✓ ${name} → allowed`);
          passed++;
        } else if (response.error) {
          console.log(`✗ ${name} → expected allow, got: ${response.error.message}`);
          failed++;
        }
      }
    } catch (e) {
      console.log(`✗ ${name} → error: ${e.message}`);
      failed++;
    }
  }

  // ─── Test Cases ──────────────────────────────────────────────────────────

  // Non-tools/call messages should pass through
  await test(
    'initialize passes through',
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { capabilities: {} } },
    false
  );

  await test(
    'tools/list passes through',
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
    false
  );

  // tools/call goes through policy evaluation
  // R095 in the active policy allows MCP domain — gate correctly evaluates this
  await test(
    'tools/call allowed by R095 (MCP catch-all)',
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'read_file', arguments: { path: '/tmp/test.txt' } } },
    false
  );

  await test(
    'tools/call with dangerous tool still allowed by R095 (policy decision)',
    { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'execute_command', arguments: { command: 'rm -rf /' } } },
    false
  );

  await test(
    'resources/read passes through (not tools/call)',
    { jsonrpc: '2.0', id: 5, method: 'resources/read', params: { uri: 'file:///tmp/test.txt' } },
    false
  );

  // ─── Test with deny policy ───────────────────────────────────────────
  // Minimal test policy that denies MCP tools/call. Signed under the same
  // ephemeral key as the allow policy so the gate's strict-signature check
  // passes and the DENY path is exercised cleanly. PC-02 is satisfied by
  // R999_PC02_SATISFIER even though this policy's intent is deny-all.
  const denyPolicyPath = join(TEST_SCRATCH, 'test-deny-policy.json');
  writeFileSync(denyPolicyPath, JSON.stringify(signPolicyUnderSpec({
    version: 'test-deny',
    default_action: 'deny',
    rules: [
      {
        id: 'T001',
        enabled: true,
        description: 'Deny all MCP tool calls',
        domain: 'mcp',
        action: 'deny',
        severity: 'critical',
        match: { domain: 'mcp' },
        risk_score: { irreversibility: 100, consequence: 100, blast_radius: 100 },
      },
      {
        id: 'R999_PC02_SATISFIER',
        enabled: true,
        description: 'PC-02 placeholder — ask rule for test fixture constitutional compliance',
        domain: 'test_never_matches',
        action: 'ask',
        severity: 'info',
        match: { domain: 'test_never_matches', detail: { tool_name: '__never_matches__' } },
        risk_score: { irreversibility: 0, consequence: 0, blast_radius: 0 },
      },
    ],
  })));

  // Start a second gate with deny policy
  const DENY_GATE_PORT = 3102;
  const denyGate = spawn('node', [
    join(__dirname, 'gate.mjs'),
    '--port', String(DENY_GATE_PORT),
    '--upstream', `localhost:${MOCK_PORT}`,
    '--audit-file', TEST_AUDIT,
    '--policy-file', denyPolicyPath,
    '--policy-pubkey', TEST_POLICY_PUBKEY,
    '--manifest-file', TEST_MANIFEST_FILE,
    '--constitution-presence-file', TEST_CONSTITUTION_PRESENCE,
    '--restore-config-file', TEST_RESTORE_CONFIG,
    '--no-telegram',
    '--agent-id', 'test-deny-agent',
  ], { stdio: ['pipe', 'pipe', 'pipe'] });

  await new Promise((resolve) => {
    denyGate.stdout.on('data', (data) => {
      if (data.toString().includes('listening')) resolve();
    });
    setTimeout(resolve, 2000);
  });

  // Override sendMessage port for deny tests
  const sendDeny = (msg) => sendMessage(DENY_GATE_PORT, msg);

  try {
    const resp = await sendDeny({ jsonrpc: '2.0', id: 10, method: 'tools/call', params: { name: 'dangerous_tool', arguments: {} } });
    if (resp.error) {
      console.log(`✓ deny policy blocks tools/call → ${resp.error.message.substring(0, 60)}`);
      passed++;
    } else {
      console.log(`✗ deny policy should block tools/call`);
      failed++;
    }
  } catch (e) {
    console.log(`✗ deny policy test error: ${e.message}`);
    failed++;
  }

  // Non-tools/call should still pass through even with deny policy
  try {
    const resp = await sendDeny({ jsonrpc: '2.0', id: 11, method: 'tools/list', params: {} });
    if (resp.result) {
      console.log(`✓ deny policy allows tools/list (not tools/call) → allowed`);
      passed++;
    } else {
      console.log(`✗ deny policy should allow tools/list`);
      failed++;
    }
  } catch (e) {
    console.log(`✗ deny policy tools/list error: ${e.message}`);
    failed++;
  }

  denyGate.kill();
  unlinkSync(denyPolicyPath);

  // ─── Test: Fail-closed on missing policy ─────────────────────────────
  const FAILCLOSED_GATE_PORT = 3103;
  const failClosedGate = spawn('node', [
    join(__dirname, 'gate.mjs'),
    '--port', String(FAILCLOSED_GATE_PORT),
    '--upstream', `localhost:${MOCK_PORT}`,
    '--audit-file', TEST_AUDIT,
    '--policy-file', '/nonexistent/policy.json',
    '--manifest-file', TEST_MANIFEST_FILE,
    '--constitution-presence-file', TEST_CONSTITUTION_PRESENCE,
    '--restore-config-file', TEST_RESTORE_CONFIG,
    '--no-telegram',
    '--agent-id', 'test-failclosed-agent',
  ], { stdio: ['pipe', 'pipe', 'pipe'] });

  await new Promise((resolve) => {
    failClosedGate.stdout.on('data', (data) => {
      if (data.toString().includes('listening')) resolve();
    });
    setTimeout(resolve, 2000);
  });

  try {
    const resp = await sendMessage(FAILCLOSED_GATE_PORT, { jsonrpc: '2.0', id: 20, method: 'tools/call', params: { name: 'read_file', arguments: {} } });
    if (resp.error) {
      console.log(`✓ missing policy → fail-closed (deny) → ${resp.error.message.substring(0, 60)}`);
      passed++;
    } else {
      console.log(`✗ missing policy should fail-closed (deny), got allow`);
      failed++;
    }
  } catch (e) {
    console.log(`✗ fail-closed test error: ${e.message}`);
    failed++;
  }

  failClosedGate.kill();

  // ─── Trust Lane Parity Tests ─────────────────────────────────────────────
  // Verify MCP gate passive canary result processing drives trust lane
  // transitions, matching bash gate behavior from lib/canary.sh.
  //
  // Isolated via ZLAR_HUMAN_STATE_DIR, ZLAR_HUMAN_STATE_HMAC_KEY_FILE,
  // ZLAR_INBOX_HMAC_SECRET_FILE, --canary-state-dir, --cc-inbox-dir,
  // --session-id, --telegram-chat-id.

  const TEST_HUMAN_STATE_DIR = join(TEST_SCRATCH, 'var', 'human-state');
  const TEST_CANARY_DIR      = join(TEST_SCRATCH, 'var', 'canary');
  const TEST_CC_INBOX_DIR    = join(TEST_SCRATCH, 'inbox', 'cc');
  const TEST_HMAC_SECRET     = 'test-inbox-hmac-secret-01';
  const TEST_HMAC_SECRET_FILE = join(TEST_SCRATCH, 'inbox-hmac-secret');

  mkdirSync(TEST_HUMAN_STATE_DIR, { recursive: true });
  mkdirSync(TEST_CANARY_DIR,      { recursive: true });
  mkdirSync(TEST_CC_INBOX_DIR,    { recursive: true });
  writeFileSync(TEST_HMAC_SECRET_FILE, TEST_HMAC_SECRET);

  const TL_SESSION_ID = 'tl-mcp-session-001';
  const TL_HUMAN_ID   = 'test-mcp-tl-001';
  const TL_GATE_PORT  = 3104;

  const tlGate = spawn('node', [
    join(__dirname, 'gate.mjs'),
    '--port', String(TL_GATE_PORT),
    '--upstream', `localhost:${MOCK_PORT}`,
    '--audit-file', TEST_AUDIT,
    '--policy-file', TEST_ALLOW_POLICY,
    '--policy-pubkey', TEST_POLICY_PUBKEY,
    '--manifest-file', TEST_MANIFEST_FILE,
    '--constitution-presence-file', TEST_CONSTITUTION_PRESENCE,
    '--restore-config-file', TEST_RESTORE_CONFIG,
    '--telegram-chat-id', TL_HUMAN_ID,
    '--session-id', TL_SESSION_ID,
    '--canary-state-dir', TEST_CANARY_DIR,
    '--cc-inbox-dir', TEST_CC_INBOX_DIR,
    '--agent-id', 'test-tl-agent',
  ], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      ZLAR_HUMAN_STATE_DIR: TEST_HUMAN_STATE_DIR,
      ZLAR_HUMAN_STATE_HMAC_KEY_FILE: join(TEST_SCRATCH, 'no-hmac-key'),
      ZLAR_INBOX_HMAC_SECRET_FILE: TEST_HMAC_SECRET_FILE,
    },
  });

  await new Promise((resolve) => {
    tlGate.stdout.on('data', (data) => { if (data.toString().includes('listening')) resolve(); });
    setTimeout(resolve, 2000);
  });
  console.log(`✓ Trust lane test gate on port ${TL_GATE_PORT}\n`);

  const sendTL = (msg) => sendMessage(TL_GATE_PORT, msg);
  let tlMsgId = 300;

  // Write initial trust lane state (unkeyed mode — no HMAC key in test env).
  // v3.3.4: optionally preload clean_run_count to test promotion threshold.
  function writeTLState(lane, grantPresent = false, cleanRunCount = 0) {
    const state = {
      human_id: TL_HUMAN_ID,
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
      trust_lane: lane,
      clean_run_count: cleanRunCount,
      clean_run_started_epoch: 0,
      ...(grantPresent ? { trust_lane_grant: { source: 'authority', granted_at: Math.floor(Date.now() / 1000), reason: 'test' } } : {}),
    };
    writeFileSync(join(TEST_HUMAN_STATE_DIR, `${TL_HUMAN_ID}.json`), JSON.stringify(state));
  }

  function readTLLane() {
    try { return JSON.parse(readFileSync(join(TEST_HUMAN_STATE_DIR, `${TL_HUMAN_ID}.json`), 'utf8')).trust_lane; }
    catch { return null; }
  }

  function readTLState() {
    try { return JSON.parse(readFileSync(join(TEST_HUMAN_STATE_DIR, `${TL_HUMAN_ID}.json`), 'utf8')); }
    catch { return null; }
  }

  function writePending(canaryId) {
    // Routing artifact (per-session) — kept for the inbox handler.
    writeFileSync(join(TEST_CANARY_DIR, `${TL_SESSION_ID}.canary.pending`), canaryId + '\n');
    // v3.3.6: per-human pending fields — checkCanaryResult reads these first.
    // Without canary_pending_id set, the resolver returns early before scanning
    // the inbox, so the inbox callback never gets processed.
    const stateFile = join(TEST_HUMAN_STATE_DIR, `${TL_HUMAN_ID}.json`);
    const state = JSON.parse(readFileSync(stateFile, 'utf8'));
    state.canary_pending_id = canaryId;
    state.canary_pending_session_id = TL_SESSION_ID;
    state.canary_pending_started_epoch = Math.floor(Date.now() / 1000);
    writeFileSync(stateFile, JSON.stringify(state));
  }

  function writeCallback(canaryId, result) {
    const data  = `cc:canary:${result}:${canaryId}`;
    const from  = TL_HUMAN_ID;
    const cbId  = `cb-${canaryId}`;
    const hmac  = createHmac('sha256', TEST_HMAC_SECRET).update(`${data}|${from}|${cbId}`).digest('base64');
    writeFileSync(join(TEST_CC_INBOX_DIR, `${canaryId}.json`), JSON.stringify({ data, from_id: from, callback_query_id: cbId, hmac }));
  }

  function cleanTLFiles(canaryId) {
    try { unlinkSync(join(TEST_CANARY_DIR, `${TL_SESSION_ID}.canary.pending`)); } catch {}
    try { unlinkSync(join(TEST_CC_INBOX_DIR, `${canaryId}.json`)); } catch {}
  }

  // TL-MCP-1: canary_failed demotes fast→guarded
  writeTLState('fast');
  writePending('canary-mcp-01');
  writeCallback('canary-mcp-01', 'approve');
  try {
    await sendTL({ jsonrpc: '2.0', id: ++tlMsgId, method: 'tools/call', params: { name: 'test_tool', arguments: {} } });
    const lane = readTLLane();
    if (lane === 'guarded') { console.log(`✓ TL-MCP-1: canary_failed demotes fast→guarded`); passed++; }
    else { console.log(`✗ TL-MCP-1: expected guarded, got ${lane}`); failed++; }
  } catch (e) { console.log(`✗ TL-MCP-1: ${e.message}`); failed++; }
  cleanTLFiles('canary-mcp-01');

  // TL-MCP-2: canary_missed demotes fast→guarded (stale pending, no callback)
  writeTLState('fast');
  writePending('canary-mcp-02');
  try { utimesSync(join(TEST_CANARY_DIR, `${TL_SESSION_ID}.canary.pending`), new Date(0), new Date(0)); } catch {}
  try {
    await sendTL({ jsonrpc: '2.0', id: ++tlMsgId, method: 'tools/call', params: { name: 'test_tool', arguments: {} } });
    const lane = readTLLane();
    if (lane === 'guarded') { console.log(`✓ TL-MCP-2: canary_missed demotes fast→guarded`); passed++; }
    else { console.log(`✗ TL-MCP-2: expected guarded, got ${lane}`); failed++; }
  } catch (e) { console.log(`✗ TL-MCP-2: ${e.message}`); failed++; }
  cleanTLFiles('canary-mcp-02');

  // TL-MCP-3 (v3.3.4): single canary_passed at guarded does not promote.
  // Promotion now requires 5 consecutive healthy canaries — manual grant
  // does not shortcut the run. ZLAR does not score the human. It watches
  // the run.
  writeTLState('guarded', true);
  writePending('canary-mcp-03');
  writeCallback('canary-mcp-03', 'deny');
  try {
    await sendTL({ jsonrpc: '2.0', id: ++tlMsgId, method: 'tools/call', params: { name: 'test_tool', arguments: {} } });
    const s = readTLState();
    if (s.trust_lane === 'guarded' && s.clean_run_count === 1) { console.log(`✓ TL-MCP-3: 1 canary_passed at guarded → lane stays guarded, count=1 (grant does not shortcut)`); passed++; }
    else { console.log(`✗ TL-MCP-3: expected lane=guarded count=1, got lane=${s.trust_lane} count=${s.clean_run_count}`); failed++; }
  } catch (e) { console.log(`✗ TL-MCP-3: ${e.message}`); failed++; }
  cleanTLFiles('canary-mcp-03');

  // TL-MCP-4 (v3.3.4): single canary_passed at guarded with no grant —
  // same expectation. count increments, lane unchanged below threshold.
  writeTLState('guarded', false);
  writePending('canary-mcp-04');
  writeCallback('canary-mcp-04', 'deny');
  try {
    await sendTL({ jsonrpc: '2.0', id: ++tlMsgId, method: 'tools/call', params: { name: 'test_tool', arguments: {} } });
    const s = readTLState();
    if (s.trust_lane === 'guarded' && s.clean_run_count === 1) { console.log(`✓ TL-MCP-4: 1 canary_passed at guarded (no grant) → lane stays guarded, count=1`); passed++; }
    else { console.log(`✗ TL-MCP-4: expected lane=guarded count=1, got lane=${s.trust_lane} count=${s.clean_run_count}`); failed++; }
  } catch (e) { console.log(`✗ TL-MCP-4: ${e.message}`); failed++; }
  cleanTLFiles('canary-mcp-04');

  // TL-MCP-5: HMAC mismatch discards callback — lane unchanged
  writeTLState('fast');
  writePending('canary-mcp-05');
  writeFileSync(join(TEST_CC_INBOX_DIR, 'canary-mcp-05.json'), JSON.stringify({
    data: `cc:canary:approve:canary-mcp-05`,
    from_id: TL_HUMAN_ID,
    callback_query_id: 'cb-05',
    hmac: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
  }));
  try {
    await sendTL({ jsonrpc: '2.0', id: ++tlMsgId, method: 'tools/call', params: { name: 'test_tool', arguments: {} } });
    const lane = readTLLane();
    if (lane === 'fast') { console.log(`✓ TL-MCP-5: HMAC mismatch discards callback — lane unchanged`); passed++; }
    else { console.log(`✗ TL-MCP-5: expected fast (HMAC discarded), got ${lane}`); failed++; }
  } catch (e) { console.log(`✗ TL-MCP-5: ${e.message}`); failed++; }
  cleanTLFiles('canary-mcp-05');

  // ─── v3.3.4: Clean Run Trust Lane Auto-Promotion ──────────────────────────
  // ZLAR does not score the human. It watches the run.

  // CR-MCP-1: 5th consecutive healthy canary at guarded promotes to fast.
  // Preload count=4; this canary pushes count to 5 → promotion + reset.
  writeTLState('guarded', false, 4);
  writePending('canary-mcp-cr1');
  writeCallback('canary-mcp-cr1', 'deny');
  try {
    await sendTL({ jsonrpc: '2.0', id: ++tlMsgId, method: 'tools/call', params: { name: 'test_tool', arguments: {} } });
    const s = readTLState();
    if (s.trust_lane === 'fast' && s.clean_run_count === 0) { console.log(`✓ CR-MCP-1: 5th passed at guarded → lane=fast, count=0 (no grant required)`); passed++; }
    else { console.log(`✗ CR-MCP-1: expected lane=fast count=0, got lane=${s.trust_lane} count=${s.clean_run_count}`); failed++; }
  } catch (e) { console.log(`✗ CR-MCP-1: ${e.message}`); failed++; }
  cleanTLFiles('canary-mcp-cr1');

  // CR-MCP-2: 5th consecutive healthy canary at slow promotes to guarded.
  writeTLState('slow', false, 4);
  writePending('canary-mcp-cr2');
  writeCallback('canary-mcp-cr2', 'deny');
  try {
    await sendTL({ jsonrpc: '2.0', id: ++tlMsgId, method: 'tools/call', params: { name: 'test_tool', arguments: {} } });
    const s = readTLState();
    if (s.trust_lane === 'guarded' && s.clean_run_count === 0) { console.log(`✓ CR-MCP-2: 5th passed at slow → lane=guarded, count=0`); passed++; }
    else { console.log(`✗ CR-MCP-2: expected lane=guarded count=0, got lane=${s.trust_lane} count=${s.clean_run_count}`); failed++; }
  } catch (e) { console.log(`✗ CR-MCP-2: ${e.message}`); failed++; }
  cleanTLFiles('canary-mcp-cr2');

  // CR-MCP-3: failed canary at fast (with active grant) demotes anyway —
  // grant does not shield from demotion. clean_run_count resets.
  writeTLState('fast', true, 3);
  writePending('canary-mcp-cr3');
  writeCallback('canary-mcp-cr3', 'approve');
  try {
    await sendTL({ jsonrpc: '2.0', id: ++tlMsgId, method: 'tools/call', params: { name: 'test_tool', arguments: {} } });
    const s = readTLState();
    const grantStill = s.trust_lane_grant !== undefined;
    if (s.trust_lane === 'guarded' && s.clean_run_count === 0 && grantStill) { console.log(`✓ CR-MCP-3: failed at fast WITH grant → demotes to guarded, count=0, grant retained`); passed++; }
    else { console.log(`✗ CR-MCP-3: expected lane=guarded count=0 grant=true, got lane=${s.trust_lane} count=${s.clean_run_count} grant=${grantStill}`); failed++; }
  } catch (e) { console.log(`✗ CR-MCP-3: ${e.message}`); failed++; }
  cleanTLFiles('canary-mcp-cr3');

  tlGate.kill();
  console.log('');

  // ─── MCP Canary SEND Tests ────────────────────────────────────────────────
  // Verify that recordCanaryApproval, canaryShouldTrigger, and sendCanary
  // operate correctly end-to-end. Uses a mock Telegram HTTP server so no
  // real bot token is required. Shares canary artifact dirs with the TL gate
  // tests but uses a separate session and human ID.
  //
  // Test gate: port 3105
  // Mock Telegram API: port 8766 (intercepts telegramApi via ZLAR_TELEGRAM_API_BASE)
  //
  // Sequenced (requests build on prior state):
  //   SEND-1: first human approval creates state, counter=1
  //   SEND-2: second approval, counter=2, still below threshold (3) — no canary
  //   SEND-3: third approval reaches threshold — canary send fires
  //   SEND-4: pending guard blocks re-trigger while canary outstanding
  //   SEND-5: captured canary request uses cc:canary: callback shape + 🔷 prefix

  const SEND_SESSION_ID  = 'send-test-session-001';
  const SEND_HUMAN_ID    = 'test-mcp-send-001';
  const SEND_GATE_PORT   = 3105;
  const SEND_TG_PORT     = 8766;
  const SEND_HMAC_SECRET = 'test-send-hmac-secret-01';

  const SEND_CANARY_DIR   = join(TEST_SCRATCH, 'var', 'canary-send');
  const SEND_MCP_INBOX    = join(TEST_SCRATCH, 'inbox', 'mcp-send');
  const SEND_HMAC_FILE    = join(TEST_SCRATCH, 'send-inbox-hmac-secret');
  const SEND_HUMAN_DIR    = join(TEST_SCRATCH, 'var', 'human-state-send');

  mkdirSync(SEND_CANARY_DIR,  { recursive: true });
  mkdirSync(SEND_MCP_INBOX,   { recursive: true });
  mkdirSync(SEND_HUMAN_DIR,   { recursive: true });
  writeFileSync(SEND_HMAC_FILE, SEND_HMAC_SECRET);

  // Minimal human state for SEND gate. Fast lane keeps H17 floor at 500ms
  // absoluteFloor so the ~1.1s approval cycle clears it reliably.
  writeFileSync(join(SEND_HUMAN_DIR, `${SEND_HUMAN_ID}.json`), JSON.stringify({
    human_id: SEND_HUMAN_ID, date: new Date().toISOString().slice(0, 10),
    decisions_today: 0, response_times: [], pending: [],
    last_ask_epoch: 0, last_ask_epoch_ms: 0,
    canary_tier: 0, canary_trip_count: 0,
    timing_observations: [], operator_profile_level: 0, trust_lane: 'fast',
  }));

  // Signed test policy with an ask rule matching 'test_ask_tool'.
  // R001_ASK fires before R095_ALLOW so test_ask_tool always reaches telegramAsk.
  const TEST_ASK_POLICY_FILE = join(TEST_SCRATCH, 'test-ask-policy.json');
  const TEST_ASK_POLICY_OBJ = {
    version: 'test-ask',
    default_action: 'deny',
    rules: [
      {
        id: 'R001_TEST_ASK',
        enabled: true,
        description: 'Test ask rule — fires for test_ask_tool',
        domain: 'mcp',
        action: 'ask',
        severity: 'critical',
        match: { domain: 'mcp', detail: { tool_name: { eq: 'test_ask_tool' } } },
        risk_score: { irreversibility: 50, consequence: 50, blast_radius: 50 },
      },
      {
        id: 'R095_TEST_ALLOW',
        enabled: true,
        description: 'Allow other tools in test',
        domain: 'mcp',
        action: 'allow',
        severity: 'info',
        match: { domain: 'mcp' },
        risk_score: { irreversibility: 0, consequence: 0, blast_radius: 0 },
      },
      {
        id: 'R999_PC02',
        enabled: true,
        description: 'PC-02 placeholder',
        domain: 'test_never_matches',
        action: 'ask',
        severity: 'info',
        match: { domain: 'test_never_matches', detail: { tool_name: { eq: '__never__' } } },
        risk_score: { irreversibility: 0, consequence: 0, blast_radius: 0 },
      },
    ],
  };
  writeFileSync(TEST_ASK_POLICY_FILE, JSON.stringify(signPolicyUnderSpec(TEST_ASK_POLICY_OBJ)));

  // Mock Telegram HTTP server. For MCP asks it auto-injects an approval into
  // SEND_MCP_INBOX so telegramAsk returns 'allow' without blocking.
  // For canary sends it captures the request body for shape assertion.
  let lastCanarySendBody = null;
  const { createServer: createHttpServer } = await import('http');
  const mockTgServer = await new Promise((resolve) => {
    const srv = createHttpServer((req, res) => {
      let body = '';
      req.on('data', d => { body += d; });
      req.on('end', () => {
        let parsed = {};
        try { parsed = JSON.parse(body); } catch {}
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, result: { message_id: 42 } }));
        const buttons = parsed?.reply_markup?.inline_keyboard?.[0] || [];
        const isCanary = buttons.some(b => typeof b.callback_data === 'string' && b.callback_data.startsWith('cc:canary:'));
        const isMcpAsk = buttons.some(b => typeof b.callback_data === 'string' && b.callback_data.startsWith('mcp:approve:'));
        if (isMcpAsk) {
          const actionId = buttons.find(b => b.callback_data.startsWith('mcp:approve:'))
                                   .callback_data.replace('mcp:approve:', '');
          const data = `mcp:approve:${actionId}`;
          const from = SEND_HUMAN_ID;
          const cbId = `cb-${actionId}`;
          const hmac = createHmac('sha256', SEND_HMAC_SECRET).update(`${data}|${from}|${cbId}`).digest('base64');
          // Delay 600ms so the gate's polling cycle picks up the approval after
          // at least one 1000ms sleep — keeps elapsed > 500ms (fast lane H17 floor).
          setTimeout(() => {
            writeFileSync(join(SEND_MCP_INBOX, `${actionId}.json`),
              JSON.stringify({ data, from_id: from, callback_query_id: cbId, hmac }));
          }, 600);
        } else if (isCanary) {
          lastCanarySendBody = parsed;
        }
      });
    });
    srv.listen(SEND_TG_PORT, '127.0.0.1', () => resolve(srv));
  });

  // Spawn SEND gate with mock Telegram API and 3-approval threshold
  const sendGate = spawn('node', [
    join(__dirname, 'gate.mjs'),
    '--port', String(SEND_GATE_PORT),
    '--upstream', `localhost:${MOCK_PORT}`,
    '--audit-file', TEST_AUDIT,
    '--policy-file', TEST_ASK_POLICY_FILE,
    '--policy-pubkey', TEST_POLICY_PUBKEY,
    '--manifest-file', TEST_MANIFEST_FILE,
    '--constitution-presence-file', TEST_CONSTITUTION_PRESENCE,
    '--restore-config-file', TEST_RESTORE_CONFIG,
    '--telegram-chat-id', SEND_HUMAN_ID,
    '--session-id', SEND_SESSION_ID,
    '--canary-state-dir', SEND_CANARY_DIR,
    '--cc-inbox-dir', join(TEST_SCRATCH, 'inbox', 'cc-send'),
    '--agent-id', 'test-send-agent',
  ], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      ZLAR_TELEGRAM_TOKEN: 'fake-test-token',
      ZLAR_TELEGRAM_API_BASE: `http://127.0.0.1:${SEND_TG_PORT}`,
      ZLAR_MCP_INBOX_DIR: SEND_MCP_INBOX,
      ZLAR_CANARY_MIN_APPROVALS: '3',
      ZLAR_CANARY_PROBABILITY: '100',
      ZLAR_CANARY_COOLDOWN: '0',
      ZLAR_CANARY_ENABLED: 'true',
      ZLAR_HUMAN_STATE_DIR: SEND_HUMAN_DIR,
      ZLAR_HUMAN_STATE_HMAC_KEY_FILE: join(TEST_SCRATCH, 'no-hmac-key'),
      ZLAR_INBOX_HMAC_SECRET_FILE: SEND_HMAC_FILE,
    },
  });

  await new Promise((resolve) => {
    sendGate.stdout.on('data', (data) => { if (data.toString().includes('listening')) resolve(); });
    setTimeout(resolve, 2000);
  });
  console.log(`✓ SEND test gate on port ${SEND_GATE_PORT}\n`);

  const sendSEND = (msg) => sendMessage(SEND_GATE_PORT, msg);
  let sendMsgId = 400;

  // v3.3.6: trigger eligibility lives in per-human state, not per-session.
  // The .pending file in var/canary/{session}.canary.pending stays as a routing
  // artifact for the inbox handler; authoritative state is the human-state file.
  const readSendState = () => {
    try { return JSON.parse(readFileSync(join(SEND_HUMAN_DIR, `${SEND_HUMAN_ID}.json`), 'utf8')); }
    catch { return null; }
  };
  const sendPendingExists = () => existsSync(join(SEND_CANARY_DIR, `${SEND_SESSION_ID}.canary.pending`));

  // SEND-1: first human approval creates per-human counter=1
  lastCanarySendBody = null;
  try {
    await sendSEND({ jsonrpc: '2.0', id: ++sendMsgId, method: 'tools/call',
                     params: { name: 'test_ask_tool', arguments: {} } });
    await new Promise(r => setTimeout(r, 300)); // allow async sendCanary to settle
    const st = readSendState();
    if (st && st.canary_approvals_since_last === 1) {
      console.log('✓ SEND-1: first approval creates state, per-human counter=1'); passed++;
    } else {
      console.log(`✗ SEND-1: expected canary_approvals_since_last=1, got ${st?.canary_approvals_since_last}`); failed++;
    }
  } catch (e) { console.log(`✗ SEND-1: ${e.message}`); failed++; }

  // SEND-2: second approval, counter=2, below threshold — no canary sent
  lastCanarySendBody = null;
  try {
    await sendSEND({ jsonrpc: '2.0', id: ++sendMsgId, method: 'tools/call',
                     params: { name: 'test_ask_tool', arguments: {} } });
    await new Promise(r => setTimeout(r, 300));
    const st = readSendState();
    if (st && st.canary_approvals_since_last === 2 && !sendPendingExists()) {
      console.log('✓ SEND-2: counter=2, below threshold — no canary sent'); passed++;
    } else {
      console.log(`✗ SEND-2: counter=${st?.canary_approvals_since_last}, pending=${sendPendingExists()}`); failed++;
    }
  } catch (e) { console.log(`✗ SEND-2: ${e.message}`); failed++; }

  // SEND-3: third approval reaches threshold — canary fires;
  // human-state pending fields are populated; routing artifact is written.
  lastCanarySendBody = null;
  try {
    await sendSEND({ jsonrpc: '2.0', id: ++sendMsgId, method: 'tools/call',
                     params: { name: 'test_ask_tool', arguments: {} } });
    await new Promise(r => setTimeout(r, 500)); // allow async sendCanary write
    const st = readSendState();
    const humanPendingSet = !!(st && st.canary_pending_id && st.canary_pending_session_id === SEND_SESSION_ID);
    if (sendPendingExists() && lastCanarySendBody !== null && humanPendingSet) {
      console.log('✓ SEND-3: threshold reached — canary sent, .pending written, per-human pending set'); passed++;
    } else {
      console.log(`✗ SEND-3: pending=${sendPendingExists()}, canaryBody=${lastCanarySendBody !== null}, humanPendingSet=${humanPendingSet}`); failed++;
    }
  } catch (e) { console.log(`✗ SEND-3: ${e.message}`); failed++; }

  // SEND-4: per-human pending lock blocks re-trigger.
  // v3.3.6: the lock fires on canary_pending_id != "" — counter value is
  // irrelevant once a canary is outstanding, so we don't need to seed state.
  const capturedCanaryBody = lastCanarySendBody;
  lastCanarySendBody = null;
  try {
    await sendSEND({ jsonrpc: '2.0', id: ++sendMsgId, method: 'tools/call',
                     params: { name: 'test_ask_tool', arguments: {} } });
    await new Promise(r => setTimeout(r, 300));
    if (lastCanarySendBody === null) {
      console.log('✓ SEND-4: per-human pending lock blocks re-trigger'); passed++;
    } else {
      console.log('✗ SEND-4: sendCanary fired despite per-human pending lock'); failed++;
    }
  } catch (e) { console.log(`✗ SEND-4: ${e.message}`); failed++; }

  // SEND-5: captured canary request uses cc:canary: callback shape + 🔷 prefix
  try {
    if (!capturedCanaryBody) throw new Error('no canary body captured (SEND-3 may have failed)');
    const buttons = capturedCanaryBody?.reply_markup?.inline_keyboard?.[0] || [];
    const approveData = buttons.find(b => b.text?.includes('Approve'))?.callback_data || '';
    const denyData    = buttons.find(b => b.text?.includes('Deny'))?.callback_data    || '';
    const textOk = (capturedCanaryBody.text || '').includes('🔷');
    const approveOk = approveData.startsWith('cc:canary:approve:');
    const denyOk    = denyData.startsWith('cc:canary:deny:');
    if (textOk && approveOk && denyOk) {
      console.log('✓ SEND-5: canary card uses cc:canary: callbacks + 🔷 prefix'); passed++;
    } else {
      console.log(`✗ SEND-5: text🔷=${textOk} approve=${approveOk} deny=${denyOk}`); failed++;
    }
  } catch (e) { console.log(`✗ SEND-5: ${e.message}`); failed++; }

  sendGate.kill();
  mockTgServer.close();
  console.log('');

  // ─── Verify Audit Trail ────────────────────────────────────────────────

  console.log('\n--- Audit Trail ---');

  if (existsSync(TEST_AUDIT)) {
    const lines = readFileSync(TEST_AUDIT, 'utf8').trim().split('\n');
    console.log(`${lines.length} audit entries written`);

    for (const line of lines) {
      try {
        const entry = JSON.parse(line);
        const hasPQC = entry.signature_algorithm && entry.hash_algorithm && entry.public_key_id;
        const hasChain = entry.prev_hash;
        const hasAuth = entry.authorizer;
        console.log(`  ${entry.ts} | ${entry.action.substring(0, 30).padEnd(30)} | ${entry.outcome.padEnd(10)} | PQC:${hasPQC ? '✓' : '✗'} chain:${hasChain ? '✓' : '✗'} auth:${hasAuth ? '✓' : '✗'}`);
      } catch {}
    }
  }

  // ─── Summary ───────────────────────────────────────────────────────────

  console.log(`\n${passed} passed, ${failed} failed out of ${passed + failed} tests`);

  // Cleanup
  gate.kill();
  mockServer.close();
  if (existsSync(TEST_AUDIT)) unlinkSync(TEST_AUDIT);
  if (existsSync(TEST_ALLOW_POLICY)) unlinkSync(TEST_ALLOW_POLICY);
  if (existsSync(TEST_POLICY_PUBKEY)) unlinkSync(TEST_POLICY_PUBKEY);

  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((e) => {
  console.error(e);
  process.exit(1);
});
