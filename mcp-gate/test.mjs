#!/usr/bin/env node
// ZLAR MCP Gate — Test Harness
//
// Simulates MCP JSON-RPC messages and verifies the gate evaluates them
// correctly against policy. No real MCP server needed.

import { createServer, createConnection } from 'net';
import { readFileSync, existsSync, unlinkSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_DIR = join(__dirname, '..');
const TEST_AUDIT = join(__dirname, 'test-audit.jsonl');

// Clean up test audit file
if (existsSync(TEST_AUDIT)) unlinkSync(TEST_AUDIT);

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
    server.listen(port, () => resolve(server));
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
  // Create a minimal test policy that denies MCP tools/call
  const denyPolicyPath = join(__dirname, 'test-deny-policy.json');
  writeFileSync(denyPolicyPath, JSON.stringify({
    version: 'test-deny',
    default_action: 'deny',
    rules: [{
      id: 'T001',
      enabled: true,
      description: 'Deny all MCP tool calls',
      domain: 'mcp',
      action: 'deny',
      severity: 'critical',
      match: { domain: 'mcp' },
      risk_score: { irreversibility: 100, consequence: 100, blast_radius: 100 },
    }],
  }));

  // Start a second gate with deny policy
  const DENY_GATE_PORT = 3102;
  const denyGate = spawn('node', [
    join(__dirname, 'gate.mjs'),
    '--port', String(DENY_GATE_PORT),
    '--upstream', `localhost:${MOCK_PORT}`,
    '--audit-file', TEST_AUDIT,
    '--policy-file', denyPolicyPath,
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

  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((e) => {
  console.error(e);
  process.exit(1);
});
