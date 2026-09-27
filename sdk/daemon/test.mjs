#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR SDK Gate Daemon — Test Suite
//
// Tests policy evaluation, tool translation, and socket protocol in isolation.
// Does NOT require a running daemon or live policy file.
//
// Run: node test.mjs
// ═══════════════════════════════════════════════════════════════════════════════

import { createConnection } from 'net';
import { createHash, randomBytes } from 'crypto';
import { existsSync, mkdirSync, writeFileSync, unlinkSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { homedir } from 'os';
import { fileURLToPath } from 'url';
import { spawnSync } from 'child_process';

const __filename  = fileURLToPath(import.meta.url);
const __dirname   = dirname(__filename);

// ─── Test Harness ─────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures = [];

function assert(condition, name, detail = '') {
  if (condition) {
    console.log(`  ✓ ${name}`);
    passed++;
  } else {
    console.error(`  ✗ ${name}${detail ? ': ' + detail : ''}`);
    failed++;
    failures.push({ name, detail });
  }
}

function section(title) {
  console.log(`\n── ${title} ──`);
}

// ─── Import daemon internals for unit testing ─────────────────────────────────
// We import the functions directly by reconstructing them here.
// This avoids needing to export from daemon.mjs (it's a CLI tool, not a library).
// The policy logic is deterministic and testable without side effects.

// Replicate translateTool for unit tests
const INTERNAL_TOOLS = new Set([
  'TodoWrite','TaskOutput','TaskStop','Skill','EnterPlanMode','ExitPlanMode',
  'AskUserQuestion','EnterWorktree','ExitWorktree','CronCreate','CronDelete',
  'CronList','RemoteTrigger',
]);

function sanitizePath(p) {
  if (!p || typeof p !== 'string') return '';
  return p.replace(/\0/g, '').replace(/\/+/g, '/');
}

function translateTool(toolName, toolInput) {
  if (INTERNAL_TOOLS.has(toolName)) return { domain: 'internal', detail: { tool: toolName }, display: toolName };
  if (toolName.startsWith('mcp__')) {
    const parts = toolName.split('__');
    return { domain: 'mcp', detail: { server: parts[1]||'', tool: parts.slice(2).join('__')||'', args: toolInput||{} }, display: `${parts[1]}/${parts.slice(2).join('__')}` };
  }
  switch (toolName) {
    case 'Bash': { const cmd = (toolInput?.command||'').replace(/[\n\r]/g,' '); return { domain:'bash', detail:{ command:cmd, cwd:toolInput?.cwd||'' }, display:cmd.slice(0,200) }; }
    case 'Write': { const path=sanitizePath(toolInput?.file_path||''); const h=createHash('sha256').update(toolInput?.content||'').digest('hex'); return { domain:'write', detail:{path,content_length:(toolInput?.content||'').length,content_sha256:h}, display:path.slice(0,200) }; }
    case 'Edit': { const path=sanitizePath(toolInput?.file_path||''); return { domain:'edit', detail:{path,old_string:(toolInput?.old_string||'').slice(0,80),new_string:(toolInput?.new_string||'').slice(0,80)}, display:path.slice(0,200) }; }
    case 'Read': { const path=sanitizePath(toolInput?.file_path||''); return { domain:'read', detail:{path}, display:path.slice(0,200) }; }
    case 'Glob': return { domain:'glob', detail:{pattern:toolInput?.pattern||'',path:toolInput?.path||''}, display:toolInput?.pattern||'' };
    case 'Grep': return { domain:'grep', detail:{pattern:toolInput?.pattern||'',path:toolInput?.path||''}, display:toolInput?.pattern||'' };
    case 'NotebookEdit': { const path=sanitizePath(toolInput?.notebook_path||''); return { domain:'notebook', detail:{path}, display:path.slice(0,200) }; }
    case 'Task': case 'Agent': return { domain:'agent', detail:{prompt:(toolInput?.prompt||toolInput?.description||'subagent').slice(0,200)}, display:'Sub-agent' };
    case 'WebFetch': return { domain:'webfetch', detail:{url:toolInput?.url||''}, display:(toolInput?.url||'').slice(0,200) };
    case 'WebSearch': return { domain:'websearch', detail:{query:toolInput?.query||''}, display:(toolInput?.query||'').slice(0,200) };
    default: return { domain:'unknown', detail:{tool:toolName}, display:toolName };
  }
}

function matchDetailField(value, matcher) {
  if (!matcher || typeof matcher !== 'object') return false;
  const s = String(value ?? '');
  if ('regex'     in matcher) { try { return new RegExp(matcher.regex).test(s); } catch { return false; } }
  if ('contains'  in matcher) return s.includes(String(matcher.contains));
  if ('prefix'    in matcher) return s.startsWith(String(matcher.prefix));
  if ('eq'        in matcher) return s === String(matcher.eq);
  if ('not_regex' in matcher) { try { return !new RegExp(matcher.not_regex).test(s); } catch { return true; } }
  return false;
}

function evaluatePolicy(policy, domain, detail) {
  if (!policy?.rules) return { rule:'no-policy', action:'deny', severity:'critical', riskScore:100 };
  for (const rule of policy.rules) {
    if (!rule.enabled) continue;
    if (rule.domain && rule.domain !== domain) continue;
    const match = rule.match || {};
    if (match.domain === domain && !match.detail) return buildMatch(rule);
    if (!match.detail) continue;
    let allMatched = true;
    for (const [field, matcher] of Object.entries(match.detail)) {
      if (!matchDetailField(String(detail[field] ?? ''), matcher)) { allMatched = false; break; }
    }
    if (!allMatched) continue;
    if (match.compound_guard) {
      let guardPassed = true;
      for (const [field, matcher] of Object.entries(match.compound_guard)) {
        if (!matchDetailField(String(detail[field] ?? ''), matcher)) { guardPassed = false; break; }
      }
      if (!guardPassed) continue;
    }
    return buildMatch(rule);
  }
  return { rule:'default', action:policy.default_action||'deny', severity:'warn', riskScore:0 };
}

function buildMatch(rule) {
  const rs = rule.risk_score || {};
  return { rule:rule.id||'unknown', action:rule.action||'deny', severity:rule.severity||'info',
           riskScore:Math.max(rs.irreversibility||0,rs.consequence||0,rs.blast_radius||0),
           audit:rule.audit!==false, description:rule.description||'' };
}

function sortedJSON(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(sortedJSON).join(',') + ']';
  return '{' + Object.keys(obj).sort().map(k => `${JSON.stringify(k)}:${sortedJSON(obj[k])}`).join(',') + '}';
}

// ─── Test: Tool Translation ───────────────────────────────────────────────────

section('Tool Translation');

{
  const r = translateTool('Bash', { command: 'ls /tmp', cwd: '/home' });
  assert(r.domain === 'bash', 'Bash → domain=bash');
  assert(r.detail.command === 'ls /tmp', 'Bash → command preserved');
  assert(r.detail.cwd === '/home', 'Bash → cwd preserved');
}

{
  const r = translateTool('Bash', { command: 'echo foo\nbar' });
  assert(r.detail.command === 'echo foo bar', 'Bash → newline stripped (injection fix S1)');
}

{
  const r = translateTool('Write', { file_path: '/tmp/test.txt', content: 'hello' });
  assert(r.domain === 'write', 'Write → domain=write');
  assert(r.detail.path === '/tmp/test.txt', 'Write → path');
  assert(r.detail.content_length === 5, 'Write → content_length');
  assert(typeof r.detail.content_sha256 === 'string' && r.detail.content_sha256.length === 64, 'Write → content_sha256');
}

{
  const r = translateTool('Edit', { file_path: '/src/foo.py', old_string: 'old', new_string: 'new' });
  assert(r.domain === 'edit', 'Edit → domain=edit');
  assert(r.detail.old_string === 'old' && r.detail.new_string === 'new', 'Edit → old/new strings');
}

{
  const r = translateTool('Read', { file_path: '/etc/hosts' });
  assert(r.domain === 'read' && r.detail.path === '/etc/hosts', 'Read → domain=read, path');
}

{
  const r = translateTool('TodoWrite', {});
  assert(r.domain === 'internal', 'TodoWrite → domain=internal (fast path)');
}

{
  const r = translateTool('AskUserQuestion', {});
  assert(r.domain === 'internal', 'AskUserQuestion → domain=internal');
}

{
  const r = translateTool('mcp__github__create_issue', { title: 'Bug' });
  assert(r.domain === 'mcp', 'MCP tool → domain=mcp');
  assert(r.detail.server === 'github', 'MCP tool → server=github');
  assert(r.detail.tool === 'create_issue', 'MCP tool → tool=create_issue');
}

{
  const r = translateTool('WebSearch', { query: 'ZLAR governance' });
  assert(r.domain === 'websearch' && r.detail.query === 'ZLAR governance', 'WebSearch → domain=websearch');
}

{
  // Path sanitization: null bytes stripped
  const r = translateTool('Read', { file_path: '/etc/\0passwd' });
  assert(!r.detail.path.includes('\0'), 'Read → null byte stripped from path');
}

{
  // Unknown tool → unknown domain
  const r = translateTool('QuantumTeleport', {});
  assert(r.domain === 'unknown', 'Unknown tool → domain=unknown');
}

// ─── Test: Detail Field Matching ──────────────────────────────────────────────

section('Detail Field Matching');

assert(matchDetailField('git push origin main', { regex: '\\bgit\\s+push\\b' }), 'regex: git push matches');
assert(!matchDetailField('git status', { regex: '\\bgit\\s+push\\b' }), 'regex: git status does not match push');
assert(matchDetailField('rm -rf /tmp', { contains: 'rm' }), 'contains: rm found');
assert(!matchDetailField('ls /tmp', { contains: 'rm' }), 'contains: rm not in ls');
assert(matchDetailField('/home/user/file.txt', { prefix: '/home' }), 'prefix: /home matches');
assert(!matchDetailField('/tmp/file.txt', { prefix: '/home' }), 'prefix: /tmp does not match /home');
assert(matchDetailField('bash', { eq: 'bash' }), 'eq: exact match');
assert(!matchDetailField('bash2', { eq: 'bash' }), 'eq: no partial match');
assert(matchDetailField('ls /tmp', { not_regex: '[;|&]' }), 'not_regex: no shell operators');
assert(!matchDetailField('ls /tmp | wc', { not_regex: '[;|&]' }), 'not_regex: pipe detected');

// Invalid regex → false (safe default)
assert(!matchDetailField('anything', { regex: '[invalid' }), 'invalid regex → false (safe)');

// ─── Test: Policy Evaluation ─────────────────────────────────────────────────

section('Policy Evaluation');

// Minimal test policy matching the live policy's structure
const TEST_POLICY = {
  version:        'test-1.0',
  default_action: 'deny',
  rules: [
    {
      id: 'T001', enabled: true, description: 'Safe reads', domain: 'bash',
      action: 'allow', severity: 'info', audit: true,
      match: {
        detail: { command: { regex: '^\\s*(ls|pwd|git\\s+status)\\b' } },
        compound_guard: { command: { not_regex: '[;|&`>]' } },
      },
      risk_score: { irreversibility: 5, consequence: 5, blast_radius: 5 },
    },
    {
      id: 'T002', enabled: true, description: 'Destructive delete', domain: 'bash',
      action: 'deny', severity: 'critical', audit: true,
      match: { detail: { command: { regex: '\\brm\\s+.*(-rf|-fr)' } } },
      risk_score: { irreversibility: 100, consequence: 100, blast_radius: 95 },
    },
    {
      id: 'T003', enabled: true, description: 'Git push', domain: 'bash',
      action: 'ask', severity: 'warn', audit: true,
      match: { detail: { command: { regex: '\\bgit\\s+push\\b' } } },
      risk_score: { irreversibility: 60, consequence: 60, blast_radius: 40 },
    },
    {
      id: 'T004', enabled: false, description: 'Disabled rule', domain: 'bash',
      action: 'deny', severity: 'critical', audit: true,
      match: { detail: { command: { regex: '.*' } } },
      risk_score: {},
    },
  ],
};

{
  const r = evaluatePolicy(TEST_POLICY, 'bash', { command: 'ls /tmp', cwd: '' });
  assert(r.rule === 'T001' && r.action === 'allow', 'ls → T001 allow');
}

{
  const r = evaluatePolicy(TEST_POLICY, 'bash', { command: 'git status', cwd: '' });
  assert(r.rule === 'T001' && r.action === 'allow', 'git status → T001 allow');
}

{
  // Compound guard: ls with pipe → guard fails → T001 doesn't match → default deny
  const r = evaluatePolicy(TEST_POLICY, 'bash', { command: 'ls /tmp | wc -l', cwd: '' });
  assert(r.action === 'deny', 'ls with pipe → compound guard fails → deny');
  assert(r.rule !== 'T001', 'ls with pipe → T001 not matched');
}

{
  const r = evaluatePolicy(TEST_POLICY, 'bash', { command: 'rm -rf /important', cwd: '' });
  assert(r.rule === 'T002' && r.action === 'deny', 'rm -rf → T002 deny');
  assert(r.riskScore === 100, 'rm -rf → risk_score 100');
}

{
  const r = evaluatePolicy(TEST_POLICY, 'bash', { command: 'git push origin main', cwd: '' });
  assert(r.rule === 'T003' && r.action === 'ask', 'git push → T003 ask');
}

{
  // T004 is disabled — should not match despite catching everything
  const r = evaluatePolicy(TEST_POLICY, 'bash', { command: 'npm install lodash', cwd: '' });
  assert(r.rule === 'default' && r.action === 'deny', 'disabled rule skipped → default deny');
}

{
  // Different domain — bash rules don't match read domain
  const r = evaluatePolicy(TEST_POLICY, 'read', { path: '/etc/hosts' });
  assert(r.rule === 'default', 'read domain → no bash rules match → default');
}

{
  // No policy → deny
  const r = evaluatePolicy(null, 'bash', { command: 'ls' });
  assert(r.action === 'deny' && r.rule === 'no-policy', 'null policy → no-policy deny');
}

// ─── Test: Approval Binding Hash ──────────────────────────────────────────────

section('Approval Binding Hash');

{
  // Same inputs → same hash (deterministic)
  const h1 = createHash('sha256').update(`R014|Bash|${sortedJSON({ command: 'git push origin main', cwd: '' })}`).digest('hex');
  const h2 = createHash('sha256').update(`R014|Bash|${sortedJSON({ command: 'git push origin main', cwd: '' })}`).digest('hex');
  assert(h1 === h2, 'Same inputs → same hash');
}

{
  // Different command → different hash
  const h1 = createHash('sha256').update(`R014|Bash|${sortedJSON({ command: 'git push origin main', cwd: '' })}`).digest('hex');
  const h2 = createHash('sha256').update(`R014|Bash|${sortedJSON({ command: 'git push origin dev', cwd: '' })}`).digest('hex');
  assert(h1 !== h2, 'Different command → different hash (approval binding)');
}

{
  // sortedJSON is key-order independent
  const a = sortedJSON({ b: 2, a: 1, c: 3 });
  const b = sortedJSON({ c: 3, a: 1, b: 2 });
  assert(a === b, 'sortedJSON: key order normalized');
  assert(a === '{"a":1,"b":2,"c":3}', 'sortedJSON: correct sorted output');
}

// ─── Test: JSON-RPC 2.0 Frame Protocol ───────────────────────────────────────

section('JSON-RPC 2.0 Frame Protocol');

{
  // Frame encoding: 4-byte big-endian length + UTF-8 JSON
  const payload = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'health' });
  const payloadBuf = Buffer.from(payload, 'utf8');
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(payloadBuf.length, 0);
  const frame = Buffer.concat([header, payloadBuf]);

  assert(frame.length === 4 + payloadBuf.length, 'Frame: correct total length');
  assert(frame.readUInt32BE(0) === payloadBuf.length, 'Frame: header encodes payload length');

  const decoded = JSON.parse(frame.subarray(4).toString('utf8'));
  assert(decoded.method === 'health', 'Frame: payload round-trips correctly');
}

{
  // Multi-frame parsing simulation
  const msgs = [
    { jsonrpc: '2.0', id: 1, method: 'health' },
    { jsonrpc: '2.0', id: 2, method: 'evaluate', params: { tool_name: 'Read' } },
  ];
  const chunks = msgs.map(m => {
    const p = Buffer.from(JSON.stringify(m), 'utf8');
    const h = Buffer.allocUnsafe(4);
    h.writeUInt32BE(p.length, 0);
    return Buffer.concat([h, p]);
  });
  const combined = Buffer.concat(chunks);

  // Parse both frames from combined buffer
  const parsed = [];
  let buf = combined;
  while (buf.length >= 4) {
    const len = buf.readUInt32BE(0);
    if (buf.length < 4 + len) break;
    parsed.push(JSON.parse(buf.subarray(4, 4 + len).toString('utf8')));
    buf = buf.subarray(4 + len);
  }

  assert(parsed.length === 2, 'Multi-frame: both messages parsed from combined buffer');
  assert(parsed[0].id === 1 && parsed[1].id === 2, 'Multi-frame: IDs preserved in order');
}

// ─── Test: Socket Integration (if daemon is running) ─────────────────────────

section('Socket Integration (health check)');

async function testLiveSocket() {
  const socketPath = process.env.ZLAR_GATE_SOCKET
    || (process.env.XDG_RUNTIME_DIR ? join(process.env.XDG_RUNTIME_DIR, 'zlar/gate.sock') : null)
    || join(homedir(), '.zlar/gate.sock');

  if (!existsSync(socketPath)) {
    console.log(`  ⊘ Daemon not running (${socketPath}) — skipping live socket tests`);
    return;
  }

  await new Promise((resolve) => {
    const client = createConnection(socketPath, () => {
      // Send health request
      const payload = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 42, method: 'health' }), 'utf8');
      const header  = Buffer.allocUnsafe(4);
      header.writeUInt32BE(payload.length, 0);
      client.write(Buffer.concat([header, payload]));
    });

    let buf = Buffer.alloc(0);
    client.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length >= 4) {
        const len = buf.readUInt32BE(0);
        if (buf.length >= 4 + len) {
          const msg = JSON.parse(buf.subarray(4, 4 + len).toString('utf8'));
          assert(msg.jsonrpc === '2.0', 'Live: health response is JSON-RPC 2.0');
          assert(msg.id === 42, 'Live: response ID matches request ID');
          assert(msg.result?.status === 'ok', 'Live: daemon health status=ok');
          assert(typeof msg.result?.policy_version === 'string', 'Live: policy_version present');
          client.destroy();
          resolve();
        }
      }
    });

    client.on('error', (e) => {
      console.log(`  ⊘ Live socket test error: ${e.message}`);
      resolve();
    });

    setTimeout(() => { client.destroy(); resolve(); }, 3000);
  });
}

await testLiveSocket();

// ─── Test: Policy Signature Verification Format ───────────────────────────────

section('Policy Signature Format');

{
  // Check that jq is available (required for signature verification)
  const r = spawnSync('jq', ['--version'], { encoding: 'utf8' });
  assert(r.status === 0, 'jq available (required for policy sig verification)');
}

{
  // Verify the live policy file has a signature field
  const PROJECT_DIR = join(__dirname, '../..');
  const policyPath  = join(PROJECT_DIR, 'etc/policies/active.policy.json');
  if (existsSync(policyPath)) {
    const p = JSON.parse(readFileSync(policyPath, 'utf8'));
    assert(typeof p.signature?.value === 'string' && p.signature.value.length > 0,
      'Live policy: signature.value present');
    assert(typeof p.signature?.algorithm === 'string', 'Live policy: signature.algorithm present');
    assert(Array.isArray(p.rules) && p.rules.length > 0, `Live policy: ${p.rules.length} rules loaded`);
  } else {
    console.log('  ⊘ No live policy file — skipping policy signature format tests');
  }
}

// ─── Summary ──────────────────────────────────────────────────────────────────

console.log(`\n${'─'.repeat(50)}`);
console.log(`${passed} passed, ${failed} failed out of ${passed + failed} tests`);

if (failures.length > 0) {
  console.error('\nFailed tests:');
  failures.forEach(f => console.error(`  ✗ ${f.name}${f.detail ? ': ' + f.detail : ''}`));
}

process.exit(failed > 0 ? 1 : 0);
