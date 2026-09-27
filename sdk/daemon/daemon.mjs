#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR SDK Gate Daemon v0.1.0
//
// Phase 2: Agents built inside governance — membrane, not wrapper.
//
// A persistent Unix domain socket server. SDK agents connect at instantiation.
// Governance is present from construction, not bolted on after.
//
// Same gate. Same signed policy. Same audit trail. Same Telegram routing.
// Different process model: daemon, not subprocess-per-call.
//
// Protocol : JSON-RPC 2.0 over 4-byte big-endian length-prefixed frames
// Discovery: ZLAR_GATE_SOCKET → $XDG_RUNTIME_DIR/zlar/gate.sock → ~/.zlar/gate.sock
// Security : Socket 0600 (owner-only), fail-closed on all error paths
//
// It cannot be persuaded because it does not reason.
// ═══════════════════════════════════════════════════════════════════════════════

import { createServer }                             from 'net';
import { readFileSync, appendFileSync, existsSync,
         mkdirSync, writeFileSync, unlinkSync,
         readdirSync, statSync, chmodSync }         from 'fs';
import { createHash, sign as cryptoSign, verify as cryptoVerify,
         createPublicKey, createPrivateKey,
         randomBytes }                              from 'crypto';
import { execSync, spawnSync }                      from 'child_process';
import { join, dirname }                            from 'path';
import { homedir }                                  from 'os';
import { fileURLToPath }                            from 'url';
import { tokenCanonical }                          from '../shared/token-canonical.mjs';

const __filename  = fileURLToPath(import.meta.url);
const __dirname   = dirname(__filename);
const PROJECT_DIR = join(__dirname, '../..');   // sdk/daemon/ → repo/

// ─── Version ─────────────────────────────────────────────────────────────────

const DAEMON_VERSION   = '0.1.0';
const PROTOCOL_VERSION = '1';

// ─── Configuration ───────────────────────────────────────────────────────────

function resolveSocketPath() {
  if (process.env.ZLAR_GATE_SOCKET) return process.env.ZLAR_GATE_SOCKET;
  const xdg = process.env.XDG_RUNTIME_DIR;
  if (xdg) return join(xdg, 'zlar/gate.sock');
  return join(homedir(), '.zlar/gate.sock');
}

function loadTelegramToken() {
  const tok = process.env.ZLAR_TELEGRAM_TOKEN || process.env.TELEGRAM_BOT_TOKEN;
  if (tok) return tok;
  const envFile = join(PROJECT_DIR, '.env');
  if (!existsSync(envFile)) return null;
  try {
    for (const line of readFileSync(envFile, 'utf8').split('\n')) {
      const m = line.match(/^(TELEGRAM_BOT_TOKEN|ZLAR_TELEGRAM_TOKEN)=["']?([^"'\s]+)/);
      if (m) return m[2];
    }
  } catch {}
  return null;
}

function loadConfig() {
  const cfg = {
    policyFile:            join(PROJECT_DIR, 'etc/policies/active.policy.json'),
    policyPubkey:          join(PROJECT_DIR, 'etc/keys/policy-signing.pub'),
    auditFile:             join(PROJECT_DIR, 'var/log/audit.jsonl'),
    auditSigningKey:       join(homedir(), '.zlar-signing.key'),
    approvalDir:           join(PROJECT_DIR, 'var/log/approvals'),
    standingApprovalsFile: join(PROJECT_DIR, 'etc/standing-approvals.json'),
    telegramToken:         null,
    telegramChatId:        null,
    telegramTimeoutS:      300,
    telegramInboxDir:      '/var/run/zlar-tg/inbox/cc',  // override via gate.json telegram.inbox_dir
    requireSignedAudit:    false,
    socketPath:            resolveSocketPath(),
    logFile:               join(PROJECT_DIR, 'var/log/gate.log'),
  };

  const gateConfigPath = join(PROJECT_DIR, 'etc/gate.json');
  if (existsSync(gateConfigPath)) {
    try {
      const gc = JSON.parse(readFileSync(gateConfigPath, 'utf8'));
      if (gc.telegram?.chat_id)       cfg.telegramChatId     = gc.telegram.chat_id;
      if (gc.telegram?.timeout_s)     cfg.telegramTimeoutS   = gc.telegram.timeout_s;
      if (gc.telegram?.inbox_dir)     cfg.telegramInboxDir   = gc.telegram.inbox_dir;
      if (gc.require_signed_audit)    cfg.requireSignedAudit = gc.require_signed_audit;
    } catch {}
  }

  cfg.telegramToken = loadTelegramToken();

  // CLI overrides
  for (let i = 2; i < process.argv.length; i++) {
    if (process.argv[i] === '--socket' && process.argv[i + 1]) cfg.socketPath = process.argv[++i];
    if (process.argv[i] === '--policy' && process.argv[i + 1]) cfg.policyFile = process.argv[++i];
  }

  return cfg;
}

// ─── Logging ──────────────────────────────────────────────────────────────────

let LOG_FILE = null;

function log(msg) {
  const ts   = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const line = `[${ts}] [sdk-daemon] ${msg}`;
  process.stderr.write(line + '\n');
  if (LOG_FILE) {
    try { appendFileSync(LOG_FILE, line + '\n'); } catch {}
  }
}

// ─── Policy Engine ────────────────────────────────────────────────────────────

let POLICY         = null;
let POLICY_VERSION = 'unknown';

function loadPolicy(cfg) {
  if (!existsSync(cfg.policyFile)) {
    log(`FATAL: Policy file not found: ${cfg.policyFile} — fail-closed`);
    return false;
  }

  let parsed;
  try {
    parsed = JSON.parse(readFileSync(cfg.policyFile, 'utf8'));
  } catch (e) {
    log(`FATAL: Policy parse error: ${e.message} — fail-closed`);
    return false;
  }

  if (!verifyPolicySignature(cfg, parsed)) {
    log('FATAL: Policy signature invalid — fail-closed');
    return false;
  }

  POLICY         = parsed;
  POLICY_VERSION = parsed.version || 'unknown';
  log(`Policy loaded: v${POLICY_VERSION}, default=${parsed.default_action}, rules=${parsed.rules?.length || 0}`);
  return true;
}

function verifyPolicySignature(cfg, parsed) {
  if (!existsSync(cfg.policyPubkey)) {
    log('FATAL: Policy public key not found — cannot verify signature');
    return false;
  }

  const sigValue = parsed?.signature?.value;
  if (!sigValue) {
    log('FATAL: Policy has no signature');
    return false;
  }

  try {
    const pubKey = createPublicKey(readFileSync(cfg.policyPubkey, 'utf8'));
    const sigBuf = Buffer.from(sigValue, 'base64');

    // Spec form (ADR-011): jq -S -c, no trailing newline — matches zlar-policy sign
    const rSpec = spawnSync('jq', ['-S', '-c', '.signature.value = ""', cfg.policyFile], { encoding: 'utf8' });
    if (rSpec.status === 0) {
      const canonSpec  = rSpec.stdout.replace(/\n$/, '');
      const sha256Spec = createHash('sha256').update(canonSpec).digest('hex');
      if (cryptoVerify(null, Buffer.from(sha256Spec), pubKey, sigBuf)) return true;
    }

    // Legacy fallback: pretty-printed with trailing newline — pre-ADR-011 signatures
    const rPretty = spawnSync('jq', ['.signature.value = ""', cfg.policyFile], { encoding: 'utf8' });
    if (rPretty.status !== 0) throw new Error(`jq exited ${rPretty.status}: ${rPretty.stderr}`);
    const sha256Pretty = createHash('sha256').update(rPretty.stdout).digest('hex');
    return cryptoVerify(null, Buffer.from(sha256Pretty), pubKey, sigBuf);
  } catch (e) {
    log(`Policy signature verification error: ${e.message}`);
    return false;
  }
}

// ─── Tool Translation (DETAIL Schema Contract) ────────────────────────────────
//
// Frozen schemas — identical to bash gate's translate_tool().
// Changing field names or types breaks approval binding hashes across gates.
//
// Bash:         { command, cwd }
// Write:        { path, content_length, content_sha256 }
// Edit:         { path, old_string, new_string }
// Read:         { path }
// Glob:         { pattern, path }
// Grep:         { pattern, path }
// NotebookEdit: { path }
// Agent/Task:   { prompt }
// WebFetch:     { url }
// WebSearch:    { query }
// MCP:          { server, tool, args }
// ─────────────────────────────────────────────────────────────────────────────

const INTERNAL_TOOLS = new Set([
  'TodoWrite', 'TaskOutput', 'TaskStop', 'Skill',
  'EnterPlanMode', 'ExitPlanMode', 'AskUserQuestion',
  'EnterWorktree', 'ExitWorktree', 'CronCreate', 'CronDelete',
  'CronList', 'RemoteTrigger',
]);

function sanitizePath(p) {
  if (!p || typeof p !== 'string') return '';
  return p.replace(/\0/g, '').replace(/\/+/g, '/');
}

function translateTool(toolName, toolInput) {
  if (INTERNAL_TOOLS.has(toolName)) {
    return { domain: 'internal', detail: { tool: toolName }, display: toolName };
  }

  if (toolName.startsWith('mcp__')) {
    const parts  = toolName.split('__');
    const server = parts[1] || 'unknown';
    const tool   = parts.slice(2).join('__') || 'unknown';
    return {
      domain:  'mcp',
      detail:  { server, tool, args: toolInput || {} },
      display: `${server}/${tool}`,
    };
  }

  switch (toolName) {
    case 'Bash': {
      // Newline injection fix — matches bash gate S1 fix
      const cmd = (toolInput?.command || '').replace(/[\n\r]/g, ' ');
      return {
        domain:  'bash',
        detail:  { command: cmd, cwd: toolInput?.cwd || '' },
        display: cmd.slice(0, 200),
      };
    }
    case 'Write': {
      const path        = sanitizePath(toolInput?.file_path || '');
      const contentHash = createHash('sha256').update(toolInput?.content || '').digest('hex');
      return {
        domain:  'write',
        detail:  { path, content_length: (toolInput?.content || '').length, content_sha256: contentHash },
        display: path.slice(0, 200),
      };
    }
    case 'Edit': {
      const path = sanitizePath(toolInput?.file_path || '');
      return {
        domain:  'edit',
        detail:  {
          path,
          old_string: (toolInput?.old_string || '').slice(0, 80),
          new_string: (toolInput?.new_string || '').slice(0, 80),
        },
        display: path.slice(0, 200),
      };
    }
    case 'Read': {
      const path = sanitizePath(toolInput?.file_path || '');
      return { domain: 'read', detail: { path }, display: path.slice(0, 200) };
    }
    case 'Glob':
      return {
        domain:  'glob',
        detail:  { pattern: toolInput?.pattern || '', path: toolInput?.path || '' },
        display: toolInput?.pattern || '',
      };
    case 'Grep':
      return {
        domain:  'grep',
        detail:  { pattern: toolInput?.pattern || '', path: toolInput?.path || '' },
        display: toolInput?.pattern || '',
      };
    case 'NotebookEdit': {
      const path = sanitizePath(toolInput?.notebook_path || '');
      return { domain: 'notebook', detail: { path }, display: path.slice(0, 200) };
    }
    case 'Task': case 'Agent':
      return {
        domain:  'agent',
        detail:  { prompt: (toolInput?.prompt || toolInput?.description || 'subagent').slice(0, 200) },
        display: 'Sub-agent',
      };
    case 'WebFetch':
      return {
        domain:  'webfetch',
        detail:  { url: toolInput?.url || '' },
        display: (toolInput?.url || '').slice(0, 200),
      };
    case 'WebSearch':
      return {
        domain:  'websearch',
        detail:  { query: toolInput?.query || '' },
        display: (toolInput?.query || '').slice(0, 200),
      };
    default:
      return { domain: 'unknown', detail: { tool: toolName }, display: toolName };
  }
}

// ─── Policy Evaluation ────────────────────────────────────────────────────────

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

function evaluatePolicy(domain, detail) {
  if (!POLICY?.rules) {
    return { rule: 'no-policy', action: 'deny', severity: 'critical',
             riskScore: 100, audit: true, description: 'No policy loaded' };
  }

  for (const rule of POLICY.rules) {
    if (!rule.enabled) continue;
    if (rule.domain && rule.domain !== domain) continue;

    const match = rule.match || {};

    // Domain-only catch-all (no detail matchers)
    if (match.domain === domain && !match.detail) {
      return buildMatch(rule);
    }

    if (!match.detail) continue;

    // All detail fields must match
    let allMatched = true;
    for (const [field, matcher] of Object.entries(match.detail)) {
      if (!matchDetailField(String(detail[field] ?? ''), matcher)) {
        allMatched = false;
        break;
      }
    }
    if (!allMatched) continue;

    // Compound guard — additional AND constraints (same detail fields, different matchers)
    if (match.compound_guard) {
      let guardPassed = true;
      for (const [field, matcher] of Object.entries(match.compound_guard)) {
        if (!matchDetailField(String(detail[field] ?? ''), matcher)) {
          guardPassed = false;
          break;
        }
      }
      if (!guardPassed) continue;
    }

    return buildMatch(rule);
  }

  return {
    rule:        'default',
    action:      POLICY.default_action || 'deny',
    severity:    'warn',
    riskScore:   0,
    audit:       true,
    description: 'No matching rule',
  };
}

function buildMatch(rule) {
  const rs = rule.risk_score || {};
  return {
    rule:        rule.id          || 'unknown',
    action:      rule.action      || 'deny',
    severity:    rule.severity    || 'info',
    riskScore:   Math.max(rs.irreversibility || 0, rs.consequence || 0, rs.blast_radius || 0),
    audit:       rule.audit !== false,
    description: rule.description || '',
  };
}

// ─── Audit Trail ──────────────────────────────────────────────────────────────

let SEQ           = 0;
let HOSTNAME      = 'unknown';
let USERNAME      = 'unknown';
let PUBLIC_KEY_ID = 'unknown';

function initAuditMeta(cfg) {
  try { HOSTNAME = execSync('hostname -s', { encoding: 'utf8' }).trim(); } catch {}
  try { USERNAME = execSync('whoami',      { encoding: 'utf8' }).trim(); } catch {}
  if (existsSync(cfg.policyPubkey)) {
    PUBLIC_KEY_ID = createHash('sha256')
      .update(readFileSync(cfg.policyPubkey))
      .digest('hex')
      .slice(0, 16);
  }
}

function genId() {
  return `${Math.floor(Date.now() / 1000).toString(16)}-${randomBytes(16).toString('hex')}`;
}

// Key-sorted compact JSON — matches `jq -S -c '.'` for audit signing
function sortedJSON(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(sortedJSON).join(',') + ']';
  return '{' + Object.keys(obj).sort()
    .map(k => `${JSON.stringify(k)}:${sortedJSON(obj[k])}`)
    .join(',') + '}';
}

function signAuditEntry(entry, cfg) {
  if (!existsSync(cfg.auditSigningKey)) return 'unsigned';
  try {
    const canonical = sortedJSON(entry);
    const hash      = createHash('sha256').update(canonical).digest();  // raw bytes, not hex string
    const privKey   = createPrivateKey(readFileSync(cfg.auditSigningKey));
    return cryptoSign(null, hash, privKey).toString('base64');
  } catch (e) {
    log(`WARN: Audit signing failed: ${e.message}`);
    return 'unsigned';
  }
}

function writeAuditEntry(cfg, { domain, action, outcome, detail, rule,
                                 severity, riskScore, authorizer, sessionId, agentId,
                                 chainDepth }) {
  SEQ++;
  const prevHash = computePrevHash(cfg);
  const entry = {
    id:                  genId(),
    ts:                  new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
    seq:                 SEQ,
    source:              'sdk-daemon',
    host:                HOSTNAME,
    user:                USERNAME,
    agent_id:            agentId   || 'sdk-agent',
    session_id:          sessionId || 'unknown',
    domain,
    action:              String(action).slice(0, 200),
    outcome,
    risk_score:          riskScore || 0,
    detail:              typeof detail === 'object' ? detail : {},
    rule:                rule || '',
    policy_version:      POLICY_VERSION,
    severity:            severity || 'info',
    prev_hash:           prevHash,
    authorizer:          authorizer || 'policy',
    ...(chainDepth != null ? { chain_depth: chainDepth } : {}),
    signature_algorithm: 'Ed25519',
    hash_algorithm:      'SHA-256',
    signature_encoding:  'raw',       // v2: signs raw SHA-256 bytes (32B), not hex string (64B)
    public_key_id:       PUBLIC_KEY_ID,
  };

  const signature  = signAuditEntry(entry, cfg);
  const finalEntry = { ...entry, signature };

  try {
    mkdirSync(dirname(cfg.auditFile), { recursive: true });
    appendFileSync(cfg.auditFile, JSON.stringify(finalEntry) + '\n');
  } catch (e) {
    log(`CRITICAL: Failed to write audit entry: ${e.message}`);
  }

  return finalEntry.id;
}

function computePrevHash(cfg) {
  if (!existsSync(cfg.auditFile)) return 'genesis';
  try {
    const content = readFileSync(cfg.auditFile, 'utf8').trim();
    const lines   = content.split('\n').filter(Boolean);
    if (lines.length === 0) return 'genesis';
    return createHash('sha256').update(lines[lines.length - 1]).digest('hex');
  } catch { return 'genesis'; }
}

// ─── Approval Binding Hash ────────────────────────────────────────────────────
// Matches bash gate: printf '%s|%s|%s' rule toolName "$(echo detail | jq -S -c '.')"
// Binds approval to exact (rule, toolName, detail) triple — not just rule.

function computeActionHash(rule, toolName, detail) {
  const canonicalDetail = sortedJSON(detail);
  return createHash('sha256')
    .update(`${rule}|${toolName}|${canonicalDetail}`)
    .digest('hex');
}

// ─── Standing Approvals ───────────────────────────────────────────────────────

function checkStandingApproval(cfg, rule, display) {
  if (!existsSync(cfg.standingApprovalsFile)) return null;
  try {
    const sa      = JSON.parse(readFileSync(cfg.standingApprovalsFile, 'utf8'));
    const entries = sa.approvals || sa.entries || [];
    const now     = Date.now();
    for (const entry of entries) {
      if (entry.rule !== rule)                                             continue;
      if (entry.expires_at && now > new Date(entry.expires_at).getTime()) continue;
      if (entry.pattern && display && !display.includes(entry.pattern))   continue;
      return entry.id || 'standing';
    }
  } catch {}
  return null;
}

// ─── Pending Approvals (deny-then-retry) ─────────────────────────────────────
// Mirrors bash gate's check_pending_approval / write_pending_approval.
// Pending file: var/log/approvals/<rule>-<sessionId>.pending
// Contains: actionId\nactionHash\n

function pendingFile(cfg, rule, sessionId) {
  return join(cfg.approvalDir, `${rule}-${sessionId}.pending`);
}

function checkPendingApproval(cfg, rule, actionHash, sessionId) {
  const pf = pendingFile(cfg, rule, sessionId);
  if (!existsSync(pf)) return 'none';

  try {
    const lines           = readFileSync(pf, 'utf8').split('\n');
    const pendingActionId = (lines[0] || '').trim();
    const pendingHash     = (lines[1] || '').trim();

    if (!pendingActionId) { unlinkSync(pf); return 'none'; }

    // Hash mismatch → different command → stale pending
    if (pendingHash && pendingHash !== actionHash) {
      log(`SECURITY: Action hash mismatch for ${rule} — stale pending cleared`);
      unlinkSync(pf);
      return 'none';
    }

    // Expiry check
    const ageMs = Date.now() - statSync(pf).mtimeMs;
    if (ageMs / 1000 > cfg.telegramTimeoutS + 30) {
      unlinkSync(pf);
      return 'none';
    }

    // Scan inbox
    const inboxDir = cfg.telegramInboxDir;
    try {
      for (const file of readdirSync(inboxDir).filter(f => f.endsWith('.json'))) {
        const fpath = join(inboxDir, file);
        try {
          const cb = JSON.parse(readFileSync(fpath, 'utf8'));
          if (String(cb.from_id || '') !== String(cfg.telegramChatId)) {
            unlinkSync(fpath); continue;
          }
          if (cb.data === `cc:approve:${pendingActionId}`) {
            unlinkSync(fpath); unlinkSync(pf);
            return 'approved';
          }
          if (cb.data === `cc:deny:${pendingActionId}`) {
            unlinkSync(fpath); unlinkSync(pf);
            return 'denied';
          }
        } catch { try { unlinkSync(fpath); } catch {} }
      }
    } catch {}

    return 'pending';
  } catch { return 'none'; }
}

function writePendingApproval(cfg, rule, actionId, actionHash, sessionId) {
  try {
    mkdirSync(cfg.approvalDir, { recursive: true });
    writeFileSync(pendingFile(cfg, rule, sessionId), `${actionId}\n${actionHash}\n`);
  } catch (e) {
    log(`WARN: Could not write pending approval: ${e.message}`);
  }
}

// ─── Telegram HITL ────────────────────────────────────────────────────────────

async function telegramApi(cfg, method, body) {
  if (!cfg.telegramToken) return null;
  try {
    const resp = await fetch(
      `https://api.telegram.org/bot${cfg.telegramToken}/${method}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
    );
    return await resp.json();
  } catch (e) {
    log(`Telegram API error (${method}): ${e.message}`);
    return null;
  }
}

// Escape MarkdownV2 special chars
function escMd(s) {
  return String(s)
    .replace(/[_[\]()~>#+=|{}.!\-]/g, '\\$&')
    .replace(/\*/g, '\\*')
    .replace(/`/g, '\\`');
}

// Blocking ask — daemon holds the connection open while the human decides.
// Node.js event loop continues serving other connections during the await.
async function telegramAsk(cfg, actionId, toolName, display, rule, riskScore, severity, sessionId) {
  if (!cfg.telegramToken || !cfg.telegramChatId) {
    log('No Telegram config — cannot ask human, denying');
    return 'error';
  }

  const emoji = severity === 'critical' ? '🔴' : severity === 'warn' ? '🟡' : '⚡';
  const text  = [
    `${emoji} 🖥️ *SDK Gate*`,
    '',
    `*Tool:* \`${escMd(toolName)}\``,
    `*Action:* \`${escMd(display.slice(0, 150))}\``,
    `*Risk:* ${riskScore}/100`,
    `*Rule:* \`${escMd(rule)}\``,
    `*Session:* \`${escMd(sessionId.slice(0, 8))}\``,
  ].join('\n');

  const result = await telegramApi(cfg, 'sendMessage', {
    chat_id:      cfg.telegramChatId,
    text,
    parse_mode:   'MarkdownV2',
    reply_markup: {
      inline_keyboard: [[
        { text: '✅ Approve', callback_data: `cc:approve:${actionId}` },
        { text: '❌ Deny',    callback_data: `cc:deny:${actionId}` },
      ]],
    },
  });

  const msgId = result?.result?.message_id;
  if (!msgId) {
    log(`Telegram send failed — denying`);
    return 'error';
  }

  log(`Telegram ask sent: msg_id=${msgId}, action_id=${actionId}`);

  // Poll inbox — non-blocking via event loop
  const inboxDir = '/var/run/zlar-tg/inbox/cc';
  const deadline = Date.now() + cfg.telegramTimeoutS * 1000;

  while (Date.now() < deadline) {
    try {
      for (const file of readdirSync(inboxDir).filter(f => f.endsWith('.json'))) {
        const fpath = join(inboxDir, file);
        try {
          const cb = JSON.parse(readFileSync(fpath, 'utf8'));
          if (String(cb.from_id || '') !== String(cfg.telegramChatId)) {
            unlinkSync(fpath); continue;
          }
          if (cb.data === `cc:approve:${actionId}`) {
            unlinkSync(fpath);
            log(`Telegram: APPROVED (session=${sessionId.slice(0, 8)})`);
            return 'allow';
          }
          if (cb.data === `cc:deny:${actionId}`) {
            unlinkSync(fpath);
            log(`Telegram: DENIED (session=${sessionId.slice(0, 8)})`);
            return 'deny';
          }
        } catch { try { unlinkSync(fpath); } catch {} }
      }
    } catch {}
    await new Promise(r => setTimeout(r, 1000));
  }

  log(`Telegram: TIMED OUT after ${cfg.telegramTimeoutS}s`);
  return 'timeout';
}

// ─── Delegation Chain Verification ───────────────────────────────────────────
//
// Called at the evaluate() boundary. Every chain is verified before any
// policy evaluation runs. Fail-closed on any verification failure.
//
// Checks:
//   1. Root token is signed by the daemon's own key
//   2. Each subsequent token is signed by the previous token's public key
//   3. parent_jti links are consistent
//   4. depth fields are sequential (0, 1, 2, …)
//
// Returns { valid: true, depth: number } or { valid: false, reason: string }

function verifyChain(cfg, chain) {
  if (!Array.isArray(chain) || chain.length === 0) return { valid: true, depth: null };

  // Load daemon public key — fail-closed if unavailable
  let daemonPubB64;
  try {
    const privKey = createPrivateKey(readFileSync(cfg.auditSigningKey));
    daemonPubB64  = Buffer.from(
      createPublicKey(privKey).export({ type: 'spki', format: 'der' })
    ).toString('base64');
  } catch (e) {
    log(`WARN: verifyChain: cannot load daemon key — ${e.message}`);
    return { valid: false, reason: 'daemon key unavailable for chain verification' };
  }

  let prevJti = null;

  for (let i = 0; i < chain.length; i++) {
    const token = chain[i];

    // Structural checks
    if (!token || typeof token !== 'object')
      return { valid: false, reason: `token[${i}]: not an object` };
    if (typeof token.jti !== 'string' || !token.jti)
      return { valid: false, reason: `token[${i}]: missing jti` };
    if (typeof token.sub !== 'string' || !token.sub)
      return { valid: false, reason: `token[${i}]: missing sub` };
    if (typeof token.pub !== 'string' || !token.pub)
      return { valid: false, reason: `token[${i}]: missing pub` };
    if (token.depth !== i)
      return { valid: false, reason: `token[${i}]: depth field ${token.depth} ≠ expected ${i}` };
    if (typeof token.sig !== 'string' || !token.sig || token.sig === 'unsigned')
      return { valid: false, reason: `token[${i}]: missing or unsigned sig` };

    // Parent JTI link
    const actualParent   = token.parent_jti ?? null;
    const expectedParent = i === 0 ? null : prevJti;
    if (actualParent !== expectedParent)
      return { valid: false, reason: `token[${i}]: parent_jti mismatch` };

    // Signature verification — root signed by daemon, children signed by parent
    const signerPubB64 = i === 0 ? daemonPubB64 : chain[i - 1].pub;
    try {
      const canonical = tokenCanonical(token);
      const hash      = createHash('sha256').update(canonical).digest();  // raw bytes
      const pubKey    = createPublicKey({ key: Buffer.from(signerPubB64, 'base64'), type: 'spki', format: 'der' });
      const ok        = cryptoVerify(null, hash, pubKey, Buffer.from(token.sig, 'base64'));
      if (!ok) return { valid: false, reason: `token[${i}]: signature invalid` };
    } catch (e) {
      return { valid: false, reason: `token[${i}]: crypto error — ${e.message}` };
    }

    prevJti = token.jti;
  }

  return { valid: true, depth: chain[chain.length - 1].depth };
}

// ─── Request Handler ──────────────────────────────────────────────────────────

async function handleEvaluate(cfg, params) {
  const toolName    = params.tool_name        || 'unknown';
  const toolInput   = params.tool_input       || {};
  const sessionId   = params.session_id       || genId();
  const agentId     = params.agent_id         || 'sdk-agent';
  const chain = params.delegation_chain || null;
  let   chainDepth = null;

  // Verify the delegation chain cryptographically before any policy evaluation.
  // Fail-closed: invalid or unverifiable chain → immediate deny.
  if (Array.isArray(chain) && chain.length > 0) {
    const cv = verifyChain(cfg, chain);
    if (!cv.valid) {
      log(`[${sessionId.slice(0,8)}] CHAIN VERIFY FAILED: ${cv.reason}`);
      writeAuditEntry(cfg, {
        domain:    'delegation', action: 'chain:verify:fail', outcome: 'deny',
        detail:    { reason: cv.reason }, rule: 'chain:verify',
        severity:  'critical', riskScore: 100, authorizer: 'gate',
        sessionId, agentId, chainDepth: null,
      });
      return { decision: 'deny', denied_by: 'chain_verification',
               reason: `[gate] Invalid delegation chain — ${cv.reason}`,
               rule: 'chain:verify', risk_score: 100 };
    }
    chainDepth = cv.depth;
  }

  const auditCtx = { sessionId, agentId, chainDepth };

  // Translate to domain + detail (DETAIL Schema Contract)
  const { domain, detail, display } = translateTool(toolName, toolInput);

  // Internal tool fast path — always allow, no policy evaluation
  if (domain === 'internal') {
    writeAuditEntry(cfg, { domain, action: display, outcome: 'allow',
      detail, rule: 'internal-fast-path', severity: 'info', riskScore: 0,
      authorizer: 'gate', ...auditCtx });
    return { decision: 'allow', reason: 'Internal tool — fast path',
             rule: 'internal-fast-path', risk_score: 0 };
  }

  // Policy evaluation
  const ev = evaluatePolicy(domain, detail);
  log(`[${sessionId.slice(0,8)}] ${toolName} → ${domain} rule=${ev.rule} action=${ev.action} risk=${ev.riskScore}`);

  switch (ev.action) {

    case 'allow': {
      if (ev.audit) {
        writeAuditEntry(cfg, { domain, action: display, outcome: 'allow',
          detail, rule: ev.rule, severity: ev.severity, riskScore: ev.riskScore,
          authorizer: 'policy', ...auditCtx });
      }
      return { decision: 'allow', reason: `${ev.rule}: ${ev.description}`,
               rule: ev.rule, risk_score: ev.riskScore };
    }

    case 'deny': {
      writeAuditEntry(cfg, { domain, action: display, outcome: 'deny',
        detail, rule: ev.rule, severity: ev.severity, riskScore: ev.riskScore,
        authorizer: 'policy', ...auditCtx });
      return { decision: 'deny', denied_by: 'policy',
               reason: `[policy] Blocked by ${ev.rule}: ${ev.description}`,
               rule: ev.rule, risk_score: ev.riskScore };
    }

    case 'log': {
      writeAuditEntry(cfg, { domain, action: display, outcome: 'logged',
        detail, rule: ev.rule, severity: ev.severity, riskScore: ev.riskScore,
        authorizer: 'policy', ...auditCtx });
      return { decision: 'allow', reason: `Logged (${ev.rule})`,
               rule: ev.rule, risk_score: ev.riskScore };
    }

    case 'ask': {
      // Standing approval — no Telegram needed
      const standingId = checkStandingApproval(cfg, ev.rule, display);
      if (standingId) {
        writeAuditEntry(cfg, { domain, action: display, outcome: 'authorized',
          detail, rule: ev.rule, severity: ev.severity, riskScore: ev.riskScore,
          authorizer: `standing:${standingId}`, ...auditCtx });
        return { decision: 'allow', reason: `Standing approval: ${ev.rule}`,
                 rule: ev.rule, risk_score: ev.riskScore };
      }

      // Pending approval (deny-then-retry pattern)
      const actionHash    = computeActionHash(ev.rule, toolName, detail);
      const pendingStatus = checkPendingApproval(cfg, ev.rule, actionHash, sessionId);

      if (pendingStatus === 'approved') {
        writeAuditEntry(cfg, { domain, action: display, outcome: 'authorized',
          detail, rule: ev.rule, severity: ev.severity, riskScore: ev.riskScore,
          authorizer: `human:${cfg.telegramChatId}`, ...auditCtx });
        return { decision: 'allow', reason: `Human approved (${ev.rule})`,
                 rule: ev.rule, risk_score: ev.riskScore };
      }
      if (pendingStatus === 'denied') {
        writeAuditEntry(cfg, { domain, action: display, outcome: 'denied',
          detail, rule: ev.rule, severity: ev.severity, riskScore: ev.riskScore,
          authorizer: `human:${cfg.telegramChatId}`, ...auditCtx });
        return { decision: 'deny', denied_by: 'human',
                 reason: `[human] Denied (${ev.rule})`,
                 rule: ev.rule, risk_score: ev.riskScore };
      }

      // Fresh ask — send Telegram, block connection until human decides
      const actionId = genId();
      writePendingApproval(cfg, ev.rule, actionId, actionHash, sessionId);
      writeAuditEntry(cfg, { domain, action: display, outcome: 'ask_pending',
        detail, rule: ev.rule, severity: ev.severity, riskScore: ev.riskScore,
        authorizer: 'gate', ...auditCtx });

      const decision = await telegramAsk(
        cfg, actionId, toolName, display,
        ev.rule, ev.riskScore, ev.severity, sessionId
      );

      if (decision === 'allow') {
        writeAuditEntry(cfg, { domain, action: display, outcome: 'authorized',
          detail, rule: ev.rule, severity: ev.severity, riskScore: ev.riskScore,
          authorizer: `human:${cfg.telegramChatId}`, ...auditCtx });
        return { decision: 'allow', reason: `Human approved (${ev.rule})`,
                 rule: ev.rule, risk_score: ev.riskScore };
      }
      if (decision === 'deny') {
        writeAuditEntry(cfg, { domain, action: display, outcome: 'denied',
          detail, rule: ev.rule, severity: ev.severity, riskScore: ev.riskScore,
          authorizer: `human:${cfg.telegramChatId}`, ...auditCtx });
        return { decision: 'deny', denied_by: 'human',
                 reason: `[human] Denied (${ev.rule})`,
                 rule: ev.rule, risk_score: ev.riskScore };
      }
      // timeout or error
      writeAuditEntry(cfg, { domain, action: display, outcome: 'denied',
        detail, rule: ev.rule, severity: ev.severity, riskScore: ev.riskScore,
        authorizer: `gate:${decision}`, ...auditCtx });
      return { decision: 'deny', denied_by: 'gate_error',
               reason: `[gate] ${decision === 'timeout' ? 'Timed out' : 'Error'} (${ev.rule})`,
               rule: ev.rule, risk_score: ev.riskScore };
    }

    default:
      writeAuditEntry(cfg, { domain, action: display, outcome: 'deny',
        detail, rule: ev.rule, severity: 'warn', riskScore: 0,
        authorizer: 'gate', ...auditCtx });
      return { decision: 'deny', denied_by: 'gate_error',
               reason: `Unknown policy action: ${ev.action}`,
               rule: ev.rule, risk_score: 0 };
  }
}

// ─── Delegation Chain — Register ─────────────────────────────────────────────
//
// Issues a daemon-endorsed root delegation token.
// The daemon signs with its audit key — the strongest trust anchor available.
// The membrane can verify root tokens with get_daemon_key.

// tokenCanonical imported from ../shared/token-canonical.mjs — single source of truth

function handleRegister(cfg, params) {
  const { agent_id, session_id, public_key } = params || {};
  if (!agent_id || !public_key) {
    return { error: { code: -32602, message: 'register requires agent_id and public_key' } };
  }

  const token = {
    v: 1, jti: genId(), sub: agent_id, pub: public_key,
    depth: 0, iat: Math.floor(Date.now() / 1000), parent_jti: null,
    sig_alg: 'ed25519', sig: null,
  };

  // Sign with daemon's audit key (fail gracefully if key unavailable)
  let daemonPubkey = null;
  try {
    const canonical = tokenCanonical(token);
    const hash      = createHash('sha256').update(canonical).digest();  // raw bytes, not hex string
    const privKey   = createPrivateKey(readFileSync(cfg.auditSigningKey));
    token.sig       = cryptoSign(null, hash, privKey).toString('base64');
    daemonPubkey    = Buffer.from(
      createPublicKey(privKey).export({ type: 'spki', format: 'der' })
    ).toString('base64');
  } catch (e) {
    log(`[register] Daemon signing key unavailable: ${e.message} — token unsigned`);
    token.sig = 'unsigned';
  }

  writeAuditEntry(cfg, {
    domain:     'delegation',
    action:     `register:${agent_id}`,
    outcome:    'registered',
    detail:     { agent_id, depth: 0, pub_prefix: public_key.slice(0, 16) },
    rule:       'chain:root',
    severity:   'info',
    riskScore:  0,
    authorizer: 'daemon:register',
    sessionId:  session_id ?? 'unknown',
    agentId:    agent_id,
    chainDepth: 0,
  });

  return { chain_token: token, daemon_pubkey: daemonPubkey };
}

function handleGetDaemonKey(cfg) {
  try {
    const privKey = createPrivateKey(readFileSync(cfg.auditSigningKey));
    const pubKeyB64 = Buffer.from(
      createPublicKey(privKey).export({ type: 'spki', format: 'der' })
    ).toString('base64');
    return { daemon_pubkey: pubKeyB64, sig_alg: 'ed25519' };
  } catch (e) {
    return { daemon_pubkey: null, error: e.message };
  }
}

async function handleRequest(cfg, msg) {
  if (!msg?.jsonrpc || msg.jsonrpc !== '2.0' || !msg.method) {
    return { jsonrpc: '2.0', id: msg?.id ?? null,
             error: { code: -32600, message: 'Invalid Request' } };
  }

  try {
    switch (msg.method) {

      case 'evaluate': {
        const result = await handleEvaluate(cfg, msg.params || {});
        return { jsonrpc: '2.0', id: msg.id, result };
      }

      case 'health':
        return { jsonrpc: '2.0', id: msg.id, result: {
          status:           'ok',
          version:          DAEMON_VERSION,
          policy_version:   POLICY_VERSION,
          protocol_version: PROTOCOL_VERSION,
        }};

      case 'register': {
        const result = handleRegister(cfg, msg.params || {});
        if (result.error) return { jsonrpc: '2.0', id: msg.id, ...result };
        return { jsonrpc: '2.0', id: msg.id, result };
      }

      case 'get_daemon_key':
        return { jsonrpc: '2.0', id: msg.id, result: handleGetDaemonKey(cfg) };

      default:
        return { jsonrpc: '2.0', id: msg.id,
                 error: { code: -32601, message: `Method not found: ${msg.method}` } };
    }
  } catch (e) {
    log(`CRITICAL: Unhandled error in handleRequest (${msg.method}): ${e.message}\n${e.stack}`);
    // Fail closed: evaluate errors return deny
    if (msg.method === 'evaluate') {
      return { jsonrpc: '2.0', id: msg.id, result: {
        decision: 'deny', denied_by: 'gate_error',
        reason: '[gate] Internal error — fail-closed', rule: 'gate-crash', risk_score: 100,
      }};
    }
    return { jsonrpc: '2.0', id: msg.id,
             error: { code: -32603, message: 'Internal error' } };
  }
}

// ─── Socket Framing (4-byte big-endian length prefix) ────────────────────────
//
// Format: [uint32 big-endian message length][UTF-8 JSON payload]
//
// Chosen over NDJSON: deterministic parsing, no byte scanning,
// max-size enforcement, binary-safe. Pattern from Docker, containerd, LSP.

const MAX_MSG_BYTES = 1 * 1024 * 1024; // 1 MB

function sendFrame(socket, obj) {
  if (socket.destroyed) return;
  const payload = Buffer.from(JSON.stringify(obj), 'utf8');
  const header  = Buffer.allocUnsafe(4);
  header.writeUInt32BE(payload.length, 0);
  socket.write(header);
  socket.write(payload);
}

// Returns a stateful data handler. Calls onMessage(parsedObj) for each frame.
// Returns 'close' signal if a frame exceeds MAX_MSG_BYTES.
function createFrameParser(onMessage) {
  let buf = Buffer.alloc(0);
  return (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 4) {
      const msgLen = buf.readUInt32BE(0);
      if (msgLen > MAX_MSG_BYTES) {
        log(`SECURITY: Oversized frame (${msgLen} bytes) — closing connection`);
        buf = Buffer.alloc(0);
        return 'close';
      }
      if (buf.length < 4 + msgLen) break;  // wait for more data
      const msgBuf = buf.subarray(4, 4 + msgLen);
      buf = buf.subarray(4 + msgLen);
      try {
        onMessage(JSON.parse(msgBuf.toString('utf8')));
      } catch (e) {
        log(`WARN: Frame JSON parse error: ${e.message}`);
      }
    }
    return 'ok';
  };
}

// ─── Connection Handler ───────────────────────────────────────────────────────

let connectionCount = 0;

function handleConnection(cfg, socket) {
  connectionCount++;
  const connId = `conn-${randomBytes(4).toString('hex')}`;
  log(`[${connId}] connected (total=${connectionCount})`);

  socket.on('error', (e) => {
    if (e.code !== 'EPIPE' && e.code !== 'ECONNRESET') {
      log(`[${connId}] socket error: ${e.message}`);
    }
  });

  socket.on('close', () => {
    connectionCount--;
    log(`[${connId}] disconnected (total=${connectionCount})`);
  });

  const parser = createFrameParser(async (msg) => {
    // Each message handled concurrently — event loop continues for other connections
    const response = await handleRequest(cfg, msg);
    sendFrame(socket, response);
  });

  socket.on('data', (chunk) => {
    if (parser(chunk) === 'close') socket.destroy();
  });
}

// ─── Startup ─────────────────────────────────────────────────────────────────

async function main() {
  const cfg = loadConfig();
  LOG_FILE  = cfg.logFile;

  log(`ZLAR SDK Gate Daemon v${DAEMON_VERSION} starting`);
  log(`Socket  : ${cfg.socketPath}`);
  log(`Policy  : ${cfg.policyFile}`);
  log(`Audit   : ${cfg.auditFile}`);

  // Ensure required directories exist
  try { mkdirSync(dirname(cfg.socketPath), { recursive: true, mode: 0o700 }); } catch {}
  try { mkdirSync(dirname(cfg.auditFile),  { recursive: true }); }              catch {}
  try { mkdirSync(cfg.approvalDir,         { recursive: true }); }              catch {}

  // Policy must load cleanly — fail-closed otherwise
  if (!loadPolicy(cfg)) {
    log('FATAL: Cannot start without valid signed policy. Exiting.');
    process.exit(1);
  }

  initAuditMeta(cfg);

  // Remove stale socket file (daemon restart scenario)
  if (existsSync(cfg.socketPath)) {
    try { unlinkSync(cfg.socketPath); log('Removed stale socket file'); }
    catch (e) { log(`WARN: Could not remove stale socket: ${e.message}`); }
  }

  const server = createServer((socket) => handleConnection(cfg, socket));
  server.maxConnections = 128;

  server.listen(cfg.socketPath, () => {
    // Restrict to owner-only — primary security layer for local IPC
    try { chmodSync(cfg.socketPath, 0o600); } catch {}
    log(`Listening — gate ready`);
    log(`Policy v${POLICY_VERSION} · ${POLICY?.rules?.length || 0} rules`);
  });

  server.on('error', (e) => {
    log(`FATAL: Server error: ${e.message}`);
    process.exit(1);
  });

  // Graceful shutdown
  const shutdown = (sig) => {
    log(`${sig} — shutting down gracefully`);
    server.close(() => {
      try { unlinkSync(cfg.socketPath); } catch {}
      log('Daemon stopped');
      process.exit(0);
    });
    // Force exit if graceful close takes too long
    setTimeout(() => { log('Force exit'); process.exit(1); }, 10_000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
  process.on('SIGPIPE', () => {}); // suppress SIGPIPE — sockets close, not process
}

main().catch((e) => {
  process.stderr.write(`[sdk-daemon] FATAL: ${e.message}\n${e.stack}\n`);
  process.exit(1);
});
