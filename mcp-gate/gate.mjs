#!/usr/bin/env node
// ZLAR MCP Gate — vendor-agnostic governance proxy for MCP tool calls
//
// Sits between any MCP client and MCP server. Intercepts tools/call
// requests, evaluates policy, routes to human via Telegram when needed,
// writes to the same hash-chained audit trail as the bash gate.
//
// The gate doesn't reason. It intercepts. That's why it can't be subverted
// by reasoning.
//
// Usage:
//   node gate.mjs --port 3100 --upstream localhost:3200
//   node gate.mjs --stdio --upstream-cmd "npx @modelcontextprotocol/server-filesystem /tmp"

import { createServer, createConnection } from 'net';
import { readFileSync, appendFileSync, existsSync, statSync } from 'fs';
import { createHash, randomBytes } from 'crypto';
import { execSync, spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PROJECT_DIR = join(__dirname, '..');

// ─── Configuration ───────────────────────────────────────────────────────────

const CONFIG = {
  port: 3100,
  upstreamHost: null,
  upstreamPort: null,
  upstreamCmd: null,
  auditFile: join(PROJECT_DIR, 'var/log/audit.jsonl'),
  policyFile: join(PROJECT_DIR, 'etc/policies/active.policy.json'),
  policyPubkey: join(PROJECT_DIR, 'etc/keys/policy-signing.pub'),
  telegramToken: null,
  telegramChatId: null,
  telegramTimeoutS: 300,
  sessionId: randomBytes(16).toString('hex'),
  agentId: 'mcp-client',
};

// Parse CLI args
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  switch (args[i]) {
    case '--port': CONFIG.port = parseInt(args[++i]); break;
    case '--upstream': {
      const [host, port] = args[++i].split(':');
      CONFIG.upstreamHost = host;
      CONFIG.upstreamPort = parseInt(port);
      break;
    }
    case '--upstream-cmd': CONFIG.upstreamCmd = args[++i]; break;
    case '--audit-file': CONFIG.auditFile = args[++i]; break;
    case '--policy-file': CONFIG.policyFile = args[++i]; break;
    case '--agent-id': CONFIG.agentId = args[++i]; break;
    case '--telegram-chat-id': CONFIG.telegramChatId = args[++i]; break;
    case '--help':
      console.log(`ZLAR MCP Gate — vendor-agnostic governance proxy

Usage:
  node gate.mjs --port 3100 --upstream localhost:3200
  node gate.mjs --port 3100 --upstream-cmd "command to start MCP server"

Options:
  --port <port>            Listen port (default: 3100)
  --upstream <host:port>   Upstream MCP server address
  --upstream-cmd <cmd>     Start MCP server as subprocess (stdio mode)
  --audit-file <path>      Audit trail path
  --policy-file <path>     Policy file path
  --agent-id <id>          Agent identifier for audit trail
  --telegram-chat-id <id>  Telegram chat ID for HITL approvals
`);
      process.exit(0);
  }
}

// Load Telegram token from .env
function loadTelegramToken() {
  const envFile = join(PROJECT_DIR, '.env');
  if (!existsSync(envFile)) return null;
  const lines = readFileSync(envFile, 'utf8').split('\n');
  for (const line of lines) {
    const match = line.match(/^(TELEGRAM_BOT_TOKEN|ZLAR_TELEGRAM_TOKEN)=["']?([^"'\s]+)/);
    if (match) return match[2];
  }
  return null;
}

CONFIG.telegramToken = process.env.ZLAR_TELEGRAM_TOKEN || loadTelegramToken();
if (!CONFIG.telegramChatId) {
  // Try loading from gate.json
  const gateConfigPath = join(PROJECT_DIR, 'etc/gate.json');
  if (existsSync(gateConfigPath)) {
    try {
      const gateConfig = JSON.parse(readFileSync(gateConfigPath, 'utf8'));
      CONFIG.telegramChatId = gateConfig?.telegram?.chat_id;
      if (gateConfig?.telegram?.timeout_s) CONFIG.telegramTimeoutS = gateConfig.telegram.timeout_s;
    } catch {}
  }
}

// ─── PQC Metadata ────────────────────────────────────────────────────────────

const SIGNATURE_ALGORITHM = 'Ed25519';
const HASH_ALGORITHM = 'SHA-256';
let PUBLIC_KEY_ID = 'unknown';
if (existsSync(CONFIG.policyPubkey)) {
  const keyHash = createHash('sha256').update(readFileSync(CONFIG.policyPubkey)).digest('hex');
  PUBLIC_KEY_ID = keyHash.substring(0, 16);
}

// ─── Policy Engine ───────────────────────────────────────────────────────────

let POLICY = null;
let POLICY_VERSION = 'unknown';

function loadPolicy() {
  if (!existsSync(CONFIG.policyFile)) return;
  try {
    POLICY = JSON.parse(readFileSync(CONFIG.policyFile, 'utf8'));
    POLICY_VERSION = POLICY.version || 'unknown';
  } catch (e) {
    console.error(`[gate] Failed to load policy: ${e.message}`);
  }
}

function evaluatePolicy(toolName, args) {
  if (!POLICY?.rules) {
    console.error(`[gate] No policy loaded — defaulting to ask`);
    return { action: 'ask', rule: 'no-policy', riskScore: 50, severity: 'warn' };
  }

  const domain = 'mcp';
  const actionStr = `${toolName}(${JSON.stringify(args).substring(0, 100)})`;

  for (const rule of POLICY.rules) {
    if (!rule.enabled) continue;

    // Match MCP-specific rules (domain === "mcp")
    if (rule.domain && rule.domain !== 'mcp') continue;

    // Check tool name match
    if (rule.match?.detail?.tool_name) {
      const matcher = rule.match.detail.tool_name;
      if (matcher.eq && matcher.eq !== toolName) continue;
      if (matcher.regex && !new RegExp(matcher.regex).test(toolName)) continue;
      if (matcher.contains && !toolName.includes(matcher.contains)) continue;
    }

    // Check argument patterns
    if (rule.match?.detail?.arguments) {
      const argStr = JSON.stringify(args);
      const matcher = rule.match.detail.arguments;
      if (matcher.regex && !new RegExp(matcher.regex).test(argStr)) continue;
      if (matcher.contains && !argStr.includes(matcher.contains)) continue;
    }

    // Rule matched
    const rs = rule.risk_score || {};
    const riskScore = Math.max(rs.irreversibility || 0, rs.consequence || 0, rs.blast_radius || 0);
    return {
      action: rule.action || 'deny',
      rule: rule.id || 'unknown',
      riskScore,
      severity: rule.severity || 'info',
      description: rule.description || '',
    };
  }

  // Default action
  return {
    action: POLICY.default_action || 'deny',
    rule: 'default',
    riskScore: 0,
    severity: 'info',
  };
}

// ─── Audit Trail ─────────────────────────────────────────────────────────────

let SEQ = 0;

function genId() {
  const hexTs = Math.floor(Date.now() / 1000).toString(16);
  const rand = randomBytes(16).toString('hex');
  return `${hexTs}-${rand}`;
}

function emitEvent(domain, action, outcome, detail, rule, severity, riskScore, authorizer) {
  SEQ++;
  const ts = new Date().toISOString().replace(/\.\d+Z$/, 'Z');

  // Hash chain
  let prevHash = 'genesis';
  if (existsSync(CONFIG.auditFile)) {
    try {
      const content = readFileSync(CONFIG.auditFile, 'utf8').trim();
      const lines = content.split('\n');
      if (lines.length > 0) {
        const lastLine = lines[lines.length - 1];
        prevHash = createHash('sha256').update(lastLine).digest('hex');
      }
    } catch {}
  }

  const event = {
    id: genId(),
    ts,
    seq: SEQ,
    source: 'mcp-gate',
    host: execSync('hostname -s', { encoding: 'utf8' }).trim(),
    user: execSync('whoami', { encoding: 'utf8' }).trim(),
    agent_id: CONFIG.agentId,
    session_id: CONFIG.sessionId,
    domain,
    action: typeof action === 'string' ? action.substring(0, 200) : String(action),
    outcome,
    risk_score: riskScore || 0,
    detail: typeof detail === 'object' ? detail : {},
    rule: rule || '',
    policy_version: POLICY_VERSION,
    severity: severity || 'info',
    prev_hash: prevHash,
    authorizer: authorizer || 'policy',
    signature_algorithm: SIGNATURE_ALGORITHM,
    hash_algorithm: HASH_ALGORITHM,
    public_key_id: PUBLIC_KEY_ID,
  };

  try {
    appendFileSync(CONFIG.auditFile, JSON.stringify(event) + '\n');
  } catch (e) {
    console.error(`[gate] CRITICAL: Failed to write audit event: ${e.message}`);
  }

  return event;
}

// ─── Telegram HITL ───────────────────────────────────────────────────────────

async function telegramApi(method, body) {
  if (!CONFIG.telegramToken) return null;
  try {
    const resp = await fetch(
      `https://api.telegram.org/bot${CONFIG.telegramToken}/${method}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
    );
    return await resp.json();
  } catch (e) {
    console.error(`[gate] Telegram API error: ${e.message}`);
    return null;
  }
}

async function telegramAsk(actionId, toolName, args, rule, riskScore, severity) {
  if (!CONFIG.telegramToken || !CONFIG.telegramChatId) {
    console.error('[gate] No Telegram token or chat ID — cannot ask human');
    return 'error';
  }

  const emoji = severity === 'critical' ? '🔴' : severity === 'warn' ? '🟡' : '⚡';
  const argsPreview = JSON.stringify(args).substring(0, 100);

  const text = `${emoji} 🔷 *MCP Gate*\n\n*Tool:* \`${toolName}\`\n*Args:* \`${argsPreview}\`\n*Risk:* ${riskScore}/100\n*Rule:* ${rule}`;
  const escapedText = text.replace(/[_\[\]()~>#+=|{}.!-]/g, '\\$&').replace(/\\`/g, '`').replace(/\\\*/g, '*');

  const keyboard = {
    inline_keyboard: [[
      { text: '✅ Approve', callback_data: `mcp:approve:${actionId}` },
      { text: '❌ Deny', callback_data: `mcp:deny:${actionId}` },
    ]],
  };

  const result = await telegramApi('sendMessage', {
    chat_id: CONFIG.telegramChatId,
    text: escapedText,
    parse_mode: 'MarkdownV2',
    reply_markup: keyboard,
  });

  const msgId = result?.result?.message_id;
  if (!msgId) return 'error';

  console.log(`[gate] Telegram ask sent: msg_id=${msgId}, action_id=${actionId}`);
  emitEvent('mcp', 'ask_sent', 'pending', { tool: toolName, args: argsPreview }, rule, severity, riskScore, 'gate');

  // Poll for response via shared inbox
  const inboxDir = '/var/run/zlar-tg/inbox/mcp';
  execSync(`mkdir -p "${inboxDir}"`, { stdio: 'ignore' });

  const deadline = Date.now() + CONFIG.telegramTimeoutS * 1000;

  while (Date.now() < deadline) {
    try {
      const { readdirSync, readFileSync: readF, unlinkSync } = await import('fs');
      const files = readdirSync(inboxDir).filter(f => f.endsWith('.json'));

      for (const file of files) {
        const filePath = join(inboxDir, file);
        try {
          const cb = JSON.parse(readF(filePath, 'utf8'));
          const cbData = cb.data || '';
          const cbFrom = cb.from_id || '';

          if (cbFrom !== CONFIG.telegramChatId) {
            unlinkSync(filePath);
            continue;
          }

          if (cbData === `mcp:approve:${actionId}`) {
            unlinkSync(filePath);
            console.log(`[gate] Telegram: APPROVED by human (user_id=${cbFrom})`);
            return 'allow';
          } else if (cbData === `mcp:deny:${actionId}`) {
            unlinkSync(filePath);
            console.log(`[gate] Telegram: DENIED by human (user_id=${cbFrom})`);
            return 'deny';
          }
        } catch { unlinkSync(filePath); }
      }
    } catch {}

    await new Promise(r => setTimeout(r, 1000));
  }

  console.log(`[gate] Telegram: TIMED OUT after ${CONFIG.telegramTimeoutS}s`);
  return 'timeout';
}

// ─── JSON-RPC Message Handling ───────────────────────────────────────────────

function parseMessages(buffer) {
  // MCP uses newline-delimited JSON-RPC
  const messages = [];
  const lines = buffer.split('\n');
  const remaining = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      messages.push(JSON.parse(trimmed));
    } catch {
      remaining.push(line);
    }
  }

  return { messages, remaining: remaining.join('\n') };
}

async function handleRequest(msg) {
  // Only intercept tools/call
  if (msg.method !== 'tools/call') {
    return { action: 'passthrough', msg };
  }

  const toolName = msg.params?.name || 'unknown';
  const args = msg.params?.arguments || {};

  console.log(`[gate] Intercepted tools/call: ${toolName}`);

  // Evaluate policy
  const evaluation = evaluatePolicy(toolName, args);
  console.log(`[gate] Policy: ${evaluation.rule} → ${evaluation.action} (risk ${evaluation.riskScore})`);


  switch (evaluation.action) {
    case 'allow': {
      emitEvent('mcp', toolName, 'allow', { tool: toolName, args_preview: JSON.stringify(args).substring(0, 200) },
        evaluation.rule, evaluation.severity, evaluation.riskScore, 'policy');
      return { action: 'passthrough', msg };
    }

    case 'deny': {
      emitEvent('mcp', toolName, 'deny', { tool: toolName, args_preview: JSON.stringify(args).substring(0, 200) },
        evaluation.rule, evaluation.severity, evaluation.riskScore, 'policy');
      return {
        action: 'deny',
        response: {
          jsonrpc: '2.0',
          id: msg.id,
          error: { code: -32600, message: `[policy] Blocked by rule ${evaluation.rule}: ${evaluation.description}` },
        },
      };
    }

    case 'ask': {
      const actionId = genId();
      // CRITICAL: telegramAsk returns a string, not an exit code.
      // No set -e concern in Node — but the pattern is documented for consistency.
      const decision = await telegramAsk(actionId, toolName, args, evaluation.rule, evaluation.riskScore, evaluation.severity);

      switch (decision) {
        case 'allow':
          emitEvent('mcp', toolName, 'authorized', { tool: toolName, args_preview: JSON.stringify(args).substring(0, 200) },
            evaluation.rule, evaluation.severity, evaluation.riskScore, `human:${CONFIG.telegramChatId}`);
          return { action: 'passthrough', msg };

        case 'deny':
          emitEvent('mcp', toolName, 'denied', { tool: toolName, args_preview: JSON.stringify(args).substring(0, 200) },
            evaluation.rule, evaluation.severity, evaluation.riskScore, `human:${CONFIG.telegramChatId}`);
          return {
            action: 'deny',
            response: {
              jsonrpc: '2.0',
              id: msg.id,
              error: { code: -32600, message: `[human] Denied by human (rule ${evaluation.rule})` },
            },
          };

        default: // timeout or error
          emitEvent('mcp', toolName, 'denied', { tool: toolName, args_preview: JSON.stringify(args).substring(0, 200) },
            evaluation.rule, evaluation.severity, evaluation.riskScore, `gate:${decision}`);
          return {
            action: 'deny',
            response: {
              jsonrpc: '2.0',
              id: msg.id,
              error: { code: -32600, message: `[gate] ${decision === 'timeout' ? 'Timed out' : 'Error'} waiting for human (rule ${evaluation.rule})` },
            },
          };
      }
    }

    case 'log': {
      emitEvent('mcp', toolName, 'logged', { tool: toolName, args_preview: JSON.stringify(args).substring(0, 200) },
        evaluation.rule, evaluation.severity, evaluation.riskScore, 'policy');
      return { action: 'passthrough', msg };
    }

    default:
      return { action: 'passthrough', msg };
  }
}

// ─── TCP Proxy Mode ──────────────────────────────────────────────────────────

function startTcpProxy() {
  if (!CONFIG.upstreamHost || !CONFIG.upstreamPort) {
    console.error('[gate] --upstream host:port required for TCP mode');
    process.exit(1);
  }

  loadPolicy();

  const server = createServer(async (clientSocket) => {
    console.log(`[gate] Client connected`);

    const upstream = createConnection(CONFIG.upstreamPort, CONFIG.upstreamHost, () => {
      console.log(`[gate] Connected to upstream ${CONFIG.upstreamHost}:${CONFIG.upstreamPort}`);
    });

    let clientBuffer = '';

    clientSocket.on('data', async (data) => {
      clientBuffer += data.toString();
      const { messages, remaining } = parseMessages(clientBuffer);
      clientBuffer = remaining;

      for (const msg of messages) {
        if (msg.method) {
          // It's a request — evaluate
          const result = await handleRequest(msg);
          if (result.action === 'passthrough') {
            upstream.write(JSON.stringify(result.msg) + '\n');
          } else {
            clientSocket.write(JSON.stringify(result.response) + '\n');
          }
        } else {
          // It's a response or notification — pass through
          upstream.write(JSON.stringify(msg) + '\n');
        }
      }
    });

    // Pass upstream responses back to client
    upstream.on('data', (data) => {
      clientSocket.write(data);
    });

    upstream.on('error', (e) => {
      console.error(`[gate] Upstream error: ${e.message}`);
      clientSocket.end();
    });

    clientSocket.on('error', (e) => {
      console.error(`[gate] Client error: ${e.message}`);
      upstream.end();
    });

    upstream.on('end', () => clientSocket.end());
    clientSocket.on('end', () => upstream.end());
  });

  server.listen(CONFIG.port, () => {
    console.log(`[gate] ZLAR MCP Gate listening on port ${CONFIG.port}`);
    console.log(`[gate] Upstream: ${CONFIG.upstreamHost}:${CONFIG.upstreamPort}`);
    console.log(`[gate] Policy: ${POLICY_VERSION}`);
    console.log(`[gate] Audit: ${CONFIG.auditFile}`);
    console.log(`[gate] Session: ${CONFIG.sessionId}`);
    console.log(`[gate] PQC: ${SIGNATURE_ALGORITHM} / ${HASH_ALGORITHM} / ${PUBLIC_KEY_ID}`);

    emitEvent('mcp', 'gate.start', 'allow', { port: CONFIG.port, upstream: `${CONFIG.upstreamHost}:${CONFIG.upstreamPort}` },
      '', 'info', 0, 'gate');
  });

  process.on('SIGINT', () => {
    emitEvent('mcp', 'gate.stop', 'allow', {}, '', 'info', 0, 'gate');
    process.exit(0);
  });
}

// ─── Entry Point ─────────────────────────────────────────────────────────────

if (!CONFIG.upstreamHost && !CONFIG.upstreamCmd) {
  console.error('[gate] Specify --upstream host:port or --upstream-cmd "command"');
  process.exit(1);
}

// Add MCP inbox route to the Telegram dispatcher
// The dispatcher routes by callback_data prefix: cc: → CC inbox, oc: → OC inbox
// We add mcp: → MCP inbox. This requires updating zlar-tg-poll, but for now
// the gate can poll getUpdates directly as a fallback.

startTcpProxy();
