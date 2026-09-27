#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR HTTP Hook Adapter — @zlar/hook-adapter v0.1.0
//
// Phase 2: Claude Code governance bridge. Zero agent code changes required.
//
// Translates between Claude Code's HTTP hook protocol and the ZLAR gate daemon.
// Any Claude Code deployment can use ZLAR governance by adding one JSON entry
// to settings.json or managed-settings.json:
//
//   { "hooks": { "PreToolUse": [{ "matcher": ".*", "hooks": [{
//       "type": "http", "url": "http://localhost:8182/hook", "timeout": 10
//   }]}]}}
//
// Endpoint:
//   POST /hook    — hook evaluation (Claude Code PreToolUse / SubagentStart)
//   GET  /health  — server health + daemon connection status
//
// CRITICAL: Claude Code treats non-2xx responses as FAIL-OPEN — the tool call
// proceeds. This adapter ALWAYS returns HTTP 200 with a valid JSON body.
// Internal errors produce 200 + deny (fail-closed at the adapter level).
//
// Default port: 8182
// ═══════════════════════════════════════════════════════════════════════════════

import { createServer }                from 'http';
import { fileURLToPath }               from 'url';
import { ZlarAgent,
         ZlarDaemonUnreachableError }  from '../membrane/index.mjs';

const VERSION = '0.1.0';

// ─── Logging ──────────────────────────────────────────────────────────────────

function log(msg) {
  process.stderr.write(
    `[${new Date().toISOString().replace(/\.\d+Z$/, 'Z')}] [hook-adapter] ${msg}\n`
  );
}

// ─── HTTP Helpers ─────────────────────────────────────────────────────────────

function jsonResponse(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type':   'application/json',
    'Content-Length':  Buffer.byteLength(payload),
    'X-ZLAR-Version': VERSION,
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1024 * 1024) reject(new Error('Request body too large'));
    });
    req.on('end', () => {
      try   { resolve(JSON.parse(data || '{}')); }
      catch (e) { reject(new Error(`Invalid JSON: ${e.message}`)); }
    });
    req.on('error', reject);
  });
}

// ─── Hook ↔ Daemon Translation ───────────────────────────────────────────────
//
// Claude Code hook input:
//   { hook_event_name, tool_name, tool_input, session_id, cwd, agent_id? }
//
// Daemon evaluate params:
//   { tool_name, tool_input, session_id, agent_id }
//
// Claude Code hook output:
//   { hookSpecificOutput: { hookEventName, permissionDecision, permissionDecisionReason? } }

/**
 * Build a hook response body. Always valid JSON that Claude Code can parse.
 */
function buildHookResponse(hookEventName, decision, reason) {
  const output = {
    hookEventName:      hookEventName || 'PreToolUse',
    permissionDecision: decision,
  };
  if (decision === 'deny' && reason) {
    output.permissionDecisionReason = reason;
  }
  return { hookSpecificOutput: output };
}

/**
 * Build a deny response for error conditions. Never throws.
 */
function buildDenyResponse(hookEventName, reason) {
  return buildHookResponse(hookEventName || 'PreToolUse', 'deny', reason);
}

/**
 * Translate Claude Code hook input into daemon evaluate() parameters.
 */
function translateHookToEvaluate(body) {
  const hookEventName = body.hook_event_name || 'PreToolUse';

  let toolName;
  let toolInput;

  if (hookEventName === 'SubagentStart') {
    // SubagentStart events map to the Agent tool domain in the daemon.
    // The daemon's translateTool('Agent', ...) → domain: 'agent'
    toolName  = 'Agent';
    toolInput = {
      prompt:      body.prompt      || body.tool_input?.prompt      || 'subagent',
      description: body.agent_type  || body.tool_input?.description || 'subagent',
    };
  } else {
    toolName  = body.tool_name || '';
    toolInput = body.tool_input || {};
    // Merge cwd into tool_input for Bash commands (daemon expects it there)
    if (body.cwd && toolName === 'Bash' && !toolInput.cwd) {
      toolInput = { ...toolInput, cwd: body.cwd };
    }
  }

  const options = {};
  if (body.session_id) options.sessionId = body.session_id;
  if (body.agent_id)   options.agentId   = body.agent_id;

  // Forward delegation chain if present (from X-Delegation-Chain header or body)
  if (Array.isArray(body.delegation_chain)) {
    options.chainTokens = body.delegation_chain;
  }

  return { hookEventName, toolName, toolInput, options };
}

/**
 * Translate daemon evaluate() result into Claude Code hook response.
 */
function translateEvaluateToHook(hookEventName, result) {
  const decision = result.decision === 'allow' ? 'allow' : 'deny';

  let reason;
  if (decision === 'deny') {
    // Format: [denied_by] reason — matches bash gate pattern
    const prefix = result.denied_by || 'policy';
    reason = result.reason || `Denied by ${result.rule || 'gate'}`;
    if (!reason.startsWith('[')) {
      reason = `[${prefix}] ${reason}`;
    }
  }

  return buildHookResponse(hookEventName, decision, reason);
}

/**
 * Evaluate a hook request against the gate daemon. Never throws.
 * Returns a valid hook response body for all code paths.
 */
async function evaluateHook(agent, body) {
  const { hookEventName, toolName, toolInput, options } = translateHookToEvaluate(body);

  // Validate: tool_name is required for PreToolUse
  if (hookEventName !== 'SubagentStart' && !toolName) {
    log('Hook input missing tool_name — deny');
    return buildDenyResponse(hookEventName, '[gate_error] No tool name in hook input');
  }

  try {
    const result = await agent.evaluate(toolName, toolInput, options);
    const response = translateEvaluateToHook(hookEventName, result);

    log(`${hookEventName} ${toolName} → ${result.decision} (${result.rule || '-'})`);
    return response;

  } catch (e) {
    if (e instanceof ZlarDaemonUnreachableError) {
      log('Daemon unreachable during hook evaluation — deny (fail-closed)');
      return buildDenyResponse(hookEventName, '[gate_error] Gate daemon unreachable — fail-closed');
    }
    log(`Hook evaluation error: ${e.message} — deny (fail-closed)`);
    return buildDenyResponse(hookEventName, `[gate_error] ${e.message} — fail-closed`);
  }
}

// ─── Request Router ───────────────────────────────────────────────────────────

async function routeRequest(agent, req, res) {
  const { method, url } = req;

  // ── GET /health ─────────────────────────────────────────────────────────────
  if (method === 'GET' && url === '/health') {
    return jsonResponse(res, 200, {
      status:           'ok',
      version:          VERSION,
      daemon_connected: agent.connected,
    });
  }

  // ── POST /hook — Claude Code hook evaluation ────────────────────────────────
  // ALWAYS returns 200. Non-2xx = fail-open in Claude Code's hook protocol.
  if (method === 'POST' && url === '/hook') {
    let body;
    try {
      body = await readBody(req);
    } catch (e) {
      // Parse error → 200 + deny (NOT 400 — fail-closed)
      log(`Hook body parse error: ${e.message} — deny`);
      return jsonResponse(res, 200,
        buildDenyResponse('PreToolUse', `[gate_error] ${e.message}`));
    }

    const result = await evaluateHook(agent, body);
    return jsonResponse(res, 200, result);
  }

  // ── 404 ─────────────────────────────────────────────────────────────────────
  return jsonResponse(res, 404, { error: `${method} ${url} not found` });
}

// ─── Server Factory ───────────────────────────────────────────────────────────

/**
 * Start the HTTP hook adapter. Connects to the gate daemon first — if the
 * daemon is unreachable, throws ZlarDaemonUnreachableError.
 *
 * @param {object} [options]
 * @param {number} [options.port]       — listen port (default: ZLAR_HOOK_PORT || 8182)
 * @param {string} [options.host]       — listen host (default: ZLAR_HOOK_HOST || '127.0.0.1')
 * @param {string} [options.socketPath] — gate daemon socket (default: auto-discover)
 * @param {string} [options.agentId]    — agent ID for this adapter (default: 'hook-adapter')
 * @returns {Promise<{ server: http.Server, port: number, host: string, agent: ZlarAgent }>}
 * @throws {ZlarDaemonUnreachableError} — if the gate daemon is not reachable
 */
export async function startServer(options = {}) {
  const {
    port:       portOpt   = parseInt(process.env.ZLAR_HOOK_PORT ?? '8182', 10),
    host:       hostOpt   = process.env.ZLAR_HOOK_HOST ?? '127.0.0.1',
    socketPath,
    agentId     = 'hook-adapter',
  } = options;

  // Connect to gate daemon — fail-closed if unreachable
  const agent = await ZlarAgent.connect({ agentId, socketPath });

  const server = createServer((req, res) => {
    routeRequest(agent, req, res).catch((e) => {
      // Last-resort catch — still return 200 + deny
      log(`Unhandled route error: ${e.message} — deny (fail-closed)`);
      jsonResponse(res, 200,
        buildDenyResponse('PreToolUse', `[gate_error] Internal error — fail-closed`));
    });
  });

  await new Promise((resolve, reject) => {
    server.listen(portOpt, hostOpt, resolve);
    server.once('error', reject);
  });

  const { port: actualPort } = server.address();

  log(`Hook adapter v${VERSION} listening on ${hostOpt}:${actualPort}`);
  log(`Endpoints: POST /hook  GET /health`);
  log(`Claude Code config: { "type": "http", "url": "http://${hostOpt}:${actualPort}/hook" }`);

  return { server, port: actualPort, host: hostOpt, agent };
}

// ─── CLI Entry Point ──────────────────────────────────────────────────────────

async function main() {
  // --generate-managed-settings: print enterprise config and exit
  if (process.argv.includes('--generate-managed-settings')) {
    const { generateManagedSettings } = await import('./managed-settings.mjs');
    const port = parseInt(process.env.ZLAR_HOOK_PORT ?? '8182', 10);
    const host = process.env.ZLAR_HOOK_HOST ?? '127.0.0.1';
    const settings = generateManagedSettings({ hookUrl: `http://${host}:${port}/hook` });
    process.stdout.write(JSON.stringify(settings, null, 2) + '\n');
    return;
  }

  try {
    const { server } = await startServer();

    process.on('SIGTERM', () => {
      log('SIGTERM — shutting down');
      server.close(() => process.exit(0));
    });
    process.on('SIGINT', () => {
      log('SIGINT — shutting down');
      server.close(() => process.exit(0));
    });

  } catch (e) {
    if (e.code === 'DAEMON_UNREACHABLE') {
      process.stderr.write(
        `[hook-adapter] FATAL: Gate daemon unreachable at ${e.socketPath}\n` +
        `[hook-adapter] Start the daemon first: zlar-daemon\n`
      );
    } else {
      process.stderr.write(`[hook-adapter] FATAL: ${e.message}\n`);
    }
    process.exit(1);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main();
}
