#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR AuthZEN Server — @zlar/authzen v0.1.0
//
// Phase 2: Standards-compliant Policy Decision Point (PDP) interface.
//
// Implements AuthZEN 1.0 Final Specification (January 6, 2026).
// The OpenID Foundation standard for authorization decision interfaces.
//
// Endpoints:
//   POST /access/v1/evaluation   — single evaluation (AuthZEN 1.0)
//   POST /access/v1/evaluations  — batch evaluation (AuthZEN 1.0)
//   GET  /health                 — server health + daemon connection status
//
// AuthZEN maps cleanly onto ZLAR's primitives:
//   subject.id   → agent_id   (who is acting)
//   resource.id  → tool_name  (what they want to do — 'Bash', 'Write', etc.)
//   action.id    → ignored    (ZLAR policy operates on tool+detail, not verb)
//   context      → tool_input, session_id, delegation_chain
//
// Response format (standard AuthZEN + ZLAR extensions):
//   { "decision": true,
//     "context": { "rule": "R001", "reason": "...", "risk_score": 10 } }
//
// The gate daemon is the PDP internals.
// This server is the PDP interface — any PEP that speaks AuthZEN can call it.
// NIST NCCoE and OpenID Foundation use this format.
//
// Default port: 8181 (AuthZEN standard)
// ═══════════════════════════════════════════════════════════════════════════════

import { createServer }                from 'http';
import { fileURLToPath }               from 'url';
import { ZlarAgent,
         ZlarDaemonUnreachableError }  from '../membrane/index.mjs';

const VERSION = '0.1.0';

// ─── Logging ──────────────────────────────────────────────────────────────────

function log(msg) {
  process.stderr.write(
    `[${new Date().toISOString().replace(/\.\d+Z$/, 'Z')}] [authzen] ${msg}\n`
  );
}

// ─── HTTP Helpers ─────────────────────────────────────────────────────────────

function jsonResponse(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type':   'application/json',
    'Content-Length': Buffer.byteLength(payload),
    'X-ZLAR-Version': VERSION,
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1024 * 1024) reject(new Error('Request body too large (max 1MB)'));
    });
    req.on('end',   () => {
      try   { resolve(JSON.parse(data || '{}')); }
      catch (e) { reject(new Error(`Invalid JSON: ${e.message}`)); }
    });
    req.on('error', reject);
  });
}

// ─── AuthZEN → ZLAR Mapping ───────────────────────────────────────────────────
//
// AuthZEN request body:
//   { subject: { type, id }, resource: { type, id }, action: { type, id }, context: {} }
//
// ZLAR evaluate() params:
//   { tool_name, tool_input, agent_id, session_id, delegation_chain? }

async function evaluateSingle(agent, body) {
  const {
    subject  = {},
    resource = {},
    action   = {},   // eslint-disable-line no-unused-vars
    context  = {},
  } = body;

  if (!resource.id) {
    return {
      decision: false,
      context:  { reason: 'resource.id is required', rule: null, risk_score: null },
    };
  }

  const toolName   = String(resource.id);
  const agentId    = subject.id  ? String(subject.id) : undefined;
  const toolInput  = context.tool_input  ?? {};
  const sessionId  = context.session_id  ?? undefined;
  const chainRaw   = Array.isArray(context.delegation_chain)
    ? context.delegation_chain
    : null;

  const evalOptions = {
    ...(agentId   ? { agentId   } : {}),
    ...(sessionId ? { sessionId } : {}),
    ...(chainRaw  ? { chainTokens: chainRaw } : {}),
  };

  try {
    const result = await agent.evaluate(toolName, toolInput, evalOptions);

    return {
      decision: result.decision === 'allow',
      context: {
        rule:       result.rule       ?? null,
        reason:     result.reason     ?? null,
        risk_score: result.risk_score ?? null,
      },
    };

  } catch (e) {
    if (e instanceof ZlarDaemonUnreachableError) {
      log(`Daemon unreachable during evaluation — fail-closed`);
      return {
        decision: false,
        context:  { reason: 'Gate daemon unreachable — fail-closed', rule: null, risk_score: null },
      };
    }
    log(`Gate error during evaluation: ${e.message}`);
    return {
      decision: false,
      context:  { reason: `Gate error — fail-closed: ${e.message}`, rule: null, risk_score: null },
    };
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

  // ── POST /access/v1/evaluation — AuthZEN 1.0 single evaluation ─────────────
  if (method === 'POST' && url === '/access/v1/evaluation') {
    let body;
    try   { body = await readBody(req); }
    catch (e) { return jsonResponse(res, 400, { error: e.message }); }

    const result = await evaluateSingle(agent, body);
    log(`${method} ${url} sub=${body.subject?.id ?? '-'} res=${body.resource?.id ?? '-'} → ${result.decision}`);
    return jsonResponse(res, 200, result);
  }

  // ── POST /access/v1/evaluations — AuthZEN 1.0 batch evaluation ─────────────
  if (method === 'POST' && url === '/access/v1/evaluations') {
    let body;
    try   { body = await readBody(req); }
    catch (e) { return jsonResponse(res, 400, { error: e.message }); }

    if (!Array.isArray(body.evaluations)) {
      return jsonResponse(res, 400, { error: 'evaluations array required' });
    }

    const results = await Promise.all(
      body.evaluations.map(e => evaluateSingle(agent, e))
    );
    log(`${method} ${url} batch=${results.length} decisions=${results.map(r => r.decision ? 'T' : 'F').join('')}`);
    return jsonResponse(res, 200, { evaluations: results });
  }

  // ── 404 ─────────────────────────────────────────────────────────────────────
  return jsonResponse(res, 404, { error: `${method} ${url} not found` });
}

// ─── Server Factory ───────────────────────────────────────────────────────────

/**
 * Start the AuthZEN server. Connects to the gate daemon first — if the daemon
 * is unreachable, throws ZlarDaemonUnreachableError.
 *
 * @param {object} [options]
 * @param {number} [options.port]        — listen port (default: ZLAR_AUTHZEN_PORT || 8181)
 * @param {string} [options.host]        — listen host (default: ZLAR_AUTHZEN_HOST || '127.0.0.1')
 * @param {string} [options.socketPath]  — gate daemon socket (default: auto-discover)
 * @param {string} [options.agentId]     — agent ID for this server (default: 'authzen-server')
 * @returns {Promise<{ server: http.Server, port: number, host: string, agent: ZlarAgent }>}
 * @throws {ZlarDaemonUnreachableError}  — if the gate daemon is not reachable
 */
export async function startServer(options = {}) {
  const {
    port:       portOpt   = parseInt(process.env.ZLAR_AUTHZEN_PORT ?? '8181', 10),
    host:       hostOpt   = process.env.ZLAR_AUTHZEN_HOST ?? '127.0.0.1',
    socketPath,
    agentId     = 'authzen-server',
  } = options;

  // Connect to gate daemon — fail-closed if unreachable
  const agent = await ZlarAgent.connect({ agentId, socketPath });

  const server = createServer((req, res) => {
    routeRequest(agent, req, res).catch((e) => {
      log(`Unhandled route error: ${e.message}`);
      jsonResponse(res, 500, { error: `Internal server error: ${e.message}` });
    });
  });

  await new Promise((resolve, reject) => {
    server.listen(portOpt, hostOpt, resolve);
    server.once('error', reject);
  });

  const { port: actualPort } = server.address();

  log(`AuthZEN server v${VERSION} listening on ${hostOpt}:${actualPort}`);
  log(`Endpoints: POST /access/v1/evaluation  POST /access/v1/evaluations  GET /health`);

  return { server, port: actualPort, host: hostOpt, agent };
}

// ─── CLI Entry Point ──────────────────────────────────────────────────────────

async function main() {
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
        `[authzen] FATAL: Gate daemon unreachable at ${e.socketPath}\n` +
        `[authzen] Start the daemon first: zlar-daemon\n`
      );
    } else {
      process.stderr.write(`[authzen] FATAL: ${e.message}\n`);
    }
    process.exit(1);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main();
}
