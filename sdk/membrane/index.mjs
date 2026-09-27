#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR SDK Membrane — @zlar/sdk v0.1.0
//
// Phase 2: Agents built inside governance — membrane, not wrapper.
//
// ZlarAgent.connect() opens a connection to the gate daemon at instantiation.
// If the daemon is unreachable, construction fails. There is no path to an
// agent that has bypassed governance.
//
// The agent does not volunteer to be governed. It cannot exist without it.
//
// Usage:
//   import { ZlarAgent, ZlarDeniedError } from '@zlar/sdk';
//
//   const agent = await ZlarAgent.connect({ agentId: 'my-agent' });
//
//   // Wrap a tool call — evaluates policy, runs fn if allowed, throws if denied
//   const result = await agent.gate('Bash', { command: 'ls -la' }, async () => {
//     return execSync('ls -la').toString();
//   });
//
//   // Or wrap a whole executor map
//   const governed = agent.wrapTools({
//     bash:      (input) => execSync(input.command).toString(),
//     read_file: (input) => fs.readFileSync(input.path, 'utf8'),
//   });
//   const result = await governed.bash({ command: 'ls -la' });
//
// ═══════════════════════════════════════════════════════════════════════════════

import { createConnection }                    from 'net';
import { randomUUID }                          from 'crypto';
import { homedir }                             from 'os';
import { join }                                from 'path';
import { existsSync }                          from 'fs';
import { DelegationChain, generateAgentKeyPair } from './chain.mjs';

export { DelegationChain, DelegationToken } from './chain.mjs';

// ─── Constants ────────────────────────────────────────────────────────────────

const MAX_MSG_BYTES             = 1 * 1024 * 1024; // 1MB — matches daemon
const DEFAULT_CONNECT_TIMEOUT   = 5_000;            // 5s
const DEFAULT_RPC_TIMEOUT       = 120_000;          // 2min — matches Telegram timeout

// ─── Error Classes ────────────────────────────────────────────────────────────

/**
 * Base class for all ZLAR gate errors.
 */
export class ZlarGateError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'ZlarGateError';
    this.code = code;
  }
}

/**
 * Thrown when the gate daemon is unreachable at construction time.
 * The agent cannot be created without a live daemon connection.
 *
 * This enforces the core invariant: governance present at instantiation.
 * There is no path to an ungoverned agent instance.
 */
export class ZlarDaemonUnreachableError extends ZlarGateError {
  constructor(socketPath) {
    super(
      `ZLAR gate daemon unreachable at ${socketPath}. ` +
      `Governance is required for construction. Start the daemon with: zlar-daemon`,
      'DAEMON_UNREACHABLE'
    );
    this.name       = 'ZlarDaemonUnreachableError';
    this.socketPath = socketPath;
  }
}

/**
 * Thrown by gate() when a tool call is denied by policy.
 * Contains the tool name, matching rule, and denial reason.
 */
export class ZlarDeniedError extends ZlarGateError {
  constructor(toolName, rule, reason) {
    super(
      `Tool call denied: ${toolName} matched rule ${rule}. ${reason}`,
      'DENIED'
    );
    this.name     = 'ZlarDeniedError';
    this.toolName = toolName;
    this.rule     = rule;
    this.reason   = reason;
  }
}

/**
 * Thrown when gate evaluation times out waiting for a human decision.
 * Fail-closed: treated as deny.
 */
export class ZlarGateTimeoutError extends ZlarGateError {
  constructor(toolName) {
    super(
      `Gate evaluation timed out for ${toolName}. Fail-closed.`,
      'TIMEOUT'
    );
    this.name     = 'ZlarGateTimeoutError';
    this.toolName = toolName;
  }
}

/**
 * Thrown on malformed frames or JSON-RPC protocol violations.
 */
export class ZlarProtocolError extends ZlarGateError {
  constructor(message) {
    super(message, 'PROTOCOL_ERROR');
    this.name = 'ZlarProtocolError';
  }
}

// ─── Socket Discovery ─────────────────────────────────────────────────────────

/**
 * Resolve socket path from: explicit option → env var → XDG_RUNTIME_DIR → home.
 * Matches daemon's resolveSocketPath() exactly.
 */
function resolveSocketPath(override) {
  if (override)                       return override;
  if (process.env.ZLAR_GATE_SOCKET)  return process.env.ZLAR_GATE_SOCKET;
  const xdg = process.env.XDG_RUNTIME_DIR;
  if (xdg) {
    const p = join(xdg, 'zlar', 'gate.sock');
    if (existsSync(p)) return p;
  }
  return join(homedir(), '.zlar', 'gate.sock');
}

// ─── Frame Protocol ───────────────────────────────────────────────────────────
// JSON-RPC 2.0 over 4-byte big-endian length-prefixed frames.
// Same wire format as the daemon.

function sendFrame(socket, obj) {
  const payload = Buffer.from(JSON.stringify(obj), 'utf8');
  const header  = Buffer.allocUnsafe(4);
  header.writeUInt32BE(payload.length, 0);
  socket.write(Buffer.concat([header, payload]));
}

function createFrameParser(onMessage) {
  let buf = Buffer.alloc(0);
  return (data) => {
    buf = Buffer.concat([buf, data]);
    while (buf.length >= 4) {
      const len = buf.readUInt32BE(0);
      if (len > MAX_MSG_BYTES) {
        throw new ZlarProtocolError(`Frame too large: ${len} bytes`);
      }
      if (buf.length < 4 + len) break;
      const payload = buf.slice(4, 4 + len);
      buf = buf.slice(4 + len);
      try {
        onMessage(JSON.parse(payload.toString('utf8')));
      } catch (e) {
        if (e instanceof ZlarProtocolError) throw e;
        throw new ZlarProtocolError(`Invalid JSON frame: ${e.message}`);
      }
    }
  };
}

// ─── ZlarAgent ────────────────────────────────────────────────────────────────

export class ZlarAgent {
  // Private state
  #cfg;
  #socket;
  #sessionId;
  #nextId;
  #pending;       // Map<id, { resolve, reject, timer }>
  #connected;
  #onDisconnect;
  #chain;         // DelegationChain | null — attached via registerChain()

  // Private constructor — use ZlarAgent.connect()
  constructor(options = {}) {
    this.#cfg = {
      agentId:        options.agentId        ?? 'zlar-sdk-agent',
      socketPath:     resolveSocketPath(options.socketPath),
      connectTimeout: options.connectTimeout ?? DEFAULT_CONNECT_TIMEOUT,
      rpcTimeout:     options.rpcTimeout     ?? DEFAULT_RPC_TIMEOUT,
    };
    this.#sessionId    = options.sessionId ?? randomUUID();
    this.#nextId       = 1;
    this.#pending      = new Map();
    this.#connected    = false;
    this.#onDisconnect = options.onDisconnect ?? null;
    this.#chain        = null;
  }

  // ── Factory ───────────────────────────────────────────────────────────────

  /**
   * Connect to the gate daemon and return a governed agent.
   * Throws ZlarDaemonUnreachableError if the daemon is not running.
   *
   * This is the only way to create a ZlarAgent. Governance is present
   * at construction — there is no ungoverned instance.
   *
   * @param {object} options
   * @param {string} [options.agentId]        - Identifies this agent in the audit trail
   * @param {string} [options.socketPath]     - Override socket path (default: auto-discover)
   * @param {number} [options.connectTimeout] - ms to wait for daemon (default: 5000)
   * @param {number} [options.rpcTimeout]     - ms to wait for gate decision (default: 120000)
   * @param {string} [options.sessionId]      - Override session ID (default: random UUID)
   * @param {function} [options.onDisconnect] - Called if connection drops post-construction
   * @returns {Promise<ZlarAgent>}
   * @throws {ZlarDaemonUnreachableError}
   */
  static async connect(options = {}) {
    const agent = new ZlarAgent(options);
    await agent.#doConnect();
    return agent;
  }

  // ── Connection ────────────────────────────────────────────────────────────

  async #doConnect() {
    const { socketPath, connectTimeout } = this.#cfg;

    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        sock.destroy();
        reject(new ZlarDaemonUnreachableError(socketPath));
      }, connectTimeout);

      const sock = createConnection(socketPath);

      sock.once('connect', () => {
        clearTimeout(timer);
        this.#socket    = sock;
        this.#connected = true;

        const parser = createFrameParser((msg) => this.#dispatch(msg));
        sock.on('data', (data) => {
          try { parser(data); }
          catch (e) { this.#rejectAll(e); }
        });

        sock.on('error', (err) => {
          this.#connected = false;
          this.#rejectAll(new ZlarGateError(`Socket error: ${err.message}`, 'SOCKET_ERROR'));
          if (this.#onDisconnect) this.#onDisconnect(err);
        });

        sock.on('close', () => {
          this.#connected = false;
          this.#rejectAll(new ZlarGateError('Daemon connection closed', 'CONNECTION_CLOSED'));
          if (this.#onDisconnect) this.#onDisconnect(null);
        });

        resolve();
      });

      sock.once('error', () => {
        clearTimeout(timer);
        reject(new ZlarDaemonUnreachableError(socketPath));
      });
    });
  }

  // ── Response Dispatch ─────────────────────────────────────────────────────

  #dispatch(msg) {
    if (msg.id == null) return; // JSON-RPC notification — not used yet
    const entry = this.#pending.get(msg.id);
    if (!entry) return;

    clearTimeout(entry.timer);
    this.#pending.delete(msg.id);

    if (msg.error) {
      entry.reject(new ZlarProtocolError(
        `RPC error ${msg.error.code}: ${msg.error.message}`
      ));
    } else {
      entry.resolve(msg.result);
    }
  }

  #rejectAll(err) {
    for (const [, entry] of this.#pending) {
      clearTimeout(entry.timer);
      entry.reject(err);
    }
    this.#pending.clear();
  }

  // ── RPC ───────────────────────────────────────────────────────────────────

  async #rpc(method, params) {
    if (!this.#connected) {
      throw new ZlarDaemonUnreachableError(this.#cfg.socketPath);
    }

    const id  = this.#nextId++;
    const msg = { jsonrpc: '2.0', id, method, params };

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new ZlarGateTimeoutError(params?.tool_name ?? 'unknown'));
      }, this.#cfg.rpcTimeout);

      this.#pending.set(id, { resolve, reject, timer });
      sendFrame(this.#socket, msg);
    });
  }

  // ── Public API ────────────────────────────────────────────────────────────

  /**
   * Evaluate a tool call against gate policy.
   * Returns the raw evaluation result from the daemon.
   *
   * Use gate() for most cases — evaluate() is for callers that need
   * to inspect the result before deciding whether to proceed.
   *
   * @param {string} toolName   - Tool name (e.g. 'Bash', 'Write', 'mcp__github__push')
   * @param {object} toolInput  - Tool parameters
   * @returns {Promise<{decision: string, reason: string, rule: string, risk_score: number}>}
   */
  async evaluate(toolName, toolInput, options = {}) {
    const params = {
      tool_name:  toolName,
      tool_input: toolInput,
      session_id: options.sessionId ?? this.#sessionId,
      agent_id:   options.agentId   ?? this.#cfg.agentId,
    };
    // Chain priority: options.chain (DelegationChain) > attached chain > options.chainTokens (raw array)
    const chain = options.chain ?? this.#chain;
    if (chain) {
      params.delegation_chain = chain.toJSON();
    } else if (Array.isArray(options.chainTokens)) {
      params.delegation_chain = options.chainTokens;
    }
    return this.#rpc('evaluate', params);
  }

  /**
   * Register this agent with the gate daemon and attach a delegation chain.
   * The daemon issues a signed root token establishing this agent as a
   * trust anchor. The chain is forwarded on all subsequent evaluate() calls.
   *
   * For sub-agents, use parentChain.delegate(childId) and pass the result
   * to ZlarAgent.connect({ chain: childChain }) instead.
   *
   * @returns {Promise<DelegationChain>}
   */
  async registerChain() {
    const { privKeyPem, pubKeyDerB64 } = generateAgentKeyPair();
    const result = await this.#rpc('register', {
      agent_id:   this.#cfg.agentId,
      session_id: this.#sessionId,
      public_key: pubKeyDerB64,
    });
    const chain      = DelegationChain.fromDaemon(result, privKeyPem, pubKeyDerB64);
    this.#chain      = chain;
    return chain;
  }

  /**
   * Get the daemon's signing public key (DER base64).
   * Use to verify daemon-issued chain tokens: chain.verify(daemonPubkey).
   *
   * @returns {Promise<string>}  — daemon pubkey DER base64, or null if unavailable
   */
  async getDaemonKey() {
    const result = await this.#rpc('get_daemon_key', {});
    return result.daemon_pubkey ?? null;
  }

  /**
   * Attach an existing DelegationChain to this agent.
   * Use when constructing a child agent that received a chain from its parent:
   *
   *   const parentChain  = await orchestrator.registerChain();
   *   const childChain   = parentChain.delegate('child-agent');
   *   const child        = await ZlarAgent.connect({ agentId: 'child-agent' });
   *   child.attachChain(childChain);
   *
   * @param {DelegationChain} chain
   */
  attachChain(chain) {
    this.#chain = chain;
  }

  /**
   * Gate a tool call. Evaluates policy and either:
   *   - Calls fn() and returns its result  (allow)
   *   - Throws ZlarDeniedError             (deny, or ask→deny/timeout)
   *
   * The primary integration point. Wrap every tool execution with gate().
   *
   * @param {string}   toolName  - Tool name
   * @param {object}   toolInput - Tool parameters
   * @param {function} fn        - Async function to call if allowed
   * @returns {Promise<*>}       - Result of fn()
   * @throws {ZlarDeniedError}   - If policy denies the call
   * @throws {ZlarDaemonUnreachableError} - If connection is lost
   */
  async gate(toolName, toolInput, fn, options = {}) {
    const result = await this.evaluate(toolName, toolInput, options);

    if (result.decision === 'allow') {
      return fn();
    }

    // deny, timeout, or error path — all fail-closed
    throw new ZlarDeniedError(
      toolName,
      result.rule   ?? 'unknown',
      result.reason ?? result.decision,
    );
  }

  /**
   * Wrap a map of tool executors with gate enforcement.
   * Every call to a wrapped executor is evaluated against policy first.
   *
   * @param {object} executors  - { toolName: async (input) => result }
   * @returns {object}          - Same shape, each call gated
   *
   * @example
   *   const governed = agent.wrapTools({
   *     bash:      (input) => exec(input.command),
   *     read_file: (input) => fs.readFile(input.path, 'utf8'),
   *   });
   *   const out = await governed.bash({ command: 'ls -la' });
   */
  wrapTools(executors) {
    const governed = {};
    for (const [name, fn] of Object.entries(executors)) {
      governed[name] = (input) => this.gate(name, input, () => fn(input));
    }
    return governed;
  }

  /**
   * Close the daemon connection.
   * In-flight gate() calls will reject with ZlarGateError('CONNECTION_CLOSED').
   */
  async close() {
    if (this.#socket && this.#connected) {
      this.#connected = false;
      this.#socket.destroy();
    }
  }

  // ── Properties ────────────────────────────────────────────────────────────

  /** True if daemon connection is live. */
  get connected() { return this.#connected; }

  /** The attached DelegationChain, or null if not registered. */
  get chain() { return this.#chain; }

  /** Session ID — present on every audit entry from this agent. */
  get sessionId() { return this.#sessionId; }

  /** Agent ID — present on every audit entry from this agent. */
  get agentId() { return this.#cfg.agentId; }

  /** The resolved Unix socket path. */
  get socketPath() { return this.#cfg.socketPath; }
}
