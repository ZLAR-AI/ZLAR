// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR SDK Delegation Chain — chain.mjs
//
// Phase 2: Cryptographic delegation chains for multi-agent systems.
//
// The gap in every major agent framework (AutoGen, CrewAI, LangGraph,
// Google ADK, Semantic Kernel): immediate-caller identity exists, but
// the full delegation chain — who authorized this agent, who authorized
// the authorizer — is never propagated.
//
// This module closes that gap. Every tool call carries a signed chain
// proving the delegation path from root to current agent. The gate logs
// it. Policy can be written against depth (agents at depth > 2 cannot
// write files). The audit trail has a complete provenance record.
//
// Chain structure:
//
//   Root token  (depth 0) — daemon-signed, or self-signed
//     │ signed by root's Ed25519 key
//   Child token (depth 1)
//     │ signed by child's parent key
//   Grandchild  (depth 2)
//     ...
//
// Token canonical form (for signing):
//   "{jti}|{sub}|{pub}|{depth}|{iat}|{parent_jti_or_empty}"
//
// ═══════════════════════════════════════════════════════════════════════════════

import { generateKeyPairSync, createHash,
         sign as cryptoSign, verify as cryptoVerify,
         createPublicKey, createPrivateKey }  from 'crypto';
import { randomUUID }                         from 'crypto';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Deterministic canonical string for signing/verifying a token.
 * Field separator '|' prevents any field from bleeding into adjacent fields.
 */
function tokenCanonical(t) {
  return [
    t.jti,
    t.sub,
    t.pub,
    String(t.depth),
    String(t.iat),
    t.parent_jti ?? '',
  ].join('|');
}

function signToken(token, privKeyPem) {
  const canonical = tokenCanonical(token);
  const hash      = createHash('sha256').update(canonical).digest();  // raw bytes, not hex string
  const privKey   = createPrivateKey(privKeyPem);
  return cryptoSign(null, hash, privKey).toString('base64');
}

function verifyTokenSig(token, pubKeyDerB64) {
  const canonical = tokenCanonical(token);
  const hash      = createHash('sha256').update(canonical).digest();  // raw bytes, not hex string
  const pubKey    = createPublicKey({
    key:    Buffer.from(pubKeyDerB64, 'base64'),
    type:   'spki',
    format: 'der',
  });
  try {
    return cryptoVerify(null, hash, pubKey, Buffer.from(token.sig, 'base64'));
  } catch (_) {
    return false;
  }
}

/**
 * Generate an ephemeral Ed25519 key pair.
 * Keys are session-scoped — not persisted to disk.
 */
export function generateAgentKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
  });
  const pubKeyDerB64 = Buffer.from(
    createPublicKey(publicKey).export({ type: 'spki', format: 'der' })
  ).toString('base64');
  return { privKeyPem: privateKey, pubKeyDerB64 };
}

// ─── DelegationToken ──────────────────────────────────────────────────────────

/**
 * An immutable signed token for one agent in a delegation chain.
 *
 * Fields:
 *   v          — schema version (1)
 *   jti        — unique token ID
 *   sub        — agent ID this token was issued to
 *   pub        — agent's Ed25519 public key (SPKI DER, base64)
 *   depth      — delegation depth (0 = root)
 *   iat        — issued-at unix timestamp
 *   parent_jti — JTI of the parent token (null for root)
 *   sig_alg    — signature algorithm ('ed25519')
 *   sig        — Ed25519 signature over tokenCanonical(this) (base64)
 */
export class DelegationToken {
  constructor(raw) {
    // Validate required fields
    for (const field of ['v', 'jti', 'sub', 'pub', 'depth', 'iat', 'sig_alg', 'sig']) {
      if (!(field in raw)) throw new Error(`DelegationToken missing field: ${field}`);
    }
    Object.assign(this, raw);
    Object.freeze(this);
  }

  /** True if this is a root token (no parent). */
  get isRoot() { return this.depth === 0 && !this.parent_jti; }

  toJSON() {
    return {
      v:          this.v,
      jti:        this.jti,
      sub:        this.sub,
      pub:        this.pub,
      depth:      this.depth,
      iat:        this.iat,
      parent_jti: this.parent_jti ?? null,
      sig_alg:    this.sig_alg,
      sig:        this.sig,
    };
  }
}

// ─── DelegationChain ──────────────────────────────────────────────────────────

/**
 * An ordered chain of DelegationTokens from root to current agent.
 *
 * The chain is the signed evidence of how authority was delegated.
 * Every tool call carries the chain — the gate logs it, policy can
 * be written against chain depth.
 *
 * Construction:
 *   DelegationChain.create(agentId)              — self-signed root chain
 *   DelegationChain.fromDaemon(result, keys)     — daemon-endorsed root chain
 *   chain.delegate(childAgentId)                 — extend chain to child
 *   DelegationChain.fromJSON(tokens, keys)       — deserialize received chain
 */
export class DelegationChain {
  #tokens;       // DelegationToken[] — root first
  #privKeyPem;   // current agent's Ed25519 private key PEM
  #pubKeyDerB64; // current agent's Ed25519 public key (SPKI DER, base64)

  constructor({ tokens, privKeyPem, pubKeyDerB64 }) {
    if (!tokens?.length) throw new Error('DelegationChain requires at least one token');
    this.#tokens       = tokens.map(t => t instanceof DelegationToken ? t : new DelegationToken(t));
    this.#privKeyPem   = privKeyPem;
    this.#pubKeyDerB64 = pubKeyDerB64;
  }

  // ── Factories ────────────────────────────────────────────────────────────

  /**
   * Create a root chain with a self-signed root token.
   * The root token is signed by the agent's own ephemeral key.
   *
   * For daemon-endorsed chains (stronger trust anchor), call
   * agent.registerChain() which uses the 'register' RPC instead.
   *
   * @param {string} agentId
   * @returns {DelegationChain}
   */
  static create(agentId) {
    const { privKeyPem, pubKeyDerB64 } = generateAgentKeyPair();
    const raw = {
      v: 1, jti: randomUUID(), sub: agentId, pub: pubKeyDerB64,
      depth: 0, iat: Math.floor(Date.now() / 1000), parent_jti: null,
      sig_alg: 'ed25519', sig: null,
    };
    raw.sig = signToken(raw, privKeyPem);
    return new DelegationChain({ tokens: [raw], privKeyPem, pubKeyDerB64 });
  }

  /**
   * Create a root chain from a daemon 'register' RPC response.
   * The root token was signed by the gate daemon (strongest trust anchor).
   *
   * @param {{ chain_token: object, daemon_pubkey: string }} registerResult
   * @param {string} privKeyPem      — private key sent during registration
   * @param {string} pubKeyDerB64    — public key sent during registration
   * @returns {DelegationChain}
   */
  static fromDaemon(registerResult, privKeyPem, pubKeyDerB64) {
    return new DelegationChain({
      tokens:       [registerResult.chain_token],
      privKeyPem,
      pubKeyDerB64,
    });
  }

  /**
   * Deserialize a chain received from a parent agent.
   * The chain tokens were signed by the parent chain — provide this
   * agent's own key pair so further delegations can be signed.
   *
   * @param {object[]} tokens       — raw token objects (root first)
   * @param {string}   privKeyPem   — this agent's private key PEM
   * @param {string}   pubKeyDerB64 — this agent's public key (DER base64)
   * @returns {DelegationChain}
   */
  static fromJSON(tokens, privKeyPem, pubKeyDerB64) {
    return new DelegationChain({ tokens, privKeyPem, pubKeyDerB64 });
  }

  // ── Delegation ────────────────────────────────────────────────────────────

  /**
   * Delegate authority to a child agent.
   * Creates a new token for the child, signed by this agent's private key.
   *
   * The returned chain contains all ancestor tokens plus the new child token.
   * Pass childChain.toJSON() and childChain.privateKey to the child agent,
   * then construct the child with DelegationChain.fromJSON(...).
   *
   * @param {string} childAgentId
   * @returns {DelegationChain}  — full chain ending at childAgentId
   */
  delegate(childAgentId) {
    const parent                          = this.#tokens[this.#tokens.length - 1];
    const { privKeyPem, pubKeyDerB64 } = generateAgentKeyPair();

    const raw = {
      v: 1, jti: randomUUID(), sub: childAgentId, pub: pubKeyDerB64,
      depth:      parent.depth + 1,
      iat:        Math.floor(Date.now() / 1000),
      parent_jti: parent.jti,
      sig_alg:    'ed25519',
      sig:        null,
    };
    raw.sig = signToken(raw, this.#privKeyPem);  // parent signs child token

    return new DelegationChain({
      tokens:       [...this.#tokens, raw],
      privKeyPem,
      pubKeyDerB64,
    });
  }

  // ── Verification ──────────────────────────────────────────────────────────

  /**
   * Verify all signatures in the chain.
   *
   * Verification rule:
   *   - Root token: if daemonPubkey provided → verified by daemon key
   *                 otherwise                → self-verified (agent's own key)
   *   - Each subsequent token: verified by the preceding token's public key
   *
   * @param {string} [daemonPubkeyDerB64]  — daemon's pubkey (DER base64)
   * @returns {{ valid: boolean, failedAt?: number, agentId?: string }}
   */
  verify(daemonPubkeyDerB64) {
    for (let i = 0; i < this.#tokens.length; i++) {
      const token     = this.#tokens[i];
      const signerPub = i === 0
        ? (daemonPubkeyDerB64 ?? token.pub)   // root: daemon key, or self
        : this.#tokens[i - 1].pub;             // child: parent's key

      if (!verifyTokenSig(token, signerPub)) {
        return { valid: false, failedAt: i, agentId: token.sub };
      }
    }
    return { valid: true };
  }

  // ── Serialization ─────────────────────────────────────────────────────────

  /**
   * Serialize chain tokens for wire transmission.
   * Include in RPC calls, or pass to DelegationChain.fromJSON() for child agents.
   * Does NOT include private keys.
   */
  toJSON() {
    return this.#tokens.map(t => t.toJSON());
  }

  // ── Properties ────────────────────────────────────────────────────────────

  /** Number of delegation hops (0 = root, 1 = first child, etc.) */
  get depth()     { return this.#tokens[this.#tokens.length - 1].depth; }

  /** Current agent's ID */
  get agentId()   { return this.#tokens[this.#tokens.length - 1].sub; }

  /** Root agent's ID */
  get rootId()    { return this.#tokens[0].sub; }

  /** IDs of all ancestor agents (root first, not including current) */
  get ancestors() { return this.#tokens.slice(0, -1).map(t => t.sub); }

  /** All tokens as plain objects (no private keys) */
  get tokens()    { return this.#tokens.map(t => t.toJSON()); }

  /** Current agent's public key DER base64 — for use by children */
  get publicKey() { return this.#pubKeyDerB64; }

  /** JTI of the leaf (current agent's) token */
  get jti()       { return this.#tokens[this.#tokens.length - 1].jti; }
}
