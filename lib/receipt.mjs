// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Governed Action Receipt — Generation and Verification
//
// The receipt is the portable proof. The stop is the product.
// The record proves the stop mattered.
//
// This module generates and verifies Governed Action Receipts — cryptographic
// proofs that a governed action was evaluated by deterministic policy and
// decided by the appropriate authority. Anyone with the public key can verify.
//
// Shared by: MCP gate (import), standalone verifier (bin/zlar-verify),
// and bash gate (via bin/zlar-receipt wrapper).
//
// Dependencies: Node.js built-ins only (crypto, fs). No npm packages.
//
// Signing approach (must match bash gate for cross-gate compatibility):
//   1. Canonical JSON: recursive key-sort, compact (matches jq -S -c)
//   2. SHA-256 hash of canonical bytes → hex string (matches shasum -a 256)
//   3. Ed25519 sign the hex string bytes (matches openssl pkeyutl -rawin)
//   4. Base64 encode the signature (matches base64 | tr -d '\n')
// ═══════════════════════════════════════════════════════════════════════════════

import { createHash, sign, verify, randomBytes, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalize } from './canonicalize.mjs';

// Re-export canonicalize for backward compatibility (callers that import from receipt.mjs)
export { canonicalize };

const RECEIPT_VERSION = '0.1.0';

// ─── Receipt ID Generation ───────────────────────────────────────────────────
// Matches the bash gate's ID format: hex timestamp + random bytes.

function generateId() {
  const ts = Date.now().toString(16).padStart(12, '0');
  const rand = randomBytes(16).toString('hex');
  return ts + rand;
}

// ─── Hashing ─────────────────────────────────────────────────────────────────
// SHA-256, output as lowercase hex string. Matches: shasum -a 256 | awk '{print $1}'

export function sha256hex(data) {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

// ─── Receipt Creation ────────────────────────────────────────────────────────

/**
 * Create an unsigned receipt from an audit event or its constituent parts.
 *
 * @param {object} params
 * @param {string} params.tool         - Tool name (e.g., "Bash", "Edit")
 * @param {string} params.domain       - Policy domain (e.g., "file", "network")
 * @param {object|string} params.detail - Action detail object or pre-computed hash
 * @param {string} params.outcome      - Decision outcome
 * @param {string} params.rule         - Matched policy rule
 * @param {string} params.authorizer   - Who decided (policy|human|gate|timeout|manifest)
 * @param {string} params.timestamp    - ISO 8601 UTC timestamp
 * @param {string} params.policy_version - Policy version
 * @param {string} params.audit_event_id - Audit trail entry ID
 * @param {string} params.audit_prev_hash - prev_hash from audit trail
 * @param {string|null} [params.manifest_version]   - Manifest version
 * @param {string|null} [params.manifest_agent_id]  - Agent ID from manifest
 * @param {string|null} [params.manifest_principal]  - Human principal
 * @param {Array}  [params.delegation_chain]         - Delegation chain array
 * @param {string|null} [params.prev_receipt_hash]   - Previous receipt hash
 * @returns {object} Unsigned receipt object (signature field is placeholder)
 */
export function createReceipt(params) {
  const detail_hash = typeof params.detail === 'string'
    ? params.detail
    : sha256hex(canonicalize(params.detail));

  return {
    receipt_version: RECEIPT_VERSION,
    id: params.id || generateId(),
    governed_action: {
      tool: params.tool,
      domain: params.domain,
      detail_hash
    },
    decision: {
      outcome: params.outcome,
      rule: params.rule,
      authorizer: params.authorizer,
      timestamp: params.timestamp
    },
    evidence: {
      policy_version: params.policy_version,
      manifest_version: params.manifest_version ?? null,
      manifest_agent_id: params.manifest_agent_id ?? null,
      manifest_principal: params.manifest_principal ?? null,
      delegation_chain: params.delegation_chain ?? [],
      audit_event_id: params.audit_event_id,
      audit_prev_hash: params.audit_prev_hash
    },
    signature: null,
    prev_receipt_hash: params.prev_receipt_hash ?? null
  };
}

/**
 * Create a receipt directly from a parsed audit event JSON object.
 *
 * @param {object} event - Parsed audit event from audit.jsonl
 * @param {object} [opts]
 * @param {string|null} [opts.manifest_version]
 * @param {string|null} [opts.manifest_agent_id]
 * @param {string|null} [opts.manifest_principal]
 * @param {Array}  [opts.delegation_chain]
 * @param {string|null} [opts.prev_receipt_hash]
 * @returns {object} Unsigned receipt
 */
export function createReceiptFromEvent(event, opts = {}) {
  return createReceipt({
    tool: event.action,
    domain: event.domain,
    detail: event.detail,
    outcome: event.outcome,
    rule: event.rule,
    authorizer: event.authorizer,
    timestamp: event.ts,
    policy_version: event.policy_version,
    audit_event_id: event.id,
    audit_prev_hash: event.prev_hash,
    manifest_version: opts.manifest_version ?? null,
    manifest_agent_id: opts.manifest_agent_id ?? null,
    manifest_principal: opts.manifest_principal ?? null,
    delegation_chain: opts.delegation_chain ?? [],
    prev_receipt_hash: opts.prev_receipt_hash ?? null
  });
}

// ─── Signing ─────────────────────────────────────────────────────────────────
// Must match bash gate signing: canonical → SHA-256 hex → Ed25519 sign hex bytes.

/**
 * Compute the signable payload from a receipt.
 * Removes the signature field, canonicalizes, and returns the SHA-256 hex string.
 * This is the exact byte sequence that gets signed.
 *
 * @param {object} receipt - Receipt object (signature field is ignored)
 * @returns {string} SHA-256 hex string of canonical receipt content
 */
export function signablePayload(receipt) {
  const content = { ...receipt };
  delete content.signature;
  return sha256hex(canonicalize(content));
}

/**
 * Sign a receipt with an Ed25519 private key.
 *
 * @param {object} receipt - Unsigned receipt (signature field will be set)
 * @param {string|Buffer} privateKeyPem - Ed25519 private key in PEM format
 * @param {string} keyId - Public key fingerprint (first 16 chars of SHA-256)
 * @param {string} [algorithm='Ed25519'] - Signing algorithm label
 * @returns {object} Signed receipt with populated signature field
 */
export function signReceipt(receipt, privateKeyPem, keyId, algorithm = 'Ed25519') {
  const hashHex = signablePayload(receipt);

  // Sign the hex string bytes directly — matches openssl pkeyutl -rawin
  const sig = sign(null, Buffer.from(hashHex, 'utf8'), privateKeyPem);

  return {
    ...receipt,
    signature: {
      algorithm,
      hash_algorithm: 'SHA-256',
      value: sig.toString('base64'),
      key_id: keyId
    }
  };
}

/**
 * Sign a receipt using key files on disk.
 *
 * @param {object} receipt - Unsigned receipt
 * @param {string} privateKeyPath - Path to Ed25519 private key PEM file
 * @param {string} publicKeyPath  - Path to public key PEM file (for fingerprint)
 * @returns {object} Signed receipt
 */
export function signReceiptFromFiles(receipt, privateKeyPath, publicKeyPath) {
  const privateKeyPem = readFileSync(privateKeyPath, 'utf8');
  const keyId = pubkeyFingerprint(publicKeyPath);
  return signReceipt(receipt, privateKeyPem, keyId);
}

// ─── Verification ────────────────────────────────────────────────────────────

/**
 * Verify a receipt's signature.
 *
 * @param {object} receipt - Signed receipt to verify
 * @param {string|Buffer} publicKeyPem - Ed25519 public key in PEM format
 * @returns {{ valid: boolean, reason: string }} Verification result
 */
export function verifyReceipt(receipt, publicKeyPem) {
  // Structure checks
  if (!receipt || typeof receipt !== 'object') {
    return { valid: false, reason: 'Receipt is not a valid object.' };
  }
  if (receipt.receipt_version !== RECEIPT_VERSION) {
    return { valid: false, reason: `Unknown receipt version: ${receipt.receipt_version}. Expected ${RECEIPT_VERSION}.` };
  }
  if (!receipt.signature || !receipt.signature.value) {
    return { valid: false, reason: 'Receipt has no signature.' };
  }
  if (receipt.signature.algorithm !== 'Ed25519') {
    // Future: support ML-DSA-44 and hybrid
    return { valid: false, reason: `Unsupported signature algorithm: ${receipt.signature.algorithm}. Only Ed25519 is supported.` };
  }

  // Required fields
  const required = ['id', 'governed_action', 'decision', 'evidence'];
  for (const field of required) {
    if (!(field in receipt)) {
      return { valid: false, reason: `Missing required field: ${field}.` };
    }
  }

  try {
    const hashHex = signablePayload(receipt);
    const sigBytes = Buffer.from(receipt.signature.value, 'base64');

    // Verify: Ed25519 over the hex string bytes
    const ok = verify(null, Buffer.from(hashHex, 'utf8'), publicKeyPem, sigBytes);

    if (ok) {
      return {
        valid: true,
        reason: `Signature valid. Action "${receipt.governed_action.tool}" in domain "${receipt.governed_action.domain}" was ${receipt.decision.outcome} by ${receipt.decision.authorizer} at ${receipt.decision.timestamp}.`
      };
    } else {
      return { valid: false, reason: 'Signature verification failed. Receipt may have been tampered with.' };
    }
  } catch (err) {
    return { valid: false, reason: `Verification error: ${err.message}` };
  }
}

/**
 * Verify a receipt using a public key file on disk.
 *
 * @param {object} receipt - Signed receipt
 * @param {string} publicKeyPath - Path to public key PEM file
 * @returns {{ valid: boolean, reason: string }}
 */
export function verifyReceiptFromFile(receipt, publicKeyPath) {
  const publicKeyPem = readFileSync(publicKeyPath, 'utf8');
  return verifyReceipt(receipt, publicKeyPem);
}

// ─── Key Utilities ───────────────────────────────────────────────────────────

/**
 * Compute public key fingerprint: first 16 chars of SHA-256 of the public key file.
 * Matches bash: shasum -a 256 "${pubkey}" | awk '{print substr($1,1,16)}'
 *
 * @param {string} publicKeyPath - Path to public key PEM file
 * @returns {string} 16-character hex fingerprint
 */
export function pubkeyFingerprint(publicKeyPath) {
  const content = readFileSync(publicKeyPath);
  return createHash('sha256').update(content).digest('hex').slice(0, 16);
}

// ─── Receipt Chain ───────────────────────────────────────────────────────────

/**
 * Compute the hash of a signed receipt for chain linking.
 * The next receipt's prev_receipt_hash should be this value.
 *
 * @param {object} receipt - Signed receipt
 * @returns {string} SHA-256 hex hash of the canonical signed receipt
 */
export function receiptHash(receipt) {
  return sha256hex(canonicalize(receipt));
}

// ═══════════════════════════════════════════════════════════════════════════════
// RECEIPT v1 — Envelope Format
//
// v1 separates the signed payload from the envelope metadata.
// The verifier never re-canonicalizes. They decode the payload bytes,
// hash them, and verify the signature. Canonicalization happens once
// at signing time.
//
// Envelope: { v: 1, id, kid, iat, type, payload, sig, prev }
// Payload:  base64url(canonical JSON of governance fields)
// Signing:  SHA-256(decoded payload bytes) → hex → Ed25519 sign hex bytes
//
// This design follows the research findings:
//   - Versioned protocol (v integer, no alg negotiation) — PASETO/age model
//   - Envelope approach (sign opaque bytes) — DSSE/COSE model
//   - No extension mechanism — strict schema, version bump for changes
// ═══════════════════════════════════════════════════════════════════════════════

const RECEIPT_V1 = 1;

// ─── Base64url (no padding) ─────────────────────────────────────────────────

function base64urlEncode(buf) {
  return buf.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64urlDecode(str) {
  // Restore standard base64
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding
  while (b64.length % 4 !== 0) b64 += '=';
  return Buffer.from(b64, 'base64');
}

// ─── Timestamp ──────────────────────────────────────────────────────────────

/**
 * Format a timestamp to ZLAR v1 canonical form: always UTC, always 3 decimal places.
 * Input: ISO string, Date object, or Unix epoch seconds.
 */
function formatTimestamp(ts) {
  let d;
  if (typeof ts === 'number') d = new Date(ts * 1000);
  else if (ts instanceof Date) d = ts;
  else d = new Date(ts);
  return d.toISOString(); // Always YYYY-MM-DDTHH:mm:ss.sssZ
}

// ─── v1 Receipt Creation ────────────────────────────────────────────────────

/**
 * Create a v1 envelope receipt from governance parameters.
 *
 * @param {object} params - Same fields as createReceipt
 * @returns {object} Unsigned v1 envelope (sig field is empty string)
 */
export function createReceiptV1(params) {
  const detail_hash = typeof params.detail === 'string'
    ? params.detail
    : sha256hex(canonicalize(params.detail));

  const ts = formatTimestamp(params.timestamp);
  const iat = Math.floor(new Date(ts).getTime() / 1000);

  // Build the payload object
  const payload = {
    tool: params.tool,
    domain: params.domain,
    detail_hash,
    outcome: params.outcome,
    rule: params.rule,
    authorizer: params.authorizer,
    ts,
    policy_version: params.policy_version,
    manifest_agent_id: params.manifest_agent_id ?? null,
    manifest_principal: params.manifest_principal ?? null,
    delegation_chain: params.delegation_chain ?? [],
    audit_event_id: params.audit_event_id,
    audit_prev_hash: params.audit_prev_hash
  };

  // Canonicalize and encode
  const canonicalBytes = Buffer.from(canonicalize(payload), 'utf8');
  const payloadB64 = base64urlEncode(canonicalBytes);

  return {
    v: RECEIPT_V1,
    id: params.id || generateId(),
    kid: '',  // Set during signing
    iat,
    type: 'governed-action',
    payload: payloadB64,
    sig: '',  // Set during signing
    prev: params.prev_receipt_hash ?? null
  };
}

/**
 * Create a v1 receipt from a parsed audit event.
 */
export function createReceiptV1FromEvent(event, opts = {}) {
  return createReceiptV1({
    tool: event.action,
    domain: event.domain,
    detail: event.detail,
    outcome: event.outcome,
    rule: event.rule,
    authorizer: event.authorizer,
    timestamp: event.ts,
    policy_version: event.policy_version,
    audit_event_id: event.id,
    audit_prev_hash: event.prev_hash,
    manifest_agent_id: opts.manifest_agent_id ?? null,
    manifest_principal: opts.manifest_principal ?? null,
    delegation_chain: opts.delegation_chain ?? [],
    prev_receipt_hash: opts.prev_receipt_hash ?? null
  });
}

// ─── v1 Signing ─────────────────────────────────────────────────────────────

/**
 * Compute the signable hash from a v1 receipt's payload.
 * Decodes the payload, hashes the raw bytes.
 * This is what gets signed — no re-canonicalization needed.
 *
 * @param {object} receipt - v1 envelope receipt
 * @returns {string} SHA-256 hex string of the decoded payload bytes
 */
export function signablePayloadV1(receipt) {
  const payloadBytes = base64urlDecode(receipt.payload);
  return sha256hex(payloadBytes.toString('utf8'));
}

/**
 * Sign a v1 receipt with an Ed25519 private key.
 *
 * @param {object} receipt - Unsigned v1 envelope
 * @param {string|Buffer} privateKeyPem - Ed25519 private key PEM
 * @param {string} keyId - Public key fingerprint
 * @returns {object} Signed v1 envelope with kid and sig populated
 */
export function signReceiptV1(receipt, privateKeyPem, keyId) {
  const hashHex = signablePayloadV1(receipt);
  const sigBytes = sign(null, Buffer.from(hashHex, 'utf8'), privateKeyPem);

  return {
    ...receipt,
    kid: keyId,
    sig: base64urlEncode(sigBytes)
  };
}

/**
 * Sign a v1 receipt using key files on disk.
 */
export function signReceiptV1FromFiles(receipt, privateKeyPath, publicKeyPath) {
  const privateKeyPem = readFileSync(privateKeyPath, 'utf8');
  const keyId = pubkeyFingerprint(publicKeyPath);
  return signReceiptV1(receipt, privateKeyPem, keyId);
}

// ─── v1 Verification ────────────────────────────────────────────────────────

/**
 * Verify a v1 receipt's signature.
 * No re-canonicalization. Decode payload bytes, hash, verify signature.
 *
 * @param {object} receipt - Signed v1 envelope
 * @param {string|Buffer} publicKeyPem - Ed25519 public key PEM
 * @returns {{ valid: boolean, reason: string, payload?: object }}
 */
export function verifyReceiptV1(receipt, publicKeyPem) {
  // Structure checks
  if (!receipt || typeof receipt !== 'object') {
    return { valid: false, reason: 'Receipt is not a valid object.' };
  }
  if (receipt.v !== RECEIPT_V1) {
    return { valid: false, reason: `Unknown receipt version: ${receipt.v}. Expected ${RECEIPT_V1}.` };
  }
  if (!receipt.sig) {
    return { valid: false, reason: 'Receipt has no signature.' };
  }
  if (!receipt.payload) {
    return { valid: false, reason: 'Receipt has no payload.' };
  }
  if (receipt.type !== 'governed-action') {
    return { valid: false, reason: `Unknown receipt type: ${receipt.type}.` };
  }

  // Required envelope fields
  for (const field of ['id', 'kid', 'iat']) {
    if (!(field in receipt)) {
      return { valid: false, reason: `Missing required envelope field: ${field}.` };
    }
  }

  try {
    // Decode payload
    const payloadBytes = base64urlDecode(receipt.payload);
    let payload;
    try {
      payload = JSON.parse(payloadBytes.toString('utf8'));
    } catch (e) {
      return { valid: false, reason: 'Payload is not valid JSON after base64url decoding.' };
    }

    // Hash the raw payload bytes (not the parsed+re-serialized form)
    const hashHex = sha256hex(payloadBytes.toString('utf8'));

    // Decode signature
    const sigBytes = base64urlDecode(receipt.sig);

    // Verify
    const ok = verify(null, Buffer.from(hashHex, 'utf8'), publicKeyPem, sigBytes);

    if (ok) {
      return {
        valid: true,
        reason: `Signature valid. Action "${payload.tool}" in domain "${payload.domain}" was ${payload.outcome} by ${payload.authorizer} at ${payload.ts}.`,
        payload
      };
    } else {
      return { valid: false, reason: 'Signature verification failed. Receipt may have been tampered with.' };
    }
  } catch (err) {
    return { valid: false, reason: `Verification error: ${err.message}` };
  }
}

/**
 * Verify a v1 receipt using a public key file on disk.
 */
export function verifyReceiptV1FromFile(receipt, publicKeyPath) {
  const publicKeyPem = readFileSync(publicKeyPath, 'utf8');
  return verifyReceiptV1(receipt, publicKeyPem);
}

/**
 * Decode the payload from a v1 receipt without verifying.
 * Useful for inspection — but ALWAYS verify before trusting.
 */
export function decodePayloadV1(receipt) {
  const payloadBytes = base64urlDecode(receipt.payload);
  return JSON.parse(payloadBytes.toString('utf8'));
}

/**
 * Compute the hash of a v1 receipt for chain linking.
 */
export function receiptHashV1(receipt) {
  return sha256hex(canonicalize(receipt));
}

// ─── Universal Verification (v0 + v1) ───────────────────────────────────────

/**
 * Verify any receipt version. Dispatches to v0 or v1 verifier.
 *
 * @param {object} receipt - Receipt (any version)
 * @param {string|Buffer} publicKeyPem - Ed25519 public key PEM
 * @returns {{ valid: boolean, reason: string, version?: string, payload?: object }}
 */
export function verifyReceiptAny(receipt, publicKeyPem) {
  if (!receipt || typeof receipt !== 'object') {
    return { valid: false, reason: 'Receipt is not a valid object.' };
  }

  // v1: integer version field
  if (typeof receipt.v === 'number') {
    if (receipt.v === 1) {
      const result = verifyReceiptV1(receipt, publicKeyPem);
      return { ...result, version: 'v1' };
    }
    return { valid: false, reason: `Unknown receipt version: v${receipt.v}` };
  }

  // v0: string receipt_version field
  if (receipt.receipt_version) {
    const result = verifyReceipt(receipt, publicKeyPem);
    return { ...result, version: 'v0' };
  }

  return { valid: false, reason: 'Cannot determine receipt version. Missing "v" (v1) or "receipt_version" (v0) field.' };
}
