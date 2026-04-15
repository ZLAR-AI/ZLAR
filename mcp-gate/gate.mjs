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

import { createServer, createConnection } from 'net';
import { readFileSync, appendFileSync, existsSync, statSync } from 'fs';
import { createHash, createHmac, randomBytes, timingSafeEqual, sign as cryptoSign, verify as cryptoVerify, createPublicKey } from 'crypto';
import { execSync, spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PROJECT_DIR = join(__dirname, '..');

// Receipt generation (Phase A — Governed Action Receipt)
import {
  createReceiptFromEvent,
  signReceipt,
  pubkeyFingerprint,
  receiptHash,
  canonicalize,
  sha256hex
} from '../lib/receipt.mjs';

// Multi-canonical Ed25519 verification (see ADR-011)
import {
  canonicalFormVariants,
  verifyAnyCanonical,
} from '../lib/sig-verify.mjs';

// Human invariant enforcement (H6, H13, H14, H15, H17)
import {
  preAskCheck,
  postResponseCheck,
  recordAskTime,
  recordDecision,
} from '../lib/human-invariants.mjs';

// Cedar policy evaluation (Phase C — Cedar Integration)
import {
  cedarAvailable,
  cedarVersion,
  evaluate as cedarEvaluate,
  validatePolicies as cedarValidate,
  loadPoliciesFromFiles as cedarLoadFiles,
  mapToGateAction as cedarMapAction,
} from '../lib/cedar-evaluator.mjs';

// Constitutional validation (Second Authority Law parity with bash gate)
import {
  loadManifest,
  validateConstitution,
} from './constitution.mjs';

// Runtime manifest-authority enforcement (parity with bash gate 2175-2246)
import {
  enforceManifestAuthority,
} from './manifest-enforcement.mjs';

// ─── Configuration ───────────────────────────────────────────────────────────

const CONFIG = {
  port: 3100,
  upstreamHost: null,
  upstreamPort: null,
  auditFile: join(PROJECT_DIR, 'var/log/audit.jsonl'),
  policyFile: join(PROJECT_DIR, 'etc/policies/active.policy.json'),
  policyPubkey: join(PROJECT_DIR, 'etc/keys/policy-signing.pub'),
  // Second Authority Law (parity with bash gate)
  constitutionFile: join(PROJECT_DIR, 'etc/constitution.json'),
  constitutionPubkey: join(PROJECT_DIR, 'etc/keys/constitution-signing.pub'),
  constitutionPresenceFile: join(PROJECT_DIR, 'var/log/.constitution-last-hash'),
  manifestFile: join(PROJECT_DIR, 'etc/manifest.json'),
  restoreConfigFile: join(PROJECT_DIR, 'etc/restore-config.json'),
  telegramToken: null,
  telegramChatId: null,
  telegramTimeoutS: 300,
  sessionId: randomBytes(16).toString('hex'),
  agentId: 'mcp-client',
  // Receipt generation (Phase A)
  signingKey: join(process.env.HOME || '', '.zlar-signing.key'),
  signingPubkey: join(process.env.HOME || '', '.zlar-signing.pub'),
  receiptFile: join(PROJECT_DIR, 'var/log/receipts.jsonl'),
  emitReceipts: process.env.ZLAR_EMIT_RECEIPTS === 'true',
  // Cedar policy engine (Phase C) — when enabled, Cedar evaluates alongside or instead of JSON
  policyEngine: process.env.ZLAR_POLICY_ENGINE || 'json', // 'json', 'cedar', or 'both'
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
    case '--audit-file': CONFIG.auditFile = args[++i]; break;
    case '--policy-file': CONFIG.policyFile = args[++i]; break;
    case '--agent-id': CONFIG.agentId = args[++i]; break;
    case '--telegram-chat-id': CONFIG.telegramChatId = args[++i]; break;
    case '--policy-engine': CONFIG.policyEngine = args[++i]; break;
    case '--help':
      console.log(`ZLAR MCP Gate — vendor-agnostic governance proxy

Usage:
  node gate.mjs --port 3100 --upstream localhost:3200

Options:
  --port <port>            Listen port (default: 3100)
  --upstream <host:port>   Upstream MCP server address (required)
  --policy-engine <kind>   Policy engine: json (default), cedar, or both
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
      if (gateConfig?.emit_receipts === true) CONFIG.emitReceipts = true;
    } catch (e) {
      // Can't call auditInternalError here — emitEvent isn't defined yet at
      // module load time. Log to stderr so operators see config corruption.
      console.error(`[gate] WARN: gate.json parse failed: ${e.message}`);
    }
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
let POLICY_MTIME_MS = 0;
let STANDING_APPROVALS_MTIME_MS = 0;

// Session-scoped novelty tracker. See novelty-escalation comment below in
// handleRequest. Reset implicitly on process restart (new session = new
// paranoia). In-memory only by design — we don't want an attacker who
// compromised a past session to grant future sessions a free pass.
const SEEN_TOOLS = new Set();

// Reload policy and standing approvals if the underlying files changed on
// disk since the last load. Bash-gate parity: bash re-reads per hook
// invocation; the MCP gate is long-running, so the operator-rotate path
// needs an explicit re-read. Called at the start of every request.
function maybeReloadPolicyAndSA() {
  try {
    if (existsSync(CONFIG.policyFile)) {
      const m = statSync(CONFIG.policyFile).mtimeMs;
      if (m !== POLICY_MTIME_MS) {
        loadPolicy();
        POLICY_MTIME_MS = m;
      }
    }
  } catch (e) {
    console.error(`[gate] WARN: policy mtime check failed: ${e.message}`);
  }
  const saFile = join(PROJECT_DIR, 'etc/standing-approvals.json');
  try {
    if (existsSync(saFile)) {
      const m = statSync(saFile).mtimeMs;
      if (m !== STANDING_APPROVALS_MTIME_MS) {
        loadStandingApprovals();
        STANDING_APPROVALS_MTIME_MS = m;
      }
    } else if (STANDING_APPROVALS_MTIME_MS !== 0) {
      // File deleted since last load — clear approvals.
      STANDING_APPROVALS = [];
      STANDING_APPROVALS_LOADED = false;
      STANDING_APPROVALS_MTIME_MS = 0;
    }
  } catch (e) {
    console.error(`[gate] WARN: standing-approvals mtime check failed: ${e.message}`);
  }
}

// ─── Signature Verification ──────────────────────────────────────────────────
// Shared by policy and standing approval verification. Matches bash gate approach:
// canonical (with signature zeroed) → SHA-256 hex → Ed25519 verify hex bytes.

function verifyJsonSignature(obj, publicKeyPath) {
  if (!existsSync(publicKeyPath)) return { ok: false, reason: 'public key not found' };

  const sig = obj?.signature;
  if (!sig?.value) return { ok: false, reason: 'no signature in file' };

  try {
    const pubKeyPem = readFileSync(publicKeyPath, 'utf8');

    // Zero ONLY .signature.value — matches the policy / standing-approvals
    // signing convention in bash (`jq '.signature.value = ""'`). Algorithm
    // and public_key fields are preserved in the canonical form.
    const cleared = JSON.parse(JSON.stringify(obj));
    cleared.signature = { ...cleared.signature, value: '' };

    // Verify under any of the three canonical forms currently in use in
    // the project. See ADR-011 and lib/sig-verify.mjs.
    const forms = canonicalFormVariants(cleared);
    const result = verifyAnyCanonical(forms, pubKeyPem, sig.value);
    if (result.ok && result.form !== 'spec') {
      console.warn(`[gate] WARN: signature verified under LEGACY canonical form "${result.form}". Migration tracked by ADR-011.`);
    }
    return result;
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

function loadPolicy() {
  if (!existsSync(CONFIG.policyFile)) {
    console.error(`[gate] CRITICAL: Policy file not found: ${CONFIG.policyFile} — fail-closed`);
    POLICY = { rules: [], default_action: 'deny', version: 'fail-closed' };
    POLICY_VERSION = 'fail-closed';
    return;
  }
  try {
    const raw = JSON.parse(readFileSync(CONFIG.policyFile, 'utf8'));

    // Ed25519 policy signature verification (parity with bash gate: required).
    // Fail-closed on missing pubkey, missing signature, or invalid signature.
    if (!existsSync(CONFIG.policyPubkey)) {
      console.error('[gate] FATAL: Policy public key not found — fail-closed');
      POLICY = { rules: [], default_action: 'deny', version: 'fail-closed-nopub' };
      POLICY_VERSION = 'fail-closed-nopub';
      return;
    }
    if (!raw.signature?.value) {
      console.error('[gate] FATAL: Policy is unsigned — fail-closed');
      POLICY = { rules: [], default_action: 'deny', version: 'fail-closed-unsigned' };
      POLICY_VERSION = 'fail-closed-unsigned';
      return;
    }
    const result = verifyJsonSignature(raw, CONFIG.policyPubkey);
    if (!result.ok) {
      console.error(`[gate] CRITICAL: Policy signature INVALID (${result.reason}) — fail-closed`);
      POLICY = { rules: [], default_action: 'deny', version: 'fail-closed-sig' };
      POLICY_VERSION = 'fail-closed-sig';
      return;
    }
    console.log('[gate] Policy signature verified');

    POLICY = raw;
    POLICY_VERSION = POLICY.version || 'unknown';
  } catch (e) {
    console.error(`[gate] CRITICAL: Failed to parse policy: ${e.message} — fail-closed`);
    POLICY = { rules: [], default_action: 'deny', version: 'fail-closed' };
    POLICY_VERSION = 'fail-closed';
  }
}

function evaluatePolicy(toolName, args) {
  if (!POLICY?.rules) {
    console.error(`[gate] No policy loaded — DENYING (fail-closed)`);
    return { action: 'deny', rule: 'no-policy', riskScore: 100, severity: 'critical' };
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

    // compound_guard (bash gate lines 1380-1398): secondary AND condition.
    // Must pass AFTER detail matches. If it fails, skip this rule and continue.
    // Found via cross-gate differential test: R012BR has a compound_guard that
    // restricts "audit file read" to safe read commands only (cat/head/tail/etc).
    // Without this check, any command touching audit.jsonl would match R012BR
    // (allow) instead of falling through to R012B (deny). Both conditions must
    // hold: the file pattern AND the safe-command guard.
    if (rule.match?.compound_guard) {
      const cg = rule.match.compound_guard;
      let guardPassed = true;
      for (const [key, matcher] of Object.entries(cg)) {
        const actual = String(args?.[key] ?? '');
        if (matcher.regex    && !new RegExp(matcher.regex).test(actual))    { guardPassed = false; break; }
        if (matcher.eq       && matcher.eq !== actual)                      { guardPassed = false; break; }
        if (matcher.contains && !actual.includes(matcher.contains))         { guardPassed = false; break; }
        if (matcher.not_regex && new RegExp(matcher.not_regex).test(actual)) { guardPassed = false; break; }
      }
      if (!guardPassed) continue;
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
      verifyHint: rule.verify_hint || '',
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

// ─── Cedar Policy Engine (Phase C) ───────────────────────────────────────────
// Cedar evaluates alongside or instead of JSON regex. Both engines produce
// the same receipt format. The gate doesn't know which engine ran.

let CEDAR_SCHEMA = null;
let CEDAR_POLICIES = null;
let CEDAR_POLICY_ID_MAP = {};
let CEDAR_LOADED = false;

function loadCedar() {
  if (CONFIG.policyEngine === 'json') return; // Cedar not requested

  if (!cedarAvailable()) {
    console.error('[gate] WARN: Cedar requested but WASM not available — falling back to JSON');
    if (CONFIG.policyEngine === 'cedar') {
      console.error('[gate] CRITICAL: Cedar-only mode with no Cedar — fail-closed');
      POLICY = { rules: [], default_action: 'deny', version: 'fail-closed-cedar' };
      POLICY_VERSION = 'fail-closed-cedar';
    }
    return;
  }

  const loaded = cedarLoadFiles();
  if (!loaded) {
    console.error('[gate] WARN: No Cedar policy files found');
    if (CONFIG.policyEngine === 'cedar') {
      console.error('[gate] CRITICAL: Cedar-only mode with no policies — fail-closed');
      POLICY = { rules: [], default_action: 'deny', version: 'fail-closed-cedar' };
      POLICY_VERSION = 'fail-closed-cedar';
    }
    return;
  }

  const validation = cedarValidate({ schema: loaded.schema, policies: loaded.policies });
  if (!validation.ok) {
    console.error(`[gate] CRITICAL: Cedar policy validation failed: ${validation.error}`);
    if (CONFIG.policyEngine === 'cedar') {
      POLICY = { rules: [], default_action: 'deny', version: 'fail-closed-cedar' };
      POLICY_VERSION = 'fail-closed-cedar';
    }
    return;
  }

  CEDAR_SCHEMA = loaded.schema;
  CEDAR_POLICIES = loaded.policies;
  CEDAR_POLICY_ID_MAP = loaded.policyIdMap || {};
  CEDAR_LOADED = true;
  console.log(`[gate] Cedar policies loaded: ${loaded.files.length} files (Cedar ${cedarVersion()})`);
}

// Wrap evaluatePolicy to support both engines
function evaluatePolicyDual(toolName, args) {
  const engine = CONFIG.policyEngine;

  if (engine === 'json' || (engine === 'both' && !CEDAR_LOADED)) {
    return evaluatePolicy(toolName, args);
  }

  if (engine === 'cedar' || engine === 'both') {
    if (!CEDAR_LOADED) {
      // Fail-closed: Cedar requested but not loaded
      return { action: 'deny', rule: 'cedar-unavailable', riskScore: 100, severity: 'critical' };
    }

    // Cedar evaluation
    const command = typeof args === 'object' ? JSON.stringify(args) : String(args);
    const result = cedarEvaluate({
      schema: CEDAR_SCHEMA,
      policies: CEDAR_POLICIES,
      agentId: CONFIG.agentId,
      toolName,
      command: `${toolName} ${command}`,
      domain: 'mcp',
      policyVersion: POLICY_VERSION,
    });

    if (result.error) {
      console.error(`[gate] Cedar evaluation error: ${result.error} — fail-closed`);
      return { action: 'deny', rule: 'cedar-error', riskScore: 100, severity: 'critical' };
    }

    const mapped = cedarMapAction(result, CEDAR_POLICY_ID_MAP);

    if (engine === 'both') {
      // Both engines: stricter result wins on divergence (DWP-01)
      const jsonResult = evaluatePolicy(toolName, args);
      if (jsonResult.action !== mapped.action) {
        console.log(`[gate] Engine divergence: JSON=${jsonResult.action} Cedar=${mapped.action} — stricter wins`);
        const order = { deny: 0, ask: 1, allow: 2 };
        return (order[mapped.action] ?? 1) <= (order[jsonResult.action] ?? 1) ? mapped : jsonResult;
      }
      return jsonResult;
    }

    return mapped;
  }

  // Unknown engine — fail-closed
  return { action: 'deny', rule: 'unknown-engine', riskScore: 100, severity: 'critical' };
}

// ─── Constitutional Validation (Second Authority Law) ──────────────────────
// Parity with bash gate validate_constitution() at bin/zlar-gate:991-1149.
// Called at startup AND on every tools/call to catch mid-run tamper. The
// validateConstitution module caches by constitution file hash, so the hot
// path is a single SHA-256 read.
//
// Fail-closed semantics: if the constitution has been deployed (presence
// tracker exists) and validation fails for any reason, the gate denies all
// subsequent tool calls until the condition is cleared. Pre-constitutional
// mode (no tracker) is an explicit pass state.
//
// Audit: one `constitution.invalid` event is emitted on each transition
// from ok → fail, so the audit trail records tamper events without spamming.

let MANIFEST = null;
let MANIFEST_LOAD_REASON = null;
let MANIFEST_HARD_DENY_REASON = null;
let CONSTITUTION_VALID = true;
let CONSTITUTION_FAIL_REASON = null;
let CONSTITUTION_LAST_OK = true;

function loadManifestAndValidateConstitution(emitOnChange = true) {
  // Reload manifest every time we revalidate — the manifest-deny set
  // participates in PC-05b and can change between tool calls if the
  // operator rotates it.
  const m = loadManifest(CONFIG.manifestFile, CONFIG.policyPubkey);
  if (m.ok) {
    MANIFEST = m.manifest;
    MANIFEST_LOAD_REASON = null;
    MANIFEST_HARD_DENY_REASON = null;
  } else {
    MANIFEST = null;
    MANIFEST_LOAD_REASON = m.reason;
    // Bash-gate parity (invariant #8): tampered / expired / parse-corrupt /
    // signed-but-unverifiable manifests are hard-deny. A missing manifest
    // file is the only no-manifest state that falls back to policy-only
    // (invariant #7). Anything that looks like active tampering denies.
    const reason = m.reason || '';
    const isMissing = reason === 'manifest file not found';
    MANIFEST_HARD_DENY_REASON = isMissing ? null : reason;
  }

  const result = validateConstitution({
    constitutionFile: CONFIG.constitutionFile,
    constitutionPubkey: CONFIG.constitutionPubkey,
    constitutionPresenceFile: CONFIG.constitutionPresenceFile,
    policyPubkey: CONFIG.policyPubkey,
    policy: POLICY,
    manifest: MANIFEST,
    restoreConfigFile: CONFIG.restoreConfigFile,
  });

  const wasOk = CONSTITUTION_LAST_OK;
  if (result.ok) {
    CONSTITUTION_VALID = true;
    CONSTITUTION_FAIL_REASON = null;
    CONSTITUTION_LAST_OK = true;
  } else {
    CONSTITUTION_VALID = false;
    CONSTITUTION_FAIL_REASON = result.reason;
    CONSTITUTION_LAST_OK = false;
    // Emit audit event only on ok → fail transition (not every call)
    if (emitOnChange && wasOk) {
      try {
        emitEvent('mcp', 'constitution.invalid', 'deny',
          { reason: result.reason, manifest_load: MANIFEST_LOAD_REASON },
          'constitution.invalid', 'critical', 100, 'gate');
      } catch (e) {
        auditInternalError('constitution_invalid_emit', e, { transition: 'ok_to_fail' });
      }
    }
  }
  return result;
}

// ─── Standing Approvals ──────────────────────────────────────────────────────
// Pre-authorized patterns that skip Telegram escalation. Same format as bash gate.
// Signed with policy key. Fail-soft: invalid/missing → no standing approvals (ask Telegram).

let STANDING_APPROVALS = [];
let STANDING_APPROVALS_LOADED = false;

function loadStandingApprovals() {
  const saFile = join(PROJECT_DIR, 'etc/standing-approvals.json');
  if (!existsSync(saFile)) return;

  try {
    const raw = JSON.parse(readFileSync(saFile, 'utf8'));

    // Signature required whenever the policy pubkey exists (parity with bash gate).
    // Unsigned / missing-signature standing approvals are refused — approvals disabled.
    if (existsSync(CONFIG.policyPubkey)) {
      if (!raw.signature?.value) {
        console.error('[gate] WARN: Standing approvals unsigned — approvals disabled');
        return;
      }
      const result = verifyJsonSignature(raw, CONFIG.policyPubkey);
      if (!result.ok) {
        console.error(`[gate] WARN: Standing approvals signature invalid (${result.reason}) — approvals disabled`);
        return;
      }
    }

    STANDING_APPROVALS = raw.approvals || [];
    STANDING_APPROVALS_LOADED = true;
    console.log(`[gate] Standing approvals loaded: ${STANDING_APPROVALS.length} entries`);
  } catch (e) {
    console.error(`[gate] WARN: Failed to load standing approvals: ${e.message}`);
  }
}

/**
 * Check if an action matches a standing approval.
 * @param {string} ruleId - The policy rule that triggered the ask
 * @param {string} toolName - The MCP tool name
 * @param {object} args - The tool arguments
 * @returns {{ match: boolean, approvalId: string|null }}
 */
function checkStandingApproval(ruleId, toolName, args) {
  if (!STANDING_APPROVALS_LOADED) return { match: false, approvalId: null };

  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const commandText = `${toolName} ${JSON.stringify(args)}`;

  for (const sa of STANDING_APPROVALS) {
    // Must match rule_id
    if (sa.rule_id !== ruleId) continue;

    // Check expiry
    if (sa.expires && today > sa.expires) continue;

    // Check match patterns
    const matcher = sa.match?.command;
    if (!matcher) continue;

    if (matcher.contains && commandText.includes(matcher.contains)) {
      return { match: true, approvalId: sa.id };
    }
    if (matcher.regex) {
      try {
        if (new RegExp(matcher.regex).test(commandText)) {
          return { match: true, approvalId: sa.id };
        }
      } catch (e) {
        // Invalid regex in a standing approval is an authoring bug worth
        // surfacing in the chain — otherwise a broken SA silently never
        // matches and the operator doesn't know why.
        auditInternalError('sa_regex_parse', e, { approval_id: sa.id, pattern: matcher.regex });
      }
    }
  }

  return { match: false, approvalId: null };
}

// ─── Audit Trail ─────────────────────────────────────────────────────────────

// Cache hostname/username at startup (not per-event — execSync is expensive)
const HOSTNAME = (() => { try { return execSync('hostname -s', { encoding: 'utf8' }).trim(); } catch { return 'unknown'; } })();
const USERNAME = (() => { try { return execSync('whoami', { encoding: 'utf8' }).trim(); } catch { return 'unknown'; } })();

let SEQ = 0;
let PREV_RECEIPT_HASH = null;
let SIGNING_KEY_PEM = null;
let SIGNING_KEY_ID = null;

// Audit-signing policy.
//
// The MCP gate defaults to STRICT signed audit: if the signing key is
// missing or signing fails, the gate refuses to write an audit entry
// rather than silently falling back to an unsigned one. This is the
// Jidoka inversion — easy to stop, hard to go. The audit chain is the
// only evidence that survives after everyone involved is dead; an
// unsigned entry is functionally equivalent to no entry for forensic
// purposes, so the right default is "no signature, no write."
//
// Bash gate defaults to advisory (ZLAR_REQUIRE_SIGNED_AUDIT=false) for
// historical parity; MCP flips it because the daemon shape of the MCP
// gate makes a silent signing failure much harder to notice in ops.
//
// To explicitly opt out (e.g., during testing without a signing key in
// place), set ZLAR_REQUIRE_SIGNED_AUDIT=false in the environment.
const REQUIRE_SIGNED_AUDIT = (process.env.ZLAR_REQUIRE_SIGNED_AUDIT || 'true').toLowerCase() !== 'false';

// Load signing key — used for both per-entry audit signing and receipt generation.
if (existsSync(CONFIG.signingKey)) {
  try {
    SIGNING_KEY_PEM = readFileSync(CONFIG.signingKey, 'utf8');
    if (existsSync(CONFIG.signingPubkey)) {
      SIGNING_KEY_ID = pubkeyFingerprint(CONFIG.signingPubkey);
    }
    console.log(`[gate] Signing key loaded (key_id: ${SIGNING_KEY_ID || 'unknown'})`);
  } catch (e) {
    console.error(`[gate] WARN: Cannot load signing key: ${e.message}`);
  }
}

// Startup fail-closed when strict mode is on and no key is available.
// Emitting events without a key would produce "unsigned" entries that
// pollute the chain; refusing to start is the only honest response.
if (REQUIRE_SIGNED_AUDIT && !SIGNING_KEY_PEM) {
  console.error('[gate] FATAL: ZLAR_REQUIRE_SIGNED_AUDIT is true (default) but no signing key is available at ' + CONFIG.signingKey);
  console.error('[gate] FATAL: Refusing to start — unsigned audit entries cannot be used as governance evidence.');
  console.error('[gate] FATAL: Either install a signing key, or set ZLAR_REQUIRE_SIGNED_AUDIT=false explicitly.');
  process.exit(1);
}

// Re-entry guard for auditInternalError. If the audit write path is the
// thing that threw, trying to emit another audit event from inside the
// catch would recurse. When this flag is set, auditInternalError falls
// back to stderr only.
let _AUDITING_INTERNAL_ERROR = false;

// Turn every caught exception into a signed audit event. The audit
// chain becomes the single source of truth for everything that
// happened in the gate, INCLUDING its own failures. An attacker who
// intentionally induces errors to muddy the record leaves MORE
// evidence behind, not less.
//
// Call sites replace bare `catch {}` and `catch (e) { console.error(e) }`.
// The `phase` argument names the code region so forensic analysts can
// cluster events (e.g., "policy_load", "sa_load", "hash_chain_read").
function auditInternalError(phase, err, detail) {
  const msg = err?.message || String(err);
  const stack = (err?.stack || '').substring(0, 500);
  console.error(`[gate] internal_error at ${phase}: ${msg}`);
  if (_AUDITING_INTERNAL_ERROR) {
    // Already in the middle of auditing an error — abort to avoid
    // recursion. Stderr is our only remaining channel.
    console.error(`[gate] internal_error recursion guard hit at ${phase}`);
    return;
  }
  _AUDITING_INTERNAL_ERROR = true;
  try {
    emitEvent('mcp', 'gate.internal_error', 'logged',
      { phase, error: msg, stack, ...(detail && typeof detail === 'object' ? detail : {}) },
      'gate.internal_error', 'warn', 0, 'gate:internal_error');
  } catch (e2) {
    console.error(`[gate] FATAL: auditInternalError write failed: ${e2.message}`);
  } finally {
    _AUDITING_INTERNAL_ERROR = false;
  }
}

function genId() {
  const hexTs = Math.floor(Date.now() / 1000).toString(16);
  const rand = randomBytes(16).toString('hex');
  return `${hexTs}-${rand}`;
}

// emitEvent is intentionally synchronous (DWP-01 defensive note):
// 1. All operations (readFileSync, createHash, cryptoSign, appendFileSync) are sync
// 2. Node.js event loop does not yield during synchronous code — no hash-chain
//    race is possible in a single-process architecture
// 3. Crash handlers (uncaughtException, unhandledRejection) rely on synchronous
//    completion to ensure audit events are written before process.exit()
// If any async operation is added to this function in the future, add an
// in-process mutex to serialize access and prevent hash-chain forks.
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
    } catch (e) {
      // If we can't compute prev_hash the chain continuity is broken —
      // worth logging loudly. Don't call auditInternalError from inside
      // emitEvent (recursion); guard catches this but stderr is cleaner.
      console.error(`[gate] WARN: prev_hash computation failed: ${e.message}`);
    }
  }

  const event = {
    id: genId(),
    ts,
    seq: SEQ,
    source: 'mcp-gate',
    host: HOSTNAME,
    user: USERNAME,
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
    public_key_id: SIGNING_KEY_ID || PUBLIC_KEY_ID,
  };

  // Per-entry Ed25519 signing (SP 800-53 AU-10 non-repudiation).
  // Matches bash gate: canonical → SHA-256 hex → sign hex bytes → base64.
  //
  // Strict mode (default): if signing is configured but fails at
  // runtime, REFUSE to write the entry. An unsigned row in the chain
  // is worse than no row — it looks like evidence but isn't.
  let signature = 'unsigned';
  let signingFailed = false;
  if (SIGNING_KEY_PEM) {
    try {
      const hashHex = sha256hex(canonicalize(event));
      const sig = cryptoSign(null, Buffer.from(hashHex, 'utf8'), SIGNING_KEY_PEM);
      signature = sig.toString('base64');
    } catch (e) {
      signingFailed = true;
      console.error(`[gate] CRITICAL: Audit entry signing failed: ${e.message}`);
    }
  }

  if (REQUIRE_SIGNED_AUDIT && (signature === 'unsigned' || signingFailed)) {
    // In strict mode we bail rather than pollute the chain with an
    // entry a forensic analyst cannot verify. The recursion guard in
    // auditInternalError means we can safely throw here without
    // re-entering emitEvent.
    const reason = signingFailed ? 'runtime-signing-failed' : 'no-signing-key';
    console.error(`[gate] CRITICAL: Refusing to write unsigned audit entry (ZLAR_REQUIRE_SIGNED_AUDIT=true, reason=${reason})`);
    throw new Error(`audit-write-refused: ${reason}`);
  }

  event.signature = signature;

  try {
    appendFileSync(CONFIG.auditFile, JSON.stringify(event) + '\n');
  } catch (e) {
    console.error(`[gate] CRITICAL: Failed to write audit event: ${e.message}`);
    if (REQUIRE_SIGNED_AUDIT) throw e;
  }

  // Generate receipt only for schema-valid outcomes. Audit-only events
  // ("pending", "logged", diagnostic system events) are not minted as
  // receipts — receipts carry governance decisions, not observability.
  const RECEIPT_OUTCOMES = new Set(['allow', 'deny', 'authorized', 'denied', 'timeout']);
  if (CONFIG.emitReceipts && SIGNING_KEY_PEM && SIGNING_KEY_ID && RECEIPT_OUTCOMES.has(outcome) && event.rule) {
    try {
      const receipt = createReceiptFromEvent(event, {
        prev_receipt_hash: PREV_RECEIPT_HASH,
      });
      const signed = signReceipt(receipt, SIGNING_KEY_PEM, SIGNING_KEY_ID);
      appendFileSync(CONFIG.receiptFile, JSON.stringify(signed) + '\n');
      PREV_RECEIPT_HASH = receiptHash(signed);
    } catch (e) {
      console.error(`[gate] WARN: Receipt generation failed: ${e.message}`);
    }
  }

  return event;
}

// ─── Inbox HMAC Verification ─────────────────────────────────────────────────

const HMAC_SECRET_FILE = '/var/run/zlar-tg/inbox-hmac-secret';

function loadHmacSecret() {
  if (!existsSync(HMAC_SECRET_FILE)) return null;
  try {
    return readFileSync(HMAC_SECRET_FILE, 'utf8').trim();
  } catch { return null; }
}

function verifyInboxHmac(data, fromId, cbId, expectedHmac) {
  const secret = loadHmacSecret();
  if (!secret || !expectedHmac) return false;
  const computed = createHmac('sha256', secret)
    .update(`${data}|${fromId}|${cbId}`)
    .digest('base64');
  try {
    return timingSafeEqual(Buffer.from(computed), Buffer.from(expectedHmac));
  } catch { return false; }  // length mismatch
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

// Consequence line — what happens if the human approves the wrong thing.
// Keyed on rule family. Fallback uses risk score.
function getConsequenceLine(toolName, rule, riskScore) {
  if (toolName === 'SubagentStart') return '⚠️ *If wrong:* you are approving an authority branch — downstream actions not individually foreseeable';
  const r = rule || '';
  if (r.startsWith('R002')) return '⚠️ *If wrong:* irreversible file deletion';
  if (r.startsWith('R003')) return '⚠️ *If wrong:* system-level privilege granted to agent';
  if (/^R00[45]/.test(r)) return '⚠️ *If wrong:* arbitrary code execution via shell escape';
  if (/^R00[67]/.test(r)) return '⚠️ *If wrong:* network boundary crossed — data may leave';
  if (/^R00[89]/.test(r)) return '⚠️ *If wrong:* package installation — supply chain risk';
  if (/^R01[01]/.test(r)) return '⚠️ *If wrong:* code execution via interpreter escape';
  if (r.startsWith('R012')) return '⚠️ *If wrong:* governance infrastructure modified';
  if (/^R01[34]/.test(r)) return '⚠️ *If wrong:* network command — data may exit perimeter';
  if (/^R031|^R041I/.test(r)) return '⚠️ *If wrong:* secrets modified — may propagate to services';
  if (/^R033/.test(r)) return '⚠️ *If wrong:* system configuration altered';
  if (/^R034|^R041H/.test(r)) return '⚠️ *If wrong:* shell environment altered — persists across sessions';
  if (/^R035|^R041J/.test(r)) return '⚠️ *If wrong:* credentials overwritten or exposed';
  if (/^R032|^R041/.test(r)) return '⚠️ *If wrong:* agent governance rules may be modified';
  if (/^R05[012]/.test(r)) return '⚠️ *If wrong:* sensitive material exposed to agent context';
  if (r.startsWith('R080')) return '⚠️ *If wrong:* new autonomous agent spawned';
  if (/^R09[05]/.test(r)) return '⚠️ *If wrong:* external service contacted — data may be shared';
  if (riskScore >= 70) return `⚠️ *If wrong:* high-consequence action (risk ${riskScore}/100)`;
  return '⚠️ *If wrong:* unreviewed action';
}

async function telegramAsk(actionId, toolName, args, rule, riskScore, severity, verifyHint = '', flags = {}) {
  if (!CONFIG.telegramToken || !CONFIG.telegramChatId) {
    console.error('[gate] No Telegram token or chat ID — cannot ask human');
    return 'error';
  }

  const emoji = severity === 'critical' ? '🔴' : severity === 'warn' ? '🟡' : '⚡';
  const argsPreview = JSON.stringify(args).substring(0, 80) + (JSON.stringify(args).length > 80 ? '…' : '');
  const consequenceLine = getConsequenceLine(toolName, rule, riskScore);

  // Agent intent: .description from Bash tool_input. Shows why the agent ran this.
  const intentRaw = (toolName === 'Bash' && args?.description) ? String(args.description).substring(0, 120) : '';
  const intentLine = intentRaw ? `\n📋 *Context:* ${intentRaw}` : '';

  // Verify hint: policy-authored check prompt for this rule.
  const verifyLine = verifyHint ? `\n🔍 *Verify:* ${verifyHint}` : '';

  // Novelty banner: first use of this tool this session.
  const noveltyLine = flags.novelty ? `\n🆕 *First use this session* — extra care.` : '';

  // Advisory banner: human invariants flagged this ask but we're asking anyway.
  const advisoryLine = flags.advisory
    ? `\n⚠️ *Advisory:* ${flags.advisory} (routed anyway — you decide)`
    : '';

  // Message layout mirrors bash gate v2.8.1: consequence first, intent (if present),
  // verify hint (if present), action for context, rule+risk as compact metadata at bottom.
  const text = `${emoji} 🔷 *${rule}*\n\n${consequenceLine}${intentLine}${verifyLine}${noveltyLine}${advisoryLine}\n\n*MCP:* \`${argsPreview}\`\nRisk ${riskScore}/100`;
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
          const cbId = cb.callback_query_id || '';
          const cbHmac = cb.hmac || '';

          if (cbFrom !== CONFIG.telegramChatId) {
            unlinkSync(filePath);
            continue;
          }

          // Verify HMAC integrity
          if (!verifyInboxHmac(cbData, cbFrom, cbId, cbHmac)) {
            console.error(`[gate] SECURITY: inbox HMAC mismatch: ${file}`);
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
        } catch (e) {
          // Malformed inbox file — delete and move on, but record the
          // fact. A poisoned inbox could otherwise be a silent denial-of-
          // service on callback processing.
          try { unlinkSync(filePath); } catch {}
          auditInternalError('inbox_file_parse', e, { file });
        }
      }
    } catch (e) {
      auditInternalError('inbox_loop_read', e);
    }

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

  // Reload policy / standing approvals if the files changed since last read.
  // The MCP gate is long-running; bash-gate parity requires that an operator
  // rotating policy without restarting the gate takes effect immediately.
  maybeReloadPolicyAndSA();

  // Second Authority Law: re-validate constitution + manifest before every
  // tool call. Cheap in the happy path (hash cache hit); catches mid-run
  // tamper (constitution deleted, manifest replaced, etc.).
  loadManifestAndValidateConstitution(true);
  if (!CONSTITUTION_VALID) {
    emitEvent('mcp', toolName, 'deny',
      { tool: toolName, reason: 'constitution_invalid', detail: CONSTITUTION_FAIL_REASON },
      'constitution.invalid', 'critical', 100, 'gate');
    return {
      action: 'deny',
      response: {
        jsonrpc: '2.0',
        id: msg.id,
        error: {
          code: -32600,
          message: `[gate] Constitutional validation failed (${CONSTITUTION_FAIL_REASON}) — denied (fail-closed)`,
        },
      },
    };
  }

  // Manifest hard-deny (invariant #8): tamper / expiry / corrupt-parse /
  // signed-but-unverifiable manifests deny every tool call until resolved.
  // A missing manifest (invariant #7) falls through to policy-only.
  if (MANIFEST_HARD_DENY_REASON) {
    emitEvent('mcp', toolName, 'deny',
      { tool: toolName, reason: 'manifest_hard_deny', detail: MANIFEST_HARD_DENY_REASON },
      'manifest:tampered', 'critical', 100, 'manifest');
    return {
      action: 'deny',
      response: {
        jsonrpc: '2.0',
        id: msg.id,
        error: {
          code: -32600,
          message: `[gate] Manifest invalid (${MANIFEST_HARD_DENY_REASON}) — denied (fail-closed per invariant 8)`,
        },
      },
    };
  }

  // Runtime manifest-authority enforcement (parity with bin/zlar-gate lines 2175-2234)
  // Classifies the tool call into a capability category and consults the
  // manifest's deny/allow/unmatched_action. Deny always wins; unmatched actions
  // either deny outright or flag for ask-override after policy evaluation.
  // The manifest narrows policy, never widens.
  const manifestDecision = enforceManifestAuthority(toolName, MANIFEST);
  if (manifestDecision.action === 'deny') {
    emitEvent('mcp', toolName, 'deny',
      { tool: toolName, cap: manifestDecision.cap, args_preview: JSON.stringify(args).substring(0, 200) },
      manifestDecision.rule, manifestDecision.severity, manifestDecision.riskScore, manifestDecision.authorizer);
    return {
      action: 'deny',
      response: {
        jsonrpc: '2.0',
        id: msg.id,
        error: {
          code: -32600,
          message: `[manifest] Blocked by rule ${manifestDecision.rule}: Action denied by capability manifest (category: ${manifestDecision.cap})`,
        },
      },
    };
  }
  const manifestForcesAsk = manifestDecision.action === 'force_ask';

  // Evaluate policy (JSON, Cedar, or both — depending on CONFIG.policyEngine)
  const evaluation = evaluatePolicyDual(toolName, args);
  console.log(`[gate] Policy: ${evaluation.rule} → ${evaluation.action} (risk ${evaluation.riskScore})`);

  // Manifest escalation override (parity with bin/zlar-gate lines 2240-2246).
  // If manifest flagged the capability as unmatched-with-escalate and policy
  // would have allowed or logged, force the final action to "ask". Manifest
  // narrows policy, never widens — deny stays deny, ask stays ask.
  if (manifestForcesAsk && (evaluation.action === 'allow' || evaluation.action === 'log')) {
    console.log(`[gate] MANIFEST: Overriding policy ${evaluation.action} → ask (${manifestDecision.cap} not in manifest allow list)`);
    evaluation.action = 'ask';
  }

  // Novelty escalation (parity with bin/zlar-gate lines 244-276).
  // First occurrence of a given tool this session escalates allow → ask.
  // Threat model: a fresh injection attempt typically targets a fresh-shaped
  // capability — by asking on first use, we catch that window. Subsequent
  // calls of the same tool proceed under normal policy. Session-scoped on
  // purpose: across sessions the alarm resets so a previously-compromised
  // session can't grant future sessions a free pass.
  const noveltyKey = toolName;
  const isNovel = !SEEN_TOOLS.has(noveltyKey);
  if (isNovel) {
    SEEN_TOOLS.add(noveltyKey);
    if (evaluation.action === 'allow' || evaluation.action === 'log') {
      console.log(`[gate] NOVELTY: First use of "${noveltyKey}" this session — escalating to ask`);
      evaluation.action = 'ask';
      evaluation.noveltyEscalated = true;
    }
  }

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
      // Check standing approvals before escalating to human
      const sa = checkStandingApproval(evaluation.rule, toolName, args);
      if (sa.match) {
        console.log(`[gate] Standing approval ${sa.approvalId} matched — auto-allow`);
        emitEvent('mcp', toolName, 'allow', { tool: toolName, args_preview: JSON.stringify(args).substring(0, 200), standing_approval: sa.approvalId },
          evaluation.rule, evaluation.severity, evaluation.riskScore, `standing:${sa.approvalId}`);
        return { action: 'passthrough', msg };
      }

      // Human invariant pre-ask checks (H6, H13, H14).
      //
      // Advisory semantics (bash-gate parity): if a pre-check trips, we
      // LOG the condition and emit a warning audit event, but we still
      // route the ask to the human. Denying here would silence the
      // human's own channel — an attacker who can provoke rapid failing
      // asks could use that as a denial-of-service on legitimate work.
      // The human is the authority; surface the condition to them and
      // let them judge.
      const humanId = CONFIG.telegramChatId || 'unknown';
      const hiPre = preAskCheck(humanId);
      if (!hiPre.ok) {
        console.log(`[gate] Human invariant ADVISORY: ${hiPre.reason} (${hiPre.detail}) — routing anyway`);
        emitEvent('mcp', toolName, 'logged',
          { tool: toolName, reason: `human_${hiPre.reason}`, detail: hiPre.detail, advisory: true },
          'human_invariant.advisory', 'warn', 0, `gate:human_${hiPre.reason}`);
      }

      // H15: Record ask time for deliberation floor check
      recordAskTime(humanId);

      const actionId = genId();
      const askFlags = {
        novelty: !!evaluation.noveltyEscalated,
        advisory: hiPre.ok ? null : `${hiPre.reason} — ${hiPre.detail}`,
      };
      const decision = await telegramAsk(actionId, toolName, args, evaluation.rule, evaluation.riskScore, evaluation.severity, evaluation.verifyHint || '', askFlags);

      switch (decision) {
        case 'allow': {
          // Human invariant post-response checks (H15, H17)
          const hiPost = postResponseCheck(humanId, evaluation.severity, 'approve');
          if (!hiPost.ok) {
            console.log(`[gate] Human invariant: approval rejected (${hiPost.reason})`);
            emitEvent('mcp', toolName, 'denied', { tool: toolName, reason: `human_${hiPost.reason}`, detail: hiPost.detail },
              evaluation.rule, evaluation.severity, evaluation.riskScore, `gate:human_${hiPost.reason}`);
            return {
              action: 'deny',
              response: {
                jsonrpc: '2.0', id: msg.id,
                error: { code: -32600, message: `[gate] Approval not accepted (${hiPost.reason}). Please review again with more time.` },
              },
            };
          }
          emitEvent('mcp', toolName, 'authorized', { tool: toolName, args_preview: JSON.stringify(args).substring(0, 200) },
            evaluation.rule, evaluation.severity, evaluation.riskScore, `human:${CONFIG.telegramChatId}`);
          return { action: 'passthrough', msg };
        }

        case 'deny': {
          // Record denial for H14 rate tracking
          try { recordDecision(humanId, 'deny'); } catch {}
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
        }

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
      // Fail-closed: unknown policy action → deny (never passthrough on unknown)
      emitEvent('mcp', toolName, 'deny', { tool: toolName, reason: `unknown policy action: ${evaluation.action}` },
        evaluation.rule, 'critical', 100, 'gate');
      return {
        action: 'deny',
        response: {
          jsonrpc: '2.0',
          id: msg.id,
          error: { code: -32600, message: `[gate] Unknown policy action "${evaluation.action}" — denied (fail-closed)` },
        },
      };
  }
}

// ─── TCP Proxy Mode ──────────────────────────────────────────────────────────

function startTcpProxy() {
  if (!CONFIG.upstreamHost || !CONFIG.upstreamPort) {
    console.error('[gate] --upstream host:port required for TCP mode');
    process.exit(1);
  }

  loadPolicy();
  try {
    if (existsSync(CONFIG.policyFile)) POLICY_MTIME_MS = statSync(CONFIG.policyFile).mtimeMs;
  } catch {}
  loadStandingApprovals();
  try {
    const saFile = join(PROJECT_DIR, 'etc/standing-approvals.json');
    if (existsSync(saFile)) STANDING_APPROVALS_MTIME_MS = statSync(saFile).mtimeMs;
  } catch {}
  loadCedar();
  // Second Authority Law: validate constitution + manifest after policy is loaded.
  // Fails-closed at startup if a deployed constitution is tampered / deleted.
  loadManifestAndValidateConstitution(false);
  if (!CONSTITUTION_VALID) {
    console.error(`[gate] CRITICAL: Constitutional validation failed at startup — fail-closed: ${CONSTITUTION_FAIL_REASON}`);
  }

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
      console.error(`[gate] Upstream error: ${e.message} — fail-closed`);
      emitEvent('mcp', 'upstream.error', 'deny', { error: e.message },
        'upstream.error', 'critical', 100, 'gate');
      // Send JSON-RPC error for any pending requests, then close
      try {
        clientSocket.write(JSON.stringify({
          jsonrpc: '2.0', id: null,
          error: { code: -32603, message: '[gate] Upstream unavailable — denied (fail-closed)' }
        }) + '\n');
      } catch (we) {
        auditInternalError('upstream_error_reply_write', we);
      }
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
    console.log(`[gate] Policy engine: ${CONFIG.policyEngine}${CEDAR_LOADED ? ` (Cedar ${cedarVersion()})` : ''}`);

    emitEvent('mcp', 'gate.start', 'allow', { port: CONFIG.port, upstream: `${CONFIG.upstreamHost}:${CONFIG.upstreamPort}`, session_id: CONFIG.sessionId },
      'gate.start', 'info', 0, 'gate');
  });

  // End-of-session anchor. On clean shutdown we emit one last signed
  // event carrying the session id and the current prev_hash. Any later
  // entry claiming to belong to this session is provably forged: the
  // chain is sealed. Pair with the gate.start event to bound the
  // session from both sides. Kept synchronous so the signature lands
  // before process.exit returns.
  function sealSession(signal) {
    try {
      emitEvent('mcp', 'gate.session_sealed', 'allow',
        { session_id: CONFIG.sessionId, signal, seq_final: SEQ + 1 },
        'gate.session_sealed', 'info', 0, 'gate');
    } catch (e) {
      console.error(`[gate] WARN: session_sealed event failed: ${e.message}`);
    }
  }

  process.on('SIGINT', () => {
    sealSession('SIGINT');
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    sealSession('SIGTERM');
    process.exit(0);
  });
}

// ─── Fail-Closed: Uncaught Exception Handler ────────────────────────────────
// Any unhandled error → log and deny. The gate must never silently pass through.

process.on('uncaughtException', (err) => {
  console.error(`[gate] CRITICAL: Uncaught exception — gate will deny all: ${err.message}`);
  try {
    emitEvent('mcp', 'gate.crash', 'deny', { error: err.message, stack: (err.stack || '').substring(0, 500) },
      'gate.crash', 'critical', 100, 'gate');
  } catch {}
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error(`[gate] CRITICAL: Unhandled rejection — gate will deny all: ${reason}`);
  try {
    emitEvent('mcp', 'gate.crash', 'deny', { error: String(reason) },
      'gate.crash', 'critical', 100, 'gate');
  } catch {}
  process.exit(1);
});

// ─── Entry Point ─────────────────────────────────────────────────────────────

if (!CONFIG.upstreamHost) {
  console.error('[gate] Specify --upstream host:port');
  process.exit(1);
}

startTcpProxy();
