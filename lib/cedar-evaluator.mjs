// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Cedar Evaluator — Production-grade Cedar WASM policy evaluation
//
// Wraps the Cedar WASM SDK into a ZLAR-specific evaluation module.
// Shared by: MCP gate (import), test suites, standalone evaluation.
//
// Cedar is default-deny. Forbid wins. This matches ZLAR's fail-closed
// architecture (ADR-003). The evaluator maps ZLAR's gate model to Cedar's
// principal/action/resource/context model.
//
// Dependencies: @cedar-policy/cedar-wasm (vendored in cedar-poc/vendor/)
// ═══════════════════════════════════════════════════════════════════════════════

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const CEDAR_POC_DIR = join(__dirname, '..', 'cedar-poc');

// Import Cedar WASM from vendored location
let cedar = null;
try {
  cedar = await import(join(CEDAR_POC_DIR, 'vendor', '@cedar-policy', 'cedar-wasm', 'nodejs', 'cedar_wasm.js'));
} catch (e) {
  // Cedar not available — evaluator will report unavailable
}

// ─── Cedar Availability ──────────────────────────────────────────────────────

export function cedarAvailable() {
  return cedar !== null;
}

export function cedarVersion() {
  if (!cedar) return 'unavailable';
  return cedar.getCedarVersion?.() || 'unknown';
}

// ─── Policy Loading ──────────────────────────────────────────────────────────

/**
 * Load and validate Cedar policies + schema.
 *
 * @param {object} opts
 * @param {string} opts.schema - Cedar schema string
 * @param {string} opts.policies - Cedar policy string (can be multiple files concatenated)
 * @returns {{ ok: boolean, error?: string }}
 */
export function validatePolicies(opts) {
  if (!cedar) return { ok: false, error: 'Cedar WASM not available' };

  try {
    const result = cedar.validate({
      schema: opts.schema,
      policies: { staticPolicies: opts.policies },
      validationSettings: { mode: 'strict' },
    });

    if (result.type === 'failure') {
      const errors = result.errors?.map(e => e.message || JSON.stringify(e)).join('; ');
      return { ok: false, error: `Validation failed: ${errors}` };
    }

    if (result.validationErrors?.length > 0) {
      const errors = result.validationErrors.map(e => `[${e.policyId}] ${e.error?.message || e}`).join('; ');
      return { ok: false, error: `Policy errors: ${errors}` };
    }

    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ─── Policy Evaluation ───────────────────────────────────────────────────────

/**
 * Evaluate a tool call against Cedar policies.
 *
 * Maps ZLAR's gate model to Cedar's authorization model:
 *   principal = ZLAR::Agent (the agent requesting)
 *   action    = ZLAR::Action::"evaluate"
 *   resource  = ZLAR::ToolCall (the tool call being evaluated)
 *   context   = { domain, severity, policy_version }
 *
 * @param {object} opts
 * @param {string} opts.schema - Cedar schema string
 * @param {string} opts.policies - Cedar policy string
 * @param {string} opts.agentId - Agent identifier
 * @param {string} opts.toolName - Tool name (used as part of command or resource ID)
 * @param {string} opts.command - For bash domain: the full command string
 * @param {string} [opts.path=''] - For file domains: the file path
 * @param {number} [opts.riskScore=0] - Computed risk score
 * @param {string} opts.domain - Policy domain (bash, file, network, mcp, etc.)
 * @param {string} [opts.severity='info'] - Severity level
 * @param {string} [opts.policyVersion='unknown'] - Policy version
 * @returns {{ decision: 'allow'|'deny', reasons: string[], diagnostics: object, error?: string }}
 */
export function evaluate(opts) {
  if (!cedar) {
    return { decision: 'deny', reasons: ['cedar-unavailable'], diagnostics: {}, error: 'Cedar WASM not available' };
  }

  const callId = `call-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;

  try {
    const result = cedar.isAuthorized({
      principal: { type: 'ZLAR::Agent', id: opts.agentId || 'unknown' },
      action: { type: 'ZLAR::Action', id: 'evaluate' },
      resource: { type: 'ZLAR::ToolCall', id: callId },
      context: {
        domain: opts.domain || 'unknown',
        severity: opts.severity || 'info',
        policy_version: opts.policyVersion || 'unknown',
      },
      schema: opts.schema,
      validateRequest: true,
      policies: { staticPolicies: opts.policies },
      entities: [
        {
          uid: { type: 'ZLAR::Agent', id: opts.agentId || 'unknown' },
          attrs: {},
          parents: [],
        },
        {
          uid: { type: 'ZLAR::ToolCall', id: callId },
          attrs: {
            command: opts.command || '',
            path: opts.path || '',
            risk_score: opts.riskScore || 0,
          },
          parents: [],
        },
      ],
    });

    if (result.type === 'failure') {
      const errors = result.errors?.map(e => e.message).join('; ');
      return { decision: 'deny', reasons: ['evaluation-error'], diagnostics: {}, error: errors };
    }

    return {
      decision: result.response.decision, // 'allow' or 'deny'
      reasons: result.response.diagnostics?.reason || [],
      diagnostics: result.response.diagnostics || {},
    };
  } catch (e) {
    // Fail-closed: any evaluation error → deny
    return { decision: 'deny', reasons: ['exception'], diagnostics: {}, error: e.message };
  }
}

// ─── Policy ID Mapping ───────────────────────────────────────────────────────
// Cedar WASM returns internal IDs like "policy3" in diagnostics.reason.
// We need to map these back to @id annotations (e.g., "R002-a").

function buildPolicyIdMap(policyText) {
  const map = {};
  let index = 0;
  // Match @id("...") annotations — only those that are actual Cedar annotations,
  // not references in comments. Cedar @id appears at the start of a line (with
  // optional whitespace). Lines starting with // are comments.
  const lines = policyText.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    // Skip comment lines
    if (trimmed.startsWith('//')) continue;
    const match = trimmed.match(/^@id\("([^"]+)"\)/);
    if (match) {
      map[`policy${index}`] = match[1];
      index++;
    }
  }
  return map;
}

// ─── Convenience: Load policies from files ───────────────────────────────────

/**
 * Load all ZLAR Cedar policies from the standard file locations.
 *
 * @param {object} [opts]
 * @param {string} [opts.cedarDir] - Cedar policy directory (default: cedar-poc/)
 * @param {string[]} [opts.policyFiles] - Policy files to load (default: all .cedar files)
 * @param {string} [opts.schemaFile] - Schema file (default: zlar.cedarschema)
 * @returns {{ schema: string, policies: string, files: string[] } | null}
 */
export function loadPoliciesFromFiles(opts = {}) {
  const cedarDir = opts.cedarDir || CEDAR_POC_DIR;
  const schemaFile = opts.schemaFile || join(cedarDir, 'zlar.cedarschema');

  if (!existsSync(schemaFile)) return null;

  const schema = readFileSync(schemaFile, 'utf8');

  // Load specified files or all .cedar files
  const policyFiles = opts.policyFiles || [
    join(cedarDir, 'zlar.cedar'),
    join(cedarDir, 'zlar-p1.cedar'),
    join(cedarDir, 'zlar-p2.cedar'),
  ];

  const loaded = [];
  const policyParts = [];
  for (const f of policyFiles) {
    if (existsSync(f)) {
      policyParts.push(readFileSync(f, 'utf8'));
      loaded.push(f);
    }
  }

  if (policyParts.length === 0) return null;

  const policies = policyParts.join('\n\n');
  return {
    schema,
    policies,
    files: loaded,
    policyIdMap: buildPolicyIdMap(policies),
  };
}

// ─── Map Cedar decision to ZLAR gate action ──────────────────────────────────

/**
 * Interpret a Cedar evaluation result as a ZLAR gate action.
 *
 * Cedar has two outcomes: allow and deny.
 * ZLAR has four: allow, deny, ask, log.
 *
 * Mapping:
 *   - Cedar allow → ZLAR allow
 *   - Cedar deny with P1 determining policy → ZLAR deny (hard block)
 *   - Cedar deny with P2 determining policy → ZLAR ask (escalate to human)
 *   - Cedar deny with no determining policy (default deny) → ZLAR deny
 *
 * Cedar WASM returns internal IDs (e.g., "policy3") in diagnostics.reason.
 * The policyIdMap translates these to @id annotations (e.g., "R002-a").
 *
 * @param {{ decision: string, reasons: string[] }} result
 * @param {object} [policyIdMap] - Map from "policyN" to @id annotation
 * @returns {{ action: 'allow'|'deny'|'ask', rule: string, severity: string, riskScore: number }}
 */
export function mapToGateAction(result, policyIdMap = {}) {
  if (result.decision === 'allow') {
    const rawId = result.reasons?.[0] || 'cedar-allow';
    const rule = policyIdMap[rawId] || rawId;
    return { action: 'allow', rule, severity: 'info', riskScore: 0 };
  }

  // Resolve Cedar internal IDs to @id annotations
  const reasons = (result.reasons || []).map(r => policyIdMap[r] || r);

  // Priority 1 rules: hard deny
  const P1_PREFIXES = ['R002', 'R003', 'R005', 'R006', 'R007', 'R012'];
  const p1Match = reasons.find(r => P1_PREFIXES.some(p => r.startsWith(p)));
  if (p1Match) {
    const ruleBase = p1Match.split('-')[0]; // R002-a → R002
    return { action: 'deny', rule: ruleBase, severity: 'critical', riskScore: 100 };
  }

  // Priority 2 rules: escalate to human
  const P2_PREFIXES = ['R014', 'R016'];
  const p2Match = reasons.find(r => P2_PREFIXES.some(p => r.startsWith(p)));
  if (p2Match) {
    const ruleBase = p2Match.split('-')[0];
    return { action: 'ask', rule: ruleBase, severity: 'warn', riskScore: 80 };
  }

  // Default deny (no matching rule → Cedar default-deny)
  return { action: 'deny', rule: 'cedar-default', severity: 'info', riskScore: 0 };
}
