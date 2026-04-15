// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR MCP Gate — Runtime Manifest-Authority Enforcement
//
// Ports bin/zlar-gate lines 2175-2246 (the dedicated manifest-enforcement block,
// not to be confused with the policy-rule evaluation that follows). The bash
// gate classifies every tool call into a capability category and consults the
// manifest's authority.deny / authority.allow / unmatched_action. Deny always
// wins; unmatched actions either deny or escalate; policy evaluation runs next;
// if the manifest forced escalation and policy said allow/log, the final action
// is overridden to "ask". The manifest narrows policy, never widens.
//
// MCP gate classification is coarse: every MCP-served tool call maps to
// "mcp.call", matching bash gate's DOMAIN=mcp → _cap_category=mcp.call mapping
// (bin/zlar-gate line 2200). Finer classification (per-server taxonomies like
// filesystem:write_* → file.write) is a future upgrade; coarse parity closes
// the immediate gap between the two enforcement surfaces.
//
// Audit event shape is bash-parity for cross-gate receipt compatibility:
//   rule "manifest:deny"       severity warn  risk_score 80  authorizer manifest
//   rule "manifest:unmatched"  severity warn  risk_score 60  authorizer manifest
//
// unmatched_action safety: any value other than "deny" or "escalate" fails closed
// (deny). Silently passing on unrecognized values was a latent bypass — fixed in
// both gates simultaneously.
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Classify an MCP tool call into a capability-surface category.
 *
 * Coarse classification: every MCP-served tool is "mcp.call". This matches
 * bash gate's DOMAIN=mcp → _cap_category=mcp.call mapping at line 2200 of
 * bin/zlar-gate. Finer-grained classification (e.g., filesystem:write_* →
 * file.write) is a future upgrade when per-server taxonomies become
 * necessary. For now, coarse parity is the right scope.
 *
 * @param {string} toolName - Tool name from tools/call.params.name
 * @returns {string} Capability category string (always "mcp.call")
 */
export function classifyMcpTool(toolName) {
  // Future: per-server mapping here. For now, coarse bash-parity.
  return 'mcp.call';
}

/**
 * Evaluate a tool call against manifest authority rules.
 *
 * Parity with bin/zlar-gate lines 2175-2234. Returns one of three decisions:
 *
 *   { action: 'pass' }       — manifest permits or no manifest loaded
 *   { action: 'deny', ... }  — capability on deny list, or unmatched with
 *                              unmatched_action=deny. Carries rule/severity/
 *                              riskScore/authorizer for emitEvent.
 *   { action: 'force_ask' }  — capability unmatched with unmatched_action=
 *                              escalate. Caller runs policy evaluation, then
 *                              if policy said allow/log, overrides to ask.
 *
 * Prefix-match semantics (bash line 2206, 2217):
 *   entry matches cap iff entry === cap OR cap.startsWith(entry + ".")
 *   Example: deny entry "bash" matches cap "bash.dangerous"
 *   Example: deny entry "mcp.call" matches cap "mcp.call" (exact)
 *
 * @param {string} toolName       - Tool name (for future granular classification)
 * @param {object|null} manifest  - Loaded manifest, or null if not loaded
 * @returns {object} Decision object; see above
 */
export function enforceManifestAuthority(toolName, manifest) {
  // No manifest → skip enforcement (bash line 2172: MANIFEST_LOADED=false skip).
  // The bash gate's manifest-load path has its own reporting; here we match
  // the coarse-grained "no-enforcement" path. Manifest-load failure is surfaced
  // elsewhere (loadManifestAndValidateConstitution in gate.mjs).
  //
  // Defensive: typeof-object check also early-returns for non-object manifests
  // (numbers, strings, booleans) that callers could hand us by mistake. In
  // current gate.mjs flow, MANIFEST is either null or a parsed JSON object, so
  // this path is theoretical — but keeps a caller-contract error from silently
  // degrading to "MCP tools need asking" (which is what falls through otherwise).
  if (!manifest || typeof manifest !== 'object') {
    return { action: 'pass', reason: 'no-manifest', cap: null };
  }

  const cap = classifyMcpTool(toolName);
  const deny = manifest.authority?.deny || [];
  const allow = manifest.authority?.allow || [];
  const unmatched = manifest.authority?.unmatched_action || 'escalate';

  // Deny always wins (bash line 2207).
  if (deny.some(d => typeof d === 'string' && (d === cap || cap.startsWith(d + '.')))) {
    return {
      action: 'deny',
      rule: 'manifest:deny',
      severity: 'warn',
      riskScore: 80,
      authorizer: 'manifest',
      cap,
    };
  }

  // Allow list check (bash line 2218).
  const inAllow = allow.some(a => typeof a === 'string' && (a === cap || cap.startsWith(a + '.')));
  if (!inAllow) {
    if (unmatched === 'deny') {
      return {
        action: 'deny',
        rule: 'manifest:unmatched',
        severity: 'warn',
        riskScore: 60,
        authorizer: 'manifest',
        cap,
      };
    }
    if (unmatched === 'escalate') {
      return {
        action: 'force_ask',
        rule: 'manifest:unmatched',
        cap,
      };
    }
    // Unknown unmatched_action value → fail closed (deny). Any value other than
    // "deny" or "escalate" is a misconfiguration. Silently passing would be a
    // security bypass. Fixed in both gates simultaneously.
    return {
      action: 'deny',
      rule: 'manifest:unmatched_invalid',
      severity: 'warn',
      riskScore: 60,
      authorizer: 'manifest',
      cap,
    };
  }

  return { action: 'pass', cap };
}
