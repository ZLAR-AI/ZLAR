// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR MCP Gate — Manifest-Authority Enforcement Tests
//
// Parity test suite for mcp-gate/manifest-enforcement.mjs. Covers every decision
// path (pass / deny / force_ask), prefix-match semantics, edge cases (null
// manifest, missing authority fields, empty lists, unknown unmatched_action),
// and one cross-gate parity fixture matching bash gate shape against the
// current prod manifest.
//
// Usage: node mcp-gate/test-manifest-enforcement.mjs
// ═══════════════════════════════════════════════════════════════════════════════

import {
  classifyMcpTool,
  enforceManifestAuthority,
} from './manifest-enforcement.mjs';

let PASS = 0, FAIL = 0, TOTAL = 0;

function assert(label, expected, actual) {
  TOTAL++;
  if (expected === actual) { PASS++; }
  else { FAIL++; console.log(`  FAIL: ${label} — expected "${expected}", got "${actual}"`); }
}

// ═════════════════════════════════════════════════════════════════════════════
// CLASSIFICATION
// ═════════════════════════════════════════════════════════════════════════════

console.log('\n── Classification ─────────────────────────────────────────────');

// Every MCP-served tool classifies as "mcp.call" (coarse bash parity).
assert('classify filesystem:write_file', 'mcp.call', classifyMcpTool('filesystem:write_file'));
assert('classify sqlite:query', 'mcp.call', classifyMcpTool('sqlite:query'));
assert('classify empty string', 'mcp.call', classifyMcpTool(''));
assert('classify arbitrary tool', 'mcp.call', classifyMcpTool('foo__bar__baz'));

// ═════════════════════════════════════════════════════════════════════════════
// PASS PATHS
// ═════════════════════════════════════════════════════════════════════════════

console.log('\n── Pass paths ─────────────────────────────────────────────────');

// Null manifest → pass with reason (bash MANIFEST_LOADED=false equivalent)
{
  const r = enforceManifestAuthority('anything', null);
  assert('null manifest pass', 'pass', r.action);
  assert('null manifest reason', 'no-manifest', r.reason);
  assert('null manifest cap', null, r.cap);
}

// Undefined manifest → pass
{
  const r = enforceManifestAuthority('anything', undefined);
  assert('undefined manifest pass', 'pass', r.action);
}

// Manifest allows mcp.call exactly → pass
{
  const m = { authority: { allow: ['mcp.call'], deny: [], unmatched_action: 'deny' } };
  const r = enforceManifestAuthority('anything', m);
  assert('allow exact pass', 'pass', r.action);
  assert('allow exact cap', 'mcp.call', r.cap);
}

// Manifest allows "mcp" (prefix match, cap "mcp.call" startsWith "mcp.")
{
  const m = { authority: { allow: ['mcp'], deny: [], unmatched_action: 'deny' } };
  const r = enforceManifestAuthority('anything', m);
  assert('allow prefix pass', 'pass', r.action);
}

// ═════════════════════════════════════════════════════════════════════════════
// DENY PATHS
// ═════════════════════════════════════════════════════════════════════════════

console.log('\n── Deny paths ─────────────────────────────────────────────────');

// Exact deny match — full audit event shape required
{
  const m = { authority: { deny: ['mcp.call'], allow: ['file.read'], unmatched_action: 'escalate' } };
  const r = enforceManifestAuthority('anything', m);
  assert('exact deny action', 'deny', r.action);
  assert('exact deny rule', 'manifest:deny', r.rule);
  assert('exact deny severity', 'warn', r.severity);
  assert('exact deny riskScore', 80, r.riskScore);
  assert('exact deny authorizer', 'manifest', r.authorizer);
  assert('exact deny cap', 'mcp.call', r.cap);
}

// Prefix deny match (deny "mcp" matches "mcp.call")
{
  const m = { authority: { deny: ['mcp'], allow: [], unmatched_action: 'escalate' } };
  const r = enforceManifestAuthority('anything', m);
  assert('prefix deny action', 'deny', r.action);
  assert('prefix deny rule', 'manifest:deny', r.rule);
}

// Deny wins over allow when same cap is in BOTH lists (invariant #1)
{
  const m = { authority: { deny: ['mcp.call'], allow: ['mcp.call'], unmatched_action: 'escalate' } };
  const r = enforceManifestAuthority('anything', m);
  assert('deny wins over allow', 'deny', r.action);
}

// Unmatched + unmatched_action=deny — full audit event shape required
{
  const m = { authority: { deny: [], allow: ['file.read'], unmatched_action: 'deny' } };
  const r = enforceManifestAuthority('anything', m);
  assert('unmatched deny action', 'deny', r.action);
  assert('unmatched deny rule', 'manifest:unmatched', r.rule);
  assert('unmatched deny severity', 'warn', r.severity);
  assert('unmatched deny riskScore', 60, r.riskScore);
  assert('unmatched deny authorizer', 'manifest', r.authorizer);
}

// ═════════════════════════════════════════════════════════════════════════════
// FORCE_ASK PATHS
// ═════════════════════════════════════════════════════════════════════════════

console.log('\n── Force-ask paths ────────────────────────────────────────────');

// Unmatched + unmatched_action=escalate → force_ask
{
  const m = { authority: { deny: [], allow: ['file.read'], unmatched_action: 'escalate' } };
  const r = enforceManifestAuthority('anything', m);
  assert('unmatched escalate action', 'force_ask', r.action);
  assert('unmatched escalate rule', 'manifest:unmatched', r.rule);
  assert('unmatched escalate cap', 'mcp.call', r.cap);
}

// Unmatched + unmatched_action missing (defaults to 'escalate' per bash line 2221)
{
  const m = { authority: { deny: [], allow: ['file.read'] } };
  const r = enforceManifestAuthority('anything', m);
  assert('default escalate action', 'force_ask', r.action);
}

// ═════════════════════════════════════════════════════════════════════════════
// EDGE CASES
// ═════════════════════════════════════════════════════════════════════════════

console.log('\n── Edge cases ─────────────────────────────────────────────────');

// Manifest with no .authority field → treat as empty deny/allow, default unmatched
{
  const m = { manifest_version: '0.1.0' };
  const r = enforceManifestAuthority('anything', m);
  assert('no authority → force_ask (default escalate)', 'force_ask', r.action);
}

// Manifest with .authority but no .deny field → deny check is no-op
{
  const m = { authority: { allow: ['mcp.call'] } };
  const r = enforceManifestAuthority('anything', m);
  assert('no deny field → allowed passes', 'pass', r.action);
}

// Empty deny AND empty allow + default unmatched → force_ask
{
  const m = { authority: { deny: [], allow: [] } };
  const r = enforceManifestAuthority('anything', m);
  assert('both empty → force_ask', 'force_ask', r.action);
}

// Unknown unmatched_action value → silent pass (BASH PARITY — known latent)
{
  const m = { authority: { deny: [], allow: ['file.read'], unmatched_action: 'log' } };
  const r = enforceManifestAuthority('anything', m);
  assert('unknown unmatched_action → silent pass', 'pass', r.action);
}

// Non-string deny entry → ignored by typeof check; valid string still matches
{
  const m = { authority: { deny: [null, 42, 'mcp.call', undefined], allow: [], unmatched_action: 'escalate' } };
  const r = enforceManifestAuthority('anything', m);
  assert('non-string deny entries filtered but valid caught', 'deny', r.action);
}

// Non-string allow entry → ignored by typeof check
{
  const m = { authority: { deny: [], allow: [null, 42, undefined], unmatched_action: 'deny' } };
  const r = enforceManifestAuthority('anything', m);
  assert('non-string allow entries filtered', 'deny', r.action);
}

// ═════════════════════════════════════════════════════════════════════════════
// CROSS-GATE PARITY FIXTURE (Bayesian's recommendation)
// ═════════════════════════════════════════════════════════════════════════════
//
// Fixture matches the shape bash gate would see if invoked on an MCP tool
// against the current prod manifest. Bash trace:
//   line 2180-2201: DOMAIN=mcp → _cap_category=mcp.call
//   line 2205-2212: deny check → no match (prod deny list has no mcp.call)
//   line 2214-2222: allow check → no match (prod allow list has no mcp.call)
//   line 2221:      read unmatched_action → "escalate"
//   line 2231:      MANIFEST_FORCES_ASK=true
// Bash outcome: force_ask with rule manifest:unmatched.
// MCP gate must produce the identical decision for the same fixture.

console.log('\n── Cross-gate parity fixture ──────────────────────────────────');

{
  const prodManifestShape = {
    manifest_version: '0.1.0',
    identity: {
      agent_id: 'zlar:agent:claude-code',
      principal: 'zlar:human:vince-nijjar',
      issued_at: '2026-04-10T00:00:00Z',
    },
    authority: {
      allow: [
        'bash.read',
        'bash.execute',
        'file.read',
        'file.write',
        'file.edit',
        'file.glob',
        'file.grep',
        'agent.spawn',
      ],
      deny: [
        'bash.dangerous',
        'system.modify',
        'governance_mutation',
        'evidence_mutation',
        'stop_restart_control',
        'key_material_signing_authority',
        'self_expansion_of_authority',
        'communication_channel_mutation',
      ],
      unmatched_action: 'escalate',
    },
    sequence: 7,
    expires: '2026-05-14T00:00:00Z',
  };

  const r = enforceManifestAuthority('filesystem:write_file', prodManifestShape);
  assert('cross-gate action matches bash', 'force_ask', r.action);
  assert('cross-gate cap classification matches bash', 'mcp.call', r.cap);
  assert('cross-gate rule matches bash', 'manifest:unmatched', r.rule);
}

// ═════════════════════════════════════════════════════════════════════════════
// SUMMARY
// ═════════════════════════════════════════════════════════════════════════════

console.log(`\n${'═'.repeat(63)}`);
console.log(`Tests: ${TOTAL}  Pass: ${PASS}  Fail: ${FAIL}`);
if (FAIL > 0) {
  console.log('❌ FAILED');
  process.exit(1);
} else {
  console.log('✓ ALL PASS');
  process.exit(0);
}
