// restore.mjs — Agent Health trust-state parity for mcp-gate
//
// Ports lib/restore.sh (bash gate Agent Health layer) to the Node.js MCP
// gate. Must match bash behavior: same config file, same trust state file,
// same escalation semantics, same INV-04 fail-open guarantee.
//
// Responsibilities:
//   1. Read etc/restore-config.json (optional) and determine enabled state
//   2. Verify HMAC sidecar when a config HMAC key exists (INV-12)
//   3. On integrity failure, force-closed (enabled + all escalations deny)
//   4. Read trust state via packages/zlar-restore/trust-state.mjs
//   5. Advise the gate on escalation for matched allow/log actions
//
// Invariants preserved (see docs/RESTORE-INVARIANTS.md):
//   INV-01: Absent trust state = healthy
//   INV-02: Malformed trust state = degraded (delegated to trust-state.mjs)
//   INV-04: Restore cannot crash the gate — every public function is wrapped
//           in try/catch and returns the input action on any error
//   INV-09: HMAC verification of trust state (delegated)
//   INV-12: Config HMAC integrity, fail-closed on mismatch

import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { loadTrustState, setHmacKey } from '../packages/zlar-restore/trust-state.mjs';
import { verifyConfig } from '../packages/zlar-restore/config-integrity.mjs';

// ── Module state ────────────────────────────────────────────────────────────

let _state = {
  enabled: false,
  trustStateFile: null,
  escalation: { degraded: 'log', at_risk: 'ask', suspended: 'deny' },
  evalMarkerFile: null,
  projectDir: null,
  forcedClosedReason: null,
};

// Action ordering: allow < log < ask < deny (same as lib/restore.sh).
const ACTION_RANK = { allow: 0, log: 1, ask: 2, deny: 3 };
function actionRank(a) { return ACTION_RANK[a] ?? 0; }
function isWeaker(a, b) { return actionRank(a) < actionRank(b); }

// ── Initialization ──────────────────────────────────────────────────────────

// Called at gate startup. Safe to call with missing config — leaves
// enabled=false. Any error yields enabled=false (INV-04).
//
// @param {object} opts
// @param {string} opts.projectDir     Repo root — used to resolve relative paths
// @param {string} opts.configFile     Path to etc/restore-config.json
// @param {function} [opts.onForceClosed]  Callback when config integrity fails.
//   Receives {reason} so the gate can log/alert.
export function initRestore(opts) {
  try {
    const { projectDir, configFile, onForceClosed } = opts;
    _state.projectDir = projectDir;

    // No config file → restore off (INV-01 intent)
    if (!configFile || !existsSync(configFile)) {
      _state.enabled = false;
      return { enabled: false };
    }

    // Parse config
    let config;
    try {
      config = JSON.parse(readFileSync(configFile, 'utf-8'));
    } catch (e) {
      // Corrupt config — do NOT flip to enabled. This matches restore.sh:
      // an unreadable config (without HMAC key) leaves restore off.
      _state.enabled = false;
      return { enabled: false, reason: `config parse error: ${e.message}` };
    }

    // Config HMAC integrity check (INV-12). If a config HMAC key exists,
    // verify the sidecar. On failure, force CLOSED (enabled=true, all deny).
    const configHmacKeyFile = join(projectDir, 'etc/keys/restore-config-hmac.key');
    if (existsSync(configHmacKeyFile)) {
      const configHmacKey = readFileSync(configHmacKeyFile, 'utf-8').trim();
      if (configHmacKey) {
        const v = verifyConfig(configFile, configHmacKey);
        if (!v.valid) {
          _state.enabled = true;
          _state.escalation = { degraded: 'deny', at_risk: 'deny', suspended: 'deny' };
          _state.forcedClosedReason = v.reason;
          const trustPath = config.trust_state_file || 'var/restore/trust-state.json';
          _state.trustStateFile = join(projectDir, trustPath);
          _state.evalMarkerFile = join(projectDir, 'var/restore/.evaluating');
          if (typeof onForceClosed === 'function') {
            try { onForceClosed({ reason: v.reason }); } catch {}
          }
          return { enabled: true, forcedClosed: true, reason: v.reason };
        }
      }
    }

    // Normal path: honor config.enabled
    const enabled = config.enabled === true;
    if (!enabled) {
      _state.enabled = false;
      return { enabled: false };
    }

    _state.enabled = true;
    const trustPath = config.trust_state_file || 'var/restore/trust-state.json';
    _state.trustStateFile = join(projectDir, trustPath);
    _state.evalMarkerFile = join(projectDir, 'var/restore/.evaluating');
    _state.escalation = {
      degraded: config.escalation?.degraded || 'log',
      at_risk: config.escalation?.at_risk || 'ask',
      suspended: config.escalation?.suspended || 'deny',
    };

    // Load trust-state HMAC key if configured (INV-09)
    const hmacKeyPath = config.hmac_key_file
      ? join(projectDir, config.hmac_key_file)
      : null;
    if (hmacKeyPath && existsSync(hmacKeyPath)) {
      setHmacKey(hmacKeyPath);
    } else {
      setHmacKey(null);
    }

    return { enabled: true };
  } catch (e) {
    // INV-04: any init failure must not crash the gate. Leave disabled.
    _state.enabled = false;
    return { enabled: false, reason: `init error: ${e.message}` };
  }
}

// ── Trust state reader ──────────────────────────────────────────────────────

// Returns 'healthy' | 'degraded' | 'at_risk' | 'suspended'.
// INV-01: absent trust state file = healthy.
// INV-02: malformed / HMAC-mismatched = degraded (via trust-state.mjs).
// INV-04: any error returns 'healthy' (fail-open as advisory layer).
//
// Pending-evaluation floor: if var/restore/.evaluating is under 30s old,
// the floor for interim actions is 'degraded' (matches lib/restore.sh).
export function readTrustState() {
  if (!_state.enabled) return 'healthy';
  try {
    // Pending evaluation marker check
    if (_state.evalMarkerFile && existsSync(_state.evalMarkerFile)) {
      try {
        const raw = readFileSync(_state.evalMarkerFile, 'utf-8').trim();
        const ts = parseInt(raw, 10);
        const age = Math.floor(Date.now() / 1000) - ts;
        if (Number.isFinite(age) && age < 30) {
          const fileState = _readFromFile();
          return (fileState === 'at_risk' || fileState === 'suspended')
            ? fileState
            : 'degraded';
        }
      } catch { /* fall through to file read */ }
    }
    return _readFromFile();
  } catch {
    return 'healthy';
  }
}

function _readFromFile() {
  if (!_state.trustStateFile) return 'healthy';
  if (!existsSync(_state.trustStateFile)) return 'healthy';
  try {
    const ts = loadTrustState(_state.trustStateFile);
    return ts.state || 'healthy';
  } catch {
    // INV-02: any parse failure from loader should already yield 'degraded'
    // in its return value. Defense-in-depth: if loader itself throws,
    // treat as degraded rather than healthy — a loader crash is a signal.
    return 'degraded';
  }
}

// ── Escalation check ────────────────────────────────────────────────────────

// Advises the gate on whether to upgrade the matched action.
// Matches lib/restore.sh restore_check_escalation() exactly:
//   - disabled → pass through
//   - healthy → pass through
//   - degraded/at_risk/suspended → upgrade to configured action iff
//     the configured action is strictly stronger than policy action
//
// Returns { action, trustState, escalated }.
// INV-04: any error returns { action: policyAction, escalated: false }.
export function checkEscalation(policyAction) {
  if (!_state.enabled) {
    return { action: policyAction, trustState: 'healthy', escalated: false };
  }
  try {
    const trustState = readTrustState();
    if (trustState === 'healthy') {
      return { action: policyAction, trustState, escalated: false };
    }

    let target;
    switch (trustState) {
      case 'degraded':  target = _state.escalation.degraded; break;
      case 'at_risk':   target = _state.escalation.at_risk; break;
      case 'suspended': target = _state.escalation.suspended; break;
      default:          target = _state.escalation.degraded;  // INV-02 extended
    }

    if (isWeaker(policyAction, target)) {
      return { action: target, trustState, escalated: true };
    }
    return { action: policyAction, trustState, escalated: false };
  } catch {
    return { action: policyAction, trustState: 'healthy', escalated: false };
  }
}

// ── Introspection ──────────────────────────────────────────────────────────

// For tests and diagnostics. Does not mutate _state.
export function getRestoreState() {
  return {
    enabled: _state.enabled,
    trustStateFile: _state.trustStateFile,
    escalation: { ..._state.escalation },
    forcedClosedReason: _state.forcedClosedReason,
  };
}

// For tests: reset module state between test cases.
export function _resetRestoreForTests() {
  _state = {
    enabled: false,
    trustStateFile: null,
    escalation: { degraded: 'log', at_risk: 'ask', suspended: 'deny' },
    evalMarkerFile: null,
    projectDir: null,
    forcedClosedReason: null,
  };
  setHmacKey(null);
}
