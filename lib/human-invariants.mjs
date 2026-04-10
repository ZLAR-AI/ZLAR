// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Human Invariants — Node.js Enforcement
//
// Mirrors lib/human-invariants.sh for the MCP gate.
// Per-human state, not per-session. Five enforcements:
//   H6  — Decision cap per day
//   H13 — Pending queue capacity
//   H14 — Response time variance (replaces approval rate monitoring)
//   H15 — Deliberation floor
//   H17 — Human authenticity
//
// v2.9.0: H14 replaced. Approval rate penalized well-calibrated gates (high
// approval rates are correct behavior when the gate filters well). Response
// time variance is a better proxy: a rubber-stamper responds uniformly fast;
// a genuine deliberator shows variable response times correlated with
// request complexity. Synced with lib/human-invariants.sh.
//
// Dependencies: Node.js built-ins only.
// ═══════════════════════════════════════════════════════════════════════════════

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PROJECT_DIR = join(__dirname, '..');

// ─── Configuration ───────────────────────────────────────────────────────────

const DEFAULTS = {
  dailyDecisionCap: 80,
  pendingCap: 5,
  // v2.8.0: pending TTL in seconds. Entries older than this are aged out on
  // every read, so orphaned increments cannot drift the counter permanently.
  pendingTtl: 1800,
  varianceStddevFloor: 4,   // H14: std_dev below this = suspiciously uniform
  varianceWindow: 20,        // H14: sliding window of response times
  varianceMinSample: 10,     // H14: minimum decisions before variance check fires
  deliberationFloor: { critical: 30, warn: 10, info: 3 },
  minResponseTime: 2,
};

// ─── State ───────────────────────────────────────────────────────────────────

const STATE_DIR = join(PROJECT_DIR, 'var', 'human-state');

function ensureStateDir() {
  if (!existsSync(STATE_DIR)) {
    mkdirSync(STATE_DIR, { recursive: true });
  }
}

function loadState(humanId) {
  ensureStateDir();
  const file = join(STATE_DIR, `${humanId}.json`);
  const today = new Date().toISOString().slice(0, 10);

  if (!existsSync(file)) {
    const state = { human_id: humanId, date: today, decisions_today: 0, response_times: [], pending: [], last_ask_epoch: 0 };
    writeFileSync(file, JSON.stringify(state));
    return state;
  }

  const state = JSON.parse(readFileSync(file, 'utf8'));
  // Reset daily counters on date change.
  // v2.7.1: also reset pending_count alongside decisions_today.
  // v2.7.2: also reset approvals_recent. Without this, yesterday's
  // approval-rate sliding window persists across the date boundary,
  // which is how H14 (rubber_stamping) can stay fire-closed after a
  // full day's reset. Origin: April 9 2026 incident where H14 fired
  // on a fresh morning session because the previous session's
  // 100% approval rate was still in the window.
  // v2.8.0: pending_count scalar replaced with pending: [{action_hash, ts}]
  // TTL array. Rollover drops the dead pending_count field and resets
  // pending to empty.
  if (state.date !== today) {
    state.date = today;
    state.decisions_today = 0;
    state.pending = [];
    state.response_times = [];
    delete state.approvals_recent;
    delete state.pending_count;
    writeFileSync(file, JSON.stringify(state));
    return state;
  }

  // v2.8.0 schema migration: mid-day files still carrying the deprecated
  // pending_count scalar (written by v2.7.x earlier today, before rollover)
  // drop it and gain a pending array. Idempotent after first run.
  // This is the code path that unblocks a human stuck at pending_count > cap:
  // the scalar dies here, the array starts empty, and the next ask finds
  // capacity again.
  let migrated = false;
  if ('pending_count' in state) {
    delete state.pending_count;
    migrated = true;
  }
  if (!Array.isArray(state.pending)) {
    state.pending = [];
    migrated = true;
  }
  if (migrated) writeFileSync(file, JSON.stringify(state));

  return state;
}

function saveState(humanId, state) {
  ensureStateDir();
  writeFileSync(join(STATE_DIR, `${humanId}.json`), JSON.stringify(state));
}

// ─── H6: Decision Cap ────────────────────────────────────────────────────────

export function checkCapacity(humanId, config = {}) {
  const cap = config.dailyDecisionCap || DEFAULTS.dailyDecisionCap;
  const state = loadState(humanId);
  if (state.decisions_today >= cap) {
    return { ok: false, reason: 'capacity_exceeded', detail: `${state.decisions_today}/${cap} decisions today` };
  }
  return { ok: true };
}

// ─── H13: Pending Queue (TTL + retry dedup) ──────────────────────────────────
//
// v2.8.0 rewrite. See lib/human-invariants.sh for the full thesis and the
// April 9 2026 incident that motivated this. Summary:
//
//   - Orphaned increments (post-response path skipped) age out automatically
//     via HI_PENDING_TTL instead of drifting the counter forever.
//   - Retry double-counting (Claude re-invoking a denied tool before the
//     human has approved) is suppressed via action_hash dedup.
//
// The MCP gate uses a synchronous poll architecture, so it's less exposed to
// the retry problem than the Claude Code bash gate, but it's still subject to
// the orphan problem (poll timeout, process crash, user never responding).
// TTL fixes that here too.

function filterStalePending(pending, nowEpoch, ttl) {
  return (pending || []).filter(e => e && typeof e.ts === 'number' && (nowEpoch - e.ts) < ttl);
}

export function incrementPending(humanId, config = {}, actionHash = '') {
  const cap = config.pendingCap || DEFAULTS.pendingCap;
  const ttl = config.pendingTtl || DEFAULTS.pendingTtl;
  const now = Math.floor(Date.now() / 1000);
  const state = loadState(humanId);

  const filtered = filterStalePending(state.pending, now, ttl);
  const alreadyPending = actionHash !== '' && filtered.some(e => e.action_hash === actionHash);

  if (alreadyPending) {
    // Retry of an already-pending ask — do not re-append.
    state.pending = filtered;
    saveState(humanId, state);
    return { ok: true };
  }

  if (filtered.length >= cap) {
    // Would exceed cap. Persist the filtered (cleaned) array without the
    // new entry, so stale cleanup still happens on every call.
    state.pending = filtered;
    saveState(humanId, state);
    return { ok: false, reason: 'overloaded', detail: `${filtered.length} pending (cap: ${cap}, ttl: ${ttl}s)` };
  }

  state.pending = [...filtered, { action_hash: actionHash, ts: now }];
  saveState(humanId, state);
  return { ok: true };
}

export function decrementPending(humanId, actionHash = '') {
  const ttl = DEFAULTS.pendingTtl;
  const now = Math.floor(Date.now() / 1000);
  const state = loadState(humanId);

  const filtered = filterStalePending(state.pending, now, ttl);

  if (actionHash !== '') {
    state.pending = filtered.filter(e => e.action_hash !== actionHash);
  } else {
    const sorted = [...filtered].sort((a, b) => (a.ts || 0) - (b.ts || 0));
    state.pending = sorted.slice(1);
  }

  saveState(humanId, state);
}

// ─── H15: Deliberation Floor ─────────────────────────────────────────────────

export function recordAskTime(humanId) {
  const state = loadState(humanId);
  state.last_ask_epoch = Math.floor(Date.now() / 1000);
  saveState(humanId, state);
}

export function checkDeliberation(humanId, severity = 'info', config = {}) {
  const floors = config.deliberationFloor || DEFAULTS.deliberationFloor;
  const floor = floors[severity] || floors.info;
  const state = loadState(humanId);
  const elapsed = Math.floor(Date.now() / 1000) - (state.last_ask_epoch || 0);

  if (elapsed < floor) {
    return { ok: false, reason: 'too_fast', detail: `${elapsed}s elapsed, ${floor}s required for ${severity}` };
  }
  return { ok: true };
}

// ─── H17: Human Authenticity ─────────────────────────────────────────────────

export function checkAuthenticity(humanId, config = {}) {
  const minTime = config.minResponseTime || DEFAULTS.minResponseTime;
  const state = loadState(humanId);
  const elapsed = Math.floor(Date.now() / 1000) - (state.last_ask_epoch || 0);

  if (elapsed < minTime) {
    return { ok: false, reason: 'suspicious', detail: `${elapsed}s response time (min: ${minTime}s)` };
  }
  return { ok: true };
}

// ─── H14: Response Time Variance ─────────────────────────────────────────────
// Replaces approval rate monitoring. A well-calibrated gate produces high
// approval rates legitimately — penalizing that creates perverse incentives.
// Response time std_dev is a better proxy: rubber-stampers respond uniformly;
// genuine deliberators show variable response times across request complexity.

export function recordDecision(humanId, decision, elapsedSeconds = 0, severity = 'info', config = {}) {
  const window = config.varianceWindow || DEFAULTS.varianceWindow;
  const state = loadState(humanId);
  state.decisions_today = (state.decisions_today || 0) + 1;
  // Store {elapsed, severity} pairs — severity weighting applied at check time
  state.response_times = [...(state.response_times || []), { elapsed: elapsedSeconds, severity }].slice(-window);
  saveState(humanId, state);
}

export function checkResponseVariance(humanId, config = {}) {
  const stddevFloor = config.varianceStddevFloor || DEFAULTS.varianceStddevFloor;
  const minSample = config.varianceMinSample || DEFAULTS.varianceMinSample;
  const state = loadState(humanId);

  // Variance check on non-critical decisions only.
  // Critical decisions are governed by H15 (30s floor) which creates artificial
  // uniformity — including critical would fire H14 against exactly the deliberate
  // behavior H15 is designed to produce.
  const times = (state.response_times || [])
    .filter(e => (typeof e === 'object' ? e.severity : null) !== 'critical')
    .map(e => typeof e === 'object' ? e.elapsed : e); // backward-compat with plain numbers

  if (times.length < minSample) {
    return { ok: true }; // Not enough non-critical data yet
  }

  const mean = times.reduce((a, b) => a + b, 0) / times.length;
  const variance = times.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / times.length;
  const stddev = Math.sqrt(variance);

  if (stddev < stddevFloor) {
    return {
      ok: false,
      reason: 'rubber_stamping',
      detail: `warn/info response time std_dev ${stddev.toFixed(1)}s over last ${times.length} decisions (floor: ${stddevFloor}s) — suspiciously uniform on non-critical decisions`
    };
  }
  return { ok: true };
}

// Backward-compatible alias
export const checkApprovalRate = checkResponseVariance;

// ─── Combined Checks ─────────────────────────────────────────────────────────

// actionHash is optional. When provided, H13 uses it to dedupe retry loops
// (same logical ask, multiple gate invocations) and to pair pre/post calls
// by identity rather than by FIFO order. Callers without a stable hash can
// omit it — TTL alone still bounds the drift.
export function preAskCheck(humanId, config = {}, actionHash = '') {
  const cap = checkCapacity(humanId, config);
  if (!cap.ok) return cap;

  const variance = checkResponseVariance(humanId, config);
  if (!variance.ok) return variance;

  const pending = incrementPending(humanId, config, actionHash);
  if (!pending.ok) return pending;

  return { ok: true };
}

export function postResponseCheck(humanId, severity, decision, config = {}, actionHash = '') {
  decrementPending(humanId, actionHash);

  const auth = checkAuthenticity(humanId, config);
  if (!auth.ok) return auth;

  const delib = checkDeliberation(humanId, severity, config);
  if (!delib.ok) return delib;

  // H14: record elapsed time + severity for variance tracking
  const state = loadState(humanId);
  const elapsed = Math.floor(Date.now() / 1000) - (state.last_ask_epoch || 0);
  recordDecision(humanId, decision, elapsed, severity, config);

  return { ok: true };
}
