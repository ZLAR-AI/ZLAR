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

import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PROJECT_DIR = join(__dirname, '..');

// ─── HMAC Protection (v3.1.3) ────────────────────────────────────────────────
// Mirrors lib/human-invariants.sh. Seals every write, verifies every read.
// Canonical form: JSON.stringify with recursively sorted keys (matches jq -cS).
// No key = unauthenticated mode (backward compat for pre-v3.1.3 deployments).
// Tampered state is logged and rebuilt with safe defaults, not fail-closed —
// locking the human out helps the attacker more than the human.

const HMAC_KEY_FILE = process.env.ZLAR_HUMAN_STATE_HMAC_KEY_FILE || join(PROJECT_DIR, 'etc', 'keys', 'human-state-hmac.key');
let HMAC_KEY = '';
try {
  if (existsSync(HMAC_KEY_FILE)) {
    HMAC_KEY = readFileSync(HMAC_KEY_FILE, 'utf8').trim();
  }
} catch { /* proceed unauthenticated */ }

// Recursive sorted-keys, compact JSON — canonical form for HMAC computation.
// Matches `jq -cS` output for simple objects/arrays with string/number/bool/
// null values (the universe of our state payloads).
function canonicalJSON(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
}

function computeHmac(payload) {
  if (!HMAC_KEY) return '';
  return createHmac('sha256', HMAC_KEY).update(canonicalJSON(payload)).digest('hex');
}

// Returns 'ok' | 'tampered' | 'unkeyed'.
function verifyHmac(state) {
  if (!HMAC_KEY) return 'unkeyed';
  const stored = state._hmac || '';
  if (!stored) return 'tampered';
  const { _hmac, ...payload } = state;
  const computed = computeHmac(payload);
  return computed === stored ? 'ok' : 'tampered';
}

// ─── Configuration ───────────────────────────────────────────────────────────

const DEFAULTS = {
  dailyDecisionCap: 80,
  pendingCap: 5,
  // v2.8.0: pending TTL in seconds. Entries older than this are aged out on
  // every read, so orphaned increments cannot drift the counter permanently.
  // v3.2.2: aligned with bash (HI_PENDING_TTL) at 360s. The earlier 1800s
  // default created a 25-min window where H13 counted entries whose pending
  // files had already expired — same bug bash fixed in v2.8.1; the fix never
  // propagated here.
  pendingTtl: 360,
  varianceStddevFloor: 4,   // H14: std_dev below this = suspiciously uniform
  varianceWindow: 20,        // H14: sliding window of response times
  varianceMinSample: 10,     // H14: minimum decisions before variance check fires
  deliberationFloor: { critical: 30, warn: 10, info: 3 },
  // H17 v1: seconds floor kept for backward compat. H17 v2 uses ms values.
  minResponseTime: 2,
  // H17 v2: ms-precision floors.
  // minResponseTimeMs: null means derive from minResponseTime * 1000 at call time.
  minResponseTimeMs: null,
  // Machine-speed / authenticity floor — no operator profile can pass below this.
  absoluteMinResponseTimeMs: 500,
  // Graduated floor for calibrated operators on critical-severity approvals.
  calibratedCriticalFloorMs: 1500,
  // Timing observations: persistent bounded record of all response events.
  // Survives UTC rollover. Foundation for Calibrated Operator Trust Graduation (Slice 2).
  timingObsMaxAgeDays: 30,
  timingObsCap: 100,
};

// ─── State ───────────────────────────────────────────────────────────────────

const STATE_DIR = process.env.ZLAR_HUMAN_STATE_DIR || join(PROJECT_DIR, 'var', 'human-state');

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
    const state = { human_id: humanId, date: today, decisions_today: 0, response_times: [], pending: [], last_ask_epoch: 0, last_ask_epoch_ms: 0, canary_tier: 0, canary_trip_count: 0, timing_observations: [], operator_profile_level: 0, trust_lane: 'guarded' };
    atomicWriteJSON(file, state);
    return state;
  }

  // Parse + HMAC verification. Corrupt JSON or tampered state: log + rebuild.
  let raw = null;
  try {
    raw = JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    raw = null;
  }

  if (!raw || verifyHmac(raw) === 'tampered') {
    // Match the bash log format so both gates surface the same signal.
    // eslint-disable-next-line no-console
    console.warn(`[human-invariants] SECURITY: ${humanId} state HMAC verification FAILED — rebuilding with safe defaults`);
    const state = { human_id: humanId, date: today, decisions_today: 0, response_times: [], pending: [], last_ask_epoch: 0, last_ask_epoch_ms: 0, canary_tier: 0, canary_trip_count: 0, timing_observations: [], operator_profile_level: 0, trust_lane: 'guarded' };
    atomicWriteJSON(file, state);
    return state;
  }

  // Strip _hmac from the in-memory state so downstream callers never see it.
  const { _hmac, ...state } = raw;
  // Reset daily counters on date change.
  // v2.7.1: also reset pending_count alongside decisions_today.
  // v2.7.2: introduced cross-day reset for H14's sliding window so
  // yesterday's window cannot keep H14 fire-closed after a full day's
  // reset. At the time the window was approvals_recent — delete approvals_recent
  // below scrubs that legacy field. Origin: April 9 2026 incident where
  // H14 fired on a fresh morning session because the previous session's
  // history was still in the window.
  // v2.8.0: pending_count scalar replaced with pending: [{action_hash, ts}]
  // TTL array. Rollover drops the dead pending_count field and resets
  // pending to empty.
  // v2.9.0: H14 switched to response-time variance. response_times is the
  // active sliding window now; the v2.7.2 cross-day reset principle
  // applies to it (response_times = []).
  // v3.2.3: timing_observations and operator_profile_level survive rollover
  // intentionally — timing_observations carries multi-day history for
  // Calibrated Operator Trust Graduation (Slice 2). Do NOT reset them here.
  // v3.3.0: trust_lane and trust_lane_grant survive rollover intentionally —
  // authority grants must not be silently revoked by a UTC date change.
  if (state.date !== today) {
    state.date = today;
    state.decisions_today = 0;
    state.pending = [];
    state.response_times = [];
    state.canary_tier = 0;
    state.canary_trip_count = 0;
    delete state.approvals_recent;
    delete state.pending_count;
    atomicWriteJSON(file, state);
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
  // v3.2.x schema migration: add canary_tier / canary_trip_count if absent.
  if (!('canary_tier' in state)) {
    state.canary_tier = 0;
    migrated = true;
  }
  if (!('canary_trip_count' in state)) {
    state.canary_trip_count = 0;
    migrated = true;
  }
  // v3.2.3 timing observation schema migration: add timing_observations /
  // operator_profile_level if absent. Idempotent after first run.
  if (!('timing_observations' in state)) {
    state.timing_observations = [];
    migrated = true;
  }
  if (!('operator_profile_level' in state)) {
    state.operator_profile_level = 0;
    migrated = true;
  }
  // v3.3.0 trust lane schema migration: add trust_lane if absent.
  if (!('trust_lane' in state)) {
    state.trust_lane = 'guarded';
    migrated = true;
  }
  if (migrated) atomicWriteJSON(file, state);

  return state;
}

// Atomic sealed write: tmp + rename prevents corrupt JSON on crash mid-write;
// HMAC seals the payload against tampering. Matches lib/human-invariants.sh.
// Any incoming _hmac field is stripped before sealing so re-sealing a loaded
// state never double-seals.
function atomicWriteJSON(filepath, data) {
  const tmp = `${filepath}.tmp`;
  const { _hmac, ...payload } = data;
  let final;
  if (HMAC_KEY) {
    const hmac = computeHmac(payload);
    final = JSON.stringify({ ...payload, _hmac: hmac });
  } else {
    final = JSON.stringify(payload);
  }
  writeFileSync(tmp, final);
  renameSync(tmp, filepath);
}

function saveState(humanId, state) {
  ensureStateDir();
  atomicWriteJSON(join(STATE_DIR, `${humanId}.json`), state);
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
  state.last_ask_epoch_ms = Date.now();
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
// Rejects machine-speed responses using ms-precision timing and per-operator
// calibration. See lib/human-invariants.sh for the full design rationale.

// Resolve the default ms floor from config. If minResponseTimeMs is explicitly
// set use it; otherwise derive from minResponseTime * 1000 for backward compat.
function resolveMinResponseTimeMs(config) {
  if (config.minResponseTimeMs != null) return config.minResponseTimeMs;
  const seconds = config.minResponseTime || DEFAULTS.minResponseTime;
  return seconds * 1000;
}

// Returns true if the human has sufficient non-critical response-time variance
// to be considered calibrated (same signal as H14).
function isCalibrated(state, config) {
  const stddevFloor = (config && config.varianceStddevFloor) || DEFAULTS.varianceStddevFloor;
  const minSample = (config && config.varianceMinSample) || DEFAULTS.varianceMinSample;

  const times = (state.response_times || [])
    .filter(e => (typeof e === 'object' ? e.severity : null) !== 'critical')
    .map(e => typeof e === 'object' ? e.elapsed : e);

  if (times.length < minSample) return false;

  const mean = times.reduce((a, b) => a + b, 0) / times.length;
  const variance = times.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / times.length;
  const stddev = Math.sqrt(variance);

  return stddev >= stddevFloor;
}

export function checkAuthenticity(humanId, severity = 'info', config = {}) {
  const absoluteFloor = (config && config.absoluteMinResponseTimeMs) || DEFAULTS.absoluteMinResponseTimeMs;
  const defaultFloor = resolveMinResponseTimeMs(config);
  const calibratedCriticalFloor = (config && config.calibratedCriticalFloorMs) || DEFAULTS.calibratedCriticalFloorMs;

  const state = loadState(humanId);
  // Use ms precision; fall back to last_ask_epoch * 1000 for pre-v2 state files.
  const askMs = state.last_ask_epoch_ms || (state.last_ask_epoch || 0) * 1000;
  const elapsedMs = Date.now() - askMs;

  // Machine-speed / authenticity floor — no operator profile can pass below this.
  if (elapsedMs < absoluteFloor) {
    return { ok: false, reason: 'suspicious', detail: `${elapsedMs}ms response time (machine-speed floor: ${absoluteFloor}ms)` };
  }

  // Fast Lane: authority-granted trust replaces calibration requirement.
  if ((state.trust_lane || 'guarded') === 'fast') {
    return { ok: true };
  }

  // Select floor by severity and calibration status.
  let floor = defaultFloor;
  if (isCalibrated(state, config)) {
    floor = severity === 'critical' ? calibratedCriticalFloor : absoluteFloor;
  }

  if (elapsedMs < floor) {
    return { ok: false, reason: 'suspicious', detail: `${elapsedMs}ms response time (floor: ${floor}ms, severity: ${severity})` };
  }
  return { ok: true };
}

// ─── H14: Response Time Variance ─────────────────────────────────────────────
// Replaces approval rate monitoring. A well-calibrated gate produces high
// approval rates legitimately — penalizing that creates perverse incentives.
// Response time std_dev is a better proxy: rubber-stampers respond uniformly;
// genuine deliberators show variable response times across request complexity.

// elapsedMs is optional ms-precision elapsed for H17 v2 floor tuning.
// H14 variance computation reads .elapsed (seconds); elapsed_ms is a side-channel.
export function recordDecision(humanId, decision, elapsedSeconds = 0, severity = 'info', config = {}, elapsedMs = null) {
  const window = config.varianceWindow || DEFAULTS.varianceWindow;
  const state = loadState(humanId);
  state.decisions_today = (state.decisions_today || 0) + 1;
  const entry = { elapsed: elapsedSeconds, severity };
  if (elapsedMs !== null && elapsedMs > 0) entry.elapsed_ms = elapsedMs;
  state.response_times = [...(state.response_times || []), entry].slice(-window);

  // Canary tier reset: if variance has recovered (stddev >= 2× floor over
  // sufficient non-critical samples), clear tier state. Does not touch
  // response_times — only resets canary_tier and canary_trip_count.
  if ((state.canary_tier || 0) > 0) {
    const minSample = config.varianceMinSample || DEFAULTS.varianceMinSample;
    const resetFloor = (config.varianceStddevFloor || DEFAULTS.varianceStddevFloor) * 2;
    const ncTimes = state.response_times
      .filter(e => (typeof e === 'object' ? e.severity : null) !== 'critical')
      .map(e => typeof e === 'object' ? e.elapsed : e);
    if (ncTimes.length >= minSample) {
      const mean = ncTimes.reduce((a, b) => a + b, 0) / ncTimes.length;
      const stddev = Math.sqrt(ncTimes.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / ncTimes.length);
      if (stddev >= resetFloor) {
        state.canary_tier = 0;
        state.canary_trip_count = 0;
      }
    }
  }

  saveState(humanId, state);
}

export function checkResponseVariance(humanId, config = {}) {
  const stddevFloor = config.varianceStddevFloor || DEFAULTS.varianceStddevFloor;
  const minSample = config.varianceMinSample || DEFAULTS.varianceMinSample;
  const state = loadState(humanId);

  // Fast Lane: H14 bypassed — authority-granted trust replaces variance check.
  if ((state.trust_lane || 'guarded') === 'fast') {
    return { ok: true };
  }

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
    // Reset response_times so the window starts fresh. Without this, H14 fires
    // on every pre-ask until midnight — no new decisions enter the window so
    // variance never recovers. Advisory semantics mean asks still route, so
    // new decisions accumulate naturally from here.
    // Also increment canary_tier (cap at 2) and canary_trip_count in the same write.
    state.response_times = [];
    state.canary_tier = Math.min((state.canary_tier || 0) + 1, 2);
    state.canary_trip_count = (state.canary_trip_count || 0) + 1;
    saveState(humanId, state);
    return {
      ok: false,
      reason: 'canary_pattern_check',
      detail: `warn/info response time std_dev ${stddev.toFixed(1)}s over last ${times.length} decisions (floor: ${stddevFloor}s)`
    };
  }
  return { ok: true };
}

// Backward-compatible alias
export const checkApprovalRate = checkResponseVariance;

// Read the current canary escalation tier (0=none, 1=banner, 2=heavy banner).
// Incremented by checkResponseVariance on H14 trips (cap 2); reset to 0 by
// recordDecision when variance recovers (stddev >= 2× floor).
export function getCanaryTier(humanId) {
  const state = loadState(humanId);
  return state.canary_tier || 0;
}

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

// ─── Timing Observation Recording ────────────────────────────────────────────
// Record every response event (approve or deny) regardless of H17/H15 outcome.
// Provides data foundation for Calibrated Operator Trust Graduation (Slice 2).
// timing_observations survives UTC rollover — not cleared by loadState rollover.
// Ring buffer: capped at timingObsCap; pruned to timingObsMaxAgeDays.
// v3.3.0: trustLane parameter (11th) records operating lane per observation.

export function recordTimingObservation(humanId, elapsedMs, h17FloorMs, h15FloorMs, effectiveFloorMs, bindingFloor, severity, riskScore, outcome, source, trustLane = 'guarded', config = {}) {
  const maxAgeDays = (config && config.timingObsMaxAgeDays) || DEFAULTS.timingObsMaxAgeDays;
  const cap = (config && config.timingObsCap) || DEFAULTS.timingObsCap;
  const maxAgeS = maxAgeDays * 86400;
  const nowEpoch = Math.floor(Date.now() / 1000);
  const nowIso = new Date().toISOString().replace(/\.\d+Z$/, 'Z');

  const state = loadState(humanId);
  const pruned = (state.timing_observations || []).filter(o => (nowEpoch - o.ts) <= maxAgeS);
  const entry = {
    ts: nowEpoch,
    iso: nowIso,
    elapsed_ms: elapsedMs,
    h17_floor_ms: h17FloorMs,
    h15_floor_ms: h15FloorMs,
    effective_floor_ms: effectiveFloorMs,
    binding_floor: bindingFloor,
    severity,
    risk_score: riskScore,
    outcome,
    source,
    trust_lane: trustLane,
  };
  state.timing_observations = [...pruned, entry].slice(-cap);
  saveState(humanId, state);
}

export function postResponseCheck(humanId, severity, decision, config = {}, actionHash = '') {
  decrementPending(humanId, actionHash);

  const absoluteFloor = (config && config.absoluteMinResponseTimeMs) || DEFAULTS.absoluteMinResponseTimeMs;
  const defaultFloor = resolveMinResponseTimeMs(config);
  const calibratedCriticalFloor = (config && config.calibratedCriticalFloorMs) || DEFAULTS.calibratedCriticalFloorMs;
  const deliberationFloors = (config && config.deliberationFloor) || DEFAULTS.deliberationFloor;
  const riskScore = (config && config.riskScore) != null ? config.riskScore : 100;

  // Compute elapsed once at the top — shared by all exit paths.
  const stateSnap = loadState(humanId);
  const askMs = stateSnap.last_ask_epoch_ms || (stateSnap.last_ask_epoch || 0) * 1000;
  const elapsedMs = Date.now() - askMs;
  const elapsedS = Math.floor(Date.now() / 1000) - (stateSnap.last_ask_epoch || 0);
  const trustLane = stateSnap.trust_lane || 'guarded';

  // ── DENY PATH FIRST — deny always stands ─────────────────────────────────
  if (decision === 'deny') {
    const calibrated = isCalibrated(stateSnap, config);
    let h17FloorMs = defaultFloor;
    if (calibrated) {
      h17FloorMs = severity === 'critical' ? calibratedCriticalFloor : absoluteFloor;
    }
    const h15FloorMs = trustLane === 'fast'
      ? absoluteFloor
      : (deliberationFloors[severity] || deliberationFloors.info) * 1000;
    const effectiveFloorMs = Math.max(h17FloorMs, h15FloorMs);
    recordTimingObservation(humanId, elapsedMs, h17FloorMs, h15FloorMs, effectiveFloorMs, 'none', severity, riskScore, 'deny_accepted', 'deny', trustLane, config);
    recordDecision(humanId, 'deny', elapsedS, severity, config, elapsedMs);
    return { ok: true };
  }

  // ── APPROVE PATH ─────────────────────────────────────────────────────────

  // Compute H17 floor (mirrors checkAuthenticity floor selection).
  const calibrated = isCalibrated(stateSnap, config);
  let h17FloorMs = defaultFloor;
  if (calibrated) {
    h17FloorMs = severity === 'critical' ? calibratedCriticalFloor : absoluteFloor;
  }
  // Fast Lane: H17 floor collapses to absolute minimum.
  if (trustLane === 'fast') {
    h17FloorMs = absoluteFloor;
  }

  // Compute H15 floor (ms). Fast Lane: same as absolute minimum.
  const h15FloorMs = trustLane === 'fast'
    ? absoluteFloor
    : (deliberationFloors[severity] || deliberationFloors.info) * 1000;

  // Effective floor = max(h17, h15).
  const effectiveFloorMs = Math.max(h17FloorMs, h15FloorMs);
  const bindingFloor = h17FloorMs >= h15FloorMs ? 'h17' : 'h15';

  // H17: Authenticity check.
  const auth = checkAuthenticity(humanId, severity, config);
  if (!auth.ok) {
    recordTimingObservation(humanId, elapsedMs, h17FloorMs, h15FloorMs, effectiveFloorMs, bindingFloor, severity, riskScore, 'rejected_h17', 'approve', trustLane, config);
    return auth;
  }

  // H15: Deliberation floor check.
  // Fast Lane: ms-precision comparison against absoluteFloor (already passed H17).
  // Guarded/Slow: integer-seconds checkDeliberation (existing behavior).
  let delib;
  if (trustLane === 'fast') {
    delib = elapsedMs >= h15FloorMs
      ? { ok: true }
      : { ok: false, reason: 'too_fast', detail: `${elapsedMs}ms elapsed, ${h15FloorMs}ms required (Fast Lane)` };
  } else {
    delib = checkDeliberation(humanId, severity, config);
  }

  if (!delib.ok) {
    if (severity === 'critical') {
      recordTimingObservation(humanId, elapsedMs, h17FloorMs, h15FloorMs, effectiveFloorMs, bindingFloor, severity, riskScore, 'rejected_h15', 'approve', trustLane, config);
      return delib;
    }
    // warn/info: H15 floor violation is signal-only — approval proceeds.
    // H17 (authenticity) already blocked machine-speed responses above;
    // this path is reached only when elapsed >= minResponseTime but < deliberationFloor.
  }

  // ACCEPTED (or warn/info H15 signal-only) — single write at final exit.
  recordTimingObservation(humanId, elapsedMs, h17FloorMs, h15FloorMs, effectiveFloorMs, bindingFloor, severity, riskScore, 'accepted', 'approve', trustLane, config);
  recordDecision(humanId, decision, elapsedS, severity, config, elapsedMs);
  return { ok: true };
}

// ─── Trust Lane (v3.3.0) ─────────────────────────────────────────────────────
// Demote: fast→guarded→slow (floor at slow). Called on canary failure/miss.
// Restore: slow→guarded→fast (fast only if trust_lane_grant present).

export function applyLaneDemotion(humanId, reason = 'unspecified') {
  const state = loadState(humanId);
  const cur = state.trust_lane || 'guarded';
  if (cur === 'fast') {
    state.trust_lane = 'guarded';
  } else if (cur === 'guarded') {
    state.trust_lane = 'slow';
  }
  state.trust_lane_demotion = { reason, ts: Math.floor(Date.now() / 1000) };
  saveState(humanId, state);
  return { ok: true };
}

export function applyLaneRestore(humanId) {
  const state = loadState(humanId);
  const cur = state.trust_lane || 'guarded';
  if (cur === 'slow') {
    state.trust_lane = 'guarded';
  } else if (cur === 'guarded' && state.trust_lane_grant) {
    state.trust_lane = 'fast';
  }
  saveState(humanId, state);
  return { ok: true };
}
