// trust-state.mjs — Monotone trust-state machine for Agent Health
//
// States: healthy -> degraded -> at_risk -> suspended
//
// Invariants:
//   RESTORE-INV-03: Monotone transitions — state can only worsen.
//     Reset to healthy requires explicit human action with friction.
//   RESTORE-INV-05: Restore observes, does not enforce directly.
//     State changes are recommendations; the gate consults lib/restore.sh.
//   RESTORE-INV-06: Reset requires friction — reason, signed event, count.
//
// The trust-state machine operates on transitions, not scores.
// Detectors produce scores; the engine maps scores to state proposals;
// this machine accepts or rejects the proposal monotonically.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

// ── State definitions ────────────────────────────────────────────────────────

export const STATES = ['healthy', 'degraded', 'at_risk', 'suspended'];

const STATE_RANK = Object.fromEntries(STATES.map((s, i) => [s, i]));

export function stateRank(state) {
  return STATE_RANK[state] ?? -1;
}

export function isValidState(state) {
  return STATES.includes(state);
}

// ── State file I/O ───────────────────────────────────────────────────────────

const EMPTY_STATE = {
  state: 'healthy',
  updated_at: null,
  detectors: {},
  history: [],
  reset_count: 0,
};

export function loadTrustState(filePath) {
  if (!existsSync(filePath)) {
    return { ...EMPTY_STATE };
  }

  try {
    const raw = readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(raw);

    // RESTORE-INV-02: malformed file = degraded
    if (!parsed || typeof parsed !== 'object' || !isValidState(parsed.state)) {
      return {
        ...EMPTY_STATE,
        state: 'degraded',
        updated_at: new Date().toISOString(),
        history: [{ from: 'unknown', to: 'degraded', reason: 'malformed trust state file', source: 'trust-state-loader', at: new Date().toISOString() }],
      };
    }

    return parsed;
  } catch {
    // Parse error = degraded
    return {
      ...EMPTY_STATE,
      state: 'degraded',
      updated_at: new Date().toISOString(),
      history: [{ from: 'unknown', to: 'degraded', reason: 'trust state file parse error', source: 'trust-state-loader', at: new Date().toISOString() }],
    };
  }
}

export function saveTrustState(filePath, trustState) {
  const dir = dirname(filePath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(filePath, JSON.stringify(trustState, null, 2) + '\n');
}

// ── Monotone transition ──────────────────────────────────────────────────────

// RESTORE-INV-03: Only accept transitions that worsen the state.
// Returns { accepted, from, to, reason } or { accepted: false, reason }.
export function proposeTransition(currentState, proposedState, source, evidence) {
  if (!isValidState(currentState)) {
    return { accepted: true, from: currentState, to: 'degraded', source, reason: 'invalid current state' };
  }

  if (!isValidState(proposedState)) {
    return { accepted: false, reason: `invalid proposed state: ${proposedState}` };
  }

  const currentRank = stateRank(currentState);
  const proposedRank = stateRank(proposedState);

  // Monotone: only worsening transitions
  if (proposedRank <= currentRank) {
    return { accepted: false, reason: `non-monotone: ${currentState} -> ${proposedState}` };
  }

  return {
    accepted: true,
    from: currentState,
    to: proposedState,
    source,
    evidence: evidence || null,
    at: new Date().toISOString(),
  };
}

// Apply a transition to the trust state object.
// Returns the updated trust state (new object, not mutated).
export function applyTransition(trustState, transition) {
  if (!transition.accepted) {
    return trustState;
  }

  return {
    ...trustState,
    state: transition.to,
    updated_at: transition.at,
    history: [...(trustState.history || []), {
      from: transition.from,
      to: transition.to,
      reason: transition.reason || transition.source,
      source: transition.source,
      evidence: transition.evidence,
      at: transition.at,
    }],
  };
}

// ── Reset ────────────────────────────────────────────────────────────────────
//
// RESTORE-INV-06: Reset requires friction.
// - reason: must be provided
// - count: tracked and reported
// - signed event: the reset itself is a history entry
//
// Delay enforcement is the caller's responsibility (CLI waits delay_s).

export function resetTrustState(trustState, reason, operatorId) {
  if (!reason || reason.trim().length === 0) {
    return { accepted: false, reason: 'reset requires a reason' };
  }

  const now = new Date().toISOString();
  const resetCount = (trustState.reset_count || 0) + 1;

  return {
    accepted: true,
    trustState: {
      state: 'healthy',
      updated_at: now,
      detectors: {},
      history: [...(trustState.history || []), {
        from: trustState.state,
        to: 'healthy',
        reason: `operator reset: ${reason}`,
        source: 'operator_reset',
        operator_id: operatorId || 'unknown',
        reset_number: resetCount,
        at: now,
      }],
      reset_count: resetCount,
    },
  };
}
