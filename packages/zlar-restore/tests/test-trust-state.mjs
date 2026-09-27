// test-trust-state.mjs — Tests for the monotone trust-state machine
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  STATES, stateRank, isValidState,
  loadTrustState, saveTrustState,
  proposeTransition, applyTransition,
  resetTrustState,
} from '../trust-state.mjs';

// ── State definitions ────────────────────────────────────────────────────────

test('STATES contains exactly 4 states in order', () => {
  assert.deepEqual(STATES, ['healthy', 'degraded', 'at_risk', 'suspended']);
});

test('stateRank returns correct ordering', () => {
  assert.equal(stateRank('healthy'), 0);
  assert.equal(stateRank('degraded'), 1);
  assert.equal(stateRank('at_risk'), 2);
  assert.equal(stateRank('suspended'), 3);
  assert.equal(stateRank('invalid'), -1);
});

test('isValidState accepts valid states', () => {
  for (const s of STATES) {
    assert.ok(isValidState(s), `${s} should be valid`);
  }
  assert.ok(!isValidState('banana'));
  assert.ok(!isValidState(''));
  assert.ok(!isValidState(undefined));
});

// ── Loading trust state ──────────────────────────────────────────────────────

test('RESTORE-INV-01: absent file returns healthy', () => {
  const state = loadTrustState('/nonexistent/path.json');
  assert.equal(state.state, 'healthy');
});

test('RESTORE-INV-02: malformed file returns degraded', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zlar-test-'));
  try {
    const file = join(dir, 'state.json');
    writeFileSync(file, 'not json');
    const state = loadTrustState(file);
    assert.equal(state.state, 'degraded');
    assert.ok(state.history.length > 0);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('RESTORE-INV-02: missing state field returns degraded', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zlar-test-'));
  try {
    const file = join(dir, 'state.json');
    writeFileSync(file, '{"session_id":"x"}');
    const state = loadTrustState(file);
    assert.equal(state.state, 'degraded');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('RESTORE-INV-02: invalid state value returns degraded', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zlar-test-'));
  try {
    const file = join(dir, 'state.json');
    writeFileSync(file, '{"state":"banana"}');
    const state = loadTrustState(file);
    assert.equal(state.state, 'degraded');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('valid state file loads correctly', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zlar-test-'));
  try {
    const file = join(dir, 'state.json');
    const data = { state: 'at_risk', updated_at: '2026-04-12T10:00:00Z', detectors: {}, history: [], reset_count: 1 };
    writeFileSync(file, JSON.stringify(data));
    const state = loadTrustState(file);
    assert.equal(state.state, 'at_risk');
    assert.equal(state.reset_count, 1);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

// ── Save + load round-trip ───────────────────────────────────────────────────

test('saveTrustState creates directories and round-trips', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zlar-test-'));
  try {
    const file = join(dir, 'sub', 'deep', 'state.json');
    const data = { state: 'degraded', updated_at: '2026-04-12T10:00:00Z', detectors: {}, history: [], reset_count: 0 };
    saveTrustState(file, data);
    const loaded = loadTrustState(file);
    assert.equal(loaded.state, 'degraded');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

// ── RESTORE-INV-03: Monotone transitions ─────────────────────────────────────

test('proposeTransition accepts worsening transitions', () => {
  const result = proposeTransition('healthy', 'degraded', 'test');
  assert.ok(result.accepted);
  assert.equal(result.from, 'healthy');
  assert.equal(result.to, 'degraded');
});

test('proposeTransition accepts multi-step worsening', () => {
  const result = proposeTransition('healthy', 'suspended', 'test');
  assert.ok(result.accepted);
  assert.equal(result.to, 'suspended');
});

test('proposeTransition rejects non-monotone: degraded -> healthy', () => {
  const result = proposeTransition('degraded', 'healthy', 'test');
  assert.ok(!result.accepted);
  assert.match(result.reason, /non-monotone/);
});

test('proposeTransition rejects same state', () => {
  const result = proposeTransition('degraded', 'degraded', 'test');
  assert.ok(!result.accepted);
});

test('proposeTransition rejects improving: at_risk -> degraded', () => {
  const result = proposeTransition('at_risk', 'degraded', 'test');
  assert.ok(!result.accepted);
});

test('proposeTransition handles invalid current state', () => {
  const result = proposeTransition('invalid', 'degraded', 'test');
  assert.ok(result.accepted);
  assert.equal(result.to, 'degraded');
});

test('proposeTransition rejects invalid proposed state', () => {
  const result = proposeTransition('healthy', 'invalid', 'test');
  assert.ok(!result.accepted);
});

// ── applyTransition ──────────────────────────────────────────────────────────

test('applyTransition updates state and appends history', () => {
  const initial = { state: 'healthy', updated_at: null, detectors: {}, history: [], reset_count: 0 };
  const transition = proposeTransition('healthy', 'degraded', 'detector:test');
  const updated = applyTransition(initial, transition);
  assert.equal(updated.state, 'degraded');
  assert.equal(updated.history.length, 1);
  assert.equal(updated.history[0].from, 'healthy');
  assert.equal(updated.history[0].to, 'degraded');
});

test('applyTransition does nothing for rejected transition', () => {
  const initial = { state: 'degraded', history: [] };
  const transition = proposeTransition('degraded', 'healthy', 'test');
  const updated = applyTransition(initial, transition);
  assert.equal(updated.state, 'degraded');
  assert.equal(updated.history.length, 0);
});

// ── RESTORE-INV-06: Reset with friction ──────────────────────────────────────

test('resetTrustState requires reason', () => {
  const state = { state: 'at_risk', history: [], reset_count: 0 };
  const result = resetTrustState(state, '', 'operator-1');
  assert.ok(!result.accepted);
  assert.match(result.reason, /reason/);
});

test('resetTrustState returns to healthy with history', () => {
  const state = { state: 'at_risk', history: [{ from: 'healthy', to: 'at_risk' }], reset_count: 0 };
  const result = resetTrustState(state, 'Investigation complete, false positive', 'operator-1');
  assert.ok(result.accepted);
  assert.equal(result.trustState.state, 'healthy');
  assert.equal(result.trustState.reset_count, 1);
  assert.equal(result.trustState.history.length, 2);
  assert.equal(result.trustState.history[1].source, 'operator_reset');
  assert.match(result.trustState.history[1].reason, /Investigation complete/);
});

test('resetTrustState increments reset count', () => {
  const state = { state: 'suspended', history: [], reset_count: 2 };
  const result = resetTrustState(state, 'Third reset', 'operator-1');
  assert.ok(result.accepted);
  assert.equal(result.trustState.reset_count, 3);
});
