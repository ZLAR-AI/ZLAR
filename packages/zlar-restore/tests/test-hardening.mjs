// test-hardening.mjs — Tests for v3.1 hardening: HMAC, entropy, evaluation history
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// ── HMAC integrity tests ────────────────────────────────────────────────────

import {
  setHmacKey, loadTrustState, saveTrustState,
} from '../trust-state.mjs';

test('HMAC: save and load round-trips with valid HMAC', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zlar-hmac-'));
  try {
    setHmacKey('test-secret-key-12345');
    const file = join(dir, 'state.json');
    const data = { state: 'degraded', updated_at: '2026-04-12T10:00:00Z', detectors: {}, history: [], reset_count: 0 };
    saveTrustState(file, data);

    // File should contain _hmac field
    const raw = JSON.parse(readFileSync(file, 'utf-8'));
    assert.ok(raw._hmac, 'saved file should contain _hmac');
    assert.ok(raw._hmac.length > 10, 'HMAC should be a hex string');

    // Load should succeed and strip _hmac
    const loaded = loadTrustState(file);
    assert.equal(loaded.state, 'degraded');
    assert.ok(!loaded._hmac, '_hmac should be stripped from loaded state');
  } finally {
    setHmacKey(null);
    rmSync(dir, { recursive: true });
  }
});

test('HMAC: tampered file returns degraded', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zlar-hmac-'));
  try {
    setHmacKey('test-secret-key-12345');
    const file = join(dir, 'state.json');
    const data = { state: 'at_risk', updated_at: '2026-04-12T10:00:00Z', detectors: {}, history: [], reset_count: 0 };
    saveTrustState(file, data);

    // Tamper with the file: change state to healthy but keep old HMAC
    const raw = JSON.parse(readFileSync(file, 'utf-8'));
    raw.state = 'healthy';
    writeFileSync(file, JSON.stringify(raw));

    // Load should detect tampering and return degraded
    const loaded = loadTrustState(file);
    assert.equal(loaded.state, 'degraded');
    assert.ok(loaded.history.some(h => h.reason.includes('HMAC')), 'history should mention HMAC failure');
  } finally {
    setHmacKey(null);
    rmSync(dir, { recursive: true });
  }
});

test('HMAC: missing HMAC field with key set returns degraded', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zlar-hmac-'));
  try {
    setHmacKey('test-secret-key-12345');
    const file = join(dir, 'state.json');
    // Write a file without _hmac
    writeFileSync(file, JSON.stringify({ state: 'healthy', updated_at: null, detectors: {}, history: [], reset_count: 0 }));

    const loaded = loadTrustState(file);
    assert.equal(loaded.state, 'degraded', 'missing HMAC with key set should be degraded');
  } finally {
    setHmacKey(null);
    rmSync(dir, { recursive: true });
  }
});

test('HMAC: no key set skips verification', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zlar-hmac-'));
  try {
    setHmacKey(null);
    const file = join(dir, 'state.json');
    writeFileSync(file, JSON.stringify({ state: 'at_risk', updated_at: null, detectors: {}, history: [], reset_count: 0 }));

    const loaded = loadTrustState(file);
    assert.equal(loaded.state, 'at_risk', 'no key = no verification = trust the file');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('HMAC: save without key produces no _hmac field', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zlar-hmac-'));
  try {
    setHmacKey(null);
    const file = join(dir, 'state.json');
    saveTrustState(file, { state: 'healthy', updated_at: null, detectors: {}, history: [], reset_count: 0 });

    const raw = JSON.parse(readFileSync(file, 'utf-8'));
    assert.ok(!raw._hmac, 'no key = no _hmac field');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

// ── Entropy shift detector tests ────────────────────────────────────────────

import { evaluate as entropyEvaluate } from '../detectors/entropy-shift.mjs';

test('entropy: short trace returns score 0', () => {
  const result = entropyEvaluate([]);
  assert.equal(result.score, 0);
  assert.equal(result.confidence, 0);
});

test('entropy: stable diverse session scores low', () => {
  // 40 events with consistent domain mix
  const domains = ['read', 'write', 'edit', 'bash', 'glob'];
  const trace = Array.from({ length: 40 }, (_, i) => ({
    seq: 1, domain: domains[i % domains.length],
    ts: new Date(Date.now() + i * 5000).toISOString(),
  }));
  const result = entropyEvaluate(trace);
  assert.ok(result.score < 0.3, `stable diverse session should score low, got ${result.score}`);
});

test('entropy: sudden narrowing scores high', () => {
  // First 20 events: diverse. Last 20: only writes.
  const domains = ['read', 'write', 'edit', 'bash', 'glob'];
  const trace = [
    ...Array.from({ length: 20 }, (_, i) => ({
      seq: 1, domain: domains[i % domains.length],
      ts: new Date(Date.now() + i * 5000).toISOString(),
    })),
    ...Array.from({ length: 20 }, (_, i) => ({
      seq: 1, domain: 'write',
      ts: new Date(Date.now() + (20 + i) * 5000).toISOString(),
    })),
  ];
  const result = entropyEvaluate(trace);
  assert.ok(result.score > 0.2, `entropy drop from diverse to uniform should score high, got ${result.score}`);
  assert.ok(result.evidence.some(e => e.type === 'entropy_drop'), 'should have entropy_drop evidence');
});

test('entropy: sudden expansion scores high', () => {
  // First 20: only reads. Last 20: everything.
  const domains = ['read', 'write', 'edit', 'bash', 'glob', 'grep'];
  const trace = [
    ...Array.from({ length: 20 }, (_, i) => ({
      seq: 1, domain: 'read',
      ts: new Date(Date.now() + i * 5000).toISOString(),
    })),
    ...Array.from({ length: 20 }, (_, i) => ({
      seq: 1, domain: domains[i % domains.length],
      ts: new Date(Date.now() + (20 + i) * 5000).toISOString(),
    })),
  ];
  const result = entropyEvaluate(trace);
  assert.ok(result.score > 0.2, `entropy rise from uniform to diverse should score high, got ${result.score}`);
  assert.ok(result.evidence.some(e => e.type === 'entropy_rise'), 'should have entropy_rise evidence');
});

// ── Evaluation history tests ────────────────────────────────────────────────

import { loadHistory, appendHistory, setHistoryHmacKey } from '../evaluation-history.mjs';

test('history: empty file returns empty array', () => {
  const h = loadHistory('/nonexistent/history.json');
  assert.deepEqual(h, []);
});

test('history: append and load round-trips', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zlar-hist-'));
  try {
    const file = join(dir, 'history.json');
    appendHistory(file, [0.1, 0.2, 0.3]);
    appendHistory(file, [0.4, 0.5, 0.6]);

    const h = loadHistory(file);
    assert.equal(h.length, 2);
    assert.deepEqual(h[0], [0.1, 0.2, 0.3]);
    assert.deepEqual(h[1], [0.4, 0.5, 0.6]);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('history: respects max entries (ring buffer)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zlar-hist-'));
  try {
    const file = join(dir, 'history.json');
    for (let i = 0; i < 15; i++) {
      appendHistory(file, [i]);
    }
    const h = loadHistory(file);
    assert.ok(h.length <= 8, `history should be capped at 8, got ${h.length}`);
    // Last entry should be most recent
    assert.deepEqual(h[h.length - 1], [14]);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('history: malformed file returns empty array', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zlar-hist-'));
  try {
    const file = join(dir, 'history.json');
    writeFileSync(file, 'not json at all');
    const h = loadHistory(file);
    assert.deepEqual(h, []);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('history HMAC: round-trips with valid HMAC', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zlar-hist-hmac-'));
  try {
    setHistoryHmacKey('history-test-key-456');
    const file = join(dir, 'history.json');
    appendHistory(file, [0.1, 0.2]);
    appendHistory(file, [0.3, 0.4]);
    const h = loadHistory(file);
    assert.equal(h.length, 2);
    assert.deepEqual(h[0], [0.1, 0.2]);

    // File should have _hmac and entries fields
    const raw = JSON.parse(readFileSync(file, 'utf-8'));
    assert.ok(raw._hmac, 'should have _hmac field');
    assert.ok(raw.entries, 'should have entries field');
  } finally {
    setHistoryHmacKey(null);
    rmSync(dir, { recursive: true });
  }
});

test('history HMAC: tampered file returns empty array', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zlar-hist-hmac-'));
  try {
    setHistoryHmacKey('history-test-key-456');
    const file = join(dir, 'history.json');
    appendHistory(file, [0.1, 0.2]);

    // Tamper with entries
    const raw = JSON.parse(readFileSync(file, 'utf-8'));
    raw.entries = [[0.9, 0.9]]; // attacker flattens history
    writeFileSync(file, JSON.stringify(raw));

    const h = loadHistory(file);
    assert.deepEqual(h, [], 'tampered history should return empty');
  } finally {
    setHistoryHmacKey(null);
    rmSync(dir, { recursive: true });
  }
});

test('history HMAC: no key means no verification', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zlar-hist-hmac-'));
  try {
    setHistoryHmacKey(null);
    const file = join(dir, 'history.json');
    appendHistory(file, [0.5, 0.6]);
    const h = loadHistory(file);
    assert.equal(h.length, 1);

    // File should be plain array (no HMAC wrapper)
    const raw = JSON.parse(readFileSync(file, 'utf-8'));
    assert.ok(Array.isArray(raw), 'without key, should be plain array');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

// ── Detector reliability tests (via engine) ─────────────────────────────────

import { evaluate as engineEvaluate } from '../restore-engine.mjs';

test('detector reliability: engine returns _signal_vector with correct length', async () => {
  const trace = Array.from({ length: 20 }, (_, i) => ({
    seq: 1,
    domain: 'read',
    action: 'cat foo.txt',
    outcome: 'allow',
    risk_score: 10,
    ts: new Date(Date.now() + i * 10000).toISOString(),
    detail: '{}',
  }));
  const result = await engineEvaluate(trace);
  assert.equal(result._signal_vector.length, 6, 'signal vector should match 6 detectors');
});
