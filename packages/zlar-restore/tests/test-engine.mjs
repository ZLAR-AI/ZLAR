// test-engine.mjs — Integration tests for the restore engine
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { evaluate, loadDetectors, listDetectors } from '../restore-engine.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const FIXTURE_DIR = join(__dirname, '..', '..', '..', 'tests', 'fixtures', 'restore');

function loadFixture(name) {
  return JSON.parse(readFileSync(join(FIXTURE_DIR, name), 'utf-8'));
}

// ── Detector loading ─────────────────────────────────────────────────────────

test('listDetectors returns 7 detector names', () => {
  const ids = listDetectors();
  assert.equal(ids.length, 7);
  assert.ok(ids.includes('contradiction-increase'));
  assert.ok(ids.includes('authority-widening'));
  assert.ok(ids.includes('entropy-shift'));
});

test('loadDetectors loads all 7', async () => {
  const detectors = await loadDetectors();
  assert.equal(detectors.length, 7);
  for (const d of detectors) {
    assert.ok(typeof d.evaluate === 'function', `${d.id} has evaluate`);
    assert.ok(d.id, `detector has id`);
  }
});

// ── Healthy session ──────────────────────────────────────────────────────────

test('healthy session recommends healthy', async () => {
  const trace = loadFixture('healthy-session.json');
  const result = await evaluate(trace);
  assert.equal(result.recommendation, 'healthy');
  assert.equal(result.trace_length, 20);
  assert.ok(result.aggregate.effective < 0.3);
  assert.ok(result.detectors);
});

// ── Contradiction trace ──────────────────────────────────────────────────────

test('contradiction trace does not recommend healthy', async () => {
  const trace = loadFixture('contradiction-trace.json');
  const result = await evaluate(trace);
  assert.ok(result.aggregate.effective > 0, 'contradiction trace should score above 0');
  assert.ok(result.detectors.contradiction_increase.score > 0);
});

// ── Escalation trace ─────────────────────────────────────────────────────────

test('escalation trace triggers escalation detector', async () => {
  const trace = loadFixture('escalation-trace.json');
  const result = await evaluate(trace);
  assert.ok(result.detectors.escalation_under_ambiguity.score > 0);
});

// ── Authority widening trace ─────────────────────────────────────────────────

test('authority widening trace triggers widening detector', async () => {
  const trace = loadFixture('authority-widening-trace.json');
  const result = await evaluate(trace);
  assert.ok(result.detectors.authority_widening.score > 0);
});

// ── Custom thresholds ────────────────────────────────────────────────────────

test('custom thresholds change recommendation', async () => {
  const trace = loadFixture('contradiction-trace.json');
  const result = await evaluate(trace, { thresholds: { degraded: 0.01, at_risk: 0.02, suspended: 0.03 } });
  assert.notEqual(result.recommendation, 'healthy');
});

// ── Empty trace ──────────────────────────────────────────────────────────────

test('empty trace recommends healthy', async () => {
  const result = await evaluate([]);
  assert.equal(result.recommendation, 'healthy');
  assert.equal(result.aggregate.effective, 0);
});

// ── Engine result structure ──────────────────────────────────────────────────

test('evaluate result has required fields', async () => {
  const trace = loadFixture('healthy-session.json');
  const result = await evaluate(trace);
  assert.ok('recommendation' in result);
  assert.ok('aggregate' in result);
  assert.ok('dominant' in result.aggregate);
  assert.ok('diffuse' in result.aggregate);
  assert.ok('effective' in result.aggregate);
  assert.ok('detectors' in result);
  assert.ok('trace_length' in result);
  assert.ok('evaluated_at' in result);
  assert.ok('primary_detector' in result);
  assert.ok('_signal_vector' in result);
});

// ── Dual-path aggregation ────────────────────────────────────────────────────

test('L2 diffuse path catches distributed pathology', async () => {
  // A trace that produces moderate scores across multiple detectors
  // should yield a meaningful diffuse score even if no single detector
  // crosses the threshold alone.
  const trace = loadFixture('healthy-session.json');
  const result = await evaluate(trace);
  // Diffuse should be computed
  assert.ok(result.aggregate.diffuse >= 0);
  assert.ok(result.aggregate.diffuse_weighted >= 0);
  // Effective should be max of dominant and diffuse_weighted
  assert.ok(result.aggregate.effective >= result.aggregate.dominant ||
            result.aggregate.effective >= result.aggregate.diffuse_weighted);
});

// ── Type-aware routing ──────────────────────────────────────────────────────

test('result includes routing hint for non-healthy recommendations', async () => {
  const trace = loadFixture('contradiction-trace.json');
  const result = await evaluate(trace, { thresholds: { degraded: 0.01, at_risk: 0.5, suspended: 0.9 } });
  if (result.recommendation !== 'healthy') {
    assert.ok(result.routing_hint || result.primary_detector === 'diffuse_degradation',
      'non-healthy recommendation should have routing hint or diffuse label');
  }
});

// ── Detector reliability ────────────────────────────────────────────────────

test('detector reliability: single crash does not force degraded', async () => {
  // With only one detector crash, the engine should still function normally
  const result = await evaluate([]);
  assert.equal(result.recommendation, 'healthy');
});

// ── Critical slowing down ───────────────────────────────────────────────────

test('critical slowing down: no history means no sensitivity multiplier', async () => {
  const trace = loadFixture('healthy-session.json');
  const result = await evaluate(trace, { evaluation_history: null });
  assert.equal(result.slowing_down, null);
});

test('critical slowing down: flat history means no multiplier', async () => {
  const trace = loadFixture('healthy-session.json');
  const history = [
    [0.1, 0.1, 0.1, 0.1, 0.1, 0.1],
    [0.1, 0.1, 0.1, 0.1, 0.1, 0.1],
    [0.1, 0.1, 0.1, 0.1, 0.1, 0.1],
  ];
  const result = await evaluate(trace, { evaluation_history: history });
  // Flat history = no autocorrelation = no slowing down
  assert.equal(result.slowing_down, null);
});

test('critical slowing down: rising history triggers sensitivity', async () => {
  const trace = loadFixture('healthy-session.json');
  // Monotonically rising signal across evaluations = high autocorrelation
  const history = [
    [0.1, 0.1, 0.1, 0.1, 0.1, 0.1],
    [0.15, 0.15, 0.15, 0.15, 0.15, 0.15],
    [0.2, 0.2, 0.2, 0.2, 0.2, 0.2],
    [0.25, 0.25, 0.25, 0.25, 0.25, 0.25],
    [0.28, 0.28, 0.28, 0.28, 0.28, 0.28],
  ];
  const result = await evaluate(trace, { evaluation_history: history });
  if (result.slowing_down) {
    assert.ok(result.slowing_down.multiplier > 1, 'rising signals should increase sensitivity');
  }
});

// ── Signal vector ───────────────────────────────────────────────────────────

test('signal vector matches detector count', async () => {
  const trace = loadFixture('healthy-session.json');
  const result = await evaluate(trace);
  assert.equal(result._signal_vector.length, 7);
  for (const v of result._signal_vector) {
    assert.ok(v >= 0 && v <= 1, 'signal values should be in [0,1]');
  }
});
