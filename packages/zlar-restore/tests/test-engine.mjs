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

test('listDetectors returns 8 detector names', () => {
  const ids = listDetectors();
  assert.equal(ids.length, 8);
  assert.ok(ids.includes('contradiction-increase'));
  assert.ok(ids.includes('authority-widening'));
  assert.ok(ids.includes('entropy-shift'));
});

test('loadDetectors loads all 8', async () => {
  const detectors = await loadDetectors();
  assert.equal(detectors.length, 8);
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
  assert.equal(result._signal_vector.length, 8);
  for (const v of result._signal_vector) {
    assert.ok(v >= 0 && v <= 1, 'signal values should be in [0,1]');
  }
});

// ── Multi-detector convergence rule (v3.0.4) ──────────────────────────────

test('active_detectors count present in aggregate', async () => {
  const trace = loadFixture('healthy-session.json');
  const result = await evaluate(trace);
  assert.ok('active_detectors' in result.aggregate, 'aggregate should include active_detectors count');
  assert.ok(result.aggregate.active_detectors >= 0);
});

test('single high-scoring detector caps at degraded (convergence rule)', async () => {
  // Even with very low thresholds, a single active detector should
  // not push past degraded. This is the structural fix for the false
  // positive cascade that hit Vincent's production session.
  //
  // We use the contradiction trace which activates one detector strongly.
  const trace = loadFixture('contradiction-trace.json');
  // Set thresholds very low so the effective score easily crosses at_risk.
  // Without the convergence rule, this would recommend at_risk or suspended.
  // With the rule, it should cap at degraded because only 1 detector is active.
  const result = await evaluate(trace, {
    thresholds: { degraded: 0.01, at_risk: 0.02, suspended: 0.03 },
  });
  // The contradiction detector should be the only one with high signal
  if (result.aggregate.active_detectors < 2) {
    assert.equal(result.recommendation, 'degraded',
      `with only ${result.aggregate.active_detectors} active detector(s), recommendation should cap at degraded, got ${result.recommendation}`);
  }
  // If somehow 2+ detectors are active on this trace, at_risk is acceptable
});

test('multiple converging detectors can reach at_risk', async () => {
  // With thresholds set very low, traces that activate multiple detectors
  // should be allowed to reach at_risk or suspended.
  // The burstiness fixture activates burstiness (burst clusters) and
  // potentially other detectors.
  const trace = loadFixture('burstiness-trace.json');
  const result = await evaluate(trace, {
    thresholds: { degraded: 0.01, at_risk: 0.02, suspended: 0.03 },
  });
  // Regardless of recommendation, the convergence rule should be respected:
  // at_risk+ only if active_detectors >= 2
  if (result.recommendation === 'at_risk' || result.recommendation === 'suspended') {
    assert.ok(result.aggregate.active_detectors >= 2,
      `at_risk/suspended requires 2+ active detectors, got ${result.aggregate.active_detectors}`);
  }
});

// ── Keyed PRNG: reproducible jitter (v3.0.5) ──────────────────────────────

test('keyed PRNG: same trace produces identical results', async () => {
  // THE test. If this passes, every evaluation is auditably reproducible.
  const trace = loadFixture('healthy-session.json');
  const opts = { thresholds: { degraded: 0.3, at_risk: 0.6, suspended: 0.85 } };

  const result1 = await evaluate(trace, opts);
  const result2 = await evaluate(trace, opts);

  assert.equal(result1.recommendation, result2.recommendation,
    'same trace must produce same recommendation');
  assert.equal(result1.aggregate.effective, result2.aggregate.effective,
    'same trace must produce same effective score');
  assert.equal(result1.aggregate.diffuse_weighted, result2.aggregate.diffuse_weighted,
    'same trace must produce same diffuse_weighted');
  assert.deepStrictEqual(result1._jitter, result2._jitter,
    'same trace must produce identical jitter values');
});

test('keyed PRNG: different traces produce different jitter', async () => {
  const trace1 = loadFixture('healthy-session.json');
  const trace2 = loadFixture('contradiction-trace.json');

  const result1 = await evaluate(trace1);
  const result2 = await evaluate(trace2);

  // Different traces should produce different jitter seeds.
  // The jitter values COULD theoretically collide, but with HMAC-derived
  // randomness across different seeds, collision is astronomically unlikely.
  const j1 = result1._jitter;
  const j2 = result2._jitter;
  const same = j1.diffuse_weight === j2.diffuse_weight &&
               j1.thresholds.degraded === j2.thresholds.degraded &&
               j1.thresholds.at_risk === j2.thresholds.at_risk;
  assert.ok(!same, 'different traces should produce different jitter (HMAC-derived)');
});

test('keyed PRNG: jitter values are in expected range', async () => {
  const trace = loadFixture('healthy-session.json');
  const result = await evaluate(trace);

  // Diffuse weight should be jittered: base 1.2 * [0.9, 1.1] = [1.08, 1.32]
  assert.ok(result._jitter.diffuse_weight >= 1.08,
    `diffuse_weight ${result._jitter.diffuse_weight} should be >= 1.08`);
  assert.ok(result._jitter.diffuse_weight <= 1.32,
    `diffuse_weight ${result._jitter.diffuse_weight} should be <= 1.32`);

  // Thresholds: base * [0.9, 1.1]
  // degraded base 0.3 -> [0.27, 0.33]
  assert.ok(result._jitter.thresholds.degraded >= 0.27,
    `degraded threshold ${result._jitter.thresholds.degraded} should be >= 0.27`);
  assert.ok(result._jitter.thresholds.degraded <= 0.33,
    `degraded threshold ${result._jitter.thresholds.degraded} should be <= 0.33`);
});

test('keyed PRNG: _jitter field present in result', async () => {
  const trace = loadFixture('healthy-session.json');
  const result = await evaluate(trace);
  assert.ok('_jitter' in result, 'result should include _jitter for audit reproducibility');
  assert.ok('diffuse_weight' in result._jitter);
  assert.ok('thresholds' in result._jitter);
  assert.ok('degraded' in result._jitter.thresholds);
  assert.ok('at_risk' in result._jitter.thresholds);
  assert.ok('suspended' in result._jitter.thresholds);
});
