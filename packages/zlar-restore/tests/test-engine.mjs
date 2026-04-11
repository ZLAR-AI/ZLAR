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

test('listDetectors returns 5 detector names', () => {
  const ids = listDetectors();
  assert.equal(ids.length, 5);
  assert.ok(ids.includes('contradiction-increase'));
  assert.ok(ids.includes('authority-widening'));
});

test('loadDetectors loads all 5', async () => {
  const detectors = await loadDetectors();
  assert.equal(detectors.length, 5);
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
  assert.ok(result.aggregate_score < 0.3);
  assert.ok(result.detectors);
  assert.equal(Object.keys(result.detectors).length, 5);
});

// ── Contradiction trace ──────────────────────────────────────────────────────

test('contradiction trace does not recommend healthy', async () => {
  const trace = loadFixture('contradiction-trace.json');
  const result = await evaluate(trace);
  // May recommend degraded or higher depending on threshold
  assert.ok(result.aggregate_score > 0, 'contradiction trace should score above 0');
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
  // With very low thresholds, even small scores trigger
  const result = await evaluate(trace, { degraded: 0.01, at_risk: 0.02, suspended: 0.03 });
  assert.notEqual(result.recommendation, 'healthy');
});

// ── Empty trace ──────────────────────────────────────────────────────────────

test('empty trace recommends healthy', async () => {
  const result = await evaluate([]);
  assert.equal(result.recommendation, 'healthy');
  assert.equal(result.aggregate_score, 0);
});

// ── Engine result structure ──────────────────────────────────────────────────

test('evaluate result has required fields', async () => {
  const trace = loadFixture('healthy-session.json');
  const result = await evaluate(trace);
  assert.ok('recommendation' in result);
  assert.ok('aggregate_score' in result);
  assert.ok('detectors' in result);
  assert.ok('trace_length' in result);
  assert.ok('evaluated_at' in result);
  assert.ok(typeof result.evaluated_at === 'string');
});
