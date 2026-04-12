// test-detectors.mjs — Tests for the 5 Agent Health detectors
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const FIXTURE_DIR = join(__dirname, '..', '..', '..', 'tests', 'fixtures', 'restore');

function loadFixture(name) {
  return JSON.parse(readFileSync(join(FIXTURE_DIR, name), 'utf-8'));
}

// ── contradiction-increase ───────────────────────────────────────────────────

import { evaluate as contradictionEval, id as contradictionId } from '../detectors/contradiction-increase.mjs';

test('contradiction detector: has correct id', () => {
  assert.equal(contradictionId, 'contradiction_increase');
});

test('contradiction detector: healthy session scores low', () => {
  const trace = loadFixture('healthy-session.json');
  const result = contradictionEval(trace);
  assert.ok(result.score < 0.3, `expected low score, got ${result.score}`);
  assert.equal(result.evidence.length, 0);
});

test('contradiction detector: contradiction trace scores high', () => {
  const trace = loadFixture('contradiction-trace.json');
  const result = contradictionEval(trace);
  assert.ok(result.score > 0, `expected positive score, got ${result.score}`);
  assert.ok(result.evidence.length > 0, 'expected evidence');
  const types = result.evidence.map(e => e.type);
  assert.ok(types.includes('write_rewrite') || types.includes('deny_retry'), `expected contradiction evidence, got ${types}`);
});

test('contradiction detector: empty trace returns zero', () => {
  const result = contradictionEval([]);
  assert.equal(result.score, 0);
  assert.equal(result.confidence, 0);
});

test('contradiction detector: single event returns zero', () => {
  const result = contradictionEval([{ seq: 1, domain: 'read', action: 'x' }]);
  assert.equal(result.score, 0);
});

// ── escalation-under-ambiguity ───────────────────────────────────────────────

import { evaluate as escalationEval, id as escalationId } from '../detectors/escalation-under-ambiguity.mjs';

test('escalation detector: has correct id', () => {
  assert.equal(escalationId, 'escalation_under_ambiguity');
});

test('escalation detector: healthy session scores low', () => {
  const trace = loadFixture('healthy-session.json');
  const result = escalationEval(trace);
  assert.ok(result.score < 0.3, `expected low score, got ${result.score}`);
});

test('escalation detector: escalation trace scores high', () => {
  const trace = loadFixture('escalation-trace.json');
  const result = escalationEval(trace);
  assert.ok(result.score > 0, `expected positive score, got ${result.score}`);
  assert.ok(result.evidence.length > 0, 'expected evidence');
});

test('escalation detector: no ambiguity means zero score', () => {
  const trace = loadFixture('healthy-session.json');
  const result = escalationEval(trace);
  // healthy session has no denials/asks, so confidence is low
  assert.ok(result.score === 0 || result.confidence < 0.5);
});

// ── source-grounding-loss ────────────────────────────────────────────────────

import { evaluate as groundingEval, id as groundingId } from '../detectors/source-grounding-loss.mjs';

test('grounding detector: has correct id', () => {
  assert.equal(groundingId, 'source_grounding_loss');
});

test('grounding detector: healthy session scores low', () => {
  const trace = loadFixture('healthy-session.json');
  const result = groundingEval(trace);
  assert.ok(result.score < 0.3, `expected low score, got ${result.score}`);
});

test('grounding detector: grounding loss trace scores high', () => {
  const trace = loadFixture('grounding-loss-trace.json');
  const result = groundingEval(trace);
  assert.ok(result.score > 0, `expected positive score, got ${result.score}`);
  assert.ok(result.evidence.length > 0, 'expected evidence of ungrounded windows');
});

test('grounding detector: empty trace returns zero', () => {
  const result = groundingEval([]);
  assert.equal(result.score, 0);
});

// ── abnormal-burstiness ──────────────────────────────────────────────────────

import { evaluate as burstEval, id as burstId } from '../detectors/abnormal-burstiness.mjs';

test('burstiness detector: has correct id', () => {
  assert.equal(burstId, 'abnormal_burstiness');
});

test('burstiness detector: healthy session scores low', () => {
  const trace = loadFixture('healthy-session.json');
  const result = burstEval(trace);
  assert.ok(result.score < 0.3, `expected low score, got ${result.score}`);
});

test('burstiness detector: bursty trace scores high', () => {
  const trace = loadFixture('burstiness-trace.json');
  const result = burstEval(trace);
  assert.ok(result.score > 0, `expected positive score, got ${result.score}`);
  assert.ok(result.evidence.length > 0, 'expected burst evidence');
});

test('burstiness detector: empty trace returns zero', () => {
  const result = burstEval([]);
  assert.equal(result.score, 0);
});

test('burstiness detector: read-heavy explore pattern scores low (v3.0.4 calibration)', () => {
  // Simulates explore agent: rapid reads, then long pause, then more reads.
  // High CV on all intervals, but read domains are excluded from CV calculation.
  // No sub-500ms bursts either (reads are at 2s intervals, not 100ms).
  const now = Date.now();
  const trace = [
    // Burst of reads at 2s intervals
    ...Array.from({ length: 10 }, (_, i) => ({
      seq: i + 1, domain: 'read', action: `file${i}.ts`,
      ts: new Date(now + i * 2000).toISOString(),
    })),
    // 5-minute pause (human thinking)
    // More reads at 2s intervals
    ...Array.from({ length: 10 }, (_, i) => ({
      seq: i + 11, domain: 'glob', action: '**/*.ts',
      ts: new Date(now + 20000 + 300000 + i * 2000).toISOString(),
    })),
    // Another 3-minute pause
    // Final reads
    ...Array.from({ length: 10 }, (_, i) => ({
      seq: i + 21, domain: 'grep', action: 'function',
      ts: new Date(now + 40000 + 300000 + 180000 + i * 2000).toISOString(),
    })),
  ];
  const result = burstEval(trace);
  // Read-only trace: CV calculated on zero write-class events, so cvScore = 0.
  // No sub-500ms bursts (2s intervals). Score should be 0.
  assert.equal(result.score, 0, `read-heavy explore pattern should score 0, got ${result.score}`);
});

test('burstiness detector: write bursts at 100ms still caught (v3.0.4 calibration)', () => {
  // Even with read exclusion, sub-500ms write bursts are still caught.
  const now = Date.now();
  const trace = [
    ...Array.from({ length: 5 }, (_, i) => ({
      seq: i + 1, domain: 'edit', action: `file${i}.ts`,
      ts: new Date(now + i * 100).toISOString(),
    })),
    // gap
    ...Array.from({ length: 5 }, (_, i) => ({
      seq: i + 6, domain: 'write', action: `out${i}.ts`,
      ts: new Date(now + 60000 + i * 100).toISOString(),
    })),
  ];
  const result = burstEval(trace);
  assert.ok(result.score > 0, `100ms write bursts should still be caught, got ${result.score}`);
  assert.ok(result.evidence.some(e => e.type === 'burst'), 'should have burst evidence');
});

// ── authority-widening ───────────────────────────────────────────────────────

import { evaluate as wideningEval, id as wideningId } from '../detectors/authority-widening.mjs';

test('widening detector: has correct id', () => {
  assert.equal(wideningId, 'authority_widening');
});

test('widening detector: healthy session scores low', () => {
  const trace = loadFixture('healthy-session.json');
  const result = wideningEval(trace);
  assert.ok(result.score < 0.3, `expected low score, got ${result.score}`);
});

test('widening detector: widening trace scores high', () => {
  const trace = loadFixture('authority-widening-trace.json');
  const result = wideningEval(trace);
  assert.ok(result.score > 0, `expected positive score, got ${result.score}`);
  assert.ok(result.evidence.length > 0, 'expected widening evidence');
  const types = result.evidence.map(e => e.type);
  assert.ok(types.includes('new_domain') || types.includes('post_denial_new_domain'));
});

test('widening detector: empty trace returns zero', () => {
  const result = wideningEval([]);
  assert.equal(result.score, 0);
});

// ── Cross-detector: all detectors handle healthy trace ───────────────────────

test('all detectors score healthy trace below 0.3', () => {
  const trace = loadFixture('healthy-session.json');
  const detectors = [contradictionEval, escalationEval, groundingEval, burstEval, wideningEval];
  const ids = [contradictionId, escalationId, groundingId, burstId, wideningId];
  for (let i = 0; i < detectors.length; i++) {
    const result = detectors[i](trace);
    assert.ok(result.score < 0.3, `${ids[i]} scored ${result.score} on healthy trace (expected < 0.3)`);
  }
});
