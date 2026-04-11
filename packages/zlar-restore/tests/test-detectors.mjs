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
