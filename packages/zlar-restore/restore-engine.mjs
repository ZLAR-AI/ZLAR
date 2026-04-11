// restore-engine.mjs — Agent Health evaluation engine
//
// Loads detectors, runs them against a session trace, aggregates results,
// and produces a trust-state recommendation.
//
// The engine does not write trust state directly. It returns a recommendation
// that the caller (CLI or gate trigger) applies via the trust-state machine.
//
// Invariants:
//   RESTORE-INV-07: Detectors are composable and independently removable.
//   RESTORE-INV-08: Trust state is derived from audit trail (rebuild-capable).

import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readdirSync } from 'node:fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ── Detector loading ─────────────────────────────────────────────────────────

const DETECTOR_DIR = join(__dirname, 'detectors');

const DETECTOR_IDS = [
  'contradiction-increase',
  'escalation-under-ambiguity',
  'source-grounding-loss',
  'abnormal-burstiness',
  'authority-widening',
];

let loadedDetectors = null;

export async function loadDetectors() {
  if (loadedDetectors) return loadedDetectors;

  loadedDetectors = [];
  for (const name of DETECTOR_IDS) {
    const path = join(DETECTOR_DIR, `${name}.mjs`);
    try {
      const mod = await import(path);
      if (typeof mod.evaluate === 'function') {
        loadedDetectors.push({
          id: mod.id || name,
          description: mod.description || '',
          evaluate: mod.evaluate,
        });
      }
    } catch {
      // RESTORE-INV-07: missing detector does not crash the engine
    }
  }

  return loadedDetectors;
}

export function listDetectors() {
  return DETECTOR_IDS;
}

// ── Evaluation ───────────────────────────────────────────────────────────────

// Thresholds for mapping aggregate scores to trust state recommendations.
// These are conservative defaults — can be overridden via config.
const DEFAULT_THRESHOLDS = {
  degraded: 0.3,    // any detector above 0.3 -> degraded
  at_risk: 0.6,     // any detector above 0.6 -> at_risk
  suspended: 0.85,  // any detector above 0.85 -> suspended
};

// Evaluate a trace against all detectors.
// Returns { recommendation, detectors: {...}, aggregate }
export async function evaluate(trace, thresholds = DEFAULT_THRESHOLDS) {
  const detectors = await loadDetectors();
  const results = {};
  let maxScore = 0;
  let maxDetector = null;

  for (const detector of detectors) {
    try {
      const result = detector.evaluate(trace);
      results[detector.id] = {
        score: result.score,
        confidence: result.confidence,
        evidence_count: (result.evidence || []).length,
        evidence: result.evidence || [],
      };

      // Weighted score: score * confidence
      const weighted = result.score * result.confidence;
      if (weighted > maxScore) {
        maxScore = weighted;
        maxDetector = detector.id;
      }
    } catch {
      results[detector.id] = {
        score: 0,
        confidence: 0,
        evidence_count: 0,
        error: 'detector evaluation failed',
      };
    }
  }

  // Map max weighted score to trust state recommendation
  let recommendation = 'healthy';
  if (maxScore >= thresholds.suspended) {
    recommendation = 'suspended';
  } else if (maxScore >= thresholds.at_risk) {
    recommendation = 'at_risk';
  } else if (maxScore >= thresholds.degraded) {
    recommendation = 'degraded';
  }

  return {
    recommendation,
    primary_detector: maxDetector,
    aggregate_score: round(maxScore),
    detectors: results,
    trace_length: trace.length,
    evaluated_at: new Date().toISOString(),
  };
}

function round(n) {
  return Math.round(n * 100) / 100;
}
