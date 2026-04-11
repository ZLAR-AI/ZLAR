// restore-engine.mjs — Agent Health evaluation engine
//
// Loads detectors, runs them against a session trace, aggregates results,
// and produces a trust-state recommendation.
//
// The engine does not write trust state directly. It returns a recommendation
// that the caller (CLI or gate trigger) applies via the trust-state machine.
//
// Aggregation: dual-path scoring (dominant + diffuse).
//   Path A (dominant): max(score * confidence) — single strong signal.
//   Path B (diffuse): L2 norm of signal vector / sqrt(N) — distributed pathology.
//   Effective score = max(dominant, diffuse * DIFFUSE_WEIGHT).
//
// Critical slowing down: if evaluation history shows rising autocorrelation
// across detectors, thresholds become more sensitive.
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
  'entropy-shift',
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

// ── Type-aware routing hints ────────────────────────────────────────────────

const ROUTING_HINTS = {
  contradiction_increase: {
    syndrome: 'confusion',
    advice: 'Agent may be stuck in a loop. Check what it is trying to do — possibly reset with clarified instruction.',
  },
  escalation_under_ambiguity: {
    syndrome: 'aggression',
    advice: 'Agent is escalating after denials. Check whether it is stuck or probing boundaries.',
  },
  source_grounding_loss: {
    syndrome: 'unmoored',
    advice: 'Agent is acting without reading. Check whether output quality has degraded.',
  },
  abnormal_burstiness: {
    syndrome: 'mania',
    advice: 'Unusual temporal pattern. Check whether agent is thrashing or has been compromised.',
  },
  authority_widening: {
    syndrome: 'probing',
    advice: 'Agent is reaching beyond its initial scope. Check whether the expansion is legitimate.',
  },
  entropy_shift: {
    syndrome: 'drift',
    advice: 'Agent behavioral diversity shifted sharply. Review recent actions for coherence.',
  },
  detector_reliability: {
    syndrome: 'tamper',
    advice: 'Multiple detectors crashed during evaluation. Possible evasion attempt or malformed data.',
  },
};

// ── Evaluation ───────────────────────────────────────────────────────────────

// Thresholds for mapping effective score to trust state recommendations.
const DEFAULT_THRESHOLDS = {
  degraded: 0.3,
  at_risk: 0.6,
  suspended: 0.85,
};

const DEFAULT_DIFFUSE_WEIGHT = 1.2;

// Evaluate a trace against all detectors.
// Returns { recommendation, primary_detector, routing_hint, aggregate, detectors }
export async function evaluate(trace, options = {}) {
  const thresholds = options.thresholds || DEFAULT_THRESHOLDS;
  const diffuseWeight = options.diffuse_weight ?? DEFAULT_DIFFUSE_WEIGHT;
  const evaluationHistory = options.evaluation_history || null;

  const detectors = await loadDetectors();
  const results = {};
  let maxScore = 0;
  let maxDetector = null;
  const signals = [];
  let crashedCount = 0;

  for (const detector of detectors) {
    try {
      const result = detector.evaluate(trace);
      results[detector.id] = {
        score: result.score,
        confidence: result.confidence,
        evidence_count: (result.evidence || []).length,
        evidence: result.evidence || [],
      };

      const weighted = result.score * result.confidence;
      signals.push(weighted);
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
      signals.push(0);
      crashedCount++;
    }
  }

  // Detector reliability check: 2+ crashed detectors is itself a degradation signal
  let reliabilityOverride = false;
  if (crashedCount >= 2) {
    reliabilityOverride = true;
    results['_detector_reliability'] = {
      crashed: crashedCount,
      total: detectors.length,
      ratio: round(crashedCount / detectors.length),
    };
  }

  // Dual-path aggregation
  // Path A: dominant (max weighted score — single strong signal)
  const dominant = maxScore;

  // Path B: diffuse (L2 norm / sqrt(N) — distributed pathology)
  const l2 = Math.sqrt(signals.reduce((s, x) => s + x * x, 0));
  const diffuse = signals.length > 0 ? l2 / Math.sqrt(signals.length) : 0;

  let effective = Math.max(dominant, diffuse * diffuseWeight);

  // Critical slowing down: rising autocorrelation tightens sensitivity
  let slowingDown = null;
  if (evaluationHistory && evaluationHistory.length >= 3) {
    const meanAC = computeMeanAutocorrelation(evaluationHistory, signals);
    if (meanAC > 0.5) {
      const multiplier = 1 + (meanAC - 0.5);
      effective = effective * multiplier;
      slowingDown = { mean_autocorrelation: round(meanAC), multiplier: round(multiplier) };
    }
  }

  // Anti-evasion: jitter thresholds by ±10% per evaluation.
  // An agent that knows the nominal thresholds cannot stay just below them
  // because the actual thresholds shift unpredictably each time.
  // This is non-deterministic only in the observation layer — policy
  // enforcement in the gate remains fully deterministic.
  const jitter = () => 0.9 + Math.random() * 0.2;
  const jitteredThresholds = {
    degraded: thresholds.degraded * jitter(),
    at_risk: thresholds.at_risk * jitter(),
    suspended: thresholds.suspended * jitter(),
  };

  // Map effective score to trust state recommendation
  let recommendation = 'healthy';
  let primaryDetector = maxDetector;

  if (reliabilityOverride && effective < jitteredThresholds.degraded) {
    recommendation = 'degraded';
    primaryDetector = 'detector_reliability';
  } else if (effective >= jitteredThresholds.suspended) {
    recommendation = 'suspended';
  } else if (effective >= jitteredThresholds.at_risk) {
    recommendation = 'at_risk';
  } else if (effective >= jitteredThresholds.degraded) {
    recommendation = 'degraded';
  }

  // If diffuse path was the trigger, note it
  if (diffuse * diffuseWeight > dominant && diffuse * diffuseWeight >= thresholds.degraded) {
    primaryDetector = 'diffuse_degradation';
  }

  const routingHint = ROUTING_HINTS[primaryDetector] || null;

  return {
    recommendation,
    primary_detector: primaryDetector,
    routing_hint: routingHint,
    aggregate: {
      dominant: round(dominant),
      diffuse: round(diffuse),
      diffuse_weighted: round(diffuse * diffuseWeight),
      effective: round(effective),
    },
    slowing_down: slowingDown,
    detectors: results,
    trace_length: trace.length,
    evaluated_at: new Date().toISOString(),
    // Signal vector for history storage
    _signal_vector: signals.map(round),
  };
}

// ── Critical slowing down ────────────────────────────────────────────────────
//
// Compute mean lag-1 autocorrelation across all detector signal histories.
// Rising autocorrelation = the system is approaching a regime transition.

function computeMeanAutocorrelation(history, currentSignals) {
  // history is an array of signal vectors from previous evaluations
  // currentSignals is the current evaluation's signal vector
  const allVectors = [...history, currentSignals];
  if (allVectors.length < 3) return 0;

  const numDetectors = currentSignals.length;
  let totalAC = 0;
  let validDetectors = 0;

  for (let d = 0; d < numDetectors; d++) {
    const series = allVectors.map(v => v[d] || 0);
    const ac = lagOneAutocorrelation(series);
    if (!isNaN(ac)) {
      totalAC += ac;
      validDetectors++;
    }
  }

  return validDetectors > 0 ? totalAC / validDetectors : 0;
}

function lagOneAutocorrelation(series) {
  if (series.length < 3) return 0;
  const mean = series.reduce((a, b) => a + b, 0) / series.length;
  let num = 0, den = 0;
  for (let i = 1; i < series.length; i++) {
    num += (series[i] - mean) * (series[i - 1] - mean);
    den += (series[i] - mean) ** 2;
  }
  return den === 0 ? 0 : num / den;
}

function round(n) {
  return Math.round(n * 100) / 100;
}
