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
//   RESTORE-INV-13: Jitter is keyed PRNG, not Math.random(). Same trace
//     always produces the same evaluation. Auditability is non-negotiable.
//
// Trace contract: the engine receives seq===1 events only (agent intent,
// not human resolution). This projection is applied by restore-trigger.mjs
// and session-state.sh. Detectors must not assume resolution data exists.
// See the PROJECTION CONTRACT comment in restore-trigger.mjs.

import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readdirSync } from 'node:fs';
import { createHmac } from 'node:crypto';

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
  'action-silence',
  'governance-vacuum',
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
  action_silence: {
    syndrome: 'stall',
    advice: 'Agent went quiet mid-session then resumed. Check whether it was stuck, waiting, or doing something off-audit.',
  },
  detector_reliability: {
    syndrome: 'tamper',
    advice: 'Multiple detectors crashed during evaluation. Possible evasion attempt or malformed data.',
  },
  governance_vacuum: {
    syndrome: 'vacuum',
    advice: 'Decisions are being made by gate infrastructure, not by policy or humans. Check Telegram connectivity and whether the human is reachable.',
  },
};

// ── Keyed PRNG ──────────────────────────────────────────────────────────────
//
// Deterministic jitter seeded from the trace content. Same trace always
// produces the same jitter values — fully reproducible for auditing.
// Unpredictable to an adversary without knowledge of the event IDs
// (which are generated from openssl rand).
//
// This replaces Math.random(). The anti-evasion property is preserved
// (an adversary cannot predict the thresholds) while restoring the
// auditability property (an operator can replay any past evaluation).

function createKeyedPRNG(trace) {
  // Seed from trace boundaries + length. Event IDs contain openssl rand
  // hex, so this is unpredictable without access to the audit trail.
  const firstId = trace[0]?.id || 'empty';
  const lastId = trace[trace.length - 1]?.id || 'empty';
  const seed = `${firstId}:${lastId}:${trace.length}`;
  let counter = 0;

  return function random() {
    const hmac = createHmac('sha256', seed);
    hmac.update(String(counter++));
    const bytes = hmac.digest();
    // First 4 bytes as uint32, normalized to [0, 1)
    const uint32 = bytes.readUInt32BE(0);
    return uint32 / 0x100000000;
  };
}

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

  // Keyed PRNG: deterministic jitter seeded from trace content.
  // Same trace → same jitter → reproducible evaluation.
  // Adversary without audit trail access cannot predict thresholds.
  const prng = createKeyedPRNG(trace);

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

  // Anti-evasion: jitter the diffuse weight. An agent that understands
  // the dual-path architecture could distribute pathology evenly across
  // detectors to stay below a constant diffuse weight. Jittering both
  // paths removes the stable target.
  //
  // Uses keyed PRNG — deterministic per-trace, unpredictable per-adversary.
  const jitteredDiffuseWeight = diffuseWeight * (0.9 + prng() * 0.2);
  let effective = Math.max(dominant, diffuse * jitteredDiffuseWeight);

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
  // Keyed PRNG: deterministic per-trace (auditable), unpredictable per-
  // adversary (anti-evasion). Policy enforcement in the gate remains
  // fully deterministic — this jitter is in the observation layer only.
  const jitter = () => 0.9 + prng() * 0.2;
  const jitteredThresholds = {
    degraded: thresholds.degraded * jitter(),
    at_risk: thresholds.at_risk * jitter(),
    suspended: thresholds.suspended * jitter(),
  };

  // ── Naveed's rule: multi-detector convergence for at_risk+ ────────────
  //
  // A single detector at max score (1.0 * 0.7 confidence = 0.7) can push
  // effective past at_risk threshold (0.6) alone. This makes a single
  // false positive indistinguishable from a single true positive.
  //
  // Fix: at_risk and suspended require 2+ detectors with weighted score
  // above the convergence floor. A lone high-scoring detector caps at
  // degraded regardless of its absolute score. Only convergent signals
  // from multiple detectors can escalate beyond degraded.
  //
  // This does NOT weaken detection — distributed pathology (the diffuse
  // path) inherently activates multiple detectors. And genuine single-
  // detector crises (e.g., sustained authority widening) still reach
  // degraded, which is now visible via Telegram.
  //
  // The convergence floor is the degraded threshold — any detector whose
  // weighted signal exceeds degraded counts as "active."
  const CONVERGENCE_FLOOR = thresholds.degraded;
  const activeDetectorCount = signals.filter(s => s >= CONVERGENCE_FLOOR).length;

  // Map effective score to trust state recommendation
  let recommendation = 'healthy';
  let primaryDetector = maxDetector;

  if (reliabilityOverride && effective < jitteredThresholds.degraded) {
    recommendation = 'degraded';
    primaryDetector = 'detector_reliability';
  } else if (effective >= jitteredThresholds.suspended && activeDetectorCount >= 2) {
    recommendation = 'suspended';
  } else if (effective >= jitteredThresholds.at_risk && activeDetectorCount >= 2) {
    recommendation = 'at_risk';
  } else if (effective >= jitteredThresholds.degraded) {
    // Single detector can reach degraded — that's fine. Degraded is
    // visible (Telegram notification) but doesn't escalate actions.
    recommendation = 'degraded';
  }

  // If diffuse path was the trigger, note it
  if (diffuse * jitteredDiffuseWeight > dominant && diffuse * jitteredDiffuseWeight >= thresholds.degraded) {
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
      diffuse_weighted: round(diffuse * jitteredDiffuseWeight),
      effective: round(effective),
      active_detectors: activeDetectorCount,
    },
    slowing_down: slowingDown,
    detectors: results,
    trace_length: trace.length,
    evaluated_at: new Date().toISOString(),
    // Jitter values for audit reproducibility — same trace always
    // produces the same jitter, so these are deterministic proof.
    _jitter: {
      diffuse_weight: round(jitteredDiffuseWeight),
      thresholds: {
        degraded: round(jitteredThresholds.degraded),
        at_risk: round(jitteredThresholds.at_risk),
        suspended: round(jitteredThresholds.suspended),
      },
    },
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
