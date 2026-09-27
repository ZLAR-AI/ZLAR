// entropy-shift detector
//
// Detects sharp changes in the diversity of an agent's action domains.
// Uses Shannon entropy over sliding windows — the signal is the rate
// of entropy change, not the absolute value.
//
// A focused session (low entropy) and a broad session (high entropy) are
// both healthy. What matters is when the pattern shifts suddenly:
//   - Sharp drop = agent fixating on one action type (e.g., hammering writes)
//   - Sharp rise = agent scattering into new domains
//
// The baseline is the session's own earlier behavior. No learned profiles.
// Information-theoretically grounded: measures surprise content of the
// agent's recent action distribution relative to its established distribution.
//
// Score 0.0 = stable diversity pattern
// Score 1.0 = extreme entropy shift

export const id = 'entropy_shift';
export const description = 'Detects sharp shifts in action domain diversity';

const WINDOW_SIZE = 20;
const MIN_EVENTS = WINDOW_SIZE + 10; // need two windows to compare

export function evaluate(trace) {
  if (!trace || trace.length < MIN_EVENTS) {
    return { score: 0, confidence: 0, evidence: [] };
  }

  const evidence = [];

  // Compute entropy over the earlier window and the later window
  const midpoint = Math.floor(trace.length / 2);
  const earlyWindow = trace.slice(
    Math.max(0, midpoint - WINDOW_SIZE),
    midpoint
  );
  const lateWindow = trace.slice(
    Math.max(midpoint, trace.length - WINDOW_SIZE)
  );

  const earlyEntropy = shannonEntropy(earlyWindow);
  const lateEntropy = shannonEntropy(lateWindow);

  // Collect all distinct domains for H_max normalization
  const allDomains = new Set(trace.map(e => e.domain).filter(Boolean));
  const hMax = allDomains.size > 1 ? Math.log2(allDomains.size) : 1;

  // Score = |deltaH| / H_max
  const deltaH = Math.abs(lateEntropy - earlyEntropy);
  const score = Math.min(deltaH / hMax, 1);

  if (score > 0.1) {
    evidence.push({
      type: lateEntropy < earlyEntropy ? 'entropy_drop' : 'entropy_rise',
      early_entropy: round(earlyEntropy),
      late_entropy: round(lateEntropy),
      delta: round(deltaH),
      h_max: round(hMax),
      early_window_size: earlyWindow.length,
      late_window_size: lateWindow.length,
    });
  }

  // Confidence scales with trace length — need enough data for stable entropy
  const confidence = trace.length >= 40 ? 0.7 : (trace.length / 40) * 0.7;

  return { score: round(score), confidence: round(confidence), evidence };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function shannonEntropy(events) {
  const counts = {};
  let total = 0;
  for (const e of events) {
    if (!e.domain) continue;
    counts[e.domain] = (counts[e.domain] || 0) + 1;
    total++;
  }
  if (total === 0) return 0;

  let H = 0;
  for (const c of Object.values(counts)) {
    const p = c / total;
    if (p > 0) H -= p * Math.log2(p);
  }
  return H;
}

function round(n) {
  return Math.round(n * 100) / 100;
}
