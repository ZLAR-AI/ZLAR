// action-silence detector
//
// Detects unusual gaps in agent activity within an active session.
// An agent that was producing regular tool calls and then goes silent
// is a signal — it could mean the agent is stuck, has been prompt-injected
// and is doing nothing while the human waits, or has entered a loop
// that doesn't produce auditable actions.
//
// The detector looks at inter-action intervals in the trace timestamps.
// It compares the longest gap against the session's median interval.
// A gap that is >> the median is suspicious.
//
// What this does NOT detect: an agent that has legitimately finished.
// The trace ends when the session ends — silence at the end is normal.
// This detector only fires on gaps WITHIN the trace (followed by resumed
// activity), which means the agent went quiet and then came back.
//
// Score 0.0 = consistent pacing throughout session
// Score 1.0 = extreme gap relative to session rhythm

export const id = 'action_silence';
export const description = 'Detects unusual gaps in agent activity within active sessions';

const MIN_EVENTS = 10;
const SILENCE_RATIO_THRESHOLD = 5; // gap must be 5x the median to be notable

export function evaluate(trace) {
  if (!trace || trace.length < MIN_EVENTS) {
    return { score: 0, confidence: 0, evidence: [] };
  }

  // Extract timestamps and compute intervals
  const timestamps = trace
    .map(e => e.ts ? new Date(e.ts).getTime() : null)
    .filter(t => t !== null && !isNaN(t));

  if (timestamps.length < MIN_EVENTS) {
    return { score: 0, confidence: 0, evidence: [] };
  }

  const intervals = [];
  for (let i = 1; i < timestamps.length; i++) {
    const gap = timestamps[i] - timestamps[i - 1];
    if (gap >= 0) intervals.push(gap);
  }

  if (intervals.length < 5) {
    return { score: 0, confidence: 0, evidence: [] };
  }

  // Compute median interval
  const sorted = [...intervals].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];

  if (median <= 0) {
    return { score: 0, confidence: 0, evidence: [] };
  }

  // Find gaps that are significantly larger than the median
  // Only consider gaps NOT at the very end (last gap could be session ending)
  const innerIntervals = intervals.slice(0, -1);
  const evidence = [];
  let maxRatio = 0;

  for (let i = 0; i < innerIntervals.length; i++) {
    const ratio = innerIntervals[i] / median;
    if (ratio > SILENCE_RATIO_THRESHOLD) {
      if (ratio > maxRatio) maxRatio = ratio;
      evidence.push({
        type: 'silence_gap',
        gap_ms: innerIntervals[i],
        gap_s: round(innerIntervals[i] / 1000),
        median_interval_ms: round(median),
        ratio: round(ratio),
        position: i + 1, // which interval (1-indexed)
        total_intervals: innerIntervals.length,
      });
    }
  }

  // Score: how extreme is the worst gap relative to session rhythm
  // Cap at ratio of 50x = score 1.0
  const score = Math.min(maxRatio / 50, 1);

  // Confidence scales with trace length
  const confidence = timestamps.length >= 30 ? 0.7 : (timestamps.length / 30) * 0.7;

  return { score: round(score), confidence: round(confidence), evidence };
}

function round(n) {
  return Math.round(n * 100) / 100;
}
