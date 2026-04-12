// action-silence detector
//
// Detects unusual gaps in agent activity WITHIN contiguous activity windows.
//
// Key insight (v3.0.4 Cassandra/Fatima): the audit trail spans the entire
// session, which includes periods when the human is absent (cleaning house,
// in a meeting, eating lunch). Those gaps are human-absence, not agent-silence.
// The detector was monitoring the wrong clock.
//
// Design: segment the trace into activity windows — contiguous runs of events
// where no gap exceeds the window boundary (15 minutes). Then look for
// suspicious gaps ONLY within those windows. A gap that splits two windows
// is a human-absence boundary, not a signal.
//
// Within a window, a gap that is both:
//   (a) over 15 minutes (absolute floor), AND
//   (b) over 20x the window's local median
// is suspicious. This means the detector only fires when an agent goes
// quiet inside what should be a continuous interaction period.
//
// Score 0.0 = consistent pacing within all activity windows
// Score 1.0 = extreme gap within an activity window

export const id = 'action_silence';
export const description = 'Detects unusual gaps in agent activity within active sessions';

const MIN_EVENTS = 10;
const WINDOW_BOUNDARY_MS = 900000;        // 15 minutes — gaps this large split windows
const SILENCE_RATIO_THRESHOLD = 20;       // gap must be 20x local median to be notable
const SILENCE_ABSOLUTE_FLOOR_MS = 900000; // gaps under 15 minutes are never suspicious
const SCORE_CAP_RATIO = 200;              // 200x local median = score 1.0

export function evaluate(trace) {
  if (!trace || trace.length < MIN_EVENTS) {
    return { score: 0, confidence: 0, evidence: [] };
  }

  // Extract timestamps
  const timestamps = trace
    .map(e => e.ts ? new Date(e.ts).getTime() : null)
    .filter(t => t !== null && !isNaN(t));

  if (timestamps.length < MIN_EVENTS) {
    return { score: 0, confidence: 0, evidence: [] };
  }

  // Compute all intervals
  const intervals = [];
  for (let i = 1; i < timestamps.length; i++) {
    const gap = timestamps[i] - timestamps[i - 1];
    if (gap >= 0) intervals.push(gap);
  }

  if (intervals.length < 5) {
    return { score: 0, confidence: 0, evidence: [] };
  }

  // Segment into activity windows.
  // A window boundary is any gap >= WINDOW_BOUNDARY_MS.
  // Each window is a list of interval indices that belong to the same
  // contiguous activity period.
  const windows = [];
  let currentWindow = [];

  for (let i = 0; i < intervals.length; i++) {
    if (intervals[i] >= WINDOW_BOUNDARY_MS && currentWindow.length > 0) {
      // This gap is a human-absence boundary — close current window
      windows.push(currentWindow);
      currentWindow = [];
    } else {
      currentWindow.push(i);
    }
  }
  if (currentWindow.length > 0) {
    windows.push(currentWindow);
  }

  // Analyze each window for internal silence gaps.
  const evidence = [];
  let maxRatio = 0;

  for (const win of windows) {
    if (win.length < 3) continue; // too few intervals for meaningful median

    // Compute local median for this window
    const winIntervals = win.map(i => intervals[i]);

    // Exclude the last interval in each window (could be window-ending)
    const inner = winIntervals.slice(0, -1);
    if (inner.length < 2) continue;

    const sorted = [...inner].sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)];
    if (median <= 0) continue;

    for (let j = 0; j < inner.length; j++) {
      // Absolute floor — gaps under 15 minutes are normal
      if (inner[j] < SILENCE_ABSOLUTE_FLOOR_MS) continue;

      const ratio = inner[j] / median;
      if (ratio > SILENCE_RATIO_THRESHOLD) {
        if (ratio > maxRatio) maxRatio = ratio;
        evidence.push({
          type: 'silence_gap',
          gap_ms: inner[j],
          gap_s: round(inner[j] / 1000),
          median_interval_ms: round(median),
          ratio: round(ratio),
          position: win[j] + 1,          // global interval position (1-indexed)
          total_intervals: intervals.length,
          window_size: win.length,
        });
      }
    }
  }

  // Score: how extreme is the worst gap relative to its window's rhythm
  const score = Math.min(maxRatio / SCORE_CAP_RATIO, 1);

  // Confidence scales with trace length
  const confidence = timestamps.length >= 30 ? 0.7 : (timestamps.length / 30) * 0.7;

  return { score: round(score), confidence: round(confidence), evidence };
}

function round(n) {
  return Math.round(n * 100) / 100;
}
