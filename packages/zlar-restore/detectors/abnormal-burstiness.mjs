// abnormal-burstiness detector
//
// Detects unusual temporal patterns in agent behavior. Normal agents
// have relatively even pacing. Drifting agents may burst (many rapid
// actions) or exhibit oscillation (burst-pause-burst).
//
// Metric: coefficient of variation (CV) of inter-action intervals.
// CV > 2.0 is abnormal for a governed agent session.
//
// Score 0.0 = even pacing
// Score 1.0 = extreme burstiness

export const id = 'abnormal_burstiness';
export const description = 'Detects abnormal temporal patterns in action sequences';

const CV_THRESHOLD = 2.0;
const BURST_THRESHOLD_MS = 500;  // actions within 500ms = burst
const MIN_EVENTS = 8;

export function evaluate(trace) {
  if (!trace || trace.length < MIN_EVENTS) {
    return { score: 0, confidence: 0, evidence: [] };
  }

  const evidence = [];

  // Compute inter-action intervals
  const intervals = [];
  for (let i = 1; i < trace.length; i++) {
    const ms = new Date(trace[i].ts) - new Date(trace[i - 1].ts);
    if (!isNaN(ms) && ms >= 0) {
      intervals.push(ms);
    }
  }

  if (intervals.length < 3) {
    return { score: 0, confidence: 0, evidence: [] };
  }

  // Coefficient of variation
  const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  const variance = intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length;
  const stddev = Math.sqrt(variance);
  const cv = mean > 0 ? stddev / mean : 0;

  // Detect burst clusters (3+ actions within BURST_THRESHOLD_MS)
  let burstCount = 0;
  let currentBurst = 1;
  for (let i = 0; i < intervals.length; i++) {
    if (intervals[i] < BURST_THRESHOLD_MS) {
      currentBurst++;
    } else {
      if (currentBurst >= 3) {
        burstCount++;
        evidence.push({
          type: 'burst',
          size: currentBurst,
          start_seq: trace[i - currentBurst + 1]?.seq,
          end_seq: trace[i]?.seq,
        });
      }
      currentBurst = 1;
    }
  }
  // Check trailing burst
  if (currentBurst >= 3) {
    burstCount++;
    evidence.push({
      type: 'burst',
      size: currentBurst,
      start_seq: trace[trace.length - currentBurst]?.seq,
      end_seq: trace[trace.length - 1]?.seq,
    });
  }

  // Score: combination of CV and burst count
  const cvScore = Math.min(Math.max(cv - 1, 0) / CV_THRESHOLD, 1);
  const burstScore = Math.min(burstCount / 3, 1);
  const score = Math.max(cvScore, burstScore);

  const confidence = intervals.length >= 15 ? 0.8 : intervals.length / 15 * 0.8;

  if (cv > CV_THRESHOLD) {
    evidence.push({ type: 'high_cv', cv: round(cv), mean_interval_ms: round(mean), stddev_ms: round(stddev) });
  }

  return { score: round(score), confidence: round(confidence), evidence };
}

function round(n) {
  return Math.round(n * 100) / 100;
}
