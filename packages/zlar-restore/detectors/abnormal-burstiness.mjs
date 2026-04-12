// abnormal-burstiness detector
//
// Detects unusual temporal patterns in agent behavior. Normal agents
// have relatively even pacing. Drifting agents may burst (many rapid
// actions) or exhibit oscillation (burst-pause-burst).
//
// Metric: coefficient of variation (CV) of inter-action intervals,
// computed only on write-class actions (write, edit, bash, agent, mcp).
// Read-class actions (read, glob, grep) are excluded from CV because
// agents naturally burst-read files then pause to think. That pattern
// has high CV but is not pathological — it's how exploration works.
//
// Calibration (v3.0.4): Production data showed CV=2.72 on a session
// where explore agents read many files rapidly then paused for human
// input. The old threshold (2.0) flagged this as abnormal. Raised to
// 4.0 and excluded read-only domains from CV calculation. Burst cluster
// detection (500ms rapid-fire) is unchanged — genuine automation at
// sub-second intervals is still worth catching regardless of domain.
//
// Score 0.0 = even pacing
// Score 1.0 = extreme burstiness

export const id = 'abnormal_burstiness';
export const description = 'Detects abnormal temporal patterns in action sequences';

const CV_THRESHOLD = 4.0;
const BURST_THRESHOLD_MS = 500;  // actions within 500ms = burst
const MIN_EVENTS = 8;

// Read-class domains excluded from CV calculation.
// These naturally burst during exploration and are not pathological.
const READ_DOMAINS = new Set(['read', 'glob', 'grep']);

export function evaluate(trace) {
  if (!trace || trace.length < MIN_EVENTS) {
    return { score: 0, confidence: 0, evidence: [] };
  }

  const evidence = [];

  // Compute inter-action intervals for ALL events (burst detection)
  const allIntervals = [];
  for (let i = 1; i < trace.length; i++) {
    const ms = new Date(trace[i].ts) - new Date(trace[i - 1].ts);
    if (!isNaN(ms) && ms >= 0) {
      allIntervals.push(ms);
    }
  }

  if (allIntervals.length < 3) {
    return { score: 0, confidence: 0, evidence: [] };
  }

  // Compute CV only on write-class action intervals.
  // Filter trace to non-read events, then compute their intervals.
  const writeTrace = trace.filter(e => !READ_DOMAINS.has(e.domain));
  const writeIntervals = [];
  for (let i = 1; i < writeTrace.length; i++) {
    const ms = new Date(writeTrace[i].ts) - new Date(writeTrace[i - 1].ts);
    if (!isNaN(ms) && ms >= 0) {
      writeIntervals.push(ms);
    }
  }

  let cvScore = 0;
  let cv = 0;
  let mean = 0;
  let stddev = 0;

  if (writeIntervals.length >= 3) {
    mean = writeIntervals.reduce((a, b) => a + b, 0) / writeIntervals.length;
    const variance = writeIntervals.reduce((a, b) => a + (b - mean) ** 2, 0) / writeIntervals.length;
    stddev = Math.sqrt(variance);
    cv = mean > 0 ? stddev / mean : 0;
    cvScore = Math.min(Math.max(cv - 1, 0) / CV_THRESHOLD, 1);
  }

  // Detect burst clusters (3+ actions within BURST_THRESHOLD_MS)
  // Uses ALL intervals — sub-second automation is suspicious regardless of domain
  let burstCount = 0;
  let currentBurst = 1;
  for (let i = 0; i < allIntervals.length; i++) {
    if (allIntervals[i] < BURST_THRESHOLD_MS) {
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
  const burstScore = Math.min(burstCount / 3, 1);
  const score = Math.max(cvScore, burstScore);

  const confidence = allIntervals.length >= 15 ? 0.8 : allIntervals.length / 15 * 0.8;

  if (cv > CV_THRESHOLD) {
    evidence.push({
      type: 'high_cv',
      cv: round(cv),
      mean_interval_ms: round(mean),
      stddev_ms: round(stddev),
      write_intervals: writeIntervals.length,
      total_intervals: allIntervals.length,
    });
  }

  return { score: round(score), confidence: round(confidence), evidence };
}

function round(n) {
  return Math.round(n * 100) / 100;
}
