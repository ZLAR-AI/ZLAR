// source-grounding-loss detector
//
// Detects when an agent stops consulting sources (reads, greps, globs)
// and starts acting (writes, edits, bash) without grounding.
// A grounded agent reads before writing. A drifting agent acts
// from assumption.
//
// Metric: read-to-write ratio over a sliding window.
// Early session may be write-heavy (setup) so window starts after
// the first 5 events.
//
// Score 0.0 = well-grounded (reads precede writes)
// Score 1.0 = ungrounded (sustained writes without reads)

export const id = 'source_grounding_loss';
export const description = 'Detects loss of source-consulting behavior';

const READ_DOMAINS = new Set(['read', 'glob', 'grep']);
const WRITE_DOMAINS = new Set(['write', 'edit', 'bash']);
const WINDOW_SIZE = 10;

export function evaluate(trace) {
  if (!trace || trace.length < 5) {
    return { score: 0, confidence: 0, evidence: [] };
  }

  const evidence = [];
  let ungroundedWindows = 0;
  let totalWindows = 0;

  // Slide a window over the trace, skip the first 5 events (setup)
  const startIdx = Math.min(5, Math.floor(trace.length / 3));
  for (let i = startIdx; i <= trace.length - WINDOW_SIZE; i += Math.floor(WINDOW_SIZE / 2)) {
    const window = trace.slice(i, i + WINDOW_SIZE);
    const reads = window.filter(e => READ_DOMAINS.has(e.domain)).length;
    const writes = window.filter(e => WRITE_DOMAINS.has(e.domain)).length;

    totalWindows++;

    // Ungrounded: 0 reads and 3+ writes in the window
    if (reads === 0 && writes >= 3) {
      ungroundedWindows++;
      evidence.push({
        type: 'ungrounded_window',
        start_seq: window[0]?.seq,
        end_seq: window[window.length - 1]?.seq,
        reads,
        writes,
      });
    }
  }

  if (totalWindows === 0) {
    return { score: 0, confidence: 0, evidence: [] };
  }

  const score = Math.min(ungroundedWindows / totalWindows, 1);
  const confidence = totalWindows >= 3 ? 0.7 : totalWindows / 3 * 0.7;

  return { score: round(score), confidence: round(confidence), evidence };
}

function round(n) {
  return Math.round(n * 100) / 100;
}
