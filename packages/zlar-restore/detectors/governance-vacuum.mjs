// governance-vacuum detector
//
// Detects when gate infrastructure is making decisions instead of policy
// or humans. When the human channel is broken (Telegram unreachable,
// timeout, rate limit), the gate falls back to deny — but nobody is
// actually governing. The stethoscope should show this reading.
//
// Three patterns:
//   1. Gate override ratio — fraction of decisions from gate:* authorizers
//   2. Timeout clustering — gate:error/timeout events bunched in time
//   3. Human absence — asks are generated but no human responds
//
// Named for what it detects: the absence of governance. The gate is
// making decisions by default, not by authority. The chair is empty.
//
// Score 0.0 = all decisions from policy or human
// Score 1.0 = pervasive gate infrastructure overrides

export const id = 'governance_vacuum';
export const description = 'Detects when gate infrastructure is making decisions instead of policy or humans';

export function evaluate(trace) {
  if (!trace || trace.length < 5) {
    return { score: 0, confidence: 0, evidence: [] };
  }

  const evidence = [];

  // ── Categorize authorizers ──────────────────────────────────────────────

  let policyCount = 0;
  let humanCount = 0;
  let standingCount = 0;
  let gateOverrideCount = 0;
  let askPendingCount = 0;

  const gateOverrideEvents = [];

  for (const e of trace) {
    const auth = e.authorizer || 'policy';

    if (auth === 'policy') {
      policyCount++;
    } else if (auth.startsWith('human:')) {
      humanCount++;
    } else if (auth.startsWith('standing:')) {
      standingCount++;
    } else if (auth.startsWith('gate:') && auth !== 'gate') {
      // gate:error, gate:timeout, gate:rate_limit — infrastructure overrides
      gateOverrideCount++;
      gateOverrideEvents.push(e);
    }
    // auth === 'gate' is internal infrastructure (ask_pending, gate.start) — don't count

    if (e.outcome === 'ask_pending') {
      askPendingCount++;
    }
  }

  const decisionCount = policyCount + humanCount + standingCount + gateOverrideCount;
  if (decisionCount === 0) {
    return { score: 0, confidence: 0, evidence: [] };
  }

  // ── Pattern 1: Gate override ratio ──────────────────────────────────────

  let overrideScore = 0;
  const overrideRatio = gateOverrideCount / decisionCount;

  if (gateOverrideCount >= 3 && overrideRatio > 0.2) {
    // Scales linearly: 0.2 ratio → 0.0, 0.8 ratio → 1.0
    overrideScore = Math.min((overrideRatio - 0.2) / 0.6, 1);
    evidence.push({
      type: 'gate_override_ratio',
      ratio: round(overrideRatio),
      gate_overrides: gateOverrideCount,
      total_decisions: decisionCount,
      policy: policyCount,
      human: humanCount,
      standing: standingCount,
    });
  }

  // ── Pattern 2: Timeout/error clustering ─────────────────────────────────

  let clusterScore = 0;
  const CLUSTER_WINDOW_MS = 120_000; // 2 minutes
  const CLUSTER_MIN = 3;

  if (gateOverrideEvents.length >= CLUSTER_MIN) {
    // Sort by timestamp, scan for clusters
    const sorted = gateOverrideEvents
      .filter(e => e.ts)
      .sort((a, b) => new Date(a.ts) - new Date(b.ts));

    let clusterStart = 0;
    for (let i = 1; i < sorted.length; i++) {
      const gap = new Date(sorted[i].ts) - new Date(sorted[clusterStart].ts);
      if (gap > CLUSTER_WINDOW_MS) {
        // Check if the window we just left was a cluster
        const clusterSize = i - clusterStart;
        if (clusterSize >= CLUSTER_MIN) {
          const clusterDuration = new Date(sorted[i - 1].ts) - new Date(sorted[clusterStart].ts);
          clusterScore = Math.max(clusterScore, Math.min(clusterSize / 8, 1));
          evidence.push({
            type: 'override_cluster',
            size: clusterSize,
            duration_ms: clusterDuration,
            start_seq: sorted[clusterStart].seq,
            end_seq: sorted[i - 1].seq,
            authorizers: sorted.slice(clusterStart, i).map(e => e.authorizer),
          });
        }
        clusterStart = i;
      }
    }
    // Check final window
    const finalSize = sorted.length - clusterStart;
    if (finalSize >= CLUSTER_MIN) {
      const clusterDuration = new Date(sorted[sorted.length - 1].ts) - new Date(sorted[clusterStart].ts);
      clusterScore = Math.max(clusterScore, Math.min(finalSize / 8, 1));
      evidence.push({
        type: 'override_cluster',
        size: finalSize,
        duration_ms: clusterDuration,
        start_seq: sorted[clusterStart].seq,
        end_seq: sorted[sorted.length - 1].seq,
        authorizers: sorted.slice(clusterStart).map(e => e.authorizer),
      });
    }
  }

  // ── Pattern 3: Human absence ────────────────────────────────────────────

  let absenceScore = 0;

  // If asks were generated but no human ever responded, the governance is
  // nominal. Use max(askPending, gateOverride) not sum — a gate:error event
  // is the OUTCOME of the same ask that produced ask_pending. Counting both
  // would double-count the same governance attempt.
  const asksGenerated = Math.max(askPendingCount, gateOverrideCount);
  if (asksGenerated >= 3 && humanCount === 0) {
    // Asks are happening but nobody is home
    absenceScore = Math.min(asksGenerated / 10, 1);
    evidence.push({
      type: 'human_absence',
      asks_generated: asksGenerated,
      ask_pending: askPendingCount,
      gate_overrides: gateOverrideCount,
      human_responses: 0,
    });
  }

  // ── Aggregate ───────────────────────────────────────────────────────────

  const score = Math.max(overrideScore, clusterScore, absenceScore);

  // Confidence scales with trace length, caps at 0.75.
  // This detector makes judgments about infrastructure state, not agent
  // behavior — slightly lower ceiling than behavioral detectors.
  const confidence = Math.min(trace.length / 15, 1) * 0.75;

  return { score: round(score), confidence: round(confidence), evidence };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function round(n) {
  return Math.round(n * 100) / 100;
}
