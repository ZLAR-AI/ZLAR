#!/usr/bin/env node
// restore-trigger.mjs — Background Agent Health evaluation
//
// Called by the gate (backgrounded) after denials, novelty escalations,
// and high-risk actions. Evaluates the session trace, updates trust state
// if warranted (monotone), and sends Telegram notification on change.
//
// Usage: node lib/restore-trigger.mjs <session_id> <project_dir> [telegram_chat_id]
//
// This runs non-blocking. The gate does not wait for it.

import { readFileSync, existsSync, appendFileSync, unlinkSync, openSync, readSync, fstatSync, closeSync } from 'node:fs';
import { join } from 'node:path';

const sessionId = process.argv[2];
const projectDir = process.argv[3];
const telegramChatId = process.argv[4] || '';

if (!sessionId || !projectDir) {
  process.exit(0);  // Silent exit — don't log errors from background process
}

const configFile = join(projectDir, 'etc', 'restore-config.json');
const auditFile = join(projectDir, 'var', 'log', 'audit.jsonl');
const logFile = join(projectDir, 'var', 'log', 'restore.log');
const evalMarker = join(projectDir, 'var', 'restore', '.evaluating');

function log(msg) {
  const ts = new Date().toISOString();
  try {
    appendFileSync(logFile, `${ts} ${msg}\n`);
  } catch { /* ignore */ }
}

// Clean up the pending evaluation marker on exit
function cleanupMarker() {
  try { unlinkSync(evalMarker); } catch { /* ignore */ }
}

async function main() {
  try {
    // Check config
    if (!existsSync(configFile)) { cleanupMarker(); process.exit(0); }
    const config = JSON.parse(readFileSync(configFile, 'utf-8'));
    if (!config.enabled) { cleanupMarker(); process.exit(0); }

    const trustStateFile = join(projectDir, config.trust_state_file || 'var/restore/trust-state.json');
    const hmacKeyFile = config.hmac_key_file ? join(projectDir, config.hmac_key_file) : null;
    const historyFile = config.evaluation_history_file
      ? join(projectDir, config.evaluation_history_file)
      : join(projectDir, 'var/restore/evaluation-history.json');
    const diffuseWeight = config.diffuse_weight ?? 1.2;

    // Extract session trace — bounded reverse-read
    if (!existsSync(auditFile)) { cleanupMarker(); process.exit(0); }
    const trace = readSessionTrace(auditFile, sessionId, 500);

    if (trace.length < 5) {
      log(`session=${sessionId} trace_length=${trace.length} — too short, skipping`);
      cleanupMarker();
      process.exit(0);
    }

    // Load HMAC keys — separate keys if configured, shared key as fallback
    const trustStateHmacKeyFile = config.trust_state_hmac_key
      ? join(projectDir, config.trust_state_hmac_key)
      : hmacKeyFile;
    const historyHmacKeyFile = config.evaluation_history_hmac_key
      ? join(projectDir, config.evaluation_history_hmac_key)
      : hmacKeyFile;

    const { setHmacKey } = await import(join(projectDir, 'packages', 'zlar-restore', 'trust-state.mjs'));
    if (trustStateHmacKeyFile && existsSync(trustStateHmacKeyFile)) {
      setHmacKey(trustStateHmacKeyFile);
    }

    // Load evaluation history for critical slowing down
    const { loadHistory, appendHistory, setHistoryHmacKey } = await import(
      join(projectDir, 'packages', 'zlar-restore', 'evaluation-history.mjs')
    );
    if (historyHmacKeyFile && existsSync(historyHmacKeyFile)) {
      setHistoryHmacKey(historyHmacKeyFile);
    }
    const evaluationHistory = loadHistory(historyFile);

    // Run engine
    const { evaluate } = await import(join(projectDir, 'packages', 'zlar-restore', 'restore-engine.mjs'));
    const result = await evaluate(trace, {
      diffuse_weight: diffuseWeight,
      evaluation_history: evaluationHistory,
    });

    log(`session=${sessionId} recommendation=${result.recommendation} effective=${result.aggregate.effective} dominant=${result.aggregate.dominant} diffuse=${result.aggregate.diffuse_weighted} trace=${trace.length}`);

    // Store signal vector in evaluation history
    if (result._signal_vector) {
      appendHistory(historyFile, result._signal_vector);
    }

    if (result.recommendation === 'healthy') {
      cleanupMarker();
      process.exit(0);
    }

    // Load current trust state and attempt monotone transition
    const { loadTrustState, proposeTransition, applyTransition, saveTrustState } = await import(
      join(projectDir, 'packages', 'zlar-restore', 'trust-state.mjs')
    );

    const currentState = loadTrustState(trustStateFile);
    const transition = proposeTransition(currentState.state, result.recommendation, `detector:${result.primary_detector}`);

    if (!transition.accepted) {
      log(`session=${sessionId} no_transition: ${transition.reason}`);
      cleanupMarker();
      process.exit(0);
    }

    // Apply transition
    const updated = applyTransition(currentState, { ...transition, evidence: result.detectors });
    saveTrustState(trustStateFile, updated);
    log(`session=${sessionId} transitioned: ${transition.from} -> ${transition.to}`);

    // Send Telegram notification if chat ID available
    if (telegramChatId) {
      await sendTelegram(telegramChatId, transition, result);
    }
  } finally {
    cleanupMarker();
  }
}

// ── Bounded audit trail reader ──────────────────────────────────────────────
//
// Reads the audit file from the end in chunks, extracts events matching
// the session ID, stops at a hard cap. Prevents OOM on long-running systems.

function readSessionTrace(auditPath, sid, maxEvents) {
  const CHUNK_SIZE = 64 * 1024; // 64KB chunks
  const trace = [];

  try {
    const fd = openSync(auditPath, 'r');
    const stat = fstatSync(fd);
    let position = stat.size;
    let remainder = '';

    while (position > 0 && trace.length < maxEvents) {
      const readSize = Math.min(CHUNK_SIZE, position);
      position -= readSize;
      const buf = Buffer.alloc(readSize);
      readSync(fd, buf, 0, readSize, position);
      const chunk = buf.toString('utf-8') + remainder;
      const lines = chunk.split('\n');

      // First element may be partial (from mid-line split)
      remainder = lines.shift() || '';

      // Process lines in reverse (most recent first)
      for (let i = lines.length - 1; i >= 0; i--) {
        const line = lines[i].trim();
        if (!line) continue;
        try {
          const event = JSON.parse(line);
          // PROJECTION CONTRACT: seq===1 selects the FIRST event per gate
          // invocation — the agent's INTENT, not the human's RESOLUTION.
          // This is deliberate. Detectors analyze what the agent tried to do,
          // not whether a human approved it. The bias toward over-detection is
          // architecturally correct for a monotone-worsening trust state
          // machine (false positives are human-resettable; false negatives
          // are not). If a future detector needs resolution data (human
          // response patterns, approval latency), this filter must be lifted.
          // See also: lib/session-state.sh which applies the same projection.
          if (event.session_id === sid && event.seq === 1) {
            trace.push(event);
            if (trace.length >= maxEvents) break;
          }
        } catch { /* skip malformed */ }
      }
    }

    // Handle the last remainder
    if (remainder.trim() && trace.length < maxEvents) {
      try {
        const event = JSON.parse(remainder.trim());
        if (event.session_id === sid && event.seq === 1) {
          trace.push(event);
        }
      } catch { /* skip */ }
    }

    closeSync(fd);
  } catch (e) {
    log(`readSessionTrace error: ${e.message}`);
  }

  // Reverse to chronological order (we read backwards)
  trace.reverse();
  return trace;
}

// ── Telegram notification ───────────────────────────────────────────────────

async function sendTelegram(chatId, transition, result) {
  const botToken = process.env.ZLAR_TELEGRAM_TOKEN || process.env.TELEGRAM_BOT_TOKEN;
  if (!botToken) {
    log('telegram: no bot token, skipping notification');
    return;
  }

  const stateEmoji = {
    degraded: '\u{1F7E1}',
    at_risk: '\u{1F7E0}',
    suspended: '\u{1F534}',
  };

  const consequence = {
    degraded: 'No action changes. The gate is watching, not intervening.',
    at_risk: 'The gate will ask for your approval on actions that would normally be allowed.',
    suspended: 'All agent actions are blocked until you reset.',
  };

  // Degraded = informational, no friction. at_risk+ = intervention.
  const headline = {
    degraded: 'Something looks off\\. Watching, not slowing down\\.',
    at_risk: 'Your agent may be off course\\. I slowed it down\\.',
    suspended: 'Your agent is suspended\\. All actions blocked\\.',
  };

  const emoji = stateEmoji[transition.to] || '\u{1FA7A}';

  // Type-aware routing: include detector-specific advice
  const hint = result.routing_hint;
  const adviceLine = hint
    ? `\n*What this means:* ${esc(hint.advice)}`
    : '';

  const aggregateInfo = result.aggregate
    ? `*Dominant:* ${result.aggregate.dominant} \\| *Diffuse:* ${result.aggregate.diffuse_weighted} \\| *Active detectors:* ${result.aggregate.active_detectors || 0}`
    : `*Score:* 0`;

  const slowingLine = result.slowing_down
    ? `\n\u{26A0}\u{FE0F} *Critical slowing down detected* \\(autocorrelation: ${result.slowing_down.mean_autocorrelation}\\)`
    : '';

  const text = `\u{1FA7A} \u{1F5A5}\u{FE0F} *Agent Health*

${emoji} ${headline[transition.to] || 'State changed\\.'}

*Trust state:* ${esc(transition.from)} \u{2192} ${esc(transition.to)}
*Primary signal:* ${esc(result.primary_detector || 'unknown')}
${aggregateInfo}
*Session:* \`${esc(process.argv[2])}\`${adviceLine}${slowingLine}

${esc(consequence[transition.to] || '')}

To review: \`zlar\\-restore status\`
To reset: \`zlar\\-restore reset <reason>\``;

  try {
    const url = `https://api.telegram.org/bot${botToken}/sendMessage`;
    const body = JSON.stringify({
      chat_id: chatId,
      text,
      parse_mode: 'MarkdownV2',
    });

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });

    if (!response.ok) {
      log(`telegram: send failed ${response.status}`);
    } else {
      log(`telegram: agent health notification sent`);
    }
  } catch (e) {
    log(`telegram: error ${e.message}`);
  }
}

function esc(s) {
  if (!s) return '';
  return String(s).replace(/[_\[\]()~>#+=|{}.!-]/g, '\\$&');
}

main().catch(e => {
  log(`error: ${e.message}`);
  cleanupMarker();
  process.exit(0);  // Never fail loudly from background process
});
