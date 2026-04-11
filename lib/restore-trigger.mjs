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

import { readFileSync, existsSync, appendFileSync } from 'node:fs';
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

function log(msg) {
  const ts = new Date().toISOString();
  try {
    appendFileSync(logFile, `${ts} ${msg}\n`);
  } catch { /* ignore */ }
}

async function main() {
  // Check config
  if (!existsSync(configFile)) { process.exit(0); }
  const config = JSON.parse(readFileSync(configFile, 'utf-8'));
  if (!config.enabled) { process.exit(0); }

  const trustStateFile = join(projectDir, config.trust_state_file || 'var/restore/trust-state.json');

  // Extract session trace
  if (!existsSync(auditFile)) { process.exit(0); }
  const lines = readFileSync(auditFile, 'utf-8').split('\n').filter(Boolean);
  const trace = [];
  for (const line of lines) {
    try {
      const event = JSON.parse(line);
      if (event.session_id === sessionId && event.seq === 1) {
        trace.push(event);
      }
    } catch { /* skip malformed lines */ }
  }

  if (trace.length < 5) {
    log(`session=${sessionId} trace_length=${trace.length} — too short, skipping`);
    process.exit(0);
  }

  // Run engine
  const { evaluate } = await import(join(projectDir, 'packages', 'zlar-restore', 'restore-engine.mjs'));
  const result = await evaluate(trace);

  log(`session=${sessionId} recommendation=${result.recommendation} score=${result.aggregate_score} trace=${trace.length}`);

  if (result.recommendation === 'healthy') {
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
}

async function sendTelegram(chatId, transition, result) {
  const botToken = process.env.ZLAR_TELEGRAM_TOKEN || process.env.TELEGRAM_BOT_TOKEN;
  if (!botToken) {
    log('telegram: no bot token, skipping notification');
    return;
  }

  // Plain language — Yuki's requirement. Not JSON.
  // Consequence first — v2.11.1 pattern.
  const stateEmoji = {
    degraded: '🟡',
    at_risk: '🟠',
    suspended: '🔴',
  };

  const consequence = {
    degraded: 'Actions will be logged with extra scrutiny.',
    at_risk: 'The gate will ask for your approval on actions that would normally be allowed.',
    suspended: 'All agent actions are blocked until you reset.',
  };

  const emoji = stateEmoji[transition.to] || '🩺';
  const text = `🩺 🖥️ *Agent Health*

${emoji} Your agent may be off course\\. I slowed it down\\.

*Trust state:* ${esc(transition.from)} → ${esc(transition.to)}
*Primary signal:* ${esc(result.primary_detector || 'unknown')}
*Score:* ${result.aggregate_score}
*Session:* \`${esc(process.argv[2])}\`

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
  process.exit(0);  // Never fail loudly from background process
});
