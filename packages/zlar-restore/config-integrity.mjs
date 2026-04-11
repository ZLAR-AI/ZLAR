// config-integrity.mjs — HMAC integrity for restore-config.json
//
// The restore config controls whether Agent Health is enabled, what
// escalation levels apply, and reset parameters. An agent that can
// tamper with this config can disable the entire subsystem.
//
// This module signs and verifies the config using a separate HMAC key.
// On verification failure, the caller should fail CLOSED: force restore
// on with maximum escalation. An attacker who tampers gets the opposite
// of what they wanted.
//
// The HMAC is stored alongside the config as restore-config.json.hmac
// (not inline — the config file stays human-readable and jq-friendly).

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHmac } from 'node:crypto';

// Sign the config file. Writes the HMAC to a .hmac sidecar file.
// Returns the HMAC hex string.
export function signConfig(configPath, hmacKey) {
  if (!hmacKey) throw new Error('HMAC key required to sign config');
  if (!existsSync(configPath)) throw new Error(`Config not found: ${configPath}`);

  const content = readFileSync(configPath, 'utf-8');
  // Normalize: parse and re-serialize to canonical JSON (no trailing whitespace variance)
  const canonical = JSON.stringify(JSON.parse(content));
  const hmac = createHmac('sha256', hmacKey).update(canonical).digest('hex');

  const hmacPath = configPath + '.hmac';
  writeFileSync(hmacPath, hmac + '\n');
  return hmac;
}

// Verify the config file against its HMAC sidecar.
// Returns { valid: true } or { valid: false, reason: string }.
export function verifyConfig(configPath, hmacKey) {
  if (!hmacKey) {
    return { valid: true, reason: 'no key — skipping verification' };
  }

  if (!existsSync(configPath)) {
    return { valid: false, reason: 'config file missing' };
  }

  const hmacPath = configPath + '.hmac';
  if (!existsSync(hmacPath)) {
    return { valid: false, reason: 'HMAC sidecar missing — config unsigned or tampered' };
  }

  const content = readFileSync(configPath, 'utf-8');
  let canonical;
  try {
    canonical = JSON.stringify(JSON.parse(content));
  } catch {
    return { valid: false, reason: 'config is not valid JSON' };
  }

  const computed = createHmac('sha256', hmacKey).update(canonical).digest('hex');
  const stored = readFileSync(hmacPath, 'utf-8').trim();

  if (computed !== stored) {
    return { valid: false, reason: 'HMAC mismatch — config tampered' };
  }

  return { valid: true };
}
