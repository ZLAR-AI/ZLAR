// evaluation-history.mjs — Ring buffer for Agent Health evaluation history
//
// Stores the last K evaluation signal vectors alongside the trust-state file.
// Used by the engine's critical-slowing-down detector to compute lag-1
// autocorrelation across consecutive evaluations. Rising autocorrelation
// signals approach to a regime transition.
//
// HMAC-protected: if an HMAC key is set (via setHmacKey), the history file
// includes an integrity signature. Tampering returns empty history (fail-open
// for the slowing-down detector, which means it won't trigger — conservative).
//
// This is pure time-series statistics on the engine's own outputs.
// No behavioral profiling. No learned baselines.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createHmac } from 'node:crypto';

const MAX_ENTRIES = 8; // keep last 8 evaluations

let _hmacKey = null;

export function setHistoryHmacKey(keyOrPath) {
  if (!keyOrPath) { _hmacKey = null; return; }
  if (existsSync(keyOrPath)) {
    _hmacKey = readFileSync(keyOrPath, 'utf-8').trim();
  } else {
    _hmacKey = keyOrPath;
  }
}

function computeHmac(payload) {
  if (!_hmacKey) return null;
  return createHmac('sha256', _hmacKey).update(payload).digest('hex');
}

export function loadHistory(filePath) {
  if (!existsSync(filePath)) {
    return [];
  }
  try {
    const raw = readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(raw);

    // HMAC verification
    if (_hmacKey) {
      const storedHmac = parsed._hmac;
      if (!storedHmac) return []; // key set but no HMAC — tampered
      const { _hmac: _, ...rest } = parsed;
      const payloadStr = JSON.stringify(rest);
      const computed = computeHmac(payloadStr);
      if (computed !== storedHmac) return []; // HMAC mismatch — tampered
      return (rest.entries || []).slice(-MAX_ENTRIES);
    }

    // No key — trust the file
    if (Array.isArray(parsed)) return parsed.slice(-MAX_ENTRIES);
    if (parsed.entries && Array.isArray(parsed.entries)) return parsed.entries.slice(-MAX_ENTRIES);
    return [];
  } catch {
    return [];
  }
}

export function appendHistory(filePath, signalVector) {
  const history = loadHistory(filePath);
  history.push(signalVector);

  // Trim to max entries
  while (history.length > MAX_ENTRIES) {
    history.shift();
  }

  const dir = dirname(filePath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  // Write with HMAC if key is available
  if (_hmacKey) {
    const payload = { entries: history };
    const payloadStr = JSON.stringify(payload);
    const hmac = computeHmac(payloadStr);
    writeFileSync(filePath, JSON.stringify({ ...payload, _hmac: hmac }, null, 2) + '\n');
  } else {
    writeFileSync(filePath, JSON.stringify(history, null, 2) + '\n');
  }

  return history;
}
