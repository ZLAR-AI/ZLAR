import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from 'node:fs';
import { dirname } from 'node:path';

import {
  runConfiguredRecognitionConsumer,
} from './zlar-configured-recognition-consumer-adapter.mjs';
import {
  DEFAULT_FORBIDDEN_CLAIMS,
  DEFAULT_REQUIRED_NON_CLAIMS,
  hashCanonical,
} from './zlar-configured-recognition-verifier.mjs';

export const CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_TYPE =
  'zlar-configured-recognition-consumer-replay-store-v0';
export const CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_RESULT_TYPE =
  'zlar-configured-recognition-consumer-replay-store-result-v0';
export const CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_VERSION = '0.1.0';
export const CONSUMER_REPLAY_STORE_SAFE_CLAIM_CEILING =
  'ZLAR can persist local no-secret configured-recognition consumer replay state in a supplied local fixture store and refuse immediate replay before callback invocation.';

const REPLAY_STORE_FORBIDDEN_CLAIMS = Object.freeze([
  ...DEFAULT_FORBIDDEN_CLAIMS,
  'production_durable_replay_persistence',
  'tamper_resistant_replay_store',
  'multi_host_replay_coordination',
  'real_downstream_recognition',
  'real_downstream_refusal',
  'real_downstream_effect',
  'receipt_backed_authority',
  'production_trust',
]);

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function canonicalKey(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (value.charCodeAt(index) > 127) return false;
  }
  return true;
}

function sha256Like(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function stringArray(value) {
  return Array.isArray(value) && value.every((item) => typeof item === 'string' && item.length > 0);
}

function hashOrNull(value) {
  try {
    return hashCanonical(value);
  } catch {
    return null;
  }
}

function pathHash(path) {
  return hashOrNull({ redacted_replay_store_path: path });
}

function targetRefLooksPrivate(value) {
  if (typeof value !== 'string') return false;
  return value.startsWith('/')
    || value.startsWith('~/')
    || value.startsWith('file:')
    || value.includes('/Users/')
    || value.includes('/Volumes/');
}

function looksSensitiveMarker(value) {
  if (typeof value !== 'string') return false;
  const compact = value.replace(/[^A-Za-z0-9]/g, '').toLowerCase();
  return [
    'apikey',
    'apitoken',
    'accesstoken',
    'refreshtoken',
    'clientsecret',
    'password',
    'passwd',
    'privatekey',
    'secret',
    'token',
    'hmac',
    'signing',
    'authorization',
    'bearer',
  ].some((marker) => compact.includes(marker))
    || /^sk_(live|test)_[A-Za-z0-9_]+/.test(value)
    || /BEGIN [A-Z ]*PRIVATE KEY/i.test(value)
    || /Authorization:\s*Bearer/i.test(value);
}

function redactPrivateString(value, label = 'replay-store-string', extraPrivateStrings = new Set()) {
  if (looksSensitiveMarker(value)) return `redacted-sensitive-${label}`;
  if (extraPrivateStrings.has(value)) return `redacted-${label}:${hashOrNull(value)}`;
  if (!targetRefLooksPrivate(value)) return value ?? null;
  return `redacted-${label}:${hashOrNull(value)}`;
}

function redactBoundaryValue(value, extraPrivateStrings = new Set(), seen = new WeakSet()) {
  if (typeof value === 'string') return redactPrivateString(value, 'replay-store-string', extraPrivateStrings);
  if (typeof value === 'bigint') return '[unsupported-bigint]';
  if (typeof value === 'function') return '[unsupported-function]';
  if (typeof value === 'symbol') return '[unsupported-symbol]';
  if (Array.isArray(value)) {
    if (seen.has(value)) return '[circular]';
    seen.add(value);
    return value.map((item) => redactBoundaryValue(item, extraPrivateStrings, seen));
  }
  if (isObject(value)) {
    if (seen.has(value)) return '[circular]';
    seen.add(value);
    const output = {};
    for (const key of Object.keys(value)) {
      const sensitiveKey = looksSensitiveMarker(key);
      const redactedKey = sensitiveKey
        ? `redacted-sensitive-replay-store-key:${hashOrNull(key)}`
        : targetRefLooksPrivate(key) || extraPrivateStrings.has(key)
        ? redactPrivateString(key, 'replay-store-key', extraPrivateStrings)
        : key;
      output[redactedKey] = sensitiveKey
        ? 'redacted-sensitive-replay-store-value'
        : redactBoundaryValue(value[key], extraPrivateStrings, seen);
    }
    return output;
  }
  return value;
}

function safeRedactBoundaryValue(value, extraPrivateStrings = new Set()) {
  try {
    return redactBoundaryValue(value, extraPrivateStrings);
  } catch {
    return '[unavailable-replay-store-value]';
  }
}

function emptyReplayState() {
  return {
    used_credential_hashes: [],
    used_credential_ids: [],
    used_nonces: [],
    last_sequence_by_issuer: {},
    last_receipt_hash_by_issuer: {},
  };
}

function emptyReplayStore() {
  return {
    store_type: CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_TYPE,
    store_version: CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_VERSION,
    replay_state: emptyReplayState(),
  };
}

function normalizeReplayState(replayState = {}) {
  const source = isObject(replayState) ? replayState : {};
  return {
    used_credential_hashes: stringArray(source.used_credential_hashes)
      ? [...source.used_credential_hashes]
      : [],
    used_credential_ids: stringArray(source.used_credential_ids)
      ? [...source.used_credential_ids]
      : [],
    used_nonces: stringArray(source.used_nonces)
      ? [...source.used_nonces]
      : [],
    last_sequence_by_issuer: isObject(source.last_sequence_by_issuer)
      ? { ...source.last_sequence_by_issuer }
      : {},
    last_receipt_hash_by_issuer: isObject(source.last_receipt_hash_by_issuer)
      ? { ...source.last_receipt_hash_by_issuer }
      : {},
  };
}

function validateReplayState(replayState) {
  if (!isObject(replayState)) return 'replay_state_not_object';
  for (const field of ['used_credential_hashes', 'used_credential_ids', 'used_nonces']) {
    if (!stringArray(replayState[field])) return 'replay_state_array_field_invalid';
  }
  if (!isObject(replayState.last_sequence_by_issuer)) {
    return 'replay_state_cursor_field_invalid';
  }
  for (const [key, value] of Object.entries(replayState.last_sequence_by_issuer)) {
    if (
      !canonicalKey(key) ||
      typeof value !== 'number' ||
      !Number.isInteger(value) ||
      !Number.isSafeInteger(value) ||
      value < 0
    ) {
      return 'replay_state_numeric_field_invalid';
    }
  }
  if (!isObject(replayState.last_receipt_hash_by_issuer)) {
    return 'replay_state_cursor_field_invalid';
  }
  for (const [key, value] of Object.entries(replayState.last_receipt_hash_by_issuer)) {
    if (!canonicalKey(key) || !sha256Like(value)) {
      return 'replay_state_cursor_field_invalid';
    }
  }
  return null;
}

function validateStore(store) {
  if (!isObject(store)) return 'replay_store_not_object';
  if (store.store_type !== CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_TYPE) {
    return 'replay_store_type_invalid';
  }
  if (store.store_version !== CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_VERSION) {
    return 'replay_store_version_invalid';
  }
  return validateReplayState(store.replay_state);
}

function readReplayStore(replayStorePath) {
  const present = existsSync(replayStorePath);
  if (!present) {
    const store = emptyReplayStore();
    return {
      ok: true,
      present,
      store,
      reason_code: 'replay_store_missing_started_empty',
    };
  }
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(replayStorePath, 'utf8'));
  } catch {
    return {
      ok: false,
      present,
      store: null,
      reason_code: 'replay_store_parse_failed',
    };
  }
  const invalid = validateStore(parsed);
  if (invalid) {
    return {
      ok: false,
      present,
      store: null,
      reason_code: invalid,
    };
  }
  return {
    ok: true,
    present,
    store: {
      store_type: CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_TYPE,
      store_version: CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_VERSION,
      replay_state: normalizeReplayState(parsed.replay_state),
    },
    reason_code: 'replay_store_loaded',
  };
}

function writeReplayStore(replayStorePath, store) {
  mkdirSync(dirname(replayStorePath), { recursive: true });
  const tmpPath = `${replayStorePath}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(tmpPath, `${JSON.stringify(store, null, 2)}\n`, 'utf8');
  renameSync(tmpPath, replayStorePath);
}

function result({
  replayStorePath,
  wrapperDecision,
  reasonCode,
  storePresentBefore = false,
  storePresentAfter = false,
  storeBefore = null,
  storeAfter = null,
  storeWritten = false,
  consumerResult = null,
}) {
  const extraPrivateStrings = new Set([replayStorePath].filter((value) => typeof value === 'string'));
  const redactedConsumerResult = consumerResult === null
    ? null
    : safeRedactBoundaryValue(consumerResult, extraPrivateStrings);
  return {
    result_type: CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_RESULT_TYPE,
    store_type: CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_TYPE,
    store_version: CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_VERSION,
    wrapper_decision: wrapperDecision,
    reason_code: reasonCode,
    store_path_hash: pathHash(replayStorePath),
    store_present_before: storePresentBefore,
    store_present_after: storePresentAfter,
    store_before_hash: storeBefore === null ? null : hashOrNull(storeBefore),
    store_after_hash: storeAfter === null ? null : hashOrNull(storeAfter),
    store_written: storeWritten,
    consumer_result_hash: redactedConsumerResult === null ? null : hashOrNull(redactedConsumerResult),
    consumer_result: redactedConsumerResult,
    safe_claim_ceiling: CONSUMER_REPLAY_STORE_SAFE_CLAIM_CEILING,
    non_claims: [...DEFAULT_REQUIRED_NON_CLAIMS],
    forbidden_claims: [...REPLAY_STORE_FORBIDDEN_CLAIMS],
  };
}

function shouldPersistConsumerReplayState(consumerResult) {
  return (
    isObject(consumerResult) &&
    consumerResult.effect_called === true &&
    isObject(consumerResult.next_replay_state) &&
    consumerResult.evidence?.replay_state_changed === true
  );
}

export async function runConfiguredRecognitionConsumerWithReplayStore(input = {}) {
  const source = isObject(input) ? input : {};
  const replayStorePath = source.replay_store_path || source.replayStorePath;
  if (typeof replayStorePath !== 'string' || replayStorePath.length === 0) {
    return result({
      replayStorePath: '[missing-replay-store-path]',
      wrapperDecision: 'fail_closed',
      reasonCode: 'replay_store_path_missing',
    });
  }

  const storeRead = readReplayStore(replayStorePath);
  if (!storeRead.ok) {
    return result({
      replayStorePath,
      wrapperDecision: 'fail_closed',
      reasonCode: storeRead.reason_code,
      storePresentBefore: storeRead.present,
      storePresentAfter: storeRead.present,
    });
  }

  const storeBefore = clone(storeRead.store);
  const {
    replay_store_path: _snakeReplayStorePath,
    replayStorePath: _camelReplayStorePath,
    ...consumerInput
  } = source;
  const consumerResult = await runConfiguredRecognitionConsumer({
    ...consumerInput,
    replay_state: clone(storeRead.store.replay_state),
  });

  if (!shouldPersistConsumerReplayState(consumerResult)) {
    return result({
      replayStorePath,
      wrapperDecision: 'ok',
      reasonCode: 'consumer_replay_state_not_persisted',
      storePresentBefore: storeRead.present,
      storePresentAfter: existsSync(replayStorePath),
      storeBefore,
      storeAfter: clone(storeRead.store),
      storeWritten: false,
      consumerResult,
    });
  }

  const invalidRawNextReplay = validateReplayState(consumerResult.next_replay_state);
  if (invalidRawNextReplay) {
    return result({
      replayStorePath,
      wrapperDecision: 'fail_closed',
      reasonCode: invalidRawNextReplay,
      storePresentBefore: storeRead.present,
      storePresentAfter: existsSync(replayStorePath),
      storeBefore,
      storeAfter: clone(storeRead.store),
      storeWritten: false,
      consumerResult,
    });
  }

  const nextStore = {
    store_type: CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_TYPE,
    store_version: CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_VERSION,
    replay_state: normalizeReplayState(consumerResult.next_replay_state),
  };
  const invalidNextStore = validateStore(nextStore);
  if (invalidNextStore) {
    return result({
      replayStorePath,
      wrapperDecision: 'fail_closed',
      reasonCode: invalidNextStore,
      storePresentBefore: storeRead.present,
      storePresentAfter: existsSync(replayStorePath),
      storeBefore,
      storeAfter: clone(storeRead.store),
      storeWritten: false,
      consumerResult,
    });
  }

  try {
    writeReplayStore(replayStorePath, nextStore);
  } catch {
    return result({
      replayStorePath,
      wrapperDecision: 'fail_closed',
      reasonCode: 'replay_store_write_failed',
      storePresentBefore: storeRead.present,
      storePresentAfter: existsSync(replayStorePath),
      storeBefore,
      storeAfter: clone(storeRead.store),
      storeWritten: false,
      consumerResult,
    });
  }

  return result({
    replayStorePath,
    wrapperDecision: 'ok',
    reasonCode: 'consumer_replay_state_persisted',
    storePresentBefore: storeRead.present,
    storePresentAfter: true,
    storeBefore,
    storeAfter: nextStore,
    storeWritten: true,
    consumerResult,
  });
}

export function assertConfiguredRecognitionConsumerReplayStorePersisted(resultValue) {
  if (
    !resultValue ||
    resultValue.result_type !== CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_RESULT_TYPE
  ) {
    throw new Error('Configured recognition replay-store result has the wrong result type');
  }
  if (resultValue.wrapper_decision !== 'ok' || resultValue.store_written !== true) {
    throw new Error(`Replay store was not persisted: ${resultValue.reason_code || 'unknown'}`);
  }
  return true;
}

export function assertConfiguredRecognitionConsumerReplayStoreFailClosed(resultValue, expectedCode = null) {
  if (
    !resultValue ||
    resultValue.result_type !== CONFIGURED_RECOGNITION_CONSUMER_REPLAY_STORE_RESULT_TYPE
  ) {
    throw new Error('Configured recognition replay-store result has the wrong result type');
  }
  if (resultValue.wrapper_decision !== 'fail_closed' || resultValue.store_written !== false) {
    throw new Error('Replay store wrapper did not fail closed');
  }
  if (expectedCode && resultValue.reason_code !== expectedCode) {
    throw new Error(`Expected replay-store failure ${expectedCode}, got ${resultValue.reason_code}`);
  }
  return true;
}
