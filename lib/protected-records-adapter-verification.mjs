export const PROTECTED_RECORDS_WRITE_RESULT_TYPE = 'protected-records-write-result-v1';
export const PROTECTED_RECORDS_ADAPTER_TYPE = 'local-protected-records-action-adapter-v1';
export const PROTECTED_RECORDS_CONSUMED_STORE_TYPE = 'protected-records-consumed-receipts-v1';

export const SAFE_CLAIM_CEILING =
  'ZLAR can run a local fixture protected-records action adapter that appends a bounded ledger entry only after a supplied signed receipt is recognized by a supplied downstream rule, and refuses missing, unrecognized, or replayed receipts before append.';

export const NON_CLAIMS = Object.freeze([
  'This adapter is a local fixture action adapter.',
  'This adapter does not inspect a live records system.',
  'This adapter does not prove production deployment.',
  'This adapter does not prove a live records-system adapter.',
  'This adapter does not prove external attestation or sovereign recognition.',
  'This adapter does not prove coverage of unrouted records paths.',
]);

const UNSAFE_OUTPUT_PATTERNS = Object.freeze([
  { label: 'private operator path', pattern: /\/Users\/[^\s"'`]+/ },
  { label: 'home path', pattern: /\/home\/[^\s"'`]+/ },
  { label: 'private path', pattern: /\/private\/[^\s"'`]+/ },
  { label: 'temp path', pattern: /\/tmp\/[^\s"'`]+/ },
  { label: 'var path', pattern: /\/var\/[^\s"'`]+/ },
  { label: 'numeric human identifier', pattern: /\bhuman:[0-9]/ },
  { label: 'chat id field', pattern: /\bchat_id\b/i },
  { label: 'private key material', pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
  { label: 'public key material', pattern: /BEGIN PUBLIC KEY/ },
  {
    label: 'key-value credential',
    pattern: /\b(?:token|secret|password|api[_-]?key)\s*[:=]\s*[^&\s"'`,;})\]]+/i,
  },
  {
    label: 'authorization credential',
    pattern: /\bauthorization\s*[:=]\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}/i,
  },
  { label: 'GitHub token', pattern: /\bghp_[A-Za-z0-9_]{10,}\b/ },
  { label: 'GitHub fine-grained token', pattern: /\bgithub_pat_[A-Za-z0-9_]{10,}\b/ },
  { label: 'Slack token', pattern: /\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b/ },
  { label: 'AWS access key', pattern: /\bAKIA[0-9A-Z]{12,}\b/ },
  { label: 'OpenAI-style key', pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/ },
  { label: 'bot token', pattern: /\bbot[0-9]{6,}:[A-Za-z0-9_-]{6,}\b/ },
]);

function requireObject(label, value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

export function assertProtectedRecordsWriteResult(result) {
  requireObject('Protected records write result', result);
  const expectedKeys = [
    'adapter_type',
    'consumed_receipt_count',
    'decision',
    'evidence_model',
    'fixture_mode',
    'ledger_entry_written',
    'live_probing',
    'non_claims',
    'record_changed',
    'record_count_after',
    'record_count_before',
    'record_count_delta',
    'result_type',
    'safe_claim_ceiling',
    'write_accepted',
    'write_detail_hash',
  ].sort();
  const actualKeys = Object.keys(result).sort();
  if (actualKeys.length !== expectedKeys.length || actualKeys.some((key, index) => key !== expectedKeys[index])) {
    throw new Error('Protected records write result contains unexpected fields');
  }
  if (result.result_type !== PROTECTED_RECORDS_WRITE_RESULT_TYPE) {
    throw new Error('Protected records write result type drifted');
  }
  if (result.adapter_type !== PROTECTED_RECORDS_ADAPTER_TYPE) {
    throw new Error('Protected records write adapter type drifted');
  }
  if (result.evidence_model !== 'local-fixture-supplied-input') {
    throw new Error('Protected records write evidence model drifted');
  }
  if (result.live_probing !== false) {
    throw new Error('Protected records write must not perform live probing');
  }
  if (result.fixture_mode !== true) {
    throw new Error('Protected records write must remain fixture-mode evidence');
  }
  if (!/^[a-f0-9]{64}$/.test(result.write_detail_hash)) {
    throw new Error('Protected records write detail hash must be sha256 hex');
  }
  for (const key of [
    'write_accepted',
    'record_changed',
    'ledger_entry_written',
  ]) {
    if (typeof result[key] !== 'boolean') {
      throw new Error(`Protected records write ${key} must be boolean`);
    }
  }
  for (const key of [
    'record_count_before',
    'record_count_after',
    'record_count_delta',
    'consumed_receipt_count',
  ]) {
    if (!Number.isInteger(result[key]) || result[key] < 0) {
      throw new Error(`Protected records write ${key} must be a non-negative integer`);
    }
  }
  if (result.record_count_delta !== result.record_count_after - result.record_count_before) {
    throw new Error('Protected records write record count delta drifted');
  }
  if (result.write_accepted !== result.record_changed || result.write_accepted !== result.ledger_entry_written) {
    throw new Error('Protected records write accepted/change/ledger flags diverged');
  }
  if (result.write_accepted && result.record_count_delta !== 1) {
    throw new Error('Protected records write must append exactly one record when accepted');
  }
  if (!result.write_accepted && result.record_count_delta !== 0) {
    throw new Error('Protected records write refusal changed the ledger');
  }
  requireObject('Protected records write decision', result.decision);
  if (!['accept', 'refuse'].includes(result.decision.decision)) {
    throw new Error('Protected records write decision must be accept or refuse');
  }
  if (!result.decision.reason_code) {
    throw new Error('Protected records write decision must carry a reason_code');
  }
  if (!Array.isArray(result.non_claims) || result.non_claims.length !== NON_CLAIMS.length) {
    throw new Error('Protected records write non-claims drifted');
  }
  for (const claim of NON_CLAIMS) {
    if (!result.non_claims.includes(claim)) {
      throw new Error('Protected records write missing non-claim');
    }
  }
  return true;
}

export function assertNoUnsafeProtectedRecordsAdapterText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_OUTPUT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`protected records adapter output contains ${label}`);
    }
  }
  return true;
}
