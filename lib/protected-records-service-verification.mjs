export const PROTECTED_RECORDS_SERVICE_RESULT_TYPE =
  'protected-records-service-result-v1';
export const PROTECTED_RECORDS_SERVICE_TYPE =
  'local-protected-records-downstream-service-v1';
export const PROTECTED_RECORDS_SERVICE_LAUNCHER_CONFIG_TYPE =
  'protected-records-service-launcher-config-v1';

// These strings describe the pinned historical result schema. Importing this
// module does not create a request path, evaluate authority, or mutate state.
export const SAFE_CLAIM_CEILING =
  'ZLAR can run a local fixture protected-records downstream service that mutates bounded service state only after a supplied signed receipt is recognized by the downstream rule, including a launcher-owned-config path where the request stream supplies only the receipt and record update while replayed, missing, unrecognized, invalid, unknown-issuer, stale, direct API, or request-stream authority-material attempts are refused before service-state mutation.';

export const NON_CLAIMS = Object.freeze([
  'This service is a local fixture downstream service.',
  'This service does not inspect a live records system.',
  'This service does not prove production deployment.',
  'This service does not prove a production records service.',
  'This service does not close direct filesystem writes to fixture paths.',
  'This service does not prove external attestation or sovereign recognition.',
  'This service does not prove coverage of unrouted records paths.',
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

export function assertProtectedRecordsServiceResult(result) {
  requireObject('Protected records service result', result);
  const expectedKeys = [
    'consumed_receipt_count',
    'decision',
    'direct_api_attempted',
    'evidence_model',
    'fixture_mode',
    'live_probing',
    'non_claims',
    'record_update_hash',
    'request_mode',
    'result_type',
    'safe_claim_ceiling',
    'service_state_changed',
    'service_type',
    'service_write_accepted',
    'state_entry_count_after',
    'state_entry_count_before',
    'state_entry_count_delta',
    'state_entry_written',
  ].sort();
  const actualKeys = Object.keys(result).sort();
  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new Error('Protected records service result contains unexpected fields');
  }
  if (result.result_type !== PROTECTED_RECORDS_SERVICE_RESULT_TYPE) {
    throw new Error('Protected records service result type drifted');
  }
  if (result.service_type !== PROTECTED_RECORDS_SERVICE_TYPE) {
    throw new Error('Protected records service type drifted');
  }
  if (![
    'local-fixture-launcher-owned-config',
    'local-fixture-supplied-input',
  ].includes(result.evidence_model)) {
    throw new Error('Protected records service evidence model drifted');
  }
  if (result.live_probing !== false) {
    throw new Error('Protected records service must not perform live probing');
  }
  if (result.fixture_mode !== true) {
    throw new Error('Protected records service must remain fixture-mode evidence');
  }
  if (!/^[a-f0-9]{64}$/.test(result.record_update_hash)) {
    throw new Error('Protected records service record update hash must be sha256 hex');
  }
  if (![
    'recognized_service_write',
    'replay_service_write',
    'missing_receipt_service_write',
    'unrecognized_service_write',
    'direct_api_write_without_receipt',
    'config_backed_service_write',
    'request_stream_authority_material',
    'request_stream_forbidden_fields',
  ].includes(result.request_mode)) {
    throw new Error('Protected records service request mode drifted');
  }
  for (const key of [
    'service_write_accepted',
    'service_state_changed',
    'state_entry_written',
    'direct_api_attempted',
  ]) {
    if (typeof result[key] !== 'boolean') {
      throw new Error(`Protected records service ${key} must be boolean`);
    }
  }
  for (const key of [
    'state_entry_count_before',
    'state_entry_count_after',
    'state_entry_count_delta',
    'consumed_receipt_count',
  ]) {
    if (!Number.isInteger(result[key]) || result[key] < 0) {
      throw new Error(`Protected records service ${key} must be a non-negative integer`);
    }
  }
  if (
    result.state_entry_count_delta !==
    result.state_entry_count_after - result.state_entry_count_before
  ) {
    throw new Error('Protected records service state entry count delta drifted');
  }
  if (
    result.service_write_accepted !== result.service_state_changed ||
    result.service_write_accepted !== result.state_entry_written
  ) {
    throw new Error('Protected records service accepted/change/state flags diverged');
  }
  if (result.service_write_accepted && result.state_entry_count_delta !== 1) {
    throw new Error(
      'Protected records service must append exactly one state entry when accepted',
    );
  }
  if (!result.service_write_accepted && result.state_entry_count_delta !== 0) {
    throw new Error('Protected records service refusal changed service state');
  }
  if (
    result.request_mode === 'direct_api_write_without_receipt' &&
    result.direct_api_attempted !== true
  ) {
    throw new Error(
      'Protected records service direct API request mode must mark direct API attempt',
    );
  }
  requireObject('Protected records service decision', result.decision);
  if (!['accept', 'refuse'].includes(result.decision.decision)) {
    throw new Error('Protected records service decision must be accept or refuse');
  }
  if (!result.decision.reason_code) {
    throw new Error('Protected records service decision must carry a reason_code');
  }
  if (!Array.isArray(result.non_claims) || result.non_claims.length !== NON_CLAIMS.length) {
    throw new Error('Protected records service non-claims drifted');
  }
  for (const claim of NON_CLAIMS) {
    if (!result.non_claims.includes(claim)) {
      throw new Error('Protected records service missing non-claim');
    }
  }
  return true;
}

export function assertNoUnsafeProtectedRecordsServiceText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_OUTPUT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`protected records service output contains ${label}`);
    }
  }
  return true;
}
