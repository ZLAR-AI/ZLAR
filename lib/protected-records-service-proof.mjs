import {
  PROTECTED_RECORDS_SERVICE_RESULT_TYPE,
  PROTECTED_RECORDS_SERVICE_TYPE,
} from './protected-records-service-verification.mjs';

export const PROTECTED_RECORDS_SERVICE_PROOF_TYPE = 'protected-records-service-proof-v1';

export const REQUIRED_SERVICE_CASES = Object.freeze([
  'recognized_service_write_first_process',
  'replay_refused_after_service_restart',
  'missing_receipt_refused_before_service_mutation',
  'unrecognized_receipt_refused_before_service_mutation',
  'invalid_receipt_refused_before_service_mutation',
  'unknown_issuer_refused_before_service_mutation',
  'stale_receipt_refused_before_service_mutation',
  'direct_api_write_without_receipt_refused_before_service_mutation',
]);

export const SAFE_CLAIM_CEILING =
  'ZLAR can run a local disposable protected-records downstream service proof, showing a recognized receipt mutates bounded service state once, replay refuses across a fresh service process, missing, unrecognized, invalid, unknown-issuer, and stale receipts refuse before service-state mutation, and a fixture service API write attempt without a receipt refuses before mutation.';

export const NON_CLAIMS = Object.freeze([
  'This proof is local disposable downstream-service evidence.',
  'This proof does not inspect a live records system.',
  'This proof does not prove production records service deployment.',
  'This proof does not close direct filesystem writes to supplied fixture paths.',
  'This proof does not prove external attestation or sovereign recognition.',
  'This proof does not prove coverage of unrouted records paths.',
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

function assertExactKeys(label, value, expectedKeys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains unexpected fields`);
  }
  return true;
}

export const PROTECTED_RECORDS_SERVICE_PROOF_GENERATION_RETIREMENT_REASON =
  'e2_positive_service_proof_generation_retired';

export function runProtectedRecordsServiceProof() {
  throw new Error(PROTECTED_RECORDS_SERVICE_PROOF_GENERATION_RETIREMENT_REASON);
}

export function assertProtectedRecordsServiceProof(report) {
  assertExactKeys('Protected records service proof', report, [
    'cases',
    'evidence_model',
    'known_open_boundaries',
    'live_probing',
    'non_claims',
    'proof_type',
    'safe_claim_ceiling',
    'service_profile',
    'side_door_report',
  ]);
  if (report.proof_type !== PROTECTED_RECORDS_SERVICE_PROOF_TYPE) {
    throw new Error('Protected records service proof type drifted');
  }
  if (report.evidence_model !== 'local-disposable-service-process-fixture') {
    throw new Error('Protected records service proof evidence model drifted');
  }
  if (report.live_probing !== false) {
    throw new Error('Protected records service proof must not perform live probing');
  }
  if (report.safe_claim_ceiling !== SAFE_CLAIM_CEILING) {
    throw new Error('Protected records service proof safe claim ceiling drifted');
  }

  assertExactKeys('Protected records service profile', report.service_profile, [
    'action_class',
    'consumed_receipt_store',
    'direct_api_request_model',
    'mutation_authoritative_route',
    'profile_id',
    'recognition_boundary',
    'replay_scope',
    'result_type',
    'service_command',
    'service_process_boundary',
    'service_type',
    'state_model',
  ]);
  const profile = report.service_profile;
  if (
    profile.profile_id !== 'protected-records-downstream-service-fixture' ||
    profile.action_class !== 'records.write' ||
    profile.service_type !== PROTECTED_RECORDS_SERVICE_TYPE ||
    profile.service_command !== 'zlar protected-records-service-request --input <file|->' ||
    profile.service_process_boundary !== 'separate-cli-process' ||
    profile.recognition_boundary !== 'downstream-recognition-before-service-mutation' ||
    profile.mutation_authoritative_route !== 'receipt-recognition-before-service-state-append' ||
    profile.result_type !== PROTECTED_RECORDS_SERVICE_RESULT_TYPE ||
    profile.state_model !== 'bounded-jsonl-service-state-entry' ||
    profile.consumed_receipt_store !== 'persistent-single-use-receipt-id-store' ||
    profile.replay_scope !== 'per-service-consumed-receipt-store' ||
    profile.direct_api_request_model !== 'no-receipt-direct-api-attempt-refuses-before-mutation'
  ) {
    throw new Error('Protected records service profile drifted');
  }

  assertExactKeys('Protected records service side-door report', report.side_door_report, [
    'direct_api_without_receipt_refused',
    'direct_filesystem_write_to_fixture_paths_closed',
    'live_records_service',
    'live_records_system_checked',
    'production_records_service_checked',
    'unrouted_records_paths_checked',
  ]);
  if (
    report.side_door_report.direct_api_without_receipt_refused !== true ||
    report.side_door_report.direct_filesystem_write_to_fixture_paths_closed !== false ||
    report.side_door_report.live_records_system_checked !== false ||
    report.side_door_report.production_records_service_checked !== false ||
    report.side_door_report.unrouted_records_paths_checked !== false ||
    report.side_door_report.live_records_service !== false
  ) {
    throw new Error('Protected records service side-door report drifted');
  }

  if (!Array.isArray(report.cases) || report.cases.length !== REQUIRED_SERVICE_CASES.length) {
    throw new Error('Protected records service proof case count drifted');
  }
  for (const caseId of REQUIRED_SERVICE_CASES) {
    if (!report.cases.some((item) => item.case_id === caseId)) {
      throw new Error(`Protected records service proof missing case: ${caseId}`);
    }
  }
  for (const item of report.cases) {
    assertExactKeys('Protected records service case', item, [
      'case_id',
      'command',
      'consumed_receipt_count',
      'consumed_store_exists_after',
      'direct_api_attempted',
      'exit_status',
      'process_boundary',
      'process_invocation',
      'reason_code',
      'separate_process_from_accepted',
      'service_write_accepted',
      'state_entry_count_after',
      'state_entry_count_before',
      'state_entry_count_delta',
      'stderr_empty',
      'stdout_json_emitted',
    ]);
    if (item.process_boundary !== 'separate-cli-process') {
      throw new Error('Protected records service case process boundary drifted');
    }
    if (item.state_entry_count_delta !== item.state_entry_count_after - item.state_entry_count_before) {
      throw new Error('Protected records service case state delta drifted');
    }
  }

  const accepted = report.cases.find((item) => item.case_id === 'recognized_service_write_first_process');
  if (
    accepted.command !== 'zlar protected-records-service-request --input <file|-> --require-written' ||
    accepted.process_invocation !== 1 ||
    accepted.separate_process_from_accepted !== false ||
    accepted.exit_status !== 0 ||
    accepted.stdout_json_emitted !== true ||
    accepted.stderr_empty !== true ||
    accepted.service_write_accepted !== true ||
    accepted.reason_code !== 'recognized' ||
    accepted.state_entry_count_before !== 0 ||
    accepted.state_entry_count_after !== 1 ||
    accepted.state_entry_count_delta !== 1 ||
    accepted.consumed_receipt_count !== 1 ||
    accepted.consumed_store_exists_after !== true ||
    accepted.direct_api_attempted !== false
  ) {
    throw new Error('Protected records service accepted case failed');
  }

  const replay = report.cases.find((item) => item.case_id === 'replay_refused_after_service_restart');
  if (
    replay.process_invocation !== 2 ||
    replay.separate_process_from_accepted !== true ||
    replay.exit_status !== 0 ||
    replay.stdout_json_emitted !== true ||
    replay.stderr_empty !== true ||
    replay.service_write_accepted !== false ||
    replay.reason_code !== 'receipt_replay' ||
    replay.state_entry_count_before !== 1 ||
    replay.state_entry_count_after !== 1 ||
    replay.state_entry_count_delta !== 0 ||
    replay.consumed_receipt_count !== 1 ||
    replay.consumed_store_exists_after !== true ||
    replay.direct_api_attempted !== false
  ) {
    throw new Error('Protected records service replay case failed');
  }

  const missing = report.cases.find((item) => item.case_id === 'missing_receipt_refused_before_service_mutation');
  if (
    missing.process_invocation !== 3 ||
    missing.exit_status !== 0 ||
    missing.stdout_json_emitted !== true ||
    missing.stderr_empty !== true ||
    missing.service_write_accepted !== false ||
    missing.reason_code !== 'receipt_missing' ||
    missing.state_entry_count_before !== 0 ||
    missing.state_entry_count_after !== 0 ||
    missing.state_entry_count_delta !== 0 ||
    missing.consumed_receipt_count !== 0 ||
    missing.direct_api_attempted !== false
  ) {
    throw new Error('Protected records service missing-receipt case failed');
  }

  const unrecognized = report.cases.find((item) => item.case_id === 'unrecognized_receipt_refused_before_service_mutation');
  if (
    unrecognized.process_invocation !== 4 ||
    unrecognized.exit_status !== 0 ||
    unrecognized.stdout_json_emitted !== true ||
    unrecognized.stderr_empty !== true ||
    unrecognized.service_write_accepted !== false ||
    unrecognized.reason_code !== 'detail_hash_mismatch' ||
    unrecognized.state_entry_count_before !== 0 ||
    unrecognized.state_entry_count_after !== 0 ||
    unrecognized.state_entry_count_delta !== 0 ||
    unrecognized.consumed_receipt_count !== 0 ||
    unrecognized.direct_api_attempted !== false
  ) {
    throw new Error('Protected records service unrecognized case failed');
  }

  const invalid = report.cases.find((item) => item.case_id === 'invalid_receipt_refused_before_service_mutation');
  if (
    invalid.process_invocation !== 5 ||
    invalid.exit_status !== 0 ||
    invalid.stdout_json_emitted !== true ||
    invalid.stderr_empty !== true ||
    invalid.service_write_accepted !== false ||
    invalid.reason_code !== 'receipt_invalid' ||
    invalid.state_entry_count_before !== 0 ||
    invalid.state_entry_count_after !== 0 ||
    invalid.state_entry_count_delta !== 0 ||
    invalid.consumed_receipt_count !== 0 ||
    invalid.consumed_store_exists_after !== false ||
    invalid.direct_api_attempted !== false
  ) {
    throw new Error('Protected records service invalid-receipt case failed');
  }

  const unknownIssuer = report.cases.find((item) => item.case_id === 'unknown_issuer_refused_before_service_mutation');
  if (
    unknownIssuer.process_invocation !== 6 ||
    unknownIssuer.exit_status !== 0 ||
    unknownIssuer.stdout_json_emitted !== true ||
    unknownIssuer.stderr_empty !== true ||
    unknownIssuer.service_write_accepted !== false ||
    unknownIssuer.reason_code !== 'unknown_issuer' ||
    unknownIssuer.state_entry_count_before !== 0 ||
    unknownIssuer.state_entry_count_after !== 0 ||
    unknownIssuer.state_entry_count_delta !== 0 ||
    unknownIssuer.consumed_receipt_count !== 0 ||
    unknownIssuer.consumed_store_exists_after !== false ||
    unknownIssuer.direct_api_attempted !== false
  ) {
    throw new Error('Protected records service unknown-issuer case failed');
  }

  const stale = report.cases.find((item) => item.case_id === 'stale_receipt_refused_before_service_mutation');
  if (
    stale.process_invocation !== 7 ||
    stale.exit_status !== 0 ||
    stale.stdout_json_emitted !== true ||
    stale.stderr_empty !== true ||
    stale.service_write_accepted !== false ||
    stale.reason_code !== 'receipt_stale' ||
    stale.state_entry_count_before !== 0 ||
    stale.state_entry_count_after !== 0 ||
    stale.state_entry_count_delta !== 0 ||
    stale.consumed_receipt_count !== 0 ||
    stale.consumed_store_exists_after !== false ||
    stale.direct_api_attempted !== false
  ) {
    throw new Error('Protected records service stale-receipt case failed');
  }

  const directApi = report.cases.find((item) => item.case_id === 'direct_api_write_without_receipt_refused_before_service_mutation');
  if (
    directApi.process_invocation !== 8 ||
    directApi.exit_status !== 0 ||
    directApi.stdout_json_emitted !== true ||
    directApi.stderr_empty !== true ||
    directApi.service_write_accepted !== false ||
    directApi.reason_code !== 'receipt_missing' ||
    directApi.state_entry_count_before !== 0 ||
    directApi.state_entry_count_after !== 0 ||
    directApi.state_entry_count_delta !== 0 ||
    directApi.consumed_receipt_count !== 0 ||
    directApi.direct_api_attempted !== true
  ) {
    throw new Error('Protected records service direct API case failed');
  }

  const requiredOpenBoundaries = [
    'direct_filesystem_write_to_supplied_fixture_paths',
    'live_records_system',
    'production_records_service',
    'unrouted_records_paths',
  ];
  if (!Array.isArray(report.known_open_boundaries) || report.known_open_boundaries.length !== requiredOpenBoundaries.length) {
    throw new Error('Protected records service open boundary list drifted');
  }
  for (const boundary of requiredOpenBoundaries) {
    if (!report.known_open_boundaries.includes(boundary)) {
      throw new Error(`Protected records service missing open boundary: ${boundary}`);
    }
  }

  if (!Array.isArray(report.non_claims) || report.non_claims.length !== NON_CLAIMS.length) {
    throw new Error('Protected records service non-claims drifted');
  }
  for (const claim of NON_CLAIMS) {
    if (!report.non_claims.includes(claim)) {
      throw new Error('Protected records service missing non-claim');
    }
  }
  assertNoUnsafeProtectedRecordsServiceProofText(JSON.stringify(report));
  return true;
}

export function assertNoUnsafeProtectedRecordsServiceProofText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_OUTPUT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`protected records service proof output contains ${label}`);
    }
  }
  return true;
}

export function formatProtectedRecordsServiceProofSummary(report) {
  assertProtectedRecordsServiceProof(report);
  const accepted = report.cases.find((item) => item.case_id === 'recognized_service_write_first_process');
  const replay = report.cases.find((item) => item.case_id === 'replay_refused_after_service_restart');
  const missing = report.cases.find((item) => item.case_id === 'missing_receipt_refused_before_service_mutation');
  const unrecognized = report.cases.find((item) => item.case_id === 'unrecognized_receipt_refused_before_service_mutation');
  const invalid = report.cases.find((item) => item.case_id === 'invalid_receipt_refused_before_service_mutation');
  const unknownIssuer = report.cases.find((item) => item.case_id === 'unknown_issuer_refused_before_service_mutation');
  const stale = report.cases.find((item) => item.case_id === 'stale_receipt_refused_before_service_mutation');
  const directApi = report.cases.find((item) => item.case_id === 'direct_api_write_without_receipt_refused_before_service_mutation');
  const lines = [
    'ZLAR Protected Records Downstream Service Proof v1',
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Evidence model: ${report.evidence_model}; live probing=${report.live_probing}`,
    `Profile: id=${report.service_profile.profile_id}; action_class=${report.service_profile.action_class}; service_command=${report.service_profile.service_command}; process_boundary=${report.service_profile.service_process_boundary}; route=${report.service_profile.mutation_authoritative_route}`,
    `Recognized service write: accepted=${accepted.service_write_accepted}; reason=${accepted.reason_code}; state_delta=${accepted.state_entry_count_delta}; process=${accepted.process_invocation}`,
    `Replay after service restart: accepted=${replay.service_write_accepted}; reason=${replay.reason_code}; state_delta=${replay.state_entry_count_delta}; separate_process=${replay.separate_process_from_accepted}`,
    `Missing receipt: accepted=${missing.service_write_accepted}; reason=${missing.reason_code}; state_delta=${missing.state_entry_count_delta}`,
    `Unrecognized receipt: accepted=${unrecognized.service_write_accepted}; reason=${unrecognized.reason_code}; state_delta=${unrecognized.state_entry_count_delta}`,
    `Invalid receipt: accepted=${invalid.service_write_accepted}; reason=${invalid.reason_code}; state_delta=${invalid.state_entry_count_delta}`,
    `Unknown issuer: accepted=${unknownIssuer.service_write_accepted}; reason=${unknownIssuer.reason_code}; state_delta=${unknownIssuer.state_entry_count_delta}`,
    `Stale receipt: accepted=${stale.service_write_accepted}; reason=${stale.reason_code}; state_delta=${stale.state_entry_count_delta}`,
    `Fixture service API write without receipt: accepted=${directApi.service_write_accepted}; reason=${directApi.reason_code}; state_delta=${directApi.state_entry_count_delta}; direct_api_attempted=${directApi.direct_api_attempted}`,
    `Side-door report: direct_api_without_receipt_refused=${report.side_door_report.direct_api_without_receipt_refused}; direct_filesystem_write_to_fixture_paths_closed=${report.side_door_report.direct_filesystem_write_to_fixture_paths_closed}; live_records_service=${report.side_door_report.live_records_service}`,
    `Known open boundaries: ${report.known_open_boundaries.join(',')}`,
    'Non-claims:',
  ];
  for (const claim of report.non_claims) {
    lines.push(`- ${claim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsServiceProofText(summary);
  return summary;
}
