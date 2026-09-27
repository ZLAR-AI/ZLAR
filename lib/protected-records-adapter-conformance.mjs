import {
  PROTECTED_RECORDS_ADAPTER_TYPE,
  PROTECTED_RECORDS_WRITE_RESULT_TYPE,
} from './protected-records-adapter-verification.mjs';

export const PROTECTED_RECORDS_ADAPTER_CONFORMANCE_PROOF_TYPE =
  'protected-records-adapter-conformance-proof-v1';

export const REQUIRED_CONFORMANCE_CASES = Object.freeze([
  'recognized_write_first_process',
  'replay_refused_after_process_restart',
  'missing_receipt_refused_before_append',
  'unsupported_direct_write_option_refused',
]);

export const SAFE_CLAIM_CEILING =
  'ZLAR can run a local disposable CLI-process conformance proof for the protected-records write adapter, showing recognized writes append once, replay refuses across a fresh process, missing receipts refuse before append, and unsupported direct-write adapter options do not append.';

export const NON_CLAIMS = Object.freeze([
  'This proof is local disposable CLI-process conformance evidence.',
  'This proof does not inspect a live records system.',
  'This proof does not prove production records adapter deployment.',
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

export const PROTECTED_RECORDS_ADAPTER_CONFORMANCE_GENERATION_RETIREMENT_REASON =
  'e1_positive_adapter_conformance_generation_retired';

export function runProtectedRecordsAdapterConformanceProof() {
  throw new Error(
    PROTECTED_RECORDS_ADAPTER_CONFORMANCE_GENERATION_RETIREMENT_REASON,
  );
}

export function assertProtectedRecordsAdapterConformanceProof(report) {
  assertExactKeys('Protected records adapter conformance proof', report, [
    'cases',
    'conformance_profile',
    'evidence_model',
    'known_open_boundaries',
    'live_probing',
    'non_claims',
    'proof_type',
    'safe_claim_ceiling',
    'side_door_report',
  ]);
  if (report.proof_type !== PROTECTED_RECORDS_ADAPTER_CONFORMANCE_PROOF_TYPE) {
    throw new Error('Protected records adapter conformance proof type drifted');
  }
  if (report.evidence_model !== 'local-disposable-cli-process-fixture') {
    throw new Error('Protected records adapter conformance proof evidence model drifted');
  }
  if (report.live_probing !== false) {
    throw new Error('Protected records adapter conformance proof must not perform live probing');
  }
  if (report.safe_claim_ceiling !== SAFE_CLAIM_CEILING) {
    throw new Error('Protected records adapter conformance proof safe claim ceiling drifted');
  }

  assertExactKeys('Protected records adapter conformance profile', report.conformance_profile, [
    'action_class',
    'adapter_command',
    'adapter_process_boundary',
    'adapter_type',
    'consumed_receipt_store',
    'fixture_mode_required',
    'input_model',
    'ledger_model',
    'mutation_authoritative_route',
    'profile_id',
    'replay_scope',
    'result_type',
  ]);
  const profile = report.conformance_profile;
  if (
    profile.profile_id !== 'protected-records-cli-process-conformance' ||
    profile.action_class !== 'records.write' ||
    profile.adapter_type !== PROTECTED_RECORDS_ADAPTER_TYPE ||
    profile.adapter_command !== 'zlar protected-records-write --input <file|->' ||
    profile.adapter_process_boundary !== 'separate-cli-process' ||
    profile.input_model !== 'supplied-json-fixture' ||
    profile.fixture_mode_required !== true ||
    profile.mutation_authoritative_route !== 'receipt-recognition-before-ledger-append' ||
    profile.result_type !== PROTECTED_RECORDS_WRITE_RESULT_TYPE ||
    profile.ledger_model !== 'bounded-jsonl-ledger-entry' ||
    profile.consumed_receipt_store !== 'persistent-single-use-receipt-id-store' ||
    profile.replay_scope !== 'per-adapter-consumed-receipt-store'
  ) {
    throw new Error('Protected records adapter conformance profile drifted');
  }

  assertExactKeys('Protected records adapter conformance side-door report', report.side_door_report, [
    'cli_direct_write_option_available',
    'direct_filesystem_write_to_fixture_paths_closed',
    'live_records_adapter',
    'live_records_system_checked',
    'production_records_adapter_checked',
    'unrouted_records_paths_checked',
  ]);
  if (
    report.side_door_report.cli_direct_write_option_available !== false ||
    report.side_door_report.direct_filesystem_write_to_fixture_paths_closed !== false ||
    report.side_door_report.live_records_system_checked !== false ||
    report.side_door_report.production_records_adapter_checked !== false ||
    report.side_door_report.unrouted_records_paths_checked !== false ||
    report.side_door_report.live_records_adapter !== false
  ) {
    throw new Error('Protected records adapter conformance side-door report drifted');
  }

  if (!Array.isArray(report.cases) || report.cases.length !== REQUIRED_CONFORMANCE_CASES.length) {
    throw new Error('Protected records adapter conformance proof case count drifted');
  }
  for (const caseId of REQUIRED_CONFORMANCE_CASES) {
    if (!report.cases.some((item) => item.case_id === caseId)) {
      throw new Error(`Protected records adapter conformance proof missing case: ${caseId}`);
    }
  }
  for (const item of report.cases) {
    assertExactKeys('Protected records adapter conformance case', item, [
      'case_id',
      'command',
      'consumed_receipt_count',
      'consumed_store_exists_after',
      'exit_status',
      'ledger_entry_count_after',
      'ledger_entry_count_before',
      'ledger_entry_count_delta',
      'process_boundary',
      'process_invocation',
      'reason_code',
      'separate_process_from_accepted',
      'side_door_attempted',
      'stderr_empty',
      'stdout_json_emitted',
      'write_accepted',
    ]);
    if (item.process_boundary !== 'separate-cli-process') {
      throw new Error('Protected records adapter conformance case process boundary drifted');
    }
    if (item.ledger_entry_count_delta !== item.ledger_entry_count_after - item.ledger_entry_count_before) {
      throw new Error('Protected records adapter conformance case ledger delta drifted');
    }
  }

  const accepted = report.cases.find((item) => item.case_id === 'recognized_write_first_process');
  if (
    accepted.command !== 'zlar protected-records-write --input <file|-> --require-written' ||
    accepted.process_invocation !== 1 ||
    accepted.separate_process_from_accepted !== false ||
    accepted.exit_status !== 0 ||
    accepted.stdout_json_emitted !== true ||
    accepted.stderr_empty !== true ||
    accepted.write_accepted !== true ||
    accepted.reason_code !== 'recognized' ||
    accepted.ledger_entry_count_before !== 0 ||
    accepted.ledger_entry_count_after !== 1 ||
    accepted.ledger_entry_count_delta !== 1 ||
    accepted.consumed_receipt_count !== 1 ||
    accepted.consumed_store_exists_after !== true ||
    accepted.side_door_attempted !== false
  ) {
    throw new Error('Protected records adapter conformance accepted case failed');
  }

  const replay = report.cases.find((item) => item.case_id === 'replay_refused_after_process_restart');
  if (
    replay.process_invocation !== 2 ||
    replay.separate_process_from_accepted !== true ||
    replay.exit_status !== 0 ||
    replay.stdout_json_emitted !== true ||
    replay.stderr_empty !== true ||
    replay.write_accepted !== false ||
    replay.reason_code !== 'receipt_replay' ||
    replay.ledger_entry_count_before !== 1 ||
    replay.ledger_entry_count_after !== 1 ||
    replay.ledger_entry_count_delta !== 0 ||
    replay.consumed_receipt_count !== 1 ||
    replay.consumed_store_exists_after !== true ||
    replay.side_door_attempted !== false
  ) {
    throw new Error('Protected records adapter conformance replay case failed');
  }

  const missing = report.cases.find((item) => item.case_id === 'missing_receipt_refused_before_append');
  if (
    missing.process_invocation !== 3 ||
    missing.exit_status !== 0 ||
    missing.stdout_json_emitted !== true ||
    missing.stderr_empty !== true ||
    missing.write_accepted !== false ||
    missing.reason_code !== 'receipt_missing' ||
    missing.ledger_entry_count_before !== 0 ||
    missing.ledger_entry_count_after !== 0 ||
    missing.ledger_entry_count_delta !== 0 ||
    missing.consumed_receipt_count !== 0 ||
    missing.side_door_attempted !== false
  ) {
    throw new Error('Protected records adapter conformance missing-receipt case failed');
  }

  const sideDoor = report.cases.find((item) => item.case_id === 'unsupported_direct_write_option_refused');
  if (
    sideDoor.command !== 'zlar protected-records-write --input <file|-> --direct-write' ||
    sideDoor.process_invocation !== 4 ||
    sideDoor.separate_process_from_accepted !== true ||
    sideDoor.exit_status === 0 ||
    sideDoor.stdout_json_emitted !== false ||
    sideDoor.stderr_empty !== false ||
    sideDoor.write_accepted !== false ||
    sideDoor.reason_code !== 'unsupported_option' ||
    sideDoor.ledger_entry_count_before !== 1 ||
    sideDoor.ledger_entry_count_after !== 1 ||
    sideDoor.ledger_entry_count_delta !== 0 ||
    sideDoor.consumed_receipt_count !== null ||
    sideDoor.consumed_store_exists_after !== true ||
    sideDoor.side_door_attempted !== true
  ) {
    throw new Error('Protected records adapter conformance side-door case failed');
  }

  const requiredOpenBoundaries = [
    'direct_filesystem_write_to_supplied_fixture_paths',
    'live_records_system',
    'production_records_adapter',
    'unrouted_records_paths',
  ];
  if (!Array.isArray(report.known_open_boundaries) || report.known_open_boundaries.length !== requiredOpenBoundaries.length) {
    throw new Error('Protected records adapter conformance open boundary list drifted');
  }
  for (const boundary of requiredOpenBoundaries) {
    if (!report.known_open_boundaries.includes(boundary)) {
      throw new Error(`Protected records adapter conformance missing open boundary: ${boundary}`);
    }
  }

  if (!Array.isArray(report.non_claims) || report.non_claims.length !== NON_CLAIMS.length) {
    throw new Error('Protected records adapter conformance non-claims drifted');
  }
  for (const claim of NON_CLAIMS) {
    if (!report.non_claims.includes(claim)) {
      throw new Error('Protected records adapter conformance missing non-claim');
    }
  }
  assertNoUnsafeProtectedRecordsAdapterConformanceText(JSON.stringify(report));
  return true;
}

export function assertNoUnsafeProtectedRecordsAdapterConformanceText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_OUTPUT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`protected records adapter conformance output contains ${label}`);
    }
  }
  return true;
}

export function formatProtectedRecordsAdapterConformanceSummary(report) {
  assertProtectedRecordsAdapterConformanceProof(report);
  const accepted = report.cases.find((item) => item.case_id === 'recognized_write_first_process');
  const replay = report.cases.find((item) => item.case_id === 'replay_refused_after_process_restart');
  const missing = report.cases.find((item) => item.case_id === 'missing_receipt_refused_before_append');
  const sideDoor = report.cases.find((item) => item.case_id === 'unsupported_direct_write_option_refused');
  const lines = [
    'ZLAR Protected Records Adapter Conformance Proof v1',
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Evidence model: ${report.evidence_model}; live probing=${report.live_probing}`,
    `Profile: id=${report.conformance_profile.profile_id}; action_class=${report.conformance_profile.action_class}; adapter_command=${report.conformance_profile.adapter_command}; process_boundary=${report.conformance_profile.adapter_process_boundary}; route=${report.conformance_profile.mutation_authoritative_route}`,
    `Recognized write: accepted=${accepted.write_accepted}; reason=${accepted.reason_code}; ledger_delta=${accepted.ledger_entry_count_delta}; process=${accepted.process_invocation}`,
    `Replay after process restart: accepted=${replay.write_accepted}; reason=${replay.reason_code}; ledger_delta=${replay.ledger_entry_count_delta}; separate_process=${replay.separate_process_from_accepted}`,
    `Missing receipt: accepted=${missing.write_accepted}; reason=${missing.reason_code}; ledger_delta=${missing.ledger_entry_count_delta}`,
    `Unsupported direct-write option: accepted=${sideDoor.write_accepted}; reason=${sideDoor.reason_code}; ledger_delta=${sideDoor.ledger_entry_count_delta}; side_door_attempted=${sideDoor.side_door_attempted}`,
    `Side-door report: cli_direct_write_option_available=${report.side_door_report.cli_direct_write_option_available}; direct_filesystem_write_to_fixture_paths_closed=${report.side_door_report.direct_filesystem_write_to_fixture_paths_closed}; live_records_adapter=${report.side_door_report.live_records_adapter}`,
    `Known open boundaries: ${report.known_open_boundaries.join(',')}`,
    'Non-claims:',
  ];
  for (const claim of report.non_claims) {
    lines.push(`- ${claim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsAdapterConformanceText(summary);
  return summary;
}
