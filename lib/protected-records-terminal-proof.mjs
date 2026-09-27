import {
  PROTECTED_RECORDS_ADAPTER_TYPE,
  PROTECTED_RECORDS_WRITE_RESULT_TYPE,
} from './protected-records-adapter-verification.mjs';

export const PROTECTED_RECORDS_TERMINAL_PROOF_TYPE = 'protected-records-terminal-proof-v1';
export const PROTECTED_RECORDS_ADAPTER_PROFILE_TYPE = 'protected-records-adapter-profile-v1';

export const SAFE_CLAIM_CEILING =
  'ZLAR can demonstrate, in a local hermetic protected-records fixture, that a downstream records terminal writes only after a supplied signed receipt is recognized by the configured rule and refuses unrecognized or replayed writes before the record state changes.';

export const NON_CLAIMS = Object.freeze([
  'This proof does not inspect a live records system.',
  'This proof does not prove production deployment.',
  'This proof does not prove external attestation or sovereign recognition.',
  'This proof does not prove coverage of unrouted paths.',
]);

export const REQUIRED_REFUSAL_REASONS = Object.freeze([
  'receipt_missing',
  'unknown_issuer',
  'issuer_not_active',
  'receipt_invalid',
  'receipt_stale',
  'policy_not_recognized',
  'domain_out_of_scope',
  'tool_out_of_scope',
  'detail_hash_mismatch',
  'outcome_not_boarding',
  'receipt_replay',
]);

export const PROTECTED_RECORDS_PROFILE_CONTRACT = Object.freeze({
  profile_id: 'protected-records-terminal',
  action_class: 'records.write',
  checkpoint: 'downstream-recognition-rule',
  route: 'receipt-recognition-before-record-write',
  downstream_boundary: 'protected-records-terminal-fixture',
  downstream_effect: 'append-protected-records-ledger-entry',
  receipt_replay_policy: 'single-use-receipt-id-per-terminal-ledger',
  required_receipt_fields: Object.freeze([
    'v',
    'id',
    'kid',
    'iat',
    'type',
    'payload',
    'sig',
    'payload.audit_event_id',
    'payload.ts',
    'payload.domain',
    'payload.tool',
    'payload.outcome',
    'payload.policy_version',
    'payload.detail_hash',
  ]),
  accepted_issuer_statuses: Object.freeze(['active']),
  accepted_policy_versions: Object.freeze(['recognition-policy-v1']),
  accepted_domains: Object.freeze(['records']),
  accepted_tools: Object.freeze(['records.write']),
  accepted_outcomes: Object.freeze(['allow', 'authorized']),
  refusal_reasons: REQUIRED_REFUSAL_REASONS,
  known_ungoverned_boundaries: Object.freeze([
    'live_records_system',
    'production_records_adapter',
    'unrouted_records_paths',
  ]),
});

export const PROTECTED_RECORDS_ADAPTER_PROFILE = Object.freeze({
  profile_type: PROTECTED_RECORDS_ADAPTER_PROFILE_TYPE,
  profile_id: 'protected-records-adapter-profile',
  basis_profile_contract_id: PROTECTED_RECORDS_PROFILE_CONTRACT.profile_id,
  deployment_profile: PROTECTED_RECORDS_PROFILE_CONTRACT.profile_id,
  environment_model: 'local-hermetic-adapter-harness',
  action_class: PROTECTED_RECORDS_PROFILE_CONTRACT.action_class,
  authoritative_route: 'receipt-recognition-before-ledger-append',
  recognition_boundary: PROTECTED_RECORDS_PROFILE_CONTRACT.checkpoint,
  adapter_boundary: 'protected-records-adapter-harness',
  ledger_model: 'append-only-jsonl-ledger',
  consumed_receipt_store: 'single-use-receipt-id-store',
  replay_scope: 'per-adapter-ledger',
  downstream_effect: PROTECTED_RECORDS_PROFILE_CONTRACT.downstream_effect,
  accepted_receipt_outcomes: PROTECTED_RECORDS_PROFILE_CONTRACT.accepted_outcomes,
  refusal_before_effect: true,
  closed_in_fixture: Object.freeze([
    'direct_fixture_ledger_mutation',
    'adapter_bypass_write',
  ]),
  known_open_boundaries: PROTECTED_RECORDS_PROFILE_CONTRACT.known_ungoverned_boundaries,
  non_claims: Object.freeze([
    'This adapter profile is a local hermetic fixture profile.',
    'This adapter profile does not prove a live records-system adapter or production deployment.',
    'This adapter profile does not prove that unrouted records paths are closed outside the fixture.',
  ]),
});

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

function assertArrayEquals(label, expected, actual) {
  if (!Array.isArray(actual)) {
    throw new Error(`${label} must be an array`);
  }
  if (actual.length !== expected.length || actual.some((item, index) => item !== expected[index])) {
    throw new Error(`${label} drifted`);
  }
  return true;
}

export function assertProtectedRecordsProfileContract(contract) {
  assertExactKeys('Protected records profile contract', contract, [
    'accepted_domains',
    'accepted_issuer_statuses',
    'accepted_outcomes',
    'accepted_policy_versions',
    'accepted_tools',
    'action_class',
    'checkpoint',
    'downstream_boundary',
    'downstream_effect',
    'known_ungoverned_boundaries',
    'profile_id',
    'refusal_reasons',
    'receipt_replay_policy',
    'required_receipt_fields',
    'route',
  ]);
  if (contract.profile_id !== PROTECTED_RECORDS_PROFILE_CONTRACT.profile_id) {
    throw new Error('Protected records profile contract id drifted');
  }
  if (contract.action_class !== PROTECTED_RECORDS_PROFILE_CONTRACT.action_class) {
    throw new Error('Protected records profile contract action class drifted');
  }
  if (contract.checkpoint !== PROTECTED_RECORDS_PROFILE_CONTRACT.checkpoint) {
    throw new Error('Protected records profile contract checkpoint drifted');
  }
  if (contract.route !== PROTECTED_RECORDS_PROFILE_CONTRACT.route) {
    throw new Error('Protected records profile contract route drifted');
  }
  if (contract.downstream_boundary !== PROTECTED_RECORDS_PROFILE_CONTRACT.downstream_boundary) {
    throw new Error('Protected records profile contract downstream boundary drifted');
  }
  if (contract.downstream_effect !== PROTECTED_RECORDS_PROFILE_CONTRACT.downstream_effect) {
    throw new Error('Protected records profile contract downstream effect drifted');
  }
  if (contract.receipt_replay_policy !== PROTECTED_RECORDS_PROFILE_CONTRACT.receipt_replay_policy) {
    throw new Error('Protected records profile contract replay policy drifted');
  }
  assertArrayEquals(
    'Protected records profile contract required receipt fields',
    PROTECTED_RECORDS_PROFILE_CONTRACT.required_receipt_fields,
    contract.required_receipt_fields
  );
  assertArrayEquals(
    'Protected records profile contract accepted issuer statuses',
    PROTECTED_RECORDS_PROFILE_CONTRACT.accepted_issuer_statuses,
    contract.accepted_issuer_statuses
  );
  assertArrayEquals(
    'Protected records profile contract accepted policy versions',
    PROTECTED_RECORDS_PROFILE_CONTRACT.accepted_policy_versions,
    contract.accepted_policy_versions
  );
  assertArrayEquals(
    'Protected records profile contract accepted domains',
    PROTECTED_RECORDS_PROFILE_CONTRACT.accepted_domains,
    contract.accepted_domains
  );
  assertArrayEquals(
    'Protected records profile contract accepted tools',
    PROTECTED_RECORDS_PROFILE_CONTRACT.accepted_tools,
    contract.accepted_tools
  );
  assertArrayEquals(
    'Protected records profile contract accepted outcomes',
    PROTECTED_RECORDS_PROFILE_CONTRACT.accepted_outcomes,
    contract.accepted_outcomes
  );
  assertArrayEquals(
    'Protected records profile contract refusal reasons',
    REQUIRED_REFUSAL_REASONS,
    contract.refusal_reasons
  );
  assertArrayEquals(
    'Protected records profile contract known ungoverned boundaries',
    PROTECTED_RECORDS_PROFILE_CONTRACT.known_ungoverned_boundaries,
    contract.known_ungoverned_boundaries
  );
  return true;
}

export function assertProtectedRecordsAdapterProfile(profile) {
  assertExactKeys('Protected records adapter profile', profile, [
    'accepted_receipt_outcomes',
    'action_class',
    'adapter_boundary',
    'authoritative_route',
    'basis_profile_contract_id',
    'closed_in_fixture',
    'consumed_receipt_store',
    'deployment_profile',
    'downstream_effect',
    'environment_model',
    'known_open_boundaries',
    'ledger_model',
    'non_claims',
    'profile_id',
    'profile_type',
    'recognition_boundary',
    'refusal_before_effect',
    'replay_scope',
  ]);
  if (profile.profile_type !== PROTECTED_RECORDS_ADAPTER_PROFILE.profile_type) {
    throw new Error('Protected records adapter profile type drifted');
  }
  if (profile.profile_id !== PROTECTED_RECORDS_ADAPTER_PROFILE.profile_id) {
    throw new Error('Protected records adapter profile id drifted');
  }
  if (profile.basis_profile_contract_id !== PROTECTED_RECORDS_ADAPTER_PROFILE.basis_profile_contract_id) {
    throw new Error('Protected records adapter profile basis contract drifted');
  }
  if (profile.deployment_profile !== PROTECTED_RECORDS_ADAPTER_PROFILE.deployment_profile) {
    throw new Error('Protected records adapter profile deployment profile drifted');
  }
  if (profile.environment_model !== PROTECTED_RECORDS_ADAPTER_PROFILE.environment_model) {
    throw new Error('Protected records adapter profile environment model drifted');
  }
  if (profile.action_class !== PROTECTED_RECORDS_ADAPTER_PROFILE.action_class) {
    throw new Error('Protected records adapter profile action class drifted');
  }
  if (profile.authoritative_route !== PROTECTED_RECORDS_ADAPTER_PROFILE.authoritative_route) {
    throw new Error('Protected records adapter profile authoritative route drifted');
  }
  if (profile.recognition_boundary !== PROTECTED_RECORDS_ADAPTER_PROFILE.recognition_boundary) {
    throw new Error('Protected records adapter profile recognition boundary drifted');
  }
  if (profile.adapter_boundary !== PROTECTED_RECORDS_ADAPTER_PROFILE.adapter_boundary) {
    throw new Error('Protected records adapter profile adapter boundary drifted');
  }
  if (profile.ledger_model !== PROTECTED_RECORDS_ADAPTER_PROFILE.ledger_model) {
    throw new Error('Protected records adapter profile ledger model drifted');
  }
  if (profile.consumed_receipt_store !== PROTECTED_RECORDS_ADAPTER_PROFILE.consumed_receipt_store) {
    throw new Error('Protected records adapter profile consumed receipt store drifted');
  }
  if (profile.replay_scope !== PROTECTED_RECORDS_ADAPTER_PROFILE.replay_scope) {
    throw new Error('Protected records adapter profile replay scope drifted');
  }
  if (profile.downstream_effect !== PROTECTED_RECORDS_ADAPTER_PROFILE.downstream_effect) {
    throw new Error('Protected records adapter profile downstream effect drifted');
  }
  if (profile.refusal_before_effect !== true) {
    throw new Error('Protected records adapter profile must refuse before effect');
  }
  assertArrayEquals(
    'Protected records adapter profile accepted receipt outcomes',
    PROTECTED_RECORDS_ADAPTER_PROFILE.accepted_receipt_outcomes,
    profile.accepted_receipt_outcomes
  );
  assertArrayEquals(
    'Protected records adapter profile closed fixture routes',
    PROTECTED_RECORDS_ADAPTER_PROFILE.closed_in_fixture,
    profile.closed_in_fixture
  );
  assertArrayEquals(
    'Protected records adapter profile known open boundaries',
    PROTECTED_RECORDS_ADAPTER_PROFILE.known_open_boundaries,
    profile.known_open_boundaries
  );
  assertArrayEquals(
    'Protected records adapter profile non-claims',
    PROTECTED_RECORDS_ADAPTER_PROFILE.non_claims,
    profile.non_claims
  );
  return true;
}

function assertProtectedRecordsAdapterHarness(harness) {
  assertExactKeys('Protected records adapter harness', harness, [
    'adapter_boundary',
    'all_mutations_through_recognition_boundary',
    'consumed_receipt_count',
    'consumed_receipt_store',
    'direct_write_path_available',
    'environment_model',
    'final_ledger_entry_count',
    'harness_type',
    'ledger_model',
    'live_records_adapter',
    'recognition_boundary',
    'refusal_before_effect',
    'replay_scope',
  ]);
  if (harness.harness_type !== 'protected-records-adapter-harness-v1') {
    throw new Error('Protected records adapter harness type drifted');
  }
  if (harness.environment_model !== 'local-hermetic-fixture') {
    throw new Error('Protected records adapter harness must be a local hermetic fixture');
  }
  if (harness.recognition_boundary !== PROTECTED_RECORDS_ADAPTER_PROFILE.recognition_boundary) {
    throw new Error('Protected records adapter harness recognition boundary drifted');
  }
  if (harness.adapter_boundary !== PROTECTED_RECORDS_ADAPTER_PROFILE.adapter_boundary) {
    throw new Error('Protected records adapter harness adapter boundary drifted');
  }
  if (harness.ledger_model !== PROTECTED_RECORDS_ADAPTER_PROFILE.ledger_model) {
    throw new Error('Protected records adapter harness ledger model drifted');
  }
  if (harness.consumed_receipt_store !== PROTECTED_RECORDS_ADAPTER_PROFILE.consumed_receipt_store) {
    throw new Error('Protected records adapter harness consumed receipt store drifted');
  }
  if (harness.replay_scope !== PROTECTED_RECORDS_ADAPTER_PROFILE.replay_scope) {
    throw new Error('Protected records adapter harness replay scope drifted');
  }
  if (harness.direct_write_path_available !== false) {
    throw new Error('Protected records adapter harness direct write path must be closed in the fixture');
  }
  if (harness.live_records_adapter !== false) {
    throw new Error('Protected records adapter harness must not claim a live records adapter');
  }
  if (harness.all_mutations_through_recognition_boundary !== true) {
    throw new Error('Protected records adapter harness must route all mutations through recognition');
  }
  if (harness.refusal_before_effect !== true) {
    throw new Error('Protected records adapter harness must refuse before effect');
  }
  if (harness.final_ledger_entry_count !== 1 || harness.consumed_receipt_count !== 1) {
    throw new Error('Protected records adapter harness must end with one ledger entry and one consumed receipt');
  }
  return true;
}

function assertProtectedRecordsAdapterAction(action) {
  assertExactKeys('Protected records adapter action', action, [
    'action_type',
    'command',
    'fixture_mode_required',
    'input_model',
    'live_records_adapter',
    'raw_record_detail_output',
    'result_type',
    'writes',
  ]);
  if (action.action_type !== PROTECTED_RECORDS_ADAPTER_TYPE) {
    throw new Error('Protected records adapter action type drifted');
  }
  if (action.command !== 'zlar protected-records-write --input <file|->') {
    throw new Error('Protected records adapter action command drifted');
  }
  if (action.input_model !== 'supplied-json-fixture') {
    throw new Error('Protected records adapter action input model drifted');
  }
  if (action.result_type !== PROTECTED_RECORDS_WRITE_RESULT_TYPE) {
    throw new Error('Protected records adapter action result type drifted');
  }
  if (action.fixture_mode_required !== true) {
    throw new Error('Protected records adapter action must require fixture mode');
  }
  if (action.writes !== 'bounded-jsonl-ledger-entry') {
    throw new Error('Protected records adapter action write model drifted');
  }
  if (action.live_records_adapter !== false) {
    throw new Error('Protected records adapter action must not claim a live records adapter');
  }
  if (action.raw_record_detail_output !== false) {
    throw new Error('Protected records adapter action must not output raw record detail');
  }
  return true;
}

export const PROTECTED_RECORDS_TERMINAL_PROOF_GENERATION_RETIREMENT_REASON =
  'e1_positive_terminal_proof_generation_retired';

export function runProtectedRecordsTerminalProof() {
  throw new Error(PROTECTED_RECORDS_TERMINAL_PROOF_GENERATION_RETIREMENT_REASON);
}

export function assertProtectedRecordsTerminalProof(report) {
  if (!report || report.proof_type !== PROTECTED_RECORDS_TERMINAL_PROOF_TYPE) {
    throw new Error('Protected records terminal proof has the wrong proof type');
  }
  if (report.evidence_model !== 'local-hermetic-fixture') {
    throw new Error('Protected records terminal proof must be local hermetic fixture evidence');
  }
  if (report.live_probing !== false) {
    throw new Error('Protected records terminal proof must not perform live probing');
  }
  if (report.deployment_profile !== 'protected-records-terminal') {
    throw new Error('Protected records terminal proof has the wrong deployment profile');
  }
  assertProtectedRecordsProfileContract(report.profile_contract);
  assertProtectedRecordsAdapterProfile(report.adapter_profile);
  assertProtectedRecordsAdapterHarness(report.adapter_harness);
  assertProtectedRecordsAdapterAction(report.adapter_action);
  if (
    report.profile_contract.profile_id !== report.deployment_profile ||
    report.profile_contract.action_class !== report.action_class ||
    report.profile_contract.downstream_boundary !== report.downstream_boundary
  ) {
    throw new Error('Protected records terminal proof does not match its profile contract');
  }
  if (
    report.adapter_profile.basis_profile_contract_id !== report.profile_contract.profile_id ||
    report.adapter_profile.deployment_profile !== report.deployment_profile ||
    report.adapter_profile.action_class !== report.action_class ||
    report.adapter_profile.downstream_effect !== report.profile_contract.downstream_effect
  ) {
    throw new Error('Protected records terminal proof does not match its adapter profile');
  }
  const recognized = report.recognized_write || {};
  if (
    recognized.case_id !== 'recognized_write' ||
    recognized.write_accepted !== true ||
    recognized.record_changed !== true ||
    recognized.decision !== 'accept' ||
    recognized.reason_code !== 'recognized' ||
    recognized.record_count_delta !== 1
  ) {
    throw new Error('Recognized records receipt did not change the protected record exactly once');
  }
  const refusals = Array.isArray(report.refusals) ? report.refusals : [];
  const reasons = new Set(refusals.map((item) => item.reason_code));
  for (const reason of REQUIRED_REFUSAL_REASONS) {
    if (!reasons.has(reason)) {
      throw new Error(`Missing required protected-records refusal reason: ${reason}`);
    }
  }
  for (const refusal of refusals) {
    if (
      refusal.write_accepted !== false ||
      refusal.record_changed !== false ||
      refusal.decision !== 'refuse' ||
      refusal.record_count_delta !== 0
    ) {
      throw new Error(`Protected records refusal case changed the record unexpectedly: ${refusal.case_id || 'unknown'}`);
    }
  }
  if (report.terminal?.final_record_count !== 1) {
    throw new Error('Protected records terminal proof must end with exactly one record write');
  }
  if (report.adapter_harness.final_ledger_entry_count !== report.terminal.final_record_count) {
    throw new Error('Protected records adapter harness ledger count does not match terminal count');
  }
  if (report.terminal?.receipt_id_present !== true) {
    throw new Error('Protected records terminal proof must retain bounded receipt linkage');
  }
  if (report.terminal?.raw_record_id_present !== false) {
    throw new Error('Protected records terminal proof leaked raw record id');
  }
  if (report.terminal?.public_key_present !== false) {
    throw new Error('Protected records terminal proof leaked public key material');
  }
  if (report.terminal?.private_key_present !== false) {
    throw new Error('Protected records terminal proof leaked private key material');
  }
  assertNoUnsafeProtectedRecordsProofText(JSON.stringify(report));
  return true;
}

export function assertNoUnsafeProtectedRecordsProofText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_OUTPUT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`protected records proof output contains ${label}`);
    }
  }
  return true;
}

export function formatProtectedRecordsTerminalProofSummary(report) {
  const lines = [
    'Protected Records Terminal Proof v1',
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Evidence model: ${report.evidence_model}; live probing=${report.live_probing}`,
    `Deployment profile: ${report.deployment_profile}`,
    `Action class: ${report.action_class}`,
    `Downstream boundary: ${report.downstream_boundary}`,
    `Profile contract: checkpoint=${report.profile_contract.checkpoint}; route=${report.profile_contract.route}; downstream_effect=${report.profile_contract.downstream_effect}`,
    `Adapter profile: type=${report.adapter_profile.profile_type}; id=${report.adapter_profile.profile_id}; authoritative_route=${report.adapter_profile.authoritative_route}; adapter_boundary=${report.adapter_profile.adapter_boundary}`,
    `Adapter harness: ledger_model=${report.adapter_harness.ledger_model}; consumed_receipt_store=${report.adapter_harness.consumed_receipt_store}; replay_scope=${report.adapter_harness.replay_scope}; final_ledger_entry_count=${report.adapter_harness.final_ledger_entry_count}; consumed_receipt_count=${report.adapter_harness.consumed_receipt_count}; direct_write_path_available=${report.adapter_harness.direct_write_path_available}; live_records_adapter=${report.adapter_harness.live_records_adapter}`,
    `Adapter action: command=${report.adapter_action.command}; result_type=${report.adapter_action.result_type}; fixture_mode_required=${report.adapter_action.fixture_mode_required}; live_records_adapter=${report.adapter_action.live_records_adapter}`,
    `Replay policy: ${report.profile_contract.receipt_replay_policy}`,
    `Required receipt fields: ${report.profile_contract.required_receipt_fields.join(',')}`,
    `Known ungoverned boundaries: ${report.profile_contract.known_ungoverned_boundaries.join(',')}`,
    'Record write:',
    `- ${report.recognized_write.case_id}: ${report.recognized_write.decision}; record_delta=${report.recognized_write.record_count_delta}`,
    'Refused before record change:',
  ];
  for (const refusal of report.refusals) {
    lines.push(`- ${refusal.case_id}: ${refusal.reason_code}; record_delta=${refusal.record_count_delta}`);
  }
  lines.push(
    `Terminal: final_record_count=${report.terminal.final_record_count}; receipt_id_present=${report.terminal.receipt_id_present}; raw_record_id_present=${report.terminal.raw_record_id_present}; public_key_present=${report.terminal.public_key_present}; private_key_present=${report.terminal.private_key_present}`,
    'Non-claims:'
  );
  for (const nonClaim of report.non_claims) {
    lines.push(`- ${nonClaim}`);
  }
  return `${lines.join('\n')}\n`;
}
