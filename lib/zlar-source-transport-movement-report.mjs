import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanUnsafeTokenLifecycleText } from './zlar-github-app-token-lifecycle-wrapper.mjs';
import { runSourceTransportPreflight } from './zlar-source-transport-preflight.mjs';

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(MODULE_DIR, '..');
export const BUILD_ROOT = process.env.ZLAR_BUILD_ROOT || resolve(PROJECT_ROOT, '..', 'ZLAR-Draft', 'build');
export const MOVEMENT_REPORT_TYPE = 'zlar-github-app-source-movement-proof-v1';
export const MOVEMENT_REVIEW_TYPE = 'zlar-source-transport-movement-report-review-v1';
export const MOCK_CONTRACT_MODE = 'no_secret_mock';
export const LIVE_CONTRACT_MODE = 'live_shaped_redacted';
export const SOURCE_MOVEMENT_MECHANISM =
  'lease_gated_fast_forward_git_transport_with_github_app_installation_token';
export const SELECTED_REPO = 'ZLAR-AI/ZLAR';
export const REQUESTED_REF = 'refs/heads/local-governed-destination-boarding-proof';
export const LOCAL_BRANCH = 'local-governed-destination-boarding-proof';
export const LOCAL_SOURCE_COMMIT = '5194e4478262d87fba3ec8fc0fac8be2d5092f09';
export const LOCAL_REMOTE_TRACKING_REF =
  'refs/remotes/origin/local-governed-destination-boarding-proof';
export const EXPECTED_OLD_REMOTE_SHA = '0da556b9763b0bf44eb175f67ee668316d507dce';
export const EXPECTED_NEW_REMOTE_SHA = LOCAL_SOURCE_COMMIT;
export const LOCAL_AHEAD_COUNT = 2;
export const LOCAL_BEHIND_COUNT = 0;
export const EXPECTED_DIFF_FILES = Object.freeze([
  'bin/zlar',
  'bin/zlar-github-app-token-lifecycle',
  'bin/zlar-source-transport-preflight',
  'lib/zlar-github-app-token-lifecycle-wrapper.mjs',
  'lib/zlar-source-transport-preflight.mjs',
  'tests/test-github-app-token-lifecycle-wrapper.mjs',
  'tests/test-zlar-source-transport-preflight.mjs',
]);

const STRICT_SHA_RE = /^[0-9a-f]{40}$/;
const ISO_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const STATUS_CLASSES = new Set(['2xx', '3xx', '4xx', '5xx']);
const PERMISSIONS = Object.freeze(['contents', 'metadata']);
const REPORT_MODES = new Set([MOCK_CONTRACT_MODE, LIVE_CONTRACT_MODE]);
const MOVEMENT_STATUSES = new Set(['mocked', 'passed', 'failed', 'partial', 'anomaly']);
const FAILURE_STAGES = new Set([
  'none',
  'mock',
  'local_preflight',
  'credential_lifecycle',
  'pre_read',
  'git_transport_push',
  'post_read',
  'revocation',
  'report_redaction',
]);
const GIT_TRANSPORT_FAILURE_CLASSES = new Set([
  'none',
  'relay_construction_failed',
  'local_git_process_failed',
  'authentication_rejected',
  'lease_rejected',
  'remote_rejected',
  'network_failed',
  'unknown',
]);
const TOKEN_CLEANUP_PROOF_TYPES = new Set(['none', 'revocation_2xx', 'expiry_timestamp']);
const TOKEN_CLEANUP_ANOMALY_CLASSES = new Set([
  'none',
  'revocation_not_attempted',
  'revocation_non_2xx',
  'expiry_missing',
  'cleanup_unproven',
]);

export const SUCCESS_COUNTERS = Object.freeze({
  request_count: 6,
  token_lifecycle_request_count: 3,
  ref_read_count: 2,
  pre_ref_read_count: 1,
  post_ref_read_count: 1,
  ref_write_count: 1,
  git_transport_push_count: 1,
  rest_ref_update_count: 0,
  revocation_request_count: 1,
  credential_helper_count: 0,
});

const EXPIRY_CLEANUP_SUCCESS_COUNTERS = Object.freeze({
  ...SUCCESS_COUNTERS,
  request_count: 5,
  token_lifecycle_request_count: 2,
  revocation_request_count: 0,
});

const ZERO_COUNTERS = Object.freeze({
  request_count: 0,
  token_lifecycle_request_count: 0,
  ref_read_count: 0,
  pre_ref_read_count: 0,
  post_ref_read_count: 0,
  ref_write_count: 0,
  git_transport_push_count: 0,
  rest_ref_update_count: 0,
  revocation_request_count: 0,
  credential_helper_count: 0,
});

const COUNTER_KEYS = Object.keys(SUCCESS_COUNTERS);
const TOKEN_LIFECYCLE_REQUEST_CLASSES = ['installation_lookup', 'installation_token', 'revocation'];
const SOURCE_MOVEMENT_REQUEST_CLASSES = ['pre_ref_read', 'git_transport_push', 'post_ref_read'];

const ALLOWED_REPORT_KEYS = new Set([
  'report_type',
  'report_contract_mode',
  'mock_evidence_only',
  'modeled_source_movement',
  'modeled_remote_ref_write',
  'live_source_movement_attempted',
  'live_source_movement_authority_used',
  'selected_repo',
  'requested_ref',
  'local_branch',
  'local_source_commit',
  'local_worktree_clean',
  'local_remote_tracking_ref',
  'local_remote_tracking_sha',
  'local_ahead_count',
  'local_behind_count',
  'local_preflight_passed',
  'observed_local_branch',
  'observed_local_source_commit',
  'observed_local_remote_tracking_ref',
  'observed_local_remote_tracking_sha',
  'observed_local_ahead_count',
  'observed_local_behind_count',
  'expected_diff_files',
  'observed_diff_files',
  'request_started_at',
  'response_completed_at',
  'counter_taxonomy_version',
  'token_lifecycle_request_classes',
  'source_movement_request_classes',
  'pre_read_request_class',
  'git_transport_push_request_class',
  'post_read_request_class',
  'revocation_request_class',
  'credential_helper_counter_class',
  'rest_ref_update_counter_class',
  'request_count',
  'token_lifecycle_request_count',
  'ref_read_count',
  'pre_ref_read_count',
  'post_ref_read_count',
  'ref_write_count',
  'git_transport_push_count',
  'rest_ref_update_count',
  'revocation_request_count',
  'credential_helper_count',
  'private_key_read_inside_process_only',
  'jwt_minted',
  'installation_lookup_attempted',
  'installation_lookup_status_class',
  'installation_token_minted',
  'installation_token_status_class',
  'permission_names',
  'repository_selection',
  'pre_ref_read_attempted',
  'pre_ref_read_status_class',
  'pre_read_returned_ref',
  'pre_read_returned_object_type',
  'pre_read_returned_sha',
  'git_transport_push_attempted',
  'git_transport_push_result_class',
  'git_transport_failure_class',
  'post_ref_read_attempted',
  'post_ref_read_status_class',
  'post_read_returned_ref',
  'post_read_returned_object_type',
  'post_read_returned_sha',
  'source_movement',
  'remote_ref_write',
  'source_movement_mechanism',
  'expected_old_remote_sha',
  'expected_new_remote_sha',
  'old_sha_is_ancestor_of_new_sha',
  'force_push',
  'force_with_lease_used_as_old_sha_guard',
  'plus_refspec_used',
  'revocation_attempted',
  'revocation_status_class',
  'installation_token_expires_at',
  'installation_token_expiry_class',
  'token_cleanup_required',
  'token_cleanup_proven',
  'token_cleanup_proof_type',
  'token_cleanup_anomaly',
  'token_cleanup_anomaly_class',
  'movement_status',
  'failure_stage',
  'failure_reason_code',
  'git_fetch',
  'git_ls_remote',
  'actions_used',
  'tag_or_release_used',
  'website_touched',
  'deploy_key_policy_touched',
  'github_settings_touched',
  'production_issuer_path_used',
  'token_material_seen_by_report',
  'jwt_material_seen_by_report',
  'authorization_header_seen_by_report',
  'private_key_material_seen_by_report',
  'credentialed_url_seen_by_report',
  'raw_response_body_seen_by_report',
  'raw_error_seen_by_report',
  'raw_git_stdout_seen_by_report',
  'raw_git_stderr_seen_by_report',
  'env_values_seen_by_report',
  'shell_history_seen_by_report',
  'screenshot_seen_by_report',
  'token_stored',
  'token_output_redacted',
]);

const FORBIDDEN_TRUE_MARKERS = [
  'force_push',
  'plus_refspec_used',
  'git_fetch',
  'git_ls_remote',
  'actions_used',
  'tag_or_release_used',
  'website_touched',
  'deploy_key_policy_touched',
  'github_settings_touched',
  'production_issuer_path_used',
  'token_material_seen_by_report',
  'jwt_material_seen_by_report',
  'authorization_header_seen_by_report',
  'private_key_material_seen_by_report',
  'credentialed_url_seen_by_report',
  'raw_response_body_seen_by_report',
  'raw_error_seen_by_report',
  'raw_git_stdout_seen_by_report',
  'raw_git_stderr_seen_by_report',
  'env_values_seen_by_report',
  'shell_history_seen_by_report',
  'screenshot_seen_by_report',
  'token_stored',
];

export class SourceMovementReportRefusal extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = 'SourceMovementReportRefusal';
    this.code = code;
    this.safeCode = code;
  }
}

function refusal(code) {
  return new SourceMovementReportRefusal(code);
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function assertSafeString(value) {
  const lower = value.toLowerCase();
  if (
    lower.includes('-----begin') ||
    lower.includes('bearer ') ||
    lower.includes('authorization:') ||
    lower.includes('private_key:') ||
    lower.includes('private-key:') ||
    lower.includes('access_token:') ||
    lower.includes('installation_token:') ||
    lower.includes('credentialed_url:') ||
    lower.includes('jwt:') ||
    lower.includes('secret:') ||
    /\b(token|secret|authorization|private[_-]?key|jwt)\s*=/.test(lower)
  ) {
    throw refusal('report_redaction_failed');
  }
}

function assertSafeValue(value) {
  if (typeof value === 'string') {
    assertSafeString(value);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach(assertSafeValue);
    return;
  }
  if (value === null || typeof value === 'boolean' || typeof value === 'number') return;
  throw refusal('report_redaction_failed');
}

function assertSafeReviewObject(value) {
  if (typeof value === 'string' || Array.isArray(value) || value === null || typeof value !== 'object') {
    assertSafeValue(value);
    return;
  }
  for (const [key, entry] of Object.entries(value)) {
    assertSafeString(key);
    assertSafeReviewObject(entry);
  }
}

function assertExactArray(actual, expected, code) {
  if (
    !Array.isArray(actual) ||
    actual.length !== expected.length ||
    !expected.every((value, index) => actual[index] === value)
  ) {
    throw refusal(code);
  }
}

function assertSha(value, code) {
  if (!STRICT_SHA_RE.test(value ?? '')) throw refusal(code);
}

function isIsoUtc(value) {
  return typeof value === 'string' && ISO_UTC_RE.test(value) && !Number.isNaN(Date.parse(value));
}

function hasStatus(value) {
  return STATUS_CLASSES.has(value);
}

function assertCounter(report, key) {
  if (!Number.isSafeInteger(report[key]) || report[key] < 0) throw refusal('counter_mismatch');
}

function assertCountersEqual(report, expected) {
  for (const [key, value] of Object.entries(expected)) {
    assertCounter(report, key);
    if (report[key] !== value) throw refusal('counter_mismatch');
  }
}

function countersEqual(report, expected) {
  return Object.entries(expected).every(([key, value]) => report[key] === value);
}

function assertCounterConsistency(report) {
  for (const key of COUNTER_KEYS) assertCounter(report, key);
  if (report.credential_helper_count !== 0) throw refusal('counter_mismatch');
  if (report.rest_ref_update_count !== 0) throw refusal('counter_mismatch');
  if (report.ref_read_count !== report.pre_ref_read_count + report.post_ref_read_count) {
    throw refusal('counter_inconsistent');
  }
  if (report.ref_write_count !== report.git_transport_push_count + report.rest_ref_update_count) {
    throw refusal('counter_inconsistent');
  }
  if (report.revocation_request_count > report.token_lifecycle_request_count) {
    throw refusal('counter_inconsistent');
  }
  if (
    report.request_count !==
    report.token_lifecycle_request_count +
      report.ref_read_count +
      report.git_transport_push_count +
      report.rest_ref_update_count
  ) {
    throw refusal('counter_inconsistent');
  }
}

function hasReturnedObject(report, prefix) {
  return (
    typeof report[`${prefix}_returned_ref`] === 'string' &&
    typeof report[`${prefix}_returned_object_type`] === 'string' &&
    typeof report[`${prefix}_returned_sha`] === 'string'
  );
}

function assertCountedOperationsHaveEvidence(report) {
  if (report.token_lifecycle_request_count > 0) {
    if (
      report.private_key_read_inside_process_only !== true ||
      report.jwt_minted !== true ||
      report.installation_lookup_attempted !== true ||
      !hasStatus(report.installation_lookup_status_class)
    ) {
      throw refusal('operation_evidence_missing');
    }
  }
  if (report.token_lifecycle_request_count > 1) {
    if (report.installation_lookup_status_class !== '2xx') throw refusal('operation_evidence_missing');
    if (!hasStatus(report.installation_token_status_class)) throw refusal('operation_evidence_missing');
    if (report.installation_token_status_class === '2xx' && report.installation_token_minted !== true) {
      throw refusal('operation_evidence_missing');
    }
  }
  if (report.pre_ref_read_count > 0) {
    if (report.pre_ref_read_attempted !== true || !hasStatus(report.pre_ref_read_status_class)) {
      throw refusal('operation_evidence_missing');
    }
    if (report.pre_ref_read_status_class === '2xx' && !hasReturnedObject(report, 'pre_read')) {
      throw refusal('operation_evidence_missing');
    }
  }
  if (report.git_transport_push_count > 0) {
    if (
      report.live_source_movement_attempted !== true ||
      report.live_source_movement_authority_used !== true ||
      report.git_transport_push_attempted !== true ||
      !['success', 'failed'].includes(report.git_transport_push_result_class)
    ) {
      throw refusal('operation_evidence_missing');
    }
  }
  if (report.post_ref_read_count > 0) {
    if (report.post_ref_read_attempted !== true || !hasStatus(report.post_ref_read_status_class)) {
      throw refusal('operation_evidence_missing');
    }
    if (report.post_ref_read_status_class === '2xx' && !hasReturnedObject(report, 'post_read')) {
      throw refusal('operation_evidence_missing');
    }
  }
  if (report.revocation_request_count > 0) {
    if (report.revocation_attempted !== true || !hasStatus(report.revocation_status_class)) {
      throw refusal('operation_evidence_missing');
    }
  }
}

function cleanupSummary(report) {
  const tokenMinted =
    report.installation_token_minted === true && report.installation_token_status_class === '2xx';
  const expiryRecorded =
    isIsoUtc(report.installation_token_expires_at) &&
    report.installation_token_expiry_class === 'recorded';
  const revocationProven =
    report.revocation_attempted === true && report.revocation_status_class === '2xx';
  return {
    token_cleanup_required: tokenMinted,
    token_cleanup_proven: report.token_cleanup_proven === true,
    token_cleanup_proof_type: report.token_cleanup_proof_type,
    revocation_proven: revocationProven,
    expiry_recorded: expiryRecorded,
    cleanup_claim:
      report.token_cleanup_proof_type === 'expiry_timestamp'
        ? 'expiry_recorded_not_revocation'
        : report.token_cleanup_proof_type,
  };
}

function assertTokenCleanup(report) {
  if (!TOKEN_CLEANUP_PROOF_TYPES.has(report.token_cleanup_proof_type)) {
    throw refusal('token_cleanup_marker_mismatch');
  }
  if (!TOKEN_CLEANUP_ANOMALY_CLASSES.has(report.token_cleanup_anomaly_class)) {
    throw refusal('token_cleanup_marker_mismatch');
  }
  const tokenMinted =
    report.installation_token_minted === true && report.installation_token_status_class === '2xx';
  if (!tokenMinted) {
    if (
      report.token_cleanup_required !== false ||
      report.token_cleanup_proven !== false ||
      report.token_cleanup_proof_type !== 'none' ||
      report.token_cleanup_anomaly !== false ||
      report.token_cleanup_anomaly_class !== 'none'
    ) {
      throw refusal('token_cleanup_not_required');
    }
    return;
  }
  if (report.token_cleanup_required !== true) throw refusal('token_cleanup_required_missing');
  const revocationProof =
    report.revocation_attempted === true && report.revocation_status_class === '2xx';
  const expiryProof =
    isIsoUtc(report.installation_token_expires_at) &&
    report.installation_token_expiry_class === 'recorded';
  if (report.token_cleanup_proven === true) {
    if (report.token_cleanup_anomaly !== false || report.token_cleanup_anomaly_class !== 'none') {
      throw refusal('token_cleanup_marker_mismatch');
    }
    if (report.token_cleanup_proof_type === 'revocation_2xx' && revocationProof) return;
    if (report.token_cleanup_proof_type === 'expiry_timestamp' && expiryProof) return;
    throw refusal('token_cleanup_proof_missing');
  }
  if (report.token_cleanup_anomaly === true && report.token_cleanup_anomaly_class !== 'none') return;
  throw refusal('token_cleanup_missing');
}

function assertCommonEnvelope(report) {
  if (!isPlainObject(report)) throw refusal('malformed_report');
  for (const key of Object.keys(report)) {
    if (!ALLOWED_REPORT_KEYS.has(key)) throw refusal('unknown_report_field');
    assertSafeValue(report[key]);
  }
  if (report.report_type !== MOVEMENT_REPORT_TYPE) throw refusal('wrong_report_type');
  if (!REPORT_MODES.has(report.report_contract_mode)) throw refusal('wrong_report_mode');
  if (!MOVEMENT_STATUSES.has(report.movement_status)) throw refusal('wrong_movement_status');
  if (!FAILURE_STAGES.has(report.failure_stage)) throw refusal('wrong_failure_stage');
  if (report.counter_taxonomy_version !== 'source-movement-counter-taxonomy-v1') {
    throw refusal('counter_taxonomy_mismatch');
  }
  assertExactArray(
    report.token_lifecycle_request_classes,
    TOKEN_LIFECYCLE_REQUEST_CLASSES,
    'counter_taxonomy_mismatch',
  );
  assertExactArray(
    report.source_movement_request_classes,
    SOURCE_MOVEMENT_REQUEST_CLASSES,
    'counter_taxonomy_mismatch',
  );
  if (
    report.pre_read_request_class !== 'pre_ref_read' ||
    report.git_transport_push_request_class !== 'git_transport_push' ||
    report.post_read_request_class !== 'post_ref_read' ||
    report.revocation_request_class !== 'revocation' ||
    report.credential_helper_counter_class !== 'credential_helper' ||
    report.rest_ref_update_counter_class !== 'rest_ref_update'
  ) {
    throw refusal('counter_taxonomy_mismatch');
  }
  if (report.selected_repo !== SELECTED_REPO) throw refusal('wrong_selected_repo');
  if (report.requested_ref !== REQUESTED_REF) throw refusal('wrong_requested_ref');
  if (report.source_movement_mechanism !== SOURCE_MOVEMENT_MECHANISM) {
    throw refusal('movement_mechanism_mismatch');
  }
  if (report.expected_old_remote_sha !== EXPECTED_OLD_REMOTE_SHA) {
    throw refusal('expected_old_sha_mismatch');
  }
  if (report.expected_new_remote_sha !== EXPECTED_NEW_REMOTE_SHA) {
    throw refusal('expected_new_sha_mismatch');
  }
  assertExactArray(report.expected_diff_files, EXPECTED_DIFF_FILES, 'diff_scope_mismatch');
  assertCounterConsistency(report);
  assertCountedOperationsHaveEvidence(report);
  assertTokenCleanup(report);
  if (!GIT_TRANSPORT_FAILURE_CLASSES.has(report.git_transport_failure_class)) {
    throw refusal('git_transport_failure_class_missing');
  }
  if (report.git_transport_push_result_class === 'failed' && report.git_transport_failure_class === 'none') {
    throw refusal('git_transport_failure_class_missing');
  }
  for (const key of FORBIDDEN_TRUE_MARKERS) {
    if (report[key] !== false) throw refusal('forbidden_marker_true');
  }
  if (report.token_output_redacted !== true) throw refusal('redaction_marker_mismatch');
  if (scanUnsafeTokenLifecycleText(JSON.stringify(report)).length > 0) {
    throw refusal('report_redaction_failed');
  }
}

function assertLocalPreflightSuccess(report) {
  if (
    report.local_branch !== LOCAL_BRANCH ||
    report.local_source_commit !== LOCAL_SOURCE_COMMIT ||
    report.local_worktree_clean !== true ||
    report.local_remote_tracking_ref !== LOCAL_REMOTE_TRACKING_REF ||
    report.local_remote_tracking_sha !== EXPECTED_OLD_REMOTE_SHA ||
    report.local_ahead_count !== LOCAL_AHEAD_COUNT ||
    report.local_behind_count !== LOCAL_BEHIND_COUNT ||
    report.local_preflight_passed !== true ||
    report.observed_local_branch !== LOCAL_BRANCH ||
    report.observed_local_source_commit !== LOCAL_SOURCE_COMMIT ||
    report.observed_local_remote_tracking_ref !== LOCAL_REMOTE_TRACKING_REF ||
    report.observed_local_remote_tracking_sha !== EXPECTED_OLD_REMOTE_SHA ||
    report.observed_local_ahead_count !== LOCAL_AHEAD_COUNT ||
    report.observed_local_behind_count !== LOCAL_BEHIND_COUNT
  ) {
    throw refusal('local_preflight_mismatch');
  }
  assertExactArray(report.observed_diff_files, EXPECTED_DIFF_FILES, 'diff_scope_mismatch');
}

function assertCredentialLifecycleSuccess(report) {
  if (
    report.private_key_read_inside_process_only !== true ||
    report.jwt_minted !== true ||
    report.installation_lookup_attempted !== true ||
    report.installation_lookup_status_class !== '2xx' ||
    report.installation_token_minted !== true ||
    report.installation_token_status_class !== '2xx' ||
    report.repository_selection !== 'selected'
  ) {
    throw refusal('credential_lifecycle_marker_missing');
  }
  assertExactArray(report.permission_names, PERMISSIONS, 'permission_scope_mismatch');
}

function assertPreReadSuccess(report) {
  if (report.pre_ref_read_attempted !== true) throw refusal('pre_read_marker_missing');
  if (report.pre_ref_read_status_class !== '2xx') throw refusal('pre_read_status_class_mismatch');
  if (report.pre_read_returned_ref !== REQUESTED_REF) throw refusal('pre_ref_mismatch');
  if (report.pre_read_returned_object_type !== 'commit') throw refusal('pre_object_type_mismatch');
  assertSha(report.pre_read_returned_sha, 'invalid_pre_sha');
  if (report.pre_read_returned_sha !== EXPECTED_OLD_REMOTE_SHA) throw refusal('pre_sha_mismatch');
}

function assertPostReadSuccess(report) {
  if (report.post_ref_read_attempted !== true) throw refusal('post_read_marker_missing');
  if (report.post_ref_read_status_class !== '2xx') throw refusal('post_read_status_class_mismatch');
  if (report.post_read_returned_ref !== REQUESTED_REF) throw refusal('post_ref_mismatch');
  if (report.post_read_returned_object_type !== 'commit') throw refusal('post_object_type_mismatch');
  assertSha(report.post_read_returned_sha, 'invalid_post_sha');
  if (report.post_read_returned_sha !== EXPECTED_NEW_REMOTE_SHA) throw refusal('post_sha_mismatch');
}

function assertMovementClaimHasPostRead(report) {
  if (report.source_movement === true || report.remote_ref_write === true) {
    if (report.report_contract_mode !== LIVE_CONTRACT_MODE) throw refusal('movement_claim_not_live_shaped');
    if (report.post_ref_read_attempted !== true) throw refusal('movement_claim_without_post_read');
    if (report.post_ref_read_status_class !== '2xx') throw refusal('post_read_status_class_mismatch');
    if (report.post_read_returned_ref !== REQUESTED_REF) throw refusal('post_ref_mismatch');
    if (report.post_read_returned_object_type !== 'commit') throw refusal('post_object_type_mismatch');
    assertSha(report.post_read_returned_sha, 'invalid_post_sha');
    if (report.post_read_returned_sha !== EXPECTED_NEW_REMOTE_SHA) throw refusal('post_sha_mismatch');
  }
}

function assertLiveSuccess(report) {
  if (report.report_contract_mode !== LIVE_CONTRACT_MODE) throw refusal('wrong_report_mode');
  if (report.mock_evidence_only !== false) throw refusal('live_mode_marker_mismatch');
  if (report.movement_status !== 'passed') throw refusal('movement_status_not_passed');
  if (report.failure_stage !== 'none' || report.failure_reason_code !== 'none') {
    throw refusal('failure_marker_present');
  }
  assertLocalPreflightSuccess(report);
  if (
    !countersEqual(report, SUCCESS_COUNTERS) &&
    !countersEqual(report, EXPIRY_CLEANUP_SUCCESS_COUNTERS)
  ) {
    throw refusal('counter_mismatch');
  }
  assertCredentialLifecycleSuccess(report);
  assertPreReadSuccess(report);
  if (report.git_transport_push_attempted !== true) throw refusal('git_transport_marker_missing');
  if (report.git_transport_push_result_class !== 'success') throw refusal('git_transport_push_result_mismatch');
  assertPostReadSuccess(report);
  if (report.old_sha_is_ancestor_of_new_sha !== true) throw refusal('ancestry_mismatch');
  if (report.force_with_lease_used_as_old_sha_guard !== true) throw refusal('lease_guard_missing');
  if (report.source_movement !== true || report.remote_ref_write !== true) {
    throw refusal('movement_marker_missing');
  }
  if (report.token_cleanup_proven !== true) throw refusal('token_cleanup_proof_missing');
  if (report.token_cleanup_proof_type === 'revocation_2xx' && report.revocation_status_class !== '2xx') {
    throw refusal('revocation_status_class_mismatch');
  }
}

function assertMockReport(report) {
  if (report.report_contract_mode !== MOCK_CONTRACT_MODE) return;
  if (
    report.mock_evidence_only !== true ||
    report.movement_status !== 'mocked' ||
    report.failure_stage !== 'mock' ||
    report.failure_reason_code !== 'mock_evidence_not_live' ||
    report.source_movement !== false ||
    report.remote_ref_write !== false ||
    report.live_source_movement_attempted !== false ||
    report.live_source_movement_authority_used !== false
  ) {
    throw refusal('mock_mode_marker_mismatch');
  }
  assertCountersEqual(report, ZERO_COUNTERS);
}

export function ensureSourceMovementReportIsSafe(report) {
  assertCommonEnvelope(report);
  assertMovementClaimHasPostRead(report);
  if (report.report_contract_mode === MOCK_CONTRACT_MODE) {
    assertMockReport(report);
    return report;
  }
  if (report.movement_status === 'passed') {
    assertLiveSuccess(report);
    return report;
  }
  if (report.source_movement === true || report.remote_ref_write === true) {
    throw refusal('failed_report_cannot_claim_movement');
  }
  return report;
}

export function validateSourceMovementReport(report) {
  try {
    ensureSourceMovementReportIsSafe(report);
    const passed = report.report_contract_mode === LIVE_CONTRACT_MODE && report.movement_status === 'passed';
    return {
      report_type: MOVEMENT_REVIEW_TYPE,
      proof_status: passed ? 'passed' : 'failed',
      refusal_reason_code: passed ? null : 'report_is_not_success_proof',
      selected_repo: report.selected_repo,
      requested_ref: report.requested_ref,
      expected_old_remote_sha: report.expected_old_remote_sha,
      expected_new_remote_sha: report.expected_new_remote_sha,
      pre_read_returned_sha: report.pre_read_returned_sha,
      post_read_returned_sha: report.post_read_returned_sha,
      source_movement: passed,
      remote_ref_write: passed,
      source_movement_mechanism: report.source_movement_mechanism,
      cleanup: cleanupSummary(report),
      no_secret_verifier: true,
      live_mode_supported: false,
      forbidden_claims: forbiddenClaims(),
    };
  } catch (error) {
    return {
      report_type: MOVEMENT_REVIEW_TYPE,
      proof_status: 'failed',
      refusal_reason_code: error?.safeCode || error?.code || 'movement_report_invalid',
      no_secret_verifier: true,
      live_mode_supported: false,
      source_movement: false,
      remote_ref_write: false,
      forbidden_claims: forbiddenClaims(),
    };
  }
}

export function verifySourceTransportAuthorityPacket(packetText, options = {}) {
  const preflight = runSourceTransportPreflight(packetText, options);
  return {
    report_type: MOVEMENT_REVIEW_TYPE,
    proof_status: preflight.preflight_status === 'passed' ? 'passed' : 'failed',
    proof_kind: 'authority_packet_preflight',
    refusal_reason_code: preflight.refusal_reason_code,
    no_secret_verifier: true,
    live_mode_supported: false,
    preflight,
    forbidden_claims: forbiddenClaims(),
  };
}

export function resolveSafeMovementReviewPath(outputPath, buildRoot = BUILD_ROOT) {
  if (!outputPath || typeof outputPath !== 'string') {
    throw refusal('missing_output_path');
  }
  assertSafeString(outputPath);
  const root = resolve(buildRoot);
  const target = resolve(outputPath);
  if (target !== root && !target.startsWith(root + sep)) {
    throw refusal('unsafe_output_path');
  }
  if (existsSync(target)) throw refusal('output_exists');
  return target;
}

export function writeSourceMovementReportReview(review, outputPath, options = {}) {
  if (isPlainObject(review) && review.report_type === MOVEMENT_REVIEW_TYPE) {
    if (
      review.proof_kind !== 'authority_packet_preflight' ||
      review.source_movement === true ||
      review.remote_ref_write === true
    ) {
      throw refusal('forged_review_input_refused');
    }
  }
  const safeReview = isPlainObject(review) && review.report_type === MOVEMENT_REVIEW_TYPE
    ? review
    : validateSourceMovementReport(review);
  assertSafeReviewObject(safeReview);
  if (scanUnsafeTokenLifecycleText(JSON.stringify(safeReview)).length > 0) {
    throw refusal('report_redaction_failed');
  }
  const target = resolveSafeMovementReviewPath(outputPath, options.buildRoot ?? BUILD_ROOT);
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  writeFileSync(target, `${JSON.stringify(safeReview, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return target;
}

export function formatSourceMovementReportReview(review) {
  const lines = [
    `report_type: ${review.report_type}`,
    `proof_status: ${review.proof_status}`,
    `refusal_reason_code: ${review.refusal_reason_code ?? 'none'}`,
    `no_secret_verifier: ${review.no_secret_verifier === true}`,
    `live_mode_supported: ${review.live_mode_supported === true}`,
  ];
  if (review.selected_repo) lines.push(`selected_repo: ${review.selected_repo}`);
  if (review.requested_ref) lines.push(`requested_ref: ${review.requested_ref}`);
  lines.push(`source_movement: ${review.source_movement === true}`);
  lines.push(`remote_ref_write: ${review.remote_ref_write === true}`);
  lines.push('claim_ceiling: no-secret report verifier only');
  return `${lines.join('\n')}\n`;
}

export function forbiddenClaims() {
  return [
    'durable_github_app_source_transport_proven',
    'future_source_movement_authorized',
    'production_source_transport',
    'deploy_key_replacement_or_closure',
    'production_issuer_authority',
    'production_trust',
    'website_public_alignment',
    'tag_release_or_actions_proof',
    'arbitrary_repo_or_ref_movement',
    'all_surface_governance',
    'side_door_closure',
    'absolute_human_intention',
  ];
}

function applyCounters(report, counters) {
  for (const [key, value] of Object.entries(counters)) report[key] = value;
}

export function buildExampleSourceMovementReport(now = new Date()) {
  const report = {
    report_type: MOVEMENT_REPORT_TYPE,
    report_contract_mode: LIVE_CONTRACT_MODE,
    mock_evidence_only: false,
    modeled_source_movement: false,
    modeled_remote_ref_write: false,
    live_source_movement_attempted: true,
    live_source_movement_authority_used: true,
    selected_repo: SELECTED_REPO,
    requested_ref: REQUESTED_REF,
    local_branch: LOCAL_BRANCH,
    local_source_commit: LOCAL_SOURCE_COMMIT,
    local_worktree_clean: true,
    local_remote_tracking_ref: LOCAL_REMOTE_TRACKING_REF,
    local_remote_tracking_sha: EXPECTED_OLD_REMOTE_SHA,
    local_ahead_count: LOCAL_AHEAD_COUNT,
    local_behind_count: LOCAL_BEHIND_COUNT,
    local_preflight_passed: true,
    observed_local_branch: LOCAL_BRANCH,
    observed_local_source_commit: LOCAL_SOURCE_COMMIT,
    observed_local_remote_tracking_ref: LOCAL_REMOTE_TRACKING_REF,
    observed_local_remote_tracking_sha: EXPECTED_OLD_REMOTE_SHA,
    observed_local_ahead_count: LOCAL_AHEAD_COUNT,
    observed_local_behind_count: LOCAL_BEHIND_COUNT,
    expected_diff_files: [...EXPECTED_DIFF_FILES],
    observed_diff_files: [...EXPECTED_DIFF_FILES],
    request_started_at: now.toISOString(),
    response_completed_at: now.toISOString(),
    counter_taxonomy_version: 'source-movement-counter-taxonomy-v1',
    token_lifecycle_request_classes: [...TOKEN_LIFECYCLE_REQUEST_CLASSES],
    source_movement_request_classes: [...SOURCE_MOVEMENT_REQUEST_CLASSES],
    pre_read_request_class: 'pre_ref_read',
    git_transport_push_request_class: 'git_transport_push',
    post_read_request_class: 'post_ref_read',
    revocation_request_class: 'revocation',
    credential_helper_counter_class: 'credential_helper',
    rest_ref_update_counter_class: 'rest_ref_update',
    private_key_read_inside_process_only: true,
    jwt_minted: true,
    installation_lookup_attempted: true,
    installation_lookup_status_class: '2xx',
    installation_token_minted: true,
    installation_token_status_class: '2xx',
    permission_names: [...PERMISSIONS],
    repository_selection: 'selected',
    pre_ref_read_attempted: true,
    pre_ref_read_status_class: '2xx',
    pre_read_returned_ref: REQUESTED_REF,
    pre_read_returned_object_type: 'commit',
    pre_read_returned_sha: EXPECTED_OLD_REMOTE_SHA,
    git_transport_push_attempted: true,
    git_transport_push_result_class: 'success',
    git_transport_failure_class: 'none',
    post_ref_read_attempted: true,
    post_ref_read_status_class: '2xx',
    post_read_returned_ref: REQUESTED_REF,
    post_read_returned_object_type: 'commit',
    post_read_returned_sha: EXPECTED_NEW_REMOTE_SHA,
    source_movement: true,
    remote_ref_write: true,
    source_movement_mechanism: SOURCE_MOVEMENT_MECHANISM,
    expected_old_remote_sha: EXPECTED_OLD_REMOTE_SHA,
    expected_new_remote_sha: EXPECTED_NEW_REMOTE_SHA,
    old_sha_is_ancestor_of_new_sha: true,
    force_push: false,
    force_with_lease_used_as_old_sha_guard: true,
    plus_refspec_used: false,
    revocation_attempted: true,
    revocation_status_class: '2xx',
    installation_token_expires_at: null,
    installation_token_expiry_class: 'not_applicable',
    token_cleanup_required: true,
    token_cleanup_proven: true,
    token_cleanup_proof_type: 'revocation_2xx',
    token_cleanup_anomaly: false,
    token_cleanup_anomaly_class: 'none',
    movement_status: 'passed',
    failure_stage: 'none',
    failure_reason_code: 'none',
    git_fetch: false,
    git_ls_remote: false,
    actions_used: false,
    tag_or_release_used: false,
    website_touched: false,
    deploy_key_policy_touched: false,
    github_settings_touched: false,
    production_issuer_path_used: false,
    token_material_seen_by_report: false,
    jwt_material_seen_by_report: false,
    authorization_header_seen_by_report: false,
    private_key_material_seen_by_report: false,
    credentialed_url_seen_by_report: false,
    raw_response_body_seen_by_report: false,
    raw_error_seen_by_report: false,
    raw_git_stdout_seen_by_report: false,
    raw_git_stderr_seen_by_report: false,
    env_values_seen_by_report: false,
    shell_history_seen_by_report: false,
    screenshot_seen_by_report: false,
    token_stored: false,
    token_output_redacted: true,
  };
  applyCounters(report, SUCCESS_COUNTERS);
  return report;
}

export function buildExampleMockReport(now = new Date()) {
  const report = buildExampleSourceMovementReport(now);
  Object.assign(report, {
    report_contract_mode: MOCK_CONTRACT_MODE,
    mock_evidence_only: true,
    modeled_source_movement: true,
    modeled_remote_ref_write: true,
    live_source_movement_attempted: false,
    live_source_movement_authority_used: false,
    private_key_read_inside_process_only: false,
    jwt_minted: false,
    installation_lookup_attempted: false,
    installation_lookup_status_class: null,
    installation_token_minted: false,
    installation_token_status_class: null,
    permission_names: [],
    repository_selection: null,
    pre_ref_read_attempted: false,
    pre_ref_read_status_class: null,
    pre_read_returned_ref: null,
    pre_read_returned_object_type: null,
    pre_read_returned_sha: null,
    git_transport_push_attempted: false,
    git_transport_push_result_class: null,
    post_ref_read_attempted: false,
    post_ref_read_status_class: null,
    post_read_returned_ref: null,
    post_read_returned_object_type: null,
    post_read_returned_sha: null,
    source_movement: false,
    remote_ref_write: false,
    revocation_attempted: false,
    revocation_status_class: null,
    token_cleanup_required: false,
    token_cleanup_proven: false,
    token_cleanup_proof_type: 'none',
    movement_status: 'mocked',
    failure_stage: 'mock',
    failure_reason_code: 'mock_evidence_not_live',
  });
  applyCounters(report, ZERO_COUNTERS);
  return report;
}
