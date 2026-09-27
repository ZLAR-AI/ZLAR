import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonicalize } from './canonicalize.mjs';
import { sha256hex } from './receipt.mjs';
import {
  PROTECTED_RECORDS_SERVICE_LAUNCHER_CONFIG_TYPE,
  PROTECTED_RECORDS_SERVICE_RESULT_TYPE,
  PROTECTED_RECORDS_SERVICE_TYPE,
  assertNoUnsafeProtectedRecordsServiceText,
} from './protected-records-service-verification.mjs';

export const PROTECTED_RECORDS_SERVICE_PROFILE_TYPE =
  'zlar-protected-records-service-profile-v1';
export const PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_TYPE =
  'zlar-protected-records-service-profile-preflight-v1';
export const PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_TYPE =
  'zlar-protected-records-service-profile-preflight-artifact-v1';
export const PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_CANONICALIZATION =
  'zlar-canonical-json-v1';
export const PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE =
  'zlar-protected-records-service-profile-preflight-artifact-verification-v1';

export const REQUIRED_PROFILE_PREFLIGHT_CASES = Object.freeze([
  'recognized_profile_service_write_first_process',
  'replay_profile_refused_after_service_restart',
  'missing_receipt_profile_refused_before_service_mutation',
  'unrecognized_receipt_profile_refused_before_service_mutation',
  'invalid_receipt_profile_refused_before_service_mutation',
  'unknown_issuer_profile_refused_before_service_mutation',
  'wrong_policy_profile_refused_before_service_mutation',
  'stale_receipt_profile_refused_before_service_mutation',
  'request_stream_authority_material_profile_refused_before_service_mutation',
  'direct_api_profile_without_receipt_refused_before_service_mutation',
  'direct_api_profile_receipt_present_refused_before_service_mutation',
]);

export const REQUIRED_OPEN_BOUNDARIES = Object.freeze([
  'direct_filesystem_write_to_configured_fixture_paths',
  'live_records_system',
  'production_records_service',
  'runtime_profile_not_installed',
  'unrouted_records_paths',
]);

export const SAFE_CLAIM_CEILING =
  'ZLAR can preflight a sample protected-records downstream service profile, showing the launcher-owned-config local fixture service path accepts one recognized receipt and refuses replay, missing, unrecognized, invalid, unknown-issuer, wrong-policy, stale, request-stream authority-material, no-receipt direct API, and direct-API-with-receipt attempts before service-state mutation.';

export const NON_CLAIMS = Object.freeze([
  'This profile is a sample deployable preflight profile, not an active runtime profile.',
  'This preflight does not inspect a live records system.',
  'This preflight does not prove production records service deployment.',
  'This preflight does not close direct filesystem writes to configured fixture paths.',
  'This preflight does not prove current-machine governance, live MCP coverage, or live approval-channel health.',
  'This preflight does not prove external attestation, enterprise readiness, production authority, or sovereign recognition.',
  'This preflight does not prove coverage of unrouted records paths.',
]);

const CONFIG_BACKED_SERVICE_COMMAND =
  'zlar protected-records-service-request --config <file|-> --input <file|->';

const EXPECTED_CASE_CONTRACTS = Object.freeze({
  recognized_profile_service_write_first_process: {
    command: `${CONFIG_BACKED_SERVICE_COMMAND} --require-written`,
    process_invocation: 1,
    separate_process_from_accepted: false,
    consumed_store_exists_after: true,
  },
  replay_profile_refused_after_service_restart: {
    command: `${CONFIG_BACKED_SERVICE_COMMAND} --require-refused`,
    process_invocation: 2,
    separate_process_from_accepted: true,
    consumed_store_exists_after: true,
  },
  missing_receipt_profile_refused_before_service_mutation: {
    command: `${CONFIG_BACKED_SERVICE_COMMAND} --require-refused`,
    process_invocation: 3,
    separate_process_from_accepted: true,
    consumed_store_exists_after: false,
  },
  unrecognized_receipt_profile_refused_before_service_mutation: {
    command: `${CONFIG_BACKED_SERVICE_COMMAND} --require-refused`,
    process_invocation: 4,
    separate_process_from_accepted: true,
    consumed_store_exists_after: false,
  },
  invalid_receipt_profile_refused_before_service_mutation: {
    command: `${CONFIG_BACKED_SERVICE_COMMAND} --require-refused`,
    process_invocation: 5,
    separate_process_from_accepted: true,
    consumed_store_exists_after: false,
  },
  unknown_issuer_profile_refused_before_service_mutation: {
    command: `${CONFIG_BACKED_SERVICE_COMMAND} --require-refused`,
    process_invocation: 6,
    separate_process_from_accepted: true,
    consumed_store_exists_after: false,
  },
  wrong_policy_profile_refused_before_service_mutation: {
    command: `${CONFIG_BACKED_SERVICE_COMMAND} --require-refused`,
    process_invocation: 7,
    separate_process_from_accepted: true,
    consumed_store_exists_after: false,
  },
  stale_receipt_profile_refused_before_service_mutation: {
    command: `${CONFIG_BACKED_SERVICE_COMMAND} --require-refused`,
    process_invocation: 8,
    separate_process_from_accepted: true,
    consumed_store_exists_after: false,
  },
  request_stream_authority_material_profile_refused_before_service_mutation: {
    command: `${CONFIG_BACKED_SERVICE_COMMAND} --require-refused`,
    process_invocation: 9,
    separate_process_from_accepted: true,
    consumed_store_exists_after: false,
  },
  direct_api_profile_without_receipt_refused_before_service_mutation: {
    command: `${CONFIG_BACKED_SERVICE_COMMAND} --require-refused`,
    process_invocation: 10,
    separate_process_from_accepted: true,
    consumed_store_exists_after: false,
  },
  direct_api_profile_receipt_present_refused_before_service_mutation: {
    command: `${CONFIG_BACKED_SERVICE_COMMAND} --require-refused`,
    process_invocation: 11,
    separate_process_from_accepted: true,
    consumed_store_exists_after: false,
  },
});


function requireObject(label, value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function assertExactKeys(label, value, expectedKeys) {
  requireObject(label, value);
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains unexpected fields`);
  }
  return true;
}

function assertExactArray(label, value, expected) {
  if (!Array.isArray(value) || value.length !== expected.length) {
    throw new Error(`${label} drifted`);
  }
  for (const item of expected) {
    if (!value.includes(item)) {
      throw new Error(`${label} missing ${item}`);
    }
  }
  return true;
}

export function profileSha256(profile) {
  assertProtectedRecordsServiceProfile(profile);
  return sha256hex(canonicalize(profile));
}

export function assertProtectedRecordsServiceProfile(profile) {
  assertExactKeys('Protected records service profile', profile, [
    'action_class',
    'consumed_receipt_store',
    'deployment_posture',
    'environment_boundary',
    'known_open_boundaries',
    'mutation_authoritative_route',
    'non_claims',
    'profile_id',
    'profile_status',
    'profile_type',
    'recognition_boundary',
    'recognition_rule_contract',
    'replay_scope',
    'required_cases',
    'result_type',
    'service_command',
    'service_type',
    'state_model',
  ]);
  if (
    profile.profile_type !== PROTECTED_RECORDS_SERVICE_PROFILE_TYPE ||
    profile.profile_id !== 'protected-records-service-fixture-profile' ||
    profile.profile_status !== 'sample_not_active' ||
    profile.deployment_posture !== 'deployable_profile_preflight_only' ||
    profile.action_class !== 'records.write' ||
    profile.service_type !== PROTECTED_RECORDS_SERVICE_TYPE ||
    profile.service_command !== CONFIG_BACKED_SERVICE_COMMAND ||
    profile.result_type !== PROTECTED_RECORDS_SERVICE_RESULT_TYPE ||
    profile.recognition_boundary !== 'downstream-recognition-before-service-mutation' ||
    profile.mutation_authoritative_route !== 'receipt-recognition-before-service-state-append' ||
    profile.state_model !== 'bounded-jsonl-service-state-entry' ||
    profile.consumed_receipt_store !== 'persistent-single-use-receipt-id-store' ||
    profile.replay_scope !== 'per-service-consumed-receipt-store'
  ) {
    throw new Error('Protected records service profile contract drifted');
  }

  assertExactKeys('Protected records service environment boundary', profile.environment_boundary, [
    'authoritative_route',
    'boundary_id',
    'boundary_type',
    'direct_filesystem_write_to_fixture_paths_closed',
    'effect_boundary',
    'fixture_mode_required',
    'launcher_owned_config_required',
    'live_profile_installed',
    'request_stream_allowed_fields',
    'request_stream_authority_material_allowed',
    'runtime_activation',
    'service_entrypoint',
    'service_process_boundary',
  ]);
  const boundary = profile.environment_boundary;
  if (
    boundary.boundary_id !== 'local-disposable-cli-service-boundary' ||
    boundary.boundary_type !== 'local-disposable-cli-process' ||
    boundary.service_entrypoint !== CONFIG_BACKED_SERVICE_COMMAND ||
    boundary.service_process_boundary !== 'separate-cli-process' ||
    boundary.authoritative_route !== 'receipt-recognition-before-service-state-append' ||
    boundary.effect_boundary !== 'bounded-jsonl-service-state-entry' ||
    boundary.fixture_mode_required !== true ||
    boundary.launcher_owned_config_required !== true ||
    boundary.runtime_activation !== false ||
    boundary.live_profile_installed !== false ||
    boundary.request_stream_authority_material_allowed !== false ||
    boundary.direct_filesystem_write_to_fixture_paths_closed !== false
  ) {
    throw new Error('Protected records service environment boundary drifted');
  }
  assertExactArray('Protected records service request stream allowed fields', boundary.request_stream_allowed_fields, [
    'receipt',
    'record_update',
  ]);

  assertExactKeys('Protected records service recognition rule contract', profile.recognition_rule_contract, [
    'accepted_domains',
    'accepted_outcomes',
    'accepted_policy_versions',
    'accepted_tools',
    'deployment_scope',
    'max_age_seconds',
    'required_audit_event_id',
    'required_detail_binding',
    'required_issuer_status',
  ]);
  const contract = profile.recognition_rule_contract;
  if (
    contract.deployment_scope !== 'protected-records-service-profile-fixture' ||
    contract.max_age_seconds !== 120 ||
    contract.required_audit_event_id !== 'protected-record-service-profile-001' ||
    contract.required_issuer_status !== 'active' ||
    contract.required_detail_binding !== 'receipt.payload.detail_hash == sha256(canonical(record_update))'
  ) {
    throw new Error('Protected records service recognition contract drifted');
  }
  assertExactArray('Protected records service accepted policy versions', contract.accepted_policy_versions, ['recognition-policy-v1']);
  assertExactArray('Protected records service accepted domains', contract.accepted_domains, ['records']);
  assertExactArray('Protected records service accepted tools', contract.accepted_tools, ['records.write']);
  assertExactArray('Protected records service accepted outcomes', contract.accepted_outcomes, ['allow', 'authorized']);
  assertExactArray('Protected records service required cases', profile.required_cases, REQUIRED_PROFILE_PREFLIGHT_CASES);
  assertExactArray('Protected records service open boundaries', profile.known_open_boundaries, REQUIRED_OPEN_BOUNDARIES);
  assertExactArray('Protected records service profile non-claims', profile.non_claims, NON_CLAIMS);
  assertNoUnsafeProtectedRecordsServiceProfileText(JSON.stringify(profile));
  return true;
}

export const PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_GENERATION_RETIREMENT_REASON =
  'e2_positive_service_preflight_generation_retired';

export function runProtectedRecordsServiceProfilePreflight() {
  throw new Error(
    PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_GENERATION_RETIREMENT_REASON,
  );
}

export function assertProtectedRecordsServiceProfilePreflight(report, profile) {
  assertProtectedRecordsServiceProfile(profile);
  assertExactKeys('Protected records service profile preflight', report, [
    'cases',
    'deployment_posture',
    'environment_boundary',
    'evidence_model',
    'known_open_boundaries',
    'live_probing',
    'non_claims',
    'preflight_type',
    'profile',
    'recognition_rule_contract',
    'safe_claim_ceiling',
    'side_door_report',
  ]);
  if (
    report.preflight_type !== PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_TYPE ||
    report.evidence_model !== 'local-disposable-config-backed-profile-preflight-fixture' ||
    report.live_probing !== false ||
    report.safe_claim_ceiling !== SAFE_CLAIM_CEILING ||
    report.deployment_posture !== 'deployable_profile_preflight_only'
  ) {
    throw new Error('Protected records service profile preflight top-level contract drifted');
  }

  assertExactKeys('Protected records service profile preflight profile', report.profile, [
    'profile_id',
    'profile_sha256',
    'profile_status',
    'profile_type',
  ]);
  if (
    report.profile.profile_type !== profile.profile_type ||
    report.profile.profile_id !== profile.profile_id ||
    report.profile.profile_status !== profile.profile_status ||
    report.profile.profile_sha256 !== profileSha256(profile)
  ) {
    throw new Error('Protected records service profile preflight profile identity drifted');
  }

  assertExactKeys('Protected records service profile preflight environment boundary', report.environment_boundary, [
    'authoritative_route',
    'boundary_id',
    'boundary_type',
    'direct_filesystem_write_to_fixture_paths_closed',
    'effect_boundary',
    'fixture_mode_required',
    'launcher_owned_config_required',
    'live_profile_installed',
    'request_stream_allowed_fields',
    'request_stream_authority_material_allowed',
    'runtime_activation',
    'service_entrypoint',
    'service_process_boundary',
  ]);
  if (canonicalize(report.environment_boundary) !== canonicalize(profile.environment_boundary)) {
    throw new Error('Protected records service profile preflight environment boundary drifted');
  }

  assertExactKeys('Protected records service profile preflight recognition contract', report.recognition_rule_contract, [
    'accepted_domains',
    'accepted_outcomes',
    'accepted_policy_versions',
    'accepted_tools',
    'deployment_scope',
    'max_age_seconds',
    'required_audit_event_id',
    'required_detail_binding',
    'required_issuer_status',
  ]);
  if (canonicalize(report.recognition_rule_contract) !== canonicalize(profile.recognition_rule_contract)) {
    throw new Error('Protected records service profile preflight recognition contract drifted');
  }

  assertExactKeys('Protected records service profile preflight side-door report', report.side_door_report, [
    'direct_api_with_receipt_refused',
    'direct_api_without_receipt_refused',
    'direct_filesystem_write_to_fixture_paths_closed',
    'external_attestation',
    'launcher_owned_config_required',
    'live_approval_channel_health_checked',
    'live_mcp_coverage_checked',
    'live_profile_installed',
    'live_records_system_checked',
    'production_records_service_checked',
    'request_stream_authority_material_allowed',
    'request_stream_authority_material_refused',
    'request_stream_forbidden_fields_refused',
    'runtime_profile_activation_checked',
    'sovereign_recognition',
    'unrouted_records_paths_checked',
  ]);
  if (
    report.side_door_report.direct_api_without_receipt_refused !== true ||
    report.side_door_report.direct_api_with_receipt_refused !== true ||
    report.side_door_report.direct_filesystem_write_to_fixture_paths_closed !== false ||
    report.side_door_report.external_attestation !== false ||
    report.side_door_report.launcher_owned_config_required !== true ||
    report.side_door_report.live_approval_channel_health_checked !== false ||
    report.side_door_report.live_mcp_coverage_checked !== false ||
    report.side_door_report.live_profile_installed !== false ||
    report.side_door_report.live_records_system_checked !== false ||
    report.side_door_report.production_records_service_checked !== false ||
    report.side_door_report.request_stream_authority_material_allowed !== false ||
    report.side_door_report.request_stream_authority_material_refused !== true ||
    report.side_door_report.request_stream_forbidden_fields_refused !== true ||
    report.side_door_report.runtime_profile_activation_checked !== false ||
    report.side_door_report.sovereign_recognition !== false ||
    report.side_door_report.unrouted_records_paths_checked !== false
  ) {
    throw new Error('Protected records service profile preflight side-door report drifted');
  }

  assertExactArray('Protected records service profile preflight open boundaries', report.known_open_boundaries, REQUIRED_OPEN_BOUNDARIES);
  assertExactArray('Protected records service profile preflight non-claims', report.non_claims, NON_CLAIMS);
  if (!Array.isArray(report.cases) || report.cases.length !== REQUIRED_PROFILE_PREFLIGHT_CASES.length) {
    throw new Error('Protected records service profile preflight case count drifted');
  }
  for (const caseId of REQUIRED_PROFILE_PREFLIGHT_CASES) {
    if (!report.cases.some((item) => item.case_id === caseId)) {
      throw new Error(`Protected records service profile preflight missing case: ${caseId}`);
    }
  }
  for (const item of report.cases) {
    assertExactKeys('Protected records service profile preflight case', item, [
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
    if (
      !EXPECTED_CASE_CONTRACTS[item.case_id] ||
      item.command !== EXPECTED_CASE_CONTRACTS[item.case_id].command ||
      item.process_boundary !== 'separate-cli-process' ||
      item.process_invocation !== EXPECTED_CASE_CONTRACTS[item.case_id].process_invocation ||
      item.separate_process_from_accepted !== EXPECTED_CASE_CONTRACTS[item.case_id].separate_process_from_accepted ||
      item.exit_status !== 0 ||
      item.stdout_json_emitted !== true ||
      item.stderr_empty !== true ||
      item.consumed_store_exists_after !== EXPECTED_CASE_CONTRACTS[item.case_id].consumed_store_exists_after ||
      item.state_entry_count_delta !== item.state_entry_count_after - item.state_entry_count_before
    ) {
      throw new Error('Protected records service profile preflight case contract drifted');
    }
  }

  const accepted = report.cases.find((item) => item.case_id === 'recognized_profile_service_write_first_process');
  if (
    accepted.process_invocation !== 1 ||
    accepted.separate_process_from_accepted !== false ||
    accepted.service_write_accepted !== true ||
    accepted.reason_code !== 'recognized' ||
    accepted.state_entry_count_before !== 0 ||
    accepted.state_entry_count_after !== 1 ||
    accepted.state_entry_count_delta !== 1 ||
    accepted.consumed_receipt_count !== 1 ||
    accepted.consumed_store_exists_after !== true ||
    accepted.direct_api_attempted !== false
  ) {
    throw new Error('Protected records service profile preflight accepted case failed');
  }

  const replay = report.cases.find((item) => item.case_id === 'replay_profile_refused_after_service_restart');
  if (
    replay.process_invocation !== 2 ||
    replay.separate_process_from_accepted !== true ||
    replay.service_write_accepted !== false ||
    replay.reason_code !== 'receipt_replay' ||
    replay.state_entry_count_before !== 1 ||
    replay.state_entry_count_after !== 1 ||
    replay.state_entry_count_delta !== 0 ||
    replay.consumed_receipt_count !== 1 ||
    replay.consumed_store_exists_after !== true ||
    replay.direct_api_attempted !== false
  ) {
    throw new Error('Protected records service profile preflight replay case failed');
  }

  const missing = report.cases.find((item) => item.case_id === 'missing_receipt_profile_refused_before_service_mutation');
  if (
    missing.process_invocation !== 3 ||
    missing.service_write_accepted !== false ||
    missing.reason_code !== 'receipt_missing' ||
    missing.state_entry_count_before !== 0 ||
    missing.state_entry_count_after !== 0 ||
    missing.state_entry_count_delta !== 0 ||
    missing.consumed_receipt_count !== 0 ||
    missing.direct_api_attempted !== false
  ) {
    throw new Error('Protected records service profile preflight missing receipt case failed');
  }

  const unrecognized = report.cases.find((item) => item.case_id === 'unrecognized_receipt_profile_refused_before_service_mutation');
  if (
    unrecognized.process_invocation !== 4 ||
    unrecognized.service_write_accepted !== false ||
    unrecognized.reason_code !== 'detail_hash_mismatch' ||
    unrecognized.state_entry_count_before !== 0 ||
    unrecognized.state_entry_count_after !== 0 ||
    unrecognized.state_entry_count_delta !== 0 ||
    unrecognized.consumed_receipt_count !== 0 ||
    unrecognized.direct_api_attempted !== false
  ) {
    throw new Error('Protected records service profile preflight unrecognized case failed');
  }

  const invalid = report.cases.find((item) => item.case_id === 'invalid_receipt_profile_refused_before_service_mutation');
  if (
    invalid.process_invocation !== 5 ||
    invalid.service_write_accepted !== false ||
    invalid.reason_code !== 'receipt_invalid' ||
    invalid.state_entry_count_before !== 0 ||
    invalid.state_entry_count_after !== 0 ||
    invalid.state_entry_count_delta !== 0 ||
    invalid.consumed_receipt_count !== 0 ||
    invalid.consumed_store_exists_after !== false ||
    invalid.direct_api_attempted !== false
  ) {
    throw new Error('Protected records service profile preflight invalid receipt case failed');
  }

  const unknownIssuer = report.cases.find((item) => item.case_id === 'unknown_issuer_profile_refused_before_service_mutation');
  if (
    unknownIssuer.process_invocation !== 6 ||
    unknownIssuer.service_write_accepted !== false ||
    unknownIssuer.reason_code !== 'unknown_issuer' ||
    unknownIssuer.state_entry_count_before !== 0 ||
    unknownIssuer.state_entry_count_after !== 0 ||
    unknownIssuer.state_entry_count_delta !== 0 ||
    unknownIssuer.consumed_receipt_count !== 0 ||
    unknownIssuer.consumed_store_exists_after !== false ||
    unknownIssuer.direct_api_attempted !== false
  ) {
    throw new Error('Protected records service profile preflight unknown issuer case failed');
  }

  const wrongPolicy = report.cases.find((item) => item.case_id === 'wrong_policy_profile_refused_before_service_mutation');
  if (
    wrongPolicy.process_invocation !== 7 ||
    wrongPolicy.service_write_accepted !== false ||
    wrongPolicy.reason_code !== 'policy_not_recognized' ||
    wrongPolicy.state_entry_count_before !== 0 ||
    wrongPolicy.state_entry_count_after !== 0 ||
    wrongPolicy.state_entry_count_delta !== 0 ||
    wrongPolicy.consumed_receipt_count !== 0 ||
    wrongPolicy.consumed_store_exists_after !== false ||
    wrongPolicy.direct_api_attempted !== false
  ) {
    throw new Error('Protected records service profile preflight wrong-policy case failed');
  }

  const stale = report.cases.find((item) => item.case_id === 'stale_receipt_profile_refused_before_service_mutation');
  if (
    stale.process_invocation !== 8 ||
    stale.service_write_accepted !== false ||
    stale.reason_code !== 'receipt_stale' ||
    stale.state_entry_count_before !== 0 ||
    stale.state_entry_count_after !== 0 ||
    stale.state_entry_count_delta !== 0 ||
    stale.consumed_receipt_count !== 0 ||
    stale.consumed_store_exists_after !== false ||
    stale.direct_api_attempted !== false
  ) {
    throw new Error('Protected records service profile preflight stale receipt case failed');
  }

  const requestStreamAuthority = report.cases.find((item) => item.case_id === 'request_stream_authority_material_profile_refused_before_service_mutation');
  if (
    requestStreamAuthority.process_invocation !== 9 ||
    requestStreamAuthority.service_write_accepted !== false ||
    requestStreamAuthority.reason_code !== 'request_stream_authority_material' ||
    requestStreamAuthority.state_entry_count_before !== 0 ||
    requestStreamAuthority.state_entry_count_after !== 0 ||
    requestStreamAuthority.state_entry_count_delta !== 0 ||
    requestStreamAuthority.consumed_receipt_count !== 0 ||
    requestStreamAuthority.consumed_store_exists_after !== false ||
    requestStreamAuthority.direct_api_attempted !== false
  ) {
    throw new Error('Protected records service profile preflight request-stream authority material case failed');
  }

  const directApi = report.cases.find((item) => item.case_id === 'direct_api_profile_without_receipt_refused_before_service_mutation');
  if (
    directApi.process_invocation !== 10 ||
    directApi.service_write_accepted !== false ||
    directApi.reason_code !== 'request_stream_forbidden_fields' ||
    directApi.state_entry_count_before !== 0 ||
    directApi.state_entry_count_after !== 0 ||
    directApi.state_entry_count_delta !== 0 ||
    directApi.consumed_receipt_count !== 0 ||
    directApi.consumed_store_exists_after !== false ||
    directApi.direct_api_attempted !== true
  ) {
    throw new Error('Protected records service profile preflight direct API no-receipt case failed');
  }

  const directApiWithReceipt = report.cases.find((item) => item.case_id === 'direct_api_profile_receipt_present_refused_before_service_mutation');
  if (
    directApiWithReceipt.process_invocation !== 11 ||
    directApiWithReceipt.service_write_accepted !== false ||
    directApiWithReceipt.reason_code !== 'request_stream_forbidden_fields' ||
    directApiWithReceipt.state_entry_count_before !== 0 ||
    directApiWithReceipt.state_entry_count_after !== 0 ||
    directApiWithReceipt.state_entry_count_delta !== 0 ||
    directApiWithReceipt.consumed_receipt_count !== 0 ||
    directApiWithReceipt.consumed_store_exists_after !== false ||
    directApiWithReceipt.direct_api_attempted !== true
  ) {
    throw new Error('Protected records service profile preflight direct API receipt-present case failed');
  }

  assertNoUnsafeProtectedRecordsServiceProfileText(JSON.stringify(report));
  return true;
}

export function assertNoUnsafeProtectedRecordsServiceProfileText(value) {
  return assertNoUnsafeProtectedRecordsServiceText(value);
}

function serviceProfilePreflightArtifactBody(payload) {
  return {
    artifact_type: PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_TYPE,
    canonicalization: PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_CANONICALIZATION,
    generator: 'zlar protected-records-service-preflight --artifact',
    hash_scope: 'canonical artifact body without integrity',
    payload,
  };
}

export function buildProtectedRecordsServiceProfilePreflightArtifact(
  profile,
  report
) {
  if (report === undefined) {
    throw new Error(
      'e2_positive_service_preflight_default_artifact_generation_retired',
    );
  }
  assertProtectedRecordsServiceProfile(profile);
  assertProtectedRecordsServiceProfilePreflight(report, profile);
  const payload = {
    profile,
    preflight: report,
  };
  const body = serviceProfilePreflightArtifactBody(payload);
  const artifact = {
    ...body,
    integrity: {
      algorithm: 'SHA-256',
      body_sha256: sha256hex(canonicalize(body)),
    },
  };
  assertProtectedRecordsServiceProfilePreflightArtifact(artifact);
  return artifact;
}

export function assertProtectedRecordsServiceProfilePreflightArtifact(artifact) {
  if (
    !artifact ||
    artifact.artifact_type !== PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_TYPE
  ) {
    throw new Error('Protected records service profile preflight artifact has the wrong artifact type');
  }
  assertExactKeys('Protected records service profile preflight artifact', artifact, [
    'artifact_type',
    'canonicalization',
    'generator',
    'hash_scope',
    'integrity',
    'payload',
  ]);
  if (
    artifact.canonicalization !==
    PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_CANONICALIZATION
  ) {
    throw new Error('Protected records service profile preflight artifact canonicalization drifted');
  }
  if (artifact.generator !== 'zlar protected-records-service-preflight --artifact') {
    throw new Error('Protected records service profile preflight artifact generator drifted');
  }
  if (artifact.hash_scope !== 'canonical artifact body without integrity') {
    throw new Error('Protected records service profile preflight artifact hash scope drifted');
  }

  assertExactKeys('Protected records service profile preflight artifact payload', artifact.payload, [
    'preflight',
    'profile',
  ]);
  assertProtectedRecordsServiceProfile(artifact.payload.profile);
  assertProtectedRecordsServiceProfilePreflight(artifact.payload.preflight, artifact.payload.profile);

  if (!artifact.integrity || artifact.integrity.algorithm !== 'SHA-256') {
    throw new Error('Protected records service profile preflight artifact integrity algorithm drifted');
  }
  assertExactKeys('Protected records service profile preflight artifact integrity', artifact.integrity, [
    'algorithm',
    'body_sha256',
  ]);
  if (!/^[a-f0-9]{64}$/.test(artifact.integrity.body_sha256 || '')) {
    throw new Error('Protected records service profile preflight artifact SHA-256 is malformed');
  }
  const { integrity, ...body } = artifact;
  const expectedHash = sha256hex(canonicalize(body));
  if (artifact.integrity.body_sha256 !== expectedHash) {
    throw new Error('Protected records service profile preflight artifact SHA-256 mismatch');
  }
  assertNoUnsafeProtectedRecordsServiceProfileText(JSON.stringify(artifact));
  return true;
}

export function writeProtectedRecordsServiceProfilePreflightArtifact(artifact, outputPath) {
  assertProtectedRecordsServiceProfilePreflightArtifact(artifact);
  if (!outputPath || outputPath === '-') {
    throw new Error('Protected records service profile preflight artifact output path is required');
  }
  mkdirSync(dirname(outputPath), { recursive: true });
  const output = `${JSON.stringify(artifact, null, 2)}\n`;
  assertNoUnsafeProtectedRecordsServiceProfileText(output);
  writeFileSync(outputPath, output, { mode: 0o600 });
  return artifact.integrity.body_sha256;
}

export function parseProtectedRecordsServiceProfilePreflightArtifactText(text) {
  assertNoUnsafeProtectedRecordsServiceProfileText(text);
  let artifact;
  try {
    artifact = JSON.parse(text);
  } catch {
    throw new Error('Protected records service profile preflight artifact input is not valid JSON');
  }
  assertProtectedRecordsServiceProfilePreflightArtifact(artifact);
  return artifact;
}

function caseById(report, caseId) {
  return report.cases.find((item) => item.case_id === caseId);
}

export function verifyProtectedRecordsServiceProfilePreflightArtifact(artifact) {
  assertProtectedRecordsServiceProfilePreflightArtifact(artifact);
  const report = artifact.payload.preflight;
  const accepted = caseById(report, 'recognized_profile_service_write_first_process');
  const replay = caseById(report, 'replay_profile_refused_after_service_restart');
  const missing = caseById(report, 'missing_receipt_profile_refused_before_service_mutation');
  const unrecognized = caseById(report, 'unrecognized_receipt_profile_refused_before_service_mutation');
  const invalid = caseById(report, 'invalid_receipt_profile_refused_before_service_mutation');
  const unknownIssuer = caseById(report, 'unknown_issuer_profile_refused_before_service_mutation');
  const wrongPolicy = caseById(report, 'wrong_policy_profile_refused_before_service_mutation');
  const stale = caseById(report, 'stale_receipt_profile_refused_before_service_mutation');
  const requestStreamAuthority = caseById(report, 'request_stream_authority_material_profile_refused_before_service_mutation');
  const directApi = caseById(report, 'direct_api_profile_without_receipt_refused_before_service_mutation');
  const directApiWithReceipt = caseById(report, 'direct_api_profile_receipt_present_refused_before_service_mutation');
  const verification = {
    verification_type: PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE,
    verified: true,
    artifact_type: artifact.artifact_type,
    canonicalization: artifact.canonicalization,
    hash_scope: artifact.hash_scope,
    body_sha256: artifact.integrity.body_sha256,
    payload_type: report.preflight_type,
    evidence_model: report.evidence_model,
    live_probing: report.live_probing,
    profile_sha256: report.profile.profile_sha256,
    case_count: report.cases.length,
    required_case_count: REQUIRED_PROFILE_PREFLIGHT_CASES.length,
    recognized_write_accepted: accepted.service_write_accepted,
    replay_refused: replay.service_write_accepted === false,
    missing_receipt_refused: missing.service_write_accepted === false,
    unrecognized_receipt_refused: unrecognized.service_write_accepted === false,
    invalid_receipt_refused: invalid.service_write_accepted === false,
    unknown_issuer_refused: unknownIssuer.service_write_accepted === false,
    wrong_policy_refused: wrongPolicy.service_write_accepted === false,
    wrong_policy_reason: wrongPolicy.reason_code,
    wrong_policy_state_delta: wrongPolicy.state_entry_count_delta,
    stale_receipt_refused: stale.service_write_accepted === false,
    launcher_owned_config_required: report.side_door_report.launcher_owned_config_required,
    request_stream_authority_material_allowed:
      report.side_door_report.request_stream_authority_material_allowed,
    request_stream_authority_material_refused:
      requestStreamAuthority.service_write_accepted === false,
    request_stream_authority_material_reason: requestStreamAuthority.reason_code,
    request_stream_authority_material_state_delta:
      requestStreamAuthority.state_entry_count_delta,
    request_stream_forbidden_fields_refused:
      report.side_door_report.request_stream_forbidden_fields_refused,
    direct_api_without_receipt_refused: directApi.service_write_accepted === false,
    direct_api_with_receipt_refused: directApiWithReceipt.service_write_accepted === false,
    direct_api_without_receipt_reason: directApi.reason_code,
    direct_api_receipt_present_reason: directApiWithReceipt.reason_code,
    direct_api_receipt_present_state_delta: directApiWithReceipt.state_entry_count_delta,
    direct_filesystem_write_to_fixture_paths_closed:
      report.side_door_report.direct_filesystem_write_to_fixture_paths_closed,
    live_profile_installed: report.side_door_report.live_profile_installed,
    production_records_service_checked: report.side_door_report.production_records_service_checked,
    external_attestation: report.side_door_report.external_attestation,
    sovereign_recognition: report.side_door_report.sovereign_recognition,
    claim_boundary:
      'artifact integrity and embedded local service-profile preflight boundaries only',
    non_claims: [...report.non_claims],
  };
  assertNoUnsafeProtectedRecordsServiceProfileText(JSON.stringify(verification));
  return verification;
}

export function formatProtectedRecordsServiceProfilePreflightSummary(report, profile) {
  assertProtectedRecordsServiceProfilePreflight(report, profile);
  const accepted = report.cases.find((item) => item.case_id === 'recognized_profile_service_write_first_process');
  const replay = report.cases.find((item) => item.case_id === 'replay_profile_refused_after_service_restart');
  const missing = report.cases.find((item) => item.case_id === 'missing_receipt_profile_refused_before_service_mutation');
  const unrecognized = report.cases.find((item) => item.case_id === 'unrecognized_receipt_profile_refused_before_service_mutation');
  const invalid = report.cases.find((item) => item.case_id === 'invalid_receipt_profile_refused_before_service_mutation');
  const unknownIssuer = report.cases.find((item) => item.case_id === 'unknown_issuer_profile_refused_before_service_mutation');
  const wrongPolicy = report.cases.find((item) => item.case_id === 'wrong_policy_profile_refused_before_service_mutation');
  const stale = report.cases.find((item) => item.case_id === 'stale_receipt_profile_refused_before_service_mutation');
  const requestStreamAuthority = report.cases.find((item) => item.case_id === 'request_stream_authority_material_profile_refused_before_service_mutation');
  const directApi = report.cases.find((item) => item.case_id === 'direct_api_profile_without_receipt_refused_before_service_mutation');
  const directApiWithReceipt = report.cases.find((item) => item.case_id === 'direct_api_profile_receipt_present_refused_before_service_mutation');
  const lines = [
    'ZLAR Protected Records Service Profile Preflight v1',
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Evidence model: ${report.evidence_model}; live probing=${report.live_probing}`,
    `Profile: id=${report.profile.profile_id}; status=${report.profile.profile_status}; posture=${report.deployment_posture}; sha256=${report.profile.profile_sha256}`,
    `Environment boundary: id=${report.environment_boundary.boundary_id}; process_boundary=${report.environment_boundary.service_process_boundary}; route=${report.environment_boundary.authoritative_route}; launcher_owned_config_required=${report.environment_boundary.launcher_owned_config_required}; request_stream_authority_material_allowed=${report.environment_boundary.request_stream_authority_material_allowed}; runtime_activation=${report.environment_boundary.runtime_activation}; live_profile_installed=${report.environment_boundary.live_profile_installed}`,
    `Recognized profile service write: accepted=${accepted.service_write_accepted}; reason=${accepted.reason_code}; state_delta=${accepted.state_entry_count_delta}; process=${accepted.process_invocation}`,
    `Replay after service restart: accepted=${replay.service_write_accepted}; reason=${replay.reason_code}; state_delta=${replay.state_entry_count_delta}; separate_process=${replay.separate_process_from_accepted}`,
    `Missing receipt: accepted=${missing.service_write_accepted}; reason=${missing.reason_code}; state_delta=${missing.state_entry_count_delta}`,
    `Unrecognized receipt: accepted=${unrecognized.service_write_accepted}; reason=${unrecognized.reason_code}; state_delta=${unrecognized.state_entry_count_delta}`,
    `Invalid receipt: accepted=${invalid.service_write_accepted}; reason=${invalid.reason_code}; state_delta=${invalid.state_entry_count_delta}`,
    `Unknown issuer: accepted=${unknownIssuer.service_write_accepted}; reason=${unknownIssuer.reason_code}; state_delta=${unknownIssuer.state_entry_count_delta}`,
    `Wrong policy: accepted=${wrongPolicy.service_write_accepted}; reason=${wrongPolicy.reason_code}; state_delta=${wrongPolicy.state_entry_count_delta}`,
    `Stale receipt: accepted=${stale.service_write_accepted}; reason=${stale.reason_code}; state_delta=${stale.state_entry_count_delta}`,
    `Request-stream authority material: accepted=${requestStreamAuthority.service_write_accepted}; reason=${requestStreamAuthority.reason_code}; state_delta=${requestStreamAuthority.state_entry_count_delta}`,
    `Fixture service API without receipt: accepted=${directApi.service_write_accepted}; reason=${directApi.reason_code}; state_delta=${directApi.state_entry_count_delta}; direct_api_attempted=${directApi.direct_api_attempted}`,
    `Fixture service API carrying receipt into without-receipt case: accepted=${directApiWithReceipt.service_write_accepted}; reason=${directApiWithReceipt.reason_code}; state_delta=${directApiWithReceipt.state_entry_count_delta}; direct_api_attempted=${directApiWithReceipt.direct_api_attempted}`,
    `Side-door report: launcher_owned_config_required=${report.side_door_report.launcher_owned_config_required}; request_stream_authority_material_refused=${report.side_door_report.request_stream_authority_material_refused}; request_stream_forbidden_fields_refused=${report.side_door_report.request_stream_forbidden_fields_refused}; direct_api_without_receipt_refused=${report.side_door_report.direct_api_without_receipt_refused}; direct_api_with_receipt_refused=${report.side_door_report.direct_api_with_receipt_refused}; direct_filesystem_write_to_fixture_paths_closed=${report.side_door_report.direct_filesystem_write_to_fixture_paths_closed}; production_records_service_checked=${report.side_door_report.production_records_service_checked}`,
    `Known open boundaries: ${report.known_open_boundaries.join(',')}`,
    'Non-claims:',
  ];
  for (const claim of report.non_claims) {
    lines.push(`- ${claim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsServiceProfileText(summary);
  return summary;
}
export function formatProtectedRecordsServiceProfilePreflightArtifactVerification(verification) {
  if (
    !verification ||
    verification.verification_type !==
      PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE
  ) {
    throw new Error('Protected records service profile preflight artifact verification has the wrong type');
  }
  if (verification.verified !== true) {
    throw new Error('Protected records service profile preflight artifact verification is not verified');
  }
  const lines = [
    'ZLAR Protected Records Service Profile Preflight Artifact Verification v1',
    `verified=${verification.verified}`,
    `artifact_type=${verification.artifact_type}`,
    `sha256=${verification.body_sha256}`,
    `payload_type=${verification.payload_type}`,
    `evidence_model=${verification.evidence_model}; live_probing=${verification.live_probing}`,
    `profile_sha256=${verification.profile_sha256}`,
    `cases=${verification.case_count}/${verification.required_case_count}`,
    `recognized_write_accepted=${verification.recognized_write_accepted}; replay_refused=${verification.replay_refused}; missing_receipt_refused=${verification.missing_receipt_refused}`,
    `invalid_receipt_refused=${verification.invalid_receipt_refused}; unknown_issuer_refused=${verification.unknown_issuer_refused}; wrong_policy_refused=${verification.wrong_policy_refused}; wrong_policy_reason=${verification.wrong_policy_reason}; wrong_policy_state_delta=${verification.wrong_policy_state_delta}; stale_receipt_refused=${verification.stale_receipt_refused}`,
    `launcher_owned_config_required=${verification.launcher_owned_config_required}; request_stream_authority_material_allowed=${verification.request_stream_authority_material_allowed}; request_stream_authority_material_refused=${verification.request_stream_authority_material_refused}; request_stream_authority_material_reason=${verification.request_stream_authority_material_reason}; request_stream_authority_material_state_delta=${verification.request_stream_authority_material_state_delta}`,
    `request_stream_forbidden_fields_refused=${verification.request_stream_forbidden_fields_refused}; direct_api_without_receipt_refused=${verification.direct_api_without_receipt_refused}; direct_api_without_receipt_reason=${verification.direct_api_without_receipt_reason}; direct_api_with_receipt_refused=${verification.direct_api_with_receipt_refused}; direct_api_receipt_present_reason=${verification.direct_api_receipt_present_reason}; direct_api_receipt_present_state_delta=${verification.direct_api_receipt_present_state_delta}`,
    `direct_filesystem_write_to_fixture_paths_closed=${verification.direct_filesystem_write_to_fixture_paths_closed}; live_profile_installed=${verification.live_profile_installed}; production_records_service_checked=${verification.production_records_service_checked}`,
    `external_attestation=${verification.external_attestation}; sovereign_recognition=${verification.sovereign_recognition}`,
    `claim_boundary=${verification.claim_boundary}`,
    'Non-claims:',
  ];
  for (const claim of verification.non_claims) {
    lines.push(`- ${claim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsServiceProfileText(summary);
  return summary;
}

export function formatProtectedRecordsServiceProfilePreflightArtifactSummary(artifact) {
  assertProtectedRecordsServiceProfilePreflightArtifact(artifact);
  const lines = [
    'Portable service profile preflight artifact:',
    `- type=${artifact.artifact_type}`,
    `- sha256=${artifact.integrity.body_sha256}`,
    `- hash_scope=${artifact.hash_scope}`,
  ];
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsServiceProfileText(summary);
  return summary;
}
