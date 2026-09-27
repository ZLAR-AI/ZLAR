import { canonicalize } from './canonicalize.mjs';
import {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed,
} from './protected-records-fixture-authority-status.mjs';
import { sha256hex } from './receipt.mjs';
import {
  NON_CLAIMS as RUNTIME_PROOF_NON_CLAIMS,
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  PROTECTED_RECORDS_RUNTIME_PROFILE_PROOF_TYPE,
  PROTECTED_RECORDS_RUNTIME_SERVICE_RESULT_TYPE,
  REQUIRED_RUNTIME_PROFILE_CASES,
  SAFE_CLAIM_CEILING as RUNTIME_PROOF_SAFE_CLAIM_CEILING,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
  assertProtectedRecordsRuntimeProfileProof,
  runProtectedRecordsRuntimeProfileProof,
} from './protected-records-runtime-profile.mjs';

export const PROTECTED_RECORDS_RUNTIME_PREFLIGHT_PROFILE_TYPE =
  'zlar-protected-records-runtime-profile-v1';
export const PROTECTED_RECORDS_RUNTIME_PROFILE_PREFLIGHT_TYPE =
  'zlar-protected-records-runtime-profile-preflight-v1';

export const REQUIRED_RUNTIME_PROFILE_BOUNDARY_OBSERVATIONS = Object.freeze([
  'preconsumed_authority_grant_without_runtime_state_refuses_reuse',
  'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse',
]);

export const REQUIRED_RUNTIME_PROFILE_OPEN_BOUNDARIES = Object.freeze([
  'host_process_or_memory_introspection',
  'live_records_system',
  'production_records_service',
  'exactly_once_effect_semantics',
  'store_anchor_and_witness_rollback_or_deletion',
  'store_anchor_witness_commit_atomicity',
  'host_filesystem_path_toctou',
  'anti_rollback_anchor_custody',
  'stale_lock_recovery',
  'multi_host_consumed_store_coordination',
  'production_durable_consumed_store',
  'persistent_runtime_profile_installation',
  'unrouted_records_paths',
]);

export const RUNTIME_PROFILE_PREFLIGHT_SAFE_CLAIM_CEILING =
  'ZLAR can preflight a sample protected-records runtime profile by validating required launcher-owned authority-grant inputs and grant-consumption storage boundaries, then running the local disposable runtime-profile proof where one records.write mutates only after receipt recognition, exact fixture-grant acceptance, and one-use grant consumption; malformed stores, invalid anchors or witnesses, rollback relative to the launcher-owned witness, grant appointment failures, replay, and agent-supplied authority material are refused before runtime-state mutation.';

export const RUNTIME_PROFILE_PREFLIGHT_NON_CLAIMS = Object.freeze([
  'This profile is a sample runtime-profile preflight profile, not an active or installed runtime profile.',
  'This preflight runs local disposable runtime-profile proof only.',
  'This profile declares launcher-owned authority-grant inputs as activation requirements; it contains no exact grant contract, appointment, issuance decision, authorized record update, issuer key, or grant window.',
  ...RUNTIME_PROOF_NON_CLAIMS,
]);

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

function proofCase(proof, caseId) {
  return proof.cases.find((item) => item.case_id === caseId);
}

function boundaryObservation(proof, observationId) {
  return proof.boundary_observations.find((item) => item.observation_id === observationId);
}

function runtimeContractFromProfile(profile) {
  return {
    action_class: profile.action_class,
    runtime_profile_id: profile.runtime_profile_id,
    runtime_environment: profile.runtime_environment,
    service_command: profile.service_command,
    proof_command: profile.proof_command,
    request_contract: profile.request_contract,
    recognition_boundary: profile.recognition_boundary,
    mutation_authoritative_route: profile.mutation_authoritative_route,
    state_storage: profile.state_storage,
    consumed_authority_grant_store: profile.consumed_authority_grant_store,
    consumption_identity: profile.consumption_identity,
    signed_payload_replay_identity: profile.signed_payload_replay_identity,
    consumed_store_lock: profile.consumed_store_lock,
    consumed_store_validation: profile.consumed_store_validation,
    consumed_store_anchor: profile.consumed_store_anchor,
    consumed_store_witness: profile.consumed_store_witness,
    consumed_store_rollback_detection: profile.consumed_store_rollback_detection,
    consumed_store_write_model: profile.consumed_store_write_model,
    replay_scope: profile.replay_scope,
  };
}

export function runtimeProfileSha256(profile) {
  assertProtectedRecordsRuntimePreflightProfile(profile);
  return sha256hex(canonicalize(profile));
}

export function assertProtectedRecordsRuntimePreflightProfile(profile) {
  assertExactKeys('Protected records runtime preflight profile', profile, [
    'action_class',
    'authority_boundary',
    'consumed_authority_grant_store',
    'consumption_identity',
    'consumed_store_anchor',
    'consumed_store_witness',
    'consumed_store_lock',
    'consumed_store_rollback_detection',
    'consumed_store_validation',
    'consumed_store_write_model',
    'deployment_posture',
    'known_open_boundaries',
    'mutation_authoritative_route',
    'non_claims',
    'profile_id',
    'profile_status',
    'profile_type',
    'proof_command',
    'proof_type',
    'recognition_boundary',
    'replay_scope',
    'request_contract',
    'required_boundary_observations',
    'required_cases',
    'result_type',
    'runtime_environment',
    'runtime_profile_id',
    'service_command',
    'signed_payload_replay_identity',
    'state_storage',
    'storage_boundary',
  ]);
  if (
    profile.profile_type !== PROTECTED_RECORDS_RUNTIME_PREFLIGHT_PROFILE_TYPE ||
    profile.profile_id !== 'protected-records-runtime-fixture-profile' ||
    profile.profile_status !== 'sample_not_active' ||
    profile.deployment_posture !== 'runtime_profile_preflight_only' ||
    profile.action_class !== 'records.write' ||
    profile.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    profile.runtime_environment !== 'local-disposable-jsonl-child-process' ||
    profile.service_command !== 'zlar protected-records-runtime-service --config <file>' ||
    profile.proof_command !== 'zlar protected-records-runtime-profile-proof' ||
    profile.result_type !== PROTECTED_RECORDS_RUNTIME_SERVICE_RESULT_TYPE ||
    profile.proof_type !== PROTECTED_RECORDS_RUNTIME_PROFILE_PROOF_TYPE ||
    profile.request_contract !== 'receipt-record-update-and-routing-metadata-only' ||
    profile.recognition_boundary !== 'service-configured-recognition-rule' ||
    profile.mutation_authoritative_route !==
      'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation' ||
    profile.state_storage !== 'process-private-memory' ||
    profile.consumed_authority_grant_store !==
      'persistent-single-use-authority-grant-contract-sha256-store' ||
    profile.consumption_identity !== 'authority-grant-contract-sha256' ||
    profile.signed_payload_replay_identity !== 'verified-signed-payload-sha256' ||
    profile.consumed_store_lock !== 'launcher-owned-per-store-lockfile' ||
    profile.consumed_store_validation !== 'exact-schema-unique-grant-contract-sha256s' ||
    profile.consumed_store_anchor !== 'launcher-owned-local-store-hash-anchor' ||
    profile.consumed_store_witness !== 'launcher-owned-local-store-hash-witness' ||
    profile.consumed_store_rollback_detection !==
      'single-host-anchor-and-witness-match-before-mutation' ||
    profile.consumed_store_write_model !==
      'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness' ||
    profile.replay_scope !==
      'helper-signed-payload-identity-and-persistent-authority-grant-contract-sha256'
  ) {
    throw new Error('Protected records runtime preflight profile contract drifted');
  }

  assertExactKeys('Protected records runtime preflight authority boundary', profile.authority_boundary, [
    'authority_grant_appointment_required_from_launcher',
    'authority_grant_contract_required_from_launcher',
    'authority_grant_issuance_decision_required_from_launcher',
    'authorized_record_update_required_from_launcher',
    'config_supplied_by_launcher',
    'consumed_grant_store_anchor_path_exposed_to_agent',
    'consumed_grant_store_witness_path_exposed_to_agent',
    'consumed_grants_path_exposed_to_agent',
    'fixture_mode_supplied_by_agent',
    'recognition_rule_supplied_by_agent',
    'request_stream_authority_material_accepted',
    'source_profile_authority_grant_present',
    'state_path_exposed_to_agent',
    'unsupported_request_fields_accepted',
  ]);
  const authority = profile.authority_boundary;
  if (
    authority.config_supplied_by_launcher !== true ||
    authority.authority_grant_contract_required_from_launcher !== true ||
    authority.authority_grant_appointment_required_from_launcher !== true ||
    authority.authority_grant_issuance_decision_required_from_launcher !== true ||
    authority.authorized_record_update_required_from_launcher !== true ||
    authority.source_profile_authority_grant_present !== false ||
    authority.request_stream_authority_material_accepted !== false ||
    authority.state_path_exposed_to_agent !== false ||
    authority.consumed_grants_path_exposed_to_agent !== false ||
    authority.consumed_grant_store_anchor_path_exposed_to_agent !== false ||
    authority.consumed_grant_store_witness_path_exposed_to_agent !== false ||
    authority.recognition_rule_supplied_by_agent !== false ||
    authority.fixture_mode_supplied_by_agent !== false ||
    authority.unsupported_request_fields_accepted !== false
  ) {
    throw new Error('Protected records runtime preflight authority boundary drifted');
  }

  assertExactKeys('Protected records runtime preflight storage boundary', profile.storage_boundary, [
    'atomic_store_anchor_witness_commit',
    'exactly_once_effect_semantics',
    'host_filesystem_path_toctou_closed',
    'local_anchor_owned_by_launcher',
    'local_witness_owned_by_launcher',
    'lockfile_owned_by_launcher',
    'multi_host_coordination',
    'partial_commit_witness_missing_observed',
    'partial_grant_commit_burn_window_named',
    'persistent_consumed_authority_grant_store',
    'production_grade_anti_rollback',
    'production_grade_durable_storage',
    'single_host_rollback_detection',
    'stale_lock_recovery',
    'store_and_anchor_joint_rollback_refused_while_witness_ahead',
    'store_anchor_and_witness_joint_rollback_detection',
    'tamper_resistance',
  ]);
  const storage = profile.storage_boundary;
  if (
    storage.persistent_consumed_authority_grant_store !== true ||
    storage.lockfile_owned_by_launcher !== true ||
    storage.local_anchor_owned_by_launcher !== true ||
    storage.local_witness_owned_by_launcher !== true ||
    storage.single_host_rollback_detection !== true ||
    storage.store_and_anchor_joint_rollback_refused_while_witness_ahead !== true ||
    storage.store_anchor_and_witness_joint_rollback_detection !== false ||
    storage.atomic_store_anchor_witness_commit !== false ||
    storage.partial_grant_commit_burn_window_named !== true ||
    storage.partial_commit_witness_missing_observed !== true ||
    storage.host_filesystem_path_toctou_closed !== false ||
    storage.production_grade_anti_rollback !== false ||
    storage.production_grade_durable_storage !== false ||
    storage.stale_lock_recovery !== false ||
    storage.multi_host_coordination !== false ||
    storage.tamper_resistance !== false ||
    storage.exactly_once_effect_semantics !== false
  ) {
    throw new Error('Protected records runtime preflight storage boundary drifted');
  }

  assertExactArray('Protected records runtime preflight required cases', profile.required_cases, REQUIRED_RUNTIME_PROFILE_CASES);
  assertExactArray('Protected records runtime preflight required boundary observations', profile.required_boundary_observations, REQUIRED_RUNTIME_PROFILE_BOUNDARY_OBSERVATIONS);
  assertExactArray('Protected records runtime preflight open boundaries', profile.known_open_boundaries, REQUIRED_RUNTIME_PROFILE_OPEN_BOUNDARIES);
  assertExactArray('Protected records runtime preflight non-claims', profile.non_claims, RUNTIME_PROFILE_PREFLIGHT_NON_CLAIMS);
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(profile));
  return true;
}

export function runProtectedRecordsRuntimeProfilePreflight(profile) {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
    'Protected records runtime-profile preflight proof generation',
  );
  assertProtectedRecordsRuntimePreflightProfile(profile);
  const proof = runProtectedRecordsRuntimeProfileProof();
  assertProtectedRecordsRuntimeProfileProof(proof);

  const accepted = proofCase(proof, 'recognized_runtime_write_first_request');
  const restartReplay = proofCase(proof, 'replay_runtime_write_refused_after_service_restart');
  const invalidStore = proofCase(proof, 'invalid_consumed_store_refused_before_runtime_mutation');
  const invalidAnchor = proofCase(proof, 'invalid_consumed_store_anchor_refused_before_runtime_mutation');
  const rollback = proofCase(proof, 'valid_consumed_store_rollback_refused_before_runtime_mutation');
  const deletion = proofCase(proof, 'consumed_store_deletion_refused_before_runtime_mutation');
  const replacement = proofCase(proof, 'valid_consumed_store_replacement_refused_before_runtime_mutation');
  const witnessCommitFailure = proofCase(
    proof,
    'witness_commit_failed_after_authority_grant_store_commit'
  );
  const witnessRollback = proofCase(
    proof,
    'store_and_anchor_joint_rollback_refused_against_witness_before_runtime_mutation'
  );
  const missingGrantAppointment = proofCase(
    proof,
    'missing_authority_grant_appointment_refused_before_consumption'
  );
  const mismatchedGrantAppointment = proofCase(
    proof,
    'mismatched_authority_grant_appointment_refused_before_consumption'
  );
  const revokedGrant = proofCase(
    proof,
    'revoked_authority_grant_refused_before_consumption'
  );
  const expiredGrant = proofCase(
    proof,
    'expired_authority_grant_refused_before_consumption'
  );
  const requestSuppliedGrant = proofCase(
    proof,
    'agent_supplied_authority_grant_refused_before_runtime_mutation'
  );
  const authorityCases = proof.cases.filter((item) => item.case_id.startsWith('agent_supplied_'));
  const jointRollback = boundaryObservation(
    proof,
    'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse'
  );
  const identityPolicy = proof.runtime_profile_identity_policy;

  const report = {
    preflight_type: PROTECTED_RECORDS_RUNTIME_PROFILE_PREFLIGHT_TYPE,
    evidence_model: 'local-disposable-runtime-profile-preflight-fixture',
    live_probing: false,
    safe_claim_ceiling: RUNTIME_PROFILE_PREFLIGHT_SAFE_CLAIM_CEILING,
    deployment_posture: profile.deployment_posture,
    profile: {
      profile_type: profile.profile_type,
      profile_id: profile.profile_id,
      profile_status: profile.profile_status,
      profile_sha256: runtimeProfileSha256(profile),
      runtime_profile_id: profile.runtime_profile_id,
    },
    runtime_profile_contract: runtimeContractFromProfile(profile),
    authority_boundary: { ...profile.authority_boundary },
    storage_boundary: { ...profile.storage_boundary },
    proof_summary: {
      proof_command: profile.proof_command,
      proof_type: proof.proof_type,
      proof_run_in_preflight: true,
      proof_safe_claim_ceiling: RUNTIME_PROOF_SAFE_CLAIM_CEILING,
      proof_evidence_model: proof.evidence_model,
      proof_case_count: proof.cases.length,
      proof_required_case_count: profile.required_cases.length,
      proof_boundary_observation_count: proof.boundary_observations.length,
      proof_required_boundary_observation_count: profile.required_boundary_observations.length,
      recognized_write_accepted: accepted.service_write_accepted === true,
      replay_after_restart_refused: restartReplay.service_write_accepted === false,
      invalid_consumed_store_refused: invalidStore.service_write_accepted === false,
      invalid_consumed_store_anchor_refused: invalidAnchor.service_write_accepted === false,
      consumed_store_rollback_refused: rollback.service_write_accepted === false,
      consumed_store_deletion_refused: deletion.service_write_accepted === false,
      consumed_store_replacement_refused: replacement.service_write_accepted === false,
      witness_commit_failed_after_authority_grant_store_commit:
        witnessCommitFailure.service_write_accepted === false,
      witness_commit_failure_reason_code: witnessCommitFailure.reason_code,
      witness_commit_failure_consumed_authority_grant_count:
        witnessCommitFailure.consumed_authority_grant_count,
      store_and_anchor_joint_rollback_refused_against_witness:
        witnessRollback.service_write_accepted === false,
      missing_authority_grant_appointment_refused:
        missingGrantAppointment.service_write_accepted === false,
      mismatched_authority_grant_appointment_refused:
        mismatchedGrantAppointment.service_write_accepted === false,
      revoked_authority_grant_refused: revokedGrant.service_write_accepted === false,
      expired_authority_grant_refused: expiredGrant.service_write_accepted === false,
      request_supplied_authority_grant_refused:
        requestSuppliedGrant.service_write_accepted === false,
      agent_supplied_authority_material_refused:
        authorityCases.length === 6 &&
        authorityCases.every((item) => item.service_write_accepted === false && item.reason_code === 'agent_supplied_authority_material'),
      runtime_profile_identity_authority_source: identityPolicy.authority_source,
      runtime_profile_identity_request_stream_policy: identityPolicy.request_stream_policy,
      request_runtime_profile_id_required: identityPolicy.request_runtime_profile_id_required,
      omitted_request_runtime_profile_id_present:
        identityPolicy.omitted_request_runtime_profile_id_present,
      omitted_runtime_profile_id_uses_launcher_config:
        identityPolicy.omitted_runtime_profile_id_uses_launcher_config,
      omitted_runtime_profile_id_reason_code: identityPolicy.omitted_runtime_profile_id_reason_code,
      omitted_runtime_profile_id_state_entry_count_delta:
        identityPolicy.omitted_runtime_profile_id_state_entry_count_delta,
      omitted_runtime_profile_id_consumed_authority_grant_count:
        identityPolicy.omitted_runtime_profile_id_consumed_authority_grant_count,
      supplied_mismatched_runtime_profile_id_refused:
        identityPolicy.supplied_mismatched_runtime_profile_id_refused,
      supplied_mismatch_reason_code: identityPolicy.supplied_mismatch_reason_code,
      supplied_mismatch_state_entry_count_delta:
        identityPolicy.supplied_mismatch_state_entry_count_delta,
      store_and_anchor_joint_rollback_refused_while_witness_ahead:
        proof.side_door_report.store_and_anchor_joint_rollback_refused_while_witness_ahead,
      store_anchor_and_witness_joint_rollback_detection:
        proof.side_door_report.store_anchor_and_witness_joint_rollback_detection,
      store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse:
        jointRollback.service_write_accepted === true,
      persistent_runtime_profile_installed: proof.side_door_report.persistent_runtime_profile_installed,
      live_probing: proof.live_probing,
    },
    side_door_report: {
      state_path_exposed_to_agent: proof.side_door_report.state_path_exposed_to_agent,
      consumed_grants_path_exposed_to_agent: false,
      consumed_grant_store_anchor_path_exposed_to_agent: false,
      consumed_grant_store_witness_path_exposed_to_agent: false,
      recognition_rule_supplied_by_agent: proof.side_door_report.recognition_rule_supplied_by_agent,
      agent_supplied_authority_material_refused: authorityCases.length === 6,
      request_supplied_authority_grant_refused:
        requestSuppliedGrant.service_write_accepted === false,
      unsupported_request_field_refused: proof.side_door_report.unsupported_request_field_refused,
      persistent_consumed_authority_grant_store:
        proof.side_door_report.persistent_consumed_authority_grant_store,
      consumed_store_anchor_present: proof.side_door_report.consumed_store_anchor_present,
      consumed_store_witness_present: proof.side_door_report.consumed_store_witness_present,
      single_host_consumed_store_rollback_detection: proof.side_door_report.single_host_consumed_store_rollback_detection,
      store_and_anchor_joint_rollback_refused_while_witness_ahead:
        proof.side_door_report.store_and_anchor_joint_rollback_refused_while_witness_ahead,
      store_anchor_and_witness_joint_rollback_detection:
        proof.side_door_report.store_anchor_and_witness_joint_rollback_detection,
      store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse:
        proof.side_door_report
          .store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse,
      atomic_store_anchor_witness_commit:
        proof.side_door_report.atomic_store_anchor_witness_commit,
      partial_grant_commit_burn_window_named:
        proof.side_door_report.partial_grant_commit_burn_window_named,
      partial_commit_witness_missing_observed:
        proof.side_door_report.partial_commit_witness_missing_observed,
      host_filesystem_path_toctou_closed:
        proof.side_door_report.host_filesystem_path_toctou_closed,
      exactly_once_effect_semantics: proof.side_door_report.exactly_once_effect_semantics,
      persistent_runtime_profile_installed: proof.side_door_report.persistent_runtime_profile_installed,
      live_records_system_checked: proof.side_door_report.live_records_system_checked,
      production_records_service_checked: proof.side_door_report.production_records_service_checked,
      live_approval_channel_health_checked: false,
      live_mcp_coverage_checked: false,
      external_attestation: proof.side_door_report.external_attestation,
      sovereign_recognition: proof.side_door_report.sovereign_recognition,
      unrouted_records_paths_checked: proof.side_door_report.unrouted_records_paths_checked,
    },
    known_open_boundaries: [...profile.known_open_boundaries],
    non_claims: [...RUNTIME_PROFILE_PREFLIGHT_NON_CLAIMS],
  };
  assertProtectedRecordsRuntimeProfilePreflight(report, profile);
  return report;
}

export function assertProtectedRecordsRuntimeProfilePreflight(report, profile) {
  assertProtectedRecordsRuntimePreflightProfile(profile);
  assertExactKeys('Protected records runtime profile preflight', report, [
    'authority_boundary',
    'deployment_posture',
    'evidence_model',
    'known_open_boundaries',
    'live_probing',
    'non_claims',
    'preflight_type',
    'profile',
    'proof_summary',
    'runtime_profile_contract',
    'safe_claim_ceiling',
    'side_door_report',
    'storage_boundary',
  ]);
  if (
    report.preflight_type !== PROTECTED_RECORDS_RUNTIME_PROFILE_PREFLIGHT_TYPE ||
    report.evidence_model !== 'local-disposable-runtime-profile-preflight-fixture' ||
    report.live_probing !== false ||
    report.safe_claim_ceiling !== RUNTIME_PROFILE_PREFLIGHT_SAFE_CLAIM_CEILING ||
    report.deployment_posture !== 'runtime_profile_preflight_only'
  ) {
    throw new Error('Protected records runtime profile preflight top-level contract drifted');
  }

  assertExactKeys('Protected records runtime profile preflight profile', report.profile, [
    'profile_id',
    'profile_sha256',
    'profile_status',
    'profile_type',
    'runtime_profile_id',
  ]);
  if (
    report.profile.profile_type !== profile.profile_type ||
    report.profile.profile_id !== profile.profile_id ||
    report.profile.profile_status !== profile.profile_status ||
    report.profile.runtime_profile_id !== profile.runtime_profile_id ||
    report.profile.profile_sha256 !== runtimeProfileSha256(profile)
  ) {
    throw new Error('Protected records runtime profile preflight profile identity drifted');
  }

  assertExactKeys('Protected records runtime profile preflight contract', report.runtime_profile_contract, [
    'action_class',
    'consumed_authority_grant_store',
    'consumption_identity',
    'consumed_store_anchor',
    'consumed_store_lock',
    'consumed_store_rollback_detection',
    'consumed_store_validation',
    'consumed_store_witness',
    'consumed_store_write_model',
    'mutation_authoritative_route',
    'proof_command',
    'recognition_boundary',
    'replay_scope',
    'request_contract',
    'runtime_environment',
    'runtime_profile_id',
    'service_command',
    'signed_payload_replay_identity',
    'state_storage',
  ]);
  if (canonicalize(report.runtime_profile_contract) !== canonicalize(runtimeContractFromProfile(profile))) {
    throw new Error('Protected records runtime profile preflight contract drifted');
  }
  if (canonicalize(report.authority_boundary) !== canonicalize(profile.authority_boundary)) {
    throw new Error('Protected records runtime profile preflight authority boundary drifted');
  }
  if (canonicalize(report.storage_boundary) !== canonicalize(profile.storage_boundary)) {
    throw new Error('Protected records runtime profile preflight storage boundary drifted');
  }

  assertExactKeys('Protected records runtime profile preflight proof summary', report.proof_summary, [
    'agent_supplied_authority_material_refused',
    'consumed_store_deletion_refused',
    'consumed_store_replacement_refused',
    'consumed_store_rollback_refused',
    'expired_authority_grant_refused',
    'invalid_consumed_store_anchor_refused',
    'invalid_consumed_store_refused',
    'live_probing',
    'mismatched_authority_grant_appointment_refused',
    'missing_authority_grant_appointment_refused',
    'omitted_request_runtime_profile_id_present',
    'omitted_runtime_profile_id_consumed_authority_grant_count',
    'omitted_runtime_profile_id_reason_code',
    'omitted_runtime_profile_id_state_entry_count_delta',
    'omitted_runtime_profile_id_uses_launcher_config',
    'persistent_runtime_profile_installed',
    'proof_boundary_observation_count',
    'proof_case_count',
    'proof_command',
    'proof_evidence_model',
    'proof_required_boundary_observation_count',
    'proof_required_case_count',
    'proof_run_in_preflight',
    'proof_safe_claim_ceiling',
    'proof_type',
    'recognized_write_accepted',
    'request_supplied_authority_grant_refused',
    'request_runtime_profile_id_required',
    'replay_after_restart_refused',
    'revoked_authority_grant_refused',
    'runtime_profile_identity_authority_source',
    'runtime_profile_identity_request_stream_policy',
    'store_and_anchor_joint_rollback_refused_against_witness',
    'store_and_anchor_joint_rollback_refused_while_witness_ahead',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse',
    'supplied_mismatch_reason_code',
    'supplied_mismatch_state_entry_count_delta',
    'supplied_mismatched_runtime_profile_id_refused',
    'witness_commit_failed_after_authority_grant_store_commit',
    'witness_commit_failure_consumed_authority_grant_count',
    'witness_commit_failure_reason_code',
  ]);
  if (
    report.proof_summary.proof_command !== profile.proof_command ||
    report.proof_summary.proof_type !== PROTECTED_RECORDS_RUNTIME_PROFILE_PROOF_TYPE ||
    report.proof_summary.proof_run_in_preflight !== true ||
    report.proof_summary.proof_safe_claim_ceiling !== RUNTIME_PROOF_SAFE_CLAIM_CEILING ||
    report.proof_summary.proof_evidence_model !== 'local-disposable-runtime-process-profile' ||
    report.proof_summary.proof_case_count !== REQUIRED_RUNTIME_PROFILE_CASES.length ||
    report.proof_summary.proof_required_case_count !== profile.required_cases.length ||
    report.proof_summary.proof_boundary_observation_count !== REQUIRED_RUNTIME_PROFILE_BOUNDARY_OBSERVATIONS.length ||
    report.proof_summary.proof_required_boundary_observation_count !== profile.required_boundary_observations.length ||
    report.proof_summary.recognized_write_accepted !== true ||
    report.proof_summary.replay_after_restart_refused !== true ||
    report.proof_summary.invalid_consumed_store_refused !== true ||
    report.proof_summary.invalid_consumed_store_anchor_refused !== true ||
    report.proof_summary.consumed_store_rollback_refused !== true ||
    report.proof_summary.consumed_store_deletion_refused !== true ||
    report.proof_summary.consumed_store_replacement_refused !== true ||
    report.proof_summary.witness_commit_failed_after_authority_grant_store_commit !== true ||
    report.proof_summary.witness_commit_failure_reason_code !==
      'consumed_store_write_failed_after_grant_commit' ||
    report.proof_summary.witness_commit_failure_consumed_authority_grant_count !== 1 ||
    report.proof_summary.store_and_anchor_joint_rollback_refused_against_witness !== true ||
    report.proof_summary.missing_authority_grant_appointment_refused !== true ||
    report.proof_summary.mismatched_authority_grant_appointment_refused !== true ||
    report.proof_summary.revoked_authority_grant_refused !== true ||
    report.proof_summary.expired_authority_grant_refused !== true ||
    report.proof_summary.request_supplied_authority_grant_refused !== true ||
    report.proof_summary.agent_supplied_authority_material_refused !== true ||
    report.proof_summary.runtime_profile_identity_authority_source !==
      'launcher-owned-service-config' ||
    report.proof_summary.runtime_profile_identity_request_stream_policy !==
      'runtime_profile_id_may_be_omitted_but_if_supplied_must_match_config' ||
    report.proof_summary.request_runtime_profile_id_required !== false ||
    report.proof_summary.omitted_request_runtime_profile_id_present !== false ||
    report.proof_summary.omitted_runtime_profile_id_uses_launcher_config !== true ||
    report.proof_summary.omitted_runtime_profile_id_reason_code !==
      'fixture_authority_grant_effect_satisfied' ||
    report.proof_summary.omitted_runtime_profile_id_state_entry_count_delta !== 1 ||
    report.proof_summary.omitted_runtime_profile_id_consumed_authority_grant_count !== 1 ||
    report.proof_summary.supplied_mismatched_runtime_profile_id_refused !== true ||
    report.proof_summary.supplied_mismatch_reason_code !== 'agent_supplied_authority_material' ||
    report.proof_summary.supplied_mismatch_state_entry_count_delta !== 0 ||
    report.proof_summary.store_and_anchor_joint_rollback_refused_while_witness_ahead !== true ||
    report.proof_summary.store_anchor_and_witness_joint_rollback_detection !== false ||
    report.proof_summary.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse !== true ||
    report.proof_summary.persistent_runtime_profile_installed !== false ||
    report.proof_summary.live_probing !== false
  ) {
    throw new Error('Protected records runtime profile preflight proof summary drifted');
  }

  assertExactKeys('Protected records runtime profile preflight side-door report', report.side_door_report, [
    'agent_supplied_authority_material_refused',
    'atomic_store_anchor_witness_commit',
    'consumed_grant_store_anchor_path_exposed_to_agent',
    'consumed_grant_store_witness_path_exposed_to_agent',
    'consumed_grants_path_exposed_to_agent',
    'consumed_store_anchor_present',
    'consumed_store_witness_present',
    'exactly_once_effect_semantics',
    'external_attestation',
    'host_filesystem_path_toctou_closed',
    'live_approval_channel_health_checked',
    'live_mcp_coverage_checked',
    'live_records_system_checked',
    'persistent_consumed_authority_grant_store',
    'partial_commit_witness_missing_observed',
    'partial_grant_commit_burn_window_named',
    'persistent_runtime_profile_installed',
    'production_records_service_checked',
    'recognition_rule_supplied_by_agent',
    'request_supplied_authority_grant_refused',
    'single_host_consumed_store_rollback_detection',
    'sovereign_recognition',
    'state_path_exposed_to_agent',
    'store_and_anchor_joint_rollback_refused_while_witness_ahead',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse',
    'unsupported_request_field_refused',
    'unrouted_records_paths_checked',
  ]);
  if (
    report.side_door_report.state_path_exposed_to_agent !== false ||
    report.side_door_report.consumed_grants_path_exposed_to_agent !== false ||
    report.side_door_report.consumed_grant_store_anchor_path_exposed_to_agent !== false ||
    report.side_door_report.consumed_grant_store_witness_path_exposed_to_agent !== false ||
    report.side_door_report.recognition_rule_supplied_by_agent !== false ||
    report.side_door_report.agent_supplied_authority_material_refused !== true ||
    report.side_door_report.atomic_store_anchor_witness_commit !== false ||
    report.side_door_report.request_supplied_authority_grant_refused !== true ||
    report.side_door_report.unsupported_request_field_refused !== true ||
    report.side_door_report.persistent_consumed_authority_grant_store !== true ||
    report.side_door_report.partial_grant_commit_burn_window_named !== true ||
    report.side_door_report.partial_commit_witness_missing_observed !== true ||
    report.side_door_report.consumed_store_anchor_present !== true ||
    report.side_door_report.consumed_store_witness_present !== true ||
    report.side_door_report.single_host_consumed_store_rollback_detection !== true ||
    report.side_door_report.store_and_anchor_joint_rollback_refused_while_witness_ahead !== true ||
    report.side_door_report.store_anchor_and_witness_joint_rollback_detection !== false ||
    report.side_door_report.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse !== true ||
    report.side_door_report.exactly_once_effect_semantics !== false ||
    report.side_door_report.persistent_runtime_profile_installed !== false ||
    report.side_door_report.live_records_system_checked !== false ||
    report.side_door_report.production_records_service_checked !== false ||
    report.side_door_report.live_approval_channel_health_checked !== false ||
    report.side_door_report.live_mcp_coverage_checked !== false ||
    report.side_door_report.host_filesystem_path_toctou_closed !== false ||
    report.side_door_report.external_attestation !== false ||
    report.side_door_report.sovereign_recognition !== false ||
    report.side_door_report.unrouted_records_paths_checked !== false
  ) {
    throw new Error('Protected records runtime profile preflight side-door report drifted');
  }

  assertExactArray('Protected records runtime profile preflight open boundaries', report.known_open_boundaries, REQUIRED_RUNTIME_PROFILE_OPEN_BOUNDARIES);
  assertExactArray('Protected records runtime profile preflight non-claims', report.non_claims, RUNTIME_PROFILE_PREFLIGHT_NON_CLAIMS);
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return true;
}

export function formatProtectedRecordsRuntimeProfilePreflightSummary(report, profile) {
  assertProtectedRecordsRuntimeProfilePreflight(report, profile);
  const lines = [
    'ZLAR Protected Records Runtime Profile Preflight v1',
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Evidence model: ${report.evidence_model}; live probing=${report.live_probing}`,
    `Profile: id=${report.profile.profile_id}; runtime_profile=${report.profile.runtime_profile_id}; status=${report.profile.profile_status}; posture=${report.deployment_posture}; sha256=${report.profile.profile_sha256}`,
    `Runtime contract: service_command=${report.runtime_profile_contract.service_command}; proof_command=${report.runtime_profile_contract.proof_command}; request_contract=${report.runtime_profile_contract.request_contract}; mutation_route=${report.runtime_profile_contract.mutation_authoritative_route}`,
    `Authority boundary: launcher_config=${report.authority_boundary.config_supplied_by_launcher}; grant_contract_required=${report.authority_boundary.authority_grant_contract_required_from_launcher}; grant_appointment_required=${report.authority_boundary.authority_grant_appointment_required_from_launcher}; issuance_decision_required=${report.authority_boundary.authority_grant_issuance_decision_required_from_launcher}; authorized_record_update_required=${report.authority_boundary.authorized_record_update_required_from_launcher}; source_profile_authority_grant_present=${report.authority_boundary.source_profile_authority_grant_present}; request_authority_material_accepted=${report.authority_boundary.request_stream_authority_material_accepted}; state_path_exposed_to_agent=${report.authority_boundary.state_path_exposed_to_agent}; consumed_grant_store_anchor_path_exposed_to_agent=${report.authority_boundary.consumed_grant_store_anchor_path_exposed_to_agent}; consumed_grant_store_witness_path_exposed_to_agent=${report.authority_boundary.consumed_grant_store_witness_path_exposed_to_agent}; recognition_rule_supplied_by_agent=${report.authority_boundary.recognition_rule_supplied_by_agent}`,
    `Storage boundary: consumed_authority_grant_store=${report.runtime_profile_contract.consumed_authority_grant_store}; consumption_identity=${report.runtime_profile_contract.consumption_identity}; signed_payload_replay_identity=${report.runtime_profile_contract.signed_payload_replay_identity}; lock=${report.runtime_profile_contract.consumed_store_lock}; anchor=${report.runtime_profile_contract.consumed_store_anchor}; witness=${report.runtime_profile_contract.consumed_store_witness}; rollback_detection=${report.runtime_profile_contract.consumed_store_rollback_detection}; store_anchor_and_witness_joint_rollback_detection=${report.storage_boundary.store_anchor_and_witness_joint_rollback_detection}`,
    `Proof summary: run_in_preflight=${report.proof_summary.proof_run_in_preflight}; cases=${report.proof_summary.proof_case_count}/${report.proof_summary.proof_required_case_count}; boundary_observations=${report.proof_summary.proof_boundary_observation_count}/${report.proof_summary.proof_required_boundary_observation_count}; recognized_write_accepted=${report.proof_summary.recognized_write_accepted}; replay_after_restart_refused=${report.proof_summary.replay_after_restart_refused}`,
    `Runtime profile identity policy: authority_source=${report.proof_summary.runtime_profile_identity_authority_source}; request_runtime_profile_id_required=${report.proof_summary.request_runtime_profile_id_required}; omitted_request_field_present=${report.proof_summary.omitted_request_runtime_profile_id_present}; omitted_uses_launcher_config=${report.proof_summary.omitted_runtime_profile_id_uses_launcher_config}; supplied_mismatch_refused=${report.proof_summary.supplied_mismatched_runtime_profile_id_refused}`,
    `Consumed-store checks: invalid_store_refused=${report.proof_summary.invalid_consumed_store_refused}; invalid_anchor_refused=${report.proof_summary.invalid_consumed_store_anchor_refused}; rollback_refused=${report.proof_summary.consumed_store_rollback_refused}; deletion_refused=${report.proof_summary.consumed_store_deletion_refused}; replacement_refused=${report.proof_summary.consumed_store_replacement_refused}`,
    `Partial grant commit: witness_commit_refused=${report.proof_summary.witness_commit_failed_after_authority_grant_store_commit}; reason=${report.proof_summary.witness_commit_failure_reason_code}; consumed_grant_count=${report.proof_summary.witness_commit_failure_consumed_authority_grant_count}; atomic_store_anchor_witness_commit=${report.side_door_report.atomic_store_anchor_witness_commit}; burn_window_named=${report.side_door_report.partial_grant_commit_burn_window_named}`,
    `Grant checks: store_and_anchor_joint_rollback_refused_against_witness=${report.proof_summary.store_and_anchor_joint_rollback_refused_against_witness}; missing_appointment_refused=${report.proof_summary.missing_authority_grant_appointment_refused}; mismatched_appointment_refused=${report.proof_summary.mismatched_authority_grant_appointment_refused}; revoked_refused=${report.proof_summary.revoked_authority_grant_refused}; expired_refused=${report.proof_summary.expired_authority_grant_refused}; request_supplied_grant_refused=${report.proof_summary.request_supplied_authority_grant_refused}`,
    `Residual boundary: store_and_anchor_joint_rollback_refused_while_witness_ahead=${report.proof_summary.store_and_anchor_joint_rollback_refused_while_witness_ahead}; store_anchor_and_witness_joint_rollback_detection=${report.proof_summary.store_anchor_and_witness_joint_rollback_detection}; store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse=${report.proof_summary.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse}; persistent_runtime_profile_installed=${report.proof_summary.persistent_runtime_profile_installed}`,
    `Side-door report: state_path_exposed_to_agent=${report.side_door_report.state_path_exposed_to_agent}; agent_supplied_authority_material_refused=${report.side_door_report.agent_supplied_authority_material_refused}; persistent_consumed_authority_grant_store=${report.side_door_report.persistent_consumed_authority_grant_store}; consumed_store_anchor_present=${report.side_door_report.consumed_store_anchor_present}; consumed_store_witness_present=${report.side_door_report.consumed_store_witness_present}; production_records_service_checked=${report.side_door_report.production_records_service_checked}; live_records_system_checked=${report.side_door_report.live_records_system_checked}`,
    `Known open boundaries: ${report.known_open_boundaries.join(',')}`,
    'Non-claims:',
  ];
  for (const claim of report.non_claims) {
    lines.push(`- ${claim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(summary);
  return summary;
}
