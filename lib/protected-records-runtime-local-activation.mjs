import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonicalize } from './canonicalize.mjs';
import {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed,
  PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256,
  PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_STATUS,
  protectedRecordsFixtureAuthorityGrantEffectStatusReason,
} from './protected-records-fixture-authority-status.mjs';
import { sha256hex } from './receipt.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
  assertProtectedRecordsRuntimeProfileProof,
  runProtectedRecordsRuntimeProfileProof,
} from './protected-records-runtime-profile.mjs';
import {
  assertProtectedRecordsRuntimePreflightProfile,
  runtimeProfileSha256,
} from './protected-records-runtime-profile-preflight.mjs';

export const PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PLAN_TYPE =
  'zlar-protected-records-runtime-local-activation-plan-v1';
export const PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PROOF_TYPE =
  'zlar-protected-records-runtime-local-activation-proof-v1';
export const PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_TYPE =
  'zlar-protected-records-runtime-local-activation-artifact-v1';
export const PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_CANONICALIZATION =
  'zlar-canonical-json-v1';
export const PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_VERIFICATION_TYPE =
  'zlar-protected-records-runtime-local-activation-artifact-verification-v1';

export const REQUIRED_RUNTIME_LOCAL_ACTIVATION_OPERATOR_REQUIREMENTS = Object.freeze([
  'explicit_local_activation_command',
  'profile_sha_verified_before_activation',
  'launcher_owned_disposable_config_written_outside_request_stream',
  'launcher_owned_authority_grant_inputs_supplied_outside_request_stream',
  'downstream_refuses_missing_or_unrecognized_receipts',
  'authority_grant_refusals_before_consumption_and_mutation',
  'non_atomic_burn_joint_rollback_and_toctou_boundaries_accepted',
]);

export const REQUIRED_RUNTIME_LOCAL_ACTIVATION_OPEN_BOUNDARIES = Object.freeze([
  'local_activation_only',
  'persistent_runtime_profile_installation',
  'hook_configuration',
  'live_runtime_profile',
  'live_records_system',
  'production_records_service',
  'current_machine_governance',
  'live_mcp_coverage',
  'live_approval_channel_health',
  'exactly_once_effect_semantics',
  'store_anchor_witness_commit_atomicity',
  'store_anchor_and_witness_joint_rollback_or_deletion',
  'host_filesystem_path_toctou',
  'host_process_or_memory_introspection',
  'external_attestation',
  'sovereign_recognition',
  'unrouted_records_paths',
]);

export const RUNTIME_LOCAL_ACTIVATION_SAFE_CLAIM_CEILING =
  'ZLAR can run an explicit local disposable protected-records runtime activation fixture that verifies a pinned runtime-profile SHA, writes only launcher-owned disposable config inside the proof harness, starts local JSONL child-service processes, accepts one fixture-authorized records.write, separates same-process signed-payload replay from restart consumed-grant refusal, exercises missing, mismatched, revoked, expired, and request-supplied grant refusals, and names the witness, non-atomic burn, joint rollback, and host-path TOCTOU boundaries.';

export const RUNTIME_LOCAL_ACTIVATION_NON_CLAIMS = Object.freeze([
  'This proof is a local disposable runtime activation proof, not a persistent install or production deployment.',
  'This proof writes only launcher-owned disposable runtime config inside the proof harness; it does not modify hooks, user config, machine configuration, or production configuration.',
  'This proof starts local JSONL child service processes only; it does not start or inspect a live records system or production records service.',
  'This proof does not use Telegram or prove live human approval-channel delivery.',
  'This proof does not prove current-machine governance, live MCP coverage, external attestation, enterprise readiness, production authority, sovereign recognition, or coverage of unrouted surfaces.',
  'This proof does not prove exactly-once effects or an all-or-nothing store, anchor, and witness commit; state-append or metadata failure after grant-store commit can burn the one-use grant without runtime-state mutation.',
  'This proof does not detect rollback, deletion, or replacement when the consumed-authority-grant store, local anchor, and local witness move together without stronger custody or an external witness.',
  'This proof does not prove production durable storage, stale-lock recovery, multi-host coordination, tamper resistance, or external anti-rollback custody.',
  'This proof does not close host process, memory, debugger, operator filesystem, post-validation path-replacement, hook-configuration, or unrouted records side doors.',
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
  for (let i = 0; i < expected.length; i++) {
    if (value[i] !== expected[i]) {
      throw new Error(`${label} drifted`);
    }
  }
  return true;
}

function proofCase(proof, caseId) {
  const item = proof.cases.find((candidate) => candidate.case_id === caseId);
  if (!item) {
    throw new Error(`Runtime local activation proof missing case ${caseId}`);
  }
  return item;
}

function caseSummary(item) {
  return {
    case_id: item.case_id,
    service_process_invocation: item.service_process_invocation,
    request_ordinal: item.request_ordinal,
    service_write_accepted: item.service_write_accepted,
    reason_code: item.reason_code,
    state_entry_count_delta: item.state_entry_count_delta,
    consumed_authority_grant_count: item.consumed_authority_grant_count,
    direct_api_attempted: item.direct_api_attempted,
  };
}

export function runtimeLocalActivationPlanSha256(plan) {
  assertProtectedRecordsRuntimeLocalActivationPlan(plan);
  return sha256hex(canonicalize(plan));
}

export function assertProtectedRecordsRuntimeLocalActivationPlan(plan) {
  assertExactKeys('Protected records runtime local activation plan', plan, [
    'action_class',
    'activation_boundary',
    'activation_contract',
    'deployment_posture',
    'known_open_boundaries',
    'local_activation_command',
    'non_claims',
    'operator_requirements',
    'plan_id',
    'plan_status',
    'plan_type',
    'runtime_profile_id',
    'runtime_profile_proof_command',
    'runtime_profile_sha256',
    'runtime_profile_source',
    'service_command',
  ]);
  if (
    plan.plan_type !== PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PLAN_TYPE ||
    plan.plan_id !== 'protected-records-runtime-local-activation-fixture-plan' ||
    plan.plan_status !== 'sample_local_disposable_only' ||
    plan.deployment_posture !== 'local_disposable_activation_only' ||
    plan.action_class !== 'records.write' ||
    plan.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    plan.runtime_profile_source !== 'profiles/protected-records-runtime-fixture.profile.json' ||
    !/^[a-f0-9]{64}$/.test(plan.runtime_profile_sha256) ||
    plan.local_activation_command !== 'zlar protected-records-runtime-local-activation --plan profiles/protected-records-runtime-local-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json' ||
    plan.runtime_profile_proof_command !== 'zlar protected-records-runtime-profile-proof' ||
    plan.service_command !== 'zlar protected-records-runtime-service --config <launcher-owned-disposable-config>'
  ) {
    throw new Error('Protected records runtime local activation plan contract drifted');
  }

  assertExactKeys('Protected records runtime local activation boundary', plan.activation_boundary, [
    'disposable_runtime_config_written',
    'local_activation_applied',
    'persistent_runtime_config_written',
    'persistent_runtime_profile_installed',
    'request_stream_authority_material_accepted',
    'requires_explicit_local_command',
    'selects_latest_profile',
    'starts_runtime_service',
    'uses_live_records_system',
    'writes_hook_configuration',
  ]);
  const boundary = plan.activation_boundary;
  if (
    boundary.local_activation_applied !== true ||
    boundary.disposable_runtime_config_written !== true ||
    boundary.persistent_runtime_config_written !== false ||
    boundary.writes_hook_configuration !== false ||
    boundary.starts_runtime_service !== true ||
    boundary.persistent_runtime_profile_installed !== false ||
    boundary.requires_explicit_local_command !== true ||
    boundary.selects_latest_profile !== false ||
    boundary.request_stream_authority_material_accepted !== false ||
    boundary.uses_live_records_system !== false
  ) {
    throw new Error('Protected records runtime local activation boundary drifted');
  }

  assertExactKeys('Protected records runtime local activation contract', plan.activation_contract, [
    'authority_grant_appointment_required_from_launcher',
    'authority_grant_contract_required_from_launcher',
    'authority_grant_issuance_decision_required_from_launcher',
    'authorized_record_update_required_from_launcher',
    'config_path_agent_supplied',
    'consumed_grant_store_anchor_path_agent_supplied',
    'consumed_grant_store_witness_path_agent_supplied',
    'consumed_grants_path_agent_supplied',
    'downstream_recognition_required',
    'issuer_registry_agent_supplied',
    'launcher_supplies_config',
    'missing_or_unrecognized_receipt_refused',
    'recognition_rule_agent_supplied',
    'request_supplied_authority_grant_refused',
    'state_path_agent_supplied',
  ]);
  const contract = plan.activation_contract;
  if (
    contract.launcher_supplies_config !== true ||
    contract.config_path_agent_supplied !== false ||
    contract.state_path_agent_supplied !== false ||
    contract.consumed_grants_path_agent_supplied !== false ||
    contract.consumed_grant_store_anchor_path_agent_supplied !== false ||
    contract.consumed_grant_store_witness_path_agent_supplied !== false ||
    contract.recognition_rule_agent_supplied !== false ||
    contract.issuer_registry_agent_supplied !== false ||
    contract.authority_grant_contract_required_from_launcher !== true ||
    contract.authority_grant_appointment_required_from_launcher !== true ||
    contract.authority_grant_issuance_decision_required_from_launcher !== true ||
    contract.authorized_record_update_required_from_launcher !== true ||
    contract.request_supplied_authority_grant_refused !== true ||
    contract.downstream_recognition_required !== true ||
    contract.missing_or_unrecognized_receipt_refused !== true
  ) {
    throw new Error('Protected records runtime local activation contract drifted');
  }

  assertExactArray(
    'Protected records runtime local activation operator requirements',
    plan.operator_requirements,
    REQUIRED_RUNTIME_LOCAL_ACTIVATION_OPERATOR_REQUIREMENTS
  );
  assertExactArray(
    'Protected records runtime local activation open boundaries',
    plan.known_open_boundaries,
    REQUIRED_RUNTIME_LOCAL_ACTIVATION_OPEN_BOUNDARIES
  );
  assertExactArray(
    'Protected records runtime local activation non-claims',
    plan.non_claims,
    RUNTIME_LOCAL_ACTIVATION_NON_CLAIMS
  );
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(plan));
  return true;
}

export function runProtectedRecordsRuntimeLocalActivationProof(plan, profile) {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
    'Protected records runtime local-activation proof generation',
  );
  assertProtectedRecordsRuntimeLocalActivationPlan(plan);
  assertProtectedRecordsRuntimePreflightProfile(profile);
  const profileSha = runtimeProfileSha256(profile);
  if (plan.runtime_profile_sha256 !== profileSha) {
    throw new Error('Protected records runtime local activation plan profile SHA mismatch');
  }

  const runtimeProof = runProtectedRecordsRuntimeProfileProof();
  assertProtectedRecordsRuntimeProfileProof(runtimeProof);

  const accepted = proofCase(runtimeProof, 'recognized_runtime_write_first_request');
  const sameProcessSignedPayloadReplay = proofCase(
    runtimeProof,
    'replay_runtime_write_refused_same_service_process'
  );
  const replayAfterRestart = proofCase(runtimeProof, 'replay_runtime_write_refused_after_service_restart');
  const witnessCommitFailure = proofCase(
    runtimeProof,
    'witness_commit_failed_after_authority_grant_store_commit'
  );
  const storeAndAnchorRollbackAgainstWitness = proofCase(
    runtimeProof,
    'store_and_anchor_joint_rollback_refused_against_witness_before_runtime_mutation'
  );
  const missingAuthorityGrant = proofCase(
    runtimeProof,
    'missing_authority_grant_appointment_refused_before_consumption'
  );
  const mismatchedAuthorityGrant = proofCase(
    runtimeProof,
    'mismatched_authority_grant_appointment_refused_before_consumption'
  );
  const revokedAuthorityGrant = proofCase(
    runtimeProof,
    'revoked_authority_grant_refused_before_consumption'
  );
  const expiredAuthorityGrant = proofCase(
    runtimeProof,
    'expired_authority_grant_refused_before_consumption'
  );
  const requestSuppliedAuthorityGrant = proofCase(
    runtimeProof,
    'agent_supplied_authority_grant_refused_before_runtime_mutation'
  );
  const missingReceipt = proofCase(runtimeProof, 'missing_receipt_refused_before_runtime_mutation');
  const invalidReceipt = proofCase(runtimeProof, 'invalid_receipt_refused_before_runtime_mutation');
  const unknownIssuer = proofCase(runtimeProof, 'unknown_issuer_refused_before_runtime_mutation');
  const retiredIssuer = proofCase(runtimeProof, 'retired_issuer_refused_before_runtime_mutation');
  const missingIssuerStatus = proofCase(runtimeProof, 'missing_issuer_status_refused_before_runtime_mutation');
  const staleReceipt = proofCase(runtimeProof, 'stale_receipt_refused_before_runtime_mutation');
  const wrongPolicy = proofCase(runtimeProof, 'wrong_policy_refused_before_runtime_mutation');
  const wrongDomain = proofCase(runtimeProof, 'wrong_domain_refused_before_runtime_mutation');
  const wrongTool = proofCase(runtimeProof, 'wrong_tool_refused_before_runtime_mutation');
  const wrongRuntimeProfileId = proofCase(runtimeProof, 'wrong_runtime_profile_id_refused_before_runtime_mutation');
  const wrongAuditEvent = proofCase(runtimeProof, 'wrong_audit_event_refused_before_runtime_mutation');
  const wrongDetail = proofCase(runtimeProof, 'wrong_detail_refused_before_runtime_mutation');
  const nonBoardingOutcome = proofCase(runtimeProof, 'non_boarding_outcome_refused_before_runtime_mutation');
  const directApiWithoutReceipt = proofCase(runtimeProof, 'direct_api_without_receipt_refused_before_runtime_mutation');
  const directApiWithReceipt = proofCase(runtimeProof, 'direct_api_with_receipt_refused_before_runtime_mutation');
  const authorityCases = runtimeProof.cases.filter((item) => item.case_id.startsWith('agent_supplied_'));
  const identityPolicy = runtimeProof.runtime_profile_identity_policy;

  const report = {
    proof_type: PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PROOF_TYPE,
    evidence_model: 'local-disposable-runtime-activation-fixture',
    live_probing: false,
    safe_claim_ceiling: RUNTIME_LOCAL_ACTIVATION_SAFE_CLAIM_CEILING,
    plan: {
      plan_type: plan.plan_type,
      plan_id: plan.plan_id,
      plan_status: plan.plan_status,
      deployment_posture: plan.deployment_posture,
      plan_sha256: runtimeLocalActivationPlanSha256(plan),
    },
    runtime_profile: {
      profile_id: profile.profile_id,
      runtime_profile_id: profile.runtime_profile_id,
      profile_status: profile.profile_status,
      profile_sha256: profileSha,
      profile_sha_matches_plan: true,
    },
    activation_boundary: { ...plan.activation_boundary },
    activation_contract: { ...plan.activation_contract },
    runtime_proof_summary: {
      proof_type: runtimeProof.proof_type,
      proof_command: plan.runtime_profile_proof_command,
      proof_run: true,
      service_command: plan.service_command,
      service_process_boundary: 'local-jsonl-child-process',
      case_count: runtimeProof.cases.length,
      required_case_count: profile.required_cases.length,
      boundary_observation_count: runtimeProof.boundary_observations.length,
      required_boundary_observation_count: profile.required_boundary_observations.length,
      mutation_authoritative_route:
        runtimeProof.runtime_profile.mutation_authoritative_route,
      consumed_authority_grant_store:
        runtimeProof.runtime_profile.consumed_authority_grant_store,
      consumption_identity: runtimeProof.runtime_profile.consumption_identity,
      signed_payload_replay_identity:
        runtimeProof.runtime_profile.signed_payload_replay_identity,
      consumed_store_witness: runtimeProof.runtime_profile.consumed_store_witness,
      consumed_store_write_model:
        runtimeProof.runtime_profile.consumed_store_write_model,
      recognized_write_accepted: accepted.service_write_accepted === true,
      same_process_signed_payload_replay_refused:
        sameProcessSignedPayloadReplay.service_write_accepted === false &&
        sameProcessSignedPayloadReplay.reason_code === 'receipt_replay',
      restart_consumed_authority_grant_refused:
        replayAfterRestart.service_write_accepted === false &&
        replayAfterRestart.reason_code === 'authority_grant_already_consumed',
      witness_commit_failed_after_authority_grant_store_commit:
        witnessCommitFailure.service_write_accepted === false,
      witness_commit_failure_reason_code: witnessCommitFailure.reason_code,
      witness_commit_failure_consumed_authority_grant_count:
        witnessCommitFailure.consumed_authority_grant_count,
      store_and_anchor_joint_rollback_refused_against_witness:
        storeAndAnchorRollbackAgainstWitness.service_write_accepted === false &&
        storeAndAnchorRollbackAgainstWitness.reason_code ===
          'consumed_store_rollback_detected',
      missing_authority_grant_appointment_refused:
        missingAuthorityGrant.service_write_accepted === false &&
        missingAuthorityGrant.consumed_authority_grant_count === 0,
      mismatched_authority_grant_appointment_refused:
        mismatchedAuthorityGrant.service_write_accepted === false &&
        mismatchedAuthorityGrant.consumed_authority_grant_count === 0,
      revoked_authority_grant_refused:
        revokedAuthorityGrant.service_write_accepted === false &&
        revokedAuthorityGrant.consumed_authority_grant_count === 0,
      expired_authority_grant_refused:
        expiredAuthorityGrant.service_write_accepted === false &&
        expiredAuthorityGrant.consumed_authority_grant_count === 0,
      request_supplied_authority_grant_refused:
        requestSuppliedAuthorityGrant.service_write_accepted === false &&
        requestSuppliedAuthorityGrant.state_entry_count_delta === 0,
      missing_receipt_refused: missingReceipt.service_write_accepted === false,
      invalid_receipt_refused: invalidReceipt.service_write_accepted === false,
      unknown_issuer_refused: unknownIssuer.service_write_accepted === false,
      retired_issuer_refused: retiredIssuer.service_write_accepted === false,
      missing_issuer_status_refused: missingIssuerStatus.service_write_accepted === false,
      stale_receipt_refused: staleReceipt.service_write_accepted === false,
      wrong_policy_refused: wrongPolicy.service_write_accepted === false,
      wrong_domain_refused: wrongDomain.service_write_accepted === false,
      wrong_tool_refused: wrongTool.service_write_accepted === false,
      wrong_runtime_profile_id_refused: wrongRuntimeProfileId.service_write_accepted === false,
      wrong_audit_event_refused: wrongAuditEvent.service_write_accepted === false,
      wrong_detail_refused: wrongDetail.service_write_accepted === false,
      non_boarding_outcome_refused: nonBoardingOutcome.service_write_accepted === false,
      direct_api_without_receipt_refused: directApiWithoutReceipt.service_write_accepted === false,
      direct_api_with_receipt_refused: directApiWithReceipt.service_write_accepted === false,
      agent_supplied_authority_material_refused:
        authorityCases.length > 0 && authorityCases.every((item) => item.service_write_accepted === false),
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
        runtimeProof.side_door_report
          .store_and_anchor_joint_rollback_refused_while_witness_ahead,
      store_anchor_and_witness_joint_rollback_detection:
        runtimeProof.side_door_report
          .store_anchor_and_witness_joint_rollback_detection,
      store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse:
        runtimeProof.side_door_report
          .store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse,
    },
    case_summaries: runtimeProof.cases.map(caseSummary),
    side_door_report: {
      local_activation_applied: true,
      disposable_runtime_config_written: true,
      persistent_runtime_config_written: false,
      hook_configuration_written: false,
      runtime_service_started: true,
      persistent_runtime_profile_installed: false,
      latest_profile_selected: false,
      request_stream_authority_material_accepted: false,
      request_supplied_authority_grant_refused:
        requestSuppliedAuthorityGrant.service_write_accepted === false,
      persistent_consumed_authority_grant_store:
        runtimeProof.side_door_report.persistent_consumed_authority_grant_store,
      consumed_store_anchor_present:
        runtimeProof.side_door_report.consumed_store_anchor_present,
      consumed_store_witness_present:
        runtimeProof.side_door_report.consumed_store_witness_present,
      live_records_system_checked: false,
      production_records_service_checked: false,
      live_mcp_coverage_checked: false,
      live_approval_channel_health_checked: false,
      exactly_once_effect_semantics: false,
      store_and_anchor_joint_rollback_refused_while_witness_ahead:
        runtimeProof.side_door_report
          .store_and_anchor_joint_rollback_refused_while_witness_ahead,
      store_anchor_and_witness_joint_rollback_detection:
        runtimeProof.side_door_report
          .store_anchor_and_witness_joint_rollback_detection,
      store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse:
        runtimeProof.side_door_report
          .store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse,
      atomic_store_anchor_witness_commit:
        runtimeProof.side_door_report.atomic_store_anchor_witness_commit,
      partial_grant_commit_burn_window_named:
        runtimeProof.side_door_report.partial_grant_commit_burn_window_named,
      partial_commit_witness_missing_observed:
        runtimeProof.side_door_report.partial_commit_witness_missing_observed,
      host_filesystem_path_toctou_closed:
        runtimeProof.side_door_report.host_filesystem_path_toctou_closed,
      host_process_or_memory_introspection_closed: false,
      external_attestation: false,
      sovereign_recognition: false,
      unrouted_records_paths_checked: false,
    },
    operator_requirements: [...plan.operator_requirements],
    known_open_boundaries: [...plan.known_open_boundaries],
    non_claims: [...RUNTIME_LOCAL_ACTIVATION_NON_CLAIMS],
  };
  assertProtectedRecordsRuntimeLocalActivationProof(report, plan, profile);
  return report;
}

export function assertProtectedRecordsRuntimeLocalActivationProof(report, plan, profile) {
  assertProtectedRecordsRuntimeLocalActivationPlan(plan);
  assertProtectedRecordsRuntimePreflightProfile(profile);
  assertExactKeys('Protected records runtime local activation proof', report, [
    'activation_boundary',
    'activation_contract',
    'case_summaries',
    'evidence_model',
    'known_open_boundaries',
    'live_probing',
    'non_claims',
    'operator_requirements',
    'plan',
    'proof_type',
    'runtime_profile',
    'runtime_proof_summary',
    'safe_claim_ceiling',
    'side_door_report',
  ]);
  if (
    report.proof_type !== PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PROOF_TYPE ||
    report.evidence_model !== 'local-disposable-runtime-activation-fixture' ||
    report.live_probing !== false ||
    report.safe_claim_ceiling !== RUNTIME_LOCAL_ACTIVATION_SAFE_CLAIM_CEILING
  ) {
    throw new Error('Protected records runtime local activation proof top-level contract drifted');
  }

  assertExactKeys('Protected records runtime local activation plan identity', report.plan, [
    'deployment_posture',
    'plan_id',
    'plan_sha256',
    'plan_status',
    'plan_type',
  ]);
  if (
    report.plan.plan_type !== plan.plan_type ||
    report.plan.plan_id !== plan.plan_id ||
    report.plan.plan_status !== plan.plan_status ||
    report.plan.deployment_posture !== plan.deployment_posture ||
    report.plan.plan_sha256 !== runtimeLocalActivationPlanSha256(plan)
  ) {
    throw new Error('Protected records runtime local activation plan identity drifted');
  }

  assertExactKeys('Protected records runtime local activation profile identity', report.runtime_profile, [
    'profile_id',
    'profile_sha256',
    'profile_sha_matches_plan',
    'profile_status',
    'runtime_profile_id',
  ]);
  if (
    report.runtime_profile.profile_id !== profile.profile_id ||
    report.runtime_profile.runtime_profile_id !== profile.runtime_profile_id ||
    report.runtime_profile.profile_status !== profile.profile_status ||
    report.runtime_profile.profile_sha256 !== runtimeProfileSha256(profile) ||
    report.runtime_profile.profile_sha_matches_plan !== true ||
    report.runtime_profile.profile_sha256 !== plan.runtime_profile_sha256
  ) {
    throw new Error('Protected records runtime local activation profile identity drifted');
  }

  if (canonicalize(report.activation_boundary) !== canonicalize(plan.activation_boundary)) {
    throw new Error('Protected records runtime local activation boundary drifted');
  }
  if (canonicalize(report.activation_contract) !== canonicalize(plan.activation_contract)) {
    throw new Error('Protected records runtime local activation contract drifted');
  }

  assertExactKeys('Protected records runtime local activation proof summary', report.runtime_proof_summary, [
    'agent_supplied_authority_material_refused',
    'boundary_observation_count',
    'case_count',
    'consumed_authority_grant_store',
    'consumed_store_witness',
    'consumed_store_write_model',
    'consumption_identity',
    'direct_api_with_receipt_refused',
    'direct_api_without_receipt_refused',
    'expired_authority_grant_refused',
    'invalid_receipt_refused',
    'mismatched_authority_grant_appointment_refused',
    'missing_authority_grant_appointment_refused',
    'missing_issuer_status_refused',
    'missing_receipt_refused',
    'non_boarding_outcome_refused',
    'omitted_request_runtime_profile_id_present',
    'mutation_authoritative_route',
    'omitted_runtime_profile_id_consumed_authority_grant_count',
    'omitted_runtime_profile_id_reason_code',
    'omitted_runtime_profile_id_state_entry_count_delta',
    'omitted_runtime_profile_id_uses_launcher_config',
    'proof_command',
    'proof_run',
    'proof_type',
    'recognized_write_accepted',
    'request_runtime_profile_id_required',
    'request_supplied_authority_grant_refused',
    'restart_consumed_authority_grant_refused',
    'required_boundary_observation_count',
    'required_case_count',
    'retired_issuer_refused',
    'revoked_authority_grant_refused',
    'runtime_profile_identity_authority_source',
    'runtime_profile_identity_request_stream_policy',
    'same_process_signed_payload_replay_refused',
    'service_command',
    'service_process_boundary',
    'signed_payload_replay_identity',
    'stale_receipt_refused',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse',
    'store_and_anchor_joint_rollback_refused_against_witness',
    'store_and_anchor_joint_rollback_refused_while_witness_ahead',
    'supplied_mismatch_reason_code',
    'supplied_mismatch_state_entry_count_delta',
    'supplied_mismatched_runtime_profile_id_refused',
    'unknown_issuer_refused',
    'wrong_audit_event_refused',
    'wrong_detail_refused',
    'wrong_domain_refused',
    'wrong_policy_refused',
    'wrong_runtime_profile_id_refused',
    'wrong_tool_refused',
    'witness_commit_failed_after_authority_grant_store_commit',
    'witness_commit_failure_consumed_authority_grant_count',
    'witness_commit_failure_reason_code',
  ]);
  const summary = report.runtime_proof_summary;
  if (
    summary.proof_command !== plan.runtime_profile_proof_command ||
    summary.proof_run !== true ||
    summary.service_command !== plan.service_command ||
    summary.service_process_boundary !== 'local-jsonl-child-process' ||
    summary.case_count !== profile.required_cases.length ||
    summary.required_case_count !== profile.required_cases.length ||
    summary.boundary_observation_count !== profile.required_boundary_observations.length ||
    summary.required_boundary_observation_count !== profile.required_boundary_observations.length ||
    summary.mutation_authoritative_route !==
      'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation' ||
    summary.consumed_authority_grant_store !==
      'persistent-single-use-authority-grant-contract-sha256-store' ||
    summary.consumption_identity !== 'authority-grant-contract-sha256' ||
    summary.signed_payload_replay_identity !== 'verified-signed-payload-sha256' ||
    summary.consumed_store_witness !== 'launcher-owned-local-store-hash-witness' ||
    summary.consumed_store_write_model !==
      'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness' ||
    summary.recognized_write_accepted !== true ||
    summary.same_process_signed_payload_replay_refused !== true ||
    summary.restart_consumed_authority_grant_refused !== true ||
    summary.witness_commit_failed_after_authority_grant_store_commit !== true ||
    summary.witness_commit_failure_reason_code !==
      'consumed_store_write_failed_after_grant_commit' ||
    summary.witness_commit_failure_consumed_authority_grant_count !== 1 ||
    summary.store_and_anchor_joint_rollback_refused_against_witness !== true ||
    summary.missing_authority_grant_appointment_refused !== true ||
    summary.mismatched_authority_grant_appointment_refused !== true ||
    summary.revoked_authority_grant_refused !== true ||
    summary.expired_authority_grant_refused !== true ||
    summary.request_supplied_authority_grant_refused !== true ||
    summary.missing_receipt_refused !== true ||
    summary.invalid_receipt_refused !== true ||
    summary.unknown_issuer_refused !== true ||
    summary.retired_issuer_refused !== true ||
    summary.missing_issuer_status_refused !== true ||
    summary.stale_receipt_refused !== true ||
    summary.wrong_policy_refused !== true ||
    summary.wrong_domain_refused !== true ||
    summary.wrong_tool_refused !== true ||
    summary.wrong_runtime_profile_id_refused !== true ||
    summary.wrong_audit_event_refused !== true ||
    summary.wrong_detail_refused !== true ||
    summary.non_boarding_outcome_refused !== true ||
    summary.direct_api_without_receipt_refused !== true ||
    summary.direct_api_with_receipt_refused !== true ||
    summary.agent_supplied_authority_material_refused !== true ||
    summary.runtime_profile_identity_authority_source !== 'launcher-owned-service-config' ||
    summary.runtime_profile_identity_request_stream_policy !==
      'runtime_profile_id_may_be_omitted_but_if_supplied_must_match_config' ||
    summary.request_runtime_profile_id_required !== false ||
    summary.omitted_request_runtime_profile_id_present !== false ||
    summary.omitted_runtime_profile_id_uses_launcher_config !== true ||
    summary.omitted_runtime_profile_id_reason_code !==
      'fixture_authority_grant_effect_satisfied' ||
    summary.omitted_runtime_profile_id_state_entry_count_delta !== 1 ||
    summary.omitted_runtime_profile_id_consumed_authority_grant_count !== 1 ||
    summary.supplied_mismatched_runtime_profile_id_refused !== true ||
    summary.supplied_mismatch_reason_code !== 'agent_supplied_authority_material' ||
    summary.supplied_mismatch_state_entry_count_delta !== 0 ||
    summary.store_and_anchor_joint_rollback_refused_while_witness_ahead !== true ||
    summary.store_anchor_and_witness_joint_rollback_detection !== false ||
    summary.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse !== true
  ) {
    throw new Error('Protected records runtime local activation proof summary drifted');
  }

  if (!Array.isArray(report.case_summaries) || report.case_summaries.length !== profile.required_cases.length) {
    throw new Error('Protected records runtime local activation case summaries drifted');
  }
  for (const item of report.case_summaries) {
    assertExactKeys('Protected records runtime local activation case summary', item, [
      'case_id',
      'consumed_authority_grant_count',
      'direct_api_attempted',
      'reason_code',
      'request_ordinal',
      'service_process_invocation',
      'service_write_accepted',
      'state_entry_count_delta',
    ]);
  }

  assertExactKeys('Protected records runtime local activation side-door report', report.side_door_report, [
    'atomic_store_anchor_witness_commit',
    'consumed_store_anchor_present',
    'consumed_store_witness_present',
    'disposable_runtime_config_written',
    'exactly_once_effect_semantics',
    'external_attestation',
    'hook_configuration_written',
    'host_filesystem_path_toctou_closed',
    'host_process_or_memory_introspection_closed',
    'latest_profile_selected',
    'live_approval_channel_health_checked',
    'live_mcp_coverage_checked',
    'live_records_system_checked',
    'local_activation_applied',
    'partial_commit_witness_missing_observed',
    'partial_grant_commit_burn_window_named',
    'persistent_consumed_authority_grant_store',
    'persistent_runtime_config_written',
    'persistent_runtime_profile_installed',
    'production_records_service_checked',
    'request_stream_authority_material_accepted',
    'request_supplied_authority_grant_refused',
    'runtime_service_started',
    'sovereign_recognition',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse',
    'store_and_anchor_joint_rollback_refused_while_witness_ahead',
    'unrouted_records_paths_checked',
  ]);
  const sideDoor = report.side_door_report;
  if (
    sideDoor.local_activation_applied !== true ||
    sideDoor.disposable_runtime_config_written !== true ||
    sideDoor.persistent_runtime_config_written !== false ||
    sideDoor.hook_configuration_written !== false ||
    sideDoor.runtime_service_started !== true ||
    sideDoor.persistent_runtime_profile_installed !== false ||
    sideDoor.latest_profile_selected !== false ||
    sideDoor.request_stream_authority_material_accepted !== false ||
    sideDoor.request_supplied_authority_grant_refused !== true ||
    sideDoor.persistent_consumed_authority_grant_store !== true ||
    sideDoor.consumed_store_anchor_present !== true ||
    sideDoor.consumed_store_witness_present !== true ||
    sideDoor.live_records_system_checked !== false ||
    sideDoor.production_records_service_checked !== false ||
    sideDoor.live_mcp_coverage_checked !== false ||
    sideDoor.live_approval_channel_health_checked !== false ||
    sideDoor.exactly_once_effect_semantics !== false ||
    sideDoor.store_and_anchor_joint_rollback_refused_while_witness_ahead !== true ||
    sideDoor.store_anchor_and_witness_joint_rollback_detection !== false ||
    sideDoor.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse !== true ||
    sideDoor.atomic_store_anchor_witness_commit !== false ||
    sideDoor.partial_grant_commit_burn_window_named !== true ||
    sideDoor.partial_commit_witness_missing_observed !== true ||
    sideDoor.host_filesystem_path_toctou_closed !== false ||
    sideDoor.host_process_or_memory_introspection_closed !== false ||
    sideDoor.external_attestation !== false ||
    sideDoor.sovereign_recognition !== false ||
    sideDoor.unrouted_records_paths_checked !== false
  ) {
    throw new Error('Protected records runtime local activation side-door report drifted');
  }

  assertExactArray(
    'Protected records runtime local activation operator requirements',
    report.operator_requirements,
    REQUIRED_RUNTIME_LOCAL_ACTIVATION_OPERATOR_REQUIREMENTS
  );
  assertExactArray(
    'Protected records runtime local activation open boundaries',
    report.known_open_boundaries,
    REQUIRED_RUNTIME_LOCAL_ACTIVATION_OPEN_BOUNDARIES
  );
  assertExactArray(
    'Protected records runtime local activation non-claims',
    report.non_claims,
    RUNTIME_LOCAL_ACTIVATION_NON_CLAIMS
  );
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return true;
}

function runtimeLocalActivationArtifactBody(payload) {
  return {
    artifact_type: PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_TYPE,
    canonicalization: PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_CANONICALIZATION,
    generator: 'zlar protected-records-runtime-local-activation --artifact',
    hash_scope: 'canonical artifact body without integrity',
    payload,
  };
}

export function buildProtectedRecordsRuntimeLocalActivationArtifact(
  plan,
  profile,
  report = runProtectedRecordsRuntimeLocalActivationProof(plan, profile)
) {
  assertProtectedRecordsRuntimeLocalActivationPlan(plan);
  assertProtectedRecordsRuntimePreflightProfile(profile);
  assertProtectedRecordsRuntimeLocalActivationProof(report, plan, profile);
  const payload = {
    plan,
    runtime_profile: profile,
    proof: report,
  };
  const body = runtimeLocalActivationArtifactBody(payload);
  const artifact = {
    ...body,
    integrity: {
      algorithm: 'SHA-256',
      body_sha256: sha256hex(canonicalize(body)),
    },
  };
  assertProtectedRecordsRuntimeLocalActivationArtifact(artifact);
  return artifact;
}

export function assertProtectedRecordsRuntimeLocalActivationArtifact(artifact) {
  if (!artifact || artifact.artifact_type !== PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_TYPE) {
    throw new Error('Protected records runtime local activation artifact has the wrong artifact type');
  }
  assertExactKeys('Protected records runtime local activation artifact', artifact, [
    'artifact_type',
    'canonicalization',
    'generator',
    'hash_scope',
    'integrity',
    'payload',
  ]);
  if (artifact.canonicalization !== PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_CANONICALIZATION) {
    throw new Error('Protected records runtime local activation artifact canonicalization drifted');
  }
  if (artifact.generator !== 'zlar protected-records-runtime-local-activation --artifact') {
    throw new Error('Protected records runtime local activation artifact generator drifted');
  }
  if (artifact.hash_scope !== 'canonical artifact body without integrity') {
    throw new Error('Protected records runtime local activation artifact hash scope drifted');
  }

  assertExactKeys('Protected records runtime local activation artifact payload', artifact.payload, [
    'plan',
    'proof',
    'runtime_profile',
  ]);
  assertProtectedRecordsRuntimeLocalActivationPlan(artifact.payload.plan);
  assertProtectedRecordsRuntimePreflightProfile(artifact.payload.runtime_profile);
  assertProtectedRecordsRuntimeLocalActivationProof(
    artifact.payload.proof,
    artifact.payload.plan,
    artifact.payload.runtime_profile
  );

  if (!artifact.integrity || artifact.integrity.algorithm !== 'SHA-256') {
    throw new Error('Protected records runtime local activation artifact integrity algorithm drifted');
  }
  assertExactKeys('Protected records runtime local activation artifact integrity', artifact.integrity, [
    'algorithm',
    'body_sha256',
  ]);
  if (!/^[a-f0-9]{64}$/.test(artifact.integrity.body_sha256 || '')) {
    throw new Error('Protected records runtime local activation artifact SHA-256 is malformed');
  }
  const { integrity, ...body } = artifact;
  const expectedHash = sha256hex(canonicalize(body));
  if (integrity.body_sha256 !== expectedHash) {
    throw new Error('Protected records runtime local activation artifact SHA-256 mismatch');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(artifact));
  return true;
}

export function writeProtectedRecordsRuntimeLocalActivationArtifact(artifact, outputPath) {
  assertProtectedRecordsRuntimeLocalActivationArtifact(artifact);
  if (!outputPath || outputPath === '-') {
    throw new Error('Protected records runtime local activation artifact output path is required');
  }
  mkdirSync(dirname(outputPath), { recursive: true });
  const output = `${JSON.stringify(artifact, null, 2)}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  writeFileSync(outputPath, output, { mode: 0o600 });
  return artifact.integrity.body_sha256;
}

export function parseProtectedRecordsRuntimeLocalActivationArtifactText(text) {
  assertNoUnsafeProtectedRecordsRuntimeProfileText(text);
  let artifact;
  try {
    artifact = JSON.parse(text);
  } catch {
    throw new Error('Protected records runtime local activation artifact input is not valid JSON');
  }
  assertProtectedRecordsRuntimeLocalActivationArtifact(artifact);
  return artifact;
}

export function verifyProtectedRecordsRuntimeLocalActivationArtifact(artifact) {
  assertProtectedRecordsRuntimeLocalActivationArtifact(artifact);
  const report = artifact.payload.proof;
  const authorityStatus =
    PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_STATUS;
  const authorityStatusReason =
    protectedRecordsFixtureAuthorityGrantEffectStatusReason(
      PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256
    );
  const historicalFixtureAuthorityEffectObserved =
    report.runtime_proof_summary.recognized_write_accepted === true &&
    report.runtime_proof_summary.omitted_runtime_profile_id_reason_code ===
      'fixture_authority_grant_effect_satisfied' &&
    report.runtime_proof_summary
      .omitted_runtime_profile_id_consumed_authority_grant_count === 1;
  const verification = {
    verification_type: PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_VERIFICATION_TYPE,
    verified: true,
    artifact_type: artifact.artifact_type,
    canonicalization: artifact.canonicalization,
    hash_scope: artifact.hash_scope,
    body_sha256: artifact.integrity.body_sha256,
    payload_type: report.proof_type,
    evidence_model: report.evidence_model,
    live_probing: report.live_probing,
    plan_sha256: report.plan.plan_sha256,
    runtime_profile_sha256: report.runtime_profile.profile_sha256,
    runtime_profile_sha_matches_plan: report.runtime_profile.profile_sha_matches_plan,
    runtime_profile_identity_authority_source:
      report.runtime_proof_summary.runtime_profile_identity_authority_source,
    runtime_profile_identity_request_stream_policy:
      report.runtime_proof_summary.runtime_profile_identity_request_stream_policy,
    request_runtime_profile_id_required:
      report.runtime_proof_summary.request_runtime_profile_id_required,
    omitted_request_runtime_profile_id_present:
      report.runtime_proof_summary.omitted_request_runtime_profile_id_present,
    omitted_runtime_profile_id_uses_launcher_config:
      report.runtime_proof_summary.omitted_runtime_profile_id_uses_launcher_config,
    omitted_runtime_profile_id_reason_code:
      report.runtime_proof_summary.omitted_runtime_profile_id_reason_code,
    omitted_runtime_profile_id_state_entry_count_delta:
      report.runtime_proof_summary.omitted_runtime_profile_id_state_entry_count_delta,
    omitted_runtime_profile_id_consumed_authority_grant_count:
      report.runtime_proof_summary
        .omitted_runtime_profile_id_consumed_authority_grant_count,
    supplied_mismatched_runtime_profile_id_refused:
      report.runtime_proof_summary.supplied_mismatched_runtime_profile_id_refused,
    supplied_mismatch_reason_code:
      report.runtime_proof_summary.supplied_mismatch_reason_code,
    supplied_mismatch_state_entry_count_delta:
      report.runtime_proof_summary.supplied_mismatch_state_entry_count_delta,
    local_activation_applied: report.side_door_report.local_activation_applied,
    disposable_runtime_config_written: report.side_door_report.disposable_runtime_config_written,
    persistent_runtime_config_written: report.side_door_report.persistent_runtime_config_written,
    hook_configuration_written: report.side_door_report.hook_configuration_written,
    runtime_service_started: report.side_door_report.runtime_service_started,
    recognized_write_accepted: report.runtime_proof_summary.recognized_write_accepted,
    historical_artifact_recognized_write_accepted:
      report.runtime_proof_summary.recognized_write_accepted,
    recognized_write_accepted_is_current_authority_projection: false,
    historical_artifact_fixture_authority_effect_observed:
      historicalFixtureAuthorityEffectObserved,
    fixture_rightful_issuance_path_evidenced: false,
    authority_grant_status_type: authorityStatus.status_type,
    authority_grant_status_contract_sha256:
      authorityStatus.authority_grant_contract_sha256,
    artifact_authority_grant_contract_sha256: null,
    artifact_contract_bound_to_authority_status: false,
    historical_only_due_to_missing_artifact_grant_contract_binding: true,
    authority_grant_status: authorityStatus.status,
    authority_grant_status_source: authorityStatus.status_source,
    authority_grant_fresh_effect_allowed:
      authorityStatus.fresh_effect_allowed,
    authority_grant_repeated_use_provenance_valid:
      authorityStatus.repeated_use_provenance_valid,
    authority_grant_status_allows_fixture_rightful_projection: false,
    authority_grant_status_reason_code: authorityStatusReason?.code || null,
    consumed_authority_grant_store:
      report.runtime_proof_summary.consumed_authority_grant_store,
    consumption_identity: report.runtime_proof_summary.consumption_identity,
    signed_payload_replay_identity:
      report.runtime_proof_summary.signed_payload_replay_identity,
    same_process_signed_payload_replay_refused:
      report.runtime_proof_summary.same_process_signed_payload_replay_refused,
    restart_consumed_authority_grant_refused:
      report.runtime_proof_summary.restart_consumed_authority_grant_refused,
    missing_authority_grant_appointment_refused:
      report.runtime_proof_summary.missing_authority_grant_appointment_refused,
    mismatched_authority_grant_appointment_refused:
      report.runtime_proof_summary.mismatched_authority_grant_appointment_refused,
    revoked_authority_grant_refused:
      report.runtime_proof_summary.revoked_authority_grant_refused,
    expired_authority_grant_refused:
      report.runtime_proof_summary.expired_authority_grant_refused,
    request_supplied_authority_grant_refused:
      report.runtime_proof_summary.request_supplied_authority_grant_refused,
    witness_commit_failed_after_authority_grant_store_commit:
      report.runtime_proof_summary
        .witness_commit_failed_after_authority_grant_store_commit,
    witness_commit_failure_reason_code:
      report.runtime_proof_summary.witness_commit_failure_reason_code,
    atomic_store_anchor_witness_commit:
      report.side_door_report.atomic_store_anchor_witness_commit,
    partial_grant_commit_burn_window_named:
      report.side_door_report.partial_grant_commit_burn_window_named,
    store_and_anchor_joint_rollback_refused_while_witness_ahead:
      report.side_door_report
        .store_and_anchor_joint_rollback_refused_while_witness_ahead,
    store_anchor_and_witness_joint_rollback_detection:
      report.side_door_report.store_anchor_and_witness_joint_rollback_detection,
    store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse:
      report.side_door_report
        .store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse,
    host_filesystem_path_toctou_closed:
      report.side_door_report.host_filesystem_path_toctou_closed,
    missing_receipt_refused: report.runtime_proof_summary.missing_receipt_refused,
    invalid_receipt_refused: report.runtime_proof_summary.invalid_receipt_refused,
    unknown_issuer_refused: report.runtime_proof_summary.unknown_issuer_refused,
    retired_issuer_refused: report.runtime_proof_summary.retired_issuer_refused,
    missing_issuer_status_refused: report.runtime_proof_summary.missing_issuer_status_refused,
    stale_receipt_refused: report.runtime_proof_summary.stale_receipt_refused,
    wrong_policy_refused: report.runtime_proof_summary.wrong_policy_refused,
    wrong_domain_refused: report.runtime_proof_summary.wrong_domain_refused,
    wrong_tool_refused: report.runtime_proof_summary.wrong_tool_refused,
    wrong_runtime_profile_id_refused: report.runtime_proof_summary.wrong_runtime_profile_id_refused,
    wrong_audit_event_refused: report.runtime_proof_summary.wrong_audit_event_refused,
    wrong_detail_refused: report.runtime_proof_summary.wrong_detail_refused,
    non_boarding_outcome_refused: report.runtime_proof_summary.non_boarding_outcome_refused,
    direct_api_with_receipt_refused: report.runtime_proof_summary.direct_api_with_receipt_refused,
    agent_supplied_authority_material_refused:
      report.runtime_proof_summary.agent_supplied_authority_material_refused,
    claim_boundary:
      'artifact integrity and historical embedded local disposable runtime activation facts only; current fixture-rightful projection refused by shared authority status',
    non_claims: [...report.non_claims],
  };
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(verification));
  return verification;
}

export function formatProtectedRecordsRuntimeLocalActivationProofSummary(report, plan, profile) {
  assertProtectedRecordsRuntimeLocalActivationProof(report, plan, profile);
  const lines = [
    'ZLAR Protected Records Runtime Local Activation Proof v1',
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Evidence model: ${report.evidence_model}; live probing=${report.live_probing}`,
    `Plan: id=${report.plan.plan_id}; status=${report.plan.plan_status}; posture=${report.plan.deployment_posture}; sha256=${report.plan.plan_sha256}`,
    `Runtime profile: id=${report.runtime_profile.profile_id}; runtime_profile=${report.runtime_profile.runtime_profile_id}; profile_sha256=${report.runtime_profile.profile_sha256}; sha_matches_plan=${report.runtime_profile.profile_sha_matches_plan}`,
    `Local activation: applied=${report.activation_boundary.local_activation_applied}; disposable_runtime_config_written=${report.activation_boundary.disposable_runtime_config_written}; persistent_runtime_config_written=${report.activation_boundary.persistent_runtime_config_written}; writes_hook_configuration=${report.activation_boundary.writes_hook_configuration}; starts_runtime_service=${report.activation_boundary.starts_runtime_service}; selects_latest_profile=${report.activation_boundary.selects_latest_profile}`,
    `Activation contract: launcher_config=${report.activation_contract.launcher_supplies_config}; config_path_agent_supplied=${report.activation_contract.config_path_agent_supplied}; state_path_agent_supplied=${report.activation_contract.state_path_agent_supplied}; consumed_grants_path_agent_supplied=${report.activation_contract.consumed_grants_path_agent_supplied}; consumed_grant_anchor_path_agent_supplied=${report.activation_contract.consumed_grant_store_anchor_path_agent_supplied}; consumed_grant_witness_path_agent_supplied=${report.activation_contract.consumed_grant_store_witness_path_agent_supplied}; authority_grant_required=${report.activation_contract.authority_grant_contract_required_from_launcher}; request_supplied_grant_refused=${report.activation_contract.request_supplied_authority_grant_refused}`,
    `Runtime proof: command=${report.runtime_proof_summary.proof_command}; run=${report.runtime_proof_summary.proof_run}; service_command=${report.runtime_proof_summary.service_command}; cases=${report.runtime_proof_summary.case_count}/${report.runtime_proof_summary.required_case_count}; boundary_observations=${report.runtime_proof_summary.boundary_observation_count}/${report.runtime_proof_summary.required_boundary_observation_count}`,
    `Runtime profile identity policy: authority_source=${report.runtime_proof_summary.runtime_profile_identity_authority_source}; request_runtime_profile_id_required=${report.runtime_proof_summary.request_runtime_profile_id_required}; omitted_request_field_present=${report.runtime_proof_summary.omitted_request_runtime_profile_id_present}; omitted_uses_launcher_config=${report.runtime_proof_summary.omitted_runtime_profile_id_uses_launcher_config}; supplied_mismatch_refused=${report.runtime_proof_summary.supplied_mismatched_runtime_profile_id_refused}`,
    `Runtime storage identities: consumed_authority_grant_store=${report.runtime_proof_summary.consumed_authority_grant_store}; consumption_identity=${report.runtime_proof_summary.consumption_identity}; signed_payload_replay_identity=${report.runtime_proof_summary.signed_payload_replay_identity}; witness=${report.runtime_proof_summary.consumed_store_witness}`,
    `Runtime refusal checks: recognized_write_accepted=${report.runtime_proof_summary.recognized_write_accepted}; same_process_signed_payload_replay_refused=${report.runtime_proof_summary.same_process_signed_payload_replay_refused}; restart_consumed_authority_grant_refused=${report.runtime_proof_summary.restart_consumed_authority_grant_refused}; missing_grant_refused=${report.runtime_proof_summary.missing_authority_grant_appointment_refused}; mismatched_grant_refused=${report.runtime_proof_summary.mismatched_authority_grant_appointment_refused}; revoked_grant_refused=${report.runtime_proof_summary.revoked_authority_grant_refused}; expired_grant_refused=${report.runtime_proof_summary.expired_authority_grant_refused}; request_supplied_grant_refused=${report.runtime_proof_summary.request_supplied_authority_grant_refused}; missing_receipt_refused=${report.runtime_proof_summary.missing_receipt_refused}; invalid_receipt_refused=${report.runtime_proof_summary.invalid_receipt_refused}; unknown_issuer_refused=${report.runtime_proof_summary.unknown_issuer_refused}; retired_issuer_refused=${report.runtime_proof_summary.retired_issuer_refused}; stale_receipt_refused=${report.runtime_proof_summary.stale_receipt_refused}; wrong_runtime_profile_id_refused=${report.runtime_proof_summary.wrong_runtime_profile_id_refused}; wrong_audit_event_refused=${report.runtime_proof_summary.wrong_audit_event_refused}`,
    `Burn and rollback boundaries: witness_commit_failure_reason=${report.runtime_proof_summary.witness_commit_failure_reason_code}; atomic_store_anchor_witness_commit=${report.side_door_report.atomic_store_anchor_witness_commit}; burn_window_named=${report.side_door_report.partial_grant_commit_burn_window_named}; witness_ahead_refusal=${report.side_door_report.store_and_anchor_joint_rollback_refused_while_witness_ahead}; joint_rollback_detection=${report.side_door_report.store_anchor_and_witness_joint_rollback_detection}; joint_rollback_reopens_grant_reuse=${report.side_door_report.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse}; host_path_toctou_closed=${report.side_door_report.host_filesystem_path_toctou_closed}`,
    `Side-door report: local_activation_applied=${report.side_door_report.local_activation_applied}; persistent_runtime_profile_installed=${report.side_door_report.persistent_runtime_profile_installed}; hook_configuration_written=${report.side_door_report.hook_configuration_written}; live_records_system_checked=${report.side_door_report.live_records_system_checked}; production_records_service_checked=${report.side_door_report.production_records_service_checked}; external_attestation=${report.side_door_report.external_attestation}; sovereign_recognition=${report.side_door_report.sovereign_recognition}`,
    `Operator requirements: ${report.operator_requirements.join(',')}`,
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

export function formatProtectedRecordsRuntimeLocalActivationArtifactVerification(verification) {
  if (
    !verification ||
    verification.verification_type !== PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_VERIFICATION_TYPE
  ) {
    throw new Error('Protected records runtime local activation artifact verification has the wrong type');
  }
  if (verification.verified !== true) {
    throw new Error('Protected records runtime local activation artifact verification is not verified');
  }
  const lines = [
    'ZLAR Protected Records Runtime Local Activation Artifact Verification v1',
    `verified=${verification.verified}`,
    `artifact_type=${verification.artifact_type}`,
    `sha256=${verification.body_sha256}`,
    `payload_type=${verification.payload_type}`,
    `evidence_model=${verification.evidence_model}; live_probing=${verification.live_probing}`,
    `plan_sha256=${verification.plan_sha256}`,
    `runtime_profile_sha256=${verification.runtime_profile_sha256}; sha_matches_plan=${verification.runtime_profile_sha_matches_plan}`,
    `runtime_profile_identity_policy: authority_source=${verification.runtime_profile_identity_authority_source}; request_runtime_profile_id_required=${verification.request_runtime_profile_id_required}; omitted_request_field_present=${verification.omitted_request_runtime_profile_id_present}; omitted_uses_launcher_config=${verification.omitted_runtime_profile_id_uses_launcher_config}; supplied_mismatch_refused=${verification.supplied_mismatched_runtime_profile_id_refused}`,
    `runtime_storage_identities: consumed_authority_grant_store=${verification.consumed_authority_grant_store}; consumption_identity=${verification.consumption_identity}; signed_payload_replay_identity=${verification.signed_payload_replay_identity}`,
    `local_activation_applied=${verification.local_activation_applied}; disposable_runtime_config_written=${verification.disposable_runtime_config_written}; persistent_runtime_config_written=${verification.persistent_runtime_config_written}; hook_configuration_written=${verification.hook_configuration_written}; runtime_service_started=${verification.runtime_service_started}`,
    `historical_artifact_recognized_write_accepted=${verification.historical_artifact_recognized_write_accepted}; historical_artifact_fixture_authority_effect_observed=${verification.historical_artifact_fixture_authority_effect_observed}; is_current_authority_projection=${verification.recognized_write_accepted_is_current_authority_projection}; same_process_signed_payload_replay_refused=${verification.same_process_signed_payload_replay_refused}; restart_consumed_authority_grant_refused=${verification.restart_consumed_authority_grant_refused}; missing_grant_refused=${verification.missing_authority_grant_appointment_refused}; mismatched_grant_refused=${verification.mismatched_authority_grant_appointment_refused}; revoked_grant_refused=${verification.revoked_authority_grant_refused}; expired_grant_refused=${verification.expired_authority_grant_refused}; request_supplied_grant_refused=${verification.request_supplied_authority_grant_refused}; missing_receipt_refused=${verification.missing_receipt_refused}; invalid_receipt_refused=${verification.invalid_receipt_refused}; wrong_runtime_profile_id_refused=${verification.wrong_runtime_profile_id_refused}`,
    `fixture_authority_status: status=${verification.authority_grant_status}; status_contract_sha256=${verification.authority_grant_status_contract_sha256}; artifact_contract_bound=${verification.artifact_contract_bound_to_authority_status}; historical_only_missing_contract_binding=${verification.historical_only_due_to_missing_artifact_grant_contract_binding}; fresh_effect_allowed=${verification.authority_grant_fresh_effect_allowed}; repeated_use_provenance_valid=${verification.authority_grant_repeated_use_provenance_valid}; allows_fixture_rightful_projection=${verification.authority_grant_status_allows_fixture_rightful_projection}; reason_code=${verification.authority_grant_status_reason_code}`,
    `fixture_rightful_issuance_path_evidenced=${verification.fixture_rightful_issuance_path_evidenced}`,
    `runtime_burn_and_rollback_boundaries: witness_commit_failure_reason=${verification.witness_commit_failure_reason_code}; atomic_store_anchor_witness_commit=${verification.atomic_store_anchor_witness_commit}; burn_window_named=${verification.partial_grant_commit_burn_window_named}; witness_ahead_refusal=${verification.store_and_anchor_joint_rollback_refused_while_witness_ahead}; joint_rollback_detection=${verification.store_anchor_and_witness_joint_rollback_detection}; joint_rollback_reopens_grant_reuse=${verification.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse}; host_path_toctou_closed=${verification.host_filesystem_path_toctou_closed}`,
    `claim_boundary=${verification.claim_boundary}`,
    'Non-claims:',
  ];
  for (const claim of verification.non_claims) {
    lines.push(`- ${claim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(summary);
  return summary;
}

export function formatProtectedRecordsRuntimeLocalActivationArtifactSummary(artifact) {
  assertProtectedRecordsRuntimeLocalActivationArtifact(artifact);
  const lines = [
    'Portable local activation artifact:',
    `- type=${artifact.artifact_type}`,
    `- sha256=${artifact.integrity.body_sha256}`,
    `- hash_scope=${artifact.hash_scope}`,
  ];
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(summary);
  return summary;
}
