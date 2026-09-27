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
} from './protected-records-runtime-profile.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_PROFILE_PREFLIGHT_TYPE,
  assertProtectedRecordsRuntimePreflightProfile,
  assertProtectedRecordsRuntimeProfilePreflight,
  runProtectedRecordsRuntimeProfilePreflight,
  runtimeProfileSha256,
} from './protected-records-runtime-profile-preflight.mjs';

export const PROTECTED_RECORDS_RUNTIME_ACTIVATION_PLAN_TYPE =
  'zlar-protected-records-runtime-activation-plan-v1';
export const PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_TYPE =
  'zlar-protected-records-runtime-activation-preflight-v1';
export const PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_TYPE =
  'zlar-protected-records-runtime-activation-preflight-artifact-v1';
export const PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_CANONICALIZATION =
  'zlar-canonical-json-v1';
export const PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE =
  'zlar-protected-records-runtime-activation-preflight-artifact-verification-v1';

export const REQUIRED_RUNTIME_ACTIVATION_OPERATOR_REQUIREMENTS = Object.freeze([
  'human_explicit_install_command',
  'profile_sha_verified_before_activation',
  'launcher_owned_config_written_outside_request_stream',
  'launcher_owned_authority_grant_inputs_supplied_outside_request_stream',
  'downstream_refuses_missing_or_unrecognized_receipts',
  'authority_grant_refusals_before_consumption_and_mutation',
  'non_atomic_burn_joint_rollback_and_toctou_boundaries_accepted',
]);

export const REQUIRED_RUNTIME_ACTIVATION_OPEN_BOUNDARIES = Object.freeze([
  'activation_not_installed',
  'live_runtime_profile',
  'live_records_system',
  'production_records_service',
  'downstream_production_refusal',
  'current_machine_hook_configuration',
  'active_authority_grant_inputs',
  'exactly_once_effect_semantics',
  'store_anchor_witness_commit_atomicity',
  'store_anchor_and_witness_joint_rollback_or_deletion',
  'host_filesystem_path_toctou',
  'external_attestation',
  'sovereign_recognition',
  'unrouted_records_paths',
]);

export const RUNTIME_ACTIVATION_PREFLIGHT_SAFE_CLAIM_CEILING =
  'ZLAR can preflight a source-only sample protected-records runtime activation plan by validating that an explicit plan binds an explicit runtime-profile SHA, requires launcher-owned authority-grant inputs and hidden grant-store paths, performs no activation or configuration change, and still passes the bounded local runtime-profile preflight with signed-payload replay, persistent one-use grant, witness, grant-refusal, burn-window, joint-rollback, and host-path TOCTOU boundaries named truthfully.';

export const RUNTIME_ACTIVATION_PREFLIGHT_NON_CLAIMS = Object.freeze([
  'This activation plan is a sample preflight plan, not an active or installed runtime profile.',
  'This preflight does not install a runtime profile, write runtime configuration, modify hooks, or start a runtime service.',
  'This preflight requires an explicit plan file and explicit profile file; it does not select a live, latest, or current-machine profile.',
  'This preflight runs the bounded local runtime-profile preflight only.',
  'This preflight does not supply or authorize live authority-grant inputs; the validated runtime proof uses only launcher-owned local fixture authority.',
  'This preflight does not inspect a live records system or prove production records service deployment.',
  'This preflight does not prove exactly-once effects or an all-or-nothing store, anchor, and witness commit; state-append or metadata failure after grant-store commit can burn the one-use grant without runtime-state mutation.',
  'This preflight does not detect rollback, deletion, or replacement when the consumed-authority-grant store, local anchor, and local witness move together without stronger custody or an external witness.',
  'This preflight does not close host process, memory, debugger, operator filesystem, post-validation path-replacement, hook-configuration, or unrouted records side doors.',
  'This preflight does not prove production-grade anti-rollback, stale-lock recovery, multi-host coordination, production-grade durable storage, or tamper resistance.',
  'This preflight does not prove live MCP coverage, live approval-channel health, current-machine governance, enterprise readiness, production authority, external attestation, or sovereign recognition.',
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

export function runtimeActivationPlanSha256(plan) {
  assertProtectedRecordsRuntimeActivationPlan(plan);
  return sha256hex(canonicalize(plan));
}

export function assertProtectedRecordsRuntimeActivationPlan(plan) {
  assertExactKeys('Protected records runtime activation plan', plan, [
    'action_class',
    'activation_boundary',
    'activation_contract',
    'deployment_posture',
    'known_open_boundaries',
    'non_claims',
    'operator_install_requirements',
    'plan_id',
    'plan_status',
    'plan_type',
    'preflight_command',
    'proof_command',
    'runtime_profile_id',
    'runtime_profile_preflight_command',
    'runtime_profile_sha256',
    'runtime_profile_source',
    'service_command',
  ]);
  if (
    plan.plan_type !== PROTECTED_RECORDS_RUNTIME_ACTIVATION_PLAN_TYPE ||
    plan.plan_id !== 'protected-records-runtime-fixture-activation-plan' ||
    plan.plan_status !== 'sample_not_active' ||
    plan.deployment_posture !== 'activation_plan_preflight_only' ||
    plan.action_class !== 'records.write' ||
    plan.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    plan.runtime_profile_source !== 'profiles/protected-records-runtime-fixture.profile.json' ||
    !/^[a-f0-9]{64}$/.test(plan.runtime_profile_sha256) ||
    plan.preflight_command !== 'zlar protected-records-runtime-activation-preflight --plan profiles/protected-records-runtime-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json' ||
    plan.runtime_profile_preflight_command !== 'zlar protected-records-runtime-profile-preflight --profile profiles/protected-records-runtime-fixture.profile.json' ||
    plan.service_command !== 'zlar protected-records-runtime-service --config <launcher-owned-config>' ||
    plan.proof_command !== 'zlar protected-records-runtime-profile-proof'
  ) {
    throw new Error('Protected records runtime activation plan contract drifted');
  }

  assertExactKeys('Protected records runtime activation boundary', plan.activation_boundary, [
    'activation_applied',
    'request_stream_authority_material_accepted',
    'requires_explicit_human_install',
    'selects_latest_profile',
    'starts_runtime_service',
    'uses_live_records_system',
    'writes_hook_configuration',
    'writes_runtime_config',
  ]);
  const boundary = plan.activation_boundary;
  if (
    boundary.activation_applied !== false ||
    boundary.writes_runtime_config !== false ||
    boundary.writes_hook_configuration !== false ||
    boundary.starts_runtime_service !== false ||
    boundary.requires_explicit_human_install !== true ||
    boundary.selects_latest_profile !== false ||
    boundary.request_stream_authority_material_accepted !== false ||
    boundary.uses_live_records_system !== false
  ) {
    throw new Error('Protected records runtime activation boundary drifted');
  }

  assertExactKeys('Protected records runtime activation contract', plan.activation_contract, [
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
    throw new Error('Protected records runtime activation contract drifted');
  }

  assertExactArray(
    'Protected records runtime activation operator install requirements',
    plan.operator_install_requirements,
    REQUIRED_RUNTIME_ACTIVATION_OPERATOR_REQUIREMENTS
  );
  assertExactArray(
    'Protected records runtime activation open boundaries',
    plan.known_open_boundaries,
    REQUIRED_RUNTIME_ACTIVATION_OPEN_BOUNDARIES
  );
  assertExactArray(
    'Protected records runtime activation non-claims',
    plan.non_claims,
    RUNTIME_ACTIVATION_PREFLIGHT_NON_CLAIMS
  );
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(plan));
  return true;
}

export function runProtectedRecordsRuntimeActivationPreflight(plan, profile) {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
    'Protected records runtime activation-preflight proof generation',
  );
  assertProtectedRecordsRuntimeActivationPlan(plan);
  assertProtectedRecordsRuntimePreflightProfile(profile);
  const actualProfileSha = runtimeProfileSha256(profile);
  if (plan.runtime_profile_sha256 !== actualProfileSha) {
    throw new Error('Protected records runtime activation plan profile SHA mismatch');
  }

  const runtimePreflight = runProtectedRecordsRuntimeProfilePreflight(profile);
  assertProtectedRecordsRuntimeProfilePreflight(runtimePreflight, profile);

  const report = {
    preflight_type: PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_TYPE,
    evidence_model: 'local-runtime-activation-plan-preflight-fixture',
    live_probing: false,
    safe_claim_ceiling: RUNTIME_ACTIVATION_PREFLIGHT_SAFE_CLAIM_CEILING,
    plan: {
      plan_type: plan.plan_type,
      plan_id: plan.plan_id,
      plan_status: plan.plan_status,
      deployment_posture: plan.deployment_posture,
      plan_sha256: runtimeActivationPlanSha256(plan),
    },
    runtime_profile: {
      profile_id: profile.profile_id,
      runtime_profile_id: profile.runtime_profile_id,
      profile_status: profile.profile_status,
      profile_sha256: actualProfileSha,
      profile_sha_matches_plan: true,
    },
    activation_boundary: { ...plan.activation_boundary },
    activation_contract: { ...plan.activation_contract },
    runtime_profile_preflight_summary: {
      preflight_type: runtimePreflight.preflight_type,
      preflight_command: plan.runtime_profile_preflight_command,
      preflight_run: true,
      preflight_evidence_model: runtimePreflight.evidence_model,
      proof_run_in_preflight: runtimePreflight.proof_summary.proof_run_in_preflight,
      proof_case_count: runtimePreflight.proof_summary.proof_case_count,
      proof_required_case_count: runtimePreflight.proof_summary.proof_required_case_count,
      proof_boundary_observation_count: runtimePreflight.proof_summary.proof_boundary_observation_count,
      proof_required_boundary_observation_count:
        runtimePreflight.proof_summary.proof_required_boundary_observation_count,
      mutation_authoritative_route:
        runtimePreflight.runtime_profile_contract.mutation_authoritative_route,
      consumed_authority_grant_store:
        runtimePreflight.runtime_profile_contract.consumed_authority_grant_store,
      consumption_identity:
        runtimePreflight.runtime_profile_contract.consumption_identity,
      signed_payload_replay_identity:
        runtimePreflight.runtime_profile_contract.signed_payload_replay_identity,
      consumed_store_witness:
        runtimePreflight.runtime_profile_contract.consumed_store_witness,
      consumed_store_write_model:
        runtimePreflight.runtime_profile_contract.consumed_store_write_model,
      recognized_write_accepted: runtimePreflight.proof_summary.recognized_write_accepted,
      same_process_signed_payload_replay_refused:
        runtimePreflight.proof_summary.proof_run_in_preflight === true &&
        profile.required_cases.includes(
          'replay_runtime_write_refused_same_service_process'
        ),
      restart_consumed_authority_grant_refused:
        runtimePreflight.proof_summary.replay_after_restart_refused,
      invalid_consumed_authority_grant_store_refused:
        runtimePreflight.proof_summary.invalid_consumed_store_refused,
      invalid_consumed_authority_grant_store_anchor_refused:
        runtimePreflight.proof_summary.invalid_consumed_store_anchor_refused,
      consumed_authority_grant_store_rollback_refused:
        runtimePreflight.proof_summary.consumed_store_rollback_refused,
      consumed_authority_grant_store_deletion_refused:
        runtimePreflight.proof_summary.consumed_store_deletion_refused,
      consumed_authority_grant_store_replacement_refused:
        runtimePreflight.proof_summary.consumed_store_replacement_refused,
      witness_commit_failed_after_authority_grant_store_commit:
        runtimePreflight.proof_summary
          .witness_commit_failed_after_authority_grant_store_commit,
      witness_commit_failure_reason_code:
        runtimePreflight.proof_summary.witness_commit_failure_reason_code,
      witness_commit_failure_consumed_authority_grant_count:
        runtimePreflight.proof_summary
          .witness_commit_failure_consumed_authority_grant_count,
      store_and_anchor_joint_rollback_refused_against_witness:
        runtimePreflight.proof_summary
          .store_and_anchor_joint_rollback_refused_against_witness,
      missing_authority_grant_appointment_refused:
        runtimePreflight.proof_summary
          .missing_authority_grant_appointment_refused,
      mismatched_authority_grant_appointment_refused:
        runtimePreflight.proof_summary
          .mismatched_authority_grant_appointment_refused,
      revoked_authority_grant_refused:
        runtimePreflight.proof_summary.revoked_authority_grant_refused,
      expired_authority_grant_refused:
        runtimePreflight.proof_summary.expired_authority_grant_refused,
      request_supplied_authority_grant_refused:
        runtimePreflight.proof_summary.request_supplied_authority_grant_refused,
      agent_supplied_authority_material_refused:
        runtimePreflight.proof_summary.agent_supplied_authority_material_refused,
      runtime_profile_identity_authority_source:
        runtimePreflight.proof_summary.runtime_profile_identity_authority_source,
      runtime_profile_identity_request_stream_policy:
        runtimePreflight.proof_summary.runtime_profile_identity_request_stream_policy,
      request_runtime_profile_id_required:
        runtimePreflight.proof_summary.request_runtime_profile_id_required,
      omitted_request_runtime_profile_id_present:
        runtimePreflight.proof_summary.omitted_request_runtime_profile_id_present,
      omitted_runtime_profile_id_uses_launcher_config:
        runtimePreflight.proof_summary.omitted_runtime_profile_id_uses_launcher_config,
      omitted_runtime_profile_id_reason_code:
        runtimePreflight.proof_summary.omitted_runtime_profile_id_reason_code,
      omitted_runtime_profile_id_state_entry_count_delta:
        runtimePreflight.proof_summary.omitted_runtime_profile_id_state_entry_count_delta,
      omitted_runtime_profile_id_consumed_authority_grant_count:
        runtimePreflight.proof_summary
          .omitted_runtime_profile_id_consumed_authority_grant_count,
      supplied_mismatched_runtime_profile_id_refused:
        runtimePreflight.proof_summary.supplied_mismatched_runtime_profile_id_refused,
      supplied_mismatch_reason_code:
        runtimePreflight.proof_summary.supplied_mismatch_reason_code,
      supplied_mismatch_state_entry_count_delta:
        runtimePreflight.proof_summary.supplied_mismatch_state_entry_count_delta,
      store_and_anchor_joint_rollback_refused_while_witness_ahead:
        runtimePreflight.proof_summary
          .store_and_anchor_joint_rollback_refused_while_witness_ahead,
      store_anchor_and_witness_joint_rollback_detection:
        runtimePreflight.proof_summary
          .store_anchor_and_witness_joint_rollback_detection,
      store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse:
        runtimePreflight.proof_summary
          .store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse,
      persistent_runtime_profile_installed:
        runtimePreflight.proof_summary.persistent_runtime_profile_installed,
      live_probing: runtimePreflight.live_probing,
    },
    side_door_report: {
      activation_applied: false,
      runtime_config_written: false,
      hook_configuration_written: false,
      runtime_service_started: false,
      persistent_runtime_profile_installed: false,
      latest_profile_selected: false,
      request_stream_authority_material_accepted: false,
      consumed_grants_path_exposed_to_agent:
        runtimePreflight.side_door_report.consumed_grants_path_exposed_to_agent,
      consumed_grant_store_anchor_path_exposed_to_agent:
        runtimePreflight.side_door_report
          .consumed_grant_store_anchor_path_exposed_to_agent,
      consumed_grant_store_witness_path_exposed_to_agent:
        runtimePreflight.side_door_report
          .consumed_grant_store_witness_path_exposed_to_agent,
      request_supplied_authority_grant_refused:
        runtimePreflight.side_door_report.request_supplied_authority_grant_refused,
      persistent_consumed_authority_grant_store:
        runtimePreflight.side_door_report
          .persistent_consumed_authority_grant_store,
      consumed_store_anchor_present:
        runtimePreflight.side_door_report.consumed_store_anchor_present,
      consumed_store_witness_present:
        runtimePreflight.side_door_report.consumed_store_witness_present,
      live_records_system_checked: false,
      production_records_service_checked: false,
      live_mcp_coverage_checked: false,
      live_approval_channel_health_checked: false,
      external_attestation: false,
      sovereign_recognition: false,
      store_and_anchor_joint_rollback_refused_while_witness_ahead:
        runtimePreflight.side_door_report
          .store_and_anchor_joint_rollback_refused_while_witness_ahead,
      store_anchor_and_witness_joint_rollback_detection:
        runtimePreflight.side_door_report
          .store_anchor_and_witness_joint_rollback_detection,
      store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse:
        runtimePreflight.side_door_report
          .store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse,
      atomic_store_anchor_witness_commit:
        runtimePreflight.side_door_report.atomic_store_anchor_witness_commit,
      partial_grant_commit_burn_window_named:
        runtimePreflight.side_door_report.partial_grant_commit_burn_window_named,
      partial_commit_witness_missing_observed:
        runtimePreflight.side_door_report.partial_commit_witness_missing_observed,
      host_filesystem_path_toctou_closed:
        runtimePreflight.side_door_report.host_filesystem_path_toctou_closed,
      exactly_once_effect_semantics:
        runtimePreflight.side_door_report.exactly_once_effect_semantics,
      unrouted_records_paths_checked: false,
    },
    operator_install_requirements: [...plan.operator_install_requirements],
    known_open_boundaries: [...plan.known_open_boundaries],
    non_claims: [...RUNTIME_ACTIVATION_PREFLIGHT_NON_CLAIMS],
  };
  assertProtectedRecordsRuntimeActivationPreflight(report, plan, profile);
  return report;
}

export function assertProtectedRecordsRuntimeActivationPreflight(report, plan, profile) {
  assertProtectedRecordsRuntimeActivationPlan(plan);
  assertProtectedRecordsRuntimePreflightProfile(profile);
  assertExactKeys('Protected records runtime activation preflight', report, [
    'activation_boundary',
    'activation_contract',
    'evidence_model',
    'known_open_boundaries',
    'live_probing',
    'non_claims',
    'operator_install_requirements',
    'plan',
    'preflight_type',
    'runtime_profile',
    'runtime_profile_preflight_summary',
    'safe_claim_ceiling',
    'side_door_report',
  ]);
  if (
    report.preflight_type !== PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_TYPE ||
    report.evidence_model !== 'local-runtime-activation-plan-preflight-fixture' ||
    report.live_probing !== false ||
    report.safe_claim_ceiling !== RUNTIME_ACTIVATION_PREFLIGHT_SAFE_CLAIM_CEILING
  ) {
    throw new Error('Protected records runtime activation preflight top-level contract drifted');
  }

  assertExactKeys('Protected records runtime activation preflight plan identity', report.plan, [
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
    report.plan.plan_sha256 !== runtimeActivationPlanSha256(plan)
  ) {
    throw new Error('Protected records runtime activation preflight plan identity drifted');
  }

  assertExactKeys('Protected records runtime activation preflight profile identity', report.runtime_profile, [
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
    throw new Error('Protected records runtime activation preflight profile identity drifted');
  }

  if (canonicalize(report.activation_boundary) !== canonicalize(plan.activation_boundary)) {
    throw new Error('Protected records runtime activation preflight boundary drifted');
  }
  if (canonicalize(report.activation_contract) !== canonicalize(plan.activation_contract)) {
    throw new Error('Protected records runtime activation preflight contract drifted');
  }

  assertExactKeys('Protected records runtime activation profile preflight summary', report.runtime_profile_preflight_summary, [
    'agent_supplied_authority_material_refused',
    'consumed_authority_grant_store',
    'consumed_authority_grant_store_deletion_refused',
    'consumed_authority_grant_store_replacement_refused',
    'consumed_authority_grant_store_rollback_refused',
    'consumed_store_witness',
    'consumed_store_write_model',
    'consumption_identity',
    'expired_authority_grant_refused',
    'invalid_consumed_authority_grant_store_anchor_refused',
    'invalid_consumed_authority_grant_store_refused',
    'live_probing',
    'omitted_request_runtime_profile_id_present',
    'mismatched_authority_grant_appointment_refused',
    'missing_authority_grant_appointment_refused',
    'mutation_authoritative_route',
    'omitted_runtime_profile_id_consumed_authority_grant_count',
    'omitted_runtime_profile_id_reason_code',
    'omitted_runtime_profile_id_state_entry_count_delta',
    'omitted_runtime_profile_id_uses_launcher_config',
    'persistent_runtime_profile_installed',
    'preflight_command',
    'preflight_evidence_model',
    'preflight_run',
    'preflight_type',
    'proof_boundary_observation_count',
    'proof_case_count',
    'proof_required_boundary_observation_count',
    'proof_required_case_count',
    'proof_run_in_preflight',
    'recognized_write_accepted',
    'request_runtime_profile_id_required',
    'request_supplied_authority_grant_refused',
    'restart_consumed_authority_grant_refused',
    'revoked_authority_grant_refused',
    'runtime_profile_identity_authority_source',
    'runtime_profile_identity_request_stream_policy',
    'same_process_signed_payload_replay_refused',
    'signed_payload_replay_identity',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse',
    'store_and_anchor_joint_rollback_refused_against_witness',
    'store_and_anchor_joint_rollback_refused_while_witness_ahead',
    'supplied_mismatch_reason_code',
    'supplied_mismatch_state_entry_count_delta',
    'supplied_mismatched_runtime_profile_id_refused',
    'witness_commit_failed_after_authority_grant_store_commit',
    'witness_commit_failure_consumed_authority_grant_count',
    'witness_commit_failure_reason_code',
  ]);
  const summary = report.runtime_profile_preflight_summary;
  if (
    summary.preflight_type !== PROTECTED_RECORDS_RUNTIME_PROFILE_PREFLIGHT_TYPE ||
    summary.preflight_command !== plan.runtime_profile_preflight_command ||
    summary.preflight_run !== true ||
    summary.preflight_evidence_model !== 'local-disposable-runtime-profile-preflight-fixture' ||
    summary.proof_run_in_preflight !== true ||
    summary.proof_case_count !== profile.required_cases.length ||
    summary.proof_required_case_count !== profile.required_cases.length ||
    summary.proof_boundary_observation_count !== profile.required_boundary_observations.length ||
    summary.proof_required_boundary_observation_count !== profile.required_boundary_observations.length ||
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
    summary.invalid_consumed_authority_grant_store_refused !== true ||
    summary.invalid_consumed_authority_grant_store_anchor_refused !== true ||
    summary.consumed_authority_grant_store_rollback_refused !== true ||
    summary.consumed_authority_grant_store_deletion_refused !== true ||
    summary.consumed_authority_grant_store_replacement_refused !== true ||
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
    summary.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse !== true ||
    summary.persistent_runtime_profile_installed !== false ||
    summary.live_probing !== false
  ) {
    throw new Error('Protected records runtime activation profile preflight summary drifted');
  }

  assertExactKeys('Protected records runtime activation side-door report', report.side_door_report, [
    'activation_applied',
    'atomic_store_anchor_witness_commit',
    'consumed_grant_store_anchor_path_exposed_to_agent',
    'consumed_grant_store_witness_path_exposed_to_agent',
    'consumed_grants_path_exposed_to_agent',
    'consumed_store_anchor_present',
    'consumed_store_witness_present',
    'exactly_once_effect_semantics',
    'external_attestation',
    'hook_configuration_written',
    'host_filesystem_path_toctou_closed',
    'latest_profile_selected',
    'live_approval_channel_health_checked',
    'live_mcp_coverage_checked',
    'live_records_system_checked',
    'partial_commit_witness_missing_observed',
    'partial_grant_commit_burn_window_named',
    'persistent_consumed_authority_grant_store',
    'persistent_runtime_profile_installed',
    'production_records_service_checked',
    'request_stream_authority_material_accepted',
    'request_supplied_authority_grant_refused',
    'runtime_config_written',
    'runtime_service_started',
    'sovereign_recognition',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse',
    'store_and_anchor_joint_rollback_refused_while_witness_ahead',
    'unrouted_records_paths_checked',
  ]);
  const sideDoor = report.side_door_report;
  if (
    sideDoor.activation_applied !== false ||
    sideDoor.runtime_config_written !== false ||
    sideDoor.hook_configuration_written !== false ||
    sideDoor.runtime_service_started !== false ||
    sideDoor.persistent_runtime_profile_installed !== false ||
    sideDoor.latest_profile_selected !== false ||
    sideDoor.request_stream_authority_material_accepted !== false ||
    sideDoor.consumed_grants_path_exposed_to_agent !== false ||
    sideDoor.consumed_grant_store_anchor_path_exposed_to_agent !== false ||
    sideDoor.consumed_grant_store_witness_path_exposed_to_agent !== false ||
    sideDoor.request_supplied_authority_grant_refused !== true ||
    sideDoor.persistent_consumed_authority_grant_store !== true ||
    sideDoor.consumed_store_anchor_present !== true ||
    sideDoor.consumed_store_witness_present !== true ||
    sideDoor.live_records_system_checked !== false ||
    sideDoor.production_records_service_checked !== false ||
    sideDoor.live_mcp_coverage_checked !== false ||
    sideDoor.live_approval_channel_health_checked !== false ||
    sideDoor.external_attestation !== false ||
    sideDoor.sovereign_recognition !== false ||
    sideDoor.store_and_anchor_joint_rollback_refused_while_witness_ahead !== true ||
    sideDoor.store_anchor_and_witness_joint_rollback_detection !== false ||
    sideDoor.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse !== true ||
    sideDoor.atomic_store_anchor_witness_commit !== false ||
    sideDoor.partial_grant_commit_burn_window_named !== true ||
    sideDoor.partial_commit_witness_missing_observed !== true ||
    sideDoor.host_filesystem_path_toctou_closed !== false ||
    sideDoor.exactly_once_effect_semantics !== false ||
    sideDoor.unrouted_records_paths_checked !== false
  ) {
    throw new Error('Protected records runtime activation side-door report drifted');
  }

  assertExactArray(
    'Protected records runtime activation operator install requirements',
    report.operator_install_requirements,
    REQUIRED_RUNTIME_ACTIVATION_OPERATOR_REQUIREMENTS
  );
  assertExactArray(
    'Protected records runtime activation open boundaries',
    report.known_open_boundaries,
    REQUIRED_RUNTIME_ACTIVATION_OPEN_BOUNDARIES
  );
  assertExactArray(
    'Protected records runtime activation non-claims',
    report.non_claims,
    RUNTIME_ACTIVATION_PREFLIGHT_NON_CLAIMS
  );
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return true;
}

function runtimeActivationPreflightArtifactBody(payload) {
  return {
    artifact_type: PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_TYPE,
    canonicalization: PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_CANONICALIZATION,
    generator: 'zlar protected-records-runtime-activation-preflight --artifact',
    hash_scope: 'canonical artifact body without integrity',
    payload,
  };
}

export function buildProtectedRecordsRuntimeActivationPreflightArtifact(
  plan,
  profile,
  report = runProtectedRecordsRuntimeActivationPreflight(plan, profile)
) {
  assertProtectedRecordsRuntimeActivationPlan(plan);
  assertProtectedRecordsRuntimePreflightProfile(profile);
  assertProtectedRecordsRuntimeActivationPreflight(report, plan, profile);
  const payload = {
    plan,
    runtime_profile: profile,
    preflight: report,
  };
  const body = runtimeActivationPreflightArtifactBody(payload);
  const artifact = {
    ...body,
    integrity: {
      algorithm: 'SHA-256',
      body_sha256: sha256hex(canonicalize(body)),
    },
  };
  assertProtectedRecordsRuntimeActivationPreflightArtifact(artifact);
  return artifact;
}

export function assertProtectedRecordsRuntimeActivationPreflightArtifact(artifact) {
  if (
    !artifact ||
    artifact.artifact_type !== PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_TYPE
  ) {
    throw new Error('Protected records runtime activation preflight artifact has the wrong artifact type');
  }
  assertExactKeys('Protected records runtime activation preflight artifact', artifact, [
    'artifact_type',
    'canonicalization',
    'generator',
    'hash_scope',
    'integrity',
    'payload',
  ]);
  if (
    artifact.canonicalization !==
    PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_CANONICALIZATION
  ) {
    throw new Error('Protected records runtime activation preflight artifact canonicalization drifted');
  }
  if (artifact.generator !== 'zlar protected-records-runtime-activation-preflight --artifact') {
    throw new Error('Protected records runtime activation preflight artifact generator drifted');
  }
  if (artifact.hash_scope !== 'canonical artifact body without integrity') {
    throw new Error('Protected records runtime activation preflight artifact hash scope drifted');
  }

  assertExactKeys('Protected records runtime activation preflight artifact payload', artifact.payload, [
    'plan',
    'preflight',
    'runtime_profile',
  ]);
  assertProtectedRecordsRuntimeActivationPlan(artifact.payload.plan);
  assertProtectedRecordsRuntimePreflightProfile(artifact.payload.runtime_profile);
  assertProtectedRecordsRuntimeActivationPreflight(
    artifact.payload.preflight,
    artifact.payload.plan,
    artifact.payload.runtime_profile
  );

  if (!artifact.integrity || artifact.integrity.algorithm !== 'SHA-256') {
    throw new Error('Protected records runtime activation preflight artifact integrity algorithm drifted');
  }
  assertExactKeys('Protected records runtime activation preflight artifact integrity', artifact.integrity, [
    'algorithm',
    'body_sha256',
  ]);
  if (!/^[a-f0-9]{64}$/.test(artifact.integrity.body_sha256 || '')) {
    throw new Error('Protected records runtime activation preflight artifact SHA-256 is malformed');
  }
  const { integrity, ...body } = artifact;
  const expectedHash = sha256hex(canonicalize(body));
  if (artifact.integrity.body_sha256 !== expectedHash) {
    throw new Error('Protected records runtime activation preflight artifact SHA-256 mismatch');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(artifact));
  return true;
}

export function writeProtectedRecordsRuntimeActivationPreflightArtifact(artifact, outputPath) {
  assertProtectedRecordsRuntimeActivationPreflightArtifact(artifact);
  if (!outputPath || outputPath === '-') {
    throw new Error('Protected records runtime activation preflight artifact output path is required');
  }
  mkdirSync(dirname(outputPath), { recursive: true });
  const output = `${JSON.stringify(artifact, null, 2)}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  writeFileSync(outputPath, output, { mode: 0o600 });
  return artifact.integrity.body_sha256;
}

export function parseProtectedRecordsRuntimeActivationPreflightArtifactText(text) {
  assertNoUnsafeProtectedRecordsRuntimeProfileText(text);
  let artifact;
  try {
    artifact = JSON.parse(text);
  } catch {
    throw new Error('Protected records runtime activation preflight artifact input is not valid JSON');
  }
  assertProtectedRecordsRuntimeActivationPreflightArtifact(artifact);
  return artifact;
}

export function verifyProtectedRecordsRuntimeActivationPreflightArtifact(artifact) {
  assertProtectedRecordsRuntimeActivationPreflightArtifact(artifact);
  const report = artifact.payload.preflight;
  const authorityStatus =
    PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_STATUS;
  const authorityStatusReason =
    protectedRecordsFixtureAuthorityGrantEffectStatusReason(
      PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256
    );
  const historicalFixtureAuthorityEffectObserved =
    report.runtime_profile_preflight_summary.recognized_write_accepted === true &&
    report.runtime_profile_preflight_summary.omitted_runtime_profile_id_reason_code ===
      'fixture_authority_grant_effect_satisfied' &&
    report.runtime_profile_preflight_summary
      .omitted_runtime_profile_id_consumed_authority_grant_count === 1;
  const verification = {
    verification_type: PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE,
    verified: true,
    artifact_type: artifact.artifact_type,
    canonicalization: artifact.canonicalization,
    hash_scope: artifact.hash_scope,
    body_sha256: artifact.integrity.body_sha256,
    payload_type: report.preflight_type,
    evidence_model: report.evidence_model,
    live_probing: report.live_probing,
    plan_sha256: report.plan.plan_sha256,
    runtime_profile_sha256: report.runtime_profile.profile_sha256,
    runtime_profile_sha_matches_plan: report.runtime_profile.profile_sha_matches_plan,
    runtime_profile_preflight_run: report.runtime_profile_preflight_summary.preflight_run,
    runtime_profile_proof_run: report.runtime_profile_preflight_summary.proof_run_in_preflight,
    historical_artifact_runtime_profile_proof_run:
      report.runtime_profile_preflight_summary.proof_run_in_preflight,
    runtime_profile_proof_run_is_current_authority_projection: false,
    historical_artifact_recognized_write_accepted:
      report.runtime_profile_preflight_summary.recognized_write_accepted,
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
    runtime_profile_identity_authority_source:
      report.runtime_profile_preflight_summary.runtime_profile_identity_authority_source,
    runtime_profile_identity_request_stream_policy:
      report.runtime_profile_preflight_summary.runtime_profile_identity_request_stream_policy,
    request_runtime_profile_id_required:
      report.runtime_profile_preflight_summary.request_runtime_profile_id_required,
    omitted_request_runtime_profile_id_present:
      report.runtime_profile_preflight_summary.omitted_request_runtime_profile_id_present,
    omitted_runtime_profile_id_uses_launcher_config:
      report.runtime_profile_preflight_summary.omitted_runtime_profile_id_uses_launcher_config,
    omitted_runtime_profile_id_reason_code:
      report.runtime_profile_preflight_summary.omitted_runtime_profile_id_reason_code,
    omitted_runtime_profile_id_state_entry_count_delta:
      report.runtime_profile_preflight_summary.omitted_runtime_profile_id_state_entry_count_delta,
    omitted_runtime_profile_id_consumed_authority_grant_count:
      report.runtime_profile_preflight_summary
        .omitted_runtime_profile_id_consumed_authority_grant_count,
    supplied_mismatched_runtime_profile_id_refused:
      report.runtime_profile_preflight_summary.supplied_mismatched_runtime_profile_id_refused,
    supplied_mismatch_reason_code:
      report.runtime_profile_preflight_summary.supplied_mismatch_reason_code,
    supplied_mismatch_state_entry_count_delta:
      report.runtime_profile_preflight_summary.supplied_mismatch_state_entry_count_delta,
    consumed_authority_grant_store:
      report.runtime_profile_preflight_summary.consumed_authority_grant_store,
    consumption_identity:
      report.runtime_profile_preflight_summary.consumption_identity,
    signed_payload_replay_identity:
      report.runtime_profile_preflight_summary.signed_payload_replay_identity,
    same_process_signed_payload_replay_refused:
      report.runtime_profile_preflight_summary
        .same_process_signed_payload_replay_refused,
    restart_consumed_authority_grant_refused:
      report.runtime_profile_preflight_summary
        .restart_consumed_authority_grant_refused,
    missing_authority_grant_appointment_refused:
      report.runtime_profile_preflight_summary
        .missing_authority_grant_appointment_refused,
    mismatched_authority_grant_appointment_refused:
      report.runtime_profile_preflight_summary
        .mismatched_authority_grant_appointment_refused,
    revoked_authority_grant_refused:
      report.runtime_profile_preflight_summary.revoked_authority_grant_refused,
    expired_authority_grant_refused:
      report.runtime_profile_preflight_summary.expired_authority_grant_refused,
    request_supplied_authority_grant_refused:
      report.runtime_profile_preflight_summary
        .request_supplied_authority_grant_refused,
    witness_commit_failed_after_authority_grant_store_commit:
      report.runtime_profile_preflight_summary
        .witness_commit_failed_after_authority_grant_store_commit,
    witness_commit_failure_reason_code:
      report.runtime_profile_preflight_summary.witness_commit_failure_reason_code,
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
    activation_applied: report.side_door_report.activation_applied,
    runtime_config_written: report.side_door_report.runtime_config_written,
    hook_configuration_written: report.side_door_report.hook_configuration_written,
    runtime_service_started: report.side_door_report.runtime_service_started,
    claim_boundary:
      'artifact integrity and historical embedded local runtime activation-preflight facts only; current fixture-rightful projection refused by shared authority status',
    non_claims: [...report.non_claims],
  };
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(verification));
  return verification;
}

export function formatProtectedRecordsRuntimeActivationPreflightSummary(report, plan, profile) {
  assertProtectedRecordsRuntimeActivationPreflight(report, plan, profile);
  const lines = [
    'ZLAR Protected Records Runtime Activation Preflight v1',
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Evidence model: ${report.evidence_model}; live probing=${report.live_probing}`,
    `Plan: id=${report.plan.plan_id}; status=${report.plan.plan_status}; posture=${report.plan.deployment_posture}; sha256=${report.plan.plan_sha256}`,
    `Runtime profile: id=${report.runtime_profile.profile_id}; runtime_profile=${report.runtime_profile.runtime_profile_id}; profile_sha256=${report.runtime_profile.profile_sha256}; sha_matches_plan=${report.runtime_profile.profile_sha_matches_plan}`,
    `Activation boundary: applied=${report.activation_boundary.activation_applied}; writes_runtime_config=${report.activation_boundary.writes_runtime_config}; writes_hook_configuration=${report.activation_boundary.writes_hook_configuration}; starts_runtime_service=${report.activation_boundary.starts_runtime_service}; requires_explicit_human_install=${report.activation_boundary.requires_explicit_human_install}; selects_latest_profile=${report.activation_boundary.selects_latest_profile}`,
    `Activation contract: launcher_config=${report.activation_contract.launcher_supplies_config}; config_path_agent_supplied=${report.activation_contract.config_path_agent_supplied}; state_path_agent_supplied=${report.activation_contract.state_path_agent_supplied}; consumed_grants_path_agent_supplied=${report.activation_contract.consumed_grants_path_agent_supplied}; consumed_grant_anchor_path_agent_supplied=${report.activation_contract.consumed_grant_store_anchor_path_agent_supplied}; consumed_grant_witness_path_agent_supplied=${report.activation_contract.consumed_grant_store_witness_path_agent_supplied}; authority_grant_required=${report.activation_contract.authority_grant_contract_required_from_launcher}; request_supplied_grant_refused=${report.activation_contract.request_supplied_authority_grant_refused}`,
    `Runtime profile preflight: command=${report.runtime_profile_preflight_summary.preflight_command}; run=${report.runtime_profile_preflight_summary.preflight_run}; proof_run=${report.runtime_profile_preflight_summary.proof_run_in_preflight}; cases=${report.runtime_profile_preflight_summary.proof_case_count}/${report.runtime_profile_preflight_summary.proof_required_case_count}; boundary_observations=${report.runtime_profile_preflight_summary.proof_boundary_observation_count}/${report.runtime_profile_preflight_summary.proof_required_boundary_observation_count}`,
    `Runtime profile identity policy: authority_source=${report.runtime_profile_preflight_summary.runtime_profile_identity_authority_source}; request_runtime_profile_id_required=${report.runtime_profile_preflight_summary.request_runtime_profile_id_required}; omitted_request_field_present=${report.runtime_profile_preflight_summary.omitted_request_runtime_profile_id_present}; omitted_uses_launcher_config=${report.runtime_profile_preflight_summary.omitted_runtime_profile_id_uses_launcher_config}; supplied_mismatch_refused=${report.runtime_profile_preflight_summary.supplied_mismatched_runtime_profile_id_refused}`,
    `Runtime storage identities: consumed_authority_grant_store=${report.runtime_profile_preflight_summary.consumed_authority_grant_store}; consumption_identity=${report.runtime_profile_preflight_summary.consumption_identity}; signed_payload_replay_identity=${report.runtime_profile_preflight_summary.signed_payload_replay_identity}; witness=${report.runtime_profile_preflight_summary.consumed_store_witness}`,
    `Runtime proof checks: recognized_write_accepted=${report.runtime_profile_preflight_summary.recognized_write_accepted}; same_process_signed_payload_replay_refused=${report.runtime_profile_preflight_summary.same_process_signed_payload_replay_refused}; restart_consumed_authority_grant_refused=${report.runtime_profile_preflight_summary.restart_consumed_authority_grant_refused}; grant_store_rollback_refused=${report.runtime_profile_preflight_summary.consumed_authority_grant_store_rollback_refused}; grant_store_deletion_refused=${report.runtime_profile_preflight_summary.consumed_authority_grant_store_deletion_refused}; grant_store_replacement_refused=${report.runtime_profile_preflight_summary.consumed_authority_grant_store_replacement_refused}; missing_grant_refused=${report.runtime_profile_preflight_summary.missing_authority_grant_appointment_refused}; mismatched_grant_refused=${report.runtime_profile_preflight_summary.mismatched_authority_grant_appointment_refused}; revoked_grant_refused=${report.runtime_profile_preflight_summary.revoked_authority_grant_refused}; expired_grant_refused=${report.runtime_profile_preflight_summary.expired_authority_grant_refused}; request_supplied_grant_refused=${report.runtime_profile_preflight_summary.request_supplied_authority_grant_refused}`,
    `Burn and rollback boundaries: witness_commit_failed_after_grant_store_commit=${report.runtime_profile_preflight_summary.witness_commit_failed_after_authority_grant_store_commit}; witness_commit_failure_reason=${report.runtime_profile_preflight_summary.witness_commit_failure_reason_code}; atomic_store_anchor_witness_commit=${report.side_door_report.atomic_store_anchor_witness_commit}; burn_window_named=${report.side_door_report.partial_grant_commit_burn_window_named}; witness_ahead_refusal=${report.side_door_report.store_and_anchor_joint_rollback_refused_while_witness_ahead}; joint_rollback_detection=${report.side_door_report.store_anchor_and_witness_joint_rollback_detection}; joint_rollback_reopens_grant_reuse=${report.side_door_report.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse}; host_path_toctou_closed=${report.side_door_report.host_filesystem_path_toctou_closed}`,
    `Side-door report: activation_applied=${report.side_door_report.activation_applied}; persistent_runtime_profile_installed=${report.side_door_report.persistent_runtime_profile_installed}; runtime_config_written=${report.side_door_report.runtime_config_written}; hook_configuration_written=${report.side_door_report.hook_configuration_written}; live_records_system_checked=${report.side_door_report.live_records_system_checked}; production_records_service_checked=${report.side_door_report.production_records_service_checked}`,
    `Operator install requirements: ${report.operator_install_requirements.join(',')}`,
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

export function formatProtectedRecordsRuntimeActivationPreflightArtifactVerification(verification) {
  if (
    !verification ||
    verification.verification_type !==
      PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE
  ) {
    throw new Error('Protected records runtime activation preflight artifact verification has the wrong type');
  }
  if (verification.verified !== true) {
    throw new Error('Protected records runtime activation preflight artifact verification is not verified');
  }
  const lines = [
    'ZLAR Protected Records Runtime Activation Preflight Artifact Verification v1',
    `verified=${verification.verified}`,
    `artifact_type=${verification.artifact_type}`,
    `sha256=${verification.body_sha256}`,
    `payload_type=${verification.payload_type}`,
    `evidence_model=${verification.evidence_model}; live_probing=${verification.live_probing}`,
    `plan_sha256=${verification.plan_sha256}`,
    `runtime_profile_sha256=${verification.runtime_profile_sha256}; sha_matches_plan=${verification.runtime_profile_sha_matches_plan}`,
    `runtime_profile_preflight_run=${verification.runtime_profile_preflight_run}; historical_artifact_runtime_profile_proof_run=${verification.historical_artifact_runtime_profile_proof_run}; is_current_authority_projection=${verification.runtime_profile_proof_run_is_current_authority_projection}; historical_artifact_recognized_write_accepted=${verification.historical_artifact_recognized_write_accepted}; historical_artifact_fixture_authority_effect_observed=${verification.historical_artifact_fixture_authority_effect_observed}`,
    `fixture_authority_status: status=${verification.authority_grant_status}; status_contract_sha256=${verification.authority_grant_status_contract_sha256}; artifact_contract_bound=${verification.artifact_contract_bound_to_authority_status}; historical_only_missing_contract_binding=${verification.historical_only_due_to_missing_artifact_grant_contract_binding}; fresh_effect_allowed=${verification.authority_grant_fresh_effect_allowed}; repeated_use_provenance_valid=${verification.authority_grant_repeated_use_provenance_valid}; allows_fixture_rightful_projection=${verification.authority_grant_status_allows_fixture_rightful_projection}; reason_code=${verification.authority_grant_status_reason_code}`,
    `fixture_rightful_issuance_path_evidenced=${verification.fixture_rightful_issuance_path_evidenced}`,
    `runtime_profile_identity_policy: authority_source=${verification.runtime_profile_identity_authority_source}; request_runtime_profile_id_required=${verification.request_runtime_profile_id_required}; omitted_request_field_present=${verification.omitted_request_runtime_profile_id_present}; omitted_uses_launcher_config=${verification.omitted_runtime_profile_id_uses_launcher_config}; supplied_mismatch_refused=${verification.supplied_mismatched_runtime_profile_id_refused}`,
    `runtime_storage_identities: consumed_authority_grant_store=${verification.consumed_authority_grant_store}; consumption_identity=${verification.consumption_identity}; signed_payload_replay_identity=${verification.signed_payload_replay_identity}`,
    `runtime_replay_and_grant_refusals: same_process_signed_payload_replay_refused=${verification.same_process_signed_payload_replay_refused}; restart_consumed_authority_grant_refused=${verification.restart_consumed_authority_grant_refused}; missing_grant_refused=${verification.missing_authority_grant_appointment_refused}; mismatched_grant_refused=${verification.mismatched_authority_grant_appointment_refused}; revoked_grant_refused=${verification.revoked_authority_grant_refused}; expired_grant_refused=${verification.expired_authority_grant_refused}; request_supplied_grant_refused=${verification.request_supplied_authority_grant_refused}`,
    `runtime_burn_and_rollback_boundaries: witness_commit_failure_reason=${verification.witness_commit_failure_reason_code}; atomic_store_anchor_witness_commit=${verification.atomic_store_anchor_witness_commit}; burn_window_named=${verification.partial_grant_commit_burn_window_named}; witness_ahead_refusal=${verification.store_and_anchor_joint_rollback_refused_while_witness_ahead}; joint_rollback_detection=${verification.store_anchor_and_witness_joint_rollback_detection}; joint_rollback_reopens_grant_reuse=${verification.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse}; host_path_toctou_closed=${verification.host_filesystem_path_toctou_closed}`,
    `activation_applied=${verification.activation_applied}; runtime_config_written=${verification.runtime_config_written}; hook_configuration_written=${verification.hook_configuration_written}; runtime_service_started=${verification.runtime_service_started}`,
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

export function formatProtectedRecordsRuntimeActivationPreflightArtifactSummary(artifact) {
  assertProtectedRecordsRuntimeActivationPreflightArtifact(artifact);
  const lines = [
    'Portable activation preflight artifact:',
    `- type=${artifact.artifact_type}`,
    `- sha256=${artifact.integrity.body_sha256}`,
    `- hash_scope=${artifact.hash_scope}`,
  ];
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(summary);
  return summary;
}
