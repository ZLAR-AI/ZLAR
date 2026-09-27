import {
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from './protected-records-runtime-profile.mjs';
import {
  assertProtectedRecordsRuntimePreflightProfile,
} from './protected-records-runtime-profile-preflight.mjs';
import {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed,
} from './protected-records-fixture-authority-status.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_VERIFICATION_TYPE,
  PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PROOF_TYPE,
  RUNTIME_LOCAL_ACTIVATION_NON_CLAIMS,
  assertProtectedRecordsRuntimeLocalActivationPlan,
  assertProtectedRecordsRuntimeLocalActivationProof,
  buildProtectedRecordsRuntimeLocalActivationArtifact,
  runProtectedRecordsRuntimeLocalActivationProof,
  verifyProtectedRecordsRuntimeLocalActivationArtifact,
} from './protected-records-runtime-local-activation.mjs';

export const RECORDS_WRITE_TERMINAL_PROOF_TYPE = 'zlar-records-write-terminal-proof-v1';
export const RECORDS_WRITE_TERMINAL_ID = 'protected-records.runtime.records.write';
export const RECORDS_WRITE_TERMINAL_CHECKPOINT =
  'protected-records-runtime-local-activation:receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation';
export const RECORDS_WRITE_TERMINAL_ROUTE =
  'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation';
export const RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY =
  'protected-records-runtime-service:local-jsonl-child-process';
export const RECORDS_WRITE_TERMINAL_COMMAND = 'zlar records-write-terminal-proof';
export const RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_TYPE =
  'zlar-records-write-active-profile-selection-v1';
export const RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_SCOPE =
  'local-disposable-proof-harness';
export const RECORDS_WRITE_TERMINAL_AIRPORT_SENTENCE =
  'In this local disposable proof path, records.write reaches the protected-records runtime checkpoint, one recognized receipt with a satisfied launcher-owned fixture authority grant boards into bounded service-state mutation, and recognition or authority-grant failures refuse before mutation; grant-burn, joint-rollback, and host-path side doors remain named.';
export const RECORDS_WRITE_DOWNSTREAM_REFUSAL_CONTRACT_TYPE =
  'zlar-records-write-downstream-refusal-contract-v1';

export const REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS = Object.freeze([
  {
    case_id: 'missing_receipt_refused_before_runtime_mutation',
    refusal_class: 'missing_receipt',
    reason_code: 'receipt_missing',
  },
  {
    case_id: 'invalid_receipt_refused_before_runtime_mutation',
    refusal_class: 'invalid_receipt',
    reason_code: 'receipt_invalid',
  },
  {
    case_id: 'unknown_issuer_refused_before_runtime_mutation',
    refusal_class: 'unrecognized_issuer',
    reason_code: 'unknown_issuer',
  },
  {
    case_id: 'retired_issuer_refused_before_runtime_mutation',
    refusal_class: 'unrecognized_issuer',
    reason_code: 'issuer_not_active',
  },
  {
    case_id: 'missing_issuer_status_refused_before_runtime_mutation',
    refusal_class: 'unrecognized_issuer',
    reason_code: 'issuer_status_missing',
  },
  {
    case_id: 'missing_authority_grant_appointment_refused_before_consumption',
    refusal_class: 'authority_grant',
    reason_code: 'authority_grant_missing',
  },
  {
    case_id: 'mismatched_authority_grant_appointment_refused_before_consumption',
    refusal_class: 'authority_grant',
    reason_code: 'authority_grant_contract_mismatch',
  },
  {
    case_id: 'revoked_authority_grant_refused_before_consumption',
    refusal_class: 'authority_grant',
    reason_code: 'authority_grant_revoked',
  },
  {
    case_id: 'expired_authority_grant_refused_before_consumption',
    refusal_class: 'authority_grant',
    reason_code: 'authority_grant_expired',
  },
  {
    case_id: 'stale_receipt_refused_before_runtime_mutation',
    refusal_class: 'stale_or_expired_receipt',
    reason_code: 'receipt_stale',
  },
  {
    case_id: 'wrong_policy_refused_before_runtime_mutation',
    refusal_class: 'wrong_policy',
    reason_code: 'policy_not_recognized',
  },
  {
    case_id: 'wrong_domain_refused_before_runtime_mutation',
    refusal_class: 'out_of_scope',
    reason_code: 'domain_out_of_scope',
  },
  {
    case_id: 'wrong_tool_refused_before_runtime_mutation',
    refusal_class: 'out_of_scope',
    reason_code: 'tool_out_of_scope',
  },
  {
    case_id: 'wrong_runtime_profile_id_refused_before_runtime_mutation',
    refusal_class: 'unrecognized_runtime_profile',
    reason_code: 'agent_supplied_authority_material',
  },
  {
    case_id: 'wrong_audit_event_refused_before_runtime_mutation',
    refusal_class: 'action_binding_mismatch',
    reason_code: 'audit_event_mismatch',
  },
  {
    case_id: 'wrong_detail_refused_before_runtime_mutation',
    refusal_class: 'action_binding_mismatch',
    reason_code: 'detail_hash_mismatch',
  },
  {
    case_id: 'non_boarding_outcome_refused_before_runtime_mutation',
    refusal_class: 'non_boarding_outcome',
    reason_code: 'outcome_not_boarding',
  },
  {
    case_id: 'direct_api_without_receipt_refused_before_runtime_mutation',
    refusal_class: 'side_door_without_receipt',
    reason_code: 'receipt_missing',
  },
  {
    case_id: 'direct_api_with_receipt_refused_before_runtime_mutation',
    refusal_class: 'side_door_with_receipt',
    reason_code: 'direct_api_receipt_present',
  },
  {
    case_id: 'agent_supplied_state_path_refused_before_runtime_mutation',
    refusal_class: 'agent_supplied_authority_material',
    reason_code: 'agent_supplied_authority_material',
  },
  {
    case_id: 'agent_supplied_consumed_grants_path_refused_before_runtime_mutation',
    refusal_class: 'agent_supplied_authority_material',
    reason_code: 'agent_supplied_authority_material',
  },
  {
    case_id: 'agent_supplied_consumed_grant_store_anchor_path_refused_before_runtime_mutation',
    refusal_class: 'agent_supplied_authority_material',
    reason_code: 'agent_supplied_authority_material',
  },
  {
    case_id: 'agent_supplied_fixture_mode_refused_before_runtime_mutation',
    refusal_class: 'agent_supplied_authority_material',
    reason_code: 'agent_supplied_authority_material',
  },
  {
    case_id: 'agent_supplied_recognition_rule_refused_before_runtime_mutation',
    refusal_class: 'agent_supplied_authority_material',
    reason_code: 'agent_supplied_authority_material',
  },
  {
    case_id: 'agent_supplied_authority_grant_refused_before_runtime_mutation',
    refusal_class: 'agent_supplied_authority_material',
    reason_code: 'agent_supplied_authority_material',
  },
  {
    case_id: 'unsupported_request_field_refused_before_runtime_mutation',
    refusal_class: 'agent_supplied_authority_material',
    reason_code: 'agent_supplied_authority_material',
  },
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

function caseSummary(report, caseId) {
  const item = report.case_summaries.find((candidate) => candidate.case_id === caseId);
  if (!item) {
    throw new Error(`Records.write terminal proof missing refusal case ${caseId}`);
  }
  return item;
}

function buildDownstreamRefusalContract(localActivation) {
  const cases = REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS.map((expected) => {
    const item = caseSummary(localActivation, expected.case_id);
    return {
      case_id: expected.case_id,
      refusal_class: expected.refusal_class,
      expected_reason_code: expected.reason_code,
      observed_reason_code: item.reason_code,
      refused_before_mutation: item.service_write_accepted === false,
      state_entry_count_delta: item.state_entry_count_delta,
      direct_api_attempted: item.direct_api_attempted,
    };
  });

  return {
    contract_type: RECORDS_WRITE_DOWNSTREAM_REFUSAL_CONTRACT_TYPE,
    downstream_boundary: RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY,
    mutation_authoritative_route: RECORDS_WRITE_TERMINAL_ROUTE,
    evidence_source: PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PROOF_TYPE,
    required_case_count: REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS.length,
    case_count: cases.length,
    all_required_cases_present: cases.length === REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS.length,
    all_expected_reason_codes_match: cases.every((item) => item.expected_reason_code === item.observed_reason_code),
    all_refused_before_mutation: cases.every((item) => item.refused_before_mutation === true),
    all_zero_state_delta: cases.every((item) => item.state_entry_count_delta === 0),
    direct_api_attempts_refused: cases
      .filter((item) => item.direct_api_attempted === true)
      .every((item) => item.refused_before_mutation === true && item.state_entry_count_delta === 0),
    recognized_receipt_and_authority_grant_required_to_mutate: true,
    refusal_cases: cases,
  };
}

export function buildRecordsWriteTerminalProof(plan, profile) {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
    'Records-write terminal proof generation',
  );
  assertProtectedRecordsRuntimeLocalActivationPlan(plan);
  assertProtectedRecordsRuntimePreflightProfile(profile);

  const localActivation = runProtectedRecordsRuntimeLocalActivationProof(plan, profile);
  assertProtectedRecordsRuntimeLocalActivationProof(localActivation, plan, profile);

  const artifact = buildProtectedRecordsRuntimeLocalActivationArtifact(plan, profile, localActivation);
  const verification = verifyProtectedRecordsRuntimeLocalActivationArtifact(artifact);
  const summary = localActivation.runtime_proof_summary;
  const recognizedCase = caseSummary(localActivation, 'recognized_runtime_write_first_request');
  const stateAppendBurnCase = caseSummary(
    localActivation,
    'runtime_state_append_failed_after_consumed_store_commit'
  );

  const proof = {
    proof_type: RECORDS_WRITE_TERMINAL_PROOF_TYPE,
    command: RECORDS_WRITE_TERMINAL_COMMAND,
    action_class: 'records.write',
    evidence_model: localActivation.evidence_model,
    live_probing: localActivation.live_probing,
    terminal: {
      terminal_id: RECORDS_WRITE_TERMINAL_ID,
      action_class: 'records.write',
      checkpoint: RECORDS_WRITE_TERMINAL_CHECKPOINT,
      route: RECORDS_WRITE_TERMINAL_ROUTE,
      downstream_boundary: RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY,
      downstream_effect:
        'bounded service-state mutation after receipt recognition and fixture authority-grant satisfaction',
      airport_sentence: RECORDS_WRITE_TERMINAL_AIRPORT_SENTENCE,
    },
    active_profile_selection: {
      selection_type: RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_TYPE,
      selection_scope: RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_SCOPE,
      selected: true,
      selection_source: 'explicit-plan-and-profile-inputs',
      action_class: 'records.write',
      route: RECORDS_WRITE_TERMINAL_ROUTE,
      downstream_boundary: RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY,
      plan_sha256: verification.plan_sha256,
      profile_id: profile.profile_id,
      runtime_profile_id: profile.runtime_profile_id,
      profile_status_before_selection: profile.profile_status,
      runtime_profile_sha256: verification.runtime_profile_sha256,
      runtime_profile_sha_matches_plan: verification.runtime_profile_sha_matches_plan,
      selects_latest_profile: false,
      persistent_runtime_profile_installed: false,
      live_runtime_profile_checked: false,
      hook_configuration_written: false,
    },
    evidence: {
      local_activation_proof_type: PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PROOF_TYPE,
      artifact_verification_type: PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_VERIFICATION_TYPE,
      artifact_verified: verification.verified,
      artifact_sha256: verification.body_sha256,
      plan_sha256: verification.plan_sha256,
      runtime_profile_sha256: verification.runtime_profile_sha256,
      runtime_profile_sha_matches_plan: verification.runtime_profile_sha_matches_plan,
    },
    outcomes: {
      recognized_write_accepted: summary.recognized_write_accepted,
      same_process_signed_payload_replay_refused_before_mutation:
        summary.same_process_signed_payload_replay_refused,
      restart_consumed_authority_grant_refused_before_mutation:
        summary.restart_consumed_authority_grant_refused,
      missing_authority_grant_appointment_refused_before_mutation:
        summary.missing_authority_grant_appointment_refused,
      mismatched_authority_grant_appointment_refused_before_mutation:
        summary.mismatched_authority_grant_appointment_refused,
      revoked_authority_grant_refused_before_mutation:
        summary.revoked_authority_grant_refused,
      expired_authority_grant_refused_before_mutation:
        summary.expired_authority_grant_refused,
      request_supplied_authority_grant_refused_before_mutation:
        summary.request_supplied_authority_grant_refused,
      missing_receipt_refused_before_mutation: summary.missing_receipt_refused,
      invalid_receipt_refused_before_mutation: summary.invalid_receipt_refused,
      unknown_issuer_refused_before_mutation: summary.unknown_issuer_refused,
      retired_issuer_refused_before_mutation: summary.retired_issuer_refused,
      missing_issuer_status_refused_before_mutation: summary.missing_issuer_status_refused,
      wrong_policy_refused_before_mutation: summary.wrong_policy_refused,
      wrong_domain_refused_before_mutation: summary.wrong_domain_refused,
      wrong_tool_refused_before_mutation: summary.wrong_tool_refused,
      wrong_runtime_profile_id_refused_before_mutation: summary.wrong_runtime_profile_id_refused,
      wrong_audit_event_refused_before_mutation: summary.wrong_audit_event_refused,
      wrong_detail_refused_before_mutation: summary.wrong_detail_refused,
      non_boarding_outcome_refused_before_mutation: summary.non_boarding_outcome_refused,
      stale_receipt_refused_before_mutation: summary.stale_receipt_refused,
      unrecognized_receipt_refused_before_mutation:
        summary.unknown_issuer_refused === true &&
        summary.retired_issuer_refused === true &&
        summary.missing_issuer_status_refused === true,
      direct_api_without_receipt_refused_before_mutation: summary.direct_api_without_receipt_refused,
      direct_api_with_receipt_refused_before_mutation: summary.direct_api_with_receipt_refused,
      agent_supplied_authority_material_refused_before_mutation:
        summary.agent_supplied_authority_material_refused,
    },
    downstream_refusal_contract: buildDownstreamRefusalContract(localActivation),
    authority_boundary: {
      fixture_rightful_issuance_path_evidenced:
        recognizedCase.reason_code === 'fixture_authority_grant_effect_satisfied' &&
        recognizedCase.consumed_authority_grant_count === 1,
      consumed_authority_grant_store: summary.consumed_authority_grant_store,
      consumption_identity: summary.consumption_identity,
      signed_payload_replay_identity: summary.signed_payload_replay_identity,
      request_supplied_authority_grant_refused:
        summary.request_supplied_authority_grant_refused,
      request_stream_authority_material_accepted:
        localActivation.side_door_report.request_stream_authority_material_accepted,
    },
    storage_boundary: {
      consumed_store_witness: summary.consumed_store_witness,
      consumed_store_write_model: summary.consumed_store_write_model,
      state_append_failure_burned_one_use_grant_without_mutation:
        stateAppendBurnCase.reason_code ===
          'runtime_state_append_failed_after_consumed_store_commit' &&
        stateAppendBurnCase.state_entry_count_delta === 0 &&
        stateAppendBurnCase.consumed_authority_grant_count === 1,
      witness_commit_failed_after_authority_grant_store_commit:
        summary.witness_commit_failed_after_authority_grant_store_commit,
      witness_commit_failure_reason_code:
        summary.witness_commit_failure_reason_code,
      partial_grant_commit_burn_window_named:
        localActivation.side_door_report.partial_grant_commit_burn_window_named,
      store_and_anchor_joint_rollback_refused_while_witness_ahead:
        summary.store_and_anchor_joint_rollback_refused_while_witness_ahead,
      store_anchor_and_witness_joint_rollback_detection:
        summary.store_anchor_and_witness_joint_rollback_detection,
      store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse:
        summary.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse,
      atomic_store_anchor_witness_commit:
        localActivation.side_door_report.atomic_store_anchor_witness_commit,
      exactly_once_effect_semantics:
        localActivation.side_door_report.exactly_once_effect_semantics,
      host_filesystem_path_toctou_closed:
        localActivation.side_door_report.host_filesystem_path_toctou_closed,
    },
    mutation_boundary: {
      downstream_recognition_required: localActivation.activation_contract.downstream_recognition_required,
      authority_grant_contract_required_from_launcher:
        localActivation.activation_contract.authority_grant_contract_required_from_launcher,
      authority_grant_appointment_required_from_launcher:
        localActivation.activation_contract.authority_grant_appointment_required_from_launcher,
      authority_grant_issuance_decision_required_from_launcher:
        localActivation.activation_contract.authority_grant_issuance_decision_required_from_launcher,
      authorized_record_update_required_from_launcher:
        localActivation.activation_contract.authorized_record_update_required_from_launcher,
      request_supplied_authority_grant_refused:
        localActivation.activation_contract.request_supplied_authority_grant_refused,
      missing_or_unrecognized_receipt_refused:
        localActivation.activation_contract.missing_or_unrecognized_receipt_refused,
      local_activation_applied: localActivation.side_door_report.local_activation_applied,
      disposable_runtime_config_written: localActivation.side_door_report.disposable_runtime_config_written,
      persistent_runtime_config_written: localActivation.side_door_report.persistent_runtime_config_written,
      hook_configuration_written: localActivation.side_door_report.hook_configuration_written,
      runtime_service_started: localActivation.side_door_report.runtime_service_started,
    },
    claim_boundary: {
      fixture_rightful_issuance_path_evidenced:
        recognizedCase.reason_code === 'fixture_authority_grant_effect_satisfied' &&
        recognizedCase.consumed_authority_grant_count === 1,
      rightful_issuance_proven: false,
      portable_rightful_issuance_proven: false,
      live_authority_proven: false,
      production_rightful_issuance_proven: false,
      current_machine_governance_proven: false,
      consequence_lifecycle_closed: false,
    },
    open_boundaries: [...localActivation.known_open_boundaries],
    non_claims: [...localActivation.non_claims],
  };

  assertRecordsWriteTerminalProof(proof);
  return proof;
}

export function assertRecordsWriteTerminalProof(proof) {
  assertExactKeys('Records.write terminal proof', proof, [
    'action_class',
    'active_profile_selection',
    'authority_boundary',
    'claim_boundary',
    'command',
    'downstream_refusal_contract',
    'evidence',
    'evidence_model',
    'live_probing',
    'mutation_boundary',
    'non_claims',
    'open_boundaries',
    'outcomes',
    'proof_type',
    'storage_boundary',
    'terminal',
  ]);

  if (
    proof.proof_type !== RECORDS_WRITE_TERMINAL_PROOF_TYPE ||
    proof.command !== RECORDS_WRITE_TERMINAL_COMMAND ||
    proof.action_class !== 'records.write' ||
    proof.evidence_model !== 'local-disposable-runtime-activation-fixture' ||
    proof.live_probing !== false
  ) {
    throw new Error('Records.write terminal proof top-level contract drifted');
  }

  assertExactKeys('Records.write terminal proof terminal', proof.terminal, [
    'action_class',
    'airport_sentence',
    'checkpoint',
    'downstream_boundary',
    'downstream_effect',
    'route',
    'terminal_id',
  ]);
  if (
    proof.terminal.terminal_id !== RECORDS_WRITE_TERMINAL_ID ||
    proof.terminal.action_class !== 'records.write' ||
    proof.terminal.checkpoint !== RECORDS_WRITE_TERMINAL_CHECKPOINT ||
    proof.terminal.route !== RECORDS_WRITE_TERMINAL_ROUTE ||
    proof.terminal.downstream_boundary !== RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY ||
    proof.terminal.downstream_effect !==
      'bounded service-state mutation after receipt recognition and fixture authority-grant satisfaction' ||
    proof.terminal.airport_sentence !== RECORDS_WRITE_TERMINAL_AIRPORT_SENTENCE
  ) {
    throw new Error('Records.write terminal proof terminal contract drifted');
  }

  assertExactKeys('Records.write terminal proof active profile selection', proof.active_profile_selection, [
    'action_class',
    'downstream_boundary',
    'hook_configuration_written',
    'live_runtime_profile_checked',
    'persistent_runtime_profile_installed',
    'plan_sha256',
    'profile_id',
    'profile_status_before_selection',
    'route',
    'runtime_profile_id',
    'runtime_profile_sha256',
    'runtime_profile_sha_matches_plan',
    'selected',
    'selection_scope',
    'selection_source',
    'selection_type',
    'selects_latest_profile',
  ]);
  if (
    proof.active_profile_selection.selection_type !== RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_TYPE ||
    proof.active_profile_selection.selection_scope !== RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_SCOPE ||
    proof.active_profile_selection.selected !== true ||
    proof.active_profile_selection.selection_source !== 'explicit-plan-and-profile-inputs' ||
    proof.active_profile_selection.action_class !== 'records.write' ||
    proof.active_profile_selection.route !== RECORDS_WRITE_TERMINAL_ROUTE ||
    proof.active_profile_selection.downstream_boundary !== RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY ||
    !/^[a-f0-9]{64}$/.test(proof.active_profile_selection.plan_sha256 || '') ||
    proof.active_profile_selection.profile_id !== 'protected-records-runtime-fixture-profile' ||
    proof.active_profile_selection.runtime_profile_id !== 'protected-records-disposable-runtime-profile' ||
    proof.active_profile_selection.profile_status_before_selection !== 'sample_not_active' ||
    !/^[a-f0-9]{64}$/.test(proof.active_profile_selection.runtime_profile_sha256 || '') ||
    proof.active_profile_selection.runtime_profile_sha_matches_plan !== true ||
    proof.active_profile_selection.selects_latest_profile !== false ||
    proof.active_profile_selection.persistent_runtime_profile_installed !== false ||
    proof.active_profile_selection.live_runtime_profile_checked !== false ||
    proof.active_profile_selection.hook_configuration_written !== false
  ) {
    throw new Error('Records.write terminal proof active profile selection drifted');
  }

  assertExactKeys('Records.write terminal proof evidence', proof.evidence, [
    'artifact_sha256',
    'artifact_verification_type',
    'artifact_verified',
    'local_activation_proof_type',
    'plan_sha256',
    'runtime_profile_sha256',
    'runtime_profile_sha_matches_plan',
  ]);
  if (
    proof.evidence.local_activation_proof_type !== PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PROOF_TYPE ||
    proof.evidence.artifact_verification_type !== PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_VERIFICATION_TYPE ||
    proof.evidence.artifact_verified !== true ||
    !/^[a-f0-9]{64}$/.test(proof.evidence.artifact_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(proof.evidence.plan_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(proof.evidence.runtime_profile_sha256 || '') ||
    proof.evidence.runtime_profile_sha_matches_plan !== true
  ) {
    throw new Error('Records.write terminal proof evidence contract drifted');
  }

  assertExactKeys('Records.write terminal proof outcomes', proof.outcomes, [
    'agent_supplied_authority_material_refused_before_mutation',
    'direct_api_with_receipt_refused_before_mutation',
    'direct_api_without_receipt_refused_before_mutation',
    'invalid_receipt_refused_before_mutation',
    'expired_authority_grant_refused_before_mutation',
    'missing_receipt_refused_before_mutation',
    'missing_authority_grant_appointment_refused_before_mutation',
    'missing_issuer_status_refused_before_mutation',
    'mismatched_authority_grant_appointment_refused_before_mutation',
    'non_boarding_outcome_refused_before_mutation',
    'recognized_write_accepted',
    'request_supplied_authority_grant_refused_before_mutation',
    'restart_consumed_authority_grant_refused_before_mutation',
    'revoked_authority_grant_refused_before_mutation',
    'same_process_signed_payload_replay_refused_before_mutation',
    'retired_issuer_refused_before_mutation',
    'stale_receipt_refused_before_mutation',
    'unknown_issuer_refused_before_mutation',
    'unrecognized_receipt_refused_before_mutation',
    'wrong_audit_event_refused_before_mutation',
    'wrong_detail_refused_before_mutation',
    'wrong_domain_refused_before_mutation',
    'wrong_policy_refused_before_mutation',
    'wrong_runtime_profile_id_refused_before_mutation',
    'wrong_tool_refused_before_mutation',
  ]);
  for (const [key, value] of Object.entries(proof.outcomes)) {
    if (value !== true) {
      throw new Error(`Records.write terminal proof outcome ${key} drifted`);
    }
  }

  assertExactKeys('Records.write terminal downstream refusal contract', proof.downstream_refusal_contract, [
    'all_expected_reason_codes_match',
    'all_refused_before_mutation',
    'all_required_cases_present',
    'all_zero_state_delta',
    'case_count',
    'contract_type',
    'direct_api_attempts_refused',
    'downstream_boundary',
    'evidence_source',
    'mutation_authoritative_route',
    'recognized_receipt_and_authority_grant_required_to_mutate',
    'refusal_cases',
    'required_case_count',
  ]);
  const contract = proof.downstream_refusal_contract;
  if (
    contract.contract_type !== RECORDS_WRITE_DOWNSTREAM_REFUSAL_CONTRACT_TYPE ||
    contract.downstream_boundary !== RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY ||
    contract.mutation_authoritative_route !== RECORDS_WRITE_TERMINAL_ROUTE ||
    contract.evidence_source !== PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PROOF_TYPE ||
    contract.required_case_count !== REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS.length ||
    contract.case_count !== REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS.length ||
    contract.all_required_cases_present !== true ||
    contract.all_expected_reason_codes_match !== true ||
    contract.all_refused_before_mutation !== true ||
    contract.all_zero_state_delta !== true ||
    contract.direct_api_attempts_refused !== true ||
    contract.recognized_receipt_and_authority_grant_required_to_mutate !== true ||
    !Array.isArray(contract.refusal_cases) ||
    contract.refusal_cases.length !== REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS.length
  ) {
    throw new Error('Records.write terminal downstream refusal contract drifted');
  }
  for (let i = 0; i < REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS.length; i++) {
    const expected = REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS[i];
    const item = contract.refusal_cases[i];
    assertExactKeys('Records.write terminal downstream refusal case', item, [
      'case_id',
      'direct_api_attempted',
      'expected_reason_code',
      'observed_reason_code',
      'refusal_class',
      'refused_before_mutation',
      'state_entry_count_delta',
    ]);
    if (
      item.case_id !== expected.case_id ||
      item.refusal_class !== expected.refusal_class ||
      item.expected_reason_code !== expected.reason_code ||
      item.observed_reason_code !== expected.reason_code ||
      item.refused_before_mutation !== true ||
      item.state_entry_count_delta !== 0 ||
      typeof item.direct_api_attempted !== 'boolean'
    ) {
      throw new Error(`Records.write terminal downstream refusal case ${expected.case_id} drifted`);
    }
  }

  assertExactKeys('Records.write terminal proof authority boundary', proof.authority_boundary, [
    'consumed_authority_grant_store',
    'consumption_identity',
    'fixture_rightful_issuance_path_evidenced',
    'request_stream_authority_material_accepted',
    'request_supplied_authority_grant_refused',
    'signed_payload_replay_identity',
  ]);
  if (
    proof.authority_boundary.fixture_rightful_issuance_path_evidenced !== true ||
    proof.authority_boundary.consumed_authority_grant_store !==
      'persistent-single-use-authority-grant-contract-sha256-store' ||
    proof.authority_boundary.consumption_identity !==
      'authority-grant-contract-sha256' ||
    proof.authority_boundary.signed_payload_replay_identity !==
      'verified-signed-payload-sha256' ||
    proof.authority_boundary.request_supplied_authority_grant_refused !== true ||
    proof.authority_boundary.request_stream_authority_material_accepted !== false
  ) {
    throw new Error('Records.write terminal proof authority boundary drifted');
  }

  assertExactKeys('Records.write terminal proof storage boundary', proof.storage_boundary, [
    'atomic_store_anchor_witness_commit',
    'consumed_store_witness',
    'consumed_store_write_model',
    'exactly_once_effect_semantics',
    'host_filesystem_path_toctou_closed',
    'partial_grant_commit_burn_window_named',
    'state_append_failure_burned_one_use_grant_without_mutation',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse',
    'store_and_anchor_joint_rollback_refused_while_witness_ahead',
    'witness_commit_failed_after_authority_grant_store_commit',
    'witness_commit_failure_reason_code',
  ]);
  if (
    proof.storage_boundary.consumed_store_witness !==
      'launcher-owned-local-store-hash-witness' ||
    proof.storage_boundary.consumed_store_write_model !==
      'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness' ||
    proof.storage_boundary.state_append_failure_burned_one_use_grant_without_mutation !== true ||
    proof.storage_boundary.witness_commit_failed_after_authority_grant_store_commit !== true ||
    proof.storage_boundary.witness_commit_failure_reason_code !==
      'consumed_store_write_failed_after_grant_commit' ||
    proof.storage_boundary.partial_grant_commit_burn_window_named !== true ||
    proof.storage_boundary.store_and_anchor_joint_rollback_refused_while_witness_ahead !== true ||
    proof.storage_boundary.store_anchor_and_witness_joint_rollback_detection !== false ||
    proof.storage_boundary.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse !== true ||
    proof.storage_boundary.atomic_store_anchor_witness_commit !== false ||
    proof.storage_boundary.exactly_once_effect_semantics !== false ||
    proof.storage_boundary.host_filesystem_path_toctou_closed !== false
  ) {
    throw new Error('Records.write terminal proof storage boundary drifted');
  }

  assertExactKeys('Records.write terminal proof mutation boundary', proof.mutation_boundary, [
    'authority_grant_appointment_required_from_launcher',
    'authority_grant_contract_required_from_launcher',
    'authority_grant_issuance_decision_required_from_launcher',
    'authorized_record_update_required_from_launcher',
    'disposable_runtime_config_written',
    'downstream_recognition_required',
    'hook_configuration_written',
    'local_activation_applied',
    'missing_or_unrecognized_receipt_refused',
    'persistent_runtime_config_written',
    'request_supplied_authority_grant_refused',
    'runtime_service_started',
  ]);
  if (
    proof.mutation_boundary.downstream_recognition_required !== true ||
    proof.mutation_boundary.authority_grant_contract_required_from_launcher !== true ||
    proof.mutation_boundary.authority_grant_appointment_required_from_launcher !== true ||
    proof.mutation_boundary.authority_grant_issuance_decision_required_from_launcher !== true ||
    proof.mutation_boundary.authorized_record_update_required_from_launcher !== true ||
    proof.mutation_boundary.request_supplied_authority_grant_refused !== true ||
    proof.mutation_boundary.missing_or_unrecognized_receipt_refused !== true ||
    proof.mutation_boundary.local_activation_applied !== true ||
    proof.mutation_boundary.disposable_runtime_config_written !== true ||
    proof.mutation_boundary.persistent_runtime_config_written !== false ||
    proof.mutation_boundary.hook_configuration_written !== false ||
    proof.mutation_boundary.runtime_service_started !== true
  ) {
    throw new Error('Records.write terminal proof mutation boundary drifted');
  }

  assertExactKeys('Records.write terminal proof claim boundary', proof.claim_boundary, [
    'consequence_lifecycle_closed',
    'current_machine_governance_proven',
    'fixture_rightful_issuance_path_evidenced',
    'live_authority_proven',
    'portable_rightful_issuance_proven',
    'production_rightful_issuance_proven',
    'rightful_issuance_proven',
  ]);
  if (
    proof.claim_boundary.fixture_rightful_issuance_path_evidenced !== true ||
    proof.claim_boundary.rightful_issuance_proven !== false ||
    proof.claim_boundary.portable_rightful_issuance_proven !== false ||
    proof.claim_boundary.live_authority_proven !== false ||
    proof.claim_boundary.production_rightful_issuance_proven !== false ||
    proof.claim_boundary.current_machine_governance_proven !== false ||
    proof.claim_boundary.consequence_lifecycle_closed !== false
  ) {
    throw new Error('Records.write terminal proof claim boundary drifted');
  }

  assertExactArray('Records.write terminal proof non-claims', proof.non_claims, RUNTIME_LOCAL_ACTIVATION_NON_CLAIMS);
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(proof));
  return true;
}

export function formatRecordsWriteTerminalProofSummary(proof) {
  assertRecordsWriteTerminalProof(proof);
  const lines = [
    'ZLAR Records.Write One-Terminal Historical Proof v1',
    'Current authority: fixture_rightful_issuance_path_evidenced=false; legacy proof schema has no artifact-bound grant status',
    `Airport sentence: ${proof.terminal.airport_sentence}`,
    `Evidence model: ${proof.evidence_model}; live probing=${proof.live_probing}`,
    `Terminal: action_class=${proof.action_class}; checkpoint=${proof.terminal.checkpoint}; downstream_boundary=${proof.terminal.downstream_boundary}`,
    `Active profile selection: selected=${proof.active_profile_selection.selected}; scope=${proof.active_profile_selection.selection_scope}; profile=${proof.active_profile_selection.runtime_profile_id}; profile_status_before_selection=${proof.active_profile_selection.profile_status_before_selection}; sha_matches_plan=${proof.active_profile_selection.runtime_profile_sha_matches_plan}; persistent_runtime_profile_installed=${proof.active_profile_selection.persistent_runtime_profile_installed}; live_runtime_profile_checked=${proof.active_profile_selection.live_runtime_profile_checked}; selects_latest_profile=${proof.active_profile_selection.selects_latest_profile}`,
    `Artifact verification: verified=${proof.evidence.artifact_verified}; sha256=${proof.evidence.artifact_sha256}; plan_sha256=${proof.evidence.plan_sha256}; runtime_profile_sha256=${proof.evidence.runtime_profile_sha256}; sha_matches_plan=${proof.evidence.runtime_profile_sha_matches_plan}`,
    `Historical boarding outcome: recognized_write_accepted=${proof.outcomes.recognized_write_accepted}; historical_artifact_fixture_rightful_issuance_path_recorded=${proof.claim_boundary.fixture_rightful_issuance_path_evidenced}; current_fixture_rightful_issuance_path_evidenced=false; missing_receipt_refused_before_mutation=${proof.outcomes.missing_receipt_refused_before_mutation}; unrecognized_receipt_refused_before_mutation=${proof.outcomes.unrecognized_receipt_refused_before_mutation}; same_process_signed_payload_replay_refused=${proof.outcomes.same_process_signed_payload_replay_refused_before_mutation}; restart_consumed_authority_grant_refused=${proof.outcomes.restart_consumed_authority_grant_refused_before_mutation}`,
    `Authority refusals: missing_grant=${proof.outcomes.missing_authority_grant_appointment_refused_before_mutation}; mismatched_grant=${proof.outcomes.mismatched_authority_grant_appointment_refused_before_mutation}; revoked_grant=${proof.outcomes.revoked_authority_grant_refused_before_mutation}; expired_grant=${proof.outcomes.expired_authority_grant_refused_before_mutation}; request_supplied_grant=${proof.outcomes.request_supplied_authority_grant_refused_before_mutation}`,
    `Refusal detail: invalid=${proof.outcomes.invalid_receipt_refused_before_mutation}; unknown_issuer=${proof.outcomes.unknown_issuer_refused_before_mutation}; retired_issuer=${proof.outcomes.retired_issuer_refused_before_mutation}; missing_issuer_status=${proof.outcomes.missing_issuer_status_refused_before_mutation}; stale_or_expired=${proof.outcomes.stale_receipt_refused_before_mutation}; wrong_policy=${proof.outcomes.wrong_policy_refused_before_mutation}; wrong_domain=${proof.outcomes.wrong_domain_refused_before_mutation}; wrong_tool=${proof.outcomes.wrong_tool_refused_before_mutation}; wrong_audit_event=${proof.outcomes.wrong_audit_event_refused_before_mutation}; wrong_detail=${proof.outcomes.wrong_detail_refused_before_mutation}; non_boarding=${proof.outcomes.non_boarding_outcome_refused_before_mutation}; direct_api_with_receipt=${proof.outcomes.direct_api_with_receipt_refused_before_mutation}; authority_material=${proof.outcomes.agent_supplied_authority_material_refused_before_mutation}`,
    `Downstream refusal contract: type=${proof.downstream_refusal_contract.contract_type}; cases=${proof.downstream_refusal_contract.case_count}/${proof.downstream_refusal_contract.required_case_count}; reason_codes_match=${proof.downstream_refusal_contract.all_expected_reason_codes_match}; refused_before_mutation=${proof.downstream_refusal_contract.all_refused_before_mutation}; zero_state_delta=${proof.downstream_refusal_contract.all_zero_state_delta}; direct_api_attempts_refused=${proof.downstream_refusal_contract.direct_api_attempts_refused}`,
    `Authority boundary: store=${proof.authority_boundary.consumed_authority_grant_store}; consumption_identity=${proof.authority_boundary.consumption_identity}; signed_payload_replay_identity=${proof.authority_boundary.signed_payload_replay_identity}; request_stream_authority_material_accepted=${proof.authority_boundary.request_stream_authority_material_accepted}`,
    `Storage boundary: witness=${proof.storage_boundary.consumed_store_witness}; burn_window_named=${proof.storage_boundary.partial_grant_commit_burn_window_named}; state_append_burn=${proof.storage_boundary.state_append_failure_burned_one_use_grant_without_mutation}; witness_commit_burn=${proof.storage_boundary.witness_commit_failed_after_authority_grant_store_commit}; joint_rollback_detection=${proof.storage_boundary.store_anchor_and_witness_joint_rollback_detection}; joint_rollback_reopens_grant_reuse=${proof.storage_boundary.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse}; exactly_once=${proof.storage_boundary.exactly_once_effect_semantics}`,
    `Claim boundary: historical_artifact_fixture_rightful_issuance_recorded=${proof.claim_boundary.fixture_rightful_issuance_path_evidenced}; current_fixture_rightful_issuance=false; generic_rightful_issuance=${proof.claim_boundary.rightful_issuance_proven}; portable_rightful_issuance=${proof.claim_boundary.portable_rightful_issuance_proven}; live_authority=${proof.claim_boundary.live_authority_proven}; production_rightful_issuance=${proof.claim_boundary.production_rightful_issuance_proven}; current_machine_governance=${proof.claim_boundary.current_machine_governance_proven}; consequence_lifecycle_closed=${proof.claim_boundary.consequence_lifecycle_closed}`,
    `Mutation boundary: downstream_recognition_required=${proof.mutation_boundary.downstream_recognition_required}; authority_grant_required=${proof.mutation_boundary.authority_grant_contract_required_from_launcher}; request_supplied_authority_grant_refused=${proof.mutation_boundary.request_supplied_authority_grant_refused}; missing_or_unrecognized_receipt_refused=${proof.mutation_boundary.missing_or_unrecognized_receipt_refused}; local_activation_applied=${proof.mutation_boundary.local_activation_applied}; disposable_runtime_config_written=${proof.mutation_boundary.disposable_runtime_config_written}; persistent_runtime_config_written=${proof.mutation_boundary.persistent_runtime_config_written}; hook_configuration_written=${proof.mutation_boundary.hook_configuration_written}; runtime_service_started=${proof.mutation_boundary.runtime_service_started}`,
    `Open boundaries: ${proof.open_boundaries.join(',')}`,
    'Non-claims:',
  ];
  for (const claim of proof.non_claims) {
    lines.push(`- ${claim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(summary);
  return summary;
}
