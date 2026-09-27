import {
  lstatSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { canonicalize } from './canonicalize.mjs';
import { sha256hex } from './receipt.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH,
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from './protected-records-runtime-profile.mjs';
import {
  ACTIVE_PERSISTENT_PROFILE_MANIFEST_FILE,
  ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
} from './protected-records-active-persistent-profile-preflight.mjs';
import {
  assertActivePersistentProfileLiveReportOutputPath,
  assertActivePersistentProfileLiveManifest,
  defaultActivePersistentProfileLiveRoot,
  inspectActivePersistentProfileLiveStatus,
} from './protected-records-active-persistent-profile-live-installation.mjs';
import {
  buildProtectedRecordsInstalledRuntimeProfilePreflightArtifact,
  runProtectedRecordsInstalledRuntimeProfilePreflight,
  verifyProtectedRecordsInstalledRuntimeProfilePreflightArtifact,
} from './protected-records-installed-runtime-profile-preflight.mjs';
import {
  buildProtectedRecordsInstalledRuntimeProfileServiceProofArtifact,
  runProtectedRecordsInstalledRuntimeProfileServiceProof,
  verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact,
} from './protected-records-installed-runtime-profile-service-proof.mjs';
import {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed,
} from './protected-records-fixture-authority-status.mjs';

export const PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_TYPE =
  'zlar-protected-records-active-persistent-profile-governed-action-crossing-v1';

export const ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_SAFE_CLAIM =
  'ZLAR proved one bounded records.write action crossed one already-active explicit persistent profile root before local disposable service mutation: the active root was read at action time, the installed profile was selected by explicit id and SHA, one recognized fixture-authorized effect boarded, recognition and authority-grant refusals stayed before mutation, and same-process signed-payload replay remained distinct from restart consumed-grant refusal.';

export const ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_NON_CLAIMS = Object.freeze([
  'This proof covers one proof-owned records.write crossing through one already-active named persistent profile only.',
  'This proof reads the named active root and uses local disposable service proof machinery; it does not touch real personal, business, customer, or production records.',
  'This proof does not renew, extend, replace, or silently reinstall the active profile.',
  'This proof uses launcher-owned local fixture authority only; it does not prove portable, production, or live rightful issuance.',
  'This proof names but does not close the non-atomic grant-store/anchor/witness burn window, joint store-anchor-witness rollback reuse, exactly-once, or host-filesystem path TOCTOU side doors.',
  'This proof does not write hooks, Codex config, shell config, app config, user config, machine config, LaunchAgents, daemons, or operating-system persistence.',
  'This proof does not use credentials, secrets, HMAC, tokens, private keys, YubiKey, GitHub settings, Actions, tags, releases, website publication, Telegram, external services, production issuer custody, or production key custody.',
  'This proof does not prove raw Codex/developer-tool governance, current-machine governance generally, browser/Computer Use/MCP/shell/network/all-surface governance, side-door closure, production downstream recognition, production authority, enterprise readiness, public external attestation, sovereign recognition, or absolute human intention.',
]);

export const ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_OPEN_BOUNDARIES = Object.freeze([
  'real_personal_records_not_touched',
  'live_records_system_not_touched',
  'runtime_service_is_local_disposable_child_process_only',
  'hooks_user_machine_configuration_not_written',
  'raw_codex_developer_tool_governance_not_proven',
  'current_machine_governance_general_not_proven',
  'browser_computer_use_mcp_shell_network_all_surface_governance_not_proven',
  'production_downstream_recognition_not_proven',
  'production_authority_not_proven',
  'portable_or_production_rightful_issuance_not_proven',
  'consequence_lifecycle_not_closed',
  'exactly_once_effect_semantics_not_proven',
  'store_anchor_witness_commit_atomicity_not_proven',
  'store_anchor_and_witness_joint_rollback_detection_not_proven',
  'host_filesystem_path_toctou_not_closed',
  'side_door_closure_not_proven',
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

function assertProfileId(value) {
  if (typeof value !== 'string' || !/^[a-z0-9][a-z0-9._-]{2,127}$/.test(value)) {
    throw new Error('active persistent action crossing profile id is malformed');
  }
  return value;
}

function assertSha256(label, value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`${label} SHA-256 is malformed`);
  }
  return value;
}

function assertActiveRootUsable(status) {
  if (
    status.status_type !== 'zlar-protected-records-active-persistent-profile-live-status-v1' ||
    status.read_only !== true ||
    typeof status.named_live_root !== 'boolean' ||
    ![
      '<named-active-persistent-profile-root>',
      '<surrogate-active-persistent-profile-root>',
    ].includes(status.activation_root_label) ||
    status.activation_root_state !== 'active_until_expiry' ||
    status.manifest_present !== true ||
    status.manifest_status !== 'active_persistent_profile_installed' ||
    status.active !== true ||
    status.expired !== false ||
    status.active_index_present !== true ||
    status.installed_profile_present !== true ||
    status.safe_for_install !== false
  ) {
    throw new Error('active persistent action crossing requires an active unexpired explicit root');
  }
  return true;
}

function assertActiveManifestContract(activationRoot) {
  const manifestPath = join(activationRoot, ACTIVE_PERSISTENT_PROFILE_MANIFEST_FILE);
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch {
    throw new Error('active persistent action crossing live manifest could not be read');
  }
  assertActivePersistentProfileLiveManifest(manifest);
  if (
    manifest.status !== 'active_persistent_profile_installed' ||
    manifest.active !== true ||
    manifest.activation_allowed !== true
  ) {
    throw new Error('active persistent action crossing requires an installed active manifest');
  }
  return true;
}

function summarizeActiveStatus(status) {
  return {
    status_type: status.status_type,
    activation_root_label: status.activation_root_label,
    named_live_root: status.named_live_root,
    activation_root_state: status.activation_root_state,
    manifest_present: status.manifest_present,
    manifest_status: status.manifest_status,
    active: status.active,
    expired: status.expired,
    active_index_present: status.active_index_present,
    installed_profile_present: status.installed_profile_present,
    safe_for_install: status.safe_for_install,
    explicit_closeout_or_replace_required: status.explicit_closeout_or_replace_required,
    expires_at: status.expires_at,
  };
}

function summarizePreflightVerification(verification) {
  return {
    verification_type: verification.verification_type,
    verified: verification.verified,
    artifact_type: verification.artifact_type,
    body_sha256: verification.body_sha256,
    payload_type: verification.payload_type,
    read_only: verification.read_only,
    requested_profile_id: verification.requested_profile_id,
    requested_profile_sha256: verification.requested_profile_sha256,
    active_index_read: verification.active_index_read,
    installed_profile_read: verification.installed_profile_read,
    profile_selected_from_install_root: verification.profile_selected_from_install_root,
    selected_by_explicit_id_and_sha: verification.selected_by_explicit_id_and_sha,
    selects_latest_profile: verification.selects_latest_profile,
    recognition_contract_preserved: verification.recognition_contract_preserved,
    recognition_contract_sha256: verification.recognition_contract_sha256,
    request_stream_authority_material_accepted:
      verification.request_stream_authority_material_accepted,
    recognition_rule_supplied_by_agent: verification.recognition_rule_supplied_by_agent,
    downstream_refusal_proven: verification.downstream_refusal_proven,
    current_machine_governance_proven: verification.current_machine_governance_proven,
    mutation_authoritative_route: verification.mutation_authoritative_route,
    authority_grant_requirement_preserved:
      verification.authority_grant_requirement_preserved,
    exact_runtime_authority_grant_contract_deferred:
      verification.exact_runtime_authority_grant_contract_deferred,
    rightful_issuance_proven: verification.rightful_issuance_proven,
    consequence_lifecycle_closed: verification.consequence_lifecycle_closed,
  };
}

function summarizeServiceVerification(verification, proof) {
  return {
    verification_type: verification.verification_type,
    verified: verification.verified,
    artifact_identity_expected_sha256_supplied:
      verification.artifact_identity_expected_sha256_supplied,
    expected_artifact_body_sha256:
      verification.expected_artifact_body_sha256,
    artifact_identity_sha256_matched:
      verification.artifact_identity_sha256_matched,
    source_preflight_identity_bound_to_expected_artifact_sha256:
      verification.source_preflight_identity_bound_to_expected_artifact_sha256,
    signed_receipt_envelope_identity_bound_to_expected_artifact_sha256:
      verification.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256,
    verification_scope: verification.verification_scope,
    artifact_type: verification.artifact_type,
    body_sha256: verification.body_sha256,
    payload_type: verification.payload_type,
    evidence_model: verification.evidence_model,
    live_probing: verification.live_probing,
    source_preflight_body_sha256: verification.source_preflight_body_sha256,
    selected_profile_sha256: verification.selected_profile_sha256,
    selected_by_explicit_id_and_sha:
      proof.selected_profile.selected_by_explicit_id_and_sha,
    selects_latest_profile: proof.selected_profile.selects_latest_profile,
    recognition_contract_sha256: verification.recognition_contract_sha256,
    recognition_rule_bound_to_selected_profile:
      proof.service_config_provenance.recognition_rule_bound_to_selected_profile,
    recognition_rule_supplied_by_agent:
      proof.service_config_provenance.recognition_rule_supplied_by_agent,
    authority_grant_source: proof.service_config_provenance.authority_grant_source,
    authority_grant_supplied_by_agent:
      proof.service_config_provenance.authority_grant_supplied_by_agent,
    consumed_grant_store_witness_source:
      proof.service_config_provenance.consumed_grant_store_witness_source,
    runtime_service_started: proof.service_boundary.runtime_service_started,
    persistent_runtime_config_written:
      proof.service_boundary.persistent_runtime_config_written,
    mutation_authoritative_route: proof.service_boundary.mutation_authoritative_route,
    consumed_authority_grant_store:
      proof.service_boundary.consumed_authority_grant_store,
    consumption_identity: proof.service_boundary.consumption_identity,
    signed_payload_replay_identity:
      proof.service_boundary.signed_payload_replay_identity,
    consumed_store_write_model:
      proof.service_boundary.consumed_store_write_model,
    recognized_write_boarded: verification.recognized_write_boarded,
    recognized_write_state_append_count:
      verification.recognized_write_state_append_count,
    recognition_refusal_case_count: verification.recognition_refusal_case_count,
    authority_refusal_case_count: verification.authority_refusal_case_count,
    recognition_refusal_taxonomy_sha256:
      verification.recognition_refusal_taxonomy_sha256,
    authority_refusal_taxonomy_sha256:
      verification.authority_refusal_taxonomy_sha256,
    all_recognition_refusals_before_mutation:
      verification.all_recognition_refusals_before_mutation,
    all_authority_refusals_before_consumption_and_mutation:
      verification.all_authority_refusals_before_consumption_and_mutation,
    same_process_signed_payload_replay_refused:
      verification.same_process_signed_payload_replay_refused,
    restart_consumed_authority_grant_refused:
      verification.restart_consumed_authority_grant_refused,
    state_append_after_grant_commit_burn_observed:
      verification.state_append_after_grant_commit_burn_observed,
    metadata_partial_commit_burn_observed:
      verification.metadata_partial_commit_burn_observed,
    store_and_anchor_rollback_refused_while_witness_ahead:
      verification.store_and_anchor_rollback_refused_while_witness_ahead,
    store_anchor_and_witness_joint_rollback_detection:
      verification.store_anchor_and_witness_joint_rollback_detection,
    joint_rollback_reopened_authority_grant_reuse:
      verification.joint_rollback_reopened_authority_grant_reuse,
    fixture_rightful_issuance_path_evidenced:
      verification.fixture_rightful_issuance_path_evidenced,
    rightful_issuance_proven: verification.rightful_issuance_proven,
    portable_rightful_issuance_proven:
      verification.portable_rightful_issuance_proven,
    production_rightful_issuance_proven:
      verification.production_rightful_issuance_proven,
    consequence_lifecycle_closed: verification.consequence_lifecycle_closed,
    install_performed: verification.install_performed,
    activation_performed: verification.activation_performed,
    hook_configuration_written: proof.proof_boundary.hook_configuration_written,
    user_config_written: proof.proof_boundary.user_configuration_written,
    machine_config_written: proof.proof_boundary.machine_configuration_written,
    current_machine_governance_proven: verification.current_machine_governance_proven,
    production_downstream_recognition: verification.production_downstream_recognition,
    external_attestation: verification.external_attestation,
    sovereign_recognition: verification.sovereign_recognition,
  };
}

function writeProofTargetMarker({
  proofTarget,
  activationRoot,
  nowEpoch,
  preflightArtifactSha256,
  serviceArtifactSha256,
  recognitionContractSha256,
  recognitionRefusalTaxonomySha256,
  authorityRefusalTaxonomySha256,
  authorityGrantContractSha256,
}) {
  assertProofTargetWritable({ proofTarget, activationRoot });
  const entry = {
    marker_type: 'zlar-active-persistent-profile-action-crossing-target-marker-v1',
    action_class: 'records.write',
    write_policy: 'write-after-recognized-fixture-authority-effect-only',
    now_epoch: nowEpoch,
    preflight_artifact_body_sha256: preflightArtifactSha256,
    service_artifact_body_sha256: serviceArtifactSha256,
    recognition_contract_sha256: recognitionContractSha256,
    recognition_refusal_taxonomy_sha256: recognitionRefusalTaxonomySha256,
    authority_refusal_taxonomy_sha256: authorityRefusalTaxonomySha256,
    authority_grant_contract_sha256: authorityGrantContractSha256,
  };
  const output = `${JSON.stringify(entry)}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  mkdirSync(dirname(proofTarget), { recursive: true });
  writeFileSync(proofTarget, output, { mode: 0o600 });
  return {
    target_label: '<proof-owned-action-crossing-target>',
    existed_before: false,
    entry_count_before: 0,
    entry_count_after: 1,
    recognized_entry_delta: 1,
    refusal_entry_delta_total: 0,
    write_policy: 'write-after-recognized-fixture-authority-effect-only',
    recognition_refusal_taxonomy_sha256: recognitionRefusalTaxonomySha256,
    authority_refusal_taxonomy_sha256: authorityRefusalTaxonomySha256,
    authority_grant_contract_sha256: authorityGrantContractSha256,
    marker_sha256: sha256hex(output),
  };
}

function assertProofTargetWritable({ proofTarget, activationRoot }) {
  if (!proofTarget || typeof proofTarget !== 'string') {
    throw new Error('active persistent action crossing proof target is required');
  }
  try {
    lstatSync(proofTarget);
    throw new Error('active persistent action crossing proof target must be absent before proof');
  } catch (err) {
    if (!err || err.code !== 'ENOENT') {
      if (err?.message === 'active persistent action crossing proof target must be absent before proof') {
        throw err;
      }
      throw new Error('active persistent action crossing proof target identity could not be inspected');
    }
  }
  assertActivePersistentProfileLiveReportOutputPath({
    outputPath: proofTarget,
    activationRoot,
  });
  return true;
}

export function runProtectedRecordsActivePersistentProfileActionCrossing({
  activationRoot,
  expectedProfile,
  profileId,
  profileSha256,
  proofTarget,
  allowNamedLiveRoot = false,
  nowEpoch = Math.floor(Date.now() / 1000),
  expectedLiveRoot = defaultActivePersistentProfileLiveRoot(),
} = {}) {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
    'Protected records active persistent profile action crossing'
  );
  if (!activationRoot || typeof activationRoot !== 'string') {
    throw new Error('active persistent action crossing activation root is required');
  }
  assertProfileId(profileId);
  assertSha256('active persistent action crossing profile', profileSha256);
  if (profileSha256 !== ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256) {
    throw new Error('active persistent action crossing requires the pinned runtime profile SHA-256');
  }

  const activeStatus = inspectActivePersistentProfileLiveStatus({
    activationRoot,
    nowEpoch,
    allowNamedLiveRoot,
    expectedLiveRoot,
  });
  assertActiveRootUsable(activeStatus);
  assertActiveManifestContract(activationRoot);
  assertProofTargetWritable({ proofTarget, activationRoot });

  const preflight = runProtectedRecordsInstalledRuntimeProfilePreflight({
    installRoot: activationRoot,
    expectedProfile,
    profileId,
    profileSha256,
  });
  const preflightArtifact = buildProtectedRecordsInstalledRuntimeProfilePreflightArtifact(preflight);
  const preflightVerification =
    verifyProtectedRecordsInstalledRuntimeProfilePreflightArtifact(preflightArtifact);
  const serviceProof = runProtectedRecordsInstalledRuntimeProfileServiceProof(
    preflightArtifact,
    { nowEpoch: PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH }
  );
  const serviceArtifact = buildProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(
    serviceProof
  );
  const serviceVerification =
    verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(serviceArtifact, {
      expectedArtifactBodySha256: serviceArtifact.integrity.body_sha256,
    });
  const proofTargetMarker = writeProofTargetMarker({
    proofTarget,
    activationRoot,
    nowEpoch,
    preflightArtifactSha256: preflightArtifact.integrity.body_sha256,
    serviceArtifactSha256: serviceArtifact.integrity.body_sha256,
    recognitionContractSha256: serviceVerification.recognition_contract_sha256,
    recognitionRefusalTaxonomySha256:
      serviceVerification.recognition_refusal_taxonomy_sha256,
    authorityRefusalTaxonomySha256:
      serviceVerification.authority_refusal_taxonomy_sha256,
    authorityGrantContractSha256:
      serviceVerification.authority_grant_contract_sha256,
  });

  const report = {
    proof_type: PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_TYPE,
    evidence_model: 'active-root-read-before-local-disposable-records-write-crossing',
    safe_claim_ceiling: ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_SAFE_CLAIM,
    action_class: 'records.write',
    now_epoch: nowEpoch,
    evaluation_time_contract: {
      active_root_status_epoch: nowEpoch,
      active_root_status_uses_action_time_epoch: true,
      local_service_authority_evaluation_epoch:
        PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH,
      local_service_authority_uses_fixture_epoch: true,
      time_domains_intentionally_separate: true,
      fixture_epoch_is_not_live_authority_time: true,
    },
    active_profile: {
      status_read_at_action_time: true,
      active_root_selected_by_operator: true,
      renewal_or_extension_performed: false,
      ...summarizeActiveStatus(activeStatus),
    },
    action_crossing: {
      action_attempted: true,
      action_class: 'records.write',
      active_profile_read_before_action: true,
      installed_profile_read_before_action: true,
      selected_profile_source: 'active-persistent-profile-root-read-at-action-time',
      requested_profile_id: profileId,
      requested_profile_sha256: profileSha256,
      runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      selected_by_explicit_id_and_sha: preflight.active_index.selected_by_explicit_id_and_sha,
      selects_latest_profile: preflight.active_index.selects_latest_profile,
      recognized_receipt_boards_before_mutation:
        serviceVerification.recognized_write_boarded === true &&
        serviceVerification.recognized_write_state_append_count === 1,
      fixture_authority_grant_path_evidenced_before_mutation:
        serviceVerification.fixture_rightful_issuance_path_evidenced,
      recognition_refusals_before_mutation:
        serviceVerification.all_recognition_refusals_before_mutation,
      authority_grant_refusals_before_consumption_and_mutation:
        serviceVerification.all_authority_refusals_before_consumption_and_mutation,
      same_process_signed_payload_replay_refused_before_mutation:
        serviceVerification.same_process_signed_payload_replay_refused,
      restart_consumed_authority_grant_refused_before_mutation:
        serviceVerification.restart_consumed_authority_grant_refused,
      authority_grant_supplied_by_agent:
        serviceProof.service_config_provenance.authority_grant_supplied_by_agent,
      recognition_rule_supplied_by_agent:
        serviceProof.service_config_provenance.recognition_rule_supplied_by_agent,
    },
    proof_target: proofTargetMarker,
    generated_preflight: summarizePreflightVerification(preflightVerification),
    service_crossing: summarizeServiceVerification(serviceVerification, serviceProof),
    hashes: {
      preflight_report_sha256: sha256hex(canonicalize(preflight)),
      preflight_artifact_body_sha256: preflightArtifact.integrity.body_sha256,
      service_proof_sha256: sha256hex(canonicalize(serviceProof)),
      service_artifact_body_sha256: serviceArtifact.integrity.body_sha256,
      recognition_contract_sha256: serviceVerification.recognition_contract_sha256,
      recognition_refusal_taxonomy_sha256:
        serviceVerification.recognition_refusal_taxonomy_sha256,
      authority_refusal_taxonomy_sha256:
        serviceVerification.authority_refusal_taxonomy_sha256,
      authority_grant_contract_sha256:
        serviceVerification.authority_grant_contract_sha256,
    },
    claim_boundary: {
      active_persistent_profile_action_crossing: true,
      active_root_read_at_action_time: true,
      recognized_records_write_boarded:
        serviceVerification.artifact_identity_sha256_matched === true &&
        serviceVerification.source_preflight_identity_bound_to_expected_artifact_sha256 === true &&
        serviceVerification.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256 === true &&
        serviceVerification.recognized_write_boarded === true,
      fixture_authority_grant_path_evidenced:
        serviceVerification.artifact_identity_sha256_matched === true &&
        serviceVerification.source_preflight_identity_bound_to_expected_artifact_sha256 === true &&
        serviceVerification.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256 === true &&
        serviceVerification.fixture_rightful_issuance_path_evidenced === true,
      recognition_refusals_before_mutation: true,
      authority_grant_refusals_before_consumption_and_mutation: true,
      same_process_signed_payload_replay_refused: true,
      restart_consumed_authority_grant_refused: true,
      rightful_issuance_proven: false,
      consequence_lifecycle_closed: false,
      real_personal_records_protection: false,
      raw_codex_or_developer_tool_governance: false,
      current_machine_governance_general: false,
      browser_computer_use_mcp_shell_network_or_all_surface_governance: false,
      production_downstream_recognition: false,
      production_authority: false,
      enterprise_readiness: false,
      public_external_attestation: false,
      sovereign_recognition: false,
      side_door_closure: false,
      absolute_human_intention: false,
    },
    known_open_boundaries: [...ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_OPEN_BOUNDARIES],
    non_claims: [...ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_NON_CLAIMS],
  };
  assertProtectedRecordsActivePersistentProfileActionCrossing(report);
  return report;
}

export function assertProtectedRecordsActivePersistentProfileActionCrossing(report) {
  assertExactKeys('active persistent action crossing report', report, [
    'action_class',
    'action_crossing',
    'active_profile',
    'claim_boundary',
    'evidence_model',
    'evaluation_time_contract',
    'generated_preflight',
    'hashes',
    'known_open_boundaries',
    'non_claims',
    'now_epoch',
    'proof_type',
    'proof_target',
    'safe_claim_ceiling',
    'service_crossing',
  ]);
  if (
    report.proof_type !== PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_TYPE ||
    report.evidence_model !== 'active-root-read-before-local-disposable-records-write-crossing' ||
    report.safe_claim_ceiling !== ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_SAFE_CLAIM ||
    report.action_class !== 'records.write'
  ) {
    throw new Error('active persistent action crossing top-level drifted');
  }

  const evaluationTime = report.evaluation_time_contract;
  assertExactKeys('active persistent action crossing evaluation time contract', evaluationTime, [
    'active_root_status_epoch',
    'active_root_status_uses_action_time_epoch',
    'fixture_epoch_is_not_live_authority_time',
    'local_service_authority_evaluation_epoch',
    'local_service_authority_uses_fixture_epoch',
    'time_domains_intentionally_separate',
  ]);
  if (
    !Number.isInteger(evaluationTime.active_root_status_epoch) ||
    evaluationTime.active_root_status_epoch !== report.now_epoch ||
    evaluationTime.active_root_status_uses_action_time_epoch !== true ||
    evaluationTime.local_service_authority_evaluation_epoch !==
      PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH ||
    evaluationTime.local_service_authority_uses_fixture_epoch !== true ||
    evaluationTime.time_domains_intentionally_separate !== true ||
    evaluationTime.fixture_epoch_is_not_live_authority_time !== true
  ) {
    throw new Error('active persistent action crossing evaluation time boundary drifted');
  }

  const active = report.active_profile;
  if (
    active.status_read_at_action_time !== true ||
    active.active_root_selected_by_operator !== true ||
    active.renewal_or_extension_performed !== false ||
    ![
      '<named-active-persistent-profile-root>',
      '<surrogate-active-persistent-profile-root>',
    ].includes(active.activation_root_label) ||
    typeof active.named_live_root !== 'boolean' ||
    active.activation_root_state !== 'active_until_expiry' ||
    active.manifest_present !== true ||
    active.manifest_status !== 'active_persistent_profile_installed' ||
    active.active !== true ||
    active.expired !== false ||
    active.active_index_present !== true ||
    active.installed_profile_present !== true
  ) {
    throw new Error('active persistent action crossing active profile drifted');
  }

  const crossing = report.action_crossing;
  if (
    crossing.action_attempted !== true ||
    crossing.action_class !== 'records.write' ||
    crossing.active_profile_read_before_action !== true ||
    crossing.installed_profile_read_before_action !== true ||
    crossing.selected_profile_source !== 'active-persistent-profile-root-read-at-action-time' ||
    crossing.requested_profile_id !== 'protected-records-runtime-fixture-profile' ||
    crossing.requested_profile_sha256 !== ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256 ||
    crossing.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    crossing.selected_by_explicit_id_and_sha !== true ||
    crossing.selects_latest_profile !== false ||
    crossing.recognized_receipt_boards_before_mutation !== true ||
    crossing.fixture_authority_grant_path_evidenced_before_mutation !== true ||
    crossing.recognition_refusals_before_mutation !== true ||
    crossing.authority_grant_refusals_before_consumption_and_mutation !== true ||
    crossing.same_process_signed_payload_replay_refused_before_mutation !== true ||
    crossing.restart_consumed_authority_grant_refused_before_mutation !== true ||
    crossing.authority_grant_supplied_by_agent !== false ||
    crossing.recognition_rule_supplied_by_agent !== false
  ) {
    throw new Error(
      'active persistent action crossing action boundary drifted ' +
      `(selected_by_id_sha=${crossing.selected_by_explicit_id_and_sha}; ` +
      `selects_latest=${crossing.selects_latest_profile}; ` +
      `recognized_boards=${crossing.recognized_receipt_boards_before_mutation}; ` +
      `recognition_refusals=${crossing.recognition_refusals_before_mutation}; ` +
      `authority_refusals=${crossing.authority_grant_refusals_before_consumption_and_mutation}; ` +
      `same_process_signed_payload_replay=${crossing.same_process_signed_payload_replay_refused_before_mutation}; ` +
      `restart_consumed_grant=${crossing.restart_consumed_authority_grant_refused_before_mutation}; ` +
      `authority_grant_supplied_by_agent=${crossing.authority_grant_supplied_by_agent}; ` +
      `recognition_rule_supplied=${crossing.recognition_rule_supplied_by_agent})`
    );
  }

  if (
    report.proof_target.target_label !== '<proof-owned-action-crossing-target>' ||
    report.proof_target.existed_before !== false ||
    report.proof_target.entry_count_before !== 0 ||
    report.proof_target.entry_count_after !== 1 ||
    report.proof_target.recognized_entry_delta !== 1 ||
    report.proof_target.refusal_entry_delta_total !== 0 ||
    report.proof_target.write_policy !== 'write-after-recognized-fixture-authority-effect-only' ||
    !/^[a-f0-9]{64}$/.test(report.proof_target.marker_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(report.proof_target.recognition_refusal_taxonomy_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(report.proof_target.authority_refusal_taxonomy_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(report.proof_target.authority_grant_contract_sha256 || '')
  ) {
    throw new Error('active persistent action crossing proof target drifted');
  }

  if (
    report.generated_preflight.verified !== true ||
    report.generated_preflight.read_only !== true ||
    report.generated_preflight.requested_profile_id !== crossing.requested_profile_id ||
    report.generated_preflight.requested_profile_sha256 !== crossing.requested_profile_sha256 ||
    report.generated_preflight.profile_selected_from_install_root !== true ||
    report.generated_preflight.selected_by_explicit_id_and_sha !== true ||
    report.generated_preflight.selects_latest_profile !== false ||
    report.generated_preflight.authority_grant_requirement_preserved !== true ||
    report.generated_preflight.exact_runtime_authority_grant_contract_deferred !== true ||
    report.generated_preflight.rightful_issuance_proven !== false ||
    report.generated_preflight.consequence_lifecycle_closed !== false ||
    report.generated_preflight.downstream_refusal_proven !== false ||
    report.generated_preflight.current_machine_governance_proven !== false
  ) {
    throw new Error('active persistent action crossing preflight drifted');
  }

  if (
    report.service_crossing.verified !== true ||
    report.service_crossing.artifact_identity_expected_sha256_supplied !== true ||
    report.service_crossing.expected_artifact_body_sha256 !==
      report.hashes.service_artifact_body_sha256 ||
    report.service_crossing.body_sha256 !==
      report.hashes.service_artifact_body_sha256 ||
    report.service_crossing.artifact_identity_sha256_matched !== true ||
    report.service_crossing.source_preflight_identity_bound_to_expected_artifact_sha256 !== true ||
    report.service_crossing.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256 !== true ||
    report.service_crossing.verification_scope !==
      'expected-artifact-identity-bound-local-fixture-projection' ||
    report.service_crossing.live_probing !== false ||
    report.service_crossing.source_preflight_body_sha256 !==
      report.generated_preflight.body_sha256 ||
    report.service_crossing.selected_profile_sha256 !== crossing.requested_profile_sha256 ||
    report.service_crossing.selected_by_explicit_id_and_sha !== true ||
    report.service_crossing.selects_latest_profile !== false ||
    report.service_crossing.recognition_rule_bound_to_selected_profile !== true ||
    report.service_crossing.recognition_rule_supplied_by_agent !== false ||
    report.service_crossing.authority_grant_source !== 'launcher-owned-local-fixture-overlay' ||
    report.service_crossing.authority_grant_supplied_by_agent !== false ||
    report.service_crossing.consumed_grant_store_witness_source !==
      'launcher-owned-local-proof-witness' ||
    report.service_crossing.runtime_service_started !== true ||
    report.service_crossing.persistent_runtime_config_written !== false ||
    report.service_crossing.mutation_authoritative_route !==
      'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation' ||
    report.service_crossing.consumed_authority_grant_store !==
      'persistent-single-use-authority-grant-contract-sha256-store' ||
    report.service_crossing.consumption_identity !== 'authority-grant-contract-sha256' ||
    report.service_crossing.signed_payload_replay_identity !==
      'verified-signed-payload-sha256' ||
    report.service_crossing.consumed_store_write_model !==
      'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness' ||
    report.service_crossing.recognized_write_boarded !== true ||
    report.service_crossing.recognized_write_state_append_count !== 1 ||
    report.service_crossing.recognition_refusal_case_count !== 18 ||
    report.service_crossing.authority_refusal_case_count !== 5 ||
    report.service_crossing.all_recognition_refusals_before_mutation !== true ||
    report.service_crossing.all_authority_refusals_before_consumption_and_mutation !== true ||
    report.service_crossing.same_process_signed_payload_replay_refused !== true ||
    report.service_crossing.restart_consumed_authority_grant_refused !== true ||
    report.service_crossing.state_append_after_grant_commit_burn_observed !== true ||
    report.service_crossing.metadata_partial_commit_burn_observed !== true ||
    report.service_crossing.store_and_anchor_rollback_refused_while_witness_ahead !== true ||
    report.service_crossing.store_anchor_and_witness_joint_rollback_detection !== false ||
    report.service_crossing.joint_rollback_reopened_authority_grant_reuse !== true ||
    report.service_crossing.fixture_rightful_issuance_path_evidenced !== true ||
    report.service_crossing.rightful_issuance_proven !== false ||
    report.service_crossing.portable_rightful_issuance_proven !== false ||
    report.service_crossing.production_rightful_issuance_proven !== false ||
    report.service_crossing.consequence_lifecycle_closed !== false ||
    report.service_crossing.install_performed !== false ||
    report.service_crossing.activation_performed !== false ||
    report.service_crossing.hook_configuration_written !== false ||
    report.service_crossing.user_config_written !== false ||
    report.service_crossing.machine_config_written !== false ||
    report.service_crossing.current_machine_governance_proven !== false ||
    report.service_crossing.production_downstream_recognition !== false
  ) {
    throw new Error('active persistent action crossing service proof drifted');
  }

  for (const [key, value] of Object.entries(report.hashes)) {
    assertSha256(`active persistent action crossing ${key}`, value);
  }

  const boundary = report.claim_boundary;
  if (
    boundary.active_persistent_profile_action_crossing !== true ||
    boundary.active_root_read_at_action_time !== true ||
    boundary.recognized_records_write_boarded !== true ||
    boundary.fixture_authority_grant_path_evidenced !== true ||
    boundary.recognition_refusals_before_mutation !== true ||
    boundary.authority_grant_refusals_before_consumption_and_mutation !== true ||
    boundary.same_process_signed_payload_replay_refused !== true ||
    boundary.restart_consumed_authority_grant_refused !== true
  ) {
    throw new Error('active persistent action crossing positive claim boundary drifted');
  }
  for (const key of [
    'real_personal_records_protection',
    'raw_codex_or_developer_tool_governance',
    'current_machine_governance_general',
    'browser_computer_use_mcp_shell_network_or_all_surface_governance',
    'production_downstream_recognition',
    'production_authority',
    'enterprise_readiness',
    'public_external_attestation',
    'sovereign_recognition',
    'side_door_closure',
    'rightful_issuance_proven',
    'consequence_lifecycle_closed',
    'absolute_human_intention',
  ]) {
    if (boundary[key] !== false) {
      throw new Error(`active persistent action crossing overclaimed ${key}`);
    }
  }
  if (
    !Array.isArray(report.known_open_boundaries) ||
    report.known_open_boundaries.length !==
      ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_OPEN_BOUNDARIES.length ||
    !Array.isArray(report.non_claims) ||
    report.non_claims.length !== ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_NON_CLAIMS.length
  ) {
    throw new Error('active persistent action crossing boundaries drifted');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return true;
}

export function writeProtectedRecordsActivePersistentProfileActionCrossingReport({
  report,
  outputPath,
  activationRoot,
}) {
  assertProtectedRecordsActivePersistentProfileActionCrossing(report);
  if (!outputPath) {
    throw new Error('active persistent action crossing report output path is required');
  }
  assertActivePersistentProfileLiveReportOutputPath({ outputPath, activationRoot });
  mkdirSync(dirname(outputPath), { recursive: true });
  const output = `${JSON.stringify(report, null, 2)}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  writeFileSync(outputPath, output, { mode: 0o600 });
  return sha256hex(output);
}

export function formatProtectedRecordsActivePersistentProfileActionCrossing(report) {
  assertProtectedRecordsActivePersistentProfileActionCrossing(report);
  const lines = [
    'ZLAR Active Persistent Profile Governed Action Crossing v1',
    `active_root=${report.active_profile.activation_root_label}`,
    `expires_at=${report.active_profile.expires_at}`,
    `action_class=${report.action_class}`,
    `active_root_read_at_action_time=${report.claim_boundary.active_root_read_at_action_time}`,
    `evaluation_time_boundary: active_root_status_epoch=${report.evaluation_time_contract.active_root_status_epoch}; local_service_authority_evaluation_epoch=${report.evaluation_time_contract.local_service_authority_evaluation_epoch}; service_uses_fixture_epoch=${report.evaluation_time_contract.local_service_authority_uses_fixture_epoch}; fixture_epoch_is_not_live_authority_time=${report.evaluation_time_contract.fixture_epoch_is_not_live_authority_time}`,
    `selected_profile_id=${report.action_crossing.requested_profile_id}`,
    `selected_profile_sha256=${report.action_crossing.requested_profile_sha256}`,
    `selects_latest=${report.action_crossing.selects_latest_profile}`,
    `recognized_records_write_boarded=${report.claim_boundary.recognized_records_write_boarded}`,
    `recognized_state_append_count=${report.service_crossing.recognized_write_state_append_count}`,
    `fixture_authority_grant_path_evidenced=${report.claim_boundary.fixture_authority_grant_path_evidenced}; rightful_issuance_proven=${report.claim_boundary.rightful_issuance_proven}`,
    `recognition_refusals_before_mutation=${report.claim_boundary.recognition_refusals_before_mutation}; authority_grant_refusals_before_consumption_and_mutation=${report.claim_boundary.authority_grant_refusals_before_consumption_and_mutation}`,
    `same_process_signed_payload_replay_refused=${report.claim_boundary.same_process_signed_payload_replay_refused}; restart_consumed_authority_grant_refused=${report.claim_boundary.restart_consumed_authority_grant_refused}`,
    `runtime_contract: consumed_authority_grant_store=${report.service_crossing.consumed_authority_grant_store}; consumption_identity=${report.service_crossing.consumption_identity}; signed_payload_replay_identity=${report.service_crossing.signed_payload_replay_identity}; witness_source=${report.service_crossing.consumed_grant_store_witness_source}`,
    `burn_and_rollback: state_append_burn=${report.service_crossing.state_append_after_grant_commit_burn_observed}; metadata_burn=${report.service_crossing.metadata_partial_commit_burn_observed}; witness_ahead_refusal=${report.service_crossing.store_and_anchor_rollback_refused_while_witness_ahead}; joint_rollback_detection=${report.service_crossing.store_anchor_and_witness_joint_rollback_detection}; joint_rollback_reopened_grant_reuse=${report.service_crossing.joint_rollback_reopened_authority_grant_reuse}`,
    `proof_target=${report.proof_target.target_label}; recognized_delta=${report.proof_target.recognized_entry_delta}; refusal_delta_total=${report.proof_target.refusal_entry_delta_total}`,
    `recognition_refusal_taxonomy_sha256=${report.hashes.recognition_refusal_taxonomy_sha256}`,
    `authority_refusal_taxonomy_sha256=${report.hashes.authority_refusal_taxonomy_sha256}`,
    `current_machine_governance_general=${report.claim_boundary.current_machine_governance_general}`,
    `production_downstream_recognition=${report.claim_boundary.production_downstream_recognition}`,
    'Non-claims:',
  ];
  for (const claim of report.non_claims) {
    lines.push(`- ${claim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(summary);
  return summary;
}
