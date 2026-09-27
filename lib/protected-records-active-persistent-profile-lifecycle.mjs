import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { canonicalize } from './canonicalize.mjs';
import { sha256hex } from './receipt.mjs';
import {
  ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
  ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
} from './protected-records-active-persistent-profile-preflight.mjs';
import {
  PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_INSTALLATION_REPORT_TYPE,
  assertActivePersistentProfileLiveInstallationReport,
  assertActivePersistentProfileLiveReportOutputPath,
  closeActivePersistentProfileLiveInstallation,
  inspectActivePersistentProfileLiveStatus,
  runActivePersistentProfileLiveInstallation,
  writeActivePersistentProfileLiveReport,
} from './protected-records-active-persistent-profile-live-installation.mjs';
import {
  PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_TYPE,
  assertProtectedRecordsActivePersistentProfileActionCrossing,
  runProtectedRecordsActivePersistentProfileActionCrossing,
  writeProtectedRecordsActivePersistentProfileActionCrossingReport,
} from './protected-records-active-persistent-profile-action-crossing.mjs';
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
  PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH,
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from './protected-records-runtime-profile.mjs';
import {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed,
} from './protected-records-fixture-authority-status.mjs';

export const PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_REPORT_TYPE =
  'zlar-protected-records-active-persistent-profile-lifecycle-v1';
export const PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SOURCE_BINDING_TYPE =
  'zlar-active-persistent-profile-lifecycle-source-binding-v1';
export const PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_RUNNER_RESULT_TYPE =
  'zlar-active-persistent-profile-lifecycle-runner-result-v1';
export const ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_REPORT_FILE =
  'zlar-active-persistent-profile-lifecycle-v1.json';
export const ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SOURCE_BINDING_FILE =
  'zlar-active-persistent-profile-lifecycle-source-binding-v1.json';
export const ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_EVIDENCE_CLASS =
  'historical_supplied_local_active_persistent_profile_lifecycle';

export const ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SAFE_CLAIM =
  'ZLAR verified supplied historical local active persistent profile lifecycle mechanics: bounded installation/readback, one recorded records.write crossing, recognition and authority-grant refusal before mutation, and explicit closeout refusal; the exhausted one-use grant does not project current fixture-rightful issuance.';

export const ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_NON_CLAIMS = Object.freeze([
  'This verifier checks supplied local evidence reports; it does not reopen, renew, reactivate, or install an active profile root.',
  'This verifier does not touch real personal, business, customer, or production records.',
  'This verifier does not use credentials, secrets, HMAC, tokens, private keys, YubiKey, GitHub, Actions, tags, releases, website publication, Telegram, external services, production issuer custody, or production key custody.',
  'The active-root status observations use each action-time epoch, while local service reports use the pinned runtime fixture evaluation epoch; the source-recorded exhausted grant makes current fixture-rightful projection false and does not prove live, portable, or production rightful issuance.',
  'This lifecycle evidence does not close exactly-once, non-atomic store-anchor-witness commit, joint rollback reuse, host-filesystem path TOCTOU, or the wider consequence lifecycle.',
  'This verifier does not prove raw Codex/developer-tool governance, arbitrary current-machine governance, all-surface governance, side-door closure, production downstream recognition, production authority, enterprise readiness, public external attestation, sovereign recognition, or absolute human intention.',
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

function expectBool(label, value, expected) {
  if (value !== expected) {
    throw new Error(`${label} must be ${expected}`);
  }
  return true;
}

function expectString(label, value) {
  if (typeof value !== 'string' || value.length < 1) {
    throw new Error(`${label} must be a non-empty string`);
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(value);
  return true;
}

function expectSha(label, value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`${label} must be a SHA-256 hex string`);
  }
  return true;
}

function parseIsoMillis(label, value) {
  expectString(label, value);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new Error(`${label} must be a valid ISO-8601 timestamp`);
  }
  return parsed;
}

function expectArray(label, value) {
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  return true;
}

function assertExpectedInputReportHashes({ actual, expected = {} }) {
  const keys = [
    'install_report_sha256',
    'green_report_sha256',
    'red_report_sha256',
    'closeout_report_sha256',
  ];
  const provided = keys.filter((key) => Object.prototype.hasOwnProperty.call(expected, key));
  if (provided.length === 0) {
    return false;
  }
  if (provided.length !== keys.length) {
    throw new Error('active persistent lifecycle expected input hashes must be all-or-none');
  }
  for (const key of keys) {
    expectSha(`active persistent lifecycle expected ${key}`, expected[key]);
    if (actual[key] !== expected[key]) {
      throw new Error(`active persistent lifecycle expected input hash mismatch for ${key}`);
    }
  }
  return true;
}

function assertNoFailures(label, value) {
  if (!Array.isArray(value) || value.length !== 0) {
    throw new Error(`${label} must have no failures`);
  }
  return true;
}

function readJsonFile(path, label) {
  let text = '';
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    throw new Error(`${label} could not be read`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

function sha256File(path, label) {
  let text = '';
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    throw new Error(`${label} could not be hashed`);
  }
  return sha256hex(text);
}

function basenameLabel(path) {
  if (!path || typeof path !== 'string') {
    return '<supplied-report>';
  }
  const name = basename(path);
  assertNoUnsafeProtectedRecordsRuntimeProfileText(name);
  return name;
}

function isoFromEpoch(epoch) {
  return new Date(epoch * 1000).toISOString();
}

function buildFixtureAuthorityEvaluationTimeContract(activeRootStatusEpoch) {
  return {
    active_root_status_epoch: activeRootStatusEpoch,
    active_root_status_uses_action_time_epoch: true,
    local_service_authority_evaluation_epoch:
      PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH,
    local_service_authority_uses_fixture_epoch: true,
    time_domains_intentionally_separate: true,
    fixture_epoch_is_not_live_authority_time: true,
  };
}

function assertFixtureAuthorityEvaluationTimeContract(contract, expectedActionEpoch) {
  assertExactKeys('active persistent lifecycle evaluation time contract', contract, [
    'active_root_status_epoch',
    'active_root_status_uses_action_time_epoch',
    'fixture_epoch_is_not_live_authority_time',
    'local_service_authority_evaluation_epoch',
    'local_service_authority_uses_fixture_epoch',
    'time_domains_intentionally_separate',
  ]);
  if (
    !Number.isInteger(contract.active_root_status_epoch) ||
    contract.active_root_status_epoch !== expectedActionEpoch ||
    contract.active_root_status_uses_action_time_epoch !== true ||
    contract.local_service_authority_evaluation_epoch !==
      PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH ||
    contract.local_service_authority_uses_fixture_epoch !== true ||
    contract.time_domains_intentionally_separate !== true ||
    contract.fixture_epoch_is_not_live_authority_time !== true
  ) {
    throw new Error('active persistent lifecycle evaluation time boundary drifted');
  }
  return true;
}

function statusLifecycleSummary(status, { includeInstallSafety = false } = {}) {
  const summary = {
    active: status.active,
    expired: status.expired,
    manifest_status: status.manifest_status,
    activation_root_state: status.activation_root_state,
    expires_at: status.expires_at,
  };
  if (includeInstallSafety) {
    summary.safe_for_install = status.safe_for_install;
    summary.explicit_closeout_or_replace_required =
      status.explicit_closeout_or_replace_required;
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(summary));
  return summary;
}

function sha256Canonical(value) {
  return sha256hex(canonicalize(value));
}

function safeReportMessage(value, fallback) {
  const text = typeof value === 'string' && value.length > 0
    ? value
    : fallback;
  try {
    assertNoUnsafeProtectedRecordsRuntimeProfileText(text);
    return text;
  } catch {
    return fallback;
  }
}

function assertOutputAbsent(path, label) {
  if (existsSync(path)) {
    throw new Error(`${label} already exists`);
  }
  return true;
}

function assertLifecycleFixtureProfileBinding({ profileId, profileSha256 }) {
  if (
    profileId !== 'protected-records-runtime-fixture-profile' ||
    profileSha256 !== ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256
  ) {
    throw new Error('active persistent lifecycle fixed runtime profile binding failed');
  }
  return true;
}

function readProfileFile(path) {
  const profile = readJsonFile(path, 'active persistent lifecycle runtime profile');
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(profile));
  return profile;
}

function lifecycleAuthorityPacketSha256() {
  return sha256Canonical({
    authority: 'operator-authorized-explicit-active-persistent-profile-boundary',
    scope: 'explicit-proof-owned-or-operator-named-active-persistent-root-only',
    action_class: 'records.write',
    non_claims_preserved: [
      'no-public-claim',
      'no-production-deployment',
      'no-external-attestation',
      'no-enterprise-readiness',
    ],
  });
}

export function readActivePersistentProfileLifecycleInputs({
  installReportPath,
  greenReportPath,
  redReportPath,
  closeoutReportPath,
  expectedInputReportHashes = {},
} = {}) {
  const inputReportHashes = {
    install_report_sha256: sha256File(installReportPath, 'active persistent lifecycle installation report'),
    green_report_sha256: sha256File(greenReportPath, 'active persistent lifecycle green crossing report'),
    red_report_sha256: sha256File(redReportPath, 'active persistent lifecycle red refusal report'),
    closeout_report_sha256: sha256File(closeoutReportPath, 'active persistent lifecycle closeout report'),
  };
  const expectedInputReportHashesBound = assertExpectedInputReportHashes({
    actual: inputReportHashes,
    expected: expectedInputReportHashes,
  });
  return {
    installReport: readJsonFile(installReportPath, 'active persistent lifecycle installation report'),
    greenReport: readJsonFile(greenReportPath, 'active persistent lifecycle green crossing report'),
    redReport: readJsonFile(redReportPath, 'active persistent lifecycle red refusal report'),
    closeoutReport: readJsonFile(closeoutReportPath, 'active persistent lifecycle closeout report'),
    inputReportHashes,
    expectedInputReportHashesBound,
    inputReportLabels: {
      install_report: basenameLabel(installReportPath),
      green_report: basenameLabel(greenReportPath),
      red_report: basenameLabel(redReportPath),
      closeout_report: basenameLabel(closeoutReportPath),
    },
  };
}

export function assertActivePersistentProfileRedPathRefusalReport(report) {
  assertExactKeys('active persistent red-path refusal report', report, [
    'active_root',
    'artifact_hashes',
    'authority_packet',
    'exact_claim',
    'evaluation_time_contract',
    'failures',
    'generated_at',
    'non_claims',
    'proof_report_type',
    'red_path_result',
    'recognition_refusal_cases',
    'authority_refusal_cases',
    'scratch_dir',
    'selected_profile',
    'wrapper_note',
  ]);
  if (report.proof_report_type !== 'zlar-active-persistent-profile-red-path-refusal-proof-report-v1') {
    throw new Error('active persistent red-path refusal report type drifted');
  }
  expectString('active persistent red-path generated_at', report.generated_at);
  const generatedAtEpoch = Math.floor(
    parseIsoMillis('active persistent red-path generated_at', report.generated_at) / 1000
  );
  assertFixtureAuthorityEvaluationTimeContract(
    report.evaluation_time_contract,
    generatedAtEpoch
  );
  assertNoFailures('active persistent red-path failures', report.failures);
  expectArray('active persistent red-path non_claims', report.non_claims);

  const activeRoot = requireObject('active persistent red-path active root', report.active_root);
  if (
    ![
      '<named-active-persistent-profile-root>',
      '<surrogate-active-persistent-profile-root>',
    ].includes(activeRoot.label) ||
    activeRoot.real_path_redacted_in_public_claims !== true ||
    activeRoot.status_before?.active !== true ||
    activeRoot.status_before?.expired !== false ||
    activeRoot.status_before?.manifest_status !== 'active_persistent_profile_installed' ||
    activeRoot.status_before?.activation_root_state !== 'active_until_expiry' ||
    activeRoot.status_after?.active !== true ||
    activeRoot.status_final?.active !== true
  ) {
    throw new Error('active persistent red-path active root drifted');
  }

  const selected = requireObject('active persistent red-path selected profile', report.selected_profile);
  if (
    selected.profile_id !== 'protected-records-runtime-fixture-profile' ||
    selected.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    selected.profile_sha256 !== ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256 ||
    selected.selected_by_explicit_id_and_sha !== true ||
    selected.selects_latest_profile !== false
  ) {
    throw new Error('active persistent red-path selected profile drifted');
  }
  expectSha('active persistent red-path recognition contract', selected.recognition_contract_sha256);
  expectSha('active persistent red-path authority grant contract', selected.authority_grant_contract_sha256);

  const result = requireObject('active persistent red-path result', report.red_path_result);
  assertExactKeys('active persistent red-path result', result, [
    'active_root_bound_preflight_verified',
    'authority_grant_refusals_before_consumption_and_mutation',
    'authority_grant_supplied_by_agent',
    'authority_refusal_case_count',
    'authority_refusal_state_append_count',
    'authority_refusal_taxonomy_sha256',
    'artifact_identity_expected_sha256_supplied',
    'artifact_identity_sha256_matched',
    'baseline_recognized_state_append_count',
    'baseline_recognized_write_boarded_inside_disposable_service',
    'consequence_lifecycle_closed',
    'current_machine_governance_proven',
    'disposable_service_started',
    'expected_artifact_body_sha256',
    'fixture_rightful_issuance_path_evidenced',
    'joint_rollback_reopened_authority_grant_reuse',
    'live_authority_proven',
    'live_probing',
    'local_disposable_child_process_only',
    'metadata_partial_commit_burn_observed',
    'partial_commit_state_append_count',
    'persistent_runtime_config_written',
    'portable_rightful_issuance_proven',
    'production_rightful_issuance_proven',
    'proof_ran_while_active_root_live',
    'recognition_refusal_case_count',
    'recognition_refusal_state_append_count',
    'recognition_refusal_taxonomy_sha256',
    'recognition_refusals_before_mutation',
    'recognition_rule_supplied_by_agent',
    'replay_refusal_state_append_count',
    'restart_consumed_authority_grant_refused',
    'result',
    'rightful_issuance_proven',
    'same_process_signed_payload_replay_refused',
    'signed_receipt_envelope_identity_bound_to_expected_artifact_sha256',
    'source_preflight_identity_bound_to_expected_artifact_sha256',
    'state_append_after_grant_commit_burn_observed',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_and_anchor_rollback_refused_while_witness_ahead',
    'verification_scope',
  ]);
  if (
    result.result !== 'pass' ||
    result.artifact_identity_expected_sha256_supplied !== true ||
    result.expected_artifact_body_sha256 !==
      report.artifact_hashes.service_artifact_body_sha256 ||
    result.artifact_identity_sha256_matched !== true ||
    result.source_preflight_identity_bound_to_expected_artifact_sha256 !== true ||
    result.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256 !== true ||
    result.verification_scope !==
      'expected-artifact-identity-bound-local-fixture-projection' ||
    result.proof_ran_while_active_root_live !== true ||
    result.active_root_bound_preflight_verified !== true ||
    result.disposable_service_started !== true ||
    result.local_disposable_child_process_only !== true ||
    result.persistent_runtime_config_written !== false ||
    result.live_probing !== false ||
    result.baseline_recognized_write_boarded_inside_disposable_service !== true ||
    result.baseline_recognized_state_append_count !== 1 ||
    result.recognition_refusals_before_mutation !== true ||
    result.authority_grant_refusals_before_consumption_and_mutation !== true ||
    result.same_process_signed_payload_replay_refused !== true ||
    result.restart_consumed_authority_grant_refused !== true ||
    result.recognition_refusal_state_append_count !== 0 ||
    result.authority_refusal_state_append_count !== 0 ||
    result.replay_refusal_state_append_count !== 0 ||
    result.partial_commit_state_append_count !== 0 ||
    result.state_append_after_grant_commit_burn_observed !== true ||
    result.metadata_partial_commit_burn_observed !== true ||
    result.store_and_anchor_rollback_refused_while_witness_ahead !== true ||
    result.store_anchor_and_witness_joint_rollback_detection !== false ||
    result.joint_rollback_reopened_authority_grant_reuse !== true ||
    result.authority_grant_supplied_by_agent !== false ||
    result.recognition_rule_supplied_by_agent !== false ||
    result.recognition_refusal_case_count !== 18 ||
    result.authority_refusal_case_count !== 5 ||
    result.fixture_rightful_issuance_path_evidenced !== true ||
    result.rightful_issuance_proven !== false ||
    result.portable_rightful_issuance_proven !== false ||
    result.live_authority_proven !== false ||
    result.production_rightful_issuance_proven !== false ||
    result.current_machine_governance_proven !== false ||
    result.consequence_lifecycle_closed !== false
  ) {
    throw new Error('active persistent red-path result drifted');
  }
  expectSha('active persistent red-path recognition refusal taxonomy', result.recognition_refusal_taxonomy_sha256);
  expectSha('active persistent red-path authority refusal taxonomy', result.authority_refusal_taxonomy_sha256);
  if (
    !Array.isArray(report.recognition_refusal_cases) ||
    report.recognition_refusal_cases.length !== 18 ||
    report.recognition_refusal_cases.some((item) =>
      item.refused_before_mutation !== true ||
      typeof item.case_id !== 'string' ||
      typeof item.reason_code !== 'string'
    ) ||
    !Array.isArray(report.authority_refusal_cases) ||
    report.authority_refusal_cases.length !== 5 ||
    report.authority_refusal_cases.some((item) =>
      item.refused_before_consumption_and_mutation !== true ||
      typeof item.case_id !== 'string' ||
      typeof item.reason_code !== 'string'
    )
  ) {
    throw new Error('active persistent red-path refusal cases drifted');
  }
  for (const [key, value] of Object.entries(requireObject('active persistent red-path artifact hashes', report.artifact_hashes))) {
    expectSha(`active persistent red-path artifact ${key}`, value);
  }
  return true;
}

export function assertActivePersistentProfileCloseoutRefusalReport(report) {
  assertExactKeys('active persistent closeout refusal report', report, [
    'after_status',
    'artifact_hashes',
    'authority_packet',
    'before_status',
    'closeout',
    'exact_claim',
    'failures',
    'generated_at',
    'non_claims',
    'proof_report_type',
    'refused_after_closeout_probe',
    'scratch_dir',
  ]);
  if (report.proof_report_type !== 'zlar-active-persistent-profile-closeout-refusal-proof-report-v1') {
    throw new Error('active persistent closeout refusal report type drifted');
  }
  expectString('active persistent closeout generated_at', report.generated_at);
  assertNoFailures('active persistent closeout failures', report.failures);
  expectArray('active persistent closeout non_claims', report.non_claims);

  const before = requireObject('active persistent closeout before status', report.before_status);
  if (
    before.active !== true ||
    before.expired !== false ||
    before.manifest_status !== 'active_persistent_profile_installed' ||
    before.activation_root_state !== 'active_until_expiry'
  ) {
    throw new Error('active persistent closeout before status drifted');
  }
  expectString('active persistent closeout before expiry', before.expires_at);

  const closeout = requireObject('active persistent closeout object', report.closeout);
  if (
    closeout.status !== 'closed_inert_evidence' ||
    closeout.active !== false ||
    closeout.closeout_reactivation_allowed !== false
  ) {
    throw new Error('active persistent closeout object drifted');
  }
  expectString('active persistent closeout closed_at', closeout.closed_at);

  const after = requireObject('active persistent closeout after status', report.after_status);
  if (
    after.active !== false ||
    after.expired !== false ||
    after.manifest_status !== 'closed_inert_evidence' ||
    after.activation_root_state !== 'closed_inert_evidence' ||
    after.safe_for_install !== false ||
    after.explicit_closeout_or_replace_required !== true
  ) {
    throw new Error('active persistent closeout after status drifted');
  }
  expectString('active persistent closeout after expiry', after.expires_at);

  const probe = requireObject('active persistent closeout refused probe', report.refused_after_closeout_probe);
  if (
    probe.attempted_action_class !== 'records.write' ||
    probe.exit_code === 0 ||
    probe.target_written !== false ||
    probe.refusal_before_target_mutation !== true
  ) {
    throw new Error('active persistent closeout refusal probe drifted');
  }
  expectSha('active persistent closeout refused stdout', probe.stdout_sha256);
  expectSha('active persistent closeout refused stderr', probe.stderr_sha256);
  expectString('active persistent closeout refused stderr snippet', probe.stderr_redacted_snippet);
  if (
    !probe.stderr_redacted_snippet.includes(
      'active persistent action crossing requires an active unexpired explicit root'
    )
  ) {
    throw new Error('active persistent closeout refusal reason drifted');
  }
  for (const [key, value] of Object.entries(requireObject('active persistent closeout artifact hashes', report.artifact_hashes))) {
    expectSha(`active persistent closeout artifact ${key}`, value);
  }
  return true;
}

function assertSameProfile({ installReport, greenReport, redReport }) {
  const profileId = installReport.selected_profile.profile_id;
  const runtimeProfileId = installReport.selected_profile.runtime_profile_id;
  const profileSha256 = installReport.selected_profile.runtime_profile_sha256;
  if (
    profileId !== 'protected-records-runtime-fixture-profile' ||
    runtimeProfileId !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    profileSha256 !== ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256 ||
    greenReport.action_crossing.requested_profile_id !== profileId ||
    greenReport.action_crossing.runtime_profile_id !== runtimeProfileId ||
    greenReport.action_crossing.requested_profile_sha256 !== profileSha256 ||
    redReport.selected_profile.profile_id !== profileId ||
    redReport.selected_profile.runtime_profile_id !== runtimeProfileId ||
    redReport.selected_profile.profile_sha256 !== profileSha256 ||
    redReport.selected_profile.recognition_contract_sha256 !==
      greenReport.hashes.recognition_contract_sha256 ||
    redReport.selected_profile.authority_grant_contract_sha256 !==
      greenReport.hashes.authority_grant_contract_sha256 ||
    redReport.red_path_result.recognition_refusal_taxonomy_sha256 !==
      greenReport.hashes.recognition_refusal_taxonomy_sha256 ||
    redReport.red_path_result.authority_refusal_taxonomy_sha256 !==
      greenReport.hashes.authority_refusal_taxonomy_sha256
  ) {
    throw new Error('active persistent lifecycle profile binding drifted');
  }
  return { profileId, runtimeProfileId, profileSha256 };
}

function assertLifecycleSequence({ installReport, greenReport, redReport, closeoutReport }) {
  const installedAtMillis = parseIsoMillis(
    'active persistent lifecycle installed_at',
    installReport.installed_at
  );
  const expiryMillis = parseIsoMillis(
    'active persistent lifecycle install expiry',
    installReport.expires_at
  );
  const greenMillis = Number.isInteger(greenReport.now_epoch)
    ? greenReport.now_epoch * 1000
    : NaN;
  if (!Number.isFinite(greenMillis)) {
    throw new Error('active persistent lifecycle green now_epoch must be finite');
  }
  const redGeneratedMillis = parseIsoMillis(
    'active persistent lifecycle red generated_at',
    redReport.generated_at
  );
  const closeoutClosedMillis = parseIsoMillis(
    'active persistent lifecycle closeout closed_at',
    closeoutReport.closeout.closed_at
  );
  const closeoutGeneratedMillis = parseIsoMillis(
    'active persistent lifecycle closeout generated_at',
    closeoutReport.generated_at
  );
  const redFinalStatus = redReport.active_root.status_final;
  const closeoutBeforeStatus = closeoutReport.before_status;
  if (
    greenReport.active_profile.expires_at !== installReport.expires_at ||
    redReport.active_root.status_before.expires_at !== installReport.expires_at ||
    redReport.active_root.status_after.expires_at !== installReport.expires_at ||
    redFinalStatus.expires_at !== installReport.expires_at ||
    closeoutBeforeStatus.expires_at !== installReport.expires_at ||
    closeoutReport.after_status.expires_at !== installReport.expires_at
  ) {
    throw new Error('active persistent lifecycle expiry binding drifted');
  }
  if (
    redFinalStatus.active !== closeoutBeforeStatus.active ||
    redFinalStatus.expired !== closeoutBeforeStatus.expired ||
    redFinalStatus.manifest_status !== closeoutBeforeStatus.manifest_status ||
    redFinalStatus.activation_root_state !== closeoutBeforeStatus.activation_root_state ||
    redReport.artifact_hashes.status_final_sha256 !==
      closeoutReport.artifact_hashes.status_before_sha256
  ) {
    throw new Error('active persistent lifecycle closeout source binding drifted');
  }
  if (
    installedAtMillis > greenMillis ||
    greenMillis > redGeneratedMillis ||
    redGeneratedMillis > closeoutClosedMillis ||
    closeoutClosedMillis > closeoutGeneratedMillis ||
    closeoutClosedMillis > expiryMillis
  ) {
    throw new Error('active persistent lifecycle timestamps are out of order');
  }
  return true;
}

export function buildActivePersistentProfileLifecycleReport({
  installReport,
  greenReport,
  redReport,
  closeoutReport,
  inputReportHashes = {},
  inputReportLabels = {},
  expectedInputReportHashesBound = false,
  generatedAt = new Date().toISOString(),
} = {}) {
  assertActivePersistentProfileLiveInstallationReport(installReport);
  assertProtectedRecordsActivePersistentProfileActionCrossing(greenReport);
  assertActivePersistentProfileRedPathRefusalReport(redReport);
  assertActivePersistentProfileCloseoutRefusalReport(closeoutReport);
  const profile = assertSameProfile({ installReport, greenReport, redReport });
  assertLifecycleSequence({ installReport, greenReport, redReport, closeoutReport });
  const freshServiceArtifactIdentityPinsMatched =
    greenReport.service_crossing.artifact_identity_sha256_matched === true &&
    redReport.red_path_result.artifact_identity_sha256_matched === true;
  const freshSourcePreflightIdentitiesBound =
    greenReport.service_crossing.source_preflight_identity_bound_to_expected_artifact_sha256 === true &&
    redReport.red_path_result.source_preflight_identity_bound_to_expected_artifact_sha256 === true;
  const freshSignedReceiptEnvelopeIdentitiesBound =
    greenReport.service_crossing.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256 === true &&
    redReport.red_path_result.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256 === true;
  // Supplied lifecycle reports are historical evidence. Their schema does not
  // bind a replacement grant status record, so no future current-grant update
  // may reactivate their embedded fixture-rightful booleans.
  const fixtureRightfulIssuancePathEvidenced = false;

  const report = {
    report_type: PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_REPORT_TYPE,
    schema_version: 1,
    evidence_model: 'supplied-active-persistent-profile-lifecycle-evidence-verification',
    result: 'pass',
    generated_at: generatedAt,
    safe_claim: ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SAFE_CLAIM,
    supplied_reports: {
      expected_hashes_bound: expectedInputReportHashesBound === true,
      labels: {
        install_report: inputReportLabels.install_report || '<installation-report>',
        green_report: inputReportLabels.green_report || '<green-action-crossing-report>',
        red_report: inputReportLabels.red_report || '<red-path-refusal-report>',
        closeout_report: inputReportLabels.closeout_report || '<closeout-refusal-report>',
      },
      hashes: {
        install_report_sha256:
          inputReportHashes.install_report_sha256 || sha256hex(canonicalize(installReport)),
        green_report_sha256:
          inputReportHashes.green_report_sha256 || sha256hex(canonicalize(greenReport)),
        red_report_sha256:
          inputReportHashes.red_report_sha256 || sha256hex(canonicalize(redReport)),
        closeout_report_sha256:
          inputReportHashes.closeout_report_sha256 || sha256hex(canonicalize(closeoutReport)),
      },
    },
    selected_profile: {
      profile_id: profile.profileId,
      runtime_profile_id: profile.runtimeProfileId,
      runtime_profile_sha256: profile.profileSha256,
      selected_by_explicit_id_and_sha: true,
      selects_latest_profile: false,
    },
    lifecycle: {
      activation_root_label: installReport.activation_root_label,
      installed_at: installReport.installed_at,
      expires_at: installReport.expires_at,
      active_after_install: installReport.active_after_proof,
      green_action_class: greenReport.action_class,
      green_active_root_status_epoch:
        greenReport.evaluation_time_contract.active_root_status_epoch,
      green_local_service_authority_evaluation_epoch:
        greenReport.evaluation_time_contract.local_service_authority_evaluation_epoch,
      green_recognized_write_delta:
        greenReport.service_crossing.recognized_write_state_append_count,
      green_refusal_delta_total: greenReport.proof_target.refusal_entry_delta_total,
      red_recognition_refusal_case_count:
        redReport.red_path_result.recognition_refusal_case_count,
      red_authority_refusal_case_count:
        redReport.red_path_result.authority_refusal_case_count,
      red_active_root_status_epoch:
        redReport.evaluation_time_contract.active_root_status_epoch,
      red_local_service_authority_evaluation_epoch:
        redReport.evaluation_time_contract.local_service_authority_evaluation_epoch,
      fixture_authority_evaluation_epoch_pinned:
        greenReport.evaluation_time_contract.local_service_authority_evaluation_epoch ===
          PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH &&
        redReport.evaluation_time_contract.local_service_authority_evaluation_epoch ===
          PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH,
      action_time_and_fixture_authority_time_domains_separate: true,
      fresh_service_artifact_identity_pins_matched:
        freshServiceArtifactIdentityPinsMatched,
      fresh_source_preflight_identities_bound:
        freshSourcePreflightIdentitiesBound,
      fresh_signed_receipt_envelope_identities_bound:
        freshSignedReceiptEnvelopeIdentitiesBound,
      red_recognition_refusal_state_append_count:
        redReport.red_path_result.recognition_refusal_state_append_count,
      red_authority_refusal_state_append_count:
        redReport.red_path_result.authority_refusal_state_append_count,
      red_replay_refusal_state_append_count:
        redReport.red_path_result.replay_refusal_state_append_count,
      red_same_process_signed_payload_replay_refused:
        redReport.red_path_result.same_process_signed_payload_replay_refused,
      red_restart_consumed_authority_grant_refused:
        redReport.red_path_result.restart_consumed_authority_grant_refused,
      red_state_append_after_grant_commit_burn_observed:
        redReport.red_path_result.state_append_after_grant_commit_burn_observed,
      red_metadata_partial_commit_burn_observed:
        redReport.red_path_result.metadata_partial_commit_burn_observed,
      red_store_and_anchor_rollback_refused_while_witness_ahead:
        redReport.red_path_result.store_and_anchor_rollback_refused_while_witness_ahead,
      red_store_anchor_and_witness_joint_rollback_detection:
        redReport.red_path_result.store_anchor_and_witness_joint_rollback_detection,
      red_joint_rollback_reopened_authority_grant_reuse:
        redReport.red_path_result.joint_rollback_reopened_authority_grant_reuse,
      red_authority_grant_supplied_by_agent:
        redReport.red_path_result.authority_grant_supplied_by_agent,
      red_recognition_rule_supplied_by_agent:
        redReport.red_path_result.recognition_rule_supplied_by_agent,
      fixture_rightful_issuance_path_evidenced:
        fixtureRightfulIssuancePathEvidenced,
      closeout_at: closeoutReport.closeout.closed_at,
      closeout_status: closeoutReport.closeout.status,
      closed_root_active_after_closeout: closeoutReport.after_status.active,
      closed_root_safe_for_install: closeoutReport.after_status.safe_for_install,
      refused_after_closeout_exit_code:
        closeoutReport.refused_after_closeout_probe.exit_code,
      refused_after_closeout_target_written:
        closeoutReport.refused_after_closeout_probe.target_written,
    },
    claim_boundary: {
      local_active_persistent_profile_lifecycle_verified: true,
      install_and_readback_verified: true,
      green_path_governed_action_crossing_verified: true,
      red_path_refusal_before_mutation_verified: true,
      closeout_refusal_before_mutation_verified: true,
      expected_input_report_hashes_bound: expectedInputReportHashesBound === true,
      fixture_rightful_issuance_path_evidenced:
        fixtureRightfulIssuancePathEvidenced,
      rightful_issuance_proven: false,
      portable_rightful_issuance_proven: false,
      live_authority_proven: false,
      consequence_lifecycle_closed: false,
      current_machine_governance_general: false,
      raw_codex_or_developer_tool_governance: false,
      browser_computer_use_mcp_shell_network_or_all_surface_governance: false,
      live_always_on_runtime_service_governance: false,
      production_downstream_recognition: false,
      production_authority: false,
      enterprise_readiness: false,
      public_external_attestation: false,
      sovereign_recognition: false,
      side_door_closure: false,
      absolute_human_intention: false,
    },
    non_claims: [...ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_NON_CLAIMS],
  };
  assertActivePersistentProfileLifecycleReport(report);
  return report;
}

export function buildActivePersistentProfileLifecycleReportFromFiles(paths = {}) {
  const inputs = readActivePersistentProfileLifecycleInputs(paths);
  return buildActivePersistentProfileLifecycleReport(inputs);
}

export function runActivePersistentProfileRedPathRefusal({
  activationRoot,
  expectedProfile,
  profileId = 'protected-records-runtime-fixture-profile',
  profileSha256 = ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
  nowEpoch = Math.floor(Date.now() / 1000),
  allowNamedLiveRoot = false,
  expectedLiveRoot,
} = {}) {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
    'Protected records active persistent profile red-path evidence run'
  );
  const statusBefore = inspectActivePersistentProfileLiveStatus({
    activationRoot,
    nowEpoch,
    allowNamedLiveRoot,
    expectedLiveRoot,
  });
  const preflight = runProtectedRecordsInstalledRuntimeProfilePreflight({
    installRoot: activationRoot,
    expectedProfile,
    profileId,
    profileSha256,
  });
  const preflightArtifact = buildProtectedRecordsInstalledRuntimeProfilePreflightArtifact(
    preflight
  );
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
  const statusAfter = inspectActivePersistentProfileLiveStatus({
    activationRoot,
    nowEpoch,
    allowNamedLiveRoot,
    expectedLiveRoot,
  });
  const statusFinal = inspectActivePersistentProfileLiveStatus({
    activationRoot,
    nowEpoch,
    allowNamedLiveRoot,
    expectedLiveRoot,
  });
  const beforeSummary = statusLifecycleSummary(statusBefore);
  const afterSummary = statusLifecycleSummary(statusAfter);
  const finalSummary = statusLifecycleSummary(statusFinal);
  const preflightReportSha256 = sha256Canonical(preflight);
  const serviceProofReportSha256 = sha256Canonical(serviceProof);
  const serviceVerificationSha256 = sha256Canonical(serviceVerification);
  const report = {
    proof_report_type: 'zlar-active-persistent-profile-red-path-refusal-proof-report-v1',
    generated_at: isoFromEpoch(nowEpoch),
    evaluation_time_contract:
      buildFixtureAuthorityEvaluationTimeContract(nowEpoch),
    authority_packet: {
      packet_sha256: lifecycleAuthorityPacketSha256(),
    },
    scratch_dir: '<launcher-owned-red-path-proof-scratch>',
    active_root: {
      label: statusBefore.activation_root_label,
      real_path_redacted_in_public_claims: true,
      status_before: beforeSummary,
      status_after: afterSummary,
      status_final: finalSummary,
    },
    selected_profile: {
      source: 'explicit-active-root-installed-profile-preflight-artifact',
      profile_id: profileId,
      runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      profile_sha256: profileSha256,
      selected_by_explicit_id_and_sha:
        preflightVerification.selected_by_explicit_id_and_sha,
      selects_latest_profile: preflightVerification.selects_latest_profile,
      recognition_contract_sha256:
        serviceVerification.recognition_contract_sha256,
      authority_grant_contract_sha256:
        serviceVerification.authority_grant_contract_sha256,
    },
    red_path_result: {
      result: 'pass',
      artifact_identity_expected_sha256_supplied:
        serviceVerification.artifact_identity_expected_sha256_supplied,
      expected_artifact_body_sha256:
        serviceVerification.expected_artifact_body_sha256,
      artifact_identity_sha256_matched:
        serviceVerification.artifact_identity_sha256_matched,
      source_preflight_identity_bound_to_expected_artifact_sha256:
        serviceVerification.source_preflight_identity_bound_to_expected_artifact_sha256,
      signed_receipt_envelope_identity_bound_to_expected_artifact_sha256:
        serviceVerification.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256,
      verification_scope: serviceVerification.verification_scope,
      proof_ran_while_active_root_live: statusBefore.active === true,
      active_root_bound_preflight_verified: preflightVerification.verified === true,
      disposable_service_started: serviceProof.service_boundary.runtime_service_started,
      local_disposable_child_process_only:
        serviceProof.service_boundary.service_process_boundary === 'local-jsonl-child-process',
      persistent_runtime_config_written:
        serviceProof.service_boundary.persistent_runtime_config_written,
      live_probing: serviceVerification.live_probing,
      baseline_recognized_write_boarded_inside_disposable_service:
        serviceVerification.recognized_write_boarded,
      baseline_recognized_state_append_count:
        serviceVerification.recognized_write_state_append_count,
      recognition_refusals_before_mutation:
        serviceVerification.all_recognition_refusals_before_mutation,
      authority_grant_refusals_before_consumption_and_mutation:
        serviceVerification.all_authority_refusals_before_consumption_and_mutation,
      same_process_signed_payload_replay_refused:
        serviceVerification.same_process_signed_payload_replay_refused,
      restart_consumed_authority_grant_refused:
        serviceVerification.restart_consumed_authority_grant_refused,
      recognition_refusal_state_append_count:
        serviceProof.marker.recognition_refusal_state_append_count,
      authority_refusal_state_append_count:
        serviceProof.marker.authority_refusal_state_append_count,
      replay_refusal_state_append_count:
        serviceProof.marker.replay_refusal_state_append_count,
      partial_commit_state_append_count:
        serviceProof.marker.partial_commit_state_append_count,
      state_append_after_grant_commit_burn_observed:
        serviceVerification.state_append_after_grant_commit_burn_observed,
      metadata_partial_commit_burn_observed:
        serviceVerification.metadata_partial_commit_burn_observed,
      store_and_anchor_rollback_refused_while_witness_ahead:
        serviceVerification.store_and_anchor_rollback_refused_while_witness_ahead,
      store_anchor_and_witness_joint_rollback_detection:
        serviceVerification.store_anchor_and_witness_joint_rollback_detection,
      joint_rollback_reopened_authority_grant_reuse:
        serviceVerification.joint_rollback_reopened_authority_grant_reuse,
      authority_grant_supplied_by_agent:
        serviceProof.service_config_provenance.authority_grant_supplied_by_agent,
      recognition_rule_supplied_by_agent:
        serviceProof.service_config_provenance.recognition_rule_supplied_by_agent,
      recognition_refusal_case_count:
        serviceVerification.recognition_refusal_case_count,
      authority_refusal_case_count:
        serviceVerification.authority_refusal_case_count,
      recognition_refusal_taxonomy_sha256:
        serviceVerification.recognition_refusal_taxonomy_sha256,
      authority_refusal_taxonomy_sha256:
        serviceVerification.authority_refusal_taxonomy_sha256,
      fixture_rightful_issuance_path_evidenced:
        serviceVerification.fixture_rightful_issuance_path_evidenced,
      rightful_issuance_proven: serviceVerification.rightful_issuance_proven,
      portable_rightful_issuance_proven:
        serviceVerification.portable_rightful_issuance_proven,
      live_authority_proven: false,
      production_rightful_issuance_proven:
        serviceVerification.production_rightful_issuance_proven,
      current_machine_governance_proven:
        serviceVerification.current_machine_governance_proven,
      consequence_lifecycle_closed:
        serviceVerification.consequence_lifecycle_closed,
    },
    recognition_refusal_cases: serviceProof.refusal_cases.map((item) => ({
      case_id: item.case_id,
      reason_code: item.reason_code,
      refused_before_mutation:
        item.service_write_accepted === false && item.state_entry_count_delta === 0,
    })),
    authority_refusal_cases: serviceProof.authority_refusal_cases.map((item) => ({
      case_id: item.case_id,
      reason_code: item.reason_code,
      refused_before_consumption_and_mutation:
        item.service_write_accepted === false &&
        item.state_entry_count_delta === 0 &&
        item.consumed_authority_grant_count === 0,
    })),
    artifact_hashes: {
      preflight_report_sha256: preflightReportSha256,
      service_proof_report_sha256: serviceProofReportSha256,
      service_artifact_body_sha256: serviceArtifact.integrity.body_sha256,
      service_verification_sha256: serviceVerificationSha256,
      status_before_sha256: sha256Canonical(beforeSummary),
      status_after_sha256: sha256Canonical(afterSummary),
      status_final_sha256: sha256Canonical(finalSummary),
      run_transcript_sha256: sha256Canonical({
        preflight_report_sha256: preflightReportSha256,
        preflight_artifact_body_sha256: preflightArtifact.integrity.body_sha256,
        service_proof_report_sha256: serviceProofReportSha256,
        service_artifact_body_sha256: serviceArtifact.integrity.body_sha256,
        service_verification_sha256: serviceVerificationSha256,
        status_before_sha256: sha256Canonical(beforeSummary),
        status_after_sha256: sha256Canonical(afterSummary),
        status_final_sha256: sha256Canonical(finalSummary),
      }),
    },
    exact_claim: 'local active persistent profile red-path refusal before mutation',
    non_claims: [
      'not current-machine governance generally',
      'not live, portable, or production rightful issuance',
      'not consequence lifecycle closure',
      'not production authority',
      'not public external attestation',
      'not enterprise readiness',
    ],
    wrapper_note:
      'fresh runner-generated local red-path evidence; source report stays private unless separately authorized',
    failures: [],
  };
  assertActivePersistentProfileRedPathRefusalReport(report);
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return report;
}

export function writeActivePersistentProfileRedPathRefusalReport({
  report,
  outputPath,
  activationRoot,
}) {
  assertActivePersistentProfileRedPathRefusalReport(report);
  if (!outputPath || typeof outputPath !== 'string') {
    throw new Error('active persistent red-path refusal report output path is required');
  }
  assertActivePersistentProfileLiveReportOutputPath({ outputPath, activationRoot });
  assertOutputAbsent(outputPath, 'active persistent red-path refusal report output');
  mkdirSync(dirname(outputPath), { recursive: true, mode: 0o700 });
  const output = `${JSON.stringify(report, null, 2)}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  writeFileSync(outputPath, output, { mode: 0o600, flag: 'wx' });
  return sha256hex(output);
}

export function runActivePersistentProfileCloseoutRefusal({
  activationRoot,
  expectedProfile,
  profileId = 'protected-records-runtime-fixture-profile',
  profileSha256 = ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
  proofTarget,
  closedAt,
  reason = 'operator_closeout',
  nowEpoch = Math.floor(Date.now() / 1000),
  allowNamedLiveRoot = false,
  expectedLiveRoot,
} = {}) {
  if (!proofTarget || typeof proofTarget !== 'string') {
    throw new Error('active persistent closeout refusal proof target is required');
  }
  assertLifecycleFixtureProfileBinding({ profileId, profileSha256 });
  assertActivePersistentProfileLiveReportOutputPath({
    outputPath: proofTarget,
    activationRoot,
  });
  assertOutputAbsent(proofTarget, 'active persistent closeout refusal proof target');
  const statusBefore = inspectActivePersistentProfileLiveStatus({
    activationRoot,
    nowEpoch,
    allowNamedLiveRoot,
    expectedLiveRoot,
  });
  const closeout = closeActivePersistentProfileLiveInstallation({
    activationRoot,
    closedAt,
    reason,
    nowEpoch,
    allowNamedLiveRoot,
    expectedLiveRoot,
  });
  const statusAfter = inspectActivePersistentProfileLiveStatus({
    activationRoot,
    nowEpoch,
    allowNamedLiveRoot,
    expectedLiveRoot,
  });

  let exitCode = 0;
  let stdout = '';
  let stderr = '';
  try {
    runProtectedRecordsActivePersistentProfileActionCrossing({
      activationRoot,
      expectedProfile,
      profileId,
      profileSha256,
      proofTarget,
      nowEpoch: nowEpoch + 1,
      allowNamedLiveRoot,
      expectedLiveRoot,
    });
  } catch (err) {
    const expectedRefusal = 'active persistent action crossing requires an active unexpired explicit root';
    if (!String(err?.message || '').includes(expectedRefusal)) {
      throw new Error('active persistent closeout refusal probe failed for an unexpected reason');
    }
    exitCode = 1;
    stderr = `ERROR: ${expectedRefusal}\n`;
  }
  const targetWritten = existsSync(proofTarget);
  if (exitCode === 0 || targetWritten === true) {
    throw new Error('active persistent closeout refusal probe did not fail closed');
  }
  const stdoutSha256 = sha256hex(stdout);
  const stderrSha256 = sha256hex(stderr);
  const beforeSummary = statusLifecycleSummary(statusBefore);
  const afterSummary = statusLifecycleSummary(statusAfter, { includeInstallSafety: true });
  const report = {
    proof_report_type: 'zlar-active-persistent-profile-closeout-refusal-proof-report-v1',
    generated_at: isoFromEpoch(nowEpoch + 1),
    authority_packet: {
      packet_sha256: lifecycleAuthorityPacketSha256(),
    },
    scratch_dir: '<launcher-owned-closeout-refusal-proof-scratch>',
    closeout: {
      closed_at: closeout.closed_at,
      status: closeout.status,
      active: closeout.active,
      closeout_reactivation_allowed: closeout.closeout_reactivation_allowed,
    },
    before_status: beforeSummary,
    after_status: afterSummary,
    refused_after_closeout_probe: {
      attempted_action_class: 'records.write',
      exit_code: exitCode,
      stdout_sha256: stdoutSha256,
      stderr_sha256: stderrSha256,
      stderr_redacted_snippet: safeReportMessage(
        stderr.trim().slice(0, 240),
        'ERROR: active persistent action crossing refused after closeout'
      ),
      target_written: targetWritten,
      refusal_before_target_mutation: targetWritten === false,
    },
    artifact_hashes: {
      status_before_sha256: sha256Canonical(beforeSummary),
      closeout_sha256: closeout.manifest_sha256,
      status_after_sha256: sha256Canonical(afterSummary),
      refused_stdout_sha256: stdoutSha256,
      refused_stderr_sha256: stderrSha256,
      refused_exit_sha256: sha256Canonical({
        exit_code: exitCode,
        target_written: targetWritten,
        refusal_before_target_mutation: targetWritten === false,
        stderr_sha256: stderrSha256,
      }),
    },
    exact_claim:
      'closed active persistent profile root refuses subsequent action crossing before mutation',
    non_claims: [
      'not current-machine governance generally',
      'not production authority',
      'not public external attestation',
      'not enterprise readiness',
    ],
    failures: [],
  };
  assertActivePersistentProfileCloseoutRefusalReport(report);
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return report;
}

export function writeActivePersistentProfileCloseoutRefusalReport({
  report,
  outputPath,
  activationRoot,
}) {
  assertActivePersistentProfileCloseoutRefusalReport(report);
  if (!outputPath || typeof outputPath !== 'string') {
    throw new Error('active persistent closeout refusal report output path is required');
  }
  assertActivePersistentProfileLiveReportOutputPath({ outputPath, activationRoot });
  assertOutputAbsent(outputPath, 'active persistent closeout refusal report output');
  mkdirSync(dirname(outputPath), { recursive: true, mode: 0o700 });
  const output = `${JSON.stringify(report, null, 2)}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  writeFileSync(outputPath, output, { mode: 0o600, flag: 'wx' });
  return sha256hex(output);
}

export function buildActivePersistentProfileLifecycleSourceBinding({
  lifecycleReportFile = ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_REPORT_FILE,
  lifecycleReportSha256,
  sourceReports = {},
} = {}) {
  const source = {};
  for (const key of ['install_report', 'green_report', 'red_report', 'closeout_report']) {
    const entry = requireObject(`active persistent lifecycle binding ${key}`, sourceReports[key]);
    const file = basenameLabel(entry.file);
    if (file !== entry.file) {
      throw new Error(`active persistent lifecycle binding ${key} file must be a basename`);
    }
    expectSha(`active persistent lifecycle binding ${key} SHA-256`, entry.sha256);
    source[key] = { file, sha256: entry.sha256 };
  }
  const binding = {
    report_type: PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SOURCE_BINDING_TYPE,
    schema_version: 1,
    evidence_class: ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_EVIDENCE_CLASS,
    lifecycle_report_file: lifecycleReportFile,
    lifecycle_report_sha256: lifecycleReportSha256,
    source_reports: source,
    non_scoring: true,
    current_installation: false,
    product_proof_path_completion: false,
    production_downstream_recognition: false,
  };
  assertActivePersistentProfileLifecycleSourceBinding(binding);
  return binding;
}

export function assertActivePersistentProfileLifecycleSourceBinding(binding) {
  assertExactKeys('active persistent lifecycle source binding', binding, [
    'current_installation',
    'evidence_class',
    'lifecycle_report_file',
    'lifecycle_report_sha256',
    'non_scoring',
    'product_proof_path_completion',
    'production_downstream_recognition',
    'report_type',
    'schema_version',
    'source_reports',
  ]);
  if (
    binding.report_type !==
      PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SOURCE_BINDING_TYPE ||
    binding.schema_version !== 1 ||
    binding.evidence_class !== ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_EVIDENCE_CLASS ||
    binding.lifecycle_report_file !== ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_REPORT_FILE ||
    binding.non_scoring !== true ||
    binding.current_installation !== false ||
    binding.product_proof_path_completion !== false ||
    binding.production_downstream_recognition !== false
  ) {
    throw new Error('active persistent lifecycle source binding boundary drifted');
  }
  expectSha(
    'active persistent lifecycle source binding lifecycle report SHA-256',
    binding.lifecycle_report_sha256
  );
  assertExactKeys('active persistent lifecycle source binding source reports', binding.source_reports, [
    'closeout_report',
    'green_report',
    'install_report',
    'red_report',
  ]);
  for (const [key, entry] of Object.entries(binding.source_reports)) {
    assertExactKeys(`active persistent lifecycle source binding ${key}`, entry, [
      'file',
      'sha256',
    ]);
    if (entry.file !== basenameLabel(entry.file)) {
      throw new Error(`active persistent lifecycle source binding ${key} file must be a basename`);
    }
    expectSha(`active persistent lifecycle source binding ${key} SHA-256`, entry.sha256);
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(binding));
  return true;
}

export function writeActivePersistentProfileLifecycleSourceBinding({
  binding,
  outputPath,
  activationRoot,
}) {
  assertActivePersistentProfileLifecycleSourceBinding(binding);
  if (!outputPath || typeof outputPath !== 'string') {
    throw new Error('active persistent lifecycle source binding output path is required');
  }
  if (activationRoot) {
    assertActivePersistentProfileLiveReportOutputPath({ outputPath, activationRoot });
  }
  assertOutputAbsent(outputPath, 'active persistent lifecycle source binding output');
  mkdirSync(dirname(outputPath), { recursive: true, mode: 0o700 });
  const output = `${JSON.stringify(binding, null, 2)}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  writeFileSync(outputPath, output, { mode: 0o600, flag: 'wx' });
  return sha256hex(output);
}

export function runActivePersistentProfileLifecycleEvidence({
  activationRoot,
  outputDir,
  profilePath = ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
  runtimeProfileId = PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  runtimeProfileSha256 = ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
  expiresAt,
  nowEpoch = Math.floor(Date.now() / 1000),
  allowNamedLiveRoot = false,
  expectedLiveRoot,
  replaceClosedRoot = false,
} = {}) {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
    'Protected records active persistent profile lifecycle evidence run'
  );
  if (!activationRoot || typeof activationRoot !== 'string') {
    throw new Error('active persistent lifecycle activation root is required');
  }
  if (!outputDir || typeof outputDir !== 'string') {
    throw new Error('active persistent lifecycle output directory is required');
  }
  const closeoutEpoch = nowEpoch + 180;
  const expiryMillis = Date.parse(expiresAt);
  if (!Number.isFinite(expiryMillis) || Math.floor(expiryMillis / 1000) <= closeoutEpoch) {
    throw new Error('active persistent lifecycle expiry must remain future through closeout');
  }
  assertLifecycleFixtureProfileBinding({
    profileId: 'protected-records-runtime-fixture-profile',
    profileSha256: runtimeProfileSha256,
  });
  const profile = readProfileFile(profilePath);
  const files = {
    install: join(outputDir, 'active-persistent-live-installation-report.json'),
    green: join(outputDir, 'active-persistent-green-action-crossing-report.json'),
    red: join(outputDir, 'active-persistent-red-path-refusal-report.json'),
    closeout: join(outputDir, 'active-persistent-closeout-refusal-report.json'),
    lifecycle: join(outputDir, ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_REPORT_FILE),
    binding: join(outputDir, ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SOURCE_BINDING_FILE),
    greenTarget: join(outputDir, 'green-records-write-target.jsonl'),
    closeoutProbeTarget: join(outputDir, 'post-closeout-records-write-target.jsonl'),
  };
  for (const [label, path] of Object.entries(files)) {
    assertActivePersistentProfileLiveReportOutputPath({
      outputPath: path,
      activationRoot,
    });
    assertOutputAbsent(path, `active persistent lifecycle ${label}`);
  }
  mkdirSync(outputDir, { recursive: true, mode: 0o700 });

  const installReport = runActivePersistentProfileLiveInstallation({
    activationRoot,
    profile,
    profileSource: profilePath,
    runtimeProfileId,
    runtimeProfileSha256,
    expiresAt,
    nowEpoch,
    allowNamedLiveRoot,
    expectedLiveRoot,
    replaceClosedRoot,
  });
  writeActivePersistentProfileLiveReport({
    report: installReport,
    outputPath: files.install,
    activationRoot,
  });

  const greenReport = runProtectedRecordsActivePersistentProfileActionCrossing({
    activationRoot,
    expectedProfile: profile,
    profileId: 'protected-records-runtime-fixture-profile',
    profileSha256: runtimeProfileSha256,
    proofTarget: files.greenTarget,
    nowEpoch: nowEpoch + 60,
    allowNamedLiveRoot,
    expectedLiveRoot,
  });
  writeProtectedRecordsActivePersistentProfileActionCrossingReport({
    report: greenReport,
    outputPath: files.green,
    activationRoot,
  });

  const redReport = runActivePersistentProfileRedPathRefusal({
    activationRoot,
    expectedProfile: profile,
    profileId: 'protected-records-runtime-fixture-profile',
    profileSha256: runtimeProfileSha256,
    nowEpoch: nowEpoch + 120,
    allowNamedLiveRoot,
    expectedLiveRoot,
  });
  writeActivePersistentProfileRedPathRefusalReport({
    report: redReport,
    outputPath: files.red,
    activationRoot,
  });

  const closeoutReport = runActivePersistentProfileCloseoutRefusal({
    activationRoot,
    expectedProfile: profile,
    profileId: 'protected-records-runtime-fixture-profile',
    profileSha256: runtimeProfileSha256,
    proofTarget: files.closeoutProbeTarget,
    closedAt: isoFromEpoch(closeoutEpoch),
    nowEpoch: closeoutEpoch,
    allowNamedLiveRoot,
    expectedLiveRoot,
  });
  writeActivePersistentProfileCloseoutRefusalReport({
    report: closeoutReport,
    outputPath: files.closeout,
    activationRoot,
  });

  const expectedInputReportHashes = {
    install_report_sha256: sha256File(files.install, 'active persistent lifecycle install report'),
    green_report_sha256: sha256File(files.green, 'active persistent lifecycle green report'),
    red_report_sha256: sha256File(files.red, 'active persistent lifecycle red report'),
    closeout_report_sha256: sha256File(files.closeout, 'active persistent lifecycle closeout report'),
  };
  const lifecycleReport = buildActivePersistentProfileLifecycleReportFromFiles({
    installReportPath: files.install,
    greenReportPath: files.green,
    redReportPath: files.red,
    closeoutReportPath: files.closeout,
    expectedInputReportHashes,
  });
  const lifecycleReportSha256 = writeActivePersistentProfileLifecycleReport({
    report: lifecycleReport,
    outputPath: files.lifecycle,
    activationRoot,
  });
  const lifecycleFileSha256 = sha256File(
    files.lifecycle,
    'active persistent lifecycle report'
  );
  if (lifecycleReportSha256 !== lifecycleFileSha256) {
    throw new Error('active persistent lifecycle report file hash drifted');
  }
  const sourceBinding = buildActivePersistentProfileLifecycleSourceBinding({
    lifecycleReportSha256: lifecycleFileSha256,
    sourceReports: {
      install_report: {
        file: basename(files.install),
        sha256: expectedInputReportHashes.install_report_sha256,
      },
      green_report: {
        file: basename(files.green),
        sha256: expectedInputReportHashes.green_report_sha256,
      },
      red_report: {
        file: basename(files.red),
        sha256: expectedInputReportHashes.red_report_sha256,
      },
      closeout_report: {
        file: basename(files.closeout),
        sha256: expectedInputReportHashes.closeout_report_sha256,
      },
    },
  });
  const sourceBindingSha256 = writeActivePersistentProfileLifecycleSourceBinding({
    binding: sourceBinding,
    outputPath: files.binding,
    activationRoot,
  });
  const result = {
    report_type: PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_RUNNER_RESULT_TYPE,
    result: 'pass',
    generated_at: lifecycleReport.generated_at,
    activation_root_label: lifecycleReport.lifecycle.activation_root_label,
    named_live_root: installReport.named_live_root,
    action_class: 'records.write',
    closed_root_replacement_authorized:
      installReport.preinstall_status.closed_root_replacement_authorized === true,
    files: {
      install_report: {
        file: basename(files.install),
        sha256: expectedInputReportHashes.install_report_sha256,
      },
      green_report: {
        file: basename(files.green),
        sha256: expectedInputReportHashes.green_report_sha256,
      },
      red_report: {
        file: basename(files.red),
        sha256: expectedInputReportHashes.red_report_sha256,
      },
      closeout_report: {
        file: basename(files.closeout),
        sha256: expectedInputReportHashes.closeout_report_sha256,
      },
      lifecycle_report: {
        file: basename(files.lifecycle),
        sha256: lifecycleFileSha256,
      },
      source_binding: {
        file: basename(files.binding),
        sha256: sourceBindingSha256,
      },
    },
    proof_targets: {
      green_records_write: {
        file: basename(files.greenTarget),
        written: existsSync(files.greenTarget),
      },
      post_closeout_records_write: {
        file: basename(files.closeoutProbeTarget),
        written: existsSync(files.closeoutProbeTarget),
      },
    },
    claim_boundary: {
      local_active_persistent_profile_lifecycle_verified: true,
      readiness_source_binding_written: true,
      fixture_rightful_issuance_path_evidenced:
        lifecycleReport.claim_boundary.fixture_rightful_issuance_path_evidenced,
      fresh_service_artifact_identity_pins_matched:
        lifecycleReport.lifecycle.fresh_service_artifact_identity_pins_matched,
      fresh_source_preflight_identities_bound:
        lifecycleReport.lifecycle.fresh_source_preflight_identities_bound,
      fresh_signed_receipt_envelope_identities_bound:
        lifecycleReport.lifecycle.fresh_signed_receipt_envelope_identities_bound,
      rightful_issuance_proven: false,
      portable_rightful_issuance_proven: false,
      live_authority_proven: false,
      consequence_lifecycle_closed: false,
      current_machine_governance_general: false,
      raw_codex_or_developer_tool_governance: false,
      browser_computer_use_mcp_shell_network_or_all_surface_governance: false,
      production_downstream_recognition: false,
      production_authority: false,
      enterprise_readiness: false,
      public_external_attestation: false,
      side_door_closure: false,
    },
    non_claims: [...ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_NON_CLAIMS],
  };
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(result));
  return result;
}

export function assertActivePersistentProfileLifecycleReport(report) {
  assertExactKeys('active persistent lifecycle report', report, [
    'claim_boundary',
    'evidence_model',
    'generated_at',
    'lifecycle',
    'non_claims',
    'report_type',
    'result',
    'safe_claim',
    'schema_version',
    'selected_profile',
    'supplied_reports',
  ]);
  if (
    report.report_type !== PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_REPORT_TYPE ||
    report.schema_version !== 1 ||
    report.evidence_model !== 'supplied-active-persistent-profile-lifecycle-evidence-verification' ||
    report.result !== 'pass' ||
    report.safe_claim !== ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SAFE_CLAIM
  ) {
    throw new Error('active persistent lifecycle top-level drifted');
  }
  parseIsoMillis('active persistent lifecycle generated_at', report.generated_at);

  const supplied = requireObject('active persistent lifecycle supplied reports', report.supplied_reports);
  assertExactKeys('active persistent lifecycle supplied reports', supplied, [
    'expected_hashes_bound',
    'hashes',
    'labels',
  ]);
  if (typeof supplied.expected_hashes_bound !== 'boolean') {
    throw new Error('active persistent lifecycle expected_hashes_bound drifted');
  }
  assertExactKeys('active persistent lifecycle supplied report labels', supplied.labels, [
    'closeout_report',
    'green_report',
    'install_report',
    'red_report',
  ]);
  for (const label of Object.values(supplied.labels)) {
    expectString('active persistent lifecycle supplied report label', label);
  }
  assertExactKeys('active persistent lifecycle supplied report hashes', supplied.hashes, [
    'closeout_report_sha256',
    'green_report_sha256',
    'install_report_sha256',
    'red_report_sha256',
  ]);
  for (const [key, value] of Object.entries(supplied.hashes)) {
    expectSha(`active persistent lifecycle supplied report ${key}`, value);
  }

  const selected = requireObject('active persistent lifecycle selected profile', report.selected_profile);
  if (
    selected.profile_id !== 'protected-records-runtime-fixture-profile' ||
    selected.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    selected.runtime_profile_sha256 !== ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256 ||
    selected.selected_by_explicit_id_and_sha !== true ||
    selected.selects_latest_profile !== false
  ) {
    throw new Error('active persistent lifecycle selected profile drifted');
  }

  const lifecycle = requireObject('active persistent lifecycle', report.lifecycle);
  if (
    ![
      '<named-active-persistent-profile-root>',
      '<surrogate-active-persistent-profile-root>',
    ].includes(lifecycle.activation_root_label) ||
    lifecycle.active_after_install !== true ||
    lifecycle.green_action_class !== 'records.write' ||
    !Number.isInteger(lifecycle.green_active_root_status_epoch) ||
    !Number.isInteger(lifecycle.red_active_root_status_epoch) ||
    lifecycle.green_local_service_authority_evaluation_epoch !==
      PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH ||
    lifecycle.red_local_service_authority_evaluation_epoch !==
      PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH ||
    lifecycle.fixture_authority_evaluation_epoch_pinned !== true ||
    lifecycle.action_time_and_fixture_authority_time_domains_separate !== true ||
    lifecycle.fresh_service_artifact_identity_pins_matched !== true ||
    lifecycle.fresh_source_preflight_identities_bound !== true ||
    lifecycle.fresh_signed_receipt_envelope_identities_bound !== true ||
    lifecycle.green_recognized_write_delta !== 1 ||
    lifecycle.green_refusal_delta_total !== 0 ||
    lifecycle.red_recognition_refusal_case_count !== 18 ||
    lifecycle.red_authority_refusal_case_count !== 5 ||
    lifecycle.red_recognition_refusal_state_append_count !== 0 ||
    lifecycle.red_authority_refusal_state_append_count !== 0 ||
    lifecycle.red_replay_refusal_state_append_count !== 0 ||
    lifecycle.red_same_process_signed_payload_replay_refused !== true ||
    lifecycle.red_restart_consumed_authority_grant_refused !== true ||
    lifecycle.red_state_append_after_grant_commit_burn_observed !== true ||
    lifecycle.red_metadata_partial_commit_burn_observed !== true ||
    lifecycle.red_store_and_anchor_rollback_refused_while_witness_ahead !== true ||
    lifecycle.red_store_anchor_and_witness_joint_rollback_detection !== false ||
    lifecycle.red_joint_rollback_reopened_authority_grant_reuse !== true ||
    lifecycle.red_authority_grant_supplied_by_agent !== false ||
    lifecycle.red_recognition_rule_supplied_by_agent !== false ||
    lifecycle.fixture_rightful_issuance_path_evidenced !== false ||
    lifecycle.closeout_status !== 'closed_inert_evidence' ||
    lifecycle.closed_root_active_after_closeout !== false ||
    lifecycle.closed_root_safe_for_install !== false ||
    lifecycle.refused_after_closeout_exit_code === 0 ||
    lifecycle.refused_after_closeout_target_written !== false
  ) {
    throw new Error('active persistent lifecycle evidence drifted');
  }
  for (const key of ['installed_at', 'expires_at', 'closeout_at']) {
    parseIsoMillis(`active persistent lifecycle ${key}`, lifecycle[key]);
  }

  const boundary = requireObject('active persistent lifecycle claim boundary', report.claim_boundary);
  for (const key of [
    'local_active_persistent_profile_lifecycle_verified',
    'install_and_readback_verified',
    'green_path_governed_action_crossing_verified',
    'red_path_refusal_before_mutation_verified',
    'closeout_refusal_before_mutation_verified',
  ]) {
    expectBool(`active persistent lifecycle claim ${key}`, boundary[key], true);
  }
  expectBool(
    'active persistent lifecycle claim fixture_rightful_issuance_path_evidenced',
    boundary.fixture_rightful_issuance_path_evidenced,
    false,
  );
  if (typeof boundary.expected_input_report_hashes_bound !== 'boolean') {
    throw new Error('active persistent lifecycle expected_input_report_hashes_bound drifted');
  }
  for (const key of [
    'current_machine_governance_general',
    'raw_codex_or_developer_tool_governance',
    'browser_computer_use_mcp_shell_network_or_all_surface_governance',
    'live_always_on_runtime_service_governance',
    'rightful_issuance_proven',
    'portable_rightful_issuance_proven',
    'live_authority_proven',
    'consequence_lifecycle_closed',
    'production_downstream_recognition',
    'production_authority',
    'enterprise_readiness',
    'public_external_attestation',
    'sovereign_recognition',
    'side_door_closure',
    'absolute_human_intention',
  ]) {
    expectBool(`active persistent lifecycle non-claim ${key}`, boundary[key], false);
  }
  if (
    !Array.isArray(report.non_claims) ||
    report.non_claims.length !== ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_NON_CLAIMS.length
  ) {
    throw new Error('active persistent lifecycle non-claims drifted');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return true;
}

export function writeActivePersistentProfileLifecycleReport({ report, outputPath, activationRoot }) {
  assertActivePersistentProfileLifecycleReport(report);
  if (!outputPath || typeof outputPath !== 'string') {
    throw new Error('active persistent lifecycle report output path is required');
  }
  if (activationRoot) {
    assertActivePersistentProfileLiveReportOutputPath({
      outputPath,
      activationRoot,
    });
  }
  if (existsSync(outputPath)) {
    throw new Error('active persistent lifecycle report output path already exists');
  }
  mkdirSync(dirname(outputPath), { recursive: true, mode: 0o700 });
  const output = `${JSON.stringify(report, null, 2)}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  writeFileSync(outputPath, output, { mode: 0o600, flag: 'wx' });
  return sha256hex(output);
}

export function formatActivePersistentProfileLifecycleReport(report) {
  assertActivePersistentProfileLifecycleReport(report);
  const lines = [
    'ZLAR Active Persistent Profile Lifecycle Evidence v1',
    `result=${report.result}`,
    `selected_profile_id=${report.selected_profile.profile_id}`,
    `selected_profile_sha256=${report.selected_profile.runtime_profile_sha256}`,
    `selects_latest=${report.selected_profile.selects_latest_profile}`,
    `expires_at=${report.lifecycle.expires_at}`,
    `install_and_readback_verified=${report.claim_boundary.install_and_readback_verified}`,
    `green_path_governed_action_crossing_verified=${report.claim_boundary.green_path_governed_action_crossing_verified}`,
    `green_recognized_write_delta=${report.lifecycle.green_recognized_write_delta}`,
    `evaluation_time_boundary: green_action_epoch=${report.lifecycle.green_active_root_status_epoch}; red_action_epoch=${report.lifecycle.red_active_root_status_epoch}; fixture_authority_epoch=${report.lifecycle.green_local_service_authority_evaluation_epoch}; fixture_epoch_pinned=${report.lifecycle.fixture_authority_evaluation_epoch_pinned}; fixture_epoch_is_not_live_authority_time=true`,
    `red_path_refusal_before_mutation_verified=${report.claim_boundary.red_path_refusal_before_mutation_verified}`,
    `red_refusal_cases: recognition=${report.lifecycle.red_recognition_refusal_case_count}; authority_grant=${report.lifecycle.red_authority_refusal_case_count}; recognition_state_delta=${report.lifecycle.red_recognition_refusal_state_append_count}; authority_state_delta=${report.lifecycle.red_authority_refusal_state_append_count}`,
    `red_replay: same_process_signed_payload_refused=${report.lifecycle.red_same_process_signed_payload_replay_refused}; restart_consumed_grant_refused=${report.lifecycle.red_restart_consumed_authority_grant_refused}`,
    `red_storage_boundaries: state_append_burn=${report.lifecycle.red_state_append_after_grant_commit_burn_observed}; metadata_burn=${report.lifecycle.red_metadata_partial_commit_burn_observed}; witness_ahead_refusal=${report.lifecycle.red_store_and_anchor_rollback_refused_while_witness_ahead}; joint_rollback_detection=${report.lifecycle.red_store_anchor_and_witness_joint_rollback_detection}; joint_rollback_reopened_grant_reuse=${report.lifecycle.red_joint_rollback_reopened_authority_grant_reuse}`,
    `fixture_rightful_issuance_path_evidenced=${report.claim_boundary.fixture_rightful_issuance_path_evidenced}; rightful_issuance_proven=${report.claim_boundary.rightful_issuance_proven}; live_authority_proven=${report.claim_boundary.live_authority_proven}; consequence_lifecycle_closed=${report.claim_boundary.consequence_lifecycle_closed}`,
    `closeout_refusal_before_mutation_verified=${report.claim_boundary.closeout_refusal_before_mutation_verified}`,
    `closeout_status=${report.lifecycle.closeout_status}`,
    `refused_after_closeout_target_written=${report.lifecycle.refused_after_closeout_target_written}`,
    `expected_input_report_hashes_bound=${report.claim_boundary.expected_input_report_hashes_bound}`,
    `current_machine_governance_general=${report.claim_boundary.current_machine_governance_general}`,
    `production_downstream_recognition=${report.claim_boundary.production_downstream_recognition}`,
    'Non-claims:',
  ];
  for (const claim of report.non_claims) {
    lines.push(`- ${claim}`);
  }
  const output = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  return output;
}

export function formatActivePersistentProfileLifecycleRunResult(result) {
  if (
    !result ||
    result.report_type !== PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_RUNNER_RESULT_TYPE ||
    result.result !== 'pass'
  ) {
    throw new Error('active persistent lifecycle runner result drifted');
  }
  const lines = [
    'ZLAR Active Persistent Profile Lifecycle Runner v1',
    `result=${result.result}`,
    `activation_root=${result.activation_root_label}`,
    `named_live_root=${result.named_live_root}`,
    `action_class=${result.action_class}`,
    `closed_root_replacement_authorized=${result.closed_root_replacement_authorized}`,
    `lifecycle_report=${result.files.lifecycle_report.file}`,
    `lifecycle_report_sha256=${result.files.lifecycle_report.sha256}`,
    `source_binding=${result.files.source_binding.file}`,
    `source_binding_sha256=${result.files.source_binding.sha256}`,
    `green_target_written=${result.proof_targets.green_records_write.written}`,
    `post_closeout_target_written=${result.proof_targets.post_closeout_records_write.written}`,
    `fixture_rightful_issuance_path_evidenced=${result.claim_boundary.fixture_rightful_issuance_path_evidenced}; rightful_issuance_proven=${result.claim_boundary.rightful_issuance_proven}; live_authority_proven=${result.claim_boundary.live_authority_proven}; consequence_lifecycle_closed=${result.claim_boundary.consequence_lifecycle_closed}`,
    `current_machine_governance_general=${result.claim_boundary.current_machine_governance_general}`,
    `production_downstream_recognition=${result.claim_boundary.production_downstream_recognition}`,
    `enterprise_readiness=${result.claim_boundary.enterprise_readiness}`,
    `public_external_attestation=${result.claim_boundary.public_external_attestation}`,
  ];
  const output = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  return output;
}

export {
  PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_INSTALLATION_REPORT_TYPE,
  PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_TYPE,
};
