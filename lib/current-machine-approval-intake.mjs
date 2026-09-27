import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { canonicalize } from './canonicalize.mjs';
import {
  assertCurrentMachineApprovalPacketVerification,
  assertNoUnsafeCurrentMachineApprovalPacketText,
} from './current-machine-approval-packet.mjs';

export const CURRENT_MACHINE_APPROVAL_INTAKE_TYPE =
  'zlar-current-machine-approval-intake-v1';

export const CURRENT_MACHINE_APPROVAL_INTAKE_SAFE_CLAIM_CEILING =
  'ZLAR can run the current-machine approval packet verifier on an explicit packet and decide whether a future install/config authority request may be prepared. This intake does not install, activate, write configuration, execute live hooks, mint receipts, or prove current-machine governance.';

export const CURRENT_MACHINE_APPROVAL_INTAKE_NON_CLAIMS = Object.freeze([
  'This intake is not installation or activation.',
  'This intake does not request or grant install/config authority.',
  'This intake does not write hook, profile, user, service, or machine configuration.',
  'This intake does not touch secrets or signing material.',
  'This intake does not use Telegram.',
  'This intake does not prove current-machine governance, live hook execution, live receipt emission, or live downstream recognition.',
]);

const DEFAULT_ZLAR_BIN = fileURLToPath(new URL('../bin/zlar', import.meta.url));

const NO_WRITE_BOUNDARY_FIELDS = Object.freeze([
  'install_or_activation_applied',
  'hook_profile_written',
  'user_config_written',
  'machine_config_written',
  'service_started',
  'secrets_or_signing_material_changed',
  'telegram_used',
  'github_settings_changed',
  'website_publication',
  'current_machine_governance_evidence',
  'live_hook_execution_evidence',
  'live_receipt_emission_evidence',
  'live_downstream_recognition_evidence',
  'external_attestation',
]);

const VERIFIED_SECTION_FIELDS = Object.freeze([
  'selected_surface',
  'hook_target',
  'source_target',
  'installer_identity',
  'command_posture',
  'dry_run_plan_identity',
  'authority_request_identity',
  'backup_rollback_requirements',
  'issuer_policy',
  'receipt_path',
  'downstream_refusal_matrix',
  'explicit_non_claims',
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

function assertBoolean(label, value, expected) {
  if (typeof value !== 'boolean') {
    throw new Error(`${label} must be a boolean`);
  }
  if (arguments.length === 3 && value !== expected) {
    throw new Error(`${label} must be ${expected}`);
  }
  return true;
}

function assertString(label, value) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return true;
}

function safeVerifierSummary(text) {
  const summary = String(text || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .join(' ')
    .slice(0, 240);
  if (!summary) {
    return 'current-machine approval packet verification failed';
  }
  try {
    assertNoUnsafeCurrentMachineApprovalPacketText(summary);
    return summary;
  } catch {
    return 'current-machine approval packet verification failed; private path or credential details were suppressed';
  }
}

function sanitizedVerifierCommand(inputKind) {
  return [
    'zlar',
    'current-machine-approval-packet',
    'verify',
    '--input',
    inputKind === 'stdin' ? '-' : '<explicit-packet>',
    '--json',
  ];
}

function noWriteBoundaryFromVerification(verification) {
  return {
    install_or_activation_applied: verification?.install_or_activation_applied === true,
    hook_profile_written: verification?.hook_profile_written === true,
    user_config_written: verification?.user_config_written === true,
    machine_config_written: verification?.machine_config_written === true,
    service_started: verification?.service_started === true,
    secrets_or_signing_material_changed:
      verification?.secrets_or_signing_material_changed === true,
    telegram_used: verification?.telegram_used === true,
    github_settings_changed: verification?.github_settings_changed === true,
    website_publication: verification?.website_publication === true,
    current_machine_governance_evidence:
      verification?.current_machine_governance_evidence === true,
    live_hook_execution_evidence: false,
    live_receipt_emission_evidence: verification?.live_receipt_emission_verified === true,
    live_downstream_recognition_evidence:
      verification?.live_downstream_recognition_evidence === true,
    external_attestation: verification?.external_attestation === true,
  };
}

function falseNoWriteBoundary() {
  return noWriteBoundaryFromVerification(null);
}

function verifiedSectionsFromVerification(verification) {
  return {
    selected_surface: verification.selected_surface === 'claude_code',
    hook_target:
      verification.hook_event === 'PreToolUse' &&
      Boolean(verification.hook_profile_path) &&
      Boolean(verification.hook_command_target) &&
      Boolean(verification.delegation_target),
    source_target:
      Boolean(verification.source_target?.target_commit_sha) &&
      Boolean(verification.source_target?.target_tree_sha) &&
      verification.source_target?.dirty_worktree_allowed === false,
    installer_identity:
      verification.installer_identity?.installer_path === 'install.sh' &&
      Boolean(verification.installer_identity?.installer_git_blob_sha) &&
      Boolean(verification.installer_identity?.installer_sha256),
    command_posture:
      verification.command_posture?.selected_surface === 'claude_code' &&
      verification.command_posture?.single_surface_scope === true &&
      verification.command_posture?.no_machine_helpers === true,
    dry_run_plan_identity:
      verification.dry_run_plan_identity?.plan_type === 'zlar-install-plan-v1' &&
      Boolean(verification.dry_run_plan_identity?.plan_sha256) &&
      verification.dry_run_plan_identity?.no_write_plan === true,
    authority_request_identity:
      verification.authority_request_identity?.authority_request_made === false &&
      verification.authority_request_identity?.single_use === true &&
      verification.authority_request_identity?.replay_guard_required === true,
    backup_rollback_requirements:
      verification.backup_rollback_requirements?.backup_required_before_mutation === true &&
      verification.backup_rollback_requirements?.rollback_plan_required === true,
    issuer_policy:
      Boolean(verification.issuer_id) &&
      Boolean(verification.issuer_kid) &&
      Boolean(verification.policy_id) &&
      Boolean(verification.policy_sha256),
    receipt_path:
      verification.receipt_format === 'zlar-receipt-v1' &&
      Boolean(verification.receipt_path) &&
      verification.recognized_receipt_required_for_boarding === true,
    downstream_refusal_matrix:
      verification.downstream_refuses_before_effect === true &&
      verification.refusal_matrix_complete === true &&
      verification.refusal_reason_count === verification.required_refusal_reason_count,
    explicit_non_claims: Array.isArray(verification.non_claims) && verification.non_claims.length > 0,
  };
}

function falseVerifiedSections() {
  return Object.fromEntries(VERIFIED_SECTION_FIELDS.map((field) => [field, false]));
}

function unverifiedBindingSection() {
  return {
    verification_status: 'unverified',
  };
}

function sameCanonical(left, right) {
  return canonicalize(left) === canonicalize(right);
}

function assertDerivedFromPacketVerification(report) {
  const verification = report.packet_verification;
  assertCurrentMachineApprovalPacketVerification(verification);
  const expectedSections = verifiedSectionsFromVerification(verification);
  const expectedBoundary = noWriteBoundaryFromVerification(verification);
  if (!sameCanonical(report.verified_sections, expectedSections)) {
    throw new Error('Current-machine approval intake verified sections must be derived from packet verification');
  }
  if (!sameCanonical(report.no_write_boundary, expectedBoundary)) {
    throw new Error('Current-machine approval intake no-write boundary must be derived from packet verification');
  }
  const expectedFields = {
    packet_sha256: verification.packet_sha256,
    selected_surface: verification.selected_surface,
    hook_event: verification.hook_event,
    hook_profile_path: verification.hook_profile_path,
    hook_command_target: verification.hook_command_target,
    delegation_target: verification.delegation_target,
    source_target: verification.source_target,
    installer_identity: verification.installer_identity,
    command_posture: verification.command_posture,
    dry_run_plan_identity: verification.dry_run_plan_identity,
    authority_request_identity: verification.authority_request_identity,
    backup_rollback_requirements: verification.backup_rollback_requirements,
    issuer_id: verification.issuer_id,
    issuer_kid: verification.issuer_kid,
    policy_id: verification.policy_id,
    accepted_policy_version: verification.accepted_policy_version,
    receipt_format: verification.receipt_format,
    receipt_path: verification.receipt_path,
    downstream_terminal: verification.downstream_terminal,
    downstream_refuses_before_effect: verification.downstream_refuses_before_effect,
    refusal_matrix_complete: verification.refusal_matrix_complete,
    refusal_reason_count: verification.refusal_reason_count,
    human_authority_required_before_install_or_config:
      verification.human_authority_required_before_install_or_config,
  };
  for (const [field, expected] of Object.entries(expectedFields)) {
    if (!sameCanonical(report[field], expected)) {
      throw new Error(`Current-machine approval intake ${field} must match packet verification`);
    }
  }
}

function buildAllowedReport(verification, inputKind) {
  assertCurrentMachineApprovalPacketVerification(verification);
  const verifiedSections = verifiedSectionsFromVerification(verification);
  const noWriteBoundary = noWriteBoundaryFromVerification(verification);
  const authorityRequestAllowed =
    verification.verified === true &&
    verification.packet_complete === true &&
    verification.approval_packet_complete_before_authority_request === true &&
    verification.human_authority_required_before_install_or_config === true &&
    Object.values(verifiedSections).every(Boolean) &&
    Object.values(noWriteBoundary).every((value) => value === false);

  const report = {
    intake_type: CURRENT_MACHINE_APPROVAL_INTAKE_TYPE,
    intake_status: authorityRequestAllowed
      ? 'allowed_to_prepare_human_request_only'
      : 'refused_before_authority_request',
    verifier_command: sanitizedVerifierCommand(inputKind),
    verifier_exit_code: 0,
    verifier_verified: true,
    verifier_packet_complete: true,
    authority_request_kind: 'future_install_or_configuration_human_authority_request',
    authority_request_allowed: authorityRequestAllowed,
    authority_request_made: false,
    refusal_reason_code: authorityRequestAllowed ? 'none' : 'packet_boundary_incomplete',
    refusal_summary: authorityRequestAllowed
      ? 'none'
      : 'verified packet did not satisfy every pre-authority boundary',
    packet_sha256: verification.packet_sha256,
    packet_verification: verification,
    verified_sections: verifiedSections,
    selected_surface: verification.selected_surface,
    hook_event: verification.hook_event,
    hook_profile_path: verification.hook_profile_path,
    hook_command_target: verification.hook_command_target,
    delegation_target: verification.delegation_target,
    source_target: verification.source_target,
    installer_identity: verification.installer_identity,
    command_posture: verification.command_posture,
    dry_run_plan_identity: verification.dry_run_plan_identity,
    authority_request_identity: verification.authority_request_identity,
    backup_rollback_requirements: verification.backup_rollback_requirements,
    issuer_id: verification.issuer_id,
    issuer_kid: verification.issuer_kid,
    policy_id: verification.policy_id,
    accepted_policy_version: verification.accepted_policy_version,
    receipt_format: verification.receipt_format,
    receipt_path: verification.receipt_path,
    downstream_terminal: verification.downstream_terminal,
    downstream_refuses_before_effect: verification.downstream_refuses_before_effect,
    refusal_matrix_complete: verification.refusal_matrix_complete,
    refusal_reason_count: verification.refusal_reason_count,
    human_authority_required_before_install_or_config:
      verification.human_authority_required_before_install_or_config,
    no_write_boundary: noWriteBoundary,
    safe_claim_ceiling: CURRENT_MACHINE_APPROVAL_INTAKE_SAFE_CLAIM_CEILING,
    claim_boundary:
      'explicit packet intake only; no install, activation, hook execution, live receipt emission, live downstream recognition, current-machine governance, or authority request evidence',
    non_claims: [...CURRENT_MACHINE_APPROVAL_INTAKE_NON_CLAIMS],
  };
  assertCurrentMachineApprovalIntakeReport(report);
  return report;
}

function buildRefusalReport({ inputKind, verifierExitCode, refusalReasonCode, refusalSummary }) {
  const report = {
    intake_type: CURRENT_MACHINE_APPROVAL_INTAKE_TYPE,
    intake_status: 'refused_before_authority_request',
    verifier_command: sanitizedVerifierCommand(inputKind),
    verifier_exit_code: verifierExitCode,
    verifier_verified: false,
    verifier_packet_complete: false,
    authority_request_kind: 'future_install_or_configuration_human_authority_request',
    authority_request_allowed: false,
    authority_request_made: false,
    refusal_reason_code: refusalReasonCode,
    refusal_summary: safeVerifierSummary(refusalSummary),
    packet_sha256: 'unverified',
    packet_verification: null,
    verified_sections: falseVerifiedSections(),
    selected_surface: 'unverified',
    hook_event: 'unverified',
    hook_profile_path: 'unverified',
    hook_command_target: 'unverified',
    delegation_target: 'unverified',
    source_target: unverifiedBindingSection(),
    installer_identity: unverifiedBindingSection(),
    command_posture: unverifiedBindingSection(),
    dry_run_plan_identity: unverifiedBindingSection(),
    authority_request_identity: unverifiedBindingSection(),
    backup_rollback_requirements: unverifiedBindingSection(),
    issuer_id: 'unverified',
    issuer_kid: 'unverified',
    policy_id: 'unverified',
    accepted_policy_version: 'unverified',
    receipt_format: 'unverified',
    receipt_path: 'unverified',
    downstream_terminal: 'unverified',
    downstream_refuses_before_effect: false,
    refusal_matrix_complete: false,
    refusal_reason_count: 0,
    human_authority_required_before_install_or_config: false,
    no_write_boundary: falseNoWriteBoundary(),
    safe_claim_ceiling: CURRENT_MACHINE_APPROVAL_INTAKE_SAFE_CLAIM_CEILING,
    claim_boundary:
      'explicit packet intake refused before install/config authority request; no install, activation, hook execution, live receipt emission, live downstream recognition, current-machine governance, or authority request evidence',
    non_claims: [...CURRENT_MACHINE_APPROVAL_INTAKE_NON_CLAIMS],
  };
  assertCurrentMachineApprovalIntakeReport(report);
  return report;
}

export function runCurrentMachineApprovalIntake(options = {}) {
  const {
    packetPath,
    packetText,
    zlarBinPath = DEFAULT_ZLAR_BIN,
    cwd = process.cwd(),
    env = process.env,
  } = options;
  if (packetPath !== '-' && (typeof packetPath !== 'string' || !packetPath.trim())) {
    throw new Error('Current-machine approval intake requires an explicit packet path or stdin');
  }
  if (packetPath === '-' && typeof packetText !== 'string') {
    throw new Error('Current-machine approval intake requires packet text for stdin');
  }

  const inputKind = packetPath === '-' ? 'stdin' : 'file';
  const args = [
    'current-machine-approval-packet',
    'verify',
    '--input',
    packetPath === '-' ? '-' : packetPath,
    '--json',
  ];
  const verifier = spawnSync(zlarBinPath, args, {
    cwd,
    encoding: 'utf8',
    input: packetPath === '-' ? packetText : undefined,
    env: {
      ...env,
      NO_COLOR: '1',
    },
  });

  if (verifier.error) {
    return buildRefusalReport({
      inputKind,
      verifierExitCode: 127,
      refusalReasonCode: 'packet_verifier_unavailable',
      refusalSummary: verifier.error.message,
    });
  }

  if (verifier.status !== 0) {
    return buildRefusalReport({
      inputKind,
      verifierExitCode: Number.isInteger(verifier.status) ? verifier.status : 1,
      refusalReasonCode: 'packet_verification_failed',
      refusalSummary: verifier.stderr || verifier.stdout,
    });
  }

  let verification;
  try {
    verification = JSON.parse(verifier.stdout);
    assertCurrentMachineApprovalPacketVerification(verification);
  } catch (err) {
    return buildRefusalReport({
      inputKind,
      verifierExitCode: 1,
      refusalReasonCode: 'packet_verifier_output_unparseable',
      refusalSummary: err.message,
    });
  }

  return buildAllowedReport(verification, inputKind);
}

export function assertCurrentMachineApprovalIntakeReport(report) {
  assertExactKeys('Current-machine approval intake report', report, [
    'accepted_policy_version',
    'authority_request_identity',
    'authority_request_allowed',
    'authority_request_kind',
    'authority_request_made',
    'backup_rollback_requirements',
    'claim_boundary',
    'command_posture',
    'delegation_target',
    'downstream_refuses_before_effect',
    'downstream_terminal',
    'dry_run_plan_identity',
    'hook_command_target',
    'hook_event',
    'hook_profile_path',
    'human_authority_required_before_install_or_config',
    'installer_identity',
    'intake_status',
    'intake_type',
    'issuer_id',
    'issuer_kid',
    'no_write_boundary',
    'non_claims',
    'packet_sha256',
    'packet_verification',
    'policy_id',
    'receipt_format',
    'receipt_path',
    'refusal_matrix_complete',
    'refusal_reason_code',
    'refusal_reason_count',
    'refusal_summary',
    'safe_claim_ceiling',
    'selected_surface',
    'source_target',
    'verified_sections',
    'verifier_command',
    'verifier_exit_code',
    'verifier_packet_complete',
    'verifier_verified',
  ]);
  if (report.intake_type !== CURRENT_MACHINE_APPROVAL_INTAKE_TYPE) {
    throw new Error('Current-machine approval intake report has wrong type');
  }
  if (!['allowed_to_prepare_human_request_only', 'refused_before_authority_request'].includes(report.intake_status)) {
    throw new Error('Current-machine approval intake status drifted');
  }
  if (report.authority_request_kind !== 'future_install_or_configuration_human_authority_request') {
    throw new Error('Current-machine approval intake authority request kind drifted');
  }
  assertBoolean(
    'Current-machine approval intake authority request allowed',
    report.authority_request_allowed
  );
  assertBoolean(
    'Current-machine approval intake authority request made',
    report.authority_request_made,
    false
  );
  if (!Array.isArray(report.verifier_command) || report.verifier_command.join(' ') !== 'zlar current-machine-approval-packet verify --input <explicit-packet> --json' &&
      report.verifier_command.join(' ') !== 'zlar current-machine-approval-packet verify --input - --json') {
    throw new Error('Current-machine approval intake verifier command drifted');
  }
  if (!Number.isInteger(report.verifier_exit_code) || report.verifier_exit_code < 0) {
    throw new Error('Current-machine approval intake verifier exit code drifted');
  }
  assertBoolean('Current-machine approval intake verifier verified', report.verifier_verified);
  assertBoolean('Current-machine approval intake packet complete', report.verifier_packet_complete);
  assertExactKeys(
    'Current-machine approval intake verified sections',
    report.verified_sections,
    VERIFIED_SECTION_FIELDS
  );
  for (const field of VERIFIED_SECTION_FIELDS) {
    assertBoolean(`Current-machine approval intake verified section ${field}`, report.verified_sections[field]);
  }
  assertExactKeys(
    'Current-machine approval intake no-write boundary',
    report.no_write_boundary,
    NO_WRITE_BOUNDARY_FIELDS
  );
  for (const field of NO_WRITE_BOUNDARY_FIELDS) {
    assertBoolean(`Current-machine approval intake no-write boundary ${field}`, report.no_write_boundary[field], false);
  }
  for (const field of [
    'intake_status',
    'authority_request_kind',
    'refusal_reason_code',
    'refusal_summary',
    'packet_sha256',
    'selected_surface',
    'hook_event',
    'hook_profile_path',
    'hook_command_target',
    'delegation_target',
    'issuer_id',
    'issuer_kid',
    'policy_id',
    'accepted_policy_version',
    'receipt_format',
    'receipt_path',
    'downstream_terminal',
    'safe_claim_ceiling',
    'claim_boundary',
  ]) {
    assertString(`Current-machine approval intake ${field}`, report[field]);
  }
  for (const field of [
    'source_target',
    'installer_identity',
    'command_posture',
    'dry_run_plan_identity',
    'authority_request_identity',
    'backup_rollback_requirements',
  ]) {
    requireObject(`Current-machine approval intake ${field}`, report[field]);
  }
  assertBoolean(
    'Current-machine approval intake downstream refuses before effect',
    report.downstream_refuses_before_effect
  );
  assertBoolean(
    'Current-machine approval intake refusal matrix complete',
    report.refusal_matrix_complete
  );
  assertBoolean(
    'Current-machine approval intake human authority required before install/config',
    report.human_authority_required_before_install_or_config
  );
  if (!Number.isInteger(report.refusal_reason_count) || report.refusal_reason_count < 0) {
    throw new Error('Current-machine approval intake refusal reason count drifted');
  }
  if (!Array.isArray(report.non_claims) || report.non_claims.length !== CURRENT_MACHINE_APPROVAL_INTAKE_NON_CLAIMS.length) {
    throw new Error('Current-machine approval intake non-claims drifted');
  }
  for (let i = 0; i < CURRENT_MACHINE_APPROVAL_INTAKE_NON_CLAIMS.length; i++) {
    if (report.non_claims[i] !== CURRENT_MACHINE_APPROVAL_INTAKE_NON_CLAIMS[i]) {
      throw new Error('Current-machine approval intake non-claims drifted');
    }
  }
  if (report.authority_request_allowed) {
    if (report.intake_status !== 'allowed_to_prepare_human_request_only') {
      throw new Error('Current-machine approval intake allowed status drifted');
    }
    if (report.refusal_reason_code !== 'none' || report.refusal_summary !== 'none') {
      throw new Error('Current-machine approval intake allowed refusal drifted');
    }
    assertCurrentMachineApprovalPacketVerification(report.packet_verification);
    assertDerivedFromPacketVerification(report);
    if (!report.verifier_verified || !report.verifier_packet_complete) {
      throw new Error('Current-machine approval intake verifier flags drifted');
    }
    if (!Object.values(report.verified_sections).every(Boolean)) {
      throw new Error('Current-machine approval intake verified sections incomplete');
    }
  } else {
    if (report.intake_status !== 'refused_before_authority_request') {
      throw new Error('Current-machine approval intake refusal status drifted');
    }
    if (report.authority_request_made !== false) {
      throw new Error('Current-machine approval intake refused authority request drifted');
    }
  }
  assertNoUnsafeCurrentMachineApprovalPacketText(JSON.stringify(report));
  return true;
}

export function formatCurrentMachineApprovalIntakeReport(report) {
  assertCurrentMachineApprovalIntakeReport(report);
  const lines = [
    'ZLAR Current-Machine Approval Intake v1',
    `verifier_verified=${report.verifier_verified}; packet_complete=${report.verifier_packet_complete}; authority_request_allowed=${report.authority_request_allowed}; authority_request_made=${report.authority_request_made}`,
    `status=${report.intake_status}; refusal_reason=${report.refusal_reason_code}`,
    `verifier_command=${report.verifier_command.join(' ')}`,
    `packet_sha256=${report.packet_sha256}`,
    `selected_surface=${report.selected_surface}; hook_event=${report.hook_event}; hook_target=${report.hook_command_target}; delegation_target=${report.delegation_target}`,
    `source_target: commit=${report.source_target.target_commit_sha || 'unverified'}; tree=${report.source_target.target_tree_sha || 'unverified'}; version=${report.source_target.target_version || 'unverified'}; state=${report.source_target.source_state || 'unverified'}`,
    `installer_identity: path=${report.installer_identity.installer_path || 'unverified'}; blob=${report.installer_identity.installer_git_blob_sha || 'unverified'}; sha256=${report.installer_identity.installer_sha256 || 'unverified'}`,
    `command_posture: surface=${report.command_posture.selected_surface || 'unverified'}; existing_install_mode=${report.command_posture.existing_install_mode || 'unverified'}; no_machine_helpers=${report.command_posture.no_machine_helpers === true}`,
    `dry_run_plan_identity: type=${report.dry_run_plan_identity.plan_type || 'unverified'}; command=${report.dry_run_plan_identity.plan_command || 'unverified'}; sha256=${report.dry_run_plan_identity.plan_sha256 || 'unverified'}`,
    `authority_request_identity: request_id=${report.authority_request_identity.request_id || 'unverified'}; single_use=${report.authority_request_identity.single_use === true}; replay_guard_required=${report.authority_request_identity.replay_guard_required === true}; authority_request_made=${report.authority_request_identity.authority_request_made === true}`,
    `backup_rollback: backup_required=${report.backup_rollback_requirements.backup_required_before_mutation === true}; rollback_plan_required=${report.backup_rollback_requirements.rollback_plan_required === true}; installer_backup_enforcement_present=${report.backup_rollback_requirements.installer_backup_enforcement_present === true}`,
    `issuer_policy: issuer_id=${report.issuer_id}; issuer_kid=${report.issuer_kid}; policy_id=${report.policy_id}; accepted_policy_version=${report.accepted_policy_version}`,
    `receipt_path: format=${report.receipt_format}; path=${report.receipt_path}`,
    `downstream: terminal=${report.downstream_terminal}; refuses_before_effect=${report.downstream_refuses_before_effect}; refusal_matrix_complete=${report.refusal_matrix_complete}; refusal_reasons=${report.refusal_reason_count}`,
    `verified_sections: selected_surface=${report.verified_sections.selected_surface}; hook_target=${report.verified_sections.hook_target}; source_target=${report.verified_sections.source_target}; installer_identity=${report.verified_sections.installer_identity}; command_posture=${report.verified_sections.command_posture}; dry_run_plan_identity=${report.verified_sections.dry_run_plan_identity}; authority_request_identity=${report.verified_sections.authority_request_identity}; backup_rollback_requirements=${report.verified_sections.backup_rollback_requirements}; issuer_policy=${report.verified_sections.issuer_policy}; receipt_path=${report.verified_sections.receipt_path}; downstream_refusal_matrix=${report.verified_sections.downstream_refusal_matrix}; explicit_non_claims=${report.verified_sections.explicit_non_claims}`,
    `no_write_boundary: install_or_activation_applied=${report.no_write_boundary.install_or_activation_applied}; hook_profile_written=${report.no_write_boundary.hook_profile_written}; user_config_written=${report.no_write_boundary.user_config_written}; machine_config_written=${report.no_write_boundary.machine_config_written}; service_started=${report.no_write_boundary.service_started}; signing_material_changed=${report.no_write_boundary.secrets_or_signing_material_changed}; telegram_used=${report.no_write_boundary.telegram_used}; github_settings_changed=${report.no_write_boundary.github_settings_changed}; website_publication=${report.no_write_boundary.website_publication}`,
    `evidence_boundary: current_machine_governance_evidence=${report.no_write_boundary.current_machine_governance_evidence}; live_hook_execution_evidence=${report.no_write_boundary.live_hook_execution_evidence}; live_receipt_emission_evidence=${report.no_write_boundary.live_receipt_emission_evidence}; live_downstream_recognition_evidence=${report.no_write_boundary.live_downstream_recognition_evidence}; external_attestation=${report.no_write_boundary.external_attestation}`,
    `claim_ceiling=${report.safe_claim_ceiling}`,
    `claim_boundary=${report.claim_boundary}`,
    `refusal_summary=${report.refusal_summary}`,
    'Non-claims:',
  ];
  for (const claim of report.non_claims) {
    lines.push(`- ${claim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeCurrentMachineApprovalPacketText(summary);
  return summary;
}
