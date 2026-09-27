import {
  assertCurrentMachineApprovalIntakeReport,
  CURRENT_MACHINE_APPROVAL_INTAKE_TYPE,
} from './current-machine-approval-intake.mjs';
import {
  assertCurrentMachineApprovalPacketVerification,
  assertNoUnsafeCurrentMachineApprovalPacketText,
} from './current-machine-approval-packet.mjs';

export const CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_TYPE =
  'zlar-current-machine-approval-request-preview-v1';

export const CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_SAFE_CLAIM_CEILING =
  'ZLAR can verify that a current-machine approval intake report is complete enough to prepare a future human install/config authority request preview. This preview is not install authority, not approval, and not current-machine governance evidence.';

export const CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_NON_CLAIMS = Object.freeze([
  'This preview is not install authority.',
  'This preview is not an approval.',
  'This preview does not request or grant install/config authority.',
  'This preview does not install, activate, or write hook, profile, service, user, or machine configuration.',
  'This preview does not touch secrets or signing material.',
  'This preview does not use Telegram.',
  'This preview is not current-machine governance evidence.',
  'This preview does not prove live hook execution, live receipt emission, or live downstream recognition.',
]);

const FALSE_PREVIEW_BOUNDARY_FIELDS = Object.freeze([
  'authority_request_made',
  'install_authority_granted',
  'human_approval_granted',
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

const PRESERVED_SECTION_FIELDS = Object.freeze([
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
  'intake_non_claims',
  'packet_non_claims',
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

function safeSummary(text) {
  const summary = String(text || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .join(' ')
    .slice(0, 240);
  if (!summary) {
    return 'current-machine approval request preview refused';
  }
  try {
    assertNoUnsafeCurrentMachineApprovalPacketText(summary);
    return summary;
  } catch {
    return 'current-machine approval request preview refused; private path or credential details were suppressed';
  }
}

function falsePreviewBoundary() {
  return Object.fromEntries(FALSE_PREVIEW_BOUNDARY_FIELDS.map((field) => [field, false]));
}

function falsePreservedSections() {
  return Object.fromEntries(PRESERVED_SECTION_FIELDS.map((field) => [field, false]));
}

function unverifiedBindingSection() {
  return {
    verification_status: 'unverified',
  };
}

function preserveSectionsFromIntake(intakeReport) {
  const packetVerification = intakeReport.packet_verification;
  return {
    selected_surface: intakeReport.verified_sections.selected_surface === true,
    hook_target: intakeReport.verified_sections.hook_target === true,
    source_target:
      intakeReport.verified_sections.source_target === true &&
      Boolean(packetVerification?.source_target?.target_commit_sha),
    installer_identity:
      intakeReport.verified_sections.installer_identity === true &&
      Boolean(packetVerification?.installer_identity?.installer_sha256),
    command_posture:
      intakeReport.verified_sections.command_posture === true &&
      packetVerification?.command_posture?.selected_surface === 'claude_code',
    dry_run_plan_identity:
      intakeReport.verified_sections.dry_run_plan_identity === true &&
      Boolean(packetVerification?.dry_run_plan_identity?.plan_sha256),
    authority_request_identity:
      intakeReport.verified_sections.authority_request_identity === true &&
      packetVerification?.authority_request_identity?.authority_request_made === false,
    backup_rollback_requirements:
      intakeReport.verified_sections.backup_rollback_requirements === true &&
      packetVerification?.backup_rollback_requirements?.backup_required_before_mutation === true,
    issuer_policy: intakeReport.verified_sections.issuer_policy === true,
    receipt_path: intakeReport.verified_sections.receipt_path === true,
    downstream_refusal_matrix:
      intakeReport.verified_sections.downstream_refusal_matrix === true &&
      intakeReport.refusal_matrix_complete === true,
    intake_non_claims: Array.isArray(intakeReport.non_claims) && intakeReport.non_claims.length > 0,
    packet_non_claims: Array.isArray(packetVerification?.non_claims) && packetVerification.non_claims.length > 0,
  };
}

function boundaryFromIntake(intakeReport) {
  return {
    ...falsePreviewBoundary(),
    install_or_activation_applied: intakeReport.no_write_boundary.install_or_activation_applied,
    hook_profile_written: intakeReport.no_write_boundary.hook_profile_written,
    user_config_written: intakeReport.no_write_boundary.user_config_written,
    machine_config_written: intakeReport.no_write_boundary.machine_config_written,
    service_started: intakeReport.no_write_boundary.service_started,
    secrets_or_signing_material_changed:
      intakeReport.no_write_boundary.secrets_or_signing_material_changed,
    telegram_used: intakeReport.no_write_boundary.telegram_used,
    github_settings_changed: intakeReport.no_write_boundary.github_settings_changed,
    website_publication: intakeReport.no_write_boundary.website_publication,
    current_machine_governance_evidence:
      intakeReport.no_write_boundary.current_machine_governance_evidence,
    live_hook_execution_evidence: intakeReport.no_write_boundary.live_hook_execution_evidence,
    live_receipt_emission_evidence:
      intakeReport.no_write_boundary.live_receipt_emission_evidence,
    live_downstream_recognition_evidence:
      intakeReport.no_write_boundary.live_downstream_recognition_evidence,
    external_attestation: intakeReport.no_write_boundary.external_attestation,
  };
}

function previewReady(intakeReport, preservedSections, previewBoundary) {
  return (
    intakeReport.intake_type === CURRENT_MACHINE_APPROVAL_INTAKE_TYPE &&
    intakeReport.authority_request_allowed === true &&
    intakeReport.authority_request_made === false &&
    intakeReport.verifier_verified === true &&
    intakeReport.verifier_packet_complete === true &&
    intakeReport.packet_verification?.verified === true &&
    intakeReport.packet_verification?.packet_complete === true &&
    Object.values(preservedSections).every(Boolean) &&
    Object.values(previewBoundary).every((value) => value === false)
  );
}

function buildPreviewReport(intakeReport) {
  assertCurrentMachineApprovalIntakeReport(intakeReport);
  assertCurrentMachineApprovalPacketVerification(intakeReport.packet_verification);
  const verification = intakeReport.packet_verification;
  const preservedSections = preserveSectionsFromIntake(intakeReport);
  const previewBoundary = boundaryFromIntake(intakeReport);
  const canPreparePreview = previewReady(intakeReport, preservedSections, previewBoundary);
  const report = {
    preview_type: CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_TYPE,
    preview_status: canPreparePreview
      ? 'preview_prepared_no_authority_request'
      : 'refused_before_authority_request_preview',
    preview_can_be_prepared: canPreparePreview,
    authority_request_made: false,
    install_authority_granted: false,
    human_approval_granted: false,
    refusal_reason_code: canPreparePreview ? 'none' : 'intake_report_not_preview_ready',
    refusal_summary: canPreparePreview
      ? 'none'
      : 'intake report did not satisfy every authority-request preview boundary',
    intake_type: intakeReport.intake_type,
    intake_status: intakeReport.intake_status,
    intake_authority_request_allowed: intakeReport.authority_request_allowed,
    intake_authority_request_made: intakeReport.authority_request_made,
    intake_packet_sha256: verification.packet_sha256,
    packet_verification_complete:
      intakeReport.verifier_verified === true &&
      intakeReport.verifier_packet_complete === true &&
      intakeReport.packet_verification?.verified === true &&
      intakeReport.packet_verification?.packet_complete === true,
    preserved_sections: preservedSections,
    selected_surface: verification.selected_surface,
    hook_target: {
      hook_event: verification.hook_event,
      hook_profile_path: verification.hook_profile_path,
      hook_command_target: verification.hook_command_target,
      delegation_target: verification.delegation_target,
    },
    source_target: verification.source_target,
    installer_identity: verification.installer_identity,
    command_posture: verification.command_posture,
    dry_run_plan_identity: verification.dry_run_plan_identity,
    authority_request_identity: verification.authority_request_identity,
    backup_rollback_requirements: verification.backup_rollback_requirements,
    issuer_policy: {
      issuer_id: verification.issuer_id,
      issuer_kid: verification.issuer_kid,
      policy_id: verification.policy_id,
      accepted_policy_version: verification.accepted_policy_version,
    },
    receipt_path: {
      receipt_format: verification.receipt_format,
      receipt_path: verification.receipt_path,
    },
    downstream_refusal_matrix: {
      downstream_terminal: verification.downstream_terminal,
      downstream_refuses_before_effect: verification.downstream_refuses_before_effect,
      refusal_matrix_complete: verification.refusal_matrix_complete,
      refusal_reason_count: verification.refusal_reason_count,
      required_refusal_reasons: [
        ...verification.required_refusal_reasons,
      ],
    },
    no_authority_boundary: previewBoundary,
    intake_non_claims: [...intakeReport.non_claims],
    packet_non_claims: [...intakeReport.packet_verification.non_claims],
    preview_non_claims: [...CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_NON_CLAIMS],
    safe_claim_ceiling: CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_SAFE_CLAIM_CEILING,
    claim_boundary:
      'authority-request preview only; not install authority, not approval, no authority request made, no install/config writes, no live hook execution, no live receipt emission, no live downstream recognition, and no current-machine governance evidence',
  };
  assertCurrentMachineApprovalRequestPreviewReport(report);
  return report;
}

function buildRefusalReport(reasonCode, summary) {
  const report = {
    preview_type: CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_TYPE,
    preview_status: 'refused_before_authority_request_preview',
    preview_can_be_prepared: false,
    authority_request_made: false,
    install_authority_granted: false,
    human_approval_granted: false,
    refusal_reason_code: reasonCode,
    refusal_summary: safeSummary(summary),
    intake_type: 'unverified',
    intake_status: 'unverified',
    intake_authority_request_allowed: false,
    intake_authority_request_made: false,
    intake_packet_sha256: 'unverified',
    packet_verification_complete: false,
    preserved_sections: falsePreservedSections(),
    selected_surface: 'unverified',
    hook_target: {
      hook_event: 'unverified',
      hook_profile_path: 'unverified',
      hook_command_target: 'unverified',
      delegation_target: 'unverified',
    },
    source_target: unverifiedBindingSection(),
    installer_identity: unverifiedBindingSection(),
    command_posture: unverifiedBindingSection(),
    dry_run_plan_identity: unverifiedBindingSection(),
    authority_request_identity: unverifiedBindingSection(),
    backup_rollback_requirements: unverifiedBindingSection(),
    issuer_policy: {
      issuer_id: 'unverified',
      issuer_kid: 'unverified',
      policy_id: 'unverified',
      accepted_policy_version: 'unverified',
    },
    receipt_path: {
      receipt_format: 'unverified',
      receipt_path: 'unverified',
    },
    downstream_refusal_matrix: {
      downstream_terminal: 'unverified',
      downstream_refuses_before_effect: false,
      refusal_matrix_complete: false,
      refusal_reason_count: 0,
      required_refusal_reasons: [],
    },
    no_authority_boundary: falsePreviewBoundary(),
    intake_non_claims: [],
    packet_non_claims: [],
    preview_non_claims: [...CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_NON_CLAIMS],
    safe_claim_ceiling: CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_SAFE_CLAIM_CEILING,
    claim_boundary:
      'authority-request preview refused; not install authority, not approval, no authority request made, no install/config writes, no live hook execution, no live receipt emission, no live downstream recognition, and no current-machine governance evidence',
  };
  assertCurrentMachineApprovalRequestPreviewReport(report);
  return report;
}

export function parseCurrentMachineApprovalRequestPreviewInput(text) {
  assertNoUnsafeCurrentMachineApprovalPacketText(text);
  try {
    return JSON.parse(text);
  } catch {
    throw new Error('Current-machine approval request preview input is not valid JSON');
  }
}

export function previewCurrentMachineApprovalRequest(intakeReport) {
  try {
    return buildPreviewReport(intakeReport);
  } catch (err) {
    return buildRefusalReport('intake_report_invalid', err.message);
  }
}

export function previewCurrentMachineApprovalRequestFromText(text) {
  try {
    return previewCurrentMachineApprovalRequest(
      parseCurrentMachineApprovalRequestPreviewInput(text)
    );
  } catch (err) {
    return buildRefusalReport('intake_report_unparseable', err.message);
  }
}

export function assertCurrentMachineApprovalRequestPreviewReport(report) {
  assertExactKeys('Current-machine approval request preview report', report, [
    'authority_request_identity',
    'authority_request_made',
    'backup_rollback_requirements',
    'claim_boundary',
    'command_posture',
    'downstream_refusal_matrix',
    'dry_run_plan_identity',
    'hook_target',
    'human_approval_granted',
    'install_authority_granted',
    'installer_identity',
    'intake_authority_request_allowed',
    'intake_authority_request_made',
    'intake_non_claims',
    'intake_packet_sha256',
    'intake_status',
    'intake_type',
    'issuer_policy',
    'no_authority_boundary',
    'packet_non_claims',
    'packet_verification_complete',
    'preserved_sections',
    'preview_can_be_prepared',
    'preview_non_claims',
    'preview_status',
    'preview_type',
    'receipt_path',
    'refusal_reason_code',
    'refusal_summary',
    'safe_claim_ceiling',
    'selected_surface',
    'source_target',
  ]);
  if (report.preview_type !== CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_TYPE) {
    throw new Error('Current-machine approval request preview report has wrong type');
  }
  if (!['preview_prepared_no_authority_request', 'refused_before_authority_request_preview'].includes(report.preview_status)) {
    throw new Error('Current-machine approval request preview status drifted');
  }
  assertBoolean('Current-machine approval request preview can be prepared', report.preview_can_be_prepared);
  assertBoolean('Current-machine approval request made', report.authority_request_made, false);
  assertBoolean('Current-machine approval install authority granted', report.install_authority_granted, false);
  assertBoolean('Current-machine approval human approval granted', report.human_approval_granted, false);
  assertBoolean('Current-machine approval intake authority allowed', report.intake_authority_request_allowed);
  assertBoolean('Current-machine approval intake authority made', report.intake_authority_request_made, false);
  assertBoolean('Current-machine approval packet verification complete', report.packet_verification_complete);
  assertExactKeys(
    'Current-machine approval request preview preserved sections',
    report.preserved_sections,
    PRESERVED_SECTION_FIELDS
  );
  for (const field of PRESERVED_SECTION_FIELDS) {
    assertBoolean(`Current-machine approval request preview preserved section ${field}`, report.preserved_sections[field]);
  }
  assertExactKeys(
    'Current-machine approval request preview hook target',
    report.hook_target,
    ['delegation_target', 'hook_command_target', 'hook_event', 'hook_profile_path']
  );
  for (const field of [
    'source_target',
    'installer_identity',
    'command_posture',
    'dry_run_plan_identity',
    'authority_request_identity',
    'backup_rollback_requirements',
  ]) {
    requireObject(`Current-machine approval request preview ${field}`, report[field]);
  }
  assertExactKeys(
    'Current-machine approval request preview issuer policy',
    report.issuer_policy,
    ['accepted_policy_version', 'issuer_id', 'issuer_kid', 'policy_id']
  );
  assertExactKeys(
    'Current-machine approval request preview receipt path',
    report.receipt_path,
    ['receipt_format', 'receipt_path']
  );
  assertExactKeys(
    'Current-machine approval request preview downstream refusal matrix',
    report.downstream_refusal_matrix,
    [
      'downstream_refuses_before_effect',
      'downstream_terminal',
      'refusal_matrix_complete',
      'refusal_reason_count',
      'required_refusal_reasons',
    ]
  );
  assertBoolean(
    'Current-machine approval request preview downstream refuses before effect',
    report.downstream_refusal_matrix.downstream_refuses_before_effect
  );
  assertBoolean(
    'Current-machine approval request preview refusal matrix complete',
    report.downstream_refusal_matrix.refusal_matrix_complete
  );
  if (!Number.isInteger(report.downstream_refusal_matrix.refusal_reason_count) || report.downstream_refusal_matrix.refusal_reason_count < 0) {
    throw new Error('Current-machine approval request preview refusal reason count drifted');
  }
  if (!Array.isArray(report.downstream_refusal_matrix.required_refusal_reasons)) {
    throw new Error('Current-machine approval request preview refusal reasons must be an array');
  }
  assertExactKeys(
    'Current-machine approval request preview no-authority boundary',
    report.no_authority_boundary,
    FALSE_PREVIEW_BOUNDARY_FIELDS
  );
  for (const field of FALSE_PREVIEW_BOUNDARY_FIELDS) {
    assertBoolean(`Current-machine approval request preview no-authority boundary ${field}`, report.no_authority_boundary[field], false);
  }
  for (const field of [
    'preview_status',
    'refusal_reason_code',
    'refusal_summary',
    'intake_type',
    'intake_status',
    'intake_packet_sha256',
    'selected_surface',
    'safe_claim_ceiling',
    'claim_boundary',
  ]) {
    assertString(`Current-machine approval request preview ${field}`, report[field]);
  }
  for (const field of ['hook_event', 'hook_profile_path', 'hook_command_target', 'delegation_target']) {
    assertString(
      `Current-machine approval request preview hook target ${field}`,
      report.hook_target[field]
    );
  }
  for (const field of ['issuer_id', 'issuer_kid', 'policy_id', 'accepted_policy_version']) {
    assertString(
      `Current-machine approval request preview issuer policy ${field}`,
      report.issuer_policy[field]
    );
  }
  for (const field of ['receipt_format', 'receipt_path']) {
    assertString(
      `Current-machine approval request preview receipt path ${field}`,
      report.receipt_path[field]
    );
  }
  assertString(
    'Current-machine approval request preview downstream terminal',
    report.downstream_refusal_matrix.downstream_terminal
  );
  for (const field of ['intake_non_claims', 'packet_non_claims', 'preview_non_claims']) {
    if (!Array.isArray(report[field])) {
      throw new Error(`Current-machine approval request preview ${field} must be an array`);
    }
  }
  if (report.preview_non_claims.length !== CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_NON_CLAIMS.length) {
    throw new Error('Current-machine approval request preview non-claims drifted');
  }
  for (let i = 0; i < CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_NON_CLAIMS.length; i++) {
    if (report.preview_non_claims[i] !== CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_NON_CLAIMS[i]) {
      throw new Error('Current-machine approval request preview non-claims drifted');
    }
  }
  if (report.preview_can_be_prepared) {
    if (report.preview_status !== 'preview_prepared_no_authority_request') {
      throw new Error('Current-machine approval request preview prepared status drifted');
    }
    if (report.refusal_reason_code !== 'none' || report.refusal_summary !== 'none') {
      throw new Error('Current-machine approval request preview refusal drifted');
    }
    if (
      report.intake_type !== CURRENT_MACHINE_APPROVAL_INTAKE_TYPE ||
      report.intake_authority_request_allowed !== true ||
      report.intake_authority_request_made !== false ||
      report.packet_verification_complete !== true
    ) {
      throw new Error('Current-machine approval request preview intake gate drifted');
    }
    if (!Object.values(report.preserved_sections).every(Boolean)) {
      throw new Error('Current-machine approval request preview did not preserve every section');
    }
  } else if (report.preview_status !== 'refused_before_authority_request_preview') {
    throw new Error('Current-machine approval request preview refusal status drifted');
  }
  assertNoUnsafeCurrentMachineApprovalPacketText(JSON.stringify(report));
  return true;
}

export function formatCurrentMachineApprovalRequestPreviewReport(report) {
  assertCurrentMachineApprovalRequestPreviewReport(report);
  const lines = [
    'ZLAR Current-Machine Approval Request Preview v1',
    `preview_can_be_prepared=${report.preview_can_be_prepared}; authority_request_made=${report.authority_request_made}; install_authority_granted=${report.install_authority_granted}; human_approval_granted=${report.human_approval_granted}`,
    `status=${report.preview_status}; refusal_reason=${report.refusal_reason_code}`,
    `intake: type=${report.intake_type}; status=${report.intake_status}; authority_request_allowed=${report.intake_authority_request_allowed}; authority_request_made=${report.intake_authority_request_made}; packet_sha256=${report.intake_packet_sha256}; packet_verification_complete=${report.packet_verification_complete}`,
    `selected_surface=${report.selected_surface}; hook_event=${report.hook_target.hook_event}; hook_target=${report.hook_target.hook_command_target}; delegation_target=${report.hook_target.delegation_target}; hook_profile=${report.hook_target.hook_profile_path}`,
    `source_target: commit=${report.source_target.target_commit_sha || 'unverified'}; tree=${report.source_target.target_tree_sha || 'unverified'}; version=${report.source_target.target_version || 'unverified'}; state=${report.source_target.source_state || 'unverified'}`,
    `installer_identity: path=${report.installer_identity.installer_path || 'unverified'}; blob=${report.installer_identity.installer_git_blob_sha || 'unverified'}; sha256=${report.installer_identity.installer_sha256 || 'unverified'}`,
    `command_posture: surface=${report.command_posture.selected_surface || 'unverified'}; existing_install_mode=${report.command_posture.existing_install_mode || 'unverified'}; no_machine_helpers=${report.command_posture.no_machine_helpers === true}`,
    `dry_run_plan_identity: type=${report.dry_run_plan_identity.plan_type || 'unverified'}; command=${report.dry_run_plan_identity.plan_command || 'unverified'}; sha256=${report.dry_run_plan_identity.plan_sha256 || 'unverified'}`,
    `authority_request_identity: request_id=${report.authority_request_identity.request_id || 'unverified'}; single_use=${report.authority_request_identity.single_use === true}; replay_guard_required=${report.authority_request_identity.replay_guard_required === true}; authority_request_made=${report.authority_request_identity.authority_request_made === true}`,
    `backup_rollback: backup_required=${report.backup_rollback_requirements.backup_required_before_mutation === true}; rollback_plan_required=${report.backup_rollback_requirements.rollback_plan_required === true}; installer_backup_enforcement_present=${report.backup_rollback_requirements.installer_backup_enforcement_present === true}`,
    `issuer_policy: issuer_id=${report.issuer_policy.issuer_id}; issuer_kid=${report.issuer_policy.issuer_kid}; policy_id=${report.issuer_policy.policy_id}; accepted_policy_version=${report.issuer_policy.accepted_policy_version}`,
    `receipt_path: format=${report.receipt_path.receipt_format}; path=${report.receipt_path.receipt_path}`,
    `downstream_refusal_matrix: terminal=${report.downstream_refusal_matrix.downstream_terminal}; refuses_before_effect=${report.downstream_refusal_matrix.downstream_refuses_before_effect}; complete=${report.downstream_refusal_matrix.refusal_matrix_complete}; refusal_reasons=${report.downstream_refusal_matrix.refusal_reason_count}`,
    `preserved_sections: selected_surface=${report.preserved_sections.selected_surface}; hook_target=${report.preserved_sections.hook_target}; source_target=${report.preserved_sections.source_target}; installer_identity=${report.preserved_sections.installer_identity}; command_posture=${report.preserved_sections.command_posture}; dry_run_plan_identity=${report.preserved_sections.dry_run_plan_identity}; authority_request_identity=${report.preserved_sections.authority_request_identity}; backup_rollback_requirements=${report.preserved_sections.backup_rollback_requirements}; issuer_policy=${report.preserved_sections.issuer_policy}; receipt_path=${report.preserved_sections.receipt_path}; downstream_refusal_matrix=${report.preserved_sections.downstream_refusal_matrix}; intake_non_claims=${report.preserved_sections.intake_non_claims}; packet_non_claims=${report.preserved_sections.packet_non_claims}`,
    `no_authority_boundary: install_or_activation_applied=${report.no_authority_boundary.install_or_activation_applied}; hook_profile_written=${report.no_authority_boundary.hook_profile_written}; user_config_written=${report.no_authority_boundary.user_config_written}; machine_config_written=${report.no_authority_boundary.machine_config_written}; service_started=${report.no_authority_boundary.service_started}; signing_material_changed=${report.no_authority_boundary.secrets_or_signing_material_changed}; telegram_used=${report.no_authority_boundary.telegram_used}; github_settings_changed=${report.no_authority_boundary.github_settings_changed}; website_publication=${report.no_authority_boundary.website_publication}`,
    `evidence_boundary: current_machine_governance_evidence=${report.no_authority_boundary.current_machine_governance_evidence}; live_hook_execution_evidence=${report.no_authority_boundary.live_hook_execution_evidence}; live_receipt_emission_evidence=${report.no_authority_boundary.live_receipt_emission_evidence}; live_downstream_recognition_evidence=${report.no_authority_boundary.live_downstream_recognition_evidence}; external_attestation=${report.no_authority_boundary.external_attestation}`,
    `claim_ceiling=${report.safe_claim_ceiling}`,
    `claim_boundary=${report.claim_boundary}`,
    `refusal_summary=${report.refusal_summary}`,
    'Intake non-claims:',
  ];
  for (const claim of report.intake_non_claims) {
    lines.push(`- ${claim}`);
  }
  lines.push('Packet non-claims:');
  for (const claim of report.packet_non_claims) {
    lines.push(`- ${claim}`);
  }
  lines.push('Preview non-claims:');
  for (const claim of report.preview_non_claims) {
    lines.push(`- ${claim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeCurrentMachineApprovalPacketText(summary);
  return summary;
}
