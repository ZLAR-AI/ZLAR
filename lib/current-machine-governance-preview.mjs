import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize, sha256hex } from './receipt.mjs';
import {
  runCurrentMachineApprovalIntake,
} from './current-machine-approval-intake.mjs';
import {
  assertCurrentMachineApprovalRequestPreviewReport,
  previewCurrentMachineApprovalRequest,
} from './current-machine-approval-request-preview.mjs';
import {
  ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
  ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
  assertActivePersistentProfileSourcePreflight,
  assertActivePersistentProfileSourceStatus,
  inspectActivePersistentProfileSourceStatus,
  runActivePersistentProfileSourcePreflight,
} from './protected-records-active-persistent-profile-preflight.mjs';
import {
  PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID,
  assertProtectedRecordsNamedDeploymentProfileReadiness,
  buildProtectedRecordsNamedDeploymentProfileReadiness,
} from './protected-records-named-deployment-profile-readiness.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from './protected-records-runtime-profile.mjs';

export const CURRENT_MACHINE_GOVERNANCE_PREVIEW_TYPE =
  'zlar-current-machine-governance-preview-v1';
export const CURRENT_MACHINE_GOVERNANCE_PREVIEW_RESULT_READY =
  'PREVIEW_READY_NO_AUTHORITY';
export const CURRENT_MACHINE_GOVERNANCE_PREVIEW_PROOF_STAGE =
  'source_only_preview_no_authority';

export const CURRENT_MACHINE_GOVERNANCE_PREVIEW_SAFE_CLAIM =
  'ZLAR can compose local no-write current-machine governance preview evidence and show the next authority crossing before install/config/live governance. This is not current-machine governance evidence.';

export const CURRENT_MACHINE_GOVERNANCE_PREVIEW_NON_CLAIMS = Object.freeze([
  'This preview does not install, activate, or write hook, profile, user, service, machine, production, website, GitHub, or Telegram configuration.',
  'This preview does not request or grant install/config authority, human approval, or current-machine governance.',
  'This preview does not prove live hook execution, live receipt emission, live downstream recognition, production authority, enterprise readiness, public external attestation, sovereign recognition, all-surface governance, side-door closure, or absolute human intention.',
  'This preview uses committed fixtures and proof-owned temporary roots only; it does not inspect real personal records or a live records system.',
]);

const ZLAR_REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));
const SAMPLE_PACKET_PATH = join(
  ZLAR_REPO_ROOT,
  'tests',
  'fixtures',
  'current-machine-approval-packet-claude-code-v1.json'
);
const SAMPLE_PROFILE_PATH = join(
  ZLAR_REPO_ROOT,
  ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE
);
const FIXED_NOW_EPOCH = 1767225600;
const FIXED_EXPIRES_AT = '2099-12-31T00:00:00.000Z';

const CLAIM_BOUNDARY_KEYS = Object.freeze([
  'all_surface_governance',
  'authority_request_made',
  'current_machine_governance',
  'current_machine_governance_evidence',
  'current_machine_governance_proven',
  'deployment_readiness_claim',
  'enterprise_readiness',
  'external_attestation',
  'external_attestation_claim',
  'github_settings_changed',
  'hook_profile_written',
  'human_approval_granted',
  'install_authority_granted',
  'install_or_activation_applied',
  'live_downstream_recognition_evidence',
  'live_hook_execution_evidence',
  'live_receipt_emission_evidence',
  'live_service_started',
  'machine_config_written',
  'persistent_runtime_profile_installation',
  'production_authority',
  'production_claim',
  'production_downstream_recognition',
  'production_public_authority',
  'public_release_claim',
  'public_external_attestation',
  'real_personal_records_touched',
  'secrets_or_signing_material_changed',
  'service_started',
  'side_door_closure',
  'sovereign_recognition',
  'source_transport_proof',
  'telegram_used',
  'user_config_written',
  'website_publication',
]);

const CROSS_REPORT_CHECK_KEYS = Object.freeze([
  'action_class_matches',
  'active_persistent_source_preflight_safe',
  'approval_request_not_made',
  'approval_request_preview_prepared',
  'claim_boundaries_remain_false',
  'downstream_refusal_before_effect',
  'named_profile_matches',
  'named_profile_rehearsal_ready',
  'no_install_config_or_live_governance',
  'no_live_or_external_evidence',
  'runtime_profile_binding_matches',
]);

function exactKeys(label, value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} keys drifted`);
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

function falseClaimBoundary() {
  return Object.fromEntries(CLAIM_BOUNDARY_KEYS.map((key) => [key, false]));
}

function allFalse(value) {
  return value && typeof value === 'object' && Object.values(value).every((item) => item === false);
}

function componentHashes(components) {
  return Object.fromEntries(
    Object.entries(components).map(([key, value]) => [
      `${key}_sha256`,
      sha256hex(canonicalize(value)),
    ])
  );
}

function createSourcePreflightComponents() {
  const scratch = mkdtempSync(join(tmpdir(), 'zlar-current-machine-governance-preview-'));
  try {
    const activationRoot = join(
      scratch,
      'activation',
      PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID
    );
    const proofTarget = join(scratch, 'proof', 'records-target.jsonl');
    mkdirSync(join(scratch, 'activation'), { recursive: true });
    mkdirSync(join(scratch, 'proof'), { recursive: true });
    const status = inspectActivePersistentProfileSourceStatus({
      surrogateRoot: scratch,
      activationRoot,
      nowEpoch: FIXED_NOW_EPOCH,
    });
    const profile = JSON.parse(readFileSync(SAMPLE_PROFILE_PATH, 'utf8'));
    const preflight = runActivePersistentProfileSourcePreflight({
      surrogateRoot: scratch,
      activationRoot,
      proofTarget,
      profile,
      profileSource: ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
      runtimeProfileId: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      runtimeProfileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
      expiresAt: FIXED_EXPIRES_AT,
      nowEpoch: FIXED_NOW_EPOCH,
    });
    return { status, preflight };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

function buildComponents() {
  const approvalIntake = runCurrentMachineApprovalIntake({
    packetPath: SAMPLE_PACKET_PATH,
  });
  const approvalRequestPreview =
    previewCurrentMachineApprovalRequest(approvalIntake);
  const namedDeploymentProfileReadiness =
    buildProtectedRecordsNamedDeploymentProfileReadiness();
  const { status, preflight } = createSourcePreflightComponents();
  return {
    current_machine_approval_request_preview: approvalRequestPreview,
    named_deployment_profile_readiness: namedDeploymentProfileReadiness,
    active_persistent_profile_source_status: status,
    active_persistent_profile_source_preflight: preflight,
  };
}

function crossReportChecks(components) {
  const approval =
    components.current_machine_approval_request_preview;
  const named =
    components.named_deployment_profile_readiness;
  const status =
    components.active_persistent_profile_source_status;
  const preflight =
    components.active_persistent_profile_source_preflight;
  return {
    action_class_matches:
      named.selected_deployment_profile.action_class === 'records.write' &&
      preflight.profile_binding.action_class === 'records.write',
    active_persistent_source_preflight_safe:
      status.safe_for_source_preflight === true &&
      status.read_only === true &&
      status.real_activation_root_touched === false &&
      preflight.source_only === true &&
      preflight.authority_boundary.real_activation_root_touched === false,
    approval_request_not_made:
      approval.authority_request_made === false &&
      approval.install_authority_granted === false &&
      approval.human_approval_granted === false,
    approval_request_preview_prepared:
      approval.preview_can_be_prepared === true &&
      approval.preview_status === 'preview_prepared_no_authority_request',
    claim_boundaries_remain_false:
      allFalse(approval.no_authority_boundary) &&
      Object.values(named.claim_boundary)
        .filter((value) => typeof value === 'boolean')
        .every((value) => value === false || value === true) &&
      named.claim_boundary.active_deployment_profile === false &&
      named.claim_boundary.current_machine_governance === false &&
      named.claim_boundary.production_downstream_recognition === false &&
      named.claim_boundary.enterprise_readiness === false &&
      named.claim_boundary.public_external_attestation === false &&
      preflight.claim_boundary.current_machine_governance_general === false &&
      preflight.claim_boundary.production_downstream_recognition === false &&
      preflight.claim_boundary.enterprise_readiness === false &&
      preflight.claim_boundary.public_external_attestation === false,
    downstream_refusal_before_effect:
      approval.downstream_refusal_matrix.downstream_refuses_before_effect === true &&
      approval.downstream_refusal_matrix.refusal_matrix_complete === true &&
      named.acceptance_gates.missing_receipt_refused_before_mutation === true &&
      named.acceptance_gates.unrecognized_receipt_refused_before_mutation === true &&
      named.acceptance_gates.out_of_scope_receipt_refused_before_mutation === true &&
      named.acceptance_gates.request_authority_material_refused_before_mutation === true,
    named_profile_matches:
      named.selected_deployment_profile.profile_id ===
        PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID &&
      preflight.profile_binding.deployment_profile_id ===
        PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID,
    named_profile_rehearsal_ready:
      named.selected_deployment_profile.profile_status === 'rehearsal_not_installed' &&
      named.acceptance_gates.named_deployment_profile_declared === true &&
      named.acceptance_gates.recognized_receipt_mutates_once_rehearsed === true,
    no_install_config_or_live_governance:
      approval.no_authority_boundary.install_or_activation_applied === false &&
      approval.no_authority_boundary.hook_profile_written === false &&
      approval.no_authority_boundary.user_config_written === false &&
      approval.no_authority_boundary.machine_config_written === false &&
      approval.no_authority_boundary.service_started === false &&
      preflight.write_boundary.activation_root_write_allowed === false &&
      preflight.write_boundary.hook_configuration_write_allowed === false &&
      preflight.write_boundary.user_config_write_allowed === false &&
      preflight.write_boundary.machine_config_write_allowed === false &&
      preflight.write_boundary.runtime_service_start_allowed === false,
    no_live_or_external_evidence:
      approval.no_authority_boundary.live_hook_execution_evidence === false &&
      approval.no_authority_boundary.live_receipt_emission_evidence === false &&
      approval.no_authority_boundary.live_downstream_recognition_evidence === false &&
      approval.no_authority_boundary.external_attestation === false &&
      named.live_probing === false &&
      named.claim_boundary.production_authority === false &&
      named.claim_boundary.sovereign_recognition === false &&
      preflight.live_probing === false &&
      preflight.authority_boundary.network_or_external_service_used === false,
    runtime_profile_binding_matches:
      preflight.profile_binding.runtime_profile_id ===
        PROTECTED_RECORDS_RUNTIME_PROFILE_ID &&
      preflight.profile_binding.runtime_profile_sha256 ===
        ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256 &&
      preflight.profile_binding.runtime_profile_sha_matches_required === true,
  };
}

export function buildCurrentMachineGovernancePreview() {
  const components = buildComponents();
  const checks = crossReportChecks(components);
  const allChecksPass = Object.values(checks).every(Boolean);
  const report = {
    report_type: CURRENT_MACHINE_GOVERNANCE_PREVIEW_TYPE,
    schema_version: 1,
    evidence_model: 'local-no-write-composed-current-machine-governance-preview',
    evidence_surface: 'local-no-write-source-lane',
    proof_stage: CURRENT_MACHINE_GOVERNANCE_PREVIEW_PROOF_STAGE,
    result: allChecksPass
      ? CURRENT_MACHINE_GOVERNANCE_PREVIEW_RESULT_READY
      : 'PREVIEW_REFUSED_BEFORE_AUTHORITY',
    safe_claim: CURRENT_MACHINE_GOVERNANCE_PREVIEW_SAFE_CLAIM,
    action_class: 'records.write',
    selected_terminal: {
      surface_id: 'protected-records.runtime.profile-installation.records.write',
      deployment_profile: PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID,
      downstream_boundary: 'protected-records-runtime-service:local-jsonl-child-process',
      claim_scope: 'local no-write current-machine governance preview only',
    },
    components,
    component_hashes: componentHashes(components),
    cross_report_checks: checks,
    next_authority_crossing: {
      required_before_current_machine_governance_claim: true,
      crossing_class: 'install-config-current-machine-or-equivalent-real-deployment-boundary',
      human_authority_required: true,
      authority_request_made: false,
      install_authority_granted: false,
      reason:
        'Current-machine governance requires an authorized install/config or equivalent deployment boundary that makes the selected route active before consequence.',
    },
    claim_boundary: falseClaimBoundary(),
    non_claims: [...CURRENT_MACHINE_GOVERNANCE_PREVIEW_NON_CLAIMS],
  };
  assertCurrentMachineGovernancePreviewReport(report);
  return report;
}

export function assertCurrentMachineGovernancePreviewReport(report) {
  exactKeys('current-machine governance preview report', report, [
    'action_class',
    'claim_boundary',
    'component_hashes',
    'components',
    'cross_report_checks',
    'evidence_surface',
    'evidence_model',
    'next_authority_crossing',
    'non_claims',
    'proof_stage',
    'report_type',
    'result',
    'safe_claim',
    'schema_version',
    'selected_terminal',
  ]);
  if (
    report.report_type !== CURRENT_MACHINE_GOVERNANCE_PREVIEW_TYPE ||
    report.schema_version !== 1 ||
    report.evidence_model !== 'local-no-write-composed-current-machine-governance-preview' ||
    report.evidence_surface !== 'local-no-write-source-lane' ||
    report.proof_stage !== CURRENT_MACHINE_GOVERNANCE_PREVIEW_PROOF_STAGE ||
    report.result !== CURRENT_MACHINE_GOVERNANCE_PREVIEW_RESULT_READY ||
    report.safe_claim !== CURRENT_MACHINE_GOVERNANCE_PREVIEW_SAFE_CLAIM ||
    report.action_class !== 'records.write'
  ) {
    throw new Error('current-machine governance preview top-level contract drifted');
  }
  exactKeys('current-machine governance preview selected terminal', report.selected_terminal, [
    'claim_scope',
    'deployment_profile',
    'downstream_boundary',
    'surface_id',
  ]);
  if (
    report.selected_terminal.surface_id !== 'protected-records.runtime.profile-installation.records.write' ||
    report.selected_terminal.deployment_profile !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID ||
    report.selected_terminal.downstream_boundary !== 'protected-records-runtime-service:local-jsonl-child-process'
  ) {
    throw new Error('current-machine governance preview selected terminal drifted');
  }
  exactKeys('current-machine governance preview components', report.components, [
    'active_persistent_profile_source_preflight',
    'active_persistent_profile_source_status',
    'current_machine_approval_request_preview',
    'named_deployment_profile_readiness',
  ]);
  assertCurrentMachineApprovalRequestPreviewReport(
    report.components.current_machine_approval_request_preview
  );
  assertProtectedRecordsNamedDeploymentProfileReadiness(
    report.components.named_deployment_profile_readiness
  );
  assertActivePersistentProfileSourceStatus(
    report.components.active_persistent_profile_source_status
  );
  assertActivePersistentProfileSourcePreflight(
    report.components.active_persistent_profile_source_preflight
  );
  exactKeys('current-machine governance preview component hashes', report.component_hashes, [
    'active_persistent_profile_source_preflight_sha256',
    'active_persistent_profile_source_status_sha256',
    'current_machine_approval_request_preview_sha256',
    'named_deployment_profile_readiness_sha256',
  ]);
  for (const [componentName, component] of Object.entries(report.components)) {
    const hashKey = `${componentName}_sha256`;
    expectSha(`current-machine governance preview ${hashKey}`, report.component_hashes[hashKey]);
    if (report.component_hashes[hashKey] !== sha256hex(canonicalize(component))) {
      throw new Error(`current-machine governance preview ${hashKey} drifted`);
    }
  }
  exactKeys('current-machine governance preview cross-report checks', report.cross_report_checks, CROSS_REPORT_CHECK_KEYS);
  for (const key of CROSS_REPORT_CHECK_KEYS) {
    expectBool(`current-machine governance preview ${key}`, report.cross_report_checks[key], true);
  }
  const expectedChecks = crossReportChecks(report.components);
  if (canonicalize(report.cross_report_checks) !== canonicalize(expectedChecks)) {
    throw new Error('current-machine governance preview cross-report checks must be derived from components');
  }
  exactKeys('current-machine governance preview next authority crossing', report.next_authority_crossing, [
    'authority_request_made',
    'crossing_class',
    'human_authority_required',
    'install_authority_granted',
    'reason',
    'required_before_current_machine_governance_claim',
  ]);
  expectBool(
    'current-machine governance preview next crossing required',
    report.next_authority_crossing.required_before_current_machine_governance_claim,
    true
  );
  expectBool(
    'current-machine governance preview next crossing human authority',
    report.next_authority_crossing.human_authority_required,
    true
  );
  expectBool(
    'current-machine governance preview next crossing request made',
    report.next_authority_crossing.authority_request_made,
    false
  );
  expectBool(
    'current-machine governance preview next crossing install authority',
    report.next_authority_crossing.install_authority_granted,
    false
  );
  expectString(
    'current-machine governance preview next crossing class',
    report.next_authority_crossing.crossing_class
  );
  expectString(
    'current-machine governance preview next crossing reason',
    report.next_authority_crossing.reason
  );
  exactKeys('current-machine governance preview claim boundary', report.claim_boundary, CLAIM_BOUNDARY_KEYS);
  for (const key of CLAIM_BOUNDARY_KEYS) {
    expectBool(`current-machine governance preview claim boundary ${key}`, report.claim_boundary[key], false);
  }
  if (
    !Array.isArray(report.non_claims) ||
    report.non_claims.length !== CURRENT_MACHINE_GOVERNANCE_PREVIEW_NON_CLAIMS.length ||
    report.non_claims.some((claim, index) => claim !== CURRENT_MACHINE_GOVERNANCE_PREVIEW_NON_CLAIMS[index])
  ) {
    throw new Error('current-machine governance preview non-claims drifted');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return true;
}

export function formatCurrentMachineGovernancePreviewReport(report) {
  assertCurrentMachineGovernancePreviewReport(report);
  const checks = report.cross_report_checks;
  const lines = [
    'ZLAR Current-Machine Governance Preview v1',
    `result=${report.result}; proof_stage=${report.proof_stage}; action_class=${report.action_class}; current_machine_governance=${report.claim_boundary.current_machine_governance}`,
    `authority_request_made=${report.next_authority_crossing.authority_request_made}; install_authority_granted=${report.next_authority_crossing.install_authority_granted}; human_authority_required=${report.next_authority_crossing.human_authority_required}`,
    `approval_preview_prepared=${checks.approval_request_preview_prepared}; named_profile_rehearsal_ready=${checks.named_profile_rehearsal_ready}; active_persistent_source_preflight_safe=${checks.active_persistent_source_preflight_safe}`,
    `downstream_refusal_before_effect=${checks.downstream_refusal_before_effect}; no_install_config_or_live_governance=${checks.no_install_config_or_live_governance}; no_live_or_external_evidence=${checks.no_live_or_external_evidence}`,
    `selected_terminal=${report.selected_terminal.surface_id}; deployment_profile=${report.selected_terminal.deployment_profile}`,
    `next_authority_crossing=${report.next_authority_crossing.crossing_class}`,
    'Non-claims:',
    ...report.non_claims.map((claim) => `- ${claim}`),
  ];
  const output = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  return output;
}
