import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonicalize, sha256hex } from './receipt.mjs';
import {
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from './protected-records-runtime-profile.mjs';
import {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChain,
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification,
  parseProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactText,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
  verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact,
} from './protected-records-installed-runtime-profile-terminal-chain.mjs';

const PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_COMMITTED_TERMINAL_ARTIFACT_PATH =
  fileURLToPath(new URL(
    '../tests/fixtures/protected-records-installed-runtime-profile-terminal-chain-artifact-v1.json',
    import.meta.url,
  ));

export const PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_READINESS_REPORT_TYPE =
  'zlar-protected-records-named-deployment-profile-readiness-v1';

export const PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID =
  'protected-records-private-operator-records-terminal';

export const PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_SAFE_CLAIM =
  'ZLAR can verify the exact pinned committed local rehearsal artifact for a named protected-records deployment profile and show that its downstream boundary refused missing, unrecognized, out-of-scope, and request-authority attempts before mutation while one recognized receipt boarded through the disposable fixture path.';

export const PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_NON_CLAIMS = Object.freeze([
  'This report is a local rehearsal for a named deployment profile; it is not an active deployment profile.',
  'This report verifies one exact committed historical artifact; it does not authorize replay, fresh effect use, or a fresh fixture-rightful projection.',
  'This report does not install, activate, or persist runtime profile configuration.',
  'This report does not write hook, user, machine, production, receipt, audit, or records-system configuration.',
  'This report does not inspect real personal files or a live records system.',
  'This report does not prove current-machine governance, production downstream recognition, production authority, enterprise readiness, external attestation, sovereign recognition, all-surface governance, side-door closure, or absolute human intention.',
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

function expectSha(label, value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`${label} must be a SHA-256 hex string`);
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

function groupRefused(chain, key) {
  return chain.terminal_chain?.recognition_refusal_groups?.[key]?.all_refused_before_mutation === true;
}

function readPinnedCommittedTerminalArtifact() {
  const artifact = parseProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactText(
    readFileSync(
      PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_COMMITTED_TERMINAL_ARTIFACT_PATH,
      'utf8',
    ),
  );
  const verification =
    verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(
      artifact,
      {
        expectedArtifactBodySha256:
          PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
      },
    );
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification(
    verification,
  );
  if (
    verification.artifact_identity_sha256_matched !== true ||
    verification.structural_self_integrity_verified !== true ||
    verification.authority_grant_status !== 'exhausted' ||
    verification.authority_grant_status_reason_code !==
      'authority_grant_contract_exhausted'
  ) {
    throw new Error(
      'Named deployment profile readiness committed terminal artifact identity is not pinned',
    );
  }
  return { artifact, verification };
}

export function buildProtectedRecordsNamedDeploymentProfileReadiness({
  terminalChainArtifact,
} = {}) {
  const source = terminalChainArtifact
    ? {
        artifact: terminalChainArtifact,
        verification:
          verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(
            terminalChainArtifact,
            {
              expectedArtifactBodySha256:
                PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
            },
          ),
      }
    : readPinnedCommittedTerminalArtifact();
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification(
    source.verification,
  );
  if (
    source.verification.artifact_identity_sha256_matched !== true ||
    source.verification.structural_self_integrity_verified !== true ||
    source.verification.authority_grant_status !== 'exhausted' ||
    source.verification.authority_grant_status_reason_code !==
      'authority_grant_contract_exhausted'
  ) {
    throw new Error(
      'Named deployment profile readiness terminal artifact identity is not pinned',
    );
  }
  const chain = source.artifact.payload.chain;
  assertProtectedRecordsInstalledRuntimeProfileTerminalChain(chain);
  const service = chain.generated_service_proof;
  const sideDoor = chain.side_door_report;

  const report = {
    report_type: PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_READINESS_REPORT_TYPE,
    schema_version: 1,
    evidence_model: 'pinned-committed-terminal-artifact-read-only-rehearsal',
    live_probing: false,
    safe_claim: PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_SAFE_CLAIM,
    selected_deployment_profile: {
      profile_id: PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID,
      profile_status: 'rehearsal_not_installed',
      deployment_profile_class: 'named-private-operator-protected-records-terminal',
      action_class: 'records.write',
      downstream_boundary: 'protected-records-runtime-service:local-jsonl-child-process',
      source_terminal_surface_id: 'protected-records.runtime.profile-installation.records.write',
    },
    source_terminal_chain: {
      source_mode: 'pinned-committed-historical-artifact-verification',
      terminal_artifact_body_sha256: source.verification.body_sha256,
      terminal_artifact_identity_sha256_matched:
        source.verification.artifact_identity_sha256_matched,
      authority_grant_status: source.verification.authority_grant_status,
      fresh_fixture_rightful_projection_allowed:
        source.verification
          .authority_grant_status_allows_fixture_rightful_projection,
      authority_grant_status_reason_code:
        source.verification.authority_grant_status_reason_code,
      chain_type: chain.chain_type,
      evidence_model: chain.evidence_model,
      chain_sha256: sha256hex(canonicalize(chain)),
      service_proof_type: service.proof_type,
      service_artifact_body_sha256: service.artifact_body_sha256,
      recognition_contract_sha256: service.recognition_contract_sha256,
      refusal_case_count:
        service.recognition_refusal_case_count +
        service.authority_refusal_case_count,
      all_refusals_before_mutation:
        service.all_recognition_refusals_before_mutation === true &&
        service.all_authority_refusals_before_consumption_and_mutation === true,
      missing_receipt_refused: service.missing_receipt_refused,
      invalid_receipt_refused: service.invalid_receipt_refused,
      no_usable_recognized_receipt_authority_refused:
        groupRefused(chain, 'no_usable_recognized_receipt_authority'),
      recognized_receipt_scope_mismatch_refused:
        groupRefused(chain, 'recognized_receipt_scope_mismatch'),
      route_or_request_authority_material_refused:
        groupRefused(chain, 'route_or_request_authority_material_refused'),
      recognized_write_boarded: service.recognized_write_boarded,
      same_process_replay_refused:
        service.same_process_signed_payload_replay_refused,
      restart_replay_refused:
        service.restart_consumed_authority_grant_refused,
      runtime_service_started: service.runtime_service_started,
      disposable_runtime_config_written: service.disposable_runtime_config_written,
      persistent_runtime_config_written: service.persistent_runtime_config_written,
      current_machine_governance_proven: service.current_machine_governance_proven,
      production_downstream_recognition: service.production_downstream_recognition,
      external_attestation: service.external_attestation,
    },
    acceptance_gates: {
      named_deployment_profile_declared: true,
      downstream_boundary_named: true,
      missing_receipt_refused_before_mutation: service.missing_receipt_refused === true,
      unrecognized_receipt_refused_before_mutation:
        groupRefused(chain, 'no_usable_recognized_receipt_authority'),
      out_of_scope_receipt_refused_before_mutation:
        groupRefused(chain, 'recognized_receipt_scope_mismatch'),
      request_authority_material_refused_before_mutation:
        groupRefused(chain, 'route_or_request_authority_material_refused'),
      recognized_receipt_mutates_once_rehearsed:
        service.recognized_write_boarded === true &&
        service.same_process_signed_payload_replay_refused === true &&
        service.restart_consumed_authority_grant_refused === true,
      no_persistent_runtime_profile_install: sideDoor.persistent_runtime_profile_installed === false,
      no_persistent_runtime_config: service.persistent_runtime_config_written === false,
      no_current_machine_governance_claim: service.current_machine_governance_proven === false,
      no_production_downstream_claim: service.production_downstream_recognition === false,
      no_external_attestation_claim: service.external_attestation === false,
    },
    next_authority_crossing: {
      required_before_real_deployment_profile_claim: true,
      crossing_class: 'install-config-current-machine-or-equivalent-real-deployment-boundary',
      human_authority_required: true,
      reason:
        'A named profile becomes real only when a deployment boundary or current-machine install/config path makes it active before consequence.',
    },
    claim_boundary: {
      local_rehearsal_only: true,
      active_deployment_profile: false,
      persistent_runtime_profile_installation: false,
      hook_configuration_written: false,
      user_config_written: false,
      machine_config_written: false,
      real_personal_files_touched: false,
      live_records_system_checked: false,
      production_downstream_recognition: false,
      production_authority: false,
      enterprise_readiness: false,
      current_machine_governance: false,
      public_external_attestation: false,
      sovereign_recognition: false,
      all_surface_governance: false,
      side_door_closure: false,
      absolute_human_intention: false,
    },
    non_claims: [...PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_NON_CLAIMS],
  };
  assertProtectedRecordsNamedDeploymentProfileReadiness(report);
  return report;
}

export function assertProtectedRecordsNamedDeploymentProfileReadiness(report) {
  exactKeys('named deployment profile readiness report', report, [
    'acceptance_gates',
    'claim_boundary',
    'evidence_model',
    'live_probing',
    'next_authority_crossing',
    'non_claims',
    'report_type',
    'safe_claim',
    'schema_version',
    'selected_deployment_profile',
    'source_terminal_chain',
  ]);
  if (
    report.report_type !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_READINESS_REPORT_TYPE ||
    report.schema_version !== 1 ||
    report.evidence_model !== 'pinned-committed-terminal-artifact-read-only-rehearsal' ||
    report.live_probing !== false ||
    report.safe_claim !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_SAFE_CLAIM
  ) {
    throw new Error('named deployment profile readiness top-level contract drifted');
  }

  exactKeys('named deployment profile readiness selected deployment profile', report.selected_deployment_profile, [
    'action_class',
    'deployment_profile_class',
    'downstream_boundary',
    'profile_id',
    'profile_status',
    'source_terminal_surface_id',
  ]);
  if (
    report.selected_deployment_profile.profile_id !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID ||
    report.selected_deployment_profile.profile_status !== 'rehearsal_not_installed' ||
    report.selected_deployment_profile.deployment_profile_class !== 'named-private-operator-protected-records-terminal' ||
    report.selected_deployment_profile.action_class !== 'records.write' ||
    report.selected_deployment_profile.downstream_boundary !== 'protected-records-runtime-service:local-jsonl-child-process' ||
    report.selected_deployment_profile.source_terminal_surface_id !== 'protected-records.runtime.profile-installation.records.write'
  ) {
    throw new Error('named deployment profile selected profile drifted');
  }

  exactKeys('named deployment profile readiness source terminal chain', report.source_terminal_chain, [
    'all_refusals_before_mutation',
    'authority_grant_status',
    'authority_grant_status_reason_code',
    'chain_sha256',
    'chain_type',
    'current_machine_governance_proven',
    'disposable_runtime_config_written',
    'evidence_model',
    'external_attestation',
    'fresh_fixture_rightful_projection_allowed',
    'invalid_receipt_refused',
    'missing_receipt_refused',
    'no_usable_recognized_receipt_authority_refused',
    'persistent_runtime_config_written',
    'production_downstream_recognition',
    'recognized_receipt_scope_mismatch_refused',
    'recognized_write_boarded',
    'recognition_contract_sha256',
    'refusal_case_count',
    'restart_replay_refused',
    'route_or_request_authority_material_refused',
    'runtime_service_started',
    'same_process_replay_refused',
    'service_artifact_body_sha256',
    'service_proof_type',
    'source_mode',
    'terminal_artifact_body_sha256',
    'terminal_artifact_identity_sha256_matched',
  ]);
  if (
    report.source_terminal_chain.source_mode !==
      'pinned-committed-historical-artifact-verification'
  ) {
    throw new Error('named deployment profile terminal source mode drifted');
  }
  expectSha(
    'terminal artifact body SHA-256',
    report.source_terminal_chain.terminal_artifact_body_sha256,
  );
  if (
    report.source_terminal_chain.terminal_artifact_body_sha256 !==
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256
  ) {
    throw new Error('named deployment profile terminal artifact identity drifted');
  }
  expectBool(
    'terminal artifact identity matched',
    report.source_terminal_chain.terminal_artifact_identity_sha256_matched,
    true,
  );
  if (
    report.source_terminal_chain.authority_grant_status !== 'exhausted' ||
    report.source_terminal_chain.authority_grant_status_reason_code !==
      'authority_grant_contract_exhausted'
  ) {
    throw new Error('named deployment profile authority grant status drifted');
  }
  expectBool(
    'fresh fixture rightful projection allowed',
    report.source_terminal_chain.fresh_fixture_rightful_projection_allowed,
    false,
  );
  expectString('source terminal chain chain type', report.source_terminal_chain.chain_type);
  expectString('source terminal chain evidence model', report.source_terminal_chain.evidence_model);
  expectSha('source terminal chain hash', report.source_terminal_chain.chain_sha256);
  expectSha('service artifact body SHA-256', report.source_terminal_chain.service_artifact_body_sha256);
  expectSha('recognition contract SHA-256', report.source_terminal_chain.recognition_contract_sha256);
  if (report.source_terminal_chain.service_proof_type !== 'zlar-protected-records-installed-runtime-profile-service-proof-v1') {
    throw new Error('named deployment profile service proof type drifted');
  }
  if (report.source_terminal_chain.refusal_case_count < 18) {
    throw new Error('named deployment profile refusal taxonomy is too small');
  }
  for (const key of [
    'all_refusals_before_mutation',
    'missing_receipt_refused',
    'invalid_receipt_refused',
    'no_usable_recognized_receipt_authority_refused',
    'recognized_receipt_scope_mismatch_refused',
    'route_or_request_authority_material_refused',
    'recognized_write_boarded',
    'same_process_replay_refused',
    'restart_replay_refused',
    'runtime_service_started',
    'disposable_runtime_config_written',
  ]) {
    expectBool(`source terminal chain ${key}`, report.source_terminal_chain[key], true);
  }
  for (const key of [
    'persistent_runtime_config_written',
    'current_machine_governance_proven',
    'production_downstream_recognition',
    'external_attestation',
  ]) {
    expectBool(`source terminal chain ${key}`, report.source_terminal_chain[key], false);
  }

  exactKeys('named deployment profile readiness acceptance gates', report.acceptance_gates, [
    'downstream_boundary_named',
    'missing_receipt_refused_before_mutation',
    'named_deployment_profile_declared',
    'no_current_machine_governance_claim',
    'no_external_attestation_claim',
    'no_persistent_runtime_config',
    'no_persistent_runtime_profile_install',
    'no_production_downstream_claim',
    'out_of_scope_receipt_refused_before_mutation',
    'recognized_receipt_mutates_once_rehearsed',
    'request_authority_material_refused_before_mutation',
    'unrecognized_receipt_refused_before_mutation',
  ]);
  for (const [key, value] of Object.entries(report.acceptance_gates)) {
    expectBool(`acceptance gate ${key}`, value, true);
  }

  exactKeys('named deployment profile readiness next authority crossing', report.next_authority_crossing, [
    'crossing_class',
    'human_authority_required',
    'reason',
    'required_before_real_deployment_profile_claim',
  ]);
  expectBool('next authority crossing required', report.next_authority_crossing.required_before_real_deployment_profile_claim, true);
  expectBool('next authority crossing human required', report.next_authority_crossing.human_authority_required, true);
  expectString('next authority crossing class', report.next_authority_crossing.crossing_class);
  expectString('next authority crossing reason', report.next_authority_crossing.reason);

  exactKeys('named deployment profile readiness claim boundary', report.claim_boundary, [
    'absolute_human_intention',
    'active_deployment_profile',
    'all_surface_governance',
    'current_machine_governance',
    'enterprise_readiness',
    'hook_configuration_written',
    'live_records_system_checked',
    'local_rehearsal_only',
    'machine_config_written',
    'persistent_runtime_profile_installation',
    'production_authority',
    'production_downstream_recognition',
    'public_external_attestation',
    'real_personal_files_touched',
    'side_door_closure',
    'sovereign_recognition',
    'user_config_written',
  ]);
  expectBool('claim boundary local rehearsal only', report.claim_boundary.local_rehearsal_only, true);
  for (const [key, value] of Object.entries(report.claim_boundary)) {
    if (key !== 'local_rehearsal_only') {
      expectBool(`claim boundary ${key}`, value, false);
    }
  }

  if (
    !Array.isArray(report.non_claims) ||
    report.non_claims.length !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_NON_CLAIMS.length ||
    report.non_claims.some((claim, index) => claim !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_NON_CLAIMS[index])
  ) {
    throw new Error('named deployment profile non-claims drifted');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return true;
}

export function formatProtectedRecordsNamedDeploymentProfileReadiness(report) {
  assertProtectedRecordsNamedDeploymentProfileReadiness(report);
  return [
    'ZLAR Protected Records Named Deployment Profile Readiness v1',
    `report_type=${report.report_type}`,
    `evidence_model=${report.evidence_model}`,
    `profile_id=${report.selected_deployment_profile.profile_id}`,
    `profile_status=${report.selected_deployment_profile.profile_status}`,
    `action_class=${report.selected_deployment_profile.action_class}`,
    `downstream_boundary=${report.selected_deployment_profile.downstream_boundary}`,
    `source_mode=${report.source_terminal_chain.source_mode}`,
    `terminal_artifact_body_sha256=${report.source_terminal_chain.terminal_artifact_body_sha256}`,
    `terminal_artifact_identity_sha256_matched=${report.source_terminal_chain.terminal_artifact_identity_sha256_matched}`,
    `authority_grant_status=${report.source_terminal_chain.authority_grant_status}`,
    `fresh_fixture_rightful_projection_allowed=${report.source_terminal_chain.fresh_fixture_rightful_projection_allowed}`,
    `authority_grant_status_reason_code=${report.source_terminal_chain.authority_grant_status_reason_code}`,
    `missing_receipt_refused=${report.source_terminal_chain.missing_receipt_refused}`,
    `unrecognized_receipt_refused=${report.source_terminal_chain.no_usable_recognized_receipt_authority_refused}`,
    `out_of_scope_receipt_refused=${report.source_terminal_chain.recognized_receipt_scope_mismatch_refused}`,
    `recognized_receipt_mutates_once_rehearsed=${report.acceptance_gates.recognized_receipt_mutates_once_rehearsed}`,
    `active_deployment_profile=${report.claim_boundary.active_deployment_profile}`,
    `persistent_runtime_profile_installation=${report.claim_boundary.persistent_runtime_profile_installation}`,
    `current_machine_governance=${report.claim_boundary.current_machine_governance}`,
    `production_downstream_recognition=${report.claim_boundary.production_downstream_recognition}`,
    `enterprise_readiness=${report.claim_boundary.enterprise_readiness}`,
    `next_authority_crossing=${report.next_authority_crossing.crossing_class}`,
  ].join('\n') + '\n';
}
