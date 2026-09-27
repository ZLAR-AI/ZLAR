import { readFileSync } from 'node:fs';
import { canonicalize, sha256hex } from './receipt.mjs';
import {
  assertGovernedSurfaceCoverageMap,
} from './governed-surface-coverage-map.mjs';
import {
  CONSEQUENCE_LIFECYCLE_PINNED_TERMINAL_ARTIFACT_BODY_SHA256,
  assertConsequenceLifecycleMap,
  buildConsequenceLifecycleMap,
  consequenceLifecycleMapSha256,
} from './consequence-lifecycle-map.mjs';
import {
  LOCAL_PROOF_PACK_ARTIFACT_VERIFICATION_TYPE,
  assertNoUnsafeLocalProofPackText,
  parseLocalProofPackArtifactText,
} from './local-proof-pack.mjs';
import {
  RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_SCOPE,
  RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_TYPE,
  RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY,
} from './records-write-terminal-proof.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE,
} from './protected-records-runtime-activation-preflight.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_VERIFICATION_TYPE,
} from './protected-records-runtime-local-activation.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_VERIFICATION_TYPE,
} from './protected-records-runtime-profile-installation.mjs';
import {
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_EVIDENCE_MODEL,
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY,
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_TYPE,
  REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES,
  claudeCodeHookContractReplayContractSha256,
  claudeCodeHookContractReplayRepoAdapterSha256,
} from './claude-code-hook-contract-replay-proof.mjs';
import {
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
} from './protected-records-installed-runtime-profile-preflight.mjs';
import {
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProof,
} from './protected-records-installed-runtime-profile-recognition-proof.mjs';
import {
  assertProtectedRecordsInstalledRuntimeProfileServiceProof,
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification,
} from './protected-records-installed-runtime-profile-service-proof.mjs';
import {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChain,
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification,
  protectedRecordsInstalledRuntimeProfileTerminalChainArtifactBodySha256,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS,
} from './protected-records-installed-runtime-profile-terminal-chain.mjs';
import {
  REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES,
} from './protected-records-one-terminal-deployment-profile.mjs';
import {
  PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE,
} from './protected-records-service-profile.mjs';
import {
  REQUIRED_REFUSAL_REASONS as DOWNSTREAM_REFUSAL_REASONS,
} from './downstream-refusal-proof.mjs';
import {
  assertConfiguredRecognitionConsumerReplayStoreProof,
} from './zlar-configured-recognition-consumer-replay-store-proof.mjs';
import {
  assertSourceBridgeWindowAuthorityReport,
} from './zlar-source-bridge-window-authority.mjs';
import {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed,
} from './protected-records-fixture-authority-status.mjs';

export const PROOF_SMOKE_REPORT_TYPE = 'zlar-proof-smoke-v1';
export const PROOF_SMOKE_EVIDENCE_MODEL = 'committed-local-fixtures';
export const PROOF_SMOKE_CLAIM_BOUNDARY =
  'current proof-smoke execution and legacy fixture-rightful report acceptance are refused before consequence execution because the exact one-use fixture authority grant is exhausted; committed artifacts remain historical structural boarding and refusal evidence only';

export const PROOF_SMOKE_NON_CLAIMS = Object.freeze([
  'This smoke test does not inspect live hooks, live audit stores, runtime state, or live downstream systems.',
  'This smoke test is not currently executable as a positive fixture-rightful proof: the exact one-use grant is exhausted and repeated-use provenance is invalid.',
  'This smoke test does not run the proof pack or generate fresh proof-pack, key-state, receipt-verifier, service-profile preflight, activation-preflight, runtime-local-activation, or runtime-profile-installation evidence. It runs fresh local disposable installed-runtime-profile recognition, local disposable child-service, and local disposable installed-terminal-chain proofs plus artifact verification from committed sample plan/profile input only; it does not inspect live or non-sample recognition state.',
  'This smoke test verifies embedded active-profile selection, disposable installed-profile selection, read-only local disposable installed-runtime-profile preflight selection, local hermetic installed-profile recognition refusal, local disposable installed-profile child-service refusal, child-service proof artifact verification, fresh local disposable installed-terminal-chain refusal, and terminal-chain artifact verification only; it does not install a persistent runtime profile, activate a runtime profile, write hook/user/machine configuration, select a latest profile, inspect live runtime profile state, or prove current-machine governance.',
  'This smoke test verifies embedded trusted-issuer registry recognition over a bundled local fixture only; it does not inspect live trust-registry state, live issuer status, key custody, revocation truth, production downstream recognition, production authority, public external attestation, real non-operator review, or sovereign recognition.',
  'This smoke test verifies a committed key-state sample summary; it does not inspect operator home key material, hardware, key custody, revocation truth, production trust registry state, or current-machine governance.',
  'This smoke test verifies embedded local Claude hook-contract replay summary and case-evidence hash only; it does not invoke Claude, prove live Claude app passage, prove app-originated hook crossing, prove current-machine governance, emit a live receipt, or close side doors.',
  'This smoke test verifies a local fake configured-recognition consumer replay-store proof only; it does not prove production durable replay persistence, tamper resistance, multi-host replay coordination, real downstream recognition/refusal/effect, real receipt validity, registry activation, source movement governance, or production trust.',
  'This smoke test verifies a no-secret source bridge window authority sample only; it does not read remote refs, push source, prove deploy-key state, prove a live source bridge window, change GitHub settings, or prove durable source transport.',
  'Exact SHA pinning preserves artifact identity, historical boarding, and refusal facts; it does not restore fixture-rightful issuance under an exhausted grant or prove generic, portable, live, production, or current-machine rightful issuance.',
  'This smoke test preserves signed-payload replay and consumed-authority-grant replay as different identities, names both burn windows, and leaves joint rollback, host-filesystem TOCTOU, recovery, equivalent routes, and consequence-lifecycle closure open.',
  'This smoke test does not prove production deployment, external attestation, sovereign recognition, or coverage of unrouted surfaces.',
]);

export const PROOF_SMOKE_SAMPLE_REPORT_PATH = 'tests/fixtures/proof-smoke-v1-report.json';
export const PROOF_SMOKE_HISTORICAL_REPORT_VERIFICATION_TYPE =
  'zlar-proof-smoke-historical-report-verification-v2';
export const PROOF_SMOKE_HISTORICAL_V1_SAMPLE_FILE_SHA256 =
  'de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268';
export const PROOF_SMOKE_HISTORICAL_V1_SAMPLE_REPORT_SHA256 =
  '8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80';
export const PROOF_SMOKE_HISTORICAL_V1_LOCAL_PROOF_PACK_FILE_SHA256 =
  '331dbdae86c373e814622fc53c2969ae112d01794f832e9ca2c945a63bd1384e';
export const PROOF_SMOKE_HISTORICAL_V1_LOCAL_PROOF_PACK_BODY_SHA256 =
  'e24adc1735216e20dfb321db473cd58f6ca1b817c93d75e8b83ccf02a9622186';
export const PROOF_SMOKE_HISTORICAL_V1_DOWNSTREAM_SERVICE_COMPONENT_SHA256 =
  '51ec357ec3499b33abb27cbca6d9b24b1a717f7ee4aeda62edb1cb8ced324b3d';
export const PROOF_SMOKE_HISTORICAL_V1_SERVICE_PREFLIGHT_FILE_SHA256 =
  '5d15cc460d2cd981cdcd21999629969b87af798a6311b80fe699ec78aba7b7f2';
export const PROOF_SMOKE_HISTORICAL_V1_SERVICE_PREFLIGHT_BODY_SHA256 =
  '36a3aadfa920ea3da2ac3199b5af79f937e783e42604bfa3318d6ac8824b190c';
export const PROOF_SMOKE_HISTORICAL_V1_TERMINAL_CHAIN_BODY_SHA256 =
  '49eb293e730cccf8a67e53c6f792066645fb25f7b5ab184d2c2031e54f87d18d';
export const PROOF_SMOKE_HISTORICAL_VERIFICATION_CLAIM_BOUNDARY =
  'exact-pinned proof-smoke v1 historical report structure and embedded verification identities only; no fresh proof execution, source freshness, current coverage, current authority, current fixture-rightful issuance, lifecycle closure, or consequence projection';

const PROOF_SMOKE_HISTORICAL_V1_STEP_IDS = Object.freeze([
  'sample_artifact_verification',
  'service_profile_preflight_sample_artifact_verification',
  'activation_preflight_sample_artifact_verification',
  'runtime_local_activation_sample_artifact_verification',
  'runtime_profile_installation_sample_artifact_verification',
  'installed_runtime_profile_preflight_sample_artifact_verification',
  'installed_runtime_profile_recognition_proof',
  'installed_runtime_profile_service_proof',
  'installed_runtime_profile_service_proof_artifact_verification',
  'installed_runtime_profile_terminal_chain',
  'installed_runtime_profile_terminal_chain_artifact_verification',
  'configured_recognition_consumer_replay_store_proof',
  'source_bridge_window_authority_sample',
  'fixture_input_coverage_map',
  'consequence_lifecycle_map_projection',
]);

export function proofSmokeReportSha256(report) {
  return sha256hex(canonicalize(report));
}

function requireHistoricalSha256(label, value) {
  if (!/^[a-f0-9]{64}$/.test(value || '')) {
    throw new Error(`${label} must be a 64-character lowercase SHA-256 hex digest`);
  }
  return value;
}

export function verifyHistoricalProofSmokeReportText(
  text,
  {
    expectedFileSha256,
    expectedReportSha256,
  } = {},
) {
  if (typeof text !== 'string') {
    throw new Error('Historical proof smoke report input must be text');
  }
  assertNoUnsafeProofSmokeReportText(text);
  requireHistoricalSha256('Historical proof smoke expected file identity', expectedFileSha256);
  requireHistoricalSha256('Historical proof smoke expected report identity', expectedReportSha256);
  if (expectedFileSha256 !== PROOF_SMOKE_HISTORICAL_V1_SAMPLE_FILE_SHA256) {
    throw new Error('Historical proof smoke expected file identity is not the pinned v1 sample');
  }
  if (expectedReportSha256 !== PROOF_SMOKE_HISTORICAL_V1_SAMPLE_REPORT_SHA256) {
    throw new Error('Historical proof smoke expected report identity is not the pinned v1 sample');
  }

  const fileSha256 = sha256hex(text);
  if (fileSha256 !== expectedFileSha256) {
    throw new Error('Historical proof smoke report file SHA-256 does not match the caller-pinned identity');
  }

  let report;
  try {
    report = JSON.parse(text);
  } catch {
    throw new Error('Historical proof smoke report input is not valid JSON');
  }
  assertExactObjectKeys('Historical proof smoke v1 report', report, [
    'claim_boundary',
    'counts',
    'evidence_model',
    'live_probing',
    'non_claims',
    'report_type',
    'result',
    'steps',
  ]);
  if (
    report.report_type !== PROOF_SMOKE_REPORT_TYPE ||
    report.result !== 'passed' ||
    report.evidence_model !== PROOF_SMOKE_EVIDENCE_MODEL ||
    report.live_probing !== false ||
    !Array.isArray(report.steps) ||
    report.steps.length !== PROOF_SMOKE_HISTORICAL_V1_STEP_IDS.length ||
    !Array.isArray(report.non_claims)
  ) {
    throw new Error('Historical proof smoke v1 structural contract drifted');
  }
  const stepIds = report.steps.map((step) => step?.step);
  if (JSON.stringify(stepIds) !== JSON.stringify(PROOF_SMOKE_HISTORICAL_V1_STEP_IDS)) {
    throw new Error('Historical proof smoke v1 ordered step contract drifted');
  }
  if (report.steps.some((step) => step?.result !== 'passed')) {
    throw new Error('Historical proof smoke v1 contains a non-passing historical step');
  }

  const localProofPack = report.steps[0]?.verification;
  const servicePreflight = report.steps[1]?.verification;
  const terminalChain = report.steps[10]?.verification;
  const lifecycle = report.steps[14]?.lifecycle_map;
  const downstreamServiceComponent = localProofPack?.component_manifest?.find(
    (entry) => entry?.component === 'protected_records_downstream_service',
  );
  if (
    localProofPack?.verified !== true ||
    localProofPack?.body_sha256 !== PROOF_SMOKE_HISTORICAL_V1_LOCAL_PROOF_PACK_BODY_SHA256 ||
    localProofPack?.body_sha256 !== localProofPackSampleArtifactBodySha256() ||
    localProofPack?.fresh_proof_pack_run_performed !== false ||
    downstreamServiceComponent?.component_sha256 !== PROOF_SMOKE_HISTORICAL_V1_DOWNSTREAM_SERVICE_COMPONENT_SHA256 ||
    servicePreflight?.verified !== true ||
    servicePreflight?.body_sha256 !== PROOF_SMOKE_HISTORICAL_V1_SERVICE_PREFLIGHT_BODY_SHA256 ||
    servicePreflight?.body_sha256 !== serviceProfilePreflightSampleArtifactBodySha256() ||
    servicePreflight?.live_probing !== false ||
    terminalChain?.verified !== true ||
    terminalChain?.body_sha256 !== PROOF_SMOKE_HISTORICAL_V1_TERMINAL_CHAIN_BODY_SHA256 ||
    terminalChain?.consequence_lifecycle_closed !== false ||
    terminalChain?.current_machine_governance_proven !== false ||
    terminalChain?.production_downstream_recognition !== false ||
    lifecycle?.map_status !== 'mapped_open'
  ) {
    throw new Error('Historical proof smoke v1 embedded verification identity drifted');
  }

  const reportSha256 = proofSmokeReportSha256(report);
  if (reportSha256 !== expectedReportSha256) {
    throw new Error('Historical proof smoke canonical report SHA-256 does not match the caller-pinned identity');
  }

  return {
    verification_type: PROOF_SMOKE_HISTORICAL_REPORT_VERIFICATION_TYPE,
    verified: true,
    historical_only: true,
    historical_schema: PROOF_SMOKE_REPORT_TYPE,
    structural_self_integrity_verified: true,
    ordered_step_contract_verified: true,
    embedded_verification_identities_verified: true,
    immutable_historical_inputs: {
      local_proof_pack: {
        file_sha256: PROOF_SMOKE_HISTORICAL_V1_LOCAL_PROOF_PACK_FILE_SHA256,
        body_sha256: PROOF_SMOKE_HISTORICAL_V1_LOCAL_PROOF_PACK_BODY_SHA256,
        embedded_downstream_service_component_sha256:
          PROOF_SMOKE_HISTORICAL_V1_DOWNSTREAM_SERVICE_COMPONENT_SHA256,
        embedded_body_identity_verified: true,
        embedded_component_identity_verified: true,
        external_file_bytes_read_by_this_verifier: false,
      },
      service_preflight: {
        file_sha256: PROOF_SMOKE_HISTORICAL_V1_SERVICE_PREFLIGHT_FILE_SHA256,
        body_sha256: PROOF_SMOKE_HISTORICAL_V1_SERVICE_PREFLIGHT_BODY_SHA256,
        embedded_body_identity_verified: true,
        external_file_bytes_read_by_this_verifier: false,
      },
      proof_smoke_report: {
        file_sha256: PROOF_SMOKE_HISTORICAL_V1_SAMPLE_FILE_SHA256,
        report_sha256: PROOF_SMOKE_HISTORICAL_V1_SAMPLE_REPORT_SHA256,
        caller_pinned_file_identity_verified: true,
        caller_pinned_report_identity_verified: true,
      },
    },
    file_sha256: fileSha256,
    required_file_sha256: expectedFileSha256,
    required_file_sha256_matched: true,
    report_sha256: reportSha256,
    required_report_sha256: expectedReportSha256,
    required_report_sha256_matched: true,
    report_type: report.report_type,
    evidence_model: report.evidence_model,
    live_probing: false,
    fresh_proof_execution_performed: false,
    source_freshness_proven: false,
    current_coverage_projected: false,
    current_authority_proven: false,
    current_fixture_rightful_issuance_projected: false,
    current_effect_projected: false,
    consequence_lifecycle_closed: false,
    current_projection_allowed: false,
    historical_positive_fields_preserved_as_artifact_content_only: true,
    historical_counts_evidence_class: 'historical-non-scoring-artifact-content',
    historical_counts: report.counts,
    claim_boundary: PROOF_SMOKE_HISTORICAL_VERIFICATION_CLAIM_BOUNDARY,
    non_claims: [
      'Historical proof-smoke verification does not run any proof or consequence generator.',
      'Historical positive fields do not project current authority, current rightful issuance, current effect, source freshness, or current coverage.',
      'An exact historical file or report identity does not reactivate or legitimize an exhausted authority grant.',
    ],
  };
}

function assertObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function assertExactObjectKeys(label, value, expectedKeys) {
  assertObject(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} has unexpected fields: expected ${expected.join(',')}; got ${actual.join(',')}`);
  }
}

function recognitionRefusalGroupCaseIds(groups) {
  return Object.fromEntries(
    Object.keys(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS)
      .map((groupName) => [
        groupName,
        Array.isArray(groups?.[groupName]?.cases)
          ? groups[groupName].cases.map((item) => item.case_id)
          : [],
      ])
  );
}

function recognitionRefusalGroupCaseCount(groups) {
  return Object.values(recognitionRefusalGroupCaseIds(groups))
    .reduce((total, caseIds) => total + caseIds.length, 0);
}

function recognitionRefusalGroupCaseIdsMatch(value, groups) {
  return JSON.stringify(value) === JSON.stringify(recognitionRefusalGroupCaseIds(groups));
}

function trustedIssuerRegistryRecognitionRefusalCases(binding) {
  return Array.isArray(binding?.trusted_issuer_registry_recognition_refusals?.cases)
    ? binding.trusted_issuer_registry_recognition_refusals.cases
    : [];
}

function trustedIssuerRegistryRecognitionRefusalCaseIds(binding) {
  return trustedIssuerRegistryRecognitionRefusalCases(binding)
    .map((item) => item.case_id);
}

function trustedIssuerRegistryRecognitionRefusalReasonCodes(binding) {
  return trustedIssuerRegistryRecognitionRefusalCases(binding)
    .map((item) => item.reason_code);
}

function recognizedReceiptPathEvidencePreserved(evidence, binding, bindingSha256) {
  return (
    evidence?.component === 'terminal_chain_recognized_receipt_path_evidence' &&
    evidence?.evidence_model ===
      'artifact-owned-public-safe-local-fixture-recognized-receipt-path-v1' &&
    evidence?.evidence_scope ===
      'protected-records.installed-runtime-profile.terminal-chain.records.write' &&
    /^[a-f0-9]{64}$/.test(evidence?.source_binding_sha256 || '') &&
    evidence.source_binding_sha256 === bindingSha256 &&
    evidence.source_binding_sha256 === binding?.binding_sha256 &&
    evidence.registry_fixture_contract_sha256 === binding?.registry_fixture_contract_sha256 &&
    evidence.receipt_payload_contract_sha256 === binding?.receipt_payload_contract_sha256 &&
    evidence.receipt_audit_event_id === binding?.receipt_audit_event_id &&
    evidence.receipt_detail_hash === binding?.receipt_detail_hash &&
    evidence.selected_profile_sha256 === binding?.selected_profile_sha256 &&
    evidence.recognition_contract_sha256 === binding?.selected_profile_recognition_contract_sha256 &&
    evidence.recognition_contract_sha256 === binding?.service_recognition_contract_sha256 &&
    evidence.generated_preflight_artifact_body_sha256 ===
      binding?.generated_preflight_artifact_body_sha256 &&
    evidence.generated_service_proof_artifact_body_sha256 ===
      binding?.generated_service_proof_artifact_body_sha256 &&
    evidence.service_artifact_verification_body_sha256 ===
      binding?.service_artifact_verification_body_sha256 &&
    evidence.verdict === 'RECOGNIZED' &&
    evidence.recognized === true &&
    evidence.decision === 'accept' &&
    evidence.reason_code === 'recognized' &&
    evidence.issuer_status === 'active' &&
    evidence.signature_valid === true &&
    evidence.registry_fixture_validated === true &&
    evidence.registry_fixture_evaluated === true &&
    evidence.registry_to_recognition_rule_evaluated === true &&
    evidence.registry_evaluation_result_type === 'downstream-recognition-rule-v1' &&
    evidence.registry_trusted_issuer_count === 1 &&
    evidence.registry_receipt_contract_hash_bound === true &&
    evidence.required_audit_event_id_bound === true &&
    evidence.required_detail_hash_bound === true &&
    evidence.selected_profile_hash_bound === true &&
    evidence.recognition_contract_hash_bound === true &&
    evidence.service_artifact_hash_bound === true &&
    evidence.terminal_chain_decision_bound === true &&
    evidence.recognized_write_boarded === true &&
    evidence.registry_public_key_material_included === false &&
    evidence.receipt_envelope_included === false &&
    evidence.cryptographic_evidence_reproducible_from_artifact === false &&
    evidence.live_trust_registry_state === false &&
    evidence.live_issuer_status_proven === false &&
    evidence.key_custody_proven === false &&
    evidence.revocation_truth_proven === false &&
    evidence.production_downstream_recognition_proven === false &&
    evidence.public_external_attestation === false &&
    evidence.sovereign_recognition === false &&
    evidence.current_machine_governance_proven === false
  );
}

function expectedTrustedIssuerRegistryRecognitionRefusalCaseIds() {
  return REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS
    .map((item) => item.case_id);
}

function expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes() {
  return REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS
    .map((item) => item.reason_code);
}

function deploymentProfileAuthorityRefusalMirrorPreserved(mirror) {
  return (
    mirror?.source === 'committed-one-terminal-deployment-profile-fixture' &&
    mirror?.source_proof_type ===
      'zlar-protected-records-one-terminal-deployment-profile-proof-v1' &&
    mirror?.evidence_model ===
      'local-fixture-one-terminal-deployment-profile-authority-bridge' &&
    mirror?.local_fixture_only === true &&
    mirror?.mirrored_from_one_terminal_deployment_profile === true &&
    mirror?.source_runtime_profile_sha_matches_terminal_chain === true &&
    mirror?.deployment_profile_authority_refusal_case_count ===
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length &&
    JSON.stringify(mirror?.deployment_profile_authority_refusal_case_ids) ===
      JSON.stringify(REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES) &&
    mirror?.deployment_profile_authority_refusals_before_service_proof === true &&
    mirror?.deployment_profile_authority_refusals_before_mutation === true &&
    mirror?.deployment_profile_authority_refusal_service_proof_started === false &&
    mirror?.stale_deployment_profile_artifact_refused_before_service_proof === true &&
    mirror?.profile_recognition_mismatch_refused_before_service_proof === true &&
    mirror?.latest_profile_selection_refused_before_service_proof === true &&
    mirror?.request_stream_authority_material_refused_before_service_proof === true &&
    mirror?.current_machine_governance === false &&
    mirror?.production_downstream_recognition === false &&
    mirror?.production_authority === false &&
    mirror?.enterprise_readiness === false &&
    mirror?.external_attestation === false &&
    mirror?.sovereign_recognition === false &&
    mirror?.unrouted_surface_coverage === false
  );
}

function terminalChainArtifactVerificationMatchesChainBoundary(verification, chain) {
  const terminalChain = chain?.terminal_chain;
  return (
    terminalChain &&
    verification.generated_installed_root_preflighted ===
      terminalChain.generated_installed_root_preflighted &&
    verification.generated_preflight_artifact_consumed_by_service_proof ===
      terminalChain.generated_preflight_artifact_consumed_by_service_proof &&
    verification.generated_service_proof_artifact_verified ===
      terminalChain.generated_service_proof_artifact_verified &&
    verification.service_proof_bound_to_generated_preflight ===
      terminalChain.service_proof_bound_to_generated_preflight &&
    verification.service_artifact_verification_bound_to_service_proof ===
      terminalChain.service_artifact_verification_bound_to_service_proof &&
    verification.recognized_write_boarded === terminalChain.recognized_write_boarded &&
    verification.missing_receipt_refused_before_mutation ===
      terminalChain.missing_receipt_refused_before_mutation &&
    verification.invalid_receipt_refused_before_mutation ===
      terminalChain.invalid_receipt_refused_before_mutation &&
    verification.required_recognition_refusal_case_count ===
      terminalChain.required_recognition_refusal_case_count &&
    verification.observed_recognition_refusal_case_count ===
      terminalChain.observed_recognition_refusal_case_count &&
    verification.all_required_recognition_refusals_before_mutation ===
      terminalChain.all_required_recognition_refusals_before_mutation &&
    verification.required_authority_refusal_case_count ===
      terminalChain.required_authority_refusal_case_count &&
    verification.observed_authority_refusal_case_count ===
      terminalChain.observed_authority_refusal_case_count &&
    verification.all_required_authority_refusals_before_consumption_and_mutation ===
      terminalChain.all_required_authority_refusals_before_consumption_and_mutation &&
    verification.same_process_signed_payload_replay_refused ===
      terminalChain.same_process_signed_payload_replay_refused &&
    verification.restart_consumed_authority_grant_refused ===
      terminalChain.restart_consumed_authority_grant_refused &&
    verification.state_append_after_grant_commit_burn_observed ===
      terminalChain.state_append_after_grant_commit_burn_observed &&
    verification.metadata_partial_commit_burn_observed ===
      terminalChain.metadata_partial_commit_burn_observed &&
    verification.store_and_anchor_rollback_refused_while_witness_ahead ===
      terminalChain.store_and_anchor_rollback_refused_while_witness_ahead &&
    verification.store_anchor_and_witness_joint_rollback_detection ===
      terminalChain.store_anchor_and_witness_joint_rollback_detection &&
    verification.joint_rollback_reopened_authority_grant_reuse ===
      terminalChain.joint_rollback_reopened_authority_grant_reuse &&
    verification.fixture_rightful_issuance_path_evidenced ===
      terminalChain.fixture_rightful_issuance_path_evidenced &&
    verification.rightful_issuance_proven === terminalChain.rightful_issuance_proven &&
    verification.portable_rightful_issuance_proven ===
      terminalChain.portable_rightful_issuance_proven &&
    verification.production_rightful_issuance_proven ===
      terminalChain.production_rightful_issuance_proven &&
    verification.consequence_lifecycle_closed === terminalChain.consequence_lifecycle_closed &&
    verification.embedded_service_artifact_structural_self_integrity_verified ===
      terminalChain.generated_service_proof_structural_self_integrity_verified &&
    verification.embedded_service_artifact_identity_match_requires_expected_sha256 ===
      terminalChain.generated_service_proof_artifact_identity_match_requires_expected_sha256 &&
    verification.embedded_service_artifact_expected_body_sha256_matched ===
      terminalChain.expected_generated_service_proof_artifact_body_sha256_matched &&
    /^[a-f0-9]{64}$/.test(verification.embedded_service_artifact_expected_body_sha256 || '') &&
    /^[a-f0-9]{64}$/.test(
      terminalChain.expected_generated_service_proof_artifact_body_sha256 || ''
    ) &&
    verification.recognition_contract_sha256 === terminalChain.recognition_contract_sha256 &&
    verification.recognition_refusal_taxonomy_sha256 ===
      terminalChain.recognition_refusal_taxonomy_sha256 &&
    verification.authority_refusal_taxonomy_sha256 ===
      terminalChain.authority_refusal_taxonomy_sha256 &&
    verification.named_receipt_refusals_sha256 ===
      terminalChain.named_receipt_refusals_sha256 &&
    verification.recognition_refusal_groups_sha256 ===
      terminalChain.recognition_refusal_groups_sha256 &&
    verification.nested_artifact_binding.generated_preflight_artifact_type ===
      terminalChain.nested_artifact_binding.generated_preflight_artifact_type &&
    verification.nested_artifact_binding.generated_service_proof_artifact_type ===
      terminalChain.nested_artifact_binding.generated_service_proof_artifact_type &&
    verification.nested_artifact_binding.generated_preflight_artifact_verified === true &&
    terminalChain.nested_artifact_binding.generated_preflight_artifact_verified === true &&
    verification.nested_artifact_binding.generated_service_proof_artifact_verified === true &&
    terminalChain.nested_artifact_binding.generated_service_proof_artifact_verified === true &&
    verification.nested_artifact_binding.generated_service_proof_structural_self_integrity_verified === true &&
    terminalChain.nested_artifact_binding.generated_service_proof_structural_self_integrity_verified === true &&
    verification.nested_artifact_binding.generated_service_proof_artifact_identity_match_requires_expected_sha256 === true &&
    terminalChain.nested_artifact_binding.generated_service_proof_artifact_identity_match_requires_expected_sha256 === true &&
    verification.nested_artifact_binding.preflight_artifact_hash_bound === true &&
    terminalChain.nested_artifact_binding.preflight_artifact_hash_bound === true &&
    verification.nested_artifact_binding.service_proof_source_preflight_hash_bound === true &&
    terminalChain.nested_artifact_binding.service_proof_source_preflight_hash_bound === true &&
    verification.nested_artifact_binding.service_artifact_hash_bound === true &&
    terminalChain.nested_artifact_binding.service_artifact_hash_bound === true &&
    verification.nested_artifact_binding.service_artifact_verification_bound_to_service_proof === true &&
    terminalChain.nested_artifact_binding.service_artifact_verification_bound_to_service_proof === true &&
    JSON.stringify(verification.named_receipt_refusals) ===
      JSON.stringify(terminalChain.named_receipt_refusals) &&
    JSON.stringify(verification.recognition_refusal_groups) ===
      JSON.stringify(terminalChain.recognition_refusal_groups) &&
    JSON.stringify(verification.deployment_profile_authority_refusal_mirror) ===
      JSON.stringify(terminalChain.deployment_profile_authority_refusal_mirror) &&
    verification.current_machine_governance_proven === false &&
    verification.production_downstream_recognition === false &&
    verification.external_attestation === false &&
    verification.sovereign_recognition === false
  );
}

function assertTerminalChainArtifactVerificationMatchesChainBoundary(
  verification,
  chain,
  label
) {
  if (!terminalChainArtifactVerificationMatchesChainBoundary(verification, chain)) {
    throw new Error(`Proof smoke ${label} is not bound to the supplied chain boundary`);
  }
}

function assertNonClaims(nonClaims) {
  if (!Array.isArray(nonClaims) || nonClaims.length !== PROOF_SMOKE_NON_CLAIMS.length) {
    throw new Error('Proof smoke report non-claims drifted');
  }
  for (let i = 0; i < PROOF_SMOKE_NON_CLAIMS.length; i++) {
    if (nonClaims[i] !== PROOF_SMOKE_NON_CLAIMS[i]) {
      throw new Error('Proof smoke report non-claims drifted');
    }
  }
}

const LOCAL_PROOF_PACK_SAMPLE_ARTIFACT_URL = new URL(
  '../tests/fixtures/local-proof-pack-artifact-v1.json',
  import.meta.url
);
const SERVICE_PROFILE_PREFLIGHT_SAMPLE_ARTIFACT_URL = new URL(
  '../tests/fixtures/protected-records-service-preflight-artifact-v1.json',
  import.meta.url
);
const ACTIVATION_PREFLIGHT_SAMPLE_ARTIFACT_URL = new URL(
  '../tests/fixtures/protected-records-runtime-activation-preflight-artifact-v1.json',
  import.meta.url
);
const RUNTIME_LOCAL_ACTIVATION_SAMPLE_ARTIFACT_URL = new URL(
  '../tests/fixtures/protected-records-runtime-local-activation-artifact-v1.json',
  import.meta.url
);
const RUNTIME_PROFILE_INSTALLATION_SAMPLE_ARTIFACT_URL = new URL(
  '../tests/fixtures/protected-records-runtime-profile-installation-artifact-v1.json',
  import.meta.url
);
const INSTALLED_RUNTIME_PROFILE_PREFLIGHT_SAMPLE_ARTIFACT_URL = new URL(
  '../tests/fixtures/protected-records-installed-runtime-profile-preflight-artifact-v1.json',
  import.meta.url
);
const INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_SAMPLE_ARTIFACT_URL = new URL(
  '../tests/fixtures/protected-records-installed-runtime-profile-service-proof-artifact-v1.json',
  import.meta.url
);
const INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_URL = new URL(
  '../tests/fixtures/protected-records-installed-runtime-profile-terminal-chain-artifact-v1.json',
  import.meta.url
);

function consequenceLifecycleMapSampleArtifact() {
  let artifact;
  try {
    artifact = JSON.parse(
      readFileSync(INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_URL, 'utf8')
    );
  } catch (err) {
    throw new Error(`Unable to read consequence lifecycle map source artifact: ${err.message}`);
  }
  return artifact;
}

export function consequenceLifecycleMapSampleProjectionSha256() {
  return consequenceLifecycleMapSha256(
    buildConsequenceLifecycleMap(consequenceLifecycleMapSampleArtifact())
  );
}

function sampleArtifactBodySha256(url, label) {
  let artifact;
  try {
    artifact = JSON.parse(readFileSync(url, 'utf8'));
  } catch (err) {
    throw new Error(`Unable to read ${label} sample artifact: ${err.message}`);
  }
  const sha256 = artifact?.integrity?.body_sha256;
  if (!/^[a-f0-9]{64}$/.test(sha256 || '')) {
    throw new Error(`${label} sample artifact SHA-256 is malformed`);
  }
  return sha256;
}

function localProofPackSampleArtifact() {
  return parseLocalProofPackArtifactText(
    readFileSync(LOCAL_PROOF_PACK_SAMPLE_ARTIFACT_URL, 'utf8')
  );
}

export function localProofPackSampleArtifactBodySha256() {
  return localProofPackSampleArtifact().integrity.body_sha256;
}

export function serviceProfilePreflightSampleArtifactBodySha256() {
  return sampleArtifactBodySha256(
    SERVICE_PROFILE_PREFLIGHT_SAMPLE_ARTIFACT_URL,
    'service profile preflight'
  );
}

export function activationPreflightSampleArtifactBodySha256() {
  return sampleArtifactBodySha256(
    ACTIVATION_PREFLIGHT_SAMPLE_ARTIFACT_URL,
    'activation preflight'
  );
}

export function runtimeLocalActivationSampleArtifactBodySha256() {
  return sampleArtifactBodySha256(
    RUNTIME_LOCAL_ACTIVATION_SAMPLE_ARTIFACT_URL,
    'runtime local activation'
  );
}

export function runtimeProfileInstallationSampleArtifactBodySha256() {
  return sampleArtifactBodySha256(
    RUNTIME_PROFILE_INSTALLATION_SAMPLE_ARTIFACT_URL,
    'runtime profile installation'
  );
}

export function installedRuntimeProfilePreflightSampleArtifactBodySha256() {
  return sampleArtifactBodySha256(
    INSTALLED_RUNTIME_PROFILE_PREFLIGHT_SAMPLE_ARTIFACT_URL,
    'installed runtime profile preflight'
  );
}

export function installedRuntimeProfileServiceProofSampleArtifactBodySha256() {
  return sampleArtifactBodySha256(
    INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_SAMPLE_ARTIFACT_URL,
    'installed runtime profile service proof'
  );
}

export function installedRuntimeProfileTerminalChainSampleArtifactBodySha256() {
  return sampleArtifactBodySha256(
    INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_URL,
    'installed runtime profile terminal chain'
  );
}

function assertRequiredBodySha256Posture(verification, expectedSha256, label) {
  if (verification.body_sha256 !== expectedSha256) {
    throw new Error(`Proof smoke ${label} artifact SHA-256 does not match committed sample`);
  }
  if (verification.required_body_sha256 !== expectedSha256) {
    throw new Error(`Proof smoke ${label} required SHA-256 drifted`);
  }
  if (verification.required_body_sha256_matched !== true) {
    throw new Error(`Proof smoke ${label} required SHA-256 was not matched`);
  }
}

function verificationWithoutRequiredBodySha256(verification) {
  const {
    required_body_sha256: _requiredBodySha256,
    required_body_sha256_matched: _requiredBodySha256Matched,
    ...baseVerification
  } = verification;
  return baseVerification;
}

function localProofPackSampleClaudeHookReplayCaseEvidenceSha256() {
  const artifact = localProofPackSampleArtifact();
  const component = artifact.payload.components.find((item) =>
    item.component === 'claude_code_hook_contract_replay'
  );
  return component?.case_evidence_sha256 || null;
}

function assertSampleVerification(verification) {
  assertObject(verification, 'sample verification');
  assertExactObjectKeys('Proof smoke sample verification', verification, [
    'artifact_type',
    'artifact_verification_model',
    'body_sha256',
    'canonicalization',
    'claim_binding',
    'claim_boundary',
    'claude_hook_contract_replay',
    'component_count',
    'component_manifest',
    'component_manifest_hash_scope',
    'evidence_model',
    'fresh_proof_pack_run_performed',
    'hash_scope',
    'human_authorization',
    'key_state_report',
    'downstream_refusal',
    'live_probing',
    'non_claims',
    'payload_type',
    'receipt_verifier_boundary',
    'required_body_sha256',
    'required_body_sha256_matched',
    'runtime_local_activation',
    'runtime_profile_installation',
    'service_profile_preflight',
    'source_freshness_proven',
    'trusted_issuer_registry_recognition',
    'verification_type',
    'verified',
  ]);
  if (verification.verification_type !== LOCAL_PROOF_PACK_ARTIFACT_VERIFICATION_TYPE) {
    throw new Error('Proof smoke sample verification type drifted');
  }
  if (verification.verified !== true) {
    throw new Error('Proof smoke sample artifact must verify');
  }
  if (verification.evidence_model !== 'local-fixtures') {
    throw new Error('Proof smoke sample verification must use local fixture evidence');
  }
  if (verification.live_probing !== false) {
    throw new Error('Proof smoke sample verification must not perform live probing');
  }
  if (
    verification.artifact_verification_model !==
      'self-contained-artifact-integrity-and-embedded-boundary-validation' ||
    verification.fresh_proof_pack_run_performed !== false ||
    verification.source_freshness_proven !== false
  ) {
    throw new Error('Proof smoke sample verification artifact-only boundary drifted');
  }
  if (
    verification.claim_boundary !==
    'artifact integrity, embedded local fixture proof-pack boundaries, and verifier schema compatibility only; no fresh proof-pack run or current-checkout freshness proof'
  ) {
    throw new Error('Proof smoke sample verification claim boundary drifted');
  }
  if (!/^[a-f0-9]{64}$/.test(verification.body_sha256 || '')) {
    throw new Error('Proof smoke sample artifact SHA-256 is malformed');
  }
  if (verification.body_sha256 !== localProofPackSampleArtifactBodySha256()) {
    throw new Error('Proof smoke sample artifact SHA-256 does not match committed sample');
  }
  if (verification.required_body_sha256 !== localProofPackSampleArtifactBodySha256()) {
    throw new Error('Proof smoke sample artifact required SHA-256 drifted');
  }
  if (verification.required_body_sha256_matched !== true) {
    throw new Error('Proof smoke sample artifact required SHA-256 was not matched');
  }
  if (
    verification.component_manifest_hash_scope !==
    'canonical payload components in artifact order'
  ) {
    throw new Error('Proof smoke sample artifact component manifest hash scope drifted');
  }
  if (!Array.isArray(verification.component_manifest) || verification.component_manifest.length !== 16) {
    throw new Error('Proof smoke sample artifact component manifest drifted');
  }
  const hookReplayManifest = verification.component_manifest.find((item) =>
    item.component === 'claude_code_hook_contract_replay'
  );
  assertObject(hookReplayManifest, 'sample verification Claude hook replay component manifest');
  assertExactObjectKeys('Proof smoke Claude hook replay component manifest', hookReplayManifest, [
    'component',
    'component_sha256',
    'evidence_model',
    'identity',
    'identity_type',
    'live_probing',
    'source_state_boundary',
  ]);
  if (
    !/^[a-f0-9]{64}$/.test(hookReplayManifest.component_sha256 || '') ||
    hookReplayManifest.identity_type !== 'proof_type' ||
    hookReplayManifest.identity !== CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_TYPE ||
    hookReplayManifest.evidence_model !== CLAUDE_CODE_HOOK_CONTRACT_REPLAY_EVIDENCE_MODEL ||
    hookReplayManifest.live_probing !== false ||
    hookReplayManifest.source_state_boundary !==
      CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY
  ) {
    throw new Error('Proof smoke Claude hook replay component manifest drifted');
  }
  assertObject(verification.claim_binding, 'sample verification claim binding');
  assertExactObjectKeys('Proof smoke sample verification claim binding', verification.claim_binding, [
    'hash_scope',
    'non_claim_count',
    'non_claims_sha256',
    'safe_claim_ceiling_sha256',
  ]);
  if (
    verification.claim_binding.hash_scope !== 'canonical safe claim ceiling and non-claims' ||
    verification.claim_binding.non_claim_count !== 11 ||
    !/^[a-f0-9]{64}$/.test(verification.claim_binding.non_claims_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(verification.claim_binding.safe_claim_ceiling_sha256 || '')
  ) {
    throw new Error('Proof smoke sample verification claim binding drifted');
  }
  assertKeyStateReportSummary(verification.key_state_report);
  assertReceiptVerifierBoundarySummary(verification.receipt_verifier_boundary);
  assertTrustedIssuerRegistryRecognitionSummary(
    verification.trusted_issuer_registry_recognition
  );
  assertDownstreamRefusalSummary(verification.downstream_refusal);
  assertHumanAuthorizationSummary(verification.human_authorization);
  assertServiceProfilePreflightSummary(verification.service_profile_preflight);
  assertRuntimeLocalActivationSummary(verification.runtime_local_activation);
  assertRuntimeProfileInstallationSummary(verification.runtime_profile_installation);
  assertClaudeCodeHookContractReplaySummary(verification.claude_hook_contract_replay);
  if (
    verification.claude_hook_contract_replay.case_evidence_sha256 !==
    localProofPackSampleClaudeHookReplayCaseEvidenceSha256()
  ) {
    throw new Error('Proof smoke Claude hook-contract replay case evidence SHA-256 does not match committed sample');
  }
}

function assertDownstreamRefusalSummary(summary) {
  assertObject(summary, 'sample verification downstream refusal summary');
  assertExactObjectKeys('Proof smoke downstream-refusal summary', summary, [
    'all_refusal_marker_count_deltas_zero',
    'all_refusals_unboarded',
    'claim_boundary',
    'command',
    'component',
    'evidence_model',
    'final_marker_count',
    'live_probing',
    'proof_type',
    'recognized_boarded',
    'recognized_marker_count_delta',
    'refusal_case_count',
    'refusal_reasons',
    'run_in_proof_pack',
    'summary_type',
  ]);
  if (
    summary.summary_type !==
      'zlar-local-proof-pack-downstream-refusal-verification-summary-v1' ||
    summary.component !== 'downstream_refusal_proof' ||
    summary.run_in_proof_pack !== true ||
    summary.command !== 'zlar downstream-refusal-proof' ||
    summary.proof_type !== 'downstream-refusal-proof-v1' ||
    summary.evidence_model !== 'local-hermetic-fixture' ||
    summary.live_probing !== false ||
    summary.recognized_boarded !== true ||
    summary.recognized_marker_count_delta !== 1 ||
    summary.final_marker_count !== 1 ||
    summary.refusal_case_count !== DOWNSTREAM_REFUSAL_REASONS.length ||
    summary.all_refusals_unboarded !== true ||
    summary.all_refusal_marker_count_deltas_zero !== true ||
    !Array.isArray(summary.refusal_reasons) ||
    summary.refusal_reasons.length !== DOWNSTREAM_REFUSAL_REASONS.length ||
    summary.refusal_reasons.some(
      (reason, index) => reason !== DOWNSTREAM_REFUSAL_REASONS[index],
    ) ||
    summary.claim_boundary !==
      'embedded local proof-pack downstream-refusal summary only; local hermetic fixture, no live downstream run during artifact verification'
  ) {
    throw new Error('Proof smoke downstream-refusal summary drifted');
  }
}

function assertClaudeCodeHookContractReplaySummary(summary) {
  assertObject(summary, 'sample verification Claude hook-contract replay summary');
  assertExactObjectKeys('Proof smoke Claude hook-contract replay summary', summary, [
    'adapter_path_claimed',
    'adapter_sha256',
    'adapter_source',
    'all_required_cases_present',
    'all_surface_governance_proven',
    'app_originated_hook_crossing_proven',
    'blank_gate_response_failed_closed',
    'case_evidence_hash_scope',
    'case_evidence_sha256',
    'claim_boundary',
    'command',
    'component',
    'current_machine_governance_proven',
    'denied_effect_not_executed',
    'evidence_model',
    'hook_replay_contract_sha256',
    'live_claude_app_passage_proven',
    'live_claude_invoked',
    'live_probing',
    'live_receipt_emission_proven',
    'malformed_output_refused',
    'missing_gate_failed_closed',
    'non_pretooluse_payload_denied_by_fixture_gate',
    'permission_decisions_observed',
    'production_downstream_recognition_proven',
    'proof_type',
    'required_case_count',
    'required_cases',
    'run_in_proof_pack',
    'side_door_closure_proven',
    'source_state_boundary',
    'summary_type',
    'supporting_local_boarding_consequence_absent_on_every_refusal',
    'supporting_local_boarding_consequence_present_exactly_once_on_acceptance',
    'supporting_local_boarding_legacy_v0_recognized_boarding_identity',
    'supporting_local_boarding_proof_passed',
    'supporting_local_boarding_proof_type',
    'supporting_local_boarding_v1_receipt_identity_verified',
    'tool_input_not_executed',
  ]);
  if (
    summary.summary_type !==
      'zlar-local-proof-pack-claude-hook-contract-replay-verification-summary-v1' ||
    summary.component !== 'claude_code_hook_contract_replay' ||
    summary.run_in_proof_pack !== true ||
    summary.command !== 'zlar claude-code-hook-contract-replay-proof' ||
    summary.proof_type !== CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_TYPE ||
    summary.evidence_model !== CLAUDE_CODE_HOOK_CONTRACT_REPLAY_EVIDENCE_MODEL ||
    summary.live_probing !== false ||
    summary.hook_replay_contract_sha256 !== claudeCodeHookContractReplayContractSha256() ||
    summary.source_state_boundary !== CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY ||
    summary.adapter_source !== 'repo' ||
    summary.adapter_path_claimed !== 'repo:adapters/claude-code/hook.sh' ||
    summary.adapter_sha256 !== claudeCodeHookContractReplayRepoAdapterSha256() ||
    summary.case_evidence_hash_scope !==
      'canonical hook replay case, normalized input-contract, sentinel, marker, audit-delta, and supporting-boarding evidence embedded in local proof pack' ||
    !/^[a-f0-9]{64}$/.test(summary.case_evidence_sha256 || '') ||
    summary.required_case_count !== REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES.length ||
    JSON.stringify(summary.required_cases) !==
      JSON.stringify(REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES.map((item) => item.case_id)) ||
    summary.all_required_cases_present !== true ||
    summary.denied_effect_not_executed !== true ||
    summary.tool_input_not_executed !== true ||
    summary.missing_gate_failed_closed !== true ||
    summary.blank_gate_response_failed_closed !== true ||
    summary.malformed_output_refused !== true ||
    summary.non_pretooluse_payload_denied_by_fixture_gate !== true ||
    summary.supporting_local_boarding_proof_passed !== true ||
    summary.supporting_local_boarding_proof_type !==
      'zlar-protected-records-local-boarding-proof-v1' ||
    summary.supporting_local_boarding_v1_receipt_identity_verified !== true ||
    summary.supporting_local_boarding_consequence_absent_on_every_refusal !== true ||
    summary.supporting_local_boarding_consequence_present_exactly_once_on_acceptance !== true ||
    summary.supporting_local_boarding_legacy_v0_recognized_boarding_identity !== false
  ) {
    throw new Error('Proof smoke Claude hook-contract replay summary drifted');
  }
  assertExactObjectKeys('Proof smoke Claude hook-contract replay permission decisions', summary.permission_decisions_observed, [
    'allow',
    'deny',
  ]);
  if (
    summary.permission_decisions_observed.allow !== true ||
    summary.permission_decisions_observed.deny !== true
  ) {
    throw new Error('Proof smoke Claude hook-contract replay permission decisions drifted');
  }
  for (const field of [
    'live_claude_invoked',
    'live_claude_app_passage_proven',
    'app_originated_hook_crossing_proven',
    'live_receipt_emission_proven',
    'current_machine_governance_proven',
    'production_downstream_recognition_proven',
    'all_surface_governance_proven',
    'side_door_closure_proven',
  ]) {
    if (summary[field] !== false) {
      throw new Error(`Proof smoke Claude hook-contract replay ${field} must be false`);
    }
  }
  if (
    summary.claim_boundary !==
    'embedded local proof-pack Claude hook-contract replay summary and case-evidence hash only; source_state is not carried as freshness evidence during artifact verification; no fresh hook replay run, live Claude invocation, app-originated hook crossing, or current-machine governance proof during artifact verification'
  ) {
    throw new Error('Proof smoke Claude hook-contract replay claim boundary drifted');
  }
}

function assertKeyStateReportSummary(summary) {
  assertObject(summary, 'sample verification key-state summary');
  assertExactObjectKeys('Proof smoke key-state summary', summary, [
    'claim_boundary',
    'command',
    'component',
    'constitution_current_ceremony_ready',
    'constitution_hardware_target_observed',
    'constitution_software_pins_aligned',
    'current_machine_governance_proven',
    'evidence_model',
    'external_attestation',
    'hardware_policy_constitution',
    'key_custody_proven',
    'legacy_software_signing_key_present',
    'live_probing',
    'policy_current_ceremony_ready',
    'policy_hardware_target_observed',
    'policy_manifest_constitution',
    'policy_software_pins_aligned',
    'private_key_bytes_read',
    'private_key_material_included',
    'private_key_material_read',
    'private_key_paths_included',
    'production_trust_registry_proven',
    'read_only',
    'report_type',
    'revocation_state_proven',
    'run_in_proof_pack',
    'sovereign_recognition',
    'spec_hardware_target_observed',
    'spec_test_vectors',
    'summary_type',
    'yubi_key_serial_numbers_included',
  ]);
  if (summary.summary_type !== 'zlar-local-proof-pack-key-state-verification-summary-v1') {
    throw new Error('Proof smoke key-state summary type drifted');
  }
  if (summary.component !== 'key_state_report') {
    throw new Error('Proof smoke key-state component drifted');
  }
  if (summary.run_in_proof_pack !== true) {
    throw new Error('Proof smoke key-state report must run in proof pack');
  }
  if (summary.command !== 'zlar key-state --sample --json') {
    throw new Error('Proof smoke key-state command drifted');
  }
  if (summary.report_type !== 'zlar-key-state-report-v1') {
    throw new Error('Proof smoke key-state report type drifted');
  }
  if (
    summary.evidence_model !== 'local-read-only-key-state' ||
    summary.live_probing !== false ||
    summary.read_only !== true ||
    summary.policy_manifest_constitution !== 'software-rooted-current' ||
    summary.hardware_policy_constitution !== 'provisioned-target-not-current-custody-proof' ||
    summary.spec_test_vectors !== 'hardware-backed-target'
  ) {
    throw new Error('Proof smoke key-state posture drifted');
  }
  if (
    summary.private_key_material_read !== false ||
    summary.private_key_material_included !== false ||
    summary.private_key_paths_included !== false ||
    summary.yubi_key_serial_numbers_included !== false ||
    summary.legacy_software_signing_key_present !== false ||
    summary.private_key_bytes_read !== false ||
    summary.policy_hardware_target_observed !== false ||
    summary.constitution_hardware_target_observed !== false ||
    summary.spec_hardware_target_observed !== false ||
    summary.key_custody_proven !== false ||
    summary.revocation_state_proven !== false ||
    summary.production_trust_registry_proven !== false ||
    summary.current_machine_governance_proven !== false ||
    summary.external_attestation !== false ||
    summary.sovereign_recognition !== false
  ) {
    throw new Error('Proof smoke key-state privacy/non-claim summary drifted');
  }
  if (
    typeof summary.policy_software_pins_aligned !== 'boolean' ||
    typeof summary.constitution_software_pins_aligned !== 'boolean' ||
    typeof summary.policy_current_ceremony_ready !== 'boolean' ||
    typeof summary.constitution_current_ceremony_ready !== 'boolean'
  ) {
    throw new Error('Proof smoke key-state pin alignment summary drifted');
  }
  if (
    summary.claim_boundary !==
    'embedded local proof-pack key-state sample summary only; no current-machine key-state run during artifact verification'
  ) {
    throw new Error('Proof smoke key-state claim boundary drifted');
  }
}

function assertReceiptVerifierBoundarySummary(summary) {
  assertObject(summary, 'sample verification receipt verifier boundary summary');
  assertExactObjectKeys('Proof smoke receipt verifier boundary summary', summary, [
    'claim_boundary',
    'command',
    'component',
    'current_machine_governance_proven',
    'distinguishes_unknown_signer_from_invalid',
    'downstream_recognition_proven',
    'evidence_model',
    'external_attestation',
    'invalid_exit_code',
    'invalid_kid_match',
    'invalid_provided_pubkey_sha256_matches_valid',
    'invalid_receipt_sha256_differs_from_valid',
    'invalid_verdict',
    'issuer_recognition_proven',
    'key_custody_proven',
    'legacy_v0_required_identity_exit_code',
    'legacy_v0_required_identity_refused',
    'live_probing',
    'production_deployment_proven',
    'proof_type',
    'receipt_type',
    'receipt_version',
    'revocation_state_proven',
    'run_in_proof_pack',
    'semantic_checks_checked',
    'signed_byte_integrity_checked',
    'sovereign_recognition',
    'summary_type',
    'required_identity_command_posture',
    'required_identity_command_posture_allow_v0',
    'required_identity_command_posture_detected_format',
    'required_identity_command_posture_v1_only_required',
    'required_identity_exit_code',
    'required_identity_format_matched',
    'required_identity_kid_matched',
    'required_identity_pubkey_sha256_matched',
    'required_identity_receipt_id_matched',
    'required_identity_receipt_sha256_matched',
    'required_identity_v1_only_matched',
    'required_identity_verdict',
    'unknown_signer_exit_code',
    'unknown_signer_kid_match',
    'unknown_signer_provided_pubkey_sha256_differs',
    'unknown_signer_reason',
    'unknown_signer_receipt_sha256_matches_valid',
    'unknown_signer_verdict',
    'unrouted_paths_coverage_proven',
    'valid_command_posture_allow_v0',
    'valid_command_posture_detected_format',
    'valid_exit_code',
    'valid_kid_match',
    'valid_provided_pubkey_sha256_present',
    'valid_receipt_sha256_present',
    'valid_required_identity_command_posture',
    'valid_verdict',
  ]);
  if (
    summary.summary_type !==
    'zlar-local-proof-pack-receipt-verifier-boundary-verification-summary-v1'
  ) {
    throw new Error('Proof smoke receipt verifier boundary summary type drifted');
  }
  if (summary.component !== 'receipt_verifier_boundary') {
    throw new Error('Proof smoke receipt verifier boundary component drifted');
  }
  if (summary.run_in_proof_pack !== true) {
    throw new Error('Proof smoke receipt verifier boundary must run in proof pack');
  }
  if (summary.proof_type !== 'zlar-receipt-verifier-boundary-proof-v1') {
    throw new Error('Proof smoke receipt verifier boundary proof type drifted');
  }
  if (summary.evidence_model !== 'local-ephemeral-receipt-verifier-fixture') {
    throw new Error('Proof smoke receipt verifier boundary evidence model drifted');
  }
  if (summary.live_probing !== false) {
    throw new Error('Proof smoke receipt verifier boundary must not live probe');
  }
  if (summary.command !== 'zlar-verify <receipt.json> --pubkey <key.pub> --json') {
    throw new Error('Proof smoke receipt verifier boundary command drifted');
  }
  if (summary.receipt_version !== 'v1' || summary.receipt_type !== 'governed-action') {
    throw new Error('Proof smoke receipt verifier boundary receipt identity drifted');
  }
  if (summary.signed_byte_integrity_checked !== true || summary.semantic_checks_checked !== true) {
    throw new Error('Proof smoke receipt verifier boundary integrity checks drifted');
  }
  if (
    summary.valid_exit_code !== 0 ||
    summary.valid_verdict !== 'VALID' ||
    summary.valid_kid_match !== true ||
    summary.valid_receipt_sha256_present !== true ||
    summary.valid_provided_pubkey_sha256_present !== true ||
    summary.valid_command_posture_allow_v0 !== false ||
    summary.valid_command_posture_detected_format !== 'v1' ||
    summary.valid_required_identity_command_posture !==
      'receipt-verifier-v1-default' ||
    summary.required_identity_exit_code !== 0 ||
    summary.required_identity_verdict !== 'VALID' ||
    summary.required_identity_receipt_id_matched !== true ||
    summary.required_identity_receipt_sha256_matched !== true ||
    summary.required_identity_kid_matched !== true ||
    summary.required_identity_pubkey_sha256_matched !== true ||
    summary.required_identity_format_matched !== true ||
    summary.required_identity_v1_only_matched !== true ||
    summary.required_identity_command_posture !==
      'receipt-verifier-v1-only-required' ||
    summary.required_identity_command_posture_allow_v0 !== false ||
    summary.required_identity_command_posture_detected_format !== 'v1' ||
    summary.required_identity_command_posture_v1_only_required !== true ||
    summary.unknown_signer_exit_code !== 3 ||
    summary.unknown_signer_verdict !== 'UNKNOWN-SIGNER' ||
    summary.unknown_signer_reason !== 'Receipt kid does not match provided public key.' ||
    summary.unknown_signer_kid_match !== false ||
    summary.unknown_signer_receipt_sha256_matches_valid !== true ||
    summary.unknown_signer_provided_pubkey_sha256_differs !== true ||
    summary.invalid_exit_code !== 1 ||
    summary.invalid_verdict !== 'INVALID' ||
    summary.invalid_kid_match !== true ||
    summary.invalid_receipt_sha256_differs_from_valid !== true ||
    summary.invalid_provided_pubkey_sha256_matches_valid !== true ||
    summary.legacy_v0_required_identity_refused !== true ||
    summary.legacy_v0_required_identity_exit_code !== 1 ||
    summary.distinguishes_unknown_signer_from_invalid !== true
  ) {
    throw new Error('Proof smoke receipt verifier boundary identity summary drifted');
  }
  for (const field of [
    'issuer_recognition_proven',
    'key_custody_proven',
    'revocation_state_proven',
    'downstream_recognition_proven',
    'production_deployment_proven',
    'current_machine_governance_proven',
    'external_attestation',
    'sovereign_recognition',
    'unrouted_paths_coverage_proven',
  ]) {
    if (summary[field] !== false) {
      throw new Error(`Proof smoke receipt verifier boundary ${field} must be false`);
    }
  }
  if (
    summary.claim_boundary !==
    'embedded local proof-pack receipt-verifier boundary summary only; no fresh receipt verification run during artifact verification'
  ) {
    throw new Error('Proof smoke receipt verifier boundary claim boundary drifted');
  }
}

function assertTrustedIssuerRegistryRecognitionSummary(summary) {
  assertObject(summary, 'sample verification trusted issuer registry recognition summary');
  assertExactObjectKeys('Proof smoke trusted issuer registry recognition summary', summary, [
    'claim_boundary',
    'command',
    'component',
    'current_machine_governance_proven',
    'decision',
    'evidence_model',
    'issuer_status',
    'key_custody_proven',
    'live_issuer_status_proven',
    'live_probing',
    'live_trust_registry_state',
    'malformed_registry_error_code',
    'malformed_registry_fail_closed_before_verdict',
    'malformed_registry_unsupported_field',
    'production_authority',
    'production_downstream_recognition_proven',
    'production_trust_registry_proven',
    'public_external_attestation',
    'real_non_operator_review',
    'reason_code',
    'recognized',
    'registry_evaluation_result_type',
    'registry_evidence_model',
    'registry_fixture_evaluated',
    'registry_fixture_validated',
    'registry_scope',
    'registry_to_recognition_rule_evaluated',
    'registry_trusted_issuer_count',
    'registry_type',
    'requested_scope',
    'required_audit_event_id_bound',
    'required_detail_hash_bound',
    'revocation_truth_proven',
    'run_in_proof_pack',
    'signature_valid',
    'sovereign_recognition',
    'summary_type',
    'verdict',
  ]);
  if (
    summary.summary_type !==
    'zlar-local-proof-pack-trusted-issuer-registry-recognition-verification-summary-v2'
  ) {
    throw new Error('Proof smoke trusted issuer registry recognition summary type drifted');
  }
  if (summary.component !== 'trusted_issuer_registry_recognition') {
    throw new Error('Proof smoke trusted issuer registry recognition component drifted');
  }
  if (summary.run_in_proof_pack !== true) {
    throw new Error('Proof smoke trusted issuer registry recognition must run in proof pack');
  }
  if (summary.command !== 'embedded local proof-pack trusted issuer registry recognition fixture') {
    throw new Error('Proof smoke trusted issuer registry recognition command drifted');
  }
  if (
    summary.evidence_model !== 'fresh-local-fixture-trusted-issuer-registry-recognition' ||
    summary.registry_type !== 'trusted-receipt-issuers-v2' ||
    summary.registry_evidence_model !== 'bundled-local-fixture-no-secret-registry-contract' ||
    summary.live_probing !== false ||
    summary.requested_scope !== 'fixture-records-terminal' ||
    summary.registry_scope !== 'fixture-records-terminal' ||
    summary.registry_fixture_validated !== true ||
    summary.registry_fixture_evaluated !== true ||
    summary.registry_to_recognition_rule_evaluated !== true ||
    summary.registry_evaluation_result_type !== 'downstream-recognition-rule-v1' ||
    summary.registry_trusted_issuer_count !== 1
  ) {
    throw new Error('Proof smoke trusted issuer registry recognition evidence boundary drifted');
  }
  if (
    summary.verdict !== 'RECOGNIZED' ||
    summary.recognized !== true ||
    summary.decision !== 'accept' ||
    summary.reason_code !== 'recognized' ||
    summary.issuer_status !== 'active' ||
    summary.signature_valid !== true ||
    summary.required_audit_event_id_bound !== true ||
    summary.required_detail_hash_bound !== true ||
    summary.malformed_registry_unsupported_field !== true ||
    summary.malformed_registry_error_code !== 'unsupported_registry_field' ||
    summary.malformed_registry_fail_closed_before_verdict !== true
  ) {
    throw new Error('Proof smoke trusted issuer registry recognition facts drifted');
  }
  for (const field of [
    'live_trust_registry_state',
    'live_issuer_status_proven',
    'key_custody_proven',
    'revocation_truth_proven',
    'production_trust_registry_proven',
    'production_downstream_recognition_proven',
    'production_authority',
    'public_external_attestation',
    'real_non_operator_review',
    'sovereign_recognition',
    'current_machine_governance_proven',
  ]) {
    if (summary[field] !== false) {
      throw new Error(`Proof smoke trusted issuer registry recognition ${field} must be false`);
    }
  }
  if (
    summary.claim_boundary !==
    'embedded local proof-pack trusted issuer registry recognition summary only; no live registry or fresh verifier run during artifact verification'
  ) {
    throw new Error('Proof smoke trusted issuer registry recognition claim boundary drifted');
  }
}

function assertHumanAuthorizationSummary(summary) {
  assertObject(summary, 'sample verification human authorization summary');
  assertExactObjectKeys('Proof smoke human authorization summary', summary, [
    'approval_channel',
    'authorized_boarded',
    'authorizer',
    'claim_boundary',
    'command',
    'component',
    'denied_boarded',
    'evidence_model',
    'live_probing',
    'outcome',
    'pending_boarded',
    'proof_type',
    'run_in_proof_pack',
    'summary_type',
  ]);
  if (
    summary.summary_type !==
    'zlar-local-proof-pack-human-authorization-verification-summary-v1'
  ) {
    throw new Error('Proof smoke human authorization summary type drifted');
  }
  if (summary.component !== 'human_authorization_proof') {
    throw new Error('Proof smoke human authorization component drifted');
  }
  if (summary.run_in_proof_pack !== true) {
    throw new Error('Proof smoke human authorization proof must run in proof pack');
  }
  if (summary.command !== 'zlar human-authorization-proof') {
    throw new Error('Proof smoke human authorization command drifted');
  }
  if (summary.proof_type !== 'human-authorization-proof-v1') {
    throw new Error('Proof smoke human authorization proof type drifted');
  }
  if (summary.evidence_model !== 'local-hermetic-fixture') {
    throw new Error('Proof smoke human authorization evidence model drifted');
  }
  if (summary.live_probing !== false) {
    throw new Error('Proof smoke human authorization must not live probe');
  }
  if (summary.approval_channel !== 'simulated-human-fixture') {
    throw new Error('Proof smoke human authorization approval channel drifted');
  }
  if (
    summary.pending_boarded !== false ||
    summary.authorized_boarded !== true ||
    summary.denied_boarded !== false ||
    summary.authorizer !== 'human:fixture-operator' ||
    summary.outcome !== 'authorized'
  ) {
    throw new Error('Proof smoke human authorization boarding summary drifted');
  }
  if (
    summary.claim_boundary !==
    'embedded local proof-pack human-authorization summary only; simulated fixture, no live approval-channel run during artifact verification'
  ) {
    throw new Error('Proof smoke human authorization claim boundary drifted');
  }
}

function assertRuntimeProfileIdentityBoundary(label, summary) {
  if (
    summary.runtime_profile_identity_authority_source !== 'launcher-owned-service-config' ||
    summary.runtime_profile_identity_request_stream_policy !==
      'runtime_profile_id_may_be_omitted_but_if_supplied_must_match_config' ||
    summary.request_runtime_profile_id_required !== false ||
    summary.omitted_request_runtime_profile_id_present !== false ||
    summary.omitted_runtime_profile_id_uses_launcher_config !== true ||
    summary.omitted_runtime_profile_id_reason_code !== 'fixture_authority_grant_effect_satisfied' ||
    summary.omitted_runtime_profile_id_state_entry_count_delta !== 1 ||
    summary.omitted_runtime_profile_id_consumed_authority_grant_count !== 1 ||
    summary.supplied_mismatched_runtime_profile_id_refused !== true ||
    summary.supplied_mismatch_reason_code !== 'agent_supplied_authority_material' ||
    summary.supplied_mismatch_state_entry_count_delta !== 0
  ) {
    throw new Error(`Proof smoke ${label} runtime profile identity policy drifted`);
  }
}

function assertRuntimeLocalActivationSummary(summary) {
  assertObject(summary, 'sample verification runtime local activation summary');
  assertExactObjectKeys('Proof smoke runtime local activation summary', summary, [
    'active_profile_selection',
    'agent_supplied_authority_material_refused',
    'atomic_store_anchor_witness_commit',
    'claim_boundary',
    'component',
    'consequence_lifecycle_closed',
    'consumed_authority_grant_store',
    'consumed_store_witness',
    'consumed_store_write_model',
    'consumption_identity',
    'current_machine_governance_proven',
    'direct_api_with_receipt_refused',
    'disposable_runtime_config_written',
    'evidence_model',
    'exactly_once_effect_semantics',
    'expired_authority_grant_refused',
    'external_attestation',
    'fixture_rightful_issuance_path_evidenced',
    'hook_configuration_written',
    'host_filesystem_path_toctou_closed',
    'invalid_receipt_refused',
    'live_approval_channel_health_checked',
    'live_authority_proven',
    'live_mcp_coverage_checked',
    'live_probing',
    'live_records_system_checked',
    'local_activation_applied',
    'mismatched_authority_grant_appointment_refused',
    'missing_authority_grant_appointment_refused',
    'missing_issuer_status_refused',
    'missing_receipt_refused',
    'mutation_authoritative_route',
    'non_boarding_outcome_refused',
    'omitted_request_runtime_profile_id_present',
    'omitted_runtime_profile_id_consumed_authority_grant_count',
    'omitted_runtime_profile_id_reason_code',
    'omitted_runtime_profile_id_state_entry_count_delta',
    'omitted_runtime_profile_id_uses_launcher_config',
    'partial_grant_commit_burn_window_named',
    'persistent_runtime_config_written',
    'persistent_runtime_profile_installed',
    'plan_sha256',
    'portable_rightful_issuance_proven',
    'production_records_service_checked',
    'production_rightful_issuance_proven',
    'proof_type',
    'recognized_write_accepted',
    'request_runtime_profile_id_required',
    'request_supplied_authority_grant_refused',
    'restart_consumed_authority_grant_refused',
    'retired_issuer_refused',
    'revoked_authority_grant_refused',
    'rightful_issuance_proven',
    'run_in_proof_pack',
    'runtime_profile_identity_authority_source',
    'runtime_profile_identity_request_stream_policy',
    'runtime_profile_sha256',
    'runtime_profile_sha_matches_plan',
    'runtime_service_started',
    'same_process_signed_payload_replay_refused',
    'signed_payload_replay_identity',
    'sovereign_recognition',
    'stale_receipt_refused',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse',
    'store_and_anchor_joint_rollback_refused_against_witness',
    'store_and_anchor_joint_rollback_refused_while_witness_ahead',
    'summary_type',
    'supplied_mismatch_reason_code',
    'supplied_mismatch_state_entry_count_delta',
    'supplied_mismatched_runtime_profile_id_refused',
    'unknown_issuer_refused',
    'unrouted_records_paths_checked',
    'witness_commit_failed_after_authority_grant_store_commit',
    'witness_commit_failure_reason_code',
    'wrong_audit_event_refused',
    'wrong_detail_refused',
    'wrong_domain_refused',
    'wrong_policy_refused',
    'wrong_runtime_profile_id_refused',
    'wrong_tool_refused',
  ]);
  if (
    summary.summary_type !==
    'zlar-local-proof-pack-runtime-local-activation-verification-summary-v1'
  ) {
    throw new Error('Proof smoke runtime local activation summary type drifted');
  }
  if (summary.component !== 'protected_records_runtime_local_activation') {
    throw new Error('Proof smoke runtime local activation summary component drifted');
  }
  if (summary.run_in_proof_pack !== true) {
    throw new Error('Proof smoke runtime local activation must run in proof pack');
  }
  if (summary.proof_type !== 'zlar-protected-records-runtime-local-activation-proof-v1') {
    throw new Error('Proof smoke runtime local activation proof type drifted');
  }
  if (summary.evidence_model !== 'local-disposable-runtime-activation-fixture') {
    throw new Error('Proof smoke runtime local activation evidence model drifted');
  }
  if (summary.live_probing !== false) {
    throw new Error('Proof smoke runtime local activation must not live probe');
  }
  if (!/^[a-f0-9]{64}$/.test(summary.plan_sha256 || '')) {
    throw new Error('Proof smoke runtime local activation plan SHA-256 is malformed');
  }
  if (!/^[a-f0-9]{64}$/.test(summary.runtime_profile_sha256 || '')) {
    throw new Error('Proof smoke runtime local activation profile SHA-256 is malformed');
  }
  assertExactObjectKeys('Proof smoke runtime local activation active profile selection', summary.active_profile_selection, [
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
    summary.active_profile_selection.selection_type !==
      RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_TYPE ||
    summary.active_profile_selection.selection_scope !==
      RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_SCOPE ||
    summary.active_profile_selection.selected !== true ||
    summary.active_profile_selection.selection_source !==
      'explicit-plan-and-profile-inputs' ||
    summary.active_profile_selection.action_class !== 'records.write' ||
    summary.active_profile_selection.route !==
      'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation' ||
    summary.active_profile_selection.downstream_boundary !==
      RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY ||
    summary.active_profile_selection.plan_sha256 !== summary.plan_sha256 ||
    summary.active_profile_selection.profile_id !==
      'protected-records-runtime-fixture-profile' ||
    summary.active_profile_selection.runtime_profile_id !==
      'protected-records-disposable-runtime-profile' ||
    summary.active_profile_selection.profile_status_before_selection !==
      'sample_not_active' ||
    summary.active_profile_selection.runtime_profile_sha256 !==
      summary.runtime_profile_sha256 ||
    summary.active_profile_selection.runtime_profile_sha_matches_plan !== true ||
    summary.active_profile_selection.selects_latest_profile !== false ||
    summary.active_profile_selection.persistent_runtime_profile_installed !== false ||
    summary.active_profile_selection.live_runtime_profile_checked !== false ||
    summary.active_profile_selection.hook_configuration_written !== false
  ) {
    throw new Error('Proof smoke runtime local activation active profile selection drifted');
  }
  if (
    summary.runtime_profile_sha_matches_plan !== true ||
    summary.local_activation_applied !== true ||
    summary.disposable_runtime_config_written !== true ||
    summary.persistent_runtime_config_written !== false ||
    summary.hook_configuration_written !== false ||
    summary.runtime_service_started !== true ||
    summary.recognized_write_accepted !== true ||
    summary.mutation_authoritative_route !==
      'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation' ||
    summary.consumed_authority_grant_store !==
      'persistent-single-use-authority-grant-contract-sha256-store' ||
    summary.consumption_identity !== 'authority-grant-contract-sha256' ||
    summary.signed_payload_replay_identity !== 'verified-signed-payload-sha256' ||
    summary.same_process_signed_payload_replay_refused !== true ||
    summary.restart_consumed_authority_grant_refused !== true ||
    summary.missing_authority_grant_appointment_refused !== true ||
    summary.mismatched_authority_grant_appointment_refused !== true ||
    summary.expired_authority_grant_refused !== true ||
    summary.revoked_authority_grant_refused !== true ||
    summary.request_supplied_authority_grant_refused !== true ||
    summary.witness_commit_failed_after_authority_grant_store_commit !== true ||
    summary.store_and_anchor_joint_rollback_refused_against_witness !== true ||
    summary.store_and_anchor_joint_rollback_refused_while_witness_ahead !== true ||
    summary.store_anchor_and_witness_joint_rollback_detection !== false ||
    summary.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse !== true ||
    summary.atomic_store_anchor_witness_commit !== false ||
    summary.partial_grant_commit_burn_window_named !== true ||
    summary.host_filesystem_path_toctou_closed !== false ||
    summary.fixture_rightful_issuance_path_evidenced !== true ||
    summary.rightful_issuance_proven !== false ||
    summary.portable_rightful_issuance_proven !== false ||
    summary.live_authority_proven !== false ||
    summary.production_rightful_issuance_proven !== false ||
    summary.current_machine_governance_proven !== false ||
    summary.consequence_lifecycle_closed !== false ||
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
    summary.direct_api_with_receipt_refused !== true ||
    summary.agent_supplied_authority_material_refused !== true ||
    summary.runtime_profile_identity_authority_source !== 'launcher-owned-service-config' ||
    summary.persistent_runtime_profile_installed !== false ||
    summary.live_records_system_checked !== false ||
    summary.production_records_service_checked !== false ||
    summary.live_mcp_coverage_checked !== false ||
    summary.live_approval_channel_health_checked !== false ||
    summary.external_attestation !== false ||
    summary.sovereign_recognition !== false ||
    summary.unrouted_records_paths_checked !== false
  ) {
    throw new Error('Proof smoke runtime local activation embedded summary drifted');
  }
  assertRuntimeProfileIdentityBoundary('runtime local activation embedded summary', summary);
  if (
    summary.claim_boundary !==
    'embedded local proof-pack runtime-local-activation summary only; no fresh activation run during verification'
  ) {
    throw new Error('Proof smoke runtime local activation claim boundary drifted');
  }
}

function assertRuntimeProfileInstallationSummary(summary) {
  assertObject(summary, 'sample verification runtime profile installation summary');
  assertExactObjectKeys('Proof smoke runtime profile installation summary', summary, [
    'active_profile_index_written',
    'agent_supplied_authority_material_refused',
    'atomic_store_anchor_witness_commit',
    'claim_boundary',
    'component',
    'consequence_lifecycle_closed',
    'consumed_authority_grant_store',
    'consumed_store_witness',
    'consumed_store_write_model',
    'consumption_identity',
    'current_machine_governance_proven',
    'direct_api_with_receipt_refused',
    'disposable_profile_installation_applied',
    'disposable_profile_selection',
    'disposable_runtime_config_written',
    'evidence_model',
    'exactly_once_effect_semantics',
    'expired_authority_grant_refused',
    'external_attestation',
    'fixture_rightful_issuance_path_evidenced',
    'hook_configuration_written',
    'host_filesystem_path_toctou_closed',
    'invalid_receipt_refused',
    'latest_profile_selected',
    'live_approval_channel_health_checked',
    'live_authority_proven',
    'live_mcp_coverage_checked',
    'live_probing',
    'live_records_system_checked',
    'live_runtime_profile_checked',
    'local_disposable_install_root_created',
    'machine_config_written',
    'mismatched_authority_grant_appointment_refused',
    'missing_authority_grant_appointment_refused',
    'missing_issuer_status_refused',
    'missing_receipt_refused',
    'mutation_authoritative_route',
    'non_boarding_outcome_refused',
    'omitted_request_runtime_profile_id_present',
    'omitted_runtime_profile_id_consumed_authority_grant_count',
    'omitted_runtime_profile_id_reason_code',
    'omitted_runtime_profile_id_state_entry_count_delta',
    'omitted_runtime_profile_id_uses_launcher_config',
    'partial_grant_commit_burn_window_named',
    'persistent_runtime_config_written',
    'persistent_runtime_profile_installed',
    'plan_sha256',
    'portable_rightful_issuance_proven',
    'production_records_service_checked',
    'production_rightful_issuance_proven',
    'profile_copied_to_install_root',
    'profile_selected_from_install_root',
    'proof_type',
    'recognized_write_accepted',
    'request_authority_guard_summary',
    'request_runtime_profile_id_required',
    'request_supplied_authority_grant_refused',
    'restart_consumed_authority_grant_refused',
    'retired_issuer_refused',
    'revoked_authority_grant_refused',
    'rightful_issuance_proven',
    'run_in_proof_pack',
    'runtime_profile_sha256',
    'runtime_profile_identity_authority_source',
    'runtime_profile_identity_request_stream_policy',
    'runtime_profile_sha_matches_plan',
    'runtime_service_started',
    'same_process_signed_payload_replay_refused',
    'signed_payload_replay_identity',
    'sovereign_recognition',
    'stale_receipt_refused',
    'store_anchor_and_witness_joint_rollback_detection',
    'summary_type',
    'supplied_mismatch_reason_code',
    'supplied_mismatch_state_entry_count_delta',
    'supplied_mismatched_runtime_profile_id_refused',
    'unknown_issuer_refused',
    'unrouted_records_paths_checked',
    'user_config_written',
    'wrong_audit_event_refused',
    'wrong_detail_refused',
    'wrong_domain_refused',
    'wrong_policy_refused',
    'wrong_runtime_profile_id_refused',
    'wrong_tool_refused',
  ]);
  if (
    summary.summary_type !==
    'zlar-local-proof-pack-runtime-profile-installation-verification-summary-v1'
  ) {
    throw new Error('Proof smoke runtime profile installation summary type drifted');
  }
  if (summary.component !== 'protected_records_runtime_profile_installation') {
    throw new Error('Proof smoke runtime profile installation summary component drifted');
  }
  if (summary.run_in_proof_pack !== true) {
    throw new Error('Proof smoke runtime profile installation must run in proof pack');
  }
  if (summary.proof_type !== 'zlar-protected-records-runtime-profile-installation-proof-v1') {
    throw new Error('Proof smoke runtime profile installation proof type drifted');
  }
  if (summary.evidence_model !== 'local-disposable-runtime-profile-installation-fixture') {
    throw new Error('Proof smoke runtime profile installation evidence model drifted');
  }
  if (summary.live_probing !== false) {
    throw new Error('Proof smoke runtime profile installation must not live probe');
  }
  if (!/^[a-f0-9]{64}$/.test(summary.plan_sha256 || '')) {
    throw new Error('Proof smoke runtime profile installation plan SHA-256 is malformed');
  }
  if (!/^[a-f0-9]{64}$/.test(summary.runtime_profile_sha256 || '')) {
    throw new Error('Proof smoke runtime profile installation profile SHA-256 is malformed');
  }
  assertExactObjectKeys(
    'Proof smoke runtime profile installation disposable profile selection',
    summary.disposable_profile_selection,
    [
      'active_index_path_in_report',
      'active_profile_index_written',
      'install_root_created',
      'install_root_kind',
      'install_root_path_in_report',
      'installed_profile_path_in_report',
      'installed_profile_status',
      'profile_copy_written',
      'profile_selected_from_install_root',
      'profile_sha_verified_before_selection',
      'profile_status_before_installation',
      'selected_by_explicit_id_and_sha',
      'selected_profile_id',
      'selected_profile_sha256',
      'selected_runtime_profile_id',
      'selects_latest_profile',
    ]
  );
  assertExactObjectKeys(
    'Proof smoke runtime profile installation request authority guard summary',
    summary.request_authority_guard_summary,
    [
      'all_refused_before_mutation',
      'authority_grant_refused',
      'installed_profile_state_refused',
      'reason_codes',
      'recognition_rule_refused',
      'runtime_config_refused',
      'runtime_profile_refused',
      'state_entry_count_delta_total',
    ]
  );
  if (
    summary.runtime_profile_sha_matches_plan !== true ||
    summary.disposable_profile_selection.install_root_kind !== 'launcher-owned-disposable-proof-root' ||
    summary.disposable_profile_selection.install_root_path_in_report !== null ||
    summary.disposable_profile_selection.installed_profile_path_in_report !==
      '<launcher-owned-disposable-install-root>/profiles/protected-records-disposable-runtime-profile.json' ||
    summary.disposable_profile_selection.active_index_path_in_report !==
      '<launcher-owned-disposable-install-root>/active-runtime-profile.json' ||
    summary.disposable_profile_selection.install_root_created !== true ||
    summary.disposable_profile_selection.profile_copy_written !== true ||
    summary.disposable_profile_selection.active_profile_index_written !== true ||
    summary.disposable_profile_selection.profile_selected_from_install_root !== true ||
    summary.disposable_profile_selection.selected_by_explicit_id_and_sha !== true ||
    summary.disposable_profile_selection.selects_latest_profile !== false ||
    summary.disposable_profile_selection.profile_sha_verified_before_selection !== true ||
    summary.disposable_profile_selection.installed_profile_status !== 'installed_in_disposable_proof_root' ||
    summary.disposable_profile_selection.selected_runtime_profile_id !==
      'protected-records-disposable-runtime-profile' ||
    summary.disposable_profile_selection.selected_profile_sha256 !== summary.runtime_profile_sha256
  ) {
    throw new Error('Proof smoke runtime profile installation disposable selection drifted');
  }
  if (
    summary.request_authority_guard_summary.installed_profile_state_refused !== true ||
    summary.request_authority_guard_summary.runtime_config_refused !== true ||
    summary.request_authority_guard_summary.runtime_profile_refused !== true ||
    summary.request_authority_guard_summary.recognition_rule_refused !== true ||
    summary.request_authority_guard_summary.authority_grant_refused !== true ||
    summary.request_authority_guard_summary.all_refused_before_mutation !== true ||
    summary.request_authority_guard_summary.state_entry_count_delta_total !== 0 ||
    !Array.isArray(summary.request_authority_guard_summary.reason_codes) ||
    summary.request_authority_guard_summary.reason_codes.length !== 5 ||
    summary.request_authority_guard_summary.reason_codes.some((item) => item !== 'agent_supplied_authority_material')
  ) {
    throw new Error('Proof smoke runtime profile installation request guard drifted');
  }
  if (
    summary.disposable_profile_installation_applied !== true ||
    summary.local_disposable_install_root_created !== true ||
    summary.profile_copied_to_install_root !== true ||
    summary.active_profile_index_written !== true ||
    summary.profile_selected_from_install_root !== true ||
    summary.disposable_runtime_config_written !== true ||
    summary.persistent_runtime_config_written !== false ||
    summary.hook_configuration_written !== false ||
    summary.user_config_written !== false ||
    summary.machine_config_written !== false ||
    summary.runtime_service_started !== true ||
    summary.recognized_write_accepted !== true ||
    summary.mutation_authoritative_route !==
      'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation' ||
    summary.consumed_authority_grant_store !==
      'persistent-single-use-authority-grant-contract-sha256-store' ||
    summary.consumption_identity !== 'authority-grant-contract-sha256' ||
    summary.signed_payload_replay_identity !== 'verified-signed-payload-sha256' ||
    summary.same_process_signed_payload_replay_refused !== true ||
    summary.restart_consumed_authority_grant_refused !== true ||
    summary.missing_authority_grant_appointment_refused !== true ||
    summary.mismatched_authority_grant_appointment_refused !== true ||
    summary.expired_authority_grant_refused !== true ||
    summary.revoked_authority_grant_refused !== true ||
    summary.request_supplied_authority_grant_refused !== true ||
    summary.store_anchor_and_witness_joint_rollback_detection !== false ||
    summary.atomic_store_anchor_witness_commit !== false ||
    summary.partial_grant_commit_burn_window_named !== true ||
    summary.host_filesystem_path_toctou_closed !== false ||
    summary.fixture_rightful_issuance_path_evidenced !== true ||
    summary.rightful_issuance_proven !== false ||
    summary.portable_rightful_issuance_proven !== false ||
    summary.live_authority_proven !== false ||
    summary.production_rightful_issuance_proven !== false ||
    summary.current_machine_governance_proven !== false ||
    summary.consequence_lifecycle_closed !== false ||
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
    summary.direct_api_with_receipt_refused !== true ||
    summary.agent_supplied_authority_material_refused !== true ||
    summary.runtime_profile_identity_authority_source !== 'launcher-owned-service-config' ||
    summary.persistent_runtime_profile_installed !== false ||
    summary.latest_profile_selected !== false ||
    summary.live_runtime_profile_checked !== false ||
    summary.live_records_system_checked !== false ||
    summary.production_records_service_checked !== false ||
    summary.live_mcp_coverage_checked !== false ||
    summary.live_approval_channel_health_checked !== false ||
    summary.external_attestation !== false ||
    summary.sovereign_recognition !== false ||
    summary.unrouted_records_paths_checked !== false
  ) {
    throw new Error('Proof smoke runtime profile installation embedded summary drifted');
  }
  assertRuntimeProfileIdentityBoundary('runtime profile installation embedded summary', summary);
  if (
    summary.claim_boundary !==
    'embedded local proof-pack runtime-profile-installation summary only; no fresh profile installation run during verification'
  ) {
    throw new Error('Proof smoke runtime profile installation claim boundary drifted');
  }
}

function assertServiceProfilePreflightSummary(summary) {
  assertObject(summary, 'sample verification service profile preflight summary');
  assertExactObjectKeys('Proof smoke service profile preflight summary', summary, [
    'case_count',
    'case_summaries',
    'claim_boundary',
    'component',
    'direct_api_with_receipt_refused',
    'direct_api_without_receipt_refused',
    'evidence_model',
    'external_attestation',
    'launcher_owned_config_required',
    'live_approval_channel_health_checked',
    'live_mcp_coverage_checked',
    'live_probing',
    'live_profile_installed',
    'live_records_system_checked',
    'preflight_type',
    'production_records_service_checked',
    'request_stream_authority_material_allowed',
    'request_stream_authority_material_reason',
    'request_stream_authority_material_refused',
    'request_stream_authority_material_state_delta',
    'request_stream_forbidden_fields_refused',
    'required_case_count',
    'run_in_proof_pack',
    'runtime_profile_activation_checked',
    'sovereign_recognition',
    'summary_type',
    'unrouted_records_paths_checked',
    'wrong_policy_reason',
    'wrong_policy_refused',
    'wrong_policy_state_delta',
  ]);
  if (
    summary.summary_type !==
    'zlar-local-proof-pack-service-profile-preflight-verification-summary-v1'
  ) {
    throw new Error('Proof smoke service profile preflight summary type drifted');
  }
  if (summary.component !== 'protected_records_downstream_service') {
    throw new Error('Proof smoke service profile preflight summary component drifted');
  }
  if (summary.run_in_proof_pack !== true) {
    throw new Error('Proof smoke service profile preflight must run in proof pack');
  }
  if (summary.preflight_type !== 'zlar-protected-records-service-profile-preflight-v1') {
    throw new Error('Proof smoke service profile preflight type drifted');
  }
  if (summary.evidence_model !== 'local-disposable-config-backed-profile-preflight-fixture') {
    throw new Error('Proof smoke service profile preflight evidence model drifted');
  }
  if (summary.live_probing !== false) {
    throw new Error('Proof smoke service profile preflight must not live probe');
  }
  if (summary.case_count !== 11 || summary.required_case_count !== 11) {
    throw new Error('Proof smoke service profile preflight case count drifted');
  }
  if (!Array.isArray(summary.case_summaries) || summary.case_summaries.length !== summary.case_count) {
    throw new Error('Proof smoke service profile preflight case summaries drifted');
  }
  for (const item of summary.case_summaries) {
    assertExactObjectKeys('Proof smoke service profile preflight case summary', item, [
      'case_id',
      'direct_api_attempted',
      'process_invocation',
      'reason_code',
      'service_write_accepted',
      'state_entry_count_delta',
    ]);
  }
  const directApiWithReceipt = summary.case_summaries.find((item) =>
    item.case_id === 'direct_api_profile_receipt_present_refused_before_service_mutation'
  );
  if (
    !directApiWithReceipt ||
    directApiWithReceipt.process_invocation !== 11 ||
    directApiWithReceipt.service_write_accepted !== false ||
    directApiWithReceipt.reason_code !== 'request_stream_forbidden_fields' ||
    directApiWithReceipt.state_entry_count_delta !== 0 ||
    directApiWithReceipt.direct_api_attempted !== true
  ) {
    throw new Error('Proof smoke service profile preflight direct API receipt-present summary drifted');
  }
  const requestStreamAuthority = summary.case_summaries.find((item) =>
    item.case_id === 'request_stream_authority_material_profile_refused_before_service_mutation'
  );
  if (
    !requestStreamAuthority ||
    requestStreamAuthority.process_invocation !== 9 ||
    requestStreamAuthority.service_write_accepted !== false ||
    requestStreamAuthority.reason_code !== 'request_stream_authority_material' ||
    requestStreamAuthority.state_entry_count_delta !== 0 ||
    requestStreamAuthority.direct_api_attempted !== false ||
    summary.launcher_owned_config_required !== true ||
    summary.request_stream_authority_material_allowed !== false ||
    summary.request_stream_authority_material_refused !== true ||
    summary.request_stream_authority_material_reason !== 'request_stream_authority_material' ||
    summary.request_stream_authority_material_state_delta !== 0 ||
    summary.request_stream_forbidden_fields_refused !== true
  ) {
    throw new Error('Proof smoke service profile preflight request-stream authority summary drifted');
  }
  const wrongPolicy = summary.case_summaries.find((item) =>
    item.case_id === 'wrong_policy_profile_refused_before_service_mutation'
  );
  if (
    !wrongPolicy ||
    wrongPolicy.process_invocation !== 7 ||
    wrongPolicy.service_write_accepted !== false ||
    wrongPolicy.reason_code !== 'policy_not_recognized' ||
    wrongPolicy.state_entry_count_delta !== 0 ||
    wrongPolicy.direct_api_attempted !== false ||
    summary.wrong_policy_refused !== true ||
    summary.wrong_policy_reason !== 'policy_not_recognized' ||
    summary.wrong_policy_state_delta !== 0
  ) {
    throw new Error('Proof smoke service profile preflight wrong-policy summary drifted');
  }
  if (
    summary.direct_api_without_receipt_refused !== true ||
    summary.direct_api_with_receipt_refused !== true
  ) {
    throw new Error('Proof smoke service profile preflight direct API refusal drifted');
  }
  for (const field of [
    'live_profile_installed',
    'runtime_profile_activation_checked',
    'live_records_system_checked',
    'production_records_service_checked',
    'live_mcp_coverage_checked',
    'live_approval_channel_health_checked',
    'external_attestation',
    'sovereign_recognition',
    'unrouted_records_paths_checked',
  ]) {
    if (summary[field] !== false) {
      throw new Error(`Proof smoke service profile preflight ${field} must be false`);
    }
  }
  if (
    summary.claim_boundary !==
    'embedded local proof-pack artifact summary only; no fresh preflight run'
  ) {
    throw new Error('Proof smoke service profile preflight claim boundary drifted');
  }
}

function assertServiceProfilePreflightSampleVerification(verification) {
  assertObject(verification, 'service profile preflight sample verification');
  assertExactObjectKeys('Proof smoke service profile preflight sample verification', verification, [
    'artifact_type',
    'body_sha256',
    'canonicalization',
    'case_count',
    'claim_boundary',
    'direct_api_receipt_present_reason',
    'direct_api_receipt_present_state_delta',
    'direct_api_with_receipt_refused',
    'direct_api_without_receipt_refused',
    'direct_api_without_receipt_reason',
    'direct_filesystem_write_to_fixture_paths_closed',
    'evidence_model',
    'external_attestation',
    'hash_scope',
    'invalid_receipt_refused',
    'launcher_owned_config_required',
    'live_profile_installed',
    'live_probing',
    'missing_receipt_refused',
    'non_claims',
    'payload_type',
    'production_records_service_checked',
    'profile_sha256',
    'recognized_write_accepted',
    'replay_refused',
    'request_stream_authority_material_allowed',
    'request_stream_authority_material_reason',
    'request_stream_authority_material_refused',
    'request_stream_authority_material_state_delta',
    'request_stream_forbidden_fields_refused',
    'required_body_sha256',
    'required_body_sha256_matched',
    'required_case_count',
    'sovereign_recognition',
    'stale_receipt_refused',
    'unknown_issuer_refused',
    'unrecognized_receipt_refused',
    'verification_type',
    'verified',
    'wrong_policy_reason',
    'wrong_policy_refused',
    'wrong_policy_state_delta',
  ]);
  if (
    verification.verification_type !==
    PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE
  ) {
    throw new Error('Proof smoke service profile preflight sample verification type drifted');
  }
  if (verification.verified !== true) {
    throw new Error('Proof smoke service profile preflight sample artifact must verify');
  }
  if (verification.evidence_model !== 'local-disposable-config-backed-profile-preflight-fixture') {
    throw new Error('Proof smoke service profile preflight sample verification must use local fixture evidence');
  }
  if (verification.live_probing !== false) {
    throw new Error('Proof smoke service profile preflight sample verification must not perform live probing');
  }
  if (
    verification.claim_boundary !==
    'artifact integrity and embedded local service-profile preflight boundaries only'
  ) {
    throw new Error('Proof smoke service profile preflight sample verification claim boundary drifted');
  }
  if (!/^[a-f0-9]{64}$/.test(verification.body_sha256 || '')) {
    throw new Error('Proof smoke service profile preflight sample artifact SHA-256 is malformed');
  }
  assertRequiredBodySha256Posture(
    verification,
    serviceProfilePreflightSampleArtifactBodySha256(),
    'service profile preflight sample verification'
  );
  if (
    verification.case_count !== 11 ||
    verification.required_case_count !== 11 ||
    verification.recognized_write_accepted !== true ||
    verification.replay_refused !== true ||
    verification.missing_receipt_refused !== true ||
    verification.unrecognized_receipt_refused !== true ||
    verification.invalid_receipt_refused !== true ||
    verification.unknown_issuer_refused !== true ||
    verification.wrong_policy_refused !== true ||
    verification.wrong_policy_reason !== 'policy_not_recognized' ||
    verification.wrong_policy_state_delta !== 0 ||
    verification.stale_receipt_refused !== true ||
    verification.launcher_owned_config_required !== true ||
    verification.request_stream_authority_material_allowed !== false ||
    verification.request_stream_authority_material_refused !== true ||
    verification.request_stream_authority_material_reason !== 'request_stream_authority_material' ||
    verification.request_stream_authority_material_state_delta !== 0 ||
    verification.request_stream_forbidden_fields_refused !== true ||
    verification.direct_api_without_receipt_refused !== true ||
    verification.direct_api_with_receipt_refused !== true ||
    verification.direct_api_without_receipt_reason !== 'request_stream_forbidden_fields' ||
    verification.direct_api_receipt_present_reason !== 'request_stream_forbidden_fields' ||
    verification.direct_api_receipt_present_state_delta !== 0
  ) {
    throw new Error('Proof smoke service profile preflight sample refusal summary drifted');
  }
  for (const field of [
    'direct_filesystem_write_to_fixture_paths_closed',
    'live_profile_installed',
    'production_records_service_checked',
    'external_attestation',
    'sovereign_recognition',
  ]) {
    if (verification[field] !== false) {
      throw new Error(`Proof smoke service profile preflight sample ${field} must be false`);
    }
  }
}

function assertActivationPreflightSampleVerification(verification) {
  assertObject(verification, 'activation preflight sample verification');
  if (
    verification.verification_type !==
    PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE
  ) {
    throw new Error('Proof smoke activation preflight sample verification type drifted');
  }
  if (verification.verified !== true) {
    throw new Error('Proof smoke activation preflight sample artifact must verify');
  }
  if (verification.evidence_model !== 'local-runtime-activation-plan-preflight-fixture') {
    throw new Error('Proof smoke activation preflight sample verification must use local fixture evidence');
  }
  if (verification.live_probing !== false) {
    throw new Error('Proof smoke activation preflight sample verification must not perform live probing');
  }
  if (
    verification.claim_boundary !==
    'artifact integrity and embedded local runtime activation preflight boundaries only'
  ) {
    throw new Error('Proof smoke activation preflight sample verification claim boundary drifted');
  }
  if (!/^[a-f0-9]{64}$/.test(verification.body_sha256 || '')) {
    throw new Error('Proof smoke activation preflight sample artifact SHA-256 is malformed');
  }
  assertRequiredBodySha256Posture(
    verification,
    activationPreflightSampleArtifactBodySha256(),
    'activation preflight sample verification'
  );
  assertRuntimeProfileIdentityBoundary('activation preflight sample verification', verification);
}

function assertRuntimeLocalActivationSampleVerification(verification) {
  assertObject(verification, 'runtime local activation sample verification');
  assertExactObjectKeys('Proof smoke runtime local activation sample verification', verification, [
    'agent_supplied_authority_material_refused',
    'artifact_type',
    'atomic_store_anchor_witness_commit',
    'body_sha256',
    'canonicalization',
    'claim_boundary',
    'consumed_authority_grant_store',
    'consumption_identity',
    'direct_api_with_receipt_refused',
    'disposable_runtime_config_written',
    'evidence_model',
    'expired_authority_grant_refused',
    'hash_scope',
    'hook_configuration_written',
    'host_filesystem_path_toctou_closed',
    'invalid_receipt_refused',
    'live_probing',
    'local_activation_applied',
    'mismatched_authority_grant_appointment_refused',
    'missing_authority_grant_appointment_refused',
    'missing_issuer_status_refused',
    'missing_receipt_refused',
    'non_boarding_outcome_refused',
    'non_claims',
    'omitted_request_runtime_profile_id_present',
    'omitted_runtime_profile_id_consumed_authority_grant_count',
    'omitted_runtime_profile_id_reason_code',
    'omitted_runtime_profile_id_state_entry_count_delta',
    'omitted_runtime_profile_id_uses_launcher_config',
    'partial_grant_commit_burn_window_named',
    'payload_type',
    'persistent_runtime_config_written',
    'plan_sha256',
    'recognized_write_accepted',
    'request_runtime_profile_id_required',
    'request_supplied_authority_grant_refused',
    'required_body_sha256',
    'required_body_sha256_matched',
    'restart_consumed_authority_grant_refused',
    'retired_issuer_refused',
    'revoked_authority_grant_refused',
    'runtime_profile_sha256',
    'runtime_profile_identity_authority_source',
    'runtime_profile_identity_request_stream_policy',
    'runtime_profile_sha_matches_plan',
    'runtime_service_started',
    'same_process_signed_payload_replay_refused',
    'signed_payload_replay_identity',
    'stale_receipt_refused',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse',
    'store_and_anchor_joint_rollback_refused_while_witness_ahead',
    'supplied_mismatch_reason_code',
    'supplied_mismatch_state_entry_count_delta',
    'supplied_mismatched_runtime_profile_id_refused',
    'unknown_issuer_refused',
    'verification_type',
    'verified',
    'witness_commit_failed_after_authority_grant_store_commit',
    'witness_commit_failure_reason_code',
    'wrong_audit_event_refused',
    'wrong_detail_refused',
    'wrong_domain_refused',
    'wrong_policy_refused',
    'wrong_runtime_profile_id_refused',
    'wrong_tool_refused',
  ]);
  if (
    verification.verification_type !==
    PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_VERIFICATION_TYPE
  ) {
    throw new Error('Proof smoke runtime local activation sample verification type drifted');
  }
  if (verification.verified !== true) {
    throw new Error('Proof smoke runtime local activation sample artifact must verify');
  }
  if (verification.evidence_model !== 'local-disposable-runtime-activation-fixture') {
    throw new Error('Proof smoke runtime local activation sample verification must use local fixture evidence');
  }
  if (verification.live_probing !== false) {
    throw new Error('Proof smoke runtime local activation sample verification must not perform live probing');
  }
  if (
    verification.claim_boundary !==
    'artifact integrity and embedded local disposable runtime activation proof boundaries only'
  ) {
    throw new Error('Proof smoke runtime local activation sample verification claim boundary drifted');
  }
  if (!/^[a-f0-9]{64}$/.test(verification.body_sha256 || '')) {
    throw new Error('Proof smoke runtime local activation sample artifact SHA-256 is malformed');
  }
  assertRequiredBodySha256Posture(
    verification,
    runtimeLocalActivationSampleArtifactBodySha256(),
    'runtime local activation sample verification'
  );
  if (!/^[a-f0-9]{64}$/.test(verification.plan_sha256 || '')) {
    throw new Error('Proof smoke runtime local activation sample plan SHA-256 is malformed');
  }
  if (!/^[a-f0-9]{64}$/.test(verification.runtime_profile_sha256 || '')) {
    throw new Error('Proof smoke runtime local activation sample profile SHA-256 is malformed');
  }
  if (
    verification.local_activation_applied !== true ||
    verification.disposable_runtime_config_written !== true ||
    verification.persistent_runtime_config_written !== false ||
    verification.hook_configuration_written !== false ||
    verification.runtime_service_started !== true ||
    verification.runtime_profile_sha_matches_plan !== true ||
    verification.runtime_profile_identity_authority_source !== 'launcher-owned-service-config' ||
    verification.recognized_write_accepted !== true ||
    verification.consumed_authority_grant_store !==
      'persistent-single-use-authority-grant-contract-sha256-store' ||
    verification.consumption_identity !== 'authority-grant-contract-sha256' ||
    verification.signed_payload_replay_identity !== 'verified-signed-payload-sha256' ||
    verification.same_process_signed_payload_replay_refused !== true ||
    verification.restart_consumed_authority_grant_refused !== true ||
    verification.missing_authority_grant_appointment_refused !== true ||
    verification.mismatched_authority_grant_appointment_refused !== true ||
    verification.expired_authority_grant_refused !== true ||
    verification.revoked_authority_grant_refused !== true ||
    verification.request_supplied_authority_grant_refused !== true ||
    verification.witness_commit_failed_after_authority_grant_store_commit !== true ||
    verification.store_and_anchor_joint_rollback_refused_while_witness_ahead !== true ||
    verification.store_anchor_and_witness_joint_rollback_detection !== false ||
    verification.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse !== true ||
    verification.atomic_store_anchor_witness_commit !== false ||
    verification.partial_grant_commit_burn_window_named !== true ||
    verification.host_filesystem_path_toctou_closed !== false ||
    verification.missing_receipt_refused !== true ||
    verification.invalid_receipt_refused !== true ||
    verification.unknown_issuer_refused !== true ||
    verification.retired_issuer_refused !== true ||
    verification.missing_issuer_status_refused !== true ||
    verification.stale_receipt_refused !== true ||
    verification.wrong_policy_refused !== true ||
    verification.wrong_domain_refused !== true ||
    verification.wrong_tool_refused !== true ||
    verification.wrong_runtime_profile_id_refused !== true ||
    verification.wrong_audit_event_refused !== true ||
    verification.wrong_detail_refused !== true ||
    verification.non_boarding_outcome_refused !== true ||
    verification.direct_api_with_receipt_refused !== true ||
    verification.agent_supplied_authority_material_refused !== true
  ) {
    throw new Error('Proof smoke runtime local activation sample boundary summary drifted');
  }
  assertRuntimeProfileIdentityBoundary('runtime local activation sample verification', verification);
}

function assertRuntimeProfileInstallationSampleVerification(verification) {
  assertObject(verification, 'runtime profile installation sample verification');
  assertExactObjectKeys('Proof smoke runtime profile installation sample verification', verification, [
    'active_profile_index_written',
    'agent_supplied_authority_material_refused',
    'artifact_type',
    'atomic_store_anchor_witness_commit',
    'body_sha256',
    'canonicalization',
    'claim_boundary',
    'direct_api_with_receipt_refused',
    'disposable_profile_installation_applied',
    'evidence_model',
    'expired_authority_grant_refused',
    'fixture_rightful_issuance_path_evidenced',
    'hash_scope',
    'hook_configuration_written',
    'host_filesystem_path_toctou_closed',
    'invalid_receipt_refused',
    'live_probing',
    'machine_config_written',
    'mismatched_authority_grant_appointment_refused',
    'missing_authority_grant_appointment_refused',
    'missing_issuer_status_refused',
    'missing_receipt_refused',
    'non_boarding_outcome_refused',
    'non_claims',
    'omitted_request_runtime_profile_id_present',
    'omitted_runtime_profile_id_consumed_authority_grant_count',
    'omitted_runtime_profile_id_reason_code',
    'omitted_runtime_profile_id_state_entry_count_delta',
    'omitted_runtime_profile_id_uses_launcher_config',
    'partial_grant_commit_burn_window_named',
    'payload_type',
    'persistent_runtime_profile_installed',
    'plan_sha256',
    'profile_copied_to_install_root',
    'profile_selected_from_install_root',
    'recognized_write_accepted',
    'replay_after_restart_refused',
    'request_authority_guard_refused',
    'request_runtime_profile_id_required',
    'request_supplied_authority_grant_refused',
    'required_body_sha256',
    'required_body_sha256_matched',
    'restart_consumed_authority_grant_refused',
    'retired_issuer_refused',
    'revoked_authority_grant_refused',
    'runtime_profile_sha256',
    'runtime_profile_identity_authority_source',
    'runtime_profile_identity_request_stream_policy',
    'runtime_profile_sha_matches_plan',
    'runtime_service_started',
    'same_process_signed_payload_replay_refused',
    'selected_by_explicit_id_and_sha',
    'selects_latest_profile',
    'user_config_written',
    'verification_type',
    'verified',
    'stale_receipt_refused',
    'store_anchor_and_witness_joint_rollback_detection',
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
  ]);
  if (
    verification.verification_type !==
    PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_VERIFICATION_TYPE
  ) {
    throw new Error('Proof smoke runtime profile installation sample verification type drifted');
  }
  if (verification.verified !== true) {
    throw new Error('Proof smoke runtime profile installation sample artifact must verify');
  }
  if (verification.evidence_model !== 'local-disposable-runtime-profile-installation-fixture') {
    throw new Error('Proof smoke runtime profile installation sample verification must use local fixture evidence');
  }
  if (verification.live_probing !== false) {
    throw new Error('Proof smoke runtime profile installation sample verification must not perform live probing');
  }
  if (
    verification.claim_boundary !==
    'artifact integrity and embedded local disposable runtime profile installation proof boundaries only'
  ) {
    throw new Error('Proof smoke runtime profile installation sample verification claim boundary drifted');
  }
  if (!/^[a-f0-9]{64}$/.test(verification.body_sha256 || '')) {
    throw new Error('Proof smoke runtime profile installation sample artifact SHA-256 is malformed');
  }
  assertRequiredBodySha256Posture(
    verification,
    runtimeProfileInstallationSampleArtifactBodySha256(),
    'runtime profile installation sample verification'
  );
  if (!/^[a-f0-9]{64}$/.test(verification.plan_sha256 || '')) {
    throw new Error('Proof smoke runtime profile installation sample plan SHA-256 is malformed');
  }
  if (!/^[a-f0-9]{64}$/.test(verification.runtime_profile_sha256 || '')) {
    throw new Error('Proof smoke runtime profile installation sample profile SHA-256 is malformed');
  }
  if (
    verification.runtime_profile_sha_matches_plan !== true ||
    verification.runtime_profile_identity_authority_source !== 'launcher-owned-service-config' ||
    verification.request_authority_guard_refused !== true ||
    verification.disposable_profile_installation_applied !== true ||
    verification.profile_copied_to_install_root !== true ||
    verification.active_profile_index_written !== true ||
    verification.profile_selected_from_install_root !== true ||
    verification.selected_by_explicit_id_and_sha !== true ||
    verification.selects_latest_profile !== false ||
    verification.persistent_runtime_profile_installed !== false ||
    verification.hook_configuration_written !== false ||
    verification.user_config_written !== false ||
    verification.machine_config_written !== false ||
    verification.runtime_service_started !== true ||
    verification.recognized_write_accepted !== true ||
    verification.replay_after_restart_refused !== true ||
    verification.same_process_signed_payload_replay_refused !== true ||
    verification.restart_consumed_authority_grant_refused !== true ||
    verification.missing_authority_grant_appointment_refused !== true ||
    verification.mismatched_authority_grant_appointment_refused !== true ||
    verification.expired_authority_grant_refused !== true ||
    verification.revoked_authority_grant_refused !== true ||
    verification.request_supplied_authority_grant_refused !== true ||
    verification.store_anchor_and_witness_joint_rollback_detection !== false ||
    verification.atomic_store_anchor_witness_commit !== false ||
    verification.partial_grant_commit_burn_window_named !== true ||
    verification.host_filesystem_path_toctou_closed !== false ||
    verification.fixture_rightful_issuance_path_evidenced !== true ||
    verification.missing_receipt_refused !== true ||
    verification.invalid_receipt_refused !== true ||
    verification.unknown_issuer_refused !== true ||
    verification.retired_issuer_refused !== true ||
    verification.missing_issuer_status_refused !== true ||
    verification.stale_receipt_refused !== true ||
    verification.wrong_policy_refused !== true ||
    verification.wrong_domain_refused !== true ||
    verification.wrong_tool_refused !== true ||
    verification.wrong_runtime_profile_id_refused !== true ||
    verification.wrong_audit_event_refused !== true ||
    verification.wrong_detail_refused !== true ||
    verification.non_boarding_outcome_refused !== true ||
    verification.direct_api_with_receipt_refused !== true ||
    verification.agent_supplied_authority_material_refused !== true
  ) {
    throw new Error('Proof smoke runtime profile installation sample boundary summary drifted');
  }
  assertRuntimeProfileIdentityBoundary('runtime profile installation sample verification', verification);
}

function assertInstalledRuntimeProfilePreflightSampleVerification(verification) {
  assertObject(verification, 'installed runtime profile preflight sample verification');
  assertExactObjectKeys('Proof smoke installed runtime profile preflight sample verification', verification, [
    'active_index_read',
    'actual_issuer_appointment_present',
    'actual_issuer_kid_present',
    'actual_issuer_public_key_present',
    'artifact_type',
    'authority_grant_hash_cycle_avoided',
    'authority_grant_requirement_preserved',
    'authority_grant_requirement_sha256',
    'authority_grant_requirement_type',
    'authority_grant_runtime_enforcement_performed',
    'body_sha256',
    'canonicalization',
    'claim_boundary',
    'concrete_grant_window_present',
    'consequence_lifecycle_closed',
    'consequence_path',
    'current_machine_governance_proven',
    'downstream_refusal_proven',
    'evidence_model',
    'exact_runtime_authority_grant_contract_deferred',
    'exact_runtime_authority_grant_contract_instantiated',
    'expected_runtime_authority_grant_contract_type',
    'hash_scope',
    'hook_configuration_written',
    'installed_profile_contract_validated',
    'installed_profile_read',
    'launcher_owned_local_fixture_authority_grant_overlay',
    'live_probing',
    'live_records_system_checked',
    'live_runtime_profile_checked',
    'machine_config_written',
    'non_claims',
    'payload_type',
    'production_records_service_checked',
    'profile_selected_from_install_root',
    'profile_sha_matches_active_index',
    'profile_sha_matches_expected',
    'profile_wide_target_authority_proven',
    'read_only',
    'recognition_boundary',
    'recognition_contract_preserved',
    'recognition_contract_sha256',
    'recognition_rule_supplied_by_agent',
    'request_stream_authority_material_accepted',
    'requested_profile_id',
    'requested_profile_sha256',
    'required_body_sha256',
    'required_body_sha256_matched',
    'required_refusal_case_count',
    'rightful_issuance_proven',
    'mutation_authoritative_route',
    'runtime_config_written',
    'runtime_profile_activation_performed',
    'runtime_profile_installation_performed',
    'runtime_service_started',
    'selected_by_explicit_id_and_sha',
    'selects_latest_profile',
    'source_profile_authority_grant_present',
    'source_profile_target_handle_present',
    'target_contract_preserved',
    'target_contract_sha256',
    'target_descriptor_sha256',
    'target_handle',
    'target_instance_scope',
    'target_kind',
    'target_scope',
    'user_config_written',
    'verification_type',
    'verified',
  ]);
  if (
    verification.verification_type !==
    PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE
  ) {
    throw new Error('Proof smoke installed runtime profile preflight sample verification type drifted');
  }
  if (verification.verified !== true) {
    throw new Error('Proof smoke installed runtime profile preflight sample artifact must verify');
  }
  if (verification.evidence_model !== 'supplied-installed-runtime-profile-root-read-only') {
    throw new Error('Proof smoke installed runtime profile preflight sample evidence model drifted');
  }
  if (verification.live_probing !== false || verification.read_only !== true) {
    throw new Error('Proof smoke installed runtime profile preflight sample must be read-only and non-live');
  }
  if (
    verification.claim_boundary !==
    'artifact integrity and embedded read-only installed runtime profile preflight boundaries only'
  ) {
    throw new Error('Proof smoke installed runtime profile preflight claim boundary drifted');
  }
  if (!/^[a-f0-9]{64}$/.test(verification.body_sha256 || '')) {
    throw new Error('Proof smoke installed runtime profile preflight sample artifact SHA-256 is malformed');
  }
  assertRequiredBodySha256Posture(
    verification,
    installedRuntimeProfilePreflightSampleArtifactBodySha256(),
    'installed runtime profile preflight sample verification'
  );
  if (!/^[a-f0-9]{64}$/.test(verification.requested_profile_sha256 || '')) {
    throw new Error('Proof smoke installed runtime profile preflight sample profile SHA-256 is malformed');
  }
  if (
    verification.active_index_read !== true ||
    verification.installed_profile_read !== true ||
    verification.installed_profile_contract_validated !== true ||
    verification.profile_selected_from_install_root !== true ||
    verification.selected_by_explicit_id_and_sha !== true ||
    verification.selects_latest_profile !== false ||
    verification.profile_sha_matches_expected !== true ||
    verification.profile_sha_matches_active_index !== true ||
    verification.recognition_contract_preserved !== true ||
    !/^[a-f0-9]{64}$/.test(verification.recognition_contract_sha256 || '') ||
    verification.target_contract_preserved !== true ||
    !/^[a-f0-9]{64}$/.test(verification.target_contract_sha256 || '') ||
    verification.consequence_path !==
      'protected-records.installed-runtime-profile.terminal-chain.records.write' ||
    verification.target_kind !== 'process-private-recognized-effect-state' ||
    verification.target_scope !== 'logical-fixture' ||
    verification.target_instance_scope !== 'logical-fixture-not-per-run' ||
    !/^[a-f0-9]{64}$/.test(verification.target_descriptor_sha256 || '') ||
    verification.target_handle !==
      `zlar-target:v1:${verification.target_scope}:${verification.target_descriptor_sha256}` ||
    verification.source_profile_target_handle_present !== false ||
    verification.profile_wide_target_authority_proven !== false ||
    verification.source_profile_authority_grant_present !== false ||
    verification.authority_grant_requirement_preserved !== true ||
    verification.authority_grant_requirement_type !==
      'zlar-installed-runtime-profile-authority-grant-requirement-v1' ||
    !/^[a-f0-9]{64}$/.test(verification.authority_grant_requirement_sha256 || '') ||
    verification.authority_grant_hash_cycle_avoided !== true ||
    verification.exact_runtime_authority_grant_contract_deferred !== true ||
    verification.exact_runtime_authority_grant_contract_instantiated !== false ||
    verification.expected_runtime_authority_grant_contract_type !==
      'zlar-protected-records-fixture-authority-grant-contract-v1' ||
    verification.launcher_owned_local_fixture_authority_grant_overlay !== true ||
    verification.concrete_grant_window_present !== false ||
    verification.actual_issuer_appointment_present !== false ||
    verification.actual_issuer_kid_present !== false ||
    verification.actual_issuer_public_key_present !== false ||
    verification.authority_grant_runtime_enforcement_performed !== false ||
    verification.rightful_issuance_proven !== false ||
    verification.consequence_lifecycle_closed !== false ||
    verification.recognition_boundary !== 'service-configured-recognition-rule' ||
    verification.mutation_authoritative_route !==
      'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation' ||
    verification.request_stream_authority_material_accepted !== false ||
    verification.recognition_rule_supplied_by_agent !== false ||
    !Number.isInteger(verification.required_refusal_case_count) ||
    verification.required_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length ||
    verification.runtime_profile_installation_performed !== false ||
    verification.runtime_profile_activation_performed !== false ||
    verification.runtime_config_written !== false ||
    verification.hook_configuration_written !== false ||
    verification.user_config_written !== false ||
    verification.machine_config_written !== false ||
    verification.runtime_service_started !== false ||
    verification.live_runtime_profile_checked !== false ||
    verification.live_records_system_checked !== false ||
    verification.production_records_service_checked !== false ||
    verification.downstream_refusal_proven !== false ||
    verification.current_machine_governance_proven !== false
  ) {
    throw new Error('Proof smoke installed runtime profile preflight sample boundary summary drifted');
  }
}

function assertStep(step, expected) {
  assertExactObjectKeys('Proof smoke report step', step, [
    'step',
    'command',
    'result',
    expected.payloadKey,
  ]);
  if (step.step !== expected.step) {
    throw new Error(`Proof smoke step drifted: expected ${expected.step}`);
  }
  if (step.command !== expected.command) {
    throw new Error(`Proof smoke command drifted for ${expected.step}`);
  }
  if (step.result !== 'passed') {
    throw new Error(`Proof smoke step failed: ${expected.step}`);
  }
}

export function buildProofSmokeReport({
  sampleVerification,
  serviceProfilePreflightSampleVerification,
  activationPreflightSampleVerification,
  runtimeLocalActivationSampleVerification,
  runtimeProfileInstallationSampleVerification,
  installedRuntimeProfilePreflightSampleVerification,
  installedRuntimeProfileRecognitionProof,
  installedRuntimeProfileServiceProof,
  installedRuntimeProfileServiceProofArtifactVerification,
  installedRuntimeProfileTerminalChain,
  installedRuntimeProfileTerminalChainArtifactVerification,
  configuredRecognitionReplayStoreProof,
  sourceBridgeWindowAuthority,
  coverageMap,
}) {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
    'Proof smoke fresh consequence execution and fixture-rightful projection',
  );
  assertSampleVerification(sampleVerification);
  assertServiceProfilePreflightSampleVerification(serviceProfilePreflightSampleVerification);
  assertActivationPreflightSampleVerification(activationPreflightSampleVerification);
  assertRuntimeLocalActivationSampleVerification(runtimeLocalActivationSampleVerification);
  assertRuntimeProfileInstallationSampleVerification(runtimeProfileInstallationSampleVerification);
  assertInstalledRuntimeProfilePreflightSampleVerification(installedRuntimeProfilePreflightSampleVerification);
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(installedRuntimeProfileRecognitionProof);
  assertProtectedRecordsInstalledRuntimeProfileServiceProof(installedRuntimeProfileServiceProof);
  assertRequiredBodySha256Posture(
    installedRuntimeProfileServiceProofArtifactVerification,
    installedRuntimeProfileServiceProofSampleArtifactBodySha256(),
    'installed runtime profile service proof artifact verification'
  );
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification(
    verificationWithoutRequiredBodySha256(
      installedRuntimeProfileServiceProofArtifactVerification
    )
  );
  assertProtectedRecordsInstalledRuntimeProfileTerminalChain(installedRuntimeProfileTerminalChain);
  assertRequiredBodySha256Posture(
    installedRuntimeProfileTerminalChainArtifactVerification,
    installedRuntimeProfileTerminalChainSampleArtifactBodySha256(),
    'installed runtime profile terminal chain artifact verification'
  );
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification(
    verificationWithoutRequiredBodySha256(
      installedRuntimeProfileTerminalChainArtifactVerification
    )
  );
  assertConfiguredRecognitionConsumerReplayStoreProof(configuredRecognitionReplayStoreProof);
  assertSourceBridgeWindowAuthorityReport(sourceBridgeWindowAuthority);
  assertTerminalChainArtifactVerificationMatchesChainBoundary(
    installedRuntimeProfileTerminalChainArtifactVerification,
    installedRuntimeProfileTerminalChain,
    'installed runtime profile terminal chain artifact verification'
  );
  assertGovernedSurfaceCoverageMap(coverageMap);
  const consequenceLifecycleMap = buildConsequenceLifecycleMap(
    consequenceLifecycleMapSampleArtifact()
  );
  assertConsequenceLifecycleMap(
    consequenceLifecycleMap,
    consequenceLifecycleMapSampleArtifact()
  );

  const report = {
    report_type: PROOF_SMOKE_REPORT_TYPE,
    result: 'passed',
    evidence_model: PROOF_SMOKE_EVIDENCE_MODEL,
    live_probing: false,
    claim_boundary: PROOF_SMOKE_CLAIM_BOUNDARY,
    steps: [
      {
        step: 'sample_artifact_verification',
        command: `zlar local-proof-pack verify --sample --require-sha ${localProofPackSampleArtifactBodySha256()} --json`,
        result: 'passed',
        verification: sampleVerification,
      },
      {
        step: 'service_profile_preflight_sample_artifact_verification',
        command: `zlar protected-records-service-preflight verify --sample --require-sha ${serviceProfilePreflightSampleArtifactBodySha256()} --json`,
        result: 'passed',
        verification: serviceProfilePreflightSampleVerification,
      },
      {
        step: 'activation_preflight_sample_artifact_verification',
        command: `zlar protected-records-runtime-activation-preflight verify --sample --require-sha ${activationPreflightSampleArtifactBodySha256()} --json`,
        result: 'passed',
        verification: activationPreflightSampleVerification,
      },
      {
        step: 'runtime_local_activation_sample_artifact_verification',
        command: `zlar protected-records-runtime-local-activation verify --sample --require-sha ${runtimeLocalActivationSampleArtifactBodySha256()} --json`,
        result: 'passed',
        verification: runtimeLocalActivationSampleVerification,
      },
      {
        step: 'runtime_profile_installation_sample_artifact_verification',
        command: `zlar protected-records-runtime-profile-installation verify --sample --require-sha ${runtimeProfileInstallationSampleArtifactBodySha256()} --json`,
        result: 'passed',
        verification: runtimeProfileInstallationSampleVerification,
      },
      {
        step: 'installed_runtime_profile_preflight_sample_artifact_verification',
        command: `zlar protected-records-installed-runtime-profile-preflight verify --sample --require-sha ${installedRuntimeProfilePreflightSampleArtifactBodySha256()} --json`,
        result: 'passed',
        verification: installedRuntimeProfilePreflightSampleVerification,
      },
      {
        step: 'installed_runtime_profile_recognition_proof',
        command: 'zlar protected-records-installed-runtime-profile-recognition-proof --sample --json',
        result: 'passed',
        proof: installedRuntimeProfileRecognitionProof,
      },
      {
        step: 'installed_runtime_profile_service_proof',
        command: 'zlar protected-records-installed-runtime-profile-service-proof --sample --json',
        result: 'passed',
        proof: installedRuntimeProfileServiceProof,
      },
      {
        step: 'installed_runtime_profile_service_proof_artifact_verification',
        command: `zlar protected-records-installed-runtime-profile-service-proof verify --sample --require-sha ${installedRuntimeProfileServiceProofSampleArtifactBodySha256()} --json`,
        result: 'passed',
        verification: installedRuntimeProfileServiceProofArtifactVerification,
      },
      {
        step: 'installed_runtime_profile_terminal_chain',
        command: 'zlar protected-records-installed-runtime-profile-terminal-chain --sample --json',
        result: 'passed',
        chain: installedRuntimeProfileTerminalChain,
      },
      {
        step: 'installed_runtime_profile_terminal_chain_artifact_verification',
        command: `zlar protected-records-installed-runtime-profile-terminal-chain verify --sample --require-sha ${installedRuntimeProfileTerminalChainSampleArtifactBodySha256()} --json`,
        result: 'passed',
        verification: installedRuntimeProfileTerminalChainArtifactVerification,
      },
      {
        step: 'configured_recognition_consumer_replay_store_proof',
        command: 'zlar configured-recognition-consumer-replay-store-proof --json',
        result: 'passed',
        proof: configuredRecognitionReplayStoreProof,
      },
      {
        step: 'source_bridge_window_authority_sample',
        command: 'zlar source-bridge-window --sample --json',
        result: 'passed',
        authority: sourceBridgeWindowAuthority,
      },
      {
        step: 'fixture_input_coverage_map',
        command: 'zlar coverage --sample --require-governed --json',
        result: 'passed',
        coverage_map: coverageMap,
      },
      {
        step: 'consequence_lifecycle_map_projection',
        command: 'zlar consequence-lifecycle --sample --json',
        result: 'passed',
        lifecycle_map: consequenceLifecycleMap,
      },
    ],
    counts: {
      local_proof_pack_artifact_body_sha256:
        localProofPackSampleArtifactBodySha256(),
      service_profile_preflight_artifact_body_sha256:
        serviceProfilePreflightSampleVerification.body_sha256,
      activation_preflight_artifact_body_sha256:
        activationPreflightSampleVerification.body_sha256,
      runtime_local_activation_artifact_body_sha256:
        runtimeLocalActivationSampleVerification.body_sha256,
      runtime_profile_installation_artifact_body_sha256:
        runtimeProfileInstallationSampleVerification.body_sha256,
      installed_runtime_profile_preflight_artifact_body_sha256:
        installedRuntimeProfilePreflightSampleVerification.body_sha256,
      installed_runtime_profile_recognition_proof_sha256:
        sha256hex(canonicalize(installedRuntimeProfileRecognitionProof)),
      installed_runtime_profile_service_proof_artifact_body_sha256:
        installedRuntimeProfileServiceProofArtifactVerification.body_sha256,
      installed_runtime_profile_terminal_chain_artifact_body_sha256:
        installedRuntimeProfileTerminalChainArtifactVerification.body_sha256,
      consequence_lifecycle_map_projection_sha256:
        consequenceLifecycleMapSha256(consequenceLifecycleMap),
      coverage_map_sha256: sha256hex(canonicalize(coverageMap)),
      sample_artifact_verified: true,
      key_state_report_summary_verified: true,
      key_state_private_key_material_read:
        sampleVerification.key_state_report.private_key_material_read,
      key_state_key_custody_proven:
        sampleVerification.key_state_report.key_custody_proven,
      key_state_current_machine_governance_proven:
        sampleVerification.key_state_report.current_machine_governance_proven,
      downstream_refusal_summary_verified: true,
      downstream_refusal_recognized_marker_count_delta:
        sampleVerification.downstream_refusal.recognized_marker_count_delta,
      downstream_refusal_final_marker_count:
        sampleVerification.downstream_refusal.final_marker_count,
      downstream_refusal_case_count:
        sampleVerification.downstream_refusal.refusal_case_count,
      downstream_refusal_marker_deltas_zero:
        sampleVerification.downstream_refusal.all_refusal_marker_count_deltas_zero,
      receipt_verifier_boundary_summary_verified: true,
      receipt_verifier_v1_identity_verified:
        sampleVerification.receipt_verifier_boundary.valid_receipt_sha256_present === true &&
        sampleVerification.receipt_verifier_boundary.valid_provided_pubkey_sha256_present === true &&
        sampleVerification.receipt_verifier_boundary.required_identity_receipt_sha256_matched === true &&
        sampleVerification.receipt_verifier_boundary.required_identity_pubkey_sha256_matched === true &&
        sampleVerification.receipt_verifier_boundary.required_identity_v1_only_matched === true,
      receipt_verifier_legacy_v0_required_identity_refused:
        sampleVerification.receipt_verifier_boundary.legacy_v0_required_identity_refused,
      receipt_verifier_unknown_signer_distinguished:
        sampleVerification.receipt_verifier_boundary.distinguishes_unknown_signer_from_invalid,
      trusted_issuer_registry_recognition_summary_verified: true,
      trusted_issuer_registry_recognition_observed:
        sampleVerification.trusted_issuer_registry_recognition.recognized,
      trusted_issuer_registry_fixture_validated:
        sampleVerification.trusted_issuer_registry_recognition.registry_fixture_validated,
      trusted_issuer_registry_fixture_evaluated:
        sampleVerification.trusted_issuer_registry_recognition.registry_fixture_evaluated,
      trusted_issuer_registry_to_recognition_rule_evaluated:
        sampleVerification.trusted_issuer_registry_recognition
          .registry_to_recognition_rule_evaluated,
      trusted_issuer_registry_evaluation_result_type:
        sampleVerification.trusted_issuer_registry_recognition
          .registry_evaluation_result_type,
      trusted_issuer_registry_trusted_issuer_count:
        sampleVerification.trusted_issuer_registry_recognition.registry_trusted_issuer_count,
      trusted_issuer_registry_malformed_fixture_refused:
        sampleVerification.trusted_issuer_registry_recognition
          .malformed_registry_fail_closed_before_verdict,
      trusted_issuer_registry_live_state_proven:
        sampleVerification.trusted_issuer_registry_recognition.live_trust_registry_state,
      trusted_issuer_registry_live_issuer_status_proven:
        sampleVerification.trusted_issuer_registry_recognition.live_issuer_status_proven,
      trusted_issuer_registry_key_custody_proven:
        sampleVerification.trusted_issuer_registry_recognition.key_custody_proven,
      trusted_issuer_registry_revocation_truth_proven:
        sampleVerification.trusted_issuer_registry_recognition.revocation_truth_proven,
      trusted_issuer_registry_production_trust_registry_proven:
        sampleVerification.trusted_issuer_registry_recognition
          .production_trust_registry_proven,
      trusted_issuer_registry_production_downstream_recognition_proven:
        sampleVerification.trusted_issuer_registry_recognition
          .production_downstream_recognition_proven,
      trusted_issuer_registry_production_authority:
        sampleVerification.trusted_issuer_registry_recognition.production_authority,
      trusted_issuer_registry_public_external_attestation:
        sampleVerification.trusted_issuer_registry_recognition.public_external_attestation,
      trusted_issuer_registry_real_non_operator_review:
        sampleVerification.trusted_issuer_registry_recognition.real_non_operator_review,
      trusted_issuer_registry_sovereign_recognition:
        sampleVerification.trusted_issuer_registry_recognition.sovereign_recognition,
      trusted_issuer_registry_current_machine_governance_proven:
        sampleVerification.trusted_issuer_registry_recognition
          .current_machine_governance_proven,
      human_authorization_summary_verified: true,
      human_authorization_pending_boarded:
        sampleVerification.human_authorization.pending_boarded,
      human_authorization_authorized_boarded:
        sampleVerification.human_authorization.authorized_boarded,
      human_authorization_denied_boarded:
        sampleVerification.human_authorization.denied_boarded,
      service_profile_preflight_sample_artifact_verified: true,
      service_profile_preflight_summary_verified: true,
      service_profile_preflight_cases:
        sampleVerification.service_profile_preflight.case_count,
      activation_preflight_sample_artifact_verified: true,
      runtime_local_activation_sample_artifact_verified: true,
      runtime_local_activation_applied:
      runtimeLocalActivationSampleVerification.local_activation_applied,
      runtime_local_activation_missing_receipt_refused:
        runtimeLocalActivationSampleVerification.missing_receipt_refused,
      runtime_profile_installation_sample_artifact_verified: true,
      runtime_profile_installation_applied:
        runtimeProfileInstallationSampleVerification.disposable_profile_installation_applied,
      runtime_profile_installation_request_authority_guard_refused:
        runtimeProfileInstallationSampleVerification.request_authority_guard_refused,
      runtime_profile_installation_selects_latest:
        runtimeProfileInstallationSampleVerification.selects_latest_profile,
      runtime_profile_installation_persistent_profile_installed:
        runtimeProfileInstallationSampleVerification.persistent_runtime_profile_installed,
      runtime_profile_installation_hook_configuration_written:
        runtimeProfileInstallationSampleVerification.hook_configuration_written,
      installed_runtime_profile_preflight_sample_artifact_verified: true,
      installed_runtime_profile_preflight_read_only:
        installedRuntimeProfilePreflightSampleVerification.read_only,
      installed_runtime_profile_preflight_selected:
        installedRuntimeProfilePreflightSampleVerification.profile_selected_from_install_root,
      installed_runtime_profile_preflight_selects_latest:
        installedRuntimeProfilePreflightSampleVerification.selects_latest_profile,
      installed_runtime_profile_preflight_installation_performed:
        installedRuntimeProfilePreflightSampleVerification.runtime_profile_installation_performed,
      installed_runtime_profile_preflight_activation_performed:
        installedRuntimeProfilePreflightSampleVerification.runtime_profile_activation_performed,
      installed_runtime_profile_preflight_hook_configuration_written:
        installedRuntimeProfilePreflightSampleVerification.hook_configuration_written,
      installed_runtime_profile_preflight_recognition_contract_preserved:
        installedRuntimeProfilePreflightSampleVerification.recognition_contract_preserved,
      installed_runtime_profile_preflight_recognition_contract_sha256:
        installedRuntimeProfilePreflightSampleVerification.recognition_contract_sha256,
      installed_runtime_profile_preflight_downstream_refusal_proven:
        installedRuntimeProfilePreflightSampleVerification.downstream_refusal_proven,
      installed_runtime_profile_preflight_current_machine_governance_proven:
        installedRuntimeProfilePreflightSampleVerification.current_machine_governance_proven,
      installed_runtime_profile_recognition_proof_verified: true,
      installed_runtime_profile_recognition_recognized_write_boarded:
        installedRuntimeProfileRecognitionProof.recognized_boarding.boarded,
      installed_runtime_profile_recognition_refusal_case_count:
        installedRuntimeProfileRecognitionProof.refusal_cases.length,
      installed_runtime_profile_recognition_all_refusals_before_mutation:
        installedRuntimeProfileRecognitionProof.refusal_cases.every((item) =>
          item.boarded === false &&
          item.service_write_accepted === false &&
          item.state_entry_count_delta === 0
        ),
      installed_runtime_profile_recognition_source_preflight_downstream_refusal_proven:
        installedRuntimeProfileRecognitionProof.source_preflight.downstream_refusal_proven,
      installed_runtime_profile_recognition_install_performed:
        installedRuntimeProfileRecognitionProof.proof_boundary.install_performed,
      installed_runtime_profile_recognition_activation_performed:
        installedRuntimeProfileRecognitionProof.proof_boundary.activation_performed,
      installed_runtime_profile_recognition_runtime_service_started:
        installedRuntimeProfileRecognitionProof.proof_boundary.runtime_service_started,
      installed_runtime_profile_recognition_current_machine_governance_proven:
        installedRuntimeProfileRecognitionProof.proof_boundary.current_machine_governance_proven,
      installed_runtime_profile_recognition_production_downstream_recognition:
        installedRuntimeProfileRecognitionProof.proof_boundary.production_downstream_recognition,
      installed_runtime_profile_service_proof_verified: true,
      installed_runtime_profile_service_runtime_service_started:
        installedRuntimeProfileServiceProof.service_boundary.runtime_service_started,
      installed_runtime_profile_service_disposable_runtime_config_written:
        installedRuntimeProfileServiceProof.service_boundary.disposable_runtime_config_written,
      installed_runtime_profile_service_persistent_runtime_config_written:
        installedRuntimeProfileServiceProof.service_boundary.persistent_runtime_config_written,
      installed_runtime_profile_service_config_path_exposed_to_request_stream:
        installedRuntimeProfileServiceProof.service_config_provenance.config_path_exposed_to_request_stream,
      installed_runtime_profile_service_recognition_rule_bound_to_selected_profile:
        installedRuntimeProfileServiceProof.service_config_provenance.recognition_rule_bound_to_selected_profile,
      installed_runtime_profile_service_recognition_contract_sha256:
        installedRuntimeProfileServiceProof.recognition_contract.recognition_contract_sha256,
      installed_runtime_profile_service_consumed_store_witness_source:
        installedRuntimeProfileServiceProof.service_config_provenance.consumed_grant_store_witness_source,
      installed_runtime_profile_service_recognized_write_boarded:
        installedRuntimeProfileServiceProof.recognized_boarding.boarded,
      installed_runtime_profile_service_replay_case_count:
        installedRuntimeProfileServiceProof.service_replay_cases.length,
      installed_runtime_profile_service_same_process_replay_refused:
        installedRuntimeProfileServiceProof.proof_boundary.same_process_signed_payload_replay_refused,
      installed_runtime_profile_service_restart_replay_refused:
        installedRuntimeProfileServiceProof.proof_boundary.restart_consumed_authority_grant_refused,
      installed_runtime_profile_service_same_process_signed_payload_replay_refused:
        installedRuntimeProfileServiceProof.proof_boundary.same_process_signed_payload_replay_refused,
      installed_runtime_profile_service_restart_consumed_authority_grant_refused:
        installedRuntimeProfileServiceProof.proof_boundary.restart_consumed_authority_grant_refused,
      installed_runtime_profile_service_replay_identities_separate:
        installedRuntimeProfileServiceProof.service_boundary.signed_payload_replay_identity ===
          'verified-signed-payload-sha256' &&
        installedRuntimeProfileServiceProof.service_boundary.consumption_identity ===
          'authority-grant-contract-sha256',
      installed_runtime_profile_service_all_replay_refusals_before_mutation:
        installedRuntimeProfileServiceProof.service_replay_cases.every((item) =>
          item.boarded === false &&
          item.service_write_accepted === false &&
          item.state_entry_count_delta === 0
        ),
      installed_runtime_profile_service_consumed_store_integrity_case_count:
        installedRuntimeProfileServiceProof.partial_commit_cases.length,
      installed_runtime_profile_service_consumed_store_integrity_refusals_proven:
        installedRuntimeProfileServiceProof.partial_commit_cases.every((item) =>
          item.service_write_accepted === false
        ),
      installed_runtime_profile_service_all_consumed_store_integrity_refusals_before_mutation:
        installedRuntimeProfileServiceProof.partial_commit_cases.every((item) =>
          item.boarded === false &&
          item.service_write_accepted === false &&
          item.state_entry_count_delta === 0
        ),
      installed_runtime_profile_service_single_host_consumed_store_rollback_detection:
        installedRuntimeProfileServiceProof.proof_boundary.store_and_anchor_rollback_refused_while_witness_ahead,
      installed_runtime_profile_service_store_and_anchor_rollback_case_count:
        1,
      installed_runtime_profile_service_store_and_anchor_joint_rollback_refusals_proven:
        installedRuntimeProfileServiceProof.joint_rollback_case.store_and_anchor_only.service_write_accepted === false,
      installed_runtime_profile_service_all_store_and_anchor_rollback_refusals_before_mutation:
        installedRuntimeProfileServiceProof.joint_rollback_case.store_and_anchor_only.boarded === false &&
        installedRuntimeProfileServiceProof.joint_rollback_case.store_and_anchor_only.service_write_accepted === false &&
        installedRuntimeProfileServiceProof.joint_rollback_case.store_and_anchor_only.state_entry_count_delta === 0,
      installed_runtime_profile_service_store_and_anchor_joint_rollback_detection:
        installedRuntimeProfileServiceProof.proof_boundary.store_and_anchor_rollback_refused_while_witness_ahead,
      installed_runtime_profile_service_store_anchor_and_witness_joint_rollback_detection:
        installedRuntimeProfileServiceProof.proof_boundary.store_anchor_and_witness_joint_rollback_detection,
      installed_runtime_profile_service_recognition_refusal_case_count:
        installedRuntimeProfileServiceProof.refusal_cases.length,
      installed_runtime_profile_service_authority_refusal_case_count:
        installedRuntimeProfileServiceProof.authority_refusal_cases.length,
      installed_runtime_profile_service_all_authority_refusals_before_consumption_and_mutation:
        installedRuntimeProfileServiceProof.authority_refusal_cases.every((item) =>
          item.boarded === false &&
          item.service_write_accepted === false &&
          item.state_entry_count_delta === 0 &&
          item.consumed_authority_grant_count === 0
        ),
      installed_runtime_profile_service_state_append_after_grant_commit_burn_observed:
        installedRuntimeProfileServiceProof.proof_boundary.state_append_after_grant_commit_burn_observed,
      installed_runtime_profile_service_metadata_partial_commit_burn_observed:
        installedRuntimeProfileServiceProof.proof_boundary.metadata_partial_commit_burn_observed,
      installed_runtime_profile_service_store_and_anchor_rollback_refused_while_witness_ahead:
        installedRuntimeProfileServiceProof.proof_boundary.store_and_anchor_rollback_refused_while_witness_ahead,
      installed_runtime_profile_service_joint_rollback_reopened_authority_grant_reuse:
        installedRuntimeProfileServiceProof.proof_boundary.joint_rollback_reopened_authority_grant_reuse,
      installed_runtime_profile_service_fixture_rightful_issuance_path_evidenced:
        installedRuntimeProfileServiceProof.proof_boundary.fixture_rightful_issuance_path_evidenced,
      installed_runtime_profile_service_refusal_case_count:
        installedRuntimeProfileServiceProof.refusal_cases.length,
      installed_runtime_profile_service_all_refusals_before_mutation:
        installedRuntimeProfileServiceProof.refusal_cases.every((item) =>
          item.boarded === false &&
          item.service_write_accepted === false &&
          item.state_entry_count_delta === 0
        ),
      installed_runtime_profile_service_source_preflight_downstream_refusal_proven:
        installedRuntimeProfileServiceProof.source_preflight.downstream_refusal_proven,
      installed_runtime_profile_service_install_performed:
        installedRuntimeProfileServiceProof.proof_boundary.install_performed,
      installed_runtime_profile_service_activation_performed:
        installedRuntimeProfileServiceProof.proof_boundary.activation_performed,
      installed_runtime_profile_service_current_machine_governance_proven:
        installedRuntimeProfileServiceProof.proof_boundary.current_machine_governance_proven,
      installed_runtime_profile_service_production_downstream_recognition:
        installedRuntimeProfileServiceProof.proof_boundary.production_downstream_recognition,
      installed_runtime_profile_service_artifact_verification_verified:
        installedRuntimeProfileServiceProofArtifactVerification.verified,
      installed_runtime_profile_service_artifact_verification_body_sha256:
        installedRuntimeProfileServiceProofArtifactVerification.body_sha256,
      installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256:
        installedRuntimeProfileServiceProofArtifactVerification.recognition_refusal_taxonomy_sha256,
      installed_runtime_profile_service_artifact_verification_recognition_contract_sha256:
        installedRuntimeProfileServiceProofArtifactVerification.recognition_contract_sha256,
      installed_runtime_profile_service_artifact_verification_payload_type:
        installedRuntimeProfileServiceProofArtifactVerification.payload_type,
      installed_runtime_profile_service_artifact_verification_runtime_service_started:
        installedRuntimeProfileServiceProof.service_boundary.runtime_service_started,
      installed_runtime_profile_service_artifact_verification_recognized_write_boarded:
        installedRuntimeProfileServiceProofArtifactVerification.recognized_write_boarded,
      installed_runtime_profile_service_artifact_verification_restart_replay_refused:
        installedRuntimeProfileServiceProofArtifactVerification.restart_consumed_authority_grant_refused,
      installed_runtime_profile_service_artifact_verification_consumed_store_integrity_case_count:
        installedRuntimeProfileServiceProof.partial_commit_cases.length,
      installed_runtime_profile_service_artifact_verification_store_and_anchor_rollback_case_count:
        1,
      installed_runtime_profile_service_artifact_verification_store_and_anchor_joint_rollback_detection:
        installedRuntimeProfileServiceProofArtifactVerification.store_and_anchor_rollback_refused_while_witness_ahead,
      installed_runtime_profile_service_artifact_verification_store_anchor_and_witness_joint_rollback_detection:
        installedRuntimeProfileServiceProofArtifactVerification.store_anchor_and_witness_joint_rollback_detection,
      installed_runtime_profile_service_artifact_verification_all_refusals_before_mutation:
        installedRuntimeProfileServiceProofArtifactVerification.all_recognition_refusals_before_mutation &&
        installedRuntimeProfileServiceProofArtifactVerification.all_authority_refusals_before_consumption_and_mutation,
      installed_runtime_profile_service_artifact_verification_recognition_refusal_case_count:
        installedRuntimeProfileServiceProofArtifactVerification.recognition_refusal_case_count,
      installed_runtime_profile_service_artifact_verification_authority_refusal_case_count:
        installedRuntimeProfileServiceProofArtifactVerification.authority_refusal_case_count,
      installed_runtime_profile_service_artifact_verification_same_process_signed_payload_replay_refused:
        installedRuntimeProfileServiceProofArtifactVerification.same_process_signed_payload_replay_refused,
      installed_runtime_profile_service_artifact_verification_restart_consumed_authority_grant_refused:
        installedRuntimeProfileServiceProofArtifactVerification.restart_consumed_authority_grant_refused,
      installed_runtime_profile_service_artifact_verification_state_append_after_grant_commit_burn_observed:
        installedRuntimeProfileServiceProofArtifactVerification.state_append_after_grant_commit_burn_observed,
      installed_runtime_profile_service_artifact_verification_metadata_partial_commit_burn_observed:
        installedRuntimeProfileServiceProofArtifactVerification.metadata_partial_commit_burn_observed,
      installed_runtime_profile_service_artifact_verification_joint_rollback_reopened_authority_grant_reuse:
        installedRuntimeProfileServiceProofArtifactVerification.joint_rollback_reopened_authority_grant_reuse,
      installed_runtime_profile_service_artifact_verification_fixture_rightful_issuance_path_evidenced:
        installedRuntimeProfileServiceProofArtifactVerification.fixture_rightful_issuance_path_evidenced,
      installed_runtime_profile_service_artifact_verification_current_machine_governance_proven:
        installedRuntimeProfileServiceProofArtifactVerification.current_machine_governance_proven,
      installed_runtime_profile_service_artifact_verification_production_downstream_recognition:
        installedRuntimeProfileServiceProofArtifactVerification.production_downstream_recognition,
      installed_runtime_profile_terminal_chain_verified: true,
      installed_runtime_profile_terminal_chain_generated_installed_root_preflighted:
        installedRuntimeProfileTerminalChain.terminal_chain.generated_installed_root_preflighted,
      installed_runtime_profile_terminal_chain_generated_preflight_consumed:
        installedRuntimeProfileTerminalChain.terminal_chain.generated_preflight_artifact_consumed_by_service_proof,
      installed_runtime_profile_terminal_chain_generated_service_artifact_verified:
        installedRuntimeProfileTerminalChain.terminal_chain.generated_service_proof_artifact_verified,
      installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved:
        installedRuntimeProfileTerminalChain.terminal_chain.nested_artifact_binding.preflight_artifact_hash_bound === true &&
        installedRuntimeProfileTerminalChain.terminal_chain.nested_artifact_binding.service_artifact_hash_bound === true &&
        installedRuntimeProfileTerminalChain.terminal_chain.nested_artifact_binding.service_proof_source_preflight_hash_bound === true &&
        installedRuntimeProfileTerminalChain.terminal_chain.nested_artifact_binding.proves_current_machine_governance === false &&
        installedRuntimeProfileTerminalChain.terminal_chain.nested_artifact_binding.proves_production_downstream_recognition === false,
      installed_runtime_profile_terminal_chain_nested_preflight_artifact_type:
        installedRuntimeProfileTerminalChain.terminal_chain.nested_artifact_binding.generated_preflight_artifact_type,
      installed_runtime_profile_terminal_chain_nested_service_proof_artifact_type:
        installedRuntimeProfileTerminalChain.terminal_chain.nested_artifact_binding.generated_service_proof_artifact_type,
      installed_runtime_profile_terminal_chain_service_proof_bound_to_generated_preflight:
        installedRuntimeProfileTerminalChain.terminal_chain.service_proof_bound_to_generated_preflight,
      installed_runtime_profile_terminal_chain_service_artifact_verification_bound_to_service_proof:
        installedRuntimeProfileTerminalChain.terminal_chain.service_artifact_verification_bound_to_service_proof,
      installed_runtime_profile_terminal_chain_recognized_write_boarded:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_write_boarded,
      installed_runtime_profile_terminal_chain_missing_receipt_refused_before_mutation:
        installedRuntimeProfileTerminalChain.terminal_chain.missing_receipt_refused_before_mutation,
      installed_runtime_profile_terminal_chain_invalid_receipt_refused_before_mutation:
        installedRuntimeProfileTerminalChain.terminal_chain.invalid_receipt_refused_before_mutation,
      installed_runtime_profile_terminal_chain_required_refusal_case_count:
        installedRuntimeProfileTerminalChain.terminal_chain.required_recognition_refusal_case_count,
      installed_runtime_profile_terminal_chain_observed_refusal_case_count:
        installedRuntimeProfileTerminalChain.terminal_chain.observed_recognition_refusal_case_count,
      installed_runtime_profile_terminal_chain_all_required_refusals_before_mutation:
        installedRuntimeProfileTerminalChain.terminal_chain.all_required_recognition_refusals_before_mutation &&
        installedRuntimeProfileTerminalChain.terminal_chain.all_required_authority_refusals_before_consumption_and_mutation,
      installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256:
        installedRuntimeProfileTerminalChain.terminal_chain.recognition_refusal_taxonomy_sha256,
      installed_runtime_profile_terminal_chain_recognition_refusal_case_count:
        installedRuntimeProfileTerminalChain.terminal_chain.observed_recognition_refusal_case_count,
      installed_runtime_profile_terminal_chain_authority_refusal_case_count:
        installedRuntimeProfileTerminalChain.terminal_chain.observed_authority_refusal_case_count,
      installed_runtime_profile_terminal_chain_all_authority_refusals_before_consumption_and_mutation:
        installedRuntimeProfileTerminalChain.terminal_chain.all_required_authority_refusals_before_consumption_and_mutation,
      installed_runtime_profile_terminal_chain_same_process_signed_payload_replay_refused:
        installedRuntimeProfileTerminalChain.terminal_chain.same_process_signed_payload_replay_refused,
      installed_runtime_profile_terminal_chain_restart_consumed_authority_grant_refused:
        installedRuntimeProfileTerminalChain.terminal_chain.restart_consumed_authority_grant_refused,
      installed_runtime_profile_terminal_chain_replay_identities_separate:
        installedRuntimeProfileTerminalChain.generated_service_proof.same_process_signed_payload_replay_refused === true &&
        installedRuntimeProfileTerminalChain.generated_service_proof.restart_consumed_authority_grant_refused === true,
      installed_runtime_profile_terminal_chain_state_append_after_grant_commit_burn_observed:
        installedRuntimeProfileTerminalChain.terminal_chain.state_append_after_grant_commit_burn_observed,
      installed_runtime_profile_terminal_chain_metadata_partial_commit_burn_observed:
        installedRuntimeProfileTerminalChain.terminal_chain.metadata_partial_commit_burn_observed,
      installed_runtime_profile_terminal_chain_store_and_anchor_rollback_refused_while_witness_ahead:
        installedRuntimeProfileTerminalChain.terminal_chain.store_and_anchor_rollback_refused_while_witness_ahead,
      installed_runtime_profile_terminal_chain_store_anchor_and_witness_joint_rollback_detection:
        installedRuntimeProfileTerminalChain.terminal_chain.store_anchor_and_witness_joint_rollback_detection,
      installed_runtime_profile_terminal_chain_joint_rollback_reopened_authority_grant_reuse:
        installedRuntimeProfileTerminalChain.terminal_chain.joint_rollback_reopened_authority_grant_reuse,
      installed_runtime_profile_terminal_chain_fixture_rightful_issuance_path_evidenced:
        installedRuntimeProfileTerminalChain.terminal_chain.fixture_rightful_issuance_path_evidenced,
      installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256:
        installedRuntimeProfileTerminalChain.terminal_chain.named_receipt_refusals_sha256,
      installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256:
        installedRuntimeProfileTerminalChain.terminal_chain.recognition_refusal_groups_sha256,
      installed_runtime_profile_terminal_chain_recognition_refusal_group_count:
        Object.keys(installedRuntimeProfileTerminalChain.terminal_chain.recognition_refusal_groups).length,
      installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count:
        recognitionRefusalGroupCaseCount(
          installedRuntimeProfileTerminalChain.terminal_chain.recognition_refusal_groups
        ),
      installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids:
        recognitionRefusalGroupCaseIds(
          installedRuntimeProfileTerminalChain.terminal_chain.recognition_refusal_groups
        ),
      installed_runtime_profile_terminal_chain_recognition_contract_sha256:
        installedRuntimeProfileTerminalChain.terminal_chain.recognition_contract_sha256,
      installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved:
        deploymentProfileAuthorityRefusalMirrorPreserved(
          installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror
        ),
      installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_profile_sha_matches:
        installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror.source_runtime_profile_sha_matches_terminal_chain,
      installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count:
        installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_case_count,
      installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids:
        installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_case_ids,
      installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof:
        installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusals_before_service_proof,
      installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation:
        installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusals_before_mutation,
      installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started:
        installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_service_proof_started,
      installed_runtime_profile_terminal_chain_stale_deployment_profile_artifact_refused_before_service_proof:
        installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror.stale_deployment_profile_artifact_refused_before_service_proof,
      installed_runtime_profile_terminal_chain_profile_recognition_mismatch_refused_before_service_proof:
        installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror.profile_recognition_mismatch_refused_before_service_proof,
      installed_runtime_profile_terminal_chain_latest_profile_selection_refused_before_service_proof:
        installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror.latest_profile_selection_refused_before_service_proof,
      installed_runtime_profile_terminal_chain_request_stream_authority_material_refused_before_service_proof:
        installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror.request_stream_authority_material_refused_before_service_proof,
      installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance:
        installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror.current_machine_governance,
      installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition:
        installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror.production_downstream_recognition,
      installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority:
        installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror.production_authority,
      installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness:
        installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror.enterprise_readiness,
      installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation:
        installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror.external_attestation,
      installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition:
        installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror.sovereign_recognition,
      installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage:
        installedRuntimeProfileTerminalChain.terminal_chain.deployment_profile_authority_refusal_mirror.unrouted_surface_coverage,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.verdict ===
          'RECOGNIZED' &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.recognized ===
          true &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_fixture_validated ===
          true &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_to_recognition_rule_evaluated ===
          true &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.recognition_contract_hash_bound ===
          true &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.service_artifact_hash_bound ===
          true &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_contract_hash_bound ===
          true &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_public_key_material_included ===
          false &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.receipt_envelope_included ===
          false &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.cryptographic_evidence_reproducible_from_artifact ===
          false &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.live_trust_registry_state ===
          false &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.live_issuer_status_proven ===
          false &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.key_custody_proven ===
          false &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.revocation_truth_proven ===
          false &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.production_trust_registry_proven ===
          false &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.production_downstream_recognition_proven ===
          false &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.production_authority ===
          false &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.sovereign_recognition ===
          false &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.public_external_attestation ===
          false &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.real_non_operator_review ===
          false &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.current_machine_governance_proven ===
          false &&
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.binding_sha256 ===
          installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding_sha256,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding_sha256,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals.case_count,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals.all_refused,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids:
        trustedIssuerRegistryRecognitionRefusalCaseIds(
          installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding
        ),
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes:
        trustedIssuerRegistryRecognitionRefusalReasonCodes(
          installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding
        ),
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals_sha256,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_state_proven:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.live_trust_registry_state,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_issuer_status_proven:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.live_issuer_status_proven,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_key_custody_proven:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.key_custody_proven,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_revocation_truth_proven:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.revocation_truth_proven,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_trust_registry_proven:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.production_trust_registry_proven,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_downstream_recognition_proven:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.production_downstream_recognition_proven,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_authority:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.production_authority,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_sovereign_recognition:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.sovereign_recognition,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_external_attestation:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.public_external_attestation,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_real_non_operator_review:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.real_non_operator_review,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_current_machine_governance_proven:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.current_machine_governance_proven,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_key_material_included:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_public_key_material_included,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_envelope_included:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.receipt_envelope_included,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_artifact_crypto_reproducible:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.cryptographic_evidence_reproducible_from_artifact,
      installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_contract_hash_bound:
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_contract_hash_bound,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_preserved:
        recognizedReceiptPathEvidencePreserved(
          installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence,
          installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding,
          installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding_sha256
        ),
      installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence_sha256,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence.source_binding_sha256,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_matches_trusted_registry_binding:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence.source_binding_sha256 ===
        installedRuntimeProfileTerminalChain.terminal_chain.trusted_issuer_registry_recognition_binding_sha256,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_selected_profile_hash_bound:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence.selected_profile_hash_bound,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_recognition_contract_hash_bound:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence.recognition_contract_hash_bound,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_service_artifact_hash_bound:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence.service_artifact_hash_bound,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_terminal_chain_decision_bound:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence.terminal_chain_decision_bound,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_recognized_write_boarded:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence.recognized_write_boarded,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_public_key_material_included:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence.registry_public_key_material_included,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_receipt_envelope_included:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence.receipt_envelope_included,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_artifact_crypto_reproducible:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence.cryptographic_evidence_reproducible_from_artifact,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_live_registry_state:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence.live_trust_registry_state,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_key_custody_proven:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence.key_custody_proven,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_revocation_truth_proven:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence.revocation_truth_proven,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_production_downstream_recognition_proven:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence.production_downstream_recognition_proven,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_public_external_attestation:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence.public_external_attestation,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_sovereign_recognition:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence.sovereign_recognition,
      installed_runtime_profile_terminal_chain_recognized_receipt_path_current_machine_governance_proven:
        installedRuntimeProfileTerminalChain.terminal_chain.recognized_receipt_path_evidence.current_machine_governance_proven,
      installed_runtime_profile_terminal_chain_persistent_runtime_profile_installed:
        installedRuntimeProfileTerminalChain.side_door_report.persistent_runtime_profile_installed,
      installed_runtime_profile_terminal_chain_activation_performed:
        installedRuntimeProfileTerminalChain.side_door_report.runtime_profile_activation_performed,
      installed_runtime_profile_terminal_chain_hook_configuration_written:
        installedRuntimeProfileTerminalChain.side_door_report.hook_configuration_written,
      installed_runtime_profile_terminal_chain_current_machine_governance_proven:
        installedRuntimeProfileTerminalChain.side_door_report.current_machine_governance_proven,
      installed_runtime_profile_terminal_chain_production_downstream_recognition:
        installedRuntimeProfileTerminalChain.generated_service_proof.production_downstream_recognition,
      installed_runtime_profile_terminal_chain_artifact_verification_verified:
        installedRuntimeProfileTerminalChainArtifactVerification.verified,
      installed_runtime_profile_terminal_chain_artifact_verification_body_sha256:
        installedRuntimeProfileTerminalChainArtifactVerification.body_sha256,
      installed_runtime_profile_terminal_chain_artifact_verification_structural_self_integrity_verified:
        installedRuntimeProfileTerminalChainArtifactVerification.verified,
      installed_runtime_profile_terminal_chain_artifact_verification_identity_match_requires_expected_sha256:
        installedRuntimeProfileTerminalChainArtifactVerification.artifact_identity_match_requires_expected_sha256,
      installed_runtime_profile_terminal_chain_artifact_verification_expected_body_sha256:
        installedRuntimeProfileTerminalChainArtifactVerification.required_body_sha256,
      installed_runtime_profile_terminal_chain_artifact_verification_expected_body_sha256_matched:
        installedRuntimeProfileTerminalChainArtifactVerification.required_body_sha256_matched,
      installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_structural_self_integrity_verified:
        installedRuntimeProfileTerminalChainArtifactVerification.embedded_service_artifact_structural_self_integrity_verified,
      installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_identity_match_requires_expected_sha256:
        installedRuntimeProfileTerminalChainArtifactVerification.embedded_service_artifact_identity_match_requires_expected_sha256,
      installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_expected_body_sha256:
        installedRuntimeProfileTerminalChainArtifactVerification.embedded_service_artifact_expected_body_sha256,
      installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_expected_body_sha256_matched:
        installedRuntimeProfileTerminalChainArtifactVerification.embedded_service_artifact_expected_body_sha256_matched,
      installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved:
        installedRuntimeProfileTerminalChainArtifactVerification.nested_artifact_binding.preflight_artifact_hash_bound === true &&
        installedRuntimeProfileTerminalChainArtifactVerification.nested_artifact_binding.service_artifact_hash_bound === true &&
        installedRuntimeProfileTerminalChainArtifactVerification.nested_artifact_binding.service_proof_source_preflight_hash_bound === true &&
        installedRuntimeProfileTerminalChainArtifactVerification.nested_artifact_binding.proves_current_machine_governance === false &&
        installedRuntimeProfileTerminalChainArtifactVerification.nested_artifact_binding.proves_production_downstream_recognition === false,
      installed_runtime_profile_terminal_chain_artifact_verification_nested_preflight_artifact_type:
        installedRuntimeProfileTerminalChainArtifactVerification.nested_artifact_binding.generated_preflight_artifact_type,
      installed_runtime_profile_terminal_chain_artifact_verification_nested_service_proof_artifact_type:
        installedRuntimeProfileTerminalChainArtifactVerification.nested_artifact_binding.generated_service_proof_artifact_type,
      installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256:
        installedRuntimeProfileTerminalChainArtifactVerification.recognition_refusal_taxonomy_sha256,
      installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_case_count:
        installedRuntimeProfileTerminalChainArtifactVerification.observed_recognition_refusal_case_count,
      installed_runtime_profile_terminal_chain_artifact_verification_authority_refusal_case_count:
        installedRuntimeProfileTerminalChainArtifactVerification.observed_authority_refusal_case_count,
      installed_runtime_profile_terminal_chain_artifact_verification_all_authority_refusals_before_consumption_and_mutation:
        installedRuntimeProfileTerminalChainArtifactVerification.all_required_authority_refusals_before_consumption_and_mutation,
      installed_runtime_profile_terminal_chain_artifact_verification_same_process_signed_payload_replay_refused:
        installedRuntimeProfileTerminalChainArtifactVerification.same_process_signed_payload_replay_refused,
      installed_runtime_profile_terminal_chain_artifact_verification_restart_consumed_authority_grant_refused:
        installedRuntimeProfileTerminalChainArtifactVerification.restart_consumed_authority_grant_refused,
      installed_runtime_profile_terminal_chain_artifact_verification_state_append_after_grant_commit_burn_observed:
        installedRuntimeProfileTerminalChainArtifactVerification.state_append_after_grant_commit_burn_observed,
      installed_runtime_profile_terminal_chain_artifact_verification_metadata_partial_commit_burn_observed:
        installedRuntimeProfileTerminalChainArtifactVerification.metadata_partial_commit_burn_observed,
      installed_runtime_profile_terminal_chain_artifact_verification_store_and_anchor_rollback_refused_while_witness_ahead:
        installedRuntimeProfileTerminalChainArtifactVerification.store_and_anchor_rollback_refused_while_witness_ahead,
      installed_runtime_profile_terminal_chain_artifact_verification_store_anchor_and_witness_joint_rollback_detection:
        installedRuntimeProfileTerminalChainArtifactVerification.store_anchor_and_witness_joint_rollback_detection,
      installed_runtime_profile_terminal_chain_artifact_verification_joint_rollback_reopened_authority_grant_reuse:
        installedRuntimeProfileTerminalChainArtifactVerification.joint_rollback_reopened_authority_grant_reuse,
      installed_runtime_profile_terminal_chain_artifact_verification_host_filesystem_path_toctou_closed:
        installedRuntimeProfileTerminalChainArtifactVerification.host_filesystem_path_toctou_closed,
      installed_runtime_profile_terminal_chain_artifact_verification_fixture_rightful_issuance_path_evidenced:
        installedRuntimeProfileTerminalChainArtifactVerification.fixture_rightful_issuance_path_evidenced,
      installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256:
        installedRuntimeProfileTerminalChainArtifactVerification.named_receipt_refusals_sha256,
      installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256:
        installedRuntimeProfileTerminalChainArtifactVerification.recognition_refusal_groups_sha256,
      installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count:
        Object.keys(installedRuntimeProfileTerminalChainArtifactVerification.recognition_refusal_groups).length,
      installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count:
        recognitionRefusalGroupCaseCount(
          installedRuntimeProfileTerminalChainArtifactVerification.recognition_refusal_groups
        ),
      installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids:
        recognitionRefusalGroupCaseIds(
          installedRuntimeProfileTerminalChainArtifactVerification.recognition_refusal_groups
        ),
      installed_runtime_profile_terminal_chain_artifact_verification_recognition_contract_sha256:
        installedRuntimeProfileTerminalChainArtifactVerification.recognition_contract_sha256,
      installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_preserved:
        deploymentProfileAuthorityRefusalMirrorPreserved(
          installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror
        ),
      installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_profile_sha_matches:
        installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror.source_runtime_profile_sha_matches_terminal_chain,
      installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count:
        installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_case_count,
      installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids:
        installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_case_ids,
      installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof:
        installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusals_before_service_proof,
      installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation:
        installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusals_before_mutation,
      installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started:
        installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_service_proof_started,
      installed_runtime_profile_terminal_chain_artifact_verification_stale_deployment_profile_artifact_refused_before_service_proof:
        installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror.stale_deployment_profile_artifact_refused_before_service_proof,
      installed_runtime_profile_terminal_chain_artifact_verification_profile_recognition_mismatch_refused_before_service_proof:
        installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror.profile_recognition_mismatch_refused_before_service_proof,
      installed_runtime_profile_terminal_chain_artifact_verification_latest_profile_selection_refused_before_service_proof:
        installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror.latest_profile_selection_refused_before_service_proof,
      installed_runtime_profile_terminal_chain_artifact_verification_request_stream_authority_material_refused_before_service_proof:
        installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror.request_stream_authority_material_refused_before_service_proof,
      installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_current_machine_governance:
        installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror.current_machine_governance,
      installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_downstream_recognition:
        installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror.production_downstream_recognition,
      installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_authority:
        installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror.production_authority,
      installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_enterprise_readiness:
        installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror.enterprise_readiness,
      installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_external_attestation:
        installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror.external_attestation,
      installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_sovereign_recognition:
        installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror.sovereign_recognition,
      installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_unrouted_surface_coverage:
        installedRuntimeProfileTerminalChainArtifactVerification.deployment_profile_authority_refusal_mirror.unrouted_surface_coverage,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_preserved:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.verdict ===
          'RECOGNIZED' &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.recognized ===
          true &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.registry_fixture_validated ===
          true &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.registry_to_recognition_rule_evaluated ===
          true &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.recognition_contract_hash_bound ===
          true &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.service_artifact_hash_bound ===
          true &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.registry_receipt_contract_hash_bound ===
          true &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.registry_public_key_material_included ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.receipt_envelope_included ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.cryptographic_evidence_reproducible_from_artifact ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.live_trust_registry_state ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.live_issuer_status_proven ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.key_custody_proven ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.revocation_truth_proven ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.production_trust_registry_proven ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.production_downstream_recognition_proven ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.production_authority ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.sovereign_recognition ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.public_external_attestation ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.real_non_operator_review ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.current_machine_governance_proven ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.binding_sha256 ===
          installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding_sha256,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding_sha256,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals.case_count,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals.all_refused,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids:
        trustedIssuerRegistryRecognitionRefusalCaseIds(
          installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding
        ),
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes:
        trustedIssuerRegistryRecognitionRefusalReasonCodes(
          installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding
        ),
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals_sha256,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_state_proven:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.live_trust_registry_state,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_issuer_status_proven:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.live_issuer_status_proven,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_key_custody_proven:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.key_custody_proven,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_revocation_truth_proven:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.revocation_truth_proven,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_trust_registry_proven:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.production_trust_registry_proven,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_downstream_recognition_proven:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.production_downstream_recognition_proven,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_authority:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.production_authority,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_sovereign_recognition:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.sovereign_recognition,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_external_attestation:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.public_external_attestation,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_real_non_operator_review:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.real_non_operator_review,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_current_machine_governance_proven:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.current_machine_governance_proven,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_key_material_included:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.registry_public_key_material_included,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_envelope_included:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.receipt_envelope_included,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_artifact_crypto_reproducible:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.cryptographic_evidence_reproducible_from_artifact,
      installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_contract_hash_bound:
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding.registry_receipt_contract_hash_bound,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_preserved:
        recognizedReceiptPathEvidencePreserved(
          installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence,
          installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding,
          installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding_sha256
        ),
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_sha256:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence_sha256,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_bound_to_artifact_body:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence_bound_to_artifact_body,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_sha256:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence.source_binding_sha256,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_matches_terminal_chain:
        terminalChainArtifactVerificationMatchesChainBoundary(
          installedRuntimeProfileTerminalChainArtifactVerification,
          installedRuntimeProfileTerminalChain
        ),
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_matches_trusted_registry_binding:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence.source_binding_sha256 ===
        installedRuntimeProfileTerminalChainArtifactVerification.trusted_issuer_registry_recognition_binding_sha256,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_selected_profile_hash_bound:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence.selected_profile_hash_bound,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_recognition_contract_hash_bound:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence.recognition_contract_hash_bound,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_service_artifact_hash_bound:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence.service_artifact_hash_bound,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_terminal_chain_decision_bound:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence.terminal_chain_decision_bound,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_recognized_write_boarded:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence.recognized_write_boarded,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_public_key_material_included:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence.registry_public_key_material_included,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_receipt_envelope_included:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence.receipt_envelope_included,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_artifact_crypto_reproducible:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence.cryptographic_evidence_reproducible_from_artifact,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_live_registry_state:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence.live_trust_registry_state,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_key_custody_proven:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence.key_custody_proven,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_revocation_truth_proven:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence.revocation_truth_proven,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_production_downstream_recognition_proven:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence.production_downstream_recognition_proven,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_public_external_attestation:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence.public_external_attestation,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_sovereign_recognition:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence.sovereign_recognition,
      installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_current_machine_governance_proven:
        installedRuntimeProfileTerminalChainArtifactVerification.recognized_receipt_path_evidence.current_machine_governance_proven,
      installed_runtime_profile_terminal_chain_artifact_verification_all_required_refusals_before_mutation:
        installedRuntimeProfileTerminalChainArtifactVerification.all_required_recognition_refusals_before_mutation &&
        installedRuntimeProfileTerminalChainArtifactVerification.all_required_authority_refusals_before_consumption_and_mutation,
      installed_runtime_profile_terminal_chain_artifact_verification_current_machine_governance_proven:
        installedRuntimeProfileTerminalChainArtifactVerification.current_machine_governance_proven,
      installed_runtime_profile_terminal_chain_artifact_verification_production_downstream_recognition:
        installedRuntimeProfileTerminalChainArtifactVerification.production_downstream_recognition,
      consequence_lifecycle_map_evidenced_obligation_count:
        consequenceLifecycleMap.lifecycle_obligations.filter((item) => item.status === 'evidenced').length,
      consequence_lifecycle_map_not_evidenced_obligation_count:
        consequenceLifecycleMap.lifecycle_obligations.filter((item) => item.status === 'not_evidenced').length,
      consequence_lifecycle_map_outside_coverage_obligation_count:
        consequenceLifecycleMap.lifecycle_obligations.filter((item) => item.status === 'outside_coverage').length,
      consequence_lifecycle_map_evidence_reference_count:
        consequenceLifecycleMap.evidence_ref_resolution.total_reference_count,
      consequence_lifecycle_map_all_evidence_references_resolved:
        consequenceLifecycleMap.evidence_ref_resolution.all_references_resolved,
      local_fixture_rightful_issuance_path_evidenced:
        consequenceLifecycleMap.claim_boundary.local_fixture_rightful_issuance_path,
      generic_rightful_issuance_proven:
        consequenceLifecycleMap.claim_boundary.generic_rightful_issuance,
      portable_rightful_issuance_proven:
        consequenceLifecycleMap.claim_boundary.portable_rightful_issuance,
      live_rightful_issuance_proven:
        consequenceLifecycleMap.claim_boundary.live_rightful_issuance,
      production_rightful_issuance_proven:
        consequenceLifecycleMap.claim_boundary.production_rightful_issuance,
      current_machine_rightful_issuance_proven:
        consequenceLifecycleMap.claim_boundary.current_machine_rightful_issuance,
      consequence_lifecycle_closed:
        consequenceLifecycleMap.closure.lifecycle_closed,
      configured_recognition_replay_store_proof_verified: true,
      configured_recognition_replay_store_case_count:
        configuredRecognitionReplayStoreProof.case_count,
      configured_recognition_replay_store_first_call_persisted:
        configuredRecognitionReplayStoreProof.summary.first_call_persisted,
      configured_recognition_replay_store_first_call_effect_written:
        configuredRecognitionReplayStoreProof.summary.first_call_effect_written,
      configured_recognition_replay_store_replay_refused_before_callback:
        configuredRecognitionReplayStoreProof.summary.replay_refused_before_callback,
      configured_recognition_replay_store_invalid_store_failed_closed_before_callback:
        configuredRecognitionReplayStoreProof.summary.invalid_store_failed_closed_before_callback,
      configured_recognition_replay_store_no_secret_material:
        configuredRecognitionReplayStoreProof.no_secret_material,
      configured_recognition_replay_store_real_downstream:
        configuredRecognitionReplayStoreProof.real_downstream,
      configured_recognition_replay_store_real_receipt:
        configuredRecognitionReplayStoreProof.real_receipt,
      configured_recognition_replay_store_production_trust:
        configuredRecognitionReplayStoreProof.production_trust,
      configured_recognition_replay_store_path_redacted:
        configuredRecognitionReplayStoreProof.store_path_redacted,
      source_bridge_window_authority_verified: true,
      source_bridge_window_authority_safe_for_control_tower_use:
        sourceBridgeWindowAuthority.safe_for_control_tower_use,
      source_bridge_window_authority_can_push_under_window:
        sourceBridgeWindowAuthority.can_push_under_window,
      source_bridge_window_authority_forbidden_consequences_present:
        sourceBridgeWindowAuthority.required_forbidden_consequences_present,
      source_bridge_window_authority_stop_conditions_present:
        sourceBridgeWindowAuthority.required_stop_conditions_present,
      source_bridge_window_authority_reads_private_key_material:
        sourceBridgeWindowAuthority.no_secret_boundary.reads_private_key_material,
      source_bridge_window_authority_reads_token_material:
        sourceBridgeWindowAuthority.no_secret_boundary.reads_token_material,
      source_bridge_window_authority_mints_credentials:
        sourceBridgeWindowAuthority.no_secret_boundary.mints_credentials,
      source_bridge_window_authority_calls_github:
        sourceBridgeWindowAuthority.no_secret_boundary.calls_github,
      source_bridge_window_authority_reads_remote_refs:
        sourceBridgeWindowAuthority.no_secret_boundary.reads_remote_refs,
      source_bridge_window_authority_pushes_source:
        sourceBridgeWindowAuthority.no_secret_boundary.pushes_source,
      source_bridge_window_authority_changes_configuration:
        sourceBridgeWindowAuthority.no_secret_boundary.changes_configuration,
      active_profile_selection_verified: true,
      active_profile_selected:
        sampleVerification.runtime_local_activation.active_profile_selection.selected,
      active_profile_selects_latest:
        sampleVerification.runtime_local_activation.active_profile_selection.selects_latest_profile,
      active_profile_live_runtime_profile_checked:
        sampleVerification.runtime_local_activation.active_profile_selection.live_runtime_profile_checked,
      active_profile_persistent_runtime_profile_installed:
        sampleVerification.runtime_local_activation.active_profile_selection.persistent_runtime_profile_installed,
      governed_lanes: coverageMap.counts.governed_lanes,
      counted_lanes: coverageMap.counts.counted_lanes,
      boundary_entries: coverageMap.counts.boundary_entries,
    },
    non_claims: [...PROOF_SMOKE_NON_CLAIMS],
  };
  assertProofSmokeReport(report);
  return report;
}

export function assertProofSmokeReport(report) {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
    'Proof smoke fixture-rightful report acceptance',
  );
  throw new Error(
    'Proof smoke v1 fixture-rightful schema is retired; a replacement grant requires a new artifact-bound historical/current schema',
  );
  assertExactObjectKeys('Proof smoke report', report, [
    'report_type',
    'result',
    'evidence_model',
    'live_probing',
    'claim_boundary',
    'steps',
    'counts',
    'non_claims',
  ]);
  if (report.report_type !== PROOF_SMOKE_REPORT_TYPE) {
    throw new Error(`report_type must be ${PROOF_SMOKE_REPORT_TYPE}`);
  }
  if (report.result !== 'passed') {
    throw new Error('Proof smoke report result must be passed');
  }
  if (report.evidence_model !== PROOF_SMOKE_EVIDENCE_MODEL) {
    throw new Error('Proof smoke report evidence model drifted');
  }
  if (report.live_probing !== false) {
    throw new Error('Proof smoke report must not perform live probing');
  }
  if (report.claim_boundary !== PROOF_SMOKE_CLAIM_BOUNDARY) {
    throw new Error('Proof smoke report claim boundary drifted');
  }
  if (!Array.isArray(report.steps) || report.steps.length !== 15) {
    throw new Error('Proof smoke report must contain exactly fifteen steps');
  }

  const sampleStep = report.steps[0];
  assertStep(sampleStep, {
    step: 'sample_artifact_verification',
    command: `zlar local-proof-pack verify --sample --require-sha ${localProofPackSampleArtifactBodySha256()} --json`,
    payloadKey: 'verification',
  });
  assertSampleVerification(sampleStep.verification);

  const serviceProfilePreflightStep = report.steps[1];
  assertStep(serviceProfilePreflightStep, {
    step: 'service_profile_preflight_sample_artifact_verification',
    command: `zlar protected-records-service-preflight verify --sample --require-sha ${serviceProfilePreflightSampleArtifactBodySha256()} --json`,
    payloadKey: 'verification',
  });
  assertServiceProfilePreflightSampleVerification(serviceProfilePreflightStep.verification);

  const activationStep = report.steps[2];
  assertStep(activationStep, {
    step: 'activation_preflight_sample_artifact_verification',
    command: `zlar protected-records-runtime-activation-preflight verify --sample --require-sha ${activationPreflightSampleArtifactBodySha256()} --json`,
    payloadKey: 'verification',
  });
  assertActivationPreflightSampleVerification(activationStep.verification);

  const runtimeLocalActivationStep = report.steps[3];
  assertStep(runtimeLocalActivationStep, {
    step: 'runtime_local_activation_sample_artifact_verification',
    command: `zlar protected-records-runtime-local-activation verify --sample --require-sha ${runtimeLocalActivationSampleArtifactBodySha256()} --json`,
    payloadKey: 'verification',
  });
  assertRuntimeLocalActivationSampleVerification(runtimeLocalActivationStep.verification);

  const runtimeProfileInstallationStep = report.steps[4];
  assertStep(runtimeProfileInstallationStep, {
    step: 'runtime_profile_installation_sample_artifact_verification',
    command: `zlar protected-records-runtime-profile-installation verify --sample --require-sha ${runtimeProfileInstallationSampleArtifactBodySha256()} --json`,
    payloadKey: 'verification',
  });
  assertRuntimeProfileInstallationSampleVerification(runtimeProfileInstallationStep.verification);

  const installedRuntimeProfilePreflightStep = report.steps[5];
  assertStep(installedRuntimeProfilePreflightStep, {
    step: 'installed_runtime_profile_preflight_sample_artifact_verification',
    command: `zlar protected-records-installed-runtime-profile-preflight verify --sample --require-sha ${installedRuntimeProfilePreflightSampleArtifactBodySha256()} --json`,
    payloadKey: 'verification',
  });
  assertInstalledRuntimeProfilePreflightSampleVerification(installedRuntimeProfilePreflightStep.verification);

  const installedRuntimeProfileRecognitionStep = report.steps[6];
  assertStep(installedRuntimeProfileRecognitionStep, {
    step: 'installed_runtime_profile_recognition_proof',
    command: 'zlar protected-records-installed-runtime-profile-recognition-proof --sample --json',
    payloadKey: 'proof',
  });
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(installedRuntimeProfileRecognitionStep.proof);

  const installedRuntimeProfileServiceStep = report.steps[7];
  assertStep(installedRuntimeProfileServiceStep, {
    step: 'installed_runtime_profile_service_proof',
    command: 'zlar protected-records-installed-runtime-profile-service-proof --sample --json',
    payloadKey: 'proof',
  });
  assertProtectedRecordsInstalledRuntimeProfileServiceProof(installedRuntimeProfileServiceStep.proof);

  const installedRuntimeProfileServiceArtifactVerificationStep = report.steps[8];
  assertStep(installedRuntimeProfileServiceArtifactVerificationStep, {
    step: 'installed_runtime_profile_service_proof_artifact_verification',
    command: `zlar protected-records-installed-runtime-profile-service-proof verify --sample --require-sha ${installedRuntimeProfileServiceProofSampleArtifactBodySha256()} --json`,
    payloadKey: 'verification',
  });
  assertRequiredBodySha256Posture(
    installedRuntimeProfileServiceArtifactVerificationStep.verification,
    installedRuntimeProfileServiceProofSampleArtifactBodySha256(),
    'installed runtime profile service proof artifact verification'
  );
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification(
    verificationWithoutRequiredBodySha256(
      installedRuntimeProfileServiceArtifactVerificationStep.verification
    )
  );
  const installedRuntimeProfileTerminalChainStep = report.steps[9];
  assertStep(installedRuntimeProfileTerminalChainStep, {
    step: 'installed_runtime_profile_terminal_chain',
    command: 'zlar protected-records-installed-runtime-profile-terminal-chain --sample --json',
    payloadKey: 'chain',
  });
  assertProtectedRecordsInstalledRuntimeProfileTerminalChain(
    installedRuntimeProfileTerminalChainStep.chain
  );

  const installedRuntimeProfileTerminalChainArtifactVerificationStep = report.steps[10];
  assertStep(installedRuntimeProfileTerminalChainArtifactVerificationStep, {
    step: 'installed_runtime_profile_terminal_chain_artifact_verification',
    command: `zlar protected-records-installed-runtime-profile-terminal-chain verify --sample --require-sha ${installedRuntimeProfileTerminalChainSampleArtifactBodySha256()} --json`,
    payloadKey: 'verification',
  });
  assertRequiredBodySha256Posture(
    installedRuntimeProfileTerminalChainArtifactVerificationStep.verification,
    installedRuntimeProfileTerminalChainSampleArtifactBodySha256(),
    'installed runtime profile terminal chain artifact verification'
  );
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification(
    verificationWithoutRequiredBodySha256(
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification
    )
  );
  assertTerminalChainArtifactVerificationMatchesChainBoundary(
    installedRuntimeProfileTerminalChainArtifactVerificationStep.verification,
    installedRuntimeProfileTerminalChainStep.chain,
    'installed runtime profile terminal chain artifact verification'
  );

  const configuredRecognitionReplayStoreStep = report.steps[11];
  assertStep(configuredRecognitionReplayStoreStep, {
    step: 'configured_recognition_consumer_replay_store_proof',
    command: 'zlar configured-recognition-consumer-replay-store-proof --json',
    payloadKey: 'proof',
  });
  assertConfiguredRecognitionConsumerReplayStoreProof(configuredRecognitionReplayStoreStep.proof);

  const sourceBridgeWindowAuthorityStep = report.steps[12];
  assertStep(sourceBridgeWindowAuthorityStep, {
    step: 'source_bridge_window_authority_sample',
    command: 'zlar source-bridge-window --sample --json',
    payloadKey: 'authority',
  });
  assertSourceBridgeWindowAuthorityReport(sourceBridgeWindowAuthorityStep.authority);

  const coverageStep = report.steps[13];
  assertStep(coverageStep, {
    step: 'fixture_input_coverage_map',
    command: 'zlar coverage --sample --require-governed --json',
    payloadKey: 'coverage_map',
  });
  assertGovernedSurfaceCoverageMap(coverageStep.coverage_map);

  const consequenceLifecycleMapStep = report.steps[14];
  assertStep(consequenceLifecycleMapStep, {
    step: 'consequence_lifecycle_map_projection',
    command: 'zlar consequence-lifecycle --sample --json',
    payloadKey: 'lifecycle_map',
  });
  const consequenceLifecycleMapSourceArtifact = consequenceLifecycleMapSampleArtifact();
  assertConsequenceLifecycleMap(
    consequenceLifecycleMapStep.lifecycle_map,
    consequenceLifecycleMapSourceArtifact
  );

  assertExactObjectKeys('Proof smoke report counts', report.counts, [
    'activation_preflight_artifact_body_sha256',
    'consequence_lifecycle_closed',
    'consequence_lifecycle_map_all_evidence_references_resolved',
    'consequence_lifecycle_map_evidence_reference_count',
    'consequence_lifecycle_map_evidenced_obligation_count',
    'consequence_lifecycle_map_not_evidenced_obligation_count',
    'consequence_lifecycle_map_outside_coverage_obligation_count',
    'consequence_lifecycle_map_projection_sha256',
    'coverage_map_sha256',
    'current_machine_rightful_issuance_proven',
    'generic_rightful_issuance_proven',
    'installed_runtime_profile_preflight_artifact_body_sha256',
    'installed_runtime_profile_recognition_proof_sha256',
    'installed_runtime_profile_service_all_authority_refusals_before_consumption_and_mutation',
    'installed_runtime_profile_service_artifact_verification_authority_refusal_case_count',
    'installed_runtime_profile_service_artifact_verification_fixture_rightful_issuance_path_evidenced',
    'installed_runtime_profile_service_artifact_verification_joint_rollback_reopened_authority_grant_reuse',
    'installed_runtime_profile_service_artifact_verification_metadata_partial_commit_burn_observed',
    'installed_runtime_profile_service_artifact_verification_recognition_refusal_case_count',
    'installed_runtime_profile_service_artifact_verification_restart_consumed_authority_grant_refused',
    'installed_runtime_profile_service_artifact_verification_same_process_signed_payload_replay_refused',
    'installed_runtime_profile_service_artifact_verification_state_append_after_grant_commit_burn_observed',
    'installed_runtime_profile_service_authority_refusal_case_count',
    'installed_runtime_profile_service_fixture_rightful_issuance_path_evidenced',
    'installed_runtime_profile_service_joint_rollback_reopened_authority_grant_reuse',
    'installed_runtime_profile_service_metadata_partial_commit_burn_observed',
    'installed_runtime_profile_service_proof_artifact_body_sha256',
    'installed_runtime_profile_service_recognition_refusal_case_count',
    'installed_runtime_profile_service_replay_identities_separate',
    'installed_runtime_profile_service_restart_consumed_authority_grant_refused',
    'installed_runtime_profile_service_same_process_signed_payload_replay_refused',
    'installed_runtime_profile_service_state_append_after_grant_commit_burn_observed',
    'installed_runtime_profile_service_store_and_anchor_rollback_refused_while_witness_ahead',
    'installed_runtime_profile_terminal_chain_all_authority_refusals_before_consumption_and_mutation',
    'installed_runtime_profile_terminal_chain_artifact_body_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_all_authority_refusals_before_consumption_and_mutation',
    'installed_runtime_profile_terminal_chain_artifact_verification_authority_refusal_case_count',
    'installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_expected_body_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_expected_body_sha256_matched',
    'installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_identity_match_requires_expected_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_structural_self_integrity_verified',
    'installed_runtime_profile_terminal_chain_artifact_verification_expected_body_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_expected_body_sha256_matched',
    'installed_runtime_profile_terminal_chain_artifact_verification_fixture_rightful_issuance_path_evidenced',
    'installed_runtime_profile_terminal_chain_artifact_verification_host_filesystem_path_toctou_closed',
    'installed_runtime_profile_terminal_chain_artifact_verification_identity_match_requires_expected_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_joint_rollback_reopened_authority_grant_reuse',
    'installed_runtime_profile_terminal_chain_artifact_verification_metadata_partial_commit_burn_observed',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_case_count',
    'installed_runtime_profile_terminal_chain_artifact_verification_restart_consumed_authority_grant_refused',
    'installed_runtime_profile_terminal_chain_artifact_verification_same_process_signed_payload_replay_refused',
    'installed_runtime_profile_terminal_chain_artifact_verification_state_append_after_grant_commit_burn_observed',
    'installed_runtime_profile_terminal_chain_artifact_verification_store_anchor_and_witness_joint_rollback_detection',
    'installed_runtime_profile_terminal_chain_artifact_verification_store_and_anchor_rollback_refused_while_witness_ahead',
    'installed_runtime_profile_terminal_chain_artifact_verification_structural_self_integrity_verified',
    'installed_runtime_profile_terminal_chain_authority_refusal_case_count',
    'installed_runtime_profile_terminal_chain_fixture_rightful_issuance_path_evidenced',
    'installed_runtime_profile_terminal_chain_joint_rollback_reopened_authority_grant_reuse',
    'installed_runtime_profile_terminal_chain_metadata_partial_commit_burn_observed',
    'installed_runtime_profile_terminal_chain_recognition_refusal_case_count',
    'installed_runtime_profile_terminal_chain_replay_identities_separate',
    'installed_runtime_profile_terminal_chain_restart_consumed_authority_grant_refused',
    'installed_runtime_profile_terminal_chain_same_process_signed_payload_replay_refused',
    'installed_runtime_profile_terminal_chain_state_append_after_grant_commit_burn_observed',
    'installed_runtime_profile_terminal_chain_store_anchor_and_witness_joint_rollback_detection',
    'installed_runtime_profile_terminal_chain_store_and_anchor_rollback_refused_while_witness_ahead',
    'live_rightful_issuance_proven',
    'local_fixture_rightful_issuance_path_evidenced',
    'local_proof_pack_artifact_body_sha256',
    'portable_rightful_issuance_proven',
    'production_rightful_issuance_proven',
    'runtime_local_activation_artifact_body_sha256',
    'runtime_profile_installation_artifact_body_sha256',
    'service_profile_preflight_artifact_body_sha256',
    'active_profile_live_runtime_profile_checked',
    'active_profile_persistent_runtime_profile_installed',
    'active_profile_selected',
    'active_profile_selects_latest',
    'active_profile_selection_verified',
    'activation_preflight_sample_artifact_verified',
    'configured_recognition_replay_store_case_count',
    'configured_recognition_replay_store_first_call_effect_written',
    'configured_recognition_replay_store_first_call_persisted',
    'configured_recognition_replay_store_invalid_store_failed_closed_before_callback',
    'configured_recognition_replay_store_no_secret_material',
    'configured_recognition_replay_store_path_redacted',
    'configured_recognition_replay_store_production_trust',
    'configured_recognition_replay_store_proof_verified',
    'configured_recognition_replay_store_real_downstream',
    'configured_recognition_replay_store_real_receipt',
    'configured_recognition_replay_store_replay_refused_before_callback',
    'source_bridge_window_authority_calls_github',
    'source_bridge_window_authority_can_push_under_window',
    'source_bridge_window_authority_changes_configuration',
    'source_bridge_window_authority_forbidden_consequences_present',
    'source_bridge_window_authority_mints_credentials',
    'source_bridge_window_authority_pushes_source',
    'source_bridge_window_authority_reads_private_key_material',
    'source_bridge_window_authority_reads_remote_refs',
    'source_bridge_window_authority_reads_token_material',
    'source_bridge_window_authority_safe_for_control_tower_use',
    'source_bridge_window_authority_stop_conditions_present',
    'source_bridge_window_authority_verified',
    'human_authorization_authorized_boarded',
    'human_authorization_denied_boarded',
    'human_authorization_pending_boarded',
    'human_authorization_summary_verified',
    'downstream_refusal_case_count',
    'downstream_refusal_final_marker_count',
    'downstream_refusal_marker_deltas_zero',
    'downstream_refusal_recognized_marker_count_delta',
    'downstream_refusal_summary_verified',
    'installed_runtime_profile_preflight_activation_performed',
    'installed_runtime_profile_preflight_current_machine_governance_proven',
    'installed_runtime_profile_preflight_downstream_refusal_proven',
    'installed_runtime_profile_preflight_hook_configuration_written',
    'installed_runtime_profile_preflight_installation_performed',
    'installed_runtime_profile_preflight_read_only',
    'installed_runtime_profile_preflight_recognition_contract_preserved',
    'installed_runtime_profile_preflight_recognition_contract_sha256',
    'installed_runtime_profile_preflight_sample_artifact_verified',
    'installed_runtime_profile_preflight_selected',
    'installed_runtime_profile_preflight_selects_latest',
    'installed_runtime_profile_recognition_activation_performed',
    'installed_runtime_profile_recognition_all_refusals_before_mutation',
    'installed_runtime_profile_recognition_current_machine_governance_proven',
    'installed_runtime_profile_recognition_install_performed',
    'installed_runtime_profile_recognition_production_downstream_recognition',
    'installed_runtime_profile_recognition_proof_verified',
    'installed_runtime_profile_recognition_recognized_write_boarded',
    'installed_runtime_profile_recognition_refusal_case_count',
    'installed_runtime_profile_recognition_runtime_service_started',
    'installed_runtime_profile_recognition_source_preflight_downstream_refusal_proven',
    'installed_runtime_profile_service_activation_performed',
    'installed_runtime_profile_service_all_consumed_store_integrity_refusals_before_mutation',
    'installed_runtime_profile_service_all_refusals_before_mutation',
    'installed_runtime_profile_service_all_replay_refusals_before_mutation',
    'installed_runtime_profile_service_all_store_and_anchor_rollback_refusals_before_mutation',
    'installed_runtime_profile_service_artifact_verification_all_refusals_before_mutation',
    'installed_runtime_profile_service_artifact_verification_body_sha256',
    'installed_runtime_profile_service_artifact_verification_consumed_store_integrity_case_count',
    'installed_runtime_profile_service_artifact_verification_current_machine_governance_proven',
    'installed_runtime_profile_service_artifact_verification_payload_type',
    'installed_runtime_profile_service_artifact_verification_production_downstream_recognition',
    'installed_runtime_profile_service_artifact_verification_recognized_write_boarded',
    'installed_runtime_profile_service_artifact_verification_recognition_contract_sha256',
    'installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256',
    'installed_runtime_profile_service_artifact_verification_restart_replay_refused',
    'installed_runtime_profile_service_artifact_verification_runtime_service_started',
    'installed_runtime_profile_service_artifact_verification_store_anchor_and_witness_joint_rollback_detection',
    'installed_runtime_profile_service_artifact_verification_store_and_anchor_joint_rollback_detection',
    'installed_runtime_profile_service_artifact_verification_store_and_anchor_rollback_case_count',
    'installed_runtime_profile_service_artifact_verification_verified',
    'installed_runtime_profile_service_config_path_exposed_to_request_stream',
    'installed_runtime_profile_service_consumed_store_integrity_case_count',
    'installed_runtime_profile_service_consumed_store_integrity_refusals_proven',
    'installed_runtime_profile_service_consumed_store_witness_source',
    'installed_runtime_profile_service_current_machine_governance_proven',
    'installed_runtime_profile_service_disposable_runtime_config_written',
    'installed_runtime_profile_service_install_performed',
    'installed_runtime_profile_service_persistent_runtime_config_written',
    'installed_runtime_profile_service_production_downstream_recognition',
    'installed_runtime_profile_service_proof_verified',
    'installed_runtime_profile_service_recognized_write_boarded',
    'installed_runtime_profile_service_recognition_contract_sha256',
    'installed_runtime_profile_service_recognition_rule_bound_to_selected_profile',
    'installed_runtime_profile_service_refusal_case_count',
    'installed_runtime_profile_service_replay_case_count',
    'installed_runtime_profile_service_restart_replay_refused',
    'installed_runtime_profile_service_runtime_service_started',
    'installed_runtime_profile_service_same_process_replay_refused',
    'installed_runtime_profile_service_single_host_consumed_store_rollback_detection',
    'installed_runtime_profile_service_source_preflight_downstream_refusal_proven',
    'installed_runtime_profile_service_store_anchor_and_witness_joint_rollback_detection',
    'installed_runtime_profile_service_store_and_anchor_joint_rollback_refusals_proven',
    'installed_runtime_profile_service_store_and_anchor_joint_rollback_detection',
    'installed_runtime_profile_service_store_and_anchor_rollback_case_count',
    'installed_runtime_profile_terminal_chain_activation_performed',
    'installed_runtime_profile_terminal_chain_all_required_refusals_before_mutation',
    'installed_runtime_profile_terminal_chain_artifact_verification_all_required_refusals_before_mutation',
    'installed_runtime_profile_terminal_chain_artifact_verification_body_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_current_machine_governance_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_current_machine_governance',
    'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_enterprise_readiness',
    'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_external_attestation',
    'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_authority',
    'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_downstream_recognition',
    'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count',
    'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids',
    'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_preserved',
    'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_profile_sha_matches',
    'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started',
    'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation',
    'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof',
    'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_sovereign_recognition',
    'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_unrouted_surface_coverage',
    'installed_runtime_profile_terminal_chain_artifact_verification_latest_profile_selection_refused_before_service_proof',
    'installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved',
    'installed_runtime_profile_terminal_chain_artifact_verification_nested_preflight_artifact_type',
    'installed_runtime_profile_terminal_chain_artifact_verification_nested_service_proof_artifact_type',
    'installed_runtime_profile_terminal_chain_artifact_verification_profile_recognition_mismatch_refused_before_service_proof',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_preserved',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_artifact_crypto_reproducible',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_current_machine_governance_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_key_custody_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_issuer_status_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_state_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_authority',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_downstream_recognition_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_trust_registry_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_external_attestation',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_key_material_included',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_real_non_operator_review',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_contract_hash_bound',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_envelope_included',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_artifact_crypto_reproducible',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_current_machine_governance_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_bound_to_artifact_body',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_preserved',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_key_custody_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_live_registry_state',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_production_downstream_recognition_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_public_external_attestation',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_public_key_material_included',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_receipt_envelope_included',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_recognition_contract_hash_bound',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_recognized_write_boarded',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_revocation_truth_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_selected_profile_hash_bound',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_service_artifact_hash_bound',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_matches_terminal_chain',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_matches_trusted_registry_binding',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_sovereign_recognition',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_terminal_chain_decision_bound',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_revocation_truth_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_sovereign_recognition',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count',
    'installed_runtime_profile_terminal_chain_artifact_verification_production_downstream_recognition',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognition_contract_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_request_stream_authority_material_refused_before_service_proof',
    'installed_runtime_profile_terminal_chain_artifact_verification_stale_deployment_profile_artifact_refused_before_service_proof',
    'installed_runtime_profile_terminal_chain_artifact_verification_verified',
    'installed_runtime_profile_terminal_chain_current_machine_governance_proven',
    'installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance',
    'installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness',
    'installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation',
    'installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority',
    'installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition',
    'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count',
    'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids',
    'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved',
    'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_profile_sha_matches',
    'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started',
    'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation',
    'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof',
    'installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition',
    'installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage',
    'installed_runtime_profile_terminal_chain_generated_installed_root_preflighted',
    'installed_runtime_profile_terminal_chain_generated_preflight_consumed',
    'installed_runtime_profile_terminal_chain_generated_service_artifact_verified',
    'installed_runtime_profile_terminal_chain_hook_configuration_written',
    'installed_runtime_profile_terminal_chain_invalid_receipt_refused_before_mutation',
    'installed_runtime_profile_terminal_chain_latest_profile_selection_refused_before_service_proof',
    'installed_runtime_profile_terminal_chain_missing_receipt_refused_before_mutation',
    'installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256',
    'installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved',
    'installed_runtime_profile_terminal_chain_nested_preflight_artifact_type',
    'installed_runtime_profile_terminal_chain_nested_service_proof_artifact_type',
    'installed_runtime_profile_terminal_chain_observed_refusal_case_count',
    'installed_runtime_profile_terminal_chain_persistent_runtime_profile_installed',
    'installed_runtime_profile_terminal_chain_profile_recognition_mismatch_refused_before_service_proof',
    'installed_runtime_profile_terminal_chain_production_downstream_recognition',
    'installed_runtime_profile_terminal_chain_recognized_write_boarded',
    'installed_runtime_profile_terminal_chain_recognition_contract_sha256',
    'installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count',
    'installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids',
    'installed_runtime_profile_terminal_chain_recognition_refusal_group_count',
    'installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256',
    'installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256',
    'installed_runtime_profile_terminal_chain_request_stream_authority_material_refused_before_service_proof',
    'installed_runtime_profile_terminal_chain_required_refusal_case_count',
    'installed_runtime_profile_terminal_chain_service_artifact_verification_bound_to_service_proof',
    'installed_runtime_profile_terminal_chain_service_proof_bound_to_generated_preflight',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_artifact_crypto_reproducible',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_current_machine_governance_proven',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_key_custody_proven',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_issuer_status_proven',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_state_proven',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_authority',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_downstream_recognition_proven',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_trust_registry_proven',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_external_attestation',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_key_material_included',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_real_non_operator_review',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_contract_hash_bound',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_envelope_included',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_artifact_crypto_reproducible',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_current_machine_governance_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_preserved',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_key_custody_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_live_registry_state',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_production_downstream_recognition_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_public_external_attestation',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_public_key_material_included',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_receipt_envelope_included',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_recognition_contract_hash_bound',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_recognized_write_boarded',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_revocation_truth_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_selected_profile_hash_bound',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_service_artifact_hash_bound',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_matches_trusted_registry_binding',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_sovereign_recognition',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_terminal_chain_decision_bound',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_revocation_truth_proven',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_sovereign_recognition',
    'installed_runtime_profile_terminal_chain_stale_deployment_profile_artifact_refused_before_service_proof',
    'installed_runtime_profile_terminal_chain_verified',
    'key_state_current_machine_governance_proven',
    'key_state_key_custody_proven',
    'key_state_private_key_material_read',
    'key_state_report_summary_verified',
    'runtime_local_activation_applied',
    'runtime_local_activation_missing_receipt_refused',
    'runtime_local_activation_sample_artifact_verified',
    'runtime_profile_installation_applied',
    'runtime_profile_installation_hook_configuration_written',
    'runtime_profile_installation_persistent_profile_installed',
    'runtime_profile_installation_request_authority_guard_refused',
    'runtime_profile_installation_sample_artifact_verified',
    'runtime_profile_installation_selects_latest',
    'receipt_verifier_boundary_summary_verified',
    'receipt_verifier_legacy_v0_required_identity_refused',
    'receipt_verifier_unknown_signer_distinguished',
    'receipt_verifier_v1_identity_verified',
    'service_profile_preflight_sample_artifact_verified',
    'service_profile_preflight_cases',
    'service_profile_preflight_summary_verified',
    'sample_artifact_verified',
    'trusted_issuer_registry_current_machine_governance_proven',
    'trusted_issuer_registry_evaluation_result_type',
    'trusted_issuer_registry_fixture_evaluated',
    'trusted_issuer_registry_fixture_validated',
    'trusted_issuer_registry_key_custody_proven',
    'trusted_issuer_registry_live_issuer_status_proven',
    'trusted_issuer_registry_live_state_proven',
    'trusted_issuer_registry_malformed_fixture_refused',
    'trusted_issuer_registry_recognition_observed',
    'trusted_issuer_registry_production_authority',
    'trusted_issuer_registry_production_downstream_recognition_proven',
    'trusted_issuer_registry_production_trust_registry_proven',
    'trusted_issuer_registry_public_external_attestation',
    'trusted_issuer_registry_real_non_operator_review',
    'trusted_issuer_registry_recognition_summary_verified',
    'trusted_issuer_registry_revocation_truth_proven',
    'trusted_issuer_registry_sovereign_recognition',
    'trusted_issuer_registry_to_recognition_rule_evaluated',
    'trusted_issuer_registry_trusted_issuer_count',
    'governed_lanes',
    'counted_lanes',
    'boundary_entries',
  ]);
  if (
    report.counts.local_proof_pack_artifact_body_sha256 !==
      localProofPackSampleArtifactBodySha256() ||
    report.counts.service_profile_preflight_artifact_body_sha256 !==
      serviceProfilePreflightStep.verification.body_sha256 ||
    report.counts.activation_preflight_artifact_body_sha256 !==
      activationStep.verification.body_sha256 ||
    report.counts.runtime_local_activation_artifact_body_sha256 !==
      runtimeLocalActivationStep.verification.body_sha256 ||
    report.counts.runtime_profile_installation_artifact_body_sha256 !==
      runtimeProfileInstallationStep.verification.body_sha256 ||
    report.counts.installed_runtime_profile_preflight_artifact_body_sha256 !==
      installedRuntimeProfilePreflightStep.verification.body_sha256 ||
    report.counts.installed_runtime_profile_recognition_proof_sha256 !==
      sha256hex(canonicalize(installedRuntimeProfileRecognitionStep.proof)) ||
    report.counts.installed_runtime_profile_service_proof_artifact_body_sha256 !==
      installedRuntimeProfileServiceArtifactVerificationStep.verification.body_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_body_sha256 !==
      CONSEQUENCE_LIFECYCLE_PINNED_TERMINAL_ARTIFACT_BODY_SHA256 ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_body_sha256 !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.body_sha256 ||
    report.counts.consequence_lifecycle_map_projection_sha256 !==
      consequenceLifecycleMapSha256(consequenceLifecycleMapStep.lifecycle_map) ||
    report.counts.coverage_map_sha256 !==
      sha256hex(canonicalize(coverageStep.coverage_map))
  ) {
    throw new Error('Proof smoke exact dependency hash aggregation drifted');
  }
  const mappedObligations = consequenceLifecycleMapStep.lifecycle_map.lifecycle_obligations;
  if (
    report.counts.consequence_lifecycle_map_evidenced_obligation_count !== 13 ||
    report.counts.consequence_lifecycle_map_evidenced_obligation_count !==
      mappedObligations.filter((item) => item.status === 'evidenced').length ||
    report.counts.consequence_lifecycle_map_not_evidenced_obligation_count !== 7 ||
    report.counts.consequence_lifecycle_map_not_evidenced_obligation_count !==
      mappedObligations.filter((item) => item.status === 'not_evidenced').length ||
    report.counts.consequence_lifecycle_map_outside_coverage_obligation_count !== 2 ||
    report.counts.consequence_lifecycle_map_outside_coverage_obligation_count !==
      mappedObligations.filter((item) => item.status === 'outside_coverage').length ||
    report.counts.consequence_lifecycle_map_evidence_reference_count !== 63 ||
    report.counts.consequence_lifecycle_map_evidence_reference_count !==
      consequenceLifecycleMapStep.lifecycle_map.evidence_ref_resolution.total_reference_count ||
    report.counts.consequence_lifecycle_map_all_evidence_references_resolved !== true ||
    report.counts.consequence_lifecycle_map_all_evidence_references_resolved !==
      consequenceLifecycleMapStep.lifecycle_map.evidence_ref_resolution.all_references_resolved
  ) {
    throw new Error('Proof smoke consequence lifecycle map aggregation drifted');
  }
  if (
    report.counts.local_fixture_rightful_issuance_path_evidenced !== true ||
    report.counts.generic_rightful_issuance_proven !== false ||
    report.counts.portable_rightful_issuance_proven !== false ||
    report.counts.live_rightful_issuance_proven !== false ||
    report.counts.production_rightful_issuance_proven !== false ||
    report.counts.current_machine_rightful_issuance_proven !== false ||
    report.counts.consequence_lifecycle_closed !== false ||
    report.counts.local_fixture_rightful_issuance_path_evidenced !==
      consequenceLifecycleMapStep.lifecycle_map.claim_boundary.local_fixture_rightful_issuance_path ||
    report.counts.generic_rightful_issuance_proven !==
      consequenceLifecycleMapStep.lifecycle_map.claim_boundary.generic_rightful_issuance ||
    report.counts.portable_rightful_issuance_proven !==
      consequenceLifecycleMapStep.lifecycle_map.claim_boundary.portable_rightful_issuance ||
    report.counts.live_rightful_issuance_proven !==
      consequenceLifecycleMapStep.lifecycle_map.claim_boundary.live_rightful_issuance ||
    report.counts.production_rightful_issuance_proven !==
      consequenceLifecycleMapStep.lifecycle_map.claim_boundary.production_rightful_issuance ||
    report.counts.current_machine_rightful_issuance_proven !==
      consequenceLifecycleMapStep.lifecycle_map.claim_boundary.current_machine_rightful_issuance ||
    report.counts.consequence_lifecycle_closed !==
      consequenceLifecycleMapStep.lifecycle_map.closure.lifecycle_closed
  ) {
    throw new Error('Proof smoke rightful-issuance claim ceiling drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_recognition_refusal_case_count !== 18 ||
    report.counts.installed_runtime_profile_service_authority_refusal_case_count !== 5 ||
    report.counts.installed_runtime_profile_service_all_authority_refusals_before_consumption_and_mutation !== true ||
    report.counts.installed_runtime_profile_service_same_process_signed_payload_replay_refused !== true ||
    report.counts.installed_runtime_profile_service_restart_consumed_authority_grant_refused !== true ||
    report.counts.installed_runtime_profile_service_replay_identities_separate !== true ||
    report.counts.installed_runtime_profile_service_state_append_after_grant_commit_burn_observed !== true ||
    report.counts.installed_runtime_profile_service_metadata_partial_commit_burn_observed !== true ||
    report.counts.installed_runtime_profile_service_store_and_anchor_rollback_refused_while_witness_ahead !== true ||
    report.counts.installed_runtime_profile_service_store_anchor_and_witness_joint_rollback_detection !== false ||
    report.counts.installed_runtime_profile_service_joint_rollback_reopened_authority_grant_reuse !== true ||
    report.counts.installed_runtime_profile_service_fixture_rightful_issuance_path_evidenced !== true
  ) {
    throw new Error('Proof smoke service rightful-issuance lifecycle aggregation drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_recognition_refusal_case_count !== 18 ||
    report.counts.installed_runtime_profile_service_artifact_verification_authority_refusal_case_count !== 5 ||
    report.counts.installed_runtime_profile_service_artifact_verification_same_process_signed_payload_replay_refused !== true ||
    report.counts.installed_runtime_profile_service_artifact_verification_restart_consumed_authority_grant_refused !== true ||
    report.counts.installed_runtime_profile_service_artifact_verification_state_append_after_grant_commit_burn_observed !== true ||
    report.counts.installed_runtime_profile_service_artifact_verification_metadata_partial_commit_burn_observed !== true ||
    report.counts.installed_runtime_profile_service_artifact_verification_store_anchor_and_witness_joint_rollback_detection !== false ||
    report.counts.installed_runtime_profile_service_artifact_verification_joint_rollback_reopened_authority_grant_reuse !== true ||
    report.counts.installed_runtime_profile_service_artifact_verification_fixture_rightful_issuance_path_evidenced !== true
  ) {
    throw new Error('Proof smoke service artifact lifecycle aggregation drifted');
  }
  if (
    report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_case_count !== 18 ||
    report.counts.installed_runtime_profile_terminal_chain_authority_refusal_case_count !== 5 ||
    report.counts.installed_runtime_profile_terminal_chain_all_authority_refusals_before_consumption_and_mutation !== true ||
    report.counts.installed_runtime_profile_terminal_chain_same_process_signed_payload_replay_refused !== true ||
    report.counts.installed_runtime_profile_terminal_chain_restart_consumed_authority_grant_refused !== true ||
    report.counts.installed_runtime_profile_terminal_chain_replay_identities_separate !== true ||
    report.counts.installed_runtime_profile_terminal_chain_state_append_after_grant_commit_burn_observed !== true ||
    report.counts.installed_runtime_profile_terminal_chain_metadata_partial_commit_burn_observed !== true ||
    report.counts.installed_runtime_profile_terminal_chain_store_and_anchor_rollback_refused_while_witness_ahead !== true ||
    report.counts.installed_runtime_profile_terminal_chain_store_anchor_and_witness_joint_rollback_detection !== false ||
    report.counts.installed_runtime_profile_terminal_chain_joint_rollback_reopened_authority_grant_reuse !== true ||
    report.counts.installed_runtime_profile_terminal_chain_fixture_rightful_issuance_path_evidenced !== true
  ) {
    throw new Error('Proof smoke terminal-chain lifecycle aggregation drifted');
  }
  if (
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_case_count !== 18 ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_authority_refusal_case_count !== 5 ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_all_authority_refusals_before_consumption_and_mutation !== true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_same_process_signed_payload_replay_refused !== true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_restart_consumed_authority_grant_refused !== true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_state_append_after_grant_commit_burn_observed !== true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_metadata_partial_commit_burn_observed !== true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_store_and_anchor_rollback_refused_while_witness_ahead !== true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_store_anchor_and_witness_joint_rollback_detection !== false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_joint_rollback_reopened_authority_grant_reuse !== true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_host_filesystem_path_toctou_closed !== false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_fixture_rightful_issuance_path_evidenced !== true
  ) {
    throw new Error('Proof smoke terminal artifact lifecycle aggregation drifted');
  }
  if (
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_structural_self_integrity_verified !== true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_identity_match_requires_expected_sha256 !== true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_expected_body_sha256 !==
      CONSEQUENCE_LIFECYCLE_PINNED_TERMINAL_ARTIFACT_BODY_SHA256 ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_expected_body_sha256_matched !== true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_structural_self_integrity_verified !== true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_identity_match_requires_expected_sha256 !== true ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_expected_body_sha256 || ''
    ) ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_expected_body_sha256 !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.embedded_service_artifact_expected_body_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_embedded_service_expected_body_sha256_matched !== true
  ) {
    throw new Error('Proof smoke terminal structural-versus-pinned identity drifted');
  }
  if (
    report.counts.configured_recognition_replay_store_proof_verified !== true ||
    report.counts.configured_recognition_replay_store_case_count !== 3 ||
    report.counts.configured_recognition_replay_store_case_count !==
      configuredRecognitionReplayStoreStep.proof.case_count ||
    report.counts.configured_recognition_replay_store_first_call_persisted !== true ||
    report.counts.configured_recognition_replay_store_first_call_persisted !==
      configuredRecognitionReplayStoreStep.proof.summary.first_call_persisted ||
    report.counts.configured_recognition_replay_store_first_call_effect_written !== true ||
    report.counts.configured_recognition_replay_store_first_call_effect_written !==
      configuredRecognitionReplayStoreStep.proof.summary.first_call_effect_written ||
    report.counts.configured_recognition_replay_store_replay_refused_before_callback !== true ||
    report.counts.configured_recognition_replay_store_replay_refused_before_callback !==
      configuredRecognitionReplayStoreStep.proof.summary.replay_refused_before_callback ||
    report.counts.configured_recognition_replay_store_invalid_store_failed_closed_before_callback !== true ||
    report.counts.configured_recognition_replay_store_invalid_store_failed_closed_before_callback !==
      configuredRecognitionReplayStoreStep.proof.summary.invalid_store_failed_closed_before_callback ||
    report.counts.configured_recognition_replay_store_no_secret_material !== true ||
    report.counts.configured_recognition_replay_store_no_secret_material !==
      configuredRecognitionReplayStoreStep.proof.no_secret_material ||
    report.counts.configured_recognition_replay_store_path_redacted !== true ||
    report.counts.configured_recognition_replay_store_path_redacted !==
      configuredRecognitionReplayStoreStep.proof.store_path_redacted ||
    report.counts.configured_recognition_replay_store_real_downstream !== false ||
    report.counts.configured_recognition_replay_store_real_downstream !==
      configuredRecognitionReplayStoreStep.proof.real_downstream ||
    report.counts.configured_recognition_replay_store_real_receipt !== false ||
    report.counts.configured_recognition_replay_store_real_receipt !==
      configuredRecognitionReplayStoreStep.proof.real_receipt ||
    report.counts.configured_recognition_replay_store_production_trust !== false ||
    report.counts.configured_recognition_replay_store_production_trust !==
      configuredRecognitionReplayStoreStep.proof.production_trust
  ) {
    throw new Error('Proof smoke configured recognition replay-store count drifted');
  }
  if (
    report.counts.source_bridge_window_authority_verified !== true ||
    report.counts.source_bridge_window_authority_safe_for_control_tower_use !== true ||
    report.counts.source_bridge_window_authority_can_push_under_window !== true ||
    report.counts.source_bridge_window_authority_forbidden_consequences_present !== true ||
    report.counts.source_bridge_window_authority_stop_conditions_present !== true ||
    report.counts.source_bridge_window_authority_reads_private_key_material !== false ||
    report.counts.source_bridge_window_authority_reads_token_material !== false ||
    report.counts.source_bridge_window_authority_mints_credentials !== false ||
    report.counts.source_bridge_window_authority_calls_github !== false ||
    report.counts.source_bridge_window_authority_reads_remote_refs !== false ||
    report.counts.source_bridge_window_authority_pushes_source !== false ||
    report.counts.source_bridge_window_authority_changes_configuration !== false ||
    report.counts.source_bridge_window_authority_safe_for_control_tower_use !==
      sourceBridgeWindowAuthorityStep.authority.safe_for_control_tower_use ||
    report.counts.source_bridge_window_authority_can_push_under_window !==
      sourceBridgeWindowAuthorityStep.authority.can_push_under_window ||
    report.counts.source_bridge_window_authority_forbidden_consequences_present !==
      sourceBridgeWindowAuthorityStep.authority.required_forbidden_consequences_present ||
    report.counts.source_bridge_window_authority_stop_conditions_present !==
      sourceBridgeWindowAuthorityStep.authority.required_stop_conditions_present ||
    report.counts.source_bridge_window_authority_reads_private_key_material !==
      sourceBridgeWindowAuthorityStep.authority.no_secret_boundary.reads_private_key_material ||
    report.counts.source_bridge_window_authority_reads_token_material !==
      sourceBridgeWindowAuthorityStep.authority.no_secret_boundary.reads_token_material ||
    report.counts.source_bridge_window_authority_mints_credentials !==
      sourceBridgeWindowAuthorityStep.authority.no_secret_boundary.mints_credentials ||
    report.counts.source_bridge_window_authority_calls_github !==
      sourceBridgeWindowAuthorityStep.authority.no_secret_boundary.calls_github ||
    report.counts.source_bridge_window_authority_reads_remote_refs !==
      sourceBridgeWindowAuthorityStep.authority.no_secret_boundary.reads_remote_refs ||
    report.counts.source_bridge_window_authority_pushes_source !==
      sourceBridgeWindowAuthorityStep.authority.no_secret_boundary.pushes_source ||
    report.counts.source_bridge_window_authority_changes_configuration !==
      sourceBridgeWindowAuthorityStep.authority.no_secret_boundary.changes_configuration
  ) {
    throw new Error('Proof smoke source bridge window authority count drifted');
  }
  if (report.counts.sample_artifact_verified !== true) {
    throw new Error('Proof smoke report sample artifact count must be true');
  }
  if (report.counts.key_state_report_summary_verified !== true) {
    throw new Error('Proof smoke report key-state summary count must be true');
  }
  if (report.counts.key_state_private_key_material_read !== false) {
    throw new Error('Proof smoke report key-state private-key-read count must be false');
  }
  if (report.counts.key_state_key_custody_proven !== false) {
    throw new Error('Proof smoke report key-state custody count must be false');
  }
  if (report.counts.key_state_current_machine_governance_proven !== false) {
    throw new Error('Proof smoke report key-state current-machine-governance count must be false');
  }
  if (
    report.counts.key_state_private_key_material_read !==
    sampleStep.verification.key_state_report.private_key_material_read ||
    report.counts.key_state_key_custody_proven !==
    sampleStep.verification.key_state_report.key_custody_proven ||
    report.counts.key_state_current_machine_governance_proven !==
    sampleStep.verification.key_state_report.current_machine_governance_proven
  ) {
    throw new Error('Proof smoke key-state count drifted from embedded summary');
  }
  if (
    report.counts.downstream_refusal_summary_verified !== true ||
    report.counts.downstream_refusal_recognized_marker_count_delta !== 1 ||
    report.counts.downstream_refusal_final_marker_count !== 1 ||
    report.counts.downstream_refusal_case_count !== DOWNSTREAM_REFUSAL_REASONS.length ||
    report.counts.downstream_refusal_marker_deltas_zero !== true
  ) {
    throw new Error('Proof smoke downstream-refusal summary count drifted');
  }
  if (
    report.counts.downstream_refusal_recognized_marker_count_delta !==
      sampleStep.verification.downstream_refusal.recognized_marker_count_delta ||
    report.counts.downstream_refusal_final_marker_count !==
      sampleStep.verification.downstream_refusal.final_marker_count ||
    report.counts.downstream_refusal_case_count !==
      sampleStep.verification.downstream_refusal.refusal_case_count ||
    report.counts.downstream_refusal_marker_deltas_zero !==
      sampleStep.verification.downstream_refusal.all_refusal_marker_count_deltas_zero
  ) {
    throw new Error('Proof smoke downstream-refusal count drifted from embedded summary');
  }
  if (report.counts.receipt_verifier_boundary_summary_verified !== true) {
    throw new Error('Proof smoke report receipt verifier boundary summary count must be true');
  }
  if (
    report.counts.receipt_verifier_v1_identity_verified !== true ||
    report.counts.receipt_verifier_v1_identity_verified !==
      (
        sampleStep.verification.receipt_verifier_boundary.valid_receipt_sha256_present === true &&
        sampleStep.verification.receipt_verifier_boundary.valid_provided_pubkey_sha256_present === true &&
        sampleStep.verification.receipt_verifier_boundary.required_identity_receipt_sha256_matched === true &&
        sampleStep.verification.receipt_verifier_boundary.required_identity_pubkey_sha256_matched === true &&
        sampleStep.verification.receipt_verifier_boundary.required_identity_v1_only_matched === true
      )
  ) {
    throw new Error('Proof smoke receipt verifier v1 identity count drifted');
  }
  if (
    report.counts.receipt_verifier_legacy_v0_required_identity_refused !== true ||
    report.counts.receipt_verifier_legacy_v0_required_identity_refused !==
      sampleStep.verification.receipt_verifier_boundary.legacy_v0_required_identity_refused
  ) {
    throw new Error('Proof smoke receipt verifier legacy v0 refusal count drifted');
  }
  if (
    report.counts.receipt_verifier_unknown_signer_distinguished !==
    sampleStep.verification.receipt_verifier_boundary.distinguishes_unknown_signer_from_invalid
  ) {
    throw new Error('Proof smoke receipt verifier boundary distinction count drifted');
  }
  const trustedIssuerRegistryRecognition =
    sampleStep.verification.trusted_issuer_registry_recognition;
  if (report.counts.trusted_issuer_registry_recognition_summary_verified !== true) {
    throw new Error('Proof smoke trusted issuer registry summary count must be true');
  }
  if (
    report.counts.trusted_issuer_registry_recognition_observed !==
      trustedIssuerRegistryRecognition.recognized ||
    report.counts.trusted_issuer_registry_recognition_observed !== true ||
    report.counts.trusted_issuer_registry_malformed_fixture_refused !==
      trustedIssuerRegistryRecognition.malformed_registry_fail_closed_before_verdict ||
    report.counts.trusted_issuer_registry_malformed_fixture_refused !== true
  ) {
    throw new Error('Proof smoke trusted issuer registry recognition count drifted');
  }
  if (
    report.counts.trusted_issuer_registry_fixture_validated !==
      trustedIssuerRegistryRecognition.registry_fixture_validated ||
    report.counts.trusted_issuer_registry_fixture_validated !== true ||
    report.counts.trusted_issuer_registry_fixture_evaluated !==
      trustedIssuerRegistryRecognition.registry_fixture_evaluated ||
    report.counts.trusted_issuer_registry_fixture_evaluated !== true ||
    report.counts.trusted_issuer_registry_to_recognition_rule_evaluated !==
      trustedIssuerRegistryRecognition.registry_to_recognition_rule_evaluated ||
    report.counts.trusted_issuer_registry_to_recognition_rule_evaluated !== true ||
    report.counts.trusted_issuer_registry_evaluation_result_type !==
      trustedIssuerRegistryRecognition.registry_evaluation_result_type ||
    report.counts.trusted_issuer_registry_evaluation_result_type !==
      'downstream-recognition-rule-v1' ||
    report.counts.trusted_issuer_registry_trusted_issuer_count !==
      trustedIssuerRegistryRecognition.registry_trusted_issuer_count ||
    report.counts.trusted_issuer_registry_trusted_issuer_count !== 1
  ) {
    throw new Error('Proof smoke trusted issuer registry evaluator count drifted');
  }
  for (const [countKey, summaryKey] of [
    ['trusted_issuer_registry_live_state_proven', 'live_trust_registry_state'],
    ['trusted_issuer_registry_live_issuer_status_proven', 'live_issuer_status_proven'],
    ['trusted_issuer_registry_key_custody_proven', 'key_custody_proven'],
    ['trusted_issuer_registry_revocation_truth_proven', 'revocation_truth_proven'],
    [
      'trusted_issuer_registry_production_trust_registry_proven',
      'production_trust_registry_proven',
    ],
    [
      'trusted_issuer_registry_production_downstream_recognition_proven',
      'production_downstream_recognition_proven',
    ],
    ['trusted_issuer_registry_production_authority', 'production_authority'],
    ['trusted_issuer_registry_public_external_attestation', 'public_external_attestation'],
    ['trusted_issuer_registry_real_non_operator_review', 'real_non_operator_review'],
    ['trusted_issuer_registry_sovereign_recognition', 'sovereign_recognition'],
    [
      'trusted_issuer_registry_current_machine_governance_proven',
      'current_machine_governance_proven',
    ],
  ]) {
    if (
      report.counts[countKey] !== trustedIssuerRegistryRecognition[summaryKey] ||
      report.counts[countKey] !== false
    ) {
      throw new Error(`Proof smoke trusted issuer registry ${countKey} count must be false`);
    }
  }
  if (report.counts.human_authorization_summary_verified !== true) {
    throw new Error('Proof smoke report human authorization summary count must be true');
  }
  if (
    report.counts.human_authorization_pending_boarded !==
      sampleStep.verification.human_authorization.pending_boarded ||
    report.counts.human_authorization_pending_boarded !== false ||
    report.counts.human_authorization_authorized_boarded !==
      sampleStep.verification.human_authorization.authorized_boarded ||
    report.counts.human_authorization_authorized_boarded !== true ||
    report.counts.human_authorization_denied_boarded !==
      sampleStep.verification.human_authorization.denied_boarded ||
    report.counts.human_authorization_denied_boarded !== false
  ) {
    throw new Error('Proof smoke human authorization count drifted');
  }
  if (report.counts.service_profile_preflight_sample_artifact_verified !== true) {
    throw new Error('Proof smoke report service profile preflight sample artifact count must be true');
  }
  if (report.counts.service_profile_preflight_summary_verified !== true) {
    throw new Error('Proof smoke report service preflight summary count must be true');
  }
  if (
    report.counts.service_profile_preflight_cases !==
    sampleStep.verification.service_profile_preflight.case_count
  ) {
    throw new Error('Proof smoke service preflight case count drifted');
  }
  if (report.counts.activation_preflight_sample_artifact_verified !== true) {
    throw new Error('Proof smoke report activation preflight sample artifact count must be true');
  }
  if (report.counts.runtime_local_activation_sample_artifact_verified !== true) {
    throw new Error('Proof smoke report runtime local activation sample artifact count must be true');
  }
  if (report.counts.runtime_profile_installation_sample_artifact_verified !== true) {
    throw new Error('Proof smoke report runtime profile installation sample artifact count must be true');
  }
  if (report.counts.active_profile_selection_verified !== true) {
    throw new Error('Proof smoke active profile selection count must be true');
  }
  if (
    report.counts.active_profile_selected !==
      sampleStep.verification.runtime_local_activation.active_profile_selection.selected ||
    report.counts.active_profile_selected !== true
  ) {
    throw new Error('Proof smoke active profile selected count drifted');
  }
  if (
    report.counts.active_profile_selects_latest !==
      sampleStep.verification.runtime_local_activation.active_profile_selection.selects_latest_profile ||
    report.counts.active_profile_selects_latest !== false
  ) {
    throw new Error('Proof smoke active profile latest-selection count drifted');
  }
  if (
    report.counts.active_profile_live_runtime_profile_checked !==
      sampleStep.verification.runtime_local_activation.active_profile_selection.live_runtime_profile_checked ||
    report.counts.active_profile_live_runtime_profile_checked !== false
  ) {
    throw new Error('Proof smoke active profile live-check count drifted');
  }
  if (
    report.counts.active_profile_persistent_runtime_profile_installed !==
      sampleStep.verification.runtime_local_activation.active_profile_selection.persistent_runtime_profile_installed ||
    report.counts.active_profile_persistent_runtime_profile_installed !== false
  ) {
    throw new Error('Proof smoke active profile persistent-install count drifted');
  }
  if (
    report.counts.runtime_local_activation_applied !==
    runtimeLocalActivationStep.verification.local_activation_applied
  ) {
    throw new Error('Proof smoke runtime local activation applied count drifted');
  }
  if (
    report.counts.runtime_local_activation_missing_receipt_refused !==
    runtimeLocalActivationStep.verification.missing_receipt_refused
  ) {
    throw new Error('Proof smoke runtime local activation missing-receipt count drifted');
  }
  if (
    report.counts.runtime_profile_installation_applied !==
      runtimeProfileInstallationStep.verification.disposable_profile_installation_applied ||
    report.counts.runtime_profile_installation_applied !== true
  ) {
    throw new Error('Proof smoke runtime profile installation applied count drifted');
  }
  if (
    report.counts.runtime_profile_installation_request_authority_guard_refused !==
      runtimeProfileInstallationStep.verification.request_authority_guard_refused ||
    report.counts.runtime_profile_installation_request_authority_guard_refused !== true
  ) {
    throw new Error('Proof smoke runtime profile installation request-guard count drifted');
  }
  if (
    report.counts.runtime_profile_installation_selects_latest !==
      runtimeProfileInstallationStep.verification.selects_latest_profile ||
    report.counts.runtime_profile_installation_selects_latest !== false
  ) {
    throw new Error('Proof smoke runtime profile installation latest-selection count drifted');
  }
  if (
    report.counts.runtime_profile_installation_persistent_profile_installed !==
      runtimeProfileInstallationStep.verification.persistent_runtime_profile_installed ||
    report.counts.runtime_profile_installation_persistent_profile_installed !== false
  ) {
    throw new Error('Proof smoke runtime profile installation persistent-install count drifted');
  }
  if (
    report.counts.runtime_profile_installation_hook_configuration_written !==
      runtimeProfileInstallationStep.verification.hook_configuration_written ||
    report.counts.runtime_profile_installation_hook_configuration_written !== false
  ) {
    throw new Error('Proof smoke runtime profile installation hook-configuration count drifted');
  }
  if (report.counts.installed_runtime_profile_preflight_sample_artifact_verified !== true) {
    throw new Error('Proof smoke installed runtime profile preflight sample artifact count must be true');
  }
  if (
    report.counts.installed_runtime_profile_preflight_read_only !==
      installedRuntimeProfilePreflightStep.verification.read_only ||
    report.counts.installed_runtime_profile_preflight_read_only !== true
  ) {
    throw new Error('Proof smoke installed runtime profile preflight read-only count drifted');
  }
  if (
    report.counts.installed_runtime_profile_preflight_selected !==
      installedRuntimeProfilePreflightStep.verification.profile_selected_from_install_root ||
    report.counts.installed_runtime_profile_preflight_selected !== true
  ) {
    throw new Error('Proof smoke installed runtime profile preflight selection count drifted');
  }
  if (
    report.counts.installed_runtime_profile_preflight_selects_latest !==
      installedRuntimeProfilePreflightStep.verification.selects_latest_profile ||
    report.counts.installed_runtime_profile_preflight_selects_latest !== false
  ) {
    throw new Error('Proof smoke installed runtime profile preflight latest-selection count drifted');
  }
  if (
    report.counts.installed_runtime_profile_preflight_installation_performed !==
      installedRuntimeProfilePreflightStep.verification.runtime_profile_installation_performed ||
    report.counts.installed_runtime_profile_preflight_installation_performed !== false
  ) {
    throw new Error('Proof smoke installed runtime profile preflight installation count drifted');
  }
  if (
    report.counts.installed_runtime_profile_preflight_activation_performed !==
      installedRuntimeProfilePreflightStep.verification.runtime_profile_activation_performed ||
    report.counts.installed_runtime_profile_preflight_activation_performed !== false
  ) {
    throw new Error('Proof smoke installed runtime profile preflight activation count drifted');
  }
  if (
    report.counts.installed_runtime_profile_preflight_hook_configuration_written !==
      installedRuntimeProfilePreflightStep.verification.hook_configuration_written ||
    report.counts.installed_runtime_profile_preflight_hook_configuration_written !== false
  ) {
    throw new Error('Proof smoke installed runtime profile preflight hook-configuration count drifted');
  }
  if (
    report.counts.installed_runtime_profile_preflight_recognition_contract_preserved !==
      installedRuntimeProfilePreflightStep.verification.recognition_contract_preserved ||
    report.counts.installed_runtime_profile_preflight_recognition_contract_preserved !== true
  ) {
    throw new Error('Proof smoke installed runtime profile preflight recognition-contract count drifted');
  }
  if (
    report.counts.installed_runtime_profile_preflight_recognition_contract_sha256 !==
      installedRuntimeProfilePreflightStep.verification.recognition_contract_sha256 ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_preflight_recognition_contract_sha256 || ''
    )
  ) {
    throw new Error('Proof smoke installed runtime profile preflight recognition-contract digest drifted');
  }
  if (
    report.counts.installed_runtime_profile_preflight_downstream_refusal_proven !==
      installedRuntimeProfilePreflightStep.verification.downstream_refusal_proven ||
    report.counts.installed_runtime_profile_preflight_downstream_refusal_proven !== false
  ) {
    throw new Error('Proof smoke installed runtime profile preflight downstream-refusal count drifted');
  }
  if (
    report.counts.installed_runtime_profile_preflight_current_machine_governance_proven !==
      installedRuntimeProfilePreflightStep.verification.current_machine_governance_proven ||
    report.counts.installed_runtime_profile_preflight_current_machine_governance_proven !== false
  ) {
    throw new Error('Proof smoke installed runtime profile preflight current-machine-governance count drifted');
  }
  if (report.counts.installed_runtime_profile_recognition_proof_verified !== true) {
    throw new Error('Proof smoke installed runtime profile recognition proof count must be true');
  }
  if (
    report.counts.installed_runtime_profile_recognition_recognized_write_boarded !==
      installedRuntimeProfileRecognitionStep.proof.recognized_boarding.boarded ||
    report.counts.installed_runtime_profile_recognition_recognized_write_boarded !== true
  ) {
    throw new Error('Proof smoke installed runtime profile recognition boarded count drifted');
  }
  if (
    report.counts.installed_runtime_profile_recognition_refusal_case_count !==
      installedRuntimeProfileRecognitionStep.proof.refusal_cases.length ||
    report.counts.installed_runtime_profile_recognition_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length
  ) {
    throw new Error('Proof smoke installed runtime profile recognition refusal-case count drifted');
  }
  if (
    report.counts.installed_runtime_profile_recognition_all_refusals_before_mutation !==
      installedRuntimeProfileRecognitionStep.proof.refusal_cases.every((item) =>
        item.boarded === false &&
        item.service_write_accepted === false &&
        item.state_entry_count_delta === 0
      ) ||
    report.counts.installed_runtime_profile_recognition_all_refusals_before_mutation !== true
  ) {
    throw new Error('Proof smoke installed runtime profile recognition refusal-before-mutation count drifted');
  }
  if (
    report.counts.installed_runtime_profile_recognition_source_preflight_downstream_refusal_proven !==
      installedRuntimeProfileRecognitionStep.proof.source_preflight.downstream_refusal_proven ||
    report.counts.installed_runtime_profile_recognition_source_preflight_downstream_refusal_proven !== false
  ) {
    throw new Error('Proof smoke installed runtime profile recognition source-preflight boundary count drifted');
  }
  if (
    report.counts.installed_runtime_profile_recognition_install_performed !==
      installedRuntimeProfileRecognitionStep.proof.proof_boundary.install_performed ||
    report.counts.installed_runtime_profile_recognition_install_performed !== false
  ) {
    throw new Error('Proof smoke installed runtime profile recognition install count drifted');
  }
  if (
    report.counts.installed_runtime_profile_recognition_activation_performed !==
      installedRuntimeProfileRecognitionStep.proof.proof_boundary.activation_performed ||
    report.counts.installed_runtime_profile_recognition_activation_performed !== false
  ) {
    throw new Error('Proof smoke installed runtime profile recognition activation count drifted');
  }
  if (
    report.counts.installed_runtime_profile_recognition_runtime_service_started !==
      installedRuntimeProfileRecognitionStep.proof.proof_boundary.runtime_service_started ||
    report.counts.installed_runtime_profile_recognition_runtime_service_started !== false
  ) {
    throw new Error('Proof smoke installed runtime profile recognition runtime-service count drifted');
  }
  if (
    report.counts.installed_runtime_profile_recognition_current_machine_governance_proven !==
      installedRuntimeProfileRecognitionStep.proof.proof_boundary.current_machine_governance_proven ||
    report.counts.installed_runtime_profile_recognition_current_machine_governance_proven !== false
  ) {
    throw new Error('Proof smoke installed runtime profile recognition current-machine count drifted');
  }
  if (
    report.counts.installed_runtime_profile_recognition_production_downstream_recognition !==
      installedRuntimeProfileRecognitionStep.proof.proof_boundary.production_downstream_recognition ||
    report.counts.installed_runtime_profile_recognition_production_downstream_recognition !== false
  ) {
    throw new Error('Proof smoke installed runtime profile recognition production-downstream count drifted');
  }
  if (report.counts.installed_runtime_profile_service_proof_verified !== true) {
    throw new Error('Proof smoke installed runtime profile service proof count must be true');
  }
  if (
    report.counts.installed_runtime_profile_service_runtime_service_started !==
      installedRuntimeProfileServiceStep.proof.service_boundary.runtime_service_started ||
    report.counts.installed_runtime_profile_service_runtime_service_started !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service runtime-service count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_disposable_runtime_config_written !==
      installedRuntimeProfileServiceStep.proof.service_boundary.disposable_runtime_config_written ||
    report.counts.installed_runtime_profile_service_disposable_runtime_config_written !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service disposable-config count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_persistent_runtime_config_written !==
      installedRuntimeProfileServiceStep.proof.service_boundary.persistent_runtime_config_written ||
    report.counts.installed_runtime_profile_service_persistent_runtime_config_written !== false
  ) {
    throw new Error('Proof smoke installed runtime profile service persistent-config count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_config_path_exposed_to_request_stream !==
      installedRuntimeProfileServiceStep.proof.service_config_provenance.config_path_exposed_to_request_stream ||
    report.counts.installed_runtime_profile_service_config_path_exposed_to_request_stream !== false
  ) {
    throw new Error('Proof smoke installed runtime profile service config-path exposure count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_recognition_rule_bound_to_selected_profile !==
      installedRuntimeProfileServiceStep.proof.service_config_provenance.recognition_rule_bound_to_selected_profile ||
    report.counts.installed_runtime_profile_service_recognition_rule_bound_to_selected_profile !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service recognition-rule provenance count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_recognition_contract_sha256 !==
      report.counts.installed_runtime_profile_preflight_recognition_contract_sha256 ||
    report.counts.installed_runtime_profile_service_recognition_contract_sha256 !==
      installedRuntimeProfileServiceStep.proof.source_preflight.recognition_contract_sha256 ||
    report.counts.installed_runtime_profile_service_recognition_contract_sha256 !==
      installedRuntimeProfileServiceStep.proof.recognition_contract.recognition_contract_sha256 ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_service_recognition_contract_sha256 || ''
    )
  ) {
    throw new Error('Proof smoke installed runtime profile service recognition-contract digest drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_consumed_store_witness_source !==
      installedRuntimeProfileServiceStep.proof.service_config_provenance.consumed_grant_store_witness_source ||
    report.counts.installed_runtime_profile_service_consumed_store_witness_source !==
      'launcher-owned-local-proof-witness'
  ) {
    throw new Error('Proof smoke installed runtime profile service witness provenance count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_recognized_write_boarded !==
      installedRuntimeProfileServiceStep.proof.recognized_boarding.boarded ||
    report.counts.installed_runtime_profile_service_recognized_write_boarded !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service boarded count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_replay_case_count !==
      installedRuntimeProfileServiceStep.proof.service_replay_cases.length ||
    report.counts.installed_runtime_profile_service_replay_case_count !== 2
  ) {
    throw new Error('Proof smoke installed runtime profile service replay-case count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_same_process_replay_refused !==
      installedRuntimeProfileServiceStep.proof.proof_boundary.same_process_signed_payload_replay_refused ||
    report.counts.installed_runtime_profile_service_same_process_replay_refused !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service same-process replay count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_restart_replay_refused !==
      installedRuntimeProfileServiceStep.proof.proof_boundary.restart_consumed_authority_grant_refused ||
    report.counts.installed_runtime_profile_service_restart_replay_refused !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service restart replay count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_all_replay_refusals_before_mutation !==
      installedRuntimeProfileServiceStep.proof.service_replay_cases.every((item) =>
        item.boarded === false &&
        item.service_write_accepted === false &&
        item.state_entry_count_delta === 0
      ) ||
    report.counts.installed_runtime_profile_service_all_replay_refusals_before_mutation !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service replay-before-mutation count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_consumed_store_integrity_case_count !==
      installedRuntimeProfileServiceStep.proof.partial_commit_cases.length ||
    report.counts.installed_runtime_profile_service_consumed_store_integrity_case_count !== 2
  ) {
    throw new Error('Proof smoke installed runtime profile service consumed-store integrity count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_consumed_store_integrity_refusals_proven !==
      installedRuntimeProfileServiceStep.proof.partial_commit_cases.every((item) =>
        item.service_write_accepted === false
      ) ||
    report.counts.installed_runtime_profile_service_consumed_store_integrity_refusals_proven !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service consumed-store integrity proof count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_all_consumed_store_integrity_refusals_before_mutation !==
      installedRuntimeProfileServiceStep.proof.partial_commit_cases.every((item) =>
        item.boarded === false &&
        item.service_write_accepted === false &&
        item.state_entry_count_delta === 0
      ) ||
    report.counts.installed_runtime_profile_service_all_consumed_store_integrity_refusals_before_mutation !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service consumed-store-before-mutation count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_single_host_consumed_store_rollback_detection !==
      installedRuntimeProfileServiceStep.proof.proof_boundary.store_and_anchor_rollback_refused_while_witness_ahead ||
    report.counts.installed_runtime_profile_service_single_host_consumed_store_rollback_detection !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service single-host rollback count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_store_and_anchor_joint_rollback_detection !==
      installedRuntimeProfileServiceStep.proof.proof_boundary.store_and_anchor_rollback_refused_while_witness_ahead ||
    report.counts.installed_runtime_profile_service_store_and_anchor_joint_rollback_detection !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service joint store-anchor rollback count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_store_and_anchor_rollback_case_count !==
      1 ||
    report.counts.installed_runtime_profile_service_store_and_anchor_rollback_case_count !== 1
  ) {
    throw new Error('Proof smoke installed runtime profile service store-anchor rollback case count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_store_and_anchor_joint_rollback_refusals_proven !==
      (installedRuntimeProfileServiceStep.proof.joint_rollback_case.store_and_anchor_only.service_write_accepted === false) ||
    report.counts.installed_runtime_profile_service_store_and_anchor_joint_rollback_refusals_proven !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service store-anchor rollback proof count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_all_store_and_anchor_rollback_refusals_before_mutation !==
      (
        installedRuntimeProfileServiceStep.proof.joint_rollback_case.store_and_anchor_only.boarded === false &&
        installedRuntimeProfileServiceStep.proof.joint_rollback_case.store_and_anchor_only.service_write_accepted === false &&
        installedRuntimeProfileServiceStep.proof.joint_rollback_case.store_and_anchor_only.state_entry_count_delta === 0
      ) ||
    report.counts.installed_runtime_profile_service_all_store_and_anchor_rollback_refusals_before_mutation !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service store-anchor rollback before-mutation count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_store_anchor_and_witness_joint_rollback_detection !==
      installedRuntimeProfileServiceStep.proof.proof_boundary.store_anchor_and_witness_joint_rollback_detection ||
    report.counts.installed_runtime_profile_service_store_anchor_and_witness_joint_rollback_detection !== false
  ) {
    throw new Error('Proof smoke installed runtime profile service joint store-anchor-witness rollback count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_refusal_case_count !==
      installedRuntimeProfileServiceStep.proof.refusal_cases.length ||
    report.counts.installed_runtime_profile_service_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length
  ) {
    throw new Error('Proof smoke installed runtime profile service refusal-case count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_all_refusals_before_mutation !==
      installedRuntimeProfileServiceStep.proof.refusal_cases.every((item) =>
        item.boarded === false &&
        item.service_write_accepted === false &&
        item.state_entry_count_delta === 0
      ) ||
    report.counts.installed_runtime_profile_service_all_refusals_before_mutation !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service refusal-before-mutation count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_source_preflight_downstream_refusal_proven !==
      installedRuntimeProfileServiceStep.proof.source_preflight.downstream_refusal_proven ||
    report.counts.installed_runtime_profile_service_source_preflight_downstream_refusal_proven !== false
  ) {
    throw new Error('Proof smoke installed runtime profile service source-preflight boundary count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_install_performed !==
      installedRuntimeProfileServiceStep.proof.proof_boundary.install_performed ||
    report.counts.installed_runtime_profile_service_install_performed !== false
  ) {
    throw new Error('Proof smoke installed runtime profile service install count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_activation_performed !==
      installedRuntimeProfileServiceStep.proof.proof_boundary.activation_performed ||
    report.counts.installed_runtime_profile_service_activation_performed !== false
  ) {
    throw new Error('Proof smoke installed runtime profile service activation count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_current_machine_governance_proven !==
      installedRuntimeProfileServiceStep.proof.proof_boundary.current_machine_governance_proven ||
    report.counts.installed_runtime_profile_service_current_machine_governance_proven !== false
  ) {
    throw new Error('Proof smoke installed runtime profile service current-machine count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_production_downstream_recognition !==
      installedRuntimeProfileServiceStep.proof.proof_boundary.production_downstream_recognition ||
    report.counts.installed_runtime_profile_service_production_downstream_recognition !== false
  ) {
    throw new Error('Proof smoke installed runtime profile service production-downstream count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_verified !==
      installedRuntimeProfileServiceArtifactVerificationStep.verification.verified ||
    report.counts.installed_runtime_profile_service_artifact_verification_verified !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service artifact verification count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_payload_type !==
      installedRuntimeProfileServiceArtifactVerificationStep.verification.payload_type ||
    report.counts.installed_runtime_profile_service_artifact_verification_payload_type !==
      installedRuntimeProfileServiceStep.proof.proof_type
  ) {
    throw new Error('Proof smoke installed runtime profile service artifact verification payload drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_body_sha256 !==
      installedRuntimeProfileServiceArtifactVerificationStep.verification.body_sha256 ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_service_artifact_verification_body_sha256 || ''
    )
  ) {
    throw new Error('Proof smoke installed runtime profile service artifact verification SHA-256 drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256 !==
      installedRuntimeProfileServiceArtifactVerificationStep.verification.recognition_refusal_taxonomy_sha256 ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256 || ''
    )
  ) {
    throw new Error('Proof smoke installed runtime profile service artifact verification refusal taxonomy drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_recognition_contract_sha256 !==
      installedRuntimeProfileServiceArtifactVerificationStep.verification.recognition_contract_sha256 ||
    report.counts.installed_runtime_profile_service_artifact_verification_recognition_contract_sha256 !==
      report.counts.installed_runtime_profile_service_recognition_contract_sha256 ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_service_artifact_verification_recognition_contract_sha256 || ''
    )
  ) {
    throw new Error('Proof smoke installed runtime profile service artifact verification recognition-contract digest drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_runtime_service_started !==
      installedRuntimeProfileServiceStep.proof.service_boundary.runtime_service_started ||
    report.counts.installed_runtime_profile_service_artifact_verification_runtime_service_started !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service artifact verification runtime-service count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_recognized_write_boarded !==
      installedRuntimeProfileServiceArtifactVerificationStep.verification.recognized_write_boarded ||
    report.counts.installed_runtime_profile_service_artifact_verification_recognized_write_boarded !==
      installedRuntimeProfileServiceStep.proof.recognized_boarding.boarded ||
    report.counts.installed_runtime_profile_service_artifact_verification_recognized_write_boarded !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service artifact verification boarded count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_restart_replay_refused !==
      installedRuntimeProfileServiceArtifactVerificationStep.verification.restart_consumed_authority_grant_refused ||
    report.counts.installed_runtime_profile_service_artifact_verification_restart_replay_refused !==
      installedRuntimeProfileServiceStep.proof.proof_boundary.restart_consumed_authority_grant_refused ||
    report.counts.installed_runtime_profile_service_artifact_verification_restart_replay_refused !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service artifact verification restart replay count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_consumed_store_integrity_case_count !==
      installedRuntimeProfileServiceStep.proof.partial_commit_cases.length ||
    report.counts.installed_runtime_profile_service_artifact_verification_consumed_store_integrity_case_count !== 2
  ) {
    throw new Error('Proof smoke installed runtime profile service artifact verification consumed-store count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_store_and_anchor_rollback_case_count !==
      1 ||
    report.counts.installed_runtime_profile_service_artifact_verification_store_and_anchor_rollback_case_count !== 1
  ) {
    throw new Error('Proof smoke installed runtime profile service artifact verification store-anchor rollback count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_store_and_anchor_joint_rollback_detection !==
      installedRuntimeProfileServiceArtifactVerificationStep.verification.store_and_anchor_rollback_refused_while_witness_ahead ||
    report.counts.installed_runtime_profile_service_artifact_verification_store_and_anchor_joint_rollback_detection !==
      installedRuntimeProfileServiceStep.proof.proof_boundary.store_and_anchor_rollback_refused_while_witness_ahead ||
    report.counts.installed_runtime_profile_service_artifact_verification_store_and_anchor_joint_rollback_detection !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service artifact verification store-anchor rollback count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_store_anchor_and_witness_joint_rollback_detection !==
      installedRuntimeProfileServiceArtifactVerificationStep.verification.store_anchor_and_witness_joint_rollback_detection ||
    report.counts.installed_runtime_profile_service_artifact_verification_store_anchor_and_witness_joint_rollback_detection !==
      installedRuntimeProfileServiceStep.proof.proof_boundary.store_anchor_and_witness_joint_rollback_detection ||
    report.counts.installed_runtime_profile_service_artifact_verification_store_anchor_and_witness_joint_rollback_detection !== false
  ) {
    throw new Error('Proof smoke installed runtime profile service artifact verification store-anchor-witness rollback count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_all_refusals_before_mutation !==
      (
        installedRuntimeProfileServiceArtifactVerificationStep.verification.all_recognition_refusals_before_mutation &&
        installedRuntimeProfileServiceArtifactVerificationStep.verification.all_authority_refusals_before_consumption_and_mutation
      ) ||
    report.counts.installed_runtime_profile_service_artifact_verification_all_refusals_before_mutation !== true
  ) {
    throw new Error('Proof smoke installed runtime profile service artifact verification refusal-before-mutation count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_current_machine_governance_proven !==
      installedRuntimeProfileServiceArtifactVerificationStep.verification.current_machine_governance_proven ||
    report.counts.installed_runtime_profile_service_artifact_verification_current_machine_governance_proven !==
      installedRuntimeProfileServiceStep.proof.proof_boundary.current_machine_governance_proven ||
    report.counts.installed_runtime_profile_service_artifact_verification_current_machine_governance_proven !== false
  ) {
    throw new Error('Proof smoke installed runtime profile service artifact verification current-machine count drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_production_downstream_recognition !==
      installedRuntimeProfileServiceArtifactVerificationStep.verification.production_downstream_recognition ||
    report.counts.installed_runtime_profile_service_artifact_verification_production_downstream_recognition !==
      installedRuntimeProfileServiceStep.proof.proof_boundary.production_downstream_recognition ||
    report.counts.installed_runtime_profile_service_artifact_verification_production_downstream_recognition !== false
  ) {
    throw new Error('Proof smoke installed runtime profile service artifact verification production-downstream count drifted');
  }
  if (
    report.counts.installed_runtime_profile_terminal_chain_verified !== true ||
    report.counts.installed_runtime_profile_terminal_chain_generated_installed_root_preflighted !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.generated_installed_root_preflighted ||
    report.counts.installed_runtime_profile_terminal_chain_generated_installed_root_preflighted !== true ||
    report.counts.installed_runtime_profile_terminal_chain_generated_preflight_consumed !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.generated_preflight_artifact_consumed_by_service_proof ||
    report.counts.installed_runtime_profile_terminal_chain_generated_preflight_consumed !== true ||
    report.counts.installed_runtime_profile_terminal_chain_generated_service_artifact_verified !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.generated_service_proof_artifact_verified ||
    report.counts.installed_runtime_profile_terminal_chain_generated_service_artifact_verified !== true ||
    report.counts.installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved !== true ||
    report.counts.installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved !==
      (
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.nested_artifact_binding.preflight_artifact_hash_bound === true &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.nested_artifact_binding.service_artifact_hash_bound === true &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.nested_artifact_binding.service_proof_source_preflight_hash_bound === true &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.nested_artifact_binding.proves_current_machine_governance === false &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.nested_artifact_binding.proves_production_downstream_recognition === false
      ) ||
    report.counts.installed_runtime_profile_terminal_chain_nested_preflight_artifact_type !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.nested_artifact_binding.generated_preflight_artifact_type ||
    report.counts.installed_runtime_profile_terminal_chain_nested_preflight_artifact_type !==
      'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1' ||
    report.counts.installed_runtime_profile_terminal_chain_nested_service_proof_artifact_type !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.nested_artifact_binding.generated_service_proof_artifact_type ||
    report.counts.installed_runtime_profile_terminal_chain_nested_service_proof_artifact_type !==
      'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1' ||
    report.counts.installed_runtime_profile_terminal_chain_service_proof_bound_to_generated_preflight !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.service_proof_bound_to_generated_preflight ||
    report.counts.installed_runtime_profile_terminal_chain_service_proof_bound_to_generated_preflight !== true ||
    report.counts.installed_runtime_profile_terminal_chain_service_artifact_verification_bound_to_service_proof !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.service_artifact_verification_bound_to_service_proof ||
    report.counts.installed_runtime_profile_terminal_chain_service_artifact_verification_bound_to_service_proof !== true
  ) {
    throw new Error('Proof smoke installed runtime profile terminal chain binding count drifted');
  }
  if (
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved !==
      (
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.verdict ===
          'RECOGNIZED' &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.recognized ===
          true &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_fixture_validated ===
          true &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_to_recognition_rule_evaluated ===
          true &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.recognition_contract_hash_bound ===
          true &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.service_artifact_hash_bound ===
          true &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_contract_hash_bound ===
          true &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_public_key_material_included ===
          false &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.receipt_envelope_included ===
          false &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.cryptographic_evidence_reproducible_from_artifact ===
          false &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.live_trust_registry_state ===
          false &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.live_issuer_status_proven ===
          false &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.key_custody_proven ===
          false &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.revocation_truth_proven ===
          false &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.production_trust_registry_proven ===
          false &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.production_downstream_recognition_proven ===
          false &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.production_authority ===
          false &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.sovereign_recognition ===
          false &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.public_external_attestation ===
          false &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.real_non_operator_review ===
          false &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.current_machine_governance_proven ===
          false
      ) ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256 !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256 !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.binding_sha256 ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256 ||
        ''
    ) ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS.length ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused !==
      true ||
    JSON.stringify(
      report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids
    ) !== JSON.stringify(expectedTrustedIssuerRegistryRecognitionRefusalCaseIds()) ||
    JSON.stringify(
      report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes
    ) !== JSON.stringify(expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes()) ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256 !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals_sha256 ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256 ||
        ''
    ) ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_state_proven !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_issuer_status_proven !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_key_custody_proven !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_revocation_truth_proven !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_trust_registry_proven !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_downstream_recognition_proven !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_authority !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_sovereign_recognition !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_external_attestation !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_real_non_operator_review !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_current_machine_governance_proven !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_key_material_included !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_envelope_included !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_artifact_crypto_reproducible !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_contract_hash_bound !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_issuer_status_proven !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.live_issuer_status_proven ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_trust_registry_proven !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.production_trust_registry_proven ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_external_attestation !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.public_external_attestation ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_key_material_included !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_public_key_material_included ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_envelope_included !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.receipt_envelope_included ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_artifact_crypto_reproducible !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.cryptographic_evidence_reproducible_from_artifact ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_contract_hash_bound !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_contract_hash_bound ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_sovereign_recognition !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.sovereign_recognition ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_real_non_operator_review !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.real_non_operator_review ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_current_machine_governance_proven !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.trusted_issuer_registry_recognition_binding.current_machine_governance_proven ||
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_current_machine_governance_proven !==
      false
  ) {
    throw new Error('Proof smoke installed runtime profile terminal chain trusted issuer registry binding count drifted');
  }
  const terminalChainRecognizedReceiptPathEvidence =
    installedRuntimeProfileTerminalChainStep.chain.terminal_chain.recognized_receipt_path_evidence;
  if (
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_preserved !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_preserved !==
      recognizedReceiptPathEvidencePreserved(
        terminalChainRecognizedReceiptPathEvidence,
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain
          .trusted_issuer_registry_recognition_binding,
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain
          .trusted_issuer_registry_recognition_binding_sha256
      ) ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256 !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain
        .recognized_receipt_path_evidence_sha256 ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256 ||
        ''
    ) ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256 !==
      terminalChainRecognizedReceiptPathEvidence.source_binding_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256 !==
      report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256 ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256 ||
        ''
    ) ||
    report.counts
      .installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_matches_trusted_registry_binding !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_selected_profile_hash_bound !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_recognition_contract_hash_bound !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_service_artifact_hash_bound !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_terminal_chain_decision_bound !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_recognized_write_boarded !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_public_key_material_included !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_receipt_envelope_included !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_artifact_crypto_reproducible !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_live_registry_state !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_key_custody_proven !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_revocation_truth_proven !==
      false ||
    report.counts
      .installed_runtime_profile_terminal_chain_recognized_receipt_path_production_downstream_recognition_proven !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_public_external_attestation !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_sovereign_recognition !==
      false ||
    report.counts
      .installed_runtime_profile_terminal_chain_recognized_receipt_path_current_machine_governance_proven !==
      false
  ) {
    throw new Error('Proof smoke installed runtime profile terminal chain recognized receipt path count drifted');
  }
  if (
    report.counts.installed_runtime_profile_terminal_chain_recognized_write_boarded !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.recognized_write_boarded ||
    report.counts.installed_runtime_profile_terminal_chain_recognized_write_boarded !== true ||
    report.counts.installed_runtime_profile_terminal_chain_missing_receipt_refused_before_mutation !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.missing_receipt_refused_before_mutation ||
    report.counts.installed_runtime_profile_terminal_chain_missing_receipt_refused_before_mutation !== true ||
    report.counts.installed_runtime_profile_terminal_chain_invalid_receipt_refused_before_mutation !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.invalid_receipt_refused_before_mutation ||
    report.counts.installed_runtime_profile_terminal_chain_invalid_receipt_refused_before_mutation !== true ||
    report.counts.installed_runtime_profile_terminal_chain_required_refusal_case_count !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.required_recognition_refusal_case_count ||
    report.counts.installed_runtime_profile_terminal_chain_required_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length ||
    report.counts.installed_runtime_profile_terminal_chain_observed_refusal_case_count !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.observed_recognition_refusal_case_count ||
    report.counts.installed_runtime_profile_terminal_chain_observed_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length ||
    report.counts.installed_runtime_profile_terminal_chain_all_required_refusals_before_mutation !==
      (
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.all_required_recognition_refusals_before_mutation &&
        installedRuntimeProfileTerminalChainStep.chain.terminal_chain.all_required_authority_refusals_before_consumption_and_mutation
      ) ||
    report.counts.installed_runtime_profile_terminal_chain_all_required_refusals_before_mutation !== true ||
    report.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256 !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.recognition_refusal_taxonomy_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256 !==
      installedRuntimeProfileTerminalChainStep.chain.generated_service_proof.recognition_refusal_taxonomy_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256 !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.named_receipt_refusals_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256 !==
      installedRuntimeProfileTerminalChainStep.chain.generated_service_proof.named_receipt_refusals_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256 !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.recognition_refusal_groups_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256 !==
      installedRuntimeProfileTerminalChainStep.chain.generated_service_proof.recognition_refusal_groups_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_count !==
      Object.keys(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS).length ||
    report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length ||
    !recognitionRefusalGroupCaseIdsMatch(
      report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids,
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.recognition_refusal_groups
    ) ||
    !recognitionRefusalGroupCaseIdsMatch(
      report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids,
      installedRuntimeProfileTerminalChainStep.chain.generated_service_proof.recognition_refusal_groups
    ) ||
    report.counts.installed_runtime_profile_terminal_chain_recognition_contract_sha256 !==
      installedRuntimeProfileTerminalChainStep.chain.terminal_chain.recognition_contract_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_recognition_contract_sha256 !==
      installedRuntimeProfileTerminalChainStep.chain.generated_service_proof.recognition_contract_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_recognition_contract_sha256 !==
      report.counts.installed_runtime_profile_service_artifact_verification_recognition_contract_sha256 ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_terminal_chain_recognition_contract_sha256 || ''
    ) ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256 || ''
    ) ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256 || ''
    ) ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256 || ''
    )
  ) {
    throw new Error('Proof smoke installed runtime profile terminal chain refusal count drifted');
  }
  const terminalChainDeploymentProfileAuthorityMirror =
    installedRuntimeProfileTerminalChainStep.chain.terminal_chain.deployment_profile_authority_refusal_mirror;
  if (
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved !==
      deploymentProfileAuthorityRefusalMirrorPreserved(terminalChainDeploymentProfileAuthorityMirror) ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_profile_sha_matches !==
      terminalChainDeploymentProfileAuthorityMirror.source_runtime_profile_sha_matches_terminal_chain ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_profile_sha_matches !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count !==
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count !==
      terminalChainDeploymentProfileAuthorityMirror.deployment_profile_authority_refusal_case_count ||
    JSON.stringify(report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids) !==
      JSON.stringify(REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES) ||
    JSON.stringify(report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids) !==
      JSON.stringify(terminalChainDeploymentProfileAuthorityMirror.deployment_profile_authority_refusal_case_ids) ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof !==
      terminalChainDeploymentProfileAuthorityMirror.deployment_profile_authority_refusals_before_service_proof ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation !==
      terminalChainDeploymentProfileAuthorityMirror.deployment_profile_authority_refusals_before_mutation ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started !==
      terminalChainDeploymentProfileAuthorityMirror.deployment_profile_authority_refusal_service_proof_started ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_stale_deployment_profile_artifact_refused_before_service_proof !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_profile_recognition_mismatch_refused_before_service_proof !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_latest_profile_selection_refused_before_service_proof !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_request_stream_authority_material_refused_before_service_proof !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage !==
      false
  ) {
    throw new Error('Proof smoke installed runtime profile terminal chain deployment-profile authority refusal mirror count drifted');
  }
  if (
    report.counts.installed_runtime_profile_terminal_chain_persistent_runtime_profile_installed !==
      installedRuntimeProfileTerminalChainStep.chain.side_door_report.persistent_runtime_profile_installed ||
    report.counts.installed_runtime_profile_terminal_chain_persistent_runtime_profile_installed !== false ||
    report.counts.installed_runtime_profile_terminal_chain_activation_performed !==
      installedRuntimeProfileTerminalChainStep.chain.side_door_report.runtime_profile_activation_performed ||
    report.counts.installed_runtime_profile_terminal_chain_activation_performed !== false ||
    report.counts.installed_runtime_profile_terminal_chain_hook_configuration_written !==
      installedRuntimeProfileTerminalChainStep.chain.side_door_report.hook_configuration_written ||
    report.counts.installed_runtime_profile_terminal_chain_hook_configuration_written !== false ||
    report.counts.installed_runtime_profile_terminal_chain_current_machine_governance_proven !==
      installedRuntimeProfileTerminalChainStep.chain.side_door_report.current_machine_governance_proven ||
    report.counts.installed_runtime_profile_terminal_chain_current_machine_governance_proven !== false ||
    report.counts.installed_runtime_profile_terminal_chain_production_downstream_recognition !==
      installedRuntimeProfileTerminalChainStep.chain.generated_service_proof.production_downstream_recognition ||
    report.counts.installed_runtime_profile_terminal_chain_production_downstream_recognition !== false
  ) {
    throw new Error('Proof smoke installed runtime profile terminal chain non-claim count drifted');
  }
  if (
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_verified !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.verified ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_verified !== true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_body_sha256 !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.body_sha256 ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_body_sha256 || ''
    ) ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved !== true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved !==
      (
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.nested_artifact_binding.preflight_artifact_hash_bound === true &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.nested_artifact_binding.service_artifact_hash_bound === true &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.nested_artifact_binding.service_proof_source_preflight_hash_bound === true &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.nested_artifact_binding.proves_current_machine_governance === false &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.nested_artifact_binding.proves_production_downstream_recognition === false
      ) ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_preflight_artifact_type !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.nested_artifact_binding.generated_preflight_artifact_type ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_preflight_artifact_type !==
      'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1' ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_service_proof_artifact_type !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.nested_artifact_binding.generated_service_proof_artifact_type ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_service_proof_artifact_type !==
      'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1' ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_preserved !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_preserved !==
      (
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.verdict ===
          'RECOGNIZED' &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.recognized ===
          true &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.registry_fixture_validated ===
          true &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.registry_to_recognition_rule_evaluated ===
          true &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.recognition_contract_hash_bound ===
          true &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.service_artifact_hash_bound ===
          true &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.registry_receipt_contract_hash_bound ===
          true &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.registry_public_key_material_included ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.receipt_envelope_included ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.cryptographic_evidence_reproducible_from_artifact ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.live_trust_registry_state ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.live_issuer_status_proven ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.key_custody_proven ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.revocation_truth_proven ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.production_trust_registry_proven ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.production_downstream_recognition_proven ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.production_authority ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.sovereign_recognition ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.public_external_attestation ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.real_non_operator_review ===
          false &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.current_machine_governance_proven ===
          false
      ) ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256 !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding_sha256 ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256 ||
        ''
    ) ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count !==
      report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS.length ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused !==
      report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused !==
      true ||
    JSON.stringify(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids
    ) !==
      JSON.stringify(
        report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids
      ) ||
    JSON.stringify(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids
    ) !== JSON.stringify(expectedTrustedIssuerRegistryRecognitionRefusalCaseIds()) ||
    JSON.stringify(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes
    ) !==
      JSON.stringify(
        report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes
      ) ||
    JSON.stringify(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes
    ) !== JSON.stringify(expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes()) ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256 !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256 !==
      report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256 ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256 ||
        ''
    ) ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_state_proven !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_issuer_status_proven !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_key_custody_proven !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_revocation_truth_proven !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_trust_registry_proven !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_downstream_recognition_proven !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_authority !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_sovereign_recognition !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_external_attestation !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_real_non_operator_review !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_current_machine_governance_proven !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_key_material_included !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_envelope_included !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_artifact_crypto_reproducible !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_contract_hash_bound !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_issuer_status_proven !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.live_issuer_status_proven ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_trust_registry_proven !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.production_trust_registry_proven ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_external_attestation !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.public_external_attestation ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_key_material_included !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.registry_public_key_material_included ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_envelope_included !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.receipt_envelope_included ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_artifact_crypto_reproducible !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.cryptographic_evidence_reproducible_from_artifact ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_contract_hash_bound !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.registry_receipt_contract_hash_bound ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_sovereign_recognition !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.sovereign_recognition ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_real_non_operator_review !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.real_non_operator_review ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_current_machine_governance_proven !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.trusted_issuer_registry_recognition_binding.current_machine_governance_proven ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_current_machine_governance_proven !==
      false ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_preserved !==
      true ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_preserved !==
      recognizedReceiptPathEvidencePreserved(
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification
          .recognized_receipt_path_evidence,
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification
          .trusted_issuer_registry_recognition_binding,
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification
          .trusted_issuer_registry_recognition_binding_sha256
      ) ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_sha256 !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification
        .recognized_receipt_path_evidence_sha256 ||
    !/^[a-f0-9]{64}$/.test(
      report.counts
        .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_sha256 ||
        ''
    ) ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_bound_to_artifact_body !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification
        .recognized_receipt_path_evidence_bound_to_artifact_body ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_bound_to_artifact_body !==
      true ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_sha256 !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification
        .recognized_receipt_path_evidence.source_binding_sha256 ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_sha256 !==
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256 ||
    !/^[a-f0-9]{64}$/.test(
      report.counts
        .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_sha256 ||
        ''
    ) ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_matches_terminal_chain !==
      true ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_matches_trusted_registry_binding !==
      true ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_selected_profile_hash_bound !==
      true ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_recognition_contract_hash_bound !==
      true ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_service_artifact_hash_bound !==
      true ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_terminal_chain_decision_bound !==
      true ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_recognized_write_boarded !==
      true ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_public_key_material_included !==
      false ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_receipt_envelope_included !==
      false ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_artifact_crypto_reproducible !==
      false ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_live_registry_state !==
      false ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_key_custody_proven !==
      false ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_revocation_truth_proven !==
      false ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_production_downstream_recognition_proven !==
      false ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_public_external_attestation !==
      false ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_sovereign_recognition !==
      false ||
    report.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_current_machine_governance_proven !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256 !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.recognition_refusal_taxonomy_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256 !==
      report.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256 !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.named_receipt_refusals_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256 !==
      report.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256 !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.recognition_refusal_groups_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256 !==
      report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count !==
      report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_count ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count !==
      Object.keys(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS).length ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count !==
      report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length ||
    !recognitionRefusalGroupCaseIdsMatch(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids,
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.recognition_refusal_groups
    ) ||
    JSON.stringify(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids
    ) !==
      JSON.stringify(
        report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids
      ) ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_contract_sha256 !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.recognition_contract_sha256 ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_contract_sha256 !==
      report.counts.installed_runtime_profile_terminal_chain_recognition_contract_sha256 ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_contract_sha256 || ''
    ) ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256 || ''
    ) ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256 || ''
    ) ||
    !/^[a-f0-9]{64}$/.test(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256 || ''
    ) ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_all_required_refusals_before_mutation !==
      (
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.all_required_recognition_refusals_before_mutation &&
        installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.all_required_authority_refusals_before_consumption_and_mutation
      ) ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_all_required_refusals_before_mutation !== true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_current_machine_governance_proven !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.current_machine_governance_proven ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_current_machine_governance_proven !== false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_production_downstream_recognition !==
      installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.production_downstream_recognition ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_production_downstream_recognition !== false
  ) {
    throw new Error('Proof smoke installed runtime profile terminal chain artifact verification count drifted');
  }
  const terminalChainArtifactDeploymentProfileAuthorityMirror =
    installedRuntimeProfileTerminalChainArtifactVerificationStep.verification.deployment_profile_authority_refusal_mirror;
  if (
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_preserved !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_preserved !==
      deploymentProfileAuthorityRefusalMirrorPreserved(terminalChainArtifactDeploymentProfileAuthorityMirror) ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_profile_sha_matches !==
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_profile_sha_matches ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_profile_sha_matches !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count !==
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count !==
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length ||
    JSON.stringify(report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids) !==
      JSON.stringify(report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids) ||
    JSON.stringify(report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids) !==
      JSON.stringify(REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES) ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof !==
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation !==
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started !==
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_stale_deployment_profile_artifact_refused_before_service_proof !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_profile_recognition_mismatch_refused_before_service_proof !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_latest_profile_selection_refused_before_service_proof !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_request_stream_authority_material_refused_before_service_proof !==
      true ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_current_machine_governance !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_downstream_recognition !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_authority !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_enterprise_readiness !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_external_attestation !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_sovereign_recognition !==
      false ||
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_unrouted_surface_coverage !==
      false
  ) {
    throw new Error('Proof smoke installed runtime profile terminal chain artifact verification deployment-profile authority refusal mirror count drifted');
  }
  if (report.counts.governed_lanes !== coverageStep.coverage_map.counts.governed_lanes) {
    throw new Error('Proof smoke governed lane count drifted');
  }
  if (report.counts.counted_lanes !== coverageStep.coverage_map.counts.counted_lanes) {
    throw new Error('Proof smoke counted lane count drifted');
  }
  if (report.counts.boundary_entries !== coverageStep.coverage_map.counts.boundary_entries) {
    throw new Error('Proof smoke boundary count drifted');
  }
  if (report.counts.governed_lanes !== report.counts.counted_lanes || report.counts.counted_lanes < 1) {
    throw new Error('Proof smoke coverage step is not all governed');
  }

  assertNonClaims(report.non_claims);
  assertNoUnsafeProofSmokeReportText(report);
  return true;
}

export function parseProofSmokeReportText(text) {
  assertNoUnsafeProofSmokeReportText(text);
  let report;
  try {
    report = JSON.parse(text);
  } catch {
    throw new Error('Proof smoke report input is not valid JSON');
  }
  assertProofSmokeReport(report);
  return report;
}

export function assertNoUnsafeProofSmokeReportText(value) {
  assertNoUnsafeLocalProofPackText(value);
  return true;
}
