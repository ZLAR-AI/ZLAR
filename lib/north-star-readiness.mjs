import {
  assertVerifierKitPublicDistributionReport,
} from './verifier-kit-public-distribution.mjs';
import {
  assertVerifierKitReleaseAssetsLiveReadReport,
} from './verifier-kit-release-assets-live-read.mjs';
import {
  PUBLIC_ARTIFACT_VERIFIER_RESULT_VERIFICATION_TYPE,
} from './public-artifact-verifier-result.mjs';
import {
  PUBLIC_EXTERNAL_ATTESTATION_RESULT_VERIFICATION_TYPE,
} from './public-external-attestation-result.mjs';
import {
  PRIVATE_VERIFIER_ZIP_EVIDENCE_MODEL,
  PRIVATE_VERIFIER_ZIP_RESULT_VERIFICATION_TYPE,
  PRIVATE_VERIFIER_ZIP_SOURCE_ROUTE,
} from './private-verifier-zip-result.mjs';
import { canonicalize } from './canonicalize.mjs';
import {
  REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
} from './protected-records-installed-runtime-profile-preflight.mjs';
import {
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProof,
} from './protected-records-installed-runtime-profile-recognition-proof.mjs';
import {
  REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES,
  assertProtectedRecordsInstalledRuntimeProfileServiceProof,
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification,
  protectedRecordsInstalledRuntimeProfileServiceProofArtifactBodySha256,
} from './protected-records-installed-runtime-profile-service-proof.mjs';
import {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChain,
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact,
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_OPEN_BOUNDARIES,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS,
  TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_FALSE_BOUNDARY_FIELDS,
} from './protected-records-installed-runtime-profile-terminal-chain.mjs';
import {
  TRUSTED_RECEIPT_ISSUER_COMPLETION_AUTHORITY_PRIMITIVE,
  TRUSTED_RECEIPT_ISSUER_COMPLETION_CORE_SENTENCE,
  TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF_TYPE,
  TRUSTED_RECEIPT_ISSUER_COMPLETION_SURFACE_ID,
  TRUSTED_RECEIPT_ISSUER_COMPLETION_VERIFICATION_TYPE,
  buildTrustedReceiptIssuerCompletionVerification,
  isTrustedReceiptIssuerCompletionSurfaceId,
  readinessSummaryFromTrustedReceiptIssuerCompletionVerification,
} from './trusted-receipt-issuer-completion-proof.mjs';
import {
  PRODUCT_PROOF_PATH_EVIDENCE_MODEL,
  PRODUCT_PROOF_PATH_REPORT_TYPE,
  assertProductProofPathReport,
  historicalProductProofPathClaudeHookReplaySummary,
} from './product-proof-path.mjs';
import {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed,
} from './protected-records-fixture-authority-status.mjs';
import {
  PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_REPORT_TYPE,
  assertActivePersistentProfileLifecycleReport,
} from './protected-records-active-persistent-profile-lifecycle.mjs';
import {
  REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES,
} from './protected-records-one-terminal-deployment-profile.mjs';
import {
  REQUIRED_REFUSAL_REASONS as DOWNSTREAM_REFUSAL_REASONS,
} from './downstream-refusal-proof.mjs';
import { sha256hex } from './receipt.mjs';

export const NORTH_STAR_READINESS_REPORT_TYPE = 'zlar-north-star-readiness-v1';
export const NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE = 'committed-local-fixtures';
export const NORTH_STAR_READINESS_EVIDENCE_MODEL_RELEASE_FORWARD =
  'release-forward-dry-run-artifacts';
export const NORTH_STAR_READINESS_RESULT_NOT_READY = 'NOT_READY_FOR_V3_4_0';
export const NORTH_STAR_READINESS_RESULT_READY_PUBLIC_DISTRIBUTION =
  'READY_FOR_V3_4_0_PUBLIC_VERIFIER_KIT_DISTRIBUTION';
const PRIVATE_VERIFIER_RESULT_VERIFICATION_TYPE =
  'zlar-private-verifier-result-verification-v1';
const EXACT_RUNTIME_MUTATION_AUTHORITATIVE_ROUTE =
  'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation';

let expectedProductProofPathClaudeHookReplaySummaryCache = null;

export const NORTH_STAR_READINESS_NON_CLAIMS = Object.freeze([
  'This report does not prove v3.4.0 readiness.',
  'This report does not prove external attestation or non-operator review.',
  'This report does not prove production authority, enterprise readiness, or sovereign recognition.',
  'This report does not prove current-machine governance, live hook state, live MCP coverage, or live approval-channel health.',
  'This report does not prove live trust-registry state, key custody, revocation truth, or production downstream recognition.',
  'This report does not prove persistent runtime profile installation, production service deployment, or coverage of unrouted surfaces.',
]);
export const NORTH_STAR_READINESS_PUBLIC_DISTRIBUTION_NON_CLAIMS = Object.freeze([
  'This report proves v3.4.0 readiness only for a boundary release through public verifier-kit distribution posture.',
  'This report does not prove external attestation or non-operator review.',
  'This report does not prove production authority, enterprise readiness, or sovereign recognition.',
  'This report does not prove current-machine governance, live hook state, live MCP coverage, or live approval-channel health.',
  'This report does not prove live trust-registry state, key custody, revocation truth, or production downstream recognition.',
  'This report does not prove persistent runtime profile installation, production service deployment, or coverage of unrouted surfaces.',
]);
export const NORTH_STAR_READINESS_PRIVATE_VERIFIER_NON_CLAIMS = Object.freeze([
  'This report records private non-operator verifier result validation only; it does not prove public external attestation, public attribution, or signed/published attestation.',
  'This report does not prove v3.4.0 readiness, production authority, enterprise readiness, or sovereign recognition.',
  'This report does not prove current-machine governance, live hook state, live MCP coverage, or live approval-channel health.',
  'This report does not prove live trust-registry state, key custody, revocation truth, or production downstream recognition.',
  'This report does not prove persistent runtime profile installation, production service deployment, or coverage of unrouted surfaces.',
]);
export const NORTH_STAR_READINESS_PRIVATE_ZIP_VERIFIER_NON_CLAIMS = Object.freeze([
  'This report records private personally connected outside-machine ZIP verifier result validation only; it does not prove public external attestation, independent review, public attribution, or signed/published attestation.',
  'This report does not prove v3.4.0 readiness, production authority, enterprise readiness, or sovereign recognition.',
  'This report does not prove current-machine governance, live hook state, live MCP coverage, or live approval-channel health.',
  'This report does not prove live trust-registry state, key custody, revocation truth, or production downstream recognition.',
  'This report does not prove persistent runtime profile installation, production service deployment, or coverage of unrouted surfaces.',
]);
export const NORTH_STAR_READINESS_PUBLIC_DISTRIBUTION_PRIVATE_VERIFIER_NON_CLAIMS = Object.freeze([
  'This report proves v3.4.0 readiness only for a boundary release through public verifier-kit distribution posture.',
  'This report records private non-operator verifier result validation only; it does not prove public external attestation, public attribution, or signed/published attestation.',
  'This report does not prove production authority, enterprise readiness, or sovereign recognition.',
  'This report does not prove current-machine governance, live hook state, live MCP coverage, or live approval-channel health.',
  'This report does not prove live trust-registry state, key custody, revocation truth, or production downstream recognition.',
  'This report does not prove persistent runtime profile installation, production service deployment, or coverage of unrouted surfaces.',
]);
export const NORTH_STAR_READINESS_PUBLIC_DISTRIBUTION_PRIVATE_ZIP_VERIFIER_NON_CLAIMS = Object.freeze([
  'This report proves v3.4.0 readiness only for a boundary release through public verifier-kit distribution posture.',
  'This report records private personally connected outside-machine ZIP verifier result validation only; it does not prove public external attestation, independent review, public attribution, or signed/published attestation.',
  'This report does not prove production authority, enterprise readiness, or sovereign recognition.',
  'This report does not prove current-machine governance, live hook state, live MCP coverage, or live approval-channel health.',
  'This report does not prove live trust-registry state, key custody, revocation truth, or production downstream recognition.',
  'This report does not prove persistent runtime profile installation, production service deployment, or coverage of unrouted surfaces.',
]);

const NORTH_STAR_READINESS_CLAIM_BOUNDARY_KEYS = Object.freeze([
  'all_mcp_governance',
  'current_machine_governance',
  'enterprise_readiness',
  'key_custody',
  'live_approval_channel_health',
  'live_hook_state',
  'live_mcp_coverage',
  'live_trust_registry_state',
  'non_operator_review_proven',
  'persistent_runtime_profile_installation',
  'production_authority',
  'production_downstream_recognition',
  'production_service_deployment',
  'public_external_attestation',
  'revocation_truth',
  'sovereign_recognition',
  'unrouted_surface_coverage',
  'v3_4_0_ready',
]);

const REQUIRED_NON_CLAIM_FRAGMENTS = Object.freeze([
  'v3.4.0 readiness',
  'external attestation',
  'production authority',
  'current-machine governance',
  'live MCP coverage',
  'key custody',
  'coverage of unrouted surfaces',
]);

const RUNTIME_PROFILE_IDENTITY_POLICY_SUMMARY_KEYS = Object.freeze([
  'authority_source',
  'omitted_request_runtime_profile_id_present',
  'omitted_runtime_profile_id_uses_launcher_config',
  'request_runtime_profile_id_required',
  'request_stream_policy',
  'runtime_local_activation_summary_bound',
  'runtime_profile_installation_summary_bound',
  'summaries_match',
  'supplied_mismatched_runtime_profile_id_refused',
]);

const EXPECTED_RUNTIME_PROFILE_IDENTITY_POLICY = Object.freeze({
  authority_source: 'launcher-owned-service-config',
  request_stream_policy:
    'runtime_profile_id_may_be_omitted_but_if_supplied_must_match_config',
  request_runtime_profile_id_required: false,
  omitted_request_runtime_profile_id_present: false,
  omitted_runtime_profile_id_uses_launcher_config: true,
  supplied_mismatched_runtime_profile_id_refused: true,
  runtime_local_activation_summary_bound: true,
  runtime_profile_installation_summary_bound: true,
  summaries_match: true,
});

const DOWNSTREAM_REFUSAL_BOUNDARY_SUMMARY_KEYS = Object.freeze([
  'all_refusal_marker_count_deltas_zero',
  'all_refusals_unboarded',
  'final_marker_count',
  'provided',
  'recognized_boarded',
  'recognized_marker_count_delta',
  'refusal_case_count',
  'refusal_reasons',
]);

const PRODUCT_PROOF_PATH_RECOGNIZED_RECEIPT_PATH_MIRROR_KEYS = Object.freeze([
  'recognized_receipt_path_evidence_artifact_crypto_reproducible',
  'recognized_receipt_path_evidence_artifact_verification_sha256',
  'recognized_receipt_path_evidence_bound_to_artifact_body',
  'recognized_receipt_path_evidence_current_machine_governance_proven',
  'recognized_receipt_path_evidence_key_custody_proven',
  'recognized_receipt_path_evidence_live_issuer_status_proven',
  'recognized_receipt_path_evidence_live_state_proven',
  'recognized_receipt_path_evidence_production_downstream_recognition_proven',
  'recognized_receipt_path_evidence_public_external_attestation',
  'recognized_receipt_path_evidence_receipt_envelope_included',
  'recognized_receipt_path_evidence_recognized',
  'recognized_receipt_path_evidence_registry_public_key_material_included',
  'recognized_receipt_path_evidence_revocation_truth_proven',
  'recognized_receipt_path_evidence_sha256',
  'recognized_receipt_path_evidence_sha256_matches_artifact_verification',
  'recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding',
  'recognized_receipt_path_evidence_source_binding_sha256',
  'recognized_receipt_path_evidence_sovereign_recognition',
  'recognized_receipt_path_evidence_verdict',
]);

const PRODUCT_PROOF_PATH_CLAUDE_HOOK_CONTRACT_REPLAY_SUMMARY_KEYS = Object.freeze([
  'adapter_sha256',
  'case_evidence_hash_scope',
  'case_evidence_sha256',
  'component_sha256',
  'hook_replay_contract_sha256',
  'provided',
  'source_state_boundary',
]);

const HISTORICAL_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_EVIDENCE_CLASS =
  'historical_supplied_local_active_persistent_profile_lifecycle';

const HISTORICAL_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SOURCE_REPORT_KEYS =
  Object.freeze([
    'closeout_report_sha256',
    'green_report_sha256',
    'install_report_sha256',
    'red_report_sha256',
  ]);

const HISTORICAL_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_LABEL_KEYS =
  Object.freeze([
    'closeout_report',
    'green_report',
    'install_report',
    'red_report',
  ]);

const HISTORICAL_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_FALSE_KEYS =
  Object.freeze([
    'current_installation',
    'current_machine_governance_general',
    'does_not_complete_enterprise_deployment_profile',
    'does_not_complete_product_proof_path',
    'production_downstream_recognition',
    'public_external_attestation',
    'side_door_closure',
  ]);

const HISTORICAL_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SUMMARY_KEYS =
  Object.freeze([
    'binding_manifest_sha256',
    'claim_boundary',
    'closeout_status',
    'current_installation',
    'current_machine_governance_general',
    'does_not_complete_enterprise_deployment_profile',
    'does_not_complete_product_proof_path',
    'evidence_class',
    'expected_input_report_hashes_bound',
    'green_recognized_write_delta',
    'lifecycle_report_sha256',
    'non_scoring',
    'production_downstream_recognition',
    'provided',
    'public_external_attestation',
    'red_refusal_case_count',
    'refused_after_closeout_target_written',
    'report_type',
    'selected_profile_id',
    'selected_profile_sha256',
    'selects_latest_profile',
    'side_door_closure',
    'source_report_hashes',
    'source_report_labels',
    'status_label',
    'verified',
  ]);

const TERMINAL_CHAIN_RECOGNIZED_RECEIPT_PATH_FALSE_BOUNDARY_FIELDS =
  Object.freeze([
    'receipt_envelope_included',
    'registry_public_key_material_included',
    'cryptographic_evidence_reproducible_from_artifact',
    'live_trust_registry_state',
    'live_issuer_status_proven',
    'key_custody_proven',
    'revocation_truth_proven',
    'production_downstream_recognition_proven',
    'public_external_attestation',
    'sovereign_recognition',
    'current_machine_governance_proven',
  ]);

const TERMINAL_CHAIN_RECOGNIZED_RECEIPT_PATH_MIRROR_COUNT_KEYS =
  Object.freeze([
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_mirror_required',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_mirror_preserved',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_sha256',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_bound_to_artifact_body',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_sha256',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_matches_trusted_registry_binding',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_matches_trusted_registry_binding',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_verdict',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_verdict',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_recognized',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_recognized',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_receipt_envelope_included',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_receipt_envelope_included',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_registry_public_key_material_included',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_registry_public_key_material_included',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_artifact_crypto_reproducible',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_artifact_crypto_reproducible',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_live_state_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_live_state_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_live_issuer_status_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_live_issuer_status_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_key_custody_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_key_custody_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_revocation_truth_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_revocation_truth_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_production_downstream_recognition_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_production_downstream_recognition_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_public_external_attestation',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_public_external_attestation',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_sovereign_recognition',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_sovereign_recognition',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_current_machine_governance_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_current_machine_governance_proven',
  ]);

function absentDownstreamRefusalBoundarySummary() {
  return {
    provided: false,
    recognized_boarded: false,
    recognized_marker_count_delta: 0,
    final_marker_count: 0,
    refusal_case_count: 0,
    all_refusals_unboarded: false,
    all_refusal_marker_count_deltas_zero: false,
    refusal_reasons: [],
  };
}

function productProofPathDownstreamRefusalBoundarySummary(report) {
  const allowPath = report?.observed?.allow_path || {};
  const refusalPath = report?.observed?.refusal_path || {};
  return {
    provided: true,
    recognized_boarded: allowPath.downstream_recognized_boarded === true,
    recognized_marker_count_delta:
      allowPath.downstream_recognized_marker_count_delta ?? 0,
    final_marker_count: allowPath.downstream_final_marker_count ?? 0,
    refusal_case_count: refusalPath.downstream_refusal_case_count ?? 0,
    all_refusals_unboarded:
      refusalPath.downstream_all_refusals_unboarded === true,
    all_refusal_marker_count_deltas_zero:
      refusalPath.downstream_all_refusal_marker_count_deltas_zero === true,
    refusal_reasons: Array.isArray(refusalPath.downstream_refusal_reasons)
      ? [...refusalPath.downstream_refusal_reasons]
      : [],
  };
}

function productProofPathDownstreamRefusalBoundaryPasses(summary) {
  if (!isObject(summary)) {
    return false;
  }
  const actualKeys = Object.keys(summary).sort();
  const expectedKeys = [...DOWNSTREAM_REFUSAL_BOUNDARY_SUMMARY_KEYS].sort();
  return (
    actualKeys.length === expectedKeys.length &&
    actualKeys.every((key, index) => key === expectedKeys[index]) &&
    summary.provided === true &&
    summary.recognized_boarded === true &&
    summary.recognized_marker_count_delta === 1 &&
    summary.final_marker_count === 1 &&
    summary.refusal_case_count === DOWNSTREAM_REFUSAL_REASONS.length &&
    summary.all_refusals_unboarded === true &&
    summary.all_refusal_marker_count_deltas_zero === true &&
    downstreamRefusalReasonsPreserved(summary.refusal_reasons)
  );
}

function absentProductProofPathClaudeHookReplaySummary() {
  return {
    provided: false,
    hook_replay_contract_sha256: 'not-provided',
    adapter_sha256: 'not-provided',
    component_sha256: 'not-provided',
    case_evidence_hash_scope: 'not-provided',
    case_evidence_sha256: 'not-provided',
    source_state_boundary: 'not-provided',
  };
}

function productProofPathClaudeHookReplaySummary(summary) {
  if (!summary) {
    return absentProductProofPathClaudeHookReplaySummary();
  }
  return {
    provided: true,
    hook_replay_contract_sha256:
      summary.hook_replay_contract_sha256 || 'not-provided',
    adapter_sha256: summary.adapter_sha256 || 'not-provided',
    component_sha256: summary.component_sha256 || 'not-provided',
    case_evidence_hash_scope:
      summary.case_evidence_hash_scope || 'not-provided',
    case_evidence_sha256: summary.case_evidence_sha256 || 'not-provided',
    source_state_boundary: summary.source_state_boundary || 'not-provided',
  };
}

function productProofPathClaudeHookReplaySummaryPasses(summary) {
  if (!isObject(summary)) {
    return false;
  }
  const actualKeys = Object.keys(summary).sort();
  const expectedKeys = [
    ...PRODUCT_PROOF_PATH_CLAUDE_HOOK_CONTRACT_REPLAY_SUMMARY_KEYS,
  ].sort();
  const expected = expectedProductProofPathClaudeHookReplaySummary();
  return (
    actualKeys.length === expectedKeys.length &&
    actualKeys.every((key, index) => key === expectedKeys[index]) &&
    summary.provided === true &&
    isSha256Hex(summary.hook_replay_contract_sha256) &&
    isSha256Hex(summary.adapter_sha256) &&
    isSha256Hex(summary.component_sha256) &&
    isSha256Hex(summary.case_evidence_sha256) &&
    summary.hook_replay_contract_sha256 ===
      expected.hook_replay_contract_sha256 &&
    summary.adapter_sha256 === expected.adapter_sha256 &&
    summary.component_sha256 === expected.component_sha256 &&
    summary.case_evidence_hash_scope === expected.case_evidence_hash_scope &&
    summary.case_evidence_sha256 === expected.case_evidence_sha256 &&
    summary.source_state_boundary === expected.source_state_boundary
  );
}

function absentHistoricalActivePersistentProfileLifecycleSummary() {
  return {
    provided: false,
    verified: false,
    evidence_class:
      HISTORICAL_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_EVIDENCE_CLASS,
    status_label: 'not-provided',
    report_type: 'not-provided',
    selected_profile_id: 'not-provided',
    selected_profile_sha256: 'not-provided',
    selects_latest_profile: false,
    expected_input_report_hashes_bound: false,
    lifecycle_report_sha256: 'not-provided',
    binding_manifest_sha256: 'not-provided',
    source_report_hashes: {
      install_report_sha256: 'not-provided',
      green_report_sha256: 'not-provided',
      red_report_sha256: 'not-provided',
      closeout_report_sha256: 'not-provided',
    },
    source_report_labels: {
      install_report: 'not-provided',
      green_report: 'not-provided',
      red_report: 'not-provided',
      closeout_report: 'not-provided',
    },
    green_recognized_write_delta: 0,
    red_refusal_case_count: 0,
    closeout_status: 'not-provided',
    refused_after_closeout_target_written: false,
    non_scoring: false,
    does_not_complete_product_proof_path: false,
    does_not_complete_enterprise_deployment_profile: false,
    current_installation: false,
    current_machine_governance_general: false,
    production_downstream_recognition: false,
    public_external_attestation: false,
    side_door_closure: false,
    claim_boundary:
      'historical supplied local active-persistent-profile lifecycle evidence was not supplied',
  };
}

function assertBasenameLabel(label, value) {
  if (typeof value !== 'string' || value.length < 1) {
    throw new Error(`${label} must be a non-empty basename`);
  }
  if (value.includes('/') || value.includes('\\')) {
    throw new Error(`${label} must not contain a path separator`);
  }
  assertNoUnsafeNorthStarReadinessText(value);
}

function historicalActivePersistentProfileLifecycleSummary(input) {
  if (!input) {
    return absentHistoricalActivePersistentProfileLifecycleSummary();
  }
  exactKeys('historical active persistent lifecycle evidence input', input, [
    'binding_manifest_sha256',
    'lifecycle_report_sha256',
    'report',
    'source_report_hashes',
  ]);
  if (!isSha256Hex(input.lifecycle_report_sha256)) {
    throw new Error('historical active persistent lifecycle report hash drifted');
  }
  if (!isSha256Hex(input.binding_manifest_sha256)) {
    throw new Error('historical active persistent lifecycle binding manifest hash drifted');
  }
  assertActivePersistentProfileLifecycleReport(input.report);
  const boundary = input.report.claim_boundary || {};
  if (boundary.expected_input_report_hashes_bound !== true) {
    throw new Error('historical active persistent lifecycle evidence must bind expected input report hashes');
  }
  exactKeys(
    'historical active persistent lifecycle source report hashes',
    input.source_report_hashes,
    HISTORICAL_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SOURCE_REPORT_KEYS,
  );
  const reportHashes = input.report.supplied_reports?.hashes || {};
  for (const key of HISTORICAL_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SOURCE_REPORT_KEYS) {
    if (!isSha256Hex(input.source_report_hashes[key])) {
      throw new Error(`historical active persistent lifecycle ${key} hash drifted`);
    }
    if (input.source_report_hashes[key] !== reportHashes[key]) {
      throw new Error(`historical active persistent lifecycle ${key} does not match lifecycle report`);
    }
  }
  const labels = input.report.supplied_reports?.labels || {};
  exactKeys(
    'historical active persistent lifecycle source report labels',
    labels,
    HISTORICAL_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_LABEL_KEYS,
  );
  for (const key of HISTORICAL_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_LABEL_KEYS) {
    assertBasenameLabel(`historical active persistent lifecycle ${key} label`, labels[key]);
  }
  const lifecycle = input.report.lifecycle || {};
  const selected = input.report.selected_profile || {};
  return {
    provided: true,
    verified: true,
    evidence_class:
      HISTORICAL_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_EVIDENCE_CLASS,
    status_label: 'historical-supplied-local-non-scoring',
    report_type: input.report.report_type,
    selected_profile_id: selected.profile_id,
    selected_profile_sha256: selected.runtime_profile_sha256,
    selects_latest_profile: selected.selects_latest_profile === true,
    expected_input_report_hashes_bound: true,
    lifecycle_report_sha256: input.lifecycle_report_sha256,
    binding_manifest_sha256: input.binding_manifest_sha256,
    source_report_hashes: {
      install_report_sha256: input.source_report_hashes.install_report_sha256,
      green_report_sha256: input.source_report_hashes.green_report_sha256,
      red_report_sha256: input.source_report_hashes.red_report_sha256,
      closeout_report_sha256: input.source_report_hashes.closeout_report_sha256,
    },
    source_report_labels: {
      install_report: labels.install_report,
      green_report: labels.green_report,
      red_report: labels.red_report,
      closeout_report: labels.closeout_report,
    },
    green_recognized_write_delta: lifecycle.green_recognized_write_delta,
    red_refusal_case_count: lifecycle.red_refusal_case_count,
    closeout_status: lifecycle.closeout_status,
    refused_after_closeout_target_written:
      lifecycle.refused_after_closeout_target_written === true,
    non_scoring: true,
    does_not_complete_product_proof_path: true,
    does_not_complete_enterprise_deployment_profile: true,
    current_installation: false,
    current_machine_governance_general:
      boundary.current_machine_governance_general === true,
    production_downstream_recognition:
      boundary.production_downstream_recognition === true,
    public_external_attestation:
      boundary.public_external_attestation === true,
    side_door_closure: boundary.side_door_closure === true,
    claim_boundary:
      'historical supplied local lifecycle evidence only; non-scoring and not current installation, Product Proof Path completion, Enterprise Deployment Profile completion, production recognition, or current-machine governance',
  };
}

function assertHistoricalActivePersistentProfileLifecycleSummary(label, summary) {
  exactKeys(label, summary, HISTORICAL_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SUMMARY_KEYS);
  if (summary.evidence_class !== HISTORICAL_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_EVIDENCE_CLASS) {
    throw new Error(`${label} evidence class drifted`);
  }
  exactKeys(
    `${label} source report hashes`,
    summary.source_report_hashes,
    HISTORICAL_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SOURCE_REPORT_KEYS,
  );
  exactKeys(
    `${label} source report labels`,
    summary.source_report_labels,
    HISTORICAL_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_LABEL_KEYS,
  );
  for (const value of Object.values(summary.source_report_labels)) {
    if (value !== 'not-provided') {
      assertBasenameLabel(`${label} source report label`, value);
    }
  }
  if (summary.provided !== true) {
    if (
      summary.verified !== false ||
      summary.status_label !== 'not-provided' ||
      summary.report_type !== 'not-provided' ||
      summary.selected_profile_id !== 'not-provided' ||
      summary.selected_profile_sha256 !== 'not-provided' ||
      summary.expected_input_report_hashes_bound !== false ||
      summary.lifecycle_report_sha256 !== 'not-provided' ||
      summary.binding_manifest_sha256 !== 'not-provided'
    ) {
      throw new Error(`${label} absent summary drifted`);
    }
    return true;
  }
  if (
    summary.verified !== true ||
    summary.status_label !== 'historical-supplied-local-non-scoring' ||
    summary.report_type !== PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_REPORT_TYPE ||
    summary.selected_profile_id !== 'protected-records-runtime-fixture-profile' ||
    !isSha256Hex(summary.selected_profile_sha256) ||
    summary.selects_latest_profile !== false ||
    summary.expected_input_report_hashes_bound !== true ||
    !isSha256Hex(summary.lifecycle_report_sha256) ||
    !isSha256Hex(summary.binding_manifest_sha256) ||
    summary.green_recognized_write_delta !== 1 ||
    summary.red_refusal_case_count !== 18 ||
    summary.closeout_status !== 'closed_inert_evidence' ||
    summary.refused_after_closeout_target_written !== false ||
    summary.non_scoring !== true ||
    HISTORICAL_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_FALSE_KEYS.some((key) =>
      summary[key] !== false && !key.startsWith('does_not_complete')
    ) ||
    summary.does_not_complete_product_proof_path !== true ||
    summary.does_not_complete_enterprise_deployment_profile !== true
  ) {
    throw new Error(`${label} verified summary drifted`);
  }
  for (const key of HISTORICAL_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SOURCE_REPORT_KEYS) {
    if (!isSha256Hex(summary.source_report_hashes[key])) {
      throw new Error(`${label} ${key} drifted`);
    }
  }
  return true;
}

function expectedProductProofPathClaudeHookReplaySummary() {
  if (!expectedProductProofPathClaudeHookReplaySummaryCache) {
    expectedProductProofPathClaudeHookReplaySummaryCache =
      productProofPathClaudeHookReplaySummary(
        historicalProductProofPathClaudeHookReplaySummary(),
      );
  }
  return expectedProductProofPathClaudeHookReplaySummaryCache;
}

function productProofPathRecognizedReceiptPathMirrorPasses(boundary, required) {
  const present = hasAnyOwnKey(
    boundary,
    PRODUCT_PROOF_PATH_RECOGNIZED_RECEIPT_PATH_MIRROR_KEYS,
  );
  if (!required && !present) {
    return true;
  }
  return (
    isObject(boundary) &&
    isSha256Hex(boundary.recognized_receipt_path_evidence_sha256) &&
    isSha256Hex(
      boundary.recognized_receipt_path_evidence_artifact_verification_sha256,
    ) &&
    boundary.recognized_receipt_path_evidence_sha256 ===
      boundary.recognized_receipt_path_evidence_artifact_verification_sha256 &&
    boundary.recognized_receipt_path_evidence_sha256_matches_artifact_verification ===
      true &&
    boundary.recognized_receipt_path_evidence_bound_to_artifact_body === true &&
    boundary.recognized_receipt_path_evidence_source_binding_sha256 ===
      boundary.trusted_issuer_registry_recognition_binding_sha256 &&
    boundary.recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding ===
      true &&
    boundary.recognized_receipt_path_evidence_verdict === 'RECOGNIZED' &&
    boundary.recognized_receipt_path_evidence_recognized === true &&
    boundary.recognized_receipt_path_evidence_receipt_envelope_included ===
      false &&
    boundary
      .recognized_receipt_path_evidence_registry_public_key_material_included ===
      false &&
    boundary.recognized_receipt_path_evidence_artifact_crypto_reproducible ===
      false &&
    boundary.recognized_receipt_path_evidence_live_state_proven === false &&
    boundary.recognized_receipt_path_evidence_live_issuer_status_proven ===
      false &&
    boundary.recognized_receipt_path_evidence_key_custody_proven === false &&
    boundary.recognized_receipt_path_evidence_revocation_truth_proven === false &&
    boundary
      .recognized_receipt_path_evidence_production_downstream_recognition_proven ===
      false &&
    boundary.recognized_receipt_path_evidence_public_external_attestation ===
      false &&
    boundary.recognized_receipt_path_evidence_sovereign_recognition === false &&
    boundary
      .recognized_receipt_path_evidence_current_machine_governance_proven ===
      false
  );
}

function downstreamRefusalReasonsPreserved(value) {
  return (
    Array.isArray(value) &&
    value.length === DOWNSTREAM_REFUSAL_REASONS.length &&
    value.every((reason, index) => reason === DOWNSTREAM_REFUSAL_REASONS[index])
  );
}

function terminalChainNamedReceiptRefusalsSummary(value) {
  return Object.fromEntries(
    Object.keys(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS)
      .map((name) => {
        const refusal = value?.[name] || {};
        return [
          name,
          {
            case_id: refusal.case_id || 'not-provided',
            reason_code: refusal.reason_code || 'not-provided',
            refused_before_mutation:
              refusal.refused_before_mutation === true,
          },
        ];
      }),
  );
}

function terminalChainNamedReceiptRefusalsSummaryPasses(value) {
  if (!isObject(value)) {
    return false;
  }
  const actualKeys = Object.keys(value).sort();
  const expectedKeys = Object.keys(
    REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS,
  ).sort();
  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    return false;
  }
  return Object.entries(
    REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS,
  ).every(([name, expected]) => {
    const refusal = value[name];
    return (
      isObject(refusal) &&
      Object.keys(refusal).sort().join(',') ===
        'case_id,reason_code,refused_before_mutation' &&
      refusal.case_id === expected.case_id &&
      refusal.reason_code === expected.reason_code &&
      refusal.refused_before_mutation === true
    );
  });
}

function terminalChainNamedReceiptRefusalsSha256(value) {
  return sha256hex(canonicalize({ named_receipt_refusals: value }));
}

const UNSAFE_OUTPUT_PATTERNS = Object.freeze([
  { label: 'private operator path', pattern: /\/Users\/[^\s"'`]+/ },
  { label: 'home path', pattern: /\/home\/[^\s"'`]+/ },
  { label: 'private path', pattern: /\/private\/[^\s"'`]+/ },
  { label: 'temp path', pattern: /\/tmp\/[^\s"'`]+/ },
  { label: 'var path', pattern: /\/var\/[^\s"'`]+/ },
  { label: 'numeric human identifier', pattern: /\bhuman:[0-9]/ },
  { label: 'chat id field', pattern: /\bchat_id\b/i },
  { label: 'private key material', pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
  { label: 'public key material', pattern: /BEGIN PUBLIC KEY/ },
  {
    label: 'key-value credential',
    pattern: /\b(?:token|secret|password|api[_-]?key)\s*[:=]\s*[^&\s"'`,;})\]]+/i,
  },
  {
    label: 'authorization credential',
    pattern: /\bauthorization\s*[:=]\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}/i,
  },
  { label: 'GitHub token', pattern: /\bghp_[A-Za-z0-9_]{10,}\b/ },
  { label: 'GitHub fine-grained token', pattern: /\bgithub_pat_[A-Za-z0-9_]{10,}\b/ },
  { label: 'OpenAI-style key', pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/ },
  { label: 'bot token', pattern: /\bbot[0-9]{6,}:[A-Za-z0-9_-]{6,}\b/ },
]);

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(label, value, expectedKeys) {
  if (!isObject(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains unexpected fields`);
  }
}

function bool(value) {
  return value === true;
}

function isSha256Hex(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

function runtimeProfileIdentityPolicySummary(policy) {
  return {
    authority_source: policy?.authority_source || 'not-provided',
    request_stream_policy: policy?.request_stream_policy || 'not-provided',
    request_runtime_profile_id_required:
      policy?.request_runtime_profile_id_required === true,
    omitted_request_runtime_profile_id_present:
      policy?.omitted_request_runtime_profile_id_present === true,
    omitted_runtime_profile_id_uses_launcher_config:
      policy?.omitted_runtime_profile_id_uses_launcher_config === true,
    supplied_mismatched_runtime_profile_id_refused:
      policy?.supplied_mismatched_runtime_profile_id_refused === true,
    runtime_local_activation_summary_bound:
      policy?.runtime_local_activation_summary_bound === true,
    runtime_profile_installation_summary_bound:
      policy?.runtime_profile_installation_summary_bound === true,
    summaries_match: policy?.summaries_match === true,
  };
}

function runtimeProfileIdentityPolicySummaryPasses(summary) {
  return (
    isObject(summary) &&
    RUNTIME_PROFILE_IDENTITY_POLICY_SUMMARY_KEYS.every((key) =>
      Object.hasOwn(summary, key)
    ) &&
    Object.entries(EXPECTED_RUNTIME_PROFILE_IDENTITY_POLICY).every(
      ([key, expected]) => summary[key] === expected
    )
  );
}

function assertRuntimeProfileIdentityPolicySummary(label, summary, required) {
  if (!required && !isObject(summary)) {
    return;
  }
  exactKeys(label, summary, RUNTIME_PROFILE_IDENTITY_POLICY_SUMMARY_KEYS);
  if (required && !runtimeProfileIdentityPolicySummaryPasses(summary)) {
    throw new Error(`${label} drifted`);
  }
}

function hasText(value) {
  return typeof value === 'string' && value.length > 0;
}

const INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NESTED_PREFLIGHT_ARTIFACT_TYPE =
  'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1';
const INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NESTED_SERVICE_PROOF_ARTIFACT_TYPE =
  'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1';

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

function expectedRecognitionRefusalGroupCaseIds() {
  return Object.fromEntries(
    Object.entries(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS)
      .map(([groupName, cases]) => [groupName, cases.map((item) => item.case_id)])
  );
}

function recognitionRefusalGroupCaseIdsMatch(value, groups) {
  return JSON.stringify(value) === JSON.stringify(recognitionRefusalGroupCaseIds(groups));
}

function expectedTrustedIssuerRegistryRecognitionRefusalCaseIds() {
  return REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS
    .map((item) => item.case_id);
}

function expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes() {
  return REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS
    .map((item) => item.reason_code);
}

function assertTerminalChainRecognitionRefusalGroupCaseIdsObservedSummary(label, observed, counts, required) {
  if (!required) {
    return;
  }
  if (!isObject(observed)) {
    throw new Error(`${label} must be reported`);
  }
  if (counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved !== true) {
    return;
  }
  const expectedFields = [
    [
      'installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved',
      counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved,
    ],
    [
      'installed_runtime_profile_terminal_chain_recognition_refusal_group_count',
      counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_count,
    ],
    [
      'installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count',
      counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count,
    ],
    [
      'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count',
      counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count,
    ],
    [
      'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count',
      counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count,
    ],
  ];
  const scalarDrifted = expectedFields.some(([field, expected]) => observed[field] !== expected);
  const caseIdsDrifted =
    JSON.stringify(observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids) !==
      JSON.stringify(counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids) ||
    JSON.stringify(
      observed.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids
    ) !==
      JSON.stringify(
        counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids
      );
  if (scalarDrifted || caseIdsDrifted) {
    throw new Error(`${label} recognition refusal group case IDs observed summary drifted`);
  }
}

function assertTerminalChainNestedArtifactBindingObservedSummary(label, observed, counts, required) {
  if (!required) {
    return;
  }
  if (!isObject(observed)) {
    throw new Error(`${label} must be reported`);
  }
  if (counts.installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved !== true) {
    return;
  }
  const expectedFields = [
    [
      'installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved',
      counts.installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved,
    ],
    [
      'installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved',
      counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved,
    ],
    [
      'installed_runtime_profile_terminal_chain_nested_preflight_artifact_type',
      counts.installed_runtime_profile_terminal_chain_nested_preflight_artifact_type,
    ],
    [
      'installed_runtime_profile_terminal_chain_nested_service_proof_artifact_type',
      counts.installed_runtime_profile_terminal_chain_nested_service_proof_artifact_type,
    ],
    [
      'installed_runtime_profile_terminal_chain_artifact_verification_nested_preflight_artifact_type',
      counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_preflight_artifact_type,
    ],
    [
      'installed_runtime_profile_terminal_chain_artifact_verification_nested_service_proof_artifact_type',
      counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_service_proof_artifact_type,
    ],
  ];
  if (expectedFields.some(([field, expected]) => observed[field] !== expected)) {
    throw new Error(`${label} nested artifact binding observed summary drifted`);
  }
}

function assertTerminalChainTrustedIssuerRegistryBindingObservedSummary(label, observed, counts, required) {
  if (!required) {
    return;
  }
  if (!isObject(observed)) {
    throw new Error(`${label} must be reported`);
  }
  if (counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved !== true) {
    return;
  }
  const expectedFields = [
    [
      'installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved',
      counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved,
    ],
    [
      'installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256',
      counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256,
    ],
    [
      'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256',
      counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256,
    ],
    [
      'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved',
      counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved,
    ],
    [
      'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count',
      counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count,
    ],
    [
      'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count',
      counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count,
    ],
    [
      'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused',
      counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused,
    ],
    [
      'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused',
      counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused,
    ],
    [
      'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256',
      counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256,
    ],
    [
      'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256',
      counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256,
    ],
  ];
  const refusalCaseListsDrifted =
    JSON.stringify(
      observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids
    ) !==
      JSON.stringify(
        counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids
      ) ||
    JSON.stringify(
      observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids
    ) !==
      JSON.stringify(
        counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids
      ) ||
    JSON.stringify(
      observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes
    ) !==
      JSON.stringify(
        counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes
      ) ||
    JSON.stringify(
      observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes
    ) !==
      JSON.stringify(
        counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes
      );
  const falseBoundaryFields = [
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_state_proven',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_issuer_status_proven',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_key_custody_proven',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_revocation_truth_proven',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_trust_registry_proven',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_downstream_recognition_proven',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_authority',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_sovereign_recognition',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_external_attestation',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_real_non_operator_review',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_current_machine_governance_proven',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_key_material_included',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_envelope_included',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_artifact_crypto_reproducible',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_state_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_issuer_status_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_key_custody_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_revocation_truth_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_trust_registry_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_downstream_recognition_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_authority',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_sovereign_recognition',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_external_attestation',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_real_non_operator_review',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_current_machine_governance_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_key_material_included',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_envelope_included',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_artifact_crypto_reproducible',
  ];
  const trueBoundaryFields = [
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_contract_hash_bound',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_contract_hash_bound',
  ];
  if (
    expectedFields.some(([field, expected]) => observed[field] !== expected) ||
    refusalCaseListsDrifted ||
    falseBoundaryFields.some((field) => observed[field] !== false) ||
    trueBoundaryFields.some((field) => observed[field] !== true)
  ) {
    throw new Error(`${label} trusted issuer registry binding observed summary drifted`);
  }
}

function assertTerminalChainRecognizedReceiptPathObservedSummary(label, observed, counts, required) {
  if (!required) {
    return;
  }
  if (!isObject(observed)) {
    throw new Error(`${label} must be reported`);
  }
  if (counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_mirror_preserved !== true) {
    return;
  }
  const expectedFields = [
    [
      'installed_runtime_profile_terminal_chain_recognized_receipt_path_mirror_preserved',
      counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_mirror_preserved,
    ],
    [
      'installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256',
      counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256,
    ],
    [
      'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_sha256',
      counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_sha256,
    ],
    [
      'installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_bound_to_artifact_body',
      counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_bound_to_artifact_body,
    ],
    [
      'installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256',
      counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256,
    ],
    [
      'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_sha256',
      counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_sha256,
    ],
    [
      'installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_matches_trusted_registry_binding',
      counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_matches_trusted_registry_binding,
    ],
    [
      'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_matches_trusted_registry_binding',
      counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_matches_trusted_registry_binding,
    ],
    [
      'installed_runtime_profile_terminal_chain_recognized_receipt_path_verdict',
      counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_verdict,
    ],
    [
      'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_verdict',
      counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_verdict,
    ],
    [
      'installed_runtime_profile_terminal_chain_recognized_receipt_path_recognized',
      counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_recognized,
    ],
    [
      'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_recognized',
      counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_recognized,
    ],
  ];
  const falseBoundaryFields = [
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_receipt_envelope_included',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_receipt_envelope_included',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_registry_public_key_material_included',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_registry_public_key_material_included',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_artifact_crypto_reproducible',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_artifact_crypto_reproducible',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_live_state_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_live_state_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_live_issuer_status_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_live_issuer_status_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_key_custody_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_key_custody_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_revocation_truth_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_revocation_truth_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_production_downstream_recognition_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_production_downstream_recognition_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_public_external_attestation',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_public_external_attestation',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_sovereign_recognition',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_sovereign_recognition',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_current_machine_governance_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_current_machine_governance_proven',
  ];
  if (
    expectedFields.some(([field, expected]) => observed[field] !== expected) ||
    falseBoundaryFields.some((field) => observed[field] !== false)
  ) {
    throw new Error(`${label} recognized receipt path observed summary drifted`);
  }
}

function terminalChainTrustedIssuerRegistryFalseBoundaryPreserved(value) {
  return TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_FALSE_BOUNDARY_FIELDS
    .every((field) => value?.[field] === false);
}

function terminalChainRecognizedReceiptPathFalseBoundaryPreserved(value) {
  return TERMINAL_CHAIN_RECOGNIZED_RECEIPT_PATH_FALSE_BOUNDARY_FIELDS
    .every((field) => value?.[field] === false);
}

function evidenceItem(component, command, result, scope) {
  return { component, command, result, scope };
}

function northStarReadinessNonClaims(
  v34Ready,
  privateVerifierResultValidated = false,
  privateVerifierZipResultValidated = false,
) {
  if (privateVerifierZipResultValidated) {
    return [
      ...(v34Ready
        ? NORTH_STAR_READINESS_PUBLIC_DISTRIBUTION_PRIVATE_ZIP_VERIFIER_NON_CLAIMS
        : NORTH_STAR_READINESS_PRIVATE_ZIP_VERIFIER_NON_CLAIMS),
    ];
  }
  if (v34Ready && privateVerifierResultValidated) {
    return [...NORTH_STAR_READINESS_PUBLIC_DISTRIBUTION_PRIVATE_VERIFIER_NON_CLAIMS];
  }
  if (privateVerifierResultValidated) {
    return [...NORTH_STAR_READINESS_PRIVATE_VERIFIER_NON_CLAIMS];
  }
  return [
    ...(v34Ready
      ? NORTH_STAR_READINESS_PUBLIC_DISTRIBUTION_NON_CLAIMS
      : NORTH_STAR_READINESS_NON_CLAIMS),
  ];
}

function optionalPrivateVerifierResultVerificationSummary(report, releaseForwardTargetTag = '') {
  if (!report) {
    return {
      provided: false,
      verification_type: 'not-provided',
      intake_class: 'not-provided',
      verdict: 'not-provided',
      release_tag: releaseForwardTargetTag || 'not-provided',
      commit_sha: 'not-provided',
      verified: false,
      completed_by_non_operator: false,
      private_by_default: false,
      evidence_dir_hash_verification: false,
      evidence_dir_contract_verification: false,
      evidence_dir_contract_verification_required: false,
      downstream_refusal_boundary_required: false,
      downstream_refusal_all_refusals_unboarded: false,
      downstream_refusal_reasons: [],
      north_star_downstream_refusal_all_refusals_unboarded: false,
      north_star_downstream_refusal_reasons: [],
      artifact_hash_count: 0,
      private_non_operator_pass_validated: false,
      public_external_attestation: false,
      public_attribution: false,
      non_operator_review_publicly_claimed: false,
      claim_boundary:
        'private verifier result verification JSON was not supplied to this report',
    };
  }
  if (!isObject(report)) {
    throw new Error('North Star private verifier result verification must be an object');
  }
  if (report.verification_type !== PRIVATE_VERIFIER_RESULT_VERIFICATION_TYPE) {
    throw new Error('North Star private verifier result verification type drifted');
  }
  if (releaseForwardTargetTag && report.release_tag !== releaseForwardTargetTag) {
    throw new Error('North Star private verifier result verification release tag mismatch');
  }
  if (report.public_external_attestation !== false) {
    throw new Error('North Star private verifier result verification must not claim public external attestation');
  }
  if (report.public_attribution !== false) {
    throw new Error('North Star private verifier result verification must not claim public attribution');
  }
  if (report.non_operator_review_publicly_claimed !== false) {
    throw new Error('North Star private verifier result verification must not claim public non-operator review');
  }
  const contractVerification = isObject(report.evidence_dir_contract_verification)
    ? report.evidence_dir_contract_verification
    : {};
  const contractVerificationRequired = contractVerification.required_for_target === true;
  const contractVerificationPassed = contractVerification.verified === true;
  const downstreamRefusalBoundaryRequired =
    contractVerification.downstream_refusal_boundary_required_for_target === true;
  const downstreamRefusalReasons = Array.isArray(
    contractVerification.downstream_refusal_reasons,
  )
    ? [...contractVerification.downstream_refusal_reasons]
    : [];
  const northStarDownstreamRefusalReasons = Array.isArray(
    contractVerification.north_star_downstream_refusal_reasons,
  )
    ? [...contractVerification.north_star_downstream_refusal_reasons]
    : [];
  const privateNonOperatorPassValidated =
    report.verified === true &&
    report.intake_class === 'private-verifier-reply' &&
    report.verdict === 'PASS' &&
    report.completed_by_non_operator === true &&
    report.private_by_default === true &&
    report.evidence_model === NORTH_STAR_READINESS_EVIDENCE_MODEL_RELEASE_FORWARD &&
    report.evidence_dir_hash_verification?.verified === true &&
    (!contractVerificationRequired || contractVerificationPassed) &&
    report.public_external_attestation === false &&
    report.public_attribution === false &&
    report.non_operator_review_publicly_claimed === false &&
    report.production_authority === false &&
    report.enterprise_readiness === false &&
    report.current_machine_governance === false &&
    report.live_mcp_coverage === false &&
    report.v3_4_0_readiness === false;
  return {
    provided: true,
    verification_type: report.verification_type,
    intake_class: report.intake_class || 'unknown',
    verdict: report.verdict || 'unknown',
    release_tag: report.release_tag || 'unknown',
    commit_sha: report.commit_sha || 'unknown',
    verified: report.verified === true,
    completed_by_non_operator: report.completed_by_non_operator === true,
    private_by_default: report.private_by_default === true,
    evidence_dir_hash_verification:
      report.evidence_dir_hash_verification?.verified === true,
    evidence_dir_contract_verification: contractVerificationPassed,
    evidence_dir_contract_verification_required: contractVerificationRequired,
    downstream_refusal_boundary_required: downstreamRefusalBoundaryRequired,
    downstream_refusal_all_refusals_unboarded:
      contractVerification.downstream_refusal_all_refusals_unboarded === true,
    downstream_refusal_reasons: downstreamRefusalReasons,
    north_star_downstream_refusal_all_refusals_unboarded:
      contractVerification.north_star_downstream_refusal_all_refusals_unboarded === true,
    north_star_downstream_refusal_reasons: northStarDownstreamRefusalReasons,
    artifact_hash_count: Number.isInteger(report.artifact_hash_count)
      ? report.artifact_hash_count
      : 0,
    private_non_operator_pass_validated: privateNonOperatorPassValidated,
    public_external_attestation: false,
    public_attribution: false,
    non_operator_review_publicly_claimed: false,
    claim_boundary:
      'validated private verifier-result verification only; no raw private reply, public external attestation, public attribution, or signed/published attestation claim',
  };
}

function optionalPrivateVerifierZipResultVerificationSummary(report) {
  if (!report) {
    return {
      provided: false,
      verification_type: 'not-provided',
      relationship_label: 'not-provided',
      evidence_model: 'not-provided',
      source_route: 'not-provided',
      commit_sha: 'not-provided',
      verified: false,
      recomputed_evidence: false,
      all_sha256sums_entries_matched: false,
      all_required_steps_exit_zero: false,
      only_known_stderr_issue: false,
      proof_smoke_verified: false,
      north_star_result: 'not-provided',
      public_privacy_passed: false,
      private_personally_connected_outside_machine_signal_validated: false,
      public_external_attestation: false,
      independent_review: false,
      arms_length_review: false,
      public_attribution: false,
      claim_boundary:
        'private verifier ZIP result verification JSON was not supplied to this report',
    };
  }
  if (!isObject(report)) {
    throw new Error('North Star private verifier ZIP result verification must be an object');
  }
  if (report.verification_type !== PRIVATE_VERIFIER_ZIP_RESULT_VERIFICATION_TYPE) {
    throw new Error('North Star private verifier ZIP result verification type drifted');
  }
  if (report.target?.source_route !== PRIVATE_VERIFIER_ZIP_SOURCE_ROUTE) {
    throw new Error('North Star private verifier ZIP result source route drifted');
  }
  if (report.evidence_model !== PRIVATE_VERIFIER_ZIP_EVIDENCE_MODEL) {
    throw new Error('North Star private verifier ZIP result evidence model drifted');
  }
  if (report.claim_boundary?.public_external_attestation !== false) {
    throw new Error('North Star private verifier ZIP result must not claim public external attestation');
  }
  if (report.claim_boundary?.independent_review !== false) {
    throw new Error('North Star private verifier ZIP result must not claim independent review');
  }
  if (report.claim_boundary?.arms_length_review !== false) {
    throw new Error('North Star private verifier ZIP result must not claim arm\'s-length review');
  }
  if (report.claim_boundary?.public_attribution !== false) {
    throw new Error('North Star private verifier ZIP result must not claim public attribution');
  }
  const privateZipSignalValidated =
    report.verified === true &&
    report.recomputed_evidence === true &&
    report.allowed_claim?.private_personally_connected_outside_machine_signal === true &&
    report.allowed_claim?.locally_reviewed_returned_result_custody === true &&
    report.all_sha256sums_entries_matched === true &&
    report.all_required_steps_exit_zero === true &&
    report.only_known_stderr_issue === true &&
    report.proof_smoke_verified === true &&
    report.north_star_result === NORTH_STAR_READINESS_RESULT_NOT_READY &&
    report.public_privacy_passed === true &&
    report.target?.moving_target_used === false &&
    report.claim_boundary?.public_external_attestation === false &&
    report.claim_boundary?.independent_review === false &&
    report.claim_boundary?.arms_length_review === false &&
    report.claim_boundary?.public_attribution === false &&
    report.claim_boundary?.production_trust === false &&
    report.claim_boundary?.current_machine_governance === false &&
    report.claim_boundary?.all_surface_governance === false &&
    report.claim_boundary?.north_star_readiness === false;
  return {
    provided: true,
    verification_type: report.verification_type,
    relationship_label: report.relationship_label || 'unknown',
    evidence_model: report.evidence_model || 'unknown',
    source_route: report.target?.source_route || 'unknown',
    commit_sha: report.target?.commit_sha || 'unknown',
    verified: report.verified === true,
    recomputed_evidence: report.recomputed_evidence === true,
    all_sha256sums_entries_matched: report.all_sha256sums_entries_matched === true,
    all_required_steps_exit_zero: report.all_required_steps_exit_zero === true,
    only_known_stderr_issue: report.only_known_stderr_issue === true,
    proof_smoke_verified: report.proof_smoke_verified === true,
    north_star_result: report.north_star_result || 'unknown',
    public_privacy_passed: report.public_privacy_passed === true,
    private_personally_connected_outside_machine_signal_validated: privateZipSignalValidated,
    public_external_attestation: false,
    independent_review: false,
    arms_length_review: false,
    public_attribution: false,
    claim_boundary:
      'validated private personally connected ZIP-snapshot result only; no public external attestation, independent review, public attribution, git clone source access, or signed/published attestation claim',
  };
}

function optionalPublicArtifactVerifierResultVerificationSummary(report) {
  if (!report) {
    return {
      provided: false,
      verification_type: 'not-provided',
      verifier_label: 'not-provided',
      target_version: 'not-provided',
      verified: false,
      public_artifact_hash_consistency_signal: false,
      public_artifact_reachability_signal: false,
      source_access_used: false,
      github_access_used: false,
      credentials_used: false,
      deploy_key_used: false,
      public_artifact_reply_signal_validated: false,
      public_external_attestation: false,
      public_attribution: false,
      non_operator_review_proven: false,
      private_source_review: false,
      production_authority: false,
      enterprise_readiness: false,
      claim_boundary:
        'public artifact verifier result verification JSON was not supplied to this report',
    };
  }
  if (!isObject(report)) {
    throw new Error('North Star public artifact verifier result verification must be an object');
  }
  if (report.verification_type !== PUBLIC_ARTIFACT_VERIFIER_RESULT_VERIFICATION_TYPE) {
    throw new Error('North Star public artifact verifier result verification type drifted');
  }
  const boundary = report.claim_boundary || {};
  for (const key of [
    'public_external_attestation',
    'public_attribution',
    'non_operator_review_proven',
    'private_source_review',
    'production_authority',
    'enterprise_readiness',
    'current_machine_governance',
    'all_surface_governance',
    'key_custody',
    'revocation_truth',
    'side_door_closure',
  ]) {
    if (boundary[key] !== false) {
      throw new Error(`North Star public artifact verifier result must keep ${key}=false`);
    }
  }
  const observed = report.observed || {};
  const publicArtifactReplySignalValidated =
    report.verified === true &&
    report.target?.version === 'v3.4.59' &&
    report.target?.release_json_url === 'https://zlar.ai/release.json' &&
    report.target?.verifier_kit_url === 'https://zlar.ai/verifier-kit/v3.4.59/' &&
    report.target?.source_access_path === 'public_release_assets_only' &&
    report.public_artifact_hash_consistency_signal === true &&
    report.public_artifact_reachability_signal === true &&
    observed.sidecar_hash_matches_tarball === true &&
    observed.sidecar_check_passed === true &&
    observed.reproducibility_json_fetched === true &&
    observed.proof_pack_manifest_fetched === true &&
    observed.proof_pack_sha256sums_fetched === true &&
    observed.source_access_used === false &&
    observed.github_access_used === false &&
    observed.credentials_used === false &&
    observed.deploy_key_used === false;
  return {
    provided: true,
    verification_type: report.verification_type,
    verifier_label: report.verifier_label || 'unknown',
    target_version: report.target?.version || 'unknown',
    verified: report.verified === true,
    public_artifact_hash_consistency_signal:
      report.public_artifact_hash_consistency_signal === true,
    public_artifact_reachability_signal:
      report.public_artifact_reachability_signal === true,
    source_access_used: observed.source_access_used === true,
    github_access_used: observed.github_access_used === true,
    credentials_used: observed.credentials_used === true,
    deploy_key_used: observed.deploy_key_used === true,
    public_artifact_reply_signal_validated: publicArtifactReplySignalValidated,
    public_external_attestation: false,
    public_attribution: false,
    non_operator_review_proven: false,
    private_source_review: false,
    production_authority: false,
    enterprise_readiness: false,
    claim_boundary:
      'validated public-artifact verifier result only; no source access, public attribution, non-operator review completion, public external attestation, or production claim',
  };
}

function optionalPublicExternalAttestationResultVerificationSummary(
  report,
  releaseForwardTargetTag = '',
) {
  if (!report) {
    return {
      provided: false,
      verification_type: 'not-provided',
      verifier_label: 'not-provided',
      release_tag: releaseForwardTargetTag || 'not-provided',
      commit_sha: 'not-provided',
      result_sha256: 'not-provided',
      verified: false,
      signature_verified: false,
      signed_or_published_by_verifier: false,
      attestation_preserved_for_future_checking: false,
      bounded_signed_attestation_evidence_verified: false,
      public_external_attestation: false,
      public_attribution: false,
      non_operator_review_proven: false,
      production_authority: false,
      enterprise_readiness: false,
      sovereign_recognition: false,
      current_machine_governance: false,
      key_custody: false,
      revocation_truth: false,
      production_downstream_recognition: false,
      side_door_closure: false,
      claim_boundary:
        'public external attestation result verification JSON was not supplied to this report',
    };
  }
  if (!isObject(report)) {
    throw new Error('North Star public external attestation result verification must be an object');
  }
  if (report.verification_type !== PUBLIC_EXTERNAL_ATTESTATION_RESULT_VERIFICATION_TYPE) {
    throw new Error('North Star public external attestation result verification type drifted');
  }
  if (releaseForwardTargetTag && report.target?.release_tag !== releaseForwardTargetTag) {
    throw new Error('North Star public external attestation result verification release tag mismatch');
  }
  if (!isSha256Hex(report.result_sha256)) {
    throw new Error('North Star public external attestation result verification result hash invalid');
  }
  const boundary = report.claim_boundary || {};
  for (const key of [
    'public_external_attestation',
    'public_attribution',
    'non_operator_review_proven',
  ]) {
    if (boundary[key] !== true) {
      throw new Error(`North Star public external attestation source verification must carry ${key}=true`);
    }
  }
  for (const key of [
    'private_source_review',
    'production_authority',
    'enterprise_readiness',
    'current_machine_governance',
    'all_surface_governance',
    'key_custody',
    'revocation_truth',
    'production_downstream_recognition',
    'side_door_closure',
    'sovereign_recognition',
  ]) {
    if (boundary[key] !== false) {
      throw new Error(`North Star public external attestation result must keep ${key}=false`);
    }
  }
  const attestation = report.attestation || {};
  const boundedSignedAttestationEvidenceVerified =
    report.verified === true &&
    report.attestation_class === 'public_signed_or_published_external_attestation' &&
    report.relationship_disclosure_class === 'arms_length_external' &&
    report.target?.source_access_path === 'public_release_assets_only' &&
    isSha256Hex(report.result_sha256) &&
    isSha256Hex(report.target?.artifact_set_sha256) &&
    isSha256Hex(report.target?.readiness_report_sha256) &&
    isSha256Hex(report.target?.proof_bundle_sha256) &&
    typeof report.target?.commit_sha === 'string' &&
    /^[a-f0-9]{40}$/i.test(report.target.commit_sha) &&
    attestation.mode === 'detached_ed25519_signature' &&
    attestation.signature_verified === true &&
    attestation.named_limits_present === true &&
    attestation.target_binding_present === true &&
    attestation.non_claims_present === true &&
    attestation.signed_or_published_by_verifier === true &&
    attestation.attestation_preserved_for_future_checking === true &&
    boundary.public_external_attestation === true &&
    boundary.public_attribution === true &&
    boundary.non_operator_review_proven === true &&
    boundary.production_authority === false &&
    boundary.enterprise_readiness === false &&
    boundary.sovereign_recognition === false &&
    boundary.current_machine_governance === false &&
    boundary.key_custody === false &&
    boundary.revocation_truth === false &&
    boundary.production_downstream_recognition === false &&
    boundary.side_door_closure === false;
  return {
    provided: true,
    verification_type: report.verification_type,
    verifier_label: report.verifier_label || 'unknown',
    release_tag: report.target?.release_tag || 'unknown',
    commit_sha: report.target?.commit_sha || 'unknown',
    result_sha256: report.result_sha256,
    verified: report.verified === true,
    signature_verified: attestation.signature_verified === true,
    signed_or_published_by_verifier:
      attestation.signed_or_published_by_verifier === true,
    attestation_preserved_for_future_checking:
      attestation.attestation_preserved_for_future_checking === true,
    bounded_signed_attestation_evidence_verified:
      boundedSignedAttestationEvidenceVerified,
    public_external_attestation: false,
    public_attribution: false,
    non_operator_review_proven: false,
    production_authority: false,
    enterprise_readiness: false,
    sovereign_recognition: false,
    current_machine_governance: false,
    key_custody: false,
    revocation_truth: false,
    production_downstream_recognition: false,
    side_door_closure: false,
    claim_boundary:
      'validated public external attestation result verification as intake-only, non-scoring evidence; no readiness, public-claim, production, or authority upgrade',
  };
}

function optionalRecognitionSummary(recognition) {
  if (!recognition) {
    return {
      provided: false,
      recognized: false,
      evidence_model: 'not-provided',
      live_probing: false,
      scope: 'not-provided',
      claim_boundary: 'trusted issuer registry recognition JSON was not supplied to this report',
    };
  }
  return {
    provided: true,
    recognized: recognition.verdict === 'RECOGNIZED' && recognition.recognized === true,
    evidence_model: recognition.registry_evidence_model || 'unknown',
    live_probing: recognition.live_probing === true,
    scope: recognition.registry_scope || 'unknown',
    claim_boundary:
      'supplied fixture trusted-issuer recognition only; no live trust-registry, custody, revocation, production downstream, or external attestation claim',
  };
}

function optionalMalformedRegistrySummary(text) {
  if (!text) {
    return {
      provided: false,
      fail_closed_before_verdict: false,
      unsupported_field_detected: false,
      claim_boundary: 'malformed registry negative evidence was not supplied to this report',
    };
  }
  return {
    provided: true,
    fail_closed_before_verdict: /unsupported field: production_authority/.test(text) &&
      !/^RECOGNIZED/m.test(text) &&
      !/^RECOGNITION-REFUSED/m.test(text),
    unsupported_field_detected: /unsupported field: production_authority/.test(text),
    claim_boundary:
      'schema-contract negative fixture only; no live trust-registry, custody, revocation, production downstream, or external attestation claim',
  };
}

function publicVerifierKitHashesPresent(report) {
  const hashes = Array.isArray(report?.public_artifact_hashes)
    ? report.public_artifact_hashes
    : [];
  const requiredPaths = [
    'dist/zlar-verifier-kit-v0.1.0.tar.gz',
    'dist/zlar-verifier-kit-v0.1.0.tar.gz.sha256',
    'dist/zlar-verifier-kit-v0.1.0/MANIFEST.json',
    'dist/zlar-verifier-kit-v0.1.0/MANIFEST.sig',
  ];
  return requiredPaths.every((path) =>
    hashes.some((entry) => entry.path === path && /^[0-9a-f]{64}$/.test(entry.sha256 || ''))
  );
}

function optionalVerifierKitReproducibilitySummary(report) {
  if (!report) {
    return {
      provided: false,
      report_type: 'not-provided',
      result: 'not-provided',
      evidence_model: 'not-provided',
      tarball_sha256_identical: false,
      manifest_and_signature_sha256_identical: false,
      sidecar_matches_tarball: false,
      public_artifact_hashes_present: false,
      claim_boundary_flags_false: false,
      claim_boundary:
        'verifier-kit reproducibility JSON was not supplied to this report',
    };
  }
  return {
    provided: true,
    report_type: report.report_type || 'unknown',
    result: report.result || 'unknown',
    evidence_model: report.evidence_model || 'unknown',
    tarball_sha256_identical:
      report.reproducible?.tarball_sha256_identical === true,
    manifest_and_signature_sha256_identical:
      report.reproducible?.manifest_and_signature_sha256_identical === true,
    sidecar_matches_tarball:
      report.reproducible?.sidecar_matches_tarball === true,
    public_artifact_hashes_present: publicVerifierKitHashesPresent(report),
    claim_boundary_flags_false:
      isObject(report.claim_boundary) &&
      Object.values(report.claim_boundary).every((value) => value === false),
    claim_boundary:
      'same-source same-test-publisher-key reproducible-build evidence only; no production publisher key custody, production signing identity, public release publication, external attestation, or v3.4.0 readiness claim',
  };
}

function optionalVerifierKitPublicDistributionSummary(report, releaseForwardTargetTag = '') {
  if (!report) {
    return {
      provided: false,
      report_type: 'not-provided',
      release_tag: 'not-provided',
      posture: 'not-provided',
      ready_for_public_distribution_claim: false,
      required_release_assets_present: false,
      public_artifact_hashes_present: false,
      static_public_artifact_source_evidence: false,
      public_artifact_source: 'not-provided',
      local_artifact_hashes_match: false,
      blocking_reasons_count: 0,
      claim_boundary:
        'verifier-kit public distribution posture JSON was not supplied to this report',
    };
  }
  assertVerifierKitPublicDistributionReport(report);
  if (releaseForwardTargetTag && report.release_tag !== releaseForwardTargetTag) {
    throw new Error('North Star verifier-kit public distribution release tag mismatch');
  }
  const requiredAssets = Array.isArray(report.required_public_release_assets)
    ? report.required_public_release_assets
    : [];
  const publicationEvidence = report.release_assets?.public_release_publication_evidence || {};
  return {
    provided: true,
    report_type: report.report_type || 'unknown',
    release_tag: report.release_tag || 'unknown',
    posture: report.posture || 'unknown',
    ready_for_public_distribution_claim:
      report.ready_for_public_distribution_claim === true,
    required_release_assets_present:
      requiredAssets.length > 0 && requiredAssets.every((asset) => asset.present === true),
    public_artifact_hashes_present:
      report.reproducibility?.public_artifact_hashes_present === true,
    public_release_publication_evidence:
      publicationEvidence.supported === true,
    static_public_artifact_source_evidence:
      publicationEvidence.source_type === 'static-public-artifact-source' &&
      publicationEvidence.supported === true &&
      publicationEvidence.public_artifact_source_matches_expected === true &&
      publicationEvidence.asset_urls_name_public_source === true &&
      publicationEvidence.anonymous_access_verified === true,
    public_artifact_source:
      publicationEvidence.public_artifact_source || 'not-provided',
    release_asset_hashes_bound:
      report.release_assets?.release_asset_hashes?.all_required_assets_bound === true,
    local_artifact_hashes_match:
      report.local_artifact_hashes?.all_checked_hashes_match === true,
    blocking_reasons_count: Array.isArray(report.blocking_reasons)
      ? report.blocking_reasons.length
      : 0,
    claim_boundary:
      'verifier-kit public distribution posture audit only; no asset publication, production publisher key custody, external attestation, or v3.4.0 readiness claim',
  };
}

function optionalVerifierKitReleaseAssetsSummary(report, releaseForwardTargetTag = '') {
  const expectedRepository = 'ZLAR-AI/ZLAR';
  if (!report) {
    return {
      provided: false,
      report_type: 'not-provided',
      evidence_model: 'not-provided',
      repository: 'not-provided',
      repository_matches_expected: false,
      release_tag: releaseForwardTargetTag || 'not-provided',
      all_required_assets_present: false,
      all_required_assets_downloaded: false,
      required_asset_count: 0,
      downloaded_sha256_count: 0,
      release_url_names_tag: false,
      release_url_names_expected_repository: false,
      asset_urls_name_expected_repository: false,
      public_release_non_draft: false,
      claim_boundary_flags_false: false,
      claim_boundary:
        'verifier-kit release-asset live-read JSON was not supplied to this report',
    };
  }
  const reportLooksLikeLiveRead =
    report.report_type === 'zlar-verifier-kit-release-assets-live-v1' ||
    report.evidence_model === 'github-release-assets-json-live-read';
  if (!reportLooksLikeLiveRead) {
    return {
      provided: false,
      report_type: report.report_type || 'not-live-read',
      evidence_model: report.evidence_model || 'not-live-read',
      repository: report.repository || 'not-provided',
      repository_matches_expected: false,
      release_tag: report.tagName || releaseForwardTargetTag || 'not-provided',
      all_required_assets_present: false,
      all_required_assets_downloaded: false,
      required_asset_count: 0,
      downloaded_sha256_count: 0,
      release_url_names_tag: false,
      release_url_names_expected_repository: false,
      asset_urls_name_expected_repository: false,
      public_release_non_draft: false,
      claim_boundary_flags_false: false,
      claim_boundary:
        'release-asset live-read evidence was not supplied; local fixture evidence cannot support public distribution readiness',
    };
  }
  assertVerifierKitReleaseAssetsLiveReadReport(report);
  if (releaseForwardTargetTag && report.tagName !== releaseForwardTargetTag) {
    throw new Error('North Star verifier-kit release assets live-read release tag mismatch');
  }
  const requiredAssets = Array.isArray(report.required_release_assets)
    ? report.required_release_assets
    : [];
  const assets = Array.isArray(report.assets) ? report.assets : [];
  const downloadedSha256Count = assets
    .filter((asset) => /^[0-9a-f]{64}$/.test(asset.downloaded_sha256 || ''))
    .length;
  const releaseUrlNamesExpectedRepository =
    typeof report.html_url === 'string' &&
    report.html_url.includes(`github.com/${expectedRepository}/releases/tag/${report.tagName}`);
  const assetUrlsNameExpectedRepository =
    requiredAssets.every((required) => {
      const asset = assets.find((entry) => entry.name === required.name);
      return (
        typeof asset?.browser_download_url === 'string' &&
        asset.browser_download_url.includes(
          `github.com/${expectedRepository}/releases/download/${report.tagName}/${required.name}`
        )
      );
    });
  return {
    provided: true,
    report_type: report.report_type || 'unknown',
    evidence_model: report.evidence_model || 'unknown',
    repository: report.repository || 'unknown',
    repository_matches_expected: report.repository === expectedRepository,
    release_tag: report.tagName || 'unknown',
    all_required_assets_present: report.all_required_assets_present === true,
    all_required_assets_downloaded: report.all_required_assets_downloaded === true,
    required_asset_count: requiredAssets.length,
    downloaded_sha256_count: downloadedSha256Count,
    release_url_names_tag:
      typeof report.html_url === 'string' &&
      report.html_url.includes(`/releases/tag/${report.tagName}`),
    release_url_names_expected_repository: releaseUrlNamesExpectedRepository,
    asset_urls_name_expected_repository: assetUrlsNameExpectedRepository,
    public_release_non_draft: report.draft === false,
    claim_boundary_flags_false:
      isObject(report.claim_boundary) &&
      Object.values(report.claim_boundary).every((value) => value === false),
    claim_boundary:
      'release-asset live-read evidence only; no release mutation, production publisher key custody, external attestation, enterprise readiness, or v3.4.0 readiness claim',
  };
}

function parseReleaseTagComponents(releaseTag) {
  if (typeof releaseTag !== 'string') return null;
  const match = releaseTag.match(/^v(\d+)\.(\d+)\.(\d+)$/);
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
  };
}

function releaseTagAtLeast(releaseTag, major, minor, patch) {
  const parsed = parseReleaseTagComponents(releaseTag);
  if (!parsed) return false;
  if (parsed.major !== major) return parsed.major > major;
  if (parsed.minor !== minor) return parsed.minor > minor;
  return parsed.patch >= patch;
}

function releaseForwardTargetTagFromReport(report) {
  if (report?.evidence_model !== NORTH_STAR_READINESS_EVIDENCE_MODEL_RELEASE_FORWARD) {
    return '';
  }
  const privateIntakePointer = Array.isArray(report.puzzle_pieces)
    ? report.puzzle_pieces.find((piece) => piece?.id === 7)?.observed
        ?.private_intake_sample_manifest_pointer
    : null;
  return typeof privateIntakePointer?.release_tag === 'string'
    ? privateIntakePointer.release_tag
    : '';
}

function optionalPrivateIntakeSampleManifestPointer(releaseForwardTargetTag = '') {
  const releaseTag =
    typeof releaseForwardTargetTag === 'string' ? releaseForwardTargetTag.trim() : '';
  const supported = releaseTagAtLeast(releaseTag, 3, 3, 104);
  return {
    provided: supported,
    evidence_model: supported
      ? 'release-forward-helper-contract'
      : releaseTag
        ? 'target-before-private-intake-sample'
        : 'not-provided',
    release_tag: releaseTag || 'not-provided',
    minimum_target: 'v3.3.104',
    manifest_field: 'private_verifier_result_sample',
    envelope_path: supported ? 'ZLAR/zlar-private-verifier-result-v1.json' : 'not-provided',
    verification_path: supported
      ? 'ZLAR/zlar-private-verifier-result-verification-v1.json'
      : 'not-provided',
    result_file: supported ? 'DRY-RUN-RESULT.md' : 'not-provided',
    result_section: supported ? 'Private Verifier Result Intake' : 'not-provided',
    hash_record_location: supported
      ? 'DRY-RUN-RESULT.md#private-verifier-result-intake'
      : 'not-provided',
    included_in_core_artifact_hashes: false,
    circular_hash_avoided: supported,
    creates_public_external_attestation: false,
    proves_non_operator_review: false,
    claim_boundary: supported
      ? 'release-forward helper contract pointer only; no manifest self-read, no circular hash, no public external attestation, and no non-operator review claim'
      : 'private-intake sample manifest pointer was not available for this readiness report',
  };
}

function optionalHumanAuthorizationSummary(localProofPackVerification) {
  const summary = localProofPackVerification?.human_authorization;
  if (!summary) {
    return {
      provided: false,
      verification_type: 'not-provided',
      evidence_model: 'not-provided',
      approval_channel: 'not-provided',
      live_probing: false,
      pending_boarded: false,
      authorized_boarded: false,
      denied_boarded: false,
      simulated_human_authorization_verified: false,
      live_approval_channel_health: false,
      claim_boundary:
        'human authorization summary was not supplied to this report',
    };
  }
  return {
    provided: true,
    verification_type: summary.summary_type || 'unknown',
    evidence_model: summary.evidence_model || 'unknown',
    approval_channel: summary.approval_channel || 'unknown',
    live_probing: summary.live_probing === true,
    pending_boarded: summary.pending_boarded === true,
    authorized_boarded: summary.authorized_boarded === true,
    denied_boarded: summary.denied_boarded === true,
    simulated_human_authorization_verified:
      summary.summary_type ===
        'zlar-local-proof-pack-human-authorization-verification-summary-v1' &&
      summary.component === 'human_authorization_proof' &&
      summary.run_in_proof_pack === true &&
      summary.proof_type === 'human-authorization-proof-v1' &&
      summary.evidence_model === 'local-hermetic-fixture' &&
      summary.approval_channel === 'simulated-human-fixture' &&
      summary.live_probing === false &&
      summary.pending_boarded === false &&
      summary.authorized_boarded === true &&
      summary.denied_boarded === false,
    live_approval_channel_health: false,
    claim_boundary:
      'simulated-human fixture authorization summary only; no live approval-channel health or real operator approval claim',
  };
}

function optionalProductProofPathSummary(report) {
  if (!report) {
    return {
      provided: false,
      report_type: 'not-provided',
      result: 'not-provided',
      evidence_model: 'not-provided',
      command: 'not-provided',
      proof_pack_verified: false,
      proof_pack_sha256: 'not-provided',
      acceptance_gate_passed: false,
      governed_action_allowed: false,
      governed_action_refused: false,
      simulated_human_authorization_observed: false,
      receipt_verification_observed: false,
      trusted_issuer_registry_recognition_observed: false,
      terminal_chain_boundary_observed: false,
      terminal_chain_artifact_verified: false,
      deployment_profile_authority_bridge_observed: false,
      trusted_issuer_registry_recognition: {
        provided: false,
        registry_type: 'not-provided',
        registry_evidence_model: 'not-provided',
        live_probing: false,
        registry_fixture_validated: false,
        registry_fixture_evaluated: false,
        registry_to_recognition_rule_evaluated: false,
        registry_evaluation_result_type: 'not-provided',
        registry_trusted_issuer_count: 0,
        verdict: 'not-provided',
        recognized: false,
        issuer_status: 'not-provided',
        signature_valid: false,
        required_audit_event_id_bound: false,
        required_detail_hash_bound: false,
        malformed_registry_fail_closed_before_verdict: false,
        proves_live_registry: false,
        proves_live_issuer_status: false,
        proves_key_custody: false,
        proves_current_machine_governance: false,
        proves_revocation_truth: false,
        proves_production_trust_registry: false,
        proves_production_downstream_recognition: false,
        proves_production_authority: false,
        proves_sovereign_recognition: false,
        proves_public_external_attestation: false,
        proves_real_non_operator_review: false,
        claim_boundary: 'Trusted issuer registry recognition was not supplied to this readiness report',
        non_claims: [],
      },
      terminal_chain_boundary: {
        provided: false,
        verified: false,
        artifact_type: 'not-provided',
        payload_type: 'not-provided',
        evidence_model: 'not-provided',
        live_probing: false,
        body_sha256: 'not-provided',
        generated_installed_root_preflighted: false,
        generated_preflight_artifact_consumed_by_service_proof: false,
        generated_service_proof_artifact_verified: false,
        recognized_write_boarded: false,
        missing_receipt_refused_before_mutation: false,
        invalid_receipt_refused_before_mutation: false,
        all_required_refusals_before_mutation: false,
        required_refusal_case_count: 0,
        observed_refusal_case_count: 0,
        recognition_contract_sha256: 'not-provided',
        refusal_taxonomy_sha256: 'not-provided',
        named_receipt_refusals: terminalChainNamedReceiptRefusalsSummary(),
        named_receipt_refusals_sha256: 'not-provided',
        recognition_refusal_groups_sha256: 'not-provided',
        recognition_refusal_group_count: 0,
        recognition_refusal_group_case_count: 0,
        recognition_refusal_group_case_ids: {},
        recognition_refusal_group_case_ids_preserved: false,
        trusted_issuer_registry_recognition_binding_sha256: 'not-provided',
        trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification:
          false,
        trusted_issuer_registry_recognition_verdict: 'not-provided',
        trusted_issuer_registry_recognition_recognized: false,
        trusted_issuer_registry_recognition_decision: 'not-provided',
        trusted_issuer_registry_recognition_reason_code: 'not-provided',
        trusted_issuer_registry_recognition_issuer_status: 'not-provided',
        trusted_issuer_registry_recognition_signature_valid: false,
        trusted_issuer_registry_recognition_registry_fixture_validated: false,
        trusted_issuer_registry_recognition_registry_fixture_evaluated: false,
        trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated:
          false,
        trusted_issuer_registry_recognition_registry_evaluation_result_type:
          'not-provided',
        trusted_issuer_registry_recognition_registry_trusted_issuer_count: 0,
        trusted_issuer_registry_recognition_required_audit_event_id_bound:
          false,
        trusted_issuer_registry_recognition_required_detail_hash_bound: false,
        trusted_issuer_registry_recognition_registry_fixture_contract_sha256:
          'not-provided',
        trusted_issuer_registry_recognition_receipt_payload_contract_sha256:
          'not-provided',
        trusted_issuer_registry_recognition_refusals_sha256: 'not-provided',
        trusted_issuer_registry_recognition_refusal_hash_matches_binding: false,
        trusted_issuer_registry_recognition_refusal_case_count: 0,
        trusted_issuer_registry_recognition_refusal_case_ids: [],
        trusted_issuer_registry_recognition_refusal_reason_codes: [],
        trusted_issuer_registry_recognition_refusals_all_refused: false,
        recognized_receipt_path_evidence_sha256: 'not-provided',
        recognized_receipt_path_evidence_artifact_verification_sha256:
          'not-provided',
        recognized_receipt_path_evidence_sha256_matches_artifact_verification:
          false,
        recognized_receipt_path_evidence_bound_to_artifact_body: false,
        recognized_receipt_path_evidence_source_binding_sha256: 'not-provided',
        recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding:
          false,
        recognized_receipt_path_evidence_verdict: 'not-provided',
        recognized_receipt_path_evidence_recognized: false,
        recognized_receipt_path_evidence_receipt_envelope_included: false,
        recognized_receipt_path_evidence_registry_public_key_material_included:
          false,
        recognized_receipt_path_evidence_artifact_crypto_reproducible: false,
        recognized_receipt_path_evidence_live_state_proven: false,
        recognized_receipt_path_evidence_live_issuer_status_proven: false,
        recognized_receipt_path_evidence_key_custody_proven: false,
        recognized_receipt_path_evidence_revocation_truth_proven: false,
        recognized_receipt_path_evidence_production_downstream_recognition_proven:
          false,
        recognized_receipt_path_evidence_public_external_attestation: false,
        recognized_receipt_path_evidence_sovereign_recognition: false,
        recognized_receipt_path_evidence_current_machine_governance_proven:
          false,
        registry_receipt_contract_hash_bound: false,
        selected_profile_hash_bound: false,
        recognition_contract_hash_bound: false,
        terminal_chain_decision_bound: false,
        registry_public_key_material_included: false,
        receipt_envelope_included: false,
        cryptographic_evidence_reproducible_from_artifact: false,
        nested_artifact_binding_preserved: false,
        creates_public_external_attestation: false,
        proves_current_machine_governance: false,
        proves_production_downstream_recognition: false,
        persistent_runtime_profile_installed: false,
        runtime_profile_activation_performed: false,
        hook_configuration_written: false,
        user_configuration_written: false,
        machine_configuration_written: false,
        current_machine_governance_proven: false,
        production_records_service_checked: false,
        production_downstream_recognition: false,
        external_attestation: false,
        sovereign_recognition: false,
        unrouted_records_paths_checked: false,
        known_open_boundaries: [],
        claim_boundary:
          'Product Proof Path terminal-chain boundary was not supplied to this readiness report',
      },
      deployment_profile_authority_bridge: {
        provided: false,
        proof_type: 'not-provided',
        evidence_model: 'not-provided',
        live_probing: false,
        deployment_profile_id: 'not-provided',
        deployment_profile_sha256: 'not-provided',
        runtime_profile_sha256: 'not-provided',
        deployment_profile_artifact_authoritative: false,
        deployment_profile_authority_refusal_case_count: 0,
        deployment_profile_authority_refusal_case_ids: [],
        deployment_profile_authority_refusals_before_service_proof: false,
        deployment_profile_authority_refusals_before_mutation: false,
        deployment_profile_authority_refusal_service_proof_started: false,
        stale_deployment_profile_artifact_refused_before_service_proof: false,
        profile_recognition_mismatch_refused_before_service_proof: false,
        latest_profile_selection_refused_before_service_proof: false,
        request_stream_authority_material_refused_before_service_proof: false,
        selected_by_explicit_id_and_sha: false,
        selects_latest_profile: false,
        preflight_artifact_verified: false,
        recognized_receipt_mutates_once: false,
        recognized_state_entry_count_delta: 0,
        required_refusal_case_count: 0,
        observed_refusal_case_count: 0,
        all_required_refusals_before_mutation: false,
        agent_supplied_authority_refused_before_mutation: false,
        direct_api_refused_before_mutation: false,
        downstream_refusal_proven: false,
        request_stream_authority_material_accepted: false,
        current_machine_governance: false,
        production_downstream_recognition: false,
        production_authority: false,
        enterprise_readiness: false,
        external_attestation: false,
        sovereign_recognition: false,
        unrouted_surface_coverage: false,
        claim_boundary:
          'Product Proof Path deployment-profile authority bridge was not supplied to this readiness report',
      },
      downstream_refusal_boundary: absentDownstreamRefusalBoundarySummary(),
      non_coverage_visible: false,
      forbidden_claims_false: false,
      live_probing: false,
      private_operator_state_required: false,
      proof_pack_runtime_profile_identity_policy:
        runtimeProfileIdentityPolicySummary(null),
      proof_pack_claude_hook_contract_replay:
        absentProductProofPathClaudeHookReplaySummary(),
      claim_boundary: 'Product Proof Path report was not supplied to this readiness report',
    };
  }
  assertProductProofPathReport(report);
  const terminalChainBoundary = report.terminal_chain_boundary || {};
  const nestedArtifactBinding = terminalChainBoundary.nested_artifact_binding || {};
  const deploymentProfileAuthorityBridge =
    report.deployment_profile_authority_bridge || {};
  return {
    provided: true,
    report_type: report.report_type,
    result: report.result,
    evidence_model: report.evidence_model,
    command: report.command,
    proof_pack_verified: report.proof_pack?.verified === true,
    proof_pack_sha256: report.proof_pack?.body_sha256 || 'not-provided',
    proof_pack_runtime_profile_identity_policy:
      runtimeProfileIdentityPolicySummary(
        report.proof_pack?.runtime_profile_identity_policy
      ),
    proof_pack_claude_hook_contract_replay:
      productProofPathClaudeHookReplaySummary(
        report.proof_pack?.claude_hook_contract_replay
      ),
    acceptance_gate_passed:
      isObject(report.acceptance_gate) &&
      Object.values(report.acceptance_gate).every((value) => value === true),
    governed_action_allowed: report.acceptance_gate?.governed_action_allowed === true,
    governed_action_refused: report.acceptance_gate?.governed_action_refused === true,
    simulated_human_authorization_observed:
      report.acceptance_gate?.simulated_human_authorization_observed === true,
    receipt_verification_observed:
      report.acceptance_gate?.receipt_verification_observed === true,
    trusted_issuer_registry_recognition_observed:
      report.acceptance_gate?.trusted_issuer_registry_recognition_observed === true,
    terminal_chain_boundary_observed:
      report.acceptance_gate?.terminal_chain_boundary_observed === true,
    terminal_chain_artifact_verified:
      report.acceptance_gate?.terminal_chain_artifact_verified === true,
    deployment_profile_authority_bridge_observed:
      report.acceptance_gate?.deployment_profile_authority_bridge_observed === true,
    trusted_issuer_registry_recognition: {
      provided: true,
      registry_type:
        report.trusted_issuer_registry_recognition?.registry_type || 'not-provided',
      registry_evidence_model:
        report.trusted_issuer_registry_recognition?.registry_evidence_model ||
        'not-provided',
      registry_contract_evidence:
        report.trusted_issuer_registry_recognition?.registry_contract_evidence ||
        'not-provided',
      registry_public_safe_summary_sha256:
        report.trusted_issuer_registry_recognition
          ?.registry_public_safe_summary_sha256 || 'not-provided',
      live_probing:
        report.trusted_issuer_registry_recognition?.live_probing === true,
      registry_fixture_validated:
        report.trusted_issuer_registry_recognition?.registry_fixture_validated ===
        true,
      registry_fixture_evaluated:
        report.trusted_issuer_registry_recognition?.registry_fixture_evaluated ===
        true,
      registry_to_recognition_rule_evaluated:
        report.trusted_issuer_registry_recognition
          ?.registry_to_recognition_rule_evaluated === true,
      registry_evaluation_result_type:
        report.trusted_issuer_registry_recognition
          ?.registry_evaluation_result_type || 'not-provided',
      registry_trusted_issuer_count:
        report.trusted_issuer_registry_recognition?.registry_trusted_issuer_count ?? 0,
      verdict: report.trusted_issuer_registry_recognition?.verdict || 'not-provided',
      recognized:
        report.trusted_issuer_registry_recognition?.recognized === true,
      issuer_status:
        report.trusted_issuer_registry_recognition?.issuer_status || 'not-provided',
      signature_valid:
        report.trusted_issuer_registry_recognition?.signature_valid === true,
      required_audit_event_id_bound:
        report.trusted_issuer_registry_recognition?.required_audit_event_id_bound ===
        true,
      required_detail_hash_bound:
        report.trusted_issuer_registry_recognition?.required_detail_hash_bound ===
        true,
      malformed_registry_fail_closed_before_verdict:
        report.trusted_issuer_registry_recognition
          ?.malformed_registry_fail_closed_before_verdict === true,
      proves_live_registry:
        report.trusted_issuer_registry_recognition?.proves_live_registry === true,
      proves_live_issuer_status:
        report.trusted_issuer_registry_recognition?.proves_live_issuer_status ===
        true,
      proves_key_custody:
        report.trusted_issuer_registry_recognition?.proves_key_custody === true,
      proves_current_machine_governance:
        report.trusted_issuer_registry_recognition
          ?.proves_current_machine_governance === true,
      proves_revocation_truth:
        report.trusted_issuer_registry_recognition?.proves_revocation_truth ===
        true,
      proves_production_trust_registry:
        report.trusted_issuer_registry_recognition
          ?.proves_production_trust_registry === true,
      proves_production_downstream_recognition:
        report.trusted_issuer_registry_recognition
          ?.proves_production_downstream_recognition === true,
      proves_production_authority:
        report.trusted_issuer_registry_recognition?.proves_production_authority ===
        true,
      proves_sovereign_recognition:
        report.trusted_issuer_registry_recognition?.proves_sovereign_recognition ===
        true,
      proves_public_external_attestation:
        report.trusted_issuer_registry_recognition
          ?.proves_public_external_attestation === true,
      proves_real_non_operator_review:
        report.trusted_issuer_registry_recognition?.proves_real_non_operator_review ===
        true,
      claim_boundary:
        report.trusted_issuer_registry_recognition?.claim_boundary || 'not-provided',
      non_claims: Array.isArray(report.trusted_issuer_registry_recognition?.non_claims)
        ? [...report.trusted_issuer_registry_recognition.non_claims]
        : [],
    },
    terminal_chain_boundary: {
      provided: true,
      verified: terminalChainBoundary.verified === true,
      artifact_type: terminalChainBoundary.artifact_type || 'not-provided',
      payload_type: terminalChainBoundary.payload_type || 'not-provided',
      evidence_model: terminalChainBoundary.evidence_model || 'not-provided',
      live_probing: terminalChainBoundary.live_probing === true,
      body_sha256: terminalChainBoundary.body_sha256 || 'not-provided',
      generated_installed_root_preflighted:
        terminalChainBoundary.generated_installed_root_preflighted === true,
      generated_preflight_artifact_consumed_by_service_proof:
        terminalChainBoundary.generated_preflight_artifact_consumed_by_service_proof ===
        true,
      generated_service_proof_artifact_verified:
        terminalChainBoundary.generated_service_proof_artifact_verified === true,
      recognized_write_boarded:
        terminalChainBoundary.recognized_write_boarded === true,
      missing_receipt_refused_before_mutation:
        terminalChainBoundary.missing_receipt_refused_before_mutation === true,
      invalid_receipt_refused_before_mutation:
        terminalChainBoundary.invalid_receipt_refused_before_mutation === true,
      all_required_refusals_before_mutation:
        terminalChainBoundary.all_required_refusals_before_mutation === true,
      required_refusal_case_count:
        terminalChainBoundary.required_refusal_case_count ?? 0,
      observed_refusal_case_count:
        terminalChainBoundary.observed_refusal_case_count ?? 0,
      recognition_contract_sha256:
        terminalChainBoundary.recognition_contract_sha256 || 'not-provided',
      refusal_taxonomy_sha256:
        terminalChainBoundary.refusal_taxonomy_sha256 || 'not-provided',
      named_receipt_refusals_sha256:
        terminalChainBoundary.named_receipt_refusals_sha256 || 'not-provided',
      named_receipt_refusals: terminalChainNamedReceiptRefusalsSummary(
        terminalChainBoundary.named_receipt_refusals,
      ),
      recognition_refusal_groups_sha256:
        terminalChainBoundary.recognition_refusal_groups_sha256 || 'not-provided',
      recognition_refusal_group_count:
        terminalChainBoundary.recognition_refusal_group_count ?? 0,
      recognition_refusal_group_case_count:
        terminalChainBoundary.recognition_refusal_group_case_count ?? 0,
      recognition_refusal_group_case_ids: isObject(
        terminalChainBoundary.recognition_refusal_group_case_ids,
      )
        ? Object.fromEntries(
            Object.entries(terminalChainBoundary.recognition_refusal_group_case_ids)
              .map(([groupName, caseIds]) => [
                groupName,
                Array.isArray(caseIds) ? [...caseIds] : [],
              ]),
          )
        : {},
      recognition_refusal_group_case_ids_preserved:
        terminalChainBoundary.recognition_refusal_group_case_ids_preserved === true,
      trusted_issuer_registry_recognition_binding_sha256:
        terminalChainBoundary.trusted_issuer_registry_recognition_binding_sha256 ||
        'not-provided',
      trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification:
        terminalChainBoundary
          .trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification ===
        true,
      trusted_issuer_registry_recognition_verdict:
        terminalChainBoundary.trusted_issuer_registry_recognition_verdict ||
        'not-provided',
      trusted_issuer_registry_recognition_recognized:
        terminalChainBoundary.trusted_issuer_registry_recognition_recognized ===
        true,
      trusted_issuer_registry_recognition_decision:
        terminalChainBoundary.trusted_issuer_registry_recognition_decision ||
        'not-provided',
      trusted_issuer_registry_recognition_reason_code:
        terminalChainBoundary.trusted_issuer_registry_recognition_reason_code ||
        'not-provided',
      trusted_issuer_registry_recognition_registry_contract_evidence:
        terminalChainBoundary
          .trusted_issuer_registry_recognition_registry_contract_evidence ||
        'not-provided',
      trusted_issuer_registry_recognition_registry_public_safe_summary_sha256:
        terminalChainBoundary
          .trusted_issuer_registry_recognition_registry_public_safe_summary_sha256 ||
        'not-provided',
      trusted_issuer_registry_recognition_issuer_status:
        terminalChainBoundary.trusted_issuer_registry_recognition_issuer_status ||
        'not-provided',
      trusted_issuer_registry_recognition_signature_valid:
        terminalChainBoundary.trusted_issuer_registry_recognition_signature_valid ===
        true,
      trusted_issuer_registry_recognition_registry_fixture_validated:
        terminalChainBoundary
          .trusted_issuer_registry_recognition_registry_fixture_validated === true,
      trusted_issuer_registry_recognition_registry_fixture_evaluated:
        terminalChainBoundary
          .trusted_issuer_registry_recognition_registry_fixture_evaluated === true,
      trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated:
        terminalChainBoundary
          .trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated ===
        true,
      trusted_issuer_registry_recognition_registry_evaluation_result_type:
        terminalChainBoundary
          .trusted_issuer_registry_recognition_registry_evaluation_result_type ||
        'not-provided',
      trusted_issuer_registry_recognition_registry_trusted_issuer_count:
        terminalChainBoundary
          .trusted_issuer_registry_recognition_registry_trusted_issuer_count ?? 0,
      trusted_issuer_registry_recognition_required_audit_event_id_bound:
        terminalChainBoundary
          .trusted_issuer_registry_recognition_required_audit_event_id_bound ===
        true,
      trusted_issuer_registry_recognition_required_detail_hash_bound:
        terminalChainBoundary
          .trusted_issuer_registry_recognition_required_detail_hash_bound === true,
      trusted_issuer_registry_recognition_registry_fixture_contract_sha256:
        terminalChainBoundary
          .trusted_issuer_registry_recognition_registry_fixture_contract_sha256 ||
        'not-provided',
      trusted_issuer_registry_recognition_receipt_payload_contract_sha256:
        terminalChainBoundary
          .trusted_issuer_registry_recognition_receipt_payload_contract_sha256 ||
        'not-provided',
      trusted_issuer_registry_recognition_refusals_sha256:
        terminalChainBoundary.trusted_issuer_registry_recognition_refusals_sha256 ||
        'not-provided',
      trusted_issuer_registry_recognition_refusal_hash_matches_binding:
        terminalChainBoundary
          .trusted_issuer_registry_recognition_refusal_hash_matches_binding === true,
      trusted_issuer_registry_recognition_refusal_case_count:
        terminalChainBoundary
          .trusted_issuer_registry_recognition_refusal_case_count ?? 0,
      trusted_issuer_registry_recognition_refusal_case_ids:
        Array.isArray(
          terminalChainBoundary
            .trusted_issuer_registry_recognition_refusal_case_ids,
        )
          ? [
              ...terminalChainBoundary
                .trusted_issuer_registry_recognition_refusal_case_ids,
            ]
          : [],
      trusted_issuer_registry_recognition_refusal_reason_codes:
        Array.isArray(
          terminalChainBoundary
            .trusted_issuer_registry_recognition_refusal_reason_codes,
        )
          ? [
              ...terminalChainBoundary
                .trusted_issuer_registry_recognition_refusal_reason_codes,
            ]
          : [],
      trusted_issuer_registry_recognition_refusals_all_refused:
        terminalChainBoundary
          .trusted_issuer_registry_recognition_refusals_all_refused === true,
      recognized_receipt_path_evidence_sha256:
        terminalChainBoundary.recognized_receipt_path_evidence_sha256 ||
        'not-provided',
      recognized_receipt_path_evidence_artifact_verification_sha256:
        terminalChainBoundary
          .recognized_receipt_path_evidence_artifact_verification_sha256 ||
        'not-provided',
      recognized_receipt_path_evidence_sha256_matches_artifact_verification:
        terminalChainBoundary
          .recognized_receipt_path_evidence_sha256_matches_artifact_verification ===
        true,
      recognized_receipt_path_evidence_bound_to_artifact_body:
        terminalChainBoundary
          .recognized_receipt_path_evidence_bound_to_artifact_body === true,
      recognized_receipt_path_evidence_source_binding_sha256:
        terminalChainBoundary
          .recognized_receipt_path_evidence_source_binding_sha256 ||
        'not-provided',
      recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding:
        terminalChainBoundary
          .recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding ===
        true,
      recognized_receipt_path_evidence_verdict:
        terminalChainBoundary.recognized_receipt_path_evidence_verdict ||
        'not-provided',
      recognized_receipt_path_evidence_recognized:
        terminalChainBoundary.recognized_receipt_path_evidence_recognized === true,
      recognized_receipt_path_evidence_receipt_envelope_included:
        terminalChainBoundary
          .recognized_receipt_path_evidence_receipt_envelope_included === true,
      recognized_receipt_path_evidence_registry_public_key_material_included:
        terminalChainBoundary
          .recognized_receipt_path_evidence_registry_public_key_material_included ===
        true,
      recognized_receipt_path_evidence_artifact_crypto_reproducible:
        terminalChainBoundary
          .recognized_receipt_path_evidence_artifact_crypto_reproducible === true,
      recognized_receipt_path_evidence_live_state_proven:
        terminalChainBoundary
          .recognized_receipt_path_evidence_live_state_proven === true,
      recognized_receipt_path_evidence_live_issuer_status_proven:
        terminalChainBoundary
          .recognized_receipt_path_evidence_live_issuer_status_proven === true,
      recognized_receipt_path_evidence_key_custody_proven:
        terminalChainBoundary
          .recognized_receipt_path_evidence_key_custody_proven === true,
      recognized_receipt_path_evidence_revocation_truth_proven:
        terminalChainBoundary
          .recognized_receipt_path_evidence_revocation_truth_proven === true,
      recognized_receipt_path_evidence_production_downstream_recognition_proven:
        terminalChainBoundary
          .recognized_receipt_path_evidence_production_downstream_recognition_proven ===
        true,
      recognized_receipt_path_evidence_public_external_attestation:
        terminalChainBoundary
          .recognized_receipt_path_evidence_public_external_attestation === true,
      recognized_receipt_path_evidence_sovereign_recognition:
        terminalChainBoundary
          .recognized_receipt_path_evidence_sovereign_recognition === true,
      recognized_receipt_path_evidence_current_machine_governance_proven:
        terminalChainBoundary
          .recognized_receipt_path_evidence_current_machine_governance_proven ===
        true,
      registry_receipt_contract_hash_bound:
        terminalChainBoundary.registry_receipt_contract_hash_bound === true,
      selected_profile_hash_bound:
        terminalChainBoundary.selected_profile_hash_bound === true,
      recognition_contract_hash_bound:
        terminalChainBoundary.recognition_contract_hash_bound === true,
      terminal_chain_decision_bound:
        terminalChainBoundary.terminal_chain_decision_bound === true,
      registry_public_key_material_included:
        terminalChainBoundary.registry_public_key_material_included === true,
      receipt_envelope_included:
        terminalChainBoundary.receipt_envelope_included === true,
      cryptographic_evidence_reproducible_from_artifact:
        terminalChainBoundary.cryptographic_evidence_reproducible_from_artifact === true,
      nested_artifact_binding_preserved:
        nestedArtifactBinding.preflight_artifact_hash_bound === true &&
        nestedArtifactBinding.service_proof_source_preflight_hash_bound === true &&
        nestedArtifactBinding.service_artifact_hash_bound === true &&
        nestedArtifactBinding.service_artifact_verification_bound_to_service_proof === true,
      creates_public_external_attestation:
        nestedArtifactBinding.creates_public_external_attestation === true,
      proves_current_machine_governance:
        nestedArtifactBinding.proves_current_machine_governance === true,
      proves_production_downstream_recognition:
        nestedArtifactBinding.proves_production_downstream_recognition === true,
      persistent_runtime_profile_installed:
        terminalChainBoundary.persistent_runtime_profile_installed === true,
      runtime_profile_activation_performed:
        terminalChainBoundary.runtime_profile_activation_performed === true,
      hook_configuration_written:
        terminalChainBoundary.hook_configuration_written === true,
      user_configuration_written:
        terminalChainBoundary.user_configuration_written === true,
      machine_configuration_written:
        terminalChainBoundary.machine_configuration_written === true,
      current_machine_governance_proven:
        terminalChainBoundary.current_machine_governance_proven === true,
      production_records_service_checked:
        terminalChainBoundary.production_records_service_checked === true,
      production_downstream_recognition:
        terminalChainBoundary.production_downstream_recognition === true,
      external_attestation:
        terminalChainBoundary.external_attestation === true,
      sovereign_recognition:
        terminalChainBoundary.sovereign_recognition === true,
      unrouted_records_paths_checked:
        terminalChainBoundary.unrouted_records_paths_checked === true,
      known_open_boundaries: Array.isArray(terminalChainBoundary.known_open_boundaries)
        ? [...terminalChainBoundary.known_open_boundaries]
        : [],
      claim_boundary: terminalChainBoundary.claim_boundary || 'not-provided',
    },
    deployment_profile_authority_bridge: {
      provided: true,
      proof_type: deploymentProfileAuthorityBridge.proof_type || 'not-provided',
      evidence_model:
        deploymentProfileAuthorityBridge.evidence_model || 'not-provided',
      live_probing: deploymentProfileAuthorityBridge.live_probing === true,
      deployment_profile_id:
        deploymentProfileAuthorityBridge.deployment_profile_id || 'not-provided',
      deployment_profile_sha256:
        deploymentProfileAuthorityBridge.deployment_profile_sha256 ||
        'not-provided',
      runtime_profile_sha256:
        deploymentProfileAuthorityBridge.runtime_profile_sha256 ||
        'not-provided',
      deployment_profile_artifact_authoritative:
        deploymentProfileAuthorityBridge.deployment_profile_artifact_authoritative ===
        true,
      deployment_profile_authority_refusal_case_count:
        deploymentProfileAuthorityBridge
          .deployment_profile_authority_refusal_case_count ?? 0,
      deployment_profile_authority_refusal_case_ids: Array.isArray(
        deploymentProfileAuthorityBridge
          .deployment_profile_authority_refusal_case_ids,
      )
        ? [
            ...deploymentProfileAuthorityBridge
              .deployment_profile_authority_refusal_case_ids,
          ]
        : [],
      deployment_profile_authority_refusals_before_service_proof:
        deploymentProfileAuthorityBridge
          .deployment_profile_authority_refusals_before_service_proof === true,
      deployment_profile_authority_refusals_before_mutation:
        deploymentProfileAuthorityBridge
          .deployment_profile_authority_refusals_before_mutation === true,
      deployment_profile_authority_refusal_service_proof_started:
        deploymentProfileAuthorityBridge
          .deployment_profile_authority_refusal_service_proof_started === true,
      stale_deployment_profile_artifact_refused_before_service_proof:
        deploymentProfileAuthorityBridge
          .stale_deployment_profile_artifact_refused_before_service_proof === true,
      profile_recognition_mismatch_refused_before_service_proof:
        deploymentProfileAuthorityBridge
          .profile_recognition_mismatch_refused_before_service_proof === true,
      latest_profile_selection_refused_before_service_proof:
        deploymentProfileAuthorityBridge
          .latest_profile_selection_refused_before_service_proof === true,
      request_stream_authority_material_refused_before_service_proof:
        deploymentProfileAuthorityBridge
          .request_stream_authority_material_refused_before_service_proof === true,
      selected_by_explicit_id_and_sha:
        deploymentProfileAuthorityBridge.selected_by_explicit_id_and_sha === true,
      selects_latest_profile:
        deploymentProfileAuthorityBridge.selects_latest_profile === true,
      preflight_artifact_verified:
        deploymentProfileAuthorityBridge.preflight_artifact_verified === true,
      recognized_receipt_mutates_once:
        deploymentProfileAuthorityBridge.recognized_receipt_mutates_once === true,
      recognized_state_entry_count_delta:
        deploymentProfileAuthorityBridge.recognized_state_entry_count_delta ?? 0,
      required_refusal_case_count:
        deploymentProfileAuthorityBridge.required_refusal_case_count ?? 0,
      observed_refusal_case_count:
        deploymentProfileAuthorityBridge.observed_refusal_case_count ?? 0,
      all_required_refusals_before_mutation:
        deploymentProfileAuthorityBridge.all_required_refusals_before_mutation ===
        true,
      agent_supplied_authority_refused_before_mutation:
        deploymentProfileAuthorityBridge
          .agent_supplied_authority_refused_before_mutation === true,
      direct_api_refused_before_mutation:
        deploymentProfileAuthorityBridge.direct_api_refused_before_mutation ===
        true,
      downstream_refusal_proven:
        deploymentProfileAuthorityBridge.downstream_refusal_proven === true,
      request_stream_authority_material_accepted:
        deploymentProfileAuthorityBridge
          .request_stream_authority_material_accepted === true,
      current_machine_governance:
        deploymentProfileAuthorityBridge.current_machine_governance === true,
      production_downstream_recognition:
        deploymentProfileAuthorityBridge.production_downstream_recognition === true,
      production_authority:
        deploymentProfileAuthorityBridge.production_authority === true,
      enterprise_readiness:
        deploymentProfileAuthorityBridge.enterprise_readiness === true,
      external_attestation:
        deploymentProfileAuthorityBridge.external_attestation === true,
      sovereign_recognition:
        deploymentProfileAuthorityBridge.sovereign_recognition === true,
      unrouted_surface_coverage:
        deploymentProfileAuthorityBridge.unrouted_surface_coverage === true,
      claim_boundary:
        deploymentProfileAuthorityBridge.claim_boundary || 'not-provided',
    },
    downstream_refusal_boundary:
      productProofPathDownstreamRefusalBoundarySummary(report),
    non_coverage_visible: report.acceptance_gate?.non_coverage_visible === true,
    forbidden_claims_false:
      isObject(report.forbidden_claims) &&
      Object.values(report.forbidden_claims).every((value) => value === false),
    live_probing: report.live_probing === true,
    private_operator_state_required: report.private_operator_state_required === true,
    claim_boundary: report.claim_boundary,
  };
}

function productProofPathDeploymentProfileAuthorityBridgePasses(bridge) {
  return (
    isObject(bridge) &&
    bridge.provided === true &&
    bridge.proof_type ===
      'zlar-protected-records-one-terminal-deployment-profile-proof-v1' &&
    bridge.evidence_model ===
      'local-fixture-one-terminal-deployment-profile-authority-bridge' &&
    bridge.live_probing === false &&
    typeof bridge.deployment_profile_id === 'string' &&
    bridge.deployment_profile_id.length > 0 &&
    isSha256Hex(bridge.deployment_profile_sha256) &&
    isSha256Hex(bridge.runtime_profile_sha256) &&
    bridge.deployment_profile_artifact_authoritative === true &&
    bridge.selected_by_explicit_id_and_sha === true &&
    bridge.selects_latest_profile === false &&
    bridge.preflight_artifact_verified === true &&
    bridge.recognized_receipt_mutates_once === true &&
    bridge.recognized_state_entry_count_delta === 1 &&
    bridge.required_refusal_case_count ===
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length &&
    bridge.observed_refusal_case_count ===
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length &&
    bridge.all_required_refusals_before_mutation === true &&
    bridge.agent_supplied_authority_refused_before_mutation === true &&
    bridge.direct_api_refused_before_mutation === true &&
    bridge.downstream_refusal_proven === true &&
    bridge.request_stream_authority_material_accepted === false &&
    bridge.current_machine_governance === false &&
    bridge.production_downstream_recognition === false &&
    bridge.production_authority === false &&
    bridge.enterprise_readiness === false &&
    bridge.external_attestation === false &&
    bridge.sovereign_recognition === false &&
    bridge.unrouted_surface_coverage === false &&
    typeof bridge.claim_boundary === 'string' &&
    bridge.claim_boundary.length > 0
  );
}

function productProofPathDeploymentProfileAuthorityRefusalsPasses(bridge) {
  return (
    isObject(bridge) &&
    bridge.deployment_profile_authority_refusal_case_count ===
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length &&
    JSON.stringify(bridge.deployment_profile_authority_refusal_case_ids) ===
      JSON.stringify(REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES) &&
    bridge.deployment_profile_authority_refusals_before_service_proof === true &&
    bridge.deployment_profile_authority_refusals_before_mutation === true &&
    bridge.deployment_profile_authority_refusal_service_proof_started === false &&
    bridge.stale_deployment_profile_artifact_refused_before_service_proof === true &&
    bridge.profile_recognition_mismatch_refused_before_service_proof === true &&
    bridge.latest_profile_selection_refused_before_service_proof === true &&
    bridge.request_stream_authority_material_refused_before_service_proof === true
  );
}

function terminalChainDeploymentProfileAuthorityRefusalMirrorPasses(mirror) {
  return (
    isObject(mirror) &&
    mirror.source === 'committed-one-terminal-deployment-profile-fixture' &&
    mirror.source_proof_type ===
      'zlar-protected-records-one-terminal-deployment-profile-proof-v1' &&
    mirror.evidence_model ===
      'local-fixture-one-terminal-deployment-profile-authority-bridge' &&
    mirror.local_fixture_only === true &&
    mirror.mirrored_from_one_terminal_deployment_profile === true &&
    mirror.source_runtime_profile_sha_matches_terminal_chain === true &&
    mirror.deployment_profile_authority_refusal_case_count ===
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length &&
    JSON.stringify(mirror.deployment_profile_authority_refusal_case_ids) ===
      JSON.stringify(REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES) &&
    mirror.deployment_profile_authority_refusals_before_service_proof === true &&
    mirror.deployment_profile_authority_refusals_before_mutation === true &&
    mirror.deployment_profile_authority_refusal_service_proof_started === false &&
    mirror.stale_deployment_profile_artifact_refused_before_service_proof === true &&
    mirror.profile_recognition_mismatch_refused_before_service_proof === true &&
    mirror.latest_profile_selection_refused_before_service_proof === true &&
    mirror.request_stream_authority_material_refused_before_service_proof === true &&
    mirror.current_machine_governance === false &&
    mirror.production_downstream_recognition === false &&
    mirror.production_authority === false &&
    mirror.enterprise_readiness === false &&
    mirror.external_attestation === false &&
    mirror.sovereign_recognition === false &&
    mirror.unrouted_surface_coverage === false
  );
}

const PRODUCT_PROOF_PATH_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_SUMMARY_KEYS =
  Object.freeze([
    'deployment_profile_authority_refusal_case_count',
    'deployment_profile_authority_refusal_case_ids',
    'deployment_profile_authority_refusals_before_service_proof',
    'deployment_profile_authority_refusals_before_mutation',
    'deployment_profile_authority_refusal_service_proof_started',
    'stale_deployment_profile_artifact_refused_before_service_proof',
    'profile_recognition_mismatch_refused_before_service_proof',
    'latest_profile_selection_refused_before_service_proof',
    'request_stream_authority_material_refused_before_service_proof',
  ]);

function hasAnyOwnKey(value, keys) {
  return isObject(value) && keys.some((key) =>
    Object.prototype.hasOwnProperty.call(value, key)
  );
}

function artifactList({
  productProofPathReport,
  installedRuntimeProfileRecognitionProof,
  installedRuntimeProfileServiceProof,
  installedRuntimeProfileServiceProofArtifactVerification,
  installedRuntimeProfileTerminalChain,
  installedRuntimeProfileTerminalChainArtifact,
  installedRuntimeProfileTerminalChainArtifactVerification,
  recognition,
  trustedIssuerCompletionProof,
  malformedRegistryError,
  verifierKitReproducibility,
  verifierKitReleaseAssets,
  verifierKitPublicDistribution,
  privateVerifierResultVerification,
  privateVerifierZipResultVerification,
  publicArtifactVerifierResultVerification,
  publicExternalAttestationResultVerification,
  activePersistentProfileLifecycleEvidence,
}) {
  const artifacts = [
    'zlar-proof-smoke-sample-verification.json',
    'zlar-local-proof-pack-sample-verification.json',
    'zlar-service-preflight-sample-verification.json',
    'zlar-runtime-local-activation-sample-verification.json',
    'zlar-runtime-profile-installation-sample-verification.json',
    'zlar-installed-runtime-profile-preflight-sample-verification.json',
    'zlar-coverage-map-sample.json',
  ];
  if (productProofPathReport) artifacts.push('zlar-product-proof-path-v1.json');
  if (installedRuntimeProfileRecognitionProof) {
    artifacts.push('zlar-installed-runtime-profile-recognition-proof-v1.json');
  }
  if (installedRuntimeProfileServiceProof) {
    artifacts.push('zlar-installed-runtime-profile-service-proof-v1.json');
  }
  if (installedRuntimeProfileServiceProofArtifactVerification) {
    artifacts.push('zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json');
  }
  if (installedRuntimeProfileTerminalChain) {
    artifacts.push('zlar-installed-runtime-profile-terminal-chain-v1.json');
  }
  if (installedRuntimeProfileTerminalChainArtifact) {
    artifacts.push('zlar-installed-runtime-profile-terminal-chain-artifact-v1.json');
  }
  if (installedRuntimeProfileTerminalChainArtifactVerification) {
    artifacts.push('zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json');
  }
  if (recognition) artifacts.push('zlar-trusted-receipt-issuer-recognition.json');
  if (trustedIssuerCompletionProof) {
    artifacts.push('zlar-trusted-receipt-issuer-completion-proof-v1.json');
  }
  if (malformedRegistryError) {
    artifacts.push('zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt');
  }
  if (verifierKitReproducibility) artifacts.push('zlar-verifier-kit-reproducibility-v1.json');
  if (verifierKitReleaseAssets) artifacts.push('zlar-verifier-kit-release-assets-v1.json');
  if (verifierKitPublicDistribution) {
    artifacts.push('zlar-verifier-kit-public-distribution-v1.json');
  }
  if (privateVerifierResultVerification) {
    artifacts.push('zlar-private-verifier-result-verification-v1.json');
  }
  if (privateVerifierZipResultVerification) {
    artifacts.push('zlar-private-verifier-zip-result-verification-v1.json');
  }
  if (publicArtifactVerifierResultVerification) {
    artifacts.push('zlar-public-artifact-verifier-result-verification-v1.json');
  }
  if (publicExternalAttestationResultVerification) {
    artifacts.push('zlar-public-external-attestation-result-verification-v1.json');
  }
  if (activePersistentProfileLifecycleEvidence) {
    artifacts.push('zlar-active-persistent-profile-lifecycle-v1.json');
    artifacts.push('zlar-active-persistent-profile-lifecycle-source-binding-v1.json');
  }
  return artifacts;
}

export function buildNorthStarReadinessReport({
  evidenceModel = NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE,
  productProofPathReport = null,
  proofSmokeVerification,
  localProofPackVerification,
  servicePreflightVerification,
  runtimeLocalActivationVerification,
  runtimeProfileInstallationVerification,
  installedRuntimeProfilePreflightVerification,
  installedRuntimeProfileRecognitionProof = null,
  installedRuntimeProfileServiceProof = null,
  installedRuntimeProfileServiceProofArtifactVerification = null,
  installedRuntimeProfileTerminalChain = null,
  installedRuntimeProfileTerminalChainArtifact = null,
  installedRuntimeProfileTerminalChainArtifactVerification = null,
  coverageMap,
  trustedIssuerRecognition = null,
  trustedReceiptIssuerCompletionProof = null,
  malformedRegistryErrorText = '',
  verifierKitReproducibility = null,
  verifierKitReleaseAssets = null,
  verifierKitPublicDistribution = null,
  privateVerifierResultVerification = null,
  privateVerifierZipResultVerification = null,
  publicArtifactVerifierResultVerification = null,
  publicExternalAttestationResultVerification = null,
  activePersistentProfileLifecycleEvidence = null,
  releaseForwardTargetTag = '',
} = {}) {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
    'North Star readiness fixture-rightful composition',
  );
  const proofCounts = proofSmokeVerification?.counts || {};
  const installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomyRequired =
    evidenceModel === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 18);
  const installedRuntimeProfileRecognitionContractDigestRequired =
    evidenceModel === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 19);
  if (installedRuntimeProfileRecognitionProof) {
    assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(
      installedRuntimeProfileRecognitionProof
    );
  }
  if (installedRuntimeProfileServiceProof) {
    assertProtectedRecordsInstalledRuntimeProfileServiceProof(
      installedRuntimeProfileServiceProof
    );
  }
  if (installedRuntimeProfileServiceProofArtifactVerification) {
    assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification(
      installedRuntimeProfileServiceProofArtifactVerification,
      {
        refusalTaxonomy:
          installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomyRequired
            ? 'required'
            : 'optional',
        recognitionContractDigest:
          installedRuntimeProfileRecognitionContractDigestRequired
            ? 'required'
            : 'optional',
      }
    );
  }
  if (installedRuntimeProfileTerminalChain) {
    assertProtectedRecordsInstalledRuntimeProfileTerminalChain(
      installedRuntimeProfileTerminalChain
    );
  }
  if (installedRuntimeProfileTerminalChainArtifact) {
    assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(
      installedRuntimeProfileTerminalChainArtifact
    );
  }
  if (installedRuntimeProfileTerminalChainArtifactVerification) {
    assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification(
      installedRuntimeProfileTerminalChainArtifactVerification
    );
  }
  const packRuntimeInstallation = localProofPackVerification?.runtime_profile_installation || {};
  const packRuntimeActivation = localProofPackVerification?.runtime_local_activation || {};
  const coverageCounts = coverageMap?.counts || {};
  const serviceLane = (coverageMap?.surfaces || []).find((surface) =>
    surface.surface_id === 'protected-records.service-profile.records.write'
  );
  const runtimeInstallLane = (coverageMap?.surfaces || []).find((surface) =>
    surface.surface_id === 'protected-records.runtime.profile-installation.records.write'
  );
  const runtimeTerminalLane = (coverageMap?.surfaces || []).find((surface) =>
    surface.surface_id ===
      'protected-records.installed-runtime-profile.terminal-chain.records.write'
  );
  const recognition = optionalRecognitionSummary(trustedIssuerRecognition);
  const trustedReceiptIssuerCompletionVerification =
    trustedReceiptIssuerCompletionProof
      ? buildTrustedReceiptIssuerCompletionVerification(trustedReceiptIssuerCompletionProof)
      : null;
  const trustedReceiptIssuerCompletion =
    readinessSummaryFromTrustedReceiptIssuerCompletionVerification(
      trustedReceiptIssuerCompletionVerification
    );
  const trustedReceiptIssuerCompletionSatisfied =
    trustedReceiptIssuerCompletion.provided === true &&
    trustedReceiptIssuerCompletion.verified === true &&
    trustedReceiptIssuerCompletion.completed_for_selected_surface === true &&
    isTrustedReceiptIssuerCompletionSurfaceId(
      trustedReceiptIssuerCompletion.selected_surface_id
    ) &&
    trustedReceiptIssuerCompletion.authority_primitive ===
      TRUSTED_RECEIPT_ISSUER_COMPLETION_AUTHORITY_PRIMITIVE &&
    trustedReceiptIssuerCompletion.core_sentence ===
      TRUSTED_RECEIPT_ISSUER_COMPLETION_CORE_SENTENCE &&
    trustedReceiptIssuerCompletion.proof_type ===
      TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF_TYPE &&
    trustedReceiptIssuerCompletion.verification_type ===
      TRUSTED_RECEIPT_ISSUER_COMPLETION_VERIFICATION_TYPE &&
    isSha256Hex(trustedReceiptIssuerCompletion.proof_sha256) &&
    isSha256Hex(trustedReceiptIssuerCompletion.issuer_public_key_sha256) &&
    isSha256Hex(trustedReceiptIssuerCompletion.registry_sha256) &&
    isSha256Hex(trustedReceiptIssuerCompletion.recognition_contract_sha256) &&
    isSha256Hex(trustedReceiptIssuerCompletion.status_source_sha256) &&
    isSha256Hex(trustedReceiptIssuerCompletion.custody_posture_sha256) &&
    isSha256Hex(trustedReceiptIssuerCompletion.key_state_sha256) &&
    trustedReceiptIssuerCompletion.receipt_validity_distinct_from_human_intention === true &&
    trustedReceiptIssuerCompletion.issuer_recognition_distinct_from_human_yes === true &&
    trustedReceiptIssuerCompletion.authority_event_distinct_from_legal_consent === true &&
    trustedReceiptIssuerCompletion.operator_registry_distinct_from_customer_production_trust === true &&
    trustedReceiptIssuerCompletion.revocation_status_not_global_certainty === true &&
    trustedReceiptIssuerCompletion.summary_only_evidence_accepted === false &&
    trustedReceiptIssuerCompletion.fixture_only_evidence_accepted === false &&
    trustedReceiptIssuerCompletion.overclaim_flags_accepted === false;
  const malformedRegistry = optionalMalformedRegistrySummary(malformedRegistryErrorText);
  const verifierKit = optionalVerifierKitReproducibilitySummary(verifierKitReproducibility);
  const verifierKitReleaseAssetRead =
    optionalVerifierKitReleaseAssetsSummary(verifierKitReleaseAssets, releaseForwardTargetTag);
  const verifierKitDistribution =
    optionalVerifierKitPublicDistributionSummary(
      verifierKitPublicDistribution,
      releaseForwardTargetTag
    );
  const releaseAssetLiveReadHandoffRequired =
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 31);
  const releaseAssetLiveReadHandoffSatisfied =
    !releaseAssetLiveReadHandoffRequired ||
    verifierKitDistribution.static_public_artifact_source_evidence === true ||
    [
      verifierKitReleaseAssetRead.provided === true,
      verifierKitReleaseAssetRead.report_type === 'zlar-verifier-kit-release-assets-live-v1',
      verifierKitReleaseAssetRead.evidence_model === 'github-release-assets-json-live-read',
      verifierKitReleaseAssetRead.repository === 'ZLAR-AI/ZLAR',
      verifierKitReleaseAssetRead.repository_matches_expected === true,
      verifierKitReleaseAssetRead.release_tag === releaseForwardTargetTag,
      verifierKitReleaseAssetRead.all_required_assets_present === true,
      verifierKitReleaseAssetRead.all_required_assets_downloaded === true,
      verifierKitReleaseAssetRead.required_asset_count === 3,
      verifierKitReleaseAssetRead.downloaded_sha256_count >= 3,
      verifierKitReleaseAssetRead.release_url_names_tag === true,
      verifierKitReleaseAssetRead.release_url_names_expected_repository === true,
      verifierKitReleaseAssetRead.asset_urls_name_expected_repository === true,
      verifierKitReleaseAssetRead.public_release_non_draft === true,
      verifierKitReleaseAssetRead.claim_boundary_flags_false === true,
    ].every(bool);
  const v34ReadyViaPublicDistribution =
    verifierKitDistribution.ready_for_public_distribution_claim === true &&
    verifierKitDistribution.required_release_assets_present === true &&
    verifierKitDistribution.public_artifact_hashes_present === true &&
    verifierKitDistribution.public_release_publication_evidence === true &&
    verifierKitDistribution.release_asset_hashes_bound === true &&
    verifierKitDistribution.local_artifact_hashes_match === true &&
    verifierKitDistribution.blocking_reasons_count === 0 &&
    releaseAssetLiveReadHandoffSatisfied;
  const privateIntakeSampleManifestPointer =
    optionalPrivateIntakeSampleManifestPointer(releaseForwardTargetTag);
  const privateVerifierResult =
    optionalPrivateVerifierResultVerificationSummary(
      privateVerifierResultVerification,
      releaseForwardTargetTag
    );
  const privateVerifierZipResult =
    optionalPrivateVerifierZipResultVerificationSummary(
      privateVerifierZipResultVerification
    );
  const publicArtifactVerifierResult =
    optionalPublicArtifactVerifierResultVerificationSummary(
      publicArtifactVerifierResultVerification
    );
  const publicExternalAttestationResult =
    optionalPublicExternalAttestationResultVerificationSummary(
      publicExternalAttestationResultVerification,
      releaseForwardTargetTag
    );
  const historicalActivePersistentProfileLifecycle =
    historicalActivePersistentProfileLifecycleSummary(
      activePersistentProfileLifecycleEvidence
    );
  const humanAuthorization = optionalHumanAuthorizationSummary(localProofPackVerification);
  const productProofPath = optionalProductProofPathSummary(productProofPathReport);
  const productProofPathDeploymentProfileAuthorityBridgeRequired =
    evidenceModel === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 48);
  const productProofPathDeploymentProfileAuthorityBridgePreserved =
    productProofPath.deployment_profile_authority_bridge_observed === true &&
    productProofPathDeploymentProfileAuthorityBridgePasses(
      productProofPath.deployment_profile_authority_bridge
    );
  const productProofPathDeploymentProfileAuthorityRefusalsRequired =
    evidenceModel === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 49);
  const productProofPathDeploymentProfileAuthorityRefusalsPreserved =
    productProofPathDeploymentProfileAuthorityBridgePreserved === true &&
    productProofPathDeploymentProfileAuthorityRefusalsPasses(
      productProofPath.deployment_profile_authority_bridge
    );
  const terminalChainDeploymentProfileAuthorityRefusalMirrorRequired =
    evidenceModel === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 50);
  const terminalChainRecognizedReceiptPathMirrorRequired =
    evidenceModel === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 52);
  const installedRuntimeProfileServiceProofAvailable =
    Boolean(installedRuntimeProfileServiceProof) &&
    proofCounts.installed_runtime_profile_service_proof_verified === true;
  const installedRuntimeProfileServiceProofArtifactVerificationAvailable =
    Boolean(installedRuntimeProfileServiceProofArtifactVerification) &&
    proofCounts.installed_runtime_profile_service_artifact_verification_verified === true;
  const installedRuntimeProfileServiceProfileSha256 =
    installedRuntimeProfileServiceProof?.selected_profile?.profile_sha256 ||
    'not-provided';
  const installedRuntimeProfileServiceRightfulContractPreserved = [
    installedRuntimeProfileServiceProofAvailable,
    installedRuntimeProfileServiceProofArtifactVerificationAvailable,
    isSha256Hex(installedRuntimeProfileServiceProfileSha256),
    installedRuntimeProfileServiceProfileSha256 ===
      installedRuntimeProfileServiceProofArtifactVerification?.selected_profile_sha256,
    installedRuntimeProfileServiceProfileSha256 ===
      runtimeTerminalLane?.issuer_identity?.recognition_anchor_id,
    installedRuntimeProfileServiceProof?.service_boundary
      ?.mutation_authoritative_route ===
      EXACT_RUNTIME_MUTATION_AUTHORITATIVE_ROUTE,
    installedRuntimeProfileServiceProof?.service_boundary
      ?.consumed_authority_grant_store ===
      'persistent-single-use-authority-grant-contract-sha256-store',
    installedRuntimeProfileServiceProof?.service_boundary?.consumption_identity ===
      'authority-grant-contract-sha256',
    installedRuntimeProfileServiceProof?.service_boundary
      ?.signed_payload_replay_identity === 'verified-signed-payload-sha256',
    installedRuntimeProfileServiceProof?.service_config_provenance
      ?.consumed_grant_store_witness_source ===
      'launcher-owned-local-proof-witness',
    installedRuntimeProfileServiceProof?.refusal_cases?.length ===
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
    installedRuntimeProfileServiceProof?.authority_refusal_cases?.length ===
      REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length,
    installedRuntimeProfileServiceProofArtifactVerification
      ?.recognition_refusal_case_count ===
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
    installedRuntimeProfileServiceProofArtifactVerification
      ?.authority_refusal_case_count ===
      REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length,
    installedRuntimeProfileServiceProofArtifactVerification
      ?.all_recognition_refusals_before_mutation === true,
    installedRuntimeProfileServiceProofArtifactVerification
      ?.all_authority_refusals_before_consumption_and_mutation === true,
    installedRuntimeProfileServiceProof?.proof_boundary
      ?.same_process_signed_payload_replay_refused === true,
    installedRuntimeProfileServiceProof?.proof_boundary
      ?.restart_consumed_authority_grant_refused === true,
    installedRuntimeProfileServiceProofArtifactVerification
      ?.same_process_signed_payload_replay_refused === true,
    installedRuntimeProfileServiceProofArtifactVerification
      ?.restart_consumed_authority_grant_refused === true,
    installedRuntimeProfileServiceProof?.authority_contract
      ?.public_safe_grant_summary?.fixture_rightful_issuance_path_evidenced ===
      true,
    installedRuntimeProfileServiceProofArtifactVerification
      ?.fixture_rightful_issuance_path_evidenced === true,
    installedRuntimeProfileServiceProofArtifactVerification
      ?.rightful_issuance_proven === false,
    installedRuntimeProfileServiceProofArtifactVerification
      ?.portable_rightful_issuance_proven === false,
    installedRuntimeProfileServiceProofArtifactVerification
      ?.production_rightful_issuance_proven === false,
    installedRuntimeProfileServiceProofArtifactVerification
      ?.current_machine_governance_proven === false,
    installedRuntimeProfileServiceProofArtifactVerification
      ?.consequence_lifecycle_closed === false,
    installedRuntimeProfileServiceProofArtifactVerification
      ?.state_append_after_grant_commit_burn_observed === true,
    installedRuntimeProfileServiceProofArtifactVerification
      ?.metadata_partial_commit_burn_observed === true,
    installedRuntimeProfileServiceProofArtifactVerification
      ?.store_and_anchor_rollback_refused_while_witness_ahead === true,
    installedRuntimeProfileServiceProofArtifactVerification
      ?.store_anchor_and_witness_joint_rollback_detection === false,
    installedRuntimeProfileServiceProofArtifactVerification
      ?.joint_rollback_reopened_authority_grant_reuse === true,
  ].every(bool);
  const installedRuntimeProfileServiceProofArtifactVerificationRequired =
    evidenceModel === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 14);
  const installedRuntimeProfileServiceProofArtifactVerificationExpected =
    installedRuntimeProfileServiceProofArtifactVerificationRequired ||
    Boolean(installedRuntimeProfileServiceProofArtifactVerification);
  const installedRuntimeProfileServiceProofArtifactVerificationSatisfied =
    !installedRuntimeProfileServiceProofArtifactVerificationExpected ||
    installedRuntimeProfileServiceProofArtifactVerificationAvailable;
  const installedRuntimeProfileTerminalChainAvailable =
    Boolean(installedRuntimeProfileTerminalChain) &&
    proofCounts.installed_runtime_profile_terminal_chain_verified === true;
  const installedRuntimeProfileTerminalChainArtifactVerificationAvailable =
    Boolean(installedRuntimeProfileTerminalChainArtifactVerification) &&
    proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_verified === true;
  const installedRuntimeProfileTerminalChainRequired =
    evidenceModel === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 15);
  const installedRuntimeProfileTerminalChainExpected =
    installedRuntimeProfileTerminalChainRequired ||
    Boolean(installedRuntimeProfileTerminalChain) ||
    Boolean(installedRuntimeProfileTerminalChainArtifactVerification);
  const installedRuntimeProfileServiceProofArtifactBodySha256 =
    installedRuntimeProfileServiceProof
      ? protectedRecordsInstalledRuntimeProfileServiceProofArtifactBodySha256(installedRuntimeProfileServiceProof)
      : null;
  const installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomyExpected =
    installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomyRequired ||
    (Boolean(installedRuntimeProfileServiceProofArtifactVerification) &&
      [
        hasText(proofCounts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256),
        hasText(installedRuntimeProfileServiceProofArtifactVerification?.refusal_taxonomy_sha256),
      ].some(bool));
  const installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomySha256 =
    installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomyExpected
      ? proofCounts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256 ||
        'not-provided'
      : 'not-provided';
  const installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomyPreserved =
    installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomyExpected &&
    [
      isSha256Hex(installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomySha256),
      installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomySha256 ===
        installedRuntimeProfileServiceProofArtifactVerification
          ?.recognition_refusal_taxonomy_sha256,
    ].every(bool);
  const installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomySatisfied =
    !installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomyExpected ||
    installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomyPreserved;
  const installedRuntimeProfileTerminalChainArtifactVerificationBodySha256 =
    installedRuntimeProfileTerminalChainArtifactVerification?.body_sha256 ||
    proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_body_sha256 ||
    'not-provided';
  const installedRuntimeProfileTerminalChainArtifactVerificationBodyBoundToArtifact =
    !installedRuntimeProfileTerminalChainArtifact ||
    installedRuntimeProfileTerminalChainArtifactVerificationBodySha256 ===
      installedRuntimeProfileTerminalChainArtifact?.integrity?.body_sha256;
  const installedRuntimeProfileTerminalChainRefusalTaxonomyRequired =
    evidenceModel === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 17);
  const installedRuntimeProfileTerminalChainRefusalTaxonomyExpected =
    installedRuntimeProfileTerminalChainRefusalTaxonomyRequired ||
    Boolean(installedRuntimeProfileTerminalChain) ||
    Boolean(installedRuntimeProfileTerminalChainArtifactVerification);
  const installedRuntimeProfileTerminalChainRefusalTaxonomySha256 =
    installedRuntimeProfileTerminalChainRefusalTaxonomyExpected
      ? proofCounts.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256 || 'not-provided'
      : 'not-provided';
  const installedRuntimeProfileTerminalChainArtifactVerificationRefusalTaxonomySha256 =
    installedRuntimeProfileTerminalChainRefusalTaxonomyExpected
      ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256 ||
        'not-provided'
      : 'not-provided';
  const installedRuntimeProfileTerminalChainRefusalTaxonomyPreserved =
    installedRuntimeProfileTerminalChainRefusalTaxonomyExpected &&
    [
      isSha256Hex(installedRuntimeProfileTerminalChainRefusalTaxonomySha256),
      isSha256Hex(installedRuntimeProfileTerminalChainArtifactVerificationRefusalTaxonomySha256),
      installedRuntimeProfileTerminalChainRefusalTaxonomySha256 ===
        installedRuntimeProfileTerminalChain?.terminal_chain
          ?.recognition_refusal_taxonomy_sha256,
      installedRuntimeProfileTerminalChainRefusalTaxonomySha256 ===
        installedRuntimeProfileTerminalChain?.generated_service_proof
          ?.recognition_refusal_taxonomy_sha256,
      installedRuntimeProfileTerminalChainArtifactVerificationRefusalTaxonomySha256 ===
        installedRuntimeProfileTerminalChainArtifactVerification
          ?.recognition_refusal_taxonomy_sha256,
      installedRuntimeProfileTerminalChainArtifactVerificationRefusalTaxonomySha256 ===
        installedRuntimeProfileTerminalChainRefusalTaxonomySha256,
    ].every(bool);
  const installedRuntimeProfileTerminalChainRefusalTaxonomySatisfied =
    !installedRuntimeProfileTerminalChainRefusalTaxonomyExpected ||
    installedRuntimeProfileTerminalChainRefusalTaxonomyPreserved;
  const installedRuntimeProfileTerminalChainNamedReceiptRefusalsRequired =
    evidenceModel === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 22);
  const installedRuntimeProfileTerminalChainNamedReceiptRefusalsExpected =
    installedRuntimeProfileTerminalChainNamedReceiptRefusalsRequired ||
    [
      installedRuntimeProfileTerminalChain?.terminal_chain?.named_receipt_refusals_sha256,
      installedRuntimeProfileTerminalChainArtifactVerification?.named_receipt_refusals_sha256,
    ].some(hasText);
  const installedRuntimeProfileTerminalChainNamedReceiptRefusalsSha256 =
    installedRuntimeProfileTerminalChainNamedReceiptRefusalsExpected
      ? proofCounts.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256 ||
        'not-provided'
      : 'not-provided';
  const installedRuntimeProfileTerminalChainArtifactVerificationNamedReceiptRefusalsSha256 =
    installedRuntimeProfileTerminalChainNamedReceiptRefusalsExpected
      ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256 ||
        'not-provided'
      : 'not-provided';
  const installedRuntimeProfileTerminalChainNamedReceiptRefusalsPreserved =
    installedRuntimeProfileTerminalChainNamedReceiptRefusalsExpected &&
    [
      isSha256Hex(installedRuntimeProfileTerminalChainNamedReceiptRefusalsSha256),
      isSha256Hex(installedRuntimeProfileTerminalChainArtifactVerificationNamedReceiptRefusalsSha256),
      installedRuntimeProfileTerminalChainNamedReceiptRefusalsSha256 ===
        installedRuntimeProfileTerminalChain?.terminal_chain?.named_receipt_refusals_sha256,
      installedRuntimeProfileTerminalChainNamedReceiptRefusalsSha256 ===
        installedRuntimeProfileTerminalChain?.generated_service_proof?.named_receipt_refusals_sha256,
      installedRuntimeProfileTerminalChainArtifactVerificationNamedReceiptRefusalsSha256 ===
        installedRuntimeProfileTerminalChainArtifactVerification?.named_receipt_refusals_sha256,
      installedRuntimeProfileTerminalChainArtifactVerificationNamedReceiptRefusalsSha256 ===
        installedRuntimeProfileTerminalChainNamedReceiptRefusalsSha256,
    ].every(bool);
  const installedRuntimeProfileTerminalChainNamedReceiptRefusalsSatisfied =
    !installedRuntimeProfileTerminalChainNamedReceiptRefusalsExpected ||
    installedRuntimeProfileTerminalChainNamedReceiptRefusalsPreserved;
  const installedRuntimeProfileTerminalChainRecognitionRefusalGroupsRequired =
    evidenceModel === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 23);
  const installedRuntimeProfileTerminalChainRecognitionRefusalGroupsExpected =
    installedRuntimeProfileTerminalChainRecognitionRefusalGroupsRequired ||
    [
      installedRuntimeProfileTerminalChain?.terminal_chain?.recognition_refusal_groups_sha256,
      installedRuntimeProfileTerminalChainArtifactVerification?.recognition_refusal_groups_sha256,
    ].some(hasText);
  const installedRuntimeProfileTerminalChainRecognitionRefusalGroupsSha256 =
    installedRuntimeProfileTerminalChainRecognitionRefusalGroupsExpected
      ? proofCounts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256 ||
        'not-provided'
      : 'not-provided';
  const installedRuntimeProfileTerminalChainArtifactVerificationRecognitionRefusalGroupsSha256 =
    installedRuntimeProfileTerminalChainRecognitionRefusalGroupsExpected
      ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256 ||
        'not-provided'
      : 'not-provided';
  const installedRuntimeProfileTerminalChainRecognitionRefusalGroupsPreserved =
    installedRuntimeProfileTerminalChainRecognitionRefusalGroupsExpected &&
    [
      isSha256Hex(installedRuntimeProfileTerminalChainRecognitionRefusalGroupsSha256),
      isSha256Hex(installedRuntimeProfileTerminalChainArtifactVerificationRecognitionRefusalGroupsSha256),
      installedRuntimeProfileTerminalChainRecognitionRefusalGroupsSha256 ===
        installedRuntimeProfileTerminalChain?.terminal_chain?.recognition_refusal_groups_sha256,
      installedRuntimeProfileTerminalChainRecognitionRefusalGroupsSha256 ===
        installedRuntimeProfileTerminalChain?.generated_service_proof?.recognition_refusal_groups_sha256,
      installedRuntimeProfileTerminalChainArtifactVerificationRecognitionRefusalGroupsSha256 ===
        installedRuntimeProfileTerminalChainArtifactVerification?.recognition_refusal_groups_sha256,
      installedRuntimeProfileTerminalChainArtifactVerificationRecognitionRefusalGroupsSha256 ===
        installedRuntimeProfileTerminalChainRecognitionRefusalGroupsSha256,
    ].every(bool);
  const installedRuntimeProfileTerminalChainRecognitionRefusalGroupsSatisfied =
    !installedRuntimeProfileTerminalChainRecognitionRefusalGroupsExpected ||
    installedRuntimeProfileTerminalChainRecognitionRefusalGroupsPreserved;
  const installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsRequired =
    evidenceModel === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 25);
  const installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected =
    installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsRequired ||
    (
      Boolean(installedRuntimeProfileTerminalChain) &&
      Boolean(installedRuntimeProfileTerminalChainArtifactVerification) &&
      [
        proofCounts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids,
        proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids,
      ].some(isObject)
    );
  const installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsPreserved =
    installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected &&
    [
      proofCounts.installed_runtime_profile_terminal_chain_recognition_refusal_group_count ===
        Object.keys(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS).length,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count ===
        Object.keys(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS).length,
      proofCounts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
      recognitionRefusalGroupCaseIdsMatch(
        proofCounts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids,
        installedRuntimeProfileTerminalChain?.terminal_chain?.recognition_refusal_groups
      ),
      recognitionRefusalGroupCaseIdsMatch(
        proofCounts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids,
        installedRuntimeProfileTerminalChain?.generated_service_proof?.recognition_refusal_groups
      ),
      recognitionRefusalGroupCaseIdsMatch(
        proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids,
        installedRuntimeProfileTerminalChainArtifactVerification?.recognition_refusal_groups
      ),
      JSON.stringify(
        proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids
      ) ===
        JSON.stringify(
          proofCounts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids
        ),
    ].every(bool);
  const installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsSatisfied =
    !installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected ||
    installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsPreserved;
  const installedRuntimeProfileTerminalChainNestedArtifactBindingRequired =
    evidenceModel === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 30);
  const installedRuntimeProfileTerminalChainNestedArtifactBindingExpected =
    installedRuntimeProfileTerminalChainNestedArtifactBindingRequired ||
    [
      proofCounts.installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved,
      installedRuntimeProfileTerminalChain?.terminal_chain?.nested_artifact_binding,
      installedRuntimeProfileTerminalChainArtifactVerification?.nested_artifact_binding,
    ].some(Boolean);
  const installedRuntimeProfileTerminalChainNestedArtifactBinding =
    installedRuntimeProfileTerminalChain?.terminal_chain?.nested_artifact_binding || {};
  const installedRuntimeProfileTerminalChainArtifactVerificationNestedArtifactBinding =
    installedRuntimeProfileTerminalChainArtifactVerification?.nested_artifact_binding || {};
  const installedRuntimeProfileTerminalChainNestedPreflightArtifactType =
    installedRuntimeProfileTerminalChainNestedArtifactBindingExpected
      ? proofCounts.installed_runtime_profile_terminal_chain_nested_preflight_artifact_type ||
        'not-provided'
      : 'not-provided';
  const installedRuntimeProfileTerminalChainNestedServiceProofArtifactType =
    installedRuntimeProfileTerminalChainNestedArtifactBindingExpected
      ? proofCounts.installed_runtime_profile_terminal_chain_nested_service_proof_artifact_type ||
        'not-provided'
      : 'not-provided';
  const installedRuntimeProfileTerminalChainArtifactVerificationNestedPreflightArtifactType =
    installedRuntimeProfileTerminalChainNestedArtifactBindingExpected
      ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_nested_preflight_artifact_type ||
        'not-provided'
      : 'not-provided';
  const installedRuntimeProfileTerminalChainArtifactVerificationNestedServiceProofArtifactType =
    installedRuntimeProfileTerminalChainNestedArtifactBindingExpected
      ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_nested_service_proof_artifact_type ||
        'not-provided'
      : 'not-provided';
  const installedRuntimeProfileTerminalChainNestedArtifactBindingPreserved =
    installedRuntimeProfileTerminalChainNestedArtifactBindingExpected &&
    [
      proofCounts.installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved === true,
      installedRuntimeProfileTerminalChainNestedPreflightArtifactType ===
        INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NESTED_PREFLIGHT_ARTIFACT_TYPE,
      installedRuntimeProfileTerminalChainNestedServiceProofArtifactType ===
        INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NESTED_SERVICE_PROOF_ARTIFACT_TYPE,
      installedRuntimeProfileTerminalChainArtifactVerificationNestedPreflightArtifactType ===
        INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NESTED_PREFLIGHT_ARTIFACT_TYPE,
      installedRuntimeProfileTerminalChainArtifactVerificationNestedServiceProofArtifactType ===
        INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NESTED_SERVICE_PROOF_ARTIFACT_TYPE,
      installedRuntimeProfileTerminalChainNestedArtifactBinding.generated_preflight_artifact_type ===
        INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NESTED_PREFLIGHT_ARTIFACT_TYPE,
      installedRuntimeProfileTerminalChainNestedArtifactBinding.generated_service_proof_artifact_type ===
        INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NESTED_SERVICE_PROOF_ARTIFACT_TYPE,
      isSha256Hex(
        installedRuntimeProfileTerminalChainNestedArtifactBinding.generated_preflight_artifact_body_sha256
      ),
      isSha256Hex(
        installedRuntimeProfileTerminalChainNestedArtifactBinding.generated_service_proof_artifact_body_sha256
      ),
      installedRuntimeProfileTerminalChainNestedArtifactBinding.generated_preflight_artifact_verified === true,
      installedRuntimeProfileTerminalChainNestedArtifactBinding.generated_service_proof_artifact_verified === true,
      installedRuntimeProfileTerminalChainNestedArtifactBinding.preflight_artifact_hash_bound === true,
      installedRuntimeProfileTerminalChainNestedArtifactBinding.service_proof_source_preflight_hash_bound === true,
      installedRuntimeProfileTerminalChainNestedArtifactBinding.service_artifact_hash_bound === true,
      installedRuntimeProfileTerminalChainNestedArtifactBinding.service_artifact_verification_bound_to_service_proof === true,
      installedRuntimeProfileTerminalChainNestedArtifactBinding.creates_public_external_attestation === false,
      installedRuntimeProfileTerminalChainNestedArtifactBinding.proves_non_operator_review === false,
      installedRuntimeProfileTerminalChainNestedArtifactBinding.proves_current_machine_governance === false,
      installedRuntimeProfileTerminalChainNestedArtifactBinding.proves_production_downstream_recognition === false,
      installedRuntimeProfileTerminalChainArtifactVerificationNestedArtifactBinding.generated_preflight_artifact_type ===
        INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NESTED_PREFLIGHT_ARTIFACT_TYPE,
      installedRuntimeProfileTerminalChainArtifactVerificationNestedArtifactBinding.generated_service_proof_artifact_type ===
        INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NESTED_SERVICE_PROOF_ARTIFACT_TYPE,
      installedRuntimeProfileTerminalChainArtifactVerificationNestedArtifactBinding.generated_preflight_artifact_body_sha256 ===
        installedRuntimeProfileTerminalChainNestedArtifactBinding.generated_preflight_artifact_body_sha256,
      installedRuntimeProfileTerminalChainArtifactVerificationNestedArtifactBinding.generated_service_proof_artifact_body_sha256 ===
        installedRuntimeProfileTerminalChainNestedArtifactBinding.generated_service_proof_artifact_body_sha256,
      installedRuntimeProfileTerminalChainArtifactVerificationNestedArtifactBinding.generated_preflight_artifact_verified === true,
      installedRuntimeProfileTerminalChainArtifactVerificationNestedArtifactBinding.generated_service_proof_artifact_verified === true,
      installedRuntimeProfileTerminalChainArtifactVerificationNestedArtifactBinding.preflight_artifact_hash_bound === true,
      installedRuntimeProfileTerminalChainArtifactVerificationNestedArtifactBinding.service_proof_source_preflight_hash_bound === true,
      installedRuntimeProfileTerminalChainArtifactVerificationNestedArtifactBinding.service_artifact_hash_bound === true,
      installedRuntimeProfileTerminalChainArtifactVerificationNestedArtifactBinding.service_artifact_verification_bound_to_service_proof === true,
      installedRuntimeProfileTerminalChainArtifactVerificationNestedArtifactBinding.creates_public_external_attestation === false,
      installedRuntimeProfileTerminalChainArtifactVerificationNestedArtifactBinding.proves_non_operator_review === false,
      installedRuntimeProfileTerminalChainArtifactVerificationNestedArtifactBinding.proves_current_machine_governance === false,
      installedRuntimeProfileTerminalChainArtifactVerificationNestedArtifactBinding.proves_production_downstream_recognition === false,
    ].every(bool);
  const installedRuntimeProfileTerminalChainNestedArtifactBindingSatisfied =
    !installedRuntimeProfileTerminalChainNestedArtifactBindingExpected ||
    installedRuntimeProfileTerminalChainNestedArtifactBindingPreserved;
  const installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingRequired =
    evidenceModel === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 37);
  const installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingExpected =
    installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingRequired ||
    [
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.trusted_issuer_registry_recognition_binding,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.trusted_issuer_registry_recognition_binding,
    ].some(isObject);
  const installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingSha256 =
    installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingExpected
      ? installedRuntimeProfileTerminalChain?.terminal_chain
        ?.trusted_issuer_registry_recognition_binding_sha256 ||
        proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256 ||
        'not-provided'
      : 'not-provided';
  const installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBindingSha256 =
    installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingExpected
      ? installedRuntimeProfileTerminalChainArtifactVerification
        ?.trusted_issuer_registry_recognition_binding_sha256 ||
        proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256 ||
        'not-provided'
      : 'not-provided';
  const installedRuntimeProfileTerminalChainTrustedIssuerRegistryBinding =
    installedRuntimeProfileTerminalChain?.terminal_chain
      ?.trusted_issuer_registry_recognition_binding || {};
  const installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBinding =
    installedRuntimeProfileTerminalChainArtifactVerification
      ?.trusted_issuer_registry_recognition_binding || {};
  const installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingPreserved =
    installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingExpected &&
    [
      proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_preserved === true,
      isSha256Hex(installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingSha256),
      isSha256Hex(installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBindingSha256),
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingSha256 ===
        installedRuntimeProfileTerminalChain?.terminal_chain
          ?.trusted_issuer_registry_recognition_binding_sha256,
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingSha256 ===
        installedRuntimeProfileTerminalChainTrustedIssuerRegistryBinding.binding_sha256,
      installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBindingSha256 ===
        installedRuntimeProfileTerminalChainArtifactVerification
          ?.trusted_issuer_registry_recognition_binding_sha256,
      installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBindingSha256 ===
        installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBinding.binding_sha256,
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryBinding.verdict === 'RECOGNIZED',
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryBinding.recognized === true,
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryBinding.registry_fixture_validated === true,
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryBinding.registry_to_recognition_rule_evaluated === true,
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryBinding.recognition_contract_hash_bound === true,
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryBinding.service_artifact_hash_bound === true,
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryBinding.registry_receipt_contract_hash_bound === true,
      terminalChainTrustedIssuerRegistryFalseBoundaryPreserved(
        installedRuntimeProfileTerminalChainTrustedIssuerRegistryBinding
      ),
      installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBinding.verdict === 'RECOGNIZED',
      installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBinding.recognized === true,
      installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBinding.registry_fixture_validated === true,
      installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBinding.registry_to_recognition_rule_evaluated === true,
      installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBinding.recognition_contract_hash_bound === true,
      installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBinding.service_artifact_hash_bound === true,
      installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBinding.registry_receipt_contract_hash_bound === true,
      terminalChainTrustedIssuerRegistryFalseBoundaryPreserved(
        installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBinding
      ),
    ].every(bool);
  const installedRuntimeProfileTerminalChainTrustedIssuerRegistryRecognitionRefusalsSha256 =
    installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingExpected
      ? installedRuntimeProfileTerminalChainTrustedIssuerRegistryBinding
        .trusted_issuer_registry_recognition_refusals_sha256 ||
        proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256 ||
        'not-provided'
      : 'not-provided';
  const installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryRecognitionRefusalsSha256 =
    installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingExpected
      ? installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBinding
        .trusted_issuer_registry_recognition_refusals_sha256 ||
        proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256 ||
        'not-provided'
      : 'not-provided';
  const installedRuntimeProfileTerminalChainTrustedIssuerRegistryRecognitionRefusalsPreserved =
    installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingExpected &&
    [
      proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS.length,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS.length,
      proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused === true,
      JSON.stringify(
        proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids
      ) === JSON.stringify(expectedTrustedIssuerRegistryRecognitionRefusalCaseIds()),
      JSON.stringify(
        proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids
      ) === JSON.stringify(expectedTrustedIssuerRegistryRecognitionRefusalCaseIds()),
      JSON.stringify(
        proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes
      ) === JSON.stringify(expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes()),
      JSON.stringify(
        proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes
      ) === JSON.stringify(expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes()),
      isSha256Hex(installedRuntimeProfileTerminalChainTrustedIssuerRegistryRecognitionRefusalsSha256),
      isSha256Hex(installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryRecognitionRefusalsSha256),
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryRecognitionRefusalsSha256 ===
        installedRuntimeProfileTerminalChainTrustedIssuerRegistryBinding.trusted_issuer_registry_recognition_refusals_sha256,
      installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryRecognitionRefusalsSha256 ===
        installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBinding.trusted_issuer_registry_recognition_refusals_sha256,
      installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryRecognitionRefusalsSha256 ===
        installedRuntimeProfileTerminalChainTrustedIssuerRegistryRecognitionRefusalsSha256,
    ].every(bool);
  const installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingSatisfied =
    !installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingExpected ||
    (
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingPreserved &&
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryRecognitionRefusalsPreserved
    );
  const terminalChainRecognizedReceiptPathMirrorExpected =
    terminalChainRecognizedReceiptPathMirrorRequired ||
    [
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.recognized_receipt_path_evidence,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.recognized_receipt_path_evidence,
    ].some(isObject);
  const terminalChainRecognizedReceiptPathEvidence =
    installedRuntimeProfileTerminalChain?.terminal_chain
      ?.recognized_receipt_path_evidence || {};
  const terminalChainArtifactVerificationRecognizedReceiptPathEvidence =
    installedRuntimeProfileTerminalChainArtifactVerification
      ?.recognized_receipt_path_evidence || {};
  const terminalChainRecognizedReceiptPathEvidenceSha256 =
    terminalChainRecognizedReceiptPathMirrorExpected
      ? installedRuntimeProfileTerminalChain?.terminal_chain
        ?.recognized_receipt_path_evidence_sha256 || 'not-provided'
      : 'not-provided';
  const terminalChainArtifactVerificationRecognizedReceiptPathEvidenceSha256 =
    terminalChainRecognizedReceiptPathMirrorExpected
      ? installedRuntimeProfileTerminalChainArtifactVerification
        ?.recognized_receipt_path_evidence_sha256 || 'not-provided'
      : 'not-provided';
  const terminalChainRecognizedReceiptPathSourceBindingSha256 =
    terminalChainRecognizedReceiptPathMirrorExpected
      ? terminalChainRecognizedReceiptPathEvidence.source_binding_sha256 ||
        'not-provided'
      : 'not-provided';
  const terminalChainArtifactVerificationRecognizedReceiptPathSourceBindingSha256 =
    terminalChainRecognizedReceiptPathMirrorExpected
      ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence
        .source_binding_sha256 || 'not-provided'
      : 'not-provided';
  const terminalChainRecognizedReceiptPathSourceBindingMatchesTrustedRegistryBinding =
    terminalChainRecognizedReceiptPathMirrorExpected &&
    terminalChainRecognizedReceiptPathSourceBindingSha256 ===
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingSha256;
  const terminalChainArtifactVerificationRecognizedReceiptPathSourceBindingMatchesTrustedRegistryBinding =
    terminalChainRecognizedReceiptPathMirrorExpected &&
    terminalChainArtifactVerificationRecognizedReceiptPathSourceBindingSha256 ===
      installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBindingSha256;
  const terminalChainRecognizedReceiptPathSourceBindingsMatchTrustedRegistryBinding =
    terminalChainRecognizedReceiptPathSourceBindingMatchesTrustedRegistryBinding &&
    terminalChainArtifactVerificationRecognizedReceiptPathSourceBindingMatchesTrustedRegistryBinding;
  const terminalChainRecognizedReceiptPathMirrorPreserved =
    terminalChainRecognizedReceiptPathMirrorExpected &&
    [
      isSha256Hex(terminalChainRecognizedReceiptPathEvidenceSha256),
      isSha256Hex(
        terminalChainArtifactVerificationRecognizedReceiptPathEvidenceSha256
      ),
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.recognized_receipt_path_evidence_bound_to_artifact_body === true,
      terminalChainRecognizedReceiptPathSourceBindingsMatchTrustedRegistryBinding,
      terminalChainRecognizedReceiptPathEvidence.verdict === 'RECOGNIZED',
      terminalChainRecognizedReceiptPathEvidence.recognized === true,
      terminalChainArtifactVerificationRecognizedReceiptPathEvidence.verdict ===
        'RECOGNIZED',
      terminalChainArtifactVerificationRecognizedReceiptPathEvidence.recognized ===
        true,
      terminalChainRecognizedReceiptPathFalseBoundaryPreserved(
        terminalChainRecognizedReceiptPathEvidence
      ),
      terminalChainRecognizedReceiptPathFalseBoundaryPreserved(
        terminalChainArtifactVerificationRecognizedReceiptPathEvidence
      ),
    ].every(bool);
  const terminalChainRecognizedReceiptPathMirrorSatisfied =
    !terminalChainRecognizedReceiptPathMirrorExpected ||
    terminalChainRecognizedReceiptPathMirrorPreserved;
  const terminalChainDeploymentProfileAuthorityRefusalMirrorExpected =
    terminalChainDeploymentProfileAuthorityRefusalMirrorRequired ||
    [
      proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_preserved,
      installedRuntimeProfileTerminalChain?.terminal_chain?.deployment_profile_authority_refusal_mirror,
      installedRuntimeProfileTerminalChainArtifactVerification?.deployment_profile_authority_refusal_mirror,
    ].some(Boolean);
  const terminalChainDeploymentProfileAuthorityRefusalMirror =
    installedRuntimeProfileTerminalChain?.terminal_chain
      ?.deployment_profile_authority_refusal_mirror || {};
  const terminalChainArtifactVerificationDeploymentProfileAuthorityRefusalMirror =
    installedRuntimeProfileTerminalChainArtifactVerification
      ?.deployment_profile_authority_refusal_mirror || {};
  const terminalChainDeploymentProfileAuthorityRefusalMirrorPreserved =
    terminalChainDeploymentProfileAuthorityRefusalMirrorExpected &&
    [
      proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_preserved === true,
      proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_profile_sha_matches === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_profile_sha_matches === true,
      proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count ===
        REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count ===
        REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length,
      JSON.stringify(
        proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids
      ) === JSON.stringify(REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES),
      JSON.stringify(
        proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids
      ) === JSON.stringify(REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES),
      proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof === true,
      proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation === true,
      proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started === false,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started === false,
      proofCounts.installed_runtime_profile_terminal_chain_stale_deployment_profile_artifact_refused_before_service_proof === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_stale_deployment_profile_artifact_refused_before_service_proof === true,
      proofCounts.installed_runtime_profile_terminal_chain_profile_recognition_mismatch_refused_before_service_proof === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_profile_recognition_mismatch_refused_before_service_proof === true,
      proofCounts.installed_runtime_profile_terminal_chain_latest_profile_selection_refused_before_service_proof === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_latest_profile_selection_refused_before_service_proof === true,
      proofCounts.installed_runtime_profile_terminal_chain_request_stream_authority_material_refused_before_service_proof === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_request_stream_authority_material_refused_before_service_proof === true,
      proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance === false,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_current_machine_governance === false,
      proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition === false,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_downstream_recognition === false,
      proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority === false,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_authority === false,
      proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness === false,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_enterprise_readiness === false,
      proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation === false,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_external_attestation === false,
      proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition === false,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_sovereign_recognition === false,
      proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage === false,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_unrouted_surface_coverage === false,
      terminalChainDeploymentProfileAuthorityRefusalMirrorPasses(
        terminalChainDeploymentProfileAuthorityRefusalMirror
      ),
      terminalChainDeploymentProfileAuthorityRefusalMirrorPasses(
        terminalChainArtifactVerificationDeploymentProfileAuthorityRefusalMirror
      ),
    ].every(bool);
  const terminalChainDeploymentProfileAuthorityRefusalMirrorSatisfied =
    !terminalChainDeploymentProfileAuthorityRefusalMirrorExpected ||
    terminalChainDeploymentProfileAuthorityRefusalMirrorPreserved;
  const installedRuntimeProfileRecognitionContractDigestExpected =
    installedRuntimeProfileRecognitionContractDigestRequired ||
    [
      proofCounts.installed_runtime_profile_preflight_recognition_contract_sha256,
      proofCounts.installed_runtime_profile_service_recognition_contract_sha256,
      proofCounts.installed_runtime_profile_service_artifact_verification_recognition_contract_sha256,
      proofCounts.installed_runtime_profile_terminal_chain_recognition_contract_sha256,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_contract_sha256,
    ].some(hasText);
  const installedRuntimeProfileRecognitionContractSha256 =
    installedRuntimeProfileRecognitionContractDigestExpected
      ? proofCounts.installed_runtime_profile_preflight_recognition_contract_sha256 ||
        'not-provided'
      : 'not-provided';
  const recognitionContractDigestCountValues = [
    proofCounts.installed_runtime_profile_preflight_recognition_contract_sha256,
    proofCounts.installed_runtime_profile_service_recognition_contract_sha256,
    proofCounts.installed_runtime_profile_service_artifact_verification_recognition_contract_sha256,
    proofCounts.installed_runtime_profile_terminal_chain_recognition_contract_sha256,
    proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_contract_sha256,
  ];
  const digestCountMatches = (value) =>
    installedRuntimeProfileRecognitionContractDigestRequired
      ? value === installedRuntimeProfileRecognitionContractSha256
      : !hasText(value) || value === installedRuntimeProfileRecognitionContractSha256;
  const digestObjectMatches = (value) =>
    installedRuntimeProfileRecognitionContractDigestRequired
      ? value === installedRuntimeProfileRecognitionContractSha256
      : value == null || value === installedRuntimeProfileRecognitionContractSha256;
  const installedRuntimeProfileRecognitionContractDigestPreserved =
    installedRuntimeProfileRecognitionContractDigestExpected &&
    [
      isSha256Hex(installedRuntimeProfileRecognitionContractSha256),
      recognitionContractDigestCountValues.every(digestCountMatches),
      digestObjectMatches(installedRuntimeProfilePreflightVerification?.recognition_contract_sha256),
      digestObjectMatches(installedRuntimeProfileServiceProof?.source_preflight?.recognition_contract_sha256),
      digestObjectMatches(installedRuntimeProfileServiceProof?.recognition_contract?.recognition_contract_sha256),
      digestObjectMatches(installedRuntimeProfileServiceProofArtifactVerification?.recognition_contract_sha256),
      digestObjectMatches(installedRuntimeProfileTerminalChain?.generated_preflight?.recognition_contract_sha256),
      digestObjectMatches(installedRuntimeProfileTerminalChain?.generated_service_proof?.recognition_contract_sha256),
      digestObjectMatches(installedRuntimeProfileTerminalChain?.terminal_chain?.recognition_contract_sha256),
      digestObjectMatches(installedRuntimeProfileTerminalChainArtifactVerification?.recognition_contract_sha256),
    ].every(bool);
  const installedRuntimeProfileRecognitionContractDigestSatisfied =
    !installedRuntimeProfileRecognitionContractDigestExpected ||
    installedRuntimeProfileRecognitionContractDigestPreserved;
  const installedRuntimeProfileTerminalChainPreserved =
    installedRuntimeProfileTerminalChainExpected &&
    [
      Boolean(installedRuntimeProfileTerminalChain),
      Boolean(installedRuntimeProfileTerminalChainArtifactVerification),
      installedRuntimeProfileTerminalChainAvailable,
      installedRuntimeProfileTerminalChainArtifactVerificationAvailable,
      proofCounts.installed_runtime_profile_terminal_chain_generated_installed_root_preflighted === true,
      proofCounts.installed_runtime_profile_terminal_chain_generated_preflight_consumed === true,
      proofCounts.installed_runtime_profile_terminal_chain_generated_service_artifact_verified === true,
      proofCounts.installed_runtime_profile_terminal_chain_service_proof_bound_to_generated_preflight === true,
      proofCounts.installed_runtime_profile_terminal_chain_service_artifact_verification_bound_to_service_proof === true,
      proofCounts.installed_runtime_profile_terminal_chain_recognized_write_boarded === true,
      proofCounts.installed_runtime_profile_terminal_chain_missing_receipt_refused_before_mutation === true,
      proofCounts.installed_runtime_profile_terminal_chain_invalid_receipt_refused_before_mutation === true,
      proofCounts.installed_runtime_profile_terminal_chain_recognition_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
      proofCounts.installed_runtime_profile_terminal_chain_authority_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length,
      proofCounts.installed_runtime_profile_terminal_chain_all_authority_refusals_before_consumption_and_mutation === true,
      proofCounts.installed_runtime_profile_terminal_chain_same_process_signed_payload_replay_refused === true,
      proofCounts.installed_runtime_profile_terminal_chain_restart_consumed_authority_grant_refused === true,
      proofCounts.installed_runtime_profile_terminal_chain_fixture_rightful_issuance_path_evidenced === true,
      proofCounts.installed_runtime_profile_terminal_chain_state_append_after_grant_commit_burn_observed === true,
      proofCounts.installed_runtime_profile_terminal_chain_metadata_partial_commit_burn_observed === true,
      proofCounts.installed_runtime_profile_terminal_chain_store_and_anchor_rollback_refused_while_witness_ahead === true,
      proofCounts.installed_runtime_profile_terminal_chain_store_anchor_and_witness_joint_rollback_detection === false,
      proofCounts.installed_runtime_profile_terminal_chain_joint_rollback_reopened_authority_grant_reuse === true,
      proofCounts.installed_runtime_profile_terminal_chain_persistent_runtime_profile_installed === false,
      proofCounts.installed_runtime_profile_terminal_chain_activation_performed === false,
      proofCounts.installed_runtime_profile_terminal_chain_hook_configuration_written === false,
      proofCounts.installed_runtime_profile_terminal_chain_current_machine_governance_proven === false,
      proofCounts.installed_runtime_profile_terminal_chain_production_downstream_recognition === false,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_verified === true,
      isSha256Hex(installedRuntimeProfileTerminalChainArtifactVerificationBodySha256),
      installedRuntimeProfileTerminalChainArtifactVerificationBodySha256 ===
        installedRuntimeProfileTerminalChainArtifactVerification?.body_sha256,
      installedRuntimeProfileTerminalChainArtifactVerificationBodyBoundToArtifact,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_authority_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_all_authority_refusals_before_consumption_and_mutation === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_same_process_signed_payload_replay_refused === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_restart_consumed_authority_grant_refused === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_fixture_rightful_issuance_path_evidenced === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_state_append_after_grant_commit_burn_observed === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_metadata_partial_commit_burn_observed === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_store_and_anchor_rollback_refused_while_witness_ahead === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_store_anchor_and_witness_joint_rollback_detection === false,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_joint_rollback_reopened_authority_grant_reuse === true,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_host_filesystem_path_toctou_closed === false,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_current_machine_governance_proven === false,
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_production_downstream_recognition === false,
      installedRuntimeProfileTerminalChainRefusalTaxonomySatisfied,
      installedRuntimeProfileTerminalChainNamedReceiptRefusalsSatisfied,
      installedRuntimeProfileTerminalChainRecognitionRefusalGroupsSatisfied,
      installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsSatisfied,
      installedRuntimeProfileTerminalChainNestedArtifactBindingSatisfied,
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingSatisfied,
      terminalChainRecognizedReceiptPathMirrorSatisfied,
      terminalChainDeploymentProfileAuthorityRefusalMirrorSatisfied,
      installedRuntimeProfileRecognitionContractDigestSatisfied,
      installedRuntimeProfileTerminalChain?.terminal_chain?.generated_installed_root_preflighted === true,
      installedRuntimeProfileTerminalChain?.terminal_chain?.generated_preflight_artifact_consumed_by_service_proof === true,
      installedRuntimeProfileTerminalChain?.terminal_chain?.generated_service_proof_artifact_verified === true,
      installedRuntimeProfileTerminalChain?.terminal_chain?.service_proof_bound_to_generated_preflight === true,
      installedRuntimeProfileTerminalChain?.terminal_chain?.service_artifact_verification_bound_to_service_proof === true,
      installedRuntimeProfileTerminalChain?.terminal_chain?.recognized_write_boarded === true,
      installedRuntimeProfileTerminalChain?.terminal_chain?.missing_receipt_refused_before_mutation === true,
      installedRuntimeProfileTerminalChain?.terminal_chain?.invalid_receipt_refused_before_mutation === true,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.required_recognition_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.observed_recognition_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.all_required_recognition_refusals_before_mutation === true,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.required_authority_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.observed_authority_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.all_required_authority_refusals_before_consumption_and_mutation === true,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.same_process_signed_payload_replay_refused === true,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.restart_consumed_authority_grant_refused === true,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.fixture_rightful_issuance_path_evidenced === true,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.rightful_issuance_proven === false,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.portable_rightful_issuance_proven === false,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.production_rightful_issuance_proven === false,
      installedRuntimeProfileTerminalChain?.terminal_chain?.live_authority_proven ===
        false,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.current_machine_governance_proven === false,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.consequence_lifecycle_closed === false,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.state_append_after_grant_commit_burn_observed === true,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.metadata_partial_commit_burn_observed === true,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.store_and_anchor_rollback_refused_while_witness_ahead === true,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.store_anchor_and_witness_joint_rollback_detection === false,
      installedRuntimeProfileTerminalChain?.terminal_chain
        ?.joint_rollback_reopened_authority_grant_reuse === true,
      installedRuntimeProfileTerminalChain?.side_door_report
        ?.host_filesystem_path_toctou_closed === false,
      installedRuntimeProfileTerminalChain?.runtime_profile?.profile_sha256 ===
        installedRuntimeProfileServiceProfileSha256,
      installedRuntimeProfileTerminalChain?.runtime_profile?.profile_sha256 ===
        runtimeTerminalLane?.issuer_identity?.recognition_anchor_id,
      runtimeTerminalLane?.governed === true,
      runtimeTerminalLane?.evidence?.route?.mutation_authoritative_route ===
        EXACT_RUNTIME_MUTATION_AUTHORITATIVE_ROUTE,
      runtimeTerminalLane?.evidence?.downstream_refusal?.recognition_refusals
        ?.required_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
      runtimeTerminalLane?.evidence?.downstream_refusal?.authority_refusals
        ?.required_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length,
      runtimeTerminalLane?.evidence?.rightful_issuance
        ?.fixture_rightful_issuance_path_evidenced === true,
      runtimeTerminalLane?.evidence?.rightful_issuance?.rightful_issuance_proven ===
        false,
      installedRuntimeProfileTerminalChain?.side_door_report?.persistent_runtime_profile_installed === false,
      installedRuntimeProfileTerminalChain?.side_door_report?.runtime_profile_activation_performed === false,
      installedRuntimeProfileTerminalChain?.side_door_report?.hook_configuration_written === false,
      installedRuntimeProfileTerminalChain?.side_door_report?.current_machine_governance_proven === false,
      installedRuntimeProfileTerminalChain?.generated_service_proof?.production_downstream_recognition === false,
      installedRuntimeProfileTerminalChainArtifactVerification?.payload_type ===
        installedRuntimeProfileTerminalChain?.chain_type,
      installedRuntimeProfileTerminalChainArtifactVerification?.generated_installed_root_preflighted === true,
      installedRuntimeProfileTerminalChainArtifactVerification?.generated_preflight_artifact_consumed_by_service_proof === true,
      installedRuntimeProfileTerminalChainArtifactVerification?.generated_service_proof_artifact_verified === true,
      installedRuntimeProfileTerminalChainArtifactVerification?.service_proof_bound_to_generated_preflight === true,
      installedRuntimeProfileTerminalChainArtifactVerification?.service_artifact_verification_bound_to_service_proof === true,
      installedRuntimeProfileTerminalChainArtifactVerification?.recognized_write_boarded === true,
      installedRuntimeProfileTerminalChainArtifactVerification?.missing_receipt_refused_before_mutation === true,
      installedRuntimeProfileTerminalChainArtifactVerification?.invalid_receipt_refused_before_mutation === true,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.all_required_recognition_refusals_before_mutation === true,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.required_recognition_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.observed_recognition_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.all_required_authority_refusals_before_consumption_and_mutation === true,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.required_authority_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.observed_authority_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.same_process_signed_payload_replay_refused === true,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.restart_consumed_authority_grant_refused === true,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.fixture_rightful_issuance_path_evidenced === true,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.rightful_issuance_proven === false,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.portable_rightful_issuance_proven === false,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.production_rightful_issuance_proven === false,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.live_authority_proven === false,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.consequence_lifecycle_closed === false,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.state_append_after_grant_commit_burn_observed === true,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.metadata_partial_commit_burn_observed === true,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.store_and_anchor_rollback_refused_while_witness_ahead === true,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.store_anchor_and_witness_joint_rollback_detection === false,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.joint_rollback_reopened_authority_grant_reuse === true,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.host_filesystem_path_toctou_closed === false,
      installedRuntimeProfileTerminalChainArtifactVerification
        ?.runtime_profile_sha256 === installedRuntimeProfileServiceProfileSha256,
      installedRuntimeProfileTerminalChainArtifactVerification?.persistent_runtime_profile_installed === false,
      installedRuntimeProfileTerminalChainArtifactVerification?.runtime_profile_activation_performed === false,
      installedRuntimeProfileTerminalChainArtifactVerification?.hook_configuration_written === false,
      installedRuntimeProfileTerminalChainArtifactVerification?.current_machine_governance_proven === false,
      installedRuntimeProfileTerminalChainArtifactVerification?.production_downstream_recognition === false,
    ].every(bool);
  const installedRuntimeProfileTerminalChainSatisfied =
    !installedRuntimeProfileTerminalChainExpected ||
    installedRuntimeProfileTerminalChainPreserved;

  const puzzlePieces = [
    {
      id: 1,
      name: 'Product Proof Path',
      status: 'bounded_local_fixture_proven',
      acceptance_gate_scope: productProofPath.provided
        ? 'fresh-local-product-proof-path'
        : 'local-fixture-only',
      evidence: [
        ...(productProofPath.provided
          ? [
              evidenceItem(
                'product_proof_path',
                'zlar product-proof-path --json',
                'verified',
                'fresh local fixture'
              ),
            ]
          : []),
        evidenceItem(
          'proof_smoke',
          'zlar proof-smoke verify --historical --sample --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80 --json',
          'historical_verified_non_scoring',
          'exact-pinned committed sample',
        ),
        evidenceItem('local_proof_pack', 'zlar local-proof-pack verify --sample --json', 'verified', 'committed sample'),
      ],
      observed: {
        product_proof_path: productProofPath,
        proof_smoke_verified: proofSmokeVerification?.verified === true,
        local_proof_pack_verified: localProofPackVerification?.verified === true,
        governed_lanes: proofCounts.governed_lanes,
        simulated_human_authorization_verified:
          humanAuthorization.simulated_human_authorization_verified,
        human_authorization: humanAuthorization,
        runtime_profile_installation_sample_verified:
          proofCounts.runtime_profile_installation_sample_artifact_verified === true,
        installed_runtime_profile_preflight_sample_verified:
          proofCounts.installed_runtime_profile_preflight_sample_artifact_verified === true,
        installed_runtime_profile_preflight_recognition_contract_preserved:
          proofCounts.installed_runtime_profile_preflight_recognition_contract_preserved === true,
        installed_runtime_profile_recognition_proof_verified:
          proofCounts.installed_runtime_profile_recognition_proof_verified === true,
        installed_runtime_profile_service_artifact_verification_preserved:
          installedRuntimeProfileServiceProofArtifactVerificationAvailable,
        installed_runtime_profile_terminal_chain_preserved:
          installedRuntimeProfileTerminalChainPreserved,
      },
      missing_for_enterprise: [
        'fresh non-operator run with bounded attestation',
        'production deployment boundary',
      ],
    },
    {
      id: 2,
      name: 'Governed Surface Coverage Map',
      status: 'supplied_evidence_map_proven',
      acceptance_gate_scope: 'committed-sample-and-supplied-evidence-only',
      evidence: [
        evidenceItem('coverage_map', 'zlar coverage --sample --require-governed --json', 'verified', 'committed sample'),
      ],
      observed: {
        governed_lanes: coverageCounts.governed_lanes,
        counted_lanes: coverageCounts.counted_lanes,
        total_surfaces: coverageCounts.total_surfaces,
        live_probing: coverageMap?.evidence_model?.live_probing_performed === true,
        service_profile_lane_governed: serviceLane?.governed === true,
        runtime_profile_installation_lane_governed: runtimeInstallLane?.governed === true,
      },
      missing_for_enterprise: [
        'live configured-surface inventory',
        'coverage of unrouted surfaces',
      ],
    },
    {
      id: 3,
      name: 'Enterprise Deployment Profile',
      status: installedRuntimeProfileServiceProofAvailable &&
        installedRuntimeProfileServiceProofArtifactVerificationSatisfied &&
        installedRuntimeProfileServiceRightfulContractPreserved &&
        installedRuntimeProfileTerminalChainSatisfied
        ? 'local_disposable_profile_refusal_proven'
        : 'local_disposable_profile_partial',
      acceptance_gate_scope: installedRuntimeProfileServiceProofAvailable &&
        installedRuntimeProfileServiceProofArtifactVerificationSatisfied &&
        installedRuntimeProfileServiceRightfulContractPreserved &&
        installedRuntimeProfileTerminalChainSatisfied
        ? 'local-disposable-installed-profile-terminal-chain-only'
        : 'local-disposable-runtime-and-service-profile-only',
      evidence: [
        evidenceItem(
          'runtime_profile_installation',
          'zlar protected-records-runtime-profile-installation verify --sample --json',
          'verified',
          'committed sample'
        ),
        evidenceItem(
          'installed_runtime_profile_preflight',
          'zlar protected-records-installed-runtime-profile-preflight verify --sample --json',
          'verified',
          'committed sample'
        ),
        evidenceItem(
          'service_profile_preflight',
          'zlar protected-records-service-preflight verify --sample --json',
          'verified',
          'committed sample'
        ),
        ...(installedRuntimeProfileServiceProofAvailable
          ? [
              evidenceItem(
                'installed_runtime_profile_service_proof',
                'zlar protected-records-installed-runtime-profile-service-proof --sample --json',
                'verified',
                'committed sample'
              ),
            ]
          : []),
        ...(installedRuntimeProfileServiceProofArtifactVerificationAvailable
          ? [
              evidenceItem(
                'installed_runtime_profile_service_proof_artifact_verification',
                'zlar protected-records-installed-runtime-profile-service-proof verify --sample --json',
                'verified',
                'committed sample'
              ),
            ]
          : []),
        ...(installedRuntimeProfileTerminalChainPreserved
          ? [
              evidenceItem(
                'installed_runtime_profile_terminal_chain',
                'zlar protected-records-installed-runtime-profile-terminal-chain --sample --json',
                'verified',
                'committed sample'
              ),
              evidenceItem(
                'installed_runtime_profile_terminal_chain_artifact_verification',
                'zlar protected-records-installed-runtime-profile-terminal-chain verify --sample --json',
                'verified',
                'committed sample'
              ),
            ]
          : []),
      ],
      observed: {
        action_class: 'records.write',
        downstream_boundary: 'protected-records-runtime-service:local-jsonl-child-process',
        disposable_profile_installation_applied:
          runtimeProfileInstallationVerification?.disposable_profile_installation_applied === true,
        persistent_runtime_profile_installed:
          runtimeProfileInstallationVerification?.persistent_runtime_profile_installed === true,
        hook_configuration_written:
          runtimeProfileInstallationVerification?.hook_configuration_written === true,
        installed_runtime_profile_preflight_verified:
          installedRuntimeProfilePreflightVerification?.verified === true,
        installed_runtime_profile_preflight_read_only:
          installedRuntimeProfilePreflightVerification?.read_only === true,
        installed_runtime_profile_preflight_selected_by_explicit_id_and_sha:
          installedRuntimeProfilePreflightVerification?.selected_by_explicit_id_and_sha === true,
        installed_runtime_profile_preflight_recognition_contract_preserved:
          installedRuntimeProfilePreflightVerification?.recognition_contract_preserved === true,
        installed_runtime_profile_recognition_contract_digest_preserved:
          installedRuntimeProfileRecognitionContractDigestPreserved,
        installed_runtime_profile_recognition_contract_sha256:
          installedRuntimeProfileRecognitionContractSha256,
        installed_runtime_profile_preflight_recognition_boundary:
          installedRuntimeProfilePreflightVerification?.recognition_boundary || 'not-provided',
        installed_runtime_profile_preflight_mutation_authoritative_route:
          installedRuntimeProfilePreflightVerification?.mutation_authoritative_route || 'not-provided',
        installed_runtime_profile_preflight_recognition_rule_supplied_by_agent:
          installedRuntimeProfilePreflightVerification?.recognition_rule_supplied_by_agent === true,
        installed_runtime_profile_preflight_selects_latest:
          installedRuntimeProfilePreflightVerification?.selects_latest_profile === true,
        installed_runtime_profile_preflight_installation_performed:
          installedRuntimeProfilePreflightVerification?.runtime_profile_installation_performed === true,
        installed_runtime_profile_preflight_activation_performed:
          installedRuntimeProfilePreflightVerification?.runtime_profile_activation_performed === true,
        installed_runtime_profile_preflight_downstream_refusal_proven:
          installedRuntimeProfilePreflightVerification?.downstream_refusal_proven === true,
        installed_runtime_profile_preflight_current_machine_governance_proven:
          installedRuntimeProfilePreflightVerification?.current_machine_governance_proven === true,
        installed_runtime_profile_service_proof_verified:
          installedRuntimeProfileServiceProofAvailable,
        installed_runtime_profile_service_artifact_verification_verified:
          installedRuntimeProfileServiceProofArtifactVerificationAvailable,
        installed_runtime_profile_service_rightful_contract_preserved:
          installedRuntimeProfileServiceRightfulContractPreserved,
        installed_runtime_profile_service_artifact_verification_body_sha256:
        proofCounts.installed_runtime_profile_service_artifact_verification_body_sha256 || 'not-provided',
        installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved:
          installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomyPreserved,
        installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256:
          installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomySha256,
        installed_runtime_profile_terminal_chain_verified:
          installedRuntimeProfileTerminalChainPreserved,
        installed_runtime_profile_terminal_chain_artifact_verification_verified:
          installedRuntimeProfileTerminalChainArtifactVerificationAvailable,
        installed_runtime_profile_terminal_chain_artifact_verification_body_sha256:
          installedRuntimeProfileTerminalChainArtifactVerificationBodySha256,
        installed_runtime_profile_terminal_chain_refusal_taxonomy_preserved:
          installedRuntimeProfileTerminalChainRefusalTaxonomyPreserved,
        installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256:
          installedRuntimeProfileTerminalChainRefusalTaxonomySha256,
        installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256:
          installedRuntimeProfileTerminalChainArtifactVerificationRefusalTaxonomySha256,
        installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved:
          installedRuntimeProfileTerminalChainNamedReceiptRefusalsPreserved,
        installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256:
          installedRuntimeProfileTerminalChainNamedReceiptRefusalsSha256,
        installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256:
          installedRuntimeProfileTerminalChainArtifactVerificationNamedReceiptRefusalsSha256,
        installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupsPreserved,
        installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupsSha256,
        installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256:
          installedRuntimeProfileTerminalChainArtifactVerificationRecognitionRefusalGroupsSha256,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsPreserved,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_count:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
            ? proofCounts.installed_runtime_profile_terminal_chain_recognition_refusal_group_count || 0
            : 0,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
            ? proofCounts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count || 0
            : 0,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
            ? proofCounts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids || {}
            : {},
        installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
            ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count || 0
            : 0,
        installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
            ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count || 0
            : 0,
        installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
            ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids || {}
            : {},
        installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved:
          installedRuntimeProfileTerminalChainNestedArtifactBindingPreserved,
        installed_runtime_profile_terminal_chain_nested_preflight_artifact_type:
          installedRuntimeProfileTerminalChainNestedPreflightArtifactType,
        installed_runtime_profile_terminal_chain_nested_service_proof_artifact_type:
          installedRuntimeProfileTerminalChainNestedServiceProofArtifactType,
        installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved:
          installedRuntimeProfileTerminalChainNestedArtifactBindingExpected
            ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_nested_preflight_artifact_type:
          installedRuntimeProfileTerminalChainArtifactVerificationNestedPreflightArtifactType,
        installed_runtime_profile_terminal_chain_artifact_verification_nested_service_proof_artifact_type:
          installedRuntimeProfileTerminalChainArtifactVerificationNestedServiceProofArtifactType,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved:
          installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingPreserved,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256:
          installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingSha256,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256:
          installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBindingSha256,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved:
          installedRuntimeProfileTerminalChainTrustedIssuerRegistryRecognitionRefusalsPreserved,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count || 0,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused === true,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids || [],
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes || [],
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256:
          installedRuntimeProfileTerminalChainTrustedIssuerRegistryRecognitionRefusalsSha256,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count || 0,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused === true,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids || [],
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes || [],
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256:
          installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryRecognitionRefusalsSha256,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_state_proven:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_state_proven,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_issuer_status_proven:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_issuer_status_proven,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_key_custody_proven:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_key_custody_proven,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_revocation_truth_proven:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_revocation_truth_proven,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_trust_registry_proven:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_trust_registry_proven,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_downstream_recognition_proven:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_downstream_recognition_proven,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_authority:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_authority,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_sovereign_recognition:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_sovereign_recognition,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_external_attestation:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_external_attestation,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_real_non_operator_review:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_real_non_operator_review,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_current_machine_governance_proven:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_current_machine_governance_proven,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_key_material_included:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_key_material_included,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_envelope_included:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_envelope_included,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_artifact_crypto_reproducible:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_artifact_crypto_reproducible,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_contract_hash_bound:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_contract_hash_bound,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_state_proven:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_state_proven,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_issuer_status_proven:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_issuer_status_proven,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_key_custody_proven:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_key_custody_proven,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_revocation_truth_proven:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_revocation_truth_proven,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_trust_registry_proven:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_trust_registry_proven,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_downstream_recognition_proven:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_downstream_recognition_proven,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_authority:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_authority,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_sovereign_recognition:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_sovereign_recognition,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_external_attestation:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_external_attestation,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_real_non_operator_review:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_real_non_operator_review,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_current_machine_governance_proven:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_current_machine_governance_proven,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_key_material_included:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_key_material_included,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_envelope_included:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_envelope_included,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_artifact_crypto_reproducible:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_artifact_crypto_reproducible,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_contract_hash_bound:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_contract_hash_bound,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_mirror_preserved:
          terminalChainRecognizedReceiptPathMirrorPreserved,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256:
          terminalChainRecognizedReceiptPathEvidenceSha256,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_sha256:
          terminalChainArtifactVerificationRecognizedReceiptPathEvidenceSha256,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_bound_to_artifact_body:
          installedRuntimeProfileTerminalChainArtifactVerification
            ?.recognized_receipt_path_evidence_bound_to_artifact_body === true,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256:
          terminalChainRecognizedReceiptPathSourceBindingSha256,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_sha256:
          terminalChainArtifactVerificationRecognizedReceiptPathSourceBindingSha256,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_matches_trusted_registry_binding:
          terminalChainRecognizedReceiptPathSourceBindingMatchesTrustedRegistryBinding,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_matches_trusted_registry_binding:
          terminalChainArtifactVerificationRecognizedReceiptPathSourceBindingMatchesTrustedRegistryBinding,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_verdict:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.verdict || 'not-provided'
            : 'not-provided',
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_verdict:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.verdict || 'not-provided'
            : 'not-provided',
        installed_runtime_profile_terminal_chain_recognized_receipt_path_recognized:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.recognized === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_recognized:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.recognized === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_receipt_envelope_included:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.receipt_envelope_included === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_receipt_envelope_included:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.receipt_envelope_included === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_registry_public_key_material_included:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.registry_public_key_material_included === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_registry_public_key_material_included:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.registry_public_key_material_included === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_artifact_crypto_reproducible:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.cryptographic_evidence_reproducible_from_artifact === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_artifact_crypto_reproducible:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.cryptographic_evidence_reproducible_from_artifact === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_live_state_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.live_trust_registry_state === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_live_state_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.live_trust_registry_state === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_live_issuer_status_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.live_issuer_status_proven === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_live_issuer_status_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.live_issuer_status_proven === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_key_custody_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.key_custody_proven === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_key_custody_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.key_custody_proven === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_revocation_truth_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.revocation_truth_proven === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_revocation_truth_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.revocation_truth_proven === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_production_downstream_recognition_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.production_downstream_recognition_proven === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_production_downstream_recognition_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.production_downstream_recognition_proven === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_public_external_attestation:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.public_external_attestation === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_public_external_attestation:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.public_external_attestation === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_sovereign_recognition:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.sovereign_recognition === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_sovereign_recognition:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.sovereign_recognition === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_current_machine_governance_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.current_machine_governance_proven === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_current_machine_governance_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.current_machine_governance_proven === true
            : false,
        installed_runtime_profile_terminal_chain_generated_installed_root_preflighted:
          proofCounts.installed_runtime_profile_terminal_chain_generated_installed_root_preflighted === true,
        installed_runtime_profile_terminal_chain_generated_preflight_consumed:
          proofCounts.installed_runtime_profile_terminal_chain_generated_preflight_consumed === true,
        installed_runtime_profile_terminal_chain_generated_service_artifact_verified:
          proofCounts.installed_runtime_profile_terminal_chain_generated_service_artifact_verified === true,
        installed_runtime_profile_terminal_chain_service_proof_bound_to_generated_preflight:
          proofCounts.installed_runtime_profile_terminal_chain_service_proof_bound_to_generated_preflight === true,
        installed_runtime_profile_terminal_chain_service_artifact_verification_bound_to_service_proof:
          proofCounts.installed_runtime_profile_terminal_chain_service_artifact_verification_bound_to_service_proof === true,
        installed_runtime_profile_terminal_chain_recognized_write_boarded:
          proofCounts.installed_runtime_profile_terminal_chain_recognized_write_boarded === true,
        installed_runtime_profile_terminal_chain_missing_receipt_refused_before_mutation:
          proofCounts.installed_runtime_profile_terminal_chain_missing_receipt_refused_before_mutation === true,
        installed_runtime_profile_terminal_chain_invalid_receipt_refused_before_mutation:
          proofCounts.installed_runtime_profile_terminal_chain_invalid_receipt_refused_before_mutation === true,
        installed_runtime_profile_terminal_chain_all_required_refusals_before_mutation:
          proofCounts.installed_runtime_profile_terminal_chain_all_required_refusals_before_mutation === true,
        installed_runtime_profile_terminal_chain_current_machine_governance_proven:
          proofCounts.installed_runtime_profile_terminal_chain_current_machine_governance_proven,
        installed_runtime_profile_terminal_chain_production_downstream_recognition:
          proofCounts.installed_runtime_profile_terminal_chain_production_downstream_recognition,
        installed_runtime_profile_service_runtime_service_started:
          proofCounts.installed_runtime_profile_service_runtime_service_started === true,
        installed_runtime_profile_service_disposable_runtime_config_written:
          proofCounts.installed_runtime_profile_service_disposable_runtime_config_written === true,
        installed_runtime_profile_service_persistent_runtime_config_written:
          proofCounts.installed_runtime_profile_service_persistent_runtime_config_written === true,
        installed_runtime_profile_service_config_path_exposed_to_request_stream:
          proofCounts.installed_runtime_profile_service_config_path_exposed_to_request_stream === true,
        installed_runtime_profile_service_recognition_rule_bound_to_selected_profile:
          proofCounts.installed_runtime_profile_service_recognition_rule_bound_to_selected_profile === true,
        installed_runtime_profile_service_recognized_write_boarded:
          proofCounts.installed_runtime_profile_service_recognized_write_boarded === true,
        installed_runtime_profile_service_replay_case_count:
          proofCounts.installed_runtime_profile_service_replay_case_count,
        installed_runtime_profile_service_same_process_replay_refused:
          proofCounts.installed_runtime_profile_service_same_process_replay_refused === true,
        installed_runtime_profile_service_restart_replay_refused:
          proofCounts.installed_runtime_profile_service_restart_replay_refused === true,
        installed_runtime_profile_service_all_replay_refusals_before_mutation:
          proofCounts.installed_runtime_profile_service_all_replay_refusals_before_mutation === true,
        installed_runtime_profile_service_consumed_store_integrity_case_count:
          proofCounts.installed_runtime_profile_service_consumed_store_integrity_case_count,
        installed_runtime_profile_service_consumed_store_integrity_refusals_proven:
          proofCounts.installed_runtime_profile_service_consumed_store_integrity_refusals_proven === true,
        installed_runtime_profile_service_all_consumed_store_integrity_refusals_before_mutation:
          proofCounts.installed_runtime_profile_service_all_consumed_store_integrity_refusals_before_mutation === true,
        installed_runtime_profile_service_single_host_consumed_store_rollback_detection:
          proofCounts.installed_runtime_profile_service_single_host_consumed_store_rollback_detection === true,
        installed_runtime_profile_service_store_and_anchor_rollback_case_count:
          proofCounts.installed_runtime_profile_service_store_and_anchor_rollback_case_count,
        installed_runtime_profile_service_store_and_anchor_joint_rollback_refusals_proven:
          proofCounts.installed_runtime_profile_service_store_and_anchor_joint_rollback_refusals_proven === true,
        installed_runtime_profile_service_all_store_and_anchor_rollback_refusals_before_mutation:
          proofCounts.installed_runtime_profile_service_all_store_and_anchor_rollback_refusals_before_mutation === true,
        installed_runtime_profile_service_store_and_anchor_joint_rollback_detection:
          proofCounts.installed_runtime_profile_service_store_and_anchor_joint_rollback_detection === true,
        installed_runtime_profile_service_store_anchor_and_witness_joint_rollback_detection:
          proofCounts.installed_runtime_profile_service_store_anchor_and_witness_joint_rollback_detection,
        installed_runtime_profile_service_refusal_case_count:
          proofCounts.installed_runtime_profile_service_refusal_case_count,
        installed_runtime_profile_service_all_refusals_before_mutation:
          proofCounts.installed_runtime_profile_service_all_refusals_before_mutation === true,
        installed_runtime_profile_service_source_preflight_downstream_refusal_proven:
          proofCounts.installed_runtime_profile_service_source_preflight_downstream_refusal_proven,
        installed_runtime_profile_service_current_machine_governance_proven:
          proofCounts.installed_runtime_profile_service_current_machine_governance_proven,
        installed_runtime_profile_service_production_downstream_recognition:
          proofCounts.installed_runtime_profile_service_production_downstream_recognition,
        production_records_service_checked:
          servicePreflightVerification?.production_records_service_checked === true,
      },
      missing_for_enterprise: [
        'named real deployment owner',
        'persistent profile installation',
        'production downstream service refusal',
        'current-machine governance proof',
      ],
    },
    {
      id: 4,
      name: 'Trusted Receipt Issuer',
      status: trustedReceiptIssuerCompletionSatisfied
        ? 'operator_owned_private_core_completion_proven'
        : 'portable_fixture_partial',
      acceptance_gate_scope: trustedReceiptIssuerCompletionSatisfied
        ? 'operator-owned-private-core-recognized-authority-event-contract-for-selected-surface'
        : 'sample-key-state-and-optional-bundled-fixture-recognition-only',
      evidence: [
        evidenceItem('key_state_sample', 'zlar key-state --sample --json', 'embedded', 'local proof-pack sample'),
        evidenceItem('issuer_status_fixture', 'zlar issuer-status-proof --json', 'available', 'local fixture'),
        evidenceItem(
          'trusted_receipt_issuer_completion_proof',
          'zlar trusted-receipt-issuer-completion-proof verify --input zlar-trusted-receipt-issuer-completion-proof-v1.json --json',
          trustedReceiptIssuerCompletionSatisfied ? 'verified' : 'optional',
          'operator-owned private-core authority-event contract'
        ),
      ],
      observed: {
        key_state_private_key_material_read:
          localProofPackVerification?.key_state_report?.private_key_material_read === true,
        key_state_key_custody_proven:
          localProofPackVerification?.key_state_report?.key_custody_proven === true,
        key_state_revocation_state_proven:
          localProofPackVerification?.key_state_report?.revocation_state_proven === true,
        trusted_issuer_registry_recognition: recognition,
        trusted_receipt_issuer_completion_proof: trustedReceiptIssuerCompletion,
        malformed_registry_contract: malformedRegistry,
        verifier_kit_reproducibility: verifierKit,
        verifier_kit_release_assets: verifierKitReleaseAssetRead,
        verifier_kit_public_distribution: verifierKitDistribution,
      },
      missing_for_enterprise: trustedReceiptIssuerCompletionSatisfied
        ? [
            'customer production relying-party trust',
            'external attestation',
            'hardware-backed custody if required by a later trust contract',
          ]
        : [
            'live key custody evidence',
            'production trust registry',
            'revocation truth',
          ],
    },
    {
      id: 5,
      name: 'Downstream Recognition Rule',
      status: 'local_fixture_proven',
      acceptance_gate_scope: 'local-disposable-downstream-only',
      evidence: [
        evidenceItem(
          'runtime_local_activation',
          'zlar protected-records-runtime-local-activation verify --sample --json',
          'verified',
          'committed sample'
        ),
        evidenceItem(
          'runtime_profile_installation',
          'zlar protected-records-runtime-profile-installation verify --sample --json',
          'verified',
          'committed sample'
        ),
        evidenceItem(
          'installed_runtime_profile_recognition_proof',
          'zlar protected-records-installed-runtime-profile-recognition-proof --sample --json',
          'verified',
          'committed sample'
        ),
        ...(installedRuntimeProfileServiceProofAvailable
          ? [
              evidenceItem(
                'installed_runtime_profile_service_proof',
                'zlar protected-records-installed-runtime-profile-service-proof --sample --json',
                'verified',
                'committed sample'
              ),
            ]
          : []),
        ...(installedRuntimeProfileServiceProofArtifactVerificationAvailable
          ? [
              evidenceItem(
                'installed_runtime_profile_service_proof_artifact_verification',
                'zlar protected-records-installed-runtime-profile-service-proof verify --sample --json',
                'verified',
                'committed sample'
              ),
            ]
          : []),
        ...(installedRuntimeProfileTerminalChainPreserved
          ? [
              evidenceItem(
                'installed_runtime_profile_terminal_chain',
                'zlar protected-records-installed-runtime-profile-terminal-chain --sample --json',
                'verified',
                'committed sample'
              ),
              evidenceItem(
                'installed_runtime_profile_terminal_chain_artifact_verification',
                'zlar protected-records-installed-runtime-profile-terminal-chain verify --sample --json',
                'verified',
                'committed sample'
              ),
            ]
          : []),
      ],
      observed: {
        recognized_write_accepted: runtimeLocalActivationVerification?.local_activation_applied === true,
        missing_receipt_refused: runtimeLocalActivationVerification?.missing_receipt_refused === true,
        invalid_receipt_refused: runtimeLocalActivationVerification?.invalid_receipt_refused === true,
        unknown_issuer_refused: runtimeLocalActivationVerification?.unknown_issuer_refused === true,
        wrong_policy_refused: runtimeLocalActivationVerification?.wrong_policy_refused === true,
        wrong_runtime_profile_id_refused:
          runtimeProfileInstallationVerification?.wrong_runtime_profile_id_refused === true,
        request_authority_guard_refused:
          packRuntimeInstallation?.request_authority_guard_summary?.all_refused_before_mutation === true,
        runtime_profile_identity_policy:
          productProofPath.proof_pack_runtime_profile_identity_policy,
        installed_runtime_profile_recognition_proof_verified:
          proofCounts.installed_runtime_profile_recognition_proof_verified === true,
        installed_runtime_profile_recognition_recognized_write_boarded:
          proofCounts.installed_runtime_profile_recognition_recognized_write_boarded === true,
        installed_runtime_profile_recognition_refusal_case_count:
          proofCounts.installed_runtime_profile_recognition_refusal_case_count,
        installed_runtime_profile_recognition_all_refusals_before_mutation:
          proofCounts.installed_runtime_profile_recognition_all_refusals_before_mutation === true,
        installed_runtime_profile_recognition_contract_digest_preserved:
          installedRuntimeProfileRecognitionContractDigestPreserved,
        installed_runtime_profile_recognition_contract_sha256:
          installedRuntimeProfileRecognitionContractSha256,
        installed_runtime_profile_recognition_source_preflight_downstream_refusal_proven:
          proofCounts.installed_runtime_profile_recognition_source_preflight_downstream_refusal_proven === true,
        installed_runtime_profile_recognition_current_machine_governance_proven:
          proofCounts.installed_runtime_profile_recognition_current_machine_governance_proven === true,
        installed_runtime_profile_recognition_production_downstream_recognition:
          proofCounts.installed_runtime_profile_recognition_production_downstream_recognition === true,
        installed_runtime_profile_service_proof_verified:
          installedRuntimeProfileServiceProofAvailable,
        installed_runtime_profile_service_artifact_verification_verified:
          installedRuntimeProfileServiceProofArtifactVerificationAvailable,
        installed_runtime_profile_service_artifact_verification_body_sha256:
        proofCounts.installed_runtime_profile_service_artifact_verification_body_sha256 || 'not-provided',
        installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved:
          installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomyPreserved,
        installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256:
          installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomySha256,
        installed_runtime_profile_terminal_chain_verified:
          installedRuntimeProfileTerminalChainPreserved,
        installed_runtime_profile_terminal_chain_artifact_verification_verified:
          installedRuntimeProfileTerminalChainArtifactVerificationAvailable,
        installed_runtime_profile_terminal_chain_artifact_verification_body_sha256:
          installedRuntimeProfileTerminalChainArtifactVerificationBodySha256,
        installed_runtime_profile_terminal_chain_refusal_taxonomy_preserved:
          installedRuntimeProfileTerminalChainRefusalTaxonomyPreserved,
        installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256:
          installedRuntimeProfileTerminalChainRefusalTaxonomySha256,
        installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256:
          installedRuntimeProfileTerminalChainArtifactVerificationRefusalTaxonomySha256,
        installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved:
          installedRuntimeProfileTerminalChainNamedReceiptRefusalsPreserved,
        installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256:
          installedRuntimeProfileTerminalChainNamedReceiptRefusalsSha256,
        installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256:
          installedRuntimeProfileTerminalChainArtifactVerificationNamedReceiptRefusalsSha256,
        installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupsPreserved,
        installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupsSha256,
        installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256:
          installedRuntimeProfileTerminalChainArtifactVerificationRecognitionRefusalGroupsSha256,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsPreserved,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_count:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
            ? proofCounts.installed_runtime_profile_terminal_chain_recognition_refusal_group_count || 0
            : 0,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
            ? proofCounts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count || 0
            : 0,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
            ? proofCounts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids || {}
            : {},
        installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
            ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count || 0
            : 0,
        installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
            ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count || 0
            : 0,
        installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids:
          installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
            ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids || {}
            : {},
        installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved:
          installedRuntimeProfileTerminalChainNestedArtifactBindingPreserved,
        installed_runtime_profile_terminal_chain_nested_preflight_artifact_type:
          installedRuntimeProfileTerminalChainNestedPreflightArtifactType,
        installed_runtime_profile_terminal_chain_nested_service_proof_artifact_type:
          installedRuntimeProfileTerminalChainNestedServiceProofArtifactType,
        installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved:
          installedRuntimeProfileTerminalChainNestedArtifactBindingExpected
            ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_nested_preflight_artifact_type:
          installedRuntimeProfileTerminalChainArtifactVerificationNestedPreflightArtifactType,
        installed_runtime_profile_terminal_chain_artifact_verification_nested_service_proof_artifact_type:
          installedRuntimeProfileTerminalChainArtifactVerificationNestedServiceProofArtifactType,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved:
          installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingPreserved,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256:
          installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingSha256,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256:
          installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBindingSha256,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved:
          installedRuntimeProfileTerminalChainTrustedIssuerRegistryRecognitionRefusalsPreserved,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count || 0,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused === true,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids || [],
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes || [],
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256:
          installedRuntimeProfileTerminalChainTrustedIssuerRegistryRecognitionRefusalsSha256,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count || 0,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused === true,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids || [],
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes || [],
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256:
          installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryRecognitionRefusalsSha256,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_state_proven:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_state_proven,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_issuer_status_proven:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_issuer_status_proven,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_key_custody_proven:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_key_custody_proven,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_revocation_truth_proven:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_revocation_truth_proven,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_trust_registry_proven:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_trust_registry_proven,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_downstream_recognition_proven:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_downstream_recognition_proven,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_authority:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_authority,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_sovereign_recognition:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_sovereign_recognition,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_external_attestation:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_external_attestation,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_real_non_operator_review:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_real_non_operator_review,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_current_machine_governance_proven:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_current_machine_governance_proven,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_key_material_included:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_key_material_included,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_envelope_included:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_envelope_included,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_artifact_crypto_reproducible:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_artifact_crypto_reproducible,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_contract_hash_bound:
          proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_contract_hash_bound,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_state_proven:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_state_proven,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_issuer_status_proven:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_issuer_status_proven,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_key_custody_proven:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_key_custody_proven,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_revocation_truth_proven:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_revocation_truth_proven,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_trust_registry_proven:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_trust_registry_proven,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_downstream_recognition_proven:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_downstream_recognition_proven,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_authority:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_authority,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_sovereign_recognition:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_sovereign_recognition,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_external_attestation:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_external_attestation,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_real_non_operator_review:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_real_non_operator_review,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_current_machine_governance_proven:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_current_machine_governance_proven,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_key_material_included:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_key_material_included,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_envelope_included:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_envelope_included,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_artifact_crypto_reproducible:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_artifact_crypto_reproducible,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_contract_hash_bound:
          proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_contract_hash_bound,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_mirror_preserved:
          terminalChainRecognizedReceiptPathMirrorPreserved,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256:
          terminalChainRecognizedReceiptPathEvidenceSha256,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_sha256:
          terminalChainArtifactVerificationRecognizedReceiptPathEvidenceSha256,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_bound_to_artifact_body:
          installedRuntimeProfileTerminalChainArtifactVerification
            ?.recognized_receipt_path_evidence_bound_to_artifact_body === true,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256:
          terminalChainRecognizedReceiptPathSourceBindingSha256,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_sha256:
          terminalChainArtifactVerificationRecognizedReceiptPathSourceBindingSha256,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_matches_trusted_registry_binding:
          terminalChainRecognizedReceiptPathSourceBindingMatchesTrustedRegistryBinding,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_matches_trusted_registry_binding:
          terminalChainArtifactVerificationRecognizedReceiptPathSourceBindingMatchesTrustedRegistryBinding,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_verdict:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.verdict || 'not-provided'
            : 'not-provided',
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_verdict:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.verdict || 'not-provided'
            : 'not-provided',
        installed_runtime_profile_terminal_chain_recognized_receipt_path_recognized:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.recognized === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_recognized:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.recognized === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_receipt_envelope_included:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.receipt_envelope_included === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_receipt_envelope_included:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.receipt_envelope_included === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_registry_public_key_material_included:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.registry_public_key_material_included === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_registry_public_key_material_included:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.registry_public_key_material_included === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_artifact_crypto_reproducible:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.cryptographic_evidence_reproducible_from_artifact === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_artifact_crypto_reproducible:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.cryptographic_evidence_reproducible_from_artifact === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_live_state_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.live_trust_registry_state === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_live_state_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.live_trust_registry_state === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_live_issuer_status_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.live_issuer_status_proven === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_live_issuer_status_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.live_issuer_status_proven === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_key_custody_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.key_custody_proven === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_key_custody_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.key_custody_proven === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_revocation_truth_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.revocation_truth_proven === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_revocation_truth_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.revocation_truth_proven === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_production_downstream_recognition_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.production_downstream_recognition_proven === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_production_downstream_recognition_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.production_downstream_recognition_proven === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_public_external_attestation:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.public_external_attestation === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_public_external_attestation:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.public_external_attestation === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_sovereign_recognition:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.sovereign_recognition === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_sovereign_recognition:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.sovereign_recognition === true
            : false,
        installed_runtime_profile_terminal_chain_recognized_receipt_path_current_machine_governance_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainRecognizedReceiptPathEvidence.current_machine_governance_proven === true
            : false,
        installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_current_machine_governance_proven:
          terminalChainRecognizedReceiptPathMirrorExpected
            ? terminalChainArtifactVerificationRecognizedReceiptPathEvidence.current_machine_governance_proven === true
            : false,
        installed_runtime_profile_terminal_chain_generated_preflight_consumed:
          proofCounts.installed_runtime_profile_terminal_chain_generated_preflight_consumed === true,
        installed_runtime_profile_terminal_chain_service_proof_bound_to_generated_preflight:
          proofCounts.installed_runtime_profile_terminal_chain_service_proof_bound_to_generated_preflight === true,
        installed_runtime_profile_terminal_chain_recognized_write_boarded:
          proofCounts.installed_runtime_profile_terminal_chain_recognized_write_boarded === true,
        installed_runtime_profile_terminal_chain_missing_receipt_refused_before_mutation:
          proofCounts.installed_runtime_profile_terminal_chain_missing_receipt_refused_before_mutation === true,
        installed_runtime_profile_terminal_chain_invalid_receipt_refused_before_mutation:
          proofCounts.installed_runtime_profile_terminal_chain_invalid_receipt_refused_before_mutation === true,
        installed_runtime_profile_terminal_chain_all_required_refusals_before_mutation:
          proofCounts.installed_runtime_profile_terminal_chain_all_required_refusals_before_mutation === true,
        installed_runtime_profile_terminal_chain_current_machine_governance_proven:
          proofCounts.installed_runtime_profile_terminal_chain_current_machine_governance_proven,
        installed_runtime_profile_terminal_chain_production_downstream_recognition:
          proofCounts.installed_runtime_profile_terminal_chain_production_downstream_recognition,
        installed_runtime_profile_service_runtime_service_started:
          proofCounts.installed_runtime_profile_service_runtime_service_started === true,
        installed_runtime_profile_service_recognized_write_boarded:
          proofCounts.installed_runtime_profile_service_recognized_write_boarded === true,
        installed_runtime_profile_service_same_process_replay_refused:
          proofCounts.installed_runtime_profile_service_same_process_replay_refused === true,
        installed_runtime_profile_service_restart_replay_refused:
          proofCounts.installed_runtime_profile_service_restart_replay_refused === true,
        installed_runtime_profile_service_consumed_store_integrity_refusals_proven:
          proofCounts.installed_runtime_profile_service_consumed_store_integrity_refusals_proven === true,
        installed_runtime_profile_service_store_and_anchor_rollback_case_count:
          proofCounts.installed_runtime_profile_service_store_and_anchor_rollback_case_count,
        installed_runtime_profile_service_store_and_anchor_joint_rollback_refusals_proven:
          proofCounts.installed_runtime_profile_service_store_and_anchor_joint_rollback_refusals_proven === true,
        installed_runtime_profile_service_store_and_anchor_joint_rollback_detection:
          proofCounts.installed_runtime_profile_service_store_and_anchor_joint_rollback_detection === true,
        installed_runtime_profile_service_store_anchor_and_witness_joint_rollback_detection:
          proofCounts.installed_runtime_profile_service_store_anchor_and_witness_joint_rollback_detection,
        installed_runtime_profile_service_refusal_case_count:
          proofCounts.installed_runtime_profile_service_refusal_case_count,
        installed_runtime_profile_service_all_refusals_before_mutation:
          proofCounts.installed_runtime_profile_service_all_refusals_before_mutation === true,
        installed_runtime_profile_service_source_preflight_downstream_refusal_proven:
          proofCounts.installed_runtime_profile_service_source_preflight_downstream_refusal_proven,
        installed_runtime_profile_service_current_machine_governance_proven:
          proofCounts.installed_runtime_profile_service_current_machine_governance_proven,
        installed_runtime_profile_service_production_downstream_recognition:
          proofCounts.installed_runtime_profile_service_production_downstream_recognition,
      },
      missing_for_enterprise: [
        'production relying-party acceptance/refusal',
        'live trust-anchor registry',
      ],
    },
    {
      id: 6,
      name: 'External Attestation',
      status: 'unproven',
      acceptance_gate_scope: 'not-met',
      evidence: [],
      observed: {
        public_external_attestation: false,
        non_operator_review_proven: false,
        private_non_operator_pass_validated:
          privateVerifierResult.private_non_operator_pass_validated,
        private_personally_connected_zip_result_validated:
          privateVerifierZipResult
            .private_personally_connected_outside_machine_signal_validated,
        public_artifact_verifier_result_validated:
          publicArtifactVerifierResult.public_artifact_reply_signal_validated,
        public_external_attestation_result_validated:
          publicExternalAttestationResult
            .bounded_signed_attestation_evidence_verified,
        private_verifier_result_verification: privateVerifierResult,
        private_verifier_zip_result_verification: privateVerifierZipResult,
        public_artifact_verifier_result_verification:
          publicArtifactVerifierResult,
        public_external_attestation_result_verification:
          publicExternalAttestationResult,
      },
      missing_for_enterprise: [
        privateVerifierResult.private_non_operator_pass_validated
          ? 'bounded signed or published attestation'
          : privateVerifierZipResult
              .private_personally_connected_outside_machine_signal_validated
            ? 'independent non-operator verifier run or bounded signed/published attestation'
          : 'non-Vincent verifier run',
        'public external attestation or private disclosure approval',
      ],
    },
    {
      id: 7,
      name: 'Public Claim Boundary',
      status: 'aligned_nonclaim_boundary',
      acceptance_gate_scope: 'public-copy-guard-and-report-boundary',
      evidence: [
        evidenceItem('receipt_authority_copy_guard', 'bash tests/test-receipt-authority-copy.sh', 'verified', 'repo guard'),
        evidenceItem('north_star_readiness_report', 'zlar north-star-readiness --json', 'generated', 'machine-readable boundary'),
      ],
      observed: {
        v3_4_0_ready: v34ReadyViaPublicDistribution,
        external_attestation_claimed: false,
        production_authority_claimed: false,
        sovereign_recognition_claimed: false,
        enterprise_readiness_claimed: false,
        private_intake_sample_manifest_pointer: privateIntakeSampleManifestPointer,
      },
      missing_for_enterprise: [
        'claim upgrade evidence before v3.4.0',
      ],
    },
  ];

  const counts = {
    puzzle_pieces_total: puzzlePieces.length,
    proven_count: puzzlePieces.filter((piece) => piece.status.endsWith('_proven') || piece.status === 'aligned_nonclaim_boundary').length,
    partial_count: puzzlePieces.filter((piece) => piece.status.endsWith('_partial')).length,
    unproven_count: puzzlePieces.filter((piece) => piece.status === 'unproven').length,
    governed_lanes: coverageCounts.governed_lanes,
    counted_lanes: coverageCounts.counted_lanes,
    service_preflight_cases: servicePreflightVerification?.case_count,
    installed_runtime_profile_preflight_verified:
      installedRuntimeProfilePreflightVerification?.verified === true,
    installed_runtime_profile_preflight_no_effect_boundary_preserved: [
      installedRuntimeProfilePreflightVerification?.read_only,
      installedRuntimeProfilePreflightVerification?.profile_selected_from_install_root,
      installedRuntimeProfilePreflightVerification?.selected_by_explicit_id_and_sha,
      installedRuntimeProfilePreflightVerification?.selects_latest_profile === false,
      installedRuntimeProfilePreflightVerification?.runtime_profile_installation_performed === false,
      installedRuntimeProfilePreflightVerification?.runtime_profile_activation_performed === false,
      installedRuntimeProfilePreflightVerification?.hook_configuration_written === false,
      installedRuntimeProfilePreflightVerification?.runtime_service_started === false,
      installedRuntimeProfilePreflightVerification?.downstream_refusal_proven === false,
      installedRuntimeProfilePreflightVerification?.current_machine_governance_proven === false,
    ].every(bool),
    installed_runtime_profile_preflight_recognition_contract_preserved: [
      installedRuntimeProfilePreflightVerification?.recognition_contract_preserved,
      installedRuntimeProfilePreflightVerification?.recognition_boundary ===
        'service-configured-recognition-rule',
      installedRuntimeProfilePreflightVerification?.mutation_authoritative_route ===
        EXACT_RUNTIME_MUTATION_AUTHORITATIVE_ROUTE,
      installedRuntimeProfilePreflightVerification?.request_stream_authority_material_accepted === false,
      installedRuntimeProfilePreflightVerification?.recognition_rule_supplied_by_agent === false,
      Number.isInteger(installedRuntimeProfilePreflightVerification?.required_refusal_case_count),
      installedRuntimeProfilePreflightVerification?.required_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
      installedRuntimeProfilePreflightVerification?.downstream_refusal_proven === false,
    ].every(bool),
    installed_runtime_profile_recognition_proof_preserved: [
      proofCounts.installed_runtime_profile_recognition_proof_verified === true,
      proofCounts.installed_runtime_profile_recognition_recognized_write_boarded === true,
      proofCounts.installed_runtime_profile_recognition_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
      proofCounts.installed_runtime_profile_recognition_all_refusals_before_mutation === true,
      proofCounts.installed_runtime_profile_recognition_source_preflight_downstream_refusal_proven === false,
      proofCounts.installed_runtime_profile_recognition_install_performed === false,
      proofCounts.installed_runtime_profile_recognition_activation_performed === false,
      proofCounts.installed_runtime_profile_recognition_runtime_service_started === false,
      proofCounts.installed_runtime_profile_recognition_current_machine_governance_proven === false,
      proofCounts.installed_runtime_profile_recognition_production_downstream_recognition === false,
      installedRuntimeProfileRecognitionProof
        ? installedRuntimeProfileRecognitionProof.recognized_boarding?.boarded === true
        : true,
      installedRuntimeProfileRecognitionProof
        ? installedRuntimeProfileRecognitionProof.refusal_cases?.length ===
          REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length
        : true,
      installedRuntimeProfileRecognitionProof
        ? installedRuntimeProfileRecognitionProof.refusal_cases.every((item) =>
          item.boarded === false &&
          item.service_write_accepted === false &&
          item.state_entry_count_delta === 0
        )
        : true,
      installedRuntimeProfileRecognitionProof
        ? installedRuntimeProfileRecognitionProof.proof_boundary?.runtime_service_started === false
        : true,
      installedRuntimeProfileRecognitionProof
        ? installedRuntimeProfileRecognitionProof.proof_boundary?.current_machine_governance_proven === false
        : true,
      installedRuntimeProfileRecognitionProof
        ? installedRuntimeProfileRecognitionProof.proof_boundary?.production_downstream_recognition === false
        : true,
    ].every(bool),
    installed_runtime_profile_recognition_contract_digest_required:
      installedRuntimeProfileRecognitionContractDigestRequired,
    installed_runtime_profile_recognition_contract_digest_preserved:
      installedRuntimeProfileRecognitionContractDigestPreserved,
    installed_runtime_profile_recognition_contract_sha256:
      installedRuntimeProfileRecognitionContractSha256,
    installed_runtime_profile_service_proof_preserved: [
      Boolean(installedRuntimeProfileServiceProof),
      proofCounts.installed_runtime_profile_service_proof_verified === true,
      proofCounts.installed_runtime_profile_service_runtime_service_started === true,
      proofCounts.installed_runtime_profile_service_disposable_runtime_config_written === true,
      proofCounts.installed_runtime_profile_service_persistent_runtime_config_written === false,
      proofCounts.installed_runtime_profile_service_config_path_exposed_to_request_stream === false,
      proofCounts.installed_runtime_profile_service_recognition_rule_bound_to_selected_profile === true,
      proofCounts.installed_runtime_profile_service_recognized_write_boarded === true,
      proofCounts.installed_runtime_profile_service_same_process_signed_payload_replay_refused === true,
      proofCounts.installed_runtime_profile_service_restart_consumed_authority_grant_refused === true,
      proofCounts.installed_runtime_profile_service_replay_identities_separate === true,
      proofCounts.installed_runtime_profile_service_consumed_store_integrity_case_count === 8,
      proofCounts.installed_runtime_profile_service_consumed_store_integrity_refusals_proven === true,
      proofCounts.installed_runtime_profile_service_all_consumed_store_integrity_refusals_before_mutation === true,
      proofCounts.installed_runtime_profile_service_single_host_consumed_store_rollback_detection === true,
      proofCounts.installed_runtime_profile_service_store_and_anchor_rollback_case_count === 1,
      proofCounts.installed_runtime_profile_service_store_and_anchor_joint_rollback_refusals_proven === true,
      proofCounts.installed_runtime_profile_service_all_store_and_anchor_rollback_refusals_before_mutation === true,
      proofCounts.installed_runtime_profile_service_store_and_anchor_joint_rollback_detection === true,
      proofCounts.installed_runtime_profile_service_store_anchor_and_witness_joint_rollback_detection === false,
      proofCounts.installed_runtime_profile_service_recognition_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
      proofCounts.installed_runtime_profile_service_authority_refusal_case_count ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length,
      proofCounts.installed_runtime_profile_service_all_authority_refusals_before_consumption_and_mutation === true,
      proofCounts.installed_runtime_profile_service_state_append_after_grant_commit_burn_observed === true,
      proofCounts.installed_runtime_profile_service_metadata_partial_commit_burn_observed === true,
      proofCounts.installed_runtime_profile_service_store_and_anchor_rollback_refused_while_witness_ahead === true,
      proofCounts.installed_runtime_profile_service_store_anchor_and_witness_joint_rollback_detection === false,
      proofCounts.installed_runtime_profile_service_joint_rollback_reopened_authority_grant_reuse === true,
      proofCounts.installed_runtime_profile_service_fixture_rightful_issuance_path_evidenced === true,
      proofCounts.installed_runtime_profile_service_source_preflight_downstream_refusal_proven === false,
      proofCounts.installed_runtime_profile_service_install_performed === false,
      proofCounts.installed_runtime_profile_service_activation_performed === false,
      proofCounts.installed_runtime_profile_service_current_machine_governance_proven === false,
      proofCounts.installed_runtime_profile_service_production_downstream_recognition === false,
      installedRuntimeProfileServiceProof?.recognized_boarding?.boarded === true,
      installedRuntimeProfileServiceProof?.proof_boundary?.runtime_service_started === true,
      installedRuntimeProfileServiceProof?.proof_boundary?.persistent_runtime_config_written === false,
      installedRuntimeProfileServiceProof?.service_config_provenance?.config_path_exposed_to_request_stream === false,
      installedRuntimeProfileServiceProof?.service_config_provenance?.recognition_rule_bound_to_selected_profile === true,
      installedRuntimeProfileServiceProof?.service_replay_cases?.length === 2,
      installedRuntimeProfileServiceProof?.service_replay_cases?.every((item) =>
        item.boarded === false &&
        item.service_write_accepted === false &&
        item.state_entry_count_delta === 0
      ) === true,
      installedRuntimeProfileServiceProof?.proof_boundary?.same_process_signed_payload_replay_refused === true,
      installedRuntimeProfileServiceProof?.proof_boundary?.restart_consumed_authority_grant_refused === true,
      installedRuntimeProfileServiceProof?.consumed_store_integrity_cases?.length === 8,
      installedRuntimeProfileServiceProof?.consumed_store_integrity_cases?.every((item) =>
        item.boarded === false &&
        item.service_write_accepted === false &&
        item.state_entry_count_delta === 0
      ) === true,
      installedRuntimeProfileServiceProof?.proof_boundary?.single_host_consumed_store_rollback_detection === true,
      installedRuntimeProfileServiceProof?.store_and_anchor_rollback_cases?.length === 1,
      installedRuntimeProfileServiceProof?.store_and_anchor_rollback_cases?.every((item) =>
        item.boarded === false &&
        item.service_write_accepted === false &&
        item.state_entry_count_delta === 0
      ) === true,
      installedRuntimeProfileServiceProof?.proof_boundary?.store_and_anchor_joint_rollback_detection === true,
      installedRuntimeProfileServiceProof?.proof_boundary?.store_anchor_and_witness_joint_rollback_detection === false,
      installedRuntimeProfileServiceProof?.refusal_cases?.length ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
      installedRuntimeProfileServiceProof?.authority_refusal_cases?.length ===
        REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length,
      installedRuntimeProfileServiceProof?.refusal_cases?.every((item) =>
        item.boarded === false &&
        item.service_write_accepted === false &&
        item.state_entry_count_delta === 0
      ) === true,
      installedRuntimeProfileServiceProof?.authority_refusal_cases?.every((item) =>
        item.boarded === false &&
        item.service_write_accepted === false &&
        item.state_entry_count_delta === 0
      ) === true,
      installedRuntimeProfileServiceProof?.service_boundary
        ?.mutation_authoritative_route ===
        EXACT_RUNTIME_MUTATION_AUTHORITATIVE_ROUTE,
      installedRuntimeProfileServiceProof?.proof_boundary
        ?.fixture_rightful_issuance_path_evidenced === true,
      installedRuntimeProfileServiceProof?.proof_boundary
        ?.rightful_issuance_proven === false,
      installedRuntimeProfileServiceProof?.proof_boundary
        ?.production_rightful_issuance_proven === false,
      installedRuntimeProfileServiceProof?.proof_boundary
        ?.consequence_lifecycle_closed === false,
      installedRuntimeProfileServiceProof?.proof_boundary?.current_machine_governance_proven === false,
      installedRuntimeProfileServiceProof?.proof_boundary?.production_downstream_recognition === false,
    ].every(bool),
    installed_runtime_profile_service_artifact_verification_preserved:
      installedRuntimeProfileServiceProofArtifactVerificationExpected &&
      [
        Boolean(installedRuntimeProfileServiceProofArtifactVerification),
        installedRuntimeProfileServiceProofArtifactVerificationAvailable,
        proofCounts.installed_runtime_profile_service_artifact_verification_verified === true,
        proofCounts.installed_runtime_profile_service_artifact_verification_payload_type ===
          'zlar-protected-records-installed-runtime-profile-service-proof-v1',
        /^[a-f0-9]{64}$/.test(
          proofCounts.installed_runtime_profile_service_artifact_verification_body_sha256 || ''
        ),
        proofCounts.installed_runtime_profile_service_artifact_verification_body_sha256 ===
          installedRuntimeProfileServiceProofArtifactBodySha256,
        installedRuntimeProfileServiceProofArtifactVerification?.body_sha256 ===
          installedRuntimeProfileServiceProofArtifactBodySha256,
        proofCounts.installed_runtime_profile_service_artifact_verification_runtime_service_started === true,
        proofCounts.installed_runtime_profile_service_artifact_verification_recognized_write_boarded === true,
        proofCounts.installed_runtime_profile_service_artifact_verification_restart_replay_refused === true,
        proofCounts.installed_runtime_profile_service_artifact_verification_consumed_store_integrity_case_count === 8,
        proofCounts.installed_runtime_profile_service_artifact_verification_store_and_anchor_rollback_case_count === 1,
        proofCounts.installed_runtime_profile_service_artifact_verification_store_and_anchor_joint_rollback_detection === true,
        proofCounts.installed_runtime_profile_service_artifact_verification_store_anchor_and_witness_joint_rollback_detection === false,
        proofCounts.installed_runtime_profile_service_artifact_verification_all_refusals_before_mutation === true,
        installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomySatisfied,
        installedRuntimeProfileRecognitionContractDigestSatisfied,
        proofCounts.installed_runtime_profile_service_artifact_verification_current_machine_governance_proven === false,
        proofCounts.installed_runtime_profile_service_artifact_verification_production_downstream_recognition === false,
        installedRuntimeProfileServiceProofArtifactVerification?.payload_type ===
          installedRuntimeProfileServiceProof?.proof_type,
        installedRuntimeProfileServiceProofArtifactVerification?.runtime_service_started ===
          installedRuntimeProfileServiceProof?.proof_boundary?.runtime_service_started,
        installedRuntimeProfileServiceProofArtifactVerification?.recognized_write_boarded ===
          installedRuntimeProfileServiceProof?.recognized_boarding?.boarded,
        installedRuntimeProfileServiceProofArtifactVerification?.restart_replay_refused ===
          installedRuntimeProfileServiceProof?.proof_boundary?.cross_process_replay_after_restart_closed,
        installedRuntimeProfileServiceProofArtifactVerification?.consumed_store_integrity_case_count ===
          installedRuntimeProfileServiceProof?.consumed_store_integrity_cases?.length,
        installedRuntimeProfileServiceProofArtifactVerification?.store_and_anchor_rollback_case_count ===
          installedRuntimeProfileServiceProof?.store_and_anchor_rollback_cases?.length,
        installedRuntimeProfileServiceProofArtifactVerification?.store_and_anchor_joint_rollback_detection ===
          installedRuntimeProfileServiceProof?.proof_boundary?.store_and_anchor_joint_rollback_detection,
        installedRuntimeProfileServiceProofArtifactVerification?.store_anchor_and_witness_joint_rollback_detection ===
          installedRuntimeProfileServiceProof?.proof_boundary?.store_anchor_and_witness_joint_rollback_detection,
        installedRuntimeProfileServiceProofArtifactVerification?.all_refusals_before_mutation === true,
        installedRuntimeProfileServiceProofArtifactVerification?.current_machine_governance_proven === false,
        installedRuntimeProfileServiceProofArtifactVerification?.production_downstream_recognition === false,
      ].every(bool),
    installed_runtime_profile_service_artifact_verification_required:
      installedRuntimeProfileServiceProofArtifactVerificationRequired,
    installed_runtime_profile_service_artifact_verification_refusal_taxonomy_required:
      installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomyRequired,
    installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved:
      installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomyPreserved,
    installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256:
      installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomySha256,
    installed_runtime_profile_terminal_chain_preserved:
      installedRuntimeProfileTerminalChainPreserved,
    installed_runtime_profile_terminal_chain_required:
      installedRuntimeProfileTerminalChainRequired,
    installed_runtime_profile_terminal_chain_refusal_taxonomy_required:
      installedRuntimeProfileTerminalChainRefusalTaxonomyRequired,
    installed_runtime_profile_terminal_chain_refusal_taxonomy_preserved:
      installedRuntimeProfileTerminalChainRefusalTaxonomyPreserved,
    installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256:
      installedRuntimeProfileTerminalChainRefusalTaxonomySha256,
    installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256:
      installedRuntimeProfileTerminalChainArtifactVerificationRefusalTaxonomySha256,
    installed_runtime_profile_terminal_chain_named_receipt_refusals_required:
      installedRuntimeProfileTerminalChainNamedReceiptRefusalsRequired,
    installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved:
      installedRuntimeProfileTerminalChainNamedReceiptRefusalsPreserved,
    installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256:
      installedRuntimeProfileTerminalChainNamedReceiptRefusalsSha256,
    installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256:
      installedRuntimeProfileTerminalChainArtifactVerificationNamedReceiptRefusalsSha256,
    installed_runtime_profile_terminal_chain_recognition_refusal_groups_required:
      installedRuntimeProfileTerminalChainRecognitionRefusalGroupsRequired,
    installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved:
      installedRuntimeProfileTerminalChainRecognitionRefusalGroupsPreserved,
    installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256:
      installedRuntimeProfileTerminalChainRecognitionRefusalGroupsSha256,
    installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256:
      installedRuntimeProfileTerminalChainArtifactVerificationRecognitionRefusalGroupsSha256,
    installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required:
      installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsRequired,
    installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved:
      installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsPreserved,
    installed_runtime_profile_terminal_chain_recognition_refusal_group_count:
      installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_recognition_refusal_group_count || 0
        : 0,
    installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count:
      installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count || 0
        : 0,
    installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids:
      installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids || {}
        : {},
    installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count:
      installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count || 0
        : 0,
    installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count:
      installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count || 0
        : 0,
    installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids:
      installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids || {}
        : {},
    installed_runtime_profile_terminal_chain_nested_artifact_binding_required:
      installedRuntimeProfileTerminalChainNestedArtifactBindingRequired,
    installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved:
      installedRuntimeProfileTerminalChainNestedArtifactBindingPreserved,
    installed_runtime_profile_terminal_chain_nested_preflight_artifact_type:
      installedRuntimeProfileTerminalChainNestedPreflightArtifactType,
    installed_runtime_profile_terminal_chain_nested_service_proof_artifact_type:
      installedRuntimeProfileTerminalChainNestedServiceProofArtifactType,
    installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved:
      installedRuntimeProfileTerminalChainNestedArtifactBindingExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved === true
        : false,
    installed_runtime_profile_terminal_chain_artifact_verification_nested_preflight_artifact_type:
      installedRuntimeProfileTerminalChainArtifactVerificationNestedPreflightArtifactType,
    installed_runtime_profile_terminal_chain_artifact_verification_nested_service_proof_artifact_type:
      installedRuntimeProfileTerminalChainArtifactVerificationNestedServiceProofArtifactType,
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_required:
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingRequired,
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved:
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingPreserved,
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256:
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryBindingSha256,
    installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256:
      installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryBindingSha256,
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved:
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryRecognitionRefusalsPreserved,
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count:
      proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count || 0,
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused:
      proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused === true,
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids:
      proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids || [],
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes:
      proofCounts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes || [],
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256:
      installedRuntimeProfileTerminalChainTrustedIssuerRegistryRecognitionRefusalsSha256,
    installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count:
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count || 0,
    installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused:
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused === true,
    installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids:
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids || [],
    installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes:
      proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes || [],
    installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256:
      installedRuntimeProfileTerminalChainArtifactVerificationTrustedIssuerRegistryRecognitionRefusalsSha256,
    ...(terminalChainRecognizedReceiptPathMirrorExpected
      ? {
          installed_runtime_profile_terminal_chain_recognized_receipt_path_mirror_required:
            terminalChainRecognizedReceiptPathMirrorRequired,
          installed_runtime_profile_terminal_chain_recognized_receipt_path_mirror_preserved:
            terminalChainRecognizedReceiptPathMirrorPreserved,
          installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256:
            terminalChainRecognizedReceiptPathEvidenceSha256,
          installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_sha256:
            terminalChainArtifactVerificationRecognizedReceiptPathEvidenceSha256,
          installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_bound_to_artifact_body:
            installedRuntimeProfileTerminalChainArtifactVerification
              ?.recognized_receipt_path_evidence_bound_to_artifact_body === true,
          installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256:
            terminalChainRecognizedReceiptPathSourceBindingSha256,
          installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_sha256:
            terminalChainArtifactVerificationRecognizedReceiptPathSourceBindingSha256,
          installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_matches_trusted_registry_binding:
            terminalChainRecognizedReceiptPathSourceBindingMatchesTrustedRegistryBinding,
          installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_matches_trusted_registry_binding:
            terminalChainArtifactVerificationRecognizedReceiptPathSourceBindingMatchesTrustedRegistryBinding,
          installed_runtime_profile_terminal_chain_recognized_receipt_path_verdict:
            terminalChainRecognizedReceiptPathEvidence.verdict || 'not-provided',
          installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_verdict:
            terminalChainArtifactVerificationRecognizedReceiptPathEvidence.verdict || 'not-provided',
          installed_runtime_profile_terminal_chain_recognized_receipt_path_recognized:
            terminalChainRecognizedReceiptPathEvidence.recognized === true,
          installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_recognized:
            terminalChainArtifactVerificationRecognizedReceiptPathEvidence.recognized === true,
          installed_runtime_profile_terminal_chain_recognized_receipt_path_receipt_envelope_included:
            terminalChainRecognizedReceiptPathEvidence.receipt_envelope_included === true,
          installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_receipt_envelope_included:
            terminalChainArtifactVerificationRecognizedReceiptPathEvidence.receipt_envelope_included === true,
          installed_runtime_profile_terminal_chain_recognized_receipt_path_registry_public_key_material_included:
            terminalChainRecognizedReceiptPathEvidence.registry_public_key_material_included === true,
          installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_registry_public_key_material_included:
            terminalChainArtifactVerificationRecognizedReceiptPathEvidence.registry_public_key_material_included === true,
          installed_runtime_profile_terminal_chain_recognized_receipt_path_artifact_crypto_reproducible:
            terminalChainRecognizedReceiptPathEvidence.cryptographic_evidence_reproducible_from_artifact === true,
          installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_artifact_crypto_reproducible:
            terminalChainArtifactVerificationRecognizedReceiptPathEvidence.cryptographic_evidence_reproducible_from_artifact === true,
          installed_runtime_profile_terminal_chain_recognized_receipt_path_live_state_proven:
            terminalChainRecognizedReceiptPathEvidence.live_trust_registry_state === true,
          installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_live_state_proven:
            terminalChainArtifactVerificationRecognizedReceiptPathEvidence.live_trust_registry_state === true,
          installed_runtime_profile_terminal_chain_recognized_receipt_path_live_issuer_status_proven:
            terminalChainRecognizedReceiptPathEvidence.live_issuer_status_proven === true,
          installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_live_issuer_status_proven:
            terminalChainArtifactVerificationRecognizedReceiptPathEvidence.live_issuer_status_proven === true,
          installed_runtime_profile_terminal_chain_recognized_receipt_path_key_custody_proven:
            terminalChainRecognizedReceiptPathEvidence.key_custody_proven === true,
          installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_key_custody_proven:
            terminalChainArtifactVerificationRecognizedReceiptPathEvidence.key_custody_proven === true,
          installed_runtime_profile_terminal_chain_recognized_receipt_path_revocation_truth_proven:
            terminalChainRecognizedReceiptPathEvidence.revocation_truth_proven === true,
          installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_revocation_truth_proven:
            terminalChainArtifactVerificationRecognizedReceiptPathEvidence.revocation_truth_proven === true,
          installed_runtime_profile_terminal_chain_recognized_receipt_path_production_downstream_recognition_proven:
            terminalChainRecognizedReceiptPathEvidence.production_downstream_recognition_proven === true,
          installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_production_downstream_recognition_proven:
            terminalChainArtifactVerificationRecognizedReceiptPathEvidence.production_downstream_recognition_proven === true,
          installed_runtime_profile_terminal_chain_recognized_receipt_path_public_external_attestation:
            terminalChainRecognizedReceiptPathEvidence.public_external_attestation === true,
          installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_public_external_attestation:
            terminalChainArtifactVerificationRecognizedReceiptPathEvidence.public_external_attestation === true,
          installed_runtime_profile_terminal_chain_recognized_receipt_path_sovereign_recognition:
            terminalChainRecognizedReceiptPathEvidence.sovereign_recognition === true,
          installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_sovereign_recognition:
            terminalChainArtifactVerificationRecognizedReceiptPathEvidence.sovereign_recognition === true,
          installed_runtime_profile_terminal_chain_recognized_receipt_path_current_machine_governance_proven:
            terminalChainRecognizedReceiptPathEvidence.current_machine_governance_proven === true,
          installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_current_machine_governance_proven:
            terminalChainArtifactVerificationRecognizedReceiptPathEvidence.current_machine_governance_proven === true,
        }
      : {}),
    installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required:
      terminalChainDeploymentProfileAuthorityRefusalMirrorRequired,
    installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved:
      terminalChainDeploymentProfileAuthorityRefusalMirrorPreserved,
    installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count || 0
        : 0,
    installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids || []
        : [],
    installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof === true
        : false,
    installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation === true
        : false,
    installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started === true
        : false,
    installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance === true
        : false,
    installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition === true
        : false,
    installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority === true
        : false,
    installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness === true
        : false,
    installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation === true
        : false,
    installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition === true
        : false,
    installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage === true
        : false,
    installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count || 0
        : 0,
    installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids || []
        : [],
    installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof === true
        : false,
    installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation === true
        : false,
    installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started === true
        : false,
    installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_current_machine_governance:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_current_machine_governance === true
        : false,
    installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_downstream_recognition:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_downstream_recognition === true
        : false,
    installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_authority:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_authority === true
        : false,
    installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_enterprise_readiness:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_enterprise_readiness === true
        : false,
    installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_external_attestation:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_external_attestation === true
        : false,
    installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_sovereign_recognition:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_sovereign_recognition === true
        : false,
    installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_unrouted_surface_coverage:
      terminalChainDeploymentProfileAuthorityRefusalMirrorExpected
        ? proofCounts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_unrouted_surface_coverage === true
        : false,
    runtime_refusal_taxonomy_preserved: [
      runtimeLocalActivationVerification?.wrong_policy_refused,
      runtimeLocalActivationVerification?.wrong_domain_refused,
      runtimeLocalActivationVerification?.wrong_tool_refused,
      runtimeLocalActivationVerification?.wrong_runtime_profile_id_refused,
      runtimeLocalActivationVerification?.wrong_audit_event_refused,
      runtimeLocalActivationVerification?.wrong_detail_refused,
      runtimeLocalActivationVerification?.non_boarding_outcome_refused,
      runtimeLocalActivationVerification?.stale_receipt_refused,
      runtimeLocalActivationVerification?.missing_issuer_status_refused,
      runtimeLocalActivationVerification?.direct_api_with_receipt_refused,
      runtimeLocalActivationVerification?.agent_supplied_authority_material_refused,
      runtimeProfileInstallationVerification?.wrong_runtime_profile_id_refused,
      packRuntimeActivation?.wrong_runtime_profile_id_refused,
      packRuntimeInstallation?.wrong_runtime_profile_id_refused,
      proofCounts.installed_runtime_profile_recognition_all_refusals_before_mutation,
      proofCounts.installed_runtime_profile_service_all_refusals_before_mutation,
      installedRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomySatisfied,
      installedRuntimeProfileTerminalChainSatisfied,
      installedRuntimeProfileTerminalChainRefusalTaxonomySatisfied,
      installedRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIdsSatisfied,
    ].every(bool),
    product_proof_path_verified:
      productProofPath.provided === true &&
      productProofPath.report_type === PRODUCT_PROOF_PATH_REPORT_TYPE &&
      productProofPath.result === 'PASS' &&
      productProofPath.acceptance_gate_passed === true &&
      productProofPath.proof_pack_verified === true &&
      runtimeProfileIdentityPolicySummaryPasses(
        productProofPath.proof_pack_runtime_profile_identity_policy
      ) &&
      productProofPathClaudeHookReplaySummaryPasses(
        productProofPath.proof_pack_claude_hook_contract_replay
      ) &&
      productProofPath.governed_action_allowed === true &&
      productProofPath.governed_action_refused === true &&
      productProofPath.simulated_human_authorization_observed === true &&
      productProofPath.receipt_verification_observed === true &&
      productProofPath.trusted_issuer_registry_recognition_observed === true &&
      productProofPathDeploymentProfileAuthorityBridgePreserved === true &&
      (
        !productProofPathDeploymentProfileAuthorityRefusalsRequired ||
        productProofPathDeploymentProfileAuthorityRefusalsPreserved === true
      ) &&
      productProofPath.non_coverage_visible === true &&
      productProofPath.forbidden_claims_false === true &&
      productProofPath.live_probing === false &&
      productProofPath.private_operator_state_required === false,
    product_proof_path_deployment_profile_authority_bridge_required:
      productProofPathDeploymentProfileAuthorityBridgeRequired,
    product_proof_path_deployment_profile_authority_bridge_preserved:
      productProofPathDeploymentProfileAuthorityBridgePreserved,
    product_proof_path_deployment_profile_authority_refusals_required:
      productProofPathDeploymentProfileAuthorityRefusalsRequired,
    product_proof_path_deployment_profile_authority_refusals_preserved:
      productProofPathDeploymentProfileAuthorityRefusalsPreserved,
    historical_active_persistent_profile_lifecycle_provided:
      historicalActivePersistentProfileLifecycle.provided === true,
    historical_active_persistent_profile_lifecycle_verified:
      historicalActivePersistentProfileLifecycle.verified === true,
    historical_active_persistent_profile_lifecycle_expected_hashes_bound:
      historicalActivePersistentProfileLifecycle.expected_input_report_hashes_bound === true,
    historical_active_persistent_profile_lifecycle_non_scoring:
      historicalActivePersistentProfileLifecycle.non_scoring === true,
    historical_active_persistent_profile_lifecycle_current_installation:
      historicalActivePersistentProfileLifecycle.current_installation === true,
    historical_active_persistent_profile_lifecycle_product_proof_path_completion:
      historicalActivePersistentProfileLifecycle.provided === true &&
      historicalActivePersistentProfileLifecycle.does_not_complete_product_proof_path !== true,
    historical_active_persistent_profile_lifecycle_enterprise_deployment_profile_completion:
      historicalActivePersistentProfileLifecycle.provided === true &&
      historicalActivePersistentProfileLifecycle.does_not_complete_enterprise_deployment_profile !== true,
    historical_active_persistent_profile_lifecycle_current_machine_governance_general:
      historicalActivePersistentProfileLifecycle.current_machine_governance_general === true,
    historical_active_persistent_profile_lifecycle_production_downstream_recognition:
      historicalActivePersistentProfileLifecycle.production_downstream_recognition === true,
  };

  return {
    report_type: NORTH_STAR_READINESS_REPORT_TYPE,
    schema_version: 1,
    result: v34ReadyViaPublicDistribution
      ? NORTH_STAR_READINESS_RESULT_READY_PUBLIC_DISTRIBUTION
      : NORTH_STAR_READINESS_RESULT_NOT_READY,
    evidence_model: evidenceModel,
    action_class: 'records.write',
    selected_terminal: {
      surface_id: 'protected-records.runtime.profile-installation.records.write',
      deployment_profile: 'protected-records-disposable-runtime-profile',
      downstream_boundary: 'protected-records-runtime-service:local-jsonl-child-process',
      claim_scope: 'local disposable protected-records runtime/profile-installation fixture',
    },
    counts,
    puzzle_pieces: puzzlePieces,
    v3_4_0_gate: {
      ready: v34ReadyViaPublicDistribution,
      reason: v34ReadyViaPublicDistribution
        ? 'The verifier kit has public distribution posture with reproducible-build evidence, live release-asset evidence, and public artifact hashes. This supports a bounded v3.4.0 release decision without proving external attestation, production authority, enterprise readiness, or sovereign recognition.'
        : 'The evidence is strong local/release-forward proof-path hardening, but it has not changed class into external attestation, production deployment, or public verifier-kit distribution posture.',
      next_version_class: v34ReadyViaPublicDistribution
        ? 'v3.4.0-boundary-release-ready-public-verifier-kit-distribution'
        : 'v3.3.x-closure-or-v3.4.0-only-after-evidence-class-change',
      triggers_required: v34ReadyViaPublicDistribution
        ? []
        : [
            'non-Vincent verifier runs the pinned release-forward path and produces bounded signed or published attestation',
            'a named real deployment profile refuses missing or unrecognized receipts at the downstream boundary',
            'verifier kit moves to public distribution posture with reproducible-build evidence and public artifact hashes',
          ],
    },
    claim_boundary: {
      v3_4_0_ready: v34ReadyViaPublicDistribution,
      public_external_attestation: false,
      non_operator_review_proven: false,
      production_authority: false,
      enterprise_readiness: false,
      sovereign_recognition: false,
      current_machine_governance: false,
      live_hook_state: false,
      live_mcp_coverage: false,
      live_approval_channel_health: false,
      live_trust_registry_state: false,
      key_custody: false,
      revocation_truth: false,
      production_downstream_recognition: false,
      persistent_runtime_profile_installation: false,
      production_service_deployment: false,
      all_mcp_governance: false,
      unrouted_surface_coverage: false,
    },
    artifacts_consumed: artifactList({
      productProofPathReport,
      installedRuntimeProfileRecognitionProof,
      installedRuntimeProfileServiceProof,
      installedRuntimeProfileServiceProofArtifactVerification,
      installedRuntimeProfileTerminalChain,
      installedRuntimeProfileTerminalChainArtifact,
      installedRuntimeProfileTerminalChainArtifactVerification,
      recognition: trustedIssuerRecognition,
      trustedIssuerCompletionProof: trustedReceiptIssuerCompletionProof,
      malformedRegistryError: malformedRegistryErrorText,
      verifierKitReproducibility,
      verifierKitReleaseAssets,
      verifierKitPublicDistribution,
      privateVerifierResultVerification,
      privateVerifierZipResultVerification,
      publicArtifactVerifierResultVerification,
      publicExternalAttestationResultVerification,
      activePersistentProfileLifecycleEvidence,
    }),
    supplemental_evidence: {
      historical_supplied_local_active_persistent_profile_lifecycle:
        historicalActivePersistentProfileLifecycle,
    },
    non_claims: northStarReadinessNonClaims(
      v34ReadyViaPublicDistribution,
      privateVerifierResult.private_non_operator_pass_validated,
      privateVerifierZipResult
        .private_personally_connected_outside_machine_signal_validated
    ),
  };
}

export function assertNorthStarReadinessReport(report) {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
    'North Star readiness fixture-rightful report acceptance',
  );
  throw new Error(
    'North Star readiness v1 fixture-rightful schema is retired; a replacement grant requires a new artifact-bound historical/current schema',
  );
  exactKeys('North Star readiness report', report, [
    'action_class',
    'artifacts_consumed',
    'claim_boundary',
    'counts',
    'evidence_model',
    'non_claims',
    'puzzle_pieces',
    'report_type',
    'result',
    'schema_version',
    'selected_terminal',
    'supplemental_evidence',
    'v3_4_0_gate',
  ]);
  if (report.report_type !== NORTH_STAR_READINESS_REPORT_TYPE) {
    throw new Error('North Star readiness report type drifted');
  }
  if (report.schema_version !== 1) {
    throw new Error('North Star readiness schema version drifted');
  }
  if (
    report.result !== NORTH_STAR_READINESS_RESULT_NOT_READY &&
    report.result !== NORTH_STAR_READINESS_RESULT_READY_PUBLIC_DISTRIBUTION
  ) {
    throw new Error('North Star readiness result drifted');
  }
  if (
    report.evidence_model !== NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE &&
    report.evidence_model !== NORTH_STAR_READINESS_EVIDENCE_MODEL_RELEASE_FORWARD
  ) {
    throw new Error('North Star readiness evidence model drifted');
  }
  const releaseForwardTargetTag = releaseForwardTargetTagFromReport(report);
  const requiresRecognitionContractDigest =
    report.evidence_model === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 19);
  const requiresServiceArtifactVerification =
    report.evidence_model === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 14);
  const requiresServiceArtifactVerificationRefusalTaxonomy =
    report.evidence_model === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 18);
  const requiresTerminalChain =
    report.evidence_model === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 15);
  const requiresTerminalChainRefusalTaxonomy =
    report.evidence_model === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 17);
  const requiresTerminalChainNamedReceiptRefusals =
    report.evidence_model === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 22);
  const requiresTerminalChainRecognitionRefusalGroups =
    report.evidence_model === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 23);
  const requiresTerminalChainRecognitionRefusalGroupCaseIds =
    report.evidence_model === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 25);
  const requiresTerminalChainRecognitionRefusalGroupCaseIdObservedSummaries =
    report.evidence_model === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 26);
  const requiresTerminalChainNestedArtifactBinding =
    report.evidence_model === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 30);
  const requiresTerminalChainTrustedIssuerRegistryBinding =
    report.evidence_model === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 37);
  const requiresProductProofPathDeploymentProfileAuthorityBridge =
    report.evidence_model === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 48);
  const requiresProductProofPathDeploymentProfileAuthorityRefusals =
    report.evidence_model === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 49);
  const requiresTerminalChainDeploymentProfileAuthorityRefusalMirror =
    report.evidence_model === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 50);
  const requiresTerminalChainRecognizedReceiptPathMirror =
    report.evidence_model === NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE ||
    releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 52);
  if (report.action_class !== 'records.write') {
    throw new Error('North Star readiness action class drifted');
  }
  exactKeys('North Star selected terminal', report.selected_terminal, [
    'claim_scope',
    'deployment_profile',
    'downstream_boundary',
    'surface_id',
  ]);
  if (report.selected_terminal.surface_id !== 'protected-records.runtime.profile-installation.records.write') {
    throw new Error('North Star readiness selected terminal drifted');
  }
  const northStarCountKeys = [
    'counted_lanes',
    'governed_lanes',
    'historical_active_persistent_profile_lifecycle_current_installation',
    'historical_active_persistent_profile_lifecycle_current_machine_governance_general',
    'historical_active_persistent_profile_lifecycle_enterprise_deployment_profile_completion',
    'historical_active_persistent_profile_lifecycle_expected_hashes_bound',
    'historical_active_persistent_profile_lifecycle_non_scoring',
    'historical_active_persistent_profile_lifecycle_product_proof_path_completion',
    'historical_active_persistent_profile_lifecycle_production_downstream_recognition',
    'historical_active_persistent_profile_lifecycle_provided',
    'historical_active_persistent_profile_lifecycle_verified',
    'installed_runtime_profile_recognition_contract_digest_preserved',
    'installed_runtime_profile_recognition_contract_digest_required',
    'installed_runtime_profile_recognition_contract_sha256',
    'installed_runtime_profile_recognition_proof_preserved',
    'installed_runtime_profile_service_artifact_verification_preserved',
    'installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved',
    'installed_runtime_profile_service_artifact_verification_refusal_taxonomy_required',
    'installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256',
    'installed_runtime_profile_service_artifact_verification_required',
    'installed_runtime_profile_preflight_no_effect_boundary_preserved',
    'installed_runtime_profile_preflight_recognition_contract_preserved',
    'installed_runtime_profile_preflight_verified',
    'installed_runtime_profile_service_proof_preserved',
    'installed_runtime_profile_terminal_chain_preserved',
    'installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved',
    'installed_runtime_profile_terminal_chain_artifact_verification_nested_preflight_artifact_type',
    'installed_runtime_profile_terminal_chain_artifact_verification_nested_service_proof_artifact_type',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256',
    'installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved',
    'installed_runtime_profile_terminal_chain_named_receipt_refusals_required',
    'installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256',
    'installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved',
    'installed_runtime_profile_terminal_chain_nested_artifact_binding_required',
    'installed_runtime_profile_terminal_chain_nested_preflight_artifact_type',
    'installed_runtime_profile_terminal_chain_nested_service_proof_artifact_type',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_required',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256',
    'installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count',
    'installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids',
    'installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved',
    'installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required',
    'installed_runtime_profile_terminal_chain_recognition_refusal_group_count',
    'installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved',
    'installed_runtime_profile_terminal_chain_recognition_refusal_groups_required',
    'installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256',
    'installed_runtime_profile_terminal_chain_refusal_taxonomy_preserved',
    'installed_runtime_profile_terminal_chain_refusal_taxonomy_required',
    'installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256',
    'installed_runtime_profile_terminal_chain_required',
    'partial_count',
    'product_proof_path_deployment_profile_authority_bridge_preserved',
    'product_proof_path_deployment_profile_authority_bridge_required',
    'product_proof_path_verified',
    'proven_count',
    'puzzle_pieces_total',
    'runtime_refusal_taxonomy_preserved',
    'service_preflight_cases',
    'unproven_count',
  ];
  if (
    requiresProductProofPathDeploymentProfileAuthorityRefusals ||
    hasAnyOwnKey(report.counts, [
      'product_proof_path_deployment_profile_authority_refusals_preserved',
      'product_proof_path_deployment_profile_authority_refusals_required',
    ])
  ) {
    northStarCountKeys.push(
      'product_proof_path_deployment_profile_authority_refusals_preserved',
      'product_proof_path_deployment_profile_authority_refusals_required',
    );
  }
  if (
    requiresTerminalChainRecognizedReceiptPathMirror ||
    hasAnyOwnKey(
      report.counts,
      TERMINAL_CHAIN_RECOGNIZED_RECEIPT_PATH_MIRROR_COUNT_KEYS,
    )
  ) {
    northStarCountKeys.push(
      ...TERMINAL_CHAIN_RECOGNIZED_RECEIPT_PATH_MIRROR_COUNT_KEYS,
    );
  }
  if (
    requiresTerminalChainDeploymentProfileAuthorityRefusalMirror ||
    hasAnyOwnKey(report.counts, [
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_current_machine_governance',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_downstream_recognition',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_authority',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_enterprise_readiness',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_external_attestation',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_sovereign_recognition',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_unrouted_surface_coverage',
    ])
  ) {
    northStarCountKeys.push(
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_current_machine_governance',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_downstream_recognition',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_authority',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_enterprise_readiness',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_external_attestation',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_sovereign_recognition',
      'installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_unrouted_surface_coverage',
    );
  }
  exactKeys('North Star counts', report.counts, northStarCountKeys);
  const trustedIssuerForCount = report.puzzle_pieces.find((piece) => piece.id === 4);
  const trustedIssuerCompletionForCount =
    trustedIssuerForCount?.observed?.trusted_receipt_issuer_completion_proof;
  const trustedIssuerCompletionCounted =
    trustedIssuerCompletionForCount?.provided === true &&
    trustedIssuerCompletionForCount?.verified === true &&
    trustedIssuerCompletionForCount?.completed_for_selected_surface === true;
  const expectedProvenCount = trustedIssuerCompletionCounted ? 6 : 5;
  const expectedPartialCount = trustedIssuerCompletionCounted ? 0 : 1;
  if (
    report.counts.puzzle_pieces_total !== 7 ||
    report.counts.proven_count !== expectedProvenCount ||
    report.counts.partial_count !== expectedPartialCount ||
    report.counts.unproven_count !== 1
  ) {
    const enterprisePiece = report.puzzle_pieces.find((piece) => piece.id === 3);
    throw new Error(
      `North Star puzzle-piece counts drifted: proven=${report.counts.proven_count}/${expectedProvenCount}; partial=${report.counts.partial_count}/${expectedPartialCount}; unproven=${report.counts.unproven_count}/1; enterprise_terminal_preserved=${enterprisePiece?.observed?.installed_runtime_profile_terminal_chain_verified}; enterprise_service_verified=${enterprisePiece?.observed?.installed_runtime_profile_service_proof_verified}; enterprise_service_artifact_verified=${enterprisePiece?.observed?.installed_runtime_profile_service_artifact_verification_verified}; enterprise_service_rightful=${enterprisePiece?.observed?.installed_runtime_profile_service_rightful_contract_preserved}; terminal_taxonomy=${enterprisePiece?.observed?.installed_runtime_profile_terminal_chain_refusal_taxonomy_preserved}; terminal_named=${enterprisePiece?.observed?.installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved}; terminal_groups=${enterprisePiece?.observed?.installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved}; terminal_nested=${enterprisePiece?.observed?.installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved}; terminal_registry=${enterprisePiece?.observed?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved}; terminal_recognition_digest=${enterprisePiece?.observed?.installed_runtime_profile_recognition_contract_digest_preserved}`,
    );
  }
  if (report.counts.governed_lanes !== 6 || report.counts.counted_lanes !== 6) {
    throw new Error('North Star coverage lane counts drifted');
  }
  exactKeys('North Star supplemental evidence', report.supplemental_evidence, [
    'historical_supplied_local_active_persistent_profile_lifecycle',
  ]);
  const historicalActivePersistentProfileLifecycle =
    report.supplemental_evidence
      .historical_supplied_local_active_persistent_profile_lifecycle;
  assertHistoricalActivePersistentProfileLifecycleSummary(
    'North Star historical active persistent lifecycle supplemental evidence',
    historicalActivePersistentProfileLifecycle,
  );
  if (
    report.counts.historical_active_persistent_profile_lifecycle_provided !==
      (historicalActivePersistentProfileLifecycle.provided === true) ||
    report.counts.historical_active_persistent_profile_lifecycle_verified !==
      (historicalActivePersistentProfileLifecycle.verified === true) ||
    report.counts.historical_active_persistent_profile_lifecycle_expected_hashes_bound !==
      (historicalActivePersistentProfileLifecycle.expected_input_report_hashes_bound === true) ||
    report.counts.historical_active_persistent_profile_lifecycle_non_scoring !==
      (historicalActivePersistentProfileLifecycle.non_scoring === true) ||
    report.counts.historical_active_persistent_profile_lifecycle_current_installation !== false ||
    report.counts.historical_active_persistent_profile_lifecycle_product_proof_path_completion !== false ||
    report.counts.historical_active_persistent_profile_lifecycle_enterprise_deployment_profile_completion !== false ||
    report.counts.historical_active_persistent_profile_lifecycle_current_machine_governance_general !== false ||
    report.counts.historical_active_persistent_profile_lifecycle_production_downstream_recognition !== false
  ) {
    throw new Error('North Star historical active persistent lifecycle counts drifted');
  }
  if (report.counts.service_preflight_cases !== 11) {
    throw new Error('North Star service preflight case count drifted');
  }
  if (report.counts.installed_runtime_profile_preflight_verified !== true) {
    throw new Error('North Star installed runtime profile preflight verification count must be true');
  }
  if (report.counts.installed_runtime_profile_preflight_no_effect_boundary_preserved !== true) {
    throw new Error('North Star installed runtime profile preflight no-effect boundary drifted');
  }
  if (report.counts.installed_runtime_profile_preflight_recognition_contract_preserved !== true) {
    throw new Error('North Star installed runtime profile preflight recognition contract drifted');
  }
  if (report.counts.installed_runtime_profile_recognition_proof_preserved !== true) {
    throw new Error('North Star installed runtime profile recognition proof drifted');
  }
  if (typeof report.counts.installed_runtime_profile_recognition_contract_digest_required !== 'boolean') {
    throw new Error('North Star installed runtime profile recognition contract digest required flag drifted');
  }
  if (
    requiresRecognitionContractDigest &&
    report.counts.installed_runtime_profile_recognition_contract_digest_required !== true
  ) {
    throw new Error('North Star readiness must require installed runtime profile recognition contract digest');
  }
  const recognitionContractDigestProvided = isSha256Hex(
    report.counts.installed_runtime_profile_recognition_contract_sha256
  );
  if (
    report.counts.installed_runtime_profile_recognition_contract_digest_required === true &&
    report.counts.installed_runtime_profile_recognition_contract_digest_preserved !== true
  ) {
    throw new Error('North Star installed runtime profile recognition contract digest drifted');
  }
  if (
    recognitionContractDigestProvided !==
    report.counts.installed_runtime_profile_recognition_contract_digest_preserved
  ) {
    throw new Error('North Star installed runtime profile recognition contract digest boundary drifted');
  }
  if (report.counts.installed_runtime_profile_service_proof_preserved !== true) {
    throw new Error('North Star installed runtime profile service proof drifted');
  }
  if (typeof report.counts.installed_runtime_profile_service_artifact_verification_required !== 'boolean') {
    throw new Error('North Star installed runtime profile service proof artifact verification required flag drifted');
  }
  if (
    requiresServiceArtifactVerification &&
    report.counts.installed_runtime_profile_service_artifact_verification_required !== true
  ) {
    throw new Error('North Star readiness must require installed runtime profile service proof artifact verification');
  }
  const serviceProofArtifactVerificationConsumed =
    Array.isArray(report.artifacts_consumed) &&
    report.artifacts_consumed.includes('zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json');
  if (
    (report.counts.installed_runtime_profile_service_artifact_verification_required === true ||
      serviceProofArtifactVerificationConsumed) &&
    report.counts.installed_runtime_profile_service_artifact_verification_preserved !== true
  ) {
    throw new Error('North Star installed runtime profile service proof artifact verification drifted');
  }
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_required === false &&
    serviceProofArtifactVerificationConsumed === false &&
    report.counts.installed_runtime_profile_service_artifact_verification_preserved !== false
  ) {
    throw new Error('North Star installed runtime profile service proof artifact verification optional boundary drifted');
  }
  if (typeof report.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_required !== 'boolean') {
    throw new Error('North Star installed runtime profile service proof artifact verification refusal taxonomy required flag drifted');
  }
  if (
    requiresServiceArtifactVerificationRefusalTaxonomy &&
    report.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_required !== true
  ) {
    throw new Error('North Star readiness must require installed runtime profile service proof artifact verification refusal taxonomy');
  }
  const serviceArtifactVerificationTaxonomyHashProvided = isSha256Hex(
    report.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256
  );
  if (
    report.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_required === true &&
    report.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved !== true
  ) {
    throw new Error('North Star installed runtime profile service proof artifact verification refusal taxonomy drifted');
  }
  if (
    serviceArtifactVerificationTaxonomyHashProvided !==
    report.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved
  ) {
    throw new Error('North Star installed runtime profile service proof artifact verification refusal taxonomy hash boundary drifted');
  }
  if (typeof report.counts.installed_runtime_profile_terminal_chain_required !== 'boolean') {
    throw new Error('North Star installed runtime profile terminal chain required flag drifted');
  }
  if (
    requiresTerminalChain &&
    report.counts.installed_runtime_profile_terminal_chain_required !== true
  ) {
    throw new Error('North Star readiness must require installed runtime profile terminal chain');
  }
  const terminalChainConsumed =
    Array.isArray(report.artifacts_consumed) &&
    report.artifacts_consumed.includes('zlar-installed-runtime-profile-terminal-chain-v1.json');
  const terminalChainArtifactVerificationConsumed =
    Array.isArray(report.artifacts_consumed) &&
    report.artifacts_consumed.includes('zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json');
  if (
    (report.counts.installed_runtime_profile_terminal_chain_required === true ||
      terminalChainConsumed ||
      terminalChainArtifactVerificationConsumed) &&
    report.counts.installed_runtime_profile_terminal_chain_preserved !== true
  ) {
    throw new Error('North Star installed runtime profile terminal chain drifted');
  }
  if (
    report.counts.installed_runtime_profile_terminal_chain_required === false &&
    terminalChainConsumed === false &&
    terminalChainArtifactVerificationConsumed === false &&
    report.counts.installed_runtime_profile_terminal_chain_preserved !== false
  ) {
    throw new Error('North Star installed runtime profile terminal chain optional boundary drifted');
  }
  if (typeof report.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_required !== 'boolean') {
    throw new Error('North Star installed runtime profile terminal chain refusal taxonomy required flag drifted');
  }
  if (
    requiresTerminalChainRefusalTaxonomy &&
    report.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_required !== true
  ) {
    throw new Error('North Star readiness must require installed runtime profile terminal chain refusal taxonomy');
  }
  const terminalChainTaxonomyHashProvided = isSha256Hex(
    report.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256
  );
  const terminalChainArtifactVerificationTaxonomyHashProvided = isSha256Hex(
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256
  );
  if (
    report.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_required === true &&
    report.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_preserved !== true
  ) {
    throw new Error('North Star installed runtime profile terminal chain refusal taxonomy drifted');
  }
  if (
    terminalChainTaxonomyHashProvided !==
      report.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_preserved ||
    terminalChainArtifactVerificationTaxonomyHashProvided !==
      report.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_preserved ||
    (report.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_preserved === true &&
      report.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256 !==
        report.counts.installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256)
  ) {
    throw new Error('North Star installed runtime profile terminal chain refusal taxonomy hash boundary drifted');
  }
  if (report.counts.runtime_refusal_taxonomy_preserved !== true) {
    throw new Error('North Star runtime refusal taxonomy must be preserved');
  }
  if (typeof report.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_required !== 'boolean') {
    throw new Error('North Star installed runtime profile terminal chain named receipt refusals required flag drifted');
  }
  if (
    requiresTerminalChainNamedReceiptRefusals &&
    report.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_required !== true
  ) {
    throw new Error('North Star readiness must require installed runtime profile terminal chain named receipt refusals');
  }
  const terminalChainNamedReceiptRefusalsHashProvided = isSha256Hex(
    report.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256
  );
  const terminalChainArtifactVerificationNamedReceiptRefusalsHashProvided = isSha256Hex(
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256
  );
  if (
    report.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_required === true &&
    report.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved !== true
  ) {
    throw new Error('North Star installed runtime profile terminal chain named receipt refusals drifted');
  }
  if (
    terminalChainNamedReceiptRefusalsHashProvided !==
      report.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved ||
    terminalChainArtifactVerificationNamedReceiptRefusalsHashProvided !==
      report.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved ||
    (report.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved === true &&
      report.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256 !==
        report.counts.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256)
  ) {
    throw new Error('North Star installed runtime profile terminal chain named receipt refusals hash boundary drifted');
  }
  if (typeof report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_required !== 'boolean') {
    throw new Error('North Star installed runtime profile terminal chain recognition refusal groups required flag drifted');
  }
  if (
    requiresTerminalChainRecognitionRefusalGroups &&
    report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_required !== true
  ) {
    throw new Error('North Star readiness must require installed runtime profile terminal chain recognition refusal groups');
  }
  const terminalChainRecognitionRefusalGroupsHashProvided = isSha256Hex(
    report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256
  );
  const terminalChainArtifactVerificationRecognitionRefusalGroupsHashProvided = isSha256Hex(
    report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256
  );
  if (
    report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_required === true &&
    report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved !== true
  ) {
    throw new Error('North Star installed runtime profile terminal chain recognition refusal groups drifted');
  }
  if (
    terminalChainRecognitionRefusalGroupsHashProvided !==
      report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved ||
    terminalChainArtifactVerificationRecognitionRefusalGroupsHashProvided !==
      report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved ||
    (report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved === true &&
      report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256 !==
        report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256)
  ) {
    throw new Error('North Star installed runtime profile terminal chain recognition refusal groups hash boundary drifted');
  }
  if (typeof report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required !== 'boolean') {
    throw new Error('North Star installed runtime profile terminal chain recognition refusal group case IDs required flag drifted');
  }
  if (
    requiresTerminalChainRecognitionRefusalGroupCaseIds &&
    report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required !== true
  ) {
    throw new Error('North Star readiness must require installed runtime profile terminal chain recognition refusal group case IDs');
  }
  if (
    report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required === true &&
    report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved !== true
  ) {
    throw new Error('North Star installed runtime profile terminal chain recognition refusal group case IDs drifted');
  }
  if (
    report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved === true
  ) {
    const expectedGroupCount = Object.keys(
      REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS
    ).length;
    const expectedCaseCount = REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length;
    const expectedCaseIds = expectedRecognitionRefusalGroupCaseIds();
    if (
      report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_count !==
        expectedGroupCount ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count !==
        expectedGroupCount ||
      report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count !==
        expectedCaseCount ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count !==
        expectedCaseCount ||
      JSON.stringify(report.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids) !==
        JSON.stringify(expectedCaseIds) ||
      JSON.stringify(report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids) !==
        JSON.stringify(expectedCaseIds)
    ) {
      throw new Error('North Star installed runtime profile terminal chain recognition refusal group case IDs boundary drifted');
    }
  }
  if (typeof report.counts.installed_runtime_profile_terminal_chain_nested_artifact_binding_required !== 'boolean') {
    throw new Error('North Star installed runtime profile terminal chain nested artifact binding required flag drifted');
  }
  if (
    requiresTerminalChainNestedArtifactBinding &&
    report.counts.installed_runtime_profile_terminal_chain_nested_artifact_binding_required !== true
  ) {
    throw new Error('North Star readiness must require installed runtime profile terminal chain nested artifact binding');
  }
  if (
    report.counts.installed_runtime_profile_terminal_chain_nested_artifact_binding_required === true &&
    report.counts.installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved !== true
  ) {
    throw new Error('North Star installed runtime profile terminal chain nested artifact binding drifted');
  }
  if (
    report.counts.installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved === true
  ) {
    if (
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved !== true ||
      report.counts.installed_runtime_profile_terminal_chain_nested_preflight_artifact_type !==
        INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NESTED_PREFLIGHT_ARTIFACT_TYPE ||
      report.counts.installed_runtime_profile_terminal_chain_nested_service_proof_artifact_type !==
        INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NESTED_SERVICE_PROOF_ARTIFACT_TYPE ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_preflight_artifact_type !==
        INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NESTED_PREFLIGHT_ARTIFACT_TYPE ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_service_proof_artifact_type !==
        INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NESTED_SERVICE_PROOF_ARTIFACT_TYPE
    ) {
      throw new Error('North Star installed runtime profile terminal chain nested artifact binding boundary drifted');
    }
  }
  if (typeof report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_required !== 'boolean') {
    throw new Error('North Star installed runtime profile terminal chain trusted issuer registry binding required flag drifted');
  }
  if (
    requiresTerminalChainTrustedIssuerRegistryBinding &&
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_required !== true
  ) {
    throw new Error('North Star readiness must require installed runtime profile terminal chain trusted issuer registry binding');
  }
  const terminalChainTrustedIssuerRegistryBindingHashProvided = isSha256Hex(
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256
  );
  const terminalChainArtifactVerificationTrustedIssuerRegistryBindingHashProvided =
    isSha256Hex(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256
    );
  if (
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_required === true &&
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved !== true
  ) {
    throw new Error('North Star installed runtime profile terminal chain trusted issuer registry binding drifted');
  }
  if (
    terminalChainTrustedIssuerRegistryBindingHashProvided !==
      report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved ||
    terminalChainArtifactVerificationTrustedIssuerRegistryBindingHashProvided !==
      report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved
  ) {
    throw new Error('North Star installed runtime profile terminal chain trusted issuer registry binding hash boundary drifted');
  }
  if (
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved === true &&
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved !== true
  ) {
    throw new Error('North Star installed runtime profile terminal chain trusted issuer registry recognition refusals drifted');
  }
  if (
    report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved === true
  ) {
    const expectedCaseCount =
      REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS.length;
    const expectedCaseIds = expectedTrustedIssuerRegistryRecognitionRefusalCaseIds();
    const expectedReasonCodes = expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes();
    const terminalChainRefusalsHashProvided = isSha256Hex(
      report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256
    );
    const artifactVerificationRefusalsHashProvided = isSha256Hex(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256
    );
    if (
      report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count !==
        expectedCaseCount ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count !==
        expectedCaseCount ||
      report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused !==
        true ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused !==
        true ||
      JSON.stringify(report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids) !==
        JSON.stringify(expectedCaseIds) ||
      JSON.stringify(report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids) !==
        JSON.stringify(expectedCaseIds) ||
      JSON.stringify(report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes) !==
        JSON.stringify(expectedReasonCodes) ||
      JSON.stringify(report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes) !==
        JSON.stringify(expectedReasonCodes) ||
      terminalChainRefusalsHashProvided !== true ||
      artifactVerificationRefusalsHashProvided !== true ||
      report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256 !==
        report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256
    ) {
      throw new Error('North Star installed runtime profile terminal chain trusted issuer registry recognition refusals boundary drifted');
    }
  }
  const hasTerminalChainRecognizedReceiptPathMirrorCounts =
    hasAnyOwnKey(
      report.counts,
      TERMINAL_CHAIN_RECOGNIZED_RECEIPT_PATH_MIRROR_COUNT_KEYS,
    );
  if (
    requiresTerminalChainRecognizedReceiptPathMirror ||
    hasTerminalChainRecognizedReceiptPathMirrorCounts
  ) {
    if (typeof report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_mirror_required !== 'boolean') {
      throw new Error('North Star installed runtime profile terminal chain recognized receipt path mirror required flag drifted');
    }
    if (
      requiresTerminalChainRecognizedReceiptPathMirror &&
      report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_mirror_required !== true
    ) {
      throw new Error('North Star readiness must require installed runtime profile terminal chain recognized receipt path mirror');
    }
    if (
      report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_mirror_required === true &&
      report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_mirror_preserved !== true
    ) {
      throw new Error('North Star installed runtime profile terminal chain recognized receipt path mirror drifted');
    }
    const receiptPathShaProvided = isSha256Hex(
      report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256
    );
    const artifactReceiptPathShaProvided = isSha256Hex(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_sha256
    );
    const receiptPathSourceBindingShaProvided = isSha256Hex(
      report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256
    );
    const artifactReceiptPathSourceBindingShaProvided = isSha256Hex(
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_sha256
    );
    if (
      receiptPathShaProvided !== true ||
      artifactReceiptPathShaProvided !== true ||
      report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_bound_to_artifact_body !==
        true ||
      receiptPathSourceBindingShaProvided !== true ||
      artifactReceiptPathSourceBindingShaProvided !== true ||
      report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256 !==
        report.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256 ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_sha256 !==
        report.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256 ||
      report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_matches_trusted_registry_binding !==
        true ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_matches_trusted_registry_binding !==
        true ||
      report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_verdict !==
        'RECOGNIZED' ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_verdict !==
        'RECOGNIZED' ||
      report.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_recognized !==
        true ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_recognized !==
        true
    ) {
      throw new Error('North Star installed runtime profile terminal chain recognized receipt path mirror boundary drifted');
    }
    const recognizedReceiptPathFalseBoundaryCountKeys =
      TERMINAL_CHAIN_RECOGNIZED_RECEIPT_PATH_MIRROR_COUNT_KEYS.filter(
        (key) =>
          key.endsWith('_included') ||
          key.endsWith('_reproducible') ||
          key.endsWith('_proven') ||
          key.endsWith('_attestation') ||
          key.endsWith('_recognition'),
      ).filter((key) => !key.endsWith('_trusted_registry_binding'));
    if (
      recognizedReceiptPathFalseBoundaryCountKeys
        .some((key) => report.counts[key] !== false)
    ) {
      throw new Error('North Star installed runtime profile terminal chain recognized receipt path false boundary drifted');
    }
  }
  const hasTerminalChainDeploymentProfileAuthorityMirrorCounts =
    hasAnyOwnKey(report.counts, [
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required',
      'installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved',
    ]);
  if (
    requiresTerminalChainDeploymentProfileAuthorityRefusalMirror ||
    hasTerminalChainDeploymentProfileAuthorityMirrorCounts
  ) {
    if (typeof report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required !== 'boolean') {
      throw new Error('North Star installed runtime profile terminal chain deployment-profile authority refusal mirror required flag drifted');
    }
    if (
      requiresTerminalChainDeploymentProfileAuthorityRefusalMirror &&
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required !== true
    ) {
      throw new Error('North Star readiness must require installed runtime profile terminal chain deployment-profile authority refusal mirror');
    }
    if (
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required === true &&
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved !== true
    ) {
      throw new Error('North Star installed runtime profile terminal chain deployment-profile authority refusal mirror drifted');
    }
    const expectedCaseCount =
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length;
    if (
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count !==
        expectedCaseCount ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count !==
        expectedCaseCount ||
      JSON.stringify(report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids) !==
        JSON.stringify(REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES) ||
      JSON.stringify(report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids) !==
        JSON.stringify(REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES) ||
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof !==
        true ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof !==
        true ||
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation !==
        true ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation !==
        true ||
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started !==
        false ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started !==
        false ||
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance !==
        false ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_current_machine_governance !==
        false ||
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition !==
        false ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_downstream_recognition !==
        false ||
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority !==
        false ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_authority !==
        false ||
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness !==
        false ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_enterprise_readiness !==
        false ||
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation !==
        false ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_external_attestation !==
        false ||
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition !==
        false ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_sovereign_recognition !==
        false ||
      report.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage !==
        false ||
      report.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_unrouted_surface_coverage !==
        false
    ) {
      throw new Error('North Star installed runtime profile terminal chain deployment-profile authority refusal mirror boundary drifted');
    }
  }
  if (!Array.isArray(report.puzzle_pieces) || report.puzzle_pieces.length !== 7) {
    throw new Error('North Star puzzle-piece list drifted');
  }
  const productProof = report.puzzle_pieces.find((piece) => piece.id === 1);
  const productProofPath = productProof?.observed?.product_proof_path;
  if (!isObject(productProofPath)) {
    throw new Error('North Star Product Proof Path summary must be reported');
  }
  exactKeys('North Star Product Proof Path summary', productProofPath, [
    'acceptance_gate_passed',
    'claim_boundary',
    'command',
    'deployment_profile_authority_bridge',
    'deployment_profile_authority_bridge_observed',
    'downstream_refusal_boundary',
    'evidence_model',
    'forbidden_claims_false',
    'governed_action_allowed',
    'governed_action_refused',
    'live_probing',
    'non_coverage_visible',
    'private_operator_state_required',
    'proof_pack_claude_hook_contract_replay',
    'proof_pack_sha256',
    'proof_pack_runtime_profile_identity_policy',
    'proof_pack_verified',
    'provided',
    'receipt_verification_observed',
    'report_type',
    'result',
    'simulated_human_authorization_observed',
    'terminal_chain_artifact_verified',
    'terminal_chain_boundary',
    'terminal_chain_boundary_observed',
    'trusted_issuer_registry_recognition',
    'trusted_issuer_registry_recognition_observed',
  ]);
  assertRuntimeProfileIdentityPolicySummary(
    'North Star Product Proof Path proof-pack runtime-profile identity policy summary',
    productProofPath.proof_pack_runtime_profile_identity_policy,
    productProofPath.provided === true
  );
  exactKeys(
    'North Star Product Proof Path proof-pack Claude hook replay summary',
    productProofPath.proof_pack_claude_hook_contract_replay,
    PRODUCT_PROOF_PATH_CLAUDE_HOOK_CONTRACT_REPLAY_SUMMARY_KEYS,
  );
  if (productProofPath.provided === true) {
    if (
      !productProofPathClaudeHookReplaySummaryPasses(
        productProofPath.proof_pack_claude_hook_contract_replay
      )
    ) {
      throw new Error('North Star Product Proof Path proof-pack Claude hook replay summary drifted');
    }
    exactKeys(
      'North Star Product Proof Path trusted issuer registry recognition summary',
      productProofPath.trusted_issuer_registry_recognition,
      [
        'claim_boundary',
        'issuer_status',
        'live_probing',
        'malformed_registry_fail_closed_before_verdict',
        'non_claims',
        'provided',
        'proves_current_machine_governance',
        'proves_key_custody',
        'proves_live_issuer_status',
        'proves_live_registry',
        'proves_production_authority',
        'proves_production_downstream_recognition',
        'proves_production_trust_registry',
        'proves_public_external_attestation',
        'proves_real_non_operator_review',
        'proves_revocation_truth',
        'proves_sovereign_recognition',
        'recognized',
        'registry_contract_evidence',
        'registry_evaluation_result_type',
        'registry_evidence_model',
        'registry_fixture_evaluated',
        'registry_fixture_validated',
        'registry_public_safe_summary_sha256',
        'registry_to_recognition_rule_evaluated',
        'registry_trusted_issuer_count',
        'registry_type',
        'required_audit_event_id_bound',
        'required_detail_hash_bound',
        'signature_valid',
        'verdict',
      ],
    );
    exactKeys(
      'North Star Product Proof Path downstream refusal boundary summary',
      productProofPath.downstream_refusal_boundary,
      DOWNSTREAM_REFUSAL_BOUNDARY_SUMMARY_KEYS,
    );
    exactKeys(
      'North Star Product Proof Path terminal chain boundary summary',
      productProofPath.terminal_chain_boundary,
      [
        'all_required_refusals_before_mutation',
        'artifact_type',
        'body_sha256',
        'claim_boundary',
        'creates_public_external_attestation',
        'cryptographic_evidence_reproducible_from_artifact',
        'current_machine_governance_proven',
        'evidence_model',
        'external_attestation',
        'generated_installed_root_preflighted',
        'generated_preflight_artifact_consumed_by_service_proof',
        'generated_service_proof_artifact_verified',
        'hook_configuration_written',
        'invalid_receipt_refused_before_mutation',
        'known_open_boundaries',
        'live_probing',
        'machine_configuration_written',
        'missing_receipt_refused_before_mutation',
        'named_receipt_refusals',
        'named_receipt_refusals_sha256',
        'nested_artifact_binding_preserved',
        'observed_refusal_case_count',
        'payload_type',
        'persistent_runtime_profile_installed',
        'production_downstream_recognition',
        'production_records_service_checked',
        'provided',
        'proves_current_machine_governance',
        'proves_production_downstream_recognition',
        'receipt_envelope_included',
        'recognition_contract_hash_bound',
        'recognition_contract_sha256',
        'recognition_refusal_group_case_count',
        'recognition_refusal_group_case_ids',
        'recognition_refusal_group_case_ids_preserved',
        'recognition_refusal_group_count',
        'recognition_refusal_groups_sha256',
        'recognized_write_boarded',
        ...(
          requiresTerminalChainRecognizedReceiptPathMirror ||
          hasAnyOwnKey(
            productProofPath.terminal_chain_boundary,
            PRODUCT_PROOF_PATH_RECOGNIZED_RECEIPT_PATH_MIRROR_KEYS,
          )
            ? PRODUCT_PROOF_PATH_RECOGNIZED_RECEIPT_PATH_MIRROR_KEYS
            : []
        ),
        'refusal_taxonomy_sha256',
        'registry_public_key_material_included',
        'registry_receipt_contract_hash_bound',
        'required_refusal_case_count',
        'runtime_profile_activation_performed',
        'selected_profile_hash_bound',
        'sovereign_recognition',
        'terminal_chain_decision_bound',
        'trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification',
        'trusted_issuer_registry_recognition_binding_sha256',
        'trusted_issuer_registry_recognition_decision',
        'trusted_issuer_registry_recognition_issuer_status',
        'trusted_issuer_registry_recognition_reason_code',
        'trusted_issuer_registry_recognition_registry_contract_evidence',
        'trusted_issuer_registry_recognition_receipt_payload_contract_sha256',
        'trusted_issuer_registry_recognition_refusal_case_count',
        'trusted_issuer_registry_recognition_refusal_case_ids',
        'trusted_issuer_registry_recognition_refusal_hash_matches_binding',
        'trusted_issuer_registry_recognition_refusal_reason_codes',
        'trusted_issuer_registry_recognition_refusals_all_refused',
        'trusted_issuer_registry_recognition_refusals_sha256',
        'trusted_issuer_registry_recognition_recognized',
        'trusted_issuer_registry_recognition_registry_evaluation_result_type',
        'trusted_issuer_registry_recognition_registry_fixture_contract_sha256',
        'trusted_issuer_registry_recognition_registry_fixture_evaluated',
        'trusted_issuer_registry_recognition_registry_fixture_validated',
        'trusted_issuer_registry_recognition_registry_public_safe_summary_sha256',
        'trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated',
        'trusted_issuer_registry_recognition_registry_trusted_issuer_count',
        'trusted_issuer_registry_recognition_required_audit_event_id_bound',
        'trusted_issuer_registry_recognition_required_detail_hash_bound',
        'trusted_issuer_registry_recognition_signature_valid',
        'trusted_issuer_registry_recognition_verdict',
        'unrouted_records_paths_checked',
        'user_configuration_written',
        'verified',
      ],
    );
    const deploymentProfileAuthorityBridgeSummaryKeys = [
      'agent_supplied_authority_refused_before_mutation',
      'all_required_refusals_before_mutation',
      'claim_boundary',
      'current_machine_governance',
      'deployment_profile_artifact_authoritative',
      'deployment_profile_id',
      'deployment_profile_sha256',
      'direct_api_refused_before_mutation',
      'downstream_refusal_proven',
      'enterprise_readiness',
      'evidence_model',
      'external_attestation',
      'live_probing',
      'observed_refusal_case_count',
      'preflight_artifact_verified',
      'production_authority',
      'production_downstream_recognition',
      'proof_type',
      'provided',
      'recognized_receipt_mutates_once',
      'recognized_state_entry_count_delta',
      'request_stream_authority_material_accepted',
      'required_refusal_case_count',
      'runtime_profile_sha256',
      'selected_by_explicit_id_and_sha',
      'selects_latest_profile',
      'sovereign_recognition',
      'unrouted_surface_coverage',
    ];
    if (
      requiresProductProofPathDeploymentProfileAuthorityRefusals ||
      hasAnyOwnKey(
        productProofPath.deployment_profile_authority_bridge,
        PRODUCT_PROOF_PATH_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_SUMMARY_KEYS,
      )
    ) {
      deploymentProfileAuthorityBridgeSummaryKeys.push(
        ...PRODUCT_PROOF_PATH_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_SUMMARY_KEYS,
      );
    }
    exactKeys(
      'North Star Product Proof Path deployment-profile authority bridge summary',
      productProofPath.deployment_profile_authority_bridge,
      deploymentProfileAuthorityBridgeSummaryKeys,
    );
    if (
      productProofPath.report_type !== PRODUCT_PROOF_PATH_REPORT_TYPE ||
      productProofPath.result !== 'PASS' ||
      productProofPath.evidence_model !== PRODUCT_PROOF_PATH_EVIDENCE_MODEL ||
      productProofPath.command !== 'zlar product-proof-path' ||
      productProofPath.proof_pack_verified !== true ||
      !/^[0-9a-f]{64}$/.test(productProofPath.proof_pack_sha256) ||
      !runtimeProfileIdentityPolicySummaryPasses(
        productProofPath.proof_pack_runtime_profile_identity_policy
      ) ||
      !productProofPathClaudeHookReplaySummaryPasses(
        productProofPath.proof_pack_claude_hook_contract_replay
      ) ||
      productProofPath.acceptance_gate_passed !== true ||
      productProofPath.governed_action_allowed !== true ||
      productProofPath.governed_action_refused !== true ||
      productProofPath.simulated_human_authorization_observed !== true ||
      productProofPath.receipt_verification_observed !== true ||
      productProofPath.trusted_issuer_registry_recognition_observed !== true ||
      productProofPath.terminal_chain_boundary_observed !== true ||
      productProofPath.terminal_chain_artifact_verified !== true ||
      productProofPath.deployment_profile_authority_bridge_observed !== true ||
      !productProofPathDeploymentProfileAuthorityBridgePasses(
        productProofPath.deployment_profile_authority_bridge
      ) ||
      !productProofPathDownstreamRefusalBoundaryPasses(
        productProofPath.downstream_refusal_boundary
      ) ||
      productProofPath.non_coverage_visible !== true ||
      productProofPath.forbidden_claims_false !== true ||
      productProofPath.live_probing !== false ||
      productProofPath.private_operator_state_required !== false ||
      productProofPath.trusted_issuer_registry_recognition.provided !== true ||
      productProofPath.trusted_issuer_registry_recognition.registry_type !==
        'trusted-receipt-issuers-v2' ||
      productProofPath.trusted_issuer_registry_recognition.registry_evidence_model !==
        'bundled-local-fixture-no-secret-registry-contract' ||
      productProofPath.trusted_issuer_registry_recognition.registry_contract_evidence !==
        'no-secret-registry-contract-v2' ||
      !isSha256Hex(
        productProofPath.trusted_issuer_registry_recognition
          .registry_public_safe_summary_sha256
      ) ||
      productProofPath.trusted_issuer_registry_recognition.live_probing !== false ||
      productProofPath.trusted_issuer_registry_recognition
        .registry_fixture_validated !== true ||
      productProofPath.trusted_issuer_registry_recognition
        .registry_fixture_evaluated !== true ||
      productProofPath.trusted_issuer_registry_recognition
        .registry_to_recognition_rule_evaluated !== true ||
      productProofPath.trusted_issuer_registry_recognition
        .registry_evaluation_result_type !== 'downstream-recognition-rule-v1' ||
      productProofPath.trusted_issuer_registry_recognition
        .registry_trusted_issuer_count !== 1 ||
      productProofPath.trusted_issuer_registry_recognition.verdict !== 'RECOGNIZED' ||
      productProofPath.trusted_issuer_registry_recognition.recognized !== true ||
      productProofPath.trusted_issuer_registry_recognition.issuer_status !== 'active' ||
      productProofPath.trusted_issuer_registry_recognition.signature_valid !== true ||
      productProofPath.trusted_issuer_registry_recognition
        .required_audit_event_id_bound !== true ||
      productProofPath.trusted_issuer_registry_recognition
        .required_detail_hash_bound !== true ||
      productProofPath.trusted_issuer_registry_recognition
        .malformed_registry_fail_closed_before_verdict !== true ||
      productProofPath.trusted_issuer_registry_recognition.proves_live_registry !==
        false ||
      productProofPath.trusted_issuer_registry_recognition.proves_live_issuer_status !==
        false ||
      productProofPath.trusted_issuer_registry_recognition.proves_key_custody !==
        false ||
      productProofPath.trusted_issuer_registry_recognition
        .proves_current_machine_governance !== false ||
      productProofPath.trusted_issuer_registry_recognition.proves_revocation_truth !==
        false ||
      productProofPath.trusted_issuer_registry_recognition
        .proves_production_trust_registry !== false ||
      productProofPath.trusted_issuer_registry_recognition
        .proves_production_downstream_recognition !== false ||
      productProofPath.trusted_issuer_registry_recognition
        .proves_production_authority !== false ||
      productProofPath.trusted_issuer_registry_recognition
        .proves_sovereign_recognition !== false ||
      productProofPath.trusted_issuer_registry_recognition
        .proves_public_external_attestation !== false ||
      productProofPath.trusted_issuer_registry_recognition
        .proves_real_non_operator_review !== false ||
      !Array.isArray(productProofPath.trusted_issuer_registry_recognition.non_claims) ||
      productProofPath.trusted_issuer_registry_recognition.non_claims.length === 0 ||
      productProofPath.terminal_chain_boundary.provided !== true ||
      productProofPath.terminal_chain_boundary.verified !== true ||
      productProofPath.terminal_chain_boundary.artifact_type !==
        'zlar-protected-records-installed-runtime-profile-terminal-chain-artifact-v1' ||
      productProofPath.terminal_chain_boundary.payload_type !==
        'zlar-protected-records-installed-runtime-profile-terminal-chain-v1' ||
      productProofPath.terminal_chain_boundary.evidence_model !==
        'fresh-local-disposable-installed-runtime-profile-terminal-chain' ||
      productProofPath.terminal_chain_boundary.live_probing !== false ||
      !isSha256Hex(productProofPath.terminal_chain_boundary.body_sha256) ||
      !isSha256Hex(productProofPath.terminal_chain_boundary.recognition_contract_sha256) ||
      !isSha256Hex(productProofPath.terminal_chain_boundary.refusal_taxonomy_sha256) ||
      !terminalChainNamedReceiptRefusalsSummaryPasses(
        productProofPath.terminal_chain_boundary.named_receipt_refusals,
      ) ||
      !isSha256Hex(productProofPath.terminal_chain_boundary.named_receipt_refusals_sha256) ||
      productProofPath.terminal_chain_boundary.named_receipt_refusals_sha256 !==
        terminalChainNamedReceiptRefusalsSha256(
          productProofPath.terminal_chain_boundary.named_receipt_refusals,
        ) ||
      !isSha256Hex(productProofPath.terminal_chain_boundary.recognition_refusal_groups_sha256) ||
      productProofPath.terminal_chain_boundary.recognition_refusal_group_count !==
        Object.keys(expectedRecognitionRefusalGroupCaseIds()).length ||
      productProofPath.terminal_chain_boundary.recognition_refusal_group_case_count !==
        18 ||
      JSON.stringify(
        productProofPath.terminal_chain_boundary.recognition_refusal_group_case_ids,
      ) !== JSON.stringify(expectedRecognitionRefusalGroupCaseIds()) ||
      productProofPath.terminal_chain_boundary
        .recognition_refusal_group_case_ids_preserved !== true ||
      !isSha256Hex(
        productProofPath.terminal_chain_boundary
          .trusted_issuer_registry_recognition_binding_sha256,
      ) ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification !==
        true ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_verdict !== 'RECOGNIZED' ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_recognized !== true ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_decision !== 'accept' ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_reason_code !== 'recognized' ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_issuer_status !== 'active' ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_signature_valid !== true ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_registry_fixture_validated !== true ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_registry_fixture_evaluated !== true ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated !==
        true ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_registry_evaluation_result_type !==
        'downstream-recognition-rule-v1' ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_registry_trusted_issuer_count !== 1 ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_required_audit_event_id_bound !==
        true ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_required_detail_hash_bound !== true ||
      !isSha256Hex(
        productProofPath.terminal_chain_boundary
          .trusted_issuer_registry_recognition_registry_fixture_contract_sha256,
      ) ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_registry_contract_evidence !==
        'no-secret-registry-contract-v2' ||
      !isSha256Hex(
        productProofPath.terminal_chain_boundary
          .trusted_issuer_registry_recognition_registry_public_safe_summary_sha256,
      ) ||
      !isSha256Hex(
        productProofPath.terminal_chain_boundary
          .trusted_issuer_registry_recognition_receipt_payload_contract_sha256,
      ) ||
      !isSha256Hex(
        productProofPath.terminal_chain_boundary
          .trusted_issuer_registry_recognition_refusals_sha256,
      ) ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_refusal_hash_matches_binding !== true ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_refusal_case_count !==
        expectedTrustedIssuerRegistryRecognitionRefusalCaseIds().length ||
      JSON.stringify(
        productProofPath.terminal_chain_boundary
          .trusted_issuer_registry_recognition_refusal_case_ids,
      ) !==
        JSON.stringify(expectedTrustedIssuerRegistryRecognitionRefusalCaseIds()) ||
      JSON.stringify(
        productProofPath.terminal_chain_boundary
          .trusted_issuer_registry_recognition_refusal_reason_codes,
      ) !==
        JSON.stringify(expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes()) ||
      productProofPath.terminal_chain_boundary
        .trusted_issuer_registry_recognition_refusals_all_refused !== true ||
      !productProofPathRecognizedReceiptPathMirrorPasses(
        productProofPath.terminal_chain_boundary,
        requiresTerminalChainRecognizedReceiptPathMirror,
      ) ||
      productProofPath.terminal_chain_boundary.generated_installed_root_preflighted !== true ||
      productProofPath.terminal_chain_boundary
        .generated_preflight_artifact_consumed_by_service_proof !== true ||
      productProofPath.terminal_chain_boundary
        .generated_service_proof_artifact_verified !== true ||
      productProofPath.terminal_chain_boundary.recognized_write_boarded !== true ||
      productProofPath.terminal_chain_boundary
        .missing_receipt_refused_before_mutation !== true ||
      productProofPath.terminal_chain_boundary
        .invalid_receipt_refused_before_mutation !== true ||
      productProofPath.terminal_chain_boundary
        .all_required_refusals_before_mutation !== true ||
      productProofPath.terminal_chain_boundary.required_refusal_case_count !== 18 ||
      productProofPath.terminal_chain_boundary.observed_refusal_case_count !== 18 ||
      productProofPath.terminal_chain_boundary.registry_receipt_contract_hash_bound !== true ||
      productProofPath.terminal_chain_boundary.selected_profile_hash_bound !== true ||
      productProofPath.terminal_chain_boundary.recognition_contract_hash_bound !== true ||
      productProofPath.terminal_chain_boundary.terminal_chain_decision_bound !== true ||
      productProofPath.terminal_chain_boundary.nested_artifact_binding_preserved !== true ||
      productProofPath.terminal_chain_boundary.registry_public_key_material_included !== false ||
      productProofPath.terminal_chain_boundary.receipt_envelope_included !== false ||
      productProofPath.terminal_chain_boundary
        .cryptographic_evidence_reproducible_from_artifact !== false ||
      productProofPath.terminal_chain_boundary.creates_public_external_attestation !== false ||
      productProofPath.terminal_chain_boundary.proves_current_machine_governance !== false ||
      productProofPath.terminal_chain_boundary
        .proves_production_downstream_recognition !== false ||
      productProofPath.terminal_chain_boundary.persistent_runtime_profile_installed !== false ||
      productProofPath.terminal_chain_boundary.runtime_profile_activation_performed !== false ||
      productProofPath.terminal_chain_boundary.hook_configuration_written !== false ||
      productProofPath.terminal_chain_boundary.user_configuration_written !== false ||
      productProofPath.terminal_chain_boundary.machine_configuration_written !== false ||
      productProofPath.terminal_chain_boundary.current_machine_governance_proven !== false ||
      productProofPath.terminal_chain_boundary.production_records_service_checked !== false ||
      productProofPath.terminal_chain_boundary.production_downstream_recognition !== false ||
      productProofPath.terminal_chain_boundary.external_attestation !== false ||
      productProofPath.terminal_chain_boundary.sovereign_recognition !== false ||
      productProofPath.terminal_chain_boundary.unrouted_records_paths_checked !== false ||
      JSON.stringify(productProofPath.terminal_chain_boundary.known_open_boundaries) !==
        JSON.stringify(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_OPEN_BOUNDARIES)
    ) {
      throw new Error('North Star Product Proof Path summary drifted');
    }
  } else if (
    productProofPath.acceptance_gate_passed !== false ||
    productProofPath.forbidden_claims_false !== false ||
    productProofPath.trusted_issuer_registry_recognition_observed !== false ||
    productProofPath.trusted_issuer_registry_recognition.provided !== false ||
    productProofPath.terminal_chain_boundary_observed !== false ||
    productProofPath.terminal_chain_artifact_verified !== false ||
    productProofPath.terminal_chain_boundary.provided !== false ||
    productProofPath.deployment_profile_authority_bridge_observed !== false ||
    productProofPath.deployment_profile_authority_bridge.provided !== false ||
    productProofPath.downstream_refusal_boundary.provided !== false ||
    productProofPath.proof_pack_claude_hook_contract_replay.provided !== false ||
    productProofPath.live_probing !== false ||
    productProofPath.private_operator_state_required !== false
  ) {
    throw new Error('North Star absent Product Proof Path summary cannot verify product proof');
  }
  const productProofPathVerified =
    productProofPath.provided === true &&
    productProofPath.report_type === PRODUCT_PROOF_PATH_REPORT_TYPE &&
    productProofPath.result === 'PASS' &&
    productProofPath.acceptance_gate_passed === true &&
    productProofPath.proof_pack_verified === true &&
    runtimeProfileIdentityPolicySummaryPasses(
      productProofPath.proof_pack_runtime_profile_identity_policy
    ) &&
    productProofPathClaudeHookReplaySummaryPasses(
      productProofPath.proof_pack_claude_hook_contract_replay
    ) &&
    productProofPath.governed_action_allowed === true &&
    productProofPath.governed_action_refused === true &&
    productProofPath.simulated_human_authorization_observed === true &&
    productProofPath.receipt_verification_observed === true &&
    productProofPath.terminal_chain_boundary_observed === true &&
    productProofPath.terminal_chain_artifact_verified === true &&
    productProofPath.deployment_profile_authority_bridge_observed === true &&
    productProofPathDeploymentProfileAuthorityBridgePasses(
      productProofPath.deployment_profile_authority_bridge
    ) &&
    productProofPathDownstreamRefusalBoundaryPasses(
      productProofPath.downstream_refusal_boundary
    ) &&
    (
      !requiresProductProofPathDeploymentProfileAuthorityRefusals ||
      productProofPathDeploymentProfileAuthorityRefusalsPasses(
        productProofPath.deployment_profile_authority_bridge
      )
    ) &&
    productProofPath.terminal_chain_boundary.provided === true &&
    productProofPath.terminal_chain_boundary.verified === true &&
    productProofPath.terminal_chain_boundary
      .trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification ===
      true &&
    productProofPath.terminal_chain_boundary
      .trusted_issuer_registry_recognition_verdict === 'RECOGNIZED' &&
    productProofPath.terminal_chain_boundary
      .trusted_issuer_registry_recognition_recognized === true &&
    productProofPath.terminal_chain_boundary
      .trusted_issuer_registry_recognition_signature_valid === true &&
    productProofPath.terminal_chain_boundary
      .trusted_issuer_registry_recognition_registry_fixture_validated === true &&
    productProofPath.terminal_chain_boundary
      .trusted_issuer_registry_recognition_registry_fixture_evaluated === true &&
    productProofPath.terminal_chain_boundary
      .trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated ===
      true &&
    productProofPath.terminal_chain_boundary
      .trusted_issuer_registry_recognition_registry_evaluation_result_type ===
      'downstream-recognition-rule-v1' &&
    productProofPath.terminal_chain_boundary
      .trusted_issuer_registry_recognition_required_audit_event_id_bound === true &&
    productProofPath.terminal_chain_boundary
      .trusted_issuer_registry_recognition_required_detail_hash_bound === true &&
    productProofPath.terminal_chain_boundary
      .trusted_issuer_registry_recognition_refusal_hash_matches_binding === true &&
    terminalChainNamedReceiptRefusalsSummaryPasses(
      productProofPath.terminal_chain_boundary.named_receipt_refusals,
    ) &&
    productProofPath.terminal_chain_boundary.named_receipt_refusals_sha256 ===
      terminalChainNamedReceiptRefusalsSha256(
        productProofPath.terminal_chain_boundary.named_receipt_refusals,
      ) &&
    productProofPath.terminal_chain_boundary.recognition_refusal_group_count ===
      Object.keys(expectedRecognitionRefusalGroupCaseIds()).length &&
    productProofPath.terminal_chain_boundary.recognition_refusal_group_case_count ===
      18 &&
    JSON.stringify(productProofPath.terminal_chain_boundary.recognition_refusal_group_case_ids) ===
      JSON.stringify(expectedRecognitionRefusalGroupCaseIds()) &&
    productProofPath.terminal_chain_boundary
      .recognition_refusal_group_case_ids_preserved === true &&
    productProofPath.terminal_chain_boundary
      .trusted_issuer_registry_recognition_refusals_all_refused === true &&
    productProofPath.terminal_chain_boundary.registry_public_key_material_included === false &&
    productProofPath.terminal_chain_boundary.external_attestation === false &&
    productProofPath.terminal_chain_boundary.current_machine_governance_proven === false &&
    productProofPath.non_coverage_visible === true &&
    productProofPath.forbidden_claims_false === true &&
    productProofPath.live_probing === false &&
    productProofPath.private_operator_state_required === false;
  if (report.counts.product_proof_path_verified !== productProofPathVerified) {
    throw new Error('North Star Product Proof Path verification count drifted');
  }
  if (typeof report.counts.product_proof_path_deployment_profile_authority_bridge_required !== 'boolean') {
    throw new Error('North Star Product Proof Path deployment-profile authority bridge required flag drifted');
  }
  if (
    requiresProductProofPathDeploymentProfileAuthorityBridge &&
    report.counts.product_proof_path_deployment_profile_authority_bridge_required !== true
  ) {
    throw new Error('North Star readiness must require Product Proof Path deployment-profile authority bridge');
  }
  const productProofPathDeploymentProfileAuthorityBridgePreserved =
    productProofPath.deployment_profile_authority_bridge_observed === true &&
    productProofPathDeploymentProfileAuthorityBridgePasses(
      productProofPath.deployment_profile_authority_bridge
    );
  if (
    report.counts.product_proof_path_deployment_profile_authority_bridge_required === true &&
    report.counts.product_proof_path_deployment_profile_authority_bridge_preserved !== true
  ) {
    throw new Error('North Star Product Proof Path deployment-profile authority bridge drifted');
  }
  if (
    report.counts.product_proof_path_deployment_profile_authority_bridge_preserved !==
    productProofPathDeploymentProfileAuthorityBridgePreserved
  ) {
    throw new Error('North Star Product Proof Path deployment-profile authority bridge count drifted');
  }
  const productProofPathDeploymentProfileAuthorityRefusalsPreserved =
    productProofPathDeploymentProfileAuthorityBridgePreserved === true &&
    productProofPathDeploymentProfileAuthorityRefusalsPasses(
      productProofPath.deployment_profile_authority_bridge
    );
  const hasProductProofPathDeploymentProfileAuthorityRefusalCounts =
    hasAnyOwnKey(report.counts, [
      'product_proof_path_deployment_profile_authority_refusals_required',
      'product_proof_path_deployment_profile_authority_refusals_preserved',
    ]);
  if (
    requiresProductProofPathDeploymentProfileAuthorityRefusals ||
    hasProductProofPathDeploymentProfileAuthorityRefusalCounts
  ) {
    if (typeof report.counts.product_proof_path_deployment_profile_authority_refusals_required !== 'boolean') {
      throw new Error('North Star Product Proof Path deployment-profile authority refusals required flag drifted');
    }
    if (
      requiresProductProofPathDeploymentProfileAuthorityRefusals &&
      report.counts.product_proof_path_deployment_profile_authority_refusals_required !== true
    ) {
      throw new Error('North Star readiness must require Product Proof Path deployment-profile authority refusals');
    }
    if (
      report.counts.product_proof_path_deployment_profile_authority_refusals_required === true &&
      report.counts.product_proof_path_deployment_profile_authority_refusals_preserved !== true
    ) {
      throw new Error('North Star Product Proof Path deployment-profile authority refusals drifted');
    }
    if (
      report.counts.product_proof_path_deployment_profile_authority_refusals_preserved !==
      productProofPathDeploymentProfileAuthorityRefusalsPreserved
    ) {
      throw new Error('North Star Product Proof Path deployment-profile authority refusals count drifted');
    }
  }
  const humanAuthorization = productProof?.observed?.human_authorization;
  if (!isObject(humanAuthorization)) {
    throw new Error('North Star human authorization summary must be reported');
  }
  exactKeys('North Star human authorization summary', humanAuthorization, [
    'approval_channel',
    'authorized_boarded',
    'claim_boundary',
    'denied_boarded',
    'evidence_model',
    'live_approval_channel_health',
    'live_probing',
    'pending_boarded',
    'provided',
    'simulated_human_authorization_verified',
    'verification_type',
  ]);
  if (
    productProof.observed.simulated_human_authorization_verified !==
    humanAuthorization.simulated_human_authorization_verified
  ) {
    throw new Error('North Star human authorization observed summary drifted');
  }
  if (humanAuthorization.provided === true) {
    if (
      humanAuthorization.verification_type !==
        'zlar-local-proof-pack-human-authorization-verification-summary-v1' ||
      humanAuthorization.evidence_model !== 'local-hermetic-fixture' ||
      humanAuthorization.approval_channel !== 'simulated-human-fixture' ||
      humanAuthorization.live_probing !== false ||
      humanAuthorization.pending_boarded !== false ||
      humanAuthorization.authorized_boarded !== true ||
      humanAuthorization.denied_boarded !== false ||
      humanAuthorization.simulated_human_authorization_verified !== true ||
      humanAuthorization.live_approval_channel_health !== false
    ) {
      throw new Error('North Star human authorization summary drifted');
    }
  } else if (humanAuthorization.simulated_human_authorization_verified !== false) {
    throw new Error('North Star absent human authorization summary cannot verify simulated human authorization');
  }
  const issuerForStatus = report.puzzle_pieces.find((piece) => piece.id === 4);
  const issuerCompletionForStatus =
    issuerForStatus?.observed?.trusted_receipt_issuer_completion_proof;
  const trustedIssuerExpectedStatus =
    issuerCompletionForStatus?.provided === true &&
    issuerCompletionForStatus?.verified === true &&
    issuerCompletionForStatus?.completed_for_selected_surface === true
      ? 'operator_owned_private_core_completion_proven'
      : 'portable_fixture_partial';
  const expectedStatuses = new Map([
    [1, 'bounded_local_fixture_proven'],
    [2, 'supplied_evidence_map_proven'],
    [3, 'local_disposable_profile_refusal_proven'],
    [4, trustedIssuerExpectedStatus],
    [5, 'local_fixture_proven'],
    [6, 'unproven'],
    [7, 'aligned_nonclaim_boundary'],
  ]);
  for (const piece of report.puzzle_pieces) {
    if (piece.status !== expectedStatuses.get(piece.id)) {
      throw new Error(`North Star puzzle piece ${piece.id} status drifted`);
    }
    if (!Array.isArray(piece.missing_for_enterprise) || piece.missing_for_enterprise.length === 0) {
      throw new Error(`North Star puzzle piece ${piece.id} must name missing enterprise evidence`);
    }
  }
  assertTerminalChainRecognitionRefusalGroupCaseIdsObservedSummary(
    'North Star Enterprise Deployment Profile observed summary',
    report.puzzle_pieces.find((piece) => piece.id === 3)?.observed,
    report.counts,
    requiresTerminalChainRecognitionRefusalGroupCaseIdObservedSummaries
  );
  assertTerminalChainNestedArtifactBindingObservedSummary(
    'North Star Enterprise Deployment Profile observed summary',
    report.puzzle_pieces.find((piece) => piece.id === 3)?.observed,
    report.counts,
    requiresTerminalChainNestedArtifactBinding
  );
  assertTerminalChainTrustedIssuerRegistryBindingObservedSummary(
    'North Star Enterprise Deployment Profile observed summary',
    report.puzzle_pieces.find((piece) => piece.id === 3)?.observed,
    report.counts,
    requiresTerminalChainTrustedIssuerRegistryBinding
  );
  assertTerminalChainRecognizedReceiptPathObservedSummary(
    'North Star Enterprise Deployment Profile observed summary',
    report.puzzle_pieces.find((piece) => piece.id === 3)?.observed,
    report.counts,
    requiresTerminalChainRecognizedReceiptPathMirror
  );
  assertTerminalChainRecognitionRefusalGroupCaseIdsObservedSummary(
    'North Star Downstream Recognition Rule observed summary',
    report.puzzle_pieces.find((piece) => piece.id === 5)?.observed,
    report.counts,
    requiresTerminalChainRecognitionRefusalGroupCaseIdObservedSummaries
  );
  assertTerminalChainNestedArtifactBindingObservedSummary(
    'North Star Downstream Recognition Rule observed summary',
    report.puzzle_pieces.find((piece) => piece.id === 5)?.observed,
    report.counts,
    requiresTerminalChainNestedArtifactBinding
  );
  assertTerminalChainTrustedIssuerRegistryBindingObservedSummary(
    'North Star Downstream Recognition Rule observed summary',
    report.puzzle_pieces.find((piece) => piece.id === 5)?.observed,
    report.counts,
    requiresTerminalChainTrustedIssuerRegistryBinding
  );
  assertTerminalChainRecognizedReceiptPathObservedSummary(
    'North Star Downstream Recognition Rule observed summary',
    report.puzzle_pieces.find((piece) => piece.id === 5)?.observed,
    report.counts,
    requiresTerminalChainRecognizedReceiptPathMirror
  );
  assertRuntimeProfileIdentityPolicySummary(
    'North Star Downstream Recognition Rule runtime-profile identity policy observed summary',
    report.puzzle_pieces.find((piece) => piece.id === 5)?.observed?.runtime_profile_identity_policy,
    productProofPath.provided === true
  );
  const externalAttestation = report.puzzle_pieces.find((piece) => piece.id === 6);
  if (externalAttestation?.observed?.public_external_attestation !== false) {
    throw new Error('North Star external attestation must remain unproven');
  }
  if (externalAttestation?.observed?.non_operator_review_proven !== false) {
    throw new Error('North Star public non-operator review must remain unproven');
  }
  const privateVerifierResult =
    externalAttestation?.observed?.private_verifier_result_verification;
  if (!isObject(privateVerifierResult)) {
    throw new Error('North Star private verifier result verification must be reported');
  }
  exactKeys('North Star private verifier result verification summary', privateVerifierResult, [
    'artifact_hash_count',
    'claim_boundary',
    'commit_sha',
    'completed_by_non_operator',
    'downstream_refusal_all_refusals_unboarded',
    'downstream_refusal_boundary_required',
    'downstream_refusal_reasons',
    'evidence_dir_contract_verification',
    'evidence_dir_contract_verification_required',
    'evidence_dir_hash_verification',
    'intake_class',
    'north_star_downstream_refusal_all_refusals_unboarded',
    'north_star_downstream_refusal_reasons',
    'non_operator_review_publicly_claimed',
    'private_by_default',
    'private_non_operator_pass_validated',
    'provided',
    'public_attribution',
    'public_external_attestation',
    'release_tag',
    'verdict',
    'verification_type',
    'verified',
  ]);
  if (
    externalAttestation.observed.private_non_operator_pass_validated !==
    privateVerifierResult.private_non_operator_pass_validated
  ) {
    throw new Error('North Star private verifier result validation summary drifted');
  }
  const privateVerifierZipResult =
    externalAttestation?.observed?.private_verifier_zip_result_verification;
  if (!isObject(privateVerifierZipResult)) {
    throw new Error('North Star private verifier ZIP result verification must be reported');
  }
  exactKeys('North Star private verifier ZIP result verification summary', privateVerifierZipResult, [
    'all_required_steps_exit_zero',
    'all_sha256sums_entries_matched',
    'arms_length_review',
    'claim_boundary',
    'commit_sha',
    'evidence_model',
    'independent_review',
    'north_star_result',
    'only_known_stderr_issue',
    'private_personally_connected_outside_machine_signal_validated',
    'proof_smoke_verified',
    'provided',
    'public_attribution',
    'public_external_attestation',
    'public_privacy_passed',
    'recomputed_evidence',
    'relationship_label',
    'source_route',
    'verification_type',
    'verified',
  ]);
  if (
    externalAttestation.observed.private_personally_connected_zip_result_validated !==
    privateVerifierZipResult
      .private_personally_connected_outside_machine_signal_validated
  ) {
    throw new Error('North Star private verifier ZIP result validation summary drifted');
  }
  if (
    privateVerifierResult.public_external_attestation !== false ||
    privateVerifierResult.public_attribution !== false ||
    privateVerifierResult.non_operator_review_publicly_claimed !== false
  ) {
    throw new Error('North Star private verifier result must not widen public claims');
  }
  if (
    privateVerifierZipResult.public_external_attestation !== false ||
    privateVerifierZipResult.independent_review !== false ||
    privateVerifierZipResult.arms_length_review !== false ||
    privateVerifierZipResult.public_attribution !== false
  ) {
    throw new Error('North Star private verifier ZIP result must not widen public claims');
  }
  const publicArtifactVerifierResult =
    externalAttestation?.observed?.public_artifact_verifier_result_verification;
  if (!isObject(publicArtifactVerifierResult)) {
    throw new Error('North Star public artifact verifier result verification must be reported');
  }
  exactKeys('North Star public artifact verifier result verification summary', publicArtifactVerifierResult, [
    'claim_boundary',
    'credentials_used',
    'deploy_key_used',
    'enterprise_readiness',
    'github_access_used',
    'non_operator_review_proven',
    'private_source_review',
    'production_authority',
    'provided',
    'public_artifact_hash_consistency_signal',
    'public_artifact_reachability_signal',
    'public_artifact_reply_signal_validated',
    'public_attribution',
    'public_external_attestation',
    'source_access_used',
    'target_version',
    'verification_type',
    'verified',
    'verifier_label',
  ]);
  if (
    externalAttestation.observed.public_artifact_verifier_result_validated !==
    publicArtifactVerifierResult.public_artifact_reply_signal_validated
  ) {
    throw new Error('North Star public artifact verifier result validation summary drifted');
  }
  if (
    publicArtifactVerifierResult.public_external_attestation !== false ||
    publicArtifactVerifierResult.public_attribution !== false ||
    publicArtifactVerifierResult.non_operator_review_proven !== false ||
    publicArtifactVerifierResult.private_source_review !== false ||
    publicArtifactVerifierResult.production_authority !== false ||
    publicArtifactVerifierResult.enterprise_readiness !== false
  ) {
    throw new Error('North Star public artifact verifier result must not widen claims');
  }
  if (publicArtifactVerifierResult.provided === true) {
    if (publicArtifactVerifierResult.verification_type !== PUBLIC_ARTIFACT_VERIFIER_RESULT_VERIFICATION_TYPE) {
      throw new Error('North Star public artifact verifier result verification type drifted');
    }
    if (publicArtifactVerifierResult.public_artifact_reply_signal_validated === true) {
      if (
        publicArtifactVerifierResult.verified !== true ||
        publicArtifactVerifierResult.target_version !== 'v3.4.59' ||
        publicArtifactVerifierResult.public_artifact_hash_consistency_signal !== true ||
        publicArtifactVerifierResult.public_artifact_reachability_signal !== true ||
        publicArtifactVerifierResult.source_access_used !== false ||
        publicArtifactVerifierResult.github_access_used !== false ||
        publicArtifactVerifierResult.credentials_used !== false ||
        publicArtifactVerifierResult.deploy_key_used !== false
      ) {
        throw new Error('North Star public artifact verifier result evidence incomplete');
      }
    }
  } else if (publicArtifactVerifierResult.public_artifact_reply_signal_validated !== false) {
    throw new Error('North Star absent public artifact verifier result cannot validate public artifact reply signal');
  }
  const publicExternalAttestationResult =
    externalAttestation?.observed?.public_external_attestation_result_verification;
  if (!isObject(publicExternalAttestationResult)) {
    throw new Error('North Star public external attestation result verification must be reported');
  }
  exactKeys('North Star public external attestation result verification summary', publicExternalAttestationResult, [
    'attestation_preserved_for_future_checking',
    'bounded_signed_attestation_evidence_verified',
    'claim_boundary',
    'commit_sha',
    'current_machine_governance',
    'enterprise_readiness',
    'key_custody',
    'non_operator_review_proven',
    'production_authority',
    'production_downstream_recognition',
    'provided',
    'public_attribution',
    'public_external_attestation',
    'release_tag',
    'result_sha256',
    'revocation_truth',
    'side_door_closure',
    'signature_verified',
    'signed_or_published_by_verifier',
    'sovereign_recognition',
    'verification_type',
    'verified',
    'verifier_label',
  ]);
  if (
    externalAttestation.observed.public_external_attestation_result_validated !==
    publicExternalAttestationResult.bounded_signed_attestation_evidence_verified
  ) {
    throw new Error('North Star public external attestation result validation summary drifted');
  }
  if (
    publicExternalAttestationResult.public_external_attestation !== false ||
    publicExternalAttestationResult.public_attribution !== false ||
    publicExternalAttestationResult.non_operator_review_proven !== false ||
    publicExternalAttestationResult.production_authority !== false ||
    publicExternalAttestationResult.enterprise_readiness !== false ||
    publicExternalAttestationResult.sovereign_recognition !== false ||
    publicExternalAttestationResult.current_machine_governance !== false ||
    publicExternalAttestationResult.key_custody !== false ||
    publicExternalAttestationResult.revocation_truth !== false ||
    publicExternalAttestationResult.production_downstream_recognition !== false ||
    publicExternalAttestationResult.side_door_closure !== false
  ) {
    throw new Error('North Star public external attestation result must remain intake-only and non-scoring');
  }
  if (publicExternalAttestationResult.provided === true) {
    if (
      publicExternalAttestationResult.verification_type !==
        PUBLIC_EXTERNAL_ATTESTATION_RESULT_VERIFICATION_TYPE
    ) {
      throw new Error('North Star public external attestation result verification type drifted');
    }
    if (publicExternalAttestationResult.bounded_signed_attestation_evidence_verified === true) {
      if (
        publicExternalAttestationResult.verified !== true ||
        publicExternalAttestationResult.signature_verified !== true ||
        publicExternalAttestationResult.signed_or_published_by_verifier !== true ||
        publicExternalAttestationResult.attestation_preserved_for_future_checking !== true ||
        !isSha256Hex(publicExternalAttestationResult.result_sha256) ||
        !/^v\d+\.\d+\.\d+$/.test(publicExternalAttestationResult.release_tag) ||
        !/^[a-f0-9]{40}$/i.test(publicExternalAttestationResult.commit_sha)
      ) {
        throw new Error('North Star public external attestation result evidence incomplete');
      }
    }
  } else if (publicExternalAttestationResult.bounded_signed_attestation_evidence_verified !== false) {
    throw new Error('North Star absent public external attestation result cannot validate signed attestation evidence');
  }
  if (privateVerifierResult.provided === true) {
    if (privateVerifierResult.verification_type !== PRIVATE_VERIFIER_RESULT_VERIFICATION_TYPE) {
      throw new Error('North Star private verifier result verification type drifted');
    }
    if (privateVerifierResult.private_non_operator_pass_validated === true) {
      if (
        privateVerifierResult.verified !== true ||
        privateVerifierResult.intake_class !== 'private-verifier-reply' ||
        privateVerifierResult.verdict !== 'PASS' ||
        privateVerifierResult.completed_by_non_operator !== true ||
        privateVerifierResult.private_by_default !== true ||
        privateVerifierResult.evidence_dir_hash_verification !== true
      ) {
        throw new Error('North Star private verifier result validation evidence incomplete');
      }
      if (
        privateVerifierResult.evidence_dir_contract_verification_required === true &&
        privateVerifierResult.evidence_dir_contract_verification !== true
      ) {
        throw new Error('North Star private verifier result content-contract evidence incomplete');
      }
      if (
        privateVerifierResult.downstream_refusal_boundary_required === true &&
        (privateVerifierResult.downstream_refusal_all_refusals_unboarded !== true ||
          privateVerifierResult.north_star_downstream_refusal_all_refusals_unboarded !== true ||
          !downstreamRefusalReasonsPreserved(
            privateVerifierResult.downstream_refusal_reasons,
          ) ||
          !downstreamRefusalReasonsPreserved(
            privateVerifierResult.north_star_downstream_refusal_reasons,
          ))
      ) {
        throw new Error('North Star private verifier result downstream-refusal evidence incomplete');
      }
    }
  } else if (privateVerifierResult.private_non_operator_pass_validated !== false) {
    throw new Error('North Star absent private verifier result cannot validate private non-operator pass');
  }
  if (privateVerifierZipResult.provided === true) {
    if (privateVerifierZipResult.verification_type !== PRIVATE_VERIFIER_ZIP_RESULT_VERIFICATION_TYPE) {
      throw new Error('North Star private verifier ZIP result verification type drifted');
    }
    if (
      privateVerifierZipResult
        .private_personally_connected_outside_machine_signal_validated === true
    ) {
      if (
        privateVerifierZipResult.verified !== true ||
        privateVerifierZipResult.recomputed_evidence !== true ||
        privateVerifierZipResult.evidence_model !== PRIVATE_VERIFIER_ZIP_EVIDENCE_MODEL ||
        privateVerifierZipResult.source_route !== PRIVATE_VERIFIER_ZIP_SOURCE_ROUTE ||
        privateVerifierZipResult.all_sha256sums_entries_matched !== true ||
        privateVerifierZipResult.all_required_steps_exit_zero !== true ||
        privateVerifierZipResult.only_known_stderr_issue !== true ||
        privateVerifierZipResult.proof_smoke_verified !== true ||
        privateVerifierZipResult.north_star_result !== NORTH_STAR_READINESS_RESULT_NOT_READY ||
        privateVerifierZipResult.public_privacy_passed !== true
      ) {
        throw new Error('North Star private verifier ZIP result validation evidence incomplete');
      }
    }
  } else if (
    privateVerifierZipResult
      .private_personally_connected_outside_machine_signal_validated !== false
  ) {
    throw new Error('North Star absent private verifier ZIP result cannot validate private outside-machine signal');
  }
  const publicBoundary = report.puzzle_pieces.find((piece) => piece.id === 7);
  const privateIntakePointer =
    publicBoundary?.observed?.private_intake_sample_manifest_pointer;
  if (!isObject(privateIntakePointer)) {
    throw new Error('North Star private intake sample manifest pointer must be reported');
  }
  exactKeys('North Star private intake sample manifest pointer', privateIntakePointer, [
    'circular_hash_avoided',
    'claim_boundary',
    'creates_public_external_attestation',
    'envelope_path',
    'evidence_model',
    'hash_record_location',
    'included_in_core_artifact_hashes',
    'manifest_field',
    'minimum_target',
    'provided',
    'proves_non_operator_review',
    'release_tag',
    'result_file',
    'result_section',
    'verification_path',
  ]);
  if (typeof privateIntakePointer.provided !== 'boolean') {
    throw new Error('North Star private intake sample manifest pointer provided flag drifted');
  }
  if (
    privateIntakePointer.included_in_core_artifact_hashes !== false ||
    privateIntakePointer.creates_public_external_attestation !== false ||
    privateIntakePointer.proves_non_operator_review !== false
  ) {
    throw new Error('North Star private intake sample manifest pointer boundary drifted');
  }
  if (privateIntakePointer.provided === true) {
    if (
      privateIntakePointer.evidence_model !== 'release-forward-helper-contract' ||
      privateIntakePointer.minimum_target !== 'v3.3.104' ||
      privateIntakePointer.manifest_field !== 'private_verifier_result_sample' ||
      privateIntakePointer.envelope_path !== 'ZLAR/zlar-private-verifier-result-v1.json' ||
      privateIntakePointer.verification_path !== 'ZLAR/zlar-private-verifier-result-verification-v1.json' ||
      privateIntakePointer.result_file !== 'DRY-RUN-RESULT.md' ||
      privateIntakePointer.result_section !== 'Private Verifier Result Intake' ||
      privateIntakePointer.hash_record_location !== 'DRY-RUN-RESULT.md#private-verifier-result-intake' ||
      privateIntakePointer.circular_hash_avoided !== true
    ) {
      throw new Error('North Star private intake sample manifest pointer contract drifted');
    }
  }
  const issuer = report.puzzle_pieces.find((piece) => piece.id === 4);
  if (issuer?.observed?.key_state_key_custody_proven !== false) {
    throw new Error('North Star issuer custody must remain unproven');
  }
  const trustedIssuerCompletion =
    issuer?.observed?.trusted_receipt_issuer_completion_proof;
  if (!isObject(trustedIssuerCompletion)) {
    throw new Error('North Star trusted issuer completion proof summary must be reported');
  }
  exactKeys('North Star trusted issuer completion proof summary', trustedIssuerCompletion, [
    'authority_event_distinct_from_legal_consent',
    'authority_event_type',
    'authority_primitive',
    'claim_boundary',
    'completed_for_selected_surface',
    'core_sentence',
    'custody_posture',
    'custody_posture_sha256',
    'fixture_only_evidence_accepted',
    'issuer_kid',
    'issuer_public_key_sha256',
    'issuer_recognition_distinct_from_human_yes',
    'key_state_sha256',
    'non_claims',
    'operator_registry_distinct_from_customer_production_trust',
    'overclaim_flags_accepted',
    'proof_sha256',
    'proof_type',
    'provided',
    'receipt_validity_distinct_from_human_intention',
    'recognition_contract_sha256',
    'registry_sha256',
    'revocation_status_not_global_certainty',
    'selected_surface_id',
    'software_custody_not_hardware_backed',
    'status_source_sha256',
    'summary_only_evidence_accepted',
    'verification_type',
    'verified',
  ]);
  if (trustedIssuerCompletion.provided === true) {
    if (
      trustedIssuerCompletion.verification_type !==
        TRUSTED_RECEIPT_ISSUER_COMPLETION_VERIFICATION_TYPE ||
      trustedIssuerCompletion.proof_type !== TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF_TYPE ||
      trustedIssuerCompletion.verified !== true ||
      trustedIssuerCompletion.completed_for_selected_surface !== true ||
      !isTrustedReceiptIssuerCompletionSurfaceId(
        trustedIssuerCompletion.selected_surface_id
      ) ||
      trustedIssuerCompletion.authority_primitive !==
        TRUSTED_RECEIPT_ISSUER_COMPLETION_AUTHORITY_PRIMITIVE ||
      trustedIssuerCompletion.core_sentence !==
        TRUSTED_RECEIPT_ISSUER_COMPLETION_CORE_SENTENCE ||
      !isSha256Hex(trustedIssuerCompletion.proof_sha256) ||
      !isSha256Hex(trustedIssuerCompletion.issuer_public_key_sha256) ||
      !isSha256Hex(trustedIssuerCompletion.registry_sha256) ||
      !isSha256Hex(trustedIssuerCompletion.recognition_contract_sha256) ||
      !isSha256Hex(trustedIssuerCompletion.status_source_sha256) ||
      !isSha256Hex(trustedIssuerCompletion.custody_posture_sha256) ||
      !isSha256Hex(trustedIssuerCompletion.key_state_sha256) ||
      trustedIssuerCompletion.receipt_validity_distinct_from_human_intention !== true ||
      trustedIssuerCompletion.issuer_recognition_distinct_from_human_yes !== true ||
      trustedIssuerCompletion.authority_event_distinct_from_legal_consent !== true ||
      trustedIssuerCompletion.operator_registry_distinct_from_customer_production_trust !==
        true ||
      trustedIssuerCompletion.revocation_status_not_global_certainty !== true ||
      trustedIssuerCompletion.summary_only_evidence_accepted !== false ||
      trustedIssuerCompletion.fixture_only_evidence_accepted !== false ||
      trustedIssuerCompletion.overclaim_flags_accepted !== false
    ) {
      throw new Error('North Star trusted issuer completion proof summary incomplete');
    }
    for (const [key, value] of Object.entries(trustedIssuerCompletion.claim_boundary || {})) {
      if (value !== false) {
        throw new Error(`North Star trusted issuer completion claim boundary drifted: ${key}`);
      }
    }
  } else if (trustedIssuerCompletion.completed_for_selected_surface !== false) {
    throw new Error('North Star absent trusted issuer completion proof cannot complete selected surface');
  }
  if (
    issuer?.observed?.trusted_issuer_registry_recognition?.provided === true &&
    issuer.observed.trusted_issuer_registry_recognition.live_probing !== false
  ) {
    throw new Error('North Star trusted issuer recognition must not be live probing');
  }
  if (
    issuer?.observed?.malformed_registry_contract?.provided === true &&
    issuer.observed.malformed_registry_contract.fail_closed_before_verdict !== true
  ) {
    throw new Error('North Star malformed registry contract must fail closed before verdict');
  }
  const verifierKit = issuer?.observed?.verifier_kit_reproducibility;
  if (verifierKit?.provided === true) {
    if (verifierKit.report_type !== 'zlar-verifier-kit-reproducibility-v1') {
      throw new Error('North Star verifier-kit reproducibility report type drifted');
    }
    if (
      verifierKit.result !== 'PASS' ||
      verifierKit.tarball_sha256_identical !== true ||
      verifierKit.manifest_and_signature_sha256_identical !== true ||
      verifierKit.sidecar_matches_tarball !== true ||
      verifierKit.public_artifact_hashes_present !== true
    ) {
      throw new Error('North Star verifier-kit reproducibility evidence drifted');
    }
    if (verifierKit.claim_boundary_flags_false !== true) {
      throw new Error('North Star verifier-kit reproducibility boundary must remain false');
    }
  }
  const verifierKitReleaseAssets = issuer?.observed?.verifier_kit_release_assets;
  if (!isObject(verifierKitReleaseAssets)) {
    throw new Error('North Star verifier-kit release-asset live-read summary must be reported');
  }
  exactKeys('North Star verifier-kit release assets summary', verifierKitReleaseAssets, [
    'all_required_assets_downloaded',
    'all_required_assets_present',
    'asset_urls_name_expected_repository',
    'claim_boundary',
    'claim_boundary_flags_false',
    'downloaded_sha256_count',
    'evidence_model',
    'provided',
    'public_release_non_draft',
    'release_url_names_expected_repository',
    'release_tag',
    'release_url_names_tag',
    'repository',
    'repository_matches_expected',
    'report_type',
    'required_asset_count',
  ]);
  if (verifierKitReleaseAssets.provided === true) {
    if (verifierKitReleaseAssets.report_type !== 'zlar-verifier-kit-release-assets-live-v1') {
      throw new Error('North Star verifier-kit release assets report type drifted');
    }
    if (verifierKitReleaseAssets.claim_boundary_flags_false !== true) {
      throw new Error('North Star verifier-kit release assets boundary must remain false');
    }
  }
  const verifierKitDistribution = issuer?.observed?.verifier_kit_public_distribution;
  const verifierKitDistributionReady =
    verifierKitDistribution?.ready_for_public_distribution_claim === true;
  if (verifierKitDistribution?.provided === true) {
    if (verifierKitDistribution.report_type !== 'zlar-verifier-kit-public-distribution-v1') {
      throw new Error('North Star verifier-kit public distribution report type drifted');
    }
    if (verifierKitDistribution.public_artifact_hashes_present !== true) {
      throw new Error('North Star verifier-kit public distribution artifact hashes drifted');
    }
    if (verifierKitDistributionReady === true) {
      if (
        verifierKitDistribution.required_release_assets_present !== true ||
        verifierKitDistribution.public_release_publication_evidence !== true ||
        (
          verifierKitDistribution.static_public_artifact_source_evidence === true &&
          verifierKitDistribution.public_artifact_source !== 'zlar.ai'
        ) ||
        verifierKitDistribution.release_asset_hashes_bound !== true ||
        verifierKitDistribution.local_artifact_hashes_match !== true ||
        verifierKitDistribution.blocking_reasons_count !== 0 ||
        (releaseTagAtLeast(releaseForwardTargetTag, 3, 4, 31) &&
          verifierKitDistribution.static_public_artifact_source_evidence !== true &&
          (
            verifierKitReleaseAssets.provided !== true ||
            verifierKitReleaseAssets.evidence_model !== 'github-release-assets-json-live-read' ||
            verifierKitReleaseAssets.repository !== 'ZLAR-AI/ZLAR' ||
            verifierKitReleaseAssets.repository_matches_expected !== true ||
            verifierKitReleaseAssets.release_tag !== releaseForwardTargetTag ||
            verifierKitReleaseAssets.all_required_assets_present !== true ||
            verifierKitReleaseAssets.all_required_assets_downloaded !== true ||
            verifierKitReleaseAssets.required_asset_count !== 3 ||
            verifierKitReleaseAssets.downloaded_sha256_count < 3 ||
            verifierKitReleaseAssets.release_url_names_tag !== true ||
            verifierKitReleaseAssets.release_url_names_expected_repository !== true ||
            verifierKitReleaseAssets.asset_urls_name_expected_repository !== true ||
            verifierKitReleaseAssets.public_release_non_draft !== true ||
            verifierKitReleaseAssets.claim_boundary_flags_false !== true
          ))
      ) {
        throw new Error('North Star verifier-kit public distribution ready evidence incomplete');
      }
    } else if (verifierKitDistribution.blocking_reasons_count < 1) {
      throw new Error('North Star verifier-kit public distribution blockers must be named when not ready');
    }
  }
  exactKeys('North Star v3.4.0 gate', report.v3_4_0_gate, [
    'next_version_class',
    'ready',
    'reason',
    'triggers_required',
  ]);
  const v34Ready = verifierKitDistributionReady === true;
  if (publicBoundary?.observed?.v3_4_0_ready !== v34Ready) {
    throw new Error('North Star public claim boundary v3.4.0 readiness mismatch');
  }
  if (report.v3_4_0_gate.ready !== v34Ready) {
    throw new Error('North Star v3.4.0 gate readiness mismatch');
  }
  if (
    !Array.isArray(report.v3_4_0_gate.triggers_required) ||
    report.v3_4_0_gate.triggers_required.length !== (v34Ready ? 0 : 3)
  ) {
    throw new Error('North Star v3.4.0 trigger list drifted');
  }
  if (
    report.result !== (
      v34Ready
        ? NORTH_STAR_READINESS_RESULT_READY_PUBLIC_DISTRIBUTION
        : NORTH_STAR_READINESS_RESULT_NOT_READY
    )
  ) {
    throw new Error('North Star readiness result/gate mismatch');
  }
  exactKeys(
    'North Star claim boundary',
    report.claim_boundary,
    NORTH_STAR_READINESS_CLAIM_BOUNDARY_KEYS,
  );
  for (const [key, value] of Object.entries(report.claim_boundary)) {
    if (key === 'v3_4_0_ready') {
      if (value !== v34Ready) {
        throw new Error('North Star claim boundary v3_4_0_ready mismatch');
      }
    } else if (value !== false) {
      throw new Error(`North Star claim boundary ${key} must remain false`);
    }
  }
  const privateVerifierResultValidated =
    privateVerifierResult.private_non_operator_pass_validated === true;
  const privateVerifierZipResultValidated =
    privateVerifierZipResult
      .private_personally_connected_outside_machine_signal_validated === true;
  const expectedNonClaims = northStarReadinessNonClaims(
    v34Ready,
    privateVerifierResultValidated,
    privateVerifierZipResultValidated
  );
  if (!Array.isArray(report.non_claims) || report.non_claims.length !== expectedNonClaims.length) {
    throw new Error('North Star non-claims drifted');
  }
  for (const fragment of REQUIRED_NON_CLAIM_FRAGMENTS) {
    if (!report.non_claims.some((claim) => claim.includes(fragment))) {
      throw new Error(`North Star non-claim missing ${fragment}`);
    }
  }
  return true;
}

export function formatNorthStarReadinessSummary(report) {
  assertNorthStarReadinessReport(report);
  const productProofPath = report.puzzle_pieces.find((piece) => piece.id === 1)
    ?.observed?.product_proof_path;
  const deploymentProfileAuthorityBridge =
    productProofPath?.deployment_profile_authority_bridge || {};
  const externalAttestationObserved =
    report.puzzle_pieces.find((piece) => piece.id === 6)?.observed || {};
  const historicalLifecycleEvidence =
    report.supplemental_evidence
      ?.historical_supplied_local_active_persistent_profile_lifecycle || {};
  const lines = [
    'ZLAR North Star Readiness',
    '',
    `Result: ${report.result}`,
    `Evidence model: ${report.evidence_model}`,
    `Action class: ${report.action_class}`,
    `Selected terminal: ${report.selected_terminal.surface_id}`,
    `Puzzle pieces: ${report.counts.proven_count} proven, ${report.counts.partial_count} partial, ${report.counts.unproven_count} unproven`,
    `Governed lanes: ${report.counts.governed_lanes}/${report.counts.counted_lanes}`,
    `v3.4.0 ready: ${report.v3_4_0_gate.ready}`,
    `Private non-operator pass validated: ${
      externalAttestationObserved.private_non_operator_pass_validated === true
    }`,
    `Private ZIP outside-machine signal validated: ${
      externalAttestationObserved
        .private_personally_connected_outside_machine_signal_validated === true
    }`,
    `One-terminal deployment bridge: preserved=${
      report.counts.product_proof_path_deployment_profile_authority_bridge_preserved
    }; authority_refusals_preserved=${
      report.counts.product_proof_path_deployment_profile_authority_refusals_preserved
    }; request_authority_material_accepted=${
      deploymentProfileAuthorityBridge.request_stream_authority_material_accepted
    }; recognized_receipt_mutates_once=${
      deploymentProfileAuthorityBridge.recognized_receipt_mutates_once
    }`,
    `Stronger North Star completion still false: enterprise_readiness=${
      report.claim_boundary.enterprise_readiness
    }; public_external_attestation=${
      report.claim_boundary.public_external_attestation
    }; production_downstream_recognition=${
      report.claim_boundary.production_downstream_recognition
    }; persistent_runtime_profile_installation=${
      report.claim_boundary.persistent_runtime_profile_installation
    }`,
    `Named deployment-profile real boundary is closed-proof only; active persistent installation still false: ${
      report.claim_boundary.production_downstream_recognition !== true &&
      report.claim_boundary.persistent_runtime_profile_installation !== true
    }`,
    `Historical supplied local active-persistent lifecycle evidence: provided=${
      historicalLifecycleEvidence.provided === true
    }; verified=${historicalLifecycleEvidence.verified === true}; non_scoring=${
      historicalLifecycleEvidence.non_scoring === true
    }; current_installation=${
      historicalLifecycleEvidence.current_installation === true
    }`,
    '',
    'Triggers required:',
    ...report.v3_4_0_gate.triggers_required.map((trigger) => `- ${trigger}`),
    '',
    'Pieces:',
  ];
  for (const piece of report.puzzle_pieces) {
    lines.push(`- ${piece.id}. ${piece.name}: ${piece.status} (${piece.acceptance_gate_scope})`);
  }
  lines.push('', 'Boundary:');
  for (const claim of report.non_claims) {
    lines.push(`- ${claim}`);
  }
  return `${lines.join('\n')}\n`;
}

export function assertNoUnsafeNorthStarReadinessText(text) {
  for (const { label, pattern } of UNSAFE_OUTPUT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`North Star readiness output contains unsafe ${label}`);
    }
  }
  return true;
}
