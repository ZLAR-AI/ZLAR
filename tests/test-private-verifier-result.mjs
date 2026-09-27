#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import {
  PRIVATE_VERIFIER_RESULT_TYPE,
  assertPrivateVerifierResult,
  buildPrivateVerifierResultVerification,
  formatPrivateVerifierResultVerification,
} from '../lib/private-verifier-result.mjs';

let PASS = 0;
let FAIL = 0;
let TOTAL = 0;
const TEMP_DIRS = [];

process.on('exit', () => {
  for (const dir of TEMP_DIRS) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function assert(label, condition, detail = '') {
  TOTAL++;
  if (condition) {
    PASS++;
    console.log(`  PASS: ${label}`);
  } else {
    FAIL++;
    console.log(`  FAIL: ${label}${detail ? ` -- ${detail}` : ''}`);
  }
}

function assertEqual(label, expected, actual) {
  assert(label, expected === actual, `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
}

function assertThrows(label, fn, expectedMessageFragment) {
  TOTAL++;
  try {
    fn();
    FAIL++;
    console.log(`  FAIL: ${label} -- expected throw`);
  } catch (err) {
    if (!expectedMessageFragment || String(err.message).includes(expectedMessageFragment)) {
      PASS++;
      console.log(`  PASS: ${label}`);
    } else {
      FAIL++;
      console.log(`  FAIL: ${label} -- ${err.message}`);
    }
  }
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function sha256Text(text) {
  return createHash('sha256').update(text).digest('hex');
}

function artifactSetSha256(artifactHashes) {
  const canonical = artifactHashes
    .map((entry) => `${entry.path}\0${entry.sha256}\n`)
    .sort()
    .join('');
  return sha256Text(canonical);
}

function artifactFilePath(evidenceDir, artifactPath) {
  return join(evidenceDir, ...artifactPath.split('/'));
}

function defaultArtifactText(artifactPath) {
  return `zlar-private-verifier-result-test\n${artifactPath}\n`;
}

function defaultArtifactSha(artifactPath) {
  return sha256Text(defaultArtifactText(artifactPath));
}

const expectedRecognitionRefusalGroupCaseIds = Object.freeze({
  no_usable_recognized_receipt_authority: Object.freeze([
    'missing_receipt_refused_before_runtime_mutation',
    'invalid_receipt_refused_before_runtime_mutation',
    'unknown_issuer_refused_before_runtime_mutation',
    'retired_issuer_refused_before_runtime_mutation',
    'missing_issuer_status_refused_before_runtime_mutation',
    'stale_receipt_refused_before_runtime_mutation',
  ]),
  recognized_receipt_scope_mismatch: Object.freeze([
    'wrong_policy_refused_before_runtime_mutation',
    'wrong_domain_refused_before_runtime_mutation',
    'wrong_tool_refused_before_runtime_mutation',
    'wrong_audit_event_refused_before_runtime_mutation',
    'wrong_detail_refused_before_runtime_mutation',
    'non_boarding_outcome_refused_before_runtime_mutation',
  ]),
  route_or_request_authority_material_refused: Object.freeze([
    'wrong_runtime_profile_id_refused_before_runtime_mutation',
    'direct_api_without_receipt_refused_before_runtime_mutation',
    'direct_api_with_receipt_refused_before_runtime_mutation',
    'agent_supplied_recognition_rule_refused_before_runtime_mutation',
    'agent_supplied_fixture_mode_refused_before_runtime_mutation',
    'unsupported_request_field_refused_before_runtime_mutation',
  ]),
});

const expectedDeploymentProfileAuthorityRefusalCaseIds = Object.freeze([
  'stale_deployment_profile_runtime_sha_refused_before_service_proof',
  'runtime_profile_id_mismatch_refused_before_service_proof',
  'preflight_profile_sha_mismatch_refused_before_service_proof',
  'preflight_latest_selection_refused_before_service_proof',
  'preflight_request_authority_material_refused_before_service_proof',
]);

const expectedTrustedRegistryRecognitionRefusalCaseIds = Object.freeze([
  'unrecognized_terminal_chain_registry_scope_refused',
  'registry_receipt_contract_mismatch_refused',
]);

const expectedTrustedRegistryRecognitionRefusalReasonCodes = Object.freeze([
  'scope_not_found',
  'detail_hash_mismatch',
]);

const expectedDownstreamRefusalReasons = Object.freeze([
  'receipt_missing',
  'receipt_invalid',
  'issuer_not_active',
  'unknown_issuer',
  'outcome_not_boarding',
  'policy_not_recognized',
  'domain_out_of_scope',
  'tool_out_of_scope',
  'audit_event_mismatch',
  'detail_hash_mismatch',
  'receipt_stale',
]);

const expectedDownstreamRefusalBoundaryKeys = Object.freeze([
  'provided',
  'recognized_boarded',
  'recognized_marker_count_delta',
  'final_marker_count',
  'refusal_case_count',
  'all_refusals_unboarded',
  'all_refusal_marker_count_deltas_zero',
  'refusal_reasons',
]);

const expectedRecognizedReceiptPathMirrorKeys = Object.freeze([
  'recognized_receipt_path_evidence_sha256',
  'recognized_receipt_path_evidence_artifact_verification_sha256',
  'recognized_receipt_path_evidence_sha256_matches_artifact_verification',
  'recognized_receipt_path_evidence_bound_to_artifact_body',
  'recognized_receipt_path_evidence_source_binding_sha256',
  'recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding',
  'recognized_receipt_path_evidence_verdict',
  'recognized_receipt_path_evidence_recognized',
  'recognized_receipt_path_evidence_receipt_envelope_included',
  'recognized_receipt_path_evidence_registry_public_key_material_included',
  'recognized_receipt_path_evidence_artifact_crypto_reproducible',
  'recognized_receipt_path_evidence_live_state_proven',
  'recognized_receipt_path_evidence_live_issuer_status_proven',
  'recognized_receipt_path_evidence_key_custody_proven',
  'recognized_receipt_path_evidence_revocation_truth_proven',
  'recognized_receipt_path_evidence_production_downstream_recognition_proven',
  'recognized_receipt_path_evidence_public_external_attestation',
  'recognized_receipt_path_evidence_sovereign_recognition',
  'recognized_receipt_path_evidence_current_machine_governance_proven',
]);

const expectedPrivateVerifierResultSamplePointerKeys = Object.freeze([
  'enabled',
  'evidence_model',
  'minimum_target',
  'envelope_path',
  'verification_path',
  'result_file',
  'result_section',
  'hash_record_location',
  'included_in_core_artifact_hashes',
  'circular_hash_avoided',
  'verification_result_section',
  'verification_result_minimum_target',
  'creates_public_external_attestation',
  'proves_non_operator_review',
]);

const nestedPreflightArtifactType =
  'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1';
const nestedServiceProofArtifactType =
  'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1';

const expectedDeploymentProfileAuthorityBridgeKeys = Object.freeze([
  'proof_type',
  'evidence_model',
  'live_probing',
  'deployment_profile_id',
  'deployment_profile_sha256',
  'runtime_profile_sha256',
  'deployment_profile_artifact_authoritative',
  'selected_by_explicit_id_and_sha',
  'selects_latest_profile',
  'preflight_artifact_verified',
  'recognized_receipt_mutates_once',
  'recognized_state_entry_count_delta',
  'required_refusal_case_count',
  'observed_refusal_case_count',
  'all_required_refusals_before_mutation',
  'agent_supplied_authority_refused_before_mutation',
  'direct_api_refused_before_mutation',
  'downstream_refusal_proven',
  'request_stream_authority_material_accepted',
  'current_machine_governance',
  'production_downstream_recognition',
  'production_authority',
  'enterprise_readiness',
  'external_attestation',
  'sovereign_recognition',
  'unrouted_surface_coverage',
]);

const expectedDeploymentProfileAuthorityBridgeNorthStarKeys = Object.freeze([
  'deployment_profile_authority_bridge_required',
  'deployment_profile_authority_bridge_preserved',
  'deployment_profile_authority_bridge_observed',
  'deployment_profile_authority_bridge_proof_type',
  'deployment_profile_authority_bridge_refusal_count',
  'deployment_profile_authority_bridge_current_machine_governance',
  'deployment_profile_authority_bridge_production_authority',
]);

const expectedDeploymentProfileAuthorityRefusalBridgeKeys = Object.freeze([
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

const expectedDeploymentProfileAuthorityRefusalNorthStarKeys = Object.freeze([
  'deployment_profile_authority_refusals_required',
  'deployment_profile_authority_refusals_preserved',
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

const expectedDeploymentProfileAuthorityBridgeV349Keys = Object.freeze([
  ...expectedDeploymentProfileAuthorityBridgeKeys,
  ...expectedDeploymentProfileAuthorityRefusalBridgeKeys,
]);

const expectedDeploymentProfileAuthorityNorthStarV349Keys = Object.freeze([
  ...expectedDeploymentProfileAuthorityBridgeNorthStarKeys,
  ...expectedDeploymentProfileAuthorityRefusalNorthStarKeys,
]);

const expectedTerminalChainTrustedRegistryRecognitionRefusalKeys = Object.freeze([
  'trusted_issuer_registry_recognition_refusals_minimum_target',
  'trusted_issuer_registry_recognition_refusals_required',
  'trusted_issuer_registry_recognition_refusal_case_count',
  'artifact_verification_trusted_issuer_registry_recognition_refusal_case_count',
  'trusted_issuer_registry_recognition_refusals_all_refused',
  'artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused',
  'trusted_issuer_registry_recognition_refusal_case_ids',
  'artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids',
  'trusted_issuer_registry_recognition_refusal_reason_codes',
  'artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes',
  'trusted_issuer_registry_recognition_refusals_sha256',
  'artifact_verification_trusted_issuer_registry_recognition_refusals_sha256',
  'all_trusted_issuer_registry_recognition_refusals_preserved',
]);

const expectedReportContractTerminalChainTrustedRegistryRecognitionRefusalKeys =
  Object.freeze(
    expectedTerminalChainTrustedRegistryRecognitionRefusalKeys.filter(
      (key) => key !== 'trusted_issuer_registry_recognition_refusals_minimum_target',
    ),
  );

const expectedTerminalChainDeploymentProfileAuthorityRefusalMirrorKeys =
  Object.freeze([
    'deployment_profile_authority_refusal_mirror_minimum_target',
    'deployment_profile_authority_refusal_mirror_required',
    'deployment_profile_authority_refusal_mirror_preserved',
    'deployment_profile_authority_refusal_case_count',
    'artifact_verification_deployment_profile_authority_refusal_case_count',
    'deployment_profile_authority_refusal_case_ids',
    'artifact_verification_deployment_profile_authority_refusal_case_ids',
    'deployment_profile_authority_refusals_before_service_proof',
    'artifact_verification_deployment_profile_authority_refusals_before_service_proof',
    'deployment_profile_authority_refusals_before_mutation',
    'artifact_verification_deployment_profile_authority_refusals_before_mutation',
    'deployment_profile_authority_refusal_service_proof_started',
    'artifact_verification_deployment_profile_authority_refusal_service_proof_started',
    'stale_deployment_profile_artifact_refused_before_service_proof',
    'profile_recognition_mismatch_refused_before_service_proof',
    'latest_profile_selection_refused_before_service_proof',
    'request_stream_authority_material_refused_before_service_proof',
    'current_machine_governance',
    'production_downstream_recognition',
    'production_authority',
    'enterprise_readiness',
    'external_attestation',
    'sovereign_recognition',
    'unrouted_surface_coverage',
  ]);

const expectedReportContractTerminalChainDeploymentProfileAuthorityRefusalMirrorKeys =
  Object.freeze(
    expectedTerminalChainDeploymentProfileAuthorityRefusalMirrorKeys.filter(
      (key) => key !== 'deployment_profile_authority_refusal_mirror_minimum_target',
    ),
  );

const expectedReportContractProofSmokeTrustedRegistryRecognitionRefusalKeys =
  Object.freeze([
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256',
    'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256',
  ]);

const expectedReportContractNorthStarTrustedRegistryRecognitionRefusalKeys =
  Object.freeze([
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved',
    ...expectedReportContractProofSmokeTrustedRegistryRecognitionRefusalKeys,
  ]);

const expectedReportContractNorthStarObservedTrustedRegistryRecognitionRefusalKeys =
  Object.freeze([
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes',
  ]);

function keysEqual(value, expectedKeys) {
  const actual = Object.keys(value || {}).sort();
  const expected = [...expectedKeys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

const deploymentProfileAuthorityNorthStarPrefixes = Object.freeze([
  'deployment_profile_authority_',
  'stale_deployment_profile_artifact_',
  'profile_recognition_mismatch_',
  'latest_profile_selection_',
  'request_stream_authority_material_',
]);

function deploymentProfileAuthorityNorthStarKeysEqual(value, expectedKeys) {
  const actual = Object.keys(value || {})
    .filter((key) =>
      deploymentProfileAuthorityNorthStarPrefixes.some((prefix) =>
        key.startsWith(prefix),
      ),
    )
    .sort();
  const expected = [...expectedKeys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

function terminalChainTrustedRegistryRefusalKeysEqual(value, expectedKeys) {
  const actual = Object.keys(value || {})
    .filter((key) =>
      key.startsWith('trusted_issuer_registry_recognition_refusal') ||
      key.startsWith('artifact_verification_trusted_issuer_registry_recognition_refusal') ||
      key === 'all_trusted_issuer_registry_recognition_refusals_preserved',
    )
    .sort();
  const expected = [...expectedKeys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

function reportContractProofSummaryTrustedRegistryRefusalKeysEqual(
  value,
  expectedKeys,
) {
  const actual = Object.keys(value || {})
    .filter((key) =>
      key.startsWith(
        'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal',
      ) ||
      key.startsWith(
        'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals',
      ) ||
      key.startsWith(
        'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal',
      ) ||
      key.startsWith(
        'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals',
      ),
    )
    .sort();
  const expected = [...expectedKeys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

function terminalChainDeploymentProfileAuthorityRefusalMirrorKeysEqual(
  value,
  expectedKeys,
) {
  const falseBoundaryKeys = new Set([
    'current_machine_governance',
    'production_downstream_recognition',
    'production_authority',
    'enterprise_readiness',
    'external_attestation',
    'sovereign_recognition',
    'unrouted_surface_coverage',
  ]);
  const actual = Object.keys(value || {})
    .filter((key) =>
      key.startsWith('deployment_profile_authority_refusal') ||
      key.startsWith('artifact_verification_deployment_profile_authority_refusal') ||
      key.startsWith('stale_deployment_profile_artifact_') ||
      key.startsWith('profile_recognition_mismatch_') ||
      key.startsWith('latest_profile_selection_') ||
      key.startsWith('request_stream_authority_material_') ||
      falseBoundaryKeys.has(key),
    )
    .sort();
  const expected = [...expectedKeys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

function releaseTagAtLeast(tag, minimum) {
  const tagParts = /^v([0-9]+)\.([0-9]+)\.([0-9]+)$/.exec(tag);
  const minimumParts = /^v([0-9]+)\.([0-9]+)\.([0-9]+)$/.exec(minimum);
  if (!tagParts || !minimumParts) return false;
  const version = tagParts.slice(1).map(Number);
  const floor = minimumParts.slice(1).map(Number);
  for (let index = 0; index < 3; index++) {
    if (version[index] > floor[index]) return true;
    if (version[index] < floor[index]) return false;
  }
  return true;
}

const v346ArtifactPaths = Object.freeze([
  'ZLAR/zlar-verifier-kit-release-assets-v1.json',
  'ZLAR/zlar-verifier-kit-public-distribution-v1.json',
  'ZLAR/zlar-installed-runtime-profile-preflight-sample-verification.json',
  'ZLAR/zlar-installed-runtime-profile-recognition-proof-v1.json',
  'ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-v1.json',
  'ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json',
  'ZLAR/zlar-product-proof-path-v1.json',
  'ZLAR/zlar-installed-runtime-profile-service-proof-v1.json',
  'ZLAR/zlar-installed-runtime-profile-service-proof-artifact-v1.json',
  'ZLAR/zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json',
  'ZLAR/zlar-installed-runtime-profile-terminal-chain-v1.json',
  'ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-v1.json',
  'ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json',
  'ZLAR/zlar-verifier-kit-external-runner-diagnostics-v1.json',
  'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-v1.json',
  'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-error.txt',
  'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-v1.json',
  'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-error.txt',
]);

function writeEvidenceFiles(report, artifactTexts = {}) {
  const evidenceDir = mkdtempSync(join(tmpdir(), 'zlar-private-verifier-result-'));
  TEMP_DIRS.push(evidenceDir);
  for (const artifact of report.evidence.artifact_hashes) {
    if (['SHA256SUMS', 'RUN-SHA256SUMS'].includes(artifact.path)) continue;
    const artifactText =
      artifactTexts[artifact.path] ?? defaultArtifactText(artifact.path);
    const artifactPath = artifactFilePath(evidenceDir, artifact.path);
    mkdirSync(dirname(artifactPath), { recursive: true });
    writeFileSync(artifactPath, artifactText);
    artifact.sha256 = sha256Text(artifactText);
  }
  for (const [path, text] of Object.entries({
    'target-head.txt': `${report.target.commit_sha}\n`,
    'target-status.txt': 'PASS\n',
    'transcript.txt': 'transcript\n',
    'COMMANDS.txt': 'commands\n',
    'ASSERTIONS.txt': 'PASS assertions\n',
  })) {
    const artifactPath = artifactFilePath(evidenceDir, path);
    mkdirSync(dirname(artifactPath), { recursive: true });
    writeFileSync(artifactPath, text);
  }
  if (report.evidence.artifact_hashes.some((entry) => entry.path === 'SHA256SUMS')) {
    const sha256SumsText =
      artifactTexts.SHA256SUMS ??
      report.evidence.artifact_hashes
        .filter((entry) => entry.path.startsWith('ZLAR/'))
        .map((entry) => {
          const path = entry.path.slice('ZLAR/'.length);
          const hash = sha256Text(
            readFileSync(artifactFilePath(evidenceDir, entry.path), 'utf8'),
          );
          return `${hash}  ${path}`;
        })
        .join('\n')
        .concat('\n');
    writeFileSync(artifactFilePath(evidenceDir, 'SHA256SUMS'), sha256SumsText);
  }
  if (report.evidence.artifact_hashes.some((entry) => entry.path === 'RUN-SHA256SUMS')) {
    const runSha256SumsText =
      artifactTexts['RUN-SHA256SUMS'] ??
      ['transcript.txt', 'COMMANDS.txt', 'ASSERTIONS.txt', 'target-head.txt', 'target-status.txt', 'SHA256SUMS']
        .map((path) => {
          const hash = sha256Text(readFileSync(artifactFilePath(evidenceDir, path), 'utf8'));
          return `${hash}  ${path}`;
        })
        .join('\n')
        .concat('\n');
    writeFileSync(artifactFilePath(evidenceDir, 'RUN-SHA256SUMS'), runSha256SumsText);
  }
  for (const artifact of report.evidence.artifact_hashes) {
    artifact.sha256 = sha256Text(readFileSync(artifactFilePath(evidenceDir, artifact.path), 'utf8'));
  }
  const sha256SumsEntry = report.evidence.artifact_hashes.find((entry) => entry.path === 'SHA256SUMS');
  if (sha256SumsEntry) {
    report.evidence.received_bundle_sha256 = sha256SumsEntry.sha256;
  }
  return evidenceDir;
}

function makeEvidenceFixture() {
  const report = clone(fixture);
  const evidenceDir = writeEvidenceFiles(report);
  return { report, evidenceDir };
}

function addArtifactHashes(report, paths) {
  const existing = new Set(report.evidence.artifact_hashes.map((entry) => entry.path));
  for (const path of paths) {
    if (existing.has(path)) continue;
    report.evidence.artifact_hashes.push({
      path,
      sha256: defaultArtifactSha(path),
    });
    existing.add(path);
  }
  return report;
}

function releaseForwardManifestContract({ terminalBoundary = {}, northStar = {} } = {}) {
  return {
    release_forward_report_contract: {
      product_proof_path: {
        terminal_chain_boundary: {
          recognition_refusal_group_count: 3,
          recognition_refusal_group_case_count: 18,
          recognition_refusal_group_case_ids: clone(expectedRecognitionRefusalGroupCaseIds),
          recognition_refusal_group_case_ids_preserved: true,
          ...terminalBoundary,
        },
        north_star: {
          terminal_chain_recognition_refusal_group_count: 3,
          terminal_chain_recognition_refusal_group_case_count: 18,
          terminal_chain_recognition_refusal_group_case_ids: clone(expectedRecognitionRefusalGroupCaseIds),
          terminal_chain_recognition_refusal_group_case_ids_preserved: true,
          ...northStar,
        },
      },
    },
  };
}

function reportContractProofSmokeRecognitionRefusalGroupCaseIds(
  overrides = {},
) {
  return {
    installed_runtime_profile_terminal_chain_recognition_refusal_group_count: 3,
    installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count:
      18,
    installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count:
      3,
    installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count:
      18,
    installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids:
      clone(expectedRecognitionRefusalGroupCaseIds),
    ...overrides,
  };
}

function reportContractNorthStarRecognitionRefusalGroupCaseIds(overrides = {}) {
  return {
    installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required:
      true,
    installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved:
      true,
    ...reportContractProofSmokeRecognitionRefusalGroupCaseIds(),
    ...overrides,
  };
}

function releaseForwardReportContractClaimBoundary(overrides = {}) {
  return {
    creates_public_external_attestation: false,
    proves_non_operator_review: false,
    proves_live_registry: false,
    proves_live_issuer_status: false,
    proves_key_custody: false,
    proves_revocation_truth: false,
    proves_current_machine_governance: false,
    proves_live_mcp_coverage: false,
    proves_production_downstream_recognition: false,
    proves_production_authority: false,
    proves_enterprise_readiness: false,
    proves_sovereign_recognition: false,
    proves_unrouted_surface_coverage: false,
    ...overrides,
  };
}

function releaseForwardProductProofPathClaimBoundary(overrides = {}) {
  return {
    creates_public_external_attestation: false,
    proves_current_machine_governance: false,
    proves_all_mcp_governance: false,
    proves_unrouted_surface_coverage: false,
    ...overrides,
  };
}

function productProofPathSimulatedHumanAuthorization(overrides = {}) {
  return {
    approval_channel: 'simulated-human-fixture',
    authorized_boarded: true,
    denied_boarded: false,
    pending_boarded: false,
    ...overrides,
  };
}

function productProofPathReceiptVerifierBoundary(overrides = {}) {
  return {
    downstream_recognition_proven: false,
    invalid_verdict: 'INVALID',
    unknown_signer_verdict: 'UNKNOWN-SIGNER',
    valid_verdict: 'VALID',
    ...overrides,
  };
}

function terminalChainNestedArtifactTamperRefusals(overrides = {}) {
  return {
    generated_preflight_artifact_type: nestedPreflightArtifactType,
    generated_service_proof_artifact_type: nestedServiceProofArtifactType,
    artifact_generated_preflight_artifact_type: nestedPreflightArtifactType,
    artifact_generated_service_proof_artifact_type: nestedServiceProofArtifactType,
    forged_inner_preflight_hash_refused: true,
    forged_inner_service_hash_refused: true,
    ...overrides,
  };
}

function terminalChainNestedArtifactBinding(overrides = {}) {
  return {
    generated_preflight_artifact_type: nestedPreflightArtifactType,
    generated_service_proof_artifact_type: nestedServiceProofArtifactType,
    generated_preflight_artifact_body_sha256: '1'.repeat(64),
    generated_service_proof_artifact_body_sha256: '2'.repeat(64),
    generated_preflight_artifact_verified: true,
    generated_service_proof_artifact_verified: true,
    preflight_artifact_hash_bound: true,
    service_proof_source_preflight_hash_bound: true,
    service_artifact_hash_bound: true,
    service_artifact_verification_bound_to_service_proof: true,
    creates_public_external_attestation: false,
    proves_non_operator_review: false,
    proves_current_machine_governance: false,
    proves_production_downstream_recognition: false,
    ...overrides,
  };
}

function terminalChainTrustedRegistryRecognitionRefusals(overrides = {}) {
  return {
    trusted_issuer_registry_recognition_refusals_minimum_target: 'v3.4.39',
    trusted_issuer_registry_recognition_refusals_required: true,
    trusted_issuer_registry_recognition_refusal_case_count:
      expectedTrustedRegistryRecognitionRefusalCaseIds.length,
    artifact_verification_trusted_issuer_registry_recognition_refusal_case_count:
      expectedTrustedRegistryRecognitionRefusalCaseIds.length,
    trusted_issuer_registry_recognition_refusals_all_refused: true,
    artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused:
      true,
    trusted_issuer_registry_recognition_refusal_case_ids: clone(
      expectedTrustedRegistryRecognitionRefusalCaseIds,
    ),
    artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids:
      clone(expectedTrustedRegistryRecognitionRefusalCaseIds),
    trusted_issuer_registry_recognition_refusal_reason_codes: clone(
      expectedTrustedRegistryRecognitionRefusalReasonCodes,
    ),
    artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes:
      clone(expectedTrustedRegistryRecognitionRefusalReasonCodes),
    trusted_issuer_registry_recognition_refusals_sha256: '3'.repeat(64),
    artifact_verification_trusted_issuer_registry_recognition_refusals_sha256:
      '3'.repeat(64),
    all_trusted_issuer_registry_recognition_refusals_preserved: true,
    ...overrides,
  };
}

function terminalChainDeploymentProfileAuthorityRefusalMirror(overrides = {}) {
  return {
    deployment_profile_authority_refusal_mirror_minimum_target: 'v3.4.50',
    deployment_profile_authority_refusal_mirror_required: true,
    deployment_profile_authority_refusal_mirror_preserved: true,
    deployment_profile_authority_refusal_case_count:
      expectedDeploymentProfileAuthorityRefusalCaseIds.length,
    artifact_verification_deployment_profile_authority_refusal_case_count:
      expectedDeploymentProfileAuthorityRefusalCaseIds.length,
    deployment_profile_authority_refusal_case_ids: clone(
      expectedDeploymentProfileAuthorityRefusalCaseIds,
    ),
    artifact_verification_deployment_profile_authority_refusal_case_ids:
      clone(expectedDeploymentProfileAuthorityRefusalCaseIds),
    deployment_profile_authority_refusals_before_service_proof: true,
    artifact_verification_deployment_profile_authority_refusals_before_service_proof:
      true,
    deployment_profile_authority_refusals_before_mutation: true,
    artifact_verification_deployment_profile_authority_refusals_before_mutation:
      true,
    deployment_profile_authority_refusal_service_proof_started: false,
    artifact_verification_deployment_profile_authority_refusal_service_proof_started:
      false,
    stale_deployment_profile_artifact_refused_before_service_proof: true,
    profile_recognition_mismatch_refused_before_service_proof: true,
    latest_profile_selection_refused_before_service_proof: true,
    request_stream_authority_material_refused_before_service_proof: true,
    current_machine_governance: false,
    production_downstream_recognition: false,
    production_authority: false,
    enterprise_readiness: false,
    external_attestation: false,
    sovereign_recognition: false,
    unrouted_surface_coverage: false,
    ...overrides,
  };
}

function releaseForwardReportContractTerminalChainRefusalEvidence(
  terminalEvidence,
  overrides = {},
) {
  return {
    source: 'same-manifest.terminal_chain_refusal_evidence',
    trusted_issuer_registry_recognition_refusals_required:
      terminalEvidence.trusted_issuer_registry_recognition_refusals_required,
    trusted_issuer_registry_recognition_refusal_case_count:
      terminalEvidence.trusted_issuer_registry_recognition_refusal_case_count,
    artifact_verification_trusted_issuer_registry_recognition_refusal_case_count:
      terminalEvidence
        .artifact_verification_trusted_issuer_registry_recognition_refusal_case_count,
    trusted_issuer_registry_recognition_refusals_all_refused:
      terminalEvidence.trusted_issuer_registry_recognition_refusals_all_refused,
    artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused:
      terminalEvidence
        .artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused,
    trusted_issuer_registry_recognition_refusal_case_ids: clone(
      terminalEvidence.trusted_issuer_registry_recognition_refusal_case_ids,
    ),
    artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids:
      clone(
        terminalEvidence
          .artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids,
      ),
    trusted_issuer_registry_recognition_refusal_reason_codes: clone(
      terminalEvidence.trusted_issuer_registry_recognition_refusal_reason_codes,
    ),
    artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes:
      clone(
        terminalEvidence
          .artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes,
      ),
    trusted_issuer_registry_recognition_refusals_sha256:
      terminalEvidence.trusted_issuer_registry_recognition_refusals_sha256,
    artifact_verification_trusted_issuer_registry_recognition_refusals_sha256:
      terminalEvidence.artifact_verification_trusted_issuer_registry_recognition_refusals_sha256,
    all_trusted_issuer_registry_recognition_refusals_preserved:
      terminalEvidence.all_trusted_issuer_registry_recognition_refusals_preserved,
    ...(terminalEvidence.deployment_profile_authority_refusal_mirror_required
      ? {
          deployment_profile_authority_refusal_mirror_required:
            terminalEvidence.deployment_profile_authority_refusal_mirror_required,
          deployment_profile_authority_refusal_mirror_preserved:
            terminalEvidence.deployment_profile_authority_refusal_mirror_preserved,
          deployment_profile_authority_refusal_case_count:
            terminalEvidence.deployment_profile_authority_refusal_case_count,
          artifact_verification_deployment_profile_authority_refusal_case_count:
            terminalEvidence
              .artifact_verification_deployment_profile_authority_refusal_case_count,
          deployment_profile_authority_refusal_case_ids: clone(
            terminalEvidence.deployment_profile_authority_refusal_case_ids,
          ),
          artifact_verification_deployment_profile_authority_refusal_case_ids:
            clone(
              terminalEvidence
                .artifact_verification_deployment_profile_authority_refusal_case_ids,
            ),
          deployment_profile_authority_refusals_before_service_proof:
            terminalEvidence.deployment_profile_authority_refusals_before_service_proof,
          artifact_verification_deployment_profile_authority_refusals_before_service_proof:
            terminalEvidence
              .artifact_verification_deployment_profile_authority_refusals_before_service_proof,
          deployment_profile_authority_refusals_before_mutation:
            terminalEvidence.deployment_profile_authority_refusals_before_mutation,
          artifact_verification_deployment_profile_authority_refusals_before_mutation:
            terminalEvidence
              .artifact_verification_deployment_profile_authority_refusals_before_mutation,
          deployment_profile_authority_refusal_service_proof_started:
            terminalEvidence.deployment_profile_authority_refusal_service_proof_started,
          artifact_verification_deployment_profile_authority_refusal_service_proof_started:
            terminalEvidence
              .artifact_verification_deployment_profile_authority_refusal_service_proof_started,
          stale_deployment_profile_artifact_refused_before_service_proof:
            terminalEvidence.stale_deployment_profile_artifact_refused_before_service_proof,
          profile_recognition_mismatch_refused_before_service_proof:
            terminalEvidence.profile_recognition_mismatch_refused_before_service_proof,
          latest_profile_selection_refused_before_service_proof:
            terminalEvidence.latest_profile_selection_refused_before_service_proof,
          request_stream_authority_material_refused_before_service_proof:
            terminalEvidence.request_stream_authority_material_refused_before_service_proof,
          current_machine_governance: terminalEvidence.current_machine_governance,
          production_downstream_recognition:
            terminalEvidence.production_downstream_recognition,
          production_authority: terminalEvidence.production_authority,
          enterprise_readiness: terminalEvidence.enterprise_readiness,
          external_attestation: terminalEvidence.external_attestation,
          sovereign_recognition: terminalEvidence.sovereign_recognition,
          unrouted_surface_coverage: terminalEvidence.unrouted_surface_coverage,
        }
      : {}),
    ...overrides,
  };
}

function reportContractProofSmokeTrustedRegistryRecognitionRefusals(
  terminalEvidence,
  overrides = {},
) {
  return {
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count:
      terminalEvidence.trusted_issuer_registry_recognition_refusal_case_count,
    installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count:
      terminalEvidence
        .artifact_verification_trusted_issuer_registry_recognition_refusal_case_count,
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused:
      terminalEvidence.trusted_issuer_registry_recognition_refusals_all_refused,
    installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused:
      terminalEvidence
        .artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused,
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids:
      clone(terminalEvidence.trusted_issuer_registry_recognition_refusal_case_ids),
    installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids:
      clone(
        terminalEvidence
          .artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids,
      ),
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes:
      clone(
        terminalEvidence.trusted_issuer_registry_recognition_refusal_reason_codes,
      ),
    installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes:
      clone(
        terminalEvidence
          .artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes,
      ),
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256:
      terminalEvidence.trusted_issuer_registry_recognition_refusals_sha256,
    installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256:
      terminalEvidence
        .artifact_verification_trusted_issuer_registry_recognition_refusals_sha256,
    ...overrides,
  };
}

function reportContractNorthStarTrustedRegistryRecognitionRefusals(
  terminalEvidence,
  overrides = {},
) {
  return {
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved:
      terminalEvidence.all_trusted_issuer_registry_recognition_refusals_preserved,
    ...reportContractProofSmokeTrustedRegistryRecognitionRefusals(
      terminalEvidence,
    ),
    ...overrides,
  };
}

function reportContractNorthStarObservedTrustedRegistryRecognitionRefusals(
  terminalEvidence,
  overrides = {},
) {
  return {
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved:
      terminalEvidence.all_trusted_issuer_registry_recognition_refusals_preserved,
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids:
      clone(terminalEvidence.trusted_issuer_registry_recognition_refusal_case_ids),
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes:
      clone(
        terminalEvidence.trusted_issuer_registry_recognition_refusal_reason_codes,
      ),
    ...overrides,
  };
}

function terminalChainRefusalEvidence(overrides = {}) {
  const {
    nested_artifact_tamper_refusals: nestedTamperOverrides = {},
    nested_artifact_binding: nestedBindingOverrides = {},
    ...rest
  } = overrides;
  return {
    recognition_refusal_group_case_ids_minimum_target: 'v3.4.24',
    recognition_refusal_group_case_ids_required: true,
    recognition_refusal_group_case_ids: clone(expectedRecognitionRefusalGroupCaseIds),
    all_recognition_refusal_group_case_ids_preserved: true,
    nested_artifact_tamper_refusals_minimum_target: 'v3.4.28',
    nested_artifact_tamper_refusals_required: true,
    nested_artifact_tamper_refusals: terminalChainNestedArtifactTamperRefusals(
      nestedTamperOverrides,
    ),
    nested_artifact_binding_minimum_target: 'v3.4.30',
    nested_artifact_binding_required: true,
    nested_artifact_binding: terminalChainNestedArtifactBinding(
      nestedBindingOverrides,
    ),
    ...rest,
  };
}

function privateVerifierResultSamplePointer(overrides = {}) {
  return {
    enabled: true,
    evidence_model: 'generated-sample-fixture',
    minimum_target: 'v3.3.104',
    envelope_path: 'ZLAR/zlar-private-verifier-result-v1.json',
    verification_path: 'ZLAR/zlar-private-verifier-result-verification-v1.json',
    result_file: 'DRY-RUN-RESULT.md',
    result_section: 'Private Verifier Result Intake',
    hash_record_location: 'DRY-RUN-RESULT.md#private-verifier-result-intake',
    included_in_core_artifact_hashes: false,
    circular_hash_avoided: true,
    verification_result_section: 'Private Result Verification Evidence',
    verification_result_minimum_target: 'v3.4.34',
    creates_public_external_attestation: false,
    proves_non_operator_review: false,
    ...overrides,
  };
}

function completeReleaseForwardManifest(report, manifest) {
  const completed = clone(manifest);
  completed.target = {
    release_tag: report.target.release_tag,
    expected_commit_sha: report.target.expected_commit_sha,
    observed_commit_sha: report.target.commit_sha,
    repo_url: '<local-path>',
    source: 'fresh-clone',
    moving_target_selected: false,
    ...(completed.target || {}),
  };
  completed.artifact_hashes = report.evidence.artifact_hashes
    .filter((entry) => entry.path.startsWith('ZLAR/'))
    .map((entry) => ({
      path: entry.path,
      sha256: defaultArtifactSha(entry.path),
    }));
  const sourceArtifacts = {
    proof_smoke_sample_verification_path:
      'ZLAR/zlar-proof-smoke-sample-verification.json',
    proof_smoke_sample_verification_sha256: defaultArtifactSha(
      'ZLAR/zlar-proof-smoke-sample-verification.json',
    ),
    north_star_readiness_path: 'ZLAR/zlar-north-star-readiness-v1.json',
    north_star_readiness_sha256: defaultArtifactSha(
      'ZLAR/zlar-north-star-readiness-v1.json',
    ),
    product_proof_path_path: 'ZLAR/zlar-product-proof-path-v1.json',
    product_proof_path_sha256: defaultArtifactSha(
      'ZLAR/zlar-product-proof-path-v1.json',
    ),
    terminal_chain_refusal_evidence_source:
      'DRY-RUN-MANIFEST.json#terminal_chain_refusal_evidence',
    terminal_chain_refusal_evidence_included_in_same_manifest: true,
    ...(completed.release_forward_report_contract?.source_artifacts || {}),
  };
  completed.release_forward_report_contract = {
    ...(completed.release_forward_report_contract || {}),
    source_artifacts: sourceArtifacts,
    claim_boundary: releaseForwardReportContractClaimBoundary(
      completed.release_forward_report_contract?.claim_boundary || {},
    ),
  };
  completed.terminal_chain_refusal_evidence = terminalChainRefusalEvidence({
    ...terminalChainTrustedRegistryRecognitionRefusals(),
    ...(releaseTagAtLeast(report.target.release_tag, 'v3.4.50')
      ? terminalChainDeploymentProfileAuthorityRefusalMirror()
      : {}),
    ...(completed.terminal_chain_refusal_evidence || {}),
  });
  completed.release_forward_report_contract.terminal_chain_refusal_evidence =
    releaseForwardReportContractTerminalChainRefusalEvidence(
      completed.terminal_chain_refusal_evidence,
      completed.release_forward_report_contract
        .terminal_chain_refusal_evidence || {},
    );
  completed.release_forward_report_contract.proof_smoke = {
    ...(completed.release_forward_report_contract.proof_smoke || {}),
    counts: {
      ...reportContractProofSmokeRecognitionRefusalGroupCaseIds(),
      ...reportContractProofSmokeTrustedRegistryRecognitionRefusals(
        completed.terminal_chain_refusal_evidence,
      ),
      ...(completed.release_forward_report_contract.proof_smoke?.counts || {}),
    },
  };
  completed.release_forward_report_contract.north_star = {
    ...(completed.release_forward_report_contract.north_star || {}),
    counts: {
      ...reportContractNorthStarRecognitionRefusalGroupCaseIds(),
      ...reportContractNorthStarTrustedRegistryRecognitionRefusals(
        completed.terminal_chain_refusal_evidence,
      ),
      ...(completed.release_forward_report_contract.north_star?.counts || {}),
    },
    puzzle_3_observed: {
      ...reportContractNorthStarObservedTrustedRegistryRecognitionRefusals(
        completed.terminal_chain_refusal_evidence,
      ),
      ...(completed.release_forward_report_contract.north_star
        ?.puzzle_3_observed || {}),
    },
    puzzle_5_observed: {
      ...reportContractNorthStarObservedTrustedRegistryRecognitionRefusals(
        completed.terminal_chain_refusal_evidence,
      ),
      ...(completed.release_forward_report_contract.north_star
        ?.puzzle_5_observed || {}),
    },
  };
  if (completed.release_forward_report_contract.product_proof_path) {
    completed.release_forward_report_contract.product_proof_path = {
      ...completed.release_forward_report_contract.product_proof_path,
      claim_boundary: releaseForwardProductProofPathClaimBoundary(
        completed.release_forward_report_contract.product_proof_path
          ?.claim_boundary || {},
      ),
      simulated_human_authorization: productProofPathSimulatedHumanAuthorization(
        completed.release_forward_report_contract.product_proof_path
          ?.simulated_human_authorization || {},
      ),
      receipt_verifier_boundary: productProofPathReceiptVerifierBoundary(
        completed.release_forward_report_contract.product_proof_path
          ?.receipt_verifier_boundary || {},
      ),
    };
  }
  completed.private_verifier_result_sample = privateVerifierResultSamplePointer(
    completed.private_verifier_result_sample || {},
  );
  return completed;
}

function rewriteManifestArtifact(evidenceFixture, mutator) {
  const manifestPath = artifactFilePath(evidenceFixture.evidenceDir, 'DRY-RUN-MANIFEST.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  mutator(manifest);
  const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
  writeFileSync(manifestPath, manifestText);
  const manifestHash = sha256Text(manifestText);
  const manifestEntry = evidenceFixture.report.evidence.artifact_hashes.find(
    (entry) => entry.path === 'DRY-RUN-MANIFEST.json',
  );
  manifestEntry.sha256 = manifestHash;
}

function rewriteEvidenceText(evidenceFixture, artifactPath, text) {
  writeFileSync(artifactFilePath(evidenceFixture.evidenceDir, artifactPath), text);
  const entry = evidenceFixture.report.evidence.artifact_hashes.find(
    (item) => item.path === artifactPath,
  );
  entry.sha256 = sha256Text(text);
  if (artifactPath === 'SHA256SUMS') {
    evidenceFixture.report.evidence.received_bundle_sha256 = entry.sha256;
  }
}

function readEvidenceText(evidenceFixture, artifactPath) {
  return readFileSync(artifactFilePath(evidenceFixture.evidenceDir, artifactPath), 'utf8');
}

function refreshRunSha256Sums(evidenceFixture) {
  const text = [
    'transcript.txt',
    'COMMANDS.txt',
    'ASSERTIONS.txt',
    'target-head.txt',
    'target-status.txt',
    'SHA256SUMS',
  ]
    .map((path) => {
      const hash = sha256Text(readEvidenceText(evidenceFixture, path));
      return `${hash}  ${path}`;
    })
    .join('\n')
    .concat('\n');
  rewriteEvidenceText(evidenceFixture, 'RUN-SHA256SUMS', text);
}

function deploymentProfileAuthorityBridge(overrides = {}) {
  return {
    proof_type: 'zlar-protected-records-one-terminal-deployment-profile-proof-v1',
    evidence_model: 'local-fixture-one-terminal-deployment-profile-authority-bridge',
    live_probing: false,
    deployment_profile_id: 'protected-records-one-terminal-deployment-profile-fixture',
    deployment_profile_sha256: 'd'.repeat(64),
    runtime_profile_sha256: 'e'.repeat(64),
    deployment_profile_artifact_authoritative: true,
    selected_by_explicit_id_and_sha: true,
    selects_latest_profile: false,
    preflight_artifact_verified: true,
    recognized_receipt_mutates_once: true,
    recognized_state_entry_count_delta: 1,
    required_refusal_case_count: 18,
    observed_refusal_case_count: 18,
    all_required_refusals_before_mutation: true,
    agent_supplied_authority_refused_before_mutation: true,
    direct_api_refused_before_mutation: true,
    downstream_refusal_proven: true,
    request_stream_authority_material_accepted: false,
    current_machine_governance: false,
    production_downstream_recognition: false,
    production_authority: false,
    enterprise_readiness: false,
    external_attestation: false,
    sovereign_recognition: false,
    unrouted_surface_coverage: false,
    ...overrides,
  };
}

function deploymentProfileAuthorityBridgeNorthStar(overrides = {}) {
  return {
    deployment_profile_authority_bridge_required: true,
    deployment_profile_authority_bridge_preserved: true,
    deployment_profile_authority_bridge_observed: true,
    deployment_profile_authority_bridge_proof_type:
      'zlar-protected-records-one-terminal-deployment-profile-proof-v1',
    deployment_profile_authority_bridge_refusal_count: 18,
    deployment_profile_authority_bridge_current_machine_governance: false,
    deployment_profile_authority_bridge_production_authority: false,
    ...overrides,
  };
}

function deploymentProfileAuthorityBridgeV349(overrides = {}) {
  return deploymentProfileAuthorityBridge({
    deployment_profile_authority_refusal_case_count:
      expectedDeploymentProfileAuthorityRefusalCaseIds.length,
    deployment_profile_authority_refusal_case_ids:
      clone(expectedDeploymentProfileAuthorityRefusalCaseIds),
    deployment_profile_authority_refusals_before_service_proof: true,
    deployment_profile_authority_refusals_before_mutation: true,
    deployment_profile_authority_refusal_service_proof_started: false,
    stale_deployment_profile_artifact_refused_before_service_proof: true,
    profile_recognition_mismatch_refused_before_service_proof: true,
    latest_profile_selection_refused_before_service_proof: true,
    request_stream_authority_material_refused_before_service_proof: true,
    ...overrides,
  });
}

function deploymentProfileAuthorityBridgeNorthStarV349(overrides = {}) {
  return deploymentProfileAuthorityBridgeNorthStar({
    deployment_profile_authority_refusals_required: true,
    deployment_profile_authority_refusals_preserved: true,
    deployment_profile_authority_refusal_case_count:
      expectedDeploymentProfileAuthorityRefusalCaseIds.length,
    deployment_profile_authority_refusal_case_ids:
      clone(expectedDeploymentProfileAuthorityRefusalCaseIds),
    deployment_profile_authority_refusals_before_service_proof: true,
    deployment_profile_authority_refusals_before_mutation: true,
    deployment_profile_authority_refusal_service_proof_started: false,
    stale_deployment_profile_artifact_refused_before_service_proof: true,
    profile_recognition_mismatch_refused_before_service_proof: true,
    latest_profile_selection_refused_before_service_proof: true,
    request_stream_authority_material_refused_before_service_proof: true,
    ...overrides,
  });
}

function terminalChainTrustedRegistryVerdict(overrides = {}) {
  return {
    trusted_issuer_registry_recognition_verdict: 'RECOGNIZED',
    trusted_issuer_registry_recognition_recognized: true,
    trusted_issuer_registry_recognition_decision: 'accept',
    trusted_issuer_registry_recognition_reason_code: 'recognized',
    trusted_issuer_registry_recognition_issuer_status: 'active',
    trusted_issuer_registry_recognition_signature_valid: true,
    trusted_issuer_registry_recognition_registry_fixture_validated: true,
    trusted_issuer_registry_recognition_registry_fixture_evaluated: true,
    trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated: true,
    trusted_issuer_registry_recognition_registry_evaluation_result_type:
      'downstream-recognition-rule-v1',
    trusted_issuer_registry_recognition_registry_trusted_issuer_count: 1,
    trusted_issuer_registry_recognition_required_audit_event_id_bound: true,
    trusted_issuer_registry_recognition_required_detail_hash_bound: true,
    trusted_issuer_registry_recognition_registry_fixture_contract_sha256:
      'a'.repeat(64),
    trusted_issuer_registry_recognition_receipt_payload_contract_sha256:
      'b'.repeat(64),
    ...overrides,
  };
}

function terminalChainTrustedRegistryVerdictNorthStar(overrides = {}) {
  const boundary = terminalChainTrustedRegistryVerdict();
  return {
    terminal_chain_trusted_issuer_registry_recognition_verdict:
      boundary.trusted_issuer_registry_recognition_verdict,
    terminal_chain_trusted_issuer_registry_recognition_recognized:
      boundary.trusted_issuer_registry_recognition_recognized,
    terminal_chain_trusted_issuer_registry_recognition_decision:
      boundary.trusted_issuer_registry_recognition_decision,
    terminal_chain_trusted_issuer_registry_recognition_reason_code:
      boundary.trusted_issuer_registry_recognition_reason_code,
    terminal_chain_trusted_issuer_registry_recognition_issuer_status:
      boundary.trusted_issuer_registry_recognition_issuer_status,
    terminal_chain_trusted_issuer_registry_recognition_signature_valid:
      boundary.trusted_issuer_registry_recognition_signature_valid,
    terminal_chain_trusted_issuer_registry_recognition_registry_fixture_validated:
      boundary.trusted_issuer_registry_recognition_registry_fixture_validated,
    terminal_chain_trusted_issuer_registry_recognition_registry_fixture_evaluated:
      boundary.trusted_issuer_registry_recognition_registry_fixture_evaluated,
    terminal_chain_trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated:
      boundary.trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated,
    terminal_chain_trusted_issuer_registry_recognition_registry_evaluation_result_type:
      boundary.trusted_issuer_registry_recognition_registry_evaluation_result_type,
    terminal_chain_trusted_issuer_registry_recognition_registry_trusted_issuer_count:
      boundary.trusted_issuer_registry_recognition_registry_trusted_issuer_count,
    terminal_chain_trusted_issuer_registry_recognition_required_audit_event_id_bound:
      boundary.trusted_issuer_registry_recognition_required_audit_event_id_bound,
    terminal_chain_trusted_issuer_registry_recognition_required_detail_hash_bound:
      boundary.trusted_issuer_registry_recognition_required_detail_hash_bound,
    terminal_chain_trusted_issuer_registry_recognition_registry_fixture_contract_sha256:
      boundary.trusted_issuer_registry_recognition_registry_fixture_contract_sha256,
    terminal_chain_trusted_issuer_registry_recognition_receipt_payload_contract_sha256:
      boundary.trusted_issuer_registry_recognition_receipt_payload_contract_sha256,
    ...overrides,
  };
}

function downstreamRefusalBoundary(overrides = {}) {
  return {
    provided: true,
    recognized_boarded: true,
    recognized_marker_count_delta: 1,
    final_marker_count: 1,
    refusal_case_count: expectedDownstreamRefusalReasons.length,
    all_refusals_unboarded: true,
    all_refusal_marker_count_deltas_zero: true,
    refusal_reasons: clone(expectedDownstreamRefusalReasons),
    ...overrides,
  };
}

function recognizedReceiptPathMirror(overrides = {}) {
  const sourceBinding = 'c'.repeat(64);
  return {
    trusted_issuer_registry_recognition_binding_sha256: sourceBinding,
    recognized_receipt_path_evidence_sha256: 'f'.repeat(64),
    recognized_receipt_path_evidence_artifact_verification_sha256: 'f'.repeat(64),
    recognized_receipt_path_evidence_sha256_matches_artifact_verification: true,
    recognized_receipt_path_evidence_bound_to_artifact_body: true,
    recognized_receipt_path_evidence_source_binding_sha256: sourceBinding,
    recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding: true,
    recognized_receipt_path_evidence_verdict: 'RECOGNIZED',
    recognized_receipt_path_evidence_recognized: true,
    recognized_receipt_path_evidence_receipt_envelope_included: false,
    recognized_receipt_path_evidence_registry_public_key_material_included: false,
    recognized_receipt_path_evidence_artifact_crypto_reproducible: false,
    recognized_receipt_path_evidence_live_state_proven: false,
    recognized_receipt_path_evidence_live_issuer_status_proven: false,
    recognized_receipt_path_evidence_key_custody_proven: false,
    recognized_receipt_path_evidence_revocation_truth_proven: false,
    recognized_receipt_path_evidence_production_downstream_recognition_proven: false,
    recognized_receipt_path_evidence_public_external_attestation: false,
    recognized_receipt_path_evidence_sovereign_recognition: false,
    recognized_receipt_path_evidence_current_machine_governance_proven: false,
    ...overrides,
  };
}

function recognizedReceiptPathMirrorNorthStar(boundary = recognizedReceiptPathMirror(), overrides = {}) {
  return {
    ...Object.fromEntries(
      expectedRecognizedReceiptPathMirrorKeys.map((key) => [
        `terminal_chain_${key}`,
        boundary[key],
      ]),
    ),
    ...overrides,
  };
}

function releaseForwardManifestContractV348({
  terminalBoundary = {},
  deploymentBridge = {},
  northStar = {},
} = {}) {
  const manifest = releaseForwardManifestContract({
    terminalBoundary,
    northStar: {
      ...deploymentProfileAuthorityBridgeNorthStar(),
      ...northStar,
    },
  });
  if (deploymentBridge !== null) {
    manifest.release_forward_report_contract.product_proof_path
      .deployment_profile_authority_bridge =
        deploymentProfileAuthorityBridge(deploymentBridge);
  }
  return manifest;
}

function releaseForwardManifestContractV349({
  terminalBoundary = {},
  deploymentBridge = {},
  northStar = {},
} = {}) {
  const manifest = releaseForwardManifestContract({
    terminalBoundary,
    northStar: {
      ...deploymentProfileAuthorityBridgeNorthStarV349(),
      ...northStar,
    },
  });
  if (deploymentBridge !== null) {
    manifest.release_forward_report_contract.product_proof_path
      .deployment_profile_authority_bridge =
        deploymentProfileAuthorityBridgeV349(deploymentBridge);
  }
  return manifest;
}

function releaseForwardManifestContractV351({
  terminalBoundary = {},
  deploymentBridge = {},
  downstreamBoundary = {},
  northStar = {},
} = {}) {
  const manifest = releaseForwardManifestContractV349({
    terminalBoundary: {
      ...terminalChainTrustedRegistryVerdict(),
      ...terminalBoundary,
    },
    deploymentBridge,
    northStar: {
      ...terminalChainTrustedRegistryVerdictNorthStar(),
      downstream_refusal_boundary: downstreamRefusalBoundary(),
      ...northStar,
    },
  });
  manifest.release_forward_report_contract.product_proof_path
    .downstream_refusal_boundary = downstreamRefusalBoundary(downstreamBoundary);
  return manifest;
}

function releaseForwardManifestContractV352({
  terminalBoundary = {},
  deploymentBridge = {},
  downstreamBoundary = {},
  receiptPathMirror = {},
  northStar = {},
} = {}) {
  const receiptPathBoundary = recognizedReceiptPathMirror(receiptPathMirror);
  return releaseForwardManifestContractV351({
    terminalBoundary: {
      ...receiptPathBoundary,
      ...terminalBoundary,
    },
    deploymentBridge,
    downstreamBoundary,
    northStar: {
      ...recognizedReceiptPathMirrorNorthStar(receiptPathBoundary),
      ...northStar,
    },
  });
}

function makeV346EvidenceFixture(manifest = releaseForwardManifestContract()) {
  const report = clone(fixture);
  report.target.release_tag = 'v3.4.46';
  report.target.expected_commit_sha = '6'.repeat(40);
  report.target.commit_sha = '6'.repeat(40);
  addArtifactHashes(report, v346ArtifactPaths);
  const completedManifest = completeReleaseForwardManifest(report, manifest);
  const evidenceDir = writeEvidenceFiles(report, {
    'DRY-RUN-MANIFEST.json': `${JSON.stringify(completedManifest, null, 2)}\n`,
  });
  return { report, evidenceDir };
}

function makeV348EvidenceFixture(manifest = releaseForwardManifestContractV348()) {
  const report = clone(fixture);
  report.target.release_tag = 'v3.4.48';
  report.target.expected_commit_sha = '8'.repeat(40);
  report.target.commit_sha = '8'.repeat(40);
  addArtifactHashes(report, v346ArtifactPaths);
  const completedManifest = completeReleaseForwardManifest(report, manifest);
  const evidenceDir = writeEvidenceFiles(report, {
    'DRY-RUN-MANIFEST.json': `${JSON.stringify(completedManifest, null, 2)}\n`,
  });
  return { report, evidenceDir };
}

function makeV349EvidenceFixture(manifest = releaseForwardManifestContractV349()) {
  const report = clone(fixture);
  report.target.release_tag = 'v3.4.49';
  report.target.expected_commit_sha = '9'.repeat(40);
  report.target.commit_sha = '9'.repeat(40);
  addArtifactHashes(report, v346ArtifactPaths);
  const completedManifest = completeReleaseForwardManifest(report, manifest);
  const evidenceDir = writeEvidenceFiles(report, {
    'DRY-RUN-MANIFEST.json': `${JSON.stringify(completedManifest, null, 2)}\n`,
  });
  return { report, evidenceDir };
}

function makeV350EvidenceFixture(manifest = releaseForwardManifestContractV349()) {
  const report = clone(fixture);
  report.target.release_tag = 'v3.4.50';
  report.target.expected_commit_sha = 'b'.repeat(40);
  report.target.commit_sha = 'b'.repeat(40);
  addArtifactHashes(report, v346ArtifactPaths);
  const completedManifest = completeReleaseForwardManifest(report, manifest);
  const evidenceDir = writeEvidenceFiles(report, {
    'DRY-RUN-MANIFEST.json': `${JSON.stringify(completedManifest, null, 2)}\n`,
  });
  return { report, evidenceDir };
}

function makeV351EvidenceFixture(manifest = releaseForwardManifestContractV351()) {
  const report = clone(fixture);
  report.target.release_tag = 'v3.4.51';
  report.target.expected_commit_sha = 'a'.repeat(40);
  report.target.commit_sha = 'a'.repeat(40);
  addArtifactHashes(report, v346ArtifactPaths);
  const completedManifest = completeReleaseForwardManifest(report, manifest);
  const evidenceDir = writeEvidenceFiles(report, {
    'DRY-RUN-MANIFEST.json': `${JSON.stringify(completedManifest, null, 2)}\n`,
  });
  return { report, evidenceDir };
}

function makeV352EvidenceFixture(manifest = releaseForwardManifestContractV352()) {
  const report = clone(fixture);
  report.target.release_tag = 'v3.4.52';
  report.target.expected_commit_sha = 'c'.repeat(40);
  report.target.commit_sha = 'c'.repeat(40);
  addArtifactHashes(report, v346ArtifactPaths);
  const completedManifest = completeReleaseForwardManifest(report, manifest);
  const evidenceDir = writeEvidenceFiles(report, {
    'DRY-RUN-MANIFEST.json': `${JSON.stringify(completedManifest, null, 2)}\n`,
  });
  return { report, evidenceDir };
}

function runZlar(args, input) {
  return spawnSync(join(process.cwd(), 'bin', 'zlar'), args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    input,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

const fixturePath = join(process.cwd(), 'tests/fixtures/private-verifier-result-v1.json');
const fixtureText = readFileSync(fixturePath, 'utf8');
const fixture = JSON.parse(fixtureText);
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY|--latest/i;

console.log('\n-- fixture contract --');
assert('fixture passes validation', assertPrivateVerifierResult(fixture));
assertEqual('fixture report type', PRIVATE_VERIFIER_RESULT_TYPE, fixture.report_type);
assertEqual('fixture intake class is sample', 'sample-fixture', fixture.intake_class);
assertEqual('fixture target release', 'v3.3.103', fixture.target.release_tag);
assertEqual('fixture public attestation false', false, fixture.claim_boundary.public_external_attestation);
assertEqual('fixture attribution false', false, fixture.claim_boundary.public_attribution);
assertEqual('fixture non-operator publicly claimed false', false, fixture.claim_boundary.non_operator_review_publicly_claimed);
assertEqual('fixture private by default true', true, fixture.privacy.private_by_default);
assertEqual('fixture sample not real non-operator', false, fixture.review_result.completed_by_non_operator);
assert('fixture has north-star artifact hash', fixture.evidence.artifact_hashes.some((entry) => entry.path === 'ZLAR/zlar-north-star-readiness-v1.json'));
assert('fixture has verifier reproducibility artifact hash', fixture.evidence.artifact_hashes.some((entry) => entry.path === 'ZLAR/zlar-verifier-kit-reproducibility-v1.json'));
assert('fixture has issuer status proof artifact hash', fixture.evidence.artifact_hashes.some((entry) => entry.path === 'ZLAR/zlar-issuer-status-proof.json'));
assert('fixture has verifier kit issuer status artifact hash', fixture.evidence.artifact_hashes.some((entry) => entry.path === 'ZLAR/zlar-verifier-kit-issuer-status-fixture.json'));

const verification = buildPrivateVerifierResultVerification(fixture);
assertEqual('verification type', 'zlar-private-verifier-result-verification-v1', verification.verification_type);
assertEqual('verification result true', true, verification.verified);
assertEqual('verification direct result sha not provided', null, verification.result_sha256);
assertEqual(
  'verification artifact set sha',
  artifactSetSha256(fixture.evidence.artifact_hashes),
  verification.artifact_set_sha256
);
assertEqual('verification artifact count', fixture.evidence.artifact_hashes.length, verification.artifact_hash_count);
assertEqual('verification current-machine false', false, verification.current_machine_governance);
assertEqual('verification evidence-dir hash check not run', false, verification.evidence_dir_hash_verification.hashes_recomputed);
assertEqual(
  'verification envelope-only command posture',
  'private-result-envelope-only',
  verification.required_identity.command_posture
);
assertEqual('verification no required result sha', false, verification.required_identity.result_sha256_required);
assertEqual('verification no required target', false, verification.required_identity.target_required);
assertEqual('verification no required recompute', false, verification.required_identity.recomputed_evidence_required);

const requiredEnvelopeVerification = buildPrivateVerifierResultVerification(fixture, {
  resultText: fixtureText,
  requireResultSha: sha256Text(fixtureText),
  requireTarget: `${fixture.target.release_tag}@${fixture.target.commit_sha}`,
  requireBundleSha: fixture.evidence.received_bundle_sha256,
  requireArtifactSetSha: artifactSetSha256(fixture.evidence.artifact_hashes),
});
assertEqual('required envelope result sha exposed', sha256Text(fixtureText), requiredEnvelopeVerification.result_sha256);
assertEqual('required envelope result sha matched', true, requiredEnvelopeVerification.required_identity.result_sha256_matched);
assertEqual('required envelope target matched', true, requiredEnvelopeVerification.required_identity.target_matched);
assertEqual('required envelope bundle matched', true, requiredEnvelopeVerification.required_identity.bundle_sha256_matched);
assertEqual(
  'required envelope artifact set matched',
  true,
  requiredEnvelopeVerification.required_identity.artifact_set_sha256_matched
);
assertEqual(
  'required envelope recomputed evidence not required',
  false,
  requiredEnvelopeVerification.required_identity.recomputed_evidence_required
);

assertThrows(
  'required result sha mismatch fails',
  () => buildPrivateVerifierResultVerification(fixture, {
    resultText: fixtureText,
    requireResultSha: 'f'.repeat(64),
  }),
  'required result sha mismatch'
);
assertThrows(
  'required target mismatch fails',
  () => buildPrivateVerifierResultVerification(fixture, {
    requireTarget: `${fixture.target.release_tag}@${'f'.repeat(40)}`,
  }),
  'required target mismatch'
);
assertThrows(
  'required target malformed fails',
  () => buildPrivateVerifierResultVerification(fixture, {
    requireTarget: 'latest',
  }),
  '--require-target must be <release>@<commit>'
);
assertThrows(
  'required bundle mismatch fails',
  () => buildPrivateVerifierResultVerification(fixture, {
    requireBundleSha: 'f'.repeat(64),
  }),
  'required bundle sha mismatch'
);
assertThrows(
  'required artifact set mismatch fails',
  () => buildPrivateVerifierResultVerification(fixture, {
    requireArtifactSetSha: 'f'.repeat(64),
  }),
  'required artifact-set sha mismatch'
);
assertThrows(
  'required recomputed evidence without evidence-dir fails',
  () => buildPrivateVerifierResultVerification(fixture, {
    requireRecomputedEvidence: true,
  }),
  'required recomputed evidence was not verified'
);
const summaryOnlyFixture = clone(fixture);
summaryOnlyFixture.evidence.artifact_hashes = [];
assertThrows(
  'summary-only private result fails',
  () => buildPrivateVerifierResultVerification(summaryOnlyFixture, {
    requireArtifactSetSha: artifactSetSha256(fixture.evidence.artifact_hashes),
  }),
  'evidence.artifact_hashes must be a non-empty array'
);

console.log('\n-- evidence directory hash verification --');
const evidenceFixture = makeEvidenceFixture();
const evidenceVerification = buildPrivateVerifierResultVerification(evidenceFixture.report, {
  evidenceDir: evidenceFixture.evidenceDir,
});
assertEqual('evidence-dir verification enabled', true, evidenceVerification.evidence_dir_hash_verification.enabled);
assertEqual('evidence-dir hashes recomputed', true, evidenceVerification.evidence_dir_hash_verification.hashes_recomputed);
assertEqual('evidence-dir verification true', true, evidenceVerification.evidence_dir_hash_verification.verified);
const requiredEvidenceVerification = buildPrivateVerifierResultVerification(evidenceFixture.report, {
  evidenceDir: evidenceFixture.evidenceDir,
  resultText: JSON.stringify(evidenceFixture.report),
  requireResultSha: sha256Text(JSON.stringify(evidenceFixture.report)),
  requireTarget: `${evidenceFixture.report.target.release_tag}@${evidenceFixture.report.target.commit_sha}`,
  requireBundleSha: evidenceFixture.report.evidence.received_bundle_sha256,
  requireArtifactSetSha: artifactSetSha256(evidenceFixture.report.evidence.artifact_hashes),
  requireRecomputedEvidence: true,
});
assertEqual(
  'required evidence command posture',
  'private-result-with-required-recomputed-evidence',
  requiredEvidenceVerification.required_identity.command_posture
);
assertEqual(
  'required evidence recompute matched',
  true,
  requiredEvidenceVerification.required_identity.recomputed_evidence_matched
);
assertEqual(
  'evidence-dir artifact count',
  evidenceFixture.report.evidence.artifact_hashes.length,
  evidenceVerification.evidence_dir_hash_verification.artifact_hash_count
);
assertEqual(
  'evidence-dir checked path count',
  evidenceFixture.report.evidence.artifact_hashes.length,
  evidenceVerification.evidence_dir_hash_verification.checked_paths.length
);
assertEqual(
  'pre-v3.4.46 evidence-dir contract not required',
  false,
  evidenceVerification.evidence_dir_contract_verification.required_for_target
);
assertEqual(
  'pre-v3.4.46 evidence-dir contract not required result',
  null,
  evidenceVerification.evidence_dir_contract_verification.verified
);

const contentContractFixture = makeV346EvidenceFixture();
const contentContractVerification = buildPrivateVerifierResultVerification(contentContractFixture.report, {
  evidenceDir: contentContractFixture.evidenceDir,
});
assertEqual(
  'v3.4.46 evidence-dir contract required',
  true,
  contentContractVerification.evidence_dir_contract_verification.required_for_target
);
assertEqual(
  'v3.4.46 evidence-dir contract verified',
  true,
  contentContractVerification.evidence_dir_contract_verification.verified
);
assertEqual(
  'v3.4.46 private intake terminal group count',
  3,
  contentContractVerification.evidence_dir_contract_verification
    .product_proof_path_terminal_chain_recognition_refusal_group_count
);
assertEqual(
  'v3.4.46 private intake terminal group case count',
  18,
  contentContractVerification.evidence_dir_contract_verification
    .product_proof_path_terminal_chain_recognition_refusal_group_case_count
);
assertEqual(
  'v3.4.46 private intake terminal group IDs preserved',
  true,
  contentContractVerification.evidence_dir_contract_verification
    .product_proof_path_terminal_chain_recognition_refusal_group_case_ids_preserved
);
assertEqual(
  'v3.4.46 private intake north star group IDs preserved',
  true,
  contentContractVerification.evidence_dir_contract_verification
    .north_star_terminal_chain_recognition_refusal_group_case_ids_preserved
);
assertEqual(
  'v3.4.46 private intake deployment bridge not required',
  false,
  contentContractVerification.evidence_dir_contract_verification
    .deployment_profile_authority_bridge_required_for_target
);
assertEqual(
  'v3.4.46 private intake nested tamper required',
  true,
  contentContractVerification.evidence_dir_contract_verification
    .terminal_chain_nested_artifact_tamper_refusals_required_for_target
);
assertEqual(
  'v3.4.46 private intake nested tamper preserved',
  true,
  contentContractVerification.evidence_dir_contract_verification
    .terminal_chain_nested_artifact_tamper_refusals_preserved
);
assertEqual(
  'v3.4.46 private intake nested binding required',
  true,
  contentContractVerification.evidence_dir_contract_verification
    .terminal_chain_nested_artifact_binding_required_for_target
);
assertEqual(
  'v3.4.46 private intake nested binding preserved',
  true,
  contentContractVerification.evidence_dir_contract_verification
    .terminal_chain_nested_artifact_binding_preserved
);

const driftedContentContractFixture = makeV346EvidenceFixture(
  releaseForwardManifestContract({
    terminalBoundary: {
      recognition_refusal_group_case_ids: {
        ...clone(expectedRecognitionRefusalGroupCaseIds),
        no_usable_recognized_receipt_authority: [
          'missing_receipt_refused_before_runtime_mutation',
        ],
      },
    },
  })
);
assertThrows(
  'v3.4.46 evidence-dir contract drift fails despite matching hashes',
  () =>
    buildPrivateVerifierResultVerification(driftedContentContractFixture.report, {
      evidenceDir: driftedContentContractFixture.evidenceDir,
    }),
  'terminal chain recognition refusal group case IDs drifted'
);

const extraTerminalGroupContentContractFixture = makeV346EvidenceFixture(
  releaseForwardManifestContract({
    terminalBoundary: {
      recognition_refusal_group_case_ids: {
        ...clone(expectedRecognitionRefusalGroupCaseIds),
        summary_or_extra_group: ['collapsed_refusal_summary'],
      },
    },
  })
);
assertThrows(
  'v3.4.46 terminal group case ID extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      extraTerminalGroupContentContractFixture.report,
      {
        evidenceDir: extraTerminalGroupContentContractFixture.evidenceDir,
      }
    ),
  'terminal chain recognition refusal group case IDs drifted'
);

const missingTerminalGroupContentContractManifest = releaseForwardManifestContract();
delete missingTerminalGroupContentContractManifest.release_forward_report_contract
  .product_proof_path.terminal_chain_boundary.recognition_refusal_group_case_ids
  .recognized_receipt_scope_mismatch;
const missingTerminalGroupContentContractFixture = makeV346EvidenceFixture(
  missingTerminalGroupContentContractManifest
);
assertThrows(
  'v3.4.46 terminal group case ID missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      missingTerminalGroupContentContractFixture.report,
      {
        evidenceDir: missingTerminalGroupContentContractFixture.evidenceDir,
      }
    ),
  'terminal chain recognition refusal group case IDs drifted'
);

const renamedNorthStarGroupContentContractManifest = releaseForwardManifestContract();
const renamedNorthStarGroupCaseIds =
  renamedNorthStarGroupContentContractManifest.release_forward_report_contract
    .product_proof_path.north_star.terminal_chain_recognition_refusal_group_case_ids;
renamedNorthStarGroupCaseIds.recognized_receipt_scope_mismatches =
  renamedNorthStarGroupCaseIds.recognized_receipt_scope_mismatch;
delete renamedNorthStarGroupCaseIds.recognized_receipt_scope_mismatch;
const renamedNorthStarGroupContentContractFixture = makeV346EvidenceFixture(
  renamedNorthStarGroupContentContractManifest
);
assertThrows(
  'v3.4.46 north-star group case ID renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      renamedNorthStarGroupContentContractFixture.report,
      {
        evidenceDir: renamedNorthStarGroupContentContractFixture.evidenceDir,
      }
    ),
  'terminal chain recognition refusal group case IDs drifted'
);

const summaryTerminalGroupContentContractFixture = makeV346EvidenceFixture(
  releaseForwardManifestContract({
    terminalBoundary: {
      recognition_refusal_group_case_ids: {
        summary: clone(expectedRecognitionRefusalGroupCaseIds),
      },
    },
  })
);
assertThrows(
  'v3.4.46 terminal group case ID summary-shaped object fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      summaryTerminalGroupContentContractFixture.report,
      {
        evidenceDir: summaryTerminalGroupContentContractFixture.evidenceDir,
      }
    ),
  'terminal chain recognition refusal group case IDs drifted'
);

const extraRootGroupContentContractFixture = makeV346EvidenceFixture();
rewriteManifestArtifact(extraRootGroupContentContractFixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence.recognition_refusal_group_case_ids
    .summary_or_extra_group = ['collapsed_refusal_summary'];
});
assertThrows(
  'v3.4.46 root terminal group case ID extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      extraRootGroupContentContractFixture.report,
      {
        evidenceDir: extraRootGroupContentContractFixture.evidenceDir,
      }
    ),
  'terminal-chain recognition refusal group case IDs drifted'
);

const missingRootGroupContentContractFixture = makeV346EvidenceFixture();
rewriteManifestArtifact(missingRootGroupContentContractFixture, (manifest) => {
  delete manifest.terminal_chain_refusal_evidence
    .recognition_refusal_group_case_ids.recognized_receipt_scope_mismatch;
});
assertThrows(
  'v3.4.46 root terminal group case ID missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      missingRootGroupContentContractFixture.report,
      {
        evidenceDir: missingRootGroupContentContractFixture.evidenceDir,
      }
    ),
  'terminal-chain recognition refusal group case IDs drifted'
);

const renamedRootGroupContentContractFixture = makeV346EvidenceFixture();
rewriteManifestArtifact(renamedRootGroupContentContractFixture, (manifest) => {
  const rootCaseIds =
    manifest.terminal_chain_refusal_evidence.recognition_refusal_group_case_ids;
  rootCaseIds.recognized_receipt_scope_mismatches =
    rootCaseIds.recognized_receipt_scope_mismatch;
  delete rootCaseIds.recognized_receipt_scope_mismatch;
});
assertThrows(
  'v3.4.46 root terminal group case ID renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      renamedRootGroupContentContractFixture.report,
      {
        evidenceDir: renamedRootGroupContentContractFixture.evidenceDir,
      }
    ),
  'terminal-chain recognition refusal group case IDs drifted'
);

const summaryRootGroupContentContractFixture = makeV346EvidenceFixture();
rewriteManifestArtifact(summaryRootGroupContentContractFixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence.recognition_refusal_group_case_ids = {
    summary: clone(expectedRecognitionRefusalGroupCaseIds),
  };
});
assertThrows(
  'v3.4.46 root terminal group case ID summary-shaped object fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      summaryRootGroupContentContractFixture.report,
      {
        evidenceDir: summaryRootGroupContentContractFixture.evidenceDir,
      }
    ),
  'terminal-chain recognition refusal group case IDs drifted'
);

function assertV346ReportContractGroupCaseIdsDrift(
  label,
  mutator,
  expectedMessage,
) {
  const evidenceFixture = makeV346EvidenceFixture();
  rewriteManifestArtifact(evidenceFixture, mutator);
  assertThrows(
    label,
    () =>
      buildPrivateVerifierResultVerification(evidenceFixture.report, {
        evidenceDir: evidenceFixture.evidenceDir,
      }),
    expectedMessage,
  );
}

assertV346ReportContractGroupCaseIdsDrift(
  'v3.4.46 proof-smoke group case ID extra key fails private intake',
  (manifest) => {
    manifest.release_forward_report_contract.proof_smoke.counts
      .installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids
      .summary_or_extra_group = ['collapsed_refusal_summary'];
  },
  'report-contract proof-smoke recognition refusal group case IDs drifted',
);
assertV346ReportContractGroupCaseIdsDrift(
  'v3.4.46 proof-smoke group case ID missing key fails private intake',
  (manifest) => {
    delete manifest.release_forward_report_contract.proof_smoke.counts
      .installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids
      .recognized_receipt_scope_mismatch;
  },
  'report-contract proof-smoke recognition refusal group case IDs drifted',
);
assertV346ReportContractGroupCaseIdsDrift(
  'v3.4.46 proof-smoke group case ID renamed key fails private intake',
  (manifest) => {
    const caseIds =
      manifest.release_forward_report_contract.proof_smoke.counts
        .installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids;
    caseIds.recognized_receipt_scope_mismatches =
      caseIds.recognized_receipt_scope_mismatch;
    delete caseIds.recognized_receipt_scope_mismatch;
  },
  'report-contract proof-smoke recognition refusal group case IDs drifted',
);
assertV346ReportContractGroupCaseIdsDrift(
  'v3.4.46 proof-smoke group case ID summary-shaped object fails private intake',
  (manifest) => {
    manifest.release_forward_report_contract.proof_smoke.counts
      .installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids =
      { summary: clone(expectedRecognitionRefusalGroupCaseIds) };
  },
  'report-contract proof-smoke recognition refusal group case IDs drifted',
);
assertV346ReportContractGroupCaseIdsDrift(
  'v3.4.46 north-star counts group case ID extra key fails private intake',
  (manifest) => {
    manifest.release_forward_report_contract.north_star.counts
      .installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids
      .summary_or_extra_group = ['collapsed_refusal_summary'];
  },
  'report-contract north-star recognition refusal group case IDs drifted',
);
assertV346ReportContractGroupCaseIdsDrift(
  'v3.4.46 north-star counts group case ID missing key fails private intake',
  (manifest) => {
    delete manifest.release_forward_report_contract.north_star.counts
      .installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids
      .recognized_receipt_scope_mismatch;
  },
  'report-contract north-star recognition refusal group case IDs drifted',
);
assertV346ReportContractGroupCaseIdsDrift(
  'v3.4.46 north-star counts group case ID renamed key fails private intake',
  (manifest) => {
    const caseIds =
      manifest.release_forward_report_contract.north_star.counts
        .installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids;
    caseIds.recognized_receipt_scope_mismatches =
      caseIds.recognized_receipt_scope_mismatch;
    delete caseIds.recognized_receipt_scope_mismatch;
  },
  'report-contract north-star recognition refusal group case IDs drifted',
);
assertV346ReportContractGroupCaseIdsDrift(
  'v3.4.46 north-star counts group case ID summary-shaped object fails private intake',
  (manifest) => {
    manifest.release_forward_report_contract.north_star.counts
      .installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids =
      { summary: clone(expectedRecognitionRefusalGroupCaseIds) };
  },
  'report-contract north-star recognition refusal group case IDs drifted',
);

const manifestTargetMismatchV348Manifest = releaseForwardManifestContractV348();
manifestTargetMismatchV348Manifest.target = {
  observed_commit_sha: '7'.repeat(40),
};
const manifestTargetMismatchV348Fixture = makeV348EvidenceFixture(
  manifestTargetMismatchV348Manifest
);
assertThrows(
  'v3.4.48 manifest target mismatch fails private intake',
  () =>
    buildPrivateVerifierResultVerification(manifestTargetMismatchV348Fixture.report, {
      evidenceDir: manifestTargetMismatchV348Fixture.evidenceDir,
    }),
  'manifest target drifted'
);

const targetHeadMismatchV348Fixture = makeV348EvidenceFixture();
writeFileSync(
  artifactFilePath(targetHeadMismatchV348Fixture.evidenceDir, 'target-head.txt'),
  `${'7'.repeat(40)}\n`,
);
refreshRunSha256Sums(targetHeadMismatchV348Fixture);
assertThrows(
  'v3.4.48 target-head mismatch fails private intake',
  () =>
    buildPrivateVerifierResultVerification(targetHeadMismatchV348Fixture.report, {
      evidenceDir: targetHeadMismatchV348Fixture.evidenceDir,
    }),
  'target-head drifted'
);

const manifestArtifactHashExtraPathV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(manifestArtifactHashExtraPathV348Fixture, (manifest) => {
  manifest.artifact_hashes.push({
    path: 'ZLAR/unrecognized-evidence-summary.json',
    sha256: 'f'.repeat(64),
  });
});
assertThrows(
  'v3.4.48 manifest artifact hash extra path fails private intake',
  () =>
    buildPrivateVerifierResultVerification(manifestArtifactHashExtraPathV348Fixture.report, {
      evidenceDir: manifestArtifactHashExtraPathV348Fixture.evidenceDir,
    }),
  'manifest artifact hash path set drifted'
);

const manifestArtifactHashDriftV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(manifestArtifactHashDriftV348Fixture, (manifest) => {
  manifest.artifact_hashes.find(
    (entry) => entry.path === 'ZLAR/zlar-product-proof-path-v1.json',
  ).sha256 = 'f'.repeat(64);
});
assertThrows(
  'v3.4.48 manifest artifact hash drift fails private intake',
  () =>
    buildPrivateVerifierResultVerification(manifestArtifactHashDriftV348Fixture.report, {
      evidenceDir: manifestArtifactHashDriftV348Fixture.evidenceDir,
    }),
  'manifest artifact hash drifted'
);

const extraSourceArtifactV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(extraSourceArtifactV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.source_artifacts.extra_summary = {
    path: 'ZLAR/zlar-product-proof-path-v1.json',
  };
});
assertThrows(
  'v3.4.48 source_artifacts extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(extraSourceArtifactV348Fixture.report, {
      evidenceDir: extraSourceArtifactV348Fixture.evidenceDir,
    }),
  'source_artifacts contains unexpected fields'
);

const missingSourceArtifactV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(missingSourceArtifactV348Fixture, (manifest) => {
  delete manifest.release_forward_report_contract.source_artifacts
    .product_proof_path_sha256;
});
assertThrows(
  'v3.4.48 source_artifacts missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(missingSourceArtifactV348Fixture.report, {
      evidenceDir: missingSourceArtifactV348Fixture.evidenceDir,
    }),
  'source_artifacts contains unexpected fields'
);

const renamedSourceArtifactV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(renamedSourceArtifactV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.source_artifacts.product_proof_path_hash =
    manifest.release_forward_report_contract.source_artifacts
      .product_proof_path_sha256;
  delete manifest.release_forward_report_contract.source_artifacts
    .product_proof_path_sha256;
});
assertThrows(
  'v3.4.48 source_artifacts renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(renamedSourceArtifactV348Fixture.report, {
      evidenceDir: renamedSourceArtifactV348Fixture.evidenceDir,
    }),
  'source_artifacts contains unexpected fields'
);

const summarySourceArtifactV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(summarySourceArtifactV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.source_artifacts.source_artifacts_summary = {
    source: 'summary-shaped',
  };
});
assertThrows(
  'v3.4.48 source_artifacts summary-shaped field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(summarySourceArtifactV348Fixture.report, {
      evidenceDir: summarySourceArtifactV348Fixture.evidenceDir,
    }),
  'source_artifacts contains unexpected fields'
);

const sourceArtifactHashDriftV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(sourceArtifactHashDriftV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.source_artifacts
    .proof_smoke_sample_verification_sha256 = 'f'.repeat(64);
});
assertThrows(
  'v3.4.48 source_artifacts hash drift fails private intake',
  () =>
    buildPrivateVerifierResultVerification(sourceArtifactHashDriftV348Fixture.report, {
      evidenceDir: sourceArtifactHashDriftV348Fixture.evidenceDir,
    }),
  'source artifact hash drifted'
);

const extraNestedTamperV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(extraNestedTamperV348Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence
    .nested_artifact_tamper_refusals.extra_summary = false;
});
assertThrows(
  'v3.4.48 nested tamper extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(extraNestedTamperV348Fixture.report, {
      evidenceDir: extraNestedTamperV348Fixture.evidenceDir,
    }),
  'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals contains unexpected fields'
);

const missingNestedTamperV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(missingNestedTamperV348Fixture, (manifest) => {
  delete manifest.terminal_chain_refusal_evidence
    .nested_artifact_tamper_refusals.forged_inner_preflight_hash_refused;
});
assertThrows(
  'v3.4.48 nested tamper missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(missingNestedTamperV348Fixture.report, {
      evidenceDir: missingNestedTamperV348Fixture.evidenceDir,
    }),
  'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals contains unexpected fields'
);

const renamedNestedTamperV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(renamedNestedTamperV348Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence
    .nested_artifact_tamper_refusals.preflight_artifact_type =
      manifest.terminal_chain_refusal_evidence
        .nested_artifact_tamper_refusals.generated_preflight_artifact_type;
  delete manifest.terminal_chain_refusal_evidence
    .nested_artifact_tamper_refusals.generated_preflight_artifact_type;
});
assertThrows(
  'v3.4.48 nested tamper renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(renamedNestedTamperV348Fixture.report, {
      evidenceDir: renamedNestedTamperV348Fixture.evidenceDir,
    }),
  'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals contains unexpected fields'
);

const summaryNestedTamperV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(summaryNestedTamperV348Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals = {
    tamper_summary: { forged_inner_hashes_refused: true },
  };
});
assertThrows(
  'v3.4.48 nested tamper summary-shaped object fails private intake',
  () =>
    buildPrivateVerifierResultVerification(summaryNestedTamperV348Fixture.report, {
      evidenceDir: summaryNestedTamperV348Fixture.evidenceDir,
    }),
  'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals contains unexpected fields'
);

const driftedNestedTamperV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(driftedNestedTamperV348Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence
    .nested_artifact_tamper_refusals.forged_inner_service_hash_refused = false;
});
assertThrows(
  'v3.4.48 nested tamper value drift fails private intake',
  () =>
    buildPrivateVerifierResultVerification(driftedNestedTamperV348Fixture.report, {
      evidenceDir: driftedNestedTamperV348Fixture.evidenceDir,
    }),
  'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals.forged_inner_service_hash_refused must be true'
);

const extraNestedBindingV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(extraNestedBindingV348Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence
    .nested_artifact_binding.binding_summary = {
      bound: true,
    };
});
assertThrows(
  'v3.4.48 nested binding extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(extraNestedBindingV348Fixture.report, {
      evidenceDir: extraNestedBindingV348Fixture.evidenceDir,
    }),
  'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence.nested_artifact_binding contains unexpected fields'
);

const missingNestedBindingV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(missingNestedBindingV348Fixture, (manifest) => {
  delete manifest.terminal_chain_refusal_evidence
    .nested_artifact_binding.service_artifact_hash_bound;
});
assertThrows(
  'v3.4.48 nested binding missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(missingNestedBindingV348Fixture.report, {
      evidenceDir: missingNestedBindingV348Fixture.evidenceDir,
    }),
  'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence.nested_artifact_binding contains unexpected fields'
);

const renamedNestedBindingV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(renamedNestedBindingV348Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence
    .nested_artifact_binding.service_artifact_bound =
      manifest.terminal_chain_refusal_evidence
        .nested_artifact_binding.service_artifact_hash_bound;
  delete manifest.terminal_chain_refusal_evidence
    .nested_artifact_binding.service_artifact_hash_bound;
});
assertThrows(
  'v3.4.48 nested binding renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(renamedNestedBindingV348Fixture.report, {
      evidenceDir: renamedNestedBindingV348Fixture.evidenceDir,
    }),
  'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence.nested_artifact_binding contains unexpected fields'
);

const summaryNestedBindingV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(summaryNestedBindingV348Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence.nested_artifact_binding = {
    nested_binding_summary: { bound: true },
  };
});
assertThrows(
  'v3.4.48 nested binding summary-shaped object fails private intake',
  () =>
    buildPrivateVerifierResultVerification(summaryNestedBindingV348Fixture.report, {
      evidenceDir: summaryNestedBindingV348Fixture.evidenceDir,
    }),
  'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence.nested_artifact_binding contains unexpected fields'
);

const driftedNestedBindingV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(driftedNestedBindingV348Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence
    .nested_artifact_binding.creates_public_external_attestation = true;
});
assertThrows(
  'v3.4.48 nested binding value drift fails private intake',
  () =>
    buildPrivateVerifierResultVerification(driftedNestedBindingV348Fixture.report, {
      evidenceDir: driftedNestedBindingV348Fixture.evidenceDir,
    }),
  'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence.nested_artifact_binding.creates_public_external_attestation must be false'
);

const aggregateTerminalEvidenceExtensionV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(aggregateTerminalEvidenceExtensionV348Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence.future_unrelated_aggregate_summary = {
    preserved: true,
  };
});
assertEqual(
  'v3.4.48 terminal evidence allows unrelated aggregate evolution',
  true,
  buildPrivateVerifierResultVerification(
    aggregateTerminalEvidenceExtensionV348Fixture.report,
    {
      evidenceDir: aggregateTerminalEvidenceExtensionV348Fixture.evidenceDir,
    },
  ).evidence_dir_contract_verification.verified
);

const aggregateReportContractTerminalEvidenceExtensionV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  aggregateReportContractTerminalEvidenceExtensionV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract
      .terminal_chain_refusal_evidence.future_unrelated_aggregate_summary = {
        preserved: true,
      };
  },
);
assertEqual(
  'v3.4.48 report-contract terminal evidence allows unrelated aggregate evolution',
  true,
  buildPrivateVerifierResultVerification(
    aggregateReportContractTerminalEvidenceExtensionV348Fixture.report,
    {
      evidenceDir:
        aggregateReportContractTerminalEvidenceExtensionV348Fixture.evidenceDir,
    },
  ).evidence_dir_contract_verification.verified
);

const aggregateReportContractProofSmokeCountsExtensionV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  aggregateReportContractProofSmokeCountsExtensionV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.proof_smoke.counts
      .future_unrelated_aggregate_summary = {
        preserved: true,
      };
  },
);
assertEqual(
  'v3.4.48 report-contract proof-smoke counts allow unrelated aggregate evolution',
  true,
  buildPrivateVerifierResultVerification(
    aggregateReportContractProofSmokeCountsExtensionV348Fixture.report,
    {
      evidenceDir:
        aggregateReportContractProofSmokeCountsExtensionV348Fixture.evidenceDir,
    },
  ).evidence_dir_contract_verification.verified
);

const aggregateReportContractPuzzleObservedExtensionV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  aggregateReportContractPuzzleObservedExtensionV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.north_star.puzzle_3_observed
      .future_unrelated_aggregate_summary = {
        preserved: true,
      };
  },
);
assertEqual(
  'v3.4.48 report-contract puzzle observed allows unrelated aggregate evolution',
  true,
  buildPrivateVerifierResultVerification(
    aggregateReportContractPuzzleObservedExtensionV348Fixture.report,
    {
      evidenceDir:
        aggregateReportContractPuzzleObservedExtensionV348Fixture.evidenceDir,
    },
  ).evidence_dir_contract_verification.verified
);

const extraReportTrustedRegistryRefusalV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(extraReportTrustedRegistryRefusalV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.terminal_chain_refusal_evidence
    .trusted_issuer_registry_recognition_refusal_summary = {
      all_refused: true,
    };
});
assertThrows(
  'v3.4.48 report-contract trusted-registry refusal extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      extraReportTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir: extraReportTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const missingReportTrustedRegistryRefusalV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(
  missingReportTrustedRegistryRefusalV348Fixture,
  (manifest) => {
    delete manifest.release_forward_report_contract
      .terminal_chain_refusal_evidence
      .trusted_issuer_registry_recognition_refusal_case_ids;
  },
);
assertThrows(
  'v3.4.48 report-contract trusted-registry refusal missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      missingReportTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir: missingReportTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const renamedReportTrustedRegistryRefusalV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(
  renamedReportTrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.terminal_chain_refusal_evidence
      .trusted_issuer_registry_recognition_refusal_cases =
      manifest.release_forward_report_contract.terminal_chain_refusal_evidence
        .trusted_issuer_registry_recognition_refusal_case_ids;
    delete manifest.release_forward_report_contract
      .terminal_chain_refusal_evidence
      .trusted_issuer_registry_recognition_refusal_case_ids;
  },
);
assertThrows(
  'v3.4.48 report-contract trusted-registry refusal renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      renamedReportTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir: renamedReportTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const summaryReportTrustedRegistryRefusalV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(
  summaryReportTrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.terminal_chain_refusal_evidence
      .trusted_issuer_registry_recognition_refusal_case_ids = {
        summary: clone(expectedTrustedRegistryRecognitionRefusalCaseIds),
      };
  },
);
assertThrows(
  'v3.4.48 report-contract trusted-registry refusal summary-shaped field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      summaryReportTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir: summaryReportTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusals case IDs drifted'
);

const hashSplitReportTrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  hashSplitReportTrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.terminal_chain_refusal_evidence
      .trusted_issuer_registry_recognition_refusals_sha256 = '4'.repeat(64);
    manifest.release_forward_report_contract.terminal_chain_refusal_evidence
      .artifact_verification_trusted_issuer_registry_recognition_refusals_sha256 =
      '4'.repeat(64);
  },
);
assertThrows(
  'v3.4.48 report-contract trusted-registry refusal root mismatch fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      hashSplitReportTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir:
          hashSplitReportTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'trusted_issuer_registry_recognition_refusals drifted from DRY-RUN-MANIFEST.terminal_chain_refusal_evidence'
);

const sourceSplitReportTrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  sourceSplitReportTrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.terminal_chain_refusal_evidence.source =
      'summary-only.terminal_chain_refusal_evidence';
  },
);
assertThrows(
  'v3.4.48 report-contract terminal evidence source drift fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      sourceSplitReportTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir:
          sourceSplitReportTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
  ),
  'release_forward_report_contract.terminal_chain_refusal_evidence.source must be same-manifest.terminal_chain_refusal_evidence'
);

const extraProofSmokeTrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  extraProofSmokeTrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.proof_smoke.counts
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_summary =
      {
        all_refused: true,
      };
  },
);
assertThrows(
  'v3.4.48 proof-smoke trusted-registry refusal extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      extraProofSmokeTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir: extraProofSmokeTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.proof_smoke.counts.trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const missingProofSmokeTrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  missingProofSmokeTrustedRegistryRefusalV348Fixture,
  (manifest) => {
    delete manifest.release_forward_report_contract.proof_smoke.counts
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids;
  },
);
assertThrows(
  'v3.4.48 proof-smoke trusted-registry refusal missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      missingProofSmokeTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir:
          missingProofSmokeTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.proof_smoke.counts.trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const renamedProofSmokeTrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  renamedProofSmokeTrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.proof_smoke.counts
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_cases =
      manifest.release_forward_report_contract.proof_smoke.counts
        .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids;
    delete manifest.release_forward_report_contract.proof_smoke.counts
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids;
  },
);
assertThrows(
  'v3.4.48 proof-smoke trusted-registry refusal renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      renamedProofSmokeTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir:
          renamedProofSmokeTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.proof_smoke.counts.trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const summaryProofSmokeTrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  summaryProofSmokeTrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.proof_smoke.counts
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids =
      {
        summary: clone(expectedTrustedRegistryRecognitionRefusalCaseIds),
      };
  },
);
assertThrows(
  'v3.4.48 proof-smoke trusted-registry refusal summary-shaped field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      summaryProofSmokeTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir:
          summaryProofSmokeTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.proof_smoke.counts.trusted_issuer_registry_recognition_refusals case IDs drifted'
);

const hashSplitProofSmokeTrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  hashSplitProofSmokeTrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.proof_smoke.counts
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256 =
      '4'.repeat(64);
    manifest.release_forward_report_contract.proof_smoke.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256 =
      '4'.repeat(64);
  },
);
assertThrows(
  'v3.4.48 proof-smoke trusted-registry refusal root mismatch fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      hashSplitProofSmokeTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir:
          hashSplitProofSmokeTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.proof_smoke.counts.trusted_issuer_registry_recognition_refusals drifted from DRY-RUN-MANIFEST.terminal_chain_refusal_evidence'
);

const extraNorthStarCountsTrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  extraNorthStarCountsTrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.north_star.counts
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_summary =
      {
        all_refused: true,
      };
  },
);
assertThrows(
  'v3.4.48 north-star counts trusted-registry refusal extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      extraNorthStarCountsTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir:
          extraNorthStarCountsTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.north_star.counts.trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const missingNorthStarCountsTrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  missingNorthStarCountsTrustedRegistryRefusalV348Fixture,
  (manifest) => {
    delete manifest.release_forward_report_contract.north_star.counts
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved;
  },
);
assertThrows(
  'v3.4.48 north-star counts trusted-registry refusal missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      missingNorthStarCountsTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir:
          missingNorthStarCountsTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.north_star.counts.trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const renamedNorthStarCountsTrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  renamedNorthStarCountsTrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.north_star.counts
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_cases =
      manifest.release_forward_report_contract.north_star.counts
        .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids;
    delete manifest.release_forward_report_contract.north_star.counts
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids;
  },
);
assertThrows(
  'v3.4.48 north-star counts trusted-registry refusal renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      renamedNorthStarCountsTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir:
          renamedNorthStarCountsTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.north_star.counts.trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const summaryNorthStarCountsTrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  summaryNorthStarCountsTrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.north_star.counts
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids =
      {
        summary: clone(expectedTrustedRegistryRecognitionRefusalCaseIds),
      };
  },
);
assertThrows(
  'v3.4.48 north-star counts trusted-registry refusal summary-shaped field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      summaryNorthStarCountsTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir:
          summaryNorthStarCountsTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.north_star.counts.trusted_issuer_registry_recognition_refusals case IDs drifted'
);

const hashSplitNorthStarCountsTrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  hashSplitNorthStarCountsTrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.north_star.counts
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256 =
      '4'.repeat(64);
    manifest.release_forward_report_contract.north_star.counts
      .installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256 =
      '4'.repeat(64);
  },
);
assertThrows(
  'v3.4.48 north-star counts trusted-registry refusal root mismatch fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      hashSplitNorthStarCountsTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir:
          hashSplitNorthStarCountsTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
  ),
  'release_forward_report_contract.north_star.counts.trusted_issuer_registry_recognition_refusals drifted from DRY-RUN-MANIFEST.terminal_chain_refusal_evidence'
);

const extraPuzzle3TrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  extraPuzzle3TrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.north_star.puzzle_3_observed
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_summary =
      {
        all_refused: true,
      };
  },
);
assertThrows(
  'v3.4.48 puzzle 3 trusted-registry refusal extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      extraPuzzle3TrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir: extraPuzzle3TrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.north_star.puzzle_3_observed.trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const missingPuzzle3TrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  missingPuzzle3TrustedRegistryRefusalV348Fixture,
  (manifest) => {
    delete manifest.release_forward_report_contract.north_star.puzzle_3_observed
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved;
  },
);
assertThrows(
  'v3.4.48 puzzle 3 trusted-registry refusal missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      missingPuzzle3TrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir:
          missingPuzzle3TrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.north_star.puzzle_3_observed.trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const renamedPuzzle3TrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  renamedPuzzle3TrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.north_star.puzzle_3_observed
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_cases =
      manifest.release_forward_report_contract.north_star.puzzle_3_observed
        .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids;
    delete manifest.release_forward_report_contract.north_star.puzzle_3_observed
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids;
  },
);
assertThrows(
  'v3.4.48 puzzle 3 trusted-registry refusal renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      renamedPuzzle3TrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir:
          renamedPuzzle3TrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.north_star.puzzle_3_observed.trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const summaryPuzzle3TrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  summaryPuzzle3TrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.north_star.puzzle_3_observed
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids =
      {
        summary: clone(expectedTrustedRegistryRecognitionRefusalCaseIds),
      };
  },
);
assertThrows(
  'v3.4.48 puzzle 3 trusted-registry refusal summary-shaped field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      summaryPuzzle3TrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir:
          summaryPuzzle3TrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.north_star.puzzle_3_observed.trusted_issuer_registry_recognition_refusals case IDs drifted'
);

const extraPuzzle5TrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  extraPuzzle5TrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.north_star.puzzle_5_observed
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_summary =
      {
        all_refused: true,
      };
  },
);
assertThrows(
  'v3.4.48 puzzle 5 trusted-registry refusal extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      extraPuzzle5TrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir: extraPuzzle5TrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.north_star.puzzle_5_observed.trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const missingPuzzle5TrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  missingPuzzle5TrustedRegistryRefusalV348Fixture,
  (manifest) => {
    delete manifest.release_forward_report_contract.north_star.puzzle_5_observed
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes;
  },
);
assertThrows(
  'v3.4.48 puzzle 5 trusted-registry refusal missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      missingPuzzle5TrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir:
          missingPuzzle5TrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.north_star.puzzle_5_observed.trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const renamedPuzzle5TrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  renamedPuzzle5TrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.north_star.puzzle_5_observed
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reasons =
      manifest.release_forward_report_contract.north_star.puzzle_5_observed
        .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes;
    delete manifest.release_forward_report_contract.north_star.puzzle_5_observed
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes;
  },
);
assertThrows(
  'v3.4.48 puzzle 5 trusted-registry refusal renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      renamedPuzzle5TrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir:
          renamedPuzzle5TrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.north_star.puzzle_5_observed.trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const summaryPuzzle5TrustedRegistryRefusalV348Fixture =
  makeV348EvidenceFixture();
rewriteManifestArtifact(
  summaryPuzzle5TrustedRegistryRefusalV348Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.north_star.puzzle_5_observed
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids =
      {
        summary: clone(expectedTrustedRegistryRecognitionRefusalCaseIds),
      };
  },
);
assertThrows(
  'v3.4.48 puzzle 5 trusted-registry refusal summary-shaped field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      summaryPuzzle5TrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir:
          summaryPuzzle5TrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.north_star.puzzle_5_observed.trusted_issuer_registry_recognition_refusals case IDs drifted'
);

const extraTrustedRegistryRefusalV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(extraTrustedRegistryRefusalV348Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence
    .trusted_issuer_registry_recognition_refusal_summary = {
      all_refused: true,
    };
});
assertThrows(
  'v3.4.48 trusted-registry refusal extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      extraTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir: extraTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const missingTrustedRegistryRefusalV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(missingTrustedRegistryRefusalV348Fixture, (manifest) => {
  delete manifest.terminal_chain_refusal_evidence
    .trusted_issuer_registry_recognition_refusal_case_ids;
});
assertThrows(
  'v3.4.48 trusted-registry refusal missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      missingTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir: missingTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const renamedTrustedRegistryRefusalV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(renamedTrustedRegistryRefusalV348Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence
    .trusted_issuer_registry_recognition_refusal_cases =
      manifest.terminal_chain_refusal_evidence
        .trusted_issuer_registry_recognition_refusal_case_ids;
  delete manifest.terminal_chain_refusal_evidence
    .trusted_issuer_registry_recognition_refusal_case_ids;
});
assertThrows(
  'v3.4.48 trusted-registry refusal renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      renamedTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir: renamedTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'trusted_issuer_registry_recognition_refusals contains unexpected fields'
);

const summaryTrustedRegistryRefusalV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(summaryTrustedRegistryRefusalV348Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence
    .trusted_issuer_registry_recognition_refusal_case_ids = {
      summary: clone(expectedTrustedRegistryRecognitionRefusalCaseIds),
    };
});
assertThrows(
  'v3.4.48 trusted-registry refusal summary-shaped field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      summaryTrustedRegistryRefusalV348Fixture.report,
      {
        evidenceDir: summaryTrustedRegistryRefusalV348Fixture.evidenceDir,
      }
    ),
  'trusted_issuer_registry_recognition_refusals case IDs drifted'
);

const driftedTrustedRegistryRefusalReasonV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(driftedTrustedRegistryRefusalReasonV348Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence
    .trusted_issuer_registry_recognition_refusal_reason_codes[1] =
      'summary_reason';
});
assertThrows(
  'v3.4.48 trusted-registry refusal reason drift fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      driftedTrustedRegistryRefusalReasonV348Fixture.report,
      {
        evidenceDir: driftedTrustedRegistryRefusalReasonV348Fixture.evidenceDir,
      }
    ),
  'trusted_issuer_registry_recognition_refusals reason codes drifted'
);

const driftedTrustedRegistryRefusalHashV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(driftedTrustedRegistryRefusalHashV348Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence
    .artifact_verification_trusted_issuer_registry_recognition_refusals_sha256 =
      '4'.repeat(64);
});
assertThrows(
  'v3.4.48 trusted-registry refusal hash drift fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      driftedTrustedRegistryRefusalHashV348Fixture.report,
      {
        evidenceDir: driftedTrustedRegistryRefusalHashV348Fixture.evidenceDir,
      }
    ),
  'trusted_issuer_registry_recognition_refusals hash drifted'
);

const falseTrustedRegistryRefusalAllRefusedV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(falseTrustedRegistryRefusalAllRefusedV348Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence
    .trusted_issuer_registry_recognition_refusals_all_refused = false;
});
assertThrows(
  'v3.4.48 trusted-registry refusal all-refused drift fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      falseTrustedRegistryRefusalAllRefusedV348Fixture.report,
      {
        evidenceDir: falseTrustedRegistryRefusalAllRefusedV348Fixture.evidenceDir,
      }
    ),
  'trusted_issuer_registry_recognition_refusals_all_refused must be true'
);

const extraReportClaimBoundaryV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(extraReportClaimBoundaryV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.claim_boundary.extra_summary = false;
});
assertThrows(
  'v3.4.48 report claim boundary extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(extraReportClaimBoundaryV348Fixture.report, {
      evidenceDir: extraReportClaimBoundaryV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.claim_boundary contains unexpected fields'
);

const missingReportClaimBoundaryV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(missingReportClaimBoundaryV348Fixture, (manifest) => {
  delete manifest.release_forward_report_contract.claim_boundary
    .proves_live_registry;
});
assertThrows(
  'v3.4.48 report claim boundary missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(missingReportClaimBoundaryV348Fixture.report, {
      evidenceDir: missingReportClaimBoundaryV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.claim_boundary contains unexpected fields'
);

const renamedReportClaimBoundaryV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(renamedReportClaimBoundaryV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.claim_boundary
    .proves_live_registry_truth =
      manifest.release_forward_report_contract.claim_boundary
        .proves_live_registry;
  delete manifest.release_forward_report_contract.claim_boundary
    .proves_live_registry;
});
assertThrows(
  'v3.4.48 report claim boundary renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(renamedReportClaimBoundaryV348Fixture.report, {
      evidenceDir: renamedReportClaimBoundaryV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.claim_boundary contains unexpected fields'
);

const summaryReportClaimBoundaryV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(summaryReportClaimBoundaryV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.claim_boundary.claim_boundary_summary = {
    external_attestation: false,
  };
});
assertThrows(
  'v3.4.48 report claim boundary summary-shaped field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(summaryReportClaimBoundaryV348Fixture.report, {
      evidenceDir: summaryReportClaimBoundaryV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.claim_boundary contains unexpected fields'
);

const trueReportClaimBoundaryV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(trueReportClaimBoundaryV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.claim_boundary
    .proves_production_authority = true;
});
assertThrows(
  'v3.4.48 report claim boundary true claim fails private intake',
  () =>
    buildPrivateVerifierResultVerification(trueReportClaimBoundaryV348Fixture.report, {
      evidenceDir: trueReportClaimBoundaryV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.claim_boundary.proves_production_authority must be false'
);

const extraProductClaimBoundaryV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(extraProductClaimBoundaryV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.product_proof_path
    .claim_boundary.extra_summary = false;
});
assertThrows(
  'v3.4.48 product claim boundary extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(extraProductClaimBoundaryV348Fixture.report, {
      evidenceDir: extraProductClaimBoundaryV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.product_proof_path.claim_boundary contains unexpected fields'
);

const missingProductClaimBoundaryV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(missingProductClaimBoundaryV348Fixture, (manifest) => {
  delete manifest.release_forward_report_contract.product_proof_path
    .claim_boundary.proves_all_mcp_governance;
});
assertThrows(
  'v3.4.48 product claim boundary missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(missingProductClaimBoundaryV348Fixture.report, {
      evidenceDir: missingProductClaimBoundaryV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.product_proof_path.claim_boundary contains unexpected fields'
);

const renamedProductClaimBoundaryV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(renamedProductClaimBoundaryV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.product_proof_path.claim_boundary
    .proves_current_machine_authority =
      manifest.release_forward_report_contract.product_proof_path
        .claim_boundary.proves_current_machine_governance;
  delete manifest.release_forward_report_contract.product_proof_path
    .claim_boundary.proves_current_machine_governance;
});
assertThrows(
  'v3.4.48 product claim boundary renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(renamedProductClaimBoundaryV348Fixture.report, {
      evidenceDir: renamedProductClaimBoundaryV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.product_proof_path.claim_boundary contains unexpected fields'
);

const summaryProductClaimBoundaryV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(summaryProductClaimBoundaryV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.product_proof_path
    .claim_boundary.product_claim_boundary_summary = {
      current_machine_governance: false,
    };
});
assertThrows(
  'v3.4.48 product claim boundary summary-shaped field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(summaryProductClaimBoundaryV348Fixture.report, {
      evidenceDir: summaryProductClaimBoundaryV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.product_proof_path.claim_boundary contains unexpected fields'
);

const trueProductClaimBoundaryV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(trueProductClaimBoundaryV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.product_proof_path
    .claim_boundary.proves_current_machine_governance = true;
});
assertThrows(
  'v3.4.48 product claim boundary true claim fails private intake',
  () =>
    buildPrivateVerifierResultVerification(trueProductClaimBoundaryV348Fixture.report, {
      evidenceDir: trueProductClaimBoundaryV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.product_proof_path.claim_boundary.proves_current_machine_governance must be false'
);

const extraPrivatePointerV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(extraPrivatePointerV348Fixture, (manifest) => {
  manifest.private_verifier_result_sample.extra_summary = false;
});
assertThrows(
  'v3.4.48 private sample pointer extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(extraPrivatePointerV348Fixture.report, {
      evidenceDir: extraPrivatePointerV348Fixture.evidenceDir,
    }),
  'DRY-RUN-MANIFEST.private_verifier_result_sample contains unexpected fields'
);

const missingPrivatePointerV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(missingPrivatePointerV348Fixture, (manifest) => {
  delete manifest.private_verifier_result_sample.hash_record_location;
});
assertThrows(
  'v3.4.48 private sample pointer missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(missingPrivatePointerV348Fixture.report, {
      evidenceDir: missingPrivatePointerV348Fixture.evidenceDir,
    }),
  'DRY-RUN-MANIFEST.private_verifier_result_sample contains unexpected fields'
);

const renamedPrivatePointerV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(renamedPrivatePointerV348Fixture, (manifest) => {
  manifest.private_verifier_result_sample.result_heading =
    manifest.private_verifier_result_sample.result_section;
  delete manifest.private_verifier_result_sample.result_section;
});
assertThrows(
  'v3.4.48 private sample pointer renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(renamedPrivatePointerV348Fixture.report, {
      evidenceDir: renamedPrivatePointerV348Fixture.evidenceDir,
    }),
  'DRY-RUN-MANIFEST.private_verifier_result_sample contains unexpected fields'
);

const summaryPrivatePointerV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(summaryPrivatePointerV348Fixture, (manifest) => {
  manifest.private_verifier_result_sample.pointer_summary = {
    envelope_path: 'ZLAR/zlar-private-verifier-result-v1.json',
  };
});
assertThrows(
  'v3.4.48 private sample pointer summary-shaped field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(summaryPrivatePointerV348Fixture.report, {
      evidenceDir: summaryPrivatePointerV348Fixture.evidenceDir,
    }),
  'DRY-RUN-MANIFEST.private_verifier_result_sample contains unexpected fields'
);

const truePrivatePointerV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(truePrivatePointerV348Fixture, (manifest) => {
  manifest.private_verifier_result_sample.included_in_core_artifact_hashes = true;
});
assertThrows(
  'v3.4.48 private sample pointer core-hash overclaim fails private intake',
  () =>
    buildPrivateVerifierResultVerification(truePrivatePointerV348Fixture.report, {
      evidenceDir: truePrivatePointerV348Fixture.evidenceDir,
    }),
  'DRY-RUN-MANIFEST.private_verifier_result_sample.included_in_core_artifact_hashes must be false'
);

const extraSimulatedHumanV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(extraSimulatedHumanV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.product_proof_path
    .simulated_human_authorization.authorization_summary = {
      authorized: true,
    };
});
assertThrows(
  'v3.4.48 simulated human compact object extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(extraSimulatedHumanV348Fixture.report, {
      evidenceDir: extraSimulatedHumanV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.product_proof_path.simulated_human_authorization contains unexpected fields'
);

const missingSimulatedHumanV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(missingSimulatedHumanV348Fixture, (manifest) => {
  delete manifest.release_forward_report_contract.product_proof_path
    .simulated_human_authorization.authorized_boarded;
});
assertThrows(
  'v3.4.48 simulated human compact object missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(missingSimulatedHumanV348Fixture.report, {
      evidenceDir: missingSimulatedHumanV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.product_proof_path.simulated_human_authorization contains unexpected fields'
);

const renamedSimulatedHumanV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(renamedSimulatedHumanV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.product_proof_path
    .simulated_human_authorization.channel =
      manifest.release_forward_report_contract.product_proof_path
        .simulated_human_authorization.approval_channel;
  delete manifest.release_forward_report_contract.product_proof_path
    .simulated_human_authorization.approval_channel;
});
assertThrows(
  'v3.4.48 simulated human compact object renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(renamedSimulatedHumanV348Fixture.report, {
      evidenceDir: renamedSimulatedHumanV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.product_proof_path.simulated_human_authorization contains unexpected fields'
);

const driftedSimulatedHumanV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(driftedSimulatedHumanV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.product_proof_path
    .simulated_human_authorization.authorized_boarded = false;
});
assertThrows(
  'v3.4.48 simulated human compact object value drift fails private intake',
  () =>
    buildPrivateVerifierResultVerification(driftedSimulatedHumanV348Fixture.report, {
      evidenceDir: driftedSimulatedHumanV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.product_proof_path.simulated_human_authorization.authorized_boarded must be true'
);

const extraReceiptBoundaryV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(extraReceiptBoundaryV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.product_proof_path
    .receipt_verifier_boundary.receipt_summary = {
      verdicts: 'collapsed',
    };
});
assertThrows(
  'v3.4.48 receipt verifier compact object extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(extraReceiptBoundaryV348Fixture.report, {
      evidenceDir: extraReceiptBoundaryV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.product_proof_path.receipt_verifier_boundary contains unexpected fields'
);

const missingReceiptBoundaryV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(missingReceiptBoundaryV348Fixture, (manifest) => {
  delete manifest.release_forward_report_contract.product_proof_path
    .receipt_verifier_boundary.downstream_recognition_proven;
});
assertThrows(
  'v3.4.48 receipt verifier compact object missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(missingReceiptBoundaryV348Fixture.report, {
      evidenceDir: missingReceiptBoundaryV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.product_proof_path.receipt_verifier_boundary contains unexpected fields'
);

const renamedReceiptBoundaryV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(renamedReceiptBoundaryV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.product_proof_path
    .receipt_verifier_boundary.unknown_signer_collapsed_verdict =
      manifest.release_forward_report_contract.product_proof_path
        .receipt_verifier_boundary.unknown_signer_verdict;
  delete manifest.release_forward_report_contract.product_proof_path
    .receipt_verifier_boundary.unknown_signer_verdict;
});
assertThrows(
  'v3.4.48 receipt verifier compact object renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(renamedReceiptBoundaryV348Fixture.report, {
      evidenceDir: renamedReceiptBoundaryV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.product_proof_path.receipt_verifier_boundary contains unexpected fields'
);

const driftedReceiptBoundaryV348Fixture = makeV348EvidenceFixture();
rewriteManifestArtifact(driftedReceiptBoundaryV348Fixture, (manifest) => {
  manifest.release_forward_report_contract.product_proof_path
    .receipt_verifier_boundary.downstream_recognition_proven = true;
});
assertThrows(
  'v3.4.48 receipt verifier compact object value drift fails private intake',
  () =>
    buildPrivateVerifierResultVerification(driftedReceiptBoundaryV348Fixture.report, {
      evidenceDir: driftedReceiptBoundaryV348Fixture.evidenceDir,
    }),
  'release_forward_report_contract.product_proof_path.receipt_verifier_boundary.downstream_recognition_proven must be false'
);

const contentContract48Fixture = makeV348EvidenceFixture();
const contentContract48Verification = buildPrivateVerifierResultVerification(
  contentContract48Fixture.report,
  {
    evidenceDir: contentContract48Fixture.evidenceDir,
  }
);
const contentContract48Manifest = JSON.parse(
  readEvidenceText(contentContract48Fixture, 'DRY-RUN-MANIFEST.json'),
);
assertEqual(
  'v3.4.48 private intake content contract verified',
  true,
  contentContract48Verification.evidence_dir_contract_verification.verified
);
assertEqual(
  'v3.4.48 private intake contract type',
  'product-proof-path-terminal-chain-and-deployment-profile-authority-bridge-v1',
  contentContract48Verification.evidence_dir_contract_verification.contract_type
);
assertEqual(
  'v3.4.48 private intake manifest field names bridge',
  'release_forward_report_contract.product_proof_path.terminal_chain_boundary+deployment_profile_authority_bridge+north_star.deployment_profile_authority_bridge_*',
  contentContract48Verification.evidence_dir_contract_verification.manifest_field
);
assertEqual(
  'v3.4.48 private intake deployment bridge required',
  true,
  contentContract48Verification.evidence_dir_contract_verification
    .deployment_profile_authority_bridge_required_for_target
);
assertEqual(
  'v3.4.48 private intake deployment bridge preserved',
  true,
  contentContract48Verification.evidence_dir_contract_verification
    .product_proof_path_deployment_profile_authority_bridge_preserved
);
assertEqual(
  'v3.4.48 private intake north star deployment bridge preserved',
  true,
  contentContract48Verification.evidence_dir_contract_verification
    .north_star_deployment_profile_authority_bridge_preserved
);
assertEqual(
  'v3.4.48 private intake deployment bridge refusal count',
  18,
  contentContract48Verification.evidence_dir_contract_verification
    .deployment_profile_authority_bridge_refusal_case_count
);
assertEqual(
  'v3.4.48 private intake deployment bridge current-machine false',
  false,
  contentContract48Verification.evidence_dir_contract_verification
    .deployment_profile_authority_bridge_current_machine_governance
);
assertEqual(
  'v3.4.48 private intake deployment bridge production false',
  false,
  contentContract48Verification.evidence_dir_contract_verification
    .deployment_profile_authority_bridge_production_authority
);
assertEqual(
  'v3.4.48 private intake deployment authority refusals not required',
  false,
  contentContract48Verification.evidence_dir_contract_verification
    .deployment_profile_authority_refusals_required_for_target
);
assertEqual(
  'v3.4.48 private intake deployment authority refusals not preserved',
  null,
  contentContract48Verification.evidence_dir_contract_verification
    .product_proof_path_deployment_profile_authority_refusals_preserved
);
assertEqual(
  'v3.4.48 private intake trusted-registry refusals required',
  true,
  contentContract48Verification.evidence_dir_contract_verification
    .terminal_chain_trusted_registry_recognition_refusals_required_for_target
);
assertEqual(
  'v3.4.48 private intake trusted-registry refusals preserved',
  true,
  contentContract48Verification.evidence_dir_contract_verification
    .terminal_chain_trusted_registry_recognition_refusals_preserved
);
assert(
  'v3.4.48 private intake terminal evidence trusted-registry refusal family keys exact',
  terminalChainTrustedRegistryRefusalKeysEqual(
    terminalChainRefusalEvidence(terminalChainTrustedRegistryRecognitionRefusals()),
    expectedTerminalChainTrustedRegistryRecognitionRefusalKeys,
  )
);
assert(
  'v3.4.48 private intake report-contract trusted-registry refusal family keys exact',
  terminalChainTrustedRegistryRefusalKeysEqual(
    releaseForwardReportContractTerminalChainRefusalEvidence(
      terminalChainRefusalEvidence(
        terminalChainTrustedRegistryRecognitionRefusals(),
      ),
    ),
    expectedReportContractTerminalChainTrustedRegistryRecognitionRefusalKeys,
  )
);
assert(
  'v3.4.48 private intake report-contract proof-smoke trusted-registry refusal family keys exact',
  reportContractProofSummaryTrustedRegistryRefusalKeysEqual(
    contentContract48Manifest.release_forward_report_contract.proof_smoke.counts,
    expectedReportContractProofSmokeTrustedRegistryRecognitionRefusalKeys,
  )
);
assert(
  'v3.4.48 private intake report-contract north-star trusted-registry refusal family keys exact',
  reportContractProofSummaryTrustedRegistryRefusalKeysEqual(
    contentContract48Manifest.release_forward_report_contract.north_star.counts,
    expectedReportContractNorthStarTrustedRegistryRecognitionRefusalKeys,
  )
);
assert(
  'v3.4.48 private intake report-contract puzzle 3 trusted-registry refusal family keys exact',
  reportContractProofSummaryTrustedRegistryRefusalKeysEqual(
    contentContract48Manifest.release_forward_report_contract.north_star
      .puzzle_3_observed,
    expectedReportContractNorthStarObservedTrustedRegistryRecognitionRefusalKeys,
  )
);
assert(
  'v3.4.48 private intake report-contract puzzle 5 trusted-registry refusal family keys exact',
  reportContractProofSummaryTrustedRegistryRefusalKeysEqual(
    contentContract48Manifest.release_forward_report_contract.north_star
      .puzzle_5_observed,
    expectedReportContractNorthStarObservedTrustedRegistryRecognitionRefusalKeys,
  )
);
assertEqual(
  'v3.4.48 private intake deployment mirror not required',
  false,
  contentContract48Verification.evidence_dir_contract_verification
    .terminal_chain_deployment_profile_authority_refusal_mirror_required_for_target
);
assertEqual(
  'v3.4.48 private intake deployment mirror not preserved',
  null,
  contentContract48Verification.evidence_dir_contract_verification
    .terminal_chain_deployment_profile_authority_refusal_mirror_preserved
);
assert(
  'v3.4.48 private intake deployment bridge exact keys',
  keysEqual(
    releaseForwardManifestContractV348()
      .release_forward_report_contract.product_proof_path
      .deployment_profile_authority_bridge,
    expectedDeploymentProfileAuthorityBridgeKeys,
  )
);
assert(
  'v3.4.48 private intake north star deployment authority family keys exact',
  deploymentProfileAuthorityNorthStarKeysEqual(
    releaseForwardManifestContractV348()
      .release_forward_report_contract.product_proof_path.north_star,
    expectedDeploymentProfileAuthorityBridgeNorthStarKeys,
  )
);
const aggregateExtensionV348Fixture = makeV348EvidenceFixture(
  releaseForwardManifestContractV348({
    northStar: {
      future_unrelated_aggregate_summary: {
        preserved: true,
      },
    },
  })
);
assertEqual(
  'v3.4.48 private intake allows aggregate evolution outside deployment authority prefix',
  true,
  buildPrivateVerifierResultVerification(aggregateExtensionV348Fixture.report, {
    evidenceDir: aggregateExtensionV348Fixture.evidenceDir,
  }).evidence_dir_contract_verification.verified
);
const extraDeploymentAuthorityBridgeFieldV348Fixture = makeV348EvidenceFixture(
  releaseForwardManifestContractV348({
    deploymentBridge: {
      deployment_profile_authority_bridge_summary: {
        current_machine_governance: true,
      },
    },
  })
);
assertThrows(
  'v3.4.48 extra deployment authority bridge field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      extraDeploymentAuthorityBridgeFieldV348Fixture.report,
      {
        evidenceDir: extraDeploymentAuthorityBridgeFieldV348Fixture.evidenceDir,
      }
    ),
  'deployment-profile authority bridge drifted'
);
const missingDeploymentAuthorityBridgeKeyV348Manifest =
  releaseForwardManifestContractV348();
delete missingDeploymentAuthorityBridgeKeyV348Manifest
  .release_forward_report_contract.product_proof_path
  .deployment_profile_authority_bridge.selected_by_explicit_id_and_sha;
const missingDeploymentAuthorityBridgeKeyV348Fixture = makeV348EvidenceFixture(
  missingDeploymentAuthorityBridgeKeyV348Manifest
);
assertThrows(
  'v3.4.48 missing deployment authority bridge key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      missingDeploymentAuthorityBridgeKeyV348Fixture.report,
      {
        evidenceDir: missingDeploymentAuthorityBridgeKeyV348Fixture.evidenceDir,
      }
    ),
  'deployment-profile authority bridge drifted'
);
const renamedDeploymentAuthorityBridgeKeyV348Manifest =
  releaseForwardManifestContractV348();
renamedDeploymentAuthorityBridgeKeyV348Manifest
  .release_forward_report_contract.product_proof_path
  .deployment_profile_authority_bridge.selected_by_explicit_profile_sha =
  renamedDeploymentAuthorityBridgeKeyV348Manifest
    .release_forward_report_contract.product_proof_path
    .deployment_profile_authority_bridge.selected_by_explicit_id_and_sha;
delete renamedDeploymentAuthorityBridgeKeyV348Manifest
  .release_forward_report_contract.product_proof_path
  .deployment_profile_authority_bridge.selected_by_explicit_id_and_sha;
const renamedDeploymentAuthorityBridgeKeyV348Fixture = makeV348EvidenceFixture(
  renamedDeploymentAuthorityBridgeKeyV348Manifest
);
assertThrows(
  'v3.4.48 renamed deployment authority bridge key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      renamedDeploymentAuthorityBridgeKeyV348Fixture.report,
      {
        evidenceDir: renamedDeploymentAuthorityBridgeKeyV348Fixture.evidenceDir,
      }
    ),
  'deployment-profile authority bridge drifted'
);
const summaryDeploymentAuthorityNorthStarV348Fixture = makeV348EvidenceFixture(
  releaseForwardManifestContractV348({
    northStar: {
      deployment_profile_authority_bridge_summary: {
        preserved: true,
      },
    },
  })
);
assertThrows(
  'v3.4.48 summary-shaped north star deployment authority field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      summaryDeploymentAuthorityNorthStarV348Fixture.report,
      {
        evidenceDir: summaryDeploymentAuthorityNorthStarV348Fixture.evidenceDir,
      }
    ),
  'deployment-profile authority bridge drifted'
);
const futureDeploymentAuthorityRefusalsV348Fixture = makeV348EvidenceFixture(
  releaseForwardManifestContractV348({
    deploymentBridge: deploymentProfileAuthorityBridgeV349(),
    northStar: deploymentProfileAuthorityBridgeNorthStarV349(),
  })
);
assertThrows(
  'v3.4.48 future deployment authority refusals fail private intake',
  () =>
    buildPrivateVerifierResultVerification(
      futureDeploymentAuthorityRefusalsV348Fixture.report,
      {
        evidenceDir: futureDeploymentAuthorityRefusalsV348Fixture.evidenceDir,
      }
    ),
  'deployment-profile authority refusals appeared before v3.4.49'
);

const contentContract49Fixture = makeV349EvidenceFixture();
const contentContract49Verification = buildPrivateVerifierResultVerification(
  contentContract49Fixture.report,
  {
    evidenceDir: contentContract49Fixture.evidenceDir,
  }
);
assertEqual(
  'v3.4.49 private intake content contract verified',
  true,
  contentContract49Verification.evidence_dir_contract_verification.verified
);
assertEqual(
  'v3.4.49 private intake contract type',
  'product-proof-path-terminal-chain-deployment-profile-authority-bridge-and-authority-refusals-v1',
  contentContract49Verification.evidence_dir_contract_verification.contract_type
);
assertEqual(
  'v3.4.49 private intake deployment authority refusals required',
  true,
  contentContract49Verification.evidence_dir_contract_verification
    .deployment_profile_authority_refusals_required_for_target
);
assertEqual(
  'v3.4.49 private intake deployment authority refusals preserved',
  true,
  contentContract49Verification.evidence_dir_contract_verification
    .product_proof_path_deployment_profile_authority_refusals_preserved
);
assertEqual(
  'v3.4.49 private intake north star deployment authority refusals preserved',
  true,
  contentContract49Verification.evidence_dir_contract_verification
    .north_star_deployment_profile_authority_refusals_preserved
);
assertEqual(
  'v3.4.49 private intake deployment authority refusal count',
  expectedDeploymentProfileAuthorityRefusalCaseIds.length,
  contentContract49Verification.evidence_dir_contract_verification
    .deployment_profile_authority_refusal_case_count
);
assertEqual(
  'v3.4.49 private intake deployment authority refusal IDs preserved',
  true,
  contentContract49Verification.evidence_dir_contract_verification
    .deployment_profile_authority_refusal_case_ids_preserved
);
assertEqual(
  'v3.4.49 private intake stale artifact refused',
  true,
  contentContract49Verification.evidence_dir_contract_verification
    .stale_deployment_profile_artifact_refused_before_service_proof
);
assertEqual(
  'v3.4.49 private intake profile mismatch refused',
  true,
  contentContract49Verification.evidence_dir_contract_verification
    .profile_recognition_mismatch_refused_before_service_proof
);
assertEqual(
  'v3.4.49 private intake terminal-chain deployment mirror not required',
  false,
  contentContract49Verification.evidence_dir_contract_verification
    .terminal_chain_deployment_profile_authority_refusal_mirror_required_for_target
);
assertEqual(
  'v3.4.49 private intake terminal-chain deployment mirror not preserved',
  null,
  contentContract49Verification.evidence_dir_contract_verification
    .terminal_chain_deployment_profile_authority_refusal_mirror_preserved
);
assert(
  'v3.4.49 private intake deployment bridge refusal exact keys',
  keysEqual(
    releaseForwardManifestContractV349()
      .release_forward_report_contract.product_proof_path
      .deployment_profile_authority_bridge,
    expectedDeploymentProfileAuthorityBridgeV349Keys,
  )
);
assert(
  'v3.4.49 private intake north star deployment authority family keys exact',
  deploymentProfileAuthorityNorthStarKeysEqual(
    releaseForwardManifestContractV349()
      .release_forward_report_contract.product_proof_path.north_star,
    expectedDeploymentProfileAuthorityNorthStarV349Keys,
  )
);
const extraDeploymentAuthorityRefusalFieldV349Fixture = makeV349EvidenceFixture(
  releaseForwardManifestContractV349({
    deploymentBridge: {
      deployment_profile_authority_refusals_summary: {
        before_service_proof: true,
      },
    },
  })
);
assertThrows(
  'v3.4.49 extra deployment authority refusal field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      extraDeploymentAuthorityRefusalFieldV349Fixture.report,
      {
        evidenceDir: extraDeploymentAuthorityRefusalFieldV349Fixture.evidenceDir,
      }
    ),
  'deployment-profile authority bridge drifted'
);
const missingDeploymentAuthorityRefusalKeyV349Manifest =
  releaseForwardManifestContractV349();
delete missingDeploymentAuthorityRefusalKeyV349Manifest
  .release_forward_report_contract.product_proof_path
  .deployment_profile_authority_bridge.deployment_profile_authority_refusal_case_ids;
const missingDeploymentAuthorityRefusalKeyV349Fixture = makeV349EvidenceFixture(
  missingDeploymentAuthorityRefusalKeyV349Manifest
);
assertThrows(
  'v3.4.49 missing deployment authority refusal key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      missingDeploymentAuthorityRefusalKeyV349Fixture.report,
      {
        evidenceDir: missingDeploymentAuthorityRefusalKeyV349Fixture.evidenceDir,
      }
    ),
  'deployment-profile authority bridge drifted'
);
const renamedDeploymentAuthorityRefusalKeyV349Manifest =
  releaseForwardManifestContractV349();
renamedDeploymentAuthorityRefusalKeyV349Manifest
  .release_forward_report_contract.product_proof_path
  .deployment_profile_authority_bridge.deployment_profile_authority_refusal_cases =
  renamedDeploymentAuthorityRefusalKeyV349Manifest
    .release_forward_report_contract.product_proof_path
    .deployment_profile_authority_bridge.deployment_profile_authority_refusal_case_ids;
delete renamedDeploymentAuthorityRefusalKeyV349Manifest
  .release_forward_report_contract.product_proof_path
  .deployment_profile_authority_bridge.deployment_profile_authority_refusal_case_ids;
const renamedDeploymentAuthorityRefusalKeyV349Fixture = makeV349EvidenceFixture(
  renamedDeploymentAuthorityRefusalKeyV349Manifest
);
assertThrows(
  'v3.4.49 renamed deployment authority refusal key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      renamedDeploymentAuthorityRefusalKeyV349Fixture.report,
      {
        evidenceDir: renamedDeploymentAuthorityRefusalKeyV349Fixture.evidenceDir,
      }
    ),
  'deployment-profile authority bridge drifted'
);
const summaryDeploymentAuthorityNorthStarV349Fixture = makeV349EvidenceFixture(
  releaseForwardManifestContractV349({
    northStar: {
      deployment_profile_authority_refusals_summary: {
        preserved: true,
      },
    },
  })
);
assertThrows(
  'v3.4.49 summary-shaped north star deployment authority refusal field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      summaryDeploymentAuthorityNorthStarV349Fixture.report,
      {
        evidenceDir: summaryDeploymentAuthorityNorthStarV349Fixture.evidenceDir,
      }
    ),
  'deployment-profile authority bridge drifted'
);

const futureDeploymentAuthorityRefusalMirrorV349Fixture = makeV349EvidenceFixture();
rewriteManifestArtifact(futureDeploymentAuthorityRefusalMirrorV349Fixture, (manifest) => {
  Object.assign(
    manifest.terminal_chain_refusal_evidence,
    terminalChainDeploymentProfileAuthorityRefusalMirror(),
  );
});
assertThrows(
  'v3.4.49 terminal-chain deployment authority mirror fails before v3.4.50',
  () =>
    buildPrivateVerifierResultVerification(
      futureDeploymentAuthorityRefusalMirrorV349Fixture.report,
      {
        evidenceDir: futureDeploymentAuthorityRefusalMirrorV349Fixture.evidenceDir,
      }
    ),
  'deployment-profile authority-refusal mirror appeared before v3.4.50'
);

const futureReportDeploymentAuthorityRefusalMirrorV349Fixture =
  makeV349EvidenceFixture();
rewriteManifestArtifact(
  futureReportDeploymentAuthorityRefusalMirrorV349Fixture,
  (manifest) => {
    Object.assign(
      manifest.release_forward_report_contract.terminal_chain_refusal_evidence,
      releaseForwardReportContractTerminalChainRefusalEvidence(
        terminalChainRefusalEvidence({
          ...terminalChainTrustedRegistryRecognitionRefusals(),
          ...terminalChainDeploymentProfileAuthorityRefusalMirror(),
        }),
      ),
    );
  },
);
assertThrows(
  'v3.4.49 report-contract deployment authority mirror fails before v3.4.50',
  () =>
    buildPrivateVerifierResultVerification(
      futureReportDeploymentAuthorityRefusalMirrorV349Fixture.report,
      {
        evidenceDir:
          futureReportDeploymentAuthorityRefusalMirrorV349Fixture.evidenceDir,
      }
    ),
  'report-contract deployment-profile authority-refusal mirror appeared before v3.4.50'
);

const contentContract50Fixture = makeV350EvidenceFixture();
const contentContract50Verification = buildPrivateVerifierResultVerification(
  contentContract50Fixture.report,
  {
    evidenceDir: contentContract50Fixture.evidenceDir,
  }
);
assertEqual(
  'v3.4.50 private intake terminal-chain deployment mirror required',
  true,
  contentContract50Verification.evidence_dir_contract_verification
    .terminal_chain_deployment_profile_authority_refusal_mirror_required_for_target
);
assertEqual(
  'v3.4.50 private intake terminal-chain deployment mirror preserved',
  true,
  contentContract50Verification.evidence_dir_contract_verification
    .terminal_chain_deployment_profile_authority_refusal_mirror_preserved
);
assertEqual(
  'v3.4.50 private intake trusted-registry verdict still not required',
  false,
  contentContract50Verification.evidence_dir_contract_verification
    .terminal_chain_trusted_registry_verdict_required_for_target
);
assert(
  'v3.4.50 private intake terminal evidence deployment mirror family keys exact',
  terminalChainDeploymentProfileAuthorityRefusalMirrorKeysEqual(
    terminalChainRefusalEvidence(terminalChainDeploymentProfileAuthorityRefusalMirror()),
    expectedTerminalChainDeploymentProfileAuthorityRefusalMirrorKeys,
  )
);
assert(
  'v3.4.50 private intake report-contract deployment mirror family keys exact',
  terminalChainDeploymentProfileAuthorityRefusalMirrorKeysEqual(
    releaseForwardReportContractTerminalChainRefusalEvidence(
      terminalChainRefusalEvidence({
        ...terminalChainTrustedRegistryRecognitionRefusals(),
        ...terminalChainDeploymentProfileAuthorityRefusalMirror(),
      }),
    ),
    expectedReportContractTerminalChainDeploymentProfileAuthorityRefusalMirrorKeys,
  )
);

const extraDeploymentAuthorityMirrorV350Fixture = makeV350EvidenceFixture();
rewriteManifestArtifact(extraDeploymentAuthorityMirrorV350Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence
    .deployment_profile_authority_refusal_mirror_summary = {
      preserved: true,
    };
});
assertThrows(
  'v3.4.50 deployment authority mirror extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      extraDeploymentAuthorityMirrorV350Fixture.report,
      {
        evidenceDir: extraDeploymentAuthorityMirrorV350Fixture.evidenceDir,
      }
    ),
  'deployment_profile_authority_refusal_mirror contains unexpected fields'
);

const missingDeploymentAuthorityMirrorV350Fixture = makeV350EvidenceFixture();
rewriteManifestArtifact(missingDeploymentAuthorityMirrorV350Fixture, (manifest) => {
  delete manifest.terminal_chain_refusal_evidence
    .deployment_profile_authority_refusal_case_ids;
});
assertThrows(
  'v3.4.50 deployment authority mirror missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      missingDeploymentAuthorityMirrorV350Fixture.report,
      {
        evidenceDir: missingDeploymentAuthorityMirrorV350Fixture.evidenceDir,
      }
    ),
  'deployment_profile_authority_refusal_mirror contains unexpected fields'
);

const renamedDeploymentAuthorityMirrorV350Fixture = makeV350EvidenceFixture();
rewriteManifestArtifact(renamedDeploymentAuthorityMirrorV350Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence
    .deployment_profile_authority_refusal_cases =
      manifest.terminal_chain_refusal_evidence
        .deployment_profile_authority_refusal_case_ids;
  delete manifest.terminal_chain_refusal_evidence
    .deployment_profile_authority_refusal_case_ids;
});
assertThrows(
  'v3.4.50 deployment authority mirror renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      renamedDeploymentAuthorityMirrorV350Fixture.report,
      {
        evidenceDir: renamedDeploymentAuthorityMirrorV350Fixture.evidenceDir,
      }
    ),
  'deployment_profile_authority_refusal_mirror contains unexpected fields'
);

const summaryDeploymentAuthorityMirrorV350Fixture = makeV350EvidenceFixture();
rewriteManifestArtifact(summaryDeploymentAuthorityMirrorV350Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence
    .deployment_profile_authority_refusal_case_ids = {
      summary: clone(expectedDeploymentProfileAuthorityRefusalCaseIds),
    };
});
assertThrows(
  'v3.4.50 deployment authority mirror summary-shaped field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      summaryDeploymentAuthorityMirrorV350Fixture.report,
      {
        evidenceDir: summaryDeploymentAuthorityMirrorV350Fixture.evidenceDir,
      }
    ),
  'deployment_profile_authority_refusal_mirror case IDs drifted'
);

const driftedDeploymentAuthorityMirrorCaseV350Fixture = makeV350EvidenceFixture();
rewriteManifestArtifact(driftedDeploymentAuthorityMirrorCaseV350Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence
    .artifact_verification_deployment_profile_authority_refusal_case_ids[0] =
      'summary_case';
});
assertThrows(
  'v3.4.50 deployment authority mirror case ID drift fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      driftedDeploymentAuthorityMirrorCaseV350Fixture.report,
      {
        evidenceDir: driftedDeploymentAuthorityMirrorCaseV350Fixture.evidenceDir,
      }
    ),
  'deployment_profile_authority_refusal_mirror case IDs drifted'
);

const serviceStartedDeploymentAuthorityMirrorV350Fixture = makeV350EvidenceFixture();
rewriteManifestArtifact(
  serviceStartedDeploymentAuthorityMirrorV350Fixture,
  (manifest) => {
    manifest.terminal_chain_refusal_evidence
      .deployment_profile_authority_refusal_service_proof_started = true;
  },
);
assertThrows(
  'v3.4.50 deployment authority mirror service proof started fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      serviceStartedDeploymentAuthorityMirrorV350Fixture.report,
      {
        evidenceDir: serviceStartedDeploymentAuthorityMirrorV350Fixture.evidenceDir,
      }
    ),
  'deployment_profile_authority_refusal_service_proof_started must be false'
);

const trueBoundaryDeploymentAuthorityMirrorV350Fixture = makeV350EvidenceFixture();
rewriteManifestArtifact(trueBoundaryDeploymentAuthorityMirrorV350Fixture, (manifest) => {
  manifest.terminal_chain_refusal_evidence.external_attestation = true;
});
assertThrows(
  'v3.4.50 deployment authority mirror false-boundary drift fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      trueBoundaryDeploymentAuthorityMirrorV350Fixture.report,
      {
        evidenceDir: trueBoundaryDeploymentAuthorityMirrorV350Fixture.evidenceDir,
      }
    ),
  'external_attestation must be false'
);

const extraReportDeploymentAuthorityMirrorV350Fixture = makeV350EvidenceFixture();
rewriteManifestArtifact(
  extraReportDeploymentAuthorityMirrorV350Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.terminal_chain_refusal_evidence
      .deployment_profile_authority_refusal_mirror_summary = {
        preserved: true,
      };
  },
);
assertThrows(
  'v3.4.50 report-contract deployment authority mirror extra key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      extraReportDeploymentAuthorityMirrorV350Fixture.report,
      {
        evidenceDir: extraReportDeploymentAuthorityMirrorV350Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.terminal_chain_refusal_evidence.deployment_profile_authority_refusal_mirror contains unexpected fields'
);

const missingReportDeploymentAuthorityMirrorV350Fixture =
  makeV350EvidenceFixture();
rewriteManifestArtifact(
  missingReportDeploymentAuthorityMirrorV350Fixture,
  (manifest) => {
    delete manifest.release_forward_report_contract
      .terminal_chain_refusal_evidence
      .deployment_profile_authority_refusal_case_ids;
  },
);
assertThrows(
  'v3.4.50 report-contract deployment authority mirror missing key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      missingReportDeploymentAuthorityMirrorV350Fixture.report,
      {
        evidenceDir:
          missingReportDeploymentAuthorityMirrorV350Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.terminal_chain_refusal_evidence.deployment_profile_authority_refusal_mirror contains unexpected fields'
);

const renamedReportDeploymentAuthorityMirrorV350Fixture =
  makeV350EvidenceFixture();
rewriteManifestArtifact(
  renamedReportDeploymentAuthorityMirrorV350Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.terminal_chain_refusal_evidence
      .deployment_profile_authority_refusal_cases =
      manifest.release_forward_report_contract.terminal_chain_refusal_evidence
        .deployment_profile_authority_refusal_case_ids;
    delete manifest.release_forward_report_contract
      .terminal_chain_refusal_evidence
      .deployment_profile_authority_refusal_case_ids;
  },
);
assertThrows(
  'v3.4.50 report-contract deployment authority mirror renamed key fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      renamedReportDeploymentAuthorityMirrorV350Fixture.report,
      {
        evidenceDir:
          renamedReportDeploymentAuthorityMirrorV350Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.terminal_chain_refusal_evidence.deployment_profile_authority_refusal_mirror contains unexpected fields'
);

const summaryReportDeploymentAuthorityMirrorV350Fixture =
  makeV350EvidenceFixture();
rewriteManifestArtifact(
  summaryReportDeploymentAuthorityMirrorV350Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.terminal_chain_refusal_evidence
      .deployment_profile_authority_refusal_case_ids = {
        summary: clone(expectedDeploymentProfileAuthorityRefusalCaseIds),
      };
  },
);
assertThrows(
  'v3.4.50 report-contract deployment authority mirror summary-shaped field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      summaryReportDeploymentAuthorityMirrorV350Fixture.report,
      {
        evidenceDir:
          summaryReportDeploymentAuthorityMirrorV350Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.terminal_chain_refusal_evidence.deployment_profile_authority_refusal_mirror case IDs drifted'
);

const trueBoundaryReportDeploymentAuthorityMirrorV350Fixture =
  makeV350EvidenceFixture();
rewriteManifestArtifact(
  trueBoundaryReportDeploymentAuthorityMirrorV350Fixture,
  (manifest) => {
    manifest.release_forward_report_contract.terminal_chain_refusal_evidence
      .external_attestation = true;
  },
);
assertThrows(
  'v3.4.50 report-contract deployment authority mirror false-boundary drift fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      trueBoundaryReportDeploymentAuthorityMirrorV350Fixture.report,
      {
        evidenceDir:
          trueBoundaryReportDeploymentAuthorityMirrorV350Fixture.evidenceDir,
      }
    ),
  'release_forward_report_contract.terminal_chain_refusal_evidence.external_attestation must be false'
);

const futureRegistryVerdictV349Fixture = makeV349EvidenceFixture(
  releaseForwardManifestContractV349({
    terminalBoundary: terminalChainTrustedRegistryVerdict(),
    northStar: terminalChainTrustedRegistryVerdictNorthStar(),
  })
);
assertThrows(
  'v3.4.49 future trusted-registry verdict fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      futureRegistryVerdictV349Fixture.report,
      {
        evidenceDir: futureRegistryVerdictV349Fixture.evidenceDir,
      }
    ),
  'trusted-registry verdict appeared before v3.4.51'
);

const futureDownstreamBoundaryV349Manifest = releaseForwardManifestContractV349();
futureDownstreamBoundaryV349Manifest.release_forward_report_contract
  .product_proof_path.downstream_refusal_boundary =
    downstreamRefusalBoundary();
futureDownstreamBoundaryV349Manifest.release_forward_report_contract
  .product_proof_path.north_star.downstream_refusal_boundary =
    downstreamRefusalBoundary();
const futureDownstreamBoundaryV349Fixture = makeV349EvidenceFixture(
  futureDownstreamBoundaryV349Manifest
);
assertThrows(
  'v3.4.49 future downstream-refusal boundary fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      futureDownstreamBoundaryV349Fixture.report,
      {
        evidenceDir: futureDownstreamBoundaryV349Fixture.evidenceDir,
      }
    ),
  'downstream-refusal boundary appeared before v3.4.51'
);

const contentContract51Fixture = makeV351EvidenceFixture();
const contentContract51Verification = buildPrivateVerifierResultVerification(
  contentContract51Fixture.report,
  {
    evidenceDir: contentContract51Fixture.evidenceDir,
  }
);
assertEqual(
  'v3.4.51 private intake content contract verified',
  true,
  contentContract51Verification.evidence_dir_contract_verification.verified
);
assertEqual(
  'v3.4.51 private intake contract type',
  'product-proof-path-terminal-chain-deployment-profile-authority-refusals-trusted-registry-verdict-and-downstream-refusal-boundary-v1',
  contentContract51Verification.evidence_dir_contract_verification.contract_type
);
assertEqual(
  'v3.4.51 private intake trusted-registry verdict required',
  true,
  contentContract51Verification.evidence_dir_contract_verification
    .terminal_chain_trusted_registry_verdict_required_for_target
);
assertEqual(
  'v3.4.51 private intake trusted-registry verdict preserved',
  true,
  contentContract51Verification.evidence_dir_contract_verification
    .product_proof_path_terminal_chain_trusted_registry_verdict_preserved
);
assertEqual(
  'v3.4.51 private intake north star trusted-registry verdict preserved',
  true,
  contentContract51Verification.evidence_dir_contract_verification
    .north_star_terminal_chain_trusted_registry_verdict_preserved
);
assertEqual(
  'v3.4.51 private intake trusted-registry recognized verdict',
  'RECOGNIZED',
  contentContract51Verification.evidence_dir_contract_verification
    .terminal_chain_trusted_registry_recognition_verdict
);
assertEqual(
  'v3.4.51 private intake trusted-registry signature valid',
  true,
  contentContract51Verification.evidence_dir_contract_verification
    .terminal_chain_trusted_registry_signature_valid
);
assertEqual(
  'v3.4.51 private intake downstream-refusal boundary required',
  true,
  contentContract51Verification.evidence_dir_contract_verification
    .downstream_refusal_boundary_required_for_target
);
assertEqual(
  'v3.4.51 private intake downstream-refusal boundary preserved',
  true,
  contentContract51Verification.evidence_dir_contract_verification
    .product_proof_path_downstream_refusal_boundary_preserved
);
assertEqual(
  'v3.4.51 private intake north star downstream-refusal boundary preserved',
  true,
  contentContract51Verification.evidence_dir_contract_verification
    .north_star_downstream_refusal_boundary_preserved
);
assertEqual(
  'v3.4.51 private intake downstream marker delta',
  1,
  contentContract51Verification.evidence_dir_contract_verification
    .downstream_refusal_recognized_marker_count_delta
);
assertEqual(
  'v3.4.51 private intake downstream refusal case count',
  expectedDownstreamRefusalReasons.length,
  contentContract51Verification.evidence_dir_contract_verification
    .downstream_refusal_case_count
);
assertEqual(
  'v3.4.51 private intake downstream refusals unboarded',
  true,
  contentContract51Verification.evidence_dir_contract_verification
    .downstream_refusal_all_refusals_unboarded
);
assertEqual(
  'v3.4.51 private intake downstream refusal reasons',
  JSON.stringify(expectedDownstreamRefusalReasons),
  JSON.stringify(
    contentContract51Verification.evidence_dir_contract_verification
      .downstream_refusal_reasons
  )
);
assertEqual(
  'v3.4.51 private intake north star downstream refusals unboarded',
  true,
  contentContract51Verification.evidence_dir_contract_verification
    .north_star_downstream_refusal_all_refusals_unboarded
);
assertEqual(
  'v3.4.51 private intake north star downstream refusal reasons',
  JSON.stringify(expectedDownstreamRefusalReasons),
  JSON.stringify(
    contentContract51Verification.evidence_dir_contract_verification
      .north_star_downstream_refusal_reasons
  )
);
const contentContract51Text = formatPrivateVerifierResultVerification(
  contentContract51Verification
);
assert(
  'v3.4.51 private intake text renders trusted-registry requirement',
  contentContract51Text.includes(
    'terminal_chain_trusted_registry_verdict_required_for_target=true'
  )
);
assert(
  'v3.4.51 private intake text renders trusted-registry preservation',
  contentContract51Text.includes(
    'product_proof_path_terminal_chain_trusted_registry_verdict_preserved=true'
  )
);
assert(
  'v3.4.51 private intake text renders north-star trusted-registry preservation',
  contentContract51Text.includes(
    'north_star_terminal_chain_trusted_registry_verdict_preserved=true'
  )
);
assert(
  'v3.4.51 private intake text renders trusted-registry verdict',
  contentContract51Text.includes(
    'terminal_chain_trusted_registry_recognition_verdict=RECOGNIZED'
  )
);
assert(
  'v3.4.51 private intake text renders trusted-registry signature valid',
  contentContract51Text.includes('terminal_chain_trusted_registry_signature_valid=true')
);
assert(
  'v3.4.51 private intake text renders downstream-refusal requirement',
  contentContract51Text.includes(
    'downstream_refusal_boundary_required_for_target=true'
  )
);
assert(
  'v3.4.51 private intake text renders downstream-refusal preservation',
  contentContract51Text.includes(
    'product_proof_path_downstream_refusal_boundary_preserved=true'
  )
);
assert(
  'v3.4.51 private intake text renders north-star downstream-refusal preservation',
  contentContract51Text.includes(
    'north_star_downstream_refusal_boundary_preserved=true'
  )
);
assert(
  'v3.4.51 private intake text renders downstream marker delta',
  contentContract51Text.includes(
    'downstream_refusal_recognized_marker_count_delta=1'
  )
);
assert(
  'v3.4.51 private intake text renders downstream refusals unboarded',
  contentContract51Text.includes(
    'downstream_refusal_all_refusals_unboarded=true'
  )
);
assert(
  'v3.4.51 private intake text renders downstream refusal reasons',
  contentContract51Text.includes(
    `downstream_refusal_reasons=${expectedDownstreamRefusalReasons.join(',')}`
  )
);
assert(
  'v3.4.51 private intake text renders north-star downstream refusals unboarded',
  contentContract51Text.includes(
    'north_star_downstream_refusal_all_refusals_unboarded=true'
  )
);
assert(
  'v3.4.51 private intake text renders north-star downstream refusal reasons',
  contentContract51Text.includes(
    `north_star_downstream_refusal_reasons=${expectedDownstreamRefusalReasons.join(',')}`
  )
);
assert(
  'v3.4.51 private intake text privacy safe',
  !unsafeOutputPattern.test(contentContract51Text)
);
assertEqual(
  'v3.4.51 private intake recognized receipt path mirror not required',
  false,
  contentContract51Verification.evidence_dir_contract_verification
    .terminal_chain_recognized_receipt_path_mirror_required_for_target
);

const prematureReceiptPathMirrorV351Fixture = makeV351EvidenceFixture(
  releaseForwardManifestContractV351({
    terminalBoundary: recognizedReceiptPathMirror(),
    northStar: recognizedReceiptPathMirrorNorthStar(),
  })
);
assertThrows(
  'v3.4.51 recognized receipt path mirror fails before future-local gate',
  () =>
    buildPrivateVerifierResultVerification(
      prematureReceiptPathMirrorV351Fixture.report,
      {
        evidenceDir: prematureReceiptPathMirrorV351Fixture.evidenceDir,
      }
    ),
  'recognized receipt path mirror appeared before v3.4.52'
);

const prematureAdjacentReceiptPathV351Fixture = makeV351EvidenceFixture(
  releaseForwardManifestContractV351({
    terminalBoundary: {
      recognized_receipt_path_summary: { verdict: 'RECOGNIZED' },
    },
  })
);
assertThrows(
  'v3.4.51 adjacent recognized receipt path summary fails before future-local gate',
  () =>
    buildPrivateVerifierResultVerification(
      prematureAdjacentReceiptPathV351Fixture.report,
      {
        evidenceDir: prematureAdjacentReceiptPathV351Fixture.evidenceDir,
      }
    ),
  'recognized receipt path mirror appeared before v3.4.52'
);

const contentContract52Fixture = makeV352EvidenceFixture();
const contentContract52Verification = buildPrivateVerifierResultVerification(
  contentContract52Fixture.report,
  {
    evidenceDir: contentContract52Fixture.evidenceDir,
  }
);
assertEqual(
  'v3.4.52 private intake content contract verified',
  true,
  contentContract52Verification.evidence_dir_contract_verification.verified
);
assertEqual(
  'v3.4.52 private intake contract type',
  'product-proof-path-terminal-chain-recognized-receipt-path-mirror-v1',
  contentContract52Verification.evidence_dir_contract_verification.contract_type
);
assertEqual(
  'v3.4.52 private intake recognized receipt path mirror required',
  true,
  contentContract52Verification.evidence_dir_contract_verification
    .terminal_chain_recognized_receipt_path_mirror_required_for_target
);
assertEqual(
  'v3.4.52 private intake recognized receipt path mirror preserved',
  true,
  contentContract52Verification.evidence_dir_contract_verification
    .product_proof_path_terminal_chain_recognized_receipt_path_mirror_preserved
);
assertEqual(
  'v3.4.52 private intake north star recognized receipt path mirror preserved',
  true,
  contentContract52Verification.evidence_dir_contract_verification
    .north_star_terminal_chain_recognized_receipt_path_mirror_preserved
);
assertEqual(
  'v3.4.52 private intake recognized receipt path sha preserved',
  'f'.repeat(64),
  contentContract52Verification.evidence_dir_contract_verification
    .terminal_chain_recognized_receipt_path_evidence_sha256
);
assertEqual(
  'v3.4.52 private intake recognized receipt path source binding matches',
  true,
  contentContract52Verification.evidence_dir_contract_verification
    .terminal_chain_recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding
);
const contentContract52Text = formatPrivateVerifierResultVerification(
  contentContract52Verification
);
assert(
  'v3.4.52 private intake text renders recognized receipt path requirement',
  contentContract52Text.includes(
    'terminal_chain_recognized_receipt_path_mirror_required_for_target=true'
  )
);
assert(
  'v3.4.52 private intake text renders recognized receipt path preservation',
  contentContract52Text.includes(
    'product_proof_path_terminal_chain_recognized_receipt_path_mirror_preserved=true'
  )
);
assert(
  'v3.4.52 private intake text renders north-star recognized receipt path preservation',
  contentContract52Text.includes(
    'north_star_terminal_chain_recognized_receipt_path_mirror_preserved=true'
  )
);
assert(
  'v3.4.52 private intake text privacy safe',
  !unsafeOutputPattern.test(contentContract52Text)
);

const missingReceiptPathMirrorV352Manifest = releaseForwardManifestContractV352();
delete missingReceiptPathMirrorV352Manifest.release_forward_report_contract
  .product_proof_path.terminal_chain_boundary
  .recognized_receipt_path_evidence_sha256;
const missingReceiptPathMirrorV352Fixture = makeV352EvidenceFixture(
  missingReceiptPathMirrorV352Manifest
);
assertThrows(
  'v3.4.52 missing recognized receipt path mirror field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(missingReceiptPathMirrorV352Fixture.report, {
      evidenceDir: missingReceiptPathMirrorV352Fixture.evidenceDir,
    }),
  'recognized receipt path mirror drifted'
);

const extraReceiptPathMirrorV352Fixture = makeV352EvidenceFixture(
  releaseForwardManifestContractV352({
    terminalBoundary: {
      recognized_receipt_path_evidence_summary: {
        verdict: 'RECOGNIZED',
      },
    },
  })
);
assertThrows(
  'v3.4.52 extra recognized receipt path mirror field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(extraReceiptPathMirrorV352Fixture.report, {
      evidenceDir: extraReceiptPathMirrorV352Fixture.evidenceDir,
    }),
  'recognized receipt path mirror drifted'
);

const adjacentReceiptPathMirrorV352Fixture = makeV352EvidenceFixture(
  releaseForwardManifestContractV352({
    terminalBoundary: {
      recognized_receipt_path_summary: {
        verdict: 'RECOGNIZED',
      },
    },
  })
);
assertThrows(
  'v3.4.52 adjacent recognized receipt path terminal summary fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      adjacentReceiptPathMirrorV352Fixture.report,
      {
        evidenceDir: adjacentReceiptPathMirrorV352Fixture.evidenceDir,
      }
    ),
  'recognized receipt path mirror drifted'
);

const adjacentNorthStarReceiptPathMirrorV352Fixture = makeV352EvidenceFixture(
  releaseForwardManifestContractV352({
    northStar: {
      terminal_chain_recognized_receipt_path_summary: {
        verdict: 'RECOGNIZED',
      },
    },
  })
);
assertThrows(
  'v3.4.52 adjacent recognized receipt path north-star summary fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      adjacentNorthStarReceiptPathMirrorV352Fixture.report,
      {
        evidenceDir: adjacentNorthStarReceiptPathMirrorV352Fixture.evidenceDir,
      }
    ),
  'recognized receipt path mirror drifted'
);

const renamedReceiptPathMirrorV352Manifest = releaseForwardManifestContractV352();
const renamedReceiptPathMirrorV352Boundary =
  renamedReceiptPathMirrorV352Manifest.release_forward_report_contract
    .product_proof_path.terminal_chain_boundary;
renamedReceiptPathMirrorV352Boundary.recognized_receipt_path_evidence_hash =
  renamedReceiptPathMirrorV352Boundary.recognized_receipt_path_evidence_sha256;
delete renamedReceiptPathMirrorV352Boundary.recognized_receipt_path_evidence_sha256;
const renamedReceiptPathMirrorV352Fixture = makeV352EvidenceFixture(
  renamedReceiptPathMirrorV352Manifest
);
assertThrows(
  'v3.4.52 renamed recognized receipt path mirror field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(renamedReceiptPathMirrorV352Fixture.report, {
      evidenceDir: renamedReceiptPathMirrorV352Fixture.evidenceDir,
    }),
  'recognized receipt path mirror drifted'
);

const summaryReceiptPathMirrorV352Fixture = makeV352EvidenceFixture(
  releaseForwardManifestContractV352({
    receiptPathMirror: {
      recognized_receipt_path_evidence_sha256: {
        sha256: 'f'.repeat(64),
      },
    },
  })
);
assertThrows(
  'v3.4.52 summary-shaped recognized receipt path mirror field fails private intake',
  () =>
    buildPrivateVerifierResultVerification(summaryReceiptPathMirrorV352Fixture.report, {
      evidenceDir: summaryReceiptPathMirrorV352Fixture.evidenceDir,
    }),
  'recognized receipt path mirror drifted'
);

const tamperedReceiptPathMirrorV352Fixture = makeV352EvidenceFixture(
  releaseForwardManifestContractV352({
    receiptPathMirror: {
      recognized_receipt_path_evidence_sha256: '0'.repeat(64),
    },
  })
);
assertThrows(
  'v3.4.52 tampered recognized receipt path evidence sha fails private intake',
  () =>
    buildPrivateVerifierResultVerification(tamperedReceiptPathMirrorV352Fixture.report, {
      evidenceDir: tamperedReceiptPathMirrorV352Fixture.evidenceDir,
    }),
  'recognized receipt path mirror drifted'
);

const mismatchedReceiptPathSourceV352Fixture = makeV352EvidenceFixture(
  releaseForwardManifestContractV352({
    receiptPathMirror: {
      recognized_receipt_path_evidence_source_binding_sha256: '1'.repeat(64),
    },
  })
);
assertThrows(
  'v3.4.52 recognized receipt path source-binding mismatch fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      mismatchedReceiptPathSourceV352Fixture.report,
      {
        evidenceDir: mismatchedReceiptPathSourceV352Fixture.evidenceDir,
      }
    ),
  'recognized receipt path mirror drifted'
);

const falseBoundaryReceiptPathMirrorV352Fixture = makeV352EvidenceFixture(
  releaseForwardManifestContractV352({
    receiptPathMirror: {
      recognized_receipt_path_evidence_public_external_attestation: true,
    },
  })
);
assertThrows(
  'v3.4.52 recognized receipt path false-boundary flip fails private intake',
  () =>
    buildPrivateVerifierResultVerification(
      falseBoundaryReceiptPathMirrorV352Fixture.report,
      {
        evidenceDir: falseBoundaryReceiptPathMirrorV352Fixture.evidenceDir,
      }
    ),
  'recognized receipt path mirror drifted'
);

const driftedV351RegistryVerdictFixture = makeV351EvidenceFixture(
  releaseForwardManifestContractV351({
    terminalBoundary: {
      trusted_issuer_registry_recognition_verdict: 'RECOGNITION-REFUSED',
    },
  })
);
assertThrows(
  'v3.4.51 trusted-registry verdict drift fails',
  () =>
    buildPrivateVerifierResultVerification(driftedV351RegistryVerdictFixture.report, {
      evidenceDir: driftedV351RegistryVerdictFixture.evidenceDir,
    }),
  'trusted-registry verdict drifted'
);

const driftedV351NorthStarRegistryFixture = makeV351EvidenceFixture(
  releaseForwardManifestContractV351({
    northStar: {
      terminal_chain_trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated:
        false,
    },
  })
);
assertThrows(
  'v3.4.51 north star trusted-registry verdict drift fails',
  () =>
    buildPrivateVerifierResultVerification(driftedV351NorthStarRegistryFixture.report, {
      evidenceDir: driftedV351NorthStarRegistryFixture.evidenceDir,
    }),
  'trusted-registry verdict drifted'
);

const extraKeyV351RegistryVerdictFixture = makeV351EvidenceFixture(
  releaseForwardManifestContractV351({
    terminalBoundary: {
      trusted_issuer_registry_recognition_production_claim: false,
    },
  })
);
assertThrows(
  'v3.4.51 trusted-registry verdict extra prefixed key fails',
  () =>
    buildPrivateVerifierResultVerification(extraKeyV351RegistryVerdictFixture.report, {
      evidenceDir: extraKeyV351RegistryVerdictFixture.evidenceDir,
    }),
  'trusted-registry verdict drifted'
);

const extraKeyV351NorthStarRegistryVerdictFixture = makeV351EvidenceFixture(
  releaseForwardManifestContractV351({
    northStar: {
      terminal_chain_trusted_issuer_registry_recognition_production_claim: false,
    },
  })
);
assertThrows(
  'v3.4.51 north star trusted-registry verdict extra prefixed key fails',
  () =>
    buildPrivateVerifierResultVerification(
      extraKeyV351NorthStarRegistryVerdictFixture.report,
      {
        evidenceDir: extraKeyV351NorthStarRegistryVerdictFixture.evidenceDir,
      }
    ),
  'trusted-registry verdict drifted'
);

const missingKeyV351RegistryVerdictManifest = releaseForwardManifestContractV351();
delete missingKeyV351RegistryVerdictManifest.release_forward_report_contract
  .product_proof_path.terminal_chain_boundary
  .trusted_issuer_registry_recognition_signature_valid;
const missingKeyV351RegistryVerdictFixture = makeV351EvidenceFixture(
  missingKeyV351RegistryVerdictManifest
);
assertThrows(
  'v3.4.51 trusted-registry verdict missing key fails',
  () =>
    buildPrivateVerifierResultVerification(missingKeyV351RegistryVerdictFixture.report, {
      evidenceDir: missingKeyV351RegistryVerdictFixture.evidenceDir,
    }),
  'trusted-registry verdict drifted'
);

const renamedKeyV351RegistryVerdictManifest = releaseForwardManifestContractV351();
const renamedKeyV351RegistryBoundary =
  renamedKeyV351RegistryVerdictManifest.release_forward_report_contract
    .product_proof_path.terminal_chain_boundary;
renamedKeyV351RegistryBoundary.trusted_issuer_registry_recognition_signature_ok =
  renamedKeyV351RegistryBoundary.trusted_issuer_registry_recognition_signature_valid;
delete renamedKeyV351RegistryBoundary.trusted_issuer_registry_recognition_signature_valid;
const renamedKeyV351RegistryVerdictFixture = makeV351EvidenceFixture(
  renamedKeyV351RegistryVerdictManifest
);
assertThrows(
  'v3.4.51 trusted-registry verdict renamed key fails',
  () =>
    buildPrivateVerifierResultVerification(renamedKeyV351RegistryVerdictFixture.report, {
      evidenceDir: renamedKeyV351RegistryVerdictFixture.evidenceDir,
    }),
  'trusted-registry verdict drifted'
);

const summaryShapedV351RegistryVerdictFixture = makeV351EvidenceFixture(
  releaseForwardManifestContractV351({
    terminalBoundary: {
      trusted_issuer_registry_recognition_summary: {
        verdict: 'RECOGNIZED',
        recognized: true,
        issuer_status: 'active',
      },
    },
  })
);
assertThrows(
  'v3.4.51 trusted-registry verdict summary-shaped prefixed key fails',
  () =>
    buildPrivateVerifierResultVerification(summaryShapedV351RegistryVerdictFixture.report, {
      evidenceDir: summaryShapedV351RegistryVerdictFixture.evidenceDir,
    }),
  'trusted-registry verdict drifted'
);

const driftedV351DownstreamBoundaryFixture = makeV351EvidenceFixture(
  releaseForwardManifestContractV351({
    downstreamBoundary: {
      all_refusal_marker_count_deltas_zero: false,
    },
  })
);
assertThrows(
  'v3.4.51 downstream-refusal boundary drift fails',
  () =>
    buildPrivateVerifierResultVerification(driftedV351DownstreamBoundaryFixture.report, {
      evidenceDir: driftedV351DownstreamBoundaryFixture.evidenceDir,
    }),
  'downstream-refusal boundary drifted'
);

const driftedV351NorthStarDownstreamBoundaryFixture = makeV351EvidenceFixture(
  releaseForwardManifestContractV351({
    northStar: {
      downstream_refusal_boundary: downstreamRefusalBoundary({
        recognized_marker_count_delta: 0,
      }),
    },
  })
);
assertThrows(
  'v3.4.51 north star downstream-refusal boundary drift fails',
  () =>
    buildPrivateVerifierResultVerification(
      driftedV351NorthStarDownstreamBoundaryFixture.report,
      {
        evidenceDir: driftedV351NorthStarDownstreamBoundaryFixture.evidenceDir,
      }
  ),
  'downstream-refusal boundary drifted'
);

const extraKeyV351DownstreamBoundaryFixture = makeV351EvidenceFixture(
  releaseForwardManifestContractV351({
    downstreamBoundary: {
      summary_type: 'claim-shaped-boundary-summary',
    },
  })
);
assertThrows(
  'v3.4.51 downstream-refusal boundary extra key fails',
  () =>
    buildPrivateVerifierResultVerification(extraKeyV351DownstreamBoundaryFixture.report, {
      evidenceDir: extraKeyV351DownstreamBoundaryFixture.evidenceDir,
    }),
  'downstream-refusal boundary drifted'
);

const extraKeyV351NorthStarDownstreamBoundaryFixture = makeV351EvidenceFixture(
  releaseForwardManifestContractV351({
    northStar: {
      downstream_refusal_boundary: downstreamRefusalBoundary({
        summary_type: 'claim-shaped-boundary-summary',
      }),
    },
  })
);
assertThrows(
  'v3.4.51 north star downstream-refusal boundary extra key fails',
  () =>
    buildPrivateVerifierResultVerification(
      extraKeyV351NorthStarDownstreamBoundaryFixture.report,
      {
        evidenceDir: extraKeyV351NorthStarDownstreamBoundaryFixture.evidenceDir,
      }
    ),
  'downstream-refusal boundary drifted'
);

const missingKeyV351DownstreamBoundaryManifest = releaseForwardManifestContractV351();
delete missingKeyV351DownstreamBoundaryManifest.release_forward_report_contract
  .product_proof_path.downstream_refusal_boundary.final_marker_count;
const missingKeyV351DownstreamBoundaryFixture = makeV351EvidenceFixture(
  missingKeyV351DownstreamBoundaryManifest
);
assertThrows(
  'v3.4.51 downstream-refusal boundary missing key fails',
  () =>
    buildPrivateVerifierResultVerification(missingKeyV351DownstreamBoundaryFixture.report, {
      evidenceDir: missingKeyV351DownstreamBoundaryFixture.evidenceDir,
    }),
  'downstream-refusal boundary drifted'
);

const renamedKeyV351DownstreamBoundaryManifest = releaseForwardManifestContractV351();
const renamedKeyV351DownstreamBoundary =
  renamedKeyV351DownstreamBoundaryManifest.release_forward_report_contract
    .product_proof_path.downstream_refusal_boundary;
renamedKeyV351DownstreamBoundary.final_marker_total =
  renamedKeyV351DownstreamBoundary.final_marker_count;
delete renamedKeyV351DownstreamBoundary.final_marker_count;
const renamedKeyV351DownstreamBoundaryFixture = makeV351EvidenceFixture(
  renamedKeyV351DownstreamBoundaryManifest
);
assertThrows(
  'v3.4.51 downstream-refusal boundary renamed key fails',
  () =>
    buildPrivateVerifierResultVerification(renamedKeyV351DownstreamBoundaryFixture.report, {
      evidenceDir: renamedKeyV351DownstreamBoundaryFixture.evidenceDir,
    }),
  'downstream-refusal boundary drifted'
);

const summaryShapedV351DownstreamBoundaryFixture = makeV351EvidenceFixture(
  releaseForwardManifestContractV351({
    downstreamBoundary: {
      ...downstreamRefusalBoundary(),
      summary: {
        refusal_reasons: clone(expectedDownstreamRefusalReasons),
        expected_keys: clone(expectedDownstreamRefusalBoundaryKeys),
      },
    },
  })
);
assertThrows(
  'v3.4.51 downstream-refusal boundary summary-shaped object fails',
  () =>
    buildPrivateVerifierResultVerification(
      summaryShapedV351DownstreamBoundaryFixture.report,
      {
        evidenceDir: summaryShapedV351DownstreamBoundaryFixture.evidenceDir,
      }
    ),
  'downstream-refusal boundary drifted'
);

const driftedV349StaleArtifactFixture = makeV349EvidenceFixture(
  releaseForwardManifestContractV349({
    deploymentBridge: {
      stale_deployment_profile_artifact_refused_before_service_proof: false,
    },
  })
);
assertThrows(
  'v3.4.49 stale deployment artifact refusal drift fails',
  () =>
    buildPrivateVerifierResultVerification(driftedV349StaleArtifactFixture.report, {
      evidenceDir: driftedV349StaleArtifactFixture.evidenceDir,
    }),
  'deployment-profile authority refusals drifted'
);

const driftedV349MismatchFixture = makeV349EvidenceFixture(
  releaseForwardManifestContractV349({
    deploymentBridge: {
      profile_recognition_mismatch_refused_before_service_proof: false,
    },
  })
);
assertThrows(
  'v3.4.49 profile mismatch refusal drift fails',
  () =>
    buildPrivateVerifierResultVerification(driftedV349MismatchFixture.report, {
      evidenceDir: driftedV349MismatchFixture.evidenceDir,
    }),
  'deployment-profile authority refusals drifted'
);

const driftedV349CaseIdFixture = makeV349EvidenceFixture(
  releaseForwardManifestContractV349({
    deploymentBridge: {
      deployment_profile_authority_refusal_case_ids: [
        'drifted_case',
        ...expectedDeploymentProfileAuthorityRefusalCaseIds.slice(1),
      ],
    },
  })
);
assertThrows(
  'v3.4.49 authority refusal case ID drift fails',
  () =>
    buildPrivateVerifierResultVerification(driftedV349CaseIdFixture.report, {
      evidenceDir: driftedV349CaseIdFixture.evidenceDir,
    }),
  'deployment-profile authority refusals drifted'
);

const driftedV349NorthStarFixture = makeV349EvidenceFixture(
  releaseForwardManifestContractV349({
    northStar: {
      deployment_profile_authority_refusals_preserved: false,
    },
  })
);
assertThrows(
  'v3.4.49 north star authority refusal mirror drift fails',
  () =>
    buildPrivateVerifierResultVerification(driftedV349NorthStarFixture.report, {
      evidenceDir: driftedV349NorthStarFixture.evidenceDir,
    }),
  'deployment-profile authority refusals drifted'
);

const missingDeploymentBridgeFixture = makeV348EvidenceFixture(
  releaseForwardManifestContractV348({ deploymentBridge: null })
);
assertThrows(
  'v3.4.48 missing deployment bridge fails despite matching hashes',
  () =>
    buildPrivateVerifierResultVerification(missingDeploymentBridgeFixture.report, {
      evidenceDir: missingDeploymentBridgeFixture.evidenceDir,
    }),
  'deployment-profile authority bridge drifted'
);

const driftedDeploymentBridgeCountFixture = makeV348EvidenceFixture(
  releaseForwardManifestContractV348({
    deploymentBridge: {
      observed_refusal_case_count: 17,
    },
  })
);
assertThrows(
  'v3.4.48 deployment bridge refusal count drift fails',
  () =>
    buildPrivateVerifierResultVerification(driftedDeploymentBridgeCountFixture.report, {
      evidenceDir: driftedDeploymentBridgeCountFixture.evidenceDir,
    }),
  'deployment-profile authority bridge drifted'
);

const driftedDeploymentBridgeAuthorityFixture = makeV348EvidenceFixture(
  releaseForwardManifestContractV348({
    deploymentBridge: {
      request_stream_authority_material_accepted: true,
    },
  })
);
assertThrows(
  'v3.4.48 deployment bridge request authority drift fails',
  () =>
    buildPrivateVerifierResultVerification(driftedDeploymentBridgeAuthorityFixture.report, {
      evidenceDir: driftedDeploymentBridgeAuthorityFixture.evidenceDir,
    }),
  'deployment-profile authority bridge drifted'
);

const driftedDeploymentBridgeCurrentFixture = makeV348EvidenceFixture(
  releaseForwardManifestContractV348({
    deploymentBridge: {
      current_machine_governance: true,
    },
  })
);
assertThrows(
  'v3.4.48 deployment bridge current-machine claim fails',
  () =>
    buildPrivateVerifierResultVerification(driftedDeploymentBridgeCurrentFixture.report, {
      evidenceDir: driftedDeploymentBridgeCurrentFixture.evidenceDir,
    }),
  'deployment-profile authority bridge drifted'
);

const driftedDeploymentBridgeProductionFixture = makeV348EvidenceFixture(
  releaseForwardManifestContractV348({
    deploymentBridge: {
      production_authority: true,
    },
  })
);
assertThrows(
  'v3.4.48 deployment bridge production claim fails',
  () =>
    buildPrivateVerifierResultVerification(driftedDeploymentBridgeProductionFixture.report, {
      evidenceDir: driftedDeploymentBridgeProductionFixture.evidenceDir,
    }),
  'deployment-profile authority bridge drifted'
);

const driftedDeploymentBridgeNorthStarFixture = makeV348EvidenceFixture(
  releaseForwardManifestContractV348({
    northStar: {
      deployment_profile_authority_bridge_preserved: false,
    },
  })
);
assertThrows(
  'v3.4.48 deployment bridge north-star mirror drift fails',
  () =>
    buildPrivateVerifierResultVerification(driftedDeploymentBridgeNorthStarFixture.report, {
      evidenceDir: driftedDeploymentBridgeNorthStarFixture.evidenceDir,
    }),
  'deployment-profile authority bridge drifted'
);

const mismatchFixture = makeEvidenceFixture();
writeFileSync(artifactFilePath(mismatchFixture.evidenceDir, 'DRY-RUN-MANIFEST.json'), 'wrong hash\n');
assertThrows(
  'evidence-dir hash mismatch fails',
  () => buildPrivateVerifierResultVerification(mismatchFixture.report, { evidenceDir: mismatchFixture.evidenceDir }),
  'artifact hash mismatch: DRY-RUN-MANIFEST.json'
);

const sha256SumsExtraRowFixture = makeEvidenceFixture();
rewriteEvidenceText(
  sha256SumsExtraRowFixture,
  'SHA256SUMS',
  `${readEvidenceText(sha256SumsExtraRowFixture, 'SHA256SUMS')}${'f'.repeat(64)}  private-intake-summary.json\n`,
);
assertThrows(
  'SHA256SUMS extra row fails evidence-dir intake',
  () =>
    buildPrivateVerifierResultVerification(sha256SumsExtraRowFixture.report, {
      evidenceDir: sha256SumsExtraRowFixture.evidenceDir,
    }),
  'SHA256SUMS row path set drifted'
);

const sha256SumsMissingRowFixture = makeEvidenceFixture();
rewriteEvidenceText(
  sha256SumsMissingRowFixture,
  'SHA256SUMS',
  readEvidenceText(sha256SumsMissingRowFixture, 'SHA256SUMS')
    .split('\n')
    .filter(Boolean)
    .filter((line) => !line.includes('zlar-verifier-env-report-v0.json'))
    .join('\n')
    .concat('\n'),
);
assertThrows(
  'SHA256SUMS missing row fails evidence-dir intake',
  () =>
    buildPrivateVerifierResultVerification(sha256SumsMissingRowFixture.report, {
      evidenceDir: sha256SumsMissingRowFixture.evidenceDir,
    }),
  'SHA256SUMS row path set drifted'
);

const sha256SumsRenamedRowFixture = makeEvidenceFixture();
rewriteEvidenceText(
  sha256SumsRenamedRowFixture,
  'SHA256SUMS',
  readEvidenceText(sha256SumsRenamedRowFixture, 'SHA256SUMS').replace(
    'zlar-verifier-env-report-v0.json',
    'zlar-verifier-env-report-summary.json',
  ),
);
assertThrows(
  'SHA256SUMS renamed row fails evidence-dir intake',
  () =>
    buildPrivateVerifierResultVerification(sha256SumsRenamedRowFixture.report, {
      evidenceDir: sha256SumsRenamedRowFixture.evidenceDir,
    }),
  'SHA256SUMS row path set drifted'
);

const sha256SumsRowHashDriftFixture = makeEvidenceFixture();
rewriteEvidenceText(
  sha256SumsRowHashDriftFixture,
  'SHA256SUMS',
  readEvidenceText(sha256SumsRowHashDriftFixture, 'SHA256SUMS').replace(
    /^[0-9a-f]{64}/,
    'f'.repeat(64),
  ),
);
assertThrows(
  'SHA256SUMS row hash drift fails evidence-dir intake',
  () =>
    buildPrivateVerifierResultVerification(sha256SumsRowHashDriftFixture.report, {
      evidenceDir: sha256SumsRowHashDriftFixture.evidenceDir,
    }),
  'SHA256SUMS row hash drifted'
);

const sha256SumsMalformedLineFixture = makeEvidenceFixture();
rewriteEvidenceText(
  sha256SumsMalformedLineFixture,
  'SHA256SUMS',
  readEvidenceText(sha256SumsMalformedLineFixture, 'SHA256SUMS').replace(
    '  zlar-verifier-env-report-v0.json',
    ' zlar-verifier-env-report-v0.json',
  ),
);
assertThrows(
  'SHA256SUMS malformed line fails evidence-dir intake',
  () =>
    buildPrivateVerifierResultVerification(sha256SumsMalformedLineFixture.report, {
      evidenceDir: sha256SumsMalformedLineFixture.evidenceDir,
    }),
  'SHA256SUMS contains invalid checksum line'
);

const runSha256SumsExtraRowFixture = makeEvidenceFixture();
rewriteEvidenceText(
  runSha256SumsExtraRowFixture,
  'RUN-SHA256SUMS',
  `${readEvidenceText(runSha256SumsExtraRowFixture, 'RUN-SHA256SUMS')}${'f'.repeat(64)}  evidence-summary.txt\n`,
);
assertThrows(
  'RUN-SHA256SUMS extra row fails evidence-dir intake',
  () =>
    buildPrivateVerifierResultVerification(runSha256SumsExtraRowFixture.report, {
      evidenceDir: runSha256SumsExtraRowFixture.evidenceDir,
    }),
  'RUN-SHA256SUMS row path set drifted'
);

const runSha256SumsMissingRowFixture = makeEvidenceFixture();
rewriteEvidenceText(
  runSha256SumsMissingRowFixture,
  'RUN-SHA256SUMS',
  readEvidenceText(runSha256SumsMissingRowFixture, 'RUN-SHA256SUMS')
    .split('\n')
    .filter(Boolean)
    .filter((line) => !line.includes('target-status.txt'))
    .join('\n')
    .concat('\n'),
);
assertThrows(
  'RUN-SHA256SUMS missing row fails evidence-dir intake',
  () =>
    buildPrivateVerifierResultVerification(runSha256SumsMissingRowFixture.report, {
      evidenceDir: runSha256SumsMissingRowFixture.evidenceDir,
    }),
  'RUN-SHA256SUMS row path set drifted'
);

const runSha256SumsRenamedRowFixture = makeEvidenceFixture();
rewriteEvidenceText(
  runSha256SumsRenamedRowFixture,
  'RUN-SHA256SUMS',
  readEvidenceText(runSha256SumsRenamedRowFixture, 'RUN-SHA256SUMS').replace(
    'transcript.txt',
    'transcript-summary.txt',
  ),
);
assertThrows(
  'RUN-SHA256SUMS renamed row fails evidence-dir intake',
  () =>
    buildPrivateVerifierResultVerification(runSha256SumsRenamedRowFixture.report, {
      evidenceDir: runSha256SumsRenamedRowFixture.evidenceDir,
    }),
  'RUN-SHA256SUMS row path set drifted'
);

const runSha256SumsRowHashDriftFixture = makeEvidenceFixture();
rewriteEvidenceText(
  runSha256SumsRowHashDriftFixture,
  'RUN-SHA256SUMS',
  readEvidenceText(runSha256SumsRowHashDriftFixture, 'RUN-SHA256SUMS').replace(
    /^[0-9a-f]{64}/,
    'f'.repeat(64),
  ),
);
assertThrows(
  'RUN-SHA256SUMS row hash drift fails evidence-dir intake',
  () =>
    buildPrivateVerifierResultVerification(runSha256SumsRowHashDriftFixture.report, {
      evidenceDir: runSha256SumsRowHashDriftFixture.evidenceDir,
    }),
  'RUN-SHA256SUMS row hash drifted'
);

const missingFileFixture = makeEvidenceFixture();
rmSync(artifactFilePath(missingFileFixture.evidenceDir, 'SHA256SUMS'));
assertThrows(
  'evidence-dir missing file fails',
  () => buildPrivateVerifierResultVerification(missingFileFixture.report, { evidenceDir: missingFileFixture.evidenceDir }),
  'artifact file missing: SHA256SUMS'
);

const symlinkFileFixture = makeEvidenceFixture();
rmSync(artifactFilePath(symlinkFileFixture.evidenceDir, 'DRY-RUN-MANIFEST.json'));
symlinkSync('SHA256SUMS', artifactFilePath(symlinkFileFixture.evidenceDir, 'DRY-RUN-MANIFEST.json'));
assertThrows(
  'evidence-dir symlink file fails',
  () => buildPrivateVerifierResultVerification(symlinkFileFixture.report, { evidenceDir: symlinkFileFixture.evidenceDir }),
  'artifact file must not be a symlink: DRY-RUN-MANIFEST.json'
);

console.log('\n-- cli --');
const sampleJson = runZlar(['private-verifier-result', 'verify', '--sample', '--json']);
assertEqual('sample json exits zero', 0, sampleJson.status);
assertEqual('sample json emits no stderr', '', sampleJson.stderr);
assert('sample json privacy safe', !unsafeOutputPattern.test(sampleJson.stdout));
const sampleVerification = JSON.parse(sampleJson.stdout);
assertEqual('sample json verified', true, sampleVerification.verified);
assertEqual('sample json result sha', sha256Text(fixtureText), sampleVerification.result_sha256);
assertEqual(
  'sample json artifact set sha',
  artifactSetSha256(fixture.evidence.artifact_hashes),
  sampleVerification.artifact_set_sha256
);
assertEqual('sample json private by default', true, sampleVerification.private_by_default);
assertEqual('sample json no public attestation', false, sampleVerification.public_external_attestation);
assertEqual('sample json evidence-dir hash check not run', false, sampleVerification.evidence_dir_hash_verification.hashes_recomputed);
assertEqual(
  'sample json envelope-only posture',
  'private-result-envelope-only',
  sampleVerification.required_identity.command_posture
);
assertEqual('sample json result sha not required', false, sampleVerification.required_identity.result_sha256_required);

const sampleText = runZlar(['private-verifier-result', 'verify', '--sample']);
assertEqual('sample text exits zero', 0, sampleText.status);
assertEqual('sample text emits no stderr', '', sampleText.stderr);
assert('sample text title present', sampleText.stdout.includes('ZLAR Private Verifier Result Verification v1'));
assert('sample text names result sha', sampleText.stdout.includes(`result_sha256=${sha256Text(fixtureText)}`));
assert(
  'sample text names artifact set sha',
  sampleText.stdout.includes(`artifact_set_sha256=${artifactSetSha256(fixture.evidence.artifact_hashes)}`)
);
assert(
  'sample text names required posture',
  sampleText.stdout.includes('required_identity.command_posture=private-result-envelope-only')
);
assert('sample text names private boundary', sampleText.stdout.includes('private_by_default=true'));
assert('sample text names public attestation false', sampleText.stdout.includes('public_external_attestation=false'));
assert('sample text names evidence-dir not run', sampleText.stdout.includes('evidence_dir_hash_verification=not-run'));
assert('sample text privacy safe', !unsafeOutputPattern.test(sampleText.stdout));

const stdinJson = runZlar(['private-verifier-result', 'verify', '--input', '-', '--json'], fixtureText);
assertEqual('stdin json exits zero', 0, stdinJson.status);
assertEqual('stdin json emits no stderr', '', stdinJson.stderr);
assertEqual('stdin json matches sample json', sampleJson.stdout, stdinJson.stdout);

const cliEvidenceFixture = makeEvidenceFixture();
const cliEvidence = runZlar(
  ['private-verifier-result', 'verify', '--input', '-', '--evidence-dir', cliEvidenceFixture.evidenceDir, '--json'],
  JSON.stringify(cliEvidenceFixture.report)
);
assertEqual('cli evidence-dir exits zero', 0, cliEvidence.status);
assertEqual('cli evidence-dir emits no stderr', '', cliEvidence.stderr);
assert('cli evidence-dir privacy safe', !unsafeOutputPattern.test(cliEvidence.stdout));
const cliEvidenceVerification = JSON.parse(cliEvidence.stdout);
assertEqual(
  'cli evidence-dir hashes recomputed',
  true,
  cliEvidenceVerification.evidence_dir_hash_verification.hashes_recomputed
);
assertEqual(
  'cli pre-v3.4.46 evidence-dir contract not required',
  false,
  cliEvidenceVerification.evidence_dir_contract_verification.required_for_target
);

const cliRequiredFixture = makeEvidenceFixture();
const cliRequiredInput = JSON.stringify(cliRequiredFixture.report);
const cliRequiredTarget = `${cliRequiredFixture.report.target.release_tag}@${cliRequiredFixture.report.target.commit_sha}`;
const cliRequiredArtifactSetSha = artifactSetSha256(cliRequiredFixture.report.evidence.artifact_hashes);
const cliRequired = runZlar(
  [
    'private-verifier-result',
    'verify',
    '--input',
    '-',
    '--evidence-dir',
    cliRequiredFixture.evidenceDir,
    '--require-result-sha',
    sha256Text(cliRequiredInput),
    '--require-target',
    cliRequiredTarget,
    '--require-bundle-sha',
    cliRequiredFixture.report.evidence.received_bundle_sha256,
    '--require-artifact-set-sha',
    cliRequiredArtifactSetSha,
    '--require-recomputed-evidence',
    '--json',
  ],
  cliRequiredInput
);
assertEqual('cli required identity exits zero', 0, cliRequired.status);
assertEqual('cli required identity emits no stderr', '', cliRequired.stderr);
assert('cli required identity privacy safe', !unsafeOutputPattern.test(cliRequired.stdout));
const cliRequiredVerification = JSON.parse(cliRequired.stdout);
assertEqual('cli required identity result sha', sha256Text(cliRequiredInput), cliRequiredVerification.result_sha256);
assertEqual('cli required identity artifact set sha', cliRequiredArtifactSetSha, cliRequiredVerification.artifact_set_sha256);
assertEqual(
  'cli required identity command posture',
  'private-result-with-required-recomputed-evidence',
  cliRequiredVerification.required_identity.command_posture
);
assertEqual('cli required identity result sha matched', true, cliRequiredVerification.required_identity.result_sha256_matched);
assertEqual('cli required identity target matched', true, cliRequiredVerification.required_identity.target_matched);
assertEqual('cli required identity bundle matched', true, cliRequiredVerification.required_identity.bundle_sha256_matched);
assertEqual(
  'cli required identity artifact set matched',
  true,
  cliRequiredVerification.required_identity.artifact_set_sha256_matched
);
assertEqual(
  'cli required identity recompute matched',
  true,
  cliRequiredVerification.required_identity.recomputed_evidence_matched
);

const cliResultShaMismatch = runZlar(
  ['private-verifier-result', 'verify', '--input', '-', '--require-result-sha', 'f'.repeat(64)],
  cliRequiredInput
);
assert('cli result sha mismatch exits nonzero', cliResultShaMismatch.status !== 0);
assertEqual('cli result sha mismatch emits no stdout', '', cliResultShaMismatch.stdout);
assert(
  'cli result sha mismatch names requirement',
  cliResultShaMismatch.stderr.includes('required result sha mismatch')
);
assert('cli result sha mismatch privacy safe', !unsafeOutputPattern.test(cliResultShaMismatch.stderr));

const cliTargetMismatch = runZlar(
  [
    'private-verifier-result',
    'verify',
    '--input',
    '-',
    '--require-target',
    `${cliRequiredFixture.report.target.release_tag}@${'f'.repeat(40)}`,
  ],
  cliRequiredInput
);
assert('cli target mismatch exits nonzero', cliTargetMismatch.status !== 0);
assertEqual('cli target mismatch emits no stdout', '', cliTargetMismatch.stdout);
assert('cli target mismatch names requirement', cliTargetMismatch.stderr.includes('required target mismatch'));
assert('cli target mismatch privacy safe', !unsafeOutputPattern.test(cliTargetMismatch.stderr));

const cliMalformedTarget = runZlar(
  ['private-verifier-result', 'verify', '--input', '-', '--require-target', 'latest'],
  cliRequiredInput
);
assert('cli malformed target exits nonzero', cliMalformedTarget.status !== 0);
assertEqual('cli malformed target emits no stdout', '', cliMalformedTarget.stdout);
assert(
  'cli malformed target names syntax',
  cliMalformedTarget.stderr.includes('--require-target must be <release>@<commit>')
);
assert('cli malformed target privacy safe', !unsafeOutputPattern.test(cliMalformedTarget.stderr));

const cliMalformedResultSha = runZlar(
  ['private-verifier-result', 'verify', '--input', '-', '--require-result-sha', 'not-a-sha'],
  cliRequiredInput
);
assert('cli malformed result sha exits nonzero', cliMalformedResultSha.status !== 0);
assertEqual('cli malformed result sha emits no stdout', '', cliMalformedResultSha.stdout);
assert(
  'cli malformed result sha names syntax',
  cliMalformedResultSha.stderr.includes('--require-result-sha must be 64 lowercase hex')
);
assert('cli malformed result sha privacy safe', !unsafeOutputPattern.test(cliMalformedResultSha.stderr));

const cliMalformedBundleSha = runZlar(
  ['private-verifier-result', 'verify', '--input', '-', '--require-bundle-sha', 'not-a-sha'],
  cliRequiredInput
);
assert('cli malformed bundle sha exits nonzero', cliMalformedBundleSha.status !== 0);
assertEqual('cli malformed bundle sha emits no stdout', '', cliMalformedBundleSha.stdout);
assert(
  'cli malformed bundle sha names syntax',
  cliMalformedBundleSha.stderr.includes('--require-bundle-sha must be 64 lowercase hex')
);
assert('cli malformed bundle sha privacy safe', !unsafeOutputPattern.test(cliMalformedBundleSha.stderr));

const cliMalformedArtifactSetSha = runZlar(
  ['private-verifier-result', 'verify', '--input', '-', '--require-artifact-set-sha', 'not-a-sha'],
  cliRequiredInput
);
assert('cli malformed artifact-set sha exits nonzero', cliMalformedArtifactSetSha.status !== 0);
assertEqual('cli malformed artifact-set sha emits no stdout', '', cliMalformedArtifactSetSha.stdout);
assert(
  'cli malformed artifact-set sha names syntax',
  cliMalformedArtifactSetSha.stderr.includes('--require-artifact-set-sha must be 64 lowercase hex')
);
assert('cli malformed artifact-set sha privacy safe', !unsafeOutputPattern.test(cliMalformedArtifactSetSha.stderr));

const cliBundleMismatch = runZlar(
  ['private-verifier-result', 'verify', '--input', '-', '--require-bundle-sha', 'f'.repeat(64)],
  cliRequiredInput
);
assert('cli bundle mismatch exits nonzero', cliBundleMismatch.status !== 0);
assertEqual('cli bundle mismatch emits no stdout', '', cliBundleMismatch.stdout);
assert('cli bundle mismatch names requirement', cliBundleMismatch.stderr.includes('required bundle sha mismatch'));
assert('cli bundle mismatch privacy safe', !unsafeOutputPattern.test(cliBundleMismatch.stderr));

const cliArtifactSetMismatch = runZlar(
  ['private-verifier-result', 'verify', '--input', '-', '--require-artifact-set-sha', 'f'.repeat(64)],
  cliRequiredInput
);
assert('cli artifact set mismatch exits nonzero', cliArtifactSetMismatch.status !== 0);
assertEqual('cli artifact set mismatch emits no stdout', '', cliArtifactSetMismatch.stdout);
assert(
  'cli artifact set mismatch names requirement',
  cliArtifactSetMismatch.stderr.includes('required artifact-set sha mismatch')
);
assert('cli artifact set mismatch privacy safe', !unsafeOutputPattern.test(cliArtifactSetMismatch.stderr));

const cliRecomputeMissing = runZlar(
  ['private-verifier-result', 'verify', '--input', '-', '--require-recomputed-evidence'],
  cliRequiredInput
);
assert('cli recompute missing exits nonzero', cliRecomputeMissing.status !== 0);
assertEqual('cli recompute missing emits no stdout', '', cliRecomputeMissing.stdout);
assert(
  'cli recompute missing names requirement',
  cliRecomputeMissing.stderr.includes('required recomputed evidence was not verified')
);
assert('cli recompute missing privacy safe', !unsafeOutputPattern.test(cliRecomputeMissing.stderr));

const cliContentContractFixture = makeV346EvidenceFixture();
const cliContentContract = runZlar(
  [
    'private-verifier-result',
    'verify',
    '--input',
    '-',
    '--evidence-dir',
    cliContentContractFixture.evidenceDir,
    '--json',
  ],
  JSON.stringify(cliContentContractFixture.report)
);
assertEqual('cli v3.4.46 content contract exits zero', 0, cliContentContract.status);
assertEqual('cli v3.4.46 content contract emits no stderr', '', cliContentContract.stderr);
assert('cli v3.4.46 content contract privacy safe', !unsafeOutputPattern.test(cliContentContract.stdout));
const cliContentContractVerification = JSON.parse(cliContentContract.stdout);
assertEqual(
  'cli v3.4.46 content contract verified',
  true,
  cliContentContractVerification.evidence_dir_contract_verification.verified
);

const cliContentContract48Fixture = makeV348EvidenceFixture();
const cliContentContract48 = runZlar(
  [
    'private-verifier-result',
    'verify',
    '--input',
    '-',
    '--evidence-dir',
    cliContentContract48Fixture.evidenceDir,
    '--json',
  ],
  JSON.stringify(cliContentContract48Fixture.report)
);
assertEqual('cli v3.4.48 content contract exits zero', 0, cliContentContract48.status);
assertEqual('cli v3.4.48 content contract emits no stderr', '', cliContentContract48.stderr);
assert('cli v3.4.48 content contract privacy safe', !unsafeOutputPattern.test(cliContentContract48.stdout));
const cliContentContract48Verification = JSON.parse(cliContentContract48.stdout);
assertEqual(
  'cli v3.4.48 deployment bridge preserved',
  true,
  cliContentContract48Verification.evidence_dir_contract_verification
    .product_proof_path_deployment_profile_authority_bridge_preserved
);
assertEqual(
  'cli v3.4.48 north star deployment bridge preserved',
  true,
  cliContentContract48Verification.evidence_dir_contract_verification
    .north_star_deployment_profile_authority_bridge_preserved
);

const cliContentContract49Fixture = makeV349EvidenceFixture();
const cliContentContract49 = runZlar(
  [
    'private-verifier-result',
    'verify',
    '--input',
    '-',
    '--evidence-dir',
    cliContentContract49Fixture.evidenceDir,
    '--json',
  ],
  JSON.stringify(cliContentContract49Fixture.report)
);
assertEqual('cli v3.4.49 content contract exits zero', 0, cliContentContract49.status);
assertEqual('cli v3.4.49 content contract emits no stderr', '', cliContentContract49.stderr);
assert('cli v3.4.49 content contract privacy safe', !unsafeOutputPattern.test(cliContentContract49.stdout));
const cliContentContract49Verification = JSON.parse(cliContentContract49.stdout);
assertEqual(
  'cli v3.4.49 deployment authority refusals preserved',
  true,
  cliContentContract49Verification.evidence_dir_contract_verification
    .product_proof_path_deployment_profile_authority_refusals_preserved
);
assertEqual(
  'cli v3.4.49 north star authority refusals preserved',
  true,
  cliContentContract49Verification.evidence_dir_contract_verification
    .north_star_deployment_profile_authority_refusals_preserved
);

const cliContentContract51Fixture = makeV351EvidenceFixture();
const cliContentContract51 = runZlar(
  [
    'private-verifier-result',
    'verify',
    '--input',
    '-',
    '--evidence-dir',
    cliContentContract51Fixture.evidenceDir,
    '--json',
  ],
  JSON.stringify(cliContentContract51Fixture.report)
);
assertEqual('cli v3.4.51 content contract exits zero', 0, cliContentContract51.status);
assertEqual('cli v3.4.51 content contract emits no stderr', '', cliContentContract51.stderr);
assert('cli v3.4.51 content contract privacy safe', !unsafeOutputPattern.test(cliContentContract51.stdout));
const cliContentContract51Verification = JSON.parse(cliContentContract51.stdout);
assertEqual(
  'cli v3.4.51 trusted-registry verdict preserved',
  true,
  cliContentContract51Verification.evidence_dir_contract_verification
    .product_proof_path_terminal_chain_trusted_registry_verdict_preserved
);
assertEqual(
  'cli v3.4.51 north star trusted-registry verdict preserved',
  true,
  cliContentContract51Verification.evidence_dir_contract_verification
    .north_star_terminal_chain_trusted_registry_verdict_preserved
);
assertEqual(
  'cli v3.4.51 downstream-refusal boundary preserved',
  true,
  cliContentContract51Verification.evidence_dir_contract_verification
    .product_proof_path_downstream_refusal_boundary_preserved
);
assertEqual(
  'cli v3.4.51 north star downstream-refusal boundary preserved',
  true,
  cliContentContract51Verification.evidence_dir_contract_verification
    .north_star_downstream_refusal_boundary_preserved
);
assertEqual(
  'cli v3.4.51 downstream marker delta',
  1,
  cliContentContract51Verification.evidence_dir_contract_verification
    .downstream_refusal_recognized_marker_count_delta
);
assertEqual(
  'cli v3.4.51 downstream refusals unboarded',
  true,
  cliContentContract51Verification.evidence_dir_contract_verification
    .downstream_refusal_all_refusals_unboarded
);
assertEqual(
  'cli v3.4.51 downstream refusal reasons',
  JSON.stringify(expectedDownstreamRefusalReasons),
  JSON.stringify(
    cliContentContract51Verification.evidence_dir_contract_verification
      .downstream_refusal_reasons
  )
);
assertEqual(
  'cli v3.4.51 north star downstream refusals unboarded',
  true,
  cliContentContract51Verification.evidence_dir_contract_verification
    .north_star_downstream_refusal_all_refusals_unboarded
);
assertEqual(
  'cli v3.4.51 north star downstream refusal reasons',
  JSON.stringify(expectedDownstreamRefusalReasons),
  JSON.stringify(
    cliContentContract51Verification.evidence_dir_contract_verification
      .north_star_downstream_refusal_reasons
  )
);
const cliContentContract51Text = runZlar(
  [
    'private-verifier-result',
    'verify',
    '--input',
    '-',
    '--evidence-dir',
    cliContentContract51Fixture.evidenceDir,
  ],
  JSON.stringify(cliContentContract51Fixture.report)
);
assertEqual('cli v3.4.51 text content contract exits zero', 0, cliContentContract51Text.status);
assertEqual('cli v3.4.51 text content contract emits no stderr', '', cliContentContract51Text.stderr);
assert(
  'cli v3.4.51 text trusted-registry requirement',
  cliContentContract51Text.stdout.includes(
    'terminal_chain_trusted_registry_verdict_required_for_target=true'
  )
);
assert(
  'cli v3.4.51 text trusted-registry preservation',
  cliContentContract51Text.stdout.includes(
    'product_proof_path_terminal_chain_trusted_registry_verdict_preserved=true'
  )
);
assert(
  'cli v3.4.51 text north-star trusted-registry preservation',
  cliContentContract51Text.stdout.includes(
    'north_star_terminal_chain_trusted_registry_verdict_preserved=true'
  )
);
assert(
  'cli v3.4.51 text trusted-registry verdict',
  cliContentContract51Text.stdout.includes(
    'terminal_chain_trusted_registry_recognition_verdict=RECOGNIZED'
  )
);
assert(
  'cli v3.4.51 text trusted-registry signature valid',
  cliContentContract51Text.stdout.includes(
    'terminal_chain_trusted_registry_signature_valid=true'
  )
);
assert(
  'cli v3.4.51 text downstream-refusal requirement',
  cliContentContract51Text.stdout.includes(
    'downstream_refusal_boundary_required_for_target=true'
  )
);
assert(
  'cli v3.4.51 text downstream-refusal preservation',
  cliContentContract51Text.stdout.includes(
    'product_proof_path_downstream_refusal_boundary_preserved=true'
  )
);
assert(
  'cli v3.4.51 text north-star downstream-refusal preservation',
  cliContentContract51Text.stdout.includes(
    'north_star_downstream_refusal_boundary_preserved=true'
  )
);
assert(
  'cli v3.4.51 text downstream marker delta',
  cliContentContract51Text.stdout.includes(
    'downstream_refusal_recognized_marker_count_delta=1'
  )
);
assert(
  'cli v3.4.51 text downstream refusals unboarded',
  cliContentContract51Text.stdout.includes(
    'downstream_refusal_all_refusals_unboarded=true'
  )
);
assert(
  'cli v3.4.51 text downstream refusal reasons',
  cliContentContract51Text.stdout.includes(
    `downstream_refusal_reasons=${expectedDownstreamRefusalReasons.join(',')}`
  )
);
assert(
  'cli v3.4.51 text north-star downstream refusals unboarded',
  cliContentContract51Text.stdout.includes(
    'north_star_downstream_refusal_all_refusals_unboarded=true'
  )
);
assert(
  'cli v3.4.51 text north-star downstream refusal reasons',
  cliContentContract51Text.stdout.includes(
    `north_star_downstream_refusal_reasons=${expectedDownstreamRefusalReasons.join(',')}`
  )
);
assert(
  'cli v3.4.51 text content contract privacy safe',
  !unsafeOutputPattern.test(cliContentContract51Text.stdout)
);

const cliDriftedContentContractFixture = makeV346EvidenceFixture(
  releaseForwardManifestContract({
    northStar: {
      terminal_chain_recognition_refusal_group_case_ids_preserved: false,
    },
  })
);
const cliDriftedContentContract = runZlar(
  [
    'private-verifier-result',
    'verify',
    '--input',
    '-',
    '--evidence-dir',
    cliDriftedContentContractFixture.evidenceDir,
  ],
  JSON.stringify(cliDriftedContentContractFixture.report)
);
assert('cli v3.4.46 content drift exits nonzero', cliDriftedContentContract.status !== 0);
assertEqual('cli v3.4.46 content drift emits no stdout', '', cliDriftedContentContract.stdout);
assert(
  'cli v3.4.46 content drift names contract',
  cliDriftedContentContract.stderr.includes('terminal chain recognition refusal group case IDs drifted')
);
assert('cli v3.4.46 content drift privacy safe', !unsafeOutputPattern.test(cliDriftedContentContract.stderr));

const cliDriftedDeploymentBridgeFixture = makeV348EvidenceFixture(
  releaseForwardManifestContractV348({
    deploymentBridge: {
      production_authority: true,
    },
  })
);
const cliDriftedDeploymentBridge = runZlar(
  [
    'private-verifier-result',
    'verify',
    '--input',
    '-',
    '--evidence-dir',
    cliDriftedDeploymentBridgeFixture.evidenceDir,
  ],
  JSON.stringify(cliDriftedDeploymentBridgeFixture.report)
);
assert('cli v3.4.48 deployment bridge drift exits nonzero', cliDriftedDeploymentBridge.status !== 0);
assertEqual('cli v3.4.48 deployment bridge drift emits no stdout', '', cliDriftedDeploymentBridge.stdout);
assert(
  'cli v3.4.48 deployment bridge drift names contract',
  cliDriftedDeploymentBridge.stderr.includes('deployment-profile authority bridge drifted')
);
assert('cli v3.4.48 deployment bridge drift privacy safe', !unsafeOutputPattern.test(cliDriftedDeploymentBridge.stderr));

const cliDriftedDeploymentAuthorityRefusalsFixture = makeV349EvidenceFixture(
  releaseForwardManifestContractV349({
    deploymentBridge: {
      request_stream_authority_material_refused_before_service_proof: false,
    },
  })
);
const cliDriftedDeploymentAuthorityRefusals = runZlar(
  [
    'private-verifier-result',
    'verify',
    '--input',
    '-',
    '--evidence-dir',
    cliDriftedDeploymentAuthorityRefusalsFixture.evidenceDir,
  ],
  JSON.stringify(cliDriftedDeploymentAuthorityRefusalsFixture.report)
);
assert('cli v3.4.49 deployment authority refusal drift exits nonzero', cliDriftedDeploymentAuthorityRefusals.status !== 0);
assertEqual('cli v3.4.49 deployment authority refusal drift emits no stdout', '', cliDriftedDeploymentAuthorityRefusals.stdout);
assert(
  'cli v3.4.49 deployment authority refusal drift names contract',
  cliDriftedDeploymentAuthorityRefusals.stderr.includes('deployment-profile authority refusals drifted')
);
assert('cli v3.4.49 deployment authority refusal drift privacy safe', !unsafeOutputPattern.test(cliDriftedDeploymentAuthorityRefusals.stderr));

const cliDriftedRegistryVerdictFixture = makeV351EvidenceFixture(
  releaseForwardManifestContractV351({
    terminalBoundary: {
      trusted_issuer_registry_recognition_signature_valid: false,
    },
  })
);
const cliDriftedRegistryVerdict = runZlar(
  [
    'private-verifier-result',
    'verify',
    '--input',
    '-',
    '--evidence-dir',
    cliDriftedRegistryVerdictFixture.evidenceDir,
  ],
  JSON.stringify(cliDriftedRegistryVerdictFixture.report)
);
assert('cli v3.4.51 trusted-registry verdict drift exits nonzero', cliDriftedRegistryVerdict.status !== 0);
assertEqual('cli v3.4.51 trusted-registry verdict drift emits no stdout', '', cliDriftedRegistryVerdict.stdout);
assert(
  'cli v3.4.51 trusted-registry verdict drift names contract',
  cliDriftedRegistryVerdict.stderr.includes('trusted-registry verdict drifted')
);
assert('cli v3.4.51 trusted-registry verdict drift privacy safe', !unsafeOutputPattern.test(cliDriftedRegistryVerdict.stderr));

const cliDriftedDownstreamBoundaryFixture = makeV351EvidenceFixture(
  releaseForwardManifestContractV351({
    downstreamBoundary: {
      refusal_case_count: expectedDownstreamRefusalReasons.length - 1,
    },
  })
);
const cliDriftedDownstreamBoundary = runZlar(
  [
    'private-verifier-result',
    'verify',
    '--input',
    '-',
    '--evidence-dir',
    cliDriftedDownstreamBoundaryFixture.evidenceDir,
    '--json',
  ],
  JSON.stringify(cliDriftedDownstreamBoundaryFixture.report)
);
assert(
  'cli v3.4.51 downstream-refusal boundary drift exits nonzero',
  cliDriftedDownstreamBoundary.status !== 0
);
assertEqual(
  'cli v3.4.51 downstream-refusal boundary drift emits no stdout',
  '',
  cliDriftedDownstreamBoundary.stdout
);
assert(
  'cli v3.4.51 downstream-refusal boundary drift names contract',
  cliDriftedDownstreamBoundary.stderr.includes('downstream-refusal boundary drifted')
);
assert(
  'cli v3.4.51 downstream-refusal boundary drift privacy safe',
  !unsafeOutputPattern.test(cliDriftedDownstreamBoundary.stderr)
);

const cliMismatchFixture = makeEvidenceFixture();
writeFileSync(artifactFilePath(cliMismatchFixture.evidenceDir, 'DRY-RUN-MANIFEST.json'), 'wrong hash\n');
const cliMismatch = runZlar(
  ['private-verifier-result', 'verify', '--input', '-', '--evidence-dir', cliMismatchFixture.evidenceDir],
  JSON.stringify(cliMismatchFixture.report)
);
assert('cli evidence-dir mismatch exits nonzero', cliMismatch.status !== 0);
assertEqual('cli evidence-dir mismatch emits no stdout', '', cliMismatch.stdout);
assert('cli evidence-dir mismatch names relative artifact', cliMismatch.stderr.includes('artifact hash mismatch: DRY-RUN-MANIFEST.json'));
assert('cli evidence-dir mismatch privacy safe', !unsafeOutputPattern.test(cliMismatch.stderr));

const help = runZlar(['private-verifier-result', '--help']);
assertEqual('help exits zero', 0, help.status);
assert('help names usage', help.stderr.includes('Usage: zlar private-verifier-result verify'));
assert('help names evidence-dir', help.stderr.includes('--evidence-dir <dir>'));
assert('help names required result sha', help.stderr.includes('--require-result-sha <sha256>'));
assert('help names required target', help.stderr.includes('--require-target <release>@<commit>'));
assert('help names required bundle sha', help.stderr.includes('--require-bundle-sha <sha256>'));
assert('help names required artifact set sha', help.stderr.includes('--require-artifact-set-sha <sha256>'));
assert('help names required recomputed evidence', help.stderr.includes('--require-recomputed-evidence'));
assert('help names no public external attestation', help.stderr.includes('without creating public external attestation'));

const mainHelp = runZlar(['help']);
assertEqual('main help exits zero', 0, mainHelp.status);
assert('main help lists private-verifier-result', mainHelp.stdout.includes('private-verifier-result'));

console.log('\n-- fail closed drift --');
const publicAttestation = clone(fixture);
publicAttestation.claim_boundary.public_external_attestation = true;
assertThrows('public attestation claim fails', () => assertPrivateVerifierResult(publicAttestation), 'public_external_attestation');

const publicAttribution = clone(fixture);
publicAttribution.privacy.public_attribution_approved = true;
assertThrows('public attribution approval fails', () => assertPrivateVerifierResult(publicAttribution), 'public_attribution_approved');

const usedLatest = clone(fixture);
usedLatest.review_result.used_latest = true;
assertThrows('latest use fails', () => assertPrivateVerifierResult(usedLatest), 'used_latest');

const latestText = clone(fixture);
latestText.review_result.result_summary = 'Verifier ran with --latest by mistake.';
assertThrows('latest flag text fails', () => assertPrivateVerifierResult(latestText), 'latest flag');

const emailLeak = clone(fixture);
emailLeak.verifier.public_label = 'reviewer@example.com';
assertThrows('email leak fails', () => assertPrivateVerifierResult(emailLeak), 'email address');

const identityLabelLeak = clone(fixture);
identityLabelLeak.verifier.public_label = 'named-person';
assertThrows(
  'identity-shaped sample label fails',
  () => assertPrivateVerifierResult(identityLabelLeak),
  'approved sample fixture label'
);

const relationshipOverclaim = clone(fixture);
relationshipOverclaim.verifier.relationship_to_zlar =
  'External attestation completed by independent verifier.';
assertThrows(
  'relationship overclaim fails',
  () => assertPrivateVerifierResult(relationshipOverclaim),
  'approved sample fixture relationship'
);

const resultSummaryOverclaim = clone(fixture);
resultSummaryOverclaim.review_result.result_summary =
  'Private non-operator verifier completed public external attestation.';
assertThrows(
  'result summary overclaim fails',
  () => assertPrivateVerifierResult(resultSummaryOverclaim),
  'approved sample fixture summary'
);

const missingArtifact = clone(fixture);
missingArtifact.evidence.artifact_hashes = missingArtifact.evidence.artifact_hashes.filter((entry) =>
  entry.path !== 'ZLAR/zlar-verifier-kit-reproducibility-v1.json'
);
assertThrows('missing release-forward artifact fails', () => assertPrivateVerifierResult(missingArtifact), 'required private verifier artifacts missing');

const missingIssuerStatusProof = clone(fixture);
missingIssuerStatusProof.evidence.artifact_hashes = missingIssuerStatusProof.evidence.artifact_hashes.filter((entry) =>
  entry.path !== 'ZLAR/zlar-issuer-status-proof.json'
);
assertThrows(
  'missing issuer-status proof artifact fails',
  () => assertPrivateVerifierResult(missingIssuerStatusProof),
  'ZLAR/zlar-issuer-status-proof.json'
);

const missingVerifierKitIssuerStatus = clone(fixture);
missingVerifierKitIssuerStatus.evidence.artifact_hashes = missingVerifierKitIssuerStatus.evidence.artifact_hashes.filter((entry) =>
  entry.path !== 'ZLAR/zlar-verifier-kit-issuer-status-fixture.json'
);
assertThrows(
  'missing verifier-kit issuer-status artifact fails',
  () => assertPrivateVerifierResult(missingVerifierKitIssuerStatus),
  'ZLAR/zlar-verifier-kit-issuer-status-fixture.json'
);

const publicDistributionTarget = clone(fixture);
publicDistributionTarget.target.release_tag = 'v3.3.109';
publicDistributionTarget.target.expected_commit_sha = '1234567890abcdef1234567890abcdef12345678';
publicDistributionTarget.target.commit_sha = '1234567890abcdef1234567890abcdef12345678';
publicDistributionTarget.evidence.artifact_hashes.push(
  {
    path: 'ZLAR/zlar-verifier-kit-release-assets-v1.json',
    sha256: 'a'.repeat(64),
  },
  {
    path: 'ZLAR/zlar-verifier-kit-public-distribution-v1.json',
    sha256: 'b'.repeat(64),
  }
);
assert(
  'v3.3.109 private verifier result requires and accepts public distribution artifacts',
  assertPrivateVerifierResult(publicDistributionTarget)
);

const missingPublicDistribution = clone(publicDistributionTarget);
missingPublicDistribution.evidence.artifact_hashes = missingPublicDistribution.evidence.artifact_hashes.filter((entry) =>
  entry.path !== 'ZLAR/zlar-verifier-kit-public-distribution-v1.json'
);
assertThrows(
  'v3.3.109 missing public distribution artifact fails',
  () => assertPrivateVerifierResult(missingPublicDistribution),
  'ZLAR/zlar-verifier-kit-public-distribution-v1.json'
);

const missingReleaseAssets = clone(publicDistributionTarget);
missingReleaseAssets.evidence.artifact_hashes = missingReleaseAssets.evidence.artifact_hashes.filter((entry) =>
  entry.path !== 'ZLAR/zlar-verifier-kit-release-assets-v1.json'
);
assertThrows(
  'v3.3.109 missing release assets artifact fails',
  () => assertPrivateVerifierResult(missingReleaseAssets),
  'ZLAR/zlar-verifier-kit-release-assets-v1.json'
);

const serviceReleaseTarget = clone(fixture);
serviceReleaseTarget.target.release_tag = 'v3.4.11';
serviceReleaseTarget.target.expected_commit_sha = '3'.repeat(40);
serviceReleaseTarget.target.commit_sha = '3'.repeat(40);
addArtifactHashes(serviceReleaseTarget, [
  'ZLAR/zlar-verifier-kit-release-assets-v1.json',
  'ZLAR/zlar-verifier-kit-public-distribution-v1.json',
  'ZLAR/zlar-installed-runtime-profile-preflight-sample-verification.json',
  'ZLAR/zlar-installed-runtime-profile-recognition-proof-v1.json',
  'ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-v1.json',
  'ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json',
  'ZLAR/zlar-product-proof-path-v1.json',
  'ZLAR/zlar-installed-runtime-profile-service-proof-v1.json',
  'ZLAR/zlar-installed-runtime-profile-service-proof-artifact-v1.json',
  'ZLAR/zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json',
]);
assert(
  'v3.4.11 private verifier result requires and accepts service-proof artifacts',
  assertPrivateVerifierResult(serviceReleaseTarget)
);

const missingServiceProofArtifact = clone(serviceReleaseTarget);
missingServiceProofArtifact.evidence.artifact_hashes =
  missingServiceProofArtifact.evidence.artifact_hashes.filter((entry) =>
    entry.path !== 'ZLAR/zlar-installed-runtime-profile-service-proof-artifact-v1.json'
  );
assertThrows(
  'v3.4.11 missing service-proof artifact hash fails',
  () => assertPrivateVerifierResult(missingServiceProofArtifact),
  'ZLAR/zlar-installed-runtime-profile-service-proof-artifact-v1.json'
);

const currentReleaseTarget = clone(fixture);
currentReleaseTarget.target.release_tag = 'v3.4.17';
currentReleaseTarget.target.expected_commit_sha = '4'.repeat(40);
currentReleaseTarget.target.commit_sha = '4'.repeat(40);
addArtifactHashes(currentReleaseTarget, [
  'ZLAR/zlar-verifier-kit-release-assets-v1.json',
  'ZLAR/zlar-verifier-kit-public-distribution-v1.json',
  'ZLAR/zlar-installed-runtime-profile-preflight-sample-verification.json',
  'ZLAR/zlar-installed-runtime-profile-recognition-proof-v1.json',
  'ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-v1.json',
  'ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json',
  'ZLAR/zlar-product-proof-path-v1.json',
  'ZLAR/zlar-installed-runtime-profile-service-proof-v1.json',
  'ZLAR/zlar-installed-runtime-profile-service-proof-artifact-v1.json',
  'ZLAR/zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json',
  'ZLAR/zlar-installed-runtime-profile-terminal-chain-v1.json',
  'ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-v1.json',
  'ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json',
]);
assert(
  'v3.4.17 private verifier result requires and accepts modern release-forward artifacts',
  assertPrivateVerifierResult(currentReleaseTarget)
);

const missingTerminalChainArtifactVerification = clone(currentReleaseTarget);
missingTerminalChainArtifactVerification.evidence.artifact_hashes =
  missingTerminalChainArtifactVerification.evidence.artifact_hashes.filter((entry) =>
    entry.path !== 'ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json'
  );
assertThrows(
  'v3.4.17 missing terminal-chain artifact verification hash fails',
  () => assertPrivateVerifierResult(missingTerminalChainArtifactVerification),
  'ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json'
);

const missingServiceProofArtifactVerification = clone(currentReleaseTarget);
missingServiceProofArtifactVerification.evidence.artifact_hashes =
  missingServiceProofArtifactVerification.evidence.artifact_hashes.filter((entry) =>
    entry.path !== 'ZLAR/zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'
  );
assertThrows(
  'v3.4.17 missing service-proof artifact verification hash fails',
  () => assertPrivateVerifierResult(missingServiceProofArtifactVerification),
  'ZLAR/zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'
);

const duplicateArtifact = clone(fixture);
duplicateArtifact.evidence.artifact_hashes.push(clone(duplicateArtifact.evidence.artifact_hashes[0]));
assertThrows('duplicate artifact path fails', () => assertPrivateVerifierResult(duplicateArtifact), 'duplicate artifact hash path');

const surplusArtifact = clone(fixture);
surplusArtifact.evidence.artifact_hashes.push({
  path: 'ZLAR/unrecognized-private-intake-summary.json',
  sha256: 'f'.repeat(64),
});
assertThrows(
  'surplus unrecognized artifact path fails',
  () => assertPrivateVerifierResult(surplusArtifact),
  'unrecognized private verifier artifact hash path'
);

const bundleHashDrift = clone(fixture);
bundleHashDrift.evidence.received_bundle_sha256 = 'f'.repeat(64);
assertThrows(
  'received bundle hash drift fails',
  () => assertPrivateVerifierResult(bundleHashDrift),
  'received_bundle_sha256 must match SHA256SUMS hash'
);

const nestedTamperArtifactTarget = clone(fixture);
nestedTamperArtifactTarget.target.release_tag = 'v3.4.28';
nestedTamperArtifactTarget.target.expected_commit_sha = '5'.repeat(40);
nestedTamperArtifactTarget.target.commit_sha = '5'.repeat(40);
addArtifactHashes(nestedTamperArtifactTarget, v346ArtifactPaths);
assert(
  'v3.4.28 private verifier result requires and accepts forged-inner artifacts',
  assertPrivateVerifierResult(nestedTamperArtifactTarget)
);

const missingNestedTamperArtifact = clone(nestedTamperArtifactTarget);
missingNestedTamperArtifact.evidence.artifact_hashes =
  missingNestedTamperArtifact.evidence.artifact_hashes.filter(
    (entry) =>
      entry.path !==
      'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-error.txt',
  );
assertThrows(
  'v3.4.28 missing forged-inner artifact fails',
  () => assertPrivateVerifierResult(missingNestedTamperArtifact),
  'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-error.txt'
);

const sampleClaimsRealVerifier = clone(fixture);
sampleClaimsRealVerifier.review_result.completed_by_non_operator = true;
assertThrows('sample cannot claim real non-operator completion', () => assertPrivateVerifierResult(sampleClaimsRealVerifier), 'completed_by_non_operator');

const privateReply = clone(fixture);
privateReply.intake_class = 'private-verifier-reply';
privateReply.verifier.public_label = 'private-non-operator-verifier-v3.3.103-1';
privateReply.verifier.relationship_to_zlar =
  'Private non-operator verifier; relationship requires private handling and honest disclosure before any public use.';
privateReply.custody.source_channel_recorded_privately = true;
privateReply.custody.received_timestamp_recorded_privately = true;
privateReply.review_result.completed_by_non_operator = true;
privateReply.review_result.result_summary =
  'Private non-operator verifier reported PASS for the pinned v3.3.103 release-forward evidence path; private handling boundary preserved.';
assert('private reply shape can validate without public attribution', assertPrivateVerifierResult(privateReply));

const privateReplyIdentityLabel = clone(privateReply);
privateReplyIdentityLabel.verifier.public_label = 'private-non-operator-verifier-named-person';
assertThrows(
  'private reply identity label fails',
  () => assertPrivateVerifierResult(privateReplyIdentityLabel),
  'pseudonymous private verifier label'
);

const privateReplySummaryIdentity = clone(privateReply);
privateReplySummaryIdentity.review_result.result_summary =
  'Private non-operator verifier reported PASS for the pinned v3.3.103 release-forward evidence path after named-person review; private handling boundary preserved.';
assertThrows(
  'private reply summary unapproved prose fails',
  () => assertPrivateVerifierResult(privateReplySummaryIdentity),
  'approved private verifier result boundary'
);

const invalidCli = runZlar(
  ['private-verifier-result', 'verify', '--input', '-'],
  JSON.stringify(publicAttestation)
);
assert('invalid cli exits nonzero', invalidCli.status !== 0);
assertEqual('invalid cli emits no stdout', '', invalidCli.stdout);
assert('invalid cli names failure', invalidCli.stderr.includes('Private verifier result verification failed'));
assert('invalid cli privacy safe', !unsafeOutputPattern.test(invalidCli.stderr));

const missingInput = runZlar(['private-verifier-result', 'verify']);
assert('missing input exits usage error', missingInput.status !== 0);
assertEqual('missing input emits no stdout', '', missingInput.stdout);
assert('missing input names requirement', missingInput.stderr.includes('verify requires --input <file|-> or --sample'));

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed${FAIL ? ` (${FAIL} FAILED)` : ' ✓'}`);
if (FAIL > 0) process.exit(1);
