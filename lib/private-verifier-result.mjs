import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import {
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS,
} from './protected-records-installed-runtime-profile-terminal-chain.mjs';
import {
  REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES,
} from './protected-records-one-terminal-deployment-profile.mjs';
import {
  REQUIRED_REFUSAL_REASONS as REQUIRED_DOWNSTREAM_REFUSAL_REASONS,
} from './downstream-refusal-proof.mjs';

export const PRIVATE_VERIFIER_RESULT_TYPE = 'zlar-private-verifier-result-v1';
export const PRIVATE_VERIFIER_RESULT_VERIFICATION_TYPE =
  'zlar-private-verifier-result-verification-v1';

export const PRIVATE_VERIFIER_RESULT_NON_CLAIMS = Object.freeze([
  'This result is private/internal intake only unless separate public disclosure is approved.',
  'This result does not create public external attestation.',
  'This result does not create public attribution.',
  'This result does not prove production authority, enterprise readiness, or sovereign recognition.',
  'This result does not prove current-machine governance, live MCP coverage, or approval-channel health.',
  'This result does not prove key custody, revocation truth, live trust-registry state, or production downstream recognition.',
  'This result does not prove v3.4.0 readiness or coverage of unrouted surfaces.',
]);

const REQUIRED_NON_CLAIM_FRAGMENTS = Object.freeze([
  'private/internal intake',
  'public external attestation',
  'public attribution',
  'production authority',
  'current-machine governance',
  'key custody',
  'v3.4.0 readiness',
  'coverage of unrouted surfaces',
]);

const UNSAFE_TEXT_PATTERNS = Object.freeze([
  { label: 'private operator path', pattern: /\/Users\/[^\s"'`]+/ },
  { label: 'home path', pattern: /\/home\/[^\s"'`]+/ },
  { label: 'private path', pattern: /\/private\/[^\s"'`]+/ },
  { label: 'temp path', pattern: /\/tmp\/[^\s"'`]+/ },
  { label: 'var path', pattern: /\/var\/[^\s"'`]+/ },
  { label: 'email address', pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i },
  { label: 'numeric human identifier', pattern: /\bhuman:[0-9]/ },
  { label: 'chat id field', pattern: /\bchat_id\b/i },
  { label: 'private key material', pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
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
  { label: 'latest flag', pattern: /(^|[\s"'`])--latest([\s"'`]|$)/ },
  { label: 'moving git checkout', pattern: /\bgit\s+checkout\s+(?:main|master|HEAD|latest)\b/i },
]);

const CLAIM_BOUNDARY_FALSE_KEYS = Object.freeze([
  'public_external_attestation',
  'public_attribution',
  'non_operator_review_publicly_claimed',
  'production_authority',
  'enterprise_readiness',
  'sovereign_recognition',
  'current_machine_governance',
  'live_mcp_coverage',
  'live_approval_channel_health',
  'live_trust_registry_state',
  'key_custody',
  'revocation_truth',
  'production_downstream_recognition',
  'unrouted_surface_coverage',
  'v3_4_0_readiness',
]);

const PRIVACY_FALSE_KEYS = Object.freeze([
  'public_attribution_approved',
  'public_external_attestation_approved',
  'verifier_identity_public',
  'verifier_contact_public',
  'private_contact_included',
  'private_paths_included',
  'credentials_included',
]);

const SAMPLE_VERIFIER_LABELS = Object.freeze([
  'private-verifier-fixture',
  'release-forward-private-verifier-result-fixture',
]);

const SAMPLE_VERIFIER_RELATIONSHIPS = Object.freeze([
  'sample fixture only; no real verifier identity or public attribution',
  'release-forward dry-run generated sample only; no real verifier identity or public attribution',
]);

const SAMPLE_RESULT_SUMMARIES = Object.freeze([
  'Sample fixture proving the private intake envelope only; it is not a real verifier reply.',
  'Release-forward dry-run generated sample proving private intake artifact hashes for this packet only; it is not a real verifier reply.',
]);

const PRIVATE_VERIFIER_RELATIONSHIP =
  'Private non-operator verifier; relationship requires private handling and honest disclosure before any public use.';

const ALWAYS_REQUIRED_ARTIFACTS = Object.freeze([
  'DRY-RUN-MANIFEST.json',
  'SHA256SUMS',
  'RUN-SHA256SUMS',
  'ZLAR/zlar-verifier-env-report-v0.json',
  'ZLAR/zlar-proof-smoke-sample-verification.json',
  'ZLAR/zlar-local-proof-pack-sample-verification.json',
  'ZLAR/zlar-coverage-map-sample.json',
  'ZLAR/zlar-issuer-status-proof.json',
  'ZLAR/zlar-verifier-kit-issuer-status-fixture.json',
]);

const OPTIONAL_RECOGNIZED_ARTIFACTS = Object.freeze([
  'ZLAR/zlar-proof-smoke-v1.json',
  'ZLAR/zlar-proof-smoke-generated-verification.json',
  'ZLAR/zlar-service-preflight-sample-verification.json',
  'ZLAR/zlar-runtime-local-activation-sample-verification.json',
  'ZLAR/zlar-runtime-profile-installation-sample-verification.json',
]);

const CONDITIONAL_ARTIFACTS = Object.freeze([
  {
    min: [3, 3, 85],
    paths: ['ZLAR/zlar-service-preflight-sample-verification.json'],
  },
  {
    min: [3, 3, 90],
    paths: [
      'ZLAR/zlar-runtime-local-activation-sample-verification.json',
      'ZLAR/zlar-runtime-profile-installation-sample-verification.json',
    ],
  },
  {
    min: [3, 3, 94],
    paths: ['ZLAR/zlar-trusted-receipt-issuer-recognition.json'],
  },
  {
    min: [3, 3, 97],
    paths: [
      'ZLAR/zlar-trusted-receipt-issuer-recognition-malformed-registry.json',
      'ZLAR/zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt',
    ],
  },
  {
    min: [3, 3, 98],
    paths: ['ZLAR/zlar-north-star-readiness-v1.json'],
  },
  {
    min: [3, 3, 100],
    paths: ['ZLAR/zlar-verifier-kit-reproducibility-v1.json'],
  },
  {
    min: [3, 3, 109],
    paths: [
      'ZLAR/zlar-verifier-kit-release-assets-v1.json',
      'ZLAR/zlar-verifier-kit-public-distribution-v1.json',
    ],
  },
  {
    min: [3, 4, 5],
    paths: ['ZLAR/zlar-installed-runtime-profile-preflight-sample-verification.json'],
  },
  {
    min: [3, 4, 7],
    paths: ['ZLAR/zlar-installed-runtime-profile-recognition-proof-v1.json'],
  },
  {
    min: [3, 4, 8],
    paths: [
      'ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-v1.json',
      'ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json',
    ],
  },
  {
    min: [3, 4, 9],
    paths: ['ZLAR/zlar-product-proof-path-v1.json'],
  },
  {
    min: [3, 4, 11],
    paths: [
      'ZLAR/zlar-installed-runtime-profile-service-proof-v1.json',
      'ZLAR/zlar-installed-runtime-profile-service-proof-artifact-v1.json',
      'ZLAR/zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json',
    ],
  },
  {
    min: [3, 4, 15],
    paths: [
      'ZLAR/zlar-installed-runtime-profile-terminal-chain-v1.json',
      'ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-v1.json',
      'ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json',
    ],
  },
  {
    min: [3, 4, 21],
    paths: ['ZLAR/zlar-verifier-kit-external-runner-diagnostics-v1.json'],
  },
  {
    min: [3, 4, 28],
    paths: [
      'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-v1.json',
      'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-error.txt',
      'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-v1.json',
      'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-error.txt',
    ],
  },
]);

const RELEASE_FORWARD_MANIFEST_TARGET_KEYS = Object.freeze([
  'release_tag',
  'expected_commit_sha',
  'observed_commit_sha',
  'repo_url',
  'source',
  'moving_target_selected',
]);

const RELEASE_FORWARD_SOURCE_ARTIFACT_KEYS = Object.freeze([
  'proof_smoke_sample_verification_path',
  'proof_smoke_sample_verification_sha256',
  'north_star_readiness_path',
  'north_star_readiness_sha256',
  'product_proof_path_path',
  'product_proof_path_sha256',
  'terminal_chain_refusal_evidence_source',
  'terminal_chain_refusal_evidence_included_in_same_manifest',
]);

const RELEASE_FORWARD_REPORT_CONTRACT_CLAIM_BOUNDARY_KEYS = Object.freeze([
  'creates_public_external_attestation',
  'proves_non_operator_review',
  'proves_live_registry',
  'proves_live_issuer_status',
  'proves_key_custody',
  'proves_revocation_truth',
  'proves_current_machine_governance',
  'proves_live_mcp_coverage',
  'proves_production_downstream_recognition',
  'proves_production_authority',
  'proves_enterprise_readiness',
  'proves_sovereign_recognition',
  'proves_unrouted_surface_coverage',
]);

const RELEASE_FORWARD_PRODUCT_PROOF_PATH_CLAIM_BOUNDARY_KEYS = Object.freeze([
  'creates_public_external_attestation',
  'proves_current_machine_governance',
  'proves_all_mcp_governance',
  'proves_unrouted_surface_coverage',
]);

const RELEASE_FORWARD_PRODUCT_PROOF_PATH_SIMULATED_HUMAN_AUTHORIZATION_KEYS =
  Object.freeze([
    'approval_channel',
    'authorized_boarded',
    'denied_boarded',
    'pending_boarded',
  ]);

const RELEASE_FORWARD_PRODUCT_PROOF_PATH_RECEIPT_VERIFIER_BOUNDARY_KEYS =
  Object.freeze([
    'downstream_recognition_proven',
    'invalid_verdict',
    'unknown_signer_verdict',
    'valid_verdict',
  ]);

const NESTED_PREFLIGHT_ARTIFACT_TYPE =
  'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1';
const NESTED_SERVICE_PROOF_ARTIFACT_TYPE =
  'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1';

const TERMINAL_CHAIN_NESTED_ARTIFACT_TAMPER_REFUSAL_KEYS = Object.freeze([
  'generated_preflight_artifact_type',
  'generated_service_proof_artifact_type',
  'artifact_generated_preflight_artifact_type',
  'artifact_generated_service_proof_artifact_type',
  'forged_inner_preflight_hash_refused',
  'forged_inner_service_hash_refused',
]);

const TERMINAL_CHAIN_NESTED_ARTIFACT_BINDING_KEYS = Object.freeze([
  'generated_preflight_artifact_type',
  'generated_service_proof_artifact_type',
  'generated_preflight_artifact_body_sha256',
  'generated_service_proof_artifact_body_sha256',
  'generated_preflight_artifact_verified',
  'generated_service_proof_artifact_verified',
  'preflight_artifact_hash_bound',
  'service_proof_source_preflight_hash_bound',
  'service_artifact_hash_bound',
  'service_artifact_verification_bound_to_service_proof',
  'creates_public_external_attestation',
  'proves_non_operator_review',
  'proves_current_machine_governance',
  'proves_production_downstream_recognition',
]);

const TERMINAL_CHAIN_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_KEYS = Object.freeze([
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

const TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_MIRROR_KEYS =
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

const REPORT_CONTRACT_TERMINAL_CHAIN_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_KEYS =
  Object.freeze(
    TERMINAL_CHAIN_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_KEYS.filter(
      (key) => key !== 'trusted_issuer_registry_recognition_refusals_minimum_target',
    ),
  );

const REPORT_CONTRACT_TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_MIRROR_KEYS =
  Object.freeze(
    TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_MIRROR_KEYS.filter(
      (key) => key !== 'deployment_profile_authority_refusal_mirror_minimum_target',
    ),
  );

const REPORT_CONTRACT_PROOF_SMOKE_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_KEYS =
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

const REPORT_CONTRACT_NORTH_STAR_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_KEYS =
  Object.freeze([
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved',
    ...REPORT_CONTRACT_PROOF_SMOKE_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_KEYS,
  ]);

const REPORT_CONTRACT_NORTH_STAR_OBSERVED_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_KEYS =
  Object.freeze([
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids',
    'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes',
  ]);

const REPORT_CONTRACT_PROOF_SUMMARY_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_ROOT_KEY_MAP =
  Object.freeze({
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count:
      'trusted_issuer_registry_recognition_refusal_case_count',
    installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count:
      'artifact_verification_trusted_issuer_registry_recognition_refusal_case_count',
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused:
      'trusted_issuer_registry_recognition_refusals_all_refused',
    installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused:
      'artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused',
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids:
      'trusted_issuer_registry_recognition_refusal_case_ids',
    installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids:
      'artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids',
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes:
      'trusted_issuer_registry_recognition_refusal_reason_codes',
    installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes:
      'artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes',
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256:
      'trusted_issuer_registry_recognition_refusals_sha256',
    installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256:
      'artifact_verification_trusted_issuer_registry_recognition_refusals_sha256',
  });

const REPORT_CONTRACT_NORTH_STAR_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_ROOT_KEY_MAP =
  Object.freeze({
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved:
      'all_trusted_issuer_registry_recognition_refusals_preserved',
    ...REPORT_CONTRACT_PROOF_SUMMARY_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_ROOT_KEY_MAP,
  });

const REPORT_CONTRACT_NORTH_STAR_OBSERVED_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_ROOT_KEY_MAP =
  Object.freeze({
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved:
      'all_trusted_issuer_registry_recognition_refusals_preserved',
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids:
      'trusted_issuer_registry_recognition_refusal_case_ids',
    installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes:
      'trusted_issuer_registry_recognition_refusal_reason_codes',
  });

const PRIVATE_VERIFIER_RESULT_SAMPLE_POINTER_KEYS = Object.freeze([
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

const RUN_SHA256SUMS_PATHS = Object.freeze([
  'transcript.txt',
  'COMMANDS.txt',
  'ASSERTIONS.txt',
  'target-head.txt',
  'target-status.txt',
  'SHA256SUMS',
]);

const PRODUCT_PROOF_PATH_TERMINAL_CHAIN_RECOGNITION_GROUP_CONTRACT_TYPE =
  'product-proof-path-terminal-chain-recognition-refusal-group-case-ids-v1';
const PRODUCT_PROOF_PATH_TERMINAL_CHAIN_AND_DEPLOYMENT_PROFILE_BRIDGE_CONTRACT_TYPE =
  'product-proof-path-terminal-chain-and-deployment-profile-authority-bridge-v1';
const PRODUCT_PROOF_PATH_TERMINAL_CHAIN_DEPLOYMENT_PROFILE_BRIDGE_AND_AUTHORITY_REFUSALS_CONTRACT_TYPE =
  'product-proof-path-terminal-chain-deployment-profile-authority-bridge-and-authority-refusals-v1';
const PRODUCT_PROOF_PATH_TERMINAL_CHAIN_REGISTRY_VERDICT_CONTRACT_TYPE =
  'product-proof-path-terminal-chain-deployment-profile-authority-refusals-trusted-registry-verdict-and-downstream-refusal-boundary-v1';
const PRODUCT_PROOF_PATH_TERMINAL_CHAIN_RECOGNIZED_RECEIPT_PATH_CONTRACT_TYPE =
  'product-proof-path-terminal-chain-recognized-receipt-path-mirror-v1';
const PRODUCT_PROOF_PATH_TERMINAL_CHAIN_CONTRACT_FIELD =
  'release_forward_report_contract.product_proof_path.terminal_chain_boundary';
const PRODUCT_PROOF_PATH_TERMINAL_CHAIN_AND_DEPLOYMENT_PROFILE_BRIDGE_CONTRACT_FIELD =
  'release_forward_report_contract.product_proof_path.terminal_chain_boundary+deployment_profile_authority_bridge+north_star.deployment_profile_authority_bridge_*';
const PRODUCT_PROOF_PATH_TERMINAL_CHAIN_DEPLOYMENT_PROFILE_BRIDGE_AND_AUTHORITY_REFUSALS_CONTRACT_FIELD =
  'release_forward_report_contract.product_proof_path.terminal_chain_boundary+deployment_profile_authority_bridge.authority_refusals+north_star.deployment_profile_authority_refusals_*';
const PRODUCT_PROOF_PATH_TERMINAL_CHAIN_REGISTRY_VERDICT_CONTRACT_FIELD =
  'release_forward_report_contract.product_proof_path.terminal_chain_boundary.trusted_issuer_registry_recognition_*+downstream_refusal_boundary+north_star.terminal_chain_trusted_issuer_registry_recognition_*+north_star.downstream_refusal_boundary';
const PRODUCT_PROOF_PATH_TERMINAL_CHAIN_RECOGNIZED_RECEIPT_PATH_CONTRACT_FIELD =
  'release_forward_report_contract.product_proof_path.terminal_chain_boundary.recognized_receipt_path_evidence_*+north_star.terminal_chain_recognized_receipt_path_evidence_*';

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

function hasExactKeys(value, expectedKeys) {
  if (!isObject(value)) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function expectString(label, value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
}

function expectBool(label, value, expected) {
  if (value !== expected) {
    throw new Error(`${label} must be ${expected}`);
  }
}

function expectSha256(label, value) {
  if (!isHexSha(value)) {
    throw new Error(`${label} must be 64 lowercase hex`);
  }
}

function sha256Text(text) {
  return createHash('sha256').update(text).digest('hex');
}

function assertSafeText(text) {
  for (const { label, pattern } of UNSAFE_TEXT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`Private verifier result contains unsafe ${label}`);
    }
  }
}

function parseReleaseTag(tag) {
  const match = /^v([0-9]+)\.([0-9]+)\.([0-9]+)$/.exec(tag);
  if (!match) {
    throw new Error('target.release_tag must be an explicit vX.Y.Z release tag');
  }
  return match.slice(1).map((part) => Number(part));
}

function versionAtLeast(version, minimum) {
  for (let i = 0; i < 3; i++) {
    if (version[i] > minimum[i]) return true;
    if (version[i] < minimum[i]) return false;
  }
  return true;
}

function isHexSha(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function isCommitSha(value) {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

function isReleaseTarget(value) {
  return /^v[0-9]+\.[0-9]+\.[0-9]+@[0-9a-f]{40}$/.test(value);
}

function arraysEqual(left, right) {
  return (
    Array.isArray(left) &&
    Array.isArray(right) &&
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function exactFamilyKeys(label, value, expectedKeys, isFamilyKey) {
  if (!isObject(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).filter(isFamilyKey).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains unexpected fields`);
  }
}

function contractValuesEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function validateMirroredFamilyMatchesRoot({
  rootLabel,
  rootValue,
  mirrorLabel,
  mirrorValue,
  keys,
  familyLabel,
}) {
  for (const key of keys) {
    if (!contractValuesEqual(rootValue[key], mirrorValue[key])) {
      throw new Error(`${mirrorLabel}.${familyLabel} drifted from ${rootLabel}`);
    }
  }
}

function validateMappedFamilyMatchesRoot({
  rootLabel,
  rootValue,
  mirrorLabel,
  mirrorValue,
  keyMap,
  familyLabel,
}) {
  for (const [mirrorKey, rootKey] of Object.entries(keyMap)) {
    if (!contractValuesEqual(rootValue[rootKey], mirrorValue[mirrorKey])) {
      throw new Error(`${mirrorLabel}.${familyLabel} drifted from ${rootLabel}`);
    }
  }
}

function expectedTerminalChainRecognitionRefusalGroupCaseIds() {
  return Object.fromEntries(
    Object.entries(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS)
      .map(([groupId, cases]) => [groupId, cases.map((item) => item.case_id)])
  );
}

function countRecognitionRefusalGroupCaseIds(groups) {
  return Object.values(groups).reduce((total, cases) => total + cases.length, 0);
}

function recognitionRefusalGroupCaseIdsPass(value, expectedGroups) {
  if (!hasExactKeys(value, Object.keys(expectedGroups))) {
    return false;
  }
  return Object.keys(expectedGroups).every((key) =>
    arraysEqual(value[key], expectedGroups[key])
  );
}

function validateReportContractRecognitionRefusalGroupCaseIds(
  counts,
  label,
  expectedGroups,
  { includeRequiredPreserved = false } = {},
) {
  const expectedGroupCount = Object.keys(expectedGroups).length;
  const expectedCaseCount = countRecognitionRefusalGroupCaseIds(expectedGroups);
  const requiredPreservedPass = includeRequiredPreserved
    ? counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required ===
        true &&
      counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved ===
        true
    : true;
  const pass =
    requiredPreservedPass &&
    counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count ===
      expectedGroupCount &&
    counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count ===
      expectedCaseCount &&
    counts
      ?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count ===
      expectedGroupCount &&
    counts
      ?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count ===
      expectedCaseCount &&
    recognitionRefusalGroupCaseIdsPass(
      counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids || {},
      expectedGroups,
    );
  if (!pass) {
    throw new Error(
      `private verifier evidence contract ${label} recognition refusal group case IDs drifted`
    );
  }
  return true;
}

const EXPECTED_TERMINAL_CHAIN_TRUSTED_REGISTRY_REFUSAL_CASE_IDS = Object.freeze(
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS.map(
    (item) => item.case_id,
  ),
);

const EXPECTED_TERMINAL_CHAIN_TRUSTED_REGISTRY_REFUSAL_REASON_CODES = Object.freeze(
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS.map(
    (item) => item.reason_code,
  ),
);

const DOWNSTREAM_REFUSAL_BOUNDARY_KEYS = Object.freeze([
  'provided',
  'recognized_boarded',
  'recognized_marker_count_delta',
  'final_marker_count',
  'refusal_case_count',
  'all_refusals_unboarded',
  'all_refusal_marker_count_deltas_zero',
  'refusal_reasons',
]);

const DEPLOYMENT_PROFILE_AUTHORITY_BRIDGE_KEYS = Object.freeze([
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

const DEPLOYMENT_PROFILE_AUTHORITY_BRIDGE_NORTH_STAR_KEYS = Object.freeze([
  'deployment_profile_authority_bridge_required',
  'deployment_profile_authority_bridge_preserved',
  'deployment_profile_authority_bridge_observed',
  'deployment_profile_authority_bridge_proof_type',
  'deployment_profile_authority_bridge_refusal_count',
  'deployment_profile_authority_bridge_current_machine_governance',
  'deployment_profile_authority_bridge_production_authority',
]);

function downstreamRefusalBoundaryPasses(boundary) {
  return (
    isObject(boundary) &&
    hasExactKeys(boundary, DOWNSTREAM_REFUSAL_BOUNDARY_KEYS) &&
    boundary.provided === true &&
    boundary.recognized_boarded === true &&
    boundary.recognized_marker_count_delta === 1 &&
    boundary.final_marker_count === 1 &&
    boundary.refusal_case_count === REQUIRED_DOWNSTREAM_REFUSAL_REASONS.length &&
    boundary.all_refusals_unboarded === true &&
    boundary.all_refusal_marker_count_deltas_zero === true &&
    arraysEqual(boundary.refusal_reasons, REQUIRED_DOWNSTREAM_REFUSAL_REASONS)
  );
}

function deploymentProfileAuthorityBridgePasses(
  bridge,
  includeAuthorityRefusals = false,
) {
  return (
    isObject(bridge) &&
    hasExactKeys(
      bridge,
      includeAuthorityRefusals
        ? DEPLOYMENT_PROFILE_AUTHORITY_BRIDGE_WITH_REFUSAL_KEYS
        : DEPLOYMENT_PROFILE_AUTHORITY_BRIDGE_KEYS,
    ) &&
    bridge.proof_type === 'zlar-protected-records-one-terminal-deployment-profile-proof-v1' &&
    bridge.evidence_model === 'local-fixture-one-terminal-deployment-profile-authority-bridge' &&
    bridge.live_probing === false &&
    typeof bridge.deployment_profile_id === 'string' &&
    bridge.deployment_profile_id.length > 0 &&
    isHexSha(bridge.deployment_profile_sha256) &&
    isHexSha(bridge.runtime_profile_sha256) &&
    bridge.deployment_profile_artifact_authoritative === true &&
    bridge.selected_by_explicit_id_and_sha === true &&
    bridge.selects_latest_profile === false &&
    bridge.preflight_artifact_verified === true &&
    bridge.recognized_receipt_mutates_once === true &&
    bridge.recognized_state_entry_count_delta === 1 &&
    bridge.required_refusal_case_count === 18 &&
    bridge.observed_refusal_case_count === 18 &&
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
    bridge.unrouted_surface_coverage === false
  );
}

function deploymentProfileAuthorityBridgeNorthStarPasses(
  northStar,
  includeAuthorityRefusals = false,
) {
  return (
    isObject(northStar) &&
    hasOnlyExpectedDeploymentProfileAuthorityNorthStarKeys(
      northStar,
      includeAuthorityRefusals
        ? DEPLOYMENT_PROFILE_AUTHORITY_NORTH_STAR_KEYS
        : DEPLOYMENT_PROFILE_AUTHORITY_BRIDGE_NORTH_STAR_KEYS,
    ) &&
    northStar.deployment_profile_authority_bridge_required === true &&
    northStar.deployment_profile_authority_bridge_preserved === true &&
    northStar.deployment_profile_authority_bridge_observed === true &&
    northStar.deployment_profile_authority_bridge_proof_type ===
      'zlar-protected-records-one-terminal-deployment-profile-proof-v1' &&
    northStar.deployment_profile_authority_bridge_refusal_count === 18 &&
    northStar.deployment_profile_authority_bridge_current_machine_governance === false &&
    northStar.deployment_profile_authority_bridge_production_authority === false
  );
}

function deploymentProfileAuthorityRefusalsPasses(bridge) {
  return (
    isObject(bridge) &&
    bridge.deployment_profile_authority_refusal_case_count ===
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length &&
    arraysEqual(
      bridge.deployment_profile_authority_refusal_case_ids,
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES,
    ) &&
    bridge.deployment_profile_authority_refusals_before_service_proof === true &&
    bridge.deployment_profile_authority_refusals_before_mutation === true &&
    bridge.deployment_profile_authority_refusal_service_proof_started === false &&
    bridge.stale_deployment_profile_artifact_refused_before_service_proof === true &&
    bridge.profile_recognition_mismatch_refused_before_service_proof === true &&
    bridge.latest_profile_selection_refused_before_service_proof === true &&
    bridge.request_stream_authority_material_refused_before_service_proof === true
  );
}

function deploymentProfileAuthorityRefusalsNorthStarPasses(northStar) {
  return (
    isObject(northStar) &&
    northStar.deployment_profile_authority_refusals_required === true &&
    northStar.deployment_profile_authority_refusals_preserved === true &&
    northStar.deployment_profile_authority_refusal_case_count ===
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length &&
    arraysEqual(
      northStar.deployment_profile_authority_refusal_case_ids,
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES,
    ) &&
    northStar.deployment_profile_authority_refusals_before_service_proof === true &&
    northStar.deployment_profile_authority_refusals_before_mutation === true &&
    northStar.deployment_profile_authority_refusal_service_proof_started === false &&
    northStar.stale_deployment_profile_artifact_refused_before_service_proof === true &&
    northStar.profile_recognition_mismatch_refused_before_service_proof === true &&
    northStar.latest_profile_selection_refused_before_service_proof === true &&
    northStar.request_stream_authority_material_refused_before_service_proof === true
  );
}

const TERMINAL_CHAIN_TRUSTED_REGISTRY_VERDICT_KEYS = Object.freeze([
  'trusted_issuer_registry_recognition_verdict',
  'trusted_issuer_registry_recognition_recognized',
  'trusted_issuer_registry_recognition_decision',
  'trusted_issuer_registry_recognition_reason_code',
  'trusted_issuer_registry_recognition_issuer_status',
  'trusted_issuer_registry_recognition_signature_valid',
  'trusted_issuer_registry_recognition_registry_fixture_validated',
  'trusted_issuer_registry_recognition_registry_fixture_evaluated',
  'trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated',
  'trusted_issuer_registry_recognition_registry_evaluation_result_type',
  'trusted_issuer_registry_recognition_registry_trusted_issuer_count',
  'trusted_issuer_registry_recognition_required_audit_event_id_bound',
  'trusted_issuer_registry_recognition_required_detail_hash_bound',
  'trusted_issuer_registry_recognition_registry_fixture_contract_sha256',
  'trusted_issuer_registry_recognition_receipt_payload_contract_sha256',
]);

const TERMINAL_CHAIN_TRUSTED_REGISTRY_RECOGNITION_KEYS = Object.freeze([
  'trusted_issuer_registry_recognition_binding_sha256',
  'trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification',
  ...TERMINAL_CHAIN_TRUSTED_REGISTRY_VERDICT_KEYS,
  'trusted_issuer_registry_recognition_refusals_sha256',
  'trusted_issuer_registry_recognition_refusal_hash_matches_binding',
  'trusted_issuer_registry_recognition_refusal_case_count',
  'trusted_issuer_registry_recognition_refusal_case_ids',
  'trusted_issuer_registry_recognition_refusal_reason_codes',
  'trusted_issuer_registry_recognition_refusals_all_refused',
]);

const NORTH_STAR_TERMINAL_CHAIN_TRUSTED_REGISTRY_VERDICT_KEYS = Object.freeze(
  TERMINAL_CHAIN_TRUSTED_REGISTRY_VERDICT_KEYS.map((key) => `terminal_chain_${key}`),
);

const TERMINAL_CHAIN_RECOGNIZED_RECEIPT_PATH_MIRROR_KEYS = Object.freeze([
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

const NORTH_STAR_TERMINAL_CHAIN_RECOGNIZED_RECEIPT_PATH_MIRROR_KEYS = Object.freeze(
  TERMINAL_CHAIN_RECOGNIZED_RECEIPT_PATH_MIRROR_KEYS.map((key) => `terminal_chain_${key}`),
);

function hasAnyOwn(value, keys) {
  return keys.some((key) => Object.prototype.hasOwnProperty.call(value || {}, key));
}

function hasAnyPrefixedOwn(value, prefix) {
  return Object.keys(value || {}).some((key) => key.startsWith(prefix));
}

function hasOnlyExpectedPrefixedKeys(value, prefix, expectedKeys) {
  if (!isObject(value)) {
    return false;
  }
  const expected = new Set(expectedKeys);
  return Object.keys(value)
    .filter((key) => key.startsWith(prefix))
    .every((key) => expected.has(key));
}

function hasOnlyExpectedRecognizedReceiptPathKeys(value, expectedKeys) {
  if (!isObject(value)) {
    return false;
  }
  const expected = new Set(expectedKeys);
  return Object.keys(value)
    .filter((key) => key.includes('recognized_receipt_path'))
    .every((key) => expected.has(key));
}

function hasAnyRecognizedReceiptPathOwn(value) {
  return Object.keys(value || {}).some((key) => key.includes('recognized_receipt_path'));
}

function isTerminalChainTrustedRegistryRecognitionRefusalKey(key) {
  return (
    key.startsWith('trusted_issuer_registry_recognition_refusal') ||
    key.startsWith('artifact_verification_trusted_issuer_registry_recognition_refusal') ||
    key === 'all_trusted_issuer_registry_recognition_refusals_preserved'
  );
}

function isTerminalChainDeploymentProfileAuthorityRefusalMirrorKey(key) {
  return (
    key.startsWith('deployment_profile_authority_refusal') ||
    key.startsWith('artifact_verification_deployment_profile_authority_refusal') ||
    key.startsWith('stale_deployment_profile_artifact_') ||
    key.startsWith('profile_recognition_mismatch_') ||
    key.startsWith('latest_profile_selection_') ||
    key.startsWith('request_stream_authority_material_') ||
    [
      'current_machine_governance',
      'production_downstream_recognition',
      'production_authority',
      'enterprise_readiness',
      'external_attestation',
      'sovereign_recognition',
      'unrouted_surface_coverage',
    ].includes(key)
  );
}

function isReportContractProofSummaryTrustedRegistryRecognitionRefusalKey(key) {
  return (
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
    )
  );
}

function hasOnlyExpectedDeploymentProfileAuthorityNorthStarKeys(value, expectedKeys) {
  if (!isObject(value)) {
    return false;
  }
  const expected = new Set(expectedKeys);
  return Object.keys(value)
    .filter((key) =>
      DEPLOYMENT_PROFILE_AUTHORITY_NORTH_STAR_PREFIXES.some((prefix) =>
        key.startsWith(prefix),
      ),
    )
    .every((key) => expected.has(key));
}

function terminalChainTrustedRegistryVerdictPasses(boundary) {
  return (
    isObject(boundary) &&
    hasOnlyExpectedPrefixedKeys(
      boundary,
      'trusted_issuer_registry_recognition_',
      TERMINAL_CHAIN_TRUSTED_REGISTRY_RECOGNITION_KEYS,
    ) &&
    boundary.trusted_issuer_registry_recognition_verdict === 'RECOGNIZED' &&
    boundary.trusted_issuer_registry_recognition_recognized === true &&
    boundary.trusted_issuer_registry_recognition_decision === 'accept' &&
    boundary.trusted_issuer_registry_recognition_reason_code === 'recognized' &&
    boundary.trusted_issuer_registry_recognition_issuer_status === 'active' &&
    boundary.trusted_issuer_registry_recognition_signature_valid === true &&
    boundary.trusted_issuer_registry_recognition_registry_fixture_validated === true &&
    boundary.trusted_issuer_registry_recognition_registry_fixture_evaluated === true &&
    boundary.trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated ===
      true &&
    boundary.trusted_issuer_registry_recognition_registry_evaluation_result_type ===
      'downstream-recognition-rule-v1' &&
    boundary.trusted_issuer_registry_recognition_registry_trusted_issuer_count === 1 &&
    boundary.trusted_issuer_registry_recognition_required_audit_event_id_bound === true &&
    boundary.trusted_issuer_registry_recognition_required_detail_hash_bound === true &&
    isHexSha(boundary.trusted_issuer_registry_recognition_registry_fixture_contract_sha256) &&
    isHexSha(boundary.trusted_issuer_registry_recognition_receipt_payload_contract_sha256)
  );
}

function northStarTerminalChainTrustedRegistryVerdictPasses(northStar) {
  return (
    isObject(northStar) &&
    hasOnlyExpectedPrefixedKeys(
      northStar,
      'terminal_chain_trusted_issuer_registry_recognition_',
      NORTH_STAR_TERMINAL_CHAIN_TRUSTED_REGISTRY_VERDICT_KEYS,
    ) &&
    northStar.terminal_chain_trusted_issuer_registry_recognition_verdict ===
      'RECOGNIZED' &&
    northStar.terminal_chain_trusted_issuer_registry_recognition_recognized === true &&
    northStar.terminal_chain_trusted_issuer_registry_recognition_decision ===
      'accept' &&
    northStar.terminal_chain_trusted_issuer_registry_recognition_reason_code ===
      'recognized' &&
    northStar.terminal_chain_trusted_issuer_registry_recognition_issuer_status ===
      'active' &&
    northStar.terminal_chain_trusted_issuer_registry_recognition_signature_valid === true &&
    northStar
      .terminal_chain_trusted_issuer_registry_recognition_registry_fixture_validated ===
      true &&
    northStar
      .terminal_chain_trusted_issuer_registry_recognition_registry_fixture_evaluated ===
      true &&
    northStar
      .terminal_chain_trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated ===
      true &&
    northStar
      .terminal_chain_trusted_issuer_registry_recognition_registry_evaluation_result_type ===
      'downstream-recognition-rule-v1' &&
    northStar
      .terminal_chain_trusted_issuer_registry_recognition_registry_trusted_issuer_count ===
      1 &&
    northStar
      .terminal_chain_trusted_issuer_registry_recognition_required_audit_event_id_bound ===
      true &&
    northStar
      .terminal_chain_trusted_issuer_registry_recognition_required_detail_hash_bound === true &&
    isHexSha(
      northStar
        .terminal_chain_trusted_issuer_registry_recognition_registry_fixture_contract_sha256,
    ) &&
    isHexSha(
      northStar
        .terminal_chain_trusted_issuer_registry_recognition_receipt_payload_contract_sha256,
    )
  );
}

function hasTerminalChainTrustedRegistryVerdictFields(productContract, northStar) {
  return (
    hasAnyOwn(
      productContract?.terminal_chain_boundary,
      TERMINAL_CHAIN_TRUSTED_REGISTRY_VERDICT_KEYS,
    ) ||
    hasAnyOwn(northStar, NORTH_STAR_TERMINAL_CHAIN_TRUSTED_REGISTRY_VERDICT_KEYS)
  );
}

function recognizedReceiptPathMirrorPasses(boundary) {
  return (
    isObject(boundary) &&
    hasOnlyExpectedRecognizedReceiptPathKeys(
      boundary,
      TERMINAL_CHAIN_RECOGNIZED_RECEIPT_PATH_MIRROR_KEYS,
    ) &&
    isHexSha(boundary.recognized_receipt_path_evidence_sha256) &&
    isHexSha(boundary.recognized_receipt_path_evidence_artifact_verification_sha256) &&
    boundary.recognized_receipt_path_evidence_sha256 ===
      boundary.recognized_receipt_path_evidence_artifact_verification_sha256 &&
    boundary.recognized_receipt_path_evidence_sha256_matches_artifact_verification ===
      true &&
    boundary.recognized_receipt_path_evidence_bound_to_artifact_body === true &&
    isHexSha(boundary.recognized_receipt_path_evidence_source_binding_sha256) &&
    boundary.recognized_receipt_path_evidence_source_binding_sha256 ===
      boundary.trusted_issuer_registry_recognition_binding_sha256 &&
    boundary.recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding ===
      true &&
    boundary.recognized_receipt_path_evidence_verdict === 'RECOGNIZED' &&
    boundary.recognized_receipt_path_evidence_recognized === true &&
    boundary.recognized_receipt_path_evidence_receipt_envelope_included === false &&
    boundary.recognized_receipt_path_evidence_registry_public_key_material_included ===
      false &&
    boundary.recognized_receipt_path_evidence_artifact_crypto_reproducible === false &&
    boundary.recognized_receipt_path_evidence_live_state_proven === false &&
    boundary.recognized_receipt_path_evidence_live_issuer_status_proven === false &&
    boundary.recognized_receipt_path_evidence_key_custody_proven === false &&
    boundary.recognized_receipt_path_evidence_revocation_truth_proven === false &&
    boundary.recognized_receipt_path_evidence_production_downstream_recognition_proven ===
      false &&
    boundary.recognized_receipt_path_evidence_public_external_attestation === false &&
    boundary.recognized_receipt_path_evidence_sovereign_recognition === false &&
    boundary.recognized_receipt_path_evidence_current_machine_governance_proven ===
      false
  );
}

function northStarRecognizedReceiptPathMirrorPasses(northStar, terminalBoundary) {
  if (
    !isObject(northStar) ||
    !hasOnlyExpectedRecognizedReceiptPathKeys(
      northStar,
      NORTH_STAR_TERMINAL_CHAIN_RECOGNIZED_RECEIPT_PATH_MIRROR_KEYS,
    )
  ) {
    return false;
  }
  return TERMINAL_CHAIN_RECOGNIZED_RECEIPT_PATH_MIRROR_KEYS.every((key) =>
    contractValuesEqual(northStar[`terminal_chain_${key}`], terminalBoundary[key]),
  );
}

function hasTerminalChainRecognizedReceiptPathMirrorFields(productContract, northStar) {
  return (
    hasAnyRecognizedReceiptPathOwn(productContract?.terminal_chain_boundary) ||
    hasAnyRecognizedReceiptPathOwn(northStar)
  );
}

const DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_BRIDGE_KEYS = Object.freeze([
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

const DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_NORTH_STAR_KEYS = Object.freeze([
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

const DEPLOYMENT_PROFILE_AUTHORITY_BRIDGE_WITH_REFUSAL_KEYS = Object.freeze([
  ...DEPLOYMENT_PROFILE_AUTHORITY_BRIDGE_KEYS,
  ...DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_BRIDGE_KEYS,
]);

const DEPLOYMENT_PROFILE_AUTHORITY_NORTH_STAR_KEYS = Object.freeze([
  ...DEPLOYMENT_PROFILE_AUTHORITY_BRIDGE_NORTH_STAR_KEYS,
  ...DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_NORTH_STAR_KEYS,
]);

const DEPLOYMENT_PROFILE_AUTHORITY_NORTH_STAR_PREFIXES = Object.freeze([
  'deployment_profile_authority_',
  'stale_deployment_profile_artifact_',
  'profile_recognition_mismatch_',
  'latest_profile_selection_',
  'request_stream_authority_material_',
]);

function hasAnyOwnKey(value, keys) {
  return isObject(value) && keys.some((key) => Object.hasOwn(value, key));
}

function hasTerminalChainTrustedRegistryRecognitionRefusalFields(terminalEvidence) {
  return (
    isObject(terminalEvidence) &&
    Object.keys(terminalEvidence).some(isTerminalChainTrustedRegistryRecognitionRefusalKey)
  );
}

function hasTerminalChainDeploymentProfileAuthorityRefusalMirrorFields(
  terminalEvidence,
) {
  return (
    isObject(terminalEvidence) &&
    Object.keys(terminalEvidence).some(
      isTerminalChainDeploymentProfileAuthorityRefusalMirrorKey,
    )
  );
}

function hasDeploymentProfileAuthorityRefusalFields(productContract, northStar) {
  return (
    hasAnyOwnKey(
      productContract?.deployment_profile_authority_bridge,
      DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_BRIDGE_KEYS
    ) ||
    hasAnyOwnKey(
      northStar,
      DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_NORTH_STAR_KEYS
    )
  );
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function assertVerifierDescriptor({ intakeClass, releaseTag, verifier }) {
  const publicLabel = verifier.public_label;
  const relationship = verifier.relationship_to_zlar;
  assertSafeText(publicLabel);
  assertSafeText(relationship);
  if (intakeClass === 'sample-fixture') {
    if (!SAMPLE_VERIFIER_LABELS.includes(publicLabel)) {
      throw new Error('verifier.public_label must be an approved sample fixture label');
    }
    if (!SAMPLE_VERIFIER_RELATIONSHIPS.includes(relationship)) {
      throw new Error('verifier.relationship_to_zlar must be an approved sample fixture relationship');
    }
    return;
  }

  const expectedPrivateLabel = new RegExp(
    `^private-non-operator-verifier-${escapeRegExp(releaseTag)}-[0-9]+$`
  );
  if (!expectedPrivateLabel.test(publicLabel)) {
    throw new Error('verifier.public_label must be a pseudonymous private verifier label for the target release');
  }
  if (relationship !== PRIVATE_VERIFIER_RELATIONSHIP) {
    throw new Error('verifier.relationship_to_zlar must use the approved private verifier relationship boundary');
  }
}

function assertResultSummary({ intakeClass, releaseTag, verdict, resultSummary }) {
  assertSafeText(resultSummary);
  if (intakeClass === 'sample-fixture') {
    if (!SAMPLE_RESULT_SUMMARIES.includes(resultSummary)) {
      throw new Error('review_result.result_summary must be an approved sample fixture summary');
    }
    return;
  }

  const expected = new RegExp(
    `^Private non-operator verifier reported ${escapeRegExp(verdict)} for the pinned ${escapeRegExp(releaseTag)} release-forward evidence path(?: after Ed25519 verifier-environment remediation)?; private handling boundary preserved\\.$`
  );
  if (!expected.test(resultSummary)) {
    throw new Error('review_result.result_summary must use the approved private verifier result boundary');
  }
}

function assertRelativeArtifactPath(path) {
  if (typeof path !== 'string' || path.length === 0) {
    throw new Error('artifact path must be a non-empty string');
  }
  if (path.startsWith('/') || path.includes('..') || path.includes('\\')) {
    throw new Error(`artifact path is not a safe relative path: ${path}`);
  }
  if (!/^[A-Za-z0-9._/-]+$/.test(path)) {
    throw new Error(`artifact path contains unsupported characters: ${path}`);
  }
}

function resolveEvidenceArtifactPath(evidenceDir, artifactPath) {
  const root = resolve(evidenceDir);
  let rootStat;
  try {
    rootStat = lstatSync(root);
  } catch {
    throw new Error('evidence directory must exist and be a directory');
  }
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    throw new Error('evidence directory must exist and be a directory');
  }

  const target = resolve(root, artifactPath);
  const rootPrefix = root.endsWith(sep) ? root : `${root}${sep}`;
  if (!target.startsWith(rootPrefix)) {
    throw new Error(`artifact path is not inside evidence directory: ${artifactPath}`);
  }
  return target;
}

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function sha256EvidenceArtifact(evidenceDir, artifactPath) {
  const resolvedPath = resolveEvidenceArtifactPath(evidenceDir, artifactPath);
  let stat;
  try {
    stat = lstatSync(resolvedPath);
  } catch {
    throw new Error(`artifact file missing: ${artifactPath}`);
  }
  if (stat.isSymbolicLink()) {
    throw new Error(`artifact file must not be a symlink: ${artifactPath}`);
  }
  if (!stat.isFile()) {
    throw new Error(`artifact file must be a regular file: ${artifactPath}`);
  }
  return sha256File(resolvedPath);
}

function readEvidenceArtifactJson(evidenceDir, artifactPath) {
  const resolvedPath = resolveEvidenceArtifactPath(evidenceDir, artifactPath);
  let stat;
  try {
    stat = lstatSync(resolvedPath);
  } catch {
    throw new Error(`artifact file missing: ${artifactPath}`);
  }
  if (stat.isSymbolicLink()) {
    throw new Error(`artifact file must not be a symlink: ${artifactPath}`);
  }
  if (!stat.isFile()) {
    throw new Error(`artifact file must be a regular file: ${artifactPath}`);
  }
  try {
    return JSON.parse(readFileSync(resolvedPath, 'utf8'));
  } catch (err) {
    throw new Error(`artifact JSON invalid: ${artifactPath}: ${err.message}`);
  }
}

function readEvidenceArtifactText(evidenceDir, artifactPath) {
  const resolvedPath = resolveEvidenceArtifactPath(evidenceDir, artifactPath);
  let stat;
  try {
    stat = lstatSync(resolvedPath);
  } catch {
    throw new Error(`artifact file missing: ${artifactPath}`);
  }
  if (stat.isSymbolicLink()) {
    throw new Error(`artifact file must not be a symlink: ${artifactPath}`);
  }
  if (!stat.isFile()) {
    throw new Error(`artifact file must be a regular file: ${artifactPath}`);
  }
  return readFileSync(resolvedPath, 'utf8');
}

function expectedArtifactsForRelease(releaseVersion) {
  const paths = new Set(ALWAYS_REQUIRED_ARTIFACTS);
  for (const { min, paths: conditionalPaths } of CONDITIONAL_ARTIFACTS) {
    if (versionAtLeast(releaseVersion, min)) {
      for (const path of conditionalPaths) paths.add(path);
    }
  }
  return [...paths].sort();
}

function recognizedArtifactsForRelease(releaseVersion) {
  const paths = new Set([
    ...expectedArtifactsForRelease(releaseVersion),
    ...OPTIONAL_RECOGNIZED_ARTIFACTS,
  ]);
  return [...paths].sort();
}

function artifactHashMapFromEntries(label, artifactHashes) {
  if (!Array.isArray(artifactHashes) || artifactHashes.length === 0) {
    throw new Error(`${label} must be a non-empty array`);
  }
  const byPath = new Map();
  for (const [index, artifact] of artifactHashes.entries()) {
    exactKeys(`${label}[${index}]`, artifact, ['path', 'sha256']);
    assertRelativeArtifactPath(artifact.path);
    if (!isHexSha(artifact.sha256)) {
      throw new Error(`${label}[${index}].sha256 must be 64 lowercase hex`);
    }
    if (byPath.has(artifact.path)) {
      throw new Error(`duplicate artifact hash path: ${artifact.path}`);
    }
    byPath.set(artifact.path, artifact.sha256);
  }
  return byPath;
}

export function privateVerifierArtifactSetSha256(artifactHashes) {
  const byPath = artifactHashMapFromEntries('evidence.artifact_hashes', artifactHashes);
  const canonical = [...byPath.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([path, sha256]) => `${path}\0${sha256}\n`)
    .join('');
  return sha256Text(canonical);
}

function parseRequiredTarget(value) {
  if (typeof value !== 'string' || !isReleaseTarget(value)) {
    throw new Error('--require-target must be <release>@<commit>');
  }
  const atIndex = value.indexOf('@');
  return {
    releaseTag: value.slice(0, atIndex),
    commitSha: value.slice(atIndex + 1),
  };
}

function normalizeRequiredIdentity(options) {
  const required = {
    result_sha256: options.requireResultSha || '',
    target: options.requireTarget || '',
    bundle_sha256: options.requireBundleSha || '',
    artifact_set_sha256: options.requireArtifactSetSha || '',
    recomputed_evidence: options.requireRecomputedEvidence === true,
  };
  if (required.result_sha256) {
    expectSha256('--require-result-sha', required.result_sha256);
  }
  if (required.target) {
    parseRequiredTarget(required.target);
  }
  if (required.bundle_sha256) {
    expectSha256('--require-bundle-sha', required.bundle_sha256);
  }
  if (required.artifact_set_sha256) {
    expectSha256('--require-artifact-set-sha', required.artifact_set_sha256);
  }
  return required;
}

function buildRequiredIdentityVerification({
  report,
  resultSha256,
  artifactSetSha256,
  evidenceDirHashVerification,
  options,
}) {
  const required = normalizeRequiredIdentity(options);
  const resultShaMatched = required.result_sha256
    ? resultSha256 === required.result_sha256
    : null;
  if (required.result_sha256 && !resultShaMatched) {
    throw new Error('required result sha mismatch');
  }

  let targetMatched = null;
  if (required.target) {
    const { releaseTag, commitSha } = parseRequiredTarget(required.target);
    targetMatched =
      report.target.release_tag === releaseTag &&
      report.target.expected_commit_sha === commitSha &&
      report.target.commit_sha === commitSha;
    if (!targetMatched) {
      throw new Error('required target mismatch');
    }
  }

  const bundleMatched = required.bundle_sha256
    ? report.evidence.received_bundle_sha256 === required.bundle_sha256
    : null;
  if (required.bundle_sha256 && !bundleMatched) {
    throw new Error('required bundle sha mismatch');
  }

  const artifactSetMatched = required.artifact_set_sha256
    ? artifactSetSha256 === required.artifact_set_sha256
    : null;
  if (required.artifact_set_sha256 && !artifactSetMatched) {
    throw new Error('required artifact-set sha mismatch');
  }

  const recomputedEvidenceMatched = required.recomputed_evidence
    ? evidenceDirHashVerification.hashes_recomputed === true &&
      evidenceDirHashVerification.verified === true
    : null;
  if (required.recomputed_evidence && !recomputedEvidenceMatched) {
    throw new Error('required recomputed evidence was not verified');
  }

  return {
    result_sha256_required: Boolean(required.result_sha256),
    result_sha256_matched: resultShaMatched,
    target_required: Boolean(required.target),
    target_matched: targetMatched,
    bundle_sha256_required: Boolean(required.bundle_sha256),
    bundle_sha256_matched: bundleMatched,
    artifact_set_sha256_required: Boolean(required.artifact_set_sha256),
    artifact_set_sha256_matched: artifactSetMatched,
    recomputed_evidence_required: required.recomputed_evidence,
    recomputed_evidence_matched: recomputedEvidenceMatched,
    command_posture: required.recomputed_evidence
      ? 'private-result-with-required-recomputed-evidence'
      : 'private-result-envelope-only',
  };
}

function assertArtifactHashSetsMatch({
  label,
  expected,
  actual,
  paths = [...expected.keys()],
}) {
  const expectedPaths = [...paths].sort();
  const actualPaths = [...actual.keys()].sort();
  if (!arraysEqual(actualPaths, expectedPaths)) {
    throw new Error(`${label} artifact hash path set drifted`);
  }
  for (const path of expectedPaths) {
    if (actual.get(path) !== expected.get(path)) {
      throw new Error(`${label} artifact hash drifted: ${path}`);
    }
  }
}

function parseChecksumRows(label, text, { prefix = '' } = {}) {
  if (typeof text !== 'string' || text.length === 0) {
    throw new Error(`${label} must be a non-empty checksum file`);
  }
  const lines = text.split('\n');
  if (lines[lines.length - 1] === '') {
    lines.pop();
  }
  if (lines.length === 0) {
    throw new Error(`${label} must be a non-empty checksum file`);
  }
  const byPath = new Map();
  for (const [index, line] of lines.entries()) {
    const match = /^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$/.exec(line);
    if (!match) {
      throw new Error(`${label} contains invalid checksum line ${index + 1}`);
    }
    const [, sha256, rawPath] = match;
    assertRelativeArtifactPath(rawPath);
    const path = `${prefix}${rawPath}`;
    assertRelativeArtifactPath(path);
    if (byPath.has(path)) {
      throw new Error(`${label} contains duplicate checksum path: ${path}`);
    }
    byPath.set(path, sha256);
  }
  return byPath;
}

function assertChecksumRowsMatch(label, actual, expected) {
  const actualPaths = [...actual.keys()].sort();
  const expectedPaths = [...expected.keys()].sort();
  if (!arraysEqual(actualPaths, expectedPaths)) {
    throw new Error(`${label} row path set drifted`);
  }
  for (const path of expectedPaths) {
    if (actual.get(path) !== expected.get(path)) {
      throw new Error(`${label} row hash drifted: ${path}`);
    }
  }
}

function validateSha256SumsRows({ evidenceDir, reportHashByPath }) {
  const rows = parseChecksumRows(
    'SHA256SUMS',
    readEvidenceArtifactText(evidenceDir, 'SHA256SUMS'),
    { prefix: 'ZLAR/' },
  );
  const expected = new Map(
    [...reportHashByPath.entries()].filter(([path]) => path.startsWith('ZLAR/')),
  );
  assertChecksumRowsMatch('SHA256SUMS', rows, expected);
  for (const path of expected.keys()) {
    const observedSha256 = sha256EvidenceArtifact(evidenceDir, path);
    if (rows.get(path) !== observedSha256) {
      throw new Error(`SHA256SUMS row file hash drifted: ${path}`);
    }
  }
}

function validateRunSha256SumsRows({ evidenceDir }) {
  const rows = parseChecksumRows(
    'RUN-SHA256SUMS',
    readEvidenceArtifactText(evidenceDir, 'RUN-SHA256SUMS'),
  );
  const expected = new Map(
    RUN_SHA256SUMS_PATHS.map((path) => [
      path,
      sha256EvidenceArtifact(evidenceDir, path),
    ]),
  );
  assertChecksumRowsMatch('RUN-SHA256SUMS', rows, expected);
}

function assertArtifactHashes(report, releaseVersion) {
  const artifactHashByPath = artifactHashMapFromEntries(
    'evidence.artifact_hashes',
    report.evidence.artifact_hashes,
  );
  const missing = expectedArtifactsForRelease(releaseVersion).filter(
    (path) => !artifactHashByPath.has(path),
  );
  if (missing.length > 0) {
    throw new Error(`required private verifier artifacts missing: ${missing.join(', ')}`);
  }
  const allowed = new Set(recognizedArtifactsForRelease(releaseVersion));
  const unrecognized = [...artifactHashByPath.keys()].filter((path) => !allowed.has(path));
  if (unrecognized.length > 0) {
    throw new Error(
      `unrecognized private verifier artifact hash path: ${unrecognized.join(', ')}`
    );
  }
  if (report.evidence.received_bundle_sha256 !== artifactHashByPath.get('SHA256SUMS')) {
    throw new Error('evidence.received_bundle_sha256 must match SHA256SUMS hash');
  }
  return artifactHashByPath;
}

function verifyArtifactHashesAgainstEvidenceDir(report, evidenceDir) {
  if (typeof evidenceDir !== 'string' || evidenceDir.length === 0) {
    throw new Error('evidence directory must be a non-empty path');
  }

  const reportHashByPath = artifactHashMapFromEntries(
    'evidence.artifact_hashes',
    report.evidence.artifact_hashes,
  );
  const checkedPaths = [];
  for (const artifact of report.evidence.artifact_hashes) {
    const observedSha256 = sha256EvidenceArtifact(evidenceDir, artifact.path);
    if (observedSha256 !== artifact.sha256) {
      throw new Error(`artifact hash mismatch: ${artifact.path}`);
    }
    checkedPaths.push(artifact.path);
  }
  validateSha256SumsRows({ evidenceDir, reportHashByPath });
  validateRunSha256SumsRows({ evidenceDir });

  return {
    enabled: true,
    hashes_recomputed: true,
    verified: true,
    artifact_hash_count: checkedPaths.length,
    checked_paths: checkedPaths,
  };
}

function validateEvidenceManifestTarget({ manifest, report, evidenceDir }) {
  exactKeys('DRY-RUN-MANIFEST.target', manifest.target, RELEASE_FORWARD_MANIFEST_TARGET_KEYS);
  if (
    manifest.target.release_tag !== report.target.release_tag ||
    manifest.target.expected_commit_sha !== report.target.expected_commit_sha ||
    manifest.target.observed_commit_sha !== report.target.commit_sha
  ) {
    throw new Error('private verifier evidence contract manifest target drifted');
  }
  if (typeof manifest.target.repo_url !== 'string' || manifest.target.repo_url.length === 0) {
    throw new Error('private verifier evidence contract manifest target repo_url drifted');
  }
  if (
    manifest.target.source !== 'fresh-clone' ||
    manifest.target.moving_target_selected !== false
  ) {
    throw new Error('private verifier evidence contract manifest target boundary drifted');
  }
  const targetHead = readEvidenceArtifactText(evidenceDir, 'target-head.txt').trim();
  if (targetHead !== report.target.commit_sha) {
    throw new Error('private verifier evidence contract target-head drifted');
  }
}

function validateReleaseForwardManifestArtifactHashes({ manifest, reportHashByPath }) {
  const manifestHashByPath = artifactHashMapFromEntries(
    'DRY-RUN-MANIFEST.artifact_hashes',
    manifest.artifact_hashes,
  );
  const reportZlarHashes = new Map(
    [...reportHashByPath.entries()].filter(([path]) => path.startsWith('ZLAR/')),
  );
  assertArtifactHashSetsMatch({
    label: 'private verifier manifest',
    expected: reportZlarHashes,
    actual: manifestHashByPath,
  });
  return manifestHashByPath;
}

function validateReleaseForwardSourceArtifacts({
  sourceArtifacts,
  manifestHashByPath,
  reportHashByPath,
}) {
  exactKeys(
    'release_forward_report_contract.source_artifacts',
    sourceArtifacts,
    RELEASE_FORWARD_SOURCE_ARTIFACT_KEYS,
  );
  const expected = [
    ['proof_smoke_sample_verification', 'ZLAR/zlar-proof-smoke-sample-verification.json'],
    ['north_star_readiness', 'ZLAR/zlar-north-star-readiness-v1.json'],
    ['product_proof_path', 'ZLAR/zlar-product-proof-path-v1.json'],
  ];
  for (const [prefix, path] of expected) {
    if (sourceArtifacts[`${prefix}_path`] !== path) {
      throw new Error(
        `private verifier evidence contract source artifact path drifted: ${prefix}`
      );
    }
    const shaKey = `${prefix}_sha256`;
    if (
      sourceArtifacts[shaKey] !== manifestHashByPath.get(path) ||
      sourceArtifacts[shaKey] !== reportHashByPath.get(path)
    ) {
      throw new Error(
        `private verifier evidence contract source artifact hash drifted: ${prefix}`
      );
    }
  }
  if (
    sourceArtifacts.terminal_chain_refusal_evidence_source !==
      'DRY-RUN-MANIFEST.json#terminal_chain_refusal_evidence' ||
    sourceArtifacts.terminal_chain_refusal_evidence_included_in_same_manifest !== true
  ) {
    throw new Error(
      'private verifier evidence contract terminal-chain refusal source drifted'
    );
  }
}

function validateFalseClaimBoundary(label, claimBoundary, expectedKeys) {
  exactKeys(label, claimBoundary, expectedKeys);
  for (const key of expectedKeys) {
    expectBool(`${label}.${key}`, claimBoundary[key], false);
  }
}

function validateProductProofPathSimulatedHumanAuthorization(value) {
  const label =
    'release_forward_report_contract.product_proof_path.simulated_human_authorization';
  exactKeys(
    label,
    value,
    RELEASE_FORWARD_PRODUCT_PROOF_PATH_SIMULATED_HUMAN_AUTHORIZATION_KEYS,
  );
  expectExactString(`${label}.approval_channel`, value.approval_channel, 'simulated-human-fixture');
  expectBool(`${label}.authorized_boarded`, value.authorized_boarded, true);
  expectBool(`${label}.denied_boarded`, value.denied_boarded, false);
  expectBool(`${label}.pending_boarded`, value.pending_boarded, false);
}

function validateProductProofPathReceiptVerifierBoundary(value) {
  const label =
    'release_forward_report_contract.product_proof_path.receipt_verifier_boundary';
  exactKeys(
    label,
    value,
    RELEASE_FORWARD_PRODUCT_PROOF_PATH_RECEIPT_VERIFIER_BOUNDARY_KEYS,
  );
  expectBool(`${label}.downstream_recognition_proven`, value.downstream_recognition_proven, false);
  expectExactString(`${label}.invalid_verdict`, value.invalid_verdict, 'INVALID');
  expectExactString(
    `${label}.unknown_signer_verdict`,
    value.unknown_signer_verdict,
    'UNKNOWN-SIGNER',
  );
  expectExactString(`${label}.valid_verdict`, value.valid_verdict, 'VALID');
}

function validateTerminalChainNestedArtifactTamperRefusals(terminalEvidence) {
  const rootLabel = 'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence';
  const label = `${rootLabel}.nested_artifact_tamper_refusals`;
  expectExactString(
    `${rootLabel}.nested_artifact_tamper_refusals_minimum_target`,
    terminalEvidence.nested_artifact_tamper_refusals_minimum_target,
    'v3.4.28',
  );
  expectBool(
    `${rootLabel}.nested_artifact_tamper_refusals_required`,
    terminalEvidence.nested_artifact_tamper_refusals_required,
    true,
  );
  const nestedTamper = terminalEvidence.nested_artifact_tamper_refusals;
  exactKeys(label, nestedTamper, TERMINAL_CHAIN_NESTED_ARTIFACT_TAMPER_REFUSAL_KEYS);
  expectExactString(
    `${label}.generated_preflight_artifact_type`,
    nestedTamper.generated_preflight_artifact_type,
    NESTED_PREFLIGHT_ARTIFACT_TYPE,
  );
  expectExactString(
    `${label}.generated_service_proof_artifact_type`,
    nestedTamper.generated_service_proof_artifact_type,
    NESTED_SERVICE_PROOF_ARTIFACT_TYPE,
  );
  expectExactString(
    `${label}.artifact_generated_preflight_artifact_type`,
    nestedTamper.artifact_generated_preflight_artifact_type,
    NESTED_PREFLIGHT_ARTIFACT_TYPE,
  );
  expectExactString(
    `${label}.artifact_generated_service_proof_artifact_type`,
    nestedTamper.artifact_generated_service_proof_artifact_type,
    NESTED_SERVICE_PROOF_ARTIFACT_TYPE,
  );
  expectBool(
    `${label}.forged_inner_preflight_hash_refused`,
    nestedTamper.forged_inner_preflight_hash_refused,
    true,
  );
  expectBool(
    `${label}.forged_inner_service_hash_refused`,
    nestedTamper.forged_inner_service_hash_refused,
    true,
  );
  return true;
}

function validateTerminalChainNestedArtifactBinding(terminalEvidence) {
  const rootLabel = 'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence';
  const label = `${rootLabel}.nested_artifact_binding`;
  expectExactString(
    `${rootLabel}.nested_artifact_binding_minimum_target`,
    terminalEvidence.nested_artifact_binding_minimum_target,
    'v3.4.30',
  );
  expectBool(
    `${rootLabel}.nested_artifact_binding_required`,
    terminalEvidence.nested_artifact_binding_required,
    true,
  );
  const nested = terminalEvidence.nested_artifact_binding;
  exactKeys(label, nested, TERMINAL_CHAIN_NESTED_ARTIFACT_BINDING_KEYS);
  expectExactString(
    `${label}.generated_preflight_artifact_type`,
    nested.generated_preflight_artifact_type,
    NESTED_PREFLIGHT_ARTIFACT_TYPE,
  );
  expectExactString(
    `${label}.generated_service_proof_artifact_type`,
    nested.generated_service_proof_artifact_type,
    NESTED_SERVICE_PROOF_ARTIFACT_TYPE,
  );
  expectSha256(
    `${label}.generated_preflight_artifact_body_sha256`,
    nested.generated_preflight_artifact_body_sha256,
  );
  expectSha256(
    `${label}.generated_service_proof_artifact_body_sha256`,
    nested.generated_service_proof_artifact_body_sha256,
  );
  expectBool(
    `${label}.generated_preflight_artifact_verified`,
    nested.generated_preflight_artifact_verified,
    true,
  );
  expectBool(
    `${label}.generated_service_proof_artifact_verified`,
    nested.generated_service_proof_artifact_verified,
    true,
  );
  expectBool(`${label}.preflight_artifact_hash_bound`, nested.preflight_artifact_hash_bound, true);
  expectBool(
    `${label}.service_proof_source_preflight_hash_bound`,
    nested.service_proof_source_preflight_hash_bound,
    true,
  );
  expectBool(`${label}.service_artifact_hash_bound`, nested.service_artifact_hash_bound, true);
  expectBool(
    `${label}.service_artifact_verification_bound_to_service_proof`,
    nested.service_artifact_verification_bound_to_service_proof,
    true,
  );
  expectBool(
    `${label}.creates_public_external_attestation`,
    nested.creates_public_external_attestation,
    false,
  );
  expectBool(`${label}.proves_non_operator_review`, nested.proves_non_operator_review, false);
  expectBool(
    `${label}.proves_current_machine_governance`,
    nested.proves_current_machine_governance,
    false,
  );
  expectBool(
    `${label}.proves_production_downstream_recognition`,
    nested.proves_production_downstream_recognition,
    false,
  );
  return true;
}

function validateTerminalChainTrustedRegistryRecognitionRefusals(
  terminalEvidence,
  rootLabel = 'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence',
  { includeMinimumTarget = true } = {},
) {
  const label = `${rootLabel}.trusted_issuer_registry_recognition_refusals`;
  exactFamilyKeys(
    label,
    terminalEvidence,
    includeMinimumTarget
      ? TERMINAL_CHAIN_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_KEYS
      : REPORT_CONTRACT_TERMINAL_CHAIN_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_KEYS,
    isTerminalChainTrustedRegistryRecognitionRefusalKey,
  );
  if (includeMinimumTarget) {
    expectExactString(
      `${rootLabel}.trusted_issuer_registry_recognition_refusals_minimum_target`,
      terminalEvidence.trusted_issuer_registry_recognition_refusals_minimum_target,
      'v3.4.39',
    );
  }
  expectBool(
    `${rootLabel}.trusted_issuer_registry_recognition_refusals_required`,
    terminalEvidence.trusted_issuer_registry_recognition_refusals_required,
    true,
  );
  if (
    terminalEvidence.trusted_issuer_registry_recognition_refusal_case_count !==
      EXPECTED_TERMINAL_CHAIN_TRUSTED_REGISTRY_REFUSAL_CASE_IDS.length ||
    terminalEvidence.artifact_verification_trusted_issuer_registry_recognition_refusal_case_count !==
      EXPECTED_TERMINAL_CHAIN_TRUSTED_REGISTRY_REFUSAL_CASE_IDS.length
  ) {
    throw new Error(`${label} case count drifted`);
  }
  expectBool(
    `${rootLabel}.trusted_issuer_registry_recognition_refusals_all_refused`,
    terminalEvidence.trusted_issuer_registry_recognition_refusals_all_refused,
    true,
  );
  expectBool(
    `${rootLabel}.artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused`,
    terminalEvidence.artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused,
    true,
  );
  if (
    !arraysEqual(
      terminalEvidence.trusted_issuer_registry_recognition_refusal_case_ids,
      EXPECTED_TERMINAL_CHAIN_TRUSTED_REGISTRY_REFUSAL_CASE_IDS,
    ) ||
    !arraysEqual(
      terminalEvidence.artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids,
      EXPECTED_TERMINAL_CHAIN_TRUSTED_REGISTRY_REFUSAL_CASE_IDS,
    )
  ) {
    throw new Error(`${label} case IDs drifted`);
  }
  if (
    !arraysEqual(
      terminalEvidence.trusted_issuer_registry_recognition_refusal_reason_codes,
      EXPECTED_TERMINAL_CHAIN_TRUSTED_REGISTRY_REFUSAL_REASON_CODES,
    ) ||
    !arraysEqual(
      terminalEvidence.artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes,
      EXPECTED_TERMINAL_CHAIN_TRUSTED_REGISTRY_REFUSAL_REASON_CODES,
    )
  ) {
    throw new Error(`${label} reason codes drifted`);
  }
  expectSha256(
    `${rootLabel}.trusted_issuer_registry_recognition_refusals_sha256`,
    terminalEvidence.trusted_issuer_registry_recognition_refusals_sha256,
  );
  expectSha256(
    `${rootLabel}.artifact_verification_trusted_issuer_registry_recognition_refusals_sha256`,
    terminalEvidence.artifact_verification_trusted_issuer_registry_recognition_refusals_sha256,
  );
  if (
    terminalEvidence.trusted_issuer_registry_recognition_refusals_sha256 !==
    terminalEvidence.artifact_verification_trusted_issuer_registry_recognition_refusals_sha256
  ) {
    throw new Error(`${label} hash drifted`);
  }
  expectBool(
    `${rootLabel}.all_trusted_issuer_registry_recognition_refusals_preserved`,
    terminalEvidence.all_trusted_issuer_registry_recognition_refusals_preserved,
    true,
  );
  return true;
}

function validateReportContractProofSummaryTrustedRegistryRecognitionRefusals(
  counts,
  terminalEvidence,
  rootLabel,
  expectedKeys,
  keyMap,
  { includePreserved = false } = {},
) {
  const label = `${rootLabel}.trusted_issuer_registry_recognition_refusals`;
  exactFamilyKeys(
    label,
    counts,
    expectedKeys,
    isReportContractProofSummaryTrustedRegistryRecognitionRefusalKey,
  );
  if (includePreserved) {
    expectBool(
      `${rootLabel}.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved`,
      counts
        .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved,
      true,
    );
  }
  if (
    counts
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count !==
      EXPECTED_TERMINAL_CHAIN_TRUSTED_REGISTRY_REFUSAL_CASE_IDS.length ||
    counts
      .installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count !==
      EXPECTED_TERMINAL_CHAIN_TRUSTED_REGISTRY_REFUSAL_CASE_IDS.length
  ) {
    throw new Error(`${label} case count drifted`);
  }
  expectBool(
    `${rootLabel}.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused`,
    counts
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused,
    true,
  );
  expectBool(
    `${rootLabel}.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused`,
    counts
      .installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused,
    true,
  );
  if (
    !arraysEqual(
      counts
        .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids,
      EXPECTED_TERMINAL_CHAIN_TRUSTED_REGISTRY_REFUSAL_CASE_IDS,
    ) ||
    !arraysEqual(
      counts
        .installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids,
      EXPECTED_TERMINAL_CHAIN_TRUSTED_REGISTRY_REFUSAL_CASE_IDS,
    )
  ) {
    throw new Error(`${label} case IDs drifted`);
  }
  if (
    !arraysEqual(
      counts
        .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes,
      EXPECTED_TERMINAL_CHAIN_TRUSTED_REGISTRY_REFUSAL_REASON_CODES,
    ) ||
    !arraysEqual(
      counts
        .installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes,
      EXPECTED_TERMINAL_CHAIN_TRUSTED_REGISTRY_REFUSAL_REASON_CODES,
    )
  ) {
    throw new Error(`${label} reason codes drifted`);
  }
  expectSha256(
    `${rootLabel}.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256`,
    counts
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256,
  );
  expectSha256(
    `${rootLabel}.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256`,
    counts
      .installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256,
  );
  if (
    counts
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256 !==
    counts
      .installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256
  ) {
    throw new Error(`${label} hash drifted`);
  }
  validateMappedFamilyMatchesRoot({
    rootLabel: 'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence',
    rootValue: terminalEvidence,
    mirrorLabel: rootLabel,
    mirrorValue: counts,
    keyMap,
    familyLabel: 'trusted_issuer_registry_recognition_refusals',
  });
  return true;
}

function validateReportContractObservedTrustedRegistryRecognitionRefusals(
  observed,
  terminalEvidence,
  rootLabel,
) {
  const label = `${rootLabel}.trusted_issuer_registry_recognition_refusals`;
  exactFamilyKeys(
    label,
    observed,
    REPORT_CONTRACT_NORTH_STAR_OBSERVED_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_KEYS,
    isReportContractProofSummaryTrustedRegistryRecognitionRefusalKey,
  );
  expectBool(
    `${rootLabel}.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved`,
    observed
      .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved,
    true,
  );
  if (
    !arraysEqual(
      observed
        .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids,
      EXPECTED_TERMINAL_CHAIN_TRUSTED_REGISTRY_REFUSAL_CASE_IDS,
    )
  ) {
    throw new Error(`${label} case IDs drifted`);
  }
  if (
    !arraysEqual(
      observed
        .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes,
      EXPECTED_TERMINAL_CHAIN_TRUSTED_REGISTRY_REFUSAL_REASON_CODES,
    )
  ) {
    throw new Error(`${label} reason codes drifted`);
  }
  validateMappedFamilyMatchesRoot({
    rootLabel: 'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence',
    rootValue: terminalEvidence,
    mirrorLabel: rootLabel,
    mirrorValue: observed,
    keyMap:
      REPORT_CONTRACT_NORTH_STAR_OBSERVED_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_ROOT_KEY_MAP,
    familyLabel: 'trusted_issuer_registry_recognition_refusals',
  });
  return true;
}

function validateTerminalChainDeploymentProfileAuthorityRefusalMirror(
  terminalEvidence,
  rootLabel = 'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence',
  { includeMinimumTarget = true } = {},
) {
  const label = `${rootLabel}.deployment_profile_authority_refusal_mirror`;
  exactFamilyKeys(
    label,
    terminalEvidence,
    includeMinimumTarget
      ? TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_MIRROR_KEYS
      : REPORT_CONTRACT_TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_MIRROR_KEYS,
    isTerminalChainDeploymentProfileAuthorityRefusalMirrorKey,
  );
  if (includeMinimumTarget) {
    expectExactString(
      `${rootLabel}.deployment_profile_authority_refusal_mirror_minimum_target`,
      terminalEvidence.deployment_profile_authority_refusal_mirror_minimum_target,
      'v3.4.50',
    );
  }
  expectBool(
    `${rootLabel}.deployment_profile_authority_refusal_mirror_required`,
    terminalEvidence.deployment_profile_authority_refusal_mirror_required,
    true,
  );
  expectBool(
    `${rootLabel}.deployment_profile_authority_refusal_mirror_preserved`,
    terminalEvidence.deployment_profile_authority_refusal_mirror_preserved,
    true,
  );
  if (
    terminalEvidence.deployment_profile_authority_refusal_case_count !==
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length ||
    terminalEvidence.artifact_verification_deployment_profile_authority_refusal_case_count !==
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length
  ) {
    throw new Error(`${label} case count drifted`);
  }
  if (
    !arraysEqual(
      terminalEvidence.deployment_profile_authority_refusal_case_ids,
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES,
    ) ||
    !arraysEqual(
      terminalEvidence.artifact_verification_deployment_profile_authority_refusal_case_ids,
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES,
    )
  ) {
    throw new Error(`${label} case IDs drifted`);
  }
  expectBool(
    `${rootLabel}.deployment_profile_authority_refusals_before_service_proof`,
    terminalEvidence.deployment_profile_authority_refusals_before_service_proof,
    true,
  );
  expectBool(
    `${rootLabel}.artifact_verification_deployment_profile_authority_refusals_before_service_proof`,
    terminalEvidence.artifact_verification_deployment_profile_authority_refusals_before_service_proof,
    true,
  );
  expectBool(
    `${rootLabel}.deployment_profile_authority_refusals_before_mutation`,
    terminalEvidence.deployment_profile_authority_refusals_before_mutation,
    true,
  );
  expectBool(
    `${rootLabel}.artifact_verification_deployment_profile_authority_refusals_before_mutation`,
    terminalEvidence.artifact_verification_deployment_profile_authority_refusals_before_mutation,
    true,
  );
  expectBool(
    `${rootLabel}.deployment_profile_authority_refusal_service_proof_started`,
    terminalEvidence.deployment_profile_authority_refusal_service_proof_started,
    false,
  );
  expectBool(
    `${rootLabel}.artifact_verification_deployment_profile_authority_refusal_service_proof_started`,
    terminalEvidence.artifact_verification_deployment_profile_authority_refusal_service_proof_started,
    false,
  );
  expectBool(
    `${rootLabel}.stale_deployment_profile_artifact_refused_before_service_proof`,
    terminalEvidence.stale_deployment_profile_artifact_refused_before_service_proof,
    true,
  );
  expectBool(
    `${rootLabel}.profile_recognition_mismatch_refused_before_service_proof`,
    terminalEvidence.profile_recognition_mismatch_refused_before_service_proof,
    true,
  );
  expectBool(
    `${rootLabel}.latest_profile_selection_refused_before_service_proof`,
    terminalEvidence.latest_profile_selection_refused_before_service_proof,
    true,
  );
  expectBool(
    `${rootLabel}.request_stream_authority_material_refused_before_service_proof`,
    terminalEvidence.request_stream_authority_material_refused_before_service_proof,
    true,
  );
  for (const key of [
    'current_machine_governance',
    'production_downstream_recognition',
    'production_authority',
    'enterprise_readiness',
    'external_attestation',
    'sovereign_recognition',
    'unrouted_surface_coverage',
  ]) {
    expectBool(`${rootLabel}.${key}`, terminalEvidence[key], false);
  }
  return true;
}

function validateReportContractTerminalChainRefusalEvidenceSource(value) {
  const label =
    'release_forward_report_contract.terminal_chain_refusal_evidence';
  if (!isObject(value)) {
    throw new Error(`${label} must be an object`);
  }
  expectExactString(
    `${label}.source`,
    value.source,
    'same-manifest.terminal_chain_refusal_evidence',
  );
}

function expectExactString(label, value, expected) {
  if (value !== expected) {
    throw new Error(`${label} must be ${expected}`);
  }
}

function validatePrivateVerifierResultSamplePointer(pointer, releaseVersion) {
  const label = 'DRY-RUN-MANIFEST.private_verifier_result_sample';
  exactKeys(label, pointer, PRIVATE_VERIFIER_RESULT_SAMPLE_POINTER_KEYS);
  const expectedVerificationSection = versionAtLeast(releaseVersion, [3, 4, 34])
    ? 'Private Result Verification Evidence'
    : 'not-required-for-this-target';
  expectBool(`${label}.enabled`, pointer.enabled, true);
  expectExactString(`${label}.evidence_model`, pointer.evidence_model, 'generated-sample-fixture');
  expectExactString(`${label}.minimum_target`, pointer.minimum_target, 'v3.3.104');
  expectExactString(
    `${label}.envelope_path`,
    pointer.envelope_path,
    'ZLAR/zlar-private-verifier-result-v1.json',
  );
  expectExactString(
    `${label}.verification_path`,
    pointer.verification_path,
    'ZLAR/zlar-private-verifier-result-verification-v1.json',
  );
  expectExactString(`${label}.result_file`, pointer.result_file, 'DRY-RUN-RESULT.md');
  expectExactString(
    `${label}.result_section`,
    pointer.result_section,
    'Private Verifier Result Intake',
  );
  expectExactString(
    `${label}.hash_record_location`,
    pointer.hash_record_location,
    'DRY-RUN-RESULT.md#private-verifier-result-intake',
  );
  expectBool(
    `${label}.included_in_core_artifact_hashes`,
    pointer.included_in_core_artifact_hashes,
    false,
  );
  expectBool(`${label}.circular_hash_avoided`, pointer.circular_hash_avoided, true);
  expectExactString(
    `${label}.verification_result_section`,
    pointer.verification_result_section,
    expectedVerificationSection,
  );
  expectExactString(
    `${label}.verification_result_minimum_target`,
    pointer.verification_result_minimum_target,
    'v3.4.34',
  );
  expectBool(
    `${label}.creates_public_external_attestation`,
    pointer.creates_public_external_attestation,
    false,
  );
  expectBool(`${label}.proves_non_operator_review`, pointer.proves_non_operator_review, false);
}

function verifyEvidenceDirContract(evidenceDir, releaseVersion, report) {
  const requiredForTarget = versionAtLeast(releaseVersion, [3, 4, 46]);
  const nestedArtifactTamperRefusalsRequiredForTarget =
    requiredForTarget && versionAtLeast(releaseVersion, [3, 4, 28]);
  const nestedArtifactBindingRequiredForTarget =
    requiredForTarget && versionAtLeast(releaseVersion, [3, 4, 30]);
  const terminalChainTrustedRegistryRecognitionRefusalsRequiredForTarget =
    requiredForTarget && versionAtLeast(releaseVersion, [3, 4, 39]);
  const terminalChainDeploymentProfileAuthorityRefusalMirrorRequiredForTarget =
    requiredForTarget && versionAtLeast(releaseVersion, [3, 4, 50]);
  const deploymentBridgeRequiredForTarget = versionAtLeast(releaseVersion, [3, 4, 48]);
  const deploymentAuthorityRefusalsRequiredForTarget =
    versionAtLeast(releaseVersion, [3, 4, 49]);
  const terminalChainTrustedRegistryVerdictRequiredForTarget =
    versionAtLeast(releaseVersion, [3, 4, 51]);
  const downstreamRefusalBoundaryRequiredForTarget =
    terminalChainTrustedRegistryVerdictRequiredForTarget;
  const terminalChainRecognizedReceiptPathMirrorRequiredForTarget =
    versionAtLeast(releaseVersion, [3, 4, 52]);
  const contractType = terminalChainRecognizedReceiptPathMirrorRequiredForTarget
    ? PRODUCT_PROOF_PATH_TERMINAL_CHAIN_RECOGNIZED_RECEIPT_PATH_CONTRACT_TYPE
    : terminalChainTrustedRegistryVerdictRequiredForTarget
    ? PRODUCT_PROOF_PATH_TERMINAL_CHAIN_REGISTRY_VERDICT_CONTRACT_TYPE
    : deploymentAuthorityRefusalsRequiredForTarget
    ? PRODUCT_PROOF_PATH_TERMINAL_CHAIN_DEPLOYMENT_PROFILE_BRIDGE_AND_AUTHORITY_REFUSALS_CONTRACT_TYPE
    : deploymentBridgeRequiredForTarget
      ? PRODUCT_PROOF_PATH_TERMINAL_CHAIN_AND_DEPLOYMENT_PROFILE_BRIDGE_CONTRACT_TYPE
      : PRODUCT_PROOF_PATH_TERMINAL_CHAIN_RECOGNITION_GROUP_CONTRACT_TYPE;
  const manifestField = terminalChainRecognizedReceiptPathMirrorRequiredForTarget
    ? PRODUCT_PROOF_PATH_TERMINAL_CHAIN_RECOGNIZED_RECEIPT_PATH_CONTRACT_FIELD
    : terminalChainTrustedRegistryVerdictRequiredForTarget
    ? PRODUCT_PROOF_PATH_TERMINAL_CHAIN_REGISTRY_VERDICT_CONTRACT_FIELD
    : deploymentAuthorityRefusalsRequiredForTarget
      ? PRODUCT_PROOF_PATH_TERMINAL_CHAIN_DEPLOYMENT_PROFILE_BRIDGE_AND_AUTHORITY_REFUSALS_CONTRACT_FIELD
      : deploymentBridgeRequiredForTarget
        ? PRODUCT_PROOF_PATH_TERMINAL_CHAIN_AND_DEPLOYMENT_PROFILE_BRIDGE_CONTRACT_FIELD
        : PRODUCT_PROOF_PATH_TERMINAL_CHAIN_CONTRACT_FIELD;
  if (!evidenceDir) {
    return {
      enabled: false,
      required_for_target: requiredForTarget,
      verified: null,
      contract_type: requiredForTarget ? contractType : 'not-required-for-this-target',
      source_path: requiredForTarget ? 'DRY-RUN-MANIFEST.json' : 'not-required-for-this-target',
      manifest_field: requiredForTarget ? manifestField : 'not-required-for-this-target',
      product_proof_path_terminal_chain_recognition_refusal_group_count: requiredForTarget
        ? Object.keys(expectedTerminalChainRecognitionRefusalGroupCaseIds()).length
        : 0,
      product_proof_path_terminal_chain_recognition_refusal_group_case_count: requiredForTarget
        ? countRecognitionRefusalGroupCaseIds(expectedTerminalChainRecognitionRefusalGroupCaseIds())
        : 0,
      product_proof_path_terminal_chain_recognition_refusal_group_case_ids_preserved: null,
      north_star_terminal_chain_recognition_refusal_group_case_ids_preserved: null,
      terminal_chain_nested_artifact_tamper_refusals_required_for_target:
        nestedArtifactTamperRefusalsRequiredForTarget,
      terminal_chain_nested_artifact_tamper_refusals_preserved: null,
      terminal_chain_nested_artifact_binding_required_for_target:
        nestedArtifactBindingRequiredForTarget,
      terminal_chain_nested_artifact_binding_preserved: null,
      terminal_chain_trusted_registry_recognition_refusals_required_for_target:
        terminalChainTrustedRegistryRecognitionRefusalsRequiredForTarget,
      terminal_chain_trusted_registry_recognition_refusals_preserved: null,
      terminal_chain_deployment_profile_authority_refusal_mirror_required_for_target:
        terminalChainDeploymentProfileAuthorityRefusalMirrorRequiredForTarget,
      terminal_chain_deployment_profile_authority_refusal_mirror_preserved: null,
      deployment_profile_authority_bridge_required_for_target:
        deploymentBridgeRequiredForTarget,
      deployment_profile_authority_refusals_required_for_target:
        deploymentAuthorityRefusalsRequiredForTarget,
      terminal_chain_trusted_registry_verdict_required_for_target:
        terminalChainTrustedRegistryVerdictRequiredForTarget,
      downstream_refusal_boundary_required_for_target:
        downstreamRefusalBoundaryRequiredForTarget,
      terminal_chain_recognized_receipt_path_mirror_required_for_target:
        terminalChainRecognizedReceiptPathMirrorRequiredForTarget,
      product_proof_path_terminal_chain_recognized_receipt_path_mirror_preserved: null,
      north_star_terminal_chain_recognized_receipt_path_mirror_preserved: null,
      terminal_chain_recognized_receipt_path_evidence_sha256: null,
      terminal_chain_recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding:
        null,
      product_proof_path_deployment_profile_authority_bridge_preserved: null,
      north_star_deployment_profile_authority_bridge_preserved: null,
      deployment_profile_authority_bridge_refusal_case_count:
        deploymentBridgeRequiredForTarget ? 18 : 0,
      product_proof_path_deployment_profile_authority_refusals_preserved: null,
      north_star_deployment_profile_authority_refusals_preserved: null,
      deployment_profile_authority_refusal_case_count:
        deploymentAuthorityRefusalsRequiredForTarget
          ? REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length
          : 0,
      deployment_profile_authority_refusal_case_ids_preserved: null,
      deployment_profile_authority_refusals_before_service_proof: null,
      stale_deployment_profile_artifact_refused_before_service_proof: null,
      profile_recognition_mismatch_refused_before_service_proof: null,
      latest_profile_selection_refused_before_service_proof: null,
      request_stream_authority_material_refused_before_service_proof: null,
      deployment_profile_authority_bridge_current_machine_governance: null,
      deployment_profile_authority_bridge_production_authority: null,
      product_proof_path_terminal_chain_trusted_registry_verdict_preserved: null,
      north_star_terminal_chain_trusted_registry_verdict_preserved: null,
      terminal_chain_trusted_registry_recognition_verdict: null,
      terminal_chain_trusted_registry_signature_valid: null,
      product_proof_path_downstream_refusal_boundary_preserved: null,
      north_star_downstream_refusal_boundary_preserved: null,
      downstream_refusal_recognized_marker_count_delta: null,
      downstream_refusal_final_marker_count: null,
      downstream_refusal_case_count: downstreamRefusalBoundaryRequiredForTarget
        ? REQUIRED_DOWNSTREAM_REFUSAL_REASONS.length
        : 0,
      downstream_refusal_all_refusals_unboarded: null,
      downstream_refusal_reasons: [],
      north_star_downstream_refusal_all_refusals_unboarded: null,
      north_star_downstream_refusal_reasons: [],
      downstream_refusal_marker_count_deltas_zero: null,
    };
  }
  if (!requiredForTarget) {
    return {
      enabled: true,
      required_for_target: false,
      verified: null,
      contract_type: 'not-required-for-this-target',
      source_path: 'not-required-for-this-target',
      manifest_field: 'not-required-for-this-target',
      product_proof_path_terminal_chain_recognition_refusal_group_count: 0,
      product_proof_path_terminal_chain_recognition_refusal_group_case_count: 0,
      product_proof_path_terminal_chain_recognition_refusal_group_case_ids_preserved: null,
      north_star_terminal_chain_recognition_refusal_group_case_ids_preserved: null,
      terminal_chain_nested_artifact_tamper_refusals_required_for_target: false,
      terminal_chain_nested_artifact_tamper_refusals_preserved: null,
      terminal_chain_nested_artifact_binding_required_for_target: false,
      terminal_chain_nested_artifact_binding_preserved: null,
      terminal_chain_trusted_registry_recognition_refusals_required_for_target: false,
      terminal_chain_trusted_registry_recognition_refusals_preserved: null,
      terminal_chain_deployment_profile_authority_refusal_mirror_required_for_target: false,
      terminal_chain_deployment_profile_authority_refusal_mirror_preserved: null,
      deployment_profile_authority_bridge_required_for_target: false,
      deployment_profile_authority_refusals_required_for_target: false,
      terminal_chain_trusted_registry_verdict_required_for_target: false,
      downstream_refusal_boundary_required_for_target: false,
      terminal_chain_recognized_receipt_path_mirror_required_for_target: false,
      product_proof_path_terminal_chain_recognized_receipt_path_mirror_preserved: null,
      north_star_terminal_chain_recognized_receipt_path_mirror_preserved: null,
      terminal_chain_recognized_receipt_path_evidence_sha256: null,
      terminal_chain_recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding:
        null,
      product_proof_path_deployment_profile_authority_bridge_preserved: null,
      north_star_deployment_profile_authority_bridge_preserved: null,
      deployment_profile_authority_bridge_refusal_case_count: 0,
      product_proof_path_deployment_profile_authority_refusals_preserved: null,
      north_star_deployment_profile_authority_refusals_preserved: null,
      deployment_profile_authority_refusal_case_count: 0,
      deployment_profile_authority_refusal_case_ids_preserved: null,
      deployment_profile_authority_refusals_before_service_proof: null,
      stale_deployment_profile_artifact_refused_before_service_proof: null,
      profile_recognition_mismatch_refused_before_service_proof: null,
      latest_profile_selection_refused_before_service_proof: null,
      request_stream_authority_material_refused_before_service_proof: null,
      deployment_profile_authority_bridge_current_machine_governance: null,
      deployment_profile_authority_bridge_production_authority: null,
      product_proof_path_terminal_chain_trusted_registry_verdict_preserved: null,
      north_star_terminal_chain_trusted_registry_verdict_preserved: null,
      terminal_chain_trusted_registry_recognition_verdict: null,
      terminal_chain_trusted_registry_signature_valid: null,
      product_proof_path_downstream_refusal_boundary_preserved: null,
      north_star_downstream_refusal_boundary_preserved: null,
      downstream_refusal_recognized_marker_count_delta: null,
      downstream_refusal_final_marker_count: null,
      downstream_refusal_case_count: 0,
      downstream_refusal_all_refusals_unboarded: null,
      downstream_refusal_reasons: [],
      north_star_downstream_refusal_all_refusals_unboarded: null,
      north_star_downstream_refusal_reasons: [],
      downstream_refusal_marker_count_deltas_zero: null,
    };
  }

  const expectedGroups = expectedTerminalChainRecognitionRefusalGroupCaseIds();
  const expectedGroupCount = Object.keys(expectedGroups).length;
  const expectedCaseCount = countRecognitionRefusalGroupCaseIds(expectedGroups);
  const reportHashByPath = artifactHashMapFromEntries(
    'evidence.artifact_hashes',
    report.evidence.artifact_hashes,
  );
  const manifest = readEvidenceArtifactJson(evidenceDir, 'DRY-RUN-MANIFEST.json');
  const reportContract = manifest.release_forward_report_contract || {};
  validateEvidenceManifestTarget({ manifest, report, evidenceDir });
  const manifestHashByPath = validateReleaseForwardManifestArtifactHashes({
    manifest,
    reportHashByPath,
  });
  validateReleaseForwardSourceArtifacts({
    sourceArtifacts: reportContract.source_artifacts,
    manifestHashByPath,
    reportHashByPath,
  });
  const terminalChainRefusalEvidence = manifest.terminal_chain_refusal_evidence || {};
  const reportContractTerminalChainRefusalEvidence =
    reportContract.terminal_chain_refusal_evidence || {};
  const terminalChainNestedArtifactTamperRefusalsPreserved =
    nestedArtifactTamperRefusalsRequiredForTarget
      ? validateTerminalChainNestedArtifactTamperRefusals(terminalChainRefusalEvidence)
      : null;
  const terminalChainNestedArtifactBindingPreserved =
    nestedArtifactBindingRequiredForTarget
      ? validateTerminalChainNestedArtifactBinding(terminalChainRefusalEvidence)
      : null;
  const terminalChainTrustedRegistryRecognitionRefusalsPreserved =
    terminalChainTrustedRegistryRecognitionRefusalsRequiredForTarget
      ? validateTerminalChainTrustedRegistryRecognitionRefusals(
          terminalChainRefusalEvidence,
        )
      : null;
  if (
    !terminalChainTrustedRegistryRecognitionRefusalsRequiredForTarget &&
    hasTerminalChainTrustedRegistryRecognitionRefusalFields(terminalChainRefusalEvidence)
  ) {
    throw new Error(
      'private verifier evidence contract terminal-chain trusted-registry recognition refusals appeared before v3.4.39'
    );
  }
  if (
    !terminalChainDeploymentProfileAuthorityRefusalMirrorRequiredForTarget &&
    hasTerminalChainDeploymentProfileAuthorityRefusalMirrorFields(
      terminalChainRefusalEvidence,
    )
  ) {
    throw new Error(
      'private verifier evidence contract terminal-chain deployment-profile authority-refusal mirror appeared before v3.4.50'
    );
  }
  const terminalChainDeploymentProfileAuthorityRefusalMirrorPreserved =
    terminalChainDeploymentProfileAuthorityRefusalMirrorRequiredForTarget
      ? validateTerminalChainDeploymentProfileAuthorityRefusalMirror(
          terminalChainRefusalEvidence,
        )
      : null;
  const terminalChainRecognitionRefusalGroupCaseIdsPreserved =
    terminalChainRefusalEvidence.recognition_refusal_group_case_ids_required === true &&
    terminalChainRefusalEvidence.all_recognition_refusal_group_case_ids_preserved === true &&
    recognitionRefusalGroupCaseIdsPass(
      terminalChainRefusalEvidence.recognition_refusal_group_case_ids || {},
      expectedGroups,
    );
  if (!terminalChainRecognitionRefusalGroupCaseIdsPreserved) {
    throw new Error(
      'private verifier evidence contract terminal-chain recognition refusal group case IDs drifted'
    );
  }
  validateReportContractRecognitionRefusalGroupCaseIds(
    reportContract.proof_smoke?.counts,
    'report-contract proof-smoke',
    expectedGroups,
  );
  validateReportContractRecognitionRefusalGroupCaseIds(
    reportContract.north_star?.counts,
    'report-contract north-star',
    expectedGroups,
    { includeRequiredPreserved: true },
  );
  validateReportContractTerminalChainRefusalEvidenceSource(
    reportContractTerminalChainRefusalEvidence,
  );
  if (terminalChainTrustedRegistryRecognitionRefusalsRequiredForTarget) {
    validateTerminalChainTrustedRegistryRecognitionRefusals(
      reportContractTerminalChainRefusalEvidence,
      'release_forward_report_contract.terminal_chain_refusal_evidence',
      { includeMinimumTarget: false },
    );
    validateMirroredFamilyMatchesRoot({
      rootLabel: 'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence',
      rootValue: terminalChainRefusalEvidence,
      mirrorLabel: 'release_forward_report_contract.terminal_chain_refusal_evidence',
      mirrorValue: reportContractTerminalChainRefusalEvidence,
      keys: REPORT_CONTRACT_TERMINAL_CHAIN_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_KEYS,
      familyLabel: 'trusted_issuer_registry_recognition_refusals',
    });
    validateReportContractProofSummaryTrustedRegistryRecognitionRefusals(
      reportContract.proof_smoke?.counts,
      terminalChainRefusalEvidence,
      'release_forward_report_contract.proof_smoke.counts',
      REPORT_CONTRACT_PROOF_SMOKE_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_KEYS,
      REPORT_CONTRACT_PROOF_SUMMARY_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_ROOT_KEY_MAP,
    );
    validateReportContractProofSummaryTrustedRegistryRecognitionRefusals(
      reportContract.north_star?.counts,
      terminalChainRefusalEvidence,
      'release_forward_report_contract.north_star.counts',
      REPORT_CONTRACT_NORTH_STAR_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_KEYS,
      REPORT_CONTRACT_NORTH_STAR_TRUSTED_REGISTRY_RECOGNITION_REFUSAL_ROOT_KEY_MAP,
      { includePreserved: true },
    );
    validateReportContractObservedTrustedRegistryRecognitionRefusals(
      reportContract.north_star?.puzzle_3_observed,
      terminalChainRefusalEvidence,
      'release_forward_report_contract.north_star.puzzle_3_observed',
    );
    validateReportContractObservedTrustedRegistryRecognitionRefusals(
      reportContract.north_star?.puzzle_5_observed,
      terminalChainRefusalEvidence,
      'release_forward_report_contract.north_star.puzzle_5_observed',
    );
  }
  if (
    !terminalChainTrustedRegistryRecognitionRefusalsRequiredForTarget &&
    hasTerminalChainTrustedRegistryRecognitionRefusalFields(
      reportContractTerminalChainRefusalEvidence,
    )
  ) {
    throw new Error(
      'private verifier evidence contract report-contract trusted-registry recognition refusals appeared before v3.4.39'
    );
  }
  if (
    !terminalChainDeploymentProfileAuthorityRefusalMirrorRequiredForTarget &&
    hasTerminalChainDeploymentProfileAuthorityRefusalMirrorFields(
      reportContractTerminalChainRefusalEvidence,
    )
  ) {
    throw new Error(
      'private verifier evidence contract report-contract deployment-profile authority-refusal mirror appeared before v3.4.50'
    );
  }
  if (terminalChainDeploymentProfileAuthorityRefusalMirrorRequiredForTarget) {
    validateTerminalChainDeploymentProfileAuthorityRefusalMirror(
      reportContractTerminalChainRefusalEvidence,
      'release_forward_report_contract.terminal_chain_refusal_evidence',
      { includeMinimumTarget: false },
    );
    validateMirroredFamilyMatchesRoot({
      rootLabel: 'DRY-RUN-MANIFEST.terminal_chain_refusal_evidence',
      rootValue: terminalChainRefusalEvidence,
      mirrorLabel: 'release_forward_report_contract.terminal_chain_refusal_evidence',
      mirrorValue: reportContractTerminalChainRefusalEvidence,
      keys: REPORT_CONTRACT_TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_MIRROR_KEYS,
      familyLabel: 'deployment_profile_authority_refusal_mirror',
    });
  }
  validateFalseClaimBoundary(
    'release_forward_report_contract.claim_boundary',
    reportContract.claim_boundary,
    RELEASE_FORWARD_REPORT_CONTRACT_CLAIM_BOUNDARY_KEYS,
  );
  const productContract = reportContract.product_proof_path || {};
  validateFalseClaimBoundary(
    'release_forward_report_contract.product_proof_path.claim_boundary',
    productContract.claim_boundary,
    RELEASE_FORWARD_PRODUCT_PROOF_PATH_CLAIM_BOUNDARY_KEYS,
  );
  validateProductProofPathSimulatedHumanAuthorization(
    productContract.simulated_human_authorization,
  );
  validateProductProofPathReceiptVerifierBoundary(
    productContract.receipt_verifier_boundary,
  );
  validatePrivateVerifierResultSamplePointer(
    manifest.private_verifier_result_sample,
    releaseVersion,
  );
  const terminalBoundary = productContract.terminal_chain_boundary || {};
  const northStar = productContract.north_star || {};
  const terminalGroups =
    terminalBoundary.recognition_refusal_group_case_ids || {};
  const northStarGroups =
    northStar.terminal_chain_recognition_refusal_group_case_ids || {};
  const terminalGroupsPreserved =
    terminalBoundary.recognition_refusal_group_count === expectedGroupCount &&
    terminalBoundary.recognition_refusal_group_case_count === expectedCaseCount &&
    terminalBoundary.recognition_refusal_group_case_ids_preserved === true &&
    recognitionRefusalGroupCaseIdsPass(terminalGroups, expectedGroups);
  const northStarGroupsPreserved =
    northStar.terminal_chain_recognition_refusal_group_count === expectedGroupCount &&
    northStar.terminal_chain_recognition_refusal_group_case_count === expectedCaseCount &&
    northStar.terminal_chain_recognition_refusal_group_case_ids_preserved === true &&
    recognitionRefusalGroupCaseIdsPass(northStarGroups, expectedGroups);

  if (!terminalGroupsPreserved || !northStarGroupsPreserved) {
    throw new Error(
      'private verifier evidence contract product proof path terminal chain recognition refusal group case IDs drifted'
    );
  }
  if (
    deploymentBridgeRequiredForTarget &&
    !deploymentAuthorityRefusalsRequiredForTarget &&
    hasDeploymentProfileAuthorityRefusalFields(productContract, northStar)
  ) {
    throw new Error(
      'private verifier evidence contract product proof path deployment-profile authority refusals appeared before v3.4.49'
    );
  }
  const deploymentBridgePreserved = deploymentBridgeRequiredForTarget
    ? deploymentProfileAuthorityBridgePasses(
        productContract.deployment_profile_authority_bridge,
        deploymentAuthorityRefusalsRequiredForTarget,
      )
    : null;
  const northStarDeploymentBridgePreserved = deploymentBridgeRequiredForTarget
    ? deploymentProfileAuthorityBridgeNorthStarPasses(
        northStar,
        deploymentAuthorityRefusalsRequiredForTarget,
      )
    : null;
  if (
    deploymentBridgeRequiredForTarget &&
    (!deploymentBridgePreserved || !northStarDeploymentBridgePreserved)
  ) {
    throw new Error(
      'private verifier evidence contract product proof path deployment-profile authority bridge drifted'
    );
  }
  const deploymentAuthorityRefusalsPreserved =
    deploymentAuthorityRefusalsRequiredForTarget
      ? deploymentProfileAuthorityRefusalsPasses(
          productContract.deployment_profile_authority_bridge
        )
      : null;
  const northStarDeploymentAuthorityRefusalsPreserved =
    deploymentAuthorityRefusalsRequiredForTarget
      ? deploymentProfileAuthorityRefusalsNorthStarPasses(northStar)
      : null;
  if (
    deploymentAuthorityRefusalsRequiredForTarget &&
    (!deploymentAuthorityRefusalsPreserved ||
      !northStarDeploymentAuthorityRefusalsPreserved)
  ) {
    throw new Error(
      'private verifier evidence contract product proof path deployment-profile authority refusals drifted'
    );
  }
  if (
    !terminalChainTrustedRegistryVerdictRequiredForTarget &&
    hasTerminalChainTrustedRegistryVerdictFields(productContract, northStar)
  ) {
    throw new Error(
      'private verifier evidence contract product proof path terminal chain trusted-registry verdict appeared before v3.4.51'
    );
  }
  const terminalChainTrustedRegistryVerdictPreserved =
    terminalChainTrustedRegistryVerdictRequiredForTarget
      ? terminalChainTrustedRegistryVerdictPasses(terminalBoundary)
      : null;
  const northStarTerminalChainTrustedRegistryVerdictPreserved =
    terminalChainTrustedRegistryVerdictRequiredForTarget
      ? northStarTerminalChainTrustedRegistryVerdictPasses(northStar)
      : null;
  if (
    terminalChainTrustedRegistryVerdictRequiredForTarget &&
    (!terminalChainTrustedRegistryVerdictPreserved ||
      !northStarTerminalChainTrustedRegistryVerdictPreserved)
  ) {
    throw new Error(
      'private verifier evidence contract product proof path terminal chain trusted-registry verdict drifted'
    );
  }
  if (
    !downstreamRefusalBoundaryRequiredForTarget &&
    (Object.hasOwn(productContract, 'downstream_refusal_boundary') ||
      Object.hasOwn(northStar, 'downstream_refusal_boundary'))
  ) {
    throw new Error(
      'private verifier evidence contract product proof path downstream-refusal boundary appeared before v3.4.51'
    );
  }
  const productProofPathDownstreamRefusalBoundaryPreserved =
    downstreamRefusalBoundaryRequiredForTarget
      ? downstreamRefusalBoundaryPasses(productContract.downstream_refusal_boundary)
      : null;
  const northStarDownstreamRefusalBoundaryPreserved =
    downstreamRefusalBoundaryRequiredForTarget
      ? downstreamRefusalBoundaryPasses(northStar.downstream_refusal_boundary)
      : null;
  if (
    downstreamRefusalBoundaryRequiredForTarget &&
    (!productProofPathDownstreamRefusalBoundaryPreserved ||
      !northStarDownstreamRefusalBoundaryPreserved)
  ) {
    throw new Error(
      'private verifier evidence contract product proof path downstream-refusal boundary drifted'
    );
  }
  if (
    !terminalChainRecognizedReceiptPathMirrorRequiredForTarget &&
    hasTerminalChainRecognizedReceiptPathMirrorFields(productContract, northStar)
  ) {
    throw new Error(
      'private verifier evidence contract product proof path recognized receipt path mirror appeared before v3.4.52'
    );
  }
  const productProofPathTerminalChainRecognizedReceiptPathMirrorPreserved =
    terminalChainRecognizedReceiptPathMirrorRequiredForTarget
      ? recognizedReceiptPathMirrorPasses(terminalBoundary)
      : null;
  const northStarTerminalChainRecognizedReceiptPathMirrorPreserved =
    terminalChainRecognizedReceiptPathMirrorRequiredForTarget
      ? northStarRecognizedReceiptPathMirrorPasses(northStar, terminalBoundary)
      : null;
  if (
    terminalChainRecognizedReceiptPathMirrorRequiredForTarget &&
    (!productProofPathTerminalChainRecognizedReceiptPathMirrorPreserved ||
      !northStarTerminalChainRecognizedReceiptPathMirrorPreserved)
  ) {
    throw new Error(
      'private verifier evidence contract product proof path recognized receipt path mirror drifted'
    );
  }

  return {
    enabled: true,
    required_for_target: true,
    verified: true,
    contract_type: contractType,
    source_path: 'DRY-RUN-MANIFEST.json',
    manifest_field: manifestField,
    product_proof_path_terminal_chain_recognition_refusal_group_count: expectedGroupCount,
    product_proof_path_terminal_chain_recognition_refusal_group_case_count: expectedCaseCount,
    product_proof_path_terminal_chain_recognition_refusal_group_case_ids_preserved:
      terminalGroupsPreserved,
    north_star_terminal_chain_recognition_refusal_group_case_ids_preserved:
      northStarGroupsPreserved,
    terminal_chain_nested_artifact_tamper_refusals_required_for_target:
      nestedArtifactTamperRefusalsRequiredForTarget,
    terminal_chain_nested_artifact_tamper_refusals_preserved:
      terminalChainNestedArtifactTamperRefusalsPreserved,
    terminal_chain_nested_artifact_binding_required_for_target:
      nestedArtifactBindingRequiredForTarget,
    terminal_chain_nested_artifact_binding_preserved:
      terminalChainNestedArtifactBindingPreserved,
    terminal_chain_trusted_registry_recognition_refusals_required_for_target:
      terminalChainTrustedRegistryRecognitionRefusalsRequiredForTarget,
    terminal_chain_trusted_registry_recognition_refusals_preserved:
      terminalChainTrustedRegistryRecognitionRefusalsPreserved,
    terminal_chain_deployment_profile_authority_refusal_mirror_required_for_target:
      terminalChainDeploymentProfileAuthorityRefusalMirrorRequiredForTarget,
    terminal_chain_deployment_profile_authority_refusal_mirror_preserved:
      terminalChainDeploymentProfileAuthorityRefusalMirrorPreserved,
    deployment_profile_authority_bridge_required_for_target:
      deploymentBridgeRequiredForTarget,
    deployment_profile_authority_refusals_required_for_target:
      deploymentAuthorityRefusalsRequiredForTarget,
    terminal_chain_trusted_registry_verdict_required_for_target:
      terminalChainTrustedRegistryVerdictRequiredForTarget,
    downstream_refusal_boundary_required_for_target:
      downstreamRefusalBoundaryRequiredForTarget,
    terminal_chain_recognized_receipt_path_mirror_required_for_target:
      terminalChainRecognizedReceiptPathMirrorRequiredForTarget,
    product_proof_path_terminal_chain_recognized_receipt_path_mirror_preserved:
      productProofPathTerminalChainRecognizedReceiptPathMirrorPreserved,
    north_star_terminal_chain_recognized_receipt_path_mirror_preserved:
      northStarTerminalChainRecognizedReceiptPathMirrorPreserved,
    terminal_chain_recognized_receipt_path_evidence_sha256:
      terminalChainRecognizedReceiptPathMirrorRequiredForTarget
        ? terminalBoundary.recognized_receipt_path_evidence_sha256
        : null,
    terminal_chain_recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding:
      terminalChainRecognizedReceiptPathMirrorRequiredForTarget
        ? terminalBoundary
            .recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding
        : null,
    product_proof_path_deployment_profile_authority_bridge_preserved:
      deploymentBridgePreserved,
    north_star_deployment_profile_authority_bridge_preserved:
      northStarDeploymentBridgePreserved,
    deployment_profile_authority_bridge_refusal_case_count:
      deploymentBridgeRequiredForTarget ? 18 : 0,
    product_proof_path_deployment_profile_authority_refusals_preserved:
      deploymentAuthorityRefusalsPreserved,
    north_star_deployment_profile_authority_refusals_preserved:
      northStarDeploymentAuthorityRefusalsPreserved,
    deployment_profile_authority_refusal_case_count:
      deploymentAuthorityRefusalsRequiredForTarget
        ? REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length
        : 0,
    deployment_profile_authority_refusal_case_ids_preserved:
      deploymentAuthorityRefusalsRequiredForTarget
        ? arraysEqual(
            productContract.deployment_profile_authority_bridge
              ?.deployment_profile_authority_refusal_case_ids,
            REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES,
          )
        : null,
    deployment_profile_authority_refusals_before_service_proof:
      deploymentAuthorityRefusalsRequiredForTarget
        ? productContract.deployment_profile_authority_bridge
            .deployment_profile_authority_refusals_before_service_proof
        : null,
    stale_deployment_profile_artifact_refused_before_service_proof:
      deploymentAuthorityRefusalsRequiredForTarget
        ? productContract.deployment_profile_authority_bridge
            .stale_deployment_profile_artifact_refused_before_service_proof
        : null,
    profile_recognition_mismatch_refused_before_service_proof:
      deploymentAuthorityRefusalsRequiredForTarget
        ? productContract.deployment_profile_authority_bridge
            .profile_recognition_mismatch_refused_before_service_proof
        : null,
    latest_profile_selection_refused_before_service_proof:
      deploymentAuthorityRefusalsRequiredForTarget
        ? productContract.deployment_profile_authority_bridge
            .latest_profile_selection_refused_before_service_proof
        : null,
    request_stream_authority_material_refused_before_service_proof:
      deploymentAuthorityRefusalsRequiredForTarget
        ? productContract.deployment_profile_authority_bridge
            .request_stream_authority_material_refused_before_service_proof
        : null,
    deployment_profile_authority_bridge_current_machine_governance:
      deploymentBridgeRequiredForTarget
        ? productContract.deployment_profile_authority_bridge.current_machine_governance
        : null,
    deployment_profile_authority_bridge_production_authority:
      deploymentBridgeRequiredForTarget
        ? productContract.deployment_profile_authority_bridge.production_authority
        : null,
    product_proof_path_terminal_chain_trusted_registry_verdict_preserved:
      terminalChainTrustedRegistryVerdictPreserved,
    north_star_terminal_chain_trusted_registry_verdict_preserved:
      northStarTerminalChainTrustedRegistryVerdictPreserved,
    terminal_chain_trusted_registry_recognition_verdict:
      terminalChainTrustedRegistryVerdictRequiredForTarget
        ? terminalBoundary.trusted_issuer_registry_recognition_verdict
        : null,
    terminal_chain_trusted_registry_signature_valid:
      terminalChainTrustedRegistryVerdictRequiredForTarget
        ? terminalBoundary.trusted_issuer_registry_recognition_signature_valid
        : null,
    product_proof_path_downstream_refusal_boundary_preserved:
      productProofPathDownstreamRefusalBoundaryPreserved,
    north_star_downstream_refusal_boundary_preserved:
      northStarDownstreamRefusalBoundaryPreserved,
    downstream_refusal_recognized_marker_count_delta:
      downstreamRefusalBoundaryRequiredForTarget
        ? productContract.downstream_refusal_boundary.recognized_marker_count_delta
        : null,
    downstream_refusal_final_marker_count:
      downstreamRefusalBoundaryRequiredForTarget
        ? productContract.downstream_refusal_boundary.final_marker_count
        : null,
    downstream_refusal_case_count: downstreamRefusalBoundaryRequiredForTarget
      ? productContract.downstream_refusal_boundary.refusal_case_count
      : 0,
    downstream_refusal_all_refusals_unboarded:
      downstreamRefusalBoundaryRequiredForTarget
        ? productContract.downstream_refusal_boundary.all_refusals_unboarded
        : null,
    downstream_refusal_reasons: downstreamRefusalBoundaryRequiredForTarget
      ? [...productContract.downstream_refusal_boundary.refusal_reasons]
      : [],
    north_star_downstream_refusal_all_refusals_unboarded:
      downstreamRefusalBoundaryRequiredForTarget
        ? northStar.downstream_refusal_boundary.all_refusals_unboarded
        : null,
    north_star_downstream_refusal_reasons: downstreamRefusalBoundaryRequiredForTarget
      ? [...northStar.downstream_refusal_boundary.refusal_reasons]
      : [],
    downstream_refusal_marker_count_deltas_zero:
      downstreamRefusalBoundaryRequiredForTarget
        ? productContract.downstream_refusal_boundary.all_refusal_marker_count_deltas_zero
        : null,
  };
}

export function assertNoUnsafePrivateVerifierResultText(text) {
  assertSafeText(text);
  return true;
}

export function assertPrivateVerifierResult(report) {
  exactKeys('private verifier result', report, [
    'report_type',
    'schema_version',
    'generated_at',
    'intake_class',
    'target',
    'verifier',
    'custody',
    'review_result',
    'evidence',
    'privacy',
    'claim_boundary',
    'non_claims',
  ]);

  if (report.report_type !== PRIVATE_VERIFIER_RESULT_TYPE) {
    throw new Error(`report_type must be ${PRIVATE_VERIFIER_RESULT_TYPE}`);
  }
  if (report.schema_version !== 1) {
    throw new Error('schema_version must be 1');
  }
  if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(report.generated_at)) {
    throw new Error('generated_at must be an ISO-8601 UTC timestamp without private locale data');
  }
  if (!['sample-fixture', 'private-verifier-reply'].includes(report.intake_class)) {
    throw new Error('intake_class must be sample-fixture or private-verifier-reply');
  }

  exactKeys('target', report.target, [
    'release_tag',
    'expected_commit_sha',
    'commit_sha',
    'moving_target_used',
  ]);
  const releaseVersion = parseReleaseTag(report.target.release_tag);
  if (!isCommitSha(report.target.expected_commit_sha)) {
    throw new Error('target.expected_commit_sha must be 40-character lowercase hex');
  }
  if (!isCommitSha(report.target.commit_sha)) {
    throw new Error('target.commit_sha must be 40-character lowercase hex');
  }
  if (report.target.commit_sha !== report.target.expected_commit_sha) {
    throw new Error('target commit must match expected commit');
  }
  expectBool('target.moving_target_used', report.target.moving_target_used, false);

  exactKeys('verifier', report.verifier, [
    'public_label',
    'relationship_to_zlar',
    'identity_public',
    'contact_public',
  ]);
  expectString('verifier.public_label', report.verifier.public_label);
  expectString('verifier.relationship_to_zlar', report.verifier.relationship_to_zlar);
  assertVerifierDescriptor({
    intakeClass: report.intake_class,
    releaseTag: report.target.release_tag,
    verifier: report.verifier,
  });
  expectBool('verifier.identity_public', report.verifier.identity_public, false);
  expectBool('verifier.contact_public', report.verifier.contact_public, false);

  exactKeys('custody', report.custody, [
    'source_channel_recorded_privately',
    'received_timestamp_recorded_privately',
    'raw_reply_publicly_committed',
    'private_storage_required',
    'public_repo_material_contains_private_identity',
  ]);
  expectBool('custody.raw_reply_publicly_committed', report.custody.raw_reply_publicly_committed, false);
  expectBool('custody.private_storage_required', report.custody.private_storage_required, true);
  expectBool(
    'custody.public_repo_material_contains_private_identity',
    report.custody.public_repo_material_contains_private_identity,
    false
  );
  if (report.intake_class === 'private-verifier-reply') {
    expectBool(
      'custody.source_channel_recorded_privately',
      report.custody.source_channel_recorded_privately,
      true
    );
    expectBool(
      'custody.received_timestamp_recorded_privately',
      report.custody.received_timestamp_recorded_privately,
      true
    );
  } else {
    expectBool(
      'custody.source_channel_recorded_privately',
      report.custody.source_channel_recorded_privately,
      false
    );
    expectBool(
      'custody.received_timestamp_recorded_privately',
      report.custody.received_timestamp_recorded_privately,
      false
    );
  }

  exactKeys('review_result', report.review_result, [
    'verdict',
    'completed_by_non_operator',
    'commands_completed_without_usage_coaching',
    'used_explicit_release_tag',
    'used_expected_commit_sha',
    'used_latest',
    'result_summary',
  ]);
  if (!['PASS', 'PARTIAL', 'FAIL'].includes(report.review_result.verdict)) {
    throw new Error('review_result.verdict must be PASS, PARTIAL, or FAIL');
  }
  if (report.intake_class === 'sample-fixture') {
    expectBool(
      'review_result.completed_by_non_operator',
      report.review_result.completed_by_non_operator,
      false
    );
  } else {
    expectBool(
      'review_result.completed_by_non_operator',
      report.review_result.completed_by_non_operator,
      true
    );
  }
  expectBool(
    'review_result.commands_completed_without_usage_coaching',
    report.review_result.commands_completed_without_usage_coaching,
    true
  );
  expectBool('review_result.used_explicit_release_tag', report.review_result.used_explicit_release_tag, true);
  expectBool('review_result.used_expected_commit_sha', report.review_result.used_expected_commit_sha, true);
  expectBool('review_result.used_latest', report.review_result.used_latest, false);
  expectString('review_result.result_summary', report.review_result.result_summary);
  assertResultSummary({
    intakeClass: report.intake_class,
    releaseTag: report.target.release_tag,
    verdict: report.review_result.verdict,
    resultSummary: report.review_result.result_summary,
  });

  exactKeys('evidence', report.evidence, [
    'evidence_model',
    'received_bundle_sha256',
    'archive_integrity_checked',
    'checksum_verification_checked',
    'json_artifacts_validated',
    'latest_substitution_scan_passed',
    'identity_secret_scan_passed',
    'artifact_hashes',
  ]);
  if (report.evidence.evidence_model !== 'release-forward-dry-run-artifacts') {
    throw new Error('evidence.evidence_model must be release-forward-dry-run-artifacts');
  }
  if (!isHexSha(report.evidence.received_bundle_sha256)) {
    throw new Error('evidence.received_bundle_sha256 must be 64 lowercase hex');
  }
  expectBool('evidence.archive_integrity_checked', report.evidence.archive_integrity_checked, true);
  expectBool('evidence.checksum_verification_checked', report.evidence.checksum_verification_checked, true);
  expectBool('evidence.json_artifacts_validated', report.evidence.json_artifacts_validated, true);
  expectBool('evidence.latest_substitution_scan_passed', report.evidence.latest_substitution_scan_passed, true);
  expectBool('evidence.identity_secret_scan_passed', report.evidence.identity_secret_scan_passed, true);
  assertArtifactHashes(report, releaseVersion);

  exactKeys('privacy', report.privacy, [
    'private_by_default',
    ...PRIVACY_FALSE_KEYS,
  ]);
  expectBool('privacy.private_by_default', report.privacy.private_by_default, true);
  for (const key of PRIVACY_FALSE_KEYS) {
    expectBool(`privacy.${key}`, report.privacy[key], false);
  }

  exactKeys('claim_boundary', report.claim_boundary, [
    'private_intake_only',
    ...CLAIM_BOUNDARY_FALSE_KEYS,
  ]);
  expectBool('claim_boundary.private_intake_only', report.claim_boundary.private_intake_only, true);
  for (const key of CLAIM_BOUNDARY_FALSE_KEYS) {
    expectBool(`claim_boundary.${key}`, report.claim_boundary[key], false);
  }

  if (!Array.isArray(report.non_claims) || report.non_claims.length === 0) {
    throw new Error('non_claims must be a non-empty array with required private-intake boundaries');
  }
  for (const claim of report.non_claims) {
    expectString('non_claims[]', claim);
  }
  for (const fragment of REQUIRED_NON_CLAIM_FRAGMENTS) {
    if (!report.non_claims.some((claim) => claim.includes(fragment))) {
      throw new Error(`non_claims missing required boundary: ${fragment}`);
    }
  }

  assertSafeText(JSON.stringify(report));
  return true;
}

export function buildPrivateVerifierResultVerification(report, options = {}) {
  assertPrivateVerifierResult(report);
  const artifactHashes = report.evidence.artifact_hashes;
  const resultSha256 =
    typeof options.resultText === 'string'
      ? sha256Text(options.resultText)
      : null;
  if (resultSha256 !== null) {
    expectSha256('result_sha256', resultSha256);
  }
  const artifactSetSha256 = privateVerifierArtifactSetSha256(artifactHashes);
  const releaseVersion = parseReleaseTag(report.target.release_tag);
  const evidenceDirHashVerification = options.evidenceDir
    ? verifyArtifactHashesAgainstEvidenceDir(report, options.evidenceDir)
    : {
        enabled: false,
        hashes_recomputed: false,
        verified: null,
        artifact_hash_count: 0,
        checked_paths: [],
      };
  const evidenceDirContractVerification = verifyEvidenceDirContract(
    options.evidenceDir,
    releaseVersion,
    report,
  );
  const requiredIdentity = buildRequiredIdentityVerification({
    report,
    resultSha256,
    artifactSetSha256,
    evidenceDirHashVerification,
    options,
  });
  return {
    verification_type: PRIVATE_VERIFIER_RESULT_VERIFICATION_TYPE,
    verified: true,
    report_type: report.report_type,
    intake_class: report.intake_class,
    verdict: report.review_result.verdict,
    release_tag: report.target.release_tag,
    commit_sha: report.target.commit_sha,
    result_sha256: resultSha256,
    artifact_set_sha256: artifactSetSha256,
    evidence_model: report.evidence.evidence_model,
    artifact_hash_count: artifactHashes.length,
    completed_by_non_operator: report.review_result.completed_by_non_operator,
    private_by_default: report.privacy.private_by_default,
    public_external_attestation: report.claim_boundary.public_external_attestation,
    public_attribution: report.claim_boundary.public_attribution,
    non_operator_review_publicly_claimed:
      report.claim_boundary.non_operator_review_publicly_claimed,
    production_authority: report.claim_boundary.production_authority,
    enterprise_readiness: report.claim_boundary.enterprise_readiness,
    current_machine_governance: report.claim_boundary.current_machine_governance,
    live_mcp_coverage: report.claim_boundary.live_mcp_coverage,
    v3_4_0_readiness: report.claim_boundary.v3_4_0_readiness,
    required_artifacts_checked: expectedArtifactsForRelease(releaseVersion),
    required_identity: requiredIdentity,
    evidence_dir_hash_verification: evidenceDirHashVerification,
    evidence_dir_contract_verification: evidenceDirContractVerification,
    claim_boundary: report.claim_boundary,
    privacy: report.privacy,
    non_claims: report.non_claims,
  };
}

export function formatPrivateVerifierResultVerification(verification) {
  const lines = [
    'ZLAR Private Verifier Result Verification v1',
    `verified=${verification.verified}`,
    `intake_class=${verification.intake_class}`,
    `verdict=${verification.verdict}`,
    `target=${verification.release_tag}@${verification.commit_sha}`,
    `result_sha256=${verification.result_sha256 || 'not-provided'}`,
    `artifact_set_sha256=${verification.artifact_set_sha256}`,
    `evidence_model=${verification.evidence_model}`,
    `artifact_hash_count=${verification.artifact_hash_count}`,
    `required_identity.command_posture=${verification.required_identity.command_posture}`,
    `required_identity.result_sha256_required=${verification.required_identity.result_sha256_required}`,
    `required_identity.result_sha256_matched=${verification.required_identity.result_sha256_matched}`,
    `required_identity.target_required=${verification.required_identity.target_required}`,
    `required_identity.target_matched=${verification.required_identity.target_matched}`,
    `required_identity.bundle_sha256_required=${verification.required_identity.bundle_sha256_required}`,
    `required_identity.bundle_sha256_matched=${verification.required_identity.bundle_sha256_matched}`,
    `required_identity.artifact_set_sha256_required=${verification.required_identity.artifact_set_sha256_required}`,
    `required_identity.artifact_set_sha256_matched=${verification.required_identity.artifact_set_sha256_matched}`,
    `required_identity.recomputed_evidence_required=${verification.required_identity.recomputed_evidence_required}`,
    `required_identity.recomputed_evidence_matched=${verification.required_identity.recomputed_evidence_matched}`,
    `evidence_dir_hash_verification=${
      verification.evidence_dir_hash_verification.hashes_recomputed ? 'passed' : 'not-run'
    }`,
    `evidence_dir_contract_verification=${
      verification.evidence_dir_contract_verification.verified === true
        ? 'passed'
        : verification.evidence_dir_contract_verification.enabled
          ? 'not-required-for-this-target'
          : 'not-run'
    }`,
    `terminal_chain_nested_artifact_tamper_refusals_required_for_target=${verification.evidence_dir_contract_verification.terminal_chain_nested_artifact_tamper_refusals_required_for_target}`,
    `terminal_chain_nested_artifact_tamper_refusals_preserved=${verification.evidence_dir_contract_verification.terminal_chain_nested_artifact_tamper_refusals_preserved}`,
    `terminal_chain_nested_artifact_binding_required_for_target=${verification.evidence_dir_contract_verification.terminal_chain_nested_artifact_binding_required_for_target}`,
    `terminal_chain_nested_artifact_binding_preserved=${verification.evidence_dir_contract_verification.terminal_chain_nested_artifact_binding_preserved}`,
    `terminal_chain_trusted_registry_recognition_refusals_required_for_target=${verification.evidence_dir_contract_verification.terminal_chain_trusted_registry_recognition_refusals_required_for_target}`,
    `terminal_chain_trusted_registry_recognition_refusals_preserved=${verification.evidence_dir_contract_verification.terminal_chain_trusted_registry_recognition_refusals_preserved}`,
    `terminal_chain_deployment_profile_authority_refusal_mirror_required_for_target=${verification.evidence_dir_contract_verification.terminal_chain_deployment_profile_authority_refusal_mirror_required_for_target}`,
    `terminal_chain_deployment_profile_authority_refusal_mirror_preserved=${verification.evidence_dir_contract_verification.terminal_chain_deployment_profile_authority_refusal_mirror_preserved}`,
    `deployment_profile_authority_bridge_required_for_target=${verification.evidence_dir_contract_verification.deployment_profile_authority_bridge_required_for_target}`,
    `deployment_profile_authority_bridge_preserved=${verification.evidence_dir_contract_verification.product_proof_path_deployment_profile_authority_bridge_preserved}`,
    `north_star_deployment_profile_authority_bridge_preserved=${verification.evidence_dir_contract_verification.north_star_deployment_profile_authority_bridge_preserved}`,
    `deployment_profile_authority_refusals_required_for_target=${verification.evidence_dir_contract_verification.deployment_profile_authority_refusals_required_for_target}`,
    `deployment_profile_authority_refusals_preserved=${verification.evidence_dir_contract_verification.product_proof_path_deployment_profile_authority_refusals_preserved}`,
    `north_star_deployment_profile_authority_refusals_preserved=${verification.evidence_dir_contract_verification.north_star_deployment_profile_authority_refusals_preserved}`,
    `deployment_profile_authority_refusal_case_count=${verification.evidence_dir_contract_verification.deployment_profile_authority_refusal_case_count}`,
    `deployment_profile_authority_refusal_case_ids_preserved=${verification.evidence_dir_contract_verification.deployment_profile_authority_refusal_case_ids_preserved}`,
    `deployment_profile_authority_refusals_before_service_proof=${verification.evidence_dir_contract_verification.deployment_profile_authority_refusals_before_service_proof}`,
    `stale_deployment_profile_artifact_refused_before_service_proof=${verification.evidence_dir_contract_verification.stale_deployment_profile_artifact_refused_before_service_proof}`,
    `profile_recognition_mismatch_refused_before_service_proof=${verification.evidence_dir_contract_verification.profile_recognition_mismatch_refused_before_service_proof}`,
    `latest_profile_selection_refused_before_service_proof=${verification.evidence_dir_contract_verification.latest_profile_selection_refused_before_service_proof}`,
    `request_stream_authority_material_refused_before_service_proof=${verification.evidence_dir_contract_verification.request_stream_authority_material_refused_before_service_proof}`,
    `terminal_chain_trusted_registry_verdict_required_for_target=${verification.evidence_dir_contract_verification.terminal_chain_trusted_registry_verdict_required_for_target}`,
    `product_proof_path_terminal_chain_trusted_registry_verdict_preserved=${verification.evidence_dir_contract_verification.product_proof_path_terminal_chain_trusted_registry_verdict_preserved}`,
    `north_star_terminal_chain_trusted_registry_verdict_preserved=${verification.evidence_dir_contract_verification.north_star_terminal_chain_trusted_registry_verdict_preserved}`,
    `terminal_chain_trusted_registry_recognition_verdict=${verification.evidence_dir_contract_verification.terminal_chain_trusted_registry_recognition_verdict}`,
    `terminal_chain_trusted_registry_signature_valid=${verification.evidence_dir_contract_verification.terminal_chain_trusted_registry_signature_valid}`,
    `downstream_refusal_boundary_required_for_target=${verification.evidence_dir_contract_verification.downstream_refusal_boundary_required_for_target}`,
    `product_proof_path_downstream_refusal_boundary_preserved=${verification.evidence_dir_contract_verification.product_proof_path_downstream_refusal_boundary_preserved}`,
    `north_star_downstream_refusal_boundary_preserved=${verification.evidence_dir_contract_verification.north_star_downstream_refusal_boundary_preserved}`,
    `downstream_refusal_recognized_marker_count_delta=${verification.evidence_dir_contract_verification.downstream_refusal_recognized_marker_count_delta}`,
    `downstream_refusal_final_marker_count=${verification.evidence_dir_contract_verification.downstream_refusal_final_marker_count}`,
    `downstream_refusal_case_count=${verification.evidence_dir_contract_verification.downstream_refusal_case_count}`,
    `downstream_refusal_all_refusals_unboarded=${verification.evidence_dir_contract_verification.downstream_refusal_all_refusals_unboarded}`,
    `downstream_refusal_reasons=${verification.evidence_dir_contract_verification.downstream_refusal_reasons}`,
    `north_star_downstream_refusal_all_refusals_unboarded=${verification.evidence_dir_contract_verification.north_star_downstream_refusal_all_refusals_unboarded}`,
    `north_star_downstream_refusal_reasons=${verification.evidence_dir_contract_verification.north_star_downstream_refusal_reasons}`,
    `downstream_refusal_marker_count_deltas_zero=${verification.evidence_dir_contract_verification.downstream_refusal_marker_count_deltas_zero}`,
    `terminal_chain_recognized_receipt_path_mirror_required_for_target=${verification.evidence_dir_contract_verification.terminal_chain_recognized_receipt_path_mirror_required_for_target}`,
    `product_proof_path_terminal_chain_recognized_receipt_path_mirror_preserved=${verification.evidence_dir_contract_verification.product_proof_path_terminal_chain_recognized_receipt_path_mirror_preserved}`,
    `north_star_terminal_chain_recognized_receipt_path_mirror_preserved=${verification.evidence_dir_contract_verification.north_star_terminal_chain_recognized_receipt_path_mirror_preserved}`,
    `terminal_chain_recognized_receipt_path_evidence_sha256=${verification.evidence_dir_contract_verification.terminal_chain_recognized_receipt_path_evidence_sha256}`,
    `terminal_chain_recognized_receipt_path_source_binding_matches_trusted_registry_binding=${verification.evidence_dir_contract_verification.terminal_chain_recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding}`,
    `private_by_default=${verification.private_by_default}`,
    `public_external_attestation=${verification.public_external_attestation}`,
    `public_attribution=${verification.public_attribution}`,
    `non_operator_review_publicly_claimed=${verification.non_operator_review_publicly_claimed}`,
    `production_authority=${verification.production_authority}`,
    `enterprise_readiness=${verification.enterprise_readiness}`,
    `current_machine_governance=${verification.current_machine_governance}`,
    `live_mcp_coverage=${verification.live_mcp_coverage}`,
    `v3_4_0_readiness=${verification.v3_4_0_readiness}`,
    '',
    'Non-claims:',
    ...verification.non_claims.map((claim) => `- ${claim}`),
    '',
  ];
  const output = lines.join('\n');
  assertNoUnsafePrivateVerifierResultText(output);
  return output;
}
