import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from './canonicalize.mjs';
import { bindRequiredBodySha256 } from './artifact-required-sha.mjs';
import {
  createReceiptV1FromEvent,
  decodePayloadV1,
  sha256hex,
  signReceiptV1,
} from './receipt.mjs';
import {
  PROTECTED_RECORDS_CONSEQUENCE_PATH,
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  PROTECTED_RECORDS_TARGET_HANDLE,
  PROTECTED_RECORDS_TARGET_KIND,
  PROTECTED_RECORDS_TARGET_SCOPE,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from './protected-records-runtime-profile.mjs';
import {
  assertProtectedRecordsRuntimePreflightProfile,
  runtimeProfileSha256,
} from './protected-records-runtime-profile-preflight.mjs';
import {
  assertProtectedRecordsRuntimeProfileInstallationPlan,
  runtimeProfileInstallationPlanSha256,
} from './protected-records-runtime-profile-installation.mjs';
import {
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_ACTIVE_INDEX_TYPE,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
  buildProtectedRecordsInstalledRuntimeProfilePreflightArtifact,
  runProtectedRecordsInstalledRuntimeProfilePreflight,
  verifyProtectedRecordsInstalledRuntimeProfilePreflightArtifact,
} from './protected-records-installed-runtime-profile-preflight.mjs';
import {
  EXPECTED_REFUSAL_REASONS,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_SAMPLE_ARTIFACT_BODY_SHA256,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES,
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact,
  protectedRecordsInstalledRuntimeProfileServiceProofArtifactBodySha256,
  verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact,
} from './protected-records-installed-runtime-profile-service-proof.mjs';
import {
  PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_PROOF_TYPE,
  REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES,
} from './protected-records-one-terminal-deployment-profile.mjs';
import {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed,
  protectedRecordsFixtureAuthorityGrantEffectStatusReason,
  protectedRecordsFixtureAuthorityGrantStatus,
} from './protected-records-fixture-authority-status.mjs';
import {
  TRUSTED_RECEIPT_ISSUER_REGISTRY_V2_CONTRACT_EVIDENCE,
  assertTrustedReceiptIssuerRegistryV2Contract,
  evaluateTrustedReceiptIssuerRegistryV2Recognition,
  publicSafeTrustedReceiptIssuerRegistryV2Summary,
} from './trusted-receipt-issuer-registry.mjs';

export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TYPE =
  'zlar-protected-records-installed-runtime-profile-terminal-chain-v1';

export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_TYPE =
  'zlar-protected-records-installed-runtime-profile-terminal-chain-artifact-v1';

export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_CANONICALIZATION =
  'zlar-canonical-json-v1';

export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_VERIFICATION_TYPE =
  'zlar-protected-records-installed-runtime-profile-terminal-chain-artifact-verification-v1';

export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256 =
  '0f8db51f11885e7867c6f0fa4d737adf51774e7cd9ad711cd2073b5b684c303f';

const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_COMMITTED_SERVICE_PROOF_ARTIFACT_PATH =
  fileURLToPath(new URL(
    '../tests/fixtures/protected-records-installed-runtime-profile-service-proof-artifact-v1.json',
    import.meta.url,
  ));

function readCommittedProtectedRecordsInstalledRuntimeProfileServiceProofArtifact() {
  const artifact = JSON.parse(readFileSync(
    PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_COMMITTED_SERVICE_PROOF_ARTIFACT_PATH,
    'utf8',
  ));
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(artifact);
  if (
    artifact.integrity.body_sha256 !==
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_SAMPLE_ARTIFACT_BODY_SHA256
  ) {
    throw new Error(
      'Protected records installed runtime profile terminal chain committed service-proof artifact identity drifted',
    );
  }
  return artifact;
}

export const INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAFE_CLAIM_CEILING =
  'ZLAR can create a launcher-owned disposable installed protected-records runtime-profile root from an explicit plan and profile, preflight that generated root by exact profile id and SHA, structurally verify and exact-SHA pin the generated local service-proof artifact, and preserve its full public local-fixture authority-grant contract, public-safe summary and powers, accepted crossing links, ordered single-lock transition binding, one boarded records.write effect, separate 18-case recognition-refusal and five-case authority-refusal taxonomies, replay-identity split, named grant-burn windows, and joint store-anchor-witness rollback side door through a structurally self-verifying terminal-chain artifact.';

export const INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NON_CLAIMS = Object.freeze([
  'This chain creates only a launcher-owned disposable installed runtime-profile proof root and removes it after the run; it is not a persistent install or activation.',
  'This chain uses an explicit plan and profile; it does not select --latest, a live profile, or a current-machine default profile.',
  'This chain writes only disposable proof-harness files, disposable runtime config, consumed-authority-grant store, local anchor, and local witness material inside the proof harness.',
  'This chain starts a local disposable child service process; it does not start a live runtime service, inspect a live records system, or deploy a production records service.',
  'This chain does not write hook configuration, user configuration, machine configuration, production configuration, production receipts, production audit logs, or production stores.',
  'This chain does not use Telegram or prove live human approval-channel delivery.',
  'This chain evaluates a bundled local trusted-issuer registry fixture during terminal-chain generation and preserves only a public-safe hash-bound synthetic registry-evidence receipt summary plus artifact-owned receipt-path evidence inside the artifact; that registry receipt is not the boarded service receipt and does not authorize the service write; the artifact does not embed raw public-key material or either receipt envelope, and it does not prove live trust-registry state, live issuer status, key custody, revocation truth, production trust-registry state, production downstream recognition, production authority, public external attestation, real non-operator review, sovereign recognition, current-machine governance, or coverage of unrouted paths.',
  'This chain does not prove current-machine governance, live MCP coverage, production downstream recognition, external attestation, enterprise readiness, production authority, sovereign recognition, or coverage of unrouted surfaces.',
  'This chain does not prove exactly-once effects or an all-or-nothing store, anchor, and witness commit; a state-append or metadata failure after grant-store commit can burn the one-use grant without a state mutation.',
  'This chain does not prove production-grade durable storage, stale-lock recovery, multi-host coordination, tamper resistance, or rollback detection if the consumed-authority-grant store, local anchor, and local witness move together.',
  'This chain does not close host process, memory, debugger, operator filesystem, hook-configuration, user-configuration, machine-configuration, or unrouted records side doors.',
  'This chain carries local fixture rightful-issuance-path evidence for one hermetic crossing only; it does not prove generic, portable, production, live, or current-machine rightful issuance, profile-wide target authority, a live target, or consequence-lifecycle closure.',
  'The synthetic trusted-registry receipt is recognition evidence only: it is not the boarded service receipt, does not authorize the service write, and has a distinct detail hash and receipt role.',
  'The embedded service artifact is pinned to its exact generated SHA-256 inside this chain; the terminal-chain artifact itself proves structural self-integrity only until a caller supplies its exact expected SHA-256 or a stronger external anchor.',
]);

const TERMINAL_CHAIN_STRUCTURAL_VERIFICATION_SCOPE = 'structural-self-integrity-only';
const TERMINAL_CHAIN_PINNED_VERIFICATION_SCOPE =
  'expected-terminal-artifact-identity-bound-local-fixture-projection';
const TERMINAL_CHAIN_STRUCTURAL_CLAIM_BOUNDARY =
  'structural self-integrity only; an embedded exact-SHA-pinned service proof does not establish the identity of the enclosing terminal-chain artifact or permit outer fixture-rightful metadata';
const TERMINAL_CHAIN_PINNED_CLAIM_BOUNDARY =
  'caller-supplied expected terminal-chain artifact SHA-256 matched; historical boarding, refusal, and local-fixture metadata may be projected from the exact outer artifact and its internally exact-SHA-pinned service proof, while fixture-rightful projection additionally requires a current source-authorized grant status with valid repeated-use provenance; no generic, portable, live, production, current-machine, or lifecycle-closure claim';

const TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_CLAIM_BOUNDARY =
  'terminal-chain trusted issuer registry recognition over bundled local fixture evidence only, preserving a public-safe hash-bound synthetic registry-evidence receipt summary plus artifact-owned receipt-path evidence bound to the selected profile, generated preflight artifact, generated service proof artifact, terminal-chain recognition contract, and boarded-service target-binding SHA; the synthetic registry-evidence receipt is not the boarded service receipt, does not authorize the service write, and has a distinct detail hash and receipt role; boarded target handle and effect hashes are post-effect metadata only; no raw public-key material or receipt envelope is embedded; no live registry, live issuer status, key custody, revocation truth, production trust registry, production downstream recognition, production authority, sovereign recognition, public external attestation, real non-operator review, current-machine governance, profile-wide target authority, rightful issuance, live-target proof, consequence-lifecycle closure, or unrouted-surface claim';

const TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_NON_CLAIMS = Object.freeze([
  'This terminal-chain binding recognizes only a bundled local trusted-issuer registry fixture and preserves a public-safe hash-bound synthetic registry-evidence receipt summary plus artifact-owned receipt-path evidence for that fixture recognition.',
  'The synthetic registry-evidence receipt is not the boarded service receipt, does not authorize the service write, and has a distinct detail hash and receipt role.',
  'The boarded target handle and effect hashes appear only as post-effect hash-bound metadata; they do not prove profile-wide target authority, rightful issuance, a live target, or consequence-lifecycle closure.',
  'This terminal-chain binding omits raw public-key material and the receipt envelope from the artifact.',
  'This terminal-chain binding does not inspect a live trust registry, live issuer status, live hooks, live audit stores, runtime state, or production downstream systems.',
  'This terminal-chain binding does not prove key custody, revocation truth, production trust-registry state, production downstream recognition, production authority, public external attestation, real non-operator review, sovereign recognition, current-machine governance, enterprise readiness, or coverage of unrouted paths.',
]);

const TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_MIRROR_SOURCE =
  'committed-one-terminal-deployment-profile-fixture';

const TERMINAL_CHAIN_BOARDED_SERVICE_RECEIPT_ROLE =
  'boarded-service-write-authority-receipt';
const TERMINAL_CHAIN_REGISTRY_RECEIPT_ROLE =
  'synthetic-registry-recognition-evidence-receipt';
const TERMINAL_CHAIN_BOARDED_TARGET_METADATA_ROLE =
  'post-effect-hash-bound-metadata-only';

export const REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_FIXTURE_AUTHORITY_POWER_IDS =
  Object.freeze([
    'bind_runtime_issuer_to_slot',
    'issue_governed_action_receipt',
    'issue_replacement_authority_grant',
    'revoke_authority_grant',
  ]);

const TERMINAL_CHAIN_EXPECTED_AUTHORITY_REFUSAL_REASONS = Object.freeze({
  missing_authority_grant_appointment_refused_before_consumption:
    'authority_grant_missing',
  mismatched_authority_grant_appointment_refused_before_consumption:
    'authority_grant_contract_mismatch',
  expired_authority_grant_refused_before_consumption: 'authority_grant_expired',
  revoked_authority_grant_refused_before_consumption: 'authority_grant_revoked',
  request_supplied_authority_grant_refused_before_consumption:
    'agent_supplied_authority_material',
});

export const TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_FALSE_BOUNDARY_FIELDS = Object.freeze([
  'live_probing',
  'registry_public_key_material_included',
  'receipt_envelope_included',
  'cryptographic_evidence_reproducible_from_artifact',
  'live_trust_registry_state',
  'live_issuer_status_proven',
  'key_custody_proven',
  'revocation_truth_proven',
  'production_trust_registry_proven',
  'production_downstream_recognition_proven',
  'production_authority',
  'sovereign_recognition',
  'public_external_attestation',
  'real_non_operator_review',
  'current_machine_governance_proven',
  'profile_wide_target_authority_proven',
  'rightful_issuance_proven',
  'live_target_proven',
  'consequence_lifecycle_closed',
]);

export const REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS = Object.freeze([
  Object.freeze({
    case_id: 'unrecognized_terminal_chain_registry_scope_refused',
    reason_code: 'scope_not_found',
    requested_scope: 'unrecognized-fixture-records-terminal',
    registry_scope: 'fixture-records-terminal',
    signature_valid: null,
    issuer_status: null,
  }),
  Object.freeze({
    case_id: 'registry_receipt_contract_mismatch_refused',
    reason_code: 'detail_hash_mismatch',
    requested_scope: 'fixture-records-terminal',
    registry_scope: 'fixture-records-terminal',
    signature_valid: true,
    issuer_status: 'active',
  }),
]);

const TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_FIXTURE_NON_CLAIMS = Object.freeze([
  'This fixture does not inspect a live or production trust registry.',
  'This fixture does not prove key custody, hardware possession, revocation truth, compromise response, or production signing identity.',
  'This fixture does not prove routed coverage, live downstream deployment recognition, production authority, external attestation, sovereign recognition, or coverage of unrouted surfaces.',
]);

const TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_SCHEMA_KEYS = Object.freeze([
  'accepted_domains',
  'accepted_outcomes',
  'accepted_policy_versions',
  'accepted_tools',
  'claim_boundary',
  'deployment_scope',
  'effective_at',
  'evidence_model',
  'expires_at',
  'freshness_requirements',
  'live_probing',
  'non_claims',
  'registry_id',
  'registry_type',
  'replay_protection',
  'required_audit_event_id',
  'required_detail_hash',
  'trusted_issuers',
  'version',
]);

export const REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_OPEN_BOUNDARIES = Object.freeze([
  'disposable_install_only',
  'persistent_runtime_profile_installation',
  'runtime_profile_activation',
  'hook_configuration',
  'user_or_machine_configuration',
  'live_runtime_profile',
  'live_records_system',
  'production_records_service',
  'current_machine_governance',
  'live_mcp_coverage',
  'live_approval_channel_health',
  'exactly_once_effect_semantics',
  'store_anchor_witness_commit_atomicity',
  'store_anchor_and_witness_joint_rollback_or_deletion',
  'host_filesystem_path_toctou',
  'host_process_or_memory_introspection',
  'external_attestation',
  'sovereign_recognition',
  'unrouted_records_paths',
  'profile_wide_target_authority',
  'generic_rightful_issuance',
  'portable_rightful_issuance',
  'production_rightful_issuance',
  'live_target',
  'consequence_lifecycle_closure',
]);

export const REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS = Object.freeze({
  missing: Object.freeze({
    case_id: 'missing_receipt_refused_before_runtime_mutation',
    reason_code: 'receipt_missing',
  }),
  invalid: Object.freeze({
    case_id: 'invalid_receipt_refused_before_runtime_mutation',
    reason_code: 'receipt_invalid',
  }),
  stale: Object.freeze({
    case_id: 'stale_receipt_refused_before_runtime_mutation',
    reason_code: 'receipt_stale',
  }),
  stale_or_expired: Object.freeze({
    case_id: 'stale_receipt_refused_before_runtime_mutation',
    reason_code: 'receipt_stale',
  }),
  unknown_issuer: Object.freeze({
    case_id: 'unknown_issuer_refused_before_runtime_mutation',
    reason_code: 'unknown_issuer',
  }),
  wrong_policy: Object.freeze({
    case_id: 'wrong_policy_refused_before_runtime_mutation',
    reason_code: 'policy_not_recognized',
  }),
  wrong_domain: Object.freeze({
    case_id: 'wrong_domain_refused_before_runtime_mutation',
    reason_code: 'domain_out_of_scope',
  }),
  wrong_tool: Object.freeze({
    case_id: 'wrong_tool_refused_before_runtime_mutation',
    reason_code: 'tool_out_of_scope',
  }),
});

export const REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS = Object.freeze({
  no_usable_recognized_receipt_authority: Object.freeze([
    Object.freeze({
      case_id: 'missing_receipt_refused_before_runtime_mutation',
      reason_code: 'receipt_missing',
    }),
    Object.freeze({
      case_id: 'invalid_receipt_refused_before_runtime_mutation',
      reason_code: 'receipt_invalid',
    }),
    Object.freeze({
      case_id: 'unknown_issuer_refused_before_runtime_mutation',
      reason_code: 'unknown_issuer',
    }),
    Object.freeze({
      case_id: 'retired_issuer_refused_before_runtime_mutation',
      reason_code: 'issuer_not_active',
    }),
    Object.freeze({
      case_id: 'missing_issuer_status_refused_before_runtime_mutation',
      reason_code: 'issuer_status_missing',
    }),
    Object.freeze({
      case_id: 'stale_receipt_refused_before_runtime_mutation',
      reason_code: 'receipt_stale',
    }),
  ]),
  recognized_receipt_scope_mismatch: Object.freeze([
    Object.freeze({
      case_id: 'wrong_policy_refused_before_runtime_mutation',
      reason_code: 'policy_not_recognized',
    }),
    Object.freeze({
      case_id: 'wrong_domain_refused_before_runtime_mutation',
      reason_code: 'domain_out_of_scope',
    }),
    Object.freeze({
      case_id: 'wrong_tool_refused_before_runtime_mutation',
      reason_code: 'tool_out_of_scope',
    }),
    Object.freeze({
      case_id: 'wrong_audit_event_refused_before_runtime_mutation',
      reason_code: 'audit_event_mismatch',
    }),
    Object.freeze({
      case_id: 'wrong_detail_refused_before_runtime_mutation',
      reason_code: 'detail_hash_mismatch',
    }),
    Object.freeze({
      case_id: 'non_boarding_outcome_refused_before_runtime_mutation',
      reason_code: 'outcome_not_boarding',
    }),
  ]),
  route_or_request_authority_material_refused: Object.freeze([
    Object.freeze({
      case_id: 'wrong_runtime_profile_id_refused_before_runtime_mutation',
      reason_code: 'agent_supplied_authority_material',
    }),
    Object.freeze({
      case_id: 'direct_api_without_receipt_refused_before_runtime_mutation',
      reason_code: 'receipt_missing',
    }),
    Object.freeze({
      case_id: 'direct_api_with_receipt_refused_before_runtime_mutation',
      reason_code: 'direct_api_receipt_present',
    }),
    Object.freeze({
      case_id: 'agent_supplied_recognition_rule_refused_before_runtime_mutation',
      reason_code: 'agent_supplied_authority_material',
    }),
    Object.freeze({
      case_id: 'agent_supplied_fixture_mode_refused_before_runtime_mutation',
      reason_code: 'agent_supplied_authority_material',
    }),
    Object.freeze({
      case_id: 'unsupported_request_field_refused_before_runtime_mutation',
      reason_code: 'agent_supplied_authority_material',
    }),
  ]),
});

function requireObject(label, value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function matchExpectedArtifactSha256(label, expectedSha256, actualSha256) {
  if (expectedSha256 === null || expectedSha256 === undefined || expectedSha256 === '') {
    return { expected: null, supplied: false, matched: false };
  }
  if (!/^[a-f0-9]{64}$/.test(expectedSha256)) {
    throw new Error(`${label} expected identity must be SHA-256 hex`);
  }
  if (expectedSha256 !== actualSha256) {
    throw new Error(`${label} does not match the caller-supplied expected SHA-256 identity`);
  }
  return { expected: expectedSha256, supplied: true, matched: true };
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

function assertExactArray(label, value, expected) {
  if (!Array.isArray(value) || value.length !== expected.length) {
    throw new Error(`${label} drifted`);
  }
  for (let i = 0; i < expected.length; i++) {
    if (value[i] !== expected[i]) {
      throw new Error(`${label} drifted`);
    }
  }
  return true;
}

function publicSafeGrantSummarySha256(value) {
  return sha256hex(canonicalize({ public_safe_grant_summary: value }));
}

function publicGrantContractSha256(value) {
  return sha256hex(canonicalize(value));
}

function acceptedCrossingEvidenceSha256(value) {
  return sha256hex(canonicalize({ accepted_crossing_evidence: value }));
}

function assertTerminalChainPublicSafeGrantSummary(label, value) {
  assertExactKeys(label, value, [
    'authority_domain_id',
    'authority_grant_consumed_before_state_mutation',
    'authority_grant_contract_sha256',
    'authority_grant_id',
    'authorization_record_id',
    'consequence_lifecycle_closed',
    'consequence_path',
    'current_machine_governance_proven',
    'effect_gate_evaluated_before_authority_grant_consumption',
    'exact_runtime_kid_match_proven',
    'exact_runtime_public_key_match_proven',
    'expires_at_epoch',
    'fixture_authority_grant_satisfied_at_evaluation_time',
    'fixture_clock_model',
    'fixture_rightful_issuance_path_evidenced',
    'grantee_actor_id',
    'grantor_actor_id',
    'grantor_role_id',
    'issuance_gate_evaluated_before_signing',
    'issuer_slot',
    'live_authority_proven',
    'live_revocation_proven',
    'one_use_effect_grant',
    'portable_human_authorization_attestation',
    'portable_rightful_issuance_proven',
    'power_ids',
    'production_rightful_issuance_proven',
    'receipt_bound_to_authority_grant',
    'replacement_requires_different_contract_sha256',
    'revocation_checked_at_fixture_evaluation_time',
    'rightful_issuance_proven',
    'rightful_issuance_scope',
    'runtime_private_grant_appointment_disclosed',
    'runtime_private_issuer_identity_disclosed',
    'summary_type',
    'target_handle',
    'valid_from_epoch',
    'verified_signed_payload_identity_present',
  ]);
  assertExactArray(
    `${label} power ids`,
    value.power_ids,
    REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_FIXTURE_AUTHORITY_POWER_IDS
  );
  if (
    value.summary_type !==
      'zlar-protected-records-fixture-authority-grant-summary-v1' ||
    value.authority_domain_id !== 'protected-records.local-disposable-fixture' ||
    value.grantor_role_id !== 'fixture-consequence-authority' ||
    value.consequence_path !== PROTECTED_RECORDS_CONSEQUENCE_PATH ||
    value.target_handle !== PROTECTED_RECORDS_TARGET_HANDLE ||
    !/^[a-f0-9]{64}$/.test(value.authority_grant_contract_sha256 || '') ||
    value.authority_grant_id !==
      `zlar-grant:v1:${value.authority_grant_contract_sha256}` ||
    value.fixture_clock_model !== 'fixed-hermetic-fixture-epoch' ||
    !Number.isInteger(value.valid_from_epoch) ||
    !Number.isInteger(value.expires_at_epoch) ||
    value.valid_from_epoch >= value.expires_at_epoch ||
    value.one_use_effect_grant !== true ||
    value.replacement_requires_different_contract_sha256 !== true ||
    value.revocation_checked_at_fixture_evaluation_time !== true ||
    value.issuance_gate_evaluated_before_signing !== true ||
    value.effect_gate_evaluated_before_authority_grant_consumption !== true ||
    value.authority_grant_consumed_before_state_mutation !== true ||
    value.exact_runtime_kid_match_proven !== true ||
    value.exact_runtime_public_key_match_proven !== true ||
    value.receipt_bound_to_authority_grant !== true ||
    value.verified_signed_payload_identity_present !== true ||
    value.fixture_authority_grant_satisfied_at_evaluation_time !== true ||
    value.fixture_rightful_issuance_path_evidenced !== true ||
    value.rightful_issuance_scope !==
      'protected-records.local-disposable-fixture/one-hermetic-crossing' ||
    value.runtime_private_issuer_identity_disclosed !== false ||
    value.runtime_private_grant_appointment_disclosed !== false ||
    value.portable_human_authorization_attestation !== false ||
    value.rightful_issuance_proven !== false ||
    value.portable_rightful_issuance_proven !== false ||
    value.production_rightful_issuance_proven !== false ||
    value.live_authority_proven !== false ||
    value.live_revocation_proven !== false ||
    value.current_machine_governance_proven !== false ||
    value.consequence_lifecycle_closed !== false
  ) {
    throw new Error(`${label} drifted`);
  }
  return true;
}

function trustedIssuerRegistryFalseBoundaryPreserved(value) {
  return TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_FALSE_BOUNDARY_FIELDS
    .every((field) => value?.[field] === false);
}

const TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_SOURCE_PROOF_SHA256 =
  '78cd21bbd5180273bc9df78bf675943f756e2beab0609e2768481fc6fe5d4c33';
const TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_SOURCE_RUNTIME_PROFILE_SHA256 =
  'e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469';

function buildDeploymentProfileAuthorityRefusalMirror({ terminalRuntimeProfileSha256 }) {
  if (
    terminalRuntimeProfileSha256 !==
      TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_SOURCE_RUNTIME_PROFILE_SHA256
  ) {
    throw new Error(
      'Protected records installed runtime profile terminal chain committed deployment-profile refusal mirror runtime identity drifted',
    );
  }
  return {
    source: TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_MIRROR_SOURCE,
    source_proof_type:
      PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_PROOF_TYPE,
    source_proof_sha256:
      TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_SOURCE_PROOF_SHA256,
    evidence_model:
      'local-fixture-one-terminal-deployment-profile-authority-bridge',
    local_fixture_only: true,
    mirrored_from_one_terminal_deployment_profile: true,
    source_runtime_profile_sha256:
      TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_SOURCE_RUNTIME_PROFILE_SHA256,
    source_runtime_profile_sha_matches_terminal_chain: true,
    deployment_profile_authority_refusal_case_count:
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length,
    deployment_profile_authority_refusal_case_ids: [
      ...REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES,
    ],
    deployment_profile_authority_refusals_before_service_proof: true,
    deployment_profile_authority_refusals_before_mutation: true,
    deployment_profile_authority_refusal_service_proof_started: false,
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
  };
}

function assertDeploymentProfileAuthorityRefusalMirror(
  label,
  mirror,
  terminalRuntimeProfileSha256 = null
) {
  assertExactKeys(label, mirror, [
    'current_machine_governance',
    'deployment_profile_authority_refusal_case_count',
    'deployment_profile_authority_refusal_case_ids',
    'deployment_profile_authority_refusal_service_proof_started',
    'deployment_profile_authority_refusals_before_mutation',
    'deployment_profile_authority_refusals_before_service_proof',
    'enterprise_readiness',
    'evidence_model',
    'external_attestation',
    'latest_profile_selection_refused_before_service_proof',
    'local_fixture_only',
    'mirrored_from_one_terminal_deployment_profile',
    'production_authority',
    'production_downstream_recognition',
    'profile_recognition_mismatch_refused_before_service_proof',
    'request_stream_authority_material_refused_before_service_proof',
    'source',
    'source_proof_sha256',
    'source_proof_type',
    'source_runtime_profile_sha256',
    'source_runtime_profile_sha_matches_terminal_chain',
    'sovereign_recognition',
    'stale_deployment_profile_artifact_refused_before_service_proof',
    'unrouted_surface_coverage',
  ]);
  if (
    mirror.source !== TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_MIRROR_SOURCE ||
    mirror.source_proof_type !==
      PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_PROOF_TYPE ||
    mirror.source_proof_sha256 !==
      TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_SOURCE_PROOF_SHA256 ||
    mirror.source_runtime_profile_sha256 !==
      TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_SOURCE_RUNTIME_PROFILE_SHA256 ||
    (
      terminalRuntimeProfileSha256 !== null &&
      mirror.source_runtime_profile_sha256 !== terminalRuntimeProfileSha256
    ) ||
    mirror.evidence_model !== 'local-fixture-one-terminal-deployment-profile-authority-bridge' ||
    mirror.local_fixture_only !== true ||
    mirror.mirrored_from_one_terminal_deployment_profile !== true ||
    mirror.source_runtime_profile_sha_matches_terminal_chain !== true ||
    mirror.deployment_profile_authority_refusal_case_count !==
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length ||
    !assertExactArray(
      `${label} case ids`,
      mirror.deployment_profile_authority_refusal_case_ids,
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES
    ) ||
    mirror.deployment_profile_authority_refusals_before_service_proof !== true ||
    mirror.deployment_profile_authority_refusals_before_mutation !== true ||
    mirror.deployment_profile_authority_refusal_service_proof_started !== false ||
    mirror.stale_deployment_profile_artifact_refused_before_service_proof !== true ||
    mirror.profile_recognition_mismatch_refused_before_service_proof !== true ||
    mirror.latest_profile_selection_refused_before_service_proof !== true ||
    mirror.request_stream_authority_material_refused_before_service_proof !== true ||
    mirror.current_machine_governance !== false ||
    mirror.production_downstream_recognition !== false ||
    mirror.production_authority !== false ||
    mirror.enterprise_readiness !== false ||
    mirror.external_attestation !== false ||
    mirror.sovereign_recognition !== false ||
    mirror.unrouted_surface_coverage !== false
  ) {
    throw new Error(`${label} drifted`);
  }
  return true;
}

function trustedIssuerRegistryRecognitionRefusalCase({
  caseId,
  decision,
  requestedScope,
  registryScope,
}) {
  return {
    case_id: caseId,
    decision: decision?.decision || null,
    recognized: decision?.recognized === true,
    reason_code: decision?.reason_code || null,
    requested_scope: requestedScope,
    registry_scope: registryScope,
    signature_valid:
      typeof decision?.evidence?.signature_valid === 'boolean'
        ? decision.evidence.signature_valid
        : null,
    issuer_status: decision?.evidence?.issuer_status ?? null,
  };
}

function terminalChainTrustedIssuerRegistryRecognitionRefusalsSha256(value) {
  return sha256hex(canonicalize({
    trusted_issuer_registry_recognition_refusals: value,
  }));
}

function assertTerminalChainTrustedIssuerRegistryRecognitionRefusals(label, value) {
  requireObject(label, value);
  assertExactKeys(label, value, [
    'all_refused',
    'case_count',
    'cases',
  ]);
  if (
    value.case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS.length ||
    value.all_refused !== true ||
    !Array.isArray(value.cases) ||
    value.cases.length !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS.length
  ) {
    throw new Error(`${label} drifted`);
  }
  value.cases.forEach((observed, index) => {
    const expected =
      REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS[index];
    assertExactKeys(`${label} case`, observed, [
      'case_id',
      'decision',
      'issuer_status',
      'reason_code',
      'recognized',
      'registry_scope',
      'requested_scope',
      'signature_valid',
    ]);
    if (
      observed.case_id !== expected.case_id ||
      observed.decision !== 'refuse' ||
      observed.recognized !== false ||
      observed.reason_code !== expected.reason_code ||
      observed.requested_scope !== expected.requested_scope ||
      observed.registry_scope !== expected.registry_scope ||
      observed.signature_valid !== expected.signature_valid ||
      observed.issuer_status !== expected.issuer_status
    ) {
      throw new Error(`${label} case drifted: ${expected.case_id}`);
    }
  });
  return true;
}

function assertTerminalChainTrustedIssuerRegistryFixtureShape(registry) {
  assertTrustedReceiptIssuerRegistryV2Contract(registry);
  assertExactKeys(
    'Protected records installed runtime profile terminal chain trusted issuer registry fixture',
    registry,
    TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_SCHEMA_KEYS
  );
  if (
    registry.registry_type !== 'trusted-receipt-issuers-v2' ||
    registry.registry_id !== 'terminal-chain-local-no-secret-trusted-issuer-registry-fixture' ||
    registry.version !== 2 ||
    registry.evidence_model !== 'bundled-local-fixture-no-secret-registry-contract' ||
    registry.live_probing !== false ||
    registry.deployment_scope !== 'fixture-records-terminal' ||
    registry.freshness_requirements.max_age_seconds !== 120 ||
    registry.freshness_requirements.future_tolerance_seconds !== 0 ||
    registry.replay_protection.receipt_id_required !== true ||
    registry.replay_protection.replay_cache_required !== true ||
    registry.replay_protection.atomic_consume_required !== true
  ) {
    throw new Error('Protected records installed runtime profile terminal chain trusted issuer registry fixture drifted');
  }
  if (!Array.isArray(registry.trusted_issuers) || registry.trusted_issuers.length !== 1) {
    throw new Error('Protected records installed runtime profile terminal chain trusted issuer registry issuer count drifted');
  }
  for (const issuer of registry.trusted_issuers) {
    assertExactKeys(
      'Protected records installed runtime profile terminal chain trusted issuer registry issuer',
      issuer,
      [
        'custody_posture',
        'effective_at',
        'expires_at',
        'kid',
        'public_key_pem',
        'status',
        'status_reason',
        'status_transition',
        'trust_anchor_sha256',
      ]
    );
    if (
      typeof issuer.kid !== 'string' ||
      !/^[a-f0-9]{16}$/.test(issuer.kid) ||
      typeof issuer.public_key_pem !== 'string' ||
      !issuer.public_key_pem.startsWith('-----BEGIN PUBLIC KEY-----') ||
      issuer.trust_anchor_sha256 !== null ||
      issuer.status !== 'active' ||
      issuer.custody_posture.private_key_material_included !== false ||
      issuer.custody_posture.hardware_custody_proven !== false ||
      issuer.custody_posture.custody_proof_provided !== false
    ) {
      throw new Error('Protected records installed runtime profile terminal chain trusted issuer registry issuer drifted');
    }
  }
  for (const field of [
    'accepted_policy_versions',
    'accepted_domains',
    'accepted_tools',
    'accepted_outcomes',
    'non_claims',
  ]) {
    if (
      !Array.isArray(registry[field]) ||
      registry[field].length === 0 ||
      registry[field].some((item) => typeof item !== 'string' || item.length === 0)
    ) {
      throw new Error(`Protected records installed runtime profile terminal chain trusted issuer registry ${field} drifted`);
    }
  }
  if (
    typeof registry.required_audit_event_id !== 'string' ||
    registry.required_audit_event_id.length === 0 ||
    typeof registry.required_detail_hash !== 'string' ||
    !/^[a-f0-9]{64}$/.test(registry.required_detail_hash)
  ) {
    throw new Error('Protected records installed runtime profile terminal chain trusted issuer registry required binding drifted');
  }
  assertExactArray(
    'Protected records installed runtime profile terminal chain trusted issuer registry fixture non-claims',
    registry.non_claims,
    TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_FIXTURE_NON_CLAIMS
  );
  return true;
}

function evaluateTerminalChainTrustedIssuerRegistryRecognition({
  receipt,
  registry,
  scope,
  nowEpoch,
}) {
  assertTerminalChainTrustedIssuerRegistryFixtureShape(registry);
  return evaluateTrustedReceiptIssuerRegistryV2Recognition({
    receipt,
    registry,
    deployment_scope: scope,
    now_epoch: nowEpoch,
  });
}

function evaluateTerminalChainMalformedTrustedIssuerRegistryFixture() {
  let verdictEmitted = false;
  try {
    const registry = {
      registry_type: 'trusted-receipt-issuers-v2',
      registry_id: 'terminal-chain-local-no-secret-trusted-issuer-registry-fixture',
      version: 2,
      evidence_model: 'bundled-local-fixture-no-secret-registry-contract',
      live_probing: false,
      deployment_scope: 'fixture-records-terminal',
      effective_at: '2026-06-20T00:00:00.000Z',
      expires_at: '2026-06-20T01:00:00.000Z',
      trusted_issuers: [
        {
          kid: '0'.repeat(16),
          public_key_pem:
            '-----BEGIN PUBLIC KEY-----\nfixture-public-key-material-not-emitted\n-----END PUBLIC KEY-----\n',
          trust_anchor_sha256: null,
          status: 'active',
          status_reason: 'local fixture active issuer',
          effective_at: '2026-06-20T00:00:00.000Z',
          expires_at: '2026-06-20T01:00:00.000Z',
          status_transition: {
            transition_type: 'fixture_activation',
            transition_at: '2026-06-20T00:00:00.000Z',
            previous_status: null,
            reason: 'local fixture activation',
          },
          custody_posture: {
            declaration: 'ephemeral local fixture key; no custody proof',
            private_key_material_included: false,
            hardware_custody_proven: false,
            custody_proof_provided: false,
          },
        },
      ],
      accepted_policy_versions: ['terminal-chain-trusted-registry-fixture-v1'],
      accepted_domains: ['records'],
      accepted_tools: ['records.write'],
      accepted_outcomes: ['allow'],
      freshness_requirements: {
        max_age_seconds: 120,
        future_tolerance_seconds: 0,
      },
      replay_protection: {
        receipt_id_required: true,
        replay_cache_required: true,
        atomic_consume_required: true,
      },
      required_audit_event_id: 'zlar-terminal-chain-trusted-registry-event-001',
      required_detail_hash: '0'.repeat(64),
      claim_boundary: {
        current_machine_governance_proven: false,
        enterprise_readiness: false,
        hardware_custody_proven: false,
        key_custody_proven: false,
        live_issuer_status_proven: false,
        live_trust_registry_state: false,
        production_authority: false,
        production_downstream_recognition_proven: false,
        production_trust_registry_proven: false,
        public_external_attestation: false,
        revocation_truth_proven: false,
        sovereign_recognition: false,
      },
      non_claims: [...TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_FIXTURE_NON_CLAIMS],
      production_authority: true,
    };
    assertTerminalChainTrustedIssuerRegistryFixtureShape(registry);
    verdictEmitted = true;
  } catch (err) {
    const unsupportedField =
      String(err?.message || err).includes('unexpected fields');
    return {
      unsupported_field: unsupportedField,
      error_code: unsupportedField
        ? 'unsupported_registry_field'
        : 'malformed_registry_field',
      verdict_emitted: verdictEmitted,
      fail_closed_before_verdict: verdictEmitted === false,
    };
  }
  return {
    unsupported_field: false,
    error_code: 'not-refused',
    verdict_emitted: verdictEmitted,
    fail_closed_before_verdict: false,
  };
}

function terminalChainTrustedIssuerRegistryRecognitionBindingSha256(value) {
  const hashInput = {
    component: value.component,
    registry_fixture_contract_sha256: value.registry_fixture_contract_sha256,
    registry_accepted_policy_versions: value.registry_accepted_policy_versions,
    registry_accepted_domains: value.registry_accepted_domains,
    registry_accepted_tools: value.registry_accepted_tools,
    registry_accepted_outcomes: value.registry_accepted_outcomes,
    registry_required_audit_event_id:
      value.registry_required_audit_event_id,
    registry_required_detail_hash: value.registry_required_detail_hash,
    registry_trusted_issuer_statuses: value.registry_trusted_issuer_statuses,
    registry_public_key_material_included:
      value.registry_public_key_material_included,
    receipt_payload_contract_sha256: value.receipt_payload_contract_sha256,
    receipt_audit_event_id: value.receipt_audit_event_id,
    receipt_detail_hash: value.receipt_detail_hash,
    boarded_service_receipt_detail_hash:
      value.boarded_service_receipt_detail_hash,
    boarded_service_receipt_role: value.boarded_service_receipt_role,
    registry_receipt_role: value.registry_receipt_role,
    registry_receipt_is_boarded_service_receipt:
      value.registry_receipt_is_boarded_service_receipt,
    registry_receipt_authorized_service_write:
      value.registry_receipt_authorized_service_write,
    receipt_detail_hash_roles_distinct:
      value.receipt_detail_hash_roles_distinct,
    registry_receipt_metadata_boarded_service_target_binding_sha256:
      value.registry_receipt_metadata_boarded_service_target_binding_sha256,
    registry_receipt_metadata_hash_bound:
      value.registry_receipt_metadata_hash_bound,
    receipt_envelope_included: value.receipt_envelope_included,
    cryptographic_evidence_reproducible_from_artifact:
      value.cryptographic_evidence_reproducible_from_artifact,
    registry_receipt_contract_hash_bound:
      value.registry_receipt_contract_hash_bound,
    selected_profile_sha256: value.selected_profile_sha256,
    selected_profile_recognition_contract_sha256:
      value.selected_profile_recognition_contract_sha256,
    service_recognition_contract_sha256:
      value.service_recognition_contract_sha256,
    generated_preflight_artifact_body_sha256:
      value.generated_preflight_artifact_body_sha256,
    generated_service_proof_artifact_body_sha256:
      value.generated_service_proof_artifact_body_sha256,
    service_artifact_verification_body_sha256:
      value.service_artifact_verification_body_sha256,
    recognized_write_boarded: value.recognized_write_boarded,
    registry_type: value.registry_type,
    registry_evidence_model: value.registry_evidence_model,
    registry_fixture_validated: value.registry_fixture_validated,
    registry_fixture_evaluated: value.registry_fixture_evaluated,
    registry_to_recognition_rule_evaluated:
      value.registry_to_recognition_rule_evaluated,
    registry_evaluation_result_type: value.registry_evaluation_result_type,
    registry_trusted_issuer_count: value.registry_trusted_issuer_count,
    verdict: value.verdict,
    decision: value.decision,
    reason_code: value.reason_code,
    required_audit_event_id_bound: value.required_audit_event_id_bound,
    required_detail_hash_bound: value.required_detail_hash_bound,
    malformed_registry_fail_closed_before_verdict:
      value.malformed_registry_fail_closed_before_verdict,
    trusted_issuer_registry_recognition_refusals:
      value.trusted_issuer_registry_recognition_refusals,
    trusted_issuer_registry_recognition_refusals_sha256:
      value.trusted_issuer_registry_recognition_refusals_sha256,
    live_trust_registry_state: value.live_trust_registry_state,
    live_issuer_status_proven: value.live_issuer_status_proven,
    key_custody_proven: value.key_custody_proven,
    revocation_truth_proven: value.revocation_truth_proven,
    production_trust_registry_proven: value.production_trust_registry_proven,
    production_downstream_recognition_proven:
      value.production_downstream_recognition_proven,
    production_authority: value.production_authority,
    sovereign_recognition: value.sovereign_recognition,
    public_external_attestation: value.public_external_attestation,
    real_non_operator_review: value.real_non_operator_review,
    current_machine_governance_proven: value.current_machine_governance_proven,
    profile_wide_target_authority_proven:
      value.profile_wide_target_authority_proven,
    rightful_issuance_proven: value.rightful_issuance_proven,
    live_target_proven: value.live_target_proven,
    consequence_lifecycle_closed: value.consequence_lifecycle_closed,
  };
  if (value.registry_contract_evidence !== undefined) {
    hashInput.registry_contract_evidence = value.registry_contract_evidence;
  }
  if (value.registry_public_safe_summary_sha256 !== undefined) {
    hashInput.registry_public_safe_summary_sha256 =
      value.registry_public_safe_summary_sha256;
  }
  return sha256hex(canonicalize(hashInput));
}

function terminalChainRecognizedReceiptPathEvidenceSha256(value) {
  return sha256hex(canonicalize({
    recognized_receipt_path_evidence: {
      component: value.component,
      evidence_model: value.evidence_model,
      evidence_scope: value.evidence_scope,
      source_binding_sha256: value.source_binding_sha256,
      registry_fixture_contract_sha256: value.registry_fixture_contract_sha256,
      receipt_payload_contract_sha256: value.receipt_payload_contract_sha256,
      receipt_audit_event_id: value.receipt_audit_event_id,
      receipt_detail_hash: value.receipt_detail_hash,
      boarded_service_target_binding_sha256:
        value.boarded_service_target_binding_sha256,
      boarded_service_launcher_target_binding_sha256:
        value.boarded_service_launcher_target_binding_sha256,
      boarded_service_target_handle: value.boarded_service_target_handle,
      boarded_service_target_effect_hash:
        value.boarded_service_target_effect_hash,
      boarded_service_receipt_detail_hash:
        value.boarded_service_receipt_detail_hash,
      boarded_service_state_effect_binding_sha256:
        value.boarded_service_state_effect_binding_sha256,
      boarded_service_target_metadata_role:
        value.boarded_service_target_metadata_role,
      boarded_service_receipt_role: value.boarded_service_receipt_role,
      registry_receipt_role: value.registry_receipt_role,
      registry_receipt_is_boarded_service_receipt:
        value.registry_receipt_is_boarded_service_receipt,
      registry_receipt_authorized_service_write:
        value.registry_receipt_authorized_service_write,
      receipt_detail_hash_roles_distinct:
        value.receipt_detail_hash_roles_distinct,
      profile_wide_target_authority_proven:
        value.profile_wide_target_authority_proven,
      rightful_issuance_proven: value.rightful_issuance_proven,
      live_target_proven: value.live_target_proven,
      consequence_lifecycle_closed: value.consequence_lifecycle_closed,
      selected_profile_sha256: value.selected_profile_sha256,
      recognition_contract_sha256: value.recognition_contract_sha256,
      generated_preflight_artifact_body_sha256:
        value.generated_preflight_artifact_body_sha256,
      generated_service_proof_artifact_body_sha256:
        value.generated_service_proof_artifact_body_sha256,
      service_artifact_verification_body_sha256:
        value.service_artifact_verification_body_sha256,
      verdict: value.verdict,
      recognized: value.recognized,
      decision: value.decision,
      reason_code: value.reason_code,
      issuer_status: value.issuer_status,
      signature_valid: value.signature_valid,
      registry_fixture_validated: value.registry_fixture_validated,
      registry_fixture_evaluated: value.registry_fixture_evaluated,
      registry_to_recognition_rule_evaluated:
        value.registry_to_recognition_rule_evaluated,
      registry_evaluation_result_type: value.registry_evaluation_result_type,
      registry_trusted_issuer_count: value.registry_trusted_issuer_count,
      registry_receipt_contract_hash_bound:
        value.registry_receipt_contract_hash_bound,
      required_audit_event_id_bound: value.required_audit_event_id_bound,
      required_detail_hash_bound: value.required_detail_hash_bound,
      selected_profile_hash_bound: value.selected_profile_hash_bound,
      recognition_contract_hash_bound: value.recognition_contract_hash_bound,
      service_artifact_hash_bound: value.service_artifact_hash_bound,
      terminal_chain_decision_bound: value.terminal_chain_decision_bound,
      recognized_write_boarded: value.recognized_write_boarded,
      registry_public_key_material_included:
        value.registry_public_key_material_included,
      receipt_envelope_included: value.receipt_envelope_included,
      cryptographic_evidence_reproducible_from_artifact:
        value.cryptographic_evidence_reproducible_from_artifact,
      live_trust_registry_state: value.live_trust_registry_state,
      live_issuer_status_proven: value.live_issuer_status_proven,
      key_custody_proven: value.key_custody_proven,
      revocation_truth_proven: value.revocation_truth_proven,
      production_downstream_recognition_proven:
        value.production_downstream_recognition_proven,
      public_external_attestation: value.public_external_attestation,
      sovereign_recognition: value.sovereign_recognition,
      current_machine_governance_proven: value.current_machine_governance_proven,
      claim_boundary: value.claim_boundary,
    },
  }));
}

function terminalChainRecognizedReceiptPathEvidence(
  binding,
  boardedServiceTargetBinding,
  boardedServiceTargetBindingSha
) {
  return {
    component: 'terminal_chain_recognized_receipt_path_evidence',
    evidence_model:
      'artifact-owned-public-safe-local-fixture-recognized-receipt-path-v1',
    evidence_scope:
      'protected-records.installed-runtime-profile.terminal-chain.records.write',
    source_binding_sha256: binding.binding_sha256,
    registry_fixture_contract_sha256: binding.registry_fixture_contract_sha256,
    receipt_payload_contract_sha256: binding.receipt_payload_contract_sha256,
    receipt_audit_event_id: binding.receipt_audit_event_id,
    receipt_detail_hash: binding.receipt_detail_hash,
    boarded_service_target_binding_sha256:
      boardedServiceTargetBindingSha,
    boarded_service_launcher_target_binding_sha256:
      boardedServiceTargetBinding.launcher_target_binding_sha256,
    boarded_service_target_handle: boardedServiceTargetBinding.target_handle,
    boarded_service_target_effect_hash:
      boardedServiceTargetBinding.target_effect_sha256,
    boarded_service_receipt_detail_hash:
      boardedServiceTargetBinding.boarded_service_receipt_detail_sha256,
    boarded_service_state_effect_binding_sha256:
      boardedServiceTargetBinding.state_effect_binding_sha256,
    boarded_service_target_metadata_role:
      TERMINAL_CHAIN_BOARDED_TARGET_METADATA_ROLE,
    boarded_service_receipt_role: binding.boarded_service_receipt_role,
    registry_receipt_role: binding.registry_receipt_role,
    registry_receipt_is_boarded_service_receipt:
      binding.registry_receipt_is_boarded_service_receipt,
    registry_receipt_authorized_service_write:
      binding.registry_receipt_authorized_service_write,
    receipt_detail_hash_roles_distinct:
      binding.receipt_detail_hash_roles_distinct,
    profile_wide_target_authority_proven: false,
    rightful_issuance_proven: false,
    live_target_proven: false,
    consequence_lifecycle_closed: false,
    selected_profile_sha256: binding.selected_profile_sha256,
    recognition_contract_sha256:
      binding.selected_profile_recognition_contract_sha256,
    generated_preflight_artifact_body_sha256:
      binding.generated_preflight_artifact_body_sha256,
    generated_service_proof_artifact_body_sha256:
      binding.generated_service_proof_artifact_body_sha256,
    service_artifact_verification_body_sha256:
      binding.service_artifact_verification_body_sha256,
    verdict: binding.verdict,
    recognized: binding.recognized,
    decision: binding.decision,
    reason_code: binding.reason_code,
    issuer_status: binding.issuer_status,
    signature_valid: binding.signature_valid,
    registry_fixture_validated: binding.registry_fixture_validated,
    registry_fixture_evaluated: binding.registry_fixture_evaluated,
    registry_to_recognition_rule_evaluated:
      binding.registry_to_recognition_rule_evaluated,
    registry_evaluation_result_type: binding.registry_evaluation_result_type,
    registry_trusted_issuer_count: binding.registry_trusted_issuer_count,
    registry_receipt_contract_hash_bound:
      binding.registry_receipt_contract_hash_bound,
    required_audit_event_id_bound: binding.required_audit_event_id_bound,
    required_detail_hash_bound: binding.required_detail_hash_bound,
    selected_profile_hash_bound: binding.selected_profile_hash_bound,
    recognition_contract_hash_bound: binding.recognition_contract_hash_bound,
    service_artifact_hash_bound: binding.service_artifact_hash_bound,
    terminal_chain_decision_bound: binding.terminal_chain_decision_bound,
    recognized_write_boarded: binding.recognized_write_boarded,
    registry_public_key_material_included:
      binding.registry_public_key_material_included,
    receipt_envelope_included: binding.receipt_envelope_included,
    cryptographic_evidence_reproducible_from_artifact:
      binding.cryptographic_evidence_reproducible_from_artifact,
    live_trust_registry_state: binding.live_trust_registry_state,
    live_issuer_status_proven: binding.live_issuer_status_proven,
    key_custody_proven: binding.key_custody_proven,
    revocation_truth_proven: binding.revocation_truth_proven,
    production_downstream_recognition_proven:
      binding.production_downstream_recognition_proven,
    public_external_attestation: binding.public_external_attestation,
    sovereign_recognition: binding.sovereign_recognition,
    current_machine_governance_proven: binding.current_machine_governance_proven,
    claim_boundary: TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_CLAIM_BOUNDARY,
  };
}

function terminalChainTrustedIssuerRegistryRecognitionBinding({
  preflightArtifact,
  preflightVerification,
  serviceProof,
  serviceSummary,
  serviceVerification,
  profileSha,
}) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  const kid = sha256hex(publicPem).slice(0, 16);
  const event = {
    id: 'zlar-terminal-chain-trusted-registry-event-001',
    ts: '2026-06-20T00:00:00.000Z',
    action: 'records.write',
    domain: 'records',
    detail: {
      action_class: 'records.write',
      terminal_chain_component:
        'terminal_chain_trusted_issuer_registry_recognition_binding',
      selected_profile_sha256: profileSha,
      generated_preflight_artifact_body_sha256:
        preflightArtifact.integrity.body_sha256,
      generated_service_proof_artifact_body_sha256:
        serviceSummary.artifact_body_sha256,
      recognition_contract_sha256: serviceSummary.recognition_contract_sha256,
      boarded_service_target_binding_sha256:
        serviceSummary.boarded_service_target_binding_sha256,
    },
    outcome: 'allow',
    rule: 'RTERMINAL_CHAIN_REGISTRY_RECOGNITION_FIXTURE',
    authorizer: 'policy',
    policy_version: 'terminal-chain-trusted-registry-fixture-v1',
    prev_hash: '0'.repeat(64),
  };
  const receipt = signReceiptV1(createReceiptV1FromEvent(event), privatePem, kid);
  const payload = decodePayloadV1(receipt);
  const registryEffectiveAt = '2026-06-20T00:00:00.000Z';
  const registryExpiresAt = '2026-06-20T01:00:00.000Z';
  const registryNowEpoch = Date.parse(event.ts) / 1000 + 10;
  const mismatchReceipt = signReceiptV1(
    createReceiptV1FromEvent({
      ...event,
      detail: {
        ...event.detail,
        terminal_chain_contract_probe:
          'registry_receipt_contract_mismatch_refusal',
      },
    }),
    privatePem,
    kid
  );
  const registry = {
    registry_type: 'trusted-receipt-issuers-v2',
    registry_id: 'terminal-chain-local-no-secret-trusted-issuer-registry-fixture',
    version: 2,
    evidence_model: 'bundled-local-fixture-no-secret-registry-contract',
    live_probing: false,
    deployment_scope: 'fixture-records-terminal',
    effective_at: registryEffectiveAt,
    expires_at: registryExpiresAt,
    trusted_issuers: [
      {
        kid,
        public_key_pem: publicPem,
        trust_anchor_sha256: null,
        status: 'active',
        status_reason:
          'local fixture issuer recognized for terminal-chain no-secret registry contract validation',
        effective_at: registryEffectiveAt,
        expires_at: registryExpiresAt,
        status_transition: {
          transition_type: 'fixture_activation',
          transition_at: registryEffectiveAt,
          previous_status: null,
          reason: 'local fixture activation for terminal-chain registry contract validation',
        },
        custody_posture: {
          declaration: 'ephemeral local fixture key; no custody proof',
          private_key_material_included: false,
          hardware_custody_proven: false,
          custody_proof_provided: false,
        },
      },
    ],
    accepted_policy_versions: ['terminal-chain-trusted-registry-fixture-v1'],
    accepted_domains: ['records'],
    accepted_tools: ['records.write'],
    accepted_outcomes: ['allow'],
    freshness_requirements: {
      max_age_seconds: 120,
      future_tolerance_seconds: 0,
    },
    replay_protection: {
      receipt_id_required: true,
      replay_cache_required: true,
      atomic_consume_required: true,
    },
    required_audit_event_id: event.id,
    required_detail_hash: payload.detail_hash,
    claim_boundary: {
      current_machine_governance_proven: false,
      enterprise_readiness: false,
      hardware_custody_proven: false,
      key_custody_proven: false,
      live_issuer_status_proven: false,
      live_trust_registry_state: false,
      production_authority: false,
      production_downstream_recognition_proven: false,
      production_trust_registry_proven: false,
      public_external_attestation: false,
      revocation_truth_proven: false,
      sovereign_recognition: false,
    },
    non_claims: [...TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_FIXTURE_NON_CLAIMS],
  };
  assertTerminalChainTrustedIssuerRegistryFixtureShape(registry);
  const decision = evaluateTerminalChainTrustedIssuerRegistryRecognition({
    receipt,
    registry,
    scope: 'fixture-records-terminal',
    nowEpoch: registryNowEpoch,
  });
  const registryContractSummary =
    publicSafeTrustedReceiptIssuerRegistryV2Summary(registry);
  const receiptPayloadContract = {
    audit_event_id: payload.audit_event_id,
    detail_hash: payload.detail_hash,
    domain: payload.domain,
    outcome: payload.outcome,
    policy_version: payload.policy_version,
    tool: payload.tool,
  };
  const registryFixtureContractSha256 =
    registryContractSummary.registry_contract_sha256;
  const receiptPayloadContractSha256 = sha256hex(
    canonicalize(receiptPayloadContract)
  );
  const malformedRegistry = evaluateTerminalChainMalformedTrustedIssuerRegistryFixture();
  const unrecognizedScope = 'unrecognized-fixture-records-terminal';
  const unrecognizedScopeDecision =
    evaluateTerminalChainTrustedIssuerRegistryRecognition({
      receipt,
      registry,
      scope: unrecognizedScope,
      nowEpoch: registryNowEpoch,
    });
  const contractMismatchDecision =
    evaluateTerminalChainTrustedIssuerRegistryRecognition({
      receipt: mismatchReceipt,
      registry,
      scope: 'fixture-records-terminal',
      nowEpoch: registryNowEpoch,
    });
  const trustedIssuerRegistryRecognitionRefusals = {
    case_count:
      REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS.length,
    all_refused: [
      unrecognizedScopeDecision,
      contractMismatchDecision,
    ].every((item) =>
      item.recognized === false &&
      item.decision === 'refuse'
    ),
    cases: [
      trustedIssuerRegistryRecognitionRefusalCase({
        caseId: 'unrecognized_terminal_chain_registry_scope_refused',
        decision: unrecognizedScopeDecision,
        requestedScope: unrecognizedScope,
        registryScope: registry.deployment_scope,
      }),
      trustedIssuerRegistryRecognitionRefusalCase({
        caseId: 'registry_receipt_contract_mismatch_refused',
        decision: contractMismatchDecision,
        requestedScope: 'fixture-records-terminal',
        registryScope: registry.deployment_scope,
      }),
    ],
  };
  const trustedIssuerRegistryRecognitionRefusalsSha256 =
    terminalChainTrustedIssuerRegistryRecognitionRefusalsSha256(
      trustedIssuerRegistryRecognitionRefusals
    );
  const decisionPayload = decision.evidence?.payload || {};
  const auditEventBound =
    decisionPayload.audit_event_id === registry.required_audit_event_id &&
    decisionPayload.audit_event_id === payload.audit_event_id;
  const detailHashBound =
    decisionPayload.detail_hash === registry.required_detail_hash &&
    decisionPayload.detail_hash === payload.detail_hash;
  const recognized =
    decision.recognized === true &&
    decision.reason_code === 'recognized' &&
    decision.evidence?.issuer_status === 'active' &&
    decision.evidence?.signature_valid === true &&
    auditEventBound === true &&
    detailHashBound === true &&
    preflightVerification.recognition_contract_sha256 ===
      serviceSummary.recognition_contract_sha256 &&
    serviceVerification.recognition_contract_sha256 ===
      serviceSummary.recognition_contract_sha256 &&
    serviceProof.recognized_boarding.boarded === true;
  const binding = {
    component: 'terminal_chain_trusted_issuer_registry_recognition_binding',
    evidence_model:
      'fresh-local-fixture-terminal-chain-trusted-issuer-registry-recognition',
    registry_type: 'trusted-receipt-issuers-v2',
    registry_evidence_model: 'bundled-local-fixture-no-secret-registry-contract',
    live_probing: false,
    requested_scope: 'fixture-records-terminal',
    registry_scope: 'fixture-records-terminal',
    registry_fixture_contract_sha256: registryFixtureContractSha256,
    registry_accepted_policy_versions: [...registry.accepted_policy_versions],
    registry_accepted_domains: [...registry.accepted_domains],
    registry_accepted_tools: [...registry.accepted_tools],
    registry_accepted_outcomes: [...registry.accepted_outcomes],
    registry_required_audit_event_id: registry.required_audit_event_id,
    registry_required_detail_hash: registry.required_detail_hash,
    registry_trusted_issuer_statuses: registry.trusted_issuers.map((issuer) =>
      issuer.status
    ),
    registry_public_key_material_included: false,
    receipt_payload_contract_sha256: receiptPayloadContractSha256,
    receipt_audit_event_id: payload.audit_event_id,
    receipt_detail_hash: payload.detail_hash,
    boarded_service_receipt_detail_hash:
      serviceSummary.boarded_service_target_binding
        .boarded_service_receipt_detail_sha256,
    boarded_service_receipt_role: TERMINAL_CHAIN_BOARDED_SERVICE_RECEIPT_ROLE,
    registry_receipt_role: TERMINAL_CHAIN_REGISTRY_RECEIPT_ROLE,
    registry_receipt_is_boarded_service_receipt: false,
    registry_receipt_authorized_service_write: false,
    receipt_detail_hash_roles_distinct:
      payload.detail_hash !==
        serviceSummary.boarded_service_target_binding
          .boarded_service_receipt_detail_sha256,
    registry_receipt_metadata_boarded_service_target_binding_sha256:
      event.detail.boarded_service_target_binding_sha256,
    registry_receipt_metadata_hash_bound:
      event.detail.boarded_service_target_binding_sha256 ===
      serviceSummary.boarded_service_target_binding_sha256,
    receipt_envelope_included: false,
    cryptographic_evidence_reproducible_from_artifact: false,
    registry_receipt_contract_hash_bound:
      registryContractSummary.contract_evidence ===
        TRUSTED_RECEIPT_ISSUER_REGISTRY_V2_CONTRACT_EVIDENCE &&
      registryFixtureContractSha256 ===
        registryContractSummary.registry_contract_sha256 &&
      receiptPayloadContractSha256 ===
        sha256hex(canonicalize(receiptPayloadContract)) &&
      registry.required_audit_event_id === payload.audit_event_id &&
      registry.required_detail_hash === payload.detail_hash,
    registry_contract_evidence: registryContractSummary.contract_evidence,
    registry_public_safe_summary_sha256: registryContractSummary.summary_sha256,
    selected_profile_sha256: profileSha,
    selected_profile_recognition_contract_sha256:
      preflightVerification.recognition_contract_sha256,
    service_recognition_contract_sha256:
      serviceSummary.recognition_contract_sha256,
    generated_preflight_artifact_body_sha256:
      preflightArtifact.integrity.body_sha256,
    generated_service_proof_artifact_body_sha256:
      serviceSummary.artifact_body_sha256,
    service_artifact_verification_body_sha256:
      serviceVerification.body_sha256,
    selected_profile_hash_bound:
      profileSha === serviceProof.selected_profile.profile_sha256,
    recognition_contract_hash_bound:
      preflightVerification.recognition_contract_sha256 ===
        serviceSummary.recognition_contract_sha256 &&
      serviceVerification.recognition_contract_sha256 ===
        serviceSummary.recognition_contract_sha256,
    preflight_artifact_hash_bound:
      preflightArtifact.integrity.body_sha256 ===
        serviceProof.source_preflight.body_sha256,
    service_artifact_hash_bound:
      serviceSummary.artifact_body_sha256 === serviceVerification.body_sha256,
    service_artifact_verification_bound_to_service_proof:
      serviceVerification.body_sha256 === serviceSummary.artifact_body_sha256,
    recognized_write_boarded: serviceProof.recognized_boarding.boarded,
    terminal_chain_decision_bound:
      serviceProof.recognized_boarding.boarded === true &&
      serviceSummary.recognized_write_boarded === true,
    registry_fixture_validated: true,
    registry_fixture_evaluated: true,
    registry_to_recognition_rule_evaluated: true,
    registry_evaluation_result_type: decision.result_type,
    registry_trusted_issuer_count: registry.trusted_issuers.length,
    verdict: recognized ? 'RECOGNIZED' : 'NOT_RECOGNIZED',
    recognized,
    decision: decision.decision,
    reason_code: decision.reason_code,
    issuer_status: decision.evidence?.issuer_status ?? null,
    signature_valid: decision.evidence?.signature_valid === true,
    required_audit_event_id_bound: auditEventBound,
    required_detail_hash_bound: detailHashBound,
    malformed_registry_unsupported_field:
      malformedRegistry.unsupported_field === true,
    malformed_registry_error_code: malformedRegistry.error_code,
    malformed_registry_fail_closed_before_verdict:
      malformedRegistry.fail_closed_before_verdict === true,
    trusted_issuer_registry_recognition_refusals:
      trustedIssuerRegistryRecognitionRefusals,
    trusted_issuer_registry_recognition_refusals_sha256:
      trustedIssuerRegistryRecognitionRefusalsSha256,
    live_trust_registry_state: false,
    live_issuer_status_proven: false,
    key_custody_proven: false,
    revocation_truth_proven: false,
    production_trust_registry_proven: false,
    production_downstream_recognition_proven: false,
    production_authority: false,
    sovereign_recognition: false,
    public_external_attestation: false,
    real_non_operator_review: false,
    current_machine_governance_proven: false,
    profile_wide_target_authority_proven: false,
    rightful_issuance_proven: false,
    live_target_proven: false,
    consequence_lifecycle_closed: false,
    safe_claim_ceiling: TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_CLAIM_BOUNDARY,
    claim_boundary: TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_CLAIM_BOUNDARY,
    non_claims: [...TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_NON_CLAIMS],
  };
  return {
    ...binding,
    binding_sha256: terminalChainTrustedIssuerRegistryRecognitionBindingSha256(
      binding
    ),
  };
}

function assertTerminalChainTrustedIssuerRegistryRecognitionBinding(label, value, chain) {
  const hasNoSecretRegistryContractFields =
    Object.prototype.hasOwnProperty.call(value, 'registry_contract_evidence') ||
    Object.prototype.hasOwnProperty.call(value, 'registry_public_safe_summary_sha256');
  const expectedKeys = [
    'binding_sha256',
    'boarded_service_receipt_detail_hash',
    'boarded_service_receipt_role',
    'claim_boundary',
    'component',
    'consequence_lifecycle_closed',
    'cryptographic_evidence_reproducible_from_artifact',
    'current_machine_governance_proven',
    'decision',
    'evidence_model',
    'generated_preflight_artifact_body_sha256',
    'generated_service_proof_artifact_body_sha256',
    'issuer_status',
    'key_custody_proven',
    'live_issuer_status_proven',
    'live_probing',
    'live_target_proven',
    'live_trust_registry_state',
    'malformed_registry_error_code',
    'malformed_registry_fail_closed_before_verdict',
    'malformed_registry_unsupported_field',
    'non_claims',
    'preflight_artifact_hash_bound',
    'production_authority',
    'production_downstream_recognition_proven',
    'profile_wide_target_authority_proven',
    'production_trust_registry_proven',
    'public_external_attestation',
    'real_non_operator_review',
    'reason_code',
    'recognized',
    'recognized_write_boarded',
    'recognition_contract_hash_bound',
    'receipt_audit_event_id',
    'receipt_detail_hash',
    'receipt_envelope_included',
    'receipt_payload_contract_sha256',
    'receipt_detail_hash_roles_distinct',
    'registry_accepted_domains',
    'registry_accepted_outcomes',
    'registry_accepted_policy_versions',
    'registry_accepted_tools',
    'registry_evaluation_result_type',
    'registry_evidence_model',
    'registry_fixture_contract_sha256',
    'registry_fixture_evaluated',
    'registry_fixture_validated',
    'registry_public_key_material_included',
    'registry_receipt_contract_hash_bound',
    'registry_receipt_authorized_service_write',
    'registry_receipt_is_boarded_service_receipt',
    'registry_receipt_metadata_boarded_service_target_binding_sha256',
    'registry_receipt_metadata_hash_bound',
    'registry_receipt_role',
    'registry_required_audit_event_id',
    'registry_required_detail_hash',
    'registry_scope',
    'registry_to_recognition_rule_evaluated',
    'registry_trusted_issuer_count',
    'registry_trusted_issuer_statuses',
    'registry_type',
    'requested_scope',
    'required_audit_event_id_bound',
    'required_detail_hash_bound',
    'revocation_truth_proven',
    'rightful_issuance_proven',
    'safe_claim_ceiling',
    'selected_profile_hash_bound',
    'selected_profile_recognition_contract_sha256',
    'selected_profile_sha256',
    'service_artifact_hash_bound',
    'service_artifact_verification_body_sha256',
    'service_artifact_verification_bound_to_service_proof',
    'service_recognition_contract_sha256',
    'signature_valid',
    'sovereign_recognition',
    'terminal_chain_decision_bound',
    'trusted_issuer_registry_recognition_refusals',
    'trusted_issuer_registry_recognition_refusals_sha256',
    'verdict',
  ];
  if (hasNoSecretRegistryContractFields) {
    expectedKeys.push(
      'registry_contract_evidence',
      'registry_public_safe_summary_sha256'
    );
  }
  assertExactKeys(label, value, expectedKeys);
  const registryEvidenceModelAccepted = hasNoSecretRegistryContractFields
    ? value.registry_evidence_model ===
      'bundled-local-fixture-no-secret-registry-contract'
    : value.registry_evidence_model === 'bundled-local-fixture';
  if (
    value.component !==
      'terminal_chain_trusted_issuer_registry_recognition_binding' ||
    value.evidence_model !==
      'fresh-local-fixture-terminal-chain-trusted-issuer-registry-recognition' ||
    value.registry_type !== 'trusted-receipt-issuers-v2' ||
    registryEvidenceModelAccepted !== true ||
    value.live_probing !== false ||
    value.requested_scope !== 'fixture-records-terminal' ||
    value.registry_scope !== 'fixture-records-terminal' ||
    !/^[a-f0-9]{64}$/.test(value.registry_fixture_contract_sha256 || '') ||
    (
      hasNoSecretRegistryContractFields &&
      (
        value.registry_contract_evidence !==
          TRUSTED_RECEIPT_ISSUER_REGISTRY_V2_CONTRACT_EVIDENCE ||
        !/^[a-f0-9]{64}$/.test(value.registry_public_safe_summary_sha256 || '')
      )
    ) ||
    !/^[a-f0-9]{64}$/.test(value.receipt_payload_contract_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(value.boarded_service_receipt_detail_hash || '') ||
    value.registry_required_audit_event_id !== value.receipt_audit_event_id ||
    value.registry_required_detail_hash !== value.receipt_detail_hash ||
    value.boarded_service_receipt_role !==
      TERMINAL_CHAIN_BOARDED_SERVICE_RECEIPT_ROLE ||
    value.registry_receipt_role !== TERMINAL_CHAIN_REGISTRY_RECEIPT_ROLE ||
    value.registry_receipt_is_boarded_service_receipt !== false ||
    value.registry_receipt_authorized_service_write !== false ||
    value.receipt_detail_hash === value.boarded_service_receipt_detail_hash ||
    value.receipt_detail_hash_roles_distinct !== true ||
    value.registry_receipt_metadata_boarded_service_target_binding_sha256 !==
      chain.generated_service_proof.boarded_service_target_binding_sha256 ||
    value.registry_receipt_metadata_hash_bound !== true ||
    value.registry_public_key_material_included !== false ||
    value.receipt_envelope_included !== false ||
    value.cryptographic_evidence_reproducible_from_artifact !== false ||
    value.registry_receipt_contract_hash_bound !== true ||
    !/^[a-f0-9]{64}$/.test(value.selected_profile_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(value.selected_profile_recognition_contract_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(value.service_recognition_contract_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(value.generated_preflight_artifact_body_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(value.generated_service_proof_artifact_body_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(value.service_artifact_verification_body_sha256 || '') ||
    value.selected_profile_sha256 !== chain.runtime_profile.profile_sha256 ||
    value.selected_profile_recognition_contract_sha256 !==
      chain.generated_preflight.recognition_contract_sha256 ||
    value.service_recognition_contract_sha256 !==
      chain.generated_service_proof.recognition_contract_sha256 ||
    value.selected_profile_recognition_contract_sha256 !==
      value.service_recognition_contract_sha256 ||
    value.generated_preflight_artifact_body_sha256 !==
      chain.generated_preflight.artifact_body_sha256 ||
    value.generated_service_proof_artifact_body_sha256 !==
      chain.generated_service_proof.artifact_body_sha256 ||
    value.service_artifact_verification_body_sha256 !==
      chain.generated_service_proof.verification_body_sha256 ||
    value.selected_profile_hash_bound !== true ||
    value.recognition_contract_hash_bound !== true ||
    value.preflight_artifact_hash_bound !== true ||
    value.service_artifact_hash_bound !== true ||
    value.service_artifact_verification_bound_to_service_proof !== true ||
    value.recognized_write_boarded !== true ||
    value.recognized_write_boarded !==
      chain.generated_service_proof.recognized_write_boarded ||
    value.terminal_chain_decision_bound !== true ||
    value.registry_fixture_validated !== true ||
    value.registry_fixture_evaluated !== true ||
    value.registry_to_recognition_rule_evaluated !== true ||
    value.registry_evaluation_result_type !== 'downstream-recognition-rule-v1' ||
    value.registry_trusted_issuer_count !== 1 ||
    value.verdict !== 'RECOGNIZED' ||
    value.recognized !== true ||
    value.decision !== 'accept' ||
    value.reason_code !== 'recognized' ||
    value.issuer_status !== 'active' ||
    value.signature_valid !== true ||
    value.required_audit_event_id_bound !== true ||
    value.required_detail_hash_bound !== true ||
    value.malformed_registry_unsupported_field !== true ||
    value.malformed_registry_error_code !== 'unsupported_registry_field' ||
    value.malformed_registry_fail_closed_before_verdict !== true ||
    !assertTerminalChainTrustedIssuerRegistryRecognitionRefusals(
      `${label} trusted issuer registry recognition refusals`,
      value.trusted_issuer_registry_recognition_refusals
    ) ||
    value.trusted_issuer_registry_recognition_refusals_sha256 !==
      terminalChainTrustedIssuerRegistryRecognitionRefusalsSha256(
        value.trusted_issuer_registry_recognition_refusals
      ) ||
    !/^[a-f0-9]{64}$/.test(
      value.trusted_issuer_registry_recognition_refusals_sha256 || ''
    ) ||
    !trustedIssuerRegistryFalseBoundaryPreserved(value) ||
    value.safe_claim_ceiling !==
      TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_CLAIM_BOUNDARY ||
    value.claim_boundary !==
      TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_CLAIM_BOUNDARY ||
    !Array.isArray(value.non_claims) ||
    value.non_claims.length !==
      TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_NON_CLAIMS.length ||
    !/^[a-f0-9]{64}$/.test(value.binding_sha256 || '') ||
    value.binding_sha256 !==
      terminalChainTrustedIssuerRegistryRecognitionBindingSha256(value)
  ) {
    throw new Error(`${label} trusted issuer registry recognition binding drifted`);
  }
  assertExactArray(
    `${label} registry accepted policy versions`,
    value.registry_accepted_policy_versions,
    ['terminal-chain-trusted-registry-fixture-v1']
  );
  assertExactArray(
    `${label} registry accepted domains`,
    value.registry_accepted_domains,
    ['records']
  );
  assertExactArray(
    `${label} registry accepted tools`,
    value.registry_accepted_tools,
    ['records.write']
  );
  assertExactArray(
    `${label} registry accepted outcomes`,
    value.registry_accepted_outcomes,
    ['allow']
  );
  assertExactArray(
    `${label} registry trusted issuer statuses`,
    value.registry_trusted_issuer_statuses,
    ['active']
  );
  assertExactArray(
    `${label} trusted issuer registry recognition non-claims`,
    value.non_claims,
    TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_NON_CLAIMS
  );
  return true;
}

function assertTerminalChainRecognizedReceiptPathEvidence(
  label,
  value,
  binding,
  boardedServiceTargetBinding,
  boardedServiceTargetBindingSha
) {
  assertExactKeys(label, value, [
    'boarded_service_launcher_target_binding_sha256',
    'boarded_service_receipt_detail_hash',
    'boarded_service_receipt_role',
    'boarded_service_state_effect_binding_sha256',
    'boarded_service_target_binding_sha256',
    'boarded_service_target_effect_hash',
    'boarded_service_target_handle',
    'boarded_service_target_metadata_role',
    'claim_boundary',
    'consequence_lifecycle_closed',
    'component',
    'cryptographic_evidence_reproducible_from_artifact',
    'current_machine_governance_proven',
    'decision',
    'evidence_model',
    'evidence_scope',
    'generated_preflight_artifact_body_sha256',
    'generated_service_proof_artifact_body_sha256',
    'issuer_status',
    'key_custody_proven',
    'live_issuer_status_proven',
    'live_trust_registry_state',
    'production_downstream_recognition_proven',
    'profile_wide_target_authority_proven',
    'public_external_attestation',
    'reason_code',
    'receipt_audit_event_id',
    'receipt_detail_hash',
    'receipt_envelope_included',
    'receipt_payload_contract_sha256',
    'receipt_detail_hash_roles_distinct',
    'recognized',
    'recognized_write_boarded',
    'recognition_contract_hash_bound',
    'recognition_contract_sha256',
    'registry_evaluation_result_type',
    'registry_fixture_contract_sha256',
    'registry_fixture_evaluated',
    'registry_fixture_validated',
    'registry_public_key_material_included',
    'registry_receipt_authorized_service_write',
    'registry_receipt_contract_hash_bound',
    'registry_receipt_is_boarded_service_receipt',
    'registry_receipt_role',
    'registry_to_recognition_rule_evaluated',
    'registry_trusted_issuer_count',
    'required_audit_event_id_bound',
    'required_detail_hash_bound',
    'revocation_truth_proven',
    'rightful_issuance_proven',
    'selected_profile_hash_bound',
    'selected_profile_sha256',
    'service_artifact_hash_bound',
    'service_artifact_verification_body_sha256',
    'signature_valid',
    'sovereign_recognition',
    'source_binding_sha256',
    'terminal_chain_decision_bound',
    'verdict',
    'live_target_proven',
  ]);
  if (
    value.component !== 'terminal_chain_recognized_receipt_path_evidence' ||
    value.evidence_model !==
      'artifact-owned-public-safe-local-fixture-recognized-receipt-path-v1' ||
    value.evidence_scope !==
      'protected-records.installed-runtime-profile.terminal-chain.records.write' ||
    value.source_binding_sha256 !== binding.binding_sha256 ||
    value.registry_fixture_contract_sha256 !==
      binding.registry_fixture_contract_sha256 ||
    value.receipt_payload_contract_sha256 !==
      binding.receipt_payload_contract_sha256 ||
    value.receipt_audit_event_id !== binding.receipt_audit_event_id ||
    value.receipt_detail_hash !== binding.receipt_detail_hash ||
    value.boarded_service_target_binding_sha256 !==
      boardedServiceTargetBindingSha ||
    value.boarded_service_target_binding_sha256 !==
      binding.registry_receipt_metadata_boarded_service_target_binding_sha256 ||
    value.boarded_service_launcher_target_binding_sha256 !==
      boardedServiceTargetBinding.launcher_target_binding_sha256 ||
    value.boarded_service_target_handle !==
      boardedServiceTargetBinding.target_handle ||
    value.boarded_service_target_effect_hash !==
      boardedServiceTargetBinding.target_effect_sha256 ||
    value.boarded_service_receipt_detail_hash !==
      boardedServiceTargetBinding.boarded_service_receipt_detail_sha256 ||
    value.boarded_service_state_effect_binding_sha256 !==
      boardedServiceTargetBinding.state_effect_binding_sha256 ||
    value.boarded_service_target_metadata_role !==
      TERMINAL_CHAIN_BOARDED_TARGET_METADATA_ROLE ||
    value.boarded_service_receipt_role !==
      TERMINAL_CHAIN_BOARDED_SERVICE_RECEIPT_ROLE ||
    value.boarded_service_receipt_role !== binding.boarded_service_receipt_role ||
    value.registry_receipt_role !== TERMINAL_CHAIN_REGISTRY_RECEIPT_ROLE ||
    value.registry_receipt_role !== binding.registry_receipt_role ||
    value.registry_receipt_is_boarded_service_receipt !== false ||
    value.registry_receipt_is_boarded_service_receipt !==
      binding.registry_receipt_is_boarded_service_receipt ||
    value.registry_receipt_authorized_service_write !== false ||
    value.registry_receipt_authorized_service_write !==
      binding.registry_receipt_authorized_service_write ||
    value.receipt_detail_hash === value.boarded_service_receipt_detail_hash ||
    value.receipt_detail_hash_roles_distinct !== true ||
    value.receipt_detail_hash_roles_distinct !==
      binding.receipt_detail_hash_roles_distinct ||
    value.profile_wide_target_authority_proven !== false ||
    value.rightful_issuance_proven !== false ||
    value.live_target_proven !== false ||
    value.consequence_lifecycle_closed !== false ||
    value.selected_profile_sha256 !== binding.selected_profile_sha256 ||
    value.recognition_contract_sha256 !==
      binding.selected_profile_recognition_contract_sha256 ||
    value.generated_preflight_artifact_body_sha256 !==
      binding.generated_preflight_artifact_body_sha256 ||
    value.generated_service_proof_artifact_body_sha256 !==
      binding.generated_service_proof_artifact_body_sha256 ||
    value.service_artifact_verification_body_sha256 !==
      binding.service_artifact_verification_body_sha256 ||
    value.verdict !== 'RECOGNIZED' ||
    value.verdict !== binding.verdict ||
    value.recognized !== true ||
    value.recognized !== binding.recognized ||
    value.decision !== 'accept' ||
    value.decision !== binding.decision ||
    value.reason_code !== 'recognized' ||
    value.reason_code !== binding.reason_code ||
    value.issuer_status !== 'active' ||
    value.issuer_status !== binding.issuer_status ||
    value.signature_valid !== true ||
    value.signature_valid !== binding.signature_valid ||
    value.registry_fixture_validated !== true ||
    value.registry_fixture_validated !== binding.registry_fixture_validated ||
    value.registry_fixture_evaluated !== true ||
    value.registry_fixture_evaluated !== binding.registry_fixture_evaluated ||
    value.registry_to_recognition_rule_evaluated !== true ||
    value.registry_to_recognition_rule_evaluated !==
      binding.registry_to_recognition_rule_evaluated ||
    value.registry_evaluation_result_type !== 'downstream-recognition-rule-v1' ||
    value.registry_evaluation_result_type !== binding.registry_evaluation_result_type ||
    value.registry_trusted_issuer_count !== 1 ||
    value.registry_trusted_issuer_count !== binding.registry_trusted_issuer_count ||
    value.registry_receipt_contract_hash_bound !== true ||
    value.registry_receipt_contract_hash_bound !==
      binding.registry_receipt_contract_hash_bound ||
    value.required_audit_event_id_bound !== true ||
    value.required_audit_event_id_bound !==
      binding.required_audit_event_id_bound ||
    value.required_detail_hash_bound !== true ||
    value.required_detail_hash_bound !== binding.required_detail_hash_bound ||
    value.selected_profile_hash_bound !== true ||
    value.selected_profile_hash_bound !== binding.selected_profile_hash_bound ||
    value.recognition_contract_hash_bound !== true ||
    value.recognition_contract_hash_bound !==
      binding.recognition_contract_hash_bound ||
    value.service_artifact_hash_bound !== true ||
    value.service_artifact_hash_bound !== binding.service_artifact_hash_bound ||
    value.terminal_chain_decision_bound !== true ||
    value.terminal_chain_decision_bound !==
      binding.terminal_chain_decision_bound ||
    value.recognized_write_boarded !== true ||
    value.recognized_write_boarded !== binding.recognized_write_boarded ||
    value.registry_public_key_material_included !== false ||
    value.registry_public_key_material_included !==
      binding.registry_public_key_material_included ||
    value.receipt_envelope_included !== false ||
    value.receipt_envelope_included !== binding.receipt_envelope_included ||
    value.cryptographic_evidence_reproducible_from_artifact !== false ||
    value.cryptographic_evidence_reproducible_from_artifact !==
      binding.cryptographic_evidence_reproducible_from_artifact ||
    value.live_trust_registry_state !== false ||
    value.live_trust_registry_state !== binding.live_trust_registry_state ||
    value.live_issuer_status_proven !== false ||
    value.live_issuer_status_proven !== binding.live_issuer_status_proven ||
    value.key_custody_proven !== false ||
    value.key_custody_proven !== binding.key_custody_proven ||
    value.revocation_truth_proven !== false ||
    value.revocation_truth_proven !== binding.revocation_truth_proven ||
    value.production_downstream_recognition_proven !== false ||
    value.production_downstream_recognition_proven !==
      binding.production_downstream_recognition_proven ||
    value.public_external_attestation !== false ||
    value.public_external_attestation !== binding.public_external_attestation ||
    value.sovereign_recognition !== false ||
    value.sovereign_recognition !== binding.sovereign_recognition ||
    value.current_machine_governance_proven !== false ||
    value.current_machine_governance_proven !==
      binding.current_machine_governance_proven ||
    value.claim_boundary !== TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_CLAIM_BOUNDARY
  ) {
    throw new Error(`${label} recognized receipt path evidence drifted`);
  }
  return true;
}

function refusalTaxonomySha256(value) {
  return sha256hex(canonicalize({
    required_refusal_cases: value.required_refusal_cases,
    observed_refusal_cases: value.observed_refusal_cases,
  }));
}

function buildNamedReceiptRefusals(observedRefusalCases) {
  const byCaseId = new Map((observedRefusalCases || []).map((item) => [item.case_id, item]));
  return Object.fromEntries(
    Object.entries(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS)
      .map(([name, expected]) => {
        const observed = byCaseId.get(expected.case_id) || {};
        return [
          name,
          {
            case_id: expected.case_id,
            reason_code: observed.reason_code || null,
            refused_before_mutation: observed.refused_before_mutation === true,
          },
        ];
      })
  );
}

function namedReceiptRefusalsSha256(value) {
  return sha256hex(canonicalize({ named_receipt_refusals: value }));
}

function buildRecognitionRefusalGroups(observedRefusalCases) {
  const byCaseId = new Map((observedRefusalCases || []).map((item) => [item.case_id, item]));
  return Object.fromEntries(
    Object.entries(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS)
      .map(([groupName, expectedCases]) => {
        const cases = expectedCases.map((expected) => {
          const observed = byCaseId.get(expected.case_id) || {};
          return {
            case_id: expected.case_id,
            reason_code: observed.reason_code || null,
            refused_before_mutation: observed.refused_before_mutation === true,
          };
        });
        return [
          groupName,
          {
            case_count: cases.length,
            all_refused_before_mutation: cases.every((item) =>
              item.refused_before_mutation === true
            ),
            cases,
          },
        ];
      })
  );
}

function recognitionRefusalGroupsSha256(value) {
  return sha256hex(canonicalize({ recognition_refusal_groups: value }));
}

function assertNamedReceiptRefusals(label, value) {
  requireObject(label, value);
  assertExactKeys(
    label,
    value,
    Object.keys(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS)
  );
  for (const [name, expected] of Object.entries(
    REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS
  )) {
    const observed = value[name];
    assertExactKeys(`${label} ${name}`, observed, [
      'case_id',
      'reason_code',
      'refused_before_mutation',
    ]);
    if (
      observed.case_id !== expected.case_id ||
      observed.reason_code !== expected.reason_code ||
      observed.refused_before_mutation !== true
    ) {
      throw new Error(`${label} named receipt refusal drifted: ${name}`);
    }
  }
  return true;
}

function assertRecognitionRefusalGroups(label, value) {
  requireObject(label, value);
  assertExactKeys(
    label,
    value,
    Object.keys(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS)
  );
  for (const [groupName, expectedCases] of Object.entries(
    REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS
  )) {
    const group = value[groupName];
    assertExactKeys(`${label} ${groupName}`, group, [
      'all_refused_before_mutation',
      'case_count',
      'cases',
    ]);
    if (
      group.case_count !== expectedCases.length ||
      group.all_refused_before_mutation !== true ||
      !Array.isArray(group.cases) ||
      group.cases.length !== expectedCases.length
    ) {
      throw new Error(`${label} recognition refusal group drifted: ${groupName}`);
    }
    group.cases.forEach((observed, index) => {
      const expected = expectedCases[index];
      assertExactKeys(`${label} ${groupName} case`, observed, [
        'case_id',
        'reason_code',
        'refused_before_mutation',
      ]);
      if (
        observed.case_id !== expected.case_id ||
        observed.reason_code !== expected.reason_code ||
        observed.refused_before_mutation !== true
      ) {
        throw new Error(`${label} recognition refusal group case drifted: ${groupName}`);
      }
    });
  }
  return true;
}

function assertInstalledRuntimeProfileTerminalChainRefusalTaxonomy(label, value) {
  requireObject(label, value);
  assertExactArray(
    `${label} required refusal cases`,
    value.required_refusal_cases,
    REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES
  );
  if (
    !Array.isArray(value.observed_refusal_cases) ||
    value.observed_refusal_cases.length !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length
  ) {
    throw new Error(`${label} observed refusal cases drifted`);
  }
  value.observed_refusal_cases.forEach((item, index) => {
    assertExactKeys(`${label} observed refusal case`, item, [
      'case_id',
      'reason_code',
      'refused_before_mutation',
    ]);
    const expectedCaseId =
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES[index];
    if (
      item.case_id !== expectedCaseId ||
      item.reason_code !== EXPECTED_REFUSAL_REASONS[expectedCaseId] ||
      item.refused_before_mutation !== true
    ) {
      throw new Error(`${label} observed refusal case drifted: ${expectedCaseId}`);
    }
  });
  if (
    !/^[a-f0-9]{64}$/.test(value.refusal_taxonomy_sha256 || '') ||
    value.refusal_taxonomy_sha256 !== refusalTaxonomySha256(value)
  ) {
    throw new Error(`${label} refusal taxonomy hash drifted`);
  }
  return true;
}

function authorityRefusalTaxonomySha256(value) {
  return sha256hex(canonicalize({
    required_refusal_cases: value.required_refusal_cases,
    observed_refusal_cases: value.observed_refusal_cases.map((item) => ({
      case_id: item.case_id,
      reason_code: item.reason_code,
      refused_before_mutation: item.refused_before_consumption_and_mutation,
    })),
  }));
}

function assertInstalledRuntimeProfileTerminalChainAuthorityRefusalTaxonomy(
  label,
  value
) {
  requireObject(label, value);
  assertExactArray(
    `${label} required refusal cases`,
    value.required_refusal_cases,
    REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES
  );
  if (
    !Array.isArray(value.observed_refusal_cases) ||
    value.observed_refusal_cases.length !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length
  ) {
    throw new Error(`${label} observed refusal cases drifted`);
  }
  value.observed_refusal_cases.forEach((item, index) => {
    assertExactKeys(`${label} observed authority refusal case`, item, [
      'case_id',
      'reason_code',
      'refused_before_consumption_and_mutation',
    ]);
    const expectedCaseId =
      REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES[index];
    if (
      item.case_id !== expectedCaseId ||
      item.reason_code !==
        TERMINAL_CHAIN_EXPECTED_AUTHORITY_REFUSAL_REASONS[expectedCaseId] ||
      item.refused_before_consumption_and_mutation !== true
    ) {
      throw new Error(`${label} observed authority refusal drifted: ${expectedCaseId}`);
    }
  });
  if (
    !/^[a-f0-9]{64}$/.test(value.refusal_taxonomy_sha256 || '') ||
    value.refusal_taxonomy_sha256 !== authorityRefusalTaxonomySha256(value)
  ) {
    throw new Error(`${label} authority refusal taxonomy hash drifted`);
  }
  return true;
}

function installDisposableProfileRoot(plan, profile, profileSha) {
  const installRoot = mkdtempSync(join(tmpdir(), 'zlar-installed-terminal-chain-'));
  try {
    const profilesDir = join(installRoot, 'profiles');
    mkdirSync(profilesDir, { recursive: true });
    const installedProfilePath = join(profilesDir, `${profile.runtime_profile_id}.json`);
    writeFileSync(installedProfilePath, `${JSON.stringify(profile, null, 2)}\n`, { mode: 0o600 });
    const activeIndex = {
      index_type: PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_ACTIVE_INDEX_TYPE,
      selected_profile_id: profile.profile_id,
      selected_runtime_profile_id: profile.runtime_profile_id,
      selected_profile_sha256: profileSha,
      selected_by_explicit_id_and_sha: true,
      selects_latest_profile: false,
      installed_profile_path:
        '<launcher-owned-disposable-install-root>/profiles/protected-records-disposable-runtime-profile.json',
    };
    const activeIndexPath = join(installRoot, 'active-runtime-profile.json');
    writeFileSync(activeIndexPath, `${JSON.stringify(activeIndex, null, 2)}\n`, { mode: 0o600 });
    return {
      installRoot,
      summary: {
        install_root_kind: 'launcher-owned-disposable-proof-root',
        install_root_path_in_report: null,
        active_index_path_in_report:
          '<launcher-owned-disposable-install-root>/active-runtime-profile.json',
        installed_profile_path_in_report:
          '<launcher-owned-disposable-install-root>/profiles/protected-records-disposable-runtime-profile.json',
        install_root_created: true,
        profile_copy_written: true,
        active_profile_index_written: true,
        profile_selected_from_install_root: true,
        selected_by_explicit_id_and_sha: true,
        selects_latest_profile: false,
        selected_profile_id: profile.profile_id,
        selected_runtime_profile_id: plan.runtime_profile_id,
        selected_profile_sha256: profileSha,
        disposable_root_removed_after_run: false,
      },
    };
  } catch (err) {
    rmSync(installRoot, { recursive: true, force: true });
    throw err;
  }
}

function boardedServiceTargetBindingSha256(value) {
  return sha256hex(canonicalize({
    boarded_service_target_binding: value,
  }));
}

function boardedServiceTargetBindingSummary(serviceProof, serviceArtifactVerification) {
  const target = requireObject(
    'Protected records installed runtime profile terminal chain nested service target binding',
    serviceProof.target_binding
  );
  return {
    component: 'boarded_service_target_binding',
    evidence_model: 'nested-service-proof-post-effect-hash-bound-summary-v1',
    consequence_path: target.consequence_path,
    target_kind: target.target_kind,
    target_scope: target.target_scope,
    target_instance_scope: target.target_instance_scope,
    target_descriptor_sha256: target.target_descriptor_sha256,
    target_handle: target.target_handle,
    launcher_target_binding_sha256: target.target_binding_sha256,
    target_effect_sha256: target.target_effect_sha256,
    authorized_effect_detail_sha256: target.authorized_effect_detail_sha256,
    boarded_service_receipt_detail_sha256: target.receipt_detail_sha256,
    state_effect_binding_sha256: target.state_effect_binding_sha256,
    source_profile_sha256: target.source_profile_sha256,
    source_preflight_body_sha256: target.source_preflight_body_sha256,
    source_recognition_contract_sha256:
      target.source_recognition_contract_sha256,
    source_target_contract_sha256: target.source_target_contract_sha256,
    generated_service_proof_artifact_body_sha256:
      serviceArtifactVerification.body_sha256,
    receipt_binds_authorized_effect_detail:
      target.receipt_binds_authorized_effect_detail === true &&
      target.receipt_detail_sha256 === target.authorized_effect_detail_sha256,
    target_effect_bound_inside_authorized_effect_detail:
      target.target_effect_bound_inside_authorized_effect_detail,
    accepted_state_effect_binding_hash_present:
      target.accepted_state_effect_binding_hash_present,
    profile_hash_bound:
      target.source_profile_sha256 === serviceProof.selected_profile.profile_sha256,
    preflight_hash_bound:
      target.source_preflight_body_sha256 === serviceProof.source_preflight.body_sha256,
    recognition_contract_hash_bound:
      target.source_recognition_contract_sha256 ===
      serviceProof.source_preflight.recognition_contract_sha256,
    target_contract_hash_bound:
      target.source_target_contract_sha256 ===
      serviceProof.source_preflight.target_contract_sha256,
    service_artifact_hash_bound:
      serviceArtifactVerification.body_sha256 ===
      protectedRecordsInstalledRuntimeProfileServiceProofArtifactBodySha256(
        serviceProof
      ),
    metadata_role: TERMINAL_CHAIN_BOARDED_TARGET_METADATA_ROLE,
    boarded_service_receipt_role: TERMINAL_CHAIN_BOARDED_SERVICE_RECEIPT_ROLE,
    fixture_rightful_issuance_path_evidenced:
      target.fixture_rightful_issuance_path_evidenced,
    profile_wide_target_authority_proven: false,
    rightful_issuance_proven: false,
    live_target_proven: false,
    current_machine_governance_proven: false,
    consequence_lifecycle_closed: false,
  };
}

function assertBoardedServiceTargetBinding(label, value) {
  assertExactKeys(label, value, [
    'accepted_state_effect_binding_hash_present',
    'authorized_effect_detail_sha256',
    'boarded_service_receipt_detail_sha256',
    'boarded_service_receipt_role',
    'component',
    'consequence_lifecycle_closed',
    'consequence_path',
    'current_machine_governance_proven',
    'evidence_model',
    'fixture_rightful_issuance_path_evidenced',
    'generated_service_proof_artifact_body_sha256',
    'launcher_target_binding_sha256',
    'live_target_proven',
    'metadata_role',
    'preflight_hash_bound',
    'profile_hash_bound',
    'profile_wide_target_authority_proven',
    'recognition_contract_hash_bound',
    'rightful_issuance_proven',
    'service_artifact_hash_bound',
    'source_preflight_body_sha256',
    'source_profile_sha256',
    'source_recognition_contract_sha256',
    'source_target_contract_sha256',
    'state_effect_binding_sha256',
    'target_contract_hash_bound',
    'target_descriptor_sha256',
    'receipt_binds_authorized_effect_detail',
    'target_effect_bound_inside_authorized_effect_detail',
    'target_effect_sha256',
    'target_handle',
    'target_instance_scope',
    'target_kind',
    'target_scope',
  ]);
  for (const key of [
    'target_descriptor_sha256',
    'launcher_target_binding_sha256',
    'target_effect_sha256',
    'authorized_effect_detail_sha256',
    'boarded_service_receipt_detail_sha256',
    'state_effect_binding_sha256',
    'source_profile_sha256',
    'source_preflight_body_sha256',
    'source_recognition_contract_sha256',
    'source_target_contract_sha256',
    'generated_service_proof_artifact_body_sha256',
  ]) {
    if (!/^[a-f0-9]{64}$/.test(value[key] || '')) {
      throw new Error(`${label} ${key} drifted`);
    }
  }
  if (
    value.component !== 'boarded_service_target_binding' ||
    value.evidence_model !==
      'nested-service-proof-post-effect-hash-bound-summary-v1' ||
    value.consequence_path !== PROTECTED_RECORDS_CONSEQUENCE_PATH ||
    value.target_kind !== PROTECTED_RECORDS_TARGET_KIND ||
    value.target_scope !== PROTECTED_RECORDS_TARGET_SCOPE ||
    value.target_instance_scope !== 'logical-fixture-not-per-run' ||
    value.target_handle !== PROTECTED_RECORDS_TARGET_HANDLE ||
    value.boarded_service_receipt_detail_sha256 !==
      value.authorized_effect_detail_sha256 ||
    value.receipt_binds_authorized_effect_detail !== true ||
    value.target_effect_bound_inside_authorized_effect_detail !== true ||
    value.accepted_state_effect_binding_hash_present !== true ||
    value.profile_hash_bound !== true ||
    value.preflight_hash_bound !== true ||
    value.recognition_contract_hash_bound !== true ||
    value.target_contract_hash_bound !== true ||
    value.service_artifact_hash_bound !== true ||
    value.metadata_role !== TERMINAL_CHAIN_BOARDED_TARGET_METADATA_ROLE ||
    value.boarded_service_receipt_role !==
      TERMINAL_CHAIN_BOARDED_SERVICE_RECEIPT_ROLE ||
    value.fixture_rightful_issuance_path_evidenced !== true ||
    value.profile_wide_target_authority_proven !== false ||
    value.rightful_issuance_proven !== false ||
    value.live_target_proven !== false ||
    value.current_machine_governance_proven !== false ||
    value.consequence_lifecycle_closed !== false
  ) {
    throw new Error(`${label} drifted`);
  }
  return true;
}

function serviceProofSummary(serviceProof, serviceArtifactVerification) {
  const observedRecognitionRefusalCases = serviceProof.refusal_cases.map((item) => ({
    case_id: item.case_id,
    reason_code: item.reason_code,
    refused_before_mutation:
      item.boarded === false &&
      item.service_write_accepted === false &&
      item.state_entry_count_delta === 0,
  }));
  const observedAuthorityRefusalCases = serviceProof.authority_refusal_cases.map((item) => ({
    case_id: item.case_id,
    reason_code: item.reason_code,
    refused_before_consumption_and_mutation:
      item.boarded === false &&
      item.service_write_accepted === false &&
      item.consumed_authority_grant_count === 0 &&
      item.state_entry_count_delta === 0,
  }));
  const namedReceiptRefusals = buildNamedReceiptRefusals(
    observedRecognitionRefusalCases
  );
  const recognitionRefusalGroups = buildRecognitionRefusalGroups(
    observedRecognitionRefusalCases
  );
  const requiredRecognitionRefusalCases = [
    ...REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
  ];
  const requiredAuthorityRefusalCases = [
    ...REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES,
  ];
  const recognitionContractSha256 = serviceProof.source_preflight.recognition_contract_sha256;
  const publicGrantContract = serviceProof.authority_contract.public_grant_contract;
  const publicSafeGrantSummary = serviceProof.authority_contract.public_safe_grant_summary;
  const acceptedCrossingEvidence = serviceProof.accepted_crossing_evidence;
  const boardedTargetBinding = boardedServiceTargetBindingSummary(
    serviceProof,
    serviceArtifactVerification
  );
  assertBoardedServiceTargetBinding(
    'Protected records installed runtime profile terminal chain generated boarded service target binding',
    boardedTargetBinding
  );
  return {
    proof_type: serviceProof.proof_type,
    artifact_body_sha256: protectedRecordsInstalledRuntimeProfileServiceProofArtifactBodySha256(
      serviceProof
    ),
    verification_body_sha256: serviceArtifactVerification.body_sha256,
    artifact_verification_verified: serviceArtifactVerification.verified,
    service_structural_self_integrity_verified:
      serviceArtifactVerification.structural_self_integrity_verified,
    service_artifact_identity_match_requires_expected_sha256:
      serviceArtifactVerification.artifact_identity_match_requires_expected_sha256,
    service_verification_scope: serviceArtifactVerification.verification_scope,
    expected_service_proof_artifact_body_sha256:
      serviceArtifactVerification.required_body_sha256,
    expected_service_proof_artifact_body_sha256_matched:
      serviceArtifactVerification.required_body_sha256_matched,
    source_preflight_body_sha256: serviceProof.source_preflight.body_sha256,
    recognition_contract_sha256: recognitionContractSha256,
    public_grant_contract: publicGrantContract,
    public_grant_contract_sha256: publicGrantContractSha256(publicGrantContract),
    public_safe_grant_summary: publicSafeGrantSummary,
    public_safe_grant_summary_sha256: sha256hex(canonicalize({
      public_safe_grant_summary: publicSafeGrantSummary,
    })),
    accepted_crossing_evidence_sha256:
      acceptedCrossingEvidenceSha256(acceptedCrossingEvidence),
    authority_grant_crossing_binding_sha256:
      acceptedCrossingEvidence.authority_grant_crossing_binding_sha256,
    signed_payload_sha256: acceptedCrossingEvidence.signed_payload_sha256,
    accepted_crossing_target_binding_sha256:
      acceptedCrossingEvidence.target_binding_sha256,
    accepted_crossing_authorized_effect_detail_sha256:
      acceptedCrossingEvidence.authorized_effect_detail_sha256,
    accepted_crossing_state_effect_binding_sha256:
      acceptedCrossingEvidence.state_effect_binding_sha256,
    ordered_transition_binding_type:
      serviceArtifactVerification.ordered_transition_binding_type,
    ordered_transition_binding_sha256:
      serviceArtifactVerification.ordered_transition_binding_sha256,
    boarded_service_target_binding: boardedTargetBinding,
    boarded_service_target_binding_sha256:
      boardedServiceTargetBindingSha256(boardedTargetBinding),
    runtime_service_started: serviceProof.service_boundary.runtime_service_started,
    disposable_runtime_config_written:
      serviceProof.service_boundary.disposable_runtime_config_written,
    persistent_runtime_config_written:
      serviceProof.service_boundary.persistent_runtime_config_written,
    recognition_rule_bound_to_selected_profile:
      serviceProof.service_config_provenance.recognition_rule_bound_to_selected_profile,
    recognized_write_boarded: serviceProof.recognized_boarding.boarded,
    recognized_write_state_append_count:
      serviceArtifactVerification.recognized_write_state_append_count,
    same_process_signed_payload_replay_refused:
      serviceArtifactVerification.same_process_signed_payload_replay_refused,
    restart_consumed_authority_grant_refused:
      serviceArtifactVerification.restart_consumed_authority_grant_refused,
    state_append_after_grant_commit_burn_observed:
      serviceArtifactVerification.state_append_after_grant_commit_burn_observed,
    metadata_partial_commit_burn_observed:
      serviceArtifactVerification.metadata_partial_commit_burn_observed,
    store_and_anchor_rollback_refused_while_witness_ahead:
      serviceArtifactVerification.store_and_anchor_rollback_refused_while_witness_ahead,
    store_anchor_and_witness_joint_rollback_detection:
      serviceArtifactVerification.store_anchor_and_witness_joint_rollback_detection,
    joint_rollback_reopened_authority_grant_reuse:
      serviceArtifactVerification.joint_rollback_reopened_authority_grant_reuse,
    recognition_refusal_case_count: serviceProof.refusal_cases.length,
    required_recognition_refusal_cases: requiredRecognitionRefusalCases,
    observed_recognition_refusal_cases: observedRecognitionRefusalCases,
    recognition_refusal_taxonomy_sha256:
      serviceArtifactVerification.recognition_refusal_taxonomy_sha256,
    all_recognition_refusals_before_mutation:
      serviceArtifactVerification.all_recognition_refusals_before_mutation,
    authority_refusal_case_count: serviceProof.authority_refusal_cases.length,
    required_authority_refusal_cases: requiredAuthorityRefusalCases,
    observed_authority_refusal_cases: observedAuthorityRefusalCases,
    authority_refusal_taxonomy_sha256:
      serviceArtifactVerification.authority_refusal_taxonomy_sha256,
    all_authority_refusals_before_consumption_and_mutation:
      serviceArtifactVerification.all_authority_refusals_before_consumption_and_mutation,
    named_receipt_refusals: namedReceiptRefusals,
    named_receipt_refusals_sha256: namedReceiptRefusalsSha256(namedReceiptRefusals),
    recognition_refusal_groups: recognitionRefusalGroups,
    recognition_refusal_groups_sha256:
      recognitionRefusalGroupsSha256(recognitionRefusalGroups),
    missing_receipt_refused: Boolean(
      serviceProof.refusal_cases.find((item) =>
        item.case_id === 'missing_receipt_refused_before_runtime_mutation' &&
        item.service_write_accepted === false &&
        item.state_entry_count_delta === 0
      )
    ),
    invalid_receipt_refused: Boolean(
      serviceProof.refusal_cases.find((item) =>
        item.case_id === 'invalid_receipt_refused_before_runtime_mutation' &&
        item.service_write_accepted === false &&
        item.state_entry_count_delta === 0
      )
    ),
    fixture_rightful_issuance_path_evidenced:
      serviceArtifactVerification.fixture_rightful_issuance_path_evidenced,
    rightful_issuance_proven: serviceArtifactVerification.rightful_issuance_proven,
    portable_rightful_issuance_proven:
      serviceArtifactVerification.portable_rightful_issuance_proven,
    production_rightful_issuance_proven:
      serviceArtifactVerification.production_rightful_issuance_proven,
    live_authority_proven: false,
    current_machine_governance_proven:
      serviceArtifactVerification.current_machine_governance_proven,
    production_downstream_recognition:
      serviceArtifactVerification.production_downstream_recognition,
    external_attestation: serviceArtifactVerification.external_attestation,
    consequence_lifecycle_closed:
      serviceArtifactVerification.consequence_lifecycle_closed,
  };
}

function terminalChainNestedArtifactBindingSummary(chain) {
  const nested = requireObject(
    'Protected records installed runtime profile terminal chain nested artifacts',
    chain.nested_artifacts
  );
  const nestedPreflightVerification =
    verifyProtectedRecordsInstalledRuntimeProfilePreflightArtifact(
      nested.generated_preflight_artifact
    );
  const nestedServiceStructuralVerification =
    verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(
      nested.generated_service_proof_artifact,
      {
        expectedArtifactBodySha256:
          chain.generated_service_proof.expected_service_proof_artifact_body_sha256,
      }
    );
  const nestedServiceVerification = bindRequiredBodySha256(
    nestedServiceStructuralVerification,
    chain.generated_service_proof.expected_service_proof_artifact_body_sha256,
    'Protected records installed runtime profile terminal chain nested service proof artifact'
  );
  return {
    generated_preflight_artifact_type:
      nested.generated_preflight_artifact.artifact_type,
    generated_service_proof_artifact_type:
      nested.generated_service_proof_artifact.artifact_type,
    generated_preflight_artifact_body_sha256:
      nestedPreflightVerification.body_sha256,
    generated_service_proof_artifact_body_sha256:
      nestedServiceVerification.body_sha256,
    generated_preflight_artifact_verified:
      nestedPreflightVerification.verified,
    generated_service_proof_artifact_verified:
      nestedServiceVerification.verified,
    generated_service_proof_structural_self_integrity_verified:
      nestedServiceVerification.structural_self_integrity_verified,
    generated_service_proof_artifact_identity_match_requires_expected_sha256:
      nestedServiceVerification.artifact_identity_match_requires_expected_sha256,
    generated_service_proof_verification_scope:
      nestedServiceVerification.verification_scope,
    expected_generated_service_proof_artifact_body_sha256:
      nestedServiceVerification.required_body_sha256,
    expected_generated_service_proof_artifact_body_sha256_matched:
      nestedServiceVerification.required_body_sha256_matched,
    preflight_artifact_hash_bound:
      nestedPreflightVerification.body_sha256 ===
        chain.generated_preflight.artifact_body_sha256,
    service_proof_source_preflight_hash_bound:
      nestedServiceVerification.source_preflight_body_sha256 ===
        chain.generated_preflight.artifact_body_sha256,
    service_artifact_hash_bound:
      nestedServiceVerification.body_sha256 ===
        chain.generated_service_proof.artifact_body_sha256,
    service_artifact_verification_bound_to_service_proof:
      nestedServiceVerification.body_sha256 ===
        chain.generated_service_proof.verification_body_sha256,
    creates_public_external_attestation: false,
    proves_non_operator_review: false,
    proves_current_machine_governance: false,
    proves_production_downstream_recognition: false,
  };
}

function assertTerminalChainNestedArtifactBindingSummary(label, value) {
  assertExactKeys(label, value, [
    'creates_public_external_attestation',
    'generated_preflight_artifact_body_sha256',
    'generated_preflight_artifact_type',
    'generated_preflight_artifact_verified',
    'generated_service_proof_artifact_body_sha256',
    'generated_service_proof_artifact_type',
    'generated_service_proof_artifact_verified',
    'generated_service_proof_structural_self_integrity_verified',
    'generated_service_proof_artifact_identity_match_requires_expected_sha256',
    'generated_service_proof_verification_scope',
    'preflight_artifact_hash_bound',
    'expected_generated_service_proof_artifact_body_sha256',
    'expected_generated_service_proof_artifact_body_sha256_matched',
    'proves_current_machine_governance',
    'proves_non_operator_review',
    'proves_production_downstream_recognition',
    'service_artifact_hash_bound',
    'service_artifact_verification_bound_to_service_proof',
    'service_proof_source_preflight_hash_bound',
  ]);
  if (
    typeof value.generated_preflight_artifact_type !== 'string' ||
    typeof value.generated_service_proof_artifact_type !== 'string' ||
    !/^[a-f0-9]{64}$/.test(value.generated_preflight_artifact_body_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(value.generated_service_proof_artifact_body_sha256 || '') ||
    value.generated_preflight_artifact_verified !== true ||
    value.generated_service_proof_artifact_verified !== true ||
    value.generated_service_proof_structural_self_integrity_verified !== true ||
    value.generated_service_proof_artifact_identity_match_requires_expected_sha256 !== true ||
    value.generated_service_proof_verification_scope !==
      'expected-artifact-identity-bound-local-fixture-projection' ||
    value.expected_generated_service_proof_artifact_body_sha256 !==
      value.generated_service_proof_artifact_body_sha256 ||
    value.expected_generated_service_proof_artifact_body_sha256_matched !== true ||
    value.preflight_artifact_hash_bound !== true ||
    value.service_proof_source_preflight_hash_bound !== true ||
    value.service_artifact_hash_bound !== true ||
    value.service_artifact_verification_bound_to_service_proof !== true ||
    value.creates_public_external_attestation !== false ||
    value.proves_non_operator_review !== false ||
    value.proves_current_machine_governance !== false ||
    value.proves_production_downstream_recognition !== false
  ) {
    throw new Error(`${label} drifted`);
  }
  return true;
}

function assertTerminalChainNestedArtifactBindingMatches(label, value, chain) {
  assertTerminalChainNestedArtifactBindingSummary(label, value);
  const expected = terminalChainNestedArtifactBindingSummary(chain);
  for (const key of Object.keys(expected)) {
    if (value[key] !== expected[key]) {
      throw new Error(`${label} drifted`);
    }
  }
  return true;
}

export function runProtectedRecordsInstalledRuntimeProfileTerminalChain(
  plan,
  profile,
  { serviceProofArtifact = null } = {},
) {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
    'Installed runtime-profile terminal-chain generation',
  );
  assertProtectedRecordsRuntimeProfileInstallationPlan(plan);
  assertProtectedRecordsRuntimePreflightProfile(profile);
  const profileSha = runtimeProfileSha256(profile);
  if (
    profile.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    plan.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    plan.runtime_profile_sha256 !== profileSha
  ) {
    throw new Error('Protected records installed runtime profile terminal chain plan/profile mismatch');
  }

  const selectedServiceArtifact =
    serviceProofArtifact ||
    readCommittedProtectedRecordsInstalledRuntimeProfileServiceProofArtifact();
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(
    selectedServiceArtifact,
  );
  const selectedServiceProof = selectedServiceArtifact.payload.proof;
  const selectedAuthorityGrantContractSha256 =
    selectedServiceProof.authority_contract.public_safe_grant_summary
      .authority_grant_contract_sha256;
  const selectedAuthorityGrantStatus = protectedRecordsFixtureAuthorityGrantStatus(
    selectedAuthorityGrantContractSha256,
  );
  if (selectedAuthorityGrantStatus.fresh_fixture_rightful_projection_allowed !== true) {
    const reason = protectedRecordsFixtureAuthorityGrantEffectStatusReason(
      selectedAuthorityGrantContractSha256,
    );
    throw new Error(
      `Protected records installed runtime profile terminal-chain fixture-rightful projection refused: ${reason.code}`,
    );
  }

  let install = null;
  try {
    install = installDisposableProfileRoot(plan, profile, profileSha);
    const preflight = runProtectedRecordsInstalledRuntimeProfilePreflight({
      installRoot: install.installRoot,
      expectedProfile: profile,
      profileId: profile.profile_id,
      profileSha256: profileSha,
    });
    const preflightArtifact = buildProtectedRecordsInstalledRuntimeProfilePreflightArtifact(
      preflight
    );
    const preflightVerification = verifyProtectedRecordsInstalledRuntimeProfilePreflightArtifact(
      preflightArtifact
    );
    const serviceArtifact = selectedServiceArtifact;
    const serviceProof = serviceArtifact.payload.proof;
    const serviceStructuralVerification =
      verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(
        serviceArtifact,
        {
          expectedArtifactBodySha256:
            PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_SAMPLE_ARTIFACT_BODY_SHA256,
        }
      );
    const serviceVerification = bindRequiredBodySha256(
      serviceStructuralVerification,
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_SAMPLE_ARTIFACT_BODY_SHA256,
      'Protected records installed runtime profile terminal chain generated service proof artifact'
    );
    if (
      serviceProof.source_preflight.body_sha256 !==
        preflightArtifact.integrity.body_sha256
    ) {
      throw new Error(
        'Protected records installed runtime profile terminal chain committed service-proof source preflight identity drifted',
      );
    }
    const serviceSummary = serviceProofSummary(serviceProof, serviceVerification);
    if (serviceVerification.body_sha256 !== serviceSummary.artifact_body_sha256) {
      throw new Error('Protected records installed runtime profile terminal chain service proof hash binding failed');
    }
    if (
      preflightVerification.recognition_contract_sha256 !==
        serviceSummary.recognition_contract_sha256 ||
      serviceVerification.recognition_contract_sha256 !==
        serviceSummary.recognition_contract_sha256
    ) {
      throw new Error('Protected records installed runtime profile terminal chain recognition contract digest binding failed');
    }
    const trustedIssuerRegistryRecognitionBinding =
      terminalChainTrustedIssuerRegistryRecognitionBinding({
        preflightArtifact,
        preflightVerification,
        serviceProof,
        serviceSummary,
        serviceVerification,
        profileSha,
      });
    const recognizedReceiptPathEvidence =
      terminalChainRecognizedReceiptPathEvidence(
        trustedIssuerRegistryRecognitionBinding,
        serviceSummary.boarded_service_target_binding,
        serviceSummary.boarded_service_target_binding_sha256
      );
    const deploymentProfileAuthorityRefusalMirror =
      buildDeploymentProfileAuthorityRefusalMirror({
        terminalRuntimeProfileSha256: profileSha,
      });

    const report = {
      chain_type: PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TYPE,
      evidence_model: 'fresh-local-disposable-installed-runtime-profile-terminal-chain',
      live_probing: false,
      safe_claim_ceiling: INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAFE_CLAIM_CEILING,
      plan: {
        plan_type: plan.plan_type,
        plan_id: plan.plan_id,
        deployment_posture: plan.deployment_posture,
        plan_sha256: runtimeProfileInstallationPlanSha256(plan),
      },
      runtime_profile: {
        profile_id: profile.profile_id,
        runtime_profile_id: profile.runtime_profile_id,
        profile_status: profile.profile_status,
        profile_sha256: profileSha,
        profile_sha_matches_plan: true,
      },
      disposable_installation: {
        ...install.summary,
        disposable_root_removed_after_run: true,
      },
      generated_preflight: {
        artifact_type: preflightArtifact.artifact_type,
        artifact_body_sha256: preflightArtifact.integrity.body_sha256,
        verification_type: preflightVerification.verification_type,
        verified: preflightVerification.verified,
        read_only: preflightVerification.read_only,
        profile_selected_from_install_root:
          preflightVerification.profile_selected_from_install_root,
        selected_by_explicit_id_and_sha:
          preflightVerification.selected_by_explicit_id_and_sha,
        selects_latest_profile: preflightVerification.selects_latest_profile,
        recognition_contract_preserved:
          preflightVerification.recognition_contract_preserved,
        recognition_contract_sha256:
          preflightVerification.recognition_contract_sha256,
        downstream_refusal_proven:
          preflightVerification.downstream_refusal_proven,
        current_machine_governance_proven:
          preflightVerification.current_machine_governance_proven,
      },
      generated_service_proof: serviceSummary,
      nested_artifacts: {
        generated_preflight_artifact: preflightArtifact,
        generated_service_proof_artifact: serviceArtifact,
      },
      terminal_chain: {
        sample_artifact_used: false,
        generated_installed_root_preflighted: true,
        generated_preflight_artifact_consumed_by_service_proof: true,
        generated_service_proof_artifact_verified: serviceVerification.verified,
        generated_service_proof_structural_self_integrity_verified:
          serviceSummary.service_structural_self_integrity_verified,
        generated_service_proof_artifact_identity_match_requires_expected_sha256:
          serviceSummary.service_artifact_identity_match_requires_expected_sha256,
        generated_service_proof_verification_scope:
          serviceSummary.service_verification_scope,
        expected_generated_service_proof_artifact_body_sha256:
          serviceSummary.expected_service_proof_artifact_body_sha256,
        expected_generated_service_proof_artifact_body_sha256_matched:
          serviceSummary.expected_service_proof_artifact_body_sha256_matched,
        service_proof_bound_to_generated_preflight:
          serviceProof.source_preflight.body_sha256 === preflightArtifact.integrity.body_sha256,
        service_artifact_verification_bound_to_service_proof:
          serviceVerification.body_sha256 ===
            protectedRecordsInstalledRuntimeProfileServiceProofArtifactBodySha256(serviceProof),
        recognized_write_boarded: serviceProof.recognized_boarding.boarded,
        missing_receipt_refused_before_mutation:
          serviceSummary.missing_receipt_refused,
        invalid_receipt_refused_before_mutation:
          serviceSummary.invalid_receipt_refused,
        required_recognition_refusal_case_count:
          REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
        observed_recognition_refusal_case_count: serviceProof.refusal_cases.length,
        all_required_recognition_refusals_before_mutation:
          serviceSummary.all_recognition_refusals_before_mutation,
        required_authority_refusal_case_count:
          REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length,
        observed_authority_refusal_case_count:
          serviceProof.authority_refusal_cases.length,
        all_required_authority_refusals_before_consumption_and_mutation:
          serviceSummary.all_authority_refusals_before_consumption_and_mutation,
        recognition_contract_sha256: serviceSummary.recognition_contract_sha256,
        public_grant_contract: serviceSummary.public_grant_contract,
        public_grant_contract_sha256: serviceSummary.public_grant_contract_sha256,
        public_safe_grant_summary: serviceSummary.public_safe_grant_summary,
        public_safe_grant_summary_sha256:
          serviceSummary.public_safe_grant_summary_sha256,
        ordered_transition_binding_type:
          serviceSummary.ordered_transition_binding_type,
        ordered_transition_binding_sha256:
          serviceSummary.ordered_transition_binding_sha256,
        accepted_crossing_evidence_sha256:
          serviceSummary.accepted_crossing_evidence_sha256,
        authority_grant_crossing_binding_sha256:
          serviceSummary.authority_grant_crossing_binding_sha256,
        signed_payload_sha256: serviceSummary.signed_payload_sha256,
        accepted_crossing_target_binding_sha256:
          serviceSummary.accepted_crossing_target_binding_sha256,
        accepted_crossing_authorized_effect_detail_sha256:
          serviceSummary.accepted_crossing_authorized_effect_detail_sha256,
        accepted_crossing_state_effect_binding_sha256:
          serviceSummary.accepted_crossing_state_effect_binding_sha256,
        boarded_service_target_binding:
          serviceSummary.boarded_service_target_binding,
        boarded_service_target_binding_sha256:
          serviceSummary.boarded_service_target_binding_sha256,
        recognition_refusal_taxonomy_sha256:
          serviceSummary.recognition_refusal_taxonomy_sha256,
        authority_refusal_taxonomy_sha256:
          serviceSummary.authority_refusal_taxonomy_sha256,
        named_receipt_refusals: serviceSummary.named_receipt_refusals,
        named_receipt_refusals_sha256:
          serviceSummary.named_receipt_refusals_sha256,
        recognition_refusal_groups: serviceSummary.recognition_refusal_groups,
        recognition_refusal_groups_sha256:
          serviceSummary.recognition_refusal_groups_sha256,
        deployment_profile_authority_refusal_mirror:
          deploymentProfileAuthorityRefusalMirror,
        trusted_issuer_registry_recognition_binding:
          trustedIssuerRegistryRecognitionBinding,
        trusted_issuer_registry_recognition_binding_sha256:
          trustedIssuerRegistryRecognitionBinding.binding_sha256,
        recognized_receipt_path_evidence: recognizedReceiptPathEvidence,
        recognized_receipt_path_evidence_sha256:
          terminalChainRecognizedReceiptPathEvidenceSha256(
            recognizedReceiptPathEvidence
          ),
        same_process_signed_payload_replay_refused:
          serviceSummary.same_process_signed_payload_replay_refused,
        restart_consumed_authority_grant_refused:
          serviceSummary.restart_consumed_authority_grant_refused,
        state_append_after_grant_commit_burn_observed:
          serviceSummary.state_append_after_grant_commit_burn_observed,
        metadata_partial_commit_burn_observed:
          serviceSummary.metadata_partial_commit_burn_observed,
        store_and_anchor_rollback_refused_while_witness_ahead:
          serviceSummary.store_and_anchor_rollback_refused_while_witness_ahead,
        store_anchor_and_witness_joint_rollback_detection:
          serviceSummary.store_anchor_and_witness_joint_rollback_detection,
        joint_rollback_reopened_authority_grant_reuse:
          serviceSummary.joint_rollback_reopened_authority_grant_reuse,
        fixture_rightful_issuance_path_evidenced:
          serviceSummary.fixture_rightful_issuance_path_evidenced,
        rightful_issuance_proven: false,
        portable_rightful_issuance_proven: false,
        production_rightful_issuance_proven: false,
        live_authority_proven: false,
        current_machine_governance_proven: false,
        consequence_lifecycle_closed: false,
      },
      side_door_report: {
        disposable_install_only: true,
        persistent_runtime_profile_installed: false,
        runtime_profile_activation_performed: false,
        disposable_runtime_config_written:
          serviceProof.service_boundary.disposable_runtime_config_written,
        persistent_runtime_config_written:
          serviceProof.service_boundary.persistent_runtime_config_written,
        hook_configuration_written: false,
        user_config_written: false,
        machine_config_written: false,
        latest_profile_selected: false,
        live_runtime_profile_checked: false,
        live_records_system_checked: false,
        production_records_service_checked: false,
        current_machine_governance_proven: false,
        live_mcp_coverage_checked: false,
        live_approval_channel_health_checked: false,
        exactly_once_effect_semantics: false,
        atomic_store_anchor_witness_commit: false,
        state_append_after_grant_commit_burn_observed:
          serviceProof.proof_boundary.state_append_after_grant_commit_burn_observed,
        metadata_partial_commit_burn_observed:
          serviceProof.proof_boundary.metadata_partial_commit_burn_observed,
        store_and_anchor_rollback_refused_while_witness_ahead:
          serviceProof.proof_boundary.store_and_anchor_rollback_refused_while_witness_ahead,
        store_anchor_and_witness_joint_rollback_detection:
          serviceProof.proof_boundary.store_anchor_and_witness_joint_rollback_detection,
        joint_rollback_reopened_authority_grant_reuse:
          serviceProof.proof_boundary.joint_rollback_reopened_authority_grant_reuse,
        host_filesystem_path_toctou_closed: false,
        fixture_rightful_issuance_path_evidenced: true,
        rightful_issuance_proven: false,
        portable_rightful_issuance_proven: false,
        production_rightful_issuance_proven: false,
        live_authority_proven: false,
        consequence_lifecycle_closed: false,
        host_process_or_memory_introspection_closed: false,
        external_attestation: false,
        sovereign_recognition: false,
        unrouted_records_paths_checked: false,
      },
      known_open_boundaries: [
        ...REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_OPEN_BOUNDARIES,
      ],
      non_claims: [...INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NON_CLAIMS],
    };
    report.terminal_chain.nested_artifact_binding =
      terminalChainNestedArtifactBindingSummary(report);
    assertProtectedRecordsInstalledRuntimeProfileTerminalChain(report);
    return report;
  } finally {
    if (install?.installRoot) {
      rmSync(install.installRoot, { recursive: true, force: true });
    }
  }
}

export function assertProtectedRecordsInstalledRuntimeProfileTerminalChain(report) {
  assertExactKeys('Protected records installed runtime profile terminal chain', report, [
    'chain_type',
    'disposable_installation',
    'evidence_model',
    'generated_preflight',
    'generated_service_proof',
    'known_open_boundaries',
    'live_probing',
    'nested_artifacts',
    'non_claims',
    'plan',
    'runtime_profile',
    'safe_claim_ceiling',
    'side_door_report',
    'terminal_chain',
  ]);
  if (
    report.chain_type !== PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TYPE ||
    report.evidence_model !== 'fresh-local-disposable-installed-runtime-profile-terminal-chain' ||
    report.live_probing !== false ||
    report.safe_claim_ceiling !== INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAFE_CLAIM_CEILING
  ) {
    throw new Error('Protected records installed runtime profile terminal chain top-level contract drifted');
  }

  assertExactKeys('Protected records installed runtime profile terminal chain plan', report.plan, [
    'deployment_posture',
    'plan_id',
    'plan_sha256',
    'plan_type',
  ]);
  if (
    report.plan.plan_id !== 'protected-records-runtime-profile-installation-fixture-plan' ||
    report.plan.deployment_posture !== 'local_disposable_profile_installation_only' ||
    !/^[a-f0-9]{64}$/.test(report.plan.plan_sha256 || '')
  ) {
    throw new Error('Protected records installed runtime profile terminal chain plan drifted');
  }

  assertExactKeys('Protected records installed runtime profile terminal chain profile', report.runtime_profile, [
    'profile_id',
    'profile_sha256',
    'profile_sha_matches_plan',
    'profile_status',
    'runtime_profile_id',
  ]);
  if (
    typeof report.runtime_profile.profile_id !== 'string' ||
    report.runtime_profile.profile_id.length < 3 ||
    report.runtime_profile.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    !/^[a-f0-9]{64}$/.test(report.runtime_profile.profile_sha256 || '') ||
    report.runtime_profile.profile_sha_matches_plan !== true
  ) {
    throw new Error('Protected records installed runtime profile terminal chain profile drifted');
  }

  assertExactKeys('Protected records installed runtime profile terminal chain installation', report.disposable_installation, [
    'active_index_path_in_report',
    'active_profile_index_written',
    'disposable_root_removed_after_run',
    'install_root_created',
    'install_root_kind',
    'install_root_path_in_report',
    'installed_profile_path_in_report',
    'profile_copy_written',
    'profile_selected_from_install_root',
    'selected_by_explicit_id_and_sha',
    'selected_profile_id',
    'selected_profile_sha256',
    'selected_runtime_profile_id',
    'selects_latest_profile',
  ]);
  if (
    report.disposable_installation.install_root_kind !== 'launcher-owned-disposable-proof-root' ||
    report.disposable_installation.install_root_path_in_report !== null ||
    report.disposable_installation.active_index_path_in_report !==
      '<launcher-owned-disposable-install-root>/active-runtime-profile.json' ||
    report.disposable_installation.installed_profile_path_in_report !==
      '<launcher-owned-disposable-install-root>/profiles/protected-records-disposable-runtime-profile.json' ||
    report.disposable_installation.install_root_created !== true ||
    report.disposable_installation.profile_copy_written !== true ||
    report.disposable_installation.active_profile_index_written !== true ||
    report.disposable_installation.profile_selected_from_install_root !== true ||
    report.disposable_installation.selected_by_explicit_id_and_sha !== true ||
    report.disposable_installation.selects_latest_profile !== false ||
    report.disposable_installation.disposable_root_removed_after_run !== true ||
    report.disposable_installation.selected_profile_id !== report.runtime_profile.profile_id ||
    report.disposable_installation.selected_runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    report.disposable_installation.selected_profile_sha256 !== report.runtime_profile.profile_sha256
  ) {
    throw new Error('Protected records installed runtime profile terminal chain installation drifted');
  }

  assertExactKeys('Protected records installed runtime profile terminal chain preflight', report.generated_preflight, [
    'artifact_body_sha256',
    'artifact_type',
    'current_machine_governance_proven',
    'downstream_refusal_proven',
    'profile_selected_from_install_root',
    'read_only',
    'recognition_contract_preserved',
    'recognition_contract_sha256',
    'selected_by_explicit_id_and_sha',
    'selects_latest_profile',
    'verification_type',
    'verified',
  ]);
  if (
    !/^[a-f0-9]{64}$/.test(report.generated_preflight.artifact_body_sha256 || '') ||
    report.generated_preflight.verified !== true ||
    report.generated_preflight.read_only !== true ||
    report.generated_preflight.profile_selected_from_install_root !== true ||
    report.generated_preflight.selected_by_explicit_id_and_sha !== true ||
    report.generated_preflight.selects_latest_profile !== false ||
    report.generated_preflight.recognition_contract_preserved !== true ||
    !/^[a-f0-9]{64}$/.test(report.generated_preflight.recognition_contract_sha256 || '') ||
    report.generated_preflight.downstream_refusal_proven !== false ||
    report.generated_preflight.current_machine_governance_proven !== false
  ) {
    throw new Error('Protected records installed runtime profile terminal chain preflight drifted');
  }

  assertExactKeys('Protected records installed runtime profile terminal chain service proof', report.generated_service_proof, [
    'accepted_crossing_authorized_effect_detail_sha256',
    'accepted_crossing_evidence_sha256',
    'accepted_crossing_state_effect_binding_sha256',
    'accepted_crossing_target_binding_sha256',
    'all_authority_refusals_before_consumption_and_mutation',
    'all_recognition_refusals_before_mutation',
    'artifact_body_sha256',
    'artifact_verification_verified',
    'authority_refusal_case_count',
    'authority_refusal_taxonomy_sha256',
    'authority_grant_crossing_binding_sha256',
    'boarded_service_target_binding',
    'boarded_service_target_binding_sha256',
    'consequence_lifecycle_closed',
    'current_machine_governance_proven',
    'disposable_runtime_config_written',
    'external_attestation',
    'expected_service_proof_artifact_body_sha256',
    'expected_service_proof_artifact_body_sha256_matched',
    'fixture_rightful_issuance_path_evidenced',
    'invalid_receipt_refused',
    'joint_rollback_reopened_authority_grant_reuse',
    'live_authority_proven',
    'metadata_partial_commit_burn_observed',
    'missing_receipt_refused',
    'named_receipt_refusals',
    'named_receipt_refusals_sha256',
    'observed_authority_refusal_cases',
    'observed_recognition_refusal_cases',
    'ordered_transition_binding_sha256',
    'ordered_transition_binding_type',
    'persistent_runtime_config_written',
    'portable_rightful_issuance_proven',
    'production_downstream_recognition',
    'production_rightful_issuance_proven',
    'proof_type',
    'public_grant_contract',
    'public_grant_contract_sha256',
    'public_safe_grant_summary',
    'public_safe_grant_summary_sha256',
    'recognition_contract_sha256',
    'recognition_refusal_case_count',
    'recognition_refusal_groups',
    'recognition_refusal_groups_sha256',
    'recognition_refusal_taxonomy_sha256',
    'recognition_rule_bound_to_selected_profile',
    'recognized_write_boarded',
    'recognized_write_state_append_count',
    'required_authority_refusal_cases',
    'required_recognition_refusal_cases',
    'restart_consumed_authority_grant_refused',
    'rightful_issuance_proven',
    'runtime_service_started',
    'same_process_signed_payload_replay_refused',
    'service_artifact_identity_match_requires_expected_sha256',
    'service_structural_self_integrity_verified',
    'service_verification_scope',
    'signed_payload_sha256',
    'source_preflight_body_sha256',
    'state_append_after_grant_commit_burn_observed',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_and_anchor_rollback_refused_while_witness_ahead',
    'verification_body_sha256',
  ]);
  if (
    !/^[a-f0-9]{64}$/.test(report.generated_service_proof.artifact_body_sha256 || '') ||
    report.generated_service_proof.artifact_body_sha256 !==
      report.generated_service_proof.verification_body_sha256 ||
    report.generated_service_proof.service_structural_self_integrity_verified !== true ||
    report.generated_service_proof.service_artifact_identity_match_requires_expected_sha256 !== true ||
    report.generated_service_proof.service_verification_scope !==
      'expected-artifact-identity-bound-local-fixture-projection' ||
    report.generated_service_proof.expected_service_proof_artifact_body_sha256 !==
      report.generated_service_proof.artifact_body_sha256 ||
    report.generated_service_proof.expected_service_proof_artifact_body_sha256_matched !== true ||
    report.generated_service_proof.source_preflight_body_sha256 !==
      report.generated_preflight.artifact_body_sha256 ||
    report.generated_service_proof.recognition_contract_sha256 !==
      report.generated_preflight.recognition_contract_sha256 ||
    !assertTerminalChainPublicSafeGrantSummary(
      'Protected records installed runtime profile terminal chain public-safe grant summary',
      report.generated_service_proof.public_safe_grant_summary
    ) ||
    publicGrantContractSha256(
      report.generated_service_proof.public_grant_contract
    ) !== report.generated_service_proof.public_grant_contract_sha256 ||
    report.generated_service_proof.public_grant_contract_sha256 !==
      report.generated_service_proof.public_safe_grant_summary
        .authority_grant_contract_sha256 ||
    canonicalize(
      report.generated_service_proof.public_grant_contract.powers.map(
        (power) => power.power_id
      )
    ) !== canonicalize(
      REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_FIXTURE_AUTHORITY_POWER_IDS
    ) ||
    report.generated_service_proof.public_safe_grant_summary_sha256 !==
      publicSafeGrantSummarySha256(
        report.generated_service_proof.public_safe_grant_summary
      ) ||
    report.generated_service_proof.ordered_transition_binding_type !==
      'protected-records-runtime-ordered-single-lock-transition-binding-v1' ||
    !/^[a-f0-9]{64}$/.test(
      report.generated_service_proof.ordered_transition_binding_sha256 || ''
    ) ||
    !assertBoardedServiceTargetBinding(
      'Protected records installed runtime profile terminal chain generated service boarded target binding',
      report.generated_service_proof.boarded_service_target_binding
    ) ||
    report.generated_service_proof.boarded_service_target_binding_sha256 !==
      boardedServiceTargetBindingSha256(
        report.generated_service_proof.boarded_service_target_binding
      ) ||
    !/^[a-f0-9]{64}$/.test(
      report.generated_service_proof.accepted_crossing_evidence_sha256 || ''
    ) ||
    report.generated_service_proof.accepted_crossing_target_binding_sha256 !==
      report.generated_service_proof.boarded_service_target_binding
        .launcher_target_binding_sha256 ||
    report.generated_service_proof.accepted_crossing_authorized_effect_detail_sha256 !==
      report.generated_service_proof.boarded_service_target_binding
        .authorized_effect_detail_sha256 ||
    report.generated_service_proof.accepted_crossing_state_effect_binding_sha256 !==
      report.generated_service_proof.boarded_service_target_binding
        .state_effect_binding_sha256 ||
    !/^[a-f0-9]{64}$/.test(
      report.generated_service_proof.authority_grant_crossing_binding_sha256 || ''
    ) ||
    !/^[a-f0-9]{64}$/.test(
      report.generated_service_proof.signed_payload_sha256 || ''
    ) ||
    report.generated_service_proof.boarded_service_target_binding
      .source_profile_sha256 !== report.runtime_profile.profile_sha256 ||
    report.generated_service_proof.boarded_service_target_binding
      .source_preflight_body_sha256 !==
      report.generated_preflight.artifact_body_sha256 ||
    report.generated_service_proof.boarded_service_target_binding
      .source_recognition_contract_sha256 !==
      report.generated_preflight.recognition_contract_sha256 ||
    report.generated_service_proof.boarded_service_target_binding
      .generated_service_proof_artifact_body_sha256 !==
      report.generated_service_proof.artifact_body_sha256 ||
    report.generated_service_proof.artifact_verification_verified !== true ||
    report.generated_service_proof.runtime_service_started !== true ||
    report.generated_service_proof.disposable_runtime_config_written !== true ||
    report.generated_service_proof.persistent_runtime_config_written !== false ||
    report.generated_service_proof.recognition_rule_bound_to_selected_profile !== true ||
    report.generated_service_proof.recognized_write_boarded !== true ||
    report.generated_service_proof.recognized_write_state_append_count !== 1 ||
    report.generated_service_proof.same_process_signed_payload_replay_refused !== true ||
    report.generated_service_proof.restart_consumed_authority_grant_refused !== true ||
    report.generated_service_proof.state_append_after_grant_commit_burn_observed !== true ||
    report.generated_service_proof.metadata_partial_commit_burn_observed !== true ||
    report.generated_service_proof.store_and_anchor_rollback_refused_while_witness_ahead !== true ||
    report.generated_service_proof.store_anchor_and_witness_joint_rollback_detection !== false ||
    report.generated_service_proof.joint_rollback_reopened_authority_grant_reuse !== true ||
    report.generated_service_proof.recognition_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length ||
    !assertInstalledRuntimeProfileTerminalChainRefusalTaxonomy(
      'Protected records installed runtime profile terminal chain service proof recognition refusal taxonomy',
      {
        required_refusal_cases:
          report.generated_service_proof.required_recognition_refusal_cases,
        observed_refusal_cases:
          report.generated_service_proof.observed_recognition_refusal_cases,
        refusal_taxonomy_sha256:
          report.generated_service_proof.recognition_refusal_taxonomy_sha256,
      }
    ) ||
    report.generated_service_proof.authority_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length ||
    !assertInstalledRuntimeProfileTerminalChainAuthorityRefusalTaxonomy(
      'Protected records installed runtime profile terminal chain service proof authority refusal taxonomy',
      {
        required_refusal_cases:
          report.generated_service_proof.required_authority_refusal_cases,
        observed_refusal_cases:
          report.generated_service_proof.observed_authority_refusal_cases,
        refusal_taxonomy_sha256:
          report.generated_service_proof.authority_refusal_taxonomy_sha256,
      }
    ) ||
    !assertNamedReceiptRefusals(
      'Protected records installed runtime profile terminal chain service proof named receipt refusals',
      report.generated_service_proof.named_receipt_refusals
    ) ||
    report.generated_service_proof.named_receipt_refusals_sha256 !==
      namedReceiptRefusalsSha256(report.generated_service_proof.named_receipt_refusals) ||
    !assertRecognitionRefusalGroups(
      'Protected records installed runtime profile terminal chain service proof recognition refusal groups',
      report.generated_service_proof.recognition_refusal_groups
    ) ||
    report.generated_service_proof.recognition_refusal_groups_sha256 !==
      recognitionRefusalGroupsSha256(report.generated_service_proof.recognition_refusal_groups) ||
    report.generated_service_proof.all_recognition_refusals_before_mutation !== true ||
    report.generated_service_proof.all_authority_refusals_before_consumption_and_mutation !== true ||
    report.generated_service_proof.missing_receipt_refused !== true ||
    report.generated_service_proof.invalid_receipt_refused !== true ||
    report.generated_service_proof.fixture_rightful_issuance_path_evidenced !== true ||
    report.generated_service_proof.rightful_issuance_proven !== false ||
    report.generated_service_proof.portable_rightful_issuance_proven !== false ||
    report.generated_service_proof.production_rightful_issuance_proven !== false ||
    report.generated_service_proof.live_authority_proven !== false ||
    report.generated_service_proof.current_machine_governance_proven !== false ||
    report.generated_service_proof.production_downstream_recognition !== false ||
    report.generated_service_proof.external_attestation !== false ||
    report.generated_service_proof.consequence_lifecycle_closed !== false
  ) {
    throw new Error('Protected records installed runtime profile terminal chain service proof drifted');
  }

  assertExactKeys('Protected records installed runtime profile terminal chain nested artifacts', report.nested_artifacts, [
    'generated_preflight_artifact',
    'generated_service_proof_artifact',
  ]);
  const nestedPreflightVerification =
    verifyProtectedRecordsInstalledRuntimeProfilePreflightArtifact(
      report.nested_artifacts.generated_preflight_artifact
    );
  const nestedServiceStructuralVerification =
    verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(
      report.nested_artifacts.generated_service_proof_artifact,
      {
        expectedArtifactBodySha256:
          report.generated_service_proof.expected_service_proof_artifact_body_sha256,
      }
    );
  const nestedServiceVerification = bindRequiredBodySha256(
    nestedServiceStructuralVerification,
    report.generated_service_proof.expected_service_proof_artifact_body_sha256,
    'Protected records installed runtime profile terminal chain nested service proof artifact'
  );
  const nestedServiceProof =
    report.nested_artifacts.generated_service_proof_artifact.payload.proof;
  if (
    nestedPreflightVerification.body_sha256 !==
      report.generated_preflight.artifact_body_sha256 ||
    nestedPreflightVerification.verified !== report.generated_preflight.verified ||
    nestedPreflightVerification.read_only !== report.generated_preflight.read_only ||
    nestedPreflightVerification.profile_selected_from_install_root !==
      report.generated_preflight.profile_selected_from_install_root ||
    nestedPreflightVerification.selected_by_explicit_id_and_sha !==
      report.generated_preflight.selected_by_explicit_id_and_sha ||
    nestedPreflightVerification.selects_latest_profile !==
      report.generated_preflight.selects_latest_profile ||
    nestedPreflightVerification.recognition_contract_preserved !==
      report.generated_preflight.recognition_contract_preserved ||
    nestedPreflightVerification.recognition_contract_sha256 !==
      report.generated_preflight.recognition_contract_sha256 ||
    nestedPreflightVerification.downstream_refusal_proven !==
      report.generated_preflight.downstream_refusal_proven ||
    nestedPreflightVerification.current_machine_governance_proven !==
      report.generated_preflight.current_machine_governance_proven
  ) {
    throw new Error('Protected records installed runtime profile terminal chain nested preflight artifact binding drifted');
  }
  if (
    nestedServiceVerification.body_sha256 !==
      report.generated_service_proof.artifact_body_sha256 ||
    nestedServiceVerification.body_sha256 !==
      report.generated_service_proof.verification_body_sha256 ||
    nestedServiceVerification.structural_self_integrity_verified !==
      report.generated_service_proof.service_structural_self_integrity_verified ||
    nestedServiceVerification.artifact_identity_match_requires_expected_sha256 !==
      report.generated_service_proof
        .service_artifact_identity_match_requires_expected_sha256 ||
    nestedServiceVerification.verification_scope !==
      report.generated_service_proof.service_verification_scope ||
    nestedServiceVerification.required_body_sha256 !==
      report.generated_service_proof.expected_service_proof_artifact_body_sha256 ||
    nestedServiceVerification.required_body_sha256_matched !==
      report.generated_service_proof
        .expected_service_proof_artifact_body_sha256_matched ||
    nestedServiceVerification.source_preflight_body_sha256 !==
      report.generated_service_proof.source_preflight_body_sha256 ||
    nestedServiceVerification.source_preflight_body_sha256 !==
      report.generated_preflight.artifact_body_sha256 ||
    nestedServiceVerification.recognition_contract_sha256 !==
      report.generated_service_proof.recognition_contract_sha256 ||
    nestedServiceVerification.recognition_contract_sha256 !==
      report.generated_preflight.recognition_contract_sha256 ||
    nestedServiceVerification.target_handle !==
      report.generated_service_proof.boarded_service_target_binding.target_handle ||
    nestedServiceVerification.target_binding_sha256 !==
      report.generated_service_proof.boarded_service_target_binding
        .launcher_target_binding_sha256 ||
    nestedServiceVerification.target_effect_sha256 !==
      report.generated_service_proof.boarded_service_target_binding
        .target_effect_sha256 ||
    nestedServiceVerification.authorized_effect_detail_sha256 !==
      report.generated_service_proof.boarded_service_target_binding
        .boarded_service_receipt_detail_sha256 ||
    nestedServiceVerification.state_effect_binding_sha256 !==
      report.generated_service_proof.boarded_service_target_binding
        .state_effect_binding_sha256 ||
    nestedServiceVerification.selected_profile_sha256 !==
      report.generated_service_proof.boarded_service_target_binding
        .source_profile_sha256 ||
    nestedServiceVerification.source_preflight_body_sha256 !==
      report.generated_service_proof.boarded_service_target_binding
        .source_preflight_body_sha256 ||
    nestedServiceVerification.recognition_contract_sha256 !==
      report.generated_service_proof.boarded_service_target_binding
        .source_recognition_contract_sha256 ||
    nestedServiceVerification.target_contract_sha256 !==
      report.generated_service_proof.boarded_service_target_binding
        .source_target_contract_sha256 ||
    nestedServiceVerification.body_sha256 !==
      report.generated_service_proof.boarded_service_target_binding
        .generated_service_proof_artifact_body_sha256 ||
    canonicalize(nestedServiceProof.authority_contract.public_safe_grant_summary) !==
      canonicalize(report.generated_service_proof.public_safe_grant_summary) ||
    canonicalize(nestedServiceProof.authority_contract.public_grant_contract) !==
      canonicalize(report.generated_service_proof.public_grant_contract) ||
    publicGrantContractSha256(
      nestedServiceProof.authority_contract.public_grant_contract
    ) !== report.generated_service_proof.public_grant_contract_sha256 ||
    acceptedCrossingEvidenceSha256(nestedServiceProof.accepted_crossing_evidence) !==
      report.generated_service_proof.accepted_crossing_evidence_sha256 ||
    nestedServiceProof.accepted_crossing_evidence
      .authority_grant_crossing_binding_sha256 !==
      report.generated_service_proof.authority_grant_crossing_binding_sha256 ||
    nestedServiceProof.accepted_crossing_evidence.signed_payload_sha256 !==
      report.generated_service_proof.signed_payload_sha256 ||
    nestedServiceProof.accepted_crossing_evidence.target_binding_sha256 !==
      report.generated_service_proof.accepted_crossing_target_binding_sha256 ||
    nestedServiceProof.accepted_crossing_evidence.authorized_effect_detail_sha256 !==
      report.generated_service_proof
        .accepted_crossing_authorized_effect_detail_sha256 ||
    nestedServiceProof.accepted_crossing_evidence.state_effect_binding_sha256 !==
      report.generated_service_proof.accepted_crossing_state_effect_binding_sha256 ||
    nestedServiceVerification.authority_grant_contract_sha256 !==
      report.generated_service_proof.public_safe_grant_summary
        .authority_grant_contract_sha256 ||
    nestedServiceVerification.authority_domain_id !==
      report.generated_service_proof.public_safe_grant_summary.authority_domain_id ||
    nestedServiceVerification.grantor_role_id !==
      report.generated_service_proof.public_safe_grant_summary.grantor_role_id ||
    nestedServiceVerification.ordered_transition_binding_type !==
      report.generated_service_proof.ordered_transition_binding_type ||
    nestedServiceVerification.ordered_transition_binding_sha256 !==
      report.generated_service_proof.ordered_transition_binding_sha256 ||
    nestedPreflightVerification.target_contract_sha256 !==
      report.generated_service_proof.boarded_service_target_binding
        .source_target_contract_sha256 ||
    nestedPreflightVerification.target_handle !==
      report.generated_service_proof.boarded_service_target_binding.target_handle ||
    nestedServiceVerification.recognized_write_boarded !==
      report.generated_service_proof.recognized_write_boarded ||
    nestedServiceVerification.recognized_write_state_append_count !==
      report.generated_service_proof.recognized_write_state_append_count ||
    nestedServiceVerification.same_process_signed_payload_replay_refused !==
      report.generated_service_proof.same_process_signed_payload_replay_refused ||
    nestedServiceVerification.restart_consumed_authority_grant_refused !==
      report.generated_service_proof.restart_consumed_authority_grant_refused ||
    nestedServiceVerification.state_append_after_grant_commit_burn_observed !==
      report.generated_service_proof.state_append_after_grant_commit_burn_observed ||
    nestedServiceVerification.metadata_partial_commit_burn_observed !==
      report.generated_service_proof.metadata_partial_commit_burn_observed ||
    nestedServiceVerification.store_and_anchor_rollback_refused_while_witness_ahead !==
      report.generated_service_proof.store_and_anchor_rollback_refused_while_witness_ahead ||
    nestedServiceVerification.store_anchor_and_witness_joint_rollback_detection !==
      report.generated_service_proof.store_anchor_and_witness_joint_rollback_detection ||
    nestedServiceVerification.joint_rollback_reopened_authority_grant_reuse !==
      report.generated_service_proof.joint_rollback_reopened_authority_grant_reuse ||
    nestedServiceVerification.recognition_refusal_case_count !==
      report.generated_service_proof.recognition_refusal_case_count ||
    canonicalize(nestedServiceVerification.required_recognition_refusal_cases) !==
      canonicalize(report.generated_service_proof.required_recognition_refusal_cases) ||
    nestedServiceVerification.recognition_refusal_taxonomy_sha256 !==
      report.generated_service_proof.recognition_refusal_taxonomy_sha256 ||
    nestedServiceVerification.all_recognition_refusals_before_mutation !==
      report.generated_service_proof.all_recognition_refusals_before_mutation ||
    nestedServiceVerification.authority_refusal_case_count !==
      report.generated_service_proof.authority_refusal_case_count ||
    canonicalize(nestedServiceVerification.required_authority_refusal_cases) !==
      canonicalize(report.generated_service_proof.required_authority_refusal_cases) ||
    nestedServiceVerification.authority_refusal_taxonomy_sha256 !==
      report.generated_service_proof.authority_refusal_taxonomy_sha256 ||
    nestedServiceVerification.all_authority_refusals_before_consumption_and_mutation !==
      report.generated_service_proof
        .all_authority_refusals_before_consumption_and_mutation ||
    nestedServiceVerification.fixture_rightful_issuance_path_evidenced !==
      (report.generated_service_proof.fixture_rightful_issuance_path_evidenced &&
        nestedServiceVerification
          .authority_grant_status_allows_fixture_rightful_projection) ||
    nestedServiceVerification.rightful_issuance_proven !==
      report.generated_service_proof.rightful_issuance_proven ||
    nestedServiceVerification.portable_rightful_issuance_proven !==
      report.generated_service_proof.portable_rightful_issuance_proven ||
    nestedServiceVerification.production_rightful_issuance_proven !==
      report.generated_service_proof.production_rightful_issuance_proven ||
    nestedServiceVerification.current_machine_governance_proven !==
      report.generated_service_proof.current_machine_governance_proven ||
    nestedServiceVerification.production_downstream_recognition !==
      report.generated_service_proof.production_downstream_recognition ||
    nestedServiceVerification.external_attestation !==
      report.generated_service_proof.external_attestation ||
    nestedServiceVerification.consequence_lifecycle_closed !==
      report.generated_service_proof.consequence_lifecycle_closed
  ) {
    throw new Error('Protected records installed runtime profile terminal chain nested service proof artifact binding drifted');
  }

  assertExactKeys('Protected records installed runtime profile terminal chain binding', report.terminal_chain, [
    'accepted_crossing_authorized_effect_detail_sha256',
    'accepted_crossing_evidence_sha256',
    'accepted_crossing_state_effect_binding_sha256',
    'accepted_crossing_target_binding_sha256',
    'all_required_authority_refusals_before_consumption_and_mutation',
    'all_required_recognition_refusals_before_mutation',
    'authority_refusal_taxonomy_sha256',
    'authority_grant_crossing_binding_sha256',
    'boarded_service_target_binding',
    'boarded_service_target_binding_sha256',
    'consequence_lifecycle_closed',
    'current_machine_governance_proven',
    'deployment_profile_authority_refusal_mirror',
    'generated_installed_root_preflighted',
    'generated_preflight_artifact_consumed_by_service_proof',
    'generated_service_proof_artifact_verified',
    'generated_service_proof_artifact_identity_match_requires_expected_sha256',
    'generated_service_proof_structural_self_integrity_verified',
    'generated_service_proof_verification_scope',
    'expected_generated_service_proof_artifact_body_sha256',
    'expected_generated_service_proof_artifact_body_sha256_matched',
    'invalid_receipt_refused_before_mutation',
    'joint_rollback_reopened_authority_grant_reuse',
    'live_authority_proven',
    'metadata_partial_commit_burn_observed',
    'missing_receipt_refused_before_mutation',
    'named_receipt_refusals',
    'named_receipt_refusals_sha256',
    'nested_artifact_binding',
    'observed_authority_refusal_case_count',
    'observed_recognition_refusal_case_count',
    'ordered_transition_binding_sha256',
    'ordered_transition_binding_type',
    'portable_rightful_issuance_proven',
    'production_rightful_issuance_proven',
    'public_safe_grant_summary',
    'public_safe_grant_summary_sha256',
    'public_grant_contract',
    'public_grant_contract_sha256',
    'recognized_receipt_path_evidence',
    'recognized_receipt_path_evidence_sha256',
    'recognition_refusal_groups',
    'recognition_refusal_groups_sha256',
    'recognition_refusal_taxonomy_sha256',
    'recognition_contract_sha256',
    'recognized_write_boarded',
    'required_authority_refusal_case_count',
    'required_recognition_refusal_case_count',
    'restart_consumed_authority_grant_refused',
    'rightful_issuance_proven',
    'sample_artifact_used',
    'service_artifact_verification_bound_to_service_proof',
    'service_proof_bound_to_generated_preflight',
    'same_process_signed_payload_replay_refused',
    'signed_payload_sha256',
    'state_append_after_grant_commit_burn_observed',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_and_anchor_rollback_refused_while_witness_ahead',
    'trusted_issuer_registry_recognition_binding',
    'trusted_issuer_registry_recognition_binding_sha256',
    'fixture_rightful_issuance_path_evidenced',
  ]);
  if (
    report.terminal_chain.sample_artifact_used !== false ||
    report.terminal_chain.generated_installed_root_preflighted !== true ||
    report.terminal_chain.generated_preflight_artifact_consumed_by_service_proof !== true ||
    report.terminal_chain.generated_service_proof_artifact_verified !== true ||
    report.terminal_chain.generated_service_proof_structural_self_integrity_verified !== true ||
    report.terminal_chain.generated_service_proof_artifact_identity_match_requires_expected_sha256 !== true ||
    report.terminal_chain.generated_service_proof_verification_scope !==
      'expected-artifact-identity-bound-local-fixture-projection' ||
    report.terminal_chain.expected_generated_service_proof_artifact_body_sha256 !==
      report.generated_service_proof.artifact_body_sha256 ||
    report.terminal_chain.expected_generated_service_proof_artifact_body_sha256_matched !== true ||
    report.terminal_chain.service_proof_bound_to_generated_preflight !== true ||
    report.terminal_chain.service_artifact_verification_bound_to_service_proof !== true ||
    report.terminal_chain.recognized_write_boarded !== true ||
    report.terminal_chain.missing_receipt_refused_before_mutation !== true ||
    report.terminal_chain.invalid_receipt_refused_before_mutation !== true ||
    report.terminal_chain.required_recognition_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length ||
    report.terminal_chain.observed_recognition_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length ||
    report.terminal_chain.all_required_recognition_refusals_before_mutation !== true ||
    report.terminal_chain.required_authority_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length ||
    report.terminal_chain.observed_authority_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length ||
    report.terminal_chain.all_required_authority_refusals_before_consumption_and_mutation !== true ||
    report.terminal_chain.recognition_contract_sha256 !==
      report.generated_service_proof.recognition_contract_sha256 ||
    !assertBoardedServiceTargetBinding(
      'Protected records installed runtime profile terminal chain boarded target binding',
      report.terminal_chain.boarded_service_target_binding
    ) ||
    canonicalize(report.terminal_chain.boarded_service_target_binding) !==
      canonicalize(report.generated_service_proof.boarded_service_target_binding) ||
    report.terminal_chain.boarded_service_target_binding_sha256 !==
      report.generated_service_proof.boarded_service_target_binding_sha256 ||
    report.terminal_chain.boarded_service_target_binding_sha256 !==
      boardedServiceTargetBindingSha256(
        report.terminal_chain.boarded_service_target_binding
      ) ||
    canonicalize(report.terminal_chain.public_safe_grant_summary) !==
      canonicalize(report.generated_service_proof.public_safe_grant_summary) ||
    canonicalize(report.terminal_chain.public_grant_contract) !==
      canonicalize(report.generated_service_proof.public_grant_contract) ||
    report.terminal_chain.public_grant_contract_sha256 !==
      report.generated_service_proof.public_grant_contract_sha256 ||
    report.terminal_chain.public_grant_contract_sha256 !==
      publicGrantContractSha256(report.terminal_chain.public_grant_contract) ||
    report.terminal_chain.public_safe_grant_summary_sha256 !==
      report.generated_service_proof.public_safe_grant_summary_sha256 ||
    report.terminal_chain.public_safe_grant_summary_sha256 !==
      publicSafeGrantSummarySha256(report.terminal_chain.public_safe_grant_summary) ||
    report.terminal_chain.ordered_transition_binding_type !==
      report.generated_service_proof.ordered_transition_binding_type ||
    report.terminal_chain.ordered_transition_binding_sha256 !==
      report.generated_service_proof.ordered_transition_binding_sha256 ||
    report.terminal_chain.accepted_crossing_evidence_sha256 !==
      report.generated_service_proof.accepted_crossing_evidence_sha256 ||
    report.terminal_chain.authority_grant_crossing_binding_sha256 !==
      report.generated_service_proof.authority_grant_crossing_binding_sha256 ||
    report.terminal_chain.signed_payload_sha256 !==
      report.generated_service_proof.signed_payload_sha256 ||
    report.terminal_chain.accepted_crossing_target_binding_sha256 !==
      report.generated_service_proof.accepted_crossing_target_binding_sha256 ||
    report.terminal_chain.accepted_crossing_authorized_effect_detail_sha256 !==
      report.generated_service_proof.accepted_crossing_authorized_effect_detail_sha256 ||
    report.terminal_chain.accepted_crossing_state_effect_binding_sha256 !==
      report.generated_service_proof.accepted_crossing_state_effect_binding_sha256 ||
    report.terminal_chain.recognition_refusal_taxonomy_sha256 !==
      report.generated_service_proof.recognition_refusal_taxonomy_sha256 ||
    report.terminal_chain.authority_refusal_taxonomy_sha256 !==
      report.generated_service_proof.authority_refusal_taxonomy_sha256 ||
    report.terminal_chain.named_receipt_refusals_sha256 !==
      report.generated_service_proof.named_receipt_refusals_sha256 ||
    !assertNamedReceiptRefusals(
      'Protected records installed runtime profile terminal chain binding named receipt refusals',
      report.terminal_chain.named_receipt_refusals
    ) ||
    report.terminal_chain.named_receipt_refusals_sha256 !==
      namedReceiptRefusalsSha256(report.terminal_chain.named_receipt_refusals) ||
    report.terminal_chain.named_receipt_refusals_sha256 !==
      namedReceiptRefusalsSha256(report.generated_service_proof.named_receipt_refusals) ||
    report.terminal_chain.recognition_refusal_groups_sha256 !==
      report.generated_service_proof.recognition_refusal_groups_sha256 ||
    !assertRecognitionRefusalGroups(
      'Protected records installed runtime profile terminal chain binding recognition refusal groups',
      report.terminal_chain.recognition_refusal_groups
    ) ||
    report.terminal_chain.recognition_refusal_groups_sha256 !==
      recognitionRefusalGroupsSha256(report.terminal_chain.recognition_refusal_groups) ||
    report.terminal_chain.recognition_refusal_groups_sha256 !==
      recognitionRefusalGroupsSha256(report.generated_service_proof.recognition_refusal_groups) ||
    !assertDeploymentProfileAuthorityRefusalMirror(
      'Protected records installed runtime profile terminal chain deployment-profile authority refusal mirror',
      report.terminal_chain.deployment_profile_authority_refusal_mirror,
      report.runtime_profile.profile_sha256
    ) ||
    !assertTerminalChainTrustedIssuerRegistryRecognitionBinding(
      'Protected records installed runtime profile terminal chain binding trusted issuer registry recognition',
      report.terminal_chain.trusted_issuer_registry_recognition_binding,
      report
    ) ||
    report.terminal_chain.trusted_issuer_registry_recognition_binding_sha256 !==
      report.terminal_chain.trusted_issuer_registry_recognition_binding.binding_sha256 ||
    !assertTerminalChainRecognizedReceiptPathEvidence(
      'Protected records installed runtime profile terminal chain recognized receipt path',
      report.terminal_chain.recognized_receipt_path_evidence,
      report.terminal_chain.trusted_issuer_registry_recognition_binding,
      report.terminal_chain.boarded_service_target_binding,
      report.terminal_chain.boarded_service_target_binding_sha256
    ) ||
    report.terminal_chain.recognized_receipt_path_evidence_sha256 !==
      terminalChainRecognizedReceiptPathEvidenceSha256(
        report.terminal_chain.recognized_receipt_path_evidence
      ) ||
    !assertTerminalChainNestedArtifactBindingMatches(
      'Protected records installed runtime profile terminal chain binding nested artifact binding',
      report.terminal_chain.nested_artifact_binding,
      report
    ) ||
    report.terminal_chain.same_process_signed_payload_replay_refused !== true ||
    report.terminal_chain.restart_consumed_authority_grant_refused !== true ||
    report.terminal_chain.state_append_after_grant_commit_burn_observed !== true ||
    report.terminal_chain.metadata_partial_commit_burn_observed !== true ||
    report.terminal_chain.store_and_anchor_rollback_refused_while_witness_ahead !== true ||
    report.terminal_chain.store_anchor_and_witness_joint_rollback_detection !== false ||
    report.terminal_chain.joint_rollback_reopened_authority_grant_reuse !== true ||
    report.terminal_chain.fixture_rightful_issuance_path_evidenced !== true ||
    report.terminal_chain.rightful_issuance_proven !== false ||
    report.terminal_chain.portable_rightful_issuance_proven !== false ||
    report.terminal_chain.production_rightful_issuance_proven !== false ||
    report.terminal_chain.live_authority_proven !== false ||
    report.terminal_chain.current_machine_governance_proven !== false ||
    report.terminal_chain.consequence_lifecycle_closed !== false
  ) {
    throw new Error('Protected records installed runtime profile terminal chain binding drifted');
  }

  assertExactKeys('Protected records installed runtime profile terminal chain side-door report', report.side_door_report, [
    'atomic_store_anchor_witness_commit',
    'consequence_lifecycle_closed',
    'current_machine_governance_proven',
    'disposable_install_only',
    'disposable_runtime_config_written',
    'exactly_once_effect_semantics',
    'external_attestation',
    'hook_configuration_written',
    'host_process_or_memory_introspection_closed',
    'host_filesystem_path_toctou_closed',
    'fixture_rightful_issuance_path_evidenced',
    'joint_rollback_reopened_authority_grant_reuse',
    'latest_profile_selected',
    'live_approval_channel_health_checked',
    'live_mcp_coverage_checked',
    'live_records_system_checked',
    'live_runtime_profile_checked',
    'live_authority_proven',
    'machine_config_written',
    'metadata_partial_commit_burn_observed',
    'persistent_runtime_config_written',
    'persistent_runtime_profile_installed',
    'portable_rightful_issuance_proven',
    'production_rightful_issuance_proven',
    'production_records_service_checked',
    'rightful_issuance_proven',
    'runtime_profile_activation_performed',
    'sovereign_recognition',
    'state_append_after_grant_commit_burn_observed',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_and_anchor_rollback_refused_while_witness_ahead',
    'unrouted_records_paths_checked',
    'user_config_written',
  ]);
  const sideDoor = report.side_door_report;
  if (
    sideDoor.disposable_install_only !== true ||
    sideDoor.persistent_runtime_profile_installed !== false ||
    sideDoor.runtime_profile_activation_performed !== false ||
    sideDoor.disposable_runtime_config_written !== true ||
    sideDoor.persistent_runtime_config_written !== false ||
    sideDoor.hook_configuration_written !== false ||
    sideDoor.user_config_written !== false ||
    sideDoor.machine_config_written !== false ||
    sideDoor.latest_profile_selected !== false ||
    sideDoor.live_runtime_profile_checked !== false ||
    sideDoor.live_records_system_checked !== false ||
    sideDoor.production_records_service_checked !== false ||
    sideDoor.current_machine_governance_proven !== false ||
    sideDoor.live_mcp_coverage_checked !== false ||
    sideDoor.live_approval_channel_health_checked !== false ||
    sideDoor.exactly_once_effect_semantics !== false ||
    sideDoor.atomic_store_anchor_witness_commit !== false ||
    sideDoor.state_append_after_grant_commit_burn_observed !== true ||
    sideDoor.metadata_partial_commit_burn_observed !== true ||
    sideDoor.store_and_anchor_rollback_refused_while_witness_ahead !== true ||
    sideDoor.store_anchor_and_witness_joint_rollback_detection !== false ||
    sideDoor.joint_rollback_reopened_authority_grant_reuse !== true ||
    sideDoor.host_filesystem_path_toctou_closed !== false ||
    sideDoor.fixture_rightful_issuance_path_evidenced !== true ||
    sideDoor.rightful_issuance_proven !== false ||
    sideDoor.portable_rightful_issuance_proven !== false ||
    sideDoor.production_rightful_issuance_proven !== false ||
    sideDoor.live_authority_proven !== false ||
    sideDoor.consequence_lifecycle_closed !== false ||
    sideDoor.host_process_or_memory_introspection_closed !== false ||
    sideDoor.external_attestation !== false ||
    sideDoor.sovereign_recognition !== false ||
    sideDoor.unrouted_records_paths_checked !== false
  ) {
    throw new Error('Protected records installed runtime profile terminal chain side-door drifted');
  }

  assertExactArray(
    'Protected records installed runtime profile terminal chain open boundaries',
    report.known_open_boundaries,
    REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_OPEN_BOUNDARIES
  );
  assertExactArray(
    'Protected records installed runtime profile terminal chain non-claims',
    report.non_claims,
    INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NON_CLAIMS
  );
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report, null, 2));
  return true;
}

export function protectedRecordsInstalledRuntimeProfileTerminalChainArtifactBodySha256(report) {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChain(report);
  return sha256hex(canonicalize({ chain: report }));
}

export function buildProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(report) {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChain(report);
  const body = { chain: report };
  const bodySha256 = sha256hex(canonicalize(body));
  return {
    artifact_type: PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_TYPE,
    canonicalization:
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_CANONICALIZATION,
    generator: 'zlar protected-records-installed-runtime-profile-terminal-chain --artifact',
    hash_scope: 'canonical artifact body without integrity',
    integrity: {
      body_sha256: bodySha256,
    },
    payload: body,
  };
}

export function assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(artifact) {
  assertExactKeys('Protected records installed runtime profile terminal chain artifact', artifact, [
    'artifact_type',
    'canonicalization',
    'generator',
    'hash_scope',
    'integrity',
    'payload',
  ]);
  if (
    artifact.artifact_type !== PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_TYPE ||
    artifact.canonicalization !==
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_CANONICALIZATION ||
    artifact.generator !==
      'zlar protected-records-installed-runtime-profile-terminal-chain --artifact' ||
    artifact.hash_scope !== 'canonical artifact body without integrity'
  ) {
    throw new Error('Protected records installed runtime profile terminal chain artifact metadata drifted');
  }
  assertExactKeys('Protected records installed runtime profile terminal chain artifact integrity', artifact.integrity, [
    'body_sha256',
  ]);
  assertExactKeys('Protected records installed runtime profile terminal chain artifact payload', artifact.payload, [
    'chain',
  ]);
  assertProtectedRecordsInstalledRuntimeProfileTerminalChain(artifact.payload.chain);
  const expected = sha256hex(canonicalize(artifact.payload));
  if (artifact.integrity.body_sha256 !== expected) {
    throw new Error('Protected records installed runtime profile terminal chain artifact hash mismatch');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(artifact, null, 2));
  return true;
}

export function writeProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(artifact, outputPath) {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(artifact);
  const text = `${JSON.stringify(artifact, null, 2)}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(text);
  writeFileSync(outputPath, text, { mode: 0o600 });
}

export function parseProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactText(text) {
  assertNoUnsafeProtectedRecordsRuntimeProfileText(text);
  let artifact;
  try {
    artifact = JSON.parse(text);
  } catch {
    throw new Error('Protected records installed runtime profile terminal chain artifact is not valid JSON');
  }
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(artifact);
  return artifact;
}

function detachedFixtureAuthorityProjectionStatus(contractSha256) {
  const status = protectedRecordsFixtureAuthorityGrantStatus(contractSha256);
  const allowed =
    status.status !== 'exhausted' &&
    status.fresh_effect_allowed === true &&
    status.repeated_use_provenance_valid === true &&
    status.fresh_fixture_rightful_projection_allowed === true;
  const effectReason = allowed
    ? null
    : protectedRecordsFixtureAuthorityGrantEffectStatusReason(contractSha256);
  return {
    status,
    allowed,
    reasonCode:
      allowed
        ? null
        : effectReason?.code ||
          (status.repeated_use_provenance_valid !== true
            ? 'authority_grant_repeated_use_provenance_invalid'
            : 'fixture_rightful_issuance_projection_not_allowed'),
  };
}

export function verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(
  artifact,
  { expectedArtifactBodySha256 = null } = {}
) {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(artifact);
  const chain = artifact.payload.chain;
  const artifactIdentity = matchExpectedArtifactSha256(
    'Protected records installed runtime profile terminal chain artifact',
    expectedArtifactBodySha256,
    artifact.integrity.body_sha256
  );
  const outerIdentityBound = artifactIdentity.matched;
  const authorityProjection = detachedFixtureAuthorityProjectionStatus(
    chain.terminal_chain.public_grant_contract_sha256
  );
  return {
    verification_type:
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_VERIFICATION_TYPE,
    verified: true,
    structural_self_integrity_verified: true,
    artifact_identity_match_requires_expected_sha256: true,
    artifact_identity_expected_sha256_supplied: artifactIdentity.supplied,
    expected_artifact_body_sha256: artifactIdentity.expected,
    artifact_identity_sha256_matched: artifactIdentity.matched,
    outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256:
      outerIdentityBound,
    trusted_issuer_registry_signature_identity_bound_to_expected_terminal_artifact_sha256:
      outerIdentityBound,
    recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256:
      outerIdentityBound,
    verification_scope:
      outerIdentityBound
        ? TERMINAL_CHAIN_PINNED_VERIFICATION_SCOPE
        : TERMINAL_CHAIN_STRUCTURAL_VERIFICATION_SCOPE,
    claim_boundary:
      outerIdentityBound
        ? TERMINAL_CHAIN_PINNED_CLAIM_BOUNDARY
        : TERMINAL_CHAIN_STRUCTURAL_CLAIM_BOUNDARY,
    artifact_type: artifact.artifact_type,
    canonicalization: artifact.canonicalization,
    hash_scope: artifact.hash_scope,
    body_sha256: artifact.integrity.body_sha256,
    payload_type: chain.chain_type,
    evidence_model: chain.evidence_model,
    live_probing: chain.live_probing,
    runtime_profile_sha256: chain.runtime_profile.profile_sha256,
    generated_installed_root_preflighted:
      chain.terminal_chain.generated_installed_root_preflighted,
    generated_preflight_artifact_consumed_by_service_proof:
      chain.terminal_chain.generated_preflight_artifact_consumed_by_service_proof,
    generated_service_proof_artifact_verified:
      chain.terminal_chain.generated_service_proof_artifact_verified,
    embedded_service_artifact_structural_self_integrity_verified:
      chain.terminal_chain.generated_service_proof_structural_self_integrity_verified,
    embedded_service_artifact_identity_match_requires_expected_sha256:
      chain.terminal_chain
        .generated_service_proof_artifact_identity_match_requires_expected_sha256,
    embedded_service_artifact_verification_scope:
      chain.terminal_chain.generated_service_proof_verification_scope,
    embedded_service_artifact_expected_body_sha256:
      chain.terminal_chain.expected_generated_service_proof_artifact_body_sha256,
    embedded_service_artifact_expected_body_sha256_matched:
      chain.terminal_chain
        .expected_generated_service_proof_artifact_body_sha256_matched,
    service_proof_bound_to_generated_preflight:
      chain.terminal_chain.service_proof_bound_to_generated_preflight,
    service_artifact_verification_bound_to_service_proof:
      chain.terminal_chain.service_artifact_verification_bound_to_service_proof,
    recognized_write_boarded:
      outerIdentityBound && chain.terminal_chain.recognized_write_boarded,
    missing_receipt_refused_before_mutation:
      chain.terminal_chain.missing_receipt_refused_before_mutation,
    invalid_receipt_refused_before_mutation:
      chain.terminal_chain.invalid_receipt_refused_before_mutation,
    all_required_recognition_refusals_before_mutation:
      chain.terminal_chain.all_required_recognition_refusals_before_mutation,
    required_recognition_refusal_case_count:
      chain.terminal_chain.required_recognition_refusal_case_count,
    observed_recognition_refusal_case_count:
      chain.terminal_chain.observed_recognition_refusal_case_count,
    required_recognition_refusal_cases: [
      ...chain.generated_service_proof.required_recognition_refusal_cases,
    ],
    observed_recognition_refusal_cases: [
      ...chain.generated_service_proof.observed_recognition_refusal_cases,
    ],
    recognition_refusal_taxonomy_sha256:
      chain.generated_service_proof.recognition_refusal_taxonomy_sha256,
    all_required_authority_refusals_before_consumption_and_mutation:
      chain.terminal_chain
        .all_required_authority_refusals_before_consumption_and_mutation,
    required_authority_refusal_case_count:
      chain.terminal_chain.required_authority_refusal_case_count,
    observed_authority_refusal_case_count:
      chain.terminal_chain.observed_authority_refusal_case_count,
    required_authority_refusal_cases: [
      ...chain.generated_service_proof.required_authority_refusal_cases,
    ],
    observed_authority_refusal_cases: [
      ...chain.generated_service_proof.observed_authority_refusal_cases,
    ],
    authority_refusal_taxonomy_sha256:
      chain.generated_service_proof.authority_refusal_taxonomy_sha256,
    recognition_contract_sha256: chain.terminal_chain.recognition_contract_sha256,
    public_grant_contract: chain.terminal_chain.public_grant_contract,
    public_grant_contract_sha256:
      chain.terminal_chain.public_grant_contract_sha256,
    authority_grant_status: authorityProjection.status.status,
    authority_grant_fresh_effect_allowed:
      authorityProjection.status.fresh_effect_allowed,
    authority_grant_repeated_use_provenance_valid:
      authorityProjection.status.repeated_use_provenance_valid,
    authority_grant_status_allows_fixture_rightful_projection:
      authorityProjection.allowed,
    authority_grant_status_reason_code: authorityProjection.reasonCode,
    public_safe_grant_summary: null,
    public_safe_grant_summary_sha256:
      outerIdentityBound
        ? chain.terminal_chain.public_safe_grant_summary_sha256
        : null,
    ordered_transition_binding_type:
      chain.terminal_chain.ordered_transition_binding_type,
    ordered_transition_binding_sha256:
      chain.terminal_chain.ordered_transition_binding_sha256,
    accepted_crossing_evidence_sha256:
      chain.terminal_chain.accepted_crossing_evidence_sha256,
    authority_grant_crossing_binding_sha256:
      chain.terminal_chain.authority_grant_crossing_binding_sha256,
    signed_payload_sha256:
      outerIdentityBound ? chain.terminal_chain.signed_payload_sha256 : null,
    accepted_crossing_target_binding_sha256:
      chain.terminal_chain.accepted_crossing_target_binding_sha256,
    accepted_crossing_authorized_effect_detail_sha256:
      chain.terminal_chain.accepted_crossing_authorized_effect_detail_sha256,
    accepted_crossing_state_effect_binding_sha256:
      chain.terminal_chain.accepted_crossing_state_effect_binding_sha256,
    boarded_service_target_binding: null,
    boarded_service_target_binding_sha256:
      outerIdentityBound
        ? chain.terminal_chain.boarded_service_target_binding_sha256
        : null,
    named_receipt_refusals: chain.terminal_chain.named_receipt_refusals,
    named_receipt_refusals_sha256:
      chain.terminal_chain.named_receipt_refusals_sha256,
    recognition_refusal_groups: chain.terminal_chain.recognition_refusal_groups,
    recognition_refusal_groups_sha256:
      chain.terminal_chain.recognition_refusal_groups_sha256,
    deployment_profile_authority_refusal_mirror:
      chain.terminal_chain.deployment_profile_authority_refusal_mirror,
    trusted_issuer_registry_recognition_binding: null,
    trusted_issuer_registry_recognition_binding_sha256:
      outerIdentityBound
        ? chain.terminal_chain.trusted_issuer_registry_recognition_binding_sha256
        : null,
    recognized_receipt_path_evidence: null,
    recognized_receipt_path_evidence_sha256:
      outerIdentityBound
        ? chain.terminal_chain.recognized_receipt_path_evidence_sha256
        : null,
    recognized_receipt_path_evidence_bound_to_artifact_body:
      outerIdentityBound,
    nested_artifact_binding: terminalChainNestedArtifactBindingSummary(chain),
    same_process_signed_payload_replay_refused:
      chain.terminal_chain.same_process_signed_payload_replay_refused,
    restart_consumed_authority_grant_refused:
      chain.terminal_chain.restart_consumed_authority_grant_refused,
    state_append_after_grant_commit_burn_observed:
      chain.terminal_chain.state_append_after_grant_commit_burn_observed,
    metadata_partial_commit_burn_observed:
      chain.terminal_chain.metadata_partial_commit_burn_observed,
    store_and_anchor_rollback_refused_while_witness_ahead:
      chain.terminal_chain.store_and_anchor_rollback_refused_while_witness_ahead,
    store_anchor_and_witness_joint_rollback_detection:
      chain.terminal_chain.store_anchor_and_witness_joint_rollback_detection,
    joint_rollback_reopened_authority_grant_reuse:
      chain.terminal_chain.joint_rollback_reopened_authority_grant_reuse,
    fixture_rightful_issuance_path_evidenced:
      outerIdentityBound &&
      authorityProjection.allowed &&
      chain.terminal_chain.fixture_rightful_issuance_path_evidenced,
    rightful_issuance_proven: chain.terminal_chain.rightful_issuance_proven,
    portable_rightful_issuance_proven:
      chain.terminal_chain.portable_rightful_issuance_proven,
    production_rightful_issuance_proven:
      chain.terminal_chain.production_rightful_issuance_proven,
    live_authority_proven: chain.terminal_chain.live_authority_proven,
    consequence_lifecycle_closed:
      chain.terminal_chain.consequence_lifecycle_closed,
    atomic_store_anchor_witness_commit:
      chain.side_door_report.atomic_store_anchor_witness_commit,
    host_filesystem_path_toctou_closed:
      chain.side_door_report.host_filesystem_path_toctou_closed,
    persistent_runtime_profile_installed:
      chain.side_door_report.persistent_runtime_profile_installed,
    runtime_profile_activation_performed:
      chain.side_door_report.runtime_profile_activation_performed,
    hook_configuration_written: chain.side_door_report.hook_configuration_written,
    user_config_written: chain.side_door_report.user_config_written,
    machine_config_written: chain.side_door_report.machine_config_written,
    current_machine_governance_proven:
      chain.side_door_report.current_machine_governance_proven,
    production_records_service_checked:
      chain.side_door_report.production_records_service_checked,
    production_downstream_recognition:
      chain.generated_service_proof.production_downstream_recognition,
    external_attestation: chain.side_door_report.external_attestation,
    sovereign_recognition: chain.side_door_report.sovereign_recognition,
    unrouted_records_paths_checked: chain.side_door_report.unrouted_records_paths_checked,
  };
}

export function assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification(verification) {
  assertExactKeys('Protected records installed runtime profile terminal chain artifact verification', verification, [
    'accepted_crossing_authorized_effect_detail_sha256',
    'accepted_crossing_evidence_sha256',
    'accepted_crossing_state_effect_binding_sha256',
    'accepted_crossing_target_binding_sha256',
    'all_required_authority_refusals_before_consumption_and_mutation',
    'all_required_recognition_refusals_before_mutation',
    'artifact_identity_expected_sha256_supplied',
    'artifact_type',
    'artifact_identity_match_requires_expected_sha256',
    'artifact_identity_sha256_matched',
    'atomic_store_anchor_witness_commit',
    'authority_refusal_taxonomy_sha256',
    'authority_grant_fresh_effect_allowed',
    'authority_grant_crossing_binding_sha256',
    'authority_grant_repeated_use_provenance_valid',
    'authority_grant_status',
    'authority_grant_status_allows_fixture_rightful_projection',
    'authority_grant_status_reason_code',
    'body_sha256',
    'boarded_service_target_binding',
    'boarded_service_target_binding_sha256',
    'canonicalization',
    'claim_boundary',
    'consequence_lifecycle_closed',
    'current_machine_governance_proven',
    'deployment_profile_authority_refusal_mirror',
    'evidence_model',
    'embedded_service_artifact_expected_body_sha256',
    'embedded_service_artifact_expected_body_sha256_matched',
    'embedded_service_artifact_identity_match_requires_expected_sha256',
    'embedded_service_artifact_structural_self_integrity_verified',
    'embedded_service_artifact_verification_scope',
    'expected_artifact_body_sha256',
    'external_attestation',
    'fixture_rightful_issuance_path_evidenced',
    'generated_installed_root_preflighted',
    'generated_preflight_artifact_consumed_by_service_proof',
    'generated_service_proof_artifact_verified',
    'hash_scope',
    'hook_configuration_written',
    'invalid_receipt_refused_before_mutation',
    'joint_rollback_reopened_authority_grant_reuse',
    'live_authority_proven',
    'live_probing',
    'machine_config_written',
    'metadata_partial_commit_burn_observed',
    'missing_receipt_refused_before_mutation',
    'named_receipt_refusals',
    'named_receipt_refusals_sha256',
    'nested_artifact_binding',
    'observed_authority_refusal_case_count',
    'observed_authority_refusal_cases',
    'observed_recognition_refusal_case_count',
    'observed_recognition_refusal_cases',
    'ordered_transition_binding_sha256',
    'ordered_transition_binding_type',
    'outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256',
    'payload_type',
    'persistent_runtime_profile_installed',
    'portable_rightful_issuance_proven',
    'production_downstream_recognition',
    'production_rightful_issuance_proven',
    'production_records_service_checked',
    'public_safe_grant_summary',
    'public_safe_grant_summary_sha256',
    'public_grant_contract',
    'public_grant_contract_sha256',
    'recognition_refusal_groups',
    'recognition_refusal_groups_sha256',
    'recognized_receipt_path_evidence',
    'recognized_receipt_path_evidence_bound_to_artifact_body',
    'recognized_receipt_path_evidence_sha256',
    'recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256',
    'recognized_write_boarded',
    'recognition_contract_sha256',
    'recognition_refusal_taxonomy_sha256',
    'required_authority_refusal_case_count',
    'required_authority_refusal_cases',
    'required_recognition_refusal_case_count',
    'required_recognition_refusal_cases',
    'restart_consumed_authority_grant_refused',
    'rightful_issuance_proven',
    'runtime_profile_activation_performed',
    'runtime_profile_sha256',
    'service_artifact_verification_bound_to_service_proof',
    'service_proof_bound_to_generated_preflight',
    'same_process_signed_payload_replay_refused',
    'signed_payload_sha256',
    'sovereign_recognition',
    'state_append_after_grant_commit_burn_observed',
    'structural_self_integrity_verified',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_and_anchor_rollback_refused_while_witness_ahead',
    'trusted_issuer_registry_recognition_binding',
    'trusted_issuer_registry_recognition_binding_sha256',
    'trusted_issuer_registry_signature_identity_bound_to_expected_terminal_artifact_sha256',
    'unrouted_records_paths_checked',
    'user_config_written',
    'verification_type',
    'verification_scope',
    'verified',
    'host_filesystem_path_toctou_closed',
  ]);
  const outerIdentityBound =
    verification.artifact_identity_sha256_matched === true;
  const authorityProjection = detachedFixtureAuthorityProjectionStatus(
    verification.public_grant_contract_sha256
  );
  if (
    verification.trusted_issuer_registry_signature_identity_bound_to_expected_terminal_artifact_sha256 !==
      outerIdentityBound ||
    verification.recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256 !==
      outerIdentityBound
  ) {
    throw new Error('Protected records installed runtime profile terminal chain identity projection posture drifted');
  }
  if (outerIdentityBound) {
    if (
      verification.public_safe_grant_summary !== null ||
      verification.boarded_service_target_binding !== null ||
      verification.trusted_issuer_registry_recognition_binding !== null ||
      verification.recognized_receipt_path_evidence !== null ||
      !/^[a-f0-9]{64}$/.test(
        verification.public_safe_grant_summary_sha256 || '',
      ) ||
      !/^[a-f0-9]{64}$/.test(verification.signed_payload_sha256 || '') ||
      !/^[a-f0-9]{64}$/.test(
        verification.boarded_service_target_binding_sha256 || '',
      ) ||
      !/^[a-f0-9]{64}$/.test(
        verification.trusted_issuer_registry_recognition_binding_sha256 || '',
      ) ||
      !/^[a-f0-9]{64}$/.test(
        verification.recognized_receipt_path_evidence_sha256 || '',
      ) ||
      verification.recognized_receipt_path_evidence_bound_to_artifact_body !==
        true
    ) {
      throw new Error(
        'Protected records installed runtime profile terminal chain pinned historical identity posture drifted',
      );
    }
  } else if (
    verification.public_safe_grant_summary !== null ||
    verification.public_safe_grant_summary_sha256 !== null ||
    verification.signed_payload_sha256 !== null ||
    verification.boarded_service_target_binding !== null ||
    verification.boarded_service_target_binding_sha256 !== null ||
    verification.trusted_issuer_registry_recognition_binding !== null ||
    verification.trusted_issuer_registry_recognition_binding_sha256 !== null ||
    verification.recognized_receipt_path_evidence !== null ||
    verification.recognized_receipt_path_evidence_sha256 !== null ||
    verification.recognized_receipt_path_evidence_bound_to_artifact_body !== false
  ) {
    throw new Error('Protected records installed runtime profile terminal chain unpinned identity projection drifted');
  }
  if (
    verification.verification_type !==
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_VERIFICATION_TYPE ||
    verification.verified !== true ||
    verification.structural_self_integrity_verified !== true ||
    verification.artifact_identity_match_requires_expected_sha256 !== true ||
    verification.outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256 !==
      outerIdentityBound ||
    verification.verification_scope !==
      (outerIdentityBound
        ? TERMINAL_CHAIN_PINNED_VERIFICATION_SCOPE
        : TERMINAL_CHAIN_STRUCTURAL_VERIFICATION_SCOPE) ||
    verification.claim_boundary !==
      (outerIdentityBound
        ? TERMINAL_CHAIN_PINNED_CLAIM_BOUNDARY
        : TERMINAL_CHAIN_STRUCTURAL_CLAIM_BOUNDARY) ||
    verification.artifact_type !==
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_TYPE ||
    verification.canonicalization !==
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_CANONICALIZATION ||
    verification.hash_scope !== 'canonical artifact body without integrity' ||
    !/^[a-f0-9]{64}$/.test(verification.body_sha256 || '') ||
    verification.payload_type !== PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TYPE ||
    verification.evidence_model !== 'fresh-local-disposable-installed-runtime-profile-terminal-chain' ||
    verification.live_probing !== false ||
    !/^[a-f0-9]{64}$/.test(verification.runtime_profile_sha256 || '') ||
    verification.generated_installed_root_preflighted !== true ||
    verification.generated_preflight_artifact_consumed_by_service_proof !== true ||
    verification.generated_service_proof_artifact_verified !== true ||
    verification.embedded_service_artifact_structural_self_integrity_verified !== true ||
    verification.embedded_service_artifact_identity_match_requires_expected_sha256 !== true ||
    verification.embedded_service_artifact_verification_scope !==
      'expected-artifact-identity-bound-local-fixture-projection' ||
    verification.embedded_service_artifact_expected_body_sha256 !==
      verification.nested_artifact_binding.generated_service_proof_artifact_body_sha256 ||
    verification.embedded_service_artifact_expected_body_sha256_matched !== true ||
    verification.service_proof_bound_to_generated_preflight !== true ||
    verification.service_artifact_verification_bound_to_service_proof !== true ||
    verification.recognized_write_boarded !== outerIdentityBound ||
    verification.missing_receipt_refused_before_mutation !== true ||
    verification.invalid_receipt_refused_before_mutation !== true ||
    verification.all_required_recognition_refusals_before_mutation !== true ||
    verification.required_recognition_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length ||
    verification.observed_recognition_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length ||
    verification.all_required_authority_refusals_before_consumption_and_mutation !== true ||
    verification.required_authority_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length ||
    verification.observed_authority_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length ||
    !/^[a-f0-9]{64}$/.test(verification.recognition_contract_sha256 || '') ||
    publicGrantContractSha256(verification.public_grant_contract) !==
      verification.public_grant_contract_sha256 ||
    canonicalize(
      verification.public_grant_contract.powers.map((power) => power.power_id)
    ) !== canonicalize(
      REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_FIXTURE_AUTHORITY_POWER_IDS
    ) ||
    verification.ordered_transition_binding_type !==
      'protected-records-runtime-ordered-single-lock-transition-binding-v1' ||
    !/^[a-f0-9]{64}$/.test(
      verification.ordered_transition_binding_sha256 || ''
    ) ||
    !/^[a-f0-9]{64}$/.test(
      verification.accepted_crossing_evidence_sha256 || ''
    ) ||
    !/^[a-f0-9]{64}$/.test(
      verification.authority_grant_crossing_binding_sha256 || ''
    ) ||
    !assertInstalledRuntimeProfileTerminalChainRefusalTaxonomy(
      'Protected records installed runtime profile terminal chain artifact verification recognition refusal taxonomy',
      {
        required_refusal_cases: verification.required_recognition_refusal_cases,
        observed_refusal_cases: verification.observed_recognition_refusal_cases,
        refusal_taxonomy_sha256:
          verification.recognition_refusal_taxonomy_sha256,
      }
    ) ||
    !assertInstalledRuntimeProfileTerminalChainAuthorityRefusalTaxonomy(
      'Protected records installed runtime profile terminal chain artifact verification authority refusal taxonomy',
      {
        required_refusal_cases: verification.required_authority_refusal_cases,
        observed_refusal_cases: verification.observed_authority_refusal_cases,
        refusal_taxonomy_sha256:
          verification.authority_refusal_taxonomy_sha256,
      }
    ) ||
    !assertNamedReceiptRefusals(
      'Protected records installed runtime profile terminal chain artifact verification named receipt refusals',
      verification.named_receipt_refusals
    ) ||
    verification.named_receipt_refusals_sha256 !==
      namedReceiptRefusalsSha256(verification.named_receipt_refusals) ||
    !assertRecognitionRefusalGroups(
      'Protected records installed runtime profile terminal chain artifact verification recognition refusal groups',
      verification.recognition_refusal_groups
    ) ||
    verification.recognition_refusal_groups_sha256 !==
      recognitionRefusalGroupsSha256(verification.recognition_refusal_groups) ||
    !assertDeploymentProfileAuthorityRefusalMirror(
      'Protected records installed runtime profile terminal chain artifact verification deployment-profile authority refusal mirror',
      verification.deployment_profile_authority_refusal_mirror,
      verification.runtime_profile_sha256
    ) ||
    !assertTerminalChainNestedArtifactBindingSummary(
      'Protected records installed runtime profile terminal chain artifact verification nested artifact binding',
      verification.nested_artifact_binding
    ) ||
    verification.same_process_signed_payload_replay_refused !== true ||
    verification.restart_consumed_authority_grant_refused !== true ||
    verification.state_append_after_grant_commit_burn_observed !== true ||
    verification.metadata_partial_commit_burn_observed !== true ||
    verification.store_and_anchor_rollback_refused_while_witness_ahead !== true ||
    verification.store_anchor_and_witness_joint_rollback_detection !== false ||
    verification.joint_rollback_reopened_authority_grant_reuse !== true ||
    verification.atomic_store_anchor_witness_commit !== false ||
    verification.host_filesystem_path_toctou_closed !== false ||
    verification.authority_grant_status !== authorityProjection.status.status ||
    verification.authority_grant_fresh_effect_allowed !==
      authorityProjection.status.fresh_effect_allowed ||
    verification.authority_grant_repeated_use_provenance_valid !==
      authorityProjection.status.repeated_use_provenance_valid ||
    verification.authority_grant_status_allows_fixture_rightful_projection !==
      authorityProjection.allowed ||
    verification.authority_grant_status_reason_code !==
      authorityProjection.reasonCode ||
    verification.fixture_rightful_issuance_path_evidenced !==
      (outerIdentityBound && authorityProjection.allowed) ||
    verification.rightful_issuance_proven !== false ||
    verification.portable_rightful_issuance_proven !== false ||
    verification.production_rightful_issuance_proven !== false ||
    verification.live_authority_proven !== false ||
    verification.consequence_lifecycle_closed !== false ||
    verification.persistent_runtime_profile_installed !== false ||
    verification.runtime_profile_activation_performed !== false ||
    verification.hook_configuration_written !== false ||
    verification.user_config_written !== false ||
    verification.machine_config_written !== false ||
    verification.current_machine_governance_proven !== false ||
    verification.production_records_service_checked !== false ||
    verification.production_downstream_recognition !== false ||
    verification.external_attestation !== false ||
    verification.sovereign_recognition !== false ||
    verification.unrouted_records_paths_checked !== false
  ) {
    throw new Error('Protected records installed runtime profile terminal chain artifact verification drifted');
  }
  if (
    verification.artifact_identity_expected_sha256_supplied !==
      verification.artifact_identity_sha256_matched
  ) {
    throw new Error('Protected records installed runtime profile terminal chain artifact identity posture drifted');
  }
  if (verification.artifact_identity_expected_sha256_supplied) {
    if (
      !/^[a-f0-9]{64}$/.test(verification.expected_artifact_body_sha256 || '') ||
      verification.expected_artifact_body_sha256 !== verification.body_sha256
    ) {
      throw new Error('Protected records installed runtime profile terminal chain expected artifact identity drifted');
    }
  } else if (verification.expected_artifact_body_sha256 !== null) {
    throw new Error('Protected records installed runtime profile terminal chain unexpected artifact identity drifted');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(verification, null, 2));
  return true;
}

export function formatProtectedRecordsInstalledRuntimeProfileTerminalChainSummary(report) {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChain(report);
  const authorityGrantStatus = protectedRecordsFixtureAuthorityGrantStatus(
    report.terminal_chain.public_safe_grant_summary
      .authority_grant_contract_sha256,
  );
  return [
    'ZLAR Protected Records Installed Runtime Profile Terminal Chain v1',
    `Result: generated_installed_root_preflighted=${report.terminal_chain.generated_installed_root_preflighted}; generated_preflight_consumed=${report.terminal_chain.generated_preflight_artifact_consumed_by_service_proof}; generated_service_artifact_verified=${report.terminal_chain.generated_service_proof_artifact_verified}`,
    `Plan: plan_id=${report.plan.plan_id}; plan_sha256=${report.plan.plan_sha256}`,
    `Profile: profile_id=${report.runtime_profile.profile_id}; profile_sha256=${report.runtime_profile.profile_sha256}`,
    `Disposable installation: root_created=${report.disposable_installation.install_root_created}; profile_copy_written=${report.disposable_installation.profile_copy_written}; active_index_written=${report.disposable_installation.active_profile_index_written}; selected_by_id_and_sha=${report.disposable_installation.selected_by_explicit_id_and_sha}; root_removed_after_run=${report.disposable_installation.disposable_root_removed_after_run}`,
    `Generated preflight: verified=${report.generated_preflight.verified}; artifact_body_sha256=${report.generated_preflight.artifact_body_sha256}; read_only=${report.generated_preflight.read_only}; downstream_refusal_proven=${report.generated_preflight.downstream_refusal_proven}`,
    `Generated service proof: artifact_body_sha256=${report.generated_service_proof.artifact_body_sha256}; structural_self_integrity_verified=${report.generated_service_proof.service_structural_self_integrity_verified}; expected_body_sha256_matched=${report.generated_service_proof.expected_service_proof_artifact_body_sha256_matched}; runtime_service_started=${report.generated_service_proof.runtime_service_started}; recognized_write_boarded=${report.generated_service_proof.recognized_write_boarded}; boarded_service_target_binding_sha256=${report.generated_service_proof.boarded_service_target_binding_sha256}; missing_receipt_refused=${report.generated_service_proof.missing_receipt_refused}; invalid_receipt_refused=${report.generated_service_proof.invalid_receipt_refused}; recognition_refusal_cases=${report.generated_service_proof.recognition_refusal_case_count}; authority_refusal_cases=${report.generated_service_proof.authority_refusal_case_count}; recognition_contract_sha256=${report.generated_service_proof.recognition_contract_sha256}; recognition_refusal_taxonomy_sha256=${report.generated_service_proof.recognition_refusal_taxonomy_sha256}; authority_refusal_taxonomy_sha256=${report.generated_service_proof.authority_refusal_taxonomy_sha256}; named_receipt_refusals_sha256=${report.generated_service_proof.named_receipt_refusals_sha256}; recognition_refusal_groups_sha256=${report.generated_service_proof.recognition_refusal_groups_sha256}`,
    `Fixture authority grant: authority_domain_id=${report.terminal_chain.public_safe_grant_summary.authority_domain_id}; grantor_role_id=${report.terminal_chain.public_safe_grant_summary.grantor_role_id}; power_ids=${report.terminal_chain.public_safe_grant_summary.power_ids.join(',')}; authority_grant_contract_sha256=${report.terminal_chain.public_safe_grant_summary.authority_grant_contract_sha256}; public_grant_contract_sha256=${report.terminal_chain.public_grant_contract_sha256}; summary_sha256=${report.terminal_chain.public_safe_grant_summary_sha256}`,
    `Accepted crossing: evidence_sha256=${report.terminal_chain.accepted_crossing_evidence_sha256}; crossing_binding_sha256=${report.terminal_chain.authority_grant_crossing_binding_sha256}; signed_payload_sha256=${report.terminal_chain.signed_payload_sha256}; target_binding_sha256=${report.terminal_chain.accepted_crossing_target_binding_sha256}; authorized_effect_detail_sha256=${report.terminal_chain.accepted_crossing_authorized_effect_detail_sha256}; state_effect_binding_sha256=${report.terminal_chain.accepted_crossing_state_effect_binding_sha256}`,
    `Ordered transition binding: type=${report.terminal_chain.ordered_transition_binding_type}; sha256=${report.terminal_chain.ordered_transition_binding_sha256}`,
    `Historical boarded service target binding: handle=${report.terminal_chain.boarded_service_target_binding.target_handle}; launcher_binding_sha256=${report.terminal_chain.boarded_service_target_binding.launcher_target_binding_sha256}; effect_sha256=${report.terminal_chain.boarded_service_target_binding.target_effect_sha256}; authorized_effect_detail_sha256=${report.terminal_chain.boarded_service_target_binding.authorized_effect_detail_sha256}; state_effect_binding_sha256=${report.terminal_chain.boarded_service_target_binding.state_effect_binding_sha256}; summary_sha256=${report.terminal_chain.boarded_service_target_binding_sha256}; metadata_role=${report.terminal_chain.boarded_service_target_binding.metadata_role}; historical_artifact_fixture_rightful_issuance_path_recorded=${report.terminal_chain.boarded_service_target_binding.fixture_rightful_issuance_path_evidenced}; current_fixture_rightful_issuance_path_evidenced=false; profile_wide_target_authority_proven=${report.terminal_chain.boarded_service_target_binding.profile_wide_target_authority_proven}; rightful_issuance_proven=${report.terminal_chain.boarded_service_target_binding.rightful_issuance_proven}; live_target_proven=${report.terminal_chain.boarded_service_target_binding.live_target_proven}; consequence_lifecycle_closed=${report.terminal_chain.boarded_service_target_binding.consequence_lifecycle_closed}`,
    `Named receipt refusals: missing=${report.terminal_chain.named_receipt_refusals.missing.refused_before_mutation}; invalid=${report.terminal_chain.named_receipt_refusals.invalid.refused_before_mutation}; stale=${report.terminal_chain.named_receipt_refusals.stale.refused_before_mutation}; stale_or_expired=${report.terminal_chain.named_receipt_refusals.stale_or_expired.refused_before_mutation}; unknown_issuer=${report.terminal_chain.named_receipt_refusals.unknown_issuer.refused_before_mutation}; wrong_policy=${report.terminal_chain.named_receipt_refusals.wrong_policy.refused_before_mutation}; wrong_domain=${report.terminal_chain.named_receipt_refusals.wrong_domain.refused_before_mutation}; wrong_tool=${report.terminal_chain.named_receipt_refusals.wrong_tool.refused_before_mutation}`,
    `Recognition refusal groups: no_usable_recognized_receipt_authority=${report.terminal_chain.recognition_refusal_groups.no_usable_recognized_receipt_authority.all_refused_before_mutation}; recognized_receipt_scope_mismatch=${report.terminal_chain.recognition_refusal_groups.recognized_receipt_scope_mismatch.all_refused_before_mutation}; route_or_request_authority_material_refused=${report.terminal_chain.recognition_refusal_groups.route_or_request_authority_material_refused.all_refused_before_mutation}`,
    `Deployment-profile authority refusal mirror: source=${report.terminal_chain.deployment_profile_authority_refusal_mirror.source}; runtime_profile_sha_matches_terminal_chain=${report.terminal_chain.deployment_profile_authority_refusal_mirror.source_runtime_profile_sha_matches_terminal_chain}; case_count=${report.terminal_chain.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_case_count}; before_service_proof=${report.terminal_chain.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusals_before_service_proof}; service_proof_started=${report.terminal_chain.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_service_proof_started}`,
    `Trusted issuer registry recognition binding: verdict=${report.terminal_chain.trusted_issuer_registry_recognition_binding.verdict}; registry_fixture_validated=${report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_fixture_validated}; registry_to_recognition_rule_evaluated=${report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_to_recognition_rule_evaluated}; recognition_contract_hash_bound=${report.terminal_chain.trusted_issuer_registry_recognition_binding.recognition_contract_hash_bound}; service_artifact_hash_bound=${report.terminal_chain.trusted_issuer_registry_recognition_binding.service_artifact_hash_bound}; registry_receipt_role=${report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_role}; registry_receipt_is_boarded_service_receipt=${report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_is_boarded_service_receipt}; registry_receipt_authorized_service_write=${report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_authorized_service_write}; receipt_detail_hash_roles_distinct=${report.terminal_chain.trusted_issuer_registry_recognition_binding.receipt_detail_hash_roles_distinct}; binding_sha256=${report.terminal_chain.trusted_issuer_registry_recognition_binding_sha256}`,
    `Recognized receipt path evidence: verdict=${report.terminal_chain.recognized_receipt_path_evidence.verdict}; source_binding_sha256=${report.terminal_chain.recognized_receipt_path_evidence.source_binding_sha256}; evidence_sha256=${report.terminal_chain.recognized_receipt_path_evidence_sha256}; boarded_service_target_binding_sha256=${report.terminal_chain.recognized_receipt_path_evidence.boarded_service_target_binding_sha256}; boarded_service_target_handle=${report.terminal_chain.recognized_receipt_path_evidence.boarded_service_target_handle}; boarded_service_target_metadata_role=${report.terminal_chain.recognized_receipt_path_evidence.boarded_service_target_metadata_role}; receipt_envelope_included=${report.terminal_chain.recognized_receipt_path_evidence.receipt_envelope_included}`,
    `Trusted issuer registry recognition refusals: case_count=${report.terminal_chain.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals.case_count}; all_refused=${report.terminal_chain.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals.all_refused}; refusals_sha256=${report.terminal_chain.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals_sha256}`,
    `Trusted issuer registry recognition non-claims: live_trust_registry_state=${report.terminal_chain.trusted_issuer_registry_recognition_binding.live_trust_registry_state}; key_custody_proven=${report.terminal_chain.trusted_issuer_registry_recognition_binding.key_custody_proven}; revocation_truth_proven=${report.terminal_chain.trusted_issuer_registry_recognition_binding.revocation_truth_proven}; production_downstream_recognition_proven=${report.terminal_chain.trusted_issuer_registry_recognition_binding.production_downstream_recognition_proven}; production_authority=${report.terminal_chain.trusted_issuer_registry_recognition_binding.production_authority}; current_machine_governance_proven=${report.terminal_chain.trusted_issuer_registry_recognition_binding.current_machine_governance_proven}`,
    `Binding: service_proof_bound_to_generated_preflight=${report.terminal_chain.service_proof_bound_to_generated_preflight}; service_artifact_verification_bound_to_service_proof=${report.terminal_chain.service_artifact_verification_bound_to_service_proof}; expected_service_artifact_sha256=${report.terminal_chain.expected_generated_service_proof_artifact_body_sha256}; expected_service_artifact_sha256_matched=${report.terminal_chain.expected_generated_service_proof_artifact_body_sha256_matched}; nested_artifact_binding.preflight_artifact_hash_bound=${report.terminal_chain.nested_artifact_binding.preflight_artifact_hash_bound}; nested_artifact_binding.service_artifact_hash_bound=${report.terminal_chain.nested_artifact_binding.service_artifact_hash_bound}; nested_artifact_binding.service_proof_source_preflight_hash_bound=${report.terminal_chain.nested_artifact_binding.service_proof_source_preflight_hash_bound}; recognition_contract_sha256=${report.terminal_chain.recognition_contract_sha256}; recognition_refusal_taxonomy_sha256=${report.terminal_chain.recognition_refusal_taxonomy_sha256}; authority_refusal_taxonomy_sha256=${report.terminal_chain.authority_refusal_taxonomy_sha256}; named_receipt_refusals_sha256=${report.terminal_chain.named_receipt_refusals_sha256}; recognition_refusal_groups_sha256=${report.terminal_chain.recognition_refusal_groups_sha256}`,
    `Replay and burn boundaries: same_process_signed_payload_replay_refused=${report.terminal_chain.same_process_signed_payload_replay_refused}; restart_consumed_authority_grant_refused=${report.terminal_chain.restart_consumed_authority_grant_refused}; state_append_after_grant_commit_burn_observed=${report.terminal_chain.state_append_after_grant_commit_burn_observed}; metadata_partial_commit_burn_observed=${report.terminal_chain.metadata_partial_commit_burn_observed}`,
    `Rollback side door: store_and_anchor_rollback_refused_while_witness_ahead=${report.terminal_chain.store_and_anchor_rollback_refused_while_witness_ahead}; store_anchor_and_witness_joint_rollback_detection=${report.terminal_chain.store_anchor_and_witness_joint_rollback_detection}; joint_rollback_reopened_authority_grant_reuse=${report.terminal_chain.joint_rollback_reopened_authority_grant_reuse}`,
    `Historical artifact boundary: historical_artifact_fixture_rightful_issuance_path_recorded=${report.terminal_chain.fixture_rightful_issuance_path_evidenced}; authority_grant_status=${authorityGrantStatus.status}; current_fixture_rightful_issuance_path_evidenced=false; rightful_issuance_proven=${report.terminal_chain.rightful_issuance_proven}; portable_rightful_issuance_proven=${report.terminal_chain.portable_rightful_issuance_proven}; production_rightful_issuance_proven=${report.terminal_chain.production_rightful_issuance_proven}; live_authority_proven=${report.terminal_chain.live_authority_proven}; persistent_runtime_profile_installed=${report.side_door_report.persistent_runtime_profile_installed}; activation_performed=${report.side_door_report.runtime_profile_activation_performed}; current_machine_governance_proven=${report.side_door_report.current_machine_governance_proven}; consequence_lifecycle_closed=${report.terminal_chain.consequence_lifecycle_closed}; production_downstream_recognition=${report.generated_service_proof.production_downstream_recognition}; external_attestation=${report.side_door_report.external_attestation}`,
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Non-claim: ${report.non_claims[0]}`,
    '',
  ].join('\n');
}

export function formatProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactSummary(artifact) {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(artifact);
  return [
    '',
    'Portable installed runtime profile terminal chain artifact:',
    `  artifact_type=${artifact.artifact_type}`,
    `  body_sha256=${artifact.integrity.body_sha256}`,
    '',
  ].join('\n');
}

export function formatProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification(verification) {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification(verification);
  return [
    'ZLAR Protected Records Installed Runtime Profile Terminal Chain Artifact Verification v1',
    `verified=${verification.verified}; structural_self_integrity_verified=${verification.structural_self_integrity_verified}; artifact_identity_match_requires_expected_sha256=${verification.artifact_identity_match_requires_expected_sha256}`,
    `artifact_identity: expected_sha256_supplied=${verification.artifact_identity_expected_sha256_supplied}; sha256_matched=${verification.artifact_identity_sha256_matched}; outer_fixture_metadata_bound=${verification.outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256}`,
    `identity_projection: trusted_issuer_registry_signature_bound=${verification.trusted_issuer_registry_signature_identity_bound_to_expected_terminal_artifact_sha256}; recognized_receipt_source_bound=${verification.recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256}`,
    `verification_scope=${verification.verification_scope}`,
    `claim_boundary=${verification.claim_boundary}`,
    `body_sha256=${verification.body_sha256}`,
    `payload_type=${verification.payload_type}`,
    `runtime_profile_sha256=${verification.runtime_profile_sha256}`,
    `generated_installed_root_preflighted=${verification.generated_installed_root_preflighted}`,
    `generated_preflight_artifact_consumed_by_service_proof=${verification.generated_preflight_artifact_consumed_by_service_proof}`,
    `generated_service_proof_artifact_verified=${verification.generated_service_proof_artifact_verified}`,
    `embedded_service_artifact.structural_self_integrity_verified=${verification.embedded_service_artifact_structural_self_integrity_verified}; embedded_service_artifact.expected_body_sha256=${verification.embedded_service_artifact_expected_body_sha256}; embedded_service_artifact.expected_body_sha256_matched=${verification.embedded_service_artifact_expected_body_sha256_matched}`,
    `recognized_write_boarded=${verification.recognized_write_boarded}`,
    `missing_receipt_refused_before_mutation=${verification.missing_receipt_refused_before_mutation}`,
    `invalid_receipt_refused_before_mutation=${verification.invalid_receipt_refused_before_mutation}`,
    `all_required_recognition_refusals_before_mutation=${verification.all_required_recognition_refusals_before_mutation}; recognition_refusal_cases=${verification.observed_recognition_refusal_case_count}`,
    `all_required_authority_refusals_before_consumption_and_mutation=${verification.all_required_authority_refusals_before_consumption_and_mutation}; authority_refusal_cases=${verification.observed_authority_refusal_case_count}`,
    `recognition_contract_sha256=${verification.recognition_contract_sha256}`,
    `public_safe_grant_summary.authority_domain_id=${verification.public_safe_grant_summary?.authority_domain_id ?? 'withheld-until-outer-artifact-identity-match'}`,
    `public_safe_grant_summary.grantor_role_id=${verification.public_safe_grant_summary?.grantor_role_id ?? 'withheld-until-outer-artifact-identity-match'}`,
    `public_safe_grant_summary.power_ids=${verification.public_safe_grant_summary?.power_ids?.join(',') ?? 'withheld-until-outer-artifact-identity-match'}`,
    `public_safe_grant_summary.sha256=${verification.public_safe_grant_summary_sha256}`,
    `public_grant_contract.sha256=${verification.public_grant_contract_sha256}`,
    `authority_grant_status=${verification.authority_grant_status}; fresh_effect_allowed=${verification.authority_grant_fresh_effect_allowed}; repeated_use_provenance_valid=${verification.authority_grant_repeated_use_provenance_valid}; allows_fixture_rightful_projection=${verification.authority_grant_status_allows_fixture_rightful_projection}; reason_code=${verification.authority_grant_status_reason_code}`,
    `accepted_crossing.evidence_sha256=${verification.accepted_crossing_evidence_sha256}; accepted_crossing.binding_sha256=${verification.authority_grant_crossing_binding_sha256}; accepted_crossing.signed_payload_sha256=${verification.signed_payload_sha256}`,
    `ordered_transition_binding.type=${verification.ordered_transition_binding_type}`,
    `ordered_transition_binding.sha256=${verification.ordered_transition_binding_sha256}`,
    `boarded_service_target_binding.sha256=${verification.boarded_service_target_binding_sha256}`,
    `boarded_service_target_binding.target_handle=${verification.boarded_service_target_binding?.target_handle ?? 'withheld-until-outer-artifact-identity-match'}`,
    `boarded_service_target_binding.metadata_role=${verification.boarded_service_target_binding?.metadata_role ?? 'withheld-until-outer-artifact-identity-match'}`,
    `nested_artifact_binding.preflight_artifact_hash_bound=${verification.nested_artifact_binding.preflight_artifact_hash_bound}`,
    `nested_artifact_binding.service_artifact_hash_bound=${verification.nested_artifact_binding.service_artifact_hash_bound}`,
    `nested_artifact_binding.service_proof_source_preflight_hash_bound=${verification.nested_artifact_binding.service_proof_source_preflight_hash_bound}`,
    `trusted_issuer_registry_recognition_binding.verdict=${verification.trusted_issuer_registry_recognition_binding?.verdict ?? 'withheld-until-outer-artifact-identity-match'}`,
    `trusted_issuer_registry_recognition_binding.registry_to_recognition_rule_evaluated=${verification.trusted_issuer_registry_recognition_binding?.registry_to_recognition_rule_evaluated ?? false}`,
    `trusted_issuer_registry_recognition_binding.recognition_contract_hash_bound=${verification.trusted_issuer_registry_recognition_binding?.recognition_contract_hash_bound ?? false}`,
    `trusted_issuer_registry_recognition_binding.binding_sha256=${verification.trusted_issuer_registry_recognition_binding_sha256}`,
    `trusted_issuer_registry_recognition_binding.registry_receipt_is_boarded_service_receipt=${verification.trusted_issuer_registry_recognition_binding?.registry_receipt_is_boarded_service_receipt ?? false}`,
    `trusted_issuer_registry_recognition_binding.registry_receipt_authorized_service_write=${verification.trusted_issuer_registry_recognition_binding?.registry_receipt_authorized_service_write ?? false}`,
    `trusted_issuer_registry_recognition_binding.receipt_detail_hash_roles_distinct=${verification.trusted_issuer_registry_recognition_binding?.receipt_detail_hash_roles_distinct ?? false}`,
    `trusted_issuer_registry_recognition_binding.refusals_sha256=${verification.trusted_issuer_registry_recognition_binding?.trusted_issuer_registry_recognition_refusals_sha256 ?? 'withheld-until-outer-artifact-identity-match'}`,
    `recognized_receipt_path_evidence.verdict=${verification.recognized_receipt_path_evidence?.verdict ?? 'withheld-until-outer-artifact-identity-match'}`,
    `recognized_receipt_path_evidence.source_binding_sha256=${verification.recognized_receipt_path_evidence?.source_binding_sha256 ?? 'withheld-until-outer-artifact-identity-match'}`,
    `recognized_receipt_path_evidence.sha256=${verification.recognized_receipt_path_evidence_sha256}`,
    `recognized_receipt_path_evidence.boarded_service_target_binding_sha256=${verification.recognized_receipt_path_evidence?.boarded_service_target_binding_sha256 ?? 'withheld-until-outer-artifact-identity-match'}`,
    `recognized_receipt_path_evidence.boarded_service_target_handle=${verification.recognized_receipt_path_evidence?.boarded_service_target_handle ?? 'withheld-until-outer-artifact-identity-match'}`,
    `recognized_receipt_path_evidence.bound_to_artifact_body=${verification.recognized_receipt_path_evidence_bound_to_artifact_body}`,
    `deployment_profile_authority_refusal_mirror.source=${verification.deployment_profile_authority_refusal_mirror.source}`,
    `deployment_profile_authority_refusal_mirror.source_proof_sha256=${verification.deployment_profile_authority_refusal_mirror.source_proof_sha256}`,
    `deployment_profile_authority_refusal_mirror.runtime_profile_sha_matches_terminal_chain=${verification.deployment_profile_authority_refusal_mirror.source_runtime_profile_sha_matches_terminal_chain}`,
    `deployment_profile_authority_refusal_mirror.case_count=${verification.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_case_count}`,
    `deployment_profile_authority_refusal_mirror.before_service_proof=${verification.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusals_before_service_proof}`,
    `deployment_profile_authority_refusal_mirror.service_proof_started=${verification.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_service_proof_started}`,
    `recognition_refusal_taxonomy_sha256=${verification.recognition_refusal_taxonomy_sha256}`,
    `authority_refusal_taxonomy_sha256=${verification.authority_refusal_taxonomy_sha256}`,
    `named_receipt_refusals_sha256=${verification.named_receipt_refusals_sha256}`,
    `recognition_refusal_groups_sha256=${verification.recognition_refusal_groups_sha256}`,
    `same_process_signed_payload_replay_refused=${verification.same_process_signed_payload_replay_refused}`,
    `restart_consumed_authority_grant_refused=${verification.restart_consumed_authority_grant_refused}`,
    `state_append_after_grant_commit_burn_observed=${verification.state_append_after_grant_commit_burn_observed}`,
    `metadata_partial_commit_burn_observed=${verification.metadata_partial_commit_burn_observed}`,
    `store_and_anchor_rollback_refused_while_witness_ahead=${verification.store_and_anchor_rollback_refused_while_witness_ahead}`,
    `store_anchor_and_witness_joint_rollback_detection=${verification.store_anchor_and_witness_joint_rollback_detection}`,
    `joint_rollback_reopened_authority_grant_reuse=${verification.joint_rollback_reopened_authority_grant_reuse}`,
    `fixture_rightful_issuance_path_evidenced=${verification.fixture_rightful_issuance_path_evidenced}`,
    `rightful_issuance_proven=${verification.rightful_issuance_proven}`,
    `portable_rightful_issuance_proven=${verification.portable_rightful_issuance_proven}`,
    `production_rightful_issuance_proven=${verification.production_rightful_issuance_proven}`,
    `live_authority_proven=${verification.live_authority_proven}`,
    `current_machine_governance_proven=${verification.current_machine_governance_proven}`,
    `consequence_lifecycle_closed=${verification.consequence_lifecycle_closed}`,
    `production_downstream_recognition=${verification.production_downstream_recognition}`,
    `external_attestation=${verification.external_attestation}`,
    '',
  ].join('\n');
}
