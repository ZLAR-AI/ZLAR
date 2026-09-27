import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from './canonicalize.mjs';
import {
  LOCAL_PROOF_PACK_ARTIFACT_TYPE,
  LOCAL_PROOF_PACK_ARTIFACT_VERIFICATION_TYPE,
  LOCAL_PROOF_PACK_HISTORICAL_SAMPLE_ARTIFACT_BODY_SHA256,
  assertNoUnsafeLocalProofPackText,
  parseLocalProofPackArtifactText,
  verifyLocalProofPackArtifact,
} from './local-proof-pack.mjs';
import {
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY,
  claudeCodeHookContractReplayContractSha256,
  claudeCodeHookContractReplayRepoAdapterSha256,
} from './claude-code-hook-contract-replay-proof.mjs';
import {
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_VERIFICATION_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TYPE,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_OPEN_BOUNDARIES,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS,
  assertProtectedRecordsInstalledRuntimeProfileTerminalChain,
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact,
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification,
  verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact,
} from './protected-records-installed-runtime-profile-terminal-chain.mjs';
import {
  REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES,
} from './protected-records-installed-runtime-profile-service-proof.mjs';
import {
  PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256,
  protectedRecordsFixtureAuthorityGrantEffectStatusReason,
  protectedRecordsFixtureAuthorityGrantStatus,
} from './protected-records-fixture-authority-status.mjs';
import {
  REPORT_TYPE as GOVERNED_SURFACE_COVERAGE_MAP_REPORT_TYPE,
  assertGovernedSurfaceCoverageMap,
  buildGovernedSurfaceCoverageMap,
} from './governed-surface-coverage-map.mjs';
import {
  ONE_TERMINAL_DEPLOYMENT_PROFILE_SAFE_CLAIM_CEILING,
  REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES,
  oneTerminalDeploymentProfileSha256,
  readSampleProtectedRecordsOneTerminalDeploymentProfileInputs,
} from './protected-records-one-terminal-deployment-profile.mjs';
import { sha256hex } from './receipt.mjs';

export const PRODUCT_PROOF_PATH_REPORT_TYPE = 'zlar-product-proof-path-v1';
export const PRODUCT_PROOF_PATH_SCHEMA_VERSION = 7;
export const PRODUCT_PROOF_PATH_EVIDENCE_MODEL =
  'local-fixture-proof-pack-exact-sha-pinned-committed-terminal-chain-coverage-map-and-deployment-profile-authority-bridge';
export const PRODUCT_PROOF_PATH_CLAIM_BOUNDARY =
  'local product proof path composition and verification only, including local proof-pack artifact verification, exact-SHA-pinned reading of the committed installed-runtime-profile terminal-chain artifact without rerunning its positive consequence, current committed coverage-map fixture binding, and a local fixture deployment-profile authority-material refusal bridge; bounded historical one-hermetic-crossing fixture evidence, not renewed grant availability or generic, portable, live, production, current-machine, or consequence-lifecycle governance';

export const PRODUCT_PROOF_PATH_NON_CLAIMS = Object.freeze([
  'This report does not inspect live hooks, live audit stores, runtime state, approval channels, downstream systems, operator home key material, or hardware.',
  'This report does not use Telegram or prove live human approval-channel delivery.',
  'This report does not prove real human approval; the human-authorization evidence is a simulated local fixture.',
  'This report does not install or activate a persistent runtime profile, write hooks, write user or machine configuration, write production configuration, or start a live production service.',
  'This report reads and exact-SHA verifies the committed launcher-owned disposable installed-runtime-profile terminal-chain artifact; it does not rerun that positive consequence or prove that its one-use authority grant is currently available.',
  'This report evidences rightful issuance only for one named local disposable fixture authority domain and one hermetic crossing; it does not prove generic, portable, production, or live rightful issuance or consequence lifecycle closure.',
  'This report binds the committed coverage-map fixture bytes and its governed terminal surface to the fresh terminal-chain profile, service, and artifact hashes; it does not turn fixture binding into live discovery.',
  'This report validates a local fixture one-terminal deployment-profile authority bridge; it does not prove an active enterprise deployment, production downstream recognition, production authority, or current-machine governance.',
  'This report does not prove production deployment, production downstream recognition, current-machine governance, enterprise readiness, external attestation, sovereign recognition, key custody, revocation truth, live trust-registry truth, all-MCP governance, or coverage of unrouted surfaces.',
]);

const FORBIDDEN_CLAIM_KEYS = Object.freeze([
  'persistent_runtime_profile_installation',
  'runtime_activation',
  'live_runtime_service_started',
  'hook_configuration_written',
  'user_configuration_written',
  'machine_configuration_written',
  'live_records_system_checked',
  'current_machine_governance',
  'production_downstream_recognition',
  'production_authority',
  'enterprise_readiness',
  'external_attestation',
  'sovereign_recognition',
  'live_trust_registry_truth',
  'live_issuer_status',
  'key_custody',
  'revocation_truth',
  'production_trust_registry',
  'all_mcp_governance',
  'unrouted_surface_coverage',
]);

const ACCEPTANCE_GATE_KEYS = Object.freeze([
  'fresh_local_proof_pack_generated',
  'local_proof_pack_artifact_verified',
  'fresh_terminal_chain_generated',
  'terminal_chain_artifact_verified',
  'terminal_chain_boundary_observed',
  'governed_action_allowed',
  'governed_action_refused',
  'simulated_human_authorization_observed',
  'receipt_verification_observed',
  'trusted_issuer_registry_recognition_observed',
  'coverage_map_runtime_contract_observed',
  'deployment_profile_authority_bridge_observed',
  'receipt_effect_boundary_observed',
  'non_coverage_visible',
  'no_private_operator_state_required',
]);

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

const COMMAND_SEQUENCE = Object.freeze([
  'zlar local-proof-pack --artifact <file|->',
  'zlar local-proof-pack verify --input <file|-> --json',
  `zlar protected-records-installed-runtime-profile-terminal-chain verify --sample --require-sha ${PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256} --json`,
  'zlar protected-records-one-terminal-deployment-profile --sample --json',
]);

const REQUIRED_RECEIPT_FIELDS = Object.freeze([
  'v',
  'id',
  'kid',
  'iat',
  'type',
  'payload',
  'sig',
  'payload.audit_event_id',
  'payload.ts',
  'payload.domain',
  'payload.tool',
  'payload.outcome',
  'payload.policy_version',
  'payload.detail_hash',
]);

const DOWNSTREAM_REFUSAL_REASONS = Object.freeze([
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

const KNOWN_UNGOVERNED_BOUNDARIES = Object.freeze([
  'live_records_system',
  'production_records_adapter',
  'unrouted_records_paths',
]);

const PROOF_PACK_CLAUDE_HOOK_CONTRACT_REPLAY_KEYS = Object.freeze([
  'adapter_sha256',
  'case_evidence_hash_scope',
  'case_evidence_sha256',
  'component_sha256',
  'hook_replay_contract_sha256',
  'source_state_boundary',
]);

const PRODUCT_PROOF_PATH_COVERAGE_MAP_FIXTURE_PATH = fileURLToPath(new URL(
  '../tests/fixtures/governed-surface-coverage-map-v1-input.json',
  import.meta.url,
));
const PRODUCT_PROOF_PATH_LOCAL_PROOF_PACK_SAMPLE_ARTIFACT_PATH =
  fileURLToPath(new URL(
    '../tests/fixtures/local-proof-pack-artifact-v1.json',
    import.meta.url,
  ));
const PRODUCT_PROOF_PATH_TERMINAL_CHAIN_ARTIFACT_PATH = fileURLToPath(new URL(
  '../tests/fixtures/protected-records-installed-runtime-profile-terminal-chain-artifact-v1.json',
  import.meta.url,
));
const PRODUCT_PROOF_PATH_TERMINAL_SURFACE_ID =
  'protected-records.installed-runtime-profile.terminal-chain.records.write';
const EXACT_RUNTIME_MUTATION_AUTHORITATIVE_ROUTE =
  'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation';

const PRODUCT_PROOF_PATH_TERMINAL_CHAIN_BOUNDARY =
  'exact-SHA-pinned committed disposable installed-runtime-profile terminal-chain artifact verification only; historical launcher-owned local proof-harness evidence, not positive consequence re-execution, renewed grant availability, persistent install, activation, live runtime service, current-machine governance, production downstream recognition, or external attestation';
const PRODUCT_PROOF_PATH_COVERAGE_MAP_BOUNDARY =
  'current committed coverage-map fixture bytes and one governed installed-runtime terminal surface only; no live discovery, generic or portable rightful issuance, production authority, current-machine governance, or consequence lifecycle closure';

let expectedProofPackClaudeHookReplaySummaryCache = null;

const TERMINAL_CHAIN_BOUNDARY_KEYS = Object.freeze([
  'all_required_authority_refusals_before_consumption_and_mutation',
  'all_required_recognition_refusals_before_mutation',
  'artifact_type',
  'authority_refusal_taxonomy_sha256',
  'body_sha256',
  'claim_boundary',
  'cryptographic_evidence_reproducible_from_artifact',
  'current_machine_governance_proven',
  'evidence_model',
  'external_attestation',
  'generated_installed_root_preflighted',
  'generated_preflight_artifact_consumed_by_service_proof',
  'generated_service_proof_artifact_verified',
  'hook_configuration_written',
  'host_filesystem_path_toctou_closed',
  'invalid_receipt_refused_before_mutation',
  'joint_rollback_reopened_authority_grant_reuse',
  'known_open_boundaries',
  'live_authority_proven',
  'live_probing',
  'machine_configuration_written',
  'metadata_partial_commit_burn_observed',
  'missing_receipt_refused_before_mutation',
  'named_receipt_refusals',
  'named_receipt_refusals_sha256',
  'nested_artifact_binding',
  'observed_authority_refusal_case_count',
  'observed_recognition_refusal_case_count',
  'payload_type',
  'persistent_runtime_profile_installed',
  'portable_rightful_issuance_proven',
  'production_downstream_recognition',
  'production_records_service_checked',
  'production_rightful_issuance_proven',
  'public_safe_grant_summary',
  'public_safe_grant_summary_sha256',
  'receipt_envelope_included',
  'recognition_contract_sha256',
  'recognition_contract_hash_bound',
  'recognition_refusal_group_case_count',
  'recognition_refusal_group_case_ids',
  'recognition_refusal_group_case_ids_preserved',
  'recognition_refusal_group_count',
  'recognition_refusal_groups_sha256',
  'recognized_receipt_path_evidence_artifact_crypto_reproducible',
  'recognized_receipt_path_evidence_artifact_verification_sha256',
  'recognized_receipt_path_evidence_bound_to_artifact_body',
  'recognized_receipt_path_evidence_current_machine_governance_proven',
  'recognized_receipt_path_evidence_live_issuer_status_proven',
  'recognized_receipt_path_evidence_live_state_proven',
  'recognized_receipt_path_evidence_key_custody_proven',
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
  'recognized_write_boarded',
  'recognition_refusal_taxonomy_sha256',
  'registry_public_key_material_included',
  'registry_receipt_contract_hash_bound',
  'required_authority_refusal_case_count',
  'required_recognition_refusal_case_count',
  'restart_consumed_authority_grant_refused',
  'rightful_issuance_proven',
  'runtime_profile_sha256',
  'runtime_profile_activation_performed',
  'same_process_signed_payload_replay_refused',
  'selected_profile_hash_bound',
  'service_artifact_verification_bound_to_service_proof',
  'service_proof_bound_to_generated_preflight',
  'sovereign_recognition',
  'state_append_after_grant_commit_burn_observed',
  'store_anchor_and_witness_joint_rollback_detection',
  'store_and_anchor_rollback_refused_while_witness_ahead',
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
  'trusted_issuer_registry_recognition_refusals_sha256',
  'trusted_issuer_registry_recognition_refusals_all_refused',
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
  'trusted_issuer_registry_current_machine_governance_proven',
  'trusted_issuer_registry_key_custody_proven',
  'trusted_issuer_registry_live_issuer_status_proven',
  'trusted_issuer_registry_live_state_proven',
  'trusted_issuer_registry_production_authority',
  'trusted_issuer_registry_production_downstream_recognition_proven',
  'trusted_issuer_registry_production_trust_registry_proven',
  'trusted_issuer_registry_public_external_attestation',
  'trusted_issuer_registry_real_non_operator_review',
  'trusted_issuer_registry_revocation_truth_proven',
  'trusted_issuer_registry_sovereign_recognition',
  'unrouted_records_paths_checked',
  'user_configuration_written',
  'fixture_rightful_issuance_path_evidenced',
  'consequence_lifecycle_closed',
  'mutation_authoritative_route',
  'consumed_authority_grant_store',
  'consumption_identity',
  'signed_payload_replay_identity',
  'consumed_store_write_model',
  'consumed_grant_store_witness_source',
  'verification_type',
  'verified',
]);

const TERMINAL_CHAIN_NESTED_ARTIFACT_BINDING_KEYS = Object.freeze([
  'generated_preflight_artifact_type',
  'generated_service_proof_artifact_type',
  'generated_preflight_artifact_body_sha256',
  'generated_service_proof_artifact_body_sha256',
  'generated_preflight_artifact_verified',
  'generated_service_proof_artifact_verified',
  'generated_service_proof_structural_self_integrity_verified',
  'generated_service_proof_artifact_identity_match_requires_expected_sha256',
  'generated_service_proof_verification_scope',
  'expected_generated_service_proof_artifact_body_sha256',
  'expected_generated_service_proof_artifact_body_sha256_matched',
  'preflight_artifact_hash_bound',
  'service_proof_source_preflight_hash_bound',
  'service_artifact_hash_bound',
  'service_artifact_verification_bound_to_service_proof',
  'creates_public_external_attestation',
  'proves_non_operator_review',
  'proves_current_machine_governance',
  'proves_production_downstream_recognition',
]);

const COVERAGE_MAP_BOUNDARY_KEYS = Object.freeze([
  'all_authority_refusals_before_consumption_and_mutation',
  'all_recognition_refusals_before_mutation',
  'artifact_hash_equivalence_with_fresh_run_claimed',
  'authority_refusal_case_count',
  'authority_refusal_taxonomy_sha256',
  'claim_boundary',
  'consequence_lifecycle_closed',
  'consumed_authority_grant_store',
  'consumed_grant_store_witness_source',
  'consumed_store_write_model',
  'consumption_identity',
  'counted_lanes',
  'current_machine_governance_proven',
  'evidence_model',
  'fixture_rightful_issuance_path_evidenced',
  'governed_lanes',
  'host_filesystem_path_toctou_closed',
  'input_fixture_sha256',
  'joint_rollback_reopened_authority_grant_reuse',
  'live_authority_proven',
  'live_probing',
  'metadata_partial_commit_burn_observed',
  'mutation_authoritative_route',
  'nested_preflight_artifact_body_sha256',
  'nested_service_proof_artifact_body_sha256',
  'portable_rightful_issuance_proven',
  'production_rightful_issuance_proven',
  'profile_sha256',
  'recognition_refusal_case_count',
  'recognition_refusal_taxonomy_sha256',
  'report_type',
  'restart_consumed_authority_grant_refused',
  'rightful_issuance_proven',
  'same_process_signed_payload_replay_refused',
  'signed_payload_replay_identity',
  'state_append_after_grant_commit_burn_observed',
  'store_anchor_and_witness_joint_rollback_detection',
  'store_and_anchor_rollback_refused_while_witness_ahead',
  'surface_governed',
  'surface_id',
  'terminal_chain_artifact_body_sha256',
]);

const PUBLIC_SAFE_GRANT_SUMMARY_KEYS = Object.freeze([
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

const TRUSTED_ISSUER_REGISTRY_RECOGNITION_CLAIM_BOUNDARY =
  'trusted issuer registry recognition over bundled local fixture evidence only; no live registry, live issuer status, key custody, revocation truth, production trust registry, production downstream recognition, production authority, sovereign recognition, public external attestation, or real non-operator review claim';

const TRUSTED_ISSUER_REGISTRY_RECOGNITION_NON_CLAIMS = Object.freeze([
  'This component recognizes only a bundled local trusted-issuer registry fixture.',
  'This component does not inspect a live trust registry, live issuer status, live hooks, live audit stores, runtime state, or production downstream systems.',
  'This component does not prove key custody, revocation truth, production trust-registry state, production downstream recognition, production authority, public external attestation, real non-operator review, sovereign recognition, current-machine governance, or coverage of unrouted paths.',
]);

const TRUSTED_ISSUER_REGISTRY_RECOGNITION_KEYS = Object.freeze([
  'claim_boundary',
  'decision',
  'evidence_model',
  'issuer_status',
  'live_probing',
  'malformed_registry_error_code',
  'malformed_registry_fail_closed_before_verdict',
  'malformed_registry_unsupported_field',
  'non_claims',
  'proves_key_custody',
  'proves_current_machine_governance',
  'proves_live_issuer_status',
  'proves_live_registry',
  'proves_production_authority',
  'proves_production_downstream_recognition',
  'proves_production_trust_registry',
  'proves_public_external_attestation',
  'proves_real_non_operator_review',
  'proves_revocation_truth',
  'proves_sovereign_recognition',
  'reason_code',
  'recognized',
  'registry_contract_evidence',
  'registry_evaluation_result_type',
  'registry_evidence_model',
  'registry_fixture_evaluated',
  'registry_fixture_validated',
  'registry_public_safe_summary_sha256',
  'registry_scope',
  'registry_to_recognition_rule_evaluated',
  'registry_trusted_issuer_count',
  'registry_type',
  'requested_scope',
  'required_audit_event_id_bound',
  'required_detail_hash_bound',
  'signature_valid',
  'verdict',
]);

const DEPLOYMENT_PROFILE_AUTHORITY_BRIDGE_KEYS = Object.freeze([
  'agent_supplied_authority_refused_before_mutation',
  'all_required_refusals_before_mutation',
  'claim_boundary',
  'deployment_profile_artifact_authoritative',
  'deployment_profile_authority_refusal_case_count',
  'deployment_profile_authority_refusal_case_ids',
  'deployment_profile_authority_refusal_service_proof_started',
  'deployment_profile_authority_refusals_before_mutation',
  'deployment_profile_authority_refusals_before_service_proof',
  'deployment_profile_id',
  'deployment_profile_sha256',
  'direct_api_refused_before_mutation',
  'downstream_refusal_proven',
  'current_machine_governance',
  'enterprise_readiness',
  'evidence_model',
  'external_attestation',
  'live_probing',
  'latest_profile_selection_refused_before_service_proof',
  'observed_refusal_case_count',
  'preflight_artifact_verified',
  'production_authority',
  'production_downstream_recognition',
  'proof_type',
  'profile_recognition_mismatch_refused_before_service_proof',
  'recognized_receipt_mutates_once',
  'recognized_state_entry_count_delta',
  'request_stream_authority_material_refused_before_service_proof',
  'request_stream_authority_material_accepted',
  'required_refusal_case_count',
  'runtime_profile_sha256',
  'selected_by_explicit_id_and_sha',
  'selects_latest_profile',
  'sovereign_recognition',
  'stale_deployment_profile_artifact_refused_before_service_proof',
  'unrouted_surface_coverage',
]);

function assertObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function hasExactObjectKeys(value, expectedKeys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return JSON.stringify(actual) === JSON.stringify(expected);
}

function assertExactObjectKeys(label, value, expectedKeys) {
  assertObject(value, label);
  if (!hasExactObjectKeys(value, expectedKeys)) {
    throw new Error(`${label} has unexpected fields`);
  }
}

function exactArrayMatches(value, expected) {
  return (
    Array.isArray(value) &&
    value.length === expected.length &&
    value.every((item, index) => item === expected[index])
  );
}

function assertExactArray(label, value, expected) {
  if (!exactArrayMatches(value, expected)) {
    throw new Error(`${label} drifted`);
  }
}

function assertEqual(label, value, expected) {
  if (value !== expected) {
    throw new Error(`${label} drifted`);
  }
}

function component(report, name) {
  const found = report.components.find((item) => item.component === name);
  if (!found) {
    throw new Error(`Local proof pack missing component: ${name}`);
  }
  return found;
}

function booleanMap(keys, value = false) {
  return Object.fromEntries(keys.map((key) => [key, value]));
}

function cloneNamedReceiptRefusals(value) {
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

function namedReceiptRefusalsPass(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
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
      refusal &&
      typeof refusal === 'object' &&
      !Array.isArray(refusal) &&
      refusal.case_id === expected.case_id &&
      refusal.reason_code === expected.reason_code &&
      refusal.refused_before_mutation === true &&
      Object.keys(refusal).sort().join(',') ===
        'case_id,reason_code,refused_before_mutation'
    );
  });
}

function namedReceiptRefusalsSha256(value) {
  return sha256hex(canonicalize({ named_receipt_refusals: value }));
}

function buildTrustedIssuerRegistryRecognition(registryComponent) {
  assertObject(registryComponent, 'Product proof path trusted issuer registry recognition component');
  return {
    evidence_model: registryComponent.evidence_model,
    registry_type: registryComponent.registry_type,
    registry_evidence_model: registryComponent.registry_evidence_model,
    registry_contract_evidence: registryComponent.registry_contract_evidence || 'not-provided',
    registry_public_safe_summary_sha256:
      registryComponent.registry_public_safe_summary_sha256 || 'not-provided',
    live_probing: registryComponent.live_probing,
    requested_scope: registryComponent.requested_scope,
    registry_scope: registryComponent.registry_scope,
    registry_fixture_validated: registryComponent.registry_fixture_validated,
    registry_fixture_evaluated: registryComponent.registry_fixture_evaluated,
    registry_to_recognition_rule_evaluated:
      registryComponent.registry_to_recognition_rule_evaluated,
    registry_evaluation_result_type:
      registryComponent.registry_evaluation_result_type,
    registry_trusted_issuer_count: registryComponent.registry_trusted_issuer_count,
    verdict: registryComponent.verdict,
    recognized: registryComponent.recognized,
    decision: registryComponent.decision,
    reason_code: registryComponent.reason_code,
    issuer_status: registryComponent.issuer_status,
    signature_valid: registryComponent.signature_valid,
    malformed_registry_unsupported_field:
      registryComponent.malformed_registry_unsupported_field,
    malformed_registry_error_code: registryComponent.malformed_registry_error_code,
    malformed_registry_fail_closed_before_verdict:
      registryComponent.malformed_registry_fail_closed_before_verdict,
    required_audit_event_id_bound: registryComponent.required_audit_event_id_bound,
    required_detail_hash_bound: registryComponent.required_detail_hash_bound,
    proves_live_registry: registryComponent.live_trust_registry_state,
    proves_live_issuer_status: registryComponent.live_issuer_status_proven,
    proves_key_custody: registryComponent.key_custody_proven,
    proves_current_machine_governance:
      registryComponent.current_machine_governance_proven,
    proves_revocation_truth: registryComponent.revocation_truth_proven,
    proves_production_trust_registry: registryComponent.production_trust_registry_proven,
    proves_production_downstream_recognition:
      registryComponent.production_downstream_recognition_proven,
    proves_production_authority: registryComponent.production_authority,
    proves_sovereign_recognition: registryComponent.sovereign_recognition,
    proves_public_external_attestation: registryComponent.public_external_attestation,
    proves_real_non_operator_review: registryComponent.real_non_operator_review,
    claim_boundary: TRUSTED_ISSUER_REGISTRY_RECOGNITION_CLAIM_BOUNDARY,
    non_claims: [...registryComponent.non_claims],
  };
}

function registryRecognitionGatePasses(registryRecognition) {
  return (
    registryRecognition.recognized === true &&
    registryRecognition.verdict === 'RECOGNIZED' &&
    registryRecognition.decision === 'accept' &&
    registryRecognition.reason_code === 'recognized' &&
    registryRecognition.issuer_status === 'active' &&
    registryRecognition.signature_valid === true &&
    registryRecognition.registry_type === 'trusted-receipt-issuers-v2' &&
    registryRecognition.registry_evidence_model ===
      'bundled-local-fixture-no-secret-registry-contract' &&
    registryRecognition.registry_contract_evidence ===
      'no-secret-registry-contract-v2' &&
    isSha256Hex(registryRecognition.registry_public_safe_summary_sha256) &&
    registryRecognition.live_probing === false &&
    registryRecognition.registry_fixture_validated === true &&
    registryRecognition.registry_fixture_evaluated === true &&
    registryRecognition.registry_to_recognition_rule_evaluated === true &&
    registryRecognition.registry_evaluation_result_type === 'downstream-recognition-rule-v1' &&
    registryRecognition.registry_trusted_issuer_count === 1 &&
    registryRecognition.malformed_registry_unsupported_field === true &&
    registryRecognition.malformed_registry_error_code === 'unsupported_registry_field' &&
    registryRecognition.malformed_registry_fail_closed_before_verdict === true &&
    registryRecognition.required_audit_event_id_bound === true &&
    registryRecognition.required_detail_hash_bound === true &&
    registryRecognition.proves_live_registry === false &&
    registryRecognition.proves_live_issuer_status === false &&
    registryRecognition.proves_key_custody === false &&
    registryRecognition.proves_current_machine_governance === false &&
    registryRecognition.proves_revocation_truth === false &&
    registryRecognition.proves_production_trust_registry === false &&
    registryRecognition.proves_production_downstream_recognition === false &&
    registryRecognition.proves_production_authority === false &&
    registryRecognition.proves_sovereign_recognition === false &&
    registryRecognition.proves_public_external_attestation === false &&
    registryRecognition.proves_real_non_operator_review === false &&
    registryRecognition.claim_boundary === TRUSTED_ISSUER_REGISTRY_RECOGNITION_CLAIM_BOUNDARY &&
    exactArrayMatches(
      registryRecognition.non_claims,
      TRUSTED_ISSUER_REGISTRY_RECOGNITION_NON_CLAIMS,
    )
  );
}

function isSha256Hex(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

function readJsonFile(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new Error(`Product proof path unable to read ${label}: ${err.message}`);
  }
}

function publicSafeGrantSummaryPasses(summary, expectedSha256) {
  return (
    hasExactObjectKeys(summary, PUBLIC_SAFE_GRANT_SUMMARY_KEYS) &&
    isSha256Hex(expectedSha256) &&
    sha256hex(canonicalize({ public_safe_grant_summary: summary })) ===
      expectedSha256 &&
    summary.summary_type ===
      'zlar-protected-records-fixture-authority-grant-summary-v1' &&
    summary.authority_domain_id === 'protected-records.local-disposable-fixture' &&
    summary.grantor_role_id === 'fixture-consequence-authority' &&
    summary.consequence_path === PRODUCT_PROOF_PATH_TERMINAL_SURFACE_ID &&
    isSha256Hex(summary.authority_grant_contract_sha256) &&
    summary.authority_grant_id ===
      `zlar-grant:v1:${summary.authority_grant_contract_sha256}` &&
    summary.valid_from_epoch < summary.expires_at_epoch &&
    summary.fixture_clock_model === 'fixed-hermetic-fixture-epoch' &&
    summary.one_use_effect_grant === true &&
    summary.replacement_requires_different_contract_sha256 === true &&
    summary.revocation_checked_at_fixture_evaluation_time === true &&
    summary.issuance_gate_evaluated_before_signing === true &&
    summary.effect_gate_evaluated_before_authority_grant_consumption === true &&
    summary.authority_grant_consumed_before_state_mutation === true &&
    summary.exact_runtime_kid_match_proven === true &&
    summary.exact_runtime_public_key_match_proven === true &&
    summary.receipt_bound_to_authority_grant === true &&
    summary.verified_signed_payload_identity_present === true &&
    summary.fixture_authority_grant_satisfied_at_evaluation_time === true &&
    summary.fixture_rightful_issuance_path_evidenced === true &&
    summary.rightful_issuance_scope ===
      'protected-records.local-disposable-fixture/one-hermetic-crossing' &&
    summary.runtime_private_issuer_identity_disclosed === false &&
    summary.runtime_private_grant_appointment_disclosed === false &&
    summary.portable_human_authorization_attestation === false &&
    summary.rightful_issuance_proven === false &&
    summary.portable_rightful_issuance_proven === false &&
    summary.production_rightful_issuance_proven === false &&
    summary.live_authority_proven === false &&
    summary.live_revocation_proven === false &&
    summary.current_machine_governance_proven === false &&
    summary.consequence_lifecycle_closed === false
  );
}

function extractRecognitionRefusalGroupCaseIds(groups) {
  return Object.fromEntries(
    Object.entries(groups || {}).map(([groupName, group]) => [
      groupName,
      Array.isArray(group?.cases) ? group.cases.map((item) => item.case_id) : [],
    ]),
  );
}

function expectedTerminalChainRecognitionRefusalGroupCaseIds() {
  return Object.fromEntries(
    Object.entries(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS)
      .map(([groupName, cases]) => [
        groupName,
        cases.map((item) => item.case_id),
      ]),
  );
}

function countRecognitionRefusalGroupCaseIds(caseIds) {
  return Object.values(caseIds).reduce((total, cases) => {
    return total + (Array.isArray(cases) ? cases.length : 0);
  }, 0);
}

function readCommittedTerminalChainArtifact() {
  const terminalChainArtifact = readJsonFile(
    PRODUCT_PROOF_PATH_TERMINAL_CHAIN_ARTIFACT_PATH,
    'committed installed runtime-profile terminal-chain artifact',
  );
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(
    terminalChainArtifact,
  );
  if (
    terminalChainArtifact.integrity.body_sha256 !==
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256
  ) {
    throw new Error('Product proof path committed terminal-chain artifact identity drifted');
  }
  return terminalChainArtifact;
}

function buildCommittedTerminalChainBoundary() {
  const terminalChainArtifact = readCommittedTerminalChainArtifact();
  const terminalChain = terminalChainArtifact.payload.chain;
  assertProtectedRecordsInstalledRuntimeProfileTerminalChain(terminalChain);
  const authorityGrantContractSha256 =
    terminalChain.generated_service_proof.public_safe_grant_summary
      .authority_grant_contract_sha256;
  const authorityGrantStatus = protectedRecordsFixtureAuthorityGrantStatus(
    authorityGrantContractSha256,
  );
  if (authorityGrantStatus.fresh_fixture_rightful_projection_allowed !== true) {
    const reason = protectedRecordsFixtureAuthorityGrantEffectStatusReason(
      authorityGrantContractSha256,
    );
    throw new Error(
      `Product proof path committed terminal-chain fixture-rightful projection refused: ${reason.code}`,
    );
  }
  const terminalChainArtifactVerification =
    verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(
      terminalChainArtifact,
      {
        expectedArtifactBodySha256:
          PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
      },
    );
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification(
    terminalChainArtifactVerification,
  );
  return buildTerminalChainBoundary({
    terminalChain,
    terminalChainArtifactVerification,
  });
}

function buildCoverageMapBoundary() {
  const rawInput = readFileSync(PRODUCT_PROOF_PATH_COVERAGE_MAP_FIXTURE_PATH, 'utf8');
  const input = JSON.parse(rawInput);
  const report = buildGovernedSurfaceCoverageMap(input);
  assertGovernedSurfaceCoverageMap(report);
  const surface = report.surfaces.find((item) =>
    item.surface_id === PRODUCT_PROOF_PATH_TERMINAL_SURFACE_ID
  );
  const artifact = input.installedRuntimeProfileTerminalChainLane
    ?.installed_runtime_profile_terminal_chain_artifact;
  const nestedArtifacts = artifact?.payload?.chain?.nested_artifacts || {};
  const rightful = surface?.evidence?.rightful_issuance || {};
  const boundaries = surface?.evidence?.boundaries || {};
  const route = surface?.evidence?.route || {};
  const refusal = surface?.evidence?.downstream_refusal || {};
  return {
    report_type: report.report_type,
    input_fixture_sha256: sha256hex(rawInput),
    evidence_model: report.evidence_model?.source || 'not-provided',
    live_probing: report.evidence_model?.live_probing_performed === true,
    governed_lanes: report.counts?.governed_lanes ?? 0,
    counted_lanes: report.counts?.counted_lanes ?? 0,
    surface_id: surface?.surface_id || 'not-provided',
    surface_governed: surface?.governed === true,
    profile_sha256: surface?.issuer_identity?.recognition_anchor_id || 'not-provided',
    mutation_authoritative_route:
      route.mutation_authoritative_route || 'not-provided',
    consumed_authority_grant_store:
      route.consumed_authority_grant_store || 'not-provided',
    consumption_identity: route.consumption_identity || 'not-provided',
    signed_payload_replay_identity:
      route.signed_payload_replay_identity || 'not-provided',
    consumed_grant_store_witness_source:
      route.consumed_grant_store_witness_source || 'not-provided',
    consumed_store_write_model:
      route.consumed_store_write_model || 'not-provided',
    recognition_refusal_case_count:
      refusal.recognition_refusals?.required_case_count ?? 0,
    all_recognition_refusals_before_mutation:
      refusal.recognition_refusals?.all_refused_before_mutation === true,
    authority_refusal_case_count:
      refusal.authority_refusals?.required_case_count ?? 0,
    authority_refusal_taxonomy_sha256:
      refusal.authority_refusals?.taxonomy_sha256 || 'not-provided',
    all_authority_refusals_before_consumption_and_mutation:
      refusal.authority_refusals?.all_refused_before_consumption_and_mutation ===
      true,
    recognition_refusal_taxonomy_sha256:
      refusal.recognition_refusals?.taxonomy_sha256 || 'not-provided',
    same_process_signed_payload_replay_refused:
      refusal.same_process_signed_payload_replay_refused === true,
    restart_consumed_authority_grant_refused:
      refusal.restart_consumed_authority_grant_refused === true,
    fixture_rightful_issuance_path_evidenced:
      rightful.fixture_rightful_issuance_path_evidenced === true,
    rightful_issuance_proven: rightful.rightful_issuance_proven === true,
    portable_rightful_issuance_proven:
      rightful.portable_rightful_issuance_proven === true,
    production_rightful_issuance_proven:
      rightful.production_rightful_issuance_proven === true,
    live_authority_proven: rightful.live_authority_proven === true,
    current_machine_governance_proven:
      rightful.current_machine_governance_proven === true,
    consequence_lifecycle_closed:
      rightful.consequence_lifecycle_closed === true,
    state_append_after_grant_commit_burn_observed:
      boundaries.state_append_after_grant_commit_burn_observed === true,
    metadata_partial_commit_burn_observed:
      boundaries.metadata_partial_commit_burn_observed === true,
    store_and_anchor_rollback_refused_while_witness_ahead:
      boundaries.store_and_anchor_rollback_refused_while_witness_ahead === true,
    store_anchor_and_witness_joint_rollback_detection:
      boundaries.store_anchor_and_witness_joint_rollback_detection === true,
    joint_rollback_reopened_authority_grant_reuse:
      boundaries.joint_rollback_reopened_authority_grant_reuse === true,
    host_filesystem_path_toctou_closed:
      boundaries.host_filesystem_path_toctou_closed === true,
    terminal_chain_artifact_body_sha256:
      artifact?.integrity?.body_sha256 || 'not-provided',
    nested_preflight_artifact_body_sha256:
      nestedArtifacts.generated_preflight_artifact?.integrity?.body_sha256 ||
      'not-provided',
    nested_service_proof_artifact_body_sha256:
      nestedArtifacts.generated_service_proof_artifact?.integrity?.body_sha256 ||
      'not-provided',
    artifact_hash_equivalence_with_fresh_run_claimed: false,
    claim_boundary: PRODUCT_PROOF_PATH_COVERAGE_MAP_BOUNDARY,
  };
}

function buildDeploymentProfileAuthorityBridge() {
  const inputs = readSampleProtectedRecordsOneTerminalDeploymentProfileInputs();
  const terminalChain = readCommittedTerminalChainArtifact().payload.chain;
  const mirror = terminalChain.terminal_chain
    .deployment_profile_authority_refusal_mirror;
  const serviceProof = terminalChain.nested_artifacts
    .generated_service_proof_artifact.payload.proof;
  const refusalCases = serviceProof.refusal_cases;
  const agentSuppliedAuthorityRefusedBeforeMutation = refusalCases.some(
    (item) =>
      item.case_id ===
        'agent_supplied_recognition_rule_refused_before_runtime_mutation' &&
      item.boarded === false &&
      item.service_write_accepted === false &&
      item.state_entry_count_delta === 0,
  );
  const directApiRefusedBeforeMutation = refusalCases
    .filter((item) => item.case_id.startsWith('direct_api_'))
    .every((item) =>
      item.boarded === false &&
      item.service_write_accepted === false &&
      item.state_entry_count_delta === 0
    );
  return {
    proof_type: mirror.source_proof_type,
    evidence_model: mirror.evidence_model,
    live_probing: false,
    claim_boundary: ONE_TERMINAL_DEPLOYMENT_PROFILE_SAFE_CLAIM_CEILING,
    deployment_profile_id: inputs.deploymentProfile.profile_id,
    deployment_profile_sha256:
      oneTerminalDeploymentProfileSha256(inputs.deploymentProfile),
    runtime_profile_sha256: mirror.source_runtime_profile_sha256,
    deployment_profile_artifact_authoritative:
      inputs.deploymentProfile.authority_boundary
        .deployment_owned_profile_artifact,
    deployment_profile_authority_refusal_case_count:
      mirror.deployment_profile_authority_refusal_case_count,
    deployment_profile_authority_refusal_case_ids: [
      ...mirror.deployment_profile_authority_refusal_case_ids,
    ],
    deployment_profile_authority_refusals_before_service_proof:
      mirror.deployment_profile_authority_refusals_before_service_proof,
    deployment_profile_authority_refusals_before_mutation:
      mirror.deployment_profile_authority_refusals_before_mutation,
    deployment_profile_authority_refusal_service_proof_started:
      mirror.deployment_profile_authority_refusal_service_proof_started,
    stale_deployment_profile_artifact_refused_before_service_proof:
      mirror.stale_deployment_profile_artifact_refused_before_service_proof,
    profile_recognition_mismatch_refused_before_service_proof:
      mirror.profile_recognition_mismatch_refused_before_service_proof,
    latest_profile_selection_refused_before_service_proof:
      mirror.latest_profile_selection_refused_before_service_proof,
    request_stream_authority_material_refused_before_service_proof:
      mirror.request_stream_authority_material_refused_before_service_proof,
    selected_by_explicit_id_and_sha:
      inputs.deploymentProfile.selected_runtime_profile
        .selected_by_explicit_id_and_sha,
    selects_latest_profile:
      inputs.deploymentProfile.selected_runtime_profile.selects_latest_profile,
    preflight_artifact_verified: terminalChain.generated_preflight.verified,
    recognized_receipt_mutates_once:
      serviceProof.recognized_boarding.boarded === true &&
      serviceProof.recognized_boarding.state_entry_count_delta === 1,
    recognized_state_entry_count_delta:
      serviceProof.recognized_boarding.state_entry_count_delta,
    required_refusal_case_count:
      terminalChain.generated_service_proof.required_recognition_refusal_cases.length,
    observed_refusal_case_count:
      refusalCases.length,
    all_required_refusals_before_mutation:
      terminalChain.generated_service_proof.all_recognition_refusals_before_mutation,
    agent_supplied_authority_refused_before_mutation:
      agentSuppliedAuthorityRefusedBeforeMutation,
    direct_api_refused_before_mutation:
      directApiRefusedBeforeMutation,
    downstream_refusal_proven: true,
    request_stream_authority_material_accepted:
      inputs.deploymentProfile.authority_boundary
        .request_stream_authority_material_accepted,
    current_machine_governance: mirror.current_machine_governance,
    production_downstream_recognition:
      mirror.production_downstream_recognition,
    production_authority: mirror.production_authority,
    enterprise_readiness: mirror.enterprise_readiness,
    external_attestation: mirror.external_attestation,
    sovereign_recognition: mirror.sovereign_recognition,
    unrouted_surface_coverage: mirror.unrouted_surface_coverage,
  };
}

function deploymentProfileAuthorityBridgePasses(bridge) {
  return (
    bridge &&
    bridge.proof_type ===
      'zlar-protected-records-one-terminal-deployment-profile-proof-v1' &&
    bridge.evidence_model ===
      'local-fixture-one-terminal-deployment-profile-authority-bridge' &&
    bridge.live_probing === false &&
    bridge.claim_boundary === ONE_TERMINAL_DEPLOYMENT_PROFILE_SAFE_CLAIM_CEILING &&
    isSha256Hex(bridge.deployment_profile_sha256) &&
    isSha256Hex(bridge.runtime_profile_sha256) &&
    bridge.deployment_profile_artifact_authoritative === true &&
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
    bridge.request_stream_authority_material_refused_before_service_proof === true &&
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

function buildTerminalChainBoundary({
  terminalChain,
  terminalChainArtifactVerification,
}) {
  const serviceProof = terminalChain?.nested_artifacts
    ?.generated_service_proof_artifact?.payload?.proof || {};
  const serviceBoundary = serviceProof.service_boundary || {};
  const serviceConfigProvenance = serviceProof.service_config_provenance || {};
  const binding =
    terminalChainArtifactVerification.trusted_issuer_registry_recognition_binding;
  const refusals = binding.trusted_issuer_registry_recognition_refusals;
  const recognizedReceiptPathEvidence =
    terminalChain?.terminal_chain?.recognized_receipt_path_evidence || {};
  const artifactVerificationRecognizedReceiptPathEvidence =
    terminalChainArtifactVerification.recognized_receipt_path_evidence || {};
  const recognizedReceiptPathEvidenceSha256 =
    terminalChain?.terminal_chain?.recognized_receipt_path_evidence_sha256 ||
    'not-provided';
  const artifactVerificationRecognizedReceiptPathEvidenceSha256 =
    terminalChainArtifactVerification.recognized_receipt_path_evidence_sha256 ||
    'not-provided';
  const recognitionRefusalGroupCaseIds = extractRecognitionRefusalGroupCaseIds(
    terminalChainArtifactVerification.recognition_refusal_groups,
  );
  const expectedRecognitionRefusalGroupCaseIds =
    expectedTerminalChainRecognitionRefusalGroupCaseIds();
  return {
    verification_type: terminalChainArtifactVerification.verification_type,
    verified: terminalChainArtifactVerification.verified,
    artifact_type: terminalChainArtifactVerification.artifact_type,
    body_sha256: terminalChainArtifactVerification.body_sha256,
    payload_type: terminalChainArtifactVerification.payload_type,
    evidence_model: terminalChainArtifactVerification.evidence_model,
    live_probing: terminalChainArtifactVerification.live_probing,
    claim_boundary: PRODUCT_PROOF_PATH_TERMINAL_CHAIN_BOUNDARY,
    generated_installed_root_preflighted:
      terminalChainArtifactVerification.generated_installed_root_preflighted,
    generated_preflight_artifact_consumed_by_service_proof:
      terminalChainArtifactVerification
        .generated_preflight_artifact_consumed_by_service_proof,
    generated_service_proof_artifact_verified:
      terminalChainArtifactVerification.generated_service_proof_artifact_verified,
    service_proof_bound_to_generated_preflight:
      terminalChainArtifactVerification.service_proof_bound_to_generated_preflight,
    service_artifact_verification_bound_to_service_proof:
      terminalChainArtifactVerification
        .service_artifact_verification_bound_to_service_proof,
    recognized_write_boarded:
      terminalChainArtifactVerification.recognized_write_boarded,
    missing_receipt_refused_before_mutation:
      terminalChainArtifactVerification.missing_receipt_refused_before_mutation,
    invalid_receipt_refused_before_mutation:
      terminalChainArtifactVerification.invalid_receipt_refused_before_mutation,
    runtime_profile_sha256:
      terminalChainArtifactVerification.runtime_profile_sha256,
    mutation_authoritative_route:
      serviceBoundary.mutation_authoritative_route || 'not-provided',
    consumed_authority_grant_store:
      serviceBoundary.consumed_authority_grant_store || 'not-provided',
    consumption_identity:
      serviceBoundary.consumption_identity || 'not-provided',
    signed_payload_replay_identity:
      serviceBoundary.signed_payload_replay_identity || 'not-provided',
    consumed_store_write_model:
      serviceBoundary.consumed_store_write_model || 'not-provided',
    consumed_grant_store_witness_source:
      serviceConfigProvenance.consumed_grant_store_witness_source ||
      'not-provided',
    all_required_recognition_refusals_before_mutation:
      terminalChainArtifactVerification
        .all_required_recognition_refusals_before_mutation,
    required_recognition_refusal_case_count:
      terminalChainArtifactVerification.required_recognition_refusal_case_count,
    observed_recognition_refusal_case_count:
      terminalChainArtifactVerification.observed_recognition_refusal_case_count,
    recognition_refusal_taxonomy_sha256:
      terminalChainArtifactVerification.recognition_refusal_taxonomy_sha256,
    all_required_authority_refusals_before_consumption_and_mutation:
      terminalChainArtifactVerification
        .all_required_authority_refusals_before_consumption_and_mutation,
    required_authority_refusal_case_count:
      terminalChainArtifactVerification.required_authority_refusal_case_count,
    observed_authority_refusal_case_count:
      terminalChainArtifactVerification.observed_authority_refusal_case_count,
    authority_refusal_taxonomy_sha256:
      terminalChainArtifactVerification.authority_refusal_taxonomy_sha256,
    same_process_signed_payload_replay_refused:
      terminalChainArtifactVerification
        .same_process_signed_payload_replay_refused,
    restart_consumed_authority_grant_refused:
      terminalChainArtifactVerification.restart_consumed_authority_grant_refused,
    public_safe_grant_summary: JSON.parse(JSON.stringify(
      terminalChainArtifactVerification.public_safe_grant_summary,
    )),
    public_safe_grant_summary_sha256:
      terminalChainArtifactVerification.public_safe_grant_summary_sha256,
    fixture_rightful_issuance_path_evidenced:
      terminalChainArtifactVerification
        .fixture_rightful_issuance_path_evidenced,
    rightful_issuance_proven:
      terminalChainArtifactVerification.rightful_issuance_proven,
    portable_rightful_issuance_proven:
      terminalChainArtifactVerification.portable_rightful_issuance_proven,
    production_rightful_issuance_proven:
      terminalChainArtifactVerification.production_rightful_issuance_proven,
    live_authority_proven:
      terminalChainArtifactVerification.live_authority_proven,
    consequence_lifecycle_closed:
      terminalChainArtifactVerification.consequence_lifecycle_closed,
    state_append_after_grant_commit_burn_observed:
      terminalChainArtifactVerification
        .state_append_after_grant_commit_burn_observed,
    metadata_partial_commit_burn_observed:
      terminalChainArtifactVerification.metadata_partial_commit_burn_observed,
    store_and_anchor_rollback_refused_while_witness_ahead:
      terminalChainArtifactVerification
        .store_and_anchor_rollback_refused_while_witness_ahead,
    store_anchor_and_witness_joint_rollback_detection:
      terminalChainArtifactVerification
        .store_anchor_and_witness_joint_rollback_detection,
    joint_rollback_reopened_authority_grant_reuse:
      terminalChainArtifactVerification
        .joint_rollback_reopened_authority_grant_reuse,
    host_filesystem_path_toctou_closed:
      terminalChainArtifactVerification.host_filesystem_path_toctou_closed,
    recognition_contract_sha256:
      terminalChainArtifactVerification.recognition_contract_sha256,
    named_receipt_refusals: cloneNamedReceiptRefusals(
      terminalChainArtifactVerification.named_receipt_refusals,
    ),
    named_receipt_refusals_sha256:
      terminalChainArtifactVerification.named_receipt_refusals_sha256,
    recognition_refusal_groups_sha256:
      terminalChainArtifactVerification.recognition_refusal_groups_sha256,
    recognition_refusal_group_count:
      Object.keys(recognitionRefusalGroupCaseIds).length,
    recognition_refusal_group_case_count:
      countRecognitionRefusalGroupCaseIds(recognitionRefusalGroupCaseIds),
    recognition_refusal_group_case_ids: recognitionRefusalGroupCaseIds,
    recognition_refusal_group_case_ids_preserved:
      JSON.stringify(recognitionRefusalGroupCaseIds) ===
      JSON.stringify(expectedRecognitionRefusalGroupCaseIds),
    trusted_issuer_registry_recognition_binding_sha256:
      terminalChainArtifactVerification
        .trusted_issuer_registry_recognition_binding_sha256,
    trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification:
      binding.binding_sha256 ===
      terminalChainArtifactVerification
        .trusted_issuer_registry_recognition_binding_sha256,
    trusted_issuer_registry_recognition_verdict: binding.verdict,
    trusted_issuer_registry_recognition_recognized: binding.recognized,
    trusted_issuer_registry_recognition_decision: binding.decision,
    trusted_issuer_registry_recognition_reason_code: binding.reason_code,
    trusted_issuer_registry_recognition_issuer_status: binding.issuer_status,
    trusted_issuer_registry_recognition_signature_valid:
      binding.signature_valid,
    trusted_issuer_registry_recognition_registry_contract_evidence:
      binding.registry_contract_evidence || 'not-provided',
    trusted_issuer_registry_recognition_registry_public_safe_summary_sha256:
      binding.registry_public_safe_summary_sha256 || 'not-provided',
    trusted_issuer_registry_recognition_registry_fixture_validated:
      binding.registry_fixture_validated,
    trusted_issuer_registry_recognition_registry_fixture_evaluated:
      binding.registry_fixture_evaluated,
    trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated:
      binding.registry_to_recognition_rule_evaluated,
    trusted_issuer_registry_recognition_registry_evaluation_result_type:
      binding.registry_evaluation_result_type,
    trusted_issuer_registry_recognition_registry_trusted_issuer_count:
      binding.registry_trusted_issuer_count,
    trusted_issuer_registry_recognition_required_audit_event_id_bound:
      binding.required_audit_event_id_bound,
    trusted_issuer_registry_recognition_required_detail_hash_bound:
      binding.required_detail_hash_bound,
    trusted_issuer_registry_recognition_registry_fixture_contract_sha256:
      binding.registry_fixture_contract_sha256,
    trusted_issuer_registry_recognition_receipt_payload_contract_sha256:
      binding.receipt_payload_contract_sha256,
    trusted_issuer_registry_recognition_refusals_sha256:
      binding.trusted_issuer_registry_recognition_refusals_sha256,
    trusted_issuer_registry_recognition_refusal_hash_matches_binding:
      binding.trusted_issuer_registry_recognition_refusals_sha256 ===
      terminalChainArtifactVerification
        .trusted_issuer_registry_recognition_binding
        .trusted_issuer_registry_recognition_refusals_sha256,
    trusted_issuer_registry_recognition_refusal_case_count:
      refusals.case_count,
    trusted_issuer_registry_recognition_refusals_all_refused:
      refusals.all_refused,
    trusted_issuer_registry_recognition_refusal_case_ids:
      refusals.cases.map((item) => item.case_id),
    trusted_issuer_registry_recognition_refusal_reason_codes:
      refusals.cases.map((item) => item.reason_code),
    recognized_receipt_path_evidence_sha256:
      recognizedReceiptPathEvidenceSha256,
    recognized_receipt_path_evidence_artifact_verification_sha256:
      artifactVerificationRecognizedReceiptPathEvidenceSha256,
    recognized_receipt_path_evidence_sha256_matches_artifact_verification:
      recognizedReceiptPathEvidenceSha256 ===
      artifactVerificationRecognizedReceiptPathEvidenceSha256,
    recognized_receipt_path_evidence_bound_to_artifact_body:
      terminalChainArtifactVerification
        .recognized_receipt_path_evidence_bound_to_artifact_body === true,
    recognized_receipt_path_evidence_source_binding_sha256:
      artifactVerificationRecognizedReceiptPathEvidence.source_binding_sha256 ||
      'not-provided',
    recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding:
      recognizedReceiptPathEvidence.source_binding_sha256 === binding.binding_sha256 &&
      artifactVerificationRecognizedReceiptPathEvidence.source_binding_sha256 ===
        binding.binding_sha256,
    recognized_receipt_path_evidence_verdict:
      artifactVerificationRecognizedReceiptPathEvidence.verdict || 'not-provided',
    recognized_receipt_path_evidence_recognized:
      artifactVerificationRecognizedReceiptPathEvidence.recognized === true,
    recognized_receipt_path_evidence_receipt_envelope_included:
      artifactVerificationRecognizedReceiptPathEvidence.receipt_envelope_included ===
      true,
    recognized_receipt_path_evidence_registry_public_key_material_included:
      artifactVerificationRecognizedReceiptPathEvidence
        .registry_public_key_material_included === true,
    recognized_receipt_path_evidence_artifact_crypto_reproducible:
      artifactVerificationRecognizedReceiptPathEvidence
        .cryptographic_evidence_reproducible_from_artifact === true,
    recognized_receipt_path_evidence_live_state_proven:
      artifactVerificationRecognizedReceiptPathEvidence.live_trust_registry_state ===
      true,
    recognized_receipt_path_evidence_live_issuer_status_proven:
      artifactVerificationRecognizedReceiptPathEvidence.live_issuer_status_proven ===
      true,
    recognized_receipt_path_evidence_key_custody_proven:
      artifactVerificationRecognizedReceiptPathEvidence.key_custody_proven === true,
    recognized_receipt_path_evidence_revocation_truth_proven:
      artifactVerificationRecognizedReceiptPathEvidence.revocation_truth_proven ===
      true,
    recognized_receipt_path_evidence_production_downstream_recognition_proven:
      artifactVerificationRecognizedReceiptPathEvidence
        .production_downstream_recognition_proven === true,
    recognized_receipt_path_evidence_public_external_attestation:
      artifactVerificationRecognizedReceiptPathEvidence.public_external_attestation ===
      true,
    recognized_receipt_path_evidence_sovereign_recognition:
      artifactVerificationRecognizedReceiptPathEvidence.sovereign_recognition ===
      true,
    recognized_receipt_path_evidence_current_machine_governance_proven:
      artifactVerificationRecognizedReceiptPathEvidence
        .current_machine_governance_proven === true,
    registry_receipt_contract_hash_bound:
      binding.registry_receipt_contract_hash_bound,
    selected_profile_hash_bound: binding.selected_profile_hash_bound,
    recognition_contract_hash_bound: binding.recognition_contract_hash_bound,
    terminal_chain_decision_bound: binding.terminal_chain_decision_bound,
    registry_public_key_material_included:
      binding.registry_public_key_material_included,
    receipt_envelope_included: binding.receipt_envelope_included,
    cryptographic_evidence_reproducible_from_artifact:
      binding.cryptographic_evidence_reproducible_from_artifact,
    trusted_issuer_registry_live_state_proven:
      binding.live_trust_registry_state,
    trusted_issuer_registry_live_issuer_status_proven:
      binding.live_issuer_status_proven,
    trusted_issuer_registry_key_custody_proven:
      binding.key_custody_proven,
    trusted_issuer_registry_revocation_truth_proven:
      binding.revocation_truth_proven,
    trusted_issuer_registry_production_trust_registry_proven:
      binding.production_trust_registry_proven,
    trusted_issuer_registry_production_downstream_recognition_proven:
      binding.production_downstream_recognition_proven,
    trusted_issuer_registry_production_authority:
      binding.production_authority,
    trusted_issuer_registry_sovereign_recognition:
      binding.sovereign_recognition,
    trusted_issuer_registry_public_external_attestation:
      binding.public_external_attestation,
    trusted_issuer_registry_real_non_operator_review:
      binding.real_non_operator_review,
    trusted_issuer_registry_current_machine_governance_proven:
      binding.current_machine_governance_proven,
    nested_artifact_binding: {
      ...terminalChainArtifactVerification.nested_artifact_binding,
    },
    persistent_runtime_profile_installed:
      terminalChainArtifactVerification.persistent_runtime_profile_installed,
    runtime_profile_activation_performed:
      terminalChainArtifactVerification.runtime_profile_activation_performed,
    hook_configuration_written:
      terminalChainArtifactVerification.hook_configuration_written,
    user_configuration_written:
      terminalChainArtifactVerification.user_config_written,
    machine_configuration_written:
      terminalChainArtifactVerification.machine_config_written,
    current_machine_governance_proven:
      terminalChainArtifactVerification.current_machine_governance_proven,
    production_records_service_checked:
      terminalChainArtifactVerification.production_records_service_checked,
    production_downstream_recognition:
      terminalChainArtifactVerification.production_downstream_recognition,
    external_attestation: terminalChainArtifactVerification.external_attestation,
    sovereign_recognition: terminalChainArtifactVerification.sovereign_recognition,
    unrouted_records_paths_checked:
      terminalChainArtifactVerification.unrouted_records_paths_checked,
    known_open_boundaries: [...terminalChain.known_open_boundaries],
  };
}

function terminalChainBoundaryPasses(boundary) {
  if (!boundary || typeof boundary !== 'object') {
    return false;
  }
  const expectedRegistryRefusalCaseIds =
    REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS
      .map((item) => item.case_id);
  const expectedRegistryRefusalReasonCodes =
    REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS
      .map((item) => item.reason_code);
  const expectedRecognitionRefusalGroupCaseIds =
    expectedTerminalChainRecognitionRefusalGroupCaseIds();
  return (
    boundary.verification_type ===
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_VERIFICATION_TYPE &&
    boundary.verified === true &&
    boundary.artifact_type ===
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_TYPE &&
    boundary.payload_type ===
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TYPE &&
    boundary.evidence_model ===
      'fresh-local-disposable-installed-runtime-profile-terminal-chain' &&
    boundary.live_probing === false &&
    boundary.claim_boundary === PRODUCT_PROOF_PATH_TERMINAL_CHAIN_BOUNDARY &&
    isSha256Hex(boundary.body_sha256) &&
    boundary.generated_installed_root_preflighted === true &&
    boundary.generated_preflight_artifact_consumed_by_service_proof === true &&
    boundary.generated_service_proof_artifact_verified === true &&
    boundary.service_proof_bound_to_generated_preflight === true &&
    boundary.service_artifact_verification_bound_to_service_proof === true &&
    boundary.recognized_write_boarded === true &&
    boundary.missing_receipt_refused_before_mutation === true &&
    boundary.invalid_receipt_refused_before_mutation === true &&
    isSha256Hex(boundary.runtime_profile_sha256) &&
    boundary.mutation_authoritative_route ===
      EXACT_RUNTIME_MUTATION_AUTHORITATIVE_ROUTE &&
    boundary.consumed_authority_grant_store ===
      'persistent-single-use-authority-grant-contract-sha256-store' &&
    boundary.consumption_identity === 'authority-grant-contract-sha256' &&
    boundary.signed_payload_replay_identity ===
      'verified-signed-payload-sha256' &&
    boundary.consumed_store_write_model ===
      'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness' &&
    boundary.consumed_grant_store_witness_source ===
      'launcher-owned-local-proof-witness' &&
    boundary.all_required_recognition_refusals_before_mutation === true &&
    boundary.required_recognition_refusal_case_count === 18 &&
    boundary.observed_recognition_refusal_case_count === 18 &&
    isSha256Hex(boundary.recognition_refusal_taxonomy_sha256) &&
    boundary
      .all_required_authority_refusals_before_consumption_and_mutation ===
      true &&
    boundary.required_authority_refusal_case_count ===
      REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length &&
    boundary.observed_authority_refusal_case_count ===
      REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length &&
    isSha256Hex(boundary.authority_refusal_taxonomy_sha256) &&
    boundary.same_process_signed_payload_replay_refused === true &&
    boundary.restart_consumed_authority_grant_refused === true &&
    publicSafeGrantSummaryPasses(
      boundary.public_safe_grant_summary,
      boundary.public_safe_grant_summary_sha256,
    ) &&
    boundary.fixture_rightful_issuance_path_evidenced === true &&
    boundary.rightful_issuance_proven === false &&
    boundary.portable_rightful_issuance_proven === false &&
    boundary.production_rightful_issuance_proven === false &&
    boundary.live_authority_proven === false &&
    boundary.consequence_lifecycle_closed === false &&
    boundary.state_append_after_grant_commit_burn_observed === true &&
    boundary.metadata_partial_commit_burn_observed === true &&
    boundary.store_and_anchor_rollback_refused_while_witness_ahead === true &&
    boundary.store_anchor_and_witness_joint_rollback_detection === false &&
    boundary.joint_rollback_reopened_authority_grant_reuse === true &&
    boundary.host_filesystem_path_toctou_closed === false &&
    isSha256Hex(boundary.recognition_contract_sha256) &&
    namedReceiptRefusalsPass(boundary.named_receipt_refusals) &&
    isSha256Hex(boundary.named_receipt_refusals_sha256) &&
    boundary.named_receipt_refusals_sha256 ===
      namedReceiptRefusalsSha256(boundary.named_receipt_refusals) &&
    isSha256Hex(boundary.recognition_refusal_groups_sha256) &&
    boundary.recognition_refusal_group_count ===
      Object.keys(expectedRecognitionRefusalGroupCaseIds).length &&
    boundary.recognition_refusal_group_case_count === 18 &&
    JSON.stringify(boundary.recognition_refusal_group_case_ids) ===
      JSON.stringify(expectedRecognitionRefusalGroupCaseIds) &&
    boundary.recognition_refusal_group_case_ids_preserved === true &&
    isSha256Hex(boundary.trusted_issuer_registry_recognition_binding_sha256) &&
    boundary.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification ===
      true &&
    boundary.trusted_issuer_registry_recognition_verdict === 'RECOGNIZED' &&
    boundary.trusted_issuer_registry_recognition_recognized === true &&
    boundary.trusted_issuer_registry_recognition_decision === 'accept' &&
    boundary.trusted_issuer_registry_recognition_reason_code === 'recognized' &&
    boundary.trusted_issuer_registry_recognition_issuer_status === 'active' &&
    boundary.trusted_issuer_registry_recognition_signature_valid === true &&
    boundary.trusted_issuer_registry_recognition_registry_fixture_validated === true &&
    boundary.trusted_issuer_registry_recognition_registry_fixture_evaluated === true &&
    boundary
      .trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated ===
      true &&
    boundary
      .trusted_issuer_registry_recognition_registry_evaluation_result_type ===
      'downstream-recognition-rule-v1' &&
    boundary.trusted_issuer_registry_recognition_registry_trusted_issuer_count ===
      1 &&
    boundary.trusted_issuer_registry_recognition_required_audit_event_id_bound ===
      true &&
    boundary.trusted_issuer_registry_recognition_required_detail_hash_bound ===
      true &&
    isSha256Hex(
      boundary.trusted_issuer_registry_recognition_registry_fixture_contract_sha256,
    ) &&
    boundary.trusted_issuer_registry_recognition_registry_contract_evidence ===
      'no-secret-registry-contract-v2' &&
    isSha256Hex(
      boundary
        .trusted_issuer_registry_recognition_registry_public_safe_summary_sha256,
    ) &&
    isSha256Hex(
      boundary.trusted_issuer_registry_recognition_receipt_payload_contract_sha256,
    ) &&
    isSha256Hex(boundary.trusted_issuer_registry_recognition_refusals_sha256) &&
    boundary.trusted_issuer_registry_recognition_refusal_hash_matches_binding ===
      true &&
    boundary.trusted_issuer_registry_recognition_refusal_case_count ===
      expectedRegistryRefusalCaseIds.length &&
    boundary.trusted_issuer_registry_recognition_refusals_all_refused === true &&
    JSON.stringify(boundary.trusted_issuer_registry_recognition_refusal_case_ids) ===
      JSON.stringify(expectedRegistryRefusalCaseIds) &&
    JSON.stringify(boundary.trusted_issuer_registry_recognition_refusal_reason_codes) ===
      JSON.stringify(expectedRegistryRefusalReasonCodes) &&
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
      false &&
    boundary.registry_receipt_contract_hash_bound === true &&
    boundary.selected_profile_hash_bound === true &&
    boundary.recognition_contract_hash_bound === true &&
    boundary.terminal_chain_decision_bound === true &&
    boundary.registry_public_key_material_included === false &&
    boundary.receipt_envelope_included === false &&
    boundary.cryptographic_evidence_reproducible_from_artifact === false &&
    boundary.trusted_issuer_registry_live_state_proven === false &&
    boundary.trusted_issuer_registry_live_issuer_status_proven === false &&
    boundary.trusted_issuer_registry_key_custody_proven === false &&
    boundary.trusted_issuer_registry_revocation_truth_proven === false &&
    boundary.trusted_issuer_registry_production_trust_registry_proven === false &&
    boundary.trusted_issuer_registry_production_downstream_recognition_proven === false &&
    boundary.trusted_issuer_registry_production_authority === false &&
    boundary.trusted_issuer_registry_sovereign_recognition === false &&
    boundary.trusted_issuer_registry_public_external_attestation === false &&
    boundary.trusted_issuer_registry_real_non_operator_review === false &&
    boundary.trusted_issuer_registry_current_machine_governance_proven === false &&
    hasExactObjectKeys(
      boundary.nested_artifact_binding,
      TERMINAL_CHAIN_NESTED_ARTIFACT_BINDING_KEYS,
    ) &&
    boundary.nested_artifact_binding?.preflight_artifact_hash_bound === true &&
    boundary.nested_artifact_binding?.service_proof_source_preflight_hash_bound === true &&
    boundary.nested_artifact_binding?.service_artifact_hash_bound === true &&
    boundary.nested_artifact_binding?.service_artifact_verification_bound_to_service_proof === true &&
    boundary.nested_artifact_binding?.creates_public_external_attestation === false &&
    boundary.nested_artifact_binding?.proves_non_operator_review === false &&
    boundary.nested_artifact_binding?.proves_current_machine_governance === false &&
    boundary.nested_artifact_binding?.proves_production_downstream_recognition === false &&
    boundary.persistent_runtime_profile_installed === false &&
    boundary.runtime_profile_activation_performed === false &&
    boundary.hook_configuration_written === false &&
    boundary.user_configuration_written === false &&
    boundary.machine_configuration_written === false &&
    boundary.current_machine_governance_proven === false &&
    boundary.production_records_service_checked === false &&
    boundary.production_downstream_recognition === false &&
    boundary.external_attestation === false &&
    boundary.sovereign_recognition === false &&
    boundary.unrouted_records_paths_checked === false &&
    JSON.stringify(boundary.known_open_boundaries) ===
      JSON.stringify(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_OPEN_BOUNDARIES)
  );
}

function coverageMapBoundaryPasses(boundary, terminalChainBoundary) {
  const rawInput = readFileSync(PRODUCT_PROOF_PATH_COVERAGE_MAP_FIXTURE_PATH, 'utf8');
  const input = JSON.parse(rawInput);
  const artifact = input.installedRuntimeProfileTerminalChainLane
    ?.installed_runtime_profile_terminal_chain_artifact;
  const nestedArtifacts = artifact?.payload?.chain?.nested_artifacts || {};
  return (
    hasExactObjectKeys(boundary, COVERAGE_MAP_BOUNDARY_KEYS) &&
    boundary.report_type === GOVERNED_SURFACE_COVERAGE_MAP_REPORT_TYPE &&
    isSha256Hex(boundary.input_fixture_sha256) &&
    boundary.input_fixture_sha256 === sha256hex(rawInput) &&
    boundary.evidence_model === 'fixtures' &&
    boundary.live_probing === false &&
    boundary.governed_lanes === 6 &&
    boundary.counted_lanes === 6 &&
    boundary.surface_id === PRODUCT_PROOF_PATH_TERMINAL_SURFACE_ID &&
    boundary.surface_governed === true &&
    isSha256Hex(boundary.profile_sha256) &&
    boundary.profile_sha256 === terminalChainBoundary?.runtime_profile_sha256 &&
    boundary.mutation_authoritative_route ===
      EXACT_RUNTIME_MUTATION_AUTHORITATIVE_ROUTE &&
    boundary.mutation_authoritative_route ===
      terminalChainBoundary?.mutation_authoritative_route &&
    boundary.consumed_authority_grant_store ===
      terminalChainBoundary?.consumed_authority_grant_store &&
    boundary.consumption_identity === terminalChainBoundary?.consumption_identity &&
    boundary.signed_payload_replay_identity ===
      terminalChainBoundary?.signed_payload_replay_identity &&
    boundary.consumed_store_write_model ===
      terminalChainBoundary?.consumed_store_write_model &&
    boundary.consumed_grant_store_witness_source ===
      terminalChainBoundary?.consumed_grant_store_witness_source &&
    boundary.recognition_refusal_case_count === 18 &&
    boundary.all_recognition_refusals_before_mutation === true &&
    isSha256Hex(boundary.recognition_refusal_taxonomy_sha256) &&
    boundary.recognition_refusal_taxonomy_sha256 ===
      terminalChainBoundary?.recognition_refusal_taxonomy_sha256 &&
    boundary.authority_refusal_case_count ===
      REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length &&
    boundary.all_authority_refusals_before_consumption_and_mutation === true &&
    isSha256Hex(boundary.authority_refusal_taxonomy_sha256) &&
    boundary.authority_refusal_taxonomy_sha256 ===
      terminalChainBoundary?.authority_refusal_taxonomy_sha256 &&
    boundary.same_process_signed_payload_replay_refused === true &&
    boundary.restart_consumed_authority_grant_refused === true &&
    boundary.fixture_rightful_issuance_path_evidenced === true &&
    boundary.rightful_issuance_proven === false &&
    boundary.portable_rightful_issuance_proven === false &&
    boundary.production_rightful_issuance_proven === false &&
    boundary.live_authority_proven === false &&
    boundary.current_machine_governance_proven === false &&
    boundary.consequence_lifecycle_closed === false &&
    boundary.state_append_after_grant_commit_burn_observed === true &&
    boundary.metadata_partial_commit_burn_observed === true &&
    boundary.store_and_anchor_rollback_refused_while_witness_ahead === true &&
    boundary.store_anchor_and_witness_joint_rollback_detection === false &&
    boundary.joint_rollback_reopened_authority_grant_reuse === true &&
    boundary.host_filesystem_path_toctou_closed === false &&
    boundary.artifact_hash_equivalence_with_fresh_run_claimed === false &&
    isSha256Hex(boundary.terminal_chain_artifact_body_sha256) &&
    boundary.terminal_chain_artifact_body_sha256 ===
      artifact?.integrity?.body_sha256 &&
    isSha256Hex(boundary.nested_preflight_artifact_body_sha256) &&
    boundary.nested_preflight_artifact_body_sha256 ===
      nestedArtifacts.generated_preflight_artifact?.integrity?.body_sha256 &&
    isSha256Hex(boundary.nested_service_proof_artifact_body_sha256) &&
    boundary.nested_service_proof_artifact_body_sha256 ===
      nestedArtifacts.generated_service_proof_artifact?.integrity?.body_sha256 &&
    boundary.claim_boundary === PRODUCT_PROOF_PATH_COVERAGE_MAP_BOUNDARY
  );
}

function buildAcceptanceGate({
  coverage,
  coverageMapBoundary,
  downstream,
  humanAuthorization,
  receiptVerifier,
  protectedRecords,
  service,
  trustedIssuerRegistryRecognition,
  terminalChainBoundary,
  deploymentProfileAuthorityBridge,
}) {
  return {
    fresh_local_proof_pack_generated: true,
    local_proof_pack_artifact_verified: true,
    fresh_terminal_chain_generated:
      terminalChainBoundary?.payload_type ===
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TYPE,
    terminal_chain_artifact_verified: terminalChainBoundary?.verified === true,
    terminal_chain_boundary_observed:
      terminalChainBoundaryPasses(terminalChainBoundary),
    governed_action_allowed:
      downstream.recognized_boarded === true &&
      downstream.recognized_marker_count_delta === 1 &&
      downstream.final_marker_count === 1 &&
      protectedRecords.recognized_write_accepted === true &&
      service.recognized_service_write_accepted === true,
    governed_action_refused:
      Array.isArray(downstream.refusal_reasons) &&
      downstream.refusal_reasons.length === DOWNSTREAM_REFUSAL_REASONS.length &&
      downstream.refusal_reasons.every(
        (reason, index) => reason === DOWNSTREAM_REFUSAL_REASONS[index],
      ) &&
      downstream.refusal_case_count === DOWNSTREAM_REFUSAL_REASONS.length &&
      downstream.all_refusals_unboarded === true &&
      downstream.all_refusal_marker_count_deltas_zero === true &&
      protectedRecords.all_refusals_prevented_record_change === true &&
      service.missing_receipt_refused === true &&
      service.unrecognized_receipt_refused === true,
    simulated_human_authorization_observed:
      humanAuthorization.pending_boarded === false &&
      humanAuthorization.authorized_boarded === true &&
      humanAuthorization.denied_boarded === false &&
      humanAuthorization.approval_channel === 'simulated-human-fixture',
    receipt_verification_observed:
      receiptVerifier.valid_verdict === 'VALID' &&
      receiptVerifier.unknown_signer_verdict === 'UNKNOWN-SIGNER' &&
      receiptVerifier.invalid_verdict === 'INVALID' &&
      receiptVerifier.distinguishes_unknown_signer_from_invalid === true,
    trusted_issuer_registry_recognition_observed:
      registryRecognitionGatePasses(trustedIssuerRegistryRecognition),
    coverage_map_runtime_contract_observed:
      coverageMapBoundaryPasses(coverageMapBoundary, terminalChainBoundary),
    deployment_profile_authority_bridge_observed:
      deploymentProfileAuthorityBridgePasses(deploymentProfileAuthorityBridge),
    receipt_effect_boundary_observed:
      protectedRecords.adapter_consumed_receipt_count === 1 &&
      protectedRecords.recognized_record_count_delta === 1 &&
      protectedRecords.refusal_record_count_delta_total === 0,
    non_coverage_visible:
      coverage.boundary_entries > 0 &&
      Array.isArray(protectedRecords.known_ungoverned_boundaries) &&
      protectedRecords.known_ungoverned_boundaries.length > 0,
    no_private_operator_state_required: true,
  };
}

function buildDownstreamRefusalBoundary(downstream) {
  return {
    provided: true,
    recognized_boarded: downstream.recognized_boarded === true,
    recognized_marker_count_delta:
      downstream.recognized_marker_count_delta ?? 0,
    final_marker_count: downstream.final_marker_count ?? 0,
    refusal_case_count: downstream.refusal_case_count ?? 0,
    all_refusals_unboarded: downstream.all_refusals_unboarded === true,
    all_refusal_marker_count_deltas_zero:
      downstream.all_refusal_marker_count_deltas_zero === true,
    refusal_reasons: Array.isArray(downstream.refusal_reasons)
      ? [...downstream.refusal_reasons]
      : [],
  };
}

function downstreamRefusalBoundaryPasses(boundary) {
  return (
    boundary &&
    typeof boundary === 'object' &&
    boundary.provided === true &&
    boundary.recognized_boarded === true &&
    boundary.recognized_marker_count_delta === 1 &&
    boundary.final_marker_count === 1 &&
    boundary.refusal_case_count === DOWNSTREAM_REFUSAL_REASONS.length &&
    boundary.all_refusals_unboarded === true &&
    boundary.all_refusal_marker_count_deltas_zero === true &&
    JSON.stringify(boundary.refusal_reasons) ===
      JSON.stringify(DOWNSTREAM_REFUSAL_REASONS)
  );
}

function buildObserved({ coverage, downstream, humanAuthorization, receiptVerifier, protectedRecords, service, verification }) {
  return {
    action_class: protectedRecords.action_class,
    checkpoint: protectedRecords.profile_contract_checkpoint,
    route: protectedRecords.profile_contract_route,
    downstream_effect: protectedRecords.profile_contract_downstream_effect,
    proof_pack_sha256: verification.body_sha256,
    component_count: verification.component_count,
    coverage: {
      governed_lanes: coverage.governed_lanes,
      counted_lanes: coverage.counted_lanes,
      boundary_entries: coverage.boundary_entries,
    },
    allow_path: {
      downstream_recognized_boarded: downstream.recognized_boarded,
      downstream_recognized_marker_count_delta:
        downstream.recognized_marker_count_delta,
      downstream_final_marker_count: downstream.final_marker_count,
      protected_records_write_accepted: protectedRecords.recognized_write_accepted,
      protected_records_record_delta: protectedRecords.recognized_record_count_delta,
      service_write_accepted: service.recognized_service_write_accepted,
      service_state_delta: service.recognized_service_state_delta,
    },
    refusal_path: {
      downstream_refusal_reasons: [...downstream.refusal_reasons],
      downstream_refusal_case_count: downstream.refusal_case_count,
      downstream_all_refusals_unboarded: downstream.all_refusals_unboarded,
      downstream_all_refusal_marker_count_deltas_zero:
        downstream.all_refusal_marker_count_deltas_zero,
      protected_records_refused_write_count: protectedRecords.refused_write_count,
      protected_records_refusal_delta_total: protectedRecords.refusal_record_count_delta_total,
      service_missing_receipt_refused: service.missing_receipt_refused,
      service_unrecognized_receipt_refused: service.unrecognized_receipt_refused,
      service_invalid_receipt_refused: service.invalid_receipt_refused,
      service_unknown_issuer_refused: service.unknown_issuer_refused,
      service_stale_receipt_refused: service.stale_receipt_refused,
      service_direct_api_without_receipt_refused: service.direct_api_without_receipt_refused,
    },
    simulated_human_authorization: {
      approval_channel: humanAuthorization.approval_channel,
      pending_boarded: humanAuthorization.pending_boarded,
      authorized_boarded: humanAuthorization.authorized_boarded,
      denied_boarded: humanAuthorization.denied_boarded,
      outcome: humanAuthorization.outcome,
    },
    receipt_verifier_boundary: {
      command: receiptVerifier.command,
      valid_verdict: receiptVerifier.valid_verdict,
      valid_receipt_sha256_present: receiptVerifier.valid_receipt_sha256_present,
      valid_provided_pubkey_sha256_present:
        receiptVerifier.valid_provided_pubkey_sha256_present,
      valid_command_posture_allow_v0: receiptVerifier.valid_command_posture_allow_v0,
      valid_command_posture_detected_format:
        receiptVerifier.valid_command_posture_detected_format,
      required_identity_verdict: receiptVerifier.required_identity_verdict,
      required_identity_receipt_id_matched:
        receiptVerifier.required_identity_receipt_id_matched,
      required_identity_receipt_sha256_matched:
        receiptVerifier.required_identity_receipt_sha256_matched,
      required_identity_kid_matched: receiptVerifier.required_identity_kid_matched,
      required_identity_pubkey_sha256_matched:
        receiptVerifier.required_identity_pubkey_sha256_matched,
      required_identity_format_matched:
        receiptVerifier.required_identity_format_matched,
      required_identity_v1_only_matched:
        receiptVerifier.required_identity_v1_only_matched,
      required_identity_command_posture:
        receiptVerifier.required_identity_command_posture,
      legacy_v0_required_identity_refused:
        receiptVerifier.legacy_v0_required_identity_refused,
      unknown_signer_verdict: receiptVerifier.unknown_signer_verdict,
      unknown_signer_receipt_sha256_matches_valid:
        receiptVerifier.unknown_signer_receipt_sha256_matches_valid,
      unknown_signer_provided_pubkey_sha256_differs:
        receiptVerifier.unknown_signer_provided_pubkey_sha256_differs,
      invalid_verdict: receiptVerifier.invalid_verdict,
      invalid_receipt_sha256_differs_from_valid:
        receiptVerifier.invalid_receipt_sha256_differs_from_valid,
      invalid_provided_pubkey_sha256_matches_valid:
        receiptVerifier.invalid_provided_pubkey_sha256_matches_valid,
      distinguishes_unknown_signer_from_invalid:
        receiptVerifier.distinguishes_unknown_signer_from_invalid,
      issuer_recognition_proven: receiptVerifier.issuer_recognition_proven,
      key_custody_proven: receiptVerifier.key_custody_proven,
      revocation_state_proven: receiptVerifier.revocation_state_proven,
      downstream_recognition_proven: receiptVerifier.downstream_recognition_proven,
    },
    known_ungoverned_boundaries: [...protectedRecords.known_ungoverned_boundaries],
  };
}

function buildProofPackSummary({ artifact, verification }) {
  const activationIdentity = verification.runtime_local_activation;
  const installationIdentity = verification.runtime_profile_installation;
  const hookReplayComponent = component(
    artifact.payload,
    'claude_code_hook_contract_replay',
  );
  const hookReplay = verification.claude_hook_contract_replay;
  return {
    artifact_type: artifact.artifact_type,
    generator: artifact.generator,
    verification_type: verification.verification_type,
    verified: verification.verified,
    artifact_verification_model: verification.artifact_verification_model,
    body_sha256: verification.body_sha256,
    payload_type: verification.payload_type,
    evidence_model: verification.evidence_model,
    live_probing: verification.live_probing,
    fresh_proof_pack_run_performed: verification.fresh_proof_pack_run_performed,
    source_freshness_proven: verification.source_freshness_proven,
    component_count: verification.component_count,
    claim_boundary: verification.claim_boundary,
    runtime_profile_identity_policy: {
      authority_source: activationIdentity.runtime_profile_identity_authority_source,
      request_stream_policy:
        activationIdentity.runtime_profile_identity_request_stream_policy,
      request_runtime_profile_id_required:
        activationIdentity.request_runtime_profile_id_required,
      omitted_request_runtime_profile_id_present:
        activationIdentity.omitted_request_runtime_profile_id_present,
      omitted_runtime_profile_id_uses_launcher_config:
        activationIdentity.omitted_runtime_profile_id_uses_launcher_config,
      supplied_mismatched_runtime_profile_id_refused:
        activationIdentity.supplied_mismatched_runtime_profile_id_refused,
      runtime_local_activation_summary_bound:
        activationIdentity.runtime_profile_identity_authority_source ===
          'launcher-owned-service-config',
      runtime_profile_installation_summary_bound:
        installationIdentity.runtime_profile_identity_authority_source ===
          'launcher-owned-service-config',
      summaries_match:
        activationIdentity.runtime_profile_identity_authority_source ===
          installationIdentity.runtime_profile_identity_authority_source &&
        activationIdentity.runtime_profile_identity_request_stream_policy ===
          installationIdentity.runtime_profile_identity_request_stream_policy &&
        activationIdentity.request_runtime_profile_id_required ===
          installationIdentity.request_runtime_profile_id_required &&
        activationIdentity.omitted_request_runtime_profile_id_present ===
          installationIdentity.omitted_request_runtime_profile_id_present &&
        activationIdentity.omitted_runtime_profile_id_uses_launcher_config ===
          installationIdentity.omitted_runtime_profile_id_uses_launcher_config &&
        activationIdentity.supplied_mismatched_runtime_profile_id_refused ===
          installationIdentity.supplied_mismatched_runtime_profile_id_refused,
    },
    claude_hook_contract_replay: {
      hook_replay_contract_sha256: hookReplay.hook_replay_contract_sha256,
      adapter_sha256: hookReplay.adapter_sha256,
      component_sha256: sha256hex(canonicalize(hookReplayComponent)),
      case_evidence_hash_scope: hookReplay.case_evidence_hash_scope,
      case_evidence_sha256: hookReplay.case_evidence_sha256,
      source_state_boundary: hookReplay.source_state_boundary,
    },
  };
}

function assertProofPackClaudeHookContractReplaySummary(summary) {
  assertExactObjectKeys(
    'Product proof path proof-pack Claude hook replay summary',
    summary,
    PROOF_PACK_CLAUDE_HOOK_CONTRACT_REPLAY_KEYS,
  );
  const expected = expectedProofPackClaudeHookReplaySummary();
  if (
    !/^[a-f0-9]{64}$/.test(summary.hook_replay_contract_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(summary.adapter_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(summary.component_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(summary.case_evidence_sha256 || '') ||
    summary.hook_replay_contract_sha256 !==
      claudeCodeHookContractReplayContractSha256() ||
    summary.adapter_sha256 !== claudeCodeHookContractReplayRepoAdapterSha256() ||
    summary.component_sha256 !== expected.component_sha256 ||
    summary.case_evidence_hash_scope !== expected.case_evidence_hash_scope ||
    summary.case_evidence_sha256 !== expected.case_evidence_sha256 ||
    summary.source_state_boundary !==
      CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY
  ) {
    throw new Error('Product proof path proof-pack Claude hook replay summary drifted');
  }
  return true;
}

function expectedProofPackClaudeHookReplaySummary() {
  if (!expectedProofPackClaudeHookReplaySummaryCache) {
    const artifact = parseLocalProofPackArtifactText(
      readFileSync(
        PRODUCT_PROOF_PATH_LOCAL_PROOF_PACK_SAMPLE_ARTIFACT_PATH,
        'utf8',
      ),
    );
    const verification = verifyLocalProofPackArtifact(artifact, {
      expectedArtifactBodySha256:
        LOCAL_PROOF_PACK_HISTORICAL_SAMPLE_ARTIFACT_BODY_SHA256,
    });
    const hookReplayComponent = component(
      artifact.payload,
      'claude_code_hook_contract_replay',
    );
    expectedProofPackClaudeHookReplaySummaryCache = {
      hook_replay_contract_sha256:
        verification.claude_hook_contract_replay.hook_replay_contract_sha256,
      adapter_sha256: verification.claude_hook_contract_replay.adapter_sha256,
      component_sha256: sha256hex(canonicalize(hookReplayComponent)),
      case_evidence_hash_scope:
        verification.claude_hook_contract_replay.case_evidence_hash_scope,
      case_evidence_sha256:
        verification.claude_hook_contract_replay.case_evidence_sha256,
      source_state_boundary:
        verification.claude_hook_contract_replay.source_state_boundary,
    };
  }
  return expectedProofPackClaudeHookReplaySummaryCache;
}

export function historicalProductProofPathClaudeHookReplaySummary() {
  return { ...expectedProofPackClaudeHookReplaySummary() };
}

function verifiedArtifactBinding(artifact, verification) {
  let actualVerification;
  try {
    actualVerification = verifyLocalProofPackArtifact(artifact);
  } catch (err) {
    throw new Error(`Product proof path artifact verification binding failed: ${err.message}`);
  }
  if (JSON.stringify(actualVerification) !== JSON.stringify(verification)) {
    throw new Error('Product proof path supplied verification does not match the supplied artifact');
  }
  return actualVerification;
}

export const PRODUCT_PROOF_PATH_GENERATION_RETIREMENT_REASON =
  'product_proof_path_fresh_generation_retired';

export function buildProductProofPathReport() {
  throw new Error(PRODUCT_PROOF_PATH_GENERATION_RETIREMENT_REASON);
}

export function runProductProofPath() {
  throw new Error(PRODUCT_PROOF_PATH_GENERATION_RETIREMENT_REASON);
}

export function assertProductProofPathReport(report) {
  const authorityGrantStatus = protectedRecordsFixtureAuthorityGrantStatus(
    PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256,
  );
  if (authorityGrantStatus.fresh_fixture_rightful_projection_allowed !== true) {
    const reason = protectedRecordsFixtureAuthorityGrantEffectStatusReason(
      PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256,
    );
    throw new Error(
      `Product proof path fixture-rightful report acceptance refused: ${reason.code}`,
    );
  }
  throw new Error(
    'Product proof path schema version 7 is retired for fixture-rightful projection; a replacement grant requires a new artifact-bound historical/current schema',
  );
  assertExactObjectKeys('Product proof path report', report, [
    'acceptance_gate',
    'action_path',
    'claim_boundary',
    'command',
    'command_sequence',
    'coverage_map_boundary',
    'deployment_profile_authority_bridge',
    'downstream_refusal_boundary',
    'evidence_model',
    'forbidden_claims',
    'live_probing',
    'non_claims',
    'north_star_piece',
    'observed',
    'private_operator_state_required',
    'proof_pack',
    'report_type',
    'result',
    'schema_version',
    'terminal_chain_boundary',
    'trusted_issuer_registry_recognition',
  ]);
  if (report.report_type !== PRODUCT_PROOF_PATH_REPORT_TYPE) {
    throw new Error('Product proof path report type drifted');
  }
  if (report.schema_version !== PRODUCT_PROOF_PATH_SCHEMA_VERSION) {
    throw new Error('Product proof path schema version drifted');
  }
  if (report.result !== 'PASS') {
    throw new Error('Product proof path result must be PASS');
  }
  if (report.north_star_piece !== 'Product Proof Path') {
    throw new Error('Product proof path North Star piece drifted');
  }
  if (
    report.evidence_model !== PRODUCT_PROOF_PATH_EVIDENCE_MODEL ||
    report.live_probing !== false ||
    report.private_operator_state_required !== false
  ) {
    throw new Error('Product proof path evidence boundary drifted');
  }
  if (report.claim_boundary !== PRODUCT_PROOF_PATH_CLAIM_BOUNDARY) {
    throw new Error('Product proof path claim boundary drifted');
  }
  assertEqual('Product proof path command', report.command, 'zlar product-proof-path');
  assertExactArray('Product proof path command sequence', report.command_sequence, COMMAND_SEQUENCE);
  assertExactObjectKeys('Product proof path proof-pack summary', report.proof_pack, [
    'artifact_type',
    'artifact_verification_model',
    'body_sha256',
    'claim_boundary',
    'claude_hook_contract_replay',
    'component_count',
    'evidence_model',
    'fresh_proof_pack_run_performed',
    'generator',
    'live_probing',
    'payload_type',
    'runtime_profile_identity_policy',
    'source_freshness_proven',
    'verification_type',
    'verified',
  ]);
  if (
    report.proof_pack.artifact_type !== LOCAL_PROOF_PACK_ARTIFACT_TYPE ||
    report.proof_pack.generator !== 'zlar local-proof-pack --artifact' ||
    report.proof_pack.verification_type !== LOCAL_PROOF_PACK_ARTIFACT_VERIFICATION_TYPE ||
    report.proof_pack.verified !== true ||
    report.proof_pack.payload_type !== 'zlar-local-proof-pack-v1' ||
    report.proof_pack.artifact_verification_model !==
      'self-contained-artifact-integrity-and-embedded-boundary-validation' ||
    report.proof_pack.evidence_model !== 'local-fixtures' ||
    report.proof_pack.live_probing !== false ||
    report.proof_pack.fresh_proof_pack_run_performed !== false ||
    report.proof_pack.source_freshness_proven !== false ||
    report.proof_pack.component_count !== 16 ||
    report.proof_pack.claim_boundary !==
      'artifact integrity, embedded local fixture proof-pack boundaries, and verifier schema compatibility only; no fresh proof-pack run or current-checkout freshness proof' ||
    !/^[a-f0-9]{64}$/.test(report.proof_pack.body_sha256 || '')
  ) {
    throw new Error('Product proof path proof-pack verification drifted');
  }
  assertProofPackClaudeHookContractReplaySummary(
    report.proof_pack.claude_hook_contract_replay,
  );
  assertExactObjectKeys(
    'Product proof path proof-pack runtime profile identity policy',
    report.proof_pack.runtime_profile_identity_policy,
    [
      'authority_source',
      'omitted_request_runtime_profile_id_present',
      'omitted_runtime_profile_id_uses_launcher_config',
      'request_runtime_profile_id_required',
      'request_stream_policy',
      'runtime_local_activation_summary_bound',
      'runtime_profile_installation_summary_bound',
      'summaries_match',
      'supplied_mismatched_runtime_profile_id_refused',
    ],
  );
  if (
    report.proof_pack.runtime_profile_identity_policy.authority_source !==
      'launcher-owned-service-config' ||
    report.proof_pack.runtime_profile_identity_policy.request_stream_policy !==
      'runtime_profile_id_may_be_omitted_but_if_supplied_must_match_config' ||
    report.proof_pack.runtime_profile_identity_policy.request_runtime_profile_id_required !== false ||
    report.proof_pack.runtime_profile_identity_policy.omitted_request_runtime_profile_id_present !== false ||
    report.proof_pack.runtime_profile_identity_policy.omitted_runtime_profile_id_uses_launcher_config !==
      true ||
    report.proof_pack.runtime_profile_identity_policy.supplied_mismatched_runtime_profile_id_refused !==
      true ||
    report.proof_pack.runtime_profile_identity_policy.runtime_local_activation_summary_bound !== true ||
    report.proof_pack.runtime_profile_identity_policy.runtime_profile_installation_summary_bound !==
      true ||
    report.proof_pack.runtime_profile_identity_policy.summaries_match !== true
  ) {
    throw new Error('Product proof path proof-pack runtime profile identity policy drifted');
  }
  assertExactObjectKeys('Product proof path action path', report.action_path, [
    'action_class',
    'checkpoint',
    'deployment_profile',
    'downstream_effect',
    'receipt_replay_policy',
    'required_receipt_fields',
    'route',
  ]);
  assertEqual('Product proof path action class', report.action_path.action_class, 'records.write');
  assertEqual(
    'Product proof path deployment profile',
    report.action_path.deployment_profile,
    'protected-records-terminal',
  );
  assertEqual(
    'Product proof path checkpoint',
    report.action_path.checkpoint,
    'downstream-recognition-rule',
  );
  assertEqual(
    'Product proof path route',
    report.action_path.route,
    'receipt-recognition-before-record-write',
  );
  assertEqual(
    'Product proof path downstream effect',
    report.action_path.downstream_effect,
    'append-protected-records-ledger-entry',
  );
  assertEqual(
    'Product proof path receipt replay policy',
    report.action_path.receipt_replay_policy,
    'single-use-receipt-id-per-terminal-ledger',
  );
  assertExactArray(
    'Product proof path required receipt fields',
    report.action_path.required_receipt_fields,
    REQUIRED_RECEIPT_FIELDS,
  );
  assertExactObjectKeys(
    'Product proof path trusted issuer registry recognition',
    report.trusted_issuer_registry_recognition,
    TRUSTED_ISSUER_REGISTRY_RECOGNITION_KEYS,
  );
  if (!registryRecognitionGatePasses(report.trusted_issuer_registry_recognition)) {
    throw new Error('Product proof path trusted issuer registry recognition drifted');
  }
  assertEqual(
    'Product proof path registry recognition claim boundary',
    report.trusted_issuer_registry_recognition.claim_boundary,
    TRUSTED_ISSUER_REGISTRY_RECOGNITION_CLAIM_BOUNDARY,
  );
  assertExactObjectKeys(
    'Product proof path terminal chain boundary',
    report.terminal_chain_boundary,
    TERMINAL_CHAIN_BOUNDARY_KEYS,
  );
  if (!terminalChainBoundaryPasses(report.terminal_chain_boundary)) {
    throw new Error('Product proof path terminal chain boundary drifted');
  }
  assertExactObjectKeys(
    'Product proof path coverage map boundary',
    report.coverage_map_boundary,
    COVERAGE_MAP_BOUNDARY_KEYS,
  );
  if (!coverageMapBoundaryPasses(
    report.coverage_map_boundary,
    report.terminal_chain_boundary,
  )) {
    throw new Error('Product proof path coverage map boundary drifted');
  }
  assertExactObjectKeys(
    'Product proof path deployment profile authority bridge',
    report.deployment_profile_authority_bridge,
    DEPLOYMENT_PROFILE_AUTHORITY_BRIDGE_KEYS,
  );
  if (!deploymentProfileAuthorityBridgePasses(report.deployment_profile_authority_bridge)) {
    throw new Error('Product proof path deployment profile authority bridge drifted');
  }
  assertExactObjectKeys(
    'Product proof path downstream refusal boundary',
    report.downstream_refusal_boundary,
    DOWNSTREAM_REFUSAL_BOUNDARY_KEYS,
  );
  if (!downstreamRefusalBoundaryPasses(report.downstream_refusal_boundary)) {
    throw new Error('Product proof path downstream refusal boundary drifted');
  }

  assertExactObjectKeys('Product proof path acceptance gate', report.acceptance_gate, ACCEPTANCE_GATE_KEYS);
  for (const key of ACCEPTANCE_GATE_KEYS) {
    if (report.acceptance_gate[key] !== true) {
      throw new Error(`Product proof path acceptance gate failed: ${key}`);
    }
  }
  assertExactObjectKeys('Product proof path observed', report.observed, [
    'action_class',
    'allow_path',
    'checkpoint',
    'component_count',
    'coverage',
    'downstream_effect',
    'known_ungoverned_boundaries',
    'proof_pack_sha256',
    'receipt_verifier_boundary',
    'refusal_path',
    'route',
    'simulated_human_authorization',
  ]);
  assertEqual('Product proof path observed action class', report.observed.action_class, 'records.write');
  assertEqual(
    'Product proof path observed checkpoint',
    report.observed.checkpoint,
    'downstream-recognition-rule',
  );
  assertEqual(
    'Product proof path observed route',
    report.observed.route,
    'receipt-recognition-before-record-write',
  );
  assertEqual(
    'Product proof path observed downstream effect',
    report.observed.downstream_effect,
    'append-protected-records-ledger-entry',
  );
  assertEqual(
    'Product proof path observed proof-pack SHA',
    report.observed.proof_pack_sha256,
    report.proof_pack.body_sha256,
  );
  assertEqual('Product proof path observed component count', report.observed.component_count, 16);
  assertExactObjectKeys('Product proof path observed coverage', report.observed.coverage, [
    'boundary_entries',
    'counted_lanes',
    'governed_lanes',
  ]);
  assertEqual('Product proof path governed lanes', report.observed.coverage.governed_lanes, 6);
  assertEqual('Product proof path counted lanes', report.observed.coverage.counted_lanes, 6);
  assertEqual('Product proof path boundary entries', report.observed.coverage.boundary_entries, 12);
  assertExactObjectKeys('Product proof path observed allow path', report.observed.allow_path, [
    'downstream_recognized_boarded',
    'downstream_recognized_marker_count_delta',
    'downstream_final_marker_count',
    'protected_records_record_delta',
    'protected_records_write_accepted',
    'service_state_delta',
    'service_write_accepted',
  ]);
  assertEqual(
    'Product proof path downstream recognized boarded',
    report.observed.allow_path.downstream_recognized_boarded,
    true,
  );
  assertEqual(
    'Product proof path downstream recognized marker count delta',
    report.observed.allow_path.downstream_recognized_marker_count_delta,
    1,
  );
  assertEqual(
    'Product proof path downstream final marker count',
    report.observed.allow_path.downstream_final_marker_count,
    1,
  );
  assertEqual(
    'Product proof path protected records write accepted',
    report.observed.allow_path.protected_records_write_accepted,
    true,
  );
  assertEqual(
    'Product proof path protected records record delta',
    report.observed.allow_path.protected_records_record_delta,
    1,
  );
  assertEqual(
    'Product proof path service write accepted',
    report.observed.allow_path.service_write_accepted,
    true,
  );
  assertEqual('Product proof path service state delta', report.observed.allow_path.service_state_delta, 1);
  assertExactObjectKeys('Product proof path observed refusal path', report.observed.refusal_path, [
    'downstream_all_refusal_marker_count_deltas_zero',
    'downstream_all_refusals_unboarded',
    'downstream_refusal_case_count',
    'downstream_refusal_reasons',
    'protected_records_refusal_delta_total',
    'protected_records_refused_write_count',
    'service_direct_api_without_receipt_refused',
    'service_invalid_receipt_refused',
    'service_missing_receipt_refused',
    'service_stale_receipt_refused',
    'service_unknown_issuer_refused',
    'service_unrecognized_receipt_refused',
  ]);
  assertExactArray(
    'Product proof path downstream refusal reasons',
    report.observed.refusal_path.downstream_refusal_reasons,
    DOWNSTREAM_REFUSAL_REASONS,
  );
  assertEqual(
    'Product proof path downstream refusal case count',
    report.observed.refusal_path.downstream_refusal_case_count,
    DOWNSTREAM_REFUSAL_REASONS.length,
  );
  assertEqual(
    'Product proof path downstream all refusals unboarded',
    report.observed.refusal_path.downstream_all_refusals_unboarded,
    true,
  );
  assertEqual(
    'Product proof path downstream all refusal marker count deltas zero',
    report.observed.refusal_path.downstream_all_refusal_marker_count_deltas_zero,
    true,
  );
  assertEqual(
    'Product proof path protected records refused write count',
    report.observed.refusal_path.protected_records_refused_write_count,
    11,
  );
  assertEqual(
    'Product proof path protected records refusal delta total',
    report.observed.refusal_path.protected_records_refusal_delta_total,
    0,
  );
  for (const key of [
    'service_missing_receipt_refused',
    'service_unrecognized_receipt_refused',
    'service_invalid_receipt_refused',
    'service_unknown_issuer_refused',
    'service_stale_receipt_refused',
    'service_direct_api_without_receipt_refused',
  ]) {
    assertEqual(`Product proof path refusal ${key}`, report.observed.refusal_path[key], true);
  }
  assertExactObjectKeys(
    'Product proof path observed simulated human authorization',
    report.observed.simulated_human_authorization,
    ['approval_channel', 'authorized_boarded', 'denied_boarded', 'outcome', 'pending_boarded'],
  );
  assertEqual(
    'Product proof path simulated approval channel',
    report.observed.simulated_human_authorization.approval_channel,
    'simulated-human-fixture',
  );
  assertEqual(
    'Product proof path simulated pending boarded',
    report.observed.simulated_human_authorization.pending_boarded,
    false,
  );
  assertEqual(
    'Product proof path simulated authorized boarded',
    report.observed.simulated_human_authorization.authorized_boarded,
    true,
  );
  assertEqual(
    'Product proof path simulated denied boarded',
    report.observed.simulated_human_authorization.denied_boarded,
    false,
  );
  assertEqual(
    'Product proof path simulated outcome',
    report.observed.simulated_human_authorization.outcome,
    'authorized',
  );
  assertExactObjectKeys(
    'Product proof path observed receipt verifier boundary',
    report.observed.receipt_verifier_boundary,
    [
      'command',
      'distinguishes_unknown_signer_from_invalid',
      'downstream_recognition_proven',
      'invalid_provided_pubkey_sha256_matches_valid',
      'invalid_receipt_sha256_differs_from_valid',
      'invalid_verdict',
      'issuer_recognition_proven',
      'key_custody_proven',
      'legacy_v0_required_identity_refused',
      'required_identity_command_posture',
      'required_identity_format_matched',
      'required_identity_kid_matched',
      'required_identity_pubkey_sha256_matched',
      'required_identity_receipt_id_matched',
      'required_identity_receipt_sha256_matched',
      'required_identity_v1_only_matched',
      'required_identity_verdict',
      'revocation_state_proven',
      'unknown_signer_provided_pubkey_sha256_differs',
      'unknown_signer_receipt_sha256_matches_valid',
      'unknown_signer_verdict',
      'valid_command_posture_allow_v0',
      'valid_command_posture_detected_format',
      'valid_provided_pubkey_sha256_present',
      'valid_receipt_sha256_present',
      'valid_verdict',
    ],
  );
  assertEqual(
    'Product proof path receipt verifier command',
    report.observed.receipt_verifier_boundary.command,
    'zlar-verify <receipt.json> --pubkey <key.pub> --json',
  );
  assertEqual(
    'Product proof path valid verdict',
    report.observed.receipt_verifier_boundary.valid_verdict,
    'VALID',
  );
  for (const key of [
    'valid_receipt_sha256_present',
    'valid_provided_pubkey_sha256_present',
    'required_identity_receipt_id_matched',
    'required_identity_receipt_sha256_matched',
    'required_identity_kid_matched',
    'required_identity_pubkey_sha256_matched',
    'required_identity_format_matched',
    'required_identity_v1_only_matched',
    'legacy_v0_required_identity_refused',
    'unknown_signer_receipt_sha256_matches_valid',
    'unknown_signer_provided_pubkey_sha256_differs',
    'invalid_receipt_sha256_differs_from_valid',
    'invalid_provided_pubkey_sha256_matches_valid',
  ]) {
    assertEqual(`Product proof path receipt verifier identity ${key}`, report.observed.receipt_verifier_boundary[key], true);
  }
  assertEqual(
    'Product proof path receipt verifier default posture excludes v0',
    report.observed.receipt_verifier_boundary.valid_command_posture_allow_v0,
    false,
  );
  assertEqual(
    'Product proof path receipt verifier default detected format',
    report.observed.receipt_verifier_boundary.valid_command_posture_detected_format,
    'v1',
  );
  assertEqual(
    'Product proof path receipt verifier required identity verdict',
    report.observed.receipt_verifier_boundary.required_identity_verdict,
    'VALID',
  );
  assertEqual(
    'Product proof path receipt verifier required identity posture',
    report.observed.receipt_verifier_boundary.required_identity_command_posture,
    'receipt-verifier-v1-only-required',
  );
  assertEqual(
    'Product proof path unknown signer verdict',
    report.observed.receipt_verifier_boundary.unknown_signer_verdict,
    'UNKNOWN-SIGNER',
  );
  assertEqual(
    'Product proof path invalid verdict',
    report.observed.receipt_verifier_boundary.invalid_verdict,
    'INVALID',
  );
  assertEqual(
    'Product proof path distinguishes unknown signer',
    report.observed.receipt_verifier_boundary.distinguishes_unknown_signer_from_invalid,
    true,
  );
  for (const key of [
    'issuer_recognition_proven',
    'key_custody_proven',
    'revocation_state_proven',
    'downstream_recognition_proven',
  ]) {
    assertEqual(`Product proof path receipt verifier non-claim ${key}`, report.observed.receipt_verifier_boundary[key], false);
  }
  assertExactArray(
    'Product proof path known ungoverned boundaries',
    report.observed.known_ungoverned_boundaries,
    KNOWN_UNGOVERNED_BOUNDARIES,
  );
  assertExactObjectKeys('Product proof path forbidden claims', report.forbidden_claims, FORBIDDEN_CLAIM_KEYS);
  for (const key of FORBIDDEN_CLAIM_KEYS) {
    if (report.forbidden_claims[key] !== false) {
      throw new Error(`Product proof path forbidden claim widened: ${key}`);
    }
  }
  if (
    !Array.isArray(report.non_claims) ||
    report.non_claims.length !== PRODUCT_PROOF_PATH_NON_CLAIMS.length ||
    report.non_claims.some((claim, index) => claim !== PRODUCT_PROOF_PATH_NON_CLAIMS[index])
  ) {
    throw new Error('Product proof path non-claims drifted');
  }
  assertNoUnsafeProductProofPathText(JSON.stringify(report));
  return true;
}

export function assertNoUnsafeProductProofPathText(value) {
  assertNoUnsafeLocalProofPackText(value);
  return true;
}

export function writeProductProofPathReport(report, outputPath) {
  assertProductProofPathReport(report);
  if (!outputPath || outputPath === '-') {
    throw new Error('Product proof path report output path is required');
  }
  if (existsSync(outputPath)) {
    throw new Error('Refusing to overwrite existing output path');
  }
  mkdirSync(dirname(outputPath), { recursive: true });
  const output = `${JSON.stringify(report, null, 2)}\n`;
  assertNoUnsafeProductProofPathText(output);
  writeFileSync(outputPath, output, { mode: 0o600 });
  return outputPath;
}

export function formatProductProofPathReport(report) {
  assertProductProofPathReport(report);
  const lines = [
    'ZLAR Product Proof Path v1',
    `result=${report.result}`,
    `north_star_piece=${report.north_star_piece}`,
    `evidence_model=${report.evidence_model}; live_probing=${report.live_probing}; private_operator_state_required=${report.private_operator_state_required}`,
    `claim_boundary=${report.claim_boundary}`,
    `proof_pack_sha256=${report.proof_pack.body_sha256}`,
    `proof_pack_runtime_profile_identity_policy: authority_source=${report.proof_pack.runtime_profile_identity_policy.authority_source}; request_runtime_profile_id_required=${report.proof_pack.runtime_profile_identity_policy.request_runtime_profile_id_required}; omitted_request_field_present=${report.proof_pack.runtime_profile_identity_policy.omitted_request_runtime_profile_id_present}; omitted_uses_launcher_config=${report.proof_pack.runtime_profile_identity_policy.omitted_runtime_profile_id_uses_launcher_config}; supplied_mismatch_refused=${report.proof_pack.runtime_profile_identity_policy.supplied_mismatched_runtime_profile_id_refused}; summaries_match=${report.proof_pack.runtime_profile_identity_policy.summaries_match}`,
    `proof_pack_claude_hook_contract_replay: contract_sha256=${report.proof_pack.claude_hook_contract_replay.hook_replay_contract_sha256}; adapter_sha256=${report.proof_pack.claude_hook_contract_replay.adapter_sha256}; component_sha256=${report.proof_pack.claude_hook_contract_replay.component_sha256}; case_evidence_sha256=${report.proof_pack.claude_hook_contract_replay.case_evidence_sha256}; source_state_boundary=${report.proof_pack.claude_hook_contract_replay.source_state_boundary}`,
    `action_class=${report.action_path.action_class}`,
    `checkpoint=${report.action_path.checkpoint}`,
    `route=${report.action_path.route}`,
    `downstream_effect=${report.action_path.downstream_effect}`,
    'Acceptance gate:',
  ];
  for (const [key, value] of Object.entries(report.acceptance_gate)) {
    lines.push(`- ${key}=${value}`);
  }
  lines.push('Trusted issuer registry recognition:');
  lines.push(
    `- verdict=${report.trusted_issuer_registry_recognition.verdict}; registry_type=${report.trusted_issuer_registry_recognition.registry_type}; evidence_model=${report.trusted_issuer_registry_recognition.registry_evidence_model}; live_probing=${report.trusted_issuer_registry_recognition.live_probing}`,
  );
  lines.push(
    `- registry_fixture_validated=${report.trusted_issuer_registry_recognition.registry_fixture_validated}; registry_fixture_evaluated=${report.trusted_issuer_registry_recognition.registry_fixture_evaluated}; registry_to_recognition_rule_evaluated=${report.trusted_issuer_registry_recognition.registry_to_recognition_rule_evaluated}; registry_evaluation_result_type=${report.trusted_issuer_registry_recognition.registry_evaluation_result_type}; registry_trusted_issuer_count=${report.trusted_issuer_registry_recognition.registry_trusted_issuer_count}`,
  );
  lines.push(
    `- issuer_status=${report.trusted_issuer_registry_recognition.issuer_status}; signature_valid=${report.trusted_issuer_registry_recognition.signature_valid}; required_audit_event_id_bound=${report.trusted_issuer_registry_recognition.required_audit_event_id_bound}; required_detail_hash_bound=${report.trusted_issuer_registry_recognition.required_detail_hash_bound}; malformed_registry_fail_closed_before_verdict=${report.trusted_issuer_registry_recognition.malformed_registry_fail_closed_before_verdict}`,
  );
  lines.push(
    `- proves_live_registry=${report.trusted_issuer_registry_recognition.proves_live_registry}; proves_live_issuer_status=${report.trusted_issuer_registry_recognition.proves_live_issuer_status}; proves_key_custody=${report.trusted_issuer_registry_recognition.proves_key_custody}; proves_revocation_truth=${report.trusted_issuer_registry_recognition.proves_revocation_truth}; proves_current_machine_governance=${report.trusted_issuer_registry_recognition.proves_current_machine_governance}`,
  );
  lines.push(
    `- proves_production_trust_registry=${report.trusted_issuer_registry_recognition.proves_production_trust_registry}; proves_production_downstream_recognition=${report.trusted_issuer_registry_recognition.proves_production_downstream_recognition}; proves_production_authority=${report.trusted_issuer_registry_recognition.proves_production_authority}; proves_sovereign_recognition=${report.trusted_issuer_registry_recognition.proves_sovereign_recognition}; proves_public_external_attestation=${report.trusted_issuer_registry_recognition.proves_public_external_attestation}; proves_real_non_operator_review=${report.trusted_issuer_registry_recognition.proves_real_non_operator_review}`,
  );
  lines.push(
    `- claim_boundary=${report.trusted_issuer_registry_recognition.claim_boundary}`,
  );
  lines.push('Terminal chain boundary:');
  lines.push(
    `- verification_type=${report.terminal_chain_boundary.verification_type}; artifact_type=${report.terminal_chain_boundary.artifact_type}; payload_type=${report.terminal_chain_boundary.payload_type}; verified=${report.terminal_chain_boundary.verified}; live_probing=${report.terminal_chain_boundary.live_probing}`,
  );
  lines.push(
    `- body_sha256=${report.terminal_chain_boundary.body_sha256}; runtime_profile_sha256=${report.terminal_chain_boundary.runtime_profile_sha256}; recognition_contract_sha256=${report.terminal_chain_boundary.recognition_contract_sha256}; recognition_refusal_taxonomy_sha256=${report.terminal_chain_boundary.recognition_refusal_taxonomy_sha256}; authority_refusal_taxonomy_sha256=${report.terminal_chain_boundary.authority_refusal_taxonomy_sha256}; named_receipt_refusals_sha256=${report.terminal_chain_boundary.named_receipt_refusals_sha256}; recognition_refusal_groups_sha256=${report.terminal_chain_boundary.recognition_refusal_groups_sha256}`,
  );
  lines.push(
    `- named_receipt_refusals.missing=${report.terminal_chain_boundary.named_receipt_refusals.missing.refused_before_mutation}; named_receipt_refusals.invalid=${report.terminal_chain_boundary.named_receipt_refusals.invalid.refused_before_mutation}; named_receipt_refusals.stale_or_expired=${report.terminal_chain_boundary.named_receipt_refusals.stale_or_expired.refused_before_mutation}; named_receipt_refusals.unknown_issuer=${report.terminal_chain_boundary.named_receipt_refusals.unknown_issuer.refused_before_mutation}; named_receipt_refusals.wrong_policy=${report.terminal_chain_boundary.named_receipt_refusals.wrong_policy.refused_before_mutation}; named_receipt_refusals.wrong_domain=${report.terminal_chain_boundary.named_receipt_refusals.wrong_domain.refused_before_mutation}; named_receipt_refusals.wrong_tool=${report.terminal_chain_boundary.named_receipt_refusals.wrong_tool.refused_before_mutation}`,
  );
  lines.push(
    `- recognition_refusal_group_count=${report.terminal_chain_boundary.recognition_refusal_group_count}; recognition_refusal_group_case_count=${report.terminal_chain_boundary.recognition_refusal_group_case_count}; recognition_refusal_group_case_ids_preserved=${report.terminal_chain_boundary.recognition_refusal_group_case_ids_preserved}`,
  );
  lines.push(
    `- generated_installed_root_preflighted=${report.terminal_chain_boundary.generated_installed_root_preflighted}; generated_preflight_artifact_consumed_by_service_proof=${report.terminal_chain_boundary.generated_preflight_artifact_consumed_by_service_proof}; generated_service_proof_artifact_verified=${report.terminal_chain_boundary.generated_service_proof_artifact_verified}; service_proof_bound_to_generated_preflight=${report.terminal_chain_boundary.service_proof_bound_to_generated_preflight}; service_artifact_verification_bound_to_service_proof=${report.terminal_chain_boundary.service_artifact_verification_bound_to_service_proof}`,
  );
  lines.push(
    `- recognized_write_boarded=${report.terminal_chain_boundary.recognized_write_boarded}; missing_receipt_refused_before_mutation=${report.terminal_chain_boundary.missing_receipt_refused_before_mutation}; invalid_receipt_refused_before_mutation=${report.terminal_chain_boundary.invalid_receipt_refused_before_mutation}; all_required_recognition_refusals_before_mutation=${report.terminal_chain_boundary.all_required_recognition_refusals_before_mutation}; recognition_refusal_cases=${report.terminal_chain_boundary.observed_recognition_refusal_case_count}/${report.terminal_chain_boundary.required_recognition_refusal_case_count}; all_required_authority_refusals_before_consumption_and_mutation=${report.terminal_chain_boundary.all_required_authority_refusals_before_consumption_and_mutation}; authority_refusal_cases=${report.terminal_chain_boundary.observed_authority_refusal_case_count}/${report.terminal_chain_boundary.required_authority_refusal_case_count}`,
  );
  lines.push(
    `- mutation_authoritative_route=${report.terminal_chain_boundary.mutation_authoritative_route}; consumed_authority_grant_store=${report.terminal_chain_boundary.consumed_authority_grant_store}; consumption_identity=${report.terminal_chain_boundary.consumption_identity}; signed_payload_replay_identity=${report.terminal_chain_boundary.signed_payload_replay_identity}; consumed_store_write_model=${report.terminal_chain_boundary.consumed_store_write_model}; consumed_grant_store_witness_source=${report.terminal_chain_boundary.consumed_grant_store_witness_source}`,
  );
  lines.push(
    `- fixture_rightful_issuance_path_evidenced=${report.terminal_chain_boundary.fixture_rightful_issuance_path_evidenced}; authority_domain_id=${report.terminal_chain_boundary.public_safe_grant_summary.authority_domain_id}; grantor_role_id=${report.terminal_chain_boundary.public_safe_grant_summary.grantor_role_id}; authority_grant_contract_sha256=${report.terminal_chain_boundary.public_safe_grant_summary.authority_grant_contract_sha256}; rightful_issuance_proven=${report.terminal_chain_boundary.rightful_issuance_proven}; portable_rightful_issuance_proven=${report.terminal_chain_boundary.portable_rightful_issuance_proven}; production_rightful_issuance_proven=${report.terminal_chain_boundary.production_rightful_issuance_proven}; live_authority_proven=${report.terminal_chain_boundary.live_authority_proven}; consequence_lifecycle_closed=${report.terminal_chain_boundary.consequence_lifecycle_closed}`,
  );
  lines.push(
    `- same_process_signed_payload_replay_refused=${report.terminal_chain_boundary.same_process_signed_payload_replay_refused}; restart_consumed_authority_grant_refused=${report.terminal_chain_boundary.restart_consumed_authority_grant_refused}; state_append_after_grant_commit_burn_observed=${report.terminal_chain_boundary.state_append_after_grant_commit_burn_observed}; metadata_partial_commit_burn_observed=${report.terminal_chain_boundary.metadata_partial_commit_burn_observed}; store_and_anchor_rollback_refused_while_witness_ahead=${report.terminal_chain_boundary.store_and_anchor_rollback_refused_while_witness_ahead}; store_anchor_and_witness_joint_rollback_detection=${report.terminal_chain_boundary.store_anchor_and_witness_joint_rollback_detection}; joint_rollback_reopened_authority_grant_reuse=${report.terminal_chain_boundary.joint_rollback_reopened_authority_grant_reuse}; host_filesystem_path_toctou_closed=${report.terminal_chain_boundary.host_filesystem_path_toctou_closed}`,
  );
  lines.push(
    `- trusted_issuer_registry_recognition_binding_sha256=${report.terminal_chain_boundary.trusted_issuer_registry_recognition_binding_sha256}; trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification=${report.terminal_chain_boundary.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification}; trusted_issuer_registry_recognition_refusals_sha256=${report.terminal_chain_boundary.trusted_issuer_registry_recognition_refusals_sha256}; trusted_issuer_registry_recognition_refusal_hash_matches_binding=${report.terminal_chain_boundary.trusted_issuer_registry_recognition_refusal_hash_matches_binding}; trusted_issuer_registry_recognition_refusals_all_refused=${report.terminal_chain_boundary.trusted_issuer_registry_recognition_refusals_all_refused}`,
  );
  lines.push(
    `- trusted_issuer_registry_recognition_verdict=${report.terminal_chain_boundary.trusted_issuer_registry_recognition_verdict}; trusted_issuer_registry_recognition_recognized=${report.terminal_chain_boundary.trusted_issuer_registry_recognition_recognized}; trusted_issuer_registry_recognition_signature_valid=${report.terminal_chain_boundary.trusted_issuer_registry_recognition_signature_valid}; trusted_issuer_registry_recognition_registry_fixture_validated=${report.terminal_chain_boundary.trusted_issuer_registry_recognition_registry_fixture_validated}; trusted_issuer_registry_recognition_registry_fixture_evaluated=${report.terminal_chain_boundary.trusted_issuer_registry_recognition_registry_fixture_evaluated}; trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated=${report.terminal_chain_boundary.trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated}; trusted_issuer_registry_recognition_registry_evaluation_result_type=${report.terminal_chain_boundary.trusted_issuer_registry_recognition_registry_evaluation_result_type}`,
  );
  lines.push(
    `- recognized_receipt_path_evidence_sha256=${report.terminal_chain_boundary.recognized_receipt_path_evidence_sha256}; recognized_receipt_path_evidence_artifact_verification_sha256=${report.terminal_chain_boundary.recognized_receipt_path_evidence_artifact_verification_sha256}; recognized_receipt_path_evidence_sha256_matches_artifact_verification=${report.terminal_chain_boundary.recognized_receipt_path_evidence_sha256_matches_artifact_verification}; recognized_receipt_path_evidence_bound_to_artifact_body=${report.terminal_chain_boundary.recognized_receipt_path_evidence_bound_to_artifact_body}; recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding=${report.terminal_chain_boundary.recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding}`,
  );
  lines.push(
    `- recognized_receipt_path_evidence_verdict=${report.terminal_chain_boundary.recognized_receipt_path_evidence_verdict}; recognized_receipt_path_evidence_recognized=${report.terminal_chain_boundary.recognized_receipt_path_evidence_recognized}; recognized_receipt_path_evidence_receipt_envelope_included=${report.terminal_chain_boundary.recognized_receipt_path_evidence_receipt_envelope_included}; recognized_receipt_path_evidence_registry_public_key_material_included=${report.terminal_chain_boundary.recognized_receipt_path_evidence_registry_public_key_material_included}; recognized_receipt_path_evidence_artifact_crypto_reproducible=${report.terminal_chain_boundary.recognized_receipt_path_evidence_artifact_crypto_reproducible}`,
  );
  lines.push(
    `- recognized_receipt_path_evidence_live_state_proven=${report.terminal_chain_boundary.recognized_receipt_path_evidence_live_state_proven}; recognized_receipt_path_evidence_live_issuer_status_proven=${report.terminal_chain_boundary.recognized_receipt_path_evidence_live_issuer_status_proven}; recognized_receipt_path_evidence_key_custody_proven=${report.terminal_chain_boundary.recognized_receipt_path_evidence_key_custody_proven}; recognized_receipt_path_evidence_revocation_truth_proven=${report.terminal_chain_boundary.recognized_receipt_path_evidence_revocation_truth_proven}; recognized_receipt_path_evidence_production_downstream_recognition_proven=${report.terminal_chain_boundary.recognized_receipt_path_evidence_production_downstream_recognition_proven}; recognized_receipt_path_evidence_public_external_attestation=${report.terminal_chain_boundary.recognized_receipt_path_evidence_public_external_attestation}; recognized_receipt_path_evidence_sovereign_recognition=${report.terminal_chain_boundary.recognized_receipt_path_evidence_sovereign_recognition}; recognized_receipt_path_evidence_current_machine_governance_proven=${report.terminal_chain_boundary.recognized_receipt_path_evidence_current_machine_governance_proven}`,
  );
  lines.push(
    `- registry_receipt_contract_hash_bound=${report.terminal_chain_boundary.registry_receipt_contract_hash_bound}; selected_profile_hash_bound=${report.terminal_chain_boundary.selected_profile_hash_bound}; recognition_contract_hash_bound=${report.terminal_chain_boundary.recognition_contract_hash_bound}; terminal_chain_decision_bound=${report.terminal_chain_boundary.terminal_chain_decision_bound}`,
  );
  lines.push(
    `- registry_public_key_material_included=${report.terminal_chain_boundary.registry_public_key_material_included}; receipt_envelope_included=${report.terminal_chain_boundary.receipt_envelope_included}; cryptographic_evidence_reproducible_from_artifact=${report.terminal_chain_boundary.cryptographic_evidence_reproducible_from_artifact}; external_attestation=${report.terminal_chain_boundary.external_attestation}; current_machine_governance_proven=${report.terminal_chain_boundary.current_machine_governance_proven}; production_downstream_recognition=${report.terminal_chain_boundary.production_downstream_recognition}; sovereign_recognition=${report.terminal_chain_boundary.sovereign_recognition}`,
  );
  lines.push(
    `- trusted_issuer_registry_live_state_proven=${report.terminal_chain_boundary.trusted_issuer_registry_live_state_proven}; trusted_issuer_registry_live_issuer_status_proven=${report.terminal_chain_boundary.trusted_issuer_registry_live_issuer_status_proven}; trusted_issuer_registry_key_custody_proven=${report.terminal_chain_boundary.trusted_issuer_registry_key_custody_proven}; trusted_issuer_registry_revocation_truth_proven=${report.terminal_chain_boundary.trusted_issuer_registry_revocation_truth_proven}; trusted_issuer_registry_production_authority=${report.terminal_chain_boundary.trusted_issuer_registry_production_authority}; trusted_issuer_registry_public_external_attestation=${report.terminal_chain_boundary.trusted_issuer_registry_public_external_attestation}; trusted_issuer_registry_real_non_operator_review=${report.terminal_chain_boundary.trusted_issuer_registry_real_non_operator_review}`,
  );
  lines.push(
    `- nested_artifact_binding.preflight_artifact_hash_bound=${report.terminal_chain_boundary.nested_artifact_binding.preflight_artifact_hash_bound}; nested_artifact_binding.service_artifact_hash_bound=${report.terminal_chain_boundary.nested_artifact_binding.service_artifact_hash_bound}; nested_artifact_binding.service_artifact_verification_bound_to_service_proof=${report.terminal_chain_boundary.nested_artifact_binding.service_artifact_verification_bound_to_service_proof}; nested_artifact_binding.creates_public_external_attestation=${report.terminal_chain_boundary.nested_artifact_binding.creates_public_external_attestation}; nested_artifact_binding.proves_current_machine_governance=${report.terminal_chain_boundary.nested_artifact_binding.proves_current_machine_governance}; nested_artifact_binding.proves_production_downstream_recognition=${report.terminal_chain_boundary.nested_artifact_binding.proves_production_downstream_recognition}`,
  );
  lines.push(
    `- claim_boundary=${report.terminal_chain_boundary.claim_boundary}`,
  );
  lines.push('Coverage map runtime contract:');
  lines.push(
    `- report_type=${report.coverage_map_boundary.report_type}; input_fixture_sha256=${report.coverage_map_boundary.input_fixture_sha256}; evidence_model=${report.coverage_map_boundary.evidence_model}; live_probing=${report.coverage_map_boundary.live_probing}; governed_lanes=${report.coverage_map_boundary.governed_lanes}/${report.coverage_map_boundary.counted_lanes}`,
  );
  lines.push(
    `- surface_id=${report.coverage_map_boundary.surface_id}; surface_governed=${report.coverage_map_boundary.surface_governed}; profile_sha256=${report.coverage_map_boundary.profile_sha256}; mutation_authoritative_route=${report.coverage_map_boundary.mutation_authoritative_route}`,
  );
  lines.push(
    `- terminal_chain_artifact_body_sha256=${report.coverage_map_boundary.terminal_chain_artifact_body_sha256}; nested_preflight_artifact_body_sha256=${report.coverage_map_boundary.nested_preflight_artifact_body_sha256}; nested_service_proof_artifact_body_sha256=${report.coverage_map_boundary.nested_service_proof_artifact_body_sha256}; artifact_hash_equivalence_with_fresh_run_claimed=${report.coverage_map_boundary.artifact_hash_equivalence_with_fresh_run_claimed}`,
  );
  lines.push(
    `- recognition_refusal_case_count=${report.coverage_map_boundary.recognition_refusal_case_count}; authority_refusal_case_count=${report.coverage_map_boundary.authority_refusal_case_count}; same_process_signed_payload_replay_refused=${report.coverage_map_boundary.same_process_signed_payload_replay_refused}; restart_consumed_authority_grant_refused=${report.coverage_map_boundary.restart_consumed_authority_grant_refused}; fixture_rightful_issuance_path_evidenced=${report.coverage_map_boundary.fixture_rightful_issuance_path_evidenced}; rightful_issuance_proven=${report.coverage_map_boundary.rightful_issuance_proven}; current_machine_governance_proven=${report.coverage_map_boundary.current_machine_governance_proven}; consequence_lifecycle_closed=${report.coverage_map_boundary.consequence_lifecycle_closed}`,
  );
  lines.push(
    `- claim_boundary=${report.coverage_map_boundary.claim_boundary}`,
  );
  lines.push('Deployment profile authority-material refusal bridge:');
  lines.push(
    `- proof_type=${report.deployment_profile_authority_bridge.proof_type}; evidence_model=${report.deployment_profile_authority_bridge.evidence_model}; live_probing=${report.deployment_profile_authority_bridge.live_probing}`,
  );
  lines.push(
    `- deployment_profile_id=${report.deployment_profile_authority_bridge.deployment_profile_id}; deployment_profile_sha256=${report.deployment_profile_authority_bridge.deployment_profile_sha256}; runtime_profile_sha256=${report.deployment_profile_authority_bridge.runtime_profile_sha256}`,
  );
  lines.push(
    `- deployment_profile_artifact_authoritative=${report.deployment_profile_authority_bridge.deployment_profile_artifact_authoritative}; selected_by_explicit_id_and_sha=${report.deployment_profile_authority_bridge.selected_by_explicit_id_and_sha}; selects_latest_profile=${report.deployment_profile_authority_bridge.selects_latest_profile}; preflight_artifact_verified=${report.deployment_profile_authority_bridge.preflight_artifact_verified}`,
  );
  lines.push(
    `- deployment_profile_authority_refusal_case_count=${report.deployment_profile_authority_bridge.deployment_profile_authority_refusal_case_count}; deployment_profile_authority_refusal_case_ids=${report.deployment_profile_authority_bridge.deployment_profile_authority_refusal_case_ids.join(',')}; deployment_profile_authority_refusals_before_service_proof=${report.deployment_profile_authority_bridge.deployment_profile_authority_refusals_before_service_proof}; deployment_profile_authority_refusals_before_mutation=${report.deployment_profile_authority_bridge.deployment_profile_authority_refusals_before_mutation}; deployment_profile_authority_refusal_service_proof_started=${report.deployment_profile_authority_bridge.deployment_profile_authority_refusal_service_proof_started}`,
  );
  lines.push(
    `- stale_deployment_profile_artifact_refused_before_service_proof=${report.deployment_profile_authority_bridge.stale_deployment_profile_artifact_refused_before_service_proof}; profile_recognition_mismatch_refused_before_service_proof=${report.deployment_profile_authority_bridge.profile_recognition_mismatch_refused_before_service_proof}; latest_profile_selection_refused_before_service_proof=${report.deployment_profile_authority_bridge.latest_profile_selection_refused_before_service_proof}; request_stream_authority_material_refused_before_service_proof=${report.deployment_profile_authority_bridge.request_stream_authority_material_refused_before_service_proof}`,
  );
  lines.push(
    `- recognized_receipt_mutates_once=${report.deployment_profile_authority_bridge.recognized_receipt_mutates_once}; recognized_state_entry_count_delta=${report.deployment_profile_authority_bridge.recognized_state_entry_count_delta}; all_required_refusals_before_mutation=${report.deployment_profile_authority_bridge.all_required_refusals_before_mutation}; agent_supplied_authority_refused_before_mutation=${report.deployment_profile_authority_bridge.agent_supplied_authority_refused_before_mutation}; direct_api_refused_before_mutation=${report.deployment_profile_authority_bridge.direct_api_refused_before_mutation}; downstream_refusal_proven=${report.deployment_profile_authority_bridge.downstream_refusal_proven}`,
  );
  lines.push(
    `- request_stream_authority_material_accepted=${report.deployment_profile_authority_bridge.request_stream_authority_material_accepted}; current_machine_governance=${report.deployment_profile_authority_bridge.current_machine_governance}; production_downstream_recognition=${report.deployment_profile_authority_bridge.production_downstream_recognition}; production_authority=${report.deployment_profile_authority_bridge.production_authority}; enterprise_readiness=${report.deployment_profile_authority_bridge.enterprise_readiness}; external_attestation=${report.deployment_profile_authority_bridge.external_attestation}; sovereign_recognition=${report.deployment_profile_authority_bridge.sovereign_recognition}; unrouted_surface_coverage=${report.deployment_profile_authority_bridge.unrouted_surface_coverage}`,
  );
  lines.push(
    `- claim_boundary=${report.deployment_profile_authority_bridge.claim_boundary}`,
  );
  lines.push('Downstream refusal boundary:');
  lines.push(
    `- provided=${report.downstream_refusal_boundary.provided}; recognized_boarded=${report.downstream_refusal_boundary.recognized_boarded}; recognized_marker_count_delta=${report.downstream_refusal_boundary.recognized_marker_count_delta}; final_marker_count=${report.downstream_refusal_boundary.final_marker_count}`,
  );
  lines.push(
    `- refusal_case_count=${report.downstream_refusal_boundary.refusal_case_count}; all_refusals_unboarded=${report.downstream_refusal_boundary.all_refusals_unboarded}; all_refusal_marker_count_deltas_zero=${report.downstream_refusal_boundary.all_refusal_marker_count_deltas_zero}; refusal_reasons=${report.downstream_refusal_boundary.refusal_reasons.join(',')}`,
  );
  lines.push('Forbidden claims:');
  for (const [key, value] of Object.entries(report.forbidden_claims)) {
    lines.push(`- ${key}=${value}`);
  }
  lines.push('Non-claims:');
  for (const nonClaim of report.non_claims) {
    lines.push(`- ${nonClaim}`);
  }
  const output = `${lines.join('\n')}\n`;
  assertNoUnsafeProductProofPathText(output);
  return output;
}
