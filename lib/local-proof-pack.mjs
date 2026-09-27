import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonicalize } from './canonicalize.mjs';
import {
  assertGovernedSurfaceCoverageMap,
  assertNoUnsafeCoverageMapText,
  buildGovernedSurfaceCoverageMap,
} from './governed-surface-coverage-map.mjs';
import {
  REQUIRED_REFUSAL_REASONS as DOWNSTREAM_REFUSAL_REASONS,
  assertDownstreamRefusalProof,
  runHermeticDownstreamRefusalProof,
} from './downstream-refusal-proof.mjs';
import {
  assertHumanAuthorizationProof,
  runHumanAuthorizationProof,
} from './human-authorization-proof.mjs';
import {
  assertApprovalTransportProof,
  runApprovalTransportProof,
} from './approval-transport-proof.mjs';
import {
  REQUIRED_REFUSAL_REASONS as ISSUER_STATUS_REFUSAL_REASONS,
  assertIssuerStatusProof,
  runIssuerStatusProof,
} from './issuer-status-proof.mjs';
import {
  RECEIPT_VERIFIER_BOUNDARY_NON_CLAIMS,
  RECEIPT_VERIFIER_BOUNDARY_PROOF_TYPE,
  RECEIPT_VERIFIER_BOUNDARY_SAFE_CLAIM_CEILING,
  assertReceiptVerifierBoundaryProof,
  runReceiptVerifierBoundaryProof,
} from './receipt-verifier-boundary-proof.mjs';
import {
  REQUIRED_REFUSAL_REASONS as PROTECTED_RECORDS_REFUSAL_REASONS,
  assertProtectedRecordsTerminalProof,
} from './protected-records-terminal-proof.mjs';
import {
  REQUIRED_CONFORMANCE_CASES as PROTECTED_RECORDS_CONFORMANCE_CASES,
  assertProtectedRecordsAdapterConformanceProof,
} from './protected-records-adapter-conformance.mjs';
import {
  REQUIRED_SERVICE_CASES as PROTECTED_RECORDS_SERVICE_CASES,
  assertProtectedRecordsServiceProof,
} from './protected-records-service-proof.mjs';
import {
  PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_TYPE,
  REQUIRED_PROFILE_PREFLIGHT_CASES as PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES,
  assertProtectedRecordsServiceProfilePreflight,
  assertProtectedRecordsServiceProfile,
  profileSha256,
} from './protected-records-service-profile.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_PROFILE_PREFLIGHT_TYPE,
  assertProtectedRecordsRuntimePreflightProfile,
  runtimeProfileSha256,
} from './protected-records-runtime-profile-preflight.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_TYPE,
  RUNTIME_ACTIVATION_PREFLIGHT_NON_CLAIMS,
  RUNTIME_ACTIVATION_PREFLIGHT_SAFE_CLAIM_CEILING,
  assertProtectedRecordsRuntimeActivationPreflight,
  assertProtectedRecordsRuntimeActivationPlan,
  runProtectedRecordsRuntimeActivationPreflight,
  runtimeActivationPlanSha256,
} from './protected-records-runtime-activation-preflight.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PROOF_TYPE,
  RUNTIME_LOCAL_ACTIVATION_NON_CLAIMS,
  RUNTIME_LOCAL_ACTIVATION_SAFE_CLAIM_CEILING,
  assertProtectedRecordsRuntimeLocalActivationPlan,
  assertProtectedRecordsRuntimeLocalActivationProof,
  runProtectedRecordsRuntimeLocalActivationProof,
  runtimeLocalActivationPlanSha256,
} from './protected-records-runtime-local-activation.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_PROOF_TYPE,
  REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPEN_BOUNDARIES,
  REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPERATOR_REQUIREMENTS,
  RUNTIME_PROFILE_INSTALLATION_NON_CLAIMS,
  RUNTIME_PROFILE_INSTALLATION_SAFE_CLAIM_CEILING,
  assertProtectedRecordsRuntimeProfileInstallationPlan,
  assertProtectedRecordsRuntimeProfileInstallationProof,
  runProtectedRecordsRuntimeProfileInstallationProof,
  runtimeProfileInstallationPlanSha256,
} from './protected-records-runtime-profile-installation.mjs';
import {
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_EVIDENCE_MODEL,
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_NON_CLAIMS,
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY,
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_TYPE,
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SAFE_CLAIM_CEILING,
  REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SIDE_DOORS,
  REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES,
  assertClaudeCodeHookContractReplayProof,
  claudeCodeHookContractReplayExpectedCaseSemantics,
  claudeCodeHookContractReplayInputContractSha256,
  claudeCodeHookContractReplayContractSha256,
  claudeCodeHookContractReplayRepoAdapterSha256,
  runClaudeCodeHookContractReplayProof,
} from './claude-code-hook-contract-replay-proof.mjs';
import {
  KEY_STATE_NON_CLAIMS,
  KEY_STATE_REPORT_TYPE,
  assertKeyStateReport,
  buildSampleKeyStateReport,
} from './key-state-report.mjs';
import {
  TRUSTED_RECEIPT_ISSUER_REGISTRY_V2_CONTRACT_EVIDENCE,
  assertTrustedReceiptIssuerRegistryV2Contract,
  evaluateTrustedReceiptIssuerRegistryV2Recognition,
  publicSafeTrustedReceiptIssuerRegistryV2Summary,
} from './trusted-receipt-issuer-registry.mjs';
import {
  createReceiptV1FromEvent,
  decodePayloadV1,
  signReceiptV1,
} from './receipt.mjs';
import {
  RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_SCOPE,
  RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_TYPE,
  RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY,
  RECORDS_WRITE_TERMINAL_ROUTE,
} from './records-write-terminal-proof.mjs';
import {
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
} from './protected-records-installed-runtime-profile-terminal-chain.mjs';
import {
  PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256,
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed,
  protectedRecordsFixtureAuthorityGrantEffectStatusReason,
  protectedRecordsFixtureAuthorityGrantStatus,
} from './protected-records-fixture-authority-status.mjs';

export const LOCAL_PROOF_PACK_TYPE = 'zlar-local-proof-pack-v1';
export const LOCAL_PROOF_PACK_ARTIFACT_TYPE = 'zlar-local-proof-pack-artifact-v1';
export const LOCAL_PROOF_PACK_ARTIFACT_CANONICALIZATION = 'zlar-canonical-json-v1';
export const LOCAL_PROOF_PACK_ARTIFACT_VERIFICATION_TYPE =
  'zlar-local-proof-pack-artifact-verification-v1';
export const LOCAL_PROOF_PACK_HISTORICAL_SAMPLE_ARTIFACT_BODY_SHA256 =
  'e24adc1735216e20dfb321db473cd58f6ca1b817c93d75e8b83ccf02a9622186';

const HISTORICAL_SAFE_CLAIM_CEILING =
  'ZLAR can run a local fixture proof pack that shows supplied coverage-map evidence, downstream refusal behavior, simulated-human authorization, channel-neutral approval transport behavior, issuer status refusal behavior, trusted issuer registry recognition over bundled local fixture evidence, a deterministic read-only key-state sample summary, local receipt-verifier VALID/UNKNOWN-SIGNER/INVALID boundary behavior, a protected records terminal refusal/replay boundary, protected-records adapter CLI-process conformance, protected-records downstream service refusal before mutation, service-profile preflight evidence, runtime-profile preflight identity metadata, runtime activation-plan preflight evidence, explicit local disposable runtime activation evidence with one launcher-owned fixture authority-grant rightful-issuance path, disposable runtime profile installation evidence with installed-state selection, and local Claude-shaped hook-contract replay evidence, without live probing, persistent install, hook configuration, user or machine configuration, production deployment, current-machine key custody, live Claude app passage, or external attestation.';

export const SAFE_CLAIM_CEILING =
  'ZLAR can validate a current static 4-of-6 coverage component and verify the exact committed historical local proof-pack artifact as structural boarding and refusal evidence. The one-use fixture authority grant is exhausted, so fresh proof-pack execution refuses before proof execution, the historical 6-of-6 snapshot is not current coverage, and fixture-rightful issuance is not projected. This does not prove generic, portable, live, production, current-machine, lifecycle-closed, externally attested, or sovereign governance.';

const HISTORICAL_FIXTURE_RIGHTFUL_ISSUANCE_NON_CLAIM =
  'The runtime-profile components carry one local fixture rightful-issuance path only; they do not prove generic, portable, live, production, or current-machine rightful issuance, and they do not prove consequence-lifecycle closure.';
const DETACHED_FIXTURE_RIGHTFUL_ISSUANCE_NON_CLAIM =
  'Detached structural verification does not project embedded fixture-rightful-issuance evidence. The historical schema also lacks an exact authority-grant contract SHA binding, so a caller-supplied artifact pin cannot restore that projection.';
const EXHAUSTED_FIXTURE_RIGHTFUL_ISSUANCE_NON_CLAIM =
  'The exact one-use fixture authority grant is exhausted. Fresh proof-pack execution and current fixture-rightful projection are refused; historical embedded positive fields remain historical artifact content only.';
const HISTORICAL_PROCESS_BOUNDARY_NON_CLAIM =
  'This proof pack may start local disposable JSONL child service processes and write disposable proof-harness runtime profile installation state, but it does not install a persistent runtime profile, write hook/user/machine configuration, write production configuration, or start a live production service.';
const CURRENT_PROCESS_BOUNDARY_NON_CLAIM =
  'Fresh proof-pack generation refuses before proof execution while the one-use fixture authority grant is exhausted. Read-only artifact verification does not start a service or write proof-harness runtime state.';

const SHARED_NON_CLAIMS_PREFIX = Object.freeze([
  'This proof pack does not inspect live hooks, live audit stores, or live downstream systems.',
  'This proof pack does not use Telegram or prove live human approval-channel delivery.',
  'This proof pack does not prove production deployment.',
  'This proof pack does not prove external attestation or sovereign recognition.',
  'This proof pack does not prove coverage of unrouted paths.',
  'This proof pack verifies a local ephemeral receipt under supplied public keys, but it does not prove active issuer status, key custody, revocation state, downstream recognition, or production relying-party acceptance.',
  'This proof pack recognizes a bundled local trusted-issuer registry fixture; it does not prove live trust-registry state, live issuer status, key custody, revocation truth, production downstream recognition, production authority, public external attestation, real non-operator review, or sovereign recognition.',
  'This proof pack carries a deterministic key-state sample report; it does not inspect operator home key material, hardware, key custody, revocation truth, production trust registry state, or current-machine governance.',
]);
const SHARED_NON_CLAIMS_SUFFIX = Object.freeze([
  'This proof pack may locally replay Claude-shaped PreToolUse hook payloads through the repo Claude Code adapter fixture, but it does not invoke the claude CLI, prove live Claude app passage, prove app-originated hook crossing, write installed hooks/config, or prove current-machine governance.',
]);
const HISTORICAL_NON_CLAIMS = Object.freeze([
  ...SHARED_NON_CLAIMS_PREFIX,
  HISTORICAL_PROCESS_BOUNDARY_NON_CLAIM,
  HISTORICAL_FIXTURE_RIGHTFUL_ISSUANCE_NON_CLAIM,
  ...SHARED_NON_CLAIMS_SUFFIX,
]);
export const NON_CLAIMS = Object.freeze([
  ...SHARED_NON_CLAIMS_PREFIX,
  CURRENT_PROCESS_BOUNDARY_NON_CLAIM,
  EXHAUSTED_FIXTURE_RIGHTFUL_ISSUANCE_NON_CLAIM,
  ...SHARED_NON_CLAIMS_SUFFIX,
]);

const LOCAL_PROOF_PACK_KEYS = Object.freeze([
  'components',
  'evidence_model',
  'live_probing',
  'non_claims',
  'proof_pack_type',
  'safe_claim_ceiling',
]);

const LOCAL_PROOF_PACK_ARTIFACT_COMPONENT_MANIFEST_HASH_SCOPE =
  'canonical payload components in artifact order';
const LOCAL_PROOF_PACK_ARTIFACT_CLAIM_BINDING_HASH_SCOPE =
  'canonical safe claim ceiling and non-claims';

const LOCAL_PROOF_PACK_ARTIFACT_COMPONENT_MANIFEST_ITEM_KEYS = Object.freeze([
  'component',
  'component_sha256',
  'evidence_model',
  'identity',
  'identity_type',
  'live_probing',
  'source_state_boundary',
]);

const LOCAL_PROOF_PACK_ARTIFACT_CLAIM_BINDING_KEYS = Object.freeze([
  'hash_scope',
  'non_claim_count',
  'non_claims_sha256',
  'safe_claim_ceiling_sha256',
]);

const LOCAL_PROOF_PACK_COMPONENT_NAMES = Object.freeze([
  'governed_surface_coverage_map',
  'downstream_refusal_proof',
  'human_authorization_proof',
  'approval_transport_proof',
  'issuer_status_proof',
  'trusted_issuer_registry_recognition',
  'key_state_report',
  'receipt_verifier_boundary',
  'protected_records_terminal',
  'protected_records_adapter_conformance',
  'protected_records_downstream_service',
  'protected_records_runtime_profile_preflight_identity',
  'protected_records_runtime_activation_preflight',
  'protected_records_runtime_local_activation',
  'protected_records_runtime_profile_installation',
  'claude_code_hook_contract_replay',
]);

const LOCAL_PROOF_PACK_HISTORICAL_COVERAGE_COMPONENT_KEYS = Object.freeze([
  'boundary_entries',
  'command',
  'component',
  'counted_lanes',
  'evidence_model',
  'governed_lanes',
  'live_probing',
  'report_type',
]);

const LOCAL_PROOF_PACK_COMPONENT_KEY_MAP = Object.freeze({
  governed_surface_coverage_map: Object.freeze([
    'boundary_entries',
    'command',
    'component',
    'counted_lanes',
    'evidence_model',
    'governed_lanes',
    'live_probing',
    'report_type',
    'terminal_artifact_body_sha256',
    'terminal_artifact_expected_body_sha256',
    'terminal_artifact_identity_sha256_matched',
    'terminal_fixture_rightful_issuance_path_evidenced',
    'terminal_outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256',
    'terminal_recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256',
    'terminal_trusted_issuer_registry_signature_valid',
  ]),
  downstream_refusal_proof: Object.freeze([
    'all_refusal_marker_count_deltas_zero',
    'all_refusals_unboarded',
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
  ]),
  human_authorization_proof: Object.freeze([
    'approval_channel',
    'authorized_boarded',
    'authorizer',
    'command',
    'component',
    'denied_boarded',
    'evidence_model',
    'live_probing',
    'outcome',
    'pending_boarded',
    'proof_type',
  ]),
  approval_transport_proof: Object.freeze([
    'command',
    'component',
    'delivered_without_decision_boarded',
    'evidence_model',
    'live_probing',
    'proof_type',
    'reference_transport_healthy',
    'signed_human_decision_boarded',
    'telegram_required_for_fixture',
    'transport_model',
    'unavailable_boarded',
  ]),
  issuer_status_proof: Object.freeze([
    'active_issuer_boarded',
    'command',
    'component',
    'compromised_issuer_refused',
    'evidence_model',
    'live_probing',
    'missing_key_issuer_refused',
    'missing_status_issuer_refused',
    'proof_type',
    'refusal_reasons',
    'retired_issuer_refused',
    'trust_anchor_model',
    'unknown_issuer_refused',
  ]),
  trusted_issuer_registry_recognition: Object.freeze([
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
    'non_claims',
    'production_authority',
    'production_downstream_recognition_proven',
    'production_trust_registry_proven',
    'public_external_attestation',
    'real_non_operator_review',
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
    'revocation_truth_proven',
    'safe_claim_ceiling',
    'signature_valid',
    'sovereign_recognition',
    'verdict',
  ]),
  key_state_report: Object.freeze([
    'claim_boundary',
    'command',
    'component',
    'constitution_current_ceremony_ready',
    'constitution_hardware_target_observed',
    'constitution_software_pins_aligned',
    'current_machine_governance_proven',
    'evidence_model',
    'external_attestation',
    'fingerprint_convention',
    'key_custody_proven',
    'live_probing',
    'local_private_key_presence',
    'non_claims',
    'operational_pins',
    'operational_posture',
    'policy_current_ceremony_ready',
    'policy_hardware_target_observed',
    'policy_software_pins_aligned',
    'privacy',
    'production_trust_registry_proven',
    'public_verifiers',
    'read_only',
    'report_type',
    'revocation_state_proven',
    'sovereign_recognition',
    'spec_hardware_target_observed',
    'tools',
  ]),
  receipt_verifier_boundary: Object.freeze([
    'command',
    'component',
    'current_machine_governance_proven',
    'distinguishes_unknown_signer_from_invalid',
    'downstream_recognition_proven',
    'evidence_model',
    'external_attestation',
    'help_exit_code',
    'help_names_non_claims',
    'help_names_unknown_signer',
    'invalid_exit_code',
    'invalid_format',
    'invalid_kid_match',
    'invalid_provided_pubkey_sha256_matches_valid',
    'invalid_provided_kid_present',
    'invalid_receipt_id_present',
    'invalid_receipt_kid_present',
    'invalid_receipt_sha256_differs_from_valid',
    'invalid_receipt_version',
    'invalid_verdict',
    'issuer_recognition_proven',
    'key_custody_proven',
    'legacy_v0_required_identity_exit_code',
    'legacy_v0_required_identity_refused',
    'live_probing',
    'non_claims',
    'production_deployment_proven',
    'proof_type',
    'receipt_type',
    'receipt_version',
    'revocation_state_proven',
    'safe_claim_ceiling',
    'semantic_checks_checked',
    'signed_byte_integrity_checked',
    'sovereign_recognition',
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
    'unknown_signer_provided_kid_present',
    'unknown_signer_reason',
    'unknown_signer_receipt_id_present',
    'unknown_signer_receipt_kid_present',
    'unknown_signer_receipt_sha256_matches_valid',
    'unknown_signer_verdict',
    'unrouted_paths_coverage_proven',
    'valid_command_posture_allow_v0',
    'valid_command_posture_detected_format',
    'valid_exit_code',
    'valid_format',
    'valid_kid_match',
    'valid_provided_pubkey_sha256_present',
    'valid_provided_kid_present',
    'valid_receipt_id_present',
    'valid_receipt_kid_present',
    'valid_receipt_sha256_present',
    'valid_receipt_version',
    'valid_required_identity_command_posture',
    'valid_verdict',
  ]),
  protected_records_terminal: Object.freeze([
    'action_class',
    'adapter_action_command',
    'adapter_action_fixture_mode_required',
    'adapter_action_live_records_adapter',
    'adapter_action_raw_record_detail_output',
    'adapter_action_result_type',
    'adapter_action_type',
    'adapter_action_writes',
    'adapter_authoritative_route',
    'adapter_boundary',
    'adapter_closed_in_fixture',
    'adapter_consumed_receipt_count',
    'adapter_consumed_receipt_store',
    'adapter_direct_write_path_available',
    'adapter_final_ledger_entry_count',
    'adapter_known_open_boundaries',
    'adapter_ledger_model',
    'adapter_live_records_adapter',
    'adapter_profile_id',
    'adapter_profile_type',
    'adapter_replay_scope',
    'all_refusals_prevented_record_change',
    'command',
    'component',
    'deployment_profile',
    'downstream_boundary',
    'evidence_model',
    'final_record_count',
    'known_ungoverned_boundaries',
    'live_probing',
    'profile_contract_checkpoint',
    'profile_contract_downstream_effect',
    'profile_contract_id',
    'profile_contract_route',
    'proof_type',
    'receipt_replay_policy',
    'recognized_record_changed',
    'recognized_record_count_delta',
    'recognized_write_accepted',
    'refusal_reasons',
    'refusal_record_count_delta_total',
    'refused_write_count',
    'required_receipt_fields',
  ]),
  protected_records_adapter_conformance: Object.freeze([
    'action_class',
    'adapter_command',
    'adapter_process_boundary',
    'adapter_type',
    'cli_direct_write_option_available',
    'command',
    'component',
    'conformance_cases',
    'consumed_receipt_store',
    'direct_filesystem_write_to_fixture_paths_closed',
    'evidence_model',
    'known_open_boundaries',
    'ledger_model',
    'live_probing',
    'live_records_adapter',
    'missing_receipt_ledger_delta',
    'missing_receipt_reason',
    'missing_receipt_refused',
    'mutation_authoritative_route',
    'profile_id',
    'proof_type',
    'recognized_write_accepted',
    'recognized_write_ledger_delta',
    'recognized_write_reason',
    'replay_ledger_delta',
    'replay_reason',
    'replay_refused',
    'replay_scope',
    'replay_separate_process',
    'result_type',
    'unsupported_side_door_ledger_delta',
    'unsupported_side_door_reason',
    'unsupported_side_door_refused',
  ]),
  protected_records_downstream_service: Object.freeze([
    'action_class',
    'command',
    'component',
    'consumed_receipt_store',
    'direct_api_attempted',
    'direct_api_reason',
    'direct_api_request_model',
    'direct_api_state_delta',
    'direct_api_without_receipt_refused',
    'direct_api_without_receipt_refused_reported',
    'direct_filesystem_write_to_fixture_paths_closed',
    'evidence_model',
    'invalid_receipt_reason',
    'invalid_receipt_refused',
    'invalid_receipt_state_delta',
    'known_open_boundaries',
    'live_probing',
    'live_records_service',
    'missing_receipt_reason',
    'missing_receipt_refused',
    'missing_receipt_state_delta',
    'mutation_authoritative_route',
    'profile_id',
    'proof_type',
    'recognition_boundary',
    'recognized_service_reason',
    'recognized_service_state_delta',
    'recognized_service_write_accepted',
    'replay_reason',
    'replay_refused',
    'replay_scope',
    'replay_separate_process',
    'replay_state_delta',
    'result_type',
    'service_cases',
    'service_command',
    'service_process_boundary',
    'service_profile_preflight_case_count',
    'service_profile_preflight_case_summaries',
    'service_profile_preflight_cases',
    'service_profile_preflight_deployment_posture',
    'service_profile_preflight_direct_api_with_receipt_refused',
    'service_profile_preflight_direct_api_without_receipt_refused',
    'service_profile_preflight_direct_filesystem_write_to_fixture_paths_closed',
    'service_profile_preflight_evidence_model',
    'service_profile_preflight_external_attestation',
    'service_profile_preflight_invalid_receipt_refused',
    'service_profile_preflight_known_open_boundaries',
    'service_profile_preflight_launcher_owned_config_required',
    'service_profile_preflight_live_approval_channel_health_checked',
    'service_profile_preflight_live_mcp_coverage_checked',
    'service_profile_preflight_live_probing',
    'service_profile_preflight_live_profile_installed',
    'service_profile_preflight_live_records_system_checked',
    'service_profile_preflight_missing_receipt_refused',
    'service_profile_preflight_non_claims',
    'service_profile_preflight_production_records_service_checked',
    'service_profile_preflight_profile_id',
    'service_profile_preflight_profile_sha256',
    'service_profile_preflight_profile_status',
    'service_profile_preflight_recognized_write_accepted',
    'service_profile_preflight_replay_refused',
    'service_profile_preflight_request_stream_authority_material_allowed',
    'service_profile_preflight_request_stream_authority_material_reason',
    'service_profile_preflight_request_stream_authority_material_refused',
    'service_profile_preflight_request_stream_authority_material_state_delta',
    'service_profile_preflight_request_stream_forbidden_fields_refused',
    'service_profile_preflight_required_case_count',
    'service_profile_preflight_run_in_proof_pack',
    'service_profile_preflight_runtime_profile_activation_checked',
    'service_profile_preflight_sovereign_recognition',
    'service_profile_preflight_stale_receipt_refused',
    'service_profile_preflight_type',
    'service_profile_preflight_unknown_issuer_refused',
    'service_profile_preflight_unrecognized_receipt_refused',
    'service_profile_preflight_unrouted_records_paths_checked',
    'service_profile_preflight_wrong_policy_reason',
    'service_profile_preflight_wrong_policy_refused',
    'service_profile_preflight_wrong_policy_state_delta',
    'service_type',
    'stale_receipt_reason',
    'stale_receipt_refused',
    'stale_receipt_state_delta',
    'state_model',
    'unknown_issuer_reason',
    'unknown_issuer_refused',
    'unknown_issuer_state_delta',
    'unrecognized_receipt_reason',
    'unrecognized_receipt_refused',
    'unrecognized_receipt_state_delta',
  ]),
  protected_records_runtime_profile_preflight_identity: Object.freeze([
    'action_class',
    'atomic_store_anchor_witness_commit',
    'authority_grant_appointment_required_from_launcher',
    'authority_grant_contract_required_from_launcher',
    'authority_grant_issuance_decision_required_from_launcher',
    'authorized_record_update_required_from_launcher',
    'component',
    'config_supplied_by_launcher',
    'consumed_authority_grant_store',
    'consumed_grant_store_anchor_path_exposed_to_agent',
    'consumed_grant_store_witness_path_exposed_to_agent',
    'consumed_grants_path_exposed_to_agent',
    'consumed_store_anchor',
    'consumed_store_lock',
    'consumed_store_rollback_detection',
    'consumed_store_validation',
    'consumed_store_witness',
    'consumed_store_write_model',
    'consequence_lifecycle_closed',
    'consumption_identity',
    'current_machine_governance_proven',
    'deployment_posture',
    'exactly_once_effect_semantics',
    'fixture_rightful_issuance_path_evidenced',
    'host_filesystem_path_toctou_closed',
    'known_open_boundaries',
    'mutation_authoritative_route',
    'preflight_command',
    'portable_rightful_issuance_proven',
    'production_rightful_issuance_proven',
    'production_grade_anti_rollback',
    'profile_id',
    'profile_sha256',
    'profile_status',
    'profile_type',
    'proof_command',
    'recognition_rule_supplied_by_agent',
    'replay_scope',
    'request_contract',
    'request_stream_authority_material_accepted',
    'required_boundary_observation_count',
    'required_case_count',
    'rightful_issuance_proven',
    'runtime_profile_id',
    'runtime_profile_preflight_run_in_proof_pack',
    'runtime_profile_proof_run_in_proof_pack',
    'service_command',
    'signed_payload_replay_identity',
    'single_host_rollback_detection',
    'source_profile_authority_grant_present',
    'state_path_exposed_to_agent',
    'store_and_anchor_joint_rollback_refused_while_witness_ahead',
    'store_anchor_and_witness_joint_rollback_detection',
    'partial_grant_commit_burn_window_named',
    'live_authority_proven',
  ]),
  protected_records_runtime_activation_preflight: Object.freeze([
    'action_class',
    'activation_applied',
    'agent_supplied_authority_material_refused',
    'atomic_store_anchor_witness_commit',
    'authority_grant_appointment_required_from_launcher',
    'authority_grant_contract_required_from_launcher',
    'authority_grant_issuance_decision_required_from_launcher',
    'authorized_record_update_required_from_launcher',
    'component',
    'config_path_agent_supplied',
    'consumed_authority_grant_store',
    'consumed_authority_grant_store_deletion_refused',
    'consumed_authority_grant_store_replacement_refused',
    'consumed_authority_grant_store_rollback_refused',
    'consumed_grant_store_anchor_path_agent_supplied',
    'consumed_grant_store_witness_path_agent_supplied',
    'consumed_grants_path_agent_supplied',
    'consumed_store_witness',
    'consumed_store_write_model',
    'consequence_lifecycle_closed',
    'consumption_identity',
    'current_machine_governance_proven',
    'deployment_posture',
    'downstream_recognition_required',
    'evidence_model',
    'external_attestation',
    'expired_authority_grant_refused',
    'fixture_rightful_issuance_path_evidenced',
    'host_filesystem_path_toctou_closed',
    'issuer_registry_agent_supplied',
    'known_open_boundaries',
    'launcher_supplies_config',
    'live_approval_channel_health_checked',
    'live_mcp_coverage_checked',
    'live_probing',
    'live_records_system_checked',
    'missing_or_unrecognized_receipt_refused',
    'mutation_authoritative_route',
    'missing_authority_grant_appointment_refused',
    'mismatched_authority_grant_appointment_refused',
    'omitted_request_runtime_profile_id_present',
    'omitted_runtime_profile_id_consumed_authority_grant_count',
    'omitted_runtime_profile_id_reason_code',
    'omitted_runtime_profile_id_state_entry_count_delta',
    'omitted_runtime_profile_id_uses_launcher_config',
    'operator_install_requirements',
    'persistent_runtime_profile_installed',
    'plan_id',
    'plan_sha256',
    'plan_status',
    'plan_type',
    'preflight_command',
    'preflight_non_claims',
    'preflight_type',
    'partial_grant_commit_burn_window_named',
    'portable_rightful_issuance_proven',
    'production_records_service_checked',
    'proof_command',
    'recognition_rule_agent_supplied',
    'recognized_write_accepted',
    'request_supplied_authority_grant_refused',
    'restart_consumed_authority_grant_refused',
    'revoked_authority_grant_refused',
    'rightful_issuance_proven',
    'request_runtime_profile_id_required',
    'request_stream_authority_material_accepted',
    'requires_explicit_human_install',
    'runtime_activation_preflight_run_in_proof_pack',
    'runtime_profile_boundary_observation_count',
    'runtime_profile_id',
    'runtime_profile_identity_authority_source',
    'runtime_profile_identity_request_stream_policy',
    'runtime_profile_preflight_command',
    'runtime_profile_preflight_evidence_model',
    'runtime_profile_preflight_run_in_proof_pack',
    'runtime_profile_preflight_type',
    'runtime_profile_proof_case_count',
    'runtime_profile_proof_required_case_count',
    'runtime_profile_proof_run_in_proof_pack',
    'runtime_profile_required_boundary_observation_count',
    'runtime_profile_sha256',
    'runtime_profile_sha_matches_plan',
    'runtime_profile_source',
    'safe_claim_ceiling',
    'selects_latest_profile',
    'service_command',
    'same_process_signed_payload_replay_refused',
    'signed_payload_replay_identity',
    'sovereign_recognition',
    'starts_runtime_service',
    'state_path_agent_supplied',
    'store_and_anchor_joint_rollback_refused_against_witness',
    'store_and_anchor_joint_rollback_refused_while_witness_ahead',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse',
    'supplied_mismatch_reason_code',
    'supplied_mismatch_state_entry_count_delta',
    'supplied_mismatched_runtime_profile_id_refused',
    'unrouted_records_paths_checked',
    'uses_live_records_system',
    'witness_commit_failed_after_authority_grant_store_commit',
    'witness_commit_failure_reason_code',
    'writes_hook_configuration',
    'writes_runtime_config',
    'production_rightful_issuance_proven',
    'live_authority_proven',
  ]),
  protected_records_runtime_local_activation: Object.freeze([
    'action_class',
    'active_profile_selection',
    'agent_supplied_authority_material_refused',
    'atomic_store_anchor_witness_commit',
    'component',
    'consumed_authority_grant_store',
    'consumed_store_witness',
    'consumed_store_write_model',
    'consequence_lifecycle_closed',
    'consumption_identity',
    'current_machine_governance_proven',
    'deployment_posture',
    'direct_api_with_receipt_refused',
    'direct_api_without_receipt_refused',
    'disposable_runtime_config_written',
    'evidence_model',
    'exactly_once_effect_semantics',
    'external_attestation',
    'expired_authority_grant_refused',
    'fixture_rightful_issuance_path_evidenced',
    'hook_configuration_written',
    'host_filesystem_path_toctou_closed',
    'invalid_receipt_refused',
    'known_open_boundaries',
    'latest_profile_selected',
    'live_approval_channel_health_checked',
    'live_mcp_coverage_checked',
    'live_probing',
    'live_records_system_checked',
    'local_activation_applied',
    'local_activation_command',
    'local_activation_non_claims',
    'missing_issuer_status_refused',
    'missing_receipt_refused',
    'mutation_authoritative_route',
    'missing_authority_grant_appointment_refused',
    'mismatched_authority_grant_appointment_refused',
    'non_boarding_outcome_refused',
    'omitted_request_runtime_profile_id_present',
    'omitted_runtime_profile_id_consumed_authority_grant_count',
    'omitted_runtime_profile_id_reason_code',
    'omitted_runtime_profile_id_state_entry_count_delta',
    'omitted_runtime_profile_id_uses_launcher_config',
    'operator_requirements',
    'persistent_runtime_config_written',
    'persistent_runtime_profile_installed',
    'plan_id',
    'plan_sha256',
    'plan_status',
    'plan_type',
    'partial_grant_commit_burn_window_named',
    'portable_rightful_issuance_proven',
    'production_records_service_checked',
    'proof_type',
    'recognized_write_accepted',
    'request_supplied_authority_grant_refused',
    'restart_consumed_authority_grant_refused',
    'revoked_authority_grant_refused',
    'rightful_issuance_proven',
    'same_process_signed_payload_replay_refused',
    'request_runtime_profile_id_required',
    'request_stream_authority_material_accepted',
    'retired_issuer_refused',
    'runtime_local_activation_run_in_proof_pack',
    'runtime_profile_boundary_observation_count',
    'runtime_profile_id',
    'runtime_profile_identity_authority_source',
    'runtime_profile_identity_request_stream_policy',
    'runtime_profile_proof_case_count',
    'runtime_profile_proof_command',
    'runtime_profile_proof_required_case_count',
    'runtime_profile_proof_run_in_proof_pack',
    'runtime_profile_proof_type',
    'runtime_profile_required_boundary_observation_count',
    'runtime_profile_sha256',
    'runtime_profile_sha_matches_plan',
    'runtime_profile_source',
    'runtime_service_started',
    'safe_claim_ceiling',
    'service_command',
    'signed_payload_replay_identity',
    'sovereign_recognition',
    'stale_receipt_refused',
    'store_and_anchor_joint_rollback_refused_against_witness',
    'store_and_anchor_joint_rollback_refused_while_witness_ahead',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse',
    'supplied_mismatch_reason_code',
    'supplied_mismatch_state_entry_count_delta',
    'supplied_mismatched_runtime_profile_id_refused',
    'unknown_issuer_refused',
    'unrouted_records_paths_checked',
    'wrong_audit_event_refused',
    'wrong_detail_refused',
    'wrong_domain_refused',
    'wrong_policy_refused',
    'wrong_runtime_profile_id_refused',
    'wrong_tool_refused',
    'witness_commit_failed_after_authority_grant_store_commit',
    'witness_commit_failure_reason_code',
    'production_rightful_issuance_proven',
    'live_authority_proven',
  ]),
  protected_records_runtime_profile_installation: Object.freeze([
    'action_class',
    'active_profile_index_written',
    'agent_supplied_authority_material_refused',
    'atomic_store_anchor_witness_commit',
    'component',
    'consumed_authority_grant_store',
    'consumed_store_witness',
    'consumed_store_write_model',
    'consequence_lifecycle_closed',
    'consumption_identity',
    'current_machine_governance_proven',
    'deployment_posture',
    'direct_api_with_receipt_refused',
    'direct_api_without_receipt_refused',
    'disposable_profile_installation_applied',
    'disposable_profile_selection',
    'disposable_runtime_config_written',
    'evidence_model',
    'exactly_once_effect_semantics',
    'external_attestation',
    'expired_authority_grant_refused',
    'fixture_rightful_issuance_path_evidenced',
    'hook_configuration_written',
    'host_filesystem_path_toctou_closed',
    'installation_command',
    'invalid_receipt_refused',
    'known_open_boundaries',
    'latest_profile_selected',
    'live_approval_channel_health_checked',
    'live_mcp_coverage_checked',
    'live_probing',
    'live_records_system_checked',
    'live_runtime_profile_checked',
    'local_disposable_install_root_created',
    'machine_config_written',
    'missing_issuer_status_refused',
    'missing_receipt_refused',
    'mutation_authoritative_route',
    'missing_authority_grant_appointment_refused',
    'mismatched_authority_grant_appointment_refused',
    'non_boarding_outcome_refused',
    'omitted_request_runtime_profile_id_present',
    'omitted_runtime_profile_id_consumed_authority_grant_count',
    'omitted_runtime_profile_id_reason_code',
    'omitted_runtime_profile_id_state_entry_count_delta',
    'omitted_runtime_profile_id_uses_launcher_config',
    'operator_requirements',
    'persistent_runtime_config_written',
    'persistent_runtime_profile_installed',
    'plan_id',
    'plan_sha256',
    'plan_status',
    'plan_type',
    'partial_grant_commit_burn_window_named',
    'portable_rightful_issuance_proven',
    'production_records_service_checked',
    'profile_copied_to_install_root',
    'profile_installation_non_claims',
    'profile_selected_from_install_root',
    'proof_type',
    'recognized_write_accepted',
    'request_supplied_authority_grant_refused',
    'restart_consumed_authority_grant_refused',
    'revoked_authority_grant_refused',
    'rightful_issuance_proven',
    'same_process_signed_payload_replay_refused',
    'request_authority_guard_summary',
    'request_runtime_profile_id_required',
    'request_stream_authority_material_accepted',
    'retired_issuer_refused',
    'runtime_profile_boundary_observation_count',
    'runtime_profile_id',
    'runtime_profile_identity_authority_source',
    'runtime_profile_identity_request_stream_policy',
    'runtime_profile_installation_run_in_proof_pack',
    'runtime_profile_proof_case_count',
    'runtime_profile_proof_command',
    'runtime_profile_proof_required_case_count',
    'runtime_profile_proof_run_in_proof_pack',
    'runtime_profile_proof_type',
    'runtime_profile_required_boundary_observation_count',
    'runtime_profile_sha256',
    'runtime_profile_sha_matches_plan',
    'runtime_profile_source',
    'runtime_service_started',
    'safe_claim_ceiling',
    'service_command',
    'signed_payload_replay_identity',
    'sovereign_recognition',
    'stale_receipt_refused',
    'store_anchor_and_witness_joint_rollback_detection',
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
    'production_rightful_issuance_proven',
    'live_authority_proven',
  ]),
  claude_code_hook_contract_replay: Object.freeze([
    'adapter_path_claimed',
    'adapter_sha256',
    'adapter_source',
    'all_required_cases_present',
    'all_surface_governance_proven',
    'app_originated_hook_crossing_proven',
    'blank_gate_response_failed_closed',
    'case_evidence',
    'case_evidence_hash_scope',
    'case_evidence_sha256',
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
    'non_claims',
    'non_pretooluse_payload_denied_by_fixture_gate',
    'permission_decisions_observed',
    'production_downstream_recognition_proven',
    'proof_type',
    'required_case_count',
    'required_cases',
    'safe_claim_ceiling',
    'side_door_closure_proven',
    'side_doors',
    'source_state_boundary',
    'supporting_local_boarding_consequence_absent_on_every_refusal',
    'supporting_local_boarding_consequence_present_exactly_once_on_acceptance',
    'supporting_local_boarding_legacy_v0_recognized_boarding_identity',
    'supporting_local_boarding_proof_passed',
    'supporting_local_boarding_proof_type',
    'supporting_local_boarding_v1_receipt_identity_verified',
    'tool_input_not_executed',
  ]),
});

const DOWNSTREAM_REFUSAL_COMPONENT_KEYS = Object.freeze([
  'all_refusal_marker_count_deltas_zero',
  'all_refusals_unboarded',
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
]);

const TRUSTED_ISSUER_REGISTRY_RECOGNITION_CLAIM_BOUNDARY =
  'trusted issuer registry recognition over bundled local fixture evidence only; no live registry, live issuer status, key custody, revocation truth, production trust registry, production downstream recognition, production authority, sovereign recognition, public external attestation, or real non-operator review claim';

const TRUSTED_ISSUER_REGISTRY_RECOGNITION_NON_CLAIMS = Object.freeze([
  'This component recognizes only a bundled local trusted-issuer registry fixture.',
  'This component does not inspect a live trust registry, live issuer status, live hooks, live audit stores, runtime state, or production downstream systems.',
  'This component does not prove key custody, revocation truth, production trust-registry state, production downstream recognition, production authority, public external attestation, real non-operator review, sovereign recognition, current-machine governance, or coverage of unrouted paths.',
]);

const TRUSTED_ISSUER_REGISTRY_FIXTURE_NON_CLAIMS = Object.freeze([
  'This fixture does not inspect a live or production trust registry.',
  'This fixture does not prove key custody, hardware possession, revocation truth, compromise response, or production signing identity.',
  'This fixture does not prove routed coverage, live downstream deployment recognition, production authority, external attestation, sovereign recognition, or coverage of unrouted surfaces.',
]);

const TRUSTED_ISSUER_REGISTRY_RECOGNITION_KEYS = Object.freeze([
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
  'non_claims',
  'production_authority',
  'production_downstream_recognition_proven',
  'production_trust_registry_proven',
  'public_external_attestation',
  'real_non_operator_review',
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
  'revocation_truth_proven',
  'safe_claim_ceiling',
  'signature_valid',
  'sovereign_recognition',
  'verdict',
]);

const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_COMPONENT_KEYS = Object.freeze([
  'adapter_path_claimed',
  'adapter_sha256',
  'adapter_source',
  'all_required_cases_present',
  'all_surface_governance_proven',
  'app_originated_hook_crossing_proven',
  'blank_gate_response_failed_closed',
  'case_evidence',
  'case_evidence_hash_scope',
  'case_evidence_sha256',
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
  'non_claims',
  'non_pretooluse_payload_denied_by_fixture_gate',
  'permission_decisions_observed',
  'production_downstream_recognition_proven',
  'proof_type',
  'required_case_count',
  'required_cases',
  'safe_claim_ceiling',
  'side_door_closure_proven',
  'side_doors',
  'source_state_boundary',
  'supporting_local_boarding_consequence_absent_on_every_refusal',
  'supporting_local_boarding_consequence_present_exactly_once_on_acceptance',
  'supporting_local_boarding_legacy_v0_recognized_boarding_identity',
  'supporting_local_boarding_proof_passed',
  'supporting_local_boarding_proof_type',
  'supporting_local_boarding_v1_receipt_identity_verified',
  'tool_input_not_executed',
]);

const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASE_EVIDENCE_KEYS = Object.freeze([
  'audit_session_worker_receipt_deltas',
  'cases',
  'evidence_type',
  'hash_scope',
  'marker',
  'sentinel',
  'supporting_local_boarding_proof',
]);

const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASE_EVIDENCE_CASE_KEYS = Object.freeze([
  'adapter_exit_code',
  'case_id',
  'case_result',
  'denied_effect_executed',
  'gate_mode',
  'hook_event_name',
  'input_contract_sha256',
  'permission_decision',
  'permission_decision_reason_present',
  'proof_refusal_reason',
  'refused_before_effect',
  'sentinel_unchanged',
  'stderr_empty',
  'stderr_sha256',
  'stdout_json_valid',
  'stdout_sha256',
  'valid_claude_hook_json',
]);

const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASE_EVIDENCE_HASH_SCOPE =
  'canonical hook replay case, normalized input-contract, sentinel, marker, audit-delta, and supporting-boarding evidence embedded in local proof pack';

const TRUSTED_ISSUER_REGISTRY_SCHEMA_KEYS = Object.freeze([
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
  { label: 'Slack token', pattern: /\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b/ },
  { label: 'AWS access key', pattern: /\bAKIA[0-9A-Z]{12,}\b/ },
  { label: 'OpenAI-style key', pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/ },
  { label: 'bot token', pattern: /\bbot[0-9]{6,}:[A-Za-z0-9_-]{6,}\b/ },
]);

const COVERAGE_FIXTURE_URL = new URL(
  '../tests/fixtures/governed-surface-coverage-map-v1-input.json',
  import.meta.url
);
const PROTECTED_RECORDS_SERVICE_PROFILE_URL = new URL(
  '../profiles/protected-records-service-fixture.profile.json',
  import.meta.url
);
const PROTECTED_RECORDS_RUNTIME_PROFILE_URL = new URL(
  '../profiles/protected-records-runtime-fixture.profile.json',
  import.meta.url
);
const PROTECTED_RECORDS_RUNTIME_ACTIVATION_PLAN_URL = new URL(
  '../profiles/protected-records-runtime-activation-plan.fixture.json',
  import.meta.url
);
const PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PLAN_URL = new URL(
  '../profiles/protected-records-runtime-local-activation-plan.fixture.json',
  import.meta.url
);
const PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_PLAN_URL = new URL(
  '../profiles/protected-records-runtime-profile-installation-plan.fixture.json',
  import.meta.url
);

function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function componentIdentity(item) {
  const candidates = [
    ['proof_type', item.proof_type],
    ['report_type', item.report_type],
    ['preflight_type', item.preflight_type],
    ['service_profile_preflight_type', item.service_profile_preflight_type],
    ['runtime_profile_preflight_type', item.runtime_profile_preflight_type],
    ['profile_type', item.profile_type],
    ['registry_type', item.registry_type],
  ];
  const match = candidates.find(([, value]) => typeof value === 'string' && value);
  if (match) {
    return {
      identity_type: match[0],
      identity: match[1],
    };
  }
  return {
    identity_type: 'component',
    identity: item.component,
  };
}

function componentEvidenceModel(item) {
  return (
    item.evidence_model ||
    item.service_profile_preflight_evidence_model ||
    item.runtime_profile_preflight_evidence_model ||
    item.registry_evidence_model ||
    'not-applicable'
  );
}

function componentLiveProbing(item) {
  const candidates = [
    item.live_probing,
    item.service_profile_preflight_live_probing,
    item.runtime_profile_preflight_live_probing,
  ];
  const value = candidates.find((candidate) => typeof candidate === 'boolean');
  return value ?? false;
}

function buildLocalProofPackArtifactComponentManifest(report) {
  return report.components.map((item) => {
    const identity = componentIdentity(item);
    return {
      component: item.component,
      component_sha256: sha256Hex(canonicalize(item)),
      evidence_model: componentEvidenceModel(item),
      identity: identity.identity,
      identity_type: identity.identity_type,
      live_probing: componentLiveProbing(item),
      source_state_boundary:
        item.component === 'claude_code_hook_contract_replay'
          ? item.source_state_boundary
          : 'not-applicable',
    };
  });
}

function buildLocalProofPackArtifactClaimBinding(report) {
  return {
    hash_scope: LOCAL_PROOF_PACK_ARTIFACT_CLAIM_BINDING_HASH_SCOPE,
    non_claim_count: report.non_claims.length,
    non_claims_sha256: sha256Hex(canonicalize(report.non_claims)),
    safe_claim_ceiling_sha256: sha256Hex(canonicalize(report.safe_claim_ceiling)),
  };
}

function assertExactObjectKeys(label, value, expectedKeys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains unexpected fields`);
  }
  return true;
}

function isSha256Hex(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

function assertExactStringSet(label, values, expectedValues) {
  if (!Array.isArray(values)) {
    throw new Error(`${label} must be an array`);
  }
  const actual = [...values].sort();
  const expected = [...expectedValues].sort();
  if (actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) {
    throw new Error(`${label} drifted`);
  }
  return true;
}

function assertExactStringArray(label, values, expectedValues) {
  if (!Array.isArray(values)) {
    throw new Error(`${label} must be an array`);
  }
  if (
    values.length !== expectedValues.length ||
    values.some((value, index) => value !== expectedValues[index])
  ) {
    throw new Error(`${label} drifted`);
  }
  return true;
}

function trustedIssuerRegistryRecognitionKeysFor(component) {
  if (
    component?.component === 'trusted_issuer_registry_recognition' &&
    !Object.prototype.hasOwnProperty.call(component, 'registry_contract_evidence')
  ) {
    return TRUSTED_ISSUER_REGISTRY_RECOGNITION_KEYS.filter((key) =>
      key !== 'registry_contract_evidence' &&
      key !== 'registry_public_safe_summary_sha256'
    );
  }
  return TRUSTED_ISSUER_REGISTRY_RECOGNITION_KEYS;
}

function isHistoricalLocalProofPackCoverageComponent(component) {
  return (
    component?.component === 'governed_surface_coverage_map' &&
    Object.keys(component).length ===
      LOCAL_PROOF_PACK_HISTORICAL_COVERAGE_COMPONENT_KEYS.length &&
    LOCAL_PROOF_PACK_HISTORICAL_COVERAGE_COMPONENT_KEYS.every((key) =>
      Object.prototype.hasOwnProperty.call(component, key)
    )
  );
}

function assertLocalProofPackComponentSchemas(
  report,
  { allowHistoricalCoverageComponent = false } = {}
) {
  for (const item of report.components) {
    const expectedKeys =
      item?.component === 'trusted_issuer_registry_recognition'
        ? trustedIssuerRegistryRecognitionKeysFor(item)
        : item?.component === 'governed_surface_coverage_map' &&
            isHistoricalLocalProofPackCoverageComponent(item) &&
            allowHistoricalCoverageComponent
          ? LOCAL_PROOF_PACK_HISTORICAL_COVERAGE_COMPONENT_KEYS
        : LOCAL_PROOF_PACK_COMPONENT_KEY_MAP[item?.component];
    if (!expectedKeys) {
      throw new Error('Local proof pack component schema is not recognized');
    }
    assertExactObjectKeys(`Local proof pack ${item.component} component`, item, expectedKeys);
  }
  return true;
}

function claudeCodeHookContractReplayCaseEvidenceCase(item) {
  const { input_sha256, ...publicSafeCase } = item;
  void input_sha256;
  if (
    publicSafeCase.input_contract_sha256 !==
      claudeCodeHookContractReplayInputContractSha256(item.case_id)
  ) {
    throw new Error('Claude Code hook-contract replay input contract drifted');
  }
  return { ...publicSafeCase };
}

function claudeCodeHookContractReplayCaseEvidence(proof) {
  return {
    evidence_type: 'zlar-local-proof-pack-claude-hook-contract-replay-case-evidence-v1',
    hash_scope: CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASE_EVIDENCE_HASH_SCOPE,
    cases: proof.cases.map((item) =>
      claudeCodeHookContractReplayCaseEvidenceCase(item)
    ),
    sentinel: { ...proof.sentinel },
    marker: { ...proof.marker },
    audit_session_worker_receipt_deltas: {
      ...proof.audit_session_worker_receipt_deltas,
    },
    supporting_local_boarding_proof: {
      ...proof.supporting_local_boarding_proof,
    },
  };
}

function assertHexSha256(label, value) {
  if (!/^[a-f0-9]{64}$/.test(value || '')) {
    throw new Error(`${label} must be a SHA-256 hex digest`);
  }
}

function assertClaudeCodeHookContractReplayCaseEvidence(evidence) {
  assertExactObjectKeys(
    'Local proof pack Claude Code hook-contract replay case evidence',
    evidence,
    CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASE_EVIDENCE_KEYS
  );
  if (
    evidence.evidence_type !== 'zlar-local-proof-pack-claude-hook-contract-replay-case-evidence-v1' ||
    evidence.hash_scope !== CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASE_EVIDENCE_HASH_SCOPE
  ) {
    throw new Error('Local proof pack Claude Code hook-contract replay case evidence drifted');
  }
  if (!Array.isArray(evidence.cases) || evidence.cases.length !== REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES.length) {
    throw new Error('Local proof pack Claude Code hook-contract replay case evidence case count drifted');
  }
  for (let index = 0; index < REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES.length; index++) {
    const expected = REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES[index];
    const item = evidence.cases[index];
    assertExactObjectKeys(
      `Local proof pack Claude Code hook-contract replay case evidence ${expected.case_id}`,
      item,
      CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASE_EVIDENCE_CASE_KEYS
    );
    if (
      item.case_id !== expected.case_id ||
      item.case_result !== expected.expected_case_result ||
      item.adapter_exit_code !== expected.expected_adapter_exit ||
      item.permission_decision !== expected.expected_permission_decision ||
      item.input_contract_sha256 !==
        claudeCodeHookContractReplayInputContractSha256(expected.case_id)
    ) {
      throw new Error('Local proof pack Claude Code hook-contract replay case evidence drifted');
    }
    for (const hashField of ['input_contract_sha256', 'stderr_sha256', 'stdout_sha256']) {
      assertHexSha256(`Claude hook replay case evidence ${expected.case_id}.${hashField}`, item[hashField]);
    }
    if (item.gate_mode !== 'fixture-gate' && item.gate_mode !== 'missing-fixture-gate') {
      throw new Error('Local proof pack Claude Code hook-contract replay case evidence gate mode drifted');
    }
    const expectedSemantics =
      claudeCodeHookContractReplayExpectedCaseSemantics(expected.case_id);
    for (const [field, expectedValue] of Object.entries(expectedSemantics)) {
      if (item[field] !== expectedValue) {
        throw new Error('Local proof pack Claude Code hook-contract replay case evidence drifted');
      }
    }
  }
  assertExactObjectKeys('Local proof pack Claude Code hook-contract replay sentinel evidence', evidence.sentinel, [
    'after_exists',
    'after_sha256',
    'before_exists',
    'before_sha256',
    'denied_effect_executed',
    'unchanged',
  ]);
  if (
    evidence.sentinel.before_exists !== true ||
    evidence.sentinel.after_exists !== true ||
    evidence.sentinel.unchanged !== true ||
    evidence.sentinel.denied_effect_executed !== false ||
    evidence.sentinel.before_sha256 !== evidence.sentinel.after_sha256
  ) {
    throw new Error('Local proof pack Claude Code hook-contract replay sentinel evidence drifted');
  }
  assertHexSha256('Claude hook replay sentinel before_sha256', evidence.sentinel.before_sha256);
  assertExactObjectKeys('Local proof pack Claude Code hook-contract replay marker evidence', evidence.marker, [
    'after_exists',
    'before_exists',
    'tool_input_command_executed',
  ]);
  if (
    evidence.marker.before_exists !== false ||
    evidence.marker.after_exists !== false ||
    evidence.marker.tool_input_command_executed !== false
  ) {
    throw new Error('Local proof pack Claude Code hook-contract replay marker evidence drifted');
  }
  assertExactObjectKeys(
    'Local proof pack Claude Code hook-contract replay audit/session/worker deltas',
    evidence.audit_session_worker_receipt_deltas,
    [
      'fixture_gate_stdin_captured',
      'mode',
      'real_zlar_audit_delta',
      'real_zlar_session_delta',
      'real_zlar_worker_receipt_delta',
    ]
  );
  if (
    evidence.audit_session_worker_receipt_deltas.mode !== 'fixture-gate' ||
    evidence.audit_session_worker_receipt_deltas.fixture_gate_stdin_captured !== true ||
    evidence.audit_session_worker_receipt_deltas.real_zlar_audit_delta !== 'not_applicable' ||
    evidence.audit_session_worker_receipt_deltas.real_zlar_session_delta !== 'not_applicable' ||
    evidence.audit_session_worker_receipt_deltas.real_zlar_worker_receipt_delta !== 'not_applicable'
  ) {
    throw new Error('Local proof pack Claude Code hook-contract replay audit/session/worker evidence drifted');
  }
  assertExactObjectKeys(
    'Local proof pack Claude Code hook-contract replay supporting local boarding proof',
    evidence.supporting_local_boarding_proof,
    [
      'consequence_absent_on_every_refusal',
      'consequence_present_exactly_once_on_acceptance',
      'current_machine_governance_proven',
      'evidence_model',
      'final_effect_count',
      'legacy_v0_recognized_boarding_identity',
      'passed',
      'production_downstream_recognition_proven',
      'proof_type',
      'replay_refused_after_acceptance',
      'required_cases_present',
      'run',
      'v1_receipt_identity_verified',
    ]
  );
  if (
    evidence.supporting_local_boarding_proof.run !== true ||
    evidence.supporting_local_boarding_proof.passed !== true ||
    evidence.supporting_local_boarding_proof.proof_type !== 'zlar-protected-records-local-boarding-proof-v1' ||
    evidence.supporting_local_boarding_proof.evidence_model !== 'local-in-memory-fixture' ||
    evidence.supporting_local_boarding_proof.required_cases_present !== true ||
    evidence.supporting_local_boarding_proof.v1_receipt_identity_verified !== true ||
    evidence.supporting_local_boarding_proof.consequence_absent_on_every_refusal !== true ||
    evidence.supporting_local_boarding_proof.consequence_present_exactly_once_on_acceptance !== true ||
    evidence.supporting_local_boarding_proof.legacy_v0_recognized_boarding_identity !== false ||
    evidence.supporting_local_boarding_proof.replay_refused_after_acceptance !== true ||
    evidence.supporting_local_boarding_proof.current_machine_governance_proven !== false ||
    evidence.supporting_local_boarding_proof.production_downstream_recognition_proven !== false
  ) {
    throw new Error('Local proof pack Claude Code hook-contract replay supporting local boarding proof drifted');
  }
  return true;
}

function protectedRecordsServicePreflightProfile() {
  const profile = JSON.parse(readFileSync(PROTECTED_RECORDS_SERVICE_PROFILE_URL, 'utf8'));
  assertProtectedRecordsServiceProfile(profile);
  return profile;
}

function protectedRecordsRuntimePreflightProfile() {
  const profile = JSON.parse(readFileSync(PROTECTED_RECORDS_RUNTIME_PROFILE_URL, 'utf8'));
  assertProtectedRecordsRuntimePreflightProfile(profile);
  return profile;
}

function protectedRecordsRuntimeActivationPlan() {
  const plan = JSON.parse(readFileSync(PROTECTED_RECORDS_RUNTIME_ACTIVATION_PLAN_URL, 'utf8'));
  assertProtectedRecordsRuntimeActivationPlan(plan);
  return plan;
}

function protectedRecordsRuntimeLocalActivationPlan() {
  const plan = JSON.parse(readFileSync(PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PLAN_URL, 'utf8'));
  assertProtectedRecordsRuntimeLocalActivationPlan(plan);
  return plan;
}

function protectedRecordsRuntimeProfileInstallationPlan() {
  const plan = JSON.parse(readFileSync(PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_PLAN_URL, 'utf8'));
  assertProtectedRecordsRuntimeProfileInstallationPlan(plan);
  return plan;
}

function refusalReasons(report) {
  return report.refusals.map((item) => item.reason_code);
}

function coverageComponent(report) {
  const terminalSurface = report.surfaces.find((item) =>
    item.surface_id ===
      'protected-records.installed-runtime-profile.terminal-chain.records.write'
  );
  if (!terminalSurface) {
    throw new Error('Local proof pack coverage terminal surface is missing');
  }
  return {
    component: 'governed_surface_coverage_map',
    command: 'zlar coverage --input tests/fixtures/governed-surface-coverage-map-v1-input.json --require-governed',
    report_type: report.report_type,
    evidence_model: report.evidence_model.source,
    live_probing: report.evidence_model.live_probing_performed,
    governed_lanes: report.counts.governed_lanes,
    counted_lanes: report.counts.counted_lanes,
    boundary_entries: report.counts.boundary_entries,
    terminal_artifact_body_sha256:
      terminalSurface.evidence.validation.body_sha256,
    terminal_artifact_expected_body_sha256:
      terminalSurface.evidence.validation.expected_body_sha256,
    terminal_artifact_identity_sha256_matched:
      terminalSurface.evidence.validation.artifact_identity_sha256_matched,
    terminal_outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256:
      terminalSurface.evidence.validation
        .outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256,
    terminal_recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256:
      terminalSurface.evidence.receipt
        .recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256,
    terminal_trusted_issuer_registry_signature_valid:
      terminalSurface.evidence.trusted_issuer_registry.signature_valid,
    terminal_fixture_rightful_issuance_path_evidenced:
      terminalSurface.evidence.rightful_issuance
        .fixture_rightful_issuance_path_evidenced,
  };
}

function downstreamComponent(report) {
  return {
    component: 'downstream_refusal_proof',
    command: 'zlar downstream-refusal-proof',
    proof_type: report.proof_type,
    evidence_model: report.evidence_model,
    live_probing: report.live_probing,
    recognized_boarded: report.recognized_boarding.boarded,
    recognized_marker_count_delta:
      report.recognized_boarding.marker_count_delta,
    final_marker_count: report.marker.final_count,
    refusal_case_count: report.refusals.length,
    all_refusals_unboarded: report.refusals.every(
      (item) => item.boarded === false,
    ),
    all_refusal_marker_count_deltas_zero: report.refusals.every(
      (item) => item.marker_count_delta === 0,
    ),
    refusal_reasons: refusalReasons(report),
  };
}

function humanAuthorizationComponent(report) {
  return {
    component: 'human_authorization_proof',
    command: 'zlar human-authorization-proof',
    proof_type: report.proof_type,
    evidence_model: report.evidence_model,
    live_probing: report.live_probing,
    approval_channel: report.approval_channel,
    pending_boarded: report.pending_without_decision.boarded,
    authorized_boarded: report.authorized_boarding.boarded,
    denied_boarded: report.denied_boarding.boarded,
    authorizer: report.authorized_boarding.authorizer,
    outcome: report.authorized_boarding.outcome,
  };
}

function approvalTransportComponent(report) {
  return {
    component: 'approval_transport_proof',
    command: 'zlar approval-transport-proof',
    proof_type: report.proof_type,
    evidence_model: report.evidence_model,
    transport_model: report.transport_model,
    live_probing: report.live_probing,
    reference_transport_healthy: report.transports.find((item) => item.transport_id === 'reference-fixture-transport')?.healthy === true,
    telegram_required_for_fixture: report.transports.find((item) => item.transport_id === 'telegram-adapter')?.required_for_fixture === true,
    unavailable_boarded: report.cases.transport_unavailable.boarded,
    delivered_without_decision_boarded: report.cases.delivered_without_decision.boarded,
    signed_human_decision_boarded: report.cases.signed_human_decision.boarded,
  };
}

function issuerStatusComponent(report) {
  return {
    component: 'issuer_status_proof',
    command: 'zlar issuer-status-proof',
    proof_type: report.proof_type,
    evidence_model: report.evidence_model,
    live_probing: report.live_probing,
    trust_anchor_model: report.trust_anchor_model,
    active_issuer_boarded: report.active_issuer.boarded,
    retired_issuer_refused: report.retired_issuer.reason_code === 'issuer_not_active',
    compromised_issuer_refused: report.compromised_issuer.reason_code === 'issuer_compromised',
    missing_status_issuer_refused: report.missing_status_issuer.reason_code === 'issuer_status_missing',
    unknown_issuer_refused: report.unknown_issuer.reason_code === 'unknown_issuer',
    missing_key_issuer_refused: report.missing_key_issuer.reason_code === 'issuer_key_missing',
    refusal_reasons: [
      report.retired_issuer.reason_code,
      report.compromised_issuer.reason_code,
      report.missing_status_issuer.reason_code,
      report.unknown_issuer.reason_code,
      report.missing_key_issuer.reason_code,
    ],
  };
}

function assertTrustedIssuerRegistryFixtureShape(registry) {
  assertTrustedReceiptIssuerRegistryV2Contract(registry);
  assertExactObjectKeys(
    'Trusted issuer registry fixture',
    registry,
    TRUSTED_ISSUER_REGISTRY_SCHEMA_KEYS
  );
  if (
    registry.registry_type !== 'trusted-receipt-issuers-v2' ||
    registry.registry_id !== 'local-proof-pack-no-secret-trusted-issuer-registry-fixture' ||
    registry.version !== 2 ||
    registry.evidence_model !== 'bundled-local-fixture-no-secret-registry-contract' ||
    registry.live_probing !== false ||
    registry.deployment_scope !== 'fixture-records-terminal'
  ) {
    throw new Error('Trusted issuer registry fixture identity drifted');
  }
  if (!Array.isArray(registry.trusted_issuers) || registry.trusted_issuers.length !== 1) {
    throw new Error('Trusted issuer registry fixture must include trusted issuers');
  }
  for (const issuer of registry.trusted_issuers) {
    assertExactObjectKeys('Trusted issuer registry fixture issuer', issuer, [
      'custody_posture',
      'effective_at',
      'expires_at',
      'kid',
      'public_key_pem',
      'status',
      'status_reason',
      'status_transition',
      'trust_anchor_sha256',
    ]);
    if (typeof issuer.kid !== 'string' || !/^[0-9a-f]{16}$/.test(issuer.kid)) {
      throw new Error('Trusted issuer registry fixture issuer kid drifted');
    }
    if (
      typeof issuer.public_key_pem !== 'string' ||
      !issuer.public_key_pem.startsWith('-----BEGIN PUBLIC KEY-----')
    ) {
      throw new Error('Trusted issuer registry fixture issuer public key drifted');
    }
    if (
      issuer.trust_anchor_sha256 !== null ||
      issuer.status !== 'active' ||
      issuer.custody_posture.private_key_material_included !== false ||
      issuer.custody_posture.hardware_custody_proven !== false ||
      issuer.custody_posture.custody_proof_provided !== false
    ) {
      throw new Error('Trusted issuer registry fixture issuer status drifted');
    }
  }
  return true;
}

function trustedIssuerRegistryRecognitionFixtureEvaluation() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  const kid = createHash('sha256').update(publicPem).digest('hex').slice(0, 16);
  const event = {
    id: 'zlar-local-proof-pack-trusted-registry-event-001',
    ts: '2026-06-20T00:00:00.000Z',
    action: 'records.write',
    domain: 'records',
    detail: {
      record_id: 'fixture-record-001',
      operation: 'update_status',
    },
    outcome: 'allow',
    rule: 'RRECORDS_ALLOW',
    authorizer: 'policy',
    policy_version: 'trusted-registry-fixture-v1',
    prev_hash: '0'.repeat(64),
  };
  const receipt = signReceiptV1(createReceiptV1FromEvent(event), privatePem, kid);
  const payload = decodePayloadV1(receipt);
  const registryEffectiveAt = '2026-06-20T00:00:00.000Z';
  const registryExpiresAt = '2026-06-20T01:00:00.000Z';
  const registry = {
    registry_type: 'trusted-receipt-issuers-v2',
    registry_id: 'local-proof-pack-no-secret-trusted-issuer-registry-fixture',
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
          'local fixture issuer recognized for proof-pack no-secret registry contract validation',
        effective_at: registryEffectiveAt,
        expires_at: registryExpiresAt,
        status_transition: {
          transition_type: 'fixture_activation',
          transition_at: registryEffectiveAt,
          previous_status: null,
          reason: 'local fixture activation for proof-pack registry contract validation',
        },
        custody_posture: {
          declaration: 'ephemeral local fixture key; no custody proof',
          private_key_material_included: false,
          hardware_custody_proven: false,
          custody_proof_provided: false,
        },
      },
    ],
    accepted_policy_versions: ['trusted-registry-fixture-v1'],
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
    non_claims: [...TRUSTED_ISSUER_REGISTRY_FIXTURE_NON_CLAIMS],
  };
  assertTrustedIssuerRegistryFixtureShape(registry);
  const decision = evaluateTrustedIssuerRegistryRecognition({
    receipt,
    registry,
    scope: 'fixture-records-terminal',
    nowEpoch: Date.parse(event.ts) / 1000 + 10,
  });
  return { decision, payload, registry };
}

function evaluateTrustedIssuerRegistryRecognition({ receipt, registry, scope, nowEpoch }) {
  assertTrustedIssuerRegistryFixtureShape(registry);
  return evaluateTrustedReceiptIssuerRegistryV2Recognition({
    receipt,
    registry,
    deployment_scope: scope,
    now_epoch: nowEpoch,
  });
}

function evaluateMalformedRegistryFixture() {
  let verdictEmitted = false;
  try {
    const registry = {
      registry_type: 'trusted-receipt-issuers-v2',
      version: 2,
      evidence_model: 'bundled-local-fixture',
      live_probing: false,
      deployment_scope: 'fixture-records-terminal',
      trusted_issuers: [],
      accepted_policy_versions: [],
      accepted_domains: [],
      accepted_tools: [],
      accepted_outcomes: [],
      non_claims: [],
      production_authority: true,
    };
    assertTrustedIssuerRegistryFixtureShape(registry);
    verdictEmitted = true;
  } catch {
    return {
      unsupported_field: true,
      error_code: 'unsupported_registry_field',
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

function trustedIssuerRegistryRecognitionComponent() {
  const malformedRegistry = evaluateMalformedRegistryFixture();
  const fixtureEvaluation = trustedIssuerRegistryRecognitionFixtureEvaluation();
  const { decision, registry } = fixtureEvaluation;
  const registryContractSummary =
    publicSafeTrustedReceiptIssuerRegistryV2Summary(registry);
  const payload = decision.evidence?.payload || {};
  const auditEventBound =
    payload.audit_event_id === registry.required_audit_event_id &&
    payload.audit_event_id === fixtureEvaluation.payload.audit_event_id;
  const detailHashBound =
    payload.detail_hash === registry.required_detail_hash &&
    payload.detail_hash === fixtureEvaluation.payload.detail_hash;
  const recognized =
    decision.recognized === true &&
    decision.reason_code === 'recognized' &&
    decision.evidence?.issuer_status === 'active' &&
    decision.evidence?.signature_valid === true &&
    auditEventBound === true &&
    detailHashBound === true;
  return {
    component: 'trusted_issuer_registry_recognition',
    command: 'embedded local proof-pack trusted issuer registry recognition fixture',
    evidence_model: 'fresh-local-fixture-trusted-issuer-registry-recognition',
    registry_type: 'trusted-receipt-issuers-v2',
    registry_evidence_model: 'bundled-local-fixture-no-secret-registry-contract',
    registry_contract_evidence: registryContractSummary.contract_evidence,
    registry_public_safe_summary_sha256: registryContractSummary.summary_sha256,
    live_probing: false,
    requested_scope: 'fixture-records-terminal',
    registry_scope: 'fixture-records-terminal',
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
    malformed_registry_unsupported_field: malformedRegistry.unsupported_field === true,
    malformed_registry_error_code: malformedRegistry.error_code,
    malformed_registry_fail_closed_before_verdict:
      malformedRegistry.fail_closed_before_verdict === true,
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
    safe_claim_ceiling: TRUSTED_ISSUER_REGISTRY_RECOGNITION_CLAIM_BOUNDARY,
    claim_boundary: TRUSTED_ISSUER_REGISTRY_RECOGNITION_CLAIM_BOUNDARY,
    non_claims: [...TRUSTED_ISSUER_REGISTRY_RECOGNITION_NON_CLAIMS],
  };
}

function trustedIssuerRegistryRecognitionPasses(component) {
  const hasNoSecretRegistryContractFields =
    Object.prototype.hasOwnProperty.call(component || {}, 'registry_contract_evidence');
  const registryEvidenceModelAccepted = hasNoSecretRegistryContractFields
    ? component.registry_evidence_model ===
      'bundled-local-fixture-no-secret-registry-contract'
    : component.registry_evidence_model === 'bundled-local-fixture';
  const registryContractEvidenceAccepted = hasNoSecretRegistryContractFields
    ? (
      component.registry_contract_evidence ===
        TRUSTED_RECEIPT_ISSUER_REGISTRY_V2_CONTRACT_EVIDENCE &&
      isSha256Hex(component.registry_public_safe_summary_sha256)
    )
    : true;
  return (
    component?.component === 'trusted_issuer_registry_recognition' &&
    component.command === 'embedded local proof-pack trusted issuer registry recognition fixture' &&
    component.evidence_model === 'fresh-local-fixture-trusted-issuer-registry-recognition' &&
    component.registry_type === 'trusted-receipt-issuers-v2' &&
    registryEvidenceModelAccepted === true &&
    registryContractEvidenceAccepted === true &&
    component.live_probing === false &&
    component.requested_scope === 'fixture-records-terminal' &&
    component.registry_scope === 'fixture-records-terminal' &&
    component.registry_fixture_validated === true &&
    component.registry_fixture_evaluated === true &&
    component.registry_to_recognition_rule_evaluated === true &&
    component.registry_evaluation_result_type === 'downstream-recognition-rule-v1' &&
    component.registry_trusted_issuer_count === 1 &&
    component.verdict === 'RECOGNIZED' &&
    component.recognized === true &&
    component.decision === 'accept' &&
    component.reason_code === 'recognized' &&
    component.issuer_status === 'active' &&
    component.signature_valid === true &&
    component.required_audit_event_id_bound === true &&
    component.required_detail_hash_bound === true &&
    component.malformed_registry_unsupported_field === true &&
    component.malformed_registry_error_code === 'unsupported_registry_field' &&
    component.malformed_registry_fail_closed_before_verdict === true &&
    component.live_trust_registry_state === false &&
    component.live_issuer_status_proven === false &&
    component.key_custody_proven === false &&
    component.revocation_truth_proven === false &&
    component.production_trust_registry_proven === false &&
    component.production_downstream_recognition_proven === false &&
    component.production_authority === false &&
    component.sovereign_recognition === false &&
    component.public_external_attestation === false &&
    component.real_non_operator_review === false &&
    component.current_machine_governance_proven === false &&
    component.safe_claim_ceiling === TRUSTED_ISSUER_REGISTRY_RECOGNITION_CLAIM_BOUNDARY &&
    component.claim_boundary === TRUSTED_ISSUER_REGISTRY_RECOGNITION_CLAIM_BOUNDARY &&
    Array.isArray(component.non_claims) &&
    component.non_claims.length === TRUSTED_ISSUER_REGISTRY_RECOGNITION_NON_CLAIMS.length
  );
}

function keyStateReportComponent(report) {
  assertKeyStateReport(report);
  return {
    component: 'key_state_report',
    command: 'zlar key-state --sample --json',
    report_type: report.report_type,
    evidence_model: report.evidence_model,
    live_probing: report.live_probing,
    read_only: report.read_only,
    claim_boundary: report.claim_boundary,
    fingerprint_convention: report.fingerprint_convention,
    operational_posture: { ...report.operational_posture },
    privacy: { ...report.privacy },
    tools: { ...report.tools },
    public_verifiers: { ...report.public_verifiers },
    local_private_key_presence: { ...report.local_private_key_presence },
    operational_pins: { ...report.operational_pins },
    policy_software_pins_aligned: report.concerns.policy_signing.software_pins_aligned,
    constitution_software_pins_aligned:
      report.concerns.constitution_signing.software_pins_aligned,
    policy_current_ceremony_ready: report.concerns.policy_signing.current_ceremony_ready,
    constitution_current_ceremony_ready:
      report.concerns.constitution_signing.current_ceremony_ready,
    policy_hardware_target_observed: report.concerns.policy_signing.hardware_target_observed,
    constitution_hardware_target_observed:
      report.concerns.constitution_signing.hardware_target_observed,
    spec_hardware_target_observed:
      report.concerns.spec_test_vector_signing.hardware_target_observed,
    key_custody_proven: false,
    revocation_state_proven: false,
    production_trust_registry_proven: false,
    external_attestation: false,
    sovereign_recognition: false,
    current_machine_governance_proven: false,
    non_claims: [...report.non_claims],
  };
}

function receiptVerifierBoundaryComponent() {
  const proof = runReceiptVerifierBoundaryProof();
  assertReceiptVerifierBoundaryProof(proof);
  return {
    component: 'receipt_verifier_boundary',
    ...proof,
  };
}

function protectedRecordsComponent(report) {
  const refusalRecordDeltaTotal = report.refusals.reduce(
    (total, item) => total + item.record_count_delta,
    0
  );
  const profileContract = report.profile_contract;
  return {
    component: 'protected_records_terminal',
    command: 'zlar protected-records-proof',
    proof_type: report.proof_type,
    evidence_model: report.evidence_model,
    live_probing: report.live_probing,
    deployment_profile: report.deployment_profile,
    action_class: report.action_class,
    downstream_boundary: report.downstream_boundary,
    adapter_profile_type: report.adapter_profile.profile_type,
    adapter_profile_id: report.adapter_profile.profile_id,
    adapter_authoritative_route: report.adapter_profile.authoritative_route,
    adapter_boundary: report.adapter_profile.adapter_boundary,
    adapter_ledger_model: report.adapter_profile.ledger_model,
    adapter_consumed_receipt_store: report.adapter_profile.consumed_receipt_store,
    adapter_replay_scope: report.adapter_profile.replay_scope,
    adapter_closed_in_fixture: [...report.adapter_profile.closed_in_fixture],
    adapter_known_open_boundaries: [...report.adapter_profile.known_open_boundaries],
    adapter_final_ledger_entry_count: report.adapter_harness.final_ledger_entry_count,
    adapter_consumed_receipt_count: report.adapter_harness.consumed_receipt_count,
    adapter_direct_write_path_available: report.adapter_harness.direct_write_path_available,
    adapter_live_records_adapter: report.adapter_harness.live_records_adapter,
    adapter_action_type: report.adapter_action.action_type,
    adapter_action_command: report.adapter_action.command,
    adapter_action_result_type: report.adapter_action.result_type,
    adapter_action_fixture_mode_required: report.adapter_action.fixture_mode_required,
    adapter_action_writes: report.adapter_action.writes,
    adapter_action_live_records_adapter: report.adapter_action.live_records_adapter,
    adapter_action_raw_record_detail_output: report.adapter_action.raw_record_detail_output,
    profile_contract_id: profileContract.profile_id,
    profile_contract_checkpoint: profileContract.checkpoint,
    profile_contract_route: profileContract.route,
    profile_contract_downstream_effect: profileContract.downstream_effect,
    receipt_replay_policy: profileContract.receipt_replay_policy,
    required_receipt_fields: [...profileContract.required_receipt_fields],
    recognized_write_accepted: report.recognized_write.write_accepted,
    recognized_record_changed: report.recognized_write.record_changed,
    recognized_record_count_delta: report.recognized_write.record_count_delta,
    refused_write_count: report.refusals.length,
    all_refusals_prevented_record_change: report.refusals.every((item) => item.record_changed === false),
    refusal_record_count_delta_total: refusalRecordDeltaTotal,
    final_record_count: report.terminal.final_record_count,
    refusal_reasons: refusalReasons(report),
    known_ungoverned_boundaries: [...profileContract.known_ungoverned_boundaries],
  };
}

function protectedRecordsAdapterConformanceComponent(report) {
  const accepted = report.cases.find((item) => item.case_id === 'recognized_write_first_process');
  const replay = report.cases.find((item) => item.case_id === 'replay_refused_after_process_restart');
  const missing = report.cases.find((item) => item.case_id === 'missing_receipt_refused_before_append');
  const sideDoor = report.cases.find((item) => item.case_id === 'unsupported_direct_write_option_refused');
  return {
    component: 'protected_records_adapter_conformance',
    command: 'zlar protected-records-adapter-conformance',
    proof_type: report.proof_type,
    evidence_model: report.evidence_model,
    live_probing: report.live_probing,
    profile_id: report.conformance_profile.profile_id,
    action_class: report.conformance_profile.action_class,
    adapter_type: report.conformance_profile.adapter_type,
    adapter_command: report.conformance_profile.adapter_command,
    adapter_process_boundary: report.conformance_profile.adapter_process_boundary,
    mutation_authoritative_route: report.conformance_profile.mutation_authoritative_route,
    result_type: report.conformance_profile.result_type,
    ledger_model: report.conformance_profile.ledger_model,
    consumed_receipt_store: report.conformance_profile.consumed_receipt_store,
    replay_scope: report.conformance_profile.replay_scope,
    recognized_write_accepted: accepted.write_accepted,
    recognized_write_reason: accepted.reason_code,
    recognized_write_ledger_delta: accepted.ledger_entry_count_delta,
    replay_refused: replay.write_accepted === false,
    replay_reason: replay.reason_code,
    replay_ledger_delta: replay.ledger_entry_count_delta,
    replay_separate_process: replay.separate_process_from_accepted,
    missing_receipt_refused: missing.write_accepted === false,
    missing_receipt_reason: missing.reason_code,
    missing_receipt_ledger_delta: missing.ledger_entry_count_delta,
    unsupported_side_door_refused: sideDoor.write_accepted === false && sideDoor.exit_status !== 0,
    unsupported_side_door_reason: sideDoor.reason_code,
    unsupported_side_door_ledger_delta: sideDoor.ledger_entry_count_delta,
    cli_direct_write_option_available: report.side_door_report.cli_direct_write_option_available,
    direct_filesystem_write_to_fixture_paths_closed: report.side_door_report.direct_filesystem_write_to_fixture_paths_closed,
    live_records_adapter: report.side_door_report.live_records_adapter,
    known_open_boundaries: [...report.known_open_boundaries],
    conformance_cases: report.cases.map((item) => item.case_id),
  };
}

function protectedRecordsRuntimeProfilePreflightIdentityComponent() {
  const profile = protectedRecordsRuntimePreflightProfile();
  return {
    component: 'protected_records_runtime_profile_preflight_identity',
    preflight_command: 'zlar protected-records-runtime-profile-preflight --profile profiles/protected-records-runtime-fixture.profile.json',
    profile_type: profile.profile_type,
    profile_id: profile.profile_id,
    profile_sha256: runtimeProfileSha256(profile),
    profile_status: profile.profile_status,
    deployment_posture: profile.deployment_posture,
    runtime_profile_id: profile.runtime_profile_id,
    action_class: profile.action_class,
    service_command: profile.service_command,
    proof_command: profile.proof_command,
    request_contract: profile.request_contract,
    mutation_authoritative_route: profile.mutation_authoritative_route,
    config_supplied_by_launcher: profile.authority_boundary.config_supplied_by_launcher,
    request_stream_authority_material_accepted: profile.authority_boundary.request_stream_authority_material_accepted,
    state_path_exposed_to_agent: profile.authority_boundary.state_path_exposed_to_agent,
    consumed_grants_path_exposed_to_agent:
      profile.authority_boundary.consumed_grants_path_exposed_to_agent,
    consumed_grant_store_anchor_path_exposed_to_agent:
      profile.authority_boundary.consumed_grant_store_anchor_path_exposed_to_agent,
    consumed_grant_store_witness_path_exposed_to_agent:
      profile.authority_boundary.consumed_grant_store_witness_path_exposed_to_agent,
    recognition_rule_supplied_by_agent: profile.authority_boundary.recognition_rule_supplied_by_agent,
    authority_grant_contract_required_from_launcher:
      profile.authority_boundary.authority_grant_contract_required_from_launcher,
    authority_grant_appointment_required_from_launcher:
      profile.authority_boundary.authority_grant_appointment_required_from_launcher,
    authority_grant_issuance_decision_required_from_launcher:
      profile.authority_boundary.authority_grant_issuance_decision_required_from_launcher,
    authorized_record_update_required_from_launcher:
      profile.authority_boundary.authorized_record_update_required_from_launcher,
    source_profile_authority_grant_present:
      profile.authority_boundary.source_profile_authority_grant_present,
    consumed_authority_grant_store: profile.consumed_authority_grant_store,
    consumption_identity: profile.consumption_identity,
    signed_payload_replay_identity: profile.signed_payload_replay_identity,
    consumed_store_lock: profile.consumed_store_lock,
    consumed_store_validation: profile.consumed_store_validation,
    consumed_store_anchor: profile.consumed_store_anchor,
    consumed_store_witness: profile.consumed_store_witness,
    consumed_store_rollback_detection: profile.consumed_store_rollback_detection,
    consumed_store_write_model: profile.consumed_store_write_model,
    replay_scope: profile.replay_scope,
    single_host_rollback_detection: profile.storage_boundary.single_host_rollback_detection,
    store_and_anchor_joint_rollback_refused_while_witness_ahead:
      profile.storage_boundary.store_and_anchor_joint_rollback_refused_while_witness_ahead,
    store_anchor_and_witness_joint_rollback_detection:
      profile.storage_boundary.store_anchor_and_witness_joint_rollback_detection,
    atomic_store_anchor_witness_commit:
      profile.storage_boundary.atomic_store_anchor_witness_commit,
    partial_grant_commit_burn_window_named:
      profile.storage_boundary.partial_grant_commit_burn_window_named,
    host_filesystem_path_toctou_closed:
      profile.storage_boundary.host_filesystem_path_toctou_closed,
    production_grade_anti_rollback: profile.storage_boundary.production_grade_anti_rollback,
    exactly_once_effect_semantics: profile.storage_boundary.exactly_once_effect_semantics,
    required_case_count: profile.required_cases.length,
    required_boundary_observation_count: profile.required_boundary_observations.length,
    runtime_profile_preflight_run_in_proof_pack: false,
    runtime_profile_proof_run_in_proof_pack: false,
    fixture_rightful_issuance_path_evidenced: false,
    rightful_issuance_proven: false,
    portable_rightful_issuance_proven: false,
    live_authority_proven: false,
    production_rightful_issuance_proven: false,
    current_machine_governance_proven: false,
    consequence_lifecycle_closed: false,
    known_open_boundaries: [...profile.known_open_boundaries],
  };
}

function protectedRecordsRuntimeActivationPreflightComponent() {
  const plan = protectedRecordsRuntimeActivationPlan();
  const profile = protectedRecordsRuntimePreflightProfile();
  const preflight = runProtectedRecordsRuntimeActivationPreflight(plan, profile);
  assertProtectedRecordsRuntimeActivationPreflight(preflight, plan, profile);
  const runtimePreflightSummary = preflight.runtime_profile_preflight_summary;
  const sideDoor = preflight.side_door_report;
  return {
    component: 'protected_records_runtime_activation_preflight',
    preflight_type: preflight.preflight_type,
    evidence_model: preflight.evidence_model,
    live_probing: preflight.live_probing,
    safe_claim_ceiling: preflight.safe_claim_ceiling,
    preflight_command: plan.preflight_command,
    plan_type: preflight.plan.plan_type,
    plan_id: preflight.plan.plan_id,
    plan_sha256: preflight.plan.plan_sha256,
    plan_status: preflight.plan.plan_status,
    deployment_posture: preflight.plan.deployment_posture,
    action_class: plan.action_class,
    runtime_profile_id: preflight.runtime_profile.runtime_profile_id,
    runtime_profile_source: plan.runtime_profile_source,
    runtime_profile_sha256: preflight.runtime_profile.profile_sha256,
    runtime_profile_sha_matches_plan: preflight.runtime_profile.profile_sha_matches_plan,
    runtime_profile_preflight_command: plan.runtime_profile_preflight_command,
    service_command: plan.service_command,
    proof_command: plan.proof_command,
    activation_applied: preflight.activation_boundary.activation_applied,
    writes_runtime_config: preflight.activation_boundary.writes_runtime_config,
    writes_hook_configuration: preflight.activation_boundary.writes_hook_configuration,
    starts_runtime_service: preflight.activation_boundary.starts_runtime_service,
    requires_explicit_human_install: preflight.activation_boundary.requires_explicit_human_install,
    selects_latest_profile: preflight.activation_boundary.selects_latest_profile,
    request_stream_authority_material_accepted:
      preflight.activation_boundary.request_stream_authority_material_accepted,
    uses_live_records_system: preflight.activation_boundary.uses_live_records_system,
    launcher_supplies_config: preflight.activation_contract.launcher_supplies_config,
    config_path_agent_supplied: preflight.activation_contract.config_path_agent_supplied,
    state_path_agent_supplied: preflight.activation_contract.state_path_agent_supplied,
    consumed_grants_path_agent_supplied:
      preflight.activation_contract.consumed_grants_path_agent_supplied,
    consumed_grant_store_anchor_path_agent_supplied:
      preflight.activation_contract.consumed_grant_store_anchor_path_agent_supplied,
    consumed_grant_store_witness_path_agent_supplied:
      preflight.activation_contract.consumed_grant_store_witness_path_agent_supplied,
    recognition_rule_agent_supplied: preflight.activation_contract.recognition_rule_agent_supplied,
    issuer_registry_agent_supplied: preflight.activation_contract.issuer_registry_agent_supplied,
    authority_grant_contract_required_from_launcher:
      preflight.activation_contract.authority_grant_contract_required_from_launcher,
    authority_grant_appointment_required_from_launcher:
      preflight.activation_contract.authority_grant_appointment_required_from_launcher,
    authority_grant_issuance_decision_required_from_launcher:
      preflight.activation_contract.authority_grant_issuance_decision_required_from_launcher,
    authorized_record_update_required_from_launcher:
      preflight.activation_contract.authorized_record_update_required_from_launcher,
    downstream_recognition_required: preflight.activation_contract.downstream_recognition_required,
    missing_or_unrecognized_receipt_refused:
      preflight.activation_contract.missing_or_unrecognized_receipt_refused,
    runtime_activation_preflight_run_in_proof_pack: true,
    runtime_profile_preflight_run_in_proof_pack: runtimePreflightSummary.preflight_run,
    runtime_profile_proof_run_in_proof_pack: runtimePreflightSummary.proof_run_in_preflight,
    runtime_profile_preflight_type: runtimePreflightSummary.preflight_type,
    runtime_profile_preflight_evidence_model: runtimePreflightSummary.preflight_evidence_model,
    runtime_profile_proof_case_count: runtimePreflightSummary.proof_case_count,
    runtime_profile_proof_required_case_count: runtimePreflightSummary.proof_required_case_count,
    runtime_profile_boundary_observation_count:
      runtimePreflightSummary.proof_boundary_observation_count,
    runtime_profile_required_boundary_observation_count:
      runtimePreflightSummary.proof_required_boundary_observation_count,
    recognized_write_accepted: runtimePreflightSummary.recognized_write_accepted,
    mutation_authoritative_route:
      runtimePreflightSummary.mutation_authoritative_route,
    consumed_authority_grant_store:
      runtimePreflightSummary.consumed_authority_grant_store,
    consumption_identity: runtimePreflightSummary.consumption_identity,
    signed_payload_replay_identity:
      runtimePreflightSummary.signed_payload_replay_identity,
    consumed_store_witness: runtimePreflightSummary.consumed_store_witness,
    consumed_store_write_model: runtimePreflightSummary.consumed_store_write_model,
    same_process_signed_payload_replay_refused:
      runtimePreflightSummary.same_process_signed_payload_replay_refused,
    restart_consumed_authority_grant_refused:
      runtimePreflightSummary.restart_consumed_authority_grant_refused,
    consumed_authority_grant_store_rollback_refused:
      runtimePreflightSummary.consumed_authority_grant_store_rollback_refused,
    consumed_authority_grant_store_deletion_refused:
      runtimePreflightSummary.consumed_authority_grant_store_deletion_refused,
    consumed_authority_grant_store_replacement_refused:
      runtimePreflightSummary.consumed_authority_grant_store_replacement_refused,
    witness_commit_failed_after_authority_grant_store_commit:
      runtimePreflightSummary.witness_commit_failed_after_authority_grant_store_commit,
    witness_commit_failure_reason_code:
      runtimePreflightSummary.witness_commit_failure_reason_code,
    store_and_anchor_joint_rollback_refused_against_witness:
      runtimePreflightSummary.store_and_anchor_joint_rollback_refused_against_witness,
    missing_authority_grant_appointment_refused:
      runtimePreflightSummary.missing_authority_grant_appointment_refused,
    mismatched_authority_grant_appointment_refused:
      runtimePreflightSummary.mismatched_authority_grant_appointment_refused,
    revoked_authority_grant_refused:
      runtimePreflightSummary.revoked_authority_grant_refused,
    expired_authority_grant_refused:
      runtimePreflightSummary.expired_authority_grant_refused,
    request_supplied_authority_grant_refused:
      runtimePreflightSummary.request_supplied_authority_grant_refused,
    agent_supplied_authority_material_refused:
      runtimePreflightSummary.agent_supplied_authority_material_refused,
    runtime_profile_identity_authority_source:
      runtimePreflightSummary.runtime_profile_identity_authority_source,
    runtime_profile_identity_request_stream_policy:
      runtimePreflightSummary.runtime_profile_identity_request_stream_policy,
    request_runtime_profile_id_required:
      runtimePreflightSummary.request_runtime_profile_id_required,
    omitted_request_runtime_profile_id_present:
      runtimePreflightSummary.omitted_request_runtime_profile_id_present,
    omitted_runtime_profile_id_uses_launcher_config:
      runtimePreflightSummary.omitted_runtime_profile_id_uses_launcher_config,
    omitted_runtime_profile_id_reason_code:
      runtimePreflightSummary.omitted_runtime_profile_id_reason_code,
    omitted_runtime_profile_id_state_entry_count_delta:
      runtimePreflightSummary.omitted_runtime_profile_id_state_entry_count_delta,
    omitted_runtime_profile_id_consumed_authority_grant_count:
      runtimePreflightSummary.omitted_runtime_profile_id_consumed_authority_grant_count,
    supplied_mismatched_runtime_profile_id_refused:
      runtimePreflightSummary.supplied_mismatched_runtime_profile_id_refused,
    supplied_mismatch_reason_code:
      runtimePreflightSummary.supplied_mismatch_reason_code,
    supplied_mismatch_state_entry_count_delta:
      runtimePreflightSummary.supplied_mismatch_state_entry_count_delta,
    persistent_runtime_profile_installed: sideDoor.persistent_runtime_profile_installed,
    live_records_system_checked: sideDoor.live_records_system_checked,
    production_records_service_checked: sideDoor.production_records_service_checked,
    live_mcp_coverage_checked: sideDoor.live_mcp_coverage_checked,
    live_approval_channel_health_checked: sideDoor.live_approval_channel_health_checked,
    external_attestation: sideDoor.external_attestation,
    sovereign_recognition: sideDoor.sovereign_recognition,
    store_and_anchor_joint_rollback_refused_while_witness_ahead:
      sideDoor.store_and_anchor_joint_rollback_refused_while_witness_ahead,
    store_anchor_and_witness_joint_rollback_detection:
      sideDoor.store_anchor_and_witness_joint_rollback_detection,
    store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse:
      sideDoor.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse,
    atomic_store_anchor_witness_commit: sideDoor.atomic_store_anchor_witness_commit,
    partial_grant_commit_burn_window_named:
      sideDoor.partial_grant_commit_burn_window_named,
    host_filesystem_path_toctou_closed:
      sideDoor.host_filesystem_path_toctou_closed,
    fixture_rightful_issuance_path_evidenced:
      runtimePreflightSummary.omitted_runtime_profile_id_reason_code ===
        'fixture_authority_grant_effect_satisfied' &&
      runtimePreflightSummary.omitted_runtime_profile_id_consumed_authority_grant_count === 1,
    rightful_issuance_proven: false,
    portable_rightful_issuance_proven: false,
    live_authority_proven: false,
    production_rightful_issuance_proven: false,
    current_machine_governance_proven: false,
    consequence_lifecycle_closed: false,
    unrouted_records_paths_checked: sideDoor.unrouted_records_paths_checked,
    operator_install_requirements: [...preflight.operator_install_requirements],
    known_open_boundaries: [...preflight.known_open_boundaries],
    preflight_non_claims: [...preflight.non_claims],
  };
}

function protectedRecordsRuntimeLocalActivationComponent() {
  const plan = protectedRecordsRuntimeLocalActivationPlan();
  const profile = protectedRecordsRuntimePreflightProfile();
  const proof = runProtectedRecordsRuntimeLocalActivationProof(plan, profile);
  assertProtectedRecordsRuntimeLocalActivationProof(proof, plan, profile);
  const summary = proof.runtime_proof_summary;
  const sideDoor = proof.side_door_report;
  return {
    component: 'protected_records_runtime_local_activation',
    proof_type: proof.proof_type,
    evidence_model: proof.evidence_model,
    live_probing: proof.live_probing,
    safe_claim_ceiling: proof.safe_claim_ceiling,
    local_activation_command: plan.local_activation_command,
    plan_type: proof.plan.plan_type,
    plan_id: proof.plan.plan_id,
    plan_sha256: proof.plan.plan_sha256,
    plan_status: proof.plan.plan_status,
    deployment_posture: proof.plan.deployment_posture,
    action_class: plan.action_class,
    runtime_profile_id: proof.runtime_profile.runtime_profile_id,
    runtime_profile_source: plan.runtime_profile_source,
    runtime_profile_sha256: proof.runtime_profile.profile_sha256,
    runtime_profile_sha_matches_plan: proof.runtime_profile.profile_sha_matches_plan,
    active_profile_selection: {
      selection_type: RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_TYPE,
      selection_scope: RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_SCOPE,
      selected: true,
      selection_source: 'explicit-plan-and-profile-inputs',
      action_class: 'records.write',
      route: RECORDS_WRITE_TERMINAL_ROUTE,
      downstream_boundary: RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY,
      plan_sha256: proof.plan.plan_sha256,
      profile_id: profile.profile_id,
      runtime_profile_id: proof.runtime_profile.runtime_profile_id,
      profile_status_before_selection: profile.profile_status,
      runtime_profile_sha256: proof.runtime_profile.profile_sha256,
      runtime_profile_sha_matches_plan: proof.runtime_profile.profile_sha_matches_plan,
      selects_latest_profile: sideDoor.latest_profile_selected,
      persistent_runtime_profile_installed: sideDoor.persistent_runtime_profile_installed,
      live_runtime_profile_checked: false,
      hook_configuration_written: sideDoor.hook_configuration_written,
    },
    runtime_profile_proof_command: plan.runtime_profile_proof_command,
    service_command: plan.service_command,
    runtime_local_activation_run_in_proof_pack: true,
    runtime_profile_proof_run_in_proof_pack: summary.proof_run,
    runtime_profile_proof_type: summary.proof_type,
    runtime_profile_proof_case_count: summary.case_count,
    runtime_profile_proof_required_case_count: summary.required_case_count,
    runtime_profile_boundary_observation_count: summary.boundary_observation_count,
    runtime_profile_required_boundary_observation_count:
      summary.required_boundary_observation_count,
    recognized_write_accepted: summary.recognized_write_accepted,
    mutation_authoritative_route: summary.mutation_authoritative_route,
    consumed_authority_grant_store: summary.consumed_authority_grant_store,
    consumption_identity: summary.consumption_identity,
    signed_payload_replay_identity: summary.signed_payload_replay_identity,
    consumed_store_witness: summary.consumed_store_witness,
    consumed_store_write_model: summary.consumed_store_write_model,
    same_process_signed_payload_replay_refused:
      summary.same_process_signed_payload_replay_refused,
    restart_consumed_authority_grant_refused:
      summary.restart_consumed_authority_grant_refused,
    witness_commit_failed_after_authority_grant_store_commit:
      summary.witness_commit_failed_after_authority_grant_store_commit,
    witness_commit_failure_reason_code: summary.witness_commit_failure_reason_code,
    store_and_anchor_joint_rollback_refused_against_witness:
      summary.store_and_anchor_joint_rollback_refused_against_witness,
    missing_authority_grant_appointment_refused:
      summary.missing_authority_grant_appointment_refused,
    mismatched_authority_grant_appointment_refused:
      summary.mismatched_authority_grant_appointment_refused,
    revoked_authority_grant_refused: summary.revoked_authority_grant_refused,
    expired_authority_grant_refused: summary.expired_authority_grant_refused,
    request_supplied_authority_grant_refused:
      summary.request_supplied_authority_grant_refused,
    missing_receipt_refused: summary.missing_receipt_refused,
    invalid_receipt_refused: summary.invalid_receipt_refused,
    unknown_issuer_refused: summary.unknown_issuer_refused,
    retired_issuer_refused: summary.retired_issuer_refused,
    missing_issuer_status_refused: summary.missing_issuer_status_refused,
    stale_receipt_refused: summary.stale_receipt_refused,
    wrong_policy_refused: summary.wrong_policy_refused,
    wrong_domain_refused: summary.wrong_domain_refused,
    wrong_tool_refused: summary.wrong_tool_refused,
    wrong_runtime_profile_id_refused: summary.wrong_runtime_profile_id_refused,
    wrong_audit_event_refused: summary.wrong_audit_event_refused,
    wrong_detail_refused: summary.wrong_detail_refused,
    non_boarding_outcome_refused: summary.non_boarding_outcome_refused,
    direct_api_without_receipt_refused: summary.direct_api_without_receipt_refused,
    direct_api_with_receipt_refused: summary.direct_api_with_receipt_refused,
    agent_supplied_authority_material_refused:
      summary.agent_supplied_authority_material_refused,
    runtime_profile_identity_authority_source:
      summary.runtime_profile_identity_authority_source,
    runtime_profile_identity_request_stream_policy:
      summary.runtime_profile_identity_request_stream_policy,
    request_runtime_profile_id_required:
      summary.request_runtime_profile_id_required,
    omitted_request_runtime_profile_id_present:
      summary.omitted_request_runtime_profile_id_present,
    omitted_runtime_profile_id_uses_launcher_config:
      summary.omitted_runtime_profile_id_uses_launcher_config,
    omitted_runtime_profile_id_reason_code:
      summary.omitted_runtime_profile_id_reason_code,
    omitted_runtime_profile_id_state_entry_count_delta:
      summary.omitted_runtime_profile_id_state_entry_count_delta,
    omitted_runtime_profile_id_consumed_authority_grant_count:
      summary.omitted_runtime_profile_id_consumed_authority_grant_count,
    supplied_mismatched_runtime_profile_id_refused:
      summary.supplied_mismatched_runtime_profile_id_refused,
    supplied_mismatch_reason_code:
      summary.supplied_mismatch_reason_code,
    supplied_mismatch_state_entry_count_delta:
      summary.supplied_mismatch_state_entry_count_delta,
    local_activation_applied: sideDoor.local_activation_applied,
    disposable_runtime_config_written: sideDoor.disposable_runtime_config_written,
    persistent_runtime_config_written: sideDoor.persistent_runtime_config_written,
    hook_configuration_written: sideDoor.hook_configuration_written,
    runtime_service_started: sideDoor.runtime_service_started,
    persistent_runtime_profile_installed: sideDoor.persistent_runtime_profile_installed,
    latest_profile_selected: sideDoor.latest_profile_selected,
    request_stream_authority_material_accepted:
      sideDoor.request_stream_authority_material_accepted,
    live_records_system_checked: sideDoor.live_records_system_checked,
    production_records_service_checked: sideDoor.production_records_service_checked,
    live_mcp_coverage_checked: sideDoor.live_mcp_coverage_checked,
    live_approval_channel_health_checked: sideDoor.live_approval_channel_health_checked,
    exactly_once_effect_semantics: sideDoor.exactly_once_effect_semantics,
    store_and_anchor_joint_rollback_refused_while_witness_ahead:
      sideDoor.store_and_anchor_joint_rollback_refused_while_witness_ahead,
    store_anchor_and_witness_joint_rollback_detection:
      sideDoor.store_anchor_and_witness_joint_rollback_detection,
    store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse:
      sideDoor.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse,
    atomic_store_anchor_witness_commit: sideDoor.atomic_store_anchor_witness_commit,
    partial_grant_commit_burn_window_named:
      sideDoor.partial_grant_commit_burn_window_named,
    host_filesystem_path_toctou_closed:
      sideDoor.host_filesystem_path_toctou_closed,
    fixture_rightful_issuance_path_evidenced:
      summary.omitted_runtime_profile_id_reason_code ===
        'fixture_authority_grant_effect_satisfied' &&
      summary.omitted_runtime_profile_id_consumed_authority_grant_count === 1,
    rightful_issuance_proven: false,
    portable_rightful_issuance_proven: false,
    live_authority_proven: false,
    production_rightful_issuance_proven: false,
    current_machine_governance_proven: false,
    consequence_lifecycle_closed: false,
    external_attestation: sideDoor.external_attestation,
    sovereign_recognition: sideDoor.sovereign_recognition,
    unrouted_records_paths_checked: sideDoor.unrouted_records_paths_checked,
    operator_requirements: [...proof.operator_requirements],
    known_open_boundaries: [...proof.known_open_boundaries],
    local_activation_non_claims: [...proof.non_claims],
  };
}

function protectedRecordsRuntimeProfileInstallationComponent() {
  const plan = protectedRecordsRuntimeProfileInstallationPlan();
  const profile = protectedRecordsRuntimePreflightProfile();
  const proof = runProtectedRecordsRuntimeProfileInstallationProof(plan, profile);
  assertProtectedRecordsRuntimeProfileInstallationProof(proof, plan, profile);
  const summary = proof.runtime_proof_summary;
  const sideDoor = proof.side_door_report;
  return {
    component: 'protected_records_runtime_profile_installation',
    proof_type: proof.proof_type,
    evidence_model: proof.evidence_model,
    live_probing: proof.live_probing,
    safe_claim_ceiling: proof.safe_claim_ceiling,
    installation_command: plan.installation_command,
    plan_type: proof.plan.plan_type,
    plan_id: proof.plan.plan_id,
    plan_sha256: proof.plan.plan_sha256,
    plan_status: proof.plan.plan_status,
    deployment_posture: proof.plan.deployment_posture,
    action_class: plan.action_class,
    runtime_profile_id: proof.runtime_profile.runtime_profile_id,
    runtime_profile_source: plan.runtime_profile_source,
    runtime_profile_sha256: proof.runtime_profile.profile_sha256,
    runtime_profile_sha_matches_plan: proof.runtime_profile.profile_sha_matches_plan,
    disposable_profile_selection: {
      install_root_kind: proof.installation.install_root_kind,
      install_root_path_in_report: proof.installation.install_root_path_in_report,
      installed_profile_path_in_report: proof.installation.installed_profile_path_in_report,
      active_index_path_in_report: proof.installation.active_index_path_in_report,
      install_root_created: proof.installation.install_root_created,
      profile_copy_written: proof.installation.profile_copy_written,
      active_profile_index_written: proof.installation.active_profile_index_written,
      profile_selected_from_install_root: proof.installation.profile_selected_from_install_root,
      selected_by_explicit_id_and_sha: proof.installation.selected_by_explicit_id_and_sha,
      selects_latest_profile: proof.installation.selects_latest_profile,
      profile_sha_verified_before_selection: proof.installation.profile_sha_verified_before_selection,
      profile_status_before_installation: proof.installation.profile_status_before_installation,
      installed_profile_status: proof.installation.installed_profile_status,
      selected_profile_id: proof.installation.selected_profile_id,
      selected_runtime_profile_id: proof.installation.selected_runtime_profile_id,
      selected_profile_sha256: proof.installation.selected_profile_sha256,
    },
    request_authority_guard_summary: { ...proof.request_authority_guard_summary },
    runtime_profile_proof_command: plan.runtime_profile_proof_command,
    service_command: plan.service_command,
    runtime_profile_installation_run_in_proof_pack: true,
    runtime_profile_proof_run_in_proof_pack: summary.proof_run,
    runtime_profile_proof_type: summary.proof_type,
    runtime_profile_proof_case_count: summary.case_count,
    runtime_profile_proof_required_case_count: summary.required_case_count,
    runtime_profile_boundary_observation_count: summary.boundary_observation_count,
    runtime_profile_required_boundary_observation_count:
      summary.required_boundary_observation_count,
    recognized_write_accepted: summary.recognized_write_accepted,
    mutation_authoritative_route: profile.mutation_authoritative_route,
    consumed_authority_grant_store: profile.consumed_authority_grant_store,
    consumption_identity: profile.consumption_identity,
    signed_payload_replay_identity: profile.signed_payload_replay_identity,
    consumed_store_witness: profile.consumed_store_witness,
    consumed_store_write_model: profile.consumed_store_write_model,
    same_process_signed_payload_replay_refused:
      summary.same_process_signed_payload_replay_refused,
    restart_consumed_authority_grant_refused:
      summary.restart_consumed_authority_grant_refused,
    missing_authority_grant_appointment_refused:
      summary.missing_authority_grant_appointment_refused,
    mismatched_authority_grant_appointment_refused:
      summary.mismatched_authority_grant_appointment_refused,
    revoked_authority_grant_refused: summary.revoked_authority_grant_refused,
    expired_authority_grant_refused: summary.expired_authority_grant_refused,
    request_supplied_authority_grant_refused:
      summary.request_supplied_authority_grant_refused,
    missing_receipt_refused: summary.missing_receipt_refused,
    invalid_receipt_refused: summary.invalid_receipt_refused,
    unknown_issuer_refused: summary.unknown_issuer_refused,
    retired_issuer_refused: summary.retired_issuer_refused,
    missing_issuer_status_refused: summary.missing_issuer_status_refused,
    stale_receipt_refused: summary.stale_receipt_refused,
    wrong_policy_refused: summary.wrong_policy_refused,
    wrong_domain_refused: summary.wrong_domain_refused,
    wrong_tool_refused: summary.wrong_tool_refused,
    wrong_runtime_profile_id_refused: summary.wrong_runtime_profile_id_refused,
    wrong_audit_event_refused: summary.wrong_audit_event_refused,
    wrong_detail_refused: summary.wrong_detail_refused,
    non_boarding_outcome_refused: summary.non_boarding_outcome_refused,
    direct_api_without_receipt_refused: summary.direct_api_without_receipt_refused,
    direct_api_with_receipt_refused: summary.direct_api_with_receipt_refused,
    agent_supplied_authority_material_refused:
      summary.agent_supplied_authority_material_refused,
    runtime_profile_identity_authority_source:
      summary.runtime_profile_identity_authority_source,
    runtime_profile_identity_request_stream_policy:
      summary.runtime_profile_identity_request_stream_policy,
    request_runtime_profile_id_required:
      summary.request_runtime_profile_id_required,
    omitted_request_runtime_profile_id_present:
      summary.omitted_request_runtime_profile_id_present,
    omitted_runtime_profile_id_uses_launcher_config:
      summary.omitted_runtime_profile_id_uses_launcher_config,
    omitted_runtime_profile_id_reason_code:
      summary.omitted_runtime_profile_id_reason_code,
    omitted_runtime_profile_id_state_entry_count_delta:
      summary.omitted_runtime_profile_id_state_entry_count_delta,
    omitted_runtime_profile_id_consumed_authority_grant_count:
      summary.omitted_runtime_profile_id_consumed_authority_grant_count,
    supplied_mismatched_runtime_profile_id_refused:
      summary.supplied_mismatched_runtime_profile_id_refused,
    supplied_mismatch_reason_code:
      summary.supplied_mismatch_reason_code,
    supplied_mismatch_state_entry_count_delta:
      summary.supplied_mismatch_state_entry_count_delta,
    disposable_profile_installation_applied: sideDoor.disposable_profile_installation_applied,
    local_disposable_install_root_created: sideDoor.local_disposable_install_root_created,
    profile_copied_to_install_root: sideDoor.profile_copied_to_install_root,
    active_profile_index_written: sideDoor.active_profile_index_written,
    profile_selected_from_install_root: sideDoor.profile_selected_from_install_root,
    disposable_runtime_config_written: sideDoor.disposable_runtime_config_written,
    persistent_runtime_config_written: sideDoor.persistent_runtime_config_written,
    hook_configuration_written: sideDoor.hook_configuration_written,
    user_config_written: sideDoor.user_config_written,
    machine_config_written: sideDoor.machine_config_written,
    runtime_service_started: sideDoor.runtime_service_started,
    persistent_runtime_profile_installed: sideDoor.persistent_runtime_profile_installed,
    latest_profile_selected: sideDoor.latest_profile_selected,
    request_stream_authority_material_accepted:
      sideDoor.request_stream_authority_material_accepted,
    live_runtime_profile_checked: sideDoor.live_runtime_profile_checked,
    live_records_system_checked: sideDoor.live_records_system_checked,
    production_records_service_checked: sideDoor.production_records_service_checked,
    live_mcp_coverage_checked: sideDoor.live_mcp_coverage_checked,
    live_approval_channel_health_checked: sideDoor.live_approval_channel_health_checked,
    exactly_once_effect_semantics: sideDoor.exactly_once_effect_semantics,
    store_anchor_and_witness_joint_rollback_detection:
      sideDoor.store_anchor_and_witness_joint_rollback_detection,
    atomic_store_anchor_witness_commit: sideDoor.atomic_store_anchor_witness_commit,
    partial_grant_commit_burn_window_named:
      sideDoor.partial_grant_commit_burn_window_named,
    host_filesystem_path_toctou_closed:
      sideDoor.host_filesystem_path_toctou_closed,
    fixture_rightful_issuance_path_evidenced:
      summary.fixture_rightful_issuance_path_evidenced,
    rightful_issuance_proven: false,
    portable_rightful_issuance_proven: false,
    live_authority_proven: false,
    production_rightful_issuance_proven: false,
    current_machine_governance_proven: false,
    consequence_lifecycle_closed: false,
    external_attestation: sideDoor.external_attestation,
    sovereign_recognition: sideDoor.sovereign_recognition,
    unrouted_records_paths_checked: sideDoor.unrouted_records_paths_checked,
    operator_requirements: [...proof.operator_requirements],
    known_open_boundaries: [...proof.known_open_boundaries],
    profile_installation_non_claims: [...proof.non_claims],
  };
}

function claudeCodeHookContractReplayComponent() {
  const proof = runClaudeCodeHookContractReplayProof();
  assertClaudeCodeHookContractReplayProof(proof);
  const caseEvidence = claudeCodeHookContractReplayCaseEvidence(proof);
  assertClaudeCodeHookContractReplayCaseEvidence(caseEvidence);
  return {
    component: 'claude_code_hook_contract_replay',
    command: 'zlar claude-code-hook-contract-replay-proof',
    proof_type: proof.proof_type,
    evidence_model: proof.evidence_model,
    live_probing: false,
    hook_replay_contract_sha256: proof.hook_replay_contract_sha256,
    source_state_boundary: CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY,
    adapter_source: proof.adapter_source,
    adapter_path_claimed: proof.adapter_path_claimed,
    adapter_sha256: proof.adapter_sha256,
    case_evidence_hash_scope: CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASE_EVIDENCE_HASH_SCOPE,
    case_evidence_sha256: sha256Hex(canonicalize(caseEvidence)),
    case_evidence: caseEvidence,
    required_case_count: REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES.length,
    required_cases: proof.cases.map((item) => item.case_id),
    all_required_cases_present: proof.summary.all_required_cases_present,
    permission_decisions_observed: {
      allow: proof.summary.allow_json_observed,
      deny: proof.summary.deny_json_observed,
    },
    denied_effect_not_executed: proof.summary.denied_effect_not_executed,
    tool_input_not_executed: proof.summary.adapter_did_not_execute_tool_input,
    missing_gate_failed_closed: proof.summary.missing_gate_failed_closed,
    blank_gate_response_failed_closed: proof.summary.blank_gate_response_failed_closed,
    malformed_output_refused: proof.summary.malformed_output_refused,
    non_pretooluse_payload_denied_by_fixture_gate:
      proof.summary.non_pretooluse_payload_denied_by_fixture_gate,
    live_claude_invoked: proof.live_claude_invoked,
    live_claude_app_passage_proven: proof.live_claude_app_passage_proven,
    app_originated_hook_crossing_proven: proof.app_originated_hook_crossing_proven,
    live_receipt_emission_proven: proof.live_receipt_emission_proven,
    current_machine_governance_proven: proof.current_machine_governance_proven,
    production_downstream_recognition_proven: proof.production_downstream_recognition_proven,
    all_surface_governance_proven: proof.all_surface_governance_proven,
    side_door_closure_proven: proof.side_door_closure_proven,
    supporting_local_boarding_proof_passed:
      proof.supporting_local_boarding_proof.passed,
    supporting_local_boarding_proof_type:
      proof.supporting_local_boarding_proof.proof_type,
    supporting_local_boarding_v1_receipt_identity_verified:
      proof.supporting_local_boarding_proof.v1_receipt_identity_verified,
    supporting_local_boarding_consequence_absent_on_every_refusal:
      proof.supporting_local_boarding_proof.consequence_absent_on_every_refusal,
    supporting_local_boarding_consequence_present_exactly_once_on_acceptance:
      proof.supporting_local_boarding_proof.consequence_present_exactly_once_on_acceptance,
    supporting_local_boarding_legacy_v0_recognized_boarding_identity:
      proof.supporting_local_boarding_proof.legacy_v0_recognized_boarding_identity,
    safe_claim_ceiling: proof.safe_claim_ceiling,
    non_claims: [...proof.non_claims],
    side_doors: [...proof.side_doors],
  };
}

export const LOCAL_PROOF_PACK_GENERATION_RETIREMENT_REASON =
  'local_proof_pack_fresh_generation_retired';

export function runLocalProofPack() {
  throw new Error(LOCAL_PROOF_PACK_GENERATION_RETIREMENT_REASON);
}

export function assertLocalProofPack(report) {
  return assertLocalProofPackReport(report);
}

function assertLocalProofPackReport(
  report,
  { allowHistoricalCoverageComponent = false } = {}
) {
  if (!report || report.proof_pack_type !== LOCAL_PROOF_PACK_TYPE) {
    throw new Error('Local proof pack has the wrong proof pack type');
  }
  assertExactObjectKeys('Local proof pack', report, LOCAL_PROOF_PACK_KEYS);
  if (report.evidence_model !== 'local-fixtures') {
    throw new Error('Local proof pack must use local fixture evidence');
  }
  if (report.live_probing !== false) {
    throw new Error('Local proof pack must not perform live probing');
  }
  const expectedSafeClaimCeiling = allowHistoricalCoverageComponent
    ? HISTORICAL_SAFE_CLAIM_CEILING
    : SAFE_CLAIM_CEILING;
  if (report.safe_claim_ceiling !== expectedSafeClaimCeiling) {
    throw new Error('Local proof pack safe claim ceiling drifted');
  }
  if (!Array.isArray(report.components) || report.components.length !== 16) {
    throw new Error('Local proof pack must contain exactly sixteen components');
  }
  assertExactStringArray(
    'Local proof pack components',
    report.components.map((item) => item?.component),
    LOCAL_PROOF_PACK_COMPONENT_NAMES
  );
  assertLocalProofPackComponentSchemas(report, {
    allowHistoricalCoverageComponent,
  });

  const coverage = report.components.find((item) => item.component === 'governed_surface_coverage_map');
  const historicalCoverageComponent =
    isHistoricalLocalProofPackCoverageComponent(coverage);
  if (coverage.live_probing !== false) {
    throw new Error('Local proof pack coverage component performed live probing');
  }
  const sharedCoverageContractValid =
    coverage.command ===
      'zlar coverage --input tests/fixtures/governed-surface-coverage-map-v1-input.json --require-governed' &&
    coverage.report_type === 'governed-surface-coverage-map-v1' &&
    coverage.evidence_model === 'fixtures' &&
    coverage.counted_lanes === 6 &&
    coverage.boundary_entries === 12;
  const historicalCoverageValid =
    allowHistoricalCoverageComponent &&
    historicalCoverageComponent &&
    coverage.governed_lanes === 6;
  const currentCoverageValid =
    !historicalCoverageComponent &&
    coverage.governed_lanes === 4 &&
    coverage.terminal_artifact_body_sha256 ===
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256 &&
    coverage.terminal_artifact_expected_body_sha256 ===
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256 &&
    coverage.terminal_artifact_identity_sha256_matched === true &&
    coverage
      .terminal_outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256 === true &&
    coverage
      .terminal_recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256 === true &&
    coverage.terminal_trusted_issuer_registry_signature_valid === true &&
    coverage.terminal_fixture_rightful_issuance_path_evidenced === false;
  if (
    !coverage ||
    !sharedCoverageContractValid ||
    (!historicalCoverageValid && !currentCoverageValid)
  ) {
    throw new Error('Local proof pack coverage component drifted');
  }

  const downstream = report.components.find((item) => item.component === 'downstream_refusal_proof');
  assertExactObjectKeys(
    'Local proof pack downstream refusal component',
    downstream,
    DOWNSTREAM_REFUSAL_COMPONENT_KEYS
  );
  if (
    downstream.recognized_boarded !== true ||
    downstream.recognized_marker_count_delta !== 1 ||
    downstream.final_marker_count !== 1 ||
    downstream.refusal_case_count !== DOWNSTREAM_REFUSAL_REASONS.length ||
    downstream.all_refusals_unboarded !== true ||
    downstream.all_refusal_marker_count_deltas_zero !== true
  ) {
    throw new Error('Local proof pack downstream refusal component failed');
  }
  for (const reason of DOWNSTREAM_REFUSAL_REASONS) {
    if (!downstream.refusal_reasons.includes(reason)) {
      throw new Error(`Local proof pack downstream component missing refusal reason: ${reason}`);
    }
  }
  assertExactStringArray(
    'Local proof pack downstream component refusal reasons',
    downstream.refusal_reasons,
    DOWNSTREAM_REFUSAL_REASONS
  );

  const humanAuthorization = report.components.find((item) => item.component === 'human_authorization_proof');
  if (
    !humanAuthorization ||
    humanAuthorization.approval_channel !== 'simulated-human-fixture' ||
    humanAuthorization.pending_boarded !== false ||
    humanAuthorization.authorized_boarded !== true ||
    humanAuthorization.denied_boarded !== false ||
    humanAuthorization.authorizer !== 'human:fixture-operator' ||
    humanAuthorization.outcome !== 'authorized'
  ) {
    throw new Error('Local proof pack human authorization component failed');
  }

  const approvalTransport = report.components.find((item) => item.component === 'approval_transport_proof');
  if (
    !approvalTransport ||
    approvalTransport.transport_model !== 'channel-neutral-approval-transport-v1' ||
    approvalTransport.live_probing !== false ||
    approvalTransport.reference_transport_healthy !== true ||
    approvalTransport.telegram_required_for_fixture !== false ||
    approvalTransport.unavailable_boarded !== false ||
    approvalTransport.delivered_without_decision_boarded !== false ||
    approvalTransport.signed_human_decision_boarded !== true
  ) {
    throw new Error('Local proof pack approval transport component failed');
  }

  const issuerStatus = report.components.find((item) => item.component === 'issuer_status_proof');
  if (
    !issuerStatus ||
    issuerStatus.trust_anchor_model !== 'local-fixture-recognition-rule' ||
    issuerStatus.active_issuer_boarded !== true ||
    issuerStatus.retired_issuer_refused !== true ||
    issuerStatus.compromised_issuer_refused !== true ||
    issuerStatus.missing_status_issuer_refused !== true ||
    issuerStatus.unknown_issuer_refused !== true ||
    issuerStatus.missing_key_issuer_refused !== true
  ) {
    throw new Error('Local proof pack issuer status component failed');
  }
  for (const reason of ISSUER_STATUS_REFUSAL_REASONS) {
    if (!issuerStatus.refusal_reasons.includes(reason)) {
      throw new Error(`Local proof pack issuer status component missing refusal reason: ${reason}`);
    }
  }

  const trustedIssuerRegistryRecognition = report.components.find((item) =>
    item.component === 'trusted_issuer_registry_recognition'
  );
  assertExactObjectKeys(
    'Local proof pack trusted issuer registry recognition component',
    trustedIssuerRegistryRecognition,
    trustedIssuerRegistryRecognitionKeysFor(trustedIssuerRegistryRecognition)
  );
  if (!trustedIssuerRegistryRecognitionPasses(trustedIssuerRegistryRecognition)) {
    throw new Error('Local proof pack trusted issuer registry recognition component failed');
  }
  for (const nonClaim of TRUSTED_ISSUER_REGISTRY_RECOGNITION_NON_CLAIMS) {
    if (!trustedIssuerRegistryRecognition.non_claims.includes(nonClaim)) {
      throw new Error('Local proof pack trusted issuer registry recognition missing non-claim');
    }
  }

  const keyState = report.components.find((item) => item.component === 'key_state_report');
  if (
    !keyState ||
    keyState.command !== 'zlar key-state --sample --json' ||
    keyState.report_type !== KEY_STATE_REPORT_TYPE ||
    keyState.evidence_model !== 'local-read-only-key-state' ||
    keyState.live_probing !== false ||
    keyState.read_only !== true ||
    keyState.operational_posture?.policy_manifest_constitution !== 'software-rooted-current' ||
    keyState.privacy?.private_key_material_read !== false ||
    keyState.privacy?.private_key_material_included !== false ||
    keyState.privacy?.private_key_paths_included !== false ||
    keyState.privacy?.yubi_key_serial_numbers_included !== false ||
    keyState.local_private_key_presence?.legacy_software_signing_key_present !== false ||
    keyState.local_private_key_presence?.private_key_bytes_read !== false ||
    typeof keyState.policy_software_pins_aligned !== 'boolean' ||
    typeof keyState.constitution_software_pins_aligned !== 'boolean' ||
    keyState.policy_hardware_target_observed !== false ||
    keyState.constitution_hardware_target_observed !== false ||
    keyState.spec_hardware_target_observed !== false ||
    keyState.key_custody_proven !== false ||
    keyState.revocation_state_proven !== false ||
    keyState.production_trust_registry_proven !== false ||
    keyState.external_attestation !== false ||
    keyState.sovereign_recognition !== false ||
    keyState.current_machine_governance_proven !== false
  ) {
    throw new Error('Local proof pack key-state component failed');
  }
  if (!Array.isArray(keyState.non_claims) || keyState.non_claims.length !== KEY_STATE_NON_CLAIMS.length) {
    throw new Error('Local proof pack key-state non-claims drifted');
  }
  for (const claim of KEY_STATE_NON_CLAIMS) {
    if (!keyState.non_claims.includes(claim)) {
      throw new Error('Local proof pack key-state missing non-claim');
    }
  }

  const receiptVerifierBoundary = report.components.find((item) =>
    item.component === 'receipt_verifier_boundary'
  );
  if (!receiptVerifierBoundary) {
    throw new Error('Local proof pack receipt verifier boundary component failed');
  }
  const { component: receiptVerifierComponent, ...receiptVerifierProof } = receiptVerifierBoundary;
  if (receiptVerifierComponent !== 'receipt_verifier_boundary') {
    throw new Error('Local proof pack receipt verifier boundary component failed');
  }
  assertReceiptVerifierBoundaryProof(receiptVerifierProof);
  if (
    receiptVerifierBoundary.proof_type !== RECEIPT_VERIFIER_BOUNDARY_PROOF_TYPE ||
    receiptVerifierBoundary.safe_claim_ceiling !== RECEIPT_VERIFIER_BOUNDARY_SAFE_CLAIM_CEILING ||
    receiptVerifierBoundary.valid_exit_code !== 0 ||
    receiptVerifierBoundary.valid_verdict !== 'VALID' ||
    receiptVerifierBoundary.valid_receipt_sha256_present !== true ||
    receiptVerifierBoundary.valid_provided_pubkey_sha256_present !== true ||
    receiptVerifierBoundary.valid_command_posture_allow_v0 !== false ||
    receiptVerifierBoundary.valid_command_posture_detected_format !== 'v1' ||
    receiptVerifierBoundary.valid_required_identity_command_posture !==
      'receipt-verifier-v1-default' ||
    receiptVerifierBoundary.required_identity_exit_code !== 0 ||
    receiptVerifierBoundary.required_identity_verdict !== 'VALID' ||
    receiptVerifierBoundary.required_identity_receipt_id_matched !== true ||
    receiptVerifierBoundary.required_identity_receipt_sha256_matched !== true ||
    receiptVerifierBoundary.required_identity_kid_matched !== true ||
    receiptVerifierBoundary.required_identity_pubkey_sha256_matched !== true ||
    receiptVerifierBoundary.required_identity_format_matched !== true ||
    receiptVerifierBoundary.required_identity_v1_only_matched !== true ||
    receiptVerifierBoundary.required_identity_command_posture !==
      'receipt-verifier-v1-only-required' ||
    receiptVerifierBoundary.required_identity_command_posture_allow_v0 !== false ||
    receiptVerifierBoundary.required_identity_command_posture_detected_format !==
      'v1' ||
    receiptVerifierBoundary.required_identity_command_posture_v1_only_required !==
      true ||
    receiptVerifierBoundary.unknown_signer_exit_code !== 3 ||
    receiptVerifierBoundary.unknown_signer_verdict !== 'UNKNOWN-SIGNER' ||
    receiptVerifierBoundary.unknown_signer_receipt_sha256_matches_valid !== true ||
    receiptVerifierBoundary.unknown_signer_provided_pubkey_sha256_differs !==
      true ||
    receiptVerifierBoundary.invalid_exit_code !== 1 ||
    receiptVerifierBoundary.invalid_verdict !== 'INVALID' ||
    receiptVerifierBoundary.invalid_receipt_sha256_differs_from_valid !== true ||
    receiptVerifierBoundary.invalid_provided_pubkey_sha256_matches_valid !== true ||
    receiptVerifierBoundary.legacy_v0_required_identity_refused !== true ||
    receiptVerifierBoundary.legacy_v0_required_identity_exit_code !== 1 ||
    receiptVerifierBoundary.distinguishes_unknown_signer_from_invalid !== true ||
    receiptVerifierBoundary.issuer_recognition_proven !== false ||
    receiptVerifierBoundary.key_custody_proven !== false ||
    receiptVerifierBoundary.revocation_state_proven !== false ||
    receiptVerifierBoundary.downstream_recognition_proven !== false ||
    receiptVerifierBoundary.production_deployment_proven !== false ||
    receiptVerifierBoundary.current_machine_governance_proven !== false ||
    receiptVerifierBoundary.external_attestation !== false ||
    receiptVerifierBoundary.sovereign_recognition !== false ||
    receiptVerifierBoundary.unrouted_paths_coverage_proven !== false
  ) {
    throw new Error('Local proof pack receipt verifier boundary component failed');
  }
  for (const nonClaim of RECEIPT_VERIFIER_BOUNDARY_NON_CLAIMS) {
    if (!receiptVerifierBoundary.non_claims.includes(nonClaim)) {
      throw new Error('Local proof pack receipt verifier boundary missing non-claim');
    }
  }

  const protectedRecords = report.components.find((item) => item.component === 'protected_records_terminal');
  if (
    !protectedRecords ||
    protectedRecords.deployment_profile !== 'protected-records-terminal' ||
    protectedRecords.action_class !== 'records.write' ||
    protectedRecords.downstream_boundary !== 'protected-records-terminal-fixture' ||
    protectedRecords.adapter_profile_type !== 'protected-records-adapter-profile-v1' ||
    protectedRecords.adapter_profile_id !== 'protected-records-adapter-profile' ||
    protectedRecords.adapter_authoritative_route !== 'receipt-recognition-before-ledger-append' ||
    protectedRecords.adapter_boundary !== 'protected-records-adapter-harness' ||
    protectedRecords.adapter_ledger_model !== 'append-only-jsonl-ledger' ||
    protectedRecords.adapter_consumed_receipt_store !== 'single-use-receipt-id-store' ||
    protectedRecords.adapter_replay_scope !== 'per-adapter-ledger' ||
    protectedRecords.adapter_final_ledger_entry_count !== 1 ||
    protectedRecords.adapter_consumed_receipt_count !== 1 ||
    protectedRecords.adapter_direct_write_path_available !== false ||
    protectedRecords.adapter_live_records_adapter !== false ||
    protectedRecords.adapter_action_type !== 'local-protected-records-action-adapter-v1' ||
    protectedRecords.adapter_action_command !== 'zlar protected-records-write --input <file|->' ||
    protectedRecords.adapter_action_result_type !== 'protected-records-write-result-v1' ||
    protectedRecords.adapter_action_fixture_mode_required !== true ||
    protectedRecords.adapter_action_writes !== 'bounded-jsonl-ledger-entry' ||
    protectedRecords.adapter_action_live_records_adapter !== false ||
    protectedRecords.adapter_action_raw_record_detail_output !== false ||
    protectedRecords.profile_contract_id !== 'protected-records-terminal' ||
    protectedRecords.profile_contract_checkpoint !== 'downstream-recognition-rule' ||
    protectedRecords.profile_contract_route !== 'receipt-recognition-before-record-write' ||
    protectedRecords.profile_contract_downstream_effect !== 'append-protected-records-ledger-entry' ||
    protectedRecords.receipt_replay_policy !== 'single-use-receipt-id-per-terminal-ledger' ||
    protectedRecords.recognized_write_accepted !== true ||
    protectedRecords.recognized_record_changed !== true ||
    protectedRecords.recognized_record_count_delta !== 1 ||
    protectedRecords.refused_write_count !== PROTECTED_RECORDS_REFUSAL_REASONS.length ||
    protectedRecords.all_refusals_prevented_record_change !== true ||
    protectedRecords.refusal_record_count_delta_total !== 0 ||
    protectedRecords.final_record_count !== 1
  ) {
    throw new Error('Local proof pack protected records component failed');
  }
  for (const field of [
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
  ]) {
    if (!protectedRecords.required_receipt_fields.includes(field)) {
      throw new Error(`Local proof pack protected records component missing required receipt field: ${field}`);
    }
  }
  for (const reason of PROTECTED_RECORDS_REFUSAL_REASONS) {
    if (!protectedRecords.refusal_reasons.includes(reason)) {
      throw new Error(`Local proof pack protected records component missing refusal reason: ${reason}`);
    }
  }
  const requiredProtectedRecordsBoundaries = [
    'live_records_system',
    'production_records_adapter',
    'unrouted_records_paths',
  ];
  for (const boundary of requiredProtectedRecordsBoundaries) {
    if (!protectedRecords.known_ungoverned_boundaries.includes(boundary)) {
      throw new Error(`Local proof pack protected records component missing ungoverned boundary: ${boundary}`);
    }
  }
  for (const closedRoute of [
    'direct_fixture_ledger_mutation',
    'adapter_bypass_write',
  ]) {
    if (!protectedRecords.adapter_closed_in_fixture.includes(closedRoute)) {
      throw new Error(`Local proof pack protected records component missing adapter closed route: ${closedRoute}`);
    }
  }
  for (const boundary of requiredProtectedRecordsBoundaries) {
    if (!protectedRecords.adapter_known_open_boundaries.includes(boundary)) {
      throw new Error(`Local proof pack protected records component missing adapter open boundary: ${boundary}`);
    }
  }

  const adapterConformance = report.components.find((item) => item.component === 'protected_records_adapter_conformance');
  if (
    !adapterConformance ||
    adapterConformance.command !== 'zlar protected-records-adapter-conformance' ||
    adapterConformance.evidence_model !== 'local-disposable-cli-process-fixture' ||
    adapterConformance.live_probing !== false ||
    adapterConformance.profile_id !== 'protected-records-cli-process-conformance' ||
    adapterConformance.action_class !== 'records.write' ||
    adapterConformance.adapter_type !== 'local-protected-records-action-adapter-v1' ||
    adapterConformance.adapter_command !== 'zlar protected-records-write --input <file|->' ||
    adapterConformance.adapter_process_boundary !== 'separate-cli-process' ||
    adapterConformance.mutation_authoritative_route !== 'receipt-recognition-before-ledger-append' ||
    adapterConformance.result_type !== 'protected-records-write-result-v1' ||
    adapterConformance.ledger_model !== 'bounded-jsonl-ledger-entry' ||
    adapterConformance.consumed_receipt_store !== 'persistent-single-use-receipt-id-store' ||
    adapterConformance.replay_scope !== 'per-adapter-consumed-receipt-store' ||
    adapterConformance.recognized_write_accepted !== true ||
    adapterConformance.recognized_write_reason !== 'recognized' ||
    adapterConformance.recognized_write_ledger_delta !== 1 ||
    adapterConformance.replay_refused !== true ||
    adapterConformance.replay_reason !== 'receipt_replay' ||
    adapterConformance.replay_ledger_delta !== 0 ||
    adapterConformance.replay_separate_process !== true ||
    adapterConformance.missing_receipt_refused !== true ||
    adapterConformance.missing_receipt_reason !== 'receipt_missing' ||
    adapterConformance.missing_receipt_ledger_delta !== 0 ||
    adapterConformance.unsupported_side_door_refused !== true ||
    adapterConformance.unsupported_side_door_reason !== 'unsupported_option' ||
    adapterConformance.unsupported_side_door_ledger_delta !== 0 ||
    adapterConformance.cli_direct_write_option_available !== false ||
    adapterConformance.direct_filesystem_write_to_fixture_paths_closed !== false ||
    adapterConformance.live_records_adapter !== false
  ) {
    throw new Error('Local proof pack protected records adapter conformance component failed');
  }
  for (const caseId of PROTECTED_RECORDS_CONFORMANCE_CASES) {
    if (!adapterConformance.conformance_cases.includes(caseId)) {
      throw new Error(`Local proof pack protected records adapter conformance missing case: ${caseId}`);
    }
  }
  for (const boundary of [
    'direct_filesystem_write_to_supplied_fixture_paths',
    'live_records_system',
    'production_records_adapter',
    'unrouted_records_paths',
  ]) {
    if (!adapterConformance.known_open_boundaries.includes(boundary)) {
      throw new Error(`Local proof pack protected records adapter conformance missing open boundary: ${boundary}`);
    }
  }

  const protectedRecordsService = report.components.find((item) => item.component === 'protected_records_downstream_service');
  const protectedRecordsServiceProfile = protectedRecordsServicePreflightProfile();
  if (
    !protectedRecordsService ||
    protectedRecordsService.command !== 'zlar protected-records-service-proof' ||
    protectedRecordsService.evidence_model !== 'local-disposable-service-process-fixture' ||
    protectedRecordsService.live_probing !== false ||
    protectedRecordsService.profile_id !== 'protected-records-downstream-service-fixture' ||
    protectedRecordsService.action_class !== 'records.write' ||
    protectedRecordsService.service_type !== 'local-protected-records-downstream-service-v1' ||
    protectedRecordsService.service_command !== 'zlar protected-records-service-request --input <file|->' ||
    protectedRecordsService.service_process_boundary !== 'separate-cli-process' ||
    protectedRecordsService.recognition_boundary !== 'downstream-recognition-before-service-mutation' ||
    protectedRecordsService.mutation_authoritative_route !== 'receipt-recognition-before-service-state-append' ||
    protectedRecordsService.result_type !== 'protected-records-service-result-v1' ||
    protectedRecordsService.state_model !== 'bounded-jsonl-service-state-entry' ||
    protectedRecordsService.consumed_receipt_store !== 'persistent-single-use-receipt-id-store' ||
    protectedRecordsService.replay_scope !== 'per-service-consumed-receipt-store' ||
    protectedRecordsService.direct_api_request_model !== 'no-receipt-direct-api-attempt-refuses-before-mutation' ||
    protectedRecordsService.service_profile_preflight_profile_id !== 'protected-records-service-fixture-profile' ||
    protectedRecordsService.service_profile_preflight_profile_sha256 !== profileSha256(protectedRecordsServiceProfile) ||
    protectedRecordsService.service_profile_preflight_profile_status !== 'sample_not_active' ||
    protectedRecordsService.service_profile_preflight_deployment_posture !== 'deployable_profile_preflight_only' ||
    protectedRecordsService.service_profile_preflight_run_in_proof_pack !== true ||
    protectedRecordsService.service_profile_preflight_type !== PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_TYPE ||
    protectedRecordsService.service_profile_preflight_evidence_model !==
      'local-disposable-config-backed-profile-preflight-fixture' ||
    protectedRecordsService.service_profile_preflight_live_probing !== false ||
    !Array.isArray(protectedRecordsService.service_profile_preflight_cases) ||
    !Array.isArray(protectedRecordsService.service_profile_preflight_case_summaries) ||
    protectedRecordsService.service_profile_preflight_case_count !== protectedRecordsServiceProfile.required_cases.length ||
    protectedRecordsService.service_profile_preflight_required_case_count !==
      protectedRecordsServiceProfile.required_cases.length ||
    protectedRecordsService.service_profile_preflight_recognized_write_accepted !== true ||
    protectedRecordsService.service_profile_preflight_replay_refused !== true ||
    protectedRecordsService.service_profile_preflight_missing_receipt_refused !== true ||
    protectedRecordsService.service_profile_preflight_unrecognized_receipt_refused !== true ||
    protectedRecordsService.service_profile_preflight_invalid_receipt_refused !== true ||
    protectedRecordsService.service_profile_preflight_unknown_issuer_refused !== true ||
    protectedRecordsService.service_profile_preflight_wrong_policy_refused !== true ||
    protectedRecordsService.service_profile_preflight_wrong_policy_reason !== 'policy_not_recognized' ||
    protectedRecordsService.service_profile_preflight_wrong_policy_state_delta !== 0 ||
    protectedRecordsService.service_profile_preflight_stale_receipt_refused !== true ||
    protectedRecordsService.service_profile_preflight_launcher_owned_config_required !== true ||
    protectedRecordsService.service_profile_preflight_request_stream_authority_material_allowed !== false ||
    protectedRecordsService.service_profile_preflight_request_stream_authority_material_refused !== true ||
    protectedRecordsService.service_profile_preflight_request_stream_authority_material_reason !==
      'request_stream_authority_material' ||
    protectedRecordsService.service_profile_preflight_request_stream_authority_material_state_delta !== 0 ||
    protectedRecordsService.service_profile_preflight_request_stream_forbidden_fields_refused !== true ||
    protectedRecordsService.service_profile_preflight_direct_api_without_receipt_refused !== true ||
    protectedRecordsService.service_profile_preflight_direct_api_with_receipt_refused !== true ||
    protectedRecordsService.service_profile_preflight_direct_filesystem_write_to_fixture_paths_closed !== false ||
    protectedRecordsService.service_profile_preflight_live_profile_installed !== false ||
    protectedRecordsService.service_profile_preflight_runtime_profile_activation_checked !== false ||
    protectedRecordsService.service_profile_preflight_live_records_system_checked !== false ||
    protectedRecordsService.service_profile_preflight_production_records_service_checked !== false ||
    protectedRecordsService.service_profile_preflight_live_mcp_coverage_checked !== false ||
    protectedRecordsService.service_profile_preflight_live_approval_channel_health_checked !== false ||
    protectedRecordsService.service_profile_preflight_external_attestation !== false ||
    protectedRecordsService.service_profile_preflight_sovereign_recognition !== false ||
    protectedRecordsService.service_profile_preflight_unrouted_records_paths_checked !== false ||
    protectedRecordsService.recognized_service_write_accepted !== true ||
    protectedRecordsService.recognized_service_reason !== 'recognized' ||
    protectedRecordsService.recognized_service_state_delta !== 1 ||
    protectedRecordsService.replay_refused !== true ||
    protectedRecordsService.replay_reason !== 'receipt_replay' ||
    protectedRecordsService.replay_state_delta !== 0 ||
    protectedRecordsService.replay_separate_process !== true ||
    protectedRecordsService.missing_receipt_refused !== true ||
    protectedRecordsService.missing_receipt_reason !== 'receipt_missing' ||
    protectedRecordsService.missing_receipt_state_delta !== 0 ||
    protectedRecordsService.unrecognized_receipt_refused !== true ||
    protectedRecordsService.unrecognized_receipt_reason !== 'detail_hash_mismatch' ||
    protectedRecordsService.unrecognized_receipt_state_delta !== 0 ||
    protectedRecordsService.invalid_receipt_refused !== true ||
    protectedRecordsService.invalid_receipt_reason !== 'receipt_invalid' ||
    protectedRecordsService.invalid_receipt_state_delta !== 0 ||
    protectedRecordsService.unknown_issuer_refused !== true ||
    protectedRecordsService.unknown_issuer_reason !== 'unknown_issuer' ||
    protectedRecordsService.unknown_issuer_state_delta !== 0 ||
    protectedRecordsService.stale_receipt_refused !== true ||
    protectedRecordsService.stale_receipt_reason !== 'receipt_stale' ||
    protectedRecordsService.stale_receipt_state_delta !== 0 ||
    protectedRecordsService.direct_api_without_receipt_refused !== true ||
    protectedRecordsService.direct_api_reason !== 'receipt_missing' ||
    protectedRecordsService.direct_api_state_delta !== 0 ||
    protectedRecordsService.direct_api_attempted !== true ||
    protectedRecordsService.direct_api_without_receipt_refused_reported !== true ||
    protectedRecordsService.direct_filesystem_write_to_fixture_paths_closed !== false ||
    protectedRecordsService.live_records_service !== false
  ) {
    throw new Error('Local proof pack protected records downstream service component failed');
  }
  for (const caseId of PROTECTED_RECORDS_SERVICE_CASES) {
    if (!protectedRecordsService.service_cases.includes(caseId)) {
      throw new Error(`Local proof pack protected records downstream service missing case: ${caseId}`);
    }
  }
  if (
    !Array.isArray(protectedRecordsService.service_profile_preflight_known_open_boundaries) ||
    !Array.isArray(protectedRecordsService.service_profile_preflight_non_claims)
  ) {
    throw new Error('Local proof pack protected records service preflight summary missing boundary fields');
  }
  for (const caseId of PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES) {
    if (!protectedRecordsService.service_profile_preflight_cases.includes(caseId)) {
      throw new Error(`Local proof pack protected records service preflight missing case: ${caseId}`);
    }
  }
  if (
    protectedRecordsService.service_profile_preflight_case_summaries.length !==
    PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length
  ) {
    throw new Error('Local proof pack protected records service preflight case summaries drifted');
  }
  const preflightDirectApiWithReceiptSummary =
    protectedRecordsService.service_profile_preflight_case_summaries.find((item) =>
      item.case_id === 'direct_api_profile_receipt_present_refused_before_service_mutation'
    );
  if (
    !preflightDirectApiWithReceiptSummary ||
    preflightDirectApiWithReceiptSummary.process_invocation !== 11 ||
    preflightDirectApiWithReceiptSummary.service_write_accepted !== false ||
    preflightDirectApiWithReceiptSummary.reason_code !== 'request_stream_forbidden_fields' ||
    preflightDirectApiWithReceiptSummary.state_entry_count_delta !== 0 ||
    preflightDirectApiWithReceiptSummary.direct_api_attempted !== true
  ) {
    throw new Error('Local proof pack protected records service preflight direct API receipt-present summary failed');
  }
  const preflightRequestStreamAuthoritySummary =
    protectedRecordsService.service_profile_preflight_case_summaries.find((item) =>
      item.case_id === 'request_stream_authority_material_profile_refused_before_service_mutation'
    );
  if (
    !preflightRequestStreamAuthoritySummary ||
    preflightRequestStreamAuthoritySummary.process_invocation !== 9 ||
    preflightRequestStreamAuthoritySummary.service_write_accepted !== false ||
    preflightRequestStreamAuthoritySummary.reason_code !== 'request_stream_authority_material' ||
    preflightRequestStreamAuthoritySummary.state_entry_count_delta !== 0 ||
    preflightRequestStreamAuthoritySummary.direct_api_attempted !== false
  ) {
    throw new Error('Local proof pack protected records service preflight request-stream authority summary failed');
  }
  const preflightWrongPolicySummary =
    protectedRecordsService.service_profile_preflight_case_summaries.find((item) =>
      item.case_id === 'wrong_policy_profile_refused_before_service_mutation'
    );
  if (
    !preflightWrongPolicySummary ||
    preflightWrongPolicySummary.process_invocation !== 7 ||
    preflightWrongPolicySummary.service_write_accepted !== false ||
    preflightWrongPolicySummary.reason_code !== 'policy_not_recognized' ||
    preflightWrongPolicySummary.state_entry_count_delta !== 0 ||
    preflightWrongPolicySummary.direct_api_attempted !== false
  ) {
    throw new Error('Local proof pack protected records service preflight wrong-policy summary failed');
  }
  for (const boundary of [
    'direct_filesystem_write_to_supplied_fixture_paths',
    'live_records_system',
    'production_records_service',
    'unrouted_records_paths',
  ]) {
    if (!protectedRecordsService.known_open_boundaries.includes(boundary)) {
      throw new Error(`Local proof pack protected records downstream service missing open boundary: ${boundary}`);
    }
  }
  for (const boundary of [
    'direct_filesystem_write_to_configured_fixture_paths',
    'live_records_system',
    'production_records_service',
    'runtime_profile_not_installed',
    'unrouted_records_paths',
  ]) {
    if (!protectedRecordsService.service_profile_preflight_known_open_boundaries.includes(boundary)) {
      throw new Error(`Local proof pack protected records service preflight missing open boundary: ${boundary}`);
    }
  }
  for (const nonClaim of protectedRecordsServiceProfile.non_claims) {
    if (!protectedRecordsService.service_profile_preflight_non_claims.includes(nonClaim)) {
      throw new Error('Local proof pack protected records service preflight missing non-claim');
    }
  }

  const runtimeProfilePreflight = report.components.find((item) =>
    item.component === 'protected_records_runtime_profile_preflight_identity'
  );
  const protectedRecordsRuntimeProfile = protectedRecordsRuntimePreflightProfile();
  if (
    !runtimeProfilePreflight ||
    runtimeProfilePreflight.preflight_command !== 'zlar protected-records-runtime-profile-preflight --profile profiles/protected-records-runtime-fixture.profile.json' ||
    runtimeProfilePreflight.profile_type !== 'zlar-protected-records-runtime-profile-v1' ||
    runtimeProfilePreflight.profile_id !== 'protected-records-runtime-fixture-profile' ||
    runtimeProfilePreflight.profile_sha256 !== runtimeProfileSha256(protectedRecordsRuntimeProfile) ||
    runtimeProfilePreflight.profile_status !== 'sample_not_active' ||
    runtimeProfilePreflight.deployment_posture !== 'runtime_profile_preflight_only' ||
    runtimeProfilePreflight.runtime_profile_id !== 'protected-records-disposable-runtime-profile' ||
    runtimeProfilePreflight.action_class !== 'records.write' ||
    runtimeProfilePreflight.service_command !== 'zlar protected-records-runtime-service --config <file>' ||
    runtimeProfilePreflight.proof_command !== 'zlar protected-records-runtime-profile-proof' ||
    runtimeProfilePreflight.request_contract !== 'receipt-record-update-and-routing-metadata-only' ||
    runtimeProfilePreflight.mutation_authoritative_route !== RECORDS_WRITE_TERMINAL_ROUTE ||
    runtimeProfilePreflight.config_supplied_by_launcher !== true ||
    runtimeProfilePreflight.request_stream_authority_material_accepted !== false ||
    runtimeProfilePreflight.state_path_exposed_to_agent !== false ||
    runtimeProfilePreflight.consumed_grants_path_exposed_to_agent !== false ||
    runtimeProfilePreflight.consumed_grant_store_anchor_path_exposed_to_agent !== false ||
    runtimeProfilePreflight.consumed_grant_store_witness_path_exposed_to_agent !== false ||
    runtimeProfilePreflight.recognition_rule_supplied_by_agent !== false ||
    runtimeProfilePreflight.authority_grant_contract_required_from_launcher !== true ||
    runtimeProfilePreflight.authority_grant_appointment_required_from_launcher !== true ||
    runtimeProfilePreflight.authority_grant_issuance_decision_required_from_launcher !== true ||
    runtimeProfilePreflight.authorized_record_update_required_from_launcher !== true ||
    runtimeProfilePreflight.source_profile_authority_grant_present !== false ||
    runtimeProfilePreflight.consumed_authority_grant_store !==
      'persistent-single-use-authority-grant-contract-sha256-store' ||
    runtimeProfilePreflight.consumption_identity !== 'authority-grant-contract-sha256' ||
    runtimeProfilePreflight.signed_payload_replay_identity !== 'verified-signed-payload-sha256' ||
    runtimeProfilePreflight.consumed_store_lock !== 'launcher-owned-per-store-lockfile' ||
    runtimeProfilePreflight.consumed_store_validation !==
      'exact-schema-unique-grant-contract-sha256s' ||
    runtimeProfilePreflight.consumed_store_anchor !== 'launcher-owned-local-store-hash-anchor' ||
    runtimeProfilePreflight.consumed_store_witness !== 'launcher-owned-local-store-hash-witness' ||
    runtimeProfilePreflight.consumed_store_rollback_detection !==
      'single-host-anchor-and-witness-match-before-mutation' ||
    runtimeProfilePreflight.consumed_store_write_model !==
      'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness' ||
    runtimeProfilePreflight.replay_scope !==
      'helper-signed-payload-identity-and-persistent-authority-grant-contract-sha256' ||
    runtimeProfilePreflight.single_host_rollback_detection !== true ||
    runtimeProfilePreflight.store_and_anchor_joint_rollback_refused_while_witness_ahead !== true ||
    runtimeProfilePreflight.store_anchor_and_witness_joint_rollback_detection !== false ||
    runtimeProfilePreflight.atomic_store_anchor_witness_commit !== false ||
    runtimeProfilePreflight.partial_grant_commit_burn_window_named !== true ||
    runtimeProfilePreflight.host_filesystem_path_toctou_closed !== false ||
    runtimeProfilePreflight.production_grade_anti_rollback !== false ||
    runtimeProfilePreflight.exactly_once_effect_semantics !== false ||
    runtimeProfilePreflight.required_case_count !== protectedRecordsRuntimeProfile.required_cases.length ||
    runtimeProfilePreflight.required_boundary_observation_count !== protectedRecordsRuntimeProfile.required_boundary_observations.length ||
    runtimeProfilePreflight.runtime_profile_preflight_run_in_proof_pack !== false ||
    runtimeProfilePreflight.runtime_profile_proof_run_in_proof_pack !== false ||
    runtimeProfilePreflight.fixture_rightful_issuance_path_evidenced !== false ||
    runtimeProfilePreflight.rightful_issuance_proven !== false ||
    runtimeProfilePreflight.portable_rightful_issuance_proven !== false ||
    runtimeProfilePreflight.live_authority_proven !== false ||
    runtimeProfilePreflight.production_rightful_issuance_proven !== false ||
    runtimeProfilePreflight.current_machine_governance_proven !== false ||
    runtimeProfilePreflight.consequence_lifecycle_closed !== false
  ) {
    throw new Error('Local proof pack protected records runtime profile preflight identity component failed');
  }
  for (const boundary of protectedRecordsRuntimeProfile.known_open_boundaries) {
    if (!runtimeProfilePreflight.known_open_boundaries.includes(boundary)) {
      throw new Error(`Local proof pack runtime profile preflight identity missing open boundary: ${boundary}`);
    }
  }

  const runtimeActivationPreflight = report.components.find((item) =>
    item.component === 'protected_records_runtime_activation_preflight'
  );
  const runtimeActivationPlan = protectedRecordsRuntimeActivationPlan();
  const runtimeProfileSha = runtimeProfileSha256(protectedRecordsRuntimeProfile);
  if (
    !runtimeActivationPreflight ||
    runtimeActivationPreflight.preflight_type !== PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_TYPE ||
    runtimeActivationPreflight.evidence_model !== 'local-runtime-activation-plan-preflight-fixture' ||
    runtimeActivationPreflight.live_probing !== false ||
    runtimeActivationPreflight.safe_claim_ceiling !== RUNTIME_ACTIVATION_PREFLIGHT_SAFE_CLAIM_CEILING ||
    runtimeActivationPreflight.preflight_command !== runtimeActivationPlan.preflight_command ||
    runtimeActivationPreflight.plan_type !== 'zlar-protected-records-runtime-activation-plan-v1' ||
    runtimeActivationPreflight.plan_id !== 'protected-records-runtime-fixture-activation-plan' ||
    runtimeActivationPreflight.plan_sha256 !== runtimeActivationPlanSha256(runtimeActivationPlan) ||
    runtimeActivationPreflight.plan_status !== 'sample_not_active' ||
    runtimeActivationPreflight.deployment_posture !== 'activation_plan_preflight_only' ||
    runtimeActivationPreflight.action_class !== 'records.write' ||
    runtimeActivationPreflight.runtime_profile_id !== 'protected-records-disposable-runtime-profile' ||
    runtimeActivationPreflight.runtime_profile_source !== 'profiles/protected-records-runtime-fixture.profile.json' ||
    runtimeActivationPreflight.runtime_profile_sha256 !== runtimeProfileSha ||
    runtimeActivationPreflight.runtime_profile_sha_matches_plan !== true ||
    runtimeActivationPreflight.runtime_profile_preflight_command !== runtimeActivationPlan.runtime_profile_preflight_command ||
    runtimeActivationPreflight.service_command !== 'zlar protected-records-runtime-service --config <launcher-owned-config>' ||
    runtimeActivationPreflight.proof_command !== 'zlar protected-records-runtime-profile-proof' ||
    runtimeActivationPreflight.activation_applied !== false ||
    runtimeActivationPreflight.writes_runtime_config !== false ||
    runtimeActivationPreflight.writes_hook_configuration !== false ||
    runtimeActivationPreflight.starts_runtime_service !== false ||
    runtimeActivationPreflight.requires_explicit_human_install !== true ||
    runtimeActivationPreflight.selects_latest_profile !== false ||
    runtimeActivationPreflight.request_stream_authority_material_accepted !== false ||
    runtimeActivationPreflight.uses_live_records_system !== false ||
    runtimeActivationPreflight.launcher_supplies_config !== true ||
    runtimeActivationPreflight.config_path_agent_supplied !== false ||
    runtimeActivationPreflight.state_path_agent_supplied !== false ||
    runtimeActivationPreflight.consumed_grants_path_agent_supplied !== false ||
    runtimeActivationPreflight.consumed_grant_store_anchor_path_agent_supplied !== false ||
    runtimeActivationPreflight.consumed_grant_store_witness_path_agent_supplied !== false ||
    runtimeActivationPreflight.recognition_rule_agent_supplied !== false ||
    runtimeActivationPreflight.issuer_registry_agent_supplied !== false ||
    runtimeActivationPreflight.authority_grant_contract_required_from_launcher !== true ||
    runtimeActivationPreflight.authority_grant_appointment_required_from_launcher !== true ||
    runtimeActivationPreflight.authority_grant_issuance_decision_required_from_launcher !== true ||
    runtimeActivationPreflight.authorized_record_update_required_from_launcher !== true ||
    runtimeActivationPreflight.downstream_recognition_required !== true ||
    runtimeActivationPreflight.missing_or_unrecognized_receipt_refused !== true ||
    runtimeActivationPreflight.runtime_activation_preflight_run_in_proof_pack !== true ||
    runtimeActivationPreflight.runtime_profile_preflight_run_in_proof_pack !== true ||
    runtimeActivationPreflight.runtime_profile_proof_run_in_proof_pack !== true ||
    runtimeActivationPreflight.runtime_profile_preflight_type !== PROTECTED_RECORDS_RUNTIME_PROFILE_PREFLIGHT_TYPE ||
    runtimeActivationPreflight.runtime_profile_preflight_evidence_model !== 'local-disposable-runtime-profile-preflight-fixture' ||
    runtimeActivationPreflight.runtime_profile_proof_case_count !== protectedRecordsRuntimeProfile.required_cases.length ||
    runtimeActivationPreflight.runtime_profile_proof_required_case_count !== protectedRecordsRuntimeProfile.required_cases.length ||
    runtimeActivationPreflight.runtime_profile_boundary_observation_count !== protectedRecordsRuntimeProfile.required_boundary_observations.length ||
    runtimeActivationPreflight.runtime_profile_required_boundary_observation_count !== protectedRecordsRuntimeProfile.required_boundary_observations.length ||
    runtimeActivationPreflight.recognized_write_accepted !== true ||
    runtimeActivationPreflight.mutation_authoritative_route !== RECORDS_WRITE_TERMINAL_ROUTE ||
    runtimeActivationPreflight.consumed_authority_grant_store !==
      'persistent-single-use-authority-grant-contract-sha256-store' ||
    runtimeActivationPreflight.consumption_identity !== 'authority-grant-contract-sha256' ||
    runtimeActivationPreflight.signed_payload_replay_identity !== 'verified-signed-payload-sha256' ||
    runtimeActivationPreflight.consumed_store_witness !== 'launcher-owned-local-store-hash-witness' ||
    runtimeActivationPreflight.consumed_store_write_model !==
      'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness' ||
    runtimeActivationPreflight.same_process_signed_payload_replay_refused !== true ||
    runtimeActivationPreflight.restart_consumed_authority_grant_refused !== true ||
    runtimeActivationPreflight.consumed_authority_grant_store_rollback_refused !== true ||
    runtimeActivationPreflight.consumed_authority_grant_store_deletion_refused !== true ||
    runtimeActivationPreflight.consumed_authority_grant_store_replacement_refused !== true ||
    runtimeActivationPreflight.witness_commit_failed_after_authority_grant_store_commit !== true ||
    runtimeActivationPreflight.witness_commit_failure_reason_code !==
      'consumed_store_write_failed_after_grant_commit' ||
    runtimeActivationPreflight.store_and_anchor_joint_rollback_refused_against_witness !== true ||
    runtimeActivationPreflight.missing_authority_grant_appointment_refused !== true ||
    runtimeActivationPreflight.mismatched_authority_grant_appointment_refused !== true ||
    runtimeActivationPreflight.revoked_authority_grant_refused !== true ||
    runtimeActivationPreflight.expired_authority_grant_refused !== true ||
    runtimeActivationPreflight.request_supplied_authority_grant_refused !== true ||
    runtimeActivationPreflight.agent_supplied_authority_material_refused !== true ||
    runtimeActivationPreflight.runtime_profile_identity_authority_source !==
      'launcher-owned-service-config' ||
    runtimeActivationPreflight.runtime_profile_identity_request_stream_policy !==
      'runtime_profile_id_may_be_omitted_but_if_supplied_must_match_config' ||
    runtimeActivationPreflight.request_runtime_profile_id_required !== false ||
    runtimeActivationPreflight.omitted_request_runtime_profile_id_present !== false ||
    runtimeActivationPreflight.omitted_runtime_profile_id_uses_launcher_config !== true ||
    runtimeActivationPreflight.omitted_runtime_profile_id_reason_code !==
      'fixture_authority_grant_effect_satisfied' ||
    runtimeActivationPreflight.omitted_runtime_profile_id_state_entry_count_delta !== 1 ||
    runtimeActivationPreflight.omitted_runtime_profile_id_consumed_authority_grant_count !== 1 ||
    runtimeActivationPreflight.supplied_mismatched_runtime_profile_id_refused !== true ||
    runtimeActivationPreflight.supplied_mismatch_reason_code !==
      'agent_supplied_authority_material' ||
    runtimeActivationPreflight.supplied_mismatch_state_entry_count_delta !== 0 ||
    runtimeActivationPreflight.persistent_runtime_profile_installed !== false ||
    runtimeActivationPreflight.live_records_system_checked !== false ||
    runtimeActivationPreflight.production_records_service_checked !== false ||
    runtimeActivationPreflight.live_mcp_coverage_checked !== false ||
    runtimeActivationPreflight.live_approval_channel_health_checked !== false ||
    runtimeActivationPreflight.external_attestation !== false ||
    runtimeActivationPreflight.sovereign_recognition !== false ||
    runtimeActivationPreflight.store_and_anchor_joint_rollback_refused_while_witness_ahead !== true ||
    runtimeActivationPreflight.store_anchor_and_witness_joint_rollback_detection !== false ||
    runtimeActivationPreflight.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse !== true ||
    runtimeActivationPreflight.atomic_store_anchor_witness_commit !== false ||
    runtimeActivationPreflight.partial_grant_commit_burn_window_named !== true ||
    runtimeActivationPreflight.host_filesystem_path_toctou_closed !== false ||
    runtimeActivationPreflight.fixture_rightful_issuance_path_evidenced !== true ||
    runtimeActivationPreflight.rightful_issuance_proven !== false ||
    runtimeActivationPreflight.portable_rightful_issuance_proven !== false ||
    runtimeActivationPreflight.live_authority_proven !== false ||
    runtimeActivationPreflight.production_rightful_issuance_proven !== false ||
    runtimeActivationPreflight.current_machine_governance_proven !== false ||
    runtimeActivationPreflight.consequence_lifecycle_closed !== false ||
    runtimeActivationPreflight.unrouted_records_paths_checked !== false
  ) {
    throw new Error('Local proof pack protected records runtime activation preflight component failed');
  }
  if (
    !Array.isArray(runtimeActivationPreflight.operator_install_requirements) ||
    runtimeActivationPreflight.operator_install_requirements.length !==
      runtimeActivationPlan.operator_install_requirements.length
  ) {
    throw new Error('Local proof pack runtime activation preflight install requirements drifted');
  }
  for (const requirement of runtimeActivationPlan.operator_install_requirements) {
    if (!runtimeActivationPreflight.operator_install_requirements.includes(requirement)) {
      throw new Error(`Local proof pack runtime activation preflight missing install requirement: ${requirement}`);
    }
  }
  if (
    !Array.isArray(runtimeActivationPreflight.known_open_boundaries) ||
    runtimeActivationPreflight.known_open_boundaries.length !== runtimeActivationPlan.known_open_boundaries.length
  ) {
    throw new Error('Local proof pack runtime activation preflight open boundaries drifted');
  }
  for (const boundary of runtimeActivationPlan.known_open_boundaries) {
    if (!runtimeActivationPreflight.known_open_boundaries.includes(boundary)) {
      throw new Error(`Local proof pack runtime activation preflight missing open boundary: ${boundary}`);
    }
  }
  if (
    !Array.isArray(runtimeActivationPreflight.preflight_non_claims) ||
    runtimeActivationPreflight.preflight_non_claims.length !== RUNTIME_ACTIVATION_PREFLIGHT_NON_CLAIMS.length
  ) {
    throw new Error('Local proof pack runtime activation preflight non-claims drifted');
  }
  for (const claim of RUNTIME_ACTIVATION_PREFLIGHT_NON_CLAIMS) {
    if (!runtimeActivationPreflight.preflight_non_claims.includes(claim)) {
      throw new Error('Local proof pack runtime activation preflight missing non-claim');
    }
  }

  const runtimeLocalActivation = report.components.find((item) =>
    item.component === 'protected_records_runtime_local_activation'
  );
  const runtimeLocalActivationPlan = protectedRecordsRuntimeLocalActivationPlan();
  const runtimeLocalActivationProfile = protectedRecordsRuntimePreflightProfile();
  if (
    !runtimeLocalActivation ||
    runtimeLocalActivation.proof_type !== PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PROOF_TYPE ||
    runtimeLocalActivation.evidence_model !== 'local-disposable-runtime-activation-fixture' ||
    runtimeLocalActivation.live_probing !== false ||
    runtimeLocalActivation.safe_claim_ceiling !== RUNTIME_LOCAL_ACTIVATION_SAFE_CLAIM_CEILING ||
    runtimeLocalActivation.local_activation_command !== runtimeLocalActivationPlan.local_activation_command ||
    runtimeLocalActivation.plan_type !== 'zlar-protected-records-runtime-local-activation-plan-v1' ||
    runtimeLocalActivation.plan_id !== 'protected-records-runtime-local-activation-fixture-plan' ||
    runtimeLocalActivation.plan_sha256 !== runtimeLocalActivationPlanSha256(runtimeLocalActivationPlan) ||
    runtimeLocalActivation.plan_status !== 'sample_local_disposable_only' ||
    runtimeLocalActivation.deployment_posture !== 'local_disposable_activation_only' ||
    runtimeLocalActivation.action_class !== 'records.write' ||
    runtimeLocalActivation.runtime_profile_id !== 'protected-records-disposable-runtime-profile' ||
    runtimeLocalActivation.runtime_profile_source !== 'profiles/protected-records-runtime-fixture.profile.json' ||
    runtimeLocalActivation.runtime_profile_sha256 !== runtimeProfileSha ||
    runtimeLocalActivation.runtime_profile_sha_matches_plan !== true ||
    runtimeLocalActivation.runtime_profile_proof_command !== 'zlar protected-records-runtime-profile-proof' ||
    runtimeLocalActivation.service_command !== 'zlar protected-records-runtime-service --config <launcher-owned-disposable-config>' ||
    runtimeLocalActivation.runtime_local_activation_run_in_proof_pack !== true ||
    runtimeLocalActivation.runtime_profile_proof_run_in_proof_pack !== true ||
    runtimeLocalActivation.runtime_profile_proof_case_count !== protectedRecordsRuntimeProfile.required_cases.length ||
    runtimeLocalActivation.runtime_profile_proof_required_case_count !==
      protectedRecordsRuntimeProfile.required_cases.length ||
    runtimeLocalActivation.runtime_profile_boundary_observation_count !==
      protectedRecordsRuntimeProfile.required_boundary_observations.length ||
    runtimeLocalActivation.runtime_profile_required_boundary_observation_count !==
      protectedRecordsRuntimeProfile.required_boundary_observations.length ||
    runtimeLocalActivation.recognized_write_accepted !== true ||
    runtimeLocalActivation.mutation_authoritative_route !== RECORDS_WRITE_TERMINAL_ROUTE ||
    runtimeLocalActivation.consumed_authority_grant_store !==
      'persistent-single-use-authority-grant-contract-sha256-store' ||
    runtimeLocalActivation.consumption_identity !== 'authority-grant-contract-sha256' ||
    runtimeLocalActivation.signed_payload_replay_identity !== 'verified-signed-payload-sha256' ||
    runtimeLocalActivation.consumed_store_witness !== 'launcher-owned-local-store-hash-witness' ||
    runtimeLocalActivation.consumed_store_write_model !==
      'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness' ||
    runtimeLocalActivation.same_process_signed_payload_replay_refused !== true ||
    runtimeLocalActivation.restart_consumed_authority_grant_refused !== true ||
    runtimeLocalActivation.witness_commit_failed_after_authority_grant_store_commit !== true ||
    runtimeLocalActivation.witness_commit_failure_reason_code !==
      'consumed_store_write_failed_after_grant_commit' ||
    runtimeLocalActivation.store_and_anchor_joint_rollback_refused_against_witness !== true ||
    runtimeLocalActivation.missing_authority_grant_appointment_refused !== true ||
    runtimeLocalActivation.mismatched_authority_grant_appointment_refused !== true ||
    runtimeLocalActivation.revoked_authority_grant_refused !== true ||
    runtimeLocalActivation.expired_authority_grant_refused !== true ||
    runtimeLocalActivation.request_supplied_authority_grant_refused !== true ||
    runtimeLocalActivation.missing_receipt_refused !== true ||
    runtimeLocalActivation.invalid_receipt_refused !== true ||
    runtimeLocalActivation.unknown_issuer_refused !== true ||
    runtimeLocalActivation.retired_issuer_refused !== true ||
    runtimeLocalActivation.missing_issuer_status_refused !== true ||
    runtimeLocalActivation.stale_receipt_refused !== true ||
    runtimeLocalActivation.wrong_policy_refused !== true ||
    runtimeLocalActivation.wrong_domain_refused !== true ||
    runtimeLocalActivation.wrong_tool_refused !== true ||
    runtimeLocalActivation.wrong_runtime_profile_id_refused !== true ||
    runtimeLocalActivation.wrong_audit_event_refused !== true ||
    runtimeLocalActivation.wrong_detail_refused !== true ||
    runtimeLocalActivation.non_boarding_outcome_refused !== true ||
    runtimeLocalActivation.direct_api_without_receipt_refused !== true ||
    runtimeLocalActivation.direct_api_with_receipt_refused !== true ||
    runtimeLocalActivation.agent_supplied_authority_material_refused !== true ||
    runtimeLocalActivation.runtime_profile_identity_authority_source !==
      'launcher-owned-service-config' ||
    runtimeLocalActivation.runtime_profile_identity_request_stream_policy !==
      'runtime_profile_id_may_be_omitted_but_if_supplied_must_match_config' ||
    runtimeLocalActivation.request_runtime_profile_id_required !== false ||
    runtimeLocalActivation.omitted_request_runtime_profile_id_present !== false ||
    runtimeLocalActivation.omitted_runtime_profile_id_uses_launcher_config !== true ||
    runtimeLocalActivation.omitted_runtime_profile_id_reason_code !==
      'fixture_authority_grant_effect_satisfied' ||
    runtimeLocalActivation.omitted_runtime_profile_id_state_entry_count_delta !== 1 ||
    runtimeLocalActivation.omitted_runtime_profile_id_consumed_authority_grant_count !== 1 ||
    runtimeLocalActivation.supplied_mismatched_runtime_profile_id_refused !== true ||
    runtimeLocalActivation.supplied_mismatch_reason_code !==
      'agent_supplied_authority_material' ||
    runtimeLocalActivation.supplied_mismatch_state_entry_count_delta !== 0 ||
    runtimeLocalActivation.local_activation_applied !== true ||
    runtimeLocalActivation.disposable_runtime_config_written !== true ||
    runtimeLocalActivation.persistent_runtime_config_written !== false ||
    runtimeLocalActivation.hook_configuration_written !== false ||
    runtimeLocalActivation.runtime_service_started !== true ||
    runtimeLocalActivation.persistent_runtime_profile_installed !== false ||
    runtimeLocalActivation.latest_profile_selected !== false ||
    runtimeLocalActivation.request_stream_authority_material_accepted !== false ||
    runtimeLocalActivation.live_records_system_checked !== false ||
    runtimeLocalActivation.production_records_service_checked !== false ||
    runtimeLocalActivation.live_mcp_coverage_checked !== false ||
    runtimeLocalActivation.live_approval_channel_health_checked !== false ||
    runtimeLocalActivation.exactly_once_effect_semantics !== false ||
    runtimeLocalActivation.store_and_anchor_joint_rollback_refused_while_witness_ahead !== true ||
    runtimeLocalActivation.store_anchor_and_witness_joint_rollback_detection !== false ||
    runtimeLocalActivation.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse !== true ||
    runtimeLocalActivation.atomic_store_anchor_witness_commit !== false ||
    runtimeLocalActivation.partial_grant_commit_burn_window_named !== true ||
    runtimeLocalActivation.host_filesystem_path_toctou_closed !== false ||
    runtimeLocalActivation.fixture_rightful_issuance_path_evidenced !== true ||
    runtimeLocalActivation.rightful_issuance_proven !== false ||
    runtimeLocalActivation.portable_rightful_issuance_proven !== false ||
    runtimeLocalActivation.live_authority_proven !== false ||
    runtimeLocalActivation.production_rightful_issuance_proven !== false ||
    runtimeLocalActivation.current_machine_governance_proven !== false ||
    runtimeLocalActivation.consequence_lifecycle_closed !== false ||
    runtimeLocalActivation.external_attestation !== false ||
    runtimeLocalActivation.sovereign_recognition !== false ||
    runtimeLocalActivation.unrouted_records_paths_checked !== false
  ) {
    throw new Error('Local proof pack protected records runtime local activation component failed');
  }
  assertExactObjectKeys('Local proof pack runtime local activation active profile selection', runtimeLocalActivation.active_profile_selection, [
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
    runtimeLocalActivation.active_profile_selection.selection_type !==
      RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_TYPE ||
    runtimeLocalActivation.active_profile_selection.selection_scope !==
      RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_SCOPE ||
    runtimeLocalActivation.active_profile_selection.selected !== true ||
    runtimeLocalActivation.active_profile_selection.selection_source !==
      'explicit-plan-and-profile-inputs' ||
    runtimeLocalActivation.active_profile_selection.action_class !== 'records.write' ||
    runtimeLocalActivation.active_profile_selection.route !== RECORDS_WRITE_TERMINAL_ROUTE ||
    runtimeLocalActivation.active_profile_selection.downstream_boundary !==
      RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY ||
    runtimeLocalActivation.active_profile_selection.plan_sha256 !==
      runtimeLocalActivationPlanSha256(runtimeLocalActivationPlan) ||
    runtimeLocalActivation.active_profile_selection.profile_id !==
      runtimeLocalActivationProfile.profile_id ||
    runtimeLocalActivation.active_profile_selection.runtime_profile_id !==
      runtimeLocalActivationProfile.runtime_profile_id ||
    runtimeLocalActivation.active_profile_selection.profile_status_before_selection !==
      'sample_not_active' ||
    runtimeLocalActivation.active_profile_selection.runtime_profile_sha256 !== runtimeProfileSha ||
    runtimeLocalActivation.active_profile_selection.runtime_profile_sha_matches_plan !== true ||
    runtimeLocalActivation.active_profile_selection.selects_latest_profile !== false ||
    runtimeLocalActivation.active_profile_selection.persistent_runtime_profile_installed !== false ||
    runtimeLocalActivation.active_profile_selection.live_runtime_profile_checked !== false ||
    runtimeLocalActivation.active_profile_selection.hook_configuration_written !== false
  ) {
    throw new Error('Local proof pack runtime local activation active profile selection drifted');
  }
  if (
    !Array.isArray(runtimeLocalActivation.operator_requirements) ||
    runtimeLocalActivation.operator_requirements.length !==
      runtimeLocalActivationPlan.operator_requirements.length
  ) {
    throw new Error('Local proof pack runtime local activation operator requirements drifted');
  }
  for (const requirement of runtimeLocalActivationPlan.operator_requirements) {
    if (!runtimeLocalActivation.operator_requirements.includes(requirement)) {
      throw new Error(`Local proof pack runtime local activation missing operator requirement: ${requirement}`);
    }
  }
  if (
    !Array.isArray(runtimeLocalActivation.known_open_boundaries) ||
    runtimeLocalActivation.known_open_boundaries.length !==
      runtimeLocalActivationPlan.known_open_boundaries.length
  ) {
    throw new Error('Local proof pack runtime local activation open boundaries drifted');
  }
  for (const boundary of runtimeLocalActivationPlan.known_open_boundaries) {
    if (!runtimeLocalActivation.known_open_boundaries.includes(boundary)) {
      throw new Error(`Local proof pack runtime local activation missing open boundary: ${boundary}`);
    }
  }
  if (
    !Array.isArray(runtimeLocalActivation.local_activation_non_claims) ||
    runtimeLocalActivation.local_activation_non_claims.length !== RUNTIME_LOCAL_ACTIVATION_NON_CLAIMS.length
  ) {
    throw new Error('Local proof pack runtime local activation non-claims drifted');
  }
  for (const claim of RUNTIME_LOCAL_ACTIVATION_NON_CLAIMS) {
    if (!runtimeLocalActivation.local_activation_non_claims.includes(claim)) {
      throw new Error('Local proof pack runtime local activation missing non-claim');
    }
  }

  const runtimeProfileInstallation = report.components.find((item) =>
    item.component === 'protected_records_runtime_profile_installation'
  );
  const runtimeProfileInstallationPlan = protectedRecordsRuntimeProfileInstallationPlan();
  if (
    !runtimeProfileInstallation ||
    runtimeProfileInstallation.proof_type !== PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_PROOF_TYPE ||
    runtimeProfileInstallation.evidence_model !== 'local-disposable-runtime-profile-installation-fixture' ||
    runtimeProfileInstallation.live_probing !== false ||
    runtimeProfileInstallation.safe_claim_ceiling !== RUNTIME_PROFILE_INSTALLATION_SAFE_CLAIM_CEILING ||
    runtimeProfileInstallation.installation_command !== runtimeProfileInstallationPlan.installation_command ||
    runtimeProfileInstallation.plan_type !== 'zlar-protected-records-runtime-profile-installation-plan-v1' ||
    runtimeProfileInstallation.plan_id !== 'protected-records-runtime-profile-installation-fixture-plan' ||
    runtimeProfileInstallation.plan_sha256 !==
      runtimeProfileInstallationPlanSha256(runtimeProfileInstallationPlan) ||
    runtimeProfileInstallation.plan_status !== 'sample_local_disposable_only' ||
    runtimeProfileInstallation.deployment_posture !== 'local_disposable_profile_installation_only' ||
    runtimeProfileInstallation.action_class !== 'records.write' ||
    runtimeProfileInstallation.runtime_profile_id !== 'protected-records-disposable-runtime-profile' ||
    runtimeProfileInstallation.runtime_profile_source !== 'profiles/protected-records-runtime-fixture.profile.json' ||
    runtimeProfileInstallation.runtime_profile_sha256 !== runtimeProfileSha ||
    runtimeProfileInstallation.runtime_profile_sha_matches_plan !== true ||
    runtimeProfileInstallation.runtime_profile_proof_command !== 'zlar protected-records-runtime-profile-proof' ||
    runtimeProfileInstallation.service_command !== 'zlar protected-records-runtime-service --config <launcher-owned-disposable-config>' ||
    runtimeProfileInstallation.runtime_profile_installation_run_in_proof_pack !== true ||
    runtimeProfileInstallation.runtime_profile_proof_run_in_proof_pack !== true ||
    runtimeProfileInstallation.runtime_profile_proof_case_count !==
      protectedRecordsRuntimeProfile.required_cases.length ||
    runtimeProfileInstallation.runtime_profile_proof_required_case_count !==
      protectedRecordsRuntimeProfile.required_cases.length ||
    runtimeProfileInstallation.runtime_profile_boundary_observation_count !==
      protectedRecordsRuntimeProfile.required_boundary_observations.length ||
    runtimeProfileInstallation.runtime_profile_required_boundary_observation_count !==
      protectedRecordsRuntimeProfile.required_boundary_observations.length ||
    runtimeProfileInstallation.recognized_write_accepted !== true ||
    runtimeProfileInstallation.mutation_authoritative_route !== RECORDS_WRITE_TERMINAL_ROUTE ||
    runtimeProfileInstallation.consumed_authority_grant_store !==
      'persistent-single-use-authority-grant-contract-sha256-store' ||
    runtimeProfileInstallation.consumption_identity !== 'authority-grant-contract-sha256' ||
    runtimeProfileInstallation.signed_payload_replay_identity !== 'verified-signed-payload-sha256' ||
    runtimeProfileInstallation.consumed_store_witness !== 'launcher-owned-local-store-hash-witness' ||
    runtimeProfileInstallation.consumed_store_write_model !==
      'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness' ||
    runtimeProfileInstallation.same_process_signed_payload_replay_refused !== true ||
    runtimeProfileInstallation.restart_consumed_authority_grant_refused !== true ||
    runtimeProfileInstallation.missing_authority_grant_appointment_refused !== true ||
    runtimeProfileInstallation.mismatched_authority_grant_appointment_refused !== true ||
    runtimeProfileInstallation.revoked_authority_grant_refused !== true ||
    runtimeProfileInstallation.expired_authority_grant_refused !== true ||
    runtimeProfileInstallation.request_supplied_authority_grant_refused !== true ||
    runtimeProfileInstallation.missing_receipt_refused !== true ||
    runtimeProfileInstallation.invalid_receipt_refused !== true ||
    runtimeProfileInstallation.unknown_issuer_refused !== true ||
    runtimeProfileInstallation.retired_issuer_refused !== true ||
    runtimeProfileInstallation.missing_issuer_status_refused !== true ||
    runtimeProfileInstallation.stale_receipt_refused !== true ||
    runtimeProfileInstallation.wrong_policy_refused !== true ||
    runtimeProfileInstallation.wrong_domain_refused !== true ||
    runtimeProfileInstallation.wrong_tool_refused !== true ||
    runtimeProfileInstallation.wrong_runtime_profile_id_refused !== true ||
    runtimeProfileInstallation.wrong_audit_event_refused !== true ||
    runtimeProfileInstallation.wrong_detail_refused !== true ||
    runtimeProfileInstallation.non_boarding_outcome_refused !== true ||
    runtimeProfileInstallation.direct_api_without_receipt_refused !== true ||
    runtimeProfileInstallation.direct_api_with_receipt_refused !== true ||
    runtimeProfileInstallation.agent_supplied_authority_material_refused !== true ||
    runtimeProfileInstallation.runtime_profile_identity_authority_source !==
      'launcher-owned-service-config' ||
    runtimeProfileInstallation.runtime_profile_identity_request_stream_policy !==
      'runtime_profile_id_may_be_omitted_but_if_supplied_must_match_config' ||
    runtimeProfileInstallation.request_runtime_profile_id_required !== false ||
    runtimeProfileInstallation.omitted_request_runtime_profile_id_present !== false ||
    runtimeProfileInstallation.omitted_runtime_profile_id_uses_launcher_config !== true ||
    runtimeProfileInstallation.omitted_runtime_profile_id_reason_code !==
      'fixture_authority_grant_effect_satisfied' ||
    runtimeProfileInstallation.omitted_runtime_profile_id_state_entry_count_delta !== 1 ||
    runtimeProfileInstallation.omitted_runtime_profile_id_consumed_authority_grant_count !== 1 ||
    runtimeProfileInstallation.supplied_mismatched_runtime_profile_id_refused !== true ||
    runtimeProfileInstallation.supplied_mismatch_reason_code !==
      'agent_supplied_authority_material' ||
    runtimeProfileInstallation.supplied_mismatch_state_entry_count_delta !== 0 ||
    runtimeProfileInstallation.disposable_profile_installation_applied !== true ||
    runtimeProfileInstallation.local_disposable_install_root_created !== true ||
    runtimeProfileInstallation.profile_copied_to_install_root !== true ||
    runtimeProfileInstallation.active_profile_index_written !== true ||
    runtimeProfileInstallation.profile_selected_from_install_root !== true ||
    runtimeProfileInstallation.disposable_runtime_config_written !== true ||
    runtimeProfileInstallation.persistent_runtime_config_written !== false ||
    runtimeProfileInstallation.hook_configuration_written !== false ||
    runtimeProfileInstallation.user_config_written !== false ||
    runtimeProfileInstallation.machine_config_written !== false ||
    runtimeProfileInstallation.runtime_service_started !== true ||
    runtimeProfileInstallation.persistent_runtime_profile_installed !== false ||
    runtimeProfileInstallation.latest_profile_selected !== false ||
    runtimeProfileInstallation.request_stream_authority_material_accepted !== false ||
    runtimeProfileInstallation.live_runtime_profile_checked !== false ||
    runtimeProfileInstallation.live_records_system_checked !== false ||
    runtimeProfileInstallation.production_records_service_checked !== false ||
    runtimeProfileInstallation.live_mcp_coverage_checked !== false ||
    runtimeProfileInstallation.live_approval_channel_health_checked !== false ||
    runtimeProfileInstallation.exactly_once_effect_semantics !== false ||
    runtimeProfileInstallation.store_anchor_and_witness_joint_rollback_detection !== false ||
    runtimeProfileInstallation.atomic_store_anchor_witness_commit !== false ||
    runtimeProfileInstallation.partial_grant_commit_burn_window_named !== true ||
    runtimeProfileInstallation.host_filesystem_path_toctou_closed !== false ||
    runtimeProfileInstallation.fixture_rightful_issuance_path_evidenced !== true ||
    runtimeProfileInstallation.rightful_issuance_proven !== false ||
    runtimeProfileInstallation.portable_rightful_issuance_proven !== false ||
    runtimeProfileInstallation.live_authority_proven !== false ||
    runtimeProfileInstallation.production_rightful_issuance_proven !== false ||
    runtimeProfileInstallation.current_machine_governance_proven !== false ||
    runtimeProfileInstallation.consequence_lifecycle_closed !== false ||
    runtimeProfileInstallation.external_attestation !== false ||
    runtimeProfileInstallation.sovereign_recognition !== false ||
    runtimeProfileInstallation.unrouted_records_paths_checked !== false
  ) {
    throw new Error('Local proof pack protected records runtime profile installation component failed');
  }
  assertExactObjectKeys(
    'Local proof pack runtime profile installation disposable profile selection',
    runtimeProfileInstallation.disposable_profile_selection,
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
  const disposableSelection = runtimeProfileInstallation.disposable_profile_selection;
  if (
    disposableSelection.install_root_kind !== 'launcher-owned-disposable-proof-root' ||
    disposableSelection.install_root_path_in_report !== null ||
    disposableSelection.installed_profile_path_in_report !==
      '<launcher-owned-disposable-install-root>/profiles/protected-records-disposable-runtime-profile.json' ||
    disposableSelection.active_index_path_in_report !==
      '<launcher-owned-disposable-install-root>/active-runtime-profile.json' ||
    disposableSelection.install_root_created !== true ||
    disposableSelection.profile_copy_written !== true ||
    disposableSelection.active_profile_index_written !== true ||
    disposableSelection.profile_selected_from_install_root !== true ||
    disposableSelection.selected_by_explicit_id_and_sha !== true ||
    disposableSelection.selects_latest_profile !== false ||
    disposableSelection.profile_sha_verified_before_selection !== true ||
    disposableSelection.profile_status_before_installation !== 'sample_not_active' ||
    disposableSelection.installed_profile_status !== 'installed_in_disposable_proof_root' ||
    disposableSelection.selected_profile_id !== 'protected-records-runtime-fixture-profile' ||
    disposableSelection.selected_runtime_profile_id !== 'protected-records-disposable-runtime-profile' ||
    disposableSelection.selected_profile_sha256 !== runtimeProfileSha
  ) {
    throw new Error('Local proof pack runtime profile installation disposable profile selection drifted');
  }
  assertExactObjectKeys(
    'Local proof pack runtime profile installation request authority guard',
    runtimeProfileInstallation.request_authority_guard_summary,
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
  const installationGuard = runtimeProfileInstallation.request_authority_guard_summary;
  if (
    installationGuard.installed_profile_state_refused !== true ||
    installationGuard.runtime_config_refused !== true ||
    installationGuard.runtime_profile_refused !== true ||
    installationGuard.recognition_rule_refused !== true ||
    installationGuard.authority_grant_refused !== true ||
    installationGuard.all_refused_before_mutation !== true ||
    installationGuard.state_entry_count_delta_total !== 0 ||
    !Array.isArray(installationGuard.reason_codes) ||
    installationGuard.reason_codes.length !== 5 ||
    installationGuard.reason_codes.some((item) => item !== 'agent_supplied_authority_material')
  ) {
    throw new Error('Local proof pack runtime profile installation request authority guard drifted');
  }
  if (
    !Array.isArray(runtimeProfileInstallation.operator_requirements) ||
    runtimeProfileInstallation.operator_requirements.length !==
      REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPERATOR_REQUIREMENTS.length
  ) {
    throw new Error('Local proof pack runtime profile installation operator requirements drifted');
  }
  for (const requirement of REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPERATOR_REQUIREMENTS) {
    if (!runtimeProfileInstallation.operator_requirements.includes(requirement)) {
      throw new Error(`Local proof pack runtime profile installation missing operator requirement: ${requirement}`);
    }
  }
  if (
    !Array.isArray(runtimeProfileInstallation.known_open_boundaries) ||
    runtimeProfileInstallation.known_open_boundaries.length !==
      REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPEN_BOUNDARIES.length
  ) {
    throw new Error('Local proof pack runtime profile installation open boundaries drifted');
  }
  for (const boundary of REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPEN_BOUNDARIES) {
    if (!runtimeProfileInstallation.known_open_boundaries.includes(boundary)) {
      throw new Error(`Local proof pack runtime profile installation missing open boundary: ${boundary}`);
    }
  }
  if (
    !Array.isArray(runtimeProfileInstallation.profile_installation_non_claims) ||
    runtimeProfileInstallation.profile_installation_non_claims.length !==
      RUNTIME_PROFILE_INSTALLATION_NON_CLAIMS.length
  ) {
    throw new Error('Local proof pack runtime profile installation non-claims drifted');
  }
  for (const claim of RUNTIME_PROFILE_INSTALLATION_NON_CLAIMS) {
    if (!runtimeProfileInstallation.profile_installation_non_claims.includes(claim)) {
      throw new Error('Local proof pack runtime profile installation missing non-claim');
    }
  }

  const claudeHookReplay = report.components.find((item) =>
    item.component === 'claude_code_hook_contract_replay'
  );
  assertExactObjectKeys(
    'Local proof pack Claude Code hook-contract replay component',
    claudeHookReplay,
    CLAUDE_CODE_HOOK_CONTRACT_REPLAY_COMPONENT_KEYS
  );
  assertExactObjectKeys(
    'Local proof pack Claude Code hook-contract replay permission decisions',
    claudeHookReplay.permission_decisions_observed,
    ['allow', 'deny']
  );
  assertClaudeCodeHookContractReplayCaseEvidence(claudeHookReplay.case_evidence);
  const claudeHookReplayCaseEvidenceSha256 = sha256Hex(canonicalize(claudeHookReplay.case_evidence));
  if (
    claudeHookReplay.proof_type !== CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_TYPE ||
    claudeHookReplay.command !== 'zlar claude-code-hook-contract-replay-proof' ||
    claudeHookReplay.evidence_model !== CLAUDE_CODE_HOOK_CONTRACT_REPLAY_EVIDENCE_MODEL ||
    claudeHookReplay.live_probing !== false ||
    claudeHookReplay.hook_replay_contract_sha256 !== claudeCodeHookContractReplayContractSha256() ||
    claudeHookReplay.source_state_boundary !== CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY ||
    claudeHookReplay.adapter_source !== 'repo' ||
    claudeHookReplay.adapter_path_claimed !== 'repo:adapters/claude-code/hook.sh' ||
    claudeHookReplay.adapter_sha256 !== claudeCodeHookContractReplayRepoAdapterSha256() ||
    claudeHookReplay.case_evidence_hash_scope !== CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASE_EVIDENCE_HASH_SCOPE ||
    claudeHookReplay.case_evidence_sha256 !== claudeHookReplayCaseEvidenceSha256 ||
    claudeHookReplay.required_case_count !== REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES.length ||
    claudeHookReplay.all_required_cases_present !== true ||
    claudeHookReplay.permission_decisions_observed.allow !== true ||
    claudeHookReplay.permission_decisions_observed.deny !== true ||
    claudeHookReplay.denied_effect_not_executed !== true ||
    claudeHookReplay.tool_input_not_executed !== true ||
    claudeHookReplay.missing_gate_failed_closed !== true ||
    claudeHookReplay.blank_gate_response_failed_closed !== true ||
    claudeHookReplay.malformed_output_refused !== true ||
    claudeHookReplay.non_pretooluse_payload_denied_by_fixture_gate !== true ||
    claudeHookReplay.live_claude_invoked !== false ||
    claudeHookReplay.live_claude_app_passage_proven !== false ||
    claudeHookReplay.app_originated_hook_crossing_proven !== false ||
    claudeHookReplay.live_receipt_emission_proven !== false ||
    claudeHookReplay.current_machine_governance_proven !== false ||
    claudeHookReplay.production_downstream_recognition_proven !== false ||
    claudeHookReplay.all_surface_governance_proven !== false ||
    claudeHookReplay.side_door_closure_proven !== false ||
    claudeHookReplay.supporting_local_boarding_proof_passed !== true ||
    claudeHookReplay.supporting_local_boarding_proof_type !== 'zlar-protected-records-local-boarding-proof-v1' ||
    claudeHookReplay.supporting_local_boarding_v1_receipt_identity_verified !== true ||
    claudeHookReplay.supporting_local_boarding_consequence_absent_on_every_refusal !== true ||
    claudeHookReplay.supporting_local_boarding_consequence_present_exactly_once_on_acceptance !== true ||
    claudeHookReplay.supporting_local_boarding_legacy_v0_recognized_boarding_identity !== false ||
    claudeHookReplay.safe_claim_ceiling !== CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SAFE_CLAIM_CEILING
  ) {
    throw new Error('Local proof pack Claude Code hook-contract replay component failed');
  }
  assertExactStringArray(
    'Local proof pack Claude Code hook-contract replay required cases',
    claudeHookReplay.required_cases,
    REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES.map((item) => item.case_id)
  );
  assertExactStringArray(
    'Local proof pack Claude Code hook-contract replay non-claims',
    claudeHookReplay.non_claims,
    CLAUDE_CODE_HOOK_CONTRACT_REPLAY_NON_CLAIMS
  );
  assertExactStringArray(
    'Local proof pack Claude Code hook-contract replay side doors',
    claudeHookReplay.side_doors,
    REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SIDE_DOORS
  );

  assertExactStringArray(
    'Local proof pack non-claims',
    report.non_claims,
    allowHistoricalCoverageComponent ? HISTORICAL_NON_CLAIMS : NON_CLAIMS
  );
  assertNoUnsafeLocalProofPackText(JSON.stringify(report));
  return true;
}

function artifactBody(report) {
  return {
    artifact_type: LOCAL_PROOF_PACK_ARTIFACT_TYPE,
    canonicalization: LOCAL_PROOF_PACK_ARTIFACT_CANONICALIZATION,
    claim_binding: buildLocalProofPackArtifactClaimBinding(report),
    component_manifest: buildLocalProofPackArtifactComponentManifest(report),
    component_manifest_hash_scope: LOCAL_PROOF_PACK_ARTIFACT_COMPONENT_MANIFEST_HASH_SCOPE,
    generator: 'zlar local-proof-pack --artifact',
    hash_scope: 'canonical artifact body without integrity',
    payload: report,
  };
}

export function buildLocalProofPackArtifact(report) {
  if (report === undefined) {
    throw new Error('local_proof_pack_default_artifact_generation_retired');
  }
  assertLocalProofPack(report);
  const body = artifactBody(report);
  const artifact = {
    ...body,
    integrity: {
      algorithm: 'SHA-256',
      body_sha256: sha256Hex(canonicalize(body)),
    },
  };
  assertLocalProofPackArtifact(artifact);
  return artifact;
}

function assertLocalProofPackArtifactComponentManifest(artifact) {
  if (!Array.isArray(artifact.component_manifest)) {
    throw new Error('Local proof pack artifact component manifest must be an array');
  }
  if (artifact.component_manifest.length !== artifact.payload.components.length) {
    throw new Error('Local proof pack artifact component manifest count drifted');
  }
  for (const item of artifact.component_manifest) {
    assertExactObjectKeys(
      'Local proof pack artifact component manifest item',
      item,
      LOCAL_PROOF_PACK_ARTIFACT_COMPONENT_MANIFEST_ITEM_KEYS
    );
    assertHexSha256(
      `Local proof pack artifact component manifest ${item.component}.component_sha256`,
      item.component_sha256
    );
  }
  const expectedManifest = buildLocalProofPackArtifactComponentManifest(artifact.payload);
  if (canonicalize(artifact.component_manifest) !== canonicalize(expectedManifest)) {
    throw new Error('Local proof pack artifact component manifest drifted');
  }
  return true;
}

function assertLocalProofPackArtifactClaimBinding(artifact) {
  assertExactObjectKeys(
    'Local proof pack artifact claim binding',
    artifact.claim_binding,
    LOCAL_PROOF_PACK_ARTIFACT_CLAIM_BINDING_KEYS
  );
  assertHexSha256(
    'Local proof pack artifact claim binding safe_claim_ceiling_sha256',
    artifact.claim_binding.safe_claim_ceiling_sha256
  );
  assertHexSha256(
    'Local proof pack artifact claim binding non_claims_sha256',
    artifact.claim_binding.non_claims_sha256
  );
  const expectedBinding = buildLocalProofPackArtifactClaimBinding(artifact.payload);
  if (canonicalize(artifact.claim_binding) !== canonicalize(expectedBinding)) {
    throw new Error('Local proof pack artifact claim binding drifted');
  }
  return true;
}

export function assertLocalProofPackArtifact(artifact) {
  if (!artifact || artifact.artifact_type !== LOCAL_PROOF_PACK_ARTIFACT_TYPE) {
    throw new Error('Local proof pack artifact has the wrong artifact type');
  }
  assertExactObjectKeys('Local proof pack artifact', artifact, [
    'artifact_type',
    'canonicalization',
    'claim_binding',
    'component_manifest',
    'component_manifest_hash_scope',
    'generator',
    'hash_scope',
    'integrity',
    'payload',
  ]);
  if (artifact.canonicalization !== LOCAL_PROOF_PACK_ARTIFACT_CANONICALIZATION) {
    throw new Error('Local proof pack artifact canonicalization drifted');
  }
  if (artifact.generator !== 'zlar local-proof-pack --artifact') {
    throw new Error('Local proof pack artifact generator drifted');
  }
  if (artifact.hash_scope !== 'canonical artifact body without integrity') {
    throw new Error('Local proof pack artifact hash scope drifted');
  }
  if (
    artifact.component_manifest_hash_scope !==
    LOCAL_PROOF_PACK_ARTIFACT_COMPONENT_MANIFEST_HASH_SCOPE
  ) {
    throw new Error('Local proof pack artifact component manifest hash scope drifted');
  }
  if (!artifact.integrity || artifact.integrity.algorithm !== 'SHA-256') {
    throw new Error('Local proof pack artifact integrity algorithm drifted');
  }
  assertExactObjectKeys('Local proof pack artifact integrity', artifact.integrity, [
    'algorithm',
    'body_sha256',
  ]);
  if (!/^[a-f0-9]{64}$/.test(artifact.integrity.body_sha256 || '')) {
    throw new Error('Local proof pack artifact SHA-256 is malformed');
  }
  const { integrity, ...body } = artifact;
  const expectedHash = sha256Hex(canonicalize(body));
  if (artifact.integrity.body_sha256 !== expectedHash) {
    throw new Error('Local proof pack artifact SHA-256 mismatch');
  }
  const allowHistoricalCoverageComponent =
    artifact.integrity.body_sha256 ===
    LOCAL_PROOF_PACK_HISTORICAL_SAMPLE_ARTIFACT_BODY_SHA256;
  assertLocalProofPackReport(artifact.payload, {
    allowHistoricalCoverageComponent,
  });
  assertLocalProofPackArtifactComponentManifest(artifact);
  assertLocalProofPackArtifactClaimBinding(artifact);
  assertNoUnsafeLocalProofPackText(JSON.stringify(artifact));
  return true;
}

export function writeLocalProofPackArtifact(artifact, outputPath) {
  assertLocalProofPackArtifact(artifact);
  if (!outputPath || outputPath === '-') {
    throw new Error('Local proof pack artifact output path is required');
  }
  mkdirSync(dirname(outputPath), { recursive: true });
  const output = `${JSON.stringify(artifact, null, 2)}\n`;
  assertNoUnsafeLocalProofPackText(output);
  writeFileSync(outputPath, output, { mode: 0o600 });
  return artifact.integrity.body_sha256;
}

export function parseLocalProofPackArtifactText(text) {
  assertNoUnsafeLocalProofPackText(text);
  let artifact;
  try {
    artifact = JSON.parse(text);
  } catch {
    throw new Error('Local proof pack artifact input is not valid JSON');
  }
  assertLocalProofPackArtifact(artifact);
  return artifact;
}

function matchExpectedLocalProofPackArtifactSha256(expectedSha256, actualSha256) {
  if (expectedSha256 === null || expectedSha256 === undefined || expectedSha256 === '') {
    return { expected: null, supplied: false, matched: false };
  }
  if (!/^[a-f0-9]{64}$/.test(expectedSha256)) {
    throw new Error(
      'Local proof pack artifact expected identity must be a 64-character lowercase SHA-256 hex digest'
    );
  }
  if (expectedSha256 !== actualSha256) {
    throw new Error(
      'Local proof pack artifact SHA-256 does not match required --require-sha value'
    );
  }
  return { expected: expectedSha256, supplied: true, matched: true };
}

export function verifyLocalProofPackArtifact(
  artifact,
  { expectedArtifactBodySha256 = null } = {}
) {
  assertLocalProofPackArtifact(artifact);
  const artifactIdentity = matchExpectedLocalProofPackArtifactSha256(
    expectedArtifactBodySha256,
    artifact.integrity.body_sha256
  );
  const identityBoundProjection = artifactIdentity.matched;
  const authorityGrantStatus = protectedRecordsFixtureAuthorityGrantStatus(
    PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256
  );
  const authorityGrantStatusReason =
    protectedRecordsFixtureAuthorityGrantEffectStatusReason(
      PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256
    );
  const coverage = artifact.payload.components.find((item) =>
    item.component === 'governed_surface_coverage_map'
  );
  const historicalCoverageComponent =
    isHistoricalLocalProofPackCoverageComponent(coverage);
  const artifactBoundAuthorityGrantContractSha256 =
    typeof coverage.authority_grant_contract_sha256 === 'string'
      ? coverage.authority_grant_contract_sha256
      : null;
  const authorityGrantContractIdentityBoundByArtifact =
    artifactBoundAuthorityGrantContractSha256 ===
    PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256;
  const terminalIdentityProjectionAllowed =
    identityBoundProjection && !historicalCoverageComponent;
  const fixtureRightfulProjectionAllowed =
    terminalIdentityProjectionAllowed &&
    authorityGrantContractIdentityBoundByArtifact &&
    authorityGrantStatus.fresh_fixture_rightful_projection_allowed === true &&
    authorityGrantStatus.repeated_use_provenance_valid === true;
  const keyState = artifact.payload.components.find((item) =>
    item.component === 'key_state_report'
  );
  const receiptVerifierBoundary = artifact.payload.components.find((item) =>
    item.component === 'receipt_verifier_boundary'
  );
  const trustedIssuerRegistryRecognition = artifact.payload.components.find((item) =>
    item.component === 'trusted_issuer_registry_recognition'
  );
  const downstream = artifact.payload.components.find((item) =>
    item.component === 'downstream_refusal_proof'
  );
  const humanAuthorization = artifact.payload.components.find((item) =>
    item.component === 'human_authorization_proof'
  );
  const service = artifact.payload.components.find((item) =>
    item.component === 'protected_records_downstream_service'
  );
  const runtimeLocalActivation = artifact.payload.components.find((item) =>
    item.component === 'protected_records_runtime_local_activation'
  );
  const runtimeProfileInstallation = artifact.payload.components.find((item) =>
    item.component === 'protected_records_runtime_profile_installation'
  );
  const claudeHookReplay = artifact.payload.components.find((item) =>
    item.component === 'claude_code_hook_contract_replay'
  );
  const coverageSummary = {
    summary_type: 'zlar-local-proof-pack-coverage-verification-summary-v1',
    component: coverage.component,
    embedded_component_structurally_valid: true,
    embedded_coverage_schema: historicalCoverageComponent
      ? 'historical-pre-exhaustion-coverage-component-v1'
      : 'static-exhaustion-aware-coverage-component-v1',
    embedded_coverage_counts_historical: historicalCoverageComponent,
    current_coverage_counts_claimed: false,
    coverage_snapshot_posture: historicalCoverageComponent
      ? 'historical-pre-exhaustion-6-of-6-not-current'
      : 'embedded-static-4-of-6-without-current-checkout-freshness-proof',
    report_type: coverage.report_type,
    evidence_model: coverage.evidence_model,
    live_probing: coverage.live_probing,
    governed_lanes: coverage.governed_lanes,
    counted_lanes: coverage.counted_lanes,
    authority_grant_contract_sha256:
      authorityGrantStatus.authority_grant_contract_sha256,
    embedded_authority_grant_contract_sha256:
      artifactBoundAuthorityGrantContractSha256,
    authority_grant_contract_identity_bound_by_artifact:
      authorityGrantContractIdentityBoundByArtifact,
    authority_grant_status: authorityGrantStatus.status,
    authority_grant_fresh_effect_allowed:
      authorityGrantStatus.fresh_effect_allowed,
    authority_grant_repeated_use_provenance_valid:
      authorityGrantStatus.repeated_use_provenance_valid,
    authority_grant_status_allows_fixture_rightful_projection:
      authorityGrantStatus.fresh_fixture_rightful_projection_allowed === true &&
      authorityGrantStatus.repeated_use_provenance_valid === true,
    fixture_rightful_issuance_projection_allowed:
      fixtureRightfulProjectionAllowed,
    authority_grant_status_reason_code:
      authorityGrantStatusReason?.code || null,
    terminal_claim_projection_requires_expected_local_proof_pack_sha256: true,
    terminal_claim_projection_allowed: terminalIdentityProjectionAllowed,
    terminal_artifact_body_sha256:
      coverage.terminal_artifact_body_sha256 || null,
    terminal_artifact_expected_body_sha256:
      coverage.terminal_artifact_expected_body_sha256 || null,
    terminal_artifact_identity_sha256_matched:
      terminalIdentityProjectionAllowed &&
      coverage.terminal_artifact_identity_sha256_matched === true,
    terminal_outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256:
      terminalIdentityProjectionAllowed &&
      coverage
        .terminal_outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256 ===
        true,
    terminal_recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256:
      terminalIdentityProjectionAllowed &&
      coverage
        .terminal_recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256 ===
        true,
    terminal_trusted_issuer_registry_signature_valid:
      terminalIdentityProjectionAllowed &&
      coverage.terminal_trusted_issuer_registry_signature_valid === true,
    terminal_fixture_rightful_issuance_path_evidenced:
      fixtureRightfulProjectionAllowed &&
      coverage.terminal_fixture_rightful_issuance_path_evidenced === true,
    terminal_source_freshness_proven: false,
    rightful_issuance_proven: false,
    portable_rightful_issuance_proven: false,
    live_authority_proven: false,
    production_rightful_issuance_proven: false,
    current_machine_governance_proven: false,
    consequence_lifecycle_closed: false,
    claim_boundary: historicalCoverageComponent
      ? 'the exact committed artifact preserves a historical pre-exhaustion 6-of-6 coverage snapshot only; it does not state current coverage, does not embed terminal or authority-grant identity-binding fields, and can never project fixture-rightful issuance under this schema'
      : identityBoundProjection
        ? 'caller-pinned local proof-pack identity permits the embedded exact-terminal identity, source, signature, boarding, and refusal projection; fixture-rightful projection remains false because this schema does not bind an exact authority-grant contract SHA, independent of any later grant status'
      : 'structural local proof-pack artifact verification only; terminal identity, source, signature, and fixture-rightful fields are withheld until the caller supplies the matching expected local proof-pack SHA-256; no fresh run is claimed',
  };
  const serviceProfilePreflight = {
    summary_type: 'zlar-local-proof-pack-service-profile-preflight-verification-summary-v1',
    component: service.component,
    run_in_proof_pack: service.service_profile_preflight_run_in_proof_pack,
    preflight_type: service.service_profile_preflight_type,
    evidence_model: service.service_profile_preflight_evidence_model,
    live_probing: service.service_profile_preflight_live_probing,
    case_count: service.service_profile_preflight_case_count,
    required_case_count: service.service_profile_preflight_required_case_count,
    case_summaries: service.service_profile_preflight_case_summaries.map((item) => ({
      case_id: item.case_id,
      process_invocation: item.process_invocation,
      service_write_accepted: item.service_write_accepted,
      reason_code: item.reason_code,
      state_entry_count_delta: item.state_entry_count_delta,
      direct_api_attempted: item.direct_api_attempted,
    })),
    launcher_owned_config_required:
      service.service_profile_preflight_launcher_owned_config_required,
    request_stream_authority_material_allowed:
      service.service_profile_preflight_request_stream_authority_material_allowed,
    request_stream_authority_material_refused:
      service.service_profile_preflight_request_stream_authority_material_refused,
    request_stream_authority_material_reason:
      service.service_profile_preflight_request_stream_authority_material_reason,
    request_stream_authority_material_state_delta:
      service.service_profile_preflight_request_stream_authority_material_state_delta,
    request_stream_forbidden_fields_refused:
      service.service_profile_preflight_request_stream_forbidden_fields_refused,
    wrong_policy_refused:
      service.service_profile_preflight_wrong_policy_refused,
    wrong_policy_reason:
      service.service_profile_preflight_wrong_policy_reason,
    wrong_policy_state_delta:
      service.service_profile_preflight_wrong_policy_state_delta,
    direct_api_without_receipt_refused:
      service.service_profile_preflight_direct_api_without_receipt_refused,
    direct_api_with_receipt_refused:
      service.service_profile_preflight_direct_api_with_receipt_refused,
    live_profile_installed: service.service_profile_preflight_live_profile_installed,
    runtime_profile_activation_checked:
      service.service_profile_preflight_runtime_profile_activation_checked,
    live_records_system_checked: service.service_profile_preflight_live_records_system_checked,
    production_records_service_checked:
      service.service_profile_preflight_production_records_service_checked,
    live_mcp_coverage_checked: service.service_profile_preflight_live_mcp_coverage_checked,
    live_approval_channel_health_checked:
      service.service_profile_preflight_live_approval_channel_health_checked,
    external_attestation: service.service_profile_preflight_external_attestation,
    sovereign_recognition: service.service_profile_preflight_sovereign_recognition,
    unrouted_records_paths_checked:
      service.service_profile_preflight_unrouted_records_paths_checked,
    claim_boundary: 'embedded local proof-pack artifact summary only; no fresh preflight run',
  };
  const runtimeLocalActivationSummary = {
    summary_type: 'zlar-local-proof-pack-runtime-local-activation-verification-summary-v1',
    component: runtimeLocalActivation.component,
    run_in_proof_pack: runtimeLocalActivation.runtime_local_activation_run_in_proof_pack,
    proof_type: runtimeLocalActivation.proof_type,
    evidence_model: runtimeLocalActivation.evidence_model,
    live_probing: runtimeLocalActivation.live_probing,
    plan_sha256: runtimeLocalActivation.plan_sha256,
    runtime_profile_sha256: runtimeLocalActivation.runtime_profile_sha256,
    runtime_profile_sha_matches_plan: runtimeLocalActivation.runtime_profile_sha_matches_plan,
    active_profile_selection: { ...runtimeLocalActivation.active_profile_selection },
    runtime_profile_identity_authority_source:
      runtimeLocalActivation.runtime_profile_identity_authority_source,
    runtime_profile_identity_request_stream_policy:
      runtimeLocalActivation.runtime_profile_identity_request_stream_policy,
    request_runtime_profile_id_required:
      runtimeLocalActivation.request_runtime_profile_id_required,
    omitted_request_runtime_profile_id_present:
      runtimeLocalActivation.omitted_request_runtime_profile_id_present,
    omitted_runtime_profile_id_uses_launcher_config:
      runtimeLocalActivation.omitted_runtime_profile_id_uses_launcher_config,
    omitted_runtime_profile_id_reason_code:
      runtimeLocalActivation.omitted_runtime_profile_id_reason_code,
    omitted_runtime_profile_id_state_entry_count_delta:
      runtimeLocalActivation.omitted_runtime_profile_id_state_entry_count_delta,
    omitted_runtime_profile_id_consumed_authority_grant_count:
      runtimeLocalActivation.omitted_runtime_profile_id_consumed_authority_grant_count,
    supplied_mismatched_runtime_profile_id_refused:
      runtimeLocalActivation.supplied_mismatched_runtime_profile_id_refused,
    supplied_mismatch_reason_code:
      runtimeLocalActivation.supplied_mismatch_reason_code,
    supplied_mismatch_state_entry_count_delta:
      runtimeLocalActivation.supplied_mismatch_state_entry_count_delta,
    local_activation_applied: runtimeLocalActivation.local_activation_applied,
    disposable_runtime_config_written:
      runtimeLocalActivation.disposable_runtime_config_written,
    persistent_runtime_config_written:
      runtimeLocalActivation.persistent_runtime_config_written,
    hook_configuration_written: runtimeLocalActivation.hook_configuration_written,
    runtime_service_started: runtimeLocalActivation.runtime_service_started,
    mutation_authoritative_route: runtimeLocalActivation.mutation_authoritative_route,
    consumed_authority_grant_store:
      runtimeLocalActivation.consumed_authority_grant_store,
    consumption_identity: runtimeLocalActivation.consumption_identity,
    signed_payload_replay_identity:
      runtimeLocalActivation.signed_payload_replay_identity,
    consumed_store_witness: runtimeLocalActivation.consumed_store_witness,
    consumed_store_write_model: runtimeLocalActivation.consumed_store_write_model,
    recognized_write_accepted: runtimeLocalActivation.recognized_write_accepted,
    same_process_signed_payload_replay_refused:
      runtimeLocalActivation.same_process_signed_payload_replay_refused,
    restart_consumed_authority_grant_refused:
      runtimeLocalActivation.restart_consumed_authority_grant_refused,
    witness_commit_failed_after_authority_grant_store_commit:
      runtimeLocalActivation.witness_commit_failed_after_authority_grant_store_commit,
    witness_commit_failure_reason_code:
      runtimeLocalActivation.witness_commit_failure_reason_code,
    store_and_anchor_joint_rollback_refused_against_witness:
      runtimeLocalActivation.store_and_anchor_joint_rollback_refused_against_witness,
    missing_authority_grant_appointment_refused:
      runtimeLocalActivation.missing_authority_grant_appointment_refused,
    mismatched_authority_grant_appointment_refused:
      runtimeLocalActivation.mismatched_authority_grant_appointment_refused,
    revoked_authority_grant_refused:
      runtimeLocalActivation.revoked_authority_grant_refused,
    expired_authority_grant_refused:
      runtimeLocalActivation.expired_authority_grant_refused,
    request_supplied_authority_grant_refused:
      runtimeLocalActivation.request_supplied_authority_grant_refused,
    missing_receipt_refused: runtimeLocalActivation.missing_receipt_refused,
    invalid_receipt_refused: runtimeLocalActivation.invalid_receipt_refused,
    unknown_issuer_refused: runtimeLocalActivation.unknown_issuer_refused,
    retired_issuer_refused: runtimeLocalActivation.retired_issuer_refused,
    missing_issuer_status_refused:
      runtimeLocalActivation.missing_issuer_status_refused,
    stale_receipt_refused: runtimeLocalActivation.stale_receipt_refused,
    wrong_policy_refused: runtimeLocalActivation.wrong_policy_refused,
    wrong_domain_refused: runtimeLocalActivation.wrong_domain_refused,
    wrong_tool_refused: runtimeLocalActivation.wrong_tool_refused,
    wrong_runtime_profile_id_refused:
      runtimeLocalActivation.wrong_runtime_profile_id_refused,
    wrong_audit_event_refused: runtimeLocalActivation.wrong_audit_event_refused,
    wrong_detail_refused: runtimeLocalActivation.wrong_detail_refused,
    non_boarding_outcome_refused:
      runtimeLocalActivation.non_boarding_outcome_refused,
    direct_api_with_receipt_refused:
      runtimeLocalActivation.direct_api_with_receipt_refused,
    agent_supplied_authority_material_refused:
      runtimeLocalActivation.agent_supplied_authority_material_refused,
    persistent_runtime_profile_installed:
      runtimeLocalActivation.persistent_runtime_profile_installed,
    live_records_system_checked: runtimeLocalActivation.live_records_system_checked,
    production_records_service_checked:
      runtimeLocalActivation.production_records_service_checked,
    live_mcp_coverage_checked: runtimeLocalActivation.live_mcp_coverage_checked,
    live_approval_channel_health_checked:
      runtimeLocalActivation.live_approval_channel_health_checked,
    exactly_once_effect_semantics:
      runtimeLocalActivation.exactly_once_effect_semantics,
    store_and_anchor_joint_rollback_refused_while_witness_ahead:
      runtimeLocalActivation.store_and_anchor_joint_rollback_refused_while_witness_ahead,
    store_anchor_and_witness_joint_rollback_detection:
      runtimeLocalActivation.store_anchor_and_witness_joint_rollback_detection,
    store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse:
      runtimeLocalActivation.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse,
    atomic_store_anchor_witness_commit:
      runtimeLocalActivation.atomic_store_anchor_witness_commit,
    partial_grant_commit_burn_window_named:
      runtimeLocalActivation.partial_grant_commit_burn_window_named,
    host_filesystem_path_toctou_closed:
      runtimeLocalActivation.host_filesystem_path_toctou_closed,
    historical_embedded_fixture_rightful_issuance_path_evidenced:
      runtimeLocalActivation.fixture_rightful_issuance_path_evidenced === true,
    fixture_rightful_issuance_path_evidenced:
      fixtureRightfulProjectionAllowed &&
      runtimeLocalActivation.fixture_rightful_issuance_path_evidenced,
    rightful_issuance_proven: runtimeLocalActivation.rightful_issuance_proven,
    portable_rightful_issuance_proven:
      runtimeLocalActivation.portable_rightful_issuance_proven,
    live_authority_proven: runtimeLocalActivation.live_authority_proven,
    production_rightful_issuance_proven:
      runtimeLocalActivation.production_rightful_issuance_proven,
    current_machine_governance_proven:
      runtimeLocalActivation.current_machine_governance_proven,
    consequence_lifecycle_closed:
      runtimeLocalActivation.consequence_lifecycle_closed,
    external_attestation: runtimeLocalActivation.external_attestation,
    sovereign_recognition: runtimeLocalActivation.sovereign_recognition,
    unrouted_records_paths_checked: runtimeLocalActivation.unrouted_records_paths_checked,
    claim_boundary: 'embedded local proof-pack runtime-local-activation summary only; no fresh activation run during verification',
  };
  const runtimeProfileInstallationSummary = {
    summary_type: 'zlar-local-proof-pack-runtime-profile-installation-verification-summary-v1',
    component: runtimeProfileInstallation.component,
    run_in_proof_pack: runtimeProfileInstallation.runtime_profile_installation_run_in_proof_pack,
    proof_type: runtimeProfileInstallation.proof_type,
    evidence_model: runtimeProfileInstallation.evidence_model,
    live_probing: runtimeProfileInstallation.live_probing,
    plan_sha256: runtimeProfileInstallation.plan_sha256,
    runtime_profile_sha256: runtimeProfileInstallation.runtime_profile_sha256,
    runtime_profile_sha_matches_plan:
      runtimeProfileInstallation.runtime_profile_sha_matches_plan,
    disposable_profile_selection: {
      ...runtimeProfileInstallation.disposable_profile_selection,
    },
    request_authority_guard_summary: {
      ...runtimeProfileInstallation.request_authority_guard_summary,
    },
    runtime_profile_identity_authority_source:
      runtimeProfileInstallation.runtime_profile_identity_authority_source,
    runtime_profile_identity_request_stream_policy:
      runtimeProfileInstallation.runtime_profile_identity_request_stream_policy,
    request_runtime_profile_id_required:
      runtimeProfileInstallation.request_runtime_profile_id_required,
    omitted_request_runtime_profile_id_present:
      runtimeProfileInstallation.omitted_request_runtime_profile_id_present,
    omitted_runtime_profile_id_uses_launcher_config:
      runtimeProfileInstallation.omitted_runtime_profile_id_uses_launcher_config,
    omitted_runtime_profile_id_reason_code:
      runtimeProfileInstallation.omitted_runtime_profile_id_reason_code,
    omitted_runtime_profile_id_state_entry_count_delta:
      runtimeProfileInstallation.omitted_runtime_profile_id_state_entry_count_delta,
    omitted_runtime_profile_id_consumed_authority_grant_count:
      runtimeProfileInstallation.omitted_runtime_profile_id_consumed_authority_grant_count,
    supplied_mismatched_runtime_profile_id_refused:
      runtimeProfileInstallation.supplied_mismatched_runtime_profile_id_refused,
    supplied_mismatch_reason_code:
      runtimeProfileInstallation.supplied_mismatch_reason_code,
    supplied_mismatch_state_entry_count_delta:
      runtimeProfileInstallation.supplied_mismatch_state_entry_count_delta,
    disposable_profile_installation_applied:
      runtimeProfileInstallation.disposable_profile_installation_applied,
    local_disposable_install_root_created:
      runtimeProfileInstallation.local_disposable_install_root_created,
    profile_copied_to_install_root:
      runtimeProfileInstallation.profile_copied_to_install_root,
    active_profile_index_written:
      runtimeProfileInstallation.active_profile_index_written,
    profile_selected_from_install_root:
      runtimeProfileInstallation.profile_selected_from_install_root,
    disposable_runtime_config_written:
      runtimeProfileInstallation.disposable_runtime_config_written,
    persistent_runtime_config_written:
      runtimeProfileInstallation.persistent_runtime_config_written,
    hook_configuration_written: runtimeProfileInstallation.hook_configuration_written,
    user_config_written: runtimeProfileInstallation.user_config_written,
    machine_config_written: runtimeProfileInstallation.machine_config_written,
    runtime_service_started: runtimeProfileInstallation.runtime_service_started,
    mutation_authoritative_route:
      runtimeProfileInstallation.mutation_authoritative_route,
    consumed_authority_grant_store:
      runtimeProfileInstallation.consumed_authority_grant_store,
    consumption_identity: runtimeProfileInstallation.consumption_identity,
    signed_payload_replay_identity:
      runtimeProfileInstallation.signed_payload_replay_identity,
    consumed_store_witness: runtimeProfileInstallation.consumed_store_witness,
    consumed_store_write_model:
      runtimeProfileInstallation.consumed_store_write_model,
    recognized_write_accepted: runtimeProfileInstallation.recognized_write_accepted,
    same_process_signed_payload_replay_refused:
      runtimeProfileInstallation.same_process_signed_payload_replay_refused,
    restart_consumed_authority_grant_refused:
      runtimeProfileInstallation.restart_consumed_authority_grant_refused,
    missing_authority_grant_appointment_refused:
      runtimeProfileInstallation.missing_authority_grant_appointment_refused,
    mismatched_authority_grant_appointment_refused:
      runtimeProfileInstallation.mismatched_authority_grant_appointment_refused,
    revoked_authority_grant_refused:
      runtimeProfileInstallation.revoked_authority_grant_refused,
    expired_authority_grant_refused:
      runtimeProfileInstallation.expired_authority_grant_refused,
    request_supplied_authority_grant_refused:
      runtimeProfileInstallation.request_supplied_authority_grant_refused,
    missing_receipt_refused: runtimeProfileInstallation.missing_receipt_refused,
    invalid_receipt_refused: runtimeProfileInstallation.invalid_receipt_refused,
    unknown_issuer_refused: runtimeProfileInstallation.unknown_issuer_refused,
    retired_issuer_refused: runtimeProfileInstallation.retired_issuer_refused,
    missing_issuer_status_refused:
      runtimeProfileInstallation.missing_issuer_status_refused,
    stale_receipt_refused: runtimeProfileInstallation.stale_receipt_refused,
    wrong_policy_refused: runtimeProfileInstallation.wrong_policy_refused,
    wrong_domain_refused: runtimeProfileInstallation.wrong_domain_refused,
    wrong_tool_refused: runtimeProfileInstallation.wrong_tool_refused,
    wrong_runtime_profile_id_refused:
      runtimeProfileInstallation.wrong_runtime_profile_id_refused,
    wrong_audit_event_refused:
      runtimeProfileInstallation.wrong_audit_event_refused,
    wrong_detail_refused: runtimeProfileInstallation.wrong_detail_refused,
    non_boarding_outcome_refused:
      runtimeProfileInstallation.non_boarding_outcome_refused,
    direct_api_with_receipt_refused:
      runtimeProfileInstallation.direct_api_with_receipt_refused,
    agent_supplied_authority_material_refused:
      runtimeProfileInstallation.agent_supplied_authority_material_refused,
    persistent_runtime_profile_installed:
      runtimeProfileInstallation.persistent_runtime_profile_installed,
    latest_profile_selected: runtimeProfileInstallation.latest_profile_selected,
    live_runtime_profile_checked:
      runtimeProfileInstallation.live_runtime_profile_checked,
    live_records_system_checked: runtimeProfileInstallation.live_records_system_checked,
    production_records_service_checked:
      runtimeProfileInstallation.production_records_service_checked,
    live_mcp_coverage_checked: runtimeProfileInstallation.live_mcp_coverage_checked,
    live_approval_channel_health_checked:
      runtimeProfileInstallation.live_approval_channel_health_checked,
    exactly_once_effect_semantics:
      runtimeProfileInstallation.exactly_once_effect_semantics,
    store_anchor_and_witness_joint_rollback_detection:
      runtimeProfileInstallation.store_anchor_and_witness_joint_rollback_detection,
    atomic_store_anchor_witness_commit:
      runtimeProfileInstallation.atomic_store_anchor_witness_commit,
    partial_grant_commit_burn_window_named:
      runtimeProfileInstallation.partial_grant_commit_burn_window_named,
    host_filesystem_path_toctou_closed:
      runtimeProfileInstallation.host_filesystem_path_toctou_closed,
    historical_embedded_fixture_rightful_issuance_path_evidenced:
      runtimeProfileInstallation.fixture_rightful_issuance_path_evidenced === true,
    fixture_rightful_issuance_path_evidenced:
      fixtureRightfulProjectionAllowed &&
      runtimeProfileInstallation.fixture_rightful_issuance_path_evidenced,
    rightful_issuance_proven: runtimeProfileInstallation.rightful_issuance_proven,
    portable_rightful_issuance_proven:
      runtimeProfileInstallation.portable_rightful_issuance_proven,
    live_authority_proven: runtimeProfileInstallation.live_authority_proven,
    production_rightful_issuance_proven:
      runtimeProfileInstallation.production_rightful_issuance_proven,
    current_machine_governance_proven:
      runtimeProfileInstallation.current_machine_governance_proven,
    consequence_lifecycle_closed:
      runtimeProfileInstallation.consequence_lifecycle_closed,
    external_attestation: runtimeProfileInstallation.external_attestation,
    sovereign_recognition: runtimeProfileInstallation.sovereign_recognition,
    unrouted_records_paths_checked:
      runtimeProfileInstallation.unrouted_records_paths_checked,
    claim_boundary:
      'embedded local proof-pack runtime-profile-installation summary only; no fresh profile installation run during verification',
  };
  const keyStateReportSummary = {
    summary_type: 'zlar-local-proof-pack-key-state-verification-summary-v1',
    component: keyState.component,
    run_in_proof_pack: true,
    command: keyState.command,
    report_type: keyState.report_type,
    evidence_model: keyState.evidence_model,
    live_probing: keyState.live_probing,
    read_only: keyState.read_only,
    policy_manifest_constitution:
      keyState.operational_posture.policy_manifest_constitution,
    hardware_policy_constitution:
      keyState.operational_posture.hardware_policy_constitution,
    spec_test_vectors: keyState.operational_posture.spec_test_vectors,
    private_key_material_read: keyState.privacy.private_key_material_read,
    private_key_material_included: keyState.privacy.private_key_material_included,
    private_key_paths_included: keyState.privacy.private_key_paths_included,
    yubi_key_serial_numbers_included:
      keyState.privacy.yubi_key_serial_numbers_included,
    legacy_software_signing_key_present:
      keyState.local_private_key_presence.legacy_software_signing_key_present,
    private_key_bytes_read:
      keyState.local_private_key_presence.private_key_bytes_read,
    policy_software_pins_aligned: keyState.policy_software_pins_aligned,
    constitution_software_pins_aligned: keyState.constitution_software_pins_aligned,
    policy_current_ceremony_ready: keyState.policy_current_ceremony_ready,
    constitution_current_ceremony_ready: keyState.constitution_current_ceremony_ready,
    policy_hardware_target_observed: keyState.policy_hardware_target_observed,
    constitution_hardware_target_observed:
      keyState.constitution_hardware_target_observed,
    spec_hardware_target_observed: keyState.spec_hardware_target_observed,
    key_custody_proven: keyState.key_custody_proven,
    revocation_state_proven: keyState.revocation_state_proven,
    production_trust_registry_proven: keyState.production_trust_registry_proven,
    external_attestation: keyState.external_attestation,
    sovereign_recognition: keyState.sovereign_recognition,
    current_machine_governance_proven: keyState.current_machine_governance_proven,
    claim_boundary:
      'embedded local proof-pack key-state sample summary only; no current-machine key-state run during artifact verification',
  };
  const receiptVerifierBoundarySummary = {
    summary_type: 'zlar-local-proof-pack-receipt-verifier-boundary-verification-summary-v1',
    component: receiptVerifierBoundary.component,
    run_in_proof_pack: true,
    proof_type: receiptVerifierBoundary.proof_type,
    evidence_model: receiptVerifierBoundary.evidence_model,
    live_probing: receiptVerifierBoundary.live_probing,
    command: receiptVerifierBoundary.command,
    receipt_version: receiptVerifierBoundary.receipt_version,
    receipt_type: receiptVerifierBoundary.receipt_type,
    signed_byte_integrity_checked:
      receiptVerifierBoundary.signed_byte_integrity_checked,
    semantic_checks_checked: receiptVerifierBoundary.semantic_checks_checked,
    valid_exit_code: receiptVerifierBoundary.valid_exit_code,
    valid_verdict: receiptVerifierBoundary.valid_verdict,
    valid_kid_match: receiptVerifierBoundary.valid_kid_match,
    valid_receipt_sha256_present:
      receiptVerifierBoundary.valid_receipt_sha256_present,
    valid_provided_pubkey_sha256_present:
      receiptVerifierBoundary.valid_provided_pubkey_sha256_present,
    valid_command_posture_allow_v0:
      receiptVerifierBoundary.valid_command_posture_allow_v0,
    valid_command_posture_detected_format:
      receiptVerifierBoundary.valid_command_posture_detected_format,
    valid_required_identity_command_posture:
      receiptVerifierBoundary.valid_required_identity_command_posture,
    required_identity_exit_code:
      receiptVerifierBoundary.required_identity_exit_code,
    required_identity_verdict:
      receiptVerifierBoundary.required_identity_verdict,
    required_identity_receipt_id_matched:
      receiptVerifierBoundary.required_identity_receipt_id_matched,
    required_identity_receipt_sha256_matched:
      receiptVerifierBoundary.required_identity_receipt_sha256_matched,
    required_identity_kid_matched:
      receiptVerifierBoundary.required_identity_kid_matched,
    required_identity_pubkey_sha256_matched:
      receiptVerifierBoundary.required_identity_pubkey_sha256_matched,
    required_identity_format_matched:
      receiptVerifierBoundary.required_identity_format_matched,
    required_identity_v1_only_matched:
      receiptVerifierBoundary.required_identity_v1_only_matched,
    required_identity_command_posture:
      receiptVerifierBoundary.required_identity_command_posture,
    required_identity_command_posture_allow_v0:
      receiptVerifierBoundary.required_identity_command_posture_allow_v0,
    required_identity_command_posture_detected_format:
      receiptVerifierBoundary.required_identity_command_posture_detected_format,
    required_identity_command_posture_v1_only_required:
      receiptVerifierBoundary.required_identity_command_posture_v1_only_required,
    unknown_signer_exit_code: receiptVerifierBoundary.unknown_signer_exit_code,
    unknown_signer_verdict: receiptVerifierBoundary.unknown_signer_verdict,
    unknown_signer_reason: receiptVerifierBoundary.unknown_signer_reason,
    unknown_signer_kid_match: receiptVerifierBoundary.unknown_signer_kid_match,
    unknown_signer_receipt_sha256_matches_valid:
      receiptVerifierBoundary.unknown_signer_receipt_sha256_matches_valid,
    unknown_signer_provided_pubkey_sha256_differs:
      receiptVerifierBoundary.unknown_signer_provided_pubkey_sha256_differs,
    invalid_exit_code: receiptVerifierBoundary.invalid_exit_code,
    invalid_verdict: receiptVerifierBoundary.invalid_verdict,
    invalid_kid_match: receiptVerifierBoundary.invalid_kid_match,
    invalid_receipt_sha256_differs_from_valid:
      receiptVerifierBoundary.invalid_receipt_sha256_differs_from_valid,
    invalid_provided_pubkey_sha256_matches_valid:
      receiptVerifierBoundary.invalid_provided_pubkey_sha256_matches_valid,
    legacy_v0_required_identity_refused:
      receiptVerifierBoundary.legacy_v0_required_identity_refused,
    legacy_v0_required_identity_exit_code:
      receiptVerifierBoundary.legacy_v0_required_identity_exit_code,
    distinguishes_unknown_signer_from_invalid:
      receiptVerifierBoundary.distinguishes_unknown_signer_from_invalid,
    issuer_recognition_proven: receiptVerifierBoundary.issuer_recognition_proven,
    key_custody_proven: receiptVerifierBoundary.key_custody_proven,
    revocation_state_proven: receiptVerifierBoundary.revocation_state_proven,
    downstream_recognition_proven: receiptVerifierBoundary.downstream_recognition_proven,
    production_deployment_proven: receiptVerifierBoundary.production_deployment_proven,
    current_machine_governance_proven:
      receiptVerifierBoundary.current_machine_governance_proven,
    external_attestation: receiptVerifierBoundary.external_attestation,
    sovereign_recognition: receiptVerifierBoundary.sovereign_recognition,
    unrouted_paths_coverage_proven:
      receiptVerifierBoundary.unrouted_paths_coverage_proven,
    claim_boundary:
      'embedded local proof-pack receipt-verifier boundary summary only; no fresh receipt verification run during artifact verification',
  };
  const trustedIssuerRegistryRecognitionSummary = {
    summary_type:
      'zlar-local-proof-pack-trusted-issuer-registry-recognition-verification-summary-v2',
    component: trustedIssuerRegistryRecognition.component,
    run_in_proof_pack: true,
    command: trustedIssuerRegistryRecognition.command,
    evidence_model: trustedIssuerRegistryRecognition.evidence_model,
    registry_type: trustedIssuerRegistryRecognition.registry_type,
    registry_evidence_model:
      trustedIssuerRegistryRecognition.registry_evidence_model,
    live_probing: trustedIssuerRegistryRecognition.live_probing,
    requested_scope: trustedIssuerRegistryRecognition.requested_scope,
    registry_scope: trustedIssuerRegistryRecognition.registry_scope,
    registry_fixture_validated:
      trustedIssuerRegistryRecognition.registry_fixture_validated,
    registry_fixture_evaluated:
      trustedIssuerRegistryRecognition.registry_fixture_evaluated,
    registry_to_recognition_rule_evaluated:
      trustedIssuerRegistryRecognition.registry_to_recognition_rule_evaluated,
    registry_evaluation_result_type:
      trustedIssuerRegistryRecognition.registry_evaluation_result_type,
    registry_trusted_issuer_count:
      trustedIssuerRegistryRecognition.registry_trusted_issuer_count,
    verdict: trustedIssuerRegistryRecognition.verdict,
    recognized: trustedIssuerRegistryRecognition.recognized,
    decision: trustedIssuerRegistryRecognition.decision,
    reason_code: trustedIssuerRegistryRecognition.reason_code,
    issuer_status: trustedIssuerRegistryRecognition.issuer_status,
    signature_valid: trustedIssuerRegistryRecognition.signature_valid,
    required_audit_event_id_bound:
      trustedIssuerRegistryRecognition.required_audit_event_id_bound,
    required_detail_hash_bound:
      trustedIssuerRegistryRecognition.required_detail_hash_bound,
    malformed_registry_unsupported_field:
      trustedIssuerRegistryRecognition.malformed_registry_unsupported_field,
    malformed_registry_error_code:
      trustedIssuerRegistryRecognition.malformed_registry_error_code,
    malformed_registry_fail_closed_before_verdict:
      trustedIssuerRegistryRecognition.malformed_registry_fail_closed_before_verdict,
    live_trust_registry_state:
      trustedIssuerRegistryRecognition.live_trust_registry_state,
    live_issuer_status_proven:
      trustedIssuerRegistryRecognition.live_issuer_status_proven,
    key_custody_proven: trustedIssuerRegistryRecognition.key_custody_proven,
    revocation_truth_proven:
      trustedIssuerRegistryRecognition.revocation_truth_proven,
    production_trust_registry_proven:
      trustedIssuerRegistryRecognition.production_trust_registry_proven,
    production_downstream_recognition_proven:
      trustedIssuerRegistryRecognition.production_downstream_recognition_proven,
    production_authority: trustedIssuerRegistryRecognition.production_authority,
    sovereign_recognition: trustedIssuerRegistryRecognition.sovereign_recognition,
    public_external_attestation:
      trustedIssuerRegistryRecognition.public_external_attestation,
    real_non_operator_review:
      trustedIssuerRegistryRecognition.real_non_operator_review,
    current_machine_governance_proven:
      trustedIssuerRegistryRecognition.current_machine_governance_proven,
    claim_boundary:
      'embedded local proof-pack trusted issuer registry recognition summary only; no live registry or fresh verifier run during artifact verification',
  };
  const humanAuthorizationSummary = {
    summary_type: 'zlar-local-proof-pack-human-authorization-verification-summary-v1',
    component: humanAuthorization.component,
    run_in_proof_pack: true,
    command: humanAuthorization.command,
    proof_type: humanAuthorization.proof_type,
    evidence_model: humanAuthorization.evidence_model,
    live_probing: humanAuthorization.live_probing,
    approval_channel: humanAuthorization.approval_channel,
    pending_boarded: humanAuthorization.pending_boarded,
    authorized_boarded: humanAuthorization.authorized_boarded,
    denied_boarded: humanAuthorization.denied_boarded,
    authorizer: humanAuthorization.authorizer,
    outcome: humanAuthorization.outcome,
    claim_boundary:
      'embedded local proof-pack human-authorization summary only; simulated fixture, no live approval-channel run during artifact verification',
  };
  const downstreamRefusalSummary = {
    summary_type: 'zlar-local-proof-pack-downstream-refusal-verification-summary-v1',
    component: downstream.component,
    run_in_proof_pack: true,
    command: downstream.command,
    proof_type: downstream.proof_type,
    evidence_model: downstream.evidence_model,
    live_probing: downstream.live_probing,
    recognized_boarded: downstream.recognized_boarded,
    recognized_marker_count_delta: downstream.recognized_marker_count_delta,
    final_marker_count: downstream.final_marker_count,
    refusal_case_count: downstream.refusal_case_count,
    all_refusals_unboarded: downstream.all_refusals_unboarded,
    all_refusal_marker_count_deltas_zero:
      downstream.all_refusal_marker_count_deltas_zero,
    refusal_reasons: [...downstream.refusal_reasons],
    claim_boundary:
      'embedded local proof-pack downstream-refusal summary only; local hermetic fixture, no live downstream run during artifact verification',
  };
  const claudeHookReplaySummary = {
    summary_type: 'zlar-local-proof-pack-claude-hook-contract-replay-verification-summary-v1',
    component: claudeHookReplay.component,
    run_in_proof_pack: true,
    command: claudeHookReplay.command,
    proof_type: claudeHookReplay.proof_type,
    evidence_model: claudeHookReplay.evidence_model,
    live_probing: claudeHookReplay.live_probing,
    hook_replay_contract_sha256: claudeHookReplay.hook_replay_contract_sha256,
    source_state_boundary: claudeHookReplay.source_state_boundary,
    adapter_source: claudeHookReplay.adapter_source,
    adapter_path_claimed: claudeHookReplay.adapter_path_claimed,
    adapter_sha256: claudeHookReplay.adapter_sha256,
    case_evidence_hash_scope: claudeHookReplay.case_evidence_hash_scope,
    case_evidence_sha256: claudeHookReplay.case_evidence_sha256,
    required_case_count: claudeHookReplay.required_case_count,
    required_cases: [...claudeHookReplay.required_cases],
    all_required_cases_present: claudeHookReplay.all_required_cases_present,
    permission_decisions_observed: {
      ...claudeHookReplay.permission_decisions_observed,
    },
    denied_effect_not_executed: claudeHookReplay.denied_effect_not_executed,
    tool_input_not_executed: claudeHookReplay.tool_input_not_executed,
    missing_gate_failed_closed: claudeHookReplay.missing_gate_failed_closed,
    blank_gate_response_failed_closed:
      claudeHookReplay.blank_gate_response_failed_closed,
    malformed_output_refused: claudeHookReplay.malformed_output_refused,
    non_pretooluse_payload_denied_by_fixture_gate:
      claudeHookReplay.non_pretooluse_payload_denied_by_fixture_gate,
    supporting_local_boarding_proof_passed:
      claudeHookReplay.supporting_local_boarding_proof_passed,
    supporting_local_boarding_proof_type:
      claudeHookReplay.supporting_local_boarding_proof_type,
    supporting_local_boarding_v1_receipt_identity_verified:
      claudeHookReplay.supporting_local_boarding_v1_receipt_identity_verified,
    supporting_local_boarding_consequence_absent_on_every_refusal:
      claudeHookReplay.supporting_local_boarding_consequence_absent_on_every_refusal,
    supporting_local_boarding_consequence_present_exactly_once_on_acceptance:
      claudeHookReplay.supporting_local_boarding_consequence_present_exactly_once_on_acceptance,
    supporting_local_boarding_legacy_v0_recognized_boarding_identity:
      claudeHookReplay.supporting_local_boarding_legacy_v0_recognized_boarding_identity,
    live_claude_invoked: claudeHookReplay.live_claude_invoked,
    live_claude_app_passage_proven:
      claudeHookReplay.live_claude_app_passage_proven,
    app_originated_hook_crossing_proven:
      claudeHookReplay.app_originated_hook_crossing_proven,
    live_receipt_emission_proven: claudeHookReplay.live_receipt_emission_proven,
    current_machine_governance_proven:
      claudeHookReplay.current_machine_governance_proven,
    production_downstream_recognition_proven:
      claudeHookReplay.production_downstream_recognition_proven,
    all_surface_governance_proven: claudeHookReplay.all_surface_governance_proven,
    side_door_closure_proven: claudeHookReplay.side_door_closure_proven,
    claim_boundary:
      'embedded local proof-pack Claude hook-contract replay summary and case-evidence hash only; source_state is not carried as freshness evidence during artifact verification; no fresh hook replay run, live Claude invocation, app-originated hook crossing, or current-machine governance proof during artifact verification',
  };
  const verification = {
    verification_type: LOCAL_PROOF_PACK_ARTIFACT_VERIFICATION_TYPE,
    verified: true,
    structural_self_integrity_verified: true,
    artifact_identity_match_requires_expected_sha256: true,
    artifact_identity_expected_sha256_supplied: artifactIdentity.supplied,
    expected_artifact_body_sha256: artifactIdentity.expected,
    artifact_identity_sha256_matched: artifactIdentity.matched,
    required_body_sha256: artifactIdentity.expected,
    required_body_sha256_matched: artifactIdentity.matched,
    verification_scope: identityBoundProjection
      ? 'caller-pinned-local-proof-pack-artifact-identity-and-embedded-boundary-validation'
      : 'structural-local-proof-pack-artifact-self-integrity-and-schema-only',
    artifact_verification_model:
      'self-contained-artifact-integrity-and-embedded-boundary-validation',
    artifact_type: artifact.artifact_type,
    canonicalization: artifact.canonicalization,
    hash_scope: artifact.hash_scope,
    body_sha256: artifact.integrity.body_sha256,
    payload_type: artifact.payload.proof_pack_type,
    evidence_model: artifact.payload.evidence_model,
    live_probing: artifact.payload.live_probing,
    fresh_proof_pack_run_performed: false,
    source_freshness_proven: false,
    authority_grant_contract_sha256:
      authorityGrantStatus.authority_grant_contract_sha256,
    embedded_authority_grant_contract_sha256:
      artifactBoundAuthorityGrantContractSha256,
    authority_grant_contract_identity_bound_by_artifact:
      authorityGrantContractIdentityBoundByArtifact,
    authority_grant_status: authorityGrantStatus.status,
    authority_grant_fresh_effect_allowed:
      authorityGrantStatus.fresh_effect_allowed,
    authority_grant_repeated_use_provenance_valid:
      authorityGrantStatus.repeated_use_provenance_valid,
    authority_grant_status_allows_fixture_rightful_projection:
      authorityGrantStatus.fresh_fixture_rightful_projection_allowed === true &&
      authorityGrantStatus.repeated_use_provenance_valid === true,
    fixture_rightful_issuance_projection_allowed:
      fixtureRightfulProjectionAllowed,
    authority_grant_status_reason_code:
      authorityGrantStatusReason?.code || null,
    component_count: artifact.payload.components.length,
    component_manifest_hash_scope: artifact.component_manifest_hash_scope,
    component_manifest: artifact.component_manifest.map((item) => ({ ...item })),
    claim_binding: { ...artifact.claim_binding },
    claim_boundary: historicalCoverageComponent
      ? identityBoundProjection
        ? 'the exact caller-pinned committed artifact preserves historical structural boarding and refusal facts plus a historical pre-exhaustion 6-of-6 coverage snapshot; current coverage is not claimed, terminal and authority-grant identity bindings were not embedded, fixture-rightful projection is permanently false for this schema, and no fresh proof-pack run or current-checkout freshness proof occurred'
        : 'the exact committed artifact is structurally valid and preserves historical embedded boarding and refusal facts plus a historical pre-exhaustion 6-of-6 coverage snapshot; current coverage and exact artifact identity are not projected without a caller pin, fixture-rightful projection is permanently false for this schema, and no fresh proof-pack run occurred'
      : identityBoundProjection
        ? 'caller-pinned artifact identity, embedded structural boarding and refusal boundaries, and verifier schema compatibility only; fixture-rightful projection is false because this schema does not bind an exact authority-grant contract SHA; no later grant status can revive it without a schema revision, and no fresh proof-pack run or current-checkout freshness proof occurred'
        : 'artifact structural self-integrity and verifier schema compatibility only; embedded fixture-rightful and exact-terminal identity, signature, and source-positive projection is withheld without a caller-supplied expected artifact SHA-256; no fresh proof-pack run or current-checkout freshness proof',
    coverage: coverageSummary,
    key_state_report: keyStateReportSummary,
    receipt_verifier_boundary: receiptVerifierBoundarySummary,
    trusted_issuer_registry_recognition: trustedIssuerRegistryRecognitionSummary,
    downstream_refusal: downstreamRefusalSummary,
    human_authorization: humanAuthorizationSummary,
    service_profile_preflight: serviceProfilePreflight,
    runtime_local_activation: runtimeLocalActivationSummary,
    runtime_profile_installation: runtimeProfileInstallationSummary,
    claude_hook_contract_replay: claudeHookReplaySummary,
    non_claims: artifact.payload.non_claims.map((item) =>
      item === HISTORICAL_PROCESS_BOUNDARY_NON_CLAIM
        ? CURRENT_PROCESS_BOUNDARY_NON_CLAIM
        : item === HISTORICAL_FIXTURE_RIGHTFUL_ISSUANCE_NON_CLAIM
          ? identityBoundProjection
            ? 'The caller-pinned artifact preserves historical local-fixture structure, boarding, and refusal facts, but its schema does not bind an exact authority-grant contract SHA and can never project fixture-rightful issuance.'
            : DETACHED_FIXTURE_RIGHTFUL_ISSUANCE_NON_CLAIM
          : item
    ),
  };
  assertNoUnsafeLocalProofPackText(JSON.stringify(verification));
  return verification;
}

export function assertNoUnsafeLocalProofPackText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_OUTPUT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`local proof pack output contains ${label}`);
    }
  }
  return true;
}

export function formatLocalProofPackSummary(report) {
  if (report?.proof_pack_type === LOCAL_PROOF_PACK_TYPE) {
    throw new Error(
      'Local proof-pack v1 raw summary schema is permanently historical-only and cannot project current authority; use artifact verification or a future versioned artifact-bound schema',
    );
  }
  assertLocalProofPack(report);
  const coverage = report.components.find((item) => item.component === 'governed_surface_coverage_map');
  const downstream = report.components.find((item) => item.component === 'downstream_refusal_proof');
  const humanAuthorization = report.components.find((item) => item.component === 'human_authorization_proof');
  const approvalTransport = report.components.find((item) => item.component === 'approval_transport_proof');
  const issuerStatus = report.components.find((item) => item.component === 'issuer_status_proof');
  const trustedIssuerRegistryRecognition = report.components.find((item) => item.component === 'trusted_issuer_registry_recognition');
  const keyState = report.components.find((item) => item.component === 'key_state_report');
  const receiptVerifierBoundary = report.components.find((item) => item.component === 'receipt_verifier_boundary');
  const protectedRecords = report.components.find((item) => item.component === 'protected_records_terminal');
  const adapterConformance = report.components.find((item) => item.component === 'protected_records_adapter_conformance');
  const protectedRecordsService = report.components.find((item) => item.component === 'protected_records_downstream_service');
  const runtimeProfilePreflight = report.components.find((item) => item.component === 'protected_records_runtime_profile_preflight_identity');
  const runtimeActivationPreflight = report.components.find((item) => item.component === 'protected_records_runtime_activation_preflight');
  const runtimeLocalActivation = report.components.find((item) => item.component === 'protected_records_runtime_local_activation');
  const runtimeProfileInstallation = report.components.find((item) => item.component === 'protected_records_runtime_profile_installation');
  const claudeHookReplay = report.components.find((item) => item.component === 'claude_code_hook_contract_replay');
  const lines = [
    'ZLAR Local Proof Pack v1',
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Evidence model: ${report.evidence_model}; live probing=${report.live_probing}`,
    'Components:',
    `- coverage: governed=${coverage.governed_lanes}/${coverage.counted_lanes}; boundaries=${coverage.boundary_entries}`,
    `- coverage_terminal_identity: body_sha256=${coverage.terminal_artifact_body_sha256}; expected_body_sha256=${coverage.terminal_artifact_expected_body_sha256}; identity_sha256_matched=${coverage.terminal_artifact_identity_sha256_matched}; outer_metadata_bound=${coverage.terminal_outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256}; recognized_source_bound=${coverage.terminal_recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256}; signature_valid=${coverage.terminal_trusted_issuer_registry_signature_valid}; fixture_rightful_issuance=${coverage.terminal_fixture_rightful_issuance_path_evidenced}`,
    `- downstream_refusal: recognized_boarded=${downstream.recognized_boarded}; recognized_marker_count_delta=${downstream.recognized_marker_count_delta}; final_marker_count=${downstream.final_marker_count}; refusal_case_count=${downstream.refusal_case_count}; all_refusals_unboarded=${downstream.all_refusals_unboarded}; all_refusal_marker_count_deltas_zero=${downstream.all_refusal_marker_count_deltas_zero}; refusals=${downstream.refusal_reasons.join(',')}`,
    `- human_authorization: pending_boarded=${humanAuthorization.pending_boarded}; authorized_boarded=${humanAuthorization.authorized_boarded}; denied_boarded=${humanAuthorization.denied_boarded}; approval_channel=${humanAuthorization.approval_channel}`,
    `- approval_transport: reference_transport_healthy=${approvalTransport.reference_transport_healthy}; telegram_required_for_fixture=${approvalTransport.telegram_required_for_fixture}; unavailable_boarded=${approvalTransport.unavailable_boarded}; delivered_without_decision_boarded=${approvalTransport.delivered_without_decision_boarded}; signed_human_decision_boarded=${approvalTransport.signed_human_decision_boarded}`,
    `- issuer_status: active_boarded=${issuerStatus.active_issuer_boarded}; retired_refused=${issuerStatus.retired_issuer_refused}; compromised_refused=${issuerStatus.compromised_issuer_refused}; missing_status_refused=${issuerStatus.missing_status_issuer_refused}; unknown_refused=${issuerStatus.unknown_issuer_refused}; missing_key_refused=${issuerStatus.missing_key_issuer_refused}; refusals=${issuerStatus.refusal_reasons.join(',')}`,
    `- trusted_issuer_registry_recognition: verdict=${trustedIssuerRegistryRecognition.verdict}; registry_type=${trustedIssuerRegistryRecognition.registry_type}; evidence_model=${trustedIssuerRegistryRecognition.registry_evidence_model}; live_probing=${trustedIssuerRegistryRecognition.live_probing}; registry_fixture_validated=${trustedIssuerRegistryRecognition.registry_fixture_validated}; registry_fixture_evaluated=${trustedIssuerRegistryRecognition.registry_fixture_evaluated}; registry_to_recognition_rule_evaluated=${trustedIssuerRegistryRecognition.registry_to_recognition_rule_evaluated}; registry_evaluation_result_type=${trustedIssuerRegistryRecognition.registry_evaluation_result_type}; registry_trusted_issuer_count=${trustedIssuerRegistryRecognition.registry_trusted_issuer_count}; issuer_status=${trustedIssuerRegistryRecognition.issuer_status}; signature_valid=${trustedIssuerRegistryRecognition.signature_valid}; audit_event_bound=${trustedIssuerRegistryRecognition.required_audit_event_id_bound}; detail_hash_bound=${trustedIssuerRegistryRecognition.required_detail_hash_bound}; malformed_registry_fail_closed_before_verdict=${trustedIssuerRegistryRecognition.malformed_registry_fail_closed_before_verdict}`,
    `- trusted_issuer_registry_recognition_non_claims: live_trust_registry_state=${trustedIssuerRegistryRecognition.live_trust_registry_state}; live_issuer_status_proven=${trustedIssuerRegistryRecognition.live_issuer_status_proven}; key_custody_proven=${trustedIssuerRegistryRecognition.key_custody_proven}; revocation_truth_proven=${trustedIssuerRegistryRecognition.revocation_truth_proven}; production_trust_registry_proven=${trustedIssuerRegistryRecognition.production_trust_registry_proven}; production_downstream_recognition_proven=${trustedIssuerRegistryRecognition.production_downstream_recognition_proven}; production_authority=${trustedIssuerRegistryRecognition.production_authority}; public_external_attestation=${trustedIssuerRegistryRecognition.public_external_attestation}; real_non_operator_review=${trustedIssuerRegistryRecognition.real_non_operator_review}; sovereign_recognition=${trustedIssuerRegistryRecognition.sovereign_recognition}; current_machine_governance_proven=${trustedIssuerRegistryRecognition.current_machine_governance_proven}`,
    `- key_state_report: command=${keyState.command}; report_type=${keyState.report_type}; evidence_model=${keyState.evidence_model}; live_probing=${keyState.live_probing}; read_only=${keyState.read_only}; policy_posture=${keyState.operational_posture.policy_manifest_constitution}; private_key_material_read=${keyState.privacy.private_key_material_read}; private_key_paths_included=${keyState.privacy.private_key_paths_included}; yubi_key_serial_numbers_included=${keyState.privacy.yubi_key_serial_numbers_included}; legacy_software_signing_key_present=${keyState.local_private_key_presence.legacy_software_signing_key_present}; policy_software_pins_aligned=${keyState.policy_software_pins_aligned}; constitution_software_pins_aligned=${keyState.constitution_software_pins_aligned}; key_custody_proven=${keyState.key_custody_proven}; revocation_state_proven=${keyState.revocation_state_proven}; production_trust_registry_proven=${keyState.production_trust_registry_proven}; current_machine_governance_proven=${keyState.current_machine_governance_proven}; external_attestation=${keyState.external_attestation}; sovereign_recognition=${keyState.sovereign_recognition}`,
    `- receipt_verifier_boundary: command=${receiptVerifierBoundary.command}; valid=${receiptVerifierBoundary.valid_verdict}/${receiptVerifierBoundary.valid_exit_code}; unknown_signer=${receiptVerifierBoundary.unknown_signer_verdict}/${receiptVerifierBoundary.unknown_signer_exit_code}; invalid=${receiptVerifierBoundary.invalid_verdict}/${receiptVerifierBoundary.invalid_exit_code}; valid_kid_match=${receiptVerifierBoundary.valid_kid_match}; unknown_signer_kid_match=${receiptVerifierBoundary.unknown_signer_kid_match}; invalid_kid_match=${receiptVerifierBoundary.invalid_kid_match}; receipt_sha256_present=${receiptVerifierBoundary.valid_receipt_sha256_present}; provided_pubkey_sha256_present=${receiptVerifierBoundary.valid_provided_pubkey_sha256_present}; required_identity=${receiptVerifierBoundary.required_identity_verdict}/${receiptVerifierBoundary.required_identity_exit_code}; required_receipt_sha_match=${receiptVerifierBoundary.required_identity_receipt_sha256_matched}; required_pubkey_sha_match=${receiptVerifierBoundary.required_identity_pubkey_sha256_matched}; required_v1_only=${receiptVerifierBoundary.required_identity_v1_only_matched}; legacy_v0_required_identity_refused=${receiptVerifierBoundary.legacy_v0_required_identity_refused}; distinguishes_unknown_signer_from_invalid=${receiptVerifierBoundary.distinguishes_unknown_signer_from_invalid}; issuer_recognition_proven=${receiptVerifierBoundary.issuer_recognition_proven}; key_custody_proven=${receiptVerifierBoundary.key_custody_proven}; revocation_state_proven=${receiptVerifierBoundary.revocation_state_proven}; downstream_recognition_proven=${receiptVerifierBoundary.downstream_recognition_proven}; production_deployment_proven=${receiptVerifierBoundary.production_deployment_proven}; external_attestation=${receiptVerifierBoundary.external_attestation}; sovereign_recognition=${receiptVerifierBoundary.sovereign_recognition}`,
    `- protected_records: profile=${protectedRecords.deployment_profile}; action_class=${protectedRecords.action_class}; downstream_boundary=${protectedRecords.downstream_boundary}; adapter_profile=${protectedRecords.adapter_profile_type}; adapter_route=${protectedRecords.adapter_authoritative_route}; adapter_boundary=${protectedRecords.adapter_boundary}; adapter_ledger_model=${protectedRecords.adapter_ledger_model}; adapter_replay_scope=${protectedRecords.adapter_replay_scope}; adapter_direct_write_path_available=${protectedRecords.adapter_direct_write_path_available}; adapter_live_records_adapter=${protectedRecords.adapter_live_records_adapter}; adapter_action=${protectedRecords.adapter_action_command}; adapter_action_result_type=${protectedRecords.adapter_action_result_type}; adapter_action_fixture_mode_required=${protectedRecords.adapter_action_fixture_mode_required}; contract_route=${protectedRecords.profile_contract_route}; contract_checkpoint=${protectedRecords.profile_contract_checkpoint}; replay_policy=${protectedRecords.receipt_replay_policy}; required_receipt_fields=${protectedRecords.required_receipt_fields.join(',')}; recognized_write_accepted=${protectedRecords.recognized_write_accepted}; recognized_record_changed=${protectedRecords.recognized_record_changed}; refused_write_count=${protectedRecords.refused_write_count}; refusal_record_delta_total=${protectedRecords.refusal_record_count_delta_total}; final_record_count=${protectedRecords.final_record_count}; refusals=${protectedRecords.refusal_reasons.join(',')}; ungoverned_boundaries=${protectedRecords.known_ungoverned_boundaries.join(',')}`,
    `- protected_records_adapter_conformance: profile=${adapterConformance.profile_id}; action_class=${adapterConformance.action_class}; adapter_command=${adapterConformance.adapter_command}; process_boundary=${adapterConformance.adapter_process_boundary}; route=${adapterConformance.mutation_authoritative_route}; recognized_write_accepted=${adapterConformance.recognized_write_accepted}; recognized_write_ledger_delta=${adapterConformance.recognized_write_ledger_delta}; replay_refused=${adapterConformance.replay_refused}; replay_reason=${adapterConformance.replay_reason}; replay_ledger_delta=${adapterConformance.replay_ledger_delta}; replay_separate_process=${adapterConformance.replay_separate_process}; missing_receipt_refused=${adapterConformance.missing_receipt_refused}; missing_receipt_ledger_delta=${adapterConformance.missing_receipt_ledger_delta}; unsupported_side_door_refused=${adapterConformance.unsupported_side_door_refused}; unsupported_side_door_ledger_delta=${adapterConformance.unsupported_side_door_ledger_delta}; direct_filesystem_write_to_fixture_paths_closed=${adapterConformance.direct_filesystem_write_to_fixture_paths_closed}; live_records_adapter=${adapterConformance.live_records_adapter}; open_boundaries=${adapterConformance.known_open_boundaries.join(',')}`,
    `- protected_records_downstream_service: profile=${protectedRecordsService.profile_id}; action_class=${protectedRecordsService.action_class}; service_command=${protectedRecordsService.service_command}; process_boundary=${protectedRecordsService.service_process_boundary}; recognition_boundary=${protectedRecordsService.recognition_boundary}; route=${protectedRecordsService.mutation_authoritative_route}; preflight_profile=${protectedRecordsService.service_profile_preflight_profile_id}; preflight_profile_sha256=${protectedRecordsService.service_profile_preflight_profile_sha256}; preflight_profile_status=${protectedRecordsService.service_profile_preflight_profile_status}; preflight_run_in_proof_pack=${protectedRecordsService.service_profile_preflight_run_in_proof_pack}; preflight_type=${protectedRecordsService.service_profile_preflight_type}; preflight_evidence_model=${protectedRecordsService.service_profile_preflight_evidence_model}; preflight_live_probing=${protectedRecordsService.service_profile_preflight_live_probing}; preflight_cases=${protectedRecordsService.service_profile_preflight_case_count}/${protectedRecordsService.service_profile_preflight_required_case_count}; preflight_recognized_write_accepted=${protectedRecordsService.service_profile_preflight_recognized_write_accepted}; preflight_replay_refused=${protectedRecordsService.service_profile_preflight_replay_refused}; preflight_missing_receipt_refused=${protectedRecordsService.service_profile_preflight_missing_receipt_refused}; preflight_unrecognized_receipt_refused=${protectedRecordsService.service_profile_preflight_unrecognized_receipt_refused}; preflight_invalid_receipt_refused=${protectedRecordsService.service_profile_preflight_invalid_receipt_refused}; preflight_unknown_issuer_refused=${protectedRecordsService.service_profile_preflight_unknown_issuer_refused}; preflight_wrong_policy_refused=${protectedRecordsService.service_profile_preflight_wrong_policy_refused}; preflight_wrong_policy_reason=${protectedRecordsService.service_profile_preflight_wrong_policy_reason}; preflight_wrong_policy_state_delta=${protectedRecordsService.service_profile_preflight_wrong_policy_state_delta}; preflight_stale_receipt_refused=${protectedRecordsService.service_profile_preflight_stale_receipt_refused}; preflight_direct_api_without_receipt_refused=${protectedRecordsService.service_profile_preflight_direct_api_without_receipt_refused}; preflight_direct_api_with_receipt_refused=${protectedRecordsService.service_profile_preflight_direct_api_with_receipt_refused}; preflight_live_profile_installed=${protectedRecordsService.service_profile_preflight_live_profile_installed}; preflight_runtime_activation_checked=${protectedRecordsService.service_profile_preflight_runtime_profile_activation_checked}; recognized_service_write_accepted=${protectedRecordsService.recognized_service_write_accepted}; recognized_service_state_delta=${protectedRecordsService.recognized_service_state_delta}; replay_refused=${protectedRecordsService.replay_refused}; replay_reason=${protectedRecordsService.replay_reason}; replay_state_delta=${protectedRecordsService.replay_state_delta}; replay_separate_process=${protectedRecordsService.replay_separate_process}; missing_receipt_refused=${protectedRecordsService.missing_receipt_refused}; missing_receipt_state_delta=${protectedRecordsService.missing_receipt_state_delta}; unrecognized_receipt_refused=${protectedRecordsService.unrecognized_receipt_refused}; unrecognized_receipt_state_delta=${protectedRecordsService.unrecognized_receipt_state_delta}; invalid_receipt_refused=${protectedRecordsService.invalid_receipt_refused}; invalid_receipt_state_delta=${protectedRecordsService.invalid_receipt_state_delta}; unknown_issuer_refused=${protectedRecordsService.unknown_issuer_refused}; unknown_issuer_state_delta=${protectedRecordsService.unknown_issuer_state_delta}; stale_receipt_refused=${protectedRecordsService.stale_receipt_refused}; stale_receipt_state_delta=${protectedRecordsService.stale_receipt_state_delta}; direct_api_without_receipt_refused=${protectedRecordsService.direct_api_without_receipt_refused}; direct_api_state_delta=${protectedRecordsService.direct_api_state_delta}; direct_api_attempted=${protectedRecordsService.direct_api_attempted}; direct_filesystem_write_to_fixture_paths_closed=${protectedRecordsService.direct_filesystem_write_to_fixture_paths_closed}; live_records_service=${protectedRecordsService.live_records_service}; preflight_live_records_system_checked=${protectedRecordsService.service_profile_preflight_live_records_system_checked}; preflight_production_records_service_checked=${protectedRecordsService.service_profile_preflight_production_records_service_checked}; preflight_external_attestation=${protectedRecordsService.service_profile_preflight_external_attestation}; preflight_sovereign_recognition=${protectedRecordsService.service_profile_preflight_sovereign_recognition}; open_boundaries=${protectedRecordsService.known_open_boundaries.join(',')}`,
    `- protected_records_runtime_profile_preflight_identity: profile=${runtimeProfilePreflight.profile_id}; profile_sha256=${runtimeProfilePreflight.profile_sha256}; runtime_profile=${runtimeProfilePreflight.runtime_profile_id}; route=${runtimeProfilePreflight.mutation_authoritative_route}; preflight_run_in_proof_pack=${runtimeProfilePreflight.runtime_profile_preflight_run_in_proof_pack}; proof_run_in_proof_pack=${runtimeProfilePreflight.runtime_profile_proof_run_in_proof_pack}; launcher_config=${runtimeProfilePreflight.config_supplied_by_launcher}; request_authority_material_accepted=${runtimeProfilePreflight.request_stream_authority_material_accepted}; authority_grant_contract_required=${runtimeProfilePreflight.authority_grant_contract_required_from_launcher}; consumed_authority_grant_store=${runtimeProfilePreflight.consumed_authority_grant_store}; consumption_identity=${runtimeProfilePreflight.consumption_identity}; signed_payload_replay_identity=${runtimeProfilePreflight.signed_payload_replay_identity}; consumed_store_anchor=${runtimeProfilePreflight.consumed_store_anchor}; consumed_store_witness=${runtimeProfilePreflight.consumed_store_witness}; joint_rollback_detection=${runtimeProfilePreflight.store_anchor_and_witness_joint_rollback_detection}; atomic_store_anchor_witness_commit=${runtimeProfilePreflight.atomic_store_anchor_witness_commit}; partial_grant_commit_burn_window_named=${runtimeProfilePreflight.partial_grant_commit_burn_window_named}; fixture_rightful_issuance=${runtimeProfilePreflight.fixture_rightful_issuance_path_evidenced}; rightful_issuance=${runtimeProfilePreflight.rightful_issuance_proven}; consequence_lifecycle_closed=${runtimeProfilePreflight.consequence_lifecycle_closed}; required_cases=${runtimeProfilePreflight.required_case_count}; boundary_observations=${runtimeProfilePreflight.required_boundary_observation_count}; open_boundaries=${runtimeProfilePreflight.known_open_boundaries.join(',')}`,
    `- protected_records_runtime_activation_preflight: plan=${runtimeActivationPreflight.plan_id}; plan_sha256=${runtimeActivationPreflight.plan_sha256}; runtime_profile=${runtimeActivationPreflight.runtime_profile_id}; profile_sha256=${runtimeActivationPreflight.runtime_profile_sha256}; sha_matches_plan=${runtimeActivationPreflight.runtime_profile_sha_matches_plan}; route=${runtimeActivationPreflight.mutation_authoritative_route}; activation_preflight_run_in_proof_pack=${runtimeActivationPreflight.runtime_activation_preflight_run_in_proof_pack}; runtime_profile_proof_run_in_proof_pack=${runtimeActivationPreflight.runtime_profile_proof_run_in_proof_pack}; runtime_profile_cases=${runtimeActivationPreflight.runtime_profile_proof_case_count}/${runtimeActivationPreflight.runtime_profile_proof_required_case_count}; recognized_write_accepted=${runtimeActivationPreflight.recognized_write_accepted}; same_process_signed_payload_replay_refused=${runtimeActivationPreflight.same_process_signed_payload_replay_refused}; restart_consumed_authority_grant_refused=${runtimeActivationPreflight.restart_consumed_authority_grant_refused}; missing_grant_refused=${runtimeActivationPreflight.missing_authority_grant_appointment_refused}; mismatched_grant_refused=${runtimeActivationPreflight.mismatched_authority_grant_appointment_refused}; revoked_grant_refused=${runtimeActivationPreflight.revoked_authority_grant_refused}; expired_grant_refused=${runtimeActivationPreflight.expired_authority_grant_refused}; request_grant_refused=${runtimeActivationPreflight.request_supplied_authority_grant_refused}; witness_commit_failure_refused=${runtimeActivationPreflight.witness_commit_failed_after_authority_grant_store_commit}; joint_rollback_refused=${runtimeActivationPreflight.store_and_anchor_joint_rollback_refused_against_witness}; joint_rollback_detection=${runtimeActivationPreflight.store_anchor_and_witness_joint_rollback_detection}; joint_rollback_reopens_grant_reuse=${runtimeActivationPreflight.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse}; partial_grant_commit_burn_window_named=${runtimeActivationPreflight.partial_grant_commit_burn_window_named}; fixture_rightful_issuance=${runtimeActivationPreflight.fixture_rightful_issuance_path_evidenced}; rightful_issuance=${runtimeActivationPreflight.rightful_issuance_proven}; consequence_lifecycle_closed=${runtimeActivationPreflight.consequence_lifecycle_closed}; activation_applied=${runtimeActivationPreflight.activation_applied}; persistent_runtime_profile_installed=${runtimeActivationPreflight.persistent_runtime_profile_installed}; open_boundaries=${runtimeActivationPreflight.known_open_boundaries.join(',')}`,
    `- protected_records_runtime_activation_preflight_identity_policy: authority_source=${runtimeActivationPreflight.runtime_profile_identity_authority_source}; request_runtime_profile_id_required=${runtimeActivationPreflight.request_runtime_profile_id_required}; omitted_request_field_present=${runtimeActivationPreflight.omitted_request_runtime_profile_id_present}; omitted_uses_launcher_config=${runtimeActivationPreflight.omitted_runtime_profile_id_uses_launcher_config}; supplied_mismatch_refused=${runtimeActivationPreflight.supplied_mismatched_runtime_profile_id_refused}`,
    `- protected_records_runtime_local_activation: plan=${runtimeLocalActivation.plan_id}; plan_sha256=${runtimeLocalActivation.plan_sha256}; runtime_profile=${runtimeLocalActivation.runtime_profile_id}; profile_sha256=${runtimeLocalActivation.runtime_profile_sha256}; sha_matches_plan=${runtimeLocalActivation.runtime_profile_sha_matches_plan}; route=${runtimeLocalActivation.mutation_authoritative_route}; active_profile_selected=${runtimeLocalActivation.active_profile_selection.selected}; local_activation_run_in_proof_pack=${runtimeLocalActivation.runtime_local_activation_run_in_proof_pack}; runtime_profile_cases=${runtimeLocalActivation.runtime_profile_proof_case_count}/${runtimeLocalActivation.runtime_profile_proof_required_case_count}; recognized_write_accepted=${runtimeLocalActivation.recognized_write_accepted}; same_process_signed_payload_replay_refused=${runtimeLocalActivation.same_process_signed_payload_replay_refused}; restart_consumed_authority_grant_refused=${runtimeLocalActivation.restart_consumed_authority_grant_refused}; missing_grant_refused=${runtimeLocalActivation.missing_authority_grant_appointment_refused}; mismatched_grant_refused=${runtimeLocalActivation.mismatched_authority_grant_appointment_refused}; revoked_grant_refused=${runtimeLocalActivation.revoked_authority_grant_refused}; expired_grant_refused=${runtimeLocalActivation.expired_authority_grant_refused}; request_grant_refused=${runtimeLocalActivation.request_supplied_authority_grant_refused}; witness_commit_failure_refused=${runtimeLocalActivation.witness_commit_failed_after_authority_grant_store_commit}; joint_rollback_refused=${runtimeLocalActivation.store_and_anchor_joint_rollback_refused_against_witness}; joint_rollback_detection=${runtimeLocalActivation.store_anchor_and_witness_joint_rollback_detection}; joint_rollback_reopens_grant_reuse=${runtimeLocalActivation.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse}; partial_grant_commit_burn_window_named=${runtimeLocalActivation.partial_grant_commit_burn_window_named}; host_filesystem_path_toctou_closed=${runtimeLocalActivation.host_filesystem_path_toctou_closed}; fixture_rightful_issuance=${runtimeLocalActivation.fixture_rightful_issuance_path_evidenced}; rightful_issuance=${runtimeLocalActivation.rightful_issuance_proven}; portable_rightful_issuance=${runtimeLocalActivation.portable_rightful_issuance_proven}; live_authority=${runtimeLocalActivation.live_authority_proven}; production_rightful_issuance=${runtimeLocalActivation.production_rightful_issuance_proven}; current_machine_governance=${runtimeLocalActivation.current_machine_governance_proven}; consequence_lifecycle_closed=${runtimeLocalActivation.consequence_lifecycle_closed}; local_activation_applied=${runtimeLocalActivation.local_activation_applied}; persistent_runtime_profile_installed=${runtimeLocalActivation.persistent_runtime_profile_installed}; open_boundaries=${runtimeLocalActivation.known_open_boundaries.join(',')}`,
    `- protected_records_runtime_local_activation_identity_policy: authority_source=${runtimeLocalActivation.runtime_profile_identity_authority_source}; request_runtime_profile_id_required=${runtimeLocalActivation.request_runtime_profile_id_required}; omitted_request_field_present=${runtimeLocalActivation.omitted_request_runtime_profile_id_present}; omitted_uses_launcher_config=${runtimeLocalActivation.omitted_runtime_profile_id_uses_launcher_config}; supplied_mismatch_refused=${runtimeLocalActivation.supplied_mismatched_runtime_profile_id_refused}`,
    `- protected_records_runtime_profile_installation: plan=${runtimeProfileInstallation.plan_id}; plan_sha256=${runtimeProfileInstallation.plan_sha256}; runtime_profile=${runtimeProfileInstallation.runtime_profile_id}; profile_sha256=${runtimeProfileInstallation.runtime_profile_sha256}; sha_matches_plan=${runtimeProfileInstallation.runtime_profile_sha_matches_plan}; route=${runtimeProfileInstallation.mutation_authoritative_route}; installation_run_in_proof_pack=${runtimeProfileInstallation.runtime_profile_installation_run_in_proof_pack}; disposable_root_created=${runtimeProfileInstallation.disposable_profile_selection.install_root_created}; selected_from_install_root=${runtimeProfileInstallation.disposable_profile_selection.profile_selected_from_install_root}; request_guard_refused=${runtimeProfileInstallation.request_authority_guard_summary.all_refused_before_mutation}; runtime_profile_cases=${runtimeProfileInstallation.runtime_profile_proof_case_count}/${runtimeProfileInstallation.runtime_profile_proof_required_case_count}; recognized_write_accepted=${runtimeProfileInstallation.recognized_write_accepted}; same_process_signed_payload_replay_refused=${runtimeProfileInstallation.same_process_signed_payload_replay_refused}; restart_consumed_authority_grant_refused=${runtimeProfileInstallation.restart_consumed_authority_grant_refused}; missing_grant_refused=${runtimeProfileInstallation.missing_authority_grant_appointment_refused}; mismatched_grant_refused=${runtimeProfileInstallation.mismatched_authority_grant_appointment_refused}; revoked_grant_refused=${runtimeProfileInstallation.revoked_authority_grant_refused}; expired_grant_refused=${runtimeProfileInstallation.expired_authority_grant_refused}; request_grant_refused=${runtimeProfileInstallation.request_supplied_authority_grant_refused}; joint_rollback_detection=${runtimeProfileInstallation.store_anchor_and_witness_joint_rollback_detection}; partial_grant_commit_burn_window_named=${runtimeProfileInstallation.partial_grant_commit_burn_window_named}; host_filesystem_path_toctou_closed=${runtimeProfileInstallation.host_filesystem_path_toctou_closed}; fixture_rightful_issuance=${runtimeProfileInstallation.fixture_rightful_issuance_path_evidenced}; rightful_issuance=${runtimeProfileInstallation.rightful_issuance_proven}; portable_rightful_issuance=${runtimeProfileInstallation.portable_rightful_issuance_proven}; live_authority=${runtimeProfileInstallation.live_authority_proven}; production_rightful_issuance=${runtimeProfileInstallation.production_rightful_issuance_proven}; current_machine_governance=${runtimeProfileInstallation.current_machine_governance_proven}; consequence_lifecycle_closed=${runtimeProfileInstallation.consequence_lifecycle_closed}; disposable_profile_installation_applied=${runtimeProfileInstallation.disposable_profile_installation_applied}; persistent_runtime_profile_installed=${runtimeProfileInstallation.persistent_runtime_profile_installed}; open_boundaries=${runtimeProfileInstallation.known_open_boundaries.join(',')}`,
    `- protected_records_runtime_profile_installation_identity_policy: authority_source=${runtimeProfileInstallation.runtime_profile_identity_authority_source}; request_runtime_profile_id_required=${runtimeProfileInstallation.request_runtime_profile_id_required}; omitted_request_field_present=${runtimeProfileInstallation.omitted_request_runtime_profile_id_present}; omitted_uses_launcher_config=${runtimeProfileInstallation.omitted_runtime_profile_id_uses_launcher_config}; supplied_mismatch_refused=${runtimeProfileInstallation.supplied_mismatched_runtime_profile_id_refused}`,
    `- claude_code_hook_contract_replay: command=${claudeHookReplay.command}; evidence_model=${claudeHookReplay.evidence_model}; contract_sha256=${claudeHookReplay.hook_replay_contract_sha256}; source_state_boundary=${claudeHookReplay.source_state_boundary}; adapter_source=${claudeHookReplay.adapter_source}; adapter_path=${claudeHookReplay.adapter_path_claimed}; cases=${claudeHookReplay.required_case_count}/${claudeHookReplay.required_case_count}; allow_json=${claudeHookReplay.permission_decisions_observed.allow}; deny_json=${claudeHookReplay.permission_decisions_observed.deny}; denied_effect_not_executed=${claudeHookReplay.denied_effect_not_executed}; tool_input_not_executed=${claudeHookReplay.tool_input_not_executed}; missing_gate_failed_closed=${claudeHookReplay.missing_gate_failed_closed}; blank_gate_response_failed_closed=${claudeHookReplay.blank_gate_response_failed_closed}; malformed_output_refused=${claudeHookReplay.malformed_output_refused}; non_pretooluse_payload_denied_by_fixture_gate=${claudeHookReplay.non_pretooluse_payload_denied_by_fixture_gate}; supporting_local_boarding_proof_passed=${claudeHookReplay.supporting_local_boarding_proof_passed}; supporting_local_boarding_v1_receipt_identity_verified=${claudeHookReplay.supporting_local_boarding_v1_receipt_identity_verified}; supporting_local_boarding_consequence_absent_on_every_refusal=${claudeHookReplay.supporting_local_boarding_consequence_absent_on_every_refusal}; supporting_local_boarding_consequence_present_exactly_once_on_acceptance=${claudeHookReplay.supporting_local_boarding_consequence_present_exactly_once_on_acceptance}; supporting_local_boarding_legacy_v0_recognized_boarding_identity=${claudeHookReplay.supporting_local_boarding_legacy_v0_recognized_boarding_identity}; live_claude_invoked=${claudeHookReplay.live_claude_invoked}; live_claude_app_passage_proven=${claudeHookReplay.live_claude_app_passage_proven}; app_originated_hook_crossing_proven=${claudeHookReplay.app_originated_hook_crossing_proven}; live_receipt_emission_proven=${claudeHookReplay.live_receipt_emission_proven}; current_machine_governance_proven=${claudeHookReplay.current_machine_governance_proven}; production_downstream_recognition_proven=${claudeHookReplay.production_downstream_recognition_proven}; side_door_closure_proven=${claudeHookReplay.side_door_closure_proven}`,
    'Non-claims:',
  ];
  for (const nonClaim of report.non_claims) {
    lines.push(`- ${nonClaim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeLocalProofPackText(summary);
  return summary;
}

export function formatLocalProofPackArtifactVerification(verification) {
  if (!verification || verification.verification_type !== LOCAL_PROOF_PACK_ARTIFACT_VERIFICATION_TYPE) {
    throw new Error('Local proof pack artifact verification has the wrong type');
  }
  if (verification.verified !== true) {
    throw new Error('Local proof pack artifact verification is not verified');
  }
  const directApiReceiptPresent = verification.service_profile_preflight.case_summaries.find((item) =>
    item.case_id === 'direct_api_profile_receipt_present_refused_before_service_mutation'
  );
  const requestStreamAuthority = verification.service_profile_preflight.case_summaries.find((item) =>
    item.case_id === 'request_stream_authority_material_profile_refused_before_service_mutation'
  );
  const wrongPolicy = verification.service_profile_preflight.case_summaries.find((item) =>
    item.case_id === 'wrong_policy_profile_refused_before_service_mutation'
  );
  const lines = [
    'ZLAR Local Proof Pack Artifact Verification v1',
    `verified=${verification.verified}`,
    `structural_self_integrity_verified=${verification.structural_self_integrity_verified}`,
    `artifact_type=${verification.artifact_type}`,
    `sha256=${verification.body_sha256}`,
    ...(verification.required_body_sha256
      ? [
          `required_body_sha256=${verification.required_body_sha256}`,
          `required_body_sha256_matched=${verification.required_body_sha256_matched}`,
        ]
      : []),
    `artifact_identity_match_requires_expected_sha256=${verification.artifact_identity_match_requires_expected_sha256}; expected_sha256_supplied=${verification.artifact_identity_expected_sha256_supplied}; identity_sha256_matched=${verification.artifact_identity_sha256_matched}`,
    `verification_scope=${verification.verification_scope}`,
    `payload_type=${verification.payload_type}`,
    `evidence_model=${verification.evidence_model}; live_probing=${verification.live_probing}`,
    `artifact_verification_model=${verification.artifact_verification_model}`,
    `fresh_proof_pack_run_performed=${verification.fresh_proof_pack_run_performed}; source_freshness_proven=${verification.source_freshness_proven}`,
    `authority_grant_status=${verification.authority_grant_status}; authority_grant_contract_sha256=${verification.authority_grant_contract_sha256}; embedded_authority_grant_contract_sha256=${verification.embedded_authority_grant_contract_sha256}; artifact_grant_identity_bound=${verification.authority_grant_contract_identity_bound_by_artifact}; fresh_effect_allowed=${verification.authority_grant_fresh_effect_allowed}; repeated_use_provenance_valid=${verification.authority_grant_repeated_use_provenance_valid}; status_allows_fixture_rightful_projection=${verification.authority_grant_status_allows_fixture_rightful_projection}; fixture_rightful_projection_allowed=${verification.fixture_rightful_issuance_projection_allowed}; reason_code=${verification.authority_grant_status_reason_code}`,
    `component_count=${verification.component_count}`,
    `component_manifest_hash_scope=${verification.component_manifest_hash_scope}`,
    `component_manifest=${verification.component_manifest.map((item) => `${item.component}:${item.component_sha256}`).join(',')}`,
    `claim_binding: non_claim_count=${verification.claim_binding.non_claim_count}; safe_claim_ceiling_sha256=${verification.claim_binding.safe_claim_ceiling_sha256}; non_claims_sha256=${verification.claim_binding.non_claims_sha256}`,
    `claim_boundary=${verification.claim_boundary}`,
    `coverage_summary: governed=${verification.coverage.governed_lanes}/${verification.coverage.counted_lanes}; embedded_schema=${verification.coverage.embedded_coverage_schema}; historical_counts=${verification.coverage.embedded_coverage_counts_historical}; current_counts_claimed=${verification.coverage.current_coverage_counts_claimed}; snapshot_posture=${verification.coverage.coverage_snapshot_posture}; terminal_expected_sha256=${verification.coverage.terminal_artifact_expected_body_sha256}; terminal_claim_projection_allowed=${verification.coverage.terminal_claim_projection_allowed}`,
    `coverage_authority_status: status=${verification.coverage.authority_grant_status}; embedded_authority_grant_contract_sha256=${verification.coverage.embedded_authority_grant_contract_sha256}; artifact_grant_identity_bound=${verification.coverage.authority_grant_contract_identity_bound_by_artifact}; fresh_effect_allowed=${verification.coverage.authority_grant_fresh_effect_allowed}; repeated_use_provenance_valid=${verification.coverage.authority_grant_repeated_use_provenance_valid}; status_allows_fixture_rightful_projection=${verification.coverage.authority_grant_status_allows_fixture_rightful_projection}; fixture_rightful_projection_allowed=${verification.coverage.fixture_rightful_issuance_projection_allowed}; reason_code=${verification.coverage.authority_grant_status_reason_code}`,
    `coverage_terminal_identity: identity_sha256_matched=${verification.coverage.terminal_artifact_identity_sha256_matched}; outer_metadata_bound=${verification.coverage.terminal_outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256}; recognized_source_bound=${verification.coverage.terminal_recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256}; signature_valid=${verification.coverage.terminal_trusted_issuer_registry_signature_valid}; fixture_rightful_issuance=${verification.coverage.terminal_fixture_rightful_issuance_path_evidenced}; source_freshness_proven=${verification.coverage.terminal_source_freshness_proven}`,
    `coverage_terminal_non_claims: rightful_issuance=${verification.coverage.rightful_issuance_proven}; portable_rightful_issuance=${verification.coverage.portable_rightful_issuance_proven}; live_authority=${verification.coverage.live_authority_proven}; production_rightful_issuance=${verification.coverage.production_rightful_issuance_proven}; current_machine_governance=${verification.coverage.current_machine_governance_proven}; consequence_lifecycle_closed=${verification.coverage.consequence_lifecycle_closed}`,
    `coverage_claim_boundary=${verification.coverage.claim_boundary}`,
    `key_state_report_run_in_proof_pack=${verification.key_state_report.run_in_proof_pack}`,
    `key_state_report_summary: report_type=${verification.key_state_report.report_type}; evidence_model=${verification.key_state_report.evidence_model}; live_probing=${verification.key_state_report.live_probing}; read_only=${verification.key_state_report.read_only}; policy_posture=${verification.key_state_report.policy_manifest_constitution}`,
    `key_state_report_privacy: private_key_material_read=${verification.key_state_report.private_key_material_read}; private_key_material_included=${verification.key_state_report.private_key_material_included}; private_key_paths_included=${verification.key_state_report.private_key_paths_included}; yubi_key_serial_numbers_included=${verification.key_state_report.yubi_key_serial_numbers_included}; legacy_software_signing_key_present=${verification.key_state_report.legacy_software_signing_key_present}; private_key_bytes_read=${verification.key_state_report.private_key_bytes_read}`,
    `key_state_report_non_claims: key_custody_proven=${verification.key_state_report.key_custody_proven}; revocation_state_proven=${verification.key_state_report.revocation_state_proven}; production_trust_registry_proven=${verification.key_state_report.production_trust_registry_proven}; current_machine_governance_proven=${verification.key_state_report.current_machine_governance_proven}; external_attestation=${verification.key_state_report.external_attestation}; sovereign_recognition=${verification.key_state_report.sovereign_recognition}`,
    `key_state_report_claim_boundary=${verification.key_state_report.claim_boundary}`,
    `receipt_verifier_boundary_run_in_proof_pack=${verification.receipt_verifier_boundary.run_in_proof_pack}`,
    `receipt_verifier_boundary_verdicts: valid=${verification.receipt_verifier_boundary.valid_verdict}/${verification.receipt_verifier_boundary.valid_exit_code}; unknown_signer=${verification.receipt_verifier_boundary.unknown_signer_verdict}/${verification.receipt_verifier_boundary.unknown_signer_exit_code}; invalid=${verification.receipt_verifier_boundary.invalid_verdict}/${verification.receipt_verifier_boundary.invalid_exit_code}; distinguishes_unknown_signer_from_invalid=${verification.receipt_verifier_boundary.distinguishes_unknown_signer_from_invalid}`,
    `receipt_verifier_boundary_kid_matches: valid=${verification.receipt_verifier_boundary.valid_kid_match}; unknown_signer=${verification.receipt_verifier_boundary.unknown_signer_kid_match}; invalid=${verification.receipt_verifier_boundary.invalid_kid_match}`,
    `receipt_verifier_boundary_identity: receipt_sha256_present=${verification.receipt_verifier_boundary.valid_receipt_sha256_present}; provided_pubkey_sha256_present=${verification.receipt_verifier_boundary.valid_provided_pubkey_sha256_present}; required_identity=${verification.receipt_verifier_boundary.required_identity_verdict}/${verification.receipt_verifier_boundary.required_identity_exit_code}; required_receipt_sha_match=${verification.receipt_verifier_boundary.required_identity_receipt_sha256_matched}; required_pubkey_sha_match=${verification.receipt_verifier_boundary.required_identity_pubkey_sha256_matched}; required_v1_only=${verification.receipt_verifier_boundary.required_identity_v1_only_matched}; legacy_v0_required_identity_refused=${verification.receipt_verifier_boundary.legacy_v0_required_identity_refused}`,
    `receipt_verifier_boundary_non_claims: issuer_recognition_proven=${verification.receipt_verifier_boundary.issuer_recognition_proven}; key_custody_proven=${verification.receipt_verifier_boundary.key_custody_proven}; revocation_state_proven=${verification.receipt_verifier_boundary.revocation_state_proven}; downstream_recognition_proven=${verification.receipt_verifier_boundary.downstream_recognition_proven}; production_deployment_proven=${verification.receipt_verifier_boundary.production_deployment_proven}; current_machine_governance_proven=${verification.receipt_verifier_boundary.current_machine_governance_proven}; external_attestation=${verification.receipt_verifier_boundary.external_attestation}; sovereign_recognition=${verification.receipt_verifier_boundary.sovereign_recognition}; unrouted_paths_coverage_proven=${verification.receipt_verifier_boundary.unrouted_paths_coverage_proven}`,
    `receipt_verifier_boundary_claim_boundary=${verification.receipt_verifier_boundary.claim_boundary}`,
    `trusted_issuer_registry_recognition_run_in_proof_pack=${verification.trusted_issuer_registry_recognition.run_in_proof_pack}`,
    `trusted_issuer_registry_recognition_summary: verdict=${verification.trusted_issuer_registry_recognition.verdict}; registry_type=${verification.trusted_issuer_registry_recognition.registry_type}; evidence_model=${verification.trusted_issuer_registry_recognition.registry_evidence_model}; live_probing=${verification.trusted_issuer_registry_recognition.live_probing}; registry_fixture_validated=${verification.trusted_issuer_registry_recognition.registry_fixture_validated}; registry_fixture_evaluated=${verification.trusted_issuer_registry_recognition.registry_fixture_evaluated}; registry_to_recognition_rule_evaluated=${verification.trusted_issuer_registry_recognition.registry_to_recognition_rule_evaluated}; registry_evaluation_result_type=${verification.trusted_issuer_registry_recognition.registry_evaluation_result_type}; registry_trusted_issuer_count=${verification.trusted_issuer_registry_recognition.registry_trusted_issuer_count}; issuer_status=${verification.trusted_issuer_registry_recognition.issuer_status}; signature_valid=${verification.trusted_issuer_registry_recognition.signature_valid}; audit_event_bound=${verification.trusted_issuer_registry_recognition.required_audit_event_id_bound}; detail_hash_bound=${verification.trusted_issuer_registry_recognition.required_detail_hash_bound}; malformed_registry_fail_closed_before_verdict=${verification.trusted_issuer_registry_recognition.malformed_registry_fail_closed_before_verdict}`,
    `trusted_issuer_registry_recognition_non_claims: live_trust_registry_state=${verification.trusted_issuer_registry_recognition.live_trust_registry_state}; live_issuer_status_proven=${verification.trusted_issuer_registry_recognition.live_issuer_status_proven}; key_custody_proven=${verification.trusted_issuer_registry_recognition.key_custody_proven}; revocation_truth_proven=${verification.trusted_issuer_registry_recognition.revocation_truth_proven}; production_trust_registry_proven=${verification.trusted_issuer_registry_recognition.production_trust_registry_proven}; production_downstream_recognition_proven=${verification.trusted_issuer_registry_recognition.production_downstream_recognition_proven}; production_authority=${verification.trusted_issuer_registry_recognition.production_authority}; public_external_attestation=${verification.trusted_issuer_registry_recognition.public_external_attestation}; real_non_operator_review=${verification.trusted_issuer_registry_recognition.real_non_operator_review}; sovereign_recognition=${verification.trusted_issuer_registry_recognition.sovereign_recognition}; current_machine_governance_proven=${verification.trusted_issuer_registry_recognition.current_machine_governance_proven}`,
    `trusted_issuer_registry_recognition_claim_boundary=${verification.trusted_issuer_registry_recognition.claim_boundary}`,
    `downstream_refusal_run_in_proof_pack=${verification.downstream_refusal.run_in_proof_pack}`,
    `downstream_refusal_summary: proof_type=${verification.downstream_refusal.proof_type}; evidence_model=${verification.downstream_refusal.evidence_model}; live_probing=${verification.downstream_refusal.live_probing}; recognized_boarded=${verification.downstream_refusal.recognized_boarded}; recognized_marker_count_delta=${verification.downstream_refusal.recognized_marker_count_delta}; final_marker_count=${verification.downstream_refusal.final_marker_count}; refusal_case_count=${verification.downstream_refusal.refusal_case_count}; all_refusals_unboarded=${verification.downstream_refusal.all_refusals_unboarded}; all_refusal_marker_count_deltas_zero=${verification.downstream_refusal.all_refusal_marker_count_deltas_zero}; refusals=${verification.downstream_refusal.refusal_reasons.join(',')}`,
    `downstream_refusal_claim_boundary=${verification.downstream_refusal.claim_boundary}`,
    `human_authorization_run_in_proof_pack=${verification.human_authorization.run_in_proof_pack}`,
    `human_authorization_summary: proof_type=${verification.human_authorization.proof_type}; evidence_model=${verification.human_authorization.evidence_model}; live_probing=${verification.human_authorization.live_probing}; approval_channel=${verification.human_authorization.approval_channel}; pending_boarded=${verification.human_authorization.pending_boarded}; authorized_boarded=${verification.human_authorization.authorized_boarded}; denied_boarded=${verification.human_authorization.denied_boarded}; authorizer=${verification.human_authorization.authorizer}; outcome=${verification.human_authorization.outcome}`,
    `human_authorization_claim_boundary=${verification.human_authorization.claim_boundary}`,
    `service_profile_preflight_run_in_proof_pack=${verification.service_profile_preflight.run_in_proof_pack}`,
    `service_profile_preflight_cases=${verification.service_profile_preflight.case_count}/${verification.service_profile_preflight.required_case_count}; evidence_model=${verification.service_profile_preflight.evidence_model}; live_probing=${verification.service_profile_preflight.live_probing}`,
    `service_profile_preflight_wrong_policy: refused=${verification.service_profile_preflight.wrong_policy_refused}; reason=${wrongPolicy?.reason_code}; state_delta=${wrongPolicy?.state_entry_count_delta}`,
    `service_profile_preflight_request_stream_authority: launcher_owned_config_required=${verification.service_profile_preflight.launcher_owned_config_required}; authority_material_allowed=${verification.service_profile_preflight.request_stream_authority_material_allowed}; authority_material_refused=${verification.service_profile_preflight.request_stream_authority_material_refused}; reason=${requestStreamAuthority?.reason_code}; state_delta=${requestStreamAuthority?.state_entry_count_delta}`,
    `service_profile_preflight_direct_api_receipt_present: reason=${directApiReceiptPresent?.reason_code}; state_delta=${directApiReceiptPresent?.state_entry_count_delta}; direct_api_attempted=${directApiReceiptPresent?.direct_api_attempted}`,
    `service_profile_preflight_direct_api_refusals: without_receipt=${verification.service_profile_preflight.direct_api_without_receipt_refused}; with_receipt=${verification.service_profile_preflight.direct_api_with_receipt_refused}`,
    `service_profile_preflight_non_claims: live_profile_installed=${verification.service_profile_preflight.live_profile_installed}; runtime_profile_activation_checked=${verification.service_profile_preflight.runtime_profile_activation_checked}; live_records_system_checked=${verification.service_profile_preflight.live_records_system_checked}; production_records_service_checked=${verification.service_profile_preflight.production_records_service_checked}; live_mcp_coverage_checked=${verification.service_profile_preflight.live_mcp_coverage_checked}; live_approval_channel_health_checked=${verification.service_profile_preflight.live_approval_channel_health_checked}; external_attestation=${verification.service_profile_preflight.external_attestation}; sovereign_recognition=${verification.service_profile_preflight.sovereign_recognition}; unrouted_records_paths_checked=${verification.service_profile_preflight.unrouted_records_paths_checked}`,
    `service_profile_preflight_claim_boundary=${verification.service_profile_preflight.claim_boundary}`,
    `runtime_local_activation_run_in_proof_pack=${verification.runtime_local_activation.run_in_proof_pack}`,
    `runtime_local_activation_active_profile_selection: selected=${verification.runtime_local_activation.active_profile_selection.selected}; scope=${verification.runtime_local_activation.active_profile_selection.selection_scope}; profile=${verification.runtime_local_activation.active_profile_selection.runtime_profile_id}; profile_status_before_selection=${verification.runtime_local_activation.active_profile_selection.profile_status_before_selection}; sha_matches_plan=${verification.runtime_local_activation.active_profile_selection.runtime_profile_sha_matches_plan}; persistent_runtime_profile_installed=${verification.runtime_local_activation.active_profile_selection.persistent_runtime_profile_installed}; live_runtime_profile_checked=${verification.runtime_local_activation.active_profile_selection.live_runtime_profile_checked}; selects_latest_profile=${verification.runtime_local_activation.active_profile_selection.selects_latest_profile}`,
    `runtime_local_activation_identity_policy: authority_source=${verification.runtime_local_activation.runtime_profile_identity_authority_source}; request_runtime_profile_id_required=${verification.runtime_local_activation.request_runtime_profile_id_required}; omitted_request_field_present=${verification.runtime_local_activation.omitted_request_runtime_profile_id_present}; omitted_uses_launcher_config=${verification.runtime_local_activation.omitted_runtime_profile_id_uses_launcher_config}; supplied_mismatch_refused=${verification.runtime_local_activation.supplied_mismatched_runtime_profile_id_refused}`,
    `runtime_local_activation_summary: local_activation_applied=${verification.runtime_local_activation.local_activation_applied}; disposable_runtime_config_written=${verification.runtime_local_activation.disposable_runtime_config_written}; persistent_runtime_config_written=${verification.runtime_local_activation.persistent_runtime_config_written}; hook_configuration_written=${verification.runtime_local_activation.hook_configuration_written}; runtime_service_started=${verification.runtime_local_activation.runtime_service_started}`,
    `runtime_local_activation_authority: route=${verification.runtime_local_activation.mutation_authoritative_route}; consumed_authority_grant_store=${verification.runtime_local_activation.consumed_authority_grant_store}; consumption_identity=${verification.runtime_local_activation.consumption_identity}; signed_payload_replay_identity=${verification.runtime_local_activation.signed_payload_replay_identity}; consumed_store_witness=${verification.runtime_local_activation.consumed_store_witness}; recognized_write_accepted=${verification.runtime_local_activation.recognized_write_accepted}; same_process_signed_payload_replay_refused=${verification.runtime_local_activation.same_process_signed_payload_replay_refused}; restart_consumed_authority_grant_refused=${verification.runtime_local_activation.restart_consumed_authority_grant_refused}; missing_grant_refused=${verification.runtime_local_activation.missing_authority_grant_appointment_refused}; mismatched_grant_refused=${verification.runtime_local_activation.mismatched_authority_grant_appointment_refused}; revoked_grant_refused=${verification.runtime_local_activation.revoked_authority_grant_refused}; expired_grant_refused=${verification.runtime_local_activation.expired_authority_grant_refused}; request_grant_refused=${verification.runtime_local_activation.request_supplied_authority_grant_refused}; witness_commit_failure_refused=${verification.runtime_local_activation.witness_commit_failed_after_authority_grant_store_commit}; joint_rollback_refused=${verification.runtime_local_activation.store_and_anchor_joint_rollback_refused_against_witness}; joint_rollback_detection=${verification.runtime_local_activation.store_anchor_and_witness_joint_rollback_detection}; joint_rollback_reopens_grant_reuse=${verification.runtime_local_activation.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse}; partial_grant_commit_burn_window_named=${verification.runtime_local_activation.partial_grant_commit_burn_window_named}`,
    `runtime_local_activation_non_claims: fixture_rightful_issuance=${verification.runtime_local_activation.fixture_rightful_issuance_path_evidenced}; rightful_issuance=${verification.runtime_local_activation.rightful_issuance_proven}; portable_rightful_issuance=${verification.runtime_local_activation.portable_rightful_issuance_proven}; live_authority=${verification.runtime_local_activation.live_authority_proven}; production_rightful_issuance=${verification.runtime_local_activation.production_rightful_issuance_proven}; current_machine_governance=${verification.runtime_local_activation.current_machine_governance_proven}; consequence_lifecycle_closed=${verification.runtime_local_activation.consequence_lifecycle_closed}; exactly_once_effect_semantics=${verification.runtime_local_activation.exactly_once_effect_semantics}; host_filesystem_path_toctou_closed=${verification.runtime_local_activation.host_filesystem_path_toctou_closed}; persistent_runtime_profile_installed=${verification.runtime_local_activation.persistent_runtime_profile_installed}; live_records_system_checked=${verification.runtime_local_activation.live_records_system_checked}; production_records_service_checked=${verification.runtime_local_activation.production_records_service_checked}; external_attestation=${verification.runtime_local_activation.external_attestation}; sovereign_recognition=${verification.runtime_local_activation.sovereign_recognition}; unrouted_records_paths_checked=${verification.runtime_local_activation.unrouted_records_paths_checked}`,
    `runtime_local_activation_claim_boundary=${verification.runtime_local_activation.claim_boundary}`,
    `runtime_profile_installation_run_in_proof_pack=${verification.runtime_profile_installation.run_in_proof_pack}`,
    `runtime_profile_installation_selection: disposable_root_created=${verification.runtime_profile_installation.disposable_profile_selection.install_root_created}; profile_copy_written=${verification.runtime_profile_installation.disposable_profile_selection.profile_copy_written}; active_profile_index_written=${verification.runtime_profile_installation.disposable_profile_selection.active_profile_index_written}; selected_from_install_root=${verification.runtime_profile_installation.disposable_profile_selection.profile_selected_from_install_root}; selected_by_id_and_sha=${verification.runtime_profile_installation.disposable_profile_selection.selected_by_explicit_id_and_sha}; selects_latest_profile=${verification.runtime_profile_installation.disposable_profile_selection.selects_latest_profile}; profile_sha_verified=${verification.runtime_profile_installation.disposable_profile_selection.profile_sha_verified_before_selection}`,
    `runtime_profile_installation_request_guard: installed_profile_state_refused=${verification.runtime_profile_installation.request_authority_guard_summary.installed_profile_state_refused}; runtime_config_refused=${verification.runtime_profile_installation.request_authority_guard_summary.runtime_config_refused}; runtime_profile_refused=${verification.runtime_profile_installation.request_authority_guard_summary.runtime_profile_refused}; recognition_rule_refused=${verification.runtime_profile_installation.request_authority_guard_summary.recognition_rule_refused}; authority_grant_refused=${verification.runtime_profile_installation.request_authority_guard_summary.authority_grant_refused}; all_refused_before_mutation=${verification.runtime_profile_installation.request_authority_guard_summary.all_refused_before_mutation}; state_delta_total=${verification.runtime_profile_installation.request_authority_guard_summary.state_entry_count_delta_total}`,
    `runtime_profile_installation_identity_policy: authority_source=${verification.runtime_profile_installation.runtime_profile_identity_authority_source}; request_runtime_profile_id_required=${verification.runtime_profile_installation.request_runtime_profile_id_required}; omitted_request_field_present=${verification.runtime_profile_installation.omitted_request_runtime_profile_id_present}; omitted_uses_launcher_config=${verification.runtime_profile_installation.omitted_runtime_profile_id_uses_launcher_config}; supplied_mismatch_refused=${verification.runtime_profile_installation.supplied_mismatched_runtime_profile_id_refused}`,
    `runtime_profile_installation_summary: disposable_profile_installation_applied=${verification.runtime_profile_installation.disposable_profile_installation_applied}; disposable_runtime_config_written=${verification.runtime_profile_installation.disposable_runtime_config_written}; persistent_runtime_config_written=${verification.runtime_profile_installation.persistent_runtime_config_written}; hook_configuration_written=${verification.runtime_profile_installation.hook_configuration_written}; user_config_written=${verification.runtime_profile_installation.user_config_written}; machine_config_written=${verification.runtime_profile_installation.machine_config_written}; runtime_service_started=${verification.runtime_profile_installation.runtime_service_started}`,
    `runtime_profile_installation_authority: route=${verification.runtime_profile_installation.mutation_authoritative_route}; consumed_authority_grant_store=${verification.runtime_profile_installation.consumed_authority_grant_store}; consumption_identity=${verification.runtime_profile_installation.consumption_identity}; signed_payload_replay_identity=${verification.runtime_profile_installation.signed_payload_replay_identity}; consumed_store_witness=${verification.runtime_profile_installation.consumed_store_witness}; recognized_write_accepted=${verification.runtime_profile_installation.recognized_write_accepted}; same_process_signed_payload_replay_refused=${verification.runtime_profile_installation.same_process_signed_payload_replay_refused}; restart_consumed_authority_grant_refused=${verification.runtime_profile_installation.restart_consumed_authority_grant_refused}; missing_grant_refused=${verification.runtime_profile_installation.missing_authority_grant_appointment_refused}; mismatched_grant_refused=${verification.runtime_profile_installation.mismatched_authority_grant_appointment_refused}; revoked_grant_refused=${verification.runtime_profile_installation.revoked_authority_grant_refused}; expired_grant_refused=${verification.runtime_profile_installation.expired_authority_grant_refused}; request_grant_refused=${verification.runtime_profile_installation.request_supplied_authority_grant_refused}; joint_rollback_detection=${verification.runtime_profile_installation.store_anchor_and_witness_joint_rollback_detection}; partial_grant_commit_burn_window_named=${verification.runtime_profile_installation.partial_grant_commit_burn_window_named}`,
    `runtime_profile_installation_non_claims: fixture_rightful_issuance=${verification.runtime_profile_installation.fixture_rightful_issuance_path_evidenced}; rightful_issuance=${verification.runtime_profile_installation.rightful_issuance_proven}; portable_rightful_issuance=${verification.runtime_profile_installation.portable_rightful_issuance_proven}; live_authority=${verification.runtime_profile_installation.live_authority_proven}; production_rightful_issuance=${verification.runtime_profile_installation.production_rightful_issuance_proven}; current_machine_governance=${verification.runtime_profile_installation.current_machine_governance_proven}; consequence_lifecycle_closed=${verification.runtime_profile_installation.consequence_lifecycle_closed}; exactly_once_effect_semantics=${verification.runtime_profile_installation.exactly_once_effect_semantics}; host_filesystem_path_toctou_closed=${verification.runtime_profile_installation.host_filesystem_path_toctou_closed}; persistent_runtime_profile_installed=${verification.runtime_profile_installation.persistent_runtime_profile_installed}; latest_profile_selected=${verification.runtime_profile_installation.latest_profile_selected}; live_runtime_profile_checked=${verification.runtime_profile_installation.live_runtime_profile_checked}; live_records_system_checked=${verification.runtime_profile_installation.live_records_system_checked}; production_records_service_checked=${verification.runtime_profile_installation.production_records_service_checked}; external_attestation=${verification.runtime_profile_installation.external_attestation}; sovereign_recognition=${verification.runtime_profile_installation.sovereign_recognition}; unrouted_records_paths_checked=${verification.runtime_profile_installation.unrouted_records_paths_checked}`,
    `runtime_profile_installation_claim_boundary=${verification.runtime_profile_installation.claim_boundary}`,
    `claude_hook_contract_replay_run_in_proof_pack=${verification.claude_hook_contract_replay.run_in_proof_pack}`,
    `claude_hook_contract_replay_summary: proof_type=${verification.claude_hook_contract_replay.proof_type}; evidence_model=${verification.claude_hook_contract_replay.evidence_model}; live_probing=${verification.claude_hook_contract_replay.live_probing}; contract_sha256=${verification.claude_hook_contract_replay.hook_replay_contract_sha256}; source_state_boundary=${verification.claude_hook_contract_replay.source_state_boundary}; adapter_source=${verification.claude_hook_contract_replay.adapter_source}; adapter_path=${verification.claude_hook_contract_replay.adapter_path_claimed}; case_evidence_sha256=${verification.claude_hook_contract_replay.case_evidence_sha256}; required_cases=${verification.claude_hook_contract_replay.required_case_count}; all_required_cases_present=${verification.claude_hook_contract_replay.all_required_cases_present}; allow_json=${verification.claude_hook_contract_replay.permission_decisions_observed.allow}; deny_json=${verification.claude_hook_contract_replay.permission_decisions_observed.deny}`,
    `claude_hook_contract_replay_cases: denied_effect_not_executed=${verification.claude_hook_contract_replay.denied_effect_not_executed}; tool_input_not_executed=${verification.claude_hook_contract_replay.tool_input_not_executed}; missing_gate_failed_closed=${verification.claude_hook_contract_replay.missing_gate_failed_closed}; blank_gate_response_failed_closed=${verification.claude_hook_contract_replay.blank_gate_response_failed_closed}; malformed_output_refused=${verification.claude_hook_contract_replay.malformed_output_refused}; non_pretooluse_payload_denied_by_fixture_gate=${verification.claude_hook_contract_replay.non_pretooluse_payload_denied_by_fixture_gate}; supporting_local_boarding_proof_passed=${verification.claude_hook_contract_replay.supporting_local_boarding_proof_passed}; supporting_local_boarding_v1_receipt_identity_verified=${verification.claude_hook_contract_replay.supporting_local_boarding_v1_receipt_identity_verified}; supporting_local_boarding_consequence_absent_on_every_refusal=${verification.claude_hook_contract_replay.supporting_local_boarding_consequence_absent_on_every_refusal}; supporting_local_boarding_consequence_present_exactly_once_on_acceptance=${verification.claude_hook_contract_replay.supporting_local_boarding_consequence_present_exactly_once_on_acceptance}; supporting_local_boarding_legacy_v0_recognized_boarding_identity=${verification.claude_hook_contract_replay.supporting_local_boarding_legacy_v0_recognized_boarding_identity}`,
    `claude_hook_contract_replay_non_claims: live_claude_invoked=${verification.claude_hook_contract_replay.live_claude_invoked}; live_claude_app_passage_proven=${verification.claude_hook_contract_replay.live_claude_app_passage_proven}; app_originated_hook_crossing_proven=${verification.claude_hook_contract_replay.app_originated_hook_crossing_proven}; live_receipt_emission_proven=${verification.claude_hook_contract_replay.live_receipt_emission_proven}; current_machine_governance_proven=${verification.claude_hook_contract_replay.current_machine_governance_proven}; production_downstream_recognition_proven=${verification.claude_hook_contract_replay.production_downstream_recognition_proven}; all_surface_governance_proven=${verification.claude_hook_contract_replay.all_surface_governance_proven}; side_door_closure_proven=${verification.claude_hook_contract_replay.side_door_closure_proven}`,
    `claude_hook_contract_replay_claim_boundary=${verification.claude_hook_contract_replay.claim_boundary}`,
    'Non-claims:',
  ];
  for (const nonClaim of verification.non_claims) {
    lines.push(`- ${nonClaim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeLocalProofPackText(summary);
  return summary;
}

export function formatLocalProofPackArtifactSummary(artifact) {
  assertLocalProofPackArtifact(artifact);
  const lines = [
    'Portable artifact:',
    `- type=${artifact.artifact_type}`,
    `- sha256=${artifact.integrity.body_sha256}`,
    `- hash_scope=${artifact.hash_scope}`,
  ];
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeLocalProofPackText(summary);
  return summary;
}
