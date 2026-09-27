import { generateKeyPairSync } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { canonicalize } from './canonicalize.mjs';
import {
  createReceiptV1FromEvent,
  decodePayloadV1,
  pubkeyFingerprint,
  sha256hex,
  signReceiptV1,
  verifyReceiptV1,
} from './receipt.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_ANCHOR_TYPE,
  PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_TYPE,
  PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_WITNESS_TYPE,
  PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH,
  PROTECTED_RECORDS_RUNTIME_GRANT_STORE_WITNESS_COMMIT_FAILURE_MODE,
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  PROTECTED_RECORDS_RUNTIME_STATE_APPEND_FAILURE_MODE,
  PROTECTED_RECORDS_CONSEQUENCE_PATH,
  PROTECTED_RECORDS_TARGET_HANDLE,
  PROTECTED_RECORDS_TARGET_KIND,
  PROTECTED_RECORDS_TARGET_SCOPE,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
  assertProtectedRecordsRuntimeServiceResult,
  createProtectedRecordsRuntimeAuthorityReceiptEvidence,
  createProtectedRecordsRuntimeFixtureAuthorityGrantContract,
  createProtectedRecordsRuntimeLauncherScopeEvidence,
  createProtectedRecordsRuntimeTargetBinding,
  protectedRecordsTargetEffect,
} from './protected-records-runtime-profile.mjs';
import {
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_DOMAIN_ID,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_EXPIRES_AT_EPOCH,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_VALID_FROM_EPOCH,
  PROTECTED_RECORDS_FIXTURE_AUTHORIZED_RECORD_UPDATE,
  assertProtectedRecordsFixtureAuthorityGrantContract,
  assertProtectedRecordsFixtureAuthorityGrantDecision,
  assertProtectedRecordsFixtureAuthorityGrantSummary,
  buildProtectedRecordsFixtureAuthorityGrantSummary,
  createProtectedRecordsFixtureAuthorityGrantAppointment,
  evaluateProtectedRecordsFixtureAuthorityGrantEffect,
  evaluateProtectedRecordsFixtureAuthorityGrantIssuance,
  protectedRecordsAuthorizedEffectDetail,
  protectedRecordsAuthorizedEffectDetailSha256,
  protectedRecordsFixtureAuthorityGrantContractSha256,
} from './protected-records-fixture-authority-grant.mjs';
import {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed,
  protectedRecordsFixtureAuthorityGrantEffectStatusReason,
  protectedRecordsFixtureAuthorityGrantStatus,
} from './protected-records-fixture-authority-status.mjs';
import {
  REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
  protectedRecordsInstalledRuntimeProfileRecognitionContractSha256,
  protectedRecordsInstalledRuntimeProfileTargetContractSha256,
  verifyProtectedRecordsInstalledRuntimeProfilePreflightArtifact,
} from './protected-records-installed-runtime-profile-preflight.mjs';

export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_TYPE =
  'zlar-protected-records-installed-runtime-profile-service-proof-v1';
export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_TYPE =
  'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1';
export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_CANONICALIZATION =
  'zlar-canonical-json-v1';
export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_VERIFICATION_TYPE =
  'zlar-protected-records-installed-runtime-profile-service-proof-artifact-verification-v1';

export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_SAMPLE_ARTIFACT_BODY_SHA256 =
  '3e6bac95ba0a6b41d0ac53c16d598a22d47c871757473025a550556626f5fea8';

export const REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES = Object.freeze([
  'missing_authority_grant_appointment_refused_before_consumption',
  'mismatched_authority_grant_appointment_refused_before_consumption',
  'expired_authority_grant_refused_before_consumption',
  'revoked_authority_grant_refused_before_consumption',
  'request_supplied_authority_grant_refused_before_consumption',
]);

export const INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_SAFE_CLAIM_CEILING =
  'ZLAR can consume a verified read-only installed runtime-profile preflight artifact and run one local disposable fixture records.write crossing whose launcher-owned authority scope, one-use grant contract, issuer appointment, authorized effect, unsigned receipt, accepted issuance decision, signed receipt, recognized effect gate, grant consumption, and process-private state append are hash-bound in order. The proof also preserves the selected 18-case recognition-refusal taxonomy separately from five authority-refusal cases, distinguishes same-process signed-payload replay from restart consumed-grant refusal, and names the local multi-file burn and joint-rollback side doors.';

export const INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_NON_CLAIMS = Object.freeze([
  'This proof consumes a read-only installed-runtime-profile preflight artifact; it does not install, activate, or persist a runtime profile.',
  'This proof writes only disposable launcher-owned config and consumed-authority-grant store, anchor, and witness material inside the proof harness.',
  'This proof starts a local disposable child service process; it does not start a live runtime service, inspect a live records system, or deploy a production records service.',
  'The positive authority result is one local hermetic fixture crossing only; it is not portable, production, live, or current-machine rightful issuance.',
  'This proof does not disclose the runtime private issuer appointment, issuer kid, issuer public key, signature, or private key material.',
  'This proof does not prove exactly-once effects; a state-append failure after grant-store commit can burn the one-use grant without a state mutation.',
  'This proof does not prove an atomic all-or-nothing store, anchor, and witness commit; a metadata failure after grant-store commit can burn the one-use grant.',
  'This proof does not detect rollback when the consumed-grant store, local anchor, and local witness are moved together to a matching earlier state; the same one-use grant can board again.',
  'This proof does not close host process, memory, debugger, operator filesystem, or post-validation path-replacement side doors.',
  'A matching self-contained artifact SHA-256 proves structural self-integrity only; expected artifact identity requires a caller-supplied exact SHA-256 or a stronger external anchor.',
  'This proof does not prove current-machine governance, live MCP coverage, production downstream recognition, production authority, external attestation, enterprise readiness, sovereign recognition, unrouted-surface coverage, or consequence-lifecycle closure.',
]);

export const EXPECTED_REFUSAL_REASONS = Object.freeze({
  missing_receipt_refused_before_runtime_mutation: 'receipt_missing',
  invalid_receipt_refused_before_runtime_mutation: 'receipt_invalid',
  unknown_issuer_refused_before_runtime_mutation: 'unknown_issuer',
  retired_issuer_refused_before_runtime_mutation: 'issuer_not_active',
  missing_issuer_status_refused_before_runtime_mutation: 'issuer_status_missing',
  wrong_policy_refused_before_runtime_mutation: 'policy_not_recognized',
  wrong_domain_refused_before_runtime_mutation: 'domain_out_of_scope',
  wrong_tool_refused_before_runtime_mutation: 'tool_out_of_scope',
  wrong_runtime_profile_id_refused_before_runtime_mutation: 'agent_supplied_authority_material',
  wrong_audit_event_refused_before_runtime_mutation: 'audit_event_mismatch',
  wrong_detail_refused_before_runtime_mutation: 'detail_hash_mismatch',
  non_boarding_outcome_refused_before_runtime_mutation: 'outcome_not_boarding',
  stale_receipt_refused_before_runtime_mutation: 'receipt_stale',
  direct_api_without_receipt_refused_before_runtime_mutation: 'receipt_missing',
  direct_api_with_receipt_refused_before_runtime_mutation: 'direct_api_receipt_present',
  agent_supplied_recognition_rule_refused_before_runtime_mutation:
    'agent_supplied_authority_material',
  agent_supplied_fixture_mode_refused_before_runtime_mutation:
    'agent_supplied_authority_material',
  unsupported_request_field_refused_before_runtime_mutation:
    'agent_supplied_authority_material',
});

const EXPECTED_AUTHORITY_REFUSAL_REASONS = Object.freeze({
  missing_authority_grant_appointment_refused_before_consumption:
    'authority_grant_missing',
  mismatched_authority_grant_appointment_refused_before_consumption:
    'authority_grant_contract_mismatch',
  expired_authority_grant_refused_before_consumption: 'authority_grant_expired',
  revoked_authority_grant_refused_before_consumption: 'authority_grant_revoked',
  request_supplied_authority_grant_refused_before_consumption:
    'agent_supplied_authority_material',
});

const SERVICE_PROOF_RECOGNIZED_AUDIT_EVENT_ID =
  'protected-records-installed-profile-service-001';
const SERVICE_PROOF_TARGET_PROBE_AUDIT_EVENT_ID =
  'protected-records-installed-profile-target-probe-001';
const ORDERED_TRANSITION_BINDING_TYPE =
  'protected-records-runtime-ordered-single-lock-transition-binding-v1';
const ACCEPTED_CROSSING_EVIDENCE_TYPE =
  'zlar-protected-records-installed-runtime-profile-accepted-crossing-evidence-v1';
const STRUCTURAL_VERIFICATION_SCOPE = 'structural-self-integrity-only';
const PINNED_VERIFICATION_SCOPE =
  'expected-artifact-identity-bound-local-fixture-projection';
const STRUCTURAL_CLAIM_BOUNDARY =
  'structural self-integrity only; embedded source-preflight, signed-receipt-envelope, and fixture-rightful assertions are not identity evidence without a caller-supplied expected artifact SHA-256';
const PINNED_CLAIM_BOUNDARY =
  'caller-supplied expected artifact SHA-256 identity matched; embedded source-preflight and signed-receipt-envelope identities plus historical boarding and refusal facts are bound through that exact artifact pin, while fixture-rightful projection additionally requires a current source-authorized grant status with valid repeated-use provenance; no independent detached signature re-verification or generic, portable, live, production, current-machine, or lifecycle-closure claim';
const EXACT_AUTHORITY_CONSTRUCTION_ORDER = Object.freeze([
  'launcher_scope_evidence',
  'authority_grant_contract',
  'issuer_appointment',
  'authorized_effect_detail',
  'unsigned_receipt',
  'accepted_issuance_decision',
  'receipt_signature',
  'recognized_effect_gate',
  'authority_grant_consumption',
  'runtime_state_append',
]);
const SOURCE_PREFLIGHT_KEYS = Object.freeze([
  'artifact_type', 'authority_grant_requirement_preserved', 'body_sha256',
  'consequence_lifecycle_closed', 'current_machine_governance_proven',
  'downstream_refusal_proven', 'exact_runtime_authority_grant_contract_deferred',
  'payload_type', 'profile_wide_target_authority_proven', 'read_only',
  'recognition_contract_preserved', 'recognition_contract_sha256',
  'requested_profile_id', 'requested_profile_sha256', 'rightful_issuance_proven',
  'selected_by_explicit_id_and_sha', 'selects_latest_profile',
  'target_contract_preserved', 'target_contract_sha256', 'verified',
]);
const SELECTED_PROFILE_KEYS = Object.freeze([
  'action_class', 'profile_id', 'profile_sha256', 'runtime_profile_id',
  'selected_by_explicit_id_and_sha', 'selects_latest_profile', 'source',
]);
const SERVICE_BOUNDARY_KEYS = Object.freeze([
  'authority_refusal_taxonomy_separate', 'consumed_authority_grant_store',
  'consumed_store_write_model', 'consumption_identity',
  'disposable_runtime_config_written', 'fixture_rightful_issuance_path_evidenced',
  'joint_store_anchor_witness_rollback_reuse_observed',
  'mutation_authoritative_route', 'partial_grant_commit_burn_window_named',
  'persistent_runtime_config_written', 'recognition_boundary',
  'recognition_refusal_taxonomy_separate', 'request_contract',
  'runtime_service_started', 'service_command', 'service_process_boundary',
  'signed_payload_replay_identity',
]);
const SERVICE_CONFIG_PROVENANCE_KEYS = Object.freeze([
  'authority_grant_source', 'authority_grant_supplied_by_agent',
  'authorized_record_update_source', 'config_path_exposed_to_request_stream',
  'config_source', 'consumed_grant_store_anchor_source',
  'consumed_grant_store_source', 'consumed_grant_store_witness_source',
  'persistent_runtime_profile_config', 'recognition_rule_bound_to_selected_profile',
  'recognition_rule_source', 'recognition_rule_supplied_by_agent',
]);
const RECOGNITION_CONTRACT_KEYS = Object.freeze([
  'action_class', 'observed_refusal_taxonomy_sha256',
  'recognition_contract_sha256', 'required_refusal_case_count',
  'required_refusal_cases', 'runtime_profile_id', 'source',
]);
const AUTHORITY_CONTRACT_KEYS = Object.freeze([
  'construction_order', 'observed_refusal_taxonomy_sha256',
  'public_grant_contract', 'public_safe_grant_summary', 'required_refusal_case_count',
  'required_refusal_cases',
]);
const TARGET_BINDING_KEYS = Object.freeze([
  'accepted_state_effect_binding_hash_present', 'authorized_effect_detail_sha256',
  'consequence_lifecycle_closed', 'consequence_path',
  'current_machine_governance_proven', 'fixture_rightful_issuance_path_evidenced',
  'live_target_proven', 'profile_wide_target_authority_proven',
  'receipt_binds_authorized_effect_detail', 'receipt_detail_sha256',
  'record_update_sha256', 'request_target_semantics', 'rightful_issuance_proven',
  'source_preflight_body_sha256', 'source_profile_id', 'source_profile_sha256',
  'source_recognition_contract_sha256', 'source_runtime_profile_id',
  'source_target_contract_sha256', 'state_effect_binding_sha256',
  'target_binding_sha256', 'target_descriptor_sha256',
  'target_effect_bound_inside_authorized_effect_detail', 'target_effect_sha256',
  'target_handle', 'target_handle_source', 'target_instance_scope',
  'target_kind', 'target_scope',
]);
const PROOF_BOUNDARY_KEYS = Object.freeze([
  'activation_performed', 'consequence_lifecycle_closed',
  'current_machine_governance_proven', 'external_attestation',
  'fixture_rightful_issuance_path_evidenced', 'hook_configuration_written',
  'install_performed', 'joint_rollback_reopened_authority_grant_reuse',
  'live_records_system_checked', 'live_runtime_profile_checked',
  'local_disposable_child_service', 'machine_configuration_written',
  'metadata_partial_commit_burn_observed', 'portable_rightful_issuance_proven',
  'production_downstream_recognition', 'production_records_service_checked',
  'production_rightful_issuance_proven', 'restart_consumed_authority_grant_refused',
  'rightful_issuance_proven', 'same_process_signed_payload_replay_refused',
  'sovereign_recognition', 'state_append_after_grant_commit_burn_observed',
  'store_anchor_and_witness_joint_rollback_detection',
  'store_and_anchor_rollback_refused_while_witness_ahead',
  'user_configuration_written',
]);
const MARKER_KEYS = Object.freeze([
  'authority_refusal_state_append_count', 'auxiliary_target_state_append_count',
  'joint_rollback_reopened_state_append_count',
  'joint_rollback_seed_state_append_count', 'partial_commit_state_append_count',
  'primary_recognized_state_append_count', 'raw_receipt_id_present',
  'recognition_refusal_state_append_count', 'replay_refusal_state_append_count',
  'runtime_private_issuer_material_present', 'total_fixture_state_append_count',
]);
const TRANSITION_KEYS = Object.freeze([
  'authority_grant_consumption_count_after',
  'authority_grant_consumption_count_before', 'authority_grant_contract_sha256',
  'authority_grant_crossing_binding_sha256', 'authorized_effect_detail_sha256',
  'binding_type', 'consumed_grant_store_sha256_after',
  'consumed_grant_store_sha256_before', 'effect_gate_preceded_grant_store_commit',
  'effect_gate_sequence', 'grant_store_commit_preceded_state_append',
  'grant_store_commit_sequence', 'helper_state_promotion_sequence',
  'one_launcher_store_lock_held_across_transition', 'runtime_state_sha256_after',
  'runtime_state_sha256_before', 'signed_payload_replay_check_preceded_effect_gate',
  'signed_payload_replay_check_sequence', 'signed_payload_sha256',
  'state_append_preceded_helper_state_promotion', 'state_append_sequence',
  'state_entry_count_after', 'state_entry_count_before', 'target_effect_sha256',
]);
const CROSSING_EVIDENCE_KEYS = Object.freeze([
  'authority_construction_order_sha256', 'authority_grant_contract_sha256',
  'authority_grant_crossing_binding_sha256', 'authorized_effect_detail_sha256',
  'effect_decision', 'effect_decision_sha256', 'evidence_type',
  'issuance_decision', 'issuance_decision_sha256',
  'receipt_detail_sha256', 'receipt_semantic_binding_sha256',
  'recognition_contract_sha256', 'record_update_sha256',
  'selected_profile_sha256', 'signed_payload_sha256',
  'signed_receipt_envelope_sha256', 'source_preflight_body_sha256',
  'state_effect_binding_sha256', 'target_binding_sha256',
  'target_contract_sha256', 'target_effect_sha256',
  'unsigned_receipt_envelope_sha256', 'verified_signed_payload_base64url',
]);
const PUBLIC_AUTHORITY_SUMMARY_KEYS = Object.freeze([
  'authority_domain_id', 'authority_grant_consumed_before_state_mutation',
  'authority_grant_contract_sha256', 'authority_grant_id',
  'authorization_record_id', 'consequence_lifecycle_closed', 'consequence_path',
  'current_machine_governance_proven',
  'effect_gate_evaluated_before_authority_grant_consumption',
  'exact_runtime_kid_match_proven', 'exact_runtime_public_key_match_proven',
  'expires_at_epoch', 'fixture_authority_grant_satisfied_at_evaluation_time',
  'fixture_clock_model', 'fixture_rightful_issuance_path_evidenced',
  'grantee_actor_id', 'grantor_actor_id', 'grantor_role_id',
  'issuance_gate_evaluated_before_signing', 'issuer_slot', 'live_authority_proven',
  'live_revocation_proven', 'one_use_effect_grant',
  'portable_human_authorization_attestation', 'portable_rightful_issuance_proven',
  'power_ids', 'production_rightful_issuance_proven',
  'receipt_bound_to_authority_grant', 'replacement_requires_different_contract_sha256',
  'revocation_checked_at_fixture_evaluation_time', 'rightful_issuance_proven',
  'rightful_issuance_scope', 'runtime_private_grant_appointment_disclosed',
  'runtime_private_issuer_identity_disclosed', 'summary_type', 'target_handle',
  'valid_from_epoch', 'verified_signed_payload_identity_present',
]);
const ZLAR_BIN = fileURLToPath(new URL('../bin/zlar', import.meta.url));

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

function assertExactArray(label, value, expected) {
  if (!Array.isArray(value) || value.length !== expected.length) {
    throw new Error(`${label} drifted`);
  }
  for (let index = 0; index < expected.length; index += 1) {
    if (value[index] !== expected[index]) throw new Error(`${label} drifted`);
  }
  return true;
}

function assertSha256(label, value) {
  if (!/^[a-f0-9]{64}$/.test(value || '')) throw new Error(`${label} must be SHA-256 hex`);
  return true;
}

function matchExpectedSha256(label, expectedSha256, actualSha256) {
  if (expectedSha256 === null || expectedSha256 === undefined || expectedSha256 === '') {
    return { expected: null, supplied: false, matched: false };
  }
  assertSha256(`${label} expected identity`, expectedSha256);
  if (expectedSha256 !== actualSha256) {
    throw new Error(`${label} does not match the caller-supplied expected SHA-256 identity`);
  }
  return { expected: expectedSha256, supplied: true, matched: true };
}

function assertCanonicalEqual(label, actual, expected) {
  if (canonicalize(actual) !== canonicalize(expected)) throw new Error(`${label} drifted`);
  return true;
}

function baseRecordUpdate() {
  return {
    ...PROTECTED_RECORDS_FIXTURE_AUTHORIZED_RECORD_UPDATE,
  };
}

function keyMaterial(root, label) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  const publicPath = join(root, `${label}.pub`);
  writeFileSync(publicPath, publicPem, { mode: 0o600 });
  return { privatePem, publicPem, kid: pubkeyFingerprint(publicPath) };
}

function eventFixture({
  auditEventId,
  detail,
  issuedAtEpoch,
  action = 'records.write',
  domain = 'records',
  outcome = 'allow',
  rule = 'RRECORDS_ALLOW',
  authorizer = 'policy',
  policyVersion = 'recognition-policy-v1',
  prevHash = '0'.repeat(64),
}) {
  return {
    id: auditEventId,
    ts: new Date(issuedAtEpoch * 1000).toISOString(),
    action,
    domain,
    detail,
    outcome,
    rule,
    authorizer,
    policy_version: policyVersion,
    prev_hash: prevHash,
  };
}

function recognitionRule({
  activeIssuer,
  retiredIssuer = null,
  missingStatusIssuer = null,
  requiredAuditEventId,
  requiredDetailHash,
}) {
  const acceptedIssuers = [{
    kid: activeIssuer.kid,
    public_key_pem: activeIssuer.publicPem,
    status: 'active',
  }];
  if (retiredIssuer) {
    acceptedIssuers.push({
      kid: retiredIssuer.kid,
      public_key_pem: retiredIssuer.publicPem,
      status: 'retired',
    });
  }
  if (missingStatusIssuer) {
    acceptedIssuers.push({
      kid: missingStatusIssuer.kid,
      public_key_pem: missingStatusIssuer.publicPem,
    });
  }
  const rule = {
    deployment_scope: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    accepted_issuers: acceptedIssuers,
    accepted_policy_versions: ['recognition-policy-v1'],
    accepted_domains: ['records'],
    accepted_tools: ['records.write'],
    accepted_outcomes: ['allow', 'authorized'],
    max_age_seconds: 120,
    required_audit_event_id: requiredAuditEventId,
  };
  if (requiredDetailHash) rule.required_detail_hash = requiredDetailHash;
  return rule;
}

function issueFixtureCrossing({
  activeIssuer,
  auditEventId,
  nowEpoch,
  recordUpdate,
  targetBinding,
  retiredIssuer = null,
  missingStatusIssuer = null,
  receiptIssuedAtEpoch = nowEpoch - 5,
  runtimeAppointmentStatus = 'active',
  revokedAtEpoch = null,
  revocationReasonCode = null,
}) {
  const scopeRecognitionRule = recognitionRule({
    activeIssuer,
    requiredAuditEventId: auditEventId,
  });
  const scopeEvidence = createProtectedRecordsRuntimeLauncherScopeEvidence({
    actionClass: 'records.write',
    authorizedRecordUpdate: recordUpdate,
    profileId: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    recognitionRuleSnapshot: scopeRecognitionRule,
    targetBinding,
  });
  const contract = createProtectedRecordsRuntimeFixtureAuthorityGrantContract({
    scopeEvidence,
    validFromEpoch: PROTECTED_RECORDS_FIXTURE_AUTHORITY_VALID_FROM_EPOCH,
    expiresAtEpoch: PROTECTED_RECORDS_FIXTURE_AUTHORITY_EXPIRES_AT_EPOCH,
  });
  const activeAppointment = createProtectedRecordsFixtureAuthorityGrantAppointment({
    contract,
    granteeIssuerKid: activeIssuer.kid,
    granteePublicKeySha256: sha256hex(activeIssuer.publicPem),
  });
  const runtimeAppointment = runtimeAppointmentStatus === 'active'
    ? activeAppointment
    : createProtectedRecordsFixtureAuthorityGrantAppointment({
        contract,
        granteeIssuerKid: activeIssuer.kid,
        granteePublicKeySha256: sha256hex(activeIssuer.publicPem),
        status: runtimeAppointmentStatus,
        revokedAtEpoch,
        revocationReasonCode,
      });
  const targetEffect = protectedRecordsTargetEffect({
    targetHandle: targetBinding.target_handle,
    recordUpdate,
  });
  const authorizedEffectDetail = protectedRecordsAuthorizedEffectDetail({
    contract,
    targetEffect,
  });
  const unsignedReceipt = createReceiptV1FromEvent(eventFixture({
    auditEventId,
    detail: authorizedEffectDetail,
    issuedAtEpoch: receiptIssuedAtEpoch,
  }));
  const payload = decodePayloadV1(unsignedReceipt);
  const issuanceReceiptEvidence = createProtectedRecordsRuntimeAuthorityReceiptEvidence({
    envelope: unsignedReceipt,
    issuerKid: activeIssuer.kid,
    issuerStatus: null,
    payload,
    publicKeySha256: sha256hex(activeIssuer.publicPem),
    source: 'unsigned-receipt-payload-before-signing',
    signatureVerified: false,
    downstreamRecognitionAccepted: false,
    verifiedSignedPayloadSha256: null,
  });
  const issuanceDecision = evaluateProtectedRecordsFixtureAuthorityGrantIssuance({
    contract,
    appointment: activeAppointment,
    scopeEvidence,
    receiptEvidence: issuanceReceiptEvidence,
    authorizedEffectDetail,
    evaluationEpoch: receiptIssuedAtEpoch,
    grantPreviouslyConsumed: false,
  });
  assertProtectedRecordsFixtureAuthorityGrantDecision(
    issuanceDecision,
    contract,
    'issuance',
    { requireAccepted: true }
  );
  const receipt = signReceiptV1(unsignedReceipt, activeIssuer.privatePem, activeIssuer.kid);
  const verified = verifyReceiptV1(receipt, activeIssuer.publicPem);
  if (!verified.valid || !verified.payload || !verified.verified_signed_payload_sha256) {
    throw new Error('Installed service proof could not verify its just-signed fixture receipt');
  }
  const runtimeRecognitionRule = recognitionRule({
    activeIssuer,
    retiredIssuer,
    missingStatusIssuer,
    requiredAuditEventId: auditEventId,
    requiredDetailHash: verified.payload.detail_hash,
  });
  return {
    activeAppointment,
    authorizedEffectDetail,
    contract,
    issuanceDecision,
    receipt,
    runtimeAppointment,
    runtimeRecognitionRule,
    scopeEvidence,
    targetEffect,
    unsignedReceipt,
    verified,
  };
}

function rawSignedReceipt({ crossing, key, nowEpoch, overrides = {} }) {
  const envelope = createReceiptV1FromEvent(eventFixture({
    auditEventId: overrides.auditEventId || SERVICE_PROOF_RECOGNIZED_AUDIT_EVENT_ID,
    detail: Object.prototype.hasOwnProperty.call(overrides, 'detail')
      ? overrides.detail
      : crossing.authorizedEffectDetail,
    issuedAtEpoch: Object.prototype.hasOwnProperty.call(overrides, 'issuedAtEpoch')
      ? overrides.issuedAtEpoch
      : nowEpoch - 5,
    action: overrides.action || 'records.write',
    domain: overrides.domain || 'records',
    outcome: overrides.outcome || 'allow',
    rule: overrides.rule || 'RRECORDS_ALLOW',
    authorizer: overrides.authorizer || 'policy',
    policyVersion: overrides.policyVersion || 'recognition-policy-v1',
    prevHash: overrides.prevHash || '0'.repeat(64),
  }));
  return signReceiptV1(envelope, key.privatePem, key.kid);
}

function runtimeConfig({
  crossing,
  recordUpdate,
  targetBinding,
  nowEpoch,
  scratch,
  label,
  appointmentOverride = undefined,
  runtimeStateAppendFailure = false,
  grantStoreWitnessCommitFailure = false,
}) {
  const config = {
    profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    action_class: 'records.write',
    now_epoch: nowEpoch,
    consumed_grants_path: join(scratch, `${label}-consumed-grants.json`),
    consumed_grant_store_anchor_path: join(scratch, `${label}-consumed-grants.anchor.json`),
    consumed_grant_store_witness_path: join(scratch, `${label}-consumed-grants.witness.json`),
    authorized_record_update: recordUpdate,
    authority_grant_contract: crossing.contract,
    authority_grant_appointment:
      appointmentOverride === undefined ? crossing.runtimeAppointment : appointmentOverride,
    authority_grant_issuance_decision: crossing.issuanceDecision,
    recognition_rule: crossing.runtimeRecognitionRule,
    target_binding: targetBinding,
  };
  if (runtimeStateAppendFailure) {
    config.runtime_state_append_failure_mode =
      PROTECTED_RECORDS_RUNTIME_STATE_APPEND_FAILURE_MODE;
  }
  if (grantStoreWitnessCommitFailure) {
    config.consumed_grant_store_commit_failure_mode =
      PROTECTED_RECORDS_RUNTIME_GRANT_STORE_WITNESS_COMMIT_FAILURE_MODE;
  }
  return config;
}

function requestFor({
  receipt,
  recordUpdate,
  requestMode,
  targetHandle = PROTECTED_RECORDS_TARGET_HANDLE,
  includeTargetHandle = true,
  overrides = {},
}) {
  const request = {
    runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    receipt,
    record_update: recordUpdate,
    request_mode: requestMode,
    ...overrides,
  };
  if (includeTargetHandle) request.target_handle = targetHandle;
  return request;
}

function runRuntimeService(config, requests, scratch, label) {
  const configPath = join(scratch, `${label}-runtime-config.json`);
  writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  const input = `${requests.map((request) => JSON.stringify(request)).join('\n')}\n`;
  const run = spawnSync(ZLAR_BIN, ['protected-records-runtime-service', '--config', configPath], {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    encoding: 'utf8',
    input,
    env: { ...process.env, NO_COLOR: '1' },
  });
  if (run.error) throw new Error('Installed service proof child service failed');
  assertNoUnsafeProtectedRecordsRuntimeProfileText(run.stdout);
  assertNoUnsafeProtectedRecordsRuntimeProfileText(run.stderr);
  const results = run.stdout.trim().split(/\n/).filter(Boolean).map((line) => {
    const result = JSON.parse(line);
    assertProtectedRecordsRuntimeServiceResult(result);
    return result;
  });
  if (run.status !== 0 || run.stderr !== '' || results.length !== requests.length) {
    throw new Error('Installed service proof child service contract failed');
  }
  return results;
}

function caseSummary(caseId, result, {
  serviceProcessInvocation,
  requestOrdinal,
  separateProcessFromAccepted,
  config = null,
}) {
  return {
    case_id: caseId,
    service_process_boundary: result.service_process_boundary,
    service_process_invocation: serviceProcessInvocation,
    separate_process_from_accepted: separateProcessFromAccepted,
    request_ordinal: requestOrdinal,
    service_write_accepted: result.service_write_accepted,
    boarded: result.service_write_accepted === true,
    decision: result.decision.decision,
    reason_code: result.decision.reason_code,
    state_entry_count_before: result.state_entry_count_before,
    state_entry_count_after: result.state_entry_count_after,
    state_entry_count_delta: result.state_entry_count_delta,
    consumed_authority_grant_count: result.consumed_authority_grant_count,
    authority_grant_satisfied: result.authority_grant_satisfied,
    verified_signed_payload_identity_present:
      result.verified_signed_payload_identity_present,
    runtime_transition_binding_present: Boolean(result.runtime_transition_binding),
    consumed_grant_store_exists_after: config
      ? existsSync(config.consumed_grants_path)
      : null,
    consumed_grant_store_anchor_exists_after: config
      ? existsSync(config.consumed_grant_store_anchor_path)
      : null,
    consumed_grant_store_witness_exists_after: config
      ? existsSync(config.consumed_grant_store_witness_path)
      : null,
  };
}

function normalizedConsumedGrantStore(grantContractSha256s) {
  return {
    store_type: PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_TYPE,
    consumption_identity: 'authority-grant-contract-sha256',
    grant_contract_sha256s: [...grantContractSha256s],
  };
}

function consumedGrantStoreMetadata(grantContractSha256s, kind) {
  const store = normalizedConsumedGrantStore(grantContractSha256s);
  return {
    [kind === 'anchor' ? 'anchor_type' : 'witness_type']:
      kind === 'anchor'
        ? PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_ANCHOR_TYPE
        : PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_WITNESS_TYPE,
    store_type: PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_TYPE,
    consumption_identity: 'authority-grant-contract-sha256',
    store_canonical_sha256: sha256hex(canonicalize(store)),
    grant_contract_count: grantContractSha256s.length,
  };
}

function writeJointRollbackState(config, grantContractSha256s, { witness = true } = {}) {
  writeFileSync(
    config.consumed_grants_path,
    `${JSON.stringify(normalizedConsumedGrantStore(grantContractSha256s), null, 2)}\n`,
    { mode: 0o600 }
  );
  writeFileSync(
    config.consumed_grant_store_anchor_path,
    `${JSON.stringify(consumedGrantStoreMetadata(grantContractSha256s, 'anchor'), null, 2)}\n`,
    { mode: 0o600 }
  );
  if (witness) {
    writeFileSync(
      config.consumed_grant_store_witness_path,
      `${JSON.stringify(consumedGrantStoreMetadata(grantContractSha256s, 'witness'), null, 2)}\n`,
      { mode: 0o600 }
    );
  }
}

function publicAuthoritySummary(crossing, acceptedResult) {
  const verifiedReceiptEvidence = createProtectedRecordsRuntimeAuthorityReceiptEvidence({
    envelope: crossing.receipt,
    issuerKid: crossing.receipt.kid,
    issuerStatus: 'active',
    payload: crossing.verified.payload,
    publicKeySha256: crossing.activeAppointment.grantee_public_key_sha256,
    source: 'cryptographically-verified-downstream-recognition',
    signatureVerified: true,
    downstreamRecognitionAccepted: true,
    verifiedSignedPayloadSha256: crossing.verified.verified_signed_payload_sha256,
  });
  const effectDecision = evaluateProtectedRecordsFixtureAuthorityGrantEffect({
    contract: crossing.contract,
    appointment: crossing.activeAppointment,
    scopeEvidence: crossing.scopeEvidence,
    receiptEvidence: verifiedReceiptEvidence,
    authorizedEffectDetail: crossing.authorizedEffectDetail,
    evaluationEpoch: PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH,
    grantPreviouslyConsumed: false,
    issuanceDecision: crossing.issuanceDecision,
  });
  assertProtectedRecordsFixtureAuthorityGrantDecision(
    effectDecision,
    crossing.contract,
    'effect',
    { requireAccepted: true }
  );
  const binding = acceptedResult.runtime_transition_binding;
  if (
    effectDecision.binding.crossing_binding_sha256 !==
      acceptedResult.authority_grant_crossing_binding_sha256 ||
    effectDecision.binding.signed_payload_sha256 !== binding.signed_payload_sha256
  ) {
    throw new Error('Installed service proof effect decision did not bind the accepted transition');
  }
  const executionTrace = {
    trace_type: 'zlar-protected-records-fixture-authority-execution-trace-v1',
    authority_grant_contract_sha256: binding.authority_grant_contract_sha256,
    crossing_binding_sha256: binding.authority_grant_crossing_binding_sha256,
    signed_payload_sha256: binding.signed_payload_sha256,
    target_effect_sha256: binding.target_effect_sha256,
    consumed_grant_store_sha256_before: binding.consumed_grant_store_sha256_before,
    consumed_grant_store_sha256_after: binding.consumed_grant_store_sha256_after,
    runtime_state_sha256_before: binding.runtime_state_sha256_before,
    runtime_state_sha256_after: binding.runtime_state_sha256_after,
    authority_grant_consumption_count_before:
      binding.authority_grant_consumption_count_before,
    authority_grant_consumption_count_after:
      binding.authority_grant_consumption_count_after,
    state_entry_count_before: binding.state_entry_count_before,
    state_entry_count_after: binding.state_entry_count_after,
    issuance_gate_sequence: 1,
    receipt_sign_sequence: 2,
    effect_gate_sequence: 3,
    authority_grant_consumption_sequence: 4,
    state_mutation_sequence: 5,
  };
  const summary = buildProtectedRecordsFixtureAuthorityGrantSummary({
    contract: crossing.contract,
    issuanceDecision: crossing.issuanceDecision,
    effectDecision,
    executionTrace,
  });
  return { effectDecision, summary };
}

function acceptedCrossingEvidence({
  crossing,
  effectDecision,
  preflight,
  sourcePreflightBodySha256,
  targetBindingSha256,
  acceptedResult,
}) {
  const transition = acceptedResult.runtime_transition_binding;
  const issuanceBinding = crossing.issuanceDecision.binding;
  const effectBinding = effectDecision.binding;
  const payloadBytes = Buffer.from(crossing.receipt.payload, 'base64url');
  const signedPayloadSha256 = sha256hex(payloadBytes);
  if (
    signedPayloadSha256 !== crossing.verified.verified_signed_payload_sha256 ||
    issuanceBinding.signed_payload_sha256 !== signedPayloadSha256 ||
    effectBinding.signed_payload_sha256 !== signedPayloadSha256 ||
    issuanceBinding.receipt_semantic_binding_sha256 !==
      effectBinding.receipt_semantic_binding_sha256 ||
    issuanceBinding.crossing_binding_sha256 !== effectBinding.crossing_binding_sha256 ||
    effectBinding.crossing_binding_sha256 !==
      acceptedResult.authority_grant_crossing_binding_sha256 ||
    transition.authority_grant_crossing_binding_sha256 !==
      effectBinding.crossing_binding_sha256
  ) {
    throw new Error('Installed service accepted crossing evidence drifted before projection');
  }
  return {
    evidence_type: ACCEPTED_CROSSING_EVIDENCE_TYPE,
    source_preflight_body_sha256: sourcePreflightBodySha256,
    selected_profile_sha256: preflight.installed_profile.profile_sha256,
    recognition_contract_sha256:
      crossing.contract.scope.recognition_contract_sha256,
    target_contract_sha256: crossing.contract.scope.target_contract_sha256,
    target_binding_sha256: targetBindingSha256,
    authority_grant_contract_sha256:
      protectedRecordsFixtureAuthorityGrantContractSha256(crossing.contract),
    authority_grant_crossing_binding_sha256:
      effectBinding.crossing_binding_sha256,
    receipt_semantic_binding_sha256:
      effectBinding.receipt_semantic_binding_sha256,
    verified_signed_payload_base64url: crossing.receipt.payload,
    signed_payload_sha256: signedPayloadSha256,
    unsigned_receipt_envelope_sha256:
      sha256hex(canonicalize(crossing.unsignedReceipt)),
    signed_receipt_envelope_sha256: sha256hex(canonicalize(crossing.receipt)),
    issuance_decision: JSON.parse(canonicalize(crossing.issuanceDecision)),
    issuance_decision_sha256: sha256hex(canonicalize(crossing.issuanceDecision)),
    effect_decision: JSON.parse(canonicalize(effectDecision)),
    effect_decision_sha256: sha256hex(canonicalize(effectDecision)),
    authority_construction_order_sha256:
      sha256hex(canonicalize(EXACT_AUTHORITY_CONSTRUCTION_ORDER)),
    authorized_effect_detail_sha256:
      protectedRecordsAuthorizedEffectDetailSha256(
        crossing.authorizedEffectDetail,
        crossing.contract
      ),
    receipt_detail_sha256: crossing.verified.payload.detail_hash,
    record_update_sha256: acceptedResult.record_update_hash,
    target_effect_sha256: acceptedResult.target_effect_hash,
    state_effect_binding_sha256: acceptedResult.state_effect_binding_sha256,
  };
}

function refusalTaxonomySha256(required, cases) {
  return sha256hex(canonicalize({
    required_refusal_cases: required,
    observed_refusal_cases: cases.map((item) => ({
      case_id: item.case_id,
      reason_code: item.reason_code,
      refused_before_mutation:
        item.service_write_accepted === false && item.state_entry_count_delta === 0,
    })),
  }));
}

function assertPreflightBoundary(verification) {
  if (
    verification.verified !== true ||
    verification.read_only !== true ||
    verification.selected_by_explicit_id_and_sha !== true ||
    verification.selects_latest_profile !== false ||
    verification.recognition_contract_preserved !== true ||
    verification.target_contract_preserved !== true ||
    verification.request_stream_authority_material_accepted !== false ||
    verification.recognition_rule_supplied_by_agent !== false ||
    verification.consequence_path !== PROTECTED_RECORDS_CONSEQUENCE_PATH ||
    verification.target_handle !== PROTECTED_RECORDS_TARGET_HANDLE ||
    verification.profile_wide_target_authority_proven !== false ||
    verification.rightful_issuance_proven !== false ||
    verification.consequence_lifecycle_closed !== false ||
    verification.runtime_service_started !== false ||
    verification.current_machine_governance_proven !== false
  ) {
    throw new Error('Installed service proof source preflight boundary drifted');
  }
  return true;
}

export function runProtectedRecordsInstalledRuntimeProfileServiceProof(
  artifact,
  { nowEpoch = PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH } = {}
) {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
    'Installed runtime-profile service proof generation',
  );
  if (!Number.isInteger(nowEpoch)) throw new Error('Installed service proof nowEpoch must be an integer');
  if (nowEpoch !== PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH) {
    throw new Error('Installed service proof nowEpoch must equal the fixed fixture evaluation epoch');
  }
  const verification = verifyProtectedRecordsInstalledRuntimeProfilePreflightArtifact(artifact);
  assertPreflightBoundary(verification);
  const preflight = artifact.payload.preflight;
  if (
    verification.recognition_contract_sha256 !==
      protectedRecordsInstalledRuntimeProfileRecognitionContractSha256(preflight.recognition_contract) ||
    verification.target_contract_sha256 !==
      protectedRecordsInstalledRuntimeProfileTargetContractSha256(preflight.target_contract)
  ) {
    throw new Error('Installed service proof source contract digest drifted');
  }
  assertExactArray(
    'Installed service proof recognition refusal cases',
    preflight.recognition_contract.required_refusal_cases,
    REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES
  );

  let scratch = null;
  try {
    scratch = mkdtempSync(join(tmpdir(), 'zlar-installed-profile-service-authority-'));
    const activeIssuer = keyMaterial(scratch, 'active-issuer');
    const retiredIssuer = keyMaterial(scratch, 'retired-issuer');
    const missingStatusIssuer = keyMaterial(scratch, 'missing-status-issuer');
    const unknownIssuer = keyMaterial(scratch, 'unknown-issuer');
    const recordUpdate = baseRecordUpdate();
    const targetBinding = createProtectedRecordsRuntimeTargetBinding({
      sourceProfileId: preflight.installed_profile.profile_id,
      sourceRuntimeProfileId: preflight.installed_profile.runtime_profile_id,
      sourceProfileSha256: preflight.installed_profile.profile_sha256,
      sourceRecognitionContractSha256: verification.recognition_contract_sha256,
      sourceTargetContractSha256: verification.target_contract_sha256,
      sourcePreflightBodySha256: verification.body_sha256,
      sourceActionClass: preflight.installed_profile.action_class,
    });
    const crossing = issueFixtureCrossing({
      activeIssuer,
      retiredIssuer,
      missingStatusIssuer,
      auditEventId: SERVICE_PROOF_RECOGNIZED_AUDIT_EVENT_ID,
      nowEpoch,
      recordUpdate,
      targetBinding,
    });
    const config = runtimeConfig({
      crossing,
      recordUpdate,
      targetBinding,
      nowEpoch,
      scratch,
      label: 'primary',
    });
    const invalidReceipt = {
      ...crossing.receipt,
      sig: `${crossing.receipt.sig.slice(0, -4)}xxxx`,
    };
    const recognitionRequestSpecs = [
      ['missing_receipt_refused_before_runtime_mutation', {
        requestMode: 'missing_receipt_installed_profile_service_write',
        receipt: undefined,
      }],
      ['invalid_receipt_refused_before_runtime_mutation', {
        requestMode: 'invalid_receipt_installed_profile_service_write',
        receipt: invalidReceipt,
      }],
      ['unknown_issuer_refused_before_runtime_mutation', {
        requestMode: 'unknown_issuer_installed_profile_service_write',
        receipt: rawSignedReceipt({ crossing, key: unknownIssuer, nowEpoch }),
      }],
      ['retired_issuer_refused_before_runtime_mutation', {
        requestMode: 'retired_issuer_installed_profile_service_write',
        receipt: rawSignedReceipt({ crossing, key: retiredIssuer, nowEpoch }),
      }],
      ['missing_issuer_status_refused_before_runtime_mutation', {
        requestMode: 'missing_issuer_status_installed_profile_service_write',
        receipt: rawSignedReceipt({ crossing, key: missingStatusIssuer, nowEpoch }),
      }],
      ['wrong_policy_refused_before_runtime_mutation', {
        requestMode: 'wrong_policy_installed_profile_service_write',
        receipt: rawSignedReceipt({
          crossing,
          key: activeIssuer,
          nowEpoch,
          overrides: { policyVersion: 'recognition-policy-old' },
        }),
      }],
      ['wrong_domain_refused_before_runtime_mutation', {
        requestMode: 'wrong_domain_installed_profile_service_write',
        receipt: rawSignedReceipt({
          crossing,
          key: activeIssuer,
          nowEpoch,
          overrides: { domain: 'finance' },
        }),
      }],
      ['wrong_tool_refused_before_runtime_mutation', {
        requestMode: 'wrong_tool_installed_profile_service_write',
        receipt: rawSignedReceipt({
          crossing,
          key: activeIssuer,
          nowEpoch,
          overrides: { action: 'records.delete' },
        }),
      }],
      ['wrong_runtime_profile_id_refused_before_runtime_mutation', {
        requestMode: 'wrong_runtime_profile_id_installed_profile_service_write',
        receipt: rawSignedReceipt({ crossing, key: activeIssuer, nowEpoch }),
        overrides: { runtime_profile_id: 'wrong-runtime-profile' },
      }],
      ['wrong_audit_event_refused_before_runtime_mutation', {
        requestMode: 'wrong_audit_event_installed_profile_service_write',
        receipt: rawSignedReceipt({
          crossing,
          key: activeIssuer,
          nowEpoch,
          overrides: { auditEventId: 'protected-records-installed-profile-service-999' },
        }),
      }],
      ['wrong_detail_refused_before_runtime_mutation', {
        requestMode: 'wrong_detail_installed_profile_service_write',
        receipt: rawSignedReceipt({
          crossing,
          key: activeIssuer,
          nowEpoch,
          overrides: { detail: { operation: 'set_status', record_alias: 'other-fixture' } },
        }),
      }],
      ['non_boarding_outcome_refused_before_runtime_mutation', {
        requestMode: 'non_boarding_installed_profile_service_write',
        receipt: rawSignedReceipt({
          crossing,
          key: activeIssuer,
          nowEpoch,
          overrides: { outcome: 'deny' },
        }),
      }],
      ['stale_receipt_refused_before_runtime_mutation', {
        requestMode: 'stale_receipt_installed_profile_service_write',
        receipt: rawSignedReceipt({
          crossing,
          key: activeIssuer,
          nowEpoch,
          overrides: { issuedAtEpoch: nowEpoch - 600 },
        }),
      }],
      ['direct_api_without_receipt_refused_before_runtime_mutation', {
        requestMode: 'direct_api_write_without_receipt',
        receipt: undefined,
        overrides: { direct_api_write: true },
      }],
      ['direct_api_with_receipt_refused_before_runtime_mutation', {
        requestMode: 'direct_api_write_with_receipt',
        receipt: rawSignedReceipt({ crossing, key: activeIssuer, nowEpoch }),
        overrides: { direct_api_write: true },
      }],
      ['agent_supplied_recognition_rule_refused_before_runtime_mutation', {
        requestMode: 'agent_supplied_recognition_rule_installed_profile_service_write',
        receipt: rawSignedReceipt({ crossing, key: activeIssuer, nowEpoch }),
        overrides: { recognition_rule: { accepted_issuers: [] } },
      }],
      ['agent_supplied_fixture_mode_refused_before_runtime_mutation', {
        requestMode: 'agent_supplied_fixture_mode_installed_profile_service_write',
        receipt: rawSignedReceipt({ crossing, key: activeIssuer, nowEpoch }),
        overrides: { fixture_mode: true },
      }],
      ['unsupported_request_field_refused_before_runtime_mutation', {
        requestMode: 'unsupported_request_field_installed_profile_service_write',
        receipt: rawSignedReceipt({ crossing, key: activeIssuer, nowEpoch }),
        overrides: { unsupported_authority_field: true },
      }],
    ];
    const primaryRequests = [
      requestFor({
        receipt: crossing.receipt,
        recordUpdate,
        requestMode: 'recognized_installed_profile_service_write',
      }),
      requestFor({
        receipt: crossing.receipt,
        recordUpdate,
        requestMode: 'replay_installed_profile_service_write_same_process',
      }),
      ...recognitionRequestSpecs.map(([, input]) => requestFor({
        receipt: input.receipt,
        recordUpdate,
        requestMode: input.requestMode,
        overrides: input.overrides || {},
      })),
    ];
    const primaryResults = runRuntimeService(config, primaryRequests, scratch, 'primary');
    const recognizedBoarding = caseSummary(
      'recognized_installed_profile_service_write',
      primaryResults[0],
      { serviceProcessInvocation: 1, requestOrdinal: 1, separateProcessFromAccepted: false, config }
    );
    const sameProcessReplay = caseSummary(
      'replay_installed_profile_service_write_refused_same_process',
      primaryResults[1],
      { serviceProcessInvocation: 1, requestOrdinal: 2, separateProcessFromAccepted: false, config }
    );
    const refusalCases = recognitionRequestSpecs.map(([caseId], index) =>
      caseSummary(caseId, primaryResults[index + 2], {
        serviceProcessInvocation: 1,
        requestOrdinal: index + 3,
        separateProcessFromAccepted: false,
        config,
      })
    );
    const restartResults = runRuntimeService(
      config,
      [requestFor({
        receipt: crossing.receipt,
        recordUpdate,
        requestMode: 'replay_installed_profile_service_write_after_restart',
      })],
      scratch,
      'restart'
    );
    const restartReplay = caseSummary(
      'replay_installed_profile_service_write_refused_after_service_restart',
      restartResults[0],
      { serviceProcessInvocation: 2, requestOrdinal: 1, separateProcessFromAccepted: true, config }
    );

    const targetProbeCrossing = issueFixtureCrossing({
      activeIssuer,
      auditEventId: SERVICE_PROOF_TARGET_PROBE_AUDIT_EVENT_ID,
      nowEpoch,
      recordUpdate,
      targetBinding,
    });
    const targetProbeConfig = runtimeConfig({
      crossing: targetProbeCrossing,
      recordUpdate,
      targetBinding,
      nowEpoch,
      scratch,
      label: 'target-probe',
    });
    const targetProbeResults = runRuntimeService(
      targetProbeConfig,
      [
        requestFor({
          receipt: targetProbeCrossing.receipt,
          recordUpdate,
          requestMode: 'wrong_target_assertion_installed_profile_service_write',
          targetHandle: `zlar-target:v1:logical-fixture:${'f'.repeat(64)}`,
        }),
        requestFor({
          receipt: targetProbeCrossing.receipt,
          recordUpdate,
          requestMode: 'missing_target_assertion_installed_profile_service_write',
          includeTargetHandle: false,
        }),
        requestFor({
          receipt: targetProbeCrossing.receipt,
          recordUpdate,
          requestMode: 'malformed_target_assertion_installed_profile_service_write',
          targetHandle: 'not-a-target-handle',
        }),
        requestFor({
          receipt: targetProbeCrossing.receipt,
          recordUpdate,
          requestMode: 'correct_target_after_target_refusals_installed_profile_service_write',
        }),
      ],
      scratch,
      'target-probe'
    );
    const targetAssertionCases = [
      caseSummary('wrong_target_assertion_refused_before_runtime_mutation', targetProbeResults[0], {
        serviceProcessInvocation: 3, requestOrdinal: 1, separateProcessFromAccepted: true, config: targetProbeConfig,
      }),
      caseSummary('missing_target_assertion_refused_before_runtime_mutation', targetProbeResults[1], {
        serviceProcessInvocation: 3, requestOrdinal: 2, separateProcessFromAccepted: true, config: targetProbeConfig,
      }),
      caseSummary('malformed_target_assertion_refused_before_runtime_mutation', targetProbeResults[2], {
        serviceProcessInvocation: 3, requestOrdinal: 3, separateProcessFromAccepted: true, config: targetProbeConfig,
      }),
    ];
    const correctTargetAfterRefusals = caseSummary(
      'correct_target_after_target_refusals_boards',
      targetProbeResults[3],
      { serviceProcessInvocation: 3, requestOrdinal: 4, separateProcessFromAccepted: true, config: targetProbeConfig }
    );

    const authorityCases = [];
    const runAuthorityCase = ({
      caseId,
      label,
      caseCrossing,
      appointmentOverride,
      requestOverrides = {},
      evaluationEpoch = nowEpoch,
    }) => {
      const caseConfig = runtimeConfig({
        crossing: caseCrossing,
        recordUpdate,
        targetBinding,
        nowEpoch: evaluationEpoch,
        scratch,
        label,
        appointmentOverride,
      });
      const [result] = runRuntimeService(
        caseConfig,
        [requestFor({
          receipt: caseCrossing.receipt,
          recordUpdate,
          requestMode: caseId,
          overrides: requestOverrides,
        })],
        scratch,
        label
      );
      authorityCases.push(caseSummary(caseId, result, {
        serviceProcessInvocation: authorityCases.length + 4,
        requestOrdinal: 1,
        separateProcessFromAccepted: true,
        config: caseConfig,
      }));
    };
    runAuthorityCase({
      caseId: REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES[0],
      label: 'authority-missing',
      caseCrossing: crossing,
      appointmentOverride: null,
    });
    const mismatchCrossing = issueFixtureCrossing({
      activeIssuer,
      auditEventId: SERVICE_PROOF_RECOGNIZED_AUDIT_EVENT_ID,
      nowEpoch,
      recordUpdate,
      targetBinding,
    });
    const mismatchedAppointment = {
      ...mismatchCrossing.runtimeAppointment,
      contract_sha256: '0'.repeat(64),
      grant_id: `zlar-grant:v1:${'0'.repeat(64)}`,
    };
    runAuthorityCase({
      caseId: REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES[1],
      label: 'authority-mismatch',
      caseCrossing: mismatchCrossing,
      appointmentOverride: mismatchedAppointment,
    });
    const expiredCrossing = issueFixtureCrossing({
      activeIssuer,
      auditEventId: SERVICE_PROOF_RECOGNIZED_AUDIT_EVENT_ID,
      nowEpoch,
      recordUpdate,
      targetBinding,
      receiptIssuedAtEpoch:
        PROTECTED_RECORDS_FIXTURE_AUTHORITY_EXPIRES_AT_EPOCH - 5,
    });
    runAuthorityCase({
      caseId: REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES[2],
      label: 'authority-expired',
      caseCrossing: expiredCrossing,
      evaluationEpoch: PROTECTED_RECORDS_FIXTURE_AUTHORITY_EXPIRES_AT_EPOCH,
    });
    const revokedCrossing = issueFixtureCrossing({
      activeIssuer,
      auditEventId: SERVICE_PROOF_RECOGNIZED_AUDIT_EVENT_ID,
      nowEpoch,
      recordUpdate,
      targetBinding,
      runtimeAppointmentStatus: 'revoked',
      revokedAtEpoch: nowEpoch - 1,
      revocationReasonCode: 'fixture_grant_revoked_before_effect',
    });
    runAuthorityCase({
      caseId: REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES[3],
      label: 'authority-revoked',
      caseCrossing: revokedCrossing,
    });
    const requestSuppliedCrossing = issueFixtureCrossing({
      activeIssuer,
      auditEventId: SERVICE_PROOF_RECOGNIZED_AUDIT_EVENT_ID,
      nowEpoch,
      recordUpdate,
      targetBinding,
    });
    runAuthorityCase({
      caseId: REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES[4],
      label: 'authority-request-supplied',
      caseCrossing: requestSuppliedCrossing,
      requestOverrides: { authority_grant_contract: requestSuppliedCrossing.contract },
    });

    const stateAppendFailureCrossing = issueFixtureCrossing({
      activeIssuer,
      auditEventId: SERVICE_PROOF_RECOGNIZED_AUDIT_EVENT_ID,
      nowEpoch,
      recordUpdate,
      targetBinding,
    });
    const stateAppendFailureConfig = runtimeConfig({
      crossing: stateAppendFailureCrossing,
      recordUpdate,
      targetBinding,
      nowEpoch,
      scratch,
      label: 'state-append-failure',
      runtimeStateAppendFailure: true,
    });
    const [stateAppendFailureResult] = runRuntimeService(
      stateAppendFailureConfig,
      [requestFor({
        receipt: stateAppendFailureCrossing.receipt,
        recordUpdate,
        requestMode: 'runtime_state_append_failed_after_consumed_store_commit',
      })],
      scratch,
      'state-append-failure'
    );
    const witnessCommitFailureCrossing = issueFixtureCrossing({
      activeIssuer,
      auditEventId: SERVICE_PROOF_RECOGNIZED_AUDIT_EVENT_ID,
      nowEpoch,
      recordUpdate,
      targetBinding,
    });
    const witnessCommitFailureConfig = runtimeConfig({
      crossing: witnessCommitFailureCrossing,
      recordUpdate,
      targetBinding,
      nowEpoch,
      scratch,
      label: 'witness-commit-failure',
      grantStoreWitnessCommitFailure: true,
    });
    const [witnessCommitFailureResult] = runRuntimeService(
      witnessCommitFailureConfig,
      [requestFor({
        receipt: witnessCommitFailureCrossing.receipt,
        recordUpdate,
        requestMode: 'witness_commit_failed_after_authority_grant_store_commit',
      })],
      scratch,
      'witness-commit-failure'
    );
    const partialCommitCases = [
      caseSummary(
        'runtime_state_append_failed_after_consumed_store_commit',
        stateAppendFailureResult,
        { serviceProcessInvocation: 9, requestOrdinal: 1, separateProcessFromAccepted: true, config: stateAppendFailureConfig }
      ),
      caseSummary(
        'witness_commit_failed_after_authority_grant_store_commit',
        witnessCommitFailureResult,
        { serviceProcessInvocation: 10, requestOrdinal: 1, separateProcessFromAccepted: true, config: witnessCommitFailureConfig }
      ),
    ];

    const jointRollbackCrossing = issueFixtureCrossing({
      activeIssuer,
      auditEventId: SERVICE_PROOF_RECOGNIZED_AUDIT_EVENT_ID,
      nowEpoch,
      recordUpdate,
      targetBinding,
    });
    const jointRollbackConfig = runtimeConfig({
      crossing: jointRollbackCrossing,
      recordUpdate,
      targetBinding,
      nowEpoch,
      scratch,
      label: 'joint-rollback',
    });
    const [jointRollbackSeed] = runRuntimeService(
      jointRollbackConfig,
      [requestFor({
        receipt: jointRollbackCrossing.receipt,
        recordUpdate,
        requestMode: 'joint_rollback_seed_installed_profile_service_write',
      })],
      scratch,
      'joint-rollback-seed'
    );
    writeJointRollbackState(jointRollbackConfig, [], { witness: false });
    const [storeAnchorRollbackRefusal] = runRuntimeService(
      jointRollbackConfig,
      [requestFor({
        receipt: jointRollbackCrossing.receipt,
        recordUpdate,
        requestMode: 'store_and_anchor_joint_rollback_refused_by_witness',
      })],
      scratch,
      'joint-rollback-witness-ahead'
    );
    writeJointRollbackState(jointRollbackConfig, []);
    const [jointRollbackReopened] = runRuntimeService(
      jointRollbackConfig,
      [requestFor({
        receipt: jointRollbackCrossing.receipt,
        recordUpdate,
        requestMode: 'store_anchor_and_witness_joint_rollback_reopened_grant_reuse',
      })],
      scratch,
      'joint-rollback-reopened'
    );
    const jointRollbackCase = {
      seed: caseSummary('joint_rollback_seed_boarded', jointRollbackSeed, {
        serviceProcessInvocation: 11, requestOrdinal: 1, separateProcessFromAccepted: true, config: jointRollbackConfig,
      }),
      store_and_anchor_only: caseSummary(
        'store_and_anchor_joint_rollback_refused_by_witness_before_runtime_mutation',
        storeAnchorRollbackRefusal,
        { serviceProcessInvocation: 12, requestOrdinal: 1, separateProcessFromAccepted: true, config: jointRollbackConfig }
      ),
      store_anchor_and_witness: caseSummary(
        'store_anchor_and_witness_joint_rollback_reopened_authority_grant_reuse',
        jointRollbackReopened,
        { serviceProcessInvocation: 13, requestOrdinal: 1, separateProcessFromAccepted: true, config: jointRollbackConfig }
      ),
      boundary: 'local-store-anchor-and-witness-joint-rollback-not-detected',
    };

    const { effectDecision, summary: authoritySummary } =
      publicAuthoritySummary(crossing, primaryResults[0]);
    const crossingEvidence = acceptedCrossingEvidence({
      crossing,
      effectDecision,
      preflight,
      sourcePreflightBodySha256: verification.body_sha256,
      targetBindingSha256: primaryResults[0].target_binding_sha256,
      acceptedResult: primaryResults[0],
    });
    const recognitionTaxonomySha = refusalTaxonomySha256(
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
      refusalCases
    );
    const authorityTaxonomySha = refusalTaxonomySha256(
      REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES,
      authorityCases
    );
    const report = {
      proof_type: PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_TYPE,
      evidence_model: 'local-disposable-installed-runtime-profile-service-proof',
      live_probing: false,
      safe_claim_ceiling: INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_SAFE_CLAIM_CEILING,
      source_preflight_artifact: JSON.parse(canonicalize(artifact)),
      source_preflight: {
        verified: true,
        read_only: true,
        body_sha256: verification.body_sha256,
        artifact_type: verification.artifact_type,
        payload_type: verification.payload_type,
        requested_profile_id: verification.requested_profile_id,
        requested_profile_sha256: verification.requested_profile_sha256,
        selected_by_explicit_id_and_sha: verification.selected_by_explicit_id_and_sha,
        selects_latest_profile: verification.selects_latest_profile,
        recognition_contract_preserved: verification.recognition_contract_preserved,
        recognition_contract_sha256: verification.recognition_contract_sha256,
        target_contract_preserved: verification.target_contract_preserved,
        target_contract_sha256: verification.target_contract_sha256,
        authority_grant_requirement_preserved:
          verification.authority_grant_requirement_preserved === true,
        exact_runtime_authority_grant_contract_deferred:
          verification.exact_runtime_authority_grant_contract_deferred === true,
        downstream_refusal_proven: verification.downstream_refusal_proven,
        profile_wide_target_authority_proven:
          verification.profile_wide_target_authority_proven,
        rightful_issuance_proven: verification.rightful_issuance_proven,
        consequence_lifecycle_closed: verification.consequence_lifecycle_closed,
        current_machine_governance_proven:
          verification.current_machine_governance_proven,
      },
      selected_profile: {
        source: 'verified-installed-runtime-profile-preflight-artifact',
        profile_id: preflight.installed_profile.profile_id,
        runtime_profile_id: preflight.installed_profile.runtime_profile_id,
        profile_sha256: preflight.installed_profile.profile_sha256,
        action_class: preflight.installed_profile.action_class,
        selected_by_explicit_id_and_sha:
          preflight.active_index.selected_by_explicit_id_and_sha,
        selects_latest_profile: preflight.active_index.selects_latest_profile,
      },
      service_boundary: {
        service_command:
          'zlar protected-records-runtime-service --config <launcher-owned-disposable-config>',
        service_process_boundary: 'local-jsonl-child-process',
        runtime_service_started: true,
        disposable_runtime_config_written: true,
        persistent_runtime_config_written: false,
        request_contract: 'receipt-record-update-and-routing-metadata-only',
        recognition_boundary: 'service-configured-recognition-rule',
        mutation_authoritative_route:
          'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation',
        consumed_authority_grant_store:
          'persistent-single-use-authority-grant-contract-sha256-store',
        consumption_identity: 'authority-grant-contract-sha256',
        signed_payload_replay_identity: 'verified-signed-payload-sha256',
        consumed_store_write_model:
          'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness',
        fixture_rightful_issuance_path_evidenced: true,
        recognition_refusal_taxonomy_separate: true,
        authority_refusal_taxonomy_separate: true,
        partial_grant_commit_burn_window_named: true,
        joint_store_anchor_witness_rollback_reuse_observed: true,
      },
      service_config_provenance: {
        config_source: 'launcher-owned-disposable-proof-config',
        config_path_exposed_to_request_stream: false,
        recognition_rule_source: 'launcher-synthesized-from-selected-profile-contract',
        recognition_rule_bound_to_selected_profile: true,
        recognition_rule_supplied_by_agent: false,
        authority_grant_source: 'launcher-owned-local-fixture-overlay',
        authority_grant_supplied_by_agent: false,
        authorized_record_update_source: 'launcher-owned-service-config',
        consumed_grant_store_source: 'launcher-owned-disposable-proof-store',
        consumed_grant_store_anchor_source: 'launcher-owned-local-proof-anchor',
        consumed_grant_store_witness_source: 'launcher-owned-local-proof-witness',
        persistent_runtime_profile_config: false,
      },
      recognition_contract: {
        source: 'selected-installed-runtime-profile-child-service',
        action_class: 'records.write',
        runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
        recognition_contract_sha256: verification.recognition_contract_sha256,
        required_refusal_cases: [...REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES],
        required_refusal_case_count:
          REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
        observed_refusal_taxonomy_sha256: recognitionTaxonomySha,
      },
      authority_contract: {
        required_refusal_cases: [...REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES],
        required_refusal_case_count:
          REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length,
        observed_refusal_taxonomy_sha256: authorityTaxonomySha,
        construction_order: [...EXACT_AUTHORITY_CONSTRUCTION_ORDER],
        public_grant_contract: JSON.parse(canonicalize(crossing.contract)),
        public_safe_grant_summary: authoritySummary,
      },
      accepted_crossing_evidence: crossingEvidence,
      accepted_runtime_transition_binding:
        primaryResults[0].runtime_transition_binding,
      target_binding: {
        consequence_path: targetBinding.consequence_path,
        target_kind: targetBinding.target_kind,
        target_scope: targetBinding.target_scope,
        target_instance_scope: targetBinding.target_instance_scope,
        target_descriptor_sha256: targetBinding.target_descriptor_sha256,
        target_handle: targetBinding.target_handle,
        target_handle_source: targetBinding.target_handle_source,
        target_binding_sha256: primaryResults[0].target_binding_sha256,
        source_profile_id: targetBinding.source_profile_id,
        source_runtime_profile_id: targetBinding.source_runtime_profile_id,
        source_profile_sha256: targetBinding.source_profile_sha256,
        source_recognition_contract_sha256:
          targetBinding.source_recognition_contract_sha256,
        source_target_contract_sha256: targetBinding.source_target_contract_sha256,
        source_preflight_body_sha256: targetBinding.source_preflight_body_sha256,
        request_target_semantics: targetBinding.request_target_semantics,
        record_update_sha256: primaryResults[0].record_update_hash,
        target_effect_sha256: primaryResults[0].target_effect_hash,
        authorized_effect_detail_sha256:
          primaryResults[0].authorized_effect_detail_sha256,
        receipt_detail_sha256: primaryResults[0].receipt_detail_hash,
        receipt_binds_authorized_effect_detail:
          primaryResults[0].receipt_detail_hash ===
            primaryResults[0].authorized_effect_detail_sha256,
        target_effect_bound_inside_authorized_effect_detail:
          crossing.contract.scope.target_effect_sha256 ===
            primaryResults[0].target_effect_hash,
        state_effect_binding_sha256: primaryResults[0].state_effect_binding_sha256,
        accepted_state_effect_binding_hash_present:
          /^[a-f0-9]{64}$/.test(primaryResults[0].state_effect_binding_sha256 || ''),
        fixture_rightful_issuance_path_evidenced: true,
        profile_wide_target_authority_proven: false,
        rightful_issuance_proven: false,
        live_target_proven: false,
        current_machine_governance_proven: false,
        consequence_lifecycle_closed: false,
      },
      target_assertion_cases: targetAssertionCases,
      correct_target_after_refusals: correctTargetAfterRefusals,
      recognized_boarding: recognizedBoarding,
      service_replay_cases: [sameProcessReplay, restartReplay],
      authority_refusal_cases: authorityCases,
      partial_commit_cases: partialCommitCases,
      joint_rollback_case: jointRollbackCase,
      refusal_cases: refusalCases,
      proof_boundary: {
        local_disposable_child_service: true,
        install_performed: false,
        activation_performed: false,
        hook_configuration_written: false,
        user_configuration_written: false,
        machine_configuration_written: false,
        live_runtime_profile_checked: false,
        live_records_system_checked: false,
        production_records_service_checked: false,
        same_process_signed_payload_replay_refused:
          sameProcessReplay.reason_code === 'receipt_replay',
        restart_consumed_authority_grant_refused:
          restartReplay.reason_code === 'authority_grant_already_consumed',
        state_append_after_grant_commit_burn_observed:
          partialCommitCases[0].reason_code ===
            'runtime_state_append_failed_after_consumed_store_commit' &&
          partialCommitCases[0].consumed_authority_grant_count === 1,
        metadata_partial_commit_burn_observed:
          partialCommitCases[1].reason_code ===
            'consumed_store_write_failed_after_grant_commit' &&
          partialCommitCases[1].consumed_authority_grant_count === 1,
        store_and_anchor_rollback_refused_while_witness_ahead:
          jointRollbackCase.store_and_anchor_only.reason_code ===
            'consumed_store_rollback_detected',
        store_anchor_and_witness_joint_rollback_detection: false,
        joint_rollback_reopened_authority_grant_reuse:
          jointRollbackCase.store_anchor_and_witness.service_write_accepted === true,
        fixture_rightful_issuance_path_evidenced: true,
        rightful_issuance_proven: false,
        portable_rightful_issuance_proven: false,
        production_rightful_issuance_proven: false,
        current_machine_governance_proven: false,
        production_downstream_recognition: false,
        external_attestation: false,
        sovereign_recognition: false,
        consequence_lifecycle_closed: false,
      },
      marker: {
        primary_recognized_state_append_count: recognizedBoarding.state_entry_count_delta,
        auxiliary_target_state_append_count:
          correctTargetAfterRefusals.state_entry_count_delta,
        joint_rollback_seed_state_append_count: jointRollbackSeed.state_entry_count_delta,
        joint_rollback_reopened_state_append_count:
          jointRollbackReopened.state_entry_count_delta,
        total_fixture_state_append_count:
          recognizedBoarding.state_entry_count_delta +
          correctTargetAfterRefusals.state_entry_count_delta +
          jointRollbackSeed.state_entry_count_delta +
          jointRollbackReopened.state_entry_count_delta,
        recognition_refusal_state_append_count: refusalCases.reduce(
          (total, item) => total + item.state_entry_count_delta,
          0
        ),
        authority_refusal_state_append_count: authorityCases.reduce(
          (total, item) => total + item.state_entry_count_delta,
          0
        ),
        replay_refusal_state_append_count: [sameProcessReplay, restartReplay].reduce(
          (total, item) => total + item.state_entry_count_delta,
          0
        ),
        partial_commit_state_append_count: partialCommitCases.reduce(
          (total, item) => total + item.state_entry_count_delta,
          0
        ),
        raw_receipt_id_present: false,
        runtime_private_issuer_material_present: false,
      },
      non_claims: [...INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_NON_CLAIMS],
    };
    assertProtectedRecordsInstalledRuntimeProfileServiceProof(report);
    return report;
  } finally {
    if (scratch) rmSync(scratch, { recursive: true, force: true });
  }
}

function assertCaseShape(label, item) {
  assertExactKeys(label, item, [
    'authority_grant_satisfied',
    'boarded',
    'case_id',
    'consumed_authority_grant_count',
    'consumed_grant_store_anchor_exists_after',
    'consumed_grant_store_exists_after',
    'consumed_grant_store_witness_exists_after',
    'decision',
    'reason_code',
    'request_ordinal',
    'runtime_transition_binding_present',
    'separate_process_from_accepted',
    'service_process_boundary',
    'service_process_invocation',
    'service_write_accepted',
    'state_entry_count_after',
    'state_entry_count_before',
    'state_entry_count_delta',
    'verified_signed_payload_identity_present',
  ]);
  if (
    item.service_process_boundary !== 'local-jsonl-child-process' ||
    item.boarded !== item.service_write_accepted ||
    item.state_entry_count_delta !== item.state_entry_count_after - item.state_entry_count_before ||
    !['accept', 'refuse'].includes(item.decision) ||
    typeof item.reason_code !== 'string'
  ) {
    throw new Error(`${label} drifted`);
  }
  return true;
}

function assertNoPrivateIssuerMaterial(label, value) {
  const forbiddenKeys = new Set([
    'grantee_issuer_kid',
    'grantee_public_key_sha256',
    'issuer_kid',
    'public_key_pem',
    'private_key_pem',
    'authority_grant_appointment',
    'signature',
  ]);
  const containsForbiddenMaterial = (value) => {
    if (typeof value === 'string') return /BEGIN (?:PUBLIC|PRIVATE) KEY/.test(value);
    if (!value || typeof value !== 'object') return false;
    return Object.entries(value).some(([key, child]) =>
      forbiddenKeys.has(key) || containsForbiddenMaterial(child)
    );
  };
  if (containsForbiddenMaterial(value)) {
    throw new Error(`${label} disclosed private issuer material`);
  }
  return true;
}

function assertPublicAuthoritySummary(summary, contract) {
  assertExactKeys(
    'Installed service proof public authority summary',
    summary,
    PUBLIC_AUTHORITY_SUMMARY_KEYS
  );
  assertProtectedRecordsFixtureAuthorityGrantSummary(summary, contract);
  assertNoPrivateIssuerMaterial('Installed service proof public authority summary', summary);
  return true;
}

function assertExactCase(label, item, expected) {
  assertCaseShape(label, item);
  const completeExpected = {
    case_id: expected.case_id,
    service_process_boundary: 'local-jsonl-child-process',
    service_process_invocation: expected.service_process_invocation,
    separate_process_from_accepted: expected.separate_process_from_accepted,
    request_ordinal: expected.request_ordinal,
    service_write_accepted: expected.accepted,
    boarded: expected.accepted,
    decision: expected.accepted ? 'accept' : 'refuse',
    reason_code: expected.reason_code,
    state_entry_count_before: expected.state_entry_count_before,
    state_entry_count_after: expected.state_entry_count_after,
    state_entry_count_delta:
      expected.state_entry_count_after - expected.state_entry_count_before,
    consumed_authority_grant_count: expected.consumed_authority_grant_count,
    authority_grant_satisfied: expected.authority_grant_satisfied,
    verified_signed_payload_identity_present:
      expected.verified_signed_payload_identity_present,
    runtime_transition_binding_present: expected.runtime_transition_binding_present,
    consumed_grant_store_exists_after: expected.consumed_grant_store_exists_after,
    consumed_grant_store_anchor_exists_after:
      expected.consumed_grant_store_anchor_exists_after,
    consumed_grant_store_witness_exists_after:
      expected.consumed_grant_store_witness_exists_after,
  };
  if (canonicalize(item) !== canonicalize(completeExpected)) {
    throw new Error(`${label} drifted`);
  }
  return true;
}

function acceptedCaseExpected(caseId, invocation, requestOrdinal) {
  return {
    case_id: caseId,
    service_process_invocation: invocation,
    separate_process_from_accepted: invocation !== 1,
    request_ordinal: requestOrdinal,
    accepted: true,
    reason_code: 'fixture_authority_grant_effect_satisfied',
    state_entry_count_before: 0,
    state_entry_count_after: 1,
    consumed_authority_grant_count: 1,
    authority_grant_satisfied: true,
    verified_signed_payload_identity_present: true,
    runtime_transition_binding_present: true,
    consumed_grant_store_exists_after: true,
    consumed_grant_store_anchor_exists_after: true,
    consumed_grant_store_witness_exists_after: true,
  };
}

function assertProtectedRecordsInstalledRuntimeProfileServiceProofBase(report) {
  assertExactKeys('Installed runtime profile service proof', report, [
    'accepted_crossing_evidence',
    'accepted_runtime_transition_binding',
    'authority_contract',
    'authority_refusal_cases',
    'correct_target_after_refusals',
    'evidence_model',
    'joint_rollback_case',
    'live_probing',
    'marker',
    'non_claims',
    'partial_commit_cases',
    'proof_boundary',
    'proof_type',
    'recognition_contract',
    'recognized_boarding',
    'refusal_cases',
    'safe_claim_ceiling',
    'selected_profile',
    'service_boundary',
    'service_config_provenance',
    'service_replay_cases',
    'source_preflight',
    'source_preflight_artifact',
    'target_assertion_cases',
    'target_binding',
  ]);
  if (
    report.proof_type !== PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_TYPE ||
    report.evidence_model !== 'local-disposable-installed-runtime-profile-service-proof' ||
    report.live_probing !== false ||
    report.safe_claim_ceiling !== INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_SAFE_CLAIM_CEILING
  ) {
    throw new Error('Installed runtime profile service proof identity drifted');
  }
  assertExactArray(
    'Installed service proof recognition refusal taxonomy',
    report.recognition_contract.required_refusal_cases,
    REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES
  );
  assertExactArray(
    'Installed service proof authority refusal taxonomy',
    report.authority_contract.required_refusal_cases,
    REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES
  );
  if (
    report.refusal_cases.length !== REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length ||
    report.authority_refusal_cases.length !== REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length
  ) {
    throw new Error('Installed service proof refusal taxonomy count drifted');
  }
  report.refusal_cases.forEach((item, index) => {
    assertCaseShape('Installed service proof recognition refusal', item);
    const caseId = REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES[index];
    if (
      item.case_id !== caseId ||
      item.reason_code !== EXPECTED_REFUSAL_REASONS[caseId] ||
      item.service_write_accepted !== false ||
      item.state_entry_count_delta !== 0
    ) {
      throw new Error(`Installed service proof recognition refusal drifted: ${caseId}`);
    }
  });
  report.authority_refusal_cases.forEach((item, index) => {
    assertCaseShape('Installed service proof authority refusal', item);
    const caseId = REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES[index];
    if (
      item.case_id !== caseId ||
      item.reason_code !== EXPECTED_AUTHORITY_REFUSAL_REASONS[caseId] ||
      item.service_write_accepted !== false ||
      item.state_entry_count_delta !== 0 ||
      item.consumed_authority_grant_count !== 0
    ) {
      throw new Error(`Installed service proof authority refusal drifted: ${caseId}`);
    }
  });
  if (
    report.recognition_contract.observed_refusal_taxonomy_sha256 !==
      refusalTaxonomySha256(
        REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
        report.refusal_cases
      ) ||
    report.authority_contract.observed_refusal_taxonomy_sha256 !==
      refusalTaxonomySha256(
        REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES,
        report.authority_refusal_cases
      )
  ) {
    throw new Error('Installed service proof refusal taxonomy hash drifted');
  }
  assertCaseShape('Installed service proof recognized boarding', report.recognized_boarding);
  if (
    report.recognized_boarding.service_write_accepted !== true ||
    report.recognized_boarding.reason_code !== 'fixture_authority_grant_effect_satisfied' ||
    report.recognized_boarding.state_entry_count_delta !== 1 ||
    report.recognized_boarding.authority_grant_satisfied !== true ||
    report.recognized_boarding.verified_signed_payload_identity_present !== true ||
    report.recognized_boarding.runtime_transition_binding_present !== true
  ) {
    throw new Error('Installed service proof recognized boarding drifted');
  }
  if (report.service_replay_cases.length !== 2) throw new Error('Installed service replay count drifted');
  report.service_replay_cases.forEach((item) => assertCaseShape('Installed service replay', item));
  if (
    report.service_replay_cases[0].reason_code !== 'receipt_replay' ||
    report.service_replay_cases[1].reason_code !== 'authority_grant_already_consumed' ||
    report.service_replay_cases.some((item) =>
      item.service_write_accepted !== false || item.state_entry_count_delta !== 0)
  ) {
    throw new Error('Installed service replay identity separation drifted');
  }
  if (report.target_assertion_cases.length !== 3) throw new Error('Installed target assertion count drifted');
  report.target_assertion_cases.forEach((item) => {
    assertCaseShape('Installed target assertion refusal', item);
    if (item.service_write_accepted !== false || item.state_entry_count_delta !== 0 || item.consumed_authority_grant_count !== 0) {
      throw new Error('Installed target assertion refusal consumed authority');
    }
  });
  assertCaseShape('Installed target recovery', report.correct_target_after_refusals);
  if (report.correct_target_after_refusals.service_write_accepted !== true) {
    throw new Error('Installed target recovery did not board');
  }
  if (report.partial_commit_cases.length !== 2) throw new Error('Installed partial commit case count drifted');
  report.partial_commit_cases.forEach((item) => assertCaseShape('Installed partial commit case', item));
  if (
    report.partial_commit_cases[0].reason_code !==
      'runtime_state_append_failed_after_consumed_store_commit' ||
    report.partial_commit_cases[1].reason_code !==
      'consumed_store_write_failed_after_grant_commit' ||
    report.partial_commit_cases.some((item) =>
      item.service_write_accepted !== false ||
      item.state_entry_count_delta !== 0 ||
      item.consumed_authority_grant_count !== 1)
  ) {
    throw new Error('Installed partial commit burn boundary drifted');
  }
  assertCaseShape('Installed joint rollback seed', report.joint_rollback_case.seed);
  assertCaseShape('Installed store-anchor rollback', report.joint_rollback_case.store_and_anchor_only);
  assertCaseShape('Installed three-file rollback', report.joint_rollback_case.store_anchor_and_witness);
  if (
    report.joint_rollback_case.seed.service_write_accepted !== true ||
    report.joint_rollback_case.store_and_anchor_only.reason_code !==
      'consumed_store_rollback_detected' ||
    report.joint_rollback_case.store_and_anchor_only.service_write_accepted !== false ||
    report.joint_rollback_case.store_anchor_and_witness.service_write_accepted !== true ||
    report.joint_rollback_case.boundary !==
      'local-store-anchor-and-witness-joint-rollback-not-detected'
  ) {
    throw new Error('Installed joint rollback side door drifted');
  }
  const transition = requireObject(
    'Installed service accepted ordered transition binding',
    report.accepted_runtime_transition_binding
  );
  if (
    transition.binding_type !== ORDERED_TRANSITION_BINDING_TYPE ||
    transition.one_launcher_store_lock_held_across_transition !== true ||
    transition.signed_payload_replay_check_preceded_effect_gate !== true ||
    transition.effect_gate_preceded_grant_store_commit !== true ||
    transition.grant_store_commit_preceded_state_append !== true ||
    transition.state_append_preceded_helper_state_promotion !== true ||
    !(transition.signed_payload_replay_check_sequence < transition.effect_gate_sequence &&
      transition.effect_gate_sequence < transition.grant_store_commit_sequence &&
      transition.grant_store_commit_sequence < transition.state_append_sequence &&
      transition.state_append_sequence < transition.helper_state_promotion_sequence)
  ) {
    throw new Error('Installed service ordered transition binding drifted');
  }
  for (const key of [
    'authority_grant_contract_sha256',
    'authority_grant_crossing_binding_sha256',
    'authorized_effect_detail_sha256',
    'signed_payload_sha256',
    'target_effect_sha256',
    'consumed_grant_store_sha256_before',
    'consumed_grant_store_sha256_after',
    'runtime_state_sha256_before',
    'runtime_state_sha256_after',
  ]) assertSha256(`Installed transition ${key}`, transition[key]);
  const target = report.target_binding;
  if (
    target.consequence_path !== PROTECTED_RECORDS_CONSEQUENCE_PATH ||
    target.target_kind !== PROTECTED_RECORDS_TARGET_KIND ||
    target.target_scope !== PROTECTED_RECORDS_TARGET_SCOPE ||
    target.target_handle !== PROTECTED_RECORDS_TARGET_HANDLE ||
    target.receipt_detail_sha256 !== target.authorized_effect_detail_sha256 ||
    target.receipt_binds_authorized_effect_detail !== true ||
    target.target_effect_bound_inside_authorized_effect_detail !== true ||
    target.target_effect_sha256 === target.receipt_detail_sha256 ||
    target.fixture_rightful_issuance_path_evidenced !== true ||
    target.rightful_issuance_proven !== false ||
    target.consequence_lifecycle_closed !== false ||
    transition.authorized_effect_detail_sha256 !== target.authorized_effect_detail_sha256 ||
    transition.target_effect_sha256 !== target.target_effect_sha256
  ) {
    throw new Error('Installed service target/effect authority binding drifted');
  }
  assertPublicAuthoritySummary(
    report.authority_contract.public_safe_grant_summary,
    report.authority_contract.public_grant_contract
  );
  if (
    report.service_boundary.recognition_refusal_taxonomy_separate !== true ||
    report.service_boundary.authority_refusal_taxonomy_separate !== true ||
    report.service_boundary.partial_grant_commit_burn_window_named !== true ||
    report.service_boundary.joint_store_anchor_witness_rollback_reuse_observed !== true ||
    report.proof_boundary.fixture_rightful_issuance_path_evidenced !== true ||
    report.proof_boundary.rightful_issuance_proven !== false ||
    report.proof_boundary.portable_rightful_issuance_proven !== false ||
    report.proof_boundary.production_rightful_issuance_proven !== false ||
    report.proof_boundary.current_machine_governance_proven !== false ||
    report.proof_boundary.consequence_lifecycle_closed !== false
  ) {
    throw new Error('Installed service claim boundary drifted');
  }
  if (
    report.marker.total_fixture_state_append_count !== 4 ||
    report.marker.recognition_refusal_state_append_count !== 0 ||
    report.marker.authority_refusal_state_append_count !== 0 ||
    report.marker.replay_refusal_state_append_count !== 0 ||
    report.marker.partial_commit_state_append_count !== 0 ||
    report.marker.raw_receipt_id_present !== false ||
    report.marker.runtime_private_issuer_material_present !== false
  ) {
    throw new Error('Installed service marker drifted');
  }
  assertExactArray(
    'Installed service proof non-claims',
    report.non_claims,
    INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_NON_CLAIMS
  );
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return true;
}

export function assertProtectedRecordsInstalledRuntimeProfileServiceProof(report) {
  assertProtectedRecordsInstalledRuntimeProfileServiceProofBase(report);

  assertExactKeys('Installed service proof source preflight', report.source_preflight, SOURCE_PREFLIGHT_KEYS);
  assertExactKeys('Installed service proof selected profile', report.selected_profile, SELECTED_PROFILE_KEYS);
  assertExactKeys('Installed service proof service boundary', report.service_boundary, SERVICE_BOUNDARY_KEYS);
  assertExactKeys(
    'Installed service proof config provenance',
    report.service_config_provenance,
    SERVICE_CONFIG_PROVENANCE_KEYS
  );
  assertExactKeys(
    'Installed service proof recognition contract',
    report.recognition_contract,
    RECOGNITION_CONTRACT_KEYS
  );
  assertExactKeys(
    'Installed service proof authority contract',
    report.authority_contract,
    AUTHORITY_CONTRACT_KEYS
  );
  assertExactKeys('Installed service proof target binding', report.target_binding, TARGET_BINDING_KEYS);
  assertExactKeys('Installed service proof boundary', report.proof_boundary, PROOF_BOUNDARY_KEYS);
  assertExactKeys('Installed service proof marker', report.marker, MARKER_KEYS);
  assertExactKeys(
    'Installed service proof accepted transition',
    report.accepted_runtime_transition_binding,
    TRANSITION_KEYS
  );
  assertExactKeys(
    'Installed service proof accepted crossing evidence',
    report.accepted_crossing_evidence,
    CROSSING_EVIDENCE_KEYS
  );
  assertExactKeys('Installed service proof joint rollback case', report.joint_rollback_case, [
    'boundary', 'seed', 'store_anchor_and_witness', 'store_and_anchor_only',
  ]);

  const embeddedPreflightVerification =
    verifyProtectedRecordsInstalledRuntimeProfilePreflightArtifact(
      report.source_preflight_artifact
    );
  assertPreflightBoundary(embeddedPreflightVerification);
  const embeddedPreflight = report.source_preflight_artifact.payload.preflight;
  const expectedSourcePreflight = {
    verified: true,
    read_only: true,
    body_sha256: embeddedPreflightVerification.body_sha256,
    artifact_type: embeddedPreflightVerification.artifact_type,
    payload_type: embeddedPreflightVerification.payload_type,
    requested_profile_id: embeddedPreflightVerification.requested_profile_id,
    requested_profile_sha256: embeddedPreflightVerification.requested_profile_sha256,
    selected_by_explicit_id_and_sha:
      embeddedPreflightVerification.selected_by_explicit_id_and_sha,
    selects_latest_profile: embeddedPreflightVerification.selects_latest_profile,
    recognition_contract_preserved:
      embeddedPreflightVerification.recognition_contract_preserved,
    recognition_contract_sha256:
      embeddedPreflightVerification.recognition_contract_sha256,
    target_contract_preserved: embeddedPreflightVerification.target_contract_preserved,
    target_contract_sha256: embeddedPreflightVerification.target_contract_sha256,
    authority_grant_requirement_preserved:
      embeddedPreflightVerification.authority_grant_requirement_preserved,
    exact_runtime_authority_grant_contract_deferred:
      embeddedPreflightVerification.exact_runtime_authority_grant_contract_deferred,
    downstream_refusal_proven: embeddedPreflightVerification.downstream_refusal_proven,
    profile_wide_target_authority_proven:
      embeddedPreflightVerification.profile_wide_target_authority_proven,
    rightful_issuance_proven: embeddedPreflightVerification.rightful_issuance_proven,
    consequence_lifecycle_closed:
      embeddedPreflightVerification.consequence_lifecycle_closed,
    current_machine_governance_proven:
      embeddedPreflightVerification.current_machine_governance_proven,
  };
  assertCanonicalEqual(
    'Installed service proof source preflight projection',
    report.source_preflight,
    expectedSourcePreflight
  );
  assertCanonicalEqual('Installed service proof selected profile projection', report.selected_profile, {
    source: 'verified-installed-runtime-profile-preflight-artifact',
    profile_id: embeddedPreflight.installed_profile.profile_id,
    runtime_profile_id: embeddedPreflight.installed_profile.runtime_profile_id,
    profile_sha256: embeddedPreflight.installed_profile.profile_sha256,
    action_class: embeddedPreflight.installed_profile.action_class,
    selected_by_explicit_id_and_sha:
      embeddedPreflight.active_index.selected_by_explicit_id_and_sha,
    selects_latest_profile: embeddedPreflight.active_index.selects_latest_profile,
  });
  if (
    embeddedPreflightVerification.recognition_contract_sha256 !==
      protectedRecordsInstalledRuntimeProfileRecognitionContractSha256(
        embeddedPreflight.recognition_contract
      ) ||
    embeddedPreflightVerification.target_contract_sha256 !==
      protectedRecordsInstalledRuntimeProfileTargetContractSha256(
        embeddedPreflight.target_contract
      )
  ) {
    throw new Error('Installed service proof embedded preflight contract digest drifted');
  }

  assertCanonicalEqual('Installed service proof service boundary contract', report.service_boundary, {
    service_command:
      'zlar protected-records-runtime-service --config <launcher-owned-disposable-config>',
    service_process_boundary: 'local-jsonl-child-process',
    runtime_service_started: true,
    disposable_runtime_config_written: true,
    persistent_runtime_config_written: false,
    request_contract: 'receipt-record-update-and-routing-metadata-only',
    recognition_boundary: 'service-configured-recognition-rule',
    mutation_authoritative_route:
      'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation',
    consumed_authority_grant_store:
      'persistent-single-use-authority-grant-contract-sha256-store',
    consumption_identity: 'authority-grant-contract-sha256',
    signed_payload_replay_identity: 'verified-signed-payload-sha256',
    consumed_store_write_model:
      'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness',
    fixture_rightful_issuance_path_evidenced: true,
    recognition_refusal_taxonomy_separate: true,
    authority_refusal_taxonomy_separate: true,
    partial_grant_commit_burn_window_named: true,
    joint_store_anchor_witness_rollback_reuse_observed: true,
  });
  assertCanonicalEqual(
    'Installed service proof config provenance contract',
    report.service_config_provenance,
    {
      config_source: 'launcher-owned-disposable-proof-config',
      config_path_exposed_to_request_stream: false,
      recognition_rule_source: 'launcher-synthesized-from-selected-profile-contract',
      recognition_rule_bound_to_selected_profile: true,
      recognition_rule_supplied_by_agent: false,
      authority_grant_source: 'launcher-owned-local-fixture-overlay',
      authority_grant_supplied_by_agent: false,
      authorized_record_update_source: 'launcher-owned-service-config',
      consumed_grant_store_source: 'launcher-owned-disposable-proof-store',
      consumed_grant_store_anchor_source: 'launcher-owned-local-proof-anchor',
      consumed_grant_store_witness_source: 'launcher-owned-local-proof-witness',
      persistent_runtime_profile_config: false,
    }
  );

  report.refusal_cases.forEach((item, index) => {
    const caseId = REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES[index];
    assertExactCase(`Installed service proof recognition refusal ${caseId}`, item, {
      case_id: caseId,
      service_process_invocation: 1,
      separate_process_from_accepted: false,
      request_ordinal: index + 3,
      accepted: false,
      reason_code: EXPECTED_REFUSAL_REASONS[caseId],
      state_entry_count_before: 1,
      state_entry_count_after: 1,
      consumed_authority_grant_count: 1,
      authority_grant_satisfied: false,
      verified_signed_payload_identity_present: false,
      runtime_transition_binding_present: false,
      consumed_grant_store_exists_after: true,
      consumed_grant_store_anchor_exists_after: true,
      consumed_grant_store_witness_exists_after: true,
    });
  });
  report.authority_refusal_cases.forEach((item, index) => {
    const caseId = REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES[index];
    assertExactCase(`Installed service proof authority refusal ${caseId}`, item, {
      case_id: caseId,
      service_process_invocation: index + 4,
      separate_process_from_accepted: true,
      request_ordinal: 1,
      accepted: false,
      reason_code: EXPECTED_AUTHORITY_REFUSAL_REASONS[caseId],
      state_entry_count_before: 0,
      state_entry_count_after: 0,
      consumed_authority_grant_count: 0,
      authority_grant_satisfied: false,
      verified_signed_payload_identity_present: index < 4,
      runtime_transition_binding_present: false,
      consumed_grant_store_exists_after: false,
      consumed_grant_store_anchor_exists_after: false,
      consumed_grant_store_witness_exists_after: false,
    });
  });
  assertExactCase(
    'Installed service proof recognized boarding',
    report.recognized_boarding,
    acceptedCaseExpected('recognized_installed_profile_service_write', 1, 1)
  );
  assertExactCase('Installed service proof same-process replay', report.service_replay_cases[0], {
    case_id: 'replay_installed_profile_service_write_refused_same_process',
    service_process_invocation: 1,
    separate_process_from_accepted: false,
    request_ordinal: 2,
    accepted: false,
    reason_code: 'receipt_replay',
    state_entry_count_before: 1,
    state_entry_count_after: 1,
    consumed_authority_grant_count: 1,
    authority_grant_satisfied: false,
    verified_signed_payload_identity_present: true,
    runtime_transition_binding_present: false,
    consumed_grant_store_exists_after: true,
    consumed_grant_store_anchor_exists_after: true,
    consumed_grant_store_witness_exists_after: true,
  });
  assertExactCase('Installed service proof restart replay', report.service_replay_cases[1], {
    case_id: 'replay_installed_profile_service_write_refused_after_service_restart',
    service_process_invocation: 2,
    separate_process_from_accepted: true,
    request_ordinal: 1,
    accepted: false,
    reason_code: 'authority_grant_already_consumed',
    state_entry_count_before: 0,
    state_entry_count_after: 0,
    consumed_authority_grant_count: 1,
    authority_grant_satisfied: false,
    verified_signed_payload_identity_present: true,
    runtime_transition_binding_present: false,
    consumed_grant_store_exists_after: true,
    consumed_grant_store_anchor_exists_after: true,
    consumed_grant_store_witness_exists_after: true,
  });
  const targetRefusalIds = [
    ['wrong_target_assertion_refused_before_runtime_mutation', 'target_assertion_mismatch'],
    ['missing_target_assertion_refused_before_runtime_mutation', 'target_assertion_missing'],
    ['malformed_target_assertion_refused_before_runtime_mutation', 'target_assertion_malformed'],
  ];
  report.target_assertion_cases.forEach((item, index) => {
    const [caseId, reasonCode] = targetRefusalIds[index];
    assertExactCase(`Installed service proof target refusal ${caseId}`, item, {
      case_id: caseId,
      service_process_invocation: 3,
      separate_process_from_accepted: true,
      request_ordinal: index + 1,
      accepted: false,
      reason_code: reasonCode,
      state_entry_count_before: 0,
      state_entry_count_after: 0,
      consumed_authority_grant_count: 0,
      authority_grant_satisfied: false,
      verified_signed_payload_identity_present: false,
      runtime_transition_binding_present: false,
      consumed_grant_store_exists_after: true,
      consumed_grant_store_anchor_exists_after: true,
      consumed_grant_store_witness_exists_after: true,
    });
  });
  assertExactCase(
    'Installed service proof correct target recovery',
    report.correct_target_after_refusals,
    acceptedCaseExpected('correct_target_after_target_refusals_boards', 3, 4)
  );
  assertExactCase('Installed service proof state append burn', report.partial_commit_cases[0], {
    case_id: 'runtime_state_append_failed_after_consumed_store_commit',
    service_process_invocation: 9,
    separate_process_from_accepted: true,
    request_ordinal: 1,
    accepted: false,
    reason_code: 'runtime_state_append_failed_after_consumed_store_commit',
    state_entry_count_before: 0,
    state_entry_count_after: 0,
    consumed_authority_grant_count: 1,
    authority_grant_satisfied: false,
    verified_signed_payload_identity_present: true,
    runtime_transition_binding_present: false,
    consumed_grant_store_exists_after: true,
    consumed_grant_store_anchor_exists_after: true,
    consumed_grant_store_witness_exists_after: true,
  });
  assertExactCase('Installed service proof witness commit burn', report.partial_commit_cases[1], {
    case_id: 'witness_commit_failed_after_authority_grant_store_commit',
    service_process_invocation: 10,
    separate_process_from_accepted: true,
    request_ordinal: 1,
    accepted: false,
    reason_code: 'consumed_store_write_failed_after_grant_commit',
    state_entry_count_before: 0,
    state_entry_count_after: 0,
    consumed_authority_grant_count: 1,
    authority_grant_satisfied: true,
    verified_signed_payload_identity_present: true,
    runtime_transition_binding_present: false,
    consumed_grant_store_exists_after: true,
    consumed_grant_store_anchor_exists_after: true,
    consumed_grant_store_witness_exists_after: false,
  });
  assertExactCase(
    'Installed service proof joint rollback seed',
    report.joint_rollback_case.seed,
    acceptedCaseExpected('joint_rollback_seed_boarded', 11, 1)
  );
  assertExactCase(
    'Installed service proof store and anchor rollback',
    report.joint_rollback_case.store_and_anchor_only,
    {
      case_id: 'store_and_anchor_joint_rollback_refused_by_witness_before_runtime_mutation',
      service_process_invocation: 12,
      separate_process_from_accepted: true,
      request_ordinal: 1,
      accepted: false,
      reason_code: 'consumed_store_rollback_detected',
      state_entry_count_before: 0,
      state_entry_count_after: 0,
      consumed_authority_grant_count: 0,
      authority_grant_satisfied: false,
      verified_signed_payload_identity_present: true,
      runtime_transition_binding_present: false,
      consumed_grant_store_exists_after: true,
      consumed_grant_store_anchor_exists_after: true,
      consumed_grant_store_witness_exists_after: true,
    }
  );
  assertExactCase(
    'Installed service proof joint rollback reopening',
    report.joint_rollback_case.store_anchor_and_witness,
    acceptedCaseExpected(
      'store_anchor_and_witness_joint_rollback_reopened_authority_grant_reuse',
      13,
      1
    )
  );
  if (
    report.joint_rollback_case.boundary !==
      'local-store-anchor-and-witness-joint-rollback-not-detected'
  ) {
    throw new Error('Installed service proof joint rollback boundary drifted');
  }

  const recognitionTaxonomySha = refusalTaxonomySha256(
    REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
    report.refusal_cases
  );
  const authorityTaxonomySha = refusalTaxonomySha256(
    REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES,
    report.authority_refusal_cases
  );
  assertCanonicalEqual('Installed service proof recognition contract projection', report.recognition_contract, {
    source: 'selected-installed-runtime-profile-child-service',
    action_class: 'records.write',
    runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    recognition_contract_sha256: embeddedPreflightVerification.recognition_contract_sha256,
    required_refusal_cases: [...REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES],
    required_refusal_case_count:
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
    observed_refusal_taxonomy_sha256: recognitionTaxonomySha,
  });
  assertExactArray(
    'Installed service proof authority construction order',
    report.authority_contract.construction_order,
    EXACT_AUTHORITY_CONSTRUCTION_ORDER
  );
  if (
    report.authority_contract.required_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length ||
    report.authority_contract.observed_refusal_taxonomy_sha256 !== authorityTaxonomySha
  ) {
    throw new Error('Installed service proof authority contract taxonomy drifted');
  }

  const publicContract = report.authority_contract.public_grant_contract;
  assertProtectedRecordsFixtureAuthorityGrantContract(publicContract);
  assertNoPrivateIssuerMaterial('Installed service proof public grant contract', publicContract);
  const authorityGrantContractSha256 =
    protectedRecordsFixtureAuthorityGrantContractSha256(publicContract);
  const reconstructedTargetBinding = createProtectedRecordsRuntimeTargetBinding({
    sourceProfileId: embeddedPreflight.installed_profile.profile_id,
    sourceRuntimeProfileId: embeddedPreflight.installed_profile.runtime_profile_id,
    sourceProfileSha256: embeddedPreflight.installed_profile.profile_sha256,
    sourceRecognitionContractSha256:
      embeddedPreflightVerification.recognition_contract_sha256,
    sourceTargetContractSha256: embeddedPreflightVerification.target_contract_sha256,
    sourcePreflightBodySha256: embeddedPreflightVerification.body_sha256,
    sourceActionClass: embeddedPreflight.installed_profile.action_class,
  });
  const targetBindingSha256 = sha256hex(canonicalize(reconstructedTargetBinding));
  const recordUpdate = baseRecordUpdate();
  const recordUpdateSha256 = sha256hex(canonicalize(recordUpdate));
  const targetEffect = protectedRecordsTargetEffect({
    targetHandle: reconstructedTargetBinding.target_handle,
    recordUpdate,
  });
  const targetEffectSha256 = sha256hex(canonicalize(targetEffect));
  const authorizedEffectDetail = protectedRecordsAuthorizedEffectDetail({
    contract: publicContract,
    targetEffect,
  });
  const authorizedEffectDetailSha256 = protectedRecordsAuthorizedEffectDetailSha256(
    authorizedEffectDetail,
    publicContract
  );
  const expectedGrantScope = {
    consequence_path: PROTECTED_RECORDS_CONSEQUENCE_PATH,
    action_class: 'records.write',
    target_kind: PROTECTED_RECORDS_TARGET_KIND,
    target_scope: PROTECTED_RECORDS_TARGET_SCOPE,
    target_instance_scope: 'logical-fixture-not-per-run',
    target_handle: PROTECTED_RECORDS_TARGET_HANDLE,
    launcher_target_binding_sha256: targetBindingSha256,
    record_update_sha256: recordUpdateSha256,
    target_effect_sha256: targetEffectSha256,
    profile_id: embeddedPreflight.installed_profile.profile_id,
    runtime_profile_id: embeddedPreflight.installed_profile.runtime_profile_id,
    profile_sha256: embeddedPreflight.installed_profile.profile_sha256,
    recognition_contract_sha256:
      embeddedPreflightVerification.recognition_contract_sha256,
    target_contract_sha256: embeddedPreflightVerification.target_contract_sha256,
    policy_version: 'recognition-policy-v1',
    receipt_version: 1,
    receipt_type: 'governed-action',
    receipt_domain: 'records',
    receipt_rule: 'RRECORDS_ALLOW',
    receipt_authorizer: 'policy',
    receipt_outcome: 'allow',
  };
  assertCanonicalEqual(
    'Installed service proof public grant exact scope',
    publicContract.scope,
    expectedGrantScope
  );
  if (
    publicContract.time_policy.expires_at_epoch -
      publicContract.time_policy.valid_from_epoch !== 150
  ) {
    throw new Error('Installed service proof public grant time scope drifted');
  }
  assertPublicAuthoritySummary(
    report.authority_contract.public_safe_grant_summary,
    publicContract
  );

  const evidence = report.accepted_crossing_evidence;
  for (const key of CROSSING_EVIDENCE_KEYS.filter((key) =>
    key.endsWith('_sha256')
  )) {
    assertSha256(`Installed service crossing evidence ${key}`, evidence[key]);
  }
  if (
    typeof evidence.verified_signed_payload_base64url !== 'string' ||
    !/^[A-Za-z0-9_-]+$/.test(evidence.verified_signed_payload_base64url) ||
    Buffer.from(evidence.verified_signed_payload_base64url, 'base64url').toString('base64url') !==
      evidence.verified_signed_payload_base64url ||
    evidence.evidence_type !== ACCEPTED_CROSSING_EVIDENCE_TYPE
  ) {
    throw new Error('Installed service proof signed payload encoding drifted');
  }
  assertProtectedRecordsFixtureAuthorityGrantDecision(
    evidence.issuance_decision,
    publicContract,
    'issuance',
    { requireAccepted: true }
  );
  assertProtectedRecordsFixtureAuthorityGrantDecision(
    evidence.effect_decision,
    publicContract,
    'effect',
    { requireAccepted: true }
  );
  assertNoPrivateIssuerMaterial(
    'Installed service proof accepted crossing decisions',
    { issuance_decision: evidence.issuance_decision, effect_decision: evidence.effect_decision }
  );
  if (
    evidence.issuance_decision_sha256 !==
      sha256hex(canonicalize(evidence.issuance_decision)) ||
    evidence.effect_decision_sha256 !==
      sha256hex(canonicalize(evidence.effect_decision))
  ) {
    throw new Error('Installed service proof accepted decision digest drifted');
  }
  const fixtureNowEpoch = publicContract.time_policy.valid_from_epoch + 30;
  const reconstructedUnsignedReceipt = createReceiptV1FromEvent(eventFixture({
    auditEventId: SERVICE_PROOF_RECOGNIZED_AUDIT_EVENT_ID,
    detail: authorizedEffectDetail,
    issuedAtEpoch: fixtureNowEpoch - 5,
  }));
  const signedPayloadBytes = Buffer.from(
    evidence.verified_signed_payload_base64url,
    'base64url'
  );
  const signedPayloadSha256 = sha256hex(signedPayloadBytes);
  if (
    reconstructedUnsignedReceipt.payload !== evidence.verified_signed_payload_base64url ||
    evidence.signed_payload_sha256 !== signedPayloadSha256 ||
    evidence.signed_receipt_envelope_sha256 === evidence.unsigned_receipt_envelope_sha256
  ) {
    throw new Error('Installed service proof reconstructed signed payload drifted');
  }
  const issuanceBinding = evidence.issuance_decision.binding;
  const effectBinding = evidence.effect_decision.binding;
  const expectedCrossingBindingSha256 = sha256hex(canonicalize({
    authority_grant_contract_sha256: authorityGrantContractSha256,
    authorized_effect_detail_sha256: authorizedEffectDetailSha256,
    signed_payload_sha256: signedPayloadSha256,
    receipt_semantic_binding_sha256: effectBinding.receipt_semantic_binding_sha256,
  }));
  for (const binding of [issuanceBinding, effectBinding]) {
    if (
      binding.authority_grant_contract_sha256 !== authorityGrantContractSha256 ||
      binding.authorized_effect_detail_sha256 !== authorizedEffectDetailSha256 ||
      binding.signed_payload_sha256 !== signedPayloadSha256 ||
      binding.receipt_semantic_binding_sha256 !==
        effectBinding.receipt_semantic_binding_sha256 ||
      binding.crossing_binding_sha256 !== expectedCrossingBindingSha256
    ) {
      throw new Error('Installed service proof issuance/effect crossing link drifted');
    }
  }
  const crossingProjection = {
    source_preflight_body_sha256: embeddedPreflightVerification.body_sha256,
    selected_profile_sha256: embeddedPreflight.installed_profile.profile_sha256,
    recognition_contract_sha256:
      embeddedPreflightVerification.recognition_contract_sha256,
    target_contract_sha256: embeddedPreflightVerification.target_contract_sha256,
    target_binding_sha256: targetBindingSha256,
    authority_grant_contract_sha256: authorityGrantContractSha256,
    authority_grant_crossing_binding_sha256: expectedCrossingBindingSha256,
    receipt_semantic_binding_sha256: effectBinding.receipt_semantic_binding_sha256,
    signed_payload_sha256: signedPayloadSha256,
    authority_construction_order_sha256:
      sha256hex(canonicalize(EXACT_AUTHORITY_CONSTRUCTION_ORDER)),
    authorized_effect_detail_sha256: authorizedEffectDetailSha256,
    receipt_detail_sha256: authorizedEffectDetailSha256,
    record_update_sha256: recordUpdateSha256,
    target_effect_sha256: targetEffectSha256,
  };
  for (const [key, expected] of Object.entries(crossingProjection)) {
    if (evidence[key] !== expected) {
      throw new Error(`Installed service proof accepted crossing ${key} drifted`);
    }
  }

  const stateEntry = {
    entry_type: 'protected-records-runtime-state-entry-v2',
    audit_event_id: SERVICE_PROOF_RECOGNIZED_AUDIT_EVENT_ID,
    authority_grant_contract_sha256: authorityGrantContractSha256,
    authority_grant_crossing_binding_sha256: expectedCrossingBindingSha256,
    authorized_effect_detail_sha256: authorizedEffectDetailSha256,
    target_handle: PROTECTED_RECORDS_TARGET_HANDLE,
    target_effect_sha256: targetEffectSha256,
    receipt_detail_sha256: authorizedEffectDetailSha256,
    record_update_sha256: recordUpdateSha256,
    verified_signed_payload_sha256: signedPayloadSha256,
    verified_signed_payload_identity_present: true,
    service_transition: 'protected_records_runtime_authorized_write_accepted',
  };
  const stateEffectBindingSha256 = sha256hex(canonicalize(stateEntry));
  if (evidence.state_effect_binding_sha256 !== stateEffectBindingSha256) {
    throw new Error('Installed service proof state effect binding drifted');
  }
  const consumedStoreBefore = normalizedConsumedGrantStore([]);
  const consumedStoreAfter = normalizedConsumedGrantStore([authorityGrantContractSha256]);
  const expectedTransition = {
    binding_type: ORDERED_TRANSITION_BINDING_TYPE,
    authority_grant_contract_sha256: authorityGrantContractSha256,
    authority_grant_crossing_binding_sha256: expectedCrossingBindingSha256,
    authorized_effect_detail_sha256: authorizedEffectDetailSha256,
    signed_payload_sha256: signedPayloadSha256,
    target_effect_sha256: targetEffectSha256,
    consumed_grant_store_sha256_before: sha256hex(canonicalize(consumedStoreBefore)),
    consumed_grant_store_sha256_after: sha256hex(canonicalize(consumedStoreAfter)),
    runtime_state_sha256_before: sha256hex(canonicalize({
      state_type: 'protected-records-runtime-process-private-state-v1',
      entries: [],
    })),
    runtime_state_sha256_after: sha256hex(canonicalize({
      state_type: 'protected-records-runtime-process-private-state-v1',
      entries: [stateEntry],
    })),
    authority_grant_consumption_count_before: 0,
    authority_grant_consumption_count_after: 1,
    state_entry_count_before: 0,
    state_entry_count_after: 1,
    signed_payload_replay_check_sequence: 1,
    effect_gate_sequence: 2,
    grant_store_commit_sequence: 3,
    state_append_sequence: 4,
    helper_state_promotion_sequence: 5,
    signed_payload_replay_check_preceded_effect_gate: true,
    effect_gate_preceded_grant_store_commit: true,
    grant_store_commit_preceded_state_append: true,
    state_append_preceded_helper_state_promotion: true,
    one_launcher_store_lock_held_across_transition: true,
  };
  assertCanonicalEqual(
    'Installed service proof accepted ordered transition reconstruction',
    report.accepted_runtime_transition_binding,
    expectedTransition
  );

  assertCanonicalEqual('Installed service proof target binding reconstruction', report.target_binding, {
    consequence_path: PROTECTED_RECORDS_CONSEQUENCE_PATH,
    target_kind: PROTECTED_RECORDS_TARGET_KIND,
    target_scope: PROTECTED_RECORDS_TARGET_SCOPE,
    target_instance_scope: reconstructedTargetBinding.target_instance_scope,
    target_descriptor_sha256: reconstructedTargetBinding.target_descriptor_sha256,
    target_handle: PROTECTED_RECORDS_TARGET_HANDLE,
    target_handle_source: reconstructedTargetBinding.target_handle_source,
    target_binding_sha256: targetBindingSha256,
    source_profile_id: embeddedPreflight.installed_profile.profile_id,
    source_runtime_profile_id: embeddedPreflight.installed_profile.runtime_profile_id,
    source_profile_sha256: embeddedPreflight.installed_profile.profile_sha256,
    source_recognition_contract_sha256:
      embeddedPreflightVerification.recognition_contract_sha256,
    source_target_contract_sha256: embeddedPreflightVerification.target_contract_sha256,
    source_preflight_body_sha256: embeddedPreflightVerification.body_sha256,
    request_target_semantics: reconstructedTargetBinding.request_target_semantics,
    record_update_sha256: recordUpdateSha256,
    target_effect_sha256: targetEffectSha256,
    authorized_effect_detail_sha256: authorizedEffectDetailSha256,
    receipt_detail_sha256: authorizedEffectDetailSha256,
    receipt_binds_authorized_effect_detail: true,
    target_effect_bound_inside_authorized_effect_detail: true,
    state_effect_binding_sha256: stateEffectBindingSha256,
    accepted_state_effect_binding_hash_present: true,
    fixture_rightful_issuance_path_evidenced: true,
    profile_wide_target_authority_proven: false,
    rightful_issuance_proven: false,
    live_target_proven: false,
    current_machine_governance_proven: false,
    consequence_lifecycle_closed: false,
  });

  assertCanonicalEqual('Installed service proof claim boundary', report.proof_boundary, {
    local_disposable_child_service: true,
    install_performed: false,
    activation_performed: false,
    hook_configuration_written: false,
    user_configuration_written: false,
    machine_configuration_written: false,
    live_runtime_profile_checked: false,
    live_records_system_checked: false,
    production_records_service_checked: false,
    same_process_signed_payload_replay_refused: true,
    restart_consumed_authority_grant_refused: true,
    state_append_after_grant_commit_burn_observed: true,
    metadata_partial_commit_burn_observed: true,
    store_and_anchor_rollback_refused_while_witness_ahead: true,
    store_anchor_and_witness_joint_rollback_detection: false,
    joint_rollback_reopened_authority_grant_reuse: true,
    fixture_rightful_issuance_path_evidenced: true,
    rightful_issuance_proven: false,
    portable_rightful_issuance_proven: false,
    production_rightful_issuance_proven: false,
    current_machine_governance_proven: false,
    production_downstream_recognition: false,
    external_attestation: false,
    sovereign_recognition: false,
    consequence_lifecycle_closed: false,
  });
  assertCanonicalEqual('Installed service proof exact marker counts', report.marker, {
    primary_recognized_state_append_count: 1,
    auxiliary_target_state_append_count: 1,
    joint_rollback_seed_state_append_count: 1,
    joint_rollback_reopened_state_append_count: 1,
    total_fixture_state_append_count: 4,
    recognition_refusal_state_append_count: 0,
    authority_refusal_state_append_count: 0,
    replay_refusal_state_append_count: 0,
    partial_commit_state_append_count: 0,
    raw_receipt_id_present: false,
    runtime_private_issuer_material_present: false,
  });
  assertNoPrivateIssuerMaterial('Installed service proof public authority evidence', {
    authority_contract: report.authority_contract,
    accepted_crossing_evidence: report.accepted_crossing_evidence,
  });
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return true;
}

export function formatProtectedRecordsInstalledRuntimeProfileServiceProofSummary(report) {
  assertProtectedRecordsInstalledRuntimeProfileServiceProof(report);
  const authorityGrantStatus = protectedRecordsFixtureAuthorityGrantStatus(
    report.authority_contract.public_safe_grant_summary
      .authority_grant_contract_sha256,
  );
  const lines = [
    'ZLAR Protected Records Installed Runtime Profile Service Proof v1',
    `source_preflight_sha256=${report.source_preflight.body_sha256}; source_downstream_refusal_proven=${report.source_preflight.downstream_refusal_proven}`,
    `runtime_service_started=${report.service_boundary.runtime_service_started}; mutation_authoritative_route=${report.service_boundary.mutation_authoritative_route}`,
    `historical_artifact_fixture_rightful_issuance_path_recorded=${report.proof_boundary.fixture_rightful_issuance_path_evidenced}; authority_grant_status=${authorityGrantStatus.status}; current_fixture_rightful_issuance_path_evidenced=false; rightful_issuance_proven=${report.proof_boundary.rightful_issuance_proven}`,
    `authority_domain_id=${report.authority_contract.public_safe_grant_summary.authority_domain_id}; grantor_role_id=${report.authority_contract.public_safe_grant_summary.grantor_role_id}; authority_grant_contract_sha256=${report.authority_contract.public_safe_grant_summary.authority_grant_contract_sha256}`,
    `ordered_transition_binding_type=${report.accepted_runtime_transition_binding.binding_type}; one_launcher_store_lock_held=${report.accepted_runtime_transition_binding.one_launcher_store_lock_held_across_transition}`,
    `target_handle_source=${report.target_binding.target_handle_source}; receipt_binds_authorized_effect_detail=${report.target_binding.receipt_binds_authorized_effect_detail}; target_effect_bound_inside_authorized_effect_detail=${report.target_binding.target_effect_bound_inside_authorized_effect_detail}`,
    `Boarded: ${report.recognized_boarding.case_id}; decision=${report.recognized_boarding.decision}; marker_delta=${report.recognized_boarding.state_entry_count_delta}`,
    `same_process_signed_payload_replay_reason=${report.service_replay_cases[0].reason_code}; restart_consumed_grant_reason=${report.service_replay_cases[1].reason_code}`,
    `recognition_refusal_cases=${report.refusal_cases.length}; authority_refusal_cases=${report.authority_refusal_cases.length}; taxonomies_separate=${report.service_boundary.recognition_refusal_taxonomy_separate && report.service_boundary.authority_refusal_taxonomy_separate}`,
    `state_append_after_grant_commit_burn_observed=${report.proof_boundary.state_append_after_grant_commit_burn_observed}; metadata_partial_commit_burn_observed=${report.proof_boundary.metadata_partial_commit_burn_observed}`,
    `store_and_anchor_rollback_refused_while_witness_ahead=${report.proof_boundary.store_and_anchor_rollback_refused_while_witness_ahead}; store_anchor_and_witness_joint_rollback_detection=${report.proof_boundary.store_anchor_and_witness_joint_rollback_detection}; joint_rollback_reopened_authority_grant_reuse=${report.proof_boundary.joint_rollback_reopened_authority_grant_reuse}`,
    `install_performed=${report.proof_boundary.install_performed}; current_machine_governance_proven=${report.proof_boundary.current_machine_governance_proven}; consequence_lifecycle_closed=${report.proof_boundary.consequence_lifecycle_closed}`,
    'Recognition refusals:',
    ...report.refusal_cases.map((item) => `- ${item.case_id}: ${item.reason_code}`),
    'Authority refusals:',
    ...report.authority_refusal_cases.map((item) => `- ${item.case_id}: ${item.reason_code}`),
    'Non-claims:',
    ...report.non_claims.map((item) => `- ${item}`),
  ];
  const output = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  return output;
}

function artifactBody(payload) {
  return {
    artifact_type: PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_TYPE,
    canonicalization:
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_CANONICALIZATION,
    generator: 'zlar protected-records-installed-runtime-profile-service-proof --artifact',
    hash_scope: 'canonical artifact body without integrity',
    payload,
  };
}

export function protectedRecordsInstalledRuntimeProfileServiceProofArtifactBodySha256(report) {
  assertProtectedRecordsInstalledRuntimeProfileServiceProof(report);
  return sha256hex(canonicalize(artifactBody({ proof: report })));
}

export function buildProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(report) {
  assertProtectedRecordsInstalledRuntimeProfileServiceProof(report);
  const body = artifactBody({ proof: report });
  const artifact = {
    ...body,
    integrity: { algorithm: 'SHA-256', body_sha256: sha256hex(canonicalize(body)) },
  };
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(artifact);
  return artifact;
}

export function assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(artifact) {
  assertExactKeys('Installed service proof artifact', artifact, [
    'artifact_type', 'canonicalization', 'generator', 'hash_scope', 'integrity', 'payload',
  ]);
  if (
    artifact.artifact_type !== PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_TYPE ||
    artifact.canonicalization !== PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_CANONICALIZATION ||
    artifact.generator !== 'zlar protected-records-installed-runtime-profile-service-proof --artifact' ||
    artifact.hash_scope !== 'canonical artifact body without integrity'
  ) {
    throw new Error('Installed service proof artifact boundary drifted');
  }
  assertExactKeys('Installed service proof artifact payload', artifact.payload, ['proof']);
  assertProtectedRecordsInstalledRuntimeProfileServiceProof(artifact.payload.proof);
  assertExactKeys('Installed service proof artifact integrity', artifact.integrity, [
    'algorithm', 'body_sha256',
  ]);
  const { integrity, ...body } = artifact;
  if (
    integrity.algorithm !== 'SHA-256' ||
    integrity.body_sha256 !== sha256hex(canonicalize(body))
  ) {
    throw new Error('Installed service proof artifact SHA-256 mismatch');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(artifact));
  return true;
}

export function writeProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(artifact, outputPath) {
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(artifact);
  if (!outputPath || outputPath === '-') throw new Error('Installed service proof artifact output path is required');
  mkdirSync(dirname(outputPath), { recursive: true });
  const output = `${JSON.stringify(artifact, null, 2)}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  writeFileSync(outputPath, output, { mode: 0o600 });
  return artifact.integrity.body_sha256;
}

export function parseProtectedRecordsInstalledRuntimeProfileServiceProofArtifactText(text) {
  assertNoUnsafeProtectedRecordsRuntimeProfileText(text);
  let artifact;
  try {
    artifact = JSON.parse(text);
  } catch {
    throw new Error('Installed service proof artifact input is not valid JSON');
  }
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(artifact);
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

export function verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(
  artifact,
  { expectedArtifactBodySha256 = null } = {}
) {
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(artifact);
  const proof = artifact.payload.proof;
  const artifactIdentity = matchExpectedSha256(
    'Installed service proof artifact',
    expectedArtifactBodySha256,
    artifact.integrity.body_sha256
  );
  const fixtureIdentityBound = artifactIdentity.matched;
  const authorityGrantContractSha256 =
    proof.authority_contract.public_safe_grant_summary.authority_grant_contract_sha256;
  const authorityProjection = detachedFixtureAuthorityProjectionStatus(
    authorityGrantContractSha256
  );
  const verification = {
    verification_type:
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_VERIFICATION_TYPE,
    verified: true,
    structural_self_integrity_verified: true,
    embedded_fixture_assertions_structurally_validated: true,
    artifact_identity_match_requires_expected_sha256: true,
    artifact_identity_expected_sha256_supplied: artifactIdentity.supplied,
    expected_artifact_body_sha256: artifactIdentity.expected,
    artifact_identity_sha256_matched: artifactIdentity.matched,
    source_preflight_identity_bound_to_expected_artifact_sha256:
      fixtureIdentityBound,
    signed_receipt_envelope_identity_bound_to_expected_artifact_sha256:
      fixtureIdentityBound,
    verification_scope:
      fixtureIdentityBound ? PINNED_VERIFICATION_SCOPE : STRUCTURAL_VERIFICATION_SCOPE,
    artifact_type: artifact.artifact_type,
    canonicalization: artifact.canonicalization,
    hash_scope: artifact.hash_scope,
    body_sha256: artifact.integrity.body_sha256,
    payload_type: proof.proof_type,
    evidence_model: proof.evidence_model,
    live_probing: proof.live_probing,
    source_preflight_body_sha256: proof.source_preflight.body_sha256,
    selected_profile_sha256: proof.selected_profile.profile_sha256,
    recognition_contract_sha256: proof.recognition_contract.recognition_contract_sha256,
    target_contract_sha256: proof.source_preflight.target_contract_sha256,
    consequence_path: proof.target_binding.consequence_path,
    target_handle: proof.target_binding.target_handle,
    target_binding_sha256: proof.target_binding.target_binding_sha256,
    authority_grant_contract_sha256: authorityGrantContractSha256,
    authority_grant_status: authorityProjection.status.status,
    authority_grant_fresh_effect_allowed:
      authorityProjection.status.fresh_effect_allowed,
    authority_grant_repeated_use_provenance_valid:
      authorityProjection.status.repeated_use_provenance_valid,
    authority_grant_status_allows_fixture_rightful_projection:
      authorityProjection.allowed,
    authority_grant_status_reason_code: authorityProjection.reasonCode,
    authority_domain_id:
      proof.authority_contract.public_safe_grant_summary.authority_domain_id,
    grantor_role_id:
      proof.authority_contract.public_safe_grant_summary.grantor_role_id,
    ordered_transition_binding_type:
      proof.accepted_runtime_transition_binding.binding_type,
    ordered_transition_binding_sha256:
      sha256hex(canonicalize(proof.accepted_runtime_transition_binding)),
    authorized_effect_detail_sha256:
      proof.target_binding.authorized_effect_detail_sha256,
    target_effect_sha256: proof.target_binding.target_effect_sha256,
    state_effect_binding_sha256: proof.target_binding.state_effect_binding_sha256,
    receipt_binds_authorized_effect_detail:
      proof.target_binding.receipt_binds_authorized_effect_detail,
    target_effect_bound_inside_authorized_effect_detail:
      proof.target_binding.target_effect_bound_inside_authorized_effect_detail,
    recognized_write_boarded:
      fixtureIdentityBound && proof.recognized_boarding.boarded,
    recognized_write_state_append_count:
      fixtureIdentityBound ? proof.recognized_boarding.state_entry_count_delta : 0,
    recognition_refusal_case_count: proof.refusal_cases.length,
    required_recognition_refusal_cases:
      [...REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES],
    recognition_refusal_taxonomy_sha256:
      proof.recognition_contract.observed_refusal_taxonomy_sha256,
    all_recognition_refusals_before_mutation: proof.refusal_cases.every(
      (item) => item.service_write_accepted === false && item.state_entry_count_delta === 0
    ),
    authority_refusal_case_count: proof.authority_refusal_cases.length,
    required_authority_refusal_cases:
      [...REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES],
    authority_refusal_taxonomy_sha256:
      proof.authority_contract.observed_refusal_taxonomy_sha256,
    all_authority_refusals_before_consumption_and_mutation:
      proof.authority_refusal_cases.every((item) =>
        item.service_write_accepted === false &&
        item.state_entry_count_delta === 0 &&
        item.consumed_authority_grant_count === 0
      ),
    same_process_signed_payload_replay_refused:
      proof.proof_boundary.same_process_signed_payload_replay_refused,
    restart_consumed_authority_grant_refused:
      proof.proof_boundary.restart_consumed_authority_grant_refused,
    state_append_after_grant_commit_burn_observed:
      proof.proof_boundary.state_append_after_grant_commit_burn_observed,
    metadata_partial_commit_burn_observed:
      proof.proof_boundary.metadata_partial_commit_burn_observed,
    store_and_anchor_rollback_refused_while_witness_ahead:
      proof.proof_boundary.store_and_anchor_rollback_refused_while_witness_ahead,
    store_anchor_and_witness_joint_rollback_detection:
      proof.proof_boundary.store_anchor_and_witness_joint_rollback_detection,
    joint_rollback_reopened_authority_grant_reuse:
      proof.proof_boundary.joint_rollback_reopened_authority_grant_reuse,
    fixture_rightful_issuance_path_evidenced:
      fixtureIdentityBound &&
      authorityProjection.allowed &&
      proof.proof_boundary.fixture_rightful_issuance_path_evidenced,
    rightful_issuance_proven: proof.proof_boundary.rightful_issuance_proven,
    portable_rightful_issuance_proven:
      proof.proof_boundary.portable_rightful_issuance_proven,
    production_rightful_issuance_proven:
      proof.proof_boundary.production_rightful_issuance_proven,
    install_performed: proof.proof_boundary.install_performed,
    activation_performed: proof.proof_boundary.activation_performed,
    live_records_system_checked: proof.proof_boundary.live_records_system_checked,
    current_machine_governance_proven:
      proof.proof_boundary.current_machine_governance_proven,
    production_downstream_recognition:
      proof.proof_boundary.production_downstream_recognition,
    external_attestation: proof.proof_boundary.external_attestation,
    sovereign_recognition: proof.proof_boundary.sovereign_recognition,
    consequence_lifecycle_closed: proof.proof_boundary.consequence_lifecycle_closed,
    claim_boundary:
      fixtureIdentityBound ? PINNED_CLAIM_BOUNDARY : STRUCTURAL_CLAIM_BOUNDARY,
    non_claims: [...proof.non_claims],
  };
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification(verification);
  return verification;
}

export function assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification(
  verification,
  { refusalTaxonomy = 'required', recognitionContractDigest = 'required' } = {}
) {
  if (!['required', 'optional'].includes(refusalTaxonomy)) {
    throw new Error('Installed service proof verification refusal taxonomy option drifted');
  }
  if (!['required', 'optional'].includes(recognitionContractDigest)) {
    throw new Error('Installed service proof verification recognition digest option drifted');
  }
  assertExactKeys('Installed service proof artifact verification', verification, [
    'activation_performed',
    'all_authority_refusals_before_consumption_and_mutation',
    'all_recognition_refusals_before_mutation',
    'artifact_identity_expected_sha256_supplied',
    'artifact_type',
    'artifact_identity_match_requires_expected_sha256',
    'artifact_identity_sha256_matched',
    'authority_domain_id',
    'authority_grant_fresh_effect_allowed',
    'authority_grant_contract_sha256',
    'authority_grant_repeated_use_provenance_valid',
    'authority_grant_status',
    'authority_grant_status_allows_fixture_rightful_projection',
    'authority_grant_status_reason_code',
    'authority_refusal_case_count',
    'authority_refusal_taxonomy_sha256',
    'authorized_effect_detail_sha256',
    'body_sha256',
    'canonicalization',
    'claim_boundary',
    'consequence_lifecycle_closed',
    'consequence_path',
    'current_machine_governance_proven',
    'embedded_fixture_assertions_structurally_validated',
    'evidence_model',
    'expected_artifact_body_sha256',
    'external_attestation',
    'fixture_rightful_issuance_path_evidenced',
    'grantor_role_id',
    'hash_scope',
    'install_performed',
    'joint_rollback_reopened_authority_grant_reuse',
    'live_probing',
    'live_records_system_checked',
    'metadata_partial_commit_burn_observed',
    'non_claims',
    'ordered_transition_binding_sha256',
    'ordered_transition_binding_type',
    'payload_type',
    'portable_rightful_issuance_proven',
    'production_downstream_recognition',
    'production_rightful_issuance_proven',
    'receipt_binds_authorized_effect_detail',
    'recognition_contract_sha256',
    'recognition_refusal_case_count',
    'recognition_refusal_taxonomy_sha256',
    'recognized_write_boarded',
    'recognized_write_state_append_count',
    'required_authority_refusal_cases',
    'required_recognition_refusal_cases',
    'restart_consumed_authority_grant_refused',
    'rightful_issuance_proven',
    'same_process_signed_payload_replay_refused',
    'selected_profile_sha256',
    'signed_receipt_envelope_identity_bound_to_expected_artifact_sha256',
    'sovereign_recognition',
    'source_preflight_body_sha256',
    'source_preflight_identity_bound_to_expected_artifact_sha256',
    'state_append_after_grant_commit_burn_observed',
    'state_effect_binding_sha256',
    'structural_self_integrity_verified',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_and_anchor_rollback_refused_while_witness_ahead',
    'target_binding_sha256',
    'target_contract_sha256',
    'target_effect_bound_inside_authorized_effect_detail',
    'target_effect_sha256',
    'target_handle',
    'verification_type',
    'verification_scope',
    'verified',
  ]);
  const fixtureIdentityBound =
    verification.artifact_identity_sha256_matched === true;
  const authorityProjection = detachedFixtureAuthorityProjectionStatus(
    verification.authority_grant_contract_sha256
  );
  const expected = {
    verification_type:
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_VERIFICATION_TYPE,
    verified: true,
    structural_self_integrity_verified: true,
    embedded_fixture_assertions_structurally_validated: true,
    artifact_identity_match_requires_expected_sha256: true,
    source_preflight_identity_bound_to_expected_artifact_sha256:
      fixtureIdentityBound,
    signed_receipt_envelope_identity_bound_to_expected_artifact_sha256:
      fixtureIdentityBound,
    verification_scope:
      fixtureIdentityBound ? PINNED_VERIFICATION_SCOPE : STRUCTURAL_VERIFICATION_SCOPE,
    artifact_type: PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_TYPE,
    canonicalization:
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_CANONICALIZATION,
    hash_scope: 'canonical artifact body without integrity',
    payload_type: PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_TYPE,
    evidence_model: 'local-disposable-installed-runtime-profile-service-proof',
    live_probing: false,
    consequence_path: PROTECTED_RECORDS_CONSEQUENCE_PATH,
    target_handle: PROTECTED_RECORDS_TARGET_HANDLE,
    authority_domain_id: PROTECTED_RECORDS_FIXTURE_AUTHORITY_DOMAIN_ID,
    grantor_role_id: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID,
    authority_grant_status: authorityProjection.status.status,
    authority_grant_fresh_effect_allowed:
      authorityProjection.status.fresh_effect_allowed,
    authority_grant_repeated_use_provenance_valid:
      authorityProjection.status.repeated_use_provenance_valid,
    authority_grant_status_allows_fixture_rightful_projection:
      authorityProjection.allowed,
    authority_grant_status_reason_code: authorityProjection.reasonCode,
    ordered_transition_binding_type: ORDERED_TRANSITION_BINDING_TYPE,
    receipt_binds_authorized_effect_detail: true,
    target_effect_bound_inside_authorized_effect_detail: true,
    recognized_write_boarded: fixtureIdentityBound,
    recognized_write_state_append_count: fixtureIdentityBound ? 1 : 0,
    recognition_refusal_case_count:
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
    all_recognition_refusals_before_mutation: true,
    authority_refusal_case_count:
      REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length,
    all_authority_refusals_before_consumption_and_mutation: true,
    same_process_signed_payload_replay_refused: true,
    restart_consumed_authority_grant_refused: true,
    state_append_after_grant_commit_burn_observed: true,
    metadata_partial_commit_burn_observed: true,
    store_and_anchor_rollback_refused_while_witness_ahead: true,
    store_anchor_and_witness_joint_rollback_detection: false,
    joint_rollback_reopened_authority_grant_reuse: true,
    fixture_rightful_issuance_path_evidenced:
      fixtureIdentityBound && authorityProjection.allowed,
    rightful_issuance_proven: false,
    portable_rightful_issuance_proven: false,
    production_rightful_issuance_proven: false,
    install_performed: false,
    activation_performed: false,
    live_records_system_checked: false,
    current_machine_governance_proven: false,
    production_downstream_recognition: false,
    external_attestation: false,
    sovereign_recognition: false,
    consequence_lifecycle_closed: false,
    claim_boundary:
      fixtureIdentityBound ? PINNED_CLAIM_BOUNDARY : STRUCTURAL_CLAIM_BOUNDARY,
  };
  for (const [key, value] of Object.entries(expected)) {
    if (verification[key] !== value) throw new Error(`Installed service proof verification ${key} drifted`);
  }
  if (
    verification.artifact_identity_expected_sha256_supplied !==
      verification.artifact_identity_sha256_matched
  ) {
    throw new Error('Installed service proof verification artifact identity posture drifted');
  }
  if (verification.artifact_identity_expected_sha256_supplied) {
    assertSha256(
      'Installed service verification expected artifact identity',
      verification.expected_artifact_body_sha256
    );
    if (verification.expected_artifact_body_sha256 !== verification.body_sha256) {
      throw new Error('Installed service proof verification artifact identity drifted');
    }
  } else if (verification.expected_artifact_body_sha256 !== null) {
    throw new Error('Installed service proof verification unexpected artifact identity drifted');
  }
  for (const key of [
    'body_sha256',
    'source_preflight_body_sha256',
    'selected_profile_sha256',
    'recognition_contract_sha256',
    'target_contract_sha256',
    'target_binding_sha256',
    'authority_grant_contract_sha256',
    'ordered_transition_binding_sha256',
    'authorized_effect_detail_sha256',
    'target_effect_sha256',
    'state_effect_binding_sha256',
    'recognition_refusal_taxonomy_sha256',
    'authority_refusal_taxonomy_sha256',
  ]) assertSha256(`Installed service verification ${key}`, verification[key]);
  assertExactArray(
    'Installed service verification recognition cases',
    verification.required_recognition_refusal_cases,
    REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES
  );
  assertExactArray(
    'Installed service verification authority cases',
    verification.required_authority_refusal_cases,
    REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES
  );
  assertExactArray(
    'Installed service verification non-claims',
    verification.non_claims,
    INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_NON_CLAIMS
  );
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(verification));
  return true;
}

export function formatProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification(verification) {
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification(verification);
  const lines = [
    'ZLAR Protected Records Installed Runtime Profile Service Proof Artifact Verification v1',
    `verified=${verification.verified}; structural_self_integrity_verified=${verification.structural_self_integrity_verified}; embedded_fixture_assertions_structurally_validated=${verification.embedded_fixture_assertions_structurally_validated}; sha256=${verification.body_sha256}`,
    `verification_scope=${verification.verification_scope}`,
    `artifact_identity: expected_sha256_supplied=${verification.artifact_identity_expected_sha256_supplied}; sha256_matched=${verification.artifact_identity_sha256_matched}; match_requires_expected_sha256=${verification.artifact_identity_match_requires_expected_sha256}`,
    `embedded_identity_binding: source_preflight_bound_to_expected_artifact_sha256=${verification.source_preflight_identity_bound_to_expected_artifact_sha256}; signed_receipt_envelope_bound_to_expected_artifact_sha256=${verification.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256}`,
    `authority_domain_id=${verification.authority_domain_id}; grantor_role_id=${verification.grantor_role_id}; authority_grant_contract_sha256=${verification.authority_grant_contract_sha256}`,
    `authority_grant_status=${verification.authority_grant_status}; fresh_effect_allowed=${verification.authority_grant_fresh_effect_allowed}; repeated_use_provenance_valid=${verification.authority_grant_repeated_use_provenance_valid}; allows_fixture_rightful_projection=${verification.authority_grant_status_allows_fixture_rightful_projection}; reason_code=${verification.authority_grant_status_reason_code}`,
    `ordered_transition_binding_type=${verification.ordered_transition_binding_type}; ordered_transition_binding_sha256=${verification.ordered_transition_binding_sha256}`,
    `recognized_write_boarded=${verification.recognized_write_boarded}; recognized_write_state_append_count=${verification.recognized_write_state_append_count}`,
    `recognition_refusal_cases=${verification.recognition_refusal_case_count}; all_recognition_refusals_before_mutation=${verification.all_recognition_refusals_before_mutation}`,
    `authority_refusal_cases=${verification.authority_refusal_case_count}; all_authority_refusals_before_consumption_and_mutation=${verification.all_authority_refusals_before_consumption_and_mutation}`,
    `same_process_signed_payload_replay_refused=${verification.same_process_signed_payload_replay_refused}; restart_consumed_authority_grant_refused=${verification.restart_consumed_authority_grant_refused}`,
    `state_append_after_grant_commit_burn_observed=${verification.state_append_after_grant_commit_burn_observed}; metadata_partial_commit_burn_observed=${verification.metadata_partial_commit_burn_observed}`,
    `store_and_anchor_rollback_refused_while_witness_ahead=${verification.store_and_anchor_rollback_refused_while_witness_ahead}; store_anchor_and_witness_joint_rollback_detection=${verification.store_anchor_and_witness_joint_rollback_detection}; joint_rollback_reopened_authority_grant_reuse=${verification.joint_rollback_reopened_authority_grant_reuse}`,
    `fixture_rightful_issuance_path_evidenced=${verification.fixture_rightful_issuance_path_evidenced}; rightful_issuance_proven=${verification.rightful_issuance_proven}; consequence_lifecycle_closed=${verification.consequence_lifecycle_closed}`,
    `claim_boundary=${verification.claim_boundary}`,
  ];
  const output = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  return output;
}

export function formatProtectedRecordsInstalledRuntimeProfileServiceProofArtifactSummary(artifact) {
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(artifact);
  const output = [
    'Portable installed runtime profile service proof artifact:',
    `artifact_type=${artifact.artifact_type}`,
    `sha256=${artifact.integrity.body_sha256}`,
  ].join('\n') + '\n';
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  return output;
}
