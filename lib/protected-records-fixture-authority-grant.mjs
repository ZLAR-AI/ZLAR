import { canonicalize } from './canonicalize.mjs';
import { sha256hex } from './receipt.mjs';
import {
  protectedRecordsFixtureAuthorityGrantEffectStatusReason,
} from './protected-records-fixture-authority-status.mjs';

export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_CONTRACT_TYPE =
  'zlar-protected-records-fixture-authority-grant-contract-v1';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_APPOINTMENT_TYPE =
  'zlar-protected-records-fixture-authority-grant-appointment-v1';
export const PROTECTED_RECORDS_AUTHORIZED_EFFECT_DETAIL_TYPE =
  'zlar-protected-records-authorized-effect-detail-v1';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_DECISION_TYPE =
  'zlar-protected-records-fixture-authority-grant-decision-v1';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_SUMMARY_TYPE =
  'zlar-protected-records-fixture-authority-grant-summary-v1';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_EXECUTION_TRACE_TYPE =
  'zlar-protected-records-fixture-authority-execution-trace-v1';

export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_DOMAIN_ID =
  'protected-records.local-disposable-fixture';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ACTOR_ID =
  'fixture-deployment-owner';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID =
  'fixture-consequence-authority';
export const PROTECTED_RECORDS_FIXTURE_ISSUER_ACTOR_ID =
  'fixture-receipt-issuer';
export const PROTECTED_RECORDS_FIXTURE_ISSUER_SLOT =
  'protected-records-fixture-receipt-issuer';
export const PROTECTED_RECORDS_FIXTURE_AUTHORIZATION_RECORD_ID =
  'control-tower-fixture-rightful-issuance-20260709-v1';
export const PROTECTED_RECORDS_FIXTURE_AUTHORIZATION_BODY_TYPE =
  'zlar-protected-records-fixture-human-authorization-body-v1';
export const PROTECTED_RECORDS_FIXTURE_RIGHTFUL_ISSUANCE_SCOPE =
  'protected-records.local-disposable-fixture/one-hermetic-crossing';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_EVALUATION_EPOCH = 1_783_609_800;
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_VALID_FROM_EPOCH =
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_EVALUATION_EPOCH - 30;
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_EXPIRES_AT_EPOCH =
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_EVALUATION_EPOCH + 120;
export const PROTECTED_RECORDS_FIXTURE_AUTHORIZED_RECORD_UPDATE = Object.freeze({
  operation: 'set_status',
  record_alias: 'selected-installed-profile-service-fixture',
});

export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_POWERS = Object.freeze([
  Object.freeze({
    power_id: 'bind_runtime_issuer_to_slot',
    holder: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID,
    delegable: false,
  }),
  Object.freeze({
    power_id: 'issue_governed_action_receipt',
    holder: PROTECTED_RECORDS_FIXTURE_ISSUER_SLOT,
    delegable: false,
  }),
  Object.freeze({
    power_id: 'issue_replacement_authority_grant',
    holder: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID,
    delegable: false,
  }),
  Object.freeze({
    power_id: 'revoke_authority_grant',
    holder: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID,
    delegable: false,
  }),
]);

const CONTRACT_KEYS = Object.freeze([
  'authority_domain',
  'authorization_record',
  'claim_boundary',
  'contract_type',
  'contract_version',
  'grantee',
  'grantor',
  'powers',
  'scope',
  'time_policy',
  'usage_policy',
]);

const SCOPE_KEYS = Object.freeze([
  'action_class',
  'consequence_path',
  'launcher_target_binding_sha256',
  'policy_version',
  'profile_id',
  'profile_sha256',
  'receipt_authorizer',
  'receipt_domain',
  'receipt_outcome',
  'receipt_rule',
  'receipt_type',
  'receipt_version',
  'recognition_contract_sha256',
  'record_update_sha256',
  'runtime_profile_id',
  'target_contract_sha256',
  'target_effect_sha256',
  'target_handle',
  'target_instance_scope',
  'target_kind',
  'target_scope',
]);

const RECEIPT_EVIDENCE_KEYS = Object.freeze([
  'audit_event_id',
  'authorizer',
  'detail_hash',
  'domain',
  'downstream_recognition_accepted',
  'issued_at_epoch',
  'issuer_kid',
  'issuer_status',
  'outcome',
  'payload',
  'policy_version',
  'public_key_sha256',
  'receipt_type',
  'receipt_version',
  'rule',
  'signature_verified',
  'source',
  'tool',
  'verified_signed_payload_sha256',
]);

const SCOPE_EVIDENCE_KEYS = Object.freeze([
  'derived_from_authority_grant_contract',
  'derived_from_request_stream',
  'scope',
  'source',
  'validated_launcher_config',
]);

const DECISION_EVIDENCE_KEYS = Object.freeze([
  'accepted_issuance_decision_bound',
  'appointment_bound_to_contract',
  'appointment_precedes_grant_window',
  'authority_contract_scope_matches',
  'authority_domain_id',
  'authority_grant_contract_sha256',
  'authority_grant_id',
  'consequence_lifecycle_closed',
  'current_machine_governance_proven',
  'exact_runtime_kid_match_proven',
  'exact_runtime_public_key_match_proven',
  'fixture_authority_grant_satisfied_at_evaluation_time',
  'fixture_rightful_issuance_path_evidenced',
  'grant_current_at_evaluation',
  'grant_not_previously_consumed',
  'grant_previously_consumed',
  'grantor_role_id',
  'issuer_slot',
  'launcher_scope_provenance_validated',
  'live_authority_proven',
  'portable_rightful_issuance_proven',
  'production_rightful_issuance_proven',
  'receipt_bound_to_authority_grant',
  'receipt_timestamp_not_future',
  'receipt_timestamp_within_grant',
  'revocation_truth_proven',
  'rightful_issuance_proven',
  'rightful_issuance_scope',
  'runtime_private_grant_appointment_disclosed',
  'runtime_private_issuer_identity_disclosed',
  'signature_verified_before_effect',
  'verified_signed_payload_identity_present',
]);

const DECISION_EVIDENCE_TRUE_KEYS = Object.freeze([
  'appointment_bound_to_contract',
  'appointment_precedes_grant_window',
  'authority_contract_scope_matches',
  'exact_runtime_kid_match_proven',
  'exact_runtime_public_key_match_proven',
  'fixture_authority_grant_satisfied_at_evaluation_time',
  'grant_current_at_evaluation',
  'grant_not_previously_consumed',
  'launcher_scope_provenance_validated',
  'receipt_bound_to_authority_grant',
  'receipt_timestamp_not_future',
  'receipt_timestamp_within_grant',
]);

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

function assertSha256(label, value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`${label} must be SHA-256 hex`);
  }
}

function assertString(label, value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
}

function assertInteger(label, value) {
  if (!Number.isInteger(value)) throw new Error(`${label} must be an integer`);
}

function clone(value) {
  return JSON.parse(canonicalize(value));
}

function expectedPowers() {
  return PROTECTED_RECORDS_FIXTURE_AUTHORITY_POWERS.map((item) => ({ ...item }));
}

function expectedClaimBoundary() {
  return {
    fixture_only: true,
    generic_rightful_issuance_proven: false,
    portable_rightful_issuance_proven: false,
    production_rightful_issuance_proven: false,
    live_authority_proven: false,
    current_machine_governance_proven: false,
    consequence_lifecycle_closed: false,
  };
}

function expectedAuthorizedScope() {
  return {
    consequence_path:
      'protected-records.installed-runtime-profile.terminal-chain.records.write',
    action_class: 'records.write',
    target_kind: 'process-private-recognized-effect-state',
    target_scope: 'logical-fixture',
    target_instance_scope: 'logical-fixture-not-per-run',
    target_handle:
      'zlar-target:v1:logical-fixture:0ee8bcc85701f8ba374af28393d517d3e3e823d9e8d740d256ae7f7304f7f8a2',
    launcher_target_binding_sha256:
      '9d714ebe24688b4f5780aac5fea47dc0c82e64b5f872c9254643ac0b0159fedc',
    record_update_sha256:
      'caf9b8a9aa622f1770e0b4c3780618f5103ee2f422df73fc9d3e45979551dd9d',
    target_effect_sha256:
      'd0d2ef1c533bdcaf120a24897698c657bb18a6d0b0e55cd1e896e8433574a5f2',
    profile_id: 'protected-records-runtime-fixture-profile',
    runtime_profile_id: 'protected-records-disposable-runtime-profile',
    profile_sha256:
      'e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469',
    recognition_contract_sha256:
      '1ce1351937c4eef665f13bd53696732af0cf05d891600ce5fd6e0655b97cc045',
    target_contract_sha256:
      'a771d114340060f269f78f15016c2975983ead7534a499bee3f5912fa05f985b',
    policy_version: 'recognition-policy-v1',
    receipt_version: 1,
    receipt_type: 'governed-action',
    receipt_domain: 'records',
    receipt_rule: 'RRECORDS_ALLOW',
    receipt_authorizer: 'policy',
    receipt_outcome: 'allow',
  };
}

function expectedTimePolicy() {
  return {
    clock_source: 'fixed-hermetic-fixture-epoch',
    valid_from_epoch: PROTECTED_RECORDS_FIXTURE_AUTHORITY_VALID_FROM_EPOCH,
    expires_at_epoch: PROTECTED_RECORDS_FIXTURE_AUTHORITY_EXPIRES_AT_EPOCH,
    interval: 'half-open-[valid_from,expires_at)',
    appointment_must_precede_or_equal_valid_from: true,
    receipt_ts_must_be_within_grant: true,
    receipt_ts_must_not_exceed_effect_time: true,
    grant_must_be_current_at_effect: true,
  };
}

function expectedUsagePolicy() {
  return {
    max_uses: 1,
    consumption_identity: 'authority-grant-contract-sha256',
    replacement_requires_different_contract_sha256: true,
    mutable_extension_allowed: false,
  };
}

function authorityAuthorizationBody(contract) {
  return {
    body_type: contract.authorization_record.authorization_body_type,
    authorization_record: {
      record_id: contract.authorization_record.record_id,
      source: contract.authorization_record.source,
      portable_attestation: contract.authorization_record.portable_attestation,
    },
    contract_type: contract.contract_type,
    contract_version: contract.contract_version,
    authority_domain: clone(contract.authority_domain),
    grantor: clone(contract.grantor),
    grantee: clone(contract.grantee),
    scope: clone(contract.scope),
    time_policy: clone(contract.time_policy),
    usage_policy: clone(contract.usage_policy),
    powers: clone(contract.powers),
    claim_boundary: clone(contract.claim_boundary),
  };
}

function expectedAuthorizationBody() {
  return {
    body_type: PROTECTED_RECORDS_FIXTURE_AUTHORIZATION_BODY_TYPE,
    authorization_record: {
      record_id: PROTECTED_RECORDS_FIXTURE_AUTHORIZATION_RECORD_ID,
      source: 'explicit-in-thread-control-tower-human-authorization',
      portable_attestation: false,
    },
    contract_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_CONTRACT_TYPE,
    contract_version: 1,
    authority_domain: {
      domain_id: PROTECTED_RECORDS_FIXTURE_AUTHORITY_DOMAIN_ID,
      domain_kind: 'local-hermetic-fixture',
      production_domain: false,
    },
    grantor: {
      actor_id: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ACTOR_ID,
      role_id: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID,
    },
    grantee: {
      actor_id: PROTECTED_RECORDS_FIXTURE_ISSUER_ACTOR_ID,
      issuer_slot: PROTECTED_RECORDS_FIXTURE_ISSUER_SLOT,
      binding_mode: 'launcher-owned-runtime-private-exact-kid-and-public-key-sha256',
    },
    scope: expectedAuthorizedScope(),
    time_policy: expectedTimePolicy(),
    usage_policy: expectedUsagePolicy(),
    powers: expectedPowers(),
    claim_boundary: expectedClaimBoundary(),
  };
}

// Literal digest of the exact human-authorized body. A caller cannot widen the
// authorization by changing a field and coherently resealing this record.
export const PROTECTED_RECORDS_FIXTURE_AUTHORIZATION_BODY_SHA256 =
  '5def9dd2c31938a571bd6b80f1375d4684c91f9b3610c472d29a4e8f3ec4e364';

export function protectedRecordsFixtureAuthorityAuthorizationBody(contract) {
  return authorityAuthorizationBody(requireObject(
    'Protected records fixture authority grant contract',
    contract
  ));
}

export function protectedRecordsFixtureAuthorityAuthorizationBodySha256(contract) {
  return sha256hex(canonicalize(
    protectedRecordsFixtureAuthorityAuthorizationBody(contract)
  ));
}

export function createProtectedRecordsFixtureAuthorityGrantContract({
  consequencePath,
  actionClass,
  targetKind,
  targetScope,
  targetInstanceScope,
  targetHandle,
  launcherTargetBindingSha256,
  recordUpdateSha256,
  targetEffectSha256,
  profileId,
  runtimeProfileId,
  profileSha256,
  recognitionContractSha256,
  targetContractSha256,
  policyVersion = 'recognition-policy-v1',
  receiptDomain = 'records',
  receiptRule = 'RRECORDS_ALLOW',
  receiptAuthorizer = 'policy',
  receiptOutcome = 'allow',
  validFromEpoch = PROTECTED_RECORDS_FIXTURE_AUTHORITY_VALID_FROM_EPOCH,
  expiresAtEpoch = PROTECTED_RECORDS_FIXTURE_AUTHORITY_EXPIRES_AT_EPOCH,
} = {}) {
  const contract = {
    contract_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_CONTRACT_TYPE,
    contract_version: 1,
    authorization_record: {
      record_id: PROTECTED_RECORDS_FIXTURE_AUTHORIZATION_RECORD_ID,
      source: 'explicit-in-thread-control-tower-human-authorization',
      portable_attestation: false,
      authorization_body_type: PROTECTED_RECORDS_FIXTURE_AUTHORIZATION_BODY_TYPE,
      authorization_body_sha256:
        PROTECTED_RECORDS_FIXTURE_AUTHORIZATION_BODY_SHA256,
    },
    authority_domain: {
      domain_id: PROTECTED_RECORDS_FIXTURE_AUTHORITY_DOMAIN_ID,
      domain_kind: 'local-hermetic-fixture',
      production_domain: false,
    },
    grantor: {
      actor_id: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ACTOR_ID,
      role_id: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID,
    },
    grantee: {
      actor_id: PROTECTED_RECORDS_FIXTURE_ISSUER_ACTOR_ID,
      issuer_slot: PROTECTED_RECORDS_FIXTURE_ISSUER_SLOT,
      binding_mode: 'launcher-owned-runtime-private-exact-kid-and-public-key-sha256',
    },
    scope: {
      consequence_path: consequencePath,
      action_class: actionClass,
      target_kind: targetKind,
      target_scope: targetScope,
      target_instance_scope: targetInstanceScope,
      target_handle: targetHandle,
      launcher_target_binding_sha256: launcherTargetBindingSha256,
      record_update_sha256: recordUpdateSha256,
      target_effect_sha256: targetEffectSha256,
      profile_id: profileId,
      runtime_profile_id: runtimeProfileId,
      profile_sha256: profileSha256,
      recognition_contract_sha256: recognitionContractSha256,
      target_contract_sha256: targetContractSha256,
      policy_version: policyVersion,
      receipt_version: 1,
      receipt_type: 'governed-action',
      receipt_domain: receiptDomain,
      receipt_rule: receiptRule,
      receipt_authorizer: receiptAuthorizer,
      receipt_outcome: receiptOutcome,
    },
    time_policy: {
      clock_source: 'fixed-hermetic-fixture-epoch',
      valid_from_epoch: validFromEpoch,
      expires_at_epoch: expiresAtEpoch,
      interval: 'half-open-[valid_from,expires_at)',
      appointment_must_precede_or_equal_valid_from: true,
      receipt_ts_must_be_within_grant: true,
      receipt_ts_must_not_exceed_effect_time: true,
      grant_must_be_current_at_effect: true,
    },
    usage_policy: {
      max_uses: 1,
      consumption_identity: 'authority-grant-contract-sha256',
      replacement_requires_different_contract_sha256: true,
      mutable_extension_allowed: false,
    },
    powers: expectedPowers(),
    claim_boundary: expectedClaimBoundary(),
  };
  assertProtectedRecordsFixtureAuthorityGrantContract(contract);
  return contract;
}

export function assertProtectedRecordsFixtureAuthorityGrantContract(contract) {
  assertExactKeys('Protected records fixture authority grant contract', contract, CONTRACT_KEYS);
  assertExactKeys('Protected records fixture authority authorization record', contract.authorization_record, [
    'authorization_body_sha256', 'authorization_body_type', 'portable_attestation',
    'record_id', 'source',
  ]);
  assertExactKeys('Protected records fixture authority domain', contract.authority_domain, [
    'domain_id', 'domain_kind', 'production_domain',
  ]);
  assertExactKeys('Protected records fixture authority grantor', contract.grantor, ['actor_id', 'role_id']);
  assertExactKeys('Protected records fixture authority grantee', contract.grantee, [
    'actor_id', 'binding_mode', 'issuer_slot',
  ]);
  assertExactKeys('Protected records fixture authority scope', contract.scope, SCOPE_KEYS);
  assertExactKeys('Protected records fixture authority time policy', contract.time_policy, [
    'appointment_must_precede_or_equal_valid_from', 'clock_source', 'expires_at_epoch',
    'grant_must_be_current_at_effect', 'interval', 'receipt_ts_must_be_within_grant',
    'receipt_ts_must_not_exceed_effect_time', 'valid_from_epoch',
  ]);
  assertExactKeys('Protected records fixture authority usage policy', contract.usage_policy, [
    'consumption_identity', 'max_uses', 'mutable_extension_allowed',
    'replacement_requires_different_contract_sha256',
  ]);
  assertExactKeys('Protected records fixture authority claim boundary', contract.claim_boundary, [
    'consequence_lifecycle_closed', 'current_machine_governance_proven', 'fixture_only',
    'generic_rightful_issuance_proven', 'live_authority_proven',
    'portable_rightful_issuance_proven', 'production_rightful_issuance_proven',
  ]);
  assertSha256(
    'Protected records fixture authority authorization body SHA-256',
    contract.authorization_record.authorization_body_sha256
  );
  if (!Array.isArray(contract.powers)) {
    throw new Error('Protected records fixture authority powers drifted');
  }
  for (const [label, value] of Object.entries(contract.scope)) {
    if (label === 'receipt_version') {
      if (value !== 1) throw new Error('Protected records fixture authority receipt version drifted');
    } else if (label.endsWith('_sha256')) {
      assertSha256(`Protected records fixture authority scope ${label}`, value);
    } else {
      assertString(`Protected records fixture authority scope ${label}`, value);
    }
  }
  assertInteger('Protected records fixture authority valid_from_epoch', contract.time_policy.valid_from_epoch);
  assertInteger('Protected records fixture authority expires_at_epoch', contract.time_policy.expires_at_epoch);
  const actualAuthorizationBody =
    protectedRecordsFixtureAuthorityAuthorizationBody(contract);
  const actualAuthorizationBodySha256 =
    protectedRecordsFixtureAuthorityAuthorizationBodySha256(contract);
  if (
    canonicalize(actualAuthorizationBody) !== canonicalize(expectedAuthorizationBody()) ||
    actualAuthorizationBodySha256 !==
      PROTECTED_RECORDS_FIXTURE_AUTHORIZATION_BODY_SHA256 ||
    contract.authorization_record.authorization_body_sha256 !==
      PROTECTED_RECORDS_FIXTURE_AUTHORIZATION_BODY_SHA256
  ) {
    throw new Error('Protected records fixture human authorization body drifted');
  }
  if (canonicalize(contract.powers) !== canonicalize(expectedPowers())) {
    throw new Error('Protected records fixture authority powers drifted');
  }
  if (
    contract.contract_type !== PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_CONTRACT_TYPE ||
    contract.contract_version !== 1 ||
    contract.authorization_record.record_id !== PROTECTED_RECORDS_FIXTURE_AUTHORIZATION_RECORD_ID ||
    contract.authorization_record.source !== 'explicit-in-thread-control-tower-human-authorization' ||
    contract.authorization_record.portable_attestation !== false ||
    contract.authorization_record.authorization_body_type !==
      PROTECTED_RECORDS_FIXTURE_AUTHORIZATION_BODY_TYPE ||
    contract.authority_domain.domain_id !== PROTECTED_RECORDS_FIXTURE_AUTHORITY_DOMAIN_ID ||
    contract.authority_domain.domain_kind !== 'local-hermetic-fixture' ||
    contract.authority_domain.production_domain !== false ||
    contract.grantor.actor_id !== PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ACTOR_ID ||
    contract.grantor.role_id !== PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID ||
    contract.grantee.actor_id !== PROTECTED_RECORDS_FIXTURE_ISSUER_ACTOR_ID ||
    contract.grantee.issuer_slot !== PROTECTED_RECORDS_FIXTURE_ISSUER_SLOT ||
    contract.grantee.binding_mode !== 'launcher-owned-runtime-private-exact-kid-and-public-key-sha256' ||
    canonicalize(contract.claim_boundary) !== canonicalize(expectedClaimBoundary()) ||
    contract.time_policy.clock_source !== 'fixed-hermetic-fixture-epoch' ||
    contract.time_policy.valid_from_epoch >= contract.time_policy.expires_at_epoch ||
    contract.time_policy.interval !== 'half-open-[valid_from,expires_at)' ||
    contract.time_policy.appointment_must_precede_or_equal_valid_from !== true ||
    contract.time_policy.receipt_ts_must_be_within_grant !== true ||
    contract.time_policy.receipt_ts_must_not_exceed_effect_time !== true ||
    contract.time_policy.grant_must_be_current_at_effect !== true ||
    contract.usage_policy.max_uses !== 1 ||
    contract.usage_policy.consumption_identity !== 'authority-grant-contract-sha256' ||
    contract.usage_policy.replacement_requires_different_contract_sha256 !== true ||
    contract.usage_policy.mutable_extension_allowed !== false
  ) {
    throw new Error('Protected records fixture authority grant contract boundary drifted');
  }
  return true;
}

export function protectedRecordsFixtureAuthorityGrantContractSha256(contract) {
  assertProtectedRecordsFixtureAuthorityGrantContract(contract);
  return sha256hex(canonicalize(contract));
}

export function protectedRecordsFixtureAuthorityGrantId(contract) {
  return `zlar-grant:v1:${protectedRecordsFixtureAuthorityGrantContractSha256(contract)}`;
}

export function createProtectedRecordsFixtureAuthorityGrantAppointment({
  contract,
  granteeIssuerKid,
  granteePublicKeySha256,
  issuedAtEpoch = contract?.time_policy?.valid_from_epoch,
  status = 'active',
  revokedAtEpoch = null,
  revocationReasonCode = null,
} = {}) {
  assertProtectedRecordsFixtureAuthorityGrantContract(contract);
  const appointment = {
    appointment_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_APPOINTMENT_TYPE,
    grant_id: protectedRecordsFixtureAuthorityGrantId(contract),
    contract_sha256: protectedRecordsFixtureAuthorityGrantContractSha256(contract),
    issuer_slot: contract.grantee.issuer_slot,
    grantee_issuer_kid: granteeIssuerKid,
    grantee_public_key_sha256: granteePublicKeySha256,
    issued_at_epoch: issuedAtEpoch,
    valid_from_epoch: contract.time_policy.valid_from_epoch,
    expires_at_epoch: contract.time_policy.expires_at_epoch,
    status,
    revoked_at_epoch: revokedAtEpoch,
    revocation_reason_code: revocationReasonCode,
  };
  assertProtectedRecordsFixtureAuthorityGrantAppointment(appointment);
  return appointment;
}

export function assertProtectedRecordsFixtureAuthorityGrantAppointment(appointment) {
  assertExactKeys('Protected records fixture authority grant appointment', appointment, [
    'appointment_type', 'contract_sha256', 'expires_at_epoch', 'grant_id',
    'grantee_issuer_kid', 'grantee_public_key_sha256', 'issued_at_epoch', 'issuer_slot',
    'revocation_reason_code', 'revoked_at_epoch', 'status', 'valid_from_epoch',
  ]);
  if (appointment.appointment_type !== PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_APPOINTMENT_TYPE) {
    throw new Error('Protected records fixture authority appointment type drifted');
  }
  if (!/^zlar-grant:v1:[a-f0-9]{64}$/.test(appointment.grant_id || '')) {
    throw new Error('Protected records fixture authority grant id drifted');
  }
  assertSha256('Protected records fixture authority contract SHA-256', appointment.contract_sha256);
  assertSha256('Protected records fixture authority public key SHA-256', appointment.grantee_public_key_sha256);
  assertString('Protected records fixture authority issuer slot', appointment.issuer_slot);
  assertString('Protected records fixture authority issuer kid', appointment.grantee_issuer_kid);
  for (const key of ['issued_at_epoch', 'valid_from_epoch', 'expires_at_epoch']) {
    assertInteger(`Protected records fixture authority ${key}`, appointment[key]);
  }
  if (appointment.issued_at_epoch > appointment.valid_from_epoch || appointment.valid_from_epoch >= appointment.expires_at_epoch) {
    throw new Error('Protected records fixture authority appointment window drifted');
  }
  if (!['active', 'revoked'].includes(appointment.status)) {
    throw new Error('Protected records fixture authority appointment status drifted');
  }
  if (appointment.status === 'active') {
    if (appointment.revoked_at_epoch !== null || appointment.revocation_reason_code !== null) {
      throw new Error('Protected records fixture active appointment revocation state drifted');
    }
  } else {
    assertInteger('Protected records fixture authority revoked_at_epoch', appointment.revoked_at_epoch);
    assertString('Protected records fixture authority revocation reason', appointment.revocation_reason_code);
  }
  return true;
}

export function assertProtectedRecordsAuthorizedEffectDetail(detail, contract) {
  assertProtectedRecordsFixtureAuthorityGrantContract(contract);
  assertExactKeys('Protected records authorized effect detail', detail, [
    'authority_grant_contract_sha256', 'authority_grant_id', 'detail_type', 'target_effect',
  ]);
  assertExactKeys('Protected records authorized target effect', detail.target_effect, [
    'record_update', 'target_handle',
  ]);
  requireObject('Protected records authorized record update', detail.target_effect.record_update);
  const recordUpdateSha256 = sha256hex(canonicalize(detail.target_effect.record_update));
  const targetEffectSha256 = sha256hex(canonicalize(detail.target_effect));
  if (
    detail.detail_type !== PROTECTED_RECORDS_AUTHORIZED_EFFECT_DETAIL_TYPE ||
    detail.authority_grant_id !== protectedRecordsFixtureAuthorityGrantId(contract) ||
    detail.authority_grant_contract_sha256 !== protectedRecordsFixtureAuthorityGrantContractSha256(contract) ||
    detail.target_effect.target_handle !== contract.scope.target_handle ||
    recordUpdateSha256 !== contract.scope.record_update_sha256 ||
    targetEffectSha256 !== contract.scope.target_effect_sha256
  ) {
    throw new Error('Protected records authorized effect detail does not match the authority grant');
  }
  return true;
}

export function protectedRecordsAuthorizedEffectDetail({ contract, targetEffect }) {
  const detail = {
    detail_type: PROTECTED_RECORDS_AUTHORIZED_EFFECT_DETAIL_TYPE,
    authority_grant_id: protectedRecordsFixtureAuthorityGrantId(contract),
    authority_grant_contract_sha256:
      protectedRecordsFixtureAuthorityGrantContractSha256(contract),
    target_effect: clone(requireObject('Protected records authorized target effect', targetEffect)),
  };
  assertProtectedRecordsAuthorizedEffectDetail(detail, contract);
  return detail;
}

export function protectedRecordsAuthorizedEffectDetailSha256(detail, contract) {
  assertProtectedRecordsAuthorizedEffectDetail(detail, contract);
  return sha256hex(canonicalize(detail));
}

function assertReceiptEvidence(receiptEvidence, phase) {
  assertExactKeys('Protected records fixture authority receipt evidence', receiptEvidence, RECEIPT_EVIDENCE_KEYS);
  assertString('Protected records fixture authority audit event id', receiptEvidence.audit_event_id);
  assertString('Protected records fixture authority issuer kid', receiptEvidence.issuer_kid);
  assertSha256('Protected records fixture authority issuer public key SHA-256', receiptEvidence.public_key_sha256);
  assertInteger('Protected records fixture authority receipt issued_at_epoch', receiptEvidence.issued_at_epoch);
  assertSha256('Protected records fixture authority receipt detail hash', receiptEvidence.detail_hash);
  requireObject('Protected records fixture authority receipt payload', receiptEvidence.payload);
  if (receiptEvidence.receipt_version !== 1 || receiptEvidence.receipt_type !== 'governed-action') {
    throw new Error('Protected records fixture authority receipt format drifted');
  }
  if (phase === 'issuance') {
    if (
      receiptEvidence.source !== 'unsigned-receipt-payload-before-signing' ||
      receiptEvidence.signature_verified !== false ||
      receiptEvidence.verified_signed_payload_sha256 !== null ||
      receiptEvidence.downstream_recognition_accepted !== false ||
      receiptEvidence.issuer_status !== null
    ) {
      throw new Error('Protected records fixture authority issuance evidence drifted');
    }
  } else if (
    receiptEvidence.source !== 'cryptographically-verified-downstream-recognition' ||
    receiptEvidence.signature_verified !== true ||
    receiptEvidence.downstream_recognition_accepted !== true ||
    receiptEvidence.issuer_status !== 'active'
  ) {
    throw new Error('Protected records fixture authority effect verification evidence drifted');
  } else {
    assertSha256(
      'Protected records fixture authority verified signed payload SHA-256',
      receiptEvidence.verified_signed_payload_sha256
    );
  }
  return true;
}

function receiptPayloadSha256(receiptEvidence) {
  return sha256hex(canonicalize(receiptEvidence.payload));
}

function receiptSemanticBindingSha256(receiptEvidence) {
  return sha256hex(canonicalize({
    issuer_kid: receiptEvidence.issuer_kid,
    payload_sha256: receiptPayloadSha256(receiptEvidence),
    public_key_sha256: receiptEvidence.public_key_sha256,
  }));
}

function addReason(reasons, code, message) {
  reasons.push({ code, message });
}

function commonGrantReasons({
  contract,
  appointment,
  scopeEvidence,
  receiptEvidence,
  authorizedEffectDetail,
  evaluationEpoch,
}) {
  const reasons = [];
  assertExactKeys(
    'Protected records fixture authority launcher scope evidence',
    scopeEvidence,
    SCOPE_EVIDENCE_KEYS
  );
  assertExactKeys('Protected records fixture authority observed scope', scopeEvidence.scope, SCOPE_KEYS);
  assertInteger('Protected records fixture authority evaluation epoch', evaluationEpoch);
  const contractSha256 = protectedRecordsFixtureAuthorityGrantContractSha256(contract);
  const grantId = protectedRecordsFixtureAuthorityGrantId(contract);
  let authorizedEffectDetailSha256 = null;
  try {
    authorizedEffectDetailSha256 = protectedRecordsAuthorizedEffectDetailSha256(
      authorizedEffectDetail,
      contract
    );
  } catch {
    authorizedEffectDetailSha256 = sha256hex(canonicalize({
      invalid_authorized_effect_detail: true,
    }));
    addReason(reasons, 'authority_grant_effect_detail_mismatch', 'Authorized effect detail does not match the exact grant scope.');
  }

  if (!appointment) {
    addReason(reasons, 'authority_grant_missing', 'Launcher-owned authority grant appointment is missing.');
  } else {
    assertProtectedRecordsFixtureAuthorityGrantAppointment(appointment);
    if (appointment.contract_sha256 !== contractSha256 || appointment.grant_id !== grantId) {
      addReason(reasons, 'authority_grant_contract_mismatch', 'Authority grant appointment does not match the contract.');
    }
    if (
      appointment.issuer_slot !== contract.grantee.issuer_slot ||
      appointment.valid_from_epoch !== contract.time_policy.valid_from_epoch ||
      appointment.expires_at_epoch !== contract.time_policy.expires_at_epoch
    ) {
      addReason(reasons, 'authority_grant_appointment_mismatch', 'Authority grant appointment changed the contract-bound slot or window.');
    }
    if (appointment.issued_at_epoch > contract.time_policy.valid_from_epoch) {
      addReason(reasons, 'authority_grant_retroactive_appointment', 'Authority grant appointment was created after its contract-bound validity start.');
    }
    if (appointment.grantee_issuer_kid !== receiptEvidence.issuer_kid) {
      addReason(reasons, 'authority_grant_issuer_mismatch', 'Receipt issuer is not the appointed grant grantee.');
    }
    if (appointment.grantee_public_key_sha256 !== receiptEvidence.public_key_sha256) {
      addReason(reasons, 'authority_grant_public_key_mismatch', 'Receipt verifier key does not match the appointed grant grantee key.');
    }
    if (appointment.status === 'revoked') {
      addReason(reasons, 'authority_grant_revoked', 'Authority grant was revoked before the consequence boundary.');
    }
  }

  if (
    scopeEvidence.source !== 'validated-launcher-profile-recognition-target-config' ||
    scopeEvidence.validated_launcher_config !== true ||
    scopeEvidence.derived_from_authority_grant_contract !== false ||
    scopeEvidence.derived_from_request_stream !== false
  ) {
    addReason(reasons, 'authority_grant_scope_provenance_mismatch', 'Observed scope did not come exclusively from validated launcher configuration.');
  }
  for (const key of SCOPE_KEYS) {
    if (contract.scope[key] !== scopeEvidence.scope[key]) {
      addReason(reasons, 'authority_grant_scope_mismatch', `Authority grant scope mismatch: ${key}.`);
    }
  }

  const payloadProjectionChecks = {
    audit_event_id: receiptEvidence.audit_event_id,
    authorizer: receiptEvidence.authorizer,
    detail_hash: receiptEvidence.detail_hash,
    domain: receiptEvidence.domain,
    outcome: receiptEvidence.outcome,
    policy_version: receiptEvidence.policy_version,
    rule: receiptEvidence.rule,
    tool: receiptEvidence.tool,
  };
  for (const [key, expected] of Object.entries(payloadProjectionChecks)) {
    if (receiptEvidence.payload[key] !== expected) {
      addReason(reasons, 'authority_grant_receipt_payload_projection_mismatch', `Receipt payload projection mismatch: ${key}.`);
    }
  }
  const payloadTimestampEpoch = Math.floor(new Date(receiptEvidence.payload.ts).getTime() / 1000);
  if (!Number.isFinite(payloadTimestampEpoch) || payloadTimestampEpoch !== receiptEvidence.issued_at_epoch) {
    addReason(reasons, 'authority_grant_receipt_timestamp_projection_mismatch', 'Receipt timestamp projection does not match the signed payload.');
  }
  const payloadSha256 = receiptPayloadSha256(receiptEvidence);
  if (
    receiptEvidence.signature_verified === true &&
    receiptEvidence.verified_signed_payload_sha256 !== payloadSha256
  ) {
    addReason(reasons, 'authority_grant_verified_payload_identity_mismatch', 'Verified signed payload identity does not match the exact canonical receipt payload.');
  }

  const receiptScopeChecks = {
    policy_version: contract.scope.policy_version,
    tool: contract.scope.action_class,
    domain: contract.scope.receipt_domain,
    rule: contract.scope.receipt_rule,
    authorizer: contract.scope.receipt_authorizer,
    outcome: contract.scope.receipt_outcome,
    receipt_version: contract.scope.receipt_version,
    receipt_type: contract.scope.receipt_type,
  };
  for (const [key, expected] of Object.entries(receiptScopeChecks)) {
    if (receiptEvidence[key] !== expected) {
      addReason(reasons, 'authority_grant_receipt_scope_mismatch', `Receipt scope mismatch: ${key}.`);
    }
  }
  if (
    receiptEvidence.detail_hash !== authorizedEffectDetailSha256
  ) {
    addReason(reasons, 'authority_grant_signed_detail_mismatch', 'Verified receipt detail hash does not bind the exact grant and effect.');
  }
  if (receiptEvidence.issued_at_epoch < contract.time_policy.valid_from_epoch) {
    addReason(reasons, 'authority_grant_receipt_before_window', 'Receipt predates the authority grant window.');
  }
  if (receiptEvidence.issued_at_epoch >= contract.time_policy.expires_at_epoch) {
    addReason(reasons, 'authority_grant_receipt_after_expiry', 'Receipt was issued at or after authority grant expiry.');
  }
  if (evaluationEpoch < contract.time_policy.valid_from_epoch) {
    addReason(reasons, 'authority_grant_not_yet_valid', 'Authority grant is not yet valid at the consequence boundary.');
  }
  if (evaluationEpoch >= contract.time_policy.expires_at_epoch) {
    addReason(reasons, 'authority_grant_expired', 'Authority grant expired before the consequence boundary.');
  }
  if (receiptEvidence.issued_at_epoch > evaluationEpoch) {
    addReason(reasons, 'authority_grant_receipt_from_future', 'Receipt timestamp is later than the grant evaluation time.');
  }
  return {
    reasons,
    contractSha256,
    grantId,
    authorizedEffectDetailSha256,
    signedPayloadSha256: payloadSha256,
  };
}

function decisionEvidence({
  accepted,
  phase,
  contract,
  appointment,
  receiptEvidence,
  authorizedEffectDetailSha256,
  evaluationEpoch,
  grantPreviouslyConsumed,
  issuanceDecisionBound,
  launcherScopeProvenanceValidated,
}) {
  const receiptBound = authorizedEffectDetailSha256 !== null &&
    receiptEvidence.detail_hash === authorizedEffectDetailSha256;
  return {
    authority_domain_id: contract.authority_domain.domain_id,
    grantor_role_id: contract.grantor.role_id,
    issuer_slot: contract.grantee.issuer_slot,
    authority_grant_id: protectedRecordsFixtureAuthorityGrantId(contract),
    authority_grant_contract_sha256:
      protectedRecordsFixtureAuthorityGrantContractSha256(contract),
    authority_contract_scope_matches: accepted,
    launcher_scope_provenance_validated:
      accepted && launcherScopeProvenanceValidated,
    appointment_bound_to_contract: accepted,
    appointment_precedes_grant_window: accepted,
    exact_runtime_kid_match_proven: appointment
      ? appointment.grantee_issuer_kid === receiptEvidence.issuer_kid
      : false,
    exact_runtime_public_key_match_proven: appointment
      ? appointment.grantee_public_key_sha256 === receiptEvidence.public_key_sha256
      : false,
    receipt_bound_to_authority_grant: receiptBound,
    receipt_timestamp_within_grant:
      receiptEvidence.issued_at_epoch >= contract.time_policy.valid_from_epoch &&
      receiptEvidence.issued_at_epoch < contract.time_policy.expires_at_epoch,
    receipt_timestamp_not_future: receiptEvidence.issued_at_epoch <= evaluationEpoch,
    grant_current_at_evaluation:
      evaluationEpoch >= contract.time_policy.valid_from_epoch &&
      evaluationEpoch < contract.time_policy.expires_at_epoch,
    signature_verified_before_effect: phase === 'effect' && receiptEvidence.signature_verified === true,
    verified_signed_payload_identity_present:
      phase === 'effect' && /^[a-f0-9]{64}$/.test(receiptEvidence.verified_signed_payload_sha256 || ''),
    accepted_issuance_decision_bound: phase === 'effect' && issuanceDecisionBound,
    grant_not_previously_consumed: grantPreviouslyConsumed === false,
    grant_previously_consumed: grantPreviouslyConsumed === true,
    fixture_authority_grant_satisfied_at_evaluation_time: accepted,
    fixture_rightful_issuance_path_evidenced: phase === 'effect' && accepted && issuanceDecisionBound,
    rightful_issuance_scope: PROTECTED_RECORDS_FIXTURE_RIGHTFUL_ISSUANCE_SCOPE,
    runtime_private_issuer_identity_disclosed: false,
    runtime_private_grant_appointment_disclosed: false,
    rightful_issuance_proven: false,
    portable_rightful_issuance_proven: false,
    production_rightful_issuance_proven: false,
    live_authority_proven: false,
    revocation_truth_proven: false,
    current_machine_governance_proven: false,
    consequence_lifecycle_closed: false,
  };
}

function buildDecision({
  phase,
  contract,
  appointment,
  scopeEvidence,
  receiptEvidence,
  authorizedEffectDetail,
  evaluationEpoch,
  grantPreviouslyConsumed,
  issuanceDecisionBound = false,
  extraReasons = [],
  postConsumptionReasons = [],
}) {
  assertReceiptEvidence(receiptEvidence, phase);
  const common = commonGrantReasons({
    contract,
    appointment,
    scopeEvidence,
    receiptEvidence,
    authorizedEffectDetail,
    evaluationEpoch,
  });
  const reasons = [...extraReasons, ...common.reasons];
  if (grantPreviouslyConsumed === true) {
    addReason(reasons, 'authority_grant_already_consumed', 'The one-use authority grant was already consumed.');
  } else if (grantPreviouslyConsumed !== false) {
    addReason(reasons, 'authority_grant_consumption_state_missing', 'Launcher-owned authority grant consumption state is missing.');
  }
  for (const reason of postConsumptionReasons) {
    addReason(reasons, reason.code, reason.message);
  }
  const accepted = reasons.length === 0;
  const receiptBindingSha256 = receiptSemanticBindingSha256(receiptEvidence);
  const crossingBindingSha256 = sha256hex(canonicalize({
    authority_grant_contract_sha256: common.contractSha256,
    authorized_effect_detail_sha256: common.authorizedEffectDetailSha256,
    signed_payload_sha256: common.signedPayloadSha256,
    receipt_semantic_binding_sha256: receiptBindingSha256,
  }));
  const decision = {
    result_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_DECISION_TYPE,
    phase,
    decision: accepted ? 'accept' : 'refuse',
    reason_code: accepted ? `fixture_authority_grant_${phase}_satisfied` : reasons[0].code,
    reasons: accepted
      ? [{
          code: `fixture_authority_grant_${phase}_satisfied`,
          message: `The local fixture authority grant satisfied the ${phase} boundary.`,
        }]
      : reasons,
    binding: {
      authority_grant_id: common.grantId,
      authority_grant_contract_sha256: common.contractSha256,
      authorized_effect_detail_sha256: common.authorizedEffectDetailSha256,
      signed_payload_sha256: common.signedPayloadSha256,
      receipt_semantic_binding_sha256: receiptBindingSha256,
      crossing_binding_sha256: crossingBindingSha256,
    },
    evidence: decisionEvidence({
      accepted,
      phase,
      contract,
      appointment,
      receiptEvidence,
      authorizedEffectDetailSha256: common.authorizedEffectDetailSha256,
      evaluationEpoch,
      grantPreviouslyConsumed,
      issuanceDecisionBound,
      launcherScopeProvenanceValidated:
        scopeEvidence.source === 'validated-launcher-profile-recognition-target-config' &&
        scopeEvidence.validated_launcher_config === true &&
        scopeEvidence.derived_from_authority_grant_contract === false &&
        scopeEvidence.derived_from_request_stream === false,
    }),
  };
  assertProtectedRecordsFixtureAuthorityGrantDecision(decision, contract, phase, {
    requireAccepted: false,
  });
  return decision;
}

export function evaluateProtectedRecordsFixtureAuthorityGrantIssuance({
  contract,
  appointment,
  scopeEvidence,
  receiptEvidence,
  authorizedEffectDetail,
  evaluationEpoch,
  grantPreviouslyConsumed,
} = {}) {
  return buildDecision({
    phase: 'issuance',
    contract,
    appointment,
    scopeEvidence,
    receiptEvidence,
    authorizedEffectDetail,
    evaluationEpoch,
    grantPreviouslyConsumed,
  });
}

export function evaluateProtectedRecordsFixtureAuthorityGrantEffect({
  contract,
  appointment,
  scopeEvidence,
  receiptEvidence,
  authorizedEffectDetail,
  evaluationEpoch,
  grantPreviouslyConsumed,
  issuanceDecision,
} = {}) {
  const extraReasons = [];
  const authorityGrantContractSha256 =
    protectedRecordsFixtureAuthorityGrantContractSha256(contract);
  const effectStatusReason =
    protectedRecordsFixtureAuthorityGrantEffectStatusReason(
      authorityGrantContractSha256
    );
  let issuanceDecisionBound = false;
  if (!issuanceDecision) {
    addReason(extraReasons, 'authority_grant_issuance_decision_missing', 'Accepted issuance-gate evidence is missing.');
  } else {
    try {
      assertProtectedRecordsFixtureAuthorityGrantDecision(
        issuanceDecision,
        contract,
        'issuance',
        { requireAccepted: true }
      );
      issuanceDecisionBound =
        issuanceDecision.binding.receipt_semantic_binding_sha256 ===
          receiptSemanticBindingSha256(receiptEvidence) &&
        issuanceDecision.binding.authorized_effect_detail_sha256 ===
          protectedRecordsAuthorizedEffectDetailSha256(authorizedEffectDetail, contract) &&
        issuanceDecision.binding.signed_payload_sha256 ===
          receiptPayloadSha256(receiptEvidence);
      if (!issuanceDecisionBound) {
        addReason(extraReasons, 'authority_grant_issuance_decision_mismatch', 'Issuance-gate evidence belongs to a different crossing.');
      }
    } catch {
      addReason(extraReasons, 'authority_grant_issuance_decision_invalid', 'Issuance-gate evidence is invalid.');
    }
  }
  return buildDecision({
    phase: 'effect',
    contract,
    appointment,
    scopeEvidence,
    receiptEvidence,
    authorizedEffectDetail,
    evaluationEpoch,
    grantPreviouslyConsumed,
    issuanceDecisionBound,
    extraReasons,
    postConsumptionReasons: effectStatusReason ? [effectStatusReason] : [],
  });
}

export function assertProtectedRecordsFixtureAuthorityGrantDecision(
  decision,
  contract,
  phase,
  { requireAccepted = true } = {}
) {
  assertProtectedRecordsFixtureAuthorityGrantContract(contract);
  assertExactKeys('Protected records fixture authority grant decision', decision, [
    'binding', 'decision', 'evidence', 'phase', 'reason_code', 'reasons', 'result_type',
  ]);
  assertExactKeys('Protected records fixture authority grant decision binding', decision.binding, [
    'authority_grant_contract_sha256', 'authority_grant_id', 'authorized_effect_detail_sha256',
    'crossing_binding_sha256', 'receipt_semantic_binding_sha256', 'signed_payload_sha256',
  ]);
  const expectedContractSha256 = protectedRecordsFixtureAuthorityGrantContractSha256(contract);
  const expectedCrossingBindingSha256 = sha256hex(canonicalize({
    authority_grant_contract_sha256: decision.binding.authority_grant_contract_sha256,
    authorized_effect_detail_sha256: decision.binding.authorized_effect_detail_sha256,
    signed_payload_sha256: decision.binding.signed_payload_sha256,
    receipt_semantic_binding_sha256: decision.binding.receipt_semantic_binding_sha256,
  }));
  if (
    decision.result_type !== PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_DECISION_TYPE ||
    decision.phase !== phase ||
    !['issuance', 'effect'].includes(phase) ||
    decision.binding.authority_grant_id !== protectedRecordsFixtureAuthorityGrantId(contract) ||
    decision.binding.authority_grant_contract_sha256 !== expectedContractSha256 ||
    decision.binding.crossing_binding_sha256 !== expectedCrossingBindingSha256 ||
    !Array.isArray(decision.reasons) ||
    decision.reasons.length === 0 ||
    decision.reason_code !== decision.reasons[0]?.code
  ) {
    throw new Error('Protected records fixture authority grant decision identity drifted');
  }
  for (const key of [
    'authorized_effect_detail_sha256', 'crossing_binding_sha256',
    'receipt_semantic_binding_sha256', 'signed_payload_sha256',
  ]) {
    assertSha256(`Protected records fixture authority decision ${key}`, decision.binding[key]);
  }
  assertExactKeys(
    'Protected records fixture authority decision evidence',
    decision.evidence,
    DECISION_EVIDENCE_KEYS
  );
  if (
    decision.evidence.authority_domain_id !== contract.authority_domain.domain_id ||
    decision.evidence.grantor_role_id !== contract.grantor.role_id ||
    decision.evidence.issuer_slot !== contract.grantee.issuer_slot ||
    decision.evidence.rightful_issuance_scope !== PROTECTED_RECORDS_FIXTURE_RIGHTFUL_ISSUANCE_SCOPE
  ) {
    throw new Error('Protected records fixture authority grant decision evidence identity drifted');
  }
  if (requireAccepted || decision.decision === 'accept') {
    if (
      decision.decision !== 'accept' ||
      decision.reason_code !== `fixture_authority_grant_${phase}_satisfied` ||
      decision.evidence.authority_grant_id !== decision.binding.authority_grant_id ||
      decision.evidence.authority_grant_contract_sha256 !== expectedContractSha256
    ) {
      throw new Error('Protected records fixture authority grant decision was not accepted');
    }
    for (const key of DECISION_EVIDENCE_TRUE_KEYS) {
      if (decision.evidence[key] !== true) {
        throw new Error(`Protected records fixture authority grant accepted evidence ${key} drifted`);
      }
    }
    if (phase === 'issuance') {
      if (
        decision.evidence.signature_verified_before_effect !== false ||
        decision.evidence.verified_signed_payload_identity_present !== false ||
        decision.evidence.accepted_issuance_decision_bound !== false ||
        decision.evidence.fixture_rightful_issuance_path_evidenced !== false
      ) {
        throw new Error('Protected records fixture authority issuance decision overclaimed');
      }
    } else if (
      decision.evidence.signature_verified_before_effect !== true ||
      decision.evidence.verified_signed_payload_identity_present !== true ||
      decision.evidence.accepted_issuance_decision_bound !== true ||
      decision.evidence.fixture_rightful_issuance_path_evidenced !== true
    ) {
      throw new Error('Protected records fixture authority effect decision under-evidenced');
    }
    for (const key of [
      'runtime_private_issuer_identity_disclosed', 'runtime_private_grant_appointment_disclosed',
      'rightful_issuance_proven', 'portable_rightful_issuance_proven',
      'production_rightful_issuance_proven', 'live_authority_proven',
      'revocation_truth_proven', 'current_machine_governance_proven',
      'consequence_lifecycle_closed', 'grant_previously_consumed',
    ]) {
      if (decision.evidence[key] !== false) {
        throw new Error(`Protected records fixture authority decision ${key} overclaimed`);
      }
    }
  } else if (decision.decision !== 'refuse') {
    throw new Error('Protected records fixture authority grant decision state drifted');
  }
  return true;
}

function assertExecutionTrace(trace, contract, crossingBindingSha256, signedPayloadSha256) {
  assertExactKeys('Protected records fixture authority execution trace', trace, [
    'authority_grant_contract_sha256',
    'authority_grant_consumption_count_after', 'authority_grant_consumption_count_before',
    'authority_grant_consumption_sequence', 'effect_gate_sequence', 'issuance_gate_sequence',
    'consumed_grant_store_sha256_after', 'consumed_grant_store_sha256_before',
    'crossing_binding_sha256',
    'receipt_sign_sequence', 'state_entry_count_after', 'state_entry_count_before',
    'runtime_state_sha256_after', 'runtime_state_sha256_before', 'signed_payload_sha256',
    'state_mutation_sequence', 'target_effect_sha256', 'trace_type',
  ]);
  if (trace.trace_type !== PROTECTED_RECORDS_FIXTURE_AUTHORITY_EXECUTION_TRACE_TYPE) {
    throw new Error('Protected records fixture authority execution trace type drifted');
  }
  for (const key of [
    'issuance_gate_sequence', 'receipt_sign_sequence', 'effect_gate_sequence',
    'authority_grant_consumption_sequence', 'state_mutation_sequence',
    'authority_grant_consumption_count_before', 'authority_grant_consumption_count_after',
    'state_entry_count_before', 'state_entry_count_after',
  ]) {
    assertInteger(`Protected records fixture authority trace ${key}`, trace[key]);
  }
  for (const key of [
    'authority_grant_contract_sha256', 'consumed_grant_store_sha256_after',
    'consumed_grant_store_sha256_before', 'crossing_binding_sha256',
    'runtime_state_sha256_after', 'runtime_state_sha256_before',
    'signed_payload_sha256', 'target_effect_sha256',
  ]) {
    assertSha256(`Protected records fixture authority trace ${key}`, trace[key]);
  }
  if (
    trace.authority_grant_contract_sha256 !==
      protectedRecordsFixtureAuthorityGrantContractSha256(contract) ||
    trace.crossing_binding_sha256 !== crossingBindingSha256 ||
    trace.signed_payload_sha256 !== signedPayloadSha256 ||
    trace.target_effect_sha256 !== contract.scope.target_effect_sha256 ||
    trace.consumed_grant_store_sha256_before === trace.consumed_grant_store_sha256_after ||
    trace.runtime_state_sha256_before === trace.runtime_state_sha256_after ||
    !(trace.issuance_gate_sequence < trace.receipt_sign_sequence &&
      trace.receipt_sign_sequence < trace.effect_gate_sequence &&
      trace.effect_gate_sequence < trace.authority_grant_consumption_sequence &&
      trace.authority_grant_consumption_sequence < trace.state_mutation_sequence) ||
    trace.authority_grant_consumption_count_before !== 0 ||
    trace.authority_grant_consumption_count_after !== 1 ||
    trace.state_entry_count_after - trace.state_entry_count_before !== 1
  ) {
    throw new Error('Protected records fixture authority execution trace ordering drifted');
  }
  return true;
}

function expectedSummary(contract) {
  return {
    summary_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_SUMMARY_TYPE,
    authority_domain_id: contract.authority_domain.domain_id,
    authorization_record_id: contract.authorization_record.record_id,
    grantor_actor_id: contract.grantor.actor_id,
    grantor_role_id: contract.grantor.role_id,
    grantee_actor_id: contract.grantee.actor_id,
    issuer_slot: contract.grantee.issuer_slot,
    power_ids: contract.powers.map((power) => power.power_id),
    consequence_path: contract.scope.consequence_path,
    target_handle: contract.scope.target_handle,
    authority_grant_id: protectedRecordsFixtureAuthorityGrantId(contract),
    authority_grant_contract_sha256:
      protectedRecordsFixtureAuthorityGrantContractSha256(contract),
    fixture_clock_model: contract.time_policy.clock_source,
    valid_from_epoch: contract.time_policy.valid_from_epoch,
    expires_at_epoch: contract.time_policy.expires_at_epoch,
    one_use_effect_grant: true,
    replacement_requires_different_contract_sha256: true,
    revocation_checked_at_fixture_evaluation_time: true,
    issuance_gate_evaluated_before_signing: true,
    effect_gate_evaluated_before_authority_grant_consumption: true,
    authority_grant_consumed_before_state_mutation: true,
    exact_runtime_kid_match_proven: true,
    exact_runtime_public_key_match_proven: true,
    receipt_bound_to_authority_grant: true,
    verified_signed_payload_identity_present: true,
    fixture_authority_grant_satisfied_at_evaluation_time: true,
    fixture_rightful_issuance_path_evidenced: true,
    rightful_issuance_scope: PROTECTED_RECORDS_FIXTURE_RIGHTFUL_ISSUANCE_SCOPE,
    runtime_private_issuer_identity_disclosed: false,
    runtime_private_grant_appointment_disclosed: false,
    portable_human_authorization_attestation: false,
    rightful_issuance_proven: false,
    portable_rightful_issuance_proven: false,
    production_rightful_issuance_proven: false,
    live_authority_proven: false,
    live_revocation_proven: false,
    current_machine_governance_proven: false,
    consequence_lifecycle_closed: false,
  };
}

export function buildProtectedRecordsFixtureAuthorityGrantSummary({
  contract,
  issuanceDecision,
  effectDecision,
  executionTrace,
} = {}) {
  const contractSha256 = protectedRecordsFixtureAuthorityGrantContractSha256(contract);
  const currentStatusReason =
    protectedRecordsFixtureAuthorityGrantEffectStatusReason(contractSha256);
  if (currentStatusReason) {
    throw new Error(
      `Protected records fixture-rightful summary projection refused: ${currentStatusReason.code}`,
    );
  }
  assertProtectedRecordsFixtureAuthorityGrantDecision(
    issuanceDecision,
    contract,
    'issuance',
    { requireAccepted: true }
  );
  assertProtectedRecordsFixtureAuthorityGrantDecision(
    effectDecision,
    contract,
    'effect',
    { requireAccepted: true }
  );
  if (
    issuanceDecision.binding.crossing_binding_sha256 !==
      effectDecision.binding.crossing_binding_sha256
  ) {
    throw new Error('Protected records fixture authority decisions belong to different crossings');
  }
  assertExecutionTrace(
    executionTrace,
    contract,
    effectDecision.binding.crossing_binding_sha256,
    effectDecision.binding.signed_payload_sha256
  );
  const summary = expectedSummary(contract);
  assertProtectedRecordsFixtureAuthorityGrantSummary(summary, contract);
  return summary;
}

export function assertProtectedRecordsFixtureAuthorityGrantSummary(summary, contract) {
  const expected = expectedSummary(contract);
  assertExactKeys('Protected records fixture authority grant summary', summary, Object.keys(expected));
  if (canonicalize(summary) !== canonicalize(expected)) {
    throw new Error('Protected records fixture authority grant summary overclaimed or drifted');
  }
  return true;
}
