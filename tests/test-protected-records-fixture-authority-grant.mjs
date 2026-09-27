#!/usr/bin/env node

import { canonicalize } from '../lib/canonicalize.mjs';
import { sha256hex } from '../lib/receipt.mjs';
import {
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_DOMAIN_ID,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_EVALUATION_EPOCH,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID,
  PROTECTED_RECORDS_FIXTURE_AUTHORIZATION_BODY_SHA256,
  PROTECTED_RECORDS_FIXTURE_AUTHORIZATION_BODY_TYPE,
  PROTECTED_RECORDS_FIXTURE_ISSUER_SLOT,
  assertProtectedRecordsFixtureAuthorityGrantContract,
  buildProtectedRecordsFixtureAuthorityGrantSummary,
  createProtectedRecordsFixtureAuthorityGrantAppointment,
  createProtectedRecordsFixtureAuthorityGrantContract,
  evaluateProtectedRecordsFixtureAuthorityGrantEffect,
  evaluateProtectedRecordsFixtureAuthorityGrantIssuance,
  protectedRecordsAuthorizedEffectDetail,
  protectedRecordsAuthorizedEffectDetailSha256,
  protectedRecordsFixtureAuthorityAuthorizationBodySha256,
  protectedRecordsFixtureAuthorityGrantContractSha256,
  protectedRecordsFixtureAuthorityGrantId,
} from '../lib/protected-records-fixture-authority-grant.mjs';
import {
  PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256,
  PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_STATUS,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_EXHAUSTED_REASON_CODE,
  protectedRecordsFixtureAuthorityGrantStatus,
} from '../lib/protected-records-fixture-authority-status.mjs';

let pass = 0;
let fail = 0;
let total = 0;
function assert(label, condition, detail = '') {
  total++;
  if (condition) { pass++; console.log(`  PASS: ${label}`); }
  else { fail++; console.log(`  FAIL: ${label}${detail ? ` -- ${detail}` : ''}`); }
}
function equal(label, expected, actual) {
  assert(label, expected === actual, `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
}
function throws(label, fn, fragment = '') {
  total++;
  try { fn(); fail++; console.log(`  FAIL: ${label} -- expected throw`); }
  catch (err) {
    if (!fragment || String(err.message).includes(fragment)) { pass++; console.log(`  PASS: ${label}`); }
    else { fail++; console.log(`  FAIL: ${label} -- ${err.message}`); }
  }
}
function clone(value) { return structuredClone(value); }

const now = PROTECTED_RECORDS_FIXTURE_AUTHORITY_EVALUATION_EPOCH;
const targetEffect = {
  target_handle:
    'zlar-target:v1:logical-fixture:0ee8bcc85701f8ba374af28393d517d3e3e823d9e8d740d256ae7f7304f7f8a2',
  record_update: {
    operation: 'set_status',
    record_alias: 'selected-installed-profile-service-fixture',
  },
};
const scope = {
  consequencePath: 'protected-records.installed-runtime-profile.terminal-chain.records.write',
  actionClass: 'records.write',
  targetKind: 'process-private-recognized-effect-state',
  targetScope: 'logical-fixture',
  targetInstanceScope: 'logical-fixture-not-per-run',
  targetHandle: targetEffect.target_handle,
  launcherTargetBindingSha256:
    '9d714ebe24688b4f5780aac5fea47dc0c82e64b5f872c9254643ac0b0159fedc',
  recordUpdateSha256: sha256hex(canonicalize(targetEffect.record_update)),
  targetEffectSha256: sha256hex(canonicalize(targetEffect)),
  profileId: 'protected-records-runtime-fixture-profile',
  runtimeProfileId: 'protected-records-disposable-runtime-profile',
  profileSha256:
    'e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469',
  recognitionContractSha256:
    '1ce1351937c4eef665f13bd53696732af0cf05d891600ce5fd6e0655b97cc045',
  targetContractSha256:
    'a771d114340060f269f78f15016c2975983ead7534a499bee3f5912fa05f985b',
};
const contract = createProtectedRecordsFixtureAuthorityGrantContract(scope);
const contractSha = protectedRecordsFixtureAuthorityGrantContractSha256(contract);
const grantId = protectedRecordsFixtureAuthorityGrantId(contract);
const appointment = createProtectedRecordsFixtureAuthorityGrantAppointment({
  contract,
  granteeIssuerKid: 'fixture-kid-001',
  granteePublicKeySha256: 'f'.repeat(64),
});
const scopeEvidence = {
  source: 'validated-launcher-profile-recognition-target-config',
  validated_launcher_config: true,
  derived_from_authority_grant_contract: false,
  derived_from_request_stream: false,
  scope: { ...contract.scope },
};
const detail = protectedRecordsAuthorizedEffectDetail({ contract, targetEffect });
const detailSha = protectedRecordsAuthorizedEffectDetailSha256(detail, contract);

function receiptEvidence(phase, overrides = {}) {
  const evidence = {
    audit_event_id: 'fixture-authority-grant-001',
    source: phase === 'issuance'
      ? 'unsigned-receipt-payload-before-signing'
      : 'cryptographically-verified-downstream-recognition',
    signature_verified: phase === 'effect',
    downstream_recognition_accepted: phase === 'effect',
    issuer_status: phase === 'effect' ? 'active' : null,
    verified_signed_payload_sha256: null,
    issuer_kid: appointment.grantee_issuer_kid,
    public_key_sha256: appointment.grantee_public_key_sha256,
    issued_at_epoch: now - 5,
    policy_version: contract.scope.policy_version,
    tool: contract.scope.action_class,
    domain: contract.scope.receipt_domain,
    rule: contract.scope.receipt_rule,
    authorizer: contract.scope.receipt_authorizer,
    outcome: contract.scope.receipt_outcome,
    receipt_version: contract.scope.receipt_version,
    receipt_type: contract.scope.receipt_type,
    detail_hash: detailSha,
  };
  Object.assign(evidence, overrides);
  if (!Object.hasOwn(overrides, 'payload')) {
    evidence.payload = {
      audit_event_id: evidence.audit_event_id,
      authorizer: evidence.authorizer,
      detail_hash: evidence.detail_hash,
      domain: evidence.domain,
      outcome: evidence.outcome,
      policy_version: evidence.policy_version,
      rule: evidence.rule,
      tool: evidence.tool,
      ts: new Date(evidence.issued_at_epoch * 1000).toISOString(),
    };
  }
  if (phase === 'effect' && !Object.hasOwn(overrides, 'verified_signed_payload_sha256')) {
    evidence.verified_signed_payload_sha256 = sha256hex(canonicalize(evidence.payload));
  }
  return evidence;
}

function evaluateIssuance({
  useContract = contract,
  useAppointment = appointment,
  useScopeEvidence = scopeEvidence,
  useReceipt = receiptEvidence('issuance'),
  useDetail = detail,
  evaluationEpoch = now - 4,
  grantPreviouslyConsumed = false,
} = {}) {
  return evaluateProtectedRecordsFixtureAuthorityGrantIssuance({
    contract: useContract,
    appointment: useAppointment,
    scopeEvidence: useScopeEvidence,
    receiptEvidence: useReceipt,
    authorizedEffectDetail: useDetail,
    evaluationEpoch,
    grantPreviouslyConsumed,
  });
}

const issuance = evaluateIssuance();
function evaluateEffect({
  useContract = contract,
  useAppointment = appointment,
  useScopeEvidence = scopeEvidence,
  useReceipt = receiptEvidence('effect'),
  useDetail = detail,
  evaluationEpoch = now,
  grantPreviouslyConsumed = false,
  useIssuanceDecision = issuance,
} = {}) {
  return evaluateProtectedRecordsFixtureAuthorityGrantEffect({
    contract: useContract,
    appointment: useAppointment,
    scopeEvidence: useScopeEvidence,
    receiptEvidence: useReceipt,
    authorizedEffectDetail: useDetail,
    evaluationEpoch,
    grantPreviouslyConsumed,
    issuanceDecision: useIssuanceDecision,
  });
}

console.log('\n-- immutable fixture authority contract --');
assert('contract validates', assertProtectedRecordsFixtureAuthorityGrantContract(contract));
equal('domain exact', PROTECTED_RECORDS_FIXTURE_AUTHORITY_DOMAIN_ID, contract.authority_domain.domain_id);
equal('grantor role exact', PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID, contract.grantor.role_id);
equal('issuer slot exact', PROTECTED_RECORDS_FIXTURE_ISSUER_SLOT, contract.grantee.issuer_slot);
equal(
  'authorization body type exact',
  PROTECTED_RECORDS_FIXTURE_AUTHORIZATION_BODY_TYPE,
  contract.authorization_record.authorization_body_type
);
equal(
  'authorization body digest exact',
  PROTECTED_RECORDS_FIXTURE_AUTHORIZATION_BODY_SHA256,
  contract.authorization_record.authorization_body_sha256
);
equal(
  'authorization body digest recomputes from every authorized field',
  PROTECTED_RECORDS_FIXTURE_AUTHORIZATION_BODY_SHA256,
  protectedRecordsFixtureAuthorityAuthorizationBodySha256(contract)
);
assert('contract sha', /^[a-f0-9]{64}$/.test(contractSha));
equal(
  'contract sha is exact exhausted source record',
  PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256,
  contractSha
);
assert('grant id', /^zlar-grant:v1:[a-f0-9]{64}$/.test(grantId));
equal('one use', 1, contract.usage_policy.max_uses);
equal('absolute fixture window', true, Number.isInteger(contract.time_policy.valid_from_epoch) && Number.isInteger(contract.time_policy.expires_at_epoch));
equal('replacement requires new contract sha', true, contract.usage_policy.replacement_requires_different_contract_sha256);
equal('generic rightful false', false, contract.claim_boundary.generic_rightful_issuance_proven);
equal(
  'public authorization body omits runtime issuer kid',
  false,
  JSON.stringify(contract).includes(appointment.grantee_issuer_kid)
);
equal(
  'public authorization body omits runtime public key hash',
  false,
  JSON.stringify(contract).includes(appointment.grantee_public_key_sha256)
);

function sameRecordResealedVariant(label, mutate) {
  const variant = clone(contract);
  mutate(variant);
  variant.authorization_record.authorization_body_sha256 =
    protectedRecordsFixtureAuthorityAuthorizationBodySha256(variant);
  throws(
    `${label} rejected under the same human authorization record`,
    () => assertProtectedRecordsFixtureAuthorityGrantContract(variant),
    'human authorization body drifted'
  );
}

console.log('\n-- exact human authorization body pin --');
sameRecordResealedVariant('other consequence path', (variant) => {
  variant.scope.consequence_path =
    'protected-records.installed-runtime-profile.terminal-chain.records.delete';
});
sameRecordResealedVariant('other action', (variant) => {
  variant.scope.action_class = 'records.delete';
});
sameRecordResealedVariant('other target handle', (variant) => {
  variant.scope.target_handle = `zlar-target:v1:logical-fixture:${'2'.repeat(64)}`;
});
sameRecordResealedVariant('other launcher target binding hash', (variant) => {
  variant.scope.launcher_target_binding_sha256 = '3'.repeat(64);
});
sameRecordResealedVariant('other record update hash', (variant) => {
  variant.scope.record_update_sha256 = '4'.repeat(64);
});
sameRecordResealedVariant('other profile hash', (variant) => {
  variant.scope.profile_sha256 = '5'.repeat(64);
});
sameRecordResealedVariant('other recognition contract hash', (variant) => {
  variant.scope.recognition_contract_sha256 = '6'.repeat(64);
});
sameRecordResealedVariant('other target contract hash', (variant) => {
  variant.scope.target_contract_sha256 = '7'.repeat(64);
});
sameRecordResealedVariant('other target effect hash', (variant) => {
  variant.scope.target_effect_sha256 = '8'.repeat(64);
});
sameRecordResealedVariant('other issuer slot', (variant) => {
  variant.grantee.issuer_slot = 'other-fixture-receipt-issuer';
});
sameRecordResealedVariant('other absolute grant window', (variant) => {
  variant.time_policy.expires_at_epoch += 1;
});
sameRecordResealedVariant('other use count', (variant) => {
  variant.usage_policy.max_uses = 2;
});
sameRecordResealedVariant('other replacement power', (variant) => {
  variant.powers.find(
    ({ power_id: powerId }) => powerId === 'issue_replacement_authority_grant'
  ).delegable = true;
});
sameRecordResealedVariant('other revocation power', (variant) => {
  variant.powers.find(
    ({ power_id: powerId }) => powerId === 'revoke_authority_grant'
  ).holder = PROTECTED_RECORDS_FIXTURE_ISSUER_SLOT;
});

console.log('\n-- signed authorized effect --');
equal('detail grant id', grantId, detail.authority_grant_id);
equal('detail contract sha', contractSha, detail.authority_grant_contract_sha256);
equal('detail target', canonicalize(targetEffect), canonicalize(detail.target_effect));
equal('detail sha exact', detailSha, sha256hex(canonicalize(detail)));
const wrongEffect = clone(targetEffect);
wrongEffect.record_update.record_alias = 'other-record';
throws(
  'arbitrary effect cannot borrow grant',
  () => protectedRecordsAuthorizedEffectDetail({ contract, targetEffect: wrongEffect }),
  'does not match'
);

console.log('\n-- separate issuance and exhausted effect gates --');
const effect = evaluateEffect();
equal('issuance accepted', 'accept', issuance.decision);
equal('issuance is not full path evidence', false, issuance.evidence.fixture_rightful_issuance_path_evidenced);
equal('issuance has no signature overclaim', false, issuance.evidence.signature_verified_before_effect);
equal('fresh effect refused', 'refuse', effect.decision);
equal(
  'fresh effect refuses exact exhausted grant',
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_EXHAUSTED_REASON_CODE,
  effect.reason_code
);
equal('effect binds issuance decision', true, effect.evidence.accepted_issuance_decision_bound);
equal('effect signature verified', true, effect.evidence.signature_verified_before_effect);
equal('effect signed identity present', true, effect.evidence.verified_signed_payload_identity_present);
equal('grant unused before effect', true, effect.evidence.grant_not_previously_consumed);
equal('signed detail binds exact grant', true, effect.evidence.receipt_bound_to_authority_grant);
equal('generic rightful remains false', false, effect.evidence.rightful_issuance_proven);
equal(
  'fresh fixture-rightful projection remains false',
  false,
  effect.evidence.fixture_rightful_issuance_path_evidenced
);

console.log('\n-- source-pinned authority status --');
const currentStatus = protectedRecordsFixtureAuthorityGrantStatus(contractSha);
equal('current grant status exact', 'exhausted', currentStatus.status);
equal('current grant maximum uses exact', 1, currentStatus.maximum_effect_uses);
equal('current grant recorded uses exact', 1, currentStatus.recorded_effect_uses);
equal('current grant fresh effect disallowed', false, currentStatus.fresh_effect_allowed);
equal('repeated-use provenance invalid', false, currentStatus.repeated_use_provenance_valid);
equal(
  'fresh fixture-rightful projection disallowed',
  false,
  currentStatus.fresh_fixture_rightful_projection_allowed
);
equal('replacement grant absent', false, currentStatus.replacement_authority_grant_present);
equal(
  'exported current status is exact registry result',
  PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_STATUS,
  currentStatus
);
const unrecognizedStatus = protectedRecordsFixtureAuthorityGrantStatus('a'.repeat(64));
equal('unrecognized grant status fails closed', 'unrecognized', unrecognizedStatus.status);
equal('unrecognized grant effect disallowed', false, unrecognizedStatus.fresh_effect_allowed);
const executionTrace = {};
throws(
  'exhausted fresh effect cannot project a fixture-rightful summary',
  () => buildProtectedRecordsFixtureAuthorityGrantSummary({
    contract,
    issuanceDecision: issuance,
    effectDecision: effect,
    executionTrace,
  }),
  'authority_grant_contract_exhausted'
);

console.log('\n-- fail closed matrix --');
equal('missing appointment', 'authority_grant_missing', evaluateEffect({ useAppointment: null }).reason_code);
equal('wrong signed detail hash refuses before signing', 'authority_grant_signed_detail_mismatch', evaluateIssuance({ useReceipt: receiptEvidence('issuance', { detail_hash: '0'.repeat(64) }) }).reason_code);
equal('wrong issuer refuses before signing', 'authority_grant_issuer_mismatch', evaluateIssuance({ useReceipt: receiptEvidence('issuance', { issuer_kid: 'other-kid' }) }).reason_code);
equal('wrong public key refuses before signing', 'authority_grant_public_key_mismatch', evaluateIssuance({ useReceipt: receiptEvidence('issuance', { public_key_sha256: '0'.repeat(64) }) }).reason_code);
equal('receipt before window refuses before signing', 'authority_grant_receipt_before_window', evaluateIssuance({ useReceipt: receiptEvidence('issuance', { issued_at_epoch: contract.time_policy.valid_from_epoch - 1 }) }).reason_code);
equal('receipt at expiry refuses before signing', 'authority_grant_receipt_after_expiry', evaluateIssuance({ useReceipt: receiptEvidence('issuance', { issued_at_epoch: contract.time_policy.expires_at_epoch }) }).reason_code);
equal('future receipt refuses before signing', 'authority_grant_receipt_from_future', evaluateIssuance({ useReceipt: receiptEvidence('issuance', { issued_at_epoch: now + 1 }) }).reason_code);
equal('effect receipt tamper breaks issuance binding', 'authority_grant_issuance_decision_mismatch', evaluateEffect({ useReceipt: receiptEvidence('effect', { issuer_kid: 'other-kid' }) }).reason_code);
equal('effect before window', 'authority_grant_not_yet_valid', evaluateEffect({ evaluationEpoch: contract.time_policy.valid_from_epoch - 1 }).reason_code);
equal('effect at expiry', 'authority_grant_expired', evaluateEffect({ evaluationEpoch: contract.time_policy.expires_at_epoch }).reason_code);
const revoked = createProtectedRecordsFixtureAuthorityGrantAppointment({
  contract,
  granteeIssuerKid: appointment.grantee_issuer_kid,
  granteePublicKeySha256: appointment.grantee_public_key_sha256,
  status: 'revoked',
  revokedAtEpoch: now - 1,
  revocationReasonCode: 'fixture-revoked',
});
equal('revoked grant', 'authority_grant_revoked', evaluateEffect({ useAppointment: revoked }).reason_code);
const changedWindow = clone(appointment);
changedWindow.expires_at_epoch += 1;
equal('appointment cannot extend contract window', 'authority_grant_appointment_mismatch', evaluateEffect({ useAppointment: changedWindow }).reason_code);
const scopeMismatch = clone(scopeEvidence);
scopeMismatch.scope.target_handle = `zlar-target:v1:logical-fixture:${'2'.repeat(64)}`;
equal('scope mismatch', 'authority_grant_scope_mismatch', evaluateEffect({ useScopeEvidence: scopeMismatch }).reason_code);
const requestDerivedScope = { ...scopeEvidence, derived_from_request_stream: true };
equal('request-derived scope refuses', 'authority_grant_scope_provenance_mismatch', evaluateEffect({ useScopeEvidence: requestDerivedScope }).reason_code);
equal('receipt scope mismatch refuses before signing', 'authority_grant_receipt_scope_mismatch', evaluateIssuance({ useReceipt: receiptEvidence('issuance', { authorizer: 'human' }) }).reason_code);
equal('used grant refuses', 'authority_grant_already_consumed', evaluateEffect({ grantPreviouslyConsumed: true }).reason_code);
equal('missing consumption state refuses', 'authority_grant_consumption_state_missing', evaluateEffect({ grantPreviouslyConsumed: null }).reason_code);
equal('missing issuance decision refuses', 'authority_grant_issuance_decision_missing', evaluateEffect({ useIssuanceDecision: null }).reason_code);
equal(
  'unbound verified payload identity refuses',
  'authority_grant_verified_payload_identity_mismatch',
  evaluateEffect({
    useReceipt: receiptEvidence('effect', { verified_signed_payload_sha256: '0'.repeat(64) }),
  }).reason_code
);

throws(
  'replacement window requires a new human authorization record',
  () => createProtectedRecordsFixtureAuthorityGrantContract({
    ...scope,
    validFromEpoch: contract.time_policy.valid_from_epoch + 1,
    expiresAtEpoch: contract.time_policy.expires_at_epoch + 1,
  }),
  'human authorization body drifted'
);

const unknownField = clone(contract);
unknownField.extra = true;
throws('unknown contract field fails', () => assertProtectedRecordsFixtureAuthorityGrantContract(unknownField), 'unexpected fields');
const selfGrant = clone(contract);
selfGrant.grantor.role_id = selfGrant.grantee.issuer_slot;
throws(
  'self grant cannot be built or hashed',
  () => protectedRecordsFixtureAuthorityGrantContractSha256(selfGrant),
  'human authorization body drifted'
);

const fakeIssuance = { phase: 'issuance', decision: 'accept' };
const fakeEffect = { phase: 'effect', decision: 'accept' };
throws(
  'exhausted status blocks summary projection before decision stubs can be considered',
  () => buildProtectedRecordsFixtureAuthorityGrantSummary({
    contract,
    issuanceDecision: fakeIssuance,
    effectDecision: fakeEffect,
    executionTrace,
  }),
  'authority_grant_contract_exhausted'
);
console.log(`\nResults: ${pass}/${total} passed, ${fail} failed`);
if (fail) process.exit(1);
console.log('ALL PASS');
