import { readFileSync } from 'node:fs';
import {
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_CONFIRMATION_TYPE_V2,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_CLOCK_SOURCE_V2,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_CONSEQUENCE_PATH_V2,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_RECEIPT_EVIDENCE_TYPE_V2,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_SCOPE_EVIDENCE_TYPE_V2,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_STATUS_TYPE_V2,
  assertProtectedRecordsFixtureAuthorityGrantContractShapeV2,
  assertProtectedRecordsFixtureAuthorityGrantContractV2,
  assertProtectedRecordsFixtureAuthoritySourcePreconditionV2,
  createProtectedRecordsFixtureAuthorityAppointmentV2,
  createProtectedRecordsFixtureAuthorityGrantContractV2,
  createProtectedRecordsFixtureAuthoritySourcePreconditionV2,
  evaluateProtectedRecordsFixtureAuthorityEffectV2,
  evaluateProtectedRecordsFixtureAuthorityIssuanceV2,
  isProtectedRecordsFixtureAuthorityGrantContractV2,
  protectedRecordsAuthorizedEffectDetailSha256V2,
  protectedRecordsAuthorizedEffectDetailV2,
  protectedRecordsFixtureAuthorityAppointmentSha256V2,
  protectedRecordsFixtureAuthorityConditionalAuthorizationBodySha256V2,
  protectedRecordsFixtureAuthorityExactConfirmationSha256V2,
  protectedRecordsFixtureAuthorityGrantContractSha256V2,
  protectedRecordsFixtureAuthorityImplementationBindingFromSourcePreconditionV2,
  protectedRecordsFixtureAuthoritySourcePreconditionBodySha256V2,
} from '../lib/protected-records-fixture-authority-grant-v2.mjs';
import { canonicalize } from '../lib/canonicalize.mjs';
import { sha256hex } from '../lib/receipt.mjs';

let assertions = 0;

function equal(label, expected, actual) {
  assertions += 1;
  if (expected !== actual) {
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function ok(label, value) {
  equal(label, true, Boolean(value));
}

function refuses(label, fn, messagePart) {
  assertions += 1;
  try {
    fn();
  } catch (error) {
    if (String(error?.message).includes(messagePart)) return;
    throw new Error(`${label}: wrong refusal ${error?.message}`);
  }
  throw new Error(`${label}: expected refusal`);
}

function hasReason(label, decision, reasonCode) {
  ok(label, decision.reasons.some((reason) => reason.code === reasonCode));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

const H = Object.freeze({
  source: '1'.repeat(40),
  serviceSchema: '2'.repeat(64),
  terminalSchema: '3'.repeat(64),
  callGraph: '4'.repeat(64),
  targetBinding: '5'.repeat(64),
  profile: '6'.repeat(64),
  recognition: '7'.repeat(64),
  targetContract: '8'.repeat(64),
  installedProfilePreflight: 'e'.repeat(64),
  publicKey: '9'.repeat(64),
  packet: 'a'.repeat(64),
  signedReceipt: 'b'.repeat(64),
  receiptPayload: 'c'.repeat(64),
});

const sourcePrecondition = createProtectedRecordsFixtureAuthoritySourcePreconditionV2({
  sourceCommitOid: H.source,
  serviceArtifactSchemaContractSha256: H.serviceSchema,
  terminalArtifactSchemaContractSha256: H.terminalSchema,
  noReexecutionCallGraphSha256: H.callGraph,
  sourceCompletenessManifest: {
    authority_contract_and_evaluator_source_path:
      'lib/protected-records-fixture-authority-grant-v2.mjs',
    downstream_no_reexecution_source_path:
      'lib/protected-records-replacement-artifact-set-v2.mjs',
    no_reexecution_call_graph_spec_path:
      'spec/protected-records-no-reexecution-call-graph-v2.json',
    replacement_artifact_verifier_source_path:
      'bin/zlar-protected-records-replacement-artifact-set-v2',
    replacement_crossing_driver_cli_source_path:
      'bin/zlar-protected-records-replacement-crossing-v2',
    replacement_crossing_driver_cli_implementation_source_path:
      'lib/protected-records-replacement-crossing-cli-v2.mjs',
    replacement_crossing_driver_library_source_path:
      'lib/protected-records-replacement-crossing-driver-v2.mjs',
    replacement_hash_utility_source_path: 'lib/sha256.mjs',
    replacement_runtime_service_child_source_path:
      'lib/protected-records-replacement-runtime-child-v2.mjs',
    replacement_source_snapshot_boundary_source_path:
      'lib/protected-records-replacement-source-snapshot-v2.mjs',
    runtime_authority_adapter_source_path:
      'lib/protected-records-runtime-authority-v2.mjs',
    runtime_consequence_boundary_source_path:
      'lib/protected-records-runtime-profile.mjs',
    runtime_service_cli_source_path:
      'bin/zlar-protected-records-runtime-service',
    service_artifact_schema_source_path:
      'lib/protected-records-replacement-artifacts-v2.mjs',
    source_complete: true,
    terminal_artifact_schema_source_path:
      'lib/protected-records-replacement-artifacts-v2.mjs',
  },
  refusalTestManifest: {
    test_scope: 'pure-schema-refusal-static-no-consequence',
    key_generation_performed: false,
    receipt_signing_performed: false,
    positive_consequence_executed: false,
    test_paths: ['tests/test-protected-records-fixture-authority-grant-v2.mjs'],
    tests_passed: true,
  },
});
const sourcePreflightSha256 =
  protectedRecordsFixtureAuthoritySourcePreconditionBodySha256V2(sourcePrecondition);
const implementationBinding =
  protectedRecordsFixtureAuthorityImplementationBindingFromSourcePreconditionV2(
    sourcePrecondition,
  );
const targetEffect = {
  target_handle: `zlar-target:v1:logical-fixture:${'f'.repeat(64)}`,
  record_update: {
    operation: 'set_status',
    record_alias: 'schema-only-non-authority',
  },
};
const scope = {
  consequence_path: PROTECTED_RECORDS_FIXTURE_AUTHORITY_CONSEQUENCE_PATH_V2,
  action_class: 'records.write',
  target_kind: 'process-private-recognized-effect-state',
  target_scope: 'logical-fixture',
  target_instance_scope: 'logical-fixture-not-per-run',
  target_handle: targetEffect.target_handle,
  installed_profile_preflight_artifact_body_sha256:
    H.installedProfilePreflight,
  launcher_target_binding_sha256: H.targetBinding,
  record_update_sha256: sha256hex(canonicalize(targetEffect.record_update)),
  target_effect_sha256: sha256hex(canonicalize(targetEffect)),
  profile_id: 'protected-records-runtime-fixture-profile',
  runtime_profile_id: 'protected-records-disposable-runtime-profile',
  profile_sha256: H.profile,
  recognition_contract_sha256: H.recognition,
  target_contract_sha256: H.targetContract,
  source_precondition_artifact_body_sha256: sourcePreflightSha256,
  policy_version: 'recognition-policy-v1',
  receipt_audit_event_id: 'schema-only-fixture-audit-event',
  receipt_version: 1,
  receipt_type: 'governed-action',
  receipt_domain: 'records',
  receipt_rule: 'RRECORDS_ALLOW',
  receipt_authorizer: 'policy',
  receipt_outcome: 'allow',
};
const contract = createProtectedRecordsFixtureAuthorityGrantContractV2({
  authorizationRecordId: 'schema-only-conditional-authorization-not-executable',
  implementationBinding,
  scope,
  validFromEpoch: 2_000_000_000,
  expiresAtEpoch: 2_000_000_120,
});
const contractSha256 = protectedRecordsFixtureAuthorityGrantContractSha256V2(contract);
const appointment = createProtectedRecordsFixtureAuthorityAppointmentV2({
  contract,
  expectedContractSha256: contractSha256,
  issuerKid: 'fixture-schema-only-public-identity',
  publicKeySha256: H.publicKey,
  issuedAtEpoch: 1_999_999_990,
});
const appointmentSha256 = protectedRecordsFixtureAuthorityAppointmentSha256V2(
  appointment,
  { contract, expectedContractSha256: contractSha256 },
);
const confirmation = {
  confirmation_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_CONFIRMATION_TYPE_V2,
  confirmation_version: 2,
  authority_source: 'explicit-in-thread-control-tower-exact-human-confirmation',
  decision: 'authorize-one-canonical-positive-crossing',
  confirmed_by: {
    actor_id: 'fixture-deployment-owner',
    role_id: 'fixture-consequence-authority',
  },
  confirmed_at_epoch: 1_999_999_995,
  post_hardening_authorization_packet_body_sha256: H.packet,
  source_precondition_presented: true,
  authority_grant_contract_sha256: contractSha256,
  appointment_sha256: appointmentSha256,
  issuer_binding: {
    issuer_slot: appointment.issuer_slot,
    issuer_kid: appointment.issuer_kid,
    public_key_sha256: appointment.public_key_sha256,
  },
  time_window: {
    valid_from_epoch: contract.time_policy.valid_from_epoch,
    expires_at_epoch: contract.time_policy.expires_at_epoch,
    interval: 'half-open-[valid_from,expires_at)',
  },
  use_limit: 1,
  no_delegation: true,
};
const confirmationSha256 =
  protectedRecordsFixtureAuthorityExactConfirmationSha256V2(confirmation, {
    contract,
    expectedContractSha256: contractSha256,
    appointment,
  });
const unrecognizedStatus = {
  status_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_STATUS_TYPE_V2,
  status_version: 2,
  authority_grant_contract_sha256: contractSha256,
  appointment_sha256: appointmentSha256,
  confirmation_sha256: confirmationSha256,
  status: 'unrecognized',
  status_source: 'no-source-authorized-v2-status-record',
  maximum_effect_uses: 1,
  recorded_effect_uses: 0,
  fresh_effect_allowed: false,
  repeated_use_provenance_valid: false,
  historical_fixture_authority_at_effect_projection_allowed: false,
  consumed_crossing_binding_sha256: null,
  revoked_at_epoch: null,
  revocation_reason_code: null,
  status_updated_at_epoch: 1_999_999_995,
};
const authorizedEffectDetail = protectedRecordsAuthorizedEffectDetailV2({
  contract,
  expectedContractSha256: contractSha256,
  targetEffect,
});
const authorizedEffectDetailSha256 =
  protectedRecordsAuthorizedEffectDetailSha256V2(authorizedEffectDetail, {
    contract,
    expectedContractSha256: contractSha256,
  });
const scopeEvidence = {
  evidence_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_SCOPE_EVIDENCE_TYPE_V2,
  source: 'validated-launcher-profile-recognition-target-config',
  validated_launcher_config: true,
  derived_from_authority_grant_contract: false,
  derived_from_request_stream: false,
  scope: clone(scope),
};
const unsignedReceiptEvidence = {
  evidence_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_RECEIPT_EVIDENCE_TYPE_V2,
  receipt_evidence_phase: 'issuance',
  source: 'canonical-unsigned-receipt-payload-pre-signing',
  receipt_action_class: scope.action_class,
  receipt_audit_event_id: scope.receipt_audit_event_id,
  policy_version: scope.policy_version,
  delegation_chain_present: true,
  delegation_chain: [],
  authority_grant_contract_sha256: contractSha256,
  authorized_effect_detail_sha256: authorizedEffectDetailSha256,
  receipt_payload_sha256: H.receiptPayload,
  signed_receipt_sha256: null,
  signature_verified: false,
  issuer_kid: appointment.issuer_kid,
  public_key_sha256: appointment.public_key_sha256,
  issued_at_epoch: 2_000_000_001,
  receipt_version: 1,
  receipt_type: 'governed-action',
  receipt_domain: 'records',
  receipt_rule: 'RRECORDS_ALLOW',
  receipt_authorizer: 'policy',
  receipt_outcome: 'allow',
};
const signedReceiptEvidence = {
  ...clone(unsignedReceiptEvidence),
  receipt_evidence_phase: 'effect',
  source: 'independent-signed-receipt-verification',
  signed_receipt_sha256: H.signedReceipt,
  signature_verified: true,
};

console.log('\n-- source-only preflight and non-circular identities --');
ok('source precondition validates', assertProtectedRecordsFixtureAuthoritySourcePreconditionV2(sourcePrecondition));
for (const field of Object.keys(sourcePrecondition.source_completeness_manifest)) {
  if (field === 'source_complete') continue;
  const driftedPrecondition = clone(sourcePrecondition);
  driftedPrecondition.source_completeness_manifest[field] = 'wrong/source-path';
  refuses(
    `source completeness ${field} drift refuses`,
    () => assertProtectedRecordsFixtureAuthoritySourcePreconditionV2(
      driftedPrecondition,
    ),
    'drifted',
  );
}
equal('source preflight P is SHA-256', 64, sourcePreflightSha256.length);
equal(
  'P is not embedded in its own body',
  false,
  canonicalize(sourcePrecondition).includes(sourcePreflightSha256),
);
equal(
  'grant scope separately binds installed-profile provenance preflight',
  H.installedProfilePreflight,
  contract.scope.installed_profile_preflight_artifact_body_sha256,
);
equal(
  'grant scope binds source-precondition P without overloading installed-profile preflight',
  sourcePreflightSha256,
  contract.scope.source_precondition_artifact_body_sha256,
);
equal('grant binds Git sha1 C0', H.source, contract.implementation_binding.source_commit_oid);
equal('grant binds service schema SS', H.serviceSchema, contract.implementation_binding.service_artifact_schema_contract_sha256);
equal('grant binds terminal schema TS', H.terminalSchema, contract.implementation_binding.terminal_artifact_schema_contract_sha256);
equal('grant binds no-reexecution graph N', H.callGraph, contract.implementation_binding.no_reexecution_call_graph_sha256);
equal(
  'grant binds runtime process wall clock at effect',
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_CLOCK_SOURCE_V2,
  contract.time_policy.clock_source,
);
equal(
  'G does not embed downstream confirmation A',
  false,
  canonicalize(contract).includes(confirmationSha256),
);
equal(
  'conditional body hash is exact',
  contract.authorization_record.authorization_body_sha256,
  protectedRecordsFixtureAuthorityConditionalAuthorizationBodySha256V2(contract),
);

console.log('\n-- exact v2 contract dispatch and fail-closed schema --');
ok('v2 predicate recognizes v2 contract', isProtectedRecordsFixtureAuthorityGrantContractV2(contract));
equal('v2 predicate leaves v1 contract false', false, isProtectedRecordsFixtureAuthorityGrantContractV2({
  contract_type: 'zlar-protected-records-fixture-authority-grant-contract-v1',
  contract_version: 1,
}));
ok('contract shape validates without activating it', assertProtectedRecordsFixtureAuthorityGrantContractShapeV2(contract));
ok('exact contract identity validates', assertProtectedRecordsFixtureAuthorityGrantContractV2(contract, {
  expectedContractSha256: contractSha256,
}));
refuses(
  'missing exact expected contract identity refuses',
  () => assertProtectedRecordsFixtureAuthorityGrantContractV2(contract),
  'expected contract SHA-256',
);
refuses(
  'mismatched exact expected contract identity refuses',
  () => assertProtectedRecordsFixtureAuthorityGrantContractV2(contract, {
    expectedContractSha256: 'f'.repeat(64),
  }),
  'exact contract identity mismatched',
);

for (const [label, mutate, expectedMessage] of [
  ['wrong authority domain', (value) => { value.authority_domain.domain_id = 'wrong'; }, 'domain or actor'],
  ['wrong consequence path', (value) => { value.scope.consequence_path = 'wrong'; }, 'consequence path'],
  ['max uses greater than one', (value) => { value.usage_policy.max_uses = 2; }, 'one-use boundary'],
  ['delegation enabled', (value) => { value.delegation_policy.delegation_allowed = true; }, 'delegation is forbidden'],
  ['portable claim widened', (value) => { value.claim_ceiling.portable_rightful_issuance_proven = true; }, 'claim ceiling'],
]) {
  const changed = clone(contract);
  mutate(changed);
  changed.authorization_record.authorization_body_sha256 =
    protectedRecordsFixtureAuthorityConditionalAuthorizationBodySha256V2(changed);
  refuses(label, () => assertProtectedRecordsFixtureAuthorityGrantContractShapeV2(changed), expectedMessage);
}

console.log('\n-- conditional authorization cannot execute --');
const baseInputs = {
  contract,
  expectedContractSha256: contractSha256,
  sourcePrecondition,
  appointment,
  confirmation,
  authorityStatus: unrecognizedStatus,
  scopeEvidence,
  receiptEvidence: unsignedReceiptEvidence,
  authorizedEffectDetail,
  evaluationEpoch: 2_000_000_002,
  grantPreviouslyConsumed: false,
};
const issuance = evaluateProtectedRecordsFixtureAuthorityIssuanceV2(baseInputs);
equal('issuance refuses without source-authorized active status', 'refuse', issuance.decision);
hasReason('issuance names inactive status', issuance, 'authority_status_not_active');
equal(
  'conditional body does not self-execute evidence is explicit',
  true,
  issuance.evidence.conditional_authorization_does_not_self_execute,
);
equal('no current fresh status is projected', false, issuance.evidence.fresh_source_authorized_status_matched);

const missingConfirmation = evaluateProtectedRecordsFixtureAuthorityIssuanceV2({
  ...baseInputs,
  confirmation: null,
});
equal('missing exact confirmation refuses', 'refuse', missingConfirmation.decision);
hasReason(
  'missing exact confirmation has exact reason',
  missingConfirmation,
  'exact_human_confirmation_invalid_or_absent',
);

const wrongIssuerReceipt = clone(unsignedReceiptEvidence);
wrongIssuerReceipt.issuer_kid = 'mismatched-runtime-private-issuer';
const wrongIssuer = evaluateProtectedRecordsFixtureAuthorityIssuanceV2({
  ...baseInputs,
  receiptEvidence: wrongIssuerReceipt,
});
equal('wrong runtime-private issuer refuses', 'refuse', wrongIssuer.decision);
hasReason(
  'wrong runtime-private issuer names binding mismatch',
  wrongIssuer,
  'receipt_issuer_or_grant_binding_mismatched',
);

const outsideWindow = evaluateProtectedRecordsFixtureAuthorityIssuanceV2({
  ...baseInputs,
  evaluationEpoch: contract.time_policy.expires_at_epoch,
});
equal('expiry endpoint refuses under half-open interval', 'refuse', outsideWindow.decision);
hasReason('expiry endpoint names window', outsideWindow, 'grant_outside_half_open_window');

const consumed = evaluateProtectedRecordsFixtureAuthorityIssuanceV2({
  ...baseInputs,
  grantPreviouslyConsumed: true,
});
equal('previously consumed one-use grant refuses', 'refuse', consumed.decision);
hasReason('previously consumed one-use reason is exact', consumed, 'authority_grant_previously_consumed');

const wrongEffectReceipt = clone(unsignedReceiptEvidence);
wrongEffectReceipt.authorized_effect_detail_sha256 = 'd'.repeat(64);
const effectMismatch = evaluateProtectedRecordsFixtureAuthorityIssuanceV2({
  ...baseInputs,
  receiptEvidence: wrongEffectReceipt,
});
equal('receipt/effect identity mismatch refuses', 'refuse', effectMismatch.decision);
hasReason('receipt/effect mismatch reason is exact', effectMismatch, 'receipt_effect_binding_mismatched');

const effect = evaluateProtectedRecordsFixtureAuthorityEffectV2({
  ...baseInputs,
  receiptEvidence: signedReceiptEvidence,
  issuanceDecision: issuance,
});
equal('effect refuses without accepted bound issuance', 'refuse', effect.decision);
hasReason(
  'effect requires accepted bound issuance',
  effect,
  'accepted_issuance_decision_missing_or_unbound',
);

console.log('\n-- pure evaluator happy path does not execute an effect --');
// This synthetic in-memory status is not exported, persisted, or source-recorded
// as authority. It proves only that the evaluator can reach its accept branch
// when every required input is supplied; no generator or effect function exists
// in this module or test.
const activeStatus = {
  ...clone(unrecognizedStatus),
  status: 'active',
  status_source: 'source-recorded-exact-human-confirmation',
  fresh_effect_allowed: true,
  repeated_use_provenance_valid: true,
  status_updated_at_epoch: confirmation.confirmed_at_epoch,
};
const acceptedIssuance = evaluateProtectedRecordsFixtureAuthorityIssuanceV2({
  ...baseInputs,
  authorityStatus: activeStatus,
  receiptEvidence: unsignedReceiptEvidence,
});
equal('pure issuance evaluator accepts before signing', 'accept', acceptedIssuance.decision);
equal(
  'accepted issuance contains no signed receipt identity',
  null,
  acceptedIssuance.binding.signed_receipt_sha256,
);
equal(
  'accepted issuance binds canonical unsigned payload',
  H.receiptPayload,
  acceptedIssuance.binding.receipt_payload_sha256,
);
equal(
  'accepted issuance binds exact audit event id',
  scope.receipt_audit_event_id,
  acceptedIssuance.binding.receipt_audit_event_id,
);
equal(
  'accepted issuance explicitly proves pre-signing boundary',
  true,
  acceptedIssuance.evidence.issuance_pre_signing_boundary_matched,
);
equal(
  'accepted issuance binds explicit empty delegation state',
  true,
  acceptedIssuance.evidence.no_delegation_matched,
);
equal(
  'accepted issuance binds exact authority status',
  64,
  acceptedIssuance.binding.authority_status_sha256.length,
);
const acceptedEffect = evaluateProtectedRecordsFixtureAuthorityEffectV2({
  ...baseInputs,
  authorityStatus: activeStatus,
  receiptEvidence: signedReceiptEvidence,
  issuanceDecision: acceptedIssuance,
});
equal('pure effect evaluator accepts verified signed envelope', 'accept', acceptedEffect.decision);
equal(
  'effect binds same canonical payload as issuance',
  acceptedIssuance.binding.receipt_payload_sha256,
  acceptedEffect.binding.receipt_payload_sha256,
);
equal(
  'effect binds same audit event id as issuance',
  acceptedIssuance.binding.receipt_audit_event_id,
  acceptedEffect.binding.receipt_audit_event_id,
);
equal(
  'effect binds same delegation state as issuance',
  acceptedIssuance.binding.receipt_delegation_state_sha256,
  acceptedEffect.binding.receipt_delegation_state_sha256,
);
equal(
  'effect binds signed envelope separately from payload',
  H.signedReceipt,
  acceptedEffect.binding.signed_receipt_sha256,
);
equal(
  'effect binds accepted issuance decision',
  64,
  acceptedEffect.binding.issuance_decision_sha256.length,
);

for (const [label, field, value] of [
  ['audit event', 'receipt_audit_event_id', 'changed-audit-event'],
  ['action class', 'receipt_action_class', 'records.delete'],
  ['policy version', 'policy_version', 'recognition-policy-v2'],
]) {
  const changedReceiptIdentity = {
    ...clone(signedReceiptEvidence),
    [field]: value,
  };
  const changedIdentityEffect = evaluateProtectedRecordsFixtureAuthorityEffectV2({
    ...baseInputs,
    authorityStatus: activeStatus,
    receiptEvidence: changedReceiptIdentity,
    issuanceDecision: acceptedIssuance,
  });
  equal(`${label} drift refuses at effect`, 'refuse', changedIdentityEffect.decision);
  hasReason(
    `${label} drift names receipt evidence mismatch`,
    changedIdentityEffect,
    'receipt_evidence_invalid',
  );
}

const absentDelegationUnsigned = {
  ...clone(unsignedReceiptEvidence),
  delegation_chain_present: false,
  delegation_chain: null,
};
const absentDelegationIssuance =
  evaluateProtectedRecordsFixtureAuthorityIssuanceV2({
    ...baseInputs,
    authorityStatus: activeStatus,
    receiptEvidence: absentDelegationUnsigned,
  });
equal(
  'absent delegation field representation refuses at issuance',
  'refuse',
  absentDelegationIssuance.decision,
);
hasReason(
  'absent issuance delegation names canonical-state refusal',
  absentDelegationIssuance,
  'receipt_delegation_state_invalid',
);
const absentDelegationSigned = {
  ...clone(signedReceiptEvidence),
  delegation_chain_present: false,
  delegation_chain: null,
};
const absentDelegationEffect = evaluateProtectedRecordsFixtureAuthorityEffectV2({
  ...baseInputs,
  authorityStatus: activeStatus,
  receiptEvidence: absentDelegationSigned,
  issuanceDecision: acceptedIssuance,
});
equal(
  'absent delegation field representation refuses at effect',
  'refuse',
  absentDelegationEffect.decision,
);
hasReason(
  'absent effect delegation names canonical-state refusal',
  absentDelegationEffect,
  'receipt_delegation_state_invalid',
);

const delegatedReceiptEvidence = {
  ...clone(signedReceiptEvidence),
  delegation_chain_present: true,
  delegation_chain: [{ depth: 0, principal: 'forbidden-delegate' }],
};
const delegatedIssuanceEvidence = {
  ...clone(unsignedReceiptEvidence),
  delegation_chain_present: true,
  delegation_chain: [{ depth: 0, principal: 'forbidden-delegate' }],
};
const delegatedIssuance = evaluateProtectedRecordsFixtureAuthorityIssuanceV2({
  ...baseInputs,
  authorityStatus: activeStatus,
  receiptEvidence: delegatedIssuanceEvidence,
});
equal(
  'nonempty delegation chain refuses before issuance',
  'refuse',
  delegatedIssuance.decision,
);
hasReason(
  'nonempty issuance delegation names exact refusal',
  delegatedIssuance,
  'receipt_delegation_forbidden',
);
const delegatedEffect = evaluateProtectedRecordsFixtureAuthorityEffectV2({
  ...baseInputs,
  authorityStatus: activeStatus,
  receiptEvidence: delegatedReceiptEvidence,
  issuanceDecision: acceptedIssuance,
});
equal('nonempty delegation chain refuses at effect', 'refuse', delegatedEffect.decision);
hasReason(
  'nonempty delegation chain names exact refusal',
  delegatedEffect,
  'receipt_delegation_forbidden',
);

const futureDatedStatus = {
  ...clone(activeStatus),
  status_updated_at_epoch: 2_000_000_003,
};
const futureDated = evaluateProtectedRecordsFixtureAuthorityIssuanceV2({
  ...baseInputs,
  authorityStatus: futureDatedStatus,
  receiptEvidence: unsignedReceiptEvidence,
  evaluationEpoch: 2_000_000_002,
});
equal('future-dated active status refuses', 'refuse', futureDated.decision);
hasReason(
  'future-dated active status names exact reason',
  futureDated,
  'authority_status_future_dated',
);

console.log('\n-- static source-only guard --');
const source = readFileSync(
  'lib/protected-records-fixture-authority-grant-v2.mjs',
  'utf8',
);
for (const forbidden of [
  'node:crypto',
  'node:fs',
  'generateKeyPair',
  'privateKey',
  'writeFile',
  "from './protected-records-fixture-authority-status.mjs'",
]) {
  equal(`source excludes ${forbidden}`, false, source.includes(forbidden));
}
equal(
  'source contains no exact replacement contract SHA constant',
  false,
  /CURRENT.*GRANT.*SHA256/.test(source),
);

console.log(`\nprotected records fixture authority grant v2: ${assertions}/${assertions} assertions passed`);
