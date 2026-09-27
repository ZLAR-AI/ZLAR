import { canonicalize } from './canonicalize.mjs';
import {
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_CLOCK_SOURCE_V2,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_RECEIPT_EVIDENCE_TYPE_V2,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_SCOPE_EVIDENCE_TYPE_V2,
  assertProtectedRecordsAuthorizedEffectDetailV2,
  assertProtectedRecordsFixtureAuthorityAppointmentV2,
  assertProtectedRecordsFixtureAuthorityDecisionV2,
  assertProtectedRecordsFixtureAuthorityExactConfirmationV2,
  assertProtectedRecordsFixtureAuthorityGrantContractV2,
  assertProtectedRecordsFixtureAuthorityScopeEvidenceV2,
  assertProtectedRecordsFixtureAuthoritySourcePreconditionV2,
  assertProtectedRecordsFixtureAuthorityStatusV2,
  evaluateProtectedRecordsFixtureAuthorityEffectV2,
  protectedRecordsAuthorizedEffectDetailSha256V2,
  protectedRecordsAuthorizedEffectDetailV2,
  protectedRecordsFixtureAuthorityAppointmentSha256V2,
  protectedRecordsFixtureAuthorityDecisionSha256V2,
  protectedRecordsFixtureAuthorityExactConfirmationSha256V2,
  protectedRecordsFixtureAuthorityGrantContractSha256V2,
  protectedRecordsFixtureAuthorityIssuerBindingSha256V2,
  protectedRecordsFixtureAuthorityImplementationBindingFromSourcePreconditionV2,
  protectedRecordsFixtureAuthoritySourcePreconditionBodySha256V2,
  protectedRecordsFixtureAuthorityStatusSha256V2,
} from './protected-records-fixture-authority-grant-v2.mjs';
import { sha256hex } from './receipt.mjs';

export const PROTECTED_RECORDS_RUNTIME_AUTHORITY_VERSION_V2 = 2;
export const PROTECTED_RECORDS_RUNTIME_SERVICE_RESULT_TYPE_V2 =
  'protected-records-runtime-service-result-v2';
export const PROTECTED_RECORDS_RUNTIME_EFFECT_GATE_BINDING_TYPE_V2 =
  'zlar-protected-records-runtime-authority-effect-gate-binding-v2';
export const PROTECTED_RECORDS_RUNTIME_EXECUTION_TRACE_TYPE_V2 =
  'zlar-protected-records-runtime-authority-execution-trace-v2';
export const PROTECTED_RECORDS_RUNTIME_TRANSITION_BINDING_TYPE_V2 =
  'zlar-protected-records-runtime-ordered-single-lock-transition-binding-v2';
export const PROTECTED_RECORDS_RUNTIME_MINIMUM_EFFECT_MARGIN_SECONDS_V2 = 30;

const SHA256_PATTERN = /^[a-f0-9]{64}$/;

export function evaluateProtectedRecordsRuntimeClockTransitionV2({
  earlierEpoch,
  laterEpoch,
} = {}) {
  const valid =
    Number.isSafeInteger(earlierEpoch) &&
    earlierEpoch >= 0 &&
    Number.isSafeInteger(laterEpoch) &&
    laterEpoch >= 0;
  const accepted = valid && laterEpoch >= earlierEpoch;
  return Object.freeze({
    evaluation_type: 'zlar.protected-records.runtime-clock-transition.v2',
    accepted,
    decision: accepted ? 'continue' : 'refuse',
    reason_code: accepted
      ? 'authority_clock_monotonic'
      : valid
        ? 'authority_clock_regressed'
        : 'authority_clock_unavailable',
    earlier_epoch: valid ? earlierEpoch : null,
    later_epoch: valid ? laterEpoch : null,
    authority_grant_consumed: false,
    runtime_state_mutated: false,
  });
}

export function evaluateProtectedRecordsRuntimeEffectMarginV2({
  grantWindowRemainingSeconds,
  receiptRecognitionRemainingSeconds,
} = {}) {
  const valid =
    Number.isSafeInteger(grantWindowRemainingSeconds) &&
    Number.isSafeInteger(receiptRecognitionRemainingSeconds);
  const accepted =
    valid &&
    grantWindowRemainingSeconds >
      PROTECTED_RECORDS_RUNTIME_MINIMUM_EFFECT_MARGIN_SECONDS_V2 &&
    receiptRecognitionRemainingSeconds >
      PROTECTED_RECORDS_RUNTIME_MINIMUM_EFFECT_MARGIN_SECONDS_V2;
  return Object.freeze({
    evaluation_type: 'zlar.protected-records.runtime-effect-margin.v2',
    accepted,
    decision: accepted ? 'continue' : 'refuse',
    reason_code: accepted
      ? 'authority_effect_window_margin_satisfied'
      : 'authority_effect_window_margin_insufficient',
    minimum_effect_margin_seconds:
      PROTECTED_RECORDS_RUNTIME_MINIMUM_EFFECT_MARGIN_SECONDS_V2,
    grant_window_remaining_seconds: valid
      ? grantWindowRemainingSeconds
      : null,
    receipt_recognition_remaining_seconds: valid
      ? receiptRecognitionRemainingSeconds
      : null,
    authority_grant_consumed: false,
    runtime_state_mutated: false,
  });
}

function requireObject(label, value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function assertSha256(label, value) {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
    throw new Error(`${label} must be SHA-256 hex`);
  }
}

function assertCanonicalEqual(label, actual, expected) {
  if (canonicalize(actual) !== canonicalize(expected)) {
    throw new Error(`${label} drifted`);
  }
}

function assertExactKeys(label, value, expectedKeys) {
  requireObject(label, value);
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${label} contains unexpected or missing fields`);
  }
}

function clone(value) {
  return JSON.parse(canonicalize(value));
}

function exactReceiptRecognitionSemantics() {
  return {
    policy_version: 'recognition-policy-v1',
    receipt_authorizer: 'policy',
    receipt_domain: 'records',
    receipt_outcome: 'allow',
    receipt_rule: 'RRECORDS_ALLOW',
    receipt_type: 'governed-action',
    receipt_version: 1,
  };
}

export function createProtectedRecordsRuntimeScopeEvidenceV2({
  actionClass,
  authorizedRecordUpdate,
  profileId,
  recognitionRule,
  sourcePrecondition,
  targetBinding,
} = {}) {
  requireObject('Protected records runtime v2 authorized record update', authorizedRecordUpdate);
  requireObject('Protected records runtime v2 target binding', targetBinding);
  assertProtectedRecordsFixtureAuthoritySourcePreconditionV2(sourcePrecondition);
  const targetEffect = {
    target_handle: targetBinding.target_handle,
    record_update: clone(authorizedRecordUpdate),
  };
  return {
    evidence_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_SCOPE_EVIDENCE_TYPE_V2,
    source: 'validated-launcher-profile-recognition-target-config',
    validated_launcher_config: true,
    derived_from_authority_grant_contract: false,
    derived_from_request_stream: false,
    scope: {
      consequence_path: targetBinding.consequence_path,
      action_class: actionClass,
      target_kind: targetBinding.target_kind,
      target_scope: targetBinding.target_scope,
      target_instance_scope: targetBinding.target_instance_scope,
      target_handle: targetBinding.target_handle,
      installed_profile_preflight_artifact_body_sha256:
        targetBinding.source_preflight_body_sha256,
      launcher_target_binding_sha256: sha256hex(canonicalize(targetBinding)),
      record_update_sha256: sha256hex(canonicalize(authorizedRecordUpdate)),
      target_effect_sha256: sha256hex(canonicalize(targetEffect)),
      profile_id: targetBinding.source_profile_id,
      runtime_profile_id: profileId,
      profile_sha256: targetBinding.source_profile_sha256,
      recognition_contract_sha256:
        targetBinding.source_recognition_contract_sha256,
      target_contract_sha256: targetBinding.source_target_contract_sha256,
      receipt_audit_event_id: recognitionRule?.required_audit_event_id,
      source_precondition_artifact_body_sha256:
        protectedRecordsFixtureAuthoritySourcePreconditionBodySha256V2(
          sourcePrecondition,
        ),
      ...exactReceiptRecognitionSemantics(),
    },
  };
}

export function createProtectedRecordsRuntimeAuthorityContextV2({
  actionClass,
  authorizedRecordUpdate,
  authorityGrantAppointment,
  authorityGrantConfirmation,
  authorityGrantContract,
  authorityGrantExpectedContractSha256,
  authorityGrantIssuanceDecision,
  authorityGrantStatus,
  profileId,
  recognitionRule,
  sourcePrecondition,
  targetBinding,
} = {}) {
  assertProtectedRecordsFixtureAuthorityGrantContractV2(authorityGrantContract, {
    expectedContractSha256: authorityGrantExpectedContractSha256,
  });
  if (
    protectedRecordsFixtureAuthorityGrantContractSha256V2(
      authorityGrantContract,
    ) !== authorityGrantExpectedContractSha256
  ) {
    throw new Error('Protected records runtime v2 exact grant identity drifted');
  }
  assertProtectedRecordsFixtureAuthoritySourcePreconditionV2(sourcePrecondition);
  assertCanonicalEqual(
    'Protected records runtime v2 source implementation binding',
    authorityGrantContract.implementation_binding,
    protectedRecordsFixtureAuthorityImplementationBindingFromSourcePreconditionV2(
      sourcePrecondition,
    ),
  );
  assertProtectedRecordsFixtureAuthorityAppointmentV2(authorityGrantAppointment, {
    contract: authorityGrantContract,
    expectedContractSha256: authorityGrantExpectedContractSha256,
  });
  assertProtectedRecordsFixtureAuthorityExactConfirmationV2(
    authorityGrantConfirmation,
    {
      contract: authorityGrantContract,
      expectedContractSha256: authorityGrantExpectedContractSha256,
      appointment: authorityGrantAppointment,
    },
  );
  assertProtectedRecordsFixtureAuthorityStatusV2(authorityGrantStatus, {
    contract: authorityGrantContract,
    expectedContractSha256: authorityGrantExpectedContractSha256,
    appointment: authorityGrantAppointment,
    confirmation: authorityGrantConfirmation,
  });
  if (
    authorityGrantStatus.status !== 'active' ||
    authorityGrantStatus.fresh_effect_allowed !== true ||
    authorityGrantStatus.recorded_effect_uses !== 0
  ) {
    throw new Error(
      'Protected records runtime v2 requires a fresh source-authorized active status',
    );
  }
  assertProtectedRecordsFixtureAuthorityDecisionV2(
    authorityGrantIssuanceDecision,
  );

  const scopeEvidence = createProtectedRecordsRuntimeScopeEvidenceV2({
    actionClass,
    authorizedRecordUpdate,
    profileId,
    recognitionRule,
    sourcePrecondition,
    targetBinding,
  });
  assertProtectedRecordsFixtureAuthorityScopeEvidenceV2(
    scopeEvidence,
    authorityGrantContract,
  );
  const targetEffect = {
    target_handle: targetBinding.target_handle,
    record_update: clone(authorizedRecordUpdate),
  };
  const authorizedEffectDetail = protectedRecordsAuthorizedEffectDetailV2({
    contract: authorityGrantContract,
    expectedContractSha256: authorityGrantExpectedContractSha256,
    targetEffect,
  });
  assertProtectedRecordsAuthorizedEffectDetailV2(authorizedEffectDetail, {
    contract: authorityGrantContract,
    expectedContractSha256: authorityGrantExpectedContractSha256,
  });

  const appointmentSha256 =
    protectedRecordsFixtureAuthorityAppointmentSha256V2(
      authorityGrantAppointment,
      {
        contract: authorityGrantContract,
        expectedContractSha256: authorityGrantExpectedContractSha256,
      },
    );
  const confirmationSha256 =
    protectedRecordsFixtureAuthorityExactConfirmationSha256V2(
      authorityGrantConfirmation,
      {
        contract: authorityGrantContract,
        expectedContractSha256: authorityGrantExpectedContractSha256,
        appointment: authorityGrantAppointment,
      },
    );
  const authorityStatusAtEffectSha256 =
    protectedRecordsFixtureAuthorityStatusSha256V2(authorityGrantStatus, {
      contract: authorityGrantContract,
      expectedContractSha256: authorityGrantExpectedContractSha256,
      appointment: authorityGrantAppointment,
      confirmation: authorityGrantConfirmation,
    });
  const issuerBindingSha256 =
    protectedRecordsFixtureAuthorityIssuerBindingSha256V2(
      authorityGrantAppointment,
      {
        contract: authorityGrantContract,
        expectedContractSha256: authorityGrantExpectedContractSha256,
      },
    );
  const authorizedEffectDetailSha256 =
    protectedRecordsAuthorizedEffectDetailSha256V2(authorizedEffectDetail, {
      contract: authorityGrantContract,
      expectedContractSha256: authorityGrantExpectedContractSha256,
    });
  const issuanceDecisionSha256 =
    protectedRecordsFixtureAuthorityDecisionSha256V2(
      authorityGrantIssuanceDecision,
    );
  const sourcePreconditionSha256 =
    protectedRecordsFixtureAuthoritySourcePreconditionBodySha256V2(
      sourcePrecondition,
    );

  const issuanceBinding = authorityGrantIssuanceDecision.binding;
  if (
    authorityGrantIssuanceDecision.phase !== 'issuance' ||
    authorityGrantIssuanceDecision.decision !== 'accept' ||
    issuanceBinding.authority_grant_contract_sha256 !==
      authorityGrantExpectedContractSha256 ||
    issuanceBinding.appointment_sha256 !== appointmentSha256 ||
    issuanceBinding.confirmation_sha256 !== confirmationSha256 ||
    issuanceBinding.authority_status_sha256 !== authorityStatusAtEffectSha256 ||
    issuanceBinding.issuer_binding_sha256 !== issuerBindingSha256 ||
    issuanceBinding.receipt_audit_event_id !==
      authorityGrantContract.scope.receipt_audit_event_id ||
    issuanceBinding.authorized_effect_detail_sha256 !==
      authorizedEffectDetailSha256 ||
    issuanceBinding.source_precondition_artifact_body_sha256 !==
      sourcePreconditionSha256 ||
    !SHA256_PATTERN.test(issuanceBinding.receipt_payload_sha256 || '') ||
    issuanceBinding.signed_receipt_sha256 !== null ||
    issuanceBinding.issuance_decision_sha256 !== null
  ) {
    throw new Error(
      'Protected records runtime v2 accepted pre-signing issuance decision is unbound',
    );
  }

  requireObject('Protected records runtime v2 recognition rule', recognitionRule);
  assertExactKeys('Protected records runtime v2 recognition rule', recognitionRule, [
    'accepted_domains',
    'accepted_issuers',
    'accepted_outcomes',
    'accepted_policy_versions',
    'accepted_tools',
    'deployment_scope',
    'max_age_seconds',
    'required_audit_event_id',
    'required_detail_hash',
  ]);
  const issuers = recognitionRule.accepted_issuers;
  if (!Array.isArray(issuers) || issuers.length !== 1) {
    throw new Error('Protected records runtime v2 must recognize exactly one issuer');
  }
  const issuer = requireObject(
    'Protected records runtime v2 recognized issuer',
    issuers[0],
  );
  assertExactKeys('Protected records runtime v2 recognized issuer', issuer, [
    'kid',
    'public_key_pem',
    'status',
  ]);
  if (
    issuer.kid !== authorityGrantAppointment.issuer_kid ||
    issuer.status !== 'active' ||
    typeof issuer.public_key_pem !== 'string' ||
    issuer.public_key_pem.length < 1 ||
    sha256hex(issuer.public_key_pem) !== authorityGrantAppointment.public_key_sha256
  ) {
    throw new Error(
      'Protected records runtime v2 recognized issuer does not match the exact appointment',
    );
  }
  const recognitionSemantics = exactReceiptRecognitionSemantics();
  for (const [label, actual, expected] of [
    ['accepted policy versions', recognitionRule.accepted_policy_versions, [recognitionSemantics.policy_version]],
    ['accepted domains', recognitionRule.accepted_domains, [recognitionSemantics.receipt_domain]],
    ['accepted tools', recognitionRule.accepted_tools, [actionClass]],
    ['accepted outcomes', recognitionRule.accepted_outcomes, [recognitionSemantics.receipt_outcome]],
  ]) {
    assertCanonicalEqual(`Protected records runtime v2 ${label}`, actual, expected);
  }
  if (
    recognitionRule.deployment_scope !==
      'protected-records-disposable-runtime-profile' ||
    recognitionRule.required_detail_hash !== authorizedEffectDetailSha256 ||
    recognitionRule.required_audit_event_id !==
      authorityGrantContract.scope.receipt_audit_event_id ||
    !Number.isInteger(recognitionRule.max_age_seconds) ||
    recognitionRule.max_age_seconds < 1 ||
    typeof recognitionRule.required_audit_event_id !== 'string' ||
    recognitionRule.required_audit_event_id.length < 1
  ) {
    throw new Error('Protected records runtime v2 recognition rule drifted');
  }

  return Object.freeze({
    appointment: clone(authorityGrantAppointment),
    appointmentSha256,
    authorityGrantContract: clone(authorityGrantContract),
    authorityGrantContractSha256: authorityGrantExpectedContractSha256,
    authorityGrantStatus: clone(authorityGrantStatus),
    authorityStatusAtEffectSha256,
    authorizedEffectDetail,
    authorizedEffectDetailSha256,
    confirmation: clone(authorityGrantConfirmation),
    confirmationSha256,
    issuanceDecision: clone(authorityGrantIssuanceDecision),
    issuanceDecisionSha256,
    issuerBindingSha256,
    recognitionRule: clone(recognitionRule),
    scopeEvidence,
    sourcePrecondition: clone(sourcePrecondition),
    sourcePreconditionSha256,
    targetEffect,
    targetEffectSha256: sha256hex(canonicalize(targetEffect)),
  });
}

export function createProtectedRecordsRuntimeEffectReceiptEvidenceV2({
  context,
  envelope,
  payload,
  publicKeyPem,
  verifiedSignedPayloadSha256,
} = {}) {
  requireObject('Protected records runtime v2 authority context', context);
  requireObject('Protected records runtime v2 signed receipt envelope', envelope);
  requireObject('Protected records runtime v2 verified receipt payload', payload);
  assertSha256(
    'Protected records runtime v2 verified signed payload SHA-256',
    verifiedSignedPayloadSha256,
  );
  if (
    envelope.kid !== context.appointment.issuer_kid ||
    sha256hex(publicKeyPem) !== context.appointment.public_key_sha256
  ) {
    throw new Error('Protected records runtime v2 verified issuer binding drifted');
  }
  const issuedAtEpoch = Math.floor(new Date(payload.ts).getTime() / 1000);
  if (!Number.isInteger(issuedAtEpoch)) {
    throw new Error('Protected records runtime v2 receipt timestamp is invalid');
  }
  const delegationChainPresent = Object.prototype.hasOwnProperty.call(
    payload,
    'delegation_chain',
  );
  const delegationChain = delegationChainPresent
    ? clone(payload.delegation_chain)
    : null;
  return {
    evidence_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_RECEIPT_EVIDENCE_TYPE_V2,
    receipt_evidence_phase: 'effect',
    source: 'independent-signed-receipt-verification',
    authority_grant_contract_sha256: context.authorityGrantContractSha256,
    authorized_effect_detail_sha256: context.authorizedEffectDetailSha256,
    receipt_payload_sha256: verifiedSignedPayloadSha256,
    signed_receipt_sha256: sha256hex(canonicalize(envelope)),
    signature_verified: true,
    delegation_chain_present: delegationChainPresent,
    delegation_chain: delegationChain,
    issuer_kid: envelope.kid,
    public_key_sha256: sha256hex(publicKeyPem),
    issued_at_epoch: issuedAtEpoch,
    policy_version: payload.policy_version,
    receipt_action_class: payload.tool,
    receipt_audit_event_id: payload.audit_event_id,
    receipt_version: envelope.v,
    receipt_type: envelope.type,
    receipt_domain: payload.domain,
    receipt_rule: payload.rule,
    receipt_authorizer: payload.authorizer,
    receipt_outcome: payload.outcome,
  };
}

export function evaluateProtectedRecordsRuntimeAuthorityEffectV2({
  context,
  evaluationEpoch,
  grantPreviouslyConsumed,
  receiptEvidence,
  authorityStatusAtEffect = context?.authorityGrantStatus,
} = {}) {
  requireObject('Protected records runtime v2 authority context', context);
  const effectDecision = evaluateProtectedRecordsFixtureAuthorityEffectV2({
    contract: context.authorityGrantContract,
    expectedContractSha256: context.authorityGrantContractSha256,
    sourcePrecondition: context.sourcePrecondition,
    appointment: context.appointment,
    confirmation: context.confirmation,
    authorityStatus: authorityStatusAtEffect,
    scopeEvidence: context.scopeEvidence,
    receiptEvidence,
    authorizedEffectDetail: context.authorizedEffectDetail,
    evaluationEpoch,
    grantPreviouslyConsumed,
    issuanceDecision: context.issuanceDecision,
  });
  assertProtectedRecordsFixtureAuthorityDecisionV2(effectDecision);
  const effectDecisionSha256 =
    protectedRecordsFixtureAuthorityDecisionSha256V2(effectDecision);
  if (effectDecision.decision !== 'accept') {
    return {
      accepted: false,
      effectGateBinding: null,
      effectGateBindingSha256: null,
      effectDecision,
      effectDecisionSha256,
    };
  }
  if (!Number.isSafeInteger(evaluationEpoch) || evaluationEpoch < 0) {
    throw new Error(
      'Protected records runtime v2 accepted effect requires a valid runtime evaluation epoch',
    );
  }
  const authorityStatusAtEffectSha256 =
    protectedRecordsFixtureAuthorityStatusSha256V2(
      authorityStatusAtEffect,
      {
        contract: context.authorityGrantContract,
        expectedContractSha256: context.authorityGrantContractSha256,
        appointment: context.appointment,
        confirmation: context.confirmation,
      },
    );
  const effectGateBinding = {
    binding_type: PROTECTED_RECORDS_RUNTIME_EFFECT_GATE_BINDING_TYPE_V2,
    authority_effect_evaluation_epoch: evaluationEpoch,
    caller_supplied_consequence_time_accepted: false,
    consequence_clock_source:
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_CLOCK_SOURCE_V2,
    minimum_effect_margin_seconds:
      PROTECTED_RECORDS_RUNTIME_MINIMUM_EFFECT_MARGIN_SECONDS_V2,
    grant_window_remaining_seconds:
      context.authorityGrantContract.time_policy.expires_at_epoch -
      evaluationEpoch,
    receipt_recognition_remaining_seconds:
      receiptEvidence.issued_at_epoch + context.recognitionRule.max_age_seconds -
      evaluationEpoch,
    authority_grant_contract_sha256: context.authorityGrantContractSha256,
    source_precondition_artifact_body_sha256:
      context.sourcePreconditionSha256,
    appointment_sha256: context.appointmentSha256,
    confirmation_sha256: context.confirmationSha256,
    authority_status_at_effect_sha256:
      authorityStatusAtEffectSha256,
    issuer_binding_sha256: context.issuerBindingSha256,
    authorized_effect_detail_sha256:
      context.authorizedEffectDetailSha256,
    issuance_decision_sha256: context.issuanceDecisionSha256,
    effect_decision_sha256: effectDecisionSha256,
    receipt_payload_sha256: receiptEvidence.receipt_payload_sha256,
    signed_receipt_sha256: receiptEvidence.signed_receipt_sha256,
    installed_profile_preflight_artifact_body_sha256:
      context.authorityGrantContract.scope
        .installed_profile_preflight_artifact_body_sha256,
    launcher_target_binding_sha256:
      context.authorityGrantContract.scope.launcher_target_binding_sha256,
    profile_sha256: context.authorityGrantContract.scope.profile_sha256,
    recognition_contract_sha256:
      context.authorityGrantContract.scope.recognition_contract_sha256,
    target_contract_sha256:
      context.authorityGrantContract.scope.target_contract_sha256,
    target_effect_sha256: context.targetEffectSha256,
  };
  return {
    accepted: true,
    effectGateBinding,
    effectGateBindingSha256:
      protectedRecordsRuntimeEffectGateBindingSha256V2(effectGateBinding),
    effectDecision,
    effectDecisionSha256,
  };
}

export function assertProtectedRecordsRuntimeEffectGateBindingV2(binding) {
  assertExactKeys('Protected records runtime v2 effect-gate binding', binding, [
    'appointment_sha256',
    'authority_effect_evaluation_epoch',
    'authority_grant_contract_sha256',
    'authority_status_at_effect_sha256',
    'authorized_effect_detail_sha256',
    'binding_type',
    'caller_supplied_consequence_time_accepted',
    'confirmation_sha256',
    'consequence_clock_source',
    'effect_decision_sha256',
    'installed_profile_preflight_artifact_body_sha256',
    'issuance_decision_sha256',
    'issuer_binding_sha256',
    'grant_window_remaining_seconds',
    'launcher_target_binding_sha256',
    'profile_sha256',
    'minimum_effect_margin_seconds',
    'receipt_payload_sha256',
    'receipt_recognition_remaining_seconds',
    'recognition_contract_sha256',
    'signed_receipt_sha256',
    'source_precondition_artifact_body_sha256',
    'target_contract_sha256',
    'target_effect_sha256',
  ]);
  if (binding.binding_type !== PROTECTED_RECORDS_RUNTIME_EFFECT_GATE_BINDING_TYPE_V2) {
    throw new Error('Protected records runtime v2 effect-gate binding type drifted');
  }
  if (
    !Number.isSafeInteger(binding.authority_effect_evaluation_epoch) ||
    binding.authority_effect_evaluation_epoch < 0 ||
    binding.caller_supplied_consequence_time_accepted !== false ||
    binding.consequence_clock_source !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_CLOCK_SOURCE_V2 ||
    binding.minimum_effect_margin_seconds !==
      PROTECTED_RECORDS_RUNTIME_MINIMUM_EFFECT_MARGIN_SECONDS_V2 ||
    !Number.isSafeInteger(binding.grant_window_remaining_seconds) ||
    !Number.isSafeInteger(binding.receipt_recognition_remaining_seconds) ||
    binding.grant_window_remaining_seconds <=
      binding.minimum_effect_margin_seconds ||
    binding.receipt_recognition_remaining_seconds <=
      binding.minimum_effect_margin_seconds
  ) {
    throw new Error(
      'Protected records runtime v2 effect-gate clock boundary drifted',
    );
  }
  for (const [field, value] of Object.entries(binding)) {
    if (
      field !== 'binding_type' &&
      field !== 'authority_effect_evaluation_epoch' &&
      field !== 'caller_supplied_consequence_time_accepted' &&
      field !== 'consequence_clock_source' &&
      field !== 'minimum_effect_margin_seconds' &&
      field !== 'grant_window_remaining_seconds' &&
      field !== 'receipt_recognition_remaining_seconds'
    ) {
      assertSha256(`Protected records runtime v2 effect-gate ${field}`, value);
    }
  }
  return true;
}

export function protectedRecordsRuntimeEffectGateBindingSha256V2(binding) {
  assertProtectedRecordsRuntimeEffectGateBindingV2(binding);
  return sha256hex(canonicalize(binding));
}

export function protectedRecordsRuntimeAuthorityDecisionV2(decision) {
  assertProtectedRecordsFixtureAuthorityDecisionV2(decision);
  return {
    result_type: decision.decision_type,
    phase: decision.phase,
    decision: decision.decision,
    reason_code: decision.reason_code,
    reasons: clone(decision.reasons),
    evidence: {
      ...clone(decision.evidence),
      refused_before_authority_grant_consumption:
        decision.decision === 'refuse',
      refused_before_runtime_state_mutation: decision.decision === 'refuse',
      local_disposable_fixture_only: true,
      rightful_issuance_proven: false,
      portable_rightful_issuance_proven: false,
      production_rightful_issuance_proven: false,
      consequence_lifecycle_closed: false,
    },
  };
}

export function createProtectedRecordsRuntimeExecutionTraceV2({
  authorityStatusAtEffectSha256,
  effectGateBindingSha256,
  effectDecisionSha256,
  signedReceiptSha256,
} = {}) {
  for (const [label, value] of [
    ['authority status at effect', authorityStatusAtEffectSha256],
    ['effect-gate binding', effectGateBindingSha256],
    ['effect decision', effectDecisionSha256],
    ['signed receipt', signedReceiptSha256],
  ]) {
    assertSha256(`Protected records runtime v2 ${label} SHA-256`, value);
  }
  return {
    trace_type: PROTECTED_RECORDS_RUNTIME_EXECUTION_TRACE_TYPE_V2,
    authority_status_at_effect_sha256: authorityStatusAtEffectSha256,
    authority_effect_gate_binding_sha256: effectGateBindingSha256,
    effect_decision_sha256: effectDecisionSha256,
    signed_receipt_sha256: signedReceiptSha256,
    signed_payload_replay_check_sequence: 1,
    authority_status_refresh_sequence: 2,
    effect_gate_sequence: 3,
    grant_store_commit_sequence: 4,
    state_append_sequence: 5,
    helper_state_promotion_sequence: 6,
    signed_payload_replay_check_preceded_effect_gate: true,
    authority_status_refresh_preceded_effect_gate: true,
    effect_gate_preceded_grant_store_commit: true,
    grant_store_commit_preceded_state_append: true,
    state_append_preceded_helper_state_promotion: true,
    one_launcher_store_lock_held_across_transition: true,
  };
}

export function assertProtectedRecordsRuntimeExecutionTraceV2(trace) {
  assertExactKeys('Protected records runtime v2 execution trace', trace, [
    'authority_effect_gate_binding_sha256',
    'authority_status_at_effect_sha256',
    'authority_status_refresh_preceded_effect_gate',
    'authority_status_refresh_sequence',
    'effect_decision_sha256',
    'effect_gate_preceded_grant_store_commit',
    'effect_gate_sequence',
    'grant_store_commit_preceded_state_append',
    'grant_store_commit_sequence',
    'helper_state_promotion_sequence',
    'one_launcher_store_lock_held_across_transition',
    'signed_payload_replay_check_preceded_effect_gate',
    'signed_payload_replay_check_sequence',
    'signed_receipt_sha256',
    'state_append_preceded_helper_state_promotion',
    'state_append_sequence',
    'trace_type',
  ]);
  if (
    trace.trace_type !== PROTECTED_RECORDS_RUNTIME_EXECUTION_TRACE_TYPE_V2 ||
    trace.signed_payload_replay_check_sequence !== 1 ||
    trace.authority_status_refresh_sequence !== 2 ||
    trace.effect_gate_sequence !== 3 ||
    trace.grant_store_commit_sequence !== 4 ||
    trace.state_append_sequence !== 5 ||
    trace.helper_state_promotion_sequence !== 6 ||
    trace.signed_payload_replay_check_preceded_effect_gate !== true ||
    trace.authority_status_refresh_preceded_effect_gate !== true ||
    trace.effect_gate_preceded_grant_store_commit !== true ||
    trace.grant_store_commit_preceded_state_append !== true ||
    trace.state_append_preceded_helper_state_promotion !== true ||
    trace.one_launcher_store_lock_held_across_transition !== true
  ) {
    throw new Error('Protected records runtime v2 execution trace ordering drifted');
  }
  for (const field of [
    'authority_effect_gate_binding_sha256',
    'authority_status_at_effect_sha256',
    'effect_decision_sha256',
    'signed_receipt_sha256',
  ]) {
    assertSha256(`Protected records runtime v2 execution trace ${field}`, trace[field]);
  }
  return true;
}

export function protectedRecordsRuntimeExecutionTraceSha256V2(trace) {
  assertProtectedRecordsRuntimeExecutionTraceV2(trace);
  return sha256hex(canonicalize(trace));
}

export function assertProtectedRecordsRuntimeTransitionBindingV2(binding) {
  assertExactKeys('Protected records runtime v2 transition binding', binding, [
    'authority_grant_consumption_count_after',
    'authority_grant_consumption_count_before',
    'authority_grant_contract_sha256',
    'authority_effect_gate_binding_sha256',
    'authority_grant_effect_decision_sha256',
    'authority_grant_issuance_decision_sha256',
    'authority_grant_status_at_effect_sha256',
    'authorized_effect_detail_sha256',
    'binding_type',
    'consumed_grant_store_sha256_after',
    'consumed_grant_store_sha256_before',
    'execution_trace_sha256',
    'runtime_state_sha256_after',
    'runtime_state_sha256_before',
    'signed_receipt_sha256',
    'state_effect_binding_sha256',
    'state_entry_count_after',
    'state_entry_count_before',
    'target_effect_sha256',
    'verified_signed_payload_sha256',
  ]);
  if (
    binding.binding_type !==
      PROTECTED_RECORDS_RUNTIME_TRANSITION_BINDING_TYPE_V2 ||
    !Number.isInteger(binding.authority_grant_consumption_count_before) ||
    !Number.isInteger(binding.authority_grant_consumption_count_after) ||
    !Number.isInteger(binding.state_entry_count_before) ||
    !Number.isInteger(binding.state_entry_count_after) ||
    binding.authority_grant_consumption_count_before < 0 ||
    binding.state_entry_count_before < 0 ||
    binding.authority_grant_consumption_count_after -
      binding.authority_grant_consumption_count_before !== 1 ||
    binding.state_entry_count_after - binding.state_entry_count_before !== 1
  ) {
    throw new Error('Protected records runtime v2 transition count ordering drifted');
  }
  for (const [field, value] of Object.entries(binding)) {
    if (
      field !== 'binding_type' &&
      !field.endsWith('_count_before') &&
      !field.endsWith('_count_after')
    ) {
      assertSha256(`Protected records runtime v2 transition ${field}`, value);
    }
  }
  return true;
}

export function protectedRecordsRuntimeTransitionBindingSha256V2(binding) {
  assertProtectedRecordsRuntimeTransitionBindingV2(binding);
  return sha256hex(canonicalize(binding));
}
