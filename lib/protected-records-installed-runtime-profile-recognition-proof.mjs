import { generateKeyPairSync } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
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
  PROTECTED_RECORDS_CONSEQUENCE_PATH,
  PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH,
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  PROTECTED_RECORDS_TARGET_HANDLE,
  PROTECTED_RECORDS_TARGET_KIND,
  PROTECTED_RECORDS_TARGET_SCOPE,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
  assertProtectedRecordsRuntimeServiceResult,
  createProtectedRecordsRuntimeAuthorityReceiptEvidence,
  createProtectedRecordsRuntimeFixtureAuthorityGrantContract,
  createProtectedRecordsRuntimeLauncherScopeEvidence,
  createProtectedRecordsRuntimeService,
  createProtectedRecordsRuntimeTargetBinding,
  protectedRecordsTargetEffect,
} from './protected-records-runtime-profile.mjs';
import {
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_DOMAIN_ID,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_EXPIRES_AT_EPOCH,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_SUMMARY_TYPE,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_POWERS,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_VALID_FROM_EPOCH,
  PROTECTED_RECORDS_FIXTURE_AUTHORIZED_RECORD_UPDATE,
  PROTECTED_RECORDS_FIXTURE_RIGHTFUL_ISSUANCE_SCOPE,
  assertProtectedRecordsFixtureAuthorityGrantDecision,
  buildProtectedRecordsFixtureAuthorityGrantSummary,
  createProtectedRecordsFixtureAuthorityGrantAppointment,
  evaluateProtectedRecordsFixtureAuthorityGrantEffect,
  evaluateProtectedRecordsFixtureAuthorityGrantIssuance,
  protectedRecordsAuthorizedEffectDetail,
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

export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_TYPE =
  'zlar-protected-records-installed-runtime-profile-recognition-proof-v1';
export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_TYPE =
  'zlar-protected-records-installed-runtime-profile-recognition-proof-artifact-v1';
export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_CANONICALIZATION =
  'zlar-canonical-json-v1';
export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_VERIFICATION_TYPE =
  'zlar-protected-records-installed-runtime-profile-recognition-proof-artifact-verification-v1';

export const INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_SAFE_CLAIM_CEILING =
  'ZLAR can consume a verified read-only installed runtime-profile preflight artifact, preserve its selected 18-case recognition-refusal taxonomy, and run one local hermetic fixture records.write crossing where launcher-derived scope creates an exact one-use authority contract and issuer appointment, an issuance decision accepts the unsigned envelope before signing, downstream recognition accepts the signed payload, and the effect gate accepts before grant consumption and process-private mutation.';

export const INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_NON_CLAIMS = Object.freeze([
  'This proof consumes a read-only installed runtime-profile preflight artifact; it does not install, activate, or persist a runtime profile.',
  'This proof uses one local hermetic downstream-shaped service object and disposable launcher-owned consumed-grant store, anchor, and witness paths; it does not start a live runtime service or inspect a live records system.',
  'The positive result evidences one local fixture rightful-issuance path only; it does not prove generic, portable, production, live, or current-machine rightful issuance.',
  'Recognition-refusal probes may contain raw-signed unrecognized envelopes only to exercise the fixed recognition taxonomy; those probes do not carry accepted issuance decisions and are not rightful-issuance evidence.',
  'This proof does not prove exactly-once effects; a crash or state-append failure after one-use grant consumption and before state mutation can burn the grant.',
  'This proof does not prove an atomic all-or-nothing commit across the consumed-grant store, local anchor, and local witness; a metadata write failure after grant-store commit can burn the grant.',
  'This proof does not detect rollback, deletion, or replacement when the consumed-grant store, local anchor, and local witness move together without stronger custody or an external witness.',
  'This proof does not close post-validation filesystem path replacement or symlink time-of-check/time-of-use side doors.',
  'This proof does not close host process, memory, debugger, operator filesystem, hook-configuration, user-configuration, machine-configuration, or unrouted records side doors.',
  'This proof does not prove live approval-channel health, Telegram delivery, current-machine governance, live MCP coverage, production downstream recognition, production authority, external attestation, enterprise readiness, sovereign recognition, all-surface governance, or consequence-lifecycle closure.',
]);

const ORDERED_TRANSITION_BINDING_TYPE =
  'protected-records-runtime-ordered-single-lock-transition-binding-v1';
const MUTATION_ROUTE =
  'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation';
const AUDIT_EVENT_ID = 'protected-records-installed-profile-001';
const STRUCTURAL_VERIFICATION_SCOPE = 'structural-self-integrity-only';
const PINNED_VERIFICATION_SCOPE =
  'expected-artifact-and-source-preflight-identity-bound-local-fixture-projection';
const STRUCTURAL_CLAIM_BOUNDARY =
  'structural self-integrity only; embedded fixture, source-preflight, and signed-payload assertions are not identity evidence without caller-supplied expected artifact and source-preflight SHA-256 values';
const PINNED_CLAIM_BOUNDARY =
  'caller-supplied expected artifact and source-preflight SHA-256 identities matched; historical boarding and refusal facts are projected from that exact artifact, while fixture-rightful projection additionally requires a current source-authorized grant status with valid repeated-use provenance; no independent detached signature re-verification or generic, portable, live, production, current-machine, or lifecycle-closure claim';

const EXPECTED_REFUSAL_REASONS = Object.freeze({
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

function keyMaterial(root, label) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  const publicPath = join(root, `${label}.pub`);
  writeFileSync(publicPath, publicPem, { mode: 0o600 });
  return { privatePem, publicPem, kid: pubkeyFingerprint(publicPath) };
}

function baseRecordUpdate() {
  return {
    ...PROTECTED_RECORDS_FIXTURE_AUTHORIZED_RECORD_UPDATE,
  };
}

function eventFixture({
  detail,
  issuedAtEpoch,
  auditEventId = AUDIT_EVENT_ID,
  action = 'records.write',
  domain = 'records',
  outcome = 'allow',
  policyVersion = 'recognition-policy-v1',
}) {
  return {
    id: auditEventId,
    ts: new Date(issuedAtEpoch * 1000).toISOString(),
    action,
    domain,
    detail,
    outcome,
    rule: 'RRECORDS_ALLOW',
    authorizer: 'policy',
    policy_version: policyVersion,
    prev_hash: '0'.repeat(64),
  };
}

function recognitionRule({
  activeIssuer,
  requiredDetailHash = null,
  retiredIssuer = null,
  missingStatusIssuer = null,
}) {
  const issuers = [{
    kid: activeIssuer.kid,
    public_key_pem: activeIssuer.publicPem,
    status: 'active',
  }];
  if (retiredIssuer) {
    issuers.push({
      kid: retiredIssuer.kid,
      public_key_pem: retiredIssuer.publicPem,
      status: 'retired',
    });
  }
  if (missingStatusIssuer) {
    issuers.push({
      kid: missingStatusIssuer.kid,
      public_key_pem: missingStatusIssuer.publicPem,
    });
  }
  const rule = {
    deployment_scope: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    accepted_issuers: issuers,
    accepted_policy_versions: ['recognition-policy-v1'],
    accepted_domains: ['records'],
    accepted_tools: ['records.write'],
    accepted_outcomes: ['allow', 'authorized'],
    max_age_seconds: 120,
    required_audit_event_id: AUDIT_EVENT_ID,
  };
  if (requiredDetailHash) rule.required_detail_hash = requiredDetailHash;
  return rule;
}

function issuePositiveCrossing({
  activeIssuer,
  retiredIssuer,
  missingStatusIssuer,
  nowEpoch,
  recordUpdate,
  targetBinding,
}) {
  const scopeRule = recognitionRule({ activeIssuer });
  const scopeEvidence = createProtectedRecordsRuntimeLauncherScopeEvidence({
    actionClass: 'records.write',
    authorizedRecordUpdate: recordUpdate,
    profileId: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    recognitionRuleSnapshot: scopeRule,
    targetBinding,
  });
  const contract = createProtectedRecordsRuntimeFixtureAuthorityGrantContract({
    scopeEvidence,
    validFromEpoch: PROTECTED_RECORDS_FIXTURE_AUTHORITY_VALID_FROM_EPOCH,
    expiresAtEpoch: PROTECTED_RECORDS_FIXTURE_AUTHORITY_EXPIRES_AT_EPOCH,
  });
  const appointment = createProtectedRecordsFixtureAuthorityGrantAppointment({
    contract,
    granteeIssuerKid: activeIssuer.kid,
    granteePublicKeySha256: sha256hex(activeIssuer.publicPem),
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
    detail: authorizedEffectDetail,
    issuedAtEpoch: nowEpoch - 5,
  }));
  const unsignedPayload = decodePayloadV1(unsignedReceipt);
  const issuanceReceiptEvidence = createProtectedRecordsRuntimeAuthorityReceiptEvidence({
    envelope: unsignedReceipt,
    issuerKid: activeIssuer.kid,
    issuerStatus: null,
    payload: unsignedPayload,
    publicKeySha256: sha256hex(activeIssuer.publicPem),
    source: 'unsigned-receipt-payload-before-signing',
    signatureVerified: false,
    downstreamRecognitionAccepted: false,
    verifiedSignedPayloadSha256: null,
  });
  const issuanceDecision = evaluateProtectedRecordsFixtureAuthorityGrantIssuance({
    contract,
    appointment,
    scopeEvidence,
    receiptEvidence: issuanceReceiptEvidence,
    authorizedEffectDetail,
    evaluationEpoch: nowEpoch - 5,
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
    throw new Error('Installed recognition proof could not verify its just-signed fixture receipt');
  }
  return {
    appointment,
    authorizedEffectDetail,
    contract,
    issuanceDecision,
    receipt,
    recognitionRule: recognitionRule({
      activeIssuer,
      retiredIssuer,
      missingStatusIssuer,
      requiredDetailHash: verified.payload.detail_hash,
    }),
    scopeEvidence,
    targetEffect,
    verified,
  };
}

function rawSignedReceipt({ crossing, key, nowEpoch, overrides = {} }) {
  const envelope = createReceiptV1FromEvent(eventFixture({
    detail: Object.prototype.hasOwnProperty.call(overrides, 'detail')
      ? overrides.detail
      : crossing.authorizedEffectDetail,
    issuedAtEpoch: Object.prototype.hasOwnProperty.call(overrides, 'issuedAtEpoch')
      ? overrides.issuedAtEpoch
      : nowEpoch - 5,
    auditEventId: overrides.auditEventId || AUDIT_EVENT_ID,
    action: overrides.action || 'records.write',
    domain: overrides.domain || 'records',
    outcome: overrides.outcome || 'allow',
    policyVersion: overrides.policyVersion || 'recognition-policy-v1',
  }));
  return signReceiptV1(envelope, key.privatePem, key.kid);
}

function caseSummary(caseId, result) {
  return {
    case_id: caseId,
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
    direct_api_attempted: result.direct_api_attempted,
  };
}

function publicAuthoritySummary(crossing, acceptedResult, nowEpoch) {
  const receiptEvidence = createProtectedRecordsRuntimeAuthorityReceiptEvidence({
    envelope: crossing.receipt,
    issuerKid: crossing.receipt.kid,
    issuerStatus: 'active',
    payload: crossing.verified.payload,
    publicKeySha256: crossing.appointment.grantee_public_key_sha256,
    source: 'cryptographically-verified-downstream-recognition',
    signatureVerified: true,
    downstreamRecognitionAccepted: true,
    verifiedSignedPayloadSha256: crossing.verified.verified_signed_payload_sha256,
  });
  const effectDecision = evaluateProtectedRecordsFixtureAuthorityGrantEffect({
    contract: crossing.contract,
    appointment: crossing.appointment,
    scopeEvidence: crossing.scopeEvidence,
    receiptEvidence,
    authorizedEffectDetail: crossing.authorizedEffectDetail,
    evaluationEpoch: nowEpoch,
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
    throw new Error('Installed recognition proof effect decision did not bind the accepted transition');
  }
  const summary = buildProtectedRecordsFixtureAuthorityGrantSummary({
    contract: crossing.contract,
    issuanceDecision: crossing.issuanceDecision,
    effectDecision,
    executionTrace: {
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
    },
  });
  return summary;
}

function refusalTaxonomySha256(cases) {
  return sha256hex(canonicalize({
    required_refusal_cases: REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
    observed_refusal_cases: cases.map((item) => ({
      case_id: item.case_id,
      reason_code: item.reason_code,
      refused_before_mutation:
        item.service_write_accepted === false && item.state_entry_count_delta === 0,
    })),
  }));
}

function assertPreflightVerificationBoundary(verification) {
  if (
    verification.verified !== true ||
    verification.read_only !== true ||
    verification.profile_selected_from_install_root !== true ||
    verification.selected_by_explicit_id_and_sha !== true ||
    verification.selects_latest_profile !== false ||
    verification.recognition_contract_preserved !== true ||
    verification.recognition_boundary !== 'service-configured-recognition-rule' ||
    verification.mutation_authoritative_route !== MUTATION_ROUTE ||
    verification.request_stream_authority_material_accepted !== false ||
    verification.recognition_rule_supplied_by_agent !== false ||
    verification.target_contract_preserved !== true ||
    verification.authority_grant_requirement_preserved !== true ||
    verification.launcher_owned_local_fixture_authority_grant_overlay !== true ||
    verification.source_profile_authority_grant_present !== false ||
    verification.exact_runtime_authority_grant_contract_deferred !== true ||
    verification.target_handle !== PROTECTED_RECORDS_TARGET_HANDLE ||
    verification.profile_wide_target_authority_proven !== false ||
    verification.rightful_issuance_proven !== false ||
    verification.consequence_lifecycle_closed !== false ||
    verification.required_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length ||
    verification.runtime_profile_installation_performed !== false ||
    verification.runtime_profile_activation_performed !== false ||
    verification.runtime_config_written !== false ||
    verification.runtime_service_started !== false ||
    verification.live_records_system_checked !== false ||
    verification.current_machine_governance_proven !== false
  ) {
    throw new Error('Installed recognition proof source preflight boundary drifted');
  }
  return true;
}

export function runProtectedRecordsInstalledRuntimeProfileRecognitionProof(
  artifact,
  { nowEpoch = PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH } = {}
) {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
    'Installed runtime-profile recognition proof generation',
  );
  if (!Number.isInteger(nowEpoch)) throw new Error('Installed recognition proof nowEpoch must be an integer');
  if (nowEpoch !== PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH) {
    throw new Error('Installed recognition proof nowEpoch must equal the fixed fixture evaluation epoch');
  }
  const verification = verifyProtectedRecordsInstalledRuntimeProfilePreflightArtifact(artifact);
  assertPreflightVerificationBoundary(verification);
  const preflight = artifact.payload.preflight;
  if (
    verification.recognition_contract_sha256 !==
      protectedRecordsInstalledRuntimeProfileRecognitionContractSha256(preflight.recognition_contract) ||
    verification.target_contract_sha256 !==
      protectedRecordsInstalledRuntimeProfileTargetContractSha256(preflight.target_contract)
  ) {
    throw new Error('Installed recognition proof source contract digest drifted');
  }
  assertExactArray(
    'Installed recognition refusal taxonomy',
    preflight.recognition_contract.required_refusal_cases,
    REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES
  );

  let scratch = null;
  try {
    scratch = mkdtempSync(join(tmpdir(), 'zlar-installed-profile-recognition-authority-'));
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
    const crossing = issuePositiveCrossing({
      activeIssuer,
      retiredIssuer,
      missingStatusIssuer,
      nowEpoch,
      recordUpdate,
      targetBinding,
    });
    const service = createProtectedRecordsRuntimeService({
      profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      action_class: 'records.write',
      now_epoch: nowEpoch,
      consumed_grants_path: join(scratch, 'consumed-grants.json'),
      consumed_grant_store_anchor_path: join(scratch, 'consumed-grants.anchor.json'),
      consumed_grant_store_witness_path: join(scratch, 'consumed-grants.witness.json'),
      authorized_record_update: recordUpdate,
      authority_grant_contract: crossing.contract,
      authority_grant_appointment: crossing.appointment,
      authority_grant_issuance_decision: crossing.issuanceDecision,
      recognition_rule: crossing.recognitionRule,
      target_binding: targetBinding,
    });

    function apply(input = {}) {
      const result = service.applyRequest({
        runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
        record_update: recordUpdate,
        target_handle: PROTECTED_RECORDS_TARGET_HANDLE,
        ...input,
      });
      assertProtectedRecordsRuntimeServiceResult(result);
      return result;
    }

    const recognizedResult = apply({
      request_mode: 'recognized_installed_profile_write',
      receipt: crossing.receipt,
    });
    const invalidReceipt = {
      ...crossing.receipt,
      sig: `${crossing.receipt.sig.slice(0, -4)}xxxx`,
    };
    const cases = [
      ['missing_receipt_refused_before_runtime_mutation', {
        request_mode: 'missing_receipt_installed_profile_write',
      }],
      ['invalid_receipt_refused_before_runtime_mutation', {
        request_mode: 'invalid_receipt_installed_profile_write',
        receipt: invalidReceipt,
      }],
      ['unknown_issuer_refused_before_runtime_mutation', {
        request_mode: 'unknown_issuer_installed_profile_write',
        receipt: rawSignedReceipt({ crossing, key: unknownIssuer, nowEpoch }),
      }],
      ['retired_issuer_refused_before_runtime_mutation', {
        request_mode: 'retired_issuer_installed_profile_write',
        receipt: rawSignedReceipt({ crossing, key: retiredIssuer, nowEpoch }),
      }],
      ['missing_issuer_status_refused_before_runtime_mutation', {
        request_mode: 'missing_issuer_status_installed_profile_write',
        receipt: rawSignedReceipt({ crossing, key: missingStatusIssuer, nowEpoch }),
      }],
      ['wrong_policy_refused_before_runtime_mutation', {
        request_mode: 'wrong_policy_installed_profile_write',
        receipt: rawSignedReceipt({
          crossing,
          key: activeIssuer,
          nowEpoch,
          overrides: { policyVersion: 'recognition-policy-old' },
        }),
      }],
      ['wrong_domain_refused_before_runtime_mutation', {
        request_mode: 'wrong_domain_installed_profile_write',
        receipt: rawSignedReceipt({
          crossing,
          key: activeIssuer,
          nowEpoch,
          overrides: { domain: 'finance' },
        }),
      }],
      ['wrong_tool_refused_before_runtime_mutation', {
        request_mode: 'wrong_tool_installed_profile_write',
        receipt: rawSignedReceipt({
          crossing,
          key: activeIssuer,
          nowEpoch,
          overrides: { action: 'records.delete' },
        }),
      }],
      ['wrong_runtime_profile_id_refused_before_runtime_mutation', {
        request_mode: 'wrong_runtime_profile_id_installed_profile_write',
        runtime_profile_id: 'wrong-runtime-profile',
        receipt: rawSignedReceipt({ crossing, key: activeIssuer, nowEpoch }),
      }],
      ['wrong_audit_event_refused_before_runtime_mutation', {
        request_mode: 'wrong_audit_event_installed_profile_write',
        receipt: rawSignedReceipt({
          crossing,
          key: activeIssuer,
          nowEpoch,
          overrides: { auditEventId: 'protected-records-installed-profile-999' },
        }),
      }],
      ['wrong_detail_refused_before_runtime_mutation', {
        request_mode: 'wrong_detail_installed_profile_write',
        receipt: rawSignedReceipt({
          crossing,
          key: activeIssuer,
          nowEpoch,
          overrides: { detail: { operation: 'set_status', record_alias: 'other-fixture' } },
        }),
      }],
      ['non_boarding_outcome_refused_before_runtime_mutation', {
        request_mode: 'non_boarding_installed_profile_write',
        receipt: rawSignedReceipt({
          crossing,
          key: activeIssuer,
          nowEpoch,
          overrides: { outcome: 'deny' },
        }),
      }],
      ['stale_receipt_refused_before_runtime_mutation', {
        request_mode: 'stale_receipt_installed_profile_write',
        receipt: rawSignedReceipt({
          crossing,
          key: activeIssuer,
          nowEpoch,
          overrides: { issuedAtEpoch: nowEpoch - 600 },
        }),
      }],
      ['direct_api_without_receipt_refused_before_runtime_mutation', {
        request_mode: 'direct_api_write_without_receipt',
        direct_api_write: true,
      }],
      ['direct_api_with_receipt_refused_before_runtime_mutation', {
        request_mode: 'direct_api_write_with_receipt',
        direct_api_write: true,
        receipt: rawSignedReceipt({ crossing, key: activeIssuer, nowEpoch }),
      }],
      ['agent_supplied_recognition_rule_refused_before_runtime_mutation', {
        request_mode: 'agent_supplied_recognition_rule_installed_profile_write',
        receipt: rawSignedReceipt({ crossing, key: activeIssuer, nowEpoch }),
        recognition_rule: { accepted_issuers: [] },
      }],
      ['agent_supplied_fixture_mode_refused_before_runtime_mutation', {
        request_mode: 'agent_supplied_fixture_mode_installed_profile_write',
        receipt: rawSignedReceipt({ crossing, key: activeIssuer, nowEpoch }),
        fixture_mode: true,
      }],
      ['unsupported_request_field_refused_before_runtime_mutation', {
        request_mode: 'unsupported_request_field_installed_profile_write',
        receipt: rawSignedReceipt({ crossing, key: activeIssuer, nowEpoch }),
        unsupported_authority_field: true,
      }],
    ];
    const recognized = caseSummary('recognized_installed_profile_write', recognizedResult);
    const refusalCases = cases.map(([caseId, input]) => caseSummary(caseId, apply(input)));
    const authoritySummary = publicAuthoritySummary(crossing, recognizedResult, nowEpoch);
    const report = {
      proof_type: PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_TYPE,
      evidence_model: 'local-hermetic-installed-runtime-profile-recognition-fixture',
      live_probing: false,
      safe_claim_ceiling: INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_SAFE_CLAIM_CEILING,
      source_preflight: {
        verified: verification.verified,
        artifact_type: verification.artifact_type,
        body_sha256: verification.body_sha256,
        payload_type: verification.payload_type,
        read_only: verification.read_only,
        requested_profile_id: verification.requested_profile_id,
        requested_profile_sha256: verification.requested_profile_sha256,
        profile_selected_from_install_root: verification.profile_selected_from_install_root,
        selected_by_explicit_id_and_sha: verification.selected_by_explicit_id_and_sha,
        selects_latest_profile: verification.selects_latest_profile,
        recognition_contract_preserved: verification.recognition_contract_preserved,
        recognition_contract_sha256: verification.recognition_contract_sha256,
        target_contract_preserved: verification.target_contract_preserved,
        target_contract_sha256: verification.target_contract_sha256,
        authority_grant_requirement_preserved:
          verification.authority_grant_requirement_preserved,
        exact_runtime_authority_grant_contract_deferred:
          verification.exact_runtime_authority_grant_contract_deferred,
        mutation_authoritative_route: verification.mutation_authoritative_route,
        request_stream_authority_material_accepted:
          verification.request_stream_authority_material_accepted,
        downstream_refusal_proven: verification.downstream_refusal_proven,
        rightful_issuance_proven: verification.rightful_issuance_proven,
        consequence_lifecycle_closed: verification.consequence_lifecycle_closed,
        current_machine_governance_proven:
          verification.current_machine_governance_proven,
      },
      recognition_contract: {
        source: 'verified-installed-runtime-profile-preflight-artifact',
        action_class: 'records.write',
        runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
        recognition_boundary: verification.recognition_boundary,
        mutation_authoritative_route: MUTATION_ROUTE,
        request_stream_authority_material_accepted: false,
        recognition_rule_supplied_by_agent: false,
        required_refusal_cases: [...REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES],
        required_refusal_case_count:
          REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
        observed_refusal_taxonomy_sha256: refusalTaxonomySha256(refusalCases),
      },
      fixture_authority: {
        source: 'launcher-owned-local-fixture-overlay',
        request_supplied_authority_accepted: false,
        construction_order: [
          'launcher_scope_evidence',
          'authority_grant_contract',
          'issuer_appointment',
          'authorized_effect_detail',
          'unsigned_receipt',
          'accepted_issuance_decision',
          'receipt_signature',
          'downstream_recognition',
          'effect_gate',
          'authority_grant_consumption',
          'runtime_state_mutation',
        ],
        public_safe_grant_summary: authoritySummary,
      },
      runtime_identity_boundary: {
        ordered_transition_binding_type: recognizedResult.runtime_transition_binding.binding_type,
        signed_payload_replay_identity: recognizedResult.signed_payload_replay_identity,
        authority_grant_consumption_identity: recognizedResult.consumption_identity,
        consumed_authority_grant_store: recognizedResult.consumed_authority_grant_store,
        consumed_store_write_model: recognizedResult.consumed_store_write_model,
        mutation_authoritative_route: recognizedResult.mutation_authoritative_route,
      },
      accepted_runtime_transition_binding: recognizedResult.runtime_transition_binding,
      target_binding: {
        consequence_path: targetBinding.consequence_path,
        target_kind: targetBinding.target_kind,
        target_scope: targetBinding.target_scope,
        target_instance_scope: targetBinding.target_instance_scope,
        target_handle: targetBinding.target_handle,
        target_binding_sha256: recognizedResult.target_binding_sha256,
        record_update_sha256: recognizedResult.record_update_hash,
        target_effect_sha256: recognizedResult.target_effect_hash,
        authorized_effect_detail_sha256:
          recognizedResult.authorized_effect_detail_sha256,
        receipt_detail_sha256: recognizedResult.receipt_detail_hash,
        receipt_binds_authorized_effect_detail:
          recognizedResult.receipt_detail_hash ===
            recognizedResult.authorized_effect_detail_sha256,
        target_effect_bound_inside_authorized_effect_detail:
          crossing.contract.scope.target_effect_sha256 === recognizedResult.target_effect_hash,
        state_effect_binding_sha256: recognizedResult.state_effect_binding_sha256,
      },
      recognized_boarding: recognized,
      refusal_cases: refusalCases,
      proof_boundary: {
        local_hermetic_fixture: true,
        downstream_shaped_service_object_created: true,
        fake_effect_marker: 'process-private-service-state-entry-count',
        disposable_consumed_grant_store_written: true,
        disposable_consumed_grant_store_anchor_written: true,
        disposable_consumed_grant_store_witness_written: true,
        install_performed: false,
        activation_performed: false,
        runtime_config_written: false,
        hook_configuration_written: false,
        user_configuration_written: false,
        machine_configuration_written: false,
        runtime_service_started: false,
        live_runtime_profile_checked: false,
        live_records_system_checked: false,
        production_records_service_checked: false,
        fixture_rightful_issuance_path_evidenced: true,
        rightful_issuance_proven: false,
        portable_rightful_issuance_proven: false,
        production_rightful_issuance_proven: false,
        live_authority_proven: false,
        current_machine_governance_proven: false,
        production_downstream_recognition: false,
        external_attestation: false,
        sovereign_recognition: false,
        consequence_lifecycle_closed: false,
        unrouted_records_paths_checked: false,
      },
      marker: {
        final_state_entry_count: recognizedResult.state_entry_count_after,
        recognized_state_entry_count_delta: recognized.state_entry_count_delta,
        refusal_state_entry_count_delta_total: refusalCases.reduce(
          (total, item) => total + item.state_entry_count_delta,
          0
        ),
        consumed_authority_grant_count: recognizedResult.consumed_authority_grant_count,
        raw_receipt_id_present: false,
        raw_record_id_present: false,
        runtime_private_issuer_material_present: false,
      },
      non_claims: [...INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_NON_CLAIMS],
    };
    assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(report);
    return report;
  } finally {
    if (scratch) rmSync(scratch, { recursive: true, force: true });
  }
}

function assertCase(label, value) {
  assertExactKeys(label, value, [
    'authority_grant_satisfied',
    'boarded',
    'case_id',
    'consumed_authority_grant_count',
    'decision',
    'direct_api_attempted',
    'reason_code',
    'runtime_transition_binding_present',
    'service_write_accepted',
    'state_entry_count_after',
    'state_entry_count_before',
    'state_entry_count_delta',
    'verified_signed_payload_identity_present',
  ]);
  if (
    value.boarded !== value.service_write_accepted ||
    value.state_entry_count_delta !== value.state_entry_count_after - value.state_entry_count_before ||
    !['accept', 'refuse'].includes(value.decision) ||
    typeof value.reason_code !== 'string'
  ) {
    throw new Error(`${label} drifted`);
  }
  return true;
}

function assertPublicSummary(summary, report) {
  requireObject('Installed recognition public authority summary', summary);
  assertExactKeys('Installed recognition public authority summary', summary, [
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
  if (
    summary.summary_type !== PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_SUMMARY_TYPE ||
    summary.authority_domain_id !== PROTECTED_RECORDS_FIXTURE_AUTHORITY_DOMAIN_ID ||
    summary.grantor_role_id !== PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID ||
    summary.rightful_issuance_scope !== PROTECTED_RECORDS_FIXTURE_RIGHTFUL_ISSUANCE_SCOPE ||
    summary.consequence_path !== PROTECTED_RECORDS_CONSEQUENCE_PATH ||
    summary.target_handle !== PROTECTED_RECORDS_TARGET_HANDLE ||
    summary.authority_grant_contract_sha256 !==
      report.accepted_runtime_transition_binding.authority_grant_contract_sha256 ||
    summary.fixture_rightful_issuance_path_evidenced !== true ||
    summary.issuance_gate_evaluated_before_signing !== true ||
    summary.effect_gate_evaluated_before_authority_grant_consumption !== true ||
    summary.authority_grant_consumed_before_state_mutation !== true ||
    summary.runtime_private_issuer_identity_disclosed !== false ||
    summary.runtime_private_grant_appointment_disclosed !== false ||
    summary.rightful_issuance_proven !== false ||
    summary.portable_rightful_issuance_proven !== false ||
    summary.production_rightful_issuance_proven !== false ||
    summary.current_machine_governance_proven !== false ||
    summary.consequence_lifecycle_closed !== false
  ) {
    throw new Error('Installed recognition public authority summary drifted');
  }
  assertExactArray(
    'Installed recognition public authority powers',
    summary.power_ids,
    PROTECTED_RECORDS_FIXTURE_AUTHORITY_POWERS.map((item) => item.power_id)
  );
  const forbiddenKeys = new Set([
    'grantee_issuer_kid',
    'grantee_public_key_sha256',
    'issuer_kid',
    'public_key_pem',
    'private_key_pem',
    'authority_grant_appointment',
    'signature',
  ]);
  const containsPrivate = (value) => {
    if (typeof value === 'string') return /BEGIN (?:PUBLIC|PRIVATE) KEY/.test(value);
    if (!value || typeof value !== 'object') return false;
    return Object.entries(value).some(([key, child]) =>
      forbiddenKeys.has(key) || containsPrivate(child)
    );
  };
  if (containsPrivate(summary)) {
    throw new Error('Installed recognition public authority summary disclosed private issuer material');
  }
  return true;
}

export function assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(report) {
  assertExactKeys('Installed runtime profile recognition proof', report, [
    'accepted_runtime_transition_binding',
    'evidence_model',
    'fixture_authority',
    'live_probing',
    'marker',
    'non_claims',
    'proof_boundary',
    'proof_type',
    'recognition_contract',
    'recognized_boarding',
    'refusal_cases',
    'runtime_identity_boundary',
    'safe_claim_ceiling',
    'source_preflight',
    'target_binding',
  ]);
  if (
    report.proof_type !== PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_TYPE ||
    report.evidence_model !== 'local-hermetic-installed-runtime-profile-recognition-fixture' ||
    report.live_probing !== false ||
    report.safe_claim_ceiling !== INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_SAFE_CLAIM_CEILING
  ) {
    throw new Error('Installed recognition proof identity drifted');
  }
  assertExactKeys('Installed recognition source preflight', report.source_preflight, [
    'artifact_type',
    'authority_grant_requirement_preserved',
    'body_sha256',
    'consequence_lifecycle_closed',
    'current_machine_governance_proven',
    'downstream_refusal_proven',
    'exact_runtime_authority_grant_contract_deferred',
    'mutation_authoritative_route',
    'payload_type',
    'profile_selected_from_install_root',
    'read_only',
    'recognition_contract_preserved',
    'recognition_contract_sha256',
    'request_stream_authority_material_accepted',
    'requested_profile_id',
    'requested_profile_sha256',
    'rightful_issuance_proven',
    'selected_by_explicit_id_and_sha',
    'selects_latest_profile',
    'target_contract_preserved',
    'target_contract_sha256',
    'verified',
  ]);
  if (
    report.source_preflight.verified !== true ||
    report.source_preflight.read_only !== true ||
    report.source_preflight.selected_by_explicit_id_and_sha !== true ||
    report.source_preflight.selects_latest_profile !== false ||
    report.source_preflight.recognition_contract_preserved !== true ||
    report.source_preflight.target_contract_preserved !== true ||
    report.source_preflight.authority_grant_requirement_preserved !== true ||
    report.source_preflight.exact_runtime_authority_grant_contract_deferred !== true ||
    report.source_preflight.mutation_authoritative_route !== MUTATION_ROUTE ||
    report.source_preflight.request_stream_authority_material_accepted !== false ||
    report.source_preflight.rightful_issuance_proven !== false ||
    report.source_preflight.consequence_lifecycle_closed !== false ||
    report.source_preflight.downstream_refusal_proven !== false ||
    report.source_preflight.current_machine_governance_proven !== false
  ) {
    throw new Error('Installed recognition proof source preflight drifted');
  }
  assertSha256('Installed recognition source preflight SHA', report.source_preflight.body_sha256);
  assertSha256('Installed recognition source contract SHA', report.source_preflight.recognition_contract_sha256);
  assertSha256('Installed recognition target contract SHA', report.source_preflight.target_contract_sha256);
  assertExactKeys('Installed recognition contract', report.recognition_contract, [
    'action_class',
    'mutation_authoritative_route',
    'observed_refusal_taxonomy_sha256',
    'recognition_boundary',
    'recognition_rule_supplied_by_agent',
    'request_stream_authority_material_accepted',
    'required_refusal_case_count',
    'required_refusal_cases',
    'runtime_profile_id',
    'source',
  ]);
  assertExactArray(
    'Installed recognition required refusal cases',
    report.recognition_contract.required_refusal_cases,
    REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES
  );
  if (
    report.recognition_contract.mutation_authoritative_route !== MUTATION_ROUTE ||
    report.recognition_contract.request_stream_authority_material_accepted !== false ||
    report.recognition_contract.recognition_rule_supplied_by_agent !== false ||
    report.recognition_contract.required_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length ||
    report.recognition_contract.observed_refusal_taxonomy_sha256 !==
      refusalTaxonomySha256(report.refusal_cases)
  ) {
    throw new Error('Installed recognition contract drifted');
  }
  assertCase('Installed recognition positive case', report.recognized_boarding);
  if (
    report.recognized_boarding.case_id !== 'recognized_installed_profile_write' ||
    report.recognized_boarding.service_write_accepted !== true ||
    report.recognized_boarding.reason_code !== 'fixture_authority_grant_effect_satisfied' ||
    report.recognized_boarding.state_entry_count_delta !== 1 ||
    report.recognized_boarding.consumed_authority_grant_count !== 1 ||
    report.recognized_boarding.authority_grant_satisfied !== true ||
    report.recognized_boarding.verified_signed_payload_identity_present !== true ||
    report.recognized_boarding.runtime_transition_binding_present !== true
  ) {
    throw new Error('Installed recognition positive crossing drifted');
  }
  assertExactArray(
    'Installed recognition observed refusal cases',
    report.refusal_cases.map((item) => item.case_id),
    REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES
  );
  report.refusal_cases.forEach((item) => {
    assertCase('Installed recognition refusal', item);
    if (
      item.service_write_accepted !== false ||
      item.state_entry_count_delta !== 0 ||
      item.consumed_authority_grant_count !== 1 ||
      item.reason_code !== EXPECTED_REFUSAL_REASONS[item.case_id]
    ) {
      throw new Error(`Installed recognition refusal drifted: ${item.case_id}`);
    }
  });
  assertExactKeys('Installed recognition fixture authority', report.fixture_authority, [
    'construction_order',
    'public_safe_grant_summary',
    'request_supplied_authority_accepted',
    'source',
  ]);
  assertExactArray(
    'Installed recognition fixture authority construction order',
    report.fixture_authority.construction_order,
    [
      'launcher_scope_evidence',
      'authority_grant_contract',
      'issuer_appointment',
      'authorized_effect_detail',
      'unsigned_receipt',
      'accepted_issuance_decision',
      'receipt_signature',
      'downstream_recognition',
      'effect_gate',
      'authority_grant_consumption',
      'runtime_state_mutation',
    ]
  );
  if (
    report.fixture_authority.source !== 'launcher-owned-local-fixture-overlay' ||
    report.fixture_authority.request_supplied_authority_accepted !== false ||
    report.fixture_authority.construction_order.indexOf('accepted_issuance_decision') >=
      report.fixture_authority.construction_order.indexOf('receipt_signature') ||
    report.fixture_authority.construction_order.indexOf('effect_gate') >=
      report.fixture_authority.construction_order.indexOf('authority_grant_consumption') ||
    report.fixture_authority.construction_order.indexOf('authority_grant_consumption') >=
      report.fixture_authority.construction_order.indexOf('runtime_state_mutation')
  ) {
    throw new Error('Installed recognition fixture authority construction drifted');
  }
  const transition = requireObject(
    'Installed recognition ordered transition binding',
    report.accepted_runtime_transition_binding
  );
  assertExactKeys('Installed recognition ordered transition binding', transition, [
    'authority_grant_consumption_count_after',
    'authority_grant_consumption_count_before',
    'authority_grant_contract_sha256',
    'authority_grant_crossing_binding_sha256',
    'authorized_effect_detail_sha256',
    'binding_type',
    'consumed_grant_store_sha256_after',
    'consumed_grant_store_sha256_before',
    'effect_gate_preceded_grant_store_commit',
    'effect_gate_sequence',
    'grant_store_commit_preceded_state_append',
    'grant_store_commit_sequence',
    'helper_state_promotion_sequence',
    'one_launcher_store_lock_held_across_transition',
    'runtime_state_sha256_after',
    'runtime_state_sha256_before',
    'signed_payload_replay_check_preceded_effect_gate',
    'signed_payload_replay_check_sequence',
    'signed_payload_sha256',
    'state_append_preceded_helper_state_promotion',
    'state_append_sequence',
    'state_entry_count_after',
    'state_entry_count_before',
    'target_effect_sha256',
  ]);
  if (
    transition.binding_type !== ORDERED_TRANSITION_BINDING_TYPE ||
    transition.one_launcher_store_lock_held_across_transition !== true ||
    transition.signed_payload_replay_check_preceded_effect_gate !== true ||
    transition.effect_gate_preceded_grant_store_commit !== true ||
    transition.grant_store_commit_preceded_state_append !== true ||
    transition.state_append_preceded_helper_state_promotion !== true ||
    transition.authority_grant_consumption_count_before !== 0 ||
    transition.authority_grant_consumption_count_after !== 1 ||
    transition.state_entry_count_before !== 0 ||
    transition.state_entry_count_after !== 1 ||
    !(transition.signed_payload_replay_check_sequence < transition.effect_gate_sequence &&
      transition.effect_gate_sequence < transition.grant_store_commit_sequence &&
      transition.grant_store_commit_sequence < transition.state_append_sequence &&
      transition.state_append_sequence < transition.helper_state_promotion_sequence)
  ) {
    throw new Error('Installed recognition ordered transition drifted');
  }
  for (const key of [
    'authority_grant_contract_sha256',
    'authority_grant_crossing_binding_sha256',
    'authorized_effect_detail_sha256',
    'consumed_grant_store_sha256_after',
    'consumed_grant_store_sha256_before',
    'runtime_state_sha256_after',
    'runtime_state_sha256_before',
    'signed_payload_sha256',
    'target_effect_sha256',
  ]) assertSha256(`Installed recognition transition ${key}`, transition[key]);
  assertExactKeys('Installed recognition runtime identity boundary', report.runtime_identity_boundary, [
    'authority_grant_consumption_identity',
    'consumed_authority_grant_store',
    'consumed_store_write_model',
    'mutation_authoritative_route',
    'ordered_transition_binding_type',
    'signed_payload_replay_identity',
  ]);
  if (
    report.runtime_identity_boundary.ordered_transition_binding_type !==
      ORDERED_TRANSITION_BINDING_TYPE ||
    report.runtime_identity_boundary.signed_payload_replay_identity !==
      'verified-signed-payload-sha256' ||
    report.runtime_identity_boundary.authority_grant_consumption_identity !==
      'authority-grant-contract-sha256' ||
    report.runtime_identity_boundary.consumed_authority_grant_store !==
      'persistent-single-use-authority-grant-contract-sha256-store' ||
    report.runtime_identity_boundary.consumed_store_write_model !==
      'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness' ||
    report.runtime_identity_boundary.mutation_authoritative_route !== MUTATION_ROUTE
  ) {
    throw new Error('Installed recognition runtime identities drifted');
  }
  const target = report.target_binding;
  assertExactKeys('Installed recognition target binding', target, [
    'authorized_effect_detail_sha256',
    'consequence_path',
    'receipt_binds_authorized_effect_detail',
    'receipt_detail_sha256',
    'record_update_sha256',
    'state_effect_binding_sha256',
    'target_binding_sha256',
    'target_effect_bound_inside_authorized_effect_detail',
    'target_effect_sha256',
    'target_handle',
    'target_instance_scope',
    'target_kind',
    'target_scope',
  ]);
  if (
    target.consequence_path !== PROTECTED_RECORDS_CONSEQUENCE_PATH ||
    target.target_kind !== PROTECTED_RECORDS_TARGET_KIND ||
    target.target_scope !== PROTECTED_RECORDS_TARGET_SCOPE ||
    target.target_handle !== PROTECTED_RECORDS_TARGET_HANDLE ||
    target.receipt_detail_sha256 !== target.authorized_effect_detail_sha256 ||
    target.receipt_binds_authorized_effect_detail !== true ||
    target.target_effect_bound_inside_authorized_effect_detail !== true ||
    target.target_effect_sha256 === target.receipt_detail_sha256 ||
    transition.authorized_effect_detail_sha256 !== target.authorized_effect_detail_sha256 ||
    transition.target_effect_sha256 !== target.target_effect_sha256
  ) {
    throw new Error('Installed recognition target/effect binding drifted');
  }
  for (const key of [
    'authorized_effect_detail_sha256',
    'receipt_detail_sha256',
    'record_update_sha256',
    'state_effect_binding_sha256',
    'target_binding_sha256',
    'target_effect_sha256',
  ]) assertSha256(`Installed recognition target ${key}`, target[key]);
  assertPublicSummary(report.fixture_authority.public_safe_grant_summary, report);
  const boundary = report.proof_boundary;
  assertExactKeys('Installed recognition proof boundary', boundary, [
    'activation_performed',
    'consequence_lifecycle_closed',
    'current_machine_governance_proven',
    'disposable_consumed_grant_store_anchor_written',
    'disposable_consumed_grant_store_witness_written',
    'disposable_consumed_grant_store_written',
    'downstream_shaped_service_object_created',
    'external_attestation',
    'fake_effect_marker',
    'fixture_rightful_issuance_path_evidenced',
    'hook_configuration_written',
    'install_performed',
    'live_authority_proven',
    'live_records_system_checked',
    'live_runtime_profile_checked',
    'local_hermetic_fixture',
    'machine_configuration_written',
    'portable_rightful_issuance_proven',
    'production_downstream_recognition',
    'production_records_service_checked',
    'production_rightful_issuance_proven',
    'rightful_issuance_proven',
    'runtime_config_written',
    'runtime_service_started',
    'sovereign_recognition',
    'unrouted_records_paths_checked',
    'user_configuration_written',
  ]);
  if (
    boundary.local_hermetic_fixture !== true ||
    boundary.downstream_shaped_service_object_created !== true ||
    boundary.disposable_consumed_grant_store_written !== true ||
    boundary.disposable_consumed_grant_store_anchor_written !== true ||
    boundary.disposable_consumed_grant_store_witness_written !== true ||
    boundary.fixture_rightful_issuance_path_evidenced !== true ||
    boundary.rightful_issuance_proven !== false ||
    boundary.portable_rightful_issuance_proven !== false ||
    boundary.production_rightful_issuance_proven !== false ||
    boundary.live_authority_proven !== false ||
    boundary.current_machine_governance_proven !== false ||
    boundary.production_downstream_recognition !== false ||
    boundary.external_attestation !== false ||
    boundary.sovereign_recognition !== false ||
    boundary.consequence_lifecycle_closed !== false ||
    boundary.install_performed !== false ||
    boundary.activation_performed !== false ||
    boundary.runtime_config_written !== false ||
    boundary.runtime_service_started !== false ||
    boundary.live_records_system_checked !== false ||
    boundary.live_runtime_profile_checked !== false ||
    boundary.production_records_service_checked !== false ||
    boundary.hook_configuration_written !== false ||
    boundary.user_configuration_written !== false ||
    boundary.machine_configuration_written !== false ||
    boundary.unrouted_records_paths_checked !== false
  ) {
    throw new Error('Installed recognition claim boundary drifted');
  }
  assertExactKeys('Installed recognition marker', report.marker, [
    'consumed_authority_grant_count',
    'final_state_entry_count',
    'raw_receipt_id_present',
    'raw_record_id_present',
    'recognized_state_entry_count_delta',
    'refusal_state_entry_count_delta_total',
    'runtime_private_issuer_material_present',
  ]);
  if (
    report.marker.final_state_entry_count !== 1 ||
    report.marker.recognized_state_entry_count_delta !== 1 ||
    report.marker.refusal_state_entry_count_delta_total !== 0 ||
    report.marker.consumed_authority_grant_count !== 1 ||
    report.marker.raw_receipt_id_present !== false ||
    report.marker.raw_record_id_present !== false ||
    report.marker.runtime_private_issuer_material_present !== false
  ) {
    throw new Error('Installed recognition marker drifted');
  }
  assertExactArray(
    'Installed recognition non-claims',
    report.non_claims,
    INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_NON_CLAIMS
  );
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return true;
}

export function formatProtectedRecordsInstalledRuntimeProfileRecognitionProofSummary(report) {
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(report);
  const authorityGrantStatus = protectedRecordsFixtureAuthorityGrantStatus(
    report.fixture_authority.public_safe_grant_summary
      .authority_grant_contract_sha256,
  );
  const lines = [
    'ZLAR Protected Records Installed Runtime Profile Recognition Proof v1',
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Source preflight: verified=${report.source_preflight.verified}; read_only=${report.source_preflight.read_only}; route=${report.source_preflight.mutation_authoritative_route}; source_rightful_issuance_proven=${report.source_preflight.rightful_issuance_proven}`,
    `Recognition contract: required_refusal_cases=${report.recognition_contract.required_refusal_case_count}; taxonomy_sha256=${report.recognition_contract.observed_refusal_taxonomy_sha256}; request_stream_authority_material_accepted=${report.recognition_contract.request_stream_authority_material_accepted}`,
    `Fixture authority: domain=${report.fixture_authority.public_safe_grant_summary.authority_domain_id}; grantor_role=${report.fixture_authority.public_safe_grant_summary.grantor_role_id}; powers=${report.fixture_authority.public_safe_grant_summary.power_ids.join(',')}; request_supplied_authority_accepted=${report.fixture_authority.request_supplied_authority_accepted}`,
    `Runtime identities: ordered_transition_binding_type=${report.runtime_identity_boundary.ordered_transition_binding_type}; signed_payload_replay_identity=${report.runtime_identity_boundary.signed_payload_replay_identity}; authority_grant_consumption_identity=${report.runtime_identity_boundary.authority_grant_consumption_identity}`,
    `Boarded: ${report.recognized_boarding.case_id}; decision=${report.recognized_boarding.decision}; reason=${report.recognized_boarding.reason_code}; marker_delta=${report.recognized_boarding.state_entry_count_delta}`,
    'Recognition refusals:',
    ...report.refusal_cases.map((item) =>
      `- ${item.case_id}: reason=${item.reason_code}; marker_delta=${item.state_entry_count_delta}`
    ),
    `Historical artifact boundary: historical_artifact_fixture_rightful_issuance_path_recorded=${report.proof_boundary.fixture_rightful_issuance_path_evidenced}; authority_grant_status=${authorityGrantStatus.status}; current_fixture_rightful_issuance_path_evidenced=false; rightful_issuance_proven=${report.proof_boundary.rightful_issuance_proven}; portable_rightful_issuance_proven=${report.proof_boundary.portable_rightful_issuance_proven}; production_rightful_issuance_proven=${report.proof_boundary.production_rightful_issuance_proven}; live_authority_proven=${report.proof_boundary.live_authority_proven}; current_machine_governance_proven=${report.proof_boundary.current_machine_governance_proven}; consequence_lifecycle_closed=${report.proof_boundary.consequence_lifecycle_closed}`,
    'Non-claims:',
    ...report.non_claims.map((item) => `- ${item}`),
  ];
  const output = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  return output;
}

function artifactBody(payload) {
  return {
    artifact_type: PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_TYPE,
    canonicalization:
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_CANONICALIZATION,
    generator: 'zlar protected-records-installed-runtime-profile-recognition-proof --artifact',
    hash_scope: 'canonical artifact body without integrity',
    payload,
  };
}

export function buildProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(report) {
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(report);
  const body = artifactBody({ proof: report });
  const artifact = {
    ...body,
    integrity: { algorithm: 'SHA-256', body_sha256: sha256hex(canonicalize(body)) },
  };
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(artifact);
  return artifact;
}

export function assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(artifact) {
  assertExactKeys('Installed recognition proof artifact', artifact, [
    'artifact_type', 'canonicalization', 'generator', 'hash_scope', 'integrity', 'payload',
  ]);
  if (
    artifact.artifact_type !== PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_TYPE ||
    artifact.canonicalization !== PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_CANONICALIZATION ||
    artifact.generator !== 'zlar protected-records-installed-runtime-profile-recognition-proof --artifact' ||
    artifact.hash_scope !== 'canonical artifact body without integrity'
  ) {
    throw new Error('Installed recognition proof artifact boundary drifted');
  }
  assertExactKeys('Installed recognition proof artifact payload', artifact.payload, ['proof']);
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(artifact.payload.proof);
  assertExactKeys('Installed recognition proof artifact integrity', artifact.integrity, [
    'algorithm', 'body_sha256',
  ]);
  const { integrity, ...body } = artifact;
  if (
    integrity.algorithm !== 'SHA-256' ||
    integrity.body_sha256 !== sha256hex(canonicalize(body))
  ) {
    throw new Error('Installed recognition proof artifact SHA-256 mismatch');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(artifact));
  return true;
}

export function writeProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(artifact, outputPath) {
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(artifact);
  if (!outputPath || outputPath === '-') throw new Error('Installed recognition proof artifact output path is required');
  mkdirSync(dirname(outputPath), { recursive: true });
  const output = `${JSON.stringify(artifact, null, 2)}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  writeFileSync(outputPath, output, { mode: 0o600 });
  return artifact.integrity.body_sha256;
}

export function parseProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactText(text) {
  assertNoUnsafeProtectedRecordsRuntimeProfileText(text);
  let artifact;
  try {
    artifact = JSON.parse(text);
  } catch {
    throw new Error('Installed recognition proof artifact input is not valid JSON');
  }
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(artifact);
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

export function verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(
  artifact,
  {
    expectedArtifactBodySha256 = null,
    expectedSourcePreflightBodySha256 = null,
  } = {}
) {
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(artifact);
  const proof = artifact.payload.proof;
  const artifactIdentity = matchExpectedSha256(
    'Installed recognition proof artifact',
    expectedArtifactBodySha256,
    artifact.integrity.body_sha256
  );
  const sourcePreflightIdentity = matchExpectedSha256(
    'Installed recognition proof source preflight',
    expectedSourcePreflightBodySha256,
    proof.source_preflight.body_sha256
  );
  const fixtureIdentityBound =
    artifactIdentity.matched && sourcePreflightIdentity.matched;
  const authorityGrantContractSha256 =
    proof.fixture_authority.public_safe_grant_summary.authority_grant_contract_sha256;
  const authorityProjection = detachedFixtureAuthorityProjectionStatus(
    authorityGrantContractSha256
  );
  const verification = {
    verification_type:
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_VERIFICATION_TYPE,
    verified: true,
    structural_self_integrity_verified: true,
    embedded_fixture_assertions_structurally_validated: true,
    artifact_identity_match_requires_expected_sha256: true,
    artifact_identity_expected_sha256_supplied: artifactIdentity.supplied,
    expected_artifact_body_sha256: artifactIdentity.expected,
    artifact_identity_sha256_matched: artifactIdentity.matched,
    source_preflight_identity_match_requires_expected_sha256: true,
    source_preflight_identity_expected_sha256_supplied:
      sourcePreflightIdentity.supplied,
    expected_source_preflight_body_sha256: sourcePreflightIdentity.expected,
    source_preflight_body_sha256_matched: sourcePreflightIdentity.matched,
    signed_payload_identity_bound_to_expected_artifact_and_source_sha256:
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
    source_preflight_route: proof.source_preflight.mutation_authoritative_route,
    recognition_contract_sha256: proof.source_preflight.recognition_contract_sha256,
    target_contract_sha256: proof.source_preflight.target_contract_sha256,
    refusal_case_count: proof.refusal_cases.length,
    required_refusal_cases: [...REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES],
    refusal_taxonomy_sha256: proof.recognition_contract.observed_refusal_taxonomy_sha256,
    all_refusals_before_mutation: proof.refusal_cases.every(
      (item) => item.service_write_accepted === false && item.state_entry_count_delta === 0
    ),
    recognized_write_boarded:
      fixtureIdentityBound && proof.recognized_boarding.boarded,
    recognized_write_state_entry_delta:
      fixtureIdentityBound ? proof.recognized_boarding.state_entry_count_delta : 0,
    authority_domain_id:
      proof.fixture_authority.public_safe_grant_summary.authority_domain_id,
    grantor_role_id:
      proof.fixture_authority.public_safe_grant_summary.grantor_role_id,
    power_ids: [...proof.fixture_authority.public_safe_grant_summary.power_ids],
    authority_grant_contract_sha256: authorityGrantContractSha256,
    authority_grant_status: authorityProjection.status.status,
    authority_grant_fresh_effect_allowed:
      authorityProjection.status.fresh_effect_allowed,
    authority_grant_repeated_use_provenance_valid:
      authorityProjection.status.repeated_use_provenance_valid,
    authority_grant_status_allows_fixture_rightful_projection:
      authorityProjection.allowed,
    authority_grant_status_reason_code: authorityProjection.reasonCode,
    request_supplied_authority_accepted:
      proof.fixture_authority.request_supplied_authority_accepted,
    ordered_transition_binding_type:
      proof.runtime_identity_boundary.ordered_transition_binding_type,
    ordered_transition_binding_sha256:
      sha256hex(canonicalize(proof.accepted_runtime_transition_binding)),
    signed_payload_replay_identity:
      proof.runtime_identity_boundary.signed_payload_replay_identity,
    authority_grant_consumption_identity:
      proof.runtime_identity_boundary.authority_grant_consumption_identity,
    receipt_binds_authorized_effect_detail:
      proof.target_binding.receipt_binds_authorized_effect_detail,
    target_effect_bound_inside_authorized_effect_detail:
      proof.target_binding.target_effect_bound_inside_authorized_effect_detail,
    fixture_rightful_issuance_path_evidenced:
      fixtureIdentityBound &&
      authorityProjection.allowed &&
      proof.proof_boundary.fixture_rightful_issuance_path_evidenced,
    rightful_issuance_proven: proof.proof_boundary.rightful_issuance_proven,
    portable_rightful_issuance_proven:
      proof.proof_boundary.portable_rightful_issuance_proven,
    production_rightful_issuance_proven:
      proof.proof_boundary.production_rightful_issuance_proven,
    live_authority_proven: proof.proof_boundary.live_authority_proven,
    install_performed: proof.proof_boundary.install_performed,
    activation_performed: proof.proof_boundary.activation_performed,
    runtime_service_started: proof.proof_boundary.runtime_service_started,
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
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactVerification(verification);
  return verification;
}

export function assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactVerification(
  verification
) {
  assertExactKeys('Installed recognition proof artifact verification', verification, [
    'activation_performed',
    'all_refusals_before_mutation',
    'artifact_identity_expected_sha256_supplied',
    'artifact_identity_match_requires_expected_sha256',
    'artifact_identity_sha256_matched',
    'artifact_type',
    'authority_domain_id',
    'authority_grant_fresh_effect_allowed',
    'authority_grant_consumption_identity',
    'authority_grant_contract_sha256',
    'authority_grant_repeated_use_provenance_valid',
    'authority_grant_status',
    'authority_grant_status_allows_fixture_rightful_projection',
    'authority_grant_status_reason_code',
    'body_sha256',
    'canonicalization',
    'claim_boundary',
    'consequence_lifecycle_closed',
    'current_machine_governance_proven',
    'embedded_fixture_assertions_structurally_validated',
    'evidence_model',
    'expected_artifact_body_sha256',
    'expected_source_preflight_body_sha256',
    'external_attestation',
    'fixture_rightful_issuance_path_evidenced',
    'grantor_role_id',
    'hash_scope',
    'install_performed',
    'live_authority_proven',
    'live_probing',
    'live_records_system_checked',
    'non_claims',
    'ordered_transition_binding_sha256',
    'ordered_transition_binding_type',
    'payload_type',
    'portable_rightful_issuance_proven',
    'power_ids',
    'production_downstream_recognition',
    'production_rightful_issuance_proven',
    'receipt_binds_authorized_effect_detail',
    'recognition_contract_sha256',
    'recognized_write_boarded',
    'recognized_write_state_entry_delta',
    'refusal_case_count',
    'refusal_taxonomy_sha256',
    'request_supplied_authority_accepted',
    'required_refusal_cases',
    'rightful_issuance_proven',
    'runtime_service_started',
    'signed_payload_identity_bound_to_expected_artifact_and_source_sha256',
    'signed_payload_replay_identity',
    'source_preflight_body_sha256',
    'source_preflight_body_sha256_matched',
    'source_preflight_identity_expected_sha256_supplied',
    'source_preflight_identity_match_requires_expected_sha256',
    'source_preflight_route',
    'sovereign_recognition',
    'structural_self_integrity_verified',
    'target_contract_sha256',
    'target_effect_bound_inside_authorized_effect_detail',
    'verification_type',
    'verification_scope',
    'verified',
  ]);
  const fixtureIdentityBound =
    verification.artifact_identity_sha256_matched === true &&
    verification.source_preflight_body_sha256_matched === true;
  const authorityProjection = detachedFixtureAuthorityProjectionStatus(
    verification.authority_grant_contract_sha256
  );
  const expected = {
    verification_type:
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_VERIFICATION_TYPE,
    verified: true,
    structural_self_integrity_verified: true,
    embedded_fixture_assertions_structurally_validated: true,
    artifact_identity_match_requires_expected_sha256: true,
    source_preflight_identity_match_requires_expected_sha256: true,
    signed_payload_identity_bound_to_expected_artifact_and_source_sha256:
      fixtureIdentityBound,
    verification_scope:
      fixtureIdentityBound ? PINNED_VERIFICATION_SCOPE : STRUCTURAL_VERIFICATION_SCOPE,
    artifact_type: PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_TYPE,
    canonicalization:
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_CANONICALIZATION,
    hash_scope: 'canonical artifact body without integrity',
    payload_type: PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_TYPE,
    evidence_model: 'local-hermetic-installed-runtime-profile-recognition-fixture',
    live_probing: false,
    source_preflight_route: MUTATION_ROUTE,
    refusal_case_count: REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
    all_refusals_before_mutation: true,
    recognized_write_boarded: fixtureIdentityBound,
    recognized_write_state_entry_delta: fixtureIdentityBound ? 1 : 0,
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
    request_supplied_authority_accepted: false,
    ordered_transition_binding_type: ORDERED_TRANSITION_BINDING_TYPE,
    signed_payload_replay_identity: 'verified-signed-payload-sha256',
    authority_grant_consumption_identity: 'authority-grant-contract-sha256',
    receipt_binds_authorized_effect_detail: true,
    target_effect_bound_inside_authorized_effect_detail: true,
    fixture_rightful_issuance_path_evidenced:
      fixtureIdentityBound && authorityProjection.allowed,
    rightful_issuance_proven: false,
    portable_rightful_issuance_proven: false,
    production_rightful_issuance_proven: false,
    live_authority_proven: false,
    install_performed: false,
    activation_performed: false,
    runtime_service_started: false,
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
    if (verification[key] !== value) throw new Error(`Installed recognition verification ${key} drifted`);
  }
  if (
    verification.artifact_identity_expected_sha256_supplied !==
      verification.artifact_identity_sha256_matched ||
    verification.source_preflight_identity_expected_sha256_supplied !==
      verification.source_preflight_body_sha256_matched
  ) {
    throw new Error('Installed recognition verification identity match posture drifted');
  }
  if (verification.artifact_identity_expected_sha256_supplied) {
    assertSha256(
      'Installed recognition verification expected artifact identity',
      verification.expected_artifact_body_sha256
    );
    if (verification.expected_artifact_body_sha256 !== verification.body_sha256) {
      throw new Error('Installed recognition verification artifact identity drifted');
    }
  } else if (verification.expected_artifact_body_sha256 !== null) {
    throw new Error('Installed recognition verification unexpected artifact identity drifted');
  }
  if (verification.source_preflight_identity_expected_sha256_supplied) {
    assertSha256(
      'Installed recognition verification expected source preflight identity',
      verification.expected_source_preflight_body_sha256
    );
    if (
      verification.expected_source_preflight_body_sha256 !==
      verification.source_preflight_body_sha256
    ) {
      throw new Error('Installed recognition verification source preflight identity drifted');
    }
  } else if (verification.expected_source_preflight_body_sha256 !== null) {
    throw new Error('Installed recognition verification unexpected source identity drifted');
  }
  for (const key of [
    'body_sha256',
    'source_preflight_body_sha256',
    'recognition_contract_sha256',
    'target_contract_sha256',
    'refusal_taxonomy_sha256',
    'authority_grant_contract_sha256',
    'ordered_transition_binding_sha256',
  ]) assertSha256(`Installed recognition verification ${key}`, verification[key]);
  assertExactArray(
    'Installed recognition verification refusal cases',
    verification.required_refusal_cases,
    REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES
  );
  assertExactArray(
    'Installed recognition verification power ids',
    verification.power_ids,
    PROTECTED_RECORDS_FIXTURE_AUTHORITY_POWERS.map((item) => item.power_id)
  );
  assertExactArray(
    'Installed recognition verification non-claims',
    verification.non_claims,
    INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_NON_CLAIMS
  );
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(verification));
  return true;
}

export function formatProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactVerification(
  verification
) {
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactVerification(verification);
  const lines = [
    'ZLAR Protected Records Installed Runtime Profile Recognition Proof Artifact Verification v1',
    `verified=${verification.verified}; structural_self_integrity_verified=${verification.structural_self_integrity_verified}; embedded_fixture_assertions_structurally_validated=${verification.embedded_fixture_assertions_structurally_validated}; sha256=${verification.body_sha256}`,
    `verification_scope=${verification.verification_scope}`,
    `artifact_identity: expected_sha256_supplied=${verification.artifact_identity_expected_sha256_supplied}; sha256_matched=${verification.artifact_identity_sha256_matched}; match_requires_expected_sha256=${verification.artifact_identity_match_requires_expected_sha256}`,
    `source_preflight_identity: expected_sha256_supplied=${verification.source_preflight_identity_expected_sha256_supplied}; sha256_matched=${verification.source_preflight_body_sha256_matched}; match_requires_expected_sha256=${verification.source_preflight_identity_match_requires_expected_sha256}`,
    `signed_payload_identity_bound_to_expected_artifact_and_source_sha256=${verification.signed_payload_identity_bound_to_expected_artifact_and_source_sha256}`,
    `source_preflight_route=${verification.source_preflight_route}`,
    `recognized_write_boarded=${verification.recognized_write_boarded}; recognized_write_state_entry_delta=${verification.recognized_write_state_entry_delta}`,
    `refusal_cases=${verification.refusal_case_count}; all_refusals_before_mutation=${verification.all_refusals_before_mutation}; refusal_taxonomy_sha256=${verification.refusal_taxonomy_sha256}`,
    `fixture_authority: authority_domain_id=${verification.authority_domain_id}; grantor_role_id=${verification.grantor_role_id}; power_ids=${verification.power_ids.join(',')}; request_supplied_authority_accepted=${verification.request_supplied_authority_accepted}`,
    `fixture_authority_status: status=${verification.authority_grant_status}; fresh_effect_allowed=${verification.authority_grant_fresh_effect_allowed}; repeated_use_provenance_valid=${verification.authority_grant_repeated_use_provenance_valid}; allows_fixture_rightful_projection=${verification.authority_grant_status_allows_fixture_rightful_projection}; reason_code=${verification.authority_grant_status_reason_code}`,
    `runtime_identity_models: ordered_transition_binding_type=${verification.ordered_transition_binding_type}; signed_payload_replay_identity=${verification.signed_payload_replay_identity}; authority_grant_consumption_identity=${verification.authority_grant_consumption_identity}`,
    `claim_boundary: fixture_rightful_issuance_path_evidenced=${verification.fixture_rightful_issuance_path_evidenced}; rightful_issuance_proven=${verification.rightful_issuance_proven}; portable_rightful_issuance_proven=${verification.portable_rightful_issuance_proven}; production_rightful_issuance_proven=${verification.production_rightful_issuance_proven}; live_authority_proven=${verification.live_authority_proven}; current_machine_governance_proven=${verification.current_machine_governance_proven}; consequence_lifecycle_closed=${verification.consequence_lifecycle_closed}`,
    `claim_boundary=${verification.claim_boundary}`,
  ];
  const output = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  return output;
}

export function formatProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactSummary(artifact) {
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(artifact);
  const output = [
    'Portable installed runtime profile recognition proof artifact:',
    `- type=${artifact.artifact_type}`,
    `- sha256=${artifact.integrity.body_sha256}`,
    `- hash_scope=${artifact.hash_scope}`,
  ].join('\n') + '\n';
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  return output;
}
