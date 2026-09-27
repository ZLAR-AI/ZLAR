import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../lib/canonicalize.mjs';
import {
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_CONFIRMATION_TYPE_V2,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_RECEIPT_EVIDENCE_TYPE_V2,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_STATUS_TYPE_V2,
  createProtectedRecordsFixtureAuthorityAppointmentV2,
  createProtectedRecordsFixtureAuthorityGrantContractV2,
  createProtectedRecordsFixtureAuthoritySourcePreconditionV2,
  evaluateProtectedRecordsFixtureAuthorityIssuanceV2,
  protectedRecordsAuthorizedEffectDetailSha256V2,
  protectedRecordsAuthorizedEffectDetailV2,
  protectedRecordsFixtureAuthorityAppointmentSha256V2,
  protectedRecordsFixtureAuthorityExactConfirmationSha256V2,
  protectedRecordsFixtureAuthorityGrantContractSha256V2,
  protectedRecordsFixtureAuthorityImplementationBindingFromSourcePreconditionV2,
  protectedRecordsFixtureAuthoritySourcePreconditionBodySha256V2,
} from '../lib/protected-records-fixture-authority-grant-v2.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_EFFECT_GATE_BINDING_TYPE_V2,
  PROTECTED_RECORDS_RUNTIME_EXECUTION_TRACE_TYPE_V2,
  PROTECTED_RECORDS_RUNTIME_TRANSITION_BINDING_TYPE_V2,
  assertProtectedRecordsRuntimeEffectGateBindingV2,
  assertProtectedRecordsRuntimeExecutionTraceV2,
  assertProtectedRecordsRuntimeTransitionBindingV2,
  createProtectedRecordsRuntimeAuthorityContextV2,
  evaluateProtectedRecordsRuntimeClockTransitionV2,
  evaluateProtectedRecordsRuntimeEffectMarginV2,
  createProtectedRecordsRuntimeScopeEvidenceV2,
  evaluateProtectedRecordsRuntimeAuthorityEffectV2,
  protectedRecordsRuntimeEffectGateBindingSha256V2,
  protectedRecordsRuntimeExecutionTraceSha256V2,
  protectedRecordsRuntimeTransitionBindingSha256V2,
} from '../lib/protected-records-runtime-authority-v2.mjs';
import {
  assertProtectedRecordsRuntimeServiceResultV2,
  assertProtectedRecordsRuntimeServiceConfigV2,
  createProtectedRecordsRuntimeServiceV2,
  createProtectedRecordsRuntimeTargetBinding,
  isProtectedRecordsRuntimeServiceConfigV2,
} from '../lib/protected-records-runtime-profile.mjs';
import { sha256hex } from '../lib/receipt.mjs';

let assertions = 0;

function equal(label, expected, actual) {
  assertions += 1;
  if (expected !== actual) {
    throw new Error(
      `${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
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

const H = Object.freeze({
  a: 'a'.repeat(64),
  b: 'b'.repeat(64),
  c: 'c'.repeat(64),
  d: 'd'.repeat(64),
  e: 'e'.repeat(64),
  f: 'f'.repeat(64),
  zero: '0'.repeat(64),
  one: '1'.repeat(64),
  two: '2'.repeat(64),
  three: '3'.repeat(64),
  four: '4'.repeat(64),
  five: '5'.repeat(64),
  six: '6'.repeat(64),
  seven: '7'.repeat(64),
  eight: '8'.repeat(64),
  nine: '9'.repeat(64),
});

const effectGateBinding = {
  binding_type: PROTECTED_RECORDS_RUNTIME_EFFECT_GATE_BINDING_TYPE_V2,
  authority_effect_evaluation_epoch: 2_000_000_002,
  caller_supplied_consequence_time_accepted: false,
  consequence_clock_source: 'runtime-process-wall-clock-at-effect',
  minimum_effect_margin_seconds: 30,
  grant_window_remaining_seconds: 118,
  receipt_recognition_remaining_seconds: 119,
  authority_grant_contract_sha256: H.a,
  source_precondition_artifact_body_sha256: H.b,
  appointment_sha256: H.c,
  confirmation_sha256: H.d,
  authority_status_at_effect_sha256: H.e,
  issuer_binding_sha256: H.f,
  authorized_effect_detail_sha256: H.zero,
  issuance_decision_sha256: H.one,
  effect_decision_sha256: H.two,
  receipt_payload_sha256: H.three,
  signed_receipt_sha256: H.four,
  installed_profile_preflight_artifact_body_sha256: H.five,
  launcher_target_binding_sha256: H.six,
  profile_sha256: H.seven,
  recognition_contract_sha256: H.eight,
  target_contract_sha256: H.nine,
  target_effect_sha256: H.a,
};

console.log('\n-- strict pure v2 effect-gate and ordering evidence --');
for (const [label, earlierEpoch, laterEpoch, accepted, reasonCode] of [
  ['equal clock', 100, 100, true, 'authority_clock_monotonic'],
  ['forward clock', 100, 101, true, 'authority_clock_monotonic'],
  ['regressed clock', 100, 99, false, 'authority_clock_regressed'],
  ['invalid clock', 100, Number.NaN, false, 'authority_clock_unavailable'],
]) {
  const transition = evaluateProtectedRecordsRuntimeClockTransitionV2({
    earlierEpoch,
    laterEpoch,
  });
  equal(`${label} acceptance`, accepted, transition.accepted);
  equal(`${label} reason`, reasonCode, transition.reason_code);
  equal(`${label} consumes no grant`, false, transition.authority_grant_consumed);
  equal(`${label} mutates no state`, false, transition.runtime_state_mutated);
}
for (const [label, grantRemaining, receiptRemaining, accepted] of [
  ['30-second grant margin', 30, 31, false],
  ['30-second receipt margin', 31, 30, false],
  ['31-second margins', 31, 31, true],
]) {
  const margin = evaluateProtectedRecordsRuntimeEffectMarginV2({
    grantWindowRemainingSeconds: grantRemaining,
    receiptRecognitionRemainingSeconds: receiptRemaining,
  });
  equal(`${label} acceptance`, accepted, margin.accepted);
  equal(
    `${label} reason`,
    accepted
      ? 'authority_effect_window_margin_satisfied'
      : 'authority_effect_window_margin_insufficient',
    margin.reason_code,
  );
  equal(`${label} consumes no grant`, false, margin.authority_grant_consumed);
  equal(`${label} mutates no state`, false, margin.runtime_state_mutated);
}
ok('effect-gate binding validates', assertProtectedRecordsRuntimeEffectGateBindingV2(effectGateBinding));
equal('effect-gate binding hash is SHA-256', 64, protectedRecordsRuntimeEffectGateBindingSha256V2(effectGateBinding).length);
ok(
  'changing only effect epoch changes effect-gate binding identity',
  protectedRecordsRuntimeEffectGateBindingSha256V2(effectGateBinding) !==
    protectedRecordsRuntimeEffectGateBindingSha256V2({
      ...effectGateBinding,
      authority_effect_evaluation_epoch:
        effectGateBinding.authority_effect_evaluation_epoch + 1,
    }),
);
refuses(
  'effect-gate binding extra field refused',
  () => assertProtectedRecordsRuntimeEffectGateBindingV2({ ...effectGateBinding, hidden: H.a }),
  'unexpected or missing fields',
);
for (const [label, changes] of [
  ['negative effect epoch', { authority_effect_evaluation_epoch: -1 }],
  ['fractional effect epoch', { authority_effect_evaluation_epoch: 1.5 }],
  ['caller consequence time accepted', { caller_supplied_consequence_time_accepted: true }],
  ['wrong consequence clock source', { consequence_clock_source: 'caller-config-clock' }],
  ['changed minimum effect margin', { minimum_effect_margin_seconds: 29 }],
  ['insufficient grant margin', { grant_window_remaining_seconds: 30 }],
  ['insufficient receipt margin', { receipt_recognition_remaining_seconds: 30 }],
]) {
  refuses(
    `${label} refused`,
    () => assertProtectedRecordsRuntimeEffectGateBindingV2({
      ...effectGateBinding,
      ...changes,
    }),
    'clock boundary drifted',
  );
}

const executionTrace = {
  trace_type: PROTECTED_RECORDS_RUNTIME_EXECUTION_TRACE_TYPE_V2,
  authority_status_at_effect_sha256: H.e,
  authority_effect_gate_binding_sha256:
    protectedRecordsRuntimeEffectGateBindingSha256V2(effectGateBinding),
  effect_decision_sha256: H.two,
  signed_receipt_sha256: H.four,
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
ok('execution trace validates', assertProtectedRecordsRuntimeExecutionTraceV2(executionTrace));
equal('execution trace hash is SHA-256', 64, protectedRecordsRuntimeExecutionTraceSha256V2(executionTrace).length);
refuses(
  'recomputed structurally drifted trace refused',
  () => protectedRecordsRuntimeExecutionTraceSha256V2({
    ...executionTrace,
    effect_gate_sequence: 2,
  }),
  'ordering drifted',
);

const transition = {
  binding_type: PROTECTED_RECORDS_RUNTIME_TRANSITION_BINDING_TYPE_V2,
  authority_grant_contract_sha256: H.a,
  authority_effect_gate_binding_sha256:
    executionTrace.authority_effect_gate_binding_sha256,
  authority_grant_effect_decision_sha256: H.two,
  authority_grant_issuance_decision_sha256: H.one,
  authority_grant_status_at_effect_sha256: H.e,
  authorized_effect_detail_sha256: H.zero,
  execution_trace_sha256:
    protectedRecordsRuntimeExecutionTraceSha256V2(executionTrace),
  signed_receipt_sha256: H.four,
  verified_signed_payload_sha256: H.three,
  target_effect_sha256: H.a,
  state_effect_binding_sha256: H.b,
  consumed_grant_store_sha256_before: H.c,
  consumed_grant_store_sha256_after: H.d,
  runtime_state_sha256_before: H.e,
  runtime_state_sha256_after: H.f,
  authority_grant_consumption_count_before: 0,
  authority_grant_consumption_count_after: 1,
  state_entry_count_before: 0,
  state_entry_count_after: 1,
};
ok('transition validates', assertProtectedRecordsRuntimeTransitionBindingV2(transition));
equal('transition hash is SHA-256', 64, protectedRecordsRuntimeTransitionBindingSha256V2(transition).length);
refuses(
  'transition without one-use delta refused',
  () => protectedRecordsRuntimeTransitionBindingSha256V2({
    ...transition,
    authority_grant_consumption_count_after: 0,
  }),
  'count ordering drifted',
);

console.log('\n-- refusal-only config dispatch --');
equal('legacy contract does not dispatch v2', false, isProtectedRecordsRuntimeServiceConfigV2({
  authority_grant_contract: {
    contract_type: 'zlar-protected-records-fixture-authority-grant-contract-v1',
    contract_version: 1,
  },
}));
refuses(
  'missing source-owned v2 config refused',
  () => assertProtectedRecordsRuntimeServiceConfigV2({}),
  'unexpected fields',
);

console.log('\n-- dynamic forbidden request authority refuses without writes --');
const sourcePrecondition = createProtectedRecordsFixtureAuthoritySourcePreconditionV2({
  sourceCommitOid: '1'.repeat(40),
  serviceArtifactSchemaContractSha256: H.a,
  terminalArtifactSchemaContractSha256: H.b,
  noReexecutionCallGraphSha256: H.c,
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
    test_paths: ['tests/test-protected-records-runtime-authority-v2.mjs'],
    tests_passed: true,
  },
});
const targetBinding = createProtectedRecordsRuntimeTargetBinding();
const authorizedRecordUpdate = {
  operation: 'set_status',
  record_alias: 'v2-request-authority-refusal-only',
};
const receiptAuditEventId = 'v2-request-authority-refusal-only';
const scopeEvidence = createProtectedRecordsRuntimeScopeEvidenceV2({
  actionClass: 'records.write',
  authorizedRecordUpdate,
  profileId: 'protected-records-disposable-runtime-profile',
  recognitionRule: { required_audit_event_id: receiptAuditEventId },
  sourcePrecondition,
  targetBinding,
});
const contract = createProtectedRecordsFixtureAuthorityGrantContractV2({
  authorizationRecordId: 'schema-only-request-authority-refusal',
  implementationBinding:
    protectedRecordsFixtureAuthorityImplementationBindingFromSourcePreconditionV2(
      sourcePrecondition,
    ),
  scope: scopeEvidence.scope,
  validFromEpoch: 2_000_000_000,
  expiresAtEpoch: 2_000_000_120,
});
const contractSha256 =
  protectedRecordsFixtureAuthorityGrantContractSha256V2(contract);
const publicKeyPem = 'schema-only-public-key-string-not-cryptographic-material';
const appointment = createProtectedRecordsFixtureAuthorityAppointmentV2({
  contract,
  expectedContractSha256: contractSha256,
  issuerKid: 'schema-only-v2-request-refusal-issuer',
  publicKeySha256: sha256hex(publicKeyPem),
  issuedAtEpoch: 1_999_999_990,
});
const appointmentSha256 =
  protectedRecordsFixtureAuthorityAppointmentSha256V2(appointment, {
    contract,
    expectedContractSha256: contractSha256,
  });
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
  post_hardening_authorization_packet_body_sha256: H.d,
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
const authorityStatus = {
  status_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_STATUS_TYPE_V2,
  status_version: 2,
  authority_grant_contract_sha256: contractSha256,
  appointment_sha256: appointmentSha256,
  confirmation_sha256: confirmationSha256,
  status: 'active',
  status_source: 'source-recorded-exact-human-confirmation',
  maximum_effect_uses: 1,
  recorded_effect_uses: 0,
  fresh_effect_allowed: true,
  repeated_use_provenance_valid: true,
  historical_fixture_authority_at_effect_projection_allowed: false,
  consumed_crossing_binding_sha256: null,
  revoked_at_epoch: null,
  revocation_reason_code: null,
  status_updated_at_epoch: 1_999_999_995,
};
const targetEffect = {
  target_handle: targetBinding.target_handle,
  record_update: authorizedRecordUpdate,
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
const issuanceReceiptEvidence = {
  evidence_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_RECEIPT_EVIDENCE_TYPE_V2,
  receipt_evidence_phase: 'issuance',
  source: 'canonical-unsigned-receipt-payload-pre-signing',
  authority_grant_contract_sha256: contractSha256,
  authorized_effect_detail_sha256: authorizedEffectDetailSha256,
  receipt_payload_sha256: H.e,
  signed_receipt_sha256: null,
  signature_verified: false,
  delegation_chain_present: true,
  delegation_chain: [],
  issuer_kid: appointment.issuer_kid,
  public_key_sha256: appointment.public_key_sha256,
  issued_at_epoch: 2_000_000_001,
  policy_version: contract.scope.policy_version,
  receipt_action_class: contract.scope.action_class,
  receipt_audit_event_id: contract.scope.receipt_audit_event_id,
  receipt_version: contract.scope.receipt_version,
  receipt_type: contract.scope.receipt_type,
  receipt_domain: contract.scope.receipt_domain,
  receipt_rule: contract.scope.receipt_rule,
  receipt_authorizer: contract.scope.receipt_authorizer,
  receipt_outcome: contract.scope.receipt_outcome,
};
const issuanceDecision = evaluateProtectedRecordsFixtureAuthorityIssuanceV2({
  contract,
  expectedContractSha256: contractSha256,
  sourcePrecondition,
  appointment,
  confirmation,
  authorityStatus,
  scopeEvidence,
  receiptEvidence: issuanceReceiptEvidence,
  authorizedEffectDetail,
  evaluationEpoch: issuanceReceiptEvidence.issued_at_epoch,
  grantPreviouslyConsumed: false,
});
equal('synthetic pure issuance accepted', 'accept', issuanceDecision.decision);
const recognitionRule = {
  deployment_scope: 'protected-records-disposable-runtime-profile',
  accepted_issuers: [{
    kid: appointment.issuer_kid,
    public_key_pem: publicKeyPem,
    status: 'active',
  }],
  accepted_policy_versions: [contract.scope.policy_version],
  accepted_domains: [contract.scope.receipt_domain],
  accepted_tools: [contract.scope.action_class],
  accepted_outcomes: [contract.scope.receipt_outcome],
  max_age_seconds: 120,
  required_audit_event_id: contract.scope.receipt_audit_event_id,
  required_detail_hash: authorizedEffectDetailSha256,
};
const scratch = mkdtempSync(join(tmpdir(), 'zlar-runtime-v2-refusal-'));
try {
  const consumedPath = join(scratch, 'consumed.json');
  const anchorPath = join(scratch, 'anchor.json');
  const witnessPath = join(scratch, 'witness.json');
  const refreshPath = join(scratch, 'authority-status.json');
  writeFileSync(refreshPath, `${JSON.stringify(authorityStatus, null, 2)}\n`);
  const serviceConfig = {
    action_class: 'records.write',
    authorized_record_update: authorizedRecordUpdate,
    authority_grant_appointment: appointment,
    authority_grant_confirmation: confirmation,
    authority_grant_contract: contract,
    authority_grant_expected_contract_sha256: contractSha256,
    authority_grant_issuance_decision: issuanceDecision,
    authority_grant_status: authorityStatus,
    authority_grant_status_refresh_path: refreshPath,
    authority_source_precondition: sourcePrecondition,
    consumed_grant_store_anchor_path: anchorPath,
    consumed_grant_store_witness_path: witnessPath,
    consumed_grants_path: consumedPath,
    profile_id: 'protected-records-disposable-runtime-profile',
    recognition_rule: recognitionRule,
    target_binding: targetBinding,
  };
  refuses(
    'caller-supplied v2 consequence time refused at config boundary',
    () => assertProtectedRecordsRuntimeServiceConfigV2({
      ...serviceConfig,
      now_epoch: 2_000_000_002,
    }),
    'unexpected fields',
  );
  equal('clock refusal created no consumed store', false, existsSync(consumedPath));
  equal('clock refusal created no anchor', false, existsSync(anchorPath));
  equal('clock refusal created no witness', false, existsSync(witnessPath));
  const callerClockConfigPath = join(scratch, 'caller-clock-config.json');
  writeFileSync(
    callerClockConfigPath,
    `${JSON.stringify({ ...serviceConfig, now_epoch: 2_000_000_002 })}\n`,
  );
  const callerClockCliRun = spawnSync(
    process.execPath,
    [
      fileURLToPath(
        new URL('../bin/zlar-protected-records-runtime-service', import.meta.url),
      ),
      '--config',
      callerClockConfigPath,
    ],
    {
      cwd: fileURLToPath(new URL('..', import.meta.url)),
      encoding: 'utf8',
      input: `${JSON.stringify({
        request_mode: 'recognized_runtime_write',
        runtime_profile_id: 'protected-records-disposable-runtime-profile',
        target_handle: targetBinding.target_handle,
        record_update: authorizedRecordUpdate,
      })}\n`,
    },
  );
  equal('CLI caller clock refusal exits nonzero', 1, callerClockCliRun.status);
  equal('CLI caller clock refusal emits no result', '', callerClockCliRun.stdout);
  ok(
    'retired general CLI refuses all direct execution',
    callerClockCliRun.stderr.includes(
      'legacy_runtime_v1_direct_entry_surface_retired',
    ),
  );
  equal('CLI clock refusal created no consumed store', false, existsSync(consumedPath));
  equal('CLI clock refusal created no anchor', false, existsSync(anchorPath));
  equal('CLI clock refusal created no witness', false, existsSync(witnessPath));
  const directV2ConfigPath = join(scratch, 'direct-v2-config.json');
  writeFileSync(directV2ConfigPath, `${JSON.stringify(serviceConfig)}\n`);
  const directV2Run = spawnSync(
    process.execPath,
    [
      fileURLToPath(
        new URL('../bin/zlar-protected-records-runtime-service', import.meta.url),
      ),
      '--config',
      directV2ConfigPath,
    ],
    { encoding: 'utf8', input: '' },
  );
  equal('otherwise valid direct v2 config exits nonzero', 1, directV2Run.status);
  equal('otherwise valid direct v2 config emits no result', '', directV2Run.stdout);
  ok(
    'otherwise valid direct v2 config names retired direct route',
    directV2Run.stderr.includes(
      'legacy_runtime_v1_direct_entry_surface_retired',
    ),
  );
  equal('direct v2 refusal created no consumed store', false, existsSync(consumedPath));
  equal('direct v2 refusal created no anchor', false, existsSync(anchorPath));
  equal('direct v2 refusal created no witness', false, existsSync(witnessPath));
  const mismatchedContract = createProtectedRecordsFixtureAuthorityGrantContractV2({
    authorizationRecordId: 'schema-only-mismatched-c0-refusal',
    implementationBinding: {
      ...protectedRecordsFixtureAuthorityImplementationBindingFromSourcePreconditionV2(
        sourcePrecondition,
      ),
      source_commit_oid: '2'.repeat(40),
    },
    scope: scopeEvidence.scope,
    validFromEpoch: contract.time_policy.valid_from_epoch,
    expiresAtEpoch: contract.time_policy.expires_at_epoch,
  });
  refuses(
    'C0 implementation mismatch refuses at config boundary',
    () => assertProtectedRecordsRuntimeServiceConfigV2({
      ...serviceConfig,
      authority_grant_contract: mismatchedContract,
      authority_grant_expected_contract_sha256:
        protectedRecordsFixtureAuthorityGrantContractSha256V2(
          mismatchedContract,
        ),
    }),
    'source implementation binding drifted',
  );
  equal('C0 mismatch created no consumed store', false, existsSync(consumedPath));
  equal('C0 mismatch created no anchor', false, existsSync(anchorPath));
  equal('C0 mismatch created no witness', false, existsSync(witnessPath));

  const service = createProtectedRecordsRuntimeServiceV2(serviceConfig);
  const callerTimeRequest = service.applyRequest({
    request_mode: 'recognized_runtime_write',
    runtime_profile_id: 'protected-records-disposable-runtime-profile',
    target_handle: targetBinding.target_handle,
    record_update: authorizedRecordUpdate,
    now_epoch: 2_000_000_002,
  });
  equal(
    'request-supplied consequence time refused',
    'agent_supplied_authority_material',
    callerTimeRequest.decision.reason_code,
  );
  equal('request clock refusal state delta zero', 0, callerTimeRequest.state_entry_count_delta);
  equal('request clock refusal consumed zero', 0, callerTimeRequest.consumed_authority_grant_count);
  equal('request clock refusal created no store', false, existsSync(consumedPath));
  const originalDateNow = Date.now;
  try {
    Date.now = () => Number.NaN;
    const unavailableClock = service.applyRequest({
      request_mode: 'recognized_runtime_write',
      runtime_profile_id: 'protected-records-disposable-runtime-profile',
      target_handle: targetBinding.target_handle,
      record_update: authorizedRecordUpdate,
    });
    equal(
      'invalid runtime clock refuses',
      'authority_clock_unavailable',
      unavailableClock.decision.reason_code,
    );
    equal('invalid clock state delta zero', 0, unavailableClock.state_entry_count_delta);
    equal('invalid clock consumed zero', 0, unavailableClock.consumed_authority_grant_count);
    equal('invalid clock created no store', false, existsSync(consumedPath));
    equal('invalid clock created no anchor', false, existsSync(anchorPath));
    equal('invalid clock created no witness', false, existsSync(witnessPath));
  } finally {
    Date.now = originalDateNow;
  }
  const refusal = service.applyRequest({
    request_mode: 'forbidden_request_authority_material',
    runtime_profile_id: 'protected-records-disposable-runtime-profile',
    target_handle: targetBinding.target_handle,
    record_update: authorizedRecordUpdate,
    authority_grant_status: authorityStatus,
  });
  ok('dynamic forbidden authority result validates', assertProtectedRecordsRuntimeServiceResultV2(refusal));
  equal('dynamic forbidden authority refused', 'refuse', refusal.decision.decision);
  equal('dynamic forbidden authority reason', 'agent_supplied_authority_material', refusal.decision.reason_code);
  equal('dynamic forbidden authority state delta zero', 0, refusal.state_entry_count_delta);
  equal('dynamic forbidden authority did not consume grant', 0, refusal.consumed_authority_grant_count);
  equal('dynamic forbidden authority no consumed store', false, existsSync(consumedPath));
  equal('dynamic forbidden authority no anchor', false, existsSync(anchorPath));
  equal('dynamic forbidden authority no witness', false, existsSync(witnessPath));

  const revokedStatus = {
    ...structuredClone(authorityStatus),
    status: 'revoked',
    status_source: 'source-recorded-fixture-authority-revocation',
    fresh_effect_allowed: false,
    repeated_use_provenance_valid: false,
    revoked_at_epoch: 2_000_000_003,
    revocation_reason_code: 'fixture_owner_revoked_before_effect',
    status_updated_at_epoch: 2_000_000_003,
  };
  writeFileSync(refreshPath, `${JSON.stringify(revokedStatus, null, 2)}\n`);
  const revocationInspection = service.inspectAuthorityStatusRefresh();
  equal('post-construction revocation inspection refuses', 'refuse', revocationInspection.decision);
  equal('post-construction revocation reason', 'authority_status_not_active', revocationInspection.reason_code);
  equal('post-construction refreshed status is revoked', 'revoked', revocationInspection.authority_status.status);
  equal('post-construction refresh executes no consequence', false, revocationInspection.consequence_executed);
  equal('post-construction refresh mutates no consumed store', false, revocationInspection.consumed_store_mutated);
  equal('post-construction refresh mutates no runtime state', false, revocationInspection.runtime_state_mutated);
  equal('post-construction revocation no consumed store', false, existsSync(consumedPath));
  equal('post-construction revocation no anchor', false, existsSync(anchorPath));
  equal('post-construction revocation no witness', false, existsSync(witnessPath));
  equal('post-construction revocation leaves no lock', false, existsSync(`${consumedPath}.lock`));
  const pureRuntimeContext = createProtectedRecordsRuntimeAuthorityContextV2({
    actionClass: serviceConfig.action_class,
    authorizedRecordUpdate: serviceConfig.authorized_record_update,
    authorityGrantAppointment: serviceConfig.authority_grant_appointment,
    authorityGrantConfirmation: serviceConfig.authority_grant_confirmation,
    authorityGrantContract: serviceConfig.authority_grant_contract,
    authorityGrantExpectedContractSha256:
      serviceConfig.authority_grant_expected_contract_sha256,
    authorityGrantIssuanceDecision:
      serviceConfig.authority_grant_issuance_decision,
    authorityGrantStatus: serviceConfig.authority_grant_status,
    profileId: serviceConfig.profile_id,
    recognitionRule: serviceConfig.recognition_rule,
    sourcePrecondition: serviceConfig.authority_source_precondition,
    targetBinding: serviceConfig.target_binding,
  });
  const pureRevokedEffect = evaluateProtectedRecordsRuntimeAuthorityEffectV2({
    context: pureRuntimeContext,
    evaluationEpoch: 2_000_000_004,
    grantPreviouslyConsumed: false,
    authorityStatusAtEffect: revocationInspection.authority_status,
    receiptEvidence: {
      ...structuredClone(issuanceReceiptEvidence),
      receipt_evidence_phase: 'effect',
      source: 'independent-signed-receipt-verification',
      signed_receipt_sha256: H.f,
      signature_verified: true,
    },
  });
  equal('pure refreshed revocation effect gate refuses', false, pureRevokedEffect.accepted);
  ok(
    'pure refreshed revocation names inactive status',
    pureRevokedEffect.effectDecision.reasons.some(
      (reason) => reason.code === 'authority_status_not_active',
    ),
  );
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log('\n-- static consequence-boundary ordering and no side-door exports --');
const runtimeSource = readFileSync(
  new URL('../lib/protected-records-runtime-profile.mjs', import.meta.url),
  'utf8',
);
const adapterSource = readFileSync(
  new URL('../lib/protected-records-runtime-authority-v2.mjs', import.meta.url),
  'utf8',
);
const cliSource = readFileSync(
  new URL('../bin/zlar-protected-records-runtime-service', import.meta.url),
  'utf8',
);
const internalV2ChildSource = readFileSync(
  new URL(
    '../lib/protected-records-replacement-runtime-child-v2.mjs',
    import.meta.url,
  ),
  'utf8',
);
const v2Start = runtimeSource.indexOf(
  'export function createProtectedRecordsRuntimeServiceV2',
);
const v2End = runtimeSource.indexOf(
  'export function assertProtectedRecordsRuntimeServiceResultV2',
  v2Start,
);
const v2Source = runtimeSource.slice(v2Start, v2End);
const v2ConfigStart = runtimeSource.indexOf(
  'export function assertProtectedRecordsRuntimeServiceConfigV2',
);
const v2ConfigEnd = runtimeSource.indexOf(
  'function protectedRecordsRuntimeServiceResultV2Base',
  v2ConfigStart,
);
const v2ConfigSource = runtimeSource.slice(v2ConfigStart, v2ConfigEnd);
for (const marker of [
  'authority_grant_confirmation',
  'authority_grant_expected_contract_sha256',
  'authority_grant_status',
  'authority_grant_status_refresh_path',
  'authority_source_precondition',
]) {
  ok(`v2 config contains ${marker}`, v2Source.includes(marker));
}
for (const marker of [
  "'authority_grant_confirmation'",
  "'authority_grant_expected_contract_sha256'",
  "'authority_grant_status'",
  "'authority_grant_status_refresh_path'",
  "'authority_source_precondition'",
]) {
  ok(`request stream forbids ${marker}`, runtimeSource.includes(marker));
}
const verifyIndex = v2Source.indexOf('verifyReceiptV1(');
const effectEvidenceIndex = v2Source.indexOf(
  'createProtectedRecordsRuntimeEffectReceiptEvidenceV2(',
);
const lockIndex = v2Source.indexOf('withConsumedStoreLock(');
const statusRefreshIndex = v2Source.indexOf(
  'readProtectedRecordsRuntimeAuthorityStatusRefreshV2(',
);
const effectGateIndex = v2Source.indexOf(
  'evaluateProtectedRecordsRuntimeAuthorityEffectV2(',
);
const storeCommitIndex = v2Source.indexOf('writeConsumedStoreState(');
const stateAppendIndex = v2Source.indexOf('stateEntries.push(stateEntry)');
const lockedClockIndex = v2Source.indexOf(
  'protectedRecordsRuntimeConsequenceEpochV2()',
  lockIndex,
);
const effectClockIndex = v2Source.indexOf(
  'protectedRecordsRuntimeConsequenceEpochV2()',
  lockedClockIndex + 1,
);
const lockedReplayCheckIndex = v2Source.indexOf(
  'const helperDecision = evaluateProtectedRecordsBoardingDecision',
  lockIndex,
);
ok('independent receipt verification is present', verifyIndex >= 0);
equal(
  'v2 config has no caller-supplied consequence epoch',
  false,
  v2ConfigSource.includes("'now_epoch'"),
);
equal(
  'v2 runtime never reads serviceConfig.now_epoch',
  false,
  v2Source.includes('serviceConfig.now_epoch'),
);
ok(
  'v2 runtime reads process time at recognition and effect boundaries',
  (v2Source.match(/protectedRecordsRuntimeConsequenceEpochV2\(\)/g) || [])
    .length === 3,
);
ok(
  'v2 effect gate binds runtime evaluation epoch',
  adapterSource.includes('authority_effect_evaluation_epoch: evaluationEpoch'),
);
ok(
  'v2 effect gate refuses caller clock authority',
  adapterSource.includes('caller_supplied_consequence_time_accepted: false'),
);
ok('verified evidence follows verification', verifyIndex < effectEvidenceIndex);
ok('one launcher lock precedes status refresh', lockIndex < statusRefreshIndex);
ok('one launcher lock precedes locked recognition clock', lockIndex < lockedClockIndex);
ok('locked recognition clock precedes replay check', lockedClockIndex < lockedReplayCheckIndex);
ok('status refresh immediately precedes effect gate', statusRefreshIndex < effectGateIndex);
ok('status refresh precedes final consequence clock', statusRefreshIndex < effectClockIndex);
ok('final consequence clock precedes effect gate', effectClockIndex < effectGateIndex);
ok('effect gate precedes one-use store commit', effectGateIndex < storeCommitIndex);
ok('one-use store commit precedes state append', storeCommitIndex < stateAppendIndex);
equal('raw store reader is not exported', false, /export function readConsumedStore/.test(runtimeSource));
equal('raw store writer is not exported', false, /export function writeConsumedStore/.test(runtimeSource));
equal('raw lock helper is not exported', false, /export function withConsumedStoreLock/.test(runtimeSource));
equal('v2 adapter does not generate keys', false, /generateKeyPair|privateKey|signReceipt/.test(adapterSource));
ok('recognition rule binds exact effect detail', adapterSource.includes('required_detail_hash !== authorizedEffectDetailSha256'));
ok('recognition rule binds exact audit event', adapterSource.includes('receipt_audit_event_id'));
ok('verified receipt projects delegation presence', adapterSource.includes('delegation_chain_present: delegationChainPresent'));
ok('verified receipt projects delegation chain', adapterSource.includes('delegation_chain: delegationChain'));
ok(
  'general CLI is an unconditional import-free retirement surface',
  cliSource.includes('legacy_runtime_v1_direct_entry_surface_retired') &&
    !/^import\s/m.test(cliSource) &&
    !cliSource.includes('process.argv') &&
    !cliSource.includes('process.env') &&
    !cliSource.includes('readFileSync') &&
    !cliSource.includes('createProtectedRecordsRuntimeService'),
);
equal(
  'general CLI cannot construct v2 runtime service',
  false,
  cliSource.includes('createProtectedRecordsRuntimeServiceV2'),
);
ok(
  'internal v2 child requires the crossing routing marker',
  internalV2ChildSource.includes('ZLAR_REPLACEMENT_INTERNAL_CHILD') &&
    internalV2ChildSource.includes('exact-source-single-attempt-v2'),
);
ok(
  'internal v2 child requires exact source and one request',
  internalV2ChildSource.includes('exactSourceState(') &&
    internalV2ChildSource.includes('lines.length !== 1') &&
    internalV2ChildSource.includes('assertProtectedRecordsRuntimeServiceResultV2'),
);
const v1ConfigStart = runtimeSource.indexOf(
  'export function assertProtectedRecordsRuntimeServiceConfig(config)',
);
const v1ConfigEnd = runtimeSource.indexOf(
  'export function createProtectedRecordsRuntimeService',
  v1ConfigStart,
);
const v1ConfigSource = runtimeSource.slice(v1ConfigStart, v1ConfigEnd);
ok('v1 hermetic config still requires now_epoch', v1ConfigSource.includes("'now_epoch'"));
ok('v1 hermetic config still validates numeric now_epoch', v1ConfigSource.includes('config.now_epoch'));
ok('accepted result has strict artifact-input mapper', runtimeSource.includes('protectedRecordsReplacementCrossingInputsFromRuntimeServiceResultV2'));
ok('accepted result has strict source-binding mapper', runtimeSource.includes('protectedRecordsReplacementSourceBindingFromRuntimeServiceResultV2'));
const crossingMapperStart = runtimeSource.indexOf(
  'export function protectedRecordsReplacementCrossingInputsFromRuntimeServiceResultV2',
);
const sourceMapperStart = runtimeSource.indexOf(
  'export function protectedRecordsReplacementSourceBindingFromRuntimeServiceResultV2',
);
const crossingMapperSource = runtimeSource.slice(crossingMapperStart, sourceMapperStart);
const sourceMapperSource = runtimeSource.slice(
  sourceMapperStart,
  runtimeSource.indexOf('export function assertProtectedRecordsRuntimeServiceResult(', sourceMapperStart),
);
const forbiddenMapperCapability =
  /createProtectedRecordsRuntimeServiceV2|applyRequest\(|withConsumedStoreLock\(|writeConsumedStoreState\(|stateEntries\.push/;
equal(
  'crossing-input mapper cannot execute or mutate',
  false,
  forbiddenMapperCapability.test(crossingMapperSource),
);
equal(
  'source-binding mapper cannot execute or mutate',
  false,
  forbiddenMapperCapability.test(sourceMapperSource),
);
for (const key of [
  'activationConfirmationArtifactBodySha256',
  'authorityGrantContractSha256',
  'authorityStatusAtEffectArtifactBodySha256',
  'authorizedEffectDetailSha256',
  'effectDecisionSha256',
  'executionTraceSha256',
  'installedProfilePreflightArtifactBodySha256',
  'issuerAppointmentArtifactBodySha256',
  'issuanceDecisionSha256',
  'receiptEnvelopeBodySha256',
  'recognitionContractSha256',
  'recordUpdateSha256',
  'runtimeProfileSha256',
  'runtimeTransitionSha256',
  'sourcePreconditionArtifactBodySha256',
  'targetBindingSha256',
  'targetContractSha256',
  'targetEffectSha256',
]) {
  ok(`crossing mapper emits ${key}`, crossingMapperSource.includes(`${key}:`));
}
for (const key of [
  'repository_id',
  'git_object_format',
  'source_commit_oid',
  'service_artifact_schema_contract_sha256',
  'terminal_artifact_schema_contract_sha256',
  'no_reexecution_call_graph_sha256',
  'installed_profile_preflight_artifact_body_sha256',
  'source_precondition_artifact_body_sha256',
]) {
  ok(`source mapper emits ${key}`, sourceMapperSource.includes(`${key}:`));
}

console.log(`\nprotected records runtime authority v2: ${assertions}/${assertions} assertions passed`);
