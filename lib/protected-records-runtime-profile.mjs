import { generateKeyPairSync } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { canonicalize } from './canonicalize.mjs';
import {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed,
} from './protected-records-fixture-authority-status.mjs';
import {
  createReceiptV1FromEvent,
  decodePayloadV1,
  pubkeyFingerprint,
  sha256hex,
  signReceiptV1,
  verifyReceiptV1,
} from './receipt.mjs';
import {
  PROTECTED_RECORDS_BOARDING_DECISION_HELPER,
  createProtectedRecordsBoardingDecisionState,
  evaluateProtectedRecordsBoardingDecision,
} from './protected-records-boarding-decision.mjs';
import {
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_EVALUATION_EPOCH,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_EXPIRES_AT_EPOCH,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_VALID_FROM_EPOCH,
  PROTECTED_RECORDS_FIXTURE_AUTHORIZED_RECORD_UPDATE,
  assertProtectedRecordsFixtureAuthorityGrantAppointment,
  assertProtectedRecordsFixtureAuthorityGrantContract,
  assertProtectedRecordsFixtureAuthorityGrantDecision,
  createProtectedRecordsFixtureAuthorityGrantAppointment,
  createProtectedRecordsFixtureAuthorityGrantContract,
  evaluateProtectedRecordsFixtureAuthorityGrantEffect,
  evaluateProtectedRecordsFixtureAuthorityGrantIssuance,
  protectedRecordsAuthorizedEffectDetail,
  protectedRecordsAuthorizedEffectDetailSha256,
  protectedRecordsFixtureAuthorityGrantContractSha256,
} from './protected-records-fixture-authority-grant.mjs';
import {
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_CLOCK_SOURCE_V2,
  assertProtectedRecordsAuthorizedEffectDetailV2,
  assertProtectedRecordsFixtureAuthorityAppointmentV2,
  assertProtectedRecordsFixtureAuthorityDecisionV2,
  assertProtectedRecordsFixtureAuthorityExactConfirmationV2,
  assertProtectedRecordsFixtureAuthorityGrantContractV2,
  assertProtectedRecordsFixtureAuthoritySourcePreconditionV2,
  assertProtectedRecordsFixtureAuthorityStatusV2,
  isProtectedRecordsFixtureAuthorityGrantContractV2,
  protectedRecordsAuthorizedEffectDetailSha256V2,
  protectedRecordsFixtureAuthorityAppointmentSha256V2,
  protectedRecordsFixtureAuthorityDecisionSha256V2,
  protectedRecordsFixtureAuthorityExactConfirmationSha256V2,
  protectedRecordsFixtureAuthorityIssuerBindingSha256V2,
  protectedRecordsFixtureAuthoritySourcePreconditionBodySha256V2,
  protectedRecordsFixtureAuthorityStatusSha256V2,
} from './protected-records-fixture-authority-grant-v2.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_SERVICE_RESULT_TYPE_V2,
  PROTECTED_RECORDS_RUNTIME_MINIMUM_EFFECT_MARGIN_SECONDS_V2,
  PROTECTED_RECORDS_RUNTIME_TRANSITION_BINDING_TYPE_V2,
  assertProtectedRecordsRuntimeEffectGateBindingV2,
  assertProtectedRecordsRuntimeExecutionTraceV2,
  assertProtectedRecordsRuntimeTransitionBindingV2,
  createProtectedRecordsRuntimeAuthorityContextV2,
  createProtectedRecordsRuntimeEffectReceiptEvidenceV2,
  createProtectedRecordsRuntimeExecutionTraceV2,
  evaluateProtectedRecordsRuntimeClockTransitionV2,
  evaluateProtectedRecordsRuntimeEffectMarginV2,
  evaluateProtectedRecordsRuntimeAuthorityEffectV2,
  protectedRecordsRuntimeAuthorityDecisionV2,
  protectedRecordsRuntimeEffectGateBindingSha256V2,
  protectedRecordsRuntimeExecutionTraceSha256V2,
  protectedRecordsRuntimeTransitionBindingSha256V2,
} from './protected-records-runtime-authority-v2.mjs';

export const PROTECTED_RECORDS_RUNTIME_SERVICE_RESULT_TYPE =
  'protected-records-runtime-service-result-v1';
export const PROTECTED_RECORDS_RUNTIME_PROFILE_PROOF_TYPE =
  'protected-records-runtime-profile-proof-v1';
export const PROTECTED_RECORDS_RUNTIME_PROFILE_ID =
  'protected-records-disposable-runtime-profile';
export const PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_TYPE =
  'zlar-protected-records-runtime-consumed-authority-grants-v1';
export const PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_ANCHOR_TYPE =
  'zlar-protected-records-runtime-consumed-authority-grant-store-anchor-v1';
export const PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_WITNESS_TYPE =
  'zlar-protected-records-runtime-consumed-authority-grant-store-witness-v1';
export const PROTECTED_RECORDS_RUNTIME_STATE_APPEND_FAILURE_MODE =
  'fail_after_consumed_store_commit';
export const PROTECTED_RECORDS_RUNTIME_GRANT_STORE_WITNESS_COMMIT_FAILURE_MODE =
  'fail_after_grant_store_and_anchor_commit_before_witness';
export const PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH =
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_EVALUATION_EPOCH;
export const PROTECTED_RECORDS_CONSEQUENCE_PATH =
  'protected-records.installed-runtime-profile.terminal-chain.records.write';
export const PROTECTED_RECORDS_TARGET_KIND =
  'process-private-recognized-effect-state';
export const PROTECTED_RECORDS_TARGET_SCOPE = 'logical-fixture';
export const PROTECTED_RECORDS_TARGET_HANDLE_GRAMMAR =
  '^zlar-target:v1:logical-fixture:[a-f0-9]{64}$';
export const PROTECTED_RECORDS_TARGET_HANDLE =
  'zlar-target:v1:logical-fixture:0ee8bcc85701f8ba374af28393d517d3e3e823d9e8d740d256ae7f7304f7f8a2';
export const PROTECTED_RECORDS_AUTHORIZED_SOURCE_PROFILE_SHA256 =
  'e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469';
export const PROTECTED_RECORDS_AUTHORIZED_SOURCE_RECOGNITION_CONTRACT_SHA256 =
  '1ce1351937c4eef665f13bd53696732af0cf05d891600ce5fd6e0655b97cc045';
export const PROTECTED_RECORDS_AUTHORIZED_SOURCE_TARGET_CONTRACT_SHA256 =
  'a771d114340060f269f78f15016c2975983ead7534a499bee3f5912fa05f985b';
export const PROTECTED_RECORDS_AUTHORIZED_SOURCE_PREFLIGHT_BODY_SHA256 =
  '2b5427aec78c63cc9768bb25ed8cdde316d4b8e3f07dac11c80baa54e1b71bec';
export const PROTECTED_RECORDS_RUNTIME_TARGET_BINDING_TYPE =
  'zlar-protected-records-runtime-target-binding-v1';
export const PROTECTED_RECORDS_TARGET_DESCRIPTOR = Object.freeze({
  descriptor_type: 'zlar-protected-records-target-descriptor-v1',
  consequence_path: PROTECTED_RECORDS_CONSEQUENCE_PATH,
  target_kind: PROTECTED_RECORDS_TARGET_KIND,
  target_scope: PROTECTED_RECORDS_TARGET_SCOPE,
  target_instance_scope: 'logical-fixture-not-per-run',
});

export const REQUIRED_RUNTIME_PROFILE_CASES = Object.freeze([
  'recognized_runtime_write_first_request',
  'replay_runtime_write_refused_same_service_process',
  'replay_runtime_write_refused_after_service_restart',
  'invalid_consumed_store_refused_before_runtime_mutation',
  'duplicate_consumed_store_refused_before_runtime_mutation',
  'locked_consumed_store_refused_before_runtime_mutation',
  'invalid_consumed_store_anchor_refused_before_runtime_mutation',
  'valid_consumed_store_rollback_refused_before_runtime_mutation',
  'consumed_store_deletion_refused_before_runtime_mutation',
  'valid_consumed_store_replacement_refused_before_runtime_mutation',
  'runtime_state_append_failed_after_consumed_store_commit',
  'witness_commit_failed_after_authority_grant_store_commit',
  'store_and_anchor_joint_rollback_refused_against_witness_before_runtime_mutation',
  'missing_receipt_refused_before_runtime_mutation',
  'invalid_receipt_refused_before_runtime_mutation',
  'unknown_issuer_refused_before_runtime_mutation',
  'retired_issuer_refused_before_runtime_mutation',
  'missing_issuer_status_refused_before_runtime_mutation',
  'missing_authority_grant_appointment_refused_before_consumption',
  'mismatched_authority_grant_appointment_refused_before_consumption',
  'revoked_authority_grant_refused_before_consumption',
  'expired_authority_grant_refused_before_consumption',
  'wrong_policy_refused_before_runtime_mutation',
  'wrong_domain_refused_before_runtime_mutation',
  'wrong_tool_refused_before_runtime_mutation',
  'wrong_runtime_profile_id_refused_before_runtime_mutation',
  'wrong_audit_event_refused_before_runtime_mutation',
  'wrong_detail_refused_before_runtime_mutation',
  'non_boarding_outcome_refused_before_runtime_mutation',
  'stale_receipt_refused_before_runtime_mutation',
  'direct_api_without_receipt_refused_before_runtime_mutation',
  'direct_api_with_receipt_refused_before_runtime_mutation',
  'agent_supplied_state_path_refused_before_runtime_mutation',
  'agent_supplied_consumed_grants_path_refused_before_runtime_mutation',
  'agent_supplied_consumed_grant_store_anchor_path_refused_before_runtime_mutation',
  'agent_supplied_fixture_mode_refused_before_runtime_mutation',
  'agent_supplied_recognition_rule_refused_before_runtime_mutation',
  'agent_supplied_authority_grant_refused_before_runtime_mutation',
  'unsupported_request_field_refused_before_runtime_mutation',
]);

export const SAFE_CLAIM_CEILING =
  'ZLAR can run a local disposable protected-records runtime profile where a child service process owns process-private state, a launcher-owned fixture authority grant is checked after signed-receipt recognition and before effect, a lockfile-guarded persistent grant store enforces one use per authority-grant contract SHA across service restarts, and records.write mutates only after recognition and exact fixture-grant acceptance.';

export const NON_CLAIMS = Object.freeze([
  'This proof is a local disposable runtime-profile proof, not production deployment.',
  'This proof does not inspect a live records system.',
  'This proof does not install a persistent runtime profile.',
  'This proof does not prove a production records service.',
  'This proof does not prove production-grade durable storage, stale-lock recovery, multi-host coordination, or tamper resistance for the consumed-authority-grant store or local anchor.',
  'This proof does not prove exactly-once effect semantics; a crash after authority-grant consumption and before runtime-state mutation can burn the one-use grant.',
  'This proof does not prove an atomic all-or-nothing commit across the consumed-authority-grant store, local anchor, and local witness; a metadata write failure after grant-store commit can burn the one-use grant before runtime-state mutation.',
  'This proof does not detect rollback, deletion, or replacement when the consumed-authority-grant store, local anchor, and local witness are moved together without stronger custody or an external witness.',
  'This proof does not close host process, memory, debugger, or operator filesystem side doors.',
  'This proof does not close host filesystem path-replacement or symlink time-of-check/time-of-use side doors after launcher config validation.',
  'This proof does not prove live MCP coverage, live approval-channel health, or current-machine governance.',
  'This proof does not prove external attestation, enterprise readiness, production authority, or sovereign recognition.',
  'This proof does not prove coverage of unrouted records paths.',
]);

const ZLAR_BIN = fileURLToPath(new URL('../bin/zlar', import.meta.url));

const FORBIDDEN_AGENT_AUTHORITY_FIELDS = Object.freeze([
  'authorityGrantAppointment',
  'authorityGrantConfirmation',
  'authorityGrantContract',
  'authorityGrantExpectedContractSha256',
  'authorityGrantIssuanceDecision',
  'authorityGrantStatus',
  'authorityGrantStatusRefreshPath',
  'authoritySourcePrecondition',
  'authorizedRecordUpdate',
  'authority_grant',
  'authority_grant_appointment',
  'authority_grant_confirmation',
  'authority_grant_contract',
  'authority_grant_expected_contract_sha256',
  'authority_grant_issuance_decision',
  'authority_grant_status',
  'authority_grant_status_refresh_path',
  'authority_source_precondition',
  'authorized_record_update',
  'consumedGrantStoreAnchorPath',
  'consumedGrantStoreCommitFailureMode',
  'consumedGrantStoreWitnessPath',
  'consumedGrantsPath',
  'consumed_grant_store_anchor_path',
  'consumed_grant_store_commit_failure_mode',
  'consumed_grant_store_witness_path',
  'consumed_grants_path',
  'fixture_mode',
  'installedProfileState',
  'installed_profile_state',
  'profile',
  'recognitionRule',
  'recognition_rule',
  'runtimeConfig',
  'runtimeProfile',
  'runtime_config',
  'runtime_profile',
  'statePath',
  'state_path',
]);

const ALLOWED_REQUEST_FIELDS = Object.freeze([
  'direct_api_write',
  'receipt',
  'record_update',
  'request_mode',
  'runtime_profile_id',
  'target_handle',
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
  for (const item of expected) {
    if (!value.includes(item)) {
      throw new Error(`${label} missing ${item}`);
    }
  }
  return true;
}

function stringOrNull(value) {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function numberOrNull(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

export function assertProtectedRecordsTargetHandle(targetHandle) {
  if (
    typeof targetHandle !== 'string' ||
    !(new RegExp(PROTECTED_RECORDS_TARGET_HANDLE_GRAMMAR)).test(targetHandle)
  ) {
    throw new Error('Protected records target handle is malformed');
  }
  return true;
}

export function protectedRecordsTargetEffect({ targetHandle, recordUpdate }) {
  assertProtectedRecordsTargetHandle(targetHandle);
  return {
    target_handle: targetHandle,
    record_update: requireObject('Protected records target-bound record update', recordUpdate),
  };
}

function assertSha256(label, value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`${label} must be SHA-256 hex`);
  }
}

export function assertProtectedRecordsRuntimeTargetBinding(targetBinding, config = null) {
  assertExactKeys('Protected records runtime target binding', targetBinding, [
    'binding_type',
    'consequence_path',
    'mutation_authoritative_route',
    'profile_wide_target_authority_proven',
    'request_target_semantics',
    'rightful_issuance_proven',
    'source_action_class',
    'source_preflight_body_sha256',
    'source_profile_id',
    'source_profile_sha256',
    'source_recognition_contract_sha256',
    'source_runtime_profile_id',
    'source_target_contract_sha256',
    'target_handle',
    'target_descriptor',
    'target_descriptor_sha256',
    'target_handle_grammar',
    'target_handle_source',
    'target_kind',
    'target_instance_scope',
    'target_scope',
  ]);
  const descriptorSha256 = sha256hex(canonicalize(targetBinding.target_descriptor));
  const expectedHandle = `zlar-target:v1:logical-fixture:${descriptorSha256}`;
  if (
    targetBinding.binding_type !== PROTECTED_RECORDS_RUNTIME_TARGET_BINDING_TYPE ||
    targetBinding.consequence_path !== PROTECTED_RECORDS_CONSEQUENCE_PATH ||
    targetBinding.target_kind !== PROTECTED_RECORDS_TARGET_KIND ||
    targetBinding.target_scope !== PROTECTED_RECORDS_TARGET_SCOPE ||
    targetBinding.target_instance_scope !== 'logical-fixture-not-per-run' ||
    canonicalize(targetBinding.target_descriptor) !== canonicalize(PROTECTED_RECORDS_TARGET_DESCRIPTOR) ||
    targetBinding.target_descriptor_sha256 !== descriptorSha256 ||
    targetBinding.target_handle !== expectedHandle ||
    targetBinding.target_handle !== PROTECTED_RECORDS_TARGET_HANDLE ||
    targetBinding.target_handle_grammar !== PROTECTED_RECORDS_TARGET_HANDLE_GRAMMAR ||
    targetBinding.target_handle_source !== 'launcher-owned-service-config' ||
    targetBinding.request_target_semantics !== 'assertion-only' ||
    targetBinding.mutation_authoritative_route !==
      'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation' ||
    targetBinding.profile_wide_target_authority_proven !== false ||
    targetBinding.rightful_issuance_proven !== false ||
    typeof targetBinding.source_profile_id !== 'string' ||
    !/^[a-z0-9][a-z0-9._-]{2,127}$/.test(targetBinding.source_profile_id)
  ) {
    throw new Error('Protected records runtime target binding contract drifted');
  }
  assertProtectedRecordsTargetHandle(targetBinding.target_handle);
  for (const [label, value] of [
    ['Protected records source profile SHA-256', targetBinding.source_profile_sha256],
    ['Protected records source recognition contract SHA-256', targetBinding.source_recognition_contract_sha256],
    ['Protected records source target contract SHA-256', targetBinding.source_target_contract_sha256],
    ['Protected records source preflight body SHA-256', targetBinding.source_preflight_body_sha256],
  ]) {
    assertSha256(label, value);
  }
  if (
    config &&
    (
      targetBinding.source_runtime_profile_id !== config.profile_id ||
      targetBinding.source_action_class !== config.action_class
    )
  ) {
    throw new Error('Protected records runtime target binding source identity drifted');
  }
  return true;
}

export function createProtectedRecordsRuntimeTargetBinding({
  sourceProfileId = 'protected-records-runtime-fixture-profile',
  sourceRuntimeProfileId = PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  sourceProfileSha256 = PROTECTED_RECORDS_AUTHORIZED_SOURCE_PROFILE_SHA256,
  sourceRecognitionContractSha256 =
    PROTECTED_RECORDS_AUTHORIZED_SOURCE_RECOGNITION_CONTRACT_SHA256,
  sourceTargetContractSha256 =
    PROTECTED_RECORDS_AUTHORIZED_SOURCE_TARGET_CONTRACT_SHA256,
  sourcePreflightBodySha256 =
    PROTECTED_RECORDS_AUTHORIZED_SOURCE_PREFLIGHT_BODY_SHA256,
  sourceActionClass = 'records.write',
} = {}) {
  const targetDescriptor = { ...PROTECTED_RECORDS_TARGET_DESCRIPTOR };
  const binding = {
    binding_type: PROTECTED_RECORDS_RUNTIME_TARGET_BINDING_TYPE,
    consequence_path: PROTECTED_RECORDS_CONSEQUENCE_PATH,
    target_kind: PROTECTED_RECORDS_TARGET_KIND,
    target_scope: PROTECTED_RECORDS_TARGET_SCOPE,
    target_instance_scope: 'logical-fixture-not-per-run',
    target_descriptor: targetDescriptor,
    target_descriptor_sha256: sha256hex(canonicalize(targetDescriptor)),
    target_handle: PROTECTED_RECORDS_TARGET_HANDLE,
    target_handle_grammar: PROTECTED_RECORDS_TARGET_HANDLE_GRAMMAR,
    target_handle_source: 'launcher-owned-service-config',
    request_target_semantics: 'assertion-only',
    source_profile_id: sourceProfileId,
    source_runtime_profile_id: sourceRuntimeProfileId,
    source_profile_sha256: sourceProfileSha256,
    source_action_class: sourceActionClass,
    source_recognition_contract_sha256: sourceRecognitionContractSha256,
    source_target_contract_sha256: sourceTargetContractSha256,
    source_preflight_body_sha256: sourcePreflightBodySha256,
    mutation_authoritative_route:
      'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation',
    profile_wide_target_authority_proven: false,
    rightful_issuance_proven: false,
  };
  assertProtectedRecordsRuntimeTargetBinding(binding, {
    profile_id: sourceRuntimeProfileId,
    action_class: sourceActionClass,
  });
  return binding;
}

class ConsumedStoreError extends Error {
  constructor(reasonCode, message) {
    super(message);
    this.reasonCode = reasonCode;
  }
}

function consumedStoreLockPath(consumedPath) {
  return `${consumedPath}.lock`;
}

function consumedStoreTempPath(consumedPath) {
  return `${consumedPath}.${process.pid}.${Date.now()}.tmp`;
}

function defaultConsumedStoreAnchorPath(consumedPath) {
  return `${consumedPath}.anchor.json`;
}

function defaultConsumedStoreWitnessPath(consumedPath) {
  return `${consumedPath}.witness.json`;
}

function consumedStoreAnchorTempPath(anchorPath) {
  return `${anchorPath}.${process.pid}.${Date.now()}.tmp`;
}

function consumedStoreWitnessTempPath(witnessPath) {
  return `${witnessPath}.${process.pid}.${Date.now()}.tmp`;
}

function launcherPathIdentity(pathValue) {
  const absolute = resolve(pathValue);
  try {
    return realpathSync(absolute);
  } catch {
    try {
      return join(realpathSync(dirname(absolute)), basename(absolute));
    } catch {
      return absolute;
    }
  }
}

function assertDistinctConsumedStorePaths(consumedPath, anchorPath, witnessPath) {
  const candidates = [
    ['consumed_grants_path', consumedPath],
    ['consumed_grant_store_anchor_path', anchorPath],
    ['consumed_grant_store_witness_path', witnessPath],
    ['consumed_grant_store_lock_path', consumedStoreLockPath(consumedPath)],
  ];
  const identities = candidates.map(([label, pathValue]) => [
    label,
    launcherPathIdentity(pathValue),
  ]);
  if (new Set(identities.map(([, identity]) => identity)).size !== identities.length) {
    throw new Error('Protected records runtime consumed grant store, anchor, witness, and lock paths must be distinct');
  }

  const existingFiles = [];
  for (const [label, pathValue] of candidates) {
    try {
      if (lstatSync(pathValue).isSymbolicLink()) {
        throw new Error('Protected records runtime consumed grant store paths cannot be symbolic links');
      }
      const stat = statSync(pathValue);
      existingFiles.push([label, `${stat.dev}:${stat.ino}`]);
    } catch (err) {
      if (String(err?.message).includes('cannot be symbolic links')) throw err;
      // Nonexistent launcher paths are expected before the first fixture transition.
    }
  }
  if (new Set(existingFiles.map(([, identity]) => identity)).size !== existingFiles.length) {
    throw new Error('Protected records runtime consumed grant store paths cannot alias the same existing file');
  }
  return true;
}

function validateGrantContractSha256s(grantContractSha256s) {
  if (
    !Array.isArray(grantContractSha256s) ||
    grantContractSha256s.some((item) => typeof item !== 'string' || !/^[a-f0-9]{64}$/.test(item))
  ) {
    throw new ConsumedStoreError(
      'consumed_store_invalid',
      'Runtime consumed authority-grant store is invalid; refusing before runtime-state mutation.'
    );
  }
  if (new Set(grantContractSha256s).size !== grantContractSha256s.length) {
    throw new ConsumedStoreError(
      'consumed_store_invalid',
      'Runtime consumed authority-grant store contains duplicate grant contract SHA-256 values; refusing before runtime-state mutation.'
    );
  }
  return grantContractSha256s;
}

function normalizedConsumedStore(grantContractSha256s) {
  return {
    store_type: PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_TYPE,
    consumption_identity: 'authority-grant-contract-sha256',
    grant_contract_sha256s: [...validateGrantContractSha256s(grantContractSha256s)],
  };
}

function consumedStoreHash(store) {
  return sha256hex(canonicalize(normalizedConsumedStore(store.grant_contract_sha256s)));
}

function consumedStoreAnchorFor(store) {
  return {
    anchor_type: PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_ANCHOR_TYPE,
    store_type: PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_TYPE,
    consumption_identity: 'authority-grant-contract-sha256',
    store_canonical_sha256: consumedStoreHash(store),
    grant_contract_count: store.grant_contract_sha256s.length,
  };
}

function consumedStoreWitnessFor(store) {
  return {
    witness_type: PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_WITNESS_TYPE,
    store_type: PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_TYPE,
    consumption_identity: 'authority-grant-contract-sha256',
    store_canonical_sha256: consumedStoreHash(store),
    grant_contract_count: store.grant_contract_sha256s.length,
  };
}

function readConsumedStore(consumedPath) {
  if (!existsSync(consumedPath)) {
    return normalizedConsumedStore([]);
  }

  let parsed;
  try {
    parsed = JSON.parse(readFileSync(consumedPath, 'utf8'));
  } catch {
    throw new ConsumedStoreError(
      'consumed_store_invalid',
      'Runtime consumed authority-grant store is invalid; refusing before runtime-state mutation.'
    );
  }

  try {
    assertExactKeys('Runtime consumed authority-grant store', parsed, [
      'consumption_identity',
      'grant_contract_sha256s',
      'store_type',
    ]);
  } catch {
    throw new ConsumedStoreError(
      'consumed_store_invalid',
      'Runtime consumed authority-grant store shape is invalid; refusing before runtime-state mutation.'
    );
  }

  if (
    parsed.store_type !== PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_TYPE ||
    parsed.consumption_identity !== 'authority-grant-contract-sha256'
  ) {
    throw new ConsumedStoreError(
      'consumed_store_invalid',
      'Runtime consumed authority-grant store type is invalid; refusing before runtime-state mutation.'
    );
  }
  const grantContractSha256s = validateGrantContractSha256s(parsed.grant_contract_sha256s);

  return normalizedConsumedStore(grantContractSha256s);
}

function writeConsumedStore(consumedPath, grantContractSha256s) {
  const store = normalizedConsumedStore(grantContractSha256s);
  const tempPath = consumedStoreTempPath(consumedPath);
  const body = `${JSON.stringify(store, null, 2)}\n`;
  let fd = null;
  try {
    fd = openSync(tempPath, 'wx', 0o600);
    writeFileSync(fd, body);
    fsyncSync(fd);
    closeSync(fd);
    fd = null;
    renameSync(tempPath, consumedPath);
    try {
      const dirFd = openSync(dirname(consumedPath), 'r');
      try {
        fsyncSync(dirFd);
      } finally {
        closeSync(dirFd);
      }
    } catch {
      // Directory fsync support varies by platform; the atomic replace remains the proof boundary.
    }
  } catch (err) {
    if (fd !== null) {
      try {
        closeSync(fd);
      } catch {
        // Best effort cleanup before refusing the runtime mutation.
      }
    }
    try {
      unlinkSync(tempPath);
    } catch {
      // Best effort cleanup before refusing the runtime mutation.
    }
    throw err;
  }
}

function readConsumedStoreAnchor(anchorPath) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(anchorPath, 'utf8'));
  } catch {
    throw new ConsumedStoreError(
      'consumed_store_anchor_invalid',
      'Runtime consumed authority-grant store anchor is invalid; refusing before runtime-state mutation.'
    );
  }

  try {
    assertExactKeys('Runtime consumed authority-grant store anchor', parsed, [
      'anchor_type',
      'consumption_identity',
      'grant_contract_count',
      'store_canonical_sha256',
      'store_type',
    ]);
  } catch {
    throw new ConsumedStoreError(
      'consumed_store_anchor_invalid',
      'Runtime consumed authority-grant store anchor shape is invalid; refusing before runtime-state mutation.'
    );
  }

  if (
    parsed.anchor_type !== PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_ANCHOR_TYPE ||
    parsed.store_type !== PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_TYPE ||
    parsed.consumption_identity !== 'authority-grant-contract-sha256' ||
    !Number.isInteger(parsed.grant_contract_count) ||
    parsed.grant_contract_count < 0 ||
    typeof parsed.store_canonical_sha256 !== 'string' ||
    !/^[a-f0-9]{64}$/.test(parsed.store_canonical_sha256)
  ) {
    throw new ConsumedStoreError(
      'consumed_store_anchor_invalid',
      'Runtime consumed authority-grant store anchor is invalid; refusing before runtime-state mutation.'
    );
  }
  return parsed;
}

function assertConsumedStoreAnchorMatches(anchor, store) {
  const expected = consumedStoreAnchorFor(store);
  if (
    anchor.grant_contract_count !== expected.grant_contract_count ||
    anchor.store_canonical_sha256 !== expected.store_canonical_sha256
  ) {
    throw new ConsumedStoreError(
      'consumed_store_rollback_detected',
      'Runtime consumed authority-grant store rollback was detected against the launcher-owned local anchor; refusing before runtime-state mutation.'
    );
  }
  return true;
}

function readConsumedStoreWitness(witnessPath) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(witnessPath, 'utf8'));
  } catch {
    throw new ConsumedStoreError(
      'consumed_store_anchor_invalid',
      'Runtime consumed authority-grant store witness is invalid; refusing before runtime-state mutation.'
    );
  }

  try {
    assertExactKeys('Runtime consumed authority-grant store witness', parsed, [
      'consumption_identity',
      'grant_contract_count',
      'store_canonical_sha256',
      'store_type',
      'witness_type',
    ]);
  } catch {
    throw new ConsumedStoreError(
      'consumed_store_anchor_invalid',
      'Runtime consumed authority-grant store witness shape is invalid; refusing before runtime-state mutation.'
    );
  }

  if (
    parsed.witness_type !== PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_WITNESS_TYPE ||
    parsed.store_type !== PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_TYPE ||
    parsed.consumption_identity !== 'authority-grant-contract-sha256' ||
    !Number.isInteger(parsed.grant_contract_count) ||
    parsed.grant_contract_count < 0 ||
    typeof parsed.store_canonical_sha256 !== 'string' ||
    !/^[a-f0-9]{64}$/.test(parsed.store_canonical_sha256)
  ) {
    throw new ConsumedStoreError(
      'consumed_store_anchor_invalid',
      'Runtime consumed authority-grant store witness is invalid; refusing before runtime-state mutation.'
    );
  }
  return parsed;
}

function assertConsumedStoreWitnessMatches(witness, store) {
  const expected = consumedStoreWitnessFor(store);
  if (
    witness.grant_contract_count !== expected.grant_contract_count ||
    witness.store_canonical_sha256 !== expected.store_canonical_sha256
  ) {
    throw new ConsumedStoreError(
      'consumed_store_rollback_detected',
      'Runtime consumed authority-grant store rollback was detected against the launcher-owned witness; refusing before runtime-state mutation.'
    );
  }
  return true;
}

function readConsumedStoreState(consumedPath, anchorPath, witnessPath = null) {
  const storeExists = existsSync(consumedPath);
  const anchorExists = existsSync(anchorPath);
  const witnessExists = Boolean(witnessPath) && existsSync(witnessPath);
  if (!storeExists && !anchorExists && !witnessExists) {
    return {
      store: normalizedConsumedStore([]),
      anchor_present: false,
      witness_present: false,
    };
  }

  if (witnessPath && storeExists && anchorExists && !witnessExists) {
    throw new ConsumedStoreError(
      'consumed_store_rollback_detected',
      'Runtime consumed authority-grant store witness is missing for an existing store and anchor; refusing before runtime-state mutation.'
    );
  }

  const store = readConsumedStore(consumedPath);
  if (!storeExists || !anchorExists) {
    throw new ConsumedStoreError(
      'consumed_store_rollback_detected',
      'Runtime consumed authority-grant store and local anchor diverged; refusing before runtime-state mutation.'
    );
  }

  const anchor = readConsumedStoreAnchor(anchorPath);
  assertConsumedStoreAnchorMatches(anchor, store);
  if (witnessPath && witnessExists) {
    const witness = readConsumedStoreWitness(witnessPath);
    assertConsumedStoreWitnessMatches(witness, store);
  }
  return {
    store,
    anchor_present: true,
    witness_present: witnessExists,
  };
}

function writeConsumedStoreAnchor(anchorPath, store) {
  const anchor = consumedStoreAnchorFor(store);
  const tempPath = consumedStoreAnchorTempPath(anchorPath);
  const body = `${JSON.stringify(anchor, null, 2)}\n`;
  let fd = null;
  try {
    fd = openSync(tempPath, 'wx', 0o600);
    writeFileSync(fd, body);
    fsyncSync(fd);
    closeSync(fd);
    fd = null;
    renameSync(tempPath, anchorPath);
    try {
      const dirFd = openSync(dirname(anchorPath), 'r');
      try {
        fsyncSync(dirFd);
      } finally {
        closeSync(dirFd);
      }
    } catch {
      // Directory fsync support varies by platform; the local anchor remains the proof boundary.
    }
  } catch (err) {
    if (fd !== null) {
      try {
        closeSync(fd);
      } catch {
        // Best effort cleanup before refusing the runtime mutation.
      }
    }
    try {
      unlinkSync(tempPath);
    } catch {
      // Best effort cleanup before refusing the runtime mutation.
    }
    throw err;
  }
}

function writeConsumedStoreWitness(witnessPath, store) {
  const witness = consumedStoreWitnessFor(store);
  const tempPath = consumedStoreWitnessTempPath(witnessPath);
  const body = `${JSON.stringify(witness, null, 2)}\n`;
  let fd = null;
  try {
    fd = openSync(tempPath, 'wx', 0o600);
    writeFileSync(fd, body);
    fsyncSync(fd);
    closeSync(fd);
    fd = null;
    renameSync(tempPath, witnessPath);
    try {
      const dirFd = openSync(dirname(witnessPath), 'r');
      try {
        fsyncSync(dirFd);
      } finally {
        closeSync(dirFd);
      }
    } catch {
      // Directory fsync support varies by platform; the local witness remains the proof boundary.
    }
  } catch (err) {
    if (fd !== null) {
      try {
        closeSync(fd);
      } catch {
        // Best effort cleanup before refusing the runtime mutation.
      }
    }
    try {
      unlinkSync(tempPath);
    } catch {
      // Best effort cleanup before refusing the runtime mutation.
    }
    throw err;
  }
}

function writeConsumedStoreState(
  consumedPath,
  anchorPath,
  grantContractSha256s,
  witnessPath = null,
  failureMode = null
) {
  const store = normalizedConsumedStore(grantContractSha256s);
  writeConsumedStore(consumedPath, store.grant_contract_sha256s);
  writeConsumedStoreAnchor(anchorPath, store);
  if (
    failureMode ===
    PROTECTED_RECORDS_RUNTIME_GRANT_STORE_WITNESS_COMMIT_FAILURE_MODE
  ) {
    throw new Error('grant-store-witness-commit-failure-proof-fixture');
  }
  if (witnessPath) {
    writeConsumedStoreWitness(witnessPath, store);
  }
  return store;
}

function withConsumedStoreLock(consumedPath, fn) {
  const lockPath = consumedStoreLockPath(consumedPath);
  let lockFd = null;
  let acquired = false;
  try {
    lockFd = openSync(lockPath, 'wx', 0o600);
    acquired = true;
    writeFileSync(lockFd, `${JSON.stringify({
      lock_type: 'zlar-protected-records-runtime-consumed-store-lock-v1',
      created_epoch_ms: Date.now(),
      process_id_present: Number.isInteger(process.pid),
    }, null, 2)}\n`);
    fsyncSync(lockFd);
    closeSync(lockFd);
    lockFd = null;
    return fn();
  } catch (err) {
    if (err?.code === 'EEXIST') {
      throw new ConsumedStoreError(
        'consumed_store_locked',
        'Runtime consumed authority-grant store is locked; refusing before runtime-state mutation.'
      );
    }
    throw err;
  } finally {
    if (lockFd !== null) {
      try {
        closeSync(lockFd);
      } catch {
        // Best effort cleanup before refusing the runtime mutation.
      }
    }
    if (acquired) {
      try {
        unlinkSync(lockPath);
      } catch {
        // Stale lock cleanup failure is outside this local proof boundary.
      }
    }
  }
}

function isoSecondsAgo(nowEpoch, seconds) {
  return new Date((nowEpoch - seconds) * 1000).toISOString();
}

function keyFixture(scratch, label) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  const publicPath = join(scratch, `${label}.pub`);
  writeFileSync(publicPath, publicPem);
  return {
    privatePem,
    publicPem,
    kid: pubkeyFingerprint(publicPath),
  };
}

function eventFixture({
  authorityGrantContract = null,
  nowEpoch,
  recordUpdate,
  targetHandle = PROTECTED_RECORDS_TARGET_HANDLE,
  overrides = {},
}) {
  return {
    id: overrides.id || 'protected-records-runtime-001',
    ts: overrides.ts || isoSecondsAgo(nowEpoch, 5),
    action: overrides.action || 'records.write',
    domain: overrides.domain || 'records',
    detail: overrides.detail || (() => {
      const targetEffect = protectedRecordsTargetEffect({ targetHandle, recordUpdate });
      return authorityGrantContract
        ? protectedRecordsAuthorizedEffectDetail({
            contract: authorityGrantContract,
            targetEffect,
          })
        : targetEffect;
    })(),
    outcome: overrides.outcome || 'allow',
    rule: overrides.rule || 'RRECORDS_ALLOW',
    authorizer: overrides.authorizer || 'policy',
    policy_version: overrides.policy_version || 'recognition-policy-v1',
    prev_hash: overrides.prev_hash || '0'.repeat(64),
  };
}

function signedReceipt({
  authorityGrantContract = null,
  key,
  nowEpoch,
  recordUpdate,
  targetHandle = PROTECTED_RECORDS_TARGET_HANDLE,
  overrides = {},
}) {
  const effectiveAuthorityGrantContract = authorityGrantContract || (() => {
    const recognitionRuleSnapshot = recognitionRule({ trusted: key });
    const targetBinding = createProtectedRecordsRuntimeTargetBinding();
    return fixtureAuthorityConfig({
      trusted: key,
      nowEpoch,
      authorizedRecordUpdate: recordUpdate,
      recognitionRuleSnapshot,
      targetBinding,
    }).contract;
  })();
  return signReceiptV1(
    createReceiptV1FromEvent(eventFixture({
      authorityGrantContract: effectiveAuthorityGrantContract,
      nowEpoch,
      recordUpdate,
      targetHandle,
      overrides,
    })),
    key.privatePem,
    key.kid
  );
}

function recognitionRule({
  trusted,
  status = 'active',
  includeStatus = true,
  includePublicKey = true,
  deploymentScope = 'protected-records-disposable-runtime-profile',
} = {}) {
  const issuer = {
    kid: trusted.kid,
  };
  if (includePublicKey) issuer.public_key_pem = trusted.publicPem;
  if (includeStatus) issuer.status = status;
  return {
    deployment_scope: deploymentScope,
    accepted_issuers: [issuer],
    accepted_policy_versions: ['recognition-policy-v1'],
    accepted_domains: ['records'],
    accepted_tools: ['records.write'],
    accepted_outcomes: ['allow', 'authorized'],
    max_age_seconds: 120,
    required_audit_event_id: 'protected-records-runtime-001',
  };
}

export function createProtectedRecordsRuntimeLauncherScopeEvidence({
  actionClass,
  authorizedRecordUpdate,
  profileId,
  recognitionRuleSnapshot,
  targetBinding,
}) {
  assertProtectedRecordsRuntimeTargetBinding(targetBinding, {
    profile_id: profileId,
    action_class: actionClass,
  });
  requireObject('Protected records runtime launcher recognition semantics', recognitionRuleSnapshot);
  for (const [label, actual, expected] of [
    ['accepted policy versions', recognitionRuleSnapshot.accepted_policy_versions, ['recognition-policy-v1']],
    ['accepted domains', recognitionRuleSnapshot.accepted_domains, ['records']],
    ['accepted tools', recognitionRuleSnapshot.accepted_tools, ['records.write']],
    ['accepted outcomes', recognitionRuleSnapshot.accepted_outcomes, ['allow', 'authorized']],
  ]) {
    if (canonicalize(actual) !== canonicalize(expected)) {
      throw new Error(`Protected records runtime launcher recognition ${label} drifted`);
    }
  }
  const targetEffect = protectedRecordsTargetEffect({
    targetHandle: targetBinding.target_handle,
    recordUpdate: authorizedRecordUpdate,
  });
  return {
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
      launcher_target_binding_sha256: sha256hex(canonicalize(targetBinding)),
      record_update_sha256: sha256hex(canonicalize(authorizedRecordUpdate)),
      target_effect_sha256: sha256hex(canonicalize(targetEffect)),
      profile_id: targetBinding.source_profile_id,
      runtime_profile_id: profileId,
      profile_sha256: targetBinding.source_profile_sha256,
      recognition_contract_sha256: targetBinding.source_recognition_contract_sha256,
      target_contract_sha256: targetBinding.source_target_contract_sha256,
      policy_version: 'recognition-policy-v1',
      receipt_version: 1,
      receipt_type: 'governed-action',
      receipt_domain: 'records',
      receipt_rule: 'RRECORDS_ALLOW',
      receipt_authorizer: 'policy',
      receipt_outcome: 'allow',
    },
  };
}

export function createProtectedRecordsRuntimeFixtureAuthorityGrantContract({
  scopeEvidence,
  validFromEpoch,
  expiresAtEpoch,
} = {}) {
  assertExactKeys('Protected records runtime launcher scope evidence', scopeEvidence, [
    'derived_from_authority_grant_contract',
    'derived_from_request_stream',
    'scope',
    'source',
    'validated_launcher_config',
  ]);
  if (
    scopeEvidence.source !== 'validated-launcher-profile-recognition-target-config' ||
    scopeEvidence.validated_launcher_config !== true ||
    scopeEvidence.derived_from_authority_grant_contract !== false ||
    scopeEvidence.derived_from_request_stream !== false
  ) {
    throw new Error('Protected records runtime launcher scope evidence provenance drifted');
  }
  const scope = scopeEvidence.scope;
  return createProtectedRecordsFixtureAuthorityGrantContract({
    consequencePath: scope.consequence_path,
    actionClass: scope.action_class,
    targetKind: scope.target_kind,
    targetScope: scope.target_scope,
    targetInstanceScope: scope.target_instance_scope,
    targetHandle: scope.target_handle,
    launcherTargetBindingSha256: scope.launcher_target_binding_sha256,
    recordUpdateSha256: scope.record_update_sha256,
    targetEffectSha256: scope.target_effect_sha256,
    profileId: scope.profile_id,
    runtimeProfileId: scope.runtime_profile_id,
    profileSha256: scope.profile_sha256,
    recognitionContractSha256: scope.recognition_contract_sha256,
    targetContractSha256: scope.target_contract_sha256,
    policyVersion: scope.policy_version,
    receiptDomain: scope.receipt_domain,
    receiptRule: scope.receipt_rule,
    receiptAuthorizer: scope.receipt_authorizer,
    receiptOutcome: scope.receipt_outcome,
    validFromEpoch,
    expiresAtEpoch,
  });
}

export function createProtectedRecordsRuntimeAuthorityReceiptEvidence({
  envelope,
  issuerKid,
  issuerStatus,
  payload,
  publicKeySha256,
  source,
  signatureVerified,
  downstreamRecognitionAccepted,
  verifiedSignedPayloadSha256,
}) {
  return {
    source,
    signature_verified: signatureVerified,
    downstream_recognition_accepted: downstreamRecognitionAccepted,
    issuer_kid: issuerKid,
    issuer_status: issuerStatus,
    public_key_sha256: publicKeySha256,
    issued_at_epoch: Math.floor(new Date(payload.ts).getTime() / 1000),
    receipt_version: envelope.v,
    receipt_type: envelope.type,
    audit_event_id: payload.audit_event_id,
    tool: payload.tool,
    domain: payload.domain,
    detail_hash: payload.detail_hash,
    outcome: payload.outcome,
    rule: payload.rule,
    authorizer: payload.authorizer,
    policy_version: payload.policy_version,
    payload,
    verified_signed_payload_sha256: verifiedSignedPayloadSha256,
  };
}

function fixtureAuthorityConfig({
  trusted,
  nowEpoch,
  authorizedRecordUpdate,
  recognitionRuleSnapshot,
  targetBinding,
  appointmentStatus = 'active',
  revokedAtEpoch = null,
  revocationReasonCode = null,
  validFromEpoch = PROTECTED_RECORDS_FIXTURE_AUTHORITY_VALID_FROM_EPOCH,
  expiresAtEpoch = PROTECTED_RECORDS_FIXTURE_AUTHORITY_EXPIRES_AT_EPOCH,
} = {}) {
  const scopeEvidence = createProtectedRecordsRuntimeLauncherScopeEvidence({
    actionClass: 'records.write',
    authorizedRecordUpdate,
    profileId: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    recognitionRuleSnapshot,
    targetBinding,
  });
  const contract = createProtectedRecordsRuntimeFixtureAuthorityGrantContract({
    scopeEvidence,
    validFromEpoch,
    expiresAtEpoch,
  });
  const issuanceAppointment = createProtectedRecordsFixtureAuthorityGrantAppointment({
    contract,
    granteeIssuerKid: trusted.kid,
    granteePublicKeySha256: sha256hex(trusted.publicPem),
  });
  const appointment = appointmentStatus === 'active'
    ? issuanceAppointment
    : createProtectedRecordsFixtureAuthorityGrantAppointment({
        contract,
        granteeIssuerKid: trusted.kid,
        granteePublicKeySha256: sha256hex(trusted.publicPem),
        status: appointmentStatus,
        revokedAtEpoch,
        revocationReasonCode,
      });
  const targetEffect = protectedRecordsTargetEffect({
    targetHandle: targetBinding.target_handle,
    recordUpdate: authorizedRecordUpdate,
  });
  const authorizedEffectDetail = protectedRecordsAuthorizedEffectDetail({
    contract,
    targetEffect,
  });
  const unsignedReceipt = createReceiptV1FromEvent(eventFixture({
    authorityGrantContract: contract,
    nowEpoch,
    recordUpdate: authorizedRecordUpdate,
  }));
  const payload = decodePayloadV1(unsignedReceipt);
  const issuanceReceiptEvidence = createProtectedRecordsRuntimeAuthorityReceiptEvidence({
    envelope: unsignedReceipt,
    issuerKid: trusted.kid,
    issuerStatus: null,
    payload,
    publicKeySha256: sha256hex(trusted.publicPem),
    source: 'unsigned-receipt-payload-before-signing',
    signatureVerified: false,
    downstreamRecognitionAccepted: false,
    verifiedSignedPayloadSha256: null,
  });
  const issuanceDecision = evaluateProtectedRecordsFixtureAuthorityGrantIssuance({
    contract,
    appointment: issuanceAppointment,
    scopeEvidence,
    receiptEvidence: issuanceReceiptEvidence,
    authorizedEffectDetail,
    evaluationEpoch: issuanceReceiptEvidence.issued_at_epoch,
    grantPreviouslyConsumed: false,
  });
  assertProtectedRecordsFixtureAuthorityGrantDecision(
    issuanceDecision,
    contract,
    'issuance',
    { requireAccepted: true }
  );
  return {
    appointment,
    authorizedEffectDetail,
    contract,
    issuanceDecision,
    scopeEvidence,
    targetEffect,
  };
}

function helperRecognitionDecision(helperDecision, { helperStatePromoted = false } = {}) {
  const recognition = helperDecision.recognition;
  return {
    ...recognition,
    evidence: {
      ...recognition.evidence,
      decision_helper: PROTECTED_RECORDS_BOARDING_DECISION_HELPER,
      decision_helper_consumption:
        'staged-candidate-before-launcher-owned-consumed-store-commit',
      decision_helper_effect_count_delta: helperDecision.effect_count_delta,
      decision_helper_state_promoted: helperStatePromoted,
    },
  };
}

function consumedStoreDecision(reasonCode) {
  const messages = {
    consumed_store_invalid: 'Runtime consumed authority-grant store is invalid; refusing before runtime-state mutation.',
    consumed_store_anchor_invalid: 'Runtime consumed authority-grant store anchor is invalid; refusing before runtime-state mutation.',
    consumed_store_rollback_detected: 'Runtime consumed authority-grant store rollback was detected against the launcher-owned local anchor; refusing before runtime-state mutation.',
    consumed_store_locked: 'Runtime consumed authority-grant store is locked; refusing before runtime-state mutation.',
    consumed_store_write_failed: 'Runtime consumed authority-grant store could not be committed; refusing before runtime-state mutation.',
  };
  return {
    result_type: 'protected-records-runtime-consumed-store-rule-v1',
    recognized: false,
    decision: 'refuse',
    reason_code: reasonCode,
    reasons: [
      {
        code: reasonCode,
        message: messages[reasonCode] || messages.consumed_store_write_failed,
      },
    ],
    evidence: {
      consumed_authority_grant_store:
        'persistent-single-use-authority-grant-contract-sha256-store',
      consumption_identity: 'authority-grant-contract-sha256',
      consumed_store_lock: 'launcher-owned-per-store-lockfile',
      consumed_store_validation: 'exact-schema-unique-grant-contract-sha256s',
      consumed_store_anchor: 'launcher-owned-local-store-hash-anchor',
      consumed_store_witness: 'launcher-owned-local-store-hash-witness',
      consumed_store_rollback_detection:
        'single-host-anchor-and-witness-match-before-mutation',
      consumed_store_write_model:
        'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness',
    },
  };
}

function runtimeStateAppendFailureDecision() {
  return {
    result_type: 'protected-records-runtime-state-append-rule-v1',
    recognized: false,
    decision: 'refuse',
    reason_code: 'runtime_state_append_failed_after_consumed_store_commit',
    reasons: [
      {
        code: 'runtime_state_append_failed_after_consumed_store_commit',
        message: 'Runtime state append failed after the launcher-owned consumed store committed; refusing the runtime write claim.',
      },
    ],
    evidence: {
      consumed_store_committed: true,
      runtime_state_entry_written: false,
      boundary: 'one-use-authority-grant-consumption-not-exactly-once-effect',
      decision_helper: PROTECTED_RECORDS_BOARDING_DECISION_HELPER,
    },
  };
}

function grantStorePartialCommitDecision() {
  return {
    result_type: 'protected-records-runtime-grant-store-partial-commit-rule-v1',
    recognized: false,
    decision: 'refuse',
    reason_code: 'consumed_store_write_failed_after_grant_commit',
    reasons: [{
      code: 'consumed_store_write_failed_after_grant_commit',
      message: 'The one-use authority-grant SHA reached the persistent store, but anchor or witness commit failed; refusing the runtime write while preserving the burned-grant evidence.',
    }],
    evidence: {
      authority_grant_store_committed: true,
      consumed_store_metadata_commit_complete: false,
      runtime_state_entry_written: false,
      boundary: 'store-anchor-witness-multi-file-commit-not-atomic',
      refused_before_runtime_state_mutation: true,
    },
  };
}

function directApiReceiptPresentDecision() {
  return {
    result_type: 'protected-records-runtime-direct-api-rule-v1',
    recognized: false,
    decision: 'refuse',
    reason_code: 'direct_api_receipt_present',
    reasons: [
      {
        code: 'direct_api_receipt_present',
        message: 'Direct API attempts are not the authoritative records.write route and cannot smuggle a receipt.',
      },
    ],
    evidence: {
      direct_api_attempted: true,
      receipt_present: true,
    },
  };
}

function targetAssertionDecision(reasonCode) {
  const messages = {
    target_assertion_missing:
      'Runtime request target assertion is required and cannot be inferred from the request stream.',
    target_assertion_malformed:
      'Runtime request target assertion is malformed and cannot select a protected target.',
    target_assertion_mismatch:
      'Runtime request target assertion does not match the launcher-owned protected target.',
  };
  return {
    result_type: 'protected-records-runtime-target-assertion-rule-v1',
    recognized: false,
    decision: 'refuse',
    reason_code: reasonCode,
    reasons: [{ code: reasonCode, message: messages[reasonCode] }],
    evidence: {
      consequence_path: PROTECTED_RECORDS_CONSEQUENCE_PATH,
      target_handle_source: 'launcher-owned-service-config',
      request_target_semantics: 'assertion-only',
      refused_before_receipt_consumption: true,
      refused_before_runtime_state_mutation: true,
    },
  };
}

function recordUpdateAssertionDecision() {
  return {
    result_type: 'protected-records-runtime-record-update-assertion-rule-v1',
    recognized: false,
    decision: 'refuse',
    reason_code: 'record_update_assertion_mismatch',
    reasons: [{
      code: 'record_update_assertion_mismatch',
      message: 'Runtime request record_update does not match the launcher-owned authorized record update.',
    }],
    evidence: {
      authorized_record_update_source: 'launcher-owned-service-config',
      request_record_update_semantics: 'assertion-only',
      refused_before_receipt_recognition: true,
      refused_before_authority_grant_evaluation: true,
      refused_before_authority_grant_consumption: true,
      refused_before_runtime_state_mutation: true,
    },
  };
}

function runtimeAuthorityGrantDecision(decision) {
  return {
    result_type: decision.result_type,
    phase: decision.phase,
    decision: decision.decision,
    reason_code: decision.reason_code,
    reasons: decision.reasons,
    evidence: {
      authority_grant_contract_sha256:
        decision.evidence.authority_grant_contract_sha256,
      accepted_issuance_decision_bound:
        decision.evidence.accepted_issuance_decision_bound,
      authority_contract_scope_matches:
        decision.evidence.authority_contract_scope_matches,
      launcher_scope_provenance_validated:
        decision.evidence.launcher_scope_provenance_validated,
      receipt_bound_to_authority_grant:
        decision.evidence.receipt_bound_to_authority_grant,
      grant_not_previously_consumed:
        decision.evidence.grant_not_previously_consumed,
      grant_previously_consumed:
        decision.evidence.grant_previously_consumed,
      signature_verified_before_effect:
        decision.evidence.signature_verified_before_effect,
      verified_signed_payload_identity_present:
        decision.evidence.verified_signed_payload_identity_present,
      fixture_rightful_issuance_path_evidenced:
        decision.evidence.fixture_rightful_issuance_path_evidenced,
      rightful_issuance_proven: false,
      portable_rightful_issuance_proven: false,
      production_rightful_issuance_proven: false,
      consequence_lifecycle_closed: false,
      refused_before_authority_grant_consumption: decision.decision === 'refuse',
      refused_before_runtime_state_mutation: decision.decision === 'refuse',
    },
  };
}

function authorityMaterialDecision(fields) {
  return {
    result_type: 'protected-records-runtime-authority-material-rule-v1',
    recognized: false,
    decision: 'refuse',
    reason_code: 'agent_supplied_authority_material',
    reasons: [
      {
        code: 'agent_supplied_authority_material',
        message: 'Runtime requests cannot supply authority grants, issuance decisions, recognition rules, mutable state paths, or unsupported contract fields.',
      },
    ],
    evidence: {
      supplied_authority_fields: [...fields].sort(),
      request_contract: 'receipt-record-update-and-routing-metadata-only',
    },
  };
}

function resultBase({
  authorityGrantContractSha256,
  authorityGrantCrossingBindingSha256 = null,
  authorityGrantSatisfied = false,
  authorizedEffectDetailSha256,
  profileId,
  stateEntryCountBefore,
  stateEntryCountAfter,
  consumedAuthorityGrantCount,
  recordUpdateHash,
  requestMode,
  directApiAttempted,
  decision,
  targetBinding,
  targetAssertionMatchesConfig = null,
  targetEffectHash = null,
  receiptDetailHash = null,
  runtimeTransitionBinding = null,
  stateEffectBindingSha256 = null,
  verifiedSignedPayloadIdentityPresent = false,
}) {
  return {
    result_type: PROTECTED_RECORDS_RUNTIME_SERVICE_RESULT_TYPE,
    evidence_model: 'local-disposable-runtime-process-profile',
    live_probing: false,
    runtime_profile_id: profileId,
    runtime_profile_active: true,
    action_class: 'records.write',
    service_process_boundary: 'local-jsonl-child-process',
    recognition_boundary: 'service-configured-recognition-rule',
    mutation_authoritative_route:
      'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation',
    state_storage: 'process-private-memory',
    consumed_authority_grant_store:
      'persistent-single-use-authority-grant-contract-sha256-store',
    consumption_identity: 'authority-grant-contract-sha256',
    signed_payload_replay_identity: 'verified-signed-payload-sha256',
    consumed_store_lock: 'launcher-owned-per-store-lockfile',
    consumed_store_validation: 'exact-schema-unique-grant-contract-sha256s',
    consumed_store_anchor: 'launcher-owned-local-store-hash-anchor',
    consumed_store_witness: 'launcher-owned-local-store-hash-witness',
    consumed_store_rollback_detection:
      'single-host-anchor-and-witness-match-before-mutation',
    consumed_store_write_model:
      'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness',
    replay_scope:
      'helper-signed-payload-identity-and-persistent-authority-grant-contract-sha256',
    persistent_consumed_authority_grant_store: true,
    agent_supplied_state_paths_accepted: false,
    agent_supplied_recognition_rule_accepted: false,
    request_contract: 'agent-request-carries-receipt-record-update-and-routing-metadata-only',
    request_mode: requestMode,
    consequence_path: targetBinding.consequence_path,
    target_kind: targetBinding.target_kind,
    target_scope: targetBinding.target_scope,
    target_instance_scope: targetBinding.target_instance_scope,
    target_handle: targetBinding.target_handle,
    target_handle_source: targetBinding.target_handle_source,
    target_binding_sha256: sha256hex(canonicalize(targetBinding)),
    target_assertion_matches_config: targetAssertionMatchesConfig,
    target_effect_hash: targetEffectHash,
    authorized_effect_detail_sha256: authorizedEffectDetailSha256,
    receipt_detail_hash: receiptDetailHash,
    authority_grant_contract_sha256: authorityGrantContractSha256,
    authority_grant_crossing_binding_sha256: authorityGrantCrossingBindingSha256,
    authority_grant_satisfied: authorityGrantSatisfied,
    verified_signed_payload_identity_present: verifiedSignedPayloadIdentityPresent,
    runtime_transition_binding: runtimeTransitionBinding,
    state_effect_binding_sha256: stateEffectBindingSha256,
    record_update_hash: recordUpdateHash,
    service_write_accepted: false,
    service_state_changed: false,
    state_entry_written: false,
    state_entry_count_before: stateEntryCountBefore,
    state_entry_count_after: stateEntryCountAfter,
    state_entry_count_delta: stateEntryCountAfter - stateEntryCountBefore,
    consumed_authority_grant_count: consumedAuthorityGrantCount,
    direct_api_attempted: directApiAttempted,
    decision,
    safe_claim_ceiling: SAFE_CLAIM_CEILING,
    non_claims: [...NON_CLAIMS],
  };
}

export function assertProtectedRecordsRuntimeServiceConfig(config) {
  const expectedConfigKeys = [
    'action_class',
    'authorized_record_update',
    'authority_grant_appointment',
    'authority_grant_contract',
    'authority_grant_issuance_decision',
    'consumed_grant_store_anchor_path',
    'consumed_grant_store_witness_path',
    'consumed_grants_path',
    'now_epoch',
    'profile_id',
    'recognition_rule',
    'target_binding',
  ];
  if (Object.prototype.hasOwnProperty.call(config, 'runtime_state_append_failure_mode')) {
    expectedConfigKeys.push('runtime_state_append_failure_mode');
  }
  if (Object.prototype.hasOwnProperty.call(config, 'consumed_grant_store_commit_failure_mode')) {
    expectedConfigKeys.push('consumed_grant_store_commit_failure_mode');
  }
  assertExactKeys('Protected records runtime service config', config, expectedConfigKeys);
  if (config.profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID) {
    throw new Error('Protected records runtime profile id drifted');
  }
  if (config.action_class !== 'records.write') {
    throw new Error('Protected records runtime action class drifted');
  }
  if (numberOrNull(config.now_epoch) === null) {
    throw new Error('Protected records runtime config now_epoch must be numeric');
  }
  if (!stringOrNull(config.consumed_grants_path)) {
    throw new Error('Protected records runtime config consumed_grants_path must be a launcher-supplied string');
  }
  if (!stringOrNull(config.consumed_grant_store_anchor_path)) {
    throw new Error('Protected records runtime config consumed_grant_store_anchor_path must be a launcher-supplied string');
  }
  if (!stringOrNull(config.consumed_grant_store_witness_path)) {
    throw new Error('Protected records runtime config consumed_grant_store_witness_path must be a launcher-supplied string');
  }
  assertDistinctConsumedStorePaths(
    config.consumed_grants_path,
    config.consumed_grant_store_anchor_path,
    config.consumed_grant_store_witness_path
  );
  if (
    Object.prototype.hasOwnProperty.call(config, 'runtime_state_append_failure_mode') &&
    config.runtime_state_append_failure_mode !== PROTECTED_RECORDS_RUNTIME_STATE_APPEND_FAILURE_MODE
  ) {
    throw new Error('Protected records runtime config state append failure mode is only allowed for the local proof boundary case');
  }
  if (
    Object.prototype.hasOwnProperty.call(config, 'consumed_grant_store_commit_failure_mode') &&
    config.consumed_grant_store_commit_failure_mode !==
      PROTECTED_RECORDS_RUNTIME_GRANT_STORE_WITNESS_COMMIT_FAILURE_MODE
  ) {
    throw new Error('Protected records runtime config grant-store commit failure mode is only allowed for the local proof boundary case');
  }
  requireObject('Protected records runtime recognition_rule', config.recognition_rule);
  requireObject('Protected records runtime authorized_record_update', config.authorized_record_update);
  assertProtectedRecordsRuntimeTargetBinding(config.target_binding, config);
  for (const [label, actual, expected] of [
    ['accepted policy versions', config.recognition_rule.accepted_policy_versions, ['recognition-policy-v1']],
    ['accepted domains', config.recognition_rule.accepted_domains, ['records']],
    ['accepted tools', config.recognition_rule.accepted_tools, ['records.write']],
    ['accepted outcomes', config.recognition_rule.accepted_outcomes, ['allow', 'authorized']],
  ]) {
    if (canonicalize(actual) !== canonicalize(expected)) {
      throw new Error(`Protected records runtime recognition ${label} drifted`);
    }
  }
  assertProtectedRecordsFixtureAuthorityGrantContract(config.authority_grant_contract);
  if (config.authority_grant_appointment !== null) {
    assertProtectedRecordsFixtureAuthorityGrantAppointment(config.authority_grant_appointment);
  }
  assertProtectedRecordsFixtureAuthorityGrantDecision(
    config.authority_grant_issuance_decision,
    config.authority_grant_contract,
    'issuance',
    { requireAccepted: true }
  );
  return true;
}

function freezeCanonicalSnapshot(value) {
  const snapshot = JSON.parse(canonicalize(value));
  const freeze = (item) => {
    if (!item || typeof item !== 'object' || Object.isFrozen(item)) return item;
    for (const child of Object.values(item)) freeze(child);
    return Object.freeze(item);
  };
  return freeze(snapshot);
}

class ProtectedRecordsSnapshotError extends Error {}

function snapshotAccessorFreeData(value, label, seen = new WeakSet()) {
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) {
    return value;
  }
  if (typeof value !== 'object') {
    throw new ProtectedRecordsSnapshotError(`${label} contains non-data input`);
  }
  if (seen.has(value)) {
    throw new ProtectedRecordsSnapshotError(`${label} contains repeated or cyclic input`);
  }
  seen.add(value);

  const symbols = Object.getOwnPropertySymbols(value);
  if (symbols.length > 0) {
    throw new ProtectedRecordsSnapshotError(`${label} contains symbol-keyed input`);
  }

  if (Array.isArray(value)) {
    const names = Object.getOwnPropertyNames(value);
    const extraNames = names.filter((name) => name !== 'length' && !/^(0|[1-9][0-9]*)$/.test(name));
    if (extraNames.length > 0) {
      throw new ProtectedRecordsSnapshotError(`${label} contains non-index array input`);
    }
    const snapshot = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || descriptor.get || descriptor.set || descriptor.enumerable !== true) {
        throw new ProtectedRecordsSnapshotError(`${label}[${index}] is not an enumerable data value`);
      }
      snapshot.push(snapshotAccessorFreeData(descriptor.value, `${label}[${index}]`, seen));
    }
    return snapshot;
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new ProtectedRecordsSnapshotError(`${label} is not a plain data object`);
  }
  const snapshot = Object.create(null);
  for (const name of Object.getOwnPropertyNames(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || descriptor.get || descriptor.set || descriptor.enumerable !== true) {
      throw new ProtectedRecordsSnapshotError(`${label}.${name} is not an enumerable data value`);
    }
    Object.defineProperty(snapshot, name, {
      configurable: true,
      enumerable: true,
      writable: true,
      value: snapshotAccessorFreeData(descriptor.value, `${label}.${name}`, seen),
    });
  }
  return snapshot;
}

export function createProtectedRecordsRuntimeService() {
  throw new Error('legacy_runtime_v1_exported_factory_retired');
}

export const PROTECTED_RECORDS_RUNTIME_STATUS_REFRESH_TRANSPORT_V2 =
  'launcher-owned-local-disposable-json-file-read-under-consumed-store-lock';
export const PROTECTED_RECORDS_RUNTIME_STATUS_REFRESH_CLAIM_LIMIT_V2 =
  'The local mutable-file refresh detects the bytes observed under the runtime lock but does not prove rollback-resistant custody or writer coordination; restoring the initial active bytes or changing the file after that read can evade revocation without an external monotonic witness.';
export const PROTECTED_RECORDS_RUNTIME_CONSEQUENCE_CLOCK_CLAIM_LIMIT_V2 =
  'The v2 consequence boundary reads the process wall clock at recognition and again immediately before effect evaluation; caller-supplied consequence time is refused, but host clock rollback resistance and external time attestation are not proven.';

function protectedRecordsRuntimeConsequenceEpochV2() {
  const nowMs = Date.now();
  const nowEpoch = Math.floor(nowMs / 1000);
  if (
    !Number.isFinite(nowMs) ||
    !Number.isSafeInteger(nowEpoch) ||
    nowEpoch < 0
  ) {
    throw new Error('Protected records runtime v2 consequence clock is invalid');
  }
  return nowEpoch;
}

function authorityClockDecision(
  reasonCode,
  { recognitionEpoch = null, effectEpoch = null } = {},
) {
  const messages = {
    authority_clock_unavailable:
      'The runtime process wall clock was unavailable or invalid; refusing before effect.',
    authority_clock_regressed:
      'The runtime process wall clock regressed during the consequence boundary; refusing before effect.',
  };
  return {
    result_type: 'protected-records-runtime-authority-clock-rule-v2',
    recognized: false,
    decision: 'refuse',
    reason_code: reasonCode,
    reasons: [{
      code: reasonCode,
      message: messages[reasonCode] || messages.authority_clock_unavailable,
    }],
    evidence: {
      consequence_clock_source:
        PROTECTED_RECORDS_FIXTURE_AUTHORITY_CLOCK_SOURCE_V2,
      caller_supplied_consequence_time_accepted: false,
      recognition_epoch: recognitionEpoch,
      effect_epoch: effectEpoch,
      refused_before_authority_grant_consumption: true,
      refused_before_runtime_state_mutation: true,
      rollback_resistant_clock_custody_proven: false,
      external_time_attestation_present: false,
    },
  };
}

function authorityEffectMarginDecision({
  grantWindowRemainingSeconds,
  receiptRecognitionRemainingSeconds,
}) {
  return {
    result_type: 'protected-records-runtime-authority-effect-margin-rule-v2',
    recognized: false,
    decision: 'refuse',
    reason_code: 'authority_effect_window_margin_insufficient',
    reasons: [{
      code: 'authority_effect_window_margin_insufficient',
      message:
        'The runtime-observed grant or receipt window lacked the fixed effect margin; refusing before consumption and mutation.',
    }],
    evidence: {
      consequence_clock_source:
        PROTECTED_RECORDS_FIXTURE_AUTHORITY_CLOCK_SOURCE_V2,
      caller_supplied_consequence_time_accepted: false,
      minimum_effect_margin_seconds:
        PROTECTED_RECORDS_RUNTIME_MINIMUM_EFFECT_MARGIN_SECONDS_V2,
      grant_window_remaining_seconds: grantWindowRemainingSeconds,
      receipt_recognition_remaining_seconds:
        receiptRecognitionRemainingSeconds,
      refused_before_authority_grant_consumption: true,
      refused_before_runtime_state_mutation: true,
      exactly_once_effect_proven: false,
    },
  };
}

class ProtectedRecordsAuthorityStatusRefreshError extends Error {
  constructor(reasonCode, message) {
    super(message);
    this.reasonCode = reasonCode;
  }
}

function assertProtectedRecordsRuntimeAuthorityStatusRefreshPathV2(
  refreshPath,
  { consumedPath, anchorPath, witnessPath },
) {
  if (!stringOrNull(refreshPath)) {
    throw new Error(
      'Protected records runtime v2 authority status refresh path must be launcher supplied',
    );
  }
  const refreshIdentity = launcherPathIdentity(refreshPath);
  const forbiddenIdentities = [
    consumedPath,
    anchorPath,
    witnessPath,
    consumedStoreLockPath(consumedPath),
  ].map(launcherPathIdentity);
  if (forbiddenIdentities.includes(refreshIdentity)) {
    throw new Error(
      'Protected records runtime v2 authority status refresh path must not alias runtime state paths',
    );
  }
  let status;
  try {
    status = lstatSync(refreshPath);
  } catch {
    throw new Error(
      'Protected records runtime v2 authority status refresh source is unavailable',
    );
  }
  if (status.isSymbolicLink() || !status.isFile()) {
    throw new Error(
      'Protected records runtime v2 authority status refresh source must be a regular non-symlink file',
    );
  }
  return true;
}

function readProtectedRecordsRuntimeAuthorityStatusRefreshV2(
  refreshPath,
  context,
) {
  let parsed;
  try {
    const status = lstatSync(refreshPath);
    if (status.isSymbolicLink() || !status.isFile()) {
      throw new Error('status refresh source is not a regular file');
    }
    parsed = JSON.parse(readFileSync(refreshPath, 'utf8'));
    parsed = freezeCanonicalSnapshot(
      snapshotAccessorFreeData(
        parsed,
        'Protected records runtime v2 authority status refresh record',
      ),
    );
    assertProtectedRecordsFixtureAuthorityStatusV2(parsed, {
      contract: context.authorityGrantContract,
      expectedContractSha256: context.authorityGrantContractSha256,
      appointment: context.appointment,
      confirmation: context.confirmation,
    });
  } catch {
    throw new ProtectedRecordsAuthorityStatusRefreshError(
      'authority_status_refresh_unavailable_or_invalid',
      'The launcher-owned authority status refresh source was unavailable or invalid; refusing before effect.',
    );
  }
  const initialStatus = context.authorityGrantStatus;
  if (
    parsed.status_updated_at_epoch < initialStatus.status_updated_at_epoch ||
    (parsed.status === 'active' &&
      canonicalize(parsed) !== canonicalize(initialStatus))
  ) {
    throw new ProtectedRecordsAuthorityStatusRefreshError(
      'authority_status_refresh_continuity_invalid',
      'The launcher-owned authority status refresh violated the initial active-status continuity floor; refusing before effect.',
    );
  }
  return parsed;
}

function authorityStatusRefreshDecision(reasonCode, {
  statusRefreshValidated = false,
  statusAtEffect = null,
} = {}) {
  const messages = {
    authority_status_refresh_unavailable_or_invalid:
      'The launcher-owned authority status refresh source was unavailable or invalid; refusing before effect.',
    authority_status_refresh_continuity_invalid:
      'The launcher-owned authority status refresh violated active-status continuity; refusing before effect.',
  };
  return {
    result_type: 'protected-records-runtime-authority-status-refresh-rule-v2',
    recognized: false,
    decision: 'refuse',
    reason_code: reasonCode,
    reasons: [{
      code: reasonCode,
      message:
        messages[reasonCode] ||
        messages.authority_status_refresh_unavailable_or_invalid,
    }],
    evidence: {
      status_refresh_transport:
        PROTECTED_RECORDS_RUNTIME_STATUS_REFRESH_TRANSPORT_V2,
      request_stream_controls_status_refresh: false,
      checked_under_consumed_store_lock: true,
      status_refresh_validated: statusRefreshValidated,
      refreshed_status: statusAtEffect?.status || null,
      refused_before_authority_effect_evaluation: true,
      refused_before_authority_grant_consumption: true,
      refused_before_runtime_state_mutation: true,
      external_monotonic_witness_present: false,
      rollback_resistant_status_custody_proven: false,
    },
  };
}

export function isProtectedRecordsRuntimeServiceConfigV2(config) {
  return Boolean(
    config &&
      typeof config === 'object' &&
      !Array.isArray(config) &&
      isProtectedRecordsFixtureAuthorityGrantContractV2(
        config.authority_grant_contract,
      ),
  );
}

export function assertProtectedRecordsRuntimeServiceConfigV2(config) {
  assertExactKeys('Protected records runtime v2 service config', config, [
    'action_class',
    'authorized_record_update',
    'authority_grant_appointment',
    'authority_grant_confirmation',
    'authority_grant_contract',
    'authority_grant_expected_contract_sha256',
    'authority_grant_issuance_decision',
    'authority_grant_status',
    'authority_grant_status_refresh_path',
    'authority_source_precondition',
    'consumed_grant_store_anchor_path',
    'consumed_grant_store_witness_path',
    'consumed_grants_path',
    'profile_id',
    'recognition_rule',
    'target_binding',
  ]);
  if (!isProtectedRecordsRuntimeServiceConfigV2(config)) {
    throw new Error('Protected records runtime v2 authority contract is required');
  }
  if (config.profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID) {
    throw new Error('Protected records runtime v2 profile id drifted');
  }
  if (config.action_class !== 'records.write') {
    throw new Error('Protected records runtime v2 action class drifted');
  }
  for (const [label, value] of [
    ['consumed_grants_path', config.consumed_grants_path],
    [
      'consumed_grant_store_anchor_path',
      config.consumed_grant_store_anchor_path,
    ],
    [
      'consumed_grant_store_witness_path',
      config.consumed_grant_store_witness_path,
    ],
  ]) {
    if (!stringOrNull(value)) {
      throw new Error(
        `Protected records runtime v2 ${label} must be launcher supplied`,
      );
    }
  }
  assertDistinctConsumedStorePaths(
    config.consumed_grants_path,
    config.consumed_grant_store_anchor_path,
    config.consumed_grant_store_witness_path,
  );
  assertProtectedRecordsRuntimeAuthorityStatusRefreshPathV2(
    config.authority_grant_status_refresh_path,
    {
      consumedPath: config.consumed_grants_path,
      anchorPath: config.consumed_grant_store_anchor_path,
      witnessPath: config.consumed_grant_store_witness_path,
    },
  );
  requireObject(
    'Protected records runtime v2 authorized record update',
    config.authorized_record_update,
  );
  assertProtectedRecordsRuntimeTargetBinding(config.target_binding, config);
  const context = createProtectedRecordsRuntimeAuthorityContextV2({
    actionClass: config.action_class,
    authorizedRecordUpdate: config.authorized_record_update,
    authorityGrantAppointment: config.authority_grant_appointment,
    authorityGrantConfirmation: config.authority_grant_confirmation,
    authorityGrantContract: config.authority_grant_contract,
    authorityGrantExpectedContractSha256:
      config.authority_grant_expected_contract_sha256,
    authorityGrantIssuanceDecision:
      config.authority_grant_issuance_decision,
    authorityGrantStatus: config.authority_grant_status,
    profileId: config.profile_id,
    recognitionRule: config.recognition_rule,
    sourcePrecondition: config.authority_source_precondition,
    targetBinding: config.target_binding,
  });
  const initialRefreshStatus =
    readProtectedRecordsRuntimeAuthorityStatusRefreshV2(
      config.authority_grant_status_refresh_path,
      context,
    );
  if (canonicalize(initialRefreshStatus) !== canonicalize(context.authorityGrantStatus)) {
    throw new Error(
      'Protected records runtime v2 authority status refresh source must begin at the exact configured active status',
    );
  }
  return true;
}

function protectedRecordsRuntimeServiceResultV2Base({
  context,
  targetBinding,
  profileId,
  stateEntryCountBefore,
  stateEntryCountAfter,
  consumedAuthorityGrantCount,
  requestMode,
  directApiAttempted,
  decision,
  targetAssertionMatchesConfig = null,
  receiptDetailHash = null,
  verifiedSignedPayloadSha256 = null,
  signedReceiptSha256 = null,
  effectDecision = null,
  effectDecisionSha256 = null,
  effectGateBinding = null,
  effectGateBindingSha256 = null,
  executionTrace = null,
  executionTraceSha256 = null,
  runtimeTransitionBinding = null,
  runtimeTransitionBindingSha256 = null,
  stateEffectBindingSha256 = null,
  authorityGrantSatisfied = false,
  authorityStatusAtEffect = null,
  authorityStatusAtEffectSha256 = null,
  authorityStatusRefreshValidatedAtEffect = false,
}) {
  return {
    result_type: PROTECTED_RECORDS_RUNTIME_SERVICE_RESULT_TYPE_V2,
    authority_contract_version: 2,
    evidence_model: 'local-disposable-runtime-process-profile',
    live_probing: false,
    runtime_profile_id: profileId,
    runtime_profile_active: true,
    action_class: 'records.write',
    consequence_path: targetBinding.consequence_path,
    service_process_boundary: 'local-jsonl-child-process',
    recognition_boundary:
      'service-configured-exact-v2-receipt-and-authority-recognition-rule',
    mutation_authoritative_route:
      'signed-receipt-verification-then-v2-authority-effect-gate-before-single-lock-grant-consumption-and-runtime-state-append',
    state_storage: 'process-private-memory',
    consumed_authority_grant_store:
      'persistent-single-use-authority-grant-contract-sha256-store',
    consumption_identity: 'authority-grant-contract-sha256',
    signed_payload_replay_identity: 'verified-signed-payload-sha256',
    consumed_store_lock: 'launcher-owned-per-store-lockfile',
    consumed_store_validation: 'exact-schema-unique-grant-contract-sha256s',
    consumed_store_anchor: 'launcher-owned-local-store-hash-anchor',
    consumed_store_witness: 'launcher-owned-local-store-hash-witness',
    consumed_store_rollback_detection:
      'single-host-anchor-and-witness-match-before-mutation',
    consumed_store_write_model:
      'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness',
    replay_scope:
      'helper-signed-payload-identity-and-persistent-authority-grant-contract-sha256',
    persistent_consumed_authority_grant_store: true,
    agent_supplied_state_paths_accepted: false,
    agent_supplied_recognition_rule_accepted: false,
    agent_supplied_authority_material_accepted: false,
    request_contract:
      'agent-request-carries-receipt-record-update-and-routing-metadata-only',
    request_mode: requestMode,
    direct_api_attempted: directApiAttempted,
    target_kind: targetBinding.target_kind,
    target_scope: targetBinding.target_scope,
    target_instance_scope: targetBinding.target_instance_scope,
    target_handle: targetBinding.target_handle,
    target_handle_source: targetBinding.target_handle_source,
    target_binding_sha256: sha256hex(canonicalize(targetBinding)),
    target_assertion_matches_config: targetAssertionMatchesConfig,
    record_update_sha256:
      context.authorityGrantContract.scope.record_update_sha256,
    target_effect_sha256: context.targetEffectSha256,
    installed_profile_preflight_artifact_body_sha256:
      context.authorityGrantContract.scope
        .installed_profile_preflight_artifact_body_sha256,
    profile_sha256: context.authorityGrantContract.scope.profile_sha256,
    recognition_contract_sha256:
      context.authorityGrantContract.scope.recognition_contract_sha256,
    target_contract_sha256:
      context.authorityGrantContract.scope.target_contract_sha256,
    authority_source_precondition: context.sourcePrecondition,
    source_precondition_artifact_body_sha256:
      context.sourcePreconditionSha256,
    authority_grant_contract: context.authorityGrantContract,
    authority_grant_contract_sha256:
      context.authorityGrantContractSha256,
    authority_grant_appointment: context.appointment,
    authority_grant_appointment_sha256: context.appointmentSha256,
    authority_grant_confirmation: context.confirmation,
    authority_grant_confirmation_sha256: context.confirmationSha256,
    authority_grant_initial_status: context.authorityGrantStatus,
    authority_grant_initial_status_sha256:
      context.authorityStatusAtEffectSha256,
    authority_grant_status_at_effect: authorityStatusAtEffect,
    authority_grant_status_at_effect_sha256:
      authorityStatusAtEffectSha256,
    authority_status_refresh_validated_at_effect:
      authorityStatusRefreshValidatedAtEffect,
    authority_status_refresh_transport:
      PROTECTED_RECORDS_RUNTIME_STATUS_REFRESH_TRANSPORT_V2,
    authority_status_refresh_claim_limit:
      PROTECTED_RECORDS_RUNTIME_STATUS_REFRESH_CLAIM_LIMIT_V2,
    issuer_binding_sha256: context.issuerBindingSha256,
    authorized_effect_detail: context.authorizedEffectDetail,
    authorized_effect_detail_sha256:
      context.authorizedEffectDetailSha256,
    authority_grant_issuance_decision: context.issuanceDecision,
    authority_grant_issuance_decision_sha256:
      context.issuanceDecisionSha256,
    authority_grant_effect_decision: effectDecision,
    authority_grant_effect_decision_sha256: effectDecisionSha256,
    authority_effect_gate_binding: effectGateBinding,
    authority_effect_gate_binding_sha256: effectGateBindingSha256,
    authority_grant_satisfied: authorityGrantSatisfied,
    receipt_detail_hash: receiptDetailHash,
    verified_signed_payload_sha256: verifiedSignedPayloadSha256,
    signed_receipt_sha256: signedReceiptSha256,
    execution_trace: executionTrace,
    execution_trace_sha256: executionTraceSha256,
    runtime_transition_binding: runtimeTransitionBinding,
    runtime_transition_binding_sha256: runtimeTransitionBindingSha256,
    state_effect_binding_sha256: stateEffectBindingSha256,
    service_write_accepted: false,
    service_state_changed: false,
    state_entry_written: false,
    state_entry_count_before: stateEntryCountBefore,
    state_entry_count_after: stateEntryCountAfter,
    state_entry_count_delta: stateEntryCountAfter - stateEntryCountBefore,
    consumed_authority_grant_count: consumedAuthorityGrantCount,
    decision,
    safe_claim_ceiling:
      'One exact local disposable fixture crossing can be accepted only after the runtime independently verifies its signed receipt and accepts the exact v2 human-confirmed authority contract before one-use consumption and process-private state mutation.',
    non_claims: [...NON_CLAIMS],
  };
}

export function createProtectedRecordsRuntimeServiceV2(config = {}) {
  const serviceConfig = freezeCanonicalSnapshot(
    snapshotAccessorFreeData(
      requireObject('Protected records runtime v2 service config', config),
      'Protected records runtime v2 service config',
    ),
  );
  assertProtectedRecordsRuntimeServiceConfigV2(serviceConfig);
  const profileId = serviceConfig.profile_id;
  const actionClass = serviceConfig.action_class;
  const consumedPath = serviceConfig.consumed_grants_path;
  const anchorPath = serviceConfig.consumed_grant_store_anchor_path;
  const witnessPath = serviceConfig.consumed_grant_store_witness_path;
  const authorityStatusRefreshPath =
    serviceConfig.authority_grant_status_refresh_path;
  const recognitionRuleSnapshot = serviceConfig.recognition_rule;
  const targetBinding = serviceConfig.target_binding;
  const authorizedRecordUpdate = serviceConfig.authorized_record_update;
  const context = createProtectedRecordsRuntimeAuthorityContextV2({
    actionClass,
    authorizedRecordUpdate,
    authorityGrantAppointment: serviceConfig.authority_grant_appointment,
    authorityGrantConfirmation: serviceConfig.authority_grant_confirmation,
    authorityGrantContract: serviceConfig.authority_grant_contract,
    authorityGrantExpectedContractSha256:
      serviceConfig.authority_grant_expected_contract_sha256,
    authorityGrantIssuanceDecision:
      serviceConfig.authority_grant_issuance_decision,
    authorityGrantStatus: serviceConfig.authority_grant_status,
    profileId,
    recognitionRule: recognitionRuleSnapshot,
    sourcePrecondition: serviceConfig.authority_source_precondition,
    targetBinding,
  });
  const stateEntries = [];
  const consumedGrantContractSha256s = new Set();
  let helperDecisionState = createProtectedRecordsBoardingDecisionState();

  function serviceResult(input) {
    return protectedRecordsRuntimeServiceResultV2Base({
      ...input,
      context,
      targetBinding,
      profileId,
    });
  }

  function candidateHelperState() {
    return createProtectedRecordsBoardingDecisionState({
      effects: [...helperDecisionState.effects],
      replayCache: new Set(helperDecisionState.replayCache),
    });
  }

  function syncConsumedGrantContractSha256s(grantContractSha256s) {
    consumedGrantContractSha256s.clear();
    for (const item of grantContractSha256s) {
      consumedGrantContractSha256s.add(item);
    }
  }

  function runtimeStateSha256() {
    return sha256hex(canonicalize({
      state_type: 'protected-records-runtime-process-private-state-v2',
      entries: stateEntries,
    }));
  }

  function baseResultInput({
    stateEntryCountBefore,
    requestMode,
    directApiAttempted,
    decision,
    ...rest
  }) {
    return {
      stateEntryCountBefore,
      stateEntryCountAfter: stateEntries.length,
      consumedAuthorityGrantCount: consumedGrantContractSha256s.size,
      requestMode,
      directApiAttempted,
      decision,
      ...rest,
    };
  }

  function applyRequest(input = {}) {
    const stateEntryCountBefore = stateEntries.length;
    let request;
    try {
      request = freezeCanonicalSnapshot(
        snapshotAccessorFreeData(
          requireObject('Protected records runtime v2 request', input),
          'Protected records runtime v2 request',
        ),
      );
    } catch {
      return serviceResult(baseResultInput({
        stateEntryCountBefore,
        requestMode: 'invalid_request_shape',
        directApiAttempted: false,
        decision: authorityMaterialDecision([
          'request_accessor_or_non_data_shape',
        ]),
      }));
    }
    const unsupportedFields = Object.keys(request).filter(
      (field) => !ALLOWED_REQUEST_FIELDS.includes(field),
    );
    const forbiddenFields = FORBIDDEN_AGENT_AUTHORITY_FIELDS.filter((field) =>
      Object.prototype.hasOwnProperty.call(request, field),
    );
    const requestMode =
      stringOrNull(request.request_mode) || 'recognized_runtime_write';
    const directApiAttempted =
      requestMode === 'direct_api_write_without_receipt' ||
      request.direct_api_write === true;

    const refuse = (decision, rest = {}) => serviceResult(baseResultInput({
      stateEntryCountBefore,
      requestMode,
      directApiAttempted,
      decision,
      ...rest,
    }));

    let recognitionEpoch;
    try {
      recognitionEpoch = protectedRecordsRuntimeConsequenceEpochV2();
    } catch {
      return refuse(authorityClockDecision('authority_clock_unavailable'));
    }

    if (request.runtime_profile_id && request.runtime_profile_id !== profileId) {
      return refuse(authorityMaterialDecision(['runtime_profile_id_mismatch']));
    }
    if (forbiddenFields.length > 0) {
      return refuse(authorityMaterialDecision(forbiddenFields));
    }
    if (unsupportedFields.length > 0) {
      return refuse(authorityMaterialDecision(unsupportedFields));
    }

    const targetAssertion = request.target_handle;
    if (!Object.prototype.hasOwnProperty.call(request, 'target_handle')) {
      return refuse(targetAssertionDecision('target_assertion_missing'), {
        targetAssertionMatchesConfig: false,
      });
    }
    if (
      typeof targetAssertion !== 'string' ||
      !(new RegExp(PROTECTED_RECORDS_TARGET_HANDLE_GRAMMAR)).test(
        targetAssertion,
      )
    ) {
      return refuse(targetAssertionDecision('target_assertion_malformed'), {
        targetAssertionMatchesConfig: false,
      });
    }
    if (targetAssertion !== targetBinding.target_handle) {
      return refuse(targetAssertionDecision('target_assertion_mismatch'), {
        targetAssertionMatchesConfig: false,
      });
    }
    if (
      !request.record_update ||
      typeof request.record_update !== 'object' ||
      Array.isArray(request.record_update) ||
      canonicalize(request.record_update) !==
        canonicalize(authorizedRecordUpdate)
    ) {
      return refuse(recordUpdateAssertionDecision(), {
        targetAssertionMatchesConfig: true,
      });
    }
    if (directApiAttempted && request.receipt) {
      return refuse(directApiReceiptPresentDecision(), {
        targetAssertionMatchesConfig: true,
      });
    }

    const recognitionProbe = evaluateProtectedRecordsBoardingDecision({
      actionClass,
      caseId: requestMode,
      effectType: 'protected-records-runtime-profile-staged-effect-v2',
      expectedReasonCode: null,
      nowEpoch: recognitionEpoch,
      receipt: request.receipt,
      receiptClass: requestMode,
      recognitionRule: recognitionRuleSnapshot,
      replayScope: profileId,
      state: createProtectedRecordsBoardingDecisionState(),
    });
    if (!recognitionProbe.recognized) {
      return refuse(helperRecognitionDecision(recognitionProbe), {
        targetAssertionMatchesConfig: true,
      });
    }

    const activeIssuer = recognitionRuleSnapshot.accepted_issuers.find(
      (issuer) =>
        issuer?.kid === context.appointment.issuer_kid &&
        issuer?.status === 'active' &&
        typeof issuer?.public_key_pem === 'string' &&
        sha256hex(issuer.public_key_pem) ===
          context.appointment.public_key_sha256,
    );
    if (!activeIssuer) {
      return refuse(authorityMaterialDecision(['exact_v2_issuer_missing']), {
        targetAssertionMatchesConfig: true,
      });
    }
    const verifiedReceipt = verifyReceiptV1(
      request.receipt,
      activeIssuer.public_key_pem,
    );
    if (!verifiedReceipt.valid || !verifiedReceipt.payload) {
      return refuse({
        result_type: 'protected-records-runtime-v2-independent-receipt-rule',
        recognized: false,
        decision: 'refuse',
        reason_code: 'independent_signed_receipt_verification_failed',
        reasons: [{
          code: 'independent_signed_receipt_verification_failed',
          message:
            'The runtime could not independently verify the exact signed receipt before authority evaluation.',
        }],
        evidence: {
          refused_before_authority_grant_evaluation: true,
          refused_before_authority_grant_consumption: true,
          refused_before_runtime_state_mutation: true,
        },
      }, {
        targetAssertionMatchesConfig: true,
      });
    }
    const receiptEvidence =
      createProtectedRecordsRuntimeEffectReceiptEvidenceV2({
        context,
        envelope: request.receipt,
        payload: verifiedReceipt.payload,
        publicKeyPem: activeIssuer.public_key_pem,
        verifiedSignedPayloadSha256:
          verifiedReceipt.verified_signed_payload_sha256,
      });

    let acceptedEffectGateBindingSha256 = null;
    let acceptedAuthorityResult = null;
    try {
      const atomicResult = withConsumedStoreLock(consumedPath, () => {
        const { store } = readConsumedStoreState(
          consumedPath,
          anchorPath,
          witnessPath,
        );
        syncConsumedGrantContractSha256s(store.grant_contract_sha256s);
        const grantPreviouslyConsumed = store.grant_contract_sha256s.includes(
          context.authorityGrantContractSha256,
        );
        const consumedGrantStoreSha256Before = consumedStoreHash(store);
        const runtimeStateSha256Before = runtimeStateSha256();
        const nextHelperState = candidateHelperState();
        let lockedRecognitionEpoch;
        try {
          lockedRecognitionEpoch = protectedRecordsRuntimeConsequenceEpochV2();
        } catch {
          return {
            kind: 'refused',
            decision: authorityClockDecision('authority_clock_unavailable', {
              recognitionEpoch,
            }),
          };
        }
        const lockedClockTransition =
          evaluateProtectedRecordsRuntimeClockTransitionV2({
            earlierEpoch: recognitionEpoch,
            laterEpoch: lockedRecognitionEpoch,
          });
        if (!lockedClockTransition.accepted) {
          return {
            kind: 'refused',
            decision: authorityClockDecision('authority_clock_regressed', {
              recognitionEpoch,
              effectEpoch: lockedRecognitionEpoch,
            }),
          };
        }
        recognitionEpoch = lockedRecognitionEpoch;
        const helperDecision = evaluateProtectedRecordsBoardingDecision({
          actionClass,
          caseId: requestMode,
          effectType: 'protected-records-runtime-profile-staged-effect-v2',
          expectedReasonCode: null,
          nowEpoch: recognitionEpoch,
          receipt: request.receipt,
          receiptClass: requestMode,
          recognitionRule: recognitionRuleSnapshot,
          replayScope: profileId,
          state: nextHelperState,
        });
        if (!helperDecision.recognized) {
          return {
            kind: 'refused',
            decision: helperRecognitionDecision(helperDecision),
          };
        }

        let authorityStatusAtEffect;
        try {
          authorityStatusAtEffect =
            readProtectedRecordsRuntimeAuthorityStatusRefreshV2(
              authorityStatusRefreshPath,
              context,
            );
        } catch (error) {
          const reasonCode =
            error instanceof ProtectedRecordsAuthorityStatusRefreshError
              ? error.reasonCode
              : 'authority_status_refresh_unavailable_or_invalid';
          return {
            kind: 'refused',
            decision: authorityStatusRefreshDecision(reasonCode),
            authorityStatusRefreshValidatedAtEffect: false,
          };
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

        let authorityEffectEvaluationEpoch;
        try {
          authorityEffectEvaluationEpoch =
            protectedRecordsRuntimeConsequenceEpochV2();
        } catch {
          return {
            kind: 'refused',
            decision: authorityClockDecision('authority_clock_unavailable', {
              recognitionEpoch,
            }),
            authorityStatusAtEffect,
            authorityStatusAtEffectSha256,
            authorityStatusRefreshValidatedAtEffect: true,
          };
        }
        const effectClockTransition =
          evaluateProtectedRecordsRuntimeClockTransitionV2({
            earlierEpoch: recognitionEpoch,
            laterEpoch: authorityEffectEvaluationEpoch,
          });
        if (!effectClockTransition.accepted) {
          return {
            kind: 'refused',
            decision: authorityClockDecision('authority_clock_regressed', {
              recognitionEpoch,
              effectEpoch: authorityEffectEvaluationEpoch,
            }),
            authorityStatusAtEffect,
            authorityStatusAtEffectSha256,
            authorityStatusRefreshValidatedAtEffect: true,
          };
        }
        const effectTimeRecognitionProbe =
          evaluateProtectedRecordsBoardingDecision({
            actionClass,
            caseId: requestMode,
            effectType: 'protected-records-runtime-profile-staged-effect-v2',
            expectedReasonCode: null,
            nowEpoch: authorityEffectEvaluationEpoch,
            receipt: request.receipt,
            receiptClass: requestMode,
            recognitionRule: recognitionRuleSnapshot,
            replayScope: profileId,
            state: createProtectedRecordsBoardingDecisionState(),
          });
        if (!effectTimeRecognitionProbe.recognized) {
          return {
            kind: 'refused',
            decision: helperRecognitionDecision(effectTimeRecognitionProbe),
            authorityStatusAtEffect,
            authorityStatusAtEffectSha256,
            authorityStatusRefreshValidatedAtEffect: true,
          };
        }
        const grantWindowRemainingSeconds =
          context.authorityGrantContract.time_policy.expires_at_epoch -
          authorityEffectEvaluationEpoch;
        const receiptRecognitionRemainingSeconds =
          receiptEvidence.issued_at_epoch +
          recognitionRuleSnapshot.max_age_seconds -
          authorityEffectEvaluationEpoch;
        const effectMargin = evaluateProtectedRecordsRuntimeEffectMarginV2({
          grantWindowRemainingSeconds,
          receiptRecognitionRemainingSeconds,
        });
        if (!effectMargin.accepted) {
          return {
            kind: 'refused',
            decision: authorityEffectMarginDecision({
              grantWindowRemainingSeconds,
              receiptRecognitionRemainingSeconds,
            }),
            authorityStatusAtEffect,
            authorityStatusAtEffectSha256,
            authorityStatusRefreshValidatedAtEffect: true,
          };
        }

        const authorityResult =
          evaluateProtectedRecordsRuntimeAuthorityEffectV2({
            context,
            evaluationEpoch: authorityEffectEvaluationEpoch,
            grantPreviouslyConsumed,
            receiptEvidence,
            authorityStatusAtEffect,
          });
        if (!authorityResult.accepted) {
          return {
            kind: 'refused',
            decision: protectedRecordsRuntimeAuthorityDecisionV2(
              authorityResult.effectDecision,
            ),
            authorityResult,
            authorityStatusAtEffect,
            authorityStatusAtEffectSha256,
            authorityStatusRefreshValidatedAtEffect: true,
          };
        }
        acceptedAuthorityResult = authorityResult;
        acceptedEffectGateBindingSha256 =
          authorityResult.effectGateBindingSha256;
        const executionTrace = createProtectedRecordsRuntimeExecutionTraceV2({
          authorityStatusAtEffectSha256,
          effectGateBindingSha256: authorityResult.effectGateBindingSha256,
          effectDecisionSha256: authorityResult.effectDecisionSha256,
          signedReceiptSha256: receiptEvidence.signed_receipt_sha256,
        });
        const executionTraceSha256 =
          protectedRecordsRuntimeExecutionTraceSha256V2(executionTrace);

        const committedStore = writeConsumedStoreState(
          consumedPath,
          anchorPath,
          [
            ...store.grant_contract_sha256s,
            context.authorityGrantContractSha256,
          ],
          witnessPath,
        );
        syncConsumedGrantContractSha256s(
          committedStore.grant_contract_sha256s,
        );
        const consumedGrantStoreSha256After =
          consumedStoreHash(committedStore);
        const stateEntry = {
          entry_type: 'protected-records-runtime-state-entry-v3',
          audit_event_id: verifiedReceipt.payload.audit_event_id,
          authority_grant_contract_sha256:
            context.authorityGrantContractSha256,
          authority_effect_gate_binding_sha256:
            authorityResult.effectGateBindingSha256,
          authority_grant_effect_decision_sha256:
            authorityResult.effectDecisionSha256,
          authority_grant_issuance_decision_sha256:
            context.issuanceDecisionSha256,
          authority_grant_status_at_effect_sha256:
            authorityStatusAtEffectSha256,
          authorized_effect_detail_sha256:
            context.authorizedEffectDetailSha256,
          execution_trace_sha256: executionTraceSha256,
          target_handle: targetBinding.target_handle,
          target_effect_sha256: context.targetEffectSha256,
          record_update_sha256:
            context.authorityGrantContract.scope.record_update_sha256,
          signed_receipt_sha256: receiptEvidence.signed_receipt_sha256,
          verified_signed_payload_sha256:
            verifiedReceipt.verified_signed_payload_sha256,
          service_transition:
            'protected_records_runtime_v2_authorized_write_accepted',
        };
        const stateEffectBindingSha256 = sha256hex(
          canonicalize(stateEntry),
        );
        stateEntries.push(stateEntry);
        const runtimeStateSha256After = runtimeStateSha256();
        const runtimeTransitionBinding = {
          binding_type:
            PROTECTED_RECORDS_RUNTIME_TRANSITION_BINDING_TYPE_V2,
          authority_grant_contract_sha256:
            context.authorityGrantContractSha256,
          authority_effect_gate_binding_sha256:
            authorityResult.effectGateBindingSha256,
          authority_grant_effect_decision_sha256:
            authorityResult.effectDecisionSha256,
          authority_grant_issuance_decision_sha256:
            context.issuanceDecisionSha256,
          authority_grant_status_at_effect_sha256:
            authorityStatusAtEffectSha256,
          authorized_effect_detail_sha256:
            context.authorizedEffectDetailSha256,
          execution_trace_sha256: executionTraceSha256,
          signed_receipt_sha256: receiptEvidence.signed_receipt_sha256,
          verified_signed_payload_sha256:
            verifiedReceipt.verified_signed_payload_sha256,
          target_effect_sha256: context.targetEffectSha256,
          state_effect_binding_sha256: stateEffectBindingSha256,
          consumed_grant_store_sha256_before:
            consumedGrantStoreSha256Before,
          consumed_grant_store_sha256_after: consumedGrantStoreSha256After,
          runtime_state_sha256_before: runtimeStateSha256Before,
          runtime_state_sha256_after: runtimeStateSha256After,
          authority_grant_consumption_count_before:
            store.grant_contract_sha256s.length,
          authority_grant_consumption_count_after:
            committedStore.grant_contract_sha256s.length,
          state_entry_count_before: stateEntryCountBefore,
          state_entry_count_after: stateEntries.length,
        };
        const runtimeTransitionBindingSha256 =
          protectedRecordsRuntimeTransitionBindingSha256V2(
            runtimeTransitionBinding,
          );
        helperDecisionState = nextHelperState;
        return {
          kind: 'accepted',
          authorityResult,
          authorityStatusAtEffect,
          authorityStatusAtEffectSha256,
          authorityStatusRefreshValidatedAtEffect: true,
          executionTrace,
          executionTraceSha256,
          runtimeTransitionBinding,
          runtimeTransitionBindingSha256,
          stateEffectBindingSha256,
        };
      });

      if (atomicResult.kind !== 'accepted') {
        return refuse(atomicResult.decision, {
          targetAssertionMatchesConfig: true,
          receiptDetailHash: verifiedReceipt.payload.detail_hash,
          verifiedSignedPayloadSha256:
            verifiedReceipt.verified_signed_payload_sha256,
          signedReceiptSha256: receiptEvidence.signed_receipt_sha256,
          effectDecision:
            atomicResult.authorityResult?.effectDecision || null,
          effectDecisionSha256:
            atomicResult.authorityResult?.effectDecisionSha256 || null,
          authorityStatusAtEffect:
            atomicResult.authorityStatusAtEffect || context.authorityGrantStatus,
          authorityStatusAtEffectSha256:
            atomicResult.authorityStatusAtEffectSha256 ||
            context.authorityStatusAtEffectSha256,
          authorityStatusRefreshValidatedAtEffect:
            atomicResult.authorityStatusRefreshValidatedAtEffect === true,
        });
      }
      const authorityDecision = protectedRecordsRuntimeAuthorityDecisionV2(
        atomicResult.authorityResult.effectDecision,
      );
      return {
        ...serviceResult(baseResultInput({
          stateEntryCountBefore,
          requestMode,
          directApiAttempted,
          decision: authorityDecision,
          targetAssertionMatchesConfig: true,
          receiptDetailHash: verifiedReceipt.payload.detail_hash,
          verifiedSignedPayloadSha256:
            verifiedReceipt.verified_signed_payload_sha256,
          signedReceiptSha256: receiptEvidence.signed_receipt_sha256,
          effectDecision: atomicResult.authorityResult.effectDecision,
          effectDecisionSha256:
            atomicResult.authorityResult.effectDecisionSha256,
          effectGateBinding: atomicResult.authorityResult.effectGateBinding,
          effectGateBindingSha256:
            atomicResult.authorityResult.effectGateBindingSha256,
          executionTrace: atomicResult.executionTrace,
          executionTraceSha256: atomicResult.executionTraceSha256,
          runtimeTransitionBinding: atomicResult.runtimeTransitionBinding,
          runtimeTransitionBindingSha256:
            atomicResult.runtimeTransitionBindingSha256,
          stateEffectBindingSha256:
            atomicResult.stateEffectBindingSha256,
          authorityGrantSatisfied: true,
          authorityStatusAtEffect: atomicResult.authorityStatusAtEffect,
          authorityStatusAtEffectSha256:
            atomicResult.authorityStatusAtEffectSha256,
          authorityStatusRefreshValidatedAtEffect:
            atomicResult.authorityStatusRefreshValidatedAtEffect,
        })),
        service_write_accepted: true,
        service_state_changed: true,
        state_entry_written: true,
      };
    } catch (error) {
      let grantPersistedAfterFailure = false;
      try {
        const persistedStore = readConsumedStore(consumedPath);
        syncConsumedGrantContractSha256s(
          persistedStore.grant_contract_sha256s,
        );
        grantPersistedAfterFailure =
          persistedStore.grant_contract_sha256s.includes(
            context.authorityGrantContractSha256,
          );
      } catch {
        // Preserve the last validated in-memory view when storage is unreadable.
      }
      const reasonCode =
        grantPersistedAfterFailure && acceptedEffectGateBindingSha256
          ? 'consumed_store_write_failed_after_grant_commit'
          : error instanceof ConsumedStoreError
            ? error.reasonCode
            : 'consumed_store_write_failed';
      return refuse(
        reasonCode === 'consumed_store_write_failed_after_grant_commit'
          ? grantStorePartialCommitDecision()
          : consumedStoreDecision(reasonCode),
        {
          targetAssertionMatchesConfig: true,
          receiptDetailHash: verifiedReceipt.payload.detail_hash,
          verifiedSignedPayloadSha256:
            verifiedReceipt.verified_signed_payload_sha256,
          signedReceiptSha256: receiptEvidence.signed_receipt_sha256,
          effectDecision: acceptedAuthorityResult?.effectDecision || null,
          effectDecisionSha256:
            acceptedAuthorityResult?.effectDecisionSha256 || null,
          effectGateBinding: grantPersistedAfterFailure
            ? acceptedAuthorityResult?.effectGateBinding || null
            : null,
          effectGateBindingSha256: grantPersistedAfterFailure
            ? acceptedEffectGateBindingSha256
            : null,
          authorityGrantSatisfied:
            grantPersistedAfterFailure &&
            acceptedEffectGateBindingSha256 !== null,
          authorityStatusRefreshValidatedAtEffect:
            acceptedAuthorityResult !== null,
        },
      );
    }
  }

  function inspectAuthorityStatusRefresh() {
    return withConsumedStoreLock(consumedPath, () => {
      try {
        const refreshedStatus =
          readProtectedRecordsRuntimeAuthorityStatusRefreshV2(
            authorityStatusRefreshPath,
            context,
          );
        const refreshedStatusSha256 =
          protectedRecordsFixtureAuthorityStatusSha256V2(
            refreshedStatus,
            {
              contract: context.authorityGrantContract,
              expectedContractSha256: context.authorityGrantContractSha256,
              appointment: context.appointment,
              confirmation: context.confirmation,
            },
          );
        const active =
          refreshedStatus.status === 'active' &&
          refreshedStatus.fresh_effect_allowed === true;
        return {
          inspection_type:
            'protected-records-runtime-authority-status-refresh-inspection-v2',
          decision: active ? 'continue_to_effect_gate' : 'refuse',
          reason_code: active
            ? 'authority_status_refresh_active_but_not_authorizing'
            : 'authority_status_not_active',
          authority_status: refreshedStatus,
          authority_status_sha256: refreshedStatusSha256,
          status_refresh_transport:
            PROTECTED_RECORDS_RUNTIME_STATUS_REFRESH_TRANSPORT_V2,
          checked_under_consumed_store_lock: true,
          request_stream_controls_status_refresh: false,
          consequence_executed: false,
          consumed_store_mutated: false,
          runtime_state_mutated: false,
          rollback_resistant_status_custody_proven: false,
        };
      } catch (error) {
        const reasonCode =
          error instanceof ProtectedRecordsAuthorityStatusRefreshError
            ? error.reasonCode
            : 'authority_status_refresh_unavailable_or_invalid';
        return {
          inspection_type:
            'protected-records-runtime-authority-status-refresh-inspection-v2',
          decision: 'refuse',
          reason_code: reasonCode,
          authority_status: null,
          authority_status_sha256: null,
          status_refresh_transport:
            PROTECTED_RECORDS_RUNTIME_STATUS_REFRESH_TRANSPORT_V2,
          checked_under_consumed_store_lock: true,
          request_stream_controls_status_refresh: false,
          consequence_executed: false,
          consumed_store_mutated: false,
          runtime_state_mutated: false,
          rollback_resistant_status_custody_proven: false,
        };
      }
    });
  }

  return {
    applyRequest,
    inspectAuthorityStatusRefresh,
    status() {
      return {
        runtime_profile_id: profileId,
        authority_contract_version: 2,
        authority_grant_contract_sha256:
          context.authorityGrantContractSha256,
        authority_grant_initial_status_sha256:
          context.authorityStatusAtEffectSha256,
        state_storage: 'process-private-memory',
        consumed_authority_grant_store:
          'persistent-single-use-authority-grant-contract-sha256-store',
        state_entry_count: stateEntries.length,
        consumed_authority_grant_count:
          consumedGrantContractSha256s.size,
        state_path_exposed_to_agent: false,
        recognition_rule_exposed_to_agent_request: false,
        authority_material_exposed_to_agent_request: false,
        consequence_clock_source:
          PROTECTED_RECORDS_FIXTURE_AUTHORITY_CLOCK_SOURCE_V2,
        caller_supplied_consequence_time_accepted: false,
        consequence_clock_claim_limit:
          PROTECTED_RECORDS_RUNTIME_CONSEQUENCE_CLOCK_CLAIM_LIMIT_V2,
      };
    },
  };
}

export function assertProtectedRecordsRuntimeServiceResultV2(result) {
  assertExactKeys('Protected records runtime v2 service result', result, [
    'action_class',
    'agent_supplied_authority_material_accepted',
    'agent_supplied_recognition_rule_accepted',
    'agent_supplied_state_paths_accepted',
    'authority_contract_version',
    'authority_grant_appointment',
    'authority_grant_appointment_sha256',
    'authority_grant_confirmation',
    'authority_grant_confirmation_sha256',
    'authority_grant_contract',
    'authority_grant_contract_sha256',
    'authority_effect_gate_binding',
    'authority_effect_gate_binding_sha256',
    'authority_grant_effect_decision',
    'authority_grant_effect_decision_sha256',
    'authority_grant_issuance_decision',
    'authority_grant_issuance_decision_sha256',
    'authority_grant_initial_status',
    'authority_grant_initial_status_sha256',
    'authority_grant_satisfied',
    'authority_grant_status_at_effect',
    'authority_grant_status_at_effect_sha256',
    'authority_source_precondition',
    'authority_status_refresh_claim_limit',
    'authority_status_refresh_transport',
    'authority_status_refresh_validated_at_effect',
    'authorized_effect_detail',
    'authorized_effect_detail_sha256',
    'consequence_path',
    'consumed_authority_grant_count',
    'consumed_authority_grant_store',
    'consumed_store_anchor',
    'consumed_store_lock',
    'consumed_store_rollback_detection',
    'consumed_store_validation',
    'consumed_store_witness',
    'consumed_store_write_model',
    'consumption_identity',
    'decision',
    'direct_api_attempted',
    'evidence_model',
    'execution_trace',
    'execution_trace_sha256',
    'installed_profile_preflight_artifact_body_sha256',
    'issuer_binding_sha256',
    'live_probing',
    'mutation_authoritative_route',
    'non_claims',
    'persistent_consumed_authority_grant_store',
    'profile_sha256',
    'receipt_detail_hash',
    'recognition_boundary',
    'recognition_contract_sha256',
    'record_update_sha256',
    'replay_scope',
    'request_contract',
    'request_mode',
    'result_type',
    'runtime_profile_active',
    'runtime_profile_id',
    'runtime_transition_binding',
    'runtime_transition_binding_sha256',
    'safe_claim_ceiling',
    'service_process_boundary',
    'service_state_changed',
    'service_write_accepted',
    'signed_payload_replay_identity',
    'signed_receipt_sha256',
    'source_precondition_artifact_body_sha256',
    'state_effect_binding_sha256',
    'state_entry_count_after',
    'state_entry_count_before',
    'state_entry_count_delta',
    'state_entry_written',
    'state_storage',
    'target_assertion_matches_config',
    'target_binding_sha256',
    'target_contract_sha256',
    'target_effect_sha256',
    'target_handle',
    'target_handle_source',
    'target_instance_scope',
    'target_kind',
    'target_scope',
    'verified_signed_payload_sha256',
  ]);
  if (
    result.result_type !== PROTECTED_RECORDS_RUNTIME_SERVICE_RESULT_TYPE_V2 ||
    result.authority_contract_version !== 2 ||
    result.evidence_model !== 'local-disposable-runtime-process-profile' ||
    result.live_probing !== false ||
    result.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    result.action_class !== 'records.write' ||
    result.consequence_path !== PROTECTED_RECORDS_CONSEQUENCE_PATH ||
    result.service_process_boundary !== 'local-jsonl-child-process' ||
    result.recognition_boundary !==
      'service-configured-exact-v2-receipt-and-authority-recognition-rule' ||
    result.mutation_authoritative_route !==
      'signed-receipt-verification-then-v2-authority-effect-gate-before-single-lock-grant-consumption-and-runtime-state-append' ||
    result.state_storage !== 'process-private-memory' ||
    result.runtime_profile_active !== true ||
    result.consumed_authority_grant_store !==
      'persistent-single-use-authority-grant-contract-sha256-store' ||
    result.signed_payload_replay_identity !==
      'verified-signed-payload-sha256' ||
    result.consumed_store_lock !== 'launcher-owned-per-store-lockfile' ||
    result.consumed_store_validation !==
      'exact-schema-unique-grant-contract-sha256s' ||
    result.consumed_store_anchor !== 'launcher-owned-local-store-hash-anchor' ||
    result.consumed_store_witness !== 'launcher-owned-local-store-hash-witness' ||
    result.consumed_store_rollback_detection !==
      'single-host-anchor-and-witness-match-before-mutation' ||
    result.consumed_store_write_model !==
      'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness' ||
    result.replay_scope !==
      'helper-signed-payload-identity-and-persistent-authority-grant-contract-sha256' ||
    result.persistent_consumed_authority_grant_store !== true ||
    result.target_kind !== PROTECTED_RECORDS_TARGET_KIND ||
    result.target_scope !== PROTECTED_RECORDS_TARGET_SCOPE ||
    result.target_instance_scope !== 'logical-fixture-not-per-run' ||
    result.target_handle !== PROTECTED_RECORDS_TARGET_HANDLE ||
    result.target_handle_source !== 'launcher-owned-service-config' ||
    result.agent_supplied_state_paths_accepted !== false ||
    result.agent_supplied_recognition_rule_accepted !== false ||
    result.agent_supplied_authority_material_accepted !== false ||
    result.consumption_identity !== 'authority-grant-contract-sha256' ||
    result.request_contract !==
      'agent-request-carries-receipt-record-update-and-routing-metadata-only' ||
    typeof result.authority_status_refresh_validated_at_effect !== 'boolean' ||
    result.authority_status_refresh_transport !==
      PROTECTED_RECORDS_RUNTIME_STATUS_REFRESH_TRANSPORT_V2 ||
    result.authority_status_refresh_claim_limit !==
      PROTECTED_RECORDS_RUNTIME_STATUS_REFRESH_CLAIM_LIMIT_V2
  ) {
    throw new Error('Protected records runtime v2 service result boundary drifted');
  }

  assertProtectedRecordsFixtureAuthoritySourcePreconditionV2(
    result.authority_source_precondition,
  );
  if (
    protectedRecordsFixtureAuthoritySourcePreconditionBodySha256V2(
      result.authority_source_precondition,
    ) !== result.source_precondition_artifact_body_sha256
  ) {
    throw new Error('Protected records runtime v2 source precondition hash drifted');
  }
  assertProtectedRecordsFixtureAuthorityGrantContractV2(
    result.authority_grant_contract,
    { expectedContractSha256: result.authority_grant_contract_sha256 },
  );
  assertProtectedRecordsFixtureAuthorityAppointmentV2(
    result.authority_grant_appointment,
    {
      contract: result.authority_grant_contract,
      expectedContractSha256: result.authority_grant_contract_sha256,
    },
  );
  const authorityOptions = {
    contract: result.authority_grant_contract,
    expectedContractSha256: result.authority_grant_contract_sha256,
    appointment: result.authority_grant_appointment,
  };
  if (
    protectedRecordsFixtureAuthorityAppointmentSha256V2(
      result.authority_grant_appointment,
      authorityOptions,
    ) !== result.authority_grant_appointment_sha256
  ) {
    throw new Error('Protected records runtime v2 appointment hash drifted');
  }
  if (
    protectedRecordsFixtureAuthorityIssuerBindingSha256V2(
      result.authority_grant_appointment,
      authorityOptions,
    ) !== result.issuer_binding_sha256
  ) {
    throw new Error('Protected records runtime v2 issuer binding hash drifted');
  }
  assertProtectedRecordsFixtureAuthorityExactConfirmationV2(
    result.authority_grant_confirmation,
    authorityOptions,
  );
  if (
    protectedRecordsFixtureAuthorityExactConfirmationSha256V2(
      result.authority_grant_confirmation,
      authorityOptions,
    ) !== result.authority_grant_confirmation_sha256
  ) {
    throw new Error('Protected records runtime v2 confirmation hash drifted');
  }
  const statusOptions = {
    ...authorityOptions,
    confirmation: result.authority_grant_confirmation,
  };
  assertProtectedRecordsFixtureAuthorityStatusV2(
    result.authority_grant_initial_status,
    statusOptions,
  );
  if (
    result.authority_grant_initial_status.status !== 'active' ||
    result.authority_grant_initial_status.fresh_effect_allowed !== true ||
    protectedRecordsFixtureAuthorityStatusSha256V2(
      result.authority_grant_initial_status,
      statusOptions,
    ) !== result.authority_grant_initial_status_sha256
  ) {
    throw new Error('Protected records runtime v2 initial active status drifted');
  }
  if (result.authority_grant_status_at_effect === null) {
    if (
      result.authority_grant_status_at_effect_sha256 !== null ||
      result.authority_status_refresh_validated_at_effect !== false
    ) {
      throw new Error('Protected records runtime v2 detached status-at-effect evidence');
    }
  } else {
    assertProtectedRecordsFixtureAuthorityStatusV2(
      result.authority_grant_status_at_effect,
      statusOptions,
    );
    if (
      result.authority_status_refresh_validated_at_effect !== true ||
      protectedRecordsFixtureAuthorityStatusSha256V2(
        result.authority_grant_status_at_effect,
        statusOptions,
      ) !== result.authority_grant_status_at_effect_sha256
    ) {
      throw new Error('Protected records runtime v2 refreshed status-at-effect drifted');
    }
  }
  assertProtectedRecordsAuthorizedEffectDetailV2(
    result.authorized_effect_detail,
    authorityOptions,
  );
  if (
    protectedRecordsAuthorizedEffectDetailSha256V2(
      result.authorized_effect_detail,
      authorityOptions,
    ) !== result.authorized_effect_detail_sha256
  ) {
    throw new Error('Protected records runtime v2 effect-detail hash drifted');
  }
  assertProtectedRecordsFixtureAuthorityDecisionV2(
    result.authority_grant_issuance_decision,
  );
  if (
    result.authority_grant_issuance_decision.phase !== 'issuance' ||
    result.authority_grant_issuance_decision.decision !== 'accept' ||
    protectedRecordsFixtureAuthorityDecisionSha256V2(
      result.authority_grant_issuance_decision,
    ) !== result.authority_grant_issuance_decision_sha256
  ) {
    throw new Error('Protected records runtime v2 issuance decision drifted');
  }
  if (result.authority_grant_effect_decision !== null) {
    if (
      result.authority_grant_status_at_effect === null ||
      result.authority_status_refresh_validated_at_effect !== true
    ) {
      throw new Error(
        'Protected records runtime v2 effect decision lacks refreshed status evidence',
      );
    }
    assertProtectedRecordsFixtureAuthorityDecisionV2(
      result.authority_grant_effect_decision,
    );
    if (
      result.authority_grant_effect_decision.phase !== 'effect' ||
      protectedRecordsFixtureAuthorityDecisionSha256V2(
        result.authority_grant_effect_decision,
      ) !== result.authority_grant_effect_decision_sha256
    ) {
      throw new Error('Protected records runtime v2 effect decision drifted');
    }
    const effectBinding = result.authority_grant_effect_decision.binding;
    if (
      effectBinding.authority_grant_contract_sha256 !==
        result.authority_grant_contract_sha256 ||
      effectBinding.appointment_sha256 !==
        result.authority_grant_appointment_sha256 ||
      effectBinding.confirmation_sha256 !==
        result.authority_grant_confirmation_sha256 ||
      effectBinding.authority_status_sha256 !==
        result.authority_grant_status_at_effect_sha256 ||
      effectBinding.authorized_effect_detail_sha256 !==
        result.authorized_effect_detail_sha256 ||
      effectBinding.issuer_binding_sha256 !== result.issuer_binding_sha256 ||
      effectBinding.issuance_decision_sha256 !==
        result.authority_grant_issuance_decision_sha256 ||
      effectBinding.source_precondition_artifact_body_sha256 !==
        result.source_precondition_artifact_body_sha256 ||
      effectBinding.receipt_audit_event_id !==
        result.authority_grant_contract.scope.receipt_audit_event_id ||
      effectBinding.receipt_delegation_state_sha256 !==
        result.authority_grant_issuance_decision.binding
          .receipt_delegation_state_sha256 ||
      effectBinding.receipt_payload_sha256 !==
        result.verified_signed_payload_sha256 ||
      effectBinding.signed_receipt_sha256 !== result.signed_receipt_sha256
    ) {
      throw new Error('Protected records runtime v2 effect decision binding drifted');
    }
  } else if (result.authority_grant_effect_decision_sha256 !== null) {
    throw new Error('Protected records runtime v2 detached effect decision hash');
  }
  for (const field of [
    'authority_grant_contract_sha256',
    'authority_grant_appointment_sha256',
    'authority_grant_confirmation_sha256',
    'authority_grant_initial_status_sha256',
    'issuer_binding_sha256',
    'authorized_effect_detail_sha256',
    'authority_grant_issuance_decision_sha256',
    'source_precondition_artifact_body_sha256',
    'installed_profile_preflight_artifact_body_sha256',
    'profile_sha256',
    'recognition_contract_sha256',
    'target_contract_sha256',
    'target_binding_sha256',
    'target_effect_sha256',
    'record_update_sha256',
  ]) {
    assertSha256(`Protected records runtime v2 ${field}`, result[field]);
  }
  for (const field of [
    'authority_grant_effect_decision_sha256',
    'authority_grant_status_at_effect_sha256',
    'authority_effect_gate_binding_sha256',
    'receipt_detail_hash',
    'verified_signed_payload_sha256',
    'signed_receipt_sha256',
    'execution_trace_sha256',
    'runtime_transition_binding_sha256',
    'state_effect_binding_sha256',
  ]) {
    if (result[field] !== null) {
      assertSha256(`Protected records runtime v2 ${field}`, result[field]);
    }
  }
  const scope = result.authority_grant_contract.scope;
  const implementation = result.authority_grant_contract.implementation_binding;
  const sourcePrecondition = result.authority_source_precondition;
  if (
    scope.source_precondition_artifact_body_sha256 !==
      result.source_precondition_artifact_body_sha256 ||
    scope.installed_profile_preflight_artifact_body_sha256 !==
      result.installed_profile_preflight_artifact_body_sha256 ||
    scope.launcher_target_binding_sha256 !== result.target_binding_sha256 ||
    scope.profile_sha256 !== result.profile_sha256 ||
    scope.recognition_contract_sha256 !==
      result.recognition_contract_sha256 ||
    scope.target_contract_sha256 !== result.target_contract_sha256 ||
    scope.record_update_sha256 !== result.record_update_sha256 ||
    scope.target_effect_sha256 !== result.target_effect_sha256 ||
    scope.target_handle !== result.target_handle ||
    scope.target_kind !== result.target_kind ||
    scope.target_scope !== result.target_scope ||
    scope.target_instance_scope !== result.target_instance_scope ||
    scope.consequence_path !== result.consequence_path ||
    scope.action_class !== result.action_class ||
    implementation.repository_id !== sourcePrecondition.repository_id ||
    implementation.git_object_format !== sourcePrecondition.git_object_format ||
    implementation.source_commit_oid !== sourcePrecondition.source_commit_oid ||
    implementation.service_artifact_schema_contract_sha256 !==
      sourcePrecondition.service_artifact_schema_contract_sha256 ||
    implementation.terminal_artifact_schema_contract_sha256 !==
      sourcePrecondition.terminal_artifact_schema_contract_sha256 ||
    implementation.no_reexecution_call_graph_sha256 !==
      sourcePrecondition.no_reexecution_call_graph_sha256 ||
    result.authority_grant_issuance_decision.binding
      .authority_grant_contract_sha256 !==
      result.authority_grant_contract_sha256 ||
    result.authority_grant_issuance_decision.binding.appointment_sha256 !==
      result.authority_grant_appointment_sha256 ||
    result.authority_grant_issuance_decision.binding.confirmation_sha256 !==
      result.authority_grant_confirmation_sha256 ||
    result.authority_grant_issuance_decision.binding.authority_status_sha256 !==
      result.authority_grant_initial_status_sha256 ||
    result.authority_grant_issuance_decision.binding
      .authorized_effect_detail_sha256 !==
      result.authorized_effect_detail_sha256 ||
    result.authority_grant_issuance_decision.binding
      .source_precondition_artifact_body_sha256 !==
      result.source_precondition_artifact_body_sha256
  ) {
    throw new Error('Protected records runtime v2 source/authority projection drifted');
  }
  if (result.authority_effect_gate_binding !== null) {
    assertProtectedRecordsRuntimeEffectGateBindingV2(
      result.authority_effect_gate_binding,
    );
    if (
      protectedRecordsRuntimeEffectGateBindingSha256V2(
        result.authority_effect_gate_binding,
      ) !== result.authority_effect_gate_binding_sha256 ||
      result.authority_effect_gate_binding.authority_grant_contract_sha256 !==
        result.authority_grant_contract_sha256 ||
      result.authority_effect_gate_binding.appointment_sha256 !==
        result.authority_grant_appointment_sha256 ||
      result.authority_effect_gate_binding.confirmation_sha256 !==
        result.authority_grant_confirmation_sha256 ||
      result.authority_effect_gate_binding
        .authority_status_at_effect_sha256 !==
        result.authority_grant_status_at_effect_sha256 ||
      result.authority_effect_gate_binding
        .authorized_effect_detail_sha256 !==
        result.authorized_effect_detail_sha256 ||
      result.authority_effect_gate_binding.issuance_decision_sha256 !==
        result.authority_grant_issuance_decision_sha256 ||
      result.authority_effect_gate_binding.effect_decision_sha256 !==
        result.authority_grant_effect_decision_sha256 ||
      result.authority_effect_gate_binding.signed_receipt_sha256 !==
        result.signed_receipt_sha256 ||
      result.authority_effect_gate_binding.receipt_payload_sha256 !==
        result.verified_signed_payload_sha256 ||
      result.authority_effect_gate_binding.issuer_binding_sha256 !==
        result.issuer_binding_sha256 ||
      result.authority_effect_gate_binding
        .source_precondition_artifact_body_sha256 !==
        result.source_precondition_artifact_body_sha256 ||
      result.authority_effect_gate_binding
        .installed_profile_preflight_artifact_body_sha256 !==
        result.installed_profile_preflight_artifact_body_sha256 ||
      result.authority_effect_gate_binding.launcher_target_binding_sha256 !==
        result.target_binding_sha256 ||
      result.authority_effect_gate_binding.profile_sha256 !==
        result.profile_sha256 ||
      result.authority_effect_gate_binding.recognition_contract_sha256 !==
        result.recognition_contract_sha256 ||
      result.authority_effect_gate_binding.target_contract_sha256 !==
        result.target_contract_sha256 ||
      result.authority_effect_gate_binding.target_effect_sha256 !==
        result.target_effect_sha256
    ) {
      throw new Error('Protected records runtime v2 effect-gate projection drifted');
    }
  } else if (result.authority_effect_gate_binding_sha256 !== null) {
    throw new Error('Protected records runtime v2 detached effect-gate hash');
  }
  if (result.execution_trace !== null) {
    assertProtectedRecordsRuntimeExecutionTraceV2(result.execution_trace);
    if (
      protectedRecordsRuntimeExecutionTraceSha256V2(result.execution_trace) !==
        result.execution_trace_sha256 ||
      result.execution_trace.authority_effect_gate_binding_sha256 !==
        result.authority_effect_gate_binding_sha256 ||
      result.execution_trace.authority_status_at_effect_sha256 !==
        result.authority_grant_status_at_effect_sha256 ||
      result.execution_trace.effect_decision_sha256 !==
        result.authority_grant_effect_decision_sha256 ||
      result.execution_trace.signed_receipt_sha256 !==
        result.signed_receipt_sha256
    ) {
      throw new Error('Protected records runtime v2 execution trace drifted');
    }
  } else if (result.execution_trace_sha256 !== null) {
    throw new Error('Protected records runtime v2 detached execution trace hash');
  }
  if (result.runtime_transition_binding !== null) {
    assertProtectedRecordsRuntimeTransitionBindingV2(
      result.runtime_transition_binding,
    );
    if (
      protectedRecordsRuntimeTransitionBindingSha256V2(
        result.runtime_transition_binding,
      ) !== result.runtime_transition_binding_sha256 ||
      result.runtime_transition_binding.authority_grant_contract_sha256 !==
        result.authority_grant_contract_sha256 ||
      result.runtime_transition_binding
        .authority_effect_gate_binding_sha256 !==
        result.authority_effect_gate_binding_sha256 ||
      result.runtime_transition_binding.execution_trace_sha256 !==
        result.execution_trace_sha256 ||
      result.runtime_transition_binding
        .authority_grant_effect_decision_sha256 !==
        result.authority_grant_effect_decision_sha256 ||
      result.runtime_transition_binding
        .authority_grant_issuance_decision_sha256 !==
        result.authority_grant_issuance_decision_sha256 ||
      result.runtime_transition_binding
        .authority_grant_status_at_effect_sha256 !==
        result.authority_grant_status_at_effect_sha256 ||
      result.runtime_transition_binding.authorized_effect_detail_sha256 !==
        result.authorized_effect_detail_sha256 ||
      result.runtime_transition_binding.signed_receipt_sha256 !==
        result.signed_receipt_sha256 ||
      result.runtime_transition_binding.verified_signed_payload_sha256 !==
        result.verified_signed_payload_sha256 ||
      result.runtime_transition_binding.target_effect_sha256 !==
        result.target_effect_sha256 ||
      result.runtime_transition_binding.state_effect_binding_sha256 !==
        result.state_effect_binding_sha256 ||
      result.runtime_transition_binding.state_entry_count_before !==
        result.state_entry_count_before ||
      result.runtime_transition_binding.state_entry_count_after !==
        result.state_entry_count_after
    ) {
      throw new Error('Protected records runtime v2 transition projection drifted');
    }
  } else if (result.runtime_transition_binding_sha256 !== null) {
    throw new Error('Protected records runtime v2 detached transition hash');
  }
  for (const field of [
    'service_write_accepted',
    'service_state_changed',
    'state_entry_written',
    'authority_grant_satisfied',
  ]) {
    if (typeof result[field] !== 'boolean') {
      throw new Error(`Protected records runtime v2 ${field} must be boolean`);
    }
  }
  for (const field of [
    'state_entry_count_before',
    'state_entry_count_after',
    'state_entry_count_delta',
    'consumed_authority_grant_count',
  ]) {
    if (!Number.isInteger(result[field]) || result[field] < 0) {
      throw new Error(`Protected records runtime v2 ${field} must be non-negative integer`);
    }
  }
  if (![true, false, null].includes(result.target_assertion_matches_config)) {
    throw new Error('Protected records runtime v2 target assertion flag drifted');
  }
  if (
    result.state_entry_count_delta !==
      result.state_entry_count_after - result.state_entry_count_before ||
    result.service_write_accepted !== result.service_state_changed ||
    result.service_write_accepted !== result.state_entry_written
  ) {
    throw new Error('Protected records runtime v2 mutation flags drifted');
  }
  if (result.service_write_accepted) {
    if (
      result.state_entry_count_delta !== 1 ||
      result.authority_grant_satisfied !== true ||
      result.target_assertion_matches_config !== true ||
      result.authority_status_refresh_validated_at_effect !== true ||
      result.authority_grant_status_at_effect?.status !== 'active' ||
      result.authority_grant_status_at_effect?.fresh_effect_allowed !== true ||
      result.authority_grant_status_at_effect_sha256 !==
        result.authority_grant_initial_status_sha256 ||
      result.receipt_detail_hash !== result.authorized_effect_detail_sha256 ||
      !result.authority_grant_effect_decision ||
      result.authority_grant_effect_decision.decision !== 'accept' ||
      !result.authority_effect_gate_binding ||
      !result.execution_trace ||
      !result.runtime_transition_binding ||
      result.runtime_transition_binding.binding_type !==
        PROTECTED_RECORDS_RUNTIME_TRANSITION_BINDING_TYPE_V2
    ) {
      throw new Error(
        'Protected records runtime v2 accepted crossing evidence drifted',
      );
    }
  } else if (
    result.state_entry_count_delta !== 0 ||
    result.state_effect_binding_sha256 !== null ||
    result.runtime_transition_binding !== null ||
    result.runtime_transition_binding_sha256 !== null ||
    result.execution_trace !== null ||
    result.execution_trace_sha256 !== null
  ) {
    throw new Error('Protected records runtime v2 refusal mutated state');
  }
  requireObject('Protected records runtime v2 decision', result.decision);
  if (!['accept', 'refuse'].includes(result.decision.decision)) {
    throw new Error('Protected records runtime v2 decision drifted');
  }
  if (
    result.safe_claim_ceiling !==
      'One exact local disposable fixture crossing can be accepted only after the runtime independently verifies its signed receipt and accepts the exact v2 human-confirmed authority contract before one-use consumption and process-private state mutation.'
  ) {
    throw new Error('Protected records runtime v2 claim ceiling drifted');
  }
  assertExactArray('Protected records runtime v2 non-claims', result.non_claims, NON_CLAIMS);
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(result));
  return true;
}

export function protectedRecordsReplacementCrossingInputsFromRuntimeServiceResultV2(
  result,
) {
  assertProtectedRecordsRuntimeServiceResultV2(result);
  if (
    result.service_write_accepted !== true ||
    result.authority_grant_satisfied !== true
  ) {
    throw new Error(
      'Protected records replacement crossing inputs require one accepted v2 runtime crossing',
    );
  }
  return Object.freeze({
    activationConfirmationArtifactBodySha256:
      result.authority_grant_confirmation_sha256,
    authorityGrantContractSha256:
      result.authority_grant_contract_sha256,
    authorityStatusAtEffectArtifactBodySha256:
      result.authority_grant_status_at_effect_sha256,
    authorizedEffectDetailSha256:
      result.authorized_effect_detail_sha256,
    effectDecisionSha256:
      result.authority_grant_effect_decision_sha256,
    executionTraceSha256: result.execution_trace_sha256,
    installedProfilePreflightArtifactBodySha256:
      result.installed_profile_preflight_artifact_body_sha256,
    issuerAppointmentArtifactBodySha256:
      result.authority_grant_appointment_sha256,
    issuanceDecisionSha256:
      result.authority_grant_issuance_decision_sha256,
    receiptEnvelopeBodySha256: result.signed_receipt_sha256,
    recognitionContractSha256: result.recognition_contract_sha256,
    recordUpdateSha256: result.record_update_sha256,
    runtimeProfileSha256: result.profile_sha256,
    runtimeTransitionSha256: result.runtime_transition_binding_sha256,
    sourcePreconditionArtifactBodySha256:
      result.source_precondition_artifact_body_sha256,
    targetBindingSha256: result.target_binding_sha256,
    targetContractSha256: result.target_contract_sha256,
    targetEffectSha256: result.target_effect_sha256,
  });
}

export function protectedRecordsReplacementSourceBindingFromRuntimeServiceResultV2(
  result,
) {
  assertProtectedRecordsRuntimeServiceResultV2(result);
  if (
    result.service_write_accepted !== true ||
    result.authority_grant_satisfied !== true
  ) {
    throw new Error(
      'Protected records replacement source binding requires one accepted v2 runtime crossing',
    );
  }
  const source = result.authority_source_precondition;
  return Object.freeze({
    repository_id: source.repository_id,
    git_object_format: source.git_object_format,
    source_commit_oid: source.source_commit_oid,
    service_artifact_schema_contract_sha256:
      source.service_artifact_schema_contract_sha256,
    terminal_artifact_schema_contract_sha256:
      source.terminal_artifact_schema_contract_sha256,
    no_reexecution_call_graph_sha256:
      source.no_reexecution_call_graph_sha256,
    installed_profile_preflight_artifact_body_sha256:
      result.installed_profile_preflight_artifact_body_sha256,
    source_precondition_artifact_body_sha256:
      result.source_precondition_artifact_body_sha256,
  });
}

export function assertProtectedRecordsRuntimeServiceResult(result) {
  assertExactKeys('Protected records runtime service result', result, [
    'action_class',
    'agent_supplied_recognition_rule_accepted',
    'agent_supplied_state_paths_accepted',
    'authority_grant_contract_sha256',
    'authority_grant_crossing_binding_sha256',
    'authority_grant_satisfied',
    'authorized_effect_detail_sha256',
    'consumed_authority_grant_store',
    'consumed_authority_grant_count',
    'consumption_identity',
    'consumed_store_anchor',
    'consumed_store_witness',
    'consumed_store_lock',
    'consumed_store_rollback_detection',
    'consumed_store_validation',
    'consumed_store_write_model',
    'consequence_path',
    'decision',
    'direct_api_attempted',
    'evidence_model',
    'live_probing',
    'mutation_authoritative_route',
    'non_claims',
    'persistent_consumed_authority_grant_store',
    'recognition_boundary',
    'record_update_hash',
    'receipt_detail_hash',
    'replay_scope',
    'request_contract',
    'request_mode',
    'result_type',
    'runtime_profile_active',
    'runtime_profile_id',
    'runtime_transition_binding',
    'safe_claim_ceiling',
    'service_process_boundary',
    'service_state_changed',
    'service_write_accepted',
    'state_entry_count_after',
    'state_entry_count_before',
    'state_entry_count_delta',
    'state_entry_written',
    'state_effect_binding_sha256',
    'state_storage',
    'signed_payload_replay_identity',
    'target_assertion_matches_config',
    'target_binding_sha256',
    'target_effect_hash',
    'target_handle',
    'target_handle_source',
    'target_instance_scope',
    'target_kind',
    'target_scope',
    'verified_signed_payload_identity_present',
  ]);
  if (
    result.result_type !== PROTECTED_RECORDS_RUNTIME_SERVICE_RESULT_TYPE ||
    result.evidence_model !== 'local-disposable-runtime-process-profile' ||
    result.live_probing !== false ||
    result.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    result.runtime_profile_active !== true ||
    result.action_class !== 'records.write' ||
    result.service_process_boundary !== 'local-jsonl-child-process' ||
    result.recognition_boundary !== 'service-configured-recognition-rule' ||
    result.mutation_authoritative_route !==
      'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation' ||
    result.state_storage !== 'process-private-memory' ||
    result.consumed_authority_grant_store !==
      'persistent-single-use-authority-grant-contract-sha256-store' ||
    result.consumption_identity !== 'authority-grant-contract-sha256' ||
    result.signed_payload_replay_identity !== 'verified-signed-payload-sha256' ||
    result.consumed_store_lock !== 'launcher-owned-per-store-lockfile' ||
    result.consumed_store_validation !== 'exact-schema-unique-grant-contract-sha256s' ||
    result.consumed_store_anchor !== 'launcher-owned-local-store-hash-anchor' ||
    result.consumed_store_witness !== 'launcher-owned-local-store-hash-witness' ||
    result.consumed_store_rollback_detection !==
      'single-host-anchor-and-witness-match-before-mutation' ||
    result.consumed_store_write_model !==
      'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness' ||
    result.replay_scope !==
      'helper-signed-payload-identity-and-persistent-authority-grant-contract-sha256' ||
    result.persistent_consumed_authority_grant_store !== true ||
    result.agent_supplied_state_paths_accepted !== false ||
    result.agent_supplied_recognition_rule_accepted !== false ||
    result.request_contract !== 'agent-request-carries-receipt-record-update-and-routing-metadata-only' ||
    result.consequence_path !== PROTECTED_RECORDS_CONSEQUENCE_PATH ||
    result.target_kind !== PROTECTED_RECORDS_TARGET_KIND ||
    result.target_scope !== PROTECTED_RECORDS_TARGET_SCOPE ||
    result.target_instance_scope !== 'logical-fixture-not-per-run' ||
    result.target_handle !== PROTECTED_RECORDS_TARGET_HANDLE ||
    result.target_handle_source !== 'launcher-owned-service-config' ||
    !/^[a-f0-9]{64}$/.test(result.target_binding_sha256 || '') ||
    result.safe_claim_ceiling !== SAFE_CLAIM_CEILING
  ) {
    throw new Error('Protected records runtime service result contract drifted');
  }
  if (!/^[a-f0-9]{64}$/.test(result.record_update_hash || '')) {
    throw new Error('Protected records runtime record update hash must be sha256 hex');
  }
  for (const key of [
    'authority_grant_crossing_binding_sha256',
    'receipt_detail_hash',
    'state_effect_binding_sha256',
  ]) {
    if (result[key] !== null && !/^[a-f0-9]{64}$/.test(result[key])) {
      throw new Error(`Protected records runtime ${key} must be null or sha256 hex`);
    }
  }
  for (const key of [
    'authority_grant_contract_sha256',
    'authorized_effect_detail_sha256',
    'target_effect_hash',
  ]) {
    if (!/^[a-f0-9]{64}$/.test(result[key] || '')) {
      throw new Error(`Protected records runtime ${key} must be sha256 hex`);
    }
  }
  if (![true, false, null].includes(result.target_assertion_matches_config)) {
    throw new Error('Protected records runtime target assertion match flag drifted');
  }
  for (const key of [
    'service_write_accepted',
    'service_state_changed',
    'state_entry_written',
    'direct_api_attempted',
    'authority_grant_satisfied',
    'verified_signed_payload_identity_present',
  ]) {
    if (typeof result[key] !== 'boolean') {
      throw new Error(`Protected records runtime ${key} must be boolean`);
    }
  }
  for (const key of [
    'state_entry_count_before',
    'state_entry_count_after',
    'state_entry_count_delta',
    'consumed_authority_grant_count',
  ]) {
    if (!Number.isInteger(result[key]) || result[key] < 0) {
      throw new Error(`Protected records runtime ${key} must be a non-negative integer`);
    }
  }
  if (result.state_entry_count_delta !== result.state_entry_count_after - result.state_entry_count_before) {
    throw new Error('Protected records runtime state entry count delta drifted');
  }
  if (result.service_write_accepted !== result.service_state_changed || result.service_write_accepted !== result.state_entry_written) {
    throw new Error('Protected records runtime accepted/change/state flags diverged');
  }
  if (result.service_write_accepted && result.state_entry_count_delta !== 1) {
    throw new Error('Protected records runtime must append exactly one state entry when accepted');
  }
  if (
    result.service_write_accepted &&
    (
      result.target_assertion_matches_config !== true ||
      result.receipt_detail_hash !== result.authorized_effect_detail_sha256 ||
      result.authority_grant_crossing_binding_sha256 === null ||
      result.authority_grant_satisfied !== true ||
      result.verified_signed_payload_identity_present !== true ||
      result.state_effect_binding_sha256 === null ||
      !result.runtime_transition_binding
    )
  ) {
    throw new Error('Protected records runtime accepted target/effect/receipt/state binding drifted');
  }
  if (!result.service_write_accepted && result.state_effect_binding_sha256 !== null) {
    throw new Error('Protected records runtime refusal cannot claim a state-effect binding hash');
  }
  if (!result.service_write_accepted && result.state_entry_count_delta !== 0) {
    throw new Error('Protected records runtime refusal changed service state');
  }
  if (!result.service_write_accepted && result.runtime_transition_binding !== null) {
    throw new Error('Protected records runtime refusal cannot claim an ordered single-lock transition binding');
  }
  if (result.service_write_accepted) {
    const binding = result.runtime_transition_binding;
    assertExactKeys('Protected records runtime transition binding', binding, [
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
    ]) {
      assertSha256(`Protected records runtime transition ${key}`, binding[key]);
    }
    if (
      binding.binding_type !== 'protected-records-runtime-ordered-single-lock-transition-binding-v1' ||
      binding.authority_grant_contract_sha256 !== result.authority_grant_contract_sha256 ||
      binding.authority_grant_crossing_binding_sha256 !==
        result.authority_grant_crossing_binding_sha256 ||
      binding.authorized_effect_detail_sha256 !== result.authorized_effect_detail_sha256 ||
      binding.target_effect_sha256 !== result.target_effect_hash ||
      binding.authority_grant_consumption_count_after -
        binding.authority_grant_consumption_count_before !== 1 ||
      binding.state_entry_count_after - binding.state_entry_count_before !== 1 ||
      !(binding.signed_payload_replay_check_sequence < binding.effect_gate_sequence &&
        binding.effect_gate_sequence < binding.grant_store_commit_sequence &&
        binding.grant_store_commit_sequence < binding.state_append_sequence &&
        binding.state_append_sequence < binding.helper_state_promotion_sequence) ||
      binding.signed_payload_replay_check_preceded_effect_gate !== true ||
      binding.effect_gate_preceded_grant_store_commit !== true ||
      binding.grant_store_commit_preceded_state_append !== true ||
      binding.state_append_preceded_helper_state_promotion !== true ||
      binding.one_launcher_store_lock_held_across_transition !== true
    ) {
      throw new Error('Protected records runtime ordered single-lock transition binding drifted');
    }
  }
  requireObject('Protected records runtime decision', result.decision);
  if (!['accept', 'refuse'].includes(result.decision.decision)) {
    throw new Error('Protected records runtime decision must be accept or refuse');
  }
  if (!result.decision.reason_code) {
    throw new Error('Protected records runtime decision must carry reason_code');
  }
  assertExactArray('Protected records runtime non-claims', result.non_claims, NON_CLAIMS);
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(result));
  return true;
}

function writeJsonFile(scratch, label, value) {
  const path = join(scratch, `${label}.json`);
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
  return path;
}

function runRuntimeService(config, requests, scratch, label) {
  const configPath = writeJsonFile(scratch, `${label}-config`, config);
  const input = `${requests.map((request) => JSON.stringify(request)).join('\n')}\n`;
  const run = spawnSync(ZLAR_BIN, ['protected-records-runtime-service', '--config', configPath], {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    encoding: 'utf8',
    input,
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
  if (run.error) {
    throw new Error('Protected records runtime service subprocess failed.');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(run.stdout);
  assertNoUnsafeProtectedRecordsRuntimeProfileText(run.stderr);
  const results = run.stdout.trim().split(/\n/).filter(Boolean).map((line) => {
    const result = JSON.parse(line);
    assertProtectedRecordsRuntimeServiceResult(result);
    return result;
  });
  if (run.status !== 0 || run.stderr !== '' || results.length !== requests.length) {
    throw new Error('Protected records runtime service subprocess contract failed.');
  }
  return { run, results };
}

function runtimeConfig({
  trusted,
  nowEpoch,
  consumedPath,
  anchorPath = defaultConsumedStoreAnchorPath(consumedPath),
  witnessPath = defaultConsumedStoreWitnessPath(consumedPath),
  authorizedRecordUpdate = {
    ...PROTECTED_RECORDS_FIXTURE_AUTHORIZED_RECORD_UPDATE,
  },
  authorityGrantAppointmentOverride = undefined,
  authorityGrantAppointmentStatus = 'active',
  authorityGrantRevokedAtEpoch = null,
  authorityGrantRevocationReasonCode = null,
  authorityGrantValidFromEpoch = PROTECTED_RECORDS_FIXTURE_AUTHORITY_VALID_FROM_EPOCH,
  authorityGrantExpiresAtEpoch = PROTECTED_RECORDS_FIXTURE_AUTHORITY_EXPIRES_AT_EPOCH,
  issuerStatus = 'active',
  includeStatus = true,
  consumedGrantStoreCommitFailureMode = null,
  runtimeStateAppendFailureMode = null,
} = {}) {
  const recognitionRuleSnapshot = recognitionRule({
    trusted,
    status: issuerStatus,
    includeStatus,
  });
  const targetBinding = createProtectedRecordsRuntimeTargetBinding();
  const authority = fixtureAuthorityConfig({
    trusted,
    nowEpoch,
    authorizedRecordUpdate,
    recognitionRuleSnapshot,
    targetBinding,
    appointmentStatus: authorityGrantAppointmentStatus,
    revokedAtEpoch: authorityGrantRevokedAtEpoch,
    revocationReasonCode: authorityGrantRevocationReasonCode,
    validFromEpoch: authorityGrantValidFromEpoch,
    expiresAtEpoch: authorityGrantExpiresAtEpoch,
  });
  const config = {
    profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    action_class: 'records.write',
    now_epoch: nowEpoch,
    consumed_grants_path: consumedPath,
    consumed_grant_store_anchor_path: anchorPath,
    consumed_grant_store_witness_path: witnessPath,
    authorized_record_update: authorizedRecordUpdate,
    authority_grant_contract: authority.contract,
    authority_grant_appointment:
      authorityGrantAppointmentOverride === undefined
        ? authority.appointment
        : authorityGrantAppointmentOverride,
    authority_grant_issuance_decision: authority.issuanceDecision,
    recognition_rule: recognitionRuleSnapshot,
    target_binding: targetBinding,
  };
  if (runtimeStateAppendFailureMode) {
    config.runtime_state_append_failure_mode = runtimeStateAppendFailureMode;
  }
  if (consumedGrantStoreCommitFailureMode) {
    config.consumed_grant_store_commit_failure_mode =
      consumedGrantStoreCommitFailureMode;
  }
  return config;
}

function requestFor({
  receipt,
  recordUpdate,
  requestMode = 'recognized_runtime_write',
  targetHandle = PROTECTED_RECORDS_TARGET_HANDLE,
  overrides = {},
}) {
  return {
    runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    receipt,
    record_update: recordUpdate,
    request_mode: requestMode,
    target_handle: targetHandle,
    ...overrides,
  };
}

function proofCase({
  caseId,
  result,
  serviceProcessInvocation,
  requestOrdinal,
  separateProcessFromAccepted,
  consumedStoreExistsAfter,
  consumedStoreAnchorExistsAfter,
}) {
  return {
    case_id: caseId,
    service_process_boundary: 'local-jsonl-child-process',
    service_process_invocation: serviceProcessInvocation,
    separate_process_from_accepted: separateProcessFromAccepted,
    request_ordinal: requestOrdinal,
    service_write_accepted: result.service_write_accepted,
    reason_code: result.decision.reason_code,
    state_entry_count_before: result.state_entry_count_before,
    state_entry_count_after: result.state_entry_count_after,
    state_entry_count_delta: result.state_entry_count_delta,
    consumed_authority_grant_count: result.consumed_authority_grant_count,
    consumed_store_exists_after: consumedStoreExistsAfter,
    consumed_store_anchor_exists_after: consumedStoreAnchorExistsAfter,
    direct_api_attempted: result.direct_api_attempted,
    agent_supplied_state_paths_accepted: result.agent_supplied_state_paths_accepted,
    agent_supplied_recognition_rule_accepted: result.agent_supplied_recognition_rule_accepted,
  };
}

function boundaryObservation({
  observationId,
  boundary,
  result,
  conclusion,
}) {
  return {
    observation_id: observationId,
    boundary,
    service_write_accepted: result.service_write_accepted,
    reason_code: result.decision.reason_code,
    state_entry_count_before: result.state_entry_count_before,
    state_entry_count_after: result.state_entry_count_after,
    state_entry_count_delta: result.state_entry_count_delta,
    consumed_authority_grant_count: result.consumed_authority_grant_count,
    conclusion,
  };
}

export function runProtectedRecordsRuntimeProfileProof({
  nowEpoch = PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH,
} = {}) {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
    'Protected records runtime-profile proof generation',
  );
  const scratch = mkdtempSync(join(tmpdir(), 'zlar-protected-records-runtime-profile-'));
  try {
    const trusted = keyFixture(scratch, 'trusted');
    const unknown = keyFixture(scratch, 'unknown');
    const recordUpdate = {
      ...PROTECTED_RECORDS_FIXTURE_AUTHORIZED_RECORD_UPDATE,
    };
    const activeConsumedPath = join(scratch, 'active-consumed-grants.json');
    const activeAnchorPath = defaultConsumedStoreAnchorPath(activeConsumedPath);
    const activeWitnessPath = defaultConsumedStoreWitnessPath(activeConsumedPath);
    const activeConfig = runtimeConfig({ trusted, nowEpoch, consumedPath: activeConsumedPath });
    const acceptedReceipt = signedReceipt({
      authorityGrantContract: activeConfig.authority_grant_contract,
      key: trusted,
      nowEpoch,
      recordUpdate,
    });

    const activeRequests = [
      requestFor({ receipt: acceptedReceipt, recordUpdate }),
      requestFor({ receipt: acceptedReceipt, recordUpdate, requestMode: 'replay_runtime_write' }),
      requestFor({ receipt: null, recordUpdate, requestMode: 'missing_receipt_runtime_write' }),
      requestFor({
        receipt: { ...acceptedReceipt, payload: `${acceptedReceipt.payload.slice(0, -2)}xx` },
        recordUpdate,
        requestMode: 'invalid_receipt_runtime_write',
      }),
      requestFor({
        receipt: signedReceipt({ key: unknown, nowEpoch, recordUpdate }),
        recordUpdate,
        requestMode: 'unknown_issuer_runtime_write',
      }),
      requestFor({
        receipt: signedReceipt({
          key: trusted,
          nowEpoch,
          recordUpdate,
          overrides: { policy_version: 'recognition-policy-old' },
        }),
        recordUpdate,
        requestMode: 'wrong_policy_runtime_write',
      }),
      requestFor({
        receipt: signedReceipt({
          key: trusted,
          nowEpoch,
          recordUpdate,
          overrides: { domain: 'billing' },
        }),
        recordUpdate,
        requestMode: 'wrong_domain_runtime_write',
      }),
      requestFor({
        receipt: signedReceipt({
          key: trusted,
          nowEpoch,
          recordUpdate,
          overrides: { action: 'records.delete' },
        }),
        recordUpdate,
        requestMode: 'wrong_tool_runtime_write',
      }),
      requestFor({
        receipt: signedReceipt({ key: trusted, nowEpoch, recordUpdate }),
        recordUpdate,
        requestMode: 'wrong_runtime_profile_id_runtime_write',
        overrides: { runtime_profile_id: 'wrong-protected-records-runtime-profile' },
      }),
      requestFor({
        receipt: signedReceipt({
          key: trusted,
          nowEpoch,
          recordUpdate,
          overrides: { id: 'protected-records-runtime-999' },
        }),
        recordUpdate,
        requestMode: 'wrong_audit_event_runtime_write',
      }),
      requestFor({
        receipt: signedReceipt({
          key: trusted,
          nowEpoch,
          recordUpdate,
          overrides: {
            detail: {
              record_id: 'runtime-record-002',
              operation: 'update_status',
            },
          },
        }),
        recordUpdate,
        requestMode: 'wrong_detail_runtime_write',
      }),
      requestFor({
        receipt: signedReceipt({
          key: trusted,
          nowEpoch,
          recordUpdate,
          overrides: { outcome: 'deny' },
        }),
        recordUpdate,
        requestMode: 'non_boarding_runtime_write',
      }),
      requestFor({
        receipt: signedReceipt({
          key: trusted,
          nowEpoch,
          recordUpdate,
          overrides: { ts: isoSecondsAgo(nowEpoch, 600) },
        }),
        recordUpdate,
        requestMode: 'stale_receipt_runtime_write',
      }),
      requestFor({
        receipt: null,
        recordUpdate,
        requestMode: 'direct_api_write_without_receipt',
        overrides: { direct_api_write: true },
      }),
      requestFor({
        receipt: signedReceipt({ key: trusted, nowEpoch, recordUpdate }),
        recordUpdate,
        requestMode: 'direct_api_write_without_receipt',
        overrides: { direct_api_write: true },
      }),
      requestFor({
        receipt: signedReceipt({ key: trusted, nowEpoch, recordUpdate }),
        recordUpdate,
        requestMode: 'agent_supplied_state_path_runtime_write',
        overrides: { state_path: '/tmp/agent-supplied-state.jsonl' },
      }),
      requestFor({
        receipt: signedReceipt({ key: trusted, nowEpoch, recordUpdate }),
        recordUpdate,
        requestMode: 'agent_supplied_consumed_grants_path_runtime_write',
        overrides: { consumed_grants_path: '/tmp/agent-supplied-consumed-grants.json' },
      }),
      requestFor({
        receipt: signedReceipt({ key: trusted, nowEpoch, recordUpdate }),
        recordUpdate,
        requestMode: 'agent_supplied_consumed_grant_store_anchor_path_runtime_write',
        overrides: { consumed_grant_store_anchor_path: '/tmp/agent-supplied-consumed-store-anchor.json' },
      }),
      requestFor({
        receipt: signedReceipt({ key: trusted, nowEpoch, recordUpdate }),
        recordUpdate,
        requestMode: 'agent_supplied_fixture_mode_runtime_write',
        overrides: { fixture_mode: true },
      }),
      requestFor({
        receipt: signedReceipt({ key: trusted, nowEpoch, recordUpdate }),
        recordUpdate,
        requestMode: 'agent_supplied_recognition_rule_runtime_write',
        overrides: { recognition_rule: recognitionRule({ trusted }) },
      }),
      requestFor({
        receipt: signedReceipt({ key: trusted, nowEpoch, recordUpdate }),
        recordUpdate,
        requestMode: 'agent_supplied_authority_grant_runtime_write',
        overrides: { authority_grant_contract: activeConfig.authority_grant_contract },
      }),
      requestFor({
        receipt: signedReceipt({ key: trusted, nowEpoch, recordUpdate }),
        recordUpdate,
        requestMode: 'unsupported_request_field_runtime_write',
        overrides: { mutate_without_governance: true },
      }),
    ];
    const activeRun = runRuntimeService(activeConfig, activeRequests, scratch, 'active');
    const restartReplayRun = runRuntimeService(
      activeConfig,
      [requestFor({ receipt: acceptedReceipt, recordUpdate, requestMode: 'replay_runtime_write_after_service_restart' })],
      scratch,
      'restart-replay'
    );
    const invalidConsumedPath = join(scratch, 'invalid-consumed-grants.json');
    writeFileSync(invalidConsumedPath, '{"store_type":"not-json"');
    const invalidStoreRun = runRuntimeService(
      runtimeConfig({ trusted, nowEpoch, consumedPath: invalidConsumedPath }),
      [requestFor({
        receipt: signedReceipt({ key: trusted, nowEpoch, recordUpdate }),
        recordUpdate,
        requestMode: 'invalid_consumed_store_runtime_write',
      })],
      scratch,
      'invalid-consumed-store'
    );
    const duplicateConsumedPath = join(scratch, 'duplicate-consumed-grants.json');
    writeFileSync(duplicateConsumedPath, `${JSON.stringify({
      store_type: PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_TYPE,
      consumption_identity: 'authority-grant-contract-sha256',
      grant_contract_sha256s: ['d'.repeat(64), 'd'.repeat(64)],
    }, null, 2)}\n`);
    const duplicateStoreRun = runRuntimeService(
      runtimeConfig({ trusted, nowEpoch, consumedPath: duplicateConsumedPath }),
      [requestFor({
        receipt: signedReceipt({ key: trusted, nowEpoch, recordUpdate }),
        recordUpdate,
        requestMode: 'duplicate_consumed_store_runtime_write',
      })],
      scratch,
      'duplicate-consumed-store'
    );
    const lockedConsumedPath = join(scratch, 'locked-consumed-grants.json');
    writeFileSync(consumedStoreLockPath(lockedConsumedPath), `${JSON.stringify({
      lock_type: 'zlar-protected-records-runtime-consumed-store-lock-v1',
      test_lock: true,
    }, null, 2)}\n`);
    const lockedStoreRun = runRuntimeService(
      runtimeConfig({ trusted, nowEpoch, consumedPath: lockedConsumedPath }),
      [requestFor({
        receipt: signedReceipt({ key: trusted, nowEpoch, recordUpdate }),
        recordUpdate,
        requestMode: 'locked_consumed_store_runtime_write',
      })],
      scratch,
      'locked-consumed-store'
    );
    const invalidAnchorConsumedPath = join(scratch, 'invalid-anchor-consumed-grants.json');
    writeConsumedStore(invalidAnchorConsumedPath, []);
    writeConsumedStoreWitness(
      defaultConsumedStoreWitnessPath(invalidAnchorConsumedPath),
      normalizedConsumedStore([])
    );
    writeFileSync(defaultConsumedStoreAnchorPath(invalidAnchorConsumedPath), `${JSON.stringify({
      anchor_type: 'not-zlar-runtime-anchor',
      consumption_identity: 'authority-grant-contract-sha256',
      grant_contract_count: 0,
      store_canonical_sha256: '0'.repeat(64),
      store_type: PROTECTED_RECORDS_RUNTIME_CONSUMED_GRANT_STORE_TYPE,
    }, null, 2)}\n`);
    const invalidAnchorRun = runRuntimeService(
      runtimeConfig({ trusted, nowEpoch, consumedPath: invalidAnchorConsumedPath }),
      [requestFor({
        receipt: signedReceipt({ key: trusted, nowEpoch, recordUpdate }),
        recordUpdate,
        requestMode: 'invalid_consumed_store_anchor_runtime_write',
      })],
      scratch,
      'invalid-consumed-store-anchor'
    );
    const preconsumedGrantPath = join(scratch, 'preconsumed-authority-grant.json');
    writeConsumedStoreState(
      preconsumedGrantPath,
      defaultConsumedStoreAnchorPath(preconsumedGrantPath),
      [protectedRecordsFixtureAuthorityGrantContractSha256(
        activeConfig.authority_grant_contract
      )],
      defaultConsumedStoreWitnessPath(preconsumedGrantPath)
    );
    const preconsumedGrantRun = runRuntimeService(
      runtimeConfig({ trusted, nowEpoch, consumedPath: preconsumedGrantPath }),
      [requestFor({
        receipt: acceptedReceipt,
        recordUpdate,
        requestMode: 'preconsumed_authority_grant_without_runtime_state',
      })],
      scratch,
      'preconsumed-authority-grant-boundary'
    );

    const rollbackDetectedConsumedPath = join(scratch, 'rollback-detected-consumed-grants.json');
    const rollbackDetectedConfig = runtimeConfig({
      trusted,
      nowEpoch,
      consumedPath: rollbackDetectedConsumedPath,
    });
    runRuntimeService(
      rollbackDetectedConfig,
      [requestFor({
        receipt: acceptedReceipt,
        recordUpdate,
        requestMode: 'rollback_detection_seed_runtime_write',
      })],
      scratch,
      'rollback-detection-seed'
    );
    writeConsumedStore(rollbackDetectedConsumedPath, []);
    const rollbackDetectedRun = runRuntimeService(
      rollbackDetectedConfig,
      [requestFor({
        receipt: acceptedReceipt,
        recordUpdate,
        requestMode: 'rollback_detected_runtime_write',
      })],
      scratch,
      'rollback-detected'
    );

    const deletionDetectedConsumedPath = join(scratch, 'deletion-detected-consumed-grants.json');
    const deletionDetectedConfig = runtimeConfig({
      trusted,
      nowEpoch,
      consumedPath: deletionDetectedConsumedPath,
    });
    runRuntimeService(
      deletionDetectedConfig,
      [requestFor({
        receipt: acceptedReceipt,
        recordUpdate,
        requestMode: 'deletion_detection_seed_runtime_write',
      })],
      scratch,
      'deletion-detection-seed'
    );
    unlinkSync(deletionDetectedConsumedPath);
    const deletionDetectedRun = runRuntimeService(
      deletionDetectedConfig,
      [requestFor({
        receipt: acceptedReceipt,
        recordUpdate,
        requestMode: 'consumed_store_deletion_detected_runtime_write',
      })],
      scratch,
      'deletion-detected'
    );

    const replacementDetectedConsumedPath = join(scratch, 'replacement-detected-consumed-grants.json');
    const replacementDetectedConfig = runtimeConfig({
      trusted,
      nowEpoch,
      consumedPath: replacementDetectedConsumedPath,
    });
    runRuntimeService(
      replacementDetectedConfig,
      [requestFor({
        receipt: acceptedReceipt,
        recordUpdate,
        requestMode: 'replacement_detection_seed_runtime_write',
      })],
      scratch,
      'replacement-detection-seed'
    );
    writeConsumedStore(replacementDetectedConsumedPath, ['f'.repeat(64)]);
    const replacementDetectedRun = runRuntimeService(
      replacementDetectedConfig,
      [requestFor({
        receipt: acceptedReceipt,
        recordUpdate,
        requestMode: 'consumed_store_replacement_detected_runtime_write',
      })],
      scratch,
      'replacement-detected'
    );

    const stateAppendFailureConsumedPath = join(scratch, 'state-append-failure-consumed-grants.json');
    const stateAppendFailureRun = runRuntimeService(
      runtimeConfig({
        trusted,
        nowEpoch,
        consumedPath: stateAppendFailureConsumedPath,
        runtimeStateAppendFailureMode: PROTECTED_RECORDS_RUNTIME_STATE_APPEND_FAILURE_MODE,
      }),
      [requestFor({
        receipt: signedReceipt({ key: trusted, nowEpoch, recordUpdate }),
        recordUpdate,
        requestMode: 'runtime_state_append_failure_after_consumed_store_commit',
      })],
      scratch,
      'state-append-failure'
    );

    const witnessCommitFailureConsumedPath = join(
      scratch,
      'witness-commit-failure-consumed-grants.json'
    );
    const witnessCommitFailureConfig = runtimeConfig({
      trusted,
      nowEpoch,
      consumedPath: witnessCommitFailureConsumedPath,
      consumedGrantStoreCommitFailureMode:
        PROTECTED_RECORDS_RUNTIME_GRANT_STORE_WITNESS_COMMIT_FAILURE_MODE,
    });
    const witnessCommitFailureRun = runRuntimeService(
      witnessCommitFailureConfig,
      [requestFor({
        receipt: signedReceipt({
          authorityGrantContract:
            witnessCommitFailureConfig.authority_grant_contract,
          key: trusted,
          nowEpoch,
          recordUpdate,
        }),
        recordUpdate,
        requestMode: 'witness_commit_failure_after_grant_store_commit',
      })],
      scratch,
      'witness-commit-failure'
    );

    const jointRollbackPath = join(scratch, 'joint-rollback-consumed-grants.json');
    const jointRollbackConfig = runtimeConfig({
      trusted,
      nowEpoch,
      consumedPath: jointRollbackPath,
    });
    runRuntimeService(
      jointRollbackConfig,
      [requestFor({
        receipt: acceptedReceipt,
        recordUpdate,
        requestMode: 'joint_rollback_seed_runtime_write',
      })],
      scratch,
      'joint-rollback-seed'
    );
    writeConsumedStoreState(
      jointRollbackPath,
      defaultConsumedStoreAnchorPath(jointRollbackPath),
      []
    );
    const storeAndAnchorRollbackRefusedRun = runRuntimeService(
      jointRollbackConfig,
      [requestFor({
        receipt: acceptedReceipt,
        recordUpdate,
        requestMode: 'store_and_anchor_joint_rollback_refused_against_witness',
      })],
      scratch,
      'store-and-anchor-joint-rollback-refused'
    );
    writeConsumedStoreWitness(
      defaultConsumedStoreWitnessPath(jointRollbackPath),
      normalizedConsumedStore([])
    );
    const storeAnchorWitnessJointRollbackRun = runRuntimeService(
      jointRollbackConfig,
      [requestFor({
        receipt: acceptedReceipt,
        recordUpdate,
        requestMode: 'store_anchor_and_witness_joint_rollback_reopened_authority_grant_reuse',
      })],
      scratch,
      'store-anchor-witness-joint-rollback-boundary'
    );
    const runtimeProfileIdOmittedRequest = requestFor({
      receipt: signedReceipt({ key: trusted, nowEpoch, recordUpdate }),
      recordUpdate,
      requestMode: 'runtime_profile_id_omitted_uses_launcher_config',
    });
    delete runtimeProfileIdOmittedRequest.runtime_profile_id;
    const runtimeProfileIdOmittedRequestHasRuntimeProfileId =
      Object.prototype.hasOwnProperty.call(runtimeProfileIdOmittedRequest, 'runtime_profile_id');
    const runtimeProfileIdOmittedRun = runRuntimeService(
      runtimeConfig({
        trusted,
        nowEpoch,
        consumedPath: join(scratch, 'runtime-profile-id-omitted-consumed-grants.json'),
      }),
      [runtimeProfileIdOmittedRequest],
      scratch,
      'runtime-profile-id-omitted'
    );

    const retiredRun = runRuntimeService(
      runtimeConfig({
        trusted,
        nowEpoch,
        consumedPath: join(scratch, 'retired-consumed-grants.json'),
        issuerStatus: 'retired',
      }),
      [requestFor({ receipt: signedReceipt({ key: trusted, nowEpoch, recordUpdate }), recordUpdate })],
      scratch,
      'retired'
    );
    const missingStatusRun = runRuntimeService(
      runtimeConfig({
        trusted,
        nowEpoch,
        consumedPath: join(scratch, 'missing-status-consumed-grants.json'),
        includeStatus: false,
      }),
      [requestFor({ receipt: signedReceipt({ key: trusted, nowEpoch, recordUpdate }), recordUpdate })],
      scratch,
      'missing-status'
    );

    const missingGrantAppointmentPath = join(
      scratch,
      'missing-authority-grant-appointment-consumed-grants.json'
    );
    const missingGrantAppointmentConfig = runtimeConfig({
      trusted,
      nowEpoch,
      consumedPath: missingGrantAppointmentPath,
      authorityGrantAppointmentOverride: null,
    });
    const missingGrantAppointmentRun = runRuntimeService(
      missingGrantAppointmentConfig,
      [requestFor({
        receipt: signedReceipt({
          authorityGrantContract: missingGrantAppointmentConfig.authority_grant_contract,
          key: trusted,
          nowEpoch,
          recordUpdate,
        }),
        recordUpdate,
        requestMode: 'missing_authority_grant_appointment_runtime_write',
      })],
      scratch,
      'missing-authority-grant-appointment'
    );

    const mismatchedGrantAppointmentPath = join(
      scratch,
      'mismatched-authority-grant-appointment-consumed-grants.json'
    );
    const mismatchedGrantAppointmentConfig = runtimeConfig({
      trusted,
      nowEpoch,
      consumedPath: mismatchedGrantAppointmentPath,
    });
    mismatchedGrantAppointmentConfig.authority_grant_appointment = {
      ...mismatchedGrantAppointmentConfig.authority_grant_appointment,
      contract_sha256: '0'.repeat(64),
      grant_id: `zlar-grant:v1:${'0'.repeat(64)}`,
    };
    const mismatchedGrantAppointmentRun = runRuntimeService(
      mismatchedGrantAppointmentConfig,
      [requestFor({
        receipt: signedReceipt({
          authorityGrantContract: mismatchedGrantAppointmentConfig.authority_grant_contract,
          key: trusted,
          nowEpoch,
          recordUpdate,
        }),
        recordUpdate,
        requestMode: 'mismatched_authority_grant_appointment_runtime_write',
      })],
      scratch,
      'mismatched-authority-grant-appointment'
    );

    const revokedGrantPath = join(scratch, 'revoked-authority-grant-consumed-grants.json');
    const revokedGrantConfig = runtimeConfig({
      trusted,
      nowEpoch,
      consumedPath: revokedGrantPath,
      authorityGrantAppointmentStatus: 'revoked',
      authorityGrantRevokedAtEpoch: nowEpoch - 1,
      authorityGrantRevocationReasonCode: 'fixture_grant_revoked_before_effect',
    });
    const revokedGrantRun = runRuntimeService(
      revokedGrantConfig,
      [requestFor({
        receipt: signedReceipt({
          authorityGrantContract: revokedGrantConfig.authority_grant_contract,
          key: trusted,
          nowEpoch,
          recordUpdate,
        }),
        recordUpdate,
        requestMode: 'revoked_authority_grant_runtime_write',
      })],
      scratch,
      'revoked-authority-grant'
    );

    const expiredGrantPath = join(scratch, 'expired-authority-grant-consumed-grants.json');
    const expiredGrantEvaluationEpoch =
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_EXPIRES_AT_EPOCH;
    const expiredGrantConfig = runtimeConfig({
      trusted,
      nowEpoch: expiredGrantEvaluationEpoch,
      consumedPath: expiredGrantPath,
    });
    const expiredGrantRun = runRuntimeService(
      expiredGrantConfig,
      [requestFor({
        receipt: signedReceipt({
          authorityGrantContract: expiredGrantConfig.authority_grant_contract,
          key: trusted,
          nowEpoch: expiredGrantEvaluationEpoch,
          recordUpdate,
        }),
        recordUpdate,
        requestMode: 'expired_authority_grant_runtime_write',
      })],
      scratch,
      'expired-authority-grant'
    );

    const activeCase = ({ caseId, resultIndex, requestOrdinal }) => proofCase({
      caseId,
      result: activeRun.results[resultIndex],
      serviceProcessInvocation: 1,
      requestOrdinal,
      separateProcessFromAccepted: false,
      consumedStoreExistsAfter: existsSync(activeConsumedPath),
      consumedStoreAnchorExistsAfter: existsSync(activeAnchorPath),
    });
    const activeCases = [
      activeCase({ caseId: 'recognized_runtime_write_first_request', resultIndex: 0, requestOrdinal: 1 }),
      activeCase({ caseId: 'replay_runtime_write_refused_same_service_process', resultIndex: 1, requestOrdinal: 2 }),
      activeCase({ caseId: 'missing_receipt_refused_before_runtime_mutation', resultIndex: 2, requestOrdinal: 3 }),
      activeCase({ caseId: 'invalid_receipt_refused_before_runtime_mutation', resultIndex: 3, requestOrdinal: 4 }),
      activeCase({ caseId: 'unknown_issuer_refused_before_runtime_mutation', resultIndex: 4, requestOrdinal: 5 }),
      activeCase({ caseId: 'wrong_policy_refused_before_runtime_mutation', resultIndex: 5, requestOrdinal: 6 }),
      activeCase({ caseId: 'wrong_domain_refused_before_runtime_mutation', resultIndex: 6, requestOrdinal: 7 }),
      activeCase({ caseId: 'wrong_tool_refused_before_runtime_mutation', resultIndex: 7, requestOrdinal: 8 }),
      activeCase({ caseId: 'wrong_runtime_profile_id_refused_before_runtime_mutation', resultIndex: 8, requestOrdinal: 9 }),
      activeCase({ caseId: 'wrong_audit_event_refused_before_runtime_mutation', resultIndex: 9, requestOrdinal: 10 }),
      activeCase({ caseId: 'wrong_detail_refused_before_runtime_mutation', resultIndex: 10, requestOrdinal: 11 }),
      activeCase({ caseId: 'non_boarding_outcome_refused_before_runtime_mutation', resultIndex: 11, requestOrdinal: 12 }),
      activeCase({ caseId: 'stale_receipt_refused_before_runtime_mutation', resultIndex: 12, requestOrdinal: 13 }),
      activeCase({ caseId: 'direct_api_without_receipt_refused_before_runtime_mutation', resultIndex: 13, requestOrdinal: 14 }),
      activeCase({ caseId: 'direct_api_with_receipt_refused_before_runtime_mutation', resultIndex: 14, requestOrdinal: 15 }),
      activeCase({ caseId: 'agent_supplied_state_path_refused_before_runtime_mutation', resultIndex: 15, requestOrdinal: 16 }),
      activeCase({ caseId: 'agent_supplied_consumed_grants_path_refused_before_runtime_mutation', resultIndex: 16, requestOrdinal: 17 }),
      activeCase({ caseId: 'agent_supplied_consumed_grant_store_anchor_path_refused_before_runtime_mutation', resultIndex: 17, requestOrdinal: 18 }),
      activeCase({ caseId: 'agent_supplied_fixture_mode_refused_before_runtime_mutation', resultIndex: 18, requestOrdinal: 19 }),
      activeCase({ caseId: 'agent_supplied_recognition_rule_refused_before_runtime_mutation', resultIndex: 19, requestOrdinal: 20 }),
      activeCase({ caseId: 'agent_supplied_authority_grant_refused_before_runtime_mutation', resultIndex: 20, requestOrdinal: 21 }),
      activeCase({ caseId: 'unsupported_request_field_refused_before_runtime_mutation', resultIndex: 21, requestOrdinal: 22 }),
    ];

    const report = {
      proof_type: PROTECTED_RECORDS_RUNTIME_PROFILE_PROOF_TYPE,
      evidence_model: 'local-disposable-runtime-process-profile',
      live_probing: false,
      safe_claim_ceiling: SAFE_CLAIM_CEILING,
      accepted_runtime_transition_binding:
        activeRun.results[0].runtime_transition_binding,
      boundary_observations: [
        boundaryObservation({
          observationId: 'preconsumed_authority_grant_without_runtime_state_refuses_reuse',
          boundary: 'one-use-authority-grant-consumption-not-exactly-once-effect',
          result: preconsumedGrantRun.results[0],
          conclusion: 'A grant contract SHA present in the consumed-grant store is refused as already consumed even when the restarted runtime has zero process-private state entries.',
        }),
        boundaryObservation({
          observationId:
            'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse',
          boundary: 'local-store-anchor-and-witness-joint-rollback-not-detected',
          result: storeAnchorWitnessJointRollbackRun.results[0],
          conclusion: 'If the consumed-grant store, local anchor, and local witness are rolled back together to a matching earlier shape, this local proof does not detect rollback and the same one-use grant can board again.',
        }),
      ],
      runtime_profile: {
        profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
        profile_status: 'active_during_disposable_proof_only',
        action_class: 'records.write',
        runtime_environment: 'local-disposable-jsonl-child-process',
        service_command: 'zlar protected-records-runtime-service --config <file>',
        request_contract: 'receipt-record-update-and-routing-metadata-only',
        recognition_boundary: 'service-configured-recognition-rule',
        mutation_authoritative_route:
          'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation',
        state_storage: 'process-private-memory',
        consumed_authority_grant_store:
          'persistent-single-use-authority-grant-contract-sha256-store',
        consumption_identity: 'authority-grant-contract-sha256',
        signed_payload_replay_identity: 'verified-signed-payload-sha256',
        consumed_store_lock: 'launcher-owned-per-store-lockfile',
        consumed_store_validation: 'exact-schema-unique-grant-contract-sha256s',
        consumed_store_anchor: 'launcher-owned-local-store-hash-anchor',
        consumed_store_witness: 'launcher-owned-local-store-hash-witness',
        consumed_store_rollback_detection:
          'single-host-anchor-and-witness-match-before-mutation',
        consumed_store_write_model:
          'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness',
        replay_scope:
          'helper-signed-payload-identity-and-persistent-authority-grant-contract-sha256',
        persistent_consumed_authority_grant_store: true,
        authority_grant_contract_sha256:
          activeRun.results[0].authority_grant_contract_sha256,
        fixture_clock_model: 'fixed-hermetic-fixture-epoch',
        state_path_exposed_to_agent: false,
        recognition_rule_supplied_by_agent: false,
        agent_supplied_state_paths_accepted: false,
        agent_supplied_recognition_rule_accepted: false,
      },
      runtime_profile_identity_policy: {
        authority_source: 'launcher-owned-service-config',
        request_stream_policy:
          'runtime_profile_id_may_be_omitted_but_if_supplied_must_match_config',
        request_runtime_profile_id_required: false,
        omitted_request_runtime_profile_id_present:
          runtimeProfileIdOmittedRequestHasRuntimeProfileId,
        omitted_runtime_profile_id_uses_launcher_config:
          runtimeProfileIdOmittedRun.results[0].service_write_accepted === true,
        omitted_runtime_profile_id_reason_code:
          runtimeProfileIdOmittedRun.results[0].decision.reason_code,
        omitted_runtime_profile_id_state_entry_count_delta:
          runtimeProfileIdOmittedRun.results[0].state_entry_count_delta,
        omitted_runtime_profile_id_consumed_authority_grant_count:
          runtimeProfileIdOmittedRun.results[0].consumed_authority_grant_count,
        supplied_mismatched_runtime_profile_id_refused:
          activeRun.results[8].service_write_accepted === false,
        supplied_mismatch_reason_code: activeRun.results[8].decision.reason_code,
        supplied_mismatch_state_entry_count_delta:
          activeRun.results[8].state_entry_count_delta,
      },
      cases: [
        ...activeCases.slice(0, 2),
        proofCase({
          caseId: 'replay_runtime_write_refused_after_service_restart',
          result: restartReplayRun.results[0],
          serviceProcessInvocation: 2,
          requestOrdinal: 1,
          separateProcessFromAccepted: true,
          consumedStoreExistsAfter: existsSync(activeConsumedPath),
          consumedStoreAnchorExistsAfter: existsSync(activeAnchorPath),
        }),
        proofCase({
          caseId: 'invalid_consumed_store_refused_before_runtime_mutation',
          result: invalidStoreRun.results[0],
          serviceProcessInvocation: 3,
          requestOrdinal: 1,
          separateProcessFromAccepted: true,
          consumedStoreExistsAfter: existsSync(invalidConsumedPath),
          consumedStoreAnchorExistsAfter: existsSync(defaultConsumedStoreAnchorPath(invalidConsumedPath)),
        }),
        proofCase({
          caseId: 'duplicate_consumed_store_refused_before_runtime_mutation',
          result: duplicateStoreRun.results[0],
          serviceProcessInvocation: 4,
          requestOrdinal: 1,
          separateProcessFromAccepted: true,
          consumedStoreExistsAfter: existsSync(duplicateConsumedPath),
          consumedStoreAnchorExistsAfter: existsSync(defaultConsumedStoreAnchorPath(duplicateConsumedPath)),
        }),
        proofCase({
          caseId: 'locked_consumed_store_refused_before_runtime_mutation',
          result: lockedStoreRun.results[0],
          serviceProcessInvocation: 5,
          requestOrdinal: 1,
          separateProcessFromAccepted: true,
          consumedStoreExistsAfter: existsSync(lockedConsumedPath),
          consumedStoreAnchorExistsAfter: existsSync(defaultConsumedStoreAnchorPath(lockedConsumedPath)),
        }),
        proofCase({
          caseId: 'invalid_consumed_store_anchor_refused_before_runtime_mutation',
          result: invalidAnchorRun.results[0],
          serviceProcessInvocation: 6,
          requestOrdinal: 1,
          separateProcessFromAccepted: true,
          consumedStoreExistsAfter: existsSync(invalidAnchorConsumedPath),
          consumedStoreAnchorExistsAfter: existsSync(defaultConsumedStoreAnchorPath(invalidAnchorConsumedPath)),
        }),
        proofCase({
          caseId: 'valid_consumed_store_rollback_refused_before_runtime_mutation',
          result: rollbackDetectedRun.results[0],
          serviceProcessInvocation: 7,
          requestOrdinal: 1,
          separateProcessFromAccepted: true,
          consumedStoreExistsAfter: existsSync(rollbackDetectedConsumedPath),
          consumedStoreAnchorExistsAfter: existsSync(defaultConsumedStoreAnchorPath(rollbackDetectedConsumedPath)),
        }),
        proofCase({
          caseId: 'consumed_store_deletion_refused_before_runtime_mutation',
          result: deletionDetectedRun.results[0],
          serviceProcessInvocation: 8,
          requestOrdinal: 1,
          separateProcessFromAccepted: true,
          consumedStoreExistsAfter: existsSync(deletionDetectedConsumedPath),
          consumedStoreAnchorExistsAfter: existsSync(defaultConsumedStoreAnchorPath(deletionDetectedConsumedPath)),
        }),
        proofCase({
          caseId: 'valid_consumed_store_replacement_refused_before_runtime_mutation',
          result: replacementDetectedRun.results[0],
          serviceProcessInvocation: 9,
          requestOrdinal: 1,
          separateProcessFromAccepted: true,
          consumedStoreExistsAfter: existsSync(replacementDetectedConsumedPath),
          consumedStoreAnchorExistsAfter: existsSync(defaultConsumedStoreAnchorPath(replacementDetectedConsumedPath)),
        }),
        proofCase({
          caseId: 'runtime_state_append_failed_after_consumed_store_commit',
          result: stateAppendFailureRun.results[0],
          serviceProcessInvocation: 10,
          requestOrdinal: 1,
          separateProcessFromAccepted: true,
          consumedStoreExistsAfter: existsSync(stateAppendFailureConsumedPath),
          consumedStoreAnchorExistsAfter: existsSync(defaultConsumedStoreAnchorPath(stateAppendFailureConsumedPath)),
        }),
        proofCase({
          caseId: 'witness_commit_failed_after_authority_grant_store_commit',
          result: witnessCommitFailureRun.results[0],
          serviceProcessInvocation: 11,
          requestOrdinal: 1,
          separateProcessFromAccepted: true,
          consumedStoreExistsAfter: existsSync(witnessCommitFailureConsumedPath),
          consumedStoreAnchorExistsAfter:
            existsSync(defaultConsumedStoreAnchorPath(witnessCommitFailureConsumedPath)),
        }),
        proofCase({
          caseId:
            'store_and_anchor_joint_rollback_refused_against_witness_before_runtime_mutation',
          result: storeAndAnchorRollbackRefusedRun.results[0],
          serviceProcessInvocation: 12,
          requestOrdinal: 1,
          separateProcessFromAccepted: true,
          consumedStoreExistsAfter: existsSync(jointRollbackPath),
          consumedStoreAnchorExistsAfter:
            existsSync(defaultConsumedStoreAnchorPath(jointRollbackPath)),
        }),
        ...activeCases.slice(2, 5),
        proofCase({
          caseId: 'retired_issuer_refused_before_runtime_mutation',
          result: retiredRun.results[0],
          serviceProcessInvocation: 13,
          requestOrdinal: 1,
          separateProcessFromAccepted: true,
          consumedStoreExistsAfter: false,
          consumedStoreAnchorExistsAfter: false,
        }),
        proofCase({
          caseId: 'missing_issuer_status_refused_before_runtime_mutation',
          result: missingStatusRun.results[0],
          serviceProcessInvocation: 14,
          requestOrdinal: 1,
          separateProcessFromAccepted: true,
          consumedStoreExistsAfter: false,
          consumedStoreAnchorExistsAfter: false,
        }),
        proofCase({
          caseId: 'missing_authority_grant_appointment_refused_before_consumption',
          result: missingGrantAppointmentRun.results[0],
          serviceProcessInvocation: 15,
          requestOrdinal: 1,
          separateProcessFromAccepted: true,
          consumedStoreExistsAfter: existsSync(missingGrantAppointmentPath),
          consumedStoreAnchorExistsAfter:
            existsSync(defaultConsumedStoreAnchorPath(missingGrantAppointmentPath)),
        }),
        proofCase({
          caseId: 'mismatched_authority_grant_appointment_refused_before_consumption',
          result: mismatchedGrantAppointmentRun.results[0],
          serviceProcessInvocation: 16,
          requestOrdinal: 1,
          separateProcessFromAccepted: true,
          consumedStoreExistsAfter: existsSync(mismatchedGrantAppointmentPath),
          consumedStoreAnchorExistsAfter:
            existsSync(defaultConsumedStoreAnchorPath(mismatchedGrantAppointmentPath)),
        }),
        proofCase({
          caseId: 'revoked_authority_grant_refused_before_consumption',
          result: revokedGrantRun.results[0],
          serviceProcessInvocation: 17,
          requestOrdinal: 1,
          separateProcessFromAccepted: true,
          consumedStoreExistsAfter: existsSync(revokedGrantPath),
          consumedStoreAnchorExistsAfter:
            existsSync(defaultConsumedStoreAnchorPath(revokedGrantPath)),
        }),
        proofCase({
          caseId: 'expired_authority_grant_refused_before_consumption',
          result: expiredGrantRun.results[0],
          serviceProcessInvocation: 18,
          requestOrdinal: 1,
          separateProcessFromAccepted: true,
          consumedStoreExistsAfter: existsSync(expiredGrantPath),
          consumedStoreAnchorExistsAfter:
            existsSync(defaultConsumedStoreAnchorPath(expiredGrantPath)),
        }),
        ...activeCases.slice(5),
      ],
      side_door_report: {
        process_private_state: true,
        state_path_exposed_to_agent: false,
        recognition_rule_supplied_by_agent: false,
        agent_supplied_state_path_refused: true,
        agent_supplied_recognition_rule_refused: true,
        wrong_runtime_profile_id_refused: true,
        direct_api_without_receipt_refused: true,
        direct_api_with_receipt_refused: true,
        unsupported_request_field_refused: true,
        persistent_consumed_authority_grant_store: true,
        invalid_consumed_store_refused: true,
        invalid_consumed_store_anchor_refused: true,
        duplicate_consumed_store_refused: true,
        locked_consumed_store_refused: true,
        consumed_store_anchor_present: true,
        consumed_store_witness_present: existsSync(activeWitnessPath),
        atomic_store_anchor_witness_commit: false,
        partial_grant_commit_burn_window_named: true,
        partial_commit_witness_missing_observed:
          !existsSync(defaultConsumedStoreWitnessPath(witnessCommitFailureConsumedPath)),
        single_host_consumed_store_rollback_detection: true,
        exactly_once_effect_semantics: false,
        burned_authority_grant_window_named: true,
        valid_store_rollback_detection: true,
        valid_store_rollback_reopens_replay: false,
        store_and_anchor_joint_rollback_refused_while_witness_ahead: true,
        store_anchor_and_witness_joint_rollback_detection: false,
        store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse: true,
        cross_process_authority_grant_reuse_closed: true,
        host_process_or_memory_introspection_closed: false,
        host_filesystem_path_toctou_closed: false,
        live_records_system_checked: false,
        production_records_service_checked: false,
        persistent_runtime_profile_installed: false,
        external_attestation: false,
        sovereign_recognition: false,
        unrouted_records_paths_checked: false,
      },
      known_open_boundaries: [
        'host_process_or_memory_introspection',
        'live_records_system',
        'production_records_service',
        'exactly_once_effect_semantics',
        'store_anchor_and_witness_rollback_or_deletion',
        'store_anchor_witness_commit_atomicity',
        'host_filesystem_path_toctou',
        'anti_rollback_anchor_custody',
        'stale_lock_recovery',
        'multi_host_consumed_store_coordination',
        'production_durable_consumed_store',
        'persistent_runtime_profile_installation',
        'unrouted_records_paths',
      ],
      non_claims: [...NON_CLAIMS],
    };
    assertProtectedRecordsRuntimeProfileProof(report);
    return report;
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

const EXPECTED_CASE_REASONS = Object.freeze({
  recognized_runtime_write_first_request: 'fixture_authority_grant_effect_satisfied',
  replay_runtime_write_refused_same_service_process: 'receipt_replay',
  replay_runtime_write_refused_after_service_restart: 'authority_grant_already_consumed',
  invalid_consumed_store_refused_before_runtime_mutation: 'consumed_store_invalid',
  duplicate_consumed_store_refused_before_runtime_mutation: 'consumed_store_invalid',
  locked_consumed_store_refused_before_runtime_mutation: 'consumed_store_locked',
  invalid_consumed_store_anchor_refused_before_runtime_mutation: 'consumed_store_anchor_invalid',
  valid_consumed_store_rollback_refused_before_runtime_mutation: 'consumed_store_rollback_detected',
  consumed_store_deletion_refused_before_runtime_mutation: 'consumed_store_rollback_detected',
  valid_consumed_store_replacement_refused_before_runtime_mutation: 'consumed_store_rollback_detected',
  runtime_state_append_failed_after_consumed_store_commit: 'runtime_state_append_failed_after_consumed_store_commit',
  witness_commit_failed_after_authority_grant_store_commit:
    'consumed_store_write_failed_after_grant_commit',
  store_and_anchor_joint_rollback_refused_against_witness_before_runtime_mutation:
    'consumed_store_rollback_detected',
  missing_receipt_refused_before_runtime_mutation: 'receipt_missing',
  invalid_receipt_refused_before_runtime_mutation: 'receipt_invalid',
  unknown_issuer_refused_before_runtime_mutation: 'unknown_issuer',
  retired_issuer_refused_before_runtime_mutation: 'issuer_not_active',
  missing_issuer_status_refused_before_runtime_mutation: 'issuer_status_missing',
  missing_authority_grant_appointment_refused_before_consumption: 'authority_grant_missing',
  mismatched_authority_grant_appointment_refused_before_consumption: 'authority_grant_contract_mismatch',
  revoked_authority_grant_refused_before_consumption: 'authority_grant_revoked',
  expired_authority_grant_refused_before_consumption: 'authority_grant_expired',
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
  agent_supplied_state_path_refused_before_runtime_mutation: 'agent_supplied_authority_material',
  agent_supplied_consumed_grants_path_refused_before_runtime_mutation: 'agent_supplied_authority_material',
  agent_supplied_consumed_grant_store_anchor_path_refused_before_runtime_mutation: 'agent_supplied_authority_material',
  agent_supplied_fixture_mode_refused_before_runtime_mutation: 'agent_supplied_authority_material',
  agent_supplied_recognition_rule_refused_before_runtime_mutation: 'agent_supplied_authority_material',
  agent_supplied_authority_grant_refused_before_runtime_mutation: 'agent_supplied_authority_material',
  unsupported_request_field_refused_before_runtime_mutation: 'agent_supplied_authority_material',
});

export function assertProtectedRecordsRuntimeProfileProof(report) {
  assertExactKeys('Protected records runtime profile proof', report, [
    'accepted_runtime_transition_binding',
    'boundary_observations',
    'cases',
    'evidence_model',
    'known_open_boundaries',
    'live_probing',
    'non_claims',
    'proof_type',
    'runtime_profile',
    'runtime_profile_identity_policy',
    'safe_claim_ceiling',
    'side_door_report',
  ]);
  if (
    report.proof_type !== PROTECTED_RECORDS_RUNTIME_PROFILE_PROOF_TYPE ||
    report.evidence_model !== 'local-disposable-runtime-process-profile' ||
    report.live_probing !== false ||
    report.safe_claim_ceiling !== SAFE_CLAIM_CEILING
  ) {
    throw new Error('Protected records runtime profile proof top-level contract drifted');
  }

  assertExactKeys('Protected records runtime profile', report.runtime_profile, [
    'action_class',
    'agent_supplied_recognition_rule_accepted',
    'agent_supplied_state_paths_accepted',
    'consumed_authority_grant_store',
    'consumption_identity',
    'consumed_store_anchor',
    'consumed_store_witness',
    'consumed_store_lock',
    'consumed_store_rollback_detection',
    'consumed_store_validation',
    'consumed_store_write_model',
    'authority_grant_contract_sha256',
    'fixture_clock_model',
    'mutation_authoritative_route',
    'persistent_consumed_authority_grant_store',
    'profile_id',
    'profile_status',
    'recognition_boundary',
    'recognition_rule_supplied_by_agent',
    'replay_scope',
    'request_contract',
    'runtime_environment',
    'service_command',
    'signed_payload_replay_identity',
    'state_path_exposed_to_agent',
    'state_storage',
  ]);
  if (
    report.runtime_profile.profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    report.runtime_profile.profile_status !== 'active_during_disposable_proof_only' ||
    report.runtime_profile.action_class !== 'records.write' ||
    report.runtime_profile.runtime_environment !== 'local-disposable-jsonl-child-process' ||
    report.runtime_profile.service_command !== 'zlar protected-records-runtime-service --config <file>' ||
    report.runtime_profile.request_contract !== 'receipt-record-update-and-routing-metadata-only' ||
    report.runtime_profile.recognition_boundary !== 'service-configured-recognition-rule' ||
    report.runtime_profile.mutation_authoritative_route !==
      'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation' ||
    report.runtime_profile.state_storage !== 'process-private-memory' ||
    report.runtime_profile.consumed_authority_grant_store !==
      'persistent-single-use-authority-grant-contract-sha256-store' ||
    report.runtime_profile.consumption_identity !== 'authority-grant-contract-sha256' ||
    report.runtime_profile.signed_payload_replay_identity !==
      'verified-signed-payload-sha256' ||
    report.runtime_profile.consumed_store_lock !== 'launcher-owned-per-store-lockfile' ||
    report.runtime_profile.consumed_store_validation !==
      'exact-schema-unique-grant-contract-sha256s' ||
    report.runtime_profile.consumed_store_anchor !== 'launcher-owned-local-store-hash-anchor' ||
    report.runtime_profile.consumed_store_witness !==
      'launcher-owned-local-store-hash-witness' ||
    report.runtime_profile.consumed_store_rollback_detection !==
      'single-host-anchor-and-witness-match-before-mutation' ||
    report.runtime_profile.consumed_store_write_model !==
      'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness' ||
    report.runtime_profile.replay_scope !==
      'helper-signed-payload-identity-and-persistent-authority-grant-contract-sha256' ||
    report.runtime_profile.persistent_consumed_authority_grant_store !== true ||
    report.runtime_profile.fixture_clock_model !== 'fixed-hermetic-fixture-epoch' ||
    !/^[a-f0-9]{64}$/.test(report.runtime_profile.authority_grant_contract_sha256 || '') ||
    report.runtime_profile.state_path_exposed_to_agent !== false ||
    report.runtime_profile.recognition_rule_supplied_by_agent !== false ||
    report.runtime_profile.agent_supplied_state_paths_accepted !== false ||
    report.runtime_profile.agent_supplied_recognition_rule_accepted !== false
  ) {
    throw new Error('Protected records runtime profile drifted');
  }

  assertExactKeys('Protected records runtime profile identity policy', report.runtime_profile_identity_policy, [
    'authority_source',
    'omitted_request_runtime_profile_id_present',
    'omitted_runtime_profile_id_consumed_authority_grant_count',
    'omitted_runtime_profile_id_reason_code',
    'omitted_runtime_profile_id_state_entry_count_delta',
    'omitted_runtime_profile_id_uses_launcher_config',
    'request_runtime_profile_id_required',
    'request_stream_policy',
    'supplied_mismatch_reason_code',
    'supplied_mismatch_state_entry_count_delta',
    'supplied_mismatched_runtime_profile_id_refused',
  ]);
  if (
    report.runtime_profile_identity_policy.authority_source !==
      'launcher-owned-service-config' ||
    report.runtime_profile_identity_policy.request_stream_policy !==
      'runtime_profile_id_may_be_omitted_but_if_supplied_must_match_config' ||
    report.runtime_profile_identity_policy.request_runtime_profile_id_required !== false ||
    report.runtime_profile_identity_policy.omitted_request_runtime_profile_id_present !== false ||
    report.runtime_profile_identity_policy.omitted_runtime_profile_id_uses_launcher_config !== true ||
    report.runtime_profile_identity_policy.omitted_runtime_profile_id_reason_code !==
      'fixture_authority_grant_effect_satisfied' ||
    report.runtime_profile_identity_policy.omitted_runtime_profile_id_state_entry_count_delta !== 1 ||
    report.runtime_profile_identity_policy.omitted_runtime_profile_id_consumed_authority_grant_count !== 1 ||
    report.runtime_profile_identity_policy.supplied_mismatched_runtime_profile_id_refused !== true ||
    report.runtime_profile_identity_policy.supplied_mismatch_reason_code !==
      'agent_supplied_authority_material' ||
    report.runtime_profile_identity_policy.supplied_mismatch_state_entry_count_delta !== 0
  ) {
    throw new Error('Protected records runtime profile identity policy drifted');
  }

  assertExactKeys('Protected records runtime side-door report', report.side_door_report, [
    'agent_supplied_recognition_rule_refused',
    'agent_supplied_state_path_refused',
    'atomic_store_anchor_witness_commit',
    'burned_authority_grant_window_named',
    'consumed_store_anchor_present',
    'consumed_store_witness_present',
    'direct_api_with_receipt_refused',
    'direct_api_without_receipt_refused',
    'duplicate_consumed_store_refused',
    'exactly_once_effect_semantics',
    'external_attestation',
    'cross_process_authority_grant_reuse_closed',
    'host_process_or_memory_introspection_closed',
    'host_filesystem_path_toctou_closed',
    'invalid_consumed_store_anchor_refused',
    'invalid_consumed_store_refused',
    'live_records_system_checked',
    'locked_consumed_store_refused',
    'persistent_consumed_authority_grant_store',
    'partial_commit_witness_missing_observed',
    'partial_grant_commit_burn_window_named',
    'persistent_runtime_profile_installed',
    'process_private_state',
    'production_records_service_checked',
    'recognition_rule_supplied_by_agent',
    'single_host_consumed_store_rollback_detection',
    'sovereign_recognition',
    'state_path_exposed_to_agent',
    'store_and_anchor_joint_rollback_refused_while_witness_ahead',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse',
    'unsupported_request_field_refused',
    'unrouted_records_paths_checked',
    'valid_store_rollback_detection',
    'valid_store_rollback_reopens_replay',
    'wrong_runtime_profile_id_refused',
  ]);
  if (
    report.side_door_report.process_private_state !== true ||
    report.side_door_report.state_path_exposed_to_agent !== false ||
    report.side_door_report.recognition_rule_supplied_by_agent !== false ||
    report.side_door_report.agent_supplied_state_path_refused !== true ||
    report.side_door_report.agent_supplied_recognition_rule_refused !== true ||
    report.side_door_report.atomic_store_anchor_witness_commit !== false ||
    report.side_door_report.wrong_runtime_profile_id_refused !== true ||
    report.side_door_report.direct_api_without_receipt_refused !== true ||
    report.side_door_report.direct_api_with_receipt_refused !== true ||
    report.side_door_report.unsupported_request_field_refused !== true ||
    report.side_door_report.persistent_consumed_authority_grant_store !== true ||
    report.side_door_report.invalid_consumed_store_refused !== true ||
    report.side_door_report.invalid_consumed_store_anchor_refused !== true ||
    report.side_door_report.duplicate_consumed_store_refused !== true ||
    report.side_door_report.locked_consumed_store_refused !== true ||
    report.side_door_report.consumed_store_anchor_present !== true ||
    report.side_door_report.consumed_store_witness_present !== true ||
    report.side_door_report.partial_grant_commit_burn_window_named !== true ||
    report.side_door_report.partial_commit_witness_missing_observed !== true ||
    report.side_door_report.single_host_consumed_store_rollback_detection !== true ||
    report.side_door_report.exactly_once_effect_semantics !== false ||
    report.side_door_report.burned_authority_grant_window_named !== true ||
    report.side_door_report.valid_store_rollback_detection !== true ||
    report.side_door_report.valid_store_rollback_reopens_replay !== false ||
    report.side_door_report.store_and_anchor_joint_rollback_refused_while_witness_ahead !== true ||
    report.side_door_report.store_anchor_and_witness_joint_rollback_detection !== false ||
    report.side_door_report.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse !== true ||
    report.side_door_report.cross_process_authority_grant_reuse_closed !== true ||
    report.side_door_report.host_process_or_memory_introspection_closed !== false ||
    report.side_door_report.host_filesystem_path_toctou_closed !== false ||
    report.side_door_report.live_records_system_checked !== false ||
    report.side_door_report.production_records_service_checked !== false ||
    report.side_door_report.persistent_runtime_profile_installed !== false ||
    report.side_door_report.external_attestation !== false ||
    report.side_door_report.sovereign_recognition !== false ||
    report.side_door_report.unrouted_records_paths_checked !== false
  ) {
    throw new Error('Protected records runtime side-door report drifted');
  }

  assertExactArray('Protected records runtime open boundaries', report.known_open_boundaries, [
    'host_process_or_memory_introspection',
    'live_records_system',
    'production_records_service',
    'exactly_once_effect_semantics',
    'store_anchor_and_witness_rollback_or_deletion',
    'store_anchor_witness_commit_atomicity',
    'host_filesystem_path_toctou',
    'anti_rollback_anchor_custody',
    'stale_lock_recovery',
    'multi_host_consumed_store_coordination',
    'production_durable_consumed_store',
    'persistent_runtime_profile_installation',
    'unrouted_records_paths',
  ]);
  assertExactArray('Protected records runtime non-claims', report.non_claims, NON_CLAIMS);

  if (!Array.isArray(report.boundary_observations) || report.boundary_observations.length !== 2) {
    throw new Error('Protected records runtime boundary observation count drifted');
  }
  for (const observation of report.boundary_observations) {
    assertExactKeys('Protected records runtime boundary observation', observation, [
      'boundary',
      'conclusion',
      'consumed_authority_grant_count',
      'observation_id',
      'reason_code',
      'service_write_accepted',
      'state_entry_count_after',
      'state_entry_count_before',
      'state_entry_count_delta',
    ]);
    if (
      typeof observation.conclusion !== 'string' ||
      observation.conclusion.length === 0 ||
      observation.state_entry_count_delta !== observation.state_entry_count_after - observation.state_entry_count_before
    ) {
      throw new Error('Protected records runtime boundary observation drifted');
    }
  }
  const burnedGrant = report.boundary_observations.find((item) =>
    item.observation_id === 'preconsumed_authority_grant_without_runtime_state_refuses_reuse'
  );
  if (
    !burnedGrant ||
    burnedGrant.boundary !== 'one-use-authority-grant-consumption-not-exactly-once-effect' ||
    burnedGrant.service_write_accepted !== false ||
    burnedGrant.reason_code !== 'authority_grant_already_consumed' ||
    burnedGrant.state_entry_count_before !== 0 ||
    burnedGrant.state_entry_count_after !== 0 ||
    burnedGrant.state_entry_count_delta !== 0 ||
    burnedGrant.consumed_authority_grant_count !== 1
  ) {
    throw new Error('Protected records runtime burned-grant boundary observation drifted');
  }
  const storeAnchorWitnessJointRollback = report.boundary_observations.find((item) =>
    item.observation_id ===
      'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse'
  );
  if (
    !storeAnchorWitnessJointRollback ||
    storeAnchorWitnessJointRollback.boundary !==
      'local-store-anchor-and-witness-joint-rollback-not-detected' ||
    storeAnchorWitnessJointRollback.service_write_accepted !== true ||
    storeAnchorWitnessJointRollback.reason_code !==
      'fixture_authority_grant_effect_satisfied' ||
    storeAnchorWitnessJointRollback.state_entry_count_before !== 0 ||
    storeAnchorWitnessJointRollback.state_entry_count_after !== 1 ||
    storeAnchorWitnessJointRollback.state_entry_count_delta !== 1 ||
    storeAnchorWitnessJointRollback.consumed_authority_grant_count !== 1
  ) {
    throw new Error('Protected records runtime joint rollback boundary observation drifted');
  }

  if (!Array.isArray(report.cases) || report.cases.length !== REQUIRED_RUNTIME_PROFILE_CASES.length) {
    throw new Error('Protected records runtime profile case count drifted');
  }
  for (const caseId of REQUIRED_RUNTIME_PROFILE_CASES) {
    if (!report.cases.some((item) => item.case_id === caseId)) {
      throw new Error(`Protected records runtime profile missing case: ${caseId}`);
    }
  }
  for (const item of report.cases) {
    assertExactKeys('Protected records runtime profile case', item, [
      'agent_supplied_recognition_rule_accepted',
      'agent_supplied_state_paths_accepted',
      'case_id',
      'consumed_authority_grant_count',
      'consumed_store_anchor_exists_after',
      'consumed_store_exists_after',
      'direct_api_attempted',
      'reason_code',
      'request_ordinal',
      'separate_process_from_accepted',
      'service_process_boundary',
      'service_process_invocation',
      'service_write_accepted',
      'state_entry_count_after',
      'state_entry_count_before',
      'state_entry_count_delta',
    ]);
    if (
      !EXPECTED_CASE_REASONS[item.case_id] ||
      item.reason_code !== EXPECTED_CASE_REASONS[item.case_id] ||
      item.service_process_boundary !== 'local-jsonl-child-process' ||
      item.state_entry_count_delta !== item.state_entry_count_after - item.state_entry_count_before ||
      item.agent_supplied_state_paths_accepted !== false ||
      item.agent_supplied_recognition_rule_accepted !== false
    ) {
      throw new Error('Protected records runtime profile case contract drifted');
    }
  }

  const accepted = report.cases.find((item) => item.case_id === 'recognized_runtime_write_first_request');
  if (
    accepted.service_write_accepted !== true ||
    accepted.state_entry_count_before !== 0 ||
    accepted.state_entry_count_after !== 1 ||
    accepted.state_entry_count_delta !== 1 ||
    accepted.consumed_authority_grant_count !== 1 ||
    accepted.consumed_store_exists_after !== true ||
    accepted.consumed_store_anchor_exists_after !== true ||
    accepted.service_process_invocation !== 1 ||
    accepted.separate_process_from_accepted !== false ||
    accepted.request_ordinal !== 1
  ) {
    throw new Error('Protected records runtime accepted case failed');
  }

  const replay = report.cases.find((item) => item.case_id === 'replay_runtime_write_refused_same_service_process');
  if (
    replay.service_write_accepted !== false ||
    replay.state_entry_count_before !== 1 ||
    replay.state_entry_count_after !== 1 ||
    replay.state_entry_count_delta !== 0 ||
    replay.consumed_authority_grant_count !== 1 ||
    replay.consumed_store_exists_after !== true ||
    replay.consumed_store_anchor_exists_after !== true ||
    replay.service_process_invocation !== 1 ||
    replay.separate_process_from_accepted !== false ||
    replay.request_ordinal !== 2
  ) {
    throw new Error('Protected records runtime replay case failed');
  }

  const restartReplay = report.cases.find((item) => item.case_id === 'replay_runtime_write_refused_after_service_restart');
  if (
    restartReplay.service_write_accepted !== false ||
    restartReplay.reason_code !== 'authority_grant_already_consumed' ||
    restartReplay.state_entry_count_before !== 0 ||
    restartReplay.state_entry_count_after !== 0 ||
    restartReplay.state_entry_count_delta !== 0 ||
    restartReplay.consumed_authority_grant_count !== 1 ||
    restartReplay.consumed_store_exists_after !== true ||
    restartReplay.consumed_store_anchor_exists_after !== true ||
    restartReplay.service_process_invocation !== 2 ||
    restartReplay.separate_process_from_accepted !== true ||
    restartReplay.request_ordinal !== 1
  ) {
    throw new Error('Protected records runtime restart replay case failed');
  }

  const storeCases = report.cases.filter((item) => [
    'invalid_consumed_store_refused_before_runtime_mutation',
    'duplicate_consumed_store_refused_before_runtime_mutation',
    'locked_consumed_store_refused_before_runtime_mutation',
    'invalid_consumed_store_anchor_refused_before_runtime_mutation',
    'valid_consumed_store_rollback_refused_before_runtime_mutation',
    'consumed_store_deletion_refused_before_runtime_mutation',
    'valid_consumed_store_replacement_refused_before_runtime_mutation',
    'store_and_anchor_joint_rollback_refused_against_witness_before_runtime_mutation',
  ].includes(item.case_id));
  if (
    storeCases.length !== 8 ||
    storeCases.some((item) =>
      item.service_write_accepted !== false ||
      item.state_entry_count_before !== 0 ||
      item.state_entry_count_after !== 0 ||
      item.state_entry_count_delta !== 0 ||
      item.consumed_authority_grant_count !==
        (item.case_id ===
          'valid_consumed_store_replacement_refused_before_runtime_mutation'
          ? 1
          : 0) ||
      item.separate_process_from_accepted !== true
    )
  ) {
    throw new Error('Protected records runtime consumed-store refusal cases drifted');
  }

  const stateAppendFailure = report.cases.find((item) =>
    item.case_id === 'runtime_state_append_failed_after_consumed_store_commit'
  );
  if (
    !stateAppendFailure ||
    stateAppendFailure.service_write_accepted !== false ||
    stateAppendFailure.reason_code !== 'runtime_state_append_failed_after_consumed_store_commit' ||
    stateAppendFailure.state_entry_count_before !== 0 ||
    stateAppendFailure.state_entry_count_after !== 0 ||
    stateAppendFailure.state_entry_count_delta !== 0 ||
    stateAppendFailure.consumed_authority_grant_count !== 1 ||
    stateAppendFailure.consumed_store_exists_after !== true ||
    stateAppendFailure.consumed_store_anchor_exists_after !== true ||
    stateAppendFailure.separate_process_from_accepted !== true
  ) {
    throw new Error('Protected records runtime state append failure boundary drifted');
  }

  const witnessCommitFailure = report.cases.find((item) =>
    item.case_id === 'witness_commit_failed_after_authority_grant_store_commit'
  );
  if (
    !witnessCommitFailure ||
    witnessCommitFailure.service_write_accepted !== false ||
    witnessCommitFailure.reason_code !==
      'consumed_store_write_failed_after_grant_commit' ||
    witnessCommitFailure.state_entry_count_before !== 0 ||
    witnessCommitFailure.state_entry_count_after !== 0 ||
    witnessCommitFailure.state_entry_count_delta !== 0 ||
    witnessCommitFailure.consumed_authority_grant_count !== 1 ||
    witnessCommitFailure.consumed_store_exists_after !== true ||
    witnessCommitFailure.consumed_store_anchor_exists_after !== true ||
    witnessCommitFailure.separate_process_from_accepted !== true
  ) {
    throw new Error('Protected records runtime witness commit failure boundary drifted');
  }

  for (const item of report.cases.filter((candidate) => candidate.case_id !== accepted.case_id)) {
    if (item.service_write_accepted !== false || item.state_entry_count_delta !== 0) {
      throw new Error('Protected records runtime refusal case changed state');
    }
  }
  const directApiCases = report.cases.filter((item) => item.case_id.startsWith('direct_api_'));
  if (directApiCases.length !== 2 || directApiCases.some((item) => item.direct_api_attempted !== true)) {
    throw new Error('Protected records runtime direct API cases drifted');
  }
  const authorityCases = report.cases.filter((item) => item.case_id.startsWith('agent_supplied_'));
  if (authorityCases.length !== 6 || authorityCases.some((item) => item.reason_code !== 'agent_supplied_authority_material')) {
    throw new Error('Protected records runtime authority-material cases drifted');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return true;
}

export function formatProtectedRecordsRuntimeProfileProofSummary(report) {
  assertProtectedRecordsRuntimeProfileProof(report);
  const accepted = report.cases.find((item) => item.case_id === 'recognized_runtime_write_first_request');
  const replay = report.cases.find((item) => item.case_id === 'replay_runtime_write_refused_same_service_process');
  const restartReplay = report.cases.find((item) => item.case_id === 'replay_runtime_write_refused_after_service_restart');
  const invalidStore = report.cases.find((item) => item.case_id === 'invalid_consumed_store_refused_before_runtime_mutation');
  const duplicateStore = report.cases.find((item) => item.case_id === 'duplicate_consumed_store_refused_before_runtime_mutation');
  const lockedStore = report.cases.find((item) => item.case_id === 'locked_consumed_store_refused_before_runtime_mutation');
  const invalidAnchor = report.cases.find((item) => item.case_id === 'invalid_consumed_store_anchor_refused_before_runtime_mutation');
  const rollbackDetected = report.cases.find((item) => item.case_id === 'valid_consumed_store_rollback_refused_before_runtime_mutation');
  const deletionDetected = report.cases.find((item) => item.case_id === 'consumed_store_deletion_refused_before_runtime_mutation');
  const replacementDetected = report.cases.find((item) => item.case_id === 'valid_consumed_store_replacement_refused_before_runtime_mutation');
  const witnessCommitFailure = report.cases.find((item) =>
    item.case_id === 'witness_commit_failed_after_authority_grant_store_commit'
  );
  const burnedGrant = report.boundary_observations.find((item) =>
    item.observation_id === 'preconsumed_authority_grant_without_runtime_state_refuses_reuse'
  );
  const storeAnchorWitnessJointRollback = report.boundary_observations.find((item) =>
    item.observation_id ===
      'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse'
  );
  const missing = report.cases.find((item) => item.case_id === 'missing_receipt_refused_before_runtime_mutation');
  const invalid = report.cases.find((item) => item.case_id === 'invalid_receipt_refused_before_runtime_mutation');
  const stale = report.cases.find((item) => item.case_id === 'stale_receipt_refused_before_runtime_mutation');
  const authorityState = report.cases.find((item) => item.case_id === 'agent_supplied_state_path_refused_before_runtime_mutation');
  const authorityRule = report.cases.find((item) => item.case_id === 'agent_supplied_recognition_rule_refused_before_runtime_mutation');
  const unsupportedField = report.cases.find((item) => item.case_id === 'unsupported_request_field_refused_before_runtime_mutation');
  const lines = [
    'ZLAR Protected Records Runtime Profile Proof v1',
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Evidence model: ${report.evidence_model}; live probing=${report.live_probing}`,
    `Runtime profile: id=${report.runtime_profile.profile_id}; status=${report.runtime_profile.profile_status}; action_class=${report.runtime_profile.action_class}; environment=${report.runtime_profile.runtime_environment}`,
    `Runtime profile identity: authority_source=${report.runtime_profile_identity_policy.authority_source}; request_runtime_profile_id_required=${report.runtime_profile_identity_policy.request_runtime_profile_id_required}; omitted_request_field_present=${report.runtime_profile_identity_policy.omitted_request_runtime_profile_id_present}; omitted_uses_launcher_config=${report.runtime_profile_identity_policy.omitted_runtime_profile_id_uses_launcher_config}; supplied_mismatch_refused=${report.runtime_profile_identity_policy.supplied_mismatched_runtime_profile_id_refused}`,
    `Route: recognition_boundary=${report.runtime_profile.recognition_boundary}; mutation_route=${report.runtime_profile.mutation_authoritative_route}; state_storage=${report.runtime_profile.state_storage}; consumed_authority_grant_store=${report.runtime_profile.consumed_authority_grant_store}; consumed_store_lock=${report.runtime_profile.consumed_store_lock}; consumed_store_anchor=${report.runtime_profile.consumed_store_anchor}; consumed_store_witness=${report.runtime_profile.consumed_store_witness}; consumed_store_rollback_detection=${report.runtime_profile.consumed_store_rollback_detection}; consumed_store_write_model=${report.runtime_profile.consumed_store_write_model}; replay_scope=${report.runtime_profile.replay_scope}`,
    `Recognized write: accepted=${accepted.service_write_accepted}; reason=${accepted.reason_code}; state_delta=${accepted.state_entry_count_delta}`,
    `Replay same service process: accepted=${replay.service_write_accepted}; reason=${replay.reason_code}; state_delta=${replay.state_entry_count_delta}`,
    `Replay after service restart: accepted=${restartReplay.service_write_accepted}; reason=${restartReplay.reason_code}; state_delta=${restartReplay.state_entry_count_delta}; separate_process=${restartReplay.separate_process_from_accepted}`,
    `Consumed store failures: invalid_reason=${invalidStore.reason_code}; duplicate_reason=${duplicateStore.reason_code}; locked_reason=${lockedStore.reason_code}; invalid_anchor_reason=${invalidAnchor.reason_code}; rollback_reason=${rollbackDetected.reason_code}; deletion_reason=${deletionDetected.reason_code}; replacement_reason=${replacementDetected.reason_code}; state_delta=0`,
    `Partial grant-store commit: accepted=${witnessCommitFailure.service_write_accepted}; reason=${witnessCommitFailure.reason_code}; consumed_grant_count=${witnessCommitFailure.consumed_authority_grant_count}; state_delta=${witnessCommitFailure.state_entry_count_delta}; atomic_store_anchor_witness_commit=${report.side_door_report.atomic_store_anchor_witness_commit}`,
    `Boundary observation: burned_authority_grant_window accepted=${burnedGrant.service_write_accepted}; reason=${burnedGrant.reason_code}; state_delta=${burnedGrant.state_entry_count_delta}; boundary=${burnedGrant.boundary}`,
    `Boundary observation: store_anchor_and_witness_joint_rollback accepted=${storeAnchorWitnessJointRollback.service_write_accepted}; reason=${storeAnchorWitnessJointRollback.reason_code}; state_delta=${storeAnchorWitnessJointRollback.state_entry_count_delta}; boundary=${storeAnchorWitnessJointRollback.boundary}`,
    `Missing receipt: accepted=${missing.service_write_accepted}; reason=${missing.reason_code}; state_delta=${missing.state_entry_count_delta}`,
    `Invalid receipt: accepted=${invalid.service_write_accepted}; reason=${invalid.reason_code}; state_delta=${invalid.state_entry_count_delta}`,
    `Stale receipt: accepted=${stale.service_write_accepted}; reason=${stale.reason_code}; state_delta=${stale.state_entry_count_delta}`,
    `Agent authority material refused: state_path_reason=${authorityState.reason_code}; recognition_rule_reason=${authorityRule.reason_code}`,
    `Unsupported request field refused: reason=${unsupportedField.reason_code}; state_delta=${unsupportedField.state_entry_count_delta}`,
    `Side-door report: state_path_exposed_to_agent=${report.side_door_report.state_path_exposed_to_agent}; agent_supplied_state_path_refused=${report.side_door_report.agent_supplied_state_path_refused}; persistent_consumed_authority_grant_store=${report.side_door_report.persistent_consumed_authority_grant_store}; consumed_store_anchor_present=${report.side_door_report.consumed_store_anchor_present}; consumed_store_witness_present=${report.side_door_report.consumed_store_witness_present}; invalid_consumed_store_refused=${report.side_door_report.invalid_consumed_store_refused}; invalid_consumed_store_anchor_refused=${report.side_door_report.invalid_consumed_store_anchor_refused}; locked_consumed_store_refused=${report.side_door_report.locked_consumed_store_refused}; exactly_once_effect_semantics=${report.side_door_report.exactly_once_effect_semantics}; atomic_store_anchor_witness_commit=${report.side_door_report.atomic_store_anchor_witness_commit}; partial_grant_commit_burn_window_named=${report.side_door_report.partial_grant_commit_burn_window_named}; valid_store_rollback_detection=${report.side_door_report.valid_store_rollback_detection}; store_and_anchor_joint_rollback_refused_while_witness_ahead=${report.side_door_report.store_and_anchor_joint_rollback_refused_while_witness_ahead}; store_anchor_and_witness_joint_rollback_detection=${report.side_door_report.store_anchor_and_witness_joint_rollback_detection}; cross_process_authority_grant_reuse_closed=${report.side_door_report.cross_process_authority_grant_reuse_closed}; host_process_or_memory_introspection_closed=${report.side_door_report.host_process_or_memory_introspection_closed}; host_filesystem_path_toctou_closed=${report.side_door_report.host_filesystem_path_toctou_closed}`,
    `Known open boundaries: ${report.known_open_boundaries.join(',')}`,
    'Non-claims:',
  ];
  for (const claim of report.non_claims) {
    lines.push(`- ${claim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(summary);
  return summary;
}

export function assertNoUnsafeProtectedRecordsRuntimeProfileText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_OUTPUT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`protected records runtime profile output contains ${label}`);
    }
  }
  return true;
}
