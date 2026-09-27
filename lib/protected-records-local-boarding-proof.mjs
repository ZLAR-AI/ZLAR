import { execFileSync } from 'node:child_process';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from './canonicalize.mjs';
import {
  createProtectedRecordsBoardingDecisionState,
  evaluateProtectedRecordsBoardingDecision,
} from './protected-records-boarding-decision.mjs';
import {
  createReceipt,
  createReceiptV1,
  receiptHashV1,
  sha256hex,
  signReceipt,
  signReceiptV1,
} from './receipt.mjs';

export const PROTECTED_RECORDS_LOCAL_BOARDING_PROOF_TYPE =
  'zlar-protected-records-local-boarding-proof-v1';
export const PROTECTED_RECORDS_LOCAL_BOARDING_COMMAND =
  'zlar protected-records-local-boarding-proof';
export const PROTECTED_RECORDS_LOCAL_BOARDING_EVIDENCE_MODEL =
  'local-in-memory-fixture';
export const PROTECTED_RECORDS_LOCAL_BOARDING_DESTINATION_CONTRACT_TYPE =
  'protected-records-local-boarding-destination-v1';
export const PROTECTED_RECORDS_LOCAL_BOARDING_REPLAY_SCOPE =
  'protected-records-local-boarding-proof.records.write.fixture-v1';
export const PROTECTED_RECORDS_LOCAL_BOARDING_RECOGNITION_CONTRACT_TYPE =
  'downstream-recognition-rule-v1';
export const PROTECTED_RECORDS_LOCAL_BOARDING_REPLAY_CONTRACT_TYPE =
  'protected-records-local-boarding-replay-contract-v1';
export const PROTECTED_RECORDS_LOCAL_BOARDING_RECEIPT_IDENTITY_CONTRACT_TYPE =
  'protected-records-local-boarding-receipt-identity-v1';
export const PROTECTED_RECORDS_LOCAL_BOARDING_RECEIPT_IDENTITY_COMMAND_POSTURE =
  'local-v1-required-receipt-identity-posture';

export const LOCAL_BOARDING_SAFE_CLAIM_CEILING =
  'ZLAR can run a local in-memory protected-records records.write boarding proof where one simulated destination accepts a recognized v1 current-implementation receipt once and refuses missing, invalid, unknown-issuer, inactive-issuer, wrong-destination, wrong-action, wrong-policy, stale, wrong-detail, legacy-v0, and replayed receipts before destination effect.';

export const LOCAL_BOARDING_NON_CLAIMS = Object.freeze([
  'This proof is a local in-memory fixture proof.',
  'This proof is not an install, activation, repair, upgrade, reinstall, hook write, profile write, service write, user config write, or machine config write.',
  'This proof does not inspect a live protected-records system.',
  'This proof does not emit a live receipt.',
  'This proof does not prove current-machine governance.',
  'This proof does not prove live hook execution.',
  'This proof does not prove production downstream recognition.',
  'This proof does not prove external attestation, enterprise readiness, sovereign recognition, or unrouted-surface closure.',
  'This proof does not prove live registry state, live issuer status, key custody, revocation truth, or production authority.',
  'This proof does not prove exactly-once production effects, durable replay protection, multi-host coordination, or rollback-proof storage.',
  'This proof claims current-implementation fixture receipt recognition only, not full standalone receipt-v1 prose/schema/verifier conformance.',
]);

export const REQUIRED_PROTECTED_RECORDS_LOCAL_BOARDING_CASES = Object.freeze([
  Object.freeze({
    case_id: 'no_receipt_refused',
    receipt_class: 'missing_receipt',
    expected_reason_code: 'receipt_missing',
    expected_decision: 'refuse',
    expected_effect_delta: 0,
  }),
  Object.freeze({
    case_id: 'invalid_receipt_refused',
    receipt_class: 'invalid_receipt',
    expected_reason_code: 'receipt_invalid',
    expected_decision: 'refuse',
    expected_effect_delta: 0,
  }),
  Object.freeze({
    case_id: 'unknown_issuer_refused',
    receipt_class: 'unknown_issuer',
    expected_reason_code: 'unknown_issuer',
    expected_decision: 'refuse',
    expected_effect_delta: 0,
  }),
  Object.freeze({
    case_id: 'inactive_issuer_refused',
    receipt_class: 'inactive_issuer',
    expected_reason_code: 'issuer_not_active',
    expected_decision: 'refuse',
    expected_effect_delta: 0,
  }),
  Object.freeze({
    case_id: 'wrong_destination_refused',
    receipt_class: 'wrong_destination',
    expected_reason_code: 'domain_out_of_scope',
    expected_decision: 'refuse',
    expected_effect_delta: 0,
  }),
  Object.freeze({
    case_id: 'wrong_action_refused',
    receipt_class: 'wrong_action',
    expected_reason_code: 'tool_out_of_scope',
    expected_decision: 'refuse',
    expected_effect_delta: 0,
  }),
  Object.freeze({
    case_id: 'wrong_policy_refused',
    receipt_class: 'wrong_policy',
    expected_reason_code: 'policy_not_recognized',
    expected_decision: 'refuse',
    expected_effect_delta: 0,
  }),
  Object.freeze({
    case_id: 'stale_receipt_refused',
    receipt_class: 'stale_receipt',
    expected_reason_code: 'receipt_stale',
    expected_decision: 'refuse',
    expected_effect_delta: 0,
  }),
  Object.freeze({
    case_id: 'wrong_detail_refused',
    receipt_class: 'wrong_detail',
    expected_reason_code: 'detail_hash_mismatch',
    expected_decision: 'refuse',
    expected_effect_delta: 0,
  }),
  Object.freeze({
    case_id: 'legacy_v0_unsupported_refused',
    receipt_class: 'legacy_v0_receipt',
    expected_reason_code: 'unsupported_receipt_format',
    expected_decision: 'refuse',
    expected_effect_delta: 0,
  }),
  Object.freeze({
    case_id: 'recognized_receipt_accepted_once',
    receipt_class: 'recognized_receipt',
    expected_reason_code: 'recognized',
    expected_decision: 'accept',
    expected_effect_delta: 1,
  }),
  Object.freeze({
    case_id: 'replay_refused',
    receipt_class: 'replayed_receipt',
    expected_reason_code: 'receipt_replay',
    expected_decision: 'refuse',
    expected_effect_delta: 0,
  }),
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
  for (let i = 0; i < expected.length; i++) {
    if (value[i] !== expected[i]) {
      throw new Error(`${label} drifted`);
    }
  }
  return true;
}

function sourceState() {
  const projectDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  let commit = null;
  let status = null;
  try {
    const value = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: projectDir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    commit = /^[a-f0-9]{40}$/.test(value) ? value : null;
  } catch {
    commit = null;
  }
  try {
    status = execFileSync('git', ['status', '--porcelain', '--untracked-files=normal'], {
      cwd: projectDir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    status = null;
  }
  const statusKnown = typeof status === 'string';
  const worktreeClean = statusKnown ? status.trim().length === 0 : false;
  return {
    commit,
    provenance: worktreeClean ? 'clean-commit' : 'commit-plus-uncommitted-worktree',
    status_known: statusKnown,
    uncommitted_changes: !worktreeClean,
    worktree_clean: worktreeClean,
  };
}

function pemFingerprint(publicPem) {
  return createHash('sha256').update(Buffer.from(publicPem, 'utf8')).digest('hex').slice(0, 16);
}

function keyFixture() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  return {
    privatePem,
    publicPem,
    kid: pemFingerprint(publicPem),
  };
}

function isoSecondsAgo(nowEpoch, seconds) {
  return new Date((nowEpoch - seconds) * 1000).toISOString();
}

function hashOrNull(value) {
  return typeof value === 'string' && value.length > 0 ? sha256hex(value) : null;
}

function fixtureEvent(nowEpoch, overrides = {}) {
  return {
    id: overrides.audit_event_id || 'protected-records-local-boarding-write-001',
    action: overrides.action || 'records.write',
    authorizer: overrides.authorizer || 'policy',
    detail: overrides.detail || {
      record_id: 'local-boarding-fixture-record',
      operation: 'append_controlled_status',
    },
    domain: overrides.domain || 'records',
    outcome: overrides.outcome || 'allow',
    policy_version: overrides.policy_version || 'recognition-policy-v1',
    prev_hash: overrides.prev_hash || '0'.repeat(64),
    rule: overrides.rule || 'RRECORDS_LOCAL_BOARDING_ALLOW',
    ts: overrides.ts || isoSecondsAgo(nowEpoch, 5),
  };
}

function signedReceipt(key, nowEpoch, overrides = {}) {
  return signReceiptV1(
    createReceiptV1({
      id: overrides.receipt_id,
      tool: overrides.action || 'records.write',
      domain: overrides.domain || 'records',
      detail: overrides.detail || {
        record_id: 'local-boarding-fixture-record',
        operation: 'append_controlled_status',
      },
      outcome: overrides.outcome || 'allow',
      rule: overrides.rule || 'RRECORDS_LOCAL_BOARDING_ALLOW',
      authorizer: overrides.authorizer || 'policy',
      timestamp: overrides.ts || isoSecondsAgo(nowEpoch, 5),
      policy_version: overrides.policy_version || 'recognition-policy-v1',
      audit_event_id: overrides.audit_event_id || 'protected-records-local-boarding-write-001',
      audit_prev_hash: overrides.prev_hash || '0'.repeat(64),
      prev_receipt_hash: overrides.prev_receipt_hash ?? null,
    }),
    key.privatePem,
    key.kid
  );
}

function signedLegacyV0Receipt(key, nowEpoch, overrides = {}) {
  return signReceipt(
    createReceipt({
      id: overrides.receipt_id,
      tool: overrides.action || 'records.write',
      domain: overrides.domain || 'records',
      detail: overrides.detail || {
        record_id: 'local-boarding-fixture-record',
        operation: 'append_controlled_status',
      },
      outcome: overrides.outcome || 'allow',
      rule: overrides.rule || 'RRECORDS_LOCAL_BOARDING_ALLOW',
      authorizer: overrides.authorizer || 'policy',
      timestamp: overrides.ts || isoSecondsAgo(nowEpoch, 5),
      policy_version: overrides.policy_version || 'recognition-policy-v1',
      audit_event_id: overrides.audit_event_id || 'protected-records-local-boarding-write-001',
      audit_prev_hash: overrides.prev_hash || '0'.repeat(64),
      prev_receipt_hash: overrides.prev_receipt_hash ?? null,
    }),
    key.privatePem,
    key.kid
  );
}

function receiptIdentityContract({ receipt, publicPem, kid }) {
  return {
    contract_type: PROTECTED_RECORDS_LOCAL_BOARDING_RECEIPT_IDENTITY_CONTRACT_TYPE,
    evidence_model: 'local-fixture-v1-receipt-identity',
    command_posture: PROTECTED_RECORDS_LOCAL_BOARDING_RECEIPT_IDENTITY_COMMAND_POSTURE,
    recognized_receipt_format: 'v1',
    canonical_signed_receipt_object_sha256: receiptHashV1(receipt),
    provided_pubkey_sha256: sha256hex(publicPem),
    receipt_id_hash: hashOrNull(receipt.id),
    kid_hash: hashOrNull(kid),
    required_receipt_id_matched: true,
    required_receipt_sha256_matched: true,
    required_kid_matched: true,
    required_pubkey_sha256_matched: true,
    required_format_matched: true,
    required_v1_only_matched: true,
    legacy_v0_recognized_boarding_identity: false,
    issuer_liveness_truth_proven: false,
    key_custody_proven: false,
    revocation_truth_proven: false,
    production_downstream_recognition_proven: false,
  };
}

function createDestination({ recognitionRule, nowEpoch }) {
  const state = createProtectedRecordsBoardingDecisionState();

  function apply({ caseId, receipt, receiptClass, expectedReasonCode }) {
    return evaluateProtectedRecordsBoardingDecision({
      actionClass: 'records.write',
      caseId,
      effectType: 'protected-records-local-boarding-effect-v1',
      expectedReasonCode,
      nowEpoch,
      receipt,
      receiptClass,
      recognitionRule,
      replayScope: PROTECTED_RECORDS_LOCAL_BOARDING_REPLAY_SCOPE,
      state,
    });
  }

  return {
    apply,
    finalEffectCount: () => state.effects.length,
    replayCacheSize: () => state.replayCache.size,
    effects: () => state.effects.map((effect) => ({ ...effect })),
  };
}

function fixtureContractSha256({ actionDetailHash, recognitionRule }) {
  return sha256hex(canonicalize({
    action_class: 'records.write',
    destination_scope: PROTECTED_RECORDS_LOCAL_BOARDING_REPLAY_SCOPE,
    evidence_model: PROTECTED_RECORDS_LOCAL_BOARDING_EVIDENCE_MODEL,
    required_action_detail_hash: actionDetailHash,
    required_cases: REQUIRED_PROTECTED_RECORDS_LOCAL_BOARDING_CASES.map((item) => ({
      case_id: item.case_id,
      expected_decision: item.expected_decision,
      expected_effect_delta: item.expected_effect_delta,
      expected_reason_code: item.expected_reason_code,
      refusal_before_effect_required: item.expected_decision === 'refuse',
    })),
    terminal_outcome_contract: {
      consequence_absent_on_every_refusal: true,
      consequence_present_exactly_once_on_acceptance: true,
      final_effect_count: 1,
      legacy_v0_recognized_boarding_identity: false,
      recognized_receipt_accepted_once: true,
      replay_refused_after_acceptance: true,
      v1_receipt_identity_required: true,
    },
    recognition_rule: {
      accepted_domains: recognitionRule.accepted_domains,
      accepted_outcomes: recognitionRule.accepted_outcomes,
      accepted_policy_versions: recognitionRule.accepted_policy_versions,
      accepted_tools: recognitionRule.accepted_tools,
      deployment_scope: recognitionRule.deployment_scope,
      max_age_seconds: recognitionRule.max_age_seconds,
      required_audit_event_id: recognitionRule.required_audit_event_id,
      required_detail_hash: recognitionRule.required_detail_hash,
    },
  }));
}

function buildSummary(caseSummaries, destination, identityContract) {
  const expectedCases = REQUIRED_PROTECTED_RECORDS_LOCAL_BOARDING_CASES;
  const byId = new Map(caseSummaries.map((item) => [item.case_id, item]));
  const allRequiredCasesPresent = expectedCases.every((item) => byId.has(item.case_id));
  const allExpectedReasonCodesMatch = expectedCases.every((item) => {
    const observed = byId.get(item.case_id);
    return observed?.observed_reason_code === item.expected_reason_code;
  });
  const refusalCases = caseSummaries.filter((item) => item.expected_decision !== 'accept');
  const recognizedCase = byId.get('recognized_receipt_accepted_once');
  const replayCase = byId.get('replay_refused');
  const v1ReceiptIdentityVerified =
    identityContract.contract_type === PROTECTED_RECORDS_LOCAL_BOARDING_RECEIPT_IDENTITY_CONTRACT_TYPE &&
    identityContract.command_posture === PROTECTED_RECORDS_LOCAL_BOARDING_RECEIPT_IDENTITY_COMMAND_POSTURE &&
    identityContract.recognized_receipt_format === 'v1' &&
    /^[a-f0-9]{64}$/.test(identityContract.canonical_signed_receipt_object_sha256 || '') &&
    /^[a-f0-9]{64}$/.test(identityContract.provided_pubkey_sha256 || '') &&
    /^[a-f0-9]{64}$/.test(identityContract.receipt_id_hash || '') &&
    /^[a-f0-9]{64}$/.test(identityContract.kid_hash || '') &&
    identityContract.required_receipt_id_matched === true &&
    identityContract.required_receipt_sha256_matched === true &&
    identityContract.required_kid_matched === true &&
    identityContract.required_pubkey_sha256_matched === true &&
    identityContract.required_format_matched === true &&
    identityContract.required_v1_only_matched === true &&
    identityContract.legacy_v0_recognized_boarding_identity === false;
  const consequenceAbsentOnEveryRefusal =
    refusalCases.every((item) => item.refused_before_effect === true) &&
    refusalCases.every((item) => item.effect_count_delta === 0);
  const consequencePresentExactlyOnceOnAcceptance =
    recognizedCase?.decision === 'accept' &&
    recognizedCase?.recognized === true &&
    recognizedCase?.effect_count_before === 0 &&
    recognizedCase?.effect_count_after === 1 &&
    recognizedCase?.effect_count_delta === 1 &&
    recognizedCase?.accepted_once_marker === true &&
    destination.finalEffectCount() === 1;

  return {
    all_required_cases_present: allRequiredCasesPresent,
    all_expected_reason_codes_match: allExpectedReasonCodesMatch,
    all_refusals_before_effect: refusalCases.every((item) => item.refused_before_effect === true),
    all_refusal_effect_deltas_zero: refusalCases.every((item) => item.effect_count_delta === 0),
    consequence_absent_on_every_refusal: consequenceAbsentOnEveryRefusal,
    consequence_present_exactly_once_on_acceptance: consequencePresentExactlyOnceOnAcceptance,
    v1_receipt_identity_verified: v1ReceiptIdentityVerified,
    legacy_v0_recognized_boarding_identity: false,
    recognized_receipt_accepted_once:
      recognizedCase?.decision === 'accept' &&
      recognizedCase?.recognized === true &&
      recognizedCase?.effect_count_delta === 1 &&
      recognizedCase?.accepted_once_marker === true,
    recognized_effect_delta_is_one: recognizedCase?.effect_count_delta === 1,
    replay_refused_after_acceptance:
      replayCase?.decision === 'refuse' &&
      replayCase?.observed_reason_code === 'receipt_replay' &&
      replayCase?.effect_count_delta === 0 &&
      replayCase?.effect_count_after === 1,
    final_effect_count: destination.finalEffectCount(),
    live_probing: false,
    current_machine_governance_proven: false,
    production_downstream_recognition_proven: false,
  };
}

function assertRecognitionSummary(recognition, caseId, expectedReasonCode, expectedDecision, expectedRecognized) {
  assertExactKeys('Protected records local boarding case recognition', recognition, [
    'decision',
    'evidence',
    'reason_code',
    'reasons',
    'recognized',
    'result_type',
  ]);
  if (
    recognition.decision !== expectedDecision ||
    recognition.reason_code !== expectedReasonCode ||
    recognition.recognized !== expectedRecognized ||
    typeof recognition.result_type !== 'string' ||
    recognition.result_type.length === 0 ||
    !Array.isArray(recognition.reasons) ||
    recognition.reasons.length === 0
  ) {
    throw new Error(`Protected records local boarding recognition summary drifted for ${caseId}`);
  }
  for (const reason of recognition.reasons) {
    assertExactKeys('Protected records local boarding recognition reason', reason, [
      'code',
      'message',
    ]);
    if (typeof reason.code !== 'string' || reason.code.length === 0) {
      throw new Error(`Protected records local boarding recognition reason code drifted for ${caseId}`);
    }
    if (typeof reason.message !== 'string' || reason.message.length === 0) {
      throw new Error(`Protected records local boarding recognition reason message drifted for ${caseId}`);
    }
  }
  assertExactKeys('Protected records local boarding recognition evidence', recognition.evidence, [
    'issuer_known',
    'issuer_status',
    'kid_hash',
    'payload',
    'receipt_id_hash',
    'receipt_present',
    'receipt_type',
    'receipt_version',
    'signature_valid',
  ]);
  for (const key of [
    'kid_hash',
    'receipt_id_hash',
  ]) {
    if (recognition.evidence[key] !== null && !/^[a-f0-9]{64}$/.test(recognition.evidence[key])) {
      throw new Error(`Protected records local boarding recognition ${key} must be null or sha256 hex for ${caseId}`);
    }
  }
  assertExactKeys('Protected records local boarding recognition payload', recognition.evidence.payload, [
    'age_seconds',
    'audit_event_id',
    'authorizer',
    'detail_hash',
    'domain',
    'outcome',
    'policy_version',
    'rule',
    'tool',
  ]);
  if (
    recognition.evidence.payload.detail_hash !== null &&
    !/^[a-f0-9]{64}$/.test(recognition.evidence.payload.detail_hash)
  ) {
    throw new Error(`Protected records local boarding recognition detail hash drifted for ${caseId}`);
  }
  return true;
}

function assertReceiptIdentityContract(contract) {
  assertExactKeys('Protected records local boarding receipt identity contract', contract, [
    'canonical_signed_receipt_object_sha256',
    'command_posture',
    'contract_type',
    'evidence_model',
    'issuer_liveness_truth_proven',
    'key_custody_proven',
    'kid_hash',
    'legacy_v0_recognized_boarding_identity',
    'production_downstream_recognition_proven',
    'provided_pubkey_sha256',
    'receipt_id_hash',
    'recognized_receipt_format',
    'required_format_matched',
    'required_kid_matched',
    'required_pubkey_sha256_matched',
    'required_receipt_id_matched',
    'required_receipt_sha256_matched',
    'required_v1_only_matched',
    'revocation_truth_proven',
  ]);
  for (const key of [
    'canonical_signed_receipt_object_sha256',
    'provided_pubkey_sha256',
    'receipt_id_hash',
    'kid_hash',
  ]) {
    if (!/^[a-f0-9]{64}$/.test(contract[key] || '')) {
      throw new Error(`Protected records local boarding receipt identity ${key} must be sha256 hex`);
    }
  }
  if (
    contract.contract_type !== PROTECTED_RECORDS_LOCAL_BOARDING_RECEIPT_IDENTITY_CONTRACT_TYPE ||
    contract.evidence_model !== 'local-fixture-v1-receipt-identity' ||
    contract.command_posture !== PROTECTED_RECORDS_LOCAL_BOARDING_RECEIPT_IDENTITY_COMMAND_POSTURE ||
    contract.recognized_receipt_format !== 'v1' ||
    contract.required_receipt_id_matched !== true ||
    contract.required_receipt_sha256_matched !== true ||
    contract.required_kid_matched !== true ||
    contract.required_pubkey_sha256_matched !== true ||
    contract.required_format_matched !== true ||
    contract.required_v1_only_matched !== true ||
    contract.legacy_v0_recognized_boarding_identity !== false ||
    contract.issuer_liveness_truth_proven !== false ||
    contract.key_custody_proven !== false ||
    contract.revocation_truth_proven !== false ||
    contract.production_downstream_recognition_proven !== false
  ) {
    throw new Error('Protected records local boarding receipt identity contract drifted');
  }
  return true;
}

export function runProtectedRecordsLocalBoardingProof({
  nowEpoch = Math.floor(Date.now() / 1000),
} = {}) {
  const active = keyFixture();
  const inactive = keyFixture();
  const unknown = keyFixture();
  const actionDetail = fixtureEvent(nowEpoch).detail;
  const actionDetailHash = sha256hex(canonicalize(actionDetail));
  const recognitionRule = {
    deployment_scope: PROTECTED_RECORDS_LOCAL_BOARDING_REPLAY_SCOPE,
    accepted_issuers: [
      {
        kid: active.kid,
        public_key_pem: active.publicPem,
        status: 'active',
      },
      {
        kid: inactive.kid,
        public_key_pem: inactive.publicPem,
        status: 'inactive',
      },
    ],
    accepted_policy_versions: ['recognition-policy-v1'],
    accepted_domains: ['records'],
    accepted_tools: ['records.write'],
    accepted_outcomes: ['allow', 'authorized'],
    max_age_seconds: 120,
    required_audit_event_id: 'protected-records-local-boarding-write-001',
    required_detail_hash: actionDetailHash,
  };

  const recognizedReceipt = signedReceipt(active, nowEpoch, {
    receipt_id: `${'a'.repeat(12)}${'1'.repeat(32)}`,
  });
  const invalidReceiptBase = signedReceipt(active, nowEpoch, {
    receipt_id: `${'b'.repeat(12)}${'2'.repeat(32)}`,
  });
  const invalidReceipt = {
    ...invalidReceiptBase,
    sig: `${invalidReceiptBase.sig.slice(0, -2)}xx`,
  };
  const unknownIssuerReceipt = signedReceipt(unknown, nowEpoch, {
    receipt_id: `${'c'.repeat(12)}${'3'.repeat(32)}`,
  });
  const inactiveIssuerReceipt = signedReceipt(inactive, nowEpoch, {
    receipt_id: `${'d'.repeat(12)}${'4'.repeat(32)}`,
  });
  const wrongDestinationReceipt = signedReceipt(active, nowEpoch, {
    receipt_id: `${'f'.repeat(12)}${'6'.repeat(32)}`,
    domain: 'records-other',
  });
  const wrongActionReceipt = signedReceipt(active, nowEpoch, {
    receipt_id: `${'1'.repeat(12)}${'7'.repeat(32)}`,
    action: 'records.delete',
  });
  const wrongPolicyReceipt = signedReceipt(active, nowEpoch, {
    receipt_id: `${'2'.repeat(12)}${'8'.repeat(32)}`,
    policy_version: 'unrecognized-recognition-policy-v1',
  });
  const staleReceipt = signedReceipt(active, nowEpoch, {
    receipt_id: `${'3'.repeat(12)}${'9'.repeat(32)}`,
    ts: isoSecondsAgo(nowEpoch, 3600),
  });
  const wrongDetailReceipt = signedReceipt(active, nowEpoch, {
    receipt_id: `${'e'.repeat(12)}${'5'.repeat(32)}`,
    detail: {
      record_id: 'local-boarding-fixture-record-other',
      operation: 'append_controlled_status',
    },
  });
  const legacyV0Receipt = signedLegacyV0Receipt(active, nowEpoch, {
    receipt_id: `${'4'.repeat(12)}${'0'.repeat(32)}`,
  });
  const identityContract = receiptIdentityContract({
    receipt: recognizedReceipt,
    publicPem: active.publicPem,
    kid: active.kid,
  });

  const destination = createDestination({ recognitionRule, nowEpoch });
  const receiptsByCaseId = new Map([
    ['no_receipt_refused', null],
    ['invalid_receipt_refused', invalidReceipt],
    ['unknown_issuer_refused', unknownIssuerReceipt],
    ['inactive_issuer_refused', inactiveIssuerReceipt],
    ['wrong_destination_refused', wrongDestinationReceipt],
    ['wrong_action_refused', wrongActionReceipt],
    ['wrong_policy_refused', wrongPolicyReceipt],
    ['stale_receipt_refused', staleReceipt],
    ['wrong_detail_refused', wrongDetailReceipt],
    ['legacy_v0_unsupported_refused', legacyV0Receipt],
    ['recognized_receipt_accepted_once', recognizedReceipt],
    ['replay_refused', recognizedReceipt],
  ]);
  const inputs = REQUIRED_PROTECTED_RECORDS_LOCAL_BOARDING_CASES.map((required) => ({
    ...required,
    receipt: receiptsByCaseId.get(required.case_id),
  }));

  const caseSummaries = inputs.map((input) => {
    const summary = destination.apply({
      caseId: input.case_id,
      receipt: input.receipt,
      receiptClass: input.receipt_class,
      expectedReasonCode: input.expected_reason_code,
    });
    return {
      ...summary,
      expected_decision: input.expected_decision,
      expected_effect_delta: input.expected_effect_delta,
    };
  });

  const summary = buildSummary(caseSummaries, destination, identityContract);
  const state = sourceState();
  const report = {
    proof_type: PROTECTED_RECORDS_LOCAL_BOARDING_PROOF_TYPE,
    command: PROTECTED_RECORDS_LOCAL_BOARDING_COMMAND,
    source_commit: state.commit,
    source_state: state,
    evidence_model: PROTECTED_RECORDS_LOCAL_BOARDING_EVIDENCE_MODEL,
    live_probing: false,
    action_class: 'records.write',
    destination_contract: {
      contract_type: PROTECTED_RECORDS_LOCAL_BOARDING_DESTINATION_CONTRACT_TYPE,
      destination_scope: PROTECTED_RECORDS_LOCAL_BOARDING_REPLAY_SCOPE,
      mutation_authoritative_route: 'receipt-recognition-before-local-proof-effect',
      effect_model: 'in-memory-bounded-proof-effect',
      live_records_system: false,
      persistent_store_written: false,
      current_machine_governance_proven: false,
    },
    recognition_contract: {
      contract_type: PROTECTED_RECORDS_LOCAL_BOARDING_RECOGNITION_CONTRACT_TYPE,
      recognized_receipt_requires_active_issuer: true,
      recognized_receipt_requires_signature_valid: true,
      recognized_receipt_requires_detail_hash_match: true,
      recognized_receipt_requires_v1_identity_contract: true,
      recognized_receipt_rule_binds_policy_domain_tool_outcome_audit_freshness: true,
      policy_domain_tool_outcome_audit_freshness_refusal_cases_proven: false,
      policy_domain_tool_detail_freshness_refusal_cases_proven: true,
      legacy_v0_unsupported_refusal_case_proven: true,
      legacy_v0_receipts_recognized_as_boarding_identity: false,
      proven_scope_mismatch_refusal_reason_codes: [
        'domain_out_of_scope',
        'tool_out_of_scope',
        'detail_hash_mismatch',
      ],
      proven_refusal_reason_codes: REQUIRED_PROTECTED_RECORDS_LOCAL_BOARDING_CASES
        .filter((item) => item.expected_decision === 'refuse')
        .map((item) => item.expected_reason_code),
      current_implementation_fixture_recognition_only: true,
      full_receipt_v1_conformance_claimed: false,
    },
    receipt_identity_contract: identityContract,
    replay_contract: {
      contract_type: PROTECTED_RECORDS_LOCAL_BOARDING_REPLAY_CONTRACT_TYPE,
      cache_model: 'in-memory-single-run',
      scope: PROTECTED_RECORDS_LOCAL_BOARDING_REPLAY_SCOPE,
      durable_replay_store: false,
      exactly_once_production_effects: false,
      replay_cache_final_size: destination.replayCacheSize(),
    },
    fixture_contract_sha256: fixtureContractSha256({ actionDetailHash, recognitionRule }),
    case_summaries: caseSummaries,
    effects: destination.effects(),
    summary,
    safe_claim_ceiling: LOCAL_BOARDING_SAFE_CLAIM_CEILING,
    non_claims: [...LOCAL_BOARDING_NON_CLAIMS],
  };

  assertProtectedRecordsLocalBoardingProof(report);
  assertNoUnsafeProtectedRecordsLocalBoardingProofText(JSON.stringify(report));
  return report;
}

export function assertProtectedRecordsLocalBoardingProof(report) {
  assertExactKeys('Protected records local boarding proof', report, [
    'action_class',
    'case_summaries',
    'command',
    'destination_contract',
    'effects',
    'evidence_model',
    'fixture_contract_sha256',
    'live_probing',
    'non_claims',
    'proof_type',
    'recognition_contract',
    'receipt_identity_contract',
    'replay_contract',
    'safe_claim_ceiling',
    'source_commit',
    'source_state',
    'summary',
  ]);

  if (
    report.proof_type !== PROTECTED_RECORDS_LOCAL_BOARDING_PROOF_TYPE ||
    report.command !== PROTECTED_RECORDS_LOCAL_BOARDING_COMMAND ||
    report.evidence_model !== PROTECTED_RECORDS_LOCAL_BOARDING_EVIDENCE_MODEL ||
    report.live_probing !== false ||
    report.action_class !== 'records.write'
  ) {
    throw new Error('Protected records local boarding proof top-level contract drifted');
  }
  if (report.source_commit !== null && !/^[a-f0-9]{40}$/.test(report.source_commit)) {
    throw new Error('Protected records local boarding proof source commit must be null or a Git SHA');
  }
  assertExactKeys('Protected records local boarding source state', report.source_state, [
    'commit',
    'provenance',
    'status_known',
    'uncommitted_changes',
    'worktree_clean',
  ]);
  if (
    report.source_state.commit !== report.source_commit ||
    (report.source_state.commit !== null && !/^[a-f0-9]{40}$/.test(report.source_state.commit)) ||
    !['clean-commit', 'commit-plus-uncommitted-worktree'].includes(report.source_state.provenance) ||
    typeof report.source_state.status_known !== 'boolean' ||
    typeof report.source_state.uncommitted_changes !== 'boolean' ||
    typeof report.source_state.worktree_clean !== 'boolean' ||
    report.source_state.uncommitted_changes === report.source_state.worktree_clean
  ) {
    throw new Error('Protected records local boarding proof source state drifted');
  }
  if (report.source_state.worktree_clean === true && report.source_state.provenance !== 'clean-commit') {
    throw new Error('Protected records local boarding proof clean source provenance drifted');
  }
  if (report.source_state.worktree_clean === false && report.source_state.provenance !== 'commit-plus-uncommitted-worktree') {
    throw new Error('Protected records local boarding proof dirty source provenance drifted');
  }
  if (!/^[a-f0-9]{64}$/.test(report.fixture_contract_sha256 || '')) {
    throw new Error('Protected records local boarding proof fixture contract hash must be sha256 hex');
  }

  assertExactKeys('Protected records local boarding destination contract', report.destination_contract, [
    'contract_type',
    'current_machine_governance_proven',
    'destination_scope',
    'effect_model',
    'live_records_system',
    'mutation_authoritative_route',
    'persistent_store_written',
  ]);
  if (
    report.destination_contract.contract_type !== PROTECTED_RECORDS_LOCAL_BOARDING_DESTINATION_CONTRACT_TYPE ||
    report.destination_contract.destination_scope !== PROTECTED_RECORDS_LOCAL_BOARDING_REPLAY_SCOPE ||
    report.destination_contract.mutation_authoritative_route !== 'receipt-recognition-before-local-proof-effect' ||
    report.destination_contract.effect_model !== 'in-memory-bounded-proof-effect' ||
    report.destination_contract.live_records_system !== false ||
    report.destination_contract.persistent_store_written !== false ||
    report.destination_contract.current_machine_governance_proven !== false
  ) {
    throw new Error('Protected records local boarding destination contract drifted');
  }

  assertExactKeys('Protected records local boarding recognition contract', report.recognition_contract, [
    'contract_type',
    'current_implementation_fixture_recognition_only',
    'full_receipt_v1_conformance_claimed',
    'legacy_v0_receipts_recognized_as_boarding_identity',
    'legacy_v0_unsupported_refusal_case_proven',
    'policy_domain_tool_detail_freshness_refusal_cases_proven',
    'policy_domain_tool_outcome_audit_freshness_refusal_cases_proven',
    'proven_refusal_reason_codes',
    'proven_scope_mismatch_refusal_reason_codes',
    'recognized_receipt_requires_active_issuer',
    'recognized_receipt_requires_detail_hash_match',
    'recognized_receipt_requires_signature_valid',
    'recognized_receipt_requires_v1_identity_contract',
    'recognized_receipt_rule_binds_policy_domain_tool_outcome_audit_freshness',
  ]);
  if (
    report.recognition_contract.contract_type !== PROTECTED_RECORDS_LOCAL_BOARDING_RECOGNITION_CONTRACT_TYPE ||
    report.recognition_contract.recognized_receipt_requires_active_issuer !== true ||
    report.recognition_contract.recognized_receipt_requires_signature_valid !== true ||
    report.recognition_contract.recognized_receipt_requires_detail_hash_match !== true ||
    report.recognition_contract.recognized_receipt_requires_v1_identity_contract !== true ||
    report.recognition_contract.recognized_receipt_rule_binds_policy_domain_tool_outcome_audit_freshness !== true ||
    report.recognition_contract.policy_domain_tool_outcome_audit_freshness_refusal_cases_proven !== false ||
    report.recognition_contract.policy_domain_tool_detail_freshness_refusal_cases_proven !== true ||
    report.recognition_contract.legacy_v0_unsupported_refusal_case_proven !== true ||
    report.recognition_contract.legacy_v0_receipts_recognized_as_boarding_identity !== false ||
    report.recognition_contract.current_implementation_fixture_recognition_only !== true ||
    report.recognition_contract.full_receipt_v1_conformance_claimed !== false
  ) {
    throw new Error('Protected records local boarding recognition contract drifted');
  }
  assertExactArray(
    'Protected records local boarding proven scope mismatch refusal reason codes',
    report.recognition_contract.proven_scope_mismatch_refusal_reason_codes,
    ['domain_out_of_scope', 'tool_out_of_scope', 'detail_hash_mismatch']
  );
  assertExactArray(
    'Protected records local boarding proven refusal reason codes',
    report.recognition_contract.proven_refusal_reason_codes,
    REQUIRED_PROTECTED_RECORDS_LOCAL_BOARDING_CASES
      .filter((item) => item.expected_decision === 'refuse')
      .map((item) => item.expected_reason_code)
  );
  assertReceiptIdentityContract(report.receipt_identity_contract);

  assertExactKeys('Protected records local boarding replay contract', report.replay_contract, [
    'cache_model',
    'contract_type',
    'durable_replay_store',
    'exactly_once_production_effects',
    'replay_cache_final_size',
    'scope',
  ]);
  if (
    report.replay_contract.contract_type !== PROTECTED_RECORDS_LOCAL_BOARDING_REPLAY_CONTRACT_TYPE ||
    report.replay_contract.cache_model !== 'in-memory-single-run' ||
    report.replay_contract.scope !== PROTECTED_RECORDS_LOCAL_BOARDING_REPLAY_SCOPE ||
    report.replay_contract.durable_replay_store !== false ||
    report.replay_contract.exactly_once_production_effects !== false ||
    report.replay_contract.replay_cache_final_size !== 1
  ) {
    throw new Error('Protected records local boarding replay contract drifted');
  }

  if (!Array.isArray(report.case_summaries) || report.case_summaries.length !== REQUIRED_PROTECTED_RECORDS_LOCAL_BOARDING_CASES.length) {
    throw new Error('Protected records local boarding proof case count drifted');
  }
  for (let i = 0; i < REQUIRED_PROTECTED_RECORDS_LOCAL_BOARDING_CASES.length; i++) {
    const expected = REQUIRED_PROTECTED_RECORDS_LOCAL_BOARDING_CASES[i];
    const item = report.case_summaries[i];
    assertExactKeys('Protected records local boarding case summary', item, [
      'accepted_once_marker',
      'case_id',
      'decision',
      'effect_count_after',
      'effect_count_before',
      'effect_count_delta',
      'expected_decision',
      'expected_effect_delta',
      'expected_reason_code',
      'observed_reason_code',
      'receipt_class',
      'receipt_id_hash',
      'recognized',
      'recognition',
      'refused_before_effect',
    ]);
    if (
      item.case_id !== expected.case_id ||
      item.receipt_class !== expected.receipt_class ||
      item.expected_reason_code !== expected.expected_reason_code ||
      item.observed_reason_code !== expected.expected_reason_code ||
      item.expected_decision !== expected.expected_decision ||
      item.decision !== expected.expected_decision ||
      item.expected_effect_delta !== expected.expected_effect_delta ||
      item.effect_count_delta !== expected.expected_effect_delta
    ) {
      throw new Error(`Protected records local boarding case ${expected.case_id} drifted`);
    }
    if (item.expected_decision === 'refuse' && item.refused_before_effect !== true) {
      throw new Error(`Protected records local boarding refusal case ${expected.case_id} changed destination effect`);
    }
    if (!Number.isInteger(item.effect_count_before) || !Number.isInteger(item.effect_count_after)) {
      throw new Error(`Protected records local boarding case ${expected.case_id} has invalid effect counts`);
    }
    assertRecognitionSummary(
      item.recognition,
      expected.case_id,
      item.observed_reason_code,
      item.decision,
      item.recognized
    );
  }

  const recognized = report.case_summaries.find((item) => item.case_id === 'recognized_receipt_accepted_once');
  if (
    recognized?.recognized !== true ||
    recognized.accepted_once_marker !== true ||
    recognized.effect_count_before !== 0 ||
    recognized.effect_count_after !== 1
  ) {
    throw new Error('Protected records local boarding recognized receipt did not board exactly once in the local proof');
  }
  const replay = report.case_summaries.find((item) => item.case_id === 'replay_refused');
  if (
    replay?.recognized !== false ||
    replay.refused_before_effect !== true ||
    replay.effect_count_before !== 1 ||
    replay.effect_count_after !== 1
  ) {
    throw new Error('Protected records local boarding replay was not refused after first acceptance');
  }

  if (!Array.isArray(report.effects) || report.effects.length !== 1) {
    throw new Error('Protected records local boarding proof must end with exactly one effect');
  }
  assertExactKeys('Protected records local boarding effect', report.effects[0], [
    'action_class',
    'audit_event_id',
    'detail_hash',
    'effect_type',
    'receipt_id_hash',
    'transition',
  ]);
  if (
    report.effects[0].effect_type !== 'protected-records-local-boarding-effect-v1' ||
    report.effects[0].action_class !== 'records.write' ||
    report.effects[0].transition !== 'recognized_receipt_boarded' ||
    !/^[a-f0-9]{64}$/.test(report.effects[0].detail_hash || '') ||
    !/^[a-f0-9]{64}$/.test(report.effects[0].receipt_id_hash || '')
  ) {
    throw new Error('Protected records local boarding effect contract drifted');
  }

  assertExactKeys('Protected records local boarding summary', report.summary, [
    'all_expected_reason_codes_match',
    'all_refusal_effect_deltas_zero',
    'all_refusals_before_effect',
    'all_required_cases_present',
    'consequence_absent_on_every_refusal',
    'consequence_present_exactly_once_on_acceptance',
    'current_machine_governance_proven',
    'final_effect_count',
    'legacy_v0_recognized_boarding_identity',
    'live_probing',
    'production_downstream_recognition_proven',
    'recognized_effect_delta_is_one',
    'recognized_receipt_accepted_once',
    'replay_refused_after_acceptance',
    'v1_receipt_identity_verified',
  ]);
  for (const key of [
    'all_required_cases_present',
    'all_expected_reason_codes_match',
    'all_refusals_before_effect',
    'all_refusal_effect_deltas_zero',
    'consequence_absent_on_every_refusal',
    'consequence_present_exactly_once_on_acceptance',
    'v1_receipt_identity_verified',
    'recognized_receipt_accepted_once',
    'recognized_effect_delta_is_one',
    'replay_refused_after_acceptance',
  ]) {
    if (report.summary[key] !== true) {
      throw new Error(`Protected records local boarding summary ${key} must be true`);
    }
  }
  if (
    report.summary.final_effect_count !== 1 ||
    report.summary.legacy_v0_recognized_boarding_identity !== false ||
    report.summary.live_probing !== false ||
    report.summary.current_machine_governance_proven !== false ||
    report.summary.production_downstream_recognition_proven !== false
  ) {
    throw new Error('Protected records local boarding summary boundary drifted');
  }

  if (report.safe_claim_ceiling !== LOCAL_BOARDING_SAFE_CLAIM_CEILING) {
    throw new Error('Protected records local boarding safe claim ceiling drifted');
  }
  assertExactArray('Protected records local boarding non-claims', report.non_claims, LOCAL_BOARDING_NON_CLAIMS);
  assertNoUnsafeProtectedRecordsLocalBoardingProofText(JSON.stringify(report));
  return true;
}

export function formatProtectedRecordsLocalBoardingProofSummary(report) {
  const lines = [
    'Protected Records Local Boarding Proof v1',
    `Command: ${report.command}`,
    `Source state: commit=${report.source_commit || 'unknown'}; provenance=${report.source_state.provenance}; worktree_clean=${report.source_state.worktree_clean}; uncommitted_changes=${report.source_state.uncommitted_changes}`,
    `Evidence model: ${report.evidence_model}; live_probing=${report.live_probing}`,
    `Action class: ${report.action_class}`,
    `Destination: type=${report.destination_contract.contract_type}; scope=${report.destination_contract.destination_scope}; route=${report.destination_contract.mutation_authoritative_route}; effect_model=${report.destination_contract.effect_model}`,
    `Recognition: active_issuer=${report.recognition_contract.recognized_receipt_requires_active_issuer}; signature_valid=${report.recognition_contract.recognized_receipt_requires_signature_valid}; detail_hash_match=${report.recognition_contract.recognized_receipt_requires_detail_hash_match}; v1_identity_contract=${report.recognition_contract.recognized_receipt_requires_v1_identity_contract}; rule_scope_binding=${report.recognition_contract.recognized_receipt_rule_binds_policy_domain_tool_outcome_audit_freshness}; policy_domain_tool_detail_freshness_refusals_proven=${report.recognition_contract.policy_domain_tool_detail_freshness_refusal_cases_proven}; extra_scope_refusals_proven=${report.recognition_contract.policy_domain_tool_outcome_audit_freshness_refusal_cases_proven}; legacy_v0_recognized_boarding_identity=${report.recognition_contract.legacy_v0_receipts_recognized_as_boarding_identity}; current_implementation_fixture_only=${report.recognition_contract.current_implementation_fixture_recognition_only}`,
    `Receipt identity: type=${report.receipt_identity_contract.contract_type}; format=${report.receipt_identity_contract.recognized_receipt_format}; command_posture=${report.receipt_identity_contract.command_posture}; receipt_sha256_present=${/^[a-f0-9]{64}$/.test(report.receipt_identity_contract.canonical_signed_receipt_object_sha256)}; provided_pubkey_sha256_present=${/^[a-f0-9]{64}$/.test(report.receipt_identity_contract.provided_pubkey_sha256)}; required_identity_matched=${report.summary.v1_receipt_identity_verified}; legacy_v0_recognized_boarding_identity=${report.receipt_identity_contract.legacy_v0_recognized_boarding_identity}`,
    `Replay: cache_model=${report.replay_contract.cache_model}; scope=${report.replay_contract.scope}; durable_replay_store=${report.replay_contract.durable_replay_store}; exactly_once_production_effects=${report.replay_contract.exactly_once_production_effects}`,
    `Fixture contract sha256: ${report.fixture_contract_sha256}`,
    'Cases:',
  ];
  for (const item of report.case_summaries) {
    lines.push(`- ${item.case_id}: decision=${item.decision}; reason=${item.observed_reason_code}; effect_delta=${item.effect_count_delta}; refused_before_effect=${item.refused_before_effect}`);
  }
  lines.push(
    `Summary: cases_present=${report.summary.all_required_cases_present}; reason_codes_match=${report.summary.all_expected_reason_codes_match}; refusals_before_effect=${report.summary.all_refusals_before_effect}; consequence_absent_on_every_refusal=${report.summary.consequence_absent_on_every_refusal}; consequence_present_exactly_once_on_acceptance=${report.summary.consequence_present_exactly_once_on_acceptance}; v1_receipt_identity_verified=${report.summary.v1_receipt_identity_verified}; final_effect_count=${report.summary.final_effect_count}`,
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    'Boundary: not an install, not activation, not current-machine governance, not live downstream recognition.',
    'Non-claims:'
  );
  for (const claim of report.non_claims) {
    lines.push(`- ${claim}`);
  }
  return `${lines.join('\n')}\n`;
}

export function assertNoUnsafeProtectedRecordsLocalBoardingProofText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_OUTPUT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`protected records local boarding proof output contains ${label}`);
    }
  }
  return true;
}
