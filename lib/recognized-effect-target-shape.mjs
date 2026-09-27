import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';

export const RECOGNIZED_EFFECT_TARGET_SHAPE_ARTIFACT_TYPE =
  'zlar-recognized-effect-target-shape-artifact-v1';
export const RECOGNIZED_EFFECT_TARGET_SHAPE_VERIFICATION_TYPE =
  'zlar-recognized-effect-target-shape-verification-v1';

export const RECOGNIZED_EFFECT_SOURCE_DESIGN_PACKET_SHA256 =
  '46d13b209ef8e1a956eef3e32814b60edf2fefd5193da1eaf0fed2ed238d68a8';
export const RECOGNIZED_EFFECT_SCRATCH_PROOF_REPORT_SHA256 =
  '30b009ce2707b5a972fcf735d4bb0f11cdaa60f7ae7c690c2436958156f8abb4';

export const RECOGNIZED_EFFECT_ACTION_CLASS =
  'protected-records.private-operator.records-terminal.records.write';
export const RECOGNIZED_EFFECT_SELECTED_CONSEQUENCE = 'recognized_effect_delta';

export const RECOGNIZED_EFFECT_SAFE_CLAIM =
  'In the local no-secret recognized-effect target-shape verifier, only candidates that pass the verifier advance recognized_effect_delta; raw JSONL bytes appended to the selected fixture ingress by direct or shell writes do not change the delta, persisted replay fixtures refuse duplicate boarding, and malformed ingress fails closed.';

export const RECOGNIZED_EFFECT_FORBIDDEN_CLAIMS = Object.freeze([
  'side-door closure',
  'current-machine governance',
  'all-surface governance',
  'OS-level filesystem blocking',
  'authenticity against coherent state-plus-manifest rewrite',
  'general ingress governance outside the selected fixture path and command shapes',
  'production deployment',
  'production trust registry',
  'key custody',
  'revocation truth',
  'external attestation',
  'enterprise readiness',
  'public claim movement',
]);

const SAMPLE_GENERATED_AT = '2026-07-08T22:55:00Z';
const SAMPLE_EVALUATION_TIME = '2026-07-08T22:55:30Z';
const EXPECTED_POLICY_ID = 'policy:recognized-effect-target-shape-fixture-v1';
const EXPECTED_DOMAIN = 'protected-records';
const EXPECTED_TOOL = 'records.write';
const EXPECTED_AUDIT_EVENT_ID = 'audit-fixture-recognized-effect-001';

const EXPECTED_PROFILE = Object.freeze({
  action_class: RECOGNIZED_EFFECT_ACTION_CLASS,
  target_handle: 'fixture:private-operator-records-terminal:recognized-effect',
  runtime_profile_id: 'protected-records-private-operator-records-terminal-fixture',
  runtime_profile_sha256: '7'.repeat(64),
  receipt_contract_sha256: '8'.repeat(64),
  refusal_taxonomy_sha256: '9'.repeat(64),
});

const UNSAFE_TEXT_PATTERNS = Object.freeze([
  { label: 'private operator path', pattern: /\/Users\/[^\s"'`]+/ },
  { label: 'home path', pattern: /\/home\/[^\s"'`]+/ },
  { label: 'private temp path', pattern: /\/private\/[^\s"'`]+/ },
  { label: 'temp path', pattern: /\/tmp\/[^\s"'`]+/ },
  { label: 'private key material', pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
  {
    label: 'credential-shaped key-value',
    pattern: /\b(?:token|secret|password|credential|api[_-]?key)\s*[:=]\s*[^&\s"'`,;})\]]+/i,
  },
  { label: 'GitHub token', pattern: /\b(?:ghp|github_pat)_[A-Za-z0-9_]{10,}\b/ },
  { label: 'OpenAI-style key', pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/ },
]);

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function requireObject(label, value) {
  if (!isObject(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function requireArray(label, value) {
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  return value;
}

function requireString(label, value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function requireSha256(label, value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/i.test(value)) {
    throw new Error(`${label} must be a SHA-256 hex string`);
  }
  return value.toLowerCase();
}

function requireExact(label, expected, actual) {
  if (actual !== expected) {
    throw new Error(`${label} must be ${JSON.stringify(expected)}`);
  }
}

function requireFalse(label, actual) {
  if (actual !== false) {
    throw new Error(`${label} must be false`);
  }
}

function sortForCanonicalJson(value) {
  if (Array.isArray(value)) {
    return value.map(sortForCanonicalJson);
  }
  if (isObject(value)) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortForCanonicalJson(value[key])])
    );
  }
  return value;
}

export function canonicalRecognizedEffectJson(value) {
  return JSON.stringify(sortForCanonicalJson(value));
}

export function recognizedEffectSha256(value) {
  const text = typeof value === 'string' ? value : canonicalRecognizedEffectJson(value);
  return createHash('sha256').update(text).digest('hex');
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function receiptBody(receipt) {
  const body = clone(receipt);
  delete body.receipt_sha256;
  return body;
}

function recordUpdate() {
  return {
    record_id: 'fixture-record-001',
    operation: 'append',
    content_sha256: 'a'.repeat(64),
    body_redacted: true,
  };
}

function makeReceipt(overrides = {}) {
  const update = overrides.record_update || recordUpdate();
  const base = {
    receipt_type: 'zlar-recognized-effect-receipt-shaped-fixture-v1',
    issuer_kid: 'issuer-fixture-active',
    purpose: 'boarding',
    boarding_decision: 'board',
    action_class: EXPECTED_PROFILE.action_class,
    target_handle: EXPECTED_PROFILE.target_handle,
    runtime_profile_id: EXPECTED_PROFILE.runtime_profile_id,
    runtime_profile_sha256: EXPECTED_PROFILE.runtime_profile_sha256,
    receipt_contract_sha256: EXPECTED_PROFILE.receipt_contract_sha256,
    policy_id: EXPECTED_POLICY_ID,
    domain: EXPECTED_DOMAIN,
    tool: EXPECTED_TOOL,
    audit_event_id: EXPECTED_AUDIT_EVENT_ID,
    detail_hash: recognizedEffectSha256(update),
    nonce: 'receipt-nonce-fixture-001',
    issued_at: '2026-07-08T22:55:00Z',
    expires_at: '2026-07-08T23:55:00Z',
    authority_source: 'receipt_not_request_stream',
    signer_model: 'fixture-public-identity-only',
    ...overrides,
  };
  delete base.record_update;
  return {
    ...base,
    receipt_sha256: recognizedEffectSha256(base),
  };
}

function makeCandidate(id, overrides = {}) {
  const update = overrides.record_update || recordUpdate();
  const receipt = Object.prototype.hasOwnProperty.call(overrides, 'receipt')
    ? overrides.receipt
    : makeReceipt({ record_update: update });
  const base = {
    candidate_id: id,
    entry_kind: 'receipt_shaped_candidate',
    append_method: 'governed_receipt_ingress',
    action_class: EXPECTED_PROFILE.action_class,
    target_handle: EXPECTED_PROFILE.target_handle,
    runtime_profile_id: EXPECTED_PROFILE.runtime_profile_id,
    runtime_profile_sha256: EXPECTED_PROFILE.runtime_profile_sha256,
    record_update: update,
    receipt,
    request_stream_authority_material_present: false,
    ...overrides,
  };
  return base;
}

function issuerRegistry() {
  return {
    'issuer-fixture-active': {
      issuer_kid: 'issuer-fixture-active',
      status: 'active',
      status_source: 'fixture-registry',
    },
    'issuer-fixture-retired': {
      issuer_kid: 'issuer-fixture-retired',
      status: 'retired',
      status_source: 'fixture-registry',
    },
    'issuer-fixture-compromised': {
      issuer_kid: 'issuer-fixture-compromised',
      status: 'compromised',
      status_source: 'fixture-registry',
    },
    'issuer-fixture-missing-status': {
      issuer_kid: 'issuer-fixture-missing-status',
      status_source: 'fixture-registry',
    },
  };
}

function buildMaterializedState(ledger, profile) {
  return {
    state_type: 'zlar-recognized-effect-state-v1',
    action_class: profile.action_class,
    target_handle: profile.target_handle,
    selected_consequence: RECOGNIZED_EFFECT_SELECTED_CONSEQUENCE,
    recognized_effect_delta: ledger.length,
    effects: ledger.map((entry) => ({
      effect_id: entry.effect_id,
      record_id: entry.record_update.record_id,
      content_sha256: entry.record_update.content_sha256,
    })),
  };
}

function buildStateManifest(state, ledger, profile) {
  return {
    manifest_type: 'zlar-recognized-effect-state-manifest-v1',
    action_class: profile.action_class,
    target_handle: profile.target_handle,
    runtime_profile_id: profile.runtime_profile_id,
    runtime_profile_sha256: profile.runtime_profile_sha256,
    receipt_contract_sha256: profile.receipt_contract_sha256,
    refusal_taxonomy_sha256: profile.refusal_taxonomy_sha256,
    recognized_effect_state_sha256: recognizedEffectSha256(state),
    recognized_effect_ledger_sha256: recognizedEffectSha256(ledger),
    generated_at: SAMPLE_GENERATED_AT,
    authenticity_anchor_present: false,
  };
}

function acceptedEffect(candidate) {
  return {
    effect_id: `effect:${candidate.candidate_id}`,
    candidate_id: candidate.candidate_id,
    receipt_sha256: candidate.receipt.receipt_sha256,
    receipt_nonce: candidate.receipt.nonce,
    action_class: candidate.action_class,
    target_handle: candidate.target_handle,
    record_update: candidate.record_update,
  };
}

function sideDoorCandidate(method, id) {
  const update = {
    ...recordUpdate(),
    record_id: `fixture-record-${id}`,
    content_sha256: id === 'direct' ? 'b'.repeat(64) : 'c'.repeat(64),
  };
  return makeCandidate(`${id}-forged-raw-ingress`, {
    entry_kind: 'raw_ingress_candidate',
    append_method: method,
    record_update: update,
    receipt: {
      untrusted_claim: 'raw JSONL bytes are not recognized consequence',
    },
  });
}

function negativeCases(validCandidate) {
  const validReceipt = validCandidate.receipt;
  const validUpdate = validCandidate.record_update;
  const withReceipt = (caseId, receiptOverrides = {}, candidateOverrides = {}) =>
    makeCandidate(caseId, {
      record_update: validUpdate,
      receipt: makeReceipt({
        record_update: validUpdate,
        nonce: `receipt-nonce-${caseId}`,
        ...receiptOverrides,
      }),
      ...candidateOverrides,
    });

  const badHashReceipt = clone(validReceipt);
  badHashReceipt.receipt_sha256 = '0'.repeat(64);

  return {
    missing_receipt: makeCandidate('missing-receipt', { receipt: null }),
    invalid_receipt_hash: makeCandidate('invalid-receipt-hash', { receipt: badHashReceipt }),
    stale_receipt: withReceipt('stale-receipt', { expires_at: '2026-07-08T22:00:00Z' }),
    same_process_replay: makeCandidate('same-process-replay', { receipt: validReceipt }),
    wrong_policy: withReceipt('wrong-policy', { policy_id: 'policy:wrong' }),
    wrong_action_class: withReceipt('wrong-action-class', { action_class: 'protected-records.wrong.records.write' }),
    wrong_domain: withReceipt('wrong-domain', { domain: 'wrong-domain' }),
    wrong_tool: withReceipt('wrong-tool', { tool: 'wrong.tool' }),
    wrong_detail: withReceipt('wrong-detail', { detail_hash: 'd'.repeat(64) }),
    wrong_audit_event: withReceipt('wrong-audit-event', { audit_event_id: 'audit-fixture-wrong' }),
    wrong_target: withReceipt('wrong-target', { target_handle: 'fixture:wrong-target' }),
    wrong_runtime_profile_id: withReceipt('wrong-runtime-profile-id', {
      runtime_profile_id: 'wrong-profile-id',
    }),
    wrong_runtime_profile_sha256: withReceipt('wrong-runtime-profile-sha256', {
      runtime_profile_sha256: '6'.repeat(64),
    }),
    non_boarding_receipt: withReceipt('non-boarding-receipt', {
      purpose: 'refusal',
      boarding_decision: 'deny',
    }),
    unknown_issuer: withReceipt('unknown-issuer', { issuer_kid: 'issuer-fixture-unknown' }),
    missing_issuer_status: withReceipt('missing-issuer-status', { issuer_kid: 'issuer-fixture-missing-status' }),
    retired_issuer: withReceipt('retired-issuer', { issuer_kid: 'issuer-fixture-retired' }),
    compromised_issuer: withReceipt('compromised-issuer', { issuer_kid: 'issuer-fixture-compromised' }),
    receipt_contract_mismatch: withReceipt('receipt-contract-mismatch', {
      receipt_contract_sha256: '5'.repeat(64),
    }),
    request_stream_authority_material: withReceipt('request-stream-authority-material', {}, {
      request_stream_authority_material_present: true,
    }),
  };
}

function makeArtifactMaterialized(candidate) {
  const ledger = [acceptedEffect(candidate)];
  const state = buildMaterializedState(ledger, EXPECTED_PROFILE);
  const manifest = buildStateManifest(state, ledger, EXPECTED_PROFILE);
  const tamperedState = {
    ...state,
    recognized_effect_delta: 2,
    effects: [
      ...state.effects,
      {
        effect_id: 'effect:tampered-direct-write',
        record_id: 'fixture-record-tampered',
        content_sha256: 'e'.repeat(64),
      },
    ],
  };
  const coherentRewriteManifest = buildStateManifest(tamperedState, ledger, EXPECTED_PROFILE);
  return {
    recognized_effect_ledger: ledger,
    recognized_effect_state: state,
    state_manifest: manifest,
    tamper_fixtures: {
      materialized_state_tamper: tamperedState,
      manifest_state_hash_mismatch: {
        ...manifest,
        recognized_effect_state_sha256: '0'.repeat(64),
      },
      coherent_state_plus_manifest_rewrite: {
        recognized_effect_state: tamperedState,
        state_manifest: coherentRewriteManifest,
      },
    },
  };
}

export function buildRecognizedEffectTargetShapeSampleArtifact() {
  const validCandidate = makeCandidate('governed-receipt-shaped-candidate');
  const materialized = makeArtifactMaterialized(validCandidate);
  return {
    artifact_type: RECOGNIZED_EFFECT_TARGET_SHAPE_ARTIFACT_TYPE,
    schema_version: 1,
    generated_at: SAMPLE_GENERATED_AT,
    evaluation_time: SAMPLE_EVALUATION_TIME,
    source_design_packet_sha256: RECOGNIZED_EFFECT_SOURCE_DESIGN_PACKET_SHA256,
    scratch_proof_report_sha256: RECOGNIZED_EFFECT_SCRATCH_PROOF_REPORT_SHA256,
    profile: EXPECTED_PROFILE,
    issuer_registry: issuerRegistry(),
    candidate_input_log: [
      validCandidate,
      sideDoorCandidate('direct_filesystem_append_to_untrusted_ingress_fixture', 'direct'),
      sideDoorCandidate('shell_helper_append_to_untrusted_ingress_fixture', 'shell'),
      makeCandidate('same-process-replay-candidate', { receipt: validCandidate.receipt }),
    ],
    persisted_replay_store_fixture: {
      store_type: 'zlar-recognized-effect-persisted-replay-store-fixture-v1',
      consumed_nonces_before_restart: [validCandidate.receipt.nonce],
      consumed_receipt_sha256_before_restart: [validCandidate.receipt.receipt_sha256],
      duplicate_candidate_after_restart: makeCandidate('restart-replay-candidate', {
        receipt: validCandidate.receipt,
      }),
    },
    negative_case_inputs: negativeCases(validCandidate),
    malformed_ingress_fixture: {
      fixture_type: 'zlar-recognized-effect-malformed-jsonl-fixture-v1',
      raw_lines: [
        '{"candidate_id":"partial-write"',
        '{"candidate_id":"well-formed-but-untrusted","entry_kind":"raw_ingress_candidate","append_method":"direct_filesystem_append_to_untrusted_ingress_fixture"}',
      ],
    },
    materialized,
    claim_boundary: {
      current_machine_governance_proven: false,
      side_door_closure_proven: false,
      public_claim_movement: false,
      os_filesystem_blocking_proven: false,
      coherent_rewrite_authenticity_proven: false,
    },
  };
}

function refusal(caseId, reasonCode, candidate, extra = {}) {
  return {
    case_id: caseId,
    accepted: false,
    reason_code: reasonCode,
    recognized_effect_delta: 0,
    candidate_id: candidate?.candidate_id || caseId,
    ...extra,
  };
}

function accept(candidate) {
  return {
    case_id: candidate.candidate_id,
    accepted: true,
    reason_code: 'recognized',
    recognized_effect_delta: 1,
    candidate_id: candidate.candidate_id,
    effect: acceptedEffect(candidate),
  };
}

function evaluateReceiptCandidate(candidate, context) {
  if (!isObject(candidate)) {
    return refusal('malformed_candidate', 'candidate_not_object', {});
  }
  if (candidate.request_stream_authority_material_present === true) {
    return refusal(candidate.candidate_id, 'request_stream_authority_material', candidate);
  }
  if (candidate.append_method !== 'governed_receipt_ingress') {
    return refusal(candidate.candidate_id, 'untrusted_ingress_not_recognized', candidate, {
      route: candidate.append_method,
      target_capable_for_recognized_effect: false,
    });
  }
  if (candidate.entry_kind !== 'receipt_shaped_candidate') {
    return refusal(candidate.candidate_id, 'candidate_not_receipt_shaped', candidate);
  }
  if (!isObject(candidate.receipt)) {
    return refusal(candidate.candidate_id, 'receipt_missing', candidate);
  }
  const receipt = candidate.receipt;
  if (recognizedEffectSha256(receiptBody(receipt)) !== receipt.receipt_sha256) {
    return refusal(candidate.candidate_id, 'receipt_hash_mismatch', candidate);
  }
  if (receipt.purpose !== 'boarding' || receipt.boarding_decision !== 'board') {
    return refusal(candidate.candidate_id, 'non_boarding_receipt', candidate);
  }
  const issuer = context.issuerRegistry[receipt.issuer_kid];
  if (!issuer) {
    return refusal(candidate.candidate_id, 'unknown_issuer', candidate);
  }
  if (!issuer.status) {
    return refusal(candidate.candidate_id, 'missing_issuer_status', candidate);
  }
  if (issuer.status === 'retired') {
    return refusal(candidate.candidate_id, 'retired_issuer', candidate);
  }
  if (issuer.status === 'compromised') {
    return refusal(candidate.candidate_id, 'compromised_issuer', candidate);
  }
  if (issuer.status !== 'active') {
    return refusal(candidate.candidate_id, 'issuer_not_active', candidate);
  }
  if (receipt.action_class !== context.profile.action_class || candidate.action_class !== context.profile.action_class) {
    return refusal(candidate.candidate_id, 'action_class_mismatch', candidate);
  }
  if (receipt.policy_id !== EXPECTED_POLICY_ID) {
    return refusal(candidate.candidate_id, 'policy_not_recognized', candidate);
  }
  if (receipt.domain !== EXPECTED_DOMAIN) {
    return refusal(candidate.candidate_id, 'domain_mismatch', candidate);
  }
  if (receipt.tool !== EXPECTED_TOOL) {
    return refusal(candidate.candidate_id, 'tool_mismatch', candidate);
  }
  if (receipt.audit_event_id !== EXPECTED_AUDIT_EVENT_ID) {
    return refusal(candidate.candidate_id, 'audit_event_mismatch', candidate);
  }
  if (receipt.detail_hash !== recognizedEffectSha256(candidate.record_update)) {
    return refusal(candidate.candidate_id, 'detail_hash_mismatch', candidate);
  }
  if (receipt.target_handle !== context.profile.target_handle || candidate.target_handle !== context.profile.target_handle) {
    return refusal(candidate.candidate_id, 'target_mismatch', candidate);
  }
  if (receipt.runtime_profile_id !== context.profile.runtime_profile_id || candidate.runtime_profile_id !== context.profile.runtime_profile_id) {
    return refusal(candidate.candidate_id, 'runtime_profile_id_mismatch', candidate);
  }
  if (
    receipt.runtime_profile_sha256 !== context.profile.runtime_profile_sha256 ||
    candidate.runtime_profile_sha256 !== context.profile.runtime_profile_sha256
  ) {
    return refusal(candidate.candidate_id, 'runtime_profile_sha256_mismatch', candidate);
  }
  if (receipt.receipt_contract_sha256 !== context.profile.receipt_contract_sha256) {
    return refusal(candidate.candidate_id, 'receipt_contract_mismatch', candidate);
  }
  if (Date.parse(receipt.expires_at) <= Date.parse(context.evaluationTime)) {
    return refusal(candidate.candidate_id, 'receipt_stale', candidate);
  }
  if (context.seenNonces.has(receipt.nonce)) {
    return refusal(candidate.candidate_id, 'receipt_replay', candidate);
  }
  context.seenNonces.add(receipt.nonce);
  return accept(candidate);
}

function deriveLedger(artifact) {
  const profile = requireObject('profile', artifact.profile);
  const issuerRegistryValue = requireObject('issuer_registry', artifact.issuer_registry);
  const context = {
    profile,
    issuerRegistry: issuerRegistryValue,
    seenNonces: new Set(),
    evaluationTime: requireString('evaluation_time', artifact.evaluation_time),
  };
  const results = [];
  const ledger = [];
  for (const candidate of requireArray('candidate_input_log', artifact.candidate_input_log)) {
    const result = evaluateReceiptCandidate(candidate, context);
    results.push(result);
    if (result.accepted) {
      ledger.push(result.effect);
    }
  }
  return { ledger, results };
}

function verifyMaterialized(artifact, derivedLedger) {
  const materialized = requireObject('materialized', artifact.materialized);
  const suppliedLedger = requireArray('materialized.recognized_effect_ledger', materialized.recognized_effect_ledger);
  const suppliedState = requireObject('materialized.recognized_effect_state', materialized.recognized_effect_state);
  const suppliedManifest = requireObject('materialized.state_manifest', materialized.state_manifest);
  if (canonicalRecognizedEffectJson(suppliedLedger) !== canonicalRecognizedEffectJson(derivedLedger)) {
    throw new Error('recognized_effect_ledger mismatch');
  }
  const expectedState = buildMaterializedState(derivedLedger, artifact.profile);
  if (canonicalRecognizedEffectJson(suppliedState) !== canonicalRecognizedEffectJson(expectedState)) {
    throw new Error('recognized_effect_state mismatch');
  }
  const expectedManifest = buildStateManifest(expectedState, derivedLedger, artifact.profile);
  if (canonicalRecognizedEffectJson(suppliedManifest) !== canonicalRecognizedEffectJson(expectedManifest)) {
    throw new Error('state_manifest mismatch');
  }
  return { state: suppliedState, manifest: suppliedManifest };
}

function evaluateNegativeCases(artifact) {
  const cases = requireObject('negative_case_inputs', artifact.negative_case_inputs);
  const contextBase = {
    profile: artifact.profile,
    issuerRegistry: artifact.issuer_registry,
    evaluationTime: artifact.evaluation_time,
  };
  const validAcceptedNonce = artifact.candidate_input_log[0].receipt.nonce;
  return Object.entries(cases).map(([caseId, candidate]) => {
    const seenNonces = new Set(caseId === 'same_process_replay' ? [validAcceptedNonce] : []);
    const result = evaluateReceiptCandidate(candidate, {
      ...contextBase,
      seenNonces,
    });
    return {
      case_id: caseId,
      accepted: result.accepted,
      reason_code: result.reason_code,
      recognized_effect_delta: result.accepted ? result.recognized_effect_delta : 0,
    };
  });
}

function evaluatePersistedReplayStore(artifact) {
  const fixture = requireObject('persisted_replay_store_fixture', artifact.persisted_replay_store_fixture);
  const duplicateCandidate = requireObject(
    'persisted_replay_store_fixture.duplicate_candidate_after_restart',
    fixture.duplicate_candidate_after_restart
  );
  const seenNonces = new Set(requireArray(
    'persisted_replay_store_fixture.consumed_nonces_before_restart',
    fixture.consumed_nonces_before_restart
  ));
  const result = evaluateReceiptCandidate(duplicateCandidate, {
    profile: artifact.profile,
    issuerRegistry: artifact.issuer_registry,
    evaluationTime: artifact.evaluation_time,
    seenNonces,
  });
  return {
    case_id: 'restart_replay_refused_through_persisted_store_fixture',
    accepted: result.accepted,
    reason_code: result.accepted ? result.reason_code : 'receipt_replay_after_restart',
    recognized_effect_delta: 0,
    persisted_store_used: true,
  };
}

function evaluateMalformedIngress(artifact) {
  const fixture = requireObject('malformed_ingress_fixture', artifact.malformed_ingress_fixture);
  const rawLines = requireArray('malformed_ingress_fixture.raw_lines', fixture.raw_lines);
  let quarantined = 0;
  let parsed = 0;
  for (const line of rawLines) {
    try {
      JSON.parse(line);
      parsed++;
    } catch {
      quarantined++;
    }
  }
  return {
    case_id: 'malformed_jsonl_partial_write_ingress',
    accepted: false,
    reason_code: quarantined > 0 ? 'malformed_jsonl_quarantined' : 'raw_ingress_not_recognized',
    recognized_effect_delta: 0,
    malformed_lines_quarantined: quarantined,
    well_formed_untrusted_lines_seen: parsed,
    verifier_crashed: false,
  };
}

function evaluateTamperFixtures(artifact) {
  const materialized = requireObject('materialized', artifact.materialized);
  const fixtures = requireObject('materialized.tamper_fixtures', materialized.tamper_fixtures);
  const stateTamper = requireObject('materialized.tamper_fixtures.materialized_state_tamper', fixtures.materialized_state_tamper);
  const manifestMismatch = requireObject(
    'materialized.tamper_fixtures.manifest_state_hash_mismatch',
    fixtures.manifest_state_hash_mismatch
  );
  const coherentRewrite = requireObject(
    'materialized.tamper_fixtures.coherent_state_plus_manifest_rewrite',
    fixtures.coherent_state_plus_manifest_rewrite
  );
  const originalManifest = requireObject('materialized.state_manifest', materialized.state_manifest);
  const stateTamperRefused =
    recognizedEffectSha256(stateTamper) !== originalManifest.recognized_effect_state_sha256;
  const manifestMismatchRefused =
    manifestMismatch.recognized_effect_state_sha256 !==
    recognizedEffectSha256(requireObject('materialized.recognized_effect_state', materialized.recognized_effect_state));
  const coherentState = requireObject(
    'coherent_state_plus_manifest_rewrite.recognized_effect_state',
    coherentRewrite.recognized_effect_state
  );
  const coherentManifest = requireObject(
    'coherent_state_plus_manifest_rewrite.state_manifest',
    coherentRewrite.state_manifest
  );
  const coherentConsistencyPasses =
    coherentManifest.recognized_effect_state_sha256 === recognizedEffectSha256(coherentState);
  return {
    materialized_state_tamper_refused: stateTamperRefused,
    manifest_state_hash_mismatch_refused: manifestMismatchRefused,
    coherent_state_manifest_rewrite_consistency_passes: coherentConsistencyPasses,
    coherent_state_manifest_rewrite_authenticity_proven: false,
  };
}

function sideDoorMatrix(derivationResults) {
  const byId = Object.fromEntries(derivationResults.map((item) => [item.candidate_id, item]));
  return [
    {
      route: 'governed_receipt_shaped_candidate',
      classification: 'governed',
      accepted: byId['governed-receipt-shaped-candidate']?.accepted === true,
      recognized_effect_delta: byId['governed-receipt-shaped-candidate']?.recognized_effect_delta || 0,
    },
    {
      route: 'direct_filesystem_append_to_untrusted_ingress_fixture',
      classification: 'target_incapable_for_recognized_effect',
      accepted: byId['direct-forged-raw-ingress']?.accepted === true,
      recognized_effect_delta: byId['direct-forged-raw-ingress']?.recognized_effect_delta || 0,
      os_filesystem_blocking_proven: false,
    },
    {
      route: 'shell_helper_append_to_untrusted_ingress_fixture',
      classification: 'target_incapable_for_recognized_effect',
      accepted: byId['shell-forged-raw-ingress']?.accepted === true,
      recognized_effect_delta: byId['shell-forged-raw-ingress']?.recognized_effect_delta || 0,
      os_filesystem_blocking_proven: false,
    },
  ];
}

export function assertNoUnsafeRecognizedEffectTargetShapeText(text) {
  for (const { label, pattern } of UNSAFE_TEXT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`recognized-effect output contains unsafe ${label}`);
    }
  }
  return true;
}

export function parseRecognizedEffectTargetShapeArtifactText(text) {
  let artifact;
  try {
    artifact = JSON.parse(text);
  } catch (err) {
    throw new Error(`recognized-effect target-shape artifact is not valid JSON: ${err.message}`);
  }
  return artifact;
}

export function verifyRecognizedEffectTargetShapeArtifact(artifact) {
  requireObject('artifact', artifact);
  requireExact('artifact_type', RECOGNIZED_EFFECT_TARGET_SHAPE_ARTIFACT_TYPE, artifact.artifact_type);
  requireExact('schema_version', 1, artifact.schema_version);
  requireExact(
    'source_design_packet_sha256',
    RECOGNIZED_EFFECT_SOURCE_DESIGN_PACKET_SHA256,
    requireSha256('source_design_packet_sha256', artifact.source_design_packet_sha256)
  );
  requireExact(
    'scratch_proof_report_sha256',
    RECOGNIZED_EFFECT_SCRATCH_PROOF_REPORT_SHA256,
    requireSha256('scratch_proof_report_sha256', artifact.scratch_proof_report_sha256)
  );
  const profile = requireObject('profile', artifact.profile);
  requireExact('profile.action_class', RECOGNIZED_EFFECT_ACTION_CLASS, profile.action_class);
  requireSha256('profile.runtime_profile_sha256', profile.runtime_profile_sha256);
  requireSha256('profile.receipt_contract_sha256', profile.receipt_contract_sha256);
  requireSha256('profile.refusal_taxonomy_sha256', profile.refusal_taxonomy_sha256);
  const claimBoundary = requireObject('claim_boundary', artifact.claim_boundary);
  requireFalse('claim_boundary.current_machine_governance_proven', claimBoundary.current_machine_governance_proven);
  requireFalse('claim_boundary.side_door_closure_proven', claimBoundary.side_door_closure_proven);
  requireFalse('claim_boundary.public_claim_movement', claimBoundary.public_claim_movement);
  requireFalse('claim_boundary.os_filesystem_blocking_proven', claimBoundary.os_filesystem_blocking_proven);
  requireFalse('claim_boundary.coherent_rewrite_authenticity_proven', claimBoundary.coherent_rewrite_authenticity_proven);

  const { ledger, results } = deriveLedger(artifact);
  const { state } = verifyMaterialized(artifact, ledger);
  const negativeCaseResults = evaluateNegativeCases(artifact);
  const restartReplay = evaluatePersistedReplayStore(artifact);
  const malformedIngress = evaluateMalformedIngress(artifact);
  const tamper = evaluateTamperFixtures(artifact);

  const negativeResults = [
    ...negativeCaseResults,
    restartReplay,
    malformedIngress,
    {
      case_id: 'materialized_state_tamper',
      accepted: false,
      reason_code: tamper.materialized_state_tamper_refused
        ? 'state_manifest_mismatch'
        : 'state_tamper_not_refused',
      recognized_effect_delta: 0,
    },
    {
      case_id: 'manifest_state_hash_mismatch',
      accepted: false,
      reason_code: tamper.manifest_state_hash_mismatch_refused
        ? 'manifest_state_hash_mismatch'
        : 'manifest_hash_mismatch_not_refused',
      recognized_effect_delta: 0,
    },
  ];

  if (state.recognized_effect_delta !== 1) {
    throw new Error('recognized_effect_delta must be 1');
  }
  const acceptedNegative = negativeResults.filter((item) => item.accepted);
  if (acceptedNegative.length > 0) {
    throw new Error(`negative cases accepted: ${acceptedNegative.map((item) => item.case_id).join(',')}`);
  }
  if (!tamper.materialized_state_tamper_refused || !tamper.manifest_state_hash_mismatch_refused) {
    throw new Error('state or manifest tamper was not refused');
  }

  const report = {
    report_type: RECOGNIZED_EFFECT_TARGET_SHAPE_VERIFICATION_TYPE,
    schema_version: 1,
    verified: true,
    artifact_sha256: recognizedEffectSha256(artifact),
    action_class: profile.action_class,
    target_handle: profile.target_handle,
    selected_consequence: RECOGNIZED_EFFECT_SELECTED_CONSEQUENCE,
    recognized_effect_delta: state.recognized_effect_delta,
    side_door_matrix: sideDoorMatrix(results),
    negative_case_results: negativeResults,
    persisted_replay_store_duplicate_refused: restartReplay.accepted === false,
    same_process_replay_refused: negativeCaseResults.some(
      (item) => item.case_id === 'same_process_replay' && item.accepted === false
    ),
    malformed_ingress_fail_closed: malformedIngress.accepted === false &&
      malformedIngress.recognized_effect_delta === 0 &&
      malformedIngress.verifier_crashed === false,
    materialized_state_tamper_refused: tamper.materialized_state_tamper_refused,
    manifest_state_hash_mismatch_refused: tamper.manifest_state_hash_mismatch_refused,
    coherent_state_manifest_rewrite_consistency_passes:
      tamper.coherent_state_manifest_rewrite_consistency_passes,
    coherent_state_manifest_rewrite_authenticity_proven: false,
    safe_claim: RECOGNIZED_EFFECT_SAFE_CLAIM,
    forbidden_claims: [...RECOGNIZED_EFFECT_FORBIDDEN_CLAIMS],
    source_design_packet_sha256: RECOGNIZED_EFFECT_SOURCE_DESIGN_PACKET_SHA256,
    scratch_proof_report_sha256: RECOGNIZED_EFFECT_SCRATCH_PROOF_REPORT_SHA256,
    current_machine_governance_proven: false,
    side_door_closure_proven: false,
    public_claim_movement: false,
  };
  assertNoUnsafeRecognizedEffectTargetShapeText(JSON.stringify(report));
  return report;
}

export function writeRecognizedEffectTargetShapeArtifact(artifact, path) {
  const text = `${JSON.stringify(artifact, null, 2)}\n`;
  assertNoUnsafeRecognizedEffectTargetShapeText(text);
  writeFileSync(path, text);
}

export function formatRecognizedEffectTargetShapeVerification(report) {
  const direct = report.side_door_matrix.find(
    (item) => item.route === 'direct_filesystem_append_to_untrusted_ingress_fixture'
  );
  const shell = report.side_door_matrix.find(
    (item) => item.route === 'shell_helper_append_to_untrusted_ingress_fixture'
  );
  const text = [
    'ZLAR Recognized-Effect Target-Shape Verification v1',
    `verified=${report.verified}`,
    `action_class=${report.action_class}`,
    `selected_consequence=${report.selected_consequence}`,
    `recognized_effect_delta=${report.recognized_effect_delta}`,
    `direct_ingress_accepted=${direct?.accepted === true}; direct_ingress_delta=${direct?.recognized_effect_delta || 0}; os_blocking_proven=false`,
    `shell_ingress_accepted=${shell?.accepted === true}; shell_ingress_delta=${shell?.recognized_effect_delta || 0}; os_blocking_proven=false`,
    `same_process_replay_refused=${report.same_process_replay_refused}`,
    `persisted_restart_replay_refused=${report.persisted_replay_store_duplicate_refused}`,
    `malformed_ingress_fail_closed=${report.malformed_ingress_fail_closed}`,
    `materialized_state_tamper_refused=${report.materialized_state_tamper_refused}`,
    `manifest_state_hash_mismatch_refused=${report.manifest_state_hash_mismatch_refused}`,
    `coherent_rewrite_authenticity_proven=${report.coherent_state_manifest_rewrite_authenticity_proven}`,
    `safe_claim=${report.safe_claim}`,
    `forbidden_claims=${report.forbidden_claims.join('; ')}`,
    '',
  ].join('\n');
  assertNoUnsafeRecognizedEffectTargetShapeText(text);
  return text;
}
