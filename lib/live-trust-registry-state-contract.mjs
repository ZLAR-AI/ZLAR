import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const LIVE_TRUST_REGISTRY_STATE_CONTRACT_TYPE =
  'zlar-live-trust-registry-state-contract-v1';
export const LIVE_TRUST_REGISTRY_STATE_VERIFICATION_TYPE =
  'zlar-live-trust-registry-state-contract-verification-v1';

export const LIVE_TRUST_REGISTRY_STATE_FALSE_FLAGS = Object.freeze([
  'current_machine_governance_proven',
  'enterprise_readiness',
  'hardware_custody_proven',
  'key_custody_proven',
  'live_issuer_status_proven',
  'live_trust_registry_state',
  'production_authority',
  'production_downstream_recognition_proven',
  'production_trust_registry_proven',
  'public_external_attestation',
  'revocation_truth_proven',
  'sovereign_recognition',
]);

const SNAPSHOT_KEYS = Object.freeze([
  'claim_boundary',
  'deployment_scope',
  'effective_at',
  'evidence_model',
  'expires_at',
  'issuer_status_counts',
  'live_probing',
  'non_claims',
  'previous_snapshot_sha256',
  'private_key_material_included',
  'raw_public_key_material_included',
  'registry_id',
  'registry_sequence',
  'snapshot_sha256',
  'snapshot_type',
  'trusted_issuer_count',
]);

const ISSUER_STATE_KEYS = Object.freeze([
  'claim_boundary',
  'issuer_kid',
  'issuer_status',
  'public_key_sha256',
  'registry_snapshot_sha256',
  'scope_binding',
  'status_effective_at',
  'status_expires_at',
  'status_reason_code',
  'status_sequence',
  'trust_anchor_sha256',
]);

const CUSTODY_POSTURE_KEYS = Object.freeze([
  'claim_boundary',
  'custody_class',
  'custody_evidence_id',
  'custody_evidence_sha256',
  'hardware_custody_proven',
  'key_custody_proven',
  'private_key_material_included',
]);

const REVOCATION_CLOSURE_KEYS = Object.freeze([
  'affected_scope',
  'claim_boundary',
  'freshness_window_seconds',
  'issuer_kid',
  'new_snapshot_sha256',
  'new_status',
  'previous_snapshot_sha256',
  'previous_status',
  'recognized_after_revocation',
  'recognized_before_revocation',
  'registry_sequence',
  'revocation_event_id',
  'revoked_at',
]);

const CONTRACT_KEYS = Object.freeze([
  'claim_boundary',
  'contract_type',
  'custody_posture',
  'issuer_state',
  'non_claims',
  'registry_snapshot',
  'revocation_closure',
  'schema_version',
]);

const STATUS_COUNTS_KEYS = Object.freeze([
  'active',
  'compromised',
  'retired',
  'revoked',
  'unknown',
]);

const SUPPORTED_ISSUER_STATUSES = Object.freeze([
  'active',
  'retired',
  'revoked',
  'compromised',
  'unknown',
]);

const SUPPORTED_CUSTODY_CLASSES = Object.freeze([
  'none',
  'software_local_declared',
  'software_local_proven',
  'hardware_declared',
  'hardware_proven',
  'production_custody_proven',
]);

const UNSAFE_TEXT_PATTERNS = Object.freeze([
  { label: 'private operator path', pattern: /\/Users\/[^\s"'`]+/ },
  { label: 'home path', pattern: /\/home\/[^\s"'`]+/ },
  { label: 'private path', pattern: /\/private\/[^\s"'`]+/ },
  { label: 'temp path', pattern: /\/tmp\/[^\s"'`]+/ },
  { label: 'var path', pattern: /\/var\/[^\s"'`]+/ },
  { label: 'private key material', pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
  { label: 'public key material', pattern: /BEGIN PUBLIC KEY/ },
  {
    label: 'key-value credential',
    pattern: /\b(?:token|secret|password|credential|api[_-]?key)\s*[:=]\s*[^&\s"'`,;})\]]+/i,
  },
  {
    label: 'authorization credential',
    pattern: /\bauthorization\s*[:=]\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}/i,
  },
  { label: 'GitHub token', pattern: /\b(?:ghp|github_pat)_[A-Za-z0-9_]{10,}\b/ },
  { label: 'OpenAI-style key', pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/ },
  { label: 'bot token', pattern: /\bbot[0-9]{6,}:[A-Za-z0-9_-]{6,}\b/ },
]);

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(label, value, expectedKeys) {
  if (!isObject(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains unexpected fields`);
  }
}

function requireString(label, value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
}

function requireInteger(label, value, { min = Number.MIN_SAFE_INTEGER } = {}) {
  if (!Number.isInteger(value) || value < min) {
    throw new Error(`${label} must be an integer >= ${min}`);
  }
}

function requireBoolean(label, value) {
  if (typeof value !== 'boolean') {
    throw new Error(`${label} must be boolean`);
  }
}

function requireFalse(label, value) {
  if (value !== false) {
    throw new Error(`${label} must be false`);
  }
}

function requireTrue(label, value) {
  if (value !== true) {
    throw new Error(`${label} must be true`);
  }
}

function requireSha256(label, value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`${label} must be a SHA-256 hex string`);
  }
}

function requireKid(label, value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{16}$/.test(value)) {
    throw new Error(`${label} must be 16 lowercase hex characters`);
  }
}

function requireIso(label, value) {
  requireString(label, value);
  const millis = Date.parse(value);
  if (!Number.isFinite(millis)) {
    throw new Error(`${label} must be ISO-8601`);
  }
  return millis;
}

function assertNoUnsafeText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_TEXT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`live trust registry contract contains ${label}`);
    }
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

export function canonicalLiveTrustRegistryStateJson(value) {
  return JSON.stringify(sortForCanonicalJson(value));
}

function sha256Text(text) {
  return createHash('sha256').update(text).digest('hex');
}

function assertClaimBoundary(value, label = 'live trust registry claim_boundary') {
  exactKeys(label, value, LIVE_TRUST_REGISTRY_STATE_FALSE_FLAGS);
  for (const flag of LIVE_TRUST_REGISTRY_STATE_FALSE_FLAGS) {
    requireFalse(`${label}.${flag}`, value[flag]);
  }
}

function assertStatusCounts(value) {
  exactKeys('registry snapshot issuer_status_counts', value, STATUS_COUNTS_KEYS);
  for (const key of STATUS_COUNTS_KEYS) {
    requireInteger(`registry snapshot issuer_status_counts.${key}`, value[key], { min: 0 });
  }
}

function assertRegistrySnapshot(value) {
  exactKeys('registry snapshot', value, SNAPSHOT_KEYS);
  if (value.snapshot_type !== 'zlar-live-trust-registry-snapshot-contract-v1') {
    throw new Error('registry snapshot_type drifted');
  }
  requireString('registry id', value.registry_id);
  requireInteger('registry sequence', value.registry_sequence, { min: 1 });
  requireString('registry evidence model', value.evidence_model);
  requireFalse('registry live_probing', value.live_probing);
  requireString('registry deployment_scope', value.deployment_scope);
  const effectiveAt = requireIso('registry effective_at', value.effective_at);
  const expiresAt = requireIso('registry expires_at', value.expires_at);
  if (effectiveAt > expiresAt) {
    throw new Error('registry effective window drifted');
  }
  requireSha256('registry previous_snapshot_sha256', value.previous_snapshot_sha256);
  requireSha256('registry snapshot_sha256', value.snapshot_sha256);
  requireInteger('registry trusted_issuer_count', value.trusted_issuer_count, { min: 1 });
  assertStatusCounts(value.issuer_status_counts);
  const countedIssuers = Object.values(value.issuer_status_counts).reduce((sum, count) => sum + count, 0);
  if (countedIssuers !== value.trusted_issuer_count) {
    throw new Error('registry issuer status counts must equal trusted_issuer_count');
  }
  requireFalse('registry private_key_material_included', value.private_key_material_included);
  requireFalse('registry raw_public_key_material_included', value.raw_public_key_material_included);
  assertClaimBoundary(value.claim_boundary, 'registry snapshot claim_boundary');
  if (!Array.isArray(value.non_claims) || value.non_claims.length === 0) {
    throw new Error('registry snapshot non_claims must be non-empty');
  }
}

function assertIssuerState(value, expectedSnapshotSha) {
  exactKeys('issuer state', value, ISSUER_STATE_KEYS);
  requireKid('issuer state kid', value.issuer_kid);
  if (!SUPPORTED_ISSUER_STATUSES.includes(value.issuer_status)) {
    throw new Error('issuer status unsupported');
  }
  requireString('issuer status reason code', value.status_reason_code);
  const effectiveAt = requireIso('issuer status effective_at', value.status_effective_at);
  const expiresAt = requireIso('issuer status expires_at', value.status_expires_at);
  if (effectiveAt > expiresAt) {
    throw new Error('issuer status effective window drifted');
  }
  requireInteger('issuer status sequence', value.status_sequence, { min: 1 });
  requireSha256('issuer registry snapshot sha', value.registry_snapshot_sha256);
  if (value.registry_snapshot_sha256 !== expectedSnapshotSha) {
    throw new Error('issuer registry snapshot sha mismatch');
  }
  if (value.public_key_sha256 !== null) {
    requireSha256('issuer public key sha', value.public_key_sha256);
  }
  if (value.trust_anchor_sha256 !== null) {
    requireSha256('issuer trust anchor sha', value.trust_anchor_sha256);
  }
  if (value.public_key_sha256 === null && value.trust_anchor_sha256 === null) {
    throw new Error('issuer requires public key hash or trust anchor hash');
  }
  if (!isObject(value.scope_binding)) {
    throw new Error('issuer scope_binding must be an object');
  }
  assertClaimBoundary(value.claim_boundary, 'issuer state claim_boundary');
}

function assertCustodyPosture(value) {
  exactKeys('custody posture', value, CUSTODY_POSTURE_KEYS);
  if (!SUPPORTED_CUSTODY_CLASSES.includes(value.custody_class)) {
    throw new Error('custody class unsupported');
  }
  if (
    value.custody_class === 'software_local_proven' ||
    value.custody_class === 'hardware_proven' ||
    value.custody_class === 'production_custody_proven'
  ) {
    throw new Error('no-secret contract must not accept proven custody classes');
  }
  if (value.custody_evidence_id !== null) {
    requireString('custody evidence id', value.custody_evidence_id);
  }
  if (value.custody_evidence_sha256 !== null) {
    requireSha256('custody evidence sha', value.custody_evidence_sha256);
  }
  requireFalse('custody private_key_material_included', value.private_key_material_included);
  requireBoolean('custody key_custody_proven', value.key_custody_proven);
  requireBoolean('custody hardware_custody_proven', value.hardware_custody_proven);
  if (value.custody_class === 'none') {
    requireFalse('custody key_custody_proven', value.key_custody_proven);
    requireFalse('custody hardware_custody_proven', value.hardware_custody_proven);
  }
  if (value.key_custody_proven || value.hardware_custody_proven) {
    throw new Error('no-secret contract must not prove key or hardware custody');
  }
  assertClaimBoundary(value.claim_boundary, 'custody posture claim_boundary');
}

function assertRevocationClosure(value, expectedKid) {
  exactKeys('revocation closure', value, REVOCATION_CLOSURE_KEYS);
  requireString('revocation event id', value.revocation_event_id);
  requireKid('revocation issuer kid', value.issuer_kid);
  if (value.issuer_kid !== expectedKid) {
    throw new Error('revocation issuer kid mismatch');
  }
  if (!SUPPORTED_ISSUER_STATUSES.includes(value.previous_status)) {
    throw new Error('revocation previous status unsupported');
  }
  if (!['retired', 'revoked', 'compromised'].includes(value.new_status)) {
    throw new Error('revocation new status must be retired, revoked, or compromised');
  }
  requireIso('revoked_at', value.revoked_at);
  requireInteger('revocation registry sequence', value.registry_sequence, { min: 1 });
  requireSha256('revocation previous snapshot sha', value.previous_snapshot_sha256);
  requireSha256('revocation new snapshot sha', value.new_snapshot_sha256);
  requireString('revocation affected scope', value.affected_scope);
  requireInteger('revocation freshness window seconds', value.freshness_window_seconds, { min: 1 });
  requireTrue('revocation recognized_before_revocation', value.recognized_before_revocation);
  requireFalse('revocation recognized_after_revocation', value.recognized_after_revocation);
  assertClaimBoundary(value.claim_boundary, 'revocation closure claim_boundary');
}

export function assertLiveTrustRegistryStateContract(contract) {
  assertNoUnsafeText(contract);
  exactKeys('live trust registry state contract', contract, CONTRACT_KEYS);
  if (
    contract.contract_type !== LIVE_TRUST_REGISTRY_STATE_CONTRACT_TYPE ||
    contract.schema_version !== 1
  ) {
    throw new Error('live trust registry state contract identity drifted');
  }
  assertRegistrySnapshot(contract.registry_snapshot);
  assertIssuerState(contract.issuer_state, contract.registry_snapshot.snapshot_sha256);
  assertCustodyPosture(contract.custody_posture);
  assertRevocationClosure(contract.revocation_closure, contract.issuer_state.issuer_kid);
  assertClaimBoundary(contract.claim_boundary);
  if (!Array.isArray(contract.non_claims) || contract.non_claims.length === 0) {
    throw new Error('live trust registry contract non_claims must be non-empty');
  }
  if (
    contract.revocation_closure.previous_snapshot_sha256 !==
    contract.registry_snapshot.previous_snapshot_sha256
  ) {
    throw new Error('revocation previous snapshot must bind to registry previous snapshot');
  }
  if (contract.revocation_closure.new_snapshot_sha256 !== contract.registry_snapshot.snapshot_sha256) {
    throw new Error('revocation new snapshot must bind to registry snapshot');
  }
  if (contract.revocation_closure.registry_sequence !== contract.registry_snapshot.registry_sequence) {
    throw new Error('revocation registry sequence must bind to registry snapshot');
  }
  return true;
}

export function buildLiveTrustRegistryStateVerification(contract, { inputText = '' } = {}) {
  assertLiveTrustRegistryStateContract(contract);
  const canonical = canonicalLiveTrustRegistryStateJson(contract);
  return {
    verification_type: LIVE_TRUST_REGISTRY_STATE_VERIFICATION_TYPE,
    verified: true,
    evidence_model: 'no-secret-live-shaped-contract',
    contract_sha256: sha256Text(canonical),
    input_sha256: inputText ? sha256Text(inputText) : null,
    registry_id: contract.registry_snapshot.registry_id,
    registry_sequence: contract.registry_snapshot.registry_sequence,
    deployment_scope: contract.registry_snapshot.deployment_scope,
    issuer_kid: contract.issuer_state.issuer_kid,
    issuer_status: contract.issuer_state.issuer_status,
    custody_class: contract.custody_posture.custody_class,
    revocation_new_status: contract.revocation_closure.new_status,
    recognized_before_revocation: contract.revocation_closure.recognized_before_revocation,
    recognized_after_revocation: contract.revocation_closure.recognized_after_revocation,
    claim_boundary: { ...contract.claim_boundary },
    live_truth_claimed: false,
    key_custody_claimed: false,
    revocation_truth_claimed: false,
    production_recognition_claimed: false,
  };
}

export function formatLiveTrustRegistryStateVerification(verification) {
  assertNoUnsafeText(verification);
  return [
    'ZLAR live trust registry state contract verification',
    `verified: ${verification.verified}`,
    `evidence_model: ${verification.evidence_model}`,
    `contract_sha256: ${verification.contract_sha256}`,
    `registry_id: ${verification.registry_id}`,
    `registry_sequence: ${verification.registry_sequence}`,
    `deployment_scope: ${verification.deployment_scope}`,
    `issuer_kid: ${verification.issuer_kid}`,
    `issuer_status: ${verification.issuer_status}`,
    `custody_class: ${verification.custody_class}`,
    `recognized_before_revocation: ${verification.recognized_before_revocation}`,
    `recognized_after_revocation: ${verification.recognized_after_revocation}`,
    'claim_ceiling: no live registry, no key custody, no revocation truth, no production downstream recognition',
    '',
  ].join('\n');
}

export function readLiveTrustRegistryStateContract(path) {
  const text = readFileSync(path === '-' ? 0 : path, 'utf8');
  return {
    text,
    contract: JSON.parse(text),
  };
}
