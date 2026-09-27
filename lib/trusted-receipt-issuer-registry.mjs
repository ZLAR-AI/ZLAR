import { canonicalize } from './canonicalize.mjs';
import { evaluateDownstreamRecognition } from './downstream-recognition-rule.mjs';
import { sha256hex } from './receipt.mjs';

export const TRUSTED_RECEIPT_ISSUER_REGISTRY_V1_TYPE =
  'trusted-receipt-issuers-v1';
export const TRUSTED_RECEIPT_ISSUER_REGISTRY_V2_TYPE =
  'trusted-receipt-issuers-v2';
export const TRUSTED_RECEIPT_ISSUER_REGISTRY_V2_CONTRACT_EVIDENCE =
  'no-secret-registry-contract-v2';
export const TRUSTED_RECEIPT_ISSUER_REGISTRY_V2_SUMMARY_TYPE =
  'trusted-receipt-issuer-registry-public-safe-summary-v2';

export const TRUSTED_RECEIPT_ISSUER_V1_STATUSES = Object.freeze([
  'active',
  'retired',
  'compromised',
]);

export const TRUSTED_RECEIPT_ISSUER_V2_STATUSES = Object.freeze([
  'active',
  'retired',
  'revoked',
  'compromised',
]);

export const TRUSTED_RECEIPT_ISSUER_REGISTRY_V2_FORBIDDEN_CLAIM_FLAGS =
  Object.freeze([
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

const V1_REGISTRY_REQUIRED_KEYS = Object.freeze([
  'accepted_domains',
  'accepted_outcomes',
  'accepted_policy_versions',
  'accepted_tools',
  'deployment_scope',
  'evidence_model',
  'live_probing',
  'non_claims',
  'registry_type',
  'trusted_issuers',
  'version',
]);

const V1_REGISTRY_OPTIONAL_KEYS = Object.freeze([
  'required_audit_event_id',
  'required_detail_hash',
]);

const V1_ISSUER_KEYS = Object.freeze([
  'kid',
  'public_key_pem',
  'status',
]);

const V2_REGISTRY_KEYS = Object.freeze([
  'accepted_domains',
  'accepted_outcomes',
  'accepted_policy_versions',
  'accepted_tools',
  'claim_boundary',
  'deployment_scope',
  'effective_at',
  'evidence_model',
  'expires_at',
  'freshness_requirements',
  'live_probing',
  'non_claims',
  'registry_id',
  'registry_type',
  'replay_protection',
  'required_audit_event_id',
  'required_detail_hash',
  'trusted_issuers',
  'version',
]);

const V2_ISSUER_KEYS = Object.freeze([
  'custody_posture',
  'effective_at',
  'expires_at',
  'kid',
  'public_key_pem',
  'status',
  'status_reason',
  'status_transition',
  'trust_anchor_sha256',
]);

const CUSTODY_POSTURE_KEYS = Object.freeze([
  'custody_proof_provided',
  'declaration',
  'hardware_custody_proven',
  'private_key_material_included',
]);

const STATUS_TRANSITION_KEYS = Object.freeze([
  'previous_status',
  'reason',
  'transition_at',
  'transition_type',
]);

const FRESHNESS_REQUIREMENT_KEYS = Object.freeze([
  'future_tolerance_seconds',
  'max_age_seconds',
]);

const REPLAY_PROTECTION_KEYS = Object.freeze([
  'atomic_consume_required',
  'receipt_id_required',
  'replay_cache_required',
]);

const RAW_PRIVATE_MATERIAL_PATTERNS = Object.freeze([
  { label: 'private key material', pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
  {
    label: 'key-value credential',
    pattern: /\b(?:token|secret|password|api[_-]?key)\s*[:=]\s*[^&\s"'`,;})\]]+/i,
  },
  {
    label: 'authorization credential',
    pattern: /\bauthorization\s*[:=]\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}/i,
  },
]);

const UNSAFE_SUMMARY_PATTERNS = Object.freeze([
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
]);

function isObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(label, value, expectedKeys) {
  if (!isObject(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${label} contains unexpected fields`);
  }
}

function allowedKeys(label, value, allowed, required) {
  if (!isObject(value)) {
    throw new Error(`${label} must be an object`);
  }
  const allowedSet = new Set(allowed);
  const extras = Object.keys(value).filter((key) => !allowedSet.has(key));
  if (extras.length > 0) {
    throw new Error(`${label} contains unexpected fields`);
  }
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      throw new Error(`${label} is missing required field: ${key}`);
    }
  }
}

function requiredString(label, value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
}

function requiredSha256(label, value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`${label} must be a SHA-256 hex string`);
  }
}

function requiredIso(label, value) {
  requiredString(label, value);
  const millis = Date.parse(value);
  if (!Number.isFinite(millis)) {
    throw new Error(`${label} must be ISO-8601`);
  }
  return millis;
}

function requiredStringArray(label, value) {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((item) => typeof item !== 'string' || item.length === 0)
  ) {
    throw new Error(`${label} must be a non-empty string array`);
  }
}

function assertNoRawPrivateMaterial(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of RAW_PRIVATE_MATERIAL_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`trusted receipt issuer registry contains ${label}`);
    }
  }
}

function assertClaimBoundary(value) {
  exactKeys('trusted receipt issuer registry claim_boundary', value, [
    ...TRUSTED_RECEIPT_ISSUER_REGISTRY_V2_FORBIDDEN_CLAIM_FLAGS,
  ]);
  for (const field of TRUSTED_RECEIPT_ISSUER_REGISTRY_V2_FORBIDDEN_CLAIM_FLAGS) {
    if (value[field] !== false) {
      throw new Error(`trusted receipt issuer registry forbidden claim flag must be false: ${field}`);
    }
  }
}

function assertCustodyPosture(value) {
  exactKeys('trusted receipt issuer custody posture', value, CUSTODY_POSTURE_KEYS);
  requiredString('trusted receipt issuer custody declaration', value.declaration);
  if (
    value.private_key_material_included !== false ||
    value.hardware_custody_proven !== false ||
    value.custody_proof_provided !== false
  ) {
    throw new Error('trusted receipt issuer custody posture must not claim private material, hardware custody, or custody proof');
  }
}

function assertStatusTransition(value) {
  exactKeys('trusted receipt issuer status transition', value, STATUS_TRANSITION_KEYS);
  if (
    value.previous_status !== null &&
    !TRUSTED_RECEIPT_ISSUER_V2_STATUSES.includes(value.previous_status)
  ) {
    throw new Error('trusted receipt issuer previous status is unsupported');
  }
  requiredString('trusted receipt issuer status transition type', value.transition_type);
  requiredString('trusted receipt issuer status transition reason', value.reason);
  requiredIso('trusted receipt issuer status transition time', value.transition_at);
}

function assertIssuer(issuer, registryEffectiveAt, registryExpiresAt) {
  exactKeys('trusted receipt issuer', issuer, V2_ISSUER_KEYS);
  if (typeof issuer.kid !== 'string' || !/^[a-f0-9]{16}$/.test(issuer.kid)) {
    throw new Error('trusted receipt issuer kid must be 16 lowercase hex characters');
  }
  if (!TRUSTED_RECEIPT_ISSUER_V2_STATUSES.includes(issuer.status)) {
    throw new Error('trusted receipt issuer status is unsupported');
  }
  requiredString('trusted receipt issuer status reason', issuer.status_reason);
  const issuerEffectiveAt = requiredIso('trusted receipt issuer effective_at', issuer.effective_at);
  const issuerExpiresAt = requiredIso('trusted receipt issuer expires_at', issuer.expires_at);
  if (
    issuerEffectiveAt > issuerExpiresAt ||
    issuerEffectiveAt < registryEffectiveAt ||
    issuerExpiresAt > registryExpiresAt
  ) {
    throw new Error('trusted receipt issuer effective window drifted');
  }
  if (
    issuer.public_key_pem !== null &&
    (
      typeof issuer.public_key_pem !== 'string' ||
      !issuer.public_key_pem.startsWith('-----BEGIN PUBLIC KEY-----')
    )
  ) {
    throw new Error('trusted receipt issuer public key must be PEM or null');
  }
  if (issuer.trust_anchor_sha256 !== null) {
    requiredSha256('trusted receipt issuer trust anchor', issuer.trust_anchor_sha256);
  }
  if (issuer.status === 'active' && !issuer.public_key_pem && !issuer.trust_anchor_sha256) {
    throw new Error('active trusted receipt issuer requires a public key or trust anchor');
  }
  assertCustodyPosture(issuer.custody_posture);
  assertStatusTransition(issuer.status_transition);
}

function assertFreshness(value) {
  exactKeys('trusted receipt issuer registry freshness requirements', value, FRESHNESS_REQUIREMENT_KEYS);
  if (!Number.isInteger(value.max_age_seconds) || value.max_age_seconds <= 0) {
    throw new Error('trusted receipt issuer registry max_age_seconds must be a positive integer');
  }
  if (value.future_tolerance_seconds !== 0) {
    throw new Error('trusted receipt issuer registry future_tolerance_seconds must be 0');
  }
}

function assertReplayProtection(value) {
  exactKeys('trusted receipt issuer registry replay protection', value, REPLAY_PROTECTION_KEYS);
  if (
    value.receipt_id_required !== true ||
    value.atomic_consume_required !== true ||
    value.replay_cache_required !== true
  ) {
    throw new Error('trusted receipt issuer registry replay protection must be explicit and fail closed');
  }
}

export function assertTrustedReceiptIssuerRegistryV1Contract(registry) {
  allowedKeys(
    'trusted receipt issuer V1 registry',
    registry,
    [...V1_REGISTRY_REQUIRED_KEYS, ...V1_REGISTRY_OPTIONAL_KEYS],
    V1_REGISTRY_REQUIRED_KEYS
  );
  if (
    registry.registry_type !== TRUSTED_RECEIPT_ISSUER_REGISTRY_V1_TYPE ||
    registry.version !== 1 ||
    registry.live_probing !== false
  ) {
    throw new Error('trusted receipt issuer V1 registry identity, version, or live_probing drifted');
  }
  requiredString('trusted receipt issuer V1 registry evidence model', registry.evidence_model);
  requiredString('trusted receipt issuer V1 registry deployment scope', registry.deployment_scope);
  if (!Array.isArray(registry.trusted_issuers) || registry.trusted_issuers.length === 0) {
    throw new Error('trusted receipt issuer V1 registry requires at least one issuer');
  }
  for (const issuer of registry.trusted_issuers) {
    exactKeys('trusted receipt issuer V1', issuer, V1_ISSUER_KEYS);
    if (typeof issuer.kid !== 'string' || !/^[a-f0-9]{16}$/.test(issuer.kid)) {
      throw new Error('trusted receipt issuer V1 kid must be 16 lowercase hex characters');
    }
    if (
      typeof issuer.public_key_pem !== 'string' ||
      !issuer.public_key_pem.startsWith('-----BEGIN PUBLIC KEY-----')
    ) {
      throw new Error('trusted receipt issuer V1 public key must be PEM');
    }
    if (!TRUSTED_RECEIPT_ISSUER_V1_STATUSES.includes(issuer.status)) {
      throw new Error('trusted receipt issuer V1 status is unsupported');
    }
  }
  for (const field of [
    'accepted_policy_versions',
    'accepted_domains',
    'accepted_tools',
    'accepted_outcomes',
  ]) {
    if (
      !Array.isArray(registry[field]) ||
      registry[field].some((item) => typeof item !== 'string' || item.length === 0)
    ) {
      throw new Error(`trusted receipt issuer V1 registry ${field} must be a string array`);
    }
  }
  requiredStringArray('trusted receipt issuer V1 registry non-claims', registry.non_claims);
  if (Object.prototype.hasOwnProperty.call(registry, 'required_audit_event_id')) {
    requiredString(
      'trusted receipt issuer V1 registry required audit event id',
      registry.required_audit_event_id
    );
  }
  if (Object.prototype.hasOwnProperty.call(registry, 'required_detail_hash')) {
    requiredSha256(
      'trusted receipt issuer V1 registry required detail hash',
      registry.required_detail_hash
    );
  }
  return true;
}

export function assertTrustedReceiptIssuerRegistryV2Contract(registry) {
  assertNoRawPrivateMaterial(registry);
  exactKeys('trusted receipt issuer registry', registry, V2_REGISTRY_KEYS);
  if (
    registry.registry_type !== TRUSTED_RECEIPT_ISSUER_REGISTRY_V2_TYPE ||
    registry.version !== 2 ||
    registry.live_probing !== false
  ) {
    throw new Error('trusted receipt issuer registry identity, version, or live_probing drifted');
  }
  requiredString('trusted receipt issuer registry id', registry.registry_id);
  requiredString('trusted receipt issuer registry evidence model', registry.evidence_model);
  requiredString('trusted receipt issuer registry deployment scope', registry.deployment_scope);
  const registryEffectiveAt = requiredIso('trusted receipt issuer registry effective_at', registry.effective_at);
  const registryExpiresAt = requiredIso('trusted receipt issuer registry expires_at', registry.expires_at);
  if (registryEffectiveAt > registryExpiresAt) {
    throw new Error('trusted receipt issuer registry effective window drifted');
  }
  requiredStringArray('trusted receipt issuer registry accepted policy versions', registry.accepted_policy_versions);
  requiredStringArray('trusted receipt issuer registry accepted domains', registry.accepted_domains);
  requiredStringArray('trusted receipt issuer registry accepted tools', registry.accepted_tools);
  requiredStringArray('trusted receipt issuer registry accepted outcomes', registry.accepted_outcomes);
  requiredString('trusted receipt issuer registry required audit event id', registry.required_audit_event_id);
  requiredSha256('trusted receipt issuer registry required detail hash', registry.required_detail_hash);
  assertFreshness(registry.freshness_requirements);
  assertReplayProtection(registry.replay_protection);
  assertClaimBoundary(registry.claim_boundary);
  requiredStringArray('trusted receipt issuer registry non-claims', registry.non_claims);
  if (!Array.isArray(registry.trusted_issuers) || registry.trusted_issuers.length === 0) {
    throw new Error('trusted receipt issuer registry requires at least one issuer');
  }
  const kids = new Set();
  for (const issuer of registry.trusted_issuers) {
    assertIssuer(issuer, registryEffectiveAt, registryExpiresAt);
    if (kids.has(issuer.kid)) {
      throw new Error('trusted receipt issuer registry contains duplicate kid');
    }
    kids.add(issuer.kid);
  }
  return true;
}

export function trustedReceiptIssuerRegistryV2ToRecognitionRule(registry) {
  assertTrustedReceiptIssuerRegistryV2Contract(registry);
  return {
    deployment_scope: registry.deployment_scope,
    accepted_issuers: registry.trusted_issuers.map((issuer) => ({
      kid: issuer.kid,
      public_key_pem: issuer.public_key_pem,
      status: issuer.status,
    })),
    accepted_policy_versions: [...registry.accepted_policy_versions],
    accepted_domains: [...registry.accepted_domains],
    accepted_tools: [...registry.accepted_tools],
    accepted_outcomes: [...registry.accepted_outcomes],
    max_age_seconds: registry.freshness_requirements.max_age_seconds,
    required_audit_event_id: registry.required_audit_event_id,
    required_detail_hash: registry.required_detail_hash,
  };
}

export function evaluateTrustedReceiptIssuerRegistryV2Recognition({
  receipt,
  registry,
  deployment_scope: deploymentScope,
  now_epoch: nowEpoch,
} = {}) {
  assertTrustedReceiptIssuerRegistryV2Contract(registry);
  if (deploymentScope && deploymentScope !== registry.deployment_scope) {
    return {
      result_type: 'trusted-issuer-registry-recognition-v2',
      recognized: false,
      decision: 'refuse',
      reason_code: 'scope_not_found',
      reasons: [
        {
          code: 'scope_not_found',
          message: 'Requested deployment scope does not match the supplied registry.',
        },
      ],
      evidence: {
        receipt_present: Boolean(receipt),
        registry_type: registry.registry_type,
        requested_scope: deploymentScope,
        registry_scope: registry.deployment_scope,
      },
    };
  }
  return evaluateDownstreamRecognition({
    receipt,
    recognition_rule: trustedReceiptIssuerRegistryV2ToRecognitionRule(registry),
    now_epoch: nowEpoch,
  });
}

export function publicSafeTrustedReceiptIssuerRegistryV2Summary(registry) {
  assertTrustedReceiptIssuerRegistryV2Contract(registry);
  const summary = {
    summary_type: TRUSTED_RECEIPT_ISSUER_REGISTRY_V2_SUMMARY_TYPE,
    contract_evidence: TRUSTED_RECEIPT_ISSUER_REGISTRY_V2_CONTRACT_EVIDENCE,
    registry_type: registry.registry_type,
    registry_id: registry.registry_id,
    version: registry.version,
    evidence_model: registry.evidence_model,
    live_probing: registry.live_probing,
    deployment_scope: registry.deployment_scope,
    effective_at: registry.effective_at,
    expires_at: registry.expires_at,
    accepted_policy_versions: [...registry.accepted_policy_versions],
    accepted_domains: [...registry.accepted_domains],
    accepted_tools: [...registry.accepted_tools],
    accepted_outcomes: [...registry.accepted_outcomes],
    freshness_requirements: { ...registry.freshness_requirements },
    replay_protection: { ...registry.replay_protection },
    required_audit_event_id: registry.required_audit_event_id,
    required_detail_hash: registry.required_detail_hash,
    trusted_issuer_count: registry.trusted_issuers.length,
    trusted_issuers: registry.trusted_issuers.map((issuer) => ({
      kid: issuer.kid,
      status: issuer.status,
      status_reason: issuer.status_reason,
      effective_at: issuer.effective_at,
      expires_at: issuer.expires_at,
      public_key_sha256: issuer.public_key_pem
        ? sha256hex(issuer.public_key_pem)
        : null,
      trust_anchor_sha256: issuer.trust_anchor_sha256,
      public_key_material_included: false,
      private_key_material_included:
        issuer.custody_posture.private_key_material_included,
      hardware_custody_proven: issuer.custody_posture.hardware_custody_proven,
      custody_proof_provided: issuer.custody_posture.custody_proof_provided,
      status_transition: { ...issuer.status_transition },
    })),
    claim_boundary: { ...registry.claim_boundary },
    non_claims: [...registry.non_claims],
    registry_contract_sha256: sha256hex(canonicalize(registry)),
    raw_public_key_material_included: false,
    raw_private_key_material_included: false,
    live_registry_truth_claimed: false,
  };
  return {
    ...summary,
    summary_sha256: sha256hex(canonicalize(summary)),
  };
}

export function assertNoUnsafeTrustedReceiptIssuerRegistryV2SummaryText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_SUMMARY_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`trusted receipt issuer registry summary contains ${label}`);
    }
  }
  return true;
}
