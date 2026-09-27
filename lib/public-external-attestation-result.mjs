import { createHash, createPublicKey, verify } from 'node:crypto';

export const PUBLIC_EXTERNAL_ATTESTATION_RESULT_TYPE =
  'zlar-public-external-attestation-result-v1';
export const PUBLIC_EXTERNAL_ATTESTATION_RESULT_VERIFICATION_TYPE =
  'zlar-public-external-attestation-result-verification-v1';
export const PUBLIC_EXTERNAL_ATTESTATION_SIGNED_PAYLOAD_TYPE =
  'zlar-public-external-attestation-signed-payload-v1';

export const PUBLIC_EXTERNAL_ATTESTATION_RESULT_NON_CLAIMS = Object.freeze([
  'This report proves only bounded public external attestation for the named target.',
  'This report does not prove production authority or enterprise readiness.',
  'This report does not prove current-machine governance, all-surface governance, key custody, revocation truth, production downstream recognition, side-door closure, or sovereign recognition.',
  'This report does not prove private source review unless separately authorized and evidenced.',
]);

const ATTESTATION_CLASS = 'public_signed_or_published_external_attestation';
const SIGNATURE_MODE = 'detached_ed25519_signature';
const SOURCE_ACCESS_PATH = 'public_release_assets_only';
const RELATIONSHIP_CLASS = 'arms_length_external';

const TARGET_KEYS = Object.freeze([
  'artifact_set_sha256',
  'commit_sha',
  'proof_bundle_sha256',
  'readiness_report_sha256',
  'release_tag',
  'source_access_path',
]);

const CLAIM_BOUNDARY_KEYS = Object.freeze([
  'all_surface_governance',
  'current_machine_governance',
  'enterprise_readiness',
  'key_custody',
  'non_operator_review_proven',
  'private_source_review',
  'production_authority',
  'production_downstream_recognition',
  'public_attribution',
  'public_external_attestation',
  'revocation_truth',
  'side_door_closure',
  'sovereign_recognition',
]);

const REQUIRED_FALSE_CLAIMS = Object.freeze([
  'all_surface_governance',
  'current_machine_governance',
  'enterprise_readiness',
  'key_custody',
  'private_source_review',
  'production_authority',
  'production_downstream_recognition',
  'revocation_truth',
  'side_door_closure',
  'sovereign_recognition',
]);

const UNSAFE_TEXT_PATTERNS = Object.freeze([
  { label: 'private operator path', pattern: /\/Users\/[^\s"'`]+/ },
  { label: 'home path', pattern: /\/home\/[^\s"'`]+/ },
  { label: 'private path', pattern: /\/private\/[^\s"'`]+/ },
  { label: 'temp path', pattern: /\/tmp\/[^\s"'`]+/ },
  { label: 'private key material', pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
  {
    label: 'key-value credential',
    pattern: /\b(?:token|secret|password|credential|api[_-]?key)\s*[:=]\s*[^&\s"'`,;})\]]+/i,
  },
  { label: 'GitHub token', pattern: /\b(?:ghp|github_pat)_[A-Za-z0-9_]{10,}\b/ },
  { label: 'OpenAI-style key', pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/ },
  { label: 'latest flag', pattern: /(^|[\s"'`])--latest([\s"'`]|$)/ },
  { label: 'moving git checkout', pattern: /\bgit\s+checkout\s+(?:main|master|HEAD|latest)\b/i },
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

function requireExact(label, expected, actual) {
  if (actual !== expected) {
    throw new Error(`${label} must be ${JSON.stringify(expected)}`);
  }
}

function requireExactMatch(label, expected, actual) {
  if (actual !== expected) {
    throw new Error(`${label} mismatch`);
  }
}

function requireTrue(label, actual) {
  if (actual !== true) {
    throw new Error(`${label} must be true`);
  }
}

function requireFalse(label, actual) {
  if (actual !== false) {
    throw new Error(`${label} must be false`);
  }
}

function sha256Text(text) {
  return createHash('sha256').update(text).digest('hex');
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

export function canonicalPublicExternalAttestationJson(value) {
  return JSON.stringify(sortForCanonicalJson(value));
}

function requireSha(label, actual) {
  if (typeof actual !== 'string' || !/^[0-9a-f]{64}$/i.test(actual)) {
    throw new Error(`${label} must be a SHA-256 hex string`);
  }
  return actual.toLowerCase();
}

function requireCommit(label, actual) {
  if (typeof actual !== 'string' || !/^[0-9a-f]{40}$/i.test(actual)) {
    throw new Error(`${label} must be a 40-character git commit SHA`);
  }
  return actual.toLowerCase();
}

function requireReleaseTag(label, actual) {
  if (typeof actual !== 'string' || !/^v\d+\.\d+\.\d+$/.test(actual)) {
    throw new Error(`${label} must be an explicit vX.Y.Z release tag`);
  }
  if (actual === 'latest' || actual === 'HEAD') {
    throw new Error(`${label} must not be a moving target`);
  }
}

function requireHttps(label, actual) {
  if (typeof actual !== 'string' || !/^https:\/\/[A-Za-z0-9.-]+(?:\/[^\s"'`<>]*)?$/.test(actual)) {
    throw new Error(`${label} must be a public https URL`);
  }
}

function requireSafeLabel(label, actual) {
  if (typeof actual !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{2,120}$/.test(actual)) {
    throw new Error(`${label} must be a stable public-safe label`);
  }
}

function requireBase64(label, actual) {
  if (typeof actual !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(actual) || actual.length < 64) {
    throw new Error(`${label} must be base64-encoded signature bytes`);
  }
  return Buffer.from(actual, 'base64');
}

function requirePublicKeyPem(label, actual) {
  if (
    typeof actual !== 'string' ||
    !actual.includes('BEGIN PUBLIC KEY') ||
    !actual.includes('END PUBLIC KEY') ||
    actual.includes('PRIVATE KEY')
  ) {
    throw new Error(`${label} must be public key PEM only`);
  }
  return createPublicKey(actual);
}

function requireAttestationTextBinding(report) {
  const { attestation, target } = report;
  if (typeof attestation.attestation_text !== 'string' || attestation.attestation_text.trim() === '') {
    throw new Error('attestation.attestation_text must be non-empty text');
  }
  const text = attestation.attestation_text;
  for (const [label, fragment] of [
    ['release tag', target.release_tag],
    ['commit SHA', target.commit_sha],
    ['source access path', target.source_access_path],
    ['artifact set hash', target.artifact_set_sha256],
    ['readiness report hash', target.readiness_report_sha256],
    ['proof bundle hash', target.proof_bundle_sha256],
  ]) {
    if (!text.includes(fragment)) {
      throw new Error(`attestation.attestation_text must bind the ${label}`);
    }
  }
  for (const fragment of [
    'does not prove production authority',
    'does not prove enterprise readiness',
    'does not prove sovereign recognition',
  ]) {
    if (!text.includes(fragment)) {
      throw new Error(`attestation.attestation_text must include named limit: ${fragment}`);
    }
  }
}

function requireSignature(report, signedPayloadCanonicalJson) {
  const key = requirePublicKeyPem('attestation.public_key_pem', report.attestation.public_key_pem);
  const signature = requireBase64('attestation.signature_base64', report.attestation.signature_base64);
  const ok = verify(null, Buffer.from(signedPayloadCanonicalJson), key, signature);
  if (ok !== true) {
    throw new Error('attestation.signature_base64 must verify over the signed canonical envelope');
  }
}

export function buildPublicExternalAttestationSignedPayload(report) {
  return {
    payload_type: PUBLIC_EXTERNAL_ATTESTATION_SIGNED_PAYLOAD_TYPE,
    schema_version: 1,
    report_type: report.report_type,
    attestation_class: report.attestation_class,
    verifier: {
      verifier_label: report.verifier.verifier_label,
      relationship_disclosure_class: report.verifier.relationship_disclosure_class,
      public_attribution_approved: report.verifier.public_attribution_approved,
      public_identity_url: report.verifier.public_identity_url,
      public_identity_redacted_in_private_ledger: report.verifier.public_identity_redacted_in_private_ledger,
      public_key_pem_sha256: report.verifier.public_key_pem_sha256,
    },
    target: { ...report.target },
    attestation: {
      mode: report.attestation.mode,
      attestation_text: report.attestation.attestation_text,
      attestation_text_sha256: report.attestation.attestation_text_sha256,
      named_limits_present: report.attestation.named_limits_present,
      target_binding_present: report.attestation.target_binding_present,
      non_claims_present: report.attestation.non_claims_present,
      signed_or_published_by_verifier: report.attestation.signed_or_published_by_verifier,
      attestation_preserved_for_future_checking: report.attestation.attestation_preserved_for_future_checking,
    },
    claim_boundary: { ...report.claim_boundary },
    non_claims: [...report.non_claims],
  };
}

export function assertPublicExternalAttestationResult(report) {
  exactKeys('report', report, [
    'attestation',
    'attestation_class',
    'claim_boundary',
    'non_claims',
    'report_type',
    'schema_version',
    'target',
    'verifier',
  ]);
  requireExact('report.report_type', PUBLIC_EXTERNAL_ATTESTATION_RESULT_TYPE, report.report_type);
  requireExact('report.schema_version', 1, report.schema_version);
  requireExact('report.attestation_class', ATTESTATION_CLASS, report.attestation_class);

  exactKeys('verifier', report.verifier, [
    'public_attribution_approved',
    'public_identity_redacted_in_private_ledger',
    'public_identity_url',
    'public_key_pem_sha256',
    'relationship_disclosure_class',
    'verifier_label',
  ]);
  requireSafeLabel('verifier.verifier_label', report.verifier.verifier_label);
  report.verifier.public_key_pem_sha256 = requireSha(
    'verifier.public_key_pem_sha256',
    report.verifier.public_key_pem_sha256
  );
  requireExact(
    'verifier.relationship_disclosure_class',
    RELATIONSHIP_CLASS,
    report.verifier.relationship_disclosure_class
  );
  requireTrue('verifier.public_attribution_approved', report.verifier.public_attribution_approved);
  requireHttps('verifier.public_identity_url', report.verifier.public_identity_url);
  requireTrue(
    'verifier.public_identity_redacted_in_private_ledger',
    report.verifier.public_identity_redacted_in_private_ledger
  );

  exactKeys('target', report.target, TARGET_KEYS);
  requireReleaseTag('target.release_tag', report.target.release_tag);
  report.target.commit_sha = requireCommit('target.commit_sha', report.target.commit_sha);
  requireExact('target.source_access_path', SOURCE_ACCESS_PATH, report.target.source_access_path);
  report.target.artifact_set_sha256 = requireSha('target.artifact_set_sha256', report.target.artifact_set_sha256);
  report.target.readiness_report_sha256 = requireSha(
    'target.readiness_report_sha256',
    report.target.readiness_report_sha256
  );
  report.target.proof_bundle_sha256 = requireSha('target.proof_bundle_sha256', report.target.proof_bundle_sha256);

  exactKeys('attestation', report.attestation, [
    'attestation_preserved_for_future_checking',
    'attestation_text',
    'attestation_text_sha256',
    'mode',
    'named_limits_present',
    'non_claims_present',
    'public_key_pem',
    'signature_base64',
    'signed_payload_canonical_json',
    'signed_payload_sha256',
    'signed_or_published_by_verifier',
    'target_binding_present',
  ]);
  const publicKeyPemSha256 = sha256Text(report.attestation.public_key_pem);
  requireExact('verifier.public_key_pem_sha256', publicKeyPemSha256, report.verifier.public_key_pem_sha256);
  requireExact('attestation.mode', SIGNATURE_MODE, report.attestation.mode);
  requireTrue('attestation.named_limits_present', report.attestation.named_limits_present);
  requireTrue('attestation.target_binding_present', report.attestation.target_binding_present);
  requireTrue('attestation.non_claims_present', report.attestation.non_claims_present);
  requireTrue(
    'attestation.signed_or_published_by_verifier',
    report.attestation.signed_or_published_by_verifier
  );
  requireTrue(
    'attestation.attestation_preserved_for_future_checking',
    report.attestation.attestation_preserved_for_future_checking
  );
  const attestationTextSha256 = sha256Text(report.attestation.attestation_text);
  requireExact(
    'attestation.attestation_text_sha256',
    attestationTextSha256,
    report.attestation.attestation_text_sha256
  );
  requireAttestationTextBinding(report);

  exactKeys('claim_boundary', report.claim_boundary, CLAIM_BOUNDARY_KEYS);
  requireTrue('claim_boundary.public_external_attestation', report.claim_boundary.public_external_attestation);
  requireTrue('claim_boundary.public_attribution', report.claim_boundary.public_attribution);
  requireTrue('claim_boundary.non_operator_review_proven', report.claim_boundary.non_operator_review_proven);
  for (const key of REQUIRED_FALSE_CLAIMS) {
    requireFalse(`claim_boundary.${key}`, report.claim_boundary[key]);
  }

  if (!Array.isArray(report.non_claims)) {
    throw new Error('non_claims must be an array');
  }
  if (report.non_claims.length !== PUBLIC_EXTERNAL_ATTESTATION_RESULT_NON_CLAIMS.length) {
    throw new Error('non_claims must exactly match the public external attestation non-claim list');
  }
  for (const [index, nonClaim] of PUBLIC_EXTERNAL_ATTESTATION_RESULT_NON_CLAIMS.entries()) {
    if (report.non_claims[index] !== nonClaim) {
      throw new Error('non_claims must exactly match the public external attestation non-claim list');
    }
  }

  const signedPayloadCanonicalJson = canonicalPublicExternalAttestationJson(
    buildPublicExternalAttestationSignedPayload(report)
  );
  requireExactMatch(
    'attestation.signed_payload_canonical_json',
    signedPayloadCanonicalJson,
    report.attestation.signed_payload_canonical_json
  );
  requireExact(
    'attestation.signed_payload_sha256',
    sha256Text(signedPayloadCanonicalJson),
    report.attestation.signed_payload_sha256
  );
  requireSignature(report, signedPayloadCanonicalJson);

  assertNoUnsafePublicExternalAttestationResultText(JSON.stringify(report));
  return true;
}

export function buildPublicExternalAttestationResultVerification(report, { resultText = '' } = {}) {
  assertPublicExternalAttestationResult(report);
  const resultSha256 = resultText ? sha256Text(resultText) : sha256Text(`${JSON.stringify(report, null, 2)}\n`);
  const verification = {
    verification_type: PUBLIC_EXTERNAL_ATTESTATION_RESULT_VERIFICATION_TYPE,
    schema_version: 1,
    verified: true,
    result_sha256: resultSha256,
    attestation_class: report.attestation_class,
    verifier_label: report.verifier.verifier_label,
    relationship_disclosure_class: report.verifier.relationship_disclosure_class,
    public_key_pem_sha256: report.verifier.public_key_pem_sha256,
    target: { ...report.target },
    attestation: {
      mode: report.attestation.mode,
      attestation_text_sha256: report.attestation.attestation_text_sha256,
      signed_payload_sha256: report.attestation.signed_payload_sha256,
      signature_verified: true,
      named_limits_present: true,
      target_binding_present: true,
      non_claims_present: true,
      signed_or_published_by_verifier: true,
      attestation_preserved_for_future_checking: true,
    },
    claim_boundary: { ...report.claim_boundary },
    non_claims: [...PUBLIC_EXTERNAL_ATTESTATION_RESULT_NON_CLAIMS],
  };
  assertNoUnsafePublicExternalAttestationResultText(JSON.stringify(verification));
  return verification;
}

export function formatPublicExternalAttestationResultVerification(verification) {
  const lines = [
    'ZLAR Public External Attestation Result Verification v1',
    `verified=${verification.verified}`,
    `result_sha256=${verification.result_sha256}`,
    `verifier_label=${verification.verifier_label}`,
    `public_key_pem_sha256=${verification.public_key_pem_sha256}`,
    `attestation_class=${verification.attestation_class}`,
    `target.release_tag=${verification.target.release_tag}`,
    `target.commit_sha=${verification.target.commit_sha}`,
    `attestation.signed_payload_sha256=${verification.attestation.signed_payload_sha256}`,
    `attestation.signature_verified=${verification.attestation.signature_verified}`,
    `attestation.named_limits_present=${verification.attestation.named_limits_present}`,
    `public_external_attestation=${verification.claim_boundary.public_external_attestation}`,
    `non_operator_review_proven=${verification.claim_boundary.non_operator_review_proven}`,
    `production_authority=${verification.claim_boundary.production_authority}`,
    `enterprise_readiness=${verification.claim_boundary.enterprise_readiness}`,
    `sovereign_recognition=${verification.claim_boundary.sovereign_recognition}`,
    '',
  ];
  const output = lines.join('\n');
  assertNoUnsafePublicExternalAttestationResultText(output);
  return output;
}

export function assertNoUnsafePublicExternalAttestationResultText(text) {
  for (const { label, pattern } of UNSAFE_TEXT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`unsafe public external attestation result text contains ${label}`);
    }
  }
  return true;
}
