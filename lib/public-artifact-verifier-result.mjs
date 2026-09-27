import { createHash } from 'node:crypto';

export const PUBLIC_ARTIFACT_VERIFIER_RESULT_TYPE =
  'zlar-public-artifact-verifier-result-v1';
export const PUBLIC_ARTIFACT_VERIFIER_RESULT_VERIFICATION_TYPE =
  'zlar-public-artifact-verifier-result-verification-v1';

export const PUBLIC_ARTIFACT_VERIFIER_RESULT_NON_CLAIMS = Object.freeze([
  'This report does not prove public external attestation.',
  'This report does not prove private source review.',
  'This report does not prove production authority or enterprise readiness.',
  'This report does not prove current-machine governance, all-surface governance, key custody, revocation truth, or side-door closure.',
]);

const EXPECTED_VERSION = 'v3.4.59';
const EXPECTED_RELEASE_JSON_URL = 'https://zlar.ai/release.json';
const EXPECTED_VERIFIER_KIT_URL = 'https://zlar.ai/verifier-kit/v3.4.59/';
const EXPECTED_TARBALL_NAME = 'zlar-verifier-kit-v0.1.0.tar.gz';
const EXPECTED_TARBALL_SIDECAR_NAME = `${EXPECTED_TARBALL_NAME}.sha256`;
const EXPECTED_REPRODUCIBILITY_NAME = 'zlar-verifier-kit-reproducibility-v1.json';
const EXPECTED_PROOF_PACK_MANIFEST_NAME = 'proof-pack-manifest.json';
const EXPECTED_PROOF_PACK_SHA256SUMS_NAME = 'SHA256SUMS';
const EXPECTED_SOURCE_ACCESS_PATH = 'public_release_assets_only';
const EXPECTED_LABEL = 'public-artifact-outside-machine-review-v3459-001';
const REQUIRED_FALSE_CLAIMS = Object.freeze([
  'public_external_attestation',
  'public_attribution',
  'non_operator_review_proven',
  'private_source_review',
  'production_authority',
  'enterprise_readiness',
  'current_machine_governance',
  'all_surface_governance',
  'key_custody',
  'revocation_truth',
  'side_door_closure',
]);

const UNSAFE_TEXT_PATTERNS = Object.freeze([
  { label: 'private operator path', pattern: /\/Users\/[^\s"'`]+/ },
  { label: 'home path', pattern: /\/home\/[^\s"'`]+/ },
  { label: 'private path', pattern: /\/private\/[^\s"'`]+/ },
  { label: 'temp path', pattern: /\/tmp\/[^\s"'`]+/ },
  { label: 'private key material', pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
  { label: 'assignment-shaped secret', pattern: /\b(?:token|secret|password|credential)\s*=/i },
  { label: 'token-shaped credential', pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/ },
  { label: 'GitHub token', pattern: /\b(?:ghp|github_pat)_[A-Za-z0-9_]{10,}\b/ },
  { label: 'email header residue', pattern: /(^|\n)\s*(?:From|To|Cc|Bcc|Subject|Date):\s+/i },
  { label: 'mailbox address residue', pattern: /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i },
]);

const UNSAFE_TRANSCRIPT_PATTERNS = Object.freeze([
  { label: 'private key material', pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
  { label: 'assignment-shaped secret', pattern: /\b(?:token|secret|password|credential)\s*=/i },
  { label: 'token-shaped credential', pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/ },
  { label: 'GitHub token', pattern: /\b(?:ghp|github_pat)_[A-Za-z0-9_]{10,}\b/ },
  { label: 'email header residue', pattern: /(^|\n)\s*(?:From|To|Cc|Bcc|Subject|Date):\s+/i },
  { label: 'mailbox address residue', pattern: /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i },
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

function requireSha(label, actual) {
  if (typeof actual !== 'string' || !/^[0-9a-f]{64}$/i.test(actual)) {
    throw new Error(`${label} must be a SHA-256 hex string`);
  }
  return actual.toLowerCase();
}

function sha256Text(text) {
  return createHash('sha256').update(text).digest('hex');
}

function parseSidecarSha(sidecarText) {
  if (typeof sidecarText !== 'string') {
    throw new Error('observed.sidecar_text must be a string');
  }
  const lines = sidecarText.trim().split(/\r?\n/).filter((line) => line.trim());
  if (lines.length !== 1) {
    throw new Error('observed.sidecar_text must contain exactly one non-empty line');
  }
  const line = lines[0];
  const match = line.match(/^([0-9a-f]{64})(?:\s+[* ]?(.+))?$/i);
  if (!match) {
    throw new Error('observed.sidecar_text must begin with a SHA-256 hex string');
  }
  const fileName = match[2] ? match[2].trim() : '';
  if (fileName && fileName !== EXPECTED_TARBALL_NAME) {
    throw new Error(`observed.sidecar_text must name ${EXPECTED_TARBALL_NAME}`);
  }
  return match[1].toLowerCase();
}

function requireTranscriptMarker(transcriptText, label, markers) {
  if (!markers.some((marker) => transcriptText.includes(marker))) {
    throw new Error(`transcript missing required public artifact marker: ${label}`);
  }
}

function extractTarballShaFromTranscript(transcriptText) {
  const escapedName = EXPECTED_TARBALL_NAME.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const linePattern = new RegExp(`(^|\\n)([0-9a-f]{64})\\s+(?:[* ]?${escapedName})(?=\\r?\\n|$)`, 'gi');
  const hashes = new Set();
  let match;
  while ((match = linePattern.exec(transcriptText)) !== null) {
    hashes.add(match[2].toLowerCase());
  }
  if (hashes.size === 0) {
    throw new Error(`transcript must include a SHA-256 line for ${EXPECTED_TARBALL_NAME}`);
  }
  if (hashes.size !== 1) {
    throw new Error(`transcript contains conflicting SHA-256 lines for ${EXPECTED_TARBALL_NAME}`);
  }
  return [...hashes][0];
}

function requireTarballSidecarOk(transcriptText) {
  const okPattern = new RegExp(`${EXPECTED_TARBALL_NAME.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}:\\s+OK\\b`);
  if (/FAILED|WARNING/i.test(transcriptText)) {
    throw new Error('transcript contains checksum failure or warning text');
  }
  if (!okPattern.test(transcriptText)) {
    throw new Error(`transcript must include ${EXPECTED_TARBALL_NAME}: OK`);
  }
}

export function samplePublicArtifactVerifierResult() {
  const tarballSha256 = '4'.repeat(64);
  return {
    report_type: PUBLIC_ARTIFACT_VERIFIER_RESULT_TYPE,
    schema_version: 1,
    verifier_label: EXPECTED_LABEL,
    target: {
      version: EXPECTED_VERSION,
      release_json_url: EXPECTED_RELEASE_JSON_URL,
      verifier_kit_url: EXPECTED_VERIFIER_KIT_URL,
      source_access_path: EXPECTED_SOURCE_ACCESS_PATH,
    },
    observed: {
      release_json_fetched: true,
      verifier_kit_tarball_fetched: true,
      verifier_kit_tarball_sha256: tarballSha256,
      sidecar_text: `${tarballSha256}  ${EXPECTED_TARBALL_NAME}\n`,
      sidecar_check_passed: true,
      reproducibility_json_fetched: true,
      proof_pack_manifest_fetched: true,
      proof_pack_sha256sums_fetched: true,
      source_access_used: false,
      github_access_used: false,
      credentials_used: false,
      deploy_key_used: false,
    },
    claim_boundary: {
      public_external_attestation: false,
      public_attribution: false,
      non_operator_review_proven: false,
      private_source_review: false,
      production_authority: false,
      enterprise_readiness: false,
      current_machine_governance: false,
      all_surface_governance: false,
      key_custody: false,
      revocation_truth: false,
      side_door_closure: false,
    },
    non_claims: [...PUBLIC_ARTIFACT_VERIFIER_RESULT_NON_CLAIMS],
  };
}

export function samplePublicArtifactVerifierTranscript() {
  const tarballSha256 = '4'.repeat(64);
  return [
    'curl -fsSLO https://zlar.ai/release.json',
    'curl -fsSLO https://zlar.ai/verifier-kit/v3.4.59/zlar-verifier-kit-v0.1.0.tar.gz',
    'curl -fsSLO https://zlar.ai/verifier-kit/v3.4.59/zlar-verifier-kit-v0.1.0.tar.gz.sha256',
    'curl -fsSLO https://zlar.ai/verifier-kit/v3.4.59/zlar-verifier-kit-reproducibility-v1.json',
    'curl -fsSLO https://zlar.ai/demo/proof-pack/proof-pack-manifest.json',
    'curl -fsSLO https://zlar.ai/demo/proof-pack/SHA256SUMS',
    `${tarballSha256}  ${EXPECTED_TARBALL_NAME}`,
    `${EXPECTED_TARBALL_NAME}: OK`,
    '',
  ].join('\n');
}

export function buildPublicArtifactVerifierResultFromTranscript(transcriptText) {
  if (typeof transcriptText !== 'string' || transcriptText.trim() === '') {
    throw new Error('transcript text is required');
  }
  assertNoUnsafePublicArtifactVerifierTranscriptText(transcriptText);
  requireTranscriptMarker(transcriptText, 'release.json', [EXPECTED_RELEASE_JSON_URL, 'release.json']);
  requireTranscriptMarker(transcriptText, EXPECTED_TARBALL_NAME, [EXPECTED_TARBALL_NAME]);
  requireTranscriptMarker(transcriptText, EXPECTED_TARBALL_SIDECAR_NAME, [EXPECTED_TARBALL_SIDECAR_NAME]);
  requireTranscriptMarker(transcriptText, EXPECTED_REPRODUCIBILITY_NAME, [EXPECTED_REPRODUCIBILITY_NAME]);
  requireTranscriptMarker(transcriptText, EXPECTED_PROOF_PACK_MANIFEST_NAME, [EXPECTED_PROOF_PACK_MANIFEST_NAME]);
  requireTranscriptMarker(transcriptText, EXPECTED_PROOF_PACK_SHA256SUMS_NAME, [EXPECTED_PROOF_PACK_SHA256SUMS_NAME]);
  requireTarballSidecarOk(transcriptText);
  const tarballSha256 = extractTarballShaFromTranscript(transcriptText);
  const report = samplePublicArtifactVerifierResult();
  report.observed.verifier_kit_tarball_sha256 = tarballSha256;
  report.observed.sidecar_text = `${tarballSha256}  ${EXPECTED_TARBALL_NAME}\n`;
  assertPublicArtifactVerifierResult(report);
  return report;
}

export function assertPublicArtifactVerifierResult(report) {
  exactKeys('report', report, [
    'claim_boundary',
    'non_claims',
    'observed',
    'report_type',
    'schema_version',
    'target',
    'verifier_label',
  ]);
  requireExact('report.report_type', PUBLIC_ARTIFACT_VERIFIER_RESULT_TYPE, report.report_type);
  requireExact('report.schema_version', 1, report.schema_version);
  requireExact('report.verifier_label', EXPECTED_LABEL, report.verifier_label);

  exactKeys('target', report.target, [
    'release_json_url',
    'source_access_path',
    'verifier_kit_url',
    'version',
  ]);
  requireExact('target.version', EXPECTED_VERSION, report.target.version);
  requireExact('target.release_json_url', EXPECTED_RELEASE_JSON_URL, report.target.release_json_url);
  requireExact('target.verifier_kit_url', EXPECTED_VERIFIER_KIT_URL, report.target.verifier_kit_url);
  requireExact('target.source_access_path', EXPECTED_SOURCE_ACCESS_PATH, report.target.source_access_path);

  exactKeys('observed', report.observed, [
    'credentials_used',
    'deploy_key_used',
    'github_access_used',
    'proof_pack_manifest_fetched',
    'proof_pack_sha256sums_fetched',
    'release_json_fetched',
    'reproducibility_json_fetched',
    'sidecar_check_passed',
    'sidecar_text',
    'source_access_used',
    'verifier_kit_tarball_fetched',
    'verifier_kit_tarball_sha256',
  ]);
  requireTrue('observed.release_json_fetched', report.observed.release_json_fetched);
  requireTrue('observed.verifier_kit_tarball_fetched', report.observed.verifier_kit_tarball_fetched);
  const tarballSha256 = requireSha(
    'observed.verifier_kit_tarball_sha256',
    report.observed.verifier_kit_tarball_sha256
  );
  const sidecarSha256 = parseSidecarSha(report.observed.sidecar_text);
  if (sidecarSha256 !== tarballSha256) {
    throw new Error('observed.sidecar_text hash must match observed.verifier_kit_tarball_sha256');
  }
  requireTrue('observed.sidecar_check_passed', report.observed.sidecar_check_passed);
  requireTrue('observed.reproducibility_json_fetched', report.observed.reproducibility_json_fetched);
  requireTrue('observed.proof_pack_manifest_fetched', report.observed.proof_pack_manifest_fetched);
  requireTrue('observed.proof_pack_sha256sums_fetched', report.observed.proof_pack_sha256sums_fetched);
  requireFalse('observed.source_access_used', report.observed.source_access_used);
  requireFalse('observed.github_access_used', report.observed.github_access_used);
  requireFalse('observed.credentials_used', report.observed.credentials_used);
  requireFalse('observed.deploy_key_used', report.observed.deploy_key_used);

  exactKeys('claim_boundary', report.claim_boundary, REQUIRED_FALSE_CLAIMS);
  for (const key of REQUIRED_FALSE_CLAIMS) {
    requireFalse(`claim_boundary.${key}`, report.claim_boundary[key]);
  }

  if (!Array.isArray(report.non_claims)) {
    throw new Error('non_claims must be an array');
  }
  if (report.non_claims.length !== PUBLIC_ARTIFACT_VERIFIER_RESULT_NON_CLAIMS.length) {
    throw new Error('non_claims must exactly match the public artifact verifier result non-claim list');
  }
  for (const [index, nonClaim] of PUBLIC_ARTIFACT_VERIFIER_RESULT_NON_CLAIMS.entries()) {
    if (report.non_claims[index] !== nonClaim) {
      throw new Error('non_claims must exactly match the public artifact verifier result non-claim list');
    }
  }
  assertNoUnsafePublicArtifactVerifierResultText(JSON.stringify(report));
  return true;
}

export function buildPublicArtifactVerifierResultVerification(report, { resultText = '' } = {}) {
  assertPublicArtifactVerifierResult(report);
  const resultSha256 = resultText ? sha256Text(resultText) : sha256Text(`${JSON.stringify(report, null, 2)}\n`);
  const tarballSha256 = report.observed.verifier_kit_tarball_sha256.toLowerCase();
  const verification = {
    verification_type: PUBLIC_ARTIFACT_VERIFIER_RESULT_VERIFICATION_TYPE,
    schema_version: 1,
    verified: true,
    result_sha256: resultSha256,
    verifier_label: report.verifier_label,
    target: { ...report.target },
    public_artifact_hash_consistency_signal: true,
    public_artifact_reachability_signal: true,
    observed: {
      verifier_kit_tarball_sha256: tarballSha256,
      sidecar_hash_matches_tarball: true,
      sidecar_check_passed: true,
      reproducibility_json_fetched: true,
      proof_pack_manifest_fetched: true,
      proof_pack_sha256sums_fetched: true,
      source_access_used: false,
      github_access_used: false,
      credentials_used: false,
      deploy_key_used: false,
    },
    claim_boundary: { ...report.claim_boundary },
    non_claims: [...PUBLIC_ARTIFACT_VERIFIER_RESULT_NON_CLAIMS],
  };
  assertNoUnsafePublicArtifactVerifierResultText(JSON.stringify(verification));
  return verification;
}

export function formatPublicArtifactVerifierResultVerification(verification) {
  const lines = [
    'ZLAR Public Artifact Verifier Result Verification v1',
    `verified=${verification.verified}`,
    `result_sha256=${verification.result_sha256}`,
    `verifier_label=${verification.verifier_label}`,
    `target.version=${verification.target.version}`,
    `target.release_json_url=${verification.target.release_json_url}`,
    `target.verifier_kit_url=${verification.target.verifier_kit_url}`,
    `public_artifact_hash_consistency_signal=${verification.public_artifact_hash_consistency_signal}`,
    `verifier_kit_tarball_sha256=${verification.observed.verifier_kit_tarball_sha256}`,
    `public_external_attestation=${verification.claim_boundary.public_external_attestation}`,
    `non_operator_review_proven=${verification.claim_boundary.non_operator_review_proven}`,
    `private_source_review=${verification.claim_boundary.private_source_review}`,
    `production_authority=${verification.claim_boundary.production_authority}`,
    `enterprise_readiness=${verification.claim_boundary.enterprise_readiness}`,
    `current_machine_governance=${verification.claim_boundary.current_machine_governance}`,
    '',
  ];
  const output = lines.join('\n');
  assertNoUnsafePublicArtifactVerifierResultText(output);
  return output;
}

export function assertNoUnsafePublicArtifactVerifierResultText(text) {
  for (const { label, pattern } of UNSAFE_TEXT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`unsafe public artifact verifier result text contains ${label}`);
    }
  }
  return true;
}

export function assertNoUnsafePublicArtifactVerifierTranscriptText(text) {
  for (const { label, pattern } of UNSAFE_TRANSCRIPT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`unsafe public artifact verifier transcript contains ${label}`);
    }
  }
  return true;
}
