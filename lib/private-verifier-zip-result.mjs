import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
} from 'node:fs';
import {
  resolve,
  sep,
} from 'node:path';

export const PRIVATE_VERIFIER_ZIP_RESULT_TYPE = 'zlar-private-verifier-zip-result-v1';
export const PRIVATE_VERIFIER_ZIP_RESULT_VERIFICATION_TYPE =
  'zlar-private-verifier-zip-result-verification-v1';

export const PRIVATE_VERIFIER_ZIP_RELATIONSHIP =
  "private personally connected outside-machine verifier; not independent, public, or arm's-length attestation";

export const PRIVATE_VERIFIER_ZIP_SOURCE_ROUTE = 'browser-downloaded-zip-snapshot';
export const PRIVATE_VERIFIER_ZIP_EVIDENCE_MODEL =
  'zip-snapshot-returned-artifact-set';

export const REQUIRED_ZIP_RESULT_STEPS = Object.freeze([
  'node-check-proof-smoke',
  'source-bridge-window',
  'proof-smoke-verify',
  'north-star-readiness',
  'test-proof-smoke-cli',
  'test-proof-smoke-report',
  'public-privacy',
]);

export const PRIVATE_VERIFIER_ZIP_NON_CLAIMS = Object.freeze([
  'This result is private/internal intake only unless separate public disclosure is approved.',
  'This result is not independent, third-party, public, or arm\'s-length attestation.',
  'This result does not prove git clone source access or source-transport credential proof.',
  'This result does not prove production trust, current-machine governance, all-surface governance, or side-door closure.',
  'This result does not prove North Star readiness, website/public alignment, tag/release proof, or absolute human intention.',
]);

const REQUIRED_NON_CLAIM_FRAGMENTS = Object.freeze([
  'private/internal intake',
  'not independent',
  'git clone source access',
  'production trust',
  'North Star readiness',
]);

const CLAIM_BOUNDARY_FALSE_KEYS = Object.freeze([
  'public_external_attestation',
  'independent_review',
  'arms_length_review',
  'public_attribution',
  'git_clone_source_access',
  'source_transport_credentials',
  'tag_or_release_proof',
  'website_public_alignment',
  'production_trust',
  'current_machine_governance',
  'all_surface_governance',
  'north_star_readiness',
  'side_door_closure',
  'absolute_human_intention',
]);

const PRIVACY_FALSE_KEYS = Object.freeze([
  'public_attribution_approved',
  'public_external_attestation_approved',
  'verifier_identity_public',
  'verifier_contact_public',
  'private_contact_included',
  'private_paths_included',
  'credentials_included',
]);

const UNSAFE_ENVELOPE_TEXT_PATTERNS = Object.freeze([
  { label: 'private operator path', pattern: /\/Users\/[^\s"'`]+/ },
  { label: 'home path', pattern: /\/home\/[^\s"'`]+/ },
  { label: 'private path', pattern: /\/private\/[^\s"'`]+/ },
  { label: 'temp path', pattern: /\/tmp\/[^\s"'`]+/ },
  { label: 'var path', pattern: /\/var\/[^\s"'`]+/ },
  { label: 'email address', pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i },
  { label: 'private key material', pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
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
  { label: 'OpenAI-style key', pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/ },
  { label: 'bot token', pattern: /\bbot[0-9]{6,}:[A-Za-z0-9_-]{6,}\b/ },
  { label: 'latest flag', pattern: /(^|[\s"'`])--latest([\s"'`]|$)/ },
  { label: 'moving git checkout', pattern: /\bgit\s+checkout\s+(?:main|master|HEAD|latest)\b/i },
]);

const UNSAFE_EVIDENCE_TEXT_PATTERNS = Object.freeze([
  { label: 'private key material', pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
  {
    label: 'authorization credential',
    pattern: /\bauthorization\s*[:=]\s*(?:bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{6,}/i,
  },
  { label: 'GitHub token', pattern: /\b(?:github_pat_|gh[psuor]_|ghs_)[A-Za-z0-9_]{12,}\b/i },
  { label: 'OpenAI-style key', pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/ },
  { label: 'bot token', pattern: /\bbot[0-9]{6,}:[A-Za-z0-9_-]{6,}\b/ },
  {
    label: 'secret assignment',
    pattern:
      /\b(?:access[_-]?token|installation[_-]?token|token|secret|password|passwd|private[_-]?key|api[_-]?key|client[_-]?secret)\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{10,}/i,
  },
]);

const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const KNOWN_SHA256SUMS_ERR = 'shasum: unpacked: Is a directory\n';

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
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

function isSha256(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function isCommitSha(value) {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

function expectString(label, value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
}

function expectBool(label, value, expected) {
  if (value !== expected) {
    throw new Error(`${label} must be ${expected}`);
  }
}

function expectSha256(label, value) {
  if (!isSha256(value)) {
    throw new Error(`${label} must be 64 lowercase hex`);
  }
}

function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sha256Text(text) {
  return createHash('sha256').update(text).digest('hex');
}

function readUtf8(path) {
  return readFileSync(path, 'utf8');
}

function readJsonFile(path, label) {
  try {
    return JSON.parse(readUtf8(path));
  } catch (err) {
    throw new Error(`${label} must be valid JSON: ${err.message}`);
  }
}

function assertNoUnsafeText(text, patterns, prefix) {
  const raw = String(text ?? '');
  for (const { label, pattern } of patterns) {
    if (pattern.test(raw)) {
      throw new Error(`${prefix} contains unsafe ${label}`);
    }
  }
}

export function assertNoUnsafePrivateVerifierZipResultText(text) {
  assertNoUnsafeText(text, UNSAFE_ENVELOPE_TEXT_PATTERNS, 'private verifier ZIP result');
  return true;
}

function assertRelativePath(path, label) {
  expectString(label, path);
  if (path.startsWith('/') || path.includes('..') || path.includes('\\')) {
    throw new Error(`${label} must be a safe relative path`);
  }
  if (!/^[A-Za-z0-9._/-]+$/.test(path)) {
    throw new Error(`${label} contains unsupported characters`);
  }
}

function resolveInside(root, relativePath, label) {
  assertRelativePath(relativePath, label);
  const rootResolved = resolve(root);
  const target = resolve(rootResolved, relativePath);
  const rootPrefix = rootResolved.endsWith(sep) ? rootResolved : `${rootResolved}${sep}`;
  if (!target.startsWith(rootPrefix)) {
    throw new Error(`${label} resolved outside evidence directory`);
  }
  return target;
}

function assertDirectory(path, label) {
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    throw new Error(`${label} must exist`);
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`${label} must be a real directory`);
  }
}

function assertFile(path, label) {
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    throw new Error(`${label} must exist`);
  }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error(`${label} must be a real file`);
  }
}

function parseSha256Sums(text) {
  const entries = [];
  const lines = text.split(/\r?\n/).filter((line) => line.trim() !== '');
  for (const line of lines) {
    const match = /^([0-9a-f]{64})\s+(.+)$/.exec(line);
    if (!match) {
      throw new Error('SHA256SUMS.txt contains malformed entry');
    }
    const [, sha256, path] = match;
    assertRelativePath(path, 'SHA256SUMS.txt path');
    entries.push({ path, sha256 });
  }
  return entries;
}

function stepById(report, id) {
  return report.evidence.required_steps.find((step) => step.id === id);
}

function assertStepOutputHash(step, unpackedRoot, stepId, suffix, fieldName) {
  const relativePath = `${stepId}.${suffix}`;
  const path = resolveInside(unpackedRoot, relativePath, `${stepId}.${suffix}`);
  assertFile(path, relativePath);
  const bytes = readFileSync(path);
  const digest = sha256Bytes(bytes);
  if (digest !== step[fieldName]) {
    throw new Error(`${relativePath} hash mismatch`);
  }
  assertNoUnsafeText(bytes.toString('utf8'), UNSAFE_EVIDENCE_TEXT_PATTERNS, relativePath);
  return { path: relativePath, sha256: digest, byte_length: bytes.length };
}

function assertNorthStarBoundaryFalse(claimBoundary) {
  const requiredFalse = [
    'public_external_attestation',
    'non_operator_review_proven',
    'production_authority',
    'enterprise_readiness',
    'sovereign_recognition',
    'current_machine_governance',
    'production_downstream_recognition',
    'all_mcp_governance',
    'unrouted_surface_coverage',
  ];
  for (const key of requiredFalse) {
    if (claimBoundary?.[key] !== false) {
      throw new Error(`north-star-readiness claim_boundary.${key} must be false`);
    }
  }
}

function validateJsonOutputs(unpackedRoot) {
  const sourceBridge = readJsonFile(
    resolveInside(unpackedRoot, 'source-bridge-window.out', 'source-bridge-window.out'),
    'source-bridge-window.out',
  );
  if (sourceBridge.report_type !== 'zlar-time-boxed-source-bridge-window-report-v1') {
    throw new Error('source-bridge-window.out report_type mismatch');
  }
  if (
    sourceBridge.authority_status !== 'accepted' ||
    sourceBridge.safe_for_control_tower_use !== true ||
    sourceBridge.can_push_under_window !== true
  ) {
    throw new Error('source-bridge-window.out did not accept the bounded authority sample');
  }
  for (const key of [
    'reads_private_key_material',
    'reads_token_material',
    'mints_credentials',
    'calls_github',
    'reads_remote_refs',
    'pushes_source',
    'changes_configuration',
  ]) {
    if (sourceBridge.no_secret_boundary?.[key] !== false) {
      throw new Error(`source-bridge-window.out no_secret_boundary.${key} must be false`);
    }
  }

  const proofSmoke = readJsonFile(
    resolveInside(unpackedRoot, 'proof-smoke-verify.out', 'proof-smoke-verify.out'),
    'proof-smoke-verify.out',
  );
  if (proofSmoke.verification_type !== 'zlar-proof-smoke-report-verification-v1') {
    throw new Error('proof-smoke-verify.out verification_type mismatch');
  }
  if (proofSmoke.verified !== true) {
    throw new Error('proof-smoke-verify.out must report verified=true');
  }
  if (proofSmoke.evidence_model !== 'committed-local-fixtures') {
    throw new Error('proof-smoke-verify.out evidence_model must be committed-local-fixtures');
  }
  if (proofSmoke.live_probing !== false) {
    throw new Error('proof-smoke-verify.out live_probing must be false');
  }
  expectSha256('proof-smoke-verify.out report_sha256', proofSmoke.report_sha256);

  const readiness = readJsonFile(
    resolveInside(unpackedRoot, 'north-star-readiness.out', 'north-star-readiness.out'),
    'north-star-readiness.out',
  );
  if (readiness.report_type !== 'zlar-north-star-readiness-v1') {
    throw new Error('north-star-readiness.out report_type mismatch');
  }
  if (readiness.result !== 'NOT_READY_FOR_V3_4_0') {
    throw new Error('north-star-readiness.out must preserve NOT_READY_FOR_V3_4_0');
  }
  if (readiness.evidence_model !== 'committed-local-fixtures') {
    throw new Error('north-star-readiness.out evidence_model must be committed-local-fixtures');
  }
  assertNorthStarBoundaryFalse(readiness.claim_boundary || {});

  const privacyText = readUtf8(resolveInside(unpackedRoot, 'public-privacy.out', 'public-privacy.out'));
  if (!privacyText.includes('Results: 59/59 passed')) {
    throw new Error('public-privacy.out must report 59/59 passed');
  }

  return {
    source_bridge_authority_status: sourceBridge.authority_status,
    proof_smoke_verified: proofSmoke.verified,
    proof_smoke_report_sha256: proofSmoke.report_sha256,
    north_star_result: readiness.result,
    public_privacy_passed: true,
  };
}

function recomputeEvidence(report, evidenceDir) {
  const root = resolve(evidenceDir);
  assertDirectory(root, 'evidence directory');
  const zipPath = resolveInside(root, report.evidence.returned_results_zip_name, 'returned_results_zip_name');
  assertFile(zipPath, report.evidence.returned_results_zip_name);
  const returnedZipSha256 = sha256Bytes(readFileSync(zipPath));
  if (returnedZipSha256 !== report.evidence.returned_results_zip_sha256) {
    throw new Error('returned results ZIP hash mismatch');
  }

  const unpackedRoot = resolveInside(root, 'unpacked', 'unpacked');
  assertDirectory(unpackedRoot, 'unpacked evidence directory');
  const names = readdirSync(unpackedRoot).sort();
  const shaText = readUtf8(resolveInside(unpackedRoot, 'SHA256SUMS.txt', 'SHA256SUMS.txt'));
  const entries = parseSha256Sums(shaText);
  if (entries.length !== report.evidence.sha256sums_entry_count) {
    throw new Error('SHA256SUMS.txt entry count mismatch');
  }
  const seen = new Set();
  for (const entry of entries) {
    if (seen.has(entry.path)) {
      throw new Error(`SHA256SUMS.txt duplicate path: ${entry.path}`);
    }
    seen.add(entry.path);
    const artifactPath = resolveInside(unpackedRoot, entry.path, `SHA256SUMS.txt ${entry.path}`);
    assertFile(artifactPath, entry.path);
    const bytes = readFileSync(artifactPath);
    assertNoUnsafeText(bytes.toString('utf8'), UNSAFE_EVIDENCE_TEXT_PATTERNS, entry.path);
    const digest = sha256Bytes(bytes);
    if (digest !== entry.sha256) {
      throw new Error(`SHA256SUMS.txt hash mismatch for ${entry.path}`);
    }
  }
  const allowedUnpackedNames = new Set([...seen, 'SHA256SUMS.txt', 'SHA256SUMS.err']);
  for (const name of names) {
    assertRelativePath(name, 'unpacked evidence entry');
    const entryPath = resolveInside(unpackedRoot, name, `unpacked evidence ${name}`);
    const stat = lstatSync(entryPath);
    if (stat.isSymbolicLink() || !stat.isFile()) {
      throw new Error(`unpacked evidence entry must be a real file: ${name}`);
    }
    if (!allowedUnpackedNames.has(name)) {
      throw new Error(`unpacked evidence contains unlisted file: ${name}`);
    }
  }

  const zipShaText = readUtf8(resolveInside(unpackedRoot, 'zip-sha256.txt', 'zip-sha256.txt'));
  if (!zipShaText.includes(report.evidence.source_snapshot_zip_sha256)) {
    throw new Error('zip-sha256.txt does not contain declared source snapshot ZIP hash');
  }
  if (!zipShaText.includes(report.target.commit_sha)) {
    throw new Error('zip-sha256.txt does not bind to target commit SHA in ZIP name');
  }
  const zipSourceText = readUtf8(resolveInside(unpackedRoot, 'zip-source.txt', 'zip-source.txt'));
  if (!zipSourceText.includes(report.target.commit_sha)) {
    throw new Error('zip-source.txt does not bind to target commit SHA in ZIP name');
  }

  const stepChecks = [];
  for (const stepId of REQUIRED_ZIP_RESULT_STEPS) {
    const step = stepById(report, stepId);
    const exitPath = resolveInside(unpackedRoot, `${stepId}.exit`, `${stepId}.exit`);
    assertFile(exitPath, `${stepId}.exit`);
    const exitText = readUtf8(exitPath).trim();
    if (exitText !== '0') {
      throw new Error(`${stepId}.exit must be 0`);
    }
    if (step.exit_code !== 0) {
      throw new Error(`required_steps.${stepId}.exit_code must be 0`);
    }
    const out = assertStepOutputHash(step, unpackedRoot, stepId, 'out', 'stdout_sha256');
    const err = assertStepOutputHash(step, unpackedRoot, stepId, 'err', 'stderr_sha256');
    if (stepId !== 'node-check-proof-smoke' && err.sha256 !== EMPTY_SHA256) {
      throw new Error(`${stepId}.err must be empty`);
    }
    stepChecks.push({ id: stepId, exit_code: 0, stdout_sha256: out.sha256, stderr_sha256: err.sha256 });
  }

  for (const name of names.filter((entry) => entry.endsWith('.err'))) {
    const path = resolveInside(unpackedRoot, name, name);
    const text = readUtf8(path);
    if (name === 'SHA256SUMS.err') {
      if (text !== KNOWN_SHA256SUMS_ERR) {
        throw new Error('SHA256SUMS.err must contain only the known directory warning');
      }
    } else if (text.length !== 0) {
      throw new Error(`${name} must be empty`);
    }
  }

  const outputSummary = validateJsonOutputs(unpackedRoot);
  return {
    returned_results_zip_sha256: returnedZipSha256,
    source_snapshot_zip_sha256: report.evidence.source_snapshot_zip_sha256,
    sha256sums_entry_count: entries.length,
    sha256sums_entries_matched: entries.length,
    all_sha256sums_entries_matched: true,
    all_required_steps_exit_zero: true,
    only_known_stderr_issue: true,
    required_steps: stepChecks,
    ...outputSummary,
  };
}

export function assertPrivateVerifierZipResult(report) {
  exactKeys('private verifier ZIP result', report, [
    'report_type',
    'schema_version',
    'generated_at',
    'intake_class',
    'target',
    'verifier',
    'custody',
    'evidence',
    'privacy',
    'claim_boundary',
    'non_claims',
  ]);
  if (report.report_type !== PRIVATE_VERIFIER_ZIP_RESULT_TYPE) {
    throw new Error(`report_type must be ${PRIVATE_VERIFIER_ZIP_RESULT_TYPE}`);
  }
  if (report.schema_version !== 1) {
    throw new Error('schema_version must be 1');
  }
  if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(report.generated_at)) {
    throw new Error('generated_at must be an ISO-8601 UTC timestamp without private locale data');
  }
  if (report.intake_class !== 'zip-snapshot-private-verifier-reply') {
    throw new Error('intake_class must be zip-snapshot-private-verifier-reply');
  }

  exactKeys('target', report.target, [
    'repo',
    'expected_commit_sha',
    'commit_sha',
    'source_route',
    'moving_target_used',
  ]);
  if (report.target.repo !== 'ZLAR-AI/ZLAR') {
    throw new Error('target.repo must be ZLAR-AI/ZLAR');
  }
  if (!isCommitSha(report.target.expected_commit_sha) || !isCommitSha(report.target.commit_sha)) {
    throw new Error('target commit fields must be 40-character lowercase hex');
  }
  if (report.target.commit_sha !== report.target.expected_commit_sha) {
    throw new Error('target commit must match expected commit');
  }
  if (report.target.source_route !== PRIVATE_VERIFIER_ZIP_SOURCE_ROUTE) {
    throw new Error(`target.source_route must be ${PRIVATE_VERIFIER_ZIP_SOURCE_ROUTE}`);
  }
  expectBool('target.moving_target_used', report.target.moving_target_used, false);

  exactKeys('verifier', report.verifier, [
    'public_label',
    'relationship_to_zlar',
    'identity_public',
    'contact_public',
  ]);
  if (!/^private-personally-connected-outside-machine-verifier-[0-9]+$/.test(report.verifier.public_label)) {
    throw new Error('verifier.public_label must be pseudonymous for the private personally connected outside-machine verifier');
  }
  if (report.verifier.relationship_to_zlar !== PRIVATE_VERIFIER_ZIP_RELATIONSHIP) {
    throw new Error('verifier.relationship_to_zlar must use the approved private personally connected boundary');
  }
  expectBool('verifier.identity_public', report.verifier.identity_public, false);
  expectBool('verifier.contact_public', report.verifier.contact_public, false);

  exactKeys('custody', report.custody, [
    'source_channel_recorded_privately',
    'received_timestamp_recorded_privately',
    'raw_reply_publicly_committed',
    'private_storage_required',
    'public_repo_material_contains_private_identity',
    'returned_attachment_locally_reviewed',
  ]);
  expectBool('custody.source_channel_recorded_privately', report.custody.source_channel_recorded_privately, true);
  expectBool('custody.received_timestamp_recorded_privately', report.custody.received_timestamp_recorded_privately, true);
  expectBool('custody.raw_reply_publicly_committed', report.custody.raw_reply_publicly_committed, false);
  expectBool('custody.private_storage_required', report.custody.private_storage_required, true);
  expectBool('custody.public_repo_material_contains_private_identity', report.custody.public_repo_material_contains_private_identity, false);
  expectBool('custody.returned_attachment_locally_reviewed', report.custody.returned_attachment_locally_reviewed, true);

  exactKeys('evidence', report.evidence, [
    'evidence_model',
    'returned_results_zip_name',
    'returned_results_zip_sha256',
    'source_snapshot_zip_sha256',
    'sha256sums_entry_count',
    'required_steps',
  ]);
  if (report.evidence.evidence_model !== PRIVATE_VERIFIER_ZIP_EVIDENCE_MODEL) {
    throw new Error(`evidence.evidence_model must be ${PRIVATE_VERIFIER_ZIP_EVIDENCE_MODEL}`);
  }
  assertRelativePath(report.evidence.returned_results_zip_name, 'evidence.returned_results_zip_name');
  expectSha256('evidence.returned_results_zip_sha256', report.evidence.returned_results_zip_sha256);
  expectSha256('evidence.source_snapshot_zip_sha256', report.evidence.source_snapshot_zip_sha256);
  if (!Number.isInteger(report.evidence.sha256sums_entry_count) || report.evidence.sha256sums_entry_count <= 0) {
    throw new Error('evidence.sha256sums_entry_count must be a positive integer');
  }
  if (!Array.isArray(report.evidence.required_steps) || report.evidence.required_steps.length !== REQUIRED_ZIP_RESULT_STEPS.length) {
    throw new Error('evidence.required_steps must contain exactly the required verifier steps');
  }
  const stepIds = report.evidence.required_steps.map((step) => step.id);
  if (JSON.stringify(stepIds) !== JSON.stringify(REQUIRED_ZIP_RESULT_STEPS)) {
    throw new Error('evidence.required_steps must preserve the required step order');
  }
  for (const step of report.evidence.required_steps) {
    exactKeys(`required_steps.${step.id}`, step, ['id', 'exit_code', 'stdout_sha256', 'stderr_sha256']);
    if (!REQUIRED_ZIP_RESULT_STEPS.includes(step.id)) {
      throw new Error(`unknown required step: ${step.id}`);
    }
    if (step.exit_code !== 0) {
      throw new Error(`${step.id}.exit_code must be 0`);
    }
    expectSha256(`${step.id}.stdout_sha256`, step.stdout_sha256);
    expectSha256(`${step.id}.stderr_sha256`, step.stderr_sha256);
  }

  exactKeys('privacy', report.privacy, [
    'private_by_default',
    'public_attribution_approved',
    'public_external_attestation_approved',
    'verifier_identity_public',
    'verifier_contact_public',
    'private_contact_included',
    'private_paths_included',
    'credentials_included',
  ]);
  expectBool('privacy.private_by_default', report.privacy.private_by_default, true);
  for (const key of PRIVACY_FALSE_KEYS) {
    expectBool(`privacy.${key}`, report.privacy[key], false);
  }

  exactKeys('claim_boundary', report.claim_boundary, [
    'private_intake_only',
    'private_personally_connected_outside_machine_signal',
    'artifact_custody_reviewed',
    ...CLAIM_BOUNDARY_FALSE_KEYS,
  ]);
  expectBool('claim_boundary.private_intake_only', report.claim_boundary.private_intake_only, true);
  expectBool(
    'claim_boundary.private_personally_connected_outside_machine_signal',
    report.claim_boundary.private_personally_connected_outside_machine_signal,
    true,
  );
  expectBool('claim_boundary.artifact_custody_reviewed', report.claim_boundary.artifact_custody_reviewed, true);
  for (const key of CLAIM_BOUNDARY_FALSE_KEYS) {
    expectBool(`claim_boundary.${key}`, report.claim_boundary[key], false);
  }

  if (!Array.isArray(report.non_claims) || report.non_claims.length < PRIVATE_VERIFIER_ZIP_NON_CLAIMS.length) {
    throw new Error('non_claims must preserve private verifier ZIP result non-claims');
  }
  const nonClaimText = report.non_claims.join('\n');
  for (const fragment of REQUIRED_NON_CLAIM_FRAGMENTS) {
    if (!nonClaimText.includes(fragment)) {
      throw new Error(`non_claims missing required fragment: ${fragment}`);
    }
  }

  assertNoUnsafePrivateVerifierZipResultText(JSON.stringify(report));
  return true;
}

export function buildPrivateVerifierZipResultVerification(report, options = {}) {
  assertPrivateVerifierZipResult(report);
  const resultText = options.resultText || `${JSON.stringify(report)}\n`;
  const resultSha256 = sha256Text(resultText);

  if (options.requireTarget) {
    const expected = `${report.target.repo}@${report.target.commit_sha}`;
    if (options.requireTarget !== expected) {
      throw new Error(`target mismatch: expected ${options.requireTarget}, got ${expected}`);
    }
  }
  if (options.requireReturnedZipSha && options.requireReturnedZipSha !== report.evidence.returned_results_zip_sha256) {
    throw new Error('returned results ZIP SHA requirement mismatch');
  }
  if (options.requireSourceZipSha && options.requireSourceZipSha !== report.evidence.source_snapshot_zip_sha256) {
    throw new Error('source snapshot ZIP SHA requirement mismatch');
  }
  if (options.requireRecomputedEvidence && !options.evidenceDir) {
    throw new Error('--require-recomputed-evidence requires --evidence-dir');
  }

  const recomputed = options.evidenceDir ? recomputeEvidence(report, options.evidenceDir) : null;

  const verification = {
    verification_type: PRIVATE_VERIFIER_ZIP_RESULT_VERIFICATION_TYPE,
    verified: true,
    report_type: report.report_type,
    report_sha256: resultSha256,
    target: {
      repo: report.target.repo,
      commit_sha: report.target.commit_sha,
      source_route: report.target.source_route,
      moving_target_used: false,
    },
    relationship_label: 'private personally connected outside-machine verifier signal',
    evidence_model: report.evidence.evidence_model,
    recomputed_evidence: Boolean(recomputed),
    returned_results_zip_sha256: report.evidence.returned_results_zip_sha256,
    source_snapshot_zip_sha256: report.evidence.source_snapshot_zip_sha256,
    sha256sums_entry_count: recomputed?.sha256sums_entry_count ?? report.evidence.sha256sums_entry_count,
    all_sha256sums_entries_matched: recomputed?.all_sha256sums_entries_matched ?? null,
    all_required_steps_exit_zero: recomputed?.all_required_steps_exit_zero ?? true,
    only_known_stderr_issue: recomputed?.only_known_stderr_issue ?? null,
    proof_smoke_verified: recomputed?.proof_smoke_verified ?? null,
    proof_smoke_report_sha256: recomputed?.proof_smoke_report_sha256 ?? null,
    north_star_result: recomputed?.north_star_result ?? null,
    public_privacy_passed: recomputed?.public_privacy_passed ?? null,
    allowed_claim: {
      private_personally_connected_outside_machine_signal: true,
      locally_reviewed_returned_result_custody: Boolean(recomputed),
    },
    claim_boundary: {
      ...report.claim_boundary,
    },
    forbidden_claims: [
      'public external attestation',
      'independent review',
      'arm\'s-length review',
      'public attribution',
      'git clone source access',
      'source-transport credential proof',
      'tag or release proof',
      'website/public alignment',
      'production trust',
      'current-machine governance',
      'all-surface governance',
      'North Star readiness',
      'side-door closure',
      'absolute human intention',
    ],
  };

  assertNoUnsafePrivateVerifierZipResultText(JSON.stringify(verification));
  return verification;
}

export function formatPrivateVerifierZipResultVerification(verification) {
  const lines = [
    'ZLAR Private Verifier ZIP Result Verification',
    `verified=${verification.verified}`,
    `target=${verification.target.repo}@${verification.target.commit_sha}`,
    `source_route=${verification.target.source_route}`,
    `relationship_label=${verification.relationship_label}`,
    `evidence_model=${verification.evidence_model}`,
    `recomputed_evidence=${verification.recomputed_evidence}`,
    `returned_results_zip_sha256=${verification.returned_results_zip_sha256}`,
    `source_snapshot_zip_sha256=${verification.source_snapshot_zip_sha256}`,
    `sha256sums_entry_count=${verification.sha256sums_entry_count}`,
    `all_sha256sums_entries_matched=${verification.all_sha256sums_entries_matched}`,
    `all_required_steps_exit_zero=${verification.all_required_steps_exit_zero}`,
    `only_known_stderr_issue=${verification.only_known_stderr_issue}`,
    `proof_smoke_verified=${verification.proof_smoke_verified}`,
    `proof_smoke_report_sha256=${verification.proof_smoke_report_sha256}`,
    `north_star_result=${verification.north_star_result}`,
    `public_privacy_passed=${verification.public_privacy_passed}`,
    '',
    'Allowed claim:',
    '- private personally connected outside-machine verifier signal',
  ];
  if (verification.allowed_claim.locally_reviewed_returned_result_custody) {
    lines.push('- locally reviewed returned-result custody');
  }
  lines.push('', 'Forbidden claims:');
  for (const claim of verification.forbidden_claims) {
    lines.push(`- ${claim}`);
  }
  return `${lines.join('\n')}\n`;
}
