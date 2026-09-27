import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { basename, join, resolve, sep } from 'node:path';
import { canonicalize } from './canonicalize.mjs';
import {
  ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_REPORT_FILE,
  ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SOURCE_BINDING_FILE,
  PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_REPORT_TYPE,
  PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SOURCE_BINDING_TYPE,
  PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_RUNNER_RESULT_TYPE,
  buildActivePersistentProfileLifecycleReport,
} from './protected-records-active-persistent-profile-lifecycle.mjs';

export const PRIVATE_VERIFIER_READINESS_PACKET_TYPE =
  'zlar-private-verifier-readiness-packet-v1';
export const PRIVATE_VERIFIER_READINESS_VERIFICATION_TYPE =
  'zlar-private-verifier-readiness-verification-v1';
export const PRIVATE_VERIFIER_READINESS_PACKET_FILE =
  'zlar-private-verifier-readiness-packet-v1.json';
export const PRIVATE_VERIFIER_READINESS_README_FILE =
  'PRIVATE-VERIFIER-README.md';
export const PRIVATE_VERIFIER_READINESS_SHA256SUMS_FILE = 'SHA256SUMS';

export const PRIVATE_VERIFIER_READINESS_NON_CLAIMS = Object.freeze([
  'This packet proves only private verifier readiness for a bounded local evidence bundle.',
  'This packet does not contact a verifier, send a request, create external attestation, or create public attribution.',
  'This packet does not prove production authority, production deployment, enterprise readiness, sovereign recognition, key custody, revocation truth, side-door closure, all-surface governance, or general current-machine governance.',
  'This packet does not authorize publication, a tag, a release, a website update, GitHub access changes, production config, secrets, or real personal, business, or customer records.',
]);

const REQUIRED_NON_CLAIM_FRAGMENTS = Object.freeze([
  'private verifier readiness',
  'does not contact a verifier',
  'external attestation',
  'public attribution',
  'production authority',
  'enterprise readiness',
  'key custody',
  'general current-machine governance',
]);

const REQUIRED_EVIDENCE_FILES = Object.freeze([
  'active-persistent-closeout-refusal-report.json',
  'active-persistent-green-action-crossing-report.json',
  'active-persistent-live-installation-report.json',
  'active-persistent-red-path-refusal-report.json',
  ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_REPORT_FILE,
  ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SOURCE_BINDING_FILE,
  'north-star-readiness.json',
  'post-lifecycle-status.json',
  'pre-replacement-status.json',
  'runner-result.json',
]);

const CLAIM_CEILING_FALSE_KEYS = Object.freeze([
  'public_external_attestation',
  'actual_non_operator_review',
  'public_attribution',
  'production_authority',
  'production_deployment',
  'enterprise_readiness',
  'general_current_machine_governance',
  'all_surface_governance',
  'key_custody',
  'revocation_truth',
  'side_door_closure',
]);

const LATER_AUTHORITY_KEYS = Object.freeze([
  'actual_external_contact',
  'verifier_identity_or_contact',
  'source_access_or_packet_delivery',
  'public_disclosure_or_attribution',
  'production_deployment',
  'tag_or_release',
  'website_or_public_artifact',
  'github_access_change',
  'enterprise_readiness_claim',
]);

const UNSAFE_TEXT_PATTERNS = Object.freeze([
  { label: 'private operator path', pattern: /\/Users\/[^\s"'`]+/ },
  { label: 'home path', pattern: /\/home\/[^\s"'`]+/ },
  { label: 'private path', pattern: /\/private\/[^\s"'`]+/ },
  { label: 'temp path', pattern: /\/tmp\/[^\s"'`]+/ },
  { label: 'var path', pattern: /\/var\/[^\s"'`]+/ },
  { label: 'email address', pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i },
  { label: 'chat id field', pattern: /\bchat_id\b/i },
  { label: 'human id field', pattern: /\bhuman:[0-9]/i },
  { label: 'private key material', pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
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

function requireBool(label, actual) {
  if (typeof actual !== 'boolean') {
    throw new Error(`${label} must be boolean`);
  }
}

function requireString(label, value) {
  if (typeof value !== 'string' || value.length < 1) {
    throw new Error(`${label} must be a non-empty string`);
  }
  assertNoUnsafePrivateVerifierReadinessText(value);
  return value;
}

function requirePathArg(label, value) {
  if (typeof value !== 'string' || value.length < 1) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function requireSafeLabel(label, value) {
  requireString(label, value);
  if (
    value !== basename(value) ||
    value.includes('/') ||
    value.includes('\\') ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{2,160}$/.test(value)
  ) {
    throw new Error(`${label} must be a public-safe basename label`);
  }
  return value;
}

function requireCommit(label, value) {
  requireString(label, value);
  if (!/^[a-f0-9]{40}$/.test(value)) {
    throw new Error(`${label} must be a 40-character lowercase git commit SHA`);
  }
  return value;
}

function requireSha(label, value) {
  requireString(label, value);
  if (!/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`${label} must be a SHA-256 hex string`);
  }
  return value;
}

function requireArray(label, value) {
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  return value;
}

function requireIso(label, value) {
  requireString(label, value);
  if (!Number.isFinite(Date.parse(value))) {
    throw new Error(`${label} must be an ISO-8601 timestamp`);
  }
  return value;
}

function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sha256Text(text) {
  return sha256Bytes(Buffer.from(text, 'utf8'));
}

function sha256Canonical(value) {
  return sha256Text(canonicalize(value));
}

function readJsonBytes(path, label) {
  let bytes;
  try {
    bytes = readFileSync(path);
  } catch {
    throw new Error(`${label} could not be read`);
  }
  try {
    return {
      json: JSON.parse(bytes.toString('utf8')),
      sha256: sha256Bytes(bytes),
      bytes: bytes.length,
    };
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

function readText(path, label) {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    throw new Error(`${label} could not be read`);
  }
}

function resolveInside(root, file) {
  const resolvedRoot = resolve(root);
  const resolved = resolve(resolvedRoot, file);
  if (resolved !== resolvedRoot && !resolved.startsWith(`${resolvedRoot}${sep}`)) {
    throw new Error('private verifier readiness evidence file escaped evidence directory');
  }
  return resolved;
}

function collectEvidenceArtifacts(evidenceDir) {
  const dir = resolve(evidenceDir);
  if (!existsSync(dir)) {
    throw new Error('private verifier readiness evidence directory is missing');
  }
  const dirStat = lstatSync(dir);
  if (!dirStat.isDirectory() || dirStat.isSymbolicLink()) {
    throw new Error('private verifier readiness evidence directory must be a real directory');
  }
  const entries = readdirSync(dir)
    .filter((name) => !name.startsWith('.'))
    .sort();
  const artifacts = [];
  for (const name of entries) {
    requireSafeLabel('private verifier readiness evidence artifact name', name);
    const path = resolveInside(dir, name);
    const fileStat = lstatSync(path);
    if (fileStat.isSymbolicLink()) {
      throw new Error('private verifier readiness evidence artifacts must not be symlinks');
    }
    if (!statSync(path).isFile()) {
      continue;
    }
    const bytes = readFileSync(path);
    artifacts.push({
      path: name,
      sha256: sha256Bytes(bytes),
      bytes: bytes.length,
    });
  }
  for (const required of REQUIRED_EVIDENCE_FILES) {
    if (!artifacts.some((entry) => entry.path === required)) {
      throw new Error(`private verifier readiness evidence missing required artifact: ${required}`);
    }
  }
  return artifacts;
}

function artifactSetSha256(artifactHashes) {
  return sha256Text(
    artifactHashes
      .map((entry) => `${entry.path}\0${entry.sha256}\n`)
      .sort()
      .join('')
  );
}

function artifactSha(artifactHashes, path) {
  const found = artifactHashes.find((entry) => entry.path === path);
  if (!found) {
    throw new Error(`private verifier readiness artifact hash missing: ${path}`);
  }
  return found.sha256;
}

function readEvidenceContracts(evidenceDir, artifactHashes) {
  const dir = resolve(evidenceDir);
  const lifecycleRead = readJsonBytes(
    resolveInside(dir, ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_REPORT_FILE),
    'private verifier readiness lifecycle report'
  );
  const bindingRead = readJsonBytes(
    resolveInside(dir, ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SOURCE_BINDING_FILE),
    'private verifier readiness lifecycle source binding'
  );
  const runnerRead = readJsonBytes(
    resolveInside(dir, 'runner-result.json'),
    'private verifier readiness runner result'
  );
  const readinessRead = readJsonBytes(
    resolveInside(dir, 'north-star-readiness.json'),
    'private verifier readiness North Star readiness report'
  );

  const binding = bindingRead.json;
  exactKeys('private verifier readiness lifecycle source binding', binding, [
    'current_installation',
    'evidence_class',
    'lifecycle_report_file',
    'lifecycle_report_sha256',
    'non_scoring',
    'product_proof_path_completion',
    'production_downstream_recognition',
    'report_type',
    'schema_version',
    'source_reports',
  ]);
  requireExact('private verifier readiness lifecycle source binding type',
    PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_SOURCE_BINDING_TYPE,
    binding.report_type);
  requireExact('private verifier readiness lifecycle source binding schema', 1, binding.schema_version);
  requireExact('private verifier readiness lifecycle evidence class',
    'historical_supplied_local_active_persistent_profile_lifecycle',
    binding.evidence_class);
  requireExact('private verifier readiness lifecycle report file',
    ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_REPORT_FILE,
    binding.lifecycle_report_file);
  requireTrue('private verifier readiness lifecycle non_scoring', binding.non_scoring);
  requireFalse('private verifier readiness lifecycle current_installation', binding.current_installation);
  requireFalse('private verifier readiness lifecycle product_proof_path_completion',
    binding.product_proof_path_completion);
  requireFalse('private verifier readiness lifecycle production_downstream_recognition',
    binding.production_downstream_recognition);
  requireSha('private verifier readiness lifecycle report SHA', binding.lifecycle_report_sha256);
  if (binding.lifecycle_report_sha256 !== lifecycleRead.sha256) {
    throw new Error('private verifier readiness lifecycle source binding hash mismatch');
  }

  exactKeys('private verifier readiness lifecycle source reports', binding.source_reports, [
    'closeout_report',
    'green_report',
    'install_report',
    'red_report',
  ]);
  const sourceReportHashes = {};
  const sourceReportLabels = {};
  const sourceReports = {};
  const sourceMap = {
    install_report: 'install_report_sha256',
    green_report: 'green_report_sha256',
    red_report: 'red_report_sha256',
    closeout_report: 'closeout_report_sha256',
  };
  for (const [key, hashKey] of Object.entries(sourceMap)) {
    const entry = binding.source_reports[key];
    exactKeys(`private verifier readiness lifecycle ${key}`, entry, ['file', 'sha256']);
    requireSafeLabel(`private verifier readiness lifecycle ${key} file`, entry.file);
    requireSha(`private verifier readiness lifecycle ${key} SHA`, entry.sha256);
    if (artifactSha(artifactHashes, entry.file) !== entry.sha256) {
      throw new Error(`private verifier readiness lifecycle ${key} artifact hash mismatch`);
    }
    const read = readJsonBytes(resolveInside(dir, entry.file), `private verifier readiness lifecycle ${key}`);
    sourceReports[key] = read.json;
    sourceReportLabels[key] = entry.file;
    sourceReportHashes[hashKey] = entry.sha256;
  }

  const rebuiltLifecycle = buildActivePersistentProfileLifecycleReport({
    installReport: sourceReports.install_report,
    greenReport: sourceReports.green_report,
    redReport: sourceReports.red_report,
    closeoutReport: sourceReports.closeout_report,
    inputReportHashes: sourceReportHashes,
    inputReportLabels: sourceReportLabels,
    expectedInputReportHashesBound: true,
    generatedAt: lifecycleRead.json.generated_at,
  });
  if (canonicalize(rebuiltLifecycle) !== canonicalize(lifecycleRead.json)) {
    throw new Error('private verifier readiness lifecycle report does not rebuild from source reports');
  }

  const lifecycle = lifecycleRead.json;
  requireExact('private verifier readiness lifecycle report type',
    PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_REPORT_TYPE,
    lifecycle.report_type);
  requireExact('private verifier readiness lifecycle result', 'pass', lifecycle.result);
  requireTrue('private verifier readiness expected input hashes bound',
    lifecycle.claim_boundary.expected_input_report_hashes_bound);
  requireFalse('private verifier readiness lifecycle public external attestation',
    lifecycle.claim_boundary.public_external_attestation);
  requireFalse('private verifier readiness lifecycle enterprise readiness',
    lifecycle.claim_boundary.enterprise_readiness);
  requireFalse('private verifier readiness lifecycle production downstream recognition',
    lifecycle.claim_boundary.production_downstream_recognition);
  requireFalse('private verifier readiness lifecycle current machine governance general',
    lifecycle.claim_boundary.current_machine_governance_general);

  const runner = runnerRead.json;
  requireExact('private verifier readiness runner result type',
    PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIFECYCLE_RUNNER_RESULT_TYPE,
    runner.report_type);
  requireExact('private verifier readiness runner result', 'pass', runner.result);
  requireTrue('private verifier readiness runner named live root', runner.named_live_root);
  requireBool('private verifier readiness runner closed-root replacement authorized',
    runner.closed_root_replacement_authorized);
  requireFalse('private verifier readiness post-closeout write target',
    runner.proof_targets.post_closeout_records_write.written);
  requireFalse('private verifier readiness runner public external attestation',
    runner.claim_boundary.public_external_attestation);
  requireFalse('private verifier readiness runner enterprise readiness',
    runner.claim_boundary.enterprise_readiness);
  requireFalse('private verifier readiness runner production authority',
    runner.claim_boundary.production_authority);
  requireFalse('private verifier readiness runner current machine governance general',
    runner.claim_boundary.current_machine_governance_general);

  const readiness = readinessRead.json;
  requireExact('private verifier readiness North Star report type',
    'zlar-north-star-readiness-v1',
    readiness.report_type);
  requireExact('private verifier readiness North Star result',
    'NOT_READY_FOR_V3_4_0',
    readiness.result);
  requireTrue('private verifier readiness lifecycle provided',
    readiness.counts.historical_active_persistent_profile_lifecycle_provided);
  requireTrue('private verifier readiness lifecycle verified',
    readiness.counts.historical_active_persistent_profile_lifecycle_verified);
  requireTrue('private verifier readiness lifecycle expected hashes bound',
    readiness.counts.historical_active_persistent_profile_lifecycle_expected_hashes_bound);
  requireTrue('private verifier readiness lifecycle non-scoring',
    readiness.counts.historical_active_persistent_profile_lifecycle_non_scoring);
  requireFalse('private verifier readiness lifecycle current installation',
    readiness.counts.historical_active_persistent_profile_lifecycle_current_installation);
  requireFalse('private verifier readiness lifecycle Product Proof completion',
    readiness.counts.historical_active_persistent_profile_lifecycle_product_proof_path_completion);
  requireFalse('private verifier readiness lifecycle Enterprise Profile completion',
    readiness.counts.historical_active_persistent_profile_lifecycle_enterprise_deployment_profile_completion);
  requireFalse('private verifier readiness lifecycle current-machine general',
    readiness.counts.historical_active_persistent_profile_lifecycle_current_machine_governance_general);
  requireFalse('private verifier readiness lifecycle production recognition',
    readiness.counts.historical_active_persistent_profile_lifecycle_production_downstream_recognition);
  requireFalse('private verifier readiness claim public external attestation',
    readiness.claim_boundary.public_external_attestation);
  requireFalse('private verifier readiness claim production authority',
    readiness.claim_boundary.production_authority);
  requireFalse('private verifier readiness claim enterprise readiness',
    readiness.claim_boundary.enterprise_readiness);
  requireFalse('private verifier readiness claim current machine governance',
    readiness.claim_boundary.current_machine_governance);

  return {
    lifecycleRead,
    bindingRead,
    runnerRead,
    readinessRead,
  };
}

function buildCommandTemplates({ commit, evidenceSourceCommit, artifactSetSha256: setSha }) {
  return [
    `git checkout ${commit}`,
    'bin/zlar protected-records-active-persistent-profile-lifecycle --install-report <evidence-dir>/active-persistent-live-installation-report.json --green-report <evidence-dir>/active-persistent-green-action-crossing-report.json --red-report <evidence-dir>/active-persistent-red-path-refusal-report.json --closeout-report <evidence-dir>/active-persistent-closeout-refusal-report.json --expected-install-report-sha256 <install-report-sha256> --expected-green-report-sha256 <green-report-sha256> --expected-red-report-sha256 <red-report-sha256> --expected-closeout-report-sha256 <closeout-report-sha256> --json',
    'bin/zlar north-star-readiness --evidence-dir <evidence-dir> --json',
    `bin/zlar private-verifier-readiness verify --input ${PRIVATE_VERIFIER_READINESS_PACKET_FILE} --evidence-dir <evidence-dir> --require-commit ${commit} --require-evidence-source-commit ${evidenceSourceCommit} --require-artifact-set-sha ${setSha} --require-recomputed-evidence --json`,
  ];
}

export function buildPrivateVerifierReadinessPacket({
  evidenceDir,
  commit,
  evidenceSourceCommit,
  branch,
  repo = 'ZLAR-AI/ZLAR',
  generatedAt = new Date().toISOString(),
} = {}) {
  requirePathArg('private verifier readiness evidenceDir', evidenceDir);
  requireCommit('private verifier readiness commit', commit);
  requireCommit('private verifier readiness evidence source commit', evidenceSourceCommit);
  requireString('private verifier readiness branch', branch);
  requireString('private verifier readiness repo', repo);
  requireIso('private verifier readiness generatedAt', generatedAt);

  const evidenceDirLabel = requireSafeLabel(
    'private verifier readiness evidence directory label',
    basename(resolve(evidenceDir))
  );
  const artifactHashes = collectEvidenceArtifacts(evidenceDir);
  const setSha = artifactSetSha256(artifactHashes);
  const contracts = readEvidenceContracts(evidenceDir, artifactHashes);
  const lifecycle = contracts.lifecycleRead.json;
  const readiness = contracts.readinessRead.json;
  const runner = contracts.runnerRead.json;

  const packet = {
    report_type: PRIVATE_VERIFIER_READINESS_PACKET_TYPE,
    schema_version: 1,
    generated_at: generatedAt,
    readiness_class: 'local_private_verifier_readiness_no_contact',
    target: {
      repo,
      branch,
      commit_sha: commit,
      source_access_path: 'future_authorized_private_source_checkout_or_archive',
      moving_target_used: false,
      tag_or_release: false,
      public_release: false,
    },
    evidence: {
      evidence_model: 'local_private_active_persistent_lifecycle_hash_manifest',
      evidence_dir_label: evidenceDirLabel,
      source_commit_sha: evidenceSourceCommit,
      artifact_count: artifactHashes.length,
      artifact_hashes: artifactHashes,
      artifact_set_sha256: setSha,
      required_artifacts: [...REQUIRED_EVIDENCE_FILES],
      lifecycle: {
        lifecycle_report_sha256: contracts.lifecycleRead.sha256,
        source_binding_sha256: contracts.bindingRead.sha256,
        runner_result_sha256: contracts.runnerRead.sha256,
        result: lifecycle.result,
        action_class: lifecycle.lifecycle.green_action_class,
        runtime_profile_id: lifecycle.selected_profile.runtime_profile_id,
        runtime_profile_sha256: lifecycle.selected_profile.runtime_profile_sha256,
        expected_input_report_hashes_bound:
          lifecycle.claim_boundary.expected_input_report_hashes_bound,
        green_recognized_write_delta: lifecycle.lifecycle.green_recognized_write_delta,
        red_refusal_case_count: lifecycle.lifecycle.red_refusal_case_count,
        closed_root_replacement_authorized: runner.closed_root_replacement_authorized,
        post_closeout_target_written: runner.proof_targets.post_closeout_records_write.written,
        closeout_status: lifecycle.lifecycle.closeout_status,
        current_machine_governance_general:
          lifecycle.claim_boundary.current_machine_governance_general,
        production_downstream_recognition:
          lifecycle.claim_boundary.production_downstream_recognition,
        public_external_attestation: lifecycle.claim_boundary.public_external_attestation,
        enterprise_readiness: lifecycle.claim_boundary.enterprise_readiness,
      },
      readiness: {
        readiness_report_sha256: contracts.readinessRead.sha256,
        result: readiness.result,
        lifecycle_provided:
          readiness.counts.historical_active_persistent_profile_lifecycle_provided,
        lifecycle_verified:
          readiness.counts.historical_active_persistent_profile_lifecycle_verified,
        lifecycle_expected_hashes_bound:
          readiness.counts.historical_active_persistent_profile_lifecycle_expected_hashes_bound,
        lifecycle_non_scoring:
          readiness.counts.historical_active_persistent_profile_lifecycle_non_scoring,
        lifecycle_current_installation:
          readiness.counts.historical_active_persistent_profile_lifecycle_current_installation,
        lifecycle_product_proof_path_completion:
          readiness.counts.historical_active_persistent_profile_lifecycle_product_proof_path_completion,
        lifecycle_enterprise_deployment_profile_completion:
          readiness.counts.historical_active_persistent_profile_lifecycle_enterprise_deployment_profile_completion,
        lifecycle_current_machine_governance_general:
          readiness.counts.historical_active_persistent_profile_lifecycle_current_machine_governance_general,
        lifecycle_production_downstream_recognition:
          readiness.counts.historical_active_persistent_profile_lifecycle_production_downstream_recognition,
        claim_current_machine_governance: readiness.claim_boundary.current_machine_governance,
        claim_public_external_attestation: readiness.claim_boundary.public_external_attestation,
        claim_production_authority: readiness.claim_boundary.production_authority,
        claim_enterprise_readiness: readiness.claim_boundary.enterprise_readiness,
      },
    },
    verifier_instructions: {
      access_model: 'future_authorized_private_source_and_evidence_bundle_only',
      command_templates: buildCommandTemplates({
        commit,
        evidenceSourceCommit,
        artifactSetSha256: setSha,
      }),
      expected_pass_criteria: [
        'The verifier checks out the exact verifier source commit SHA named in target.commit_sha.',
        'The supplied lifecycle evidence remains bound to evidence.source_commit_sha.',
        'The packet verifier recomputes the evidence artifact set SHA-256 from the supplied private evidence bundle.',
        'The lifecycle verifier rebuilds the lifecycle report from the four source reports with expected hashes bound.',
        'North Star readiness consumes the lifecycle as historical, local, supplied, and non-scoring evidence.',
        'All public, production, enterprise, key-custody, side-door-closure, and general current-machine governance claim flags remain false.',
      ],
      expected_fail_criteria: [
        'Any moving target such as latest, main, master, HEAD, or an unpinned branch is used as verifier target.',
        'Any required evidence artifact is missing, renamed, symlinked, or hash-mismatched.',
        'Any lifecycle source report cannot rebuild the lifecycle report.',
        'Any claim flag flips toward public attestation, production authority, enterprise readiness, or general current-machine governance.',
        'Any private path, credential, token, email, private key material, or public attribution appears in the packet.',
      ],
    },
    claim_ceiling: {
      private_verifier_readiness: true,
      local_active_persistent_lifecycle_verified: true,
      public_external_attestation: false,
      actual_non_operator_review: false,
      public_attribution: false,
      production_authority: false,
      production_deployment: false,
      enterprise_readiness: false,
      general_current_machine_governance: false,
      all_surface_governance: false,
      key_custody: false,
      revocation_truth: false,
      side_door_closure: false,
    },
    stop_boundaries: [
      'external verifier contact or request sending',
      'email send, reply, forward, or draft',
      'GitHub access, collaborator, invite, or settings changes',
      'tag, GitHub Release, website, public artifact, or public claim movement',
      'production deployment, service activation, install/config, secrets, keys, HMAC, Telegram, YubiKey, or real records',
      'any claim stronger than private verifier readiness',
    ],
    side_doors: [
      'No external verifier has received or inspected this packet.',
      'The packet does not prove general current-machine governance or always-on live service governance.',
      'Raw Codex, shell, browser, Computer Use, MCP, network, and all-surface governance remain unproven.',
      'Production downstream recognition, production authority, key custody, revocation truth, enterprise readiness, and public attestation remain unproven.',
    ],
    later_authority_required: {
      actual_external_contact: true,
      verifier_identity_or_contact: true,
      source_access_or_packet_delivery: true,
      public_disclosure_or_attribution: true,
      production_deployment: true,
      tag_or_release: true,
      website_or_public_artifact: true,
      github_access_change: true,
      enterprise_readiness_claim: true,
    },
    non_claims: [...PRIVATE_VERIFIER_READINESS_NON_CLAIMS],
  };
  assertPrivateVerifierReadinessPacket(packet);
  return packet;
}

export function assertNoUnsafePrivateVerifierReadinessText(text) {
  for (const { label, pattern } of UNSAFE_TEXT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`private verifier readiness text contains unsafe ${label}`);
    }
  }
}

function assertArtifactEntry(entry) {
  exactKeys('private verifier readiness artifact hash entry', entry, [
    'bytes',
    'path',
    'sha256',
  ]);
  requireSafeLabel('private verifier readiness artifact path', entry.path);
  requireSha('private verifier readiness artifact sha256', entry.sha256);
  if (!Number.isInteger(entry.bytes) || entry.bytes < 0) {
    throw new Error('private verifier readiness artifact bytes must be a non-negative integer');
  }
}

export function assertPrivateVerifierReadinessPacket(packet) {
  exactKeys('private verifier readiness packet', packet, [
    'claim_ceiling',
    'evidence',
    'generated_at',
    'later_authority_required',
    'non_claims',
    'readiness_class',
    'report_type',
    'schema_version',
    'side_doors',
    'stop_boundaries',
    'target',
    'verifier_instructions',
  ]);
  requireExact('private verifier readiness report type',
    PRIVATE_VERIFIER_READINESS_PACKET_TYPE,
    packet.report_type);
  requireExact('private verifier readiness schema version', 1, packet.schema_version);
  requireIso('private verifier readiness generated_at', packet.generated_at);
  requireExact('private verifier readiness class',
    'local_private_verifier_readiness_no_contact',
    packet.readiness_class);

  exactKeys('private verifier readiness target', packet.target, [
    'branch',
    'commit_sha',
    'moving_target_used',
    'public_release',
    'repo',
    'source_access_path',
    'tag_or_release',
  ]);
  requireString('private verifier readiness target repo', packet.target.repo);
  requireString('private verifier readiness target branch', packet.target.branch);
  requireCommit('private verifier readiness target commit', packet.target.commit_sha);
  requireExact('private verifier readiness source access path',
    'future_authorized_private_source_checkout_or_archive',
    packet.target.source_access_path);
  requireFalse('private verifier readiness moving target used', packet.target.moving_target_used);
  requireFalse('private verifier readiness tag or release', packet.target.tag_or_release);
  requireFalse('private verifier readiness public release', packet.target.public_release);

  exactKeys('private verifier readiness evidence', packet.evidence, [
    'artifact_count',
    'artifact_hashes',
    'artifact_set_sha256',
    'evidence_dir_label',
    'evidence_model',
    'lifecycle',
    'readiness',
    'required_artifacts',
    'source_commit_sha',
  ]);
  requireExact('private verifier readiness evidence model',
    'local_private_active_persistent_lifecycle_hash_manifest',
    packet.evidence.evidence_model);
  requireSafeLabel('private verifier readiness evidence directory label',
    packet.evidence.evidence_dir_label);
  requireCommit('private verifier readiness evidence source commit',
    packet.evidence.source_commit_sha);
  requireSha('private verifier readiness artifact set SHA-256',
    packet.evidence.artifact_set_sha256);
  const artifacts = requireArray('private verifier readiness artifact hashes',
    packet.evidence.artifact_hashes);
  if (artifacts.length !== packet.evidence.artifact_count) {
    throw new Error('private verifier readiness artifact count mismatch');
  }
  const seen = new Set();
  for (const entry of artifacts) {
    assertArtifactEntry(entry);
    if (seen.has(entry.path)) {
      throw new Error('private verifier readiness artifact hash path duplicated');
    }
    seen.add(entry.path);
  }
  const recomputedSetSha = artifactSetSha256(artifacts);
  if (recomputedSetSha !== packet.evidence.artifact_set_sha256) {
    throw new Error('private verifier readiness artifact set SHA-256 mismatch');
  }
  const requiredArtifacts = requireArray('private verifier readiness required artifacts',
    packet.evidence.required_artifacts);
  for (const required of REQUIRED_EVIDENCE_FILES) {
    if (!requiredArtifacts.includes(required)) {
      throw new Error(`private verifier readiness required artifact omitted: ${required}`);
    }
    if (!seen.has(required)) {
      throw new Error(`private verifier readiness required artifact not hashed: ${required}`);
    }
  }

  exactKeys('private verifier readiness lifecycle summary', packet.evidence.lifecycle, [
    'action_class',
    'closed_root_replacement_authorized',
    'closeout_status',
    'current_machine_governance_general',
    'enterprise_readiness',
    'expected_input_report_hashes_bound',
    'green_recognized_write_delta',
    'lifecycle_report_sha256',
    'post_closeout_target_written',
    'production_downstream_recognition',
    'public_external_attestation',
    'red_refusal_case_count',
    'result',
    'runner_result_sha256',
    'runtime_profile_id',
    'runtime_profile_sha256',
    'source_binding_sha256',
  ]);
  requireSha('private verifier readiness lifecycle report SHA',
    packet.evidence.lifecycle.lifecycle_report_sha256);
  requireSha('private verifier readiness source binding SHA',
    packet.evidence.lifecycle.source_binding_sha256);
  requireSha('private verifier readiness runner result SHA',
    packet.evidence.lifecycle.runner_result_sha256);
  requireExact('private verifier readiness lifecycle result', 'pass',
    packet.evidence.lifecycle.result);
  requireExact('private verifier readiness lifecycle action class', 'records.write',
    packet.evidence.lifecycle.action_class);
  requireString('private verifier readiness runtime profile id',
    packet.evidence.lifecycle.runtime_profile_id);
  requireSha('private verifier readiness runtime profile SHA',
    packet.evidence.lifecycle.runtime_profile_sha256);
  requireTrue('private verifier readiness lifecycle expected hashes bound',
    packet.evidence.lifecycle.expected_input_report_hashes_bound);
  requireExact('private verifier readiness green write delta', 1,
    packet.evidence.lifecycle.green_recognized_write_delta);
  requireExact('private verifier readiness red refusal case count', 18,
    packet.evidence.lifecycle.red_refusal_case_count);
  requireBool('private verifier readiness closed-root replacement authorized',
    packet.evidence.lifecycle.closed_root_replacement_authorized);
  requireFalse('private verifier readiness post-closeout target written',
    packet.evidence.lifecycle.post_closeout_target_written);
  requireExact('private verifier readiness closeout status', 'closed_inert_evidence',
    packet.evidence.lifecycle.closeout_status);
  requireFalse('private verifier readiness lifecycle current-machine governance general',
    packet.evidence.lifecycle.current_machine_governance_general);
  requireFalse('private verifier readiness lifecycle production downstream recognition',
    packet.evidence.lifecycle.production_downstream_recognition);
  requireFalse('private verifier readiness lifecycle public external attestation',
    packet.evidence.lifecycle.public_external_attestation);
  requireFalse('private verifier readiness lifecycle enterprise readiness',
    packet.evidence.lifecycle.enterprise_readiness);

  exactKeys('private verifier readiness North Star summary', packet.evidence.readiness, [
    'claim_current_machine_governance',
    'claim_enterprise_readiness',
    'claim_production_authority',
    'claim_public_external_attestation',
    'lifecycle_current_installation',
    'lifecycle_current_machine_governance_general',
    'lifecycle_enterprise_deployment_profile_completion',
    'lifecycle_expected_hashes_bound',
    'lifecycle_non_scoring',
    'lifecycle_product_proof_path_completion',
    'lifecycle_production_downstream_recognition',
    'lifecycle_provided',
    'lifecycle_verified',
    'readiness_report_sha256',
    'result',
  ]);
  requireSha('private verifier readiness North Star report SHA',
    packet.evidence.readiness.readiness_report_sha256);
  requireExact('private verifier readiness North Star result', 'NOT_READY_FOR_V3_4_0',
    packet.evidence.readiness.result);
  requireTrue('private verifier readiness lifecycle provided',
    packet.evidence.readiness.lifecycle_provided);
  requireTrue('private verifier readiness lifecycle verified',
    packet.evidence.readiness.lifecycle_verified);
  requireTrue('private verifier readiness lifecycle expected hashes bound',
    packet.evidence.readiness.lifecycle_expected_hashes_bound);
  requireTrue('private verifier readiness lifecycle non-scoring',
    packet.evidence.readiness.lifecycle_non_scoring);
  requireFalse('private verifier readiness lifecycle current installation',
    packet.evidence.readiness.lifecycle_current_installation);
  requireFalse('private verifier readiness lifecycle Product Proof completion',
    packet.evidence.readiness.lifecycle_product_proof_path_completion);
  requireFalse('private verifier readiness lifecycle Enterprise Profile completion',
    packet.evidence.readiness.lifecycle_enterprise_deployment_profile_completion);
  requireFalse('private verifier readiness lifecycle current-machine general',
    packet.evidence.readiness.lifecycle_current_machine_governance_general);
  requireFalse('private verifier readiness lifecycle production recognition',
    packet.evidence.readiness.lifecycle_production_downstream_recognition);
  requireFalse('private verifier readiness claim current-machine governance',
    packet.evidence.readiness.claim_current_machine_governance);
  requireFalse('private verifier readiness claim public external attestation',
    packet.evidence.readiness.claim_public_external_attestation);
  requireFalse('private verifier readiness claim production authority',
    packet.evidence.readiness.claim_production_authority);
  requireFalse('private verifier readiness claim enterprise readiness',
    packet.evidence.readiness.claim_enterprise_readiness);

  exactKeys('private verifier readiness verifier instructions', packet.verifier_instructions, [
    'access_model',
    'command_templates',
    'expected_fail_criteria',
    'expected_pass_criteria',
  ]);
  requireExact('private verifier readiness verifier access model',
    'future_authorized_private_source_and_evidence_bundle_only',
    packet.verifier_instructions.access_model);
  const commandTemplates = requireArray('private verifier readiness command templates',
    packet.verifier_instructions.command_templates);
  for (const command of commandTemplates) {
    requireString('private verifier readiness command template', command);
    const checkoutMatch = command.match(/\bgit\s+checkout\s+([a-f0-9]{40})\b/i);
    if (checkoutMatch && checkoutMatch[1].toLowerCase() !== packet.target.commit_sha) {
      throw new Error('private verifier readiness command template checkout commit mismatch');
    }
    const requireCommitMatch = command.match(/--require-commit\s+([a-f0-9]{40})\b/i);
    if (requireCommitMatch && requireCommitMatch[1].toLowerCase() !== packet.target.commit_sha) {
      throw new Error('private verifier readiness command template required commit mismatch');
    }
    const requireEvidenceSourceCommitMatch =
      command.match(/--require-evidence-source-commit\s+([a-f0-9]{40})\b/i);
    if (
      requireEvidenceSourceCommitMatch &&
      requireEvidenceSourceCommitMatch[1].toLowerCase() !== packet.evidence.source_commit_sha
    ) {
      throw new Error('private verifier readiness command template required evidence source commit mismatch');
    }
  }
  if (!commandTemplates.includes(`git checkout ${packet.target.commit_sha}`)) {
    throw new Error('private verifier readiness command templates must checkout target commit');
  }
  if (!commandTemplates.some((command) =>
    command.includes(`--require-commit ${packet.target.commit_sha}`)
  )) {
    throw new Error('private verifier readiness command templates must require target commit');
  }
  if (!commandTemplates.some((command) =>
    command.includes(`--require-evidence-source-commit ${packet.evidence.source_commit_sha}`)
  )) {
    throw new Error('private verifier readiness command templates must require evidence source commit');
  }
  for (const criterion of requireArray('private verifier readiness pass criteria',
    packet.verifier_instructions.expected_pass_criteria)) {
    requireString('private verifier readiness pass criterion', criterion);
  }
  for (const criterion of requireArray('private verifier readiness fail criteria',
    packet.verifier_instructions.expected_fail_criteria)) {
    requireString('private verifier readiness fail criterion', criterion);
  }

  exactKeys('private verifier readiness claim ceiling', packet.claim_ceiling, [
    'actual_non_operator_review',
    'all_surface_governance',
    'enterprise_readiness',
    'general_current_machine_governance',
    'key_custody',
    'local_active_persistent_lifecycle_verified',
    'private_verifier_readiness',
    'production_authority',
    'production_deployment',
    'public_attribution',
    'public_external_attestation',
    'revocation_truth',
    'side_door_closure',
  ]);
  requireTrue('private verifier readiness claim ceiling private readiness',
    packet.claim_ceiling.private_verifier_readiness);
  requireTrue('private verifier readiness claim ceiling lifecycle verified',
    packet.claim_ceiling.local_active_persistent_lifecycle_verified);
  for (const key of CLAIM_CEILING_FALSE_KEYS) {
    requireFalse(`private verifier readiness claim ceiling ${key}`, packet.claim_ceiling[key]);
  }

  for (const boundary of requireArray('private verifier readiness stop boundaries',
    packet.stop_boundaries)) {
    requireString('private verifier readiness stop boundary', boundary);
  }
  for (const sideDoor of requireArray('private verifier readiness side doors',
    packet.side_doors)) {
    requireString('private verifier readiness side door', sideDoor);
  }

  exactKeys('private verifier readiness later authority required',
    packet.later_authority_required,
    LATER_AUTHORITY_KEYS);
  for (const key of LATER_AUTHORITY_KEYS) {
    requireTrue(`private verifier readiness later authority ${key}`,
      packet.later_authority_required[key]);
  }

  const nonClaims = requireArray('private verifier readiness non-claims', packet.non_claims);
  const nonClaimText = nonClaims.join('\n');
  for (const fragment of REQUIRED_NON_CLAIM_FRAGMENTS) {
    if (!nonClaimText.includes(fragment)) {
      throw new Error(`private verifier readiness non-claims missing fragment: ${fragment}`);
    }
  }
  for (const nonClaim of nonClaims) {
    requireString('private verifier readiness non-claim', nonClaim);
  }

  assertNoUnsafePrivateVerifierReadinessText(JSON.stringify(packet));
  return true;
}

export function buildPrivateVerifierReadinessVerification(packet, {
  evidenceDir = '',
  packetText = '',
  requiredCommit = '',
  requiredEvidenceSourceCommit = '',
  requireArtifactSetSha = '',
  requireRecomputedEvidence = false,
} = {}) {
  assertPrivateVerifierReadinessPacket(packet);
  if (requiredCommit) {
    const normalizedRequiredCommit = requiredCommit.toLowerCase();
    requireCommit('private verifier readiness required commit', normalizedRequiredCommit);
    if (packet.target.commit_sha !== normalizedRequiredCommit) {
      throw new Error('private verifier readiness required commit mismatch');
    }
  }
  if (requiredEvidenceSourceCommit) {
    const normalizedRequiredEvidenceSourceCommit = requiredEvidenceSourceCommit.toLowerCase();
    requireCommit('private verifier readiness required evidence source commit',
      normalizedRequiredEvidenceSourceCommit);
    if (packet.evidence.source_commit_sha !== normalizedRequiredEvidenceSourceCommit) {
      throw new Error('private verifier readiness required evidence source commit mismatch');
    }
  }
  if (requireArtifactSetSha) {
    requireArtifactSetSha = requireArtifactSetSha.toLowerCase();
    requireSha('private verifier readiness required artifact set SHA',
      requireArtifactSetSha);
    if (packet.evidence.artifact_set_sha256 !== requireArtifactSetSha) {
      throw new Error('private verifier readiness required artifact set SHA mismatch');
    }
  }
  let recomputed = null;
  if (evidenceDir) {
    const artifacts = collectEvidenceArtifacts(evidenceDir);
    const recomputedSetSha = artifactSetSha256(artifacts);
    if (recomputedSetSha !== packet.evidence.artifact_set_sha256) {
      throw new Error('private verifier readiness recomputed artifact set SHA mismatch');
    }
    readEvidenceContracts(evidenceDir, artifacts);
    recomputed = {
      evidence_dir_label: requireSafeLabel('private verifier readiness evidence directory label',
        basename(resolve(evidenceDir))),
      artifact_count: artifacts.length,
      artifact_set_sha256: recomputedSetSha,
      matches_packet: true,
    };
  } else if (requireRecomputedEvidence) {
    throw new Error('private verifier readiness recomputed evidence was required but no evidence directory was supplied');
  }
  const verification = {
    verification_type: PRIVATE_VERIFIER_READINESS_VERIFICATION_TYPE,
    schema_version: 1,
    verified: true,
    packet_canonical_sha256: sha256Canonical(packet),
    packet_text_sha256: packetText ? sha256Text(packetText) : '',
    target: { ...packet.target },
    evidence_source_commit_sha: packet.evidence.source_commit_sha,
    artifact_set_sha256: packet.evidence.artifact_set_sha256,
    recomputed_evidence: recomputed,
    claim_boundary_preserved: {
      private_verifier_readiness: true,
      public_external_attestation: false,
      actual_non_operator_review: false,
      public_attribution: false,
      production_authority: false,
      production_deployment: false,
      enterprise_readiness: false,
      general_current_machine_governance: false,
      all_surface_governance: false,
      side_door_closure: false,
    },
    stop_boundary_preserved: true,
  };
  assertNoUnsafePrivateVerifierReadinessText(JSON.stringify(verification));
  return verification;
}

export function formatPrivateVerifierReadinessVerification(verification) {
  const lines = [
    'private_verifier_readiness_verified=true',
    `commit_sha=${verification.target.commit_sha}`,
    `evidence_source_commit_sha=${verification.evidence_source_commit_sha}`,
    `artifact_set_sha256=${verification.artifact_set_sha256}`,
    `packet_canonical_sha256=${verification.packet_canonical_sha256}`,
    `recomputed_evidence=${verification.recomputed_evidence ? 'true' : 'false'}`,
    'public_external_attestation=false',
    'production_authority=false',
    'enterprise_readiness=false',
    'general_current_machine_governance=false',
  ];
  const output = `${lines.join('\n')}\n`;
  assertNoUnsafePrivateVerifierReadinessText(output);
  return output;
}

function renderReadme(packet) {
  const commands = packet.verifier_instructions.command_templates
    .map((command) => `- \`${command}\``)
    .join('\n');
  const passCriteria = packet.verifier_instructions.expected_pass_criteria
    .map((criterion) => `- ${criterion}`)
    .join('\n');
  const failCriteria = packet.verifier_instructions.expected_fail_criteria
    .map((criterion) => `- ${criterion}`)
    .join('\n');
  const nonClaims = packet.non_claims.map((claim) => `- ${claim}`).join('\n');
  const sideDoors = packet.side_doors.map((sideDoor) => `- ${sideDoor}`).join('\n');
  const text = `# ZLAR Private Verifier Readiness Packet

Packet: \`${PRIVATE_VERIFIER_READINESS_PACKET_FILE}\`

Verifier source commit: \`${packet.target.commit_sha}\`
Evidence source commit: \`${packet.evidence.source_commit_sha}\`
Target branch: \`${packet.target.branch}\`
Evidence label: \`${packet.evidence.evidence_dir_label}\`
Artifact set SHA-256: \`${packet.evidence.artifact_set_sha256}\`

This is a local private readiness packet. It is not a verifier request, not
external contact, not public external attestation, not public attribution, not a
release, not production deployment, and not enterprise readiness.

## Verifier Command Templates

${commands}

## Expected Pass Criteria

${passCriteria}

## Expected Fail Criteria

${failCriteria}

## Side Doors

${sideDoors}

## Non-Claims

${nonClaims}
`;
  assertNoUnsafePrivateVerifierReadinessText(text);
  return text;
}

export function writePrivateVerifierReadinessPacket({ packet, outputDir } = {}) {
  assertPrivateVerifierReadinessPacket(packet);
  requirePathArg('private verifier readiness outputDir', outputDir);
  mkdirSync(outputDir, { recursive: true, mode: 0o700 });
  const packetText = `${JSON.stringify(packet, null, 2)}\n`;
  assertNoUnsafePrivateVerifierReadinessText(packetText);
  const readmeText = renderReadme(packet);
  const packetPath = join(outputDir, PRIVATE_VERIFIER_READINESS_PACKET_FILE);
  const readmePath = join(outputDir, PRIVATE_VERIFIER_READINESS_README_FILE);
  const shaPath = join(outputDir, PRIVATE_VERIFIER_READINESS_SHA256SUMS_FILE);
  writeFileSync(packetPath, packetText, { mode: 0o600 });
  writeFileSync(readmePath, readmeText, { mode: 0o600 });
  const packetSha = sha256Text(packetText);
  const readmeSha = sha256Text(readmeText);
  const shaText =
    `${packetSha}  ${PRIVATE_VERIFIER_READINESS_PACKET_FILE}\n` +
    `${readmeSha}  ${PRIVATE_VERIFIER_READINESS_README_FILE}\n`;
  writeFileSync(shaPath, shaText, { mode: 0o600 });
  return {
    packet_file: PRIVATE_VERIFIER_READINESS_PACKET_FILE,
    packet_sha256: packetSha,
    readme_file: PRIVATE_VERIFIER_READINESS_README_FILE,
    readme_sha256: readmeSha,
    sha256sums_file: PRIVATE_VERIFIER_READINESS_SHA256SUMS_FILE,
  };
}

export function formatPrivateVerifierReadinessBuildResult({ packet, writeResult } = {}) {
  assertPrivateVerifierReadinessPacket(packet);
  const lines = [
    'private_verifier_readiness_packet_written=true',
    `commit_sha=${packet.target.commit_sha}`,
    `evidence_source_commit_sha=${packet.evidence.source_commit_sha}`,
    `artifact_count=${packet.evidence.artifact_count}`,
    `artifact_set_sha256=${packet.evidence.artifact_set_sha256}`,
    `packet_file=${writeResult.packet_file}`,
    `packet_sha256=${writeResult.packet_sha256}`,
    'public_external_attestation=false',
    'production_authority=false',
    'enterprise_readiness=false',
    'general_current_machine_governance=false',
  ];
  const output = `${lines.join('\n')}\n`;
  assertNoUnsafePrivateVerifierReadinessText(output);
  return output;
}

export function readPrivateVerifierReadinessPacketText(path) {
  return readText(path, 'private verifier readiness packet');
}
