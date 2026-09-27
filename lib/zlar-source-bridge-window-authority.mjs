import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from './canonicalize.mjs';
import { sha256hex } from './receipt.mjs';

export const SOURCE_BRIDGE_WINDOW_PACKET_TYPE = 'zlar-time-boxed-source-bridge-window-v1';
export const SOURCE_BRIDGE_WINDOW_REPORT_TYPE = 'zlar-time-boxed-source-bridge-window-report-v1';
export const SOURCE_BRIDGE_WINDOW_CONTRACT = 'zlar-time-boxed-source-bridge-window-authority-v1';
export const DEFAULT_REPO = 'ZLAR-AI/ZLAR';
export const DEFAULT_BRANCH = 'local-governed-destination-boarding-proof';
export const DEFAULT_REMOTE_REF = `refs/heads/${DEFAULT_BRANCH}`;
export const SOURCE_BRIDGE_WINDOW_SAMPLE_NOW_MS = Date.parse('2026-07-06T00:30:00Z');

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(MODULE_DIR, '..');
const DEFAULT_BUILD_ROOT = process.env.ZLAR_BUILD_ROOT || resolve(PROJECT_ROOT, '..', 'ZLAR-Draft', 'build');
const DEFAULT_FUTURE_SKEW_SECONDS = 5 * 60;
const DEFAULT_MAX_WINDOW_SECONDS = 36 * 60 * 60;

export const REQUIRED_ALLOWED_SOURCE_MOVEMENT = Object.freeze([
  'source_only_build_stabilization',
  'single_branch',
  'non_force_push',
  'parent_checked',
  'clean_worktree_required',
  'tests_required',
  'privacy_guard_required',
  'redacted_closeout_required',
  'current_state_ledger_required',
]);

export const REQUIRED_FORBIDDEN_CONSEQUENCES = Object.freeze([
  'force_push',
  'tags',
  'releases',
  'actions',
  'website_publication',
  'github_settings',
  'hooks_config_install',
  'deploy_key_policy_changes',
  'credentials_or_secrets',
  'yubikey_work',
  'external_services',
  'production_public_claims',
  'broader_source_movement',
]);

export const REQUIRED_STOP_CONDITIONS = Object.freeze([
  'unexpected_diffs',
  'failed_checks_requiring_product_judgment',
  'branch_divergence',
  'privacy_or_secret_findings',
  'credential_material',
  'unclear_authority',
  'consequence_class_change',
]);

export const FORBIDDEN_CLAIMS = Object.freeze([
  'durable source transport',
  'always-on source movement',
  'release/public alignment',
  'GitHub settings authority',
  'deploy-key policy authority',
  'credential custody',
  'external service authority',
  'production governance',
  'all-surface governance',
  'side-door closure',
  'absolute human intention',
]);

const TOP_LEVEL_KEYS = new Set([
  'packet_type',
  'human_grant',
  'window',
  'source_target',
  'allowed_source_movement',
  'forbidden_consequences',
  'stop_conditions',
]);
const HUMAN_GRANT_KEYS = new Set(['human', 'grant_timestamp', 'action']);
const WINDOW_KEYS = new Set(['expires_at', 'timezone']);
const SOURCE_TARGET_KEYS = new Set(['repo', 'branch', 'remote_ref']);
const ALLOWED_MOVEMENT_KEYS = new Set(REQUIRED_ALLOWED_SOURCE_MOVEMENT);

const SECRET_PATTERNS = Object.freeze([
  { code: 'private_key_material', pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/i },
  { code: 'ssh_private_key_material', pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/i },
  { code: 'authorization_header', pattern: /\bauthorization\s*[:=]\s*(?:bearer|basic|token)\s+\S+/i },
  { code: 'github_token', pattern: /\b(?:github_pat_|gh[psuor]_|ghs_)[A-Za-z0-9_]{12,}\b/i },
  { code: 'jwt_like_token', pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { code: 'credentialed_url', pattern: /\bhttps?:\/\/[^/\s:@]+:[^/\s@]+@/i },
  {
    code: 'secret_assignment',
    pattern:
      /\b(?:access[_-]?token|installation[_-]?token|token|secret|password|passwd|private[_-]?key|api[_-]?key|client[_-]?secret)\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{10,}/i,
  },
]);

class SourceBridgeWindowRefusal extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'SourceBridgeWindowRefusal';
    this.code = code;
    this.details = details;
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function noSecretBoundary() {
  return {
    reads_private_key_material: false,
    reads_token_material: false,
    mints_credentials: false,
    calls_github: false,
    reads_remote_refs: false,
    pushes_source: false,
    changes_configuration: false,
  };
}

function assertReportObjectKeys(label, value, expectedKeys) {
  if (!isPlainObject(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} has unexpected fields`);
  }
}

function refusal(code, message, details = {}) {
  return {
    report_type: SOURCE_BRIDGE_WINDOW_REPORT_TYPE,
    verifier_contract: SOURCE_BRIDGE_WINDOW_CONTRACT,
    authority_status: 'refused',
    refusal_reason_code: code,
    refusal_reason: message,
    safe_for_control_tower_use: false,
    can_push_under_window: false,
    details,
    no_secret_boundary: noSecretBoundary(),
    forbidden_claims: [...FORBIDDEN_CLAIMS],
  };
}

function assertNoUnsafeText(text) {
  const raw = String(text ?? '');
  for (const { code, pattern } of SECRET_PATTERNS) {
    if (pattern.test(raw)) {
      throw new SourceBridgeWindowRefusal('unsafe_secret_shaped_material', `Unsafe material refused: ${code}`);
    }
  }
}

export function assertNoUnsafeSourceBridgeWindowText(text) {
  assertNoUnsafeText(text);
  return true;
}

function readInput(input) {
  if (typeof input === 'string') {
    assertNoUnsafeText(input);
    try {
      return JSON.parse(input);
    } catch {
      throw new SourceBridgeWindowRefusal('malformed_json', 'Authority packet must be valid JSON');
    }
  }
  return input;
}

function assertAllowedKeys(value, allowedKeys, path) {
  for (const key of Object.keys(value)) {
    if (!allowedKeys.has(key)) {
      throw new SourceBridgeWindowRefusal('unknown_field', `Unknown field refused at ${path.concat(key).join('.')}`);
    }
  }
}

function requireObject(label, value) {
  if (!isPlainObject(value)) {
    throw new SourceBridgeWindowRefusal('malformed_packet', `${label} must be an object`);
  }
  return value;
}

function requireString(label, value) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new SourceBridgeWindowRefusal('malformed_packet', `${label} must be a non-empty string`);
  }
  assertNoUnsafeText(value);
  return value;
}

function requireStringArray(label, value) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new SourceBridgeWindowRefusal('malformed_packet', `${label} must be a non-empty string array`);
  }
  for (const entry of value) requireString(label, entry);
  return value;
}

function requireIso(label, value) {
  requireString(label, value);
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    throw new SourceBridgeWindowRefusal('invalid_timestamp', `${label} must be an ISO-8601 timestamp`);
  }
  return parsed;
}

function assertAllRequiredIncluded(label, observed, required) {
  const set = new Set(observed);
  const missing = required.filter((entry) => !set.has(entry));
  if (missing.length > 0) {
    throw new SourceBridgeWindowRefusal('required_boundary_missing', `${label} missing required entries`, { missing });
  }
}

function validateAllowedMovement(value) {
  const movement = requireObject('allowed_source_movement', value);
  assertAllowedKeys(movement, ALLOWED_MOVEMENT_KEYS, ['allowed_source_movement']);
  for (const key of REQUIRED_ALLOWED_SOURCE_MOVEMENT) {
    if (movement[key] !== true) {
      throw new SourceBridgeWindowRefusal('required_guard_not_true', `allowed_source_movement.${key} must be true`);
    }
  }
  return Object.fromEntries(REQUIRED_ALLOWED_SOURCE_MOVEMENT.map((key) => [key, true]));
}

function packetHash(packet) {
  return sha256hex(canonicalize(packet));
}

function validatePacket(packet, options = {}) {
  requireObject('authority packet', packet);
  assertAllowedKeys(packet, TOP_LEVEL_KEYS, []);
  if (packet.packet_type !== SOURCE_BRIDGE_WINDOW_PACKET_TYPE) {
    throw new SourceBridgeWindowRefusal('packet_type_mismatch', `packet_type must be ${SOURCE_BRIDGE_WINDOW_PACKET_TYPE}`);
  }

  const humanGrant = requireObject('human_grant', packet.human_grant);
  assertAllowedKeys(humanGrant, HUMAN_GRANT_KEYS, ['human_grant']);
  const human = requireString('human_grant.human', humanGrant.human);
  const action = requireString('human_grant.action', humanGrant.action);
  const grantMs = requireIso('human_grant.grant_timestamp', humanGrant.grant_timestamp);

  const window = requireObject('window', packet.window);
  assertAllowedKeys(window, WINDOW_KEYS, ['window']);
  const expiresMs = requireIso('window.expires_at', window.expires_at);
  const timezone = requireString('window.timezone', window.timezone);

  const nowMs = options.nowMs ?? Date.now();
  const futureSkewMs = (options.futureSkewSeconds ?? DEFAULT_FUTURE_SKEW_SECONDS) * 1000;
  const maxWindowMs = (options.maxWindowSeconds ?? DEFAULT_MAX_WINDOW_SECONDS) * 1000;
  if (grantMs > nowMs + futureSkewMs) {
    throw new SourceBridgeWindowRefusal('grant_from_future', 'human grant timestamp is in the future');
  }
  if (expiresMs <= nowMs) {
    throw new SourceBridgeWindowRefusal('window_expired', 'source bridge window is expired');
  }
  if (expiresMs <= grantMs) {
    throw new SourceBridgeWindowRefusal('expiry_before_grant', 'window expiry must be after grant timestamp');
  }
  if (expiresMs - grantMs > maxWindowMs) {
    throw new SourceBridgeWindowRefusal('window_too_long', 'source bridge window exceeds max duration');
  }

  const source = requireObject('source_target', packet.source_target);
  assertAllowedKeys(source, SOURCE_TARGET_KEYS, ['source_target']);
  const repo = requireString('source_target.repo', source.repo);
  const branch = requireString('source_target.branch', source.branch);
  const remoteRef = requireString('source_target.remote_ref', source.remote_ref);
  if (repo !== DEFAULT_REPO) {
    throw new SourceBridgeWindowRefusal('repo_not_selected', `source_target.repo must be ${DEFAULT_REPO}`);
  }
  if (branch !== DEFAULT_BRANCH) {
    throw new SourceBridgeWindowRefusal('branch_not_selected', `source_target.branch must be ${DEFAULT_BRANCH}`);
  }
  if (remoteRef !== DEFAULT_REMOTE_REF) {
    throw new SourceBridgeWindowRefusal('remote_ref_not_selected', `source_target.remote_ref must be ${DEFAULT_REMOTE_REF}`);
  }

  const allowedMovement = validateAllowedMovement(packet.allowed_source_movement);
  const forbiddenConsequences = requireStringArray('forbidden_consequences', packet.forbidden_consequences);
  const stopConditions = requireStringArray('stop_conditions', packet.stop_conditions);
  assertAllRequiredIncluded('forbidden_consequences', forbiddenConsequences, REQUIRED_FORBIDDEN_CONSEQUENCES);
  assertAllRequiredIncluded('stop_conditions', stopConditions, REQUIRED_STOP_CONDITIONS);

  return {
    report_type: SOURCE_BRIDGE_WINDOW_REPORT_TYPE,
    verifier_contract: SOURCE_BRIDGE_WINDOW_CONTRACT,
    authority_status: 'accepted',
    refusal_reason_code: null,
    refusal_reason: null,
    safe_for_control_tower_use: true,
    can_push_under_window: true,
    packet_sha256: packetHash(packet),
    human_grant: {
      human,
      action,
      grant_timestamp: humanGrant.grant_timestamp,
    },
    window: {
      expires_at: window.expires_at,
      timezone,
      expires_in_seconds: Math.floor((expiresMs - nowMs) / 1000),
      max_window_seconds: Math.floor(maxWindowMs / 1000),
    },
    source_target: {
      repo,
      branch,
      remote_ref: remoteRef,
    },
    allowed_source_movement: allowedMovement,
    required_forbidden_consequences_present: true,
    required_stop_conditions_present: true,
    safe_claim:
      'This packet authorizes a time-boxed source-only bridge window for one repo/ref when all required guards remain true.',
    no_secret_boundary: noSecretBoundary(),
    forbidden_claims: [...FORBIDDEN_CLAIMS],
  };
}

export function runSourceBridgeWindowAuthority(input, options = {}) {
  try {
    const packet = readInput(input);
    return validatePacket(packet, options);
  } catch (error) {
    if (error instanceof SourceBridgeWindowRefusal) {
      return refusal(error.code, error.message, error.details ?? {});
    }
    return refusal('unexpected_refusal', 'Source bridge window authority refused');
  }
}

export function sourceBridgeWindowSamplePacket() {
  return {
    packet_type: SOURCE_BRIDGE_WINDOW_PACKET_TYPE,
    human_grant: {
      human: 'Vincent Nijjar',
      grant_timestamp: '2026-07-06T00:28:59Z',
      action: 'overnight source bridge window',
    },
    window: {
      expires_at: '2026-07-06T13:00:00Z',
      timezone: 'America/Winnipeg',
    },
    source_target: {
      repo: DEFAULT_REPO,
      branch: DEFAULT_BRANCH,
      remote_ref: DEFAULT_REMOTE_REF,
    },
    allowed_source_movement: Object.fromEntries(
      REQUIRED_ALLOWED_SOURCE_MOVEMENT.map((key) => [key, true])
    ),
    forbidden_consequences: [...REQUIRED_FORBIDDEN_CONSEQUENCES],
    stop_conditions: [...REQUIRED_STOP_CONDITIONS],
  };
}

export function runSourceBridgeWindowSampleAuthority(options = {}) {
  return runSourceBridgeWindowAuthority(sourceBridgeWindowSamplePacket(), {
    nowMs: options.nowMs ?? SOURCE_BRIDGE_WINDOW_SAMPLE_NOW_MS,
    futureSkewSeconds: options.futureSkewSeconds,
    maxWindowSeconds: options.maxWindowSeconds,
  });
}

export function assertSourceBridgeWindowAuthorityReport(report) {
  assertReportObjectKeys('Source bridge window authority report', report, [
    'report_type',
    'verifier_contract',
    'authority_status',
    'refusal_reason_code',
    'refusal_reason',
    'safe_for_control_tower_use',
    'can_push_under_window',
    'packet_sha256',
    'human_grant',
    'window',
    'source_target',
    'allowed_source_movement',
    'required_forbidden_consequences_present',
    'required_stop_conditions_present',
    'safe_claim',
    'no_secret_boundary',
    'forbidden_claims',
  ]);
  if (
    report.report_type !== SOURCE_BRIDGE_WINDOW_REPORT_TYPE ||
    report.verifier_contract !== SOURCE_BRIDGE_WINDOW_CONTRACT ||
    report.authority_status !== 'accepted' ||
    report.refusal_reason_code !== null ||
    report.refusal_reason !== null ||
    report.safe_for_control_tower_use !== true ||
    report.can_push_under_window !== true ||
    !/^[a-f0-9]{64}$/.test(report.packet_sha256 || '') ||
    report.required_forbidden_consequences_present !== true ||
    report.required_stop_conditions_present !== true ||
    report.safe_claim !==
      'This packet authorizes a time-boxed source-only bridge window for one repo/ref when all required guards remain true.'
  ) {
    throw new Error('Source bridge window authority report posture drifted');
  }
  assertReportObjectKeys('Source bridge window human grant', report.human_grant, [
    'human',
    'action',
    'grant_timestamp',
  ]);
  assertReportObjectKeys('Source bridge window', report.window, [
    'expires_at',
    'timezone',
    'expires_in_seconds',
    'max_window_seconds',
  ]);
  assertReportObjectKeys('Source bridge window source target', report.source_target, [
    'repo',
    'branch',
    'remote_ref',
  ]);
  assertReportObjectKeys('Source bridge window no-secret boundary', report.no_secret_boundary, [
    'reads_private_key_material',
    'reads_token_material',
    'mints_credentials',
    'calls_github',
    'reads_remote_refs',
    'pushes_source',
    'changes_configuration',
  ]);
  if (
    report.human_grant.human !== 'Vincent Nijjar' ||
    typeof report.human_grant.action !== 'string' ||
    Number.isNaN(Date.parse(report.human_grant.grant_timestamp)) ||
    Number.isNaN(Date.parse(report.window.expires_at)) ||
    report.window.timezone !== 'America/Winnipeg' ||
    !Number.isInteger(report.window.expires_in_seconds) ||
    report.window.expires_in_seconds <= 0 ||
    report.window.max_window_seconds !== DEFAULT_MAX_WINDOW_SECONDS ||
    report.source_target.repo !== DEFAULT_REPO ||
    report.source_target.branch !== DEFAULT_BRANCH ||
    report.source_target.remote_ref !== DEFAULT_REMOTE_REF
  ) {
    throw new Error('Source bridge window authority report identity drifted');
  }
  for (const key of REQUIRED_ALLOWED_SOURCE_MOVEMENT) {
    if (report.allowed_source_movement?.[key] !== true) {
      throw new Error(`Source bridge window required allowed movement missing: ${key}`);
    }
  }
  for (const value of Object.values(report.no_secret_boundary)) {
    if (value !== false) {
      throw new Error('Source bridge window no-secret boundary drifted');
    }
  }
  if (JSON.stringify(report.forbidden_claims) !== JSON.stringify(FORBIDDEN_CLAIMS)) {
    throw new Error('Source bridge window forbidden claims drifted');
  }
  return true;
}

export function formatSourceBridgeWindowAuthority(report) {
  const lines = [
    `Source bridge window authority: ${report.authority_status}`,
    `safe_for_control_tower_use: ${report.safe_for_control_tower_use}`,
    `can_push_under_window: ${report.can_push_under_window}`,
  ];
  if (report.refusal_reason_code) {
    lines.push(`refusal_reason_code: ${report.refusal_reason_code}`);
  }
  if (report.source_target) {
    lines.push(`source_target: ${report.source_target.repo} ${report.source_target.remote_ref}`);
  }
  if (report.window) {
    lines.push(`expires_at: ${report.window.expires_at}`);
  }
  lines.push('claim_boundary: source-only window authority shape; no push, credential, release, website, or production claim');
  return `${lines.join('\n')}\n`;
}

export function resolveSafeSourceBridgeWindowReportPath(outputPath, buildRoot = DEFAULT_BUILD_ROOT) {
  if (!outputPath || typeof outputPath !== 'string') {
    throw new SourceBridgeWindowRefusal('output_path_missing', 'Output path is required');
  }
  const root = resolve(buildRoot);
  const target = resolve(outputPath);
  if (target !== root && !target.startsWith(root + sep)) {
    throw new SourceBridgeWindowRefusal('unsafe_output_path', 'Output path must stay under build scratch root');
  }
  return target;
}

export function writeSourceBridgeWindowAuthorityReport(report, outputPath, options = {}) {
  const target = resolveSafeSourceBridgeWindowReportPath(outputPath, options.buildRoot ?? DEFAULT_BUILD_ROOT);
  mkdirSync(dirname(target), { recursive: true });
  if (existsSync(target)) {
    throw new SourceBridgeWindowRefusal('output_exists', 'Output path already exists');
  }
  writeFileSync(target, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return target;
}
