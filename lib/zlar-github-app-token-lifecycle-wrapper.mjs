import { dirname, resolve, sep } from 'node:path';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const TOKEN_LIFECYCLE_WRAPPER_CONTRACT = 'zlar-github-app-token-lifecycle-wrapper-v1';
export const TOKEN_LIFECYCLE_REPORT_TYPE = 'zlar-github-app-token-lifecycle-redacted-report-v1';
const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(MODULE_DIR, '..');
export const DEFAULT_BUILD_ROOT = process.env.ZLAR_BUILD_ROOT || resolve(PROJECT_ROOT, '..', 'ZLAR-Draft', 'build');
export const EXPECTED_APP_NAME = 'ZLAR Source Transport';
export const EXPECTED_APP_ID = '4217513';
export const EXPECTED_SELECTED_REPO = 'ZLAR-AI/ZLAR';
export const EXPECTED_CUSTODY_TARGET =
  '/operator-private-config/source-transport/github-app/zlar-source-transport.app-4217513.private-key.pem';

export const FORBIDDEN_CLAIMS = Object.freeze([
  'token minting',
  'token custody',
  'token revocation proof',
  'remote ref read through app credentials',
  'source movement',
  'durable GitHub App source transport',
  'production trust',
  'all-surface governance',
  'side-door closure',
  'absolute human intention',
]);

const UNSAFE_TEXT_PATTERNS = Object.freeze([
  { code: 'github_token_prefix', regex: /\b(?:github_pat_|gh[oprsu]_[A-Za-z0-9_]{10,})/i },
  { code: 'jwt_shaped_material', regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/ },
  { code: 'authorization_header', regex: /\bauthorization\s*:\s*(?:bearer|token|basic)\s+\S+/i },
  { code: 'bearer_token', regex: /\bbearer\s+[A-Za-z0-9._~+/=-]{16,}/i },
  { code: 'private_key_pem', regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/i },
  { code: 'pem_header', regex: /-----BEGIN [A-Z0-9 ]+-----/i },
  { code: 'credentialed_url', regex: /\bhttps?:\/\/[^/\s:@]+:[^/\s@]+@/i },
  {
    code: 'secret_assignment',
    regex:
      /\b(?:access[_-]?token|installation[_-]?token|token|secret|password|passwd|private[_-]?key|api[_-]?key|client[_-]?secret|authorization|auth|headers?|credentials?)\s*[:=]\s*[^,\s"']{4,}/i,
  },
]);

const FORBIDDEN_REPORT_KEYS = Object.freeze([
  'token',
  'jwt',
  'authorization',
  'authorization_header',
  'private_key',
  'private_key_contents',
  'private_key_hash',
  'private_key_fingerprint',
  'token_hash',
  'token_fingerprint',
  'token_length',
  'key_hash',
  'key_fingerprint',
  'pem_header',
  'file_size',
  'line_count',
  'public_key',
  'derived_key_identity',
]);

const TOP_LEVEL_INPUT_KEYS = new Set(['mode', 'expected_app', 'app', 'fixture', 'authority_packet_path', 'authority_packet_sha256']);
const APP_INPUT_KEYS = new Set(['name', 'app_id', 'id', 'selected_repo', 'custody_target_path']);
const FIXTURE_INPUT_KEYS = new Set([
  'request_started_at',
  'response_received_at',
  'simulated_expires_at',
  'simulated_revocation_status',
  'network_calls',
  'github_api_used',
  'remote_ref_read',
  'source_movement',
  'git_push',
  'git_fetch',
  'git_ls_remote',
  'credential_helper',
  'private_key_touched',
  'yubikey_used',
]);

const REPORT_ROOT_KEYS = new Set([
  'report_type',
  'wrapper_contract',
  'mode',
  'lifecycle_status',
  'refusal_reason_code',
  'refusal_reason',
  'app',
  'fake_lifecycle',
  'no_secret_guarantees',
  'boundary_statement',
  'chat2_adversarial_review_required_before_live_token_authority',
  'forbidden_claims',
]);

const REPORT_APP_KEYS = new Set(['name', 'app_id', 'selected_repo', 'custody_target_path', 'custody_target_metadata_only']);
const REPORT_FAKE_LIFECYCLE_KEYS = new Set([
  'request_started_at',
  'response_received_at',
  'simulated_installation_id',
  'simulated_expires_at',
  'simulated_revocation_status',
  'jwt_stage',
  'installation_credential_stage',
  'revocation_stage',
]);

const REPORT_GUARANTEE_KEYS = new Set([
  'fake_fixture_mode',
  'report_redacted_by_construction',
  'token_material_seen_by_report',
  'jwt_material_seen_by_report',
  'authorization_header_seen_by_report',
  'private_key_material_seen_by_report',
  'private_key_file_touched',
  'github_api_used',
  'network_path_used',
  'jwt_minted',
  'installation_token_minted',
  'remote_ref_read',
  'source_movement',
  'git_push',
  'git_fetch',
  'git_ls_remote',
  'credential_helper_used',
  'env_file_written',
  'shell_history_written',
  'yubikey_used',
  'actions_used',
  'tag_or_release_used',
  'website_touched',
  'deploy_key_policy_touched',
  'production_issuer_path_used',
]);

const SECRET_BEARING_KEY_PATTERN =
  /(?:^|[_-])(?:access[_-]?token|installation[_-]?token|token|jwt|auth|authorization|headers?|credentials?|secret|password|passwd|private[_-]?key|api[_-]?key|client[_-]?secret|pem)(?:$|[_-])/i;
const ISO_UTC_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const REVOCATION_STATUS_VALUES = new Set(['not_exercised_in_fake_mode', 'simulated_revoked', 'simulated_not_found']);

class TokenLifecycleRefusal extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'TokenLifecycleRefusal';
    this.code = code;
  }
}

export function scanUnsafeTokenLifecycleText(text) {
  if (text === null || text === undefined) return [];
  const value = String(text);
  return UNSAFE_TEXT_PATTERNS.filter((pattern) => pattern.regex.test(value)).map((pattern) => pattern.code);
}

export function assertNoUnsafeTokenLifecycleText(text, code = 'unsafe_secret_shaped_material') {
  const findings = scanUnsafeTokenLifecycleText(text);
  if (findings.length > 0) {
    throw new TokenLifecycleRefusal(code, `Unsafe credential-shaped material refused: ${findings.join(',')}`);
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function readInput(input) {
  if (typeof input === 'string') {
    assertNoUnsafeTokenLifecycleText(input);
    try {
      return JSON.parse(input);
    } catch {
      throw new TokenLifecycleRefusal('malformed_input', 'Input must be valid JSON');
    }
  }
  return input;
}

function inspectValue(value, path = []) {
  if (typeof value === 'string') {
    assertNoUnsafeTokenLifecycleText(value);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => inspectValue(entry, path.concat(String(index))));
    return;
  }
  if (isPlainObject(value)) {
    for (const [key, entry] of Object.entries(value)) {
      const normalizedKey = key.toLowerCase();
      if (FORBIDDEN_REPORT_KEYS.includes(normalizedKey)) {
        throw new TokenLifecycleRefusal('unsafe_report_key', `Unsafe report/input key refused at ${path.concat(key).join('.')}`);
      }
      inspectValue(entry, path.concat(key));
    }
  }
}

function pathKey(path) {
  return path.join('.');
}

function assertAllowedKeys(value, allowedKeys, path, code = 'unknown_input_key') {
  for (const key of Object.keys(value)) {
    if (!allowedKeys.has(key)) {
      const normalizedPath = pathKey(path.concat(key));
      const refusalCode = SECRET_BEARING_KEY_PATTERN.test(key) ? 'unsafe_input_key' : code;
      throw new TokenLifecycleRefusal(refusalCode, `Unexpected key refused at ${normalizedPath}`);
    }
  }
}

function assertInputShape(value, path = []) {
  if (!isPlainObject(value)) {
    throw new TokenLifecycleRefusal('malformed_input', 'Input must be a JSON object');
  }
  if (path.length === 0) {
    assertAllowedKeys(value, TOP_LEVEL_INPUT_KEYS, path);
    for (const [key, entry] of Object.entries(value)) {
      if (key === 'expected_app' || key === 'app' || key === 'fixture') {
        assertInputShape(entry, [key]);
      }
    }
    return;
  }
  const current = pathKey(path);
  if (current === 'expected_app' || current === 'app') {
    if (!isPlainObject(value)) throw new TokenLifecycleRefusal('malformed_input', 'Expected app metadata must be an object');
    assertAllowedKeys(value, APP_INPUT_KEYS, path);
    return;
  }
  if (current === 'fixture') {
    if (!isPlainObject(value)) throw new TokenLifecycleRefusal('malformed_fixture', 'Fake fixture must be an object');
    assertAllowedKeys(value, FIXTURE_INPUT_KEYS, path);
    return;
  }
  throw new TokenLifecycleRefusal('unknown_input_path', `Unexpected input path refused at ${current}`);
}

function assertReportShape(value, path = []) {
  if (!isPlainObject(value)) {
    throw new TokenLifecycleRefusal('malformed_report', 'Report must be an object');
  }
  if (path.length === 0) {
    assertAllowedKeys(value, REPORT_ROOT_KEYS, path, 'unknown_report_key');
    for (const [key, entry] of Object.entries(value)) {
      if (key === 'app' || key === 'fake_lifecycle' || key === 'no_secret_guarantees') {
        assertReportShape(entry, [key]);
      }
    }
    return;
  }
  const current = pathKey(path);
  if (current === 'app') {
    assertAllowedKeys(value, REPORT_APP_KEYS, path, 'unknown_report_key');
    return;
  }
  if (current === 'fake_lifecycle') {
    assertAllowedKeys(value, REPORT_FAKE_LIFECYCLE_KEYS, path, 'unknown_report_key');
    return;
  }
  if (current === 'no_secret_guarantees') {
    assertAllowedKeys(value, REPORT_GUARANTEE_KEYS, path, 'unknown_report_key');
    return;
  }
  throw new TokenLifecycleRefusal('unknown_report_path', `Unexpected report path refused at ${current}`);
}

function ensureBooleanFalse(value, code, label) {
  if (value !== undefined && value !== false) {
    throw new TokenLifecycleRefusal(code, `${label} must be false in no-secret fake mode`);
  }
}

function validateIsoUtcOrNull(value, label) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || !ISO_UTC_PATTERN.test(value) || Number.isNaN(Date.parse(value))) {
    throw new TokenLifecycleRefusal('invalid_fixture_timestamp', `${label} must be an ISO-8601 UTC timestamp or null`);
  }
  return value;
}

function validateRevocationStatus(value) {
  if (value === undefined || value === null) return 'not_exercised_in_fake_mode';
  if (typeof value !== 'string' || !REVOCATION_STATUS_VALUES.has(value)) {
    throw new TokenLifecycleRefusal('invalid_revocation_status', 'simulated_revocation_status must be a known enum value');
  }
  return value;
}

function normalizeAppId(value) {
  if (typeof value === 'number' && Number.isInteger(value)) return String(value);
  if (typeof value === 'string') return value.trim();
  return '';
}

function validateExpectedMetadata(input) {
  const app = input.expected_app ?? input.app;
  if (!isPlainObject(app)) {
    throw new TokenLifecycleRefusal('missing_expected_app_metadata', 'Expected app metadata is required');
  }
  if (app.name !== EXPECTED_APP_NAME) {
    throw new TokenLifecycleRefusal('app_name_mismatch', 'Expected app name mismatch');
  }
  if (normalizeAppId(app.app_id ?? app.id) !== EXPECTED_APP_ID) {
    throw new TokenLifecycleRefusal('app_id_mismatch', 'Expected app id mismatch');
  }
  if (app.selected_repo !== EXPECTED_SELECTED_REPO) {
    throw new TokenLifecycleRefusal('selected_repo_mismatch', 'Selected repository mismatch');
  }
  if (app.custody_target_path !== EXPECTED_CUSTODY_TARGET) {
    throw new TokenLifecycleRefusal('custody_target_mismatch', 'Custody target metadata mismatch');
  }
  return {
    name: app.name,
    app_id: EXPECTED_APP_ID,
    selected_repo: app.selected_repo,
    custody_target_path: app.custody_target_path,
    custody_target_metadata_only: true,
  };
}

function validateFakeFixture(input) {
  const fixture = input.fixture ?? {};
  if (!isPlainObject(fixture)) {
    throw new TokenLifecycleRefusal('malformed_fixture', 'Fake fixture must be an object');
  }

  ensureBooleanFalse(fixture.network_calls, 'network_path_requested', 'network_calls');
  ensureBooleanFalse(fixture.github_api_used, 'github_api_requested', 'github_api_used');
  ensureBooleanFalse(fixture.remote_ref_read, 'remote_ref_requested', 'remote_ref_read');
  ensureBooleanFalse(fixture.source_movement, 'source_movement_requested', 'source_movement');
  ensureBooleanFalse(fixture.git_push, 'git_push_requested', 'git_push');
  ensureBooleanFalse(fixture.git_fetch, 'git_fetch_requested', 'git_fetch');
  ensureBooleanFalse(fixture.git_ls_remote, 'git_ls_remote_requested', 'git_ls_remote');
  ensureBooleanFalse(fixture.credential_helper, 'credential_helper_requested', 'credential_helper');
  ensureBooleanFalse(fixture.private_key_touched, 'private_key_touch_requested', 'private_key_touched');
  ensureBooleanFalse(fixture.yubikey_used, 'yubikey_requested', 'yubikey_used');

  return {
    request_started_at: validateIsoUtcOrNull(fixture.request_started_at, 'request_started_at'),
    response_received_at: validateIsoUtcOrNull(fixture.response_received_at, 'response_received_at'),
    simulated_installation_id: 'fixture-installation-id-redacted',
    simulated_expires_at: validateIsoUtcOrNull(fixture.simulated_expires_at, 'simulated_expires_at'),
    simulated_revocation_status: validateRevocationStatus(fixture.simulated_revocation_status),
  };
}

function buildNoSecretGuarantees() {
  return {
    fake_fixture_mode: true,
    report_redacted_by_construction: true,
    token_material_seen_by_report: false,
    jwt_material_seen_by_report: false,
    authorization_header_seen_by_report: false,
    private_key_material_seen_by_report: false,
    private_key_file_touched: false,
    github_api_used: false,
    network_path_used: false,
    jwt_minted: false,
    installation_token_minted: false,
    remote_ref_read: false,
    source_movement: false,
    git_push: false,
    git_fetch: false,
    git_ls_remote: false,
    credential_helper_used: false,
    env_file_written: false,
    shell_history_written: false,
    yubikey_used: false,
    actions_used: false,
    tag_or_release_used: false,
    website_touched: false,
    deploy_key_policy_touched: false,
    production_issuer_path_used: false,
  };
}

function normalizeReportMode(inputMode, reasonCode = null) {
  if (inputMode === 'fake-fixture' || inputMode === 'live') return inputMode;
  if (reasonCode === 'unsupported_mode') return 'unsupported';
  return 'unknown';
}

function buildRefusalReport(reasonCode, reasonMessage, inputMode = 'unknown') {
  return {
    report_type: TOKEN_LIFECYCLE_REPORT_TYPE,
    wrapper_contract: TOKEN_LIFECYCLE_WRAPPER_CONTRACT,
    mode: normalizeReportMode(inputMode, reasonCode),
    lifecycle_status: 'refused',
    refusal_reason_code: reasonCode,
    refusal_reason: reasonMessage,
    no_secret_guarantees: buildNoSecretGuarantees(),
    chat2_adversarial_review_required_before_live_token_authority: true,
    forbidden_claims: FORBIDDEN_CLAIMS,
  };
}

function ensureSafeReport(report) {
  assertReportShape(report);
  inspectValue(report);
  assertNoUnsafeTokenLifecycleText(JSON.stringify(report));
  return report;
}

export function runGithubAppTokenLifecycleWrapper(input, options = {}) {
  let parsed;
  try {
    parsed = readInput(input);
    if (!isPlainObject(parsed)) {
      throw new TokenLifecycleRefusal('malformed_input', 'Input must be a JSON object');
    }
    assertInputShape(parsed);
    inspectValue(parsed);

    const mode = options.mode ?? parsed.mode ?? 'fake-fixture';
    if (mode === 'live') {
      const hasAuthorityPacket = Boolean(options.authorityPacketPath ?? parsed.authority_packet_path);
      const hasAuthoritySha = Boolean(options.authorityPacketSha256 ?? parsed.authority_packet_sha256);
      const code = hasAuthorityPacket && hasAuthoritySha
        ? 'live_mode_disabled_in_no_secret_build'
        : 'live_mode_requires_later_authority_packet';
      throw new TokenLifecycleRefusal(code, 'Live token lifecycle is refused in this no-secret build');
    }
    if (mode !== 'fake-fixture') {
      throw new TokenLifecycleRefusal('unsupported_mode', 'Only fake-fixture mode is supported in this build');
    }

    const app = validateExpectedMetadata(parsed);
    const fixture = validateFakeFixture(parsed);
    const report = {
      report_type: TOKEN_LIFECYCLE_REPORT_TYPE,
      wrapper_contract: TOKEN_LIFECYCLE_WRAPPER_CONTRACT,
      mode,
      lifecycle_status: 'passed',
      refusal_reason_code: null,
      app,
      fake_lifecycle: {
        request_started_at: fixture.request_started_at,
        response_received_at: fixture.response_received_at,
        simulated_installation_id: fixture.simulated_installation_id,
        simulated_expires_at: fixture.simulated_expires_at,
        simulated_revocation_status: fixture.simulated_revocation_status,
        jwt_stage: 'not_minted_fake_fixture_only',
        installation_credential_stage: 'not_minted_fake_fixture_only',
        revocation_stage: 'not_exercised_fake_fixture_only',
      },
      no_secret_guarantees: buildNoSecretGuarantees(),
      boundary_statement:
        'This report is a no-secret fake-fixture guardrail. It does not mint, read, hash, or verify any live credential.',
      chat2_adversarial_review_required_before_live_token_authority: true,
      forbidden_claims: FORBIDDEN_CLAIMS,
    };
    return ensureSafeReport(report);
  } catch (error) {
    if (error instanceof TokenLifecycleRefusal) {
      return ensureSafeReport(buildRefusalReport(error.code, error.message, parsed?.mode ?? options.mode ?? 'unknown'));
    }
    return ensureSafeReport(buildRefusalReport('unexpected_wrapper_error', 'Unexpected wrapper error', parsed?.mode ?? options.mode ?? 'unknown'));
  }
}

export function resolveSafeTokenLifecycleReportPath(outputPath, buildRoot = DEFAULT_BUILD_ROOT) {
  if (!outputPath || typeof outputPath !== 'string') {
    throw new TokenLifecycleRefusal('missing_output_path', 'Report output path is required');
  }
  assertNoUnsafeTokenLifecycleText(outputPath);
  const root = resolve(buildRoot);
  const target = resolve(outputPath);
  if (target !== root && !target.startsWith(root + sep)) {
    throw new TokenLifecycleRefusal('unsafe_output_path', 'Report output must stay under the ZLAR build scratch root');
  }
  if (existsSync(target)) {
    throw new TokenLifecycleRefusal('output_exists', 'Report output already exists');
  }
  return target;
}

export function writeGithubAppTokenLifecycleReport(report, outputPath, options = {}) {
  const safeReport = ensureSafeReport(report);
  const target = resolveSafeTokenLifecycleReportPath(outputPath, options.buildRoot ?? DEFAULT_BUILD_ROOT);
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  writeFileSync(target, `${JSON.stringify(safeReport, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return target;
}

export function formatGithubAppTokenLifecycleReport(report) {
  const lines = [
    `report_type: ${report.report_type}`,
    `wrapper_contract: ${report.wrapper_contract}`,
    `mode: ${report.mode}`,
    `lifecycle_status: ${report.lifecycle_status}`,
  ];
  if (report.refusal_reason_code) lines.push(`refusal_reason_code: ${report.refusal_reason_code}`);
  if (report.app) {
    lines.push(`app_name: ${report.app.name}`);
    lines.push(`app_id: ${report.app.app_id}`);
    lines.push(`selected_repo: ${report.app.selected_repo}`);
    lines.push('custody_target: metadata-only path string; private key file not touched');
  }
  lines.push('no_secret_guarantees: true');
  lines.push('chat2_review_required_before_live_token_authority: true');
  return `${lines.join('\n')}\n`;
}
