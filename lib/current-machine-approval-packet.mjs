import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { canonicalize } from './canonicalize.mjs';
import { sha256hex } from './receipt.mjs';

export const CURRENT_MACHINE_APPROVAL_PACKET_TYPE =
  'zlar-current-machine-approval-packet-v1';
export const CURRENT_MACHINE_APPROVAL_PACKET_VERIFICATION_TYPE =
  'zlar-current-machine-approval-packet-verification-v1';
export const CURRENT_MACHINE_APPROVAL_PACKET_ID =
  'claude-code-current-machine-approval-packet-private-core-v3.4.55';
export const CURRENT_MACHINE_APPROVAL_PACKET_SHA256 =
  '7012e6e6bb8e89358363ce073422bb74f30ee63af50be5870eace96e6f672e68';
export const CURRENT_MACHINE_APPROVAL_PACKET_SCHEMA_VERSION = 1;
export const CURRENT_MACHINE_APPROVAL_PACKET_CANONICALIZATION = 'zlar-canonical-json-v1';
export const CURRENT_MACHINE_APPROVAL_PACKET_SURFACE = 'claude_code';
export const CURRENT_MACHINE_APPROVAL_PACKET_SURFACE_LABEL = 'Claude Code';
export const CURRENT_MACHINE_APPROVAL_PACKET_SOURCE_DESIGN =
  'install.sh --surface claude-code --dry-run --json current_machine_governance_design';
export const CURRENT_MACHINE_APPROVAL_PACKET_BOARDING_RULE =
  'recognized boarding credential can be minted only by a routed hook/gate passage for the selected surface; this verifier cannot mint receipts';
export const CURRENT_MACHINE_APPROVAL_PACKET_SOURCE_KIND =
  'private_core_release_checkpoint';
export const CURRENT_MACHINE_APPROVAL_PACKET_TARGET_COMMIT_SHA =
  'b89b0c2e2d79db4981cad69af4a190e9c77fb089';
export const CURRENT_MACHINE_APPROVAL_PACKET_TARGET_TREE_SHA =
  '91eaff8cc48b905192ddc238b6c9a9049a9efbee';
export const CURRENT_MACHINE_APPROVAL_PACKET_TARGET_VERSION = '3.4.55';
export const CURRENT_MACHINE_APPROVAL_PACKET_SOURCE_STATE =
  'private_core_v3.4.55_fixture_not_install_authority';
export const CURRENT_MACHINE_APPROVAL_PACKET_PRIVATE_CORE_TAG = 'v3.4.55';
export const CURRENT_MACHINE_APPROVAL_PACKET_PRIVATE_CORE_TAG_OBJECT_SHA =
  'fe16ef4d22a09fdb282898cb029bd25eefde24f5';
export const CURRENT_MACHINE_APPROVAL_PACKET_INSTALLER_BLOB_SHA =
  '295a71e6e6c1fd331c90f1c2f43d21903bc18057';
export const CURRENT_MACHINE_APPROVAL_PACKET_INSTALLER_SHA256 =
  '62fe23e17864cace9b76e706792bd3849f8be76df6bd3ef2be09f42ec52b27e2';
export const CURRENT_MACHINE_APPROVAL_PACKET_DRY_RUN_PLAN_SHA256 =
  '1f1eb0150d6117e3036595a593b6eec87a5ce225796350702a3201e4447c64ea';
export const CURRENT_MACHINE_APPROVAL_PACKET_PLANNED_WRITES_SHA256 =
  '32fa855729357903f7855301c5a0b92ac632029bb14c35a75b86ec15c2560198';
export const CURRENT_MACHINE_APPROVAL_PACKET_WRITE_EFFECTS_SHA256 =
  'a90e1e5a66929231376bb37a9e9dec970736374b4b61232628bf159632968a33';
export const CURRENT_MACHINE_APPROVAL_PACKET_REQUEST_ID =
  'claude-code-current-machine-approval-request-private-core-v3.4.55-fixture-v1';
export const CURRENT_MACHINE_APPROVAL_PACKET_ISSUED_AT =
  '2099-12-30T00:00:00Z';
export const CURRENT_MACHINE_APPROVAL_PACKET_EXPIRES_AT =
  '2099-12-31T00:00:00Z';
export const CURRENT_MACHINE_APPROVAL_PACKET_TTL_SECONDS = 86400;
export const CURRENT_MACHINE_APPROVAL_PACKET_NONCE_SHA256 =
  'fe51851183aeef5e2d453a8d38b01dcb83d17cf6ae5374a166b3f6860272f9f3';
export const CURRENT_MACHINE_APPROVAL_PACKET_REPLAY_SCOPE =
  'claude-code-private-core-v3.4.55-single-use-authority-request-fixture';
export const CURRENT_MACHINE_APPROVAL_PACKET_POLICY_SHA256 =
  '5fe78410bdbac8b1b91c062ca5c0f710194939da9dd8eb0140ba54af1525f0b0';

export const CURRENT_MACHINE_APPROVAL_PACKET_SAFE_CLAIM_CEILING =
  'ZLAR can verify that a Claude Code current-machine approval packet names the selected surface, hook target, issuer/policy, receipt path, downstream refusal matrix, source target, installer identity, command posture, plan identity, freshness/replay guard, backup/rollback requirements, and explicit non-claims before any install or configuration authority is requested.';

export const REQUIRED_CURRENT_MACHINE_APPROVAL_REFUSAL_REASONS = Object.freeze([
  'receipt_missing',
  'receipt_invalid',
  'receipt_stale_or_expired',
  'receipt_replay',
  'unknown_issuer',
  'issuer_not_active',
  'policy_not_recognized',
  'surface_not_recognized',
  'terminal_not_recognized',
  'detail_hash_mismatch',
  'unsupported_receipt_format',
  'request_stream_authority_material',
  'authority_request_missing',
  'authority_request_invalid',
  'authority_request_expired',
  'authority_request_replay',
  'wrong_request',
  'wrong_policy',
  'wrong_profile',
  'wrong_surface',
  'wrong_terminal',
  'unrecognized_authority_material',
  'summary_only_authority_material',
  'tampered_authority_material',
  'false_boundary_flip',
  'target_source_mismatch',
  'installer_identity_mismatch',
  'dry_run_plan_identity_mismatch',
  'backup_rollback_missing',
]);

export const REQUIRED_CURRENT_MACHINE_APPROVAL_NON_CLAIMS = Object.freeze([
  'This packet is not installation or activation.',
  'This packet does not prove current-machine governance.',
  'This packet does not prove the current invocation crossed a hook.',
  'This packet does not prove live downstream recognition or live records-system coverage.',
  'This packet does not prove production authority, enterprise readiness, external attestation, or sovereign recognition.',
  'This packet does not close unrouted side doors.',
]);

const FALSE_AUTHORITY_FIELDS = Object.freeze([
  'install_or_activation_applied',
  'hook_profile_written',
  'user_config_written',
  'machine_config_written',
  'service_started',
  'secrets_or_signing_material_changed',
  'telegram_used',
  'github_settings_changed',
  'website_publication',
  'current_machine_governance_evidence',
  'live_downstream_recognition_evidence',
  'external_attestation',
]);

const ZLAR_REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));

const UNSAFE_OUTPUT_PATTERNS = Object.freeze([
  { label: 'private operator path', pattern: /\/Users\/[^\s"'`]+/ },
  { label: 'home path', pattern: /\/home\/[^\s"'`]+/ },
  { label: 'private path', pattern: /\/private\/[^\s"'`]+/ },
  { label: 'temp path', pattern: /\/tmp\/[^\s"'`]+/ },
  { label: 'var path', pattern: /\/var\/[^\s"'`]+/ },
  { label: 'private key material', pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
  { label: 'public key material', pattern: /BEGIN PUBLIC KEY/ },
  { label: 'key-value credential', pattern: /\b(?:token|secret|password|api[_-]?key)\s*[:=]\s*[^&\s"'`,;})\]]+/i },
  { label: 'authorization credential', pattern: /\bauthorization\s*[:=]\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}/i },
  { label: 'GitHub token', pattern: /\bghp_[A-Za-z0-9_]{10,}\b/ },
  { label: 'GitHub fine-grained token', pattern: /\bgithub_pat_[A-Za-z0-9_]{10,}\b/ },
  { label: 'Slack token', pattern: /\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b/ },
  { label: 'AWS access key', pattern: /\bAKIA[0-9A-Z]{12,}\b/ },
  { label: 'OpenAI-style key', pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/ },
  { label: 'bot token', pattern: /\bbot[0-9]{6,}:[A-Za-z0-9_-]{6,}\b/ },
]);

export function assertNoUnsafeCurrentMachineApprovalPacketText(text) {
  if (typeof text !== 'string') {
    throw new Error('Current-machine approval packet text must be a string');
  }
  for (const { label, pattern } of UNSAFE_OUTPUT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`Current-machine approval packet contains unsafe ${label}`);
    }
  }
  return true;
}

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

function assertNonEmptyString(label, value) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return true;
}

function assertBoolean(label, value, expected) {
  if (typeof value !== 'boolean') {
    throw new Error(`${label} must be a boolean`);
  }
  if (arguments.length === 3 && value !== expected) {
    throw new Error(`${label} must be ${expected}`);
  }
  return true;
}

function assertSha256(label, value) {
  if (!/^[a-f0-9]{64}$/.test(value || '')) {
    throw new Error(`${label} must be a lowercase SHA-256 hex string`);
  }
  return true;
}

function assertGitSha(label, value) {
  if (!/^[a-f0-9]{40}$/.test(value || '')) {
    throw new Error(`${label} must be a lowercase Git object hex string`);
  }
  return true;
}

function assertNoAnglePlaceholder(label, value) {
  assertNonEmptyString(label, value);
  if (/[<>]/.test(value)) {
    throw new Error(`${label} must not be a placeholder`);
  }
  return true;
}

function assertNonEmptyStringArray(label, value) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${label} must be a non-empty array`);
  }
  for (const item of value) {
    assertNonEmptyString(label, item);
  }
  return true;
}

function assertIsoTimestamp(label, value) {
  assertNonEmptyString(label, value);
  if (Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} must be an ISO timestamp`);
  }
  return true;
}

function timestampMs(label, value) {
  assertIsoTimestamp(label, value);
  return Date.parse(value);
}

function withoutKeys(value, keys) {
  return Object.fromEntries(
    Object.entries(value).filter(([key]) => !keys.includes(key))
  );
}

function expectedSourceManifestSha256(sourceTarget, installerIdentity) {
  return sha256hex(canonicalize({
    source_target: withoutKeys(sourceTarget, ['source_manifest_sha256']),
    installer_identity: installerIdentity,
  }));
}

function expectedDryRunPlanSha256(planIdentity) {
  return sha256hex(canonicalize(withoutKeys(planIdentity, ['plan_sha256'])));
}

function expectedAuthorityRequestSha256(packet) {
  return sha256hex(canonicalize({
    packet_type: packet.packet_type,
    packet_id: packet.packet_id,
    selected_surface: packet.selected_surface,
    hook_target: packet.hook_target,
    source_target: packet.source_target,
    installer_identity: packet.installer_identity,
    command_posture: packet.command_posture,
    dry_run_plan_identity: packet.dry_run_plan_identity,
    authority_request_identity: withoutKeys(packet.authority_request_identity, ['request_sha256']),
    backup_rollback_requirements: packet.backup_rollback_requirements,
  }));
}

function expectedAuthorityRequestSha256FromVerification(verification) {
  return sha256hex(canonicalize({
    packet_type: verification.packet_type,
    packet_id: verification.packet_id,
    selected_surface: {
      selected_surface: verification.selected_surface,
      surface_label: CURRENT_MACHINE_APPROVAL_PACKET_SURFACE_LABEL,
      single_surface_scope: verification.single_surface_scope,
      source_design: CURRENT_MACHINE_APPROVAL_PACKET_SOURCE_DESIGN,
      live_surface_probe_performed: verification.live_surface_probe_performed,
    },
    hook_target: {
      hook_profile_path: verification.hook_profile_path,
      hook_event: verification.hook_event,
      hook_command_target: verification.hook_command_target,
      delegation_target: verification.delegation_target,
      expected_executable: true,
      hook_target_verified_by_live_read: verification.hook_target_verified_by_live_read,
      writes_hook_profile: false,
    },
    source_target: verification.source_target,
    installer_identity: verification.installer_identity,
    command_posture: verification.command_posture,
    dry_run_plan_identity: verification.dry_run_plan_identity,
    authority_request_identity: withoutKeys(verification.authority_request_identity, ['request_sha256']),
    backup_rollback_requirements: verification.backup_rollback_requirements,
  }));
}

function gitOutput(args, { trim = true } = {}) {
  try {
    const output = execFileSync('git', ['-C', ZLAR_REPO_ROOT, ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    return trim ? output.trimEnd() : output;
  } catch {
    throw new Error('Current-machine approval source target could not be verified against local Git objects');
  }
}

function assertLocalGitSourceIdentity(sourceTarget, installerIdentity) {
  const targetTree = gitOutput(['rev-parse', `${sourceTarget.target_commit_sha}^{tree}`]).trim();
  if (targetTree !== sourceTarget.target_tree_sha) {
    throw new Error('Current-machine approval target tree SHA mismatch against local Git object');
  }
  const installerTreeLine = gitOutput(['ls-tree', sourceTarget.target_commit_sha, installerIdentity.installer_path]).trim();
  const installerBlob = installerTreeLine.split(/\s+/)[2] || '';
  if (installerBlob !== installerIdentity.installer_git_blob_sha) {
    throw new Error('Current-machine approval installer Git blob SHA mismatch against local Git object');
  }
  const installerContent = gitOutput(
    ['show', `${sourceTarget.target_commit_sha}:${installerIdentity.installer_path}`],
    { trim: false }
  );
  if (sha256hex(installerContent) !== installerIdentity.installer_sha256) {
    throw new Error('Current-machine approval installer SHA-256 mismatch against local Git object');
  }
  return true;
}

function assertLocalGitPrivateCoreReleaseIdentity(sourceTarget) {
  const tagRef = `refs/tags/${sourceTarget.published_release_tag}`;
  const tagObject = gitOutput(['rev-parse', tagRef]).trim();
  if (tagObject !== sourceTarget.published_release_tag_object_sha) {
    throw new Error('Current-machine approval private-core tag object SHA mismatch against local Git object');
  }
  const peeledCommit = gitOutput(['rev-parse', `${tagRef}^{}`]).trim();
  if (peeledCommit !== sourceTarget.published_release_commit_sha) {
    throw new Error('Current-machine approval private-core tag peeled commit mismatch against local Git object');
  }
  if (peeledCommit !== sourceTarget.target_commit_sha) {
    throw new Error('Current-machine approval private-core tag must peel to the target commit');
  }
  return true;
}

function refusalMatrixByReason(matrix) {
  if (!Array.isArray(matrix)) {
    throw new Error('Current-machine approval downstream refusal matrix must be an array');
  }
  const byReason = new Map();
  for (const item of matrix) {
    assertExactKeys('Current-machine approval downstream refusal matrix item', item, [
      'effect_mutation_allowed',
      'reason_code',
      'recognized_receipt_required',
      'refuses_before_effect',
    ]);
    assertNonEmptyString('Current-machine approval refusal reason code', item.reason_code);
    if (byReason.has(item.reason_code)) {
      throw new Error(`Current-machine approval downstream refusal matrix duplicates ${item.reason_code}`);
    }
    assertBoolean(`Current-machine approval ${item.reason_code} refuses_before_effect`, item.refuses_before_effect, true);
    assertBoolean(`Current-machine approval ${item.reason_code} recognized_receipt_required`, item.recognized_receipt_required, true);
    assertBoolean(`Current-machine approval ${item.reason_code} effect_mutation_allowed`, item.effect_mutation_allowed, false);
    byReason.set(item.reason_code, item);
  }
  return byReason;
}

function assertCurrentMachineApprovalSelectedSurface(surface) {
  assertExactKeys('Current-machine approval selected surface', surface, [
    'live_surface_probe_performed',
    'selected_surface',
    'single_surface_scope',
    'source_design',
    'surface_label',
  ]);
  if (surface.selected_surface !== CURRENT_MACHINE_APPROVAL_PACKET_SURFACE) {
    throw new Error('Current-machine approval packet must select claude_code');
  }
  if (surface.surface_label !== CURRENT_MACHINE_APPROVAL_PACKET_SURFACE_LABEL) {
    throw new Error('Current-machine approval selected surface label drifted');
  }
  assertBoolean('Current-machine approval selected surface single_surface_scope', surface.single_surface_scope, true);
  assertBoolean('Current-machine approval live surface probe performed', surface.live_surface_probe_performed, false);
  if (surface.source_design !== CURRENT_MACHINE_APPROVAL_PACKET_SOURCE_DESIGN) {
    throw new Error('Current-machine approval selected surface source design drifted');
  }
  return true;
}

function assertCurrentMachineApprovalHookTarget(hookTarget) {
  assertExactKeys('Current-machine approval hook target', hookTarget, [
    'delegation_target',
    'expected_executable',
    'hook_command_target',
    'hook_event',
    'hook_profile_path',
    'hook_target_verified_by_live_read',
    'writes_hook_profile',
  ]);
  if (hookTarget.hook_event !== 'PreToolUse') {
    throw new Error('Current-machine approval hook event must be PreToolUse');
  }
  if (hookTarget.hook_profile_path !== '~/.claude/settings.json') {
    throw new Error('Current-machine approval hook profile path must be ~/.claude/settings.json');
  }
  if (hookTarget.hook_command_target !== '~/.zlar/adapters/claude-code/hook.sh') {
    throw new Error('Current-machine approval hook command target must be ~/.zlar/adapters/claude-code/hook.sh');
  }
  if (hookTarget.delegation_target !== '~/.zlar/bin/zlar-gate') {
    throw new Error('Current-machine approval hook delegation target must be ~/.zlar/bin/zlar-gate');
  }
  assertNonEmptyString('Current-machine approval hook profile path', hookTarget.hook_profile_path);
  assertNonEmptyString('Current-machine approval hook command target', hookTarget.hook_command_target);
  assertNonEmptyString('Current-machine approval hook delegation target', hookTarget.delegation_target);
  assertBoolean('Current-machine approval hook expected executable', hookTarget.expected_executable, true);
  assertBoolean('Current-machine approval hook target verified by live read', hookTarget.hook_target_verified_by_live_read, false);
  assertBoolean('Current-machine approval writes hook profile', hookTarget.writes_hook_profile, false);
  return true;
}

function assertCurrentMachineApprovalSourceTarget(sourceTarget) {
  assertExactKeys('Current-machine approval source target', sourceTarget, [
    'dirty_worktree_allowed',
    'published_release_claimed',
    'published_release_commit_sha',
    'published_release_tag',
    'published_release_tag_object_sha',
    'repo_url',
    'source_kind',
    'source_manifest_sha256',
    'source_state',
    'target_commit_sha',
    'target_tree_sha',
    'target_version',
  ]);
  if (sourceTarget.repo_url !== 'https://github.com/ZLAR-AI/ZLAR') {
    throw new Error('Current-machine approval source repo URL drifted');
  }
  if (sourceTarget.source_kind !== CURRENT_MACHINE_APPROVAL_PACKET_SOURCE_KIND) {
    throw new Error('Current-machine approval source kind must be private_core_release_checkpoint');
  }
  if (sourceTarget.source_state !== CURRENT_MACHINE_APPROVAL_PACKET_SOURCE_STATE) {
    throw new Error('Current-machine approval source state must be the v3.4.55 private-core fixture state');
  }
  assertGitSha('Current-machine approval target commit SHA', sourceTarget.target_commit_sha);
  assertGitSha('Current-machine approval target tree SHA', sourceTarget.target_tree_sha);
  if (sourceTarget.target_commit_sha !== CURRENT_MACHINE_APPROVAL_PACKET_TARGET_COMMIT_SHA) {
    throw new Error('Current-machine approval target commit SHA is not the expected fixture target');
  }
  if (sourceTarget.target_tree_sha !== CURRENT_MACHINE_APPROVAL_PACKET_TARGET_TREE_SHA) {
    throw new Error('Current-machine approval target tree SHA is not the expected fixture target');
  }
  assertNonEmptyString('Current-machine approval target version', sourceTarget.target_version);
  if (sourceTarget.target_version !== CURRENT_MACHINE_APPROVAL_PACKET_TARGET_VERSION) {
    throw new Error('Current-machine approval target version is not the expected fixture version');
  }
  assertBoolean('Current-machine approval dirty worktree allowed', sourceTarget.dirty_worktree_allowed, false);
  assertBoolean('Current-machine approval private-core release claimed', sourceTarget.published_release_claimed, true);
  if (sourceTarget.published_release_tag !== CURRENT_MACHINE_APPROVAL_PACKET_PRIVATE_CORE_TAG) {
    throw new Error('Current-machine approval private-core release tag mismatch');
  }
  if (sourceTarget.published_release_commit_sha !== CURRENT_MACHINE_APPROVAL_PACKET_TARGET_COMMIT_SHA) {
    throw new Error('Current-machine approval private-core release commit mismatch');
  }
  if (sourceTarget.published_release_tag_object_sha !== CURRENT_MACHINE_APPROVAL_PACKET_PRIVATE_CORE_TAG_OBJECT_SHA) {
    throw new Error('Current-machine approval private-core release tag object mismatch');
  }
  assertSha256('Current-machine approval source manifest SHA-256', sourceTarget.source_manifest_sha256);
  return true;
}

function assertCurrentMachineApprovalInstallerIdentity(installerIdentity) {
  assertExactKeys('Current-machine approval installer identity', installerIdentity, [
    'installer_executable_expected',
    'installer_git_blob_sha',
    'installer_identity_verified_live',
    'installer_path',
    'installer_sha256',
    'installer_source_commit_sha',
  ]);
  if (installerIdentity.installer_path !== 'install.sh') {
    throw new Error('Current-machine approval installer path drifted');
  }
  assertGitSha('Current-machine approval installer Git blob SHA', installerIdentity.installer_git_blob_sha);
  if (installerIdentity.installer_git_blob_sha !== CURRENT_MACHINE_APPROVAL_PACKET_INSTALLER_BLOB_SHA) {
    throw new Error('Current-machine approval installer Git blob SHA is not the expected fixture blob');
  }
  assertSha256('Current-machine approval installer SHA-256', installerIdentity.installer_sha256);
  if (installerIdentity.installer_sha256 !== CURRENT_MACHINE_APPROVAL_PACKET_INSTALLER_SHA256) {
    throw new Error('Current-machine approval installer SHA-256 is not the expected fixture installer');
  }
  assertGitSha(
    'Current-machine approval installer source commit SHA',
    installerIdentity.installer_source_commit_sha
  );
  if (installerIdentity.installer_source_commit_sha !== CURRENT_MACHINE_APPROVAL_PACKET_TARGET_COMMIT_SHA) {
    throw new Error('Current-machine approval installer source commit SHA is not the expected fixture target');
  }
  assertBoolean(
    'Current-machine approval installer executable expected',
    installerIdentity.installer_executable_expected,
    true
  );
  assertBoolean(
    'Current-machine approval installer identity verified live',
    installerIdentity.installer_identity_verified_live,
    false
  );
  return true;
}

function assertCurrentMachineApprovalCommandPosture(commandPosture) {
  assertExactKeys('Current-machine approval command posture', commandPosture, [
    'curl_pipe_allowed',
    'dry_run_argv',
    'existing_install_mode',
    'latest_or_remote_fetch_allowed',
    'machine_helpers_allowed',
    'no_machine_helpers',
    'real_install_argv',
    'selected_surface',
    'single_surface_scope',
  ]);
  assertExactArray('Current-machine approval dry-run argv', commandPosture.dry_run_argv, [
    'bash',
    'install.sh',
    '--surface',
    'claude-code',
    '--no-machine-helpers',
    '--dry-run',
    '--json',
    '--existing-install',
    'repair',
  ]);
  assertExactArray('Current-machine approval real install argv', commandPosture.real_install_argv, [
    'bash',
    'install.sh',
    '--surface',
    'claude-code',
    '--no-machine-helpers',
    '--existing-install',
    'repair',
  ]);
  if (commandPosture.selected_surface !== CURRENT_MACHINE_APPROVAL_PACKET_SURFACE) {
    throw new Error('Current-machine approval command posture must select claude_code');
  }
  if (commandPosture.existing_install_mode !== 'repair') {
    throw new Error('Current-machine approval existing-install mode drifted');
  }
  assertBoolean('Current-machine approval command single-surface scope', commandPosture.single_surface_scope, true);
  assertBoolean('Current-machine approval command no-machine-helpers', commandPosture.no_machine_helpers, true);
  assertBoolean('Current-machine approval command machine helpers allowed', commandPosture.machine_helpers_allowed, false);
  assertBoolean('Current-machine approval command curl pipe allowed', commandPosture.curl_pipe_allowed, false);
  assertBoolean(
    'Current-machine approval command latest or remote fetch allowed',
    commandPosture.latest_or_remote_fetch_allowed,
    false
  );
  return true;
}

function assertCurrentMachineApprovalDryRunPlanIdentity(planIdentity) {
  assertExactKeys('Current-machine approval dry-run plan identity', planIdentity, [
    'dry_run_performed_by_packet_verifier',
    'no_write_plan',
    'plan_canonicalization',
    'plan_command',
    'plan_schema_version',
    'plan_sha256',
    'plan_type',
    'planned_writes_sha256',
    'selected_surface',
    'write_effects_sha256',
  ]);
  if (planIdentity.plan_type !== 'zlar-install-plan-v1') {
    throw new Error('Current-machine approval dry-run plan type drifted');
  }
  if (planIdentity.plan_schema_version !== 1) {
    throw new Error('Current-machine approval dry-run plan schema version drifted');
  }
  if (planIdentity.plan_canonicalization !== CURRENT_MACHINE_APPROVAL_PACKET_CANONICALIZATION) {
    throw new Error('Current-machine approval dry-run plan canonicalization drifted');
  }
  if (
    planIdentity.plan_command !==
    'install.sh --dry-run --json --surface claude_code --no-machine-helpers --existing-install repair'
  ) {
    throw new Error('Current-machine approval dry-run plan command drifted');
  }
  if (planIdentity.selected_surface !== CURRENT_MACHINE_APPROVAL_PACKET_SURFACE) {
    throw new Error('Current-machine approval dry-run plan must select claude_code');
  }
  assertSha256('Current-machine approval dry-run plan SHA-256', planIdentity.plan_sha256);
  if (planIdentity.plan_sha256 !== expectedDryRunPlanSha256(planIdentity)) {
    throw new Error('Current-machine approval dry-run plan SHA-256 mismatch');
  }
  if (planIdentity.plan_sha256 !== CURRENT_MACHINE_APPROVAL_PACKET_DRY_RUN_PLAN_SHA256) {
    throw new Error('Current-machine approval dry-run plan SHA-256 is not the expected fixture plan');
  }
  assertSha256(
    'Current-machine approval dry-run planned writes SHA-256',
    planIdentity.planned_writes_sha256
  );
  if (planIdentity.planned_writes_sha256 !== CURRENT_MACHINE_APPROVAL_PACKET_PLANNED_WRITES_SHA256) {
    throw new Error('Current-machine approval planned writes SHA-256 is not the expected fixture plan');
  }
  assertSha256(
    'Current-machine approval dry-run write effects SHA-256',
    planIdentity.write_effects_sha256
  );
  if (planIdentity.write_effects_sha256 !== CURRENT_MACHINE_APPROVAL_PACKET_WRITE_EFFECTS_SHA256) {
    throw new Error('Current-machine approval write effects SHA-256 is not the expected fixture plan');
  }
  assertBoolean(
    'Current-machine approval dry-run performed by packet verifier',
    planIdentity.dry_run_performed_by_packet_verifier,
    false
  );
  assertBoolean('Current-machine approval no-write plan', planIdentity.no_write_plan, true);
  return true;
}

function assertCurrentMachineApprovalAuthorityRequestIdentity(identity, options = {}) {
  const { enforceFreshness = true } = options;
  assertExactKeys('Current-machine approval authority request identity', identity, [
    'authority_request_made',
    'expires_at',
    'issued_at',
    'nonce_sha256',
    'replay_guard_required',
    'replay_scope',
    'request_id',
    'request_sha256',
    'single_use',
    'summary_only_authority_material_allowed',
    'ttl_seconds',
  ]);
  assertNoAnglePlaceholder('Current-machine approval request id', identity.request_id);
  if (identity.request_id !== CURRENT_MACHINE_APPROVAL_PACKET_REQUEST_ID) {
    throw new Error('Current-machine approval request id is not the expected fixture request');
  }
  const issuedMs = timestampMs('Current-machine approval issued at', identity.issued_at);
  const expiresMs = timestampMs('Current-machine approval expires at', identity.expires_at);
  if (identity.issued_at !== CURRENT_MACHINE_APPROVAL_PACKET_ISSUED_AT) {
    throw new Error('Current-machine approval issue time is not the expected fixture request');
  }
  if (identity.expires_at !== CURRENT_MACHINE_APPROVAL_PACKET_EXPIRES_AT) {
    throw new Error('Current-machine approval expiry time is not the expected fixture request');
  }
  if (expiresMs <= issuedMs) {
    throw new Error('Current-machine approval request expiry must be after issue time');
  }
  if (!Number.isInteger(identity.ttl_seconds) || identity.ttl_seconds <= 0 || identity.ttl_seconds > 86400) {
    throw new Error('Current-machine approval request TTL must be a positive integer <= 86400');
  }
  if (identity.ttl_seconds !== CURRENT_MACHINE_APPROVAL_PACKET_TTL_SECONDS) {
    throw new Error('Current-machine approval request TTL is not the expected fixture request');
  }
  if (expiresMs - issuedMs !== identity.ttl_seconds * 1000) {
    throw new Error('Current-machine approval request TTL must match issue/expiry window');
  }
  if (enforceFreshness) {
    const nowMs = Date.now();
    if (expiresMs <= nowMs) {
      throw new Error('Current-machine approval request expired before verification time');
    }
  }
  assertSha256('Current-machine approval nonce SHA-256', identity.nonce_sha256);
  if (identity.nonce_sha256 !== CURRENT_MACHINE_APPROVAL_PACKET_NONCE_SHA256) {
    throw new Error('Current-machine approval nonce SHA-256 is not the expected fixture nonce');
  }
  assertSha256('Current-machine approval request SHA-256', identity.request_sha256);
  assertNoAnglePlaceholder('Current-machine approval replay scope', identity.replay_scope);
  if (identity.replay_scope !== CURRENT_MACHINE_APPROVAL_PACKET_REPLAY_SCOPE) {
    throw new Error('Current-machine approval replay scope is not the expected fixture scope');
  }
  assertBoolean('Current-machine approval authority request made', identity.authority_request_made, false);
  assertBoolean('Current-machine approval replay guard required', identity.replay_guard_required, true);
  assertBoolean('Current-machine approval single use', identity.single_use, true);
  assertBoolean(
    'Current-machine approval summary-only authority material allowed',
    identity.summary_only_authority_material_allowed,
    false
  );
  return true;
}

function assertCurrentMachineApprovalBackupRollback(requirements) {
  assertExactKeys('Current-machine approval backup/rollback requirements', requirements, [
    'backup_artifact_identity_required',
    'backup_created_by_installer',
    'backup_required_before_mutation',
    'backup_scope',
    'installer_backup_enforcement_present',
    'mutation_refuses_without_backup_ack',
    'rollback_authority_required',
    'rollback_plan_identity_required',
    'rollback_plan_required',
  ]);
  assertBoolean(
    'Current-machine approval backup required before mutation',
    requirements.backup_required_before_mutation,
    true
  );
  assertBoolean(
    'Current-machine approval backup artifact identity required',
    requirements.backup_artifact_identity_required,
    true
  );
  assertBoolean(
    'Current-machine approval backup created by installer',
    requirements.backup_created_by_installer,
    false
  );
  assertBoolean(
    'Current-machine approval rollback plan required',
    requirements.rollback_plan_required,
    true
  );
  assertBoolean(
    'Current-machine approval rollback plan identity required',
    requirements.rollback_plan_identity_required,
    true
  );
  assertBoolean(
    'Current-machine approval rollback authority required',
    requirements.rollback_authority_required,
    true
  );
  assertBoolean(
    'Current-machine approval mutation refuses without backup ack',
    requirements.mutation_refuses_without_backup_ack,
    true
  );
  assertBoolean(
    'Current-machine approval installer backup enforcement present',
    requirements.installer_backup_enforcement_present,
    false
  );
  assertNonEmptyStringArray('Current-machine approval backup scope', requirements.backup_scope);
  for (const requiredPath of ['~/.zlar', '~/.zlar-signing.key', '~/.claude/settings.json']) {
    if (!requirements.backup_scope.includes(requiredPath)) {
      throw new Error(`Current-machine approval backup scope missing ${requiredPath}`);
    }
  }
  return true;
}

function assertCurrentMachineApprovalIssuerPolicy(issuerPolicy) {
  assertExactKeys('Current-machine approval issuer/policy', issuerPolicy, [
    'issuer',
    'policy',
  ]);
  assertExactKeys('Current-machine approval issuer', issuerPolicy.issuer, [
    'issuer_id',
    'issuer_kid',
    'issuer_status_claim',
    'issuer_status_verified_live',
    'private_key_material_included',
    'public_key_material_included',
    'public_key_reference',
  ]);
  assertNonEmptyString('Current-machine approval issuer id', issuerPolicy.issuer.issuer_id);
  assertNonEmptyString('Current-machine approval issuer kid', issuerPolicy.issuer.issuer_kid);
  assertNonEmptyString('Current-machine approval issuer status claim', issuerPolicy.issuer.issuer_status_claim);
  assertNonEmptyString('Current-machine approval public key reference', issuerPolicy.issuer.public_key_reference);
  assertBoolean('Current-machine approval issuer status verified live', issuerPolicy.issuer.issuer_status_verified_live, false);
  assertBoolean('Current-machine approval public key material included', issuerPolicy.issuer.public_key_material_included, false);
  assertBoolean('Current-machine approval private key material included', issuerPolicy.issuer.private_key_material_included, false);

  assertExactKeys('Current-machine approval policy', issuerPolicy.policy, [
    'accepted_policy_version',
    'live_policy_signature_verified',
    'policy_id',
    'policy_material_included',
    'policy_sha256',
    'policy_signature_required',
    'policy_signature_verifier',
  ]);
  assertNonEmptyString('Current-machine approval policy id', issuerPolicy.policy.policy_id);
  assertNonEmptyString('Current-machine approval accepted policy version', issuerPolicy.policy.accepted_policy_version);
  assertSha256('Current-machine approval policy SHA-256', issuerPolicy.policy.policy_sha256);
  if (issuerPolicy.policy.policy_sha256 !== CURRENT_MACHINE_APPROVAL_PACKET_POLICY_SHA256) {
    throw new Error('Current-machine approval policy SHA-256 is not the expected v3.4.55 private-core policy identity');
  }
  assertNonEmptyString('Current-machine approval policy signature verifier', issuerPolicy.policy.policy_signature_verifier);
  assertBoolean('Current-machine approval policy signature required', issuerPolicy.policy.policy_signature_required, true);
  assertBoolean('Current-machine approval policy material included', issuerPolicy.policy.policy_material_included, false);
  assertBoolean('Current-machine approval live policy signature verified', issuerPolicy.policy.live_policy_signature_verified, false);
  return true;
}

function assertCurrentMachineApprovalReceiptPath(receiptPath) {
  assertExactKeys('Current-machine approval receipt path', receiptPath, [
    'boarding_credential_minted_by_verifier',
    'live_receipt_emission_verified',
    'receipt_emission_source',
    'receipt_format',
    'receipt_path',
    'recognized_receipt_required_for_boarding',
  ]);
  if (receiptPath.receipt_format !== 'zlar-receipt-v1') {
    throw new Error('Current-machine approval receipt format must be zlar-receipt-v1');
  }
  assertNonEmptyString('Current-machine approval receipt emission source', receiptPath.receipt_emission_source);
  assertNonEmptyString('Current-machine approval receipt path', receiptPath.receipt_path);
  assertBoolean('Current-machine approval recognized receipt required for boarding', receiptPath.recognized_receipt_required_for_boarding, true);
  assertBoolean('Current-machine approval boarding credential minted by verifier', receiptPath.boarding_credential_minted_by_verifier, false);
  assertBoolean('Current-machine approval live receipt emission verified', receiptPath.live_receipt_emission_verified, false);
  return true;
}

function assertCurrentMachineApprovalDownstreamRecognition(downstream) {
  assertExactKeys('Current-machine approval downstream recognition', downstream, [
    'freshness_window_seconds',
    'recognition_rule',
    'refusal_matrix',
    'refuses_before_effect',
    'replay_store',
    'terminal',
  ]);
  assertNonEmptyString('Current-machine approval downstream terminal', downstream.terminal);
  assertNonEmptyString('Current-machine approval downstream recognition rule', downstream.recognition_rule);
  if (!Number.isInteger(downstream.freshness_window_seconds) || downstream.freshness_window_seconds <= 0) {
    throw new Error('Current-machine approval freshness window must be a positive integer');
  }
  assertNonEmptyString('Current-machine approval downstream replay store', downstream.replay_store);
  assertBoolean('Current-machine approval downstream refuses before effect', downstream.refuses_before_effect, true);

  const byReason = refusalMatrixByReason(downstream.refusal_matrix);
  if (byReason.size !== REQUIRED_CURRENT_MACHINE_APPROVAL_REFUSAL_REASONS.length) {
    throw new Error('Current-machine approval downstream refusal matrix reason count drifted');
  }
  for (const reason of REQUIRED_CURRENT_MACHINE_APPROVAL_REFUSAL_REASONS) {
    if (!byReason.has(reason)) {
      throw new Error(`Current-machine approval downstream refusal matrix missing ${reason}`);
    }
  }
  return true;
}

function assertCurrentMachineApprovalAuthorityBoundary(boundary) {
  assertExactKeys('Current-machine approval authority boundary', boundary, [
    'approval_packet_complete_before_authority_request',
    'current_machine_governance_evidence',
    'external_attestation',
    'github_settings_changed',
    'hook_profile_written',
    'human_authority_required_before_install_or_config',
    'install_or_activation_applied',
    'live_downstream_recognition_evidence',
    'machine_config_written',
    'secrets_or_signing_material_changed',
    'service_started',
    'telegram_used',
    'user_config_written',
    'website_publication',
  ]);
  assertBoolean(
    'Current-machine approval packet complete before authority request',
    boundary.approval_packet_complete_before_authority_request,
    true
  );
  assertBoolean(
    'Current-machine approval human authority required before install or config',
    boundary.human_authority_required_before_install_or_config,
    true
  );
  for (const field of FALSE_AUTHORITY_FIELDS) {
    assertBoolean(`Current-machine approval authority boundary ${field}`, boundary[field], false);
  }
  return true;
}

export function currentMachineApprovalPacketSha256(packet) {
  assertCurrentMachineApprovalPacket(packet);
  return sha256hex(canonicalize(packet));
}

export function assertCurrentMachineApprovalPacket(packet) {
  assertExactKeys('Current-machine approval packet', packet, [
    'authority_request_identity',
    'authority_boundary',
    'backup_rollback_requirements',
    'boarding_credential_rule',
    'canonicalization',
    'command_posture',
    'downstream_recognition',
    'dry_run_plan_identity',
    'explicit_non_claims',
    'hook_target',
    'installer_identity',
    'issuer_policy',
    'packet_id',
    'packet_type',
    'receipt_path',
    'schema_version',
    'selected_surface',
    'source_target',
  ]);
  if (packet.packet_type !== CURRENT_MACHINE_APPROVAL_PACKET_TYPE) {
    throw new Error('Current-machine approval packet has the wrong packet type');
  }
  assertNonEmptyString('Current-machine approval packet id', packet.packet_id);
  if (packet.packet_id !== CURRENT_MACHINE_APPROVAL_PACKET_ID) {
    throw new Error('Current-machine approval packet id is not the expected fixture packet');
  }
  if (packet.schema_version !== CURRENT_MACHINE_APPROVAL_PACKET_SCHEMA_VERSION) {
    throw new Error('Current-machine approval packet schema version drifted');
  }
  if (packet.canonicalization !== CURRENT_MACHINE_APPROVAL_PACKET_CANONICALIZATION) {
    throw new Error('Current-machine approval packet canonicalization drifted');
  }
  if (packet.boarding_credential_rule !== CURRENT_MACHINE_APPROVAL_PACKET_BOARDING_RULE) {
    throw new Error('Current-machine approval packet boarding credential rule drifted');
  }
  assertCurrentMachineApprovalSelectedSurface(packet.selected_surface);
  assertCurrentMachineApprovalHookTarget(packet.hook_target);
  assertCurrentMachineApprovalSourceTarget(packet.source_target);
  assertCurrentMachineApprovalInstallerIdentity(packet.installer_identity);
  assertCurrentMachineApprovalCommandPosture(packet.command_posture);
  assertCurrentMachineApprovalDryRunPlanIdentity(packet.dry_run_plan_identity);
  assertCurrentMachineApprovalAuthorityRequestIdentity(packet.authority_request_identity);
  assertCurrentMachineApprovalBackupRollback(packet.backup_rollback_requirements);
  assertCurrentMachineApprovalIssuerPolicy(packet.issuer_policy);
  assertCurrentMachineApprovalReceiptPath(packet.receipt_path);
  assertCurrentMachineApprovalDownstreamRecognition(packet.downstream_recognition);
  assertCurrentMachineApprovalAuthorityBoundary(packet.authority_boundary);
  if (packet.installer_identity.installer_source_commit_sha !== packet.source_target.target_commit_sha) {
    throw new Error('Current-machine approval installer source commit must match target commit');
  }
  if (
    packet.source_target.source_manifest_sha256 !==
    expectedSourceManifestSha256(packet.source_target, packet.installer_identity)
  ) {
    throw new Error('Current-machine approval source manifest SHA-256 mismatch');
  }
  assertLocalGitSourceIdentity(packet.source_target, packet.installer_identity);
  assertLocalGitPrivateCoreReleaseIdentity(packet.source_target);
  if (packet.issuer_policy.policy.accepted_policy_version !== packet.source_target.target_version) {
    throw new Error('Current-machine approval accepted policy version must match target version');
  }
  if (
    packet.authority_request_identity.request_sha256 !==
    expectedAuthorityRequestSha256(packet)
  ) {
    throw new Error('Current-machine approval request SHA-256 mismatch');
  }
  assertExactArray(
    'Current-machine approval explicit non-claims',
    packet.explicit_non_claims,
    REQUIRED_CURRENT_MACHINE_APPROVAL_NON_CLAIMS
  );
  assertNoUnsafeCurrentMachineApprovalPacketText(JSON.stringify(packet));
  if (sha256hex(canonicalize(packet)) !== CURRENT_MACHINE_APPROVAL_PACKET_SHA256) {
    throw new Error('Current-machine approval packet SHA-256 is not the expected fixture packet');
  }
  return true;
}

export function parseCurrentMachineApprovalPacketText(text) {
  assertNoUnsafeCurrentMachineApprovalPacketText(text);
  let packet;
  try {
    packet = JSON.parse(text);
  } catch {
    throw new Error('Current-machine approval packet input is not valid JSON');
  }
  assertCurrentMachineApprovalPacket(packet);
  return packet;
}

export function verifyCurrentMachineApprovalPacket(packet) {
  assertCurrentMachineApprovalPacket(packet);
  const packetSha256 = currentMachineApprovalPacketSha256(packet);
  const verification = {
    verification_type: CURRENT_MACHINE_APPROVAL_PACKET_VERIFICATION_TYPE,
    verified: true,
    packet_complete: true,
    packet_type: packet.packet_type,
    packet_id: packet.packet_id,
    schema_version: packet.schema_version,
    canonicalization: packet.canonicalization,
    packet_sha256: packetSha256,
    safe_claim_ceiling: CURRENT_MACHINE_APPROVAL_PACKET_SAFE_CLAIM_CEILING,
    selected_surface: packet.selected_surface.selected_surface,
    single_surface_scope: packet.selected_surface.single_surface_scope,
    live_surface_probe_performed: packet.selected_surface.live_surface_probe_performed,
    hook_profile_path: packet.hook_target.hook_profile_path,
    hook_event: packet.hook_target.hook_event,
    hook_command_target: packet.hook_target.hook_command_target,
    delegation_target: packet.hook_target.delegation_target,
    hook_target_verified_by_live_read: packet.hook_target.hook_target_verified_by_live_read,
    hook_profile_written: packet.authority_boundary.hook_profile_written,
    source_target: packet.source_target,
    installer_identity: packet.installer_identity,
    command_posture: packet.command_posture,
    dry_run_plan_identity: packet.dry_run_plan_identity,
    authority_request_identity: packet.authority_request_identity,
    backup_rollback_requirements: packet.backup_rollback_requirements,
    issuer_id: packet.issuer_policy.issuer.issuer_id,
    issuer_kid: packet.issuer_policy.issuer.issuer_kid,
    issuer_status_claim: packet.issuer_policy.issuer.issuer_status_claim,
    issuer_status_verified_live: packet.issuer_policy.issuer.issuer_status_verified_live,
    public_key_material_included: packet.issuer_policy.issuer.public_key_material_included,
    private_key_material_included: packet.issuer_policy.issuer.private_key_material_included,
    policy_id: packet.issuer_policy.policy.policy_id,
    accepted_policy_version: packet.issuer_policy.policy.accepted_policy_version,
    policy_sha256: packet.issuer_policy.policy.policy_sha256,
    policy_signature_required: packet.issuer_policy.policy.policy_signature_required,
    live_policy_signature_verified: packet.issuer_policy.policy.live_policy_signature_verified,
    receipt_format: packet.receipt_path.receipt_format,
    receipt_emission_source: packet.receipt_path.receipt_emission_source,
    receipt_path: packet.receipt_path.receipt_path,
    recognized_receipt_required_for_boarding:
      packet.receipt_path.recognized_receipt_required_for_boarding,
    boarding_credential_minted_by_verifier:
      packet.receipt_path.boarding_credential_minted_by_verifier,
    live_receipt_emission_verified: packet.receipt_path.live_receipt_emission_verified,
    downstream_terminal: packet.downstream_recognition.terminal,
    downstream_refuses_before_effect: packet.downstream_recognition.refuses_before_effect,
    refusal_reason_count: packet.downstream_recognition.refusal_matrix.length,
    required_refusal_reason_count: REQUIRED_CURRENT_MACHINE_APPROVAL_REFUSAL_REASONS.length,
    refusal_matrix_complete: true,
    required_refusal_reasons: [...REQUIRED_CURRENT_MACHINE_APPROVAL_REFUSAL_REASONS],
    approval_packet_complete_before_authority_request:
      packet.authority_boundary.approval_packet_complete_before_authority_request,
    human_authority_required_before_install_or_config:
      packet.authority_boundary.human_authority_required_before_install_or_config,
    install_or_activation_applied: packet.authority_boundary.install_or_activation_applied,
    user_config_written: packet.authority_boundary.user_config_written,
    machine_config_written: packet.authority_boundary.machine_config_written,
    service_started: packet.authority_boundary.service_started,
    secrets_or_signing_material_changed:
      packet.authority_boundary.secrets_or_signing_material_changed,
    telegram_used: packet.authority_boundary.telegram_used,
    github_settings_changed: packet.authority_boundary.github_settings_changed,
    website_publication: packet.authority_boundary.website_publication,
    current_machine_governance_evidence:
      packet.authority_boundary.current_machine_governance_evidence,
    live_downstream_recognition_evidence:
      packet.authority_boundary.live_downstream_recognition_evidence,
    external_attestation: packet.authority_boundary.external_attestation,
    claim_boundary:
      'approval-packet completeness only; no install, activation, hook execution, live receipt emission, or current-machine governance evidence',
    non_claims: [...packet.explicit_non_claims],
  };
  assertNoUnsafeCurrentMachineApprovalPacketText(JSON.stringify(verification));
  return verification;
}

export function assertCurrentMachineApprovalPacketVerification(verification) {
  assertExactKeys('Current-machine approval packet verification', verification, [
    'accepted_policy_version',
    'approval_packet_complete_before_authority_request',
    'boarding_credential_minted_by_verifier',
    'canonicalization',
    'claim_boundary',
    'current_machine_governance_evidence',
    'authority_request_identity',
    'backup_rollback_requirements',
    'command_posture',
    'delegation_target',
    'downstream_refuses_before_effect',
    'downstream_terminal',
    'dry_run_plan_identity',
    'external_attestation',
    'github_settings_changed',
    'hook_command_target',
    'hook_event',
    'hook_profile_path',
    'hook_profile_written',
    'hook_target_verified_by_live_read',
    'installer_identity',
    'human_authority_required_before_install_or_config',
    'install_or_activation_applied',
    'issuer_id',
    'issuer_kid',
    'issuer_status_claim',
    'issuer_status_verified_live',
    'live_downstream_recognition_evidence',
    'live_policy_signature_verified',
    'live_receipt_emission_verified',
    'live_surface_probe_performed',
    'machine_config_written',
    'non_claims',
    'packet_complete',
    'packet_id',
    'packet_sha256',
    'packet_type',
    'policy_id',
    'policy_sha256',
    'policy_signature_required',
    'private_key_material_included',
    'public_key_material_included',
    'receipt_emission_source',
    'receipt_format',
    'receipt_path',
    'recognized_receipt_required_for_boarding',
    'refusal_matrix_complete',
    'refusal_reason_count',
    'required_refusal_reason_count',
    'required_refusal_reasons',
    'safe_claim_ceiling',
    'schema_version',
    'secrets_or_signing_material_changed',
    'selected_surface',
    'service_started',
    'single_surface_scope',
    'source_target',
    'telegram_used',
    'user_config_written',
    'verification_type',
    'verified',
    'website_publication',
  ]);
  if (verification.verification_type !== CURRENT_MACHINE_APPROVAL_PACKET_VERIFICATION_TYPE) {
    throw new Error('Current-machine approval packet verification has the wrong type');
  }
  assertBoolean('Current-machine approval packet verification verified', verification.verified, true);
  assertBoolean('Current-machine approval packet verification packet complete', verification.packet_complete, true);
  if (verification.packet_type !== CURRENT_MACHINE_APPROVAL_PACKET_TYPE) {
    throw new Error('Current-machine approval packet verification packet type drifted');
  }
  if (verification.packet_id !== CURRENT_MACHINE_APPROVAL_PACKET_ID) {
    throw new Error('Current-machine approval packet verification packet id is not the expected fixture packet');
  }
  assertSha256('Current-machine approval packet verification SHA-256', verification.packet_sha256);
  if (verification.packet_sha256 !== CURRENT_MACHINE_APPROVAL_PACKET_SHA256) {
    throw new Error('Current-machine approval packet verification SHA-256 is not the expected fixture packet');
  }
  if (verification.selected_surface !== CURRENT_MACHINE_APPROVAL_PACKET_SURFACE) {
    throw new Error('Current-machine approval packet verification selected surface drifted');
  }
  assertBoolean(
    'Current-machine approval packet verification single-surface scope',
    verification.single_surface_scope,
    true
  );
  assertBoolean(
    'Current-machine approval packet verification live surface probe performed',
    verification.live_surface_probe_performed,
    false
  );
  if (verification.hook_event !== 'PreToolUse') {
    throw new Error('Current-machine approval packet verification hook event drifted');
  }
  if (verification.hook_profile_path !== '~/.claude/settings.json') {
    throw new Error('Current-machine approval packet verification hook profile path drifted');
  }
  if (verification.hook_command_target !== '~/.zlar/adapters/claude-code/hook.sh') {
    throw new Error('Current-machine approval packet verification hook command target drifted');
  }
  if (verification.delegation_target !== '~/.zlar/bin/zlar-gate') {
    throw new Error('Current-machine approval packet verification hook delegation target drifted');
  }
  assertBoolean(
    'Current-machine approval packet verification hook target live read',
    verification.hook_target_verified_by_live_read,
    false
  );
  assertCurrentMachineApprovalSourceTarget(verification.source_target);
  assertCurrentMachineApprovalInstallerIdentity(verification.installer_identity);
  assertCurrentMachineApprovalCommandPosture(verification.command_posture);
  assertCurrentMachineApprovalDryRunPlanIdentity(verification.dry_run_plan_identity);
  assertCurrentMachineApprovalAuthorityRequestIdentity(verification.authority_request_identity);
  assertCurrentMachineApprovalBackupRollback(verification.backup_rollback_requirements);
  if (verification.installer_identity.installer_source_commit_sha !== verification.source_target.target_commit_sha) {
    throw new Error('Current-machine approval packet verification installer source commit must match target commit');
  }
  if (
    verification.source_target.source_manifest_sha256 !==
    expectedSourceManifestSha256(verification.source_target, verification.installer_identity)
  ) {
    throw new Error('Current-machine approval packet verification source manifest SHA-256 mismatch');
  }
  assertLocalGitSourceIdentity(verification.source_target, verification.installer_identity);
  assertLocalGitPrivateCoreReleaseIdentity(verification.source_target);
  if (verification.accepted_policy_version !== verification.source_target.target_version) {
    throw new Error('Current-machine approval packet verification accepted policy version must match target version');
  }
  if (verification.dry_run_plan_identity.selected_surface !== verification.selected_surface) {
    throw new Error('Current-machine approval packet verification dry-run surface drifted');
  }
  if (verification.command_posture.selected_surface !== verification.selected_surface) {
    throw new Error('Current-machine approval packet verification command surface drifted');
  }
  if (
    verification.authority_request_identity.request_sha256 !==
    expectedAuthorityRequestSha256FromVerification(verification)
  ) {
    throw new Error('Current-machine approval packet verification request SHA-256 mismatch');
  }
  assertExactArray(
    'Current-machine approval packet verification required refusal reasons',
    verification.required_refusal_reasons,
    REQUIRED_CURRENT_MACHINE_APPROVAL_REFUSAL_REASONS
  );
  assertExactArray(
    'Current-machine approval packet verification non-claims',
    verification.non_claims,
    REQUIRED_CURRENT_MACHINE_APPROVAL_NON_CLAIMS
  );
  if (
    verification.refusal_reason_count !== REQUIRED_CURRENT_MACHINE_APPROVAL_REFUSAL_REASONS.length ||
    verification.required_refusal_reason_count !== REQUIRED_CURRENT_MACHINE_APPROVAL_REFUSAL_REASONS.length ||
    verification.refusal_matrix_complete !== true
  ) {
    throw new Error('Current-machine approval packet verification refusal matrix drifted');
  }
  for (const field of FALSE_AUTHORITY_FIELDS) {
    if (verification[field] !== false) {
      throw new Error(`Current-machine approval packet verification ${field} must be false`);
    }
  }
  assertNoUnsafeCurrentMachineApprovalPacketText(JSON.stringify(verification));
  return true;
}

export function formatCurrentMachineApprovalPacketVerification(verification) {
  assertCurrentMachineApprovalPacketVerification(verification);
  const lines = [
    'ZLAR Current-Machine Approval Packet Verification v1',
    `verified=${verification.verified}; packet_complete=${verification.packet_complete}`,
    `packet=${verification.packet_id}; sha256=${verification.packet_sha256}`,
    `claim_ceiling=${verification.safe_claim_ceiling}`,
    `selected_surface=${verification.selected_surface}; single_surface_scope=${verification.single_surface_scope}; live_surface_probe_performed=${verification.live_surface_probe_performed}`,
    `hook_target: profile=${verification.hook_profile_path}; event=${verification.hook_event}; target=${verification.hook_command_target}; delegation_target=${verification.delegation_target}; target_verified_by_live_read=${verification.hook_target_verified_by_live_read}; hook_profile_written=${verification.hook_profile_written}`,
    `source_target: repo=${verification.source_target.repo_url}; commit=${verification.source_target.target_commit_sha}; tree=${verification.source_target.target_tree_sha}; version=${verification.source_target.target_version}; state=${verification.source_target.source_state}; dirty_allowed=${verification.source_target.dirty_worktree_allowed}; published_release_claimed=${verification.source_target.published_release_claimed}`,
    `installer_identity: path=${verification.installer_identity.installer_path}; blob=${verification.installer_identity.installer_git_blob_sha}; sha256=${verification.installer_identity.installer_sha256}; source_commit=${verification.installer_identity.installer_source_commit_sha}; verified_live=${verification.installer_identity.installer_identity_verified_live}`,
    `command_posture: dry_run=${verification.command_posture.dry_run_argv.join(' ')}; real=${verification.command_posture.real_install_argv.join(' ')}; surface=${verification.command_posture.selected_surface}; existing_install_mode=${verification.command_posture.existing_install_mode}; no_machine_helpers=${verification.command_posture.no_machine_helpers}`,
    `dry_run_plan_identity: type=${verification.dry_run_plan_identity.plan_type}; command=${verification.dry_run_plan_identity.plan_command}; sha256=${verification.dry_run_plan_identity.plan_sha256}; selected_surface=${verification.dry_run_plan_identity.selected_surface}; no_write_plan=${verification.dry_run_plan_identity.no_write_plan}`,
    `authority_request_identity: request_id=${verification.authority_request_identity.request_id}; issued_at=${verification.authority_request_identity.issued_at}; expires_at=${verification.authority_request_identity.expires_at}; single_use=${verification.authority_request_identity.single_use}; replay_guard_required=${verification.authority_request_identity.replay_guard_required}; authority_request_made=${verification.authority_request_identity.authority_request_made}`,
    `backup_rollback: backup_required=${verification.backup_rollback_requirements.backup_required_before_mutation}; backup_artifact_identity_required=${verification.backup_rollback_requirements.backup_artifact_identity_required}; rollback_plan_required=${verification.backup_rollback_requirements.rollback_plan_required}; installer_backup_enforcement_present=${verification.backup_rollback_requirements.installer_backup_enforcement_present}`,
    `issuer_policy: issuer_id=${verification.issuer_id}; issuer_kid=${verification.issuer_kid}; issuer_status_verified_live=${verification.issuer_status_verified_live}; policy_id=${verification.policy_id}; accepted_policy_version=${verification.accepted_policy_version}; policy_sha256=${verification.policy_sha256}; live_policy_signature_verified=${verification.live_policy_signature_verified}`,
    `receipt_path: format=${verification.receipt_format}; source=${verification.receipt_emission_source}; path=${verification.receipt_path}; required_for_boarding=${verification.recognized_receipt_required_for_boarding}; minted_by_verifier=${verification.boarding_credential_minted_by_verifier}; live_emission_verified=${verification.live_receipt_emission_verified}`,
    `downstream: terminal=${verification.downstream_terminal}; refuses_before_effect=${verification.downstream_refuses_before_effect}; refusal_matrix_complete=${verification.refusal_matrix_complete}; refusal_reasons=${verification.refusal_reason_count}/${verification.required_refusal_reason_count}`,
    `authority_boundary: packet_before_authority_request=${verification.approval_packet_complete_before_authority_request}; human_authority_required=${verification.human_authority_required_before_install_or_config}; install_or_activation_applied=${verification.install_or_activation_applied}; user_config_written=${verification.user_config_written}; machine_config_written=${verification.machine_config_written}; service_started=${verification.service_started}; signing_material_changed=${verification.secrets_or_signing_material_changed}; telegram_used=${verification.telegram_used}; github_settings_changed=${verification.github_settings_changed}; website_publication=${verification.website_publication}`,
    `evidence_boundary: current_machine_governance_evidence=${verification.current_machine_governance_evidence}; live_downstream_recognition_evidence=${verification.live_downstream_recognition_evidence}; external_attestation=${verification.external_attestation}`,
    `claim_boundary=${verification.claim_boundary}`,
    `required_refusal_reasons=${verification.required_refusal_reasons.join(',')}`,
    'Non-claims:',
  ];
  for (const claim of verification.non_claims) {
    lines.push(`- ${claim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeCurrentMachineApprovalPacketText(summary);
  return summary;
}
