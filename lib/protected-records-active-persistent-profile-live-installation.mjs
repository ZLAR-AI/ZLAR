import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { canonicalize } from './canonicalize.mjs';
import { sha256hex } from './receipt.mjs';
import {
  assertProtectedRecordsActivePersistentProfileMutationAuthorityPresent,
} from './protected-records-fixture-authority-status.mjs';
import {
  ACTIVE_PERSISTENT_PROFILE_ACTION_CLASS,
  ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
  ACTIVE_PERSISTENT_PROFILE_FORBIDDEN_CLAIMS,
  ACTIVE_PERSISTENT_PROFILE_MANIFEST_FILE,
  ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
  assertActivePersistentProfileRuntimeContractEvidence,
  buildActivePersistentProfileRuntimeContractEvidence,
} from './protected-records-active-persistent-profile-preflight.mjs';
import {
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_ACTIVE_INDEX_TYPE,
  runProtectedRecordsInstalledRuntimeProfilePreflight,
} from './protected-records-installed-runtime-profile-preflight.mjs';
import {
  PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID,
} from './protected-records-named-deployment-profile-real-boundary.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from './protected-records-runtime-profile.mjs';
import {
  assertProtectedRecordsRuntimePreflightProfile,
  runtimeProfileSha256 as computeRuntimeProfileSha256,
} from './protected-records-runtime-profile-preflight.mjs';

export const PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_INSTALLATION_REPORT_TYPE =
  'zlar-protected-records-active-persistent-profile-live-installation-proof-v1';
export const PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_STATUS_TYPE =
  'zlar-protected-records-active-persistent-profile-live-status-v1';
export const PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_MANIFEST_TYPE =
  'zlar-protected-records-active-persistent-profile-live-manifest-v1';
export const PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_CLOSEOUT_TYPE =
  'zlar-protected-records-active-persistent-profile-live-closeout-v1';

export const ACTIVE_PERSISTENT_PROFILE_LIVE_CLAIM =
  'ZLAR installed one bounded active persistent runtime profile under one explicit proof-owned or operator-named ZLAR activation root, selected by explicit runtime profile id and SHA, and proved readback of the selected profile plus its launcher-owned authority-grant requirement and grant-store, signed-payload replay, witness, burn, joint-rollback, and host-path TOCTOU contract boundaries.';

export const ACTIVE_PERSISTENT_PROFILE_LIVE_NON_CLAIMS = Object.freeze([
  'This proof installs one active persistent profile under one named ZLAR-owned activation root only.',
  'This proof does not write hooks, Codex config, shell config, app config, user config, machine config, LaunchAgents, daemons, or operating-system persistence.',
  'This proof does not touch real personal, business, customer, or production records.',
  'This installation readback preserves launcher-owned authority-grant requirements but does not instantiate a live grant, issuer appointment, issuer key, grant window, or authorized target effect.',
  'This installation does not run the service crossing, replay, authority-grant refusal, burn, or joint-rollback cases; those remain separate local-disposable evidence surfaces.',
  'This proof does not prove exactly-once effects, atomic store-anchor-witness commit, joint store-anchor-witness rollback detection, or host-filesystem path TOCTOU closure.',
  'This proof does not use credentials, secrets, HMAC, tokens, private keys, YubiKey, GitHub settings, Actions, tags, releases, website publication, Telegram, external services, production issuer custody, or production key custody.',
  'This proof does not prove raw Codex/developer-tool governance, current-machine governance generally, all-surface governance, side-door closure, production downstream recognition, production authority, enterprise readiness, public external attestation, sovereign recognition, or absolute human intention.',
]);

export const ACTIVE_PERSISTENT_PROFILE_LIVE_OPEN_BOUNDARIES = Object.freeze([
  'runtime_service_not_started',
  'exact_runtime_authority_grant_not_instantiated',
  'rightful_issuance_not_proven',
  'same_process_signed_payload_replay_not_run_by_installation',
  'restart_consumed_authority_grant_refusal_not_run_by_installation',
  'authority_grant_refusals_not_run_by_installation',
  'exactly_once_effect_semantics_not_proven',
  'store_anchor_witness_commit_atomicity_not_proven',
  'store_anchor_and_witness_joint_rollback_detection_not_proven',
  'host_filesystem_path_toctou_not_closed',
  'live_records_system_not_touched',
  'real_personal_records_not_touched',
  'hook_configuration_not_written',
  'user_or_machine_configuration_not_written',
  'raw_codex_developer_tool_governance_not_proven',
  'current_machine_governance_general_not_proven',
  'production_downstream_recognition_not_proven',
  'side_door_closure_not_proven',
  'all_surface_governance_not_proven',
]);

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
  for (let index = 0; index < expected.length; index++) {
    if (value[index] !== expected[index]) {
      throw new Error(`${label} drifted`);
    }
  }
  return true;
}

function expectBool(label, value, expected) {
  if (value !== expected) {
    throw new Error(`${label} must be ${expected}`);
  }
  return true;
}

function expectString(label, value) {
  if (typeof value !== 'string' || value.length < 1) {
    throw new Error(`${label} must be a non-empty string`);
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(value);
  return true;
}

function expectSha(label, value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`${label} must be a SHA-256 hex string`);
  }
  return true;
}

function isoFromEpoch(epoch) {
  return new Date(epoch * 1000).toISOString();
}

function epochFromIso(label, value) {
  if (typeof value !== 'string' || value.length < 1) {
    throw new Error(`${label} is mandatory`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new Error(`${label} must be an ISO-8601 timestamp`);
  }
  return Math.floor(parsed / 1000);
}

function assertFutureExpiry(expiresAt, nowEpoch) {
  const expiryEpoch = epochFromIso('active persistent live expiry', expiresAt);
  if (expiryEpoch <= nowEpoch) {
    throw new Error('active persistent live expiry is expired');
  }
  return expiryEpoch;
}

function assertCloseoutReason(reason) {
  if (typeof reason !== 'string' || !/^[a-z0-9][a-z0-9._-]{2,127}$/.test(reason)) {
    throw new Error('active persistent live closeout reason is malformed');
  }
  return true;
}

export function defaultActivePersistentProfileLiveRoot() {
  return resolve(
    homedir(),
    '.zlar',
    'protected-records',
    'deployments',
    PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID
  );
}

function isNamedLiveRoot(activationRoot, expectedLiveRoot = defaultActivePersistentProfileLiveRoot()) {
  const liveRoot = resolve(expectedLiveRoot);
  const lexicalRoot = resolve(activationRoot);
  if (lexicalRoot === liveRoot) {
    return true;
  }
  return effectivePath(activationRoot) === effectivePath(expectedLiveRoot);
}

function rootLabel(activationRoot, expectedLiveRoot = defaultActivePersistentProfileLiveRoot()) {
  return isNamedLiveRoot(activationRoot, expectedLiveRoot)
    ? '<named-active-persistent-profile-root>'
    : '<surrogate-active-persistent-profile-root>';
}

function activeIndexPath(activationRoot) {
  return join(activationRoot, 'active-runtime-profile.json');
}

function profilesDir(activationRoot) {
  return join(activationRoot, 'profiles');
}

function installedProfilePath(activationRoot) {
  return join(profilesDir(activationRoot), `${PROTECTED_RECORDS_RUNTIME_PROFILE_ID}.json`);
}

function liveManifestPath(activationRoot) {
  return join(activationRoot, ACTIVE_PERSISTENT_PROFILE_MANIFEST_FILE);
}

function pathIsInside(rootRealPath, childRealPath) {
  const rel = relative(rootRealPath, childRealPath);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`));
}

function effectivePath(path) {
  const resolved = resolve(path);
  const parts = resolved.split(sep).filter(Boolean);
  let current = sep;
  for (let index = 0; index < parts.length; index++) {
    const candidate = join(current, parts[index]);
    try {
      current = realpathSync(candidate);
    } catch (err) {
      if (err && err.code === 'ENOENT') {
        return resolve(current, ...parts.slice(index));
      }
      throw new Error('active persistent live path identity could not be inspected');
    }
  }
  return current;
}

function assertPathBasename(activationRoot) {
  if (basename(resolve(activationRoot)) !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID) {
    throw new Error('active persistent live activation root must end with the named deployment profile id');
  }
  return true;
}

function assertNotSymlink(path, label, { allowMissing = false } = {}) {
  try {
    if (lstatSync(path).isSymbolicLink()) {
      throw new Error(`${label} symlink refused`);
    }
  } catch (err) {
    if (String(err.message).includes('symlink refused')) {
      throw err;
    }
    if (allowMissing && err && err.code === 'ENOENT') {
      return false;
    }
    throw new Error(`${label} could not be inspected`);
  }
  return true;
}

function assertActivationRootAuthority({
  activationRoot,
  allowNamedLiveRoot,
  expectedLiveRoot = defaultActivePersistentProfileLiveRoot(),
}) {
  assertPathBasename(activationRoot);
  if (isNamedLiveRoot(activationRoot, expectedLiveRoot) && allowNamedLiveRoot !== true) {
    throw new Error('named active persistent live root requires explicit --allow-named-live-root authority');
  }
  return true;
}

function assertReportOutputPath({ outputPath, activationRoot }) {
  if (!outputPath) {
    return true;
  }
  const outputResolved = resolve(outputPath);
  const rootResolved = resolve(activationRoot);
  if (
    pathIsInside(rootResolved, outputResolved) ||
    pathIsInside(effectivePath(activationRoot), effectivePath(outputPath))
  ) {
    throw new Error('active persistent live report output may not be written inside the activation root');
  }
  return true;
}

export function assertActivePersistentProfileLiveReportOutputPath({
  outputPath,
  activationRoot,
}) {
  return assertReportOutputPath({ outputPath, activationRoot });
}

function readJson(path, label) {
  let text = '';
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    throw new Error(`${label} could not be read`);
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(text);
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

function writeJsonAtomic(path, value, mode = 0o600) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}.${Date.now()}.tmp`);
  const text = `${JSON.stringify(value, null, 2)}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(text);
  writeFileSync(tmp, text, { mode });
  const fd = openSync(tmp, 'r');
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
  try {
    const dirFd = openSync(dirname(path), 'r');
    try {
      fsyncSync(dirFd);
    } finally {
      closeSync(dirFd);
    }
  } catch {
    // Directory fsync is best-effort across platforms; the file fsync and rename
    // still preserve the proof's observable atomic-write contract.
  }
  return sha256hex(canonicalize(value));
}

function readStatusState({
  activationRoot,
  nowEpoch,
  allowNamedLiveRoot,
  expectedLiveRoot = defaultActivePersistentProfileLiveRoot(),
}) {
  assertActivationRootAuthority({ activationRoot, allowNamedLiveRoot, expectedLiveRoot });
  const rootExists = existsSync(activationRoot);
  const activeIndexPresent = existsSync(activeIndexPath(activationRoot));
  const installedProfilePresent = existsSync(installedProfilePath(activationRoot));
  const manifestPresent = existsSync(liveManifestPath(activationRoot));

  if (!rootExists) {
    return {
      activation_root_state: 'absent',
      manifest_present: false,
      manifest_status: 'not_present',
      active: false,
      expired: false,
      active_index_present: false,
      installed_profile_present: false,
      safe_for_install: true,
      ambiguous_or_active_root_refused: false,
      explicit_closeout_or_replace_required: false,
      expires_at: null,
    };
  }

  assertNotSymlink(activationRoot, 'active persistent live activation root');
  const stat = statSync(activationRoot);
  if (!stat.isDirectory()) {
    throw new Error('active persistent live activation root must be a directory');
  }

  if (!manifestPresent) {
    const hasPersistentInstallResidue = activeIndexPresent || installedProfilePresent;
    return {
      activation_root_state: hasPersistentInstallResidue
        ? 'ambiguous_persistent_install_residue'
        : 'inert_legacy_evidence_or_empty',
      manifest_present: false,
      manifest_status: 'not_present',
      active: false,
      expired: false,
      active_index_present: activeIndexPresent,
      installed_profile_present: installedProfilePresent,
      safe_for_install: !hasPersistentInstallResidue,
      ambiguous_or_active_root_refused: hasPersistentInstallResidue,
      explicit_closeout_or_replace_required: hasPersistentInstallResidue,
      expires_at: null,
    };
  }

  assertNotSymlink(liveManifestPath(activationRoot), 'active persistent live manifest');
  const manifest = readJson(liveManifestPath(activationRoot), 'active persistent live manifest');
  if (manifest.manifest_type !== PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_MANIFEST_TYPE) {
    return {
      activation_root_state: 'ambiguous_manifest',
      manifest_present: true,
      manifest_status: manifest.status || 'unknown',
      active: false,
      expired: false,
      active_index_present: activeIndexPresent,
      installed_profile_present: installedProfilePresent,
      safe_for_install: false,
      ambiguous_or_active_root_refused: true,
      explicit_closeout_or_replace_required: true,
      expires_at: manifest.expires_at || null,
    };
  }

  const expiryEpoch = epochFromIso('active persistent live manifest expiry', manifest.expires_at);
  const expired = expiryEpoch <= nowEpoch;
  const active = manifest.status === 'active_persistent_profile_installed' &&
    manifest.active === true &&
    manifest.activation_allowed === true &&
    !expired;
  const closed = manifest.status === 'closed_inert_evidence' ||
    manifest.active === false ||
    manifest.activation_allowed === false;
  return {
    activation_root_state: active
      ? 'active_until_expiry'
      : (expired && manifest.active === true
        ? 'expired_active_persistent_profile'
        : (closed ? 'closed_inert_evidence' : 'ambiguous_manifest')),
    manifest_present: true,
    manifest_status: expired && manifest.active === true
      ? 'expired_active_persistent_profile'
      : manifest.status,
    active,
    expired,
    active_index_present: activeIndexPresent,
    installed_profile_present: installedProfilePresent,
    safe_for_install: false,
    ambiguous_or_active_root_refused: !closed || activeIndexPresent || installedProfilePresent,
    explicit_closeout_or_replace_required: true,
    expires_at: manifest.expires_at,
  };
}

export function inspectActivePersistentProfileLiveStatus({
  activationRoot,
  nowEpoch = Math.floor(Date.now() / 1000),
  allowNamedLiveRoot = false,
  expectedLiveRoot = defaultActivePersistentProfileLiveRoot(),
}) {
  const state = readStatusState({ activationRoot, nowEpoch, allowNamedLiveRoot, expectedLiveRoot });
  const status = {
    status_type: PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_STATUS_TYPE,
    evidence_model: 'explicit-active-persistent-profile-root-status',
    read_only: true,
    activation_root_label: rootLabel(activationRoot, expectedLiveRoot),
    named_live_root: isNamedLiveRoot(activationRoot, expectedLiveRoot),
    activation_root_state: state.activation_root_state,
    manifest_present: state.manifest_present,
    manifest_status: state.manifest_status,
    active: state.active,
    expired: state.expired,
    active_index_present: state.active_index_present,
    installed_profile_present: state.installed_profile_present,
    safe_for_install: state.safe_for_install,
    ambiguous_or_active_root_refused: state.ambiguous_or_active_root_refused,
    explicit_closeout_or_replace_required: state.explicit_closeout_or_replace_required,
    expires_at: state.expires_at,
  };
  assertActivePersistentProfileLiveStatus(status);
  return status;
}

function assertInstallSafe({ activationRoot, nowEpoch, allowNamedLiveRoot }) {
  const status = inspectActivePersistentProfileLiveStatus({
    activationRoot,
    nowEpoch,
    allowNamedLiveRoot,
  });
  if (status.safe_for_install !== true) {
    throw new Error('active persistent live activation root is active, closed, expired, or ambiguous; install refused');
  }
  return status;
}

function closedRootReplacementAllowed(status) {
  return (
    status.activation_root_state === 'closed_inert_evidence' &&
    status.manifest_present === true &&
    status.manifest_status === 'closed_inert_evidence' &&
    status.active === false &&
    status.safe_for_install === false &&
    status.explicit_closeout_or_replace_required === true
  );
}

function assertInstallPermitted(status, replaceClosedRoot) {
  if (status.safe_for_install === true) {
    return false;
  }
  if (replaceClosedRoot === true && closedRootReplacementAllowed(status)) {
    return true;
  }
  throw new Error('active persistent live activation root is active, closed, expired, or ambiguous; install refused');
}

function assertFixedProfile({ profile, profileSource, runtimeProfileId, runtimeProfileSha256 }) {
  assertProtectedRecordsRuntimePreflightProfile(profile);
  const profileSha = computeRuntimeProfileSha256(profile);
  if (
    profileSource !== ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE ||
    profile.profile_id !== 'protected-records-runtime-fixture-profile' ||
    profile.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    runtimeProfileId !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    runtimeProfileSha256 !== ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256 ||
    profileSha !== ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256 ||
    profile.action_class !== ACTIVE_PERSISTENT_PROFILE_ACTION_CLASS
  ) {
    throw new Error('active persistent live fixed runtime profile binding failed');
  }
  return profileSha;
}

function buildActiveIndex(profile, profileSha) {
  return {
    index_type: PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_ACTIVE_INDEX_TYPE,
    selected_profile_id: profile.profile_id,
    selected_runtime_profile_id: profile.runtime_profile_id,
    selected_profile_sha256: profileSha,
    selected_by_explicit_id_and_sha: true,
    selects_latest_profile: false,
    installed_profile_path:
      '<launcher-owned-disposable-install-root>/profiles/protected-records-disposable-runtime-profile.json',
  };
}

function buildManifest({
  status,
  active,
  activationAllowed,
  installedAt,
  expiresAt,
  profileSha,
  preinstallStatus,
}) {
  return {
    manifest_type: PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_MANIFEST_TYPE,
    deployment_profile_id: PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID,
    runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    runtime_profile_sha256: profileSha,
    action_class: ACTIVE_PERSISTENT_PROFILE_ACTION_CLASS,
    status,
    active,
    activation_allowed: activationAllowed,
    installed_at: installedAt,
    expires_at: expiresAt,
    activation_root_label: '<active-persistent-profile-root>',
    selected_profile_id: 'protected-records-runtime-fixture-profile',
    selected_by_explicit_id_and_sha: true,
    selects_latest_profile: false,
    runtime_profile_source: ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
    final_state_option: 'active_until_expiry',
    previous_root_state: preinstallStatus.activation_root_state,
    previous_manifest_status: preinstallStatus.manifest_status,
    hooks_or_config_written_outside_root: false,
    runtime_service_started: false,
    real_records_touched: false,
    private_material_persisted: false,
    production_authority: false,
    current_machine_governance_general: false,
  };
}

export function assertActivePersistentProfileLiveManifest(manifest) {
  assertExactKeys('active persistent live manifest', manifest, [
    'action_class',
    'activation_allowed',
    'activation_root_label',
    'active',
    'current_machine_governance_general',
    'deployment_profile_id',
    'expires_at',
    'final_state_option',
    'hooks_or_config_written_outside_root',
    'installed_at',
    'manifest_type',
    'previous_manifest_status',
    'previous_root_state',
    'private_material_persisted',
    'production_authority',
    'real_records_touched',
    'runtime_profile_id',
    'runtime_profile_sha256',
    'runtime_profile_source',
    'runtime_service_started',
    'selected_by_explicit_id_and_sha',
    'selected_profile_id',
    'selects_latest_profile',
    'status',
  ]);
  if (
    manifest.manifest_type !== PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_MANIFEST_TYPE ||
    manifest.deployment_profile_id !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID ||
    manifest.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    manifest.runtime_profile_sha256 !== ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256 ||
    manifest.action_class !== ACTIVE_PERSISTENT_PROFILE_ACTION_CLASS ||
    !['preparing_active_persistent_profile_install', 'active_persistent_profile_installed'].includes(manifest.status) ||
    manifest.activation_root_label !== '<active-persistent-profile-root>' ||
    manifest.selected_profile_id !== 'protected-records-runtime-fixture-profile' ||
    manifest.selected_by_explicit_id_and_sha !== true ||
    manifest.selects_latest_profile !== false ||
    manifest.runtime_profile_source !== ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE ||
    manifest.final_state_option !== 'active_until_expiry'
  ) {
    throw new Error('active persistent live manifest drifted');
  }
  for (const key of [
    'hooks_or_config_written_outside_root',
    'runtime_service_started',
    'real_records_touched',
    'private_material_persisted',
    'production_authority',
    'current_machine_governance_general',
  ]) {
    expectBool(`active persistent live manifest ${key}`, manifest[key], false);
  }
  if (manifest.status === 'preparing_active_persistent_profile_install') {
    expectBool('preparing manifest active', manifest.active, false);
    expectBool('preparing manifest activation allowed', manifest.activation_allowed, false);
  } else {
    expectBool('active manifest active', manifest.active, true);
    expectBool('active manifest activation allowed', manifest.activation_allowed, true);
  }
  expectString('active persistent live installed at', manifest.installed_at);
  expectString('active persistent live expiry', manifest.expires_at);
  expectString('active persistent live previous root state', manifest.previous_root_state);
  expectString('active persistent live previous manifest status', manifest.previous_manifest_status);
  return true;
}

export function runActivePersistentProfileLiveInstallation({
  activationRoot,
  profile,
  profileSource,
  runtimeProfileId,
  runtimeProfileSha256,
  expiresAt,
  nowEpoch = Math.floor(Date.now() / 1000),
  allowNamedLiveRoot = false,
  expectedLiveRoot = defaultActivePersistentProfileLiveRoot(),
  replaceClosedRoot = false,
} = {}) {
  assertProtectedRecordsActivePersistentProfileMutationAuthorityPresent(
    'Protected records active persistent profile live installation'
  );
  if (!activationRoot || typeof activationRoot !== 'string') {
    throw new Error('active persistent live activation root is required');
  }
  assertFutureExpiry(expiresAt, nowEpoch);
  assertActivationRootAuthority({ activationRoot, allowNamedLiveRoot, expectedLiveRoot });
  const preinstallStatus = inspectActivePersistentProfileLiveStatus({
    activationRoot,
    nowEpoch,
    allowNamedLiveRoot,
    expectedLiveRoot,
  });
  const closedRootReplacementAuthorized = assertInstallPermitted(
    preinstallStatus,
    replaceClosedRoot
  );
  const profileSha = assertFixedProfile({
    profile,
    profileSource,
    runtimeProfileId,
    runtimeProfileSha256,
  });

  mkdirSync(activationRoot, { recursive: true, mode: 0o700 });
  assertNotSymlink(activationRoot, 'active persistent live activation root');
  assertNotSymlink(activeIndexPath(activationRoot), 'active persistent live active index', { allowMissing: true });
  assertNotSymlink(profilesDir(activationRoot), 'active persistent live profiles directory', { allowMissing: true });
  assertNotSymlink(installedProfilePath(activationRoot), 'active persistent live installed profile', { allowMissing: true });

  const installedAt = isoFromEpoch(nowEpoch);
  const preparingManifest = buildManifest({
    status: 'preparing_active_persistent_profile_install',
    active: false,
    activationAllowed: false,
    installedAt,
    expiresAt,
    profileSha,
    preinstallStatus,
  });
  assertActivePersistentProfileLiveManifest(preparingManifest);
  const preparingManifestSha256 = writeJsonAtomic(liveManifestPath(activationRoot), preparingManifest);

  mkdirSync(profilesDir(activationRoot), { recursive: true, mode: 0o700 });
  const installedProfileSha256 = writeJsonAtomic(installedProfilePath(activationRoot), profile);
  if (installedProfileSha256 !== profileSha) {
    throw new Error('active persistent live installed profile hash mismatch');
  }
  const activeIndex = buildActiveIndex(profile, profileSha);
  const activeIndexSha256 = writeJsonAtomic(activeIndexPath(activationRoot), activeIndex);

  const finalManifest = buildManifest({
    status: 'active_persistent_profile_installed',
    active: true,
    activationAllowed: true,
    installedAt,
    expiresAt,
    profileSha,
    preinstallStatus,
  });
  assertActivePersistentProfileLiveManifest(finalManifest);
  const finalManifestSha256 = writeJsonAtomic(liveManifestPath(activationRoot), finalManifest);

  const installedPreflight = runProtectedRecordsInstalledRuntimeProfilePreflight({
    installRoot: activationRoot,
    expectedProfile: profile,
    profileId: profile.profile_id,
    profileSha256: profileSha,
  });
  const installedPreflightSha256 = sha256hex(canonicalize(installedPreflight));
  const statusAfterInstall = inspectActivePersistentProfileLiveStatus({
    activationRoot,
    nowEpoch,
    allowNamedLiveRoot,
    expectedLiveRoot,
  });

  const report = {
    report_type: PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_INSTALLATION_REPORT_TYPE,
    schema_version: 1,
    evidence_model: 'bounded-active-persistent-profile-live-installation',
    safe_claim: ACTIVE_PERSISTENT_PROFILE_LIVE_CLAIM,
    activation_root_label: rootLabel(activationRoot, expectedLiveRoot),
    named_live_root: isNamedLiveRoot(activationRoot, expectedLiveRoot),
    installed_at: installedAt,
    expires_at: expiresAt,
    final_root_state: statusAfterInstall.activation_root_state,
    active_after_proof: statusAfterInstall.active,
    preinstall_status: {
      activation_root_state: preinstallStatus.activation_root_state,
      manifest_present: preinstallStatus.manifest_present,
      manifest_status: preinstallStatus.manifest_status,
      inert_legacy_evidence_preserved:
        preinstallStatus.activation_root_state === 'inert_legacy_evidence_or_empty',
      closed_root_replacement_authorized: closedRootReplacementAuthorized,
    },
    selected_profile: {
      profile_id: profile.profile_id,
      runtime_profile_id: profile.runtime_profile_id,
      runtime_profile_sha256: profileSha,
      runtime_profile_source: ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
      selected_by_explicit_id_and_sha: true,
      selects_latest_profile: false,
    },
    runtime_profile_contract:
      buildActivePersistentProfileRuntimeContractEvidence(profile),
    files_written: {
      manifest_path_label: '<active-persistent-profile-root>/active-persistent-profile-manifest.json',
      active_index_path_label: '<active-persistent-profile-root>/active-runtime-profile.json',
      installed_profile_path_label:
        '<active-persistent-profile-root>/profiles/protected-records-disposable-runtime-profile.json',
      preparing_manifest_sha256: preparingManifestSha256,
      final_manifest_sha256: finalManifestSha256,
      active_index_sha256: activeIndexSha256,
      installed_profile_sha256: installedProfileSha256,
    },
    readback_preflight: {
      installed_runtime_profile_preflight_performed: true,
      installed_runtime_profile_preflight_sha256: installedPreflightSha256,
      read_only: installedPreflight.read_only,
      selected_by_explicit_id_and_sha:
        installedPreflight.active_index.selected_by_explicit_id_and_sha,
      selects_latest_profile: installedPreflight.active_index.selects_latest_profile,
      runtime_profile_installation_performed_by_preflight:
        installedPreflight.inspection_boundary.runtime_profile_installation_performed,
      runtime_profile_activation_performed_by_preflight:
        installedPreflight.inspection_boundary.runtime_profile_activation_performed,
      authority_grant_requirement_preserved:
        installedPreflight.authority_grant_requirement !== null,
      exact_runtime_authority_grant_contract_deferred:
        installedPreflight.authority_grant_requirement
          .exact_runtime_contract_deferred_until_preflight_body_sha_available,
      rightful_issuance_proven:
        installedPreflight.authority_grant_requirement.rightful_issuance_proven,
      consequence_lifecycle_closed:
        installedPreflight.authority_grant_requirement.consequence_lifecycle_closed,
      atomic_store_anchor_witness_commit:
        installedPreflight.side_door_report.atomic_store_anchor_witness_commit,
      partial_grant_commit_burn_window_proven:
        installedPreflight.side_door_report.partial_grant_commit_burn_window_proven,
      store_anchor_and_witness_joint_rollback_detection:
        installedPreflight.side_door_report
          .store_anchor_and_witness_joint_rollback_detection,
      host_filesystem_path_toctou_closed:
        installedPreflight.side_door_report.host_filesystem_path_toctou_closed,
    },
    write_boundary: {
      activation_root_written: true,
      root_created_or_reused_by_explicit_path: true,
      closed_root_replaced_by_explicit_authority: closedRootReplacementAuthorized,
      hooks_or_config_written_outside_root: false,
      runtime_service_started: false,
      real_records_touched: false,
      credentials_or_key_material_used: false,
      external_services_used: false,
    },
    claim_boundary: {
      active_persistent_runtime_profile_installation: true,
      persistent_active_state_after_proof: true,
      installed_runtime_profile_readback_preflight: true,
      proof_owned_or_named_zlar_root_only: true,
      real_personal_records_touched: false,
      hooks_or_machine_config_written: false,
      runtime_service_started: false,
      production_downstream_recognition: false,
      fixture_rightful_issuance_path_evidenced: false,
      rightful_issuance_proven: false,
      portable_rightful_issuance_proven: false,
      live_authority_proven: false,
      production_rightful_issuance_proven: false,
      consequence_lifecycle_closed: false,
      current_machine_governance_general: false,
      raw_codex_developer_tool_governance: false,
      enterprise_readiness: false,
      public_external_attestation: false,
      all_surface_governance: false,
      side_door_closure: false,
      absolute_human_intention: false,
    },
    open_boundaries: [...ACTIVE_PERSISTENT_PROFILE_LIVE_OPEN_BOUNDARIES],
    non_claims: [...ACTIVE_PERSISTENT_PROFILE_LIVE_NON_CLAIMS],
    forbidden_claims: [...ACTIVE_PERSISTENT_PROFILE_FORBIDDEN_CLAIMS],
  };
  assertActivePersistentProfileLiveInstallationReport(report);
  return report;
}

export function closeActivePersistentProfileLiveInstallation({
  activationRoot,
  closedAt,
  reason = 'operator_closeout',
  nowEpoch = Math.floor(Date.now() / 1000),
  allowNamedLiveRoot = false,
  expectedLiveRoot = defaultActivePersistentProfileLiveRoot(),
} = {}) {
  assertProtectedRecordsActivePersistentProfileMutationAuthorityPresent(
    'Protected records active persistent profile closeout'
  );
  if (!activationRoot || typeof activationRoot !== 'string') {
    throw new Error('active persistent live activation root is required');
  }
  epochFromIso('active persistent live closed_at', closedAt);
  assertCloseoutReason(reason);
  assertActivationRootAuthority({ activationRoot, allowNamedLiveRoot, expectedLiveRoot });
  const statusBefore = inspectActivePersistentProfileLiveStatus({
    activationRoot,
    nowEpoch,
    allowNamedLiveRoot,
    expectedLiveRoot,
  });
  if (!statusBefore.manifest_present) {
    throw new Error('active persistent live closeout requires a live manifest');
  }
  const manifest = readJson(liveManifestPath(activationRoot), 'active persistent live manifest');
  if (manifest.manifest_type !== PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_MANIFEST_TYPE) {
    throw new Error('active persistent live closeout refused ambiguous manifest');
  }
  const closeoutManifest = {
    ...manifest,
    status: 'closed_inert_evidence',
    active: false,
    activation_allowed: false,
    closed_at: closedAt,
    closeout_reason: reason,
    closeout_type: PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_CLOSEOUT_TYPE,
    closeout_reactivation_allowed: false,
  };
  const manifestSha256 = writeJsonAtomic(liveManifestPath(activationRoot), closeoutManifest);
  const statusAfter = inspectActivePersistentProfileLiveStatus({
    activationRoot,
    nowEpoch,
    allowNamedLiveRoot,
    expectedLiveRoot,
  });
  const closeout = {
    closeout_type: PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_CLOSEOUT_TYPE,
    deployment_profile_id: PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID,
    runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    runtime_profile_sha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    action_class: ACTIVE_PERSISTENT_PROFILE_ACTION_CLASS,
    previous_status: statusBefore.manifest_status,
    status: statusAfter.manifest_status,
    active: statusAfter.active,
    closed_at: closedAt,
    closeout_reason: reason,
    activation_root_label: rootLabel(activationRoot, expectedLiveRoot),
    manifest_sha256: manifestSha256,
    closeout_reactivation_allowed: false,
  };
  assertActivePersistentProfileLiveCloseout(closeout);
  return closeout;
}

export function assertActivePersistentProfileLiveStatus(status) {
  assertExactKeys('active persistent live status', status, [
    'activation_root_label',
    'activation_root_state',
    'active',
    'active_index_present',
    'ambiguous_or_active_root_refused',
    'evidence_model',
    'expired',
    'expires_at',
    'explicit_closeout_or_replace_required',
    'installed_profile_present',
    'manifest_present',
    'manifest_status',
    'named_live_root',
    'read_only',
    'safe_for_install',
    'status_type',
  ]);
  if (
    status.status_type !== PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_STATUS_TYPE ||
    status.evidence_model !== 'explicit-active-persistent-profile-root-status' ||
    status.read_only !== true
  ) {
    throw new Error('active persistent live status drifted');
  }
  expectString('active persistent live status root label', status.activation_root_label);
  expectString('active persistent live status root state', status.activation_root_state);
  expectString('active persistent live status manifest status', status.manifest_status);
  for (const key of [
    'named_live_root',
    'manifest_present',
    'active',
    'expired',
    'active_index_present',
    'installed_profile_present',
    'safe_for_install',
    'ambiguous_or_active_root_refused',
    'explicit_closeout_or_replace_required',
  ]) {
    if (typeof status[key] !== 'boolean') {
      throw new Error(`active persistent live status ${key} drifted`);
    }
  }
  if (status.expires_at !== null) {
    expectString('active persistent live status expiry', status.expires_at);
  }
  return true;
}

export function assertActivePersistentProfileLiveInstallationReport(report) {
  assertExactKeys('active persistent live installation report', report, [
    'activation_root_label',
    'active_after_proof',
    'claim_boundary',
    'evidence_model',
    'expires_at',
    'files_written',
    'final_root_state',
    'forbidden_claims',
    'installed_at',
    'named_live_root',
    'non_claims',
    'open_boundaries',
    'preinstall_status',
    'readback_preflight',
    'report_type',
    'runtime_profile_contract',
    'safe_claim',
    'schema_version',
    'selected_profile',
    'write_boundary',
  ]);
  if (
    report.report_type !== PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_INSTALLATION_REPORT_TYPE ||
    report.schema_version !== 1 ||
    report.evidence_model !== 'bounded-active-persistent-profile-live-installation' ||
    report.safe_claim !== ACTIVE_PERSISTENT_PROFILE_LIVE_CLAIM ||
    report.final_root_state !== 'active_until_expiry' ||
    report.active_after_proof !== true
  ) {
    throw new Error('active persistent live installation top-level drifted');
  }
  expectString('active persistent live activation root label', report.activation_root_label);
  expectString('active persistent live installed at', report.installed_at);
  expectString('active persistent live expiry', report.expires_at);

  const legacyFirstInstallPreinstallStatus =
    report.preinstall_status &&
    typeof report.preinstall_status === 'object' &&
    !Array.isArray(report.preinstall_status) &&
    Object.keys(report.preinstall_status).sort().join('\n') === [
      'activation_root_state',
      'inert_legacy_evidence_preserved',
      'manifest_present',
      'manifest_status',
    ].sort().join('\n') &&
    report.preinstall_status.activation_root_state ===
      'inert_legacy_evidence_or_empty' &&
    report.preinstall_status.manifest_present === false &&
    report.preinstall_status.manifest_status === 'not_present' &&
    typeof report.preinstall_status.inert_legacy_evidence_preserved === 'boolean';
  if (!legacyFirstInstallPreinstallStatus) {
    assertExactKeys('active persistent live preinstall status', report.preinstall_status, [
      'activation_root_state',
      'closed_root_replacement_authorized',
      'inert_legacy_evidence_preserved',
      'manifest_present',
      'manifest_status',
    ]);
  }
  expectString('active persistent live preinstall root state', report.preinstall_status.activation_root_state);
  expectString('active persistent live preinstall manifest status', report.preinstall_status.manifest_status);
  if (typeof report.preinstall_status.manifest_present !== 'boolean') {
    throw new Error('active persistent live preinstall manifest_present drifted');
  }
  const closedRootReplacementAuthorized = legacyFirstInstallPreinstallStatus
    ? false
    : report.preinstall_status.closed_root_replacement_authorized;
  if (typeof closedRootReplacementAuthorized !== 'boolean') {
    throw new Error('active persistent live preinstall closed_root_replacement_authorized drifted');
  }

  assertExactKeys('active persistent live selected profile', report.selected_profile, [
    'profile_id',
    'runtime_profile_id',
    'runtime_profile_sha256',
    'runtime_profile_source',
    'selected_by_explicit_id_and_sha',
    'selects_latest_profile',
  ]);
  if (
    report.selected_profile.profile_id !== 'protected-records-runtime-fixture-profile' ||
    report.selected_profile.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    report.selected_profile.runtime_profile_sha256 !== ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256 ||
    report.selected_profile.runtime_profile_source !== ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE ||
    report.selected_profile.selected_by_explicit_id_and_sha !== true ||
    report.selected_profile.selects_latest_profile !== false
  ) {
    throw new Error('active persistent live selected profile drifted');
  }
  assertActivePersistentProfileRuntimeContractEvidence(
    report.runtime_profile_contract
  );

  assertExactKeys('active persistent live files written', report.files_written, [
    'active_index_path_label',
    'active_index_sha256',
    'final_manifest_sha256',
    'installed_profile_path_label',
    'installed_profile_sha256',
    'manifest_path_label',
    'preparing_manifest_sha256',
  ]);
  for (const key of [
    'preparing_manifest_sha256',
    'final_manifest_sha256',
    'active_index_sha256',
    'installed_profile_sha256',
  ]) {
    expectSha(`active persistent live file hash ${key}`, report.files_written[key]);
  }
  for (const key of ['manifest_path_label', 'active_index_path_label', 'installed_profile_path_label']) {
    expectString(`active persistent live file label ${key}`, report.files_written[key]);
  }

  assertExactKeys('active persistent live readback preflight', report.readback_preflight, [
    'atomic_store_anchor_witness_commit',
    'authority_grant_requirement_preserved',
    'consequence_lifecycle_closed',
    'exact_runtime_authority_grant_contract_deferred',
    'host_filesystem_path_toctou_closed',
    'installed_runtime_profile_preflight_performed',
    'installed_runtime_profile_preflight_sha256',
    'partial_grant_commit_burn_window_proven',
    'read_only',
    'rightful_issuance_proven',
    'runtime_profile_activation_performed_by_preflight',
    'runtime_profile_installation_performed_by_preflight',
    'selected_by_explicit_id_and_sha',
    'selects_latest_profile',
    'store_anchor_and_witness_joint_rollback_detection',
  ]);
  expectSha('active persistent live installed preflight hash', report.readback_preflight.installed_runtime_profile_preflight_sha256);
  for (const key of ['installed_runtime_profile_preflight_performed', 'read_only', 'selected_by_explicit_id_and_sha', 'authority_grant_requirement_preserved', 'exact_runtime_authority_grant_contract_deferred']) {
    expectBool(`active persistent live readback ${key}`, report.readback_preflight[key], true);
  }
  for (const key of [
    'selects_latest_profile',
    'runtime_profile_installation_performed_by_preflight',
    'runtime_profile_activation_performed_by_preflight',
    'rightful_issuance_proven',
    'consequence_lifecycle_closed',
    'atomic_store_anchor_witness_commit',
    'partial_grant_commit_burn_window_proven',
    'store_anchor_and_witness_joint_rollback_detection',
    'host_filesystem_path_toctou_closed',
  ]) {
    expectBool(`active persistent live readback ${key}`, report.readback_preflight[key], false);
  }

  const legacyFirstInstallWriteBoundary =
    legacyFirstInstallPreinstallStatus &&
    report.write_boundary &&
    typeof report.write_boundary === 'object' &&
    !Array.isArray(report.write_boundary) &&
    Object.keys(report.write_boundary).sort().join('\n') === [
      'activation_root_written',
      'credentials_or_key_material_used',
      'external_services_used',
      'hooks_or_config_written_outside_root',
      'real_records_touched',
      'root_created_or_reused_by_explicit_path',
      'runtime_service_started',
    ].sort().join('\n');
  if (!legacyFirstInstallWriteBoundary) {
    assertExactKeys('active persistent live write boundary', report.write_boundary, [
      'activation_root_written',
      'closed_root_replaced_by_explicit_authority',
      'credentials_or_key_material_used',
      'external_services_used',
      'hooks_or_config_written_outside_root',
      'real_records_touched',
      'root_created_or_reused_by_explicit_path',
      'runtime_service_started',
    ]);
  }
  for (const key of ['activation_root_written', 'root_created_or_reused_by_explicit_path']) {
    expectBool(`active persistent live write boundary ${key}`, report.write_boundary[key], true);
  }
  for (const key of [
    'hooks_or_config_written_outside_root',
    'runtime_service_started',
    'real_records_touched',
    'credentials_or_key_material_used',
    'external_services_used',
  ]) {
    expectBool(`active persistent live write boundary ${key}`, report.write_boundary[key], false);
  }
  const closedRootReplacedByExplicitAuthority = legacyFirstInstallWriteBoundary
    ? false
    : report.write_boundary.closed_root_replaced_by_explicit_authority;
  expectBool(
    'active persistent live write boundary closed_root_replaced_by_explicit_authority',
    closedRootReplacedByExplicitAuthority,
    closedRootReplacementAuthorized
  );

  assertExactKeys('active persistent live claim boundary', report.claim_boundary, [
    'absolute_human_intention',
    'active_persistent_runtime_profile_installation',
    'all_surface_governance',
    'consequence_lifecycle_closed',
    'current_machine_governance_general',
    'enterprise_readiness',
    'fixture_rightful_issuance_path_evidenced',
    'hooks_or_machine_config_written',
    'installed_runtime_profile_readback_preflight',
    'live_authority_proven',
    'persistent_active_state_after_proof',
    'portable_rightful_issuance_proven',
    'production_downstream_recognition',
    'production_rightful_issuance_proven',
    'proof_owned_or_named_zlar_root_only',
    'public_external_attestation',
    'raw_codex_developer_tool_governance',
    'real_personal_records_touched',
    'rightful_issuance_proven',
    'runtime_service_started',
    'side_door_closure',
  ]);
  for (const key of [
    'active_persistent_runtime_profile_installation',
    'persistent_active_state_after_proof',
    'installed_runtime_profile_readback_preflight',
    'proof_owned_or_named_zlar_root_only',
  ]) {
    expectBool(`active persistent live claim ${key}`, report.claim_boundary[key], true);
  }
  for (const [key, value] of Object.entries(report.claim_boundary)) {
    if (![
      'active_persistent_runtime_profile_installation',
      'persistent_active_state_after_proof',
      'installed_runtime_profile_readback_preflight',
      'proof_owned_or_named_zlar_root_only',
    ].includes(key)) {
      expectBool(`active persistent live claim ${key}`, value, false);
    }
  }
  assertExactArray('active persistent live open boundaries', report.open_boundaries, ACTIVE_PERSISTENT_PROFILE_LIVE_OPEN_BOUNDARIES);
  assertExactArray('active persistent live non-claims', report.non_claims, ACTIVE_PERSISTENT_PROFILE_LIVE_NON_CLAIMS);
  assertExactArray('active persistent live forbidden claims', report.forbidden_claims, ACTIVE_PERSISTENT_PROFILE_FORBIDDEN_CLAIMS);
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return true;
}

export function assertActivePersistentProfileLiveCloseout(closeout) {
  assertExactKeys('active persistent live closeout', closeout, [
    'action_class',
    'activation_root_label',
    'active',
    'closed_at',
    'closeout_reactivation_allowed',
    'closeout_reason',
    'closeout_type',
    'deployment_profile_id',
    'manifest_sha256',
    'previous_status',
    'runtime_profile_id',
    'runtime_profile_sha256',
    'status',
  ]);
  if (
    closeout.closeout_type !== PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_CLOSEOUT_TYPE ||
    closeout.deployment_profile_id !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID ||
    closeout.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    closeout.runtime_profile_sha256 !== ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256 ||
    closeout.action_class !== ACTIVE_PERSISTENT_PROFILE_ACTION_CLASS ||
    closeout.status !== 'closed_inert_evidence' ||
    closeout.active !== false ||
    closeout.closeout_reactivation_allowed !== false
  ) {
    throw new Error('active persistent live closeout drifted');
  }
  expectString('active persistent live closeout previous status', closeout.previous_status);
  expectString('active persistent live closeout closed at', closeout.closed_at);
  expectString('active persistent live closeout reason', closeout.closeout_reason);
  expectString('active persistent live closeout root label', closeout.activation_root_label);
  expectSha('active persistent live closeout manifest hash', closeout.manifest_sha256);
  return true;
}

export function formatActivePersistentProfileLiveInstallationReport(report) {
  assertActivePersistentProfileLiveInstallationReport(report);
  return [
    'ZLAR Active Persistent Profile Live Installation Proof v1',
    `claim=${report.safe_claim}`,
    `activation_root=${report.activation_root_label}`,
    `named_live_root=${report.named_live_root}`,
    `runtime_profile_id=${report.selected_profile.runtime_profile_id}`,
    `runtime_profile_sha256=${report.selected_profile.runtime_profile_sha256}`,
    `selected_by_explicit_id_and_sha=${report.selected_profile.selected_by_explicit_id_and_sha}`,
    `selects_latest=${report.selected_profile.selects_latest_profile}`,
    `final_root_state=${report.final_root_state}`,
    `active_after_proof=${report.active_after_proof}`,
    `closed_root_replacement_authorized=${report.preinstall_status.closed_root_replacement_authorized}`,
    `expires_at=${report.expires_at}`,
    `installed_preflight_sha256=${report.readback_preflight.installed_runtime_profile_preflight_sha256}`,
    `runtime_contract: consumed_authority_grant_store=${report.runtime_profile_contract.consumed_authority_grant_store}; consumption_identity=${report.runtime_profile_contract.consumption_identity}; signed_payload_replay_identity=${report.runtime_profile_contract.signed_payload_replay_identity}; witness=${report.runtime_profile_contract.consumed_store_witness}`,
    `grant_readback: requirement_preserved=${report.readback_preflight.authority_grant_requirement_preserved}; exact_runtime_contract_deferred=${report.readback_preflight.exact_runtime_authority_grant_contract_deferred}; rightful_issuance_proven=${report.readback_preflight.rightful_issuance_proven}`,
    `storage_boundaries: atomic_store_anchor_witness_commit=${report.readback_preflight.atomic_store_anchor_witness_commit}; burn_window_proven_by_installation=${report.readback_preflight.partial_grant_commit_burn_window_proven}; joint_rollback_detection=${report.readback_preflight.store_anchor_and_witness_joint_rollback_detection}; host_path_toctou_closed=${report.readback_preflight.host_filesystem_path_toctou_closed}`,
    `rightful_issuance_boundary: fixture_path_evidenced=${report.claim_boundary.fixture_rightful_issuance_path_evidenced}; rightful_issuance_proven=${report.claim_boundary.rightful_issuance_proven}; live_authority_proven=${report.claim_boundary.live_authority_proven}; consequence_lifecycle_closed=${report.claim_boundary.consequence_lifecycle_closed}`,
    `runtime_service_started=${report.write_boundary.runtime_service_started}`,
    `hooks_or_config_written_outside_root=${report.write_boundary.hooks_or_config_written_outside_root}`,
    `current_machine_governance_general=${report.claim_boundary.current_machine_governance_general}`,
    `production_downstream_recognition=${report.claim_boundary.production_downstream_recognition}`,
  ].join('\n') + '\n';
}

export function formatActivePersistentProfileLiveStatus(status) {
  assertActivePersistentProfileLiveStatus(status);
  return [
    'ZLAR Active Persistent Profile Live Status v1',
    `activation_root=${status.activation_root_label}`,
    `named_live_root=${status.named_live_root}`,
    `state=${status.activation_root_state}`,
    `manifest_status=${status.manifest_status}`,
    `active=${status.active}`,
    `expired=${status.expired}`,
    `safe_for_install=${status.safe_for_install}`,
    `explicit_closeout_or_replace_required=${status.explicit_closeout_or_replace_required}`,
    `expires_at=${status.expires_at || 'none'}`,
  ].join('\n') + '\n';
}

export function formatActivePersistentProfileLiveCloseout(closeout) {
  assertActivePersistentProfileLiveCloseout(closeout);
  return [
    'ZLAR Active Persistent Profile Live Closeout v1',
    `activation_root=${closeout.activation_root_label}`,
    `previous_status=${closeout.previous_status}`,
    `status=${closeout.status}`,
    `active=${closeout.active}`,
    `closed_at=${closeout.closed_at}`,
    `reason=${closeout.closeout_reason}`,
    `manifest_sha256=${closeout.manifest_sha256}`,
    `closeout_reactivation_allowed=${closeout.closeout_reactivation_allowed}`,
  ].join('\n') + '\n';
}

export function writeActivePersistentProfileLiveReport({
  report,
  outputPath,
  activationRoot,
}) {
  assertActivePersistentProfileLiveInstallationReport(report);
  if (!outputPath) {
    throw new Error('active persistent live report output path is required');
  }
  assertReportOutputPath({ outputPath, activationRoot });
  return writeJsonAtomic(outputPath, report);
}
