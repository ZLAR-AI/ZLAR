import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { canonicalize } from './canonicalize.mjs';
import { sha256hex } from './receipt.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from './protected-records-runtime-profile.mjs';
import {
  assertProtectedRecordsRuntimePreflightProfile,
  runtimeProfileSha256 as computeRuntimeProfileSha256,
} from './protected-records-runtime-profile-preflight.mjs';
import {
  PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID,
} from './protected-records-named-deployment-profile-real-boundary.mjs';

export const PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_SOURCE_PREFLIGHT_TYPE =
  'zlar-protected-records-active-persistent-profile-source-preflight-v1';
export const PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_STATUS_TYPE =
  'zlar-protected-records-active-persistent-profile-source-status-v1';
export const PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_MANIFEST_TYPE =
  'zlar-protected-records-active-persistent-profile-manifest-v1';
export const PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_CLOSEOUT_TYPE =
  'zlar-protected-records-active-persistent-profile-closeout-v1';

export const ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE =
  'profiles/protected-records-runtime-fixture.profile.json';
export const ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256 =
  'e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469';
export const ACTIVE_PERSISTENT_PROFILE_ACTION_CLASS = 'records.write';
export const ACTIVE_PERSISTENT_PROFILE_MANIFEST_FILE =
  'active-persistent-profile-manifest.json';

export const ACTIVE_PERSISTENT_PROFILE_SOURCE_PREFLIGHT_CLAIM =
  'ZLAR has source support for a future active persistent profile installation proof, tested only against temp/proof-owned roots. Live activation remains unproven and unauthorized.';

export const ACTIVE_PERSISTENT_PROFILE_FORBIDDEN_CLAIMS = Object.freeze([
  'Active persistent runtime-profile installation.',
  'Current-machine governance generally.',
  'Raw Codex/developer-tool governance.',
  'Browser, Computer Use, MCP, shell, network, or all-surface governance.',
  'Real personal records protection.',
  'Production downstream recognition.',
  'Production authority.',
  'Enterprise readiness.',
  'Public external attestation.',
  'Sovereign recognition.',
  'Side-door closure.',
  'Local fixture rightful-issuance path evidence.',
  'Generic, portable, live, or production rightful issuance.',
  'Consequence lifecycle closure.',
  'Absolute human intention.',
]);

export const REQUIRED_ACTIVE_PERSISTENT_PROFILE_REFUSAL_CASES = Object.freeze([
  'missing_receipt_refused_before_target_mutation',
  'invalid_receipt_refused_before_target_mutation',
  'unknown_signer_refused_before_target_mutation',
  'wrong_issuer_refused_before_target_mutation',
  'wrong_policy_refused_before_target_mutation',
  'wrong_profile_refused_before_target_mutation',
  'wrong_action_class_refused_before_target_mutation',
  'wrong_target_refused_before_target_mutation',
  'stale_receipt_refused_before_target_mutation',
  'expired_receipt_refused_before_target_mutation',
  'same_process_signed_payload_replay_refused_before_target_mutation',
  'restart_consumed_authority_grant_refused_before_target_mutation',
  'missing_authority_grant_appointment_refused_before_consumption_and_target_mutation',
  'mismatched_authority_grant_appointment_refused_before_consumption_and_target_mutation',
  'revoked_authority_grant_refused_before_consumption_and_target_mutation',
  'expired_authority_grant_refused_before_consumption_and_target_mutation',
  'revoked_or_closed_profile_refused_before_target_mutation',
  'request_supplied_authority_grant_refused_before_target_mutation',
]);

export const ACTIVE_PERSISTENT_PROFILE_SOURCE_OPEN_BOUNDARIES = Object.freeze([
  'source_preflight_only',
  'activation_not_performed',
  'persistent_runtime_profile_not_installed',
  'runtime_service_not_started',
  'hook_configuration_not_written',
  'user_or_machine_configuration_not_written',
  'real_activation_root_not_touched',
  'real_records_system_not_touched',
  'production_downstream_recognition_not_proven',
  'current_machine_governance_not_proven',
  'exactly_once_effect_semantics_not_proven',
  'store_anchor_witness_commit_atomicity_not_proven',
  'store_anchor_and_witness_joint_rollback_detection_not_proven',
  'host_filesystem_path_toctou_not_closed',
  'external_attestation_not_proven',
  'unrouted_records_paths_not_closed',
]);

export const ACTIVE_PERSISTENT_PROFILE_SOURCE_NON_CLAIMS = Object.freeze([
  'This source preflight validates command contracts and path gates only; it does not install or activate a persistent profile.',
  'This source preflight requires explicit temp/proof-owned surrogate roots and refuses default current-machine activation roots.',
  'This source preflight binds the runtime profile by explicit runtime profile id, canonical profile artifact label, and canonical profile SHA-256; it does not select --latest, branch, tag, directory order, or repo HEAD.',
  'This source preflight does not write hooks, shell config, app config, user config, machine config, LaunchAgents, daemons, background persistence, runtime service config, production config, receipts, audit logs, or real records.',
  'This source preflight does not use Telegram, external services, GitHub settings, Actions, tags, releases, credentials, HMAC, tokens, YubiKey, private keys, production issuer custody, or production downstream recognition.',
  'This source preflight preserves launcher-owned authority-grant requirements and the selected profile grant-store, signed-payload replay, local-witness, burn-window, joint-rollback, and host-path TOCTOU boundaries; it does not instantiate or enforce a live grant.',
  'This source preflight does not prove exactly-once effects, atomic store-anchor-witness commit, joint store-anchor-witness rollback detection, or host-filesystem path TOCTOU closure.',
  'This source preflight does not prove active persistent runtime-profile installation, current-machine governance, enterprise readiness, public external attestation, sovereign recognition, side-door closure, or absolute human intention.',
]);

function requireObject(label, value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function assertExactKeys(label, value, keys) {
  requireObject(label, value);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} keys drifted`);
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
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) {
    throw new Error(`${label} must be an ISO-8601 timestamp`);
  }
  return Math.floor(ms / 1000);
}

function assertFutureExpiry(expiresAt, nowEpoch) {
  const expiryEpoch = epochFromIso('active persistent profile expiry', expiresAt);
  if (expiryEpoch <= nowEpoch) {
    throw new Error('active persistent profile expiry is expired');
  }
  return expiryEpoch;
}

function assertClosedAt(closedAt) {
  epochFromIso('active persistent profile closeout timestamp', closedAt);
  return true;
}

function isInside(rootRealPath, childRealPath) {
  const rel = relative(rootRealPath, childRealPath);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`));
}

function safeLabel(rootRealPath, candidatePath) {
  let candidateRealPath;
  try {
    candidateRealPath = realpathSync(candidatePath);
  } catch {
    candidateRealPath = join(realpathSync(dirname(candidatePath)), basename(candidatePath));
  }
  const rel = relative(rootRealPath, candidateRealPath);
  if (rel === '') {
    return '<source-preflight-surrogate-root>';
  }
  if (rel === '..' || rel.startsWith(`..${sep}`)) {
    return '<outside-source-preflight-surrogate-root>';
  }
  return `<source-preflight-surrogate-root>/${rel.split(sep).join('/')}`;
}

function assertNotSymlink(path, label, { allowMissing = false } = {}) {
  try {
    if (lstatSync(path).isSymbolicLink()) {
      throw new Error(`${label} symlink escape refused`);
    }
  } catch (err) {
    if (String(err.message).includes('symlink escape refused')) {
      throw err;
    }
    if (allowMissing) {
      return false;
    }
    throw new Error(`${label} could not be inspected`);
  }
  return true;
}

function assertNoPracticalHardlinkEscape(path, label, { allowMissing = false } = {}) {
  try {
    const stat = statSync(path);
    if (stat.isFile() && stat.nlink > 1) {
      throw new Error(`${label} hardlink or alias risk refused`);
    }
  } catch (err) {
    if (String(err.message).includes('hardlink or alias risk refused')) {
      throw err;
    }
    if (allowMissing) {
      return false;
    }
    throw new Error(`${label} could not be inspected`);
  }
  return true;
}

function forbiddenRealActivationRoot() {
  return resolve(
    homedir(),
    '.zlar',
    'protected-records',
    'deployments',
    PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID
  );
}

function assertNotRealActivationRoot(path) {
  const resolved = resolve(path);
  const forbidden = forbiddenRealActivationRoot();
  if (resolved === forbidden || resolved.startsWith(`${forbidden}${sep}`)) {
    throw new Error('real active persistent profile activation root is not allowed in source preflight');
  }
  return true;
}

function isForbiddenRealActivationPath(path) {
  const resolved = resolve(path);
  const forbidden = forbiddenRealActivationRoot();
  return resolved === forbidden || resolved.startsWith(`${forbidden}${sep}`);
}

function assertNamedActivationRootShape(path) {
  if (basename(resolve(path)) !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID) {
    throw new Error('active persistent activation root must end with the named deployment profile id');
  }
  return true;
}

export function assertSourcePreflightIoPathNotRealActivationRoot(path, label = 'active persistent profile source preflight path') {
  if (!path || path === '-') {
    return true;
  }
  const resolved = resolve(path);
  if (isForbiddenRealActivationPath(resolved)) {
    throw new Error(`${label} may not be inside the real active persistent profile activation root`);
  }
  const pending = [resolved];
  const seen = new Set();
  while (pending.length > 0) {
    const candidate = resolve(pending.pop());
    if (seen.has(candidate)) {
      continue;
    }
    seen.add(candidate);
    if (isForbiddenRealActivationPath(candidate)) {
      throw new Error(`${label} symlink route refused`);
    }
    let current = sep;
    const parts = candidate.split(sep).filter(Boolean);
    for (let index = 0; index < parts.length; index++) {
      current = join(current, parts[index]);
      try {
        if (lstatSync(current).isSymbolicLink()) {
          const target = readlinkSync(current);
          const remaining = parts.slice(index + 1).join(sep);
          const routed = remaining
            ? resolve(dirname(current), target, remaining)
            : resolve(dirname(current), target);
          if (isForbiddenRealActivationPath(routed)) {
            throw new Error(`${label} symlink route refused`);
          }
          pending.push(routed);
          break;
        }
      } catch (err) {
        if (String(err.message).includes('symlink route refused')) {
          throw err;
        }
        if (err && err.code === 'ENOENT') {
          break;
        }
        throw new Error(`${label} could not be inspected`);
      }
    }
  }
  return true;
}

function assertContainedPath({ surrogateRootRealPath, path, label, mustExist = true }) {
  assertNotSymlink(path, label, { allowMissing: !mustExist });
  const targetRealPath = mustExist ? realpathSync(path) : realpathSync(dirname(path));
  if (!isInside(surrogateRootRealPath, targetRealPath)) {
    throw new Error(`${label} realpath containment refused`);
  }
  return true;
}

function activationRootState({ activationRoot, nowEpoch }) {
  assertNotRealActivationRoot(activationRoot);
  assertNamedActivationRootShape(activationRoot);
  const manifestPath = join(activationRoot, ACTIVE_PERSISTENT_PROFILE_MANIFEST_FILE);
  if (!existsSync(activationRoot)) {
    return {
      state: 'absent',
      safe_for_source_preflight: true,
      existing_active_root_refused: false,
      manifest_present: false,
      manifest_status: 'not_present',
      explicit_replace_required: false,
    };
  }
  assertNotSymlink(activationRoot, 'active persistent activation root');
  const stat = statSync(activationRoot);
  if (!stat.isDirectory()) {
    throw new Error('active persistent activation root must be a directory');
  }
  const entries = readdirSync(activationRoot);
  if (entries.length === 0) {
    return {
      state: 'empty',
      safe_for_source_preflight: true,
      existing_active_root_refused: false,
      manifest_present: false,
      manifest_status: 'not_present',
      explicit_replace_required: false,
    };
  }

  let manifestStatus = 'unreadable_or_unknown';
  let expiresAt = null;
  if (existsSync(manifestPath)) {
    try {
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
      manifestStatus = manifest.status || 'missing_status';
      expiresAt = manifest.expires_at || null;
      if (
        typeof expiresAt === 'string' &&
        Date.parse(expiresAt) <= nowEpoch * 1000 &&
        !['closed_inert_evidence', 'revoked'].includes(manifestStatus)
      ) {
        manifestStatus = 'expired_active_or_preparing';
      }
    } catch {
      manifestStatus = 'invalid_manifest';
    }
  }

  return {
    state: 'existing_nonempty',
    safe_for_source_preflight: false,
    existing_active_root_refused: true,
    manifest_present: existsSync(manifestPath),
    manifest_status: manifestStatus,
    explicit_replace_required: true,
  };
}

export function inspectActivePersistentProfileSourceStatus({
  surrogateRoot,
  activationRoot,
  nowEpoch = Math.floor(Date.now() / 1000),
}) {
  if (!surrogateRoot || !activationRoot) {
    throw new Error('active persistent source status requires surrogate root and activation root');
  }
  assertNotRealActivationRoot(activationRoot);
  assertNamedActivationRootShape(activationRoot);
  assertNotSymlink(surrogateRoot, 'source-preflight surrogate root');
  const surrogateRootRealPath = realpathSync(surrogateRoot);
  assertContainedPath({
    surrogateRootRealPath,
    path: activationRoot,
    label: 'active persistent activation root',
    mustExist: existsSync(activationRoot),
  });
  const state = activationRootState({ activationRoot, nowEpoch });
  const status = {
    status_type: PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_STATUS_TYPE,
    evidence_model: 'explicit-proof-owned-surrogate-root-status-only',
    live_probing: false,
    read_only: true,
    real_activation_root_touched: false,
    activation_root_label: safeLabel(surrogateRootRealPath, activationRoot),
    activation_root_state: state.state,
    safe_for_source_preflight: state.safe_for_source_preflight,
    existing_active_root_refused: state.existing_active_root_refused,
    manifest_present: state.manifest_present,
    manifest_status: state.manifest_status,
    explicit_replace_required: state.explicit_replace_required,
  };
  assertActivePersistentProfileSourceStatus(status);
  return status;
}

export function assertActivePersistentProfileSourceStatus(status) {
  assertExactKeys('active persistent profile source status', status, [
    'activation_root_label',
    'activation_root_state',
    'evidence_model',
    'existing_active_root_refused',
    'explicit_replace_required',
    'live_probing',
    'manifest_present',
    'manifest_status',
    'read_only',
    'real_activation_root_touched',
    'safe_for_source_preflight',
    'status_type',
  ]);
  if (
    status.status_type !== PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_STATUS_TYPE ||
    status.evidence_model !== 'explicit-proof-owned-surrogate-root-status-only' ||
    status.live_probing !== false ||
    status.read_only !== true ||
    status.real_activation_root_touched !== false
  ) {
    throw new Error('active persistent profile source status drifted');
  }
  expectString('active persistent activation root label', status.activation_root_label);
  for (const key of [
    'safe_for_source_preflight',
    'existing_active_root_refused',
    'manifest_present',
    'explicit_replace_required',
  ]) {
    if (typeof status[key] !== 'boolean') {
      throw new Error(`active persistent profile source status ${key} drifted`);
    }
  }
  return true;
}

function assertFixedRuntimeProfile({
  profile,
  profileSource,
  runtimeProfileId,
  runtimeProfileSha256,
}) {
  assertProtectedRecordsRuntimePreflightProfile(profile);
  const profileSha = computeRuntimeProfileSha256(profile);
  if (
    profileSource !== ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE ||
    profile.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    runtimeProfileId !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    runtimeProfileSha256 !== ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256 ||
    profileSha !== ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256 ||
    profile.action_class !== ACTIVE_PERSISTENT_PROFILE_ACTION_CLASS
  ) {
    throw new Error('active persistent profile source preflight fixed runtime profile binding failed');
  }
  return profileSha;
}

export function buildActivePersistentProfileRuntimeContractEvidence(profile) {
  assertProtectedRecordsRuntimePreflightProfile(profile);
  const required = new Set(profile.required_cases);
  const evidence = {
    mutation_authoritative_route: profile.mutation_authoritative_route,
    consumed_authority_grant_store: profile.consumed_authority_grant_store,
    consumption_identity: profile.consumption_identity,
    signed_payload_replay_identity: profile.signed_payload_replay_identity,
    consumed_store_witness: profile.consumed_store_witness,
    consumed_store_write_model: profile.consumed_store_write_model,
    authority_grant_contract_required_from_launcher:
      profile.authority_boundary.authority_grant_contract_required_from_launcher,
    authority_grant_appointment_required_from_launcher:
      profile.authority_boundary.authority_grant_appointment_required_from_launcher,
    authority_grant_issuance_decision_required_from_launcher:
      profile.authority_boundary.authority_grant_issuance_decision_required_from_launcher,
    authorized_record_update_required_from_launcher:
      profile.authority_boundary.authorized_record_update_required_from_launcher,
    request_stream_authority_material_accepted:
      profile.authority_boundary.request_stream_authority_material_accepted,
    same_process_signed_payload_replay_case_required:
      required.has('replay_runtime_write_refused_same_service_process'),
    restart_consumed_authority_grant_refusal_case_required:
      required.has('replay_runtime_write_refused_after_service_restart'),
    missing_authority_grant_appointment_refusal_case_required:
      required.has('missing_authority_grant_appointment_refused_before_consumption'),
    mismatched_authority_grant_appointment_refusal_case_required:
      required.has('mismatched_authority_grant_appointment_refused_before_consumption'),
    revoked_authority_grant_refusal_case_required:
      required.has('revoked_authority_grant_refused_before_consumption'),
    expired_authority_grant_refusal_case_required:
      required.has('expired_authority_grant_refused_before_consumption'),
    request_supplied_authority_grant_refusal_case_required:
      required.has('agent_supplied_authority_grant_refused_before_runtime_mutation'),
    persistent_consumed_authority_grant_store:
      profile.storage_boundary.persistent_consumed_authority_grant_store,
    store_and_anchor_joint_rollback_refused_while_witness_ahead:
      profile.storage_boundary.store_and_anchor_joint_rollback_refused_while_witness_ahead,
    store_anchor_and_witness_joint_rollback_detection:
      profile.storage_boundary.store_anchor_and_witness_joint_rollback_detection,
    atomic_store_anchor_witness_commit:
      profile.storage_boundary.atomic_store_anchor_witness_commit,
    partial_grant_commit_burn_window_named:
      profile.storage_boundary.partial_grant_commit_burn_window_named,
    partial_commit_witness_missing_observed:
      profile.storage_boundary.partial_commit_witness_missing_observed,
    host_filesystem_path_toctou_closed:
      profile.storage_boundary.host_filesystem_path_toctou_closed,
    exactly_once_effect_semantics:
      profile.storage_boundary.exactly_once_effect_semantics,
  };
  assertActivePersistentProfileRuntimeContractEvidence(evidence);
  return evidence;
}

export function assertActivePersistentProfileRuntimeContractEvidence(evidence) {
  assertExactKeys('active persistent runtime contract evidence', evidence, [
    'atomic_store_anchor_witness_commit',
    'authority_grant_appointment_required_from_launcher',
    'authority_grant_contract_required_from_launcher',
    'authority_grant_issuance_decision_required_from_launcher',
    'authorized_record_update_required_from_launcher',
    'consumed_authority_grant_store',
    'consumed_store_witness',
    'consumed_store_write_model',
    'consumption_identity',
    'exactly_once_effect_semantics',
    'expired_authority_grant_refusal_case_required',
    'host_filesystem_path_toctou_closed',
    'mismatched_authority_grant_appointment_refusal_case_required',
    'missing_authority_grant_appointment_refusal_case_required',
    'mutation_authoritative_route',
    'partial_commit_witness_missing_observed',
    'partial_grant_commit_burn_window_named',
    'persistent_consumed_authority_grant_store',
    'request_stream_authority_material_accepted',
    'request_supplied_authority_grant_refusal_case_required',
    'restart_consumed_authority_grant_refusal_case_required',
    'revoked_authority_grant_refusal_case_required',
    'same_process_signed_payload_replay_case_required',
    'signed_payload_replay_identity',
    'store_anchor_and_witness_joint_rollback_detection',
    'store_and_anchor_joint_rollback_refused_while_witness_ahead',
  ]);
  if (
    evidence.mutation_authoritative_route !==
      'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation' ||
    evidence.consumed_authority_grant_store !==
      'persistent-single-use-authority-grant-contract-sha256-store' ||
    evidence.consumption_identity !== 'authority-grant-contract-sha256' ||
    evidence.signed_payload_replay_identity !== 'verified-signed-payload-sha256' ||
    evidence.consumed_store_witness !== 'launcher-owned-local-store-hash-witness' ||
    evidence.consumed_store_write_model !==
      'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness'
  ) {
    throw new Error('active persistent runtime storage or replay contract drifted');
  }
  for (const key of [
    'authority_grant_contract_required_from_launcher',
    'authority_grant_appointment_required_from_launcher',
    'authority_grant_issuance_decision_required_from_launcher',
    'authorized_record_update_required_from_launcher',
    'same_process_signed_payload_replay_case_required',
    'restart_consumed_authority_grant_refusal_case_required',
    'missing_authority_grant_appointment_refusal_case_required',
    'mismatched_authority_grant_appointment_refusal_case_required',
    'revoked_authority_grant_refusal_case_required',
    'expired_authority_grant_refusal_case_required',
    'request_supplied_authority_grant_refusal_case_required',
    'persistent_consumed_authority_grant_store',
    'store_and_anchor_joint_rollback_refused_while_witness_ahead',
    'partial_grant_commit_burn_window_named',
    'partial_commit_witness_missing_observed',
  ]) {
    expectBool(`active persistent runtime contract ${key}`, evidence[key], true);
  }
  for (const key of [
    'request_stream_authority_material_accepted',
    'store_anchor_and_witness_joint_rollback_detection',
    'atomic_store_anchor_witness_commit',
    'host_filesystem_path_toctou_closed',
    'exactly_once_effect_semantics',
  ]) {
    expectBool(`active persistent runtime contract ${key}`, evidence[key], false);
  }
  return true;
}

function buildCommandContracts({ activationRootLabel, proofTargetLabel, expiresAt }) {
  return {
    install_command_contract:
      'zlar protected-records-active-persistent-profile-preflight --surrogate-root <explicit-temp-or-proof-owned-root> --activation-root <explicit-temp-or-proof-owned-root>/activation/protected-records-private-operator-records-terminal --proof-target <explicit-temp-or-proof-owned-root>/proof/records-target.jsonl --profile profiles/protected-records-runtime-fixture.profile.json --runtime-profile-id protected-records-disposable-runtime-profile --runtime-profile-sha256 e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469 --expires-at <future-iso8601>',
    status_command_contract:
      'zlar protected-records-active-persistent-profile-preflight status --surrogate-root <explicit-temp-or-proof-owned-root> --activation-root <explicit-temp-or-proof-owned-root>/activation/protected-records-private-operator-records-terminal',
    closeout_command_contract:
      'zlar protected-records-active-persistent-profile-preflight closeout --manifest <source-preflight-manifest.json> --closed-at <iso8601> --reason <operator-approved-closeout> --output <explicit-temp-or-proof-owned-closeout.json>',
    generated_command_defaults_real_activation_root: false,
    generated_command_has_postinstall_side_effects: false,
    generated_command_writes_hooks_or_persistence: false,
    generated_command_requires_explicit_activation_root: true,
    generated_command_requires_explicit_proof_target: true,
    generated_command_requires_explicit_expiry: true,
    command_target_labels: {
      activation_root: activationRootLabel,
      proof_target: proofTargetLabel,
      expires_at: expiresAt,
    },
  };
}

function buildRefusalMatrix() {
  return REQUIRED_ACTIVE_PERSISTENT_PROFILE_REFUSAL_CASES.map((caseId) => ({
    case_id: caseId,
    supported_by_source_preflight_contract: true,
    refused_before_target_mutation: true,
    target_mutation_allowed: false,
  }));
}

function buildCrashInterruptionContract() {
  return {
    contract_type: 'zlar-active-persistent-profile-crash-interruption-contract-v1',
    manifest_write_model: 'future-install-must-use-temp-file-fsync-rename',
    before_manifest_commit: 'no active profile exists; rerun only after empty-root check',
    preparing_manifest_found: 'refuse new install; require closeout or explicit replace authority',
    active_manifest_found: 'refuse new install; require closeout or explicit replace authority',
    expired_manifest_found: 'refuse before activation or target mutation',
    closeout_manifest_found: 'treat as inert evidence; do not reactivate silently',
    service_crash_after_authority_grant_consumption: 'the one-use authority grant may be burned without runtime-state mutation; closeout records interrupted state before any retry authority',
    testable_in_source_preflight: true,
  };
}

export function buildActivePersistentProfileSourceManifest(report) {
  assertActivePersistentProfileSourcePreflight(report);
  return {
    manifest_type: PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_MANIFEST_TYPE,
    deployment_profile_id: report.profile_binding.deployment_profile_id,
    runtime_profile_id: report.profile_binding.runtime_profile_id,
    runtime_profile_sha256: report.profile_binding.runtime_profile_sha256,
    action_class: report.profile_binding.action_class,
    status: 'prepared_source_preflight_only',
    active: false,
    activation_allowed: false,
    expires_at: report.expiry.expires_at,
    activation_root_label: report.path_boundary.activation_root_label,
    proof_target_label: report.path_boundary.proof_target_label,
    source_preflight_report_sha256: sha256hex(canonicalize(report)),
  };
}

export function buildActivePersistentProfileCloseout(manifest, {
  closedAt,
  reason = 'operator_closeout',
} = {}) {
  assertActivePersistentProfileSourceManifest(manifest);
  assertClosedAt(closedAt);
  if (typeof reason !== 'string' || !/^[a-z0-9][a-z0-9._-]{2,127}$/.test(reason)) {
    throw new Error('active persistent profile closeout reason is malformed');
  }
  const closeout = {
    closeout_type: PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_CLOSEOUT_TYPE,
    deployment_profile_id: manifest.deployment_profile_id,
    runtime_profile_id: manifest.runtime_profile_id,
    runtime_profile_sha256: manifest.runtime_profile_sha256,
    action_class: manifest.action_class,
    previous_status: manifest.status,
    status: 'closed_inert_evidence',
    active: false,
    activation_allowed: false,
    closed_at: closedAt,
    closeout_reason: reason,
    activation_root_label: manifest.activation_root_label,
    proof_target_label: manifest.proof_target_label,
    rollback_or_closeout_tested: true,
    closeout_reactivation_allowed: false,
    source_preflight_report_sha256: manifest.source_preflight_report_sha256,
  };
  assertActivePersistentProfileCloseout(closeout);
  return closeout;
}

export function assertActivePersistentProfileSourceManifest(manifest) {
  assertExactKeys('active persistent profile source manifest', manifest, [
    'action_class',
    'activation_allowed',
    'activation_root_label',
    'active',
    'deployment_profile_id',
    'expires_at',
    'manifest_type',
    'proof_target_label',
    'runtime_profile_id',
    'runtime_profile_sha256',
    'source_preflight_report_sha256',
    'status',
  ]);
  if (
    manifest.manifest_type !== PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_MANIFEST_TYPE ||
    manifest.deployment_profile_id !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID ||
    manifest.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    manifest.runtime_profile_sha256 !== ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256 ||
    manifest.action_class !== ACTIVE_PERSISTENT_PROFILE_ACTION_CLASS ||
    manifest.status !== 'prepared_source_preflight_only' ||
    manifest.active !== false ||
    manifest.activation_allowed !== false
  ) {
    throw new Error('active persistent profile source manifest drifted');
  }
  expectSha('active persistent profile source report hash', manifest.source_preflight_report_sha256);
  expectString('active persistent profile manifest activation root label', manifest.activation_root_label);
  expectString('active persistent profile manifest proof target label', manifest.proof_target_label);
  expectString('active persistent profile manifest expiry', manifest.expires_at);
  return true;
}

export function assertActivePersistentProfileCloseout(closeout) {
  assertExactKeys('active persistent profile closeout', closeout, [
    'action_class',
    'activation_allowed',
    'activation_root_label',
    'active',
    'closed_at',
    'closeout_reason',
    'closeout_reactivation_allowed',
    'closeout_type',
    'deployment_profile_id',
    'previous_status',
    'proof_target_label',
    'rollback_or_closeout_tested',
    'runtime_profile_id',
    'runtime_profile_sha256',
    'source_preflight_report_sha256',
    'status',
  ]);
  if (
    closeout.closeout_type !== PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_CLOSEOUT_TYPE ||
    closeout.deployment_profile_id !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID ||
    closeout.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    closeout.runtime_profile_sha256 !== ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256 ||
    closeout.action_class !== ACTIVE_PERSISTENT_PROFILE_ACTION_CLASS ||
    closeout.previous_status !== 'prepared_source_preflight_only' ||
    closeout.status !== 'closed_inert_evidence' ||
    closeout.active !== false ||
    closeout.activation_allowed !== false ||
    closeout.rollback_or_closeout_tested !== true ||
    closeout.closeout_reactivation_allowed !== false
  ) {
    throw new Error('active persistent profile closeout drifted');
  }
  expectSha('active persistent profile closeout source preflight report hash', closeout.source_preflight_report_sha256);
  expectString('active persistent profile closeout activation root label', closeout.activation_root_label);
  expectString('active persistent profile closeout proof target label', closeout.proof_target_label);
  expectString('active persistent profile closeout closed at', closeout.closed_at);
  return true;
}

export function runActivePersistentProfileSourcePreflight({
  surrogateRoot,
  activationRoot,
  proofTarget,
  profile,
  profileSource,
  runtimeProfileId,
  runtimeProfileSha256,
  expiresAt,
  nowEpoch = Math.floor(Date.now() / 1000),
}) {
  if (!surrogateRoot || !activationRoot || !proofTarget) {
    throw new Error('active persistent profile source preflight requires surrogate root, activation root, and proof target');
  }
  assertFutureExpiry(expiresAt, nowEpoch);
  const profileSha = assertFixedRuntimeProfile({
    profile,
    profileSource,
    runtimeProfileId,
    runtimeProfileSha256,
  });

  assertNotRealActivationRoot(activationRoot);
  assertNotSymlink(surrogateRoot, 'source-preflight surrogate root');
  const surrogateRootRealPath = realpathSync(surrogateRoot);
  assertContainedPath({
    surrogateRootRealPath,
    path: activationRoot,
    label: 'active persistent activation root',
    mustExist: existsSync(activationRoot),
  });
  assertContainedPath({
    surrogateRootRealPath,
    path: proofTarget,
    label: 'active persistent proof target',
    mustExist: existsSync(proofTarget),
  });
  assertNamedActivationRootShape(activationRoot);
  assertNotSymlink(proofTarget, 'active persistent proof target', { allowMissing: true });
  assertNoPracticalHardlinkEscape(proofTarget, 'active persistent proof target', { allowMissing: true });

  const existingState = activationRootState({ activationRoot, nowEpoch });
  if (!existingState.safe_for_source_preflight) {
    throw new Error('active persistent profile existing activation root requires explicit closeout or replace authority');
  }

  const activationRootLabel = safeLabel(surrogateRootRealPath, activationRoot);
  const proofTargetLabel = safeLabel(surrogateRootRealPath, proofTarget);
  const report = {
    report_type: PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_SOURCE_PREFLIGHT_TYPE,
    schema_version: 1,
    evidence_model: 'source-only-active-persistent-profile-preflight-temp-surrogate',
    live_probing: false,
    source_only: true,
    claim: ACTIVE_PERSISTENT_PROFILE_SOURCE_PREFLIGHT_CLAIM,
    authority_boundary: {
      human_authority_scope: 'source_preflight_only',
      activation_authorized: false,
      install_authorized: false,
      real_activation_root_touched: false,
      hooks_or_config_written: false,
      network_or_external_service_used: false,
      private_key_or_credential_material_used: false,
    },
    profile_binding: {
      deployment_profile_id: PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID,
      action_class: ACTIVE_PERSISTENT_PROFILE_ACTION_CLASS,
      runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      runtime_profile_sha256: profileSha,
      runtime_profile_sha_matches_required: true,
      canonical_runtime_profile_source: ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
      selected_by_explicit_id_and_sha: true,
      selects_latest_profile: false,
      moving_selector_accepted: false,
    },
    runtime_profile_contract: buildActivePersistentProfileRuntimeContractEvidence(profile),
    expiry: {
      expiry_required: true,
      expires_at: expiresAt,
      now: isoFromEpoch(nowEpoch),
      expired_profile_refused: true,
    },
    path_boundary: {
      surrogate_root_label: '<source-preflight-surrogate-root>',
      activation_root_label: activationRootLabel,
      proof_target_label: proofTargetLabel,
      activation_root_name_matches_profile_id: true,
      activation_root_realpath_contained: true,
      proof_target_realpath_contained: true,
      symlink_escape_refused: true,
      hardlink_escape_refused_where_practical: true,
      alias_risk_documented: true,
      portable_alias_boundary: 'symlink and multi-link file refusal are enforced; platform-specific Finder aliases remain documented residual risk unless exposed as symlinks or multi-link files',
      real_activation_root_default_used: false,
      real_activation_root_lexical_refusal: true,
    },
    existing_root_policy: {
      existing_root_state: existingState.state,
      existing_active_root_refused: existingState.existing_active_root_refused,
      silent_overwrite_allowed: false,
      explicit_closeout_or_replace_required_for_nonempty_root: true,
      replace_mode_supported_by_source_preflight: false,
    },
    command_contracts: buildCommandContracts({
      activationRootLabel,
      proofTargetLabel,
      expiresAt,
    }),
    refusal_matrix: buildRefusalMatrix(),
    closeout_contract: {
      rollback_or_closeout_required: true,
      closeout_manifest_type: PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_CLOSEOUT_TYPE,
      closeout_sets_active_false: true,
      closeout_reactivation_allowed: false,
      revoked_or_closed_profile_refused_before_target_mutation: true,
      rollback_without_explicit_closeout_refused: true,
    },
    crash_interruption_contract: buildCrashInterruptionContract(),
    write_boundary: {
      report_write_allowed: true,
      activation_root_write_allowed: false,
      proof_target_write_allowed: false,
      hook_configuration_write_allowed: false,
      user_config_write_allowed: false,
      machine_config_write_allowed: false,
      daemon_or_launchagent_write_allowed: false,
      shell_config_write_allowed: false,
      runtime_service_start_allowed: false,
      background_persistence_allowed: false,
      auto_activation_allowed: false,
    },
    privacy_hygiene: {
      private_key_material_absent: true,
      hmac_token_yubikey_material_absent: true,
      real_personal_files_used: false,
      activation_temp_root_private_material_absent: true,
      scratch_evidence_private_material_absent: true,
      report_private_material_absent: true,
      logs_private_material_absent: true,
      closeout_private_material_absent: true,
      source_diff_private_material_required: false,
    },
    claim_boundary: {
      active_persistent_runtime_profile_installation: false,
      fixture_rightful_issuance_path_evidenced: false,
      rightful_issuance_proven: false,
      portable_rightful_issuance_proven: false,
      live_authority_proven: false,
      production_rightful_issuance_proven: false,
      consequence_lifecycle_closed: false,
      current_machine_governance_general: false,
      raw_codex_or_developer_tool_governance: false,
      browser_computer_use_mcp_shell_network_or_all_surface_governance: false,
      real_personal_records_protection: false,
      production_downstream_recognition: false,
      production_authority: false,
      enterprise_readiness: false,
      public_external_attestation: false,
      sovereign_recognition: false,
      side_door_closure: false,
      absolute_human_intention: false,
    },
    known_open_boundaries: [...ACTIVE_PERSISTENT_PROFILE_SOURCE_OPEN_BOUNDARIES],
    forbidden_claims: [...ACTIVE_PERSISTENT_PROFILE_FORBIDDEN_CLAIMS],
    non_claims: [...ACTIVE_PERSISTENT_PROFILE_SOURCE_NON_CLAIMS],
  };
  assertActivePersistentProfileSourcePreflight(report);
  return report;
}

export function assertActivePersistentProfileSourcePreflight(report) {
  assertExactKeys('active persistent profile source preflight report', report, [
    'authority_boundary',
    'claim',
    'claim_boundary',
    'closeout_contract',
    'command_contracts',
    'crash_interruption_contract',
    'evidence_model',
    'existing_root_policy',
    'expiry',
    'forbidden_claims',
    'known_open_boundaries',
    'live_probing',
    'non_claims',
    'path_boundary',
    'privacy_hygiene',
    'profile_binding',
    'refusal_matrix',
    'report_type',
    'runtime_profile_contract',
    'schema_version',
    'source_only',
    'write_boundary',
  ]);
  if (
    report.report_type !== PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_SOURCE_PREFLIGHT_TYPE ||
    report.schema_version !== 1 ||
    report.evidence_model !== 'source-only-active-persistent-profile-preflight-temp-surrogate' ||
    report.live_probing !== false ||
    report.source_only !== true ||
    report.claim !== ACTIVE_PERSISTENT_PROFILE_SOURCE_PREFLIGHT_CLAIM
  ) {
    throw new Error('active persistent profile source preflight top-level contract drifted');
  }

  assertExactKeys('active persistent profile source authority boundary', report.authority_boundary, [
    'activation_authorized',
    'hooks_or_config_written',
    'human_authority_scope',
    'install_authorized',
    'network_or_external_service_used',
    'private_key_or_credential_material_used',
    'real_activation_root_touched',
  ]);
  if (report.authority_boundary.human_authority_scope !== 'source_preflight_only') {
    throw new Error('active persistent profile source authority scope drifted');
  }
  for (const key of [
    'activation_authorized',
    'install_authorized',
    'real_activation_root_touched',
    'hooks_or_config_written',
    'network_or_external_service_used',
    'private_key_or_credential_material_used',
  ]) {
    expectBool(`active persistent source authority ${key}`, report.authority_boundary[key], false);
  }

  assertExactKeys('active persistent profile source profile binding', report.profile_binding, [
    'action_class',
    'canonical_runtime_profile_source',
    'deployment_profile_id',
    'moving_selector_accepted',
    'runtime_profile_id',
    'runtime_profile_sha256',
    'runtime_profile_sha_matches_required',
    'selected_by_explicit_id_and_sha',
    'selects_latest_profile',
  ]);
  if (
    report.profile_binding.deployment_profile_id !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID ||
    report.profile_binding.action_class !== ACTIVE_PERSISTENT_PROFILE_ACTION_CLASS ||
    report.profile_binding.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    report.profile_binding.runtime_profile_sha256 !== ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256 ||
    report.profile_binding.canonical_runtime_profile_source !== ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE ||
    report.profile_binding.runtime_profile_sha_matches_required !== true ||
    report.profile_binding.selected_by_explicit_id_and_sha !== true ||
    report.profile_binding.selects_latest_profile !== false ||
    report.profile_binding.moving_selector_accepted !== false
  ) {
    throw new Error('active persistent profile source profile binding drifted');
  }
  assertActivePersistentProfileRuntimeContractEvidence(report.runtime_profile_contract);

  assertExactKeys('active persistent profile source expiry', report.expiry, [
    'expired_profile_refused',
    'expires_at',
    'expiry_required',
    'now',
  ]);
  expectBool('active persistent expiry required', report.expiry.expiry_required, true);
  expectBool('active persistent expired profile refused', report.expiry.expired_profile_refused, true);
  expectString('active persistent expiry timestamp', report.expiry.expires_at);
  expectString('active persistent now timestamp', report.expiry.now);

  assertExactKeys('active persistent profile source path boundary', report.path_boundary, [
    'activation_root_label',
    'activation_root_name_matches_profile_id',
    'activation_root_realpath_contained',
    'alias_risk_documented',
    'hardlink_escape_refused_where_practical',
    'portable_alias_boundary',
    'proof_target_label',
    'proof_target_realpath_contained',
    'real_activation_root_default_used',
    'real_activation_root_lexical_refusal',
    'surrogate_root_label',
    'symlink_escape_refused',
  ]);
  expectString('active persistent activation root label', report.path_boundary.activation_root_label);
  expectString('active persistent proof target label', report.path_boundary.proof_target_label);
  if (report.path_boundary.surrogate_root_label !== '<source-preflight-surrogate-root>') {
    throw new Error('active persistent surrogate root label drifted');
  }
  for (const key of [
    'activation_root_name_matches_profile_id',
    'activation_root_realpath_contained',
    'proof_target_realpath_contained',
    'symlink_escape_refused',
    'hardlink_escape_refused_where_practical',
    'alias_risk_documented',
    'real_activation_root_lexical_refusal',
  ]) {
    expectBool(`active persistent path boundary ${key}`, report.path_boundary[key], true);
  }
  expectBool('active persistent real activation root default used', report.path_boundary.real_activation_root_default_used, false);

  assertExactKeys('active persistent existing root policy', report.existing_root_policy, [
    'existing_active_root_refused',
    'existing_root_state',
    'explicit_closeout_or_replace_required_for_nonempty_root',
    'replace_mode_supported_by_source_preflight',
    'silent_overwrite_allowed',
  ]);
  expectBool('active persistent silent overwrite allowed', report.existing_root_policy.silent_overwrite_allowed, false);
  expectBool('active persistent explicit closeout required', report.existing_root_policy.explicit_closeout_or_replace_required_for_nonempty_root, true);
  expectBool('active persistent source replace mode supported', report.existing_root_policy.replace_mode_supported_by_source_preflight, false);

  assertExactKeys('active persistent command contracts', report.command_contracts, [
    'closeout_command_contract',
    'command_target_labels',
    'generated_command_defaults_real_activation_root',
    'generated_command_has_postinstall_side_effects',
    'generated_command_requires_explicit_activation_root',
    'generated_command_requires_explicit_expiry',
    'generated_command_requires_explicit_proof_target',
    'generated_command_writes_hooks_or_persistence',
    'install_command_contract',
    'status_command_contract',
  ]);
  for (const key of [
    'install_command_contract',
    'status_command_contract',
    'closeout_command_contract',
  ]) {
    expectString(`active persistent ${key}`, report.command_contracts[key]);
    if (
      report.command_contracts[key].includes('--latest') ||
      report.command_contracts[key].includes('~/.zlar')
    ) {
      throw new Error('active persistent generated command contract drifted');
    }
  }
  for (const key of [
    'generated_command_requires_explicit_activation_root',
    'generated_command_requires_explicit_proof_target',
    'generated_command_requires_explicit_expiry',
  ]) {
    expectBool(`active persistent command contract ${key}`, report.command_contracts[key], true);
  }
  for (const key of [
    'generated_command_defaults_real_activation_root',
    'generated_command_has_postinstall_side_effects',
    'generated_command_writes_hooks_or_persistence',
  ]) {
    expectBool(`active persistent command contract ${key}`, report.command_contracts[key], false);
  }

  if (
    !Array.isArray(report.refusal_matrix) ||
    report.refusal_matrix.length !== REQUIRED_ACTIVE_PERSISTENT_PROFILE_REFUSAL_CASES.length
  ) {
    throw new Error('active persistent refusal matrix drifted');
  }
  for (const caseId of REQUIRED_ACTIVE_PERSISTENT_PROFILE_REFUSAL_CASES) {
    const item = report.refusal_matrix.find((candidate) => candidate.case_id === caseId);
    if (!item) {
      throw new Error(`active persistent refusal case missing: ${caseId}`);
    }
    assertExactKeys(`active persistent refusal case ${caseId}`, item, [
      'case_id',
      'refused_before_target_mutation',
      'supported_by_source_preflight_contract',
      'target_mutation_allowed',
    ]);
    expectBool(`active persistent refusal ${caseId} supported`, item.supported_by_source_preflight_contract, true);
    expectBool(`active persistent refusal ${caseId} before mutation`, item.refused_before_target_mutation, true);
    expectBool(`active persistent refusal ${caseId} target mutation`, item.target_mutation_allowed, false);
  }

  assertExactKeys('active persistent closeout contract', report.closeout_contract, [
    'closeout_manifest_type',
    'closeout_reactivation_allowed',
    'closeout_sets_active_false',
    'revoked_or_closed_profile_refused_before_target_mutation',
    'rollback_or_closeout_required',
    'rollback_without_explicit_closeout_refused',
  ]);
  if (report.closeout_contract.closeout_manifest_type !== PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_CLOSEOUT_TYPE) {
    throw new Error('active persistent closeout type drifted');
  }
  for (const key of [
    'rollback_or_closeout_required',
    'closeout_sets_active_false',
    'revoked_or_closed_profile_refused_before_target_mutation',
    'rollback_without_explicit_closeout_refused',
  ]) {
    expectBool(`active persistent closeout ${key}`, report.closeout_contract[key], true);
  }
  expectBool('active persistent closeout reactivation allowed', report.closeout_contract.closeout_reactivation_allowed, false);

  assertExactKeys('active persistent crash contract', report.crash_interruption_contract, [
    'active_manifest_found',
    'before_manifest_commit',
    'closeout_manifest_found',
    'contract_type',
    'expired_manifest_found',
    'manifest_write_model',
    'preparing_manifest_found',
    'service_crash_after_authority_grant_consumption',
    'testable_in_source_preflight',
  ]);
  if (
    report.crash_interruption_contract.contract_type !==
      'zlar-active-persistent-profile-crash-interruption-contract-v1' ||
    report.crash_interruption_contract.testable_in_source_preflight !== true
  ) {
    throw new Error('active persistent crash/interruption contract drifted');
  }

  assertExactKeys('active persistent write boundary', report.write_boundary, [
    'activation_root_write_allowed',
    'auto_activation_allowed',
    'background_persistence_allowed',
    'daemon_or_launchagent_write_allowed',
    'hook_configuration_write_allowed',
    'machine_config_write_allowed',
    'proof_target_write_allowed',
    'report_write_allowed',
    'runtime_service_start_allowed',
    'shell_config_write_allowed',
    'user_config_write_allowed',
  ]);
  expectBool('active persistent report write allowed', report.write_boundary.report_write_allowed, true);
  for (const [key, value] of Object.entries(report.write_boundary)) {
    if (key !== 'report_write_allowed') {
      expectBool(`active persistent write boundary ${key}`, value, false);
    }
  }

  assertExactKeys('active persistent privacy hygiene', report.privacy_hygiene, [
    'activation_temp_root_private_material_absent',
    'closeout_private_material_absent',
    'hmac_token_yubikey_material_absent',
    'logs_private_material_absent',
    'private_key_material_absent',
    'real_personal_files_used',
    'report_private_material_absent',
    'scratch_evidence_private_material_absent',
    'source_diff_private_material_required',
  ]);
  for (const [key, value] of Object.entries(report.privacy_hygiene)) {
    if (['real_personal_files_used', 'source_diff_private_material_required'].includes(key)) {
      expectBool(`active persistent privacy ${key}`, value, false);
    } else {
      expectBool(`active persistent privacy ${key}`, value, true);
    }
  }

  assertExactKeys('active persistent claim boundary', report.claim_boundary, [
    'absolute_human_intention',
    'active_persistent_runtime_profile_installation',
    'browser_computer_use_mcp_shell_network_or_all_surface_governance',
    'consequence_lifecycle_closed',
    'current_machine_governance_general',
    'enterprise_readiness',
    'fixture_rightful_issuance_path_evidenced',
    'live_authority_proven',
    'portable_rightful_issuance_proven',
    'production_authority',
    'production_downstream_recognition',
    'production_rightful_issuance_proven',
    'public_external_attestation',
    'raw_codex_or_developer_tool_governance',
    'real_personal_records_protection',
    'side_door_closure',
    'sovereign_recognition',
    'rightful_issuance_proven',
  ]);
  for (const [key, value] of Object.entries(report.claim_boundary)) {
    expectBool(`active persistent forbidden claim ${key}`, value, false);
  }

  assertExactArray(
    'active persistent known open boundaries',
    report.known_open_boundaries,
    ACTIVE_PERSISTENT_PROFILE_SOURCE_OPEN_BOUNDARIES
  );
  assertExactArray(
    'active persistent forbidden claims',
    report.forbidden_claims,
    ACTIVE_PERSISTENT_PROFILE_FORBIDDEN_CLAIMS
  );
  assertExactArray(
    'active persistent non-claims',
    report.non_claims,
    ACTIVE_PERSISTENT_PROFILE_SOURCE_NON_CLAIMS
  );
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return true;
}

export function formatActivePersistentProfileSourcePreflight(report) {
  assertActivePersistentProfileSourcePreflight(report);
  const lines = [
    'ZLAR Active Persistent Profile Source Preflight v1',
    `claim=${report.claim}`,
    `evidence_model=${report.evidence_model}; source_only=${report.source_only}; live_probing=${report.live_probing}`,
    `deployment_profile_id=${report.profile_binding.deployment_profile_id}`,
    `action_class=${report.profile_binding.action_class}`,
    `runtime_profile_id=${report.profile_binding.runtime_profile_id}`,
    `runtime_profile_sha256=${report.profile_binding.runtime_profile_sha256}`,
    `canonical_runtime_profile_source=${report.profile_binding.canonical_runtime_profile_source}`,
    `selected_by_id_and_sha=${report.profile_binding.selected_by_explicit_id_and_sha}; selects_latest=${report.profile_binding.selects_latest_profile}; moving_selector_accepted=${report.profile_binding.moving_selector_accepted}`,
    `runtime_contract: mutation_route=${report.runtime_profile_contract.mutation_authoritative_route}; consumed_authority_grant_store=${report.runtime_profile_contract.consumed_authority_grant_store}; consumption_identity=${report.runtime_profile_contract.consumption_identity}; signed_payload_replay_identity=${report.runtime_profile_contract.signed_payload_replay_identity}; witness=${report.runtime_profile_contract.consumed_store_witness}`,
    `grant_requirements: contract=${report.runtime_profile_contract.authority_grant_contract_required_from_launcher}; appointment=${report.runtime_profile_contract.authority_grant_appointment_required_from_launcher}; issuance_decision=${report.runtime_profile_contract.authority_grant_issuance_decision_required_from_launcher}; authorized_record_update=${report.runtime_profile_contract.authorized_record_update_required_from_launcher}; request_stream_authority_material_accepted=${report.runtime_profile_contract.request_stream_authority_material_accepted}`,
    `replay_and_storage_boundaries: same_process_signed_payload_case=${report.runtime_profile_contract.same_process_signed_payload_replay_case_required}; restart_consumed_grant_case=${report.runtime_profile_contract.restart_consumed_authority_grant_refusal_case_required}; atomic_store_anchor_witness_commit=${report.runtime_profile_contract.atomic_store_anchor_witness_commit}; burn_window_named=${report.runtime_profile_contract.partial_grant_commit_burn_window_named}; witness_ahead_refusal=${report.runtime_profile_contract.store_and_anchor_joint_rollback_refused_while_witness_ahead}; joint_rollback_detection=${report.runtime_profile_contract.store_anchor_and_witness_joint_rollback_detection}; host_path_toctou_closed=${report.runtime_profile_contract.host_filesystem_path_toctou_closed}`,
    `rightful_issuance_boundary: fixture_path_evidenced=${report.claim_boundary.fixture_rightful_issuance_path_evidenced}; rightful_issuance_proven=${report.claim_boundary.rightful_issuance_proven}; live_authority_proven=${report.claim_boundary.live_authority_proven}; consequence_lifecycle_closed=${report.claim_boundary.consequence_lifecycle_closed}`,
    `expires_at=${report.expiry.expires_at}; expired_profile_refused=${report.expiry.expired_profile_refused}`,
    `activation_root=${report.path_boundary.activation_root_label}; proof_target=${report.path_boundary.proof_target_label}`,
    `containment: activation_root=${report.path_boundary.activation_root_realpath_contained}; proof_target=${report.path_boundary.proof_target_realpath_contained}; symlink_escape_refused=${report.path_boundary.symlink_escape_refused}; hardlink_refused_where_practical=${report.path_boundary.hardlink_escape_refused_where_practical}`,
    `existing_root_policy: state=${report.existing_root_policy.existing_root_state}; silent_overwrite_allowed=${report.existing_root_policy.silent_overwrite_allowed}; replace_mode_supported=${report.existing_root_policy.replace_mode_supported_by_source_preflight}`,
    `refusal_matrix_count=${report.refusal_matrix.length}`,
    `closeout: required=${report.closeout_contract.rollback_or_closeout_required}; sets_active_false=${report.closeout_contract.closeout_sets_active_false}; reactivation_allowed=${report.closeout_contract.closeout_reactivation_allowed}`,
    `write_boundary: activation_root_write_allowed=${report.write_boundary.activation_root_write_allowed}; proof_target_write_allowed=${report.write_boundary.proof_target_write_allowed}; hooks_written=${report.write_boundary.hook_configuration_write_allowed}; runtime_service_started=${report.write_boundary.runtime_service_start_allowed}; auto_activation=${report.write_boundary.auto_activation_allowed}`,
    `privacy: private_key_material_absent=${report.privacy_hygiene.private_key_material_absent}; hmac_token_yubikey_material_absent=${report.privacy_hygiene.hmac_token_yubikey_material_absent}; real_personal_files_used=${report.privacy_hygiene.real_personal_files_used}`,
    'Forbidden claims:',
  ];
  for (const claim of report.forbidden_claims) {
    lines.push(`- ${claim}`);
  }
  const output = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  return output;
}

export function formatActivePersistentProfileSourceStatus(status) {
  assertActivePersistentProfileSourceStatus(status);
  const output = [
    'ZLAR Active Persistent Profile Source Status v1',
    `evidence_model=${status.evidence_model}; read_only=${status.read_only}; live_probing=${status.live_probing}`,
    `activation_root=${status.activation_root_label}`,
    `state=${status.activation_root_state}; safe_for_source_preflight=${status.safe_for_source_preflight}; existing_active_root_refused=${status.existing_active_root_refused}; manifest_status=${status.manifest_status}`,
    `real_activation_root_touched=${status.real_activation_root_touched}; explicit_replace_required=${status.explicit_replace_required}`,
  ].join('\n') + '\n';
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  return output;
}

export function formatActivePersistentProfileCloseout(closeout) {
  assertActivePersistentProfileCloseout(closeout);
  const output = [
    'ZLAR Active Persistent Profile Closeout v1',
    `deployment_profile_id=${closeout.deployment_profile_id}`,
    `runtime_profile_id=${closeout.runtime_profile_id}`,
    `runtime_profile_sha256=${closeout.runtime_profile_sha256}`,
    `previous_status=${closeout.previous_status}; status=${closeout.status}; active=${closeout.active}; activation_allowed=${closeout.activation_allowed}`,
    `closed_at=${closeout.closed_at}; reason=${closeout.closeout_reason}`,
    `rollback_or_closeout_tested=${closeout.rollback_or_closeout_tested}; closeout_reactivation_allowed=${closeout.closeout_reactivation_allowed}`,
  ].join('\n') + '\n';
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  return output;
}

export function writeActivePersistentProfileSourcePreflightReport(report, outputPath) {
  assertActivePersistentProfileSourcePreflight(report);
  if (!outputPath || outputPath === '-') {
    throw new Error('active persistent profile source preflight report output path is required');
  }
  assertSourcePreflightIoPathNotRealActivationRoot(
    outputPath,
    'active persistent profile source preflight report output path'
  );
  const output = `${JSON.stringify(report, null, 2)}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, output, { mode: 0o600 });
  return sha256hex(output);
}

export function writeActivePersistentProfileCloseout(closeout, outputPath) {
  assertActivePersistentProfileCloseout(closeout);
  if (!outputPath || outputPath === '-') {
    throw new Error('active persistent profile closeout output path is required');
  }
  assertSourcePreflightIoPathNotRealActivationRoot(
    outputPath,
    'active persistent profile closeout output path'
  );
  const output = `${JSON.stringify(closeout, null, 2)}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, output, { mode: 0o600 });
  return sha256hex(output);
}
