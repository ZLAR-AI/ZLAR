#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import {
  existsSync,
  lstatSync,
  realpathSync,
  writeFileSync
} from 'node:fs';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from './canonicalize.mjs';
import { sha256hex } from './receipt.mjs';

export const SOURCE_TRANSPORT_PREFLIGHT_TYPE = 'zlar-source-transport-preflight-v1';
export const SOURCE_TRANSPORT_AUTHORITY_PACKET_TYPE =
  'zlar-source-transport-authority-packet-v1';
export const SOURCE_TRANSPORT_SAFE_CLAIM =
  'ZLAR can locally validate source-movement authority packet shape and local repo facts before any future GitHub App installation-token source movement; this preflight cannot move source or handle credentials.';

export const REQUIRED_FORBIDDEN_SIDE_EFFECTS = Object.freeze([
  'force_push',
  'workflow_files',
  'tags',
  'releases',
  'pull_requests',
  'website_publication',
  'actions',
  'github_settings',
  'hooks_config_install_paths',
  'manifests',
  'production_issuer_authority',
  'secret_material',
]);

export const FORBIDDEN_CLAIMS = Object.freeze([
  'GitHub App transport exists',
  'GitHub App transport is proven',
  'durable source transport is solved',
  'app private-key custody is solved',
  'token custody is solved',
  'source movement occurred',
  'production issuer authority',
  'production trust',
  'website/public alignment',
  'all-surface governance',
  'side-door closure',
  'absolute human intention',
]);

export const RUNTIME_LOCAL_COMMANDS = Object.freeze([
  'git rev-parse',
  'git status',
  'git show-ref',
]);

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(MODULE_DIR, '..');
const DEFAULT_BUILD_ROOT = process.env.ZLAR_BUILD_ROOT || resolve(PROJECT_ROOT, '..', 'ZLAR-Draft', 'build');
const DEFAULT_GRANT_MAX_AGE_SECONDS = 24 * 60 * 60;
const DEFAULT_FUTURE_SKEW_SECONDS = 5 * 60;

const SECRET_PATTERNS = Object.freeze([
  { code: 'private_key_material', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/i },
  { code: 'ssh_private_key_material', pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/i },
  { code: 'authorization_header', pattern: /\bauthorization\s*[:=]\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/i },
  { code: 'github_pat', pattern: /\bgithub_pat_[A-Za-z0-9_]{12,}\b/i },
  { code: 'github_classic_pat', pattern: /\bghp_[A-Za-z0-9_]{12,}\b/i },
  { code: 'github_app_installation_token', pattern: /\bghs_[A-Za-z0-9_]{12,}\b/i },
  { code: 'github_oauth_token', pattern: /\bgho_[A-Za-z0-9_]{12,}\b/i },
  { code: 'github_user_token', pattern: /\bghu_[A-Za-z0-9_]{12,}\b/i },
  { code: 'jwt_like_token', pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { code: 'credentialed_url', pattern: /\bhttps?:\/\/[^/\s:@]+:[^@\s]+@/i },
  { code: 'generic_secret_assignment', pattern: /\b(?:token|secret|password|private[_-]?key|api[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{10,}/i },
]);

function nowIso() {
  return new Date().toISOString();
}

function git(repoPath, args) {
  return execFileSync('git', ['-C', repoPath, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

function gitOrNull(repoPath, args) {
  try {
    return git(repoPath, args);
  } catch {
    return null;
  }
}

function refusal(reasonCode, message, details = {}) {
  return { ok: false, reasonCode, message, details };
}

function ok(value = {}) {
  return { ok: true, value };
}

function requireObject(label, value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function nonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function assertGitSha(label, value) {
  if (!/^[a-f0-9]{40}$/.test(value || '')) {
    throw new Error(`${label} must be a lowercase 40-character Git SHA`);
  }
  return true;
}

function assertIsoTimestamp(label, value) {
  if (!nonEmptyString(value) || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} must be an ISO-8601 timestamp`);
  }
  return true;
}

function assertCredentialDeath(humanGrant, transport) {
  assertIsoTimestamp('transport.token_expires_at', transport.token_expires_at);
  const grantMs = Date.parse(humanGrant.grant_timestamp);
  const expiresMs = Date.parse(transport.token_expires_at);
  if (expiresMs <= grantMs) {
    throw new Error('transport.token_expires_at must be after the human grant timestamp');
  }
  if (expiresMs - grantMs > 60 * 60 * 1000) {
    throw new Error('transport.token_expires_at must be within one hour of the human grant timestamp');
  }
  if (
    transport.token_revocation_required !== true &&
    transport.credential_death_evidence_required !== true
  ) {
    throw new Error('transport must require token revocation or credential-death evidence');
  }
  return true;
}

function assertNoSecretMaterial(text) {
  const raw = String(text || '');
  for (const { code, pattern } of SECRET_PATTERNS) {
    if (pattern.test(raw)) {
      return refusal('secret_material_detected', `secret-like material detected: ${code}`);
    }
  }
  return ok();
}

export function assertNoUnsafeSourceTransportPreflightText(text) {
  const secret = assertNoSecretMaterial(text);
  if (!secret.ok) throw new Error(secret.message);
  return true;
}

function packetSha256(packet) {
  return sha256hex(canonicalize(packet));
}

function parsePacket(packetText) {
  const secret = assertNoSecretMaterial(packetText);
  if (!secret.ok) {
    return { ok: false, reasonCode: secret.reasonCode, message: secret.message };
  }
  try {
    const packet = JSON.parse(packetText);
    return { ok: true, packet };
  } catch {
    return { ok: false, reasonCode: 'packet_json_invalid', message: 'authority packet is not valid JSON' };
  }
}

function validateRequiredAuthorityShape(packet, options = {}) {
  try {
    requireObject('authority packet', packet);
    if (packet.packet_type !== SOURCE_TRANSPORT_AUTHORITY_PACKET_TYPE) {
      throw new Error('packet_type must be zlar-source-transport-authority-packet-v1');
    }

    const humanGrant = requireObject('human_grant', packet.human_grant);
    if (!nonEmptyString(humanGrant.human)) throw new Error('human_grant.human is required');
    if (!nonEmptyString(humanGrant.grant_timestamp)) {
      throw new Error('human_grant.grant_timestamp is required');
    }
    assertIsoTimestamp('human_grant.grant_timestamp', humanGrant.grant_timestamp);
    if (!nonEmptyString(humanGrant.action)) throw new Error('human_grant.action is required');

    const nowEpoch = options.nowEpoch ?? Math.floor(Date.now() / 1000);
    const grantEpoch = Math.floor(Date.parse(humanGrant.grant_timestamp) / 1000);
    const maxAge = options.grantMaxAgeSeconds ?? DEFAULT_GRANT_MAX_AGE_SECONDS;
    const futureSkew = options.futureSkewSeconds ?? DEFAULT_FUTURE_SKEW_SECONDS;
    if (grantEpoch > nowEpoch + futureSkew) throw new Error('human grant timestamp is in the future');
    if (nowEpoch - grantEpoch > maxAge) throw new Error('human grant timestamp is stale');

    const source = requireObject('source_target', packet.source_target);
    if (!nonEmptyString(source.repo)) throw new Error('source_target.repo is required');
    if (!nonEmptyString(source.branch)) throw new Error('source_target.branch is required');
    if (!nonEmptyString(source.local_path)) throw new Error('source_target.local_path is required');
    assertGitSha('source_target.expected_local_commit', source.expected_local_commit);
    assertGitSha('source_target.expected_pre_push_remote_ref', source.expected_pre_push_remote_ref);
    assertGitSha('source_target.expected_post_push_remote_ref', source.expected_post_push_remote_ref);
    if (source.remote_ref && source.remote_ref !== `refs/heads/${source.branch}`) {
      throw new Error('source_target.remote_ref must match branch');
    }

    const transport = requireObject('transport', packet.transport);
    if (transport.push_mode !== 'non-force-fast-forward-only') {
      throw new Error('transport.push_mode must be non-force-fast-forward-only');
    }
    if (transport.credential_class !== 'github-app-installation-token') {
      throw new Error('transport.credential_class must be github-app-installation-token');
    }
    assertCredentialDeath(humanGrant, transport);
    if (!Array.isArray(transport.token_repository_scope) || transport.token_repository_scope.length !== 1) {
      throw new Error('transport.token_repository_scope must name one repository');
    }
    if (transport.token_repository_scope[0] !== source.repo) {
      throw new Error('transport.token_repository_scope must match source repo');
    }
    const permissions = requireObject('transport.token_permission_scope', transport.token_permission_scope);
    const permissionKeys = Object.keys(permissions);
    const allowedPermissionKeys = new Set(['contents', 'metadata']);
    for (const key of permissionKeys) {
      if (!allowedPermissionKeys.has(key)) {
        throw new Error('transport.token_permission_scope contains an unsupported permission key');
      }
    }
    if (permissions.contents !== 'write') {
      throw new Error('transport.token_permission_scope.contents must be write');
    }
    if ('metadata' in permissions && permissions.metadata !== 'read') {
      throw new Error('transport.token_permission_scope.metadata must be read when present');
    }
    if (transport.token_seen_by_report !== false) {
      throw new Error('transport.token_seen_by_report must be false');
    }

    const forbidden = packet.forbidden_side_effects;
    if (!Array.isArray(forbidden)) throw new Error('forbidden_side_effects must be an array');
    for (const item of REQUIRED_FORBIDDEN_SIDE_EFFECTS) {
      if (!forbidden.includes(item)) throw new Error(`forbidden_side_effects missing ${item}`);
    }

    const proposed = requireObject('proposed_source_movement', packet.proposed_source_movement);
    if (proposed.force === true) throw new Error('proposed source movement permits force push');
    if (proposed.tags === true) throw new Error('proposed source movement permits tags');
    if (proposed.releases === true) throw new Error('proposed source movement permits releases');
    if (proposed.pull_requests === true) throw new Error('proposed source movement permits pull requests');
    if (proposed.website_publication === true) throw new Error('proposed source movement permits website publication');
    if (proposed.actions === true) throw new Error('proposed source movement permits Actions');
    if (proposed.github_settings === true) throw new Error('proposed source movement permits GitHub settings');
    if (proposed.hooks_config_install_paths === true) {
      throw new Error('proposed source movement permits hooks/config/install paths');
    }
    if (proposed.manifests === true) throw new Error('proposed source movement permits manifests');
    if (proposed.production_issuer_authority === true) {
      throw new Error('proposed source movement permits production issuer authority');
    }
    if (proposed.secret_material === true) {
      throw new Error('proposed source movement permits secret material');
    }
    if (Array.isArray(proposed.allowed_side_effects)) {
      for (const item of proposed.allowed_side_effects) {
        if (REQUIRED_FORBIDDEN_SIDE_EFFECTS.includes(item) || item === 'website') {
          throw new Error(`proposed source movement allows forbidden side effect ${item}`);
        }
      }
    }
    const paths = Array.isArray(proposed.paths) ? proposed.paths : [];
    for (const path of paths) {
      if (typeof path !== 'string') throw new Error('proposed source movement paths must be strings');
      if (path === '.github/workflows' || path.startsWith('.github/workflows/')) {
        throw new Error('workflow file movement is forbidden');
      }
      if (
        path.startsWith('ZLAR_Website/') ||
        path.startsWith('../ZLAR_Website/') ||
        path === 'website' ||
        path.startsWith('website/')
      ) {
        throw new Error('website/publication scope is forbidden');
      }
      if (
        path.startsWith('.github/') ||
        path.startsWith('hooks/') ||
        path.startsWith('config/') ||
        path.startsWith('install/') ||
        path === 'install.sh' ||
        path === 'etc/manifest.json' ||
        path.startsWith('etc/manifest')
      ) {
        throw new Error('forbidden source path scope requested');
      }
    }

    const website = requireObject('website', packet.website);
    if (!nonEmptyString(website.path)) throw new Error('website.path is required');
    assertGitSha('website.expected_head', website.expected_head);
    if (!Array.isArray(website.allowed_untracked) || !website.allowed_untracked.includes('var/')) {
      throw new Error('website.allowed_untracked must include var/');
    }

    return ok({
      humanGrant,
      source,
      transport,
      website,
      proposed,
      packet_sha256: packetSha256(packet),
    });
  } catch (err) {
    return refusal('authority_packet_invalid', err.message);
  }
}

function localRepoFacts(repoPath) {
  const realRepoPath = realpathSync(repoPath);
  const branch = git(realRepoPath, ['rev-parse', '--abbrev-ref', 'HEAD']);
  const head = git(realRepoPath, ['rev-parse', 'HEAD']);
  const statusPorcelain = git(realRepoPath, ['status', '--porcelain=v1', '--untracked-files=all']);
  const statusShort = git(realRepoPath, ['status', '--short', '--branch', '--untracked-files=all']);
  const upstream = gitOrNull(realRepoPath, ['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{u}']);
  const upstreamHead = upstream ? gitOrNull(realRepoPath, ['rev-parse', '@{u}']) : null;
  const remoteTrackingRef = upstream ? `refs/remotes/${upstream}` : null;
  const remoteTrackingHead = remoteTrackingRef
    ? gitOrNull(realRepoPath, ['show-ref', '--hash', remoteTrackingRef])
    : null;
  return {
    real_path: realRepoPath,
    branch,
    head,
    clean: statusPorcelain.length === 0,
    status_summary: statusShort,
    upstream,
    upstream_head: upstreamHead,
    remote_tracking_ref: remoteTrackingRef,
    remote_tracking_head: remoteTrackingHead,
  };
}

function websiteFacts(websitePath) {
  const realWebsitePath = realpathSync(websitePath);
  const head = git(realWebsitePath, ['rev-parse', 'HEAD']);
  const statusShort = git(realWebsitePath, ['status', '--short', '--branch']);
  const statusLines = statusShort.split('\n').filter(Boolean);
  const unexpected = statusLines.filter((line) => !line.startsWith('## ') && line.trim() !== '?? var/');
  return {
    real_path: realWebsitePath,
    head,
    status_summary: statusShort,
    unchanged_except_known_var: unexpected.length === 0,
    unexpected_status_lines: unexpected,
  };
}

function verifyFacts(packetShape, options = {}) {
  const source = packetShape.source;
  const website = packetShape.website;
  let repoFacts;
  let siteFacts;
  if (options.repoFactsOverride) {
    repoFacts = options.repoFactsOverride;
  } else {
    try {
      repoFacts = localRepoFacts(source.local_path);
    } catch (err) {
      return refusal('local_repo_unreadable', 'local repo facts could not be read', { message: err.message });
    }
  }
  if (options.websiteFactsOverride) {
    siteFacts = options.websiteFactsOverride;
  } else {
    try {
      siteFacts = websiteFacts(website.path);
    } catch (err) {
      return refusal('website_unreadable', 'website facts could not be read', { message: err.message });
    }
  }

  const sourceReal = options.repoFactsOverride ? source.local_path : realpathSync(source.local_path);
  if (repoFacts.real_path !== sourceReal) {
    return refusal('local_path_mismatch', 'local repo path did not resolve consistently');
  }
  if (repoFacts.branch !== source.branch) {
    return refusal('branch_mismatch', 'local branch does not match authority packet', {
      expected: source.branch,
      actual: repoFacts.branch,
    });
  }
  if (repoFacts.head !== source.expected_local_commit) {
    return refusal('expected_local_commit_mismatch', 'local HEAD does not match authority packet', {
      expected: source.expected_local_commit,
      actual: repoFacts.head,
    });
  }
  if (!repoFacts.clean) {
    return refusal('local_repo_dirty', 'local repo is not clean');
  }
  if (!repoFacts.upstream) {
    return refusal('upstream_missing', 'local branch has no upstream/tracking branch');
  }
  if (!repoFacts.remote_tracking_head) {
    return refusal('remote_tracking_ref_missing', 'local remote-tracking ref is missing');
  }
  if (repoFacts.remote_tracking_head !== source.expected_pre_push_remote_ref) {
    return refusal('pre_push_remote_ref_mismatch', 'local remote-tracking ref does not match expected pre-push ref', {
      expected: source.expected_pre_push_remote_ref,
      actual: repoFacts.remote_tracking_head,
    });
  }
  if (source.expected_post_push_remote_ref !== source.expected_local_commit) {
    return refusal('post_push_ref_not_local_commit', 'expected post-push remote ref must equal expected local commit');
  }
  if (siteFacts.head !== website.expected_head) {
    return refusal('website_head_mismatch', 'website HEAD does not match expected unchanged website state', {
      expected: website.expected_head,
      actual: siteFacts.head,
    });
  }
  if (!siteFacts.unchanged_except_known_var) {
    return refusal('website_status_mismatch', 'website status has unexpected changes');
  }
  return ok({ repoFacts, siteFacts });
}

function reportBase({ status, reasonCode = null, refusalMessage = null, packetShape = null, facts = null }) {
  const source = packetShape?.source ?? null;
  const transport = packetShape?.transport ?? null;
  return {
    report_type: SOURCE_TRANSPORT_PREFLIGHT_TYPE,
    schema_version: 1,
    created_at: nowIso(),
    preflight_status: status,
    refusal_reason_code: reasonCode,
    refusal_message: refusalMessage,
    authority_packet: packetShape ? {
      packet_sha256: packetShape.packet_sha256,
      human: packetShape.humanGrant.human,
      grant_timestamp: packetShape.humanGrant.grant_timestamp,
      repo: source.repo,
      branch: source.branch,
      expected_local_commit: source.expected_local_commit,
      expected_pre_push_remote_ref: source.expected_pre_push_remote_ref,
      expected_post_push_remote_ref: source.expected_post_push_remote_ref,
      push_mode: transport.push_mode,
      credential_class: transport.credential_class,
      token_expires_at: transport.token_expires_at,
      token_revocation_required: transport.token_revocation_required === true,
      credential_death_evidence_required: transport.credential_death_evidence_required === true,
    } : {
      packet_sha256: null,
      present: false,
    },
    token_metadata: {
      credential_class: transport?.credential_class ?? null,
      token_repository_scope: transport?.token_repository_scope ?? [],
      token_permission_scope: transport?.token_permission_scope ?? {},
      token_expires_at: transport?.token_expires_at ?? null,
      token_revocation_required: transport?.token_revocation_required === true,
      credential_death_evidence_required: transport?.credential_death_evidence_required === true,
      token_seen_by_report: false,
      fake_non_secret_metadata_only: true,
    },
    local_facts: facts?.repoFacts ? {
      branch: facts.repoFacts.branch,
      head: facts.repoFacts.head,
      clean: facts.repoFacts.clean,
      upstream: facts.repoFacts.upstream,
      upstream_head: facts.repoFacts.upstream_head,
      remote_tracking_ref: facts.repoFacts.remote_tracking_ref,
      remote_tracking_head: facts.repoFacts.remote_tracking_head,
    } : null,
    website_facts: facts?.siteFacts ? {
      head: facts.siteFacts.head,
      unchanged_except_known_var: facts.siteFacts.unchanged_except_known_var,
      status_summary: facts.siteFacts.status_summary,
    } : null,
    no_source_movement_boundary: {
      can_move_source: false,
      network_calls: false,
      github_api_used: false,
      token_minted: false,
      token_read: false,
      token_seen_by_report: false,
      git_push_available: false,
      git_remote_config_changed: false,
      credential_helper_touched: false,
      website_changed: false,
    },
    safe_claim: SOURCE_TRANSPORT_SAFE_CLAIM,
    forbidden_claims: [...FORBIDDEN_CLAIMS],
  };
}

export function runSourceTransportPreflight(input, options = {}) {
  let packet;
  let parsed = null;
  if (typeof input === 'string') {
    parsed = parsePacket(input);
    if (!parsed.ok) {
      return reportBase({
        status: 'refused',
        reasonCode: parsed.reasonCode,
        refusalMessage: parsed.message,
      });
    }
    packet = parsed.packet;
  } else if (input && typeof input === 'object') {
    const secret = assertNoSecretMaterial(JSON.stringify(input));
    if (!secret.ok) {
      return reportBase({
        status: 'refused',
        reasonCode: secret.reasonCode,
        refusalMessage: secret.message,
      });
    }
    packet = input;
  } else {
    return reportBase({
      status: 'refused',
      reasonCode: 'authority_packet_absent',
      refusalMessage: 'authority packet is required',
    });
  }

  const shape = validateRequiredAuthorityShape(packet, options);
  if (!shape.ok) {
    return reportBase({
      status: 'refused',
      reasonCode: shape.reasonCode,
      refusalMessage: shape.message,
    });
  }

  const facts = verifyFacts(shape.value, options);
  if (!facts.ok) {
    return reportBase({
      status: 'refused',
      reasonCode: facts.reasonCode,
      refusalMessage: facts.message,
      packetShape: shape.value,
      facts: facts.details?.repoFacts || facts.details?.siteFacts ? facts.details : null,
    });
  }

  const report = reportBase({
    status: 'passed',
    packetShape: shape.value,
    facts: facts.value,
  });
  assertNoUnsafeSourceTransportPreflightText(JSON.stringify(report));
  return report;
}

export function writeSourceTransportPreflightReport(report, outputPath, options = {}) {
  if (!outputPath || typeof outputPath !== 'string') {
    throw new Error('output path is required');
  }
  const buildRoot = realpathSync(options.buildRoot || DEFAULT_BUILD_ROOT);
  const resolved = resolve(outputPath);
  if (existsSync(resolved) && lstatSync(resolved).isSymbolicLink()) {
    throw new Error('report output path must not be a symlink');
  }
  const parent = realpathSync(dirname(resolved));
  if (parent !== buildRoot && !parent.startsWith(`${buildRoot}${sep}`)) {
    throw new Error('report output path must stay under the proof-owned build scratch root');
  }
  const text = `${JSON.stringify(report, null, 2)}\n`;
  assertNoUnsafeSourceTransportPreflightText(text);
  writeFileSync(resolved, text, { flag: 'wx', mode: 0o600 });
  return resolved;
}

export function formatSourceTransportPreflight(report) {
  const lines = [
    `Source transport preflight: ${report.preflight_status}`,
    `Reason: ${report.refusal_reason_code ?? 'none'}`,
    `Repo: ${report.authority_packet.repo ?? 'n/a'}`,
    `Branch: ${report.authority_packet.branch ?? 'n/a'}`,
    `Expected local commit: ${report.authority_packet.expected_local_commit ?? 'n/a'}`,
    `Credential class: ${report.authority_packet.credential_class ?? 'n/a'}`,
    `Token seen by report: ${report.token_metadata.token_seen_by_report}`,
    `Can move source: ${report.no_source_movement_boundary.can_move_source}`,
    `Network calls: ${report.no_source_movement_boundary.network_calls}`,
    `GitHub API used: ${report.no_source_movement_boundary.github_api_used}`,
    `Safe claim: ${report.safe_claim}`,
  ];
  return `${lines.join('\n')}\n`;
}
