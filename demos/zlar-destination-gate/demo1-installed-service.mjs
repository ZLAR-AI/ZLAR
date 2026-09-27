#!/usr/local/libexec/zlar-demo1/node
// Protected one-request destination child. It is not a socket server and has no
// caller-selectable path, identity, key, clock, policy, or software fallback.

import { createHash } from 'node:crypto';
import {
  lstatSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  canonicalBytes,
  keyId,
  parseCanonical,
  policyDigest,
  validatePolicy,
} from '../../cyan/demo1-protocol.mjs';
import { Demo1Destination } from '../../cyan/demo1-destination.mjs';
import { handleInstalledRequest } from './demo1-installed-handler.mjs';
import {
  AUTHORITY_TRANSFER_GID,
  AUTHORITY_TRANSFER_MODE,
  AUTHORITY_TRANSFER_UID,
  CLIENT_UID,
  C_ROOT_KEY_ID,
  C_ROOT_PUBLIC_PEM_SHA256,
  EXPECTED_BROKER_SHA256,
  EXPECTED_CLANG_SHA256,
  EXPECTED_NODE_SHA256,
  INSTALLED_CLAIM_CEILING,
  INSTALLED_PATHS,
  INSTALLED_PROFILE_ID,
  IPC_MAX_BYTES,
  SERVICE_GID,
  SERVICE_UID,
  SOCKET_GROUP_GID,
} from './demo1-installed-profile.mjs';

class InstalledRefusal extends Error {
  constructor(code) {
    super(code);
    this.name = 'InstalledRefusal';
    this.code = code;
  }
}

function refuse(condition, code) {
  if (!condition) throw new InstalledRefusal(code);
}

function mode(path) {
  return lstatSync(path).mode & 0o7777;
}

function assertFile(path, { uid, gid, fileMode }) {
  const node = lstatSync(path);
  refuse(node.isFile() && !node.isSymbolicLink() && node.nlink === 1, `installed_file_identity:${path}`);
  refuse(node.uid === uid && node.gid === gid && mode(path) === fileMode, `installed_file_permissions:${path}`);
  refuse(realpathSync(path) === join(realpathSync(dirname(path)), basename(path)), `installed_file_realpath:${path}`);
}

function assertDirectory(path, { uid, gid, directoryMode }) {
  const node = lstatSync(path);
  refuse(node.isDirectory() && !node.isSymbolicLink(), `installed_directory_identity:${path}`);
  refuse(node.uid === uid && node.gid === gid && mode(path) === directoryMode, `installed_directory_permissions:${path}`);
  refuse(realpathSync(path) === join(realpathSync(dirname(path)), basename(path)), `installed_directory_realpath:${path}`);
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function loadManifest() {
  assertFile(INSTALLED_PATHS.installationManifest, { uid: 0, gid: 0, fileMode: 0o444 });
  const manifest = parseCanonical(readFileSync(INSTALLED_PATHS.installationManifest));
  const expectedKeys = [
    'authority_transfer_gid', 'authority_transfer_mode', 'authority_transfer_uid', 'broker_sha256', 'ceremony_tool_sha256',
    'clang_sha256',
    'client_uid', 'installed_file_sha256', 'node_sha256', 'profile_id',
    'recognition_policy_sha256', 'service_gid', 'service_uid',
    'socket_group_gid', 'source_commit', 'source_manifest_sha256', 'type', 'v',
  ].sort();
  const actualKeys = Object.keys(manifest).sort();
  refuse(actualKeys.length === expectedKeys.length && actualKeys.every((key, index) => key === expectedKeys[index]), 'installation_manifest_shape');
  refuse(manifest.v === 1 && manifest.type === 'zlar.demo1.installation_manifest', 'installation_manifest_schema');
  refuse(manifest.profile_id === INSTALLED_PROFILE_ID, 'installation_manifest_profile');
  refuse(manifest.client_uid === CLIENT_UID, 'installation_manifest_client_uid');
  refuse(manifest.socket_group_gid === SOCKET_GROUP_GID, 'installation_manifest_socket_group_gid');
  refuse(
    manifest.authority_transfer_uid === AUTHORITY_TRANSFER_UID
      && manifest.authority_transfer_gid === AUTHORITY_TRANSFER_GID
      && manifest.authority_transfer_mode === AUTHORITY_TRANSFER_MODE,
    'installation_manifest_authority_transfer',
  );
  refuse(manifest.service_uid === SERVICE_UID && manifest.service_gid === SERVICE_GID, 'installation_manifest_service_identity');
  refuse(typeof manifest.ceremony_tool_sha256 === 'string' && /^[0-9a-f]{64}$/.test(manifest.ceremony_tool_sha256), 'installation_manifest_ceremony_digest');
  refuse(
    manifest.broker_sha256 === EXPECTED_BROKER_SHA256
      && manifest.broker_sha256 === manifest.installed_file_sha256[INSTALLED_PATHS.broker],
    'installation_manifest_broker_digest',
  );
  refuse(manifest.clang_sha256 === EXPECTED_CLANG_SHA256, 'installation_manifest_compiler_digest');
  refuse(manifest.node_sha256 === EXPECTED_NODE_SHA256, 'installation_manifest_node_digest');
  return manifest;
}

function verifyInstalledBoundary({ initialization }) {
  refuse(process.geteuid?.() === SERVICE_UID && process.getegid?.() === SERVICE_GID, 'service_process_identity');
  refuse(process.execPath === INSTALLED_PATHS.node && realpathSync(process.execPath) === INSTALLED_PATHS.node, 'runtime_path');
  for (const name of Object.keys(process.env)) {
    refuse(name !== 'NODE_OPTIONS' && name !== 'NODE_PATH' && !name.startsWith('DYLD_'), `dangerous_environment:${name}`);
  }
  assertDirectory(INSTALLED_PATHS.runtimeRoot, { uid: 0, gid: 0, directoryMode: 0o755 });
  assertFile(INSTALLED_PATHS.node, { uid: 0, gid: 0, fileMode: 0o555 });
  for (const path of [
    INSTALLED_PATHS.protocol,
    INSTALLED_PATHS.store,
    INSTALLED_PATHS.destination,
    INSTALLED_PATHS.handler,
    INSTALLED_PATHS.profile,
    INSTALLED_PATHS.service,
  ]) assertFile(path, { uid: 0, gid: 0, fileMode: 0o444 });
  assertFile(INSTALLED_PATHS.broker, { uid: 0, gid: 0, fileMode: 0o555 });
  assertFile(INSTALLED_PATHS.policy, { uid: 0, gid: 0, fileMode: 0o444 });
  assertFile(INSTALLED_PATHS.cRootPublicKey, { uid: 0, gid: 0, fileMode: 0o444 });
  assertFile(INSTALLED_PATHS.issuerPrivateKey, { uid: 0, gid: SERVICE_GID, fileMode: 0o440 });
  assertFile(INSTALLED_PATHS.destinationPrivateKey, { uid: 0, gid: SERVICE_GID, fileMode: 0o440 });
  assertFile(INSTALLED_PATHS.issuerPublicKey, { uid: 0, gid: 0, fileMode: 0o444 });
  assertFile(INSTALLED_PATHS.destinationPublicKey, { uid: 0, gid: 0, fileMode: 0o444 });
  assertDirectory(INSTALLED_PATHS.stateRoot, { uid: SERVICE_UID, gid: SERVICE_GID, directoryMode: 0o700 });
  assertDirectory(INSTALLED_PATHS.stagingRoot, { uid: CLIENT_UID, gid: SERVICE_GID, directoryMode: 0o2750 });
  assertDirectory(INSTALLED_PATHS.authorityTransferRoot, {
    uid: AUTHORITY_TRANSFER_UID,
    gid: AUTHORITY_TRANSFER_GID,
    directoryMode: AUTHORITY_TRANSFER_MODE,
  });
  assertFile(INSTALLED_PATHS.launchdPlist, { uid: 0, gid: 0, fileMode: 0o644 });
  if (!initialization) assertFile(INSTALLED_PATHS.database, { uid: SERVICE_UID, gid: SERVICE_GID, fileMode: 0o600 });

  const manifest = loadManifest();
  refuse(sha256(INSTALLED_PATHS.node) === manifest.node_sha256, 'runtime_digest');
  for (const [path, digest] of Object.entries(manifest.installed_file_sha256)) {
    refuse(typeof digest === 'string' && sha256(path) === digest, `installed_file_digest:${path}`);
  }
  const policy = parseCanonical(readFileSync(INSTALLED_PATHS.policy));
  validatePolicy(policy);
  refuse(policy.profile_id === INSTALLED_PROFILE_ID, 'installed_policy_profile');
  refuse(policy.roots.length === 1 && policy.roots[0].status === 'active', 'installed_policy_root_count');
  refuse(policy.roots[0].key_id === C_ROOT_KEY_ID, 'installed_policy_wrong_root');
  refuse(policy.issuers.length === 1 && policy.issuers[0].status === 'active', 'installed_policy_issuer_count');
  refuse(policy.destination.status === 'active', 'installed_policy_destination');
  refuse(policyDigest(policy) === manifest.recognition_policy_sha256, 'installed_policy_digest');
  refuse(sha256(INSTALLED_PATHS.cRootPublicKey) === C_ROOT_PUBLIC_PEM_SHA256, 'installed_c_root_public_key_digest');
  refuse(keyId(readFileSync(INSTALLED_PATHS.cRootPublicKey, 'utf8')) === C_ROOT_KEY_ID, 'installed_c_root_key_id');
  const issuerPrivateKeyPem = readFileSync(INSTALLED_PATHS.issuerPrivateKey, 'utf8');
  const destinationPrivateKeyPem = readFileSync(INSTALLED_PATHS.destinationPrivateKey, 'utf8');
  refuse(keyId(issuerPrivateKeyPem) === policy.issuers[0].key_id, 'installed_issuer_key_mismatch');
  refuse(keyId(destinationPrivateKeyPem) === policy.destination.key_id, 'installed_destination_key_mismatch');
  return { manifest, policy, issuerPrivateKeyPem, destinationPrivateKeyPem };
}

function openDestination({ initialization }) {
  const trusted = verifyInstalledBoundary({ initialization });
  return new Demo1Destination({
    databasePath: INSTALLED_PATHS.database,
    stagingRoot: INSTALLED_PATHS.stagingRoot,
    recognitionPolicy: trusted.policy,
    destinationPrivateKeyPem: trusted.destinationPrivateKeyPem,
    issuerPrivateKeyPem: trusted.issuerPrivateKeyPem,
    openingMode: initialization ? 'initialize_new' : 'open_existing',
    evidenceClaimCeiling: INSTALLED_CLAIM_CEILING,
  });
}

async function readStandardInput() {
  const chunks = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length;
    refuse(length <= IPC_MAX_BYTES, 'request_too_large');
    chunks.push(chunk);
  }
  refuse(length > 0, 'request_missing');
  return Buffer.concat(chunks);
}

export async function installedMain(argv) {
  let destination = null;
  try {
    if (argv.length === 1 && argv[0] === '--initialize') {
      destination = openDestination({ initialization: true });
      const active = destination.activeRelease();
      process.stdout.write(canonicalBytes({
        v: 1,
        status: 'INITIALIZED',
        profile_id: INSTALLED_PROFILE_ID,
        active_generation: active.generation,
        recognition_policy_sha256: destination.policyDigest,
      }));
      return 0;
    }
    refuse(argv.length === 2 && argv[0] === '--peer-uid' && argv[1] === String(CLIENT_UID), 'service_usage');
    destination = openDestination({ initialization: false });
    const response = handleInstalledRequest(await readStandardInput(), {
      destination,
      peerUid: CLIENT_UID,
    });
    process.stdout.write(canonicalBytes(response));
    return 0;
  } catch (error) {
    process.stdout.write(canonicalBytes({
      v: 1,
      status: 'REFUSED',
      reason: error?.code ?? error?.message ?? 'installed_destination_failure',
    }));
    return 42;
  } finally {
    destination?.close();
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  process.exitCode = await installedMain(process.argv.slice(2));
}
