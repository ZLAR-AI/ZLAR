#!/usr/bin/env node

import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  ProtocolError,
  bodyId,
  canonicalBytes,
} from '../../cyan/demo1-protocol.mjs';
import { Demo1Destination } from '../../cyan/demo1-destination.mjs';
import { handleInstalledRequest } from './demo1-installed-handler.mjs';
import {
  AUTHORITY_TRANSFER_GID,
  AUTHORITY_TRANSFER_MODE,
  AUTHORITY_TRANSFER_UID,
  CLIENT_PRINCIPAL_ID,
  CLIENT_UID,
  C_ROOT_KEY_ID,
  INSTALLED_CLAIM_CEILING,
  INSTALLED_PROFILE_ID,
  SERVICE_UID,
  SOCKET_GROUP_GID,
} from './demo1-installed-profile.mjs';
import {
  Demo1SoftwareProfile,
  SOFTWARE_PRINCIPAL_ID,
} from './demo1-software-profile.mjs';

const directory = mkdtempSync(join(tmpdir(), 'zlar-demo1-installed-handler-'));
const profile = new Demo1SoftwareProfile({ rootDirectory: directory, clock: () => 1000 });
try {
  profile.stage(Buffer.from('{"release":"demo-1-b","effect":"harmless-local"}\n'));
  assert.equal(CLIENT_UID, 501);
  assert.equal(CLIENT_PRINCIPAL_ID, 'macos-euid:501');
  assert.equal(SERVICE_UID, 450);
  assert.equal(AUTHORITY_TRANSFER_UID, 501);
  assert.equal(AUTHORITY_TRANSFER_GID, 20);
  assert.equal(AUTHORITY_TRANSFER_MODE, 0o700);
  assert.equal(SOCKET_GROUP_GID, 80);
  assert.equal(INSTALLED_PROFILE_ID, 'zlar.demo1.c-backed.v1');
  assert.equal(INSTALLED_CLAIM_CEILING, 'installed_c_backed_candidate_evidence_only');
  assert.equal(C_ROOT_KEY_ID, 'spki-sha256:eb746072b61c1f21225e6504accf55ec99d5ba73f3117c80e0d092c1436ab07c');

  assert.throws(
    () => handleInstalledRequest(canonicalBytes({ operation: 'health' }), {
      destination: profile.destination,
      peerUid: 502,
    }),
    (error) => error instanceof ProtocolError && error.code === 'peer_uid_refused',
  );
  assert.throws(
    () => handleInstalledRequest(canonicalBytes({
      operation: 'health',
      principal_id: CLIENT_PRINCIPAL_ID,
    }), {
      destination: profile.destination,
      peerUid: CLIENT_UID,
    }),
    (error) => error instanceof ProtocolError && error.code === 'ipc_request_unknown_or_missing_field',
  );

  const health = handleInstalledRequest(canonicalBytes({ operation: 'health' }), {
    destination: profile.destination,
    peerUid: CLIENT_UID,
  });
  assert.equal(health.status, 'DESTINATION_REACHED');
  assert.equal(health.observed_principal_id, CLIENT_PRINCIPAL_ID);

  // Use the generic software profile only to exercise transport plumbing. The
  // installed handler itself supplies the kernel-derived installed principal,
  // so create a separate destination with a matching test challenge identity.
  profile.destination.close();
  profile.destination = new Demo1Destination({
    databasePath: profile.databasePath,
    stagingRoot: profile.stagingRoot,
    recognitionPolicy: profile.policy,
    destinationPrivateKeyPem: profile.keys.destination.privateKeyPem,
    issuerPrivateKeyPem: profile.keys.issuer.privateKeyPem,
    clock: profile.clock,
    openingMode: 'open_existing',
  });
  const challengeResponse = handleInstalledRequest(canonicalBytes({ operation: 'challenge' }), {
    destination: profile.destination,
    peerUid: CLIENT_UID,
  });
  assert.equal(challengeResponse.status, 'CHALLENGE_ISSUED');
  assert.equal(challengeResponse.challenge.body.principal_id, CLIENT_PRINCIPAL_ID);
  const grant = profile.signedGrant(challengeResponse.challenge);
  // softwareProfile.signedGrant binds the challenge body and is authority-effect-none.
  const credentialResponse = handleInstalledRequest(canonicalBytes({ operation: 'credential', grant }), {
    destination: profile.destination,
    peerUid: CLIENT_UID,
  });
  assert.equal(credentialResponse.status, 'CREDENTIAL_DERIVED');
  const request = {
    request_id: 'req-ABCDEFGHIJKLMNOP',
    challenge_id: bodyId('challenge', challengeResponse.challenge.body),
    grant,
    credential: credentialResponse.credential,
  };
  const effect = handleInstalledRequest(canonicalBytes({ operation: 'promote', request }), {
    destination: profile.destination,
    peerUid: CLIENT_UID,
  });
  assert.equal(effect.status, 'EFFECT_EXECUTED');
  assert.equal(effect.receipt.body.principal_id, CLIENT_PRINCIPAL_ID);
  const replay = handleInstalledRequest(canonicalBytes({
    operation: 'promote',
    request: { ...request, request_id: 'req-QRSTUVWXYZabcdef' },
  }), {
    destination: profile.destination,
    peerUid: CLIENT_UID,
  });
  assert.equal(replay.status, 'EFFECT_REFUSED');
  assert.equal(profile.destination.activeRelease().generation, 1);
  const evidence = handleInstalledRequest(canonicalBytes({ operation: 'evidence' }), {
    destination: profile.destination,
    peerUid: CLIENT_UID,
  });
  assert.equal(evidence.v, 2);
  assert.equal(evidence.challenges.length, 1);
  assert.equal(evidence.grants.length, 1);
  assert.equal(evidence.credentials.length, 1);
  assert.equal(evidence.grants[0].spent_allocation, 1);
  assert.equal(evidence.credentials[0].used, true);

  profile.close();
  const corrupted = new DatabaseSync(profile.databasePath);
  corrupted.exec('DELETE FROM active_release');
  corrupted.close();
  assert.throws(
    () => new Demo1Destination({
      databasePath: profile.databasePath,
      stagingRoot: profile.stagingRoot,
      recognitionPolicy: profile.policy,
      destinationPrivateKeyPem: profile.keys.destination.privateKeyPem,
      issuerPrivateKeyPem: profile.keys.issuer.privateKeyPem,
      openingMode: 'open_existing',
    }),
    (error) => error.code === 'active_release_missing',
  );
  assert.throws(
    () => new Demo1Destination({
      databasePath: join(directory, 'missing.sqlite'),
      stagingRoot: profile.stagingRoot,
      recognitionPolicy: profile.policy,
      destinationPrivateKeyPem: profile.keys.destination.privateKeyPem,
      issuerPrivateKeyPem: profile.keys.issuer.privateKeyPem,
      openingMode: 'open_existing',
    }),
    (error) => error.code === 'database_missing',
  );

  const clientSource = readFileSync(join(import.meta.dirname, 'demo1.mjs'), 'utf8');
  for (const forbidden of ['demo1-software-profile', 'Demo1Destination', 'demo1-destination-key.pem', 'state.sqlite']) {
    assert.ok(!clientSource.includes(forbidden), forbidden);
  }
  const serviceSource = readFileSync(join(import.meta.dirname, 'demo1-installed-service.mjs'), 'utf8');
  assert.ok(!serviceSource.includes('demo1-software-profile'));
  assert.ok(!serviceSource.includes(SOFTWARE_PRINCIPAL_ID));
} finally {
  profile.close();
  rmSync(directory, { recursive: true, force: true });
}

process.stdout.write('PASS demo1 installed source: fixed peer identity, no caller identity, exact N/G/A evidence, fail-closed restart\n');
