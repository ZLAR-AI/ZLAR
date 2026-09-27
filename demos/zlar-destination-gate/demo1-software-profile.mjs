// Disposable software-key profile for protocol and transaction testing only.
// It cannot establish YubiKey custody, a fresh human act, OS separation, or
// Demo 1 PASS and is never eligible as a fallback in the C-backed profile.

import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  STAGED_OBJECT_ID,
  bodyId,
  canonicalBytes,
  keyId,
  makeRecognitionPolicy,
  publicKeyPem,
  randomNonce,
  signRecord,
} from '../../cyan/demo1-protocol.mjs';
import {
  Demo1Destination,
  buildCandidateGrantBody,
} from '../../cyan/demo1-destination.mjs';

export const SOFTWARE_PROFILE_ID = 'zlar.demo1.software-test.v1';
export const SOFTWARE_PRINCIPAL_ID = 'software-test:acting-client';
export const SOFTWARE_CLAIM_CEILING = 'software_key_protocol_and_transaction_only';

function keyPair() {
  const pair = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

export class Demo1SoftwareProfile {
  constructor({ rootDirectory, clock = () => Math.floor(Date.now() / 1000), keys = null }) {
    this.rootDirectory = rootDirectory;
    this.stagingRoot = join(rootDirectory, 'agent-staging');
    this.databasePath = join(rootDirectory, 'destination.sqlite');
    mkdirSync(this.stagingRoot, { recursive: true, mode: 0o700 });
    this.keys = keys ?? {
      root: keyPair(),
      issuer: keyPair(),
      destination: keyPair(),
    };
    this.policy = makeRecognitionPolicy({
      profileId: SOFTWARE_PROFILE_ID,
      roots: [{ publicKeyPem: this.keys.root.publicKeyPem }],
      issuers: [{ publicKeyPem: this.keys.issuer.publicKeyPem }],
      destination: { publicKeyPem: this.keys.destination.publicKeyPem },
    });
    this.clock = clock;
    this.destination = null;
    this.open();
  }

  open() {
    if (this.destination !== null) return;
    this.destination = new Demo1Destination({
      databasePath: this.databasePath,
      stagingRoot: this.stagingRoot,
      recognitionPolicy: this.policy,
      destinationPrivateKeyPem: this.keys.destination.privateKeyPem,
      issuerPrivateKeyPem: this.keys.issuer.privateKeyPem,
      clock: this.clock,
    });
  }

  close() {
    this.destination?.close();
    this.destination = null;
  }

  restart() {
    this.close();
    this.open();
  }

  stage(bytes) {
    writeFileSync(join(this.stagingRoot, STAGED_OBJECT_ID), bytes, { mode: 0o600 });
  }

  challenge() {
    return this.destination.issueChallenge({ observedPrincipalId: SOFTWARE_PRINCIPAL_ID });
  }

  signedGrant(challengeRecord, { now = this.clock(), expiresAt = challengeRecord.body.expires_at } = {}) {
    const body = buildCandidateGrantBody({
      challengeRecord,
      authorityRootKeyId: keyId(this.keys.root.publicKeyPem),
      authorizedIssuerKeyId: keyId(this.keys.issuer.publicKeyPem),
      grantNonce: randomNonce(randomBytes),
      issuedAt: now,
      notBefore: now,
      expiresAt,
    });
    return signRecord('grant', body, this.keys.root.privateKeyPem);
  }

  credential(grantRecord) {
    return this.destination.issueCredential({
      grantRecord,
      observedPrincipalId: SOFTWARE_PRINCIPAL_ID,
    });
  }

  requestId() {
    return `req-${randomBytes(18).toString('base64url')}`;
  }

  promotionRequest({ challengeRecord, grantRecord = null, credentialRecord = null, requestId = this.requestId() }) {
    const challengeId = bodyId('challenge', challengeRecord.body);
    return { challengeId, requestId, bytes: canonicalBytes({
      request_id: requestId,
      challenge_id: challengeId,
      grant: grantRecord,
      credential: credentialRecord,
    }) };
  }
}

// Kept as a function so the test runner can create a complete private fixture
// without exporting any key bytes into a committed artifact.
export function softwareProfilePublicSummary(profile) {
  return {
    v: 1,
    profile_id: SOFTWARE_PROFILE_ID,
    claim_ceiling: SOFTWARE_CLAIM_CEILING,
    root_key_id: keyId(profile.keys.root.publicKeyPem),
    issuer_key_id: keyId(profile.keys.issuer.publicKeyPem),
    destination_key_id: keyId(profile.keys.destination.publicKeyPem),
    destination_public_key_pem: publicKeyPem(profile.keys.destination.publicKeyPem),
  };
}
