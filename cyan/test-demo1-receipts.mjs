#!/usr/bin/env node

import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  ProtocolError,
  bodyId,
  canonical,
  signedRecordHash,
  verifyReceiptChain,
  verifyRecord,
} from './demo1-protocol.mjs';
import {
  Demo1SoftwareProfile,
  SOFTWARE_PRINCIPAL_ID,
} from '../demos/zlar-destination-gate/demo1-software-profile.mjs';

const directory = mkdtempSync(join(tmpdir(), 'zlar-demo1-receipts-'));
const profile = new Demo1SoftwareProfile({ rootDirectory: directory, clock: () => 1000 });
try {
  profile.stage(Buffer.from('{"release":"demo-1-b"}\n'));
  const challenge = profile.challenge();
  const missing = profile.promotionRequest({ challengeRecord: challenge });
  profile.destination.promote(missing.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID });
  const grant = profile.signedGrant(challenge);
  const credential = profile.credential(grant);
  const exact = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credential });
  profile.destination.promote(exact.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID });
  const replay = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credential });
  profile.destination.promote(replay.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID });

  const receipts = profile.destination.receipts();
  const commits = profile.destination.commits();
  assert.equal(receipts.length, 3);
  assert.equal(commits.length, 1);
  const evidence = profile.destination.evidenceBundle();
  assert.equal(evidence.v, 2);
  assert.equal(evidence.challenges.length, 1);
  assert.equal(evidence.challenges[0].challenge_id, bodyId('challenge', challenge.body));
  assert.equal(canonical(evidence.challenges[0].record), canonical(challenge));
  assert.equal(evidence.challenges[0].consumed, true);
  assert.equal(evidence.grants.length, 1);
  assert.equal(canonical(evidence.grants[0].record), canonical(grant));
  assert.equal(evidence.grants[0].spent_allocation, 1);
  assert.equal(evidence.credentials.length, 1);
  assert.equal(canonical(evidence.credentials[0].record), canonical(credential));
  assert.equal(evidence.credentials[0].used, true);
  const beforeVerification = canonical(profile.destination.evidenceBundle());
  const chain = verifyReceiptChain(receipts, {
    destinationPublicKeyPem: profile.destination.destinationPublicKeyPem,
    policy: profile.policy,
  });
  assert.equal(chain.count, 3);
  assert.equal(chain.head, signedRecordHash(receipts[2]));
  assert.equal(canonical(profile.destination.evidenceBundle()), beforeVerification);

  const executed = receipts.find((record) => record.body.outcome === 'executed');
  assert.ok(executed);
  assert.equal(executed.body.grant_id, bodyId('grant', grant.body));
  assert.equal(executed.body.credential_id, bodyId('credential', credential.body));
  assert.equal(executed.body.allocation_before, 1);
  assert.equal(executed.body.allocation_after, 0);
  assert.notEqual(executed.body.state_before_sha256, executed.body.state_after_sha256);
  assert.equal(executed.body.promotion_commit_id, signedRecordHash(commits[0]));
  verifyRecord('commit', commits[0], profile.destination.destinationPublicKeyPem);

  assert.throws(
    () => verifyReceiptChain([receipts[1], receipts[0], receipts[2]], {
      destinationPublicKeyPem: profile.destination.destinationPublicKeyPem,
      policy: profile.policy,
    }),
    (error) => error instanceof ProtocolError,
  );
  assert.throws(
    () => verifyReceiptChain([receipts[0], receipts[2]], {
      destinationPublicKeyPem: profile.destination.destinationPublicKeyPem,
      policy: profile.policy,
    }),
    (error) => error instanceof ProtocolError,
  );

  const mutatedBody = structuredClone(receipts);
  mutatedBody[0].body.reason_code = 'forged_reason';
  assert.throws(
    () => verifyReceiptChain(mutatedBody, {
      destinationPublicKeyPem: profile.destination.destinationPublicKeyPem,
      policy: profile.policy,
    }),
    (error) => error instanceof ProtocolError,
  );
  for (const [allocationBefore, allocationAfter] of [[1, 0], [null, 0]]) {
    const refusalAllocationDelta = structuredClone(receipts.at(-1));
    refusalAllocationDelta.body.allocation_before = allocationBefore;
    refusalAllocationDelta.body.allocation_after = allocationAfter;
    assert.throws(
      () => verifyRecord('receipt', refusalAllocationDelta, profile.destination.destinationPublicKeyPem),
      (error) => error instanceof ProtocolError && error.code === 'refusal_allocation_delta',
    );
  }
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  for (const [kind, record, publicKey] of [
    ['grant', grant, profile.keys.root.publicKeyPem],
    ['credential', credential, profile.keys.issuer.publicKeyPem],
    ['commit', commits[0], profile.destination.destinationPublicKeyPem],
    ['receipt', receipts.at(-1), profile.destination.destinationPublicKeyPem],
  ]) {
    let equivalentAliases = 0;
    for (const character of alphabet) {
      const signature = `${record.signature.slice(0, -1)}${character}`;
      if (signature === record.signature) continue;
      if (!Buffer.from(signature, 'base64url').equals(Buffer.from(record.signature, 'base64url'))) continue;
      equivalentAliases += 1;
      const mutated = structuredClone(record);
      mutated.signature = signature;
      assert.throws(
        () => verifyRecord(kind, mutated, publicKey),
        (error) => error instanceof ProtocolError && error.code === 'noncanonical_signature',
        `${kind}:${character}`,
      );
    }
    assert.equal(equivalentAliases, 15, kind);
  }
  const wrongDestination = generateKeyPairSync('ed25519');
  assert.throws(
    () => verifyReceiptChain(receipts, {
      destinationPublicKeyPem: wrongDestination.publicKey,
      policy: profile.policy,
    }),
    (error) => error instanceof ProtocolError,
  );

  for (const [kind, record] of [
    ['grant', executed],
    ['credential', executed],
    ['receipt', grant],
    ['receipt', credential],
    ['receipt', commits[0]],
  ]) {
    assert.throws(
      () => verifyRecord(kind, record, profile.destination.destinationPublicKeyPem),
      (error) => error instanceof ProtocolError,
    );
  }
} finally {
  profile.close();
  rmSync(directory, { recursive: true, force: true });
}

process.stdout.write('PASS demo1 receipts: attributable, chained, mutation-evident, non-authority, offline-verifiable\n');
