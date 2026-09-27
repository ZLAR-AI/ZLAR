#!/usr/bin/env node

import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import {
  DESTINATION_ID,
  STAGED_OBJECT_ID,
  ProtocolError,
  actionFromChallenge,
  assertExactGrantToCredential,
  bodyId,
  canonicalBytes,
  keyId,
  makeRecognitionPolicy,
  parseCanonical,
  policyDigest,
  signRecord,
  validateBody,
  verifyRecord,
} from './demo1-protocol.mjs';

const pair = () => generateKeyPairSync('ed25519');
const root = pair();
const issuer = pair();
const destination = pair();
const other = pair();
const pem = (key) => key.export({ type: 'spki', format: 'pem' }).toString();

const policy = makeRecognitionPolicy({
  profileId: 'zlar.demo1.software-test.v1',
  roots: [{ publicKeyPem: pem(root.publicKey) }],
  issuers: [{ publicKeyPem: pem(issuer.publicKey) }],
  destination: { publicKeyPem: pem(destination.publicKey) },
});

const challenge = {
  v: 1,
  type: 'challenge',
  profile_id: policy.profile_id,
  destination_id: DESTINATION_ID,
  principal_id: 'software-test:acting-client',
  challenge_nonce: 'A'.repeat(43),
  staged_object_id: STAGED_OBJECT_ID,
  artifact_sha256: `sha256:${'1'.repeat(64)}`,
  from_generation: 0,
  to_generation: 1,
  issued_at: 1000,
  expires_at: 1300,
};
const challengeRecord = signRecord('challenge', challenge, destination.privateKey);
const action = actionFromChallenge(challenge);
const grant = {
  v: 1,
  type: 'grant',
  profile_id: policy.profile_id,
  authority_root_key_id: keyId(root.publicKey),
  authorized_issuer_key_id: keyId(issuer.publicKey),
  grant_nonce: 'B'.repeat(43),
  action,
  action_id: bodyId('action', action),
  allocation_unit: 'protected_promotion',
  maximum_allocation: 1,
  issued_at: 1000,
  not_before: 1000,
  expires_at: 1300,
};
const grantRecord = signRecord('grant', grant, root.privateKey);
const credential = {
  v: 1,
  type: 'boarding_credential',
  profile_id: policy.profile_id,
  issuer_key_id: keyId(issuer.publicKey),
  credential_nonce: 'C'.repeat(43),
  grant_id: bodyId('grant', grant),
  action,
  action_id: bodyId('action', action),
  allocation_debit: 1,
  not_before: 1000,
  expires_at: 1300,
};
const credentialRecord = signRecord('credential', credential, issuer.privateKey);

function expectCode(fn, code) {
  assert.throws(fn, (error) => error instanceof ProtocolError && error.code === code);
}

function expectProtocolRefusal(fn) {
  assert.throws(fn, (error) => error instanceof ProtocolError);
}

verifyRecord('challenge', challengeRecord, destination.publicKey);
verifyRecord('grant', grantRecord, root.publicKey);
verifyRecord('credential', credentialRecord, issuer.publicKey);
assertExactGrantToCredential(grant, credential);
assert.match(policyDigest(policy), /^sha256:[0-9a-f]{64}$/);

expectCode(() => parseCanonical(Buffer.from('{"a":1,"a":1}')), 'noncanonical_transport');
expectCode(() => parseCanonical(Buffer.from('{"a":1.5}')), 'unsafe_integer');
expectCode(() => parseCanonical(Buffer.from('{"a":1e3}')), 'noncanonical_transport');
expectCode(() => parseCanonical(Buffer.from('{"a":9007199254740992}')), 'unsafe_integer');
expectCode(() => parseCanonical(Buffer.from('{"a":-0}')), 'unsafe_integer');
expectCode(() => parseCanonical(Buffer.from('{"x":"\\ud800"}')), 'lone_surrogate');
expectCode(() => parseCanonical(Buffer.from([0xff])), 'invalid_utf8');
expectCode(() => parseCanonical(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{}')])), 'bom_forbidden');
expectCode(() => parseCanonical(Buffer.from('{}\n')), 'noncanonical_transport');

const actionWithUnknown = { ...action, client_claimed_state: 'active' };
expectCode(() => validateBody('action', actionWithUnknown), 'unknown_or_missing_field');
expectCode(() => verifyRecord('grant', grantRecord, other.publicKey), 'bad_signature');
expectProtocolRefusal(() => verifyRecord('credential', grantRecord, root.publicKey));
expectProtocolRefusal(() => verifyRecord('grant', credentialRecord, issuer.publicKey));
expectProtocolRefusal(() => verifyRecord('receipt', credentialRecord, issuer.publicKey));

const shortenedRoot = { ...grant, authority_root_key_id: keyId(root.publicKey).slice(0, 28) };
expectCode(() => validateBody('grant', shortenedRoot), 'invalid_string');
const expandedAllocation = { ...grant, maximum_allocation: 2 };
expectCode(() => validateBody('grant', expandedAllocation), 'wrong_maximum_allocation');
const expandedCredential = { ...credential, expires_at: 1301 };
expectCode(() => assertExactGrantToCredential(grant, expandedCredential), 'credential_time_expansion');
const changedAction = { ...action, principal_id: 'software-test:other-client' };
const changedCredential = {
  ...credential,
  action: changedAction,
  action_id: bodyId('action', changedAction),
};
expectCode(() => assertExactGrantToCredential(grant, changedCredential), 'credential_wrong_action_id');

assert.equal(canonicalBytes(grant).toString('utf8'), Buffer.from(canonicalBytes(grant)).toString('utf8'));
process.stdout.write('PASS demo1 protocol: strict bytes, exact G-to-A, role and domain separation\n');
