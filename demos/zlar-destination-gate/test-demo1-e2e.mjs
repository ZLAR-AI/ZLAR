#!/usr/bin/env node

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

import {
  canonicalBytes,
  policyDigest,
  signRecord,
  signedRecordHash,
} from '../../cyan/demo1-protocol.mjs';
import { verifyEvidenceBundle } from './demo1-verify.mjs';
import {
  Demo1SoftwareProfile,
  SOFTWARE_CLAIM_CEILING,
  SOFTWARE_PRINCIPAL_ID,
  softwareProfilePublicSummary,
} from './demo1-software-profile.mjs';

const productRoot = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = dirname(dirname(productRoot));
const directory = mkdtempSync(join(tmpdir(), 'zlar-demo1-e2e-'));
const profile = new Demo1SoftwareProfile({ rootDirectory: directory, clock: () => 1000 });

function candidateAggregate() {
  const root = join(repositoryRoot, 'v4/reference-transfer-proof/candidate-005');
  const files = readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => join(root, entry.name))
    .sort((a, b) => Buffer.from(relative(root, a)).compare(Buffer.from(relative(root, b))));
  const aggregate = createHash('sha256');
  for (const path of files) {
    const rel = relative(root, path);
    const raw = readFileSync(path);
    const digest = createHash('sha256').update(raw).digest('hex');
    aggregate.update(Buffer.from(rel, 'utf8'));
    aggregate.update(Buffer.from([0]));
    aggregate.update(Buffer.from(String(raw.length), 'ascii'));
    aggregate.update(Buffer.from([0]));
    aggregate.update(Buffer.from(`${digest}\n`, 'ascii'));
  }
  return { count: files.length, digest: aggregate.digest('hex') };
}

try {
  profile.stage(Buffer.from('{"release":"demo-1-b","effect":"harmless-local"}\n'));
  const challenge = profile.challenge();
  const missing = profile.promotionRequest({ challengeRecord: challenge });
  assert.equal(
    profile.destination.promote(missing.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID }).body.reason_code,
    'missing_authority',
  );
  const grant = profile.signedGrant(challenge);
  const credential = profile.credential(grant);
  const exact = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credential });
  assert.equal(
    profile.destination.promote(exact.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID }).body.outcome,
    'executed',
  );
  const immediate = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credential });
  assert.equal(
    profile.destination.promote(immediate.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID }).body.outcome,
    'refused',
  );
  profile.restart();
  const durable = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credential });
  assert.equal(
    profile.destination.promote(durable.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID }).body.outcome,
    'refused',
  );

  profile.stage(Buffer.from('{"release":"demo-1-c","effect":"harmless-local"}\n'));
  const secondChallenge = profile.challenge();
  const secondGrant = profile.signedGrant(secondChallenge);
  const secondCredential = profile.credential(secondGrant);
  const secondRequest = profile.promotionRequest({
    challengeRecord: secondChallenge,
    grantRecord: secondGrant,
    credentialRecord: secondCredential,
  });
  assert.equal(
    profile.destination.promote(secondRequest.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID }).body.outcome,
    'executed',
  );

  const bundle = profile.destination.evidenceBundle();
  assert.equal(bundle.claim_ceiling, SOFTWARE_CLAIM_CEILING);
  const publicSummary = softwareProfilePublicSummary(profile);
  assert.equal(publicSummary.claim_ceiling, SOFTWARE_CLAIM_CEILING);
  assert.ok(!canonicalBytes(publicSummary).includes(Buffer.from('PRIVATE KEY')));
  const evidencePath = join(directory, 'software-evidence.json');
  const destinationKeyPath = join(directory, 'expected-destination-public.pem');
  writeFileSync(destinationKeyPath, profile.keys.destination.publicKeyPem);
  const expectedTrust = {
    expectedPolicyDigest: profile.destination.policyDigest,
    expectedDestinationPublicKeyPem: profile.keys.destination.publicKeyPem,
    expectedClaimCeiling: SOFTWARE_CLAIM_CEILING,
  };
  assert.throws(() => verifyEvidenceBundle(canonicalBytes(bundle)));
  assert.throws(() => verifyEvidenceBundle(canonicalBytes(bundle), {
    ...expectedTrust,
    expectedClaimCeiling: 'production_ready',
  }));
  const relabeled = structuredClone(bundle);
  relabeled.claim_ceiling = 'installed_c_backed_candidate_evidence_only';
  assert.throws(() => verifyEvidenceBundle(canonicalBytes(relabeled), {
    ...expectedTrust,
    expectedClaimCeiling: relabeled.claim_ceiling,
  }));
  const direct = verifyEvidenceBundle(canonicalBytes(bundle), expectedTrust);
  assert.equal(direct.status, 'VERIFIED_SOFTWARE_PROFILE_ONLY');
  assert.ok(direct.executed_count >= 1);
  assert.ok(direct.refusal_count >= 1);

  function mutateExecutedPair(commitIndex, changes) {
    const copy = structuredClone(bundle);
    const originalCommitId = signedRecordHash(copy.commits[commitIndex]);
    copy.commits[commitIndex] = signRecord('commit', {
      ...copy.commits[commitIndex].body,
      ...changes,
    }, profile.keys.destination.privateKeyPem);
    const replacementCommitId = signedRecordHash(copy.commits[commitIndex]);
    let previousReceiptHash = null;
    copy.receipts = copy.receipts.map((record) => {
      const matches = record.body.promotion_commit_id === originalCommitId;
      const receiptChanges = Object.fromEntries(
        Object.entries(changes).filter(([field]) => Object.hasOwn(record.body, field)),
      );
      const body = {
        ...record.body,
        ...(matches ? receiptChanges : {}),
        previous_receipt_hash: previousReceiptHash,
        promotion_commit_id: matches ? replacementCommitId : record.body.promotion_commit_id,
      };
      const resigned = signRecord('receipt', body, profile.keys.destination.privateKeyPem);
      previousReceiptHash = signedRecordHash(resigned);
      return resigned;
    });
    return copy;
  }

  function mutateReceipt(receiptIndex, changes) {
    const copy = structuredClone(bundle);
    let previousReceiptHash = null;
    copy.receipts = copy.receipts.map((record, index) => {
      const body = {
        ...record.body,
        ...(index === receiptIndex ? changes : {}),
        previous_receipt_hash: previousReceiptHash,
      };
      const resigned = signRecord('receipt', body, profile.keys.destination.privateKeyPem);
      previousReceiptHash = signedRecordHash(resigned);
      return resigned;
    });
    return copy;
  }

  function mutatePolicy(mutator) {
    const copy = structuredClone(bundle);
    mutator(copy.recognition_policy);
    const digest = policyDigest(copy.recognition_policy);
    copy.recognition_policy_sha256 = digest;
    const replacementIds = new Map();
    copy.commits = copy.commits.map((record) => {
      const originalId = signedRecordHash(record);
      const replacement = signRecord('commit', {
        ...record.body,
        recognition_policy_sha256: digest,
      }, profile.keys.destination.privateKeyPem);
      replacementIds.set(originalId, signedRecordHash(replacement));
      return replacement;
    });
    let previousReceiptHash = null;
    copy.receipts = copy.receipts.map((record) => {
      const body = {
        ...record.body,
        recognition_policy_sha256: digest,
        previous_receipt_hash: previousReceiptHash,
        promotion_commit_id: record.body.promotion_commit_id === null
          ? null
          : replacementIds.get(record.body.promotion_commit_id),
      };
      const replacement = signRecord('receipt', body, profile.keys.destination.privateKeyPem);
      previousReceiptHash = signedRecordHash(replacement);
      return replacement;
    });
    return { bundle: copy, digest };
  }

  const forgedHistory = mutateExecutedPair(0, {
    artifact_sha256: `sha256:${'0'.repeat(64)}`,
  });
  assert.throws(
    () => verifyEvidenceBundle(canonicalBytes(forgedHistory), expectedTrust),
    (error) => error.code === 'commit_artifact_mismatch',
  );

  for (const [field, code] of [
    ['request_id', 'duplicate_receipt_request_id'],
    ['challenge_id', 'duplicate_executed_challenge_id'],
    ['action_id', 'receipt_grant_action_mismatch'],
  ]) {
    const duplicateIdentity = mutateExecutedPair(1, {
      [field]: bundle.commits[0].body[field],
    });
    assert.throws(
      () => verifyEvidenceBundle(canonicalBytes(duplicateIdentity), expectedTrust),
      (error) => error.code === code,
      field,
    );
  }

  const unrecognizedGrantRefusal = mutateReceipt(0, {
    allocation_before: 0,
    allocation_after: 0,
  });
  assert.throws(
    () => verifyEvidenceBundle(canonicalBytes(unrecognizedGrantRefusal), expectedTrust),
    (error) => error.code === 'refusal_allocation_projection_mismatch',
  );
  const exhaustedRefusalIndex = bundle.receipts.findIndex((record) => (
    record.body.outcome === 'refused' && record.body.grant_id === bundle.commits[0].body.grant_id
  ));
  assert.ok(exhaustedRefusalIndex > 0);
  const falseRemainingAllocation = mutateReceipt(exhaustedRefusalIndex, {
    allocation_before: 1,
    allocation_after: 1,
  });
  assert.throws(
    () => verifyEvidenceBundle(canonicalBytes(falseRemainingAllocation), expectedTrust),
    (error) => error.code === 'refusal_allocation_projection_mismatch',
  );

  for (const [mutatePolicyRegistry, code] of [
    [(policy) => { policy.destination.status = 'revoked'; }, 'destination_key_not_active'],
    [(policy) => { policy.roots.forEach((entry) => { entry.status = 'revoked'; }); }, 'grant_root_unrecognized'],
    [(policy) => { policy.issuers.forEach((entry) => { entry.status = 'revoked'; }); }, 'grant_issuer_unrecognized'],
  ]) {
    const changedPolicy = mutatePolicy(mutatePolicyRegistry);
    assert.throws(
      () => verifyEvidenceBundle(canonicalBytes(changedPolicy.bundle), {
        expectedPolicyDigest: changedPolicy.digest,
        expectedDestinationPublicKeyPem: expectedTrust.expectedDestinationPublicKeyPem,
        expectedClaimCeiling: SOFTWARE_CLAIM_CEILING,
      }),
      (error) => error.code === code,
      code,
    );
  }

  for (const mutate of [
    (copy) => { copy.final_projection.active.generation += 1; },
    (copy) => { copy.final_projection.active.state_sha256 = `sha256:${'0'.repeat(64)}`; },
    (copy) => { copy.final_projection.grants = []; },
    (copy) => { copy.final_projection.credentials = []; },
    (copy) => { copy.final_projection.commit_count += 1; },
    (copy) => { copy.final_projection.receipt_count += 1; },
  ]) {
    const copy = structuredClone(bundle);
    mutate(copy);
    assert.throws(() => verifyEvidenceBundle(canonicalBytes(copy), expectedTrust));
  }

  const attackerDirectory = join(directory, 'attacker-profile');
  const attacker = new Demo1SoftwareProfile({ rootDirectory: attackerDirectory, clock: () => 1000 });
  try {
    attacker.stage(Buffer.from('{"release":"attacker"}\n'));
    const attackerChallenge = attacker.challenge();
    const attackerGrant = attacker.signedGrant(attackerChallenge);
    const attackerCredential = attacker.credential(attackerGrant);
    const attackerRequest = attacker.promotionRequest({
      challengeRecord: attackerChallenge,
      grantRecord: attackerGrant,
      credentialRecord: attackerCredential,
    });
    assert.equal(attacker.destination.promote(attackerRequest.bytes, {
      observedPrincipalId: SOFTWARE_PRINCIPAL_ID,
    }).body.outcome, 'executed');
    assert.throws(() => verifyEvidenceBundle(
      canonicalBytes(attacker.destination.evidenceBundle()),
      expectedTrust,
    ));
  } finally {
    attacker.close();
  }

  const verifierArguments = [
    join(productRoot, 'demo1-verify.mjs'),
    '--evidence', evidencePath,
    '--expected-policy-digest', profile.destination.policyDigest,
    '--destination-public-key', destinationKeyPath,
    '--expected-claim-ceiling', SOFTWARE_CLAIM_CEILING,
  ];
  writeFileSync(evidencePath, Buffer.concat([canonicalBytes(bundle), Buffer.from('\n')]));
  const offline = spawnSync(process.execPath, verifierArguments, {
    encoding: 'utf8',
  });
  assert.equal(offline.status, 42, `newline-bearing evidence must refuse: ${offline.stderr}`);
  writeFileSync(evidencePath, canonicalBytes(bundle));
  const missingTrust = spawnSync(process.execPath, [join(productRoot, 'demo1-verify.mjs'), '--evidence', evidencePath], {
    encoding: 'utf8',
  });
  assert.equal(missingTrust.status, 42);
  const exactOffline = spawnSync(process.execPath, verifierArguments, {
    encoding: 'utf8',
  });
  assert.equal(exactOffline.status, 0, exactOffline.stderr);
  assert.equal(JSON.parse(exactOffline.stdout).status, 'VERIFIED_SOFTWARE_PROFILE_ONLY');

  const outward = spawnSync(process.execPath, [join(productRoot, 'demo1.mjs'), 'health'], { encoding: 'utf8' });
  assert.equal(outward.status, 42);
  const outwardRefusal = JSON.parse(outward.stderr);
  assert.equal(outwardRefusal.status, 'REFUSED_NOT_INSTALLED');
  assert.equal(outwardRefusal.destination_reached, false);
  const historical = spawnSync('python3', ['-B', join(productRoot, 'run.py')], { encoding: 'utf8' });
  assert.equal(historical.status, 42);
  assert.equal(JSON.parse(historical.stderr).status, 'REFUSED_HISTORICAL_NON_ROUTING');

  const sourceFiles = [
    join(repositoryRoot, 'cyan/demo1-protocol.mjs'),
    join(repositoryRoot, 'cyan/demo1-store.mjs'),
    join(repositoryRoot, 'cyan/demo1-destination.mjs'),
    join(productRoot, 'demo1.mjs'),
    join(productRoot, 'demo1-software-profile.mjs'),
  ];
  const sourceText = sourceFiles.map((path) => readFileSync(path, 'utf8')).join('\n');
  for (const forbidden of [
    'candidate-005', "./guard.mjs", "./grant-store.mjs", "./replay-store.mjs",
    'eb746072b61c1f21225e6504accf55ec99d5ba73f3117c80e0d092c1436ab07c',
  ]) assert.ok(!sourceText.includes(forbidden), forbidden);

  const frozen = candidateAggregate();
  assert.equal(frozen.count, 13);
  assert.equal(frozen.digest, 'e037738dc7abe3b2c1d6c63e7103275ed73ce241ab0236f21f1feadee4914e2f');
  assert.ok(statSync(profile.databasePath).isFile());
} finally {
  profile.close();
  rmSync(directory, { recursive: true, force: true });
}

process.stdout.write('PASS demo1 e2e: software-only refusal/effect/replay, exact authority evidence, pure client route, frozen baseline\n');
