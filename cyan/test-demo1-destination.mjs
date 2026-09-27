#!/usr/bin/env node

import assert from 'node:assert/strict';
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { isMainThread, parentPort, Worker, workerData } from 'node:worker_threads';

import {
  bodyId,
  canonicalBytes,
  parseCanonical,
  signRecord,
} from './demo1-protocol.mjs';
import { InjectedFault } from './demo1-destination.mjs';
import { verifyEvidenceBundle } from '../demos/zlar-destination-gate/demo1-verify.mjs';
import {
  Demo1SoftwareProfile,
  SOFTWARE_PRINCIPAL_ID,
} from '../demos/zlar-destination-gate/demo1-software-profile.mjs';

const crashChildMode = process.argv[2] === '--abrupt-crash-child';

if (crashChildMode) {
  const fixturePath = process.env.ZLAR_DEMO1_CRASH_FIXTURE;
  if (!fixturePath) throw new Error('missing_crash_fixture');
  const data = JSON.parse(readFileSync(fixturePath, 'utf8'));
  const profile = new Demo1SoftwareProfile({
    rootDirectory: data.rootDirectory,
    keys: data.keys,
    clock: () => data.now,
  });
  const stopInsideTransaction = () => {
    writeSync(1, 'CRASH_POINT_REACHED\n');
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
  };
  if (data.mode === 'before_commit') {
    const original = profile.destination.store.insertReceipt.bind(profile.destination.store);
    profile.destination.store.insertReceipt = (...args) => {
      original(...args);
      stopInsideTransaction();
    };
  } else if (data.mode === 'after_commit') {
    const original = profile.destination.store.transaction.bind(profile.destination.store);
    profile.destination.store.transaction = (fn) => {
      const result = original(fn);
      stopInsideTransaction();
      return result;
    };
  } else {
    throw new Error('unknown_crash_mode');
  }
  profile.destination.promote(Buffer.from(data.request, 'base64'), {
    observedPrincipalId: SOFTWARE_PRINCIPAL_ID,
  });
} else if (!isMainThread) {
  const profile = new Demo1SoftwareProfile({
    rootDirectory: workerData.rootDirectory,
    keys: workerData.keys,
    clock: () => workerData.now,
  });
  parentPort.postMessage({ ready: true });
  Atomics.wait(new Int32Array(workerData.barrier), 0, 0);
  try {
    const receipt = profile.destination.promote(Buffer.from(workerData.request, 'base64'), {
      observedPrincipalId: SOFTWARE_PRINCIPAL_ID,
    });
    parentPort.postMessage({ outcome: receipt.body.outcome, reason: receipt.body.reason_code });
  } finally {
    profile.close();
  }
} else {
  function fixture(fn) {
    const directory = mkdtempSync(join(tmpdir(), 'zlar-demo1-destination-'));
    const profile = new Demo1SoftwareProfile({ rootDirectory: directory, clock: () => 1000 });
    try {
      profile.stage(Buffer.from('{"release":"demo-1-b"}\n'));
      return fn(profile, directory);
    } finally {
      profile.close();
      rmSync(directory, { recursive: true, force: true });
    }
  }

  fixture((profile) => {
    const challenge = profile.challenge();
    const missing = profile.promotionRequest({ challengeRecord: challenge });
    const refusal = profile.destination.promote(missing.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID });
    assert.equal(refusal.body.outcome, 'refused');
    assert.equal(refusal.body.reason_code, 'missing_authority');
    assert.equal(refusal.body.state_before_sha256, refusal.body.state_after_sha256);
    assert.equal(profile.destination.activeRelease().generation, 0);

    const grant = profile.signedGrant(challenge);
    const credential = profile.credential(grant);
    const exact = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credential });
    const executed = profile.destination.promote(exact.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID });
    assert.equal(executed.body.outcome, 'executed');
    assert.equal(profile.destination.activeRelease().generation, 1);
    assert.equal(profile.destination.activeRelease().artifactBytes.toString(), '{"release":"demo-1-b"}\n');

    const replay = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credential });
    const replayReceipt = profile.destination.promote(replay.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID });
    assert.equal(replayReceipt.body.outcome, 'refused');
    assert.equal(replayReceipt.body.reason_code, 'grant_allocation_exhausted');
    assert.equal(profile.destination.activeRelease().generation, 1);

    profile.restart();
    const durableReplay = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credential });
    const durableReceipt = profile.destination.promote(durableReplay.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID });
    assert.equal(durableReceipt.body.outcome, 'refused');
    assert.equal(durableReceipt.body.reason_code, 'grant_allocation_exhausted');
    assert.equal(profile.destination.activeRelease().generation, 1);
  });

  fixture((profile) => {
    const challenge = profile.challenge();
    const grant = profile.signedGrant(challenge);
    const credentialA = profile.credential(grant);
    const credentialB = profile.credential(grant);
    const first = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credentialA });
    const second = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credentialB });
    assert.equal(profile.destination.promote(first.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID }).body.outcome, 'executed');
    assert.equal(profile.destination.promote(second.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID }).body.reason_code, 'grant_allocation_exhausted');
    assert.equal(profile.destination.projection().commitCount, 1);
  });

  fixture((profile) => {
    const challenge = profile.challenge();
    const grant = profile.signedGrant(challenge);
    const credential = profile.credential(grant);
    profile.stage(Buffer.from('{"release":"substituted"}\n'));
    const request = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credential });
    const receipt = profile.destination.promote(request.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID });
    assert.equal(receipt.body.reason_code, 'staged_artifact_changed');
    assert.equal(profile.destination.activeRelease().generation, 0);
  });

  fixture((profile) => {
    profile.close();
    profile.policy.destination.status = 'revoked';
    assert.throws(
      () => profile.open(),
      (error) => error.code === 'destination_key_not_active',
    );
  });

  fixture((profile) => {
    const challengeX = profile.challenge();
    const challengeY = profile.challenge();
    const grant = profile.signedGrant(challengeX);
    const credential = profile.credential(grant);
    const request = parseCanonical(profile.promotionRequest({
      challengeRecord: challengeX,
      grantRecord: grant,
      credentialRecord: credential,
    }).bytes);
    request.challenge_id = bodyId('challenge', challengeY.body);
    const receipt = profile.destination.promote(canonicalBytes(request), {
      observedPrincipalId: SOFTWARE_PRINCIPAL_ID,
    });
    assert.equal(receipt.body.outcome, 'refused');
    assert.equal(receipt.body.reason_code, 'request_challenge_mismatch');
    assert.equal(receipt.body.challenge_id, bodyId('challenge', challengeX.body));
    assert.equal(profile.destination.store.challenge(bodyId('challenge', challengeX.body)).consumed, false);
    assert.equal(profile.destination.store.challenge(bodyId('challenge', challengeY.body)).consumed, false);
    const projection = profile.destination.projection();
    assert.equal(projection.active.generation, 0);
    assert.equal(projection.grants.length, 1);
    assert.equal(projection.grants[0].spentAllocation, 0);
    assert.equal(projection.credentials.length, 1);
    assert.equal(projection.credentials[0].used, false);
    assert.equal(projection.commitCount, 0);
  });

  function temporalOutcome(evaluatedAt, { credentialExpiresAt = 1300 } = {}) {
    const directory = mkdtempSync(join(tmpdir(), 'zlar-demo1-time-'));
    let now = 1000;
    const profile = new Demo1SoftwareProfile({ rootDirectory: directory, clock: () => now });
    try {
      profile.stage(Buffer.from('{"release":"demo-1-b"}\n'));
      const challenge = profile.challenge();
      const grant = profile.signedGrant(challenge, { now: 1000, expiresAt: 1300 });
      now = 1001;
      let credential = profile.credential(grant);
      if (credentialExpiresAt !== credential.body.expires_at) {
        credential = signRecord('credential', {
          ...credential.body,
          expires_at: credentialExpiresAt,
        }, profile.keys.issuer.privateKeyPem);
      }
      now = evaluatedAt;
      const request = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credential });
      return profile.destination.promote(request.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID });
    } finally {
      profile.close();
      rmSync(directory, { recursive: true, force: true });
    }
  }

  assert.equal(temporalOutcome(1000).body.reason_code, 'credential_not_current');
  assert.equal(temporalOutcome(1001).body.outcome, 'executed');
  assert.equal(temporalOutcome(1299).body.outcome, 'executed');
  assert.equal(temporalOutcome(1300).body.reason_code, 'grant_not_current');

  function advancingClockOutcome(readings, { expiresAt = 1300, refusalReason = null } = {}) {
    fixture((profile) => {
      const challenge = profile.challenge();
      const grant = profile.signedGrant(challenge, { expiresAt });
      const credential = profile.credential(grant);
      const request = profile.promotionRequest({
        challengeRecord: challenge, grantRecord: grant, credentialRecord: credential,
      });
      let clockReads = 0;
      profile.destination.clock = () => readings[Math.min(clockReads++, readings.length - 1)];
      const receipt = profile.destination.promote(request.bytes, {
        observedPrincipalId: SOFTWARE_PRINCIPAL_ID,
      });
      const expired = readings.some((reading) => reading >= expiresAt);
      const refused = expired || refusalReason !== null;
      assert.equal(receipt.body.outcome, refused ? 'refused' : 'executed');
      const projection = profile.destination.projection();
      assert.equal(projection.active.generation, refused ? 0 : 1);
      assert.equal(projection.grants[0].spentAllocation, refused ? 0 : 1);
      assert.equal(projection.credentials[0].used, !refused);
      assert.equal(profile.destination.store.challenge(bodyId('challenge', challenge.body)).consumed, !refused);
      assert.equal(projection.commitCount, refused ? 0 : 1);
      assert.equal(projection.receiptCount, 1);
      if (refused) {
        assert.equal(receipt.body.reason_code, refusalReason ?? 'grant_not_current');
        assert.equal(receipt.body.state_before_sha256, receipt.body.state_after_sha256);
        assert.equal(receipt.body.allocation_before, 1);
        assert.equal(receipt.body.allocation_after, 1);
      } else {
        // Keep the actual record-formation times; do not backdate the receipt
        // to the first freshness check to make evidence verification pass.
        assert.equal(profile.destination.commits()[0].body.committed_at, 1297);
        assert.equal(receipt.body.recorded_at, 1298);
      }
      const verified = verifyEvidenceBundle(canonicalBytes(profile.destination.evidenceBundle()), {
        expectedPolicyDigest: profile.destination.policyDigest,
        expectedDestinationPublicKeyPem: profile.destination.destinationPublicKeyPem,
        expectedClaimCeiling: 'software_key_protocol_and_transaction_only',
      });
      assert.equal(verified.executed_count, refused ? 0 : 1);
      assert.equal(verified.refusal_count, refused ? 1 : 0);
    });
  }

  advancingClockOutcome([1299, 1300]);
  advancingClockOutcome([1299, 1299, 1299, 1300]);
  advancingClockOutcome([1299, 1300, 1299]);
  advancingClockOutcome([1299, 1299, 1300, 1299]);
  advancingClockOutcome([1296, 1298, 1297, 1299], { refusalReason: 'destination_clock_regressed' });
  advancingClockOutcome([1296, 1297, 1298, 1297], { refusalReason: 'destination_clock_regressed' });
  advancingClockOutcome([1289, 1290], { expiresAt: 1290 });
  advancingClockOutcome([1296, 1297, 1298, 1299]);

  function credentialIssuanceAt(evaluatedAt) {
    const directory = mkdtempSync(join(tmpdir(), 'zlar-demo1-issuer-time-'));
    let now = 1000;
    const profile = new Demo1SoftwareProfile({ rootDirectory: directory, clock: () => now });
    try {
      profile.stage(Buffer.from('{"release":"demo-1-b"}\n'));
      const challenge = profile.challenge();
      const grant = profile.signedGrant(challenge, { now: 1000, expiresAt: 1300 });
      now = evaluatedAt;
      return profile.credential(grant);
    } finally {
      profile.close();
      rmSync(directory, { recursive: true, force: true });
    }
  }

  assert.throws(() => credentialIssuanceAt(999), (error) => error.code === 'grant_not_current');
  assert.ok(credentialIssuanceAt(1000));
  assert.ok(credentialIssuanceAt(1299));
  assert.throws(() => credentialIssuanceAt(1300), (error) => error.code === 'grant_not_current');

  fixture((profile) => {
    const challenge = profile.challenge();
    const grant = profile.signedGrant(challenge);
    const credential = profile.credential(grant);
    const staged = join(profile.stagingRoot, 'demo-1-release.json');
    const alternate = join(profile.stagingRoot, 'alternate.json');
    unlinkSync(staged);
    writeFileSync(alternate, '{"release":"demo-1-b"}\n');
    symlinkSync(alternate, staged);
    const request = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credential });
    const receipt = profile.destination.promote(request.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID });
    assert.equal(receipt.body.reason_code, 'staged_object_not_regular');
    assert.equal(profile.destination.activeRelease().generation, 0);
  });

  for (const point of [
    'after_verification', 'after_commit_formed', 'after_commit_inserted',
    'after_debit', 'after_consumption', 'after_active_update',
    'after_receipt_formed', 'before_transaction_commit',
  ]) {
    fixture((profile) => {
      const challenge = profile.challenge();
      const grant = profile.signedGrant(challenge);
      const credential = profile.credential(grant);
      const request = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credential });
      assert.throws(
        () => profile.destination.promote(request.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID, faultAt: point }),
        (error) => error instanceof InjectedFault && error.point === point,
      );
      const projection = profile.destination.projection();
      assert.equal(projection.active.generation, 0, point);
      assert.equal(projection.grants.length, 1, point);
      assert.equal(projection.grants[0].spentAllocation, 0, point);
      assert.equal(projection.credentials.length, 1, point);
      assert.equal(projection.credentials[0].used, false, point);
      assert.equal(projection.commitCount, 0, point);
      assert.equal(projection.receiptCount, 0, point);
    });
  }

  fixture((profile) => {
    const challenge = profile.challenge();
    const grant = profile.signedGrant(challenge);
    const credential = profile.credential(grant);
    const request = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credential });
    assert.throws(
      () => profile.destination.promote(request.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID, faultAt: 'after_commit_before_response' }),
      /after_commit_before_response/,
    );
    assert.equal(profile.destination.activeRelease().generation, 1);
    const recovered = profile.destination.promote(request.bytes, { observedPrincipalId: SOFTWARE_PRINCIPAL_ID });
    assert.equal(recovered.body.outcome, 'executed');
    assert.equal(profile.destination.projection().commitCount, 1);
  });

  async function concurrencyTest() {
    const directory = mkdtempSync(join(tmpdir(), 'zlar-demo1-concurrency-'));
    const profile = new Demo1SoftwareProfile({ rootDirectory: directory, clock: () => 1000 });
    try {
      profile.stage(Buffer.from('{"release":"demo-1-b"}\n'));
      const challenge = profile.challenge();
      const grant = profile.signedGrant(challenge);
      const credentialA = profile.credential(grant);
      const credentialB = profile.credential(grant);
      const requestA = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credentialA });
      const requestB = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credentialB });
      const keys = profile.keys;
      profile.close();
      const barrier = new SharedArrayBuffer(4);
      const run = (request) => new Promise((resolve, reject) => {
        const worker = new Worker(new URL(import.meta.url), {
          workerData: {
            rootDirectory: directory,
            keys,
            now: 1000,
            barrier,
            request: request.bytes.toString('base64'),
          },
        });
        let ready = false;
        worker.on('message', (message) => {
          if (message.ready) {
            ready = true;
            resolve({ worker, ready: true, result: new Promise((done) => worker.once('message', done)) });
          }
        });
        worker.on('error', reject);
        worker.on('exit', (code) => {
          if (!ready && code !== 0) reject(new Error(`worker_exit:${code}`));
        });
      });
      const [a, b] = await Promise.all([run(requestA), run(requestB)]);
      Atomics.store(new Int32Array(barrier), 0, 1);
      Atomics.notify(new Int32Array(barrier), 0, 2);
      const results = await Promise.all([a.result, b.result]);
      await Promise.all([a.worker.terminate(), b.worker.terminate()]);
      assert.deepEqual(results.map((row) => row.outcome).sort(), ['executed', 'refused']);
      profile.open();
      assert.equal(profile.destination.activeRelease().generation, 1);
      assert.equal(profile.destination.projection().commitCount, 1);
    } finally {
      profile.close();
      rmSync(directory, { recursive: true, force: true });
    }
  }

  async function abruptProcessCrashTest(mode) {
    const directory = mkdtempSync(join(tmpdir(), `zlar-demo1-crash-${mode}-`));
    const profile = new Demo1SoftwareProfile({ rootDirectory: directory, clock: () => 1000 });
    let reopened = profile;
    try {
      profile.stage(Buffer.from('{"release":"demo-1-b"}\n'));
      const challenge = profile.challenge();
      const grant = profile.signedGrant(challenge);
      const credential = profile.credential(grant);
      const request = profile.promotionRequest({ challengeRecord: challenge, grantRecord: grant, credentialRecord: credential });
      const fixturePath = join(directory, 'crash-fixture.json');
      writeFileSync(fixturePath, JSON.stringify({
        mode,
        rootDirectory: directory,
        keys: profile.keys,
        now: 1000,
        request: request.bytes.toString('base64'),
      }), { mode: 0o600 });
      profile.close();
      reopened = null;

      const child = spawn(process.execPath, [new URL(import.meta.url).pathname, '--abrupt-crash-child'], {
        env: { ...process.env, ZLAR_DEMO1_CRASH_FIXTURE: fixturePath },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let stderr = '';
      child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          child.kill('SIGKILL');
          reject(new Error(`crash_child_timeout:${mode}:${stderr}`));
        }, 5000);
        child.stdout.on('data', (chunk) => {
          if (!chunk.toString().includes('CRASH_POINT_REACHED')) return;
          child.kill('SIGKILL');
        });
        child.once('error', (error) => {
          clearTimeout(timer);
          reject(error);
        });
        child.once('close', (_code, signal) => {
          clearTimeout(timer);
          if (signal !== 'SIGKILL') reject(new Error(`crash_child_not_killed:${mode}:${stderr}`));
          else resolve();
        });
      });

      reopened = new Demo1SoftwareProfile({ rootDirectory: directory, keys: profile.keys, clock: () => 1000 });
      const projection = reopened.destination.projection();
      if (mode === 'before_commit') {
        assert.equal(projection.active.generation, 0);
        assert.equal(projection.grants.length, 1);
        assert.equal(projection.grants[0].spentAllocation, 0);
        assert.equal(projection.credentials.length, 1);
        assert.equal(projection.credentials[0].used, false);
        assert.equal(projection.commitCount, 0);
        assert.equal(projection.receiptCount, 0);
      } else {
        assert.equal(projection.active.generation, 1);
        assert.equal(projection.grants[0].spentAllocation, 1);
        assert.equal(projection.credentials[0].used, true);
        assert.equal(projection.commitCount, 1);
        assert.equal(projection.receiptCount, 1);
      }
      const recovered = reopened.destination.promote(request.bytes, {
        observedPrincipalId: SOFTWARE_PRINCIPAL_ID,
      });
      assert.equal(recovered.body.outcome, 'executed');
      assert.equal(reopened.destination.projection().commitCount, 1);
      assert.equal(reopened.destination.activeRelease().generation, 1);
    } finally {
      reopened?.close();
      rmSync(directory, { recursive: true, force: true });
    }
  }

  await concurrencyTest();
  await abruptProcessCrashTest('before_commit');
  await abruptProcessCrashTest('after_commit');
  process.stdout.write('PASS demo1 destination: refusal, exact effect, allocation, replay, restart, concurrency, rollback, abrupt crash\n');
}
