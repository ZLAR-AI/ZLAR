#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_FORBIDDEN_CLAIMS,
  CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_MODEL,
  CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_SAFE_CLAIM,
  CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_TYPE,
  assertConfiguredRecognitionConsumerReplayStoreProof,
  assertNoUnsafeConfiguredRecognitionReplayStoreProofText,
  formatConfiguredRecognitionConsumerReplayStoreProof,
  runConfiguredRecognitionConsumerReplayStoreProof,
} from '../lib/zlar-configured-recognition-consumer-replay-store-proof.mjs';

let pass = 0;
let fail = 0;

async function test(name, fn) {
  try {
    await fn();
    pass++;
    console.log(`PASS ${name}`);
  } catch (error) {
    fail++;
    console.log(`FAIL ${name}`);
    console.log(error?.stack || error);
  }
}

await test('proof report passes and preserves claim ceiling', async () => {
  const report = await runConfiguredRecognitionConsumerReplayStoreProof();
  assertConfiguredRecognitionConsumerReplayStoreProof(report);
  assert.equal(report.proof_type, CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_TYPE);
  assert.equal(report.evidence_model, CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_MODEL);
  assert.equal(report.safe_claim, CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_SAFE_CLAIM);
  assert.equal(report.case_count, 3);
  assert.equal(report.local_fixture_only, true);
  assert.equal(report.no_secret_material, true);
  assert.equal(report.live_probe, false);
  assert.equal(report.real_downstream, false);
  assert.equal(report.real_receipt, false);
  assert.equal(report.production_trust, false);
  for (const claim of CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_FORBIDDEN_CLAIMS) {
    assert.equal(report.forbidden_claims.includes(claim), true);
  }
});

await test('proof cases show consume, replay refusal, and invalid-store refusal', async () => {
  const report = await runConfiguredRecognitionConsumerReplayStoreProof();
  const cases = new Map(report.cases.map((item) => [item.case_id, item]));
  const first = cases.get('first_call_persists_replay_state_after_effect');
  const replay = cases.get('second_call_refuses_replay_before_callback');
  const invalid = cases.get('invalid_store_fails_closed_before_callback');

  assert.equal(first.wrapper_decision, 'ok');
  assert.equal(first.reason_code, 'consumer_replay_state_persisted');
  assert.equal(first.store_written, true);
  assert.equal(first.consumer_decision, 'effect_written');
  assert.equal(first.effect_called, true);
  assert.equal(first.effect_written, true);
  assert.equal(first.callback_calls, 1);
  assert.equal(first.persisted_replay_state_matches_returned, true);
  assert.match(first.persisted_replay_state_hash, /^[0-9a-f]{64}$/);
  assert.equal(first.persisted_replay_state_hash, first.returned_replay_state_hash);
  assert.equal(report.summary.persisted_replay_state_matches_returned, true);

  assert.equal(replay.wrapper_decision, 'ok');
  assert.equal(replay.store_written, false);
  assert.equal(replay.consumer_decision, 'refuse');
  assert.equal(replay.consumer_reason_code, 'credential_id_replayed');
  assert.equal(replay.effect_called, false);
  assert.equal(replay.callback_calls, 0);

  assert.equal(invalid.wrapper_decision, 'fail_closed');
  assert.equal(invalid.reason_code, 'replay_state_array_field_invalid');
  assert.equal(invalid.consumer_decision, null);
  assert.equal(invalid.effect_called, false);
  assert.equal(invalid.callback_calls, 0);
});

await test('proof JSON and summary are privacy safe', async () => {
  const report = await runConfiguredRecognitionConsumerReplayStoreProof();
  const json = JSON.stringify(report, null, 2);
  const summary = formatConfiguredRecognitionConsumerReplayStoreProof(report);
  assertNoUnsafeConfiguredRecognitionReplayStoreProofText(json);
  assertNoUnsafeConfiguredRecognitionReplayStoreProofText(summary);
  assert.equal(json.includes('replay-store.json'), false);
  assert.equal(summary.includes('replay-store.json'), false);
});

await test('direct CLI and zlar dispatch return proof JSON', async () => {
  const binPath = fileURLToPath(
    new URL('../bin/zlar-configured-recognition-consumer-replay-store-proof', import.meta.url),
  );
  const zlarPath = fileURLToPath(new URL('../bin/zlar', import.meta.url));

  const direct = spawnSync(process.execPath, [binPath, '--json'], { encoding: 'utf8' });
  assert.equal(direct.status, 0);
  assert.equal(direct.stderr, '');
  const directReport = JSON.parse(direct.stdout);
  assert.equal(directReport.proof_type, CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_TYPE);
  assert.equal(directReport.proof_status, 'passed');
  assertNoUnsafeConfiguredRecognitionReplayStoreProofText(direct.stdout);

  const dispatched = spawnSync(
    zlarPath,
    ['configured-recognition-consumer-replay-store-proof', '--json'],
    { encoding: 'utf8' },
  );
  assert.equal(dispatched.status, 0);
  assert.equal(dispatched.stderr, '');
  const dispatchedReport = JSON.parse(dispatched.stdout);
  assert.equal(dispatchedReport.proof_type, CONFIGURED_RECOGNITION_REPLAY_STORE_PROOF_TYPE);
  assert.equal(dispatchedReport.proof_status, 'passed');
});

await test('unsupported CLI argument fails without private output', async () => {
  const binPath = fileURLToPath(
    new URL('../bin/zlar-configured-recognition-consumer-replay-store-proof', import.meta.url),
  );
  const run = spawnSync(process.execPath, [
    binPath,
    '--live',
    '/Users/example/private/path',
    'Authorization: Bearer EXAMPLE',
    'client_secret=EXAMPLE',
  ], { encoding: 'utf8' });
  assert.equal(run.status, 1);
  assert.match(run.stderr, /unsupported argument/);
  assertNoUnsafeConfiguredRecognitionReplayStoreProofText(run.stderr);
  assert.equal(run.stderr.includes('/Users/example'), false);
  assert.equal(run.stderr.includes('Authorization: Bearer'), false);
  assert.equal(run.stderr.includes('client_secret'), false);
});

console.log(`${pass} passed, ${fail} failed`);
if (fail > 0) {
  process.exitCode = 1;
}
