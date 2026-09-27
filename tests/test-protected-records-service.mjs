#!/usr/bin/env node

import { generateKeyPairSync } from 'node:crypto';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createReceiptV1FromEvent,
  pubkeyFingerprint,
  signReceiptV1,
} from '../lib/receipt.mjs';
import {
  PROTECTED_RECORDS_SERVICE_RESULT_TYPE,
  PROTECTED_RECORDS_SERVICE_TYPE,
  SAFE_CLAIM_CEILING,
  applyProtectedRecordsServiceRequest,
  assertNoUnsafeProtectedRecordsServiceText,
  assertProtectedRecordsServiceResult,
} from '../lib/protected-records-service.mjs';

let PASS = 0;
let FAIL = 0;
let TOTAL = 0;

function assert(label, condition, detail = '') {
  TOTAL++;
  if (condition) {
    PASS++;
    console.log(`  PASS: ${label}`);
  } else {
    FAIL++;
    console.log(`  FAIL: ${label}${detail ? ` -- ${detail}` : ''}`);
  }
}

function assertEqual(label, expected, actual) {
  assert(label, expected === actual, `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
}

function assertThrows(label, fn, expectedMessageFragment) {
  TOTAL++;
  try {
    fn();
    FAIL++;
    console.log(`  FAIL: ${label} -- expected throw`);
  } catch (err) {
    if (!expectedMessageFragment || String(err.message).includes(expectedMessageFragment)) {
      PASS++;
      console.log(`  PASS: ${label}`);
    } else {
      FAIL++;
      console.log(`  FAIL: ${label} -- ${err.message}`);
    }
  }
}

function section(title) {
  console.log(`\n-- ${title} --`);
}

function isoSecondsAgo(nowEpoch, seconds) {
  return new Date((nowEpoch - seconds) * 1000).toISOString();
}

const scratch = mkdtempSync(join(tmpdir(), 'zlar-protected-records-service-'));

function keyFixture(label) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  const publicPath = join(scratch, `${label}.pub`);
  writeFileSync(publicPath, publicPem);
  return {
    privatePem,
    publicPem,
    kid: pubkeyFingerprint(publicPath),
  };
}

const nowEpoch = Math.floor(Date.now() / 1000);
const trusted = keyFixture('trusted');
const unknown = keyFixture('unknown');
const recordUpdate = {
  record_id: 'fixture-record-001',
  operation: 'update_status',
};

function eventFixture(overrides = {}) {
  return {
    id: overrides.id || 'protected-record-service-001',
    ts: overrides.ts || isoSecondsAgo(nowEpoch, 5),
    action: overrides.action || 'records.write',
    domain: overrides.domain || 'records',
    detail: overrides.detail || recordUpdate,
    outcome: overrides.outcome || 'allow',
    rule: overrides.rule || 'RRECORDS_ALLOW',
    authorizer: overrides.authorizer || 'policy',
    policy_version: overrides.policy_version || 'recognition-policy-v1',
    prev_hash: overrides.prev_hash || '0'.repeat(64),
  };
}

function signedReceipt(key = trusted, overrides = {}) {
  return signReceiptV1(
    createReceiptV1FromEvent(eventFixture(overrides)),
    key.privatePem,
    key.kid
  );
}

function recognitionRule() {
  return {
    deployment_scope: 'protected-records-service-fixture',
    accepted_issuers: [
      {
        kid: trusted.kid,
        public_key_pem: trusted.publicPem,
        status: 'active',
      },
    ],
    accepted_policy_versions: ['recognition-policy-v1'],
    accepted_domains: ['records'],
    accepted_tools: ['records.write'],
    accepted_outcomes: ['allow', 'authorized'],
    max_age_seconds: 120,
    required_audit_event_id: 'protected-record-service-001',
  };
}

function paths(label) {
  return {
    state_path: join(scratch, `${label}.jsonl`),
    consumed_receipts_path: join(scratch, `${label}-consumed.json`),
  };
}

function inputFor(label, overrides = {}) {
  return {
    fixture_mode: true,
    receipt: signedReceipt(),
    recognition_rule: recognitionRule(),
    record_update: recordUpdate,
    request_mode: 'recognized_service_write',
    now_epoch: nowEpoch,
    ...paths(label),
    ...overrides,
  };
}

try {
  section('recognized service write mutates bounded service state');
  const acceptedInput = inputFor('accepted');
  const accepted = applyProtectedRecordsServiceRequest(acceptedInput);
  assert('accepted result passes validation', assertProtectedRecordsServiceResult(accepted));
  assertEqual('result type', PROTECTED_RECORDS_SERVICE_RESULT_TYPE, accepted.result_type);
  assertEqual('service type', PROTECTED_RECORDS_SERVICE_TYPE, accepted.service_type);
  assertEqual('safe claim ceiling exact', SAFE_CLAIM_CEILING, accepted.safe_claim_ceiling);
  assertEqual('fixture evidence', 'local-fixture-supplied-input', accepted.evidence_model);
  assertEqual('no live probing', false, accepted.live_probing);
  assertEqual('service write accepted', true, accepted.service_write_accepted);
  assertEqual('service state changed', true, accepted.service_state_changed);
  assertEqual('one state entry', 1, accepted.state_entry_count_after);
  assertEqual('one consumed receipt', 1, accepted.consumed_receipt_count);
  assertEqual('recognized decision', 'recognized', accepted.decision.reason_code);
  assert('accepted output privacy safe', assertNoUnsafeProtectedRecordsServiceText(JSON.stringify(accepted, null, 2)));

  const stateText = readFileSync(acceptedInput.state_path, 'utf8');
  const stateEntry = JSON.parse(stateText.trim());
  assertEqual('state entry type', 'protected-records-service-state-entry-v1', stateEntry.entry_type);
  assertEqual('state binds receipt id', accepted.decision.evidence.receipt_id, stateEntry.receipt_id);
  assertEqual('state binds record update hash', accepted.record_update_hash, stateEntry.detail_hash);
  assertEqual('state omits raw record id', false, stateText.includes('fixture-record-001'));
  assertEqual('state omits public key', false, stateText.includes('BEGIN PUBLIC KEY'));
  assertEqual('state omits private key', false, stateText.includes('BEGIN PRIVATE KEY'));

  section('persistent replay refusal before service-state mutation');
  const replay = applyProtectedRecordsServiceRequest({
    ...acceptedInput,
    request_mode: 'replay_service_write',
  });
  assert('replay result passes validation', assertProtectedRecordsServiceResult(replay));
  assertEqual('replay refused', false, replay.service_write_accepted);
  assertEqual('replay reason', 'receipt_replay', replay.decision.reason_code);
  assertEqual('replay changes no state', 0, replay.state_entry_count_delta);
  assertEqual('replay leaves one state entry', 1, replay.state_entry_count_after);
  assertEqual('replay preserves consumed receipt count', 1, replay.consumed_receipt_count);

  section('refusal cases prevent service-state mutation');
  const missingInput = inputFor('missing', {
    receipt: null,
    request_mode: 'missing_receipt_service_write',
  });
  const missing = applyProtectedRecordsServiceRequest(missingInput);
  assert('missing result passes validation', assertProtectedRecordsServiceResult(missing));
  assertEqual('missing receipt refused', 'receipt_missing', missing.decision.reason_code);
  assertEqual('missing writes no state', false, existsSync(missingInput.state_path));

  const wrongDetailInput = inputFor('wrong-detail', {
    record_update: {
      record_id: 'fixture-record-002',
      operation: 'update_status',
    },
    request_mode: 'unrecognized_service_write',
  });
  const wrongDetail = applyProtectedRecordsServiceRequest(wrongDetailInput);
  assertEqual('wrong record update refused', 'detail_hash_mismatch', wrongDetail.decision.reason_code);
  assertEqual('wrong record update changes no state', 0, wrongDetail.state_entry_count_delta);
  assertEqual('wrong record update writes no state', false, existsSync(wrongDetailInput.state_path));

  const unknownInput = inputFor('unknown', {
    receipt: signedReceipt(unknown),
    request_mode: 'unrecognized_service_write',
  });
  const unknownResult = applyProtectedRecordsServiceRequest(unknownInput);
  assertEqual('unknown issuer refused', 'unknown_issuer', unknownResult.decision.reason_code);
  assertEqual('unknown issuer writes no state', false, existsSync(unknownInput.state_path));

  const directApiInput = inputFor('direct-api', {
    receipt: null,
    request_mode: 'direct_api_write_without_receipt',
    direct_api_write: true,
  });
  const directApi = applyProtectedRecordsServiceRequest(directApiInput);
  assert('direct api result passes validation', assertProtectedRecordsServiceResult(directApi));
  assertEqual('direct api refused', false, directApi.service_write_accepted);
  assertEqual('direct api reason', 'receipt_missing', directApi.decision.reason_code);
  assertEqual('direct api marked', true, directApi.direct_api_attempted);
  assertEqual('direct api writes no state', false, existsSync(directApiInput.state_path));

  const directApiWithReceiptInput = inputFor('direct-api-with-receipt', {
    request_mode: 'direct_api_write_without_receipt',
    direct_api_write: true,
  });
  const directApiWithReceipt = applyProtectedRecordsServiceRequest(directApiWithReceiptInput);
  assert('direct api with receipt result passes validation', assertProtectedRecordsServiceResult(directApiWithReceipt));
  assertEqual('direct api with receipt refused', false, directApiWithReceipt.service_write_accepted);
  assertEqual('direct api with receipt reason', 'direct_api_receipt_present', directApiWithReceipt.decision.reason_code);
  assertEqual('direct api with receipt writes no state', false, existsSync(directApiWithReceiptInput.state_path));
  assertEqual('direct api with receipt consumes no receipt', false, existsSync(directApiWithReceiptInput.consumed_receipts_path));

  section('fail closed local service boundaries');
  const missingFixtureMode = inputFor('missing-fixture-mode');
  delete missingFixtureMode.fixture_mode;
  assertThrows('fixture mode is required', () => applyProtectedRecordsServiceRequest(missingFixtureMode), 'fixture_mode true is required');

  const invalidStore = inputFor('invalid-store');
  writeFileSync(invalidStore.consumed_receipts_path, 'not-json\n');
  assertThrows('invalid consumed store refuses before mutation', () => applyProtectedRecordsServiceRequest(invalidStore), 'Consumed receipt store is invalid');
  assertEqual('invalid consumed store writes no state', false, existsSync(invalidStore.state_path));

  const postAppendFailureInput = inputFor('post-append-failure');
  const priorState = `${JSON.stringify({
    entry_type: 'existing-protected-records-service-state-entry-v1',
    marker: 'before',
  })}\n`;
  writeFileSync(postAppendFailureInput.state_path, priorState);
  assertThrows(
    'consumed-store commit failure rolls back state append',
    () => applyProtectedRecordsServiceRequest(postAppendFailureInput, {
      writeConsumedStoreForTest: () => {
        throw new Error('simulated consumed-store commit failure');
      },
    }),
    'refusing before committed service-state mutation'
  );
  assertEqual(
    'post-append failure leaves state bytes unchanged',
    priorState,
    readFileSync(postAppendFailureInput.state_path, 'utf8')
  );
  assertEqual(
    'post-append failure burns no receipt',
    false,
    existsSync(postAppendFailureInput.consumed_receipts_path)
  );

  const samePath = inputFor('same-path');
  samePath.consumed_receipts_path = samePath.state_path;
  assertThrows('state and store paths must differ', () => applyProtectedRecordsServiceRequest(samePath), 'must be different');

  const missingStateParent = inputFor('missing-state-parent', {
    state_path: join(scratch, 'missing-parent', 'state.jsonl'),
    consumed_receipts_path: join(scratch, 'missing-state-parent-consumed.json'),
  });
  assertThrows('missing state parent refuses before consuming receipt', () => applyProtectedRecordsServiceRequest(missingStateParent), 'state_path fixture path is not writable');
  assertEqual('missing state parent writes no consumed store', false, existsSync(missingStateParent.consumed_receipts_path));

  const drifted = structuredClone(accepted);
  drifted.live_probing = true;
  assertThrows('live probing claim fails validation', () => assertProtectedRecordsServiceResult(drifted), 'must not perform live probing');

  const changedRefusal = structuredClone(missing);
  changedRefusal.state_entry_count_after = 1;
  changedRefusal.state_entry_count_delta = 1;
  assertThrows('refusal state change fails validation', () => assertProtectedRecordsServiceResult(changedRefusal), 'refusal changed service state');
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
