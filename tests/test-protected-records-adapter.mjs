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
  PROTECTED_RECORDS_CONSUMED_STORE_TYPE,
  PROTECTED_RECORDS_ADAPTER_TYPE,
  PROTECTED_RECORDS_WRITE_RESULT_TYPE,
  SAFE_CLAIM_CEILING,
  applyProtectedRecordsWrite,
  assertNoUnsafeProtectedRecordsAdapterText,
  assertProtectedRecordsWriteResult,
} from '../lib/protected-records-adapter.mjs';

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

const scratch = mkdtempSync(join(tmpdir(), 'zlar-protected-records-adapter-'));

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
const writeDetail = {
  record_id: 'fixture-record-001',
  operation: 'update_status',
};

function eventFixture(overrides = {}) {
  return {
    id: overrides.id || 'protected-record-write-001',
    ts: overrides.ts || isoSecondsAgo(nowEpoch, 5),
    action: overrides.action || 'records.write',
    domain: overrides.domain || 'records',
    detail: overrides.detail || writeDetail,
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
    deployment_scope: 'protected-records-adapter-fixture',
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
    required_audit_event_id: 'protected-record-write-001',
  };
}

function paths(label) {
  return {
    ledger_path: join(scratch, `${label}.jsonl`),
    consumed_receipts_path: join(scratch, `${label}-consumed.json`),
  };
}

function inputFor(label, overrides = {}) {
  return {
    fixture_mode: true,
    receipt: signedReceipt(),
    recognition_rule: recognitionRule(),
    write_detail: writeDetail,
    now_epoch: nowEpoch,
    ...paths(label),
    ...overrides,
  };
}

function assertAdapterRefusalBeforeAppend(label, input, expectedReasonCode) {
  const result = applyProtectedRecordsWrite(input);
  assert(`${label} result passes validation`, assertProtectedRecordsWriteResult(result));
  assertEqual(`${label} refused`, false, result.write_accepted);
  assertEqual(`${label} reason`, expectedReasonCode, result.decision.reason_code);
  assertEqual(`${label} record delta zero`, 0, result.record_count_delta);
  assertEqual(`${label} record count unchanged`, result.record_count_before, result.record_count_after);
  assertEqual(`${label} ledger entry not written`, false, result.ledger_entry_written);
  assertEqual(`${label} writes no ledger`, false, existsSync(input.ledger_path));
  return result;
}

try {
  section('recognized write appends bounded ledger entry');
  const acceptedInput = inputFor('accepted');
  const accepted = applyProtectedRecordsWrite(acceptedInput);
  assert('accepted result passes validation', assertProtectedRecordsWriteResult(accepted));
  assertEqual('result type', PROTECTED_RECORDS_WRITE_RESULT_TYPE, accepted.result_type);
  assertEqual('adapter type', PROTECTED_RECORDS_ADAPTER_TYPE, accepted.adapter_type);
  assertEqual('safe claim ceiling exact', SAFE_CLAIM_CEILING, accepted.safe_claim_ceiling);
  assertEqual('fixture evidence', 'local-fixture-supplied-input', accepted.evidence_model);
  assertEqual('no live probing', false, accepted.live_probing);
  assertEqual('write accepted', true, accepted.write_accepted);
  assertEqual('record changed', true, accepted.record_changed);
  assertEqual('one ledger entry', 1, accepted.record_count_after);
  assertEqual('one consumed receipt', 1, accepted.consumed_receipt_count);
  assertEqual('recognized decision', 'recognized', accepted.decision.reason_code);
  assert('accepted output privacy safe', assertNoUnsafeProtectedRecordsAdapterText(JSON.stringify(accepted, null, 2)));

  const ledgerText = readFileSync(acceptedInput.ledger_path, 'utf8');
  const ledgerEntry = JSON.parse(ledgerText.trim());
  assertEqual('ledger entry type', 'protected-records-ledger-entry-v1', ledgerEntry.entry_type);
  assertEqual('ledger binds receipt id', accepted.decision.evidence.receipt_id, ledgerEntry.receipt_id);
  assertEqual('ledger binds write detail hash', accepted.write_detail_hash, ledgerEntry.detail_hash);
  assertEqual('ledger omits raw record id', false, ledgerText.includes('fixture-record-001'));
  assertEqual('ledger omits public key', false, ledgerText.includes('BEGIN PUBLIC KEY'));
  assertEqual('ledger omits private key', false, ledgerText.includes('BEGIN PRIVATE KEY'));

  section('persistent replay refusal before append');
  const replay = applyProtectedRecordsWrite(acceptedInput);
  assert('replay result passes validation', assertProtectedRecordsWriteResult(replay));
  assertEqual('replay refused', false, replay.write_accepted);
  assertEqual('replay reason', 'receipt_replay', replay.decision.reason_code);
  assertEqual('replay changes no records', 0, replay.record_count_delta);
  assertEqual('replay leaves ledger count one', 1, replay.record_count_after);
  assertEqual('replay preserves consumed receipt count', 1, replay.consumed_receipt_count);

  section('refusal cases prevent append');
  const missingInput = inputFor('missing', { receipt: null });
  const missing = assertAdapterRefusalBeforeAppend('missing receipt', missingInput, 'receipt_missing');

  const invalidReceipt = signedReceipt();
  invalidReceipt.sig = 'AAAA';
  const invalidInput = inputFor('invalid-receipt', { receipt: invalidReceipt });
  assertAdapterRefusalBeforeAppend('invalid receipt', invalidInput, 'receipt_invalid');

  const wrongDetailInput = inputFor('wrong-detail', {
    write_detail: {
      record_id: 'fixture-record-002',
      operation: 'update_status',
    },
  });
  assertAdapterRefusalBeforeAppend('wrong write detail', wrongDetailInput, 'detail_hash_mismatch');

  const unknownInput = inputFor('unknown', { receipt: signedReceipt(unknown) });
  assertAdapterRefusalBeforeAppend('unknown issuer', unknownInput, 'unknown_issuer');

  const retiredRule = recognitionRule();
  retiredRule.accepted_issuers = [
    {
      kid: trusted.kid,
      public_key_pem: trusted.publicPem,
      status: 'retired',
    },
  ];
  const retiredInput = inputFor('retired-issuer', { recognition_rule: retiredRule });
  assertAdapterRefusalBeforeAppend('retired issuer', retiredInput, 'issuer_not_active');

  const missingStatusRule = recognitionRule();
  missingStatusRule.accepted_issuers = [
    {
      kid: trusted.kid,
      public_key_pem: trusted.publicPem,
    },
  ];
  const missingStatusInput = inputFor('missing-issuer-status', { recognition_rule: missingStatusRule });
  assertAdapterRefusalBeforeAppend('missing issuer status', missingStatusInput, 'issuer_status_missing');

  const wrongPolicyInput = inputFor('wrong-policy', {
    receipt: signedReceipt(trusted, { policy_version: 'recognition-policy-other' }),
  });
  assertAdapterRefusalBeforeAppend('wrong policy', wrongPolicyInput, 'policy_not_recognized');

  const wrongDomainInput = inputFor('wrong-domain', {
    receipt: signedReceipt(trusted, { domain: 'other-records-domain' }),
  });
  assertAdapterRefusalBeforeAppend('wrong domain', wrongDomainInput, 'domain_out_of_scope');

  const wrongToolInput = inputFor('wrong-tool', {
    receipt: signedReceipt(trusted, { action: 'records.delete' }),
  });
  assertAdapterRefusalBeforeAppend('wrong tool', wrongToolInput, 'tool_out_of_scope');

  const nonBoardingInput = inputFor('non-boarding-outcome', {
    receipt: signedReceipt(trusted, { outcome: 'deny' }),
  });
  assertAdapterRefusalBeforeAppend('non-boarding outcome', nonBoardingInput, 'outcome_not_boarding');

  const staleInput = inputFor('stale', {
    receipt: signedReceipt(trusted, { ts: isoSecondsAgo(nowEpoch, 600) }),
  });
  assertAdapterRefusalBeforeAppend('stale receipt', staleInput, 'receipt_stale');

  const replayAfterTtlReceipt = signedReceipt(trusted, { ts: isoSecondsAgo(nowEpoch, 600) });
  const replayAfterTtlInput = inputFor('replay-after-ttl', {
    receipt: replayAfterTtlReceipt,
  });
  writeFileSync(replayAfterTtlInput.consumed_receipts_path, `${JSON.stringify({
    store_type: PROTECTED_RECORDS_CONSUMED_STORE_TYPE,
    receipt_ids: [replayAfterTtlReceipt.id],
  }, null, 2)}\n`);
  const replayAfterTtl = applyProtectedRecordsWrite(replayAfterTtlInput);
  assert('replay after TTL result passes validation', assertProtectedRecordsWriteResult(replayAfterTtl));
  assertEqual('replay after TTL refuses as freshness before replay', 'receipt_stale', replayAfterTtl.decision.reason_code);
  assertEqual('replay after TTL changes no records', 0, replayAfterTtl.record_count_delta);
  assertEqual('replay after TTL preserves consumed receipt count', 1, replayAfterTtl.consumed_receipt_count);
  assertEqual('replay after TTL writes no ledger', false, existsSync(replayAfterTtlInput.ledger_path));

  section('fail closed local adapter boundaries');
  const missingFixtureMode = inputFor('missing-fixture-mode');
  delete missingFixtureMode.fixture_mode;
  assertThrows('fixture mode is required', () => applyProtectedRecordsWrite(missingFixtureMode), 'fixture_mode true is required');

  const invalidStore = inputFor('invalid-store');
  writeFileSync(invalidStore.consumed_receipts_path, 'not-json\n');
  assertThrows('invalid consumed store refuses before append', () => applyProtectedRecordsWrite(invalidStore), 'Consumed receipt store is invalid');
  assertEqual('invalid consumed store writes no ledger', false, existsSync(invalidStore.ledger_path));

  const samePath = inputFor('same-path');
  samePath.consumed_receipts_path = samePath.ledger_path;
  assertThrows('ledger and store paths must differ', () => applyProtectedRecordsWrite(samePath), 'must be different');

  const drifted = structuredClone(accepted);
  drifted.live_probing = true;
  assertThrows('live probing claim fails validation', () => assertProtectedRecordsWriteResult(drifted), 'must not perform live probing');

  const changedRefusal = structuredClone(missing);
  changedRefusal.record_count_after = 1;
  changedRefusal.record_count_delta = 1;
  assertThrows('refusal ledger change fails validation', () => assertProtectedRecordsWriteResult(changedRefusal), 'refusal changed the ledger');
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
