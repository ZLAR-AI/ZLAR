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
import { spawnSync } from 'node:child_process';
import {
  createReceiptV1FromEvent,
  pubkeyFingerprint,
  signReceiptV1,
} from '../lib/receipt.mjs';

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

function section(title) {
  console.log(`\n-- ${title} --`);
}

function isoSecondsAgo(nowEpoch, seconds) {
  return new Date((nowEpoch - seconds) * 1000).toISOString();
}

const ZLAR_BIN = join(process.cwd(), 'bin', 'zlar');
const scratch = mkdtempSync(join(tmpdir(), 'zlar-protected-records-write-cli-'));
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;

function runZlar(args, options = {}) {
  return spawnSync(ZLAR_BIN, args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    input: options.input,
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

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

function signedReceipt(overrides = {}) {
  return signReceiptV1(
    createReceiptV1FromEvent(eventFixture(overrides)),
    trusted.privatePem,
    trusted.kid
  );
}

function baseInput(label, overrides = {}) {
  return {
    fixture_mode: true,
    receipt: signedReceipt(),
    recognition_rule: {
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
    },
    write_detail: writeDetail,
    ledger_path: join(scratch, `${label}.jsonl`),
    consumed_receipts_path: join(scratch, `${label}-consumed.json`),
    now_epoch: nowEpoch,
    ...overrides,
  };
}

function writeInput(label, input) {
  const path = join(scratch, `${label}.json`);
  writeFileSync(path, `${JSON.stringify(input, null, 2)}\n`);
  return path;
}

try {
  section('recognized write command');
  const acceptedInput = baseInput('accepted');
  const acceptedPath = writeInput('accepted-input', acceptedInput);
  const acceptedRun = runZlar(['protected-records-write', '--input', acceptedPath, '--require-written']);
  assertEqual('accepted command exits zero', 0, acceptedRun.status);
  assertEqual('accepted command emits no stderr', '', acceptedRun.stderr);
  assert('accepted command output privacy safe', !unsafeOutputPattern.test(acceptedRun.stdout));
  const accepted = JSON.parse(acceptedRun.stdout);
  assertEqual('accepted result type', 'protected-records-write-result-v1', accepted.result_type);
  assertEqual('accepted write true', true, accepted.write_accepted);
  assertEqual('accepted reason recognized', 'recognized', accepted.decision.reason_code);
  assertEqual('accepted ledger count', 1, accepted.record_count_after);
  assert('accepted ledger exists', existsSync(acceptedInput.ledger_path));
  assert('accepted consumed store exists', existsSync(acceptedInput.consumed_receipts_path));
  const acceptedLedgerText = readFileSync(acceptedInput.ledger_path, 'utf8');
  assert('accepted ledger omits raw record id', !acceptedLedgerText.includes('fixture-record-001'));
  assert('accepted ledger omits key material', !/BEGIN [A-Z ]*KEY/.test(acceptedLedgerText));

  section('replay command refuses from persistent consumed store');
  const replayRun = runZlar(['protected-records-write', '--input', acceptedPath, '--require-refused']);
  assertEqual('replay command exits zero', 0, replayRun.status);
  assertEqual('replay command emits no stderr', '', replayRun.stderr);
  const replay = JSON.parse(replayRun.stdout);
  assertEqual('replay refused', false, replay.write_accepted);
  assertEqual('replay reason', 'receipt_replay', replay.decision.reason_code);
  assertEqual('replay record delta zero', 0, replay.record_count_delta);
  assertEqual('replay leaves one ledger entry', 1, replay.record_count_after);

  section('stdin refused command');
  const wrongDetailInput = baseInput('wrong-detail', {
    write_detail: {
      record_id: 'fixture-record-002',
      operation: 'update_status',
    },
  });
  const wrongDetailRun = runZlar(['protected-records-write', '--input', '-', '--require-refused'], {
    input: `${JSON.stringify(wrongDetailInput, null, 2)}\n`,
  });
  assertEqual('wrong detail stdin exits zero', 0, wrongDetailRun.status);
  assertEqual('wrong detail stdin emits no stderr', '', wrongDetailRun.stderr);
  const wrongDetail = JSON.parse(wrongDetailRun.stdout);
  assertEqual('wrong detail refused', 'detail_hash_mismatch', wrongDetail.decision.reason_code);
  assertEqual('wrong detail writes no ledger', false, existsSync(wrongDetailInput.ledger_path));

  const requireWrittenFailure = runZlar(['protected-records-write', '--input', '-','--require-written'], {
    input: `${JSON.stringify(wrongDetailInput, null, 2)}\n`,
  });
  assert('require-written fails refused input', requireWrittenFailure.status !== 0);
  assertEqual('require-written failure emits no JSON', '', requireWrittenFailure.stdout);
  assert('require-written failure names refusal', requireWrittenFailure.stderr.includes('detail_hash_mismatch'));

  section('fail closed command handling');
  const missingInput = runZlar(['protected-records-write']);
  assert('missing input exits usage error', missingInput.status !== 0);
  assert('missing input refuses live writes', missingInput.stderr.includes('live protected-records writes are not implemented'));
  assertEqual('missing input emits no JSON', '', missingInput.stdout);

  const unsupported = runZlar(['protected-records-write', '--input', acceptedPath, '--latest']);
  assert('unsupported option exits usage error', unsupported.status !== 0);
  assertEqual('unsupported option emits no JSON', '', unsupported.stdout);
  assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

  const bothRequire = runZlar([
    'protected-records-write',
    '--input',
    acceptedPath,
    '--require-written',
    '--require-refused',
  ]);
  assert('mutually exclusive require flags fail', bothRequire.status !== 0);
  assert('mutually exclusive error is explicit', bothRequire.stderr.includes('mutually exclusive'));
  assertEqual('mutually exclusive emits no JSON', '', bothRequire.stdout);

  const noFixtureInput = baseInput('no-fixture');
  delete noFixtureInput.fixture_mode;
  const noFixturePath = writeInput('no-fixture-input', noFixtureInput);
  const noFixtureRun = runZlar(['protected-records-write', '--input', noFixturePath]);
  assert('missing fixture mode fails', noFixtureRun.status !== 0);
  assertEqual('missing fixture mode emits no JSON', '', noFixtureRun.stdout);
  assert('missing fixture mode names boundary', noFixtureRun.stderr.includes('fixture_mode true is required'));
  assertEqual('missing fixture mode writes no ledger', false, existsSync(noFixtureInput.ledger_path));

  const helpRun = runZlar(['protected-records-write', '--help']);
  assertEqual('help exits zero', 0, helpRun.status);
  assert('help names usage', helpRun.stderr.includes('Usage: zlar protected-records-write --input <file|->'));
  assert('help states local fixture paths', helpRun.stderr.includes('supplied local fixture paths'));
  assertEqual('help emits no stdout', '', helpRun.stdout);

  const helpList = runZlar(['help']);
  assertEqual('main help exits zero', 0, helpList.status);
  assert('main help lists protected records write', helpList.stdout.includes('protected-records-write'));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
