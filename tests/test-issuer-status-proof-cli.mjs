#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import {
  ISSUER_STATUS_PROOF_TYPE,
  assertIssuerStatusProof,
} from '../lib/issuer-status-proof.mjs';

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

const ZLAR_BIN = join(process.cwd(), 'bin', 'zlar');
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;

function runZlar(args) {
  return spawnSync(ZLAR_BIN, args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

section('text summary command');
const textRun = runZlar(['issuer-status-proof']);
assertEqual('text command exits zero', 0, textRun.status);
assertEqual('text command emits no stderr', '', textRun.stderr);
assert('text summary title present', textRun.stdout.includes('Issuer Status Proof v1'));
assert('text summary states fixture model', textRun.stdout.includes('Evidence model: local-hermetic-fixture; live probing=false'));
assert('text summary names fixture trust anchor', textRun.stdout.includes('Trust anchor model: local-fixture-recognition-rule'));
assert('text summary includes active recognition', textRun.stdout.includes('active_issuer_recognized: accept'));
assert('text summary includes retired refusal', textRun.stdout.includes('retired_issuer_refused: refuse; reason=issuer_not_active'));
assert('text summary includes compromised refusal', textRun.stdout.includes('compromised_issuer_refused: refuse; reason=issuer_compromised'));
assert('text summary includes missing status refusal', textRun.stdout.includes('missing_status_issuer_refused: refuse; reason=issuer_status_missing'));
assert('text summary includes unknown refusal', textRun.stdout.includes('unknown_issuer_refused: refuse; reason=unknown_issuer'));
assert('text summary includes missing key refusal', textRun.stdout.includes('missing_key_issuer_refused: refuse; reason=issuer_key_missing'));
assert('text summary states production key non-claim', textRun.stdout.includes('not live or production signing authority'));
assert('text summary is privacy safe', !unsafeOutputPattern.test(textRun.stdout));

section('json command');
const jsonRun = runZlar(['issuer-status-proof', '--json']);
assertEqual('json command exits zero', 0, jsonRun.status);
assertEqual('json command emits no stderr', '', jsonRun.stderr);
assert('json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report passes proof validation', assertIssuerStatusProof(report));
assertEqual('json proof type', ISSUER_STATUS_PROOF_TYPE, report.proof_type);
assertEqual('json live probing false', false, report.live_probing);
assertEqual('json active boards', true, report.active_issuer.boarded);
assertEqual('json retired refuses', 'issuer_not_active', report.retired_issuer.reason_code);
assertEqual('json compromised refuses', 'issuer_compromised', report.compromised_issuer.reason_code);
assertEqual('json missing status refuses', 'issuer_status_missing', report.missing_status_issuer.reason_code);
assertEqual('json unknown refuses', 'unknown_issuer', report.unknown_issuer.reason_code);
assertEqual('json missing key refuses', 'issuer_key_missing', report.missing_key_issuer.reason_code);
assert('json omits raw fixture record', !jsonRun.stdout.includes('issuer-status-fixture-record'));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonRun.stdout));

section('help and fail closed command handling');
const helpRun = runZlar(['issuer-status-proof', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assert('help names usage', helpRun.stderr.includes('Usage: zlar issuer-status-proof [--json]'));
assert('help states no live probing', helpRun.stderr.includes('does not live probe'));
assert('help states no production keys', helpRun.stderr.includes('use production keys'));
assertEqual('help emits no stdout', '', helpRun.stdout);

const unsupported = runZlar(['issuer-status-proof', '--latest']);
assert('unsupported option exits usage error', unsupported.status !== 0);
assert('unsupported option emits no report', unsupported.stdout === '');
assert('unsupported option names unsupported option', unsupported.stderr.includes('Unsupported option'));
assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

const helpList = runZlar(['help']);
assertEqual('main help exits zero', 0, helpList.status);
assert('main help lists issuer status proof', helpList.stdout.includes('issuer-status-proof'));

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
