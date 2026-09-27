#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import {
  APPROVAL_TRANSPORT_PROOF_TYPE,
  assertApprovalTransportProof,
} from '../lib/approval-transport-proof.mjs';

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
const textRun = runZlar(['approval-transport-proof']);
assertEqual('text command exits zero', 0, textRun.status);
assertEqual('text command emits no stderr', '', textRun.stderr);
assert('text summary title present', textRun.stdout.includes('Approval Transport Proof v1'));
assert('text summary states fixture model', textRun.stdout.includes('Evidence model: local-hermetic-fixture; live probing=false'));
assert('text summary names channel-neutral model', textRun.stdout.includes('Transport model: channel-neutral-approval-transport-v1'));
assert('text summary names reference transport', textRun.stdout.includes('reference-fixture-transport'));
assert('text summary names Telegram adapter', textRun.stdout.includes('telegram-adapter'));
assert('text summary shows Telegram nonessential', textRun.stdout.includes('not_configured_not_required_for_fixture'));
assert('text summary includes missing receipt refusal', textRun.stdout.includes('transport_delivered_no_human_decision: refuse'));
assert('text summary includes signed decision acceptance', textRun.stdout.includes('transport_delivered_signed_human_decision: accept'));
assert('text summary is privacy safe', !unsafeOutputPattern.test(textRun.stdout));

section('json command');
const jsonRun = runZlar(['approval-transport-proof', '--json']);
assertEqual('json command exits zero', 0, jsonRun.status);
assertEqual('json command emits no stderr', '', jsonRun.stderr);
assert('json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report passes proof validation', assertApprovalTransportProof(report));
assertEqual('json proof type', APPROVAL_TRANSPORT_PROOF_TYPE, report.proof_type);
assertEqual('json live probing false', false, report.live_probing);
assertEqual('json transport model', 'channel-neutral-approval-transport-v1', report.transport_model);
assertEqual('json unavailable does not board', false, report.cases.transport_unavailable.boarded);
assertEqual('json pending does not board', false, report.cases.delivered_without_decision.boarded);
assertEqual('json signed decision boards', true, report.cases.signed_human_decision.boarded);
assertEqual('json Telegram not required', false, report.cases.telegram_not_required.required_for_fixture);
assert('json omits raw fixture record', !jsonRun.stdout.includes('approval-transport-fixture-record'));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonRun.stdout));

section('help and fail closed command handling');
const helpRun = runZlar(['approval-transport-proof', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assert('help names usage', helpRun.stderr.includes('Usage: zlar approval-transport-proof [--json]'));
assert('help states no live probing', helpRun.stderr.includes('does not live probe'));
assert('help states no Telegram', helpRun.stderr.includes('use Telegram'));
assertEqual('help emits no stdout', '', helpRun.stdout);

const unsupported = runZlar(['approval-transport-proof', '--latest']);
assert('unsupported option exits usage error', unsupported.status !== 0);
assert('unsupported option emits no report', unsupported.stdout === '');
assert('unsupported option names unsupported option', unsupported.stderr.includes('Unsupported option'));
assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

const helpList = runZlar(['help']);
assertEqual('main help exits zero', 0, helpList.status);
assert('main help lists approval transport proof', helpList.stdout.includes('approval-transport-proof'));

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
