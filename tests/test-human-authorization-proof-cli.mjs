#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import {
  HUMAN_AUTHORIZATION_PROOF_TYPE,
  assertHumanAuthorizationProof,
} from '../lib/human-authorization-proof.mjs';

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
const textRun = runZlar(['human-authorization-proof']);
assertEqual('text command exits zero', 0, textRun.status);
assertEqual('text command emits no stderr', '', textRun.stderr);
assert('text summary title present', textRun.stdout.includes('Human Authorization Proof v1'));
assert('text summary states fixture model', textRun.stdout.includes('Evidence model: local-hermetic-fixture; live probing=false'));
assert('text summary names simulated channel', textRun.stdout.includes('Approval channel: simulated-human-fixture'));
assert('text summary includes pending refusal', textRun.stdout.includes('ask_pending_without_human_decision: refuse'));
assert('text summary includes authorized boarding', textRun.stdout.includes('simulated_human_approved: accept'));
assert('text summary includes denied refusal', textRun.stdout.includes('simulated_human_denied: refuse'));
assert('text summary states Telegram non-claim', textRun.stdout.includes('not live Telegram'));
assert('text summary is privacy safe', !unsafeOutputPattern.test(textRun.stdout));

section('json command');
const jsonRun = runZlar(['human-authorization-proof', '--json']);
assertEqual('json command exits zero', 0, jsonRun.status);
assertEqual('json command emits no stderr', '', jsonRun.stderr);
assert('json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report passes proof validation', assertHumanAuthorizationProof(report));
assertEqual('json proof type', HUMAN_AUTHORIZATION_PROOF_TYPE, report.proof_type);
assertEqual('json live probing false', false, report.live_probing);
assertEqual('json approval channel simulated', 'simulated-human-fixture', report.approval_channel);
assertEqual('json pending does not board', false, report.pending_without_decision.boarded);
assertEqual('json authorized boards', true, report.authorized_boarding.boarded);
assertEqual('json denied does not board', false, report.denied_boarding.boarded);
assert('json omits raw fixture record', !jsonRun.stdout.includes('authorized-fixture-record'));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonRun.stdout));

section('help and fail closed command handling');
const helpRun = runZlar(['human-authorization-proof', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assert('help names usage', helpRun.stderr.includes('Usage: zlar human-authorization-proof [--json]'));
assert('help states no live probing', helpRun.stderr.includes('does not live probe'));
assert('help states no Telegram', helpRun.stderr.includes('use Telegram'));
assertEqual('help emits no stdout', '', helpRun.stdout);

const unsupported = runZlar(['human-authorization-proof', '--latest']);
assert('unsupported option exits usage error', unsupported.status !== 0);
assert('unsupported option emits no report', unsupported.stdout === '');
assert('unsupported option names unsupported option', unsupported.stderr.includes('Unsupported option'));
assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

const helpList = runZlar(['help']);
assertEqual('main help exits zero', 0, helpList.status);
assert('main help lists human authorization proof', helpList.stdout.includes('human-authorization-proof'));

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
