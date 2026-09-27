#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import {
  DOWNSTREAM_REFUSAL_PROOF_TYPE,
  REQUIRED_REFUSAL_REASONS,
  assertDownstreamRefusalProof,
} from '../lib/downstream-refusal-proof.mjs';

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
const textRun = runZlar(['downstream-refusal-proof']);
assertEqual('text command exits zero', 0, textRun.status);
assertEqual('text command emits no stderr', '', textRun.stderr);
assert('text summary title present', textRun.stdout.includes('Downstream Refusal Proof v1'));
assert('text summary states fixture model', textRun.stdout.includes('Evidence model: local-hermetic-fixture; live probing=false'));
assert('text summary includes recognized boarding', textRun.stdout.includes('- recognized: accept; marker_delta=1'));
for (const reason of REQUIRED_REFUSAL_REASONS) {
  assert(`text summary includes refusal reason: ${reason}`, textRun.stdout.includes(reason));
}
assert('text summary states non-claims', textRun.stdout.includes('does not prove production deployment'));
assert('text summary is privacy safe', !unsafeOutputPattern.test(textRun.stdout));

section('json command');
const jsonRun = runZlar(['downstream-refusal-proof', '--json']);
assertEqual('json command exits zero', 0, jsonRun.status);
assertEqual('json command emits no stderr', '', jsonRun.stderr);
assert('json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report passes proof validation', assertDownstreamRefusalProof(report));
assertEqual('json proof type', DOWNSTREAM_REFUSAL_PROOF_TYPE, report.proof_type);
assertEqual('json live probing false', false, report.live_probing);
assertEqual('json marker final count', 1, report.marker.final_count);
assertEqual('json refusal count', 11, report.refusals.length);
assert('json omits raw record id', !jsonRun.stdout.includes('fixture-record-001'));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonRun.stdout));

section('help and fail closed command handling');
const helpRun = runZlar(['downstream-refusal-proof', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assert('help names usage', helpRun.stderr.includes('Usage: zlar downstream-refusal-proof [--json]'));
assert('help states no live probing', helpRun.stderr.includes('does not live probe'));
assertEqual('help emits no stdout', '', helpRun.stdout);

const unsupported = runZlar(['downstream-refusal-proof', '--latest']);
assert('unsupported option exits usage error', unsupported.status !== 0);
assert('unsupported option emits no report', unsupported.stdout === '');
assert('unsupported option names unsupported option', unsupported.stderr.includes('Unsupported option'));
assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
