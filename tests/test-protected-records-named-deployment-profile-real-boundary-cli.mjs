#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import {
  PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID,
  PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_REFUSAL_MESSAGE,
} from '../lib/protected-records-named-deployment-profile-real-boundary.mjs';

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

function runZlar(args) {
  return spawnSync('bin/zlar', args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;
const unique = `.zlar-named-real-boundary-cli-refusal-${process.pid}-${Date.now()}`;
const activationRoot = join(process.cwd(), unique, PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID);
const proofRoot = join(process.cwd(), `${unique}-proof`);
const artifactPath = join(process.cwd(), `${unique}-artifact.json`);

console.log('\n-- CLI machine-local named route authority refusal --');
assertEqual('activation root absent before CLI refusal', false, existsSync(activationRoot));
assertEqual('proof root absent before CLI refusal', false, existsSync(proofRoot));
assertEqual('artifact absent before CLI refusal', false, existsSync(artifactPath));

const run = runZlar([
  'protected-records-named-deployment-profile-real-boundary',
  '--run',
  '--json',
  '--artifact',
  artifactPath,
  '--activation-root',
  activationRoot,
  '--proof-root',
  proofRoot,
  '--reset-activation-root',
]);
assert('CLI authority refusal exits nonzero', run.status !== 0);
assertEqual('CLI authority refusal emits no stdout', '', run.stdout);
assert('CLI names exact authority refusal', run.stderr.includes(PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_REFUSAL_MESSAGE));
assert('CLI refusal text is privacy safe', !unsafeOutputPattern.test(run.stderr));
assertEqual('activation root remains absent', false, existsSync(activationRoot));
assertEqual('proof root remains absent', false, existsSync(proofRoot));
assertEqual('artifact remains absent', false, existsSync(artifactPath));

console.log('\n-- CLI refuses before activation-root shape validation --');
const wrongRoot = join(process.cwd(), `${unique}-wrong-profile`);
const wrongRootRun = runZlar([
  'protected-records-named-deployment-profile-real-boundary',
  '--run',
  '--activation-root',
  wrongRoot,
  '--proof-root',
  proofRoot,
  '--reset-activation-root',
]);
assert('wrong-root CLI run exits nonzero', wrongRootRun.status !== 0);
assertEqual('wrong-root CLI run emits no stdout', '', wrongRootRun.stdout);
assert('wrong-root CLI receives authority refusal', wrongRootRun.stderr.includes(PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_REFUSAL_MESSAGE));
assertEqual('wrong root remains absent', false, existsSync(wrongRoot));
assertEqual('proof root still remains absent', false, existsSync(proofRoot));

console.log('\n-- missing execution intent remains refusal-only --');
const missingRun = runZlar(['protected-records-named-deployment-profile-real-boundary', '--json']);
assert('missing --run exits nonzero', missingRun.status !== 0);
assertEqual('missing --run emits no stdout', '', missingRun.stdout);
assert('missing --run names refusal evaluation', missingRun.stderr.includes('evaluate the machine-local named-route authority refusal'));
assert('missing --run stderr is privacy safe', !unsafeOutputPattern.test(missingRun.stderr));

console.log(`\nResults: ${PASS}/${TOTAL} passed${FAIL ? `, ${FAIL} failed` : ''}`);
if (FAIL) {
  process.exit(1);
}
