#!/usr/bin/env node

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import {
  PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID,
  PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_REFUSAL_CODE,
  PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_REFUSAL_MESSAGE,
  runProtectedRecordsNamedDeploymentProfileRealBoundaryProof,
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

function captureRefusal(options) {
  try {
    runProtectedRecordsNamedDeploymentProfileRealBoundaryProof(options);
  } catch (err) {
    return err;
  }
  return null;
}

const unique = `.zlar-named-real-boundary-refusal-${process.pid}-${Date.now()}`;
const activationRoot = join(process.cwd(), unique, PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID);
const proofRoot = join(process.cwd(), `${unique}-proof`);

console.log('\n-- machine-local named route authority refusal --');
assertEqual('activation root absent before refusal', false, existsSync(activationRoot));
assertEqual('proof root absent before refusal', false, existsSync(proofRoot));

const refusal = captureRefusal({
  activationRoot,
  proofRoot,
  nowEpoch: 1783609800,
  resetActivationRoot: true,
});
assert('run refuses', refusal instanceof Error);
assertEqual(
  'refusal code is exact',
  PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_REFUSAL_CODE,
  refusal?.code
);
assertEqual(
  'refusal message is exact',
  PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_REFUSAL_MESSAGE,
  refusal?.message
);
assertEqual('activation root remains absent after refusal', false, existsSync(activationRoot));
assertEqual('proof root remains absent after refusal', false, existsSync(proofRoot));

console.log('\n-- authority refusal precedes path validation and every side-effect call --');
const wrongRoot = join(process.cwd(), `${unique}-wrong-profile`);
const wrongRootRefusal = captureRefusal({
  activationRoot: wrongRoot,
  proofRoot,
  resetActivationRoot: true,
});
assertEqual(
  'wrong-shaped activation root still receives authority refusal first',
  PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_REFUSAL_CODE,
  wrongRootRefusal?.code
);
assertEqual('wrong-shaped activation root remains absent', false, existsSync(wrongRoot));

const runSource = runProtectedRecordsNamedDeploymentProfileRealBoundaryProof.toString();
const refusalIndex = runSource.indexOf('throw refusal');
assert('run source contains unconditional refusal', refusalIndex >= 0);
for (const call of [
  'ensureActivationRootShape(activationRoot)',
  'rmSync(activationRoot',
  'mkdirSync(runDir',
  'mkdirSync(proofDir',
  'runRuntimeChild(configPath',
  'writeJson(publicRecognitionPath',
]) {
  const sideEffectIndex = runSource.indexOf(call);
  assert(
    `authority refusal precedes ${call}`,
    sideEffectIndex >= 0 && refusalIndex < sideEffectIndex,
    `refusalIndex=${refusalIndex} sideEffectIndex=${sideEffectIndex}`
  );
}

console.log(`\nResults: ${PASS}/${TOTAL} passed${FAIL ? `, ${FAIL} failed` : ''}`);
if (FAIL) {
  process.exit(1);
}
