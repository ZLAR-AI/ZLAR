#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import {
  assertProtectedRecordsNamedDeploymentProfileReadiness,
} from '../lib/protected-records-named-deployment-profile-readiness.mjs';
import {
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from '../lib/protected-records-runtime-profile.mjs';

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

console.log('\n-- text output --');
const textRun = runZlar(['protected-records-named-deployment-profile-readiness', '--sample']);
assertEqual('text run exits zero', 0, textRun.status);
assertEqual('text run emits no stderr', '', textRun.stderr);
assert('text output privacy safe', !unsafeOutputPattern.test(textRun.stdout));
assert('text summary validates safe text', assertNoUnsafeProtectedRecordsRuntimeProfileText(textRun.stdout));
assert('text summary title', textRun.stdout.includes('ZLAR Protected Records Named Deployment Profile Readiness v1'));
assert('text summary names pinned historical source', textRun.stdout.includes('source_mode=pinned-committed-historical-artifact-verification'));
assert('text summary names exact exhausted status', textRun.stdout.includes('authority_grant_status=exhausted'));
assert('text summary refuses fresh rightful projection', textRun.stdout.includes('fresh_fixture_rightful_projection_allowed=false'));
assert('text summary names missing receipt refused', textRun.stdout.includes('missing_receipt_refused=true'));
assert('text summary names active deployment false', textRun.stdout.includes('active_deployment_profile=false'));
assert('text summary names enterprise false', textRun.stdout.includes('enterprise_readiness=false'));

console.log('\n-- json output --');
const jsonRun = runZlar(['protected-records-named-deployment-profile-readiness', '--sample', '--json']);
assertEqual('json run exits zero', 0, jsonRun.status);
assertEqual('json run emits no stderr', '', jsonRun.stderr);
assert('json output privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report validates', assertProtectedRecordsNamedDeploymentProfileReadiness(report));
assertEqual('json terminal artifact identity matched', true, report.source_terminal_chain.terminal_artifact_identity_sha256_matched);
assertEqual('json fresh fixture-rightful projection false', false, report.source_terminal_chain.fresh_fixture_rightful_projection_allowed);
assertEqual('json local rehearsal only', true, report.claim_boundary.local_rehearsal_only);
assertEqual('json active deployment false', false, report.claim_boundary.active_deployment_profile);
assertEqual('json human authority crossing true', true, report.next_authority_crossing.human_authority_required);

console.log('\n-- fail closed CLI boundaries --');
const missingSampleRun = runZlar(['protected-records-named-deployment-profile-readiness', '--json']);
assert('missing sample exits nonzero', missingSampleRun.status !== 0);
assertEqual('missing sample emits no stdout', '', missingSampleRun.stdout);
assert('missing sample names sample requirement', missingSampleRun.stderr.includes('--sample is required'));
assert('missing sample stderr privacy safe', !unsafeOutputPattern.test(missingSampleRun.stderr));

const unknownArgRun = runZlar(['protected-records-named-deployment-profile-readiness', '--sample', '--profile', 'anything']);
assert('unknown arg exits nonzero', unknownArgRun.status !== 0);
assertEqual('unknown arg emits no stdout', '', unknownArgRun.stdout);
assert('unknown arg names unknown argument', unknownArgRun.stderr.includes('Unknown argument'));
assert('unknown arg stderr privacy safe', !unsafeOutputPattern.test(unknownArgRun.stderr));

console.log(`\nResults: ${PASS}/${TOTAL} passed${FAIL ? `, ${FAIL} failed` : ' ✓'}`);
if (FAIL) {
  process.exit(1);
}
