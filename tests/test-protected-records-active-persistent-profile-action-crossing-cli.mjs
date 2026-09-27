#!/usr/bin/env node

import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
  ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
} from '../lib/protected-records-active-persistent-profile-preflight.mjs';
import {
  defaultActivePersistentProfileLiveRoot,
  runActivePersistentProfileLiveInstallation,
} from '../lib/protected-records-active-persistent-profile-live-installation.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH,
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
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
    console.error(`  FAIL: ${label}${detail ? ` (${detail})` : ''}`);
  }
}

const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY|~\/\.zlar/i;
const ZLAR = join(process.cwd(), 'bin', 'zlar');

function runCli(args, { home } = {}) {
  return spawnSync(ZLAR, ['protected-records-active-persistent-profile-action-crossing', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: home
      ? { ...process.env, HOME: home, NO_COLOR: '1' }
      : { ...process.env, NO_COLOR: '1' },
  });
}

function baseArgs(scratch, activationRoot = defaultActivePersistentProfileLiveRoot()) {
  return [
    '--activation-root', activationRoot,
    '--expected-profile', 'profiles/protected-records-runtime-fixture.profile.json',
    '--profile-id', 'protected-records-runtime-fixture-profile',
    '--profile-sha256', ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    '--proof-target', join(scratch, 'target.jsonl'),
    '--json',
  ];
}

const scratch = mkdtempSync(join(tmpdir(), 'zlar-active-action-crossing-cli-'));
try {
  console.log('\n-- cli positive crossing on fake HOME root --');
  const fakeHome = join(scratch, 'fake-home');
  const fakeNamedRoot = join(
    fakeHome,
    '.zlar',
    'protected-records',
    'deployments',
    'protected-records-private-operator-records-terminal'
  );
  const profile = JSON.parse(
    readFileSync(ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE, 'utf8')
  );
  const nowEpoch = Math.floor(Date.now() / 1000);
  runActivePersistentProfileLiveInstallation({
    activationRoot: fakeNamedRoot,
    profile,
    profileSource: ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
    runtimeProfileId: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    runtimeProfileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    expiresAt: new Date((nowEpoch + 3600) * 1000).toISOString(),
    nowEpoch: nowEpoch - 60,
    allowNamedLiveRoot: true,
    expectedLiveRoot: fakeNamedRoot,
  });
  const positiveTarget = join(scratch, 'positive', 'target.jsonl');
  const positiveReportPath = join(scratch, 'positive', 'report.json');
  const positiveArgs = baseArgs(scratch, fakeNamedRoot);
  positiveArgs[positiveArgs.indexOf('--proof-target') + 1] = positiveTarget;
  positiveArgs.push(
    '--allow-named-live-root',
    '--now-epoch', String(nowEpoch),
    '--report', positiveReportPath
  );
  const positive = runCli(positiveArgs, { home: fakeHome });
  assert('positive fake-HOME crossing exits zero', positive.status === 0, positive.stderr);
  assert('positive stdout privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(positive.stdout));
  assert('positive stdout omits raw paths', !unsafeOutputPattern.test(positive.stdout));
  assert('positive target written once', existsSync(positiveTarget) && readFileSync(positiveTarget, 'utf8').trim().split('\n').length === 1);
  assert('positive report written', existsSync(positiveReportPath));
  const positiveReport = JSON.parse(readFileSync(positiveReportPath, 'utf8'));
  assert('positive action status uses action epoch', positiveReport.evaluation_time_contract.active_root_status_epoch === nowEpoch);
  assert('positive service authority uses fixture epoch', positiveReport.evaluation_time_contract.local_service_authority_evaluation_epoch === PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH);
  assert('positive fixture epoch is not live authority time', positiveReport.evaluation_time_contract.fixture_epoch_is_not_live_authority_time === true);
  assert('positive fresh service artifact identity pin matched', positiveReport.service_crossing.artifact_identity_expected_sha256_supplied === true && positiveReport.service_crossing.artifact_identity_sha256_matched === true && positiveReport.service_crossing.expected_artifact_body_sha256 === positiveReport.hashes.service_artifact_body_sha256);
  assert('positive embedded identities bound through fresh artifact pin', positiveReport.service_crossing.source_preflight_identity_bound_to_expected_artifact_sha256 === true && positiveReport.service_crossing.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256 === true);
  assert('positive fixture rightful path only', positiveReport.claim_boundary.fixture_authority_grant_path_evidenced === true && positiveReport.claim_boundary.rightful_issuance_proven === false);

  console.log('\n-- cli refusal paths --');
  const latestRun = runCli([...baseArgs(scratch), '--latest']);
  assert('latest exits nonzero', latestRun.status !== 0);
  assert('latest names selector boundary', latestRun.stderr.includes('--latest is not accepted'));
  assert('latest stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(latestRun.stderr));
  assert('latest stderr omits raw paths', !unsafeOutputPattern.test(latestRun.stderr));

  const missingProofTarget = runCli(baseArgs(scratch).filter((_, index, args) =>
    args[index - 1] !== '--proof-target' && args[index] !== '--proof-target'
  ));
  assert('missing proof target exits nonzero', missingProofTarget.status !== 0);
  assert('missing proof target names requirement', missingProofTarget.stderr.includes('--proof-target'));
  assert('missing proof target stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(missingProofTarget.stderr));

  const wrongProfileIdArgs = baseArgs(scratch);
  wrongProfileIdArgs[wrongProfileIdArgs.indexOf('--profile-id') + 1] = 'wrong-profile';
  const wrongProfileId = runCli(wrongProfileIdArgs);
  assert('wrong profile id exits nonzero', wrongProfileId.status !== 0);
  assert('wrong profile id names expected profile', wrongProfileId.stderr.includes('protected-records-runtime-fixture-profile'));
  assert('wrong profile id stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(wrongProfileId.stderr));

  const noAuthority = runCli(baseArgs(scratch));
  assert('real named root without flag exits nonzero', noAuthority.status !== 0);
  assert('real named root without flag names explicit authority', noAuthority.stderr.includes('requires explicit --allow-named-live-root'));
  assert('real named root without flag stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(noAuthority.stderr));
  assert('real named root without flag stderr omits raw paths', !unsafeOutputPattern.test(noAuthority.stderr));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(`\nResults: ${PASS}/${TOTAL} passed${FAIL ? `, ${FAIL} failed` : ''}`);
if (FAIL) process.exit(1);
console.log('ALL PASS');
