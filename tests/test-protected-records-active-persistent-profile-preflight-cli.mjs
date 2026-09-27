#!/usr/bin/env node

import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
  PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_SOURCE_PREFLIGHT_TYPE,
  assertActivePersistentProfileCloseout,
  assertActivePersistentProfileSourcePreflight,
  assertActivePersistentProfileSourceStatus,
  buildActivePersistentProfileSourceManifest,
  runActivePersistentProfileSourcePreflight,
} from '../lib/protected-records-active-persistent-profile-preflight.mjs';
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

function section(title) {
  console.log(`\n-- ${title} --`);
}

function runCli(args) {
  return spawnSync(process.execPath, ['bin/zlar-protected-records-active-persistent-profile-preflight', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });
}

function runMainCli(args) {
  return spawnSync('bin/zlar', ['protected-records-active-persistent-profile-preflight', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });
}

function requiredArgs(scratch) {
  return [
    '--surrogate-root', scratch,
    '--activation-root', join(scratch, 'activation', 'protected-records-private-operator-records-terminal'),
    '--proof-target', join(scratch, 'proof', 'records-target.jsonl'),
    '--profile', './profiles/protected-records-runtime-fixture.profile.json',
    '--runtime-profile-id', 'protected-records-disposable-runtime-profile',
    '--runtime-profile-sha256', ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    '--expires-at', '2030-01-01T00:00:00.000Z',
    '--now-epoch', '1700000000',
  ];
}

function prepareRoot(scratch) {
  mkdirSync(join(scratch, 'activation', 'protected-records-private-operator-records-terminal'), { recursive: true });
  mkdirSync(join(scratch, 'proof'), { recursive: true });
  writeFileSync(join(scratch, 'proof', 'records-target.jsonl'), '');
}

const scratch = mkdtempSync(join(tmpdir(), 'zlar-active-persistent-source-preflight-cli-test-'));
const realActivationRoot = join(
  homedir(),
  '.zlar',
  'protected-records',
  'deployments',
  'protected-records-private-operator-records-terminal'
);
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY|~\/\.zlar/i;

try {
  prepareRoot(scratch);

  section('json report command');
  const reportPath = join(scratch, 'reports', 'active-persistent-source-preflight.json');
  const jsonRun = runCli([...requiredArgs(scratch), '--json', '--report', reportPath]);
  assertEqual('json run exits zero', 0, jsonRun.status);
  assert('json stdout privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(jsonRun.stdout));
  assert('json stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(jsonRun.stderr));
  assert('json stdout omits raw paths and key material', !unsafeOutputPattern.test(jsonRun.stdout));
  assert('report file written', existsSync(reportPath));
  const reportFileText = readFileSync(reportPath, 'utf8');
  assert('report file privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(reportFileText));
  assert('report file omits raw paths and key material', !unsafeOutputPattern.test(reportFileText));
  const report = JSON.parse(reportFileText);
  assert('report validates from file', assertActivePersistentProfileSourcePreflight(report));
  assertEqual('report type from file', PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_SOURCE_PREFLIGHT_TYPE, report.report_type);
  assertEqual('report has no activation claim', false, report.claim_boundary.active_persistent_runtime_profile_installation);
  assertEqual('report preserves launcher authority grant requirement', true, report.runtime_profile_contract.authority_grant_contract_required_from_launcher);
  assertEqual('report preserves same-process signed payload replay case', true, report.runtime_profile_contract.same_process_signed_payload_replay_case_required);
  assertEqual('report preserves restart consumed grant refusal case', true, report.runtime_profile_contract.restart_consumed_authority_grant_refusal_case_required);
  assertEqual('report refuses request-stream authority material', false, report.runtime_profile_contract.request_stream_authority_material_accepted);
  assertEqual('report names burn window', true, report.runtime_profile_contract.partial_grant_commit_burn_window_named);
  assertEqual('report does not claim joint rollback detection', false, report.runtime_profile_contract.store_anchor_and_witness_joint_rollback_detection);
  assertEqual('report does not evidence fixture rightful issuance', false, report.claim_boundary.fixture_rightful_issuance_path_evidenced);
  assertEqual('report does not prove rightful issuance', false, report.claim_boundary.rightful_issuance_proven);
  assertEqual('report does not close consequence lifecycle', false, report.claim_boundary.consequence_lifecycle_closed);
  assert('report activation label is surrogate-contained', report.path_boundary.activation_root_label.startsWith('<source-preflight-surrogate-root>/'));
  assert('report proof target label is surrogate-contained', report.path_boundary.proof_target_label.startsWith('<source-preflight-surrogate-root>/'));
  assert('stdout includes report sha', /report_sha256=[a-f0-9]{64}/.test(jsonRun.stdout));

  section('main dispatcher summary command');
  const summaryRun = runMainCli(requiredArgs(scratch));
  assertEqual('dispatcher exits zero', 0, summaryRun.status);
  assert('dispatcher stdout title', summaryRun.stdout.includes('ZLAR Active Persistent Profile Source Preflight v1'));
  assert('dispatcher stdout runtime grant contract', summaryRun.stdout.includes('consumption_identity=authority-grant-contract-sha256'));
  assert('dispatcher stdout rightful issuance ceiling', summaryRun.stdout.includes('fixture_path_evidenced=false') && summaryRun.stdout.includes('rightful_issuance_proven=false'));
  assert('dispatcher stdout privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(summaryRun.stdout));
  assert('dispatcher stdout omits raw paths and key material', !unsafeOutputPattern.test(summaryRun.stdout));

  section('status command');
  const statusRun = runCli([
    'status',
    '--surrogate-root', scratch,
    '--activation-root', join(scratch, 'activation', 'protected-records-private-operator-records-terminal'),
    '--now-epoch', '1700000000',
    '--json',
  ]);
  assertEqual('status exits zero', 0, statusRun.status);
  assert('status stdout privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(statusRun.stdout));
  const status = JSON.parse(statusRun.stdout);
  assert('status validates', assertActivePersistentProfileSourceStatus(status));
  assertEqual('status safe true', true, status.safe_for_source_preflight);

  const activeRoot = join(scratch, 'existing-active-root', 'protected-records-private-operator-records-terminal');
  mkdirSync(activeRoot, { recursive: true });
  writeFileSync(join(activeRoot, 'active-persistent-profile-manifest.json'), `${JSON.stringify({
    manifest_type: 'zlar-protected-records-active-persistent-profile-manifest-v1',
    status: 'active',
    expires_at: '2030-01-01T00:00:00.000Z',
  }, null, 2)}\n`);
  const activeStatusRun = runCli([
    'status',
    '--surrogate-root', scratch,
    '--activation-root', activeRoot,
    '--now-epoch', '1700000000',
    '--json',
  ]);
  assertEqual('active status exits zero', 0, activeStatusRun.status);
  const activeStatus = JSON.parse(activeStatusRun.stdout);
  assertEqual('active status safe false', false, activeStatus.safe_for_source_preflight);
  assertEqual('active status existing refused true', true, activeStatus.existing_active_root_refused);

  section('closeout command');
  const profile = JSON.parse(readFileSync('profiles/protected-records-runtime-fixture.profile.json', 'utf8'));
  const sourceReport = runActivePersistentProfileSourcePreflight({
    surrogateRoot: scratch,
    activationRoot: join(scratch, 'activation', 'protected-records-private-operator-records-terminal'),
    proofTarget: join(scratch, 'proof', 'records-target.jsonl'),
    profile,
    profileSource: 'profiles/protected-records-runtime-fixture.profile.json',
    runtimeProfileId: 'protected-records-disposable-runtime-profile',
    runtimeProfileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    expiresAt: '2030-01-01T00:00:00.000Z',
    nowEpoch: 1700000000,
  });
  const manifest = buildActivePersistentProfileSourceManifest(sourceReport);
  const manifestPath = join(scratch, 'manifest.json');
  const closeoutPath = join(scratch, 'closeout.json');
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  const closeoutRun = runCli([
    'closeout',
    '--manifest', manifestPath,
    '--closed-at', '2030-01-01T00:10:00.000Z',
    '--reason', 'operator_closeout',
    '--output', closeoutPath,
    '--json',
  ]);
  assertEqual('closeout exits zero', 0, closeoutRun.status);
  assert('closeout stdout privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(closeoutRun.stdout));
  assert('closeout file written', existsSync(closeoutPath));
  const closeout = JSON.parse(readFileSync(closeoutPath, 'utf8'));
  assert('closeout validates', assertActivePersistentProfileCloseout(closeout));
  assertEqual('closeout active false', false, closeout.active);
  assert('closeout stdout includes sha', /closeout_sha256=[a-f0-9]{64}/.test(closeoutRun.stdout));

  section('cli refusal paths');
  const latestRun = runCli([...requiredArgs(scratch), '--latest']);
  assert('latest run exits nonzero', latestRun.status !== 0);
  assert('latest stderr says not accepted', latestRun.stderr.includes('--latest is not accepted'));
  assert('latest stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(latestRun.stderr));

  const missingExpiryArgs = requiredArgs(scratch);
  const expiryIndex = missingExpiryArgs.indexOf('--expires-at');
  missingExpiryArgs.splice(expiryIndex, 2);
  const missingExpiryRun = runCli(missingExpiryArgs);
  assert('missing expiry exits nonzero', missingExpiryRun.status !== 0);
  assert('missing expiry stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(missingExpiryRun.stderr));

  const expiredRun = runCli([
    ...requiredArgs(scratch).slice(0, -4),
    '--expires-at', '2020-01-01T00:00:00.000Z',
    '--now-epoch', '1700000000',
  ]);
  assert('expired run exits nonzero', expiredRun.status !== 0);
  assert('expired stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(expiredRun.stderr));

  const movingProfileRun = runCli([
    ...requiredArgs(scratch).slice(0, 6),
    '--profile', 'profiles/latest.profile.json',
    '--runtime-profile-id', 'protected-records-disposable-runtime-profile',
    '--runtime-profile-sha256', ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    '--expires-at', '2030-01-01T00:00:00.000Z',
    '--now-epoch', '1700000000',
  ]);
  assert('moving profile run exits nonzero', movingProfileRun.status !== 0);
  assert('moving profile stderr names canonical artifact', movingProfileRun.stderr.includes('canonical runtime profile artifact'));
  assert('moving profile stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(movingProfileRun.stderr));

  const wrongActivationArgs = requiredArgs(scratch);
  wrongActivationArgs[wrongActivationArgs.indexOf('--activation-root') + 1] = join(scratch, 'activation', 'wrong-profile');
  const wrongActivationRun = runCli(wrongActivationArgs);
  assert('wrong activation root basename exits nonzero', wrongActivationRun.status !== 0);
  assert('wrong activation stderr names profile id requirement', wrongActivationRun.stderr.includes('named deployment profile id'));
  assert('wrong activation stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(wrongActivationRun.stderr));

  const realRootReportRun = runCli([
    ...requiredArgs(scratch),
    '--report', join(realActivationRoot, 'source-preflight.json'),
  ]);
  assert('real-root report output exits nonzero', realRootReportRun.status !== 0);
  assert('real-root report stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(realRootReportRun.stderr));
  assert('real-root report stderr omits raw paths', !unsafeOutputPattern.test(realRootReportRun.stderr));

  const realRootAlias = join(scratch, 'real-root-alias');
  symlinkSync(realActivationRoot, realRootAlias);
  const symlinkRootReportRun = runCli([
    ...requiredArgs(scratch),
    '--report', join(realRootAlias, 'source-preflight.json'),
  ]);
  assert('symlink real-root report output exits nonzero', symlinkRootReportRun.status !== 0);
  assert('symlink real-root report stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(symlinkRootReportRun.stderr));
  assert('symlink real-root report stderr omits raw paths', !unsafeOutputPattern.test(symlinkRootReportRun.stderr));

  const realRootManifestRun = runCli([
    'closeout',
    '--manifest', join(realActivationRoot, 'manifest.json'),
    '--closed-at', '2030-01-01T00:10:00.000Z',
    '--reason', 'operator_closeout',
    '--json',
  ]);
  assert('real-root manifest input exits nonzero', realRootManifestRun.status !== 0);
  assert('real-root manifest stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(realRootManifestRun.stderr));
  assert('real-root manifest stderr omits raw paths', !unsafeOutputPattern.test(realRootManifestRun.stderr));

  const symlinkRootManifestRun = runCli([
    'closeout',
    '--manifest', join(realRootAlias, 'manifest.json'),
    '--closed-at', '2030-01-01T00:10:00.000Z',
    '--reason', 'operator_closeout',
    '--json',
  ]);
  assert('symlink real-root manifest input exits nonzero', symlinkRootManifestRun.status !== 0);
  assert('symlink real-root manifest stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(symlinkRootManifestRun.stderr));
  assert('symlink real-root manifest stderr omits raw paths', !unsafeOutputPattern.test(symlinkRootManifestRun.stderr));

  const realRootCloseoutRun = runCli([
    'closeout',
    '--manifest', manifestPath,
    '--closed-at', '2030-01-01T00:10:00.000Z',
    '--reason', 'operator_closeout',
    '--output', join(realActivationRoot, 'closeout.json'),
    '--json',
  ]);
  assert('real-root closeout output exits nonzero', realRootCloseoutRun.status !== 0);
  assert('real-root closeout stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(realRootCloseoutRun.stderr));
  assert('real-root closeout stderr omits raw paths', !unsafeOutputPattern.test(realRootCloseoutRun.stderr));

  const symlinkRootCloseoutRun = runCli([
    'closeout',
    '--manifest', manifestPath,
    '--closed-at', '2030-01-01T00:10:00.000Z',
    '--reason', 'operator_closeout',
    '--output', join(realRootAlias, 'closeout.json'),
    '--json',
  ]);
  assert('symlink real-root closeout output exits nonzero', symlinkRootCloseoutRun.status !== 0);
  assert('symlink real-root closeout stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(symlinkRootCloseoutRun.stderr));
  assert('symlink real-root closeout stderr omits raw paths', !unsafeOutputPattern.test(symlinkRootCloseoutRun.stderr));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(`\nResults: ${PASS}/${TOTAL} passed${FAIL ? `, ${FAIL} failed` : ''}`);
if (FAIL) {
  process.exit(1);
}
console.log('ALL PASS');
