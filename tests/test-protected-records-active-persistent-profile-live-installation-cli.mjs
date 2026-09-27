#!/usr/bin/env node

import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  ACTIVE_PERSISTENT_PROFILE_MANIFEST_FILE,
  ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
} from '../lib/protected-records-active-persistent-profile-preflight.mjs';
import {
  assertActivePersistentProfileLiveCloseout,
  assertActivePersistentProfileLiveInstallationReport,
  assertActivePersistentProfileLiveStatus,
  defaultActivePersistentProfileLiveRoot,
} from '../lib/protected-records-active-persistent-profile-live-installation.mjs';
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
  return spawnSync(process.execPath, ['bin/zlar-protected-records-active-persistent-profile-live-installation', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });
}

function runCliWithEnv(args, env) {
  return spawnSync(process.execPath, ['bin/zlar-protected-records-active-persistent-profile-live-installation', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
}

function runMainCli(args) {
  return spawnSync('bin/zlar', ['protected-records-active-persistent-profile-live-installation', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });
}

function activationRoot(scratch) {
  return join(scratch, 'activation', 'protected-records-private-operator-records-terminal');
}

function installArgs(scratch) {
  return [
    'install',
    '--activation-root', activationRoot(scratch),
    '--profile', 'profiles/protected-records-runtime-fixture.profile.json',
    '--runtime-profile-id', 'protected-records-disposable-runtime-profile',
    '--runtime-profile-sha256', ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    '--expires-at', '2030-01-01T00:00:00.000Z',
    '--now-epoch', '1700000000',
  ];
}

function parseJsonWithTrailingReportSha(text) {
  return JSON.parse(text.replace(/report_written=true\nreport_sha256=[a-f0-9]{64}\n$/, ''));
}

const scratch = mkdtempSync(join(tmpdir(), 'zlar-active-persistent-live-cli-test-'));
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY|~\/\.zlar/i;

try {
  section('json install command');
  const reportPath = join(scratch, 'reports', 'active-persistent-live-installation.json');
  const installRun = runCli([...installArgs(scratch), '--json', '--report', reportPath]);
  assertEqual('install exits zero', 0, installRun.status);
  assertEqual('install stderr empty', '', installRun.stderr);
  assert('install stdout privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(installRun.stdout));
  assert('install stdout omits raw paths and key material', !unsafeOutputPattern.test(installRun.stdout));
  assert('report file written', existsSync(reportPath));
  const report = parseJsonWithTrailingReportSha(installRun.stdout);
  assert('stdout report validates', assertActivePersistentProfileLiveInstallationReport(report));
  const reportFromFile = JSON.parse(readFileSync(reportPath, 'utf8'));
  assert('file report validates', assertActivePersistentProfileLiveInstallationReport(reportFromFile));
  assertEqual('report active true', true, report.active_after_proof);
  assertEqual('report final active until expiry', 'active_until_expiry', report.final_root_state);
  assertEqual('report launcher grant requirement true', true, report.runtime_profile_contract.authority_grant_contract_required_from_launcher);
  assertEqual('report authority grant readback true', true, report.readback_preflight.authority_grant_requirement_preserved);
  assertEqual('report rightful issuance readback false', false, report.readback_preflight.rightful_issuance_proven);
  assertEqual('report burn proof false at installation', false, report.readback_preflight.partial_grant_commit_burn_window_proven);
  assertEqual('report fixture rightful path claim false', false, report.claim_boundary.fixture_rightful_issuance_path_evidenced);
  assertEqual('report rightful issuance claim false', false, report.claim_boundary.rightful_issuance_proven);
  assertEqual('report consequence lifecycle claim false', false, report.claim_boundary.consequence_lifecycle_closed);

  section('main dispatcher status command');
  const statusRun = runMainCli([
    'status',
    '--activation-root', activationRoot(scratch),
    '--now-epoch', '1700000000',
    '--json',
  ]);
  assertEqual('status exits zero', 0, statusRun.status);
  assertEqual('status stderr empty', '', statusRun.stderr);
  assert('status stdout privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(statusRun.stdout));
  assert('status stdout omits raw paths', !unsafeOutputPattern.test(statusRun.stdout));
  const status = JSON.parse(statusRun.stdout);
  assert('status validates', assertActivePersistentProfileLiveStatus(status));
  assertEqual('status active', true, status.active);
  assertEqual('status safe for install false', false, status.safe_for_install);

  section('summary command');
  const summaryScratch = mkdtempSync(join(tmpdir(), 'zlar-active-persistent-live-cli-summary-'));
  const summaryRun = runMainCli(installArgs(summaryScratch));
  assertEqual('summary install exits zero', 0, summaryRun.status);
  assert('summary title present', summaryRun.stdout.includes('ZLAR Active Persistent Profile Live Installation Proof v1'));
  assert('summary includes final state', summaryRun.stdout.includes('final_root_state=active_until_expiry'));
  assert('summary includes authority grant readback', summaryRun.stdout.includes('requirement_preserved=true') && summaryRun.stdout.includes('rightful_issuance_proven=false'));
  assert('summary includes rightful issuance ceiling', summaryRun.stdout.includes('fixture_path_evidenced=false') && summaryRun.stdout.includes('consequence_lifecycle_closed=false'));
  assert('summary privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(summaryRun.stdout));
  assert('summary omits raw paths', !unsafeOutputPattern.test(summaryRun.stdout));
  rmSync(summaryScratch, { recursive: true, force: true });

  section('closeout command');
  const closeoutRun = runCli([
    'closeout',
    '--activation-root', activationRoot(scratch),
    '--closed-at', '2030-01-01T00:10:00.000Z',
    '--reason', 'operator_closeout',
    '--now-epoch', '1700000000',
    '--json',
  ]);
  assertEqual('closeout exits zero', 0, closeoutRun.status);
  assertEqual('closeout stderr empty', '', closeoutRun.stderr);
  assert('closeout stdout privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(closeoutRun.stdout));
  assert('closeout stdout omits raw paths', !unsafeOutputPattern.test(closeoutRun.stdout));
  const closeout = JSON.parse(closeoutRun.stdout);
  assert('closeout validates', assertActivePersistentProfileLiveCloseout(closeout));
  assertEqual('closeout status inert', 'closed_inert_evidence', closeout.status);
  assertEqual('closeout active false', false, closeout.active);

  section('cli refusal paths');
  const secondInstallRun = runCli([...installArgs(scratch), '--json']);
  assert('second install exits nonzero', secondInstallRun.status !== 0);
  assert('second install stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(secondInstallRun.stderr));
  assert('second install stderr omits raw paths', !unsafeOutputPattern.test(secondInstallRun.stderr));

  const replaceClosedRun = runCli([...installArgs(scratch), '--replace-closed-root', '--json']);
  assertEqual('replace closed root exits zero', 0, replaceClosedRun.status);
  assertEqual('replace closed root stderr empty', '', replaceClosedRun.stderr);
  assert('replace closed root stdout privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(replaceClosedRun.stdout));
  const replacementReport = JSON.parse(replaceClosedRun.stdout);
  assert('replace closed root report validates', assertActivePersistentProfileLiveInstallationReport(replacementReport));
  assertEqual('replace closed root preinstall replacement true', true, replacementReport.preinstall_status.closed_root_replacement_authorized);
  assertEqual('replace closed root write boundary true', true, replacementReport.write_boundary.closed_root_replaced_by_explicit_authority);
  assertEqual('replace closed root prior status closed', 'closed_inert_evidence', replacementReport.preinstall_status.activation_root_state);

  const latestRun = runCli([...installArgs(mkdtempSync(join(tmpdir(), 'zlar-active-persistent-latest-'))), '--latest']);
  assert('latest exits nonzero', latestRun.status !== 0);
  assert('latest stderr names selector boundary', latestRun.stderr.includes('--latest is not accepted'));
  assert('latest stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(latestRun.stderr));

  const missingExpiryScratch = mkdtempSync(join(tmpdir(), 'zlar-active-persistent-missing-expiry-'));
  const missingExpiryArgs = installArgs(missingExpiryScratch);
  const expiryIndex = missingExpiryArgs.indexOf('--expires-at');
  missingExpiryArgs.splice(expiryIndex, 2);
  const missingExpiryRun = runCli(missingExpiryArgs);
  assert('missing expiry exits nonzero', missingExpiryRun.status !== 0);
  assert('missing expiry stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(missingExpiryRun.stderr));

  const realRootStatusRun = runCli([
    'status',
    '--activation-root', defaultActivePersistentProfileLiveRoot(),
    '--now-epoch', '1700000000',
    '--json',
  ]);
  assert('real root without flag exits nonzero', realRootStatusRun.status !== 0);
  assert('real root without flag says explicit authority', realRootStatusRun.stderr.includes('requires explicit --allow-named-live-root'));
  assert('real root without flag stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(realRootStatusRun.stderr));
  assert('real root without flag stderr omits raw paths', !unsafeOutputPattern.test(realRootStatusRun.stderr));

  const wrongReportScratch = mkdtempSync(join(tmpdir(), 'zlar-active-persistent-report-refusal-'));
  mkdirSync(activationRoot(wrongReportScratch), { recursive: true });
  const activationReportRun = runCli([
    ...installArgs(wrongReportScratch),
    '--report', join(activationRoot(wrongReportScratch), 'report.json'),
  ]);
  assert('activation-root report exits nonzero', activationReportRun.status !== 0);
  assert('activation-root report stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(activationReportRun.stderr));
  assert('activation-root report stderr omits raw paths', !unsafeOutputPattern.test(activationReportRun.stderr));
  assert('activation-root report refusal writes no manifest', !existsSync(join(activationRoot(wrongReportScratch), ACTIVE_PERSISTENT_PROFILE_MANIFEST_FILE)));
  assert('activation-root report refusal writes no active index', !existsSync(join(activationRoot(wrongReportScratch), 'active-runtime-profile.json')));
  const activationReportAliasScratch = mkdtempSync(join(tmpdir(), 'zlar-active-persistent-report-alias-refusal-'));
  mkdirSync(activationRoot(activationReportAliasScratch), { recursive: true });
  const reportAlias = join(activationReportAliasScratch, 'activation-report-alias');
  symlinkSync(activationRoot(activationReportAliasScratch), reportAlias);
  const activationAliasReportRun = runCli([
    ...installArgs(activationReportAliasScratch),
    '--report', join(reportAlias, 'report.json'),
  ]);
  assert('activation-root report symlink exits nonzero', activationAliasReportRun.status !== 0);
  assert('activation-root report symlink stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(activationAliasReportRun.stderr));
  assert('activation-root report symlink stderr omits raw paths', !unsafeOutputPattern.test(activationAliasReportRun.stderr));
  assert('activation-root report symlink refusal writes no manifest', !existsSync(join(activationRoot(activationReportAliasScratch), ACTIVE_PERSISTENT_PROFILE_MANIFEST_FILE)));
  assert('activation-root report symlink refusal writes no active index', !existsSync(join(activationRoot(activationReportAliasScratch), 'active-runtime-profile.json')));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(`\nResults: ${PASS}/${TOTAL} passed${FAIL ? `, ${FAIL} failed` : ''}`);
if (FAIL) {
  process.exit(1);
}
console.log('ALL PASS');
