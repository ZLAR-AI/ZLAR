#!/usr/bin/env node

import {
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_TYPE,
  assertCurrentMachineApprovalRequestPreviewReport,
} from '../lib/current-machine-approval-request-preview.mjs';
import { runCurrentMachineApprovalIntake } from '../lib/current-machine-approval-intake.mjs';

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
const SAMPLE_PACKET_PATH = 'tests/fixtures/current-machine-approval-packet-claude-code-v1.json';
const SAMPLE_PACKET_SHA256 = '7012e6e6bb8e89358363ce073422bb74f30ee63af50be5870eace96e6f672e68';
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|BEGIN [A-Z ]*KEY/i;
const scratch = mkdtempSync(join(tmpdir(), 'zlar-current-machine-approval-request-preview-cli-'));

function runZlar(args, options = {}) {
  return spawnSync(ZLAR_BIN, args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    input: options.input,
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

try {
  const intakeReport = runCurrentMachineApprovalIntake({ packetPath: SAMPLE_PACKET_PATH });
  const intakePath = join(scratch, 'valid-intake.json');
  writeFileSync(intakePath, `${JSON.stringify(intakeReport, null, 2)}\n`);

  section('valid intake report command');
  const textRun = runZlar(['current-machine-approval-request-preview', '--intake', intakePath]);
  assertEqual('text run exits zero', 0, textRun.status);
  assertEqual('text run emits no stderr', '', textRun.stderr);
  assert('text run title present', textRun.stdout.includes('ZLAR Current-Machine Approval Request Preview v1'));
  assert('text run preview can be prepared', textRun.stdout.includes('preview_can_be_prepared=true'));
  assert('text run authority request not made', textRun.stdout.includes('authority_request_made=false'));
  assert('text run no install authority', textRun.stdout.includes('install_authority_granted=false'));
  assert('text run no human approval', textRun.stdout.includes('human_approval_granted=false'));
  assert('text run selected surface preserved', textRun.stdout.includes('selected_surface=claude_code'));
  assert('text run delegation target preserved', textRun.stdout.includes('delegation_target=~/.zlar/bin/zlar-gate'));
  assert('text run source target preserved', textRun.stdout.includes('source_target:'));
  assert('text run installer identity preserved', textRun.stdout.includes('installer_identity:'));
  assert('text run command posture preserved', textRun.stdout.includes('command_posture:'));
  assert('text run dry-run plan identity preserved', textRun.stdout.includes('dry_run_plan_identity:'));
  assert('text run authority request identity preserved', textRun.stdout.includes('authority_request_identity:'));
  assert('text run backup rollback preserved', textRun.stdout.includes('backup_rollback:'));
  assert('text run sha preserved', textRun.stdout.includes(SAMPLE_PACKET_SHA256));
  assert('text run states not install authority', textRun.stdout.includes('This preview is not install authority.'));
  assert('text run states not approval', textRun.stdout.includes('This preview is not an approval.'));
  assert('text run privacy safe', !unsafeOutputPattern.test(textRun.stdout));

  const jsonRun = runZlar(['current-machine-approval-request-preview', '--intake', intakePath, '--json']);
  assertEqual('json run exits zero', 0, jsonRun.status);
  assertEqual('json run emits no stderr', '', jsonRun.stderr);
  assert('json run privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
  const report = JSON.parse(jsonRun.stdout);
  assert('json report validates', assertCurrentMachineApprovalRequestPreviewReport(report));
  assertEqual('json report type', CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_TYPE, report.preview_type);
  assertEqual('json report preview can be prepared', true, report.preview_can_be_prepared);
  assertEqual('json report authority request not made', false, report.authority_request_made);
  assertEqual('json report install authority false', false, report.install_authority_granted);
  assertEqual('json report human approval false', false, report.human_approval_granted);
  assertEqual('json report packet verification complete', true, report.packet_verification_complete);
  assertEqual('json report packet sha stable', SAMPLE_PACKET_SHA256, report.intake_packet_sha256);
  assertEqual('json report source target commit', 'b89b0c2e2d79db4981cad69af4a190e9c77fb089', report.source_target.target_commit_sha);
  assertEqual('json report delegation target', '~/.zlar/bin/zlar-gate', report.hook_target.delegation_target);
  assertEqual('json report command posture mode', 'repair', report.command_posture.existing_install_mode);

  section('stdin command');
  const stdinRun = runZlar(['current-machine-approval-request-preview', '--intake', '-', '--json'], {
    input: `${JSON.stringify(intakeReport, null, 2)}\n`,
  });
  assertEqual('stdin exits zero', 0, stdinRun.status);
  assertEqual('stdin emits no stderr', '', stdinRun.stderr);
  const stdinReport = JSON.parse(stdinRun.stdout);
  assert('stdin report validates', assertCurrentMachineApprovalRequestPreviewReport(stdinReport));
  assertEqual('stdin report can prepare', true, stdinReport.preview_can_be_prepared);
  assertEqual('stdin report authority request not made', false, stdinReport.authority_request_made);

  section('invalid intake reports refuse');
  const refusedIntake = structuredClone(intakeReport);
  refusedIntake.authority_request_allowed = false;
  refusedIntake.intake_status = 'refused_before_authority_request';
  refusedIntake.refusal_reason_code = 'packet_verification_failed';
  refusedIntake.refusal_summary = 'forced refusal fixture';
  const refusedIntakePath = join(scratch, 'refused-intake.json');
  writeFileSync(refusedIntakePath, `${JSON.stringify(refusedIntake, null, 2)}\n`);
  const refusedRun = runZlar(['current-machine-approval-request-preview', '--intake', refusedIntakePath, '--json']);
  assert('refused intake exits nonzero', refusedRun.status !== 0);
  assertEqual('refused intake emits no stderr', '', refusedRun.stderr);
  assert('refused intake stdout privacy safe', !unsafeOutputPattern.test(refusedRun.stdout));
  const refusedReport = JSON.parse(refusedRun.stdout);
  assert('refused report validates', assertCurrentMachineApprovalRequestPreviewReport(refusedReport));
  assertEqual('refused report cannot prepare', false, refusedReport.preview_can_be_prepared);
  assertEqual('refused report authority request not made', false, refusedReport.authority_request_made);
  assertEqual('refused report no install authority', false, refusedReport.install_authority_granted);
  assertEqual('refused report no human approval', false, refusedReport.human_approval_granted);

  const madeRequest = structuredClone(intakeReport);
  madeRequest.authority_request_made = true;
  const madeRequestPath = join(scratch, 'made-request.json');
  writeFileSync(madeRequestPath, `${JSON.stringify(madeRequest, null, 2)}\n`);
  const madeRequestRun = runZlar(['current-machine-approval-request-preview', '--intake', madeRequestPath]);
  assert('made request exits nonzero', madeRequestRun.status !== 0);
  assertEqual('made request emits no stderr', '', madeRequestRun.stderr);
  assert('made request stdout refuses preview', madeRequestRun.stdout.includes('preview_can_be_prepared=false'));
  assert('made request stdout says no authority request made', madeRequestRun.stdout.includes('authority_request_made=false'));
  assert('made request stdout no install authority', madeRequestRun.stdout.includes('install_authority_granted=false'));

  const liveHook = structuredClone(intakeReport);
  liveHook.no_write_boundary.live_hook_execution_evidence = true;
  const liveHookPath = join(scratch, 'live-hook.json');
  writeFileSync(liveHookPath, `${JSON.stringify(liveHook, null, 2)}\n`);
  const liveHookRun = runZlar(['current-machine-approval-request-preview', '--intake', liveHookPath, '--json']);
  assert('live hook claim exits nonzero', liveHookRun.status !== 0);
  assertEqual('live hook claim emits no stderr', '', liveHookRun.stderr);
  const liveHookReport = JSON.parse(liveHookRun.stdout);
  assert('live hook report validates', assertCurrentMachineApprovalRequestPreviewReport(liveHookReport));
  assertEqual('live hook report refuses', false, liveHookReport.preview_can_be_prepared);
  assertEqual('live hook evidence not carried', false, liveHookReport.no_authority_boundary.live_hook_execution_evidence);

  const unparseablePath = join(scratch, 'unparseable.json');
  writeFileSync(unparseablePath, '{');
  const unparseableRun = runZlar(['current-machine-approval-request-preview', '--intake', unparseablePath, '--json']);
  assert('unparseable exits nonzero', unparseableRun.status !== 0);
  assertEqual('unparseable emits no stderr', '', unparseableRun.stderr);
  const unparseableReport = JSON.parse(unparseableRun.stdout);
  assert('unparseable report validates', assertCurrentMachineApprovalRequestPreviewReport(unparseableReport));
  assertEqual('unparseable report refuses', false, unparseableReport.preview_can_be_prepared);
  assertEqual('unparseable reason', 'intake_report_unparseable', unparseableReport.refusal_reason_code);

  section('help and argument handling');
  const helpRun = runZlar(['current-machine-approval-request-preview', '--help']);
  assertEqual('help exits zero', 0, helpRun.status);
  assertEqual('help emits no stdout', '', helpRun.stdout);
  assert('help names usage', helpRun.stderr.includes('Usage: zlar current-machine-approval-request-preview --intake <file|-> [--json]'));
  assert('help states refusal conditions', helpRun.stderr.includes('authority_request_allowed=true'));
  assert('help states not install authority', helpRun.stderr.includes('not install authority'));
  assert('help states not approval', helpRun.stderr.includes('not an approval'));
  assert('help states no current-machine governance', helpRun.stderr.includes('does not prove current-machine governance'));

  const missingIntake = runZlar(['current-machine-approval-request-preview']);
  assert('missing intake exits nonzero', missingIntake.status !== 0);
  assertEqual('missing intake emits no stdout', '', missingIntake.stdout);
  assert('missing intake names missing intake', missingIntake.stderr.includes('Missing required --intake <file|->'));

  const missingIntakeValue = runZlar(['current-machine-approval-request-preview', '--intake']);
  assert('missing intake value exits nonzero', missingIntakeValue.status !== 0);
  assertEqual('missing intake value emits no stdout', '', missingIntakeValue.stdout);
  assert('missing intake value names missing value', missingIntakeValue.stderr.includes('Missing value for --intake'));

  const unsupported = runZlar(['current-machine-approval-request-preview', '--intake', intakePath, '--sample']);
  assert('unsupported option exits nonzero', unsupported.status !== 0);
  assertEqual('unsupported option emits no stdout', '', unsupported.stdout);
  assert('unsupported option names unsupported option', unsupported.stderr.includes('Unsupported current-machine approval request preview option provided'));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

if (FAIL > 0) {
  console.log(`\nResults: ${PASS}/${TOTAL} passed`);
  console.log(`\nFAIL: ${FAIL}/${TOTAL} assertions failed`);
  process.exit(1);
}

console.log(`\nResults: ${PASS}/${TOTAL} passed`);
console.log(`\nPASS: ${PASS}/${TOTAL} assertions passed`);
