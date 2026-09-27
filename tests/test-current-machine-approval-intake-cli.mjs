#!/usr/bin/env node

import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  CURRENT_MACHINE_APPROVAL_INTAKE_TYPE,
  assertCurrentMachineApprovalIntakeReport,
} from '../lib/current-machine-approval-intake.mjs';

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
const packetText = readFileSync(SAMPLE_PACKET_PATH, 'utf8');
const packet = JSON.parse(packetText);
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|BEGIN [A-Z ]*KEY/i;
const scratch = mkdtempSync(join(tmpdir(), 'zlar-current-machine-approval-intake-cli-'));

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
  section('valid explicit packet command');
  const textRun = runZlar(['current-machine-approval-intake', '--packet', SAMPLE_PACKET_PATH]);
  assertEqual('text run exits zero', 0, textRun.status);
  assertEqual('text run emits no stderr', '', textRun.stderr);
  assert('text run title present', textRun.stdout.includes('ZLAR Current-Machine Approval Intake v1'));
  assert('text run authority request allowed', textRun.stdout.includes('authority_request_allowed=true'));
  assert('text run authority request not made', textRun.stdout.includes('authority_request_made=false'));
  assert('text run uses verifier command', textRun.stdout.includes('zlar current-machine-approval-packet verify --input <explicit-packet> --json'));
  assert('text run names selected surface', textRun.stdout.includes('selected_surface=claude_code'));
  assert('text run names delegation target', textRun.stdout.includes('delegation_target=~/.zlar/bin/zlar-gate'));
  assert('text run names source target', textRun.stdout.includes('source_target:'));
  assert('text run names installer identity', textRun.stdout.includes('installer_identity:'));
  assert('text run names command posture', textRun.stdout.includes('command_posture:'));
  assert('text run names dry-run plan identity', textRun.stdout.includes('dry_run_plan_identity:'));
  assert('text run names authority request identity', textRun.stdout.includes('authority_request_identity:'));
  assert('text run names backup rollback', textRun.stdout.includes('backup_rollback:'));
  assert('text run names sha', textRun.stdout.includes(SAMPLE_PACKET_SHA256));
  assert('text run names live hook evidence false', textRun.stdout.includes('live_hook_execution_evidence=false'));
  assert('text run privacy safe', !unsafeOutputPattern.test(textRun.stdout));

  const jsonRun = runZlar(['current-machine-approval-intake', '--packet', SAMPLE_PACKET_PATH, '--json']);
  assertEqual('json run exits zero', 0, jsonRun.status);
  assertEqual('json run emits no stderr', '', jsonRun.stderr);
  assert('json run privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
  const report = JSON.parse(jsonRun.stdout);
  assert('json report validates', assertCurrentMachineApprovalIntakeReport(report));
  assertEqual('json report type', CURRENT_MACHINE_APPROVAL_INTAKE_TYPE, report.intake_type);
  assertEqual('json report authority request allowed', true, report.authority_request_allowed);
  assertEqual('json report authority request not made', false, report.authority_request_made);
  assertEqual('json report packet complete', true, report.verifier_packet_complete);
  assertEqual('json report sha stable', SAMPLE_PACKET_SHA256, report.packet_sha256);
  assertEqual('json report source target commit', 'b89b0c2e2d79db4981cad69af4a190e9c77fb089', report.source_target.target_commit_sha);
  assertEqual('json report delegation target', '~/.zlar/bin/zlar-gate', report.delegation_target);
  assertEqual('json report command posture mode', 'repair', report.command_posture.existing_install_mode);

  section('stdin command');
  const stdinRun = runZlar(['current-machine-approval-intake', '--packet', '-', '--json'], {
    input: packetText,
  });
  assertEqual('stdin exits zero', 0, stdinRun.status);
  assertEqual('stdin emits no stderr', '', stdinRun.stderr);
  const stdinReport = JSON.parse(stdinRun.stdout);
  assert('stdin report validates', assertCurrentMachineApprovalIntakeReport(stdinReport));
  assertEqual('stdin report uses stdin verifier command', 'zlar current-machine-approval-packet verify --input - --json', stdinReport.verifier_command.join(' '));
  assertEqual('stdin report authority request allowed', true, stdinReport.authority_request_allowed);
  assertEqual('stdin report authority request not made', false, stdinReport.authority_request_made);

  section('invalid packets refuse before authority request');
  const wrongSurface = structuredClone(packet);
  wrongSurface.selected_surface.selected_surface = 'codex';
  const wrongSurfacePath = join(scratch, 'wrong-surface.json');
  writeFileSync(wrongSurfacePath, `${JSON.stringify(wrongSurface, null, 2)}\n`);
  const wrongSurfaceRun = runZlar(['current-machine-approval-intake', '--packet', wrongSurfacePath]);
  assert('wrong surface exits nonzero', wrongSurfaceRun.status !== 0);
  assertEqual('wrong surface emits no stderr', '', wrongSurfaceRun.stderr);
  assert('wrong surface stdout refuses authority request', wrongSurfaceRun.stdout.includes('authority_request_allowed=false'));
  assert('wrong surface stdout says request not made', wrongSurfaceRun.stdout.includes('authority_request_made=false'));
  assert('wrong surface stdout names verifier failure', wrongSurfaceRun.stdout.includes('packet_verification_failed'));
  assert('wrong surface stdout omits temp path', !unsafeOutputPattern.test(wrongSurfaceRun.stdout));

  const missingRefusal = structuredClone(packet);
  missingRefusal.downstream_recognition.refusal_matrix =
    missingRefusal.downstream_recognition.refusal_matrix.filter((item) => item.reason_code !== 'unknown_issuer');
  const missingRefusalPath = join(scratch, 'missing-refusal.json');
  writeFileSync(missingRefusalPath, `${JSON.stringify(missingRefusal, null, 2)}\n`);
  const missingRefusalJsonRun = runZlar(['current-machine-approval-intake', '--packet', missingRefusalPath, '--json']);
  assert('missing refusal json exits nonzero', missingRefusalJsonRun.status !== 0);
  assertEqual('missing refusal json emits no stderr', '', missingRefusalJsonRun.stderr);
  assert('missing refusal json omits temp path', !unsafeOutputPattern.test(missingRefusalJsonRun.stdout));
  const missingRefusalReport = JSON.parse(missingRefusalJsonRun.stdout);
  assert('missing refusal report validates', assertCurrentMachineApprovalIntakeReport(missingRefusalReport));
  assertEqual('missing refusal authority request allowed false', false, missingRefusalReport.authority_request_allowed);
  assertEqual('missing refusal authority request not made', false, missingRefusalReport.authority_request_made);
  assertEqual('missing refusal packet complete false', false, missingRefusalReport.verifier_packet_complete);
  assertEqual('missing refusal packet verification absent', null, missingRefusalReport.packet_verification);
  assertEqual('missing refusal verified surface false', false, missingRefusalReport.verified_sections.selected_surface);

  section('help and argument handling');
  const helpRun = runZlar(['current-machine-approval-intake', '--help']);
  assertEqual('help exits zero', 0, helpRun.status);
  assertEqual('help emits no stdout', '', helpRun.stdout);
  assert('help names usage', helpRun.stderr.includes('Usage: zlar current-machine-approval-intake --packet <file|-> [--json]'));
  assert('help states verifier path', helpRun.stderr.includes('Runs the current-machine approval packet verifier'));
  assert('help states no install', helpRun.stderr.includes('does not install'));
  assert('help states no current-machine governance', helpRun.stderr.includes('prove current-machine governance'));

  const missingPacket = runZlar(['current-machine-approval-intake']);
  assert('missing packet exits nonzero', missingPacket.status !== 0);
  assertEqual('missing packet emits no stdout', '', missingPacket.stdout);
  assert('missing packet names missing packet', missingPacket.stderr.includes('Missing required --packet <file|->'));

  const missingPacketValue = runZlar(['current-machine-approval-intake', '--packet']);
  assert('missing packet value exits nonzero', missingPacketValue.status !== 0);
  assertEqual('missing packet value emits no stdout', '', missingPacketValue.stdout);
  assert('missing packet value names missing value', missingPacketValue.stderr.includes('Missing value for --packet'));

  const unsupported = runZlar(['current-machine-approval-intake', '--packet', SAMPLE_PACKET_PATH, '--sample']);
  assert('unsupported option exits nonzero', unsupported.status !== 0);
  assertEqual('unsupported option emits no stdout', '', unsupported.stdout);
  assert('unsupported option names unsupported option', unsupported.stderr.includes('Unsupported current-machine approval intake option provided'));
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
