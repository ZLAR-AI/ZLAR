#!/usr/bin/env node

import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  CURRENT_MACHINE_APPROVAL_INTAKE_NON_CLAIMS,
  CURRENT_MACHINE_APPROVAL_INTAKE_SAFE_CLAIM_CEILING,
  CURRENT_MACHINE_APPROVAL_INTAKE_TYPE,
  assertCurrentMachineApprovalIntakeReport,
  formatCurrentMachineApprovalIntakeReport,
  runCurrentMachineApprovalIntake,
} from '../lib/current-machine-approval-intake.mjs';
import { assertNoUnsafeCurrentMachineApprovalPacketText } from '../lib/current-machine-approval-packet.mjs';

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

function assertThrows(label, fn, expectedMessageFragment) {
  TOTAL++;
  try {
    fn();
    FAIL++;
    console.log(`  FAIL: ${label} -- expected throw`);
  } catch (err) {
    if (!expectedMessageFragment || String(err.message).includes(expectedMessageFragment)) {
      PASS++;
      console.log(`  PASS: ${label}`);
    } else {
      FAIL++;
      console.log(`  FAIL: ${label} -- ${err.message}`);
    }
  }
}

function section(title) {
  console.log(`\n-- ${title} --`);
}

const SAMPLE_PACKET_PATH = 'tests/fixtures/current-machine-approval-packet-claude-code-v1.json';
const SAMPLE_PACKET_SHA256 = '7012e6e6bb8e89358363ce073422bb74f30ee63af50be5870eace96e6f672e68';
const packetText = readFileSync(SAMPLE_PACKET_PATH, 'utf8');
const packet = JSON.parse(packetText);
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|BEGIN [A-Z ]*KEY/i;
const scratch = mkdtempSync(join(tmpdir(), 'zlar-current-machine-approval-intake-'));

try {
  section('valid explicit packet intake');
  const report = runCurrentMachineApprovalIntake({ packetPath: SAMPLE_PACKET_PATH });
  assert('valid report validates', assertCurrentMachineApprovalIntakeReport(report));
  assertEqual('intake type', CURRENT_MACHINE_APPROVAL_INTAKE_TYPE, report.intake_type);
  assertEqual('intake allowed status', 'allowed_to_prepare_human_request_only', report.intake_status);
  assertEqual('verifier command uses verifier', 'zlar current-machine-approval-packet verify --input <explicit-packet> --json', report.verifier_command.join(' '));
  assertEqual('verifier exits zero', 0, report.verifier_exit_code);
  assertEqual('verifier verified true', true, report.verifier_verified);
  assertEqual('verifier packet complete true', true, report.verifier_packet_complete);
  assertEqual('authority request allowed true', true, report.authority_request_allowed);
  assertEqual('authority request made false', false, report.authority_request_made);
  assertEqual('authority request kind', 'future_install_or_configuration_human_authority_request', report.authority_request_kind);
  assertEqual('packet sha stable', SAMPLE_PACKET_SHA256, report.packet_sha256);
  assertEqual('selected surface', 'claude_code', report.selected_surface);
  assertEqual('hook event', 'PreToolUse', report.hook_event);
  assertEqual('delegation target preserved', '~/.zlar/bin/zlar-gate', report.delegation_target);
  assertEqual('source target commit preserved', 'b89b0c2e2d79db4981cad69af4a190e9c77fb089', report.source_target.target_commit_sha);
  assertEqual('installer identity preserved', 'install.sh', report.installer_identity.installer_path);
  assertEqual('command posture preserved', 'repair', report.command_posture.existing_install_mode);
  assertEqual('dry-run plan identity preserved', 'zlar-install-plan-v1', report.dry_run_plan_identity.plan_type);
  assertEqual('authority request still not made', false, report.authority_request_identity.authority_request_made);
  assertEqual('backup rollback requirement preserved', true, report.backup_rollback_requirements.backup_required_before_mutation);
  assertEqual('issuer id preserved', 'zlar-current-machine-claude-code-fixture-issuer', report.issuer_id);
  assertEqual('issuer kid preserved', 'zlar-current-machine-claude-code-fixture-kid', report.issuer_kid);
  assertEqual('policy id preserved', 'zlar-current-machine-claude-code-policy-v1', report.policy_id);
  assertEqual('receipt format preserved', 'zlar-receipt-v1', report.receipt_format);
  assertEqual('downstream refuses before effect', true, report.downstream_refuses_before_effect);
  assertEqual('refusal matrix complete', true, report.refusal_matrix_complete);
  assertEqual('human authority still required', true, report.human_authority_required_before_install_or_config);
  for (const [field, value] of Object.entries(report.verified_sections)) {
    assertEqual(`verified section true: ${field}`, true, value);
  }
  for (const [field, value] of Object.entries(report.no_write_boundary)) {
    assertEqual(`no-write boundary false: ${field}`, false, value);
  }
  for (const claim of CURRENT_MACHINE_APPROVAL_INTAKE_NON_CLAIMS) {
    assert(`non-claim present: ${claim}`, report.non_claims.includes(claim));
  }
  assertEqual('safe claim ceiling exact', CURRENT_MACHINE_APPROVAL_INTAKE_SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
  assert('embedded packet verification preserved', report.packet_verification.packet_complete === true);
  assert('report JSON privacy safe', assertNoUnsafeCurrentMachineApprovalPacketText(JSON.stringify(report)));
  assert('report JSON omits unsafe details', !unsafeOutputPattern.test(JSON.stringify(report)));

  const summary = formatCurrentMachineApprovalIntakeReport(report);
  assert('summary title present', summary.includes('ZLAR Current-Machine Approval Intake v1'));
  assert('summary allows request preparation only', summary.includes('authority_request_allowed=true'));
  assert('summary says request not made', summary.includes('authority_request_made=false'));
  assert('summary names verifier command', summary.includes('zlar current-machine-approval-packet verify --input <explicit-packet> --json'));
  assert('summary names selected surface', summary.includes('selected_surface=claude_code'));
  assert('summary names delegation target', summary.includes('delegation_target=~/.zlar/bin/zlar-gate'));
  assert('summary names source target', summary.includes('source_target:'));
  assert('summary names installer identity', summary.includes('installer_identity:'));
  assert('summary names command posture', summary.includes('command_posture:'));
  assert('summary names dry-run plan identity', summary.includes('dry_run_plan_identity:'));
  assert('summary names authority request identity', summary.includes('authority_request_identity:'));
  assert('summary names backup rollback', summary.includes('backup_rollback:'));
  assert('summary names refusal matrix', summary.includes('refusal_matrix_complete=true'));
  assert('summary names no-write boundary', summary.includes('install_or_activation_applied=false'));
  assert('summary names live hook non-evidence', summary.includes('live_hook_execution_evidence=false'));
  assert('summary is privacy safe', assertNoUnsafeCurrentMachineApprovalPacketText(summary));
  assert('summary omits unsafe details', !unsafeOutputPattern.test(summary));

  section('stdin packet intake');
  const stdinReport = runCurrentMachineApprovalIntake({
    packetPath: '-',
    packetText,
  });
  assert('stdin report validates', assertCurrentMachineApprovalIntakeReport(stdinReport));
  assertEqual('stdin verifier command uses stdin', 'zlar current-machine-approval-packet verify --input - --json', stdinReport.verifier_command.join(' '));
  assertEqual('stdin authority request allowed', true, stdinReport.authority_request_allowed);
  assertEqual('stdin authority request not made', false, stdinReport.authority_request_made);
  assertEqual('stdin sha stable', SAMPLE_PACKET_SHA256, stdinReport.packet_sha256);

  section('invalid packet refuses before authority request');
  const missingRefusal = structuredClone(packet);
  missingRefusal.downstream_recognition.refusal_matrix =
    missingRefusal.downstream_recognition.refusal_matrix.filter((item) => item.reason_code !== 'receipt_replay');
  const missingRefusalPath = join(scratch, 'missing-refusal.json');
  writeFileSync(missingRefusalPath, `${JSON.stringify(missingRefusal, null, 2)}\n`);
  const missingRefusalReport = runCurrentMachineApprovalIntake({ packetPath: missingRefusalPath });
  assert('missing refusal report validates', assertCurrentMachineApprovalIntakeReport(missingRefusalReport));
  assertEqual('missing refusal status refuses', 'refused_before_authority_request', missingRefusalReport.intake_status);
  assertEqual('missing refusal authority request allowed false', false, missingRefusalReport.authority_request_allowed);
  assertEqual('missing refusal authority request made false', false, missingRefusalReport.authority_request_made);
  assertEqual('missing refusal verifier packet complete false', false, missingRefusalReport.verifier_packet_complete);
  assertEqual('missing refusal packet verification absent', null, missingRefusalReport.packet_verification);
  assertEqual('missing refusal reason', 'packet_verification_failed', missingRefusalReport.refusal_reason_code);
  assert('missing refusal summary names verification failure', missingRefusalReport.refusal_summary.includes('ERROR:'));
  for (const [field, value] of Object.entries(missingRefusalReport.verified_sections)) {
    assertEqual(`missing refusal verified section false: ${field}`, false, value);
  }
  for (const [field, value] of Object.entries(missingRefusalReport.no_write_boundary)) {
    assertEqual(`missing refusal no-write boundary false: ${field}`, false, value);
  }
  assert('missing refusal report privacy safe', assertNoUnsafeCurrentMachineApprovalPacketText(JSON.stringify(missingRefusalReport)));
  assert('missing refusal report omits temp path', !unsafeOutputPattern.test(JSON.stringify(missingRefusalReport)));

  const wrongSurface = structuredClone(packet);
  wrongSurface.selected_surface.selected_surface = 'codex';
  const wrongSurfacePath = join(scratch, 'wrong-surface.json');
  writeFileSync(wrongSurfacePath, `${JSON.stringify(wrongSurface, null, 2)}\n`);
  const wrongSurfaceReport = runCurrentMachineApprovalIntake({ packetPath: wrongSurfacePath });
  assert('wrong surface report validates', assertCurrentMachineApprovalIntakeReport(wrongSurfaceReport));
  assertEqual('wrong surface authority request allowed false', false, wrongSurfaceReport.authority_request_allowed);
  assertEqual('wrong surface reason', 'packet_verification_failed', wrongSurfaceReport.refusal_reason_code);
  assert('wrong surface summary names selected surface failure', wrongSurfaceReport.refusal_summary.includes('must select claude_code'));

  const missingPathReport = runCurrentMachineApprovalIntake({ packetPath: join(scratch, 'missing.json') });
  assert('missing path report validates', assertCurrentMachineApprovalIntakeReport(missingPathReport));
  assertEqual('missing path refuses authority request', false, missingPathReport.authority_request_allowed);
  assertEqual('missing path request not made', false, missingPathReport.authority_request_made);
  assert('missing path summary avoids raw path', !unsafeOutputPattern.test(missingPathReport.refusal_summary));

  section('contract failures');
  assertThrows(
    'stdin without packet text refuses at API boundary',
    () => runCurrentMachineApprovalIntake({ packetPath: '-' }),
    'requires packet text'
  );
  const forgedAllowed = structuredClone(report);
  forgedAllowed.authority_request_made = true;
  assertThrows(
    'authority request made claim refuses',
    () => assertCurrentMachineApprovalIntakeReport(forgedAllowed),
    'must be false'
  );
  const forgedNoWrite = structuredClone(report);
  forgedNoWrite.no_write_boundary.user_config_written = true;
  assertThrows(
    'user config write claim refuses',
    () => assertCurrentMachineApprovalIntakeReport(forgedNoWrite),
    'must be false'
  );

  const forgedSelectedSurface = structuredClone(report);
  forgedSelectedSurface.selected_surface = 'cursor';
  assertThrows(
    'forged top-level selected surface refuses',
    () => assertCurrentMachineApprovalIntakeReport(forgedSelectedSurface),
    'selected_surface must match packet verification'
  );

  const forgedPacketSha = structuredClone(report);
  forgedPacketSha.packet_sha256 = '9'.repeat(64);
  assertThrows(
    'forged top-level packet sha refuses',
    () => assertCurrentMachineApprovalIntakeReport(forgedPacketSha),
    'packet_sha256 must match packet verification'
  );

  const forgedSourceTarget = structuredClone(report);
  forgedSourceTarget.source_target = {
    ...forgedSourceTarget.source_target,
    target_commit_sha: '1111111111111111111111111111111111111111',
  };
  assertThrows(
    'forged top-level source target refuses',
    () => assertCurrentMachineApprovalIntakeReport(forgedSourceTarget),
    'source_target must match packet verification'
  );

  const forgedVerifiedSection = structuredClone(report);
  forgedVerifiedSection.verified_sections.source_target = false;
  assertThrows(
    'forged verified sections refuse',
    () => assertCurrentMachineApprovalIntakeReport(forgedVerifiedSection),
    'verified sections must be derived from packet verification'
  );
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
