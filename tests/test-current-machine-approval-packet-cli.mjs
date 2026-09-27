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
  CURRENT_MACHINE_APPROVAL_PACKET_VERIFICATION_TYPE,
  REQUIRED_CURRENT_MACHINE_APPROVAL_REFUSAL_REASONS,
  assertCurrentMachineApprovalPacketVerification,
} from '../lib/current-machine-approval-packet.mjs';

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
const scratch = mkdtempSync(join(tmpdir(), 'zlar-current-machine-approval-packet-cli-'));

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

const packetText = readFileSync(SAMPLE_PACKET_PATH, 'utf8');
const packet = JSON.parse(packetText);

try {
  section('sample verification command');
  const sampleRun = runZlar(['current-machine-approval-packet', 'verify', '--sample']);
  assertEqual('sample verify exits zero', 0, sampleRun.status);
  assertEqual('sample verify emits no stderr', '', sampleRun.stderr);
  assert('sample verify title present', sampleRun.stdout.includes('ZLAR Current-Machine Approval Packet Verification v1'));
  assert('sample verify says complete', sampleRun.stdout.includes('packet_complete=true'));
  assert('sample verify includes sha', sampleRun.stdout.includes(SAMPLE_PACKET_SHA256));
  assert('sample verify names selected surface', sampleRun.stdout.includes('selected_surface=claude_code'));
  assert('sample verify names hook target', sampleRun.stdout.includes('hook_target:'));
  assert('sample verify names delegation target', sampleRun.stdout.includes('delegation_target=~/.zlar/bin/zlar-gate'));
  assert('sample verify names source target', sampleRun.stdout.includes('source_target:'));
  assert('sample verify names installer identity', sampleRun.stdout.includes('installer_identity:'));
  assert('sample verify names command posture', sampleRun.stdout.includes('command_posture:'));
  assert('sample verify names dry-run plan identity', sampleRun.stdout.includes('dry_run_plan_identity:'));
  assert('sample verify names authority request identity', sampleRun.stdout.includes('authority_request_identity:'));
  assert('sample verify names backup rollback', sampleRun.stdout.includes('backup_rollback:'));
  assert('sample verify names receipt path', sampleRun.stdout.includes('receipt_path:'));
  assert('sample verify names refusal matrix', sampleRun.stdout.includes('refusal_matrix_complete=true'));
  assert('sample verify names current-machine non-claim', sampleRun.stdout.includes('current_machine_governance_evidence=false'));
  assert('sample verify output is privacy safe', !unsafeOutputPattern.test(sampleRun.stdout));

  const sampleJsonRun = runZlar(['current-machine-approval-packet', 'verify', '--sample', '--json']);
  assertEqual('sample json exits zero', 0, sampleJsonRun.status);
  assertEqual('sample json emits no stderr', '', sampleJsonRun.stderr);
  assert('sample json output is privacy safe', !unsafeOutputPattern.test(sampleJsonRun.stdout));
  const sampleVerification = JSON.parse(sampleJsonRun.stdout);
  assert('sample json verification validates', assertCurrentMachineApprovalPacketVerification(sampleVerification));
  assertEqual('sample json verification type', CURRENT_MACHINE_APPROVAL_PACKET_VERIFICATION_TYPE, sampleVerification.verification_type);
  assertEqual('sample json packet complete true', true, sampleVerification.packet_complete);
  assertEqual('sample json sha stable', SAMPLE_PACKET_SHA256, sampleVerification.packet_sha256);
  assertEqual('sample json refusal reason count', REQUIRED_CURRENT_MACHINE_APPROVAL_REFUSAL_REASONS.length, sampleVerification.refusal_reason_count);
  assertEqual('sample json source target commit', 'b89b0c2e2d79db4981cad69af4a190e9c77fb089', sampleVerification.source_target.target_commit_sha);
  assertEqual('sample json delegation target', '~/.zlar/bin/zlar-gate', sampleVerification.delegation_target);
  assertEqual('sample json command posture mode', 'repair', sampleVerification.command_posture.existing_install_mode);
  assertEqual('sample json install false', false, sampleVerification.install_or_activation_applied);
  assertEqual('sample json current-machine governance false', false, sampleVerification.current_machine_governance_evidence);
  assertEqual('sample json Telegram false', false, sampleVerification.telegram_used);

  section('required packet sha posture');
  const sampleRequiredShaRun = runZlar([
    'current-machine-approval-packet',
    'verify',
    '--sample',
    '--require-packet-sha',
    SAMPLE_PACKET_SHA256,
  ]);
  assertEqual('sample required sha exits zero', 0, sampleRequiredShaRun.status);
  assertEqual('sample required sha emits no stderr', '', sampleRequiredShaRun.stderr);
  assert('sample required sha reports posture', sampleRequiredShaRun.stdout.includes(`required_packet_sha256=${SAMPLE_PACKET_SHA256}`));
  assert('sample required sha reports matched', sampleRequiredShaRun.stdout.includes('required_packet_sha256_matched=true'));
  assert('sample required sha output is privacy safe', !unsafeOutputPattern.test(sampleRequiredShaRun.stdout));

  const sampleRequiredShaJsonRun = runZlar([
    'current-machine-approval-packet',
    'verify',
    '--sample',
    '--json',
    '--require-packet-sha',
    SAMPLE_PACKET_SHA256,
  ]);
  assertEqual('sample required sha json exits zero', 0, sampleRequiredShaJsonRun.status);
  assertEqual('sample required sha json emits no stderr', '', sampleRequiredShaJsonRun.stderr);
  assert('sample required sha json output is privacy safe', !unsafeOutputPattern.test(sampleRequiredShaJsonRun.stdout));
  const requiredShaVerification = JSON.parse(sampleRequiredShaJsonRun.stdout);
  assertEqual('sample required sha json packet sha stable', SAMPLE_PACKET_SHA256, requiredShaVerification.packet_sha256);
  assertEqual('sample required sha json required packet sha', SAMPLE_PACKET_SHA256, requiredShaVerification.required_packet_sha256);
  assertEqual('sample required sha json required packet sha matched', true, requiredShaVerification.required_packet_sha256_matched);

  const mismatchedRequiredShaRun = runZlar([
    'current-machine-approval-packet',
    'verify',
    '--sample',
    '--json',
    '--require-packet-sha',
    '0'.repeat(64),
  ]);
  assert('mismatched required sha exits nonzero', mismatchedRequiredShaRun.status !== 0);
  assertEqual('mismatched required sha emits no stdout', '', mismatchedRequiredShaRun.stdout);
  assert('mismatched required sha names required packet sha', mismatchedRequiredShaRun.stderr.includes('does not match required --require-packet-sha value'));
  assert('mismatched required sha stderr privacy safe', !unsafeOutputPattern.test(mismatchedRequiredShaRun.stderr));

  const malformedRequiredShaRun = runZlar([
    'current-machine-approval-packet',
    'verify',
    '--sample',
    '--json',
    '--require-packet-sha',
    'abc',
  ]);
  assert('malformed required sha exits nonzero', malformedRequiredShaRun.status !== 0);
  assertEqual('malformed required sha emits no stdout', '', malformedRequiredShaRun.stdout);
  assert('malformed required sha names required packet sha format', malformedRequiredShaRun.stderr.includes('--require-packet-sha must be a 64-character lowercase SHA-256 hex digest'));
  assert('malformed required sha stderr privacy safe', !unsafeOutputPattern.test(malformedRequiredShaRun.stderr));

  const missingRequiredShaRun = runZlar([
    'current-machine-approval-packet',
    'verify',
    '--sample',
    '--require-packet-sha',
  ]);
  assert('missing required sha exits nonzero', missingRequiredShaRun.status !== 0);
  assertEqual('missing required sha emits no stdout', '', missingRequiredShaRun.stdout);
  assert('missing required sha names missing value', missingRequiredShaRun.stderr.includes('Missing value for --require-packet-sha'));
  assert('missing required sha stderr privacy safe', !unsafeOutputPattern.test(missingRequiredShaRun.stderr));

  section('input and stdin verification');
  const inputRun = runZlar(['current-machine-approval-packet', 'verify', '--input', SAMPLE_PACKET_PATH, '--json']);
  assertEqual('input json exits zero', 0, inputRun.status);
  assertEqual('input json emits no stderr', '', inputRun.stderr);
  const inputVerification = JSON.parse(inputRun.stdout);
  assertEqual('input json sha stable', SAMPLE_PACKET_SHA256, inputVerification.packet_sha256);

  const stdinRun = runZlar(['current-machine-approval-packet', 'verify', '--input', '-'], {
    input: packetText,
  });
  assertEqual('stdin verify exits zero', 0, stdinRun.status);
  assertEqual('stdin verify emits no stderr', '', stdinRun.stderr);
  assert('stdin verify says complete', stdinRun.stdout.includes('packet_complete=true'));
  assert('stdin verify output is privacy safe', !unsafeOutputPattern.test(stdinRun.stdout));

  section('help and fail closed command handling');
  const helpRun = runZlar(['current-machine-approval-packet', '--help']);
  assertEqual('help exits zero', 0, helpRun.status);
  assertEqual('help emits no stdout', '', helpRun.stdout);
  assert('help names usage', helpRun.stderr.includes('Usage: zlar current-machine-approval-packet verify (--input <file|->|--sample) [--json] [--require-packet-sha <packet_sha256>]'));
  assert('help names required packet sha posture', helpRun.stderr.includes('Use --require-packet-sha <packet_sha256>'));
  assert('help names sample packet', helpRun.stderr.includes(SAMPLE_PACKET_PATH));
  assert('help states no install', helpRun.stderr.includes('does not install'));
  assert('help states no current-machine governance', helpRun.stderr.includes('prove current-machine governance'));

  const missingVerify = runZlar(['current-machine-approval-packet']);
  assert('missing verify exits nonzero', missingVerify.status !== 0);
  assertEqual('missing verify emits no stdout', '', missingVerify.stdout);
  assert('missing verify names verify subcommand', missingVerify.stderr.includes('Missing required verify subcommand'));

  const missingInput = runZlar(['current-machine-approval-packet', 'verify']);
  assert('missing input exits nonzero', missingInput.status !== 0);
  assertEqual('missing input emits no stdout', '', missingInput.stdout);
  assert('missing input names input/sample', missingInput.stderr.includes('Missing required --input <file|-> or --sample'));
  assert('missing input stderr privacy safe', !unsafeOutputPattern.test(missingInput.stderr));

  const inputSampleConflict = runZlar(['current-machine-approval-packet', 'verify', '--input', SAMPLE_PACKET_PATH, '--sample']);
  assert('input sample conflict exits nonzero', inputSampleConflict.status !== 0);
  assertEqual('input sample conflict emits no stdout', '', inputSampleConflict.stdout);
  assert('input sample conflict names conflict', inputSampleConflict.stderr.includes('Cannot combine --input with --sample'));

  const unsupported = runZlar(['current-machine-approval-packet', 'verify', '--sample', '--latest']);
  assert('unsupported option exits nonzero', unsupported.status !== 0);
  assertEqual('unsupported option emits no stdout', '', unsupported.stdout);
  assert('unsupported option names unsupported option', unsupported.stderr.includes('Unsupported verify option provided'));

  section('invalid packets fail closed');
  const wrongSurface = structuredClone(packet);
  wrongSurface.selected_surface.selected_surface = 'codex';
  const wrongSurfacePath = join(scratch, 'wrong-surface.json');
  writeFileSync(wrongSurfacePath, `${JSON.stringify(wrongSurface, null, 2)}\n`);
  const wrongSurfaceRun = runZlar(['current-machine-approval-packet', 'verify', '--input', wrongSurfacePath]);
  assert('wrong surface exits nonzero', wrongSurfaceRun.status !== 0);
  assertEqual('wrong surface emits no report', '', wrongSurfaceRun.stdout);
  assert('wrong surface names claude_code', wrongSurfaceRun.stderr.includes('must select claude_code'));

  const missingRefusal = structuredClone(packet);
  missingRefusal.downstream_recognition.refusal_matrix =
    missingRefusal.downstream_recognition.refusal_matrix.filter((item) => item.reason_code !== 'unknown_issuer');
  const missingRefusalPath = join(scratch, 'missing-refusal.json');
  writeFileSync(missingRefusalPath, `${JSON.stringify(missingRefusal, null, 2)}\n`);
  const missingRefusalRun = runZlar(['current-machine-approval-packet', 'verify', '--input', missingRefusalPath]);
  assert('missing refusal exits nonzero', missingRefusalRun.status !== 0);
  assertEqual('missing refusal emits no report', '', missingRefusalRun.stdout);
  assert('missing refusal names refusal matrix', missingRefusalRun.stderr.includes('refusal matrix reason count drifted'));

  const installClaim = structuredClone(packet);
  installClaim.authority_boundary.install_or_activation_applied = true;
  const installClaimPath = join(scratch, 'install-claim.json');
  writeFileSync(installClaimPath, `${JSON.stringify(installClaim, null, 2)}\n`);
  const installClaimRun = runZlar(['current-machine-approval-packet', 'verify', '--input', installClaimPath]);
  assert('install claim exits nonzero', installClaimRun.status !== 0);
  assertEqual('install claim emits no report', '', installClaimRun.stdout);
  assert('install claim names install false boundary', installClaimRun.stderr.includes('install_or_activation_applied must be false'));

  const rawKey = structuredClone(packet);
  rawKey.issuer_policy.issuer.public_key_reference = '-----BEGIN PUBLIC KEY-----';
  const rawKeyPath = join(scratch, 'raw-key.json');
  writeFileSync(rawKeyPath, `${JSON.stringify(rawKey, null, 2)}\n`);
  const rawKeyRun = runZlar(['current-machine-approval-packet', 'verify', '--input', rawKeyPath]);
  assert('raw key exits nonzero', rawKeyRun.status !== 0);
  assertEqual('raw key emits no report', '', rawKeyRun.stdout);
  assert('raw key error names unsafe class', rawKeyRun.stderr.includes('unsafe public key material'));
  assert('raw key stderr omits raw key text', !rawKeyRun.stderr.includes('BEGIN PUBLIC KEY'));
  assert('raw key stderr is privacy safe', !unsafeOutputPattern.test(rawKeyRun.stderr));
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
