#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import {
  PROTECTED_RECORDS_TERMINAL_PROOF_TYPE,
  REQUIRED_REFUSAL_REASONS,
  assertProtectedRecordsTerminalProof,
} from '../lib/protected-records-terminal-proof.mjs';

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
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;

function runZlar(args) {
  return spawnSync(ZLAR_BIN, args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

section('text summary command');
const textRun = runZlar(['protected-records-proof']);
assertEqual('text command exits zero', 0, textRun.status);
assertEqual('text command emits no stderr', '', textRun.stderr);
assert('text summary title present', textRun.stdout.includes('Protected Records Terminal Proof v1'));
assert('text summary states fixture model', textRun.stdout.includes('Evidence model: local-hermetic-fixture; live probing=false'));
assert('text summary includes protected profile', textRun.stdout.includes('Deployment profile: protected-records-terminal'));
assert('text summary includes profile contract route', textRun.stdout.includes('route=receipt-recognition-before-record-write'));
assert('text summary includes adapter profile', textRun.stdout.includes('Adapter profile: type=protected-records-adapter-profile-v1; id=protected-records-adapter-profile'));
assert('text summary includes adapter harness', textRun.stdout.includes('Adapter harness: ledger_model=append-only-jsonl-ledger; consumed_receipt_store=single-use-receipt-id-store; replay_scope=per-adapter-ledger'));
assert('text summary includes adapter action', textRun.stdout.includes('Adapter action: command=zlar protected-records-write --input <file|->; result_type=protected-records-write-result-v1'));
assert('text summary includes replay policy', textRun.stdout.includes('Replay policy: single-use-receipt-id-per-terminal-ledger'));
assert('text summary includes required receipt fields', textRun.stdout.includes('Required receipt fields: v,id,kid'));
assert('text summary includes known side doors', textRun.stdout.includes('Known ungoverned boundaries: live_records_system,production_records_adapter,unrouted_records_paths'));
assert('text summary includes recognized write', textRun.stdout.includes('- recognized_write: accept; record_delta=1'));
for (const reason of REQUIRED_REFUSAL_REASONS) {
  assert(`text summary includes refusal reason: ${reason}`, textRun.stdout.includes(reason));
}
assert('text summary states non-claims', textRun.stdout.includes('does not prove production deployment'));
assert('text summary is privacy safe', !unsafeOutputPattern.test(textRun.stdout));

section('json command');
const jsonRun = runZlar(['protected-records-proof', '--json']);
assertEqual('json command exits zero', 0, jsonRun.status);
assertEqual('json command emits no stderr', '', jsonRun.stderr);
assert('json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report passes proof validation', assertProtectedRecordsTerminalProof(report));
assertEqual('json proof type', PROTECTED_RECORDS_TERMINAL_PROOF_TYPE, report.proof_type);
assertEqual('json live probing false', false, report.live_probing);
assertEqual('json profile contract id', 'protected-records-terminal', report.profile_contract.profile_id);
assertEqual('json profile contract route', 'receipt-recognition-before-record-write', report.profile_contract.route);
assertEqual('json profile contract replay policy', 'single-use-receipt-id-per-terminal-ledger', report.profile_contract.receipt_replay_policy);
assertEqual('json adapter profile type', 'protected-records-adapter-profile-v1', report.adapter_profile.profile_type);
assertEqual('json adapter profile route', 'receipt-recognition-before-ledger-append', report.adapter_profile.authoritative_route);
assertEqual('json adapter profile boundary', 'protected-records-adapter-harness', report.adapter_profile.adapter_boundary);
assertEqual('json adapter harness type', 'protected-records-adapter-harness-v1', report.adapter_harness.harness_type);
assertEqual('json adapter harness direct write closed', false, report.adapter_harness.direct_write_path_available);
assertEqual('json adapter harness no live adapter claim', false, report.adapter_harness.live_records_adapter);
assertEqual('json adapter harness final ledger entry count', 1, report.adapter_harness.final_ledger_entry_count);
assertEqual('json adapter action command', 'zlar protected-records-write --input <file|->', report.adapter_action.command);
assertEqual('json adapter action result type', 'protected-records-write-result-v1', report.adapter_action.result_type);
assertEqual('json adapter action requires fixture mode', true, report.adapter_action.fixture_mode_required);
assertEqual('json adapter action no live adapter claim', false, report.adapter_action.live_records_adapter);
assert('json profile contract requires receipt fields', report.profile_contract.required_receipt_fields.includes('payload.detail_hash'));
assertEqual('json final record count', 1, report.terminal.final_record_count);
assertEqual('json refusal count', 11, report.refusals.length);
assert('json has replay refusal', report.refusals.some((item) => item.reason_code === 'receipt_replay' && item.record_count_delta === 0));
assert('json has unknown issuer refusal', report.refusals.some((item) => item.reason_code === 'unknown_issuer'));
assert('json has retired issuer refusal', report.refusals.some((item) => item.reason_code === 'issuer_not_active'));
assert('json omits raw record id', !jsonRun.stdout.includes('fixture-record-001'));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonRun.stdout));

section('help and fail closed command handling');
const helpRun = runZlar(['protected-records-proof', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assert('help names usage', helpRun.stderr.includes('Usage: zlar protected-records-proof [--json]'));
assert('help states no live probing', helpRun.stderr.includes('does not live probe'));
assertEqual('help emits no stdout', '', helpRun.stdout);

const unsupported = runZlar(['protected-records-proof', '--latest']);
assert('unsupported option exits usage error', unsupported.status !== 0);
assert('unsupported option emits no report', unsupported.stdout === '');
assert('unsupported option names unsupported option', unsupported.stderr.includes('Unsupported option'));
assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

const helpList = runZlar(['help']);
assertEqual('main help exits zero', 0, helpList.status);
assert('main help lists protected records proof', helpList.stdout.includes('protected-records-proof'));

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
