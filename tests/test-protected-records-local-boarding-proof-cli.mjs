#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import {
  PROTECTED_RECORDS_LOCAL_BOARDING_PROOF_TYPE,
  REQUIRED_PROTECTED_RECORDS_LOCAL_BOARDING_CASES,
  assertProtectedRecordsLocalBoardingProof,
} from '../lib/protected-records-local-boarding-proof.mjs';

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
const textRun = runZlar(['protected-records-local-boarding-proof']);
assertEqual('text command exits zero', 0, textRun.status);
assertEqual('text command emits no stderr', '', textRun.stderr);
assert('text summary title present', textRun.stdout.includes('Protected Records Local Boarding Proof v1'));
assert('text summary names command', textRun.stdout.includes('Command: zlar protected-records-local-boarding-proof'));
assert('text summary states in-memory fixture', textRun.stdout.includes('Evidence model: local-in-memory-fixture; live_probing=false'));
assert('text summary states destination route', textRun.stdout.includes('route=receipt-recognition-before-local-proof-effect'));
assert('text summary states replay scope', textRun.stdout.includes('protected-records-local-boarding-proof.records.write.fixture-v1'));
assert('text summary states no durable replay store', textRun.stdout.includes('durable_replay_store=false'));
assert('text summary states no exactly-once production effects', textRun.stdout.includes('exactly_once_production_effects=false'));
assert('text summary states final effect count', textRun.stdout.includes('final_effect_count=1'));
assert('text summary states non-install boundary', textRun.stdout.includes('not an install, not activation, not current-machine governance'));
for (const expected of REQUIRED_PROTECTED_RECORDS_LOCAL_BOARDING_CASES) {
  assert(`text summary includes case: ${expected.case_id}`, textRun.stdout.includes(expected.case_id));
  assert(`text summary includes reason: ${expected.expected_reason_code}`, textRun.stdout.includes(expected.expected_reason_code));
}
assert('text summary is privacy safe', !unsafeOutputPattern.test(textRun.stdout));
assert('text summary omits raw fixture record id', !textRun.stdout.includes('local-boarding-fixture-record'));

section('json command');
const jsonRun = runZlar(['protected-records-local-boarding-proof', '--json']);
assertEqual('json command exits zero', 0, jsonRun.status);
assertEqual('json command emits no stderr', '', jsonRun.stderr);
assert('json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
assert('json omits raw fixture record id', !jsonRun.stdout.includes('local-boarding-fixture-record'));
const report = JSON.parse(jsonRun.stdout);
assert('json report passes proof validation', assertProtectedRecordsLocalBoardingProof(report));
assertEqual('json proof type', PROTECTED_RECORDS_LOCAL_BOARDING_PROOF_TYPE, report.proof_type);
assertEqual('json command field', 'zlar protected-records-local-boarding-proof', report.command);
assertEqual('json evidence model', 'local-in-memory-fixture', report.evidence_model);
assertEqual('json no live probing', false, report.live_probing);
assertEqual('json action class', 'records.write', report.action_class);
assertEqual('json destination no live records', false, report.destination_contract.live_records_system);
assertEqual('json no persistent store', false, report.destination_contract.persistent_store_written);
assertEqual('json no current-machine governance', false, report.destination_contract.current_machine_governance_proven);
assertEqual('json source state commit matches source commit', report.source_commit, report.source_state.commit);
assert('json source state provenance named', ['clean-commit', 'commit-plus-uncommitted-worktree'].includes(report.source_state.provenance));
assertEqual('json fixture-only recognition', true, report.recognition_contract.current_implementation_fixture_recognition_only);
assertEqual('json no full receipt conformance claim', false, report.recognition_contract.full_receipt_v1_conformance_claimed);
assertEqual('json extra scope refusal cases not claimed', false, report.recognition_contract.policy_domain_tool_outcome_audit_freshness_refusal_cases_proven);
assertEqual('json policy/domain/tool/detail/freshness refusal cases proven', true, report.recognition_contract.policy_domain_tool_detail_freshness_refusal_cases_proven);
assertEqual('json v1 identity contract required', true, report.recognition_contract.recognized_receipt_requires_v1_identity_contract);
assertEqual('json legacy v0 unsupported refusal proven', true, report.recognition_contract.legacy_v0_unsupported_refusal_case_proven);
assertEqual('json legacy v0 not recognized as boarding identity', false, report.recognition_contract.legacy_v0_receipts_recognized_as_boarding_identity);
assert('json proven scope mismatch covers domain/tool/detail', JSON.stringify(report.recognition_contract.proven_scope_mismatch_refusal_reason_codes) === JSON.stringify(['domain_out_of_scope', 'tool_out_of_scope', 'detail_hash_mismatch']));
assert('json receipt identity contract present', report.receipt_identity_contract.contract_type === 'protected-records-local-boarding-receipt-identity-v1');
assertEqual('json receipt identity v1 format', 'v1', report.receipt_identity_contract.recognized_receipt_format);
assertEqual('json receipt identity command posture', 'local-v1-required-receipt-identity-posture', report.receipt_identity_contract.command_posture);
assertEqual('json receipt identity matched', true, report.summary.v1_receipt_identity_verified);
assertEqual('json consequence absent on refusals', true, report.summary.consequence_absent_on_every_refusal);
assertEqual('json consequence present exactly once', true, report.summary.consequence_present_exactly_once_on_acceptance);
assertEqual('json no v0 boarding identity', false, report.summary.legacy_v0_recognized_boarding_identity);
assertEqual('json replay cache final size', 1, report.replay_contract.replay_cache_final_size);
assertEqual('json final effect count', 1, report.summary.final_effect_count);
assertEqual('json production downstream false', false, report.summary.production_downstream_recognition_proven);
assertEqual('json one effect emitted', 1, report.effects.length);
for (const expected of REQUIRED_PROTECTED_RECORDS_LOCAL_BOARDING_CASES) {
  const item = report.case_summaries.find((candidate) => candidate.case_id === expected.case_id);
  assert(`json case present: ${expected.case_id}`, Boolean(item));
  assertEqual(`json case reason: ${expected.case_id}`, expected.expected_reason_code, item.observed_reason_code);
  assertEqual(`json case effect delta: ${expected.case_id}`, expected.expected_effect_delta, item.effect_count_delta);
}
assert('json has replay refusal after accepted effect', report.case_summaries.some((item) =>
  item.case_id === 'replay_refused' &&
  item.observed_reason_code === 'receipt_replay' &&
  item.effect_count_before === 1 &&
  item.effect_count_after === 1
));
assert('json omits public key material', !jsonRun.stdout.includes('BEGIN PUBLIC KEY'));
assert('json omits private key material', !jsonRun.stdout.includes('BEGIN PRIVATE KEY'));

section('help and fail closed command handling');
const helpRun = runZlar(['protected-records-local-boarding-proof', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assert('help names usage', helpRun.stderr.includes('Usage: zlar protected-records-local-boarding-proof [--json]'));
assert('help states no external fixture paths', helpRun.stderr.includes('accepts no external fixture paths'));
assert('help states no install/config/live claims', helpRun.stderr.includes('does not install, activate'));
assertEqual('help emits no stdout', '', helpRun.stdout);

for (const args of [
  ['protected-records-local-boarding-proof', '--latest'],
  ['protected-records-local-boarding-proof', '--receipt', 'receipt.json'],
  ['protected-records-local-boarding-proof', '--state-path', 'state.jsonl'],
]) {
  const unsupported = runZlar(args);
  assert(`unsupported option exits usage error: ${args.slice(1).join(' ')}`, unsupported.status !== 0);
  assert(`unsupported option emits no report: ${args.slice(1).join(' ')}`, unsupported.stdout === '');
  assert(`unsupported option names unsupported option: ${args.slice(1).join(' ')}`, unsupported.stderr.includes('Unsupported option'));
  assert(`unsupported option is privacy safe: ${args.slice(1).join(' ')}`, !unsafeOutputPattern.test(unsupported.stderr));
}

const helpList = runZlar(['help']);
assertEqual('main help exits zero', 0, helpList.status);
assert('main help lists local boarding proof', helpList.stdout.includes('protected-records-local-boarding-proof'));

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
