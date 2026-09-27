#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import {
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SOURCE_STATE_BOUNDARY,
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_TYPE,
  REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES,
  assertClaudeCodeHookContractReplayProof,
  claudeCodeHookContractReplayContractSha256,
  claudeCodeHookContractReplayRepoAdapterSha256,
} from '../lib/claude-code-hook-contract-replay-proof.mjs';

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
const textRun = runZlar(['claude-code-hook-contract-replay-proof']);
assertEqual('text command exits zero', 0, textRun.status);
assertEqual('text command emits no stderr', '', textRun.stderr);
assert('text summary title present', textRun.stdout.includes('Claude Code Hook-Contract Replay Proof v1'));
assert('text summary names command', textRun.stdout.includes('Command: zlar claude-code-hook-contract-replay-proof'));
assert('text summary states evidence model', textRun.stdout.includes('Evidence model: local-fixture-hook-contract-replay'));
assert('text summary says live app passage false', textRun.stdout.includes('live_app_passage=false'));
assert('text summary names local replay layer', textRun.stdout.includes('local Claude-shaped PreToolUse replay'));
assert('text summary names denied effect non-execution', textRun.stdout.includes('denied_effect_not_executed=true'));
assert('text summary preserves non-claims', textRun.stdout.includes('not live Claude app passage'));
assert('text summary includes source-state boundary', textRun.stdout.includes(CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SOURCE_STATE_BOUNDARY));
assert('text summary does not retain wrong-event wording', !/wrong[-_ ]hook|wrong[-_ ]event|wrong hook event/i.test(textRun.stdout));
for (const expected of REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES) {
  assert(`text summary includes case ${expected.case_id}`, textRun.stdout.includes(expected.case_id));
}
assert('text output privacy safe', !unsafeOutputPattern.test(textRun.stdout));

section('json command');
const jsonRun = runZlar(['claude-code-hook-contract-replay-proof', '--json']);
assertEqual('json command exits zero', 0, jsonRun.status);
assertEqual('json command emits no stderr', '', jsonRun.stderr);
assert('json output privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report validates', assertClaudeCodeHookContractReplayProof(report));
assertEqual('json proof type', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_TYPE, report.proof_type);
assertEqual('json command field', 'zlar claude-code-hook-contract-replay-proof', report.command);
assertEqual('json evidence model', 'local-fixture-hook-contract-replay', report.evidence_model);
assertEqual('json adapter source repo', 'repo', report.adapter_source);
assertEqual('json contract hash bound', claudeCodeHookContractReplayContractSha256(), report.hook_replay_contract_sha256);
assertEqual('json adapter hash bound', claudeCodeHookContractReplayRepoAdapterSha256(), report.adapter_sha256);
assertEqual('json source-state boundary exact', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SOURCE_STATE_BOUNDARY, report.source_state_boundary);
assert('json output does not retain wrong-event wording', !/wrong[-_ ]hook|wrong[-_ ]event|wrong hook event/i.test(jsonRun.stdout));
assertEqual('json live claude false', false, report.live_claude_invoked);
assertEqual('json live app passage false', false, report.live_claude_app_passage_proven);
assertEqual('json current-machine governance false', false, report.current_machine_governance_proven);
assertEqual('json live receipt false', false, report.live_receipt_emission_proven);
assertEqual('json production downstream false', false, report.production_downstream_recognition_proven);
assertEqual('json denied effect not executed', true, report.summary.denied_effect_not_executed);
assertEqual('json missing gate failed closed', true, report.summary.missing_gate_failed_closed);
assertEqual('json blank gate failed closed', true, report.summary.blank_gate_response_failed_closed);
assertEqual('json malformed output refused', true, report.summary.malformed_output_refused);
assertEqual('json non-PreToolUse payload denied by fixture gate', true, report.summary.non_pretooluse_payload_denied_by_fixture_gate);
assertEqual('json supporting local boarding passed', true, report.supporting_local_boarding_proof.passed);
assertEqual('json supporting local boarding v1 identity verified', true, report.supporting_local_boarding_proof.v1_receipt_identity_verified);
assertEqual('json supporting local boarding refusal consequence absent', true, report.supporting_local_boarding_proof.consequence_absent_on_every_refusal);
assertEqual('json supporting local boarding acceptance consequence once', true, report.supporting_local_boarding_proof.consequence_present_exactly_once_on_acceptance);
assertEqual('json supporting local boarding legacy v0 not boarding', false, report.supporting_local_boarding_proof.legacy_v0_recognized_boarding_identity);
assert('json omits raw sentinel target path', !jsonRun.stdout.includes('sentinel-target'));
assert('json omits key material', !jsonRun.stdout.includes('BEGIN PRIVATE KEY') && !jsonRun.stdout.includes('BEGIN PUBLIC KEY'));

section('explicit repo adapter source');
const repoRun = runZlar(['claude-code-hook-contract-replay-proof', '--adapter-source', 'repo', '--json']);
assertEqual('explicit repo source exits zero', 0, repoRun.status);
assertEqual('explicit repo source emits no stderr', '', repoRun.stderr);
const repoReport = JSON.parse(repoRun.stdout);
assertEqual('explicit repo adapter source', 'repo', repoReport.adapter_source);

section('help and fail closed command handling');
const helpRun = runZlar(['claude-code-hook-contract-replay-proof', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assert('help names usage', helpRun.stderr.includes('Usage: zlar claude-code-hook-contract-replay-proof [--json] [--adapter-source repo|installed]'));
assert('help states built-in fixtures only', helpRun.stderr.includes('built-in fixtures only'));
assert('help states no live Claude prompts', helpRun.stderr.includes('live Claude prompts'));
assertEqual('help emits no stdout', '', helpRun.stdout);

for (const args of [
  ['claude-code-hook-contract-replay-proof', '--fixture', 'hook.json'],
  ['claude-code-hook-contract-replay-proof', '--input', 'hook.json'],
  ['claude-code-hook-contract-replay-proof', '--live'],
  ['claude-code-hook-contract-replay-proof', '--adapter-source', 'installed'],
]) {
  const unsupported = runZlar(args);
  assert(`unsupported option exits usage error: ${args.slice(1).join(' ')}`, unsupported.status !== 0);
  assert(`unsupported option emits no report: ${args.slice(1).join(' ')}`, unsupported.stdout === '');
  assert(`unsupported option emits usage/error: ${args.slice(1).join(' ')}`, unsupported.stderr.includes('ERROR:'));
  assert(`unsupported option privacy safe: ${args.slice(1).join(' ')}`, !unsafeOutputPattern.test(unsupported.stderr));
}

const helpList = runZlar(['help']);
assertEqual('main help exits zero', 0, helpList.status);
assert('main help lists hook-contract replay proof', helpList.stdout.includes('claude-code-hook-contract-replay-proof'));

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
