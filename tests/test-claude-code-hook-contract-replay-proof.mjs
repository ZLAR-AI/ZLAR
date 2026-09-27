#!/usr/bin/env node

import {
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_EVIDENCE_MODEL,
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_NON_CLAIMS,
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_TYPE,
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SAFE_CLAIM_CEILING,
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SOURCE_STATE_BOUNDARY,
  REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SIDE_DOORS,
  REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES,
  assertClaudeCodeHookContractReplayProof,
  assertNoUnsafeClaudeCodeHookContractReplayProofText,
  claudeCodeHookContractReplayContractSha256,
  claudeCodeHookContractReplayInputContractSha256,
  claudeCodeHookContractReplayRepoAdapterSha256,
  formatClaudeCodeHookContractReplayProofSummary,
  runClaudeCodeHookContractReplayProof,
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

function caseById(report, caseId) {
  return report.cases.find((item) => item.case_id === caseId);
}

section('local hook-contract replay proof');
const report = runClaudeCodeHookContractReplayProof();
assert('valid report passes validation', assertClaudeCodeHookContractReplayProof(report));
assertEqual('proof type', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_TYPE, report.proof_type);
assertEqual('command', 'zlar claude-code-hook-contract-replay-proof', report.command);
assertEqual('evidence model', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_EVIDENCE_MODEL, report.evidence_model);
assertEqual('adapter source repo', 'repo', report.adapter_source);
assertEqual('adapter path is repo-relative', 'repo:adapters/claude-code/hook.sh', report.adapter_path_claimed);
assert('adapter hash shape', /^[a-f0-9]{64}$/.test(report.adapter_sha256));
assertEqual('adapter hash bound to repo adapter', claudeCodeHookContractReplayRepoAdapterSha256(), report.adapter_sha256);
assertEqual('hook replay contract hash bound', claudeCodeHookContractReplayContractSha256(), report.hook_replay_contract_sha256);
assert('source commit shape', report.source_commit === null || /^[a-f0-9]{40}$/.test(report.source_commit));
assertEqual('source state commit matches source commit', report.source_commit, report.source_state.commit);
assert('source state provenance named', ['clean-commit', 'commit-plus-uncommitted-worktree'].includes(report.source_state.provenance));
assert('source status fingerprint shape', /^[a-f0-9]{64}$/.test(report.source_state.status_sha256));
assertEqual('source state boundary exact', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SOURCE_STATE_BOUNDARY, report.source_state_boundary);
assertEqual('safe claim ceiling exact', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SAFE_CLAIM_CEILING, report.safe_claim_ceiling);

section('strict non-claims');
for (const field of [
  'live_claude_invoked',
  'live_claude_app_passage_proven',
  'app_originated_hook_crossing_proven',
  'installed_hook_configuration_written',
  'current_machine_governance_proven',
  'live_receipt_emission_proven',
  'production_downstream_recognition_proven',
  'all_surface_governance_proven',
  'side_door_closure_proven',
]) {
  assertEqual(`${field} false`, false, report[field]);
}
assertEqual('non-claim count exact', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_NON_CLAIMS.length, report.non_claims.length);
for (const claim of CLAUDE_CODE_HOOK_CONTRACT_REPLAY_NON_CLAIMS) {
  assert(`non-claim present: ${claim.slice(0, 42)}`, report.non_claims.includes(claim));
}
assert('side doors named', report.side_doors.length >= 8);
assert('live Claude side door named', report.side_doors.includes('live Claude Code app-originated hook passage'));
assert('direct shell side door named', report.side_doors.includes('direct shell/filesystem outside Claude Code'));
assertEqual('side doors exact', JSON.stringify(REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SIDE_DOORS), JSON.stringify(report.side_doors));

section('fixture contract');
assertEqual('fixture contract type', 'zlar-claude-code-hook-contract-replay-fixture-v1', report.fixture_contract.fixture_contract_type);
assertEqual('copied adapter model', 'copied-adapter-in-proof-owned-install-shaped-fixture-root', report.fixture_contract.adapter_invocation_model);
assertEqual('no arbitrary external fixture paths', false, report.fixture_contract.arbitrary_external_fixture_paths_allowed);
assertEqual('no live Claude contact', false, report.fixture_contract.live_claude_contact_allowed);
assertEqual('no real ZLAR audit paths written', false, report.fixture_contract.real_zlar_audit_paths_written);
assertEqual('no real worker receipt paths written', false, report.fixture_contract.real_zlar_worker_receipt_paths_written);

section('required cases');
assertEqual('case count', REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES.length, report.cases.length);
for (const expected of REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES) {
  const item = caseById(report, expected.case_id);
  assert(`case present: ${expected.case_id}`, Boolean(item));
  assertEqual(`case result: ${expected.case_id}`, expected.expected_case_result, item.case_result);
  assertEqual(`adapter exit: ${expected.case_id}`, expected.expected_adapter_exit, item.adapter_exit_code);
  assertEqual(`permission decision: ${expected.case_id}`, expected.expected_permission_decision, item.permission_decision);
  assert(`stdout hash shape: ${expected.case_id}`, /^[a-f0-9]{64}$/.test(item.stdout_sha256));
  assert(`stderr hash shape: ${expected.case_id}`, /^[a-f0-9]{64}$/.test(item.stderr_sha256));
  assert(`input hash shape: ${expected.case_id}`, /^[a-f0-9]{64}$/.test(item.input_sha256));
  assert(`input contract hash shape: ${expected.case_id}`, /^[a-f0-9]{64}$/.test(item.input_contract_sha256));
  assertEqual(
    `input contract hash bound: ${expected.case_id}`,
    claudeCodeHookContractReplayInputContractSha256(expected.case_id),
    item.input_contract_sha256
  );
}

const allow = caseById(report, 'allow_pwd_hook_json');
assertEqual('allow is valid hook JSON', true, allow.valid_claude_hook_json);
assertEqual('allow hook event', 'PreToolUse', allow.hook_event_name);
assertEqual('allow decision', 'allow', allow.permission_decision);
assertEqual('allow stderr empty', true, allow.stderr_empty);

const deny = caseById(report, 'deny_destructive_sentinel_hook_json');
assertEqual('deny is valid hook JSON', true, deny.valid_claude_hook_json);
assertEqual('deny hook event', 'PreToolUse', deny.hook_event_name);
assertEqual('deny decision', 'deny', deny.permission_decision);
assertEqual('deny reason present', true, deny.permission_decision_reason_present);
assertEqual('deny refused before effect', true, deny.refused_before_effect);
assertEqual('deny sentinel unchanged', true, deny.sentinel_unchanged);
assertEqual('deny effect not executed', false, deny.denied_effect_executed);
assertEqual('sentinel unchanged summary', true, report.sentinel.unchanged);
assertEqual('sentinel effect not executed', false, report.sentinel.denied_effect_executed);
assertEqual('sentinel hash stable', report.sentinel.before_sha256, report.sentinel.after_sha256);

const noExec = caseById(report, 'adapter_does_not_execute_tool_input');
assertEqual('adapter does not execute command', false, report.marker.tool_input_command_executed);
assertEqual('no-exec marker absent', false, report.marker.after_exists);
assertEqual('no-exec fixture passes', 'passed', noExec.case_result);

const missingGate = caseById(report, 'missing_gate_fails_closed');
assertEqual('missing gate denied', 'deny', missingGate.permission_decision);
assertEqual('missing gate valid hook JSON', true, missingGate.valid_claude_hook_json);

const blankGate = caseById(report, 'blank_gate_response_fails_closed');
assertEqual('blank gate denied', 'deny', blankGate.permission_decision);
assertEqual('blank gate valid hook JSON', true, blankGate.valid_claude_hook_json);

const malformed = caseById(report, 'malformed_output_refused');
assertEqual('malformed output refused', 'refused', malformed.case_result);
assertEqual('malformed stdout invalid', false, malformed.stdout_json_valid);
assertEqual('malformed refusal reason', 'adapter_stdout_not_valid_claude_hook_json', malformed.proof_refusal_reason);

const nonPreToolUse = caseById(report, 'non_pretooluse_payload_denied_by_fixture_gate');
assertEqual('non-PreToolUse fixture refused', 'refused', nonPreToolUse.case_result);
assertEqual('non-PreToolUse fixture denied', 'deny', nonPreToolUse.permission_decision);
assertEqual('non-PreToolUse fixture reason', 'fixture_gate_denied_non_pretooluse_payload', nonPreToolUse.proof_refusal_reason);

section('summary and supporting boarding proof');
for (const requiredTrue of [
  'all_required_cases_present',
  'all_adapter_exits_zero',
  'allow_json_observed',
  'deny_json_observed',
  'denied_effect_not_executed',
  'adapter_did_not_execute_tool_input',
  'missing_gate_failed_closed',
  'blank_gate_response_failed_closed',
  'malformed_output_refused',
  'non_pretooluse_payload_denied_by_fixture_gate',
]) {
  assertEqual(`summary ${requiredTrue}`, true, report.summary[requiredTrue]);
}
for (const requiredFalse of [
  'live_claude_app_passage_proven',
  'app_originated_hook_crossing_proven',
  'live_receipt_emission_proven',
  'current_machine_governance_proven',
  'production_downstream_recognition_proven',
  'side_door_closure_proven',
]) {
  assertEqual(`summary ${requiredFalse}`, false, report.summary[requiredFalse]);
}
assertEqual('supporting proof run', true, report.supporting_local_boarding_proof.run);
assertEqual('supporting proof passed', true, report.supporting_local_boarding_proof.passed);
assertEqual('supporting proof type', 'zlar-protected-records-local-boarding-proof-v1', report.supporting_local_boarding_proof.proof_type);
assertEqual('supporting proof v1 receipt identity verified', true, report.supporting_local_boarding_proof.v1_receipt_identity_verified);
assertEqual('supporting proof refusal consequence absent', true, report.supporting_local_boarding_proof.consequence_absent_on_every_refusal);
assertEqual('supporting proof acceptance consequence exactly once', true, report.supporting_local_boarding_proof.consequence_present_exactly_once_on_acceptance);
assertEqual('supporting proof legacy v0 not boarding identity', false, report.supporting_local_boarding_proof.legacy_v0_recognized_boarding_identity);
assertEqual('supporting no current-machine governance', false, report.supporting_local_boarding_proof.current_machine_governance_proven);
assertEqual('supporting no production downstream', false, report.supporting_local_boarding_proof.production_downstream_recognition_proven);

section('privacy and summary text');
const jsonText = JSON.stringify(report, null, 2);
assert('json output privacy safe', assertNoUnsafeClaudeCodeHookContractReplayProofText(jsonText));
assert('json omits live temp path', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(jsonText));
assert('json omits raw sentinel target path', !jsonText.includes('sentinel-target'));
assert('json omits private key material', !jsonText.includes('BEGIN PRIVATE KEY'));
assert('json omits public key material', !jsonText.includes('BEGIN PUBLIC KEY'));

const summary = formatClaudeCodeHookContractReplayProofSummary(report);
assert('summary title present', summary.includes('Claude Code Hook-Contract Replay Proof v1'));
assert('summary names local replay layer', summary.includes('local Claude-shaped PreToolUse replay'));
assert('summary names non-live app passage', summary.includes('not live Claude app passage'));
assert('summary privacy safe', assertNoUnsafeClaudeCodeHookContractReplayProofText(summary));
assert('report output does not retain wrong-event wording', !/wrong[-_ ]hook|wrong[-_ ]event|wrong hook event/i.test(JSON.stringify(report)));
assert('summary output does not retain wrong-event wording', !/wrong[-_ ]hook|wrong[-_ ]event|wrong hook event/i.test(summary));

section('fail closed validation');
const liveClaim = structuredClone(report);
liveClaim.live_claude_app_passage_proven = true;
assertThrows('live app passage claim fails validation', () => assertClaudeCodeHookContractReplayProof(liveClaim), 'live_claude_app_passage_proven must be false');

const forgedAdapterHash = structuredClone(report);
forgedAdapterHash.adapter_sha256 = '0'.repeat(64);
assertThrows('forged adapter hash fails validation', () => assertClaudeCodeHookContractReplayProof(forgedAdapterHash), 'hook replay contract hash drifted');

const staleContractHash = structuredClone(report);
staleContractHash.hook_replay_contract_sha256 = '0'.repeat(64);
assertThrows('stale contract hash fails validation', () => assertClaudeCodeHookContractReplayProof(staleContractHash), 'hook replay contract hash drifted');

const staleSourceCommit = structuredClone(report);
staleSourceCommit.source_commit = '1'.repeat(40);
assertThrows('stale source commit fails validation', () => assertClaudeCodeHookContractReplayProof(staleSourceCommit), 'source commit does not match source state');

const synchronizedStaleSourceState = structuredClone(report);
synchronizedStaleSourceState.source_commit = '1'.repeat(40);
synchronizedStaleSourceState.source_state = {
  ...synchronizedStaleSourceState.source_state,
  commit: '1'.repeat(40),
};
assertThrows(
  'synchronized stale source metadata fails validation',
  () => assertClaudeCodeHookContractReplayProof(synchronizedStaleSourceState),
  'source state drifted from current local HEAD/status fingerprint'
);

const staleStatusFingerprint = structuredClone(report);
staleStatusFingerprint.source_state.status_sha256 = '0'.repeat(64);
assertThrows(
  'stale source status fingerprint fails validation',
  () => assertClaudeCodeHookContractReplayProof(staleStatusFingerprint),
  'source state drifted from current local HEAD/status fingerprint'
);

const sourceStateBoundaryOverclaim = structuredClone(report);
sourceStateBoundaryOverclaim.source_state_boundary = 'source state proves remote release freshness';
assertThrows(
  'source-state boundary overclaim fails validation',
  () => assertClaudeCodeHookContractReplayProof(sourceStateBoundaryOverclaim),
  'source state boundary drifted'
);

const currentMachine = structuredClone(report);
currentMachine.current_machine_governance_proven = true;
assertThrows('current-machine claim fails validation', () => assertClaudeCodeHookContractReplayProof(currentMachine), 'current_machine_governance_proven must be false');

const realSessionDelta = structuredClone(report);
realSessionDelta.audit_session_worker_receipt_deltas.real_zlar_session_delta = 'changed';
assertThrows('real session delta fails validation', () => assertClaudeCodeHookContractReplayProof(realSessionDelta), 'audit/session/worker receipt boundary drifted');

const caseOverclaim = structuredClone(report);
caseById(caseOverclaim, 'allow_pwd_hook_json').live_claude_app_passage_proven = true;
assertThrows('case overclaim field fails validation', () => assertClaudeCodeHookContractReplayProof(caseOverclaim), 'contains unexpected fields');

const inputContractDrift = structuredClone(report);
caseById(inputContractDrift, 'allow_pwd_hook_json').input_contract_sha256 = '0'.repeat(64);
assertThrows('input contract drift fails validation', () => assertClaudeCodeHookContractReplayProof(inputContractDrift), 'input contract drifted');

const rehashedSemanticDrift = structuredClone(report);
caseById(rehashedSemanticDrift, 'malformed_output_refused').stdout_json_valid = true;
assertThrows('semantic drift fails validation', () => assertClaudeCodeHookContractReplayProof(rehashedSemanticDrift), 'stdout_json_valid drifted');

const summaryOverclaim = structuredClone(report);
summaryOverclaim.summary.live_claude_invoked = true;
assertThrows('summary overclaim field fails validation', () => assertClaudeCodeHookContractReplayProof(summaryOverclaim), 'contains unexpected fields');

const executed = structuredClone(report);
executed.sentinel.denied_effect_executed = true;
assertThrows('sentinel execution fails validation', () => assertClaudeCodeHookContractReplayProof(executed), 'sentinel proof drifted');

const missingCase = structuredClone(report);
missingCase.cases = missingCase.cases.filter((item) => item.case_id !== 'blank_gate_response_fails_closed');
assertThrows('missing required case fails validation', () => assertClaudeCodeHookContractReplayProof(missingCase), 'case count drifted');

const reducedSideDoors = structuredClone(report);
reducedSideDoors.side_doors = reducedSideDoors.side_doors.filter((item) => item !== 'Claude Stop hook and non-PreToolUse surfaces');
assertThrows('reduced side-door list fails validation', () => assertClaudeCodeHookContractReplayProof(reducedSideDoors), 'side_doors drifted');

const reorderedNonClaims = structuredClone(report);
reorderedNonClaims.non_claims = [...reorderedNonClaims.non_claims].reverse();
assertThrows('reordered non-claims fail validation', () => assertClaudeCodeHookContractReplayProof(reorderedNonClaims), 'non_claims drifted');

const unsupportedSource = () => runClaudeCodeHookContractReplayProof({ adapterSource: 'bogus' });
assertThrows('unsupported adapter source refused', unsupportedSource, 'use repo or installed');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
