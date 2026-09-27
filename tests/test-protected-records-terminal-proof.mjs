#!/usr/bin/env node

import {
  PROTECTED_RECORDS_ADAPTER_PROFILE,
  PROTECTED_RECORDS_ADAPTER_PROFILE_TYPE,
  PROTECTED_RECORDS_PROFILE_CONTRACT,
  PROTECTED_RECORDS_TERMINAL_PROOF_TYPE,
  REQUIRED_REFUSAL_REASONS,
  SAFE_CLAIM_CEILING,
  assertNoUnsafeProtectedRecordsProofText,
  assertProtectedRecordsAdapterProfile,
  assertProtectedRecordsProfileContract,
  assertProtectedRecordsTerminalProof,
  formatProtectedRecordsTerminalProofSummary,
  runProtectedRecordsTerminalProof,
} from '../lib/protected-records-terminal-proof.mjs';
import {
  PROTECTED_RECORDS_ADAPTER_TYPE,
  PROTECTED_RECORDS_WRITE_RESULT_TYPE,
} from '../lib/protected-records-adapter.mjs';

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

section('protected records terminal proof report');
const report = runProtectedRecordsTerminalProof();
assert('valid report passes validation', assertProtectedRecordsTerminalProof(report));
assertEqual('proof type', PROTECTED_RECORDS_TERMINAL_PROOF_TYPE, report.proof_type);
assertEqual('safe claim ceiling exact', SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('local hermetic fixture evidence', 'local-hermetic-fixture', report.evidence_model);
assertEqual('no live probing', false, report.live_probing);
assertEqual('deployment profile', 'protected-records-terminal', report.deployment_profile);
assertEqual('action class', 'records.write', report.action_class);
assertEqual('downstream boundary', 'protected-records-terminal-fixture', report.downstream_boundary);

section('profile contract');
assert('profile contract passes validation', assertProtectedRecordsProfileContract(report.profile_contract));
assertEqual('profile contract id', PROTECTED_RECORDS_PROFILE_CONTRACT.profile_id, report.profile_contract.profile_id);
assertEqual('profile contract checkpoint', 'downstream-recognition-rule', report.profile_contract.checkpoint);
assertEqual('profile contract route', 'receipt-recognition-before-record-write', report.profile_contract.route);
assertEqual('profile contract downstream effect', 'append-protected-records-ledger-entry', report.profile_contract.downstream_effect);
assertEqual('profile contract replay policy', 'single-use-receipt-id-per-terminal-ledger', report.profile_contract.receipt_replay_policy);
assert('profile contract requires issuer kid', report.profile_contract.required_receipt_fields.includes('kid'));
assert('profile contract requires payload detail hash', report.profile_contract.required_receipt_fields.includes('payload.detail_hash'));
assert('profile contract accepts active issuer status only', report.profile_contract.accepted_issuer_statuses.length === 1 && report.profile_contract.accepted_issuer_statuses[0] === 'active');
assert('profile contract accepts records domain', report.profile_contract.accepted_domains.includes('records'));
assert('profile contract accepts records.write tool', report.profile_contract.accepted_tools.includes('records.write'));
assert('profile contract accepts allow outcome', report.profile_contract.accepted_outcomes.includes('allow'));
assert('profile contract names live records side door', report.profile_contract.known_ungoverned_boundaries.includes('live_records_system'));

section('adapter deployment profile');
assert('adapter profile passes validation', assertProtectedRecordsAdapterProfile(report.adapter_profile));
assertEqual('adapter profile type', PROTECTED_RECORDS_ADAPTER_PROFILE_TYPE, report.adapter_profile.profile_type);
assertEqual('adapter profile id', PROTECTED_RECORDS_ADAPTER_PROFILE.profile_id, report.adapter_profile.profile_id);
assertEqual('adapter profile basis contract', PROTECTED_RECORDS_PROFILE_CONTRACT.profile_id, report.adapter_profile.basis_profile_contract_id);
assertEqual('adapter profile environment', 'local-hermetic-adapter-harness', report.adapter_profile.environment_model);
assertEqual('adapter profile authoritative route', 'receipt-recognition-before-ledger-append', report.adapter_profile.authoritative_route);
assertEqual('adapter profile boundary', 'protected-records-adapter-harness', report.adapter_profile.adapter_boundary);
assertEqual('adapter profile ledger model', 'append-only-jsonl-ledger', report.adapter_profile.ledger_model);
assertEqual('adapter profile consumed receipt store', 'single-use-receipt-id-store', report.adapter_profile.consumed_receipt_store);
assertEqual('adapter profile replay scope', 'per-adapter-ledger', report.adapter_profile.replay_scope);
assertEqual('adapter profile refuses before effect', true, report.adapter_profile.refusal_before_effect);
assert('adapter profile names fixture closed route', report.adapter_profile.closed_in_fixture.includes('direct_fixture_ledger_mutation'));
assert('adapter profile names production side door', report.adapter_profile.known_open_boundaries.includes('production_records_adapter'));
assert('adapter profile keeps live adapter non-claim', report.adapter_profile.non_claims.some((claim) => claim.includes('does not prove a live records-system adapter')));

section('adapter harness');
assertEqual('adapter harness type', 'protected-records-adapter-harness-v1', report.adapter_harness.harness_type);
assertEqual('adapter harness fixture environment', 'local-hermetic-fixture', report.adapter_harness.environment_model);
assertEqual('adapter harness recognition boundary', 'downstream-recognition-rule', report.adapter_harness.recognition_boundary);
assertEqual('adapter harness boundary', 'protected-records-adapter-harness', report.adapter_harness.adapter_boundary);
assertEqual('adapter harness ledger model', 'append-only-jsonl-ledger', report.adapter_harness.ledger_model);
assertEqual('adapter harness consumed receipt store', 'single-use-receipt-id-store', report.adapter_harness.consumed_receipt_store);
assertEqual('adapter harness replay scope', 'per-adapter-ledger', report.adapter_harness.replay_scope);
assertEqual('adapter harness direct write closed', false, report.adapter_harness.direct_write_path_available);
assertEqual('adapter harness no live adapter claim', false, report.adapter_harness.live_records_adapter);
assertEqual('adapter harness all mutations recognized', true, report.adapter_harness.all_mutations_through_recognition_boundary);
assertEqual('adapter harness refuses before effect', true, report.adapter_harness.refusal_before_effect);
assertEqual('adapter harness final ledger entries', 1, report.adapter_harness.final_ledger_entry_count);
assertEqual('adapter harness consumed receipt count', 1, report.adapter_harness.consumed_receipt_count);

section('adapter action');
assertEqual('adapter action type', PROTECTED_RECORDS_ADAPTER_TYPE, report.adapter_action.action_type);
assertEqual('adapter action command', 'zlar protected-records-write --input <file|->', report.adapter_action.command);
assertEqual('adapter action input model', 'supplied-json-fixture', report.adapter_action.input_model);
assertEqual('adapter action result type', PROTECTED_RECORDS_WRITE_RESULT_TYPE, report.adapter_action.result_type);
assertEqual('adapter action requires fixture mode', true, report.adapter_action.fixture_mode_required);
assertEqual('adapter action write model', 'bounded-jsonl-ledger-entry', report.adapter_action.writes);
assertEqual('adapter action no live adapter claim', false, report.adapter_action.live_records_adapter);
assertEqual('adapter action omits raw record detail output', false, report.adapter_action.raw_record_detail_output);

section('recognized receipt changes protected record');
assertEqual('recognized write case id', 'recognized_write', report.recognized_write.case_id);
assertEqual('recognized write accepted', true, report.recognized_write.write_accepted);
assertEqual('recognized record changed', true, report.recognized_write.record_changed);
assertEqual('recognized decision accepts', 'accept', report.recognized_write.decision);
assertEqual('recognized reason', 'recognized', report.recognized_write.reason_code);
assertEqual('one protected record write', 1, report.recognized_write.record_count_delta);

section('unrecognized and replayed receipts do not change record');
assertEqual('eleven refusal cases', 11, report.refusals.length);
for (const reason of REQUIRED_REFUSAL_REASONS) {
  assert(`required refusal reason present: ${reason}`, report.refusals.some((item) => item.reason_code === reason));
}
const replayRefusal = report.refusals.find((item) => item.reason_code === 'receipt_replay');
assertEqual('replay case id', 'replayed_receipt', replayRefusal?.case_id);
assertEqual('replayed receipt refused', false, replayRefusal?.write_accepted);
assertEqual('replayed receipt record delta zero', 0, replayRefusal?.record_count_delta);
assert('all refusals reject write', report.refusals.every((item) => item.write_accepted === false));
assert('all refusals keep record unchanged', report.refusals.every((item) => item.record_changed === false));
assert('all refusals decide refuse', report.refusals.every((item) => item.decision === 'refuse'));
assert('all refusals write no record event', report.refusals.every((item) => item.record_count_delta === 0));

section('terminal evidence remains bounded');
assertEqual('terminal final record count', 1, report.terminal.final_record_count);
assertEqual('terminal contains bounded receipt id', true, report.terminal.receipt_id_present);
assertEqual('terminal omits raw record id', false, report.terminal.raw_record_id_present);
assertEqual('terminal omits public key', false, report.terminal.public_key_present);
assertEqual('terminal omits private key', false, report.terminal.private_key_present);

section('safe output formatting');
const summary = formatProtectedRecordsTerminalProofSummary(report);
assert('summary title present', summary.includes('Protected Records Terminal Proof v1'));
assert('summary includes deployment profile', summary.includes('Deployment profile: protected-records-terminal'));
assert('summary includes profile contract route', summary.includes('route=receipt-recognition-before-record-write'));
assert('summary includes adapter profile route', summary.includes('Adapter profile: type=protected-records-adapter-profile-v1; id=protected-records-adapter-profile; authoritative_route=receipt-recognition-before-ledger-append'));
assert('summary includes adapter harness', summary.includes('Adapter harness: ledger_model=append-only-jsonl-ledger; consumed_receipt_store=single-use-receipt-id-store; replay_scope=per-adapter-ledger'));
assert('summary includes adapter action', summary.includes('Adapter action: command=zlar protected-records-write --input <file|->; result_type=protected-records-write-result-v1; fixture_mode_required=true'));
assert('summary includes replay policy', summary.includes('Replay policy: single-use-receipt-id-per-terminal-ledger'));
assert('summary includes required receipt fields', summary.includes('Required receipt fields: v,id,kid'));
assert('summary includes known side doors', summary.includes('Known ungoverned boundaries: live_records_system,production_records_adapter,unrouted_records_paths'));
assert('summary includes recognized write', summary.includes('- recognized_write: accept; record_delta=1'));
for (const reason of REQUIRED_REFUSAL_REASONS) {
  assert(`summary includes refusal reason: ${reason}`, summary.includes(reason));
}
assert('summary states non-claim boundary', summary.includes('does not inspect a live records system'));
assert('summary output is privacy safe', assertNoUnsafeProtectedRecordsProofText(summary));

const jsonText = JSON.stringify(report, null, 2);
assert('json output is privacy safe', assertNoUnsafeProtectedRecordsProofText(jsonText));
assert('json omits raw record id', !jsonText.includes('fixture-record-001'));
assert('json omits public key material', !jsonText.includes('BEGIN PUBLIC KEY'));
assert('json omits private key material', !jsonText.includes('BEGIN PRIVATE KEY'));
assert('json omits private and temp paths', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(jsonText));

section('fail closed validation');
const liveProbeClaim = structuredClone(report);
liveProbeClaim.live_probing = true;
assertThrows('live probing claim fails', () => assertProtectedRecordsTerminalProof(liveProbeClaim), 'must not perform live probing');

const changedRefusal = structuredClone(report);
changedRefusal.refusals[0].record_changed = true;
assertThrows('changed refusal fails', () => assertProtectedRecordsTerminalProof(changedRefusal), 'changed the record unexpectedly');

const missingReason = structuredClone(report);
missingReason.refusals = missingReason.refusals.filter((item) => item.reason_code !== 'unknown_issuer');
assertThrows('missing required refusal reason fails', () => assertProtectedRecordsTerminalProof(missingReason), 'unknown_issuer');

const missingProfileField = structuredClone(report);
delete missingProfileField.profile_contract.route;
assertThrows('missing profile field fails', () => assertProtectedRecordsTerminalProof(missingProfileField), 'unexpected fields');

const driftedProfileRoute = structuredClone(report);
driftedProfileRoute.profile_contract.route = 'monitor-after-record-write';
assertThrows('drifted profile route fails', () => assertProtectedRecordsTerminalProof(driftedProfileRoute), 'route drifted');

const missingAdapterProfileField = structuredClone(report);
delete missingAdapterProfileField.adapter_profile.replay_scope;
assertThrows('missing adapter profile field fails', () => assertProtectedRecordsTerminalProof(missingAdapterProfileField), 'unexpected fields');

const driftedAdapterRoute = structuredClone(report);
driftedAdapterRoute.adapter_profile.authoritative_route = 'monitor-after-ledger-append';
assertThrows('drifted adapter route fails', () => assertProtectedRecordsTerminalProof(driftedAdapterRoute), 'authoritative route drifted');

const openDirectAdapterPath = structuredClone(report);
openDirectAdapterPath.adapter_harness.direct_write_path_available = true;
assertThrows('open adapter direct write path fails', () => assertProtectedRecordsTerminalProof(openDirectAdapterPath), 'direct write path');

const liveAdapterClaim = structuredClone(report);
liveAdapterClaim.adapter_harness.live_records_adapter = true;
assertThrows('live adapter claim fails', () => assertProtectedRecordsTerminalProof(liveAdapterClaim), 'live records adapter');

const driftedAdapterAction = structuredClone(report);
driftedAdapterAction.adapter_action.command = 'zlar protected-records-write --latest';
assertThrows('drifted adapter action command fails', () => assertProtectedRecordsTerminalProof(driftedAdapterAction), 'command drifted');

const liveAdapterActionClaim = structuredClone(report);
liveAdapterActionClaim.adapter_action.live_records_adapter = true;
assertThrows('live adapter action claim fails', () => assertProtectedRecordsTerminalProof(liveAdapterActionClaim), 'live records adapter');

const missingReceiptField = structuredClone(report);
missingReceiptField.profile_contract.required_receipt_fields =
  missingReceiptField.profile_contract.required_receipt_fields.filter((field) => field !== 'payload.detail_hash');
assertThrows('missing required receipt field fails', () => assertProtectedRecordsTerminalProof(missingReceiptField), 'required receipt fields drifted');

const leakedTerminal = structuredClone(report);
leakedTerminal.terminal.public_key_present = true;
assertThrows('public key leakage fails', () => assertProtectedRecordsTerminalProof(leakedTerminal), 'public key');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
