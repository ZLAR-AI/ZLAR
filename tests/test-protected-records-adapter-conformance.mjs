#!/usr/bin/env node

import {
  NON_CLAIMS,
  PROTECTED_RECORDS_ADAPTER_CONFORMANCE_PROOF_TYPE,
  REQUIRED_CONFORMANCE_CASES,
  SAFE_CLAIM_CEILING,
  assertNoUnsafeProtectedRecordsAdapterConformanceText,
  assertProtectedRecordsAdapterConformanceProof,
  formatProtectedRecordsAdapterConformanceSummary,
  runProtectedRecordsAdapterConformanceProof,
} from '../lib/protected-records-adapter-conformance.mjs';
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

function conformanceCase(report, caseId) {
  return report.cases.find((item) => item.case_id === caseId);
}

section('adapter conformance proof report');
const report = runProtectedRecordsAdapterConformanceProof();
assert('valid report passes validation', assertProtectedRecordsAdapterConformanceProof(report));
assertEqual('proof type', PROTECTED_RECORDS_ADAPTER_CONFORMANCE_PROOF_TYPE, report.proof_type);
assertEqual('safe claim ceiling exact', SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('local disposable evidence', 'local-disposable-cli-process-fixture', report.evidence_model);
assertEqual('no live probing', false, report.live_probing);
assertEqual('case count', REQUIRED_CONFORMANCE_CASES.length, report.cases.length);

section('conformance profile');
assertEqual('profile id', 'protected-records-cli-process-conformance', report.conformance_profile.profile_id);
assertEqual('action class', 'records.write', report.conformance_profile.action_class);
assertEqual('adapter type', PROTECTED_RECORDS_ADAPTER_TYPE, report.conformance_profile.adapter_type);
assertEqual('adapter command', 'zlar protected-records-write --input <file|->', report.conformance_profile.adapter_command);
assertEqual('process boundary', 'separate-cli-process', report.conformance_profile.adapter_process_boundary);
assertEqual('input model', 'supplied-json-fixture', report.conformance_profile.input_model);
assertEqual('fixture mode required', true, report.conformance_profile.fixture_mode_required);
assertEqual('mutation route', 'receipt-recognition-before-ledger-append', report.conformance_profile.mutation_authoritative_route);
assertEqual('result type', PROTECTED_RECORDS_WRITE_RESULT_TYPE, report.conformance_profile.result_type);
assertEqual('ledger model', 'bounded-jsonl-ledger-entry', report.conformance_profile.ledger_model);
assertEqual('persistent store', 'persistent-single-use-receipt-id-store', report.conformance_profile.consumed_receipt_store);
assertEqual('replay scope', 'per-adapter-consumed-receipt-store', report.conformance_profile.replay_scope);

section('process-boundary cases');
const accepted = conformanceCase(report, 'recognized_write_first_process');
assert('accepted case present', Boolean(accepted));
assertEqual('accepted process 1', 1, accepted.process_invocation);
assertEqual('accepted is separate process boundary', 'separate-cli-process', accepted.process_boundary);
assertEqual('accepted exits zero', 0, accepted.exit_status);
assertEqual('accepted emits json', true, accepted.stdout_json_emitted);
assertEqual('accepted stderr empty', true, accepted.stderr_empty);
assertEqual('accepted write true', true, accepted.write_accepted);
assertEqual('accepted reason', 'recognized', accepted.reason_code);
assertEqual('accepted ledger delta', 1, accepted.ledger_entry_count_delta);
assertEqual('accepted consumed count', 1, accepted.consumed_receipt_count);
assertEqual('accepted store exists', true, accepted.consumed_store_exists_after);

const replay = conformanceCase(report, 'replay_refused_after_process_restart');
assert('replay case present', Boolean(replay));
assertEqual('replay process 2', 2, replay.process_invocation);
assertEqual('replay is second process', true, replay.separate_process_from_accepted);
assertEqual('replay exits zero', 0, replay.exit_status);
assertEqual('replay refused', false, replay.write_accepted);
assertEqual('replay reason', 'receipt_replay', replay.reason_code);
assertEqual('replay ledger delta', 0, replay.ledger_entry_count_delta);
assertEqual('replay leaves ledger one', 1, replay.ledger_entry_count_after);
assertEqual('replay consumed count', 1, replay.consumed_receipt_count);

const missing = conformanceCase(report, 'missing_receipt_refused_before_append');
assert('missing receipt case present', Boolean(missing));
assertEqual('missing exits zero', 0, missing.exit_status);
assertEqual('missing refused', false, missing.write_accepted);
assertEqual('missing reason', 'receipt_missing', missing.reason_code);
assertEqual('missing ledger delta', 0, missing.ledger_entry_count_delta);
assertEqual('missing consumed count', 0, missing.consumed_receipt_count);

const sideDoor = conformanceCase(report, 'unsupported_direct_write_option_refused');
assert('side-door case present', Boolean(sideDoor));
assertEqual('side-door process 4', 4, sideDoor.process_invocation);
assert('side-door exits nonzero', sideDoor.exit_status !== 0);
assertEqual('side-door emits no json', false, sideDoor.stdout_json_emitted);
assertEqual('side-door stderr not empty', false, sideDoor.stderr_empty);
assertEqual('side-door refused', false, sideDoor.write_accepted);
assertEqual('side-door reason', 'unsupported_option', sideDoor.reason_code);
assertEqual('side-door ledger delta', 0, sideDoor.ledger_entry_count_delta);
assertEqual('side-door attempted', true, sideDoor.side_door_attempted);

section('open-boundary honesty');
assertEqual('cli direct-write option unavailable', false, report.side_door_report.cli_direct_write_option_available);
assertEqual('direct filesystem side door not closed', false, report.side_door_report.direct_filesystem_write_to_fixture_paths_closed);
assertEqual('live records not checked', false, report.side_door_report.live_records_system_checked);
assertEqual('production adapter not checked', false, report.side_door_report.production_records_adapter_checked);
assertEqual('unrouted records not checked', false, report.side_door_report.unrouted_records_paths_checked);
assertEqual('no live adapter claim', false, report.side_door_report.live_records_adapter);
for (const boundary of [
  'direct_filesystem_write_to_supplied_fixture_paths',
  'live_records_system',
  'production_records_adapter',
  'unrouted_records_paths',
]) {
  assert(`open boundary present: ${boundary}`, report.known_open_boundaries.includes(boundary));
}
for (const claim of NON_CLAIMS) {
  assert(`non-claim present: ${claim}`, report.non_claims.includes(claim));
}

section('safe output formatting');
const summary = formatProtectedRecordsAdapterConformanceSummary(report);
assert('summary title present', summary.includes('ZLAR Protected Records Adapter Conformance Proof v1'));
assert('summary includes process boundary', summary.includes('process_boundary=separate-cli-process'));
assert('summary includes accepted write', summary.includes('Recognized write: accepted=true; reason=recognized; ledger_delta=1'));
assert('summary includes replay process restart', summary.includes('Replay after process restart: accepted=false; reason=receipt_replay; ledger_delta=0; separate_process=true'));
assert('summary includes side-door boundary', summary.includes('direct_filesystem_write_to_fixture_paths_closed=false'));
assert('summary output is privacy safe', assertNoUnsafeProtectedRecordsAdapterConformanceText(summary));
const jsonText = JSON.stringify(report, null, 2);
assert('json output is privacy safe', assertNoUnsafeProtectedRecordsAdapterConformanceText(jsonText));
assert('json omits raw record id', !jsonText.includes('fixture-record-001'));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonText));
assert('json omits private and temp paths', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(jsonText));

section('fail closed validation');
const liveProbeClaim = structuredClone(report);
liveProbeClaim.live_probing = true;
assertThrows('live probing claim fails', () => assertProtectedRecordsAdapterConformanceProof(liveProbeClaim), 'must not perform live probing');

const missingCase = structuredClone(report);
missingCase.cases = missingCase.cases.filter((item) => item.case_id !== 'replay_refused_after_process_restart');
assertThrows('missing replay case fails', () => assertProtectedRecordsAdapterConformanceProof(missingCase), 'case count');

const acceptedDoesNotAppend = structuredClone(report);
conformanceCase(acceptedDoesNotAppend, 'recognized_write_first_process').ledger_entry_count_delta = 0;
assertThrows('accepted no append fails', () => assertProtectedRecordsAdapterConformanceProof(acceptedDoesNotAppend), 'ledger delta');

const replayAppends = structuredClone(report);
conformanceCase(replayAppends, 'replay_refused_after_process_restart').ledger_entry_count_delta = 1;
conformanceCase(replayAppends, 'replay_refused_after_process_restart').ledger_entry_count_after = 2;
assertThrows('replay append fails', () => assertProtectedRecordsAdapterConformanceProof(replayAppends), 'replay case');

const directFilesystemClosedClaim = structuredClone(report);
directFilesystemClosedClaim.side_door_report.direct_filesystem_write_to_fixture_paths_closed = true;
assertThrows('direct filesystem closure claim fails', () => assertProtectedRecordsAdapterConformanceProof(directFilesystemClosedClaim), 'side-door report');

const liveAdapterClaim = structuredClone(report);
liveAdapterClaim.side_door_report.live_records_adapter = true;
assertThrows('live adapter claim fails', () => assertProtectedRecordsAdapterConformanceProof(liveAdapterClaim), 'side-door report');

const missingOpenBoundary = structuredClone(report);
missingOpenBoundary.known_open_boundaries = missingOpenBoundary.known_open_boundaries.filter((item) => item !== 'production_records_adapter');
assertThrows('missing open boundary fails', () => assertProtectedRecordsAdapterConformanceProof(missingOpenBoundary), 'open boundary');

const unsupportedOptionAccepted = structuredClone(report);
conformanceCase(unsupportedOptionAccepted, 'unsupported_direct_write_option_refused').exit_status = 0;
assertThrows('unsupported option acceptance fails', () => assertProtectedRecordsAdapterConformanceProof(unsupportedOptionAccepted), 'side-door case');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
