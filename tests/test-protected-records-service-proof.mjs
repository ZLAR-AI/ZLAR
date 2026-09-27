#!/usr/bin/env node

import {
  NON_CLAIMS,
  PROTECTED_RECORDS_SERVICE_PROOF_TYPE,
  REQUIRED_SERVICE_CASES,
  SAFE_CLAIM_CEILING,
  assertNoUnsafeProtectedRecordsServiceProofText,
  assertProtectedRecordsServiceProof,
  formatProtectedRecordsServiceProofSummary,
  runProtectedRecordsServiceProof,
} from '../lib/protected-records-service-proof.mjs';
import {
  PROTECTED_RECORDS_SERVICE_RESULT_TYPE,
  PROTECTED_RECORDS_SERVICE_TYPE,
} from '../lib/protected-records-service.mjs';

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

function proofCase(report, caseId) {
  return report.cases.find((item) => item.case_id === caseId);
}

section('service proof report');
const report = runProtectedRecordsServiceProof();
assert('valid report passes validation', assertProtectedRecordsServiceProof(report));
assertEqual('proof type', PROTECTED_RECORDS_SERVICE_PROOF_TYPE, report.proof_type);
assertEqual('safe claim ceiling exact', SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('local disposable evidence', 'local-disposable-service-process-fixture', report.evidence_model);
assertEqual('no live probing', false, report.live_probing);
assertEqual('case count', REQUIRED_SERVICE_CASES.length, report.cases.length);

section('service profile');
assertEqual('profile id', 'protected-records-downstream-service-fixture', report.service_profile.profile_id);
assertEqual('action class', 'records.write', report.service_profile.action_class);
assertEqual('service type', PROTECTED_RECORDS_SERVICE_TYPE, report.service_profile.service_type);
assertEqual('service command', 'zlar protected-records-service-request --input <file|->', report.service_profile.service_command);
assertEqual('process boundary', 'separate-cli-process', report.service_profile.service_process_boundary);
assertEqual('recognition boundary', 'downstream-recognition-before-service-mutation', report.service_profile.recognition_boundary);
assertEqual('mutation route', 'receipt-recognition-before-service-state-append', report.service_profile.mutation_authoritative_route);
assertEqual('result type', PROTECTED_RECORDS_SERVICE_RESULT_TYPE, report.service_profile.result_type);
assertEqual('state model', 'bounded-jsonl-service-state-entry', report.service_profile.state_model);
assertEqual('persistent store', 'persistent-single-use-receipt-id-store', report.service_profile.consumed_receipt_store);
assertEqual('replay scope', 'per-service-consumed-receipt-store', report.service_profile.replay_scope);
assertEqual('direct api model', 'no-receipt-direct-api-attempt-refuses-before-mutation', report.service_profile.direct_api_request_model);

section('process-boundary service cases');
const accepted = proofCase(report, 'recognized_service_write_first_process');
assert('accepted case present', Boolean(accepted));
assertEqual('accepted process 1', 1, accepted.process_invocation);
assertEqual('accepted exits zero', 0, accepted.exit_status);
assertEqual('accepted emits json', true, accepted.stdout_json_emitted);
assertEqual('accepted stderr empty', true, accepted.stderr_empty);
assertEqual('accepted write true', true, accepted.service_write_accepted);
assertEqual('accepted reason', 'recognized', accepted.reason_code);
assertEqual('accepted state delta', 1, accepted.state_entry_count_delta);
assertEqual('accepted consumed count', 1, accepted.consumed_receipt_count);
assertEqual('accepted store exists', true, accepted.consumed_store_exists_after);

const replay = proofCase(report, 'replay_refused_after_service_restart');
assert('replay case present', Boolean(replay));
assertEqual('replay process 2', 2, replay.process_invocation);
assertEqual('replay is second process', true, replay.separate_process_from_accepted);
assertEqual('replay refused', false, replay.service_write_accepted);
assertEqual('replay reason', 'receipt_replay', replay.reason_code);
assertEqual('replay state delta', 0, replay.state_entry_count_delta);
assertEqual('replay leaves state one', 1, replay.state_entry_count_after);
assertEqual('replay consumed count', 1, replay.consumed_receipt_count);

const missing = proofCase(report, 'missing_receipt_refused_before_service_mutation');
assert('missing receipt case present', Boolean(missing));
assertEqual('missing refused', false, missing.service_write_accepted);
assertEqual('missing reason', 'receipt_missing', missing.reason_code);
assertEqual('missing state delta', 0, missing.state_entry_count_delta);
assertEqual('missing consumed count', 0, missing.consumed_receipt_count);

const unrecognized = proofCase(report, 'unrecognized_receipt_refused_before_service_mutation');
assert('unrecognized case present', Boolean(unrecognized));
assertEqual('unrecognized refused', false, unrecognized.service_write_accepted);
assertEqual('unrecognized reason', 'detail_hash_mismatch', unrecognized.reason_code);
assertEqual('unrecognized state delta', 0, unrecognized.state_entry_count_delta);

const invalid = proofCase(report, 'invalid_receipt_refused_before_service_mutation');
assert('invalid receipt case present', Boolean(invalid));
assertEqual('invalid receipt refused', false, invalid.service_write_accepted);
assertEqual('invalid receipt reason', 'receipt_invalid', invalid.reason_code);
assertEqual('invalid receipt state delta', 0, invalid.state_entry_count_delta);
assertEqual('invalid receipt consumed count', 0, invalid.consumed_receipt_count);

const unknownIssuer = proofCase(report, 'unknown_issuer_refused_before_service_mutation');
assert('unknown issuer case present', Boolean(unknownIssuer));
assertEqual('unknown issuer refused', false, unknownIssuer.service_write_accepted);
assertEqual('unknown issuer reason', 'unknown_issuer', unknownIssuer.reason_code);
assertEqual('unknown issuer state delta', 0, unknownIssuer.state_entry_count_delta);
assertEqual('unknown issuer consumed count', 0, unknownIssuer.consumed_receipt_count);

const stale = proofCase(report, 'stale_receipt_refused_before_service_mutation');
assert('stale receipt case present', Boolean(stale));
assertEqual('stale receipt refused', false, stale.service_write_accepted);
assertEqual('stale receipt reason', 'receipt_stale', stale.reason_code);
assertEqual('stale receipt state delta', 0, stale.state_entry_count_delta);
assertEqual('stale receipt consumed count', 0, stale.consumed_receipt_count);

const directApi = proofCase(report, 'direct_api_write_without_receipt_refused_before_service_mutation');
assert('direct api case present', Boolean(directApi));
assertEqual('direct api refused', false, directApi.service_write_accepted);
assertEqual('direct api reason', 'receipt_missing', directApi.reason_code);
assertEqual('direct api state delta', 0, directApi.state_entry_count_delta);
assertEqual('direct api attempted', true, directApi.direct_api_attempted);

section('open-boundary honesty');
assertEqual('direct api without receipt refused', true, report.side_door_report.direct_api_without_receipt_refused);
assertEqual('direct filesystem side door not closed', false, report.side_door_report.direct_filesystem_write_to_fixture_paths_closed);
assertEqual('live records not checked', false, report.side_door_report.live_records_system_checked);
assertEqual('production service not checked', false, report.side_door_report.production_records_service_checked);
assertEqual('unrouted records not checked', false, report.side_door_report.unrouted_records_paths_checked);
assertEqual('no live service claim', false, report.side_door_report.live_records_service);
for (const boundary of [
  'direct_filesystem_write_to_supplied_fixture_paths',
  'live_records_system',
  'production_records_service',
  'unrouted_records_paths',
]) {
  assert(`open boundary present: ${boundary}`, report.known_open_boundaries.includes(boundary));
}
for (const claim of NON_CLAIMS) {
  assert(`non-claim present: ${claim}`, report.non_claims.includes(claim));
}

section('safe output formatting');
const summary = formatProtectedRecordsServiceProofSummary(report);
assert('summary title present', summary.includes('ZLAR Protected Records Downstream Service Proof v1'));
assert('summary includes process boundary', summary.includes('process_boundary=separate-cli-process'));
assert('summary includes accepted service write', summary.includes('Recognized service write: accepted=true; reason=recognized; state_delta=1'));
assert('summary includes replay process restart', summary.includes('Replay after service restart: accepted=false; reason=receipt_replay; state_delta=0; separate_process=true'));
assert('summary includes invalid receipt refusal', summary.includes('Invalid receipt: accepted=false; reason=receipt_invalid; state_delta=0'));
assert('summary includes unknown issuer refusal', summary.includes('Unknown issuer: accepted=false; reason=unknown_issuer; state_delta=0'));
assert('summary includes stale receipt refusal', summary.includes('Stale receipt: accepted=false; reason=receipt_stale; state_delta=0'));
assert('summary includes direct api refusal', summary.includes('Fixture service API write without receipt: accepted=false; reason=receipt_missing; state_delta=0; direct_api_attempted=true'));
assert('summary includes side-door boundary', summary.includes('direct_filesystem_write_to_fixture_paths_closed=false'));
assert('summary output is privacy safe', assertNoUnsafeProtectedRecordsServiceProofText(summary));
const jsonText = JSON.stringify(report, null, 2);
assert('json output is privacy safe', assertNoUnsafeProtectedRecordsServiceProofText(jsonText));
assert('json omits raw record id', !jsonText.includes('fixture-record-001'));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonText));
assert('json omits private and temp paths', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(jsonText));

section('fail closed validation');
const liveProbeClaim = structuredClone(report);
liveProbeClaim.live_probing = true;
assertThrows('live probing claim fails', () => assertProtectedRecordsServiceProof(liveProbeClaim), 'must not perform live probing');

const missingCase = structuredClone(report);
missingCase.cases = missingCase.cases.filter((item) => item.case_id !== 'replay_refused_after_service_restart');
assertThrows('missing replay case fails', () => assertProtectedRecordsServiceProof(missingCase), 'case count');

const acceptedDoesNotMutate = structuredClone(report);
proofCase(acceptedDoesNotMutate, 'recognized_service_write_first_process').state_entry_count_delta = 0;
assertThrows('accepted no mutation fails', () => assertProtectedRecordsServiceProof(acceptedDoesNotMutate), 'state delta');

const replayMutates = structuredClone(report);
proofCase(replayMutates, 'replay_refused_after_service_restart').state_entry_count_delta = 1;
proofCase(replayMutates, 'replay_refused_after_service_restart').state_entry_count_after = 2;
assertThrows('replay mutation fails', () => assertProtectedRecordsServiceProof(replayMutates), 'replay case');

const directApiBoards = structuredClone(report);
proofCase(directApiBoards, 'direct_api_write_without_receipt_refused_before_service_mutation').service_write_accepted = true;
assertThrows('direct api boarding fails', () => assertProtectedRecordsServiceProof(directApiBoards), 'direct API case');

const invalidBoards = structuredClone(report);
proofCase(invalidBoards, 'invalid_receipt_refused_before_service_mutation').state_entry_count_delta = 1;
proofCase(invalidBoards, 'invalid_receipt_refused_before_service_mutation').state_entry_count_after = 1;
assertThrows('invalid receipt mutation fails', () => assertProtectedRecordsServiceProof(invalidBoards), 'invalid-receipt case');

const unknownConsumes = structuredClone(report);
proofCase(unknownConsumes, 'unknown_issuer_refused_before_service_mutation').consumed_receipt_count = 1;
assertThrows('unknown issuer consumption fails', () => assertProtectedRecordsServiceProof(unknownConsumes), 'unknown-issuer case');

const staleReasonDrift = structuredClone(report);
proofCase(staleReasonDrift, 'stale_receipt_refused_before_service_mutation').reason_code = 'recognized';
assertThrows('stale reason drift fails', () => assertProtectedRecordsServiceProof(staleReasonDrift), 'stale-receipt case');

const directFilesystemClosedClaim = structuredClone(report);
directFilesystemClosedClaim.side_door_report.direct_filesystem_write_to_fixture_paths_closed = true;
assertThrows('direct filesystem closure claim fails', () => assertProtectedRecordsServiceProof(directFilesystemClosedClaim), 'side-door report');

const liveServiceClaim = structuredClone(report);
liveServiceClaim.side_door_report.live_records_service = true;
assertThrows('live service claim fails', () => assertProtectedRecordsServiceProof(liveServiceClaim), 'side-door report');

const missingOpenBoundary = structuredClone(report);
missingOpenBoundary.known_open_boundaries = missingOpenBoundary.known_open_boundaries.filter((item) => item !== 'production_records_service');
assertThrows('missing open boundary fails', () => assertProtectedRecordsServiceProof(missingOpenBoundary), 'open boundary');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
