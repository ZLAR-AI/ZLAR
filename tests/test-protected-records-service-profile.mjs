#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import {
  NON_CLAIMS,
  PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_TYPE,
  PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE,
  PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_TYPE,
  PROTECTED_RECORDS_SERVICE_PROFILE_TYPE,
  REQUIRED_OPEN_BOUNDARIES,
  REQUIRED_PROFILE_PREFLIGHT_CASES,
  SAFE_CLAIM_CEILING,
  assertNoUnsafeProtectedRecordsServiceProfileText,
  assertProtectedRecordsServiceProfile,
  assertProtectedRecordsServiceProfilePreflightArtifact,
  assertProtectedRecordsServiceProfilePreflight,
  buildProtectedRecordsServiceProfilePreflightArtifact,
  formatProtectedRecordsServiceProfilePreflightArtifactSummary,
  formatProtectedRecordsServiceProfilePreflightArtifactVerification,
  formatProtectedRecordsServiceProfilePreflightSummary,
  parseProtectedRecordsServiceProfilePreflightArtifactText,
  profileSha256,
  runProtectedRecordsServiceProfilePreflight,
  verifyProtectedRecordsServiceProfilePreflightArtifact,
} from '../lib/protected-records-service-profile.mjs';

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

function preflightCase(report, caseId) {
  return report.cases.find((item) => item.case_id === caseId);
}

const profile = JSON.parse(readFileSync('profiles/protected-records-service-fixture.profile.json', 'utf8'));
const SAMPLE_ARTIFACT_PATH = 'tests/fixtures/protected-records-service-preflight-artifact-v1.json';
const SAMPLE_ARTIFACT_SHA256 = '36a3aadfa920ea3da2ac3199b5af79f937e783e42604bfa3318d6ac8824b190c';

section('profile contract');
assert('profile passes validation', assertProtectedRecordsServiceProfile(profile));
assertEqual('profile type', PROTECTED_RECORDS_SERVICE_PROFILE_TYPE, profile.profile_type);
assertEqual('profile id', 'protected-records-service-fixture-profile', profile.profile_id);
assertEqual('profile status sample not active', 'sample_not_active', profile.profile_status);
assertEqual('deployment posture preflight only', 'deployable_profile_preflight_only', profile.deployment_posture);
assertEqual('action class', 'records.write', profile.action_class);
assertEqual('service command', 'zlar protected-records-service-request --config <file|-> --input <file|->', profile.service_command);
assertEqual('launcher-owned config required', true, profile.environment_boundary.launcher_owned_config_required);
assertEqual('request stream authority false', false, profile.environment_boundary.request_stream_authority_material_allowed);
assertEqual('request stream allowed fields', 'receipt,record_update', profile.environment_boundary.request_stream_allowed_fields.join(','));
assertEqual('runtime activation false', false, profile.environment_boundary.runtime_activation);
assertEqual('live profile installed false', false, profile.environment_boundary.live_profile_installed);
assertEqual('direct filesystem closure false', false, profile.environment_boundary.direct_filesystem_write_to_fixture_paths_closed);
assertEqual('contract detail binding', 'receipt.payload.detail_hash == sha256(canonical(record_update))', profile.recognition_rule_contract.required_detail_binding);
assert('profile hash is sha256', /^[a-f0-9]{64}$/.test(profileSha256(profile)));
for (const caseId of REQUIRED_PROFILE_PREFLIGHT_CASES) {
  assert(`profile required case present: ${caseId}`, profile.required_cases.includes(caseId));
}
for (const boundary of REQUIRED_OPEN_BOUNDARIES) {
  assert(`profile open boundary present: ${boundary}`, profile.known_open_boundaries.includes(boundary));
}
for (const claim of NON_CLAIMS) {
  assert(`profile non-claim present: ${claim}`, profile.non_claims.includes(claim));
}
assert('profile output is privacy safe', assertNoUnsafeProtectedRecordsServiceProfileText(JSON.stringify(profile)));

section('profile preflight');
const report = runProtectedRecordsServiceProfilePreflight(profile);
assert('preflight report passes validation', assertProtectedRecordsServiceProfilePreflight(report, profile));
assertEqual('preflight type', PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_TYPE, report.preflight_type);
assertEqual('safe claim ceiling exact', SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('evidence model', 'local-disposable-config-backed-profile-preflight-fixture', report.evidence_model);
assertEqual('no live probing', false, report.live_probing);
assertEqual('profile sha binds input profile', profileSha256(profile), report.profile.profile_sha256);
assertEqual('case count', REQUIRED_PROFILE_PREFLIGHT_CASES.length, report.cases.length);

const accepted = preflightCase(report, 'recognized_profile_service_write_first_process');
assertEqual('accepted service write true', true, accepted.service_write_accepted);
assertEqual('accepted reason', 'recognized', accepted.reason_code);
assertEqual('accepted state delta', 1, accepted.state_entry_count_delta);
assertEqual('accepted process one', 1, accepted.process_invocation);

const replay = preflightCase(report, 'replay_profile_refused_after_service_restart');
assertEqual('replay refused', false, replay.service_write_accepted);
assertEqual('replay reason', 'receipt_replay', replay.reason_code);
assertEqual('replay state delta zero', 0, replay.state_entry_count_delta);
assertEqual('replay separate process', true, replay.separate_process_from_accepted);

const missing = preflightCase(report, 'missing_receipt_profile_refused_before_service_mutation');
assertEqual('missing refused', false, missing.service_write_accepted);
assertEqual('missing reason', 'receipt_missing', missing.reason_code);
assertEqual('missing state delta zero', 0, missing.state_entry_count_delta);

const unrecognized = preflightCase(report, 'unrecognized_receipt_profile_refused_before_service_mutation');
assertEqual('unrecognized refused', false, unrecognized.service_write_accepted);
assertEqual('unrecognized reason', 'detail_hash_mismatch', unrecognized.reason_code);
assertEqual('unrecognized state delta zero', 0, unrecognized.state_entry_count_delta);

const invalid = preflightCase(report, 'invalid_receipt_profile_refused_before_service_mutation');
assertEqual('invalid receipt refused', false, invalid.service_write_accepted);
assertEqual('invalid receipt reason', 'receipt_invalid', invalid.reason_code);
assertEqual('invalid receipt state delta zero', 0, invalid.state_entry_count_delta);
assertEqual('invalid receipt consumed store absent', false, invalid.consumed_store_exists_after);

const unknownIssuer = preflightCase(report, 'unknown_issuer_profile_refused_before_service_mutation');
assertEqual('unknown issuer refused', false, unknownIssuer.service_write_accepted);
assertEqual('unknown issuer reason', 'unknown_issuer', unknownIssuer.reason_code);
assertEqual('unknown issuer state delta zero', 0, unknownIssuer.state_entry_count_delta);
assertEqual('unknown issuer consumed store absent', false, unknownIssuer.consumed_store_exists_after);

const wrongPolicy = preflightCase(report, 'wrong_policy_profile_refused_before_service_mutation');
assertEqual('wrong policy refused', false, wrongPolicy.service_write_accepted);
assertEqual('wrong policy reason', 'policy_not_recognized', wrongPolicy.reason_code);
assertEqual('wrong policy state delta zero', 0, wrongPolicy.state_entry_count_delta);
assertEqual('wrong policy consumed store absent', false, wrongPolicy.consumed_store_exists_after);

const stale = preflightCase(report, 'stale_receipt_profile_refused_before_service_mutation');
assertEqual('stale receipt refused', false, stale.service_write_accepted);
assertEqual('stale receipt reason', 'receipt_stale', stale.reason_code);
assertEqual('stale receipt state delta zero', 0, stale.state_entry_count_delta);
assertEqual('stale receipt consumed store absent', false, stale.consumed_store_exists_after);

const requestStreamAuthority = preflightCase(report, 'request_stream_authority_material_profile_refused_before_service_mutation');
assertEqual('request stream authority refused', false, requestStreamAuthority.service_write_accepted);
assertEqual('request stream authority reason', 'request_stream_authority_material', requestStreamAuthority.reason_code);
assertEqual('request stream authority state delta zero', 0, requestStreamAuthority.state_entry_count_delta);
assertEqual('request stream authority consumed store absent', false, requestStreamAuthority.consumed_store_exists_after);

const directApi = preflightCase(report, 'direct_api_profile_without_receipt_refused_before_service_mutation');
assertEqual('direct api without receipt refused', false, directApi.service_write_accepted);
assertEqual('direct api without receipt reason', 'request_stream_forbidden_fields', directApi.reason_code);
assertEqual('direct api without receipt state delta zero', 0, directApi.state_entry_count_delta);
assertEqual('direct api without receipt attempted', true, directApi.direct_api_attempted);

const directApiWithReceipt = preflightCase(report, 'direct_api_profile_receipt_present_refused_before_service_mutation');
assertEqual('direct api with receipt refused', false, directApiWithReceipt.service_write_accepted);
assertEqual('direct api with receipt reason', 'request_stream_forbidden_fields', directApiWithReceipt.reason_code);
assertEqual('direct api with receipt state delta zero', 0, directApiWithReceipt.state_entry_count_delta);
assertEqual('direct api with receipt consumed store absent', false, directApiWithReceipt.consumed_store_exists_after);

section('open-boundary honesty');
assertEqual('direct api without receipt reported refused', true, report.side_door_report.direct_api_without_receipt_refused);
assertEqual('direct api with receipt reported refused', true, report.side_door_report.direct_api_with_receipt_refused);
assertEqual('launcher-owned config required reported', true, report.side_door_report.launcher_owned_config_required);
assertEqual('request stream authority material allowed false reported', false, report.side_door_report.request_stream_authority_material_allowed);
assertEqual('request stream authority material refused reported', true, report.side_door_report.request_stream_authority_material_refused);
assertEqual('request stream forbidden fields refused reported', true, report.side_door_report.request_stream_forbidden_fields_refused);
assertEqual('direct filesystem closure false', false, report.side_door_report.direct_filesystem_write_to_fixture_paths_closed);
assertEqual('production service unchecked', false, report.side_door_report.production_records_service_checked);
assertEqual('live records unchecked', false, report.side_door_report.live_records_system_checked);
assertEqual('live profile not installed', false, report.side_door_report.live_profile_installed);
assertEqual('runtime activation unchecked', false, report.side_door_report.runtime_profile_activation_checked);
assertEqual('external attestation false', false, report.side_door_report.external_attestation);
assertEqual('sovereign recognition false', false, report.side_door_report.sovereign_recognition);
for (const boundary of REQUIRED_OPEN_BOUNDARIES) {
  assert(`preflight open boundary present: ${boundary}`, report.known_open_boundaries.includes(boundary));
}
for (const claim of NON_CLAIMS) {
  assert(`preflight non-claim present: ${claim}`, report.non_claims.includes(claim));
}

section('safe output formatting');
const summary = formatProtectedRecordsServiceProfilePreflightSummary(report, profile);
assert('summary title present', summary.includes('ZLAR Protected Records Service Profile Preflight v1'));
assert('summary includes profile id', summary.includes('Profile: id=protected-records-service-fixture-profile'));
assert('summary includes runtime activation boundary', summary.includes('runtime_activation=false'));
assert('summary includes accepted case', summary.includes('Recognized profile service write: accepted=true; reason=recognized; state_delta=1'));
assert('summary includes invalid receipt case', summary.includes('Invalid receipt: accepted=false; reason=receipt_invalid; state_delta=0'));
assert('summary includes unknown issuer case', summary.includes('Unknown issuer: accepted=false; reason=unknown_issuer; state_delta=0'));
assert('summary includes wrong policy case', summary.includes('Wrong policy: accepted=false; reason=policy_not_recognized; state_delta=0'));
assert('summary includes stale receipt case', summary.includes('Stale receipt: accepted=false; reason=receipt_stale; state_delta=0'));
assert('summary includes request stream authority case', summary.includes('Request-stream authority material: accepted=false; reason=request_stream_authority_material; state_delta=0'));
assert('summary includes direct api with receipt case', summary.includes('Fixture service API carrying receipt into without-receipt case: accepted=false; reason=request_stream_forbidden_fields; state_delta=0'));
assert('summary includes production service non-check', summary.includes('production_records_service_checked=false'));
assert('summary output is privacy safe', assertNoUnsafeProtectedRecordsServiceProfileText(summary));
const jsonText = JSON.stringify(report, null, 2);
assert('json output is privacy safe', assertNoUnsafeProtectedRecordsServiceProfileText(jsonText));
assert('json omits raw record id', !jsonText.includes('fixture-record-profile-001'));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonText));
assert('json omits private and temp paths', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(jsonText));

section('portable artifact and verification');
const artifact = buildProtectedRecordsServiceProfilePreflightArtifact(profile, report);
assert('artifact passes validation', assertProtectedRecordsServiceProfilePreflightArtifact(artifact));
assertEqual('artifact type', PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_TYPE, artifact.artifact_type);
assertEqual('artifact canonicalization', 'zlar-canonical-json-v1', artifact.canonicalization);
assertEqual('artifact generator', 'zlar protected-records-service-preflight --artifact', artifact.generator);
assertEqual('artifact hash scope', 'canonical artifact body without integrity', artifact.hash_scope);
assert('artifact sha is sha256', /^[a-f0-9]{64}$/.test(artifact.integrity.body_sha256));
assertEqual('artifact embeds profile sha', profileSha256(profile), artifact.payload.preflight.profile.profile_sha256);
assertEqual('artifact embeds exact case count', REQUIRED_PROFILE_PREFLIGHT_CASES.length, artifact.payload.preflight.cases.length);
assertEqual('artifact embeds no live probing', false, artifact.payload.preflight.live_probing);
assertEqual('artifact embeds request stream authority refusal', 'request_stream_authority_material', preflightCase(artifact.payload.preflight, 'request_stream_authority_material_profile_refused_before_service_mutation').reason_code);
assertEqual('artifact embeds direct api with receipt refusal', 'request_stream_forbidden_fields', preflightCase(artifact.payload.preflight, 'direct_api_profile_receipt_present_refused_before_service_mutation').reason_code);
assert('artifact text is privacy safe', assertNoUnsafeProtectedRecordsServiceProfileText(JSON.stringify(artifact, null, 2)));

const parsedArtifact = parseProtectedRecordsServiceProfilePreflightArtifactText(JSON.stringify(artifact, null, 2));
assert('parsed artifact passes validation', assertProtectedRecordsServiceProfilePreflightArtifact(parsedArtifact));
assertEqual('parsed artifact sha stable', artifact.integrity.body_sha256, parsedArtifact.integrity.body_sha256);

const verification = verifyProtectedRecordsServiceProfilePreflightArtifact(parsedArtifact);
assertEqual('verification type', PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
assertEqual('verification verified true', true, verification.verified);
assertEqual('verification sha matches artifact', artifact.integrity.body_sha256, verification.body_sha256);
assertEqual('verification payload type', PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_TYPE, verification.payload_type);
assertEqual('verification live probing false', false, verification.live_probing);
assertEqual('verification profile sha matches', profileSha256(profile), verification.profile_sha256);
assertEqual('verification case count', REQUIRED_PROFILE_PREFLIGHT_CASES.length, verification.case_count);
assertEqual('verification required case count', REQUIRED_PROFILE_PREFLIGHT_CASES.length, verification.required_case_count);
assertEqual('verification recognized write accepted', true, verification.recognized_write_accepted);
assertEqual('verification replay refused', true, verification.replay_refused);
assertEqual('verification missing receipt refused', true, verification.missing_receipt_refused);
assertEqual('verification invalid receipt refused', true, verification.invalid_receipt_refused);
assertEqual('verification unknown issuer refused', true, verification.unknown_issuer_refused);
assertEqual('verification wrong policy refused', true, verification.wrong_policy_refused);
assertEqual('verification wrong policy reason', 'policy_not_recognized', verification.wrong_policy_reason);
assertEqual('verification wrong policy state delta', 0, verification.wrong_policy_state_delta);
assertEqual('verification stale receipt refused', true, verification.stale_receipt_refused);
assertEqual('verification launcher-owned config required', true, verification.launcher_owned_config_required);
assertEqual('verification request stream authority allowed false', false, verification.request_stream_authority_material_allowed);
assertEqual('verification request stream authority refused', true, verification.request_stream_authority_material_refused);
assertEqual('verification request stream authority reason', 'request_stream_authority_material', verification.request_stream_authority_material_reason);
assertEqual('verification request stream authority state delta', 0, verification.request_stream_authority_material_state_delta);
assertEqual('verification request stream forbidden fields refused', true, verification.request_stream_forbidden_fields_refused);
assertEqual('verification direct api with receipt refused', true, verification.direct_api_with_receipt_refused);
assertEqual('verification direct api without receipt reason', 'request_stream_forbidden_fields', verification.direct_api_without_receipt_reason);
assertEqual('verification direct api with receipt reason', 'request_stream_forbidden_fields', verification.direct_api_receipt_present_reason);
assertEqual('verification direct api with receipt state delta', 0, verification.direct_api_receipt_present_state_delta);
assertEqual('verification direct filesystem closure false', false, verification.direct_filesystem_write_to_fixture_paths_closed);
assertEqual('verification production service unchecked', false, verification.production_records_service_checked);
assertEqual('verification external attestation false', false, verification.external_attestation);
assertEqual('verification sovereign recognition false', false, verification.sovereign_recognition);
assert('verification output is privacy safe', assertNoUnsafeProtectedRecordsServiceProfileText(JSON.stringify(verification, null, 2)));

const artifactSummary = formatProtectedRecordsServiceProfilePreflightArtifactSummary(artifact);
assert('artifact summary names portable artifact', artifactSummary.includes('Portable service profile preflight artifact:'));
assert('artifact summary includes checksum', artifactSummary.includes(artifact.integrity.body_sha256));
assert('artifact summary is privacy safe', assertNoUnsafeProtectedRecordsServiceProfileText(artifactSummary));

const verificationSummary = formatProtectedRecordsServiceProfilePreflightArtifactVerification(verification);
assert('verification summary title present', verificationSummary.includes('ZLAR Protected Records Service Profile Preflight Artifact Verification v1'));
assert('verification summary says verified', verificationSummary.includes('verified=true'));
assert('verification summary includes claim boundary', verificationSummary.includes('embedded local service-profile preflight boundaries only'));
assert('verification summary keeps wrong policy boundary', verificationSummary.includes('wrong_policy_refused=true; wrong_policy_reason=policy_not_recognized; wrong_policy_state_delta=0'));
assert('verification summary keeps request stream boundary', verificationSummary.includes('request_stream_authority_material_refused=true; request_stream_authority_material_reason=request_stream_authority_material'));
assert('verification summary keeps direct api boundary', verificationSummary.includes('direct_api_with_receipt_refused=true; direct_api_receipt_present_reason=request_stream_forbidden_fields'));
assert('verification summary is privacy safe', assertNoUnsafeProtectedRecordsServiceProfileText(verificationSummary));

section('committed sample artifact');
const sampleArtifactText = readFileSync(SAMPLE_ARTIFACT_PATH, 'utf8');
assert('sample artifact text is privacy safe', assertNoUnsafeProtectedRecordsServiceProfileText(sampleArtifactText));
const sampleArtifact = parseProtectedRecordsServiceProfilePreflightArtifactText(sampleArtifactText);
assert('sample artifact passes validation', assertProtectedRecordsServiceProfilePreflightArtifact(sampleArtifact));
assertEqual('sample artifact hash is stable', SAMPLE_ARTIFACT_SHA256, sampleArtifact.integrity.body_sha256);
assertEqual('sample artifact embeds same profile sha', profileSha256(profile), sampleArtifact.payload.preflight.profile.profile_sha256);
assertEqual('sample artifact embeds wrong policy refusal', 'policy_not_recognized', preflightCase(sampleArtifact.payload.preflight, 'wrong_policy_profile_refused_before_service_mutation').reason_code);
assertEqual('sample artifact embeds request stream authority refusal', 'request_stream_authority_material', preflightCase(sampleArtifact.payload.preflight, 'request_stream_authority_material_profile_refused_before_service_mutation').reason_code);
assertEqual('sample artifact embeds direct api with receipt refusal', 'request_stream_forbidden_fields', preflightCase(sampleArtifact.payload.preflight, 'direct_api_profile_receipt_present_refused_before_service_mutation').reason_code);
const sampleVerification = verifyProtectedRecordsServiceProfilePreflightArtifact(sampleArtifact);
assertEqual('sample artifact verifies true', true, sampleVerification.verified);
assertEqual('sample verification sha matches fixture', SAMPLE_ARTIFACT_SHA256, sampleVerification.body_sha256);
assertEqual('sample verification live probing false', false, sampleVerification.live_probing);

section('fail closed validation');
const wrongCommand = structuredClone(profile);
wrongCommand.service_command = 'zlar protected-records-service-request --latest';
assertThrows('wrong command fails profile validation', () => assertProtectedRecordsServiceProfile(wrongCommand), 'contract drifted');

const liveProfile = structuredClone(profile);
liveProfile.environment_boundary.live_profile_installed = true;
assertThrows('live profile installed claim fails', () => assertProtectedRecordsServiceProfile(liveProfile), 'environment boundary drifted');

const directFilesystemClosed = structuredClone(profile);
directFilesystemClosed.environment_boundary.direct_filesystem_write_to_fixture_paths_closed = true;
assertThrows('direct filesystem closure claim fails', () => assertProtectedRecordsServiceProfile(directFilesystemClosed), 'environment boundary drifted');

const missingCase = structuredClone(profile);
missingCase.required_cases = missingCase.required_cases.filter((item) => item !== 'replay_profile_refused_after_service_restart');
assertThrows('missing profile case fails', () => assertProtectedRecordsServiceProfile(missingCase), 'required cases drifted');

const liveProbeReport = structuredClone(report);
liveProbeReport.live_probing = true;
assertThrows('live probing report fails', () => assertProtectedRecordsServiceProfilePreflight(liveProbeReport, profile), 'top-level contract drifted');

const acceptedNoMutation = structuredClone(report);
preflightCase(acceptedNoMutation, 'recognized_profile_service_write_first_process').state_entry_count_delta = 0;
preflightCase(acceptedNoMutation, 'recognized_profile_service_write_first_process').state_entry_count_after = 0;
assertThrows('accepted no mutation fails', () => assertProtectedRecordsServiceProfilePreflight(acceptedNoMutation, profile), 'accepted case failed');

const tamperedMissingCommand = structuredClone(report);
preflightCase(tamperedMissingCommand, 'missing_receipt_profile_refused_before_service_mutation').command = 'zlar protected-records-service-request --latest';
assertThrows('tampered case command fails', () => assertProtectedRecordsServiceProfilePreflight(tamperedMissingCommand, profile), 'case contract drifted');

const tamperedMissingProcessFlag = structuredClone(report);
preflightCase(tamperedMissingProcessFlag, 'missing_receipt_profile_refused_before_service_mutation').separate_process_from_accepted = false;
assertThrows('tampered refusal process flag fails', () => assertProtectedRecordsServiceProfilePreflight(tamperedMissingProcessFlag, profile), 'case contract drifted');

const tamperedMissingStore = structuredClone(report);
preflightCase(tamperedMissingStore, 'missing_receipt_profile_refused_before_service_mutation').consumed_store_exists_after = true;
assertThrows('tampered refusal consumed store fails', () => assertProtectedRecordsServiceProfilePreflight(tamperedMissingStore, profile), 'case contract drifted');

const invalidBoards = structuredClone(report);
preflightCase(invalidBoards, 'invalid_receipt_profile_refused_before_service_mutation').state_entry_count_delta = 1;
preflightCase(invalidBoards, 'invalid_receipt_profile_refused_before_service_mutation').state_entry_count_after = 1;
assertThrows('invalid receipt mutation fails', () => assertProtectedRecordsServiceProfilePreflight(invalidBoards, profile), 'invalid receipt case failed');

const unknownConsumes = structuredClone(report);
preflightCase(unknownConsumes, 'unknown_issuer_profile_refused_before_service_mutation').consumed_receipt_count = 1;
assertThrows('unknown issuer consumption fails', () => assertProtectedRecordsServiceProfilePreflight(unknownConsumes, profile), 'unknown issuer case failed');

const wrongPolicyBoards = structuredClone(report);
preflightCase(wrongPolicyBoards, 'wrong_policy_profile_refused_before_service_mutation').service_write_accepted = true;
assertThrows('wrong policy boarding fails', () => assertProtectedRecordsServiceProfilePreflight(wrongPolicyBoards, profile), 'wrong-policy case failed');

const staleReasonDrift = structuredClone(report);
preflightCase(staleReasonDrift, 'stale_receipt_profile_refused_before_service_mutation').reason_code = 'recognized';
assertThrows('stale reason drift fails', () => assertProtectedRecordsServiceProfilePreflight(staleReasonDrift, profile), 'stale receipt case failed');

const directApiBoards = structuredClone(report);
preflightCase(directApiBoards, 'direct_api_profile_without_receipt_refused_before_service_mutation').service_write_accepted = true;
assertThrows('direct api boarding fails', () => assertProtectedRecordsServiceProfilePreflight(directApiBoards, profile), 'direct API no-receipt case failed');

const directApiReceiptConsumes = structuredClone(report);
preflightCase(directApiReceiptConsumes, 'direct_api_profile_receipt_present_refused_before_service_mutation').consumed_receipt_count = 1;
assertThrows('direct api receipt consume fails', () => assertProtectedRecordsServiceProfilePreflight(directApiReceiptConsumes, profile), 'direct API receipt-present case failed');

const productionClaim = structuredClone(report);
productionClaim.side_door_report.production_records_service_checked = true;
assertThrows('production service check claim fails', () => assertProtectedRecordsServiceProfilePreflight(productionClaim, profile), 'side-door report drifted');

const tamperedArtifactHash = structuredClone(artifact);
tamperedArtifactHash.integrity.body_sha256 = '0'.repeat(64);
assertThrows('tampered artifact hash fails', () => assertProtectedRecordsServiceProfilePreflightArtifact(tamperedArtifactHash), 'SHA-256 mismatch');

const tamperedArtifactLiveProbe = structuredClone(artifact);
tamperedArtifactLiveProbe.payload.preflight.live_probing = true;
assertThrows('tampered artifact live probing fails', () => assertProtectedRecordsServiceProfilePreflightArtifact(tamperedArtifactLiveProbe), 'top-level contract drifted');

const tamperedArtifactPayload = structuredClone(artifact);
tamperedArtifactPayload.payload.extra = true;
assertThrows('artifact extra payload field fails', () => assertProtectedRecordsServiceProfilePreflightArtifact(tamperedArtifactPayload), 'payload contains unexpected fields');

assertThrows('invalid artifact json fails', () => parseProtectedRecordsServiceProfilePreflightArtifactText('{'), 'not valid JSON');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
