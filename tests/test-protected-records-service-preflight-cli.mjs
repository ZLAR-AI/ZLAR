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
  PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_TYPE,
  PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE,
  assertProtectedRecordsServiceProfilePreflightArtifact,
  assertProtectedRecordsServiceProfilePreflight,
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

function section(title) {
  console.log(`\n-- ${title} --`);
}

const ZLAR_BIN = join(process.cwd(), 'bin', 'zlar');
const PROFILE_PATH = 'profiles/protected-records-service-fixture.profile.json';
const SAMPLE_ARTIFACT_PATH = 'tests/fixtures/protected-records-service-preflight-artifact-v1.json';
const SAMPLE_ARTIFACT_SHA256 = '36a3aadfa920ea3da2ac3199b5af79f937e783e42604bfa3318d6ac8824b190c';
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;
const scratch = mkdtempSync(join(tmpdir(), 'zlar-protected-records-service-preflight-cli-'));

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

const profile = JSON.parse(readFileSync(PROFILE_PATH, 'utf8'));

section('text preflight command');
const textRun = runZlar(['protected-records-service-preflight', '--profile', PROFILE_PATH]);
assertEqual('text command exits zero', 0, textRun.status);
assertEqual('text command emits no stderr', '', textRun.stderr);
assert('text summary title present', textRun.stdout.includes('ZLAR Protected Records Service Profile Preflight v1'));
assert('text summary includes profile id', textRun.stdout.includes('Profile: id=protected-records-service-fixture-profile'));
assert('text summary states config-backed fixture model', textRun.stdout.includes('Evidence model: local-disposable-config-backed-profile-preflight-fixture; live probing=false'));
assert('text summary includes runtime boundary', textRun.stdout.includes('runtime_activation=false; live_profile_installed=false'));
assert('text summary includes accepted service write', textRun.stdout.includes('Recognized profile service write: accepted=true; reason=recognized; state_delta=1'));
assert('text summary includes replay refusal', textRun.stdout.includes('Replay after service restart: accepted=false; reason=receipt_replay; state_delta=0; separate_process=true'));
assert('text summary includes missing refusal', textRun.stdout.includes('Missing receipt: accepted=false; reason=receipt_missing; state_delta=0'));
assert('text summary includes unrecognized refusal', textRun.stdout.includes('Unrecognized receipt: accepted=false; reason=detail_hash_mismatch; state_delta=0'));
assert('text summary includes invalid receipt refusal', textRun.stdout.includes('Invalid receipt: accepted=false; reason=receipt_invalid; state_delta=0'));
assert('text summary includes unknown issuer refusal', textRun.stdout.includes('Unknown issuer: accepted=false; reason=unknown_issuer; state_delta=0'));
assert('text summary includes wrong policy refusal', textRun.stdout.includes('Wrong policy: accepted=false; reason=policy_not_recognized; state_delta=0'));
assert('text summary includes stale receipt refusal', textRun.stdout.includes('Stale receipt: accepted=false; reason=receipt_stale; state_delta=0'));
assert('text summary includes direct api no-receipt refusal', textRun.stdout.includes('Fixture service API without receipt: accepted=false; reason=request_stream_forbidden_fields; state_delta=0'));
assert('text summary includes request stream authority refusal', textRun.stdout.includes('Request-stream authority material: accepted=false; reason=request_stream_authority_material; state_delta=0'));
assert('text summary includes direct api receipt-present refusal', textRun.stdout.includes('Fixture service API carrying receipt into without-receipt case: accepted=false; reason=request_stream_forbidden_fields; state_delta=0'));
assert('text summary names open boundaries', textRun.stdout.includes('Known open boundaries: direct_filesystem_write_to_configured_fixture_paths,live_records_system,production_records_service,runtime_profile_not_installed,unrouted_records_paths'));
assert('text summary states production non-claim', textRun.stdout.includes('does not prove production records service deployment'));
assert('text summary is privacy safe', !unsafeOutputPattern.test(textRun.stdout));

section('json preflight command');
const jsonRun = runZlar(['protected-records-service-preflight', '--profile', PROFILE_PATH, '--json']);
assertEqual('json command exits zero', 0, jsonRun.status);
assertEqual('json command emits no stderr', '', jsonRun.stderr);
assert('json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report passes validation', assertProtectedRecordsServiceProfilePreflight(report, profile));
assertEqual('json preflight type', 'zlar-protected-records-service-profile-preflight-v1', report.preflight_type);
assertEqual('json live probing false', false, report.live_probing);
assertEqual('json evidence model', 'local-disposable-config-backed-profile-preflight-fixture', report.evidence_model);
assertEqual('json case count', 11, report.cases.length);
assert('json includes profile sha', /"profile_sha256": "[a-f0-9]{64}"/.test(jsonRun.stdout));
assert('json includes invalid receipt case', jsonRun.stdout.includes('"case_id": "invalid_receipt_profile_refused_before_service_mutation"'));
assert('json includes unknown issuer case', jsonRun.stdout.includes('"case_id": "unknown_issuer_profile_refused_before_service_mutation"'));
assert('json includes wrong policy case', jsonRun.stdout.includes('"case_id": "wrong_policy_profile_refused_before_service_mutation"'));
assert('json includes stale receipt case', jsonRun.stdout.includes('"case_id": "stale_receipt_profile_refused_before_service_mutation"'));
assert('json includes wrong policy reason', jsonRun.stdout.includes('"reason_code": "policy_not_recognized"'));
assert('json includes direct api receipt-present case', jsonRun.stdout.includes('"case_id": "direct_api_profile_receipt_present_refused_before_service_mutation"'));
assert('json includes request stream authority reason', jsonRun.stdout.includes('"reason_code": "request_stream_authority_material"'));
assert('json includes direct api receipt-present reason', jsonRun.stdout.includes('"reason_code": "request_stream_forbidden_fields"'));
assert('json includes runtime profile not installed boundary', jsonRun.stdout.includes('"runtime_profile_not_installed"'));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonRun.stdout));

section('stdin profile command');
const stdinRun = runZlar(['protected-records-service-preflight', '--profile', '-', '--json'], {
  input: readFileSync(PROFILE_PATH, 'utf8'),
});
assertEqual('stdin command exits zero', 0, stdinRun.status);
assertEqual('stdin command emits no stderr', '', stdinRun.stderr);
const stdinReport = JSON.parse(stdinRun.stdout);
assert('stdin report passes validation', assertProtectedRecordsServiceProfilePreflight(stdinReport, profile));

section('artifact command');
const artifactPath = join(scratch, 'service-profile-preflight-artifact.json');
const artifactRun = runZlar(['protected-records-service-preflight', '--profile', PROFILE_PATH, '--artifact', artifactPath]);
assertEqual('artifact command exits zero', 0, artifactRun.status);
assertEqual('artifact command emits no stderr', '', artifactRun.stderr);
assert('artifact command keeps text summary', artifactRun.stdout.includes('ZLAR Protected Records Service Profile Preflight v1'));
assert('artifact command prints checksum', artifactRun.stdout.includes('Portable service profile preflight artifact:'));
assert('artifact command output is privacy safe', !unsafeOutputPattern.test(artifactRun.stdout));
const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
assert('artifact file passes validation', assertProtectedRecordsServiceProfilePreflightArtifact(artifact));
assertEqual('artifact file type', PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_TYPE, artifact.artifact_type);
assert('artifact file has sha256', /^[a-f0-9]{64}$/.test(artifact.integrity.body_sha256));
assertEqual('artifact embeds service preflight report type', 'zlar-protected-records-service-profile-preflight-v1', artifact.payload.preflight.preflight_type);
assertEqual('artifact embeds wrong policy reason', 'policy_not_recognized', artifact.payload.preflight.cases.find((item) => item.case_id === 'wrong_policy_profile_refused_before_service_mutation').reason_code);
assertEqual('artifact embeds request stream authority reason', 'request_stream_authority_material', artifact.payload.preflight.cases.find((item) => item.case_id === 'request_stream_authority_material_profile_refused_before_service_mutation').reason_code);
assertEqual('artifact embeds direct api receipt-present reason', 'request_stream_forbidden_fields', artifact.payload.preflight.cases.find((item) => item.case_id === 'direct_api_profile_receipt_present_refused_before_service_mutation').reason_code);

const artifactStdoutRun = runZlar(['protected-records-service-preflight', '--profile', PROFILE_PATH, '--artifact', '-']);
assertEqual('artifact stdout command exits zero', 0, artifactStdoutRun.status);
assertEqual('artifact stdout command emits no stderr', '', artifactStdoutRun.stderr);
assert('artifact stdout output is privacy safe', !unsafeOutputPattern.test(artifactStdoutRun.stdout));
const stdoutArtifact = JSON.parse(artifactStdoutRun.stdout);
assert('artifact stdout passes validation', assertProtectedRecordsServiceProfilePreflightArtifact(stdoutArtifact));
assertEqual('artifact stdout type', PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_TYPE, stdoutArtifact.artifact_type);

section('artifact verify command');
const verifyRun = runZlar(['protected-records-service-preflight', 'verify', '--input', artifactPath]);
assertEqual('verify command exits zero', 0, verifyRun.status);
assertEqual('verify command emits no stderr', '', verifyRun.stderr);
assert('verify summary title present', verifyRun.stdout.includes('ZLAR Protected Records Service Profile Preflight Artifact Verification v1'));
assert('verify summary says verified', verifyRun.stdout.includes('verified=true'));
assert('verify summary includes artifact sha', verifyRun.stdout.includes(artifact.integrity.body_sha256));
assert('verify summary includes wrong policy boundary', verifyRun.stdout.includes('wrong_policy_refused=true; wrong_policy_reason=policy_not_recognized; wrong_policy_state_delta=0'));
assert('verify summary includes request stream authority boundary', verifyRun.stdout.includes('request_stream_authority_material_refused=true; request_stream_authority_material_reason=request_stream_authority_material'));
assert('verify summary includes direct api receipt-present boundary', verifyRun.stdout.includes('direct_api_with_receipt_refused=true; direct_api_receipt_present_reason=request_stream_forbidden_fields'));
assert('verify summary is privacy safe', !unsafeOutputPattern.test(verifyRun.stdout));

const verifyJsonRun = runZlar(['protected-records-service-preflight', 'verify', '--input', artifactPath, '--json']);
assertEqual('verify json command exits zero', 0, verifyJsonRun.status);
assertEqual('verify json command emits no stderr', '', verifyJsonRun.stderr);
assert('verify json output is privacy safe', !unsafeOutputPattern.test(verifyJsonRun.stdout));
const verification = JSON.parse(verifyJsonRun.stdout);
assertEqual('verify json type', PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
assertEqual('verify json verified true', true, verification.verified);
assertEqual('verify json sha matches artifact', artifact.integrity.body_sha256, verification.body_sha256);
assertEqual('verify json live probing false', false, verification.live_probing);
assertEqual('verify json wrong policy reason', 'policy_not_recognized', verification.wrong_policy_reason);
assertEqual('verify json wrong policy state delta', 0, verification.wrong_policy_state_delta);
assertEqual('verify json request stream authority reason', 'request_stream_authority_material', verification.request_stream_authority_material_reason);
assertEqual('verify json direct api receipt-present reason', 'request_stream_forbidden_fields', verification.direct_api_receipt_present_reason);
assertEqual('verify json direct api receipt-present state delta', 0, verification.direct_api_receipt_present_state_delta);

const verifyStdinRun = runZlar(['protected-records-service-preflight', 'verify', '--input', '-'], {
  input: JSON.stringify(artifact, null, 2),
});
assertEqual('verify stdin command exits zero', 0, verifyStdinRun.status);
assertEqual('verify stdin command emits no stderr', '', verifyStdinRun.stderr);
assert('verify stdin says verified', verifyStdinRun.stdout.includes('verified=true'));
assert('verify stdin is privacy safe', !unsafeOutputPattern.test(verifyStdinRun.stdout));

section('committed sample artifact verify command');
const sampleVerifyRun = runZlar(['protected-records-service-preflight', 'verify', '--input', SAMPLE_ARTIFACT_PATH]);
assertEqual('sample verify command exits zero', 0, sampleVerifyRun.status);
assertEqual('sample verify command emits no stderr', '', sampleVerifyRun.stderr);
assert('sample verify says verified', sampleVerifyRun.stdout.includes('verified=true'));
assert('sample verify includes stable sha', sampleVerifyRun.stdout.includes(SAMPLE_ARTIFACT_SHA256));
assert('sample verify is privacy safe', !unsafeOutputPattern.test(sampleVerifyRun.stdout));

const sampleVerifyJsonRun = runZlar(['protected-records-service-preflight', 'verify', '--input', SAMPLE_ARTIFACT_PATH, '--json']);
assertEqual('sample verify json command exits zero', 0, sampleVerifyJsonRun.status);
assertEqual('sample verify json command emits no stderr', '', sampleVerifyJsonRun.stderr);
const sampleVerification = JSON.parse(sampleVerifyJsonRun.stdout);
assertEqual('sample verify json type', PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE, sampleVerification.verification_type);
assertEqual('sample verify json sha matches fixture', SAMPLE_ARTIFACT_SHA256, sampleVerification.body_sha256);
assertEqual('sample verify json live probing false', false, sampleVerification.live_probing);

const sampleOptionVerifyRun = runZlar(['protected-records-service-preflight', 'verify', '--sample']);
assertEqual('sample option verify command exits zero', 0, sampleOptionVerifyRun.status);
assertEqual('sample option verify command emits no stderr', '', sampleOptionVerifyRun.stderr);
assert('sample option verify says verified', sampleOptionVerifyRun.stdout.includes('verified=true'));
assert('sample option verify includes stable sha', sampleOptionVerifyRun.stdout.includes(SAMPLE_ARTIFACT_SHA256));
assert('sample option verify is privacy safe', !unsafeOutputPattern.test(sampleOptionVerifyRun.stdout));

const sampleOptionVerifyJsonRun = runZlar(['protected-records-service-preflight', 'verify', '--sample', '--json']);
assertEqual('sample option verify json command exits zero', 0, sampleOptionVerifyJsonRun.status);
assertEqual('sample option verify json command emits no stderr', '', sampleOptionVerifyJsonRun.stderr);
const sampleOptionVerification = JSON.parse(sampleOptionVerifyJsonRun.stdout);
assertEqual('sample option verify json type', PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE, sampleOptionVerification.verification_type);
assertEqual('sample option verify json sha matches fixture', SAMPLE_ARTIFACT_SHA256, sampleOptionVerification.body_sha256);
assertEqual('sample option verify json live probing false', false, sampleOptionVerification.live_probing);

section('help and fail closed command handling');
const helpRun = runZlar(['protected-records-service-preflight', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assert('help names usage', helpRun.stderr.includes('Usage: zlar protected-records-service-preflight --profile <file|-> [--json] [--artifact <file|->]'));
assert('help names verify usage', helpRun.stderr.includes('zlar protected-records-service-preflight verify (--input <file|->|--sample) [--json] [--require-sha <artifact_body_sha256>]'));
assert('help describes artifact', helpRun.stderr.includes('portable checksummed service-profile preflight artifact'));
assert('help describes verify', helpRun.stderr.includes('verify a supplied service-profile preflight artifact'));
assert('help describes sample option', helpRun.stderr.includes('verify --sample'));
assert('help names sample artifact', helpRun.stderr.includes(SAMPLE_ARTIFACT_PATH));
assert('help states no live probing', helpRun.stderr.includes('does not live probe'));
assert('help states no profile install', helpRun.stderr.includes('install a profile'));
assert('help states direct filesystem boundary', helpRun.stderr.includes('close direct filesystem writes'));
assertEqual('help emits no stdout', '', helpRun.stdout);

const missingProfile = runZlar(['protected-records-service-preflight']);
assert('missing profile exits usage error', missingProfile.status !== 0);
assertEqual('missing profile emits no stdout', '', missingProfile.stdout);
assert('missing profile refuses latest runtime profile', missingProfile.stderr.includes('does not select a live or latest runtime profile'));

const unsupported = runZlar(['protected-records-service-preflight', '--profile', PROFILE_PATH, '--latest']);
assert('unsupported option exits usage error', unsupported.status !== 0);
assertEqual('unsupported option emits no stdout', '', unsupported.stdout);
assert('unsupported option names unsupported option', unsupported.stderr.includes('Unsupported option provided.'));
assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

const missingArtifactValue = runZlar(['protected-records-service-preflight', '--profile', PROFILE_PATH, '--artifact']);
assert('missing artifact value exits usage error', missingArtifactValue.status !== 0);
assertEqual('missing artifact value emits no stdout', '', missingArtifactValue.stdout);
assert('missing artifact value names missing value', missingArtifactValue.stderr.includes('Missing value for --artifact'));
assert('missing artifact value is privacy safe', !unsafeOutputPattern.test(missingArtifactValue.stderr));

const artifactJsonConflict = runZlar(['protected-records-service-preflight', '--profile', PROFILE_PATH, '--json', '--artifact', '-']);
assert('artifact stdout json conflict exits usage error', artifactJsonConflict.status !== 0);
assertEqual('artifact stdout json conflict emits no stdout', '', artifactJsonConflict.stdout);
assert('artifact stdout json conflict names conflict', artifactJsonConflict.stderr.includes('Cannot combine --json with --artifact -'));
assert('artifact stdout json conflict is privacy safe', !unsafeOutputPattern.test(artifactJsonConflict.stderr));

const missingVerifyInput = runZlar(['protected-records-service-preflight', 'verify']);
assert('missing verify input exits usage error', missingVerifyInput.status !== 0);
assertEqual('missing verify input emits no stdout', '', missingVerifyInput.stdout);
assert('missing verify input names input or sample', missingVerifyInput.stderr.includes('Missing required --input <file|-> or --sample'));
assert('missing verify input is privacy safe', !unsafeOutputPattern.test(missingVerifyInput.stderr));

const verifyInputSampleConflict = runZlar(['protected-records-service-preflight', 'verify', '--input', SAMPLE_ARTIFACT_PATH, '--sample']);
assert('verify input sample conflict exits usage error', verifyInputSampleConflict.status !== 0);
assertEqual('verify input sample conflict emits no stdout', '', verifyInputSampleConflict.stdout);
assert('verify input sample conflict names conflict', verifyInputSampleConflict.stderr.includes('Cannot combine --input with --sample'));
assert('verify input sample conflict is privacy safe', !unsafeOutputPattern.test(verifyInputSampleConflict.stderr));

const unsupportedVerify = runZlar(['protected-records-service-preflight', 'verify', '--latest']);
assert('unsupported verify option exits usage error', unsupportedVerify.status !== 0);
assertEqual('unsupported verify option emits no stdout', '', unsupportedVerify.stdout);
assert('unsupported verify option names unsupported verify option', unsupportedVerify.stderr.includes('Unsupported verify option provided.'));
assert('unsupported verify option is privacy safe', !unsafeOutputPattern.test(unsupportedVerify.stderr));

const driftedProfile = structuredClone(profile);
driftedProfile.environment_boundary.live_profile_installed = true;
const driftedPath = join(scratch, 'drifted-profile.json');
writeFileSync(driftedPath, `${JSON.stringify(driftedProfile, null, 2)}\n`);
const driftedRun = runZlar(['protected-records-service-preflight', '--profile', driftedPath]);
assert('drifted live profile claim fails', driftedRun.status !== 0);
assertEqual('drifted profile emits no stdout', '', driftedRun.stdout);
assert('drifted profile names boundary drift', driftedRun.stderr.includes('environment boundary drifted') || driftedRun.stderr.includes('private path or credential details were suppressed'));
assert('drifted profile stderr is privacy safe', !unsafeOutputPattern.test(driftedRun.stderr));

const invalidJsonRun = runZlar(['protected-records-service-preflight', '--profile', '-'], {
  input: '{not-json}\n',
});
assert('invalid json exits nonzero', invalidJsonRun.status !== 0);
assertEqual('invalid json emits no stdout', '', invalidJsonRun.stdout);
assert('invalid json names parse failure', invalidJsonRun.stderr.includes('Could not parse protected records service profile JSON'));

const invalidArtifactPath = join(scratch, 'invalid-artifact.json');
writeFileSync(invalidArtifactPath, '{');
const invalidArtifactRun = runZlar(['protected-records-service-preflight', 'verify', '--input', invalidArtifactPath]);
assert('invalid artifact json exits nonzero', invalidArtifactRun.status !== 0);
assertEqual('invalid artifact json emits no stdout', '', invalidArtifactRun.stdout);
assert('invalid artifact json names invalid json', invalidArtifactRun.stderr.includes('not valid JSON'));
assert('invalid artifact json is privacy safe', !unsafeOutputPattern.test(invalidArtifactRun.stderr));

const tamperedArtifactPath = join(scratch, 'tampered-artifact.json');
const tamperedArtifact = structuredClone(artifact);
tamperedArtifact.integrity.body_sha256 = '0'.repeat(64);
writeFileSync(tamperedArtifactPath, `${JSON.stringify(tamperedArtifact, null, 2)}\n`);
const tamperedRun = runZlar(['protected-records-service-preflight', 'verify', '--input', tamperedArtifactPath]);
assert('tampered artifact verify exits nonzero', tamperedRun.status !== 0);
assertEqual('tampered artifact verify emits no stdout', '', tamperedRun.stdout);
assert('tampered artifact verify names sha mismatch', tamperedRun.stderr.includes('SHA-256 mismatch'));
assert('tampered artifact verify is privacy safe', !unsafeOutputPattern.test(tamperedRun.stderr));

const mainHelp = runZlar(['help']);
assertEqual('main help exits zero', 0, mainHelp.status);
assert('main help lists service preflight', mainHelp.stdout.includes('protected-records-service-preflight'));

rmSync(scratch, { recursive: true, force: true });

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
