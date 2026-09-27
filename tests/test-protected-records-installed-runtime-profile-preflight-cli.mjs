#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  runtimeProfileSha256,
} from '../lib/protected-records-runtime-profile-preflight.mjs';
import {
  INSTALLED_RUNTIME_PROFILE_AUTHORITY_GRANT_REQUIREMENT_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE,
  assertProtectedRecordsInstalledRuntimeProfilePreflight,
  assertProtectedRecordsInstalledRuntimeProfilePreflightArtifact,
} from '../lib/protected-records-installed-runtime-profile-preflight.mjs';

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

function writeInstallRoot(root, profile, profileSha, indexOverrides = {}) {
  mkdirSync(join(root, 'profiles'), { recursive: true });
  writeFileSync(join(root, 'profiles', `${profile.runtime_profile_id}.json`), `${JSON.stringify(profile, null, 2)}\n`);
  const index = {
    index_type: 'zlar-disposable-runtime-profile-active-index-v1',
    selected_profile_id: profile.profile_id,
    selected_runtime_profile_id: profile.runtime_profile_id,
    selected_profile_sha256: profileSha,
    selected_by_explicit_id_and_sha: true,
    selects_latest_profile: false,
    installed_profile_path: '<launcher-owned-disposable-install-root>/profiles/protected-records-disposable-runtime-profile.json',
    ...indexOverrides,
  };
  writeFileSync(join(root, 'active-runtime-profile.json'), `${JSON.stringify(index, null, 2)}\n`);
}

const ZLAR_BIN = join(process.cwd(), 'bin', 'zlar');
const PROFILE_PATH = 'profiles/protected-records-runtime-fixture.profile.json';
const SAMPLE_ARTIFACT_PATH = 'tests/fixtures/protected-records-installed-runtime-profile-preflight-artifact-v1.json';
const profile = JSON.parse(readFileSync(PROFILE_PATH, 'utf8'));
const profileSha = runtimeProfileSha256(profile);
const scratch = mkdtempSync(join(tmpdir(), 'zlar-installed-runtime-profile-preflight-cli-'));
const installRoot = join(scratch, 'install-root');
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;

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

try {
  writeInstallRoot(installRoot, profile, profileSha);

  section('text installed runtime profile preflight command');
  const textRun = runZlar([
    'protected-records-installed-runtime-profile-preflight',
    '--install-root',
    installRoot,
    '--expected-profile',
    PROFILE_PATH,
    '--profile-id',
    profile.profile_id,
    '--profile-sha256',
    profileSha,
  ]);
  assertEqual('text command exits zero', 0, textRun.status);
  assertEqual('text command emits no stderr', '', textRun.stderr);
  assert('text summary title present', textRun.stdout.includes('ZLAR Protected Records Installed Runtime Profile Preflight v1'));
  assert('text summary includes profile id', textRun.stdout.includes(`profile_id=${profile.profile_id}`));
  assert('text summary includes selected by id and sha', textRun.stdout.includes('selected_by_id_and_sha=true'));
  assert('text summary includes recognition contract', textRun.stdout.includes('Recognition contract: boundary=service-configured-recognition-rule'));
  assert('text summary includes authority grant requirement', textRun.stdout.includes('Authority grant requirement:'));
  assert('text summary keeps source profile grant false', textRun.stdout.includes('source_profile_authority_grant_present=false'));
  assert('text summary keeps exact runtime grant deferred', textRun.stdout.includes('exact_runtime_contract_deferred=true'));
  assert('text summary includes no activation', textRun.stdout.includes('activation_performed=false'));
  assert('text summary includes no current machine governance', textRun.stdout.includes('current_machine_governance_proven=false'));
  assert('text summary is privacy safe', !unsafeOutputPattern.test(textRun.stdout));

  section('json installed runtime profile preflight command');
  const jsonRun = runZlar([
    'protected-records-installed-runtime-profile-preflight',
    '--install-root',
    installRoot,
    '--expected-profile',
    PROFILE_PATH,
    '--profile-id',
    profile.profile_id,
    '--profile-sha256',
    profileSha,
    '--json',
  ]);
  assertEqual('json command exits zero', 0, jsonRun.status);
  assertEqual('json command emits no stderr', '', jsonRun.stderr);
  assert('json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
  const report = JSON.parse(jsonRun.stdout);
  assert('json report passes validation', assertProtectedRecordsInstalledRuntimeProfilePreflight(report));
  assertEqual('json preflight type', 'zlar-protected-records-installed-runtime-profile-preflight-v1', report.preflight_type);
  assertEqual('json read only true', true, report.read_only);
  assertEqual('json active index read true', true, report.inspection_boundary.active_index_read);
  assertEqual('json expected profile required true', true, report.requested_selection.expected_profile_required);
  assertEqual('json selected by id and sha true', true, report.inspection_boundary.selected_by_explicit_id_and_sha);
  assertEqual('json recognition contract preserved', 'service-configured-recognition-rule', report.recognition_contract.recognition_boundary);
  assertEqual('json recognition route preserved', 'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation', report.recognition_contract.mutation_authoritative_route);
  assertEqual('json recognition downstream refusal still false', false, report.recognition_contract.downstream_refusal_proven);
  assertEqual('json authority grant requirement type', INSTALLED_RUNTIME_PROFILE_AUTHORITY_GRANT_REQUIREMENT_TYPE, report.authority_grant_requirement.requirement_type);
  assertEqual('json launcher-owned fixture overlay true', true, report.authority_grant_requirement.launcher_owned_local_fixture_overlay);
  assertEqual('json source profile authority grant absent', false, report.authority_grant_requirement.source_profile_authority_grant_present);
  assertEqual('json exact runtime grant absent', false, report.authority_grant_requirement.exact_runtime_contract_instantiated);
  assertEqual('json exact runtime grant deferred', true, report.authority_grant_requirement.exact_runtime_contract_deferred_until_preflight_body_sha_available);
  assertEqual('json authority grant hash cycle avoided', true, report.authority_grant_requirement.hash_cycle_avoided);
  assert('json authority grant requires replacement-contract issuance power', report.authority_grant_requirement.required_power_ids.includes('issue_replacement_authority_grant'));
  assert('json authority grant omits ambiguous renewal power', !report.authority_grant_requirement.required_power_ids.includes('renew_authority_grant'));
  assertEqual('json issuer appointment absent', false, report.authority_grant_requirement.actual_issuer_appointment_present);
  assertEqual('json issuer kid absent', false, report.authority_grant_requirement.actual_issuer_kid_present);
  assertEqual('json issuer public key absent', false, report.authority_grant_requirement.actual_issuer_public_key_present);
  assertEqual('json concrete grant window absent', false, report.authority_grant_requirement.concrete_grant_window_present);
  assertEqual('json authority grant runtime enforcement absent', false, report.authority_grant_requirement.runtime_enforcement_performed);
  assertEqual('json rightful issuance remains false', false, report.authority_grant_requirement.rightful_issuance_proven);
  assertEqual('json selects latest false', false, report.inspection_boundary.selects_latest_profile);
  assertEqual('json activation false', false, report.inspection_boundary.runtime_profile_activation_performed);
  assertEqual('json runtime service false', false, report.inspection_boundary.runtime_service_started);
  assertEqual('json live records false', false, report.inspection_boundary.live_records_system_checked);
  assertEqual('json current machine governance false', false, report.inspection_boundary.current_machine_governance_proven);

  section('stdin expected profile form');
  const stdinExpected = runZlar([
    'protected-records-installed-runtime-profile-preflight',
    '--install-root',
    installRoot,
    '--expected-profile',
    '-',
    '--profile-id',
    profile.profile_id,
    '--profile-sha256',
    profileSha,
    '--json',
  ], {
    input: JSON.stringify(profile),
  });
  assertEqual('stdin expected profile exits zero', 0, stdinExpected.status);
  assertEqual('stdin expected profile emits no stderr', '', stdinExpected.stderr);
  const stdinReport = JSON.parse(stdinExpected.stdout);
  assertEqual('stdin expected profile content match true', true, stdinReport.expected_profile.profile_content_matches_installed_profile);

  section('artifact command and verify command');
  const artifactPath = join(scratch, 'installed-runtime-profile-preflight-artifact.json');
  const artifactRun = runZlar([
    'protected-records-installed-runtime-profile-preflight',
    '--install-root',
    installRoot,
    '--expected-profile',
    PROFILE_PATH,
    '--profile-id',
    profile.profile_id,
    '--profile-sha256',
    profileSha,
    '--artifact',
    artifactPath,
  ]);
  assertEqual('artifact command exits zero', 0, artifactRun.status);
  assertEqual('artifact command emits no stderr', '', artifactRun.stderr);
  assert('artifact command keeps text summary', artifactRun.stdout.includes('Portable installed runtime profile preflight artifact:'));
  assert('artifact command output is privacy safe', !unsafeOutputPattern.test(artifactRun.stdout));
  const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
  assert('artifact file passes validation', assertProtectedRecordsInstalledRuntimeProfilePreflightArtifact(artifact));
  assertEqual('artifact file type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_TYPE, artifact.artifact_type);

  const artifactStdoutRun = runZlar([
    'protected-records-installed-runtime-profile-preflight',
    '--install-root',
    installRoot,
    '--expected-profile',
    PROFILE_PATH,
    '--profile-id',
    profile.profile_id,
    '--profile-sha256',
    profileSha,
    '--artifact',
    '-',
  ]);
  assertEqual('artifact stdout command exits zero', 0, artifactStdoutRun.status);
  assertEqual('artifact stdout command emits no stderr', '', artifactStdoutRun.stderr);
  assert('artifact stdout output is privacy safe', !unsafeOutputPattern.test(artifactStdoutRun.stdout));
  const artifactStdout = JSON.parse(artifactStdoutRun.stdout);
  assert('artifact stdout passes validation', assertProtectedRecordsInstalledRuntimeProfilePreflightArtifact(artifactStdout));
  assertEqual('artifact stdout equals artifact file', JSON.stringify(artifact), JSON.stringify(artifactStdout));

  const verifyRun = runZlar([
    'protected-records-installed-runtime-profile-preflight',
    'verify',
    '--input',
    artifactPath,
  ]);
  assertEqual('verify command exits zero', 0, verifyRun.status);
  assertEqual('verify command emits no stderr', '', verifyRun.stderr);
  assert('verify summary title present', verifyRun.stdout.includes('ZLAR Protected Records Installed Runtime Profile Preflight Artifact Verification v1'));
  assert('verify summary says verified', verifyRun.stdout.includes('verified=true'));
  assert('verify summary includes recognition contract', verifyRun.stdout.includes('recognition_contract_preserved=true'));
  assert('verify summary includes authority grant requirement', verifyRun.stdout.includes('authority_grant_requirement_preserved=true'));
  assert('verify summary keeps exact runtime grant deferred', verifyRun.stdout.includes('exact_runtime_contract_deferred=true'));
  assert('verify summary includes no effects', verifyRun.stdout.includes('activation_performed=false'));
  assert('verify summary is privacy safe', !unsafeOutputPattern.test(verifyRun.stdout));

  const verifyJsonRun = runZlar([
    'protected-records-installed-runtime-profile-preflight',
    'verify',
    '--input',
    artifactPath,
    '--json',
  ]);
  assertEqual('verify json command exits zero', 0, verifyJsonRun.status);
  assertEqual('verify json command emits no stderr', '', verifyJsonRun.stderr);
  assert('verify json output is privacy safe', !unsafeOutputPattern.test(verifyJsonRun.stdout));
  const verification = JSON.parse(verifyJsonRun.stdout);
  assertEqual('verify json type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
  assertEqual('verify json verified true', true, verification.verified);
  assertEqual('verify json read only true', true, verification.read_only);
  assertEqual('verify json selects latest false', false, verification.selects_latest_profile);
  assertEqual('verify json recognition contract preserved', true, verification.recognition_contract_preserved);
  assertEqual('verify json recognition boundary', 'service-configured-recognition-rule', verification.recognition_boundary);
  assertEqual('verify json recognition rule not agent supplied', false, verification.recognition_rule_supplied_by_agent);
  assertEqual('verify json authority grant requirement preserved', true, verification.authority_grant_requirement_preserved);
  assert('verify json authority grant requirement sha present', /^[a-f0-9]{64}$/.test(verification.authority_grant_requirement_sha256));
  assertEqual('verify json launcher-owned fixture overlay true', true, verification.launcher_owned_local_fixture_authority_grant_overlay);
  assertEqual('verify json source profile authority grant absent', false, verification.source_profile_authority_grant_present);
  assertEqual('verify json exact runtime grant absent', false, verification.exact_runtime_authority_grant_contract_instantiated);
  assertEqual('verify json exact runtime grant deferred', true, verification.exact_runtime_authority_grant_contract_deferred);
  assertEqual('verify json authority grant hash cycle avoided', true, verification.authority_grant_hash_cycle_avoided);
  assertEqual('verify json issuer appointment absent', false, verification.actual_issuer_appointment_present);
  assertEqual('verify json issuer kid absent', false, verification.actual_issuer_kid_present);
  assertEqual('verify json issuer public key absent', false, verification.actual_issuer_public_key_present);
  assertEqual('verify json concrete grant window absent', false, verification.concrete_grant_window_present);
  assertEqual('verify json authority grant runtime enforcement absent', false, verification.authority_grant_runtime_enforcement_performed);
  assertEqual('verify json install performed false', false, verification.runtime_profile_installation_performed);
  assertEqual('verify json runtime service false', false, verification.runtime_service_started);
  assertEqual('verify json downstream refusal false', false, verification.downstream_refusal_proven);

  const verifyStdinRun = runZlar(['protected-records-installed-runtime-profile-preflight', 'verify', '--input', '-'], {
    input: readFileSync(artifactPath, 'utf8'),
  });
  assertEqual('verify stdin command exits zero', 0, verifyStdinRun.status);
  assertEqual('verify stdin command emits no stderr', '', verifyStdinRun.stderr);
  assert('verify stdin says verified', verifyStdinRun.stdout.includes('verified=true'));
  assert('verify stdin is privacy safe', !unsafeOutputPattern.test(verifyStdinRun.stdout));

  section('committed sample artifact verify command');
  const sampleVerifyRun = runZlar(['protected-records-installed-runtime-profile-preflight', 'verify', '--sample']);
  assertEqual('sample option verify command exits zero', 0, sampleVerifyRun.status);
  assertEqual('sample option verify emits no stderr', '', sampleVerifyRun.stderr);
  assert('sample option verify says verified', sampleVerifyRun.stdout.includes('verified=true'));
  assert('sample option verify is privacy safe', !unsafeOutputPattern.test(sampleVerifyRun.stdout));

  const sampleOptionVerifyJsonRun = runZlar(['protected-records-installed-runtime-profile-preflight', 'verify', '--sample', '--json']);
  assertEqual('sample option verify json exits zero', 0, sampleOptionVerifyJsonRun.status);
  assertEqual('sample option verify json emits no stderr', '', sampleOptionVerifyJsonRun.stderr);
  const sampleOptionVerification = JSON.parse(sampleOptionVerifyJsonRun.stdout);
  assertEqual('sample option verify json type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE, sampleOptionVerification.verification_type);
  assertEqual('sample option verify json selected true', true, sampleOptionVerification.profile_selected_from_install_root);
  assertEqual('sample option verify json recognition contract preserved', true, sampleOptionVerification.recognition_contract_preserved);
  assertEqual('sample option verify json authority grant requirement preserved', true, sampleOptionVerification.authority_grant_requirement_preserved);
  assertEqual('sample option verify json exact runtime grant deferred', true, sampleOptionVerification.exact_runtime_authority_grant_contract_deferred);

  section('help and fail closed command handling');
  const helpRun = runZlar(['protected-records-installed-runtime-profile-preflight', '--help']);
  assertEqual('help exits zero', 0, helpRun.status);
  assert('help names usage', helpRun.stderr.includes('Usage: zlar protected-records-installed-runtime-profile-preflight --install-root <dir> --expected-profile <file|-> --profile-id <id> --profile-sha256 <sha256> [--json] [--artifact <file|->]'));
  assert('help names verify usage', helpRun.stderr.includes('zlar protected-records-installed-runtime-profile-preflight verify (--input <file|->|--sample) [--json] [--require-sha <artifact_body_sha256>]'));
  assert('help states proof-only evidence', helpRun.stderr.includes('validates active-profile selection metadata as proof-only evidence'));
  assert('help names first safe sample run', helpRun.stderr.includes('Use verify --sample as the first safe run'));
  assert('help states no latest', helpRun.stderr.includes('does not select --latest'));
  assert('help states no current-machine governance proof', helpRun.stderr.includes('prove current-machine governance'));
  assertEqual('help emits no stdout', '', helpRun.stdout);

  const mainHelp = runZlar(['help']);
  assertEqual('main help exits zero', 0, mainHelp.status);
  assert('main help lists installed runtime profile preflight', mainHelp.stdout.includes('protected-records-installed-runtime-profile-preflight'));

  const missingInputs = runZlar(['protected-records-installed-runtime-profile-preflight']);
  assert('missing inputs exits usage error', missingInputs.status !== 0);
  assertEqual('missing inputs emits no report', '', missingInputs.stdout);
  assert('missing inputs names required args', missingInputs.stderr.includes('--install-root, --expected-profile, --profile-id, and --profile-sha256 are required'));

  const unsupported = runZlar([
    'protected-records-installed-runtime-profile-preflight',
    '--install-root',
    installRoot,
    '--expected-profile',
    PROFILE_PATH,
    '--profile-id',
    profile.profile_id,
    '--profile-sha256',
    profileSha,
    '--latest',
  ]);
  assert('unsupported option exits usage error', unsupported.status !== 0);
  assertEqual('unsupported option emits no report', '', unsupported.stdout);
  assert('unsupported option names unsupported option', unsupported.stderr.includes('Unsupported option provided'));
  assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

  const artifactJsonConflict = runZlar([
    'protected-records-installed-runtime-profile-preflight',
    '--install-root',
    installRoot,
    '--expected-profile',
    PROFILE_PATH,
    '--profile-id',
    profile.profile_id,
    '--profile-sha256',
    profileSha,
    '--json',
    '--artifact',
    '-',
  ]);
  assert('artifact stdout json conflict exits usage error', artifactJsonConflict.status !== 0);
  assertEqual('artifact stdout json conflict emits no report', '', artifactJsonConflict.stdout);
  assert('artifact stdout json conflict names conflict', artifactJsonConflict.stderr.includes('Cannot combine --json with --artifact -'));

  const missingVerifyInput = runZlar(['protected-records-installed-runtime-profile-preflight', 'verify']);
  assert('missing verify input exits usage error', missingVerifyInput.status !== 0);
  assertEqual('missing verify input emits no report', '', missingVerifyInput.stdout);
  assert('missing verify input names input or sample', missingVerifyInput.stderr.includes('Missing required --input <file|-> or --sample'));

  const verifyInputSampleConflict = runZlar([
    'protected-records-installed-runtime-profile-preflight',
    'verify',
    '--input',
    SAMPLE_ARTIFACT_PATH,
    '--sample',
  ]);
  assert('verify input sample conflict exits usage error', verifyInputSampleConflict.status !== 0);
  assertEqual('verify input sample conflict emits no report', '', verifyInputSampleConflict.stdout);
  assert('verify input sample conflict names conflict', verifyInputSampleConflict.stderr.includes('Cannot combine --input with --sample'));

  const badShaRun = runZlar([
    'protected-records-installed-runtime-profile-preflight',
    '--install-root',
    installRoot,
    '--expected-profile',
    PROFILE_PATH,
    '--profile-id',
    profile.profile_id,
    '--profile-sha256',
    '0'.repeat(64),
  ]);
  assert('bad sha exits failure', badShaRun.status !== 0);
  assertEqual('bad sha emits no report', '', badShaRun.stdout);
  assert('bad sha names mismatch', badShaRun.stderr.includes('expected profile mismatch'));

  const latestRoot = join(scratch, 'latest-root');
  writeInstallRoot(latestRoot, profile, profileSha, { selects_latest_profile: true });
  const latestRun = runZlar([
    'protected-records-installed-runtime-profile-preflight',
    '--install-root',
    latestRoot,
    '--expected-profile',
    PROFILE_PATH,
    '--profile-id',
    profile.profile_id,
    '--profile-sha256',
    profileSha,
  ]);
  assert('latest index exits failure', latestRun.status !== 0);
  assertEqual('latest index emits no report', '', latestRun.stdout);
  assert('latest index names drift', latestRun.stderr.includes('active index drifted'));

  const profilesDirSymlinkRoot = join(scratch, 'profiles-dir-symlink-root');
  const externalProfilesDir = join(scratch, 'external-profiles-dir');
  mkdirSync(profilesDirSymlinkRoot, { recursive: true });
  mkdirSync(externalProfilesDir, { recursive: true });
  writeFileSync(join(externalProfilesDir, `${profile.runtime_profile_id}.json`), `${JSON.stringify(profile, null, 2)}\n`);
  writeFileSync(join(profilesDirSymlinkRoot, 'active-runtime-profile.json'), `${JSON.stringify({
    index_type: 'zlar-disposable-runtime-profile-active-index-v1',
    selected_profile_id: profile.profile_id,
    selected_runtime_profile_id: profile.runtime_profile_id,
    selected_profile_sha256: profileSha,
    selected_by_explicit_id_and_sha: true,
    selects_latest_profile: false,
    installed_profile_path: '<launcher-owned-disposable-install-root>/profiles/protected-records-disposable-runtime-profile.json',
  }, null, 2)}\n`);
  symlinkSync(externalProfilesDir, join(profilesDirSymlinkRoot, 'profiles'));
  const profilesDirSymlinkRun = runZlar([
    'protected-records-installed-runtime-profile-preflight',
    '--install-root',
    profilesDirSymlinkRoot,
    '--expected-profile',
    PROFILE_PATH,
    '--profile-id',
    profile.profile_id,
    '--profile-sha256',
    profileSha,
  ]);
  assert('symlink profiles directory exits failure', profilesDirSymlinkRun.status !== 0);
  assertEqual('symlink profiles directory emits no report', '', profilesDirSymlinkRun.stdout);
  assert('symlink profiles directory names boundary', profilesDirSymlinkRun.stderr.includes('installed runtime profiles directory must not be a symlink'));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(`\nResults: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) {
  process.exit(1);
}
console.log('ALL PASS');
