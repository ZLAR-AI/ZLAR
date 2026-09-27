#!/usr/bin/env node

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
  PROTECTED_RECORDS_CONSEQUENCE_PATH,
  PROTECTED_RECORDS_TARGET_HANDLE,
  PROTECTED_RECORDS_TARGET_KIND,
  PROTECTED_RECORDS_TARGET_SCOPE,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from '../lib/protected-records-runtime-profile.mjs';
import {
  runtimeProfileSha256,
} from '../lib/protected-records-runtime-profile-preflight.mjs';
import {
  INSTALLED_RUNTIME_PROFILE_PREFLIGHT_NON_CLAIMS,
  INSTALLED_RUNTIME_PROFILE_PREFLIGHT_SAFE_CLAIM_CEILING,
  INSTALLED_RUNTIME_PROFILE_AUTHORITY_GRANT_REQUIREMENT_TYPE,
  INSTALLED_RUNTIME_PROFILE_RECOGNITION_CONTRACT_TYPE,
  INSTALLED_RUNTIME_PROFILE_TARGET_CONTRACT_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_TYPE,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_OPEN_BOUNDARIES,
  assertProtectedRecordsInstalledRuntimeProfileActiveIndex,
  assertProtectedRecordsInstalledRuntimeProfilePreflight,
  assertProtectedRecordsInstalledRuntimeProfilePreflightArtifact,
  buildProtectedRecordsInstalledRuntimeProfilePreflightArtifact,
  formatProtectedRecordsInstalledRuntimeProfilePreflightArtifactSummary,
  formatProtectedRecordsInstalledRuntimeProfilePreflightArtifactVerification,
  formatProtectedRecordsInstalledRuntimeProfilePreflightSummary,
  parseProtectedRecordsInstalledRuntimeProfilePreflightArtifactText,
  protectedRecordsInstalledRuntimeProfileAuthorityGrantRequirementSha256,
  protectedRecordsInstalledRuntimeProfileTargetContractSha256,
  runProtectedRecordsInstalledRuntimeProfilePreflight,
  verifyProtectedRecordsInstalledRuntimeProfilePreflightArtifact,
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

function writeInstallRoot(root, profile, profileSha, indexOverrides = {}, profileOverrides = {}) {
  mkdirSync(join(root, 'profiles'), { recursive: true });
  const installedProfile = {
    ...profile,
    ...profileOverrides,
  };
  writeFileSync(
    join(root, 'profiles', `${profile.runtime_profile_id}.json`),
    `${JSON.stringify(installedProfile, null, 2)}\n`
  );
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
  return { index, installedProfile };
}

const PROFILE_PATH = 'profiles/protected-records-runtime-fixture.profile.json';
const SAMPLE_ARTIFACT_PATH = 'tests/fixtures/protected-records-installed-runtime-profile-preflight-artifact-v1.json';
const profile = JSON.parse(readFileSync(PROFILE_PATH, 'utf8'));
const profileSha = runtimeProfileSha256(profile);
const scratch = mkdtempSync(join(tmpdir(), 'zlar-installed-runtime-profile-preflight-test-'));
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;

try {
  const installRoot = join(scratch, 'install-root');
  const { index } = writeInstallRoot(installRoot, profile, profileSha);

  section('active index contract');
  assert('active index passes validation', assertProtectedRecordsInstalledRuntimeProfileActiveIndex(index, profile.profile_id, profileSha));
  assertEqual('active index type', 'zlar-disposable-runtime-profile-active-index-v1', index.index_type);
  assertEqual('active index selected by explicit id and sha', true, index.selected_by_explicit_id_and_sha);
  assertEqual('active index does not select latest', false, index.selects_latest_profile);

  section('installed runtime profile preflight report');
  const report = runProtectedRecordsInstalledRuntimeProfilePreflight({
    installRoot,
    expectedProfile: profile,
    profileId: profile.profile_id,
    profileSha256: profileSha,
  });
  assert('preflight report passes validation', assertProtectedRecordsInstalledRuntimeProfilePreflight(report));
  assertEqual('preflight type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_TYPE, report.preflight_type);
  assertEqual('safe claim ceiling exact', INSTALLED_RUNTIME_PROFILE_PREFLIGHT_SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
  assertEqual('evidence model read-only root', 'supplied-installed-runtime-profile-root-read-only', report.evidence_model);
  assertEqual('read only true', true, report.read_only);
  assertEqual('live probing false', false, report.live_probing);
  assertEqual('explicit install root required', true, report.requested_selection.install_root_required);
  assertEqual('explicit expected profile required', true, report.requested_selection.expected_profile_required);
  assertEqual('current machine default false', false, report.requested_selection.current_machine_default_used);
  assertEqual('profile id bound', profile.profile_id, report.requested_selection.profile_id);
  assertEqual('profile sha bound', profileSha, report.requested_selection.profile_sha256);
  assertEqual('expected profile sha matches CLI', true, report.expected_profile.profile_sha_matches_cli_argument);
  assertEqual('expected profile content matches installed', true, report.expected_profile.profile_content_matches_installed_profile);
  assertEqual('active index read', true, report.inspection_boundary.active_index_read);
  assertEqual('active index symlink refused', true, report.inspection_boundary.active_index_symlink_refused);
  assertEqual('installed profile read', true, report.inspection_boundary.installed_profile_read);
  assertEqual('installed profile contract valid', true, report.installed_profile.contract_valid);
  assertEqual('profile sha matches active index', true, report.installed_profile.profile_sha_matches_active_index);
  assertEqual('recognition contract type', INSTALLED_RUNTIME_PROFILE_RECOGNITION_CONTRACT_TYPE, report.recognition_contract.contract_type);
  assertEqual('recognition contract source', 'selected-installed-runtime-profile', report.recognition_contract.source);
  assertEqual('recognition boundary preserved', 'service-configured-recognition-rule', report.recognition_contract.recognition_boundary);
  assertEqual('mutation route preserved', 'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation', report.recognition_contract.mutation_authoritative_route);
  assertEqual('request contract preserved', 'receipt-record-update-and-routing-metadata-only', report.recognition_contract.request_contract);
  assertEqual('downstream recognition required', true, report.recognition_contract.downstream_recognition_required);
  assertEqual('launcher supplies config', true, report.recognition_contract.launcher_authority.config_supplied_by_launcher);
  assertEqual('request stream authority material refused', false, report.recognition_contract.launcher_authority.request_stream_authority_material_accepted);
  assertEqual('recognition rule not agent supplied', false, report.recognition_contract.launcher_authority.recognition_rule_supplied_by_agent);
  assertEqual('fixture mode not agent supplied', false, report.recognition_contract.launcher_authority.fixture_mode_supplied_by_agent);
  assertEqual('unsupported request fields refused', false, report.recognition_contract.launcher_authority.unsupported_request_fields_accepted);
  assertEqual('recognition contract refusal case count', REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length, report.recognition_contract.required_refusal_case_count);
  assertEqual('recognition contract downstream refusal still false', false, report.recognition_contract.downstream_refusal_proven);
  assertEqual('recognition contract current machine governance false', false, report.recognition_contract.current_machine_governance_proven);
  for (const caseId of REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES) {
    assert(`recognition refusal case preserved: ${caseId}`, report.recognition_contract.required_refusal_cases.includes(caseId));
  }
  assertEqual('target contract type', INSTALLED_RUNTIME_PROFILE_TARGET_CONTRACT_TYPE, report.target_contract.contract_type);
  assertEqual('target consequence path exact', PROTECTED_RECORDS_CONSEQUENCE_PATH, report.target_contract.consequence_path);
  assertEqual('target kind exact', PROTECTED_RECORDS_TARGET_KIND, report.target_contract.target_kind);
  assertEqual('target scope logical fixture', PROTECTED_RECORDS_TARGET_SCOPE, report.target_contract.target_scope);
  assertEqual('target instance is not per run', 'logical-fixture-not-per-run', report.target_contract.target_instance_scope);
  assertEqual('target handle exact', PROTECTED_RECORDS_TARGET_HANDLE, report.target_contract.target_handle);
  assertEqual('request target is assertion only', 'assertion-only', report.target_contract.request_target_semantics);
  assertEqual('source profile has no target handle', false, report.target_contract.source_profile_target_handle_present);
  assertEqual('profile-wide target authority not proven', false, report.target_contract.profile_wide_target_authority_proven);
  assertEqual('rightful issuance not proven', false, report.target_contract.rightful_issuance_proven);
  assertEqual('lifecycle remains open', false, report.target_contract.consequence_lifecycle_closed);
  assert('target contract sha present', /^[a-f0-9]{64}$/.test(
    protectedRecordsInstalledRuntimeProfileTargetContractSha256(report.target_contract)
  ));
  assertEqual(
    'authority grant requirement type',
    INSTALLED_RUNTIME_PROFILE_AUTHORITY_GRANT_REQUIREMENT_TYPE,
    report.authority_grant_requirement.requirement_type
  );
  assertEqual(
    'authority grant requirement is launcher fixture overlay',
    true,
    report.authority_grant_requirement.launcher_owned_local_fixture_overlay
  );
  assertEqual(
    'source profile carries no authority grant',
    false,
    report.authority_grant_requirement.source_profile_authority_grant_present
  );
  assertEqual(
    'exact runtime grant not instantiated',
    false,
    report.authority_grant_requirement.exact_runtime_contract_instantiated
  );
  assertEqual(
    'exact runtime grant deferred until preflight hash exists',
    true,
    report.authority_grant_requirement
      .exact_runtime_contract_deferred_until_preflight_body_sha_available
  );
  assertEqual(
    'authority grant hash cycle avoided',
    true,
    report.authority_grant_requirement.hash_cycle_avoided
  );
  assert(
    'authority grant requires replacement-contract issuance power',
    report.authority_grant_requirement.required_power_ids.includes(
      'issue_replacement_authority_grant'
    )
  );
  assert(
    'authority grant omits ambiguous renewal power',
    !report.authority_grant_requirement.required_power_ids.includes(
      'renew_authority_grant'
    )
  );
  assertEqual(
    'no issuer appointment in preflight',
    false,
    report.authority_grant_requirement.actual_issuer_appointment_present
  );
  assertEqual(
    'no issuer kid in preflight',
    false,
    report.authority_grant_requirement.actual_issuer_kid_present
  );
  assertEqual(
    'no issuer public key in preflight',
    false,
    report.authority_grant_requirement.actual_issuer_public_key_present
  );
  assertEqual(
    'no concrete grant window in preflight',
    false,
    report.authority_grant_requirement.concrete_grant_window_present
  );
  assertEqual(
    'no grant runtime enforcement in preflight',
    false,
    report.authority_grant_requirement.runtime_enforcement_performed
  );
  assertEqual(
    'preflight requirement does not prove rightful issuance',
    false,
    report.authority_grant_requirement.rightful_issuance_proven
  );
  const authorityGrantRequirementSha256 =
    protectedRecordsInstalledRuntimeProfileAuthorityGrantRequirementSha256(
      report.authority_grant_requirement
    );
  assert(
    'authority grant requirement digest present',
    /^[a-f0-9]{64}$/.test(authorityGrantRequirementSha256)
  );
  assertEqual(
    'authority grant requirement digest deterministic',
    authorityGrantRequirementSha256,
    protectedRecordsInstalledRuntimeProfileAuthorityGrantRequirementSha256(
      structuredClone(report.authority_grant_requirement)
    )
  );
  assertEqual('profile selected from install root', true, report.inspection_boundary.profile_selected_from_install_root);
  assertEqual('selected by explicit id and sha', true, report.inspection_boundary.selected_by_explicit_id_and_sha);
  assertEqual('selects latest false', false, report.inspection_boundary.selects_latest_profile);
  assertEqual('install not performed', false, report.inspection_boundary.runtime_profile_installation_performed);
  assertEqual('activation not performed', false, report.inspection_boundary.runtime_profile_activation_performed);
  assertEqual('runtime config not written', false, report.inspection_boundary.runtime_config_written);
  assertEqual('hook config not written', false, report.inspection_boundary.hook_configuration_written);
  assertEqual('user config not written', false, report.inspection_boundary.user_config_written);
  assertEqual('machine config not written', false, report.inspection_boundary.machine_config_written);
  assertEqual('runtime service not started', false, report.inspection_boundary.runtime_service_started);
  assertEqual('live records unchecked', false, report.inspection_boundary.live_records_system_checked);
  assertEqual('downstream refusal not proven', false, report.inspection_boundary.downstream_refusal_proven);
  assertEqual('current machine governance not proven', false, report.inspection_boundary.current_machine_governance_proven);
  for (const boundary of REQUIRED_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_OPEN_BOUNDARIES) {
    assert(`open boundary present: ${boundary}`, report.known_open_boundaries.includes(boundary));
  }
  for (const claim of INSTALLED_RUNTIME_PROFILE_PREFLIGHT_NON_CLAIMS) {
    assert(`non-claim present: ${claim}`, report.non_claims.includes(claim));
  }
  assert('json output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report, null, 2)));
  assert('json omits raw paths and secrets', !unsafeOutputPattern.test(JSON.stringify(report)));

  section('safe output formatting');
  const summary = formatProtectedRecordsInstalledRuntimeProfilePreflightSummary(report);
  assert('summary title present', summary.includes('ZLAR Protected Records Installed Runtime Profile Preflight v1'));
  assert('summary includes expected selection', summary.includes('install_root_required=true'));
  assert('summary includes selected by id and sha', summary.includes('selected_by_id_and_sha=true'));
  assert('summary includes recognition contract', summary.includes('Recognition contract: boundary=service-configured-recognition-rule'));
  assert('summary includes target contract', summary.includes(`Target contract: consequence_path=${PROTECTED_RECORDS_CONSEQUENCE_PATH}`));
  assert('summary includes authority grant requirement', summary.includes('Authority grant requirement:'));
  assert('summary keeps exact grant deferred', summary.includes('exact_runtime_contract_deferred=true'));
  assert('summary keeps source profile grant false', summary.includes('source_profile_authority_grant_present=false'));
  assert('summary includes downstream refusal non-proof', summary.includes('downstream_refusal_proven=false'));
  assert('summary includes no effects', summary.includes('activation_performed=false'));
  assert('summary includes current machine non-proof', summary.includes('current_machine_governance_proven=false'));
  assert('summary output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(summary));

  section('portable artifact and verification');
  const artifact = buildProtectedRecordsInstalledRuntimeProfilePreflightArtifact(report);
  assert('artifact passes validation', assertProtectedRecordsInstalledRuntimeProfilePreflightArtifact(artifact));
  assertEqual('artifact type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_TYPE, artifact.artifact_type);
  assertEqual('artifact canonicalization', 'zlar-canonical-json-v1', artifact.canonicalization);
  assertEqual('artifact generator', 'zlar protected-records-installed-runtime-profile-preflight --artifact', artifact.generator);
  assertEqual('artifact hash scope', 'canonical artifact body without integrity', artifact.hash_scope);
  assert('artifact sha malformed false', /^[a-f0-9]{64}$/.test(artifact.integrity.body_sha256));
  assert('artifact text is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(artifact, null, 2)));

  const parsedArtifact = parseProtectedRecordsInstalledRuntimeProfilePreflightArtifactText(JSON.stringify(artifact, null, 2));
  assert('parsed artifact passes validation', assertProtectedRecordsInstalledRuntimeProfilePreflightArtifact(parsedArtifact));
  assertEqual('parsed artifact sha stable', artifact.integrity.body_sha256, parsedArtifact.integrity.body_sha256);

  const verification = verifyProtectedRecordsInstalledRuntimeProfilePreflightArtifact(parsedArtifact);
  assertEqual('verification type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
  assertEqual('verification verified true', true, verification.verified);
  assertEqual('verification sha matches artifact', artifact.integrity.body_sha256, verification.body_sha256);
  assertEqual('verification read only true', true, verification.read_only);
  assertEqual('verification active index read true', true, verification.active_index_read);
  assertEqual('verification installed profile read true', true, verification.installed_profile_read);
  assertEqual('verification contract validated true', true, verification.installed_profile_contract_validated);
  assertEqual('verification selected by id and sha true', true, verification.selected_by_explicit_id_and_sha);
  assertEqual('verification selects latest false', false, verification.selects_latest_profile);
  assertEqual('verification recognition contract preserved', true, verification.recognition_contract_preserved);
  assertEqual('verification recognition boundary', 'service-configured-recognition-rule', verification.recognition_boundary);
  assertEqual('verification mutation route', 'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation', verification.mutation_authoritative_route);
  assertEqual('verification request stream authority material false', false, verification.request_stream_authority_material_accepted);
  assertEqual('verification recognition rule supplied false', false, verification.recognition_rule_supplied_by_agent);
  assertEqual('verification refusal case count', REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length, verification.required_refusal_case_count);
  assertEqual('verification target contract preserved', true, verification.target_contract_preserved);
  assert('verification target contract sha present', /^[a-f0-9]{64}$/.test(verification.target_contract_sha256));
  assertEqual('verification consequence path exact', PROTECTED_RECORDS_CONSEQUENCE_PATH, verification.consequence_path);
  assertEqual('verification target handle exact', PROTECTED_RECORDS_TARGET_HANDLE, verification.target_handle);
  assertEqual('verification profile-wide target authority false', false, verification.profile_wide_target_authority_proven);
  assertEqual('verification rightful issuance false', false, verification.rightful_issuance_proven);
  assertEqual('verification lifecycle open', false, verification.consequence_lifecycle_closed);
  assertEqual('verification authority grant requirement preserved', true, verification.authority_grant_requirement_preserved);
  assertEqual('verification authority grant requirement sha preserved', authorityGrantRequirementSha256, verification.authority_grant_requirement_sha256);
  assertEqual('verification launcher fixture overlay true', true, verification.launcher_owned_local_fixture_authority_grant_overlay);
  assertEqual('verification source profile grant false', false, verification.source_profile_authority_grant_present);
  assertEqual('verification exact runtime grant absent', false, verification.exact_runtime_authority_grant_contract_instantiated);
  assertEqual('verification exact runtime grant deferred', true, verification.exact_runtime_authority_grant_contract_deferred);
  assertEqual('verification hash cycle avoided', true, verification.authority_grant_hash_cycle_avoided);
  assertEqual('verification issuer appointment absent', false, verification.actual_issuer_appointment_present);
  assertEqual('verification issuer kid absent', false, verification.actual_issuer_kid_present);
  assertEqual('verification issuer public key absent', false, verification.actual_issuer_public_key_present);
  assertEqual('verification concrete window absent', false, verification.concrete_grant_window_present);
  assertEqual('verification grant runtime enforcement absent', false, verification.authority_grant_runtime_enforcement_performed);
  assertEqual('verification install performed false', false, verification.runtime_profile_installation_performed);
  assertEqual('verification activation performed false', false, verification.runtime_profile_activation_performed);
  assertEqual('verification runtime service false', false, verification.runtime_service_started);
  assertEqual('verification downstream refusal false', false, verification.downstream_refusal_proven);
  assertEqual('verification current machine governance false', false, verification.current_machine_governance_proven);
  assert('verification output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(verification, null, 2)));

  const artifactSummary = formatProtectedRecordsInstalledRuntimeProfilePreflightArtifactSummary(artifact);
  assert('artifact summary names portable artifact', artifactSummary.includes('Portable installed runtime profile preflight artifact:'));
  assert('artifact summary includes checksum', artifactSummary.includes(artifact.integrity.body_sha256));
  assert('artifact summary is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(artifactSummary));

  const verificationSummary = formatProtectedRecordsInstalledRuntimeProfilePreflightArtifactVerification(verification);
  assert('verification summary title present', verificationSummary.includes('ZLAR Protected Records Installed Runtime Profile Preflight Artifact Verification v1'));
  assert('verification summary says verified', verificationSummary.includes('verified=true'));
  assert('verification summary includes recognition contract', verificationSummary.includes('recognition_contract_preserved=true'));
  assert('verification summary includes target contract', verificationSummary.includes('target_contract_preserved=true'));
  assert('verification summary includes authority grant requirement', verificationSummary.includes('authority_grant_requirement_preserved=true'));
  assert('verification summary keeps exact grant deferred', verificationSummary.includes('exact_runtime_contract_deferred=true'));
  assert('verification summary includes no effects', verificationSummary.includes('activation_performed=false'));
  assert('verification summary includes claim boundary', verificationSummary.includes('read-only installed runtime profile preflight boundaries only'));
  assert('verification summary is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(verificationSummary));

  section('committed sample artifact');
  const sampleArtifactText = readFileSync(SAMPLE_ARTIFACT_PATH, 'utf8');
  assert('sample artifact text is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(sampleArtifactText));
  const sampleArtifact = parseProtectedRecordsInstalledRuntimeProfilePreflightArtifactText(sampleArtifactText);
  assert('sample artifact passes validation', assertProtectedRecordsInstalledRuntimeProfilePreflightArtifact(sampleArtifact));
  assertEqual('sample artifact matches generated artifact', JSON.stringify(artifact), JSON.stringify(sampleArtifact));
  const sampleVerification = verifyProtectedRecordsInstalledRuntimeProfilePreflightArtifact(sampleArtifact);
  assertEqual('sample artifact verifies true', true, sampleVerification.verified);
  assertEqual('sample verification sha matches fixture', artifact.integrity.body_sha256, sampleVerification.body_sha256);

  section('fail closed validation');
  assertThrows('missing install root fails', () => runProtectedRecordsInstalledRuntimeProfilePreflight({
    expectedProfile: profile,
    profileId: profile.profile_id,
    profileSha256: profileSha,
  }), 'install root is required');

  assertThrows('expected profile sha mismatch fails', () => runProtectedRecordsInstalledRuntimeProfilePreflight({
    installRoot,
    expectedProfile: profile,
    profileId: profile.profile_id,
    profileSha256: '0'.repeat(64),
  }), 'expected profile mismatch');

  const latestRoot = join(scratch, 'latest-root');
  writeInstallRoot(latestRoot, profile, profileSha, { selects_latest_profile: true });
  assertThrows('latest selection fails', () => runProtectedRecordsInstalledRuntimeProfilePreflight({
    installRoot: latestRoot,
    expectedProfile: profile,
    profileId: profile.profile_id,
    profileSha256: profileSha,
  }), 'active index drifted');

  const selectedByRoot = join(scratch, 'selected-by-root');
  writeInstallRoot(selectedByRoot, profile, profileSha, { selected_by_explicit_id_and_sha: false });
  assertThrows('non-explicit selection fails', () => runProtectedRecordsInstalledRuntimeProfilePreflight({
    installRoot: selectedByRoot,
    expectedProfile: profile,
    profileId: profile.profile_id,
    profileSha256: profileSha,
  }), 'active index drifted');

  const installedMismatchRoot = join(scratch, 'installed-mismatch-root');
  writeInstallRoot(installedMismatchRoot, profile, profileSha, {}, { service_command: 'zlar protected-records-runtime-service --config <drifted>' });
  assertThrows('installed profile contract drift fails', () => runProtectedRecordsInstalledRuntimeProfilePreflight({
    installRoot: installedMismatchRoot,
    expectedProfile: profile,
    profileId: profile.profile_id,
    profileSha256: profileSha,
  }), 'contract drifted');

  const symlinkRoot = join(scratch, 'symlink-root');
  symlinkSync(installRoot, symlinkRoot);
  assertThrows('symlink install root fails', () => runProtectedRecordsInstalledRuntimeProfilePreflight({
    installRoot: symlinkRoot,
    expectedProfile: profile,
    profileId: profile.profile_id,
    profileSha256: profileSha,
  }), 'install root must not be a symlink');

  const activeIndexSymlinkRoot = join(scratch, 'active-index-symlink-root');
  mkdirSync(activeIndexSymlinkRoot, { recursive: true });
  symlinkSync(join(installRoot, 'active-runtime-profile.json'), join(activeIndexSymlinkRoot, 'active-runtime-profile.json'));
  mkdirSync(join(activeIndexSymlinkRoot, 'profiles'), { recursive: true });
  writeFileSync(join(activeIndexSymlinkRoot, 'profiles', `${profile.runtime_profile_id}.json`), `${JSON.stringify(profile, null, 2)}\n`);
  assertThrows('symlink active index fails', () => runProtectedRecordsInstalledRuntimeProfilePreflight({
    installRoot: activeIndexSymlinkRoot,
    expectedProfile: profile,
    profileId: profile.profile_id,
    profileSha256: profileSha,
  }), 'active-profile index must not be a symlink');

  const profilesDirSymlinkRoot = join(scratch, 'profiles-dir-symlink-root');
  const externalProfilesDir = join(scratch, 'external-profiles-dir');
  mkdirSync(profilesDirSymlinkRoot, { recursive: true });
  mkdirSync(externalProfilesDir, { recursive: true });
  writeFileSync(join(externalProfilesDir, `${profile.runtime_profile_id}.json`), `${JSON.stringify(profile, null, 2)}\n`);
  writeFileSync(join(profilesDirSymlinkRoot, 'active-runtime-profile.json'), `${JSON.stringify(index, null, 2)}\n`);
  symlinkSync(externalProfilesDir, join(profilesDirSymlinkRoot, 'profiles'));
  assertThrows('symlink profiles directory fails', () => runProtectedRecordsInstalledRuntimeProfilePreflight({
    installRoot: profilesDirSymlinkRoot,
    expectedProfile: profile,
    profileId: profile.profile_id,
    profileSha256: profileSha,
  }), 'installed runtime profiles directory must not be a symlink');

  const driftedReport = structuredClone(report);
  driftedReport.inspection_boundary.runtime_service_started = true;
  assertThrows('runtime service claim fails', () => assertProtectedRecordsInstalledRuntimeProfilePreflight(driftedReport), 'inspection boundary drifted');

  const currentMachineReport = structuredClone(report);
  currentMachineReport.requested_selection.current_machine_default_used = true;
  assertThrows('current machine default claim fails', () => assertProtectedRecordsInstalledRuntimeProfilePreflight(currentMachineReport), 'requested selection drifted');

  const hookWriteReport = structuredClone(report);
  hookWriteReport.side_door_report.hook_configuration_written = true;
  assertThrows('hook write claim fails', () => assertProtectedRecordsInstalledRuntimeProfilePreflight(hookWriteReport), 'side-door report drifted');

  const recognitionDriftReport = structuredClone(report);
  recognitionDriftReport.recognition_contract.downstream_refusal_proven = true;
  assertThrows('recognition contract refusal proof drift fails', () => assertProtectedRecordsInstalledRuntimeProfilePreflight(recognitionDriftReport), 'recognition contract drifted');

  const targetHandleDriftReport = structuredClone(report);
  targetHandleDriftReport.target_contract.target_handle = `zlar-target:v1:logical-fixture:${'f'.repeat(64)}`;
  assertThrows('target contract handle drift fails', () => assertProtectedRecordsInstalledRuntimeProfilePreflight(targetHandleDriftReport), 'target contract drifted');

  const targetAuthorityClaimReport = structuredClone(report);
  targetAuthorityClaimReport.target_contract.profile_wide_target_authority_proven = true;
  assertThrows('target authority overclaim fails', () => assertProtectedRecordsInstalledRuntimeProfilePreflight(targetAuthorityClaimReport), 'target contract drifted');

  const instantiatedGrantReport = structuredClone(report);
  instantiatedGrantReport.authority_grant_requirement.exact_runtime_contract_instantiated = true;
  assertThrows('preflight exact grant instantiation fails', () => assertProtectedRecordsInstalledRuntimeProfilePreflight(instantiatedGrantReport), 'authority grant requirement drifted');

  const hiddenGrantCycleReport = structuredClone(report);
  hiddenGrantCycleReport.authority_grant_requirement.hash_cycle_avoided = false;
  assertThrows('preflight grant hash cycle concealment fails', () => assertProtectedRecordsInstalledRuntimeProfilePreflight(hiddenGrantCycleReport), 'authority grant requirement drifted');

  const issuerAppointmentReport = structuredClone(report);
  issuerAppointmentReport.authority_grant_requirement.actual_issuer_appointment_present = true;
  assertThrows('preflight issuer appointment claim fails', () => assertProtectedRecordsInstalledRuntimeProfilePreflight(issuerAppointmentReport), 'authority grant requirement drifted');

  for (const field of [
    'source_profile_authority_grant_present',
    'actual_issuer_kid_present',
    'actual_issuer_public_key_present',
    'concrete_grant_window_present',
    'runtime_enforcement_performed',
    'rightful_issuance_proven',
  ]) {
    const overclaimReport = structuredClone(report);
    overclaimReport.authority_grant_requirement[field] = true;
    assertThrows(`preflight authority grant overclaim fails: ${field}`, () => assertProtectedRecordsInstalledRuntimeProfilePreflight(overclaimReport), 'authority grant requirement drifted');
  }

  const tamperedArtifact = structuredClone(artifact);
  tamperedArtifact.payload.preflight.inspection_boundary.runtime_profile_activation_performed = true;
  assertThrows('tampered artifact fails validation', () => assertProtectedRecordsInstalledRuntimeProfilePreflightArtifact(tamperedArtifact), 'inspection boundary drifted');

  const tamperedTargetArtifact = structuredClone(artifact);
  tamperedTargetArtifact.payload.preflight.target_contract.target_descriptor.target_scope = 'drifted';
  assertThrows('tampered target artifact fails validation', () => assertProtectedRecordsInstalledRuntimeProfilePreflightArtifact(tamperedTargetArtifact), 'target contract drifted');
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(`\nResults: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) {
  process.exit(1);
}
console.log('ALL PASS');
