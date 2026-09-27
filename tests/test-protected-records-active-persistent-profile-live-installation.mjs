#!/usr/bin/env node

import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
} from '../lib/protected-records-active-persistent-profile-preflight.mjs';
import {
  ACTIVE_PERSISTENT_PROFILE_LIVE_CLAIM,
  ACTIVE_PERSISTENT_PROFILE_LIVE_NON_CLAIMS,
  ACTIVE_PERSISTENT_PROFILE_LIVE_OPEN_BOUNDARIES,
  PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_INSTALLATION_REPORT_TYPE,
  assertActivePersistentProfileLiveCloseout,
  assertActivePersistentProfileLiveInstallationReport,
  assertActivePersistentProfileLiveStatus,
  closeActivePersistentProfileLiveInstallation,
  defaultActivePersistentProfileLiveRoot,
  formatActivePersistentProfileLiveCloseout,
  formatActivePersistentProfileLiveInstallationReport,
  formatActivePersistentProfileLiveStatus,
  inspectActivePersistentProfileLiveStatus,
  runActivePersistentProfileLiveInstallation,
  writeActivePersistentProfileLiveReport,
} from '../lib/protected-records-active-persistent-profile-live-installation.mjs';
import {
  runProtectedRecordsInstalledRuntimeProfilePreflight,
} from '../lib/protected-records-installed-runtime-profile-preflight.mjs';
import {
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from '../lib/protected-records-runtime-profile.mjs';

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

function activationRoot(scratch) {
  return join(scratch, 'activation', 'protected-records-private-operator-records-terminal');
}

function installOptions(scratch, profile) {
  return {
    activationRoot: activationRoot(scratch),
    profile,
    profileSource: 'profiles/protected-records-runtime-fixture.profile.json',
    runtimeProfileId: 'protected-records-disposable-runtime-profile',
    runtimeProfileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    expiresAt: '2030-01-01T00:00:00.000Z',
    nowEpoch: 1700000000,
  };
}

const profile = JSON.parse(readFileSync('profiles/protected-records-runtime-fixture.profile.json', 'utf8'));
const scratch = mkdtempSync(join(tmpdir(), 'zlar-active-persistent-live-test-'));
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY|~\/\.zlar/i;

try {
  section('live installation report on surrogate root');
  const report = runActivePersistentProfileLiveInstallation(installOptions(scratch, profile));
  assert('report validates', assertActivePersistentProfileLiveInstallationReport(report));
  const legacyFirstInstallReport = structuredClone(report);
  legacyFirstInstallReport.preinstall_status.activation_root_state = 'inert_legacy_evidence_or_empty';
  legacyFirstInstallReport.preinstall_status.manifest_present = false;
  legacyFirstInstallReport.preinstall_status.manifest_status = 'not_present';
  legacyFirstInstallReport.preinstall_status.inert_legacy_evidence_preserved = true;
  delete legacyFirstInstallReport.preinstall_status.closed_root_replacement_authorized;
  delete legacyFirstInstallReport.write_boundary.closed_root_replaced_by_explicit_authority;
  assert(
    'legacy first-install report without replacement fields validates',
    assertActivePersistentProfileLiveInstallationReport(legacyFirstInstallReport),
  );
  const ambiguousLegacyReport = structuredClone(legacyFirstInstallReport);
  ambiguousLegacyReport.preinstall_status.manifest_present = true;
  assertThrows(
    'ambiguous legacy report with manifest present refused',
    () => assertActivePersistentProfileLiveInstallationReport(ambiguousLegacyReport),
    'contains unexpected fields',
  );
  assertEqual('report type', PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_LIVE_INSTALLATION_REPORT_TYPE, report.report_type);
  assertEqual('safe claim exact', ACTIVE_PERSISTENT_PROFILE_LIVE_CLAIM, report.safe_claim);
  assertEqual('surrogate root label', '<surrogate-active-persistent-profile-root>', report.activation_root_label);
  assertEqual('named live root false', false, report.named_live_root);
  assertEqual('final root active', 'active_until_expiry', report.final_root_state);
  assertEqual('active after proof true', true, report.active_after_proof);
  assertEqual('closed root replacement false on first install', false, report.preinstall_status.closed_root_replacement_authorized);
  assertEqual('profile id bound', 'protected-records-runtime-fixture-profile', report.selected_profile.profile_id);
  assertEqual('runtime profile id bound', 'protected-records-disposable-runtime-profile', report.selected_profile.runtime_profile_id);
  assertEqual('runtime profile sha bound', ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256, report.selected_profile.runtime_profile_sha256);
  assertEqual('selected by exact id and sha', true, report.selected_profile.selected_by_explicit_id_and_sha);
  assertEqual('latest selector false', false, report.selected_profile.selects_latest_profile);
  assertEqual('installed preflight performed', true, report.readback_preflight.installed_runtime_profile_preflight_performed);
  assertEqual('installed preflight read-only', true, report.readback_preflight.read_only);
  assertEqual('preflight did not install', false, report.readback_preflight.runtime_profile_installation_performed_by_preflight);
  assertEqual('preflight did not activate', false, report.readback_preflight.runtime_profile_activation_performed_by_preflight);
  assertEqual('runtime launcher authority grant requirement true', true, report.runtime_profile_contract.authority_grant_contract_required_from_launcher);
  assertEqual('runtime signed payload replay identity exact', 'verified-signed-payload-sha256', report.runtime_profile_contract.signed_payload_replay_identity);
  assertEqual('readback authority grant requirement preserved', true, report.readback_preflight.authority_grant_requirement_preserved);
  assertEqual('readback exact grant contract deferred', true, report.readback_preflight.exact_runtime_authority_grant_contract_deferred);
  assertEqual('readback rightful issuance false', false, report.readback_preflight.rightful_issuance_proven);
  assertEqual('readback lifecycle closure false', false, report.readback_preflight.consequence_lifecycle_closed);
  assertEqual('readback atomic store anchor witness false', false, report.readback_preflight.atomic_store_anchor_witness_commit);
  assertEqual('readback burn proof false at installation', false, report.readback_preflight.partial_grant_commit_burn_window_proven);
  assertEqual('readback joint rollback detection false', false, report.readback_preflight.store_anchor_and_witness_joint_rollback_detection);
  assertEqual('readback host path TOCTOU closure false', false, report.readback_preflight.host_filesystem_path_toctou_closed);
  assertEqual('activation root written', true, report.write_boundary.activation_root_written);
  assertEqual('runtime service not started', false, report.write_boundary.runtime_service_started);
  assertEqual('outside hooks/config false', false, report.write_boundary.hooks_or_config_written_outside_root);
  assertEqual('real records touched false', false, report.write_boundary.real_records_touched);
  assertEqual('live install claim true', true, report.claim_boundary.active_persistent_runtime_profile_installation);
  assertEqual('persistent active state true', true, report.claim_boundary.persistent_active_state_after_proof);
  assertEqual('fixture rightful path false for installation', false, report.claim_boundary.fixture_rightful_issuance_path_evidenced);
  assertEqual('rightful issuance false for installation', false, report.claim_boundary.rightful_issuance_proven);
  assertEqual('portable rightful issuance false', false, report.claim_boundary.portable_rightful_issuance_proven);
  assertEqual('live authority false', false, report.claim_boundary.live_authority_proven);
  assertEqual('production rightful issuance false', false, report.claim_boundary.production_rightful_issuance_proven);
  assertEqual('consequence lifecycle false', false, report.claim_boundary.consequence_lifecycle_closed);
  assertEqual('current-machine general false', false, report.claim_boundary.current_machine_governance_general);
  assertEqual('production recognition false', false, report.claim_boundary.production_downstream_recognition);
  assertEqual('all-surface governance false', false, report.claim_boundary.all_surface_governance);
  assertEqual('open boundaries preserved', ACTIVE_PERSISTENT_PROFILE_LIVE_OPEN_BOUNDARIES.length, report.open_boundaries.length);
  assertEqual('non-claims preserved', ACTIVE_PERSISTENT_PROFILE_LIVE_NON_CLAIMS.length, report.non_claims.length);
  const reportText = JSON.stringify(report, null, 2);
  assert('report privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(reportText));
  assert('report omits raw local paths and key material', !unsafeOutputPattern.test(reportText));

  section('installed-root readback and status');
  const installedPreflight = runProtectedRecordsInstalledRuntimeProfilePreflight({
    installRoot: activationRoot(scratch),
    expectedProfile: profile,
    profileId: 'protected-records-runtime-fixture-profile',
    profileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
  });
  assertEqual('installed preflight selected exact profile', true, installedPreflight.active_index.selected_by_explicit_id_and_sha);
  assertEqual('installed preflight latest false', false, installedPreflight.active_index.selects_latest_profile);
  assertEqual('installed preflight read-only', true, installedPreflight.read_only);

  const status = inspectActivePersistentProfileLiveStatus({
    activationRoot: activationRoot(scratch),
    nowEpoch: 1700000000,
  });
  assert('status validates', assertActivePersistentProfileLiveStatus(status));
  assertEqual('status active until expiry', 'active_until_expiry', status.activation_root_state);
  assertEqual('status active true', true, status.active);
  assertEqual('status safe for install false', false, status.safe_for_install);
  const statusSummary = formatActivePersistentProfileLiveStatus(status);
  assert('status summary privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(statusSummary));
  assert('status summary omits raw paths', !unsafeOutputPattern.test(statusSummary));

  section('formatting and report write');
  const summary = formatActivePersistentProfileLiveInstallationReport(report);
  assert('summary title present', summary.includes('ZLAR Active Persistent Profile Live Installation Proof v1'));
  assert('summary includes active final state', summary.includes('final_root_state=active_until_expiry'));
  assert('summary includes grant readback boundary', summary.includes('requirement_preserved=true') && summary.includes('rightful_issuance_proven=false'));
  assert('summary includes storage boundaries', summary.includes('atomic_store_anchor_witness_commit=false') && summary.includes('joint_rollback_detection=false'));
  assert('summary includes rightful issuance ceiling', summary.includes('fixture_path_evidenced=false') && summary.includes('consequence_lifecycle_closed=false'));
  assert('summary privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(summary));
  assert('summary omits raw paths', !unsafeOutputPattern.test(summary));
  const reportPath = join(scratch, 'reports', 'active-persistent-live-installation.json');
  const writtenSha = writeActivePersistentProfileLiveReport({
    report,
    outputPath: reportPath,
    activationRoot: activationRoot(scratch),
  });
  assert('report written', existsSync(reportPath));
  assert('report sha present', /^[a-f0-9]{64}$/.test(writtenSha));
  assertThrows('report inside activation root refused', () => writeActivePersistentProfileLiveReport({
    report,
    outputPath: join(activationRoot(scratch), 'report.json'),
    activationRoot: activationRoot(scratch),
  }), 'may not be written inside the activation root');
  const reportAlias = join(scratch, 'activation-report-alias');
  symlinkSync(activationRoot(scratch), reportAlias);
  assertThrows('report through activation-root parent symlink refused', () => writeActivePersistentProfileLiveReport({
    report,
    outputPath: join(reportAlias, 'report.json'),
    activationRoot: activationRoot(scratch),
  }), 'may not be written inside the activation root');

  section('fail-closed install gates');
  assertThrows('second install refuses active root', () => runActivePersistentProfileLiveInstallation(installOptions(scratch, profile)), 'install refused');
  assertThrows('missing expiry fails', () => runActivePersistentProfileLiveInstallation({
    ...installOptions(scratch, profile),
    activationRoot: join(scratch, 'missing-expiry', 'protected-records-private-operator-records-terminal'),
    expiresAt: '',
  }), 'expiry is mandatory');
  assertThrows('expired install fails', () => runActivePersistentProfileLiveInstallation({
    ...installOptions(scratch, profile),
    activationRoot: join(scratch, 'expired', 'protected-records-private-operator-records-terminal'),
    expiresAt: '2020-01-01T00:00:00.000Z',
  }), 'expired');
  assertThrows('wrong sha fails', () => runActivePersistentProfileLiveInstallation({
    ...installOptions(scratch, profile),
    activationRoot: join(scratch, 'wrong-sha', 'protected-records-private-operator-records-terminal'),
    runtimeProfileSha256: '0'.repeat(64),
  }), 'fixed runtime profile binding');
  assertThrows('wrong profile source fails', () => runActivePersistentProfileLiveInstallation({
    ...installOptions(scratch, profile),
    activationRoot: join(scratch, 'wrong-source', 'protected-records-private-operator-records-terminal'),
    profileSource: 'profiles/latest.profile.json',
  }), 'fixed runtime profile binding');
  assertThrows('wrong activation root basename fails', () => runActivePersistentProfileLiveInstallation({
    ...installOptions(scratch, profile),
    activationRoot: join(scratch, 'activation', 'wrong-profile'),
  }), 'named deployment profile id');
  assertThrows('named live root requires explicit flag before touch', () => inspectActivePersistentProfileLiveStatus({
    activationRoot: defaultActivePersistentProfileLiveRoot(),
    nowEpoch: 1700000000,
  }), 'requires explicit --allow-named-live-root');

  const fakeDeployments = join(scratch, 'fake-home', '.zlar', 'protected-records', 'deployments');
  const fakeLiveRoot = join(fakeDeployments, 'protected-records-private-operator-records-terminal');
  const fakeAliasParent = join(scratch, 'fake-deployments-alias');
  const fakeAliasActivation = join(fakeAliasParent, 'protected-records-private-operator-records-terminal');
  mkdirSync(fakeLiveRoot, { recursive: true });
  symlinkSync(fakeDeployments, fakeAliasParent);
  assertThrows('parent symlink alias to named live root requires explicit flag', () => inspectActivePersistentProfileLiveStatus({
    activationRoot: fakeAliasActivation,
    nowEpoch: 1700000000,
    expectedLiveRoot: fakeLiveRoot,
  }), 'requires explicit --allow-named-live-root');
  const aliasStatus = inspectActivePersistentProfileLiveStatus({
    activationRoot: fakeAliasActivation,
    nowEpoch: 1700000000,
    allowNamedLiveRoot: true,
    expectedLiveRoot: fakeLiveRoot,
  });
  assertEqual('parent symlink alias reports named live root', true, aliasStatus.named_live_root);
  const aliasReport = runActivePersistentProfileLiveInstallation({
    ...installOptions(scratch, profile),
    activationRoot: fakeAliasActivation,
    allowNamedLiveRoot: true,
    expectedLiveRoot: fakeLiveRoot,
  });
  assertEqual('parent symlink alias install reports named live root', true, aliasReport.named_live_root);
  assertEqual('parent symlink alias install active', true, aliasReport.active_after_proof);

  const symlinkTarget = join(scratch, 'symlink-target');
  mkdirSync(symlinkTarget, { recursive: true });
  const symlinkActivation = join(scratch, 'symlink', 'protected-records-private-operator-records-terminal');
  mkdirSync(join(scratch, 'symlink'), { recursive: true });
  symlinkSync(symlinkTarget, symlinkActivation);
  assertThrows('symlink activation root refuses', () => runActivePersistentProfileLiveInstallation({
    ...installOptions(scratch, profile),
    activationRoot: symlinkActivation,
  }), 'symlink refused');

  section('closeout');
  const closeout = closeActivePersistentProfileLiveInstallation({
    activationRoot: activationRoot(scratch),
    closedAt: '2030-01-01T00:10:00.000Z',
    reason: 'operator_closeout',
    nowEpoch: 1700000000,
  });
  assert('closeout validates', assertActivePersistentProfileLiveCloseout(closeout));
  assertEqual('closeout status', 'closed_inert_evidence', closeout.status);
  assertEqual('closeout active false', false, closeout.active);
  assertEqual('closeout reactivation false', false, closeout.closeout_reactivation_allowed);
  const closeoutStatus = inspectActivePersistentProfileLiveStatus({
    activationRoot: activationRoot(scratch),
    nowEpoch: 1700000000,
  });
  assertEqual('status after closeout is inert', 'closed_inert_evidence', closeoutStatus.activation_root_state);
  assertEqual('status after closeout active false', false, closeoutStatus.active);
  assertEqual('status after closeout safe for install false', false, closeoutStatus.safe_for_install);
  const closeoutSummary = formatActivePersistentProfileLiveCloseout(closeout);
  assert('closeout summary privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(closeoutSummary));
  assert('closeout summary omits raw paths', !unsafeOutputPattern.test(closeoutSummary));
  assertThrows('closed root does not silently reinstall', () => runActivePersistentProfileLiveInstallation({
    ...installOptions(scratch, profile),
  }), 'install refused');
  const replacementReport = runActivePersistentProfileLiveInstallation({
    ...installOptions(scratch, profile),
    nowEpoch: 1700000100,
    expiresAt: '2030-01-01T01:00:00.000Z',
    replaceClosedRoot: true,
  });
  assert('closed root replacement report validates', assertActivePersistentProfileLiveInstallationReport(replacementReport));
  assertEqual('closed root replacement authorized', true, replacementReport.preinstall_status.closed_root_replacement_authorized);
  assertEqual('closed root replacement write boundary', true, replacementReport.write_boundary.closed_root_replaced_by_explicit_authority);
  assertEqual('closed root replacement previous state', 'closed_inert_evidence', replacementReport.preinstall_status.activation_root_state);
  assertEqual('closed root replacement active again', true, replacementReport.active_after_proof);

  section('claim drift guards');
  const widenedReport = structuredClone(report);
  widenedReport.claim_boundary.current_machine_governance_general = true;
  assertThrows('current-machine overclaim fails', () => assertActivePersistentProfileLiveInstallationReport(widenedReport), 'claim current_machine_governance_general');
  const rightfulOverclaimReport = structuredClone(report);
  rightfulOverclaimReport.claim_boundary.rightful_issuance_proven = true;
  assertThrows('rightful issuance overclaim fails', () => assertActivePersistentProfileLiveInstallationReport(rightfulOverclaimReport), 'claim rightful_issuance_proven');
  const latestReport = structuredClone(report);
  latestReport.selected_profile.selects_latest_profile = true;
  assertThrows('latest selection overclaim fails', () => assertActivePersistentProfileLiveInstallationReport(latestReport), 'selected profile drifted');
  const missingBoundaryReport = structuredClone(report);
  missingBoundaryReport.open_boundaries = missingBoundaryReport.open_boundaries.slice(1);
  assertThrows('missing open boundary fails', () => assertActivePersistentProfileLiveInstallationReport(missingBoundaryReport), 'open boundaries drifted');
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(`\nResults: ${PASS}/${TOTAL} passed${FAIL ? `, ${FAIL} failed` : ''}`);
if (FAIL) {
  process.exit(1);
}
console.log('ALL PASS');
