#!/usr/bin/env node

import {
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
  ACTIVE_PERSISTENT_PROFILE_FORBIDDEN_CLAIMS,
  ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
  ACTIVE_PERSISTENT_PROFILE_SOURCE_PREFLIGHT_CLAIM,
  PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_CLOSEOUT_TYPE,
  PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_SOURCE_PREFLIGHT_TYPE,
  REQUIRED_ACTIVE_PERSISTENT_PROFILE_REFUSAL_CASES,
  assertActivePersistentProfileCloseout,
  assertActivePersistentProfileSourceManifest,
  assertActivePersistentProfileSourcePreflight,
  assertActivePersistentProfileSourceStatus,
  buildActivePersistentProfileCloseout,
  buildActivePersistentProfileSourceManifest,
  formatActivePersistentProfileCloseout,
  formatActivePersistentProfileSourcePreflight,
  formatActivePersistentProfileSourceStatus,
  inspectActivePersistentProfileSourceStatus,
  runActivePersistentProfileSourcePreflight,
  writeActivePersistentProfileCloseout,
  writeActivePersistentProfileSourcePreflightReport,
} from '../lib/protected-records-active-persistent-profile-preflight.mjs';
import {
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from '../lib/protected-records-runtime-profile.mjs';
import {
  runtimeProfileSha256,
} from '../lib/protected-records-runtime-profile-preflight.mjs';

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

function baseOptions(scratch, profile) {
  return {
    surrogateRoot: scratch,
    activationRoot: join(scratch, 'activation', 'protected-records-private-operator-records-terminal'),
    proofTarget: join(scratch, 'proof', 'records-target.jsonl'),
    profile,
    profileSource: ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
    runtimeProfileId: 'protected-records-disposable-runtime-profile',
    runtimeProfileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    expiresAt: '2030-01-01T00:00:00.000Z',
    nowEpoch: 1700000000,
  };
}

const PROFILE_PATH = 'profiles/protected-records-runtime-fixture.profile.json';
const profile = JSON.parse(readFileSync(PROFILE_PATH, 'utf8'));
const profileSha = runtimeProfileSha256(profile);
const scratch = mkdtempSync(join(tmpdir(), 'zlar-active-persistent-source-preflight-test-'));
const realActivationRoot = join(
  homedir(),
  '.zlar',
  'protected-records',
  'deployments',
  'protected-records-private-operator-records-terminal'
);
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY|~\/\.zlar/i;

try {
  const options = baseOptions(scratch, profile);
  mkdirSync(options.activationRoot, { recursive: true });
  mkdirSync(join(scratch, 'proof'), { recursive: true });
  writeFileSync(options.proofTarget, '');

  section('fixed profile binding');
  assertEqual('canonical profile sha', ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256, profileSha);

  section('source preflight report');
  const report = runActivePersistentProfileSourcePreflight(options);
  assert('report validates', assertActivePersistentProfileSourcePreflight(report));
  assertEqual('report type', PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_SOURCE_PREFLIGHT_TYPE, report.report_type);
  assertEqual('source claim exact', ACTIVE_PERSISTENT_PROFILE_SOURCE_PREFLIGHT_CLAIM, report.claim);
  assertEqual('source only true', true, report.source_only);
  assertEqual('live probing false', false, report.live_probing);
  assertEqual('activation unauthorized', false, report.authority_boundary.activation_authorized);
  assertEqual('install unauthorized', false, report.authority_boundary.install_authorized);
  assertEqual('real activation untouched', false, report.authority_boundary.real_activation_root_touched);
  assertEqual('runtime profile id bound', 'protected-records-disposable-runtime-profile', report.profile_binding.runtime_profile_id);
  assertEqual('runtime profile sha bound', ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256, report.profile_binding.runtime_profile_sha256);
  assertEqual('canonical source bound', ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE, report.profile_binding.canonical_runtime_profile_source);
  assertEqual('no moving selector', false, report.profile_binding.moving_selector_accepted);
  assertEqual('no latest selection', false, report.profile_binding.selects_latest_profile);
  assertEqual(
    'runtime mutation route preserves recognition then authority grant',
    'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation',
    report.runtime_profile_contract.mutation_authoritative_route,
  );
  assertEqual(
    'runtime consumption identity is authority grant contract sha',
    'authority-grant-contract-sha256',
    report.runtime_profile_contract.consumption_identity,
  );
  assertEqual(
    'runtime signed payload replay identity is separate',
    'verified-signed-payload-sha256',
    report.runtime_profile_contract.signed_payload_replay_identity,
  );
  for (const key of [
    'authority_grant_contract_required_from_launcher',
    'authority_grant_appointment_required_from_launcher',
    'authority_grant_issuance_decision_required_from_launcher',
    'authorized_record_update_required_from_launcher',
    'same_process_signed_payload_replay_case_required',
    'restart_consumed_authority_grant_refusal_case_required',
    'missing_authority_grant_appointment_refusal_case_required',
    'mismatched_authority_grant_appointment_refusal_case_required',
    'revoked_authority_grant_refusal_case_required',
    'expired_authority_grant_refusal_case_required',
    'request_supplied_authority_grant_refusal_case_required',
    'persistent_consumed_authority_grant_store',
    'store_and_anchor_joint_rollback_refused_while_witness_ahead',
    'partial_grant_commit_burn_window_named',
    'partial_commit_witness_missing_observed',
  ]) {
    assertEqual(`runtime contract true: ${key}`, true, report.runtime_profile_contract[key]);
  }
  for (const key of [
    'request_stream_authority_material_accepted',
    'store_anchor_and_witness_joint_rollback_detection',
    'atomic_store_anchor_witness_commit',
    'host_filesystem_path_toctou_closed',
    'exactly_once_effect_semantics',
  ]) {
    assertEqual(`runtime contract false: ${key}`, false, report.runtime_profile_contract[key]);
  }
  assertEqual('expiry required', true, report.expiry.expiry_required);
  assertEqual('expired profile refused', true, report.expiry.expired_profile_refused);
  assertEqual('activation contained', true, report.path_boundary.activation_root_realpath_contained);
  assertEqual('proof target contained', true, report.path_boundary.proof_target_realpath_contained);
  assertEqual('activation root name matches profile', true, report.path_boundary.activation_root_name_matches_profile_id);
  assert('activation label is surrogate-contained', report.path_boundary.activation_root_label.startsWith('<source-preflight-surrogate-root>/'));
  assert('proof target label is surrogate-contained', report.path_boundary.proof_target_label.startsWith('<source-preflight-surrogate-root>/'));
  assertEqual('symlink escape refused', true, report.path_boundary.symlink_escape_refused);
  assertEqual('hardlink refused where practical', true, report.path_boundary.hardlink_escape_refused_where_practical);
  assertEqual('alias risk documented', true, report.path_boundary.alias_risk_documented);
  assertEqual('real root default false', false, report.path_boundary.real_activation_root_default_used);
  assertEqual('silent overwrite false', false, report.existing_root_policy.silent_overwrite_allowed);
  assertEqual('replace mode unsupported', false, report.existing_root_policy.replace_mode_supported_by_source_preflight);
  assertEqual('refusal matrix count', REQUIRED_ACTIVE_PERSISTENT_PROFILE_REFUSAL_CASES.length, report.refusal_matrix.length);
  for (const caseId of REQUIRED_ACTIVE_PERSISTENT_PROFILE_REFUSAL_CASES) {
    const item = report.refusal_matrix.find((candidate) => candidate.case_id === caseId);
    assert(`refusal matrix includes ${caseId}`, Boolean(item));
    assertEqual(`${caseId} refused before mutation`, true, item.refused_before_target_mutation);
    assertEqual(`${caseId} target mutation false`, false, item.target_mutation_allowed);
  }
  assertEqual('closeout required', true, report.closeout_contract.rollback_or_closeout_required);
  assertEqual('closeout reactivation false', false, report.closeout_contract.closeout_reactivation_allowed);
  assertEqual('crash contract testable', true, report.crash_interruption_contract.testable_in_source_preflight);
  assertEqual('activation root write false', false, report.write_boundary.activation_root_write_allowed);
  assertEqual('proof target write false', false, report.write_boundary.proof_target_write_allowed);
  assertEqual('runtime service start false', false, report.write_boundary.runtime_service_start_allowed);
  assertEqual('auto activation false', false, report.write_boundary.auto_activation_allowed);
  assertEqual('private key absent', true, report.privacy_hygiene.private_key_material_absent);
  assertEqual('real personal files false', false, report.privacy_hygiene.real_personal_files_used);
  for (const claim of ACTIVE_PERSISTENT_PROFILE_FORBIDDEN_CLAIMS) {
    assert(`forbidden claim preserved: ${claim}`, report.forbidden_claims.includes(claim));
  }
  for (const [key, value] of Object.entries(report.claim_boundary)) {
    assertEqual(`claim boundary false: ${key}`, false, value);
  }
  assertEqual('fixture rightful path not evidenced by source preflight', false, report.claim_boundary.fixture_rightful_issuance_path_evidenced);
  assertEqual('rightful issuance not proven by source preflight', false, report.claim_boundary.rightful_issuance_proven);
  assertEqual('live authority not proven by source preflight', false, report.claim_boundary.live_authority_proven);
  assertEqual('consequence lifecycle not closed by source preflight', false, report.claim_boundary.consequence_lifecycle_closed);
  const reportText = JSON.stringify(report, null, 2);
  assert('report text privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(reportText));
  assert('report omits raw paths and key material', !unsafeOutputPattern.test(reportText));

  section('formatting and report write');
  const summary = formatActivePersistentProfileSourcePreflight(report);
  assert('summary title present', summary.includes('ZLAR Active Persistent Profile Source Preflight v1'));
  assert('summary includes exact claim', summary.includes(ACTIVE_PERSISTENT_PROFILE_SOURCE_PREFLIGHT_CLAIM));
  assert('summary includes no latest selector', summary.includes('selects_latest=false'));
  assert('summary includes authority grant runtime contract', summary.includes('consumption_identity=authority-grant-contract-sha256'));
  assert('summary includes signed payload replay split', summary.includes('signed_payload_replay_identity=verified-signed-payload-sha256'));
  assert('summary includes burn and joint rollback boundaries', summary.includes('burn_window_named=true') && summary.includes('joint_rollback_detection=false'));
  assert('summary includes rightful issuance claim ceiling', summary.includes('fixture_path_evidenced=false') && summary.includes('rightful_issuance_proven=false') && summary.includes('consequence_lifecycle_closed=false'));
  assert('summary includes write boundary', summary.includes('activation_root_write_allowed=false'));
  assert('summary privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(summary));
  assert('summary omits raw paths and key material', !unsafeOutputPattern.test(summary));
  const writtenSha = writeActivePersistentProfileSourcePreflightReport(report, join(scratch, 'reports', 'source-preflight.json'));
  assert('written report sha present', /^[a-f0-9]{64}$/.test(writtenSha));
  const realRootAlias = join(scratch, 'real-root-alias');
  symlinkSync(realActivationRoot, realRootAlias);
  assertThrows('report output under real activation root fails', () => writeActivePersistentProfileSourcePreflightReport(
    report,
    join(realActivationRoot, 'source-preflight.json')
  ), 'real active persistent profile activation root');
  assertThrows('report output through real-root symlink route fails', () => writeActivePersistentProfileSourcePreflightReport(
    report,
    join(realRootAlias, 'source-preflight.json')
  ), 'symlink route refused');

  section('status and closeout');
  const emptyStatus = inspectActivePersistentProfileSourceStatus({
    surrogateRoot: scratch,
    activationRoot: options.activationRoot,
    nowEpoch: options.nowEpoch,
  });
  assert('empty status validates', assertActivePersistentProfileSourceStatus(emptyStatus));
  assertEqual('empty status safe', true, emptyStatus.safe_for_source_preflight);
  assertEqual('empty status read-only', true, emptyStatus.read_only);
  const statusSummary = formatActivePersistentProfileSourceStatus(emptyStatus);
  assert('status summary privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(statusSummary));

  const manifest = buildActivePersistentProfileSourceManifest(report);
  assert('manifest validates', assertActivePersistentProfileSourceManifest(manifest));
  assertEqual('manifest active false', false, manifest.active);
  assertEqual('manifest activation allowed false', false, manifest.activation_allowed);
  const closeout = buildActivePersistentProfileCloseout(manifest, {
    closedAt: '2030-01-01T00:10:00.000Z',
    reason: 'operator_closeout',
  });
  assert('closeout validates', assertActivePersistentProfileCloseout(closeout));
  assertEqual('closeout type', PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_CLOSEOUT_TYPE, closeout.closeout_type);
  assertEqual('closeout status', 'closed_inert_evidence', closeout.status);
  assertEqual('closeout active false', false, closeout.active);
  assertEqual('closeout reactivation false', false, closeout.closeout_reactivation_allowed);
  const closeoutSummary = formatActivePersistentProfileCloseout(closeout);
  assert('closeout summary privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(closeoutSummary));
  assertThrows('closeout output under real activation root fails', () => writeActivePersistentProfileCloseout(
    closeout,
    join(realActivationRoot, 'closeout.json')
  ), 'real active persistent profile activation root');
  assertThrows('closeout output through real-root symlink route fails', () => writeActivePersistentProfileCloseout(
    closeout,
    join(realRootAlias, 'closeout.json')
  ), 'symlink route refused');

  section('fail closed source gates');
  assertThrows('missing expiry fails', () => runActivePersistentProfileSourcePreflight({
    ...options,
    expiresAt: '',
  }), 'expiry is mandatory');
  assertThrows('expired profile fails', () => runActivePersistentProfileSourcePreflight({
    ...options,
    expiresAt: '2020-01-01T00:00:00.000Z',
  }), 'expired');
  assertThrows('wrong runtime profile sha fails', () => runActivePersistentProfileSourcePreflight({
    ...options,
    runtimeProfileSha256: '0'.repeat(64),
  }), 'fixed runtime profile binding');
  assertThrows('wrong profile source fails', () => runActivePersistentProfileSourcePreflight({
    ...options,
    profileSource: 'profiles/latest.profile.json',
  }), 'fixed runtime profile binding');
  assertThrows('wrong activation root basename fails', () => runActivePersistentProfileSourcePreflight({
    ...options,
    activationRoot: join(scratch, 'activation', 'wrong-profile'),
  }), 'named deployment profile id');

  const outsideRoot = mkdtempSync(join(tmpdir(), 'zlar-active-persistent-outside-'));
  try {
    const outsideActivation = join(outsideRoot, 'activation', 'protected-records-private-operator-records-terminal');
    mkdirSync(outsideActivation, { recursive: true });
    assertThrows('activation root outside surrogate fails', () => runActivePersistentProfileSourcePreflight({
      ...options,
      activationRoot: outsideActivation,
    }), 'realpath containment refused');

    const outsideTarget = join(outsideRoot, 'records-target.jsonl');
    writeFileSync(outsideTarget, '');
    assertThrows('proof target outside surrogate fails', () => runActivePersistentProfileSourcePreflight({
      ...options,
      proofTarget: outsideTarget,
    }), 'realpath containment refused');

    const symlinkActivation = join(scratch, 'symlink-activation');
    symlinkSync(options.activationRoot, symlinkActivation);
    assertThrows('symlink activation root fails', () => runActivePersistentProfileSourcePreflight({
      ...options,
      activationRoot: symlinkActivation,
    }), 'symlink escape refused');

    const symlinkTarget = join(scratch, 'proof', 'symlink-target.jsonl');
    symlinkSync(outsideTarget, symlinkTarget);
    assertThrows('symlink proof target fails', () => runActivePersistentProfileSourcePreflight({
      ...options,
      proofTarget: symlinkTarget,
    }), 'symlink escape refused');

    const hardlinkTarget = join(scratch, 'proof', 'hardlink-target.jsonl');
    linkSync(outsideTarget, hardlinkTarget);
    assertThrows('hardlink proof target fails', () => runActivePersistentProfileSourcePreflight({
      ...options,
      proofTarget: hardlinkTarget,
    }), 'hardlink or alias risk refused');
  } finally {
    rmSync(outsideRoot, { recursive: true, force: true });
  }

  const activeRoot = join(scratch, 'existing-active-root', 'protected-records-private-operator-records-terminal');
  mkdirSync(activeRoot, { recursive: true });
  writeFileSync(join(activeRoot, 'active-persistent-profile-manifest.json'), `${JSON.stringify({
    manifest_type: 'zlar-protected-records-active-persistent-profile-manifest-v1',
    status: 'active',
    expires_at: '2030-01-01T00:00:00.000Z',
  }, null, 2)}\n`);
  const activeStatus = inspectActivePersistentProfileSourceStatus({
    surrogateRoot: scratch,
    activationRoot: activeRoot,
    nowEpoch: options.nowEpoch,
  });
  assertEqual('active status unsafe for source preflight', false, activeStatus.safe_for_source_preflight);
  assertEqual('active status existing root refused', true, activeStatus.existing_active_root_refused);
  assertThrows('existing active root fails preflight', () => runActivePersistentProfileSourcePreflight({
    ...options,
    activationRoot: activeRoot,
  }), 'existing activation root requires explicit closeout or replace authority');

  const driftedReport = structuredClone(report);
  driftedReport.write_boundary.activation_root_write_allowed = true;
  assertThrows('activation write claim fails', () => assertActivePersistentProfileSourcePreflight(driftedReport), 'write boundary');

  const latestReport = structuredClone(report);
  latestReport.profile_binding.selects_latest_profile = true;
  assertThrows('latest claim fails', () => assertActivePersistentProfileSourcePreflight(latestReport), 'profile binding drifted');

  const missingGrantRequirementReport = structuredClone(report);
  missingGrantRequirementReport.runtime_profile_contract.authority_grant_contract_required_from_launcher = false;
  assertThrows('authority grant requirement drift fails', () => assertActivePersistentProfileSourcePreflight(missingGrantRequirementReport), 'authority_grant_contract_required_from_launcher');

  const rightfulOverclaimReport = structuredClone(report);
  rightfulOverclaimReport.claim_boundary.rightful_issuance_proven = true;
  assertThrows('rightful issuance overclaim fails', () => assertActivePersistentProfileSourcePreflight(rightfulOverclaimReport), 'rightful_issuance_proven');

  const missingCaseReport = structuredClone(report);
  missingCaseReport.refusal_matrix = missingCaseReport.refusal_matrix.slice(1);
  assertThrows('missing refusal case fails', () => assertActivePersistentProfileSourcePreflight(missingCaseReport), 'refusal matrix drifted');

  const reactivationCloseout = structuredClone(closeout);
  reactivationCloseout.closeout_reactivation_allowed = true;
  assertThrows('closeout reactivation claim fails', () => assertActivePersistentProfileCloseout(reactivationCloseout), 'closeout drifted');
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(`\nResults: ${PASS}/${TOTAL} passed${FAIL ? `, ${FAIL} failed` : ''}`);
if (FAIL) {
  process.exit(1);
}
console.log('ALL PASS');
