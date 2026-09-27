#!/usr/bin/env node

import {
  existsSync,
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
  ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
  ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
} from '../lib/protected-records-active-persistent-profile-preflight.mjs';
import {
  runActivePersistentProfileLiveInstallation,
} from '../lib/protected-records-active-persistent-profile-live-installation.mjs';
import {
  ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_SAFE_CLAIM,
  assertProtectedRecordsActivePersistentProfileActionCrossing,
  formatProtectedRecordsActivePersistentProfileActionCrossing,
  runProtectedRecordsActivePersistentProfileActionCrossing,
  writeProtectedRecordsActivePersistentProfileActionCrossingReport,
} from '../lib/protected-records-active-persistent-profile-action-crossing.mjs';
import {
  PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID,
} from '../lib/protected-records-named-deployment-profile-real-boundary.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH,
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
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
    console.error(`  FAIL: ${label}${detail ? ` (${detail})` : ''}`);
  }
}

function assertEqual(label, expected, actual) {
  assert(label, Object.is(expected, actual), `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

function assertThrows(label, fn, pattern) {
  let threw = false;
  try {
    fn();
  } catch (err) {
    threw = true;
    assert(label, String(err.message).includes(pattern), err.message);
  }
  if (!threw) assert(label, false, 'expected throw');
}

const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY|~\/\.zlar/i;

function readProfile() {
  return JSON.parse(readFileSync(ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE, 'utf8'));
}

function iso(epoch) {
  return new Date(epoch * 1000).toISOString();
}

function installActiveRoot(root, profile, nowEpoch = 1700000000, expiresAt = iso(1700003600)) {
  return runActivePersistentProfileLiveInstallation({
    activationRoot: root,
    profile,
    profileSource: ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
    runtimeProfileId: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    runtimeProfileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    expiresAt,
    nowEpoch,
    allowNamedLiveRoot: true,
    expectedLiveRoot: root,
  });
}

const scratch = mkdtempSync(join(tmpdir(), 'zlar-active-action-crossing-'));
try {
  const profile = readProfile();
  const root = join(scratch, 'activation', PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID);
  const testNowEpoch = Math.floor(Date.now() / 1000);
  const installEpoch = testNowEpoch - 60;
  const expiredEpoch = testNowEpoch + 7200;
  mkdirSync(root, { recursive: true });
  installActiveRoot(root, profile, installEpoch, iso(testNowEpoch + 3600));

  console.log('\n-- active persistent action crossing success --');
  const proofTarget = join(scratch, 'proof-target', 'records-write.jsonl');
  const report = runProtectedRecordsActivePersistentProfileActionCrossing({
    activationRoot: root,
    expectedProfile: profile,
    profileId: 'protected-records-runtime-fixture-profile',
    profileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    proofTarget,
    nowEpoch: testNowEpoch,
    allowNamedLiveRoot: true,
    expectedLiveRoot: root,
  });
  assert('report validates', assertProtectedRecordsActivePersistentProfileActionCrossing(report));
  assertEqual('safe claim exact', ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_SAFE_CLAIM, report.safe_claim_ceiling);
  assertEqual('active root read at action time', true, report.claim_boundary.active_root_read_at_action_time);
  assertEqual('recognized records write boarded', true, report.claim_boundary.recognized_records_write_boarded);
  assertEqual('recognized state append count', 1, report.service_crossing.recognized_write_state_append_count);
  assertEqual('fresh service artifact expected SHA supplied', true, report.service_crossing.artifact_identity_expected_sha256_supplied);
  assertEqual('fresh service artifact identity matched', true, report.service_crossing.artifact_identity_sha256_matched);
  assertEqual('fresh service artifact expected SHA matches body', report.hashes.service_artifact_body_sha256, report.service_crossing.expected_artifact_body_sha256);
  assertEqual('source preflight identity bound through fresh artifact pin', true, report.service_crossing.source_preflight_identity_bound_to_expected_artifact_sha256);
  assertEqual('signed receipt envelope identity bound through fresh artifact pin', true, report.service_crossing.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256);
  assertEqual('recognition refusals before mutation', true, report.claim_boundary.recognition_refusals_before_mutation);
  assertEqual('authority refusals before consumption and mutation', true, report.claim_boundary.authority_grant_refusals_before_consumption_and_mutation);
  assertEqual('latest false', false, report.action_crossing.selects_latest_profile);
  assertEqual('request authority grant false', false, report.action_crossing.authority_grant_supplied_by_agent);
  assertEqual('recognition rule false', false, report.action_crossing.recognition_rule_supplied_by_agent);
  assertEqual('action status epoch uses action time', testNowEpoch, report.evaluation_time_contract.active_root_status_epoch);
  assertEqual('service authority evaluation uses fixture epoch', PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH, report.evaluation_time_contract.local_service_authority_evaluation_epoch);
  assertEqual('service fixture epoch explicitly not live authority time', true, report.evaluation_time_contract.fixture_epoch_is_not_live_authority_time);
  assertEqual('fixture rightful path evidenced', true, report.claim_boundary.fixture_authority_grant_path_evidenced);
  assertEqual('generic rightful issuance false', false, report.claim_boundary.rightful_issuance_proven);
  assertEqual('lifecycle closure false', false, report.claim_boundary.consequence_lifecycle_closed);
  assertEqual('current-machine general false', false, report.claim_boundary.current_machine_governance_general);
  assertEqual('production recognition false', false, report.claim_boundary.production_downstream_recognition);
  assertEqual('proof target marker exists', true, existsSync(proofTarget));
  assertEqual('proof target one entry', 1, readFileSync(proofTarget, 'utf8').trim().split('\n').length);
  assertEqual('proof target recognized delta', 1, report.proof_target.recognized_entry_delta);
  assertEqual('proof target refusal delta', 0, report.proof_target.refusal_entry_delta_total);
  const summary = formatProtectedRecordsActivePersistentProfileActionCrossing(report);
  assert('summary privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(summary));
  assert('summary omits raw paths', !unsafeOutputPattern.test(summary));

  console.log('\n-- report write and safety --');
  const reportPath = join(scratch, 'reports', 'crossing.json');
  const writtenSha = writeProtectedRecordsActivePersistentProfileActionCrossingReport({
    report,
    outputPath: reportPath,
    activationRoot: root,
  });
  assert('report written', /^[a-f0-9]{64}$/.test(writtenSha) && existsSync(reportPath));
  assert('report privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(readFileSync(reportPath, 'utf8')));
  assertThrows('report inside activation root refused', () => writeProtectedRecordsActivePersistentProfileActionCrossingReport({
    report,
    outputPath: join(root, 'bad-report.json'),
    activationRoot: root,
  }), 'may not be written inside the activation root');

  console.log('\n-- fail closed cases --');
  assertThrows('expired root refuses before target write', () => runProtectedRecordsActivePersistentProfileActionCrossing({
    activationRoot: root,
    expectedProfile: profile,
    profileId: 'protected-records-runtime-fixture-profile',
    profileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    proofTarget: join(scratch, 'expired-target.jsonl'),
    nowEpoch: expiredEpoch,
    allowNamedLiveRoot: true,
    expectedLiveRoot: root,
  }), 'requires an active unexpired explicit root');
  assertEqual('expired target absent', false, existsSync(join(scratch, 'expired-target.jsonl')));
  assertThrows('missing named-root authority refuses', () => runProtectedRecordsActivePersistentProfileActionCrossing({
    activationRoot: root,
    expectedProfile: profile,
    profileId: 'protected-records-runtime-fixture-profile',
    profileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    proofTarget: join(scratch, 'missing-authority-target.jsonl'),
    nowEpoch: testNowEpoch,
    expectedLiveRoot: root,
  }), 'requires explicit --allow-named-live-root');
  assertEqual('missing authority target absent', false, existsSync(join(scratch, 'missing-authority-target.jsonl')));
  const existingTarget = join(scratch, 'existing-target.jsonl');
  mkdirSync(join(scratch, 'existing-dir'), { recursive: true });
  writeFileSync(existingTarget, '{"already":true}\n');
  assertThrows('pre-existing target refuses', () => runProtectedRecordsActivePersistentProfileActionCrossing({
    activationRoot: root,
    expectedProfile: profile,
    profileId: 'protected-records-runtime-fixture-profile',
    profileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    proofTarget: existingTarget,
    nowEpoch: testNowEpoch,
    allowNamedLiveRoot: true,
    expectedLiveRoot: root,
  }), 'proof target must be absent before proof');
  const danglingTarget = join(scratch, 'dangling-target.jsonl');
  symlinkSync(join(scratch, 'missing-target-destination.jsonl'), danglingTarget);
  assertThrows('dangling symlink target refuses', () => runProtectedRecordsActivePersistentProfileActionCrossing({
    activationRoot: root,
    expectedProfile: profile,
    profileId: 'protected-records-runtime-fixture-profile',
    profileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    proofTarget: danglingTarget,
    nowEpoch: testNowEpoch,
    allowNamedLiveRoot: true,
    expectedLiveRoot: root,
  }), 'proof target must be absent before proof');
  assertThrows('proof target inside activation root refused', () => runProtectedRecordsActivePersistentProfileActionCrossing({
    activationRoot: root,
    expectedProfile: profile,
    profileId: 'protected-records-runtime-fixture-profile',
    profileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    proofTarget: join(root, 'target.jsonl'),
    nowEpoch: testNowEpoch,
    allowNamedLiveRoot: true,
    expectedLiveRoot: root,
  }), 'may not be written inside the activation root');

  console.log('\n-- claim drift guards --');
  const widened = structuredClone(report);
  widened.claim_boundary.current_machine_governance_general = true;
  assertThrows('current-machine overclaim fails', () => assertProtectedRecordsActivePersistentProfileActionCrossing(widened), 'overclaimed current_machine_governance_general');
  const latest = structuredClone(report);
  latest.action_crossing.selects_latest_profile = true;
  assertThrows('latest selection drift fails', () => assertProtectedRecordsActivePersistentProfileActionCrossing(latest), 'action boundary drifted');
  const liveTimeLaundering = structuredClone(report);
  liveTimeLaundering.evaluation_time_contract.local_service_authority_evaluation_epoch = testNowEpoch;
  assertThrows('action time cannot launder fixture authority time', () => assertProtectedRecordsActivePersistentProfileActionCrossing(liveTimeLaundering), 'evaluation time boundary drifted');
  const detachedStructuralPosture = structuredClone(report);
  detachedStructuralPosture.service_crossing.artifact_identity_expected_sha256_supplied = false;
  detachedStructuralPosture.service_crossing.expected_artifact_body_sha256 = null;
  detachedStructuralPosture.service_crossing.artifact_identity_sha256_matched = false;
  detachedStructuralPosture.service_crossing.source_preflight_identity_bound_to_expected_artifact_sha256 = false;
  detachedStructuralPosture.service_crossing.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256 = false;
  detachedStructuralPosture.service_crossing.verification_scope = 'structural-self-integrity-only';
  detachedStructuralPosture.service_crossing.recognized_write_boarded = false;
  detachedStructuralPosture.service_crossing.recognized_write_state_append_count = 0;
  detachedStructuralPosture.service_crossing.fixture_rightful_issuance_path_evidenced = false;
  assertThrows('detached structural verification cannot preserve positive action crossing', () => assertProtectedRecordsActivePersistentProfileActionCrossing(detachedStructuralPosture), 'service proof drifted');
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(`\nResults: ${PASS}/${TOTAL} passed${FAIL ? `, ${FAIL} failed` : ''}`);
if (FAIL) process.exit(1);
console.log('ALL PASS');
