#!/usr/bin/env node

import {
  createHash,
} from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
  ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
} from '../lib/protected-records-active-persistent-profile-preflight.mjs';
import {
  closeActivePersistentProfileLiveInstallation,
  inspectActivePersistentProfileLiveStatus,
  runActivePersistentProfileLiveInstallation,
} from '../lib/protected-records-active-persistent-profile-live-installation.mjs';
import {
  runProtectedRecordsActivePersistentProfileActionCrossing,
} from '../lib/protected-records-active-persistent-profile-action-crossing.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH,
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

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function fileSha256(path) {
  return createHash('sha256').update(readFileSync(path, 'utf8')).digest('hex');
}

const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY|~\/\.zlar/i;
const profile = JSON.parse(readFileSync(ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE, 'utf8'));
const scratch = mkdtempSync(join(tmpdir(), 'zlar-active-lifecycle-cli-test-'));
const fakeSha = 'b'.repeat(64);

function iso(epoch) {
  return new Date(epoch * 1000).toISOString();
}

function makeRedReport({ greenReport, expiresAt, generatedAt }) {
  const actionEpoch = Math.floor(Date.parse(generatedAt) / 1000);
  return {
    proof_report_type: 'zlar-active-persistent-profile-red-path-refusal-proof-report-v1',
    generated_at: generatedAt,
    evaluation_time_contract: {
      active_root_status_epoch: actionEpoch,
      active_root_status_uses_action_time_epoch: true,
      local_service_authority_evaluation_epoch:
        PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH,
      local_service_authority_uses_fixture_epoch: true,
      time_domains_intentionally_separate: true,
      fixture_epoch_is_not_live_authority_time: true,
    },
    authority_packet: { packet_sha256: fakeSha },
    scratch_dir: '<private-red-scratch>',
    active_root: {
      label: '<named-active-persistent-profile-root>',
      real_path_redacted_in_public_claims: true,
      status_before: {
        active: true,
        expired: false,
        manifest_status: 'active_persistent_profile_installed',
        activation_root_state: 'active_until_expiry',
        expires_at: expiresAt,
      },
      status_after: {
        active: true,
        expired: false,
        manifest_status: 'active_persistent_profile_installed',
        activation_root_state: 'active_until_expiry',
        expires_at: expiresAt,
      },
      status_final: {
        active: true,
        expired: false,
        manifest_status: 'active_persistent_profile_installed',
        activation_root_state: 'active_until_expiry',
        expires_at: expiresAt,
      },
    },
    selected_profile: {
      source: 'explicit-active-root-installed-profile-preflight-artifact',
      profile_id: 'protected-records-runtime-fixture-profile',
      runtime_profile_id: 'protected-records-disposable-runtime-profile',
      profile_sha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
      selected_by_explicit_id_and_sha: true,
      selects_latest_profile: false,
      recognition_contract_sha256: greenReport.hashes.recognition_contract_sha256,
      authority_grant_contract_sha256:
        greenReport.hashes.authority_grant_contract_sha256,
    },
    red_path_result: {
      result: 'pass',
      artifact_identity_expected_sha256_supplied: true,
      expected_artifact_body_sha256:
        greenReport.hashes.service_artifact_body_sha256,
      artifact_identity_sha256_matched: true,
      source_preflight_identity_bound_to_expected_artifact_sha256: true,
      signed_receipt_envelope_identity_bound_to_expected_artifact_sha256: true,
      verification_scope:
        'expected-artifact-identity-bound-local-fixture-projection',
      proof_ran_while_active_root_live: true,
      active_root_bound_preflight_verified: true,
      disposable_service_started: true,
      local_disposable_child_process_only: true,
      persistent_runtime_config_written: false,
      live_probing: false,
      baseline_recognized_write_boarded_inside_disposable_service: true,
      baseline_recognized_state_append_count: 1,
      recognition_refusals_before_mutation: true,
      authority_grant_refusals_before_consumption_and_mutation: true,
      same_process_signed_payload_replay_refused: true,
      restart_consumed_authority_grant_refused: true,
      recognition_refusal_state_append_count: 0,
      authority_refusal_state_append_count: 0,
      replay_refusal_state_append_count: 0,
      partial_commit_state_append_count: 0,
      state_append_after_grant_commit_burn_observed: true,
      metadata_partial_commit_burn_observed: true,
      store_and_anchor_rollback_refused_while_witness_ahead: true,
      store_anchor_and_witness_joint_rollback_detection: false,
      joint_rollback_reopened_authority_grant_reuse: true,
      authority_grant_supplied_by_agent: false,
      recognition_rule_supplied_by_agent: false,
      recognition_refusal_case_count: 18,
      authority_refusal_case_count: 5,
      recognition_refusal_taxonomy_sha256:
        greenReport.hashes.recognition_refusal_taxonomy_sha256,
      authority_refusal_taxonomy_sha256:
        greenReport.hashes.authority_refusal_taxonomy_sha256,
      fixture_rightful_issuance_path_evidenced: true,
      rightful_issuance_proven: false,
      portable_rightful_issuance_proven: false,
      live_authority_proven: false,
      production_rightful_issuance_proven: false,
      current_machine_governance_proven: false,
      consequence_lifecycle_closed: false,
    },
    recognition_refusal_cases: Array.from({ length: 18 }, (_, index) => ({
      case_id: `recognition_case_${index + 1}`,
      reason_code: `recognition_reason_${index + 1}`,
      refused_before_mutation: true,
    })),
    authority_refusal_cases: Array.from({ length: 5 }, (_, index) => ({
      case_id: `authority_case_${index + 1}`,
      reason_code: `authority_reason_${index + 1}`,
      refused_before_consumption_and_mutation: true,
    })),
    artifact_hashes: {
      preflight_report_sha256: greenReport.hashes.preflight_report_sha256,
      service_proof_report_sha256: greenReport.hashes.service_proof_sha256,
      service_artifact_body_sha256:
        greenReport.hashes.service_artifact_body_sha256,
      service_verification_sha256: fakeSha,
      status_before_sha256: fakeSha,
      status_after_sha256: fakeSha,
      status_final_sha256: fakeSha,
      run_transcript_sha256: fakeSha,
    },
    exact_claim: 'local active persistent profile red-path refusal before mutation',
    non_claims: ['not production authority'],
    wrapper_note: 'cli fixture includes private scratch path; command output must not echo it',
    failures: [],
  };
}

function makeCloseoutReport({ closeout, beforeStatus, afterStatus, generatedAt }) {
  return {
    proof_report_type: 'zlar-active-persistent-profile-closeout-refusal-proof-report-v1',
    generated_at: generatedAt,
    authority_packet: { packet_sha256: fakeSha },
    scratch_dir: '<private-closeout-scratch>',
    closeout: {
      closed_at: closeout.closed_at,
      status: closeout.status,
      active: closeout.active,
      closeout_reactivation_allowed: closeout.closeout_reactivation_allowed,
    },
    before_status: {
      active: beforeStatus.active,
      expired: beforeStatus.expired,
      manifest_status: beforeStatus.manifest_status,
      activation_root_state: beforeStatus.activation_root_state,
      expires_at: beforeStatus.expires_at,
    },
    after_status: {
      active: afterStatus.active,
      expired: afterStatus.expired,
      manifest_status: afterStatus.manifest_status,
      activation_root_state: afterStatus.activation_root_state,
      safe_for_install: afterStatus.safe_for_install,
      explicit_closeout_or_replace_required: afterStatus.explicit_closeout_or_replace_required,
      expires_at: afterStatus.expires_at,
    },
    refused_after_closeout_probe: {
      attempted_action_class: 'records.write',
      exit_code: 1,
      stdout_sha256: fakeSha,
      stderr_sha256: fakeSha,
      stderr_redacted_snippet: 'ERROR: active persistent action crossing requires an active unexpired explicit root',
      target_written: false,
      refusal_before_target_mutation: true,
    },
    artifact_hashes: {
      status_before_sha256: fakeSha,
      closeout_sha256: closeout.manifest_sha256,
      status_after_sha256: fakeSha,
      refused_stdout_sha256: fakeSha,
      refused_stderr_sha256: fakeSha,
      refused_exit_sha256: fakeSha,
    },
    exact_claim: 'closed active persistent profile root refuses subsequent action crossing before mutation',
    non_claims: ['not current-machine governance'],
    failures: [],
  };
}

try {
  const root = join(scratch, 'activation', 'protected-records-private-operator-records-terminal');
  const nowEpoch = Math.floor(Date.now() / 1000);
  const expiresAt = iso(nowEpoch + 3600);
  const installReport = runActivePersistentProfileLiveInstallation({
    activationRoot: root,
    profile,
    profileSource: ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
    runtimeProfileId: 'protected-records-disposable-runtime-profile',
    runtimeProfileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    expiresAt,
    nowEpoch,
    allowNamedLiveRoot: true,
    expectedLiveRoot: root,
  });
  const greenReport = runProtectedRecordsActivePersistentProfileActionCrossing({
    activationRoot: root,
    expectedProfile: profile,
    profileId: 'protected-records-runtime-fixture-profile',
    profileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    proofTarget: join(scratch, 'green', 'records-write.jsonl'),
    nowEpoch: nowEpoch + 60,
    allowNamedLiveRoot: true,
    expectedLiveRoot: root,
  });
  const beforeStatus = inspectActivePersistentProfileLiveStatus({
    activationRoot: root,
    nowEpoch: nowEpoch + 120,
    allowNamedLiveRoot: true,
    expectedLiveRoot: root,
  });
  const closeout = closeActivePersistentProfileLiveInstallation({
    activationRoot: root,
    closedAt: iso(nowEpoch + 180),
    reason: 'operator_closeout',
    nowEpoch: nowEpoch + 180,
    allowNamedLiveRoot: true,
    expectedLiveRoot: root,
  });
  const afterStatus = inspectActivePersistentProfileLiveStatus({
    activationRoot: root,
    nowEpoch: nowEpoch + 180,
    allowNamedLiveRoot: true,
    expectedLiveRoot: root,
  });
  const redReport = makeRedReport({
    greenReport,
    expiresAt,
    generatedAt: iso(nowEpoch + 120),
  });
  const closeoutReport = makeCloseoutReport({
    closeout,
    beforeStatus,
    afterStatus,
    generatedAt: iso(nowEpoch + 181),
  });

  const installPath = join(scratch, 'reports', 'install.json');
  const greenPath = join(scratch, 'reports', 'green.json');
  const redPath = join(scratch, 'reports', 'red.json');
  const closeoutPath = join(scratch, 'reports', 'closeout.json');
  const outputPath = join(scratch, 'reports', 'lifecycle.json');
  writeJson(installPath, installReport);
  writeJson(greenPath, greenReport);
  writeJson(redPath, redReport);
  writeJson(closeoutPath, closeoutReport);
  const expectedHashes = {
    install: fileSha256(installPath),
    green: fileSha256(greenPath),
    red: fileSha256(redPath),
    closeout: fileSha256(closeoutPath),
  };

  console.log('\n-- lifecycle CLI success --');
  const command = [
    'protected-records-active-persistent-profile-lifecycle',
    '--install-report', installPath,
    '--green-report', greenPath,
    '--red-report', redPath,
    '--closeout-report', closeoutPath,
    '--expected-install-report-sha256', expectedHashes.install,
    '--expected-green-report-sha256', expectedHashes.green,
    '--expected-red-report-sha256', expectedHashes.red,
    '--expected-closeout-report-sha256', expectedHashes.closeout,
    '--report', outputPath,
  ];
  const result = spawnSync('./bin/zlar', command, {
    cwd: process.cwd(),
    encoding: 'utf8',
  });
  assert('cli exits zero', result.status === 0, result.stderr);
  assert('cli stdout privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(result.stdout));
  assert('cli stdout omits raw paths', !unsafeOutputPattern.test(result.stdout));
  assert('cli writes lifecycle report', existsSync(outputPath));
  assert('written lifecycle report privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(readFileSync(outputPath, 'utf8')));
  const written = JSON.parse(readFileSync(outputPath, 'utf8'));
  assert('written report uses basename labels', Object.values(written.supplied_reports.labels).every((value) => !value.includes('/')));
  assert('written report records expected hashes bound', written.claim_boundary.expected_input_report_hashes_bound === true);
  assert('written report pins fixture authority epoch', written.lifecycle.green_local_service_authority_evaluation_epoch === PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH && written.lifecycle.red_local_service_authority_evaluation_epoch === PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH && written.lifecycle.fixture_authority_evaluation_epoch_pinned === true);
  assert('written report binds fresh service artifact and embedded identities', written.lifecycle.fresh_service_artifact_identity_pins_matched === true && written.lifecycle.fresh_source_preflight_identities_bound === true && written.lifecycle.fresh_signed_receipt_envelope_identities_bound === true);
  assert('written report keeps fixture rightful claim bounded', written.claim_boundary.fixture_rightful_issuance_path_evidenced === true && written.claim_boundary.rightful_issuance_proven === false && written.claim_boundary.live_authority_proven === false && written.claim_boundary.consequence_lifecycle_closed === false);

  console.log('\n-- lifecycle CLI runner success --');
  const fakeHome = join(scratch, 'fake-home');
  const runnerRoot = join(fakeHome, '.zlar', 'protected-records', 'deployments', 'protected-records-private-operator-records-terminal');
  const runnerOutput = join(scratch, 'runner-output');
  const runner = spawnSync('./bin/zlar', [
    'protected-records-active-persistent-profile-lifecycle',
    'run',
    '--activation-root', runnerRoot,
    '--output-dir', runnerOutput,
    '--profile', ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
    '--runtime-profile-id', 'protected-records-disposable-runtime-profile',
    '--runtime-profile-sha256', ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    '--expires-at', iso(nowEpoch + 5400),
    '--allow-named-live-root',
  ], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: {
      ...process.env,
      HOME: fakeHome,
      NO_COLOR: '1',
    },
  });
  assert('runner exits zero', runner.status === 0, runner.stderr);
  assert('runner stdout privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(runner.stdout));
  assert('runner stdout omits raw paths', !unsafeOutputPattern.test(runner.stdout));
  assert('runner writes lifecycle report', existsSync(join(runnerOutput, 'zlar-active-persistent-profile-lifecycle-v1.json')));
  assert('runner writes source binding', existsSync(join(runnerOutput, 'zlar-active-persistent-profile-lifecycle-source-binding-v1.json')));
  assert('runner post-closeout target absent', !existsSync(join(runnerOutput, 'post-closeout-records-write-target.jsonl')));
  const runnerLifecycle = JSON.parse(
    readFileSync(join(runnerOutput, 'zlar-active-persistent-profile-lifecycle-v1.json'), 'utf8')
  );
  assert('runner lifecycle pins fixture authority epoch', runnerLifecycle.lifecycle.fixture_authority_evaluation_epoch_pinned === true && runnerLifecycle.lifecycle.green_local_service_authority_evaluation_epoch === PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH);
  assert('runner lifecycle binds fresh service artifact and embedded identities', runnerLifecycle.lifecycle.fresh_service_artifact_identity_pins_matched === true && runnerLifecycle.lifecycle.fresh_source_preflight_identities_bound === true && runnerLifecycle.lifecycle.fresh_signed_receipt_envelope_identities_bound === true);
  assert('runner lifecycle does not imply live rightful issuance', runnerLifecycle.claim_boundary.fixture_rightful_issuance_path_evidenced === true && runnerLifecycle.claim_boundary.rightful_issuance_proven === false && runnerLifecycle.claim_boundary.live_authority_proven === false && runnerLifecycle.claim_boundary.consequence_lifecycle_closed === false);
  assert('runner summary names rightful claim ceiling', runner.stdout.includes('fixture_rightful_issuance_path_evidenced=true; rightful_issuance_proven=false; live_authority_proven=false; consequence_lifecycle_closed=false'));

  console.log('\n-- lifecycle CLI refusal --');
  const latest = spawnSync('./bin/zlar', [
    'protected-records-active-persistent-profile-lifecycle',
    '--latest',
  ], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });
  assert('latest refused', latest.status !== 0);
  assert('latest refusal privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(latest.stderr));
  const tamperedRedPath = join(scratch, 'reports', 'red-tampered.json');
  const tamperedRed = structuredClone(redReport);
  tamperedRed.red_path_result.recognition_refusal_state_append_count = 1;
  writeJson(tamperedRedPath, tamperedRed);
  const tampered = spawnSync('./bin/zlar', [
    'protected-records-active-persistent-profile-lifecycle',
    '--install-report', installPath,
    '--green-report', greenPath,
    '--red-report', tamperedRedPath,
    '--closeout-report', closeoutPath,
  ], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });
  assert('tampered red report refused', tampered.status !== 0);
  assert('tampered refusal privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(tampered.stderr));
  const mismatch = spawnSync('./bin/zlar', [
    'protected-records-active-persistent-profile-lifecycle',
    '--install-report', installPath,
    '--green-report', greenPath,
    '--red-report', redPath,
    '--closeout-report', closeoutPath,
    '--expected-install-report-sha256', expectedHashes.install,
    '--expected-green-report-sha256', expectedHashes.green,
    '--expected-red-report-sha256', '0'.repeat(64),
    '--expected-closeout-report-sha256', expectedHashes.closeout,
  ], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });
  assert('expected hash mismatch refused', mismatch.status !== 0);
  assert('expected hash mismatch privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(mismatch.stderr));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(`\nResults: ${PASS}/${TOTAL} passed${FAIL ? `, ${FAIL} failed` : ''}`);
if (FAIL) process.exit(1);
console.log('ALL PASS');
