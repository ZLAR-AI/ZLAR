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
import { join } from 'node:path';
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
import {
  assertActivePersistentProfileCloseoutRefusalReport,
  assertActivePersistentProfileLifecycleSourceBinding,
  assertActivePersistentProfileLifecycleReport,
  assertActivePersistentProfileRedPathRefusalReport,
  buildActivePersistentProfileLifecycleSourceBinding,
  buildActivePersistentProfileLifecycleReport,
  buildActivePersistentProfileLifecycleReportFromFiles,
  formatActivePersistentProfileLifecycleReport,
  runActivePersistentProfileCloseoutRefusal,
  runActivePersistentProfileLifecycleEvidence,
  runActivePersistentProfileRedPathRefusal,
  writeActivePersistentProfileLifecycleReport,
} from '../lib/protected-records-active-persistent-profile-lifecycle.mjs';

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
const profile = JSON.parse(readFileSync(ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE, 'utf8'));
const scratch = mkdtempSync(join(tmpdir(), 'zlar-active-lifecycle-test-'));

function iso(epoch) {
  return new Date(epoch * 1000).toISOString();
}

function writeJson(path, value) {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function fileSha256(path) {
  return createHash('sha256').update(readFileSync(path, 'utf8')).digest('hex');
}

try {
  const root = join(scratch, 'activation', 'protected-records-private-operator-records-terminal');
  const nowEpoch = Math.floor(Date.now() / 1000);
  const expiresAt = iso(nowEpoch + 3600);

  console.log('\n-- build local lifecycle evidence --');
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
  const redReport = runActivePersistentProfileRedPathRefusal({
    activationRoot: root,
    expectedProfile: profile,
    profileId: 'protected-records-runtime-fixture-profile',
    profileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    nowEpoch: nowEpoch + 120,
    allowNamedLiveRoot: true,
    expectedLiveRoot: root,
  });
  const closeoutReport = runActivePersistentProfileCloseoutRefusal({
    activationRoot: root,
    expectedProfile: profile,
    profileId: 'protected-records-runtime-fixture-profile',
    profileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    proofTarget: join(scratch, 'after-closeout', 'records-write.jsonl'),
    closedAt: iso(nowEpoch + 180),
    nowEpoch: nowEpoch + 180,
    allowNamedLiveRoot: true,
    expectedLiveRoot: root,
  });
  assert('red report validates', assertActivePersistentProfileRedPathRefusalReport(redReport));
  assertEqual('red active-root status uses action epoch', nowEpoch + 120, redReport.evaluation_time_contract.active_root_status_epoch);
  assertEqual('red local service uses fixture authority epoch', PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH, redReport.evaluation_time_contract.local_service_authority_evaluation_epoch);
  assertEqual('red fixture epoch not live authority time', true, redReport.evaluation_time_contract.fixture_epoch_is_not_live_authority_time);
  assertEqual('red recognition refusal cases', 18, redReport.red_path_result.recognition_refusal_case_count);
  assertEqual('red authority refusal cases', 5, redReport.red_path_result.authority_refusal_case_count);
  assertEqual('red same-process signed replay refused', true, redReport.red_path_result.same_process_signed_payload_replay_refused);
  assertEqual('red restart consumed grant refused', true, redReport.red_path_result.restart_consumed_authority_grant_refused);
  assertEqual('red fresh service artifact expected SHA supplied', true, redReport.red_path_result.artifact_identity_expected_sha256_supplied);
  assertEqual('red fresh service artifact identity matched', true, redReport.red_path_result.artifact_identity_sha256_matched);
  assertEqual('red fresh service artifact expected SHA matches body', redReport.artifact_hashes.service_artifact_body_sha256, redReport.red_path_result.expected_artifact_body_sha256);
  assertEqual('red source preflight identity bound through fresh artifact pin', true, redReport.red_path_result.source_preflight_identity_bound_to_expected_artifact_sha256);
  assertEqual('red signed receipt envelope identity bound through fresh artifact pin', true, redReport.red_path_result.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256);
  assertEqual('red fixture rightful issuance true', true, redReport.red_path_result.fixture_rightful_issuance_path_evidenced);
  assertEqual('red generic rightful issuance false', false, redReport.red_path_result.rightful_issuance_proven);
  assertEqual('red lifecycle closure false', false, redReport.red_path_result.consequence_lifecycle_closed);
  assert('closeout report validates', assertActivePersistentProfileCloseoutRefusalReport(closeoutReport));
  assert('red report privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(redReport)));
  assert('closeout report privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(closeoutReport)));

  console.log('\n-- lifecycle verifier success --');
  const lifecycleReport = buildActivePersistentProfileLifecycleReport({
    installReport,
    greenReport,
    redReport,
    closeoutReport,
    inputReportLabels: {
      install_report: 'install.json',
      green_report: 'green.json',
      red_report: 'red.json',
      closeout_report: 'closeout.json',
    },
    generatedAt: '2030-01-01T00:07:00.000Z',
  });
  assert('lifecycle report validates', assertActivePersistentProfileLifecycleReport(lifecycleReport));
  assertEqual('result pass', 'pass', lifecycleReport.result);
  assertEqual('green verified', true, lifecycleReport.claim_boundary.green_path_governed_action_crossing_verified);
  assertEqual('red verified', true, lifecycleReport.claim_boundary.red_path_refusal_before_mutation_verified);
  assertEqual('closeout verified', true, lifecycleReport.claim_boundary.closeout_refusal_before_mutation_verified);
  assertEqual('expected hashes unbound by default', false, lifecycleReport.claim_boundary.expected_input_report_hashes_bound);
  assertEqual('production recognition false', false, lifecycleReport.claim_boundary.production_downstream_recognition);
  assertEqual('current-machine governance false', false, lifecycleReport.claim_boundary.current_machine_governance_general);
  assertEqual('lifecycle fixture authority epoch pinned', true, lifecycleReport.lifecycle.fixture_authority_evaluation_epoch_pinned);
  assertEqual('lifecycle fresh service artifact identity pins matched', true, lifecycleReport.lifecycle.fresh_service_artifact_identity_pins_matched);
  assertEqual('lifecycle fresh source preflight identities bound', true, lifecycleReport.lifecycle.fresh_source_preflight_identities_bound);
  assertEqual('lifecycle fresh signed receipt envelope identities bound', true, lifecycleReport.lifecycle.fresh_signed_receipt_envelope_identities_bound);
  assertEqual('lifecycle fixture rightful issuance true', true, lifecycleReport.claim_boundary.fixture_rightful_issuance_path_evidenced);
  assertEqual('lifecycle generic rightful issuance false', false, lifecycleReport.claim_boundary.rightful_issuance_proven);
  assertEqual('lifecycle live authority false', false, lifecycleReport.claim_boundary.live_authority_proven);
  assertEqual('lifecycle closure false', false, lifecycleReport.claim_boundary.consequence_lifecycle_closed);
  const summary = formatActivePersistentProfileLifecycleReport(lifecycleReport);
  assert('summary privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(summary));
  assert('summary omits raw paths', !unsafeOutputPattern.test(summary));

  console.log('\n-- file input and report writing --');
  const installPath = join(scratch, 'reports', 'install.json');
  const greenPath = join(scratch, 'reports', 'green.json');
  const redPath = join(scratch, 'reports', 'red.json');
  const closeoutPath = join(scratch, 'reports', 'closeout.json');
  writeJson(installPath, installReport);
  writeJson(greenPath, greenReport);
  writeJson(redPath, redReport);
  writeJson(closeoutPath, closeoutReport);
  const expectedInputReportHashes = {
    install_report_sha256: fileSha256(installPath),
    green_report_sha256: fileSha256(greenPath),
    red_report_sha256: fileSha256(redPath),
    closeout_report_sha256: fileSha256(closeoutPath),
  };
  const fromFiles = buildActivePersistentProfileLifecycleReportFromFiles({
    installReportPath: installPath,
    greenReportPath: greenPath,
    redReportPath: redPath,
    closeoutReportPath: closeoutPath,
    expectedInputReportHashes,
  });
  assert('file report validates', assertActivePersistentProfileLifecycleReport(fromFiles));
  assertEqual('expected hashes bound true', true, fromFiles.claim_boundary.expected_input_report_hashes_bound);
  assert('file report labels are basenames', Object.values(fromFiles.supplied_reports.labels).every((value) => !value.includes('/')));
  const outputPath = join(scratch, 'lifecycle-output', 'lifecycle.json');
  const writtenSha = writeActivePersistentProfileLifecycleReport({ report: fromFiles, outputPath });
  assert('lifecycle output written', existsSync(outputPath) && /^[a-f0-9]{64}$/.test(writtenSha));
  assert('lifecycle output privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(readFileSync(outputPath, 'utf8')));
  const sourceBinding = buildActivePersistentProfileLifecycleSourceBinding({
    lifecycleReportSha256: writtenSha,
    sourceReports: {
      install_report: { file: 'install.json', sha256: expectedInputReportHashes.install_report_sha256 },
      green_report: { file: 'green.json', sha256: expectedInputReportHashes.green_report_sha256 },
      red_report: { file: 'red.json', sha256: expectedInputReportHashes.red_report_sha256 },
      closeout_report: { file: 'closeout.json', sha256: expectedInputReportHashes.closeout_report_sha256 },
    },
  });
  assert('source binding validates', assertActivePersistentProfileLifecycleSourceBinding(sourceBinding));
  assertEqual('source binding non-scoring', true, sourceBinding.non_scoring);
  assertEqual('source binding current installation false', false, sourceBinding.current_installation);
  assertEqual('source binding production recognition false', false, sourceBinding.production_downstream_recognition);
  assertThrows('existing lifecycle output refused', () => writeActivePersistentProfileLifecycleReport({ report: fromFiles, outputPath }), 'already exists');
  assertThrows('expected hash mismatch fails', () => buildActivePersistentProfileLifecycleReportFromFiles({
    installReportPath: installPath,
    greenReportPath: greenPath,
    redReportPath: redPath,
    closeoutReportPath: closeoutPath,
    expectedInputReportHashes: {
      ...expectedInputReportHashes,
      red_report_sha256: '0'.repeat(64),
    },
  }), 'expected input hash mismatch');
  assertThrows('partial expected hashes fail', () => buildActivePersistentProfileLifecycleReportFromFiles({
    installReportPath: installPath,
    greenReportPath: greenPath,
    redReportPath: redPath,
    closeoutReportPath: closeoutPath,
    expectedInputReportHashes: {
      install_report_sha256: expectedInputReportHashes.install_report_sha256,
    },
  }), 'all-or-none');

  console.log('\n-- lifecycle runner generates source-bound evidence --');
  const runnerRoot = join(scratch, 'runner', 'activation', 'protected-records-private-operator-records-terminal');
  const runnerOutput = join(scratch, 'runner-evidence');
  const runnerNowEpoch = Math.floor(Date.now() / 1000);
  const runnerResult = runActivePersistentProfileLifecycleEvidence({
    activationRoot: runnerRoot,
    outputDir: runnerOutput,
    profilePath: ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
    runtimeProfileId: 'protected-records-disposable-runtime-profile',
    runtimeProfileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    expiresAt: iso(runnerNowEpoch + 5400),
    nowEpoch: runnerNowEpoch,
    allowNamedLiveRoot: true,
    expectedLiveRoot: runnerRoot,
  });
  assertEqual('runner passes', 'pass', runnerResult.result);
  assertEqual('runner replacement false on fresh root', false, runnerResult.closed_root_replacement_authorized);
  assertEqual('runner post-closeout target absent', false, runnerResult.proof_targets.post_closeout_records_write.written);
  assertEqual('runner fixture rightful issuance true', true, runnerResult.claim_boundary.fixture_rightful_issuance_path_evidenced);
  assertEqual('runner fresh service artifact identity pins matched', true, runnerResult.claim_boundary.fresh_service_artifact_identity_pins_matched);
  assertEqual('runner fresh source preflight identities bound', true, runnerResult.claim_boundary.fresh_source_preflight_identities_bound);
  assertEqual('runner fresh signed receipt envelope identities bound', true, runnerResult.claim_boundary.fresh_signed_receipt_envelope_identities_bound);
  assertEqual('runner generic rightful issuance false', false, runnerResult.claim_boundary.rightful_issuance_proven);
  assertEqual('runner live authority false', false, runnerResult.claim_boundary.live_authority_proven);
  assertEqual('runner lifecycle closure false', false, runnerResult.claim_boundary.consequence_lifecycle_closed);
  assert('runner lifecycle report exists', existsSync(join(runnerOutput, runnerResult.files.lifecycle_report.file)));
  assert('runner source binding exists', existsSync(join(runnerOutput, runnerResult.files.source_binding.file)));
  assert('runner result privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(runnerResult)));
  const runnerBinding = JSON.parse(readFileSync(join(runnerOutput, runnerResult.files.source_binding.file), 'utf8'));
  assert('runner source binding validates', assertActivePersistentProfileLifecycleSourceBinding(runnerBinding));
  const insideRoot = join(scratch, 'inside-output', 'protected-records-private-operator-records-terminal');
  const insideOutput = join(insideRoot, 'evidence');
  assertThrows('runner output directory inside activation root refused', () => runActivePersistentProfileLifecycleEvidence({
    activationRoot: insideRoot,
    outputDir: insideOutput,
    profilePath: ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
    runtimeProfileId: 'protected-records-disposable-runtime-profile',
    runtimeProfileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    expiresAt: iso(runnerNowEpoch + 5400),
    nowEpoch: runnerNowEpoch,
    allowNamedLiveRoot: true,
    expectedLiveRoot: insideRoot,
  }), 'may not be written inside the activation root');
  assertEqual('refused inside-root output leaves no activation root residue', false, existsSync(insideRoot));
  assertEqual('refused inside-root output leaves no output dir residue', false, existsSync(insideOutput));
  const wrongCloseoutRoot = join(scratch, 'wrong-closeout', 'protected-records-private-operator-records-terminal');
  const wrongCloseoutNow = Math.floor(Date.now() / 1000);
  runActivePersistentProfileLiveInstallation({
    activationRoot: wrongCloseoutRoot,
    profile,
    profileSource: ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
    runtimeProfileId: 'protected-records-disposable-runtime-profile',
    runtimeProfileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    expiresAt: iso(wrongCloseoutNow + 5400),
    nowEpoch: wrongCloseoutNow,
    allowNamedLiveRoot: true,
    expectedLiveRoot: wrongCloseoutRoot,
  });
  const wrongCloseoutTarget = join(scratch, 'wrong-closeout-target', 'records-write.jsonl');
  assertThrows('closeout proof refuses wrong profile SHA before laundering probe failure', () => runActivePersistentProfileCloseoutRefusal({
    activationRoot: wrongCloseoutRoot,
    expectedProfile: profile,
    profileId: 'protected-records-runtime-fixture-profile',
    profileSha256: '0'.repeat(64),
    proofTarget: wrongCloseoutTarget,
    closedAt: iso(wrongCloseoutNow + 180),
    nowEpoch: wrongCloseoutNow + 180,
    allowNamedLiveRoot: true,
    expectedLiveRoot: wrongCloseoutRoot,
  }), 'fixed runtime profile binding');
  const wrongCloseoutStatus = inspectActivePersistentProfileLiveStatus({
    activationRoot: wrongCloseoutRoot,
    nowEpoch: wrongCloseoutNow + 180,
    allowNamedLiveRoot: true,
    expectedLiveRoot: wrongCloseoutRoot,
  });
  assertEqual('wrong profile SHA leaves active root unclosed', true, wrongCloseoutStatus.active);
  assertEqual('wrong profile SHA writes no probe target', false, existsSync(wrongCloseoutTarget));

  console.log('\n-- drift guards --');
  const redMutation = structuredClone(redReport);
  redMutation.red_path_result.recognition_refusal_state_append_count = 1;
  assertThrows('red mutation drift fails', () => buildActivePersistentProfileLifecycleReport({
    installReport,
    greenReport,
    redReport: redMutation,
    closeoutReport,
  }), 'red-path result drifted');
  const detachedStructuralRed = structuredClone(redReport);
  detachedStructuralRed.red_path_result.artifact_identity_expected_sha256_supplied = false;
  detachedStructuralRed.red_path_result.expected_artifact_body_sha256 = null;
  detachedStructuralRed.red_path_result.artifact_identity_sha256_matched = false;
  detachedStructuralRed.red_path_result.source_preflight_identity_bound_to_expected_artifact_sha256 = false;
  detachedStructuralRed.red_path_result.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256 = false;
  detachedStructuralRed.red_path_result.verification_scope = 'structural-self-integrity-only';
  detachedStructuralRed.red_path_result.baseline_recognized_write_boarded_inside_disposable_service = false;
  detachedStructuralRed.red_path_result.baseline_recognized_state_append_count = 0;
  detachedStructuralRed.red_path_result.fixture_rightful_issuance_path_evidenced = false;
  assertThrows('detached structural verification cannot preserve positive lifecycle evidence', () => buildActivePersistentProfileLifecycleReport({
    installReport,
    greenReport,
    redReport: detachedStructuralRed,
    closeoutReport,
  }), 'red-path result drifted');
  const closeoutMutation = structuredClone(closeoutReport);
  closeoutMutation.refused_after_closeout_probe.target_written = true;
  assertThrows('closeout mutation drift fails', () => buildActivePersistentProfileLifecycleReport({
    installReport,
    greenReport,
    redReport,
    closeoutReport: closeoutMutation,
  }), 'closeout refusal probe drifted');
  const closeoutReasonMutation = structuredClone(closeoutReport);
  closeoutReasonMutation.refused_after_closeout_probe.stderr_redacted_snippet = 'ERROR: wrong refusal';
  assertThrows('closeout refusal reason drift fails', () => buildActivePersistentProfileLifecycleReport({
    installReport,
    greenReport,
    redReport,
    closeoutReport: closeoutReasonMutation,
  }), 'closeout refusal reason drifted');
  const latestMutation = structuredClone(redReport);
  latestMutation.selected_profile.selects_latest_profile = true;
  assertThrows('latest red profile drift fails', () => buildActivePersistentProfileLifecycleReport({
    installReport,
    greenReport,
    redReport: latestMutation,
    closeoutReport,
  }), 'selected profile drifted');
  const recognitionMutation = structuredClone(redReport);
  recognitionMutation.selected_profile.recognition_contract_sha256 = '0'.repeat(64);
  assertThrows('recognition contract mismatch fails', () => buildActivePersistentProfileLifecycleReport({
    installReport,
    greenReport,
    redReport: recognitionMutation,
    closeoutReport,
  }), 'profile binding drifted');
  const taxonomyMutation = structuredClone(redReport);
  taxonomyMutation.red_path_result.recognition_refusal_taxonomy_sha256 = '0'.repeat(64);
  assertThrows('refusal taxonomy mismatch fails', () => buildActivePersistentProfileLifecycleReport({
    installReport,
    greenReport,
    redReport: taxonomyMutation,
    closeoutReport,
  }), 'profile binding drifted');
  const closeoutSourceMutation = structuredClone(closeoutReport);
  closeoutSourceMutation.artifact_hashes.status_before_sha256 = '0'.repeat(64);
  assertThrows('closeout source hash mismatch fails', () => buildActivePersistentProfileLifecycleReport({
    installReport,
    greenReport,
    redReport,
    closeoutReport: closeoutSourceMutation,
  }), 'closeout source binding drifted');
  const invalidTimestamp = structuredClone(redReport);
  invalidTimestamp.generated_at = 'not-a-date';
  assertThrows('invalid timestamp fails', () => buildActivePersistentProfileLifecycleReport({
    installReport,
    greenReport,
    redReport: invalidTimestamp,
    closeoutReport,
  }), 'valid ISO-8601');
  const outOfOrder = structuredClone(redReport);
  outOfOrder.generated_at = iso(nowEpoch - 1);
  outOfOrder.evaluation_time_contract.active_root_status_epoch = nowEpoch - 1;
  assertThrows('out-of-order timestamp fails', () => buildActivePersistentProfileLifecycleReport({
    installReport,
    greenReport,
    redReport: outOfOrder,
    closeoutReport,
  }), 'out of order');
  const overclaim = structuredClone(lifecycleReport);
  overclaim.claim_boundary.enterprise_readiness = true;
  assertThrows('lifecycle overclaim fails', () => assertActivePersistentProfileLifecycleReport(overclaim), 'enterprise_readiness');
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(`\nResults: ${PASS}/${TOTAL} passed${FAIL ? `, ${FAIL} failed` : ''}`);
if (FAIL) process.exit(1);
console.log('ALL PASS');
