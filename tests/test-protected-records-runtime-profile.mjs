#!/usr/bin/env node

import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  NON_CLAIMS,
  PROTECTED_RECORDS_TARGET_HANDLE,
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  PROTECTED_RECORDS_RUNTIME_PROFILE_PROOF_TYPE,
  REQUIRED_RUNTIME_PROFILE_CASES,
  SAFE_CLAIM_CEILING,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
  assertProtectedRecordsRuntimeProfileProof,
  assertProtectedRecordsRuntimeServiceResult,
  createProtectedRecordsRuntimeAuthorityReceiptEvidence,
  createProtectedRecordsRuntimeFixtureAuthorityGrantContract,
  createProtectedRecordsRuntimeLauncherScopeEvidence,
  createProtectedRecordsRuntimeService,
  createProtectedRecordsRuntimeTargetBinding,
  formatProtectedRecordsRuntimeProfileProofSummary,
  protectedRecordsTargetEffect,
  runProtectedRecordsRuntimeProfileProof,
} from '../lib/protected-records-runtime-profile.mjs';
import {
  createReceiptV1FromEvent,
  decodePayloadV1,
  signReceiptV1,
} from '../lib/receipt.mjs';
import {
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_EVALUATION_EPOCH,
  PROTECTED_RECORDS_FIXTURE_AUTHORIZED_RECORD_UPDATE,
  createProtectedRecordsFixtureAuthorityGrantAppointment,
  evaluateProtectedRecordsFixtureAuthorityGrantIssuance,
  protectedRecordsAuthorizedEffectDetail,
} from '../lib/protected-records-fixture-authority-grant.mjs';

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

const expectedReasons = {
  recognized_runtime_write_first_request: 'fixture_authority_grant_effect_satisfied',
  replay_runtime_write_refused_same_service_process: 'receipt_replay',
  replay_runtime_write_refused_after_service_restart: 'authority_grant_already_consumed',
  invalid_consumed_store_refused_before_runtime_mutation: 'consumed_store_invalid',
  duplicate_consumed_store_refused_before_runtime_mutation: 'consumed_store_invalid',
  locked_consumed_store_refused_before_runtime_mutation: 'consumed_store_locked',
  invalid_consumed_store_anchor_refused_before_runtime_mutation: 'consumed_store_anchor_invalid',
  valid_consumed_store_rollback_refused_before_runtime_mutation: 'consumed_store_rollback_detected',
  consumed_store_deletion_refused_before_runtime_mutation: 'consumed_store_rollback_detected',
  valid_consumed_store_replacement_refused_before_runtime_mutation: 'consumed_store_rollback_detected',
  runtime_state_append_failed_after_consumed_store_commit: 'runtime_state_append_failed_after_consumed_store_commit',
  witness_commit_failed_after_authority_grant_store_commit:
    'consumed_store_write_failed_after_grant_commit',
  store_and_anchor_joint_rollback_refused_against_witness_before_runtime_mutation: 'consumed_store_rollback_detected',
  missing_receipt_refused_before_runtime_mutation: 'receipt_missing',
  invalid_receipt_refused_before_runtime_mutation: 'receipt_invalid',
  unknown_issuer_refused_before_runtime_mutation: 'unknown_issuer',
  retired_issuer_refused_before_runtime_mutation: 'issuer_not_active',
  missing_issuer_status_refused_before_runtime_mutation: 'issuer_status_missing',
  missing_authority_grant_appointment_refused_before_consumption: 'authority_grant_missing',
  mismatched_authority_grant_appointment_refused_before_consumption: 'authority_grant_contract_mismatch',
  revoked_authority_grant_refused_before_consumption: 'authority_grant_revoked',
  expired_authority_grant_refused_before_consumption: 'authority_grant_expired',
  wrong_policy_refused_before_runtime_mutation: 'policy_not_recognized',
  wrong_domain_refused_before_runtime_mutation: 'domain_out_of_scope',
  wrong_tool_refused_before_runtime_mutation: 'tool_out_of_scope',
  wrong_runtime_profile_id_refused_before_runtime_mutation: 'agent_supplied_authority_material',
  wrong_audit_event_refused_before_runtime_mutation: 'audit_event_mismatch',
  wrong_detail_refused_before_runtime_mutation: 'detail_hash_mismatch',
  non_boarding_outcome_refused_before_runtime_mutation: 'outcome_not_boarding',
  stale_receipt_refused_before_runtime_mutation: 'receipt_stale',
  direct_api_without_receipt_refused_before_runtime_mutation: 'receipt_missing',
  direct_api_with_receipt_refused_before_runtime_mutation: 'direct_api_receipt_present',
  agent_supplied_state_path_refused_before_runtime_mutation: 'agent_supplied_authority_material',
  agent_supplied_consumed_grants_path_refused_before_runtime_mutation: 'agent_supplied_authority_material',
  agent_supplied_consumed_grant_store_anchor_path_refused_before_runtime_mutation: 'agent_supplied_authority_material',
  agent_supplied_fixture_mode_refused_before_runtime_mutation: 'agent_supplied_authority_material',
  agent_supplied_recognition_rule_refused_before_runtime_mutation: 'agent_supplied_authority_material',
  agent_supplied_authority_grant_refused_before_runtime_mutation: 'agent_supplied_authority_material',
  unsupported_request_field_refused_before_runtime_mutation: 'agent_supplied_authority_material',
};

section('runtime profile proof report');
const report = runProtectedRecordsRuntimeProfileProof();
assert('valid report passes validation', assertProtectedRecordsRuntimeProfileProof(report));
assertEqual('proof type', PROTECTED_RECORDS_RUNTIME_PROFILE_PROOF_TYPE, report.proof_type);
assertEqual('safe claim ceiling exact', SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('local disposable evidence', 'local-disposable-runtime-process-profile', report.evidence_model);
assertEqual('no live probing', false, report.live_probing);
assertEqual('case count', REQUIRED_RUNTIME_PROFILE_CASES.length, report.cases.length);
assertEqual('boundary observation count', 2, report.boundary_observations.length);

section('runtime profile contract');
assertEqual('profile id', PROTECTED_RECORDS_RUNTIME_PROFILE_ID, report.runtime_profile.profile_id);
assertEqual('profile status', 'active_during_disposable_proof_only', report.runtime_profile.profile_status);
assertEqual('action class', 'records.write', report.runtime_profile.action_class);
assertEqual('runtime environment', 'local-disposable-jsonl-child-process', report.runtime_profile.runtime_environment);
assertEqual('service command', 'zlar protected-records-runtime-service --config <file>', report.runtime_profile.service_command);
assertEqual('request contract', 'receipt-record-update-and-routing-metadata-only', report.runtime_profile.request_contract);
assertEqual('recognition boundary', 'service-configured-recognition-rule', report.runtime_profile.recognition_boundary);
assertEqual('mutation route', 'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation', report.runtime_profile.mutation_authoritative_route);
assertEqual('state storage', 'process-private-memory', report.runtime_profile.state_storage);
assertEqual('persistent consumed grant store', 'persistent-single-use-authority-grant-contract-sha256-store', report.runtime_profile.consumed_authority_grant_store);
assertEqual('consumption identity', 'authority-grant-contract-sha256', report.runtime_profile.consumption_identity);
assertEqual('signed payload replay identity', 'verified-signed-payload-sha256', report.runtime_profile.signed_payload_replay_identity);
assertEqual('consumed store lock', 'launcher-owned-per-store-lockfile', report.runtime_profile.consumed_store_lock);
assertEqual('consumed store validation', 'exact-schema-unique-grant-contract-sha256s', report.runtime_profile.consumed_store_validation);
assertEqual('consumed store anchor', 'launcher-owned-local-store-hash-anchor', report.runtime_profile.consumed_store_anchor);
assertEqual('consumed store witness', 'launcher-owned-local-store-hash-witness', report.runtime_profile.consumed_store_witness);
assertEqual('consumed store rollback detection', 'single-host-anchor-and-witness-match-before-mutation', report.runtime_profile.consumed_store_rollback_detection);
assertEqual('consumed store write model', 'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness', report.runtime_profile.consumed_store_write_model);
assertEqual('runtime replay scope', 'helper-signed-payload-identity-and-persistent-authority-grant-contract-sha256', report.runtime_profile.replay_scope);
assertEqual('persistent consumed grant store true', true, report.runtime_profile.persistent_consumed_authority_grant_store);
assertEqual('fixture clock model', 'fixed-hermetic-fixture-epoch', report.runtime_profile.fixture_clock_model);
assertEqual('state path hidden from agent', false, report.runtime_profile.state_path_exposed_to_agent);
assertEqual('recognition rule not agent supplied', false, report.runtime_profile.recognition_rule_supplied_by_agent);

section('runtime profile identity policy');
assertEqual('identity authority source', 'launcher-owned-service-config', report.runtime_profile_identity_policy.authority_source);
assertEqual('request runtime profile id not required', false, report.runtime_profile_identity_policy.request_runtime_profile_id_required);
assertEqual('omitted runtime profile id request field absent', false, report.runtime_profile_identity_policy.omitted_request_runtime_profile_id_present);
assertEqual('omitted runtime profile id uses launcher config', true, report.runtime_profile_identity_policy.omitted_runtime_profile_id_uses_launcher_config);
assertEqual('omitted runtime profile id grant reason', 'fixture_authority_grant_effect_satisfied', report.runtime_profile_identity_policy.omitted_runtime_profile_id_reason_code);
assertEqual('omitted runtime profile id mutates once', 1, report.runtime_profile_identity_policy.omitted_runtime_profile_id_state_entry_count_delta);
assertEqual('omitted runtime profile id consumes grant once', 1, report.runtime_profile_identity_policy.omitted_runtime_profile_id_consumed_authority_grant_count);
assertEqual('supplied mismatched runtime profile id refused', true, report.runtime_profile_identity_policy.supplied_mismatched_runtime_profile_id_refused);
assertEqual('supplied mismatched runtime profile id reason', 'agent_supplied_authority_material', report.runtime_profile_identity_policy.supplied_mismatch_reason_code);
assertEqual('supplied mismatched runtime profile id state delta zero', 0, report.runtime_profile_identity_policy.supplied_mismatch_state_entry_count_delta);

section('required cases');
for (const caseId of REQUIRED_RUNTIME_PROFILE_CASES) {
  const item = proofCase(report, caseId);
  assert(`case present: ${caseId}`, Boolean(item));
  assertEqual(`reason: ${caseId}`, expectedReasons[caseId], item.reason_code);
}

const accepted = proofCase(report, 'recognized_runtime_write_first_request');
assertEqual('accepted write true', true, accepted.service_write_accepted);
assertEqual('accepted first request', 1, accepted.request_ordinal);
assertEqual('accepted service process one', 1, accepted.service_process_invocation);
assertEqual('accepted before zero', 0, accepted.state_entry_count_before);
assertEqual('accepted after one', 1, accepted.state_entry_count_after);
assertEqual('accepted state delta one', 1, accepted.state_entry_count_delta);
assertEqual('accepted consumed grant count one', 1, accepted.consumed_authority_grant_count);
assertEqual('accepted consumed store exists', true, accepted.consumed_store_exists_after);
assertEqual('accepted consumed store anchor exists', true, accepted.consumed_store_anchor_exists_after);

const replay = proofCase(report, 'replay_runtime_write_refused_same_service_process');
assertEqual('replay refused', false, replay.service_write_accepted);
assertEqual('replay same service process', 1, replay.service_process_invocation);
assertEqual('replay second request', 2, replay.request_ordinal);
assertEqual('replay before one', 1, replay.state_entry_count_before);
assertEqual('replay after one', 1, replay.state_entry_count_after);
assertEqual('replay state delta zero', 0, replay.state_entry_count_delta);
assertEqual('replay consumed grant count stays one', 1, replay.consumed_authority_grant_count);
assertEqual('replay consumed store exists', true, replay.consumed_store_exists_after);
assertEqual('replay consumed store anchor exists', true, replay.consumed_store_anchor_exists_after);

const restartReplay = proofCase(report, 'replay_runtime_write_refused_after_service_restart');
assertEqual('restart replay refused', false, restartReplay.service_write_accepted);
assertEqual('restart replay separate service process', true, restartReplay.separate_process_from_accepted);
assertEqual('restart replay service process two', 2, restartReplay.service_process_invocation);
assertEqual('restart replay first request in process', 1, restartReplay.request_ordinal);
assertEqual('restart replay before zero', 0, restartReplay.state_entry_count_before);
assertEqual('restart replay after zero', 0, restartReplay.state_entry_count_after);
assertEqual('restart replay state delta zero', 0, restartReplay.state_entry_count_delta);
assertEqual('restart replay consumed grant count one', 1, restartReplay.consumed_authority_grant_count);
assertEqual('restart replay consumed store exists', true, restartReplay.consumed_store_exists_after);
assertEqual('restart replay consumed store anchor exists', true, restartReplay.consumed_store_anchor_exists_after);

const invalidStore = proofCase(report, 'invalid_consumed_store_refused_before_runtime_mutation');
assertEqual('invalid consumed store refused', false, invalidStore.service_write_accepted);
assertEqual('invalid consumed store reason', 'consumed_store_invalid', invalidStore.reason_code);
assertEqual('invalid consumed store state delta zero', 0, invalidStore.state_entry_count_delta);
assertEqual('invalid consumed store count zero', 0, invalidStore.consumed_authority_grant_count);

const duplicateStore = proofCase(report, 'duplicate_consumed_store_refused_before_runtime_mutation');
assertEqual('duplicate consumed store refused', false, duplicateStore.service_write_accepted);
assertEqual('duplicate consumed store reason', 'consumed_store_invalid', duplicateStore.reason_code);
assertEqual('duplicate consumed store state delta zero', 0, duplicateStore.state_entry_count_delta);
assertEqual('duplicate consumed store count zero', 0, duplicateStore.consumed_authority_grant_count);

const lockedStore = proofCase(report, 'locked_consumed_store_refused_before_runtime_mutation');
assertEqual('locked consumed store refused', false, lockedStore.service_write_accepted);
assertEqual('locked consumed store reason', 'consumed_store_locked', lockedStore.reason_code);
assertEqual('locked consumed store state delta zero', 0, lockedStore.state_entry_count_delta);
assertEqual('locked consumed store count zero', 0, lockedStore.consumed_authority_grant_count);

const invalidAnchor = proofCase(report, 'invalid_consumed_store_anchor_refused_before_runtime_mutation');
assertEqual('invalid consumed store anchor refused', false, invalidAnchor.service_write_accepted);
assertEqual('invalid consumed store anchor reason', 'consumed_store_anchor_invalid', invalidAnchor.reason_code);
assertEqual('invalid consumed store anchor state delta zero', 0, invalidAnchor.state_entry_count_delta);
assertEqual('invalid consumed store anchor count zero', 0, invalidAnchor.consumed_authority_grant_count);
assertEqual('invalid consumed store anchor store exists', true, invalidAnchor.consumed_store_exists_after);
assertEqual('invalid consumed store anchor exists', true, invalidAnchor.consumed_store_anchor_exists_after);

const rollbackDetected = proofCase(report, 'valid_consumed_store_rollback_refused_before_runtime_mutation');
assertEqual('valid consumed store rollback refused', false, rollbackDetected.service_write_accepted);
assertEqual('valid consumed store rollback reason', 'consumed_store_rollback_detected', rollbackDetected.reason_code);
assertEqual('valid consumed store rollback state delta zero', 0, rollbackDetected.state_entry_count_delta);
assertEqual('valid consumed store rollback count zero', 0, rollbackDetected.consumed_authority_grant_count);
assertEqual('valid consumed store rollback store exists', true, rollbackDetected.consumed_store_exists_after);
assertEqual('valid consumed store rollback anchor exists', true, rollbackDetected.consumed_store_anchor_exists_after);

const deletionDetected = proofCase(report, 'consumed_store_deletion_refused_before_runtime_mutation');
assertEqual('consumed store deletion refused', false, deletionDetected.service_write_accepted);
assertEqual('consumed store deletion reason', 'consumed_store_rollback_detected', deletionDetected.reason_code);
assertEqual('consumed store deletion state delta zero', 0, deletionDetected.state_entry_count_delta);
assertEqual('consumed store deletion count zero', 0, deletionDetected.consumed_authority_grant_count);
assertEqual('consumed store deletion store missing', false, deletionDetected.consumed_store_exists_after);
assertEqual('consumed store deletion anchor exists', true, deletionDetected.consumed_store_anchor_exists_after);

const replacementDetected = proofCase(report, 'valid_consumed_store_replacement_refused_before_runtime_mutation');
assertEqual('valid consumed store replacement refused', false, replacementDetected.service_write_accepted);
assertEqual('valid consumed store replacement reason', 'consumed_store_rollback_detected', replacementDetected.reason_code);
assertEqual('valid consumed store replacement state delta zero', 0, replacementDetected.state_entry_count_delta);
assertEqual('valid consumed store replacement reports persisted count', 1, replacementDetected.consumed_authority_grant_count);
assertEqual('valid consumed store replacement store exists', true, replacementDetected.consumed_store_exists_after);
assertEqual('valid consumed store replacement anchor exists', true, replacementDetected.consumed_store_anchor_exists_after);

const stateAppendFailure = proofCase(report, 'runtime_state_append_failed_after_consumed_store_commit');
assertEqual('state append failure refused', false, stateAppendFailure.service_write_accepted);
assertEqual('state append failure reason', 'runtime_state_append_failed_after_consumed_store_commit', stateAppendFailure.reason_code);
assertEqual('state append failure state delta zero', 0, stateAppendFailure.state_entry_count_delta);
assertEqual('state append failure consumed grant count one', 1, stateAppendFailure.consumed_authority_grant_count);
assertEqual('state append failure store exists', true, stateAppendFailure.consumed_store_exists_after);
assertEqual('state append failure anchor exists', true, stateAppendFailure.consumed_store_anchor_exists_after);

const witnessCommitFailure = proofCase(report, 'witness_commit_failed_after_authority_grant_store_commit');
assertEqual('witness commit failure refused', false, witnessCommitFailure.service_write_accepted);
assertEqual('witness commit failure reason', 'consumed_store_write_failed_after_grant_commit', witnessCommitFailure.reason_code);
assertEqual('witness commit failure changes no runtime state', 0, witnessCommitFailure.state_entry_count_delta);
assertEqual('witness commit failure reports burned grant', 1, witnessCommitFailure.consumed_authority_grant_count);

const burnedGrant = report.boundary_observations.find((item) => item.observation_id === 'preconsumed_authority_grant_without_runtime_state_refuses_reuse');
assertEqual('burned grant boundary exists', true, Boolean(burnedGrant));
assertEqual('burned grant boundary name', 'one-use-authority-grant-consumption-not-exactly-once-effect', burnedGrant.boundary);
assertEqual('burned grant refused as consumed', false, burnedGrant.service_write_accepted);
assertEqual('burned grant reason', 'authority_grant_already_consumed', burnedGrant.reason_code);
assertEqual('burned grant state delta zero', 0, burnedGrant.state_entry_count_delta);
assertEqual('burned grant consumed count one', 1, burnedGrant.consumed_authority_grant_count);

const storeAnchorWitnessJointRollback = report.boundary_observations.find((item) => item.observation_id === 'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse');
assertEqual('store anchor and witness joint rollback boundary exists', true, Boolean(storeAnchorWitnessJointRollback));
assertEqual('store anchor and witness joint rollback boundary name', 'local-store-anchor-and-witness-joint-rollback-not-detected', storeAnchorWitnessJointRollback.boundary);
assertEqual('store anchor and witness joint rollback accepted after matched rollback', true, storeAnchorWitnessJointRollback.service_write_accepted);
assertEqual('store anchor and witness joint rollback reason', 'fixture_authority_grant_effect_satisfied', storeAnchorWitnessJointRollback.reason_code);
assertEqual('store anchor and witness joint rollback state delta one', 1, storeAnchorWitnessJointRollback.state_entry_count_delta);
assertEqual('store anchor and witness joint rollback consumed grant count one', 1, storeAnchorWitnessJointRollback.consumed_authority_grant_count);

const storeAnchorRollbackRefused = proofCase(report, 'store_and_anchor_joint_rollback_refused_against_witness_before_runtime_mutation');
assertEqual('store and anchor joint rollback refused while witness ahead', false, storeAnchorRollbackRefused.service_write_accepted);
assertEqual('store and anchor joint rollback reason', 'consumed_store_rollback_detected', storeAnchorRollbackRefused.reason_code);
assertEqual('store and anchor joint rollback changes no state', 0, storeAnchorRollbackRefused.state_entry_count_delta);

const directApi = proofCase(report, 'direct_api_without_receipt_refused_before_runtime_mutation');
assertEqual('direct api without receipt refused', false, directApi.service_write_accepted);
assertEqual('direct api without receipt attempted', true, directApi.direct_api_attempted);
assertEqual('direct api without receipt state delta zero', 0, directApi.state_entry_count_delta);

const directApiWithReceipt = proofCase(report, 'direct_api_with_receipt_refused_before_runtime_mutation');
assertEqual('direct api with receipt refused', false, directApiWithReceipt.service_write_accepted);
assertEqual('direct api with receipt attempted', true, directApiWithReceipt.direct_api_attempted);
assertEqual('direct api with receipt state delta zero', 0, directApiWithReceipt.state_entry_count_delta);

const wrongRuntimeProfileId = proofCase(report, 'wrong_runtime_profile_id_refused_before_runtime_mutation');
assertEqual('wrong runtime profile id refused', false, wrongRuntimeProfileId.service_write_accepted);
assertEqual('wrong runtime profile id reason', 'agent_supplied_authority_material', wrongRuntimeProfileId.reason_code);
assertEqual('wrong runtime profile id state delta zero', 0, wrongRuntimeProfileId.state_entry_count_delta);

const authorityState = proofCase(report, 'agent_supplied_state_path_refused_before_runtime_mutation');
assertEqual('agent supplied state path refused', false, authorityState.service_write_accepted);
assertEqual('agent supplied state paths not accepted', false, authorityState.agent_supplied_state_paths_accepted);
assertEqual('agent supplied state path state delta zero', 0, authorityState.state_entry_count_delta);

const authorityConsumedPath = proofCase(report, 'agent_supplied_consumed_grants_path_refused_before_runtime_mutation');
assertEqual('agent supplied consumed path refused', false, authorityConsumedPath.service_write_accepted);
assertEqual('agent supplied consumed path state delta zero', 0, authorityConsumedPath.state_entry_count_delta);

const authorityConsumedAnchorPath = proofCase(report, 'agent_supplied_consumed_grant_store_anchor_path_refused_before_runtime_mutation');
assertEqual('agent supplied consumed anchor path refused', false, authorityConsumedAnchorPath.service_write_accepted);
assertEqual('agent supplied consumed anchor path state delta zero', 0, authorityConsumedAnchorPath.state_entry_count_delta);

const authorityFixtureMode = proofCase(report, 'agent_supplied_fixture_mode_refused_before_runtime_mutation');
assertEqual('agent supplied fixture mode refused', false, authorityFixtureMode.service_write_accepted);
assertEqual('agent supplied fixture mode state delta zero', 0, authorityFixtureMode.state_entry_count_delta);

const authorityRule = proofCase(report, 'agent_supplied_recognition_rule_refused_before_runtime_mutation');
assertEqual('agent supplied recognition rule refused', false, authorityRule.service_write_accepted);
assertEqual('agent supplied recognition rules not accepted', false, authorityRule.agent_supplied_recognition_rule_accepted);
assertEqual('agent supplied recognition rule state delta zero', 0, authorityRule.state_entry_count_delta);

const unsupportedField = proofCase(report, 'unsupported_request_field_refused_before_runtime_mutation');
assertEqual('unsupported request field refused', false, unsupportedField.service_write_accepted);
assertEqual('unsupported request field reason', 'agent_supplied_authority_material', unsupportedField.reason_code);
assertEqual('unsupported request field state delta zero', 0, unsupportedField.state_entry_count_delta);

section('open-boundary honesty');
assertEqual('process private state true', true, report.side_door_report.process_private_state);
assertEqual('state path not exposed', false, report.side_door_report.state_path_exposed_to_agent);
assertEqual('recognition rule not agent supplied', false, report.side_door_report.recognition_rule_supplied_by_agent);
assertEqual('agent supplied state path refused', true, report.side_door_report.agent_supplied_state_path_refused);
assertEqual('agent supplied recognition rule refused', true, report.side_door_report.agent_supplied_recognition_rule_refused);
assertEqual('direct api without receipt refused', true, report.side_door_report.direct_api_without_receipt_refused);
assertEqual('direct api with receipt refused', true, report.side_door_report.direct_api_with_receipt_refused);
assertEqual('wrong runtime profile id refused', true, report.side_door_report.wrong_runtime_profile_id_refused);
assertEqual('unsupported request field refused', true, report.side_door_report.unsupported_request_field_refused);
assertEqual('persistent consumed grant store present', true, report.side_door_report.persistent_consumed_authority_grant_store);
assertEqual('invalid consumed store refused present', true, report.side_door_report.invalid_consumed_store_refused);
assertEqual('invalid consumed store anchor refused present', true, report.side_door_report.invalid_consumed_store_anchor_refused);
assertEqual('duplicate consumed store refused present', true, report.side_door_report.duplicate_consumed_store_refused);
assertEqual('locked consumed store refused present', true, report.side_door_report.locked_consumed_store_refused);
assertEqual('consumed store anchor present', true, report.side_door_report.consumed_store_anchor_present);
assertEqual('consumed store witness present', true, report.side_door_report.consumed_store_witness_present);
assertEqual('multi-file store commit not claimed atomic', false, report.side_door_report.atomic_store_anchor_witness_commit);
assertEqual('partial grant commit burn window named', true, report.side_door_report.partial_grant_commit_burn_window_named);
assertEqual('partial commit missing witness observed', true, report.side_door_report.partial_commit_witness_missing_observed);
assertEqual('single-host rollback detection present', true, report.side_door_report.single_host_consumed_store_rollback_detection);
assertEqual('exactly-once effect semantics not claimed', false, report.side_door_report.exactly_once_effect_semantics);
assertEqual('burned authority grant window named', true, report.side_door_report.burned_authority_grant_window_named);
assertEqual('valid rollback detection claimed only against anchor', true, report.side_door_report.valid_store_rollback_detection);
assertEqual('valid rollback alone does not reopen replay', false, report.side_door_report.valid_store_rollback_reopens_replay);
assertEqual('store and anchor joint rollback refused while witness ahead', true, report.side_door_report.store_and_anchor_joint_rollback_refused_while_witness_ahead);
assertEqual('store anchor and witness joint rollback detection not claimed', false, report.side_door_report.store_anchor_and_witness_joint_rollback_detection);
assertEqual('store anchor and witness joint rollback reopens grant reuse named', true, report.side_door_report.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse);
assertEqual('cross-process authority grant reuse closed', true, report.side_door_report.cross_process_authority_grant_reuse_closed);
assertEqual('host process side door not closed', false, report.side_door_report.host_process_or_memory_introspection_closed);
assertEqual('host path TOCTOU side door not closed', false, report.side_door_report.host_filesystem_path_toctou_closed);
assertEqual('live records not checked', false, report.side_door_report.live_records_system_checked);
assertEqual('production service not checked', false, report.side_door_report.production_records_service_checked);
assertEqual('persistent runtime profile not installed', false, report.side_door_report.persistent_runtime_profile_installed);
assertEqual('external attestation false', false, report.side_door_report.external_attestation);
assertEqual('sovereign recognition false', false, report.side_door_report.sovereign_recognition);
assertEqual('unrouted records not checked', false, report.side_door_report.unrouted_records_paths_checked);
for (const boundary of [
  'host_process_or_memory_introspection',
  'live_records_system',
  'production_records_service',
  'exactly_once_effect_semantics',
  'store_anchor_and_witness_rollback_or_deletion',
  'store_anchor_witness_commit_atomicity',
  'host_filesystem_path_toctou',
  'anti_rollback_anchor_custody',
  'stale_lock_recovery',
  'multi_host_consumed_store_coordination',
  'production_durable_consumed_store',
  'persistent_runtime_profile_installation',
  'unrouted_records_paths',
]) {
  assert(`open boundary present: ${boundary}`, report.known_open_boundaries.includes(boundary));
}
for (const claim of NON_CLAIMS) {
  assert(`non-claim present: ${claim}`, report.non_claims.includes(claim));
}

section('safe output formatting');
const summary = formatProtectedRecordsRuntimeProfileProofSummary(report);
assert('summary title present', summary.includes('ZLAR Protected Records Runtime Profile Proof v1'));
assert('summary includes runtime environment', summary.includes('environment=local-disposable-jsonl-child-process'));
assert('summary includes consumed store lock', summary.includes('consumed_store_lock=launcher-owned-per-store-lockfile'));
assert('summary includes consumed store anchor', summary.includes('consumed_store_anchor=launcher-owned-local-store-hash-anchor'));
assert('summary includes consumed store rollback detection', summary.includes('consumed_store_rollback_detection=single-host-anchor-and-witness-match-before-mutation'));
assert('summary includes consumed store write model', summary.includes('consumed_store_write_model=per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness'));
assert('summary includes recognized authorized write', summary.includes('Recognized write: accepted=true; reason=fixture_authority_grant_effect_satisfied; state_delta=1'));
assert('summary includes runtime identity policy', summary.includes('Runtime profile identity: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('summary includes replay same process', summary.includes('Replay same service process: accepted=false; reason=receipt_replay; state_delta=0'));
assert('summary includes grant reuse after restart', summary.includes('Replay after service restart: accepted=false; reason=authority_grant_already_consumed; state_delta=0; separate_process=true'));
assert('summary includes consumed store failures', summary.includes('Consumed store failures: invalid_reason=consumed_store_invalid; duplicate_reason=consumed_store_invalid; locked_reason=consumed_store_locked; invalid_anchor_reason=consumed_store_anchor_invalid; rollback_reason=consumed_store_rollback_detected; deletion_reason=consumed_store_rollback_detected; replacement_reason=consumed_store_rollback_detected; state_delta=0'));
assert('summary includes partial grant-store commit', summary.includes('Partial grant-store commit: accepted=false; reason=consumed_store_write_failed_after_grant_commit; consumed_grant_count=1; state_delta=0; atomic_store_anchor_witness_commit=false'));
assert('summary includes burned grant boundary', summary.includes('Boundary observation: burned_authority_grant_window accepted=false; reason=authority_grant_already_consumed; state_delta=0; boundary=one-use-authority-grant-consumption-not-exactly-once-effect'));
assert('summary includes store anchor and witness rollback boundary', summary.includes('Boundary observation: store_anchor_and_witness_joint_rollback accepted=true; reason=fixture_authority_grant_effect_satisfied; state_delta=1; boundary=local-store-anchor-and-witness-joint-rollback-not-detected'));
assert('summary includes authority material refusal', summary.includes('Agent authority material refused: state_path_reason=agent_supplied_authority_material; recognition_rule_reason=agent_supplied_authority_material'));
assert('summary includes unsupported request field refusal', summary.includes('Unsupported request field refused: reason=agent_supplied_authority_material; state_delta=0'));
assert('summary includes cross-process grant reuse closure', summary.includes('cross_process_authority_grant_reuse_closed=true'));
assert('summary includes store anchor and witness rollback non-detection', summary.includes('store_anchor_and_witness_joint_rollback_detection=false'));
assert('summary includes host side-door non-closure', summary.includes('host_process_or_memory_introspection_closed=false'));
assert('summary includes host path TOCTOU non-closure', summary.includes('host_filesystem_path_toctou_closed=false'));
assert('summary output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(summary));
const jsonText = JSON.stringify(report, null, 2);
assert('json output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(jsonText));
assert('json omits raw record id', !jsonText.includes('runtime-record-001'));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonText));
assert('json omits private and temp paths', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(jsonText));

section('runtime helper import boundary');
const runtimeProfileSource = readFileSync('lib/protected-records-runtime-profile.mjs', 'utf8');
const runtimeProfileImportLines = runtimeProfileSource
  .split('\n')
  .filter((line) => line.startsWith('import '))
  .join('\n');
assert('runtime profile imports skinny helper', runtimeProfileSource.includes("from './protected-records-boarding-decision.mjs'"));
assert('runtime profile calls skinny helper', runtimeProfileSource.includes('evaluateProtectedRecordsBoardingDecision({'));
assert('runtime profile uses candidate helper state', runtimeProfileSource.includes('candidateHelperState()'));
assert('runtime profile no longer imports downstream recognition directly', !runtimeProfileImportLines.includes('./downstream-recognition-rule.mjs'));
for (const forbiddenImport of [
  'local-proof-pack',
  'proof-smoke',
  'product-proof-path',
  'Product Proof Path',
  'github',
  'GitHub',
  'release.json',
  'ZLAR_Website',
  'CURRENT-STATE',
]) {
  assert(`runtime hot path import excludes ${forbiddenImport}`, !runtimeProfileImportLines.includes(forbiddenImport));
}

section('fail closed validation');
const liveProbeClaim = structuredClone(report);
liveProbeClaim.live_probing = true;
assertThrows('live probing claim fails', () => assertProtectedRecordsRuntimeProfileProof(liveProbeClaim), 'top-level contract drifted');

const wrongServiceCommand = structuredClone(report);
wrongServiceCommand.runtime_profile.service_command = 'zlar protected-records-runtime-service --latest';
assertThrows('wrong service command fails', () => assertProtectedRecordsRuntimeProfileProof(wrongServiceCommand), 'profile drifted');

const statePathExposed = structuredClone(report);
statePathExposed.runtime_profile.state_path_exposed_to_agent = true;
assertThrows('state path exposed claim fails', () => assertProtectedRecordsRuntimeProfileProof(statePathExposed), 'profile drifted');

const acceptedDoesNotMutate = structuredClone(report);
proofCase(acceptedDoesNotMutate, 'recognized_runtime_write_first_request').state_entry_count_delta = 0;
proofCase(acceptedDoesNotMutate, 'recognized_runtime_write_first_request').state_entry_count_after = 0;
assertThrows('accepted no mutation fails', () => assertProtectedRecordsRuntimeProfileProof(acceptedDoesNotMutate), 'accepted case failed');

const replayMutates = structuredClone(report);
proofCase(replayMutates, 'replay_runtime_write_refused_same_service_process').state_entry_count_delta = 1;
proofCase(replayMutates, 'replay_runtime_write_refused_same_service_process').state_entry_count_after = 2;
assertThrows('replay mutation fails', () => assertProtectedRecordsRuntimeProfileProof(replayMutates), 'replay case failed');

const directApiBoards = structuredClone(report);
proofCase(directApiBoards, 'direct_api_with_receipt_refused_before_runtime_mutation').service_write_accepted = true;
assertThrows('direct api boarding fails', () => assertProtectedRecordsRuntimeProfileProof(directApiBoards), 'refusal case changed state');

const wrongRuntimeProfileBoards = structuredClone(report);
proofCase(wrongRuntimeProfileBoards, 'wrong_runtime_profile_id_refused_before_runtime_mutation').state_entry_count_delta = 1;
proofCase(wrongRuntimeProfileBoards, 'wrong_runtime_profile_id_refused_before_runtime_mutation').state_entry_count_after =
  proofCase(wrongRuntimeProfileBoards, 'wrong_runtime_profile_id_refused_before_runtime_mutation').state_entry_count_before + 1;
assertThrows('wrong runtime profile id mutation fails', () => assertProtectedRecordsRuntimeProfileProof(wrongRuntimeProfileBoards), 'refusal case changed state');

const runtimeProfileIdentityPolicyDrift = structuredClone(report);
runtimeProfileIdentityPolicyDrift.runtime_profile_identity_policy.omitted_runtime_profile_id_uses_launcher_config = false;
assertThrows('runtime profile identity policy drift fails', () => assertProtectedRecordsRuntimeProfileProof(runtimeProfileIdentityPolicyDrift), 'identity policy drifted');

const hostSideDoorClosedClaim = structuredClone(report);
hostSideDoorClosedClaim.side_door_report.host_process_or_memory_introspection_closed = true;
assertThrows('host process closure claim fails', () => assertProtectedRecordsRuntimeProfileProof(hostSideDoorClosedClaim), 'side-door report drifted');

const productionClaim = structuredClone(report);
productionClaim.side_door_report.production_records_service_checked = true;
assertThrows('production service check claim fails', () => assertProtectedRecordsRuntimeProfileProof(productionClaim), 'side-door report drifted');

const missingOpenBoundary = structuredClone(report);
missingOpenBoundary.known_open_boundaries = missingOpenBoundary.known_open_boundaries.filter((item) => item !== 'production_records_service');
assertThrows('missing open boundary fails', () => assertProtectedRecordsRuntimeProfileProof(missingOpenBoundary), 'open boundaries');

const missingCase = structuredClone(report);
missingCase.cases = missingCase.cases.filter((item) => item.case_id !== 'agent_supplied_recognition_rule_refused_before_runtime_mutation');
assertThrows('missing authority case fails', () => assertProtectedRecordsRuntimeProfileProof(missingCase), 'case count drifted');

const anchorDropped = structuredClone(report);
anchorDropped.runtime_profile.consumed_store_anchor = 'none';
assertThrows('missing consumed store anchor claim fails', () => assertProtectedRecordsRuntimeProfileProof(anchorDropped), 'profile drifted');

const unsupportedFieldClaim = structuredClone(report);
unsupportedFieldClaim.side_door_report.unsupported_request_field_refused = false;
assertThrows('unsupported request field claim fails', () => assertProtectedRecordsRuntimeProfileProof(unsupportedFieldClaim), 'side-door report drifted');

const crossProcessGrantReuseReopenedClaim = structuredClone(report);
crossProcessGrantReuseReopenedClaim.side_door_report.cross_process_authority_grant_reuse_closed = false;
assertThrows('cross-process grant reuse reopened claim fails', () => assertProtectedRecordsRuntimeProfileProof(crossProcessGrantReuseReopenedClaim), 'side-door report drifted');

const missingConsumedStoreCase = structuredClone(report);
missingConsumedStoreCase.cases = missingConsumedStoreCase.cases.filter((item) => item.case_id !== 'locked_consumed_store_refused_before_runtime_mutation');
assertThrows('missing consumed store case fails', () => assertProtectedRecordsRuntimeProfileProof(missingConsumedStoreCase), 'case count drifted');

const invalidStoreMutates = structuredClone(report);
proofCase(invalidStoreMutates, 'invalid_consumed_store_refused_before_runtime_mutation').state_entry_count_delta = 1;
proofCase(invalidStoreMutates, 'invalid_consumed_store_refused_before_runtime_mutation').state_entry_count_after = 1;
assertThrows('invalid consumed store mutation fails', () => assertProtectedRecordsRuntimeProfileProof(invalidStoreMutates), 'consumed-store refusal cases drifted');

const invalidAnchorMutates = structuredClone(report);
proofCase(invalidAnchorMutates, 'invalid_consumed_store_anchor_refused_before_runtime_mutation').state_entry_count_delta = 1;
proofCase(invalidAnchorMutates, 'invalid_consumed_store_anchor_refused_before_runtime_mutation').state_entry_count_after = 1;
assertThrows('invalid consumed store anchor mutation fails', () => assertProtectedRecordsRuntimeProfileProof(invalidAnchorMutates), 'consumed-store refusal cases drifted');

const rollbackStoreMutates = structuredClone(report);
proofCase(rollbackStoreMutates, 'valid_consumed_store_rollback_refused_before_runtime_mutation').state_entry_count_delta = 1;
proofCase(rollbackStoreMutates, 'valid_consumed_store_rollback_refused_before_runtime_mutation').state_entry_count_after = 1;
assertThrows('rollback consumed store mutation fails', () => assertProtectedRecordsRuntimeProfileProof(rollbackStoreMutates), 'consumed-store refusal cases drifted');

const stateAppendFailureBoards = structuredClone(report);
proofCase(stateAppendFailureBoards, 'runtime_state_append_failed_after_consumed_store_commit').service_write_accepted = true;
assertThrows('state append failure boarding fails', () => assertProtectedRecordsRuntimeProfileProof(stateAppendFailureBoards), 'state append failure boundary drifted');

const stateAppendFailureMutates = structuredClone(report);
proofCase(stateAppendFailureMutates, 'runtime_state_append_failed_after_consumed_store_commit').state_entry_count_delta = 1;
proofCase(stateAppendFailureMutates, 'runtime_state_append_failed_after_consumed_store_commit').state_entry_count_after = 1;
assertThrows('state append failure mutation fails', () => assertProtectedRecordsRuntimeProfileProof(stateAppendFailureMutates), 'state append failure boundary drifted');

const missingBoundaryObservation = structuredClone(report);
missingBoundaryObservation.boundary_observations = missingBoundaryObservation.boundary_observations.filter((item) => item.observation_id !== 'store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse');
assertThrows('missing boundary observation fails', () => assertProtectedRecordsRuntimeProfileProof(missingBoundaryObservation), 'boundary observation count drifted');

const rollbackDetectionHiddenClaim = structuredClone(report);
rollbackDetectionHiddenClaim.side_door_report.valid_store_rollback_detection = false;
assertThrows('rollback detection hidden claim fails', () => assertProtectedRecordsRuntimeProfileProof(rollbackDetectionHiddenClaim), 'side-door report drifted');

const storeAnchorWitnessRollbackClosedClaim = structuredClone(report);
storeAnchorWitnessRollbackClosedClaim.side_door_report.store_anchor_and_witness_joint_rollback_detection = true;
assertThrows('store anchor and witness rollback closure claim fails', () => assertProtectedRecordsRuntimeProfileProof(storeAnchorWitnessRollbackClosedClaim), 'side-door report drifted');

section('launcher target binding snapshot and coherent wrong-target receipt');
const targetSnapshotScratch = mkdtempSync(join(tmpdir(), 'zlar-target-binding-snapshot-'));
try {
  const nowEpoch = PROTECTED_RECORDS_FIXTURE_AUTHORITY_EVALUATION_EPOCH;
  const recordUpdate = {
    ...PROTECTED_RECORDS_FIXTURE_AUTHORIZED_RECORD_UPDATE,
  };
  const wrongTargetHandle = `zlar-target:v1:logical-fixture:${'f'.repeat(64)}`;
  const { publicKey: publicPem, privateKey: privatePem } = generateKeyPairSync(
    'ed25519',
    {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    }
  );
  const kid = createHash('sha256').update(publicPem).digest('hex').slice(0, 16);
  const mutableTargetBinding = createProtectedRecordsRuntimeTargetBinding();
  const recognitionRule = {
    deployment_scope: 'protected-records-disposable-runtime-profile',
    accepted_issuers: [{ kid, public_key_pem: publicPem, status: 'active' }],
    accepted_policy_versions: ['recognition-policy-v1'],
    accepted_domains: ['records'],
    accepted_tools: ['records.write'],
    accepted_outcomes: ['allow', 'authorized'],
    max_age_seconds: 120,
    required_audit_event_id: 'target-snapshot-wrong-target-receipt',
  };
  const scopeEvidence = createProtectedRecordsRuntimeLauncherScopeEvidence({
    actionClass: 'records.write',
    authorizedRecordUpdate: recordUpdate,
    profileId: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    recognitionRuleSnapshot: recognitionRule,
    targetBinding: mutableTargetBinding,
  });
  const authorityGrantContract = createProtectedRecordsRuntimeFixtureAuthorityGrantContract({
    scopeEvidence,
    validFromEpoch: nowEpoch - 30,
    expiresAtEpoch: nowEpoch + 120,
  });
  const authorityGrantAppointment = createProtectedRecordsFixtureAuthorityGrantAppointment({
    contract: authorityGrantContract,
    granteeIssuerKid: kid,
    granteePublicKeySha256: createHash('sha256').update(publicPem).digest('hex'),
  });
  const authorizedEffectDetail = protectedRecordsAuthorizedEffectDetail({
    contract: authorityGrantContract,
    targetEffect: protectedRecordsTargetEffect({
      targetHandle: PROTECTED_RECORDS_TARGET_HANDLE,
      recordUpdate,
    }),
  });
  const issuanceEnvelope = createReceiptV1FromEvent({
    id: 'target-snapshot-wrong-target-receipt',
    ts: new Date((nowEpoch - 5) * 1000).toISOString(),
    action: 'records.write',
    domain: 'records',
    detail: authorizedEffectDetail,
    outcome: 'allow',
    rule: 'RRECORDS_ALLOW',
    authorizer: 'policy',
    policy_version: 'recognition-policy-v1',
    prev_hash: '0'.repeat(64),
  });
  const issuancePayload = decodePayloadV1(issuanceEnvelope);
  const authorityGrantIssuanceDecision = evaluateProtectedRecordsFixtureAuthorityGrantIssuance({
    contract: authorityGrantContract,
    appointment: authorityGrantAppointment,
    scopeEvidence,
    receiptEvidence: createProtectedRecordsRuntimeAuthorityReceiptEvidence({
      envelope: issuanceEnvelope,
      issuerKid: kid,
      issuerStatus: null,
      payload: issuancePayload,
      publicKeySha256: createHash('sha256').update(publicPem).digest('hex'),
      source: 'unsigned-receipt-payload-before-signing',
      signatureVerified: false,
      downstreamRecognitionAccepted: false,
      verifiedSignedPayloadSha256: null,
    }),
    authorizedEffectDetail,
    evaluationEpoch: nowEpoch - 5,
    grantPreviouslyConsumed: false,
  });
  const serviceConfig = {
    profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    action_class: 'records.write',
    now_epoch: nowEpoch,
    authorized_record_update: recordUpdate,
    authority_grant_appointment: authorityGrantAppointment,
    authority_grant_contract: authorityGrantContract,
    authority_grant_issuance_decision: authorityGrantIssuanceDecision,
    consumed_grants_path: join(targetSnapshotScratch, 'consumed.json'),
    consumed_grant_store_anchor_path: join(targetSnapshotScratch, 'anchor.json'),
    consumed_grant_store_witness_path: join(targetSnapshotScratch, 'witness.json'),
    recognition_rule: recognitionRule,
    target_binding: mutableTargetBinding,
  };
  const legacyReceiptStoreConfig = {
    ...serviceConfig,
    consumed_receipts_path: serviceConfig.consumed_grants_path,
  };
  delete legacyReceiptStoreConfig.consumed_grants_path;
  assertThrows(
    'legacy receipt-store config fails closed',
    () => createProtectedRecordsRuntimeService(legacyReceiptStoreConfig),
    'contains unexpected fields'
  );
  const missingWitnessConfig = { ...serviceConfig };
  delete missingWitnessConfig.consumed_grant_store_witness_path;
  assertThrows(
    'launcher grant-store witness path is required',
    () => createProtectedRecordsRuntimeService(missingWitnessConfig),
    'contains unexpected fields'
  );
  assertThrows(
    'grant store and witness path alias fails closed',
    () => createProtectedRecordsRuntimeService({
      ...serviceConfig,
      consumed_grant_store_witness_path: serviceConfig.consumed_grants_path,
    }),
    'must be distinct'
  );
  const accessorConfig = { ...serviceConfig };
  Object.defineProperty(accessorConfig, 'authority_grant_contract', {
    enumerable: true,
    get() {
      return serviceConfig.authority_grant_contract;
    },
  });
  assertThrows(
    'launcher config accessor fails before validation',
    () => createProtectedRecordsRuntimeService(accessorConfig),
    'not an enumerable data value'
  );
  const service = createProtectedRecordsRuntimeService(serviceConfig);
  const wrongTargetReceipt = signReceiptV1(
    createReceiptV1FromEvent({
      id: 'target-snapshot-wrong-target-receipt',
      ts: new Date((nowEpoch - 5) * 1000).toISOString(),
      action: 'records.write',
      domain: 'records',
      detail: protectedRecordsTargetEffect({
        targetHandle: wrongTargetHandle,
        recordUpdate,
      }),
      outcome: 'allow',
      rule: 'RRECORDS_ALLOW',
      authorizer: 'policy',
      policy_version: 'recognition-policy-v1',
      prev_hash: '0'.repeat(64),
    }),
    privatePem,
    kid
  );
  let nestedReceiptAccessorReads = 0;
  const accessorReceipt = { ...wrongTargetReceipt };
  Object.defineProperty(accessorReceipt, 'payload', {
    enumerable: true,
    get() {
      nestedReceiptAccessorReads += 1;
      return wrongTargetReceipt.payload;
    },
  });
  const accessorReceiptResult = service.applyRequest({
    runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    receipt: accessorReceipt,
    record_update: recordUpdate,
    request_mode: 'nested_receipt_accessor_attack',
    target_handle: PROTECTED_RECORDS_TARGET_HANDLE,
  });
  assert('nested receipt accessor result validates', assertProtectedRecordsRuntimeServiceResult(accessorReceiptResult));
  assertEqual('nested receipt accessor refused before recognition', 'agent_supplied_authority_material', accessorReceiptResult.decision.reason_code);
  assertEqual('nested receipt accessor never invoked', 0, nestedReceiptAccessorReads);
  assertEqual('nested receipt accessor consumes no grant', 0, accessorReceiptResult.consumed_authority_grant_count);
  const getterMutationRequest = {
    runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    receipt: wrongTargetReceipt,
    record_update: recordUpdate,
    request_mode: 'mutable_target_binding_getter_attack',
  };
  Object.defineProperty(getterMutationRequest, 'target_handle', {
    enumerable: true,
    get() {
      mutableTargetBinding.target_handle = wrongTargetHandle;
      return wrongTargetHandle;
    },
  });
  const getterMutationResult = service.applyRequest(getterMutationRequest);
  assert('getter mutation result validates', assertProtectedRecordsRuntimeServiceResult(getterMutationResult));
  assertEqual('getter mutation is refused before recognition', 'agent_supplied_authority_material', getterMutationResult.decision.reason_code);
  assertEqual('getter mutation consumes no grant', 0, getterMutationResult.consumed_authority_grant_count);
  assertEqual('getter mutation changes no state', 0, getterMutationResult.state_entry_count_delta);
  assertEqual('service retains configured target snapshot', PROTECTED_RECORDS_TARGET_HANDLE, getterMutationResult.target_handle);

  const coherentWrongTargetResult = service.applyRequest({
    runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    receipt: wrongTargetReceipt,
    record_update: recordUpdate,
    request_mode: 'coherent_wrong_target_receipt',
    target_handle: PROTECTED_RECORDS_TARGET_HANDLE,
  });
  assert('coherent wrong-target result validates', assertProtectedRecordsRuntimeServiceResult(coherentWrongTargetResult));
  assert(
    'coherent wrong-target receipt refuses at detail binding',
    coherentWrongTargetResult.decision.reason_code === 'detail_hash_mismatch',
    JSON.stringify(coherentWrongTargetResult.decision)
  );
  assertEqual('coherent wrong-target grant remains unconsumed', 0, coherentWrongTargetResult.consumed_authority_grant_count);
  assertEqual('coherent wrong-target receipt changes no state', 0, coherentWrongTargetResult.state_entry_count_delta);
} finally {
  rmSync(targetSnapshotScratch, { recursive: true, force: true });
}

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
