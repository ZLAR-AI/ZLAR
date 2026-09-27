#!/usr/bin/env node

import { createHash, generateKeyPairSync } from 'node:crypto';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  PROTECTED_RECORDS_TARGET_HANDLE,
  REQUIRED_RUNTIME_PROFILE_CASES,
  assertProtectedRecordsRuntimeProfileProof,
  assertProtectedRecordsRuntimeServiceResult,
  createProtectedRecordsRuntimeAuthorityReceiptEvidence,
  createProtectedRecordsRuntimeFixtureAuthorityGrantContract,
  createProtectedRecordsRuntimeLauncherScopeEvidence,
  createProtectedRecordsRuntimeTargetBinding,
  protectedRecordsTargetEffect,
} from '../lib/protected-records-runtime-profile.mjs';
import {
  createReceiptV1FromEvent,
  decodePayloadV1,
  pubkeyFingerprint,
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

function section(title) {
  console.log(`\n-- ${title} --`);
}

const ZLAR_BIN = join(process.cwd(), 'bin', 'zlar');
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;
const scratch = mkdtempSync(join(tmpdir(), 'zlar-protected-records-runtime-profile-cli-'));

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

function keyFixture() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  const publicPath = join(scratch, 'trusted.pub');
  writeFileSync(publicPath, publicPem);
  return {
    privatePem,
    publicPem,
    kid: pubkeyFingerprint(publicPath),
  };
}

function isoSecondsAgo(nowEpoch, seconds) {
  return new Date((nowEpoch - seconds) * 1000).toISOString();
}

function runtimeFixture() {
  const key = keyFixture();
  const nowEpoch = PROTECTED_RECORDS_FIXTURE_AUTHORITY_EVALUATION_EPOCH;
  const recordUpdate = {
    ...PROTECTED_RECORDS_FIXTURE_AUTHORIZED_RECORD_UPDATE,
  };
  const targetBinding = createProtectedRecordsRuntimeTargetBinding();
  const recognitionRule = {
    deployment_scope: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    accepted_issuers: [
      {
        kid: key.kid,
        public_key_pem: key.publicPem,
        status: 'active',
      },
    ],
    accepted_policy_versions: ['recognition-policy-v1'],
    accepted_domains: ['records'],
    accepted_tools: ['records.write'],
    accepted_outcomes: ['allow', 'authorized'],
    max_age_seconds: 120,
    required_audit_event_id: 'runtime-cli-event-001',
  };
  const scopeEvidence = createProtectedRecordsRuntimeLauncherScopeEvidence({
    actionClass: 'records.write',
    authorizedRecordUpdate: recordUpdate,
    profileId: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    recognitionRuleSnapshot: recognitionRule,
    targetBinding,
  });
  const authorityGrantContract = createProtectedRecordsRuntimeFixtureAuthorityGrantContract({
    scopeEvidence,
    validFromEpoch: nowEpoch - 30,
    expiresAtEpoch: nowEpoch + 120,
  });
  const publicKeySha256 = createHash('sha256').update(key.publicPem).digest('hex');
  const authorityGrantAppointment = createProtectedRecordsFixtureAuthorityGrantAppointment({
    contract: authorityGrantContract,
    granteeIssuerKid: key.kid,
    granteePublicKeySha256: publicKeySha256,
  });
  const authorizedEffectDetail = protectedRecordsAuthorizedEffectDetail({
    contract: authorityGrantContract,
    targetEffect: protectedRecordsTargetEffect({
      targetHandle: PROTECTED_RECORDS_TARGET_HANDLE,
      recordUpdate,
    }),
  });
  const event = {
    id: 'runtime-cli-event-001',
    ts: isoSecondsAgo(nowEpoch, 5),
    action: 'records.write',
    domain: 'records',
    detail: authorizedEffectDetail,
    outcome: 'allow',
    rule: 'RRECORDS_ALLOW',
    authorizer: 'policy',
    policy_version: 'recognition-policy-v1',
    prev_hash: '0'.repeat(64),
  };
  const unsignedReceipt = createReceiptV1FromEvent(event);
  const issuancePayload = decodePayloadV1(unsignedReceipt);
  const authorityGrantIssuanceDecision = evaluateProtectedRecordsFixtureAuthorityGrantIssuance({
    contract: authorityGrantContract,
    appointment: authorityGrantAppointment,
    scopeEvidence,
    receiptEvidence: createProtectedRecordsRuntimeAuthorityReceiptEvidence({
      envelope: unsignedReceipt,
      issuerKid: key.kid,
      issuerStatus: null,
      payload: issuancePayload,
      publicKeySha256,
      source: 'unsigned-receipt-payload-before-signing',
      signatureVerified: false,
      downstreamRecognitionAccepted: false,
      verifiedSignedPayloadSha256: null,
    }),
    authorizedEffectDetail,
    evaluationEpoch: nowEpoch - 5,
    grantPreviouslyConsumed: false,
  });
  const receipt = signReceiptV1(unsignedReceipt, key.privatePem, key.kid);
  const config = {
    profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    action_class: 'records.write',
    now_epoch: nowEpoch,
    authorized_record_update: recordUpdate,
    authority_grant_appointment: authorityGrantAppointment,
    authority_grant_contract: authorityGrantContract,
    authority_grant_issuance_decision: authorityGrantIssuanceDecision,
    consumed_grants_path: join(scratch, 'runtime-cli-consumed-grants.json'),
    consumed_grant_store_anchor_path: join(scratch, 'runtime-cli-consumed-grants.anchor.json'),
    consumed_grant_store_witness_path: join(scratch, 'runtime-cli-consumed-grants.witness.json'),
    recognition_rule: recognitionRule,
    target_binding: targetBinding,
  };
  return { config, receipt, recordUpdate };
}

try {
  section('text proof command');
  const textRun = runZlar(['protected-records-runtime-profile-proof']);
  assertEqual('text command exits zero', 0, textRun.status);
  assertEqual('text command emits no stderr', '', textRun.stderr);
  assert('text summary title present', textRun.stdout.includes('ZLAR Protected Records Runtime Profile Proof v1'));
  assert('text summary states disposable model', textRun.stdout.includes('Evidence model: local-disposable-runtime-process-profile; live probing=false'));
  assert('text summary includes process-private state', textRun.stdout.includes('state_storage=process-private-memory'));
  assert('text summary includes persistent consumed grant store', textRun.stdout.includes('consumed_authority_grant_store=persistent-single-use-authority-grant-contract-sha256-store'));
  assert('text summary includes consumed store lock', textRun.stdout.includes('consumed_store_lock=launcher-owned-per-store-lockfile'));
  assert('text summary includes consumed store anchor', textRun.stdout.includes('consumed_store_anchor=launcher-owned-local-store-hash-anchor'));
  assert('text summary includes consumed store witness', textRun.stdout.includes('consumed_store_witness=launcher-owned-local-store-hash-witness'));
  assert('text summary includes consumed store rollback detection', textRun.stdout.includes('consumed_store_rollback_detection=single-host-anchor-and-witness-match-before-mutation'));
  assert('text summary includes consumed store write model', textRun.stdout.includes('consumed_store_write_model=per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness'));
  assert('text summary includes recognized authorized write', textRun.stdout.includes('Recognized write: accepted=true; reason=fixture_authority_grant_effect_satisfied; state_delta=1'));
  assert('text summary includes replay same process', textRun.stdout.includes('Replay same service process: accepted=false; reason=receipt_replay; state_delta=0'));
  assert('text summary includes grant reuse after restart', textRun.stdout.includes('Replay after service restart: accepted=false; reason=authority_grant_already_consumed; state_delta=0; separate_process=true'));
  assert('text summary includes consumed store failures', textRun.stdout.includes('Consumed store failures: invalid_reason=consumed_store_invalid; duplicate_reason=consumed_store_invalid; locked_reason=consumed_store_locked; invalid_anchor_reason=consumed_store_anchor_invalid; rollback_reason=consumed_store_rollback_detected; deletion_reason=consumed_store_rollback_detected; replacement_reason=consumed_store_rollback_detected; state_delta=0'));
  assert('text summary includes partial grant commit boundary', textRun.stdout.includes('Partial grant-store commit: accepted=false; reason=consumed_store_write_failed_after_grant_commit; consumed_grant_count=1; state_delta=0; atomic_store_anchor_witness_commit=false'));
  assert('text summary includes burned grant boundary', textRun.stdout.includes('Boundary observation: burned_authority_grant_window accepted=false; reason=authority_grant_already_consumed; state_delta=0; boundary=one-use-authority-grant-consumption-not-exactly-once-effect'));
  assert('text summary includes store anchor and witness joint rollback boundary', textRun.stdout.includes('Boundary observation: store_anchor_and_witness_joint_rollback accepted=true; reason=fixture_authority_grant_effect_satisfied; state_delta=1; boundary=local-store-anchor-and-witness-joint-rollback-not-detected'));
  assert('text summary includes authority material refusal', textRun.stdout.includes('Agent authority material refused: state_path_reason=agent_supplied_authority_material; recognition_rule_reason=agent_supplied_authority_material'));
  assert('text summary includes unsupported request field refusal', textRun.stdout.includes('Unsupported request field refused: reason=agent_supplied_authority_material; state_delta=0'));
  assert('text summary includes cross-process grant reuse closure', textRun.stdout.includes('cross_process_authority_grant_reuse_closed=true'));
  assert('text summary includes host side-door boundary', textRun.stdout.includes('host_process_or_memory_introspection_closed=false'));
  assert('text summary names open boundaries', textRun.stdout.includes('Known open boundaries: host_process_or_memory_introspection,live_records_system,production_records_service,exactly_once_effect_semantics,store_anchor_and_witness_rollback_or_deletion,store_anchor_witness_commit_atomicity,host_filesystem_path_toctou,anti_rollback_anchor_custody,stale_lock_recovery,multi_host_consumed_store_coordination,production_durable_consumed_store,persistent_runtime_profile_installation,unrouted_records_paths'));
  assert('text summary is privacy safe', !unsafeOutputPattern.test(textRun.stdout));

  section('json proof command');
  const jsonRun = runZlar(['protected-records-runtime-profile-proof', '--json']);
  assertEqual('json command exits zero', 0, jsonRun.status);
  assertEqual('json command emits no stderr', '', jsonRun.stderr);
  assert('json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
  const report = JSON.parse(jsonRun.stdout);
  assert('json report passes validation', assertProtectedRecordsRuntimeProfileProof(report));
  assertEqual('json proof type', 'protected-records-runtime-profile-proof-v1', report.proof_type);
  assertEqual('json live probing false', false, report.live_probing);
  assertEqual('json evidence model', 'local-disposable-runtime-process-profile', report.evidence_model);
  assertEqual('json case count', REQUIRED_RUNTIME_PROFILE_CASES.length, report.cases.length);
  assert('json includes runtime service command', jsonRun.stdout.includes('"service_command": "zlar protected-records-runtime-service --config <file>"'));
  assert('json includes tightened request contract', jsonRun.stdout.includes('"request_contract": "receipt-record-update-and-routing-metadata-only"'));
  assert('json includes consumed store lock', jsonRun.stdout.includes('"consumed_store_lock": "launcher-owned-per-store-lockfile"'));
  assert('json includes consumed store anchor', jsonRun.stdout.includes('"consumed_store_anchor": "launcher-owned-local-store-hash-anchor"'));
  assert('json includes consumed store witness', jsonRun.stdout.includes('"consumed_store_witness": "launcher-owned-local-store-hash-witness"'));
  assert('json includes consumed store rollback detection', jsonRun.stdout.includes('"consumed_store_rollback_detection": "single-host-anchor-and-witness-match-before-mutation"'));
  assert('json includes consumed grant store validation', jsonRun.stdout.includes('"consumed_store_validation": "exact-schema-unique-grant-contract-sha256s"'));
  assert('json includes consumed store write model', jsonRun.stdout.includes('"consumed_store_write_model": "per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness"'));
  assert('json includes boundary observations', jsonRun.stdout.includes('"boundary_observations"'));
  assert('json includes burned grant boundary', jsonRun.stdout.includes('"observation_id": "preconsumed_authority_grant_without_runtime_state_refuses_reuse"'));
  assert('json includes store anchor and witness joint rollback boundary', jsonRun.stdout.includes('"observation_id": "store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse"'));
  assert('json includes exactly-once non-claim flag', jsonRun.stdout.includes('"exactly_once_effect_semantics": false'));
  assert('json includes single-host rollback detection flag', jsonRun.stdout.includes('"valid_store_rollback_detection": true'));
  assert('json includes store and anchor joint rollback refusal against witness', jsonRun.stdout.includes('"store_and_anchor_joint_rollback_refused_while_witness_ahead": true'));
  assert('json includes store anchor and witness joint rollback non-detection flag', jsonRun.stdout.includes('"store_anchor_and_witness_joint_rollback_detection": false'));
  assert('json includes same-process replay case', jsonRun.stdout.includes('"case_id": "replay_runtime_write_refused_same_service_process"'));
  assert('json includes restart replay case', jsonRun.stdout.includes('"case_id": "replay_runtime_write_refused_after_service_restart"'));
  assert('json includes invalid store case', jsonRun.stdout.includes('"case_id": "invalid_consumed_store_refused_before_runtime_mutation"'));
  assert('json includes duplicate store case', jsonRun.stdout.includes('"case_id": "duplicate_consumed_store_refused_before_runtime_mutation"'));
  assert('json includes locked store case', jsonRun.stdout.includes('"case_id": "locked_consumed_store_refused_before_runtime_mutation"'));
  assert('json includes invalid anchor case', jsonRun.stdout.includes('"case_id": "invalid_consumed_store_anchor_refused_before_runtime_mutation"'));
  assert('json includes rollback store case', jsonRun.stdout.includes('"case_id": "valid_consumed_store_rollback_refused_before_runtime_mutation"'));
  assert('json includes deletion store case', jsonRun.stdout.includes('"case_id": "consumed_store_deletion_refused_before_runtime_mutation"'));
  assert('json includes replacement store case', jsonRun.stdout.includes('"case_id": "valid_consumed_store_replacement_refused_before_runtime_mutation"'));
  assert('json includes store and anchor rollback witness refusal case', jsonRun.stdout.includes('"case_id": "store_and_anchor_joint_rollback_refused_against_witness_before_runtime_mutation"'));
  assert('json includes partial grant-store commit case', jsonRun.stdout.includes('"case_id": "witness_commit_failed_after_authority_grant_store_commit"'));
  assert('json names non-atomic multi-file commit', jsonRun.stdout.includes('"atomic_store_anchor_witness_commit": false'));
  assert('json names host path TOCTOU boundary', jsonRun.stdout.includes('"host_filesystem_path_toctou_closed": false'));
  assert('json includes wrong runtime profile id case', jsonRun.stdout.includes('"case_id": "wrong_runtime_profile_id_refused_before_runtime_mutation"'));
  assert('json includes agent-supplied state refusal', jsonRun.stdout.includes('"case_id": "agent_supplied_state_path_refused_before_runtime_mutation"'));
  assert('json includes agent-supplied consumed grant path refusal', jsonRun.stdout.includes('"case_id": "agent_supplied_consumed_grants_path_refused_before_runtime_mutation"'));
  assert('json includes agent-supplied consumed grant anchor path refusal', jsonRun.stdout.includes('"case_id": "agent_supplied_consumed_grant_store_anchor_path_refused_before_runtime_mutation"'));
  assert('json includes agent-supplied fixture mode refusal', jsonRun.stdout.includes('"case_id": "agent_supplied_fixture_mode_refused_before_runtime_mutation"'));
  assert('json includes unsupported request field refusal', jsonRun.stdout.includes('"case_id": "unsupported_request_field_refused_before_runtime_mutation"'));
  assert('json includes authority material reason', jsonRun.stdout.includes('"reason_code": "agent_supplied_authority_material"'));
  assert('json includes missing authority grant case', jsonRun.stdout.includes('"case_id": "missing_authority_grant_appointment_refused_before_consumption"'));
  assert('json includes mismatched authority grant case', jsonRun.stdout.includes('"case_id": "mismatched_authority_grant_appointment_refused_before_consumption"'));
  assert('json includes revoked authority grant case', jsonRun.stdout.includes('"case_id": "revoked_authority_grant_refused_before_consumption"'));
  assert('json includes expired authority grant case', jsonRun.stdout.includes('"case_id": "expired_authority_grant_refused_before_consumption"'));
  assert('json includes agent-supplied authority grant refusal', jsonRun.stdout.includes('"case_id": "agent_supplied_authority_grant_refused_before_runtime_mutation"'));
  assert('json includes cross-process authority grant reuse closure', jsonRun.stdout.includes('"cross_process_authority_grant_reuse_closed": true'));
  assert('json includes persistent consumed authority grant store boundary', jsonRun.stdout.includes('"persistent_consumed_authority_grant_store"'));
  assert('json includes host side-door non-closure', jsonRun.stdout.includes('"host_process_or_memory_introspection_closed": false'));
  assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonRun.stdout));

  section('runtime service JSONL command');
  const fixture = runtimeFixture();
  const configPath = join(scratch, 'runtime-config.json');
  writeFileSync(configPath, `${JSON.stringify(fixture.config, null, 2)}\n`);
  const requests = [
    {
      runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      receipt: fixture.receipt,
      record_update: fixture.recordUpdate,
      request_mode: 'recognized_runtime_write',
    },
    {
      runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      receipt: fixture.receipt,
      record_update: fixture.recordUpdate,
      request_mode: 'replay_runtime_write',
    },
    {
      runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      receipt: fixture.receipt,
      record_update: fixture.recordUpdate,
      request_mode: 'agent_supplied_state_path_runtime_write',
      state_path: '/tmp/agent-supplied-state.jsonl',
    },
    {
      runtime_profile_id: 'wrong-protected-records-runtime-profile',
      receipt: fixture.receipt,
      record_update: fixture.recordUpdate,
      request_mode: 'wrong_runtime_profile_id_runtime_write',
    },
    {
      runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      receipt: fixture.receipt,
      record_update: fixture.recordUpdate,
      request_mode: 'unsupported_request_field_runtime_write',
      mutate_without_governance: true,
    },
    {
      runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      receipt: fixture.receipt,
      record_update: fixture.recordUpdate,
      request_mode: 'agent_supplied_consumed_grant_store_witness_path_runtime_write',
      consumed_grant_store_witness_path: '/tmp/agent-supplied-consumed-grant-store-witness.json',
    },
    {
      runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      receipt: fixture.receipt,
      record_update: fixture.recordUpdate,
      request_mode: 'agent_supplied_authority_grant_runtime_write',
      authority_grant_contract: fixture.config.authority_grant_contract,
    },
    {
      runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      request_mode: 'agent_supplied_state_path_malformed_runtime_write',
      state_path: '/tmp/agent-supplied-state.jsonl',
    },
  ].map((item) => ({
    ...item,
    target_handle: PROTECTED_RECORDS_TARGET_HANDLE,
  }));
  const serviceRun = runZlar(['protected-records-runtime-service', '--config', configPath], {
    input: `${requests.map((item) => JSON.stringify(item)).join('\n')}\n`,
  });
  assertEqual('runtime service exits zero', 0, serviceRun.status);
  assertEqual('runtime service emits no stderr', '', serviceRun.stderr);
  assert('runtime service output is privacy safe', !unsafeOutputPattern.test(serviceRun.stdout));
  const results = serviceRun.stdout.trim().split(/\n/).map((line) => JSON.parse(line));
  assertEqual('runtime service emits eight results', 8, results.length);
  for (const result of results) {
    assert('service result passes validation', assertProtectedRecordsRuntimeServiceResult(result));
  }
  assertEqual('service first request accepted', true, results[0].service_write_accepted);
  assertEqual('service first reason', 'fixture_authority_grant_effect_satisfied', results[0].decision.reason_code);
  assertEqual('service first grant satisfied', true, results[0].authority_grant_satisfied);
  assertEqual('service first verified signed payload identity present', true, results[0].verified_signed_payload_identity_present);
  assertEqual('service first consumed grant count', 1, results[0].consumed_authority_grant_count);
  assertEqual('service first state delta', 1, results[0].state_entry_count_delta);
  assertEqual('service transition binds grant contract', results[0].authority_grant_contract_sha256, results[0].runtime_transition_binding.authority_grant_contract_sha256);
  assertEqual('service transition binds grant crossing', results[0].authority_grant_crossing_binding_sha256, results[0].runtime_transition_binding.authority_grant_crossing_binding_sha256);
  assertEqual('service transition binds authorized detail', results[0].authorized_effect_detail_sha256, results[0].runtime_transition_binding.authorized_effect_detail_sha256);
  assertEqual('service transition binds target effect', results[0].target_effect_hash, results[0].runtime_transition_binding.target_effect_sha256);
  assertEqual(
    'service transition binds exact verified signed payload bytes',
    createHash('sha256').update(Buffer.from(fixture.receipt.payload, 'base64url')).digest('hex'),
    results[0].runtime_transition_binding.signed_payload_sha256
  );
  assertEqual('service transition replay check first', 1, results[0].runtime_transition_binding.signed_payload_replay_check_sequence);
  assertEqual('service transition effect gate second', 2, results[0].runtime_transition_binding.effect_gate_sequence);
  assertEqual('service transition grant commit third', 3, results[0].runtime_transition_binding.grant_store_commit_sequence);
  assertEqual('service transition state append fourth', 4, results[0].runtime_transition_binding.state_append_sequence);
  assertEqual('service transition helper promotion fifth', 5, results[0].runtime_transition_binding.helper_state_promotion_sequence);
  assertEqual('service transition holds one launcher lock', true, results[0].runtime_transition_binding.one_launcher_store_lock_held_across_transition);
  assertEqual('service replay refused', false, results[1].service_write_accepted);
  assertEqual('service replay reason', 'receipt_replay', results[1].decision.reason_code);
  assertEqual('service replay state delta zero', 0, results[1].state_entry_count_delta);
  assertEqual('service replay has no accepted transition binding', null, results[1].runtime_transition_binding);
  assertEqual('service authority material refused', false, results[2].service_write_accepted);
  assertEqual('service authority material reason', 'agent_supplied_authority_material', results[2].decision.reason_code);
  assertEqual('service authority material state delta zero', 0, results[2].state_entry_count_delta);
  assertEqual('service wrong runtime profile id refused', false, results[3].service_write_accepted);
  assertEqual('service wrong runtime profile id reason', 'agent_supplied_authority_material', results[3].decision.reason_code);
  assertEqual('service wrong runtime profile id state delta zero', 0, results[3].state_entry_count_delta);
  assertEqual('service unsupported field refused', false, results[4].service_write_accepted);
  assertEqual('service unsupported field reason', 'agent_supplied_authority_material', results[4].decision.reason_code);
  assertEqual('service unsupported field state delta zero', 0, results[4].state_entry_count_delta);
  assertEqual('service witness authority path refused', false, results[5].service_write_accepted);
  assertEqual('service witness authority path reason', 'agent_supplied_authority_material', results[5].decision.reason_code);
  assertEqual('service witness authority path state delta zero', 0, results[5].state_entry_count_delta);
  assertEqual('service request-supplied grant refused', false, results[6].service_write_accepted);
  assertEqual('service request-supplied grant reason', 'agent_supplied_authority_material', results[6].decision.reason_code);
  assertEqual('service request-supplied grant state delta zero', 0, results[6].state_entry_count_delta);
  assertEqual('service malformed authority request refused', false, results[7].service_write_accepted);
  assertEqual('service malformed authority request reason', 'agent_supplied_authority_material', results[7].decision.reason_code);
  assertEqual('service malformed authority request remains bound to launcher authorized update', results[0].record_update_hash, results[7].record_update_hash);
  assertEqual('service malformed authority request state delta zero', 0, results[7].state_entry_count_delta);
  assert('service omits raw record id', !serviceRun.stdout.includes('runtime-cli-record-001'));
  assert('service omits key material', !/BEGIN [A-Z ]*KEY/.test(serviceRun.stdout));

  section('help and fail closed command handling');
  const proofHelp = runZlar(['protected-records-runtime-profile-proof', '--help']);
  assertEqual('proof help exits zero', 0, proofHelp.status);
  assert('proof help names usage', proofHelp.stderr.includes('Usage: zlar protected-records-runtime-profile-proof [--json]'));
  assert('proof help states no live probing', proofHelp.stderr.includes('does not live probe'));
  assert('proof help states no persistent profile', proofHelp.stderr.includes('install a persistent profile'));
  assertEqual('proof help emits no stdout', '', proofHelp.stdout);

  const serviceHelp = runZlar(['protected-records-runtime-service', '--help']);
  assertEqual('service help exits zero', 0, serviceHelp.status);
  assert('service help names usage', serviceHelp.stderr.includes('Usage: zlar protected-records-runtime-service --config <file>'));
  assert('service help states config boundary', serviceHelp.stderr.includes('Config is launcher-supplied out of band from the JSONL request stream'));
  assertEqual('service help emits no stdout', '', serviceHelp.stdout);

  const unsupportedProof = runZlar(['protected-records-runtime-profile-proof', '--latest']);
  assert('unsupported proof option exits usage error', unsupportedProof.status !== 0);
  assertEqual('unsupported proof emits no stdout', '', unsupportedProof.stdout);
  assert('unsupported proof names unsupported option', unsupportedProof.stderr.includes('Unsupported option provided.'));
  assert('unsupported proof stderr is privacy safe', !unsafeOutputPattern.test(unsupportedProof.stderr));

  const missingConfig = runZlar(['protected-records-runtime-service']);
  assert('missing config exits usage error', missingConfig.status !== 0);
  assertEqual('missing config emits no stdout', '', missingConfig.stdout);
  assert('missing config explains request stream boundary', missingConfig.stderr.includes('runtime service config cannot be supplied by the request stream'));
  assert('missing config stderr is privacy safe', !unsafeOutputPattern.test(missingConfig.stderr));

  const stdinConfig = runZlar(['protected-records-runtime-service', '--config', '-'], {
    input: '{}\n',
  });
  assert('stdin config exits usage error', stdinConfig.status !== 0);
  assertEqual('stdin config emits no stdout', '', stdinConfig.stdout);
  assert('stdin config refuses because stdin is requests', stdinConfig.stderr.includes('stdin is reserved for JSONL service requests'));
  assert('stdin config stderr is privacy safe', !unsafeOutputPattern.test(stdinConfig.stderr));

  const invalidRequest = runZlar(['protected-records-runtime-service', '--config', configPath], {
    input: '{not-json}\n',
  });
  assert('invalid JSONL request exits nonzero', invalidRequest.status !== 0);
  assertEqual('invalid JSONL request emits no stdout', '', invalidRequest.stdout);
  assert('invalid JSONL request names parse failure', invalidRequest.stderr.includes('Could not parse JSONL request 1'));
  assert('invalid JSONL request stderr is privacy safe', !unsafeOutputPattern.test(invalidRequest.stderr));

  const mainHelp = runZlar(['help']);
  assertEqual('main help exits zero', 0, mainHelp.status);
  assert('main help lists runtime service', mainHelp.stdout.includes('protected-records-runtime-service'));
  assert('main help lists runtime profile proof', mainHelp.stdout.includes('protected-records-runtime-profile-proof'));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
