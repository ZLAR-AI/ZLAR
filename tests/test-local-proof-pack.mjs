#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalize } from '../lib/canonicalize.mjs';
import {
  LOCAL_PROOF_PACK_ARTIFACT_CANONICALIZATION,
  LOCAL_PROOF_PACK_ARTIFACT_TYPE,
  LOCAL_PROOF_PACK_ARTIFACT_VERIFICATION_TYPE,
  LOCAL_PROOF_PACK_TYPE,
  NON_CLAIMS,
  SAFE_CLAIM_CEILING,
  assertLocalProofPackArtifact,
  assertLocalProofPack,
  assertNoUnsafeLocalProofPackText,
  buildLocalProofPackArtifact,
  formatLocalProofPackArtifactVerification,
  formatLocalProofPackArtifactSummary,
  formatLocalProofPackSummary,
  parseLocalProofPackArtifactText,
  runLocalProofPack,
  verifyLocalProofPackArtifact,
} from '../lib/local-proof-pack.mjs';
import {
  REQUIRED_REFUSAL_REASONS as DOWNSTREAM_REFUSAL_REASONS,
} from '../lib/downstream-refusal-proof.mjs';
import {
  REQUIRED_REFUSAL_REASONS as PROTECTED_RECORDS_REFUSAL_REASONS,
} from '../lib/protected-records-terminal-proof.mjs';
import {
  REQUIRED_REFUSAL_REASONS as ISSUER_STATUS_REFUSAL_REASONS,
} from '../lib/issuer-status-proof.mjs';
import {
  RECEIPT_VERIFIER_BOUNDARY_NON_CLAIMS,
  RECEIPT_VERIFIER_BOUNDARY_PROOF_TYPE,
  RECEIPT_VERIFIER_BOUNDARY_SAFE_CLAIM_CEILING,
} from '../lib/receipt-verifier-boundary-proof.mjs';
import {
  REQUIRED_CONFORMANCE_CASES as PROTECTED_RECORDS_CONFORMANCE_CASES,
} from '../lib/protected-records-adapter-conformance.mjs';
import {
  REQUIRED_SERVICE_CASES as PROTECTED_RECORDS_SERVICE_CASES,
} from '../lib/protected-records-service-proof.mjs';
import {
  PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_TYPE,
  REQUIRED_PROFILE_PREFLIGHT_CASES as PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES,
  assertProtectedRecordsServiceProfile,
  profileSha256,
} from '../lib/protected-records-service-profile.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_PROFILE_PREFLIGHT_TYPE,
  assertProtectedRecordsRuntimePreflightProfile,
  runtimeProfileSha256,
} from '../lib/protected-records-runtime-profile-preflight.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_TYPE,
  RUNTIME_ACTIVATION_PREFLIGHT_NON_CLAIMS,
  RUNTIME_ACTIVATION_PREFLIGHT_SAFE_CLAIM_CEILING,
  assertProtectedRecordsRuntimeActivationPlan,
  runtimeActivationPlanSha256,
} from '../lib/protected-records-runtime-activation-preflight.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PROOF_TYPE,
  RUNTIME_LOCAL_ACTIVATION_NON_CLAIMS,
  RUNTIME_LOCAL_ACTIVATION_SAFE_CLAIM_CEILING,
  assertProtectedRecordsRuntimeLocalActivationPlan,
  runtimeLocalActivationPlanSha256,
} from '../lib/protected-records-runtime-local-activation.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_PROOF_TYPE,
  REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPEN_BOUNDARIES,
  REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPERATOR_REQUIREMENTS,
  RUNTIME_PROFILE_INSTALLATION_NON_CLAIMS,
  RUNTIME_PROFILE_INSTALLATION_SAFE_CLAIM_CEILING,
  assertProtectedRecordsRuntimeProfileInstallationPlan,
  runtimeProfileInstallationPlanSha256,
} from '../lib/protected-records-runtime-profile-installation.mjs';
import {
  KEY_STATE_NON_CLAIMS,
  KEY_STATE_REPORT_TYPE,
} from '../lib/key-state-report.mjs';
import {
  RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_SCOPE,
  RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_TYPE,
  RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY,
  RECORDS_WRITE_TERMINAL_ROUTE,
} from '../lib/records-write-terminal-proof.mjs';
import {
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
} from '../lib/protected-records-installed-runtime-profile-terminal-chain.mjs';
import {
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_EVIDENCE_MODEL,
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_NON_CLAIMS,
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY,
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_TYPE,
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SAFE_CLAIM_CEILING,
  REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES,
  REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SIDE_DOORS,
  claudeCodeHookContractReplayContractSha256,
  claudeCodeHookContractReplayInputContractSha256,
  claudeCodeHookContractReplayRepoAdapterSha256,
} from '../lib/claude-code-hook-contract-replay-proof.mjs';

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

function artifactWithRehashedBody(artifact) {
  const { integrity, ...body } = artifact;
  return {
    ...body,
    integrity: {
      ...integrity,
      body_sha256: createHash('sha256')
        .update(canonicalize(body), 'utf8')
        .digest('hex'),
    },
  };
}

function artifactWithRehashedComponentManifestAndBody(artifact) {
  const copy = structuredClone(artifact);
  copy.component_manifest = copy.payload.components.map((item) => {
    const existing = copy.component_manifest.find((entry) => entry.component === item.component);
    return {
      ...existing,
      component_sha256: createHash('sha256')
        .update(canonicalize(item), 'utf8')
        .digest('hex'),
    };
  });
  return artifactWithRehashedBody(copy);
}

function component(report, name) {
  return report.components.find((item) => item.component === name);
}

function assertRuntimeProfileIdentitySummary(prefix, summary) {
  assertEqual(`${prefix} identity authority source`, 'launcher-owned-service-config', summary.runtime_profile_identity_authority_source);
  assertEqual(`${prefix} identity request-stream policy`, 'runtime_profile_id_may_be_omitted_but_if_supplied_must_match_config', summary.runtime_profile_identity_request_stream_policy);
  assertEqual(`${prefix} request runtime profile id not required`, false, summary.request_runtime_profile_id_required);
  assertEqual(`${prefix} omitted request runtime profile id absent`, false, summary.omitted_request_runtime_profile_id_present);
  assertEqual(`${prefix} omitted runtime profile id uses launcher config`, true, summary.omitted_runtime_profile_id_uses_launcher_config);
  assertEqual(`${prefix} omitted runtime profile id rightful fixture reason`, 'fixture_authority_grant_effect_satisfied', summary.omitted_runtime_profile_id_reason_code);
  assertEqual(`${prefix} omitted runtime profile id mutates once`, 1, summary.omitted_runtime_profile_id_state_entry_count_delta);
  assertEqual(`${prefix} omitted runtime profile id consumes one authority grant`, 1, summary.omitted_runtime_profile_id_consumed_authority_grant_count);
  assertEqual(`${prefix} supplied mismatched runtime profile id refused`, true, summary.supplied_mismatched_runtime_profile_id_refused);
  assertEqual(`${prefix} supplied mismatched runtime profile id reason`, 'agent_supplied_authority_material', summary.supplied_mismatch_reason_code);
  assertEqual(`${prefix} supplied mismatched runtime profile id state delta zero`, 0, summary.supplied_mismatch_state_entry_count_delta);
}

const SAMPLE_ARTIFACT_PATH = 'tests/fixtures/local-proof-pack-artifact-v1.json';
const SAMPLE_ARTIFACT_SHA256 = 'e24adc1735216e20dfb321db473cd58f6ca1b817c93d75e8b83ccf02a9622186';
const SERVICE_PREFLIGHT_PROFILE = JSON.parse(readFileSync('profiles/protected-records-service-fixture.profile.json', 'utf8'));
assertProtectedRecordsServiceProfile(SERVICE_PREFLIGHT_PROFILE);
const SERVICE_PREFLIGHT_PROFILE_SHA256 = profileSha256(SERVICE_PREFLIGHT_PROFILE);
const RUNTIME_PREFLIGHT_PROFILE = JSON.parse(readFileSync('profiles/protected-records-runtime-fixture.profile.json', 'utf8'));
assertProtectedRecordsRuntimePreflightProfile(RUNTIME_PREFLIGHT_PROFILE);
const RUNTIME_PREFLIGHT_PROFILE_SHA256 = runtimeProfileSha256(RUNTIME_PREFLIGHT_PROFILE);
const RUNTIME_ACTIVATION_PLAN = JSON.parse(readFileSync('profiles/protected-records-runtime-activation-plan.fixture.json', 'utf8'));
assertProtectedRecordsRuntimeActivationPlan(RUNTIME_ACTIVATION_PLAN);
const RUNTIME_ACTIVATION_PLAN_SHA256 = runtimeActivationPlanSha256(RUNTIME_ACTIVATION_PLAN);
const RUNTIME_LOCAL_ACTIVATION_PLAN = JSON.parse(readFileSync('profiles/protected-records-runtime-local-activation-plan.fixture.json', 'utf8'));
assertProtectedRecordsRuntimeLocalActivationPlan(RUNTIME_LOCAL_ACTIVATION_PLAN);
const RUNTIME_LOCAL_ACTIVATION_PLAN_SHA256 = runtimeLocalActivationPlanSha256(RUNTIME_LOCAL_ACTIVATION_PLAN);
const RUNTIME_PROFILE_INSTALLATION_PLAN = JSON.parse(readFileSync('profiles/protected-records-runtime-profile-installation-plan.fixture.json', 'utf8'));
assertProtectedRecordsRuntimeProfileInstallationPlan(RUNTIME_PROFILE_INSTALLATION_PLAN);
const RUNTIME_PROFILE_INSTALLATION_PLAN_SHA256 = runtimeProfileInstallationPlanSha256(RUNTIME_PROFILE_INSTALLATION_PLAN);

section('local proof pack report');
const report = runLocalProofPack();
assert('valid report passes validation', assertLocalProofPack(report));
assertEqual('proof pack type', LOCAL_PROOF_PACK_TYPE, report.proof_pack_type);
assertEqual('safe claim ceiling exact', SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('local fixture evidence', 'local-fixtures', report.evidence_model);
assertEqual('no live probing', false, report.live_probing);
assertEqual('sixteen components', 16, report.components.length);

section('coverage component');
const coverage = component(report, 'governed_surface_coverage_map');
assert('coverage component present', Boolean(coverage));
assertEqual('coverage command named', 'zlar coverage --input tests/fixtures/governed-surface-coverage-map-v1-input.json --require-governed', coverage.command);
assertEqual('coverage governed lanes', coverage.counted_lanes, coverage.governed_lanes);
assert('coverage has counted lanes', coverage.counted_lanes > 0);
assert('coverage names boundaries', coverage.boundary_entries > 0);
assertEqual('coverage live probing false', false, coverage.live_probing);
assertEqual(
  'coverage terminal artifact matches code-owned expected identity',
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
  coverage.terminal_artifact_body_sha256
);
assertEqual(
  'coverage terminal expected identity is code-owned pin',
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
  coverage.terminal_artifact_expected_body_sha256
);
assertEqual('coverage terminal identity matched', true, coverage.terminal_artifact_identity_sha256_matched);
assertEqual(
  'coverage terminal outer metadata identity-bound',
  true,
  coverage.terminal_outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256
);
assertEqual(
  'coverage terminal recognized source identity-bound',
  true,
  coverage.terminal_recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256
);
assertEqual('coverage terminal signature valid', true, coverage.terminal_trusted_issuer_registry_signature_valid);
assertEqual('coverage terminal fixture rightful path evidenced', true, coverage.terminal_fixture_rightful_issuance_path_evidenced);

section('downstream refusal component');
const downstream = component(report, 'downstream_refusal_proof');
assert('downstream component present', Boolean(downstream));
assertEqual('downstream command named', 'zlar downstream-refusal-proof', downstream.command);
assertEqual('downstream recognized boarded', true, downstream.recognized_boarded);
assertEqual('downstream recognized marker delta', 1, downstream.recognized_marker_count_delta);
assertEqual('downstream final marker count', 1, downstream.final_marker_count);
assertEqual('downstream refusal case count', DOWNSTREAM_REFUSAL_REASONS.length, downstream.refusal_case_count);
assertEqual('downstream all refusals unboarded', true, downstream.all_refusals_unboarded);
assertEqual('downstream all refusal marker deltas zero', true, downstream.all_refusal_marker_count_deltas_zero);
for (const reason of DOWNSTREAM_REFUSAL_REASONS) {
  assert(`downstream refusal reason present: ${reason}`, downstream.refusal_reasons.includes(reason));
}

section('human authorization component');
const humanAuthorization = component(report, 'human_authorization_proof');
assert('human authorization component present', Boolean(humanAuthorization));
assertEqual('human authorization command named', 'zlar human-authorization-proof', humanAuthorization.command);
assertEqual('human authorization channel simulated', 'simulated-human-fixture', humanAuthorization.approval_channel);
assertEqual('human authorization pending does not board', false, humanAuthorization.pending_boarded);
assertEqual('human authorization authorized boards', true, humanAuthorization.authorized_boarded);
assertEqual('human authorization denied does not board', false, humanAuthorization.denied_boarded);
assertEqual('human authorization authorizer', 'human:fixture-operator', humanAuthorization.authorizer);
assertEqual('human authorization outcome', 'authorized', humanAuthorization.outcome);

section('approval transport component');
const approvalTransport = component(report, 'approval_transport_proof');
assert('approval transport component present', Boolean(approvalTransport));
assertEqual('approval transport command named', 'zlar approval-transport-proof', approvalTransport.command);
assertEqual('approval transport model', 'channel-neutral-approval-transport-v1', approvalTransport.transport_model);
assertEqual('approval transport live probing false', false, approvalTransport.live_probing);
assertEqual('approval transport reference healthy', true, approvalTransport.reference_transport_healthy);
assertEqual('approval transport Telegram not required for fixture', false, approvalTransport.telegram_required_for_fixture);
assertEqual('approval transport unavailable does not board', false, approvalTransport.unavailable_boarded);
assertEqual('approval transport delivered without decision does not board', false, approvalTransport.delivered_without_decision_boarded);
assertEqual('approval transport signed human decision boards', true, approvalTransport.signed_human_decision_boarded);

section('protected records component');
const protectedRecords = component(report, 'protected_records_terminal');
assert('protected records component present', Boolean(protectedRecords));
assertEqual('protected records command named', 'zlar protected-records-proof', protectedRecords.command);
assertEqual('protected records deployment profile', 'protected-records-terminal', protectedRecords.deployment_profile);
assertEqual('protected records action class', 'records.write', protectedRecords.action_class);
assertEqual('protected records downstream boundary', 'protected-records-terminal-fixture', protectedRecords.downstream_boundary);
assertEqual('protected records adapter profile type', 'protected-records-adapter-profile-v1', protectedRecords.adapter_profile_type);
assertEqual('protected records adapter profile id', 'protected-records-adapter-profile', protectedRecords.adapter_profile_id);
assertEqual('protected records adapter route', 'receipt-recognition-before-ledger-append', protectedRecords.adapter_authoritative_route);
assertEqual('protected records adapter boundary', 'protected-records-adapter-harness', protectedRecords.adapter_boundary);
assertEqual('protected records adapter ledger model', 'append-only-jsonl-ledger', protectedRecords.adapter_ledger_model);
assertEqual('protected records adapter consumed receipt store', 'single-use-receipt-id-store', protectedRecords.adapter_consumed_receipt_store);
assertEqual('protected records adapter replay scope', 'per-adapter-ledger', protectedRecords.adapter_replay_scope);
assertEqual('protected records adapter final ledger entries', 1, protectedRecords.adapter_final_ledger_entry_count);
assertEqual('protected records adapter consumed receipt count', 1, protectedRecords.adapter_consumed_receipt_count);
assertEqual('protected records adapter direct write closed', false, protectedRecords.adapter_direct_write_path_available);
assertEqual('protected records adapter live adapter false', false, protectedRecords.adapter_live_records_adapter);
assertEqual('protected records adapter action type', 'local-protected-records-action-adapter-v1', protectedRecords.adapter_action_type);
assertEqual('protected records adapter action command', 'zlar protected-records-write --input <file|->', protectedRecords.adapter_action_command);
assertEqual('protected records adapter action result type', 'protected-records-write-result-v1', protectedRecords.adapter_action_result_type);
assertEqual('protected records adapter action fixture mode', true, protectedRecords.adapter_action_fixture_mode_required);
assertEqual('protected records adapter action writes bounded ledger', 'bounded-jsonl-ledger-entry', protectedRecords.adapter_action_writes);
assertEqual('protected records adapter action live adapter false', false, protectedRecords.adapter_action_live_records_adapter);
assertEqual('protected records adapter action omits raw detail output', false, protectedRecords.adapter_action_raw_record_detail_output);
for (const route of ['direct_fixture_ledger_mutation', 'adapter_bypass_write']) {
  assert(`protected records adapter closed route present: ${route}`, protectedRecords.adapter_closed_in_fixture.includes(route));
}
for (const boundary of ['live_records_system', 'production_records_adapter', 'unrouted_records_paths']) {
  assert(`protected records adapter open boundary present: ${boundary}`, protectedRecords.adapter_known_open_boundaries.includes(boundary));
}
assertEqual('protected records profile contract id', 'protected-records-terminal', protectedRecords.profile_contract_id);
assertEqual('protected records profile checkpoint', 'downstream-recognition-rule', protectedRecords.profile_contract_checkpoint);
assertEqual('protected records profile route', 'receipt-recognition-before-record-write', protectedRecords.profile_contract_route);
assertEqual('protected records profile effect', 'append-protected-records-ledger-entry', protectedRecords.profile_contract_downstream_effect);
assertEqual('protected records replay policy', 'single-use-receipt-id-per-terminal-ledger', protectedRecords.receipt_replay_policy);
for (const field of ['v', 'id', 'kid', 'iat', 'type', 'payload', 'sig', 'payload.audit_event_id', 'payload.ts', 'payload.domain', 'payload.tool', 'payload.outcome', 'payload.policy_version', 'payload.detail_hash']) {
  assert(`protected records required receipt field present: ${field}`, protectedRecords.required_receipt_fields.includes(field));
}
assertEqual('protected records accepted write', true, protectedRecords.recognized_write_accepted);
assertEqual('protected records changed once', true, protectedRecords.recognized_record_changed);
assertEqual('protected records recognized delta', 1, protectedRecords.recognized_record_count_delta);
assertEqual('protected records refused write count', PROTECTED_RECORDS_REFUSAL_REASONS.length, protectedRecords.refused_write_count);
assertEqual('protected records all refusals prevent change', true, protectedRecords.all_refusals_prevented_record_change);
assertEqual('protected records refusal delta total', 0, protectedRecords.refusal_record_count_delta_total);
assertEqual('protected records final count', 1, protectedRecords.final_record_count);
for (const reason of PROTECTED_RECORDS_REFUSAL_REASONS) {
  assert(`protected records refusal reason present: ${reason}`, protectedRecords.refusal_reasons.includes(reason));
}
for (const boundary of ['live_records_system', 'production_records_adapter', 'unrouted_records_paths']) {
  assert(`protected records ungoverned boundary present: ${boundary}`, protectedRecords.known_ungoverned_boundaries.includes(boundary));
}

section('protected records adapter conformance component');
const adapterConformance = component(report, 'protected_records_adapter_conformance');
assert('protected records adapter conformance component present', Boolean(adapterConformance));
assertEqual('adapter conformance command named', 'zlar protected-records-adapter-conformance', adapterConformance.command);
assertEqual('adapter conformance proof type', 'protected-records-adapter-conformance-proof-v1', adapterConformance.proof_type);
assertEqual('adapter conformance evidence model', 'local-disposable-cli-process-fixture', adapterConformance.evidence_model);
assertEqual('adapter conformance live probing false', false, adapterConformance.live_probing);
assertEqual('adapter conformance profile', 'protected-records-cli-process-conformance', adapterConformance.profile_id);
assertEqual('adapter conformance action class', 'records.write', adapterConformance.action_class);
assertEqual('adapter conformance adapter type', 'local-protected-records-action-adapter-v1', adapterConformance.adapter_type);
assertEqual('adapter conformance adapter command', 'zlar protected-records-write --input <file|->', adapterConformance.adapter_command);
assertEqual('adapter conformance process boundary', 'separate-cli-process', adapterConformance.adapter_process_boundary);
assertEqual('adapter conformance route', 'receipt-recognition-before-ledger-append', adapterConformance.mutation_authoritative_route);
assertEqual('adapter conformance result type', 'protected-records-write-result-v1', adapterConformance.result_type);
assertEqual('adapter conformance ledger model', 'bounded-jsonl-ledger-entry', adapterConformance.ledger_model);
assertEqual('adapter conformance persistent store', 'persistent-single-use-receipt-id-store', adapterConformance.consumed_receipt_store);
assertEqual('adapter conformance replay scope', 'per-adapter-consumed-receipt-store', adapterConformance.replay_scope);
assertEqual('adapter conformance recognized write accepted', true, adapterConformance.recognized_write_accepted);
assertEqual('adapter conformance recognized reason', 'recognized', adapterConformance.recognized_write_reason);
assertEqual('adapter conformance recognized delta', 1, adapterConformance.recognized_write_ledger_delta);
assertEqual('adapter conformance replay refused', true, adapterConformance.replay_refused);
assertEqual('adapter conformance replay reason', 'receipt_replay', adapterConformance.replay_reason);
assertEqual('adapter conformance replay delta', 0, adapterConformance.replay_ledger_delta);
assertEqual('adapter conformance replay separate process', true, adapterConformance.replay_separate_process);
assertEqual('adapter conformance missing receipt refused', true, adapterConformance.missing_receipt_refused);
assertEqual('adapter conformance missing reason', 'receipt_missing', adapterConformance.missing_receipt_reason);
assertEqual('adapter conformance missing delta', 0, adapterConformance.missing_receipt_ledger_delta);
assertEqual('adapter conformance unsupported side door refused', true, adapterConformance.unsupported_side_door_refused);
assertEqual('adapter conformance unsupported reason', 'unsupported_option', adapterConformance.unsupported_side_door_reason);
assertEqual('adapter conformance unsupported delta', 0, adapterConformance.unsupported_side_door_ledger_delta);
assertEqual('adapter conformance CLI direct write unavailable', false, adapterConformance.cli_direct_write_option_available);
assertEqual('adapter conformance direct filesystem side door open', false, adapterConformance.direct_filesystem_write_to_fixture_paths_closed);
assertEqual('adapter conformance live adapter false', false, adapterConformance.live_records_adapter);
for (const caseId of PROTECTED_RECORDS_CONFORMANCE_CASES) {
  assert(`adapter conformance case present: ${caseId}`, adapterConformance.conformance_cases.includes(caseId));
}
for (const boundary of ['direct_filesystem_write_to_supplied_fixture_paths', 'live_records_system', 'production_records_adapter', 'unrouted_records_paths']) {
  assert(`adapter conformance open boundary present: ${boundary}`, adapterConformance.known_open_boundaries.includes(boundary));
}

section('protected records downstream service component');
const protectedRecordsService = component(report, 'protected_records_downstream_service');
assert('protected records downstream service component present', Boolean(protectedRecordsService));
assertEqual('service command named', 'zlar protected-records-service-proof', protectedRecordsService.command);
assertEqual('service proof type', 'protected-records-service-proof-v1', protectedRecordsService.proof_type);
assertEqual('service evidence model', 'local-disposable-service-process-fixture', protectedRecordsService.evidence_model);
assertEqual('service live probing false', false, protectedRecordsService.live_probing);
assertEqual('service profile', 'protected-records-downstream-service-fixture', protectedRecordsService.profile_id);
assertEqual('service action class', 'records.write', protectedRecordsService.action_class);
assertEqual('service type', 'local-protected-records-downstream-service-v1', protectedRecordsService.service_type);
assertEqual('service command field', 'zlar protected-records-service-request --input <file|->', protectedRecordsService.service_command);
assertEqual('service process boundary', 'separate-cli-process', protectedRecordsService.service_process_boundary);
assertEqual('service recognition boundary', 'downstream-recognition-before-service-mutation', protectedRecordsService.recognition_boundary);
assertEqual('service route', 'receipt-recognition-before-service-state-append', protectedRecordsService.mutation_authoritative_route);
assertEqual('service result type', 'protected-records-service-result-v1', protectedRecordsService.result_type);
assertEqual('service state model', 'bounded-jsonl-service-state-entry', protectedRecordsService.state_model);
assertEqual('service persistent store', 'persistent-single-use-receipt-id-store', protectedRecordsService.consumed_receipt_store);
assertEqual('service replay scope', 'per-service-consumed-receipt-store', protectedRecordsService.replay_scope);
assertEqual('service direct api model', 'no-receipt-direct-api-attempt-refuses-before-mutation', protectedRecordsService.direct_api_request_model);
assertEqual('service preflight profile id', 'protected-records-service-fixture-profile', protectedRecordsService.service_profile_preflight_profile_id);
assertEqual('service preflight profile sha', SERVICE_PREFLIGHT_PROFILE_SHA256, protectedRecordsService.service_profile_preflight_profile_sha256);
assertEqual('service preflight profile status', 'sample_not_active', protectedRecordsService.service_profile_preflight_profile_status);
assertEqual('service preflight deployment posture', 'deployable_profile_preflight_only', protectedRecordsService.service_profile_preflight_deployment_posture);
assertEqual('service preflight run in proof pack', true, protectedRecordsService.service_profile_preflight_run_in_proof_pack);
assertEqual('service preflight type', PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_TYPE, protectedRecordsService.service_profile_preflight_type);
assertEqual('service preflight evidence model', 'local-disposable-config-backed-profile-preflight-fixture', protectedRecordsService.service_profile_preflight_evidence_model);
assertEqual('service preflight live probing false', false, protectedRecordsService.service_profile_preflight_live_probing);
assertEqual('service preflight case count', PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length, protectedRecordsService.service_profile_preflight_case_count);
assertEqual('service preflight required case count', PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length, protectedRecordsService.service_profile_preflight_required_case_count);
for (const caseId of PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES) {
  assert(`service preflight case present: ${caseId}`, protectedRecordsService.service_profile_preflight_cases.includes(caseId));
}
const servicePreflightDirectApiReceiptSummary = protectedRecordsService.service_profile_preflight_case_summaries.find((item) =>
  item.case_id === 'direct_api_profile_receipt_present_refused_before_service_mutation'
);
assertEqual('service preflight direct api receipt summary process', 11, servicePreflightDirectApiReceiptSummary.process_invocation);
assertEqual('service preflight direct api receipt summary accepted false', false, servicePreflightDirectApiReceiptSummary.service_write_accepted);
assertEqual('service preflight direct api receipt summary reason', 'request_stream_forbidden_fields', servicePreflightDirectApiReceiptSummary.reason_code);
assertEqual('service preflight direct api receipt summary state delta', 0, servicePreflightDirectApiReceiptSummary.state_entry_count_delta);
assertEqual('service preflight direct api receipt summary attempted', true, servicePreflightDirectApiReceiptSummary.direct_api_attempted);
const servicePreflightWrongPolicySummary = protectedRecordsService.service_profile_preflight_case_summaries.find((item) =>
  item.case_id === 'wrong_policy_profile_refused_before_service_mutation'
);
assertEqual('service preflight wrong policy process', 7, servicePreflightWrongPolicySummary.process_invocation);
assertEqual('service preflight wrong policy accepted false', false, servicePreflightWrongPolicySummary.service_write_accepted);
assertEqual('service preflight wrong policy reason', 'policy_not_recognized', servicePreflightWrongPolicySummary.reason_code);
assertEqual('service preflight wrong policy state delta', 0, servicePreflightWrongPolicySummary.state_entry_count_delta);
assertEqual('service preflight wrong policy attempted false', false, servicePreflightWrongPolicySummary.direct_api_attempted);
const servicePreflightRequestStreamAuthoritySummary = protectedRecordsService.service_profile_preflight_case_summaries.find((item) =>
  item.case_id === 'request_stream_authority_material_profile_refused_before_service_mutation'
);
assertEqual('service preflight request stream authority process', 9, servicePreflightRequestStreamAuthoritySummary.process_invocation);
assertEqual('service preflight request stream authority accepted false', false, servicePreflightRequestStreamAuthoritySummary.service_write_accepted);
assertEqual('service preflight request stream authority reason', 'request_stream_authority_material', servicePreflightRequestStreamAuthoritySummary.reason_code);
assertEqual('service preflight request stream authority state delta', 0, servicePreflightRequestStreamAuthoritySummary.state_entry_count_delta);
assertEqual('service preflight request stream authority attempted false', false, servicePreflightRequestStreamAuthoritySummary.direct_api_attempted);
assertEqual('service preflight recognized write accepted', true, protectedRecordsService.service_profile_preflight_recognized_write_accepted);
assertEqual('service preflight replay refused', true, protectedRecordsService.service_profile_preflight_replay_refused);
assertEqual('service preflight missing receipt refused', true, protectedRecordsService.service_profile_preflight_missing_receipt_refused);
assertEqual('service preflight unrecognized receipt refused', true, protectedRecordsService.service_profile_preflight_unrecognized_receipt_refused);
assertEqual('service preflight invalid receipt refused', true, protectedRecordsService.service_profile_preflight_invalid_receipt_refused);
assertEqual('service preflight unknown issuer refused', true, protectedRecordsService.service_profile_preflight_unknown_issuer_refused);
assertEqual('service preflight wrong policy refused', true, protectedRecordsService.service_profile_preflight_wrong_policy_refused);
assertEqual('service preflight wrong policy reason field', 'policy_not_recognized', protectedRecordsService.service_profile_preflight_wrong_policy_reason);
assertEqual('service preflight wrong policy delta field', 0, protectedRecordsService.service_profile_preflight_wrong_policy_state_delta);
assertEqual('service preflight stale receipt refused', true, protectedRecordsService.service_profile_preflight_stale_receipt_refused);
assertEqual('service preflight launcher-owned config required', true, protectedRecordsService.service_profile_preflight_launcher_owned_config_required);
assertEqual('service preflight request stream authority allowed false', false, protectedRecordsService.service_profile_preflight_request_stream_authority_material_allowed);
assertEqual('service preflight request stream authority refused', true, protectedRecordsService.service_profile_preflight_request_stream_authority_material_refused);
assertEqual('service preflight request stream authority reason field', 'request_stream_authority_material', protectedRecordsService.service_profile_preflight_request_stream_authority_material_reason);
assertEqual('service preflight request stream authority delta field', 0, protectedRecordsService.service_profile_preflight_request_stream_authority_material_state_delta);
assertEqual('service preflight request stream forbidden fields refused', true, protectedRecordsService.service_profile_preflight_request_stream_forbidden_fields_refused);
assertEqual('service preflight direct api without receipt refused', true, protectedRecordsService.service_profile_preflight_direct_api_without_receipt_refused);
assertEqual('service preflight direct api with receipt refused', true, protectedRecordsService.service_profile_preflight_direct_api_with_receipt_refused);
assertEqual('service preflight filesystem side door open', false, protectedRecordsService.service_profile_preflight_direct_filesystem_write_to_fixture_paths_closed);
assertEqual('service preflight live profile installed false', false, protectedRecordsService.service_profile_preflight_live_profile_installed);
assertEqual('service preflight runtime activation checked false', false, protectedRecordsService.service_profile_preflight_runtime_profile_activation_checked);
assertEqual('service preflight live records checked false', false, protectedRecordsService.service_profile_preflight_live_records_system_checked);
assertEqual('service preflight production service checked false', false, protectedRecordsService.service_profile_preflight_production_records_service_checked);
assertEqual('service preflight live MCP checked false', false, protectedRecordsService.service_profile_preflight_live_mcp_coverage_checked);
assertEqual('service preflight approval health checked false', false, protectedRecordsService.service_profile_preflight_live_approval_channel_health_checked);
assertEqual('service preflight external attestation false', false, protectedRecordsService.service_profile_preflight_external_attestation);
assertEqual('service preflight sovereign recognition false', false, protectedRecordsService.service_profile_preflight_sovereign_recognition);
assertEqual('service preflight unrouted paths checked false', false, protectedRecordsService.service_profile_preflight_unrouted_records_paths_checked);
assertEqual('service recognized write accepted', true, protectedRecordsService.recognized_service_write_accepted);
assertEqual('service recognized reason', 'recognized', protectedRecordsService.recognized_service_reason);
assertEqual('service recognized state delta', 1, protectedRecordsService.recognized_service_state_delta);
assertEqual('service replay refused', true, protectedRecordsService.replay_refused);
assertEqual('service replay reason', 'receipt_replay', protectedRecordsService.replay_reason);
assertEqual('service replay state delta', 0, protectedRecordsService.replay_state_delta);
assertEqual('service replay separate process', true, protectedRecordsService.replay_separate_process);
assertEqual('service missing receipt refused', true, protectedRecordsService.missing_receipt_refused);
assertEqual('service missing reason', 'receipt_missing', protectedRecordsService.missing_receipt_reason);
assertEqual('service missing state delta', 0, protectedRecordsService.missing_receipt_state_delta);
assertEqual('service unrecognized receipt refused', true, protectedRecordsService.unrecognized_receipt_refused);
assertEqual('service unrecognized reason', 'detail_hash_mismatch', protectedRecordsService.unrecognized_receipt_reason);
assertEqual('service unrecognized state delta', 0, protectedRecordsService.unrecognized_receipt_state_delta);
assertEqual('service invalid receipt refused', true, protectedRecordsService.invalid_receipt_refused);
assertEqual('service invalid reason', 'receipt_invalid', protectedRecordsService.invalid_receipt_reason);
assertEqual('service invalid state delta', 0, protectedRecordsService.invalid_receipt_state_delta);
assertEqual('service unknown issuer refused', true, protectedRecordsService.unknown_issuer_refused);
assertEqual('service unknown issuer reason', 'unknown_issuer', protectedRecordsService.unknown_issuer_reason);
assertEqual('service unknown issuer state delta', 0, protectedRecordsService.unknown_issuer_state_delta);
assertEqual('service stale receipt refused', true, protectedRecordsService.stale_receipt_refused);
assertEqual('service stale reason', 'receipt_stale', protectedRecordsService.stale_receipt_reason);
assertEqual('service stale state delta', 0, protectedRecordsService.stale_receipt_state_delta);
assertEqual('service direct api refused', true, protectedRecordsService.direct_api_without_receipt_refused);
assertEqual('service direct api reason', 'receipt_missing', protectedRecordsService.direct_api_reason);
assertEqual('service direct api state delta', 0, protectedRecordsService.direct_api_state_delta);
assertEqual('service direct api attempted', true, protectedRecordsService.direct_api_attempted);
assertEqual('service direct api refusal reported', true, protectedRecordsService.direct_api_without_receipt_refused_reported);
assertEqual('service direct filesystem side door open', false, protectedRecordsService.direct_filesystem_write_to_fixture_paths_closed);
assertEqual('service live service false', false, protectedRecordsService.live_records_service);
for (const caseId of PROTECTED_RECORDS_SERVICE_CASES) {
  assert(`service case present: ${caseId}`, protectedRecordsService.service_cases.includes(caseId));
}
for (const boundary of ['direct_filesystem_write_to_supplied_fixture_paths', 'live_records_system', 'production_records_service', 'unrouted_records_paths']) {
  assert(`service open boundary present: ${boundary}`, protectedRecordsService.known_open_boundaries.includes(boundary));
}
for (const boundary of SERVICE_PREFLIGHT_PROFILE.known_open_boundaries) {
  assert(`service preflight open boundary present: ${boundary}`, protectedRecordsService.service_profile_preflight_known_open_boundaries.includes(boundary));
}
for (const nonClaim of SERVICE_PREFLIGHT_PROFILE.non_claims) {
  assert(`service preflight non-claim present: ${nonClaim}`, protectedRecordsService.service_profile_preflight_non_claims.includes(nonClaim));
}

section('protected records runtime profile preflight identity component');
const runtimeProfilePreflight = component(report, 'protected_records_runtime_profile_preflight_identity');
assert('runtime profile preflight identity component present', Boolean(runtimeProfilePreflight));
assertEqual('runtime preflight command named', 'zlar protected-records-runtime-profile-preflight --profile profiles/protected-records-runtime-fixture.profile.json', runtimeProfilePreflight.preflight_command);
assertEqual('runtime preflight profile type', 'zlar-protected-records-runtime-profile-v1', runtimeProfilePreflight.profile_type);
assertEqual('runtime preflight profile id', 'protected-records-runtime-fixture-profile', runtimeProfilePreflight.profile_id);
assertEqual('runtime preflight profile sha', RUNTIME_PREFLIGHT_PROFILE_SHA256, runtimeProfilePreflight.profile_sha256);
assertEqual('runtime preflight profile status', 'sample_not_active', runtimeProfilePreflight.profile_status);
assertEqual('runtime preflight deployment posture', 'runtime_profile_preflight_only', runtimeProfilePreflight.deployment_posture);
assertEqual('runtime preflight runtime profile id', 'protected-records-disposable-runtime-profile', runtimeProfilePreflight.runtime_profile_id);
assertEqual('runtime preflight action class', 'records.write', runtimeProfilePreflight.action_class);
assertEqual('runtime preflight service command', 'zlar protected-records-runtime-service --config <file>', runtimeProfilePreflight.service_command);
assertEqual('runtime preflight proof command', 'zlar protected-records-runtime-profile-proof', runtimeProfilePreflight.proof_command);
assertEqual('runtime preflight request contract', 'receipt-record-update-and-routing-metadata-only', runtimeProfilePreflight.request_contract);
assertEqual('runtime preflight mutation route', RECORDS_WRITE_TERMINAL_ROUTE, runtimeProfilePreflight.mutation_authoritative_route);
assertEqual('runtime preflight launcher config true', true, runtimeProfilePreflight.config_supplied_by_launcher);
assertEqual('runtime preflight request authority false', false, runtimeProfilePreflight.request_stream_authority_material_accepted);
assertEqual('runtime preflight state path hidden', false, runtimeProfilePreflight.state_path_exposed_to_agent);
assertEqual('runtime preflight consumed grants path hidden', false, runtimeProfilePreflight.consumed_grants_path_exposed_to_agent);
assertEqual('runtime preflight grant anchor path hidden', false, runtimeProfilePreflight.consumed_grant_store_anchor_path_exposed_to_agent);
assertEqual('runtime preflight grant witness path hidden', false, runtimeProfilePreflight.consumed_grant_store_witness_path_exposed_to_agent);
assertEqual('runtime preflight recognition rule not agent supplied', false, runtimeProfilePreflight.recognition_rule_supplied_by_agent);
assertEqual('runtime preflight authority contract required', true, runtimeProfilePreflight.authority_grant_contract_required_from_launcher);
assertEqual('runtime preflight authority appointment required', true, runtimeProfilePreflight.authority_grant_appointment_required_from_launcher);
assertEqual('runtime preflight issuance decision required', true, runtimeProfilePreflight.authority_grant_issuance_decision_required_from_launcher);
assertEqual('runtime preflight authorized update required', true, runtimeProfilePreflight.authorized_record_update_required_from_launcher);
assertEqual('runtime preflight source profile grant absent', false, runtimeProfilePreflight.source_profile_authority_grant_present);
assertEqual('runtime preflight consumed grant store model', 'persistent-single-use-authority-grant-contract-sha256-store', runtimeProfilePreflight.consumed_authority_grant_store);
assertEqual('runtime preflight consumption identity', 'authority-grant-contract-sha256', runtimeProfilePreflight.consumption_identity);
assertEqual('runtime preflight signed replay identity', 'verified-signed-payload-sha256', runtimeProfilePreflight.signed_payload_replay_identity);
assertEqual('runtime preflight consumed store lock', 'launcher-owned-per-store-lockfile', runtimeProfilePreflight.consumed_store_lock);
assertEqual('runtime preflight consumed store validation', 'exact-schema-unique-grant-contract-sha256s', runtimeProfilePreflight.consumed_store_validation);
assertEqual('runtime preflight consumed store anchor', 'launcher-owned-local-store-hash-anchor', runtimeProfilePreflight.consumed_store_anchor);
assertEqual('runtime preflight consumed store witness', 'launcher-owned-local-store-hash-witness', runtimeProfilePreflight.consumed_store_witness);
assertEqual('runtime preflight rollback detection', 'single-host-anchor-and-witness-match-before-mutation', runtimeProfilePreflight.consumed_store_rollback_detection);
assertEqual('runtime preflight write model', 'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness', runtimeProfilePreflight.consumed_store_write_model);
assertEqual('runtime preflight replay scope', 'helper-signed-payload-identity-and-persistent-authority-grant-contract-sha256', runtimeProfilePreflight.replay_scope);
assertEqual('runtime preflight single host rollback detection true', true, runtimeProfilePreflight.single_host_rollback_detection);
assertEqual('runtime preflight witness-ahead rollback refused', true, runtimeProfilePreflight.store_and_anchor_joint_rollback_refused_while_witness_ahead);
assertEqual('runtime preflight joint rollback detection false', false, runtimeProfilePreflight.store_anchor_and_witness_joint_rollback_detection);
assertEqual('runtime preflight atomic triple commit false', false, runtimeProfilePreflight.atomic_store_anchor_witness_commit);
assertEqual('runtime preflight burn window named', true, runtimeProfilePreflight.partial_grant_commit_burn_window_named);
assertEqual('runtime preflight host path TOCTOU false', false, runtimeProfilePreflight.host_filesystem_path_toctou_closed);
assertEqual('runtime preflight production anti rollback false', false, runtimeProfilePreflight.production_grade_anti_rollback);
assertEqual('runtime preflight exactly once false', false, runtimeProfilePreflight.exactly_once_effect_semantics);
assertEqual('runtime preflight required case count', RUNTIME_PREFLIGHT_PROFILE.required_cases.length, runtimeProfilePreflight.required_case_count);
assertEqual('runtime preflight boundary observation count', RUNTIME_PREFLIGHT_PROFILE.required_boundary_observations.length, runtimeProfilePreflight.required_boundary_observation_count);
assertEqual('runtime preflight not run in proof pack', false, runtimeProfilePreflight.runtime_profile_preflight_run_in_proof_pack);
assertEqual('runtime proof not run in proof pack', false, runtimeProfilePreflight.runtime_profile_proof_run_in_proof_pack);
assertEqual('runtime preflight fixture rightful issuance false', false, runtimeProfilePreflight.fixture_rightful_issuance_path_evidenced);
assertEqual('runtime preflight rightful issuance false', false, runtimeProfilePreflight.rightful_issuance_proven);
assertEqual('runtime preflight portable rightful issuance false', false, runtimeProfilePreflight.portable_rightful_issuance_proven);
assertEqual('runtime preflight live authority false', false, runtimeProfilePreflight.live_authority_proven);
assertEqual('runtime preflight production rightful issuance false', false, runtimeProfilePreflight.production_rightful_issuance_proven);
assertEqual('runtime preflight current-machine governance false', false, runtimeProfilePreflight.current_machine_governance_proven);
assertEqual('runtime preflight lifecycle closure false', false, runtimeProfilePreflight.consequence_lifecycle_closed);
for (const boundary of RUNTIME_PREFLIGHT_PROFILE.known_open_boundaries) {
  assert(`runtime preflight open boundary present: ${boundary}`, runtimeProfilePreflight.known_open_boundaries.includes(boundary));
}

section('protected records runtime activation preflight component');
const runtimeActivationPreflight = component(report, 'protected_records_runtime_activation_preflight');
assert('runtime activation preflight component present', Boolean(runtimeActivationPreflight));
assertEqual('runtime activation preflight type', PROTECTED_RECORDS_RUNTIME_ACTIVATION_PREFLIGHT_TYPE, runtimeActivationPreflight.preflight_type);
assertEqual('runtime activation evidence model', 'local-runtime-activation-plan-preflight-fixture', runtimeActivationPreflight.evidence_model);
assertEqual('runtime activation live probing false', false, runtimeActivationPreflight.live_probing);
assertEqual('runtime activation safe claim ceiling', RUNTIME_ACTIVATION_PREFLIGHT_SAFE_CLAIM_CEILING, runtimeActivationPreflight.safe_claim_ceiling);
assertEqual('runtime activation preflight command named', RUNTIME_ACTIVATION_PLAN.preflight_command, runtimeActivationPreflight.preflight_command);
assertEqual('runtime activation plan type', 'zlar-protected-records-runtime-activation-plan-v1', runtimeActivationPreflight.plan_type);
assertEqual('runtime activation plan id', 'protected-records-runtime-fixture-activation-plan', runtimeActivationPreflight.plan_id);
assertEqual('runtime activation plan sha', RUNTIME_ACTIVATION_PLAN_SHA256, runtimeActivationPreflight.plan_sha256);
assertEqual('runtime activation plan status', 'sample_not_active', runtimeActivationPreflight.plan_status);
assertEqual('runtime activation deployment posture', 'activation_plan_preflight_only', runtimeActivationPreflight.deployment_posture);
assertEqual('runtime activation action class', 'records.write', runtimeActivationPreflight.action_class);
assertEqual('runtime activation runtime profile id', 'protected-records-disposable-runtime-profile', runtimeActivationPreflight.runtime_profile_id);
assertEqual('runtime activation runtime profile source', 'profiles/protected-records-runtime-fixture.profile.json', runtimeActivationPreflight.runtime_profile_source);
assertEqual('runtime activation runtime profile sha', RUNTIME_PREFLIGHT_PROFILE_SHA256, runtimeActivationPreflight.runtime_profile_sha256);
assertEqual('runtime activation profile sha matches plan', true, runtimeActivationPreflight.runtime_profile_sha_matches_plan);
assertEqual('runtime activation runtime preflight command', RUNTIME_ACTIVATION_PLAN.runtime_profile_preflight_command, runtimeActivationPreflight.runtime_profile_preflight_command);
assertEqual('runtime activation service command', 'zlar protected-records-runtime-service --config <launcher-owned-config>', runtimeActivationPreflight.service_command);
assertEqual('runtime activation proof command', 'zlar protected-records-runtime-profile-proof', runtimeActivationPreflight.proof_command);
assertEqual('runtime activation applied false', false, runtimeActivationPreflight.activation_applied);
assertEqual('runtime activation writes runtime config false', false, runtimeActivationPreflight.writes_runtime_config);
assertEqual('runtime activation writes hook config false', false, runtimeActivationPreflight.writes_hook_configuration);
assertEqual('runtime activation starts service false', false, runtimeActivationPreflight.starts_runtime_service);
assertEqual('runtime activation requires explicit install true', true, runtimeActivationPreflight.requires_explicit_human_install);
assertEqual('runtime activation latest selection false', false, runtimeActivationPreflight.selects_latest_profile);
assertEqual('runtime activation request authority false', false, runtimeActivationPreflight.request_stream_authority_material_accepted);
assertEqual('runtime activation live records false', false, runtimeActivationPreflight.uses_live_records_system);
assertEqual('runtime activation launcher config true', true, runtimeActivationPreflight.launcher_supplies_config);
assertEqual('runtime activation config path agent supplied false', false, runtimeActivationPreflight.config_path_agent_supplied);
assertEqual('runtime activation state path agent supplied false', false, runtimeActivationPreflight.state_path_agent_supplied);
assertEqual('runtime activation consumed grants path agent supplied false', false, runtimeActivationPreflight.consumed_grants_path_agent_supplied);
assertEqual('runtime activation grant anchor path agent supplied false', false, runtimeActivationPreflight.consumed_grant_store_anchor_path_agent_supplied);
assertEqual('runtime activation grant witness path agent supplied false', false, runtimeActivationPreflight.consumed_grant_store_witness_path_agent_supplied);
assertEqual('runtime activation recognition rule agent supplied false', false, runtimeActivationPreflight.recognition_rule_agent_supplied);
assertEqual('runtime activation issuer registry agent supplied false', false, runtimeActivationPreflight.issuer_registry_agent_supplied);
assertEqual('runtime activation authority contract required', true, runtimeActivationPreflight.authority_grant_contract_required_from_launcher);
assertEqual('runtime activation authority appointment required', true, runtimeActivationPreflight.authority_grant_appointment_required_from_launcher);
assertEqual('runtime activation issuance decision required', true, runtimeActivationPreflight.authority_grant_issuance_decision_required_from_launcher);
assertEqual('runtime activation authorized update required', true, runtimeActivationPreflight.authorized_record_update_required_from_launcher);
assertEqual('runtime activation downstream recognition true', true, runtimeActivationPreflight.downstream_recognition_required);
assertEqual('runtime activation missing receipt refused true', true, runtimeActivationPreflight.missing_or_unrecognized_receipt_refused);
assertEqual('runtime activation preflight run in proof pack', true, runtimeActivationPreflight.runtime_activation_preflight_run_in_proof_pack);
assertEqual('runtime activation runtime preflight run in proof pack', true, runtimeActivationPreflight.runtime_profile_preflight_run_in_proof_pack);
assertEqual('runtime activation runtime proof run in proof pack', true, runtimeActivationPreflight.runtime_profile_proof_run_in_proof_pack);
assertEqual('runtime activation runtime preflight type', PROTECTED_RECORDS_RUNTIME_PROFILE_PREFLIGHT_TYPE, runtimeActivationPreflight.runtime_profile_preflight_type);
assertEqual('runtime activation runtime preflight evidence model', 'local-disposable-runtime-profile-preflight-fixture', runtimeActivationPreflight.runtime_profile_preflight_evidence_model);
assertEqual('runtime activation runtime proof case count', RUNTIME_PREFLIGHT_PROFILE.required_cases.length, runtimeActivationPreflight.runtime_profile_proof_case_count);
assertEqual('runtime activation runtime proof required case count', RUNTIME_PREFLIGHT_PROFILE.required_cases.length, runtimeActivationPreflight.runtime_profile_proof_required_case_count);
assertEqual('runtime activation runtime boundary observation count', RUNTIME_PREFLIGHT_PROFILE.required_boundary_observations.length, runtimeActivationPreflight.runtime_profile_boundary_observation_count);
assertEqual('runtime activation runtime required boundary observation count', RUNTIME_PREFLIGHT_PROFILE.required_boundary_observations.length, runtimeActivationPreflight.runtime_profile_required_boundary_observation_count);
assertEqual('runtime activation recognized write accepted', true, runtimeActivationPreflight.recognized_write_accepted);
assertEqual('runtime activation route', RECORDS_WRITE_TERMINAL_ROUTE, runtimeActivationPreflight.mutation_authoritative_route);
assertEqual('runtime activation consumed grant store', 'persistent-single-use-authority-grant-contract-sha256-store', runtimeActivationPreflight.consumed_authority_grant_store);
assertEqual('runtime activation consumption identity', 'authority-grant-contract-sha256', runtimeActivationPreflight.consumption_identity);
assertEqual('runtime activation signed replay identity', 'verified-signed-payload-sha256', runtimeActivationPreflight.signed_payload_replay_identity);
assertEqual('runtime activation store witness', 'launcher-owned-local-store-hash-witness', runtimeActivationPreflight.consumed_store_witness);
assertEqual('runtime activation store write model', 'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness', runtimeActivationPreflight.consumed_store_write_model);
assertEqual('runtime activation same-process signed replay refused', true, runtimeActivationPreflight.same_process_signed_payload_replay_refused);
assertEqual('runtime activation restart grant replay refused', true, runtimeActivationPreflight.restart_consumed_authority_grant_refused);
assertEqual('runtime activation grant rollback refused', true, runtimeActivationPreflight.consumed_authority_grant_store_rollback_refused);
assertEqual('runtime activation grant deletion refused', true, runtimeActivationPreflight.consumed_authority_grant_store_deletion_refused);
assertEqual('runtime activation grant replacement refused', true, runtimeActivationPreflight.consumed_authority_grant_store_replacement_refused);
assertEqual('runtime activation witness commit failure refused', true, runtimeActivationPreflight.witness_commit_failed_after_authority_grant_store_commit);
assertEqual('runtime activation witness commit reason', 'consumed_store_write_failed_after_grant_commit', runtimeActivationPreflight.witness_commit_failure_reason_code);
assertEqual('runtime activation joint rollback refused against witness', true, runtimeActivationPreflight.store_and_anchor_joint_rollback_refused_against_witness);
assertEqual('runtime activation missing grant refused', true, runtimeActivationPreflight.missing_authority_grant_appointment_refused);
assertEqual('runtime activation mismatched grant refused', true, runtimeActivationPreflight.mismatched_authority_grant_appointment_refused);
assertEqual('runtime activation revoked grant refused', true, runtimeActivationPreflight.revoked_authority_grant_refused);
assertEqual('runtime activation expired grant refused', true, runtimeActivationPreflight.expired_authority_grant_refused);
assertEqual('runtime activation request grant refused', true, runtimeActivationPreflight.request_supplied_authority_grant_refused);
assertEqual('runtime activation authority material refused', true, runtimeActivationPreflight.agent_supplied_authority_material_refused);
assertRuntimeProfileIdentitySummary('runtime activation preflight component', runtimeActivationPreflight);
assertEqual('runtime activation persistent profile installed false', false, runtimeActivationPreflight.persistent_runtime_profile_installed);
assertEqual('runtime activation live records checked false', false, runtimeActivationPreflight.live_records_system_checked);
assertEqual('runtime activation production service checked false', false, runtimeActivationPreflight.production_records_service_checked);
assertEqual('runtime activation live MCP checked false', false, runtimeActivationPreflight.live_mcp_coverage_checked);
assertEqual('runtime activation approval health checked false', false, runtimeActivationPreflight.live_approval_channel_health_checked);
assertEqual('runtime activation external attestation false', false, runtimeActivationPreflight.external_attestation);
assertEqual('runtime activation sovereign recognition false', false, runtimeActivationPreflight.sovereign_recognition);
assertEqual('runtime activation witness-ahead rollback refused', true, runtimeActivationPreflight.store_and_anchor_joint_rollback_refused_while_witness_ahead);
assertEqual('runtime activation joint rollback detection false', false, runtimeActivationPreflight.store_anchor_and_witness_joint_rollback_detection);
assertEqual('runtime activation joint rollback reopens grant reuse', true, runtimeActivationPreflight.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse);
assertEqual('runtime activation atomic triple commit false', false, runtimeActivationPreflight.atomic_store_anchor_witness_commit);
assertEqual('runtime activation burn window named', true, runtimeActivationPreflight.partial_grant_commit_burn_window_named);
assertEqual('runtime activation host path TOCTOU false', false, runtimeActivationPreflight.host_filesystem_path_toctou_closed);
assertEqual('runtime activation fixture rightful issuance true', true, runtimeActivationPreflight.fixture_rightful_issuance_path_evidenced);
assertEqual('runtime activation generic rightful issuance false', false, runtimeActivationPreflight.rightful_issuance_proven);
assertEqual('runtime activation portable rightful issuance false', false, runtimeActivationPreflight.portable_rightful_issuance_proven);
assertEqual('runtime activation live authority false', false, runtimeActivationPreflight.live_authority_proven);
assertEqual('runtime activation production rightful issuance false', false, runtimeActivationPreflight.production_rightful_issuance_proven);
assertEqual('runtime activation current-machine governance false', false, runtimeActivationPreflight.current_machine_governance_proven);
assertEqual('runtime activation lifecycle closure false', false, runtimeActivationPreflight.consequence_lifecycle_closed);
assertEqual('runtime activation unrouted records checked false', false, runtimeActivationPreflight.unrouted_records_paths_checked);
for (const requirement of RUNTIME_ACTIVATION_PLAN.operator_install_requirements) {
  assert(`runtime activation install requirement present: ${requirement}`, runtimeActivationPreflight.operator_install_requirements.includes(requirement));
}
for (const boundary of RUNTIME_ACTIVATION_PLAN.known_open_boundaries) {
  assert(`runtime activation open boundary present: ${boundary}`, runtimeActivationPreflight.known_open_boundaries.includes(boundary));
}
for (const nonClaim of RUNTIME_ACTIVATION_PREFLIGHT_NON_CLAIMS) {
  assert(`runtime activation non-claim present: ${nonClaim}`, runtimeActivationPreflight.preflight_non_claims.includes(nonClaim));
}

section('protected records runtime local activation component');
const runtimeLocalActivation = component(report, 'protected_records_runtime_local_activation');
assert('runtime local activation component present', Boolean(runtimeLocalActivation));
assertEqual('runtime local activation proof type', PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_PROOF_TYPE, runtimeLocalActivation.proof_type);
assertEqual('runtime local activation evidence model', 'local-disposable-runtime-activation-fixture', runtimeLocalActivation.evidence_model);
assertEqual('runtime local activation live probing false', false, runtimeLocalActivation.live_probing);
assertEqual('runtime local activation safe claim ceiling', RUNTIME_LOCAL_ACTIVATION_SAFE_CLAIM_CEILING, runtimeLocalActivation.safe_claim_ceiling);
assertEqual('runtime local activation command named', RUNTIME_LOCAL_ACTIVATION_PLAN.local_activation_command, runtimeLocalActivation.local_activation_command);
assertEqual('runtime local activation plan type', 'zlar-protected-records-runtime-local-activation-plan-v1', runtimeLocalActivation.plan_type);
assertEqual('runtime local activation plan id', 'protected-records-runtime-local-activation-fixture-plan', runtimeLocalActivation.plan_id);
assertEqual('runtime local activation plan sha', RUNTIME_LOCAL_ACTIVATION_PLAN_SHA256, runtimeLocalActivation.plan_sha256);
assertEqual('runtime local activation plan status', 'sample_local_disposable_only', runtimeLocalActivation.plan_status);
assertEqual('runtime local activation deployment posture', 'local_disposable_activation_only', runtimeLocalActivation.deployment_posture);
assertEqual('runtime local activation action class', 'records.write', runtimeLocalActivation.action_class);
assertEqual('runtime local activation runtime profile id', 'protected-records-disposable-runtime-profile', runtimeLocalActivation.runtime_profile_id);
assertEqual('runtime local activation runtime profile source', 'profiles/protected-records-runtime-fixture.profile.json', runtimeLocalActivation.runtime_profile_source);
assertEqual('runtime local activation runtime profile sha', RUNTIME_PREFLIGHT_PROFILE_SHA256, runtimeLocalActivation.runtime_profile_sha256);
assertEqual('runtime local activation profile sha matches plan', true, runtimeLocalActivation.runtime_profile_sha_matches_plan);
assertEqual('runtime local activation active profile selection type', RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_TYPE, runtimeLocalActivation.active_profile_selection.selection_type);
assertEqual('runtime local activation active profile selection scope', RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_SCOPE, runtimeLocalActivation.active_profile_selection.selection_scope);
assertEqual('runtime local activation active profile selected', true, runtimeLocalActivation.active_profile_selection.selected);
assertEqual('runtime local activation active profile source', 'explicit-plan-and-profile-inputs', runtimeLocalActivation.active_profile_selection.selection_source);
assertEqual('runtime local activation active profile action class', 'records.write', runtimeLocalActivation.active_profile_selection.action_class);
assertEqual('runtime local activation active profile route', RECORDS_WRITE_TERMINAL_ROUTE, runtimeLocalActivation.active_profile_selection.route);
assertEqual('runtime local activation active profile downstream', RECORDS_WRITE_TERMINAL_DOWNSTREAM_BOUNDARY, runtimeLocalActivation.active_profile_selection.downstream_boundary);
assertEqual('runtime local activation active profile plan sha', RUNTIME_LOCAL_ACTIVATION_PLAN_SHA256, runtimeLocalActivation.active_profile_selection.plan_sha256);
assertEqual('runtime local activation active profile id', 'protected-records-runtime-fixture-profile', runtimeLocalActivation.active_profile_selection.profile_id);
assertEqual('runtime local activation active runtime profile id', 'protected-records-disposable-runtime-profile', runtimeLocalActivation.active_profile_selection.runtime_profile_id);
assertEqual('runtime local activation active profile status before selection', 'sample_not_active', runtimeLocalActivation.active_profile_selection.profile_status_before_selection);
assertEqual('runtime local activation active profile sha', RUNTIME_PREFLIGHT_PROFILE_SHA256, runtimeLocalActivation.active_profile_selection.runtime_profile_sha256);
assertEqual('runtime local activation active profile sha matches plan', true, runtimeLocalActivation.active_profile_selection.runtime_profile_sha_matches_plan);
assertEqual('runtime local activation active profile latest false', false, runtimeLocalActivation.active_profile_selection.selects_latest_profile);
assertEqual('runtime local activation active profile persistent install false', false, runtimeLocalActivation.active_profile_selection.persistent_runtime_profile_installed);
assertEqual('runtime local activation active profile live check false', false, runtimeLocalActivation.active_profile_selection.live_runtime_profile_checked);
assertEqual('runtime local activation active profile hook config false', false, runtimeLocalActivation.active_profile_selection.hook_configuration_written);
assertEqual('runtime local activation proof command', 'zlar protected-records-runtime-profile-proof', runtimeLocalActivation.runtime_profile_proof_command);
assertEqual('runtime local activation service command', 'zlar protected-records-runtime-service --config <launcher-owned-disposable-config>', runtimeLocalActivation.service_command);
assertEqual('runtime local activation run in proof pack', true, runtimeLocalActivation.runtime_local_activation_run_in_proof_pack);
assertEqual('runtime local activation runtime proof run', true, runtimeLocalActivation.runtime_profile_proof_run_in_proof_pack);
assertEqual('runtime local activation runtime proof cases', RUNTIME_PREFLIGHT_PROFILE.required_cases.length, runtimeLocalActivation.runtime_profile_proof_case_count);
assertEqual('runtime local activation runtime proof required cases', RUNTIME_PREFLIGHT_PROFILE.required_cases.length, runtimeLocalActivation.runtime_profile_proof_required_case_count);
assertEqual('runtime local activation runtime boundary observations', RUNTIME_PREFLIGHT_PROFILE.required_boundary_observations.length, runtimeLocalActivation.runtime_profile_boundary_observation_count);
assertEqual('runtime local activation runtime required boundary observations', RUNTIME_PREFLIGHT_PROFILE.required_boundary_observations.length, runtimeLocalActivation.runtime_profile_required_boundary_observation_count);
assertEqual('runtime local activation recognized write accepted', true, runtimeLocalActivation.recognized_write_accepted);
assertEqual('runtime local activation route', RECORDS_WRITE_TERMINAL_ROUTE, runtimeLocalActivation.mutation_authoritative_route);
assertEqual('runtime local activation consumed grant store', 'persistent-single-use-authority-grant-contract-sha256-store', runtimeLocalActivation.consumed_authority_grant_store);
assertEqual('runtime local activation consumption identity', 'authority-grant-contract-sha256', runtimeLocalActivation.consumption_identity);
assertEqual('runtime local activation signed replay identity', 'verified-signed-payload-sha256', runtimeLocalActivation.signed_payload_replay_identity);
assertEqual('runtime local activation store witness', 'launcher-owned-local-store-hash-witness', runtimeLocalActivation.consumed_store_witness);
assertEqual('runtime local activation store write model', 'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness', runtimeLocalActivation.consumed_store_write_model);
assertEqual('runtime local activation same-process signed replay refused', true, runtimeLocalActivation.same_process_signed_payload_replay_refused);
assertEqual('runtime local activation restart consumed grant refused', true, runtimeLocalActivation.restart_consumed_authority_grant_refused);
assertEqual('runtime local activation witness commit failure refused', true, runtimeLocalActivation.witness_commit_failed_after_authority_grant_store_commit);
assertEqual('runtime local activation witness commit reason', 'consumed_store_write_failed_after_grant_commit', runtimeLocalActivation.witness_commit_failure_reason_code);
assertEqual('runtime local activation joint rollback refused against witness', true, runtimeLocalActivation.store_and_anchor_joint_rollback_refused_against_witness);
assertEqual('runtime local activation missing grant refused', true, runtimeLocalActivation.missing_authority_grant_appointment_refused);
assertEqual('runtime local activation mismatched grant refused', true, runtimeLocalActivation.mismatched_authority_grant_appointment_refused);
assertEqual('runtime local activation revoked grant refused', true, runtimeLocalActivation.revoked_authority_grant_refused);
assertEqual('runtime local activation expired grant refused', true, runtimeLocalActivation.expired_authority_grant_refused);
assertEqual('runtime local activation request grant refused', true, runtimeLocalActivation.request_supplied_authority_grant_refused);
assertEqual('runtime local activation missing receipt refused', true, runtimeLocalActivation.missing_receipt_refused);
assertEqual('runtime local activation invalid receipt refused', true, runtimeLocalActivation.invalid_receipt_refused);
assertEqual('runtime local activation unknown issuer refused', true, runtimeLocalActivation.unknown_issuer_refused);
assertEqual('runtime local activation retired issuer refused', true, runtimeLocalActivation.retired_issuer_refused);
assertEqual('runtime local activation missing issuer status refused', true, runtimeLocalActivation.missing_issuer_status_refused);
assertEqual('runtime local activation stale receipt refused', true, runtimeLocalActivation.stale_receipt_refused);
assertEqual('runtime local activation wrong policy refused', true, runtimeLocalActivation.wrong_policy_refused);
assertEqual('runtime local activation wrong domain refused', true, runtimeLocalActivation.wrong_domain_refused);
assertEqual('runtime local activation wrong tool refused', true, runtimeLocalActivation.wrong_tool_refused);
assertEqual('runtime local activation wrong runtime profile id refused', true, runtimeLocalActivation.wrong_runtime_profile_id_refused);
assertEqual('runtime local activation wrong audit event refused', true, runtimeLocalActivation.wrong_audit_event_refused);
assertEqual('runtime local activation wrong detail refused', true, runtimeLocalActivation.wrong_detail_refused);
assertEqual('runtime local activation non-boarding outcome refused', true, runtimeLocalActivation.non_boarding_outcome_refused);
assertEqual('runtime local activation direct api without receipt refused', true, runtimeLocalActivation.direct_api_without_receipt_refused);
assertEqual('runtime local activation direct api with receipt refused', true, runtimeLocalActivation.direct_api_with_receipt_refused);
assertEqual('runtime local activation authority material refused', true, runtimeLocalActivation.agent_supplied_authority_material_refused);
assertRuntimeProfileIdentitySummary('runtime local activation component', runtimeLocalActivation);
assertEqual('runtime local activation applied true', true, runtimeLocalActivation.local_activation_applied);
assertEqual('runtime local activation disposable config written', true, runtimeLocalActivation.disposable_runtime_config_written);
assertEqual('runtime local activation persistent config false', false, runtimeLocalActivation.persistent_runtime_config_written);
assertEqual('runtime local activation hook config false', false, runtimeLocalActivation.hook_configuration_written);
assertEqual('runtime local activation runtime service started', true, runtimeLocalActivation.runtime_service_started);
assertEqual('runtime local activation persistent profile false', false, runtimeLocalActivation.persistent_runtime_profile_installed);
assertEqual('runtime local activation latest profile false', false, runtimeLocalActivation.latest_profile_selected);
assertEqual('runtime local activation request authority false', false, runtimeLocalActivation.request_stream_authority_material_accepted);
assertEqual('runtime local activation live records false', false, runtimeLocalActivation.live_records_system_checked);
assertEqual('runtime local activation production service false', false, runtimeLocalActivation.production_records_service_checked);
assertEqual('runtime local activation live MCP false', false, runtimeLocalActivation.live_mcp_coverage_checked);
assertEqual('runtime local activation live approval false', false, runtimeLocalActivation.live_approval_channel_health_checked);
assertEqual('runtime local activation exactly once false', false, runtimeLocalActivation.exactly_once_effect_semantics);
assertEqual('runtime local activation witness-ahead rollback refused', true, runtimeLocalActivation.store_and_anchor_joint_rollback_refused_while_witness_ahead);
assertEqual('runtime local activation joint rollback detection false', false, runtimeLocalActivation.store_anchor_and_witness_joint_rollback_detection);
assertEqual('runtime local activation joint rollback reopens grant reuse', true, runtimeLocalActivation.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse);
assertEqual('runtime local activation atomic triple commit false', false, runtimeLocalActivation.atomic_store_anchor_witness_commit);
assertEqual('runtime local activation burn window named', true, runtimeLocalActivation.partial_grant_commit_burn_window_named);
assertEqual('runtime local activation host path TOCTOU false', false, runtimeLocalActivation.host_filesystem_path_toctou_closed);
assertEqual('runtime local activation fixture rightful issuance true', true, runtimeLocalActivation.fixture_rightful_issuance_path_evidenced);
assertEqual('runtime local activation generic rightful issuance false', false, runtimeLocalActivation.rightful_issuance_proven);
assertEqual('runtime local activation portable rightful issuance false', false, runtimeLocalActivation.portable_rightful_issuance_proven);
assertEqual('runtime local activation live authority false', false, runtimeLocalActivation.live_authority_proven);
assertEqual('runtime local activation production rightful issuance false', false, runtimeLocalActivation.production_rightful_issuance_proven);
assertEqual('runtime local activation current-machine governance false', false, runtimeLocalActivation.current_machine_governance_proven);
assertEqual('runtime local activation lifecycle closure false', false, runtimeLocalActivation.consequence_lifecycle_closed);
assertEqual('runtime local activation external attestation false', false, runtimeLocalActivation.external_attestation);
assertEqual('runtime local activation sovereign recognition false', false, runtimeLocalActivation.sovereign_recognition);
assertEqual('runtime local activation unrouted records false', false, runtimeLocalActivation.unrouted_records_paths_checked);
for (const requirement of RUNTIME_LOCAL_ACTIVATION_PLAN.operator_requirements) {
  assert(`runtime local activation operator requirement present: ${requirement}`, runtimeLocalActivation.operator_requirements.includes(requirement));
}
for (const boundary of RUNTIME_LOCAL_ACTIVATION_PLAN.known_open_boundaries) {
  assert(`runtime local activation open boundary present: ${boundary}`, runtimeLocalActivation.known_open_boundaries.includes(boundary));
}
for (const nonClaim of RUNTIME_LOCAL_ACTIVATION_NON_CLAIMS) {
  assert(`runtime local activation non-claim present: ${nonClaim}`, runtimeLocalActivation.local_activation_non_claims.includes(nonClaim));
}

section('protected records runtime profile installation component');
const runtimeProfileInstallation = component(report, 'protected_records_runtime_profile_installation');
assert('runtime profile installation component present', Boolean(runtimeProfileInstallation));
assertEqual('runtime profile installation proof type', PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_PROOF_TYPE, runtimeProfileInstallation.proof_type);
assertEqual('runtime profile installation evidence model', 'local-disposable-runtime-profile-installation-fixture', runtimeProfileInstallation.evidence_model);
assertEqual('runtime profile installation live probing false', false, runtimeProfileInstallation.live_probing);
assertEqual('runtime profile installation safe claim ceiling', RUNTIME_PROFILE_INSTALLATION_SAFE_CLAIM_CEILING, runtimeProfileInstallation.safe_claim_ceiling);
assertEqual('runtime profile installation command named', RUNTIME_PROFILE_INSTALLATION_PLAN.installation_command, runtimeProfileInstallation.installation_command);
assertEqual('runtime profile installation plan sha', RUNTIME_PROFILE_INSTALLATION_PLAN_SHA256, runtimeProfileInstallation.plan_sha256);
assertEqual('runtime profile installation runtime profile sha', RUNTIME_PREFLIGHT_PROFILE_SHA256, runtimeProfileInstallation.runtime_profile_sha256);
assertEqual('runtime profile installation profile sha matches plan', true, runtimeProfileInstallation.runtime_profile_sha_matches_plan);
assertEqual('runtime profile installation run in proof pack', true, runtimeProfileInstallation.runtime_profile_installation_run_in_proof_pack);
assertEqual('runtime profile installation runtime proof run', true, runtimeProfileInstallation.runtime_profile_proof_run_in_proof_pack);
assertEqual('runtime profile installation runtime proof cases', RUNTIME_PREFLIGHT_PROFILE.required_cases.length, runtimeProfileInstallation.runtime_profile_proof_case_count);
assertEqual('runtime profile installation selected from root', true, runtimeProfileInstallation.disposable_profile_selection.profile_selected_from_install_root);
assertEqual('runtime profile installation selected by id and sha', true, runtimeProfileInstallation.disposable_profile_selection.selected_by_explicit_id_and_sha);
assertEqual('runtime profile installation no latest', false, runtimeProfileInstallation.disposable_profile_selection.selects_latest_profile);
assertEqual('runtime profile installation omitted root path', null, runtimeProfileInstallation.disposable_profile_selection.install_root_path_in_report);
assertEqual('runtime profile installation request guard refused', true, runtimeProfileInstallation.request_authority_guard_summary.all_refused_before_mutation);
assertEqual('runtime profile installation installed state refused', true, runtimeProfileInstallation.request_authority_guard_summary.installed_profile_state_refused);
assertEqual('runtime profile installation runtime config refused', true, runtimeProfileInstallation.request_authority_guard_summary.runtime_config_refused);
assertEqual('runtime profile installation runtime profile refused', true, runtimeProfileInstallation.request_authority_guard_summary.runtime_profile_refused);
assertEqual('runtime profile installation recognition rule refused', true, runtimeProfileInstallation.request_authority_guard_summary.recognition_rule_refused);
assertEqual('runtime profile installation authority grant refused', true, runtimeProfileInstallation.request_authority_guard_summary.authority_grant_refused);
assertEqual('runtime profile installation guard state delta zero', 0, runtimeProfileInstallation.request_authority_guard_summary.state_entry_count_delta_total);
assertEqual('runtime profile installation recognized write accepted', true, runtimeProfileInstallation.recognized_write_accepted);
assertEqual('runtime profile installation route', RECORDS_WRITE_TERMINAL_ROUTE, runtimeProfileInstallation.mutation_authoritative_route);
assertEqual('runtime profile installation consumed grant store', 'persistent-single-use-authority-grant-contract-sha256-store', runtimeProfileInstallation.consumed_authority_grant_store);
assertEqual('runtime profile installation consumption identity', 'authority-grant-contract-sha256', runtimeProfileInstallation.consumption_identity);
assertEqual('runtime profile installation signed replay identity', 'verified-signed-payload-sha256', runtimeProfileInstallation.signed_payload_replay_identity);
assertEqual('runtime profile installation store witness', 'launcher-owned-local-store-hash-witness', runtimeProfileInstallation.consumed_store_witness);
assertEqual('runtime profile installation store write model', 'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness', runtimeProfileInstallation.consumed_store_write_model);
assertEqual('runtime profile installation same-process signed replay refused', true, runtimeProfileInstallation.same_process_signed_payload_replay_refused);
assertEqual('runtime profile installation restart consumed grant refused', true, runtimeProfileInstallation.restart_consumed_authority_grant_refused);
assertEqual('runtime profile installation missing grant refused', true, runtimeProfileInstallation.missing_authority_grant_appointment_refused);
assertEqual('runtime profile installation mismatched grant refused', true, runtimeProfileInstallation.mismatched_authority_grant_appointment_refused);
assertEqual('runtime profile installation revoked grant refused', true, runtimeProfileInstallation.revoked_authority_grant_refused);
assertEqual('runtime profile installation expired grant refused', true, runtimeProfileInstallation.expired_authority_grant_refused);
assertEqual('runtime profile installation request grant refused', true, runtimeProfileInstallation.request_supplied_authority_grant_refused);
assertEqual('runtime profile installation missing receipt refused', true, runtimeProfileInstallation.missing_receipt_refused);
assertEqual('runtime profile installation invalid receipt refused', true, runtimeProfileInstallation.invalid_receipt_refused);
assertEqual('runtime profile installation unknown issuer refused', true, runtimeProfileInstallation.unknown_issuer_refused);
assertEqual('runtime profile installation retired issuer refused', true, runtimeProfileInstallation.retired_issuer_refused);
assertEqual('runtime profile installation missing issuer status refused', true, runtimeProfileInstallation.missing_issuer_status_refused);
assertEqual('runtime profile installation stale receipt refused', true, runtimeProfileInstallation.stale_receipt_refused);
assertEqual('runtime profile installation wrong policy refused', true, runtimeProfileInstallation.wrong_policy_refused);
assertEqual('runtime profile installation wrong domain refused', true, runtimeProfileInstallation.wrong_domain_refused);
assertEqual('runtime profile installation wrong tool refused', true, runtimeProfileInstallation.wrong_tool_refused);
assertEqual('runtime profile installation wrong runtime profile id refused', true, runtimeProfileInstallation.wrong_runtime_profile_id_refused);
assertEqual('runtime profile installation wrong audit event refused', true, runtimeProfileInstallation.wrong_audit_event_refused);
assertEqual('runtime profile installation wrong detail refused', true, runtimeProfileInstallation.wrong_detail_refused);
assertEqual('runtime profile installation non-boarding outcome refused', true, runtimeProfileInstallation.non_boarding_outcome_refused);
assertEqual('runtime profile installation direct api with receipt refused', true, runtimeProfileInstallation.direct_api_with_receipt_refused);
assertEqual('runtime profile installation authority material refused', true, runtimeProfileInstallation.agent_supplied_authority_material_refused);
assertRuntimeProfileIdentitySummary('runtime profile installation component', runtimeProfileInstallation);
assertEqual('runtime profile installation applied true', true, runtimeProfileInstallation.disposable_profile_installation_applied);
assertEqual('runtime profile installation disposable config written', true, runtimeProfileInstallation.disposable_runtime_config_written);
assertEqual('runtime profile installation persistent config false', false, runtimeProfileInstallation.persistent_runtime_config_written);
assertEqual('runtime profile installation hook config false', false, runtimeProfileInstallation.hook_configuration_written);
assertEqual('runtime profile installation user config false', false, runtimeProfileInstallation.user_config_written);
assertEqual('runtime profile installation machine config false', false, runtimeProfileInstallation.machine_config_written);
assertEqual('runtime profile installation service started true', true, runtimeProfileInstallation.runtime_service_started);
assertEqual('runtime profile installation persistent profile false', false, runtimeProfileInstallation.persistent_runtime_profile_installed);
assertEqual('runtime profile installation live runtime profile false', false, runtimeProfileInstallation.live_runtime_profile_checked);
assertEqual('runtime profile installation live records false', false, runtimeProfileInstallation.live_records_system_checked);
assertEqual('runtime profile installation production service false', false, runtimeProfileInstallation.production_records_service_checked);
assertEqual('runtime profile installation exactly once false', false, runtimeProfileInstallation.exactly_once_effect_semantics);
assertEqual('runtime profile installation joint rollback detection false', false, runtimeProfileInstallation.store_anchor_and_witness_joint_rollback_detection);
assertEqual('runtime profile installation atomic triple commit false', false, runtimeProfileInstallation.atomic_store_anchor_witness_commit);
assertEqual('runtime profile installation burn window named', true, runtimeProfileInstallation.partial_grant_commit_burn_window_named);
assertEqual('runtime profile installation host path TOCTOU false', false, runtimeProfileInstallation.host_filesystem_path_toctou_closed);
assertEqual('runtime profile installation fixture rightful issuance true', true, runtimeProfileInstallation.fixture_rightful_issuance_path_evidenced);
assertEqual('runtime profile installation generic rightful issuance false', false, runtimeProfileInstallation.rightful_issuance_proven);
assertEqual('runtime profile installation portable rightful issuance false', false, runtimeProfileInstallation.portable_rightful_issuance_proven);
assertEqual('runtime profile installation live authority false', false, runtimeProfileInstallation.live_authority_proven);
assertEqual('runtime profile installation production rightful issuance false', false, runtimeProfileInstallation.production_rightful_issuance_proven);
assertEqual('runtime profile installation current-machine governance false', false, runtimeProfileInstallation.current_machine_governance_proven);
assertEqual('runtime profile installation lifecycle closure false', false, runtimeProfileInstallation.consequence_lifecycle_closed);
assertEqual('runtime profile installation external attestation false', false, runtimeProfileInstallation.external_attestation);
assertEqual('runtime profile installation sovereign recognition false', false, runtimeProfileInstallation.sovereign_recognition);
for (const requirement of REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPERATOR_REQUIREMENTS) {
  assert(`runtime profile installation operator requirement present: ${requirement}`, runtimeProfileInstallation.operator_requirements.includes(requirement));
}
for (const boundary of REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPEN_BOUNDARIES) {
  assert(`runtime profile installation open boundary present: ${boundary}`, runtimeProfileInstallation.known_open_boundaries.includes(boundary));
}
for (const nonClaim of RUNTIME_PROFILE_INSTALLATION_NON_CLAIMS) {
  assert(`runtime profile installation non-claim present: ${nonClaim}`, runtimeProfileInstallation.profile_installation_non_claims.includes(nonClaim));
}

section('Claude Code hook-contract replay component');
const claudeHookReplay = component(report, 'claude_code_hook_contract_replay');
assert('Claude hook replay component present', Boolean(claudeHookReplay));
assertEqual('Claude hook replay proof type', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_TYPE, claudeHookReplay.proof_type);
assertEqual('Claude hook replay command named', 'zlar claude-code-hook-contract-replay-proof', claudeHookReplay.command);
assertEqual('Claude hook replay evidence model', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_EVIDENCE_MODEL, claudeHookReplay.evidence_model);
assertEqual('Claude hook replay live probing false', false, claudeHookReplay.live_probing);
assertEqual('Claude hook replay adapter source repo', 'repo', claudeHookReplay.adapter_source);
assertEqual('Claude hook replay adapter path repo relative', 'repo:adapters/claude-code/hook.sh', claudeHookReplay.adapter_path_claimed);
assert('Claude hook replay adapter hash shape', /^[a-f0-9]{64}$/.test(claudeHookReplay.adapter_sha256));
assertEqual('Claude hook replay adapter hash bound to repo adapter', claudeCodeHookContractReplayRepoAdapterSha256(), claudeHookReplay.adapter_sha256);
assertEqual('Claude hook replay contract hash bound', claudeCodeHookContractReplayContractSha256(), claudeHookReplay.hook_replay_contract_sha256);
assertEqual('Claude hook replay proof-pack source boundary exact', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY, claudeHookReplay.source_state_boundary);
assertEqual(
  'Claude hook replay case evidence hash scope exact',
  'canonical hook replay case, normalized input-contract, sentinel, marker, audit-delta, and supporting-boarding evidence embedded in local proof pack',
  claudeHookReplay.case_evidence_hash_scope
);
assertEqual(
  'Claude hook replay case evidence hash bound',
  createHash('sha256').update(canonicalize(claudeHookReplay.case_evidence), 'utf8').digest('hex'),
  claudeHookReplay.case_evidence_sha256
);
assertEqual(
  'Claude hook replay case evidence type',
  'zlar-local-proof-pack-claude-hook-contract-replay-case-evidence-v1',
  claudeHookReplay.case_evidence.evidence_type
);
assertEqual('Claude hook replay case evidence count', REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES.length, claudeHookReplay.case_evidence.cases.length);
for (const expected of REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES) {
  const item = claudeHookReplay.case_evidence.cases.find((candidate) => candidate.case_id === expected.case_id);
  assert(`Claude hook replay case evidence present: ${expected.case_id}`, Boolean(item));
  assertEqual(
    `Claude hook replay input contract bound: ${expected.case_id}`,
    claudeCodeHookContractReplayInputContractSha256(expected.case_id),
    item.input_contract_sha256,
  );
}
assertEqual('Claude hook replay case evidence sentinel unchanged', true, claudeHookReplay.case_evidence.sentinel.unchanged);
assertEqual('Claude hook replay case evidence sentinel not executed', false, claudeHookReplay.case_evidence.sentinel.denied_effect_executed);
assertEqual('Claude hook replay case evidence marker not executed', false, claudeHookReplay.case_evidence.marker.tool_input_command_executed);
assertEqual('Claude hook replay case evidence supporting boarding passed', true, claudeHookReplay.case_evidence.supporting_local_boarding_proof.passed);
assertEqual('Claude hook replay case evidence supporting boarding v1 identity verified', true, claudeHookReplay.case_evidence.supporting_local_boarding_proof.v1_receipt_identity_verified);
assertEqual('Claude hook replay case evidence supporting boarding refusal consequence absent', true, claudeHookReplay.case_evidence.supporting_local_boarding_proof.consequence_absent_on_every_refusal);
assertEqual('Claude hook replay case evidence supporting boarding acceptance consequence once', true, claudeHookReplay.case_evidence.supporting_local_boarding_proof.consequence_present_exactly_once_on_acceptance);
assertEqual('Claude hook replay case evidence supporting boarding v0 not recognized', false, claudeHookReplay.case_evidence.supporting_local_boarding_proof.legacy_v0_recognized_boarding_identity);
assertEqual('Claude hook replay required case count', REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES.length, claudeHookReplay.required_case_count);
assertEqual('Claude hook replay required cases present', true, claudeHookReplay.all_required_cases_present);
assertEqual('Claude hook replay allow JSON observed', true, claudeHookReplay.permission_decisions_observed.allow);
assertEqual('Claude hook replay deny JSON observed', true, claudeHookReplay.permission_decisions_observed.deny);
assertEqual('Claude hook replay denied effect not executed', true, claudeHookReplay.denied_effect_not_executed);
assertEqual('Claude hook replay tool input not executed', true, claudeHookReplay.tool_input_not_executed);
assertEqual('Claude hook replay missing gate fail closed', true, claudeHookReplay.missing_gate_failed_closed);
assertEqual('Claude hook replay blank gate fail closed', true, claudeHookReplay.blank_gate_response_failed_closed);
assertEqual('Claude hook replay malformed output refused', true, claudeHookReplay.malformed_output_refused);
assertEqual('Claude hook replay non-PreToolUse payload denied by fixture gate', true, claudeHookReplay.non_pretooluse_payload_denied_by_fixture_gate);
assertEqual('Claude hook replay supporting local boarding passed', true, claudeHookReplay.supporting_local_boarding_proof_passed);
assertEqual('Claude hook replay supporting local boarding type', 'zlar-protected-records-local-boarding-proof-v1', claudeHookReplay.supporting_local_boarding_proof_type);
assertEqual('Claude hook replay supporting local boarding v1 identity verified', true, claudeHookReplay.supporting_local_boarding_v1_receipt_identity_verified);
assertEqual('Claude hook replay supporting local boarding refusal consequence absent', true, claudeHookReplay.supporting_local_boarding_consequence_absent_on_every_refusal);
assertEqual('Claude hook replay supporting local boarding acceptance consequence once', true, claudeHookReplay.supporting_local_boarding_consequence_present_exactly_once_on_acceptance);
assertEqual('Claude hook replay supporting local boarding v0 not recognized', false, claudeHookReplay.supporting_local_boarding_legacy_v0_recognized_boarding_identity);
assertEqual('Claude hook replay safe claim ceiling', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SAFE_CLAIM_CEILING, claudeHookReplay.safe_claim_ceiling);
for (const field of [
  'live_claude_invoked',
  'live_claude_app_passage_proven',
  'app_originated_hook_crossing_proven',
  'live_receipt_emission_proven',
  'current_machine_governance_proven',
  'production_downstream_recognition_proven',
  'all_surface_governance_proven',
  'side_door_closure_proven',
]) {
  assertEqual(`Claude hook replay ${field} false`, false, claudeHookReplay[field]);
}
for (const expected of REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES) {
  assert(`Claude hook replay required case present: ${expected.case_id}`, claudeHookReplay.required_cases.includes(expected.case_id));
}
for (const nonClaim of CLAUDE_CODE_HOOK_CONTRACT_REPLAY_NON_CLAIMS) {
  assert(`Claude hook replay non-claim present: ${nonClaim}`, claudeHookReplay.non_claims.includes(nonClaim));
}
assertEqual(
  'Claude hook replay side doors exact',
  JSON.stringify(REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SIDE_DOORS),
  JSON.stringify(claudeHookReplay.side_doors)
);
for (const sideDoor of [
  'live Claude Code app-originated hook passage',
  'direct shell/filesystem outside Claude Code',
  'Cursor, Windsurf, Codex, and other AI client surfaces',
  'direct MCP registrations bypassing the Claude Code hook',
  'unrouted records paths and production downstream systems',
]) {
  assert(`Claude hook replay side door present: ${sideDoor}`, claudeHookReplay.side_doors.includes(sideDoor));
}

section('issuer status component');
const issuerStatus = component(report, 'issuer_status_proof');
assert('issuer status component present', Boolean(issuerStatus));
assertEqual('issuer status command named', 'zlar issuer-status-proof', issuerStatus.command);
assertEqual('issuer status trust anchor fixture', 'local-fixture-recognition-rule', issuerStatus.trust_anchor_model);
assertEqual('issuer status active boards', true, issuerStatus.active_issuer_boarded);
assertEqual('issuer status retired refuses', true, issuerStatus.retired_issuer_refused);
assertEqual('issuer status compromised refuses', true, issuerStatus.compromised_issuer_refused);
assertEqual('issuer status missing status refuses', true, issuerStatus.missing_status_issuer_refused);
assertEqual('issuer status unknown refuses', true, issuerStatus.unknown_issuer_refused);
assertEqual('issuer status missing key refuses', true, issuerStatus.missing_key_issuer_refused);
for (const reason of ISSUER_STATUS_REFUSAL_REASONS) {
  assert(`issuer status refusal reason present: ${reason}`, issuerStatus.refusal_reasons.includes(reason));
}

section('trusted issuer registry recognition component');
const trustedIssuerRegistryRecognition = component(report, 'trusted_issuer_registry_recognition');
assert('trusted issuer registry recognition component present', Boolean(trustedIssuerRegistryRecognition));
assertEqual('trusted issuer registry recognition command', 'embedded local proof-pack trusted issuer registry recognition fixture', trustedIssuerRegistryRecognition.command);
assertEqual('trusted issuer registry recognition evidence model', 'fresh-local-fixture-trusted-issuer-registry-recognition', trustedIssuerRegistryRecognition.evidence_model);
assertEqual('trusted issuer registry recognition registry type', 'trusted-receipt-issuers-v2', trustedIssuerRegistryRecognition.registry_type);
assertEqual('trusted issuer registry recognition fixture model', 'bundled-local-fixture-no-secret-registry-contract', trustedIssuerRegistryRecognition.registry_evidence_model);
assertEqual('trusted issuer registry recognition no live probing', false, trustedIssuerRegistryRecognition.live_probing);
assertEqual('trusted issuer registry recognition fixture validated', true, trustedIssuerRegistryRecognition.registry_fixture_validated);
assertEqual('trusted issuer registry recognition fixture evaluated', true, trustedIssuerRegistryRecognition.registry_fixture_evaluated);
assertEqual('trusted issuer registry recognition rule path evaluated', true, trustedIssuerRegistryRecognition.registry_to_recognition_rule_evaluated);
assertEqual('trusted issuer registry recognition evaluator result type', 'downstream-recognition-rule-v1', trustedIssuerRegistryRecognition.registry_evaluation_result_type);
assertEqual('trusted issuer registry recognition issuer count', 1, trustedIssuerRegistryRecognition.registry_trusted_issuer_count);
assertEqual('trusted issuer registry recognition verdict', 'RECOGNIZED', trustedIssuerRegistryRecognition.verdict);
assertEqual('trusted issuer registry recognition recognized', true, trustedIssuerRegistryRecognition.recognized);
assertEqual('trusted issuer registry recognition decision', 'accept', trustedIssuerRegistryRecognition.decision);
assertEqual('trusted issuer registry recognition reason', 'recognized', trustedIssuerRegistryRecognition.reason_code);
assertEqual('trusted issuer registry recognition issuer active', 'active', trustedIssuerRegistryRecognition.issuer_status);
assertEqual('trusted issuer registry recognition signature valid', true, trustedIssuerRegistryRecognition.signature_valid);
assertEqual('trusted issuer registry recognition audit event bound', true, trustedIssuerRegistryRecognition.required_audit_event_id_bound);
assertEqual('trusted issuer registry recognition detail hash bound', true, trustedIssuerRegistryRecognition.required_detail_hash_bound);
assertEqual('trusted issuer registry recognition malformed unsupported field', true, trustedIssuerRegistryRecognition.malformed_registry_unsupported_field);
assertEqual('trusted issuer registry recognition malformed error', 'unsupported_registry_field', trustedIssuerRegistryRecognition.malformed_registry_error_code);
assertEqual('trusted issuer registry recognition malformed fail closed', true, trustedIssuerRegistryRecognition.malformed_registry_fail_closed_before_verdict);
for (const field of [
  'live_trust_registry_state',
  'live_issuer_status_proven',
  'key_custody_proven',
  'revocation_truth_proven',
  'production_trust_registry_proven',
  'production_downstream_recognition_proven',
  'production_authority',
  'public_external_attestation',
  'real_non_operator_review',
  'sovereign_recognition',
  'current_machine_governance_proven',
]) {
  assertEqual(`trusted issuer registry recognition ${field} false`, false, trustedIssuerRegistryRecognition[field]);
}
assert(
  'trusted issuer registry recognition non-claims name fixture boundary',
  trustedIssuerRegistryRecognition.non_claims.some((item) =>
    item.includes('bundled local trusted-issuer registry fixture')
  ),
);

section('key-state component');
const keyState = component(report, 'key_state_report');
assert('key-state component present', Boolean(keyState));
assertEqual('key-state command named', 'zlar key-state --sample --json', keyState.command);
assertEqual('key-state report type', KEY_STATE_REPORT_TYPE, keyState.report_type);
assertEqual('key-state evidence model', 'local-read-only-key-state', keyState.evidence_model);
assertEqual('key-state live probing false', false, keyState.live_probing);
assertEqual('key-state read-only true', true, keyState.read_only);
assertEqual('key-state policy posture', 'software-rooted-current', keyState.operational_posture.policy_manifest_constitution);
assertEqual('key-state private key material read false', false, keyState.privacy.private_key_material_read);
assertEqual('key-state private key material included false', false, keyState.privacy.private_key_material_included);
assertEqual('key-state private key paths included false', false, keyState.privacy.private_key_paths_included);
assertEqual('key-state YubiKey serials omitted', false, keyState.privacy.yubi_key_serial_numbers_included);
assertEqual('key-state sample legacy private key absent', false, keyState.local_private_key_presence.legacy_software_signing_key_present);
assertEqual('key-state private key bytes read false', false, keyState.local_private_key_presence.private_key_bytes_read);
assertEqual('key-state policy software pin alignment boolean', 'boolean', typeof keyState.policy_software_pins_aligned);
assertEqual('key-state constitution software pin alignment boolean', 'boolean', typeof keyState.constitution_software_pins_aligned);
assertEqual('key-state policy hardware unobserved', false, keyState.policy_hardware_target_observed);
assertEqual('key-state constitution hardware unobserved', false, keyState.constitution_hardware_target_observed);
assertEqual('key-state spec hardware unobserved', false, keyState.spec_hardware_target_observed);
assertEqual('key-state no custody proof', false, keyState.key_custody_proven);
assertEqual('key-state no revocation proof', false, keyState.revocation_state_proven);
assertEqual('key-state no trust registry proof', false, keyState.production_trust_registry_proven);
assertEqual('key-state no current-machine governance proof', false, keyState.current_machine_governance_proven);
assertEqual('key-state no external attestation', false, keyState.external_attestation);
assertEqual('key-state no sovereign recognition', false, keyState.sovereign_recognition);
for (const claim of KEY_STATE_NON_CLAIMS) {
  assert(`key-state non-claim present: ${claim}`, keyState.non_claims.includes(claim));
}

section('receipt verifier boundary component');
const receiptVerifierBoundary = component(report, 'receipt_verifier_boundary');
assert('receipt verifier boundary component present', Boolean(receiptVerifierBoundary));
assertEqual('receipt verifier boundary proof type', RECEIPT_VERIFIER_BOUNDARY_PROOF_TYPE, receiptVerifierBoundary.proof_type);
assertEqual('receipt verifier boundary evidence model', 'local-ephemeral-receipt-verifier-fixture', receiptVerifierBoundary.evidence_model);
assertEqual('receipt verifier boundary live probing false', false, receiptVerifierBoundary.live_probing);
assertEqual('receipt verifier boundary safe claim ceiling', RECEIPT_VERIFIER_BOUNDARY_SAFE_CLAIM_CEILING, receiptVerifierBoundary.safe_claim_ceiling);
assertEqual('receipt verifier boundary command', 'zlar-verify <receipt.json> --pubkey <key.pub> --json', receiptVerifierBoundary.command);
assertEqual('receipt verifier boundary receipt version', 'v1', receiptVerifierBoundary.receipt_version);
assertEqual('receipt verifier boundary receipt type', 'governed-action', receiptVerifierBoundary.receipt_type);
assertEqual('receipt verifier boundary signed bytes checked', true, receiptVerifierBoundary.signed_byte_integrity_checked);
assertEqual('receipt verifier boundary semantics checked', true, receiptVerifierBoundary.semantic_checks_checked);
assertEqual('receipt verifier boundary valid exit', 0, receiptVerifierBoundary.valid_exit_code);
assertEqual('receipt verifier boundary valid verdict', 'VALID', receiptVerifierBoundary.valid_verdict);
assertEqual('receipt verifier boundary valid kid match', true, receiptVerifierBoundary.valid_kid_match);
assertEqual('receipt verifier boundary valid receipt sha present', true, receiptVerifierBoundary.valid_receipt_sha256_present);
assertEqual('receipt verifier boundary valid pubkey sha present', true, receiptVerifierBoundary.valid_provided_pubkey_sha256_present);
assertEqual('receipt verifier boundary valid posture excludes v0', false, receiptVerifierBoundary.valid_command_posture_allow_v0);
assertEqual('receipt verifier boundary valid detected format', 'v1', receiptVerifierBoundary.valid_command_posture_detected_format);
assertEqual('receipt verifier boundary valid default identity posture', 'receipt-verifier-v1-default', receiptVerifierBoundary.valid_required_identity_command_posture);
assertEqual('receipt verifier boundary required identity exit', 0, receiptVerifierBoundary.required_identity_exit_code);
assertEqual('receipt verifier boundary required identity verdict', 'VALID', receiptVerifierBoundary.required_identity_verdict);
assertEqual('receipt verifier boundary required receipt id matched', true, receiptVerifierBoundary.required_identity_receipt_id_matched);
assertEqual('receipt verifier boundary required receipt sha matched', true, receiptVerifierBoundary.required_identity_receipt_sha256_matched);
assertEqual('receipt verifier boundary required kid matched', true, receiptVerifierBoundary.required_identity_kid_matched);
assertEqual('receipt verifier boundary required pubkey sha matched', true, receiptVerifierBoundary.required_identity_pubkey_sha256_matched);
assertEqual('receipt verifier boundary required format matched', true, receiptVerifierBoundary.required_identity_format_matched);
assertEqual('receipt verifier boundary required v1-only matched', true, receiptVerifierBoundary.required_identity_v1_only_matched);
assertEqual('receipt verifier boundary required identity posture', 'receipt-verifier-v1-only-required', receiptVerifierBoundary.required_identity_command_posture);
assertEqual('receipt verifier boundary unknown signer exit', 3, receiptVerifierBoundary.unknown_signer_exit_code);
assertEqual('receipt verifier boundary unknown signer verdict', 'UNKNOWN-SIGNER', receiptVerifierBoundary.unknown_signer_verdict);
assertEqual('receipt verifier boundary unknown signer reason', 'Receipt kid does not match provided public key.', receiptVerifierBoundary.unknown_signer_reason);
assertEqual('receipt verifier boundary unknown signer kid mismatch', false, receiptVerifierBoundary.unknown_signer_kid_match);
assertEqual('receipt verifier boundary unknown signer receipt sha matches valid', true, receiptVerifierBoundary.unknown_signer_receipt_sha256_matches_valid);
assertEqual('receipt verifier boundary unknown signer pubkey sha differs', true, receiptVerifierBoundary.unknown_signer_provided_pubkey_sha256_differs);
assertEqual('receipt verifier boundary invalid exit', 1, receiptVerifierBoundary.invalid_exit_code);
assertEqual('receipt verifier boundary invalid verdict', 'INVALID', receiptVerifierBoundary.invalid_verdict);
assertEqual('receipt verifier boundary invalid kid match', true, receiptVerifierBoundary.invalid_kid_match);
assertEqual('receipt verifier boundary invalid receipt sha differs', true, receiptVerifierBoundary.invalid_receipt_sha256_differs_from_valid);
assertEqual('receipt verifier boundary invalid pubkey sha matches valid', true, receiptVerifierBoundary.invalid_provided_pubkey_sha256_matches_valid);
assertEqual('receipt verifier boundary legacy v0 required identity refused', true, receiptVerifierBoundary.legacy_v0_required_identity_refused);
assertEqual('receipt verifier boundary legacy v0 required identity exit', 1, receiptVerifierBoundary.legacy_v0_required_identity_exit_code);
assertEqual('receipt verifier boundary distinguishes unknown signer', true, receiptVerifierBoundary.distinguishes_unknown_signer_from_invalid);
assertEqual('receipt verifier boundary help names unknown signer', true, receiptVerifierBoundary.help_names_unknown_signer);
assertEqual('receipt verifier boundary help names non-claims', true, receiptVerifierBoundary.help_names_non_claims);
for (const field of [
  'issuer_recognition_proven',
  'key_custody_proven',
  'revocation_state_proven',
  'downstream_recognition_proven',
  'production_deployment_proven',
  'current_machine_governance_proven',
  'external_attestation',
  'sovereign_recognition',
  'unrouted_paths_coverage_proven',
]) {
  assertEqual(`receipt verifier boundary ${field} false`, false, receiptVerifierBoundary[field]);
}
for (const nonClaim of RECEIPT_VERIFIER_BOUNDARY_NON_CLAIMS) {
  assert(`receipt verifier boundary non-claim present: ${nonClaim}`, receiptVerifierBoundary.non_claims.includes(nonClaim));
}

section('safe output formatting');
const summary = formatLocalProofPackSummary(report);
assert('summary title present', summary.includes('ZLAR Local Proof Pack v1'));
assert('summary includes coverage component', summary.includes('coverage: governed='));
assert('summary includes downstream component', summary.includes('downstream_refusal: recognized_boarded=true'));
assert('summary includes downstream marker boundary', summary.includes('recognized_marker_count_delta=1') && summary.includes('all_refusal_marker_count_deltas_zero=true'));
assert('summary includes human authorization component', summary.includes('human_authorization: pending_boarded=false; authorized_boarded=true; denied_boarded=false'));
assert('summary includes approval transport component', summary.includes('approval_transport: reference_transport_healthy=true; telegram_required_for_fixture=false'));
assert('summary includes issuer status component', summary.includes('issuer_status: active_boarded=true; retired_refused=true; compromised_refused=true; missing_status_refused=true; unknown_refused=true; missing_key_refused=true'));
assert('summary includes trusted issuer registry recognition', summary.includes('trusted_issuer_registry_recognition: verdict=RECOGNIZED; registry_type=trusted-receipt-issuers-v2; evidence_model=bundled-local-fixture-no-secret-registry-contract; live_probing=false'));
assert('summary includes trusted issuer registry evaluator path', summary.includes('registry_fixture_validated=true') && summary.includes('registry_to_recognition_rule_evaluated=true') && summary.includes('registry_evaluation_result_type=downstream-recognition-rule-v1'));
assert('summary includes trusted issuer registry recognition nonclaims', summary.includes('live_trust_registry_state=false; live_issuer_status_proven=false') && summary.includes('production_authority=false') && summary.includes('real_non_operator_review=false') && summary.includes('current_machine_governance_proven=false'));
assert('summary includes key-state report', summary.includes('key_state_report: command=zlar key-state --sample --json; report_type=zlar-key-state-report-v1'));
assert('summary includes key-state nonclaims', summary.includes('private_key_material_read=false') && summary.includes('current_machine_governance_proven=false'));
assert('summary includes receipt verifier boundary', summary.includes('receipt_verifier_boundary: command=zlar-verify <receipt.json> --pubkey <key.pub> --json; valid=VALID/0; unknown_signer=UNKNOWN-SIGNER/3; invalid=INVALID/1'));
assert('summary includes receipt verifier identity', summary.includes('receipt_sha256_present=true; provided_pubkey_sha256_present=true') && summary.includes('required_receipt_sha_match=true') && summary.includes('legacy_v0_required_identity_refused=true'));
assert('summary includes receipt verifier nonclaims', summary.includes('issuer_recognition_proven=false; key_custody_proven=false; revocation_state_proven=false; downstream_recognition_proven=false'));
assert('summary includes protected records profile', summary.includes('protected_records: profile=protected-records-terminal; action_class=records.write; downstream_boundary=protected-records-terminal-fixture'));
assert('summary includes protected records adapter profile', summary.includes('adapter_profile=protected-records-adapter-profile-v1; adapter_route=receipt-recognition-before-ledger-append'));
assert('summary includes protected records adapter closure', summary.includes('adapter_direct_write_path_available=false; adapter_live_records_adapter=false'));
assert('summary includes protected records adapter action', summary.includes('adapter_action=zlar protected-records-write --input <file|->; adapter_action_result_type=protected-records-write-result-v1'));
assert('summary includes protected records adapter conformance', summary.includes('protected_records_adapter_conformance: profile=protected-records-cli-process-conformance; action_class=records.write'));
assert('summary includes adapter conformance replay', summary.includes('replay_refused=true; replay_reason=receipt_replay; replay_ledger_delta=0; replay_separate_process=true'));
assert('summary includes adapter conformance open boundary', summary.includes('direct_filesystem_write_to_fixture_paths_closed=false; live_records_adapter=false'));
assert('summary includes protected records downstream service', summary.includes('protected_records_downstream_service: profile=protected-records-downstream-service-fixture; action_class=records.write'));
assert('summary includes service preflight profile identity', summary.includes('preflight_profile=protected-records-service-fixture-profile'));
assert('summary includes service preflight profile sha', summary.includes(`preflight_profile_sha256=${SERVICE_PREFLIGHT_PROFILE_SHA256}`));
assert('summary includes service preflight run', summary.includes('preflight_run_in_proof_pack=true'));
assert('summary includes service preflight case counts', summary.includes(`preflight_cases=${PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length}/${PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length}`));
assert('summary includes service preflight refusal summary', summary.includes('preflight_replay_refused=true; preflight_missing_receipt_refused=true'));
assert('summary includes service preflight wrong policy refusal', summary.includes('preflight_wrong_policy_refused=true; preflight_wrong_policy_reason=policy_not_recognized; preflight_wrong_policy_state_delta=0'));
assert('summary includes service preflight direct api receipt refusal', summary.includes('preflight_direct_api_without_receipt_refused=true; preflight_direct_api_with_receipt_refused=true'));
assert('summary includes service preflight no live activation', summary.includes('preflight_live_profile_installed=false; preflight_runtime_activation_checked=false'));
assert('summary includes service invalid refusal', summary.includes('invalid_receipt_refused=true; invalid_receipt_state_delta=0'));
assert('summary includes service unknown issuer refusal', summary.includes('unknown_issuer_refused=true; unknown_issuer_state_delta=0'));
assert('summary includes service stale refusal', summary.includes('stale_receipt_refused=true; stale_receipt_state_delta=0'));
assert('summary includes service direct api refusal', summary.includes('direct_api_without_receipt_refused=true; direct_api_state_delta=0; direct_api_attempted=true'));
assert('summary includes service open boundary', summary.includes('direct_filesystem_write_to_fixture_paths_closed=false; live_records_service=false'));
assert('summary includes runtime preflight identity', summary.includes('protected_records_runtime_profile_preflight_identity: profile=protected-records-runtime-fixture-profile'));
assert('summary includes runtime preflight profile sha', summary.includes(`profile_sha256=${RUNTIME_PREFLIGHT_PROFILE_SHA256}`));
assert('summary includes runtime preflight not run', summary.includes('preflight_run_in_proof_pack=false; proof_run_in_proof_pack=false'));
assert('summary includes runtime grant store witness boundary', summary.includes('consumed_authority_grant_store=persistent-single-use-authority-grant-contract-sha256-store') && summary.includes('consumed_store_witness=launcher-owned-local-store-hash-witness; joint_rollback_detection=false'));
assert('summary includes runtime activation preflight', summary.includes('protected_records_runtime_activation_preflight: plan=protected-records-runtime-fixture-activation-plan'));
assert('summary includes runtime activation plan sha', summary.includes(`plan_sha256=${RUNTIME_ACTIVATION_PLAN_SHA256}`));
assert('summary includes runtime activation profile sha match', summary.includes(`profile_sha256=${RUNTIME_PREFLIGHT_PROFILE_SHA256}; sha_matches_plan=true`));
assert('summary includes runtime activation run', summary.includes('activation_preflight_run_in_proof_pack=true; runtime_profile_proof_run_in_proof_pack=true'));
assert('summary includes runtime activation nested proof counts', summary.includes(`runtime_profile_cases=${RUNTIME_PREFLIGHT_PROFILE.required_cases.length}/${RUNTIME_PREFLIGHT_PROFILE.required_cases.length}`));
assert('summary includes runtime activation proof refusals', summary.includes('recognized_write_accepted=true; same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true') && summary.includes('missing_grant_refused=true; mismatched_grant_refused=true; revoked_grant_refused=true; expired_grant_refused=true; request_grant_refused=true'));
assert('summary includes runtime activation identity policy', summary.includes('protected_records_runtime_activation_preflight_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('summary includes runtime activation witness and rollback limits', summary.includes('witness_commit_failure_refused=true; joint_rollback_refused=true; joint_rollback_detection=false; joint_rollback_reopens_grant_reuse=true'));
assert('summary includes runtime activation no install', summary.includes('persistent_runtime_profile_installed=false'));
assert('summary includes runtime activation burn window', summary.includes('partial_grant_commit_burn_window_named=true'));
assert('summary includes runtime activation claim boundary', summary.includes('fixture_rightful_issuance=true; rightful_issuance=false; consequence_lifecycle_closed=false'));
assert('summary includes runtime local activation', summary.includes('- protected_records_runtime_local_activation: plan=protected-records-runtime-local-activation-fixture-plan'));
assert('summary includes runtime local activation active profile selection', summary.includes('active_profile_selected=true; local_activation_run_in_proof_pack=true'));
assert('summary includes runtime local activation route', summary.includes(`route=${RECORDS_WRITE_TERMINAL_ROUTE}`));
assert('summary includes runtime local activation grant refusals', summary.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true') && summary.includes('missing_grant_refused=true; mismatched_grant_refused=true; revoked_grant_refused=true; expired_grant_refused=true; request_grant_refused=true'));
assert('summary includes runtime local activation identity policy', summary.includes('protected_records_runtime_local_activation_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('summary includes runtime local activation applied', summary.includes('local_activation_applied=true; persistent_runtime_profile_installed=false'));
assert('summary includes runtime local activation witness limits', summary.includes('witness_commit_failure_refused=true; joint_rollback_refused=true; joint_rollback_detection=false; joint_rollback_reopens_grant_reuse=true'));
assert('summary includes runtime local activation claim boundary', summary.includes('fixture_rightful_issuance=true; rightful_issuance=false; portable_rightful_issuance=false; live_authority=false; production_rightful_issuance=false; current_machine_governance=false; consequence_lifecycle_closed=false'));
assert('summary includes runtime profile installation', summary.includes('- protected_records_runtime_profile_installation: plan=protected-records-runtime-profile-installation-fixture-plan'));
assert('summary includes runtime profile installation selection', summary.includes('disposable_root_created=true; selected_from_install_root=true'));
assert('summary includes runtime profile installation guard', summary.includes('request_guard_refused=true'));
assert('summary includes runtime profile installation grant refusals', summary.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true') && summary.includes('missing_grant_refused=true; mismatched_grant_refused=true; revoked_grant_refused=true; expired_grant_refused=true; request_grant_refused=true'));
assert('summary includes runtime profile installation identity policy', summary.includes('protected_records_runtime_profile_installation_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('summary includes runtime profile installation no persistent profile', summary.includes('persistent_runtime_profile_installed=false'));
assert('summary includes runtime profile installation claim boundary', summary.includes('fixture_rightful_issuance=true; rightful_issuance=false; portable_rightful_issuance=false; live_authority=false; production_rightful_issuance=false; current_machine_governance=false; consequence_lifecycle_closed=false'));
assert(
  'summary includes Claude hook replay component',
  summary.includes('- claude_code_hook_contract_replay: command=zlar claude-code-hook-contract-replay-proof; evidence_model=local-fixture-hook-contract-replay') &&
    summary.includes('adapter_source=repo')
);
assert('summary includes Claude hook replay cases', summary.includes(`cases=${REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES.length}/${REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES.length}; allow_json=true; deny_json=true`));
assert('summary includes Claude hook replay contract hash', summary.includes(`contract_sha256=${claudeCodeHookContractReplayContractSha256()}`));
assert('summary includes Claude hook replay fail-closed cases', summary.includes('missing_gate_failed_closed=true; blank_gate_response_failed_closed=true; malformed_output_refused=true; non_pretooluse_payload_denied_by_fixture_gate=true'));
assert('summary includes Claude hook replay nonclaims', summary.includes('live_claude_invoked=false; live_claude_app_passage_proven=false; app_originated_hook_crossing_proven=false') && summary.includes('current_machine_governance_proven=false') && summary.includes('side_door_closure_proven=false'));
assert('summary includes protected records contract route', summary.includes('contract_route=receipt-recognition-before-record-write'));
assert('summary includes protected records replay policy', summary.includes('replay_policy=single-use-receipt-id-per-terminal-ledger'));
assert('summary includes protected records required receipt fields', summary.includes('required_receipt_fields=v,id,kid'));
assert('summary includes protected records refusal count', summary.includes('refused_write_count=11; refusal_record_delta_total=0'));
assert('summary includes protected records ungoverned boundaries', summary.includes('ungoverned_boundaries=live_records_system,production_records_adapter,unrouted_records_paths'));
assert('summary states non-claims', summary.includes('does not inspect live hooks'));
assert('summary states Telegram non-claim', summary.includes('does not use Telegram'));
assert('summary output is privacy safe', assertNoUnsafeLocalProofPackText(summary));

const jsonText = JSON.stringify(report, null, 2);
assert('json output is privacy safe', assertNoUnsafeLocalProofPackText(jsonText));
assert('json omits raw record id', !jsonText.includes('fixture-record-001'));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonText));
assert('json omits private and temp paths', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(jsonText));

section('portable artifact');
const artifact = buildLocalProofPackArtifact(report);
assert('artifact passes validation', assertLocalProofPackArtifact(artifact));
assertEqual('artifact type', LOCAL_PROOF_PACK_ARTIFACT_TYPE, artifact.artifact_type);
assertEqual('artifact canonicalization', LOCAL_PROOF_PACK_ARTIFACT_CANONICALIZATION, artifact.canonicalization);
assertEqual('artifact embeds proof pack payload', LOCAL_PROOF_PACK_TYPE, artifact.payload.proof_pack_type);
assertEqual('artifact component manifest scope', 'canonical payload components in artifact order', artifact.component_manifest_hash_scope);
assertEqual('artifact component manifest count', 16, artifact.component_manifest.length);
const hookReplayManifest = artifact.component_manifest.find((item) => item.component === 'claude_code_hook_contract_replay');
assert('artifact hook replay component manifest exists', !!hookReplayManifest);
assertEqual('artifact hook replay manifest identity type', 'proof_type', hookReplayManifest.identity_type);
assertEqual('artifact hook replay manifest evidence model', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_EVIDENCE_MODEL, hookReplayManifest.evidence_model);
assertEqual('artifact hook replay manifest live probing false', false, hookReplayManifest.live_probing);
assertEqual('artifact hook replay manifest source boundary', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY, hookReplayManifest.source_state_boundary);
assertEqual(
  'artifact hook replay manifest component sha matches payload',
  createHash('sha256')
    .update(canonicalize(component(artifact.payload, 'claude_code_hook_contract_replay')), 'utf8')
    .digest('hex'),
  hookReplayManifest.component_sha256
);
assertEqual('artifact claim binding scope', 'canonical safe claim ceiling and non-claims', artifact.claim_binding.hash_scope);
assertEqual('artifact claim binding non-claim count', NON_CLAIMS.length, artifact.claim_binding.non_claim_count);
assertEqual(
  'artifact claim binding non-claims sha matches payload',
  createHash('sha256').update(canonicalize(artifact.payload.non_claims), 'utf8').digest('hex'),
  artifact.claim_binding.non_claims_sha256
);
assertEqual('artifact uses sha256', 'SHA-256', artifact.integrity.algorithm);
assert('artifact sha256 is hex', /^[a-f0-9]{64}$/.test(artifact.integrity.body_sha256));
const artifactAgain = buildLocalProofPackArtifact(report);
assertEqual('artifact hash is deterministic', artifact.integrity.body_sha256, artifactAgain.integrity.body_sha256);
const artifactSummary = formatLocalProofPackArtifactSummary(artifact);
assert('artifact summary names type', artifactSummary.includes(LOCAL_PROOF_PACK_ARTIFACT_TYPE));
assert('artifact summary names sha256', artifactSummary.includes(artifact.integrity.body_sha256));
assert('artifact summary is privacy safe', assertNoUnsafeLocalProofPackText(artifactSummary));
assert('artifact json is privacy safe', assertNoUnsafeLocalProofPackText(JSON.stringify(artifact, null, 2)));

section('artifact verification');
const parsedArtifact = parseLocalProofPackArtifactText(JSON.stringify(artifact, null, 2));
assert('parsed artifact passes validation', assertLocalProofPackArtifact(parsedArtifact));
const verification = verifyLocalProofPackArtifact(parsedArtifact);
assertEqual('verification type', LOCAL_PROOF_PACK_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
assertEqual('verification is true', true, verification.verified);
assertEqual('verification structural self-integrity true', true, verification.structural_self_integrity_verified);
assertEqual('verification identity match requires expected SHA', true, verification.artifact_identity_match_requires_expected_sha256);
assertEqual('verification expected SHA not supplied', false, verification.artifact_identity_expected_sha256_supplied);
assertEqual('verification expected SHA absent', null, verification.expected_artifact_body_sha256);
assertEqual('verification identity not matched without expected SHA', false, verification.artifact_identity_sha256_matched);
assertEqual('verification required SHA absent', null, verification.required_body_sha256);
assertEqual('verification required SHA not matched', false, verification.required_body_sha256_matched);
assertEqual(
  'verification scope structural only',
  'structural-local-proof-pack-artifact-self-integrity-and-schema-only',
  verification.verification_scope
);
assertEqual(
  'verification model is artifact-only',
  'self-contained-artifact-integrity-and-embedded-boundary-validation',
  verification.artifact_verification_model
);
assertEqual('verification binds artifact type', LOCAL_PROOF_PACK_ARTIFACT_TYPE, verification.artifact_type);
assertEqual('verification binds sha256', artifact.integrity.body_sha256, verification.body_sha256);
assertEqual('verification payload type', LOCAL_PROOF_PACK_TYPE, verification.payload_type);
assertEqual('verification live probing false', false, verification.live_probing);
assertEqual('verification performs no fresh proof-pack run', false, verification.fresh_proof_pack_run_performed);
assertEqual('verification proves no source freshness', false, verification.source_freshness_proven);
assertEqual('verification component count', 16, verification.component_count);
assertEqual('verification component manifest scope', 'canonical payload components in artifact order', verification.component_manifest_hash_scope);
assertEqual('verification component manifest count', 16, verification.component_manifest.length);
assertEqual('verification component manifest first component', 'governed_surface_coverage_map', verification.component_manifest[0].component);
assertEqual('verification component manifest hook source boundary', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY, verification.component_manifest.find((item) => item.component === 'claude_code_hook_contract_replay').source_state_boundary);
assertEqual('verification claim binding non-claim count', NON_CLAIMS.length, verification.claim_binding.non_claim_count);
assertEqual('verification coverage summary structural', true, verification.coverage.embedded_component_structurally_valid);
assertEqual('verification coverage terminal projection withheld', false, verification.coverage.terminal_claim_projection_allowed);
assertEqual('verification coverage terminal identity withheld', false, verification.coverage.terminal_artifact_identity_sha256_matched);
assertEqual('verification coverage terminal outer metadata withheld', false, verification.coverage.terminal_outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256);
assertEqual('verification coverage terminal recognized source withheld', false, verification.coverage.terminal_recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256);
assertEqual('verification coverage terminal signature withheld', false, verification.coverage.terminal_trusted_issuer_registry_signature_valid);
assertEqual('verification coverage terminal fixture rightful path withheld', false, verification.coverage.terminal_fixture_rightful_issuance_path_evidenced);
assertEqual('verification coverage terminal source freshness false', false, verification.coverage.terminal_source_freshness_proven);
assertEqual('verification key-state summary type', 'zlar-local-proof-pack-key-state-verification-summary-v1', verification.key_state_report.summary_type);
assertEqual('verification key-state run', true, verification.key_state_report.run_in_proof_pack);
assertEqual('verification key-state command', 'zlar key-state --sample --json', verification.key_state_report.command);
assertEqual('verification key-state report type', KEY_STATE_REPORT_TYPE, verification.key_state_report.report_type);
assertEqual('verification key-state live probing false', false, verification.key_state_report.live_probing);
assertEqual('verification key-state read-only true', true, verification.key_state_report.read_only);
assertEqual('verification key-state private key material read false', false, verification.key_state_report.private_key_material_read);
assertEqual('verification key-state private key paths included false', false, verification.key_state_report.private_key_paths_included);
assertEqual('verification key-state legacy software key absent', false, verification.key_state_report.legacy_software_signing_key_present);
assertEqual('verification key-state no key custody', false, verification.key_state_report.key_custody_proven);
assertEqual('verification key-state no revocation state', false, verification.key_state_report.revocation_state_proven);
assertEqual('verification key-state no trust registry', false, verification.key_state_report.production_trust_registry_proven);
assertEqual('verification key-state no current-machine governance', false, verification.key_state_report.current_machine_governance_proven);
assertEqual('verification receipt verifier summary type', 'zlar-local-proof-pack-receipt-verifier-boundary-verification-summary-v1', verification.receipt_verifier_boundary.summary_type);
assertEqual('verification receipt verifier run', true, verification.receipt_verifier_boundary.run_in_proof_pack);
assertEqual('verification receipt verifier valid verdict', 'VALID', verification.receipt_verifier_boundary.valid_verdict);
assertEqual('verification receipt verifier receipt sha present', true, verification.receipt_verifier_boundary.valid_receipt_sha256_present);
assertEqual('verification receipt verifier pubkey sha present', true, verification.receipt_verifier_boundary.valid_provided_pubkey_sha256_present);
assertEqual('verification receipt verifier required identity verdict', 'VALID', verification.receipt_verifier_boundary.required_identity_verdict);
assertEqual('verification receipt verifier required receipt sha matched', true, verification.receipt_verifier_boundary.required_identity_receipt_sha256_matched);
assertEqual('verification receipt verifier required pubkey sha matched', true, verification.receipt_verifier_boundary.required_identity_pubkey_sha256_matched);
assertEqual('verification receipt verifier required v1-only matched', true, verification.receipt_verifier_boundary.required_identity_v1_only_matched);
assertEqual('verification receipt verifier legacy v0 identity refused', true, verification.receipt_verifier_boundary.legacy_v0_required_identity_refused);
assertEqual('verification receipt verifier unknown signer verdict', 'UNKNOWN-SIGNER', verification.receipt_verifier_boundary.unknown_signer_verdict);
assertEqual('verification receipt verifier invalid verdict', 'INVALID', verification.receipt_verifier_boundary.invalid_verdict);
assertEqual('verification receipt verifier distinguishes unknown signer', true, verification.receipt_verifier_boundary.distinguishes_unknown_signer_from_invalid);
assertEqual('verification receipt verifier no issuer recognition', false, verification.receipt_verifier_boundary.issuer_recognition_proven);
assertEqual('verification receipt verifier no key custody', false, verification.receipt_verifier_boundary.key_custody_proven);
assertEqual('verification receipt verifier no downstream recognition', false, verification.receipt_verifier_boundary.downstream_recognition_proven);
assertEqual('verification trusted registry summary type', 'zlar-local-proof-pack-trusted-issuer-registry-recognition-verification-summary-v2', verification.trusted_issuer_registry_recognition.summary_type);
assertEqual('verification trusted registry run', true, verification.trusted_issuer_registry_recognition.run_in_proof_pack);
assertEqual('verification trusted registry verdict', 'RECOGNIZED', verification.trusted_issuer_registry_recognition.verdict);
assertEqual('verification trusted registry fixture validated', true, verification.trusted_issuer_registry_recognition.registry_fixture_validated);
assertEqual('verification trusted registry fixture evaluated', true, verification.trusted_issuer_registry_recognition.registry_fixture_evaluated);
assertEqual('verification trusted registry rule path evaluated', true, verification.trusted_issuer_registry_recognition.registry_to_recognition_rule_evaluated);
assertEqual('verification trusted registry evaluator result type', 'downstream-recognition-rule-v1', verification.trusted_issuer_registry_recognition.registry_evaluation_result_type);
assertEqual('verification trusted registry issuer count', 1, verification.trusted_issuer_registry_recognition.registry_trusted_issuer_count);
assertEqual('verification trusted registry malformed fail closed', true, verification.trusted_issuer_registry_recognition.malformed_registry_fail_closed_before_verdict);
assertEqual('verification trusted registry audit event bound', true, verification.trusted_issuer_registry_recognition.required_audit_event_id_bound);
assertEqual('verification trusted registry detail hash bound', true, verification.trusted_issuer_registry_recognition.required_detail_hash_bound);
for (const field of [
  'live_trust_registry_state',
  'live_issuer_status_proven',
  'key_custody_proven',
  'revocation_truth_proven',
  'production_trust_registry_proven',
  'production_downstream_recognition_proven',
  'production_authority',
  'public_external_attestation',
  'real_non_operator_review',
  'sovereign_recognition',
  'current_machine_governance_proven',
]) {
  assertEqual(`verification trusted registry ${field} false`, false, verification.trusted_issuer_registry_recognition[field]);
}
assertEqual('verification human authorization summary type', 'zlar-local-proof-pack-human-authorization-verification-summary-v1', verification.human_authorization.summary_type);
assertEqual('verification human authorization run', true, verification.human_authorization.run_in_proof_pack);
assertEqual('verification human authorization command', 'zlar human-authorization-proof', verification.human_authorization.command);
assertEqual('verification human authorization evidence model', 'local-hermetic-fixture', verification.human_authorization.evidence_model);
assertEqual('verification human authorization live probing false', false, verification.human_authorization.live_probing);
assertEqual('verification human authorization channel simulated', 'simulated-human-fixture', verification.human_authorization.approval_channel);
assertEqual('verification human authorization pending not boarded', false, verification.human_authorization.pending_boarded);
assertEqual('verification human authorization authorized boarded', true, verification.human_authorization.authorized_boarded);
assertEqual('verification human authorization denied not boarded', false, verification.human_authorization.denied_boarded);
assertEqual('verification service preflight summary type', 'zlar-local-proof-pack-service-profile-preflight-verification-summary-v1', verification.service_profile_preflight.summary_type);
assertEqual('verification service preflight run', true, verification.service_profile_preflight.run_in_proof_pack);
assertEqual('verification service preflight type', PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_TYPE, verification.service_profile_preflight.preflight_type);
assertEqual('verification service preflight evidence model', 'local-disposable-config-backed-profile-preflight-fixture', verification.service_profile_preflight.evidence_model);
assertEqual('verification service preflight live probing false', false, verification.service_profile_preflight.live_probing);
assertEqual('verification service preflight case count', PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length, verification.service_profile_preflight.case_count);
assertEqual('verification service preflight required case count', PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length, verification.service_profile_preflight.required_case_count);
assertEqual('verification service preflight direct api without receipt refused', true, verification.service_profile_preflight.direct_api_without_receipt_refused);
assertEqual('verification service preflight direct api with receipt refused', true, verification.service_profile_preflight.direct_api_with_receipt_refused);
assertEqual('verification service preflight launcher-owned config required', true, verification.service_profile_preflight.launcher_owned_config_required);
assertEqual('verification service preflight request stream authority allowed false', false, verification.service_profile_preflight.request_stream_authority_material_allowed);
assertEqual('verification service preflight request stream authority refused', true, verification.service_profile_preflight.request_stream_authority_material_refused);
assertEqual('verification service preflight request stream authority reason', 'request_stream_authority_material', verification.service_profile_preflight.request_stream_authority_material_reason);
assertEqual('verification service preflight request stream authority state delta', 0, verification.service_profile_preflight.request_stream_authority_material_state_delta);
assertEqual('verification service preflight request stream forbidden fields refused', true, verification.service_profile_preflight.request_stream_forbidden_fields_refused);
const verificationDirectApiReceiptSummary = verification.service_profile_preflight.case_summaries.find((item) =>
  item.case_id === 'direct_api_profile_receipt_present_refused_before_service_mutation'
);
assertEqual('verification service preflight direct api receipt summary reason', 'request_stream_forbidden_fields', verificationDirectApiReceiptSummary.reason_code);
assertEqual('verification service preflight direct api receipt summary state delta', 0, verificationDirectApiReceiptSummary.state_entry_count_delta);
assertEqual('verification service preflight direct api receipt summary attempted', true, verificationDirectApiReceiptSummary.direct_api_attempted);
assertEqual('verification service preflight no live profile install', false, verification.service_profile_preflight.live_profile_installed);
assertEqual('verification service preflight no runtime activation', false, verification.service_profile_preflight.runtime_profile_activation_checked);
assertEqual('verification service preflight no live records check', false, verification.service_profile_preflight.live_records_system_checked);
assertEqual('verification service preflight no production service check', false, verification.service_profile_preflight.production_records_service_checked);
assertEqual('verification service preflight no live MCP check', false, verification.service_profile_preflight.live_mcp_coverage_checked);
assertEqual('verification service preflight no approval health check', false, verification.service_profile_preflight.live_approval_channel_health_checked);
assertEqual('verification service preflight no external attestation', false, verification.service_profile_preflight.external_attestation);
assertEqual('verification service preflight no sovereign recognition', false, verification.service_profile_preflight.sovereign_recognition);
assertEqual('verification service preflight no unrouted paths check', false, verification.service_profile_preflight.unrouted_records_paths_checked);
assertEqual('verification runtime local activation summary type', 'zlar-local-proof-pack-runtime-local-activation-verification-summary-v1', verification.runtime_local_activation.summary_type);
assertEqual('verification runtime local activation run', true, verification.runtime_local_activation.run_in_proof_pack);
assertEqual('verification runtime local activation evidence model', 'local-disposable-runtime-activation-fixture', verification.runtime_local_activation.evidence_model);
assertEqual('verification runtime local activation live probing false', false, verification.runtime_local_activation.live_probing);
assertEqual('verification runtime local activation active profile selection type', RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_TYPE, verification.runtime_local_activation.active_profile_selection.selection_type);
assertEqual('verification runtime local activation active profile selected', true, verification.runtime_local_activation.active_profile_selection.selected);
assertEqual('verification runtime local activation active profile scope', RECORDS_WRITE_ACTIVE_PROFILE_SELECTION_SCOPE, verification.runtime_local_activation.active_profile_selection.selection_scope);
assertEqual('verification runtime local activation active profile sha matches plan', true, verification.runtime_local_activation.active_profile_selection.runtime_profile_sha_matches_plan);
assertEqual('verification runtime local activation active profile no latest', false, verification.runtime_local_activation.active_profile_selection.selects_latest_profile);
assertEqual('verification runtime local activation active profile no live check', false, verification.runtime_local_activation.active_profile_selection.live_runtime_profile_checked);
assertEqual('verification runtime local activation active profile no persistent install', false, verification.runtime_local_activation.active_profile_selection.persistent_runtime_profile_installed);
assertRuntimeProfileIdentitySummary('verification runtime local activation', verification.runtime_local_activation);
assertEqual('verification runtime local activation applied', true, verification.runtime_local_activation.local_activation_applied);
assertEqual('verification runtime local activation disposable config written', true, verification.runtime_local_activation.disposable_runtime_config_written);
assertEqual('verification runtime local activation persistent config false', false, verification.runtime_local_activation.persistent_runtime_config_written);
assertEqual('verification runtime local activation hook config false', false, verification.runtime_local_activation.hook_configuration_written);
assertEqual('verification runtime local activation service started', true, verification.runtime_local_activation.runtime_service_started);
assertEqual('verification runtime local activation accepted write', true, verification.runtime_local_activation.recognized_write_accepted);
assertEqual('verification runtime local activation route', RECORDS_WRITE_TERMINAL_ROUTE, verification.runtime_local_activation.mutation_authoritative_route);
assertEqual('verification runtime local activation same-process replay refused', true, verification.runtime_local_activation.same_process_signed_payload_replay_refused);
assertEqual('verification runtime local activation restart grant replay refused', true, verification.runtime_local_activation.restart_consumed_authority_grant_refused);
assertEqual('verification runtime local activation request grant refused', true, verification.runtime_local_activation.request_supplied_authority_grant_refused);
assertEqual('verification runtime local activation witness failure refused', true, verification.runtime_local_activation.witness_commit_failed_after_authority_grant_store_commit);
assertEqual('verification runtime local activation joint rollback detection false', false, verification.runtime_local_activation.store_anchor_and_witness_joint_rollback_detection);
assertEqual('verification runtime local activation burn window named', true, verification.runtime_local_activation.partial_grant_commit_burn_window_named);
assertEqual('verification runtime local activation fixture rightful issuance withheld', false, verification.runtime_local_activation.fixture_rightful_issuance_path_evidenced);
assertEqual('verification runtime local activation generic rightful issuance false', false, verification.runtime_local_activation.rightful_issuance_proven);
assertEqual('verification runtime local activation lifecycle closure false', false, verification.runtime_local_activation.consequence_lifecycle_closed);
assertEqual('verification runtime local activation missing receipt refused', true, verification.runtime_local_activation.missing_receipt_refused);
assertEqual('verification runtime local activation invalid receipt refused', true, verification.runtime_local_activation.invalid_receipt_refused);
assertEqual('verification runtime local activation unknown issuer refused', true, verification.runtime_local_activation.unknown_issuer_refused);
assertEqual('verification runtime local activation retired issuer refused', true, verification.runtime_local_activation.retired_issuer_refused);
assertEqual('verification runtime local activation missing issuer status refused', true, verification.runtime_local_activation.missing_issuer_status_refused);
assertEqual('verification runtime local activation wrong runtime profile id refused', true, verification.runtime_local_activation.wrong_runtime_profile_id_refused);
assertEqual('verification runtime local activation wrong audit event refused', true, verification.runtime_local_activation.wrong_audit_event_refused);
assertEqual('verification runtime local activation non-boarding outcome refused', true, verification.runtime_local_activation.non_boarding_outcome_refused);
assertEqual('verification runtime local activation direct api with receipt refused', true, verification.runtime_local_activation.direct_api_with_receipt_refused);
assertEqual('verification runtime local activation authority material refused', true, verification.runtime_local_activation.agent_supplied_authority_material_refused);
assertEqual('verification runtime local activation no production service', false, verification.runtime_local_activation.production_records_service_checked);
assertEqual('verification runtime local activation no external attestation', false, verification.runtime_local_activation.external_attestation);
assertEqual('verification runtime profile installation summary type', 'zlar-local-proof-pack-runtime-profile-installation-verification-summary-v1', verification.runtime_profile_installation.summary_type);
assertEqual('verification runtime profile installation run', true, verification.runtime_profile_installation.run_in_proof_pack);
assertEqual('verification runtime profile installation evidence model', 'local-disposable-runtime-profile-installation-fixture', verification.runtime_profile_installation.evidence_model);
assertEqual('verification runtime profile installation live probing false', false, verification.runtime_profile_installation.live_probing);
assertEqual('verification runtime profile installation selected from root', true, verification.runtime_profile_installation.disposable_profile_selection.profile_selected_from_install_root);
assertEqual('verification runtime profile installation selected by id and sha', true, verification.runtime_profile_installation.disposable_profile_selection.selected_by_explicit_id_and_sha);
assertEqual('verification runtime profile installation no latest', false, verification.runtime_profile_installation.disposable_profile_selection.selects_latest_profile);
assertEqual('verification runtime profile installation request guard refused', true, verification.runtime_profile_installation.request_authority_guard_summary.all_refused_before_mutation);
assertEqual('verification runtime profile installation runtime config refused', true, verification.runtime_profile_installation.request_authority_guard_summary.runtime_config_refused);
assertEqual('verification runtime profile installation authority grant refused', true, verification.runtime_profile_installation.request_authority_guard_summary.authority_grant_refused);
assertRuntimeProfileIdentitySummary('verification runtime profile installation', verification.runtime_profile_installation);
assertEqual('verification runtime profile installation applied', true, verification.runtime_profile_installation.disposable_profile_installation_applied);
assertEqual('verification runtime profile installation hook config false', false, verification.runtime_profile_installation.hook_configuration_written);
assertEqual('verification runtime profile installation user config false', false, verification.runtime_profile_installation.user_config_written);
assertEqual('verification runtime profile installation machine config false', false, verification.runtime_profile_installation.machine_config_written);
assertEqual('verification runtime profile installation accepted write', true, verification.runtime_profile_installation.recognized_write_accepted);
assertEqual('verification runtime profile installation route', RECORDS_WRITE_TERMINAL_ROUTE, verification.runtime_profile_installation.mutation_authoritative_route);
assertEqual('verification runtime profile installation same-process replay refused', true, verification.runtime_profile_installation.same_process_signed_payload_replay_refused);
assertEqual('verification runtime profile installation restart grant replay refused', true, verification.runtime_profile_installation.restart_consumed_authority_grant_refused);
assertEqual('verification runtime profile installation request grant refused', true, verification.runtime_profile_installation.request_supplied_authority_grant_refused);
assertEqual('verification runtime profile installation burn window named', true, verification.runtime_profile_installation.partial_grant_commit_burn_window_named);
assertEqual('verification runtime profile installation fixture rightful issuance withheld', false, verification.runtime_profile_installation.fixture_rightful_issuance_path_evidenced);
assertEqual('verification runtime profile installation generic rightful issuance false', false, verification.runtime_profile_installation.rightful_issuance_proven);
assertEqual('verification runtime profile installation lifecycle closure false', false, verification.runtime_profile_installation.consequence_lifecycle_closed);
assertEqual('verification runtime profile installation missing receipt refused', true, verification.runtime_profile_installation.missing_receipt_refused);
assertEqual('verification runtime profile installation invalid receipt refused', true, verification.runtime_profile_installation.invalid_receipt_refused);
assertEqual('verification runtime profile installation unknown issuer refused', true, verification.runtime_profile_installation.unknown_issuer_refused);
assertEqual('verification runtime profile installation retired issuer refused', true, verification.runtime_profile_installation.retired_issuer_refused);
assertEqual('verification runtime profile installation missing issuer status refused', true, verification.runtime_profile_installation.missing_issuer_status_refused);
assertEqual('verification runtime profile installation wrong runtime profile id refused', true, verification.runtime_profile_installation.wrong_runtime_profile_id_refused);
assertEqual('verification runtime profile installation wrong audit event refused', true, verification.runtime_profile_installation.wrong_audit_event_refused);
assertEqual('verification runtime profile installation non-boarding outcome refused', true, verification.runtime_profile_installation.non_boarding_outcome_refused);
assertEqual('verification runtime profile installation direct api with receipt refused', true, verification.runtime_profile_installation.direct_api_with_receipt_refused);
assertEqual('verification runtime profile installation no persistent profile', false, verification.runtime_profile_installation.persistent_runtime_profile_installed);
assertEqual('verification runtime profile installation no live runtime profile', false, verification.runtime_profile_installation.live_runtime_profile_checked);
assertEqual('verification runtime profile installation no external attestation', false, verification.runtime_profile_installation.external_attestation);
assertEqual('verification Claude hook replay summary type', 'zlar-local-proof-pack-claude-hook-contract-replay-verification-summary-v1', verification.claude_hook_contract_replay.summary_type);
assertEqual('verification Claude hook replay run', true, verification.claude_hook_contract_replay.run_in_proof_pack);
assertEqual('verification Claude hook replay evidence model', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_EVIDENCE_MODEL, verification.claude_hook_contract_replay.evidence_model);
assertEqual('verification Claude hook replay live probing false', false, verification.claude_hook_contract_replay.live_probing);
assertEqual('verification Claude hook replay adapter source', 'repo', verification.claude_hook_contract_replay.adapter_source);
assertEqual('verification Claude hook replay adapter hash bound', claudeCodeHookContractReplayRepoAdapterSha256(), verification.claude_hook_contract_replay.adapter_sha256);
assertEqual('verification Claude hook replay contract hash bound', claudeCodeHookContractReplayContractSha256(), verification.claude_hook_contract_replay.hook_replay_contract_sha256);
assertEqual('verification Claude hook replay source boundary exact', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY, verification.claude_hook_contract_replay.source_state_boundary);
assertEqual('verification Claude hook replay case evidence hash carried', claudeHookReplay.case_evidence_sha256, verification.claude_hook_contract_replay.case_evidence_sha256);
assertEqual('verification Claude hook replay required cases present', true, verification.claude_hook_contract_replay.all_required_cases_present);
assertEqual('verification Claude hook replay allow JSON', true, verification.claude_hook_contract_replay.permission_decisions_observed.allow);
assertEqual('verification Claude hook replay deny JSON', true, verification.claude_hook_contract_replay.permission_decisions_observed.deny);
assertEqual('verification Claude hook replay denied effect not executed', true, verification.claude_hook_contract_replay.denied_effect_not_executed);
assertEqual('verification Claude hook replay missing gate fail closed', true, verification.claude_hook_contract_replay.missing_gate_failed_closed);
assertEqual('verification Claude hook replay no live Claude invocation', false, verification.claude_hook_contract_replay.live_claude_invoked);
assertEqual('verification Claude hook replay no live app passage', false, verification.claude_hook_contract_replay.live_claude_app_passage_proven);
assertEqual('verification Claude hook replay no current-machine governance', false, verification.claude_hook_contract_replay.current_machine_governance_proven);
assert('verification carries non-claims', verification.non_claims.includes('This proof pack does not prove production deployment.'));
const verificationSummary = formatLocalProofPackArtifactVerification(verification);
assert('verification summary names verified true', verificationSummary.includes('verified=true'));
assert('verification summary names sha256', verificationSummary.includes(artifact.integrity.body_sha256));
assert('verification summary names structural identity posture', verificationSummary.includes('expected_sha256_supplied=false; identity_sha256_matched=false'));
assert('verification summary withholds terminal projection', verificationSummary.includes('terminal_claim_projection_allowed=false') && verificationSummary.includes('recognized_source_bound=false; signature_valid=false; fixture_rightful_issuance=false'));
assert('verification summary states no terminal freshness', verificationSummary.includes('source_freshness_proven=false'));
assert('verification summary names key-state run', verificationSummary.includes('key_state_report_run_in_proof_pack=true'));
assert('verification summary names key-state privacy', verificationSummary.includes('private_key_material_read=false') && verificationSummary.includes('legacy_software_signing_key_present=false'));
assert('verification summary names key-state nonclaims', verificationSummary.includes('production_trust_registry_proven=false') && verificationSummary.includes('current_machine_governance_proven=false'));
assert('verification summary names receipt verifier run', verificationSummary.includes('receipt_verifier_boundary_run_in_proof_pack=true'));
assert('verification summary names receipt verifier verdicts', verificationSummary.includes('receipt_verifier_boundary_verdicts: valid=VALID/0; unknown_signer=UNKNOWN-SIGNER/3; invalid=INVALID/1; distinguishes_unknown_signer_from_invalid=true'));
assert('verification summary names receipt verifier identity', verificationSummary.includes('receipt_verifier_boundary_identity: receipt_sha256_present=true; provided_pubkey_sha256_present=true') && verificationSummary.includes('required_receipt_sha_match=true') && verificationSummary.includes('legacy_v0_required_identity_refused=true'));
assert('verification summary names receipt verifier nonclaims', verificationSummary.includes('issuer_recognition_proven=false; key_custody_proven=false; revocation_state_proven=false; downstream_recognition_proven=false'));
assert('verification summary names trusted registry run', verificationSummary.includes('trusted_issuer_registry_recognition_run_in_proof_pack=true'));
assert('verification summary names trusted registry facts', verificationSummary.includes('trusted_issuer_registry_recognition_summary: verdict=RECOGNIZED') && verificationSummary.includes('malformed_registry_fail_closed_before_verdict=true'));
assert('verification summary names trusted registry evaluator path', verificationSummary.includes('registry_fixture_validated=true') && verificationSummary.includes('registry_to_recognition_rule_evaluated=true') && verificationSummary.includes('registry_evaluation_result_type=downstream-recognition-rule-v1'));
assert('verification summary names trusted registry nonclaims', verificationSummary.includes('live_trust_registry_state=false; live_issuer_status_proven=false') && verificationSummary.includes('production_authority=false') && verificationSummary.includes('real_non_operator_review=false') && verificationSummary.includes('current_machine_governance_proven=false'));
assert('verification summary names downstream refusal run', verificationSummary.includes('downstream_refusal_run_in_proof_pack=true'));
assert('verification summary names downstream refusal marker boundary', verificationSummary.includes('downstream_refusal_summary: proof_type=downstream-refusal-proof-v1') && verificationSummary.includes('recognized_marker_count_delta=1') && verificationSummary.includes('all_refusal_marker_count_deltas_zero=true'));
assert('verification summary names human authorization run', verificationSummary.includes('human_authorization_run_in_proof_pack=true'));
assert('verification summary names human authorization boarding', verificationSummary.includes('human_authorization_summary: proof_type=human-authorization-proof-v1; evidence_model=local-hermetic-fixture; live_probing=false; approval_channel=simulated-human-fixture; pending_boarded=false; authorized_boarded=true; denied_boarded=false'));
assert('verification summary names service preflight run', verificationSummary.includes('service_profile_preflight_run_in_proof_pack=true'));
assert('verification summary names service preflight cases', verificationSummary.includes(`service_profile_preflight_cases=${PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length}/${PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length}`));
assert('verification summary names service preflight request stream authority', verificationSummary.includes('service_profile_preflight_request_stream_authority: launcher_owned_config_required=true; authority_material_allowed=false; authority_material_refused=true; reason=request_stream_authority_material; state_delta=0'));
assert('verification summary names service preflight direct api receipt reason', verificationSummary.includes('service_profile_preflight_direct_api_receipt_present: reason=request_stream_forbidden_fields; state_delta=0; direct_api_attempted=true'));
assert('verification summary names service preflight non-claims', verificationSummary.includes('live_records_system_checked=false'));
assert('verification summary names runtime local activation run', verificationSummary.includes('runtime_local_activation_run_in_proof_pack=true'));
assert('verification summary names runtime local activation active profile', verificationSummary.includes('runtime_local_activation_active_profile_selection: selected=true; scope=local-disposable-proof-harness; profile=protected-records-disposable-runtime-profile'));
assert('verification summary names runtime local activation active profile nonclaims', verificationSummary.includes('live_runtime_profile_checked=false; selects_latest_profile=false'));
assert('verification summary names runtime local activation identity policy', verificationSummary.includes('runtime_local_activation_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('verification summary names runtime local activation applied', verificationSummary.includes('local_activation_applied=true; disposable_runtime_config_written=true; persistent_runtime_config_written=false'));
assert('verification summary names runtime local activation authority', verificationSummary.includes(`runtime_local_activation_authority: route=${RECORDS_WRITE_TERMINAL_ROUTE}`) && verificationSummary.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true') && verificationSummary.includes('missing_grant_refused=true; mismatched_grant_refused=true; revoked_grant_refused=true; expired_grant_refused=true; request_grant_refused=true'));
assert('verification summary names runtime profile installation run', verificationSummary.includes('runtime_profile_installation_run_in_proof_pack=true'));
assert('verification summary names runtime profile installation selection', verificationSummary.includes('selected_from_install_root=true; selected_by_id_and_sha=true; selects_latest_profile=false'));
assert('verification summary names runtime profile installation guard', verificationSummary.includes('runtime_config_refused=true; runtime_profile_refused=true; recognition_rule_refused=true; authority_grant_refused=true; all_refused_before_mutation=true'));
assert('verification summary names runtime profile installation identity policy', verificationSummary.includes('runtime_profile_installation_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true'));
assert('verification summary names runtime profile installation authority', verificationSummary.includes(`runtime_profile_installation_authority: route=${RECORDS_WRITE_TERMINAL_ROUTE}`) && verificationSummary.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true') && verificationSummary.includes('missing_grant_refused=true; mismatched_grant_refused=true; revoked_grant_refused=true; expired_grant_refused=true; request_grant_refused=true'));
assert('verification summary withholds runtime profile installation fixture rightful projection', verificationSummary.includes('runtime_profile_installation_non_claims: fixture_rightful_issuance=false; rightful_issuance=false') && verificationSummary.includes('current_machine_governance=false; consequence_lifecycle_closed=false'));
assert('verification summary is privacy safe', assertNoUnsafeLocalProofPackText(verificationSummary));
assert('verification json is privacy safe', assertNoUnsafeLocalProofPackText(JSON.stringify(verification, null, 2)));

const pinnedVerification = verifyLocalProofPackArtifact(parsedArtifact, {
  expectedArtifactBodySha256: artifact.integrity.body_sha256,
});
assertEqual('pinned verification expected SHA supplied', true, pinnedVerification.artifact_identity_expected_sha256_supplied);
assertEqual('pinned verification expected SHA exact', artifact.integrity.body_sha256, pinnedVerification.expected_artifact_body_sha256);
assertEqual('pinned verification identity matched', true, pinnedVerification.artifact_identity_sha256_matched);
assertEqual('pinned verification required SHA exact', artifact.integrity.body_sha256, pinnedVerification.required_body_sha256);
assertEqual('pinned verification required SHA matched', true, pinnedVerification.required_body_sha256_matched);
assertEqual('pinned verification coverage terminal projection allowed', true, pinnedVerification.coverage.terminal_claim_projection_allowed);
assertEqual('pinned verification coverage terminal identity matched', true, pinnedVerification.coverage.terminal_artifact_identity_sha256_matched);
assertEqual('pinned verification coverage terminal outer metadata bound', true, pinnedVerification.coverage.terminal_outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256);
assertEqual('pinned verification coverage terminal recognized source bound', true, pinnedVerification.coverage.terminal_recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256);
assertEqual('pinned verification coverage terminal signature valid', true, pinnedVerification.coverage.terminal_trusted_issuer_registry_signature_valid);
assertEqual('pinned verification coverage terminal fixture rightful path evidenced', true, pinnedVerification.coverage.terminal_fixture_rightful_issuance_path_evidenced);
assertEqual('pinned verification runtime local fixture rightful path evidenced', true, pinnedVerification.runtime_local_activation.fixture_rightful_issuance_path_evidenced);
assertEqual('pinned verification runtime installation fixture rightful path evidenced', true, pinnedVerification.runtime_profile_installation.fixture_rightful_issuance_path_evidenced);
assertEqual('pinned verification generic rightful issuance false', false, pinnedVerification.coverage.rightful_issuance_proven);
assertEqual('pinned verification lifecycle closure false', false, pinnedVerification.coverage.consequence_lifecycle_closed);

section('committed sample artifact');
const sampleArtifactText = readFileSync(SAMPLE_ARTIFACT_PATH, 'utf8');
assert('sample artifact text is privacy safe', assertNoUnsafeLocalProofPackText(sampleArtifactText));
const sampleArtifact = parseLocalProofPackArtifactText(sampleArtifactText);
assert('sample artifact passes validation', assertLocalProofPackArtifact(sampleArtifact));
assertEqual('sample artifact hash is stable', SAMPLE_ARTIFACT_SHA256, sampleArtifact.integrity.body_sha256);
const sampleVerification = verifyLocalProofPackArtifact(sampleArtifact, {
  expectedArtifactBodySha256: SAMPLE_ARTIFACT_SHA256,
});
assertEqual('sample artifact verifies true', true, sampleVerification.verified);
assertEqual('sample artifact verification sha matches', SAMPLE_ARTIFACT_SHA256, sampleVerification.body_sha256);
assertEqual('sample artifact verification component count', 16, sampleVerification.component_count);
assertEqual('sample artifact key-state run', true, sampleVerification.key_state_report.run_in_proof_pack);
assertEqual('sample artifact key-state report type', KEY_STATE_REPORT_TYPE, sampleVerification.key_state_report.report_type);
assertEqual('sample artifact key-state private key material read false', false, sampleVerification.key_state_report.private_key_material_read);
assertEqual('sample artifact key-state no key custody', false, sampleVerification.key_state_report.key_custody_proven);
assertEqual('sample artifact key-state no current-machine governance', false, sampleVerification.key_state_report.current_machine_governance_proven);
assertEqual('sample artifact receipt verifier run', true, sampleVerification.receipt_verifier_boundary.run_in_proof_pack);
assertEqual('sample artifact receipt verifier valid verdict', 'VALID', sampleVerification.receipt_verifier_boundary.valid_verdict);
assertEqual('sample artifact receipt verifier receipt sha present', true, sampleVerification.receipt_verifier_boundary.valid_receipt_sha256_present);
assertEqual('sample artifact receipt verifier required identity bound', true, sampleVerification.receipt_verifier_boundary.required_identity_receipt_sha256_matched);
assertEqual('sample artifact receipt verifier legacy v0 refused', true, sampleVerification.receipt_verifier_boundary.legacy_v0_required_identity_refused);
assertEqual('sample artifact receipt verifier unknown signer verdict', 'UNKNOWN-SIGNER', sampleVerification.receipt_verifier_boundary.unknown_signer_verdict);
assertEqual('sample artifact receipt verifier invalid verdict', 'INVALID', sampleVerification.receipt_verifier_boundary.invalid_verdict);
assertEqual('sample artifact receipt verifier distinguishes unknown signer', true, sampleVerification.receipt_verifier_boundary.distinguishes_unknown_signer_from_invalid);
assertEqual('sample artifact trusted registry verdict', 'RECOGNIZED', sampleVerification.trusted_issuer_registry_recognition.verdict);
assertEqual('sample artifact trusted registry fixture evaluated', true, sampleVerification.trusted_issuer_registry_recognition.registry_fixture_evaluated);
assertEqual('sample artifact trusted registry evaluator result type', 'downstream-recognition-rule-v1', sampleVerification.trusted_issuer_registry_recognition.registry_evaluation_result_type);
assertEqual('sample artifact trusted registry no live registry', false, sampleVerification.trusted_issuer_registry_recognition.live_trust_registry_state);
assertEqual('sample artifact trusted registry no current-machine governance', false, sampleVerification.trusted_issuer_registry_recognition.current_machine_governance_proven);
assertEqual('sample artifact downstream refusal run', true, sampleVerification.downstream_refusal.run_in_proof_pack);
assertEqual('sample artifact downstream recognized marker delta', 1, sampleVerification.downstream_refusal.recognized_marker_count_delta);
assertEqual('sample artifact downstream final marker count', 1, sampleVerification.downstream_refusal.final_marker_count);
assertEqual('sample artifact downstream refusal case count', DOWNSTREAM_REFUSAL_REASONS.length, sampleVerification.downstream_refusal.refusal_case_count);
assertEqual('sample artifact downstream refusal marker deltas zero', true, sampleVerification.downstream_refusal.all_refusal_marker_count_deltas_zero);
assertEqual('sample artifact service preflight run', true, sampleVerification.service_profile_preflight.run_in_proof_pack);
assertEqual('sample artifact service preflight cases', PROTECTED_RECORDS_SERVICE_PREFLIGHT_CASES.length, sampleVerification.service_profile_preflight.case_count);
assertEqual('sample artifact service preflight direct api with receipt refused', true, sampleVerification.service_profile_preflight.direct_api_with_receipt_refused);
assertEqual('sample artifact runtime local activation run', true, sampleVerification.runtime_local_activation.run_in_proof_pack);
assertEqual('sample artifact runtime local activation applied', true, sampleVerification.runtime_local_activation.local_activation_applied);
assertEqual('sample artifact runtime local activation missing receipt refused', true, sampleVerification.runtime_local_activation.missing_receipt_refused);
assertEqual('sample artifact runtime local activation wrong runtime profile id refused', true, sampleVerification.runtime_local_activation.wrong_runtime_profile_id_refused);
assertEqual('sample artifact runtime local activation wrong audit event refused', true, sampleVerification.runtime_local_activation.wrong_audit_event_refused);
assertEqual('sample artifact runtime local activation no hook config', false, sampleVerification.runtime_local_activation.hook_configuration_written);
assertRuntimeProfileIdentitySummary('sample artifact runtime local activation', sampleVerification.runtime_local_activation);
assertEqual('sample artifact runtime profile installation run', true, sampleVerification.runtime_profile_installation.run_in_proof_pack);
assertEqual('sample artifact runtime profile installation selected', true, sampleVerification.runtime_profile_installation.disposable_profile_selection.profile_selected_from_install_root);
assertEqual('sample artifact runtime profile installation request guard refused', true, sampleVerification.runtime_profile_installation.request_authority_guard_summary.all_refused_before_mutation);
assertEqual('sample artifact runtime profile installation missing receipt refused', true, sampleVerification.runtime_profile_installation.missing_receipt_refused);
assertEqual('sample artifact runtime profile installation wrong runtime profile id refused', true, sampleVerification.runtime_profile_installation.wrong_runtime_profile_id_refused);
assertEqual('sample artifact runtime profile installation wrong audit event refused', true, sampleVerification.runtime_profile_installation.wrong_audit_event_refused);
assertEqual('sample artifact runtime profile installation no hook config', false, sampleVerification.runtime_profile_installation.hook_configuration_written);
assertRuntimeProfileIdentitySummary('sample artifact runtime profile installation', sampleVerification.runtime_profile_installation);
assertEqual('sample artifact Claude hook replay run', true, sampleVerification.claude_hook_contract_replay.run_in_proof_pack);
assertEqual('sample artifact Claude hook replay adapter hash bound', claudeCodeHookContractReplayRepoAdapterSha256(), sampleVerification.claude_hook_contract_replay.adapter_sha256);
assertEqual('sample artifact Claude hook replay contract hash bound', claudeCodeHookContractReplayContractSha256(), sampleVerification.claude_hook_contract_replay.hook_replay_contract_sha256);
assertEqual('sample artifact Claude hook replay source boundary exact', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY, sampleVerification.claude_hook_contract_replay.source_state_boundary);
assertEqual('sample artifact Claude hook replay allow JSON', true, sampleVerification.claude_hook_contract_replay.permission_decisions_observed.allow);
assertEqual('sample artifact Claude hook replay deny JSON', true, sampleVerification.claude_hook_contract_replay.permission_decisions_observed.deny);
assertEqual('sample artifact Claude hook replay denied effect not executed', true, sampleVerification.claude_hook_contract_replay.denied_effect_not_executed);
assertEqual('sample artifact Claude hook replay missing gate fail closed', true, sampleVerification.claude_hook_contract_replay.missing_gate_failed_closed);
assertEqual('sample artifact Claude hook replay no live app passage', false, sampleVerification.claude_hook_contract_replay.live_claude_app_passage_proven);
assertEqual('sample artifact Claude hook replay no current-machine governance', false, sampleVerification.claude_hook_contract_replay.current_machine_governance_proven);
const sampleDirectApiReceiptSummary = sampleVerification.service_profile_preflight.case_summaries.find((item) =>
  item.case_id === 'direct_api_profile_receipt_present_refused_before_service_mutation'
);
assertEqual('sample artifact service preflight direct api receipt reason', 'request_stream_forbidden_fields', sampleDirectApiReceiptSummary.reason_code);
assertEqual('sample artifact service preflight direct api receipt state delta', 0, sampleDirectApiReceiptSummary.state_entry_count_delta);

section('fail closed validation');
const liveProbeClaim = structuredClone(report);
liveProbeClaim.live_probing = true;
assertThrows('live probing claim fails', () => assertLocalProofPack(liveProbeClaim), 'must not perform live probing');

const extraRootField = structuredClone(report);
extraRootField.unreviewed_claim = 'not allowed';
assertThrows('unexpected proof-pack root field fails', () => assertLocalProofPack(extraRootField), 'unexpected fields');

const missingRootField = structuredClone(report);
delete missingRootField.safe_claim_ceiling;
assertThrows('missing proof-pack root field fails', () => assertLocalProofPack(missingRootField), 'unexpected fields');

const renamedRootField = structuredClone(report);
renamedRootField.safe_claim_summary = renamedRootField.safe_claim_ceiling;
delete renamedRootField.safe_claim_ceiling;
assertThrows('renamed proof-pack root field fails', () => assertLocalProofPack(renamedRootField), 'unexpected fields');

const summaryRootField = structuredClone(report);
summaryRootField.claim_boundary_summary = {
  safe_claim_ceiling: summaryRootField.safe_claim_ceiling,
};
assertThrows('summary-shaped proof-pack root field fails', () => assertLocalProofPack(summaryRootField), 'unexpected fields');

const renamedComponentFamily = structuredClone(report);
component(renamedComponentFamily, 'downstream_refusal_proof').component = 'downstream_refusal_summary';
assertThrows('renamed proof-pack component fails', () => assertLocalProofPack(renamedComponentFamily), 'components drifted');

const brokenCoverage = structuredClone(report);
component(brokenCoverage, 'governed_surface_coverage_map').governed_lanes = 0;
assertThrows('ungoverned coverage fails', () => assertLocalProofPack(brokenCoverage), 'coverage component');

const extraDownstreamField = structuredClone(report);
component(extraDownstreamField, 'downstream_refusal_proof').unreviewed_claim = 'not allowed';
assertThrows('unexpected downstream component field fails', () => assertLocalProofPack(extraDownstreamField), 'unexpected fields');

const missingDownstreamField = structuredClone(report);
delete component(missingDownstreamField, 'downstream_refusal_proof').final_marker_count;
assertThrows('missing downstream component field fails', () => assertLocalProofPack(missingDownstreamField), 'unexpected fields');

const renamedDownstreamField = structuredClone(report);
component(renamedDownstreamField, 'downstream_refusal_proof').final_marker_total =
  component(renamedDownstreamField, 'downstream_refusal_proof').final_marker_count;
delete component(renamedDownstreamField, 'downstream_refusal_proof').final_marker_count;
assertThrows('renamed downstream component field fails', () => assertLocalProofPack(renamedDownstreamField), 'unexpected fields');

const summaryDownstreamField = structuredClone(report);
component(summaryDownstreamField, 'downstream_refusal_proof').refusal_summary = {
  refusal_case_count: component(summaryDownstreamField, 'downstream_refusal_proof').refusal_case_count,
};
assertThrows('summary-shaped downstream component field fails', () => assertLocalProofPack(summaryDownstreamField), 'unexpected fields');

const missingDownstreamMutation = structuredClone(report);
component(missingDownstreamMutation, 'downstream_refusal_proof').recognized_marker_count_delta = 0;
assertThrows('missing downstream recognized mutation fails', () => assertLocalProofPack(missingDownstreamMutation), 'downstream refusal component');

const downstreamRefusalMutation = structuredClone(report);
component(downstreamRefusalMutation, 'downstream_refusal_proof').all_refusal_marker_count_deltas_zero = false;
assertThrows('downstream refusal mutation fails', () => assertLocalProofPack(downstreamRefusalMutation), 'downstream refusal component');

const reorderedDownstreamReasons = structuredClone(report);
component(reorderedDownstreamReasons, 'downstream_refusal_proof').refusal_reasons =
  [...component(reorderedDownstreamReasons, 'downstream_refusal_proof').refusal_reasons].reverse();
assertThrows('reordered downstream refusal reasons fail', () => assertLocalProofPack(reorderedDownstreamReasons), 'refusal reasons drifted');

const keyStateCustodyClaim = structuredClone(report);
component(keyStateCustodyClaim, 'key_state_report').key_custody_proven = true;
assertThrows('key-state custody claim fails', () => assertLocalProofPack(keyStateCustodyClaim), 'key-state component');

const keyStatePrivateKeyReadClaim = structuredClone(report);
component(keyStatePrivateKeyReadClaim, 'key_state_report').privacy.private_key_material_read = true;
assertThrows('key-state private key read claim fails', () => assertLocalProofPack(keyStatePrivateKeyReadClaim), 'key-state component');

const keyStateCurrentMachineClaim = structuredClone(report);
component(keyStateCurrentMachineClaim, 'key_state_report').current_machine_governance_proven = true;
assertThrows('key-state current-machine governance claim fails', () => assertLocalProofPack(keyStateCurrentMachineClaim), 'key-state component');

const missingProtectedReason = structuredClone(report);
component(missingProtectedReason, 'protected_records_terminal').refusal_reasons =
  component(missingProtectedReason, 'protected_records_terminal').refusal_reasons.filter((reason) => reason !== 'unknown_issuer');
assertThrows('missing protected refusal reason fails', () => assertLocalProofPack(missingProtectedReason), 'unknown_issuer');

const driftedProtectedRoute = structuredClone(report);
component(driftedProtectedRoute, 'protected_records_terminal').profile_contract_route = 'monitor-after-record-write';
assertThrows('drifted protected profile route fails', () => assertLocalProofPack(driftedProtectedRoute), 'protected records component');

const driftedProtectedReplayPolicy = structuredClone(report);
component(driftedProtectedReplayPolicy, 'protected_records_terminal').receipt_replay_policy = 'none';
assertThrows('drifted protected replay policy fails', () => assertLocalProofPack(driftedProtectedReplayPolicy), 'protected records component');

const driftedAdapterRoute = structuredClone(report);
component(driftedAdapterRoute, 'protected_records_terminal').adapter_authoritative_route = 'monitor-after-ledger-append';
assertThrows('drifted adapter route fails', () => assertLocalProofPack(driftedAdapterRoute), 'protected records component');

const openAdapterDirectWrite = structuredClone(report);
component(openAdapterDirectWrite, 'protected_records_terminal').adapter_direct_write_path_available = true;
assertThrows('open adapter direct write path fails', () => assertLocalProofPack(openAdapterDirectWrite), 'protected records component');

const liveRecordsAdapterClaim = structuredClone(report);
component(liveRecordsAdapterClaim, 'protected_records_terminal').adapter_live_records_adapter = true;
assertThrows('live records adapter claim fails', () => assertLocalProofPack(liveRecordsAdapterClaim), 'protected records component');

const driftedAdapterAction = structuredClone(report);
component(driftedAdapterAction, 'protected_records_terminal').adapter_action_command = 'zlar protected-records-write --latest';
assertThrows('drifted adapter action command fails', () => assertLocalProofPack(driftedAdapterAction), 'protected records component');

const liveAdapterActionClaim = structuredClone(report);
component(liveAdapterActionClaim, 'protected_records_terminal').adapter_action_live_records_adapter = true;
assertThrows('live adapter action claim fails', () => assertLocalProofPack(liveAdapterActionClaim), 'protected records component');

const adapterConformanceReplayBoards = structuredClone(report);
component(adapterConformanceReplayBoards, 'protected_records_adapter_conformance').replay_refused = false;
assertThrows('adapter conformance replay boarding fails', () => assertLocalProofPack(adapterConformanceReplayBoards), 'adapter conformance component');

const adapterConformanceMissingCase = structuredClone(report);
component(adapterConformanceMissingCase, 'protected_records_adapter_conformance').conformance_cases =
  component(adapterConformanceMissingCase, 'protected_records_adapter_conformance').conformance_cases.filter((caseId) => caseId !== 'unsupported_direct_write_option_refused');
assertThrows('adapter conformance missing case fails', () => assertLocalProofPack(adapterConformanceMissingCase), 'unsupported_direct_write_option_refused');

const adapterConformanceFilesystemClaim = structuredClone(report);
component(adapterConformanceFilesystemClaim, 'protected_records_adapter_conformance').direct_filesystem_write_to_fixture_paths_closed = true;
assertThrows('adapter conformance filesystem closure claim fails', () => assertLocalProofPack(adapterConformanceFilesystemClaim), 'adapter conformance component');

const serviceReplayBoards = structuredClone(report);
component(serviceReplayBoards, 'protected_records_downstream_service').replay_refused = false;
assertThrows('service replay boarding fails', () => assertLocalProofPack(serviceReplayBoards), 'downstream service component');

const serviceProfileShaDrift = structuredClone(report);
component(serviceProfileShaDrift, 'protected_records_downstream_service').service_profile_preflight_profile_sha256 = '0'.repeat(64);
assertThrows('service preflight profile sha drift fails', () => assertLocalProofPack(serviceProfileShaDrift), 'downstream service component');

const serviceProfileRunMissing = structuredClone(report);
component(serviceProfileRunMissing, 'protected_records_downstream_service').service_profile_preflight_run_in_proof_pack = false;
assertThrows('service preflight missing run fails', () => assertLocalProofPack(serviceProfileRunMissing), 'downstream service component');

const serviceProfileCaseCountDrift = structuredClone(report);
component(serviceProfileCaseCountDrift, 'protected_records_downstream_service').service_profile_preflight_case_count = 8;
assertThrows('service preflight case count drift fails', () => assertLocalProofPack(serviceProfileCaseCountDrift), 'downstream service component');

const serviceProfileMissingCase = structuredClone(report);
component(serviceProfileMissingCase, 'protected_records_downstream_service').service_profile_preflight_cases =
  component(serviceProfileMissingCase, 'protected_records_downstream_service').service_profile_preflight_cases.filter((caseId) =>
    caseId !== 'direct_api_profile_receipt_present_refused_before_service_mutation'
  );
assertThrows('service preflight missing case fails', () => assertLocalProofPack(serviceProfileMissingCase), 'direct_api_profile_receipt_present_refused_before_service_mutation');

const serviceProfileDirectApiWithReceiptBoards = structuredClone(report);
component(serviceProfileDirectApiWithReceiptBoards, 'protected_records_downstream_service').service_profile_preflight_direct_api_with_receipt_refused = false;
assertThrows('service preflight direct api receipt boarding fails', () => assertLocalProofPack(serviceProfileDirectApiWithReceiptBoards), 'downstream service component');

const serviceProfileWrongPolicyBoards = structuredClone(report);
component(serviceProfileWrongPolicyBoards, 'protected_records_downstream_service').service_profile_preflight_wrong_policy_refused = false;
assertThrows('service preflight wrong policy boarding fails', () => assertLocalProofPack(serviceProfileWrongPolicyBoards), 'downstream service component');

const serviceProfileLiveActivationClaim = structuredClone(report);
component(serviceProfileLiveActivationClaim, 'protected_records_downstream_service').service_profile_preflight_runtime_profile_activation_checked = true;
assertThrows('service preflight runtime activation claim fails', () => assertLocalProofPack(serviceProfileLiveActivationClaim), 'downstream service component');

const serviceProfileExternalAttestationClaim = structuredClone(report);
component(serviceProfileExternalAttestationClaim, 'protected_records_downstream_service').service_profile_preflight_external_attestation = true;
assertThrows('service preflight external attestation claim fails', () => assertLocalProofPack(serviceProfileExternalAttestationClaim), 'downstream service component');

const serviceDirectApiBoards = structuredClone(report);
component(serviceDirectApiBoards, 'protected_records_downstream_service').direct_api_without_receipt_refused = false;
assertThrows('service direct api boarding fails', () => assertLocalProofPack(serviceDirectApiBoards), 'downstream service component');

const serviceInvalidBoards = structuredClone(report);
component(serviceInvalidBoards, 'protected_records_downstream_service').invalid_receipt_refused = false;
assertThrows('service invalid receipt boarding fails', () => assertLocalProofPack(serviceInvalidBoards), 'downstream service component');

const serviceUnknownMutates = structuredClone(report);
component(serviceUnknownMutates, 'protected_records_downstream_service').unknown_issuer_state_delta = 1;
assertThrows('service unknown issuer mutation fails', () => assertLocalProofPack(serviceUnknownMutates), 'downstream service component');

const serviceStaleReasonDrift = structuredClone(report);
component(serviceStaleReasonDrift, 'protected_records_downstream_service').stale_receipt_reason = 'recognized';
assertThrows('service stale reason drift fails', () => assertLocalProofPack(serviceStaleReasonDrift), 'downstream service component');

const serviceFilesystemClaim = structuredClone(report);
component(serviceFilesystemClaim, 'protected_records_downstream_service').direct_filesystem_write_to_fixture_paths_closed = true;
assertThrows('service filesystem closure claim fails', () => assertLocalProofPack(serviceFilesystemClaim), 'downstream service component');

const runtimePreflightShaDrift = structuredClone(report);
component(runtimePreflightShaDrift, 'protected_records_runtime_profile_preflight_identity').profile_sha256 = '0'.repeat(64);
assertThrows('runtime preflight profile sha drift fails', () => assertLocalProofPack(runtimePreflightShaDrift), 'runtime profile preflight identity');

const runtimePreflightRunClaim = structuredClone(report);
component(runtimePreflightRunClaim, 'protected_records_runtime_profile_preflight_identity').runtime_profile_preflight_run_in_proof_pack = true;
assertThrows('runtime preflight run claim fails', () => assertLocalProofPack(runtimePreflightRunClaim), 'runtime profile preflight identity');

const runtimeProofRunClaim = structuredClone(report);
component(runtimeProofRunClaim, 'protected_records_runtime_profile_preflight_identity').runtime_profile_proof_run_in_proof_pack = true;
assertThrows('runtime proof run claim fails', () => assertLocalProofPack(runtimeProofRunClaim), 'runtime profile preflight identity');

const runtimePreflightAnchorExposure = structuredClone(report);
component(runtimePreflightAnchorExposure, 'protected_records_runtime_profile_preflight_identity').consumed_grant_store_anchor_path_exposed_to_agent = true;
assertThrows('runtime preflight anchor exposure claim fails', () => assertLocalProofPack(runtimePreflightAnchorExposure), 'runtime profile preflight identity');

const runtimePreflightRollbackClosure = structuredClone(report);
component(runtimePreflightRollbackClosure, 'protected_records_runtime_profile_preflight_identity').store_anchor_and_witness_joint_rollback_detection = true;
assertThrows('runtime preflight rollback closure claim fails', () => assertLocalProofPack(runtimePreflightRollbackClosure), 'runtime profile preflight identity');

const runtimeActivationPlanShaDrift = structuredClone(report);
component(runtimeActivationPlanShaDrift, 'protected_records_runtime_activation_preflight').plan_sha256 = '0'.repeat(64);
assertThrows('runtime activation plan sha drift fails', () => assertLocalProofPack(runtimeActivationPlanShaDrift), 'runtime activation preflight component');

const runtimeActivationProfileShaDrift = structuredClone(report);
component(runtimeActivationProfileShaDrift, 'protected_records_runtime_activation_preflight').runtime_profile_sha256 = '0'.repeat(64);
assertThrows('runtime activation profile sha drift fails', () => assertLocalProofPack(runtimeActivationProfileShaDrift), 'runtime activation preflight component');

const runtimeActivationProfileShaMismatch = structuredClone(report);
component(runtimeActivationProfileShaMismatch, 'protected_records_runtime_activation_preflight').runtime_profile_sha_matches_plan = false;
assertThrows('runtime activation profile sha mismatch fails', () => assertLocalProofPack(runtimeActivationProfileShaMismatch), 'runtime activation preflight component');

const runtimeActivationPreflightMissingClaim = structuredClone(report);
component(runtimeActivationPreflightMissingClaim, 'protected_records_runtime_activation_preflight').runtime_activation_preflight_run_in_proof_pack = false;
assertThrows('runtime activation preflight missing claim fails', () => assertLocalProofPack(runtimeActivationPreflightMissingClaim), 'runtime activation preflight component');

const runtimeActivationRuntimePreflightMissingClaim = structuredClone(report);
component(runtimeActivationRuntimePreflightMissingClaim, 'protected_records_runtime_activation_preflight').runtime_profile_preflight_run_in_proof_pack = false;
assertThrows('runtime activation runtime preflight missing claim fails', () => assertLocalProofPack(runtimeActivationRuntimePreflightMissingClaim), 'runtime activation preflight component');

const runtimeActivationRuntimeProofMissingClaim = structuredClone(report);
component(runtimeActivationRuntimeProofMissingClaim, 'protected_records_runtime_activation_preflight').runtime_profile_proof_run_in_proof_pack = false;
assertThrows('runtime activation runtime proof missing claim fails', () => assertLocalProofPack(runtimeActivationRuntimeProofMissingClaim), 'runtime activation preflight component');

const runtimeActivationAppliedClaim = structuredClone(report);
component(runtimeActivationAppliedClaim, 'protected_records_runtime_activation_preflight').activation_applied = true;
assertThrows('runtime activation applied claim fails', () => assertLocalProofPack(runtimeActivationAppliedClaim), 'runtime activation preflight component');

const runtimeActivationConfigWriteClaim = structuredClone(report);
component(runtimeActivationConfigWriteClaim, 'protected_records_runtime_activation_preflight').writes_runtime_config = true;
assertThrows('runtime activation config write claim fails', () => assertLocalProofPack(runtimeActivationConfigWriteClaim), 'runtime activation preflight component');

const runtimeActivationHookWriteClaim = structuredClone(report);
component(runtimeActivationHookWriteClaim, 'protected_records_runtime_activation_preflight').writes_hook_configuration = true;
assertThrows('runtime activation hook write claim fails', () => assertLocalProofPack(runtimeActivationHookWriteClaim), 'runtime activation preflight component');

const runtimeActivationLatestClaim = structuredClone(report);
component(runtimeActivationLatestClaim, 'protected_records_runtime_activation_preflight').selects_latest_profile = true;
assertThrows('runtime activation latest selection claim fails', () => assertLocalProofPack(runtimeActivationLatestClaim), 'runtime activation preflight component');

const runtimeActivationAuthorityClaim = structuredClone(report);
component(runtimeActivationAuthorityClaim, 'protected_records_runtime_activation_preflight').request_stream_authority_material_accepted = true;
assertThrows('runtime activation request authority claim fails', () => assertLocalProofPack(runtimeActivationAuthorityClaim), 'runtime activation preflight component');

const runtimeActivationIdentityDrift = structuredClone(report);
component(runtimeActivationIdentityDrift, 'protected_records_runtime_activation_preflight').omitted_runtime_profile_id_uses_launcher_config = false;
assertThrows('runtime activation identity policy drift fails', () => assertLocalProofPack(runtimeActivationIdentityDrift), 'runtime activation preflight component');

const runtimeLocalActivationMissingClaim = structuredClone(report);
component(runtimeLocalActivationMissingClaim, 'protected_records_runtime_local_activation').runtime_local_activation_run_in_proof_pack = false;
assertThrows('runtime local activation missing run fails', () => assertLocalProofPack(runtimeLocalActivationMissingClaim), 'runtime local activation component');

const runtimeLocalActivationPersistentConfigClaim = structuredClone(report);
component(runtimeLocalActivationPersistentConfigClaim, 'protected_records_runtime_local_activation').persistent_runtime_config_written = true;
assertThrows('runtime local activation persistent config claim fails', () => assertLocalProofPack(runtimeLocalActivationPersistentConfigClaim), 'runtime local activation component');

const runtimeLocalActivationHookClaim = structuredClone(report);
component(runtimeLocalActivationHookClaim, 'protected_records_runtime_local_activation').hook_configuration_written = true;
assertThrows('runtime local activation hook claim fails', () => assertLocalProofPack(runtimeLocalActivationHookClaim), 'runtime local activation component');

const runtimeLocalActivationMissingReceiptBoards = structuredClone(report);
component(runtimeLocalActivationMissingReceiptBoards, 'protected_records_runtime_local_activation').missing_receipt_refused = false;
assertThrows('runtime local activation missing receipt boarding fails', () => assertLocalProofPack(runtimeLocalActivationMissingReceiptBoards), 'runtime local activation component');

const runtimeLocalActivationIdentityDrift = structuredClone(report);
component(runtimeLocalActivationIdentityDrift, 'protected_records_runtime_local_activation').omitted_runtime_profile_id_uses_launcher_config = false;
assertThrows('runtime local activation identity policy drift fails', () => assertLocalProofPack(runtimeLocalActivationIdentityDrift), 'runtime local activation component');

const runtimeProfileInstallationMissingClaim = structuredClone(report);
component(runtimeProfileInstallationMissingClaim, 'protected_records_runtime_profile_installation').runtime_profile_installation_run_in_proof_pack = false;
assertThrows('runtime profile installation missing run fails', () => assertLocalProofPack(runtimeProfileInstallationMissingClaim), 'runtime profile installation component');

const runtimeProfileInstallationPersistentClaim = structuredClone(report);
component(runtimeProfileInstallationPersistentClaim, 'protected_records_runtime_profile_installation').persistent_runtime_profile_installed = true;
assertThrows('runtime profile installation persistent claim fails', () => assertLocalProofPack(runtimeProfileInstallationPersistentClaim), 'runtime profile installation component');

const runtimeProfileInstallationLatestClaim = structuredClone(report);
component(runtimeProfileInstallationLatestClaim, 'protected_records_runtime_profile_installation').disposable_profile_selection.selects_latest_profile = true;
assertThrows('runtime profile installation latest claim fails', () => assertLocalProofPack(runtimeProfileInstallationLatestClaim), 'disposable profile selection drifted');

const runtimeProfileInstallationGuardBypass = structuredClone(report);
component(runtimeProfileInstallationGuardBypass, 'protected_records_runtime_profile_installation').request_authority_guard_summary.runtime_config_refused = false;
assertThrows('runtime profile installation request guard bypass fails', () => assertLocalProofPack(runtimeProfileInstallationGuardBypass), 'request authority guard drifted');

const runtimeProfileInstallationHookClaim = structuredClone(report);
component(runtimeProfileInstallationHookClaim, 'protected_records_runtime_profile_installation').hook_configuration_written = true;
assertThrows('runtime profile installation hook claim fails', () => assertLocalProofPack(runtimeProfileInstallationHookClaim), 'runtime profile installation component');

const runtimeProfileInstallationIdentityDrift = structuredClone(report);
component(runtimeProfileInstallationIdentityDrift, 'protected_records_runtime_profile_installation').omitted_runtime_profile_id_uses_launcher_config = false;
assertThrows('runtime profile installation identity policy drift fails', () => assertLocalProofPack(runtimeProfileInstallationIdentityDrift), 'runtime profile installation component');

const claudeHookReplayLiveClaim = structuredClone(report);
component(claudeHookReplayLiveClaim, 'claude_code_hook_contract_replay').live_claude_invoked = true;
assertThrows('Claude hook replay live claim fails', () => assertLocalProofPack(claudeHookReplayLiveClaim), 'Claude Code hook-contract replay');

const claudeHookReplayCurrentMachineClaim = structuredClone(report);
component(claudeHookReplayCurrentMachineClaim, 'claude_code_hook_contract_replay').current_machine_governance_proven = true;
assertThrows('Claude hook replay current-machine claim fails', () => assertLocalProofPack(claudeHookReplayCurrentMachineClaim), 'Claude Code hook-contract replay');

const claudeHookReplayMissingCase = structuredClone(report);
component(claudeHookReplayMissingCase, 'claude_code_hook_contract_replay').required_cases =
  component(claudeHookReplayMissingCase, 'claude_code_hook_contract_replay').required_cases.filter((item) =>
    item !== 'blank_gate_response_fails_closed'
  );
assertThrows('Claude hook replay missing case fails', () => assertLocalProofPack(claudeHookReplayMissingCase), 'required cases');

const claudeHookReplayStaleAdapterHash = structuredClone(report);
component(claudeHookReplayStaleAdapterHash, 'claude_code_hook_contract_replay').adapter_sha256 = '0'.repeat(64);
assertThrows('Claude hook replay stale adapter hash fails', () => assertLocalProofPack(claudeHookReplayStaleAdapterHash), 'Claude Code hook-contract replay');

const claudeHookReplayStaleContractHash = structuredClone(report);
component(claudeHookReplayStaleContractHash, 'claude_code_hook_contract_replay').hook_replay_contract_sha256 = '0'.repeat(64);
assertThrows('Claude hook replay stale contract hash fails', () => assertLocalProofPack(claudeHookReplayStaleContractHash), 'Claude Code hook-contract replay');

const claudeHookReplaySourceBoundaryOverclaim = structuredClone(report);
component(claudeHookReplaySourceBoundaryOverclaim, 'claude_code_hook_contract_replay').source_state_boundary = 'source state freshness preserved by artifact';
assertThrows('Claude hook replay source boundary overclaim fails', () => assertLocalProofPack(claudeHookReplaySourceBoundaryOverclaim), 'Claude Code hook-contract replay');

const claudeHookReplaySummaryOnly = structuredClone(report);
delete component(claudeHookReplaySummaryOnly, 'claude_code_hook_contract_replay').case_evidence;
assertThrows('Claude hook replay summary-only evidence fails', () => assertLocalProofPack(claudeHookReplaySummaryOnly), 'unexpected fields');

const claudeHookReplayCaseEvidenceHashDrift = structuredClone(report);
component(claudeHookReplayCaseEvidenceHashDrift, 'claude_code_hook_contract_replay').case_evidence.sentinel.unchanged = false;
assertThrows('Claude hook replay case evidence hash drift fails', () => assertLocalProofPack(claudeHookReplayCaseEvidenceHashDrift), 'Claude Code hook-contract replay');

const claudeHookReplayForgedCaseEvidence = structuredClone(report);
component(claudeHookReplayForgedCaseEvidence, 'claude_code_hook_contract_replay').case_evidence.cases[0].permission_decision = 'deny';
component(claudeHookReplayForgedCaseEvidence, 'claude_code_hook_contract_replay').case_evidence_sha256 = createHash('sha256')
  .update(canonicalize(component(claudeHookReplayForgedCaseEvidence, 'claude_code_hook_contract_replay').case_evidence), 'utf8')
  .digest('hex');
assertThrows('Claude hook replay forged case evidence fails', () => assertLocalProofPack(claudeHookReplayForgedCaseEvidence), 'case evidence drifted');

const claudeHookReplayForgedMalformedStdoutSemantics = structuredClone(report);
component(claudeHookReplayForgedMalformedStdoutSemantics, 'claude_code_hook_contract_replay')
  .case_evidence.cases.find((item) => item.case_id === 'malformed_output_refused')
  .stdout_json_valid = true;
component(claudeHookReplayForgedMalformedStdoutSemantics, 'claude_code_hook_contract_replay').case_evidence_sha256 = createHash('sha256')
  .update(canonicalize(component(claudeHookReplayForgedMalformedStdoutSemantics, 'claude_code_hook_contract_replay').case_evidence), 'utf8')
  .digest('hex');
assertThrows('Claude hook replay forged malformed stdout semantics fail', () => assertLocalProofPack(claudeHookReplayForgedMalformedStdoutSemantics), 'case evidence drifted');

const claudeHookReplayForgedHookEventSemantics = structuredClone(report);
component(claudeHookReplayForgedHookEventSemantics, 'claude_code_hook_contract_replay')
  .case_evidence.cases.find((item) => item.case_id === 'allow_pwd_hook_json')
  .hook_event_name = 'Stop';
component(claudeHookReplayForgedHookEventSemantics, 'claude_code_hook_contract_replay').case_evidence_sha256 = createHash('sha256')
  .update(canonicalize(component(claudeHookReplayForgedHookEventSemantics, 'claude_code_hook_contract_replay').case_evidence), 'utf8')
  .digest('hex');
assertThrows('Claude hook replay forged hook event semantics fail', () => assertLocalProofPack(claudeHookReplayForgedHookEventSemantics), 'case evidence drifted');

const claudeHookReplayForgedDenySemantics = structuredClone(report);
component(claudeHookReplayForgedDenySemantics, 'claude_code_hook_contract_replay')
  .case_evidence.cases.find((item) => item.case_id === 'deny_destructive_sentinel_hook_json')
  .refused_before_effect = false;
component(claudeHookReplayForgedDenySemantics, 'claude_code_hook_contract_replay').case_evidence_sha256 = createHash('sha256')
  .update(canonicalize(component(claudeHookReplayForgedDenySemantics, 'claude_code_hook_contract_replay').case_evidence), 'utf8')
  .digest('hex');
assertThrows('Claude hook replay forged deny semantics fail', () => assertLocalProofPack(claudeHookReplayForgedDenySemantics), 'case evidence drifted');

const claudeHookReplayForgedMissingGateSemantics = structuredClone(report);
component(claudeHookReplayForgedMissingGateSemantics, 'claude_code_hook_contract_replay')
  .case_evidence.cases.find((item) => item.case_id === 'missing_gate_fails_closed')
  .gate_mode = 'fixture-gate';
component(claudeHookReplayForgedMissingGateSemantics, 'claude_code_hook_contract_replay').case_evidence_sha256 = createHash('sha256')
  .update(canonicalize(component(claudeHookReplayForgedMissingGateSemantics, 'claude_code_hook_contract_replay').case_evidence), 'utf8')
  .digest('hex');
assertThrows('Claude hook replay forged missing-gate semantics fail', () => assertLocalProofPack(claudeHookReplayForgedMissingGateSemantics), 'case evidence drifted');

const claudeHookReplayForgedNonPreToolUseSemantics = structuredClone(report);
component(claudeHookReplayForgedNonPreToolUseSemantics, 'claude_code_hook_contract_replay')
  .case_evidence.cases.find((item) => item.case_id === 'non_pretooluse_payload_denied_by_fixture_gate')
  .proof_refusal_reason = null;
component(claudeHookReplayForgedNonPreToolUseSemantics, 'claude_code_hook_contract_replay').case_evidence_sha256 = createHash('sha256')
  .update(canonicalize(component(claudeHookReplayForgedNonPreToolUseSemantics, 'claude_code_hook_contract_replay').case_evidence), 'utf8')
  .digest('hex');
assertThrows('Claude hook replay forged non-PreToolUse semantics fail', () => assertLocalProofPack(claudeHookReplayForgedNonPreToolUseSemantics), 'case evidence drifted');

const claudeHookReplayForgedInputContract = structuredClone(report);
component(claudeHookReplayForgedInputContract, 'claude_code_hook_contract_replay')
  .case_evidence.cases.find((item) => item.case_id === 'allow_pwd_hook_json')
  .input_contract_sha256 = '0'.repeat(64);
component(claudeHookReplayForgedInputContract, 'claude_code_hook_contract_replay').case_evidence_sha256 = createHash('sha256')
  .update(canonicalize(component(claudeHookReplayForgedInputContract, 'claude_code_hook_contract_replay').case_evidence), 'utf8')
  .digest('hex');
assertThrows('Claude hook replay forged input contract fails', () => assertLocalProofPack(claudeHookReplayForgedInputContract), 'case evidence drifted');

const claudeHookReplayReducedSideDoors = structuredClone(report);
component(claudeHookReplayReducedSideDoors, 'claude_code_hook_contract_replay').side_doors =
  component(claudeHookReplayReducedSideDoors, 'claude_code_hook_contract_replay').side_doors.filter((item) =>
    item !== 'Claude Stop hook and non-PreToolUse surfaces'
  );
assertThrows('Claude hook replay reduced side-door list fails', () => assertLocalProofPack(claudeHookReplayReducedSideDoors), 'Claude Code hook-contract replay');

const claudeHookReplayReorderedNonClaims = structuredClone(report);
component(claudeHookReplayReorderedNonClaims, 'claude_code_hook_contract_replay').non_claims =
  [...component(claudeHookReplayReorderedNonClaims, 'claude_code_hook_contract_replay').non_claims].reverse();
assertThrows('Claude hook replay reordered non-claims fail', () => assertLocalProofPack(claudeHookReplayReorderedNonClaims), 'Claude Code hook-contract replay');

const missingProtectedReceiptField = structuredClone(report);
component(missingProtectedReceiptField, 'protected_records_terminal').required_receipt_fields =
  component(missingProtectedReceiptField, 'protected_records_terminal').required_receipt_fields.filter((field) => field !== 'payload.detail_hash');
assertThrows('missing protected receipt field fails', () => assertLocalProofPack(missingProtectedReceiptField), 'payload.detail_hash');

const brokenHumanAuthorization = structuredClone(report);
component(brokenHumanAuthorization, 'human_authorization_proof').authorized_boarded = false;
assertThrows('broken human authorization fails', () => assertLocalProofPack(brokenHumanAuthorization), 'human authorization component');

const brokenApprovalTransport = structuredClone(report);
component(brokenApprovalTransport, 'approval_transport_proof').signed_human_decision_boarded = false;
assertThrows('broken approval transport fails', () => assertLocalProofPack(brokenApprovalTransport), 'approval transport component');

const brokenIssuerStatus = structuredClone(report);
component(brokenIssuerStatus, 'issuer_status_proof').unknown_issuer_refused = false;
assertThrows('broken issuer status fails', () => assertLocalProofPack(brokenIssuerStatus), 'issuer status component');

const receiptVerifierUnknownSignerCollapsed = structuredClone(report);
component(receiptVerifierUnknownSignerCollapsed, 'receipt_verifier_boundary').unknown_signer_verdict = 'INVALID';
assertThrows('receipt verifier unknown signer collapse fails', () => assertLocalProofPack(receiptVerifierUnknownSignerCollapsed), 'UNKNOWN-SIGNER case');

const receiptVerifierInvalidExitDrift = structuredClone(report);
component(receiptVerifierInvalidExitDrift, 'receipt_verifier_boundary').invalid_exit_code = 3;
assertThrows('receipt verifier invalid exit drift fails', () => assertLocalProofPack(receiptVerifierInvalidExitDrift), 'INVALID case');

const receiptVerifierIssuerRecognitionClaim = structuredClone(report);
component(receiptVerifierIssuerRecognitionClaim, 'receipt_verifier_boundary').issuer_recognition_proven = true;
assertThrows('receipt verifier issuer recognition claim fails', () => assertLocalProofPack(receiptVerifierIssuerRecognitionClaim), 'issuer_recognition_proven');

const receiptVerifierRequiredIdentityDrift = structuredClone(report);
component(receiptVerifierRequiredIdentityDrift, 'receipt_verifier_boundary').required_identity_receipt_sha256_matched = false;
assertThrows('receipt verifier required identity drift fails', () => assertLocalProofPack(receiptVerifierRequiredIdentityDrift), 'required identity case');

const receiptVerifierLegacyV0RequiredIdentityClaim = structuredClone(report);
component(receiptVerifierLegacyV0RequiredIdentityClaim, 'receipt_verifier_boundary').legacy_v0_required_identity_refused = false;
assertThrows('receipt verifier legacy v0 required identity claim fails', () => assertLocalProofPack(receiptVerifierLegacyV0RequiredIdentityClaim), 'legacy v0 required identity');

const rootNonClaimSubstitution = structuredClone(report);
rootNonClaimSubstitution.non_claims = [
  ...rootNonClaimSubstitution.non_claims.slice(0, -1),
  'This proof pack proves live Claude application passage.',
];
assertThrows('root non-claim substitution fails', () => assertLocalProofPack(rootNonClaimSubstitution), 'Local proof pack non-claims drifted');

const reorderedComponents = structuredClone(report);
reorderedComponents.components = [...reorderedComponents.components].reverse();
assertThrows('reordered proof-pack components fail', () => assertLocalProofPack(reorderedComponents), 'components drifted');

const openCoverageOverclaim = structuredClone(report);
component(openCoverageOverclaim, 'governed_surface_coverage_map').production_authority = true;
assertThrows('open coverage component overclaim fails', () => assertLocalProofPack(openCoverageOverclaim), 'unexpected fields');

for (const [field, value] of [
  ['terminal_artifact_body_sha256', '0'.repeat(64)],
  ['terminal_artifact_expected_body_sha256', '0'.repeat(64)],
  ['terminal_artifact_identity_sha256_matched', false],
  ['terminal_outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256', false],
  ['terminal_recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256', false],
  ['terminal_trusted_issuer_registry_signature_valid', false],
  ['terminal_fixture_rightful_issuance_path_evidenced', false],
]) {
  const driftedCoverageIdentity = structuredClone(report);
  component(driftedCoverageIdentity, 'governed_surface_coverage_map')[field] = value;
  assertThrows(
    `coverage terminal identity contract rejects ${field}`,
    () => assertLocalProofPack(driftedCoverageIdentity),
    'coverage component drifted'
  );
}

const tamperedArtifactHash = structuredClone(artifact);
tamperedArtifactHash.integrity.body_sha256 = '0'.repeat(64);
assertThrows('tampered artifact hash fails', () => assertLocalProofPackArtifact(tamperedArtifactHash), 'SHA-256 mismatch');

const tamperedArtifactPayload = structuredClone(artifact);
tamperedArtifactPayload.payload.live_probing = true;
assertThrows('tampered artifact payload fails', () => assertLocalProofPackArtifact(tamperedArtifactPayload), 'must not perform live probing');

const staleManifestArtifact = structuredClone(artifact);
staleManifestArtifact.component_manifest[0].component_sha256 = '0'.repeat(64);
const staleManifestArtifactRehashed = artifactWithRehashedBody(staleManifestArtifact);
assertThrows('stale component manifest artifact fails', () => assertLocalProofPackArtifact(staleManifestArtifactRehashed), 'component manifest drifted');

const staleClaimBindingArtifact = structuredClone(artifact);
staleClaimBindingArtifact.claim_binding.non_claim_count = 999;
const staleClaimBindingArtifactRehashed = artifactWithRehashedBody(staleClaimBindingArtifact);
assertThrows('stale claim binding artifact fails', () => assertLocalProofPackArtifact(staleClaimBindingArtifactRehashed), 'claim binding drifted');

const rehashedStaleCoverageArtifact = structuredClone(artifact);
component(rehashedStaleCoverageArtifact.payload, 'governed_surface_coverage_map').boundary_entries = 13;
const rehashedStaleCoverageArtifactRehashed =
  artifactWithRehashedComponentManifestAndBody(rehashedStaleCoverageArtifact);
assertThrows('rehashed stale component artifact fails', () => assertLocalProofPackArtifact(rehashedStaleCoverageArtifactRehashed), 'coverage component drifted');

const attackerChosenArtifact = structuredClone(artifact);
const attackerKeyState = component(attackerChosenArtifact.payload, 'key_state_report');
attackerKeyState.policy_software_pins_aligned = !attackerKeyState.policy_software_pins_aligned;
const attackerChosenResealedArtifact =
  artifactWithRehashedComponentManifestAndBody(attackerChosenArtifact);
assert('coherently resealed attacker-chosen artifact remains structurally valid', assertLocalProofPackArtifact(attackerChosenResealedArtifact));
assert('coherently resealed attacker-chosen artifact has a distinct identity', attackerChosenResealedArtifact.integrity.body_sha256 !== artifact.integrity.body_sha256);
const attackerStructuralVerification = verifyLocalProofPackArtifact(attackerChosenResealedArtifact);
assertEqual('coherently resealed attacker artifact structural self-integrity true', true, attackerStructuralVerification.structural_self_integrity_verified);
assertEqual('coherently resealed attacker artifact identity not matched', false, attackerStructuralVerification.artifact_identity_sha256_matched);
assertEqual('coherently resealed attacker artifact terminal identity withheld', false, attackerStructuralVerification.coverage.terminal_artifact_identity_sha256_matched);
assertEqual('coherently resealed attacker artifact terminal source withheld', false, attackerStructuralVerification.coverage.terminal_recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256);
assertEqual('coherently resealed attacker artifact terminal signature withheld', false, attackerStructuralVerification.coverage.terminal_trusted_issuer_registry_signature_valid);
assertEqual('coherently resealed attacker artifact fixture rightful path withheld', false, attackerStructuralVerification.coverage.terminal_fixture_rightful_issuance_path_evidenced);
assertThrows(
  'coherently resealed attacker artifact refuses original expected SHA',
  () => verifyLocalProofPackArtifact(attackerChosenResealedArtifact, {
    expectedArtifactBodySha256: artifact.integrity.body_sha256,
  }),
  'does not match required --require-sha value'
);

const staleAdapterHashArtifact = structuredClone(artifact);
component(staleAdapterHashArtifact.payload, 'claude_code_hook_contract_replay').adapter_sha256 = '0'.repeat(64);
const staleAdapterHashArtifactRehashed = artifactWithRehashedBody(staleAdapterHashArtifact);
assertThrows('stale adapter hash artifact fails', () => assertLocalProofPackArtifact(staleAdapterHashArtifactRehashed), 'Claude Code hook-contract replay');

const staleContractHashArtifact = structuredClone(artifact);
component(staleContractHashArtifact.payload, 'claude_code_hook_contract_replay').hook_replay_contract_sha256 = '0'.repeat(64);
const staleContractHashArtifactRehashed = artifactWithRehashedBody(staleContractHashArtifact);
assertThrows('stale contract hash artifact fails', () => assertLocalProofPackArtifact(staleContractHashArtifactRehashed), 'Claude Code hook-contract replay');

const sourceBoundaryOverclaimArtifact = structuredClone(artifact);
component(sourceBoundaryOverclaimArtifact.payload, 'claude_code_hook_contract_replay').source_state_boundary = 'source state freshness preserved by artifact';
const sourceBoundaryOverclaimArtifactRehashed = artifactWithRehashedBody(sourceBoundaryOverclaimArtifact);
assertThrows('source boundary overclaim artifact fails', () => assertLocalProofPackArtifact(sourceBoundaryOverclaimArtifactRehashed), 'Claude Code hook-contract replay');

const summaryOnlyHookReplayArtifact = structuredClone(artifact);
delete component(summaryOnlyHookReplayArtifact.payload, 'claude_code_hook_contract_replay').case_evidence;
const summaryOnlyHookReplayArtifactRehashed = artifactWithRehashedBody(summaryOnlyHookReplayArtifact);
assertThrows('summary-only hook replay artifact fails', () => assertLocalProofPackArtifact(summaryOnlyHookReplayArtifactRehashed), 'unexpected fields');

const forgedHookReplayCaseEvidenceArtifact = structuredClone(artifact);
component(forgedHookReplayCaseEvidenceArtifact.payload, 'claude_code_hook_contract_replay').case_evidence.cases[0].permission_decision = 'deny';
component(forgedHookReplayCaseEvidenceArtifact.payload, 'claude_code_hook_contract_replay').case_evidence_sha256 = createHash('sha256')
  .update(canonicalize(component(forgedHookReplayCaseEvidenceArtifact.payload, 'claude_code_hook_contract_replay').case_evidence), 'utf8')
  .digest('hex');
const forgedHookReplayCaseEvidenceArtifactRehashed = artifactWithRehashedBody(forgedHookReplayCaseEvidenceArtifact);
assertThrows('forged hook replay case evidence artifact fails', () => assertLocalProofPackArtifact(forgedHookReplayCaseEvidenceArtifactRehashed), 'case evidence drifted');

const forgedHookReplaySemanticsArtifact = structuredClone(artifact);
component(forgedHookReplaySemanticsArtifact.payload, 'claude_code_hook_contract_replay')
  .case_evidence.cases.find((item) => item.case_id === 'deny_destructive_sentinel_hook_json')
  .sentinel_unchanged = false;
component(forgedHookReplaySemanticsArtifact.payload, 'claude_code_hook_contract_replay').case_evidence_sha256 = createHash('sha256')
  .update(canonicalize(component(forgedHookReplaySemanticsArtifact.payload, 'claude_code_hook_contract_replay').case_evidence), 'utf8')
  .digest('hex');
const forgedHookReplaySemanticsArtifactRehashed = artifactWithRehashedBody(forgedHookReplaySemanticsArtifact);
assertThrows('forged hook replay semantic artifact fails', () => assertLocalProofPackArtifact(forgedHookReplaySemanticsArtifactRehashed), 'case evidence drifted');

const extraArtifactField = structuredClone(artifact);
extraArtifactField.unreviewed_field = 'not allowed';
assertThrows('unexpected artifact field fails', () => assertLocalProofPackArtifact(extraArtifactField), 'unexpected fields');

const extraIntegrityField = structuredClone(artifact);
extraIntegrityField.integrity.unreviewed_field = 'not allowed';
assertThrows('unexpected integrity field fails', () => assertLocalProofPackArtifact(extraIntegrityField), 'unexpected fields');

assertThrows('artifact parser rejects invalid json', () => parseLocalProofPackArtifactText('{'), 'not valid JSON');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
