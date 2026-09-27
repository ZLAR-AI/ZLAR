#!/usr/bin/env node
// Hermetic tests for Governed Surface Coverage Map v1 first slice.

import { readFileSync } from 'node:fs';
import { projectWorkerReceipt } from '../lib/worker-receipt.mjs';
import { DOWNSTREAM_RECOGNITION_RULE_TYPE } from '../lib/downstream-recognition-rule.mjs';
import {
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
} from '../lib/protected-records-installed-runtime-profile-terminal-chain.mjs';
import {
  SAFE_CLAIM_CEILING,
  assertGovernedSurfaceCoverageMap,
  assertNoUnsafeCoverageMapText,
  buildGovernedSurfaceCoverageMap,
  formatGovernedSurfaceCoverageMapSummary,
} from '../lib/governed-surface-coverage-map.mjs';

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

function surface(report, id) {
  return report.surfaces.find((item) => item.surface_id === id);
}

const POLICY_VERSION = 'coverage-policy-v1';
const RUNTIME_PROFILE_SHA256 =
  'e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469';
const EXACT_RUNTIME_ROUTE =
  'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation';
const CURRENT_AUTHORITY_GRANT_SHA256 =
  '0c074a8e96559a29fc23d2f18f6062d539e2a1ea5baa25d53b7ba4b8fec4eaba';
const SERVICE_PROFILE_PREFLIGHT_ARTIFACT = JSON.parse(readFileSync(
  new URL('./fixtures/protected-records-service-preflight-artifact-v1.json', import.meta.url),
  'utf8'
));
const RUNTIME_LOCAL_ACTIVATION_ARTIFACT = JSON.parse(readFileSync(
  new URL('./fixtures/protected-records-runtime-local-activation-artifact-v1.json', import.meta.url),
  'utf8'
));
const RUNTIME_PROFILE_INSTALLATION_ARTIFACT = JSON.parse(readFileSync(
  new URL('./fixtures/protected-records-runtime-profile-installation-artifact-v1.json', import.meta.url),
  'utf8'
));
const INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT = JSON.parse(readFileSync(
  new URL('./fixtures/protected-records-installed-runtime-profile-terminal-chain-artifact-v1.json', import.meta.url),
  'utf8'
));
const freshHeartbeat = {
  state: 'on',
  last_heartbeat_epoch: 2000,
  now_epoch: 2030,
  freshness_seconds: 120,
};
const staleHeartbeat = {
  state: 'on',
  last_heartbeat_epoch: 2000,
  now_epoch: 2301,
  freshness_seconds: 120,
};

function bashEvent(overrides = {}) {
  return {
    id: overrides.id || 'coverage-bash-001',
    ts: '2026-06-17T12:00:00Z',
    seq: 1,
    source: 'gate',
    host: 'test-host',
    user: 'tester',
    agent_id: 'codex-cli',
    session_id: 'coverage-map-session',
    domain: 'bash',
    action: 'Bash',
    outcome: overrides.outcome || 'allow',
    risk_score: 0,
    detail: {
      command: 'printf safe && cat /Users/tester/private-key token=sk-live-fixture-000000',
    },
    rule: overrides.rule || 'RTEST_BASH',
    rule_description: 'Fixture bash gate rule.',
    policy_version: overrides.policy_version || POLICY_VERSION,
    policy_key_id: 'policy-key-test',
    severity: 'info',
    prev_hash: overrides.prev_hash || 'genesis',
    authorizer: overrides.authorizer || 'policy',
    signature_algorithm: 'Ed25519',
    hash_algorithm: 'SHA-256',
    public_key_id: 'audit-key-test',
    signature: 'test',
  };
}

function mcpEvent(overrides = {}) {
  return {
    id: overrides.id || 'coverage-mcp-001',
    ts: '2026-06-17T12:00:01Z',
    seq: 2,
    source: 'mcp-gate',
    host: 'test-host',
    user: 'tester',
    agent_id: 'codex-cli',
    session_id: 'coverage-map-session',
    transport: 'stdio',
    domain: 'mcp',
    action: overrides.action || 'filesystem.write_file',
    outcome: overrides.outcome || 'deny',
    risk_score: 80,
    detail: {
      tool: overrides.action || 'filesystem.write_file',
      args_preview: '{"path":"/Users/tester/private","api_key":"sk-live-mcp-000000"}',
    },
    rule: overrides.rule || 'RTEST_MCP',
    rule_description: 'Fixture routed MCP gate rule.',
    policy_version: overrides.policy_version || POLICY_VERSION,
    policy_key_id: 'policy-key-test',
    severity: 'critical',
    prev_hash: overrides.prev_hash || 'a'.repeat(64),
    authorizer: overrides.authorizer || 'policy',
    signature_algorithm: 'Ed25519',
    hash_algorithm: 'SHA-256',
    public_key_id: 'audit-key-test',
    signature: 'test',
  };
}

function policy(overrides = {}) {
  return {
    active_version: POLICY_VERSION,
    evidence_version: POLICY_VERSION,
    expected_version: POLICY_VERSION,
    signature_valid: true,
    acknowledged: true,
    key_id: 'policy-key-test',
    ...overrides,
  };
}

function bashLane(overrides = {}) {
  const event = overrides.audit_event || overrides.auditEvent || bashEvent(overrides.eventOverrides);
  return {
    surface_id: 'bash.pre_tool_use',
    boarding_lane: 'Bash gate PreToolUse boarding lane',
    checkpoint_path: 'bash-gate:PreToolUse->zlar-gate',
    hook: {
      configured: true,
      routed: true,
      name: 'PreToolUse',
    },
    heartbeat: freshHeartbeat,
    policy: policy(),
    audit_event: event,
    worker_receipt: projectWorkerReceipt(event),
    downstream_refusal: {
      proved: true,
      mechanism: 'Fixture downstream refusal evidence for missing or unrecognized boarding credential.',
    },
    ...overrides,
  };
}

function mcpLane(overrides = {}) {
  const event = overrides.audit_event || overrides.auditEvent || mcpEvent(overrides.eventOverrides);
  return {
    surface_id: 'mcp.tools_call',
    boarding_lane: 'Routed MCP tools/call boarding lane',
    checkpoint_path: 'mcp-gate:tools/call->fake-upstream',
    mcp_registration: {
      configured: true,
      routed: true,
      zlar_routed: true,
      configured_server_count: 1,
      server_name: 'zlar-routed-fixture',
      direct_upstream_observed: false,
      extra_registration_observed: false,
    },
    heartbeat: freshHeartbeat,
    policy: policy(),
    audit_event: event,
    worker_receipt: projectWorkerReceipt(event),
    downstream_refusal: {
      proved: true,
      upstream_observed_on_deny: false,
      mechanism: 'Fixture deny decision did not reach upstream.',
    },
    ...overrides,
  };
}

function runtimeArtifact(overrides = {}) {
  const artifact = JSON.parse(JSON.stringify(RUNTIME_LOCAL_ACTIVATION_ARTIFACT));
  if (overrides.mutate) overrides.mutate(artifact);
  return artifact;
}

function servicePreflightArtifact(overrides = {}) {
  const artifact = JSON.parse(JSON.stringify(SERVICE_PROFILE_PREFLIGHT_ARTIFACT));
  if (overrides.mutate) overrides.mutate(artifact);
  return artifact;
}

function runtimeInstallationArtifact(overrides = {}) {
  const artifact = JSON.parse(JSON.stringify(RUNTIME_PROFILE_INSTALLATION_ARTIFACT));
  if (overrides.mutate) overrides.mutate(artifact);
  return artifact;
}

function serviceProfilePreflightLane(overrides = {}) {
  return {
    surface_id: 'protected-records.service-profile.records.write',
    boarding_lane: 'Protected records service-profile preflight records.write lane',
    checkpoint_path: 'protected-records-service-profile-preflight:receipt-recognition-before-service-state-append',
    service_profile_preflight_artifact: servicePreflightArtifact(overrides.artifact || {}),
    non_claims: [
      'This lane counts only the committed local disposable service-profile preflight artifact.',
      'This lane does not claim runtime activation, production service deployment, live current-machine governance, or unrouted records paths.',
      'This lane does not claim authority beyond the supplied fixture artifact.',
    ],
    ...overrides,
  };
}

function runtimeLocalActivationLane(overrides = {}) {
  return {
    surface_id: 'protected-records.runtime.records.write',
    boarding_lane: 'Protected records runtime local activation records.write lane',
    checkpoint_path: `protected-records-runtime-local-activation:${EXACT_RUNTIME_ROUTE}`,
    runtime_local_activation_artifact: runtimeArtifact(overrides.artifact || {}),
    non_claims: [
      'This lane counts only the committed local disposable runtime activation artifact.',
      'This lane does not claim persistent install, hook configuration, production service deployment, live current-machine governance, or unrouted records paths.',
      'This lane does not claim authority beyond the supplied fixture artifact.',
    ],
    ...overrides,
  };
}

function runtimeProfileInstallationLane(overrides = {}) {
  return {
    surface_id: 'protected-records.runtime.profile-installation.records.write',
    boarding_lane: 'Protected records runtime profile installation records.write lane',
    checkpoint_path: `protected-records-runtime-profile-installation:installed-profile-selection-then-${EXACT_RUNTIME_ROUTE}`,
    runtime_profile_installation_artifact: runtimeInstallationArtifact(overrides.artifact || {}),
    non_claims: [
      'This lane counts only the committed local disposable runtime profile installation artifact.',
      'This lane does not claim persistent install, hook configuration, user or machine configuration, production service deployment, live current-machine governance, or unrouted records paths.',
      'This lane does not claim authority beyond the supplied fixture artifact.',
    ],
    ...overrides,
  };
}

function installedRuntimeProfileTerminalChainArtifact(overrides = {}) {
  const artifact = JSON.parse(JSON.stringify(INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT));
  if (overrides.mutate) overrides.mutate(artifact);
  return artifact;
}

function installedRuntimeProfileTerminalChainLane(overrides = {}) {
  return {
    surface_id: 'protected-records.installed-runtime-profile.terminal-chain.records.write',
    boarding_lane: 'Protected records installed-runtime-profile terminal-chain records.write lane',
    checkpoint_path: `protected-records-installed-runtime-profile-terminal-chain:${EXACT_RUNTIME_ROUTE}`,
    installed_runtime_profile_terminal_chain_artifact:
      installedRuntimeProfileTerminalChainArtifact(overrides.artifact || {}),
    non_claims: [
      'This lane counts only the committed local disposable installed-runtime-profile terminal-chain artifact.',
      'This lane does not claim persistent install, activation, hook/user/machine configuration, production service deployment, live current-machine governance, or unrouted records paths.',
      'This lane does not claim authority beyond the supplied fixture artifact.',
    ],
    ...overrides,
  };
}

section('happy path coverage map');
const report = buildGovernedSurfaceCoverageMap({
  generatedAt: '2026-06-17T12:34:56Z',
  bashGateLane: bashLane(),
  mcpGateLane: mcpLane(),
  serviceProfilePreflightLane: serviceProfilePreflightLane(),
  runtimeLocalActivationLane: runtimeLocalActivationLane(),
  runtimeProfileInstallationLane: runtimeProfileInstallationLane(),
  installedRuntimeProfileTerminalChainLane: installedRuntimeProfileTerminalChainLane(),
});

assert('valid report passes validation', assertGovernedSurfaceCoverageMap(report));
assertEqual('report type', 'governed-surface-coverage-map-v1', report.report_type);
assertEqual('safe claim ceiling exact', SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('six counted lanes', 6, report.counts.counted_lanes);
assertEqual('four currently governed lanes', 4, report.counts.governed_lanes);
assertEqual('fixture evidence model', 'fixtures', report.evidence_model.source);
assertEqual('no live probing', false, report.evidence_model.live_probing_performed);

const bashSurface = surface(report, 'bash.pre_tool_use');
assertEqual('bash lane governed', true, bashSurface.governed);
assertEqual('bash lane configured', true, bashSurface.configured);
assertEqual('bash lane routed', true, bashSurface.routed);
assertEqual('bash lane alive', true, bashSurface.alive);
assertEqual('bash lane policy-current', true, bashSurface.policy_current);
assertEqual('bash lane receipt-capable', true, bashSurface.receipt_capable);
assertEqual('bash lane downstream refusal', true, bashSurface.downstream_refusal);
assertEqual('bash lane governed status', 'governed', bashSurface.verification_status);
assertEqual('bash coverage route status', 'routed', bashSurface.coverage_summary.route_status);
assertEqual('bash coverage freshness status', 'fresh', bashSurface.coverage_summary.freshness_status);
assertEqual('bash coverage policy version', POLICY_VERSION, bashSurface.coverage_summary.policy_version);
assertEqual('bash coverage receipt status', 'receipt_capable', bashSurface.coverage_summary.receipt_status);
assertEqual('bash last decision outcome', 'allow', bashSurface.last_decision.outcome);
assertEqual('bash last decision event', 'coverage-bash-001', bashSurface.last_decision.audit_event_id);
assertEqual('bash last receipt valid', true, bashSurface.last_receipt.valid);
assertEqual('bash last receipt status', 'valid', bashSurface.last_receipt.verification_status);
assertEqual('bash issuer policy key', 'policy-key-test', bashSurface.issuer_identity.policy_key_id);
assertEqual('bash issuer custody not proven', false, bashSurface.issuer_identity.key_custody_proven);
assert('bash known boundaries named', bashSurface.known_boundaries.includes('unrouted_side_doors'));
assertEqual('bash receipt surface evidence', 'bash-gate', bashSurface.evidence.receipt.surface);
assert('bash receipt hash present', /^[a-f0-9]{64}$/.test(bashSurface.evidence.receipt.receipt_sha256));

const mcpSurface = surface(report, 'mcp.tools_call');
assertEqual('mcp lane governed', true, mcpSurface.governed);
assertEqual('mcp lane configured', true, mcpSurface.configured);
assertEqual('mcp lane routed', true, mcpSurface.routed);
assertEqual('mcp lane alive', true, mcpSurface.alive);
assertEqual('mcp lane policy-current', true, mcpSurface.policy_current);
assertEqual('mcp lane receipt-capable', true, mcpSurface.receipt_capable);
assertEqual('mcp lane downstream refusal', true, mcpSurface.downstream_refusal);
assertEqual('mcp lane governed status', 'governed', mcpSurface.verification_status);
assertEqual('mcp coverage route status', 'routed', mcpSurface.coverage_summary.route_status);
assertEqual('mcp coverage policy version', POLICY_VERSION, mcpSurface.coverage_summary.policy_version);
assertEqual('mcp last decision outcome', 'deny', mcpSurface.last_decision.outcome);
assertEqual('mcp last decision tool', 'filesystem.write_file', mcpSurface.last_decision.tool);
assertEqual('mcp last receipt status', 'valid', mcpSurface.last_receipt.verification_status);
assertEqual('mcp issuer audit key', 'audit-key-test', mcpSurface.issuer_identity.audit_public_key_id);
assertEqual('mcp issuer revocation not proven', false, mcpSurface.issuer_identity.revocation_state_proven);
assertEqual('mcp route has one server', 1, mcpSurface.evidence.route.configured_server_count);
assertEqual('mcp direct upstream absent', false, mcpSurface.evidence.route.direct_upstream_observed);
assertEqual('mcp extra registration absent', false, mcpSurface.evidence.route.extra_registration_observed);
assertEqual('mcp receipt surface evidence', 'mcp-gate', mcpSurface.evidence.receipt.surface);

const serviceProfileSurface = surface(report, 'protected-records.service-profile.records.write');
assertEqual('service profile lane governed', true, serviceProfileSurface.governed);
assertEqual('service profile lane configured', true, serviceProfileSurface.configured);
assertEqual('service profile lane routed', true, serviceProfileSurface.routed);
assertEqual('service profile lane alive', true, serviceProfileSurface.alive);
assertEqual('service profile lane policy-current', true, serviceProfileSurface.policy_current);
assertEqual('service profile lane receipt-capable', true, serviceProfileSurface.receipt_capable);
assertEqual('service profile lane downstream refusal', true, serviceProfileSurface.downstream_refusal);
assertEqual('service profile lane governed status', 'governed', serviceProfileSurface.verification_status);
assertEqual('service profile coverage route status', 'routed', serviceProfileSurface.coverage_summary.route_status);
assertEqual('service profile coverage policy version', 'protected-records-service-profile-fixture', serviceProfileSurface.coverage_summary.policy_version);
assertEqual('service profile last decision outcome', 'recognized_write_accepted', serviceProfileSurface.last_decision.outcome);
assertEqual('service profile last receipt status', 'recognized_receipt_accepted', serviceProfileSurface.last_receipt.verification_status);
assertEqual('service profile issuer policy key', 'protected-records-service-profile-fixture', serviceProfileSurface.issuer_identity.policy_key_id);
assertEqual('service profile recognition anchor', SERVICE_PROFILE_PREFLIGHT_ARTIFACT.payload.preflight.profile.profile_sha256, serviceProfileSurface.issuer_identity.recognition_anchor_id);
assertEqual('service profile production trust registry not proven', false, serviceProfileSurface.issuer_identity.production_trust_registry_proven);
assert('service profile known boundaries named', serviceProfileSurface.known_boundaries.includes('runtime_profile_not_installed'));
assertEqual('service profile lane surface type', 'protected-records-service-profile-preflight', serviceProfileSurface.surface_type);
assertEqual('service profile lane action class', 'records.write', serviceProfileSurface.evidence.route.action_class);
assertEqual(
  'service profile lane route',
  'receipt-recognition-before-service-state-append',
  serviceProfileSurface.evidence.route.mutation_authoritative_route
);
assertEqual('service profile lane recognized write accepted', true, serviceProfileSurface.evidence.receipt.recognized_write_accepted);
assertEqual('service profile lane missing receipt refused', true, serviceProfileSurface.evidence.downstream_refusal.required_refusals.missing_receipt_refused);
assertEqual('service profile lane unrecognized receipt refused', true, serviceProfileSurface.evidence.downstream_refusal.required_refusals.unrecognized_receipt_refused);
assertEqual('service profile lane wrong policy refused', true, serviceProfileSurface.evidence.downstream_refusal.required_refusals.wrong_policy_refused);
assertEqual('service profile lane request stream authority refused', true, serviceProfileSurface.evidence.downstream_refusal.required_refusals.request_stream_authority_material_refused);
assertEqual('service profile lane direct API with receipt refused', true, serviceProfileSurface.evidence.downstream_refusal.required_refusals.direct_api_with_receipt_refused);
assertEqual('service profile lane profile status', 'sample_not_active', serviceProfileSurface.evidence.policy.profile_status);
assertEqual('service profile lane no live profile', false, serviceProfileSurface.evidence.boundaries.live_profile_installed);
assertEqual('service profile lane no production check', false, serviceProfileSurface.evidence.boundaries.production_records_service_checked);
assert('service profile lane artifact hash present', /^[a-f0-9]{64}$/.test(serviceProfileSurface.evidence.validation.body_sha256));

const runtimeSurface = surface(report, 'protected-records.runtime.records.write');
assertEqual('runtime local lane governed', true, runtimeSurface.governed);
assertEqual('runtime local lane configured', true, runtimeSurface.configured);
assertEqual('runtime local lane routed', true, runtimeSurface.routed);
assertEqual('runtime local lane alive', true, runtimeSurface.alive);
assertEqual('runtime local lane policy-current', true, runtimeSurface.policy_current);
assertEqual('runtime local lane receipt-capable', true, runtimeSurface.receipt_capable);
assertEqual('runtime local lane downstream refusal', true, runtimeSurface.downstream_refusal);
assertEqual('runtime local lane governed status', 'governed', runtimeSurface.verification_status);
assertEqual('runtime local coverage route status', 'routed', runtimeSurface.coverage_summary.route_status);
assertEqual('runtime local coverage policy version', 'protected-records-disposable-runtime-profile', runtimeSurface.coverage_summary.policy_version);
assertEqual('runtime local last decision outcome', 'recognized_write_accepted', runtimeSurface.last_decision.outcome);
assertEqual('runtime local last receipt status', 'recognized_receipt_accepted', runtimeSurface.last_receipt.verification_status);
assertEqual('runtime local issuer policy key', 'protected-records-disposable-runtime-profile', runtimeSurface.issuer_identity.policy_key_id);
assertEqual('runtime local recognition anchor', RUNTIME_PROFILE_SHA256, runtimeSurface.issuer_identity.recognition_anchor_id);
assertEqual('runtime local production trust registry not proven', false, runtimeSurface.issuer_identity.production_trust_registry_proven);
assert('runtime local known boundaries named', runtimeSurface.known_boundaries.includes('current_machine_governance'));
assertEqual('runtime local lane surface type', 'protected-records-runtime-local-activation', runtimeSurface.surface_type);
assertEqual('runtime local lane action class', 'records.write', runtimeSurface.evidence.route.action_class);
assertEqual(
  'runtime local lane route',
  EXACT_RUNTIME_ROUTE,
  runtimeSurface.evidence.route.mutation_authoritative_route
);
assertEqual('runtime local lane recognized write accepted', true, runtimeSurface.evidence.receipt.recognized_write_accepted);
assertEqual('runtime local grant store identity', 'persistent-single-use-authority-grant-contract-sha256-store', runtimeSurface.evidence.route.runtime_contract.consumed_authority_grant_store);
assertEqual('runtime local consumption identity', 'authority-grant-contract-sha256', runtimeSurface.evidence.route.runtime_contract.consumption_identity);
assertEqual('runtime local signed-payload replay identity', 'verified-signed-payload-sha256', runtimeSurface.evidence.route.runtime_contract.signed_payload_replay_identity);
assertEqual('runtime local witness identity', 'launcher-owned-local-store-hash-witness', runtimeSurface.evidence.route.runtime_contract.consumed_store_witness);
assertEqual('runtime local recognition refusal count', 18, runtimeSurface.evidence.downstream_refusal.recognition_refusals.required_case_count);
assertEqual('runtime local recognition refusals all before mutation', true, runtimeSurface.evidence.downstream_refusal.recognition_refusals.all_refused_before_mutation);
assertEqual('runtime local authority refusal count', 5, runtimeSurface.evidence.downstream_refusal.authority_refusals.required_case_count);
assertEqual('runtime local authority refusals all before consumption and mutation', true, runtimeSurface.evidence.downstream_refusal.authority_refusals.all_refused_before_consumption_and_mutation);
assertEqual('runtime local same-process signed-payload replay refused', true, runtimeSurface.evidence.downstream_refusal.same_process_signed_payload_replay_refused);
assertEqual('runtime local restart consumed-grant replay refused', true, runtimeSurface.evidence.downstream_refusal.restart_consumed_authority_grant_refused);
assertEqual('runtime local lane profile SHA matches plan', true, runtimeSurface.evidence.policy.runtime_profile_sha_matches_plan);
assertEqual('runtime local lane no persistent install', false, runtimeSurface.evidence.boundaries.persistent_runtime_profile_installed);
assertEqual('runtime local burn window named', true, runtimeSurface.evidence.boundaries.partial_grant_commit_burn_window_named);
assertEqual('runtime local witness-ahead rollback refused', true, runtimeSurface.evidence.boundaries.store_and_anchor_joint_rollback_refused_while_witness_ahead);
assertEqual('runtime local joint rollback detection open', false, runtimeSurface.evidence.boundaries.store_anchor_and_witness_joint_rollback_detection);
assertEqual('runtime local joint rollback reopens grant reuse', true, runtimeSurface.evidence.boundaries.joint_rollback_reopened_authority_grant_reuse);
assertEqual('runtime local host path TOCTOU open', false, runtimeSurface.evidence.boundaries.host_filesystem_path_toctou_closed);
assertEqual('runtime local fixture grant effect satisfied', true, runtimeSurface.evidence.boundaries.fixture_authority_grant_effect_satisfied);
assertEqual('runtime local rightful issuance not projected', false, runtimeSurface.evidence.boundaries.fixture_rightful_issuance_path_evidenced);
assert('runtime local lane artifact hash present', /^[a-f0-9]{64}$/.test(runtimeSurface.evidence.validation.body_sha256));

const runtimeInstallationSurface = surface(report, 'protected-records.runtime.profile-installation.records.write');
assertEqual('runtime installation lane governed', false, runtimeInstallationSurface.governed);
assertEqual('runtime installation lane configured', true, runtimeInstallationSurface.configured);
assertEqual('runtime installation lane routed', true, runtimeInstallationSurface.routed);
assertEqual('runtime installation lane alive', true, runtimeInstallationSurface.alive);
assertEqual('runtime installation lane policy-current', true, runtimeInstallationSurface.policy_current);
assertEqual('runtime installation lane receipt-capable', false, runtimeInstallationSurface.receipt_capable);
assertEqual('runtime installation lane downstream refusal', true, runtimeInstallationSurface.downstream_refusal);
assertEqual('runtime installation lane governed status', 'receipt_not_capable', runtimeInstallationSurface.verification_status);
assertEqual('runtime installation coverage route status', 'routed', runtimeInstallationSurface.coverage_summary.route_status);
assertEqual('runtime installation coverage policy version', 'protected-records-disposable-runtime-profile', runtimeInstallationSurface.coverage_summary.policy_version);
assertEqual('runtime installation last decision outcome', 'recognized_write_accepted', runtimeInstallationSurface.last_decision.outcome);
assertEqual('runtime installation last receipt status', 'recognized_receipt_accepted', runtimeInstallationSurface.last_receipt.verification_status);
assertEqual('runtime installation issuer policy key', 'protected-records-disposable-runtime-profile', runtimeInstallationSurface.issuer_identity.policy_key_id);
assertEqual('runtime installation recognition anchor', RUNTIME_PROFILE_SHA256, runtimeInstallationSurface.issuer_identity.recognition_anchor_id);
assertEqual('runtime installation production trust registry not proven', false, runtimeInstallationSurface.issuer_identity.production_trust_registry_proven);
assert('runtime installation known boundaries named', runtimeInstallationSurface.known_boundaries.includes('current_machine_governance'));
assertEqual('runtime installation lane surface type', 'protected-records-runtime-profile-installation', runtimeInstallationSurface.surface_type);
assertEqual('runtime installation lane action class', 'records.write', runtimeInstallationSurface.evidence.route.action_class);
assertEqual(
  'runtime installation lane route',
  EXACT_RUNTIME_ROUTE,
  runtimeInstallationSurface.evidence.route.mutation_authoritative_route
);
assertEqual('runtime installation grant store identity', 'persistent-single-use-authority-grant-contract-sha256-store', runtimeInstallationSurface.evidence.route.runtime_contract.consumed_authority_grant_store);
assertEqual('runtime installation signed-payload replay identity', 'verified-signed-payload-sha256', runtimeInstallationSurface.evidence.route.runtime_contract.signed_payload_replay_identity);
assertEqual('runtime installation witness identity', 'launcher-owned-local-store-hash-witness', runtimeInstallationSurface.evidence.route.runtime_contract.consumed_store_witness);
assertEqual('runtime installation selected by id and sha', true, runtimeInstallationSurface.evidence.policy.selected_by_explicit_id_and_sha);
assertEqual('runtime installation no latest', false, runtimeInstallationSurface.evidence.policy.selects_latest_profile);
assertEqual('runtime installation request guard refused', true, runtimeInstallationSurface.evidence.downstream_refusal.request_authority_guard_refused);
assertEqual('runtime installation recognition refusal count', 18, runtimeInstallationSurface.evidence.downstream_refusal.recognition_refusals.required_case_count);
assertEqual('runtime installation recognition refusals all before mutation', true, runtimeInstallationSurface.evidence.downstream_refusal.recognition_refusals.all_refused_before_mutation);
assertEqual('runtime installation authority refusal count', 5, runtimeInstallationSurface.evidence.downstream_refusal.authority_refusals.required_case_count);
assertEqual('runtime installation authority refusals all before consumption and mutation', true, runtimeInstallationSurface.evidence.downstream_refusal.authority_refusals.all_refused_before_consumption_and_mutation);
assertEqual('runtime installation same-process signed-payload replay refused', true, runtimeInstallationSurface.evidence.downstream_refusal.same_process_signed_payload_replay_refused);
assertEqual('runtime installation restart consumed-grant replay refused', true, runtimeInstallationSurface.evidence.downstream_refusal.restart_consumed_authority_grant_refused);
assertEqual('runtime installation profile SHA matches plan', true, runtimeInstallationSurface.evidence.policy.runtime_profile_sha_matches_plan);
assertEqual('runtime installation no persistent install', false, runtimeInstallationSurface.evidence.boundaries.persistent_runtime_profile_installed);
assertEqual('runtime installation no hook config', false, runtimeInstallationSurface.evidence.boundaries.hook_configuration_written);
assertEqual('runtime installation burn window named', true, runtimeInstallationSurface.evidence.boundaries.partial_grant_commit_burn_window_named);
assertEqual('runtime installation joint rollback detection open', false, runtimeInstallationSurface.evidence.boundaries.store_anchor_and_witness_joint_rollback_detection);
assertEqual('runtime installation host path TOCTOU open', false, runtimeInstallationSurface.evidence.boundaries.host_filesystem_path_toctou_closed);
assertEqual('runtime installation historical artifact rightful path preserved', true, runtimeInstallationSurface.evidence.boundaries.historical_artifact_fixture_rightful_issuance_path_evidenced);
assertEqual('runtime installation current fixture rightful path refused', false, runtimeInstallationSurface.evidence.boundaries.fixture_rightful_issuance_path_evidenced);
assertEqual('runtime installation authority status contract', CURRENT_AUTHORITY_GRANT_SHA256, runtimeInstallationSurface.evidence.authority_status.authority_grant_contract_sha256);
assertEqual('runtime installation artifact does not bind grant contract identity', false, runtimeInstallationSurface.evidence.authority_status.artifact_contract_bound_to_status);
assertEqual('runtime installation authority status exhausted', 'exhausted', runtimeInstallationSurface.evidence.authority_status.status);
assertEqual('runtime installation fresh effect refused', false, runtimeInstallationSurface.evidence.authority_status.fresh_effect_allowed);
assertEqual('runtime installation repeated-use provenance invalid', false, runtimeInstallationSurface.evidence.authority_status.repeated_use_provenance_valid);
assertEqual('runtime installation fresh fixture rightful projection refused', false, runtimeInstallationSurface.evidence.authority_status.fresh_fixture_rightful_projection_allowed);
assertEqual('runtime installation generic rightful issuance false', false, runtimeInstallationSurface.evidence.boundaries.rightful_issuance_proven);
assertEqual('runtime installation live authority false', false, runtimeInstallationSurface.evidence.boundaries.live_authority_proven);
assertEqual('runtime installation production rightful false', false, runtimeInstallationSurface.evidence.boundaries.production_rightful_issuance_proven);
assertEqual('runtime installation current-machine governance false', false, runtimeInstallationSurface.evidence.boundaries.current_machine_governance_proven);
assertEqual('runtime installation lifecycle closure false', false, runtimeInstallationSurface.evidence.boundaries.consequence_lifecycle_closed);
assert('runtime installation artifact hash present', /^[a-f0-9]{64}$/.test(runtimeInstallationSurface.evidence.validation.body_sha256));

const terminalChainSurface = surface(report, 'protected-records.installed-runtime-profile.terminal-chain.records.write');
assertEqual('terminal chain lane governed', false, terminalChainSurface.governed);
assertEqual('terminal chain lane configured', true, terminalChainSurface.configured);
assertEqual('terminal chain lane routed', true, terminalChainSurface.routed);
assertEqual('terminal chain lane alive', true, terminalChainSurface.alive);
assertEqual('terminal chain lane policy-current', true, terminalChainSurface.policy_current);
assertEqual('terminal chain lane receipt-capable', false, terminalChainSurface.receipt_capable);
assertEqual('terminal chain lane downstream refusal', true, terminalChainSurface.downstream_refusal);
assertEqual('terminal chain lane governed status', 'receipt_not_capable', terminalChainSurface.verification_status);
assertEqual(
  'terminal chain exact fixture identity matched',
  true,
  terminalChainSurface.evidence.validation.artifact_identity_sha256_matched
);
assertEqual(
  'terminal chain expected fixture identity',
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
  terminalChainSurface.evidence.validation.expected_body_sha256
);
assertEqual(
  'terminal chain outer fixture metadata identity-bound',
  true,
  terminalChainSurface.evidence.validation
    .outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256
);
assertEqual('terminal chain coverage route status', 'routed', terminalChainSurface.coverage_summary.route_status);
assertEqual('terminal chain coverage policy version', 'protected-records-disposable-runtime-profile', terminalChainSurface.coverage_summary.policy_version);
assertEqual('terminal chain last decision outcome', 'recognized_write_boarded', terminalChainSurface.last_decision.outcome);
assertEqual('terminal chain last receipt status', 'recognized_receipt_boarded', terminalChainSurface.last_receipt.verification_status);
assertEqual('terminal chain issuer policy key', 'protected-records-disposable-runtime-profile', terminalChainSurface.issuer_identity.policy_key_id);
assertEqual('terminal chain recognition anchor', RUNTIME_PROFILE_SHA256, terminalChainSurface.issuer_identity.recognition_anchor_id);
assertEqual('terminal chain production trust registry not proven', false, terminalChainSurface.issuer_identity.production_trust_registry_proven);
assert('terminal chain known boundaries named', terminalChainSurface.known_boundaries.includes('current_machine_governance'));
assertEqual('terminal chain lane surface type', 'protected-records-installed-runtime-profile-terminal-chain', terminalChainSurface.surface_type);
assertEqual('terminal chain lane action class', 'records.write', terminalChainSurface.evidence.route.action_class);
assertEqual(
  'terminal chain lane route',
  EXACT_RUNTIME_ROUTE,
  terminalChainSurface.evidence.route.mutation_authoritative_route
);
assertEqual('terminal chain grant store identity', 'persistent-single-use-authority-grant-contract-sha256-store', terminalChainSurface.evidence.route.consumed_authority_grant_store);
assertEqual('terminal chain consumption identity', 'authority-grant-contract-sha256', terminalChainSurface.evidence.route.consumption_identity);
assertEqual('terminal chain signed-payload replay identity', 'verified-signed-payload-sha256', terminalChainSurface.evidence.route.signed_payload_replay_identity);
assertEqual('terminal chain witness source', 'launcher-owned-local-proof-witness', terminalChainSurface.evidence.route.consumed_grant_store_witness_source);
assertEqual('terminal chain selected by id and sha', true, terminalChainSurface.evidence.policy.selected_by_explicit_id_and_sha);
assertEqual('terminal chain no latest', false, terminalChainSurface.evidence.policy.selects_latest_profile);
assertEqual('terminal chain recognized write boarded', true, terminalChainSurface.evidence.receipt.recognized_write_boarded);
assertEqual(
  'terminal chain recognized receipt source identity-bound',
  true,
  terminalChainSurface.evidence.receipt
    .recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256
);
assertEqual('terminal chain trusted registry verdict', 'RECOGNIZED', terminalChainSurface.evidence.trusted_issuer_registry.verdict);
assertEqual('terminal chain trusted registry recognized', true, terminalChainSurface.evidence.trusted_issuer_registry.recognized);
assertEqual('terminal chain trusted registry signature valid', true, terminalChainSurface.evidence.trusted_issuer_registry.signature_valid);
assertEqual('terminal chain trusted registry rule evaluated', true, terminalChainSurface.evidence.trusted_issuer_registry.registry_to_recognition_rule_evaluated);
assertEqual('terminal chain trusted registry binding hash matched', true, terminalChainSurface.evidence.trusted_issuer_registry.binding_sha_matches_summary);
assert('terminal chain trusted registry binding hash present', /^[a-f0-9]{64}$/.test(terminalChainSurface.evidence.trusted_issuer_registry.binding_sha256));
assert('terminal chain trusted registry fixture contract hash present', /^[a-f0-9]{64}$/.test(terminalChainSurface.evidence.trusted_issuer_registry.registry_fixture_contract_sha256));
assert('terminal chain trusted registry receipt contract hash present', /^[a-f0-9]{64}$/.test(terminalChainSurface.evidence.trusted_issuer_registry.receipt_payload_contract_sha256));
assertEqual('terminal chain trusted registry local refusals all refused', true, terminalChainSurface.evidence.trusted_issuer_registry.local_refusals_all_refused);
assertEqual('terminal chain trusted registry local refusal count', 2, terminalChainSurface.evidence.trusted_issuer_registry.local_refusal_case_count);
assertEqual('terminal chain trusted registry local refusal case IDs preserved', true, terminalChainSurface.evidence.trusted_issuer_registry.local_refusal_case_ids_preserved);
assertEqual(
  'terminal chain trusted registry local refusal case IDs',
  JSON.stringify([
    'unrecognized_terminal_chain_registry_scope_refused',
    'registry_receipt_contract_mismatch_refused',
  ]),
  JSON.stringify(terminalChainSurface.evidence.trusted_issuer_registry.local_refusal_case_ids)
);
assertEqual(
  'terminal chain trusted registry local refusal reasons',
  JSON.stringify(['scope_not_found', 'detail_hash_mismatch']),
  JSON.stringify(terminalChainSurface.evidence.trusted_issuer_registry.local_refusal_reason_codes)
);
assert('terminal chain trusted registry local refusal hash present', /^[a-f0-9]{64}$/.test(terminalChainSurface.evidence.trusted_issuer_registry.local_refusals_sha256));
assertEqual('terminal chain trusted registry public key material omitted', false, terminalChainSurface.evidence.trusted_issuer_registry.registry_public_key_material_included);
assertEqual('terminal chain trusted registry receipt envelope omitted', false, terminalChainSurface.evidence.trusted_issuer_registry.receipt_envelope_included);
assertEqual('terminal chain trusted registry no artifact-only crypto reconstruction', false, terminalChainSurface.evidence.trusted_issuer_registry.cryptographic_evidence_reproducible_from_artifact);
assertEqual('terminal chain trusted registry no live registry', false, terminalChainSurface.evidence.trusted_issuer_registry.live_trust_registry_state);
assertEqual('terminal chain trusted registry no live issuer status', false, terminalChainSurface.evidence.trusted_issuer_registry.live_issuer_status_proven);
assertEqual('terminal chain trusted registry no key custody', false, terminalChainSurface.evidence.trusted_issuer_registry.key_custody_proven);
assertEqual('terminal chain trusted registry no revocation truth', false, terminalChainSurface.evidence.trusted_issuer_registry.revocation_truth_proven);
assertEqual('terminal chain trusted registry no production trust registry', false, terminalChainSurface.evidence.trusted_issuer_registry.production_trust_registry_proven);
assertEqual('terminal chain trusted registry no production downstream', false, terminalChainSurface.evidence.trusted_issuer_registry.production_downstream_recognition_proven);
assertEqual('terminal chain trusted registry no production authority', false, terminalChainSurface.evidence.trusted_issuer_registry.production_authority);
assertEqual('terminal chain trusted registry no public attestation', false, terminalChainSurface.evidence.trusted_issuer_registry.public_external_attestation);
assertEqual('terminal chain trusted registry no current-machine governance', false, terminalChainSurface.evidence.trusted_issuer_registry.current_machine_governance_proven);
assertEqual('terminal chain missing receipt refused', true, terminalChainSurface.evidence.downstream_refusal.named_receipt_refusals.missing);
assertEqual('terminal chain invalid receipt refused', true, terminalChainSurface.evidence.downstream_refusal.named_receipt_refusals.invalid);
assertEqual('terminal chain stale-or-expired receipt refused', true, terminalChainSurface.evidence.downstream_refusal.named_receipt_refusals.stale_or_expired);
assertEqual('terminal chain unknown issuer refused', true, terminalChainSurface.evidence.downstream_refusal.named_receipt_refusals.unknown_issuer);
assertEqual('terminal chain wrong policy refused', true, terminalChainSurface.evidence.downstream_refusal.named_receipt_refusals.wrong_policy);
assertEqual('terminal chain all named refusals', true, terminalChainSurface.evidence.downstream_refusal.all_named_receipt_refusals);
assertEqual('terminal chain recognition refusal count', 18, terminalChainSurface.evidence.downstream_refusal.recognition_refusals.required_case_count);
assertEqual('terminal chain recognition refusals before mutation', true, terminalChainSurface.evidence.downstream_refusal.recognition_refusals.all_refused_before_mutation);
assertEqual('terminal chain authority refusal count', 5, terminalChainSurface.evidence.downstream_refusal.authority_refusals.required_case_count);
assertEqual('terminal chain authority refusals before consumption and mutation', true, terminalChainSurface.evidence.downstream_refusal.authority_refusals.all_refused_before_consumption_and_mutation);
assertEqual('terminal chain same-process signed-payload replay refused', true, terminalChainSurface.evidence.downstream_refusal.same_process_signed_payload_replay_refused);
assertEqual('terminal chain restart consumed-grant replay refused', true, terminalChainSurface.evidence.downstream_refusal.restart_consumed_authority_grant_refused);
assertEqual('terminal chain historical artifact fixture rightful path preserved', true, terminalChainSurface.evidence.rightful_issuance.historical_artifact_fixture_rightful_issuance_path_evidenced);
assertEqual('terminal chain current fixture rightful path refused', false, terminalChainSurface.evidence.rightful_issuance.fixture_rightful_issuance_path_evidenced);
assertEqual('terminal chain historical authority satisfaction preserved', true, terminalChainSurface.evidence.rightful_issuance.historical_artifact_fixture_authority_grant_satisfied_at_evaluation_time);
assertEqual('terminal chain current authority satisfaction refused', false, terminalChainSurface.evidence.rightful_issuance.fixture_authority_grant_satisfied_at_evaluation_time);
assertEqual('terminal chain authority status contract', CURRENT_AUTHORITY_GRANT_SHA256, terminalChainSurface.evidence.authority_status.authority_grant_contract_sha256);
assertEqual('terminal chain artifact binds grant contract identity', true, terminalChainSurface.evidence.authority_status.artifact_contract_bound_to_status);
assertEqual('terminal chain authority status exhausted', 'exhausted', terminalChainSurface.evidence.authority_status.status);
assertEqual('terminal chain fresh effect refused', false, terminalChainSurface.evidence.authority_status.fresh_effect_allowed);
assertEqual('terminal chain repeated-use provenance invalid', false, terminalChainSurface.evidence.authority_status.repeated_use_provenance_valid);
assertEqual('terminal chain fresh fixture rightful projection refused', false, terminalChainSurface.evidence.authority_status.fresh_fixture_rightful_projection_allowed);
assertEqual('terminal chain generic rightful issuance false', false, terminalChainSurface.evidence.rightful_issuance.rightful_issuance_proven);
assertEqual('terminal chain live authority false', false, terminalChainSurface.evidence.rightful_issuance.live_authority_proven);
assertEqual('terminal chain production rightful false', false, terminalChainSurface.evidence.rightful_issuance.production_rightful_issuance_proven);
assertEqual('terminal chain current-machine governance false', false, terminalChainSurface.evidence.rightful_issuance.current_machine_governance_proven);
assertEqual('terminal chain lifecycle closure false', false, terminalChainSurface.evidence.rightful_issuance.consequence_lifecycle_closed);
assertEqual('terminal chain no persistent install', false, terminalChainSurface.evidence.boundaries.persistent_runtime_profile_installed);
assertEqual('terminal chain no activation', false, terminalChainSurface.evidence.boundaries.runtime_profile_activation_performed);
assertEqual('terminal chain no hook config', false, terminalChainSurface.evidence.boundaries.hook_configuration_written);
assertEqual('terminal chain no current-machine governance', false, terminalChainSurface.evidence.boundaries.current_machine_governance_proven);
assertEqual('terminal chain state-append burn observed', true, terminalChainSurface.evidence.boundaries.state_append_after_grant_commit_burn_observed);
assertEqual('terminal chain metadata burn observed', true, terminalChainSurface.evidence.boundaries.metadata_partial_commit_burn_observed);
assertEqual('terminal chain witness-ahead rollback refused', true, terminalChainSurface.evidence.boundaries.store_and_anchor_rollback_refused_while_witness_ahead);
assertEqual('terminal chain joint rollback detection open', false, terminalChainSurface.evidence.boundaries.store_anchor_and_witness_joint_rollback_detection);
assertEqual('terminal chain joint rollback reopens grant reuse', true, terminalChainSurface.evidence.boundaries.joint_rollback_reopened_authority_grant_reuse);
assertEqual('terminal chain host path TOCTOU open', false, terminalChainSurface.evidence.boundaries.host_filesystem_path_toctou_closed);
assert('terminal chain artifact hash present', /^[a-f0-9]{64}$/.test(terminalChainSurface.evidence.validation.body_sha256));

section('fail closed: heartbeat and policy evidence');
const staleReport = buildGovernedSurfaceCoverageMap({
  bashGateLane: bashLane({ heartbeat: staleHeartbeat }),
});
assertGovernedSurfaceCoverageMap(staleReport);
assertEqual('stale heartbeat downgrades alive', false, surface(staleReport, 'bash.pre_tool_use').alive);
assertEqual('stale heartbeat downgrades governed', false, surface(staleReport, 'bash.pre_tool_use').governed);
assertEqual('stale heartbeat status', 'stale_or_missing_heartbeat', surface(staleReport, 'bash.pre_tool_use').verification_status);

const mismatchPolicyReport = buildGovernedSurfaceCoverageMap({
  bashGateLane: bashLane({ policy: policy({ evidence_version: 'coverage-policy-old' }) }),
});
assertGovernedSurfaceCoverageMap(mismatchPolicyReport);
assertEqual('policy mismatch downgrades policy-current', false, surface(mismatchPolicyReport, 'bash.pre_tool_use').policy_current);
assertEqual('policy mismatch downgrades governed', false, surface(mismatchPolicyReport, 'bash.pre_tool_use').governed);
assertEqual('policy mismatch status', 'policy_not_current', surface(mismatchPolicyReport, 'bash.pre_tool_use').verification_status);

const invalidPolicyReport = buildGovernedSurfaceCoverageMap({
  bashGateLane: bashLane({ policy: policy({ signature_valid: false }) }),
});
assertGovernedSurfaceCoverageMap(invalidPolicyReport);
assertEqual('invalid policy evidence downgrades policy-current', false, surface(invalidPolicyReport, 'bash.pre_tool_use').policy_current);
assertEqual('invalid policy evidence downgrades governed', false, surface(invalidPolicyReport, 'bash.pre_tool_use').governed);

section('fail closed: receipt evidence');
const missingReceiptReport = buildGovernedSurfaceCoverageMap({
  bashGateLane: bashLane({ worker_receipt: null }),
});
assertGovernedSurfaceCoverageMap(missingReceiptReport);
assertEqual('missing Worker Receipt downgrades receipt-capable', false, surface(missingReceiptReport, 'bash.pre_tool_use').receipt_capable);
assertEqual('missing Worker Receipt downgrades governed', false, surface(missingReceiptReport, 'bash.pre_tool_use').governed);
assertEqual('missing Worker Receipt status', 'receipt_not_capable', surface(missingReceiptReport, 'bash.pre_tool_use').verification_status);

const otherEvent = bashEvent({ id: 'coverage-bash-other' });
const mismatchedReceiptReport = buildGovernedSurfaceCoverageMap({
  bashGateLane: bashLane({ worker_receipt: projectWorkerReceipt(otherEvent) }),
});
assertGovernedSurfaceCoverageMap(mismatchedReceiptReport);
assertEqual('mismatched Worker Receipt downgrades receipt-capable', false, surface(mismatchedReceiptReport, 'bash.pre_tool_use').receipt_capable);
assertEqual('mismatched Worker Receipt id mismatch named', false, surface(mismatchedReceiptReport, 'bash.pre_tool_use').evidence.receipt.id_matches_audit);

const forgedRefHash = 'f'.repeat(64);
const forgedRefReport = buildGovernedSurfaceCoverageMap({
  bashGateLane: {
    surface_id: 'bash.pre_tool_use',
    boarding_lane: 'Bash gate PreToolUse boarding lane',
    checkpoint_path: 'bash-gate:PreToolUse->zlar-gate',
    hook: {
      configured: true,
      routed: true,
      name: 'PreToolUse',
    },
    heartbeat: freshHeartbeat,
    policy: policy(),
    audit_event_ref: {
      id: 'coverage-bash-forged-ref',
      source: 'gate',
      domain: 'bash',
      outcome: 'deny',
      rule: 'RTEST_BASH',
      policy_version: POLICY_VERSION,
      audit_hash: forgedRefHash,
    },
    worker_receipt_ref: {
      present: true,
      valid: true,
      event_id: 'coverage-bash-forged-ref',
      surface: 'bash-gate',
      policy_version: POLICY_VERSION,
      audit_hash: forgedRefHash,
      detail_hash: 'a'.repeat(64),
      decision_outcome: 'deny',
    },
    downstream_refusal: {
      proved: true,
      mechanism: 'Fixture downstream refusal evidence for missing or unrecognized boarding credential.',
    },
  },
});
assertGovernedSurfaceCoverageMap(forgedRefReport);
assertEqual('forged Worker Receipt ref is reference-only', true, surface(forgedRefReport, 'bash.pre_tool_use').evidence.receipt.reference_only);
assertEqual('forged Worker Receipt ref downgrades receipt-capable', false, surface(forgedRefReport, 'bash.pre_tool_use').receipt_capable);
assertEqual('forged Worker Receipt ref downgrades governed', false, surface(forgedRefReport, 'bash.pre_tool_use').governed);
assertEqual('forged Worker Receipt ref status', 'receipt_not_capable', surface(forgedRefReport, 'bash.pre_tool_use').verification_status);

section('fail closed: downstream refusal evidence');
const missingDownstreamRefusalReport = buildGovernedSurfaceCoverageMap({
  bashGateLane: bashLane({
    downstream_refusal: {
      proved: false,
      mechanism: 'Fixture intentionally omits aircraft-door refusal proof.',
    },
  }),
});
assertGovernedSurfaceCoverageMap(missingDownstreamRefusalReport);
const missingDownstreamRefusalSurface = surface(missingDownstreamRefusalReport, 'bash.pre_tool_use');
assertEqual('missing downstream refusal downgrades downstream_refusal', false, missingDownstreamRefusalSurface.downstream_refusal);
assertEqual('missing downstream refusal downgrades governed', false, missingDownstreamRefusalSurface.governed);
assertEqual('missing downstream refusal status', 'downstream_refusal_missing', missingDownstreamRefusalSurface.verification_status);

const notApplicableDownstreamRefusalReport = buildGovernedSurfaceCoverageMap({
  bashGateLane: bashLane({
    downstream_refusal: {
      applicable: false,
      proved: false,
      mechanism: 'Fixture marks downstream refusal not applicable on a counted lane.',
    },
  }),
});
assertGovernedSurfaceCoverageMap(notApplicableDownstreamRefusalReport);
const notApplicableDownstreamRefusalSurface = surface(notApplicableDownstreamRefusalReport, 'bash.pre_tool_use');
assertEqual('not-applicable downstream refusal downgrades downstream_refusal', false, notApplicableDownstreamRefusalSurface.downstream_refusal);
assertEqual('not-applicable downstream refusal downgrades governed', false, notApplicableDownstreamRefusalSurface.governed);
assertEqual('not-applicable downstream refusal status', 'downstream_refusal_missing', notApplicableDownstreamRefusalSurface.verification_status);

const recognitionRefusalLane = bashLane();
const recognitionRefusalDecision = {
  result_type: DOWNSTREAM_RECOGNITION_RULE_TYPE,
  recognized: false,
  decision: 'refuse',
  reason_code: 'unknown_issuer',
  reasons: [{ code: 'unknown_issuer', message: 'Fixture issuer is not recognized.' }],
  evidence: {
    receipt_present: true,
    kid: 'fixture-kid',
    signature_valid: false,
    receipt_id: 'fixture-receipt-refused',
    payload: {
      tool: 'deploy.release',
      domain: 'deploy',
      outcome: 'allow',
      policy_version: POLICY_VERSION,
      audit_event_id: recognitionRefusalLane.audit_event.id,
      detail_hash: recognitionRefusalLane.worker_receipt.action.detail_hash,
    },
    rule: {
      deployment_scope: 'fixture-terminal',
    },
  },
};
const recognitionRefusalReport = buildGovernedSurfaceCoverageMap({
  bashGateLane: {
    ...recognitionRefusalLane,
    downstream_refusal: {
      recognition_decision: recognitionRefusalDecision,
    },
  },
});
assertGovernedSurfaceCoverageMap(recognitionRefusalReport);
const recognitionRefusalSurface = surface(recognitionRefusalReport, 'bash.pre_tool_use');
assertEqual('refused recognition decision proves downstream refusal', true, recognitionRefusalSurface.downstream_refusal);
assertEqual('refused recognition decision preserves governed lane', true, recognitionRefusalSurface.governed);
assertEqual('refused recognition decision reason carried', 'unknown_issuer', recognitionRefusalSurface.evidence.downstream_refusal.recognition_decision.reason_code);
assertEqual('refused recognition audit event matches lane', true, recognitionRefusalSurface.evidence.downstream_refusal.recognition_decision.lane_match.audit_event_matches_lane);
assertEqual('refused recognition detail hash matches lane', true, recognitionRefusalSurface.evidence.downstream_refusal.recognition_decision.lane_match.detail_hash_matches_lane);
assertEqual('refused recognition decision omits raw key', false, JSON.stringify(recognitionRefusalSurface.evidence.downstream_refusal).includes('BEGIN PUBLIC KEY'));

const mismatchedRecognitionAuditReport = buildGovernedSurfaceCoverageMap({
  bashGateLane: {
    ...recognitionRefusalLane,
    downstream_refusal: {
      recognition_decision: {
        ...recognitionRefusalDecision,
        evidence: {
          ...recognitionRefusalDecision.evidence,
          payload: {
            ...recognitionRefusalDecision.evidence.payload,
            audit_event_id: 'other-audit-event',
          },
        },
      },
    },
  },
});
assertGovernedSurfaceCoverageMap(mismatchedRecognitionAuditReport);
const mismatchedRecognitionAuditSurface = surface(mismatchedRecognitionAuditReport, 'bash.pre_tool_use');
assertEqual('mismatched recognition audit id is not refusal proof', false, mismatchedRecognitionAuditSurface.downstream_refusal);
assertEqual('mismatched recognition audit id downgrades governed', false, mismatchedRecognitionAuditSurface.governed);
assertEqual('mismatched recognition audit id status', 'downstream_refusal_missing', mismatchedRecognitionAuditSurface.verification_status);
assertEqual('mismatched recognition audit id names mismatch', false, mismatchedRecognitionAuditSurface.evidence.downstream_refusal.recognition_decision.lane_match.audit_event_matches_lane);

const mismatchedRecognitionDetailReport = buildGovernedSurfaceCoverageMap({
  bashGateLane: {
    ...recognitionRefusalLane,
    downstream_refusal: {
      recognition_decision: {
        ...recognitionRefusalDecision,
        evidence: {
          ...recognitionRefusalDecision.evidence,
          payload: {
            ...recognitionRefusalDecision.evidence.payload,
            detail_hash: 'd'.repeat(64),
          },
        },
      },
    },
  },
});
assertGovernedSurfaceCoverageMap(mismatchedRecognitionDetailReport);
const mismatchedRecognitionDetailSurface = surface(mismatchedRecognitionDetailReport, 'bash.pre_tool_use');
assertEqual('mismatched recognition detail hash is not refusal proof', false, mismatchedRecognitionDetailSurface.downstream_refusal);
assertEqual('mismatched recognition detail hash downgrades governed', false, mismatchedRecognitionDetailSurface.governed);
assertEqual('mismatched recognition detail hash status', 'downstream_refusal_missing', mismatchedRecognitionDetailSurface.verification_status);
assertEqual('mismatched recognition detail hash names mismatch', false, mismatchedRecognitionDetailSurface.evidence.downstream_refusal.recognition_decision.lane_match.detail_hash_matches_lane);

const acceptedRecognitionLane = bashLane();
const acceptedRecognitionReport = buildGovernedSurfaceCoverageMap({
  bashGateLane: {
    ...acceptedRecognitionLane,
    downstream_refusal: {
      recognition_decision: {
        result_type: DOWNSTREAM_RECOGNITION_RULE_TYPE,
        recognized: true,
        decision: 'accept',
        reason_code: 'recognized',
        reasons: [{ code: 'recognized', message: 'Fixture receipt matched.' }],
        evidence: {
          receipt_present: true,
          kid: 'fixture-kid',
          signature_valid: true,
          receipt_id: 'fixture-receipt-accepted',
          payload: {
            tool: 'deploy.release',
            domain: 'deploy',
            outcome: 'allow',
            policy_version: POLICY_VERSION,
            audit_event_id: acceptedRecognitionLane.audit_event.id,
            detail_hash: acceptedRecognitionLane.worker_receipt.action.detail_hash,
          },
          rule: {
            deployment_scope: 'fixture-terminal',
          },
        },
      },
    },
  },
});
assertGovernedSurfaceCoverageMap(acceptedRecognitionReport);
const acceptedRecognitionSurface = surface(acceptedRecognitionReport, 'bash.pre_tool_use');
assertEqual('accepted recognition decision is not refusal proof', false, acceptedRecognitionSurface.downstream_refusal);
assertEqual('accepted recognition decision downgrades governed', false, acceptedRecognitionSurface.governed);
assertEqual('accepted recognition decision status', 'downstream_refusal_missing', acceptedRecognitionSurface.verification_status);

section('fail closed: service profile preflight lane evidence');
const missingServicePreflightArtifactReport = buildGovernedSurfaceCoverageMap({
  serviceProfilePreflightLane: {
    ...serviceProfilePreflightLane(),
    service_profile_preflight_artifact: null,
  },
});
assertGovernedSurfaceCoverageMap(missingServicePreflightArtifactReport);
const missingServicePreflightArtifactSurface = surface(missingServicePreflightArtifactReport, 'protected-records.service-profile.records.write');
assertEqual('missing service preflight artifact not governed', false, missingServicePreflightArtifactSurface.governed);
assertEqual('missing service preflight artifact status', 'missing_configuration', missingServicePreflightArtifactSurface.verification_status);
assertEqual('missing service preflight artifact evidence present false', false, missingServicePreflightArtifactSurface.evidence.validation.artifact_present);

const mismatchedServicePreflightProfileReport = buildGovernedSurfaceCoverageMap({
  serviceProfilePreflightLane: serviceProfilePreflightLane({
    artifact: {
      mutate: (artifact) => {
        artifact.payload.preflight.profile.profile_sha256 = '0'.repeat(64);
      },
    },
  }),
});
assertGovernedSurfaceCoverageMap(mismatchedServicePreflightProfileReport);
const mismatchedServicePreflightProfileSurface = surface(mismatchedServicePreflightProfileReport, 'protected-records.service-profile.records.write');
assertEqual('mismatched service preflight profile not governed', false, mismatchedServicePreflightProfileSurface.governed);
assertEqual('mismatched service preflight profile status', 'missing_configuration', mismatchedServicePreflightProfileSurface.verification_status);
assert('mismatched service preflight profile names validation error', Boolean(mismatchedServicePreflightProfileSurface.evidence.validation.validation_error));

const missingServicePreflightRefusalReport = buildGovernedSurfaceCoverageMap({
  serviceProfilePreflightLane: serviceProfilePreflightLane({
    artifact: {
      mutate: (artifact) => {
        const missing = artifact.payload.preflight.cases.find((item) =>
          item.case_id === 'missing_receipt_profile_refused_before_service_mutation'
        );
        missing.service_write_accepted = true;
      },
    },
  }),
});
assertGovernedSurfaceCoverageMap(missingServicePreflightRefusalReport);
const missingServicePreflightRefusalSurface = surface(missingServicePreflightRefusalReport, 'protected-records.service-profile.records.write');
assertEqual('missing service preflight refusal not governed', false, missingServicePreflightRefusalSurface.governed);
assertEqual('missing service preflight refusal status', 'missing_configuration', missingServicePreflightRefusalSurface.verification_status);
assert('missing service preflight refusal names validation error', Boolean(missingServicePreflightRefusalSurface.evidence.validation.validation_error));

const missingServicePreflightWrongPolicyReport = buildGovernedSurfaceCoverageMap({
  serviceProfilePreflightLane: serviceProfilePreflightLane({
    artifact: {
      mutate: (artifact) => {
        const wrongPolicy = artifact.payload.preflight.cases.find((item) =>
          item.case_id === 'wrong_policy_profile_refused_before_service_mutation'
        );
        wrongPolicy.service_write_accepted = true;
      },
    },
  }),
});
assertGovernedSurfaceCoverageMap(missingServicePreflightWrongPolicyReport);
const missingServicePreflightWrongPolicySurface = surface(missingServicePreflightWrongPolicyReport, 'protected-records.service-profile.records.write');
assertEqual('missing service preflight wrong-policy refusal not governed', false, missingServicePreflightWrongPolicySurface.governed);
assertEqual('missing service preflight wrong-policy status', 'missing_configuration', missingServicePreflightWrongPolicySurface.verification_status);
assert('missing service preflight wrong-policy names validation error', Boolean(missingServicePreflightWrongPolicySurface.evidence.validation.validation_error));

section('fail closed: runtime local activation lane evidence');
const missingRuntimeArtifactReport = buildGovernedSurfaceCoverageMap({
  runtimeLocalActivationLane: {
    ...runtimeLocalActivationLane(),
    runtime_local_activation_artifact: null,
  },
});
assertGovernedSurfaceCoverageMap(missingRuntimeArtifactReport);
const missingRuntimeArtifactSurface = surface(missingRuntimeArtifactReport, 'protected-records.runtime.records.write');
assertEqual('missing runtime artifact not governed', false, missingRuntimeArtifactSurface.governed);
assertEqual('missing runtime artifact status', 'missing_configuration', missingRuntimeArtifactSurface.verification_status);
assertEqual('missing runtime artifact evidence present false', false, missingRuntimeArtifactSurface.evidence.validation.artifact_present);

const mismatchedRuntimeProfileReport = buildGovernedSurfaceCoverageMap({
  runtimeLocalActivationLane: runtimeLocalActivationLane({
    artifact: {
      mutate: (artifact) => {
        artifact.payload.proof.runtime_profile.profile_sha256 = '0'.repeat(64);
      },
    },
  }),
});
assertGovernedSurfaceCoverageMap(mismatchedRuntimeProfileReport);
const mismatchedRuntimeProfileSurface = surface(mismatchedRuntimeProfileReport, 'protected-records.runtime.records.write');
assertEqual('mismatched runtime profile not governed', false, mismatchedRuntimeProfileSurface.governed);
assertEqual('mismatched runtime profile status', 'missing_configuration', mismatchedRuntimeProfileSurface.verification_status);
assert('mismatched runtime profile names validation error', Boolean(mismatchedRuntimeProfileSurface.evidence.validation.validation_error));

const missingRuntimeRefusalReport = buildGovernedSurfaceCoverageMap({
  runtimeLocalActivationLane: runtimeLocalActivationLane({
    artifact: {
      mutate: (artifact) => {
        artifact.payload.proof.runtime_proof_summary.missing_receipt_refused = false;
      },
    },
  }),
});
assertGovernedSurfaceCoverageMap(missingRuntimeRefusalReport);
const missingRuntimeRefusalSurface = surface(missingRuntimeRefusalReport, 'protected-records.runtime.records.write');
assertEqual('missing runtime refusal not governed', false, missingRuntimeRefusalSurface.governed);
assertEqual('missing runtime refusal status', 'missing_configuration', missingRuntimeRefusalSurface.verification_status);
assert('missing runtime refusal names validation error', Boolean(missingRuntimeRefusalSurface.evidence.validation.validation_error));

section('fail closed: runtime profile installation lane evidence');
const missingRuntimeInstallationArtifactReport = buildGovernedSurfaceCoverageMap({
  runtimeProfileInstallationLane: {
    ...runtimeProfileInstallationLane(),
    runtime_profile_installation_artifact: null,
  },
});
assertGovernedSurfaceCoverageMap(missingRuntimeInstallationArtifactReport);
const missingRuntimeInstallationArtifactSurface = surface(missingRuntimeInstallationArtifactReport, 'protected-records.runtime.profile-installation.records.write');
assertEqual('missing runtime installation artifact not governed', false, missingRuntimeInstallationArtifactSurface.governed);
assertEqual('missing runtime installation artifact status', 'missing_configuration', missingRuntimeInstallationArtifactSurface.verification_status);
assertEqual('missing runtime installation artifact evidence present false', false, missingRuntimeInstallationArtifactSurface.evidence.validation.artifact_present);

const mismatchedRuntimeInstallationProfileReport = buildGovernedSurfaceCoverageMap({
  runtimeProfileInstallationLane: runtimeProfileInstallationLane({
    artifact: {
      mutate: (artifact) => {
        artifact.payload.proof.runtime_profile.profile_sha256 = '0'.repeat(64);
      },
    },
  }),
});
assertGovernedSurfaceCoverageMap(mismatchedRuntimeInstallationProfileReport);
const mismatchedRuntimeInstallationProfileSurface = surface(mismatchedRuntimeInstallationProfileReport, 'protected-records.runtime.profile-installation.records.write');
assertEqual('mismatched runtime installation profile not governed', false, mismatchedRuntimeInstallationProfileSurface.governed);
assertEqual('mismatched runtime installation profile status', 'missing_configuration', mismatchedRuntimeInstallationProfileSurface.verification_status);
assert('mismatched runtime installation profile names validation error', Boolean(mismatchedRuntimeInstallationProfileSurface.evidence.validation.validation_error));

const bypassedRuntimeInstallationGuardReport = buildGovernedSurfaceCoverageMap({
  runtimeProfileInstallationLane: runtimeProfileInstallationLane({
    artifact: {
      mutate: (artifact) => {
        artifact.payload.proof.request_authority_guard_summary.all_refused_before_mutation = false;
      },
    },
  }),
});
assertGovernedSurfaceCoverageMap(bypassedRuntimeInstallationGuardReport);
const bypassedRuntimeInstallationGuardSurface = surface(bypassedRuntimeInstallationGuardReport, 'protected-records.runtime.profile-installation.records.write');
assertEqual('bypassed runtime installation guard not governed', false, bypassedRuntimeInstallationGuardSurface.governed);
assertEqual('bypassed runtime installation guard status', 'missing_configuration', bypassedRuntimeInstallationGuardSurface.verification_status);
assert('bypassed runtime installation guard names validation error', Boolean(bypassedRuntimeInstallationGuardSurface.evidence.validation.validation_error));

section('fail closed: installed runtime profile terminal chain lane evidence');
const missingTerminalChainArtifactReport = buildGovernedSurfaceCoverageMap({
  installedRuntimeProfileTerminalChainLane: {
    ...installedRuntimeProfileTerminalChainLane(),
    installed_runtime_profile_terminal_chain_artifact: null,
  },
});
assertGovernedSurfaceCoverageMap(missingTerminalChainArtifactReport);
const missingTerminalChainArtifactSurface = surface(missingTerminalChainArtifactReport, 'protected-records.installed-runtime-profile.terminal-chain.records.write');
assertEqual('missing terminal chain artifact not governed', false, missingTerminalChainArtifactSurface.governed);
assertEqual('missing terminal chain artifact status', 'missing_configuration', missingTerminalChainArtifactSurface.verification_status);
assertEqual('missing terminal chain artifact evidence present false', false, missingTerminalChainArtifactSurface.evidence.validation.artifact_present);

const driftedTerminalChainNamedHashReport = buildGovernedSurfaceCoverageMap({
  installedRuntimeProfileTerminalChainLane: installedRuntimeProfileTerminalChainLane({
    artifact: {
      mutate: (artifact) => {
        artifact.payload.chain.terminal_chain.named_receipt_refusals_sha256 = '0'.repeat(64);
      },
    },
  }),
});
assertGovernedSurfaceCoverageMap(driftedTerminalChainNamedHashReport);
const driftedTerminalChainNamedHashSurface = surface(driftedTerminalChainNamedHashReport, 'protected-records.installed-runtime-profile.terminal-chain.records.write');
assertEqual('drifted terminal chain named hash not governed', false, driftedTerminalChainNamedHashSurface.governed);
assertEqual('drifted terminal chain named hash status', 'missing_configuration', driftedTerminalChainNamedHashSurface.verification_status);
assert('drifted terminal chain named hash names validation error', Boolean(driftedTerminalChainNamedHashSurface.evidence.validation.validation_error));

const driftedTerminalChainTrustedRegistryReport = buildGovernedSurfaceCoverageMap({
  installedRuntimeProfileTerminalChainLane: installedRuntimeProfileTerminalChainLane({
    artifact: {
      mutate: (artifact) => {
        artifact.payload.chain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_public_key_material_included = true;
      },
    },
  }),
});
assertGovernedSurfaceCoverageMap(driftedTerminalChainTrustedRegistryReport);
const driftedTerminalChainTrustedRegistrySurface = surface(driftedTerminalChainTrustedRegistryReport, 'protected-records.installed-runtime-profile.terminal-chain.records.write');
assertEqual('drifted terminal chain trusted registry not governed', false, driftedTerminalChainTrustedRegistrySurface.governed);
assertEqual('drifted terminal chain trusted registry status', 'missing_configuration', driftedTerminalChainTrustedRegistrySurface.verification_status);
assert('drifted terminal chain trusted registry names validation error', Boolean(driftedTerminalChainTrustedRegistrySurface.evidence.validation.validation_error));

const driftedTerminalChainTrustedRegistryRefusalCaseIdReport = buildGovernedSurfaceCoverageMap({
  installedRuntimeProfileTerminalChainLane: installedRuntimeProfileTerminalChainLane({
    artifact: {
      mutate: (artifact) => {
        artifact.payload.chain.terminal_chain.trusted_issuer_registry_recognition_binding
          .trusted_issuer_registry_recognition_refusals.cases[0].case_id =
            'vague_registry_refusal';
      },
    },
  }),
});
assertGovernedSurfaceCoverageMap(driftedTerminalChainTrustedRegistryRefusalCaseIdReport);
const driftedTerminalChainTrustedRegistryRefusalCaseIdSurface = surface(driftedTerminalChainTrustedRegistryRefusalCaseIdReport, 'protected-records.installed-runtime-profile.terminal-chain.records.write');
assertEqual('drifted terminal chain trusted registry refusal case ID not governed', false, driftedTerminalChainTrustedRegistryRefusalCaseIdSurface.governed);
assertEqual('drifted terminal chain trusted registry refusal case ID status', 'missing_configuration', driftedTerminalChainTrustedRegistryRefusalCaseIdSurface.verification_status);
assert('drifted terminal chain trusted registry refusal case ID names validation error', Boolean(driftedTerminalChainTrustedRegistryRefusalCaseIdSurface.evidence.validation.validation_error));

const driftedTerminalChainTrustedRegistryRefusalReasonReport = buildGovernedSurfaceCoverageMap({
  installedRuntimeProfileTerminalChainLane: installedRuntimeProfileTerminalChainLane({
    artifact: {
      mutate: (artifact) => {
        artifact.payload.chain.terminal_chain.trusted_issuer_registry_recognition_binding
          .trusted_issuer_registry_recognition_refusals.cases[1].reason_code =
            'generic_refusal';
      },
    },
  }),
});
assertGovernedSurfaceCoverageMap(driftedTerminalChainTrustedRegistryRefusalReasonReport);
const driftedTerminalChainTrustedRegistryRefusalReasonSurface = surface(driftedTerminalChainTrustedRegistryRefusalReasonReport, 'protected-records.installed-runtime-profile.terminal-chain.records.write');
assertEqual('drifted terminal chain trusted registry refusal reason not governed', false, driftedTerminalChainTrustedRegistryRefusalReasonSurface.governed);
assertEqual('drifted terminal chain trusted registry refusal reason status', 'missing_configuration', driftedTerminalChainTrustedRegistryRefusalReasonSurface.verification_status);
assert('drifted terminal chain trusted registry refusal reason names validation error', Boolean(driftedTerminalChainTrustedRegistryRefusalReasonSurface.evidence.validation.validation_error));

section('fail closed: MCP bypass evidence');
const directMcpReport = buildGovernedSurfaceCoverageMap({
  mcpGateLane: mcpLane({
    mcp_registration: {
      configured: true,
      routed: true,
      zlar_routed: true,
      configured_server_count: 1,
      direct_upstream_observed: true,
      extra_registration_observed: false,
    },
  }),
});
const directMcpSurface = surface(directMcpReport, 'mcp.tools_call');
assertEqual('direct MCP upstream forces routed false', false, directMcpSurface.routed);
assertEqual('direct MCP upstream forces governed false', false, directMcpSurface.governed);
assertEqual('direct MCP upstream rejected status', 'rejected_mcp_bypass', directMcpSurface.verification_status);
assertThrows('direct MCP upstream rejected by validator', () => {
  assertGovernedSurfaceCoverageMap(directMcpReport);
}, 'direct MCP upstream');

const extraMcpReport = buildGovernedSurfaceCoverageMap({
  mcpGateLane: mcpLane({
    mcp_registration: {
      configured: true,
      routed: true,
      zlar_routed: true,
      configured_server_count: 2,
      direct_upstream_observed: false,
      extra_registration_observed: true,
    },
  }),
});
const extraMcpSurface = surface(extraMcpReport, 'mcp.tools_call');
assertEqual('extra MCP registration forces routed false', false, extraMcpSurface.routed);
assertEqual('extra MCP registration forces governed false', false, extraMcpSurface.governed);
assertEqual('extra MCP registration rejected status', 'rejected_mcp_bypass', extraMcpSurface.verification_status);
assertThrows('extra MCP registration rejected by validator', () => {
  assertGovernedSurfaceCoverageMap(extraMcpReport);
}, 'extra MCP registration');

section('boundary entries');
assertEqual('Cursor afterFileEdit is audit-only', 'audit_only', surface(report, 'cursor.afterFileEdit').verification_status);
assertEqual('Cursor afterFileEdit never governed', false, surface(report, 'cursor.afterFileEdit').governed);
assertEqual('Windsurf post_* is audit-only', 'audit_only', surface(report, 'windsurf.post_events').verification_status);
assertEqual('Windsurf post_* never governed', false, surface(report, 'windsurf.post_events').governed);
assertEqual('SDK/AuthZEN boundary is deferred', 'deferred', surface(report, 'sdk.daemon_membrane_authzen').verification_status);
assertEqual('SDK/AuthZEN not counted', false, surface(report, 'sdk.daemon_membrane_authzen').counted);
assertEqual('SubagentStart not receipt-capable', false, surface(report, 'hook.subagent_start').receipt_capable);
assertEqual('SubagentStart not governed', false, surface(report, 'hook.subagent_start').governed);
assertEqual('direct MCP registrations listed', 'rejected_mcp_bypass', surface(report, 'mcp.direct_registration').verification_status);
for (const id of [
  'unrouted.shell',
  'unrouted.filesystem',
  'unrouted.browser',
  'unrouted.app_control',
  'unrouted.network',
  'unrouted.model',
  'unrouted.final_text',
]) {
  assertEqual(`${id} boundary is unrouted`, 'unrouted', surface(report, id).verification_status);
  assertEqual(`${id} boundary is not governed`, false, surface(report, id).governed);
}

section('privacy and claim scans');
const summary = formatGovernedSurfaceCoverageMapSummary(report);
assert('summary validates against scanner', assertNoUnsafeCoverageMapText(summary));
assert('summary states governed count', summary.includes('governed=4/6'));
const serializedReport = JSON.stringify(report);
assert('report omits raw bash command args', !serializedReport.includes('private-key') && !serializedReport.includes('printf safe'));
assert('report omits raw MCP args', !serializedReport.includes('args_preview') && !serializedReport.includes('sk-live-mcp'));
assert('report omits private fixture paths', !serializedReport.includes('/Users/tester'));

const leakyLaneReport = buildGovernedSurfaceCoverageMap({
  bashGateLane: bashLane({
    boarding_lane: 'Bash /Users/tester/.zlar lane token=sk-live-fixture-111111 human:123456',
    checkpoint_path: '/Users/tester/.zlar/bin/zlar-gate',
  }),
});
const leakyText = JSON.stringify(leakyLaneReport);
assert('builder redacts private paths from strings', !leakyText.includes('/Users/tester') && leakyText.includes('[REDACTED_PATH]'));
assert('builder redacts credentials from strings', !leakyText.includes('sk-live-fixture-111111') && leakyText.includes('[REDACTED_CREDENTIAL]'));
assert('builder redacts numeric human ids from strings', !leakyText.includes('human:123456') && leakyText.includes('human:[REDACTED_ID]'));
assertThrows('scanner rejects private paths', () => {
  assertNoUnsafeCoverageMapText('/Users/tester/.zlar/bin/zlar-gate');
}, 'private operator path');
assertThrows('scanner rejects credentials', () => {
  assertNoUnsafeCoverageMapText('token=sk-live-fixture-222222');
}, 'credential');
assertThrows('scanner rejects chat IDs', () => {
  assertNoUnsafeCoverageMapText('chat_id=123456');
}, 'chat id');
assertThrows('scanner rejects numeric human ids', () => {
  assertNoUnsafeCoverageMapText('human:123456');
}, 'numeric human');
assertThrows('scanner rejects broad all-actions claim', () => {
  assertNoUnsafeCoverageMapText('ZLAR governs all actions');
}, 'broad action');
assertThrows('scanner rejects broad Codex claim', () => {
  assertNoUnsafeCoverageMapText(['ZLAR', 'governs', 'Codex'].join(' '));
}, 'broad Codex');
assertThrows('scanner rejects enterprise-ready claim', () => {
  assertNoUnsafeCoverageMapText('enterprise ready');
}, 'enterprise');
assertThrows('scanner rejects sovereign claim', () => {
  assertNoUnsafeCoverageMapText('sovereign recognition');
}, 'sovereign');
assertThrows('scanner rejects external attestation claim', () => {
  assertNoUnsafeCoverageMapText('externally attested');
}, 'external');
assertThrows('scanner rejects production authority claim', () => {
  assertNoUnsafeCoverageMapText('production authority');
}, 'production');

console.log(`\nResults: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
