#!/usr/bin/env node
// CLI tests for fixture-input Governed Surface Coverage Map v1 wiring.

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { projectWorkerReceipt } from '../lib/worker-receipt.mjs';

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

const POLICY_VERSION = 'coverage-policy-v1';
const RUNTIME_PROFILE_SHA256 =
  'e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469';
const EXACT_RUNTIME_ROUTE =
  'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation';
const CURRENT_AUTHORITY_GRANT_SHA256 =
  '0c074a8e96559a29fc23d2f18f6062d539e2a1ea5baa25d53b7ba4b8fec4eaba';
const ZLAR_BIN = join(process.cwd(), 'bin', 'zlar');
const COMMITTED_FIXTURE_PATH = join(
  process.cwd(),
  'tests',
  'fixtures',
  'governed-surface-coverage-map-v1-input.json'
);
const RUNTIME_LOCAL_ACTIVATION_ARTIFACT = JSON.parse(readFileSync(
  join(process.cwd(), 'tests', 'fixtures', 'protected-records-runtime-local-activation-artifact-v1.json'),
  'utf8'
));

function bashEvent(overrides = {}) {
  return {
    id: overrides.id || 'coverage-cli-bash-001',
    ts: '2026-06-17T13:00:00Z',
    seq: 1,
    source: 'gate',
    host: 'test-host',
    user: 'tester',
    agent_id: 'codex-cli',
    session_id: 'coverage-cli-session',
    domain: 'bash',
    action: 'Bash',
    outcome: overrides.outcome || 'allow',
    risk_score: 0,
    detail: {
      command: 'cat /Users/tester/private-key token=sk-live-cli-fixture-000000',
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
    id: overrides.id || 'coverage-cli-mcp-001',
    ts: '2026-06-17T13:00:01Z',
    seq: 2,
    source: 'mcp-gate',
    host: 'test-host',
    user: 'tester',
    agent_id: 'codex-cli',
    session_id: 'coverage-cli-session',
    transport: 'stdio',
    domain: 'mcp',
    action: overrides.action || 'filesystem.write_file',
    outcome: overrides.outcome || 'deny',
    risk_score: 80,
    detail: {
      tool: overrides.action || 'filesystem.write_file',
      args_preview: '{"path":"/Users/tester/private","api_key":"sk-live-cli-mcp-000000"}',
    },
    rule: overrides.rule || 'RTEST_MCP',
    rule_description: 'Fixture routed MCP gate rule.',
    policy_version: overrides.policy_version || POLICY_VERSION,
    policy_key_id: 'policy-key-test',
    severity: 'critical',
    prev_hash: overrides.prev_hash || 'b'.repeat(64),
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

function freshHeartbeat() {
  return {
    state: 'on',
    last_heartbeat_epoch: 3000,
    now_epoch: 3015,
    freshness_seconds: 120,
  };
}

function bashLane(overrides = {}) {
  const event = overrides.audit_event || overrides.auditEvent || bashEvent(overrides.eventOverrides);
  return {
    surface_id: 'bash.pre_tool_use',
    boarding_lane: 'Bash gate PreToolUse boarding lane',
    checkpoint_path: 'bash-gate:PreToolUse->zlar-gate',
    hook: { configured: true, routed: true, name: 'PreToolUse' },
    heartbeat: freshHeartbeat(),
    policy: policy(),
    audit_event: event,
    worker_receipt: projectWorkerReceipt(event),
    downstream_refusal: {
      proved: true,
      mechanism: 'Fixture downstream refusal evidence for missing credential.',
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
    heartbeat: freshHeartbeat(),
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

function runtimeLocalActivationLane(overrides = {}) {
  return {
    surface_id: 'protected-records.runtime.records.write',
    boarding_lane: 'Protected records runtime local activation records.write lane',
    checkpoint_path: `protected-records-runtime-local-activation:${EXACT_RUNTIME_ROUTE}`,
    runtime_local_activation_artifact: JSON.parse(JSON.stringify(RUNTIME_LOCAL_ACTIVATION_ARTIFACT)),
    non_claims: [
      'This lane counts only the committed local disposable runtime activation artifact.',
      'This lane does not claim persistent install, hook configuration, production service deployment, live current-machine governance, or unrouted records paths.',
      'This lane does not claim authority beyond the supplied fixture artifact.',
    ],
    ...overrides,
  };
}

function coverageInput(overrides = {}) {
  return {
    generatedAt: '2026-06-17T13:34:56Z',
    bashGateLane: bashLane(overrides.bashGateLane || {}),
    mcpGateLane: mcpLane(overrides.mcpGateLane || {}),
    runtimeLocalActivationLane: runtimeLocalActivationLane(overrides.runtimeLocalActivationLane || {}),
    ...(overrides.root || {}),
  };
}

function runCoverage(args, options = {}) {
  return spawnSync(ZLAR_BIN, ['coverage', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
    input: options.input,
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

const scratch = mkdtempSync(join(tmpdir(), 'zlar-coverage-map-cli-'));
try {
  const happyInput = coverageInput();
  const downgradedInput = coverageInput({
    bashGateLane: {
      heartbeat: {
        state: 'on',
        last_heartbeat_epoch: 3000,
        now_epoch: 4000,
        freshness_seconds: 120,
      },
    },
  });
  const unsafeInput = coverageInput({
    root: {
      non_claims: ['ZLAR governs all actions'],
    },
  });
  const directMcpInput = coverageInput({
    mcpGateLane: {
      mcp_registration: {
        configured: true,
        routed: true,
        zlar_routed: true,
        configured_server_count: 1,
        server_name: 'zlar-routed-fixture',
        direct_upstream_observed: true,
        extra_registration_observed: false,
      },
    },
  });

  const happyPath = join(scratch, 'happy.json');
  const downgradedPath = join(scratch, 'downgraded.json');
  const unsafePath = join(scratch, 'unsafe.json');
  const directMcpPath = join(scratch, 'direct-mcp.json');
  writeFileSync(happyPath, `${JSON.stringify(happyInput, null, 2)}\n`);
  writeFileSync(downgradedPath, `${JSON.stringify(downgradedInput, null, 2)}\n`);
  writeFileSync(unsafePath, `${JSON.stringify(unsafeInput, null, 2)}\n`);
  writeFileSync(directMcpPath, `${JSON.stringify(directMcpInput, null, 2)}\n`);

  section('committed example fixture');
  const committedFixtureText = readFileSync(COMMITTED_FIXTURE_PATH, 'utf8');
  assert('committed fixture omits private paths', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(committedFixtureText));
  const unsafeFixturePattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]/i;
  assert('committed fixture omits fake credentials', !unsafeFixturePattern.test(committedFixtureText));
  assert('committed fixture omits raw shell command text', !committedFixtureText.includes('cat /Users/tester/private-key'));

  const fixtureSummary = runCoverage(['--input', COMMITTED_FIXTURE_PATH]);
  assertEqual('committed fixture summary exits zero', 0, fixtureSummary.status);
  assert('committed fixture summary states fixture model', fixtureSummary.stdout.includes('Evidence model: fixtures; live probing=false'));
  assert('committed fixture summary states governed count', fixtureSummary.stdout.includes('Counts: governed=4/6'));
  assert('committed fixture summary names service profile lane', fixtureSummary.stdout.includes('protected-records.service-profile.records.write: governed'));
  assert('committed fixture summary names runtime lane', fixtureSummary.stdout.includes('protected-records.runtime.records.write: governed'));
  assert('committed fixture summary demotes runtime installation lane', fixtureSummary.stdout.includes('protected-records.runtime.profile-installation.records.write: receipt_not_capable'));
  assert('committed fixture summary demotes terminal chain lane', fixtureSummary.stdout.includes('protected-records.installed-runtime-profile.terminal-chain.records.write: receipt_not_capable'));
  assert('committed fixture summary names last decisions', fixtureSummary.stdout.includes('last_decision=allow') && fixtureSummary.stdout.includes('last_decision=recognized_write_accepted'));
  assert('committed fixture summary names last receipts', fixtureSummary.stdout.includes('last_receipt=valid') && fixtureSummary.stdout.includes('last_receipt=recognized_receipt_accepted'));
  assert('committed fixture summary names issuer anchors', fixtureSummary.stdout.includes('issuer=fixture-policy-key') && fixtureSummary.stdout.includes('issuer=protected-records-disposable-runtime-profile'));
  assert('committed fixture summary is privacy safe', !unsafeFixturePattern.test(fixtureSummary.stdout));
  assert('committed fixture summary avoids live coverage claim', !/live machine|live deployment|live coverage/i.test(fixtureSummary.stdout));

  const fixtureJson = runCoverage(['--input', COMMITTED_FIXTURE_PATH, '--json']);
  assertEqual('committed fixture json exits zero', 0, fixtureJson.status);
  const fixtureReport = JSON.parse(fixtureJson.stdout);
  assertEqual('committed fixture json report type', 'governed-surface-coverage-map-v1', fixtureReport.report_type);
  assertEqual('committed fixture json model is fixtures', 'fixtures', fixtureReport.evidence_model.source);
  assertEqual('committed fixture json live probing false', false, fixtureReport.evidence_model.live_probing_performed);
  assertEqual('committed fixture json governed count', 4, fixtureReport.counts.governed_lanes);
  const fixtureRuntimeSurface = fixtureReport.surfaces.find((item) =>
    item.surface_id === 'protected-records.runtime.records.write'
  );
  const fixtureRuntimeInstallationSurface = fixtureReport.surfaces.find((item) =>
    item.surface_id === 'protected-records.runtime.profile-installation.records.write'
  );
  const fixtureTerminalChainSurface = fixtureReport.surfaces.find((item) =>
    item.surface_id === 'protected-records.installed-runtime-profile.terminal-chain.records.write'
  );
  assert('committed fixture json includes service profile lane', fixtureReport.surfaces.some((item) => item.surface_id === 'protected-records.service-profile.records.write' && item.governed === true));
  assert('committed fixture json includes runtime lane', fixtureReport.surfaces.some((item) => item.surface_id === 'protected-records.runtime.records.write' && item.governed === true));
  assert('committed fixture json demotes runtime installation lane', fixtureReport.surfaces.some((item) => item.surface_id === 'protected-records.runtime.profile-installation.records.write' && item.governed === false && item.receipt_capable === false && item.verification_status === 'receipt_not_capable'));
  assert('committed fixture json demotes terminal chain lane', fixtureReport.surfaces.some((item) => item.surface_id === 'protected-records.installed-runtime-profile.terminal-chain.records.write' && item.governed === false && item.receipt_capable === false && item.verification_status === 'receipt_not_capable'));
  assert('committed fixture json includes terminal chain trusted-registry refusal identities', fixtureReport.surfaces.some((item) => (
    item.surface_id === 'protected-records.installed-runtime-profile.terminal-chain.records.write' &&
    item.evidence?.trusted_issuer_registry?.local_refusal_case_ids_preserved === true &&
    item.evidence.trusted_issuer_registry.local_refusal_case_ids?.includes('unrecognized_terminal_chain_registry_scope_refused') &&
    item.evidence.trusted_issuer_registry.local_refusal_reason_codes?.includes('detail_hash_mismatch')
  )));
  assert('committed fixture json includes last decision summaries', fixtureReport.surfaces.some((item) => item.surface_id === 'bash.pre_tool_use' && item.last_decision.outcome === 'allow'));
  assert('committed fixture json includes receipt summaries', fixtureReport.surfaces.some((item) => item.surface_id === 'mcp.tools_call' && item.last_receipt.verification_status === 'valid'));
  assertEqual('committed fixture runtime recognition anchor', RUNTIME_PROFILE_SHA256, fixtureRuntimeSurface?.issuer_identity?.recognition_anchor_id);
  assertEqual('committed fixture installation recognition anchor', RUNTIME_PROFILE_SHA256, fixtureRuntimeInstallationSurface?.issuer_identity?.recognition_anchor_id);
  assertEqual('committed fixture terminal recognition anchor', RUNTIME_PROFILE_SHA256, fixtureTerminalChainSurface?.issuer_identity?.recognition_anchor_id);
  for (const [label, item] of [
    ['runtime', fixtureRuntimeSurface],
    ['installation', fixtureRuntimeInstallationSurface],
    ['terminal', fixtureTerminalChainSurface],
  ]) {
    assertEqual(`committed fixture ${label} exact route`, EXACT_RUNTIME_ROUTE, item?.evidence?.route?.mutation_authoritative_route);
    assertEqual(`committed fixture ${label} grant store identity`, 'persistent-single-use-authority-grant-contract-sha256-store', item?.evidence?.route?.runtime_contract?.consumed_authority_grant_store || item?.evidence?.route?.consumed_authority_grant_store);
    assertEqual(`committed fixture ${label} signed-payload replay identity`, 'verified-signed-payload-sha256', item?.evidence?.route?.runtime_contract?.signed_payload_replay_identity || item?.evidence?.route?.signed_payload_replay_identity);
    assertEqual(`committed fixture ${label} recognition refusal count`, 18, item?.evidence?.downstream_refusal?.recognition_refusals?.required_case_count);
    assertEqual(`committed fixture ${label} recognition refusals before mutation`, true, item?.evidence?.downstream_refusal?.recognition_refusals?.all_refused_before_mutation);
    assertEqual(`committed fixture ${label} authority refusal count`, 5, item?.evidence?.downstream_refusal?.authority_refusals?.required_case_count);
    assertEqual(`committed fixture ${label} authority refusals before consumption`, true, item?.evidence?.downstream_refusal?.authority_refusals?.all_refused_before_consumption_and_mutation);
    assertEqual(`committed fixture ${label} same-process signed-payload replay refused`, true, item?.evidence?.downstream_refusal?.same_process_signed_payload_replay_refused);
    assertEqual(`committed fixture ${label} restart consumed-grant replay refused`, true, item?.evidence?.downstream_refusal?.restart_consumed_authority_grant_refused);
    assertEqual(`committed fixture ${label} joint rollback detection remains open`, false, item?.evidence?.boundaries?.store_anchor_and_witness_joint_rollback_detection);
    assertEqual(`committed fixture ${label} host path TOCTOU remains open`, false, item?.evidence?.boundaries?.host_filesystem_path_toctou_closed);
  }
  assertEqual('committed fixture runtime witness identity', 'launcher-owned-local-store-hash-witness', fixtureRuntimeSurface?.evidence?.route?.runtime_contract?.consumed_store_witness);
  assertEqual('committed fixture installation witness identity', 'launcher-owned-local-store-hash-witness', fixtureRuntimeInstallationSurface?.evidence?.route?.runtime_contract?.consumed_store_witness);
  assertEqual('committed fixture terminal witness source', 'launcher-owned-local-proof-witness', fixtureTerminalChainSurface?.evidence?.route?.consumed_grant_store_witness_source);
  assertEqual('committed fixture runtime burn window named', true, fixtureRuntimeSurface?.evidence?.boundaries?.partial_grant_commit_burn_window_named);
  assertEqual('committed fixture installation burn window named', true, fixtureRuntimeInstallationSurface?.evidence?.boundaries?.partial_grant_commit_burn_window_named);
  assertEqual('committed fixture terminal state-append burn observed', true, fixtureTerminalChainSurface?.evidence?.boundaries?.state_append_after_grant_commit_burn_observed);
  assertEqual('committed fixture terminal metadata burn observed', true, fixtureTerminalChainSurface?.evidence?.boundaries?.metadata_partial_commit_burn_observed);
  assertEqual('committed fixture terminal witness-ahead rollback refused', true, fixtureTerminalChainSurface?.evidence?.boundaries?.store_and_anchor_rollback_refused_while_witness_ahead);
  assertEqual('committed fixture terminal joint rollback reopens grant reuse', true, fixtureTerminalChainSurface?.evidence?.boundaries?.joint_rollback_reopened_authority_grant_reuse);
  assertEqual('committed fixture local fixture rightful path not projected', false, fixtureRuntimeSurface?.evidence?.boundaries?.fixture_rightful_issuance_path_evidenced);
  assertEqual('committed fixture installation historical rightful path preserved', true, fixtureRuntimeInstallationSurface?.evidence?.boundaries?.historical_artifact_fixture_rightful_issuance_path_evidenced);
  assertEqual('committed fixture installation current rightful path refused', false, fixtureRuntimeInstallationSurface?.evidence?.boundaries?.fixture_rightful_issuance_path_evidenced);
  assertEqual('committed fixture terminal historical rightful path preserved', true, fixtureTerminalChainSurface?.evidence?.rightful_issuance?.historical_artifact_fixture_rightful_issuance_path_evidenced);
  assertEqual('committed fixture terminal current rightful path refused', false, fixtureTerminalChainSurface?.evidence?.rightful_issuance?.fixture_rightful_issuance_path_evidenced);
  for (const [label, item] of [
    ['installation', fixtureRuntimeInstallationSurface],
    ['terminal', fixtureTerminalChainSurface],
  ]) {
    assertEqual(`committed fixture ${label} authority status contract`, CURRENT_AUTHORITY_GRANT_SHA256, item?.evidence?.authority_status?.authority_grant_contract_sha256);
    assertEqual(`committed fixture ${label} authority status exhausted`, 'exhausted', item?.evidence?.authority_status?.status);
    assertEqual(`committed fixture ${label} fresh effect refused`, false, item?.evidence?.authority_status?.fresh_effect_allowed);
    assertEqual(`committed fixture ${label} repeated-use provenance invalid`, false, item?.evidence?.authority_status?.repeated_use_provenance_valid);
    assertEqual(`committed fixture ${label} fresh fixture rightful projection refused`, false, item?.evidence?.authority_status?.fresh_fixture_rightful_projection_allowed);
  }
  for (const [label, rightful] of [
    ['installation', fixtureRuntimeInstallationSurface?.evidence?.boundaries],
    ['terminal', fixtureTerminalChainSurface?.evidence?.rightful_issuance],
  ]) {
    assertEqual(`committed fixture ${label} generic rightful issuance false`, false, rightful?.rightful_issuance_proven);
    assertEqual(`committed fixture ${label} live authority false`, false, rightful?.live_authority_proven);
    assertEqual(`committed fixture ${label} production rightful issuance false`, false, rightful?.production_rightful_issuance_proven);
    assertEqual(`committed fixture ${label} current-machine governance false`, false, rightful?.current_machine_governance_proven);
    assertEqual(`committed fixture ${label} lifecycle closure false`, false, rightful?.consequence_lifecycle_closed);
  }
  assert('committed fixture json includes known boundaries', fixtureReport.surfaces.some((item) => item.surface_id === 'protected-records.service-profile.records.write' && item.known_boundaries.includes('runtime_profile_not_installed')));
  assert('committed fixture json is privacy safe', !unsafeFixturePattern.test(fixtureJson.stdout));
  assert('committed fixture json avoids live coverage claim', !/live machine|live deployment|live coverage/i.test(fixtureJson.stdout));

  const fixtureRequire = runCoverage(['--input', COMMITTED_FIXTURE_PATH, '--require-governed']);
  assertEqual('committed fixture require-governed refuses exhausted authority lanes', 1, fixtureRequire.status);
  assertEqual('committed fixture require-governed emits no report', '', fixtureRequire.stdout);
  assert('committed fixture require-governed names runtime installation demotion', fixtureRequire.stderr.includes('protected-records.runtime.profile-installation.records.write:receipt_not_capable'));
  assert('committed fixture require-governed names terminal demotion', fixtureRequire.stderr.includes('protected-records.installed-runtime-profile.terminal-chain.records.write:receipt_not_capable'));

  const fixtureSampleSummary = runCoverage(['--sample']);
  assertEqual('committed fixture sample summary exits zero', 0, fixtureSampleSummary.status);
  assertEqual('committed fixture sample summary matches explicit input', fixtureSummary.stdout, fixtureSampleSummary.stdout);
  assert('committed fixture sample summary is privacy safe', !unsafeFixturePattern.test(fixtureSampleSummary.stdout));

  const fixtureSampleJson = runCoverage(['--sample', '--json']);
  assertEqual('committed fixture sample json exits zero', 0, fixtureSampleJson.status);
  assertEqual('committed fixture sample json matches explicit input', fixtureJson.stdout, fixtureSampleJson.stdout);
  assert('committed fixture sample json is privacy safe', !unsafeFixturePattern.test(fixtureSampleJson.stdout));

  const fixtureSampleRequire = runCoverage(['--sample', '--require-governed']);
  assertEqual('committed fixture sample require-governed refuses exhausted authority lanes', 1, fixtureSampleRequire.status);
  assertEqual('committed fixture sample require-governed emits no report', '', fixtureSampleRequire.stdout);
  assertEqual('committed fixture sample require-governed matches explicit error', fixtureRequire.stderr, fixtureSampleRequire.stderr);

  section('summary output');
  const summary = runCoverage(['--input', happyPath]);
  assertEqual('summary exits zero', 0, summary.status);
  assert('summary title present', summary.stdout.includes('Governed Surface Coverage Map v1'));
  assert('summary states fixture model', summary.stdout.includes('Evidence model: fixtures; live probing=false'));
  assert('summary includes non-claims', summary.stdout.includes('Non-claims:'));
  assert('summary states governed count', summary.stdout.includes('Counts: governed=3/3'));
  assert('summary names runtime lane', summary.stdout.includes('protected-records.runtime.records.write: governed'));
  assert('summary names last decision and receipt', summary.stdout.includes('last_decision=allow') && summary.stdout.includes('last_receipt=recognized_receipt_accepted'));
  assert('summary omits raw private path', !summary.stdout.includes('/Users/tester'));
  assert('summary omits raw credential', !summary.stdout.includes('sk-live-cli'));
  assert('summary avoids live coverage claim', !/live machine|live deployment/i.test(summary.stdout));

  section('JSON output');
  const json = runCoverage(['--input', happyPath, '--json']);
  assertEqual('json exits zero', 0, json.status);
  const report = JSON.parse(json.stdout);
  assertEqual('json report type', 'governed-surface-coverage-map-v1', report.report_type);
  assertEqual('json fixture evidence model', 'fixtures', report.evidence_model.source);
  assertEqual('json live probing false', false, report.evidence_model.live_probing_performed);
  assertEqual('json governed count', 3, report.counts.governed_lanes);
  assert('json includes runtime lane', report.surfaces.some((item) => item.surface_id === 'protected-records.runtime.records.write' && item.governed === true));
  assert('json includes coverage summary', report.surfaces.every((item) => item.coverage_summary && item.coverage_summary.verification_status === item.verification_status));
  assert('json includes issuer non-claims', report.surfaces.every((item) => item.issuer_identity && item.issuer_identity.external_attestation === false));
  assert('json includes non-claims', report.non_claims.includes('/contest is not implemented.'));
  assert('json omits raw private path', !json.stdout.includes('/Users/tester'));
  assert('json omits raw credential', !json.stdout.includes('sk-live-cli'));

  section('stdin input');
  const stdinJson = runCoverage(['--input', '-', '--json'], {
    input: JSON.stringify(happyInput),
  });
  assertEqual('stdin json exits zero', 0, stdinJson.status);
  assertEqual('stdin json report type', 'governed-surface-coverage-map-v1', JSON.parse(stdinJson.stdout).report_type);

  section('require governed');
  const requirePass = runCoverage(['--input', happyPath, '--require-governed']);
  assertEqual('require-governed passes all-governed fixture', 0, requirePass.status);
  const requireFail = runCoverage(['--input', downgradedPath, '--require-governed']);
  assertEqual('require-governed fails downgraded fixture', 1, requireFail.status);
  assert('require-governed failure names lane', requireFail.stderr.includes('bash.pre_tool_use:stale_or_missing_heartbeat'));
  assertEqual('require-governed failure emits no report', '', requireFail.stdout);

  section('fail closed cases');
  const noInput = runCoverage([]);
  assertEqual('no input exits usage error', 2, noInput.status);
  assert('no input says live probing is not implemented', noInput.stderr.includes('live probing is not implemented'));
  assert('no input says input is required', noInput.stderr.includes('--input <file|-> or --sample is required'));
  assertEqual('no input emits no report', '', noInput.stdout);

  const inputSampleConflict = runCoverage(['--input', COMMITTED_FIXTURE_PATH, '--sample']);
  assertEqual('input/sample conflict exits usage error', 2, inputSampleConflict.status);
  assert('input/sample conflict names one input source', inputSampleConflict.stderr.includes('coverage accepts only one input source'));
  assertEqual('input/sample conflict emits no report', '', inputSampleConflict.stdout);

  const missingPath = join(scratch, 'missing-input.json');
  const missingInputFile = runCoverage(['--input', missingPath]);
  assertEqual('missing input file exits nonzero', 1, missingInputFile.status);
  assert('missing input file emits generic read failure', missingInputFile.stderr.includes('Could not read coverage evidence input.'));
  assert('missing input file does not echo path', !missingInputFile.stderr.includes(missingPath) && !missingInputFile.stderr.includes(scratch));
  assertEqual('missing input file emits no report', '', missingInputFile.stdout);

  const fakePrivateOption = `/Users/tester/private-${['sk', 'live', 'cli', 'option', '000000'].join('-')}`;
  const unsupportedOption = runCoverage([`--${fakePrivateOption}`]);
  assertEqual('unsupported option exits usage error', 2, unsupportedOption.status);
  assert('unsupported option emits generic error', unsupportedOption.stderr.includes('Unsupported option provided.'));
  assert('unsupported option does not echo raw value', !unsupportedOption.stderr.includes(fakePrivateOption) && !unsupportedOption.stderr.includes('sk-live-cli-option'));
  assertEqual('unsupported option emits no report', '', unsupportedOption.stdout);

  const unsafe = runCoverage(['--input', unsafePath]);
  assertEqual('unsafe claim exits nonzero', 1, unsafe.status);
  assert('unsafe claim rejected by scanner', unsafe.stderr.includes('coverage map contains broad action claim'));
  assertEqual('unsafe claim emits no report', '', unsafe.stdout);

  const directMcp = runCoverage(['--input', directMcpPath]);
  assertEqual('direct MCP bypass evidence exits nonzero', 1, directMcp.status);
  assert('direct MCP bypass evidence rejected', directMcp.stderr.includes('direct MCP upstream'));
  assertEqual('direct MCP bypass emits no report', '', directMcp.stdout);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(`\nResults: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
