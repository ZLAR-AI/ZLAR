#!/usr/bin/env node

import {
  AGENT_PASSENGER_LAB_EVIDENCE_MODEL,
  AGENT_PASSENGER_LAB_REPORT_TYPE,
  AGENT_PASSENGER_LAB_SCHEMA_VERSION,
  agentPassengerLabScenarioSetSha256,
  assertAgentPassengerLabReport,
  assertNoUnsafeAgentPassengerLabText,
  buildAgentPassengerLabReport,
  formatAgentPassengerLabReport,
  runAgentPassengerLab,
} from '../lib/agent-passenger-lab.mjs';

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

function assertThrows(label, fn, expectedFragment) {
  try {
    fn();
    assert(label, false, 'expected throw');
  } catch (err) {
    assert(
      label,
      err.message.includes(expectedFragment),
      `expected fragment=${JSON.stringify(expectedFragment)} actual=${JSON.stringify(err.message)}`,
    );
  }
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

console.log('\n-- agent passenger lab contract --');

const report = buildAgentPassengerLabReport();
assert('report validates', assertAgentPassengerLabReport(report));
assert('run result validates', assertAgentPassengerLabReport(runAgentPassengerLab()));
assertEqual('report type', AGENT_PASSENGER_LAB_REPORT_TYPE, report.report_type);
assertEqual('schema version', AGENT_PASSENGER_LAB_SCHEMA_VERSION, report.schema_version);
assertEqual('result pass', 'PASS', report.result);
assertEqual('evidence model', AGENT_PASSENGER_LAB_EVIDENCE_MODEL, report.evidence_model);
assertEqual('live probing false', false, report.live_probing);
assertEqual('passenger role count', 10, report.counts.passenger_role_count);
assertEqual('scenario count', 6, report.counts.scenario_count);
assertEqual('allowed effect count', 1, report.counts.allowed_effect_count);
assertEqual('refused before effect count', 4, report.counts.refused_before_effect_count);
assertEqual('claim refusal count', 1, report.counts.claim_refusal_count);
assertEqual('semantic disguise count', 5, report.counts.semantic_disguise_count);
assertEqual('human proxy pressure count', 1, report.counts.human_proxy_pressure_count);
assertEqual('authority laundering attempt count', 4, report.counts.authority_laundering_attempt_count);
assertEqual('duplicate refusal noise count', 1, report.counts.duplicate_refusal_noise_count);
assertEqual('missing route candidate count', 5, report.counts.missing_route_candidate_count);
assertEqual('observes private reasoning false', false, report.claim_boundary.observes_private_reasoning);
assertEqual('live agent surveillance false', false, report.claim_boundary.live_agent_surveillance);
assertEqual('creates authority false', false, report.claim_boundary.creates_authority);
assertEqual('agent vote authority false', false, report.claim_boundary.agent_vote_authority);
assertEqual('production governance false', false, report.claim_boundary.production_governance);
assertEqual('external attestation false', false, report.claim_boundary.external_attestation);
assertEqual('public claim upgrade false', false, report.claim_boundary.public_claim_upgrade);
assertEqual('current-machine governance false', false, report.claim_boundary.current_machine_governance);
assertEqual('unrouted surface coverage false', false, report.claim_boundary.unrouted_surface_coverage);
assertEqual('agent outputs are traffic', true, report.invariants.agent_outputs_are_traffic_not_authority);
assertEqual('observe crossings only', true, report.invariants.observe_crossings_not_private_reasoning);
assertEqual(
  'observation may improve maps',
  true,
  report.invariants.observation_may_improve_maps_tests_and_claim_ceilings,
);
assertEqual('observation may not create authority', false, report.invariants.observation_may_create_authority);
assertEqual(
  'passenger behavior may not replace human authority',
  false,
  report.invariants.passenger_behavior_may_replace_human_authority,
);
assertEqual('missing route is not permission', true, report.invariants.missing_route_is_a_learning_signal_not_permission);
assertEqual(
  'observation pipeline text',
  'proposal -> action_class -> route -> authority_topology -> receipt_request -> verifier_result -> effect_or_refusal',
  report.observation_pipeline.primary_observation,
);
assert('action class records.write discovered', report.coverage_learning.action_classes_discovered.includes('records.write'));
assert('action class claim.publish discovered', report.coverage_learning.action_classes_discovered.includes('claim.publish'));
assert('semantic disguise cleanup seen', report.coverage_learning.semantic_disguises_seen.includes('cleanup'));
assertEqual('human proxy pressure seen', true, report.coverage_learning.human_proxy_pressure_seen);
assertEqual('authority laundering seen', true, report.coverage_learning.authority_laundering_seen);
assertEqual('duplicate refusal noise seen', true, report.coverage_learning.duplicate_refusal_noise_seen);
assertEqual(
  'claim ceiling update requires evidence gate',
  true,
  report.coverage_learning.claim_ceiling_update_requires_evidence_gate,
);
assert('missing route candidates present', report.coverage_learning.missing_route_candidates.length >= 5);

const scenarioSha = agentPassengerLabScenarioSetSha256(report);
assert('scenario hash is sha256 hex', /^[a-f0-9]{64}$/.test(scenarioSha));

const formatted = formatAgentPassengerLabReport(report);
assert('formatted report privacy safe', assertNoUnsafeAgentPassengerLabText(formatted));
assert('formatted report names title', formatted.includes('ZLAR Agent Passenger Lab v1'));
assert('formatted report names pipeline', formatted.includes('proposal -> action_class -> route'));
assert('formatted report names invariant', formatted.includes('agent_outputs_are_traffic_not_authority=true'));
assert('formatted report names claim boundary', formatted.includes('creates_authority=false'));
assert('json report privacy safe', assertNoUnsafeAgentPassengerLabText(JSON.stringify(report)));

const liveProbe = clone(report);
liveProbe.live_probing = true;
assertThrows(
  'live probing true fails validation',
  () => assertAgentPassengerLabReport(liveProbe),
  'evidence boundary drifted',
);

const authorityClaim = clone(report);
authorityClaim.claim_boundary.creates_authority = true;
assertThrows(
  'creates authority claim fails validation',
  () => assertAgentPassengerLabReport(authorityClaim),
  'claim boundary creates_authority drifted',
);

const invariantAuthority = clone(report);
invariantAuthority.invariants.observation_may_create_authority = true;
assertThrows(
  'authority invariant true fails validation',
  () => assertAgentPassengerLabReport(invariantAuthority),
  'invariants observation_may_create_authority drifted',
);

const missingScenarioField = clone(report);
delete missingScenarioField.scenarios[0].route;
assertThrows(
  'missing scenario route fails validation',
  () => assertAgentPassengerLabReport(missingScenarioField),
  'scenario builder_records_write_happy_path has unexpected fields',
);

const roleDrift = clone(report);
roleDrift.passenger_roles[0].role_id = 'other_agent';
assertThrows(
  'passenger role drift fails validation',
  () => assertAgentPassengerLabReport(roleDrift),
  'passenger role drifted',
);

const coverageGateDrift = clone(report);
coverageGateDrift.coverage_learning.claim_ceiling_update_requires_evidence_gate = false;
assertThrows(
  'claim ceiling gate false fails validation',
  () => assertAgentPassengerLabReport(coverageGateDrift),
  'coverage learning drifted',
);

const countDrift = clone(report);
countDrift.counts.scenario_count += 1;
assertThrows(
  'count drift fails validation',
  () => assertAgentPassengerLabReport(countDrift),
  'count drifted: scenario_count',
);

assertThrows(
  'credential-shaped output fails safety check',
  () => assertNoUnsafeAgentPassengerLabText('token=abc123'),
  'credential-shaped text',
);

console.log(`\nAgent passenger lab contract tests: ${PASS}/${TOTAL} passed`);
if (FAIL > 0) {
  process.exit(1);
}
