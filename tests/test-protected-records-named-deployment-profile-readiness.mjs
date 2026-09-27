#!/usr/bin/env node
import {
  PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID,
  PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_READINESS_REPORT_TYPE,
  assertProtectedRecordsNamedDeploymentProfileReadiness,
  buildProtectedRecordsNamedDeploymentProfileReadiness,
  formatProtectedRecordsNamedDeploymentProfileReadiness,
} from '../lib/protected-records-named-deployment-profile-readiness.mjs';
import {
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

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

console.log('\n-- named deployment profile readiness --');
const report = buildProtectedRecordsNamedDeploymentProfileReadiness();
assert('report validates', assertProtectedRecordsNamedDeploymentProfileReadiness(report));
assertEqual('report type', PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_READINESS_REPORT_TYPE, report.report_type);
assertEqual('evidence model', 'pinned-committed-terminal-artifact-read-only-rehearsal', report.evidence_model);
assertEqual('source mode', 'pinned-committed-historical-artifact-verification', report.source_terminal_chain.source_mode);
assertEqual('terminal artifact identity matched', true, report.source_terminal_chain.terminal_artifact_identity_sha256_matched);
assertEqual('authority grant exhausted', 'exhausted', report.source_terminal_chain.authority_grant_status);
assertEqual('fresh fixture-rightful projection false', false, report.source_terminal_chain.fresh_fixture_rightful_projection_allowed);
assertEqual('exhaustion reason exact', 'authority_grant_contract_exhausted', report.source_terminal_chain.authority_grant_status_reason_code);
assertEqual('profile id', PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID, report.selected_deployment_profile.profile_id);
assertEqual('profile status', 'rehearsal_not_installed', report.selected_deployment_profile.profile_status);
assertEqual('action class', 'records.write', report.selected_deployment_profile.action_class);
assertEqual('downstream boundary', 'protected-records-runtime-service:local-jsonl-child-process', report.selected_deployment_profile.downstream_boundary);
assertEqual('missing receipt refused', true, report.acceptance_gates.missing_receipt_refused_before_mutation);
assertEqual('unrecognized receipt refused', true, report.acceptance_gates.unrecognized_receipt_refused_before_mutation);
assertEqual('out-of-scope receipt refused', true, report.acceptance_gates.out_of_scope_receipt_refused_before_mutation);
assertEqual('request authority material refused', true, report.acceptance_gates.request_authority_material_refused_before_mutation);
assertEqual('recognized receipt mutates once rehearsed', true, report.acceptance_gates.recognized_receipt_mutates_once_rehearsed);
assertEqual('local rehearsal only', true, report.claim_boundary.local_rehearsal_only);
assertEqual('active deployment profile false', false, report.claim_boundary.active_deployment_profile);
assertEqual('persistent runtime profile installation false', false, report.claim_boundary.persistent_runtime_profile_installation);
assertEqual('current machine governance false', false, report.claim_boundary.current_machine_governance);
assertEqual('production downstream false', false, report.claim_boundary.production_downstream_recognition);
assertEqual('enterprise readiness false', false, report.claim_boundary.enterprise_readiness);
assertEqual('human authority required next', true, report.next_authority_crossing.human_authority_required);
assert('source chain hash present', /^[a-f0-9]{64}$/.test(report.source_terminal_chain.chain_sha256));
assert('service artifact hash present', /^[a-f0-9]{64}$/.test(report.source_terminal_chain.service_artifact_body_sha256));
assert('recognition contract hash present', /^[a-f0-9]{64}$/.test(report.source_terminal_chain.recognition_contract_sha256));

console.log('\n-- summary --');
const summary = formatProtectedRecordsNamedDeploymentProfileReadiness(report);
assert('summary privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(summary));
assert('summary names profile', summary.includes(`profile_id=${PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID}`));
assert('summary names missing receipt refusal', summary.includes('missing_receipt_refused=true'));
assert('summary names unrecognized receipt refusal', summary.includes('unrecognized_receipt_refused=true'));
assert('summary names active deployment false', summary.includes('active_deployment_profile=false'));
assert('summary names next authority crossing', summary.includes('next_authority_crossing=install-config-current-machine-or-equivalent-real-deployment-boundary'));

console.log('\n-- fail closed drift --');
const activeProfile = clone(report);
activeProfile.claim_boundary.active_deployment_profile = true;
assertThrows('active deployment claim fails', () => assertProtectedRecordsNamedDeploymentProfileReadiness(activeProfile), 'active_deployment_profile');

const missingReceiptBoards = clone(report);
missingReceiptBoards.acceptance_gates.missing_receipt_refused_before_mutation = false;
assertThrows('missing receipt refusal drift fails', () => assertProtectedRecordsNamedDeploymentProfileReadiness(missingReceiptBoards), 'acceptance gate');

const productionDownstream = clone(report);
productionDownstream.source_terminal_chain.production_downstream_recognition = true;
assertThrows('production downstream source claim fails', () => assertProtectedRecordsNamedDeploymentProfileReadiness(productionDownstream), 'production_downstream_recognition');

const noHumanCrossing = clone(report);
noHumanCrossing.next_authority_crossing.human_authority_required = false;
assertThrows('human authority crossing drift fails', () => assertProtectedRecordsNamedDeploymentProfileReadiness(noHumanCrossing), 'human required');

console.log(`\nResults: ${PASS}/${TOTAL} passed${FAIL ? `, ${FAIL} failed` : ' ✓'}`);
if (FAIL) {
  process.exit(1);
}
