#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import {
  CURRENT_MACHINE_GOVERNANCE_PREVIEW_PROOF_STAGE,
  CURRENT_MACHINE_GOVERNANCE_PREVIEW_RESULT_READY,
  CURRENT_MACHINE_GOVERNANCE_PREVIEW_TYPE,
  assertCurrentMachineGovernancePreviewReport,
  buildCurrentMachineGovernancePreview,
  formatCurrentMachineGovernancePreviewReport,
} from '../lib/current-machine-governance-preview.mjs';

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

function runZlar(args) {
  return spawnSync('bin/zlar', args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|BEGIN [A-Z ]*KEY/i;

console.log('\n-- current-machine governance preview report --');
const report = buildCurrentMachineGovernancePreview();
assert('report validates', assertCurrentMachineGovernancePreviewReport(report));
assertEqual('report type', CURRENT_MACHINE_GOVERNANCE_PREVIEW_TYPE, report.report_type);
assertEqual('result ready no authority', CURRENT_MACHINE_GOVERNANCE_PREVIEW_RESULT_READY, report.result);
assertEqual('evidence surface local no-write', 'local-no-write-source-lane', report.evidence_surface);
assertEqual('proof stage source only no authority', CURRENT_MACHINE_GOVERNANCE_PREVIEW_PROOF_STAGE, report.proof_stage);
assertEqual('action class records.write', 'records.write', report.action_class);
assertEqual('approval request preview prepared', true, report.cross_report_checks.approval_request_preview_prepared);
assertEqual('approval request not made', true, report.cross_report_checks.approval_request_not_made);
assertEqual('named profile rehearsal ready', true, report.cross_report_checks.named_profile_rehearsal_ready);
assertEqual('active persistent source preflight safe', true, report.cross_report_checks.active_persistent_source_preflight_safe);
assertEqual('downstream refusal before effect', true, report.cross_report_checks.downstream_refusal_before_effect);
assertEqual('no install/config/live governance', true, report.cross_report_checks.no_install_config_or_live_governance);
assertEqual('no live or external evidence', true, report.cross_report_checks.no_live_or_external_evidence);
assertEqual('current-machine governance false', false, report.claim_boundary.current_machine_governance);
assertEqual('current-machine governance evidence false', false, report.claim_boundary.current_machine_governance_evidence);
assertEqual('current-machine governance proven false', false, report.claim_boundary.current_machine_governance_proven);
assertEqual('production public authority false', false, report.claim_boundary.production_public_authority);
assertEqual('public release claim false', false, report.claim_boundary.public_release_claim);
assertEqual('deployment readiness claim false', false, report.claim_boundary.deployment_readiness_claim);
assertEqual('source transport proof false', false, report.claim_boundary.source_transport_proof);
assertEqual('next authority request not made', false, report.next_authority_crossing.authority_request_made);
assertEqual('next install authority not granted', false, report.next_authority_crossing.install_authority_granted);
assertEqual('next human authority required', true, report.next_authority_crossing.human_authority_required);
assert('component hash for approval preview present', /^[a-f0-9]{64}$/.test(report.component_hashes.current_machine_approval_request_preview_sha256));
assert('component hash for named readiness present', /^[a-f0-9]{64}$/.test(report.component_hashes.named_deployment_profile_readiness_sha256));
assert('component hash for source status present', /^[a-f0-9]{64}$/.test(report.component_hashes.active_persistent_profile_source_status_sha256));
assert('component hash for source preflight present', /^[a-f0-9]{64}$/.test(report.component_hashes.active_persistent_profile_source_preflight_sha256));
assert('report JSON privacy safe', !unsafeOutputPattern.test(JSON.stringify(report)));

const summary = formatCurrentMachineGovernancePreviewReport(report);
assert('summary title present', summary.includes('ZLAR Current-Machine Governance Preview v1'));
assert('summary says proof stage no authority', summary.includes('proof_stage=source_only_preview_no_authority'));
assert('summary says current-machine false', summary.includes('current_machine_governance=false'));
assert('summary says authority request not made', summary.includes('authority_request_made=false'));
assert('summary names no install/config/live governance', summary.includes('no_install_config_or_live_governance=true'));
assert('summary non-claim says does not install', summary.includes('This preview does not install, activate'));
assert('summary non-claim says does not request authority', summary.includes('This preview does not request or grant install/config authority'));
assert('summary non-claim says does not prove current-machine', summary.includes('current-machine governance'));
assert('summary privacy safe', !unsafeOutputPattern.test(summary));

console.log('\n-- contract failures --');
const governanceClaim = clone(report);
governanceClaim.claim_boundary.current_machine_governance = true;
assertThrows(
  'current-machine governance claim fails',
  () => assertCurrentMachineGovernancePreviewReport(governanceClaim),
  'must be false'
);

const governanceProvenClaim = clone(report);
governanceProvenClaim.claim_boundary.current_machine_governance_proven = true;
assertThrows(
  'current-machine governance proven claim fails',
  () => assertCurrentMachineGovernancePreviewReport(governanceProvenClaim),
  'must be false'
);

const installAuthorityClaim = clone(report);
installAuthorityClaim.claim_boundary.install_authority_granted = true;
assertThrows(
  'install authority claim fails',
  () => assertCurrentMachineGovernancePreviewReport(installAuthorityClaim),
  'must be false'
);

const publicClaim = clone(report);
publicClaim.claim_boundary.public_release_claim = true;
assertThrows(
  'public release claim fails',
  () => assertCurrentMachineGovernancePreviewReport(publicClaim),
  'must be false'
);

const proofStageDrift = clone(report);
proofStageDrift.proof_stage = 'source_only_governance_ready';
assertThrows(
  'proof stage drift fails',
  () => assertCurrentMachineGovernancePreviewReport(proofStageDrift),
  'top-level contract drifted'
);

const requestMade = clone(report);
requestMade.components.current_machine_approval_request_preview.authority_request_made = true;
assertThrows(
  'component authority request made fails',
  () => assertCurrentMachineGovernancePreviewReport(requestMade),
  'must be false'
);

const forgedCheck = clone(report);
forgedCheck.cross_report_checks.no_live_or_external_evidence = false;
assertThrows(
  'forged cross-report check fails',
  () => assertCurrentMachineGovernancePreviewReport(forgedCheck),
  'must be true'
);

const hashDrift = clone(report);
hashDrift.component_hashes.current_machine_approval_request_preview_sha256 =
  '0'.repeat(64);
assertThrows(
  'component hash drift fails',
  () => assertCurrentMachineGovernancePreviewReport(hashDrift),
  'current_machine_approval_request_preview_sha256 drifted'
);

console.log('\n-- cli --');
const jsonRun = runZlar(['current-machine-governance-preview', '--sample', '--json']);
assertEqual('json run exits zero', 0, jsonRun.status);
assertEqual('json run emits no stderr', '', jsonRun.stderr);
assert('json run privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const jsonReport = JSON.parse(jsonRun.stdout);
assert('json report validates', assertCurrentMachineGovernancePreviewReport(jsonReport));
assertEqual('json report proof stage no authority', CURRENT_MACHINE_GOVERNANCE_PREVIEW_PROOF_STAGE, jsonReport.proof_stage);
assertEqual('json report current-machine false', false, jsonReport.claim_boundary.current_machine_governance);

const textRun = runZlar(['current-machine-governance-preview', '--sample']);
assertEqual('text run exits zero', 0, textRun.status);
assertEqual('text run emits no stderr', '', textRun.stderr);
assert('text run title present', textRun.stdout.includes('ZLAR Current-Machine Governance Preview v1'));
assert('text run says proof stage no authority', textRun.stdout.includes('proof_stage=source_only_preview_no_authority'));
assert('text run says no authority request', textRun.stdout.includes('authority_request_made=false'));
assert('text run says current-machine false', textRun.stdout.includes('current_machine_governance=false'));
assert('text run privacy safe', !unsafeOutputPattern.test(textRun.stdout));

const helpRun = runZlar(['current-machine-governance-preview', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assertEqual('help emits no stdout', '', helpRun.stdout);
assert('help names usage', helpRun.stderr.includes('Usage: zlar current-machine-governance-preview --sample [--json]'));
assert('help says does not prove current-machine', helpRun.stderr.includes('does not prove current-machine governance'));

const missingSample = runZlar(['current-machine-governance-preview']);
assert('missing sample exits nonzero', missingSample.status !== 0);
assertEqual('missing sample emits no stdout', '', missingSample.stdout);
assert('missing sample names required sample', missingSample.stderr.includes('--sample is required'));

const unsupported = runZlar(['current-machine-governance-preview', '--sample', '--artifact', 'x.json']);
assert('unsupported option exits nonzero', unsupported.status !== 0);
assertEqual('unsupported option emits no stdout', '', unsupported.stdout);
assert('unsupported option names unsupported', unsupported.stderr.includes('Unsupported current-machine governance preview option provided'));

if (FAIL > 0) {
  console.log(`\nResults: ${PASS}/${TOTAL} passed`);
  console.log(`\nFAIL: ${FAIL}/${TOTAL} assertions failed`);
  process.exit(1);
}

console.log(`\nResults: ${PASS}/${TOTAL} passed`);
console.log(`\nPASS: ${PASS}/${TOTAL} assertions passed`);
