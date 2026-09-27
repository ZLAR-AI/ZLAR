#!/usr/bin/env node

import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  PRODUCT_PROOF_PATH_REPORT_TYPE,
  assertNoUnsafeProductProofPathText,
  assertProductProofPathReport,
} from '../lib/product-proof-path.mjs';

let PASS = 0;
let FAIL = 0;
let TOTAL = 0;

const RUNTIME_PROFILE_SHA256 =
  'e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469';
const COVERAGE_MAP_FIXTURE_SHA256 =
  '108468719bc1cc13a07abdb88753f1675147de3607118a42565154e6e31e0e77';

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

function clone(value) {
  return JSON.parse(JSON.stringify(value));
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

function runZlar(args) {
  return spawnSync(join(process.cwd(), 'bin', 'zlar'), args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

console.log('\n-- product proof path cli --');

const textRun = runZlar(['product-proof-path']);
assertEqual('text exits zero', 0, textRun.status);
assertEqual('text stderr empty', '', textRun.stderr);
assert('text privacy safe', assertNoUnsafeProductProofPathText(textRun.stdout));
assert('text names command', textRun.stdout.includes('ZLAR Product Proof Path v1'));
assert('text shows acceptance gate', textRun.stdout.includes('Acceptance gate:'));
assert('text shows terminal chain boundary', textRun.stdout.includes('Terminal chain boundary:'));
assert('text shows coverage map contract', textRun.stdout.includes('Coverage map runtime contract:'));
assert('text shows coverage map fixture hash', textRun.stdout.includes(`input_fixture_sha256=${COVERAGE_MAP_FIXTURE_SHA256}`));
assert('text shows exact rightful route', textRun.stdout.includes('mutation_authoritative_route=receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation'));
assert('text shows refusal split', textRun.stdout.includes('recognition_refusal_cases=18/18') && textRun.stdout.includes('authority_refusal_cases=5/5'));
assert('text shows rightful claim ceiling', textRun.stdout.includes('fixture_rightful_issuance_path_evidenced=true') && textRun.stdout.includes('rightful_issuance_proven=false') && textRun.stdout.includes('consequence_lifecycle_closed=false'));
assert('text shows deployment profile authority bridge', textRun.stdout.includes('Deployment profile authority-material refusal bridge:'));
assert('text shows deployment bridge authority refusal', textRun.stdout.includes('agent_supplied_authority_refused_before_mutation=true'));
assert('text shows deployment bridge pre-service refusals', textRun.stdout.includes('deployment_profile_authority_refusals_before_service_proof=true'));
assert('text shows deployment bridge stale artifact refusal', textRun.stdout.includes('stale_deployment_profile_artifact_refused_before_service_proof=true'));
assert('text shows deployment bridge current-machine non-claim', textRun.stdout.includes('current_machine_governance=false'));
assert('text shows terminal chain binding match', textRun.stdout.includes('trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification=true'));
assert('text shows terminal chain group case IDs preserved', textRun.stdout.includes('recognition_refusal_group_case_ids_preserved=true'));
assert('text shows terminal chain stale-or-expired named refusal', textRun.stdout.includes('named_receipt_refusals.stale_or_expired=true'));
assert('text shows proof-pack identity policy', textRun.stdout.includes('proof_pack_runtime_profile_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true; summaries_match=true'));
assert('text shows proof-pack Claude hook replay', textRun.stdout.includes('proof_pack_claude_hook_contract_replay: contract_sha256=') && textRun.stdout.includes('component_sha256=') && textRun.stdout.includes('case_evidence_sha256='));
assert('text shows forbidden external attestation false', textRun.stdout.includes('external_attestation=false'));
assert('text shows non-claims', textRun.stdout.includes('Non-claims:'));

const jsonRun = runZlar(['product-proof-path', '--json']);
assertEqual('json exits zero', 0, jsonRun.status);
assertEqual('json stderr empty', '', jsonRun.stderr);
assert('json privacy safe', assertNoUnsafeProductProofPathText(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report validates', assertProductProofPathReport(report));
assertEqual('json report type', PRODUCT_PROOF_PATH_REPORT_TYPE, report.report_type);
assertEqual('json result', 'PASS', report.result);
assertEqual('json live probing false', false, report.live_probing);
assertEqual('json fresh local proof pack generated', true, report.acceptance_gate.fresh_local_proof_pack_generated);
assertEqual('json terminal chain boundary observed', true, report.acceptance_gate.terminal_chain_boundary_observed);
assertEqual('json terminal chain artifact verified', true, report.acceptance_gate.terminal_chain_artifact_verified);
assertEqual('json deployment profile authority bridge observed', true, report.acceptance_gate.deployment_profile_authority_bridge_observed);
assertEqual('json receipt verification observed', true, report.acceptance_gate.receipt_verification_observed);
assertEqual('json non coverage visible', true, report.acceptance_gate.non_coverage_visible);
assertEqual('json terminal chain verified', true, report.terminal_chain_boundary.verified);
assertEqual('json coverage map contract observed', true, report.acceptance_gate.coverage_map_runtime_contract_observed);
assertEqual('json terminal profile sha', RUNTIME_PROFILE_SHA256, report.terminal_chain_boundary.runtime_profile_sha256);
assertEqual('json terminal recognition refusal count', 18, report.terminal_chain_boundary.required_recognition_refusal_case_count);
assertEqual('json terminal authority refusal count', 5, report.terminal_chain_boundary.required_authority_refusal_case_count);
assertEqual('json terminal signed replay refused', true, report.terminal_chain_boundary.same_process_signed_payload_replay_refused);
assertEqual('json terminal consumed grant replay refused', true, report.terminal_chain_boundary.restart_consumed_authority_grant_refused);
assertEqual('json terminal fixture rightful path evidenced', true, report.terminal_chain_boundary.fixture_rightful_issuance_path_evidenced);
assertEqual('json terminal production rightful false', false, report.terminal_chain_boundary.production_rightful_issuance_proven);
assertEqual('json terminal lifecycle false', false, report.terminal_chain_boundary.consequence_lifecycle_closed);
assertEqual('json terminal joint rollback detection open', false, report.terminal_chain_boundary.store_anchor_and_witness_joint_rollback_detection);
assertEqual('json terminal host path TOCTOU open', false, report.terminal_chain_boundary.host_filesystem_path_toctou_closed);
assertEqual('json coverage map fixture hash', COVERAGE_MAP_FIXTURE_SHA256, report.coverage_map_boundary.input_fixture_sha256);
assertEqual('json coverage map terminal governed', true, report.coverage_map_boundary.surface_governed);
assertEqual('json coverage map profile sha', RUNTIME_PROFILE_SHA256, report.coverage_map_boundary.profile_sha256);
assertEqual('json coverage map no fresh hash equivalence claim', false, report.coverage_map_boundary.artifact_hash_equivalence_with_fresh_run_claimed);
assertEqual(
  'json terminal chain trusted registry binding matches artifact verification',
  true,
  report.terminal_chain_boundary.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification,
);
assertEqual(
  'json terminal chain trusted registry refusal hash matches binding',
  true,
  report.terminal_chain_boundary.trusted_issuer_registry_recognition_refusal_hash_matches_binding,
);
assert('json terminal chain recognized receipt path sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain_boundary.recognized_receipt_path_evidence_sha256));
assertEqual(
  'json terminal chain recognized receipt path sha bound to artifact verification',
  report.terminal_chain_boundary.recognized_receipt_path_evidence_sha256,
  report.terminal_chain_boundary.recognized_receipt_path_evidence_artifact_verification_sha256,
);
assertEqual(
  'json terminal chain recognized receipt path sha match flag',
  true,
  report.terminal_chain_boundary.recognized_receipt_path_evidence_sha256_matches_artifact_verification,
);
assertEqual(
  'json terminal chain recognized receipt path bound to artifact body',
  true,
  report.terminal_chain_boundary.recognized_receipt_path_evidence_bound_to_artifact_body,
);
assertEqual(
  'json terminal chain recognized receipt path source binding equals trusted registry binding',
  report.terminal_chain_boundary.trusted_issuer_registry_recognition_binding_sha256,
  report.terminal_chain_boundary.recognized_receipt_path_evidence_source_binding_sha256,
);
assertEqual(
  'json terminal chain recognized receipt path source binding match flag',
  true,
  report.terminal_chain_boundary.recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding,
);
assertEqual(
  'json terminal chain recognized receipt path verdict',
  'RECOGNIZED',
  report.terminal_chain_boundary.recognized_receipt_path_evidence_verdict,
);
assertEqual(
  'json terminal chain recognized receipt path recognized',
  true,
  report.terminal_chain_boundary.recognized_receipt_path_evidence_recognized,
);
for (const [field, value] of Object.entries(report.terminal_chain_boundary)) {
  if (
    field.startsWith('recognized_receipt_path_evidence_') &&
    (
      field.endsWith('_included') ||
      field.endsWith('_reproducible') ||
      field.endsWith('_proven') ||
      field.endsWith('_attestation') ||
      field.endsWith('_recognition')
    )
  ) {
    assertEqual(`json terminal chain ${field} false`, false, value);
  }
}
assertEqual('json terminal chain recognition refusal group count', 3, report.terminal_chain_boundary.recognition_refusal_group_count);
assertEqual('json terminal chain recognition refusal group case count', 18, report.terminal_chain_boundary.recognition_refusal_group_case_count);
assertEqual(
  'json terminal chain recognition refusal group case IDs preserved',
  true,
  report.terminal_chain_boundary.recognition_refusal_group_case_ids_preserved,
);
assertEqual(
  'json terminal chain stale-or-expired named refusal',
  true,
  report.terminal_chain_boundary.named_receipt_refusals.stale_or_expired.refused_before_mutation,
);
assertEqual(
  'json terminal chain stale-or-expired named refusal reason',
  'receipt_stale',
  report.terminal_chain_boundary.named_receipt_refusals.stale_or_expired.reason_code,
);
assertEqual('json terminal chain public key omitted', false, report.terminal_chain_boundary.registry_public_key_material_included);
assertEqual('json terminal chain no external attestation', false, report.terminal_chain_boundary.external_attestation);
assertEqual('json deployment bridge explicit id+sha', true, report.deployment_profile_authority_bridge.selected_by_explicit_id_and_sha);
assertEqual('json deployment bridge no latest', false, report.deployment_profile_authority_bridge.selects_latest_profile);
assertEqual('json deployment bridge preflight verified', true, report.deployment_profile_authority_bridge.preflight_artifact_verified);
assertEqual('json deployment bridge recognized once', true, report.deployment_profile_authority_bridge.recognized_receipt_mutates_once);
assertEqual('json deployment bridge authority refusals before service proof', true, report.deployment_profile_authority_bridge.deployment_profile_authority_refusals_before_service_proof);
assertEqual('json deployment bridge stale artifact refused before service proof', true, report.deployment_profile_authority_bridge.stale_deployment_profile_artifact_refused_before_service_proof);
assertEqual('json deployment bridge profile mismatch refused before service proof', true, report.deployment_profile_authority_bridge.profile_recognition_mismatch_refused_before_service_proof);
assertEqual('json deployment bridge all refusals before mutation', true, report.deployment_profile_authority_bridge.all_required_refusals_before_mutation);
assertEqual('json deployment bridge agent authority refused', true, report.deployment_profile_authority_bridge.agent_supplied_authority_refused_before_mutation);
assertEqual('json deployment bridge current-machine false', false, report.deployment_profile_authority_bridge.current_machine_governance);
assertEqual('json deployment bridge production false', false, report.deployment_profile_authority_bridge.production_downstream_recognition);
assertEqual('json proof-pack identity authority source', 'launcher-owned-service-config', report.proof_pack.runtime_profile_identity_policy.authority_source);
assertEqual('json proof-pack omitted runtime profile id uses launcher config', true, report.proof_pack.runtime_profile_identity_policy.omitted_runtime_profile_id_uses_launcher_config);
assertEqual('json proof-pack supplied mismatched runtime profile id refused', true, report.proof_pack.runtime_profile_identity_policy.supplied_mismatched_runtime_profile_id_refused);
assertEqual('json proof-pack identity summaries match', true, report.proof_pack.runtime_profile_identity_policy.summaries_match);
assert('json proof-pack Claude hook replay contract hash present', /^[a-f0-9]{64}$/.test(report.proof_pack.claude_hook_contract_replay.hook_replay_contract_sha256));
assert('json proof-pack Claude hook replay adapter hash present', /^[a-f0-9]{64}$/.test(report.proof_pack.claude_hook_contract_replay.adapter_sha256));
assert('json proof-pack Claude hook replay component hash present', /^[a-f0-9]{64}$/.test(report.proof_pack.claude_hook_contract_replay.component_sha256));
assert('json proof-pack Claude hook replay case evidence hash present', /^[a-f0-9]{64}$/.test(report.proof_pack.claude_hook_contract_replay.case_evidence_sha256));
assertEqual('json external attestation false', false, report.forbidden_claims.external_attestation);
assertEqual('json current machine governance false', false, report.forbidden_claims.current_machine_governance);

const missingReceiptPathMirror = clone(report);
delete missingReceiptPathMirror.terminal_chain_boundary.recognized_receipt_path_evidence_sha256;
assertThrows(
  'missing recognized receipt path mirror field fails product proof validation',
  () => assertProductProofPathReport(missingReceiptPathMirror),
  'Product proof path terminal chain boundary has unexpected fields',
);

const extraReceiptPathMirror = clone(report);
extraReceiptPathMirror.terminal_chain_boundary.recognized_receipt_path_evidence_summary = {
  verdict: 'RECOGNIZED',
};
assertThrows(
  'extra recognized receipt path summary field fails product proof validation',
  () => assertProductProofPathReport(extraReceiptPathMirror),
  'Product proof path terminal chain boundary has unexpected fields',
);

const renamedReceiptPathMirror = clone(report);
renamedReceiptPathMirror.terminal_chain_boundary.recognized_receipt_path_evidence_hash =
  renamedReceiptPathMirror.terminal_chain_boundary.recognized_receipt_path_evidence_sha256;
delete renamedReceiptPathMirror.terminal_chain_boundary.recognized_receipt_path_evidence_sha256;
assertThrows(
  'renamed recognized receipt path mirror field fails product proof validation',
  () => assertProductProofPathReport(renamedReceiptPathMirror),
  'Product proof path terminal chain boundary has unexpected fields',
);

const summaryShapedReceiptPathMirror = clone(report);
summaryShapedReceiptPathMirror.terminal_chain_boundary.recognized_receipt_path_evidence_sha256 = {
  sha256: report.terminal_chain_boundary.recognized_receipt_path_evidence_sha256,
};
assertThrows(
  'summary-shaped recognized receipt path mirror field fails product proof validation',
  () => assertProductProofPathReport(summaryShapedReceiptPathMirror),
  'Product proof path terminal chain boundary drifted',
);

const tamperedReceiptPathSha = clone(report);
tamperedReceiptPathSha.terminal_chain_boundary.recognized_receipt_path_evidence_sha256 =
  '0'.repeat(64);
assertThrows(
  'tampered recognized receipt path evidence sha fails product proof validation',
  () => assertProductProofPathReport(tamperedReceiptPathSha),
  'Product proof path terminal chain boundary drifted',
);

const mismatchedReceiptPathSourceBinding = clone(report);
mismatchedReceiptPathSourceBinding.terminal_chain_boundary.recognized_receipt_path_evidence_source_binding_sha256 =
  '1'.repeat(64);
assertThrows(
  'recognized receipt path source-binding mismatch fails product proof validation',
  () => assertProductProofPathReport(mismatchedReceiptPathSourceBinding),
  'Product proof path terminal chain boundary drifted',
);

const receiptPathFalseBoundaryFlip = clone(report);
receiptPathFalseBoundaryFlip.terminal_chain_boundary.recognized_receipt_path_evidence_public_external_attestation = true;
assertThrows(
  'recognized receipt path false-boundary flip fails product proof validation',
  () => assertProductProofPathReport(receiptPathFalseBoundaryFlip),
  'Product proof path terminal chain boundary drifted',
);

const scratch = mkdtempSync(join(tmpdir(), 'zlar-product-proof-path-cli-'));
try {
  const jsonOut = join(scratch, 'product-proof-path.json');
  const jsonOutRun = runZlar(['product-proof-path', '--json-out', jsonOut]);
  assertEqual('json-out exits zero', 0, jsonOutRun.status);
  assertEqual('json-out stdout empty', '', jsonOutRun.stdout);
  assertEqual('json-out stderr empty', '', jsonOutRun.stderr);
  const outReport = JSON.parse(readFileSync(jsonOut, 'utf8'));
  assert('json-out report validates', assertProductProofPathReport(outReport));

  const overwriteRun = runZlar(['product-proof-path', '--json-out', jsonOut]);
  assertEqual('json-out refuses overwrite', 1, overwriteRun.status);
  assert('json-out overwrite names refusal', overwriteRun.stderr.includes('Refusing to overwrite'));
  assert('json-out overwrite stderr privacy safe', assertNoUnsafeProductProofPathText(overwriteRun.stderr));
  assert('json-out overwrite does not leak output path', !overwriteRun.stderr.includes(jsonOut));
  assert('json-out overwrite does not leak scratch path', !overwriteRun.stderr.includes(scratch));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

const helpRun = runZlar(['product-proof-path', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assert('help names usage', helpRun.stderr.includes('Usage: zlar product-proof-path [--json|--json-out <file>]'));
assert('help names non-claim', helpRun.stderr.includes('does not live probe'));

const conflictRun = runZlar(['product-proof-path', '--json', '--json-out', 'unused.json']);
assertEqual('json/json-out conflict exits two', 2, conflictRun.status);

const unsupportedRun = runZlar(['product-proof-path', '--latest']);
assertEqual('unsupported option exits two', 2, unsupportedRun.status);

const mainHelp = runZlar(['help']);
assertEqual('main help exits zero', 0, mainHelp.status);
assert('main help lists product proof path', mainHelp.stdout.includes('product-proof-path'));

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed${FAIL ? ` (${FAIL} FAILED)` : ' ✓'}`);
if (FAIL > 0) process.exit(1);
