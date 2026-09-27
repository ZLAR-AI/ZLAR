#!/usr/bin/env node

import {
  PRODUCT_PROOF_PATH_CLAIM_BOUNDARY,
  PRODUCT_PROOF_PATH_EVIDENCE_MODEL,
  PRODUCT_PROOF_PATH_NON_CLAIMS,
  PRODUCT_PROOF_PATH_REPORT_TYPE,
  PRODUCT_PROOF_PATH_SCHEMA_VERSION,
  assertNoUnsafeProductProofPathText,
  assertProductProofPathReport,
  buildProductProofPathReport,
  formatProductProofPathReport,
} from '../lib/product-proof-path.mjs';
import {
  buildLocalProofPackArtifact,
  runLocalProofPack,
  verifyLocalProofPackArtifact,
} from '../lib/local-proof-pack.mjs';
import {
  REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES,
} from '../lib/protected-records-one-terminal-deployment-profile.mjs';
import {
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS,
} from '../lib/protected-records-installed-runtime-profile-terminal-chain.mjs';
import {
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY,
} from '../lib/claude-code-hook-contract-replay-proof.mjs';

let PASS = 0;
let FAIL = 0;
let TOTAL = 0;

const RUNTIME_PROFILE_SHA256 =
  'e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469';
const COVERAGE_MAP_FIXTURE_SHA256 =
  '108468719bc1cc13a07abdb88753f1675147de3607118a42565154e6e31e0e77';
const COMMITTED_TERMINAL_ARTIFACT_BODY_SHA256 =
  '49eb293e730cccf8a67e53c6f792066645fb25f7b5ab184d2c2031e54f87d18d';
const COMMITTED_PREFLIGHT_ARTIFACT_BODY_SHA256 =
  '2b5427aec78c63cc9768bb25ed8cdde316d4b8e3f07dac11c80baa54e1b71bec';
const COMMITTED_SERVICE_ARTIFACT_BODY_SHA256 =
  'b32c35576bcd859ddd548d91bcb2029046dbcfc0b24c6cb8e7f70f2966ac8294';
const EXACT_RUNTIME_ROUTE =
  'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation';

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

function rejectsProductProofPathReport(label, candidate, messagePart) {
  assert(label, (() => {
    try {
      assertProductProofPathReport(candidate);
      return false;
    } catch (err) {
      return err.message.includes(messagePart);
    }
  })());
}

console.log('\n-- product proof path report --');

const report = buildProductProofPathReport();
const expectedTrustedIssuerRegistryRefusalCaseIds = [
  'unrecognized_terminal_chain_registry_scope_refused',
  'registry_receipt_contract_mismatch_refused',
];
const expectedTrustedIssuerRegistryRefusalReasonCodes = [
  'scope_not_found',
  'detail_hash_mismatch',
];
const expectedRecognitionRefusalGroupCaseIds = {
  no_usable_recognized_receipt_authority: [
    'missing_receipt_refused_before_runtime_mutation',
    'invalid_receipt_refused_before_runtime_mutation',
    'unknown_issuer_refused_before_runtime_mutation',
    'retired_issuer_refused_before_runtime_mutation',
    'missing_issuer_status_refused_before_runtime_mutation',
    'stale_receipt_refused_before_runtime_mutation',
  ],
  recognized_receipt_scope_mismatch: [
    'wrong_policy_refused_before_runtime_mutation',
    'wrong_domain_refused_before_runtime_mutation',
    'wrong_tool_refused_before_runtime_mutation',
    'wrong_audit_event_refused_before_runtime_mutation',
    'wrong_detail_refused_before_runtime_mutation',
    'non_boarding_outcome_refused_before_runtime_mutation',
  ],
  route_or_request_authority_material_refused: [
    'wrong_runtime_profile_id_refused_before_runtime_mutation',
    'direct_api_without_receipt_refused_before_runtime_mutation',
    'direct_api_with_receipt_refused_before_runtime_mutation',
    'agent_supplied_recognition_rule_refused_before_runtime_mutation',
    'agent_supplied_fixture_mode_refused_before_runtime_mutation',
    'unsupported_request_field_refused_before_runtime_mutation',
  ],
};
const expectedDownstreamRefusalReasons = [
  'receipt_missing',
  'receipt_invalid',
  'issuer_not_active',
  'unknown_issuer',
  'outcome_not_boarding',
  'policy_not_recognized',
  'domain_out_of_scope',
  'tool_out_of_scope',
  'audit_event_mismatch',
  'detail_hash_mismatch',
  'receipt_stale',
];

assert('report validates', assertProductProofPathReport(report));
assertEqual('report type', PRODUCT_PROOF_PATH_REPORT_TYPE, report.report_type);
assertEqual('schema version', PRODUCT_PROOF_PATH_SCHEMA_VERSION, report.schema_version);
assertEqual('result', 'PASS', report.result);
assertEqual('north star piece', 'Product Proof Path', report.north_star_piece);
assertEqual('evidence model', PRODUCT_PROOF_PATH_EVIDENCE_MODEL, report.evidence_model);
assertEqual('live probing false', false, report.live_probing);
assertEqual('private operator state not required', false, report.private_operator_state_required);
assertEqual('claim boundary', PRODUCT_PROOF_PATH_CLAIM_BOUNDARY, report.claim_boundary);
assert('proof pack sha present', /^[a-f0-9]{64}$/.test(report.proof_pack.body_sha256));
assertEqual('proof pack verified', true, report.proof_pack.verified);
assertEqual('proof pack live probing false', false, report.proof_pack.live_probing);
assertEqual('proof pack component count', 16, report.proof_pack.component_count);
assertEqual('proof pack identity authority source', 'launcher-owned-service-config', report.proof_pack.runtime_profile_identity_policy.authority_source);
assertEqual('proof pack identity request stream policy', 'runtime_profile_id_may_be_omitted_but_if_supplied_must_match_config', report.proof_pack.runtime_profile_identity_policy.request_stream_policy);
assertEqual('proof pack request runtime profile id not required', false, report.proof_pack.runtime_profile_identity_policy.request_runtime_profile_id_required);
assertEqual('proof pack omitted runtime profile id field absent', false, report.proof_pack.runtime_profile_identity_policy.omitted_request_runtime_profile_id_present);
assertEqual('proof pack omitted runtime profile id uses launcher config', true, report.proof_pack.runtime_profile_identity_policy.omitted_runtime_profile_id_uses_launcher_config);
assertEqual('proof pack supplied mismatched runtime profile id refused', true, report.proof_pack.runtime_profile_identity_policy.supplied_mismatched_runtime_profile_id_refused);
assertEqual('proof pack local activation identity summary bound', true, report.proof_pack.runtime_profile_identity_policy.runtime_local_activation_summary_bound);
assertEqual('proof pack profile installation identity summary bound', true, report.proof_pack.runtime_profile_identity_policy.runtime_profile_installation_summary_bound);
assertEqual('proof pack identity summaries match', true, report.proof_pack.runtime_profile_identity_policy.summaries_match);
assert('proof pack Claude hook replay contract hash present', /^[a-f0-9]{64}$/.test(report.proof_pack.claude_hook_contract_replay.hook_replay_contract_sha256));
assert('proof pack Claude hook replay adapter hash present', /^[a-f0-9]{64}$/.test(report.proof_pack.claude_hook_contract_replay.adapter_sha256));
assert('proof pack Claude hook replay component hash present', /^[a-f0-9]{64}$/.test(report.proof_pack.claude_hook_contract_replay.component_sha256));
assert('proof pack Claude hook replay case evidence hash present', /^[a-f0-9]{64}$/.test(report.proof_pack.claude_hook_contract_replay.case_evidence_sha256));
assertEqual(
  'proof pack Claude hook replay source boundary exact',
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY,
  report.proof_pack.claude_hook_contract_replay.source_state_boundary,
);

assertEqual('terminal chain boundary observed', true, report.acceptance_gate.terminal_chain_boundary_observed);
assertEqual('terminal chain artifact verified gate', true, report.acceptance_gate.terminal_chain_artifact_verified);
assertEqual('fresh terminal chain generated gate', true, report.acceptance_gate.fresh_terminal_chain_generated);
assertEqual('terminal chain verified', true, report.terminal_chain_boundary.verified);
assertEqual('terminal chain live probing false', false, report.terminal_chain_boundary.live_probing);
assertEqual(
  'terminal chain payload type',
  'zlar-protected-records-installed-runtime-profile-terminal-chain-v1',
  report.terminal_chain_boundary.payload_type,
);
assert('terminal chain body sha present', /^[a-f0-9]{64}$/.test(report.terminal_chain_boundary.body_sha256));
assertEqual('terminal chain runtime profile sha', RUNTIME_PROFILE_SHA256, report.terminal_chain_boundary.runtime_profile_sha256);
assert('terminal chain recognition contract sha present', /^[a-f0-9]{64}$/.test(report.terminal_chain_boundary.recognition_contract_sha256));
assert('terminal chain recognition refusal taxonomy sha present', /^[a-f0-9]{64}$/.test(report.terminal_chain_boundary.recognition_refusal_taxonomy_sha256));
assert('terminal chain authority refusal taxonomy sha present', /^[a-f0-9]{64}$/.test(report.terminal_chain_boundary.authority_refusal_taxonomy_sha256));
assert('terminal chain named refusal sha present', /^[a-f0-9]{64}$/.test(report.terminal_chain_boundary.named_receipt_refusals_sha256));
for (const [name, expected] of Object.entries(
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS,
)) {
  assertEqual(`terminal chain named refusal ${name} case`, expected.case_id, report.terminal_chain_boundary.named_receipt_refusals[name].case_id);
  assertEqual(`terminal chain named refusal ${name} reason`, expected.reason_code, report.terminal_chain_boundary.named_receipt_refusals[name].reason_code);
  assertEqual(`terminal chain named refusal ${name} before mutation`, true, report.terminal_chain_boundary.named_receipt_refusals[name].refused_before_mutation);
}
assert('terminal chain recognition refusal groups sha present', /^[a-f0-9]{64}$/.test(report.terminal_chain_boundary.recognition_refusal_groups_sha256));
assertEqual('terminal chain recognition refusal group count', 3, report.terminal_chain_boundary.recognition_refusal_group_count);
assertEqual('terminal chain recognition refusal group case count', 18, report.terminal_chain_boundary.recognition_refusal_group_case_count);
assertEqual('terminal chain recognition refusal group case IDs preserved', true, report.terminal_chain_boundary.recognition_refusal_group_case_ids_preserved);
assertEqual(
  'terminal chain recognition refusal group case IDs',
  JSON.stringify(expectedRecognitionRefusalGroupCaseIds),
  JSON.stringify(report.terminal_chain_boundary.recognition_refusal_group_case_ids),
);
assertEqual('terminal chain generated root preflighted', true, report.terminal_chain_boundary.generated_installed_root_preflighted);
assertEqual('terminal chain generated preflight consumed', true, report.terminal_chain_boundary.generated_preflight_artifact_consumed_by_service_proof);
assertEqual('terminal chain generated service proof artifact verified', true, report.terminal_chain_boundary.generated_service_proof_artifact_verified);
assertEqual('terminal chain service proof bound', true, report.terminal_chain_boundary.service_proof_bound_to_generated_preflight);
assertEqual('terminal chain service artifact bound', true, report.terminal_chain_boundary.service_artifact_verification_bound_to_service_proof);
assertEqual('terminal chain recognized write boarded', true, report.terminal_chain_boundary.recognized_write_boarded);
assertEqual('terminal chain missing receipt refused', true, report.terminal_chain_boundary.missing_receipt_refused_before_mutation);
assertEqual('terminal chain invalid receipt refused', true, report.terminal_chain_boundary.invalid_receipt_refused_before_mutation);
assertEqual('terminal chain exact route', EXACT_RUNTIME_ROUTE, report.terminal_chain_boundary.mutation_authoritative_route);
assertEqual('terminal chain grant store identity', 'persistent-single-use-authority-grant-contract-sha256-store', report.terminal_chain_boundary.consumed_authority_grant_store);
assertEqual('terminal chain grant consumption identity', 'authority-grant-contract-sha256', report.terminal_chain_boundary.consumption_identity);
assertEqual('terminal chain signed-payload replay identity', 'verified-signed-payload-sha256', report.terminal_chain_boundary.signed_payload_replay_identity);
assertEqual('terminal chain witness source', 'launcher-owned-local-proof-witness', report.terminal_chain_boundary.consumed_grant_store_witness_source);
assertEqual('terminal chain all recognition refusals', true, report.terminal_chain_boundary.all_required_recognition_refusals_before_mutation);
assertEqual('terminal chain required recognition refusal count', 18, report.terminal_chain_boundary.required_recognition_refusal_case_count);
assertEqual('terminal chain observed recognition refusal count', 18, report.terminal_chain_boundary.observed_recognition_refusal_case_count);
assertEqual('terminal chain all authority refusals', true, report.terminal_chain_boundary.all_required_authority_refusals_before_consumption_and_mutation);
assertEqual('terminal chain required authority refusal count', 5, report.terminal_chain_boundary.required_authority_refusal_case_count);
assertEqual('terminal chain observed authority refusal count', 5, report.terminal_chain_boundary.observed_authority_refusal_case_count);
assertEqual('terminal chain same-process signed replay refused', true, report.terminal_chain_boundary.same_process_signed_payload_replay_refused);
assertEqual('terminal chain restart consumed-grant replay refused', true, report.terminal_chain_boundary.restart_consumed_authority_grant_refused);
assertEqual('terminal chain fixture rightful path evidenced', true, report.terminal_chain_boundary.fixture_rightful_issuance_path_evidenced);
assertEqual('terminal chain rightful issuance generic false', false, report.terminal_chain_boundary.rightful_issuance_proven);
assertEqual('terminal chain portable rightful false', false, report.terminal_chain_boundary.portable_rightful_issuance_proven);
assertEqual('terminal chain production rightful false', false, report.terminal_chain_boundary.production_rightful_issuance_proven);
assertEqual('terminal chain live authority false', false, report.terminal_chain_boundary.live_authority_proven);
assertEqual('terminal chain lifecycle closure false', false, report.terminal_chain_boundary.consequence_lifecycle_closed);
assertEqual('terminal chain rightful authority domain', 'protected-records.local-disposable-fixture', report.terminal_chain_boundary.public_safe_grant_summary.authority_domain_id);
assertEqual('terminal chain rightful grantor role', 'fixture-consequence-authority', report.terminal_chain_boundary.public_safe_grant_summary.grantor_role_id);
assert('terminal chain rightful grant summary hash present', /^[a-f0-9]{64}$/.test(report.terminal_chain_boundary.public_safe_grant_summary_sha256));
assertEqual('terminal chain state-append burn observed', true, report.terminal_chain_boundary.state_append_after_grant_commit_burn_observed);
assertEqual('terminal chain metadata burn observed', true, report.terminal_chain_boundary.metadata_partial_commit_burn_observed);
assertEqual('terminal chain witness-ahead rollback refused', true, report.terminal_chain_boundary.store_and_anchor_rollback_refused_while_witness_ahead);
assertEqual('terminal chain joint rollback detection open', false, report.terminal_chain_boundary.store_anchor_and_witness_joint_rollback_detection);
assertEqual('terminal chain joint rollback reopens reuse', true, report.terminal_chain_boundary.joint_rollback_reopened_authority_grant_reuse);
assertEqual('terminal chain host path TOCTOU open', false, report.terminal_chain_boundary.host_filesystem_path_toctou_closed);
assert('terminal chain trusted registry binding sha present', /^[a-f0-9]{64}$/.test(report.terminal_chain_boundary.trusted_issuer_registry_recognition_binding_sha256));
assertEqual(
  'terminal chain trusted registry binding hash matches verification',
  true,
  report.terminal_chain_boundary.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification,
);
assertEqual('terminal chain trusted registry verdict', 'RECOGNIZED', report.terminal_chain_boundary.trusted_issuer_registry_recognition_verdict);
assertEqual('terminal chain trusted registry recognized', true, report.terminal_chain_boundary.trusted_issuer_registry_recognition_recognized);
assertEqual('terminal chain trusted registry decision', 'accept', report.terminal_chain_boundary.trusted_issuer_registry_recognition_decision);
assertEqual('terminal chain trusted registry reason', 'recognized', report.terminal_chain_boundary.trusted_issuer_registry_recognition_reason_code);
assertEqual('terminal chain trusted registry issuer active', 'active', report.terminal_chain_boundary.trusted_issuer_registry_recognition_issuer_status);
assertEqual('terminal chain trusted registry signature valid', true, report.terminal_chain_boundary.trusted_issuer_registry_recognition_signature_valid);
assertEqual('terminal chain trusted registry fixture validated', true, report.terminal_chain_boundary.trusted_issuer_registry_recognition_registry_fixture_validated);
assertEqual('terminal chain trusted registry fixture evaluated', true, report.terminal_chain_boundary.trusted_issuer_registry_recognition_registry_fixture_evaluated);
assertEqual('terminal chain trusted registry rule evaluated', true, report.terminal_chain_boundary.trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated);
assertEqual('terminal chain trusted registry evaluator type', 'downstream-recognition-rule-v1', report.terminal_chain_boundary.trusted_issuer_registry_recognition_registry_evaluation_result_type);
assertEqual('terminal chain trusted registry issuer count', 1, report.terminal_chain_boundary.trusted_issuer_registry_recognition_registry_trusted_issuer_count);
assertEqual('terminal chain trusted registry audit bound', true, report.terminal_chain_boundary.trusted_issuer_registry_recognition_required_audit_event_id_bound);
assertEqual('terminal chain trusted registry detail bound', true, report.terminal_chain_boundary.trusted_issuer_registry_recognition_required_detail_hash_bound);
assert('terminal chain trusted registry fixture contract sha present', /^[a-f0-9]{64}$/.test(report.terminal_chain_boundary.trusted_issuer_registry_recognition_registry_fixture_contract_sha256));
assertEqual('terminal chain trusted registry contract evidence', 'no-secret-registry-contract-v2', report.terminal_chain_boundary.trusted_issuer_registry_recognition_registry_contract_evidence);
assert('terminal chain trusted registry public-safe summary sha present', /^[a-f0-9]{64}$/.test(report.terminal_chain_boundary.trusted_issuer_registry_recognition_registry_public_safe_summary_sha256));
assert('terminal chain trusted registry receipt contract sha present', /^[a-f0-9]{64}$/.test(report.terminal_chain_boundary.trusted_issuer_registry_recognition_receipt_payload_contract_sha256));
assert('terminal chain trusted registry refusal sha present', /^[a-f0-9]{64}$/.test(report.terminal_chain_boundary.trusted_issuer_registry_recognition_refusals_sha256));
assertEqual(
  'terminal chain trusted registry refusal hash matches binding',
  true,
  report.terminal_chain_boundary.trusted_issuer_registry_recognition_refusal_hash_matches_binding,
);
assertEqual('terminal chain trusted registry refusal count', 2, report.terminal_chain_boundary.trusted_issuer_registry_recognition_refusal_case_count);
assertEqual('terminal chain trusted registry refusals all refused', true, report.terminal_chain_boundary.trusted_issuer_registry_recognition_refusals_all_refused);
assertEqual(
  'terminal chain trusted registry refusal case IDs',
  JSON.stringify(expectedTrustedIssuerRegistryRefusalCaseIds),
  JSON.stringify(report.terminal_chain_boundary.trusted_issuer_registry_recognition_refusal_case_ids),
);
assertEqual(
  'terminal chain trusted registry refusal reason codes',
  JSON.stringify(expectedTrustedIssuerRegistryRefusalReasonCodes),
  JSON.stringify(report.terminal_chain_boundary.trusted_issuer_registry_recognition_refusal_reason_codes),
);
assertEqual('terminal chain registry receipt contract bound', true, report.terminal_chain_boundary.registry_receipt_contract_hash_bound);
assertEqual('terminal chain selected profile bound', true, report.terminal_chain_boundary.selected_profile_hash_bound);
assertEqual('terminal chain recognition contract bound', true, report.terminal_chain_boundary.recognition_contract_hash_bound);
assertEqual('terminal chain decision bound', true, report.terminal_chain_boundary.terminal_chain_decision_bound);
assertEqual('terminal chain nested preflight hash bound', true, report.terminal_chain_boundary.nested_artifact_binding.preflight_artifact_hash_bound);
assertEqual('terminal chain nested service hash bound', true, report.terminal_chain_boundary.nested_artifact_binding.service_artifact_hash_bound);
assertEqual('terminal chain nested no public attestation', false, report.terminal_chain_boundary.nested_artifact_binding.creates_public_external_attestation);
assertEqual('terminal chain nested no current-machine governance', false, report.terminal_chain_boundary.nested_artifact_binding.proves_current_machine_governance);
assertEqual('terminal chain public key omitted', false, report.terminal_chain_boundary.registry_public_key_material_included);
assertEqual('terminal chain receipt envelope omitted', false, report.terminal_chain_boundary.receipt_envelope_included);
assertEqual('terminal chain no artifact-only crypto reconstruction', false, report.terminal_chain_boundary.cryptographic_evidence_reproducible_from_artifact);
assertEqual('terminal chain no persistent install', false, report.terminal_chain_boundary.persistent_runtime_profile_installed);
assertEqual('terminal chain no activation', false, report.terminal_chain_boundary.runtime_profile_activation_performed);
assertEqual('terminal chain no hook config', false, report.terminal_chain_boundary.hook_configuration_written);
assertEqual('terminal chain no user config', false, report.terminal_chain_boundary.user_configuration_written);
assertEqual('terminal chain no machine config', false, report.terminal_chain_boundary.machine_configuration_written);
assertEqual('terminal chain no current-machine governance', false, report.terminal_chain_boundary.current_machine_governance_proven);
assertEqual('terminal chain no production service checked', false, report.terminal_chain_boundary.production_records_service_checked);
assertEqual('terminal chain no production downstream recognition', false, report.terminal_chain_boundary.production_downstream_recognition);
assertEqual('terminal chain no external attestation', false, report.terminal_chain_boundary.external_attestation);
assertEqual('terminal chain no sovereign recognition', false, report.terminal_chain_boundary.sovereign_recognition);
assertEqual('terminal chain no unrouted records coverage', false, report.terminal_chain_boundary.unrouted_records_paths_checked);
assertEqual('terminal chain trusted registry no live state', false, report.terminal_chain_boundary.trusted_issuer_registry_live_state_proven);
assertEqual('terminal chain trusted registry no live issuer status', false, report.terminal_chain_boundary.trusted_issuer_registry_live_issuer_status_proven);
assertEqual('terminal chain trusted registry no key custody', false, report.terminal_chain_boundary.trusted_issuer_registry_key_custody_proven);
assertEqual('terminal chain trusted registry no revocation truth', false, report.terminal_chain_boundary.trusted_issuer_registry_revocation_truth_proven);
assertEqual('terminal chain trusted registry no production authority', false, report.terminal_chain_boundary.trusted_issuer_registry_production_authority);
assertEqual('terminal chain trusted registry no public attestation', false, report.terminal_chain_boundary.trusted_issuer_registry_public_external_attestation);
assertEqual('terminal chain trusted registry no real non-operator review', false, report.terminal_chain_boundary.trusted_issuer_registry_real_non_operator_review);

assertEqual('coverage map contract gate observed', true, report.acceptance_gate.coverage_map_runtime_contract_observed);
assertEqual('coverage map report type', 'governed-surface-coverage-map-v1', report.coverage_map_boundary.report_type);
assertEqual('coverage map fixture hash', COVERAGE_MAP_FIXTURE_SHA256, report.coverage_map_boundary.input_fixture_sha256);
assertEqual('coverage map governed lanes', 6, report.coverage_map_boundary.governed_lanes);
assertEqual('coverage map counted lanes', 6, report.coverage_map_boundary.counted_lanes);
assertEqual('coverage map terminal surface governed', true, report.coverage_map_boundary.surface_governed);
assertEqual('coverage map profile sha', RUNTIME_PROFILE_SHA256, report.coverage_map_boundary.profile_sha256);
assertEqual('coverage map exact route', EXACT_RUNTIME_ROUTE, report.coverage_map_boundary.mutation_authoritative_route);
assertEqual('coverage map recognition refusal count', 18, report.coverage_map_boundary.recognition_refusal_case_count);
assertEqual('coverage map authority refusal count', 5, report.coverage_map_boundary.authority_refusal_case_count);
assertEqual('coverage map fixture rightful path evidenced', true, report.coverage_map_boundary.fixture_rightful_issuance_path_evidenced);
assertEqual('coverage map generic rightful false', false, report.coverage_map_boundary.rightful_issuance_proven);
assertEqual('coverage map production rightful false', false, report.coverage_map_boundary.production_rightful_issuance_proven);
assertEqual('coverage map live authority false', false, report.coverage_map_boundary.live_authority_proven);
assertEqual('coverage map current-machine false', false, report.coverage_map_boundary.current_machine_governance_proven);
assertEqual('coverage map lifecycle closure false', false, report.coverage_map_boundary.consequence_lifecycle_closed);
assertEqual('coverage map committed terminal body hash', COMMITTED_TERMINAL_ARTIFACT_BODY_SHA256, report.coverage_map_boundary.terminal_chain_artifact_body_sha256);
assertEqual('coverage map committed preflight body hash', COMMITTED_PREFLIGHT_ARTIFACT_BODY_SHA256, report.coverage_map_boundary.nested_preflight_artifact_body_sha256);
assertEqual('coverage map committed service body hash', COMMITTED_SERVICE_ARTIFACT_BODY_SHA256, report.coverage_map_boundary.nested_service_proof_artifact_body_sha256);
assertEqual('coverage map does not claim fresh artifact hash equivalence', false, report.coverage_map_boundary.artifact_hash_equivalence_with_fresh_run_claimed);

assertEqual(
  'deployment profile authority bridge gate observed',
  true,
  report.acceptance_gate.deployment_profile_authority_bridge_observed,
);
assertEqual(
  'deployment profile bridge proof type',
  'zlar-protected-records-one-terminal-deployment-profile-proof-v1',
  report.deployment_profile_authority_bridge.proof_type,
);
assertEqual(
  'deployment profile bridge evidence model',
  'local-fixture-one-terminal-deployment-profile-authority-bridge',
  report.deployment_profile_authority_bridge.evidence_model,
);
assertEqual('deployment profile bridge live probing false', false, report.deployment_profile_authority_bridge.live_probing);
assert('deployment profile bridge profile sha present', /^[a-f0-9]{64}$/.test(report.deployment_profile_authority_bridge.deployment_profile_sha256));
assert('deployment profile bridge runtime profile sha present', /^[a-f0-9]{64}$/.test(report.deployment_profile_authority_bridge.runtime_profile_sha256));
assertEqual('deployment profile bridge artifact authoritative', true, report.deployment_profile_authority_bridge.deployment_profile_artifact_authoritative);
assertEqual('deployment profile bridge authority refusal count', REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length, report.deployment_profile_authority_bridge.deployment_profile_authority_refusal_case_count);
assertEqual('deployment profile bridge authority refusal case IDs', JSON.stringify(REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES), JSON.stringify(report.deployment_profile_authority_bridge.deployment_profile_authority_refusal_case_ids));
assertEqual('deployment profile bridge authority refusals before service proof', true, report.deployment_profile_authority_bridge.deployment_profile_authority_refusals_before_service_proof);
assertEqual('deployment profile bridge authority refusals before mutation', true, report.deployment_profile_authority_bridge.deployment_profile_authority_refusals_before_mutation);
assertEqual('deployment profile bridge authority refusal service proof not started', false, report.deployment_profile_authority_bridge.deployment_profile_authority_refusal_service_proof_started);
assertEqual('deployment profile bridge stale artifact refused before service proof', true, report.deployment_profile_authority_bridge.stale_deployment_profile_artifact_refused_before_service_proof);
assertEqual('deployment profile bridge profile mismatch refused before service proof', true, report.deployment_profile_authority_bridge.profile_recognition_mismatch_refused_before_service_proof);
assertEqual('deployment profile bridge latest selection refused before service proof', true, report.deployment_profile_authority_bridge.latest_profile_selection_refused_before_service_proof);
assertEqual('deployment profile bridge request authority refused before service proof', true, report.deployment_profile_authority_bridge.request_stream_authority_material_refused_before_service_proof);
assertEqual('deployment profile bridge explicit id+sha selection', true, report.deployment_profile_authority_bridge.selected_by_explicit_id_and_sha);
assertEqual('deployment profile bridge no latest selection', false, report.deployment_profile_authority_bridge.selects_latest_profile);
assertEqual('deployment profile bridge preflight verified', true, report.deployment_profile_authority_bridge.preflight_artifact_verified);
assertEqual('deployment profile bridge recognized mutates once', true, report.deployment_profile_authority_bridge.recognized_receipt_mutates_once);
assertEqual('deployment profile bridge recognized state delta one', 1, report.deployment_profile_authority_bridge.recognized_state_entry_count_delta);
assertEqual('deployment profile bridge required refusal count', 18, report.deployment_profile_authority_bridge.required_refusal_case_count);
assertEqual('deployment profile bridge observed refusal count', 18, report.deployment_profile_authority_bridge.observed_refusal_case_count);
assertEqual('deployment profile bridge all refusals before mutation', true, report.deployment_profile_authority_bridge.all_required_refusals_before_mutation);
assertEqual('deployment profile bridge agent authority refused', true, report.deployment_profile_authority_bridge.agent_supplied_authority_refused_before_mutation);
assertEqual('deployment profile bridge direct API refused', true, report.deployment_profile_authority_bridge.direct_api_refused_before_mutation);
assertEqual('deployment profile bridge downstream refusal proven', true, report.deployment_profile_authority_bridge.downstream_refusal_proven);
assertEqual('deployment profile bridge request authority not accepted', false, report.deployment_profile_authority_bridge.request_stream_authority_material_accepted);
assertEqual('deployment profile bridge current-machine governance false', false, report.deployment_profile_authority_bridge.current_machine_governance);
assertEqual('deployment profile bridge production downstream false', false, report.deployment_profile_authority_bridge.production_downstream_recognition);
assertEqual('deployment profile bridge production authority false', false, report.deployment_profile_authority_bridge.production_authority);
assertEqual('deployment profile bridge enterprise readiness false', false, report.deployment_profile_authority_bridge.enterprise_readiness);
assertEqual('deployment profile bridge external attestation false', false, report.deployment_profile_authority_bridge.external_attestation);
assertEqual('deployment profile bridge sovereign recognition false', false, report.deployment_profile_authority_bridge.sovereign_recognition);
assertEqual('deployment profile bridge unrouted coverage false', false, report.deployment_profile_authority_bridge.unrouted_surface_coverage);

assertEqual('downstream refusal boundary provided', true, report.downstream_refusal_boundary.provided);
assertEqual('downstream refusal boundary recognized boarded', true, report.downstream_refusal_boundary.recognized_boarded);
assertEqual('downstream refusal boundary marker delta one', 1, report.downstream_refusal_boundary.recognized_marker_count_delta);
assertEqual('downstream refusal boundary final marker count one', 1, report.downstream_refusal_boundary.final_marker_count);
assertEqual('downstream refusal boundary refusal count', expectedDownstreamRefusalReasons.length, report.downstream_refusal_boundary.refusal_case_count);
assertEqual('downstream refusal boundary all unboarded', true, report.downstream_refusal_boundary.all_refusals_unboarded);
assertEqual('downstream refusal boundary marker deltas zero', true, report.downstream_refusal_boundary.all_refusal_marker_count_deltas_zero);
assertEqual('downstream refusal boundary reasons', JSON.stringify(expectedDownstreamRefusalReasons), JSON.stringify(report.downstream_refusal_boundary.refusal_reasons));

assertEqual('action class records.write', 'records.write', report.action_path.action_class);
assertEqual('checkpoint named', 'downstream-recognition-rule', report.action_path.checkpoint);
assertEqual('route named', 'receipt-recognition-before-record-write', report.action_path.route);
assert('required receipt fields include payload.detail_hash', report.action_path.required_receipt_fields.includes('payload.detail_hash'));

for (const [key, value] of Object.entries(report.acceptance_gate)) {
  assertEqual(`acceptance gate ${key}`, true, value);
}

assertEqual('observed action class', 'records.write', report.observed.action_class);
assertEqual('coverage governed lanes', 6, report.observed.coverage.governed_lanes);
assertEqual('coverage counted lanes', 6, report.observed.coverage.counted_lanes);
assert('coverage boundary entries visible', report.observed.coverage.boundary_entries > 0);
assertEqual('allow downstream boarded', true, report.observed.allow_path.downstream_recognized_boarded);
assertEqual('allow downstream marker delta one', 1, report.observed.allow_path.downstream_recognized_marker_count_delta);
assertEqual('allow downstream final marker count one', 1, report.observed.allow_path.downstream_final_marker_count);
assertEqual('allow protected records accepted', true, report.observed.allow_path.protected_records_write_accepted);
assertEqual('allow service accepted', true, report.observed.allow_path.service_write_accepted);
assert('refusal reasons include receipt_missing', report.observed.refusal_path.downstream_refusal_reasons.includes('receipt_missing'));
assertEqual('downstream refusal case count', 11, report.observed.refusal_path.downstream_refusal_case_count);
assertEqual('downstream refusals unboarded', true, report.observed.refusal_path.downstream_all_refusals_unboarded);
assertEqual('downstream refusal marker deltas zero', true, report.observed.refusal_path.downstream_all_refusal_marker_count_deltas_zero);
assertEqual('protected records refusal delta zero', 0, report.observed.refusal_path.protected_records_refusal_delta_total);
assertEqual('service missing receipt refused', true, report.observed.refusal_path.service_missing_receipt_refused);
assertEqual('service unrecognized receipt refused', true, report.observed.refusal_path.service_unrecognized_receipt_refused);
assertEqual('service invalid receipt refused', true, report.observed.refusal_path.service_invalid_receipt_refused);
assertEqual('service unknown issuer refused', true, report.observed.refusal_path.service_unknown_issuer_refused);
assertEqual('service stale receipt refused', true, report.observed.refusal_path.service_stale_receipt_refused);
assertEqual('direct API without receipt refused', true, report.observed.refusal_path.service_direct_api_without_receipt_refused);

assertEqual('simulated approval channel', 'simulated-human-fixture', report.observed.simulated_human_authorization.approval_channel);
assertEqual('pending did not board', false, report.observed.simulated_human_authorization.pending_boarded);
assertEqual('authorized boarded', true, report.observed.simulated_human_authorization.authorized_boarded);
assertEqual('denied did not board', false, report.observed.simulated_human_authorization.denied_boarded);

assertEqual('receipt valid verdict', 'VALID', report.observed.receipt_verifier_boundary.valid_verdict);
assertEqual('receipt valid receipt sha present', true, report.observed.receipt_verifier_boundary.valid_receipt_sha256_present);
assertEqual('receipt valid pubkey sha present', true, report.observed.receipt_verifier_boundary.valid_provided_pubkey_sha256_present);
assertEqual('receipt required identity verdict', 'VALID', report.observed.receipt_verifier_boundary.required_identity_verdict);
assertEqual('receipt required receipt id matched', true, report.observed.receipt_verifier_boundary.required_identity_receipt_id_matched);
assertEqual('receipt required receipt sha matched', true, report.observed.receipt_verifier_boundary.required_identity_receipt_sha256_matched);
assertEqual('receipt required kid matched', true, report.observed.receipt_verifier_boundary.required_identity_kid_matched);
assertEqual('receipt required pubkey sha matched', true, report.observed.receipt_verifier_boundary.required_identity_pubkey_sha256_matched);
assertEqual('receipt required format matched', true, report.observed.receipt_verifier_boundary.required_identity_format_matched);
assertEqual('receipt required v1-only matched', true, report.observed.receipt_verifier_boundary.required_identity_v1_only_matched);
assertEqual('receipt legacy v0 required identity refused', true, report.observed.receipt_verifier_boundary.legacy_v0_required_identity_refused);
assertEqual('receipt unknown signer verdict', 'UNKNOWN-SIGNER', report.observed.receipt_verifier_boundary.unknown_signer_verdict);
assertEqual('receipt unknown signer receipt sha matches valid', true, report.observed.receipt_verifier_boundary.unknown_signer_receipt_sha256_matches_valid);
assertEqual('receipt unknown signer pubkey sha differs', true, report.observed.receipt_verifier_boundary.unknown_signer_provided_pubkey_sha256_differs);
assertEqual('receipt invalid verdict', 'INVALID', report.observed.receipt_verifier_boundary.invalid_verdict);
assertEqual('receipt invalid receipt sha differs', true, report.observed.receipt_verifier_boundary.invalid_receipt_sha256_differs_from_valid);
assertEqual('receipt invalid pubkey sha matches valid', true, report.observed.receipt_verifier_boundary.invalid_provided_pubkey_sha256_matches_valid);
assertEqual('receipt distinguishes unknown signer', true, report.observed.receipt_verifier_boundary.distinguishes_unknown_signer_from_invalid);
assertEqual('receipt issuer recognition not proven', false, report.observed.receipt_verifier_boundary.issuer_recognition_proven);
assertEqual('receipt key custody not proven', false, report.observed.receipt_verifier_boundary.key_custody_proven);
assertEqual('receipt revocation not proven', false, report.observed.receipt_verifier_boundary.revocation_state_proven);
assertEqual('receipt downstream recognition not proven', false, report.observed.receipt_verifier_boundary.downstream_recognition_proven);
assertEqual(
  'trusted issuer registry gate observed',
  true,
  report.acceptance_gate.trusted_issuer_registry_recognition_observed,
);
assertEqual(
  'trusted issuer registry evidence model',
  'fresh-local-fixture-trusted-issuer-registry-recognition',
  report.trusted_issuer_registry_recognition.evidence_model,
);
assertEqual(
  'trusted issuer registry type',
  'trusted-receipt-issuers-v2',
  report.trusted_issuer_registry_recognition.registry_type,
);
assertEqual(
  'trusted issuer registry fixture model',
  'bundled-local-fixture-no-secret-registry-contract',
  report.trusted_issuer_registry_recognition.registry_evidence_model,
);
assertEqual(
  'trusted issuer registry contract evidence',
  'no-secret-registry-contract-v2',
  report.trusted_issuer_registry_recognition.registry_contract_evidence,
);
assert(
  'trusted issuer registry public-safe summary sha present',
  /^[a-f0-9]{64}$/.test(report.trusted_issuer_registry_recognition.registry_public_safe_summary_sha256),
);
assertEqual('trusted issuer registry live probing false', false, report.trusted_issuer_registry_recognition.live_probing);
assertEqual('trusted issuer registry fixture validated', true, report.trusted_issuer_registry_recognition.registry_fixture_validated);
assertEqual('trusted issuer registry fixture evaluated', true, report.trusted_issuer_registry_recognition.registry_fixture_evaluated);
assertEqual('trusted issuer registry rule path evaluated', true, report.trusted_issuer_registry_recognition.registry_to_recognition_rule_evaluated);
assertEqual('trusted issuer registry evaluator result type', 'downstream-recognition-rule-v1', report.trusted_issuer_registry_recognition.registry_evaluation_result_type);
assertEqual('trusted issuer registry issuer count', 1, report.trusted_issuer_registry_recognition.registry_trusted_issuer_count);
assertEqual('trusted issuer registry verdict recognized', 'RECOGNIZED', report.trusted_issuer_registry_recognition.verdict);
assertEqual('trusted issuer registry recognized true', true, report.trusted_issuer_registry_recognition.recognized);
assertEqual('trusted issuer registry issuer active', 'active', report.trusted_issuer_registry_recognition.issuer_status);
assertEqual('trusted issuer registry signature valid', true, report.trusted_issuer_registry_recognition.signature_valid);
assertEqual(
  'trusted issuer registry audit event bound',
  true,
  report.trusted_issuer_registry_recognition.required_audit_event_id_bound,
);
assertEqual(
  'trusted issuer registry detail hash bound',
  true,
  report.trusted_issuer_registry_recognition.required_detail_hash_bound,
);
assertEqual(
  'trusted issuer malformed registry unsupported field',
  true,
  report.trusted_issuer_registry_recognition.malformed_registry_unsupported_field,
);
assertEqual(
  'trusted issuer malformed registry fail closed',
  true,
  report.trusted_issuer_registry_recognition.malformed_registry_fail_closed_before_verdict,
);
assertEqual(
  'trusted issuer registry does not prove live registry',
  false,
  report.trusted_issuer_registry_recognition.proves_live_registry,
);
assertEqual(
  'trusted issuer registry does not prove live issuer status',
  false,
  report.trusted_issuer_registry_recognition.proves_live_issuer_status,
);
assertEqual(
  'trusted issuer registry does not prove key custody',
  false,
  report.trusted_issuer_registry_recognition.proves_key_custody,
);
assertEqual(
  'trusted issuer registry does not prove current-machine governance',
  false,
  report.trusted_issuer_registry_recognition.proves_current_machine_governance,
);
assertEqual(
  'trusted issuer registry does not prove revocation truth',
  false,
  report.trusted_issuer_registry_recognition.proves_revocation_truth,
);
assertEqual(
  'trusted issuer registry does not prove production trust registry',
  false,
  report.trusted_issuer_registry_recognition.proves_production_trust_registry,
);
assertEqual(
  'trusted issuer registry does not prove production downstream recognition',
  false,
  report.trusted_issuer_registry_recognition.proves_production_downstream_recognition,
);
assertEqual(
  'trusted issuer registry does not prove production authority',
  false,
  report.trusted_issuer_registry_recognition.proves_production_authority,
);
assertEqual(
  'trusted issuer registry does not prove sovereign recognition',
  false,
  report.trusted_issuer_registry_recognition.proves_sovereign_recognition,
);
assertEqual(
  'trusted issuer registry does not prove public external attestation',
  false,
  report.trusted_issuer_registry_recognition.proves_public_external_attestation,
);
assertEqual(
  'trusted issuer registry does not prove real non-operator review',
  false,
  report.trusted_issuer_registry_recognition.proves_real_non_operator_review,
);
assert(
  'trusted issuer registry preserves component non-claims',
  report.trusted_issuer_registry_recognition.non_claims.some((item) =>
    item.includes('bundled local trusted-issuer registry fixture')
  ),
);
assert('known ungoverned boundaries visible', report.observed.known_ungoverned_boundaries.length > 0);

for (const [key, value] of Object.entries(report.forbidden_claims)) {
  assertEqual(`forbidden claim ${key}`, false, value);
}

assertEqual('non-claims length', PRODUCT_PROOF_PATH_NON_CLAIMS.length, report.non_claims.length);
for (let i = 0; i < PRODUCT_PROOF_PATH_NON_CLAIMS.length; i++) {
  assertEqual(`non-claim ${i}`, PRODUCT_PROOF_PATH_NON_CLAIMS[i], report.non_claims[i]);
}

const formatted = formatProductProofPathReport(report);
assert('formatted output privacy safe', assertNoUnsafeProductProofPathText(formatted));
assert('formatted names product proof path', formatted.includes('ZLAR Product Proof Path v1'));
assert('formatted names trusted issuer registry', formatted.includes('Trusted issuer registry recognition:'));
assert('formatted names terminal chain boundary', formatted.includes('Terminal chain boundary:'));
assert('formatted names coverage map contract', formatted.includes('Coverage map runtime contract:'));
assert('formatted names coverage map fixture hash', formatted.includes(`input_fixture_sha256=${COVERAGE_MAP_FIXTURE_SHA256}`));
assert('formatted names rightful issuance boundary', formatted.includes('fixture_rightful_issuance_path_evidenced=true') && formatted.includes('rightful_issuance_proven=false') && formatted.includes('consequence_lifecycle_closed=false'));
assert('formatted names replay split', formatted.includes('same_process_signed_payload_replay_refused=true') && formatted.includes('restart_consumed_authority_grant_refused=true'));
assert('formatted names deployment profile bridge', formatted.includes('Deployment profile authority-material refusal bridge:'));
assert('formatted names proof-pack identity policy', formatted.includes('proof_pack_runtime_profile_identity_policy: authority_source=launcher-owned-service-config; request_runtime_profile_id_required=false; omitted_request_field_present=false; omitted_uses_launcher_config=true; supplied_mismatch_refused=true; summaries_match=true'));
assert('formatted names proof-pack Claude hook replay', formatted.includes('proof_pack_claude_hook_contract_replay: contract_sha256=') && formatted.includes('case_evidence_sha256='));
assert('formatted names deployment bridge authority refusal', formatted.includes('agent_supplied_authority_refused_before_mutation=true'));
assert('formatted names deployment bridge current-machine boundary', formatted.includes('current_machine_governance=false'));
assert('formatted names downstream refusal boundary', formatted.includes('Downstream refusal boundary:') && formatted.includes('all_refusals_unboarded=true'));
assert('formatted names terminal chain binding matches', formatted.includes('trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification=true'));
assert('formatted names terminal chain registry verdict', formatted.includes('trusted_issuer_registry_recognition_verdict=RECOGNIZED'));
assert('formatted names terminal chain false boundary', formatted.includes('registry_public_key_material_included=false') && formatted.includes('cryptographic_evidence_reproducible_from_artifact=false') && formatted.includes('production_downstream_recognition=false'));
assert('formatted names registry evaluator path', formatted.includes('registry_fixture_validated=true') && formatted.includes('registry_to_recognition_rule_evaluated=true') && formatted.includes('registry_evaluation_result_type=downstream-recognition-rule-v1'));
assert('formatted names malformed registry fail closed', formatted.includes('malformed_registry_fail_closed_before_verdict=true'));
assert('formatted names registry audit/detail binding', formatted.includes('required_audit_event_id_bound=true') && formatted.includes('required_detail_hash_bound=true'));
assert('formatted names full registry false boundary', formatted.includes('proves_live_issuer_status=false') && formatted.includes('proves_production_downstream_recognition=false') && formatted.includes('proves_public_external_attestation=false') && formatted.includes('proves_real_non_operator_review=false') && formatted.includes('proves_current_machine_governance=false'));
assert('formatted names forbidden claims', formatted.includes('Forbidden claims:'));
assert('formatted names non claims', formatted.includes('Non-claims:'));

const widened = clone(report);
widened.forbidden_claims.external_attestation = true;
rejectsProductProofPathReport('external attestation widening rejected', widened, 'external_attestation');

const failedGate = clone(report);
failedGate.acceptance_gate.governed_action_allowed = false;
rejectsProductProofPathReport('failed acceptance gate rejected', failedGate, 'governed_action_allowed');

const missingGate = clone(report);
delete missingGate.acceptance_gate.governed_action_refused;
rejectsProductProofPathReport('missing acceptance gate rejected', missingGate, 'acceptance gate');

const emptyGate = clone(report);
emptyGate.acceptance_gate = {};
rejectsProductProofPathReport('empty acceptance gate rejected', emptyGate, 'acceptance gate');

const missingDownstreamBoundary = clone(report);
delete missingDownstreamBoundary.downstream_refusal_boundary;
rejectsProductProofPathReport('missing downstream refusal boundary rejected', missingDownstreamBoundary, 'Product proof path report');

const driftedDownstreamBoundary = clone(report);
driftedDownstreamBoundary.downstream_refusal_boundary.refusal_case_count = 10;
rejectsProductProofPathReport('downstream refusal boundary drift rejected', driftedDownstreamBoundary, 'downstream refusal boundary');

const extraProofPackField = clone(report);
extraProofPackField.proof_pack.external_attestation = true;
rejectsProductProofPathReport('extra proof-pack field rejected', extraProofPackField, 'proof-pack summary');

const proofPackIdentityDrift = clone(report);
proofPackIdentityDrift.proof_pack.runtime_profile_identity_policy.omitted_runtime_profile_id_uses_launcher_config = false;
rejectsProductProofPathReport('proof-pack identity policy drift rejected', proofPackIdentityDrift, 'runtime profile identity policy');

const proofPackClaudeHookReplayDrift = clone(report);
proofPackClaudeHookReplayDrift.proof_pack.claude_hook_contract_replay.case_evidence_sha256 = '0'.repeat(64);
rejectsProductProofPathReport('proof-pack Claude hook replay drift rejected', proofPackClaudeHookReplayDrift, 'Claude hook replay summary');

const proofPackClaudeHookReplayComponentDrift = clone(report);
proofPackClaudeHookReplayComponentDrift.proof_pack.claude_hook_contract_replay.component_sha256 = '0'.repeat(64);
rejectsProductProofPathReport('proof-pack Claude hook replay component drift rejected', proofPackClaudeHookReplayComponentDrift, 'Claude hook replay summary');

const artifactForBinding = buildLocalProofPackArtifact(runLocalProofPack());
const verificationForBinding = verifyLocalProofPackArtifact(artifactForBinding);
const tamperedArtifactWithStaleVerification = clone(artifactForBinding);
tamperedArtifactWithStaleVerification.payload.components.find(
  (item) => item.component === 'downstream_refusal_proof',
).external_attestation = true;
assert('tampered artifact with stale verification rejected', (() => {
  try {
    buildProductProofPathReport({
      artifact: tamperedArtifactWithStaleVerification,
      verification: verificationForBinding,
    });
    return false;
  } catch (err) {
    return err.message.includes('artifact verification binding');
  }
})());

const liveEvidenceModel = clone(report);
liveEvidenceModel.proof_pack.evidence_model = 'live-production-governance';
rejectsProductProofPathReport('live proof-pack evidence model rejected', liveEvidenceModel, 'proof-pack verification');

const terminalBindingMismatch = clone(report);
terminalBindingMismatch.terminal_chain_boundary.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification = false;
rejectsProductProofPathReport(
  'terminal chain trusted registry binding mismatch rejected',
  terminalBindingMismatch,
  'terminal chain boundary',
);

const terminalRegistryVerdictDrift = clone(report);
terminalRegistryVerdictDrift.terminal_chain_boundary.trusted_issuer_registry_recognition_verdict =
  'UNRECOGNIZED';
rejectsProductProofPathReport(
  'terminal chain trusted registry verdict drift rejected',
  terminalRegistryVerdictDrift,
  'terminal chain boundary',
);

const terminalRegistryRuleDrift = clone(report);
terminalRegistryRuleDrift.terminal_chain_boundary.trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated = false;
rejectsProductProofPathReport(
  'terminal chain trusted registry rule drift rejected',
  terminalRegistryRuleDrift,
  'terminal chain boundary',
);

const terminalRefusalHashMismatch = clone(report);
terminalRefusalHashMismatch.terminal_chain_boundary.trusted_issuer_registry_recognition_refusal_hash_matches_binding = false;
rejectsProductProofPathReport(
  'terminal chain trusted registry refusal hash mismatch rejected',
  terminalRefusalHashMismatch,
  'terminal chain boundary',
);

const terminalPublicKeyLeak = clone(report);
terminalPublicKeyLeak.terminal_chain_boundary.registry_public_key_material_included = true;
rejectsProductProofPathReport(
  'terminal chain public key material claim rejected',
  terminalPublicKeyLeak,
  'terminal chain boundary',
);

const terminalExternalAttestationClaim = clone(report);
terminalExternalAttestationClaim.terminal_chain_boundary.external_attestation = true;
rejectsProductProofPathReport(
  'terminal chain external attestation claim rejected',
  terminalExternalAttestationClaim,
  'terminal chain boundary',
);

const terminalAuthorityCountDrift = clone(report);
terminalAuthorityCountDrift.terminal_chain_boundary.required_authority_refusal_case_count = 4;
rejectsProductProofPathReport(
  'terminal chain authority refusal split drift rejected',
  terminalAuthorityCountDrift,
  'terminal chain boundary',
);

const terminalRightfulDrift = clone(report);
terminalRightfulDrift.terminal_chain_boundary.fixture_rightful_issuance_path_evidenced = false;
rejectsProductProofPathReport(
  'terminal chain fixture rightful path drift rejected',
  terminalRightfulDrift,
  'terminal chain boundary',
);

const terminalRouteDrift = clone(report);
terminalRouteDrift.terminal_chain_boundary.mutation_authoritative_route =
  'receipt-recognition-before-runtime-state-mutation';
rejectsProductProofPathReport(
  'terminal chain pre-authority route rejected',
  terminalRouteDrift,
  'terminal chain boundary',
);

const coverageFixtureHashDrift = clone(report);
coverageFixtureHashDrift.coverage_map_boundary.input_fixture_sha256 = '0'.repeat(64);
rejectsProductProofPathReport(
  'coverage map fixture hash drift rejected',
  coverageFixtureHashDrift,
  'coverage map boundary',
);

const coverageCurrentMachineClaim = clone(report);
coverageCurrentMachineClaim.coverage_map_boundary.current_machine_governance_proven = true;
rejectsProductProofPathReport(
  'coverage map current-machine claim rejected',
  coverageCurrentMachineClaim,
  'coverage map boundary',
);

const terminalRefusalIdDrift = clone(report);
terminalRefusalIdDrift.terminal_chain_boundary.trusted_issuer_registry_recognition_refusal_case_ids[0] =
  'drifted_case';
rejectsProductProofPathReport(
  'terminal chain trusted registry refusal case drift rejected',
  terminalRefusalIdDrift,
  'terminal chain boundary',
);

const terminalRecognitionGroupIdDrift = clone(report);
terminalRecognitionGroupIdDrift.terminal_chain_boundary
  .recognition_refusal_group_case_ids
  .no_usable_recognized_receipt_authority[0] = 'drifted_case';
rejectsProductProofPathReport(
  'terminal chain recognition refusal group case drift rejected',
  terminalRecognitionGroupIdDrift,
  'terminal chain boundary',
);

const terminalNamedRefusalDrift = clone(report);
terminalNamedRefusalDrift.terminal_chain_boundary.named_receipt_refusals.stale_or_expired.refused_before_mutation = false;
rejectsProductProofPathReport(
  'terminal chain stale-or-expired named refusal drift rejected',
  terminalNamedRefusalDrift,
  'terminal chain boundary',
);

const terminalNamedRefusalReasonDrift = clone(report);
terminalNamedRefusalReasonDrift.terminal_chain_boundary.named_receipt_refusals.stale_or_expired.reason_code = 'receipt_expired';
rejectsProductProofPathReport(
  'terminal chain stale-or-expired named refusal reason drift rejected',
  terminalNamedRefusalReasonDrift,
  'terminal chain boundary',
);

const terminalNamedRefusalHashDrift = clone(report);
terminalNamedRefusalHashDrift.terminal_chain_boundary.named_receipt_refusals_sha256 =
  '0'.repeat(64);
rejectsProductProofPathReport(
  'terminal chain named refusal hash drift rejected',
  terminalNamedRefusalHashDrift,
  'terminal chain boundary',
);

const terminalNestedBindingExtra = clone(report);
terminalNestedBindingExtra.terminal_chain_boundary.nested_artifact_binding.binding_summary = {
  bound: true,
};
rejectsProductProofPathReport(
  'terminal chain nested binding extra key rejected',
  terminalNestedBindingExtra,
  'terminal chain boundary',
);

const terminalNestedBindingMissing = clone(report);
delete terminalNestedBindingMissing.terminal_chain_boundary.nested_artifact_binding
  .service_artifact_hash_bound;
rejectsProductProofPathReport(
  'terminal chain nested binding missing key rejected',
  terminalNestedBindingMissing,
  'terminal chain boundary',
);

const terminalNestedBindingRenamed = clone(report);
terminalNestedBindingRenamed.terminal_chain_boundary.nested_artifact_binding
  .service_artifact_bound =
  terminalNestedBindingRenamed.terminal_chain_boundary.nested_artifact_binding
    .service_artifact_hash_bound;
delete terminalNestedBindingRenamed.terminal_chain_boundary.nested_artifact_binding
  .service_artifact_hash_bound;
rejectsProductProofPathReport(
  'terminal chain nested binding renamed key rejected',
  terminalNestedBindingRenamed,
  'terminal chain boundary',
);

const terminalNestedBindingSummary = clone(report);
terminalNestedBindingSummary.terminal_chain_boundary.nested_artifact_binding = {
  summary: {
    bound: true,
  },
};
rejectsProductProofPathReport(
  'terminal chain nested binding summary-shaped object rejected',
  terminalNestedBindingSummary,
  'terminal chain boundary',
);

const deploymentProfileLatestSelection = clone(report);
deploymentProfileLatestSelection.deployment_profile_authority_bridge.selects_latest_profile = true;
rejectsProductProofPathReport(
  'deployment profile bridge latest selection rejected',
  deploymentProfileLatestSelection,
  'deployment profile authority bridge',
);

const deploymentProfileRefusalMissing = clone(report);
deploymentProfileRefusalMissing.deployment_profile_authority_bridge.observed_refusal_case_count = 17;
rejectsProductProofPathReport(
  'deployment profile bridge refusal count drift rejected',
  deploymentProfileRefusalMissing,
  'deployment profile authority bridge',
);

const deploymentProfileAgentAuthorityAccepted = clone(report);
deploymentProfileAgentAuthorityAccepted.deployment_profile_authority_bridge.agent_supplied_authority_refused_before_mutation = false;
rejectsProductProofPathReport(
  'deployment profile bridge agent authority drift rejected',
  deploymentProfileAgentAuthorityAccepted,
  'deployment profile authority bridge',
);

const deploymentProfileAuthorityRefusalMissing = clone(report);
deploymentProfileAuthorityRefusalMissing.deployment_profile_authority_bridge.deployment_profile_authority_refusal_case_count = 4;
rejectsProductProofPathReport(
  'deployment profile bridge authority refusal count drift rejected',
  deploymentProfileAuthorityRefusalMissing,
  'deployment profile authority bridge',
);

const deploymentProfileAuthorityRefusalCaseIdDrift = clone(report);
deploymentProfileAuthorityRefusalCaseIdDrift.deployment_profile_authority_bridge.deployment_profile_authority_refusal_case_ids[0] = 'drifted_case';
rejectsProductProofPathReport(
  'deployment profile bridge authority refusal case ID drift rejected',
  deploymentProfileAuthorityRefusalCaseIdDrift,
  'deployment profile authority bridge',
);

const deploymentProfileAuthorityRefusalServiceStarted = clone(report);
deploymentProfileAuthorityRefusalServiceStarted.deployment_profile_authority_bridge.deployment_profile_authority_refusal_service_proof_started = true;
rejectsProductProofPathReport(
  'deployment profile bridge authority refusal service proof start rejected',
  deploymentProfileAuthorityRefusalServiceStarted,
  'deployment profile authority bridge',
);

const deploymentProfileStaleArtifactAccepted = clone(report);
deploymentProfileStaleArtifactAccepted.deployment_profile_authority_bridge.stale_deployment_profile_artifact_refused_before_service_proof = false;
rejectsProductProofPathReport(
  'deployment profile bridge stale artifact refusal drift rejected',
  deploymentProfileStaleArtifactAccepted,
  'deployment profile authority bridge',
);

const deploymentProfileMismatchAccepted = clone(report);
deploymentProfileMismatchAccepted.deployment_profile_authority_bridge.profile_recognition_mismatch_refused_before_service_proof = false;
rejectsProductProofPathReport(
  'deployment profile bridge profile mismatch refusal drift rejected',
  deploymentProfileMismatchAccepted,
  'deployment profile authority bridge',
);

const deploymentProfileRequestAuthorityAcceptedBeforeService = clone(report);
deploymentProfileRequestAuthorityAcceptedBeforeService.deployment_profile_authority_bridge.request_stream_authority_material_refused_before_service_proof = false;
rejectsProductProofPathReport(
  'deployment profile bridge request authority refusal drift rejected',
  deploymentProfileRequestAuthorityAcceptedBeforeService,
  'deployment profile authority bridge',
);

const deploymentProfileCurrentMachineClaim = clone(report);
deploymentProfileCurrentMachineClaim.deployment_profile_authority_bridge.current_machine_governance = true;
rejectsProductProofPathReport(
  'deployment profile bridge current-machine claim rejected',
  deploymentProfileCurrentMachineClaim,
  'deployment profile authority bridge',
);

const deploymentProfileProductionClaim = clone(report);
deploymentProfileProductionClaim.deployment_profile_authority_bridge.production_downstream_recognition = true;
rejectsProductProofPathReport(
  'deployment profile bridge production claim rejected',
  deploymentProfileProductionClaim,
  'deployment profile authority bridge',
);

const deploymentProfileClaimBoundaryDrift = clone(report);
deploymentProfileClaimBoundaryDrift.deployment_profile_authority_bridge.claim_boundary =
  'This proves production authority.';
rejectsProductProofPathReport(
  'deployment profile bridge claim boundary drift rejected',
  deploymentProfileClaimBoundaryDrift,
  'deployment profile authority bridge',
);

const nestedDownstreamClaim = clone(report);
nestedDownstreamClaim.observed.receipt_verifier_boundary.downstream_recognition_proven = true;
rejectsProductProofPathReport(
  'nested downstream recognition claim rejected',
  nestedDownstreamClaim,
  'downstream_recognition_proven',
);

const receiptIdentityDrift = clone(report);
receiptIdentityDrift.observed.receipt_verifier_boundary.required_identity_receipt_sha256_matched = false;
rejectsProductProofPathReport(
  'receipt required identity drift rejected',
  receiptIdentityDrift,
  'required_identity_receipt_sha256_matched',
);

const receiptLegacyV0RefusalDrift = clone(report);
receiptLegacyV0RefusalDrift.observed.receipt_verifier_boundary.legacy_v0_required_identity_refused = false;
rejectsProductProofPathReport(
  'receipt legacy v0 required identity drift rejected',
  receiptLegacyV0RefusalDrift,
  'legacy_v0_required_identity_refused',
);

const registryLiveClaim = clone(report);
registryLiveClaim.trusted_issuer_registry_recognition.proves_live_registry = true;
rejectsProductProofPathReport(
  'trusted registry live claim rejected',
  registryLiveClaim,
  'trusted issuer registry recognition',
);

const registryNonClaimCollapse = clone(report);
registryNonClaimCollapse.trusted_issuer_registry_recognition.non_claims = [
  'This proves production authority.',
];
rejectsProductProofPathReport(
  'trusted registry non-claim collapse rejected',
  registryNonClaimCollapse,
  'trusted issuer registry recognition',
);

for (const field of [
  'proves_live_issuer_status',
  'proves_key_custody',
  'proves_current_machine_governance',
  'proves_revocation_truth',
  'proves_production_trust_registry',
  'proves_production_downstream_recognition',
  'proves_production_authority',
  'proves_sovereign_recognition',
  'proves_public_external_attestation',
  'proves_real_non_operator_review',
]) {
  const drifted = clone(report);
  drifted.trusted_issuer_registry_recognition[field] = true;
  rejectsProductProofPathReport(
    `trusted registry ${field} claim rejected`,
    drifted,
    'trusted issuer registry recognition',
  );
}

const registryMalformedDrift = clone(report);
registryMalformedDrift.trusted_issuer_registry_recognition.malformed_registry_fail_closed_before_verdict = false;
rejectsProductProofPathReport(
  'trusted registry malformed drift rejected',
  registryMalformedDrift,
  'trusted issuer registry recognition',
);

const registryAuditBindingDrift = clone(report);
registryAuditBindingDrift.trusted_issuer_registry_recognition.required_audit_event_id_bound = false;
rejectsProductProofPathReport(
  'trusted registry audit binding drift rejected',
  registryAuditBindingDrift,
  'trusted issuer registry recognition',
);

for (const field of [
  'registry_fixture_validated',
  'registry_fixture_evaluated',
  'registry_to_recognition_rule_evaluated',
]) {
  const drifted = clone(report);
  drifted.trusted_issuer_registry_recognition[field] = false;
  rejectsProductProofPathReport(
    `trusted registry ${field} drift rejected`,
    drifted,
    'trusted issuer registry recognition',
  );
}

const registryEvaluatorTypeDrift = clone(report);
registryEvaluatorTypeDrift.trusted_issuer_registry_recognition.registry_evaluation_result_type =
  'synthetic-summary';
rejectsProductProofPathReport(
  'trusted registry evaluator type drift rejected',
  registryEvaluatorTypeDrift,
  'trusted issuer registry recognition',
);

const registryIssuerCountDrift = clone(report);
registryIssuerCountDrift.trusted_issuer_registry_recognition.registry_trusted_issuer_count = 0;
rejectsProductProofPathReport(
  'trusted registry issuer count drift rejected',
  registryIssuerCountDrift,
  'trusted issuer registry recognition',
);

const extraAllowPathField = clone(report);
extraAllowPathField.observed.allow_path.live_records_system_checked = true;
rejectsProductProofPathReport('extra nested observed field rejected', extraAllowPathField, 'allow path');

const downstreamMarkerDrift = clone(report);
downstreamMarkerDrift.observed.allow_path.downstream_recognized_marker_count_delta = 0;
rejectsProductProofPathReport('downstream marker delta drift rejected', downstreamMarkerDrift, 'downstream recognized marker count delta');

const downstreamRefusalMutation = clone(report);
downstreamRefusalMutation.observed.refusal_path.downstream_all_refusal_marker_count_deltas_zero = false;
rejectsProductProofPathReport('downstream refusal mutation drift rejected', downstreamRefusalMutation, 'all refusal marker count deltas zero');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed${FAIL ? ` (${FAIL} FAILED)` : ' ✓'}`);
if (FAIL > 0) process.exit(1);
