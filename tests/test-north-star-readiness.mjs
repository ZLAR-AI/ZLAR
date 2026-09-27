#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE,
  NORTH_STAR_READINESS_REPORT_TYPE,
  assertNorthStarReadinessReport,
  buildNorthStarReadinessReport,
  formatNorthStarReadinessSummary,
} from '../lib/north-star-readiness.mjs';
import {
  TRUSTED_RECEIPT_ISSUER_COMPLETION_CORE_SENTENCE,
  TRUSTED_RECEIPT_ISSUER_COMPLETION_PRIVATE_OPERATOR_RECORDS_TERMINAL_SURFACE_ID,
  TRUSTED_RECEIPT_ISSUER_COMPLETION_SURFACE_ID,
  buildTrustedReceiptIssuerCompletionProofTestVector,
} from '../lib/trusted-receipt-issuer-completion-proof.mjs';
import {
  buildVerifierKitPublicDistributionReport,
} from '../lib/verifier-kit-public-distribution.mjs';
import {
  ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_NON_CLAIMS,
  ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_OPEN_BOUNDARIES,
  ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_SAFE_CLAIM,
} from '../lib/protected-records-active-persistent-profile-action-crossing.mjs';
import {
  ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
  ACTIVE_PERSISTENT_PROFILE_FORBIDDEN_CLAIMS,
  ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
} from '../lib/protected-records-active-persistent-profile-preflight.mjs';
import {
  ACTIVE_PERSISTENT_PROFILE_LIVE_CLAIM,
  ACTIVE_PERSISTENT_PROFILE_LIVE_NON_CLAIMS,
  ACTIVE_PERSISTENT_PROFILE_LIVE_OPEN_BOUNDARIES,
} from '../lib/protected-records-active-persistent-profile-live-installation.mjs';
import {
  buildActivePersistentProfileLifecycleReport,
} from '../lib/protected-records-active-persistent-profile-lifecycle.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
} from '../lib/protected-records-runtime-profile.mjs';
import {
  buildProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS,
  verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact,
} from '../lib/protected-records-installed-runtime-profile-terminal-chain.mjs';
import {
  PUBLIC_EXTERNAL_ATTESTATION_RESULT_NON_CLAIMS,
  buildPublicExternalAttestationResultVerification,
  buildPublicExternalAttestationSignedPayload,
  canonicalPublicExternalAttestationJson,
} from '../lib/public-external-attestation-result.mjs';

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

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function sha(value = '') {
  return createHash('sha256').update(value).digest('hex');
}

function signedPublicExternalAttestationResultVerification(releaseTag = 'v3.3.106') {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const target = {
    release_tag: releaseTag,
    commit_sha: '5c89e6bb51a1442528ba5a2b41bdeb127211aba4',
    source_access_path: 'public_release_assets_only',
    artifact_set_sha256: '1'.repeat(64),
    readiness_report_sha256: '2'.repeat(64),
    proof_bundle_sha256: '3'.repeat(64),
  };
  const attestationText = [
    `I verified ZLAR ${target.release_tag} at ${target.commit_sha}.`,
    `Source access path: ${target.source_access_path}.`,
    `Artifact set SHA-256: ${target.artifact_set_sha256}.`,
    `Readiness report SHA-256: ${target.readiness_report_sha256}.`,
    `Proof bundle SHA-256: ${target.proof_bundle_sha256}.`,
    'This bounded public external attestation does not prove production authority.',
    'This bounded public external attestation does not prove enterprise readiness.',
    'This bounded public external attestation does not prove sovereign recognition.',
    'Named limits: public artifact target only; no current-machine governance; no all-surface closure.',
    '',
  ].join('\n');
  const report = {
    report_type: 'zlar-public-external-attestation-result-v1',
    schema_version: 1,
    attestation_class: 'public_signed_or_published_external_attestation',
    verifier: {
      verifier_label: 'arms-length-public-verifier-v3459-001',
      relationship_disclosure_class: 'arms_length_external',
      public_attribution_approved: true,
      public_identity_url: 'https://example.org/zlar-verifier',
      public_identity_redacted_in_private_ledger: true,
      public_key_pem_sha256: sha(publicKeyPem),
    },
    target,
    attestation: {
      mode: 'detached_ed25519_signature',
      attestation_text: attestationText,
      attestation_text_sha256: sha(attestationText),
      public_key_pem: publicKeyPem,
      signature_base64: '',
      signed_payload_canonical_json: '',
      signed_payload_sha256: '',
      named_limits_present: true,
      target_binding_present: true,
      non_claims_present: true,
      signed_or_published_by_verifier: true,
      attestation_preserved_for_future_checking: true,
    },
    claim_boundary: {
      public_external_attestation: true,
      public_attribution: true,
      non_operator_review_proven: true,
      private_source_review: false,
      production_authority: false,
      enterprise_readiness: false,
      sovereign_recognition: false,
      current_machine_governance: false,
      all_surface_governance: false,
      key_custody: false,
      revocation_truth: false,
      production_downstream_recognition: false,
      side_door_closure: false,
    },
    non_claims: [...PUBLIC_EXTERNAL_ATTESTATION_RESULT_NON_CLAIMS],
  };
  const signedPayloadCanonicalJson = canonicalPublicExternalAttestationJson(
    buildPublicExternalAttestationSignedPayload(report)
  );
  report.attestation.signed_payload_canonical_json = signedPayloadCanonicalJson;
  report.attestation.signed_payload_sha256 = sha(signedPayloadCanonicalJson);
  report.attestation.signature_base64 = sign(
    null,
    Buffer.from(signedPayloadCanonicalJson),
    privateKey
  ).toString('base64');
  return buildPublicExternalAttestationResultVerification(report, {
    resultText: `${JSON.stringify(report, null, 2)}\n`,
  });
}

function writeJsonArtifact(dir, name, value) {
  const body = `${JSON.stringify(value, null, 2)}\n`;
  writeFileSync(join(dir, name), body);
  return sha256(body);
}

function activePersistentLifecycleFixtureReports() {
  const installedAt = '2026-07-07T12:00:00.000Z';
  const greenAt = '2026-07-07T12:01:00.000Z';
  const redAt = '2026-07-07T12:02:00.000Z';
  const closeoutAt = '2026-07-07T12:03:00.000Z';
  const closeoutGeneratedAt = '2026-07-07T12:03:10.000Z';
  const expiresAt = '2026-07-07T16:00:00.000Z';
  const recognitionContractSha256 = sha('active-persistent-recognition-contract');
  const refusalTaxonomySha256 = sha('active-persistent-refusal-taxonomy');
  const statusBeforeCloseoutSha256 = sha('active-persistent-status-before-closeout');

  const installReport = {
    report_type: 'zlar-protected-records-active-persistent-profile-live-installation-proof-v1',
    schema_version: 1,
    evidence_model: 'bounded-active-persistent-profile-live-installation',
    safe_claim: ACTIVE_PERSISTENT_PROFILE_LIVE_CLAIM,
    activation_root_label: '<named-active-persistent-profile-root>',
    named_live_root: true,
    installed_at: installedAt,
    expires_at: expiresAt,
    final_root_state: 'active_until_expiry',
    active_after_proof: true,
    preinstall_status: {
      activation_root_state: 'absent',
      closed_root_replacement_authorized: false,
      inert_legacy_evidence_preserved: false,
      manifest_present: false,
      manifest_status: 'absent',
    },
    selected_profile: {
      profile_id: 'protected-records-runtime-fixture-profile',
      runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      runtime_profile_sha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
      runtime_profile_source: ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
      selected_by_explicit_id_and_sha: true,
      selects_latest_profile: false,
    },
    files_written: {
      manifest_path_label: '<active-manifest>',
      preparing_manifest_sha256: sha('preparing-manifest'),
      final_manifest_sha256: sha('final-manifest'),
      active_index_path_label: '<active-index>',
      active_index_sha256: sha('active-index'),
      installed_profile_path_label: '<installed-profile>',
      installed_profile_sha256: sha('installed-profile'),
    },
    readback_preflight: {
      installed_runtime_profile_preflight_performed: true,
      installed_runtime_profile_preflight_sha256: sha('readback-preflight'),
      read_only: true,
      selected_by_explicit_id_and_sha: true,
      selects_latest_profile: false,
      runtime_profile_installation_performed_by_preflight: false,
      runtime_profile_activation_performed_by_preflight: false,
    },
    write_boundary: {
      activation_root_written: true,
      root_created_or_reused_by_explicit_path: true,
      closed_root_replaced_by_explicit_authority: false,
      hooks_or_config_written_outside_root: false,
      runtime_service_started: false,
      real_records_touched: false,
      credentials_or_key_material_used: false,
      external_services_used: false,
    },
    claim_boundary: {
      active_persistent_runtime_profile_installation: true,
      persistent_active_state_after_proof: true,
      installed_runtime_profile_readback_preflight: true,
      proof_owned_or_named_zlar_root_only: true,
      hooks_or_machine_config_written: false,
      runtime_service_started: false,
      real_personal_records_touched: false,
      raw_codex_developer_tool_governance: false,
      current_machine_governance_general: false,
      all_surface_governance: false,
      production_downstream_recognition: false,
      enterprise_readiness: false,
      public_external_attestation: false,
      side_door_closure: false,
      absolute_human_intention: false,
    },
    open_boundaries: [...ACTIVE_PERSISTENT_PROFILE_LIVE_OPEN_BOUNDARIES],
    non_claims: [...ACTIVE_PERSISTENT_PROFILE_LIVE_NON_CLAIMS],
    forbidden_claims: [...ACTIVE_PERSISTENT_PROFILE_FORBIDDEN_CLAIMS],
  };

  const greenReport = {
    proof_type: 'zlar-protected-records-active-persistent-profile-governed-action-crossing-v1',
    evidence_model: 'active-root-read-before-local-disposable-records-write-crossing',
    safe_claim_ceiling: ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_SAFE_CLAIM,
    action_class: 'records.write',
    now_epoch: Math.floor(Date.parse(greenAt) / 1000),
    active_profile: {
      status_read_at_action_time: true,
      active_root_selected_by_operator: true,
      renewal_or_extension_performed: false,
      activation_root_label: '<named-active-persistent-profile-root>',
      named_live_root: true,
      activation_root_state: 'active_until_expiry',
      manifest_present: true,
      manifest_status: 'active_persistent_profile_installed',
      active: true,
      expired: false,
      expires_at: expiresAt,
      active_index_present: true,
      installed_profile_present: true,
    },
    action_crossing: {
      action_attempted: true,
      action_class: 'records.write',
      active_profile_read_before_action: true,
      installed_profile_read_before_action: true,
      selected_profile_source: 'active-persistent-profile-root-read-at-action-time',
      requested_profile_id: 'protected-records-runtime-fixture-profile',
      requested_profile_sha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
      runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      selected_by_explicit_id_and_sha: true,
      selects_latest_profile: false,
      recognized_receipt_boards_before_mutation: true,
      refusals_before_mutation: true,
      replay_refusals_before_mutation: true,
      request_stream_authority_material_accepted: false,
      recognition_rule_supplied_by_agent: false,
    },
    proof_target: {
      target_label: '<proof-owned-action-crossing-target>',
      existed_before: false,
      entry_count_before: 0,
      entry_count_after: 1,
      recognized_entry_delta: 1,
      refusal_entry_delta_total: 0,
      write_policy: 'write-after-recognized-service-acceptance-only',
      marker_sha256: sha('recognized-marker'),
    },
    generated_preflight: {
      verified: true,
      read_only: true,
      requested_profile_id: 'protected-records-runtime-fixture-profile',
      requested_profile_sha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
      profile_selected_from_install_root: true,
      selected_by_explicit_id_and_sha: true,
      selects_latest_profile: false,
      downstream_refusal_proven: false,
      current_machine_governance_proven: false,
      body_sha256: sha('generated-preflight-body'),
    },
    service_crossing: {
      verified: true,
      live_probing: false,
      source_preflight_body_sha256: sha('generated-preflight-body'),
      selected_profile_sha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
      selected_by_explicit_id_and_sha: true,
      selects_latest_profile: false,
      recognition_rule_bound_to_selected_profile: true,
      recognition_rule_supplied_by_agent: false,
      request_stream_authority_material_accepted: false,
      runtime_service_started: true,
      persistent_runtime_config_written: false,
      recognized_write_boarded: true,
      recognized_write_marker_delta: 1,
      same_process_replay_refused: true,
      restart_replay_refused: true,
      all_replay_refusals_before_mutation: true,
      all_refusals_before_mutation: true,
      install_performed: false,
      activation_performed: false,
      hook_configuration_written: false,
      user_config_written: false,
      machine_config_written: false,
      current_machine_governance_proven: false,
      production_downstream_recognition: false,
    },
    hashes: {
      recognition_contract_sha256: recognitionContractSha256,
      refusal_taxonomy_sha256: refusalTaxonomySha256,
    },
    claim_boundary: {
      active_persistent_profile_action_crossing: true,
      active_root_read_at_action_time: true,
      recognized_records_write_boarded: true,
      refusals_before_mutation: true,
      real_personal_records_protection: false,
      raw_codex_or_developer_tool_governance: false,
      current_machine_governance_general: false,
      browser_computer_use_mcp_shell_network_or_all_surface_governance: false,
      production_downstream_recognition: false,
      production_authority: false,
      enterprise_readiness: false,
      public_external_attestation: false,
      sovereign_recognition: false,
      side_door_closure: false,
      absolute_human_intention: false,
    },
    known_open_boundaries: [...ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_OPEN_BOUNDARIES],
    non_claims: [...ACTIVE_PERSISTENT_PROFILE_ACTION_CROSSING_NON_CLAIMS],
  };

  const activeStatus = {
    active: true,
    expired: false,
    manifest_status: 'active_persistent_profile_installed',
    activation_root_state: 'active_until_expiry',
    expires_at: expiresAt,
  };
  const redReport = {
    proof_report_type: 'zlar-active-persistent-profile-red-path-refusal-proof-report-v1',
    generated_at: redAt,
    authority_packet: { path: '<authority-packet>' },
    scratch_dir: '<scratch-dir>',
    exact_claim: 'Red-path refusals stayed before mutation for the named active persistent profile proof fixture.',
    wrapper_note: 'fixture',
    failures: [],
    non_claims: ['fixture non-claim'],
    active_root: {
      label: '<named-active-persistent-profile-root>',
      real_path_redacted_in_public_claims: true,
      status_before: { ...activeStatus },
      status_after: { ...activeStatus },
      status_final: { ...activeStatus },
    },
    selected_profile: {
      profile_id: 'protected-records-runtime-fixture-profile',
      runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      profile_sha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
      selected_by_explicit_id_and_sha: true,
      selects_latest_profile: false,
      recognition_contract_sha256: recognitionContractSha256,
    },
    red_path_result: {
      result: 'pass',
      proof_ran_while_active_root_live: true,
      active_root_bound_preflight_verified: true,
      disposable_service_started: true,
      local_disposable_child_process_only: true,
      persistent_runtime_config_written: false,
      live_probing: false,
      baseline_recognized_write_boarded_inside_disposable_service: true,
      baseline_recognized_marker_delta: 1,
      all_refusals_before_mutation: true,
      all_replay_refusals_before_mutation: true,
      refusal_marker_delta_total: 0,
      replay_marker_delta_total: 0,
      consumed_store_integrity_marker_delta_total: 0,
      store_and_anchor_rollback_marker_delta_total: 0,
      request_stream_authority_material_accepted: false,
      recognition_rule_supplied_by_agent: false,
      refusal_case_count: 18,
      required_refusal_case_count: 18,
      refusal_taxonomy_sha256: refusalTaxonomySha256,
    },
    artifact_hashes: {
      status_final_sha256: statusBeforeCloseoutSha256,
    },
    refusal_cases: [],
  };

  const closeoutReport = {
    proof_report_type: 'zlar-active-persistent-profile-closeout-refusal-proof-report-v1',
    generated_at: closeoutGeneratedAt,
    authority_packet: { path: '<authority-packet>' },
    scratch_dir: '<scratch-dir>',
    exact_claim: 'Closed-root action crossing refused before target mutation for the fixture.',
    failures: [],
    non_claims: ['fixture non-claim'],
    before_status: { ...activeStatus },
    closeout: {
      status: 'closed_inert_evidence',
      active: false,
      closeout_reactivation_allowed: false,
      closed_at: closeoutAt,
    },
    after_status: {
      active: false,
      expired: false,
      manifest_status: 'closed_inert_evidence',
      activation_root_state: 'closed_inert_evidence',
      safe_for_install: false,
      explicit_closeout_or_replace_required: true,
      expires_at: expiresAt,
    },
    refused_after_closeout_probe: {
      attempted_action_class: 'records.write',
      exit_code: 2,
      target_written: false,
      refusal_before_target_mutation: true,
      stdout_sha256: sha('closed-root-stdout'),
      stderr_sha256: sha('closed-root-stderr'),
      stderr_redacted_snippet:
        'ERROR: active persistent action crossing requires an active unexpired named root',
    },
    artifact_hashes: {
      status_before_sha256: statusBeforeCloseoutSha256,
    },
  };

  return { installReport, greenReport, redReport, closeoutReport };
}

function writeActivePersistentLifecycleEvidence(dir) {
  const reports = activePersistentLifecycleFixtureReports();
  const filenames = {
    install_report: 'active-persistent-installation-report.json',
    green_report: 'active-persistent-green-crossing-report.json',
    red_report: 'active-persistent-red-refusal-report.json',
    closeout_report: 'active-persistent-closeout-refusal-report.json',
  };
  const hashes = {
    install_report_sha256: writeJsonArtifact(dir, filenames.install_report, reports.installReport),
    green_report_sha256: writeJsonArtifact(dir, filenames.green_report, reports.greenReport),
    red_report_sha256: writeJsonArtifact(dir, filenames.red_report, reports.redReport),
    closeout_report_sha256: writeJsonArtifact(dir, filenames.closeout_report, reports.closeoutReport),
  };
  const lifecycleReport = buildActivePersistentProfileLifecycleReport({
    ...reports,
    inputReportHashes: hashes,
    inputReportLabels: filenames,
    expectedInputReportHashesBound: true,
    generatedAt: '2026-07-07T12:04:00.000Z',
  });
  const lifecycleReportSha256 = writeJsonArtifact(
    dir,
    'zlar-active-persistent-profile-lifecycle-v1.json',
    lifecycleReport,
  );
  const binding = {
    report_type: 'zlar-active-persistent-profile-lifecycle-source-binding-v1',
    schema_version: 1,
    evidence_class: 'historical_supplied_local_active_persistent_profile_lifecycle',
    lifecycle_report_file: 'zlar-active-persistent-profile-lifecycle-v1.json',
    lifecycle_report_sha256: lifecycleReportSha256,
    source_reports: {
      install_report: {
        file: filenames.install_report,
        sha256: hashes.install_report_sha256,
      },
      green_report: {
        file: filenames.green_report,
        sha256: hashes.green_report_sha256,
      },
      red_report: {
        file: filenames.red_report,
        sha256: hashes.red_report_sha256,
      },
      closeout_report: {
        file: filenames.closeout_report,
        sha256: hashes.closeout_report_sha256,
      },
    },
    non_scoring: true,
    current_installation: false,
    product_proof_path_completion: false,
    production_downstream_recognition: false,
  };
  writeJsonArtifact(
    dir,
    'zlar-active-persistent-profile-lifecycle-source-binding-v1.json',
    binding,
  );
  return { lifecycleReport, lifecycleReportSha256, hashes };
}

const EXPECTED_RECOGNITION_REFUSAL_GROUP_CASE_IDS = {
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
const EXPECTED_DOWNSTREAM_REFUSAL_REASONS = [
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
const EXPECTED_NESTED_PREFLIGHT_ARTIFACT_TYPE =
  'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1';
const EXPECTED_NESTED_SERVICE_PROOF_ARTIFACT_TYPE =
  'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1';
const EXPECTED_TRUSTED_ISSUER_REGISTRY_REFUSAL_CASE_IDS = [
  'unrecognized_terminal_chain_registry_scope_refused',
  'registry_receipt_contract_mismatch_refused',
];
const EXPECTED_TRUSTED_ISSUER_REGISTRY_REFUSAL_REASON_CODES = [
  'scope_not_found',
  'detail_hash_mismatch',
];
const EXPECTED_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASE_IDS = [
  'stale_deployment_profile_runtime_sha_refused_before_service_proof',
  'runtime_profile_id_mismatch_refused_before_service_proof',
  'preflight_profile_sha_mismatch_refused_before_service_proof',
  'preflight_latest_selection_refused_before_service_proof',
  'preflight_request_authority_material_refused_before_service_proof',
];
const EXPECTED_RUNTIME_PROFILE_IDENTITY_POLICY = {
  authority_source: 'launcher-owned-service-config',
  request_stream_policy:
    'runtime_profile_id_may_be_omitted_but_if_supplied_must_match_config',
  request_runtime_profile_id_required: false,
  omitted_request_runtime_profile_id_present: false,
  omitted_runtime_profile_id_uses_launcher_config: true,
  supplied_mismatched_runtime_profile_id_refused: true,
  runtime_local_activation_summary_bound: true,
  runtime_profile_installation_summary_bound: true,
  summaries_match: true,
};

function assertRuntimeProfileIdentityPolicy(label, summary) {
  assertEqual(
    `${label} authority source`,
    EXPECTED_RUNTIME_PROFILE_IDENTITY_POLICY.authority_source,
    summary.authority_source,
  );
  assertEqual(
    `${label} request stream policy`,
    EXPECTED_RUNTIME_PROFILE_IDENTITY_POLICY.request_stream_policy,
    summary.request_stream_policy,
  );
  assertEqual(
    `${label} request runtime profile id not required`,
    EXPECTED_RUNTIME_PROFILE_IDENTITY_POLICY.request_runtime_profile_id_required,
    summary.request_runtime_profile_id_required,
  );
  assertEqual(
    `${label} omitted request runtime profile id absent`,
    EXPECTED_RUNTIME_PROFILE_IDENTITY_POLICY.omitted_request_runtime_profile_id_present,
    summary.omitted_request_runtime_profile_id_present,
  );
  assertEqual(
    `${label} omitted runtime profile id uses launcher config`,
    EXPECTED_RUNTIME_PROFILE_IDENTITY_POLICY.omitted_runtime_profile_id_uses_launcher_config,
    summary.omitted_runtime_profile_id_uses_launcher_config,
  );
  assertEqual(
    `${label} supplied mismatched runtime profile id refused`,
    EXPECTED_RUNTIME_PROFILE_IDENTITY_POLICY.supplied_mismatched_runtime_profile_id_refused,
    summary.supplied_mismatched_runtime_profile_id_refused,
  );
  assertEqual(
    `${label} local activation summary bound`,
    EXPECTED_RUNTIME_PROFILE_IDENTITY_POLICY.runtime_local_activation_summary_bound,
    summary.runtime_local_activation_summary_bound,
  );
  assertEqual(
    `${label} profile installation summary bound`,
    EXPECTED_RUNTIME_PROFILE_IDENTITY_POLICY.runtime_profile_installation_summary_bound,
    summary.runtime_profile_installation_summary_bound,
  );
  assertEqual(
    `${label} summaries match`,
    EXPECTED_RUNTIME_PROFILE_IDENTITY_POLICY.summaries_match,
    summary.summaries_match,
  );
}

function assertObservedDeploymentProfileAuthorityRefusalMirror(label, observed) {
  assertEqual(`${label} required`, true, observed.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required);
  assertEqual(`${label} preserved`, true, observed.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved);
  assertEqual(`${label} case count`, 5, observed.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count);
  assertEqual(
    `${label} case IDs`,
    JSON.stringify(EXPECTED_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASE_IDS),
    JSON.stringify(observed.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids)
  );
  assertEqual(`${label} refused before service proof`, true, observed.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof);
  assertEqual(`${label} refused before mutation`, true, observed.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation);
  assertEqual(`${label} service proof not started`, false, observed.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started);
  assertEqual(`${label} current-machine governance false`, false, observed.installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance);
  assertEqual(`${label} production downstream false`, false, observed.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition);
  assertEqual(`${label} production authority false`, false, observed.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority);
  assertEqual(`${label} enterprise readiness false`, false, observed.installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness);
  assertEqual(`${label} external attestation false`, false, observed.installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation);
  assertEqual(`${label} sovereign recognition false`, false, observed.installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition);
  assertEqual(`${label} unrouted coverage false`, false, observed.installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage);
  assertEqual(`${label} artifact case count`, 5, observed.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count);
  assertEqual(
    `${label} artifact case IDs`,
    JSON.stringify(EXPECTED_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASE_IDS),
    JSON.stringify(observed.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids)
  );
  assertEqual(`${label} artifact refused before service proof`, true, observed.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof);
  assertEqual(`${label} artifact refused before mutation`, true, observed.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation);
  assertEqual(`${label} artifact service proof not started`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started);
  assertEqual(`${label} artifact current-machine governance false`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_current_machine_governance);
  assertEqual(`${label} artifact production downstream false`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_downstream_recognition);
  assertEqual(`${label} artifact production authority false`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_authority);
  assertEqual(`${label} artifact enterprise readiness false`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_enterprise_readiness);
  assertEqual(`${label} artifact external attestation false`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_external_attestation);
  assertEqual(`${label} artifact sovereign recognition false`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_sovereign_recognition);
  assertEqual(`${label} artifact unrouted coverage false`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_unrouted_surface_coverage);
}

function assertObservedRecognitionRefusalGroupCaseIds(label, observed) {
  assertEqual(`${label} case IDs preserved`, true, observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved);
  assertEqual(`${label} group count`, 3, observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_count);
  assertEqual(`${label} case count`, 18, observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count);
  assertEqual(
    `${label} case IDs`,
    JSON.stringify(EXPECTED_RECOGNITION_REFUSAL_GROUP_CASE_IDS),
    JSON.stringify(observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids)
  );
  assertEqual(`${label} artifact group count`, 3, observed.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count);
  assertEqual(`${label} artifact case count`, 18, observed.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count);
  assertEqual(
    `${label} artifact case IDs`,
    JSON.stringify(EXPECTED_RECOGNITION_REFUSAL_GROUP_CASE_IDS),
    JSON.stringify(observed.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids)
  );
}

function assertObservedNestedArtifactBinding(label, observed) {
  assertEqual(`${label} nested binding preserved`, true, observed.installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved);
  assertEqual(`${label} nested preflight type`, EXPECTED_NESTED_PREFLIGHT_ARTIFACT_TYPE, observed.installed_runtime_profile_terminal_chain_nested_preflight_artifact_type);
  assertEqual(`${label} nested service proof type`, EXPECTED_NESTED_SERVICE_PROOF_ARTIFACT_TYPE, observed.installed_runtime_profile_terminal_chain_nested_service_proof_artifact_type);
  assertEqual(`${label} artifact nested binding preserved`, true, observed.installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved);
  assertEqual(`${label} artifact nested preflight type`, EXPECTED_NESTED_PREFLIGHT_ARTIFACT_TYPE, observed.installed_runtime_profile_terminal_chain_artifact_verification_nested_preflight_artifact_type);
  assertEqual(`${label} artifact nested service proof type`, EXPECTED_NESTED_SERVICE_PROOF_ARTIFACT_TYPE, observed.installed_runtime_profile_terminal_chain_artifact_verification_nested_service_proof_artifact_type);
}

function assertObservedTrustedIssuerRegistryBinding(label, observed) {
  assertEqual(`${label} trusted registry binding preserved`, true, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved);
  assert(`${label} trusted registry binding sha`, /^[a-f0-9]{64}$/.test(observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256));
  assert(`${label} artifact trusted registry binding sha`, /^[a-f0-9]{64}$/.test(observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256));
  assertEqual(
    `${label} trusted registry binding hashes match`,
    observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256,
    observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256
  );
  assertEqual(`${label} trusted registry refusals preserved`, true, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved);
  assertEqual(`${label} trusted registry refusal count`, 2, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count);
  assertEqual(`${label} trusted registry all refusals refused`, true, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused);
  assertEqual(
    `${label} trusted registry refusal case IDs`,
    JSON.stringify(EXPECTED_TRUSTED_ISSUER_REGISTRY_REFUSAL_CASE_IDS),
    JSON.stringify(observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids)
  );
  assertEqual(
    `${label} trusted registry refusal reason codes`,
    JSON.stringify(EXPECTED_TRUSTED_ISSUER_REGISTRY_REFUSAL_REASON_CODES),
    JSON.stringify(observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes)
  );
  assert(`${label} trusted registry refusal sha`, /^[a-f0-9]{64}$/.test(observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256));
  assertEqual(`${label} artifact trusted registry refusal count`, 2, observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count);
  assertEqual(`${label} artifact trusted registry all refusals refused`, true, observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused);
  assertEqual(
    `${label} artifact trusted registry refusal case IDs`,
    JSON.stringify(EXPECTED_TRUSTED_ISSUER_REGISTRY_REFUSAL_CASE_IDS),
    JSON.stringify(observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids)
  );
  assertEqual(
    `${label} artifact trusted registry refusal reason codes`,
    JSON.stringify(EXPECTED_TRUSTED_ISSUER_REGISTRY_REFUSAL_REASON_CODES),
    JSON.stringify(observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes)
  );
  assertEqual(
    `${label} trusted registry refusal hashes match`,
    observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256,
    observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256
  );
  assertEqual(`${label} trusted registry no live registry`, false, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_state_proven);
  assertEqual(`${label} trusted registry no live issuer status`, false, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_live_issuer_status_proven);
  assertEqual(`${label} trusted registry no key custody`, false, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_key_custody_proven);
  assertEqual(`${label} trusted registry no revocation truth`, false, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_revocation_truth_proven);
  assertEqual(`${label} trusted registry no production trust registry`, false, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_trust_registry_proven);
  assertEqual(`${label} trusted registry no production downstream recognition`, false, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_downstream_recognition_proven);
  assertEqual(`${label} trusted registry no production authority`, false, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_authority);
  assertEqual(`${label} trusted registry no sovereign recognition`, false, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_sovereign_recognition);
  assertEqual(`${label} trusted registry no public external attestation`, false, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_external_attestation);
  assertEqual(`${label} trusted registry no real non-operator review`, false, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_real_non_operator_review);
  assertEqual(`${label} trusted registry no current-machine governance`, false, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_current_machine_governance_proven);
  assertEqual(`${label} trusted registry public key material omitted`, false, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_public_key_material_included);
  assertEqual(`${label} trusted registry receipt envelope omitted`, false, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_envelope_included);
  assertEqual(`${label} trusted registry no artifact-only crypto reconstruction`, false, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_artifact_crypto_reproducible);
  assertEqual(`${label} trusted registry receipt contract hash bound`, true, observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_receipt_contract_hash_bound);
  assertEqual(`${label} artifact trusted registry no live registry`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_state_proven);
  assertEqual(`${label} artifact trusted registry no live issuer status`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_live_issuer_status_proven);
  assertEqual(`${label} artifact trusted registry no key custody`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_key_custody_proven);
  assertEqual(`${label} artifact trusted registry no revocation truth`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_revocation_truth_proven);
  assertEqual(`${label} artifact trusted registry no production trust registry`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_trust_registry_proven);
  assertEqual(`${label} artifact trusted registry no production downstream recognition`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_downstream_recognition_proven);
  assertEqual(`${label} artifact trusted registry no production authority`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_production_authority);
  assertEqual(`${label} artifact trusted registry no sovereign recognition`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_sovereign_recognition);
  assertEqual(`${label} artifact trusted registry no public external attestation`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_external_attestation);
  assertEqual(`${label} artifact trusted registry no real non-operator review`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_real_non_operator_review);
  assertEqual(`${label} artifact trusted registry no current-machine governance`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_current_machine_governance_proven);
  assertEqual(`${label} artifact trusted registry public key material omitted`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_public_key_material_included);
  assertEqual(`${label} artifact trusted registry receipt envelope omitted`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_envelope_included);
  assertEqual(`${label} artifact trusted registry no artifact-only crypto reconstruction`, false, observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_artifact_crypto_reproducible);
  assertEqual(`${label} artifact trusted registry receipt contract hash bound`, true, observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_receipt_contract_hash_bound);
}

function assertObservedRecognizedReceiptPathMirror(label, observed) {
  if (Object.hasOwn(observed, 'installed_runtime_profile_terminal_chain_recognized_receipt_path_mirror_required')) {
    assertEqual(`${label} required`, true, observed.installed_runtime_profile_terminal_chain_recognized_receipt_path_mirror_required);
  }
  assertEqual(`${label} preserved`, true, observed.installed_runtime_profile_terminal_chain_recognized_receipt_path_mirror_preserved);
  assert(`${label} evidence sha`, /^[a-f0-9]{64}$/.test(observed.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256));
  assert(`${label} artifact evidence sha`, /^[a-f0-9]{64}$/.test(observed.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_sha256));
  assertEqual(
    `${label} evidence hashes match`,
    observed.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256,
    observed.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_evidence_sha256
  );
  assertEqual(`${label} evidence bound to artifact body`, true, observed.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_bound_to_artifact_body);
  assert(`${label} source binding sha`, /^[a-f0-9]{64}$/.test(observed.installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256));
  assert(`${label} artifact source binding sha`, /^[a-f0-9]{64}$/.test(observed.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_sha256));
  assertEqual(
    `${label} source binding matches trusted registry`,
    observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256,
    observed.installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256
  );
  assertEqual(
    `${label} artifact source binding matches trusted registry`,
    observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256,
    observed.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_sha256
  );
  assertEqual(`${label} source binding match flag`, true, observed.installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_matches_trusted_registry_binding);
  assertEqual(`${label} artifact source binding match flag`, true, observed.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_source_binding_matches_trusted_registry_binding);
  assertEqual(`${label} verdict`, 'RECOGNIZED', observed.installed_runtime_profile_terminal_chain_recognized_receipt_path_verdict);
  assertEqual(`${label} artifact verdict`, 'RECOGNIZED', observed.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_verdict);
  assertEqual(`${label} recognized`, true, observed.installed_runtime_profile_terminal_chain_recognized_receipt_path_recognized);
  assertEqual(`${label} artifact recognized`, true, observed.installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_recognized);
  const falseBoundaryFields = [
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_receipt_envelope_included',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_receipt_envelope_included',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_registry_public_key_material_included',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_registry_public_key_material_included',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_artifact_crypto_reproducible',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_artifact_crypto_reproducible',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_live_state_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_live_state_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_live_issuer_status_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_live_issuer_status_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_key_custody_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_key_custody_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_revocation_truth_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_revocation_truth_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_production_downstream_recognition_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_production_downstream_recognition_proven',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_public_external_attestation',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_public_external_attestation',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_sovereign_recognition',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_sovereign_recognition',
    'installed_runtime_profile_terminal_chain_recognized_receipt_path_current_machine_governance_proven',
    'installed_runtime_profile_terminal_chain_artifact_verification_recognized_receipt_path_current_machine_governance_proven',
  ];
  for (const field of falseBoundaryFields) {
    assertEqual(`${label} ${field} false`, false, observed[field]);
  }
}

function assertProductProofPathRecognizedReceiptPathMirror(label, boundary) {
  assert(`${label} evidence sha`, /^[a-f0-9]{64}$/.test(boundary.recognized_receipt_path_evidence_sha256));
  assert(`${label} artifact evidence sha`, /^[a-f0-9]{64}$/.test(boundary.recognized_receipt_path_evidence_artifact_verification_sha256));
  assertEqual(
    `${label} evidence hashes match`,
    boundary.recognized_receipt_path_evidence_sha256,
    boundary.recognized_receipt_path_evidence_artifact_verification_sha256
  );
  assertEqual(`${label} evidence hash match flag`, true, boundary.recognized_receipt_path_evidence_sha256_matches_artifact_verification);
  assertEqual(`${label} evidence bound to artifact body`, true, boundary.recognized_receipt_path_evidence_bound_to_artifact_body);
  assertEqual(
    `${label} source binding equals trusted registry binding`,
    boundary.trusted_issuer_registry_recognition_binding_sha256,
    boundary.recognized_receipt_path_evidence_source_binding_sha256
  );
  assertEqual(`${label} source binding match flag`, true, boundary.recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding);
  assertEqual(`${label} verdict`, 'RECOGNIZED', boundary.recognized_receipt_path_evidence_verdict);
  assertEqual(`${label} recognized`, true, boundary.recognized_receipt_path_evidence_recognized);
  for (const [field, value] of Object.entries(boundary)) {
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
      assertEqual(`${label} ${field} false`, false, value);
    }
  }
}

function stripRecognizedReceiptPathMirror(report) {
  for (const key of Object.keys(report.counts || {})) {
    if (key.includes('recognized_receipt_path')) {
      delete report.counts[key];
    }
  }
  for (const piece of report.puzzle_pieces || []) {
    for (const key of Object.keys(piece.observed || {})) {
      if (key.includes('recognized_receipt_path')) {
        delete piece.observed[key];
      }
    }
  }
  const productProofPath = report.puzzle_pieces
    ?.find((piece) => piece.id === 1)
    ?.observed
    ?.product_proof_path;
  for (const key of Object.keys(productProofPath?.terminal_chain_boundary || {})) {
    if (key.startsWith('recognized_receipt_path_evidence_')) {
      delete productProofPath.terminal_chain_boundary[key];
    }
  }
  return report;
}

const DYNAMIC_ONE_RUN_TERMINAL_CHAIN_IDENTITY_KEYS = new Set([
  'installed_runtime_profile_terminal_chain_artifact_verification_body_sha256',
  'installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256',
  'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256',
  'trusted_issuer_registry_recognition_binding_sha256',
  'registry_public_safe_summary_sha256',
  'trusted_issuer_registry_recognition_registry_fixture_contract_sha256',
  'trusted_issuer_registry_recognition_registry_public_safe_summary_sha256',
]);

function stripOneRunTerminalChainIdentity(report) {
  function stripDynamicKeys(container) {
    for (const key of Object.keys(container || {})) {
      if (
        key.includes('recognized_receipt_path') ||
        DYNAMIC_ONE_RUN_TERMINAL_CHAIN_IDENTITY_KEYS.has(key)
      ) {
        delete container[key];
      }
    }
  }

  stripDynamicKeys(report.counts);
  for (const piece of report.puzzle_pieces || []) {
    stripDynamicKeys(piece.observed);
    if (piece.observed?.product_proof_path) {
      delete piece.observed.product_proof_path.proof_pack_sha256;
      stripDynamicKeys(piece.observed.product_proof_path.trusted_issuer_registry_recognition);
    }
    stripDynamicKeys(piece.observed?.product_proof_path?.terminal_chain_boundary);
    delete piece.observed?.product_proof_path?.terminal_chain_boundary?.body_sha256;
  }
  return report;
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

function runZlarJson(args) {
  const result = runZlar(args);
  assertEqual(`zlar ${args.join(' ')} exits zero`, 0, result.status);
  assertEqual(`zlar ${args.join(' ')} emits no stderr`, '', result.stderr);
  return JSON.parse(result.stdout);
}

function freshTerminalChainEvidence() {
  const report = runZlarJson([
    'protected-records-installed-runtime-profile-terminal-chain',
    '--sample',
    '--json',
  ]);
  const artifact =
    buildProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(report);
  return {
    report,
    artifact,
    artifactVerification:
      verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(
        artifact
      ),
  };
}

const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;

console.log('\n-- sample command --');
const sampleRun = runZlar(['north-star-readiness', '--sample', '--json']);
assertEqual('sample json exits zero', 0, sampleRun.status);
assertEqual('sample json emits no stderr', '', sampleRun.stderr);
assert('sample output privacy safe', !unsafeOutputPattern.test(sampleRun.stdout));
const sampleReport = JSON.parse(sampleRun.stdout);
assert('sample report passes validation', assertNorthStarReadinessReport(sampleReport));
const sampleSummary = formatNorthStarReadinessSummary(sampleReport);
assert('sample summary privacy safe', !unsafeOutputPattern.test(sampleSummary));
assert('sample summary names private ZIP signal boundary', sampleSummary.includes('Private ZIP outside-machine signal validated: false'));
assert(
  'sample summary surfaces one-terminal bridge preservation',
  sampleSummary.includes(
    'One-terminal deployment bridge: preserved=true; authority_refusals_preserved=true; request_authority_material_accepted=false; recognized_receipt_mutates_once=true',
  ),
);
assert(
  'sample summary surfaces stronger North Star completion boundary',
  sampleSummary.includes(
    'Stronger North Star completion still false: enterprise_readiness=false; public_external_attestation=false; production_downstream_recognition=false; persistent_runtime_profile_installation=false',
  ),
);
assert(
  'sample summary keeps named deployment-profile proof below active persistent installation',
  sampleSummary.includes('Named deployment-profile real boundary is closed-proof only; active persistent installation still false: true'),
);
assert('sample summary names required trigger heading', sampleSummary.includes('Triggers required:'));
for (const trigger of sampleReport.v3_4_0_gate.triggers_required) {
  assert(`sample summary surfaces trigger ${trigger}`, sampleSummary.includes(`- ${trigger}`));
}
assertEqual('sample report type', NORTH_STAR_READINESS_REPORT_TYPE, sampleReport.report_type);
assertEqual('sample result not ready', 'NOT_READY_FOR_V3_4_0', sampleReport.result);
assertEqual('sample v3.4 gate false', false, sampleReport.v3_4_0_gate.ready);
assertEqual('sample puzzle pieces', 7, sampleReport.counts.puzzle_pieces_total);
assertEqual('sample proven count', 5, sampleReport.counts.proven_count);
assertEqual('sample partial count', 1, sampleReport.counts.partial_count);
assertEqual('sample unproven count', 1, sampleReport.counts.unproven_count);
assertEqual('sample governed lanes', 6, sampleReport.counts.governed_lanes);
assertEqual('sample service cases', 11, sampleReport.counts.service_preflight_cases);
assertEqual('sample installed runtime profile preflight verified', true, sampleReport.counts.installed_runtime_profile_preflight_verified);
assertEqual('sample installed runtime profile no-effect boundary', true, sampleReport.counts.installed_runtime_profile_preflight_no_effect_boundary_preserved);
assertEqual('sample installed runtime profile recognition contract preserved', true, sampleReport.counts.installed_runtime_profile_preflight_recognition_contract_preserved);
assertEqual('sample installed runtime profile recognition contract digest required', true, sampleReport.counts.installed_runtime_profile_recognition_contract_digest_required);
assertEqual('sample installed runtime profile recognition contract digest preserved', true, sampleReport.counts.installed_runtime_profile_recognition_contract_digest_preserved);
assert('sample installed runtime profile recognition contract digest sha', /^[a-f0-9]{64}$/.test(sampleReport.counts.installed_runtime_profile_recognition_contract_sha256));
assertEqual('sample installed runtime profile recognition proof preserved', true, sampleReport.counts.installed_runtime_profile_recognition_proof_preserved);
assertEqual('sample installed runtime profile service proof preserved', true, sampleReport.counts.installed_runtime_profile_service_proof_preserved);
assertEqual('sample installed runtime profile service artifact verification required', true, sampleReport.counts.installed_runtime_profile_service_artifact_verification_required);
assertEqual('sample installed runtime profile service artifact verification preserved', true, sampleReport.counts.installed_runtime_profile_service_artifact_verification_preserved);
assertEqual('sample installed runtime profile service artifact verification taxonomy required', true, sampleReport.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_required);
assertEqual('sample installed runtime profile service artifact verification taxonomy preserved', true, sampleReport.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved);
assert('sample installed runtime profile service artifact verification taxonomy sha', /^[a-f0-9]{64}$/.test(sampleReport.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256));
assertEqual('sample installed runtime profile terminal chain required', true, sampleReport.counts.installed_runtime_profile_terminal_chain_required);
assertEqual('sample installed runtime profile terminal chain preserved', true, sampleReport.counts.installed_runtime_profile_terminal_chain_preserved);
assertEqual('sample installed runtime profile terminal chain taxonomy required', true, sampleReport.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_required);
assertEqual('sample installed runtime profile terminal chain taxonomy preserved', true, sampleReport.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_preserved);
assert('sample installed runtime profile terminal chain taxonomy sha', /^[a-f0-9]{64}$/.test(sampleReport.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256));
assert('sample installed runtime profile terminal chain artifact verification taxonomy sha', /^[a-f0-9]{64}$/.test(sampleReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256));
assertEqual('sample installed runtime profile terminal chain named refusals required', true, sampleReport.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_required);
assertEqual('sample installed runtime profile terminal chain named refusals preserved', true, sampleReport.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved);
assert('sample installed runtime profile terminal chain named refusals sha', /^[a-f0-9]{64}$/.test(sampleReport.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256));
assert('sample installed runtime profile terminal chain artifact verification named refusals sha', /^[a-f0-9]{64}$/.test(sampleReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256));
assertEqual('sample installed runtime profile terminal chain recognition refusal groups required', true, sampleReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_required);
assertEqual('sample installed runtime profile terminal chain recognition refusal groups preserved', true, sampleReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved);
assert('sample installed runtime profile terminal chain recognition refusal groups sha', /^[a-f0-9]{64}$/.test(sampleReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256));
assert('sample installed runtime profile terminal chain artifact verification recognition refusal groups sha', /^[a-f0-9]{64}$/.test(sampleReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256));
assertEqual('sample installed runtime profile terminal chain recognition refusal group case IDs required', true, sampleReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required);
assertEqual('sample installed runtime profile terminal chain recognition refusal group case IDs preserved', true, sampleReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved);
assertEqual('sample installed runtime profile terminal chain recognition refusal group count', 3, sampleReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_count);
assertEqual('sample installed runtime profile terminal chain recognition refusal group case count', 18, sampleReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count);
assertEqual(
  'sample installed runtime profile terminal chain recognition refusal group case IDs',
  JSON.stringify(EXPECTED_RECOGNITION_REFUSAL_GROUP_CASE_IDS),
  JSON.stringify(sampleReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids)
);
assertEqual('sample installed runtime profile terminal chain artifact verification recognition refusal group count', 3, sampleReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count);
assertEqual('sample installed runtime profile terminal chain artifact verification recognition refusal group case count', 18, sampleReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count);
assertEqual(
  'sample installed runtime profile terminal chain artifact verification recognition refusal group case IDs',
  JSON.stringify(EXPECTED_RECOGNITION_REFUSAL_GROUP_CASE_IDS),
  JSON.stringify(sampleReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids)
);
assertEqual('sample installed runtime profile terminal chain nested binding required', true, sampleReport.counts.installed_runtime_profile_terminal_chain_nested_artifact_binding_required);
assertEqual('sample installed runtime profile terminal chain nested binding preserved', true, sampleReport.counts.installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved);
assertEqual('sample installed runtime profile terminal chain nested preflight type', EXPECTED_NESTED_PREFLIGHT_ARTIFACT_TYPE, sampleReport.counts.installed_runtime_profile_terminal_chain_nested_preflight_artifact_type);
assertEqual('sample installed runtime profile terminal chain nested service proof type', EXPECTED_NESTED_SERVICE_PROOF_ARTIFACT_TYPE, sampleReport.counts.installed_runtime_profile_terminal_chain_nested_service_proof_artifact_type);
assertEqual('sample installed runtime profile terminal chain artifact verification nested binding preserved', true, sampleReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved);
assertEqual('sample installed runtime profile terminal chain artifact verification nested preflight type', EXPECTED_NESTED_PREFLIGHT_ARTIFACT_TYPE, sampleReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_preflight_artifact_type);
assertEqual('sample installed runtime profile terminal chain artifact verification nested service proof type', EXPECTED_NESTED_SERVICE_PROOF_ARTIFACT_TYPE, sampleReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_service_proof_artifact_type);
assertEqual('sample installed runtime profile terminal chain trusted registry binding required', true, sampleReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_required);
assertEqual('sample installed runtime profile terminal chain trusted registry binding preserved', true, sampleReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved);
assert('sample installed runtime profile terminal chain trusted registry binding sha', /^[a-f0-9]{64}$/.test(sampleReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256));
assert('sample installed runtime profile terminal chain artifact verification trusted registry binding sha', /^[a-f0-9]{64}$/.test(sampleReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256));
assertEqual(
  'sample installed runtime profile terminal chain trusted registry binding hashes match',
  sampleReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256,
  sampleReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256
);
assertEqual(
  'sample installed runtime profile terminal chain taxonomy hashes match',
  sampleReport.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256,
  sampleReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256
);
assertEqual(
  'sample installed runtime profile terminal chain named refusal hashes match',
  sampleReport.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256,
  sampleReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256
);
assertEqual(
  'sample installed runtime profile terminal chain recognition refusal group hashes match',
  sampleReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256,
  sampleReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256
);
assertObservedRecognizedReceiptPathMirror(
  'sample installed runtime profile terminal chain recognized receipt path mirror',
  sampleReport.counts
);
assertObservedDeploymentProfileAuthorityRefusalMirror(
  'sample installed runtime profile terminal chain deployment-profile authority refusal mirror',
  sampleReport.counts
);
assertEqual('sample runtime taxonomy preserved', true, sampleReport.counts.runtime_refusal_taxonomy_preserved);
assertEqual('sample product proof path verified', true, sampleReport.counts.product_proof_path_verified);
assertEqual('sample product proof path deployment bridge required', true, sampleReport.counts.product_proof_path_deployment_profile_authority_bridge_required);
assertEqual('sample product proof path deployment bridge preserved', true, sampleReport.counts.product_proof_path_deployment_profile_authority_bridge_preserved);
assertEqual('sample product proof path deployment authority refusals required', true, sampleReport.counts.product_proof_path_deployment_profile_authority_refusals_required);
assertEqual('sample product proof path deployment authority refusals preserved', true, sampleReport.counts.product_proof_path_deployment_profile_authority_refusals_preserved);
const sampleHistoricalLifecycle =
  sampleReport.supplemental_evidence
    .historical_supplied_local_active_persistent_profile_lifecycle;
assertEqual('sample historical active persistent lifecycle absent', false, sampleHistoricalLifecycle.provided);
assertEqual('sample historical active persistent lifecycle count absent', false, sampleReport.counts.historical_active_persistent_profile_lifecycle_provided);
assertEqual('sample historical active persistent lifecycle not verified', false, sampleReport.counts.historical_active_persistent_profile_lifecycle_verified);
assertEqual('sample historical active persistent lifecycle not current install', false, sampleReport.counts.historical_active_persistent_profile_lifecycle_current_installation);
assertEqual('sample historical active persistent lifecycle not product proof completion', false, sampleReport.counts.historical_active_persistent_profile_lifecycle_product_proof_path_completion);
assertEqual('sample historical active persistent lifecycle not enterprise completion', false, sampleReport.counts.historical_active_persistent_profile_lifecycle_enterprise_deployment_profile_completion);
assertEqual('sample external attestation false', false, sampleReport.claim_boundary.public_external_attestation);
assertEqual('sample production authority false', false, sampleReport.claim_boundary.production_authority);
assertEqual('sample current-machine governance false', false, sampleReport.claim_boundary.current_machine_governance);
const sampleTrustedIssuer = sampleReport.puzzle_pieces.find((piece) => piece.id === 4);
assertEqual('sample trusted issuer remains partial', 'portable_fixture_partial', sampleTrustedIssuer.status);
assertEqual(
  'sample trusted issuer completion proof absent',
  false,
  sampleTrustedIssuer.observed.trusted_receipt_issuer_completion_proof.provided,
);
assertEqual(
  'sample trusted issuer selected surface names target',
  TRUSTED_RECEIPT_ISSUER_COMPLETION_SURFACE_ID,
  sampleTrustedIssuer.observed.trusted_receipt_issuer_completion_proof.selected_surface_id,
);
assertEqual(
  'sample trusted issuer completion core sentence preserved',
  TRUSTED_RECEIPT_ISSUER_COMPLETION_CORE_SENTENCE,
  sampleTrustedIssuer.observed.trusted_receipt_issuer_completion_proof.core_sentence,
);

console.log('\n-- explicit trusted issuer completion proof --');
const completionTerminalChainEvidence = freshTerminalChainEvidence();
const completionReport = buildNorthStarReadinessReport({
  evidenceModel: NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE,
  productProofPathReport: runZlarJson(['product-proof-path', '--json']),
  proofSmokeVerification: runZlarJson(['proof-smoke', 'verify', '--historical', '--sample', '--require-file-sha', 'de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268', '--require-sha', '8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80', '--json']),
  localProofPackVerification: runZlarJson(['local-proof-pack', 'verify', '--sample', '--json']),
  servicePreflightVerification: runZlarJson(['protected-records-service-preflight', 'verify', '--sample', '--json']),
  runtimeLocalActivationVerification: runZlarJson(['protected-records-runtime-local-activation', 'verify', '--sample', '--json']),
  runtimeProfileInstallationVerification: runZlarJson(['protected-records-runtime-profile-installation', 'verify', '--sample', '--json']),
  installedRuntimeProfilePreflightVerification: runZlarJson(['protected-records-installed-runtime-profile-preflight', 'verify', '--sample', '--json']),
  installedRuntimeProfileRecognitionProof: runZlarJson(['protected-records-installed-runtime-profile-recognition-proof', '--sample', '--json']),
  installedRuntimeProfileServiceProof: runZlarJson(['protected-records-installed-runtime-profile-service-proof', '--sample', '--json']),
  installedRuntimeProfileServiceProofArtifactVerification: runZlarJson(['protected-records-installed-runtime-profile-service-proof', 'verify', '--sample', '--json']),
  installedRuntimeProfileTerminalChain: completionTerminalChainEvidence.report,
  installedRuntimeProfileTerminalChainArtifact:
    completionTerminalChainEvidence.artifact,
  installedRuntimeProfileTerminalChainArtifactVerification:
    completionTerminalChainEvidence.artifactVerification,
  coverageMap: runZlarJson(['coverage', '--sample', '--require-governed', '--json']),
  trustedReceiptIssuerCompletionProof: buildTrustedReceiptIssuerCompletionProofTestVector(),
});
assert('completion report passes validation', assertNorthStarReadinessReport(completionReport));
assertEqual('completion report proven count', 6, completionReport.counts.proven_count);
assertEqual('completion report partial count', 0, completionReport.counts.partial_count);
assertEqual('completion report unproven count unchanged', 1, completionReport.counts.unproven_count);
assertEqual('completion report global key custody remains false', false, completionReport.claim_boundary.key_custody);
assertEqual('completion report global revocation truth remains false', false, completionReport.claim_boundary.revocation_truth);
assertEqual('completion report production downstream remains false', false, completionReport.claim_boundary.production_downstream_recognition);
const completionTrustedIssuer = completionReport.puzzle_pieces.find((piece) => piece.id === 4);
assertEqual(
  'completion trusted issuer status',
  'operator_owned_private_core_completion_proven',
  completionTrustedIssuer.status,
);
assertEqual(
  'completion selected surface',
  TRUSTED_RECEIPT_ISSUER_COMPLETION_SURFACE_ID,
  completionTrustedIssuer.observed.trusted_receipt_issuer_completion_proof.selected_surface_id,
);
assertEqual(
  'completion core sentence',
  TRUSTED_RECEIPT_ISSUER_COMPLETION_CORE_SENTENCE,
  completionTrustedIssuer.observed.trusted_receipt_issuer_completion_proof.core_sentence,
);
assertEqual(
  'completion receipt validity stays distinct from intention',
  true,
  completionTrustedIssuer.observed.trusted_receipt_issuer_completion_proof.receipt_validity_distinct_from_human_intention,
);
assertEqual(
  'completion issuer recognition stays distinct from human yes',
  true,
  completionTrustedIssuer.observed.trusted_receipt_issuer_completion_proof.issuer_recognition_distinct_from_human_yes,
);
assertEqual(
  'completion authority event stays distinct from legal consent',
  true,
  completionTrustedIssuer.observed.trusted_receipt_issuer_completion_proof.authority_event_distinct_from_legal_consent,
);

console.log('\n-- explicit one-terminal trusted issuer completion proof --');
const oneTerminalCompletionProof = buildTrustedReceiptIssuerCompletionProofTestVector({
  selected_surface_id: TRUSTED_RECEIPT_ISSUER_COMPLETION_PRIVATE_OPERATOR_RECORDS_TERMINAL_SURFACE_ID,
});
const oneTerminalCompletionTerminalChainEvidence = freshTerminalChainEvidence();
const oneTerminalCompletionReport = buildNorthStarReadinessReport({
  evidenceModel: NORTH_STAR_READINESS_EVIDENCE_MODEL_SAMPLE,
  productProofPathReport: runZlarJson(['product-proof-path', '--json']),
  proofSmokeVerification: runZlarJson(['proof-smoke', 'verify', '--historical', '--sample', '--require-file-sha', 'de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268', '--require-sha', '8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80', '--json']),
  localProofPackVerification: runZlarJson(['local-proof-pack', 'verify', '--sample', '--json']),
  servicePreflightVerification: runZlarJson(['protected-records-service-preflight', 'verify', '--sample', '--json']),
  runtimeLocalActivationVerification: runZlarJson(['protected-records-runtime-local-activation', 'verify', '--sample', '--json']),
  runtimeProfileInstallationVerification: runZlarJson(['protected-records-runtime-profile-installation', 'verify', '--sample', '--json']),
  installedRuntimeProfilePreflightVerification: runZlarJson(['protected-records-installed-runtime-profile-preflight', 'verify', '--sample', '--json']),
  installedRuntimeProfileRecognitionProof: runZlarJson(['protected-records-installed-runtime-profile-recognition-proof', '--sample', '--json']),
  installedRuntimeProfileServiceProof: runZlarJson(['protected-records-installed-runtime-profile-service-proof', '--sample', '--json']),
  installedRuntimeProfileServiceProofArtifactVerification: runZlarJson(['protected-records-installed-runtime-profile-service-proof', 'verify', '--sample', '--json']),
  installedRuntimeProfileTerminalChain:
    oneTerminalCompletionTerminalChainEvidence.report,
  installedRuntimeProfileTerminalChainArtifact:
    oneTerminalCompletionTerminalChainEvidence.artifact,
  installedRuntimeProfileTerminalChainArtifactVerification:
    oneTerminalCompletionTerminalChainEvidence.artifactVerification,
  coverageMap: runZlarJson(['coverage', '--sample', '--require-governed', '--json']),
  trustedReceiptIssuerCompletionProof: oneTerminalCompletionProof,
});
assert(
  'one-terminal completion report passes validation',
  assertNorthStarReadinessReport(oneTerminalCompletionReport),
);
assertEqual('one-terminal completion report proven count', 6, oneTerminalCompletionReport.counts.proven_count);
assertEqual('one-terminal completion global key custody remains false', false, oneTerminalCompletionReport.claim_boundary.key_custody);
assertEqual('one-terminal completion global revocation truth remains false', false, oneTerminalCompletionReport.claim_boundary.revocation_truth);
assertEqual('one-terminal completion production downstream remains false', false, oneTerminalCompletionReport.claim_boundary.production_downstream_recognition);
const oneTerminalCompletionTrustedIssuer =
  oneTerminalCompletionReport.puzzle_pieces.find((piece) => piece.id === 4);
assertEqual(
  'one-terminal completion trusted issuer status',
  'operator_owned_private_core_completion_proven',
  oneTerminalCompletionTrustedIssuer.status,
);
assertEqual(
  'one-terminal completion selected surface names private-operator terminal',
  TRUSTED_RECEIPT_ISSUER_COMPLETION_PRIVATE_OPERATOR_RECORDS_TERMINAL_SURFACE_ID,
  oneTerminalCompletionTrustedIssuer.observed.trusted_receipt_issuer_completion_proof.selected_surface_id,
);
assertEqual(
  'one-terminal completion does not rename readiness selected terminal',
  TRUSTED_RECEIPT_ISSUER_COMPLETION_SURFACE_ID,
  oneTerminalCompletionReport.selected_terminal.surface_id,
);
const sampleProductProof = sampleReport.puzzle_pieces.find((piece) => piece.id === 1);
assertEqual('sample product proof path summary provided', true, sampleProductProof.observed.product_proof_path.provided);
assertEqual('sample product proof path report type', 'zlar-product-proof-path-v1', sampleProductProof.observed.product_proof_path.report_type);
assertEqual('sample product proof path result', 'PASS', sampleProductProof.observed.product_proof_path.result);
assertEqual(
  'sample product proof path evidence model',
  'fresh-local-fixture-proof-pack-terminal-chain-and-deployment-profile-authority-bridge',
  sampleProductProof.observed.product_proof_path.evidence_model,
);
assertEqual('sample product proof path gates passed', true, sampleProductProof.observed.product_proof_path.acceptance_gate_passed);
assertEqual('sample product proof path forbidden claims false', true, sampleProductProof.observed.product_proof_path.forbidden_claims_false);
assertEqual('sample product proof path no live probing', false, sampleProductProof.observed.product_proof_path.live_probing);
assertRuntimeProfileIdentityPolicy(
  'sample product proof path proof-pack runtime-profile identity policy',
  sampleProductProof.observed.product_proof_path.proof_pack_runtime_profile_identity_policy,
);
assertEqual(
  'sample product proof path Claude hook replay summary provided',
  true,
  sampleProductProof.observed.product_proof_path.proof_pack_claude_hook_contract_replay.provided,
);
assert(
  'sample product proof path Claude hook replay contract hash present',
  /^[a-f0-9]{64}$/.test(
    sampleProductProof.observed.product_proof_path
      .proof_pack_claude_hook_contract_replay.hook_replay_contract_sha256,
  ),
);
assert(
  'sample product proof path Claude hook replay component hash present',
  /^[a-f0-9]{64}$/.test(
    sampleProductProof.observed.product_proof_path
      .proof_pack_claude_hook_contract_replay.component_sha256,
  ),
);
assert(
  'sample product proof path Claude hook replay case evidence hash present',
  /^[a-f0-9]{64}$/.test(
    sampleProductProof.observed.product_proof_path
      .proof_pack_claude_hook_contract_replay.case_evidence_sha256,
  ),
);
const sampleProductProofDownstreamRefusal =
  sampleProductProof.observed.product_proof_path.downstream_refusal_boundary;
assertEqual('sample product proof path downstream boundary provided', true, sampleProductProofDownstreamRefusal.provided);
assertEqual('sample product proof path downstream recognized boarded', true, sampleProductProofDownstreamRefusal.recognized_boarded);
assertEqual('sample product proof path downstream recognized marker delta', 1, sampleProductProofDownstreamRefusal.recognized_marker_count_delta);
assertEqual('sample product proof path downstream final marker count', 1, sampleProductProofDownstreamRefusal.final_marker_count);
assertEqual('sample product proof path downstream refusal case count', 11, sampleProductProofDownstreamRefusal.refusal_case_count);
assertEqual('sample product proof path downstream refusals unboarded', true, sampleProductProofDownstreamRefusal.all_refusals_unboarded);
assertEqual('sample product proof path downstream refusal marker deltas zero', true, sampleProductProofDownstreamRefusal.all_refusal_marker_count_deltas_zero);
assert('sample product proof path downstream refusal reasons present', sampleProductProofDownstreamRefusal.refusal_reasons.includes('receipt_missing') && sampleProductProofDownstreamRefusal.refusal_reasons.includes('receipt_stale'));
assertEqual(
  'sample product proof path terminal chain boundary observed',
  true,
  sampleProductProof.observed.product_proof_path.terminal_chain_boundary_observed,
);
assertEqual(
  'sample product proof path terminal chain artifact verified',
  true,
  sampleProductProof.observed.product_proof_path.terminal_chain_artifact_verified,
);
const sampleProductProofTerminalChain =
  sampleProductProof.observed.product_proof_path.terminal_chain_boundary;
assertEqual('sample product proof path terminal chain provided', true, sampleProductProofTerminalChain.provided);
assertEqual('sample product proof path terminal chain verified', true, sampleProductProofTerminalChain.verified);
assertEqual(
  'sample product proof path terminal chain payload type',
  'zlar-protected-records-installed-runtime-profile-terminal-chain-v1',
  sampleProductProofTerminalChain.payload_type,
);
assert('sample product proof path terminal chain body sha', /^[a-f0-9]{64}$/.test(sampleProductProofTerminalChain.body_sha256));
assertEqual(
  'sample product proof path terminal chain generated root preflighted',
  true,
  sampleProductProofTerminalChain.generated_installed_root_preflighted,
);
assertEqual(
  'sample product proof path terminal chain generated service artifact verified',
  true,
  sampleProductProofTerminalChain.generated_service_proof_artifact_verified,
);
assertEqual(
  'sample product proof path terminal chain recognized write boarded',
  true,
  sampleProductProofTerminalChain.recognized_write_boarded,
);
assertEqual(
  'sample product proof path terminal chain all refusals before mutation',
  true,
  sampleProductProofTerminalChain.all_required_refusals_before_mutation,
);
for (const [name, expected] of Object.entries(
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS,
)) {
  assertEqual(
    `sample product proof path terminal chain named refusal ${name} case`,
    expected.case_id,
    sampleProductProofTerminalChain.named_receipt_refusals[name].case_id,
  );
  assertEqual(
    `sample product proof path terminal chain named refusal ${name} reason`,
    expected.reason_code,
    sampleProductProofTerminalChain.named_receipt_refusals[name].reason_code,
  );
  assertEqual(
    `sample product proof path terminal chain named refusal ${name} before mutation`,
    true,
    sampleProductProofTerminalChain.named_receipt_refusals[name].refused_before_mutation,
  );
}
assertEqual(
  'sample product proof path terminal chain required refusals',
  18,
  sampleProductProofTerminalChain.required_refusal_case_count,
);
assertEqual(
  'sample product proof path terminal chain recognition refusal group count',
  3,
  sampleProductProofTerminalChain.recognition_refusal_group_count,
);
assertEqual(
  'sample product proof path terminal chain recognition refusal group case count',
  18,
  sampleProductProofTerminalChain.recognition_refusal_group_case_count,
);
assertEqual(
  'sample product proof path terminal chain recognition refusal group case IDs preserved',
  true,
  sampleProductProofTerminalChain.recognition_refusal_group_case_ids_preserved,
);
assertEqual(
  'sample product proof path terminal chain recognition refusal group case IDs',
  JSON.stringify(EXPECTED_RECOGNITION_REFUSAL_GROUP_CASE_IDS),
  JSON.stringify(sampleProductProofTerminalChain.recognition_refusal_group_case_ids),
);
assert('sample product proof path terminal chain binding sha', /^[a-f0-9]{64}$/.test(sampleProductProofTerminalChain.trusted_issuer_registry_recognition_binding_sha256));
assertEqual(
  'sample product proof path terminal chain binding matches verification',
  true,
  sampleProductProofTerminalChain.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification,
);
assertEqual(
  'sample product proof path terminal chain trusted registry verdict',
  'RECOGNIZED',
  sampleProductProofTerminalChain.trusted_issuer_registry_recognition_verdict,
);
assertEqual(
  'sample product proof path terminal chain trusted registry recognized',
  true,
  sampleProductProofTerminalChain.trusted_issuer_registry_recognition_recognized,
);
assertEqual(
  'sample product proof path terminal chain trusted registry signature valid',
  true,
  sampleProductProofTerminalChain.trusted_issuer_registry_recognition_signature_valid,
);
assertEqual(
  'sample product proof path terminal chain trusted registry fixture validated',
  true,
  sampleProductProofTerminalChain.trusted_issuer_registry_recognition_registry_fixture_validated,
);
assertEqual(
  'sample product proof path terminal chain trusted registry fixture evaluated',
  true,
  sampleProductProofTerminalChain.trusted_issuer_registry_recognition_registry_fixture_evaluated,
);
assertEqual(
  'sample product proof path terminal chain trusted registry rule evaluated',
  true,
  sampleProductProofTerminalChain.trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated,
);
assertEqual(
  'sample product proof path terminal chain trusted registry evaluator type',
  'downstream-recognition-rule-v1',
  sampleProductProofTerminalChain.trusted_issuer_registry_recognition_registry_evaluation_result_type,
);
assertEqual(
  'sample product proof path terminal chain trusted registry audit bound',
  true,
  sampleProductProofTerminalChain.trusted_issuer_registry_recognition_required_audit_event_id_bound,
);
assertEqual(
  'sample product proof path terminal chain trusted registry detail bound',
  true,
  sampleProductProofTerminalChain.trusted_issuer_registry_recognition_required_detail_hash_bound,
);
assert('sample product proof path terminal chain refusal sha', /^[a-f0-9]{64}$/.test(sampleProductProofTerminalChain.trusted_issuer_registry_recognition_refusals_sha256));
assertEqual(
  'sample product proof path terminal chain refusal hash matches binding',
  true,
  sampleProductProofTerminalChain.trusted_issuer_registry_recognition_refusal_hash_matches_binding,
);
assertEqual(
  'sample product proof path terminal chain trusted registry refusal IDs',
  JSON.stringify(EXPECTED_TRUSTED_ISSUER_REGISTRY_REFUSAL_CASE_IDS),
  JSON.stringify(sampleProductProofTerminalChain.trusted_issuer_registry_recognition_refusal_case_ids),
);
assertEqual(
  'sample product proof path terminal chain trusted registry refusal reason codes',
  JSON.stringify(EXPECTED_TRUSTED_ISSUER_REGISTRY_REFUSAL_REASON_CODES),
  JSON.stringify(sampleProductProofTerminalChain.trusted_issuer_registry_recognition_refusal_reason_codes),
);
assertProductProofPathRecognizedReceiptPathMirror(
  'sample product proof path terminal chain recognized receipt path mirror',
  sampleProductProofTerminalChain
);
assertEqual(
  'sample product proof path terminal chain registry receipt contract bound',
  true,
  sampleProductProofTerminalChain.registry_receipt_contract_hash_bound,
);
assertEqual(
  'sample product proof path terminal chain selected profile bound',
  true,
  sampleProductProofTerminalChain.selected_profile_hash_bound,
);
assertEqual(
  'sample product proof path terminal chain recognition contract bound',
  true,
  sampleProductProofTerminalChain.recognition_contract_hash_bound,
);
assertEqual(
  'sample product proof path terminal chain decision bound',
  true,
  sampleProductProofTerminalChain.terminal_chain_decision_bound,
);
assertEqual(
  'sample product proof path terminal chain nested binding preserved',
  true,
  sampleProductProofTerminalChain.nested_artifact_binding_preserved,
);
assertEqual(
  'sample product proof path terminal chain public key omitted',
  false,
  sampleProductProofTerminalChain.registry_public_key_material_included,
);
assertEqual(
  'sample product proof path terminal chain receipt envelope omitted',
  false,
  sampleProductProofTerminalChain.receipt_envelope_included,
);
assertEqual(
  'sample product proof path terminal chain no artifact-only crypto reconstruction',
  false,
  sampleProductProofTerminalChain.cryptographic_evidence_reproducible_from_artifact,
);
assertEqual(
  'sample product proof path terminal chain no current-machine governance',
  false,
  sampleProductProofTerminalChain.current_machine_governance_proven,
);
assertEqual(
  'sample product proof path terminal chain no external attestation',
  false,
  sampleProductProofTerminalChain.external_attestation,
);
assertEqual(
  'sample product proof path deployment bridge observed',
  true,
  sampleProductProof.observed.product_proof_path.deployment_profile_authority_bridge_observed,
);
const sampleDeploymentBridge =
  sampleProductProof.observed.product_proof_path.deployment_profile_authority_bridge;
assertEqual('sample product proof path deployment bridge provided', true, sampleDeploymentBridge.provided);
assertEqual(
  'sample product proof path deployment bridge proof type',
  'zlar-protected-records-one-terminal-deployment-profile-proof-v1',
  sampleDeploymentBridge.proof_type,
);
assertEqual(
  'sample product proof path deployment bridge evidence model',
  'local-fixture-one-terminal-deployment-profile-authority-bridge',
  sampleDeploymentBridge.evidence_model,
);
assertEqual('sample product proof path deployment bridge live probing false', false, sampleDeploymentBridge.live_probing);
assert('sample product proof path deployment bridge profile sha', /^[a-f0-9]{64}$/.test(sampleDeploymentBridge.deployment_profile_sha256));
assert('sample product proof path deployment bridge runtime sha', /^[a-f0-9]{64}$/.test(sampleDeploymentBridge.runtime_profile_sha256));
assertEqual('sample product proof path deployment bridge artifact authoritative', true, sampleDeploymentBridge.deployment_profile_artifact_authoritative);
assertEqual('sample product proof path deployment bridge authority refusal count', 5, sampleDeploymentBridge.deployment_profile_authority_refusal_case_count);
assertEqual('sample product proof path deployment bridge authority refusals before service proof', true, sampleDeploymentBridge.deployment_profile_authority_refusals_before_service_proof);
assertEqual('sample product proof path deployment bridge authority refusals before mutation', true, sampleDeploymentBridge.deployment_profile_authority_refusals_before_mutation);
assertEqual('sample product proof path deployment bridge authority refusal service proof not started', false, sampleDeploymentBridge.deployment_profile_authority_refusal_service_proof_started);
assertEqual('sample product proof path deployment bridge stale artifact refused before service proof', true, sampleDeploymentBridge.stale_deployment_profile_artifact_refused_before_service_proof);
assertEqual('sample product proof path deployment bridge profile mismatch refused before service proof', true, sampleDeploymentBridge.profile_recognition_mismatch_refused_before_service_proof);
assertEqual('sample product proof path deployment bridge latest selection refused before service proof', true, sampleDeploymentBridge.latest_profile_selection_refused_before_service_proof);
assertEqual('sample product proof path deployment bridge request authority refused before service proof', true, sampleDeploymentBridge.request_stream_authority_material_refused_before_service_proof);
assertEqual('sample product proof path deployment bridge explicit id+sha', true, sampleDeploymentBridge.selected_by_explicit_id_and_sha);
assertEqual('sample product proof path deployment bridge no latest', false, sampleDeploymentBridge.selects_latest_profile);
assertEqual('sample product proof path deployment bridge preflight verified', true, sampleDeploymentBridge.preflight_artifact_verified);
assertEqual('sample product proof path deployment bridge recognized once', true, sampleDeploymentBridge.recognized_receipt_mutates_once);
assertEqual('sample product proof path deployment bridge recognized delta one', 1, sampleDeploymentBridge.recognized_state_entry_count_delta);
assertEqual('sample product proof path deployment bridge required refusals', 18, sampleDeploymentBridge.required_refusal_case_count);
assertEqual('sample product proof path deployment bridge observed refusals', 18, sampleDeploymentBridge.observed_refusal_case_count);
assertEqual('sample product proof path deployment bridge all refusals before mutation', true, sampleDeploymentBridge.all_required_refusals_before_mutation);
assertEqual('sample product proof path deployment bridge agent authority refused', true, sampleDeploymentBridge.agent_supplied_authority_refused_before_mutation);
assertEqual('sample product proof path deployment bridge direct API refused', true, sampleDeploymentBridge.direct_api_refused_before_mutation);
assertEqual('sample product proof path deployment bridge downstream refusal proven', true, sampleDeploymentBridge.downstream_refusal_proven);
assertEqual('sample product proof path deployment bridge request authority not accepted', false, sampleDeploymentBridge.request_stream_authority_material_accepted);
assertEqual('sample product proof path deployment bridge current-machine false', false, sampleDeploymentBridge.current_machine_governance);
assertEqual('sample product proof path deployment bridge production downstream false', false, sampleDeploymentBridge.production_downstream_recognition);
assertEqual('sample product proof path deployment bridge production authority false', false, sampleDeploymentBridge.production_authority);
assertEqual('sample product proof path deployment bridge enterprise readiness false', false, sampleDeploymentBridge.enterprise_readiness);
assertEqual('sample product proof path deployment bridge external attestation false', false, sampleDeploymentBridge.external_attestation);
assertEqual('sample product proof path deployment bridge sovereign false', false, sampleDeploymentBridge.sovereign_recognition);
assertEqual('sample product proof path deployment bridge unrouted false', false, sampleDeploymentBridge.unrouted_surface_coverage);
assertEqual(
  'sample product proof path trusted registry observed',
  true,
  sampleProductProof.observed.product_proof_path.trusted_issuer_registry_recognition_observed,
);
assertEqual(
  'sample product proof path trusted registry type',
  'trusted-receipt-issuers-v2',
  sampleProductProof.observed.product_proof_path.trusted_issuer_registry_recognition.registry_type,
);
assertEqual(
  'sample product proof path trusted registry recognized',
  true,
  sampleProductProof.observed.product_proof_path.trusted_issuer_registry_recognition.recognized,
);
assertEqual(
  'sample product proof path trusted registry fixture evaluated',
  true,
  sampleProductProof.observed.product_proof_path.trusted_issuer_registry_recognition
    .registry_fixture_evaluated,
);
assertEqual(
  'sample product proof path trusted registry evaluator result type',
  'downstream-recognition-rule-v1',
  sampleProductProof.observed.product_proof_path.trusted_issuer_registry_recognition
    .registry_evaluation_result_type,
);
assertEqual(
  'sample product proof path trusted registry issuer count',
  1,
  sampleProductProof.observed.product_proof_path.trusted_issuer_registry_recognition
    .registry_trusted_issuer_count,
);
assertEqual(
  'sample product proof path malformed registry fail closed',
  true,
  sampleProductProof.observed.product_proof_path.trusted_issuer_registry_recognition
    .malformed_registry_fail_closed_before_verdict,
);
assertEqual(
  'sample product proof path trusted registry audit event bound',
  true,
  sampleProductProof.observed.product_proof_path.trusted_issuer_registry_recognition
    .required_audit_event_id_bound,
);
assertEqual(
  'sample product proof path trusted registry detail hash bound',
  true,
  sampleProductProof.observed.product_proof_path.trusted_issuer_registry_recognition
    .required_detail_hash_bound,
);
assertEqual(
  'sample product proof path trusted registry no live registry',
  false,
  sampleProductProof.observed.product_proof_path.trusted_issuer_registry_recognition
    .proves_live_registry,
);
assertEqual(
  'sample product proof path trusted registry no key custody',
  false,
  sampleProductProof.observed.product_proof_path.trusted_issuer_registry_recognition
    .proves_key_custody,
);
assertEqual(
  'sample product proof path trusted registry no current-machine governance',
  false,
  sampleProductProof.observed.product_proof_path.trusted_issuer_registry_recognition
    .proves_current_machine_governance,
);
assertEqual('sample simulated human authorization verified', true, sampleProductProof.observed.simulated_human_authorization_verified);
assertEqual('sample human authorization summary provided', true, sampleProductProof.observed.human_authorization.provided);
assertEqual('sample human authorization channel simulated', 'simulated-human-fixture', sampleProductProof.observed.human_authorization.approval_channel);
assertEqual('sample human authorization pending not boarded', false, sampleProductProof.observed.human_authorization.pending_boarded);
assertEqual('sample human authorization authorized boarded', true, sampleProductProof.observed.human_authorization.authorized_boarded);
assertEqual('sample human authorization denied not boarded', false, sampleProductProof.observed.human_authorization.denied_boarded);
assertEqual('sample human authorization live health false', false, sampleProductProof.observed.human_authorization.live_approval_channel_health);
const sampleEnterpriseProfile = sampleReport.puzzle_pieces.find((piece) => piece.id === 3);
assertEqual('sample enterprise profile status upgraded', 'local_disposable_profile_refusal_proven', sampleEnterpriseProfile.status);
assertEqual('sample installed runtime profile preflight observed verified', true, sampleEnterpriseProfile.observed.installed_runtime_profile_preflight_verified);
assertEqual('sample installed runtime profile preflight observed read only', true, sampleEnterpriseProfile.observed.installed_runtime_profile_preflight_read_only);
assertEqual('sample installed runtime profile preflight observed selected', true, sampleEnterpriseProfile.observed.installed_runtime_profile_preflight_selected_by_explicit_id_and_sha);
assertEqual('sample installed runtime profile preflight observed no latest', false, sampleEnterpriseProfile.observed.installed_runtime_profile_preflight_selects_latest);
assertEqual('sample installed runtime profile preflight observed no install', false, sampleEnterpriseProfile.observed.installed_runtime_profile_preflight_installation_performed);
assertEqual('sample installed runtime profile preflight observed no activation', false, sampleEnterpriseProfile.observed.installed_runtime_profile_preflight_activation_performed);
assertEqual('sample installed runtime profile preflight observed recognition contract preserved', true, sampleEnterpriseProfile.observed.installed_runtime_profile_preflight_recognition_contract_preserved);
assertEqual('sample installed runtime profile preflight observed recognition boundary', 'service-configured-recognition-rule', sampleEnterpriseProfile.observed.installed_runtime_profile_preflight_recognition_boundary);
assertEqual('sample installed runtime profile preflight observed mutation route', 'receipt-recognition-before-runtime-state-mutation', sampleEnterpriseProfile.observed.installed_runtime_profile_preflight_mutation_authoritative_route);
assertEqual('sample installed runtime profile preflight observed recognition rule not agent supplied', false, sampleEnterpriseProfile.observed.installed_runtime_profile_preflight_recognition_rule_supplied_by_agent);
assertEqual('sample installed runtime profile preflight observed no downstream refusal', false, sampleEnterpriseProfile.observed.installed_runtime_profile_preflight_downstream_refusal_proven);
assertEqual('sample installed runtime profile preflight observed no current-machine governance', false, sampleEnterpriseProfile.observed.installed_runtime_profile_preflight_current_machine_governance_proven);
assertEqual('sample installed runtime profile service proof observed verified', true, sampleEnterpriseProfile.observed.installed_runtime_profile_service_proof_verified);
assertEqual('sample installed runtime profile service artifact verification observed verified', true, sampleEnterpriseProfile.observed.installed_runtime_profile_service_artifact_verification_verified);
assert('sample installed runtime profile service artifact verification observed sha', /^[a-f0-9]{64}$/.test(sampleEnterpriseProfile.observed.installed_runtime_profile_service_artifact_verification_body_sha256));
assertEqual('sample installed runtime profile service artifact verification observed taxonomy preserved', true, sampleEnterpriseProfile.observed.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved);
assert('sample installed runtime profile service artifact verification observed taxonomy sha', /^[a-f0-9]{64}$/.test(sampleEnterpriseProfile.observed.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256));
assertEqual('sample installed runtime profile terminal chain observed verified', true, sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_verified);
assertEqual('sample installed runtime profile terminal chain artifact verification observed verified', true, sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_artifact_verification_verified);
assert('sample installed runtime profile terminal chain artifact verification observed sha', /^[a-f0-9]{64}$/.test(sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_artifact_verification_body_sha256));
assertEqual('sample installed runtime profile terminal chain observed taxonomy preserved', true, sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_refusal_taxonomy_preserved);
assert('sample installed runtime profile terminal chain observed taxonomy sha', /^[a-f0-9]{64}$/.test(sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256));
assertEqual('sample installed runtime profile terminal chain observed named refusals preserved', true, sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved);
assert('sample installed runtime profile terminal chain observed named refusals sha', /^[a-f0-9]{64}$/.test(sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256));
assertEqual('sample installed runtime profile terminal chain observed recognition refusal groups preserved', true, sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved);
assert('sample installed runtime profile terminal chain observed recognition refusal groups sha', /^[a-f0-9]{64}$/.test(sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256));
assertEqual(
  'sample installed runtime profile terminal chain observed taxonomy hashes match',
  sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256,
  sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256
);
assertEqual(
  'sample installed runtime profile terminal chain observed named refusal hashes match',
  sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256,
  sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256
);
assertEqual(
  'sample installed runtime profile terminal chain observed recognition refusal group hashes match',
  sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256,
  sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256
);
assertObservedRecognitionRefusalGroupCaseIds(
  'sample installed runtime profile terminal chain observed recognition refusal group',
  sampleEnterpriseProfile.observed
);
assertObservedNestedArtifactBinding(
  'sample installed runtime profile terminal chain observed nested binding',
  sampleEnterpriseProfile.observed
);
assertObservedTrustedIssuerRegistryBinding(
  'sample installed runtime profile terminal chain observed trusted registry binding',
  sampleEnterpriseProfile.observed
);
assertObservedRecognizedReceiptPathMirror(
  'sample installed runtime profile terminal chain observed recognized receipt path mirror',
  sampleEnterpriseProfile.observed
);
assertEqual('sample installed runtime profile terminal chain observed root preflighted', true, sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_generated_installed_root_preflighted);
assertEqual('sample installed runtime profile terminal chain observed generated preflight consumed', true, sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_generated_preflight_consumed);
assertEqual('sample installed runtime profile terminal chain observed service artifact verified', true, sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_generated_service_artifact_verified);
assertEqual('sample installed runtime profile terminal chain observed service proof bound', true, sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_service_proof_bound_to_generated_preflight);
assertEqual('sample installed runtime profile terminal chain observed service artifact bound', true, sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_service_artifact_verification_bound_to_service_proof);
assertEqual('sample installed runtime profile terminal chain observed boarded', true, sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_recognized_write_boarded);
assertEqual('sample installed runtime profile terminal chain observed missing receipt refused', true, sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_missing_receipt_refused_before_mutation);
assertEqual('sample installed runtime profile terminal chain observed invalid receipt refused', true, sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_invalid_receipt_refused_before_mutation);
assertEqual('sample installed runtime profile terminal chain observed refusals before mutation', true, sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_all_required_refusals_before_mutation);
assertEqual('sample installed runtime profile terminal chain current-machine false', false, sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_current_machine_governance_proven);
assertEqual('sample installed runtime profile terminal chain production downstream false', false, sampleEnterpriseProfile.observed.installed_runtime_profile_terminal_chain_production_downstream_recognition);
assertEqual('sample installed runtime profile service observed runtime service started', true, sampleEnterpriseProfile.observed.installed_runtime_profile_service_runtime_service_started);
assertEqual('sample installed runtime profile service observed disposable config written', true, sampleEnterpriseProfile.observed.installed_runtime_profile_service_disposable_runtime_config_written);
assertEqual('sample installed runtime profile service observed persistent config false', false, sampleEnterpriseProfile.observed.installed_runtime_profile_service_persistent_runtime_config_written);
assertEqual('sample installed runtime profile service observed config path not exposed', false, sampleEnterpriseProfile.observed.installed_runtime_profile_service_config_path_exposed_to_request_stream);
assertEqual('sample installed runtime profile service observed recognition bound', true, sampleEnterpriseProfile.observed.installed_runtime_profile_service_recognition_rule_bound_to_selected_profile);
assertEqual('sample installed runtime profile service observed boarded', true, sampleEnterpriseProfile.observed.installed_runtime_profile_service_recognized_write_boarded);
assertEqual('sample installed runtime profile service observed replay cases', 2, sampleEnterpriseProfile.observed.installed_runtime_profile_service_replay_case_count);
assertEqual('sample installed runtime profile service observed same-process replay refused', true, sampleEnterpriseProfile.observed.installed_runtime_profile_service_same_process_replay_refused);
assertEqual('sample installed runtime profile service observed restart replay refused', true, sampleEnterpriseProfile.observed.installed_runtime_profile_service_restart_replay_refused);
assertEqual('sample installed runtime profile service observed replay before mutation', true, sampleEnterpriseProfile.observed.installed_runtime_profile_service_all_replay_refusals_before_mutation);
assertEqual('sample installed runtime profile service observed consumed-store cases', 8, sampleEnterpriseProfile.observed.installed_runtime_profile_service_consumed_store_integrity_case_count);
assertEqual('sample installed runtime profile service observed consumed-store proven', true, sampleEnterpriseProfile.observed.installed_runtime_profile_service_consumed_store_integrity_refusals_proven);
assertEqual('sample installed runtime profile service observed consumed-store before mutation', true, sampleEnterpriseProfile.observed.installed_runtime_profile_service_all_consumed_store_integrity_refusals_before_mutation);
assertEqual('sample installed runtime profile service observed single-host rollback detection', true, sampleEnterpriseProfile.observed.installed_runtime_profile_service_single_host_consumed_store_rollback_detection);
assertEqual('sample installed runtime profile service observed store-anchor rollback cases', 1, sampleEnterpriseProfile.observed.installed_runtime_profile_service_store_and_anchor_rollback_case_count);
assertEqual('sample installed runtime profile service observed store-anchor rollback proven', true, sampleEnterpriseProfile.observed.installed_runtime_profile_service_store_and_anchor_joint_rollback_refusals_proven);
assertEqual('sample installed runtime profile service observed store-anchor rollback before mutation', true, sampleEnterpriseProfile.observed.installed_runtime_profile_service_all_store_and_anchor_rollback_refusals_before_mutation);
assertEqual('sample installed runtime profile service observed joint store-anchor rollback true', true, sampleEnterpriseProfile.observed.installed_runtime_profile_service_store_and_anchor_joint_rollback_detection);
assertEqual('sample installed runtime profile service observed joint store-anchor-witness rollback false', false, sampleEnterpriseProfile.observed.installed_runtime_profile_service_store_anchor_and_witness_joint_rollback_detection);
assertEqual('sample installed runtime profile service observed refusal cases', 18, sampleEnterpriseProfile.observed.installed_runtime_profile_service_refusal_case_count);
assertEqual('sample installed runtime profile service observed refusals before mutation', true, sampleEnterpriseProfile.observed.installed_runtime_profile_service_all_refusals_before_mutation);
assertEqual('sample installed runtime profile service observed source downstream false', false, sampleEnterpriseProfile.observed.installed_runtime_profile_service_source_preflight_downstream_refusal_proven);
assertEqual('sample installed runtime profile service observed current-machine false', false, sampleEnterpriseProfile.observed.installed_runtime_profile_service_current_machine_governance_proven);
assertEqual('sample installed runtime profile service observed production downstream false', false, sampleEnterpriseProfile.observed.installed_runtime_profile_service_production_downstream_recognition);
const sampleDownstreamRecognition = sampleReport.puzzle_pieces.find((piece) => piece.id === 5);
assertEqual('sample installed runtime profile recognition proof observed verified', true, sampleDownstreamRecognition.observed.installed_runtime_profile_recognition_proof_verified);
assertEqual('sample installed runtime profile recognition observed boarded', true, sampleDownstreamRecognition.observed.installed_runtime_profile_recognition_recognized_write_boarded);
assertEqual('sample installed runtime profile recognition observed refusal cases', 18, sampleDownstreamRecognition.observed.installed_runtime_profile_recognition_refusal_case_count);
assertEqual('sample installed runtime profile recognition observed refusals before mutation', true, sampleDownstreamRecognition.observed.installed_runtime_profile_recognition_all_refusals_before_mutation);
assertRuntimeProfileIdentityPolicy(
  'sample downstream recognition runtime-profile identity policy',
  sampleDownstreamRecognition.observed.runtime_profile_identity_policy,
);
assertEqual('sample installed runtime profile recognition source preflight downstream false', false, sampleDownstreamRecognition.observed.installed_runtime_profile_recognition_source_preflight_downstream_refusal_proven);
assertEqual('sample installed runtime profile recognition no current-machine governance', false, sampleDownstreamRecognition.observed.installed_runtime_profile_recognition_current_machine_governance_proven);
assertEqual('sample installed runtime profile recognition no production downstream', false, sampleDownstreamRecognition.observed.installed_runtime_profile_recognition_production_downstream_recognition);
assertEqual('sample installed runtime profile service proof observed in downstream', true, sampleDownstreamRecognition.observed.installed_runtime_profile_service_proof_verified);
assertEqual('sample installed runtime profile service artifact verification observed in downstream', true, sampleDownstreamRecognition.observed.installed_runtime_profile_service_artifact_verification_verified);
assert('sample installed runtime profile service artifact verification downstream sha', /^[a-f0-9]{64}$/.test(sampleDownstreamRecognition.observed.installed_runtime_profile_service_artifact_verification_body_sha256));
assertEqual('sample installed runtime profile service artifact verification downstream taxonomy preserved', true, sampleDownstreamRecognition.observed.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved);
assert('sample installed runtime profile service artifact verification downstream taxonomy sha', /^[a-f0-9]{64}$/.test(sampleDownstreamRecognition.observed.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256));
assertEqual('sample installed runtime profile terminal chain observed in downstream', true, sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_verified);
assertEqual('sample installed runtime profile terminal chain artifact verification observed in downstream', true, sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_artifact_verification_verified);
assert('sample installed runtime profile terminal chain artifact verification downstream sha', /^[a-f0-9]{64}$/.test(sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_artifact_verification_body_sha256));
assertEqual('sample installed runtime profile terminal chain downstream taxonomy preserved', true, sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_refusal_taxonomy_preserved);
assert('sample installed runtime profile terminal chain downstream taxonomy sha', /^[a-f0-9]{64}$/.test(sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256));
assertEqual('sample installed runtime profile terminal chain downstream named refusals preserved', true, sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved);
assert('sample installed runtime profile terminal chain downstream named refusals sha', /^[a-f0-9]{64}$/.test(sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256));
assertEqual('sample installed runtime profile terminal chain downstream recognition refusal groups preserved', true, sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved);
assert('sample installed runtime profile terminal chain downstream recognition refusal groups sha', /^[a-f0-9]{64}$/.test(sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256));
assertEqual(
  'sample installed runtime profile terminal chain downstream taxonomy hashes match',
  sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256,
  sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256
);
assertEqual(
  'sample installed runtime profile terminal chain downstream named refusal hashes match',
  sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256,
  sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256
);
assertEqual(
  'sample installed runtime profile terminal chain downstream recognition refusal group hashes match',
  sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256,
  sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256
);
assertObservedRecognitionRefusalGroupCaseIds(
  'sample installed runtime profile terminal chain downstream recognition refusal group',
  sampleDownstreamRecognition.observed
);
assertObservedNestedArtifactBinding(
  'sample installed runtime profile terminal chain downstream nested binding',
  sampleDownstreamRecognition.observed
);
assertObservedTrustedIssuerRegistryBinding(
  'sample installed runtime profile terminal chain downstream trusted registry binding',
  sampleDownstreamRecognition.observed
);
assertObservedRecognizedReceiptPathMirror(
  'sample installed runtime profile terminal chain downstream recognized receipt path mirror',
  sampleDownstreamRecognition.observed
);
assertEqual('sample installed runtime profile terminal chain generated preflight consumed in downstream', true, sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_generated_preflight_consumed);
assertEqual('sample installed runtime profile terminal chain service proof bound in downstream', true, sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_service_proof_bound_to_generated_preflight);
assertEqual('sample installed runtime profile terminal chain boarded in downstream', true, sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_recognized_write_boarded);
assertEqual('sample installed runtime profile terminal chain missing receipt refused in downstream', true, sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_missing_receipt_refused_before_mutation);
assertEqual('sample installed runtime profile terminal chain invalid receipt refused in downstream', true, sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_invalid_receipt_refused_before_mutation);
assertEqual('sample installed runtime profile terminal chain refusals before mutation in downstream', true, sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_all_required_refusals_before_mutation);
assertEqual('sample installed runtime profile terminal chain no current-machine governance in downstream', false, sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_current_machine_governance_proven);
assertEqual('sample installed runtime profile terminal chain no production downstream in downstream', false, sampleDownstreamRecognition.observed.installed_runtime_profile_terminal_chain_production_downstream_recognition);
assertEqual('sample installed runtime profile service observed service started in downstream', true, sampleDownstreamRecognition.observed.installed_runtime_profile_service_runtime_service_started);
assertEqual('sample installed runtime profile service replay refused in downstream', true, sampleDownstreamRecognition.observed.installed_runtime_profile_service_restart_replay_refused);
assertEqual('sample installed runtime profile service consumed-store proven in downstream', true, sampleDownstreamRecognition.observed.installed_runtime_profile_service_consumed_store_integrity_refusals_proven);
assertEqual('sample installed runtime profile service store-anchor rollback cases in downstream', 1, sampleDownstreamRecognition.observed.installed_runtime_profile_service_store_and_anchor_rollback_case_count);
assertEqual('sample installed runtime profile service store-anchor rollback proven in downstream', true, sampleDownstreamRecognition.observed.installed_runtime_profile_service_store_and_anchor_joint_rollback_refusals_proven);
assertEqual('sample installed runtime profile service joint store-anchor rollback true in downstream', true, sampleDownstreamRecognition.observed.installed_runtime_profile_service_store_and_anchor_joint_rollback_detection);
assertEqual('sample installed runtime profile service joint store-anchor-witness rollback false in downstream', false, sampleDownstreamRecognition.observed.installed_runtime_profile_service_store_anchor_and_witness_joint_rollback_detection);
assertEqual('sample installed runtime profile service observed refusals before mutation in downstream', true, sampleDownstreamRecognition.observed.installed_runtime_profile_service_all_refusals_before_mutation);
assertEqual('sample installed runtime profile service no current-machine governance in downstream', false, sampleDownstreamRecognition.observed.installed_runtime_profile_service_current_machine_governance_proven);
assertEqual('sample installed runtime profile service no production downstream in downstream', false, sampleDownstreamRecognition.observed.installed_runtime_profile_service_production_downstream_recognition);
assertEqual('sample external attestation piece unproven', 'unproven', sampleReport.puzzle_pieces.find((piece) => piece.id === 6).status);
assertEqual(
  'sample private verifier result absent',
  false,
  sampleReport.puzzle_pieces.find((piece) => piece.id === 6).observed.private_verifier_result_verification.provided
);
assertEqual('sample trusted registry optional absent', false, sampleReport.puzzle_pieces.find((piece) => piece.id === 4).observed.trusted_issuer_registry_recognition.provided);
assertEqual('sample verifier kit reproducibility optional absent', false, sampleReport.puzzle_pieces.find((piece) => piece.id === 4).observed.verifier_kit_reproducibility.provided);
assertEqual('sample verifier kit release assets optional absent', false, sampleReport.puzzle_pieces.find((piece) => piece.id === 4).observed.verifier_kit_release_assets.provided);
assertEqual('sample verifier kit public distribution optional absent', false, sampleReport.puzzle_pieces.find((piece) => piece.id === 4).observed.verifier_kit_public_distribution.provided);
assertEqual(
  'sample private intake manifest pointer absent',
  false,
  sampleReport.puzzle_pieces.find((piece) => piece.id === 7).observed.private_intake_sample_manifest_pointer.provided
);

console.log('\n-- evidence-dir command --');
const evidenceDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-readiness-test-'));
let evidenceReport;
let evidenceWithPrivateReport;
let evidenceWithPrivateZipReport;
let evidenceWithPublicExternalAttestationReport;
let readyEvidenceReport;
try {
  const files = [
    ['zlar-product-proof-path-v1.json', ['product-proof-path', '--json']],
    ['zlar-proof-smoke-sample-verification.json', ['proof-smoke', 'verify', '--historical', '--sample', '--require-file-sha', 'de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268', '--require-sha', '8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80', '--json']],
    ['zlar-local-proof-pack-sample-verification.json', ['local-proof-pack', 'verify', '--sample', '--json']],
    ['zlar-service-preflight-sample-verification.json', ['protected-records-service-preflight', 'verify', '--sample', '--json']],
    ['zlar-runtime-local-activation-sample-verification.json', ['protected-records-runtime-local-activation', 'verify', '--sample', '--json']],
    ['zlar-runtime-profile-installation-sample-verification.json', ['protected-records-runtime-profile-installation', 'verify', '--sample', '--json']],
    ['zlar-installed-runtime-profile-preflight-sample-verification.json', ['protected-records-installed-runtime-profile-preflight', 'verify', '--sample', '--json']],
    ['zlar-installed-runtime-profile-recognition-proof-v1.json', ['protected-records-installed-runtime-profile-recognition-proof', '--sample', '--json']],
    ['zlar-installed-runtime-profile-service-proof-v1.json', ['protected-records-installed-runtime-profile-service-proof', '--sample', '--json']],
    ['zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json', ['protected-records-installed-runtime-profile-service-proof', 'verify', '--sample', '--json']],
    ['zlar-coverage-map-sample.json', ['coverage', '--sample', '--require-governed', '--json']],
  ];
  for (const [name, args] of files) {
    const result = runZlar(args);
    assertEqual(`prepare ${name} exits zero`, 0, result.status);
    assertEqual(`prepare ${name} emits no stderr`, '', result.stderr);
    writeFileSync(join(evidenceDir, name), result.stdout);
  }
  const evidenceDirTerminalChainEvidence = freshTerminalChainEvidence();
  writeFileSync(
    join(evidenceDir, 'zlar-installed-runtime-profile-terminal-chain-v1.json'),
    `${JSON.stringify(evidenceDirTerminalChainEvidence.report, null, 2)}\n`,
  );
  writeFileSync(
    join(evidenceDir, 'zlar-installed-runtime-profile-terminal-chain-artifact-v1.json'),
    `${JSON.stringify(evidenceDirTerminalChainEvidence.artifact, null, 2)}\n`,
  );
  writeFileSync(
    join(
      evidenceDir,
      'zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json',
    ),
    `${JSON.stringify(evidenceDirTerminalChainEvidence.artifactVerification, null, 2)}\n`,
  );
  writeFileSync(
    join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition.json'),
    `${JSON.stringify({
      verdict: 'RECOGNIZED',
      recognized: true,
      signature_valid: true,
      registry_evidence_model: 'bundled-local-fixture-no-secret-registry-contract',
      registry_contract_evidence: 'no-secret-registry-contract-v1',
      registry_public_safe_summary_sha256: 'a'.repeat(64),
      registry_scope: 'verifier-kit-sample',
      live_probing: false,
    }, null, 2)}\n`
  );
  writeFileSync(
    join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt'),
    'ERROR: trusted-receipt-issuers-v1 registry has unsupported field: production_authority\n'
  );
  writeFileSync(
    join(evidenceDir, 'zlar-verifier-kit-reproducibility-v1.json'),
    `${JSON.stringify({
      report_type: 'zlar-verifier-kit-reproducibility-v1',
      schema_version: 1,
      result: 'PASS',
      kit_version: 'v0.1.0',
      evidence_model: 'local-source-build-same-test-publisher-key-twice',
      publisher_key_model: 'temporary test Ed25519 key generated for this check; private key removed on exit',
      publisher_kid: 'fixture-kid',
      builds: [],
      reproducible: {
        tarball_sha256_identical: true,
        manifest_and_signature_sha256_identical: true,
        sidecar_matches_tarball: true,
      },
      public_artifact_hashes: [
        {
          path: 'dist/zlar-verifier-kit-v0.1.0.tar.gz',
          sha256: 'a'.repeat(64),
        },
        {
          path: 'dist/zlar-verifier-kit-v0.1.0.tar.gz.sha256',
          sha256: 'b'.repeat(64),
        },
        {
          path: 'dist/zlar-verifier-kit-v0.1.0/MANIFEST.json',
          sha256: 'c'.repeat(64),
        },
        {
          path: 'dist/zlar-verifier-kit-v0.1.0/MANIFEST.sig',
          sha256: 'd'.repeat(64),
        },
      ],
      claim_boundary: {
        external_attestation: false,
        production_publisher_key_custody: false,
        production_signing_identity: false,
        public_release_publication: false,
        live_trust_registry_state: false,
        revocation_truth: false,
        enterprise_readiness: false,
        v3_4_0_readiness: false,
      },
    }, null, 2)}\n`
  );
  writeFileSync(
    join(evidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'),
    `${JSON.stringify({
      report_type: 'zlar-verifier-kit-public-distribution-v1',
      schema_version: 1,
      result: 'AUDIT_PASS',
      release_tag: 'v3.3.106',
      kit_version: 'v0.1.0',
      release_assets: {
        evidence_model: 'release-forward-local-no-assets-fixture',
        release_url: 'not-queried-release-forward-dry-run',
        asset_count: 0,
        assets: [],
        release_asset_hashes: {
          all_required_assets_uploaded: false,
          all_required_assets_positive_size: false,
          all_required_expected_hashes_present: false,
          all_required_supplied_hashes_present: false,
          all_required_assets_bound: false,
          checks: [
            { name: 'zlar-verifier-kit-v0.1.0.tar.gz', matches_expected_sha256: false },
            { name: 'zlar-verifier-kit-v0.1.0.tar.gz.sha256', matches_expected_sha256: false },
            { name: 'zlar-verifier-kit-reproducibility-v1.json', matches_expected_sha256: false },
          ],
        },
      },
      required_public_release_assets: [
        { name: 'zlar-verifier-kit-v0.1.0.tar.gz', present: false },
        { name: 'zlar-verifier-kit-v0.1.0.tar.gz.sha256', present: false },
        { name: 'zlar-verifier-kit-reproducibility-v1.json', present: false },
      ],
      reproducibility: {
        provided: true,
        report_type: 'zlar-verifier-kit-reproducibility-v1',
        result: 'PASS',
        evidence_model: 'local-source-build-same-test-publisher-key-twice',
        publisher_key_model: 'temporary test Ed25519 key generated for this check; private key removed on exit',
        publisher_kid: 'fixture-kid',
        public_artifact_hashes_present: true,
        public_release_publication_boundary: false,
        production_publisher_key_custody: false,
        production_signing_identity: false,
      },
      local_artifact_hashes: {
        asset_dir_provided: true,
        all_checked_hashes_match: true,
        checks: [],
      },
      posture: 'public_release_assets_absent',
      ready_for_public_distribution_claim: false,
      blocking_reasons: [
        'missing public release assets: zlar-verifier-kit-v0.1.0.tar.gz, zlar-verifier-kit-v0.1.0.tar.gz.sha256, zlar-verifier-kit-reproducibility-v1.json',
        'reproducibility report explicitly does not prove public release publication',
      ],
      claim_boundary: {
        publishes_release_assets: false,
        creates_public_external_attestation: false,
        proves_non_operator_review: false,
        proves_production_publisher_key_custody: false,
        proves_production_signing_identity: false,
        proves_live_trust_registry_state: false,
        proves_revocation_truth: false,
        proves_production_downstream_recognition: false,
        proves_enterprise_readiness: false,
        proves_sovereign_recognition: false,
        proves_v3_4_0_readiness: false,
      },
      non_claims: [
        'This report does not publish release assets.',
        'This report does not prove production publisher key custody or production signing identity.',
        'This report does not prove external attestation or non-operator review.',
        'This report does not prove live trust-registry state, revocation truth, production downstream recognition, enterprise readiness, sovereign recognition, or v3.4.0 readiness.',
      ],
    }, null, 2)}\n`
  );
  const activePersistentLifecycleFixture =
    writeActivePersistentLifecycleEvidence(evidenceDir);
  const privateVerifierResultVerification = {
    verification_type: 'zlar-private-verifier-result-verification-v1',
    verified: true,
    report_type: 'zlar-private-verifier-result-v1',
    intake_class: 'private-verifier-reply',
    verdict: 'PASS',
    release_tag: 'v3.3.106',
    commit_sha: '1234567890abcdef1234567890abcdef12345678',
    evidence_model: 'release-forward-dry-run-artifacts',
    artifact_hash_count: 27,
    completed_by_non_operator: true,
    private_by_default: true,
    public_external_attestation: false,
    public_attribution: false,
    non_operator_review_publicly_claimed: false,
    production_authority: false,
    enterprise_readiness: false,
    current_machine_governance: false,
    live_mcp_coverage: false,
    v3_4_0_readiness: false,
    evidence_dir_hash_verification: {
      enabled: true,
      hashes_recomputed: true,
      verified: true,
      artifact_hash_count: 27,
      checked_paths: [],
    },
    evidence_dir_contract_verification: {
      required_for_target: true,
      verified: true,
      downstream_refusal_boundary_required_for_target: true,
      downstream_refusal_all_refusals_unboarded: true,
      downstream_refusal_reasons: clone(EXPECTED_DOWNSTREAM_REFUSAL_REASONS),
      north_star_downstream_refusal_all_refusals_unboarded: true,
      north_star_downstream_refusal_reasons: clone(EXPECTED_DOWNSTREAM_REFUSAL_REASONS),
    },
    claim_boundary: {},
    privacy: {},
    non_claims: [],
  };
  const privateVerifierResultVerificationPath = join(
    evidenceDir,
    'private-verifier-result-verification-v1.json'
  );
  writeFileSync(
    privateVerifierResultVerificationPath,
    `${JSON.stringify(privateVerifierResultVerification, null, 2)}\n`
  );
  const privateVerifierZipResultVerification = {
    verification_type: 'zlar-private-verifier-zip-result-verification-v1',
    verified: true,
    report_type: 'zlar-private-verifier-zip-result-v1',
    report_sha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    target: {
      repo: 'ZLAR-AI/ZLAR',
      commit_sha: '1234567890abcdef1234567890abcdef12345678',
      source_route: 'browser-downloaded-zip-snapshot',
      moving_target_used: false,
    },
    relationship_label: 'private personally connected outside-machine verifier signal',
    evidence_model: 'zip-snapshot-returned-artifact-set',
    recomputed_evidence: true,
    returned_results_zip_sha256: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    source_snapshot_zip_sha256: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    sha256sums_entry_count: 24,
    all_sha256sums_entries_matched: true,
    all_required_steps_exit_zero: true,
    only_known_stderr_issue: true,
    proof_smoke_verified: true,
    proof_smoke_report_sha256: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    north_star_result: 'NOT_READY_FOR_V3_4_0',
    public_privacy_passed: true,
    allowed_claim: {
      private_personally_connected_outside_machine_signal: true,
      locally_reviewed_returned_result_custody: true,
    },
    claim_boundary: {
      private_intake_only: true,
      private_personally_connected_outside_machine_signal: true,
      artifact_custody_reviewed: true,
      public_external_attestation: false,
      independent_review: false,
      arms_length_review: false,
      public_attribution: false,
      git_clone_source_access: false,
      source_transport_credentials: false,
      tag_or_release_proof: false,
      website_public_alignment: false,
      production_trust: false,
      current_machine_governance: false,
      all_surface_governance: false,
      north_star_readiness: false,
      side_door_closure: false,
      absolute_human_intention: false,
    },
    forbidden_claims: [
      'public external attestation',
      'independent review',
      "arm's-length review",
      'public attribution',
      'North Star readiness',
    ],
  };
  const privateVerifierZipResultVerificationPath = join(
    evidenceDir,
    'private-verifier-zip-result-verification-v1.json'
  );
  writeFileSync(
    privateVerifierZipResultVerificationPath,
    `${JSON.stringify(privateVerifierZipResultVerification, null, 2)}\n`
  );
  const publicArtifactVerifierResultVerification = {
    verification_type: 'zlar-public-artifact-verifier-result-verification-v1',
    schema_version: 1,
    verified: true,
    result_sha256: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    verifier_label: 'public-artifact-outside-machine-review-v3459-001',
    target: {
      version: 'v3.4.59',
      release_json_url: 'https://zlar.ai/release.json',
      verifier_kit_url: 'https://zlar.ai/verifier-kit/v3.4.59/',
      source_access_path: 'public_release_assets_only',
    },
    public_artifact_hash_consistency_signal: true,
    public_artifact_reachability_signal: true,
    observed: {
      verifier_kit_tarball_sha256: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      sidecar_hash_matches_tarball: true,
      sidecar_check_passed: true,
      reproducibility_json_fetched: true,
      proof_pack_manifest_fetched: true,
      proof_pack_sha256sums_fetched: true,
      source_access_used: false,
      github_access_used: false,
      credentials_used: false,
      deploy_key_used: false,
    },
    claim_boundary: {
      public_external_attestation: false,
      public_attribution: false,
      non_operator_review_proven: false,
      private_source_review: false,
      production_authority: false,
      enterprise_readiness: false,
      current_machine_governance: false,
      all_surface_governance: false,
      key_custody: false,
      revocation_truth: false,
      side_door_closure: false,
    },
    non_claims: [
      'This report does not prove public external attestation.',
      'This report does not prove private source review.',
      'This report does not prove production authority or enterprise readiness.',
      'This report does not prove current-machine governance, all-surface governance, key custody, revocation truth, or side-door closure.',
    ],
  };
  const publicArtifactVerifierResultVerificationPath = join(
    evidenceDir,
    'public-artifact-verifier-result-verification-v1.json'
  );
  writeFileSync(
    publicArtifactVerifierResultVerificationPath,
    `${JSON.stringify(publicArtifactVerifierResultVerification, null, 2)}\n`
  );
  const publicExternalAttestationResultVerification =
    signedPublicExternalAttestationResultVerification('v3.3.106');
  const publicExternalAttestationResultVerificationPath = join(
    evidenceDir,
    'public-external-attestation-result-verification-v1.json'
  );
  writeFileSync(
    publicExternalAttestationResultVerificationPath,
    `${JSON.stringify(publicExternalAttestationResultVerification, null, 2)}\n`
  );
  const readEvidenceJson = (name) => JSON.parse(readFileSync(join(evidenceDir, name), 'utf8'));
  const buildReleaseForwardReadinessReport = (overrides = {}) => buildNorthStarReadinessReport({
    evidenceModel: 'release-forward-dry-run-artifacts',
    productProofPathReport: readEvidenceJson('zlar-product-proof-path-v1.json'),
    proofSmokeVerification: readEvidenceJson('zlar-proof-smoke-sample-verification.json'),
    localProofPackVerification: readEvidenceJson('zlar-local-proof-pack-sample-verification.json'),
    servicePreflightVerification: readEvidenceJson('zlar-service-preflight-sample-verification.json'),
    runtimeLocalActivationVerification: readEvidenceJson('zlar-runtime-local-activation-sample-verification.json'),
    runtimeProfileInstallationVerification: readEvidenceJson('zlar-runtime-profile-installation-sample-verification.json'),
    installedRuntimeProfilePreflightVerification: readEvidenceJson('zlar-installed-runtime-profile-preflight-sample-verification.json'),
    installedRuntimeProfileRecognitionProof: readEvidenceJson('zlar-installed-runtime-profile-recognition-proof-v1.json'),
    installedRuntimeProfileServiceProof: readEvidenceJson('zlar-installed-runtime-profile-service-proof-v1.json'),
    installedRuntimeProfileServiceProofArtifactVerification: readEvidenceJson('zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'),
    installedRuntimeProfileTerminalChain: readEvidenceJson('zlar-installed-runtime-profile-terminal-chain-v1.json'),
    installedRuntimeProfileTerminalChainArtifact: readEvidenceJson('zlar-installed-runtime-profile-terminal-chain-artifact-v1.json'),
    installedRuntimeProfileTerminalChainArtifactVerification: readEvidenceJson('zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json'),
    coverageMap: readEvidenceJson('zlar-coverage-map-sample.json'),
    trustedIssuerRecognition: readEvidenceJson('zlar-trusted-receipt-issuer-recognition.json'),
    malformedRegistryErrorText: readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt'), 'utf8'),
    verifierKitReproducibility: readEvidenceJson('zlar-verifier-kit-reproducibility-v1.json'),
    verifierKitPublicDistribution: readEvidenceJson('zlar-verifier-kit-public-distribution-v1.json'),
    releaseForwardTargetTag: 'v3.3.106',
    ...overrides,
  });

  const evidenceRun = runZlar(['north-star-readiness', '--evidence-dir', evidenceDir, '--release-tag', 'v3.3.106', '--json']);
  assertEqual('evidence-dir json exits zero', 0, evidenceRun.status);
  assertEqual('evidence-dir json emits no stderr', '', evidenceRun.stderr);
  assert('evidence-dir output privacy safe', !unsafeOutputPattern.test(evidenceRun.stdout));
  evidenceReport = JSON.parse(evidenceRun.stdout);
  assert('evidence-dir report passes validation', assertNorthStarReadinessReport(evidenceReport));
  assertEqual('evidence-dir evidence model', 'release-forward-dry-run-artifacts', evidenceReport.evidence_model);
  assert('evidence-dir artifacts include installed runtime profile preflight', evidenceReport.artifacts_consumed.includes('zlar-installed-runtime-profile-preflight-sample-verification.json'));
  assert('evidence-dir artifacts include installed runtime profile recognition proof', evidenceReport.artifacts_consumed.includes('zlar-installed-runtime-profile-recognition-proof-v1.json'));
  assert('evidence-dir artifacts include installed runtime profile service proof', evidenceReport.artifacts_consumed.includes('zlar-installed-runtime-profile-service-proof-v1.json'));
  assert('evidence-dir artifacts include installed runtime profile service proof artifact verification', evidenceReport.artifacts_consumed.includes('zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'));
  assert('evidence-dir artifacts include installed runtime profile terminal chain', evidenceReport.artifacts_consumed.includes('zlar-installed-runtime-profile-terminal-chain-v1.json'));
  assert('evidence-dir artifacts include installed runtime profile terminal chain artifact', evidenceReport.artifacts_consumed.includes('zlar-installed-runtime-profile-terminal-chain-artifact-v1.json'));
  assert('evidence-dir artifacts include installed runtime profile terminal chain artifact verification', evidenceReport.artifacts_consumed.includes('zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json'));
  assert('evidence-dir artifacts include product proof path', evidenceReport.artifacts_consumed.includes('zlar-product-proof-path-v1.json'));
  assert('evidence-dir artifacts include historical lifecycle evidence', evidenceReport.artifacts_consumed.includes('zlar-active-persistent-profile-lifecycle-v1.json'));
  assert('evidence-dir artifacts include historical lifecycle binding', evidenceReport.artifacts_consumed.includes('zlar-active-persistent-profile-lifecycle-source-binding-v1.json'));
  assertEqual('evidence-dir product proof path verified', true, evidenceReport.counts.product_proof_path_verified);
  const historicalLifecycle =
    evidenceReport.supplemental_evidence
      .historical_supplied_local_active_persistent_profile_lifecycle;
  assertEqual('evidence-dir historical lifecycle provided', true, historicalLifecycle.provided);
  assertEqual('evidence-dir historical lifecycle verified', true, historicalLifecycle.verified);
  assertEqual('evidence-dir historical lifecycle class', 'historical_supplied_local_active_persistent_profile_lifecycle', historicalLifecycle.evidence_class);
  assertEqual('evidence-dir historical lifecycle report hash', activePersistentLifecycleFixture.lifecycleReportSha256, historicalLifecycle.lifecycle_report_sha256);
  assertEqual('evidence-dir historical lifecycle source install hash', activePersistentLifecycleFixture.hashes.install_report_sha256, historicalLifecycle.source_report_hashes.install_report_sha256);
  assertEqual('evidence-dir historical lifecycle expected hashes bound', true, historicalLifecycle.expected_input_report_hashes_bound);
  assertEqual('evidence-dir historical lifecycle non-scoring', true, historicalLifecycle.non_scoring);
  assertEqual('evidence-dir historical lifecycle not current install', false, historicalLifecycle.current_installation);
  assertEqual('evidence-dir historical lifecycle not product proof completion', true, historicalLifecycle.does_not_complete_product_proof_path);
  assertEqual('evidence-dir historical lifecycle not enterprise completion', true, historicalLifecycle.does_not_complete_enterprise_deployment_profile);
  assertEqual('evidence-dir historical lifecycle production downstream false', false, historicalLifecycle.production_downstream_recognition);
  assertEqual('evidence-dir historical lifecycle count provided', true, evidenceReport.counts.historical_active_persistent_profile_lifecycle_provided);
  assertEqual('evidence-dir historical lifecycle count verified', true, evidenceReport.counts.historical_active_persistent_profile_lifecycle_verified);
  assertEqual('evidence-dir historical lifecycle count non-scoring', true, evidenceReport.counts.historical_active_persistent_profile_lifecycle_non_scoring);
  assertEqual('evidence-dir historical lifecycle count current install false', false, evidenceReport.counts.historical_active_persistent_profile_lifecycle_current_installation);
  assertEqual('evidence-dir historical lifecycle count product completion false', false, evidenceReport.counts.historical_active_persistent_profile_lifecycle_product_proof_path_completion);
  assertEqual('evidence-dir historical lifecycle count enterprise completion false', false, evidenceReport.counts.historical_active_persistent_profile_lifecycle_enterprise_deployment_profile_completion);
  assertEqual('evidence-dir proven count unchanged by lifecycle', 5, evidenceReport.counts.proven_count);
  const missingLifecycleBindingDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-missing-lifecycle-binding-'));
  rmSync(missingLifecycleBindingDir, { recursive: true, force: true });
  cpSync(evidenceDir, missingLifecycleBindingDir, { recursive: true });
  rmSync(join(missingLifecycleBindingDir, 'zlar-active-persistent-profile-lifecycle-source-binding-v1.json'), { force: true });
  const missingLifecycleBindingRun = runZlar(['north-star-readiness', '--evidence-dir', missingLifecycleBindingDir, '--release-tag', 'v3.3.106', '--json']);
  assert('missing lifecycle binding exits nonzero', missingLifecycleBindingRun.status !== 0);
  assertEqual('missing lifecycle binding emits no stdout', '', missingLifecycleBindingRun.stdout);
  assert('missing lifecycle binding output privacy safe', !unsafeOutputPattern.test(missingLifecycleBindingRun.stderr));

  const missingLifecycleSourceDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-missing-lifecycle-source-'));
  rmSync(missingLifecycleSourceDir, { recursive: true, force: true });
  cpSync(evidenceDir, missingLifecycleSourceDir, { recursive: true });
  rmSync(join(missingLifecycleSourceDir, 'active-persistent-red-refusal-report.json'), { force: true });
  const missingLifecycleSourceRun = runZlar(['north-star-readiness', '--evidence-dir', missingLifecycleSourceDir, '--release-tag', 'v3.3.106', '--json']);
  assert('missing lifecycle source report exits nonzero', missingLifecycleSourceRun.status !== 0);
  assertEqual('missing lifecycle source report emits no stdout', '', missingLifecycleSourceRun.stdout);
  assert('missing lifecycle source report output privacy safe', !unsafeOutputPattern.test(missingLifecycleSourceRun.stderr));

  const tamperedLifecycleSourceDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-tampered-lifecycle-source-'));
  rmSync(tamperedLifecycleSourceDir, { recursive: true, force: true });
  cpSync(evidenceDir, tamperedLifecycleSourceDir, { recursive: true });
  const tamperedRed = JSON.parse(readFileSync(join(tamperedLifecycleSourceDir, 'active-persistent-red-refusal-report.json'), 'utf8'));
  tamperedRed.red_path_result.refusal_case_count = 17;
  writeFileSync(join(tamperedLifecycleSourceDir, 'active-persistent-red-refusal-report.json'), `${JSON.stringify(tamperedRed, null, 2)}\n`);
  const tamperedLifecycleSourceRun = runZlar(['north-star-readiness', '--evidence-dir', tamperedLifecycleSourceDir, '--release-tag', 'v3.3.106', '--json']);
  assert('tampered lifecycle source report exits nonzero', tamperedLifecycleSourceRun.status !== 0);
  assertEqual('tampered lifecycle source report emits no stdout', '', tamperedLifecycleSourceRun.stdout);
  assert('tampered lifecycle source report output privacy safe', !unsafeOutputPattern.test(tamperedLifecycleSourceRun.stderr));

  const tamperedLifecycleSummaryDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-tampered-lifecycle-summary-'));
  rmSync(tamperedLifecycleSummaryDir, { recursive: true, force: true });
  cpSync(evidenceDir, tamperedLifecycleSummaryDir, { recursive: true });
  const tamperedLifecycle = JSON.parse(readFileSync(join(tamperedLifecycleSummaryDir, 'zlar-active-persistent-profile-lifecycle-v1.json'), 'utf8'));
  tamperedLifecycle.claim_boundary.expected_input_report_hashes_bound = false;
  const tamperedLifecycleBody = `${JSON.stringify(tamperedLifecycle, null, 2)}\n`;
  writeFileSync(join(tamperedLifecycleSummaryDir, 'zlar-active-persistent-profile-lifecycle-v1.json'), tamperedLifecycleBody);
  const tamperedLifecycleBinding = JSON.parse(readFileSync(join(tamperedLifecycleSummaryDir, 'zlar-active-persistent-profile-lifecycle-source-binding-v1.json'), 'utf8'));
  tamperedLifecycleBinding.lifecycle_report_sha256 = sha256(tamperedLifecycleBody);
  writeFileSync(join(tamperedLifecycleSummaryDir, 'zlar-active-persistent-profile-lifecycle-source-binding-v1.json'), `${JSON.stringify(tamperedLifecycleBinding, null, 2)}\n`);
  const tamperedLifecycleSummaryRun = runZlar(['north-star-readiness', '--evidence-dir', tamperedLifecycleSummaryDir, '--release-tag', 'v3.3.106', '--json']);
  assert('tampered lifecycle summary exits nonzero', tamperedLifecycleSummaryRun.status !== 0);
  assertEqual('tampered lifecycle summary emits no stdout', '', tamperedLifecycleSummaryRun.stdout);
  assert('tampered lifecycle summary output privacy safe', !unsafeOutputPattern.test(tamperedLifecycleSummaryRun.stderr));
  assertEqual('evidence-dir installed runtime profile preflight verified', true, evidenceReport.counts.installed_runtime_profile_preflight_verified);
  assertEqual('evidence-dir installed runtime profile no-effect boundary', true, evidenceReport.counts.installed_runtime_profile_preflight_no_effect_boundary_preserved);
  assertEqual('evidence-dir installed runtime profile recognition contract preserved', true, evidenceReport.counts.installed_runtime_profile_preflight_recognition_contract_preserved);
  assertEqual('evidence-dir installed runtime profile recognition proof preserved', true, evidenceReport.counts.installed_runtime_profile_recognition_proof_preserved);
  assertEqual('evidence-dir installed runtime profile service proof preserved', true, evidenceReport.counts.installed_runtime_profile_service_proof_preserved);
  assertEqual('evidence-dir installed runtime profile service artifact verification not required before v3.4.14', false, evidenceReport.counts.installed_runtime_profile_service_artifact_verification_required);
  assertEqual('evidence-dir installed runtime profile service artifact verification preserved', true, evidenceReport.counts.installed_runtime_profile_service_artifact_verification_preserved);
  assertEqual('evidence-dir installed runtime profile service artifact verification taxonomy not required before v3.4.18', false, evidenceReport.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_required);
  assertEqual('evidence-dir installed runtime profile service artifact verification taxonomy preserved when supplied', true, evidenceReport.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved);
  assert('evidence-dir installed runtime profile service artifact verification taxonomy sha', /^[a-f0-9]{64}$/.test(evidenceReport.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256));
  assertEqual('evidence-dir installed runtime profile terminal chain not required before v3.4.15', false, evidenceReport.counts.installed_runtime_profile_terminal_chain_required);
  assertEqual('evidence-dir installed runtime profile terminal chain preserved', true, evidenceReport.counts.installed_runtime_profile_terminal_chain_preserved);
  assertEqual('evidence-dir installed runtime profile terminal chain taxonomy not required before v3.4.17', false, evidenceReport.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_required);
  assertEqual('evidence-dir installed runtime profile terminal chain taxonomy preserved when supplied', true, evidenceReport.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_preserved);
  assert('evidence-dir installed runtime profile terminal chain taxonomy sha', /^[a-f0-9]{64}$/.test(evidenceReport.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256));
  assertEqual('evidence-dir installed runtime profile terminal chain named refusals not required before v3.4.22', false, evidenceReport.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_required);
  assertEqual('evidence-dir installed runtime profile terminal chain named refusals preserved when supplied', true, evidenceReport.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved);
  assert('evidence-dir installed runtime profile terminal chain named refusals sha', /^[a-f0-9]{64}$/.test(evidenceReport.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256));
  assertEqual('evidence-dir installed runtime profile terminal chain recognition refusal groups not required before v3.4.23', false, evidenceReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_required);
  assertEqual('evidence-dir installed runtime profile terminal chain recognition refusal groups preserved when supplied', true, evidenceReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved);
  assert('evidence-dir installed runtime profile terminal chain recognition refusal groups sha', /^[a-f0-9]{64}$/.test(evidenceReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256));
  assertEqual(
    'evidence-dir installed runtime profile terminal chain taxonomy hashes match',
    evidenceReport.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256,
    evidenceReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256
  );
  assertEqual(
    'evidence-dir installed runtime profile terminal chain named refusal hashes match',
    evidenceReport.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256,
    evidenceReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256
  );
  assertEqual(
    'evidence-dir installed runtime profile terminal chain recognition refusal group hashes match',
    evidenceReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256,
    evidenceReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256
  );
  assertEqual('evidence-dir installed runtime profile terminal chain deployment-profile authority refusal mirror not required before v3.4.50', false, evidenceReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required);
  assertEqual('evidence-dir installed runtime profile terminal chain deployment-profile authority refusal mirror preserved when supplied', true, evidenceReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved);
  assertEqual('evidence-dir installed runtime profile terminal chain deployment-profile authority current-machine false when supplied', false, evidenceReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance);
  assertEqual('evidence-dir installed runtime profile terminal chain artifact deployment-profile authority external attestation false when supplied', false, evidenceReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_external_attestation);
  assertEqual('evidence-dir installed runtime profile terminal chain deployment-profile authority refusal case count', 5, evidenceReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count);
  assertEqual(
    'evidence-dir installed runtime profile terminal chain deployment-profile authority refusal case IDs',
    JSON.stringify(EXPECTED_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASE_IDS),
    JSON.stringify(evidenceReport.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids)
  );
  assertEqual(
    'evidence-dir installed runtime profile terminal chain artifact verification deployment-profile authority refusal case IDs',
    JSON.stringify(EXPECTED_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASE_IDS),
    JSON.stringify(evidenceReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids)
  );

  const v3419EvidenceReport = buildReleaseForwardReadinessReport({
    verifierKitPublicDistribution: null,
    releaseForwardTargetTag: 'v3.4.19',
  });
  assert('v3.4.19 release-forward digest report passes validation', assertNorthStarReadinessReport(v3419EvidenceReport));
  assertEqual('v3.4.19 release-forward recognition digest required', true, v3419EvidenceReport.counts.installed_runtime_profile_recognition_contract_digest_required);
  assertEqual('v3.4.19 release-forward recognition digest preserved', true, v3419EvidenceReport.counts.installed_runtime_profile_recognition_contract_digest_preserved);

  const v3422EvidenceReport = buildReleaseForwardReadinessReport({
    verifierKitPublicDistribution: null,
    releaseForwardTargetTag: 'v3.4.22',
  });
  assert('v3.4.22 release-forward named refusal report passes validation', assertNorthStarReadinessReport(v3422EvidenceReport));
  assertEqual('v3.4.22 release-forward named refusals required', true, v3422EvidenceReport.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_required);
  assertEqual('v3.4.22 release-forward named refusals preserved', true, v3422EvidenceReport.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved);
  assertEqual('v3.4.22 release-forward recognition refusal groups not required', false, v3422EvidenceReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_required);
  assertEqual('v3.4.22 release-forward recognition refusal groups preserved when supplied', true, v3422EvidenceReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved);
  const v3422NamedRefusalsRequiredTamper = clone(v3422EvidenceReport);
  v3422NamedRefusalsRequiredTamper.counts.installed_runtime_profile_terminal_chain_named_receipt_refusals_required = false;
  assertThrows(
    'v3.4.22 release-forward named refusals required=false fails readiness',
    () => assertNorthStarReadinessReport(v3422NamedRefusalsRequiredTamper),
    'must require installed runtime profile terminal chain named receipt refusals'
  );

  const v3423EvidenceReport = buildReleaseForwardReadinessReport({
    verifierKitPublicDistribution: null,
    releaseForwardTargetTag: 'v3.4.23',
  });
  assert('v3.4.23 release-forward recognition refusal groups report passes validation', assertNorthStarReadinessReport(v3423EvidenceReport));
  assertEqual('v3.4.23 release-forward recognition refusal groups required', true, v3423EvidenceReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_required);
  assertEqual('v3.4.23 release-forward recognition refusal groups preserved', true, v3423EvidenceReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved);
  const v3423RecognitionGroupsRequiredTamper = clone(v3423EvidenceReport);
  v3423RecognitionGroupsRequiredTamper.counts.installed_runtime_profile_terminal_chain_recognition_refusal_groups_required = false;
  assertThrows(
    'v3.4.23 release-forward recognition refusal groups required=false fails readiness',
    () => assertNorthStarReadinessReport(v3423RecognitionGroupsRequiredTamper),
    'must require installed runtime profile terminal chain recognition refusal groups'
  );

  const v3424EvidenceReport = buildReleaseForwardReadinessReport({
    verifierKitPublicDistribution: null,
    releaseForwardTargetTag: 'v3.4.24',
  });
  assert('v3.4.24 release-forward recognition refusal group case IDs report passes validation', assertNorthStarReadinessReport(v3424EvidenceReport));
  assertEqual('v3.4.24 release-forward recognition refusal group case IDs not required', false, v3424EvidenceReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required);
  assertEqual('v3.4.24 release-forward recognition refusal group case IDs preserved when supplied', true, v3424EvidenceReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved);
  assertEqual(
    'v3.4.24 release-forward recognition refusal group case IDs',
    JSON.stringify(EXPECTED_RECOGNITION_REFUSAL_GROUP_CASE_IDS),
    JSON.stringify(v3424EvidenceReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids)
  );

  const v3425EvidenceReport = buildReleaseForwardReadinessReport({
    verifierKitPublicDistribution: null,
    releaseForwardTargetTag: 'v3.4.25',
  });
  assert('v3.4.25 release-forward recognition refusal group case IDs report passes validation', assertNorthStarReadinessReport(v3425EvidenceReport));
  assertEqual('v3.4.25 release-forward recognition refusal group case IDs required', true, v3425EvidenceReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required);
  assertEqual('v3.4.25 release-forward recognition refusal group case IDs preserved', true, v3425EvidenceReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved);
  assertEqual('v3.4.25 release-forward recognition refusal group count', 3, v3425EvidenceReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_count);
  assertEqual('v3.4.25 release-forward recognition refusal group case count', 18, v3425EvidenceReport.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count);

  const v3425HistoricalObservedSummaryShape = clone(v3425EvidenceReport);
  for (const pieceId of [3, 5]) {
    const observed = v3425HistoricalObservedSummaryShape.puzzle_pieces.find((piece) => piece.id === pieceId).observed;
    delete observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved;
    delete observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_count;
    delete observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count;
    delete observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids;
    delete observed.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count;
    delete observed.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count;
    delete observed.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids;
  }
  assert(
    'v3.4.25 release-forward historical observed-summary shape remains valid',
    assertNorthStarReadinessReport(v3425HistoricalObservedSummaryShape)
  );

  const v3426EvidenceReport = buildReleaseForwardReadinessReport({
    verifierKitPublicDistribution: null,
    releaseForwardTargetTag: 'v3.4.26',
  });
  assert('v3.4.26 release-forward observed summary case IDs report passes validation', assertNorthStarReadinessReport(v3426EvidenceReport));
  assertObservedRecognitionRefusalGroupCaseIds(
    'v3.4.26 enterprise observed recognition refusal group',
    v3426EvidenceReport.puzzle_pieces.find((piece) => piece.id === 3).observed
  );
  assertObservedRecognitionRefusalGroupCaseIds(
    'v3.4.26 downstream observed recognition refusal group',
    v3426EvidenceReport.puzzle_pieces.find((piece) => piece.id === 5).observed
  );

  const v3426EnterpriseCaseIdsMissingTamper = clone(v3426EvidenceReport);
  delete v3426EnterpriseCaseIdsMissingTamper.puzzle_pieces.find((piece) => piece.id === 3).observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids;
  assertThrows(
    'v3.4.26 enterprise observed missing recognition refusal group case IDs fails readiness',
    () => assertNorthStarReadinessReport(v3426EnterpriseCaseIdsMissingTamper),
    'Enterprise Deployment Profile observed summary recognition refusal group case IDs observed summary drifted'
  );

  const v3426DownstreamCaseIdsMissingTamper = clone(v3426EvidenceReport);
  delete v3426DownstreamCaseIdsMissingTamper.puzzle_pieces.find((piece) => piece.id === 5).observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids;
  assertThrows(
    'v3.4.26 downstream observed missing recognition refusal group case IDs fails readiness',
    () => assertNorthStarReadinessReport(v3426DownstreamCaseIdsMissingTamper),
    'Downstream Recognition Rule observed summary recognition refusal group case IDs observed summary drifted'
  );

  const v3426EnterpriseCaseCountTamper = clone(v3426EvidenceReport);
  v3426EnterpriseCaseCountTamper.puzzle_pieces.find((piece) => piece.id === 3).observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count = 17;
  assertThrows(
    'v3.4.26 enterprise observed recognition refusal group case count drift fails readiness',
    () => assertNorthStarReadinessReport(v3426EnterpriseCaseCountTamper),
    'Enterprise Deployment Profile observed summary recognition refusal group case IDs observed summary drifted'
  );

  const v3426DownstreamArtifactCaseIdsTamper = clone(v3426EvidenceReport);
  v3426DownstreamArtifactCaseIdsTamper.puzzle_pieces.find((piece) => piece.id === 5).observed.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids.route_or_request_authority_material_refused.reverse();
  assertThrows(
    'v3.4.26 downstream observed artifact recognition refusal group case IDs drift fails readiness',
    () => assertNorthStarReadinessReport(v3426DownstreamArtifactCaseIdsTamper),
    'Downstream Recognition Rule observed summary recognition refusal group case IDs observed summary drifted'
  );

  const v3426EnterprisePreservedFalseTamper = clone(v3426EvidenceReport);
  v3426EnterprisePreservedFalseTamper.puzzle_pieces.find((piece) => piece.id === 3).observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved = false;
  assertThrows(
    'v3.4.26 enterprise observed recognition refusal group case IDs preserved=false fails readiness',
    () => assertNorthStarReadinessReport(v3426EnterprisePreservedFalseTamper),
    'Enterprise Deployment Profile observed summary recognition refusal group case IDs observed summary drifted'
  );

  const v3430EvidenceReport = buildReleaseForwardReadinessReport({
    verifierKitPublicDistribution: null,
    releaseForwardTargetTag: 'v3.4.30',
  });
  assert('v3.4.30 release-forward nested artifact binding report passes validation', assertNorthStarReadinessReport(v3430EvidenceReport));
  assertEqual('v3.4.30 nested artifact binding required', true, v3430EvidenceReport.counts.installed_runtime_profile_terminal_chain_nested_artifact_binding_required);
  assertEqual('v3.4.30 nested artifact binding preserved', true, v3430EvidenceReport.counts.installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved);
  assertEqual('v3.4.30 nested preflight type', EXPECTED_NESTED_PREFLIGHT_ARTIFACT_TYPE, v3430EvidenceReport.counts.installed_runtime_profile_terminal_chain_nested_preflight_artifact_type);
  assertEqual('v3.4.30 nested service proof type', EXPECTED_NESTED_SERVICE_PROOF_ARTIFACT_TYPE, v3430EvidenceReport.counts.installed_runtime_profile_terminal_chain_nested_service_proof_artifact_type);
  assertEqual('v3.4.30 artifact nested artifact binding preserved', true, v3430EvidenceReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved);
  assertEqual('v3.4.30 artifact nested preflight type', EXPECTED_NESTED_PREFLIGHT_ARTIFACT_TYPE, v3430EvidenceReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_preflight_artifact_type);
  assertEqual('v3.4.30 artifact nested service proof type', EXPECTED_NESTED_SERVICE_PROOF_ARTIFACT_TYPE, v3430EvidenceReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_service_proof_artifact_type);
  assertObservedNestedArtifactBinding(
    'v3.4.30 enterprise observed nested binding',
    v3430EvidenceReport.puzzle_pieces.find((piece) => piece.id === 3).observed
  );
  assertObservedNestedArtifactBinding(
    'v3.4.30 downstream observed nested binding',
    v3430EvidenceReport.puzzle_pieces.find((piece) => piece.id === 5).observed
  );

  const v3430NestedBindingRequiredTamper = clone(v3430EvidenceReport);
  v3430NestedBindingRequiredTamper.counts.installed_runtime_profile_terminal_chain_nested_artifact_binding_required = false;
  assertThrows(
    'v3.4.30 nested artifact binding required=false fails readiness',
    () => assertNorthStarReadinessReport(v3430NestedBindingRequiredTamper),
    'must require installed runtime profile terminal chain nested artifact binding'
  );

  const v3430NestedBindingPreservedTamper = clone(v3430EvidenceReport);
  v3430NestedBindingPreservedTamper.counts.installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved = false;
  assertThrows(
    'v3.4.30 nested artifact binding preserved=false fails readiness',
    () => assertNorthStarReadinessReport(v3430NestedBindingPreservedTamper),
    'nested artifact binding drifted'
  );

  const v3430NestedBindingTypeTamper = clone(v3430EvidenceReport);
  v3430NestedBindingTypeTamper.counts.installed_runtime_profile_terminal_chain_artifact_verification_nested_service_proof_artifact_type =
    'wrong-artifact-type';
  assertThrows(
    'v3.4.30 nested artifact binding type drift fails readiness',
    () => assertNorthStarReadinessReport(v3430NestedBindingTypeTamper),
    'nested artifact binding boundary drifted'
  );

  const v3430EnterpriseObservedNestedBindingMissingTamper = clone(v3430EvidenceReport);
  delete v3430EnterpriseObservedNestedBindingMissingTamper.puzzle_pieces.find((piece) => piece.id === 3).observed.installed_runtime_profile_terminal_chain_nested_preflight_artifact_type;
  assertThrows(
    'v3.4.30 enterprise observed missing nested artifact binding fails readiness',
    () => assertNorthStarReadinessReport(v3430EnterpriseObservedNestedBindingMissingTamper),
    'Enterprise Deployment Profile observed summary nested artifact binding observed summary drifted'
  );

  const v3430DownstreamObservedNestedBindingTamper = clone(v3430EvidenceReport);
  v3430DownstreamObservedNestedBindingTamper.puzzle_pieces.find((piece) => piece.id === 5).observed.installed_runtime_profile_terminal_chain_artifact_verification_nested_preflight_artifact_type =
    'wrong-artifact-type';
  assertThrows(
    'v3.4.30 downstream observed nested artifact binding drift fails readiness',
    () => assertNorthStarReadinessReport(v3430DownstreamObservedNestedBindingTamper),
    'Downstream Recognition Rule observed summary nested artifact binding observed summary drifted'
  );

  const v3437EvidenceReport = buildReleaseForwardReadinessReport({
    verifierKitPublicDistribution: null,
    releaseForwardTargetTag: 'v3.4.37',
  });
  assert('v3.4.37 release-forward trusted registry binding report passes validation', assertNorthStarReadinessReport(v3437EvidenceReport));
  assertEqual('v3.4.37 trusted registry binding required', true, v3437EvidenceReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_required);
  assertEqual('v3.4.37 trusted registry binding preserved', true, v3437EvidenceReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved);
  assert('v3.4.37 trusted registry binding sha', /^[a-f0-9]{64}$/.test(v3437EvidenceReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256));
  assert('v3.4.37 artifact trusted registry binding sha', /^[a-f0-9]{64}$/.test(v3437EvidenceReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256));
  assertEqual(
    'v3.4.37 trusted registry binding hashes match',
    v3437EvidenceReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256,
    v3437EvidenceReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256
  );
  assertEqual('v3.4.37 trusted registry recognition refusals preserved', true, v3437EvidenceReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved);
  assertEqual('v3.4.37 trusted registry recognition refusal count', 2, v3437EvidenceReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count);
  assertEqual('v3.4.37 trusted registry recognition refusals all refused', true, v3437EvidenceReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused);
  assertEqual(
    'v3.4.37 trusted registry recognition refusal case IDs',
    JSON.stringify(EXPECTED_TRUSTED_ISSUER_REGISTRY_REFUSAL_CASE_IDS),
    JSON.stringify(v3437EvidenceReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids)
  );
  assertEqual(
    'v3.4.37 trusted registry recognition refusal reason codes',
    JSON.stringify(EXPECTED_TRUSTED_ISSUER_REGISTRY_REFUSAL_REASON_CODES),
    JSON.stringify(v3437EvidenceReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes)
  );
  assert('v3.4.37 trusted registry recognition refusals sha', /^[a-f0-9]{64}$/.test(v3437EvidenceReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256));
  assertEqual(
    'v3.4.37 trusted registry recognition refusal hashes match',
    v3437EvidenceReport.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256,
    v3437EvidenceReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256
  );
  assertObservedTrustedIssuerRegistryBinding(
    'v3.4.37 enterprise observed trusted registry binding',
    v3437EvidenceReport.puzzle_pieces.find((piece) => piece.id === 3).observed
  );
  assertObservedTrustedIssuerRegistryBinding(
    'v3.4.37 downstream observed trusted registry binding',
    v3437EvidenceReport.puzzle_pieces.find((piece) => piece.id === 5).observed
  );

  const v3437TrustedRegistryBindingRequiredTamper = clone(v3437EvidenceReport);
  v3437TrustedRegistryBindingRequiredTamper.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_required = false;
  assertThrows(
    'v3.4.37 trusted registry binding required=false fails readiness',
    () => assertNorthStarReadinessReport(v3437TrustedRegistryBindingRequiredTamper),
    'must require installed runtime profile terminal chain trusted issuer registry binding'
  );

  const v3437TrustedRegistryBindingPreservedTamper = clone(v3437EvidenceReport);
  v3437TrustedRegistryBindingPreservedTamper.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved = false;
  assertThrows(
    'v3.4.37 trusted registry binding preserved=false fails readiness',
    () => assertNorthStarReadinessReport(v3437TrustedRegistryBindingPreservedTamper),
    'trusted issuer registry binding drifted'
  );

  const v3437TrustedRegistryBindingHashTamper = clone(v3437EvidenceReport);
  v3437TrustedRegistryBindingHashTamper.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256 =
    '1'.repeat(64);
  assertThrows(
    'v3.4.37 trusted registry binding hash drift fails readiness',
    () => assertNorthStarReadinessReport(v3437TrustedRegistryBindingHashTamper),
    'recognized receipt path mirror boundary drifted'
  );

  const v3437TrustedRegistryRecognitionRefusalsTamper = clone(v3437EvidenceReport);
  v3437TrustedRegistryRecognitionRefusalsTamper.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes[1] =
    'wrong_reason';
  assertThrows(
    'v3.4.37 trusted registry recognition refusal reason drift fails readiness',
    () => assertNorthStarReadinessReport(v3437TrustedRegistryRecognitionRefusalsTamper),
    'trusted issuer registry recognition refusals boundary drifted'
  );

  const v3437ArtifactTrustedRegistryRecognitionRefusalsTamper = clone(v3437EvidenceReport);
  v3437ArtifactTrustedRegistryRecognitionRefusalsTamper.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids[0] =
    'wrong_refusal_case';
  assertThrows(
    'v3.4.37 artifact trusted registry recognition refusal case drift fails readiness',
    () => assertNorthStarReadinessReport(v3437ArtifactTrustedRegistryRecognitionRefusalsTamper),
    'trusted issuer registry recognition refusals boundary drifted'
  );

  const v3437EnterpriseObservedTrustedRegistryRefusalsTamper = clone(v3437EvidenceReport);
  v3437EnterpriseObservedTrustedRegistryRefusalsTamper.puzzle_pieces.find((piece) => piece.id === 3).observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids[0] =
    'wrong_refusal_case';
  assertThrows(
    'v3.4.37 enterprise observed trusted registry refusal drift fails readiness',
    () => assertNorthStarReadinessReport(v3437EnterpriseObservedTrustedRegistryRefusalsTamper),
    'Enterprise Deployment Profile observed summary trusted issuer registry binding observed summary drifted'
  );

  const v3437DownstreamObservedTrustedRegistryRefusalsTamper = clone(v3437EvidenceReport);
  v3437DownstreamObservedTrustedRegistryRefusalsTamper.puzzle_pieces.find((piece) => piece.id === 5).observed.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes[1] =
    'wrong_reason';
  assertThrows(
    'v3.4.37 downstream observed trusted registry artifact refusal drift fails readiness',
    () => assertNorthStarReadinessReport(v3437DownstreamObservedTrustedRegistryRefusalsTamper),
    'Downstream Recognition Rule observed summary trusted issuer registry binding observed summary drifted'
  );

  const v3437EnterpriseObservedTrustedRegistryBindingMissingTamper = clone(v3437EvidenceReport);
  delete v3437EnterpriseObservedTrustedRegistryBindingMissingTamper.puzzle_pieces.find((piece) => piece.id === 3).observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256;
  assertThrows(
    'v3.4.37 enterprise observed missing trusted registry binding fails readiness',
    () => assertNorthStarReadinessReport(v3437EnterpriseObservedTrustedRegistryBindingMissingTamper),
    'Enterprise Deployment Profile observed summary trusted issuer registry binding observed summary drifted'
  );

  const v3437DownstreamObservedTrustedRegistryBindingClaimTamper = clone(v3437EvidenceReport);
  v3437DownstreamObservedTrustedRegistryBindingClaimTamper.puzzle_pieces.find((piece) => piece.id === 5).observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_production_downstream_recognition_proven =
    true;
  assertThrows(
    'v3.4.37 downstream observed trusted registry production claim fails readiness',
    () => assertNorthStarReadinessReport(v3437DownstreamObservedTrustedRegistryBindingClaimTamper),
    'Downstream Recognition Rule observed summary trusted issuer registry binding observed summary drifted'
  );

  assertEqual('v3.4.37 product proof path deployment bridge not required', false, v3437EvidenceReport.counts.product_proof_path_deployment_profile_authority_bridge_required);
  assertEqual('v3.4.37 product proof path deployment bridge preserved when supplied', true, v3437EvidenceReport.counts.product_proof_path_deployment_profile_authority_bridge_preserved);
  assertEqual('v3.4.37 product proof path deployment authority refusals not required', false, v3437EvidenceReport.counts.product_proof_path_deployment_profile_authority_refusals_required);
  assertEqual('v3.4.37 product proof path deployment authority refusals preserved when supplied', true, v3437EvidenceReport.counts.product_proof_path_deployment_profile_authority_refusals_preserved);

  const v3448EvidenceReport = buildReleaseForwardReadinessReport({
    verifierKitPublicDistribution: null,
    releaseForwardTargetTag: 'v3.4.48',
  });
  assert('v3.4.48 release-forward deployment bridge report passes validation', assertNorthStarReadinessReport(v3448EvidenceReport));
  assertEqual('v3.4.48 product proof path deployment bridge required', true, v3448EvidenceReport.counts.product_proof_path_deployment_profile_authority_bridge_required);
  assertEqual('v3.4.48 product proof path deployment bridge preserved', true, v3448EvidenceReport.counts.product_proof_path_deployment_profile_authority_bridge_preserved);
  assertEqual('v3.4.48 product proof path deployment authority refusals not required', false, v3448EvidenceReport.counts.product_proof_path_deployment_profile_authority_refusals_required);
  assertEqual('v3.4.48 product proof path deployment authority refusals preserved when supplied', true, v3448EvidenceReport.counts.product_proof_path_deployment_profile_authority_refusals_preserved);
  assertEqual(
    'v3.4.48 product proof path deployment bridge observed',
    true,
    v3448EvidenceReport.puzzle_pieces.find((piece) => piece.id === 1)
      .observed.product_proof_path.deployment_profile_authority_bridge_observed,
  );

  const v3448DeploymentBridgeRequiredTamper = clone(v3448EvidenceReport);
  v3448DeploymentBridgeRequiredTamper.counts.product_proof_path_deployment_profile_authority_bridge_required = false;
  assertThrows(
    'v3.4.48 deployment bridge required=false fails readiness',
    () => assertNorthStarReadinessReport(v3448DeploymentBridgeRequiredTamper),
    'must require Product Proof Path deployment-profile authority bridge'
  );

  const v3448DeploymentBridgePreservedTamper = clone(v3448EvidenceReport);
  v3448DeploymentBridgePreservedTamper.counts.product_proof_path_deployment_profile_authority_bridge_preserved = false;
  assertThrows(
    'v3.4.48 deployment bridge preserved=false fails readiness',
    () => assertNorthStarReadinessReport(v3448DeploymentBridgePreservedTamper),
    'deployment-profile authority bridge drifted'
  );

  const v3449EvidenceReport = buildReleaseForwardReadinessReport({
    verifierKitPublicDistribution: null,
    releaseForwardTargetTag: 'v3.4.49',
  });
  assert('v3.4.49 release-forward deployment authority refusal report passes validation', assertNorthStarReadinessReport(v3449EvidenceReport));
  assertEqual('v3.4.49 product proof path deployment bridge required', true, v3449EvidenceReport.counts.product_proof_path_deployment_profile_authority_bridge_required);
  assertEqual('v3.4.49 product proof path deployment authority refusals required', true, v3449EvidenceReport.counts.product_proof_path_deployment_profile_authority_refusals_required);
  assertEqual('v3.4.49 product proof path deployment authority refusals preserved', true, v3449EvidenceReport.counts.product_proof_path_deployment_profile_authority_refusals_preserved);

  const v3449DeploymentAuthorityRefusalsRequiredTamper = clone(v3449EvidenceReport);
  v3449DeploymentAuthorityRefusalsRequiredTamper.counts.product_proof_path_deployment_profile_authority_refusals_required = false;
  assertThrows(
    'v3.4.49 deployment authority refusals required=false fails readiness',
    () => assertNorthStarReadinessReport(v3449DeploymentAuthorityRefusalsRequiredTamper),
    'must require Product Proof Path deployment-profile authority refusals'
  );

  const v3449DeploymentAuthorityRefusalsPreservedTamper = clone(v3449EvidenceReport);
  v3449DeploymentAuthorityRefusalsPreservedTamper.counts.product_proof_path_deployment_profile_authority_refusals_preserved = false;
  assertThrows(
    'v3.4.49 deployment authority refusals preserved=false fails readiness',
    () => assertNorthStarReadinessReport(v3449DeploymentAuthorityRefusalsPreservedTamper),
    'deployment-profile authority refusals drifted'
  );

  const v3450EvidenceReport = buildReleaseForwardReadinessReport({
    verifierKitPublicDistribution: null,
    releaseForwardTargetTag: 'v3.4.50',
  });
  assert('v3.4.50 release-forward terminal-chain deployment-profile authority refusal mirror report passes validation', assertNorthStarReadinessReport(v3450EvidenceReport));
  assertObservedDeploymentProfileAuthorityRefusalMirror(
    'v3.4.50 terminal-chain deployment-profile authority refusal mirror',
    v3450EvidenceReport.counts
  );

  const v3450DeploymentAuthorityMirrorRequiredTamper = clone(v3450EvidenceReport);
  v3450DeploymentAuthorityMirrorRequiredTamper.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required = false;
  assertThrows(
    'v3.4.50 terminal-chain deployment-profile authority refusal mirror required=false fails readiness',
    () => assertNorthStarReadinessReport(v3450DeploymentAuthorityMirrorRequiredTamper),
    'must require installed runtime profile terminal chain deployment-profile authority refusal mirror'
  );

  const v3450DeploymentAuthorityMirrorPreservedTamper = clone(v3450EvidenceReport);
  v3450DeploymentAuthorityMirrorPreservedTamper.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved = false;
  assertThrows(
    'v3.4.50 terminal-chain deployment-profile authority refusal mirror preserved=false fails readiness',
    () => assertNorthStarReadinessReport(v3450DeploymentAuthorityMirrorPreservedTamper),
    'deployment-profile authority refusal mirror drifted'
  );

  const v3450DeploymentAuthorityMirrorCountTamper = clone(v3450EvidenceReport);
  v3450DeploymentAuthorityMirrorCountTamper.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count = 4;
  assertThrows(
    'v3.4.50 terminal-chain deployment-profile authority refusal count drift fails readiness',
    () => assertNorthStarReadinessReport(v3450DeploymentAuthorityMirrorCountTamper),
    'deployment-profile authority refusal mirror boundary drifted'
  );

  const v3450DeploymentAuthorityMirrorIdTamper = clone(v3450EvidenceReport);
  v3450DeploymentAuthorityMirrorIdTamper.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids[0] =
    'drifted_case';
  assertThrows(
    'v3.4.50 terminal-chain artifact deployment-profile authority refusal ID drift fails readiness',
    () => assertNorthStarReadinessReport(v3450DeploymentAuthorityMirrorIdTamper),
    'deployment-profile authority refusal mirror boundary drifted'
  );

  const v3450DeploymentAuthorityMirrorServiceProofTamper = clone(v3450EvidenceReport);
  v3450DeploymentAuthorityMirrorServiceProofTamper.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started = true;
  assertThrows(
    'v3.4.50 terminal-chain deployment-profile authority service proof start claim fails readiness',
    () => assertNorthStarReadinessReport(v3450DeploymentAuthorityMirrorServiceProofTamper),
    'deployment-profile authority refusal mirror boundary drifted'
  );

  const v3450DeploymentAuthorityMirrorExternalAttestationTamper = clone(v3450EvidenceReport);
  v3450DeploymentAuthorityMirrorExternalAttestationTamper.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation = true;
  assertThrows(
    'v3.4.50 terminal-chain deployment-profile authority external attestation claim fails readiness',
    () => assertNorthStarReadinessReport(v3450DeploymentAuthorityMirrorExternalAttestationTamper),
    'deployment-profile authority refusal mirror boundary drifted'
  );

  const v3450DeploymentAuthorityMirrorArtifactEnterpriseTamper = clone(v3450EvidenceReport);
  v3450DeploymentAuthorityMirrorArtifactEnterpriseTamper.counts.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_enterprise_readiness = true;
  assertThrows(
    'v3.4.50 terminal-chain artifact deployment-profile authority enterprise claim fails readiness',
    () => assertNorthStarReadinessReport(v3450DeploymentAuthorityMirrorArtifactEnterpriseTamper),
    'deployment-profile authority refusal mirror boundary drifted'
  );

  const v3451EvidenceReport = buildReleaseForwardReadinessReport({
    verifierKitPublicDistribution: null,
    releaseForwardTargetTag: 'v3.4.51',
  });
  assert('v3.4.51 release-forward report with compact receipt path mirror passes validation', assertNorthStarReadinessReport(v3451EvidenceReport));
  const v3451HistoricalReceiptPathOmission = stripRecognizedReceiptPathMirror(clone(v3451EvidenceReport));
  assert(
    'v3.4.51 historical evidence remains valid without future-local recognized receipt path mirror',
    assertNorthStarReadinessReport(v3451HistoricalReceiptPathOmission)
  );
  assertEqual(
    'v3.4.51 historical omission removes recognized receipt path counts',
    false,
    Object.keys(v3451HistoricalReceiptPathOmission.counts).some((key) => key.includes('recognized_receipt_path'))
  );

  const v3452EvidenceReport = buildReleaseForwardReadinessReport({
    verifierKitPublicDistribution: null,
    releaseForwardTargetTag: 'v3.4.52',
  });
  assert('v3.4.52 future-local compact receipt path mirror report passes validation', assertNorthStarReadinessReport(v3452EvidenceReport));
  assertObservedRecognizedReceiptPathMirror(
    'v3.4.52 terminal-chain recognized receipt path mirror',
    v3452EvidenceReport.counts
  );

  const v3452ReceiptPathMirrorMissing = stripRecognizedReceiptPathMirror(clone(v3452EvidenceReport));
  assertThrows(
    'v3.4.52 missing recognized receipt path mirror fails readiness',
    () => assertNorthStarReadinessReport(v3452ReceiptPathMirrorMissing),
    'North Star counts contains unexpected fields'
  );

  const v3452ProductProofReceiptPathMirrorExtra = clone(v3452EvidenceReport);
  v3452ProductProofReceiptPathMirrorExtra.puzzle_pieces.find(
    (piece) => piece.id === 1,
  ).observed.product_proof_path.terminal_chain_boundary
    .recognized_receipt_path_evidence_summary = { verdict: 'RECOGNIZED' };
  assertThrows(
    'v3.4.52 extra recognized receipt path mirror field fails readiness',
    () => assertNorthStarReadinessReport(v3452ProductProofReceiptPathMirrorExtra),
    'North Star Product Proof Path terminal chain boundary summary contains unexpected fields'
  );

  const v3452ProductProofReceiptPathMirrorRenamed = clone(v3452EvidenceReport);
  v3452ProductProofReceiptPathMirrorRenamed.puzzle_pieces.find(
    (piece) => piece.id === 1,
  ).observed.product_proof_path.terminal_chain_boundary
    .recognized_receipt_path_evidence_hash =
      v3452ProductProofReceiptPathMirrorRenamed.puzzle_pieces.find(
        (piece) => piece.id === 1,
      ).observed.product_proof_path.terminal_chain_boundary
        .recognized_receipt_path_evidence_sha256;
  delete v3452ProductProofReceiptPathMirrorRenamed.puzzle_pieces.find(
    (piece) => piece.id === 1,
  ).observed.product_proof_path.terminal_chain_boundary
    .recognized_receipt_path_evidence_sha256;
  assertThrows(
    'v3.4.52 renamed recognized receipt path mirror field fails readiness',
    () => assertNorthStarReadinessReport(v3452ProductProofReceiptPathMirrorRenamed),
    'North Star Product Proof Path terminal chain boundary summary contains unexpected fields'
  );

  const v3452ProductProofReceiptPathMirrorSummaryShaped = clone(v3452EvidenceReport);
  v3452ProductProofReceiptPathMirrorSummaryShaped.puzzle_pieces.find(
    (piece) => piece.id === 1,
  ).observed.product_proof_path.terminal_chain_boundary
    .recognized_receipt_path_evidence_sha256 = {
      sha256: v3452EvidenceReport.counts
        .installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256,
    };
  assertThrows(
    'v3.4.52 summary-shaped recognized receipt path mirror field fails readiness',
    () => assertNorthStarReadinessReport(v3452ProductProofReceiptPathMirrorSummaryShaped),
    'North Star Product Proof Path summary drifted'
  );

  const v3452ProductProofReceiptPathMirrorMissingField = clone(v3452EvidenceReport);
  delete v3452ProductProofReceiptPathMirrorMissingField.puzzle_pieces.find(
    (piece) => piece.id === 1,
  ).observed.product_proof_path.terminal_chain_boundary
    .recognized_receipt_path_evidence_sha256;
  assertThrows(
    'v3.4.52 missing Product Proof Path recognized receipt path mirror field fails readiness',
    () => assertNorthStarReadinessReport(v3452ProductProofReceiptPathMirrorMissingField),
    'North Star Product Proof Path terminal chain boundary summary contains unexpected fields'
  );

  const v3452ReceiptPathShaTamper = clone(v3452EvidenceReport);
  v3452ReceiptPathShaTamper.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_sha256 =
    '0'.repeat(64);
  assertThrows(
    'v3.4.52 recognized receipt path evidence sha tamper fails readiness',
    () => assertNorthStarReadinessReport(v3452ReceiptPathShaTamper),
    'Enterprise Deployment Profile observed summary recognized receipt path observed summary drifted'
  );

  const v3452ReceiptPathSourceMismatch = clone(v3452EvidenceReport);
  v3452ReceiptPathSourceMismatch.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_source_binding_sha256 =
    '1'.repeat(64);
  assertThrows(
    'v3.4.52 recognized receipt path source-binding mismatch fails readiness',
    () => assertNorthStarReadinessReport(v3452ReceiptPathSourceMismatch),
    'recognized receipt path mirror boundary drifted'
  );

  const v3452ReceiptPathBoundToArtifactTamper = clone(v3452EvidenceReport);
  v3452ReceiptPathBoundToArtifactTamper.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_evidence_bound_to_artifact_body =
    false;
  assertThrows(
    'v3.4.52 recognized receipt path artifact-body binding drift fails readiness',
    () => assertNorthStarReadinessReport(v3452ReceiptPathBoundToArtifactTamper),
    'recognized receipt path mirror boundary drifted'
  );

  const v3452ReceiptPathFalseBoundaryCountFlip = clone(v3452EvidenceReport);
  v3452ReceiptPathFalseBoundaryCountFlip.counts.installed_runtime_profile_terminal_chain_recognized_receipt_path_public_external_attestation = true;
  assertThrows(
    'v3.4.52 recognized receipt path false-boundary count flip fails readiness',
    () => assertNorthStarReadinessReport(v3452ReceiptPathFalseBoundaryCountFlip),
    'recognized receipt path false boundary drifted'
  );

  const v3452ProductProofReceiptPathFalseBoundaryFlip = clone(v3452EvidenceReport);
  v3452ProductProofReceiptPathFalseBoundaryFlip.puzzle_pieces.find(
    (piece) => piece.id === 1,
  ).observed.product_proof_path.terminal_chain_boundary
    .recognized_receipt_path_evidence_public_external_attestation = true;
  assertThrows(
    'v3.4.52 Product Proof Path recognized receipt path false-boundary flip fails readiness',
    () => assertNorthStarReadinessReport(v3452ProductProofReceiptPathFalseBoundaryFlip),
    'North Star Product Proof Path summary drifted'
  );

  const v3425CaseIdsRequiredTamper = clone(v3425EvidenceReport);
  v3425CaseIdsRequiredTamper.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required = false;
  assertThrows(
    'v3.4.25 release-forward recognition refusal group case IDs required=false fails readiness',
    () => assertNorthStarReadinessReport(v3425CaseIdsRequiredTamper),
    'must require installed runtime profile terminal chain recognition refusal group case IDs'
  );

  const v3425CaseIdsMissingTamper = clone(v3425EvidenceReport);
  v3425CaseIdsMissingTamper.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved = false;
  delete v3425CaseIdsMissingTamper.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids;
  assertThrows(
    'v3.4.25 release-forward missing recognition refusal group case IDs fails readiness',
    () => assertNorthStarReadinessReport(v3425CaseIdsMissingTamper),
    'North Star counts contains unexpected fields'
  );

  const v3425CaseIdsDriftTamper = clone(v3425EvidenceReport);
  v3425CaseIdsDriftTamper.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids.recognized_receipt_scope_mismatch[0] =
    'wrong_case_id';
  assertThrows(
    'v3.4.25 release-forward changed recognition refusal group case ID fails readiness',
    () => assertNorthStarReadinessReport(v3425CaseIdsDriftTamper),
    'recognition refusal group case IDs boundary drifted'
  );

  const v3425ArtifactCaseIdsDriftTamper = clone(v3425EvidenceReport);
  v3425ArtifactCaseIdsDriftTamper.counts.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids.route_or_request_authority_material_refused.reverse();
  assertThrows(
    'v3.4.25 release-forward reordered artifact recognition refusal group case IDs fails readiness',
    () => assertNorthStarReadinessReport(v3425ArtifactCaseIdsDriftTamper),
    'recognition refusal group case IDs boundary drifted'
  );

  const v3425CaseCountTamper = clone(v3425EvidenceReport);
  v3425CaseCountTamper.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count = 17;
  assertThrows(
    'v3.4.25 release-forward recognition refusal group case count drift fails readiness',
    () => assertNorthStarReadinessReport(v3425CaseCountTamper),
    'recognition refusal group case IDs boundary drifted'
  );

  const missingRecognitionDigestPreflight = readEvidenceJson('zlar-installed-runtime-profile-preflight-sample-verification.json');
  delete missingRecognitionDigestPreflight.recognition_contract_sha256;
  const missingRecognitionDigestReport = buildReleaseForwardReadinessReport({
    installedRuntimeProfilePreflightVerification: missingRecognitionDigestPreflight,
    verifierKitPublicDistribution: null,
    releaseForwardTargetTag: 'v3.4.19',
  });
  assertEqual(
    'v3.4.19 missing preflight recognition digest count false',
    false,
    missingRecognitionDigestReport.counts.installed_runtime_profile_recognition_contract_digest_preserved
  );
  assertThrows(
    'v3.4.19 missing preflight recognition digest fails readiness',
    () => assertNorthStarReadinessReport(missingRecognitionDigestReport),
    'puzzle-piece counts drifted'
  );

  const driftedRecognitionDigestSmoke = readEvidenceJson('zlar-proof-smoke-sample-verification.json');
  driftedRecognitionDigestSmoke.counts.installed_runtime_profile_service_recognition_contract_sha256 = '5'.repeat(64);
  const driftedRecognitionDigestReport = buildReleaseForwardReadinessReport({
    proofSmokeVerification: driftedRecognitionDigestSmoke,
    verifierKitPublicDistribution: null,
    releaseForwardTargetTag: 'v3.4.19',
  });
  assertEqual(
    'v3.4.19 drifted service recognition digest count false',
    false,
    driftedRecognitionDigestReport.counts.installed_runtime_profile_recognition_contract_digest_preserved
  );
  assertThrows(
    'v3.4.19 drifted service recognition digest fails readiness',
    () => assertNorthStarReadinessReport(driftedRecognitionDigestReport),
    'puzzle-piece counts drifted'
  );

  const legacyServiceArtifactVerificationSmoke = clone(JSON.parse(readFileSync(join(evidenceDir, 'zlar-proof-smoke-sample-verification.json'), 'utf8')));
  const legacyServiceArtifactVerification = clone(JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'), 'utf8')));
  delete legacyServiceArtifactVerificationSmoke.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256;
  delete legacyServiceArtifactVerification.required_refusal_cases;
  delete legacyServiceArtifactVerification.observed_refusal_cases;
  delete legacyServiceArtifactVerification.refusal_taxonomy_sha256;
  const legacyServiceArtifactVerificationReport = buildNorthStarReadinessReport({
    evidenceModel: 'release-forward-dry-run-artifacts',
    productProofPathReport: JSON.parse(readFileSync(join(evidenceDir, 'zlar-product-proof-path-v1.json'), 'utf8')),
    proofSmokeVerification: legacyServiceArtifactVerificationSmoke,
    localProofPackVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-local-proof-pack-sample-verification.json'), 'utf8')),
    servicePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-service-preflight-sample-verification.json'), 'utf8')),
    runtimeLocalActivationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-local-activation-sample-verification.json'), 'utf8')),
    runtimeProfileInstallationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-profile-installation-sample-verification.json'), 'utf8')),
    installedRuntimeProfilePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-preflight-sample-verification.json'), 'utf8')),
    installedRuntimeProfileRecognitionProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-recognition-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProofArtifactVerification: legacyServiceArtifactVerification,
    coverageMap: JSON.parse(readFileSync(join(evidenceDir, 'zlar-coverage-map-sample.json'), 'utf8')),
    releaseForwardTargetTag: 'v3.4.14',
  });
  assert('legacy v3.4.14 service artifact verification without taxonomy passes validation', assertNorthStarReadinessReport(legacyServiceArtifactVerificationReport));
  assertEqual('legacy v3.4.14 service artifact verification required', true, legacyServiceArtifactVerificationReport.counts.installed_runtime_profile_service_artifact_verification_required);
  assertEqual('legacy v3.4.14 service artifact verification preserved', true, legacyServiceArtifactVerificationReport.counts.installed_runtime_profile_service_artifact_verification_preserved);
  assertEqual('legacy v3.4.14 service artifact taxonomy not required', false, legacyServiceArtifactVerificationReport.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_required);
  assertEqual('legacy v3.4.14 service artifact taxonomy not preserved', false, legacyServiceArtifactVerificationReport.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved);
  assertEqual('legacy v3.4.14 service artifact taxonomy hash absent', 'not-provided', legacyServiceArtifactVerificationReport.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256);

  assertEqual(
    'evidence-dir simulated human authorization verified',
    true,
    evidenceReport.puzzle_pieces.find((piece) => piece.id === 1).observed.simulated_human_authorization_verified
  );
  assertEqual(
    'evidence-dir product proof path summary provided',
    true,
    evidenceReport.puzzle_pieces.find((piece) => piece.id === 1).observed.product_proof_path.provided
  );
  assertRuntimeProfileIdentityPolicy(
    'evidence-dir product proof path proof-pack runtime-profile identity policy',
    evidenceReport.puzzle_pieces.find((piece) => piece.id === 1).observed.product_proof_path
      .proof_pack_runtime_profile_identity_policy,
  );
  assertRuntimeProfileIdentityPolicy(
    'evidence-dir downstream recognition runtime-profile identity policy',
    evidenceReport.puzzle_pieces.find((piece) => piece.id === 5).observed
      .runtime_profile_identity_policy,
  );
  assertEqual(
    'evidence-dir product proof path trusted registry observed',
    true,
    evidenceReport.puzzle_pieces.find((piece) => piece.id === 1).observed.product_proof_path
      .trusted_issuer_registry_recognition_observed
  );
  assertEqual(
    'evidence-dir product proof path trusted registry no current-machine governance',
    false,
    evidenceReport.puzzle_pieces.find((piece) => piece.id === 1).observed.product_proof_path
      .trusted_issuer_registry_recognition.proves_current_machine_governance
  );
  assertEqual(
    'evidence-dir product proof path trusted registry fixture evaluated',
    true,
    evidenceReport.puzzle_pieces.find((piece) => piece.id === 1).observed.product_proof_path
      .trusted_issuer_registry_recognition.registry_fixture_evaluated
  );
  assertEqual(
    'evidence-dir product proof path trusted registry evaluator result type',
    'downstream-recognition-rule-v1',
    evidenceReport.puzzle_pieces.find((piece) => piece.id === 1).observed.product_proof_path
      .trusted_issuer_registry_recognition.registry_evaluation_result_type
  );
  const issuerPiece = evidenceReport.puzzle_pieces.find((piece) => piece.id === 4);
  const publicBoundaryPiece = evidenceReport.puzzle_pieces.find((piece) => piece.id === 7);
  const privateIntakePointer = publicBoundaryPiece.observed.private_intake_sample_manifest_pointer;
  assertEqual('evidence-dir trusted registry provided', true, issuerPiece.observed.trusted_issuer_registry_recognition.provided);
  assertEqual('evidence-dir trusted registry recognized', true, issuerPiece.observed.trusted_issuer_registry_recognition.recognized);
  assertEqual('evidence-dir malformed registry provided', true, issuerPiece.observed.malformed_registry_contract.provided);
  assertEqual('evidence-dir malformed registry fail-closed', true, issuerPiece.observed.malformed_registry_contract.fail_closed_before_verdict);
  assertEqual('evidence-dir verifier kit reproducibility provided', true, issuerPiece.observed.verifier_kit_reproducibility.provided);
  assertEqual('evidence-dir verifier kit reproducibility result', 'PASS', issuerPiece.observed.verifier_kit_reproducibility.result);
  assertEqual('evidence-dir verifier kit tarball identical', true, issuerPiece.observed.verifier_kit_reproducibility.tarball_sha256_identical);
  assertEqual('evidence-dir verifier kit manifest identical', true, issuerPiece.observed.verifier_kit_reproducibility.manifest_and_signature_sha256_identical);
  assertEqual('evidence-dir verifier kit sidecar matches', true, issuerPiece.observed.verifier_kit_reproducibility.sidecar_matches_tarball);
  assertEqual('evidence-dir verifier kit public hashes present', true, issuerPiece.observed.verifier_kit_reproducibility.public_artifact_hashes_present);
  assertEqual('evidence-dir verifier kit boundary false', true, issuerPiece.observed.verifier_kit_reproducibility.claim_boundary_flags_false);
  assert('evidence-dir artifacts include verifier kit reproducibility', evidenceReport.artifacts_consumed.includes('zlar-verifier-kit-reproducibility-v1.json'));
  assertEqual('evidence-dir verifier kit release assets absent before v3.4.31', false, issuerPiece.observed.verifier_kit_release_assets.provided);
  assertEqual('evidence-dir verifier kit public distribution provided', true, issuerPiece.observed.verifier_kit_public_distribution.provided);
  assertEqual('evidence-dir verifier kit public distribution posture', 'public_release_assets_absent', issuerPiece.observed.verifier_kit_public_distribution.posture);
  assertEqual('evidence-dir verifier kit public distribution not ready', false, issuerPiece.observed.verifier_kit_public_distribution.ready_for_public_distribution_claim);
  assertEqual('evidence-dir verifier kit public distribution blockers', true, issuerPiece.observed.verifier_kit_public_distribution.blocking_reasons_count > 0);
  assertEqual('evidence-dir verifier kit public distribution hashes', true, issuerPiece.observed.verifier_kit_public_distribution.public_artifact_hashes_present);
  assertEqual('evidence-dir verifier kit public distribution byte binding false', false, issuerPiece.observed.verifier_kit_public_distribution.release_asset_hashes_bound);
  assert('evidence-dir artifacts include verifier kit public distribution', evidenceReport.artifacts_consumed.includes('zlar-verifier-kit-public-distribution-v1.json'));
  assertEqual('evidence-dir private intake pointer provided', true, privateIntakePointer.provided);
  assertEqual('evidence-dir private intake pointer release tag', 'v3.3.106', privateIntakePointer.release_tag);
  assertEqual('evidence-dir private intake pointer manifest field', 'private_verifier_result_sample', privateIntakePointer.manifest_field);
  assertEqual('evidence-dir private intake pointer result section', 'Private Verifier Result Intake', privateIntakePointer.result_section);
  assertEqual('evidence-dir private intake pointer non-circular', true, privateIntakePointer.circular_hash_avoided);
  assertEqual('evidence-dir private intake pointer no attestation', false, privateIntakePointer.creates_public_external_attestation);
  assertEqual('evidence-dir private intake pointer no non-operator review', false, privateIntakePointer.proves_non_operator_review);

  const publicEvidenceDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-public-assets-'));
  rmSync(publicEvidenceDir, { recursive: true, force: true });
  cpSync(evidenceDir, publicEvidenceDir, { recursive: true });
  try {
    const distDir = join(publicEvidenceDir, 'dist');
    const kitDir = join(distDir, 'zlar-verifier-kit-v0.1.0');
    mkdirSync(kitDir, { recursive: true });
    const tarballBody = Buffer.from('public verifier kit tarball fixture\n', 'utf8');
    const sidecarBody = Buffer.from(`${sha256(tarballBody)}  zlar-verifier-kit-v0.1.0.tar.gz\n`, 'utf8');
    const manifestBody = Buffer.from('{"fixture":"manifest"}\n', 'utf8');
    const signatureBody = Buffer.from('fixture-signature\n', 'utf8');
    writeFileSync(join(distDir, 'zlar-verifier-kit-v0.1.0.tar.gz'), tarballBody);
    writeFileSync(join(distDir, 'zlar-verifier-kit-v0.1.0.tar.gz.sha256'), sidecarBody);
    writeFileSync(join(kitDir, 'MANIFEST.json'), manifestBody);
    writeFileSync(join(kitDir, 'MANIFEST.sig'), signatureBody);
    const publicReproducibility = {
      ...readEvidenceJson('zlar-verifier-kit-reproducibility-v1.json'),
      public_artifact_hashes: [
        {
          path: 'dist/zlar-verifier-kit-v0.1.0.tar.gz',
          sha256: sha256(tarballBody),
        },
        {
          path: 'dist/zlar-verifier-kit-v0.1.0.tar.gz.sha256',
          sha256: sha256(sidecarBody),
        },
        {
          path: 'dist/zlar-verifier-kit-v0.1.0/MANIFEST.json',
          sha256: sha256(manifestBody),
        },
        {
          path: 'dist/zlar-verifier-kit-v0.1.0/MANIFEST.sig',
          sha256: sha256(signatureBody),
        },
      ],
    };
    const publicReproducibilityText = `${JSON.stringify(publicReproducibility, null, 2)}\n`;
    const publicReproducibilitySha256 = sha256(publicReproducibilityText);
    writeFileSync(
      join(publicEvidenceDir, 'zlar-verifier-kit-reproducibility-v1.json'),
      publicReproducibilityText
    );
    const liveReleaseAssets = {
      report_type: 'zlar-verifier-kit-release-assets-live-v1',
      schema_version: 1,
      generated_at: '2026-06-23T00:00:00Z',
      evidence_model: 'github-release-assets-json-live-read',
      repository: 'ZLAR-AI/ZLAR',
      tagName: 'v3.4.31',
      tag_name: 'v3.4.31',
      url: 'https://github.com/ZLAR-AI/ZLAR/releases/tag/v3.4.31',
      html_url: 'https://github.com/ZLAR-AI/ZLAR/releases/tag/v3.4.31',
      isDraft: false,
      draft: false,
      immutable: false,
      prerelease: false,
      published_at: '2026-06-23T00:00:00Z',
      asset_count: 3,
      assets: [
        {
          name: 'zlar-verifier-kit-v0.1.0.tar.gz',
          size: tarballBody.length,
          state: 'uploaded',
          content_type: 'application/gzip',
          digest: '',
          browser_download_url: 'https://github.com/ZLAR-AI/ZLAR/releases/download/v3.4.31/zlar-verifier-kit-v0.1.0.tar.gz',
          api_url: 'https://api.github.com/repos/ZLAR-AI/ZLAR/releases/assets/1',
          downloaded_sha256: sha256(tarballBody),
          downloaded_size: tarballBody.length,
          downloaded: true,
        },
        {
          name: 'zlar-verifier-kit-v0.1.0.tar.gz.sha256',
          size: sidecarBody.length,
          state: 'uploaded',
          content_type: 'text/plain',
          digest: '',
          browser_download_url: 'https://github.com/ZLAR-AI/ZLAR/releases/download/v3.4.31/zlar-verifier-kit-v0.1.0.tar.gz.sha256',
          api_url: 'https://api.github.com/repos/ZLAR-AI/ZLAR/releases/assets/2',
          downloaded_sha256: sha256(sidecarBody),
          downloaded_size: sidecarBody.length,
          downloaded: true,
        },
        {
          name: 'zlar-verifier-kit-reproducibility-v1.json',
          size: Buffer.byteLength(publicReproducibilityText),
          state: 'uploaded',
          content_type: 'application/json',
          digest: '',
          browser_download_url: 'https://github.com/ZLAR-AI/ZLAR/releases/download/v3.4.31/zlar-verifier-kit-reproducibility-v1.json',
          api_url: 'https://api.github.com/repos/ZLAR-AI/ZLAR/releases/assets/3',
          downloaded_sha256: publicReproducibilitySha256,
          downloaded_size: Buffer.byteLength(publicReproducibilityText),
          downloaded: true,
        },
      ],
      required_release_assets: [
        { name: 'zlar-verifier-kit-v0.1.0.tar.gz', present: true, downloaded_sha256_present: true },
        { name: 'zlar-verifier-kit-v0.1.0.tar.gz.sha256', present: true, downloaded_sha256_present: true },
        { name: 'zlar-verifier-kit-reproducibility-v1.json', present: true, downloaded_sha256_present: true },
      ],
      all_required_assets_present: true,
      all_required_assets_downloaded: true,
      claim_boundary: {
        mutates_release: false,
        uploads_release_assets: false,
        creates_public_external_attestation: false,
        proves_non_operator_review: false,
        proves_production_publisher_key_custody: false,
        proves_production_signing_identity: false,
        proves_enterprise_readiness: false,
        proves_sovereign_recognition: false,
        proves_v3_4_0_readiness: false,
      },
      non_claims: [
        'This report only reads release metadata and release asset bytes.',
        'This report does not upload release assets or mutate GitHub release state.',
      ],
    };
    writeFileSync(
      join(publicEvidenceDir, 'zlar-verifier-kit-release-assets-v1.json'),
      `${JSON.stringify(liveReleaseAssets, null, 2)}\n`
    );
    const rebuiltPublicDistribution = buildVerifierKitPublicDistributionReport({
      releaseTag: 'v3.4.31',
      releaseAssetsJson: liveReleaseAssets,
      reproducibility: publicReproducibility,
      reproducibilitySha256: publicReproducibilitySha256,
      assetDir: publicEvidenceDir,
    });
    writeFileSync(
      join(publicEvidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'),
      `${JSON.stringify(rebuiltPublicDistribution, null, 2)}\n`
    );
    const publicEvidenceRun = runZlar([
      'north-star-readiness',
      '--evidence-dir',
      publicEvidenceDir,
      '--release-tag',
      'v3.4.31',
      '--json',
    ]);
    assertEqual('v3.4.31 public assets readiness exits zero', 0, publicEvidenceRun.status);
    assertEqual('v3.4.31 public assets readiness emits no stderr', '', publicEvidenceRun.stderr);
    const publicEvidenceReport = JSON.parse(publicEvidenceRun.stdout);
    assert('v3.4.31 public assets report validates', assertNorthStarReadinessReport(publicEvidenceReport));
    assertEqual('v3.4.31 public assets readiness result', 'READY_FOR_V3_4_0_PUBLIC_VERIFIER_KIT_DISTRIBUTION', publicEvidenceReport.result);
    assert('v3.4.31 public assets consumed live-read artifact', publicEvidenceReport.artifacts_consumed.includes('zlar-verifier-kit-release-assets-v1.json'));
    const publicIssuer = publicEvidenceReport.puzzle_pieces.find((piece) => piece.id === 4);
    assertEqual('v3.4.31 public assets live-read provided', true, publicIssuer.observed.verifier_kit_release_assets.provided);
    assertEqual('v3.4.31 public assets live-read model', 'github-release-assets-json-live-read', publicIssuer.observed.verifier_kit_release_assets.evidence_model);
    assertEqual('v3.4.31 public assets live-read repository', 'ZLAR-AI/ZLAR', publicIssuer.observed.verifier_kit_release_assets.repository);
    assertEqual('v3.4.31 public assets live-read repository match', true, publicIssuer.observed.verifier_kit_release_assets.repository_matches_expected);
    assertEqual('v3.4.31 public assets live-read release URL repository', true, publicIssuer.observed.verifier_kit_release_assets.release_url_names_expected_repository);
    assertEqual('v3.4.31 public assets live-read asset URL repository', true, publicIssuer.observed.verifier_kit_release_assets.asset_urls_name_expected_repository);
    assertEqual('v3.4.31 public assets live-read downloaded', true, publicIssuer.observed.verifier_kit_release_assets.all_required_assets_downloaded);
    assertEqual('v3.4.31 public assets distribution ready', true, publicIssuer.observed.verifier_kit_public_distribution.ready_for_public_distribution_claim);
    assertEqual('v3.4.31 public assets external attestation false', false, publicEvidenceReport.claim_boundary.public_external_attestation);

    const staticPublicEvidenceDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-static-public-assets-'));
    rmSync(staticPublicEvidenceDir, { recursive: true, force: true });
    cpSync(publicEvidenceDir, staticPublicEvidenceDir, { recursive: true });
    try {
      const staticPublicAssets = {
        tagName: 'v3.4.59',
        url: 'https://zlar.ai/verifier-kit/v3.4.59/',
        evidence_model: 'static-public-artifact-source-live-read',
        public_artifact_source: 'zlar.ai',
        anonymous_access_verified: true,
        assets: [
          {
            name: 'zlar-verifier-kit-v0.1.0.tar.gz',
            size: tarballBody.length,
            state: 'uploaded',
            browser_download_url: 'https://zlar.ai/verifier-kit/v3.4.59/zlar-verifier-kit-v0.1.0.tar.gz',
            digest: `sha256:${sha256(tarballBody)}`,
          },
          {
            name: 'zlar-verifier-kit-v0.1.0.tar.gz.sha256',
            size: sidecarBody.length,
            state: 'uploaded',
            browser_download_url: 'https://zlar.ai/verifier-kit/v3.4.59/zlar-verifier-kit-v0.1.0.tar.gz.sha256',
            digest: `sha256:${sha256(sidecarBody)}`,
          },
          {
            name: 'zlar-verifier-kit-reproducibility-v1.json',
            size: Buffer.byteLength(publicReproducibilityText),
            state: 'uploaded',
            browser_download_url: 'https://zlar.ai/verifier-kit/v3.4.59/zlar-verifier-kit-reproducibility-v1.json',
            digest: `sha256:${publicReproducibilitySha256}`,
          },
        ],
      };
      writeFileSync(
        join(staticPublicEvidenceDir, 'zlar-verifier-kit-release-assets-v1.json'),
        `${JSON.stringify(staticPublicAssets, null, 2)}\n`
      );
      const staticPublicDistribution = buildVerifierKitPublicDistributionReport({
        releaseTag: 'v3.4.59',
        releaseAssetsJson: staticPublicAssets,
        reproducibility: publicReproducibility,
        reproducibilitySha256: publicReproducibilitySha256,
        assetDir: staticPublicEvidenceDir,
      });
      writeFileSync(
        join(staticPublicEvidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'),
        `${JSON.stringify(staticPublicDistribution, null, 2)}\n`
      );
      const staticPublicRun = runZlar([
        'north-star-readiness',
        '--evidence-dir',
        staticPublicEvidenceDir,
        '--release-tag',
        'v3.4.59',
        '--json',
      ]);
      assertEqual('v3.4.59 static public readiness exits zero', 0, staticPublicRun.status);
      assertEqual('v3.4.59 static public readiness emits no stderr', '', staticPublicRun.stderr);
      const staticPublicReport = JSON.parse(staticPublicRun.stdout);
      assert('v3.4.59 static public report validates', assertNorthStarReadinessReport(staticPublicReport));
      assertEqual('v3.4.59 static public readiness result', 'READY_FOR_V3_4_0_PUBLIC_VERIFIER_KIT_DISTRIBUTION', staticPublicReport.result);
      const staticPublicIssuer = staticPublicReport.puzzle_pieces.find((piece) => piece.id === 4);
      assertEqual('v3.4.59 static public live-read absent', false, staticPublicIssuer.observed.verifier_kit_release_assets.provided);
      assertEqual('v3.4.59 static public distribution ready', true, staticPublicIssuer.observed.verifier_kit_public_distribution.ready_for_public_distribution_claim);
      assertEqual('v3.4.59 static public evidence true', true, staticPublicIssuer.observed.verifier_kit_public_distribution.static_public_artifact_source_evidence);
      assertEqual('v3.4.59 static public source', 'zlar.ai', staticPublicIssuer.observed.verifier_kit_public_distribution.public_artifact_source);
      assertEqual('v3.4.59 static public external attestation false', false, staticPublicReport.claim_boundary.public_external_attestation);

      const missingStaticSourceDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-missing-static-source-'));
      rmSync(missingStaticSourceDir, { recursive: true, force: true });
      cpSync(staticPublicEvidenceDir, missingStaticSourceDir, { recursive: true });
      try {
        rmSync(join(missingStaticSourceDir, 'zlar-verifier-kit-release-assets-v1.json'), { force: true });
        const missingStaticSourceRun = runZlar([
          'north-star-readiness',
          '--evidence-dir',
          missingStaticSourceDir,
          '--release-tag',
          'v3.4.59',
          '--json',
        ]);
        assert('v3.4.59 missing static source exits nonzero', missingStaticSourceRun.status !== 0);
        assertEqual('v3.4.59 missing static source emits no stdout', '', missingStaticSourceRun.stdout);
        assert('v3.4.59 missing static source names evidence requirement', missingStaticSourceRun.stderr.includes('release-asset live-read or static public artifact source evidence is required'));
      } finally {
        rmSync(missingStaticSourceDir, { recursive: true, force: true });
      }

      const tamperedStaticSourceDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-tampered-static-source-'));
      rmSync(tamperedStaticSourceDir, { recursive: true, force: true });
      cpSync(staticPublicEvidenceDir, tamperedStaticSourceDir, { recursive: true });
      try {
        writeFileSync(
          join(tamperedStaticSourceDir, 'zlar-verifier-kit-release-assets-v1.json'),
          `${JSON.stringify({ ...staticPublicAssets, anonymous_access_verified: false }, null, 2)}\n`
        );
        const tamperedStaticSourceRun = runZlar([
          'north-star-readiness',
          '--evidence-dir',
          tamperedStaticSourceDir,
          '--release-tag',
          'v3.4.59',
          '--json',
        ]);
        assert('v3.4.59 tampered static source exits nonzero', tamperedStaticSourceRun.status !== 0);
        assertEqual('v3.4.59 tampered static source emits no stdout', '', tamperedStaticSourceRun.stdout);
        assert('v3.4.59 tampered static source names evidence requirement', tamperedStaticSourceRun.stderr.includes('release-asset live-read or static public artifact source evidence is required'));
      } finally {
        rmSync(tamperedStaticSourceDir, { recursive: true, force: true });
      }
    } finally {
      rmSync(staticPublicEvidenceDir, { recursive: true, force: true });
    }

    const wrongRepoEvidenceDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-wrong-repo-assets-'));
    rmSync(wrongRepoEvidenceDir, { recursive: true, force: true });
    cpSync(publicEvidenceDir, wrongRepoEvidenceDir, { recursive: true });
    try {
      const wrongRepoReleaseAssets = clone(liveReleaseAssets);
      wrongRepoReleaseAssets.repository = 'not-zlar/not-zlar';
      wrongRepoReleaseAssets.url = 'https://github.com/not-zlar/not-zlar/releases/tag/v3.4.31';
      wrongRepoReleaseAssets.html_url = 'https://github.com/not-zlar/not-zlar/releases/tag/v3.4.31';
      wrongRepoReleaseAssets.assets = wrongRepoReleaseAssets.assets.map((asset, index) => ({
        ...asset,
        browser_download_url:
          `https://github.com/not-zlar/not-zlar/releases/download/v3.4.31/${asset.name}`,
        api_url: `https://api.github.com/repos/not-zlar/not-zlar/releases/assets/${index + 1}`,
      }));
      writeFileSync(
        join(wrongRepoEvidenceDir, 'zlar-verifier-kit-release-assets-v1.json'),
        `${JSON.stringify(wrongRepoReleaseAssets, null, 2)}\n`
      );
      const wrongRepoPublicDistribution = buildVerifierKitPublicDistributionReport({
        releaseTag: 'v3.4.31',
        releaseAssetsJson: wrongRepoReleaseAssets,
        reproducibility: publicReproducibility,
        reproducibilitySha256: publicReproducibilitySha256,
        assetDir: wrongRepoEvidenceDir,
      });
      writeFileSync(
        join(wrongRepoEvidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'),
        `${JSON.stringify(wrongRepoPublicDistribution, null, 2)}\n`
      );
      const wrongRepoRun = runZlar([
        'north-star-readiness',
        '--evidence-dir',
        wrongRepoEvidenceDir,
        '--release-tag',
        'v3.4.31',
        '--json',
      ]);
      assertEqual('v3.4.31 wrong repo readiness exits zero', 0, wrongRepoRun.status);
      assertEqual('v3.4.31 wrong repo readiness emits no stderr', '', wrongRepoRun.stderr);
      const wrongRepoReport = JSON.parse(wrongRepoRun.stdout);
      assert('v3.4.31 wrong repo report validates', assertNorthStarReadinessReport(wrongRepoReport));
      assertEqual('v3.4.31 wrong repo not ready', 'NOT_READY_FOR_V3_4_0', wrongRepoReport.result);
      const wrongRepoIssuer = wrongRepoReport.puzzle_pieces.find((piece) => piece.id === 4);
      assertEqual('v3.4.31 wrong repo live-read repository mismatch', false, wrongRepoIssuer.observed.verifier_kit_release_assets.repository_matches_expected);
      assertEqual('v3.4.31 wrong repo distribution not ready', false, wrongRepoIssuer.observed.verifier_kit_public_distribution.ready_for_public_distribution_claim);
    } finally {
      rmSync(wrongRepoEvidenceDir, { recursive: true, force: true });
    }

    const incompleteEvidenceDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-incomplete-live-assets-'));
    rmSync(incompleteEvidenceDir, { recursive: true, force: true });
    cpSync(publicEvidenceDir, incompleteEvidenceDir, { recursive: true });
    try {
      const incompleteReleaseAssets = clone(liveReleaseAssets);
      incompleteReleaseAssets.assets = incompleteReleaseAssets.assets.slice(0, 2);
      incompleteReleaseAssets.asset_count = incompleteReleaseAssets.assets.length;
      incompleteReleaseAssets.required_release_assets =
        incompleteReleaseAssets.required_release_assets.map((asset) => (
          asset.name === 'zlar-verifier-kit-reproducibility-v1.json'
            ? { ...asset, present: false, downloaded_sha256_present: false }
            : asset
        ));
      incompleteReleaseAssets.all_required_assets_present = false;
      incompleteReleaseAssets.all_required_assets_downloaded = false;
      writeFileSync(
        join(incompleteEvidenceDir, 'zlar-verifier-kit-release-assets-v1.json'),
        `${JSON.stringify(incompleteReleaseAssets, null, 2)}\n`
      );
      const incompletePublicDistribution = buildVerifierKitPublicDistributionReport({
        releaseTag: 'v3.4.31',
        releaseAssetsJson: incompleteReleaseAssets,
        reproducibility: publicReproducibility,
        reproducibilitySha256: publicReproducibilitySha256,
        assetDir: incompleteEvidenceDir,
      });
      writeFileSync(
        join(incompleteEvidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'),
        `${JSON.stringify(incompletePublicDistribution, null, 2)}\n`
      );
      const incompleteRun = runZlar([
        'north-star-readiness',
        '--evidence-dir',
        incompleteEvidenceDir,
        '--release-tag',
        'v3.4.31',
        '--json',
      ]);
      assertEqual('v3.4.31 incomplete live evidence exits zero', 0, incompleteRun.status);
      assertEqual('v3.4.31 incomplete live evidence emits no stderr', '', incompleteRun.stderr);
      const incompleteReport = JSON.parse(incompleteRun.stdout);
      assert('v3.4.31 incomplete live evidence report validates', assertNorthStarReadinessReport(incompleteReport));
      assertEqual('v3.4.31 incomplete live evidence not ready', 'NOT_READY_FOR_V3_4_0', incompleteReport.result);
      const incompleteIssuer = incompleteReport.puzzle_pieces.find((piece) => piece.id === 4);
      assertEqual('v3.4.31 incomplete live-read provided', true, incompleteIssuer.observed.verifier_kit_release_assets.provided);
      assertEqual('v3.4.31 incomplete distribution not ready', false, incompleteIssuer.observed.verifier_kit_public_distribution.ready_for_public_distribution_claim);
    } finally {
      rmSync(incompleteEvidenceDir, { recursive: true, force: true });
    }

    const tamperedPublicDistribution = clone(rebuiltPublicDistribution);
    tamperedPublicDistribution.release_assets.release_asset_hashes.checks[0].matches_expected_sha256 = false;
    writeFileSync(
      join(publicEvidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'),
      `${JSON.stringify(tamperedPublicDistribution, null, 2)}\n`
    );
    const tamperedPublicDistributionRun = runZlar([
      'north-star-readiness',
      '--evidence-dir',
      publicEvidenceDir,
      '--release-tag',
      'v3.4.31',
      '--json',
    ]);
    assert('v3.4.31 tampered public distribution exits nonzero', tamperedPublicDistributionRun.status !== 0);
    assertEqual('v3.4.31 tampered public distribution emits no stdout', '', tamperedPublicDistributionRun.stdout);
    assert('v3.4.31 tampered public distribution names rebuilt mismatch', tamperedPublicDistributionRun.stderr.includes('does not match rebuilt release-asset evidence'));
  } finally {
    rmSync(publicEvidenceDir, { recursive: true, force: true });
  }

  const missingServiceEvidenceDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-missing-service-'));
  rmSync(missingServiceEvidenceDir, { recursive: true, force: true });
  cpSync(evidenceDir, missingServiceEvidenceDir, { recursive: true });
  rmSync(join(missingServiceEvidenceDir, 'zlar-installed-runtime-profile-service-proof-v1.json'), { force: true });
  try {
    const missingServiceRun = runZlar([
      'north-star-readiness',
      '--evidence-dir',
      missingServiceEvidenceDir,
      '--release-tag',
      'v3.4.11',
      '--json',
    ]);
    assert('missing v3.4.11 service proof exits nonzero', missingServiceRun.status !== 0);
    assertEqual('missing v3.4.11 service proof emits no stdout', '', missingServiceRun.stdout);
    assert('missing v3.4.11 service proof names required evidence', missingServiceRun.stderr.includes('Required evidence file missing'));
    assert('missing v3.4.11 service proof output privacy safe', !unsafeOutputPattern.test(missingServiceRun.stderr));
  } finally {
    rmSync(missingServiceEvidenceDir, { recursive: true, force: true });
  }

  const missingServiceArtifactVerificationEvidenceDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-missing-service-artifact-verification-'));
  rmSync(missingServiceArtifactVerificationEvidenceDir, { recursive: true, force: true });
  cpSync(evidenceDir, missingServiceArtifactVerificationEvidenceDir, { recursive: true });
  rmSync(join(missingServiceArtifactVerificationEvidenceDir, 'zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'), { force: true });
  try {
    const missingServiceArtifactVerificationRun = runZlar([
      'north-star-readiness',
      '--evidence-dir',
      missingServiceArtifactVerificationEvidenceDir,
      '--release-tag',
      'v3.4.14',
      '--json',
    ]);
    assert('missing v3.4.14 service proof artifact verification exits nonzero', missingServiceArtifactVerificationRun.status !== 0);
    assertEqual('missing v3.4.14 service proof artifact verification emits no stdout', '', missingServiceArtifactVerificationRun.stdout);
    assert('missing v3.4.14 service proof artifact verification names required evidence', missingServiceArtifactVerificationRun.stderr.includes('Required evidence file missing'));
    assert('missing v3.4.14 service proof artifact verification output privacy safe', !unsafeOutputPattern.test(missingServiceArtifactVerificationRun.stderr));
  } finally {
    rmSync(missingServiceArtifactVerificationEvidenceDir, { recursive: true, force: true });
  }

  const optionalServiceArtifactVerificationEvidenceDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-optional-service-artifact-verification-'));
  rmSync(optionalServiceArtifactVerificationEvidenceDir, { recursive: true, force: true });
  cpSync(evidenceDir, optionalServiceArtifactVerificationEvidenceDir, { recursive: true });
  rmSync(join(optionalServiceArtifactVerificationEvidenceDir, 'zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'), { force: true });
  rmSync(join(optionalServiceArtifactVerificationEvidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'), { force: true });
  try {
    const optionalServiceArtifactVerificationRun = runZlar([
      'north-star-readiness',
      '--evidence-dir',
      optionalServiceArtifactVerificationEvidenceDir,
      '--release-tag',
      'v3.4.13',
      '--json',
    ]);
    assertEqual('missing v3.4.13 service proof artifact verification exits zero', 0, optionalServiceArtifactVerificationRun.status);
    assertEqual('missing v3.4.13 service proof artifact verification emits no stderr', '', optionalServiceArtifactVerificationRun.stderr);
    assert('missing v3.4.13 service proof artifact verification output privacy safe', !unsafeOutputPattern.test(optionalServiceArtifactVerificationRun.stdout));
    const optionalServiceArtifactVerificationReport = JSON.parse(optionalServiceArtifactVerificationRun.stdout);
    assert('missing v3.4.13 service proof artifact verification passes validation', assertNorthStarReadinessReport(optionalServiceArtifactVerificationReport));
    assertEqual('missing v3.4.13 service proof artifact verification not required', false, optionalServiceArtifactVerificationReport.counts.installed_runtime_profile_service_artifact_verification_required);
    assertEqual('missing v3.4.13 service proof artifact verification not preserved', false, optionalServiceArtifactVerificationReport.counts.installed_runtime_profile_service_artifact_verification_preserved);
    assertEqual('missing v3.4.13 service proof artifact verification taxonomy not required', false, optionalServiceArtifactVerificationReport.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_required);
    assertEqual('missing v3.4.13 service proof artifact verification taxonomy not preserved', false, optionalServiceArtifactVerificationReport.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved);
    assertEqual('missing v3.4.13 service proof artifact verification taxonomy hash absent', 'not-provided', optionalServiceArtifactVerificationReport.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256);
    assert(
      'missing v3.4.13 service proof artifact verification omitted from artifact list',
      !optionalServiceArtifactVerificationReport.artifacts_consumed.includes('zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json')
    );
  } finally {
    rmSync(optionalServiceArtifactVerificationEvidenceDir, { recursive: true, force: true });
  }

  const missingTerminalChainEvidenceDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-missing-terminal-chain-'));
  rmSync(missingTerminalChainEvidenceDir, { recursive: true, force: true });
  cpSync(evidenceDir, missingTerminalChainEvidenceDir, { recursive: true });
  rmSync(join(missingTerminalChainEvidenceDir, 'zlar-installed-runtime-profile-terminal-chain-v1.json'), { force: true });
  try {
    const missingTerminalChainRun = runZlar([
      'north-star-readiness',
      '--evidence-dir',
      missingTerminalChainEvidenceDir,
      '--release-tag',
      'v3.4.15',
      '--json',
    ]);
    assert('missing v3.4.15 terminal chain exits nonzero', missingTerminalChainRun.status !== 0);
    assertEqual('missing v3.4.15 terminal chain emits no stdout', '', missingTerminalChainRun.stdout);
    assert('missing v3.4.15 terminal chain names required evidence', missingTerminalChainRun.stderr.includes('Required evidence file missing'));
    assert('missing v3.4.15 terminal chain output privacy safe', !unsafeOutputPattern.test(missingTerminalChainRun.stderr));
  } finally {
    rmSync(missingTerminalChainEvidenceDir, { recursive: true, force: true });
  }

  const missingTerminalChainArtifactEvidenceDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-missing-terminal-chain-artifact-'));
  rmSync(missingTerminalChainArtifactEvidenceDir, { recursive: true, force: true });
  cpSync(evidenceDir, missingTerminalChainArtifactEvidenceDir, { recursive: true });
  rmSync(join(missingTerminalChainArtifactEvidenceDir, 'zlar-installed-runtime-profile-terminal-chain-artifact-v1.json'), { force: true });
  try {
    const missingTerminalChainArtifactRun = runZlar([
      'north-star-readiness',
      '--evidence-dir',
      missingTerminalChainArtifactEvidenceDir,
      '--release-tag',
      'v3.4.15',
      '--json',
    ]);
    assert('missing v3.4.15 terminal chain artifact exits nonzero', missingTerminalChainArtifactRun.status !== 0);
    assertEqual('missing v3.4.15 terminal chain artifact emits no stdout', '', missingTerminalChainArtifactRun.stdout);
    assert('missing v3.4.15 terminal chain artifact names required evidence', missingTerminalChainArtifactRun.stderr.includes('Required evidence file missing'));
    assert('missing v3.4.15 terminal chain artifact output privacy safe', !unsafeOutputPattern.test(missingTerminalChainArtifactRun.stderr));
  } finally {
    rmSync(missingTerminalChainArtifactEvidenceDir, { recursive: true, force: true });
  }

  const missingTerminalChainArtifactVerificationEvidenceDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-missing-terminal-chain-artifact-verification-'));
  rmSync(missingTerminalChainArtifactVerificationEvidenceDir, { recursive: true, force: true });
  cpSync(evidenceDir, missingTerminalChainArtifactVerificationEvidenceDir, { recursive: true });
  rmSync(join(missingTerminalChainArtifactVerificationEvidenceDir, 'zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json'), { force: true });
  try {
    const missingTerminalChainArtifactVerificationRun = runZlar([
      'north-star-readiness',
      '--evidence-dir',
      missingTerminalChainArtifactVerificationEvidenceDir,
      '--release-tag',
      'v3.4.15',
      '--json',
    ]);
    assert('missing v3.4.15 terminal chain artifact verification exits nonzero', missingTerminalChainArtifactVerificationRun.status !== 0);
    assertEqual('missing v3.4.15 terminal chain artifact verification emits no stdout', '', missingTerminalChainArtifactVerificationRun.stdout);
    assert('missing v3.4.15 terminal chain artifact verification names required evidence', missingTerminalChainArtifactVerificationRun.stderr.includes('Required evidence file missing'));
    assert('missing v3.4.15 terminal chain artifact verification output privacy safe', !unsafeOutputPattern.test(missingTerminalChainArtifactVerificationRun.stderr));
  } finally {
    rmSync(missingTerminalChainArtifactVerificationEvidenceDir, { recursive: true, force: true });
  }

  const optionalTerminalChainEvidenceDir = mkdtempSync(join(tmpdir(), 'zlar-north-star-optional-terminal-chain-'));
  rmSync(optionalTerminalChainEvidenceDir, { recursive: true, force: true });
  cpSync(evidenceDir, optionalTerminalChainEvidenceDir, { recursive: true });
  rmSync(join(optionalTerminalChainEvidenceDir, 'zlar-installed-runtime-profile-terminal-chain-v1.json'), { force: true });
  rmSync(join(optionalTerminalChainEvidenceDir, 'zlar-installed-runtime-profile-terminal-chain-artifact-v1.json'), { force: true });
  rmSync(join(optionalTerminalChainEvidenceDir, 'zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json'), { force: true });
  rmSync(join(optionalTerminalChainEvidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'), { force: true });
  try {
    const optionalTerminalChainRun = runZlar([
      'north-star-readiness',
      '--evidence-dir',
      optionalTerminalChainEvidenceDir,
      '--release-tag',
      'v3.4.14',
      '--json',
    ]);
    assertEqual('missing v3.4.14 terminal chain exits zero', 0, optionalTerminalChainRun.status);
    assertEqual('missing v3.4.14 terminal chain emits no stderr', '', optionalTerminalChainRun.stderr);
    assert('missing v3.4.14 terminal chain output privacy safe', !unsafeOutputPattern.test(optionalTerminalChainRun.stdout));
    const optionalTerminalChainReport = JSON.parse(optionalTerminalChainRun.stdout);
    assert('missing v3.4.14 terminal chain passes validation', assertNorthStarReadinessReport(optionalTerminalChainReport));
    assertEqual('missing v3.4.14 terminal chain not required', false, optionalTerminalChainReport.counts.installed_runtime_profile_terminal_chain_required);
    assertEqual('missing v3.4.14 terminal chain not preserved', false, optionalTerminalChainReport.counts.installed_runtime_profile_terminal_chain_preserved);
    assertEqual('missing v3.4.14 terminal chain taxonomy not required', false, optionalTerminalChainReport.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_required);
    assertEqual('missing v3.4.14 terminal chain taxonomy not preserved', false, optionalTerminalChainReport.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_preserved);
    assertEqual('missing v3.4.14 terminal chain taxonomy hash absent', 'not-provided', optionalTerminalChainReport.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256);
    assertEqual('missing v3.4.14 terminal chain artifact verification taxonomy hash absent', 'not-provided', optionalTerminalChainReport.counts.installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256);
    assert(
      'missing v3.4.14 terminal chain omitted from artifact list',
      !optionalTerminalChainReport.artifacts_consumed.includes('zlar-installed-runtime-profile-terminal-chain-v1.json')
    );
  } finally {
    rmSync(optionalTerminalChainEvidenceDir, { recursive: true, force: true });
  }

  const productProofPathFile = join(evidenceDir, 'zlar-product-proof-path-v1.json');
  const productProofPathBody = readFileSync(productProofPathFile, 'utf8');
  rmSync(productProofPathFile, { force: true });
  const legacyEvidenceRun = runZlar(['north-star-readiness', '--evidence-dir', evidenceDir, '--release-tag', 'v3.3.106', '--json']);
  assertEqual('legacy evidence-dir without product proof exits zero', 0, legacyEvidenceRun.status);
  assertEqual('legacy evidence-dir without product proof emits no stderr', '', legacyEvidenceRun.stderr);
  assert('legacy evidence-dir without product proof output privacy safe', !unsafeOutputPattern.test(legacyEvidenceRun.stdout));
  const legacyEvidenceReport = JSON.parse(legacyEvidenceRun.stdout);
  assert('legacy evidence-dir without product proof passes validation', assertNorthStarReadinessReport(legacyEvidenceReport));
  assertEqual('legacy product proof path not verified', false, legacyEvidenceReport.counts.product_proof_path_verified);
  assertEqual(
    'legacy product proof path summary absent',
    false,
    legacyEvidenceReport.puzzle_pieces.find((piece) => piece.id === 1).observed.product_proof_path.provided
  );
  assertEqual(
    'legacy product proof scope preserved',
    'local-fixture-only',
    legacyEvidenceReport.puzzle_pieces.find((piece) => piece.id === 1).acceptance_gate_scope
  );
  assert(
    'legacy artifacts omit product proof path',
    !legacyEvidenceReport.artifacts_consumed.includes('zlar-product-proof-path-v1.json')
  );
  writeFileSync(productProofPathFile, productProofPathBody);

  const evidenceWithPrivateRun = runZlar([
    'north-star-readiness',
    '--evidence-dir',
    evidenceDir,
    '--release-tag',
    'v3.3.106',
    '--private-verifier-result-verification',
    privateVerifierResultVerificationPath,
    '--json',
  ]);
  assertEqual('evidence-dir private verifier json exits zero', 0, evidenceWithPrivateRun.status);
  assertEqual('evidence-dir private verifier json emits no stderr', '', evidenceWithPrivateRun.stderr);
  assert('evidence-dir private verifier output privacy safe', !unsafeOutputPattern.test(evidenceWithPrivateRun.stdout));
  evidenceWithPrivateReport = JSON.parse(evidenceWithPrivateRun.stdout);
  assert('evidence-dir private verifier report passes validation', assertNorthStarReadinessReport(evidenceWithPrivateReport));
  const externalWithPrivate = evidenceWithPrivateReport.puzzle_pieces.find((piece) => piece.id === 6);
  assertEqual('evidence-dir private verifier keeps piece unproven', 'unproven', externalWithPrivate.status);
  assertEqual('evidence-dir private verifier pass validated', true, externalWithPrivate.observed.private_non_operator_pass_validated);
  assertEqual('evidence-dir private verifier summary provided', true, externalWithPrivate.observed.private_verifier_result_verification.provided);
  assertEqual('evidence-dir private verifier public attestation false', false, externalWithPrivate.observed.private_verifier_result_verification.public_external_attestation);
  assertEqual('evidence-dir private verifier downstream boundary required', true, externalWithPrivate.observed.private_verifier_result_verification.downstream_refusal_boundary_required);
  assertEqual('evidence-dir private verifier downstream refusals unboarded', true, externalWithPrivate.observed.private_verifier_result_verification.downstream_refusal_all_refusals_unboarded);
  assertEqual(
    'evidence-dir private verifier downstream refusal reasons',
    JSON.stringify(EXPECTED_DOWNSTREAM_REFUSAL_REASONS),
    JSON.stringify(externalWithPrivate.observed.private_verifier_result_verification.downstream_refusal_reasons)
  );
  assertEqual('evidence-dir private verifier north star downstream refusals unboarded', true, externalWithPrivate.observed.private_verifier_result_verification.north_star_downstream_refusal_all_refusals_unboarded);
  assertEqual(
    'evidence-dir private verifier north star downstream refusal reasons',
    JSON.stringify(EXPECTED_DOWNSTREAM_REFUSAL_REASONS),
    JSON.stringify(externalWithPrivate.observed.private_verifier_result_verification.north_star_downstream_refusal_reasons)
  );
  assertEqual('evidence-dir private verifier public non-operator false', false, evidenceWithPrivateReport.claim_boundary.non_operator_review_proven);
  assert('evidence-dir artifacts include private verifier verification', evidenceWithPrivateReport.artifacts_consumed.includes('zlar-private-verifier-result-verification-v1.json'));
  assert('evidence-dir private verifier non-claim present', evidenceWithPrivateReport.non_claims.some((claim) => claim.includes('private non-operator verifier result validation')));

  const evidenceWithPrivateZipRun = runZlar([
    'north-star-readiness',
    '--evidence-dir',
    evidenceDir,
    '--release-tag',
    'v3.3.106',
    '--private-verifier-zip-result-verification',
    privateVerifierZipResultVerificationPath,
    '--json',
  ]);
  assertEqual('evidence-dir private ZIP verifier json exits zero', 0, evidenceWithPrivateZipRun.status);
  assertEqual('evidence-dir private ZIP verifier json emits no stderr', '', evidenceWithPrivateZipRun.stderr);
  assert('evidence-dir private ZIP verifier output privacy safe', !unsafeOutputPattern.test(evidenceWithPrivateZipRun.stdout));
  evidenceWithPrivateZipReport = JSON.parse(evidenceWithPrivateZipRun.stdout);
  assert('evidence-dir private ZIP verifier report passes validation', assertNorthStarReadinessReport(evidenceWithPrivateZipReport));
  const externalWithPrivateZip = evidenceWithPrivateZipReport.puzzle_pieces.find((piece) => piece.id === 6);
  assertEqual('evidence-dir private ZIP verifier keeps piece unproven', 'unproven', externalWithPrivateZip.status);
  assertEqual('evidence-dir private ZIP verifier signal validated', true, externalWithPrivateZip.observed.private_personally_connected_zip_result_validated);
  assertEqual('evidence-dir private ZIP verifier public attestation false', false, externalWithPrivateZip.observed.private_verifier_zip_result_verification.public_external_attestation);
  assertEqual('evidence-dir private ZIP verifier independent false', false, externalWithPrivateZip.observed.private_verifier_zip_result_verification.independent_review);
  assertEqual('evidence-dir private ZIP verifier north star not ready', 'NOT_READY_FOR_V3_4_0', externalWithPrivateZip.observed.private_verifier_zip_result_verification.north_star_result);
  assertEqual('evidence-dir private ZIP verifier public non-operator false', false, evidenceWithPrivateZipReport.claim_boundary.non_operator_review_proven);
  assert('evidence-dir artifacts include private ZIP verifier verification', evidenceWithPrivateZipReport.artifacts_consumed.includes('zlar-private-verifier-zip-result-verification-v1.json'));
  assert('evidence-dir private ZIP verifier non-claim present', evidenceWithPrivateZipReport.non_claims.some((claim) => claim.includes('private personally connected outside-machine ZIP verifier result validation')));

  const evidenceWithPublicArtifactRun = runZlar([
    'north-star-readiness',
    '--evidence-dir',
    evidenceDir,
    '--public-artifact-verifier-result-verification',
    publicArtifactVerifierResultVerificationPath,
    '--json',
  ]);
  assertEqual('evidence-dir public artifact verifier json exits zero', 0, evidenceWithPublicArtifactRun.status);
  assertEqual('evidence-dir public artifact verifier json emits no stderr', '', evidenceWithPublicArtifactRun.stderr);
  assert('evidence-dir public artifact verifier output privacy safe', !unsafeOutputPattern.test(evidenceWithPublicArtifactRun.stdout));
  const evidenceWithPublicArtifactReport = JSON.parse(evidenceWithPublicArtifactRun.stdout);
  assert('evidence-dir public artifact verifier report passes validation', assertNorthStarReadinessReport(evidenceWithPublicArtifactReport));
  const externalWithPublicArtifact = evidenceWithPublicArtifactReport.puzzle_pieces.find((piece) => piece.id === 6);
  assertEqual('evidence-dir public artifact verifier keeps piece unproven', 'unproven', externalWithPublicArtifact.status);
  assertEqual('evidence-dir public artifact verifier signal validated', true, externalWithPublicArtifact.observed.public_artifact_verifier_result_validated);
  assertEqual('evidence-dir public artifact verifier summary provided', true, externalWithPublicArtifact.observed.public_artifact_verifier_result_verification.provided);
  assertEqual('evidence-dir public artifact verifier public attestation false', false, externalWithPublicArtifact.observed.public_artifact_verifier_result_verification.public_external_attestation);
  assertEqual('evidence-dir public artifact verifier public attribution false', false, externalWithPublicArtifact.observed.public_artifact_verifier_result_verification.public_attribution);
  assertEqual('evidence-dir public artifact verifier non-operator false', false, externalWithPublicArtifact.observed.public_artifact_verifier_result_verification.non_operator_review_proven);
  assertEqual('evidence-dir public artifact verifier private source false', false, externalWithPublicArtifact.observed.public_artifact_verifier_result_verification.private_source_review);
  assertEqual('evidence-dir public artifact verifier source access false', false, externalWithPublicArtifact.observed.public_artifact_verifier_result_verification.source_access_used);
  assertEqual('evidence-dir public artifact verifier public non-operator false', false, evidenceWithPublicArtifactReport.claim_boundary.non_operator_review_proven);
  assert('evidence-dir artifacts include public artifact verifier verification', evidenceWithPublicArtifactReport.artifacts_consumed.includes('zlar-public-artifact-verifier-result-verification-v1.json'));

  const publicArtifactVerifierPublicClaim = clone(publicArtifactVerifierResultVerification);
  publicArtifactVerifierPublicClaim.claim_boundary.public_external_attestation = true;
  writeFileSync(
    publicArtifactVerifierResultVerificationPath,
    `${JSON.stringify(publicArtifactVerifierPublicClaim, null, 2)}\n`
  );
  const publicArtifactClaimRun = runZlar([
    'north-star-readiness',
    '--evidence-dir',
    evidenceDir,
    '--public-artifact-verifier-result-verification',
    publicArtifactVerifierResultVerificationPath,
    '--json',
  ]);
  assert('public artifact verifier public claim exits nonzero', publicArtifactClaimRun.status !== 0);
  assertEqual('public artifact verifier public claim emits no stdout', '', publicArtifactClaimRun.stdout);
  assert('public artifact verifier public claim names boundary', publicArtifactClaimRun.stderr.includes('public_external_attestation=false'));
  assert('public artifact verifier public claim privacy safe', !unsafeOutputPattern.test(publicArtifactClaimRun.stderr));
  writeFileSync(
    publicArtifactVerifierResultVerificationPath,
    `${JSON.stringify(publicArtifactVerifierResultVerification, null, 2)}\n`
  );

  const evidenceWithPublicExternalAttestationRun = runZlar([
    'north-star-readiness',
    '--evidence-dir',
    evidenceDir,
    '--release-tag',
    'v3.3.106',
    '--public-external-attestation-result-verification',
    publicExternalAttestationResultVerificationPath,
    '--json',
  ]);
  assertEqual('evidence-dir public external attestation intake json exits zero', 0, evidenceWithPublicExternalAttestationRun.status);
  assertEqual('evidence-dir public external attestation intake json emits no stderr', '', evidenceWithPublicExternalAttestationRun.stderr);
  assert('evidence-dir public external attestation intake output privacy safe', !unsafeOutputPattern.test(evidenceWithPublicExternalAttestationRun.stdout));
  evidenceWithPublicExternalAttestationReport = JSON.parse(evidenceWithPublicExternalAttestationRun.stdout);
  assert('evidence-dir public external attestation intake report passes validation', assertNorthStarReadinessReport(evidenceWithPublicExternalAttestationReport));
  const externalWithPublicExternalAttestation =
    evidenceWithPublicExternalAttestationReport.puzzle_pieces.find((piece) => piece.id === 6);
  assertEqual('evidence-dir public external attestation intake keeps piece unproven', 'unproven', externalWithPublicExternalAttestation.status);
  assertEqual('evidence-dir public external attestation intake signal validated', true, externalWithPublicExternalAttestation.observed.public_external_attestation_result_validated);
  assertEqual('evidence-dir public external attestation intake summary provided', true, externalWithPublicExternalAttestation.observed.public_external_attestation_result_verification.provided);
  assertEqual('evidence-dir public external attestation intake readiness public attestation false', false, externalWithPublicExternalAttestation.observed.public_external_attestation_result_verification.public_external_attestation);
  assertEqual('evidence-dir public external attestation intake readiness public attribution false', false, externalWithPublicExternalAttestation.observed.public_external_attestation_result_verification.public_attribution);
  assertEqual('evidence-dir public external attestation intake readiness non-operator false', false, externalWithPublicExternalAttestation.observed.public_external_attestation_result_verification.non_operator_review_proven);
  assertEqual('evidence-dir public external attestation intake top-level public attestation false', false, evidenceWithPublicExternalAttestationReport.claim_boundary.public_external_attestation);
  assertEqual('evidence-dir public external attestation intake top-level non-operator false', false, evidenceWithPublicExternalAttestationReport.claim_boundary.non_operator_review_proven);
  assert('evidence-dir artifacts include public external attestation verification', evidenceWithPublicExternalAttestationReport.artifacts_consumed.includes('zlar-public-external-attestation-result-verification-v1.json'));

  const publicExternalAttestationProductionClaim = clone(publicExternalAttestationResultVerification);
  publicExternalAttestationProductionClaim.claim_boundary.production_authority = true;
  writeFileSync(
    publicExternalAttestationResultVerificationPath,
    `${JSON.stringify(publicExternalAttestationProductionClaim, null, 2)}\n`
  );
  const publicExternalAttestationProductionClaimRun = runZlar([
    'north-star-readiness',
    '--evidence-dir',
    evidenceDir,
    '--release-tag',
    'v3.3.106',
    '--public-external-attestation-result-verification',
    publicExternalAttestationResultVerificationPath,
    '--json',
  ]);
  assert('public external attestation production claim exits nonzero', publicExternalAttestationProductionClaimRun.status !== 0);
  assertEqual('public external attestation production claim emits no stdout', '', publicExternalAttestationProductionClaimRun.stdout);
  assert('public external attestation production claim names boundary', publicExternalAttestationProductionClaimRun.stderr.includes('production_authority=false'));
  assert('public external attestation production claim privacy safe', !unsafeOutputPattern.test(publicExternalAttestationProductionClaimRun.stderr));
  writeFileSync(
    publicExternalAttestationResultVerificationPath,
    `${JSON.stringify(publicExternalAttestationResultVerification, null, 2)}\n`
  );

  const publicExternalAttestationReleaseMismatch =
    signedPublicExternalAttestationResultVerification('v3.3.107');
  writeFileSync(
    publicExternalAttestationResultVerificationPath,
    `${JSON.stringify(publicExternalAttestationReleaseMismatch, null, 2)}\n`
  );
  const publicExternalAttestationReleaseMismatchRun = runZlar([
    'north-star-readiness',
    '--evidence-dir',
    evidenceDir,
    '--release-tag',
    'v3.3.106',
    '--public-external-attestation-result-verification',
    publicExternalAttestationResultVerificationPath,
    '--json',
  ]);
  assert('public external attestation release mismatch exits nonzero', publicExternalAttestationReleaseMismatchRun.status !== 0);
  assertEqual('public external attestation release mismatch emits no stdout', '', publicExternalAttestationReleaseMismatchRun.stdout);
  assert('public external attestation release mismatch names boundary', publicExternalAttestationReleaseMismatchRun.stderr.includes('release tag mismatch'));
  assert('public external attestation release mismatch privacy safe', !unsafeOutputPattern.test(publicExternalAttestationReleaseMismatchRun.stderr));
  writeFileSync(
    publicExternalAttestationResultVerificationPath,
    `${JSON.stringify(publicExternalAttestationResultVerification, null, 2)}\n`
  );

  const privateZipVerifierIndependenceClaim = clone(privateVerifierZipResultVerification);
  privateZipVerifierIndependenceClaim.claim_boundary.independent_review = true;
  writeFileSync(
    privateVerifierZipResultVerificationPath,
    `${JSON.stringify(privateZipVerifierIndependenceClaim, null, 2)}\n`
  );
  const privateZipIndependenceRun = runZlar([
    'north-star-readiness',
    '--evidence-dir',
    evidenceDir,
    '--release-tag',
    'v3.3.106',
    '--private-verifier-zip-result-verification',
    privateVerifierZipResultVerificationPath,
    '--json',
  ]);
  assert('private ZIP verifier independence claim exits nonzero', privateZipIndependenceRun.status !== 0);
  assertEqual('private ZIP verifier independence claim emits no stdout', '', privateZipIndependenceRun.stdout);
  assert('private ZIP verifier independence claim names boundary', privateZipIndependenceRun.stderr.includes('independent review'));
  assert('private ZIP verifier independence claim privacy safe', !unsafeOutputPattern.test(privateZipIndependenceRun.stderr));
  writeFileSync(
    privateVerifierZipResultVerificationPath,
    `${JSON.stringify(privateVerifierZipResultVerification, null, 2)}\n`
  );

  const privateVerifierTagMismatch = clone(privateVerifierResultVerification);
  privateVerifierTagMismatch.release_tag = 'v3.3.105';
  writeFileSync(
    privateVerifierResultVerificationPath,
    `${JSON.stringify(privateVerifierTagMismatch, null, 2)}\n`
  );
  const privateTagMismatchRun = runZlar([
    'north-star-readiness',
    '--evidence-dir',
    evidenceDir,
    '--release-tag',
    'v3.3.106',
    '--private-verifier-result-verification',
    privateVerifierResultVerificationPath,
    '--json',
  ]);
  assert('private verifier release mismatch exits nonzero', privateTagMismatchRun.status !== 0);
  assertEqual('private verifier release mismatch emits no stdout', '', privateTagMismatchRun.stdout);
  assert('private verifier release mismatch names boundary', privateTagMismatchRun.stderr.includes('release tag mismatch'));
  assert('private verifier release mismatch privacy safe', !unsafeOutputPattern.test(privateTagMismatchRun.stderr));
  const privateVerifierPublicClaim = clone(privateVerifierResultVerification);
  privateVerifierPublicClaim.public_external_attestation = true;
  assertThrows(
    'private verifier public attestation input fails',
    () => buildNorthStarReadinessReport({
      evidenceModel: 'release-forward-dry-run-artifacts',
      productProofPathReport: JSON.parse(readFileSync(join(evidenceDir, 'zlar-product-proof-path-v1.json'), 'utf8')),
      proofSmokeVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-proof-smoke-sample-verification.json'), 'utf8')),
      localProofPackVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-local-proof-pack-sample-verification.json'), 'utf8')),
      servicePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-service-preflight-sample-verification.json'), 'utf8')),
      runtimeLocalActivationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-local-activation-sample-verification.json'), 'utf8')),
      runtimeProfileInstallationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-profile-installation-sample-verification.json'), 'utf8')),
      installedRuntimeProfilePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-preflight-sample-verification.json'), 'utf8')),
      installedRuntimeProfileServiceProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-v1.json'), 'utf8')),
      installedRuntimeProfileServiceProofArtifactVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'), 'utf8')),
      coverageMap: JSON.parse(readFileSync(join(evidenceDir, 'zlar-coverage-map-sample.json'), 'utf8')),
      privateVerifierResultVerification: privateVerifierPublicClaim,
      releaseForwardTargetTag: 'v3.3.106',
    }),
    'must not claim public external attestation'
  );

  const weakenedInstalledRuntimeProfileRecognition = clone(JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-preflight-sample-verification.json'), 'utf8')));
  weakenedInstalledRuntimeProfileRecognition.required_refusal_case_count = 1;
  const weakenedInstalledRuntimeProfileRecognitionReport = buildNorthStarReadinessReport({
    evidenceModel: 'release-forward-dry-run-artifacts',
    productProofPathReport: JSON.parse(readFileSync(join(evidenceDir, 'zlar-product-proof-path-v1.json'), 'utf8')),
    proofSmokeVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-proof-smoke-sample-verification.json'), 'utf8')),
    localProofPackVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-local-proof-pack-sample-verification.json'), 'utf8')),
    servicePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-service-preflight-sample-verification.json'), 'utf8')),
    runtimeLocalActivationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-local-activation-sample-verification.json'), 'utf8')),
    runtimeProfileInstallationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-profile-installation-sample-verification.json'), 'utf8')),
    installedRuntimeProfilePreflightVerification: weakenedInstalledRuntimeProfileRecognition,
    installedRuntimeProfileServiceProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProofArtifactVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'), 'utf8')),
    coverageMap: JSON.parse(readFileSync(join(evidenceDir, 'zlar-coverage-map-sample.json'), 'utf8')),
    trustedIssuerRecognition: JSON.parse(readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition.json'), 'utf8')),
    malformedRegistryErrorText: readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt'), 'utf8'),
    verifierKitReproducibility: JSON.parse(readFileSync(join(evidenceDir, 'zlar-verifier-kit-reproducibility-v1.json'), 'utf8')),
    verifierKitPublicDistribution: JSON.parse(readFileSync(join(evidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'), 'utf8')),
    releaseForwardTargetTag: 'v3.3.106',
  });
  assertThrows(
    'weakened installed runtime profile recognition taxonomy fails readiness',
    () => assertNorthStarReadinessReport(weakenedInstalledRuntimeProfileRecognitionReport),
    'recognition contract drifted'
  );

  const weakenedInstalledRuntimeProfileRecognitionProof = clone(JSON.parse(readFileSync(join(evidenceDir, 'zlar-proof-smoke-sample-verification.json'), 'utf8')));
  weakenedInstalledRuntimeProfileRecognitionProof.counts.installed_runtime_profile_recognition_all_refusals_before_mutation = false;
  const weakenedInstalledRuntimeProfileRecognitionProofReport = buildNorthStarReadinessReport({
    evidenceModel: 'release-forward-dry-run-artifacts',
    productProofPathReport: JSON.parse(readFileSync(join(evidenceDir, 'zlar-product-proof-path-v1.json'), 'utf8')),
    proofSmokeVerification: weakenedInstalledRuntimeProfileRecognitionProof,
    localProofPackVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-local-proof-pack-sample-verification.json'), 'utf8')),
    servicePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-service-preflight-sample-verification.json'), 'utf8')),
    runtimeLocalActivationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-local-activation-sample-verification.json'), 'utf8')),
    runtimeProfileInstallationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-profile-installation-sample-verification.json'), 'utf8')),
    installedRuntimeProfilePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-preflight-sample-verification.json'), 'utf8')),
    installedRuntimeProfileServiceProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProofArtifactVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'), 'utf8')),
    coverageMap: JSON.parse(readFileSync(join(evidenceDir, 'zlar-coverage-map-sample.json'), 'utf8')),
    trustedIssuerRecognition: JSON.parse(readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition.json'), 'utf8')),
    malformedRegistryErrorText: readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt'), 'utf8'),
    verifierKitReproducibility: JSON.parse(readFileSync(join(evidenceDir, 'zlar-verifier-kit-reproducibility-v1.json'), 'utf8')),
    verifierKitPublicDistribution: JSON.parse(readFileSync(join(evidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'), 'utf8')),
    releaseForwardTargetTag: 'v3.3.106',
  });
  assertThrows(
    'weakened installed runtime profile recognition proof fails readiness',
    () => assertNorthStarReadinessReport(weakenedInstalledRuntimeProfileRecognitionProofReport),
    'recognition proof drifted'
  );

  const weakenedInstalledRuntimeProfileServiceProof = clone(JSON.parse(readFileSync(join(evidenceDir, 'zlar-proof-smoke-sample-verification.json'), 'utf8')));
  weakenedInstalledRuntimeProfileServiceProof.counts.installed_runtime_profile_service_all_refusals_before_mutation = false;
  const weakenedInstalledRuntimeProfileServiceProofReport = buildNorthStarReadinessReport({
    evidenceModel: 'release-forward-dry-run-artifacts',
    productProofPathReport: JSON.parse(readFileSync(join(evidenceDir, 'zlar-product-proof-path-v1.json'), 'utf8')),
    proofSmokeVerification: weakenedInstalledRuntimeProfileServiceProof,
    localProofPackVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-local-proof-pack-sample-verification.json'), 'utf8')),
    servicePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-service-preflight-sample-verification.json'), 'utf8')),
    runtimeLocalActivationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-local-activation-sample-verification.json'), 'utf8')),
    runtimeProfileInstallationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-profile-installation-sample-verification.json'), 'utf8')),
    installedRuntimeProfilePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-preflight-sample-verification.json'), 'utf8')),
    installedRuntimeProfileRecognitionProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-recognition-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProofArtifactVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'), 'utf8')),
    coverageMap: JSON.parse(readFileSync(join(evidenceDir, 'zlar-coverage-map-sample.json'), 'utf8')),
    trustedIssuerRecognition: JSON.parse(readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition.json'), 'utf8')),
    malformedRegistryErrorText: readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt'), 'utf8'),
    verifierKitReproducibility: JSON.parse(readFileSync(join(evidenceDir, 'zlar-verifier-kit-reproducibility-v1.json'), 'utf8')),
    verifierKitPublicDistribution: JSON.parse(readFileSync(join(evidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'), 'utf8')),
    releaseForwardTargetTag: 'v3.3.106',
  });
  assertThrows(
    'weakened installed runtime profile service proof fails readiness',
    () => assertNorthStarReadinessReport(weakenedInstalledRuntimeProfileServiceProofReport),
    'service proof drifted'
  );

  const weakenedInstalledRuntimeProfileServiceProofArtifactVerification = clone(JSON.parse(readFileSync(join(evidenceDir, 'zlar-proof-smoke-sample-verification.json'), 'utf8')));
  weakenedInstalledRuntimeProfileServiceProofArtifactVerification.counts.installed_runtime_profile_service_artifact_verification_restart_replay_refused = false;
  const weakenedInstalledRuntimeProfileServiceProofArtifactVerificationReport = buildNorthStarReadinessReport({
    evidenceModel: 'release-forward-dry-run-artifacts',
    productProofPathReport: JSON.parse(readFileSync(join(evidenceDir, 'zlar-product-proof-path-v1.json'), 'utf8')),
    proofSmokeVerification: weakenedInstalledRuntimeProfileServiceProofArtifactVerification,
    localProofPackVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-local-proof-pack-sample-verification.json'), 'utf8')),
    servicePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-service-preflight-sample-verification.json'), 'utf8')),
    runtimeLocalActivationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-local-activation-sample-verification.json'), 'utf8')),
    runtimeProfileInstallationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-profile-installation-sample-verification.json'), 'utf8')),
    installedRuntimeProfilePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-preflight-sample-verification.json'), 'utf8')),
    installedRuntimeProfileRecognitionProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-recognition-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProofArtifactVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'), 'utf8')),
    coverageMap: JSON.parse(readFileSync(join(evidenceDir, 'zlar-coverage-map-sample.json'), 'utf8')),
    trustedIssuerRecognition: JSON.parse(readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition.json'), 'utf8')),
    malformedRegistryErrorText: readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt'), 'utf8'),
    verifierKitReproducibility: JSON.parse(readFileSync(join(evidenceDir, 'zlar-verifier-kit-reproducibility-v1.json'), 'utf8')),
    verifierKitPublicDistribution: JSON.parse(readFileSync(join(evidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'), 'utf8')),
    releaseForwardTargetTag: 'v3.3.106',
  });
  assertThrows(
    'weakened installed runtime profile service proof artifact verification fails readiness',
    () => assertNorthStarReadinessReport(weakenedInstalledRuntimeProfileServiceProofArtifactVerificationReport),
    'service proof artifact verification drifted'
  );

  const driftedInstalledRuntimeProfileServiceProofArtifactVerificationHashSmoke = clone(JSON.parse(readFileSync(join(evidenceDir, 'zlar-proof-smoke-sample-verification.json'), 'utf8')));
  const driftedInstalledRuntimeProfileServiceProofArtifactVerificationHash = clone(JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'), 'utf8')));
  driftedInstalledRuntimeProfileServiceProofArtifactVerificationHashSmoke.counts.installed_runtime_profile_service_artifact_verification_body_sha256 = '1'.repeat(64);
  driftedInstalledRuntimeProfileServiceProofArtifactVerificationHash.body_sha256 = '1'.repeat(64);
  const driftedInstalledRuntimeProfileServiceProofArtifactVerificationHashReport = buildNorthStarReadinessReport({
    evidenceModel: 'release-forward-dry-run-artifacts',
    productProofPathReport: JSON.parse(readFileSync(join(evidenceDir, 'zlar-product-proof-path-v1.json'), 'utf8')),
    proofSmokeVerification: driftedInstalledRuntimeProfileServiceProofArtifactVerificationHashSmoke,
    localProofPackVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-local-proof-pack-sample-verification.json'), 'utf8')),
    servicePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-service-preflight-sample-verification.json'), 'utf8')),
    runtimeLocalActivationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-local-activation-sample-verification.json'), 'utf8')),
    runtimeProfileInstallationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-profile-installation-sample-verification.json'), 'utf8')),
    installedRuntimeProfilePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-preflight-sample-verification.json'), 'utf8')),
    installedRuntimeProfileRecognitionProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-recognition-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProofArtifactVerification: driftedInstalledRuntimeProfileServiceProofArtifactVerificationHash,
    coverageMap: JSON.parse(readFileSync(join(evidenceDir, 'zlar-coverage-map-sample.json'), 'utf8')),
    trustedIssuerRecognition: JSON.parse(readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition.json'), 'utf8')),
    malformedRegistryErrorText: readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt'), 'utf8'),
    verifierKitReproducibility: JSON.parse(readFileSync(join(evidenceDir, 'zlar-verifier-kit-reproducibility-v1.json'), 'utf8')),
    verifierKitPublicDistribution: JSON.parse(readFileSync(join(evidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'), 'utf8')),
    releaseForwardTargetTag: 'v3.3.106',
  });
  assertThrows(
    'drifted installed runtime profile service proof artifact verification hash fails readiness',
    () => assertNorthStarReadinessReport(driftedInstalledRuntimeProfileServiceProofArtifactVerificationHashReport),
    'service proof artifact verification drifted'
  );

  const driftedInstalledRuntimeProfileServiceProofArtifactVerificationTaxonomySmoke = clone(JSON.parse(readFileSync(join(evidenceDir, 'zlar-proof-smoke-sample-verification.json'), 'utf8')));
  driftedInstalledRuntimeProfileServiceProofArtifactVerificationTaxonomySmoke.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256 = '3'.repeat(64);
  const driftedInstalledRuntimeProfileServiceProofArtifactVerificationTaxonomyReport = buildNorthStarReadinessReport({
    evidenceModel: 'release-forward-dry-run-artifacts',
    productProofPathReport: JSON.parse(readFileSync(join(evidenceDir, 'zlar-product-proof-path-v1.json'), 'utf8')),
    proofSmokeVerification: driftedInstalledRuntimeProfileServiceProofArtifactVerificationTaxonomySmoke,
    localProofPackVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-local-proof-pack-sample-verification.json'), 'utf8')),
    servicePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-service-preflight-sample-verification.json'), 'utf8')),
    runtimeLocalActivationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-local-activation-sample-verification.json'), 'utf8')),
    runtimeProfileInstallationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-profile-installation-sample-verification.json'), 'utf8')),
    installedRuntimeProfilePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-preflight-sample-verification.json'), 'utf8')),
    installedRuntimeProfileRecognitionProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-recognition-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProofArtifactVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'), 'utf8')),
    coverageMap: JSON.parse(readFileSync(join(evidenceDir, 'zlar-coverage-map-sample.json'), 'utf8')),
    trustedIssuerRecognition: JSON.parse(readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition.json'), 'utf8')),
    malformedRegistryErrorText: readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt'), 'utf8'),
    releaseForwardTargetTag: 'v3.4.18',
  });
  assertEqual(
    'drifted installed runtime profile service proof artifact verification taxonomy count false',
    false,
    driftedInstalledRuntimeProfileServiceProofArtifactVerificationTaxonomyReport.counts.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved
  );
  assertThrows(
    'drifted installed runtime profile service proof artifact verification taxonomy fails readiness',
    () => assertNorthStarReadinessReport(driftedInstalledRuntimeProfileServiceProofArtifactVerificationTaxonomyReport),
    'puzzle-piece counts drifted'
  );

  const driftedInstalledRuntimeProfileTerminalChainArtifactVerificationHashSmoke = clone(JSON.parse(readFileSync(join(evidenceDir, 'zlar-proof-smoke-sample-verification.json'), 'utf8')));
  const driftedInstalledRuntimeProfileTerminalChainArtifactVerificationHash = clone(JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json'), 'utf8')));
  driftedInstalledRuntimeProfileTerminalChainArtifactVerificationHashSmoke.counts.installed_runtime_profile_terminal_chain_artifact_verification_body_sha256 = '2'.repeat(64);
  driftedInstalledRuntimeProfileTerminalChainArtifactVerificationHash.body_sha256 = '2'.repeat(64);
  const driftedInstalledRuntimeProfileTerminalChainArtifactVerificationHashReport = buildNorthStarReadinessReport({
    evidenceModel: 'release-forward-dry-run-artifacts',
    productProofPathReport: JSON.parse(readFileSync(join(evidenceDir, 'zlar-product-proof-path-v1.json'), 'utf8')),
    proofSmokeVerification: driftedInstalledRuntimeProfileTerminalChainArtifactVerificationHashSmoke,
    localProofPackVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-local-proof-pack-sample-verification.json'), 'utf8')),
    servicePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-service-preflight-sample-verification.json'), 'utf8')),
    runtimeLocalActivationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-local-activation-sample-verification.json'), 'utf8')),
    runtimeProfileInstallationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-profile-installation-sample-verification.json'), 'utf8')),
    installedRuntimeProfilePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-preflight-sample-verification.json'), 'utf8')),
    installedRuntimeProfileRecognitionProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-recognition-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProofArtifactVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'), 'utf8')),
    installedRuntimeProfileTerminalChain: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-terminal-chain-v1.json'), 'utf8')),
    installedRuntimeProfileTerminalChainArtifact: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-terminal-chain-artifact-v1.json'), 'utf8')),
    installedRuntimeProfileTerminalChainArtifactVerification: driftedInstalledRuntimeProfileTerminalChainArtifactVerificationHash,
    coverageMap: JSON.parse(readFileSync(join(evidenceDir, 'zlar-coverage-map-sample.json'), 'utf8')),
    trustedIssuerRecognition: JSON.parse(readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition.json'), 'utf8')),
    malformedRegistryErrorText: readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt'), 'utf8'),
    releaseForwardTargetTag: 'v3.4.15',
  });
  assertEqual(
    'drifted installed runtime profile terminal chain artifact verification hash count false',
    false,
    driftedInstalledRuntimeProfileTerminalChainArtifactVerificationHashReport.counts.installed_runtime_profile_terminal_chain_preserved
  );
  assertThrows(
    'drifted installed runtime profile terminal chain artifact verification hash fails readiness',
    () => assertNorthStarReadinessReport(driftedInstalledRuntimeProfileTerminalChainArtifactVerificationHashReport),
    'puzzle-piece counts drifted'
  );

  const driftedInstalledRuntimeProfileTerminalChainTaxonomySmoke = clone(JSON.parse(readFileSync(join(evidenceDir, 'zlar-proof-smoke-sample-verification.json'), 'utf8')));
  driftedInstalledRuntimeProfileTerminalChainTaxonomySmoke.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256 = '4'.repeat(64);
  const driftedInstalledRuntimeProfileTerminalChainTaxonomyReport = buildNorthStarReadinessReport({
    evidenceModel: 'release-forward-dry-run-artifacts',
    productProofPathReport: JSON.parse(readFileSync(join(evidenceDir, 'zlar-product-proof-path-v1.json'), 'utf8')),
    proofSmokeVerification: driftedInstalledRuntimeProfileTerminalChainTaxonomySmoke,
    localProofPackVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-local-proof-pack-sample-verification.json'), 'utf8')),
    servicePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-service-preflight-sample-verification.json'), 'utf8')),
    runtimeLocalActivationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-local-activation-sample-verification.json'), 'utf8')),
    runtimeProfileInstallationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-profile-installation-sample-verification.json'), 'utf8')),
    installedRuntimeProfilePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-preflight-sample-verification.json'), 'utf8')),
    installedRuntimeProfileRecognitionProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-recognition-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProofArtifactVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'), 'utf8')),
    installedRuntimeProfileTerminalChain: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-terminal-chain-v1.json'), 'utf8')),
    installedRuntimeProfileTerminalChainArtifact: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-terminal-chain-artifact-v1.json'), 'utf8')),
    installedRuntimeProfileTerminalChainArtifactVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json'), 'utf8')),
    coverageMap: JSON.parse(readFileSync(join(evidenceDir, 'zlar-coverage-map-sample.json'), 'utf8')),
    trustedIssuerRecognition: JSON.parse(readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition.json'), 'utf8')),
    malformedRegistryErrorText: readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt'), 'utf8'),
    releaseForwardTargetTag: 'v3.4.17',
  });
  assertEqual(
    'drifted installed runtime profile terminal chain taxonomy count false',
    false,
    driftedInstalledRuntimeProfileTerminalChainTaxonomyReport.counts.installed_runtime_profile_terminal_chain_refusal_taxonomy_preserved
  );
  assertEqual(
    'drifted installed runtime profile terminal chain taxonomy preserved false',
    false,
    driftedInstalledRuntimeProfileTerminalChainTaxonomyReport.counts.installed_runtime_profile_terminal_chain_preserved
  );
  assertThrows(
    'drifted installed runtime profile terminal chain taxonomy fails readiness',
    () => assertNorthStarReadinessReport(driftedInstalledRuntimeProfileTerminalChainTaxonomyReport),
    'puzzle-piece counts drifted'
  );

  const missingInstalledRuntimeProfileServiceProofReport = buildNorthStarReadinessReport({
    evidenceModel: 'release-forward-dry-run-artifacts',
    productProofPathReport: JSON.parse(readFileSync(join(evidenceDir, 'zlar-product-proof-path-v1.json'), 'utf8')),
    proofSmokeVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-proof-smoke-sample-verification.json'), 'utf8')),
    localProofPackVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-local-proof-pack-sample-verification.json'), 'utf8')),
    servicePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-service-preflight-sample-verification.json'), 'utf8')),
    runtimeLocalActivationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-local-activation-sample-verification.json'), 'utf8')),
    runtimeProfileInstallationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-profile-installation-sample-verification.json'), 'utf8')),
    installedRuntimeProfilePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-preflight-sample-verification.json'), 'utf8')),
    installedRuntimeProfileRecognitionProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-recognition-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProofArtifactVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'), 'utf8')),
    coverageMap: JSON.parse(readFileSync(join(evidenceDir, 'zlar-coverage-map-sample.json'), 'utf8')),
    trustedIssuerRecognition: JSON.parse(readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition.json'), 'utf8')),
    malformedRegistryErrorText: readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt'), 'utf8'),
    verifierKitReproducibility: JSON.parse(readFileSync(join(evidenceDir, 'zlar-verifier-kit-reproducibility-v1.json'), 'utf8')),
    verifierKitPublicDistribution: JSON.parse(readFileSync(join(evidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'), 'utf8')),
    releaseForwardTargetTag: 'v3.3.106',
  });
  assertEqual(
    'missing direct installed runtime profile service proof count false',
    false,
    missingInstalledRuntimeProfileServiceProofReport.counts.installed_runtime_profile_service_proof_preserved
  );
  assertEqual(
    'missing direct installed runtime profile service proof does not upgrade enterprise profile',
    'local_disposable_profile_partial',
    missingInstalledRuntimeProfileServiceProofReport.puzzle_pieces.find((piece) => piece.id === 3).status
  );
  assertThrows(
    'missing direct installed runtime profile service proof fails readiness',
    () => assertNorthStarReadinessReport(missingInstalledRuntimeProfileServiceProofReport),
    'puzzle-piece counts drifted'
  );

  const publicDistributionTagMismatch = clone(JSON.parse(readFileSync(join(evidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'), 'utf8')));
  publicDistributionTagMismatch.release_tag = 'v3.3.105';
  writeFileSync(
    join(evidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'),
    `${JSON.stringify(publicDistributionTagMismatch, null, 2)}\n`
  );
  const publicDistributionTagMismatchRun = runZlar([
    'north-star-readiness',
    '--evidence-dir',
    evidenceDir,
    '--release-tag',
    'v3.3.106',
    '--json',
  ]);
  assert('public distribution release mismatch exits nonzero', publicDistributionTagMismatchRun.status !== 0);
  assertEqual('public distribution release mismatch emits no stdout', '', publicDistributionTagMismatchRun.stdout);
  assert('public distribution release mismatch names boundary', publicDistributionTagMismatchRun.stderr.includes('public distribution release tag mismatch'));
  assert('public distribution release mismatch privacy safe', !unsafeOutputPattern.test(publicDistributionTagMismatchRun.stderr));

  const publicDistributionBoundaryClaim = clone(JSON.parse(readFileSync(join(evidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'), 'utf8')));
  publicDistributionBoundaryClaim.release_tag = 'v3.3.106';
  publicDistributionBoundaryClaim.claim_boundary.proves_enterprise_readiness = true;
  writeFileSync(
    join(evidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'),
    `${JSON.stringify(publicDistributionBoundaryClaim, null, 2)}\n`
  );
  const publicDistributionBoundaryClaimRun = runZlar([
    'north-star-readiness',
    '--evidence-dir',
    evidenceDir,
    '--release-tag',
    'v3.3.106',
    '--json',
  ]);
  assert('public distribution claim-boundary drift exits nonzero', publicDistributionBoundaryClaimRun.status !== 0);
  assertEqual('public distribution claim-boundary drift emits no stdout', '', publicDistributionBoundaryClaimRun.stdout);
  assert('public distribution claim-boundary drift names validator', publicDistributionBoundaryClaimRun.stderr.includes('claim boundary proves_enterprise_readiness must remain false'));
  assert('public distribution claim-boundary drift privacy safe', !unsafeOutputPattern.test(publicDistributionBoundaryClaimRun.stderr));

  writeFileSync(
    join(evidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'),
    `${JSON.stringify({
      ...publicDistributionBoundaryClaim,
      claim_boundary: {
        publishes_release_assets: false,
        creates_public_external_attestation: false,
        proves_non_operator_review: false,
        proves_production_publisher_key_custody: false,
        proves_production_signing_identity: false,
        proves_live_trust_registry_state: false,
        proves_revocation_truth: false,
        proves_production_downstream_recognition: false,
        proves_enterprise_readiness: false,
        proves_sovereign_recognition: false,
        proves_v3_4_0_readiness: false,
      },
    }, null, 2)}\n`
  );

  const readyPublicDistribution = clone(JSON.parse(readFileSync(join(evidenceDir, 'zlar-verifier-kit-public-distribution-v1.json'), 'utf8')));
  readyPublicDistribution.release_assets = {
    evidence_model: 'github-release-assets-json-live-read',
    release_url: 'https://github.com/ZLAR-AI/ZLAR/releases/tag/v3.3.110',
    asset_count: 3,
    assets: [
      { name: 'zlar-verifier-kit-v0.1.0.tar.gz', size: 10, state: 'uploaded' },
      { name: 'zlar-verifier-kit-v0.1.0.tar.gz.sha256', size: 11, state: 'uploaded' },
      { name: 'zlar-verifier-kit-reproducibility-v1.json', size: 12, state: 'uploaded' },
    ],
    public_release_publication_evidence: {
      supported: true,
      evidence_model: 'github-release-assets-json-live-read',
      supported_evidence_model: true,
      repository: 'ZLAR-AI/ZLAR',
      expected_repository: 'ZLAR-AI/ZLAR',
      repository_matches_expected: true,
      release_url: 'https://github.com/ZLAR-AI/ZLAR/releases/tag/v3.3.110',
      release_url_names_tag: true,
      release_url_names_expected_repository: true,
      asset_urls_name_expected_repository: true,
      release_draft: false,
      missing: [],
    },
    release_asset_hashes: {
      all_required_assets_uploaded: true,
      all_required_assets_positive_size: true,
      all_required_expected_hashes_present: true,
      all_required_supplied_hashes_present: true,
      all_required_assets_bound: true,
      checks: [
        { name: 'zlar-verifier-kit-v0.1.0.tar.gz', matches_expected_sha256: true },
        { name: 'zlar-verifier-kit-v0.1.0.tar.gz.sha256', matches_expected_sha256: true },
        { name: 'zlar-verifier-kit-reproducibility-v1.json', matches_expected_sha256: true },
      ],
    },
  };
  readyPublicDistribution.release_tag = 'v3.3.110';
  readyPublicDistribution.required_public_release_assets = readyPublicDistribution.required_public_release_assets.map((asset) => ({
    ...asset,
    present: true,
  }));
  readyPublicDistribution.reproducibility.public_release_publication_boundary = false;
  readyPublicDistribution.local_artifact_hashes.all_checked_hashes_match = true;
  readyPublicDistribution.posture = 'public_distribution_posture_ready';
  readyPublicDistribution.ready_for_public_distribution_claim = true;
  readyPublicDistribution.blocking_reasons = [];
  readyEvidenceReport = buildNorthStarReadinessReport({
    evidenceModel: 'release-forward-dry-run-artifacts',
    productProofPathReport: JSON.parse(readFileSync(join(evidenceDir, 'zlar-product-proof-path-v1.json'), 'utf8')),
    proofSmokeVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-proof-smoke-sample-verification.json'), 'utf8')),
    localProofPackVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-local-proof-pack-sample-verification.json'), 'utf8')),
    servicePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-service-preflight-sample-verification.json'), 'utf8')),
    runtimeLocalActivationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-local-activation-sample-verification.json'), 'utf8')),
    runtimeProfileInstallationVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-runtime-profile-installation-sample-verification.json'), 'utf8')),
    installedRuntimeProfilePreflightVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-preflight-sample-verification.json'), 'utf8')),
    installedRuntimeProfileRecognitionProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-recognition-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProof: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-v1.json'), 'utf8')),
    installedRuntimeProfileServiceProofArtifactVerification: JSON.parse(readFileSync(join(evidenceDir, 'zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json'), 'utf8')),
    coverageMap: JSON.parse(readFileSync(join(evidenceDir, 'zlar-coverage-map-sample.json'), 'utf8')),
    trustedIssuerRecognition: JSON.parse(readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition.json'), 'utf8')),
    malformedRegistryErrorText: readFileSync(join(evidenceDir, 'zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt'), 'utf8'),
    verifierKitReproducibility: JSON.parse(readFileSync(join(evidenceDir, 'zlar-verifier-kit-reproducibility-v1.json'), 'utf8')),
    verifierKitPublicDistribution: readyPublicDistribution,
    releaseForwardTargetTag: 'v3.3.110',
  });
  assert('ready public distribution report passes validation', assertNorthStarReadinessReport(readyEvidenceReport));
  assertEqual('ready public distribution result', 'READY_FOR_V3_4_0_PUBLIC_VERIFIER_KIT_DISTRIBUTION', readyEvidenceReport.result);
  assertEqual('ready public distribution v3.4 gate true', true, readyEvidenceReport.v3_4_0_gate.ready);
  assertEqual('ready public distribution triggers empty', 0, readyEvidenceReport.v3_4_0_gate.triggers_required.length);
  assertEqual(
    'ready public distribution byte binding true',
    true,
    readyEvidenceReport.puzzle_pieces.find((piece) => piece.id === 4).observed.verifier_kit_public_distribution.release_asset_hashes_bound
  );
  assertEqual('ready public distribution claim boundary true', true, readyEvidenceReport.claim_boundary.v3_4_0_ready);
  assertEqual('ready public distribution keeps external attestation false', false, readyEvidenceReport.claim_boundary.public_external_attestation);
  const readyEvidenceSummary = formatNorthStarReadinessSummary(readyEvidenceReport);
  assert(
    'ready public distribution summary still surfaces stronger North Star completion boundary',
    readyEvidenceSummary.includes(
      'Stronger North Star completion still false: enterprise_readiness=false; public_external_attestation=false; production_downstream_recognition=false; persistent_runtime_profile_installation=false',
    ),
  );
  assert(
    'ready public distribution summary keeps named deployment-profile proof below active persistent installation',
    readyEvidenceSummary.includes('Named deployment-profile real boundary is closed-proof only; active persistent installation still false: true'),
  );
} finally {
  rmSync(evidenceDir, { recursive: true, force: true });
}

console.log('\n-- builder contract --');
const rebuiltTerminalChainEvidence = freshTerminalChainEvidence();
const rebuilt = buildNorthStarReadinessReport({
  proofSmokeVerification: runZlarJson(['proof-smoke', 'verify', '--historical', '--sample', '--require-file-sha', 'de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268', '--require-sha', '8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80', '--json']),
  productProofPathReport: runZlarJson(['product-proof-path', '--json']),
  localProofPackVerification: runZlarJson(['local-proof-pack', 'verify', '--sample', '--json']),
  servicePreflightVerification: runZlarJson(['protected-records-service-preflight', 'verify', '--sample', '--json']),
  runtimeLocalActivationVerification: runZlarJson(['protected-records-runtime-local-activation', 'verify', '--sample', '--json']),
  runtimeProfileInstallationVerification: runZlarJson(['protected-records-runtime-profile-installation', 'verify', '--sample', '--json']),
  installedRuntimeProfilePreflightVerification: runZlarJson(['protected-records-installed-runtime-profile-preflight', 'verify', '--sample', '--json']),
  installedRuntimeProfileRecognitionProof: runZlarJson(['protected-records-installed-runtime-profile-recognition-proof', '--sample', '--json']),
  installedRuntimeProfileServiceProof: runZlarJson(['protected-records-installed-runtime-profile-service-proof', '--sample', '--json']),
  installedRuntimeProfileServiceProofArtifactVerification: runZlarJson(['protected-records-installed-runtime-profile-service-proof', 'verify', '--sample', '--json']),
  installedRuntimeProfileTerminalChain: rebuiltTerminalChainEvidence.report,
  installedRuntimeProfileTerminalChainArtifact: rebuiltTerminalChainEvidence.artifact,
  installedRuntimeProfileTerminalChainArtifactVerification:
    rebuiltTerminalChainEvidence.artifactVerification,
  coverageMap: runZlarJson(['coverage', '--sample', '--require-governed', '--json']),
});
assert('rebuilt report passes validation', assertNorthStarReadinessReport(rebuilt));
assertEqual(
  'rebuilt installed runtime profile terminal chain trusted registry binding required',
  true,
  rebuilt.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_required
);
assertEqual(
  'rebuilt installed runtime profile terminal chain trusted registry binding preserved',
  true,
  rebuilt.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_preserved
);
assert(
  'rebuilt installed runtime profile terminal chain trusted registry binding sha',
  /^[a-f0-9]{64}$/.test(rebuilt.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256)
);
assert(
  'rebuilt installed runtime profile terminal chain artifact verification trusted registry binding sha',
  /^[a-f0-9]{64}$/.test(rebuilt.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256)
);
assertEqual(
  'rebuilt installed runtime profile terminal chain trusted registry binding hashes match',
  rebuilt.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_binding_sha256,
  rebuilt.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_binding_sha256
);
assertObservedRecognizedReceiptPathMirror(
  'rebuilt installed runtime profile terminal chain recognized receipt path mirror',
  rebuilt.counts
);
assertObservedTrustedIssuerRegistryBinding(
  'rebuilt installed runtime profile terminal chain observed trusted registry binding',
  rebuilt.puzzle_pieces.find((piece) => piece.id === 3).observed
);
assertObservedRecognizedReceiptPathMirror(
  'rebuilt installed runtime profile terminal chain observed recognized receipt path mirror',
  rebuilt.puzzle_pieces.find((piece) => piece.id === 3).observed
);
assertObservedTrustedIssuerRegistryBinding(
  'rebuilt installed runtime profile terminal chain downstream trusted registry binding',
  rebuilt.puzzle_pieces.find((piece) => piece.id === 5).observed
);
assertObservedRecognizedReceiptPathMirror(
  'rebuilt installed runtime profile terminal chain downstream recognized receipt path mirror',
  rebuilt.puzzle_pieces.find((piece) => piece.id === 5).observed
);
assertEqual(
  'rebuilt report matches sample command outside one-run terminal-chain identity hashes',
  JSON.stringify(stripOneRunTerminalChainIdentity(clone(sampleReport))),
  JSON.stringify(stripOneRunTerminalChainIdentity(clone(rebuilt)))
);

console.log('\n-- fail closed report drift --');
const privateVerifierWithSample = runZlar([
  'north-star-readiness',
  '--sample',
  '--private-verifier-result-verification',
  'zlar-private-verifier-result-verification-v1.json',
]);
assert('private verifier option with sample exits nonzero', privateVerifierWithSample.status !== 0);
assertEqual('private verifier option with sample emits no stdout', '', privateVerifierWithSample.stdout);
assert('private verifier option with sample names evidence-dir boundary', privateVerifierWithSample.stderr.includes('only valid with --evidence-dir'));

const privateZipVerifierWithSample = runZlar([
  'north-star-readiness',
  '--sample',
  '--private-verifier-zip-result-verification',
  'zlar-private-verifier-zip-result-verification-v1.json',
]);
assert('private ZIP verifier option with sample exits nonzero', privateZipVerifierWithSample.status !== 0);
assertEqual('private ZIP verifier option with sample emits no stdout', '', privateZipVerifierWithSample.stdout);
assert('private ZIP verifier option with sample names evidence-dir boundary', privateZipVerifierWithSample.stderr.includes('only valid with --evidence-dir'));

const publicExternalAttestationWithSample = runZlar([
  'north-star-readiness',
  '--sample',
  '--public-external-attestation-result-verification',
  'zlar-public-external-attestation-result-verification-v1.json',
]);
assert('public external attestation option with sample exits nonzero', publicExternalAttestationWithSample.status !== 0);
assertEqual('public external attestation option with sample emits no stdout', '', publicExternalAttestationWithSample.stdout);
assert('public external attestation option with sample names evidence-dir boundary', publicExternalAttestationWithSample.stderr.includes('only valid with --evidence-dir'));

const v34Claim = clone(sampleReport);
v34Claim.v3_4_0_gate.ready = true;
assertThrows('v3.4 readiness claim fails', () => assertNorthStarReadinessReport(v34Claim), 'v3.4.0 gate readiness mismatch');

const externalAttestationClaim = clone(sampleReport);
externalAttestationClaim.claim_boundary.public_external_attestation = true;
assertThrows('external attestation claim fails', () => assertNorthStarReadinessReport(externalAttestationClaim), 'claim boundary public_external_attestation');

const extraClaimBoundaryField = clone(sampleReport);
extraClaimBoundaryField.claim_boundary.public_claim_boundary_summary = false;
assertThrows(
  'extra claim boundary field fails',
  () => assertNorthStarReadinessReport(extraClaimBoundaryField),
  'North Star claim boundary contains unexpected fields',
);

const missingClaimBoundaryField = clone(sampleReport);
delete missingClaimBoundaryField.claim_boundary.public_external_attestation;
assertThrows(
  'missing claim boundary field fails',
  () => assertNorthStarReadinessReport(missingClaimBoundaryField),
  'North Star claim boundary contains unexpected fields',
);

const renamedClaimBoundaryField = clone(sampleReport);
renamedClaimBoundaryField.claim_boundary.public_attestation = renamedClaimBoundaryField.claim_boundary.public_external_attestation;
delete renamedClaimBoundaryField.claim_boundary.public_external_attestation;
assertThrows(
  'renamed claim boundary field fails',
  () => assertNorthStarReadinessReport(renamedClaimBoundaryField),
  'North Star claim boundary contains unexpected fields',
);

const summaryShapedClaimBoundary = clone(sampleReport);
summaryShapedClaimBoundary.claim_boundary.claim_boundary_summary = {
  all_public_claims_false: true,
  public_external_attestation: false,
};
assertThrows(
  'summary-shaped claim boundary field fails',
  () => assertNorthStarReadinessReport(summaryShapedClaimBoundary),
  'North Star claim boundary contains unexpected fields',
);

const missingPiece = clone(sampleReport);
missingPiece.puzzle_pieces = missingPiece.puzzle_pieces.slice(0, 6);
assertThrows('missing puzzle piece fails', () => assertNorthStarReadinessReport(missingPiece), 'puzzle-piece list');

const driftedCoverage = clone(sampleReport);
driftedCoverage.counts.governed_lanes = 4;
assertThrows('coverage lane drift fails', () => assertNorthStarReadinessReport(driftedCoverage), 'coverage lane counts');

const custodyClaim = clone(sampleReport);
custodyClaim.puzzle_pieces.find((piece) => piece.id === 4).observed.key_state_key_custody_proven = true;
assertThrows('issuer custody claim fails', () => assertNorthStarReadinessReport(custodyClaim), 'issuer custody');

const humanAuthorizationDrift = clone(sampleReport);
humanAuthorizationDrift.puzzle_pieces.find((piece) => piece.id === 1).observed.human_authorization.authorized_boarded = false;
assertThrows('human authorization drift fails', () => assertNorthStarReadinessReport(humanAuthorizationDrift), 'human authorization summary drifted');

const productProofPathDrift = clone(sampleReport);
productProofPathDrift.puzzle_pieces.find((piece) => piece.id === 1).observed.product_proof_path.forbidden_claims_false = false;
assertThrows('product proof path drift fails', () => assertNorthStarReadinessReport(productProofPathDrift), 'Product Proof Path summary drifted');

const productProofPathIdentityDrift = clone(sampleReport);
productProofPathIdentityDrift.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.proof_pack_runtime_profile_identity_policy
  .omitted_runtime_profile_id_uses_launcher_config = false;
assertThrows(
  'product proof path runtime-profile identity policy drift fails',
  () => assertNorthStarReadinessReport(productProofPathIdentityDrift),
  'Product Proof Path proof-pack runtime-profile identity policy summary drifted',
);

const productProofPathClaudeHookReplayDrift = clone(sampleReport);
productProofPathClaudeHookReplayDrift.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.proof_pack_claude_hook_contract_replay
  .case_evidence_sha256 = '0'.repeat(64);
assertThrows(
  'product proof path Claude hook replay summary drift fails',
  () => assertNorthStarReadinessReport(productProofPathClaudeHookReplayDrift),
  'Product Proof Path proof-pack Claude hook replay summary drifted',
);

const productProofPathClaudeHookReplayComponentDrift = clone(sampleReport);
productProofPathClaudeHookReplayComponentDrift.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.proof_pack_claude_hook_contract_replay
  .component_sha256 = '0'.repeat(64);
assertThrows(
  'product proof path Claude hook replay component summary drift fails',
  () => assertNorthStarReadinessReport(productProofPathClaudeHookReplayComponentDrift),
  'Product Proof Path proof-pack Claude hook replay summary drifted',
);

const productProofPathDownstreamRefusalDrift = clone(sampleReport);
productProofPathDownstreamRefusalDrift.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.downstream_refusal_boundary
  .all_refusal_marker_count_deltas_zero = false;
assertThrows(
  'product proof path downstream refusal boundary drift fails',
  () => assertNorthStarReadinessReport(productProofPathDownstreamRefusalDrift),
  'Product Proof Path summary drifted',
);

const downstreamIdentityDrift = clone(sampleReport);
downstreamIdentityDrift.puzzle_pieces.find(
  (piece) => piece.id === 5,
).observed.runtime_profile_identity_policy.supplied_mismatched_runtime_profile_id_refused =
  false;
assertThrows(
  'downstream recognition runtime-profile identity policy drift fails',
  () => assertNorthStarReadinessReport(downstreamIdentityDrift),
  'Downstream Recognition Rule runtime-profile identity policy observed summary drifted',
);

const productProofPathTerminalBindingDrift = clone(sampleReport);
productProofPathTerminalBindingDrift.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.terminal_chain_boundary.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification = false;
assertThrows(
  'product proof path terminal binding drift fails',
  () => assertNorthStarReadinessReport(productProofPathTerminalBindingDrift),
  'Product Proof Path summary drifted',
);

const productProofPathTerminalRefusalIdDrift = clone(sampleReport);
productProofPathTerminalRefusalIdDrift.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.terminal_chain_boundary.trusted_issuer_registry_recognition_refusal_case_ids[0] =
  'drifted_case';
assertThrows(
  'product proof path terminal refusal ID drift fails',
  () => assertNorthStarReadinessReport(productProofPathTerminalRefusalIdDrift),
  'Product Proof Path summary drifted',
);

const productProofPathTerminalRecognitionGroupIdDrift = clone(sampleReport);
productProofPathTerminalRecognitionGroupIdDrift.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.terminal_chain_boundary
  .recognition_refusal_group_case_ids
  .no_usable_recognized_receipt_authority[0] = 'drifted_case';
assertThrows(
  'product proof path terminal recognition refusal group ID drift fails',
  () => assertNorthStarReadinessReport(productProofPathTerminalRecognitionGroupIdDrift),
  'Product Proof Path summary drifted',
);

const productProofPathTerminalNamedRefusalDrift = clone(sampleReport);
productProofPathTerminalNamedRefusalDrift.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.terminal_chain_boundary
  .named_receipt_refusals.stale_or_expired.refused_before_mutation = false;
assertThrows(
  'product proof path terminal named stale-or-expired refusal drift fails',
  () => assertNorthStarReadinessReport(productProofPathTerminalNamedRefusalDrift),
  'Product Proof Path summary drifted',
);

const productProofPathTerminalNamedRefusalHashDrift = clone(sampleReport);
productProofPathTerminalNamedRefusalHashDrift.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.terminal_chain_boundary
  .named_receipt_refusals_sha256 = '0'.repeat(64);
assertThrows(
  'product proof path terminal named refusal hash drift fails',
  () => assertNorthStarReadinessReport(productProofPathTerminalNamedRefusalHashDrift),
  'Product Proof Path summary drifted',
);

const productProofPathTerminalExternalAttestation = clone(sampleReport);
productProofPathTerminalExternalAttestation.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.terminal_chain_boundary.external_attestation = true;
assertThrows(
  'product proof path terminal external attestation claim fails',
  () => assertNorthStarReadinessReport(productProofPathTerminalExternalAttestation),
  'Product Proof Path summary drifted',
);

const productProofPathDeploymentBridgeLatest = clone(sampleReport);
productProofPathDeploymentBridgeLatest.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.deployment_profile_authority_bridge.selects_latest_profile = true;
assertThrows(
  'product proof path deployment bridge latest selection fails',
  () => assertNorthStarReadinessReport(productProofPathDeploymentBridgeLatest),
  'Product Proof Path summary drifted',
);

const productProofPathDeploymentBridgeRefusalCount = clone(sampleReport);
productProofPathDeploymentBridgeRefusalCount.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.deployment_profile_authority_bridge.observed_refusal_case_count = 17;
assertThrows(
  'product proof path deployment bridge refusal count fails',
  () => assertNorthStarReadinessReport(productProofPathDeploymentBridgeRefusalCount),
  'Product Proof Path summary drifted',
);

const productProofPathDeploymentBridgeMutation = clone(sampleReport);
productProofPathDeploymentBridgeMutation.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.deployment_profile_authority_bridge.recognized_state_entry_count_delta = 2;
assertThrows(
  'product proof path deployment bridge mutation delta fails',
  () => assertNorthStarReadinessReport(productProofPathDeploymentBridgeMutation),
  'Product Proof Path summary drifted',
);

const productProofPathDeploymentBridgeAuthorityClaim = clone(sampleReport);
productProofPathDeploymentBridgeAuthorityClaim.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.deployment_profile_authority_bridge.request_stream_authority_material_accepted = true;
assertThrows(
  'product proof path deployment bridge request authority claim fails',
  () => assertNorthStarReadinessReport(productProofPathDeploymentBridgeAuthorityClaim),
  'Product Proof Path summary drifted',
);

const productProofPathDeploymentBridgeStaleArtifact = clone(sampleReport);
productProofPathDeploymentBridgeStaleArtifact.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.deployment_profile_authority_bridge.stale_deployment_profile_artifact_refused_before_service_proof = false;
assertThrows(
  'product proof path deployment bridge stale artifact refusal fails',
  () => assertNorthStarReadinessReport(productProofPathDeploymentBridgeStaleArtifact),
  'Product Proof Path verification count drifted',
);

const productProofPathDeploymentBridgeMismatch = clone(sampleReport);
productProofPathDeploymentBridgeMismatch.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.deployment_profile_authority_bridge.profile_recognition_mismatch_refused_before_service_proof = false;
assertThrows(
  'product proof path deployment bridge mismatch refusal fails',
  () => assertNorthStarReadinessReport(productProofPathDeploymentBridgeMismatch),
  'Product Proof Path verification count drifted',
);

const productProofPathDeploymentBridgeProductionClaim = clone(sampleReport);
productProofPathDeploymentBridgeProductionClaim.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.deployment_profile_authority_bridge.production_authority = true;
assertThrows(
  'product proof path deployment bridge production authority claim fails',
  () => assertNorthStarReadinessReport(productProofPathDeploymentBridgeProductionClaim),
  'Product Proof Path summary drifted',
);

const productProofPathRegistryClaim = clone(sampleReport);
productProofPathRegistryClaim.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.trusted_issuer_registry_recognition.proves_live_registry = true;
assertThrows(
  'product proof path trusted registry claim fails',
  () => assertNorthStarReadinessReport(productProofPathRegistryClaim),
  'Product Proof Path summary drifted',
);

const productProofPathRegistryCurrentMachineClaim = clone(sampleReport);
productProofPathRegistryCurrentMachineClaim.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.trusted_issuer_registry_recognition.proves_current_machine_governance = true;
assertThrows(
  'product proof path trusted registry current-machine claim fails',
  () => assertNorthStarReadinessReport(productProofPathRegistryCurrentMachineClaim),
  'Product Proof Path summary drifted',
);

const productProofPathRegistryEvaluatorDrift = clone(sampleReport);
productProofPathRegistryEvaluatorDrift.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.trusted_issuer_registry_recognition.registry_evaluation_result_type =
  'synthetic-summary';
assertThrows(
  'product proof path trusted registry evaluator drift fails',
  () => assertNorthStarReadinessReport(productProofPathRegistryEvaluatorDrift),
  'Product Proof Path summary drifted',
);

const productProofPathTerminalRegistryVerdictDrift = clone(sampleReport);
productProofPathTerminalRegistryVerdictDrift.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.terminal_chain_boundary.trusted_issuer_registry_recognition_verdict =
  'UNRECOGNIZED';
assertThrows(
  'product proof path terminal registry verdict drift fails',
  () => assertNorthStarReadinessReport(productProofPathTerminalRegistryVerdictDrift),
  'Product Proof Path summary drifted',
);

const productProofPathTerminalRegistryRuleDrift = clone(sampleReport);
productProofPathTerminalRegistryRuleDrift.puzzle_pieces.find(
  (piece) => piece.id === 1,
).observed.product_proof_path.terminal_chain_boundary.trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated = false;
assertThrows(
  'product proof path terminal registry rule drift fails',
  () => assertNorthStarReadinessReport(productProofPathTerminalRegistryRuleDrift),
  'Product Proof Path summary drifted',
);

const malformedDrift = clone(sampleReport);
malformedDrift.puzzle_pieces.find((piece) => piece.id === 4).observed.malformed_registry_contract = {
  provided: true,
  fail_closed_before_verdict: false,
  unsupported_field_detected: false,
  claim_boundary: 'drifted',
};
assertThrows('malformed registry drift fails', () => assertNorthStarReadinessReport(malformedDrift), 'malformed registry contract');

const verifierKitDrift = clone(evidenceReport);
verifierKitDrift.puzzle_pieces.find((piece) => piece.id === 4).observed.verifier_kit_reproducibility.claim_boundary_flags_false = false;
assertThrows('verifier kit reproducibility boundary drift fails', () => assertNorthStarReadinessReport(verifierKitDrift), 'verifier-kit reproducibility boundary');

const verifierKitDistributionDrift = clone(evidenceReport);
verifierKitDistributionDrift.puzzle_pieces.find((piece) => piece.id === 4).observed.verifier_kit_public_distribution.ready_for_public_distribution_claim = true;
assertThrows('verifier kit public distribution claim drift fails', () => assertNorthStarReadinessReport(verifierKitDistributionDrift), 'ready evidence incomplete');

const verifierKitDistributionByteBindingDrift = clone(readyEvidenceReport);
verifierKitDistributionByteBindingDrift.puzzle_pieces.find((piece) => piece.id === 4).observed.verifier_kit_public_distribution.release_asset_hashes_bound = false;
assertThrows('verifier kit public distribution byte binding drift fails', () => assertNorthStarReadinessReport(verifierKitDistributionByteBindingDrift), 'ready evidence incomplete');

const privateVerifierResultDrift = clone(evidenceWithPrivateReport);
privateVerifierResultDrift.puzzle_pieces.find((piece) => piece.id === 6).observed.private_verifier_result_verification.public_attribution = true;
assertThrows('private verifier public attribution drift fails', () => assertNorthStarReadinessReport(privateVerifierResultDrift), 'must not widen public claims');

const privateVerifierDownstreamReasonDrift = clone(evidenceWithPrivateReport);
privateVerifierDownstreamReasonDrift.puzzle_pieces.find((piece) => piece.id === 6).observed.private_verifier_result_verification.downstream_refusal_reasons = ['generic_refusal'];
assertThrows('private verifier downstream reason drift fails', () => assertNorthStarReadinessReport(privateVerifierDownstreamReasonDrift), 'downstream-refusal evidence incomplete');

const privateZipVerifierPublicClaimDrift = clone(evidenceWithPrivateZipReport);
privateZipVerifierPublicClaimDrift.puzzle_pieces.find((piece) => piece.id === 6).observed.private_verifier_zip_result_verification.public_external_attestation = true;
assertThrows('private ZIP verifier public attestation drift fails', () => assertNorthStarReadinessReport(privateZipVerifierPublicClaimDrift), 'must not widen public claims');

const publicExternalAttestationIntakeClaimDrift =
  clone(evidenceWithPublicExternalAttestationReport);
publicExternalAttestationIntakeClaimDrift
  .puzzle_pieces.find((piece) => piece.id === 6)
  .observed.public_external_attestation_result_verification.public_external_attestation = true;
assertThrows(
  'public external attestation intake claim drift fails',
  () => assertNorthStarReadinessReport(publicExternalAttestationIntakeClaimDrift),
  'must remain intake-only and non-scoring'
);

const privateIntakePointerDrift = clone(evidenceReport);
privateIntakePointerDrift.puzzle_pieces.find((piece) => piece.id === 7).observed.private_intake_sample_manifest_pointer.creates_public_external_attestation = true;
assertThrows('private intake pointer attestation drift fails', () => assertNorthStarReadinessReport(privateIntakePointerDrift), 'private intake sample manifest pointer boundary');

const missingNonClaim = clone(sampleReport);
missingNonClaim.non_claims = missingNonClaim.non_claims.filter((claim) => !claim.includes('external attestation'));
assertThrows('missing non-claim fails', () => assertNorthStarReadinessReport(missingNonClaim), 'non-claims drifted');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed${FAIL ? ` (${FAIL} FAILED)` : ' ✓'}`);
if (FAIL > 0) {
  process.exit(1);
}
