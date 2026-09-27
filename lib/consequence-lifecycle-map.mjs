import { createHash } from 'node:crypto';
import {
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact,
  verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact,
} from './protected-records-installed-runtime-profile-terminal-chain.mjs';
import {
  PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256,
  protectedRecordsFixtureAuthorityGrantStatus,
} from './protected-records-fixture-authority-status.mjs';

export const CONSEQUENCE_LIFECYCLE_MAP_TYPE = 'zlar-consequence-lifecycle-map-v0';
export const CONSEQUENCE_LIFECYCLE_MAP_VERSION = 0;
export const CONSEQUENCE_LIFECYCLE_PATH_ID =
  'protected-records.installed-runtime-profile.terminal-chain.records.write';
export const CONSEQUENCE_LIFECYCLE_SAFE_CLAIM_CEILING =
  'ZLAR can map one exact SHA-pinned historical local disposable protected-records terminal-chain fixture path with a full public authority-grant topology, structural boarding evidence, 18 recognition refusals, five authority refusals, replay separation, named burn windows, and an explicit joint-rollback side door; source reconciliation records the one-use grant as exhausted and repeated-use provenance as invalid, so current fixture-rightful issuance remains open.';

export const CONSEQUENCE_LIFECYCLE_PINNED_TERMINAL_ARTIFACT_BODY_SHA256 =
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256;

const CHECKPOINT_ID =
  'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation';
const ACTION_CLASS = 'records.write';

const PATH_NODES = Object.freeze([
  'proposal',
  'receipt_recognition_checkpoint',
  'authority_grant_effect_gate',
  'authority_grant_consumption',
  'runtime_state_append',
  'refusal',
  'evidence_closeout',
]);

const PATH_EDGES = Object.freeze([
  Object.freeze({ from: 'proposal', to: 'receipt_recognition_checkpoint', when: 'action_attempted' }),
  Object.freeze({ from: 'receipt_recognition_checkpoint', to: 'refusal', when: 'receipt_not_recognized' }),
  Object.freeze({ from: 'receipt_recognition_checkpoint', to: 'authority_grant_effect_gate', when: 'receipt_recognized' }),
  Object.freeze({ from: 'authority_grant_effect_gate', to: 'refusal', when: 'authority_grant_refused' }),
  Object.freeze({ from: 'authority_grant_effect_gate', to: 'authority_grant_consumption', when: 'authority_grant_accepted' }),
  Object.freeze({ from: 'authority_grant_consumption', to: 'runtime_state_append', when: 'grant_store_commit_succeeds' }),
  Object.freeze({ from: 'authority_grant_consumption', to: 'refusal', when: 'post_consumption_commit_or_append_fails' }),
  Object.freeze({ from: 'refusal', to: 'evidence_closeout', when: 'refusal_recorded' }),
  Object.freeze({ from: 'runtime_state_append', to: 'evidence_closeout', when: 'result_recorded' }),
]);

export const REQUIRED_REVOCATION_POWER_IDS = Object.freeze([
  'withdraw_receipt_recognition',
  'retire_issuer_key',
  'mark_issuer_compromised',
  'withdraw_authority_grant',
  'decommission_route',
  'invalidate_policy',
  'close_deployment_profile',
  'reject_or_supersede_hardening_rule',
]);

const ADDITIONAL_OPEN_BOUNDARIES = Object.freeze([
  'profile_wide_target_authority',
  'per_run_or_physical_target_identity',
  'live_target_binding',
  'source_commit_binding',
  'generic_rightful_issuance',
  'portable_rightful_issuance',
  'live_rightful_issuance',
  'production_rightful_issuance',
  'current_machine_authority_identity',
  'portable_cryptographic_reverification',
  'revocation_authority_topology',
  'appeal_or_contest',
  'consequence_recovery',
  'governed_hardening',
  'regression_closure',
  'equivalent_route_classification',
  'current_fixture_authority_grant_exhausted',
]);

const ADDITIONAL_CLOSURE_BLOCKERS = Object.freeze([
  'profile_wide_target_authority_unproven',
  'per_run_or_physical_target_identity_unproven',
  'live_target_binding_unproven',
  'source_commit_binding_missing',
  'generic_rightful_issuance_outside_local_fixture_scope',
  'portable_authority_identity_unproven',
  'live_authority_identity_unproven',
  'production_authority_identity_unproven',
  'current_machine_authority_identity_unproven',
  'portable_cryptographic_reverification_unavailable',
  'revocation_truth_unproven',
  'exactly_once_effects_unproven',
  'unrouted_records_paths_unchecked',
  'current_fixture_authority_grant_exhausted',
  'repeated_use_fixture_provenance_invalid',
]);

const NON_CLAIMS = Object.freeze([
  'This map is a deterministic projection of one exact SHA-pinned local disposable terminal-chain fixture artifact.',
  'This map does not borrow active-persistent current-machine evidence or evidence from another consequence path.',
  'The pinned artifact is historical structural evidence. Its one-use grant is source-recorded as exhausted and its repeated-use provenance is invalid, so it does not currently evidence even fixture-scoped rightful issuance.',
  'This map binds one launcher-owned logical-fixture target only; it does not prove profile-wide target authority, a per-run or physical target identity, or a live target.',
  'The synthetic registry-recognition evidence receipt is not the boarded service receipt and did not authorize the service write.',
  'This map does not claim rollback of the records.write consequence; consumed-store rollback detection is replay protection only.',
  'The fixture contract evidences an expiry window, replacement power, and authority-grant revocation power plus local expired and revoked refusal behavior; it does not prove live revocation truth or external custody of revocation state.',
  'This map does not create authority from observations, refusals, recommendations, map ownership, or hardening proposals.',
  'This map does not prove appeal, contest, containment, compensation, governed hardening, regression closure, equivalent-route parity, or side-door closure.',
  'This map does not prove production governance, enterprise readiness, general current-machine governance, public external attestation, sovereign recognition, or all-surface governance.',
]);

function assertObject(label, value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function assertExactKeys(label, value, expectedKeys) {
  assertObject(label, value);
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} fields must be exactly: ${expected.join(', ')}`);
  }
}

function assertExactArray(label, actual, expected) {
  if (!Array.isArray(actual) || JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} does not match the required canonical values`);
  }
}

function unique(values) {
  return [...new Set(values)];
}

function lifecycleGraphSha256() {
  return createHash('sha256')
    .update(JSON.stringify({ nodes: PATH_NODES, edges: PATH_EDGES }))
    .digest('hex');
}

function resolveEvidenceRef(ref, report, sourceArtifact) {
  if (typeof ref !== 'string' || (!ref.startsWith('source:') && !ref.startsWith('report:'))) {
    throw new Error('Consequence lifecycle evidence reference must use source: or report: namespace');
  }
  const [namespace, path] = ref.split(':', 2);
  if (!path) {
    throw new Error(`Consequence lifecycle evidence reference path is empty: ${ref}`);
  }
  let value = namespace === 'source' ? sourceArtifact : report;
  for (const segment of path.split('.')) {
    if (value === null || value === undefined || !Object.prototype.hasOwnProperty.call(Object(value), segment)) {
      throw new Error(`Consequence lifecycle evidence reference does not resolve: ${ref}`);
    }
    value = value[segment];
  }
  if (value === undefined) {
    throw new Error(`Consequence lifecycle evidence reference does not resolve: ${ref}`);
  }
  return value;
}

function evidenceRefCollections(report) {
  return [
    ...report.observed_traces.map((item) => ({ label: item.trace_id, status: item.evidence_status, refs: item.evidence_refs })),
    ...report.lifecycle_obligations.map((item) => ({ label: item.obligation_id, status: item.status, refs: item.evidence_refs })),
    ...report.authority_topology.powers.map((item) => ({ label: item.power_id, status: item.evidence_status, refs: item.evidence_refs })),
    ...report.revocation_powers.powers.map((item) => ({
      label: item.power_id,
      status: item.evidence_status,
      refs: item.refusal_behavior_evidence_refs,
    })),
  ];
}

function validateEvidenceRefs(report, sourceArtifact) {
  const collections = evidenceRefCollections(report);
  let totalReferenceCount = 0;
  let sourceReferenceCount = 0;
  let reportReferenceCount = 0;
  for (const item of collections) {
    if (!Array.isArray(item.refs)) {
      throw new Error(`Consequence lifecycle evidence references must be an array: ${item.label}`);
    }
    if (new Set(item.refs).size !== item.refs.length) {
      throw new Error(`Consequence lifecycle evidence references must be unique: ${item.label}`);
    }
    for (const ref of item.refs) {
      resolveEvidenceRef(ref, report, sourceArtifact);
      totalReferenceCount += 1;
      if (ref.startsWith('source:')) sourceReferenceCount += 1;
      if (ref.startsWith('report:')) reportReferenceCount += 1;
    }
    if ((item.status === 'evidenced' || item.status === 'refused') &&
        !item.refs.some((ref) => ref.startsWith('source:'))) {
      throw new Error(`Consequence lifecycle evidenced item requires a source reference: ${item.label}`);
    }
  }
  return {
    resolution_model: 'exact-own-property-path-v1',
    collection_count: collections.length,
    evidenced_or_refused_item_count: collections.filter((item) =>
      item.status === 'evidenced' || item.status === 'refused'
    ).length,
    total_reference_count: totalReferenceCount,
    source_reference_count: sourceReferenceCount,
    report_reference_count: reportReferenceCount,
    all_references_resolved: true,
    pinned_source_artifact_body_sha256:
      CONSEQUENCE_LIFECYCLE_PINNED_TERMINAL_ARTIFACT_BODY_SHA256,
    pinned_source_artifact_body_sha256_matched:
      sourceArtifact.integrity.body_sha256 ===
        CONSEQUENCE_LIFECYCLE_PINNED_TERMINAL_ARTIFACT_BODY_SHA256,
  };
}

function authorityPower(power_id, actor_id, object, scope, evidence_status, evidence_refs = []) {
  return {
    power_id,
    actor_id,
    object,
    scope,
    evidence_status,
    evidence_refs,
    map_declaration_creates_authority: false,
  };
}

function revocationPower(
  power_id,
  object,
  scope,
  refusal_behavior_evidence_refs = [],
  actor_id = 'unassigned',
  evidence_status = 'not_evidenced'
) {
  return {
    power_id,
    actor_id,
    object,
    scope,
    evidence_status,
    refusal_behavior_evidence_refs,
    map_declaration_creates_authority: false,
  };
}

function obligation(obligation_id, status, authority_id, evidence_refs, reason, claim_allowed) {
  const blocks_closure = status !== 'evidenced' && status !== 'not_applicable_with_reason';
  return {
    obligation_id,
    status,
    authority_id,
    evidence_refs,
    reason,
    claim_allowed,
    blocks_closure,
    closure_blocker_id: blocks_closure ? `${obligation_id}_${status}` : null,
  };
}

function equivalentRoute(surface_id) {
  return {
    surface_id,
    relationship: 'unknown',
    parity_proven: false,
  };
}

function reportFromArtifact(sourceArtifact) {
  const terminalArtifactVerification =
    verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(sourceArtifact, {
      expectedArtifactBodySha256:
        CONSEQUENCE_LIFECYCLE_PINNED_TERMINAL_ARTIFACT_BODY_SHA256,
    });
  const chain = sourceArtifact.payload.chain;
  const terminal = chain.terminal_chain;
  const registry = terminal.trusted_issuer_registry_recognition_binding;
  const receiptPath = terminal.recognized_receipt_path_evidence;
  const targetBinding = terminal.boarded_service_target_binding;
  const serviceProof = chain.generated_service_proof;
  const publicGrantContract = terminal.public_grant_contract;
  const publicGrantSummary = terminal.public_safe_grant_summary;
  const publicGrantPowerIds = publicGrantContract.powers.map((power) => power.power_id);
  const nestedServiceProof =
    chain.nested_artifacts.generated_service_proof_artifact.payload.proof;
  const sourceOpenBoundaries = [...chain.known_open_boundaries];
  const authorityGrantStatus = protectedRecordsFixtureAuthorityGrantStatus(
    terminal.public_grant_contract_sha256
  );
  if (
    terminal.public_grant_contract_sha256 !==
      PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256 ||
    authorityGrantStatus.status !== 'exhausted' ||
    authorityGrantStatus.fresh_effect_allowed !== false ||
    authorityGrantStatus.repeated_use_provenance_valid !== false ||
    authorityGrantStatus.fresh_fixture_rightful_projection_allowed !== false
  ) {
    throw new Error('Consequence lifecycle map fixture authority status drifted');
  }

  const report = {
    report_type: CONSEQUENCE_LIFECYCLE_MAP_TYPE,
    map_version: CONSEQUENCE_LIFECYCLE_MAP_VERSION,
    map_status: 'mapped_open',
    safe_claim_ceiling: CONSEQUENCE_LIFECYCLE_SAFE_CLAIM_CEILING,
    authority_domain: {
      domain_id: publicGrantContract.authority_domain.domain_id,
      named: true,
      evidence_model: chain.evidence_model,
      production_domain: false,
      public_grant_contract_sha256: terminal.public_grant_contract_sha256,
      authorization_record_id: publicGrantContract.authorization_record.record_id,
      rightful_issuance_scope: publicGrantSummary.rightful_issuance_scope,
      fixture_rightful_issuance_path_evidenced: false,
      generic_rightful_issuance_proven: false,
    },
    consequence_path: {
      path_id: CONSEQUENCE_LIFECYCLE_PATH_ID,
      action_class: ACTION_CLASS,
      protected_target: targetBinding.target_kind,
      protected_target_handle: targetBinding.target_handle,
      protected_target_scope: targetBinding.target_scope,
      protected_target_instance_scope: targetBinding.target_instance_scope,
      protected_target_binding_sha256:
        terminal.boarded_service_target_binding_sha256,
      protected_target_binding_proven: true,
      launcher_owned_target_binding_proven: true,
      profile_wide_target_authority_proven: false,
      per_run_or_physical_target_identity_proven: false,
      live_target_binding_proven: false,
      target_binding_metadata_role: targetBinding.metadata_role,
      registry_receipt_is_boarded_service_receipt: false,
      checkpoint: CHECKPOINT_ID,
      authority_grant_contract_sha256: terminal.public_grant_contract_sha256,
      authority_grant_crossing_binding_sha256:
        terminal.authority_grant_crossing_binding_sha256,
      accepted_crossing_evidence_sha256:
        terminal.accepted_crossing_evidence_sha256,
      fixture_rightful_issuance_path_evidenced: false,
      generic_rightful_issuance_proven: false,
      downstream_door: 'local-disposable-protected-records-runtime-service',
      exact_path_evidence_bound: receiptPath.evidence_scope === CONSEQUENCE_LIFECYCLE_PATH_ID,
    },
    source_evidence: {
      artifact_type: sourceArtifact.artifact_type,
      artifact_body_sha256: sourceArtifact.integrity.body_sha256,
      artifact_generator: sourceArtifact.generator,
      artifact_hash_scope: sourceArtifact.hash_scope,
      expected_artifact_body_sha256:
        CONSEQUENCE_LIFECYCLE_PINNED_TERMINAL_ARTIFACT_BODY_SHA256,
      expected_artifact_body_sha256_matched:
        sourceArtifact.integrity.body_sha256 ===
          CONSEQUENCE_LIFECYCLE_PINNED_TERMINAL_ARTIFACT_BODY_SHA256,
      artifact_structural_self_integrity_verified:
        terminalArtifactVerification.structural_self_integrity_verified,
      artifact_identity_match_requires_expected_sha256:
        terminalArtifactVerification.artifact_identity_match_requires_expected_sha256,
      terminal_verification_scope: terminalArtifactVerification.verification_scope,
      embedded_service_artifact_body_sha256:
        terminal.expected_generated_service_proof_artifact_body_sha256,
      embedded_service_expected_sha256_matched:
        terminal.expected_generated_service_proof_artifact_body_sha256_matched,
      path_id: receiptPath.evidence_scope,
      evidence_model: chain.evidence_model,
      source_commit: null,
      source_commit_bound: false,
      generation_time_recognition_evaluation: registry.registry_fixture_evaluated === true,
      artifact_integrity_verified: true,
      evidence_ref_resolution_model: 'exact-own-property-path-v1',
      portable_cryptographic_reverification_possible:
        receiptPath.cryptographic_evidence_reproducible_from_artifact === true,
      boarded_service_target_binding_sha256:
        terminal.boarded_service_target_binding_sha256,
      boarded_service_receipt_role: targetBinding.boarded_service_receipt_role,
      registry_receipt_role: registry.registry_receipt_role,
      receipt_roles_distinct:
        registry.registry_receipt_is_boarded_service_receipt === false &&
        registry.receipt_detail_hash_roles_distinct === true,
      public_grant_contract_sha256: terminal.public_grant_contract_sha256,
      public_grant_summary_sha256: terminal.public_safe_grant_summary_sha256,
      public_grant_power_ids: [...publicGrantPowerIds],
      accepted_crossing_evidence_sha256:
        terminal.accepted_crossing_evidence_sha256,
      recognition_refusal_case_count:
        terminal.observed_recognition_refusal_case_count,
      authority_refusal_case_count: terminal.observed_authority_refusal_case_count,
    },
    path_definition: {
      graph_type: 'branching_dag',
      evidence_status: 'artifact_projected_open',
      source_artifact_bound: true,
      source_commit_bound: false,
      checkpoint_route: CHECKPOINT_ID,
      evidence_refs: [
        'source:payload.chain.nested_artifacts.generated_preflight_artifact.payload.preflight.recognition_contract.mutation_authoritative_route',
        'source:payload.chain.nested_artifacts.generated_service_proof_artifact.payload.proof.authority_contract.construction_order',
        'source:payload.chain.terminal_chain.recognition_refusal_groups',
        'source:payload.chain.terminal_chain.authority_refusal_taxonomy_sha256',
      ],
      graph_sha256: lifecycleGraphSha256(),
      linear_lifecycle_trace_claimed: false,
      nodes: [...PATH_NODES],
      edges: PATH_EDGES.map((edge) => ({ ...edge })),
    },
    observed_traces: [
      {
        trace_id: 'recognized_fixture_boarding',
        path_id: CONSEQUENCE_LIFECYCLE_PATH_ID,
        outcome: 'boarded',
        evidence_status: 'evidenced',
        refusal_case_count: 0,
        evidence_refs: [
          'source:payload.chain.terminal_chain.recognized_write_boarded',
          'source:payload.chain.terminal_chain.boarded_service_target_binding',
          'source:payload.chain.terminal_chain.public_grant_contract',
          'source:payload.chain.terminal_chain.public_safe_grant_summary',
          'source:payload.chain.nested_artifacts.generated_service_proof_artifact.payload.proof.accepted_crossing_evidence',
          'source:payload.chain.terminal_chain.recognized_receipt_path_evidence.boarded_service_receipt_role',
        ],
        continued_after_refusal: false,
      },
      {
        trace_id: 'required_fixture_refusals',
        path_id: CONSEQUENCE_LIFECYCLE_PATH_ID,
        outcome: 'refused_before_mutation',
        evidence_status: 'refused',
        refusal_case_count: terminal.observed_recognition_refusal_case_count,
        evidence_refs: [
          'source:payload.chain.terminal_chain.recognition_refusal_groups',
          'source:payload.chain.terminal_chain.named_receipt_refusals',
        ],
        continued_after_refusal: false,
      },
      {
        trace_id: 'required_fixture_authority_refusals',
        path_id: CONSEQUENCE_LIFECYCLE_PATH_ID,
        outcome: 'refused_before_consumption_and_mutation',
        evidence_status: 'refused',
        refusal_case_count: terminal.observed_authority_refusal_case_count,
        evidence_refs: [
          'source:payload.chain.nested_artifacts.generated_service_proof_artifact.payload.proof.authority_refusal_cases',
          'source:payload.chain.terminal_chain.authority_refusal_taxonomy_sha256',
        ],
        continued_after_refusal: false,
      },
    ],
    lifecycle_obligations: [
      obligation('path_identity', 'evidenced', 'fixture-deployment-owner', ['source:payload.chain.terminal_chain.recognized_receipt_path_evidence.evidence_scope'], 'The exact consequence path identity is bound to the artifact.', 'One fixture path identity is mapped.'),
      obligation('protected_target_binding', 'evidenced', 'launcher-owned-fixture-service-config', ['source:payload.chain.terminal_chain.boarded_service_target_binding', 'source:payload.chain.terminal_chain.boarded_service_target_binding_sha256'], 'One fixed logical-fixture target is bound across launcher config, request assertion, boarded receipt detail, accepted state-effect summary, nested artifacts, and the terminal artifact; profile-wide, per-run, physical, and live target authority remain unproven.', 'One launcher-owned logical-fixture target binding is evidenced.'),
      obligation('lifecycle_graph_definition', 'evidenced', 'artifact-projector', ['source:payload.chain.nested_artifacts.generated_preflight_artifact.payload.preflight.recognition_contract.mutation_authoritative_route', 'source:payload.chain.nested_artifacts.generated_service_proof_artifact.payload.proof.authority_contract.construction_order', 'source:payload.chain.terminal_chain.recognition_refusal_groups', 'source:payload.chain.terminal_chain.authority_refusal_taxonomy_sha256'], 'The pinned artifact directly supports the receipt-recognition, authority-grant effect gate, one-use consumption, state-append, and refusal branches; broader lifecycle closeout remains open.', 'The exact local-fixture route graph is evidenced.'),
      obligation('action_classification', 'evidenced', 'fixture-policy-contract', ['source:payload.chain.nested_artifacts.generated_preflight_artifact.payload.preflight.installed_profile.action_class'], 'The artifact binds records.write.', 'The fixture action class is records.write.'),
      obligation('checkpoint_routing', 'evidenced', 'fixture-deployment-owner', ['source:payload.chain.nested_artifacts.generated_preflight_artifact.payload.preflight.recognition_contract.mutation_authoritative_route', 'source:payload.chain.nested_artifacts.generated_service_proof_artifact.payload.proof.accepted_runtime_transition_binding'], 'The exact fixture route is receipt recognition, authority-grant effect evaluation, one-use grant consumption, then runtime-state append.', 'The exact local-fixture checkpoint route is evidenced.'),
      obligation('authority_topology', 'evidenced', 'fixture-consequence-authority', ['source:payload.chain.terminal_chain.public_grant_contract', 'source:payload.chain.terminal_chain.public_safe_grant_summary', 'source:payload.chain.terminal_chain.public_grant_contract_sha256'], 'The full public fixture contract names grantor, grantee slot, exact scope, four non-delegable powers, validity window, one-use policy, replacement behavior, and claim boundary without disclosing the runtime-private appointment.', 'The exact local-fixture authority topology is evidenced.'),
      obligation('local_fixture_rightful_issuance', 'not_evidenced', 'fixture-consequence-authority', ['source:payload.chain.terminal_chain.public_grant_contract', 'source:payload.chain.terminal_chain.public_safe_grant_summary', 'source:payload.chain.nested_artifacts.generated_service_proof_artifact.payload.proof.accepted_crossing_evidence', 'source:payload.chain.terminal_chain.expected_generated_service_proof_artifact_body_sha256_matched'], 'The artifact records historical issuance/effect mechanics, but its one-use contract is exhausted and repeated-use provenance is invalid. Fresh stores cannot create new authority.', 'Fixture-rightful issuance remains open pending a separately authorized replacement contract and one canonical crossing.'),
      obligation('receipt_requirement', 'evidenced', 'fixture-recognition-rule', ['source:payload.chain.terminal_chain.recognition_contract_sha256'], 'A recognized receipt is required by the fixture downstream door.', 'Receipt-required fixture boarding is evidenced.'),
      obligation('receipt_issuance_or_refusal', 'evidenced', 'fixture-receipt-issuer', ['source:payload.chain.terminal_chain.recognized_write_boarded', 'source:payload.chain.terminal_chain.observed_recognition_refusal_case_count', 'source:payload.chain.terminal_chain.observed_authority_refusal_case_count'], 'The fixture records one accepted crossing, 18 recognition refusals before mutation, and five authority refusals before consumption and mutation.', 'The exact 18+5 fixture issuance/refusal branches are mapped.'),
      obligation('boundary_verification', 'evidenced', 'artifact-validator', ['source:integrity.body_sha256', 'source:payload.chain.terminal_chain.expected_generated_service_proof_artifact_body_sha256', 'source:payload.chain.terminal_chain.expected_generated_service_proof_artifact_body_sha256_matched'], 'The terminal artifact is structurally verified and matched to the map-pinned terminal SHA; its embedded service artifact is structurally verified and exact-SHA matched. Portable signed-receipt cryptographic re-verification remains unavailable.', 'Structural verification and exact expected-artifact identity are distinguished and evidenced.'),
      obligation('effect_or_refusal', 'evidenced', 'fixture-downstream-door', ['source:payload.chain.terminal_chain.recognized_write_boarded', 'source:payload.chain.terminal_chain.observed_recognition_refusal_case_count', 'source:payload.chain.terminal_chain.observed_authority_refusal_case_count', 'source:payload.chain.terminal_chain.state_append_after_grant_commit_burn_observed', 'source:payload.chain.terminal_chain.metadata_partial_commit_burn_observed'], 'One write boards, 18 recognition cases refuse before mutation, five authority cases refuse before consumption and mutation, and both post-consumption burn windows are named.', 'Fixture boarding, refusal, and burn-window outcomes are evidenced.'),
      obligation('logging_and_memorialization', 'evidenced', 'artifact-validator', ['source:integrity.body_sha256'], 'The validated artifact memorializes the fixture result.', 'The fixture result is memorialized.'),
      obligation('path_closeout', 'not_evidenced', 'unassigned', [], 'Disposable-root cleanup is not authority-domain lifecycle closeout.', 'Path closeout remains open.'),
      obligation('expiry_or_supersession', 'evidenced', 'fixture-consequence-authority', ['source:payload.chain.terminal_chain.public_grant_contract.time_policy', 'source:payload.chain.terminal_chain.public_grant_contract.usage_policy', 'source:payload.chain.terminal_chain.public_grant_contract.powers.2', 'source:payload.chain.terminal_chain.public_grant_contract.powers.3', 'source:payload.chain.nested_artifacts.generated_service_proof_artifact.payload.proof.authority_refusal_cases.2', 'source:payload.chain.nested_artifacts.generated_service_proof_artifact.payload.proof.authority_refusal_cases.3'], 'The fixture contract fixes a half-open expiry window, requires a different contract SHA for replacement, grants replacement and revocation powers to the fixture authority, and demonstrates local expired and revoked refusals. Live revocation truth remains unproven.', 'Fixture expiry, replacement, and revocation behavior are evidenced only for this exact local contract.'),
      obligation('appeal_or_contest', 'outside_coverage', 'unassigned', [], '/contest is not implemented.', 'Appeal is explicitly outside coverage.'),
      obligation('consequence_recovery', 'not_evidenced', 'unassigned', [], 'Replay-store rollback protection is not rollback of the records.write consequence.', 'Recovery remains open.'),
      obligation('learning', 'outside_coverage', 'unassigned', [], 'The terminal-chain artifact does not run a governed learning workflow.', 'Learning is explicitly outside this fixture.'),
      obligation('hardening_proposal', 'not_evidenced', 'unassigned', [], 'No governed hardening proposal evidence is present.', 'Hardening proposal remains open.'),
      obligation('hardening_authorization', 'not_evidenced', 'unassigned', [], 'No distinct governed change grant is present.', 'Hardening authorization remains open.'),
      obligation('hardening_application', 'not_evidenced', 'unassigned', [], 'No hardening change is installed by this map.', 'Hardening application remains open.'),
      obligation('regression_verification', 'not_evidenced', 'unassigned', [], 'No lifecycle-hardening regression closure is present.', 'Regression closure remains open.'),
      obligation('equivalent_route_closure', 'not_evidenced', 'unassigned', [], 'Candidate records.write routes are not classified as equivalent or distinct.', 'Equivalent-route closure remains open.'),
    ],
    authority_topology: {
      topology_status: 'local_fixture_topology_evidenced_effect_authority_exhausted',
      fixture_rightful_issuance_path_evidenced: false,
      rightful_issuance_scope: publicGrantSummary.rightful_issuance_scope,
      public_grant_contract_sha256: terminal.public_grant_contract_sha256,
      authorization_record_id: publicGrantContract.authorization_record.record_id,
      grantor_actor_id: publicGrantContract.grantor.actor_id,
      grantor_role_id: publicGrantContract.grantor.role_id,
      grantee_actor_id: publicGrantContract.grantee.actor_id,
      issuer_slot: publicGrantContract.grantee.issuer_slot,
      power_ids: [...publicGrantPowerIds],
      valid_from_epoch: publicGrantContract.time_policy.valid_from_epoch,
      expires_at_epoch: publicGrantContract.time_policy.expires_at_epoch,
      one_use_effect_grant: publicGrantContract.usage_policy.max_uses === 1,
      replacement_requires_different_contract_sha256:
        publicGrantContract.usage_policy
          .replacement_requires_different_contract_sha256,
      generic_rightful_issuance_proven: false,
      portable_rightful_issuance_proven: false,
      live_rightful_issuance_proven: false,
      production_rightful_issuance_proven: false,
      current_machine_rightful_issuance_proven: false,
      powers: [
        authorityPower('bind_runtime_issuer_to_slot', 'fixture-deployment-owner', 'runtime-private issuer appointment to the fixture issuer slot', CONSEQUENCE_LIFECYCLE_PATH_ID, 'evidenced', ['source:payload.chain.terminal_chain.public_grant_contract.powers.0', 'source:payload.chain.terminal_chain.public_grant_contract.grantee']),
        authorityPower('issue_governed_action_receipt', 'fixture-receipt-issuer', 'one governed records.write receipt', CONSEQUENCE_LIFECYCLE_PATH_ID, 'evidenced', ['source:payload.chain.terminal_chain.public_grant_contract.powers.1', 'source:payload.chain.nested_artifacts.generated_service_proof_artifact.payload.proof.accepted_crossing_evidence.issuance_decision']),
        authorityPower('issue_replacement_authority_grant', 'fixture-deployment-owner', 'replacement authority-grant contract', CONSEQUENCE_LIFECYCLE_PATH_ID, 'evidenced', ['source:payload.chain.terminal_chain.public_grant_contract.powers.2', 'source:payload.chain.terminal_chain.public_grant_contract.usage_policy.replacement_requires_different_contract_sha256']),
        authorityPower('revoke_authority_grant', 'fixture-deployment-owner', 'fixture authority-grant contract', CONSEQUENCE_LIFECYCLE_PATH_ID, 'evidenced', ['source:payload.chain.terminal_chain.public_grant_contract.powers.3', 'source:payload.chain.nested_artifacts.generated_service_proof_artifact.payload.proof.authority_refusal_cases.3']),
        authorityPower('policy_authority', 'fixture-policy-contract', 'receipt recognition policy', CONSEQUENCE_LIFECYCLE_PATH_ID, 'evidenced', ['source:payload.chain.terminal_chain.recognition_contract_sha256']),
        authorityPower('registry_recognition_authority', 'bundled-fixture-registry', 'fixture issuer recognition', CONSEQUENCE_LIFECYCLE_PATH_ID, 'evidenced', ['source:payload.chain.terminal_chain.trusted_issuer_registry_recognition_binding']),
        authorityPower('verifier_authority', 'artifact-validator', 'structural integrity and expected artifact identity', CONSEQUENCE_LIFECYCLE_PATH_ID, 'evidenced', ['source:integrity.body_sha256', 'source:payload.chain.terminal_chain.expected_generated_service_proof_artifact_body_sha256_matched']),
        authorityPower('appeal_authority', 'unassigned', 'appeal or contest', CONSEQUENCE_LIFECYCLE_PATH_ID, 'not_evidenced'),
        authorityPower('recovery_authority', 'unassigned', 'containment compensation or memorialization', CONSEQUENCE_LIFECYCLE_PATH_ID, 'not_evidenced'),
        authorityPower('hardening_change_authority', 'unassigned', 'route or policy hardening', CONSEQUENCE_LIFECYCLE_PATH_ID, 'not_evidenced'),
      ],
    },
    receipt_integrity: {
      signature_valid_summary: registry.signature_valid === true,
      signature_valid_summary_receipt_role: registry.registry_receipt_role,
      issuer_recognized_summary: registry.recognized === true,
      issuer_recognized_summary_receipt_role: registry.registry_receipt_role,
      registry_receipt_is_boarded_service_receipt:
        registry.registry_receipt_is_boarded_service_receipt,
      registry_receipt_authorized_service_write:
        registry.registry_receipt_authorized_service_write,
      boarded_service_receipt_role: targetBinding.boarded_service_receipt_role,
      boarded_service_receipt_detail_hash_bound:
        targetBinding.receipt_binds_authorized_effect_detail,
      boarded_service_receipt_portable_cryptographic_reverification_possible: false,
      rightful_issuance_required: true,
      fixture_rightful_issuance_path_evidenced: false,
      rightful_issuance_scope: publicGrantSummary.rightful_issuance_scope,
      public_grant_contract_sha256: terminal.public_grant_contract_sha256,
      public_grant_summary_sha256: terminal.public_safe_grant_summary_sha256,
      public_grant_power_ids: [...publicGrantPowerIds],
      authority_grant_crossing_binding_sha256:
        terminal.authority_grant_crossing_binding_sha256,
      signed_payload_sha256: terminal.signed_payload_sha256,
      issuance_gate_evaluated_before_signing:
        publicGrantSummary.issuance_gate_evaluated_before_signing,
      effect_gate_evaluated_before_authority_grant_consumption:
        publicGrantSummary.effect_gate_evaluated_before_authority_grant_consumption,
      authority_grant_consumed_before_state_mutation:
        publicGrantSummary.authority_grant_consumed_before_state_mutation,
      recognition_refusal_case_count:
        terminal.observed_recognition_refusal_case_count,
      authority_refusal_case_count: terminal.observed_authority_refusal_case_count,
      generic_rightful_issuance_proven: false,
      portable_rightful_issuance_proven: false,
      live_rightful_issuance_proven: false,
      production_rightful_issuance_proven: false,
      current_machine_rightful_issuance_proven: false,
      recognition_is_rightful_issuance: false,
      evaluation_time: 'generation_time',
      artifact_integrity_verified: true,
      terminal_artifact_expected_sha256:
        CONSEQUENCE_LIFECYCLE_PINNED_TERMINAL_ARTIFACT_BODY_SHA256,
      terminal_artifact_expected_sha256_matched: true,
      embedded_service_expected_sha256:
        terminal.expected_generated_service_proof_artifact_body_sha256,
      embedded_service_expected_sha256_matched:
        terminal.expected_generated_service_proof_artifact_body_sha256_matched,
      portable_cryptographic_reverification_possible:
        receiptPath.cryptographic_evidence_reproducible_from_artifact === true,
      freshness_refusal_evidenced:
        terminal.named_receipt_refusals?.stale_or_expired?.refused_before_mutation === true,
      same_process_replay_refusal_evidenced:
        terminal.same_process_signed_payload_replay_refused === true,
      restart_replay_refusal_evidenced:
        terminal.restart_consumed_authority_grant_refused === true,
      replay_identities_separate:
        terminal.same_process_signed_payload_replay_refused === true &&
        terminal.restart_consumed_authority_grant_refused === true,
      historical_validity_implies_current_authority: false,
    },
    revocation_powers: {
      revocation_truth_proven: false,
      live_revocation_truth_proven: false,
      fixture_grant_expiry_refusal_evidenced:
        nestedServiceProof.authority_refusal_cases[2].reason_code ===
          'authority_grant_expired',
      fixture_grant_replacement_power_evidenced:
        publicGrantPowerIds.includes('issue_replacement_authority_grant') &&
        publicGrantContract.usage_policy
          .replacement_requires_different_contract_sha256 === true,
      fixture_grant_revocation_power_evidenced:
        publicGrantPowerIds.includes('revoke_authority_grant'),
      fixture_grant_revocation_refusal_evidenced:
        nestedServiceProof.authority_refusal_cases[3].reason_code ===
          'authority_grant_revoked',
      powers: [
        revocationPower('withdraw_receipt_recognition', 'receipt recognition', CONSEQUENCE_LIFECYCLE_PATH_ID, ['source:payload.chain.terminal_chain.named_receipt_refusals.stale_or_expired']),
        revocationPower('retire_issuer_key', 'issuer key', CONSEQUENCE_LIFECYCLE_PATH_ID, ['source:payload.chain.terminal_chain.recognition_refusal_groups.no_usable_recognized_receipt_authority']),
        revocationPower('mark_issuer_compromised', 'issuer status', CONSEQUENCE_LIFECYCLE_PATH_ID),
        revocationPower('withdraw_authority_grant', 'authority grant', CONSEQUENCE_LIFECYCLE_PATH_ID, ['source:payload.chain.terminal_chain.public_grant_contract.powers.3', 'source:payload.chain.nested_artifacts.generated_service_proof_artifact.payload.proof.authority_refusal_cases.3'], 'fixture-deployment-owner', 'evidenced'),
        revocationPower('decommission_route', 'consequence route', CONSEQUENCE_LIFECYCLE_PATH_ID),
        revocationPower('invalidate_policy', 'recognition policy', CONSEQUENCE_LIFECYCLE_PATH_ID, ['source:payload.chain.terminal_chain.named_receipt_refusals.wrong_policy']),
        revocationPower('close_deployment_profile', 'deployment profile', CONSEQUENCE_LIFECYCLE_PATH_ID),
        revocationPower('reject_or_supersede_hardening_rule', 'hardening rule', CONSEQUENCE_LIFECYCLE_PATH_ID),
      ],
    },
    effect_boundary: {
      recognized_write_boarded: terminal.recognized_write_boarded === true,
      protected_target_handle: targetBinding.target_handle,
      protected_target_scope: targetBinding.target_scope,
      protected_target_instance_scope: targetBinding.target_instance_scope,
      launcher_owned_target_binding_proven: true,
      profile_wide_target_authority_proven: false,
      per_run_or_physical_target_identity_proven: false,
      live_target_binding_proven: false,
      boarded_service_target_binding_sha256:
        terminal.boarded_service_target_binding_sha256,
      authority_grant_contract_sha256: terminal.public_grant_contract_sha256,
      accepted_crossing_evidence_sha256:
        terminal.accepted_crossing_evidence_sha256,
      authority_grant_crossing_binding_sha256:
        terminal.authority_grant_crossing_binding_sha256,
      signed_payload_sha256: terminal.signed_payload_sha256,
      authorized_effect_detail_sha256:
        terminal.accepted_crossing_authorized_effect_detail_sha256,
      state_effect_binding_sha256:
        terminal.accepted_crossing_state_effect_binding_sha256,
      effect_gate_before_grant_consumption_evidenced:
        publicGrantSummary.effect_gate_evaluated_before_authority_grant_consumption,
      grant_consumption_before_state_mutation_evidenced:
        publicGrantSummary.authority_grant_consumed_before_state_mutation,
      fixture_rightful_issuance_path_evidenced: false,
      generic_rightful_issuance_proven: false,
      effect_completion_beyond_fixture_boarding_proven: false,
      exactly_once_effect_semantics: chain.side_door_report.exactly_once_effect_semantics === true,
      state_append_after_grant_commit_burn_observed:
        chain.side_door_report.state_append_after_grant_commit_burn_observed,
      metadata_partial_commit_burn_observed:
        chain.side_door_report.metadata_partial_commit_burn_observed,
      store_and_anchor_rollback_refused_while_witness_ahead:
        chain.side_door_report
          .store_and_anchor_rollback_refused_while_witness_ahead,
      store_anchor_and_witness_joint_rollback_detection:
        chain.side_door_report
          .store_anchor_and_witness_joint_rollback_detection,
      joint_rollback_reopened_authority_grant_reuse:
        chain.side_door_report.joint_rollback_reopened_authority_grant_reuse,
      anti_replay_rollback_is_consequence_rollback: false,
      consequence_rollback_proven: false,
      recovery_posture: ['contain', 'compensate', 'memorialize', 'harden'],
      recovery_lifecycle_proven: false,
    },
    learning_boundary: {
      observation_creates_authority: false,
      refusal_creates_authority: false,
      hardening_proposal_creates_authority: false,
      governed_change_grant_required: true,
      hardening_authority_proven: false,
      regression_closure_proven: false,
    },
    equivalent_route_inventory: {
      inventory_status: 'open',
      selected_path_id: CONSEQUENCE_LIFECYCLE_PATH_ID,
      candidates: [
        equivalentRoute('protected-records.service-profile.records.write'),
        equivalentRoute('protected-records.runtime.records.write'),
        equivalentRoute('protected-records.runtime.profile-installation.records.write'),
        equivalentRoute('protected-records.private-operator.records-terminal.records.write'),
      ],
      live_mcp_coverage_proven: false,
      unrouted_records_paths_checked: chain.side_door_report.unrouted_records_paths_checked === true,
      closure_blocked: true,
    },
    side_doors: {
      source_boundaries_preserved: true,
      pinned_terminal_artifact_identity_preserved: true,
      embedded_service_expected_sha256_match_preserved:
        terminal.expected_generated_service_proof_artifact_body_sha256_matched,
      local_fixture_rightful_issuance_evidenced: false,
      generic_rightful_issuance_open: true,
      portable_rightful_issuance_open: true,
      live_rightful_issuance_open: true,
      production_rightful_issuance_open: true,
      current_machine_authority_identity_open: true,
      live_revocation_truth_open: true,
      consequence_recovery_open: true,
      equivalent_routes_open: true,
      state_append_burn_window_open:
        terminal.state_append_after_grant_commit_burn_observed,
      metadata_burn_window_open:
        terminal.metadata_partial_commit_burn_observed,
      joint_store_anchor_witness_rollback_open:
        terminal.joint_rollback_reopened_authority_grant_reuse,
      source_boundary_count: sourceOpenBoundaries.length,
      open_boundary_count: unique([...sourceOpenBoundaries, ...ADDITIONAL_OPEN_BOUNDARIES]).length,
      open_boundaries: unique([...sourceOpenBoundaries, ...ADDITIONAL_OPEN_BOUNDARIES]),
    },
    closure: {
      map_valid: true,
      closure_status: 'mapped_open',
      lifecycle_closed: false,
      lifecycle_governance_proven: false,
      closure_blockers: [],
    },
    claim_boundary: {
      safe_claim: CONSEQUENCE_LIFECYCLE_SAFE_CLAIM_CEILING,
      local_fixture_rightful_issuance_path: false,
      generic_rightful_issuance: false,
      portable_rightful_issuance: false,
      live_rightful_issuance: false,
      production_rightful_issuance: false,
      current_machine_rightful_issuance: false,
      production_governance: false,
      enterprise_readiness: false,
      general_current_machine_governance: false,
      public_external_attestation: false,
      all_surface_governance: false,
      revocation_truth: false,
      side_door_closure: false,
      sovereign_recognition: false,
    },
    evidence_ref_resolution: null,
    non_claims: [...NON_CLAIMS],
  };
  report.closure.closure_blockers = unique([
    ...report.lifecycle_obligations
      .filter((item) => item.blocks_closure)
      .map((item) => item.closure_blocker_id),
    ...ADDITIONAL_CLOSURE_BLOCKERS,
  ]);
  report.evidence_ref_resolution = validateEvidenceRefs(report, sourceArtifact);
  return report;
}

export function buildConsequenceLifecycleMap(sourceArtifact) {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(sourceArtifact);
  if (
    sourceArtifact.integrity.body_sha256 !==
      CONSEQUENCE_LIFECYCLE_PINNED_TERMINAL_ARTIFACT_BODY_SHA256
  ) {
    throw new Error('Consequence lifecycle map source artifact does not match the pinned terminal artifact SHA-256');
  }
  return reportFromArtifact(sourceArtifact);
}

export function assertConsequenceLifecycleMap(report, sourceArtifact) {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(sourceArtifact);
  if (
    sourceArtifact.integrity.body_sha256 !==
      CONSEQUENCE_LIFECYCLE_PINNED_TERMINAL_ARTIFACT_BODY_SHA256
  ) {
    throw new Error('Consequence lifecycle map source artifact does not match the pinned terminal artifact SHA-256');
  }
  assertExactKeys('Consequence lifecycle map', report, [
    'report_type',
    'map_version',
    'map_status',
    'safe_claim_ceiling',
    'authority_domain',
    'consequence_path',
    'source_evidence',
    'path_definition',
    'observed_traces',
    'lifecycle_obligations',
    'authority_topology',
    'receipt_integrity',
    'revocation_powers',
    'effect_boundary',
    'learning_boundary',
    'equivalent_route_inventory',
    'side_doors',
    'closure',
    'claim_boundary',
    'evidence_ref_resolution',
    'non_claims',
  ]);

  if (report.report_type !== CONSEQUENCE_LIFECYCLE_MAP_TYPE ||
      report.map_version !== CONSEQUENCE_LIFECYCLE_MAP_VERSION ||
      report.map_status !== 'mapped_open') {
    throw new Error('Consequence lifecycle map identity must remain v0 mapped_open');
  }
  if (report.closure?.closure_status !== 'mapped_open' ||
      report.closure?.lifecycle_closed !== false ||
      report.closure?.lifecycle_governance_proven !== false) {
    throw new Error('Consequence lifecycle map v0 must not claim lifecycle closure');
  }
  if (
    report.consequence_path?.protected_target_binding_proven !== true ||
    report.consequence_path?.launcher_owned_target_binding_proven !== true ||
    !/^zlar-target:v1:logical-fixture:[a-f0-9]{64}$/.test(
      report.consequence_path?.protected_target_handle || ''
    ) ||
    report.consequence_path?.protected_target_scope !== 'logical-fixture' ||
    report.consequence_path?.protected_target_instance_scope !==
      'logical-fixture-not-per-run' ||
    report.consequence_path?.profile_wide_target_authority_proven !== false ||
    report.consequence_path?.per_run_or_physical_target_identity_proven !== false ||
    report.consequence_path?.live_target_binding_proven !== false ||
    report.consequence_path?.checkpoint !== CHECKPOINT_ID ||
    report.consequence_path?.fixture_rightful_issuance_path_evidenced !== false ||
    report.consequence_path?.generic_rightful_issuance_proven !== false ||
    report.consequence_path?.registry_receipt_is_boarded_service_receipt !== false ||
    !/^[a-f0-9]{64}$/.test(
      report.consequence_path?.protected_target_binding_sha256 || ''
    )
  ) {
    throw new Error('Consequence lifecycle map protected target boundary drifted');
  }
  if (
    report.source_evidence?.expected_artifact_body_sha256 !==
      CONSEQUENCE_LIFECYCLE_PINNED_TERMINAL_ARTIFACT_BODY_SHA256 ||
    report.source_evidence?.expected_artifact_body_sha256_matched !== true ||
    report.source_evidence?.artifact_structural_self_integrity_verified !== true ||
    report.source_evidence?.artifact_identity_match_requires_expected_sha256 !== true ||
    report.source_evidence?.embedded_service_expected_sha256_matched !== true ||
    report.source_evidence?.evidence_ref_resolution_model !==
      'exact-own-property-path-v1'
  ) {
    throw new Error('Consequence lifecycle map pinned source evidence drifted');
  }
  if (
    report.path_definition?.evidence_status !== 'artifact_projected_open' ||
    report.path_definition?.source_artifact_bound !== true ||
    report.path_definition?.source_commit_bound !== false ||
    report.path_definition?.checkpoint_route !== CHECKPOINT_ID
  ) {
    throw new Error('Consequence lifecycle map exact route projection drifted');
  }
  if (
    report.source_evidence?.receipt_roles_distinct !== true ||
    report.receipt_integrity?.registry_receipt_is_boarded_service_receipt !== false ||
    report.receipt_integrity?.registry_receipt_authorized_service_write !== false ||
    report.receipt_integrity?.signature_valid_summary_receipt_role !==
      'synthetic-registry-recognition-evidence-receipt' ||
    report.receipt_integrity?.issuer_recognized_summary_receipt_role !==
      'synthetic-registry-recognition-evidence-receipt' ||
    report.receipt_integrity?.boarded_service_receipt_role !==
      'boarded-service-write-authority-receipt' ||
    report.receipt_integrity?.boarded_service_receipt_detail_hash_bound !== true ||
    report.receipt_integrity
      ?.boarded_service_receipt_portable_cryptographic_reverification_possible !== false
  ) {
    throw new Error('Consequence lifecycle map receipt-role boundary drifted');
  }
  if (
    report.effect_boundary?.launcher_owned_target_binding_proven !== true ||
    report.effect_boundary?.profile_wide_target_authority_proven !== false ||
    report.effect_boundary?.per_run_or_physical_target_identity_proven !== false ||
    report.effect_boundary?.live_target_binding_proven !== false ||
    report.effect_boundary?.fixture_rightful_issuance_path_evidenced !== false ||
    report.effect_boundary?.generic_rightful_issuance_proven !== false ||
    report.effect_boundary?.effect_gate_before_grant_consumption_evidenced !== true ||
    report.effect_boundary?.grant_consumption_before_state_mutation_evidenced !== true ||
    report.effect_boundary?.state_append_after_grant_commit_burn_observed !== true ||
    report.effect_boundary?.metadata_partial_commit_burn_observed !== true ||
    report.effect_boundary?.store_and_anchor_rollback_refused_while_witness_ahead !== true ||
    report.effect_boundary?.store_anchor_and_witness_joint_rollback_detection !== false ||
    report.effect_boundary?.joint_rollback_reopened_authority_grant_reuse !== true
  ) {
    throw new Error('Consequence lifecycle map effect target boundary drifted');
  }
  if (
    report.authority_topology?.topology_status !==
      'local_fixture_topology_evidenced_effect_authority_exhausted' ||
    report.authority_topology?.fixture_rightful_issuance_path_evidenced !== false ||
    report.authority_topology?.generic_rightful_issuance_proven !== false ||
    report.authority_topology?.portable_rightful_issuance_proven !== false ||
    report.authority_topology?.live_rightful_issuance_proven !== false ||
    report.authority_topology?.production_rightful_issuance_proven !== false ||
    report.authority_topology?.current_machine_rightful_issuance_proven !== false ||
    JSON.stringify(report.authority_topology?.power_ids) !==
      JSON.stringify([
        'bind_runtime_issuer_to_slot',
        'issue_governed_action_receipt',
        'issue_replacement_authority_grant',
        'revoke_authority_grant',
      ])
  ) {
    throw new Error('Consequence lifecycle map local-fixture authority topology drifted');
  }
  if (
    report.receipt_integrity?.fixture_rightful_issuance_path_evidenced !== false ||
    report.receipt_integrity?.generic_rightful_issuance_proven !== false ||
    report.receipt_integrity?.portable_rightful_issuance_proven !== false ||
    report.receipt_integrity?.live_rightful_issuance_proven !== false ||
    report.receipt_integrity?.production_rightful_issuance_proven !== false ||
    report.receipt_integrity?.current_machine_rightful_issuance_proven !== false ||
    report.receipt_integrity?.recognition_is_rightful_issuance !== false ||
    report.receipt_integrity?.recognition_refusal_case_count !== 18 ||
    report.receipt_integrity?.authority_refusal_case_count !== 5 ||
    report.receipt_integrity?.same_process_replay_refusal_evidenced !== true ||
    report.receipt_integrity?.restart_replay_refusal_evidenced !== true ||
    report.receipt_integrity?.replay_identities_separate !== true
  ) {
    throw new Error('Consequence lifecycle map local-fixture rightful-issuance boundary drifted');
  }
  if (report.receipt_integrity?.portable_cryptographic_reverification_possible !== false) {
    throw new Error('Consequence lifecycle map v0 must preserve the portable cryptographic re-verification boundary');
  }
  if (report.effect_boundary?.consequence_rollback_proven !== false ||
      report.effect_boundary?.anti_replay_rollback_is_consequence_rollback !== false) {
    throw new Error('Consequence lifecycle map v0 must not launder replay-store rollback into consequence rollback');
  }
  if (report.learning_boundary?.observation_creates_authority !== false ||
      report.learning_boundary?.refusal_creates_authority !== false ||
      report.learning_boundary?.hardening_proposal_creates_authority !== false) {
    throw new Error('Consequence lifecycle map v0 observations and hardening proposals must not create authority');
  }
  if (
    report.revocation_powers?.revocation_truth_proven !== false ||
    report.revocation_powers?.live_revocation_truth_proven !== false ||
    report.revocation_powers?.fixture_grant_expiry_refusal_evidenced !== true ||
    report.revocation_powers?.fixture_grant_replacement_power_evidenced !== true ||
    report.revocation_powers?.fixture_grant_revocation_power_evidenced !== true ||
    report.revocation_powers?.fixture_grant_revocation_refusal_evidenced !== true
  ) {
    throw new Error('Consequence lifecycle map v0 must keep revocation truth unproven');
  }
  const revocationIds = report.revocation_powers?.powers?.map((power) => power.power_id);
  assertExactArray('Consequence lifecycle revocation powers', revocationIds, REQUIRED_REVOCATION_POWER_IDS);
  if (
    report.side_doors?.source_boundaries_preserved !== true ||
    report.side_doors?.pinned_terminal_artifact_identity_preserved !== true ||
    report.side_doors?.embedded_service_expected_sha256_match_preserved !== true ||
    report.side_doors?.local_fixture_rightful_issuance_evidenced !== false ||
    report.side_doors?.generic_rightful_issuance_open !== true ||
    report.side_doors?.portable_rightful_issuance_open !== true ||
    report.side_doors?.live_rightful_issuance_open !== true ||
    report.side_doors?.production_rightful_issuance_open !== true ||
    report.side_doors?.current_machine_authority_identity_open !== true ||
    report.side_doors?.live_revocation_truth_open !== true ||
    report.side_doors?.consequence_recovery_open !== true ||
    report.side_doors?.equivalent_routes_open !== true ||
    report.side_doors?.state_append_burn_window_open !== true ||
    report.side_doors?.metadata_burn_window_open !== true ||
    report.side_doors?.joint_store_anchor_witness_rollback_open !== true
  ) {
    throw new Error('Consequence lifecycle map v0 must preserve source side doors');
  }
  for (const boundary of sourceArtifact.payload.chain.known_open_boundaries) {
    if (!report.side_doors.open_boundaries.includes(boundary)) {
      throw new Error(`Consequence lifecycle map v0 hides source boundary: ${boundary}`);
    }
  }
  for (const item of report.lifecycle_obligations) {
    const shouldBlock = item.status !== 'evidenced' && item.status !== 'not_applicable_with_reason';
    if (item.blocks_closure !== shouldBlock) {
      throw new Error(`Consequence lifecycle obligation closure posture drifted: ${item.obligation_id}`);
    }
    if (shouldBlock &&
        (typeof item.closure_blocker_id !== 'string' ||
         !report.closure.closure_blockers.includes(item.closure_blocker_id))) {
      throw new Error(`Consequence lifecycle closure blocker missing for obligation: ${item.obligation_id}`);
    }
    if (!shouldBlock && item.closure_blocker_id !== null) {
      throw new Error(`Consequence lifecycle evidenced obligation cannot carry a closure blocker: ${item.obligation_id}`);
    }
  }
  const obligationCounts = {
    evidenced: report.lifecycle_obligations.filter((item) => item.status === 'evidenced').length,
    open: report.lifecycle_obligations.filter((item) => item.status === 'not_evidenced').length,
    outside: report.lifecycle_obligations.filter((item) => item.status === 'outside_coverage').length,
  };
  if (
    obligationCounts.evidenced !== 12 ||
    obligationCounts.open !== 8 ||
    obligationCounts.outside !== 2
  ) {
    throw new Error('Consequence lifecycle map obligation counts drifted');
  }
  const requiredIdentityBlockers = [
    'local_fixture_rightful_issuance_not_evidenced',
    'current_fixture_authority_grant_exhausted',
    'repeated_use_fixture_provenance_invalid',
    'generic_rightful_issuance_outside_local_fixture_scope',
    'portable_authority_identity_unproven',
    'live_authority_identity_unproven',
    'production_authority_identity_unproven',
    'current_machine_authority_identity_unproven',
  ];
  if (
    report.closure.closure_blockers.includes('rightful_issuance_unproven') ||
    requiredIdentityBlockers.some((item) =>
      !report.closure.closure_blockers.includes(item)
    )
  ) {
    throw new Error('Consequence lifecycle map rightful-issuance blocker precision drifted');
  }
  if (report.claim_boundary?.local_fixture_rightful_issuance_path !== false) {
    throw new Error('Consequence lifecycle map must keep exhausted local-fixture rightful issuance false');
  }
  for (const field of [
    'generic_rightful_issuance',
    'portable_rightful_issuance',
    'live_rightful_issuance',
    'production_rightful_issuance',
    'current_machine_rightful_issuance',
    'production_governance',
    'enterprise_readiness',
    'general_current_machine_governance',
    'public_external_attestation',
    'all_surface_governance',
    'revocation_truth',
    'side_door_closure',
    'sovereign_recognition',
  ]) {
    if (report.claim_boundary?.[field] !== false) {
      throw new Error(`Consequence lifecycle map v0 forbidden claim must remain false: ${field}`);
    }
  }

  const evidenceRefResolution = validateEvidenceRefs(report, sourceArtifact);
  if (
    JSON.stringify(report.evidence_ref_resolution) !==
      JSON.stringify(evidenceRefResolution)
  ) {
    throw new Error('Consequence lifecycle map evidence reference resolution drifted');
  }

  const expected = reportFromArtifact(sourceArtifact);
  if (JSON.stringify(report) !== JSON.stringify(expected)) {
    throw new Error('Consequence lifecycle map does not match the canonical artifact-bound projection');
  }
  return true;
}

export function formatConsequenceLifecycleMapSummary(report) {
  assertObject('Consequence lifecycle map summary input', report);
  const evidenced = report.lifecycle_obligations.filter((item) => item.status === 'evidenced').length;
  const refused = report.observed_traces.filter((item) => item.evidence_status === 'refused')
    .reduce((sum, item) => sum + item.refusal_case_count, 0);
  const open = report.lifecycle_obligations.filter((item) => item.status === 'not_evidenced').length;
  const outside = report.lifecycle_obligations.filter((item) => item.status === 'outside_coverage').length;
  return [
    `Consequence lifecycle map: ${report.map_status}`,
    `Path: ${report.consequence_path.path_id}`,
    `Protected target: handle=${report.consequence_path.protected_target_handle}; scope=${report.consequence_path.protected_target_scope}; binding_proven=${report.consequence_path.protected_target_binding_proven}; profile_wide_authority=${report.consequence_path.profile_wide_target_authority_proven}; per_run_or_physical_identity=${report.consequence_path.per_run_or_physical_target_identity_proven}; live_target=${report.consequence_path.live_target_binding_proven}`,
    `Route: checkpoint=${report.consequence_path.checkpoint}; local_fixture_rightful_issuance=${report.consequence_path.fixture_rightful_issuance_path_evidenced}`,
    `Evidence: artifact=${report.source_evidence.artifact_type}; body_sha256=${report.source_evidence.artifact_body_sha256}; expected_sha256_matched=${report.source_evidence.expected_artifact_body_sha256_matched}; embedded_service_expected_sha256_matched=${report.source_evidence.embedded_service_expected_sha256_matched}`,
    `Authority: contract_sha256=${report.authority_topology.public_grant_contract_sha256}; power_ids=${report.authority_topology.power_ids.join(',')}; generic_rightful_issuance=${report.authority_topology.generic_rightful_issuance_proven}`,
    `Obligations: evidenced=${evidenced}; open=${open}; outside_coverage=${outside}`,
    `Observed refusals before mutation: ${refused}`,
    `Evidence refs: resolved=${report.evidence_ref_resolution.all_references_resolved}; total=${report.evidence_ref_resolution.total_reference_count}`,
    `Lifecycle closed: ${report.closure.lifecycle_closed}`,
    `Closure blockers: ${report.closure.closure_blockers.join(', ')}`,
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Projection SHA-256: ${consequenceLifecycleMapSha256(report)}`,
  ].join('\n');
}

export function consequenceLifecycleMapSha256(report) {
  assertObject('Consequence lifecycle map hash input', report);
  return createHash('sha256').update(JSON.stringify(report)).digest('hex');
}

export function assertNoUnsafeConsequenceLifecycleText(value) {
  const text = String(value);
  const unsafe = [
    { label: 'private operator path', pattern: /\/Users\/[A-Za-z0-9._-]+\// },
    { label: 'home path', pattern: /\/home\/[A-Za-z0-9._-]+\// },
    { label: 'credential value', pattern: /\b(?:token|secret|password|api[_-]?key)\s*[:=]\s*[^\s,;]+/i },
    { label: 'broad all-actions claim', pattern: /\bZLAR governs all (?:AI|actions|agents)\b/i },
    { label: 'closed lifecycle claim', pattern: /"lifecycle_closed"\s*:\s*true/i },
  ];
  for (const item of unsafe) {
    if (item.pattern.test(text)) {
      throw new Error(`Unsafe consequence lifecycle output: ${item.label}`);
    }
  }
  return true;
}

export const CONSEQUENCE_LIFECYCLE_SOURCE_ARTIFACT_TYPE =
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_TYPE;
