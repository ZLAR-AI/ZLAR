#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import {
  CONSEQUENCE_LIFECYCLE_MAP_TYPE,
  CONSEQUENCE_LIFECYCLE_MAP_VERSION,
  CONSEQUENCE_LIFECYCLE_PINNED_TERMINAL_ARTIFACT_BODY_SHA256,
  CONSEQUENCE_LIFECYCLE_PATH_ID,
  CONSEQUENCE_LIFECYCLE_SAFE_CLAIM_CEILING,
  REQUIRED_REVOCATION_POWER_IDS,
  assertConsequenceLifecycleMap,
  assertNoUnsafeConsequenceLifecycleText,
  buildConsequenceLifecycleMap,
  consequenceLifecycleMapSha256,
  formatConsequenceLifecycleMapSummary,
} from '../lib/consequence-lifecycle-map.mjs';

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

function section(title) {
  console.log(`\n-- ${title} --`);
}

const PROJECT_DIR = process.cwd();
const ZLAR_BIN = join(PROJECT_DIR, 'bin', 'zlar');
const ARTIFACT_PATH = join(
  PROJECT_DIR,
  'tests',
  'fixtures',
  'protected-records-installed-runtime-profile-terminal-chain-artifact-v1.json'
);
const ARTIFACT_TEXT = readFileSync(ARTIFACT_PATH, 'utf8');
const ARTIFACT = JSON.parse(ARTIFACT_TEXT);

section('canonical mapped-open projection');

const report = buildConsequenceLifecycleMap(ARTIFACT);
assert('canonical map passes strict validation', assertConsequenceLifecycleMap(report, ARTIFACT));
assertEqual('map type', CONSEQUENCE_LIFECYCLE_MAP_TYPE, report.report_type);
assertEqual('map version', CONSEQUENCE_LIFECYCLE_MAP_VERSION, report.map_version);
assertEqual('map status remains mapped_open', 'mapped_open', report.map_status);
assertEqual('safe claim ceiling exact', CONSEQUENCE_LIFECYCLE_SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('exact terminal path', CONSEQUENCE_LIFECYCLE_PATH_ID, report.consequence_path.path_id);
assertEqual('action class', 'records.write', report.consequence_path.action_class);
assertEqual('protected target kind', 'process-private-recognized-effect-state', report.consequence_path.protected_target);
assertEqual('protected target handle', ARTIFACT.payload.chain.terminal_chain.boarded_service_target_binding.target_handle, report.consequence_path.protected_target_handle);
assertEqual('protected target scope', 'logical-fixture', report.consequence_path.protected_target_scope);
assertEqual('protected target is not per-run', 'logical-fixture-not-per-run', report.consequence_path.protected_target_instance_scope);
assertEqual('protected target binding sha', ARTIFACT.payload.chain.terminal_chain.boarded_service_target_binding_sha256, report.consequence_path.protected_target_binding_sha256);
assert('launcher-owned logical target binding proven', report.consequence_path.protected_target_binding_proven && report.consequence_path.launcher_owned_target_binding_proven);
assert('profile-wide target authority unproven', report.consequence_path.profile_wide_target_authority_proven === false);
assert('per-run or physical target identity unproven', report.consequence_path.per_run_or_physical_target_identity_proven === false);
assert('live target binding unproven', report.consequence_path.live_target_binding_proven === false);
assertEqual('target metadata is post-effect only', 'post-effect-hash-bound-metadata-only', report.consequence_path.target_binding_metadata_role);
assert('registry receipt is not boarded service receipt', report.consequence_path.registry_receipt_is_boarded_service_receipt === false);
assertEqual('checkpoint', 'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation', report.consequence_path.checkpoint);
assert('exhausted local-fixture rightful path remains open', report.consequence_path.fixture_rightful_issuance_path_evidenced === false);
assert('generic rightful issuance remains false', report.consequence_path.generic_rightful_issuance_proven === false);
assert('exact path evidence bound', report.consequence_path.exact_path_evidence_bound);
assertEqual('source artifact body sha', ARTIFACT.integrity.body_sha256, report.source_evidence.artifact_body_sha256);
assertEqual('source artifact exact pin', CONSEQUENCE_LIFECYCLE_PINNED_TERMINAL_ARTIFACT_BODY_SHA256, report.source_evidence.expected_artifact_body_sha256);
assert('source artifact exact pin matched', report.source_evidence.expected_artifact_body_sha256_matched === true);
assert('source artifact structural self-integrity verified', report.source_evidence.artifact_structural_self_integrity_verified === true);
assert('source identity requires exact expected sha', report.source_evidence.artifact_identity_match_requires_expected_sha256 === true);
assert('embedded service exact sha matched', report.source_evidence.embedded_service_expected_sha256_matched === true);
assertEqual('source commit absent', null, report.source_evidence.source_commit);
assert('source commit unbound', report.source_evidence.source_commit_bound === false);
assertEqual('path definition is branching DAG', 'branching_dag', report.path_definition.graph_type);
assertEqual('path graph is artifact projected open', 'artifact_projected_open', report.path_definition.evidence_status);
assert('path graph is artifact bound', report.path_definition.source_artifact_bound === true);
assert('path graph source commit is unbound', report.path_definition.source_commit_bound === false);
assert('path graph sha is present', /^[a-f0-9]{64}$/.test(report.path_definition.graph_sha256));
assert('linear lifecycle trace not claimed', report.path_definition.linear_lifecycle_trace_claimed === false);
assertEqual('three observed branch traces', 3, report.observed_traces.length);
assertEqual('recognized branch boards', 'boarded', report.observed_traces[0].outcome);
assertEqual('refusal branch refuses before mutation', 'refused_before_mutation', report.observed_traces[1].outcome);
assertEqual('all terminal refusal cases carried', 18, report.observed_traces[1].refusal_case_count);
assert('refusal branch does not continue', report.observed_traces[1].continued_after_refusal === false);
assertEqual('authority refusal branch refuses before consumption', 'refused_before_consumption_and_mutation', report.observed_traces[2].outcome);
assertEqual('all authority refusal cases carried', 5, report.observed_traces[2].refusal_case_count);
assertEqual('path identity obligation evidenced', 'evidenced', report.lifecycle_obligations.find((item) => item.obligation_id === 'path_identity').status);
const targetObligation = report.lifecycle_obligations.find((item) => item.obligation_id === 'protected_target_binding');
assertEqual('protected target obligation evidenced', 'evidenced', targetObligation.status);
assertEqual('protected target obligation launcher authority', 'launcher-owned-fixture-service-config', targetObligation.authority_id);
assert('protected target obligation carries source evidence', targetObligation.evidence_refs.every((ref) => ref.startsWith('source:payload.chain.terminal_chain.boarded_service_target_binding')));
assert('protected target obligation does not block closure', targetObligation.blocks_closure === false && targetObligation.closure_blocker_id === null);
assertEqual('lifecycle graph obligation evidenced', 'evidenced', report.lifecycle_obligations.find((item) => item.obligation_id === 'lifecycle_graph_definition').status);
assertEqual('authority topology obligation evidenced', 'evidenced', report.lifecycle_obligations.find((item) => item.obligation_id === 'authority_topology').status);
assertEqual('local fixture rightful issuance obligation open', 'not_evidenced', report.lifecycle_obligations.find((item) => item.obligation_id === 'local_fixture_rightful_issuance').status);
assertEqual('fixture expiry or supersession obligation evidenced', 'evidenced', report.lifecycle_obligations.find((item) => item.obligation_id === 'expiry_or_supersession').status);
assertEqual('twelve evidenced obligations', 12, report.lifecycle_obligations.filter((item) => item.status === 'evidenced').length);
assertEqual('eight open obligations', 8, report.lifecycle_obligations.filter((item) => item.status === 'not_evidenced').length);
assertEqual('two outside-coverage obligations', 2, report.lifecycle_obligations.filter((item) => item.status === 'outside_coverage').length);
assert('rightful issuance required', report.receipt_integrity.rightful_issuance_required);
assert('local fixture rightful issuance remains false', report.receipt_integrity.fixture_rightful_issuance_path_evidenced === false);
assert('generic rightful issuance unproven', report.receipt_integrity.generic_rightful_issuance_proven === false);
assert('portable rightful issuance unproven', report.receipt_integrity.portable_rightful_issuance_proven === false);
assert('recognition not treated as rightful issuance', report.receipt_integrity.recognition_is_rightful_issuance === false);
assert('signature summary present', report.receipt_integrity.signature_valid_summary);
assertEqual('signature summary belongs to registry evidence receipt', 'synthetic-registry-recognition-evidence-receipt', report.receipt_integrity.signature_valid_summary_receipt_role);
assert('issuer-recognition summary present', report.receipt_integrity.issuer_recognized_summary);
assertEqual('issuer-recognition summary belongs to registry evidence receipt', 'synthetic-registry-recognition-evidence-receipt', report.receipt_integrity.issuer_recognized_summary_receipt_role);
assert('registry receipt did not board', report.receipt_integrity.registry_receipt_is_boarded_service_receipt === false);
assert('registry receipt did not authorize service write', report.receipt_integrity.registry_receipt_authorized_service_write === false);
assertEqual('boarded receipt role explicit', 'boarded-service-write-authority-receipt', report.receipt_integrity.boarded_service_receipt_role);
assert('boarded receipt detail hash bound', report.receipt_integrity.boarded_service_receipt_detail_hash_bound);
assert('boarded receipt not portably reverified', report.receipt_integrity.boarded_service_receipt_portable_cryptographic_reverification_possible === false);
assert('portable cryptographic re-verification remains unavailable', report.receipt_integrity.portable_cryptographic_reverification_possible === false);
assert('stale refusal evidenced', report.receipt_integrity.freshness_refusal_evidenced);
assert('same-process replay refusal evidenced', report.receipt_integrity.same_process_replay_refusal_evidenced);
assert('restart replay refusal evidenced', report.receipt_integrity.restart_replay_refusal_evidenced);
assert('historical validity does not imply current authority', report.receipt_integrity.historical_validity_implies_current_authority === false);
assertEqual('receipt integrity carries 18 recognition refusals', 18, report.receipt_integrity.recognition_refusal_case_count);
assertEqual('receipt integrity carries 5 authority refusals', 5, report.receipt_integrity.authority_refusal_case_count);
assert('replay identities remain separate', report.receipt_integrity.replay_identities_separate === true);
assertEqual('authority topology exact public contract sha', ARTIFACT.payload.chain.terminal_chain.public_grant_contract_sha256, report.authority_topology.public_grant_contract_sha256);
assertEqual('authority topology exact powers', 'bind_runtime_issuer_to_slot,issue_governed_action_receipt,issue_replacement_authority_grant,revoke_authority_grant', report.authority_topology.power_ids.join(','));
assert('authority topology does not restore exhausted effect authority', report.authority_topology.fixture_rightful_issuance_path_evidenced === false);
assert('authority topology generic rightful remains false', report.authority_topology.generic_rightful_issuance_proven === false);
assertEqual('revocation powers split', REQUIRED_REVOCATION_POWER_IDS.join(','), report.revocation_powers.powers.map((item) => item.power_id).join(','));
assert('revocation truth unproven', report.revocation_powers.revocation_truth_proven === false);
assert('live revocation truth unproven', report.revocation_powers.live_revocation_truth_proven === false);
assert('fixture grant expiry refusal evidenced', report.revocation_powers.fixture_grant_expiry_refusal_evidenced === true);
assert('fixture grant replacement power evidenced', report.revocation_powers.fixture_grant_replacement_power_evidenced === true);
assert('fixture grant revocation power evidenced', report.revocation_powers.fixture_grant_revocation_power_evidenced === true);
assert('fixture grant revoked refusal evidenced', report.revocation_powers.fixture_grant_revocation_refusal_evidenced === true);
assert('effect boarding carried', report.effect_boundary.recognized_write_boarded);
assertEqual('effect target handle carried', report.consequence_path.protected_target_handle, report.effect_boundary.protected_target_handle);
assert('effect launcher target binding proven', report.effect_boundary.launcher_owned_target_binding_proven);
assert('effect profile-wide target authority false', report.effect_boundary.profile_wide_target_authority_proven === false);
assert('effect per-run target identity false', report.effect_boundary.per_run_or_physical_target_identity_proven === false);
assert('effect live target false', report.effect_boundary.live_target_binding_proven === false);
assert('exactly-once remains false', report.effect_boundary.exactly_once_effect_semantics === false);
assert('state append burn window preserved', report.effect_boundary.state_append_after_grant_commit_burn_observed === true);
assert('metadata burn window preserved', report.effect_boundary.metadata_partial_commit_burn_observed === true);
assert('joint rollback side door remains open', report.effect_boundary.joint_rollback_reopened_authority_grant_reuse === true && report.effect_boundary.store_anchor_and_witness_joint_rollback_detection === false);
assert('anti-replay rollback not consequence rollback', report.effect_boundary.anti_replay_rollback_is_consequence_rollback === false);
assert('consequence rollback unproven', report.effect_boundary.consequence_rollback_proven === false);
assert('recovery lifecycle unproven', report.effect_boundary.recovery_lifecycle_proven === false);
assert('observation does not create authority', report.learning_boundary.observation_creates_authority === false);
assert('refusal does not create authority', report.learning_boundary.refusal_creates_authority === false);
assert('hardening proposal does not create authority', report.learning_boundary.hardening_proposal_creates_authority === false);
assert('governed change grant remains required', report.learning_boundary.governed_change_grant_required);
assertEqual('equivalent-route inventory open', 'open', report.equivalent_route_inventory.inventory_status);
assert('all candidate route relationships unknown', report.equivalent_route_inventory.candidates.every((item) => item.relationship === 'unknown' && item.parity_proven === false));
assert('equivalent-route inventory blocks closure', report.equivalent_route_inventory.closure_blocked);
assert('source boundaries preserved', report.side_doors.source_boundaries_preserved);
assert('pinned terminal identity preserved', report.side_doors.pinned_terminal_artifact_identity_preserved === true);
assert('exhausted fixture and generic side doors remain open', report.side_doors.local_fixture_rightful_issuance_evidenced === false && report.side_doors.generic_rightful_issuance_open === true && report.side_doors.live_rightful_issuance_open === true);
assert('source side doors are a subset', ARTIFACT.payload.chain.known_open_boundaries.every((item) => report.side_doors.open_boundaries.includes(item)));
assert('active-persistent evidence is not referenced', !JSON.stringify(report).includes('active-persistent-current-machine'));
assertEqual('closure status mapped_open', 'mapped_open', report.closure.closure_status);
assert('lifecycle closed remains false', report.closure.lifecycle_closed === false);
assert('lifecycle governance remains false', report.closure.lifecycle_governance_proven === false);
assert('closure blockers named', report.closure.closure_blockers.length >= 10);
assert('every open obligation names a closure blocker', report.lifecycle_obligations
  .filter((item) => item.status !== 'evidenced' && item.status !== 'not_applicable_with_reason')
  .every((item) => item.blocks_closure === true && report.closure.closure_blockers.includes(item.closure_blocker_id)));
assert('evidenced obligations carry no closure blocker', report.lifecycle_obligations
  .filter((item) => item.status === 'evidenced')
  .every((item) => item.blocks_closure === false && item.closure_blocker_id === null));
assert('path closeout blocker named', report.closure.closure_blockers.includes('path_closeout_not_evidenced'));
assert('expiry blocker removed by exact fixture evidence', !report.closure.closure_blockers.includes('expiry_or_supersession_not_evidenced'));
assert('learning boundary blocker named', report.closure.closure_blockers.includes('learning_outside_coverage'));
assert('old generic target blocker removed', !report.closure.closure_blockers.includes('protected_target_binding_missing'));
assert('profile-wide target authority blocker remains', report.closure.closure_blockers.includes('profile_wide_target_authority_unproven'));
assert('per-run or physical target blocker remains', report.closure.closure_blockers.includes('per_run_or_physical_target_identity_unproven'));
assert('live target blocker remains', report.closure.closure_blockers.includes('live_target_binding_unproven'));
assert('obsolete rightful issuance blocker removed', !report.closure.closure_blockers.includes('rightful_issuance_unproven'));
assert('local fixture rightful issuance blocker named', report.closure.closure_blockers.includes('local_fixture_rightful_issuance_not_evidenced'));
assert('exhausted grant blocker named', report.closure.closure_blockers.includes('current_fixture_authority_grant_exhausted'));
assert('repeated-use provenance blocker named', report.closure.closure_blockers.includes('repeated_use_fixture_provenance_invalid'));
assert('portable authority identity blocker remains', report.closure.closure_blockers.includes('portable_authority_identity_unproven'));
assert('live authority identity blocker remains', report.closure.closure_blockers.includes('live_authority_identity_unproven'));
assert('production governance false', report.claim_boundary.production_governance === false);
assert('enterprise readiness false', report.claim_boundary.enterprise_readiness === false);
assert('general current-machine governance false', report.claim_boundary.general_current_machine_governance === false);
assert('public external attestation false', report.claim_boundary.public_external_attestation === false);
assert('all-surface governance false', report.claim_boundary.all_surface_governance === false);
assert('side-door closure false', report.claim_boundary.side_door_closure === false);
assert('claim boundary keeps local and broader rightful issuance false', report.claim_boundary.local_fixture_rightful_issuance_path === false && report.claim_boundary.generic_rightful_issuance === false && report.claim_boundary.live_rightful_issuance === false);
assertEqual('all evidence references resolve', true, report.evidence_ref_resolution.all_references_resolved);
assertEqual('evidence reference resolution model exact', 'exact-own-property-path-v1', report.evidence_ref_resolution.resolution_model);
assertEqual('evidence refs all source-backed', report.evidence_ref_resolution.total_reference_count, report.evidence_ref_resolution.source_reference_count);
assertEqual('map projection hash is sha256', 64, consequenceLifecycleMapSha256(report).length);

const summary = formatConsequenceLifecycleMapSummary(report);
assert('summary names mapped_open', summary.includes('Consequence lifecycle map: mapped_open'));
assert('summary names lifecycle false', summary.includes('Lifecycle closed: false'));
assert('summary names exact path', summary.includes(CONSEQUENCE_LIFECYCLE_PATH_ID));
assert('summary names protected target binding', summary.includes('binding_proven=true'));
assert('summary keeps profile-wide target authority false', summary.includes('profile_wide_authority=false'));
assert('summary names exhausted local fixture rightful issuance false', summary.includes('local_fixture_rightful_issuance=false'));
assert('summary names pinned terminal identity match', summary.includes('expected_sha256_matched=true'));
assert('summary names evidence ref resolution', summary.includes('Evidence refs: resolved=true'));
assert('summary names projection hash', summary.includes('Projection SHA-256:'));
assert('summary is privacy safe', assertNoUnsafeConsequenceLifecycleText(summary));
assert('json is privacy safe', assertNoUnsafeConsequenceLifecycleText(JSON.stringify(report)));

section('fail closed on evidence laundering and claim upgrades');

const closed = clone(report);
closed.closure.lifecycle_closed = true;
assertThrows('lifecycle closure upgrade refused', () => assertConsequenceLifecycleMap(closed, ARTIFACT), 'must not claim lifecycle closure');

const closureStatus = clone(report);
closureStatus.closure.closure_status = 'closed';
assertThrows('closed status refused', () => assertConsequenceLifecycleMap(closureStatus, ARTIFACT), 'must not claim lifecycle closure');

const targetBindingRemoved = clone(report);
targetBindingRemoved.consequence_path.protected_target_binding_proven = false;
assertThrows('protected target binding removal refused', () => assertConsequenceLifecycleMap(targetBindingRemoved, ARTIFACT), 'protected target boundary drifted');

const profileTargetAuthority = clone(report);
profileTargetAuthority.consequence_path.profile_wide_target_authority_proven = true;
assertThrows('profile-wide target authority upgrade refused', () => assertConsequenceLifecycleMap(profileTargetAuthority, ARTIFACT), 'protected target boundary drifted');

const physicalTargetIdentity = clone(report);
physicalTargetIdentity.consequence_path.per_run_or_physical_target_identity_proven = true;
assertThrows('per-run or physical target identity upgrade refused', () => assertConsequenceLifecycleMap(physicalTargetIdentity, ARTIFACT), 'protected target boundary drifted');

const registryReceiptBoards = clone(report);
registryReceiptBoards.receipt_integrity.registry_receipt_is_boarded_service_receipt = true;
assertThrows('registry receipt boarding role laundering refused', () => assertConsequenceLifecycleMap(registryReceiptBoards, ARTIFACT), 'receipt-role boundary drifted');

const registryReceiptAuthorizes = clone(report);
registryReceiptAuthorizes.receipt_integrity.registry_receipt_authorized_service_write = true;
assertThrows('registry receipt authority laundering refused', () => assertConsequenceLifecycleMap(registryReceiptAuthorizes, ARTIFACT), 'receipt-role boundary drifted');

const rightful = clone(report);
rightful.receipt_integrity.generic_rightful_issuance_proven = true;
assertThrows('generic rightful issuance laundering refused', () => assertConsequenceLifecycleMap(rightful, ARTIFACT), 'local-fixture rightful-issuance boundary drifted');

const recognitionEqualsIssuance = clone(report);
recognitionEqualsIssuance.receipt_integrity.recognition_is_rightful_issuance = true;
assertThrows('recognition cannot become rightful issuance', () => assertConsequenceLifecycleMap(recognitionEqualsIssuance, ARTIFACT), 'local-fixture rightful-issuance boundary drifted');

const portableRightful = clone(report);
portableRightful.authority_topology.portable_rightful_issuance_proven = true;
assertThrows('portable rightful issuance overclaim refused', () => assertConsequenceLifecycleMap(portableRightful, ARTIFACT), 'authority topology drifted');

const liveRightful = clone(report);
liveRightful.claim_boundary.live_rightful_issuance = true;
assertThrows('live rightful issuance overclaim refused', () => assertConsequenceLifecycleMap(liveRightful, ARTIFACT), 'live_rightful_issuance');

const localFixtureEvidenceForged = clone(report);
localFixtureEvidenceForged.receipt_integrity.fixture_rightful_issuance_path_evidenced = true;
assertThrows('local fixture rightful issuance evidence forgery refused', () => assertConsequenceLifecycleMap(localFixtureEvidenceForged, ARTIFACT), 'local-fixture rightful-issuance boundary drifted');

const portableCrypto = clone(report);
portableCrypto.receipt_integrity.portable_cryptographic_reverification_possible = true;
assertThrows('portable crypto overclaim refused', () => assertConsequenceLifecycleMap(portableCrypto, ARTIFACT), 'portable cryptographic re-verification boundary');

const rollback = clone(report);
rollback.effect_boundary.consequence_rollback_proven = true;
assertThrows('false consequence rollback refused', () => assertConsequenceLifecycleMap(rollback, ARTIFACT), 'must not launder replay-store rollback');

const rollbackLaundering = clone(report);
rollbackLaundering.effect_boundary.anti_replay_rollback_is_consequence_rollback = true;
assertThrows('anti-replay rollback laundering refused', () => assertConsequenceLifecycleMap(rollbackLaundering, ARTIFACT), 'must not launder replay-store rollback');

const observationAuthority = clone(report);
observationAuthority.learning_boundary.observation_creates_authority = true;
assertThrows('observation-as-authority refused', () => assertConsequenceLifecycleMap(observationAuthority, ARTIFACT), 'must not create authority');

const refusalAuthority = clone(report);
refusalAuthority.learning_boundary.refusal_creates_authority = true;
assertThrows('refusal-as-authority refused', () => assertConsequenceLifecycleMap(refusalAuthority, ARTIFACT), 'must not create authority');

const hardeningAuthority = clone(report);
hardeningAuthority.learning_boundary.hardening_proposal_creates_authority = true;
assertThrows('hardening-proposal authority refused', () => assertConsequenceLifecycleMap(hardeningAuthority, ARTIFACT), 'must not create authority');

const collapsedRevocation = clone(report);
collapsedRevocation.revocation_powers.powers = [{ power_id: 'revoked' }];
assertThrows('collapsed revocation power refused', () => assertConsequenceLifecycleMap(collapsedRevocation, ARTIFACT), 'required canonical values');

const revocationTruth = clone(report);
revocationTruth.revocation_powers.revocation_truth_proven = true;
assertThrows('revocation truth upgrade refused', () => assertConsequenceLifecycleMap(revocationTruth, ARTIFACT), 'revocation truth unproven');

const liveRevocationTruth = clone(report);
liveRevocationTruth.revocation_powers.live_revocation_truth_proven = true;
assertThrows('live revocation truth upgrade refused', () => assertConsequenceLifecycleMap(liveRevocationTruth, ARTIFACT), 'revocation truth unproven');

const hiddenSideDoor = clone(report);
hiddenSideDoor.side_doors.open_boundaries = hiddenSideDoor.side_doors.open_boundaries.filter((item) => item !== 'unrouted_records_paths');
assertThrows('hidden source side door refused', () => assertConsequenceLifecycleMap(hiddenSideDoor, ARTIFACT), 'hides source boundary');

const missingObligationBlocker = clone(report);
missingObligationBlocker.closure.closure_blockers = missingObligationBlocker.closure.closure_blockers
  .filter((item) => item !== 'path_closeout_not_evidenced');
assertThrows('missing open-obligation blocker refused', () => assertConsequenceLifecycleMap(missingObligationBlocker, ARTIFACT), 'closure blocker missing for obligation');

const evidencedBlocker = clone(report);
const evidencedPathIdentity = evidencedBlocker.lifecycle_obligations.find((item) => item.obligation_id === 'path_identity');
evidencedPathIdentity.blocks_closure = true;
evidencedPathIdentity.closure_blocker_id = 'path_identity_evidenced';
assertThrows('evidenced obligation blocker refused', () => assertConsequenceLifecycleMap(evidencedBlocker, ARTIFACT), 'closure posture drifted');

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
  const widened = clone(report);
  widened.claim_boundary[field] = true;
  assertThrows(`forbidden claim refused: ${field}`, () => assertConsequenceLifecycleMap(widened, ARTIFACT), field);
}

const linearized = clone(report);
linearized.path_definition.linear_lifecycle_trace_claimed = true;
assertThrows('linearized state machine refused', () => assertConsequenceLifecycleMap(linearized, ARTIFACT), 'canonical artifact-bound projection');

const crossPath = clone(report);
crossPath.source_evidence.path_id = 'protected-records.active-persistent-profile.records.write';
assertThrows('cross-path evidence laundering refused', () => assertConsequenceLifecycleMap(crossPath, ARTIFACT), 'canonical artifact-bound projection');

const sourceCommit = clone(report);
sourceCommit.source_evidence.source_commit = 'c6fca6e93cfe5e771d19002cab9b1340348dda7b';
sourceCommit.source_evidence.source_commit_bound = true;
assertThrows('unproved source commit binding refused', () => assertConsequenceLifecycleMap(sourceCommit, ARTIFACT), 'canonical artifact-bound projection');

const unresolvedEvidenceRef = clone(report);
unresolvedEvidenceRef.lifecycle_obligations.find((item) => item.obligation_id === 'action_classification').evidence_refs[0] =
  'source:payload.chain.missing.action_class';
assertThrows('unresolved source evidence reference refused', () => assertConsequenceLifecycleMap(unresolvedEvidenceRef, ARTIFACT), 'evidence reference does not resolve');

const unnamespacedEvidenceRef = clone(report);
unnamespacedEvidenceRef.lifecycle_obligations.find((item) => item.obligation_id === 'action_classification').evidence_refs[0] =
  'payload.chain.terminal_chain';
assertThrows('unnamespaced evidence reference refused', () => assertConsequenceLifecycleMap(unnamespacedEvidenceRef, ARTIFACT), 'must use source: or report: namespace');

const graphBinding = clone(report);
graphBinding.path_definition.source_artifact_bound = false;
assertThrows('artifact-projected graph binding removal refused', () => assertConsequenceLifecycleMap(graphBinding, ARTIFACT), 'exact route projection drifted');

const pinnedSourceMismatch = clone(report);
pinnedSourceMismatch.source_evidence.expected_artifact_body_sha256_matched = false;
assertThrows('pinned terminal identity mismatch refused', () => assertConsequenceLifecycleMap(pinnedSourceMismatch, ARTIFACT), 'pinned source evidence drifted');

const duplicateEvidenceRef = clone(report);
const actionClassification = duplicateEvidenceRef.lifecycle_obligations.find((item) => item.obligation_id === 'action_classification');
actionClassification.evidence_refs.push(actionClassification.evidence_refs[0]);
assertThrows('duplicate evidence reference refused', () => assertConsequenceLifecycleMap(duplicateEvidenceRef, ARTIFACT), 'must be unique');

const reportOnlyEvidenceRef = clone(report);
reportOnlyEvidenceRef.lifecycle_obligations.find((item) => item.obligation_id === 'action_classification').evidence_refs = [
  'report:path_definition.graph_sha256',
];
assertThrows('evidenced item without source reference refused', () => assertConsequenceLifecycleMap(reportOnlyEvidenceRef, ARTIFACT), 'requires a source reference');

const evidenceResolutionTamper = clone(report);
evidenceResolutionTamper.evidence_ref_resolution.total_reference_count += 1;
assertThrows('evidence reference resolution count tamper refused', () => assertConsequenceLifecycleMap(evidenceResolutionTamper, ARTIFACT), 'resolution drifted');

const tamperedArtifact = clone(ARTIFACT);
tamperedArtifact.payload.chain.terminal_chain.recognized_write_boarded = false;
assertThrows('tampered source artifact refused', () => buildConsequenceLifecycleMap(tamperedArtifact), 'binding drifted');

assertThrows('unsafe private path refused', () => assertNoUnsafeConsequenceLifecycleText('/Users/private/operator/evidence.json'), 'private operator path');
assertThrows('unsafe credential refused', () => assertNoUnsafeConsequenceLifecycleText('token=secret-value'), 'credential value');
assertThrows('unsafe broad claim refused', () => assertNoUnsafeConsequenceLifecycleText('ZLAR governs all AI'), 'broad all-actions claim');

section('CLI wiring');

function run(args, options = {}) {
  return spawnSync(ZLAR_BIN, ['consequence-lifecycle', ...args], {
    cwd: PROJECT_DIR,
    encoding: 'utf8',
    input: options.input,
  });
}

const sampleText = run(['--sample']);
assertEqual('sample text exits zero', 0, sampleText.status);
assert('sample text names mapped_open', sampleText.stdout.includes('Consequence lifecycle map: mapped_open'));
assert('sample text names lifecycle false', sampleText.stdout.includes('Lifecycle closed: false'));

const sampleJson = run(['--sample', '--json']);
assertEqual('sample json exits zero', 0, sampleJson.status);
const sampleReport = JSON.parse(sampleJson.stdout);
assertEqual('sample json type', CONSEQUENCE_LIFECYCLE_MAP_TYPE, sampleReport.report_type);
assert('sample json remains open', sampleReport.closure.lifecycle_closed === false);
assert('sample json carries protected target binding', sampleReport.consequence_path.protected_target_binding_proven === true);
assert('sample json keeps live target false', sampleReport.consequence_path.live_target_binding_proven === false);
assertEqual('sample json evidenced obligation count', 12, sampleReport.lifecycle_obligations.filter((item) => item.status === 'evidenced').length);
assertEqual('sample json open obligation count', 8, sampleReport.lifecycle_obligations.filter((item) => item.status === 'not_evidenced').length);
assertEqual('sample json outside obligation count', 2, sampleReport.lifecycle_obligations.filter((item) => item.status === 'outside_coverage').length);
assert('sample json local fixture rightful path false', sampleReport.receipt_integrity.fixture_rightful_issuance_path_evidenced === false);
assert('sample json generic rightful false', sampleReport.receipt_integrity.generic_rightful_issuance_proven === false);
assert('sample json evidence refs resolved', sampleReport.evidence_ref_resolution.all_references_resolved === true);

const explicitInput = run(['--input', ARTIFACT_PATH, '--json']);
assertEqual('explicit artifact input exits zero', 0, explicitInput.status);
assertEqual('explicit artifact body hash bound', ARTIFACT.integrity.body_sha256, JSON.parse(explicitInput.stdout).source_evidence.artifact_body_sha256);

const stdinInput = run(['--input', '-', '--json'], { input: ARTIFACT_TEXT });
assertEqual('stdin artifact input exits zero', 0, stdinInput.status);
assertEqual('stdin exact path bound', CONSEQUENCE_LIFECYCLE_PATH_ID, JSON.parse(stdinInput.stdout).consequence_path.path_id);

const requireClosed = run(['--sample', '--require-closed']);
assertEqual('require-closed refuses mapped-open sample', 1, requireClosed.status);
assert('require-closed names mapped_open', requireClosed.stderr.includes('closure_status=mapped_open'));

const noInput = run([]);
assertEqual('missing input exits usage error', 2, noInput.status);
assert('missing input refuses live probing', noInput.stderr.includes('live probing is not implemented'));

const duplicateInput = run(['--sample', '--input', ARTIFACT_PATH]);
assertEqual('duplicate input source exits usage error', 2, duplicateInput.status);
assert('duplicate input source refused', duplicateInput.stderr.includes('only one input source'));

const optionAsInput = run(['--input', '--json']);
assertEqual('input does not consume json option', 2, optionAsInput.status);
assert('input option value error is explicit', optionAsInput.stderr.includes('cannot consume another option'));

const sampleAsInput = run(['--input', '--sample']);
assertEqual('input does not consume sample option', 2, sampleAsInput.status);
assert('sample option value error is explicit', sampleAsInput.stderr.includes('cannot consume another option'));

const unsupported = run(['--sample', '--closure-status', 'closed']);
assertEqual('manual closure option exits usage error', 2, unsupported.status);
assert('manual closure option refused', unsupported.stderr.includes('Unsupported option'));

const invalidJson = run(['--input', '-'], { input: '{not-json' });
assertEqual('invalid json exits error', 1, invalidJson.status);
assert('invalid json names parse failure', invalidJson.stderr.includes('Could not parse terminal-chain artifact JSON'));

const tamperedInput = run(['--input', '-'], { input: JSON.stringify(tamperedArtifact) });
assertEqual('tampered artifact CLI exits error', 1, tamperedInput.status);
assert('tampered artifact CLI names integrity failure', tamperedInput.stderr.includes('binding drifted'));

const help = run(['--help']);
assertEqual('help exits zero', 0, help.status);
assert('help names consequence-lifecycle', help.stderr.includes('zlar consequence-lifecycle'));

console.log(`\nResults: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) {
  process.exit(1);
}
console.log('ALL PASS');
