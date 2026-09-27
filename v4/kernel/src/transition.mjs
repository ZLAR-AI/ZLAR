import { FIXTURE_NAMESPACE, SCHEMA_VERSION } from "./constants.mjs";
import {
  assertProposalBinding,
  assertReference,
  assertReferenceArray,
} from "./contracts.mjs";
import { identifyMaterialized } from "./identity.mjs";
import {
  refuse,
  refusalResult,
  RefusalSignal,
} from "./refusal.mjs";
import {
  assertCanonicalInstant,
  assertExactKeys,
  assertSyntheticId,
  canonicalTextFromMaterialized,
} from "./safe-data.mjs";

const lifecycleStates = Object.freeze({
  mandate: Object.freeze(["absent", "pending", "current", "suspended", "expired", "revoked"]),
  credential_status: Object.freeze(["absent", "unknown", "current", "disabled", "expired"]),
  exercise: Object.freeze(["unresolved", "eligible_synthetic", "ineligible", "pending_review"]),
  recognition: Object.freeze(["unbound", "unavailable"]),
  consequence: Object.freeze(["not_observed", "synthetic_observation_recorded"]),
  remedy: Object.freeze(["not_requested", "requested", "pending_review", "disposition_recorded"]),
  recovery: Object.freeze(["not_requested", "requested", "pending_review", "observation_recorded"]),
  revocation: Object.freeze([
    "no_record",
    "internal_decision",
    "institutional_effective",
    "propagation_unknown",
  ]),
});

const eventKinds = Object.freeze([
  "challenge_recorded",
  "consequence_observed",
  "constitutive_step_recorded",
  "credential_disabled",
  "exercise_evaluated",
  "mandate_fact_recorded",
  "recognition_unavailable_recorded",
  "recovery_observed",
  "recovery_requested",
  "remedy_disposition_recorded",
  "remedy_requested",
  "revocation_internal_decision_recorded",
  "revocation_institutional_effective_recorded",
  "revocation_propagation_unknown_recorded",
]);

const semanticEdges = Object.freeze([
  ["mandate", "absent", "pending", "mandate_fact_recorded"],
  ["mandate", "pending", "current", "mandate_fact_recorded"],
  ["credential_status", "current", "disabled", "credential_disabled"],
  ["exercise", "unresolved", "eligible_synthetic", "exercise_evaluated"],
  ["exercise", "unresolved", "ineligible", "exercise_evaluated"],
  ["exercise", "unresolved", "pending_review", "exercise_evaluated"],
  ["recognition", "unbound", "unavailable", "recognition_unavailable_recorded"],
  ["consequence", "not_observed", "synthetic_observation_recorded", "consequence_observed"],
  ["remedy", "not_requested", "requested", "remedy_requested"],
  ["remedy", "requested", "pending_review", "challenge_recorded"],
  ["remedy", "pending_review", "disposition_recorded", "remedy_disposition_recorded"],
  ["recovery", "not_requested", "requested", "recovery_requested"],
  ["recovery", "requested", "pending_review", "challenge_recorded"],
  ["recovery", "pending_review", "observation_recorded", "recovery_observed"],
  ["revocation", "no_record", "internal_decision", "revocation_internal_decision_recorded"],
  ["revocation", "internal_decision", "institutional_effective", "revocation_institutional_effective_recorded"],
  ["revocation", "internal_decision", "propagation_unknown", "revocation_propagation_unknown_recorded"],
]);

function semanticEdgeAllowed(lifecycleType, fromState, toState, eventKind) {
  return semanticEdges.some((edge) =>
    edge[0] === lifecycleType &&
    edge[1] === fromState &&
    edge[2] === toState &&
    edge[3] === eventKind);
}

function assertLifecycleState(lifecycleType, state, path) {
  if (!Object.hasOwn(lifecycleStates, lifecycleType)) {
    refuse("record_type_unknown", path, "lifecycle_type");
  }
  if (!lifecycleStates[lifecycleType].includes(state)) {
    refuse("transition_not_allowed", path, "lifecycle_state");
  }
}

function snapshotBody(snapshot) {
  return {
    evidence_refs: snapshot.evidence_refs,
    lifecycle_type: snapshot.lifecycle_type,
    predecessor_ref: snapshot.predecessor_ref,
    proposal_binding: snapshot.proposal_binding,
    state: snapshot.state,
  };
}

function validateSnapshot(snapshot) {
  assertExactKeys(snapshot, [
    "evidence_refs",
    "lifecycle_type",
    "predecessor_ref",
    "proposal_binding",
    "schema_version",
    "snapshot_id",
    "snapshot_type",
    "state",
  ], "$.prior_snapshot");
  if (
    snapshot.snapshot_type !== "lifecycle_snapshot" ||
    snapshot.schema_version !== SCHEMA_VERSION
  ) refuse("schema_version_unknown", "$.prior_snapshot", "snapshot_contract");
  assertLifecycleState(snapshot.lifecycle_type, snapshot.state, "$.prior_snapshot.state");
  assertReference(snapshot.predecessor_ref, "$.prior_snapshot.predecessor_ref", true);
  assertProposalBinding(snapshot.proposal_binding, "$.prior_snapshot.proposal_binding");
  assertReferenceArray(snapshot.evidence_refs, "$.prior_snapshot.evidence_refs");
  const identity = identifyMaterialized({
    record_type: "lifecycle_snapshot",
    schema_version: SCHEMA_VERSION,
    record_body: snapshotBody(snapshot),
  });
  if (identity.evidence_id !== snapshot.snapshot_id) {
    refuse("identity_mismatch", "$.prior_snapshot.snapshot_id", "snapshot_identity");
  }
}

function eventBody(event) {
  return {
    claim_basis: event.claim_basis,
    effective_at: event.effective_at,
    event_kind: event.event_kind,
    evidence_refs: event.evidence_refs,
    from_state: event.from_state,
    lifecycle_type: event.lifecycle_type,
    observed_at: event.observed_at,
    prior_snapshot_id: event.prior_snapshot_id,
    profile_id: event.profile_id,
    profile_version: event.profile_version,
    proposal_binding: event.proposal_binding,
    rule_set_id: event.rule_set_id,
    rule_set_version: event.rule_set_version,
    source_class: event.source_class,
    source_ref: event.source_ref,
    to_state: event.to_state,
  };
}

function validateEvent(event) {
  assertExactKeys(event, [
    "claim_basis",
    "effective_at",
    "event_id",
    "event_kind",
    "event_type",
    "evidence_refs",
    "from_state",
    "lifecycle_type",
    "observed_at",
    "prior_snapshot_id",
    "profile_id",
    "profile_version",
    "proposal_binding",
    "rule_set_id",
    "rule_set_version",
    "schema_version",
    "source_class",
    "source_ref",
    "to_state",
  ], "$.proposed_event");
  if (
    event.event_type !== "synthetic_transition_event" ||
    event.schema_version !== SCHEMA_VERSION
  ) refuse("schema_version_unknown", "$.proposed_event", "event_contract");
  if (["grant_enlargement", "profile_change", "restoration", "waiver"].includes(event.event_kind)) {
    refuse("self_mandate_forbidden", "$.proposed_event.event_kind", "self_mandate");
  }
  if (!eventKinds.includes(event.event_kind)) {
    refuse("transition_not_allowed", "$.proposed_event.event_kind", "event_registry");
  }
  if (event.source_class !== "synthetic_fixture_external") {
    refuse("external_authority_reference_missing", "$.proposed_event.source_class", "event_source");
  }
  assertReference(event.source_ref, "$.proposed_event.source_ref");
  assertLifecycleState(event.lifecycle_type, event.from_state, "$.proposed_event.from_state");
  assertLifecycleState(event.lifecycle_type, event.to_state, "$.proposed_event.to_state");
  if (!semanticEdgeAllowed(
    event.lifecycle_type,
    event.from_state,
    event.to_state,
    event.event_kind,
  )) refuse("transition_not_allowed", "$.proposed_event", "typed_lifecycle_edge");
  assertReference(event.prior_snapshot_id, "$.proposed_event.prior_snapshot_id");
  assertSyntheticId(event.profile_id, "$.proposed_event.profile_id");
  assertSyntheticId(event.rule_set_id, "$.proposed_event.rule_set_id");
  if (event.profile_version !== SCHEMA_VERSION || event.rule_set_version !== SCHEMA_VERSION) {
    refuse("profile_rule_missing", "$.proposed_event", "event_profile_version");
  }
  assertProposalBinding(event.proposal_binding, "$.proposed_event.proposal_binding");
  assertCanonicalInstant(event.observed_at, "$.proposed_event.observed_at");
  if (event.effective_at !== null) {
    assertCanonicalInstant(event.effective_at, "$.proposed_event.effective_at");
  }
  assertReferenceArray(event.evidence_refs, "$.proposed_event.evidence_refs");
  if (event.claim_basis !== "deterministic_synthetic_transition_evaluation_only") {
    refuse("claim_ceiling_overreach", "$.proposed_event.claim_basis", "transition_claim_basis");
  }
  const identity = identifyMaterialized({
    record_type: "synthetic_transition_event",
    schema_version: SCHEMA_VERSION,
    record_body: eventBody(event),
  });
  if (identity.evidence_id !== event.event_id) {
    refuse("identity_mismatch", "$.proposed_event.event_id", "event_identity");
  }
}

function validateTransitionProfile(profile) {
  assertExactKeys(profile, [
    "do_not_use_for",
    "effective_time_rule",
    "fixture_namespace",
    "profile_id",
    "profile_type",
    "profile_version",
    "observed_time_rule",
    "reset",
    "residue",
    "rule_set_id",
    "rule_set_version",
    "transitions",
    "unknown_disposition",
    "use_for",
  ], "$.profile");
  if (
    profile.profile_type !== "synthetic_transition_profile" ||
    profile.fixture_namespace !== FIXTURE_NAMESPACE ||
    profile.profile_version !== SCHEMA_VERSION ||
    profile.rule_set_version !== SCHEMA_VERSION ||
    !["pending_review", "unknown_refuse"].includes(profile.unknown_disposition)
  ) refuse("profile_rule_missing", "$.profile", "transition_profile");
  assertSyntheticId(profile.profile_id, "$.profile.profile_id");
  assertSyntheticId(profile.rule_set_id, "$.profile.rule_set_id");
  if (
    profile.observed_time_rule !== "not_after_evaluation" ||
    profile.effective_time_rule !== "not_after_evaluation"
  ) refuse("profile_rule_missing", "$.profile", "explicit_time_rules");
  if (!Array.isArray(profile.transitions) || !profile.transitions.length) {
    refuse("profile_rule_missing", "$.profile.transitions", "transition_rules");
  }
  for (let index = 0; index < profile.transitions.length; index += 1) {
    const rule = profile.transitions[index];
    assertExactKeys(rule, [
      "event_kind",
      "from_state",
      "lifecycle_type",
      "requires_proposal",
      "to_state",
    ], `$.profile.transitions[${index}]`);
    assertLifecycleState(rule.lifecycle_type, rule.from_state, `$.profile.transitions[${index}].from_state`);
    assertLifecycleState(rule.lifecycle_type, rule.to_state, `$.profile.transitions[${index}].to_state`);
    if (!eventKinds.includes(rule.event_kind) || typeof rule.requires_proposal !== "boolean") {
      refuse("profile_rule_missing", `$.profile.transitions[${index}]`, "transition_rule");
    }
    if (!semanticEdgeAllowed(
      rule.lifecycle_type,
      rule.from_state,
      rule.to_state,
      rule.event_kind,
    )) refuse("transition_not_allowed", `$.profile.transitions[${index}]`, "typed_lifecycle_edge");
  }
  if (
    profile.use_for !== "private_synthetic_source_evidence_only" ||
    canonicalTextFromMaterialized(profile.do_not_use_for) !==
      '["authority","effect","execution","partner_truth","recognition"]' ||
    profile.reset !== "profile_identity_change_requires_new_evidence" ||
    profile.residue !== "real_institutional_rules_remain_absent"
  ) refuse("claim_ceiling_overreach", "$.profile", "transition_profile_boundary");
}

function sameProposal(left, right) {
  return canonicalTextFromMaterialized(left) === canonicalTextFromMaterialized(right);
}

function addSignal(codes, error) {
  if (error instanceof RefusalSignal) codes.add(error.code);
  else codes.add("internal_contract_refusal");
}

export function evaluateMaterialized(input) {
  assertExactKeys(input, [
    "evaluation_time",
    "fixture_namespace",
    "mode",
    "prior_snapshot",
    "profile",
    "proposed_event",
  ], "$" );
  if (input.mode !== "synthetic") refuse("live_mode_forbidden", "$.mode", "mode");
  if (input.fixture_namespace !== FIXTURE_NAMESPACE) {
    refuse("fixture_namespace_forbidden", "$.fixture_namespace", "fixture_namespace");
  }
  assertCanonicalInstant(input.evaluation_time, "$.evaluation_time");
  const priorBytes = canonicalTextFromMaterialized(input.prior_snapshot);
  const codes = new Set();
  let snapshotValid = false;
  let eventValid = false;
  let profileValid = false;
  try {
    validateSnapshot(input.prior_snapshot);
    snapshotValid = true;
  } catch (error) { addSignal(codes, error); }
  try {
    validateEvent(input.proposed_event);
    eventValid = true;
  } catch (error) { addSignal(codes, error); }
  try {
    validateTransitionProfile(input.profile);
    profileValid = true;
  } catch (error) { addSignal(codes, error); }

  const event = input.proposed_event;
  const prior = input.prior_snapshot;
  let matchingRules = [];
  if (snapshotValid && eventValid) {
    if (event.prior_snapshot_id === "latest" || event.prior_snapshot_id !== prior.snapshot_id) {
      codes.add("transition_input_stale");
    }
    if (event.lifecycle_type !== prior.lifecycle_type || event.from_state !== prior.state) {
      codes.add("transition_not_allowed");
    }
    if (!sameProposal(event.proposal_binding, prior.proposal_binding)) {
      codes.add("proposal_version_mismatch");
    }
  }
  if (eventValid && profileValid) {
    if (
      event.profile_id !== input.profile.profile_id ||
      event.profile_version !== input.profile.profile_version ||
      event.rule_set_id !== input.profile.rule_set_id ||
      event.rule_set_version !== input.profile.rule_set_version
    ) codes.add("profile_rule_missing");
    matchingRules = input.profile.transitions.filter((rule) =>
      rule.lifecycle_type === event.lifecycle_type &&
      rule.from_state === event.from_state &&
      rule.to_state === event.to_state &&
      rule.event_kind === event.event_kind);
    if (matchingRules.length !== 1) codes.add("transition_not_allowed");
    if (matchingRules[0]?.requires_proposal && event.proposal_binding === null) {
      codes.add("proposal_version_mismatch");
    }
    if (
      event.observed_at > input.evaluation_time ||
      (event.effective_at !== null && event.effective_at > input.evaluation_time)
    ) codes.add("transition_not_allowed");
  }
  if (canonicalTextFromMaterialized(input.prior_snapshot) !== priorBytes) {
    codes.add("identity_mismatch");
  }
  const sortedCodes = [...codes].sort();
  if (sortedCodes.length) {
    return {
      codes: sortedCodes,
      unchanged_snapshot: input.prior_snapshot,
    };
  }

  const combinedEvidence = [...new Set([
    ...prior.evidence_refs,
    ...event.evidence_refs,
    event.event_id,
  ])].sort();
  const nextBody = {
    evidence_refs: combinedEvidence,
    lifecycle_type: prior.lifecycle_type,
    predecessor_ref: prior.snapshot_id,
    proposal_binding: event.proposal_binding,
    state: event.to_state,
  };
  const nextIdentity = identifyMaterialized({
    record_type: "lifecycle_snapshot",
    schema_version: SCHEMA_VERSION,
    record_body: nextBody,
  });
  const nextSnapshot = Object.freeze({
    snapshot_type: "lifecycle_snapshot",
    schema_version: SCHEMA_VERSION,
    snapshot_id: nextIdentity.evidence_id,
    ...nextBody,
  });
  return {
    codes: [],
    result: Object.freeze({
      outcome: "synthetic_transition_accepted",
      next_snapshot: nextSnapshot,
      transition_receipt: Object.freeze({
        receipt_type: "synthetic_transition_receipt",
        kernel_result: "deterministic_transition_evaluated",
        prior_snapshot_id: prior.snapshot_id,
        next_snapshot_id: nextSnapshot.snapshot_id,
        event_id: event.event_id,
        proposal_binding: event.proposal_binding,
        profile_id: event.profile_id,
        profile_version: event.profile_version,
        rule_set_id: event.rule_set_id,
        rule_set_version: event.rule_set_version,
        evidence_refs: Object.freeze([...event.evidence_refs]),
        observed_at: event.observed_at,
        effective_at: event.effective_at,
        evaluation_time: input.evaluation_time,
        claim_basis: "deterministic_synthetic_transition_evaluation_only",
        limitations: Object.freeze([
          "no_global_fork_prevention",
          "no_persistence_or_atomicity",
          "no_real_authority_or_effect",
        ]),
      }),
    }),
  };
}

export function publicTransitionResult(evaluation) {
  if (!evaluation.codes.length) return evaluation.result;
  return Object.freeze({
    ...refusalResult(
      "evaluateTransition",
      evaluation.codes,
      "$",
      "transition_invariants",
    ),
    unchanged_snapshot: evaluation.unchanged_snapshot,
  });
}
