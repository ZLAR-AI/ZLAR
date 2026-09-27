import assert from "node:assert/strict";
import test from "node:test";

import {
  evaluateTransition,
  identifyEvidence,
  projectAuthorityView,
  validateGraph,
} from "../src/index.mjs";
import {
  eventFixture,
  graphFixture,
  PROPOSAL,
  searchRecord,
  snapshotFixture,
  sourceRecord,
  transitionInput,
  transitionProfile,
} from "./helpers/fixtures.mjs";

test("all linked lifecycle families use explicit profile edges", () => {
  const cases = [
    ["mandate", "pending", "current", "mandate_fact_recorded", false],
    ["credential_status", "current", "disabled", "credential_disabled", false],
    ["exercise", "unresolved", "eligible_synthetic", "exercise_evaluated", true],
    ["recognition", "unbound", "unavailable", "recognition_unavailable_recorded", true],
    ["consequence", "not_observed", "synthetic_observation_recorded", "consequence_observed", true],
    ["remedy", "not_requested", "requested", "remedy_requested", true],
    ["recovery", "not_requested", "requested", "recovery_requested", true],
    ["revocation", "no_record", "internal_decision", "revocation_internal_decision_recorded", false],
  ];
  for (const [lifecycleType, fromState, toState, eventKind, requiresProposal] of cases) {
    const proposalBinding = requiresProposal ? PROPOSAL : null;
    const prior = snapshotFixture({
      lifecycle_type: lifecycleType,
      state: fromState,
      proposal_binding: proposalBinding,
    });
    const event = eventFixture(prior, {
      lifecycle_type: lifecycleType,
      from_state: fromState,
      to_state: toState,
      event_kind: eventKind,
      proposal_binding: proposalBinding,
    });
    const profile = transitionProfile({
      transitions: [{
        lifecycle_type: lifecycleType,
        from_state: fromState,
        to_state: toState,
        event_kind: eventKind,
        requires_proposal: requiresProposal,
      }],
    });
    const result = evaluateTransition(transitionInput({
      prior_snapshot: prior,
      proposed_event: event,
      profile,
    }));
    assert.equal(result.outcome, "synthetic_transition_accepted", lifecycleType);
    assert.equal(result.next_snapshot.predecessor_ref, prior.snapshot_id);
  }
});

test("co-present successors refuse as graph-visible fork", () => {
  const base = sourceRecord("mandate", "syn:v4:proposition:mandate", {
    authoritative_head_evidence_ref: null,
  });
  const left = sourceRecord("mandate", "syn:v4:proposition:mandate", {
    predecessor_ref: base.evidence_id,
    source_ref: "syn:v4:source:mandate_left",
  });
  const right = sourceRecord("mandate", "syn:v4:proposition:mandate", {
    predecessor_ref: base.evidence_id,
    source_ref: "syn:v4:source:mandate_right",
  });
  const result = validateGraph(graphFixture({
    expectedPropositions: ["syn:v4:proposition:mandate"],
    records: [base, left, right],
  }));
  assert.equal(result.refusal_codes.includes("lifecycle_fork"), true);
});

test("proposal collision and invariant failures aggregate", () => {
  const exercise = sourceRecord("exercise", "syn:v4:proposition:exercise");
  const recognition = sourceRecord("recognition", "syn:v4:proposition:recognition", {
    proposal_binding: {
      proposal_id: "syn:v4:proposal:alpha",
      proposal_version: "v1",
      proposal_digest: "b".repeat(64),
    },
  });
  const mutated = structuredClone(sourceRecord(
    "observation",
    "syn:v4:proposition:observation",
  ));
  mutated.record_body.claim_ceiling = "forbidden";
  mutated.record_body.credential = "promoted";
  const result = validateGraph(graphFixture({
    expectedPropositions: [
      "syn:v4:proposition:exercise",
      "syn:v4:proposition:observation",
      "syn:v4:proposition:recognition",
    ],
    records: [exercise, recognition, mutated],
  }));
  for (const code of [
    "credential_promoted_to_authority",
    "proposal_identity_collision",
    "self_mandate_forbidden",
  ]) assert.equal(result.refusal_codes.includes(code), true);
  assert.deepEqual(result.refusal_codes, [...result.refusal_codes].sort());
});

test("proposal-bound exercise requires an exact recomputed proposal source", () => {
  const graph = graphFixture({
    expectedPropositions: ["syn:v4:proposition:exercise"],
    records: [sourceRecord("exercise", "syn:v4:proposition:exercise")],
  });
  graph.records = graph.records.filter((record) => record.record_type !== "proposal");
  assert.equal(
    validateGraph(graph).refusal_codes.includes("required_evidence_missing"),
    true,
  );
});

test("graph aggregation preserves independent envelope and record failures", () => {
  const mandate = structuredClone(sourceRecord(
    "mandate",
    "syn:v4:proposition:mandate",
  ));
  mandate.record_body.source_class = "synthetic_fixture_observation";
  mandate.record_body.self_grant = true;
  const graph = graphFixture({
    expectedPropositions: ["syn:v4:proposition:mandate"],
    records: [mandate],
  });
  graph.mode = "live";
  graph.fixture_namespace = "wrong_namespace";
  const result = validateGraph(graph);
  for (const code of [
    "external_authority_reference_missing",
    "fixture_namespace_forbidden",
    "identity_mismatch",
    "live_mode_forbidden",
    "self_mandate_forbidden",
  ]) assert.equal(result.refusal_codes.includes(code), true, code);
});

test("derived projection cannot return as source", () => {
  const graph = graphFixture({
    expectedPropositions: ["syn:v4:proposition:mandate"],
    records: [{
      record_type: "authority_projection",
      schema_version: "v1",
      evidence_id: "syn:v4:evidence:projection",
      record_body: {},
    }],
  });
  assert.deepEqual(
    validateGraph(graph).refusal_codes,
    ["derived_view_used_as_source"],
  );
});

test("lineage current requires exact head evidence", () => {
  const graph = graphFixture({
    expectedPropositions: ["syn:v4:proposition:mandate"],
    records: [sourceRecord("mandate", "syn:v4:proposition:mandate", {
      authoritative_head_evidence_ref: null,
    })],
  });
  assert.equal(
    projectAuthorityView({ graph, as_of: 50 }).assessments[0].lineage,
    "unknown",
  );
});

test("observation cannot satisfy a mandate proposition", () => {
  const graph = graphFixture({
    expectedPropositions: ["syn:v4:proposition:mandate"],
    records: [sourceRecord("observation", "syn:v4:proposition:mandate")],
  });
  assert.equal(
    validateGraph(graph).refusal_codes.includes("record_role_mismatch"),
    true,
  );
});

test("a naked head reference cannot manufacture current lineage", () => {
  const graph = graphFixture({
    expectedPropositions: ["syn:v4:proposition:mandate"],
    records: [sourceRecord("mandate", "syn:v4:proposition:mandate", {
      authoritative_head_evidence_ref: "syn:v4:evidence:nonexistent_head",
    })],
  });
  assert.equal(
    validateGraph(graph).refusal_codes.includes("required_evidence_missing"),
    true,
  );
});

test("revocation milestone identity must be scoped to its referencing revocation", () => {
  const milestone = sourceRecord(
    "revocation_milestone",
    "syn:v4:proposition:revocation_milestone",
    {
      effective_at: 50,
      milestone_kind: "institutional_effective",
      revocation_proposition_id: "syn:v4:proposition:other_revocation",
      payload: {
        category: "revocation_milestone_fact",
        data_class: "synthetic_non_identifying",
        proposal_content: null,
        references: ["syn:v4:proposition:other_revocation"],
      },
    },
  );
  const revocation = sourceRecord(
    "revocation",
    "syn:v4:proposition:revocation",
    {
      payload: {
        category: "revocation_fact",
        data_class: "synthetic_non_identifying",
        proposal_content: null,
        references: [milestone.evidence_id],
      },
    },
  );
  const graph = graphFixture({
    expectedPropositions: [
      "syn:v4:proposition:revocation",
      "syn:v4:proposition:revocation_milestone",
    ],
    records: [revocation, milestone],
  });
  assert.equal(
    validateGraph(graph).refusal_codes.includes("required_evidence_missing"),
    true,
  );
});

test("complete profile-bound fusion derives its exact result proposition", () => {
  const authorityDomainOwner = sourceRecord(
    "authority_domain_owner",
    "syn:v4:proposition:authority_domain_owner",
  );
  const changeAuthority = sourceRecord(
    "change_authority",
    "syn:v4:proposition:change_authority",
  );
  const constitutiveEvent = sourceRecord(
    "constitutive_event",
    "syn:v4:proposition:constitutive_event",
  );
  const revocationAuthority = sourceRecord(
    "revocation_authority",
    "syn:v4:proposition:revocation_authority",
  );
  const sourceRule = sourceRecord(
    "source_rule",
    "syn:v4:proposition:source_rule",
  );
  const graph = graphFixture({
    expectedPropositions: [
      "syn:v4:proposition:authority_domain_owner",
      "syn:v4:proposition:change_authority",
      "syn:v4:proposition:constitutive_event",
      "syn:v4:proposition:exercise",
      "syn:v4:proposition:mandate",
      "syn:v4:proposition:observation",
      "syn:v4:proposition:revocation_authority",
      "syn:v4:proposition:source_rule",
    ],
    records: [
      authorityDomainOwner,
      changeAuthority,
      constitutiveEvent,
      sourceRecord("mandate", "syn:v4:proposition:mandate"),
      sourceRecord("observation", "syn:v4:proposition:observation"),
      revocationAuthority,
      sourceRule,
    ],
    profileOverrides: {
      constitutive_propositions: ["syn:v4:proposition:exercise"],
      source_ref: sourceRule.evidence_id,
      fusion_rules: [{
        authority_domain_owner_ref: authorityDomainOwner.evidence_id,
        change_authority_ref: changeAuthority.evidence_id,
        constitutive_event_ref: constitutiveEvent.evidence_id,
        effective_time_rule: "explicit_canonical_instant",
        freshness_rule: "half_open_interval",
        proposal_binding: PROPOSAL,
        required_propositions: [
          "syn:v4:proposition:mandate",
          "syn:v4:proposition:observation",
        ],
        result_proposition: "syn:v4:proposition:exercise",
        revocation_authority_ref: revocationAuthority.evidence_id,
        source_rule_ref: sourceRule.evidence_id,
        unknown_disposition: "unknown_refuse",
      }],
    },
  });
  const projection = projectAuthorityView({ graph, as_of: 50 });
  const exercise = projection.assessments.find(
    (assessment) => assessment.proposition_id === "syn:v4:proposition:exercise",
  );
  assert.equal(exercise.source_record_type, "profile_bound_fusion");
  assert.equal(exercise.presence, "present");
  for (const reference of [
    authorityDomainOwner.evidence_id,
    changeAuthority.evidence_id,
    constitutiveEvent.evidence_id,
    revocationAuthority.evidence_id,
    sourceRule.evidence_id,
  ]) assert.equal(exercise.source_evidence_refs.includes(reference), true);

  const unbounded = structuredClone(graph);
  const mandateIndex = unbounded.records.findIndex((record) =>
    record.record_type === "mandate");
  unbounded.records[mandateIndex] = sourceRecord(
    "mandate",
    "syn:v4:proposition:mandate",
    { valid_from: null, valid_until: null },
  );
  const unboundedProjection = projectAuthorityView({ graph: unbounded, as_of: 50 });
  const unboundedExercise = unboundedProjection.assessments.find(
    (assessment) => assessment.proposition_id === "syn:v4:proposition:exercise",
  );
  assert.equal(unboundedExercise.presence, "unknown");
  assert.equal(
    unboundedProjection.refusal_codes.includes("required_evidence_missing"),
    true,
  );
});

test("fusion refuses nonexistent authority evidence and an empty basis", () => {
  const nonexistentRefs = graphFixture({
    expectedPropositions: [
      "syn:v4:proposition:exercise",
      "syn:v4:proposition:observation",
    ],
    records: [sourceRecord("observation", "syn:v4:proposition:observation")],
    profileOverrides: {
      source_ref: "syn:v4:evidence:nonexistent_source_rule",
      fusion_rules: [{
        authority_domain_owner_ref: "syn:v4:evidence:nonexistent_domain_owner",
        change_authority_ref: "syn:v4:evidence:nonexistent_change_authority",
        constitutive_event_ref: "syn:v4:evidence:nonexistent_constitutive_event",
        effective_time_rule: "explicit_canonical_instant",
        freshness_rule: "half_open_interval",
        proposal_binding: PROPOSAL,
        required_propositions: ["syn:v4:proposition:observation"],
        result_proposition: "syn:v4:proposition:exercise",
        revocation_authority_ref: "syn:v4:evidence:nonexistent_revocation_authority",
        source_rule_ref: "syn:v4:evidence:nonexistent_source_rule",
        unknown_disposition: "unknown_refuse",
      }],
    },
  });
  assert.equal(
    validateGraph(nonexistentRefs).refusal_codes.includes("required_evidence_missing"),
    true,
  );

  const emptyBasis = structuredClone(nonexistentRefs);
  emptyBasis.profile.fusion_rules[0].required_propositions = [];
  assert.equal(
    validateGraph(emptyBasis).refusal_codes.includes("silent_proposition_fusion"),
    true,
  );
});

test("fusion refuses required evidence from a different proposal slot", () => {
  const proposalContentB = {
    proposal_id: "syn:v4:proposal:beta",
    proposal_version: "v1",
    content_atoms: ["synthetic_action_beta"],
  };
  const proposalB = {
    proposal_id: proposalContentB.proposal_id,
    proposal_version: proposalContentB.proposal_version,
    proposal_digest: identifyEvidence({
      record_type: "proposal",
      schema_version: "v1",
      record_body: proposalContentB,
    }).evidence_id.slice(-64),
  };
  const authorityDomainOwner = sourceRecord(
    "authority_domain_owner",
    "syn:v4:proposition:authority_domain_owner",
  );
  const changeAuthority = sourceRecord(
    "change_authority",
    "syn:v4:proposition:change_authority",
  );
  const constitutiveEvent = sourceRecord(
    "constitutive_event",
    "syn:v4:proposition:constitutive_event",
  );
  const revocationAuthority = sourceRecord(
    "revocation_authority",
    "syn:v4:proposition:revocation_authority",
  );
  const sourceRule = sourceRecord(
    "source_rule",
    "syn:v4:proposition:source_rule",
  );
  const graph = graphFixture({
    expectedPropositions: [
      "syn:v4:proposition:authority_domain_owner",
      "syn:v4:proposition:change_authority",
      "syn:v4:proposition:constitutive_event",
      "syn:v4:proposition:constitutive_step",
      "syn:v4:proposition:exercise",
      "syn:v4:proposition:revocation_authority",
      "syn:v4:proposition:source_rule",
    ],
    records: [
      authorityDomainOwner,
      changeAuthority,
      constitutiveEvent,
      sourceRecord("constitutive_step", "syn:v4:proposition:constitutive_step", {
        proposal_binding: proposalB,
      }),
      revocationAuthority,
      sourceRule,
      sourceRecord("proposal", "syn:v4:proposition:proposal_alpha"),
      sourceRecord("proposal", "syn:v4:proposition:proposal_beta", {
        proposal_binding: proposalB,
        payload: {
          category: "proposal_bytes",
          data_class: "synthetic_non_identifying",
          proposal_content: proposalContentB,
          references: [],
        },
      }),
    ],
    profileOverrides: {
      source_ref: sourceRule.evidence_id,
      fusion_rules: [{
        authority_domain_owner_ref: authorityDomainOwner.evidence_id,
        change_authority_ref: changeAuthority.evidence_id,
        constitutive_event_ref: constitutiveEvent.evidence_id,
        effective_time_rule: "explicit_canonical_instant",
        freshness_rule: "half_open_interval",
        proposal_binding: PROPOSAL,
        required_propositions: ["syn:v4:proposition:constitutive_step"],
        result_proposition: "syn:v4:proposition:exercise",
        revocation_authority_ref: revocationAuthority.evidence_id,
        source_rule_ref: sourceRule.evidence_id,
        unknown_disposition: "unknown_refuse",
      }],
    },
  });
  assert.equal(
    validateGraph(graph).refusal_codes.includes("proposal_version_mismatch"),
    true,
  );
});

test("closed-search absence is bound to its exact observation time", () => {
  const graph = graphFixture({
    expectedPropositions: ["syn:v4:proposition:mandate"],
    records: [searchRecord("syn:v4:proposition:mandate", "mandate")],
  });
  const later = projectAuthorityView({ graph, as_of: 1000 });
  assert.equal(later.assessments[0].presence, "unknown");
  assert.equal(later.assessments[0].freshness, "unknown");
});

test("typed edge matrix blocks cross-family and revoked restoration", () => {
  const mandate = snapshotFixture({ lifecycle_type: "mandate", state: "pending" });
  const crossFamily = transitionInput({
    prior_snapshot: mandate,
    proposed_event: eventFixture(mandate, {
      event_kind: "consequence_observed",
      lifecycle_type: "mandate",
      from_state: "pending",
      to_state: "current",
    }),
    profile: transitionProfile({
      transitions: [{
        event_kind: "consequence_observed",
        lifecycle_type: "mandate",
        from_state: "pending",
        to_state: "current",
        requires_proposal: false,
      }],
    }),
  });
  assert.equal(
    evaluateTransition(crossFamily).refusal_codes.includes("transition_not_allowed"),
    true,
  );

  const revoked = snapshotFixture({ lifecycle_type: "mandate", state: "revoked" });
  const restore = transitionInput({
    prior_snapshot: revoked,
    proposed_event: eventFixture(revoked, {
      event_kind: "mandate_fact_recorded",
      from_state: "revoked",
      to_state: "current",
    }),
    profile: transitionProfile({
      transitions: [{
        event_kind: "mandate_fact_recorded",
        lifecycle_type: "mandate",
        from_state: "revoked",
        to_state: "current",
        requires_proposal: false,
      }],
    }),
  });
  assert.equal(
    evaluateTransition(restore).refusal_codes.includes("transition_not_allowed"),
    true,
  );
});

test("future observed or effective times cannot transition early", () => {
  const input = transitionInput();
  input.proposed_event = eventFixture(input.prior_snapshot, {
    observed_at: 100,
    effective_at: 100,
  });
  assert.equal(
    evaluateTransition(input).refusal_codes.includes("transition_not_allowed"),
    true,
  );
});

test("profile installs no default transition and recognition cannot become positive", () => {
  const input = transitionInput({ profile: transitionProfile({ transitions: [] }) });
  assert.equal(evaluateTransition(input).refusal_codes.includes("profile_rule_missing"), true);

  const prior = {
    ...input.prior_snapshot,
    lifecycle_type: "recognition",
    state: "unbound",
  };
  const invalid = transitionInput({
    prior_snapshot: prior,
    proposed_event: eventFixture(prior, {
      lifecycle_type: "recognition",
      from_state: "unbound",
      to_state: "recognized",
      event_kind: "recognition_unavailable_recorded",
    }),
  });
  assert.equal(evaluateTransition(invalid).outcome, "refused");
  assert.equal(evaluateTransition(invalid).refusal_codes.includes("transition_not_allowed"), true);
});

test("no transition can reach a positive crossing state", () => {
  const prior = snapshotFixture({
    lifecycle_type: "exercise",
    state: "unresolved",
    proposal_binding: PROPOSAL,
  });
  for (const forbiddenState of [
    "attempted",
    "executed",
    "recognized",
    "effected",
    "delivered",
    "crossed",
  ]) {
    const input = transitionInput({
      prior_snapshot: prior,
      proposed_event: eventFixture(prior, {
        lifecycle_type: "exercise",
        from_state: "unresolved",
        to_state: forbiddenState,
        event_kind: "exercise_evaluated",
        proposal_binding: PROPOSAL,
      }),
      profile: transitionProfile({
        transitions: [{
          lifecycle_type: "exercise",
          from_state: "unresolved",
          to_state: forbiddenState,
          event_kind: "exercise_evaluated",
          requires_proposal: true,
        }],
      }),
    });
    assert.equal(evaluateTransition(input).outcome, "refused", forbiddenState);
  }
});

test("self-mandate event refuses", () => {
  const input = transitionInput();
  input.proposed_event.event_kind = "grant_enlargement";
  const result = evaluateTransition(input);
  assert.equal(result.refusal_codes.includes("self_mandate_forbidden"), true);
});
