import {
  identifyEvidence,
} from "../../src/index.mjs";

export const PROPOSAL_CONTENT = Object.freeze({
  proposal_id: "syn:v4:proposal:alpha",
  proposal_version: "v1",
  content_atoms: Object.freeze(["synthetic_action_alpha"]),
});

const proposalContentIdentity = identifyEvidence({
  record_type: "proposal",
  schema_version: "v1",
  record_body: PROPOSAL_CONTENT,
});

export const PROPOSAL = Object.freeze({
  proposal_id: PROPOSAL_CONTENT.proposal_id,
  proposal_version: PROPOSAL_CONTENT.proposal_version,
  proposal_digest: proposalContentIdentity.evidence_id.slice(-64),
});

const categoryByType = Object.freeze({
  attention_selection: "attention_selection_declared",
  authority_domain_owner: "authority_domain_owner_declared",
  authoritative_head: "authoritative_head_designated",
  authority_profile: "authority_profile_declared",
  challenge: "challenge_recorded",
  change_authority: "change_authority_declared",
  checkpoint: "checkpoint_recorded",
  consequence_observation: "consequence_generic_non_identifying",
  constitutive_event: "constitutive_event_recorded",
  constitutive_step: "constitutive_step_recorded",
  credential_status: "credential_status_fact",
  exercise: "exercise_rule_declared",
  frame: "frame_declared",
  human_judgment_record: "human_judgment_attributed",
  interpretation: "interpretation_declared",
  mandate: "mandate_fact",
  observation: "observation_raw",
  proposal: "proposal_bytes",
  recognition: "recognition_unavailable",
  recovery_disposition: "recovery_disposition_recorded",
  recovery_observation: "recovery_observation_recorded",
  recovery_request: "recovery_request_recorded",
  remedy_disposition: "remedy_disposition_recorded",
  remedy_request: "remedy_request_recorded",
  reserved_matter_disposition: "reserved_matter_disposition_recorded",
  retroactive_legitimacy_attempt: "retroactive_legitimacy_attempt_recorded",
  revocation: "revocation_fact",
  revocation_authority: "revocation_authority_declared",
  revocation_milestone: "revocation_milestone_fact",
  source_rule: "source_rule_declared",
});

export function envelope(recordType, recordBody) {
  const identified = identifyEvidence({
    record_type: recordType,
    schema_version: "v1",
    record_body: recordBody,
  });
  if (identified.outcome !== "evidence_identified") {
    throw new Error(`fixture identity refused: ${identified.refusal_codes}`);
  }
  return {
    record_type: recordType,
    schema_version: "v1",
    evidence_id: identified.evidence_id,
    record_body: recordBody,
  };
}

export function sourceRecord(recordType, propositionId, overrides = {}) {
  const defaultHead = recordType === "authoritative_head"
    ? null
    : headDesignation(recordType, propositionId).evidence_id;
  const body = {
    proposition_id: propositionId,
    source_class: [
      "attention_selection",
      "consequence_observation",
      "frame",
      "human_judgment_record",
      "interpretation",
      "observation",
      "recovery_observation",
    ].includes(recordType)
      ? "synthetic_fixture_observation"
      : "synthetic_fixture_external",
    source_ref: `syn:v4:source:${recordType}`,
    profile_ref: "syn:v4:profile:validator",
    rule_set_ref: "syn:v4:rules:validator",
    observed_at: 50,
    valid_from: 0,
    valid_until: 100,
    authoritative_head_evidence_ref: defaultHead,
    predecessor_ref: null,
    superseded_by_refs: [],
    withdrawal_evidence_refs: [],
    challenge_refs: [],
    challenge_surface_closed: true,
    proposal_binding: [
      "checkpoint",
      "constitutive_event",
      "constitutive_step",
      "exercise",
      "human_judgment_record",
      "proposal",
      "recognition",
      "reserved_matter_disposition",
      "retroactive_legitimacy_attempt",
    ].includes(recordType) ? PROPOSAL : null,
    payload: {
      category: categoryByType[recordType],
      data_class: "synthetic_non_identifying",
      references: recordType === "authoritative_head" ? [propositionId] : [],
      proposal_content: recordType === "proposal" ? PROPOSAL_CONTENT : null,
    },
    use_for: "private_synthetic_source_evidence_only",
    do_not_use_for: ["authority_effect", "production", "public_claim"],
    reset: "source_identity_change_invalidates_record",
    residue: recordType === "observation"
      ? "synthetic_observation_remains_non_authoritative"
      : "institutional_truth_remains_external",
    ...overrides,
  };
  return envelope(recordType, body);
}

export function headDesignation(recordType, propositionId) {
  return sourceRecord("authoritative_head", propositionId, {
    source_ref: `syn:v4:source:${recordType}_head_designation`,
    payload: {
      category: "authoritative_head_designated",
      data_class: "synthetic_non_identifying",
      references: [propositionId],
      proposal_content: null,
    },
  });
}

export function searchRecord(
  propositionId,
  subjectRecordType,
  overrides = {},
) {
  return envelope("closed_search", {
    proposition_id: propositionId,
    subject_record_type: subjectRecordType,
    source_class: "synthetic_fixture_external",
    source_ref: `syn:v4:source:${subjectRecordType}_search`,
    profile_ref: "syn:v4:profile:validator",
    rule_set_ref: "syn:v4:rules:validator",
    observed_at: 50,
    search_closed: true,
    search_surface_ref: `syn:v4:evidence:${subjectRecordType}_surface`,
    matching_evidence_refs: [],
    challenge_refs: [],
    challenge_surface_closed: true,
    use_for: "synthetic_authority_projection_input_only",
    do_not_use_for: ["authority_effect", "production", "public_claim"],
    reset: "search_scope_change_invalidates_absence",
    residue: "open_universe_remains_unknown",
    ...overrides,
  });
}

export function syntheticProfile(
  expectedPropositions,
  overrides = {},
) {
  return {
    profile_type: "synthetic_rule_set",
    fixture_namespace: "zlar_v4_formation_fixtures_v1",
    profile_id: "syn:v4:profile:validator",
    profile_version: "v1",
    rule_set_id: "syn:v4:rules:validator",
    rule_set_version: "v1",
    source_class: "synthetic_fixture_external",
    source_ref: "syn:v4:evidence:profile_source",
    proposition_contracts: expectedPropositions.map((propositionId) => ({
      proposition_id: propositionId,
      record_type: propositionId.split(":").at(-1),
    })),
    constitutive_propositions: [],
    frame_constitutive: false,
    fusion_rules: [],
    unknown_disposition: "unknown_refuse",
    use_for: "private_synthetic_source_evidence_only",
    do_not_use_for: ["authority", "effect", "partner_truth", "production"],
    reset: "profile_identity_change_requires_new_evidence",
    residue: "real_institutional_rules_remain_absent",
    ...overrides,
  };
}

export function graphFixture({
  expectedPropositions = [
    "syn:v4:proposition:frame",
    "syn:v4:proposition:mandate",
  ],
  records = [
    sourceRecord("frame", "syn:v4:proposition:frame"),
    sourceRecord("mandate", "syn:v4:proposition:mandate"),
  ],
  profileOverrides = {},
} = {}) {
  const expandedRecords = [...records];
  for (const record of records) {
    if (
      record.record_type !== "authoritative_head" &&
      !["closed_search", "negative_evidence"].includes(record.record_type) &&
      Object.hasOwn(record.record_body, "authoritative_head_evidence_ref") &&
      record.record_body.authoritative_head_evidence_ref !== null
    ) {
      const head = headDesignation(
        record.record_type,
        record.record_body.proposition_id,
      );
      if (!expandedRecords.some((candidate) => candidate.evidence_id === head.evidence_id)) {
        expandedRecords.push(head);
      }
    }
  }
  if (
    (records.some((record) => record.record_body?.proposal_binding) ||
      profileOverrides.fusion_rules?.some((rule) => rule.proposal_binding)) &&
    !records.some((record) => record.record_type === "proposal")
  ) {
    const proposal = sourceRecord("proposal", "syn:v4:proposition:proposal");
    expandedRecords.push(proposal);
    const proposalHead = headDesignation("proposal", "syn:v4:proposition:proposal");
    expandedRecords.push(proposalHead);
  }
  return {
    mode: "synthetic",
    fixture_namespace: "zlar_v4_formation_fixtures_v1",
    graph_type: "synthetic_authority_graph",
    schema_version: "v1",
    expected_propositions: [...expectedPropositions].sort(),
    profile: syntheticProfile(expectedPropositions, profileOverrides),
    records: expandedRecords,
  };
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

export function snapshotFixture(overrides = {}) {
  const snapshot = {
    snapshot_type: "lifecycle_snapshot",
    schema_version: "v1",
    lifecycle_type: "mandate",
    state: "pending",
    predecessor_ref: null,
    proposal_binding: null,
    evidence_refs: ["syn:v4:evidence:mandate_fact"],
    ...overrides,
  };
  const identity = identifyEvidence({
    record_type: "lifecycle_snapshot",
    schema_version: "v1",
    record_body: snapshotBody(snapshot),
  });
  return { ...snapshot, snapshot_id: identity.evidence_id };
}

function eventBody(event) {
  const body = { ...event };
  delete body.event_id;
  delete body.event_type;
  delete body.schema_version;
  return body;
}

export function eventFixture(priorSnapshot, overrides = {}) {
  const event = {
    event_type: "synthetic_transition_event",
    schema_version: "v1",
    event_kind: "mandate_fact_recorded",
    source_class: "synthetic_fixture_external",
    source_ref: "syn:v4:evidence:mandate_source",
    lifecycle_type: priorSnapshot.lifecycle_type,
    from_state: priorSnapshot.state,
    to_state: "current",
    prior_snapshot_id: priorSnapshot.snapshot_id,
    proposal_binding: priorSnapshot.proposal_binding,
    profile_id: "syn:v4:profile:validator",
    profile_version: "v1",
    rule_set_id: "syn:v4:rules:validator",
    rule_set_version: "v1",
    observed_at: 50,
    effective_at: 50,
    evidence_refs: ["syn:v4:evidence:mandate_fact"],
    claim_basis: "deterministic_synthetic_transition_evaluation_only",
    ...overrides,
  };
  const identity = identifyEvidence({
    record_type: "synthetic_transition_event",
    schema_version: "v1",
    record_body: eventBody(event),
  });
  return { ...event, event_id: identity.evidence_id };
}

export function transitionProfile(overrides = {}) {
  return {
    profile_type: "synthetic_transition_profile",
    fixture_namespace: "zlar_v4_formation_fixtures_v1",
    profile_id: "syn:v4:profile:validator",
    profile_version: "v1",
    rule_set_id: "syn:v4:rules:validator",
    rule_set_version: "v1",
    transitions: [{
      lifecycle_type: "mandate",
      from_state: "pending",
      to_state: "current",
      event_kind: "mandate_fact_recorded",
      requires_proposal: false,
    }],
    observed_time_rule: "not_after_evaluation",
    effective_time_rule: "not_after_evaluation",
    unknown_disposition: "unknown_refuse",
    use_for: "private_synthetic_source_evidence_only",
    do_not_use_for: ["authority", "effect", "execution", "partner_truth", "recognition"],
    reset: "profile_identity_change_requires_new_evidence",
    residue: "real_institutional_rules_remain_absent",
    ...overrides,
  };
}

export function transitionInput(overrides = {}) {
  const priorSnapshot = overrides.prior_snapshot ?? snapshotFixture();
  return {
    mode: "synthetic",
    fixture_namespace: "zlar_v4_formation_fixtures_v1",
    prior_snapshot: priorSnapshot,
    proposed_event: overrides.proposed_event ?? eventFixture(priorSnapshot),
    evaluation_time: 50,
    profile: transitionProfile(),
    ...overrides,
  };
}
