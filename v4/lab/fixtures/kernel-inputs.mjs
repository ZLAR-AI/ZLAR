import { identifyEvidence } from "../../kernel/src/index.mjs";

const PROPOSAL_CONTENT = Object.freeze({
  proposal_id: "syn:v4:proposal:alpha",
  proposal_version: "v1",
  content_atoms: Object.freeze(["synthetic_action_alpha"]),
});

const proposalContentIdentity = identifyEvidence({
  record_type: "proposal",
  schema_version: "v1",
  record_body: PROPOSAL_CONTENT,
});

const PROPOSAL = Object.freeze({
  proposal_id: PROPOSAL_CONTENT.proposal_id,
  proposal_version: PROPOSAL_CONTENT.proposal_version,
  proposal_digest: proposalContentIdentity.evidence_id.slice(-64),
});

const categoryByType = Object.freeze({
  attention_selection: "attention_selection_declared",
  authoritative_head: "authoritative_head_designated",
  consequence_observation: "consequence_generic_non_identifying",
  checkpoint: "checkpoint_recorded",
  constitutive_step: "constitutive_step_recorded",
  credential_status: "credential_status_fact",
  exercise: "exercise_rule_declared",
  frame: "frame_declared",
  human_judgment_record: "human_judgment_attributed",
  interpretation: "interpretation_declared",
  mandate: "mandate_fact",
  observation: "observation_raw",
  proposal: "proposal_bytes",
  reserved_matter_disposition: "reserved_matter_disposition_recorded",
  retroactive_legitimacy_attempt: "retroactive_legitimacy_attempt_recorded",
  revocation: "revocation_fact",
  revocation_milestone: "revocation_milestone_fact",
});

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && "value" in descriptor) deepFreeze(descriptor.value);
  }
  return Object.freeze(value);
}

function envelope(recordType, recordBody) {
  const identity = identifyEvidence({
    record_type: recordType,
    schema_version: "v1",
    record_body: recordBody,
  });
  return deepFreeze({
    record_type: recordType,
    schema_version: "v1",
    evidence_id: identity.evidence_id,
    record_body: recordBody,
  });
}

function headDesignation(recordType, propositionId) {
  return sourceRecord("authoritative_head", propositionId, {
    authoritative_head_evidence_ref: null,
    source_ref: `syn:v4:source:${recordType}_head_designation`,
    payload: {
      category: "authoritative_head_designated",
      data_class: "synthetic_non_identifying",
      proposal_content: null,
      references: [propositionId],
    },
  });
}

function sourceRecord(recordType, propositionId, overrides = {}) {
  const head = recordType === "authoritative_head"
    ? null
    : headDesignation(recordType, propositionId);
  const proposalBinding = [
    "checkpoint",
    "constitutive_step",
    "exercise",
    "proposal",
    "reserved_matter_disposition",
    "retroactive_legitimacy_attempt",
  ].includes(recordType) ? PROPOSAL : null;
  return envelope(recordType, {
    proposition_id: propositionId,
    source_class: [
      "attention_selection",
      "consequence_observation",
      "checkpoint",
      "frame",
      "human_judgment_record",
      "interpretation",
      "observation",
      "retroactive_legitimacy_attempt",
    ].includes(recordType)
      ? "synthetic_fixture_observation"
      : "synthetic_fixture_external",
    source_ref: `syn:v4:source:${recordType}`,
    profile_ref: "syn:v4:profile:validator",
    rule_set_ref: "syn:v4:rules:validator",
    observed_at: 50,
    valid_from: 0,
    valid_until: 100,
    authoritative_head_evidence_ref: head?.evidence_id ?? null,
    predecessor_ref: null,
    superseded_by_refs: [],
    withdrawal_evidence_refs: [],
    challenge_refs: [],
    challenge_surface_closed: true,
    proposal_binding: proposalBinding,
    payload: {
      category: categoryByType[recordType],
      data_class: "synthetic_non_identifying",
      proposal_content: recordType === "proposal" ? PROPOSAL_CONTENT : null,
      references: [],
    },
    use_for: "private_synthetic_source_evidence_only",
    do_not_use_for: ["authority_effect", "production", "public_claim"],
    reset: "source_identity_change_invalidates_record",
    residue: [
      "attention_selection",
      "checkpoint",
      "consequence_observation",
      "frame",
      "human_judgment_record",
      "interpretation",
      "observation",
      "retroactive_legitimacy_attempt",
    ].includes(recordType)
      ? "synthetic_observation_remains_non_authoritative"
      : "institutional_truth_remains_external",
    ...overrides,
  });
}

function searchRecord(propositionId, subjectRecordType, overrides = {}) {
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

function expandRecords(records) {
  const expanded = [...records];
  for (const record of records) {
    if (
      !["authoritative_head", "closed_search", "negative_evidence"].includes(record.record_type) &&
      record.record_body.authoritative_head_evidence_ref !== null
    ) {
      const head = headDesignation(record.record_type, record.record_body.proposition_id);
      if (!expanded.some((candidate) => candidate.evidence_id === head.evidence_id)) {
        expanded.push(head);
      }
    }
  }
  if (
    records.some((record) => record.record_body.proposal_binding) &&
    !records.some((record) => record.record_type === "proposal")
  ) {
    const proposal = sourceRecord("proposal", "syn:v4:proposition:proposal");
    expanded.push(proposal);
    expanded.push(headDesignation("proposal", "syn:v4:proposition:proposal"));
  }
  return expanded;
}

function graph(contracts, records, profileOverrides = {}) {
  const expectedPropositions = contracts.map((contract) => contract.proposition_id).sort();
  return deepFreeze({
    mode: "synthetic",
    fixture_namespace: "zlar_v4_formation_fixtures_v1",
    graph_type: "synthetic_authority_graph",
    schema_version: "v1",
    expected_propositions: expectedPropositions,
    profile: {
      profile_type: "synthetic_rule_set",
      fixture_namespace: "zlar_v4_formation_fixtures_v1",
      profile_id: "syn:v4:profile:validator",
      profile_version: "v1",
      rule_set_id: "syn:v4:rules:validator",
      rule_set_version: "v1",
      source_class: "synthetic_fixture_external",
      source_ref: "syn:v4:evidence:profile_source",
      proposition_contracts: contracts,
      constitutive_propositions: [],
      frame_constitutive: false,
      fusion_rules: [],
      unknown_disposition: "unknown_refuse",
      use_for: "private_synthetic_source_evidence_only",
      do_not_use_for: ["authority", "effect", "partner_truth", "production"],
      reset: "profile_identity_change_requires_new_evidence",
      residue: "real_institutional_rules_remain_absent",
      ...profileOverrides,
    },
    records: expandRecords(records),
  });
}

function contract(propositionId, recordType) {
  return Object.freeze({ proposition_id: propositionId, record_type: recordType });
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

function transitionInput(
  lifecycleType,
  fromState,
  toState,
  eventKind,
  proposalBinding,
) {
  const snapshot = {
    snapshot_type: "lifecycle_snapshot",
    schema_version: "v1",
    lifecycle_type: lifecycleType,
    state: fromState,
    predecessor_ref: null,
    proposal_binding: proposalBinding,
    evidence_refs: ["syn:v4:evidence:transition_basis"],
  };
  snapshot.snapshot_id = identifyEvidence({
    record_type: "lifecycle_snapshot",
    schema_version: "v1",
    record_body: snapshotBody(snapshot),
  }).evidence_id;
  const eventBody = {
    claim_basis: "deterministic_synthetic_transition_evaluation_only",
    effective_at: 50,
    event_kind: eventKind,
    evidence_refs: ["syn:v4:evidence:transition_basis"],
    from_state: fromState,
    lifecycle_type: lifecycleType,
    observed_at: 50,
    prior_snapshot_id: snapshot.snapshot_id,
    profile_id: "syn:v4:profile:validator",
    profile_version: "v1",
    proposal_binding: proposalBinding,
    rule_set_id: "syn:v4:rules:validator",
    rule_set_version: "v1",
    source_class: "synthetic_fixture_external",
    source_ref: "syn:v4:evidence:transition_source",
    to_state: toState,
  };
  const event = {
    event_type: "synthetic_transition_event",
    schema_version: "v1",
    event_id: identifyEvidence({
      record_type: "synthetic_transition_event",
      schema_version: "v1",
      record_body: eventBody,
    }).evidence_id,
    ...eventBody,
  };
  return deepFreeze({
    mode: "synthetic",
    fixture_namespace: "zlar_v4_formation_fixtures_v1",
    prior_snapshot: snapshot,
    proposed_event: event,
    evaluation_time: 50,
    profile: {
      profile_type: "synthetic_transition_profile",
      fixture_namespace: "zlar_v4_formation_fixtures_v1",
      profile_id: "syn:v4:profile:validator",
      profile_version: "v1",
      rule_set_id: "syn:v4:rules:validator",
      rule_set_version: "v1",
      transitions: [{
        lifecycle_type: lifecycleType,
        from_state: fromState,
        to_state: toState,
        event_kind: eventKind,
        requires_proposal: proposalBinding !== null,
      }],
      observed_time_rule: "not_after_evaluation",
      effective_time_rule: "not_after_evaluation",
      unknown_disposition: "unknown_refuse",
      use_for: "private_synthetic_source_evidence_only",
      do_not_use_for: ["authority", "effect", "execution", "partner_truth", "recognition"],
      reset: "profile_identity_change_requires_new_evidence",
      residue: "real_institutional_rules_remain_absent",
    },
  });
}

const mandateContract = contract("syn:v4:proposition:mandate", "mandate");
const frameContract = contract("syn:v4:proposition:frame", "frame");
const stepContract = contract("syn:v4:proposition:constitutive_step", "constitutive_step");
const reservedContract = contract(
  "syn:v4:proposition:reserved_matter_disposition",
  "reserved_matter_disposition",
);
const revocationContract = contract("syn:v4:proposition:revocation", "revocation");
const observationContract = contract("syn:v4:proposition:observation", "observation");
const credentialContract = contract("syn:v4:proposition:credential_status", "credential_status");
const exerciseContract = contract("syn:v4:proposition:exercise", "exercise");
const consequenceContract = contract(
  "syn:v4:proposition:consequence_observation",
  "consequence_observation",
);
const checkpointContract = contract("syn:v4:proposition:checkpoint", "checkpoint");
const rewriteAttemptContract = contract(
  "syn:v4:proposition:retroactive_legitimacy_attempt",
  "retroactive_legitimacy_attempt",
);

const mandate = () => sourceRecord("mandate", mandateContract.proposition_id);
const frame = (overrides = {}) => sourceRecord("frame", frameContract.proposition_id, overrides);
const step = () => sourceRecord("constitutive_step", stepContract.proposition_id);
const reserved = () => sourceRecord(
  "reserved_matter_disposition",
  reservedContract.proposition_id,
);

function revocationMilestone(
  milestoneKind,
  effectiveAt,
  revocationPropositionId = revocationContract.proposition_id,
) {
  const milestoneContract = contract(
    `syn:v4:proposition:revocation_milestone:${milestoneKind}`,
    "revocation_milestone",
  );
  const milestone = sourceRecord(
    "revocation_milestone",
    milestoneContract.proposition_id,
    {
      effective_at: effectiveAt,
      milestone_kind: milestoneKind,
      revocation_proposition_id: revocationPropositionId,
      payload: {
        category: "revocation_milestone_fact",
        data_class: "synthetic_non_identifying",
        proposal_content: null,
        references: [revocationPropositionId],
      },
    },
  );
  return { milestone, milestoneContract };
}

function revocationGraph(
  milestoneKind,
  effectiveAt,
  profileOverrides = {},
  options = {},
) {
  const { milestone, milestoneContract } = revocationMilestone(
    milestoneKind,
    effectiveAt,
    options.revocationPropositionId,
  );
  const revocationReferences = options.referenceMilestone === false
    ? []
    : [milestone.evidence_id];
  return graph([mandateContract, revocationContract, milestoneContract], [
    mandate(),
    sourceRecord("revocation", revocationContract.proposition_id, {
      payload: {
        category: "revocation_fact",
        data_class: "synthetic_non_identifying",
        proposal_content: null,
        references: revocationReferences,
      },
    }),
    milestone,
  ], profileOverrides);
}

export const CASE_KERNEL_INPUTS = deepFreeze({
  "syn:v4:case:standing": {
    graph: graph([mandateContract], [mandate()]),
    as_of: 50,
    transition_input: transitionInput("mandate", "pending", "current", "mandate_fact_recorded", null),
  },
  "syn:v4:case:per_action": {
    graph: graph([mandateContract, stepContract], [mandate(), step()], {
      constitutive_propositions: [stepContract.proposition_id],
    }),
    as_of: 50,
    transition_input: transitionInput("exercise", "unresolved", "eligible_synthetic", "exercise_evaluated", PROPOSAL),
  },
  "syn:v4:case:per_action_mismatch": {
    graph: graph([mandateContract, stepContract], [
      mandate(),
      sourceRecord("constitutive_step", stepContract.proposition_id, {
        proposal_binding: { ...PROPOSAL, proposal_digest: "b".repeat(64) },
      }),
    ], { constitutive_propositions: [stepContract.proposition_id] }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:per_action_missing": {
    graph: graph([mandateContract, stepContract], [mandate()], {
      constitutive_propositions: [stepContract.proposition_id],
    }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:per_action_stale": {
    graph: graph([mandateContract, stepContract], [
      mandate(),
      sourceRecord("constitutive_step", stepContract.proposition_id, {
        valid_until: 50,
      }),
    ], { constitutive_propositions: [stepContract.proposition_id] }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:reserved": {
    graph: graph([mandateContract, stepContract, reservedContract], [mandate(), step(), reserved()], {
      constitutive_propositions: [reservedContract.proposition_id, stepContract.proposition_id].sort(),
    }),
    as_of: 50,
    transition_input: transitionInput("exercise", "unresolved", "eligible_synthetic", "exercise_evaluated", PROPOSAL),
  },
  "syn:v4:case:reserved_mismatch": {
    graph: graph([mandateContract, stepContract, reservedContract], [
      mandate(),
      step(),
      sourceRecord("reserved_matter_disposition", reservedContract.proposition_id, {
        proposal_binding: { ...PROPOSAL, proposal_digest: "b".repeat(64) },
      }),
    ], {
      constitutive_propositions: [reservedContract.proposition_id, stepContract.proposition_id].sort(),
    }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:reserved_missing": {
    graph: graph([mandateContract, stepContract, reservedContract], [mandate()], {
      constitutive_propositions: [reservedContract.proposition_id, stepContract.proposition_id].sort(),
    }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:reserved_stale": {
    graph: graph([mandateContract, stepContract, reservedContract], [
      mandate(),
      step(),
      sourceRecord("reserved_matter_disposition", reservedContract.proposition_id, {
        valid_until: 50,
      }),
    ], {
      constitutive_propositions: [reservedContract.proposition_id, stepContract.proposition_id].sort(),
    }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:revoked": {
    graph: revocationGraph("institutional_effective", 50),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:expired": {
    graph: graph([mandateContract], [sourceRecord("mandate", mandateContract.proposition_id, {
      valid_until: 50,
    })], { constitutive_propositions: [mandateContract.proposition_id] }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:propagation_lag_refuse": {
    graph: revocationGraph("internal_decision", 50, {
      unknown_disposition: "unknown_refuse",
    }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:propagation_lag_pending": {
    graph: revocationGraph("notice_publication", 50, {
      unknown_disposition: "pending_review",
    }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:propagation_credential_disabled": {
    graph: revocationGraph("credential_disabled", 50),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:propagation_external_cutoff": {
    graph: revocationGraph("external_reliance_cutoff", 50),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:propagation_future_institutional": {
    graph: revocationGraph("institutional_effective", 60),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:propagation_unreferenced_institutional": {
    graph: revocationGraph("institutional_effective", 50, {}, {
      referenceMilestone: false,
    }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:disputed": {
    graph: graph([frameContract], [frame({
      valid_until: 50,
      authoritative_head_evidence_ref: null,
      superseded_by_refs: ["syn:v4:evidence:frame_successor"],
      challenge_refs: ["syn:v4:evidence:frame_challenge"],
    })], {
      constitutive_propositions: [frameContract.proposition_id],
      frame_constitutive: true,
    }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:lineage_conflict": {
    graph: graph([frameContract], [frame({
      authoritative_head_evidence_ref: null,
      superseded_by_refs: ["syn:v4:evidence:frame_successor"],
      withdrawal_evidence_refs: ["syn:v4:evidence:frame_withdrawal"],
    })], {
      constitutive_propositions: [frameContract.proposition_id],
      frame_constitutive: true,
    }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:missing": {
    graph: graph([mandateContract], [], {
      constitutive_propositions: [mandateContract.proposition_id],
    }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:missing_challenged_absence": {
    graph: graph([mandateContract], [searchRecord(
      mandateContract.proposition_id,
      "mandate",
      { challenge_refs: ["syn:v4:evidence:mandate_search_challenge"] },
    )], { constitutive_propositions: [mandateContract.proposition_id] }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:stale_frame_nonconstitutive": {
    graph: graph([frameContract], [frame({ valid_until: 50 })]),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:stale_frame_constitutive": {
    graph: graph([frameContract], [frame({ valid_until: 50 })], {
      constitutive_propositions: [frameContract.proposition_id],
      frame_constitutive: true,
    }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:fresh_eyes": {
    graph: graph([observationContract], [sourceRecord("observation", observationContract.proposition_id)]),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:fresh_eyes_checkpoint": {
    graph: graph([observationContract], [
      sourceRecord("observation", observationContract.proposition_id),
      sourceRecord("checkpoint", "syn:v4:proposition:inherited_checkpoint"),
    ]),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:fresh_eyes_consequence": {
    graph: graph([observationContract], [
      sourceRecord("observation", observationContract.proposition_id),
      sourceRecord("consequence_observation", "syn:v4:proposition:inherited_consequence"),
    ]),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:fresh_eyes_inherited": {
    graph: graph([observationContract], [
      sourceRecord("observation", observationContract.proposition_id),
      frame(),
    ]),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:fresh_eyes_interpretation": {
    graph: graph([observationContract], [
      sourceRecord("observation", observationContract.proposition_id),
      sourceRecord("interpretation", "syn:v4:proposition:inherited_interpretation"),
    ]),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:fresh_eyes_judgment": {
    graph: graph([observationContract], [
      sourceRecord("observation", observationContract.proposition_id),
      sourceRecord("human_judgment_record", "syn:v4:proposition:inherited_judgment"),
    ]),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:no_authority": {
    graph: graph([mandateContract], [searchRecord(mandateContract.proposition_id, "mandate")], {
      constitutive_propositions: [mandateContract.proposition_id],
    }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:credential_laundering": {
    graph: graph([credentialContract, mandateContract], [
      sourceRecord("credential_status", credentialContract.proposition_id),
      searchRecord(mandateContract.proposition_id, "mandate"),
    ], { constitutive_propositions: [mandateContract.proposition_id] }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:proposal_mutation": {
    graph: graph([exerciseContract], [
      sourceRecord("exercise", exerciseContract.proposition_id, {
        proposal_binding: { ...PROPOSAL, proposal_digest: "b".repeat(64) },
      }),
      sourceRecord("exercise", exerciseContract.proposition_id, {
        proposal_binding: {
          ...PROPOSAL,
          proposal_digest: "c".repeat(64),
          proposal_version: "v0",
        },
      }),
    ], { constitutive_propositions: [exerciseContract.proposition_id] }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:silent_fusion": {
    graph: graph([exerciseContract, observationContract], [
      sourceRecord("observation", observationContract.proposition_id),
    ], { constitutive_propositions: [exerciseContract.proposition_id] }),
    as_of: 50,
    transition_input: null,
  },
  "syn:v4:case:forward_consequence": {
    graph: graph([consequenceContract, observationContract], [
      sourceRecord("consequence_observation", consequenceContract.proposition_id, {
        payload: {
          category: "consequence_generic_non_identifying",
          data_class: "synthetic_non_identifying",
          proposal_content: null,
          references: ["syn:v4:observation:forward_only"],
        },
      }),
      sourceRecord("observation", observationContract.proposition_id),
    ]),
    as_of: 50,
    transition_input: transitionInput(
      "consequence",
      "not_observed",
      "synthetic_observation_recorded",
      "consequence_observed",
      null,
    ),
  },
  "syn:v4:case:forward_consequence_rewrite": {
    graph: (() => {
      const checkpoint = sourceRecord("checkpoint", checkpointContract.proposition_id);
      const attempt = sourceRecord(
        "retroactive_legitimacy_attempt",
        rewriteAttemptContract.proposition_id,
        {
          target_checkpoint_evidence_ref: checkpoint.evidence_id,
          payload: {
            category: "retroactive_legitimacy_attempt_recorded",
            data_class: "synthetic_non_identifying",
            proposal_content: null,
            references: [checkpoint.evidence_id],
          },
        },
      );
      return graph(
        [checkpointContract, rewriteAttemptContract],
        [checkpoint, attempt],
      );
    })(),
    as_of: 50,
    transition_input: null,
  },
});
