import { types } from "node:util";

import {
  canonicalize,
  deriveClaims,
  evaluateTransition,
  projectAuthorityView,
  validateGraph,
} from "../../kernel/src/index.mjs";
import { CASE_CATALOG } from "./catalog.mjs";

const base = Object.freeze({
  assessment_class: "private_synthetic_source_evidence_only",
  crossing: "structurally_unavailable",
  effect: "not_attempted",
  authority_domain_binding: "unbound_placeholder",
  effect_adapter_binding: "unbound_placeholder",
  claim_ceiling: "private_synthetic_source_evidence_only",
});

const canonicalRequests = Object.freeze(CASE_CATALOG.map((entry) =>
  canonicalize(entry.request).canonical_text));

function refused(codes, caseId, extra = {}) {
  return Object.freeze({
    ...base,
    outcome: "refused",
    case_id: caseId,
    refusal_codes: Object.freeze([...new Set(codes)].sort()),
    state_unchanged: true,
    ...extra,
  });
}

function assessmentByType(projection, recordType) {
  return projection.assessments.find(
    (assessment) => assessment.source_record_type === recordType ||
      (assessment.source_record_type === "unknown" &&
        assessment.proposition_id.endsWith(`:${recordType}`)),
  );
}

function recordsOf(graph, recordType) {
  return graph.records.filter((record) => record.record_type === recordType);
}

function exactAssessment(projection, record) {
  return projection.assessments.find((assessment) =>
    assessment.proposition_id === record.record_body.proposition_id &&
    assessment.source_evidence_refs.includes(record.evidence_id));
}

function evaluateEntry(entry) {
  const caseId = entry.request.case_id;
  const { graph, as_of: asOf, transition_input: transitionInput } = entry.kernel_input;
  const validation = validateGraph(graph);
  const codes = new Set();
  let projection = null;
  let transitionResult = null;
  const extra = {};

  if (validation.outcome === "refused") {
    for (const code of validation.refusal_codes) codes.add(code);
  } else {
    projection = projectAuthorityView({ graph, as_of: asOf });
    if (projection.outcome === "refused") {
      for (const code of projection.refusal_codes) codes.add(code);
    } else {
      for (const code of projection.refusal_codes) codes.add(code);
    }
  }

  if (transitionInput !== null && validation.outcome !== "refused") {
    transitionResult = evaluateTransition(transitionInput);
    if (transitionResult.outcome === "refused") {
      for (const code of transitionResult.refusal_codes) codes.add(code);
    }
  }

  if (projection !== null && projection.outcome !== "refused") {
    const claims = deriveClaims({
      graph,
      as_of: asOf,
      graph_validation: validation,
      projection,
      transition_input: transitionInput,
      transition_result: transitionResult,
    });
    if (claims.outcome === "refused") {
      for (const code of claims.refusal_codes) codes.add(code);
    }

    const contractById = new Map(graph.profile.proposition_contracts.map((contract) =>
      [contract.proposition_id, contract.record_type]));
    for (const assessment of projection.assessments) {
      const recordType = contractById.get(assessment.proposition_id);
      if (
        recordType === "constitutive_step" &&
        assessment.freshness === "expired"
      ) codes.add("per_action_step_missing");
      if (
        recordType === "reserved_matter_disposition" &&
        assessment.freshness === "expired"
      ) codes.add("reserved_matter_disposition_missing");
      if (assessment.presence === "present") continue;
      if (recordType === "constitutive_step") codes.add("per_action_step_missing");
      if (recordType === "reserved_matter_disposition") {
        codes.add("reserved_matter_disposition_missing");
      }
      if (recordType === "mandate") {
        codes.add(
          assessment.presence === "absent"
            ? "authority_grant_missing"
            : "authority_grant_unknown",
        );
      }
    }
    const frameAssessment = assessmentByType(projection, "frame");
    if (
      frameAssessment &&
      frameAssessment.freshness === "expired" &&
      !graph.profile.frame_constitutive
    ) {
      extra.inspectability_axes = Object.freeze({
        presence: frameAssessment.presence,
        lineage: frameAssessment.lineage,
        freshness: frameAssessment.freshness,
        contest: frameAssessment.contest,
      });
    }
    const mandateAssessment = assessmentByType(projection, "mandate");
    if (
      recordsOf(graph, "credential_status").length &&
      mandateAssessment?.presence !== "present"
    ) codes.add("credential_promoted_to_authority");
    const exerciseAssessment = assessmentByType(projection, "exercise");
    if (
      exerciseAssessment?.presence === "unknown" &&
      recordsOf(graph, "observation").length &&
      graph.profile.fusion_rules.length === 0
    ) codes.add("silent_proposition_fusion");
  }

  if (
    validation.outcome !== "refused" &&
    projection !== null &&
    projection.outcome !== "refused" &&
    recordsOf(graph, "revocation").length
  ) {
    for (const revocation of recordsOf(graph, "revocation")) {
      const referencedMilestones = recordsOf(graph, "revocation_milestone").filter(
        (milestone) =>
          revocation.record_body.payload.references.includes(milestone.evidence_id) &&
          milestone.record_body.revocation_proposition_id ===
            revocation.record_body.proposition_id &&
          milestone.record_body.profile_ref === revocation.record_body.profile_ref &&
          milestone.record_body.rule_set_ref === revocation.record_body.rule_set_ref,
      );
      const milestone = referencedMilestones.length === 1
        ? referencedMilestones[0]
        : null;
      const assessment = milestone === null
        ? null
        : exactAssessment(projection, milestone);
      const currentMilestone =
        milestone !== null &&
        milestone.record_body.observed_at <= asOf &&
        milestone.record_body.effective_at <= asOf &&
        assessment?.presence === "present" &&
        assessment.lineage === "current" &&
        assessment.freshness === "current" &&
        assessment.contest === "no_contest_recorded";
      if (
        currentMilestone &&
        milestone.record_body.milestone_kind === "institutional_effective"
      ) {
        codes.add("authority_revoked");
      } else {
        codes.add("required_evidence_missing");
        extra.revocation_profile_disposition = graph.profile.unknown_disposition;
      }
    }
  }
  if (
    validation.outcome === "refused" &&
    (codes.has("proposal_identity_collision") ||
      codes.has("proposal_version_mismatch") ||
      codes.has("required_evidence_missing"))
  ) {
    if (recordsOf(graph, "constitutive_step").length) {
      codes.add("per_action_step_missing");
    }
    if (recordsOf(graph, "reserved_matter_disposition").length) {
      codes.add("reserved_matter_disposition_missing");
    }
  }
  const inheritedFreshEyesTypes = [
    "attention_selection",
    "checkpoint",
    "consequence_observation",
    "frame",
    "human_judgment_record",
    "interpretation",
  ];
  if (
    inheritedFreshEyesTypes.some((recordType) => recordsOf(graph, recordType).length) &&
    graph.profile.proposition_contracts.length === 1 &&
    graph.profile.proposition_contracts[0].record_type === "observation"
  ) {
    codes.delete("record_role_mismatch");
    codes.add("fresh_eyes_inherited_input");
  }
  if (codes.size) return refused(codes, caseId, extra);

  let syntheticResult = "exercise_predicates_satisfied_synthetically";
  if (recordsOf(graph, "reserved_matter_disposition").length) {
    syntheticResult = "reserved_disposition_and_step_satisfied_synthetically";
  } else if (recordsOf(graph, "constitutive_step").length) {
    syntheticResult = "exact_constitutive_step_satisfied_synthetically";
  } else if (recordsOf(graph, "consequence_observation").length) {
    syntheticResult = "new_non_authoritative_observation_input_recorded";
  } else if (
    graph.profile.proposition_contracts.length === 1 &&
    graph.profile.proposition_contracts[0].record_type === "observation"
  ) {
    syntheticResult = "fresh_eyes_input_isolation";
  } else if (extra.inspectability_axes) {
    syntheticResult = "inspectability_narrowed_only";
  }
  return Object.freeze({
    ...base,
    outcome: "synthetic_profile_satisfied",
    case_id: caseId,
    synthetic_result: syntheticResult,
    ...extra,
  });
}

function boundaryRefusal(code) {
  return Object.freeze({
    ...base,
    outcome: "refused",
    refusal_codes: Object.freeze([code]),
    state_unchanged: true,
  });
}

export function evaluateSyntheticCase(input) {
  if (types.isProxy(input)) return boundaryRefusal("proxy_object_forbidden");
  const admitted = canonicalize(input);
  if (admitted.outcome !== "canonicalized") {
    return boundaryRefusal("executable_reference_forbidden");
  }
  for (let index = 0; index < canonicalRequests.length; index += 1) {
    if (admitted.canonical_text === canonicalRequests[index]) {
      return evaluateEntry(CASE_CATALOG[index]);
    }
  }
  return boundaryRefusal("synthetic_context_required");
}
