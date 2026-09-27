import { analyzeGraph } from "./graph.mjs";
import { identifyDerived } from "./identity.mjs";
import { refuse } from "./refusal.mjs";
import {
  assertCanonicalInstant,
  assertExactKeys,
} from "./safe-data.mjs";

function contestFrom(recordBody) {
  if (!recordBody.challenge_surface_closed) return "unknown";
  return recordBody.challenge_refs.length
    ? "disputed"
    : "no_contest_recorded";
}

function sourceAssessment(record, asOf) {
  const body = record.record_body;
  let lineage = "unknown";
  let lineageConflict = false;
  if (body.superseded_by_refs.length && body.withdrawal_evidence_refs.length) {
    lineageConflict = true;
  } else if (body.withdrawal_evidence_refs.length) {
    lineage = "withdrawn";
  } else if (body.superseded_by_refs.length) {
    lineage = "superseded";
  } else if (body.authoritative_head_evidence_ref !== null) {
    lineage = "current";
  }
  let freshness = "not_applicable";
  if (body.observed_at > asOf) {
    freshness = "unknown";
  } else if (body.valid_from !== null && body.valid_until !== null) {
    freshness = asOf >= body.valid_from && asOf < body.valid_until
      ? "current"
      : "expired";
  }
  return {
    assessment_type: "proposition_assessment",
    proposition_id: body.proposition_id,
    source_record_type: record.record_type,
    source_evidence_refs: [record.evidence_id],
    presence: "present",
    lineage,
    freshness,
    contest: contestFrom(body),
    lineage_conflict: lineageConflict,
  };
}

function searchAssessment(record, asOf) {
  const body = record.record_body;
  const exactTime = body.observed_at === asOf;
  const absent =
    exactTime && body.search_closed && body.matching_evidence_refs.length === 0;
  return {
    assessment_type: "proposition_assessment",
    proposition_id: body.proposition_id,
    source_record_type: body.subject_record_type,
    source_evidence_refs: [record.evidence_id],
    presence: absent ? "absent" : "unknown",
    lineage: "unknown",
    freshness: absent ? "not_applicable" : "unknown",
    contest: exactTime ? contestFrom(body) : "unknown",
    lineage_conflict: false,
  };
}

function unknownAssessment(propositionId) {
  return {
    assessment_type: "proposition_assessment",
    proposition_id: propositionId,
    source_record_type: "unknown",
    source_evidence_refs: [],
    presence: "unknown",
    lineage: "unknown",
    freshness: "unknown",
    contest: "unknown",
    lineage_conflict: false,
  };
}

function selectPositive(records, propositionId) {
  const positives = records.filter(
    (record) =>
      !["closed_search", "negative_evidence"].includes(record.record_type) &&
      record.record_type !== "authoritative_head" &&
      record.record_body.proposition_id === propositionId,
  );
  if (positives.length <= 1) return positives[0] ?? null;
  const currentCandidates = positives.filter(
    (record) =>
      record.record_body.authoritative_head_evidence_ref !== null &&
      record.record_body.superseded_by_refs.length === 0 &&
      record.record_body.withdrawal_evidence_refs.length === 0,
  );
  if (currentCandidates.length !== 1) {
    refuse("state_axis_collapsed", "$.graph.records", "ambiguous_positive_head");
  }
  return currentCandidates[0];
}

function selectSearch(records, propositionId) {
  const searches = records.filter(
    (record) =>
      ["closed_search", "negative_evidence"].includes(record.record_type) &&
      record.record_body.proposition_id === propositionId,
  );
  if (searches.length > 1) {
    refuse("identity_mismatch", "$.graph.records", "duplicate_search_surface");
  }
  return searches[0] ?? null;
}

export function projectMaterialized(input) {
  assertExactKeys(input, ["as_of", "graph"], "$" );
  assertCanonicalInstant(input.as_of, "$.as_of");
  const analysis = analyzeGraph(input.graph);
  if (analysis.codes.length) {
    refuse(analysis.codes[0], "$.graph", "graph_validation_required");
  }
  const assessments = [];
  const refusalCodes = new Set();
  for (const propositionId of input.graph.expected_propositions) {
    const positive = selectPositive(input.graph.records, propositionId);
    const search = selectSearch(input.graph.records, propositionId);
    let assessment;
    if (positive && search) {
      refusalCodes.add("state_axis_collapsed");
      assessment = sourceAssessment(positive, input.as_of);
    } else if (positive) {
      assessment = sourceAssessment(positive, input.as_of);
    } else if (search) {
      assessment = searchAssessment(search, input.as_of);
    } else {
      assessment = unknownAssessment(propositionId);
    }

    assessments.push(Object.freeze(assessment));
  }
  const recordsByIdentity = new Map(
    input.graph.records.map((record) => [record.evidence_id, record]),
  );
  for (const rule of input.graph.profile.fusion_rules) {
    const resultIndex = assessments.findIndex(
      (assessment) => assessment.proposition_id === rule.result_proposition,
    );
    if (resultIndex < 0 || assessments[resultIndex].presence !== "unknown") continue;
    const required = rule.required_propositions.map((propositionId) =>
      assessments.find((assessment) => assessment.proposition_id === propositionId));
    const referenceRecords = [
      rule.authority_domain_owner_ref,
      rule.change_authority_ref,
      rule.constitutive_event_ref,
      rule.revocation_authority_ref,
      rule.source_rule_ref,
    ].map((reference) => recordsByIdentity.get(reference));
    const referenceAssessments = referenceRecords.map((record) =>
      record ? sourceAssessment(record, input.as_of) : null);
    const assessmentIsCurrent = (assessment) =>
      assessment &&
      assessment.presence === "present" &&
      assessment.lineage === "current" &&
      assessment.freshness === "current" &&
      assessment.contest === "no_contest_recorded";
    if (
      required.length > 0 &&
      required.every(assessmentIsCurrent) &&
      referenceAssessments.every(assessmentIsCurrent)
    ) {
      assessments[resultIndex] = Object.freeze({
        assessment_type: "proposition_assessment",
        proposition_id: rule.result_proposition,
        source_record_type: "profile_bound_fusion",
        source_evidence_refs: [...new Set([
          ...required.flatMap((assessment) => assessment.source_evidence_refs),
          ...referenceRecords.map((record) => record.evidence_id),
        ])].sort(),
        presence: "present",
        lineage: "current",
        freshness: "current",
        contest: "no_contest_recorded",
        lineage_conflict: false,
      });
    }
  }
  for (const assessment of assessments) {
    const constitutive = input.graph.profile.constitutive_propositions.includes(
      assessment.proposition_id,
    );
    if (assessment.lineage_conflict) refusalCodes.add("frame_lineage_conflict");
    if (!constitutive) continue;
    if (assessment.presence !== "present") {
      refusalCodes.add("required_evidence_missing");
    }
    if (assessment.contest === "disputed") {
      refusalCodes.add("required_evidence_disputed");
    }
    if (assessment.contest === "unknown") {
      refusalCodes.add("required_evidence_missing");
    }
    if (assessment.freshness === "expired") {
      refusalCodes.add("authority_expired");
    }
    if (assessment.freshness === "unknown") {
      refusalCodes.add("required_evidence_missing");
    }
    if (assessment.lineage !== "current") {
      refusalCodes.add("required_evidence_missing");
    }
    if (
      assessment.source_record_type === "frame" &&
      input.graph.profile.frame_constitutive
    ) {
      if (assessment.presence !== "present") {
        refusalCodes.add("frame_presence_not_present");
      }
      if (assessment.freshness === "expired") {
        refusalCodes.add("expired_frame_silent_use");
      }
      if (
        assessment.presence === "present" &&
        assessment.lineage !== "current"
      ) refusalCodes.add("frame_lineage_not_current");
    }
  }
  assessments.sort((left, right) =>
    left.proposition_id < right.proposition_id ? -1 : 1,
  );
  const unresolvedPropositions = assessments
    .filter((assessment) =>
      assessment.presence !== "present" ||
      assessment.lineage !== "current" ||
      ["expired", "unknown"].includes(assessment.freshness) ||
      assessment.contest !== "no_contest_recorded",
    )
    .map((assessment) => assessment.proposition_id);
  const projectionBody = {
    as_of: input.as_of,
    assessments,
    graph_identity: analysis.result.graph_identity,
    profile_id: input.graph.profile.profile_id,
    profile_version: input.graph.profile.profile_version,
    refusal_codes: [...refusalCodes].sort(),
    rule_set_id: input.graph.profile.rule_set_id,
    rule_set_version: input.graph.profile.rule_set_version,
    unresolved_propositions: unresolvedPropositions,
  };
  const identity = identifyDerived("authority_projection", projectionBody);
  return Object.freeze({
    outcome: "authority_view_projected",
    view_type: "authority_projection",
    projection_id: identity.evidence_id,
    ...projectionBody,
    known_side_doors: Object.freeze([
      "authoritative_source_designation_external",
      "cross_process_head_state_absent",
      "institutional_rule_correctness_external",
      "semantic_relabeling_not_proven_absent",
    ]),
  });
}
