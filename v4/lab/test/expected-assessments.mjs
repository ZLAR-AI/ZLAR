const base = Object.freeze({
  assessment_class: "private_synthetic_source_evidence_only",
  crossing: "structurally_unavailable",
  effect: "not_attempted",
  authority_domain_binding: "unbound_placeholder",
  effect_adapter_binding: "unbound_placeholder",
  claim_ceiling: "private_synthetic_source_evidence_only",
});

function satisfied(caseId, syntheticResult, extra = {}) {
  return {
    ...base,
    outcome: "synthetic_profile_satisfied",
    case_id: caseId,
    synthetic_result: syntheticResult,
    ...extra,
  };
}

function refused(caseId, refusalCodes, extra = {}) {
  return {
    ...base,
    outcome: "refused",
    case_id: caseId,
    refusal_codes: [...refusalCodes].sort(),
    state_unchanged: true,
    ...extra,
  };
}

export const EXPECTED_ASSESSMENTS = Object.freeze({
  "syn:v4:case:credential_laundering": refused(
    "syn:v4:case:credential_laundering",
    ["authority_grant_missing", "credential_promoted_to_authority", "required_evidence_missing"],
  ),
  "syn:v4:case:disputed": refused(
    "syn:v4:case:disputed",
    [
      "authority_expired",
      "expired_frame_silent_use",
      "frame_lineage_not_current",
      "required_evidence_disputed",
      "required_evidence_missing",
    ],
  ),
  "syn:v4:case:expired": refused("syn:v4:case:expired", ["authority_expired"]),
  "syn:v4:case:forward_consequence": satisfied(
    "syn:v4:case:forward_consequence",
    "new_non_authoritative_observation_input_recorded",
  ),
  "syn:v4:case:forward_consequence_rewrite": refused(
    "syn:v4:case:forward_consequence_rewrite",
    ["post_effect_retroactive_legitimacy"],
  ),
  "syn:v4:case:fresh_eyes": satisfied(
    "syn:v4:case:fresh_eyes",
    "fresh_eyes_input_isolation",
  ),
  "syn:v4:case:fresh_eyes_checkpoint": refused(
    "syn:v4:case:fresh_eyes_checkpoint",
    ["fresh_eyes_inherited_input"],
  ),
  "syn:v4:case:fresh_eyes_consequence": refused(
    "syn:v4:case:fresh_eyes_consequence",
    ["fresh_eyes_inherited_input"],
  ),
  "syn:v4:case:fresh_eyes_inherited": refused(
    "syn:v4:case:fresh_eyes_inherited",
    ["fresh_eyes_inherited_input"],
  ),
  "syn:v4:case:fresh_eyes_interpretation": refused(
    "syn:v4:case:fresh_eyes_interpretation",
    ["fresh_eyes_inherited_input"],
  ),
  "syn:v4:case:fresh_eyes_judgment": refused(
    "syn:v4:case:fresh_eyes_judgment",
    ["fresh_eyes_inherited_input"],
  ),
  "syn:v4:case:lineage_conflict": refused(
    "syn:v4:case:lineage_conflict",
    ["frame_lineage_conflict", "frame_lineage_not_current", "required_evidence_missing"],
  ),
  "syn:v4:case:missing": refused(
    "syn:v4:case:missing",
    ["authority_grant_unknown", "required_evidence_missing"],
  ),
  "syn:v4:case:missing_challenged_absence": refused(
    "syn:v4:case:missing_challenged_absence",
    ["authority_grant_missing", "required_evidence_disputed", "required_evidence_missing"],
  ),
  "syn:v4:case:no_authority": refused(
    "syn:v4:case:no_authority",
    ["authority_grant_missing", "required_evidence_missing"],
  ),
  "syn:v4:case:per_action": satisfied(
    "syn:v4:case:per_action",
    "exact_constitutive_step_satisfied_synthetically",
  ),
  "syn:v4:case:per_action_mismatch": refused(
    "syn:v4:case:per_action_mismatch",
    ["per_action_step_missing", "proposal_identity_collision", "required_evidence_missing"],
  ),
  "syn:v4:case:per_action_missing": refused(
    "syn:v4:case:per_action_missing",
    ["per_action_step_missing", "required_evidence_missing"],
  ),
  "syn:v4:case:per_action_stale": refused(
    "syn:v4:case:per_action_stale",
    ["authority_expired", "per_action_step_missing"],
  ),
  "syn:v4:case:propagation_credential_disabled": refused(
    "syn:v4:case:propagation_credential_disabled",
    ["required_evidence_missing"],
    { revocation_profile_disposition: "unknown_refuse" },
  ),
  "syn:v4:case:propagation_external_cutoff": refused(
    "syn:v4:case:propagation_external_cutoff",
    ["required_evidence_missing"],
    { revocation_profile_disposition: "unknown_refuse" },
  ),
  "syn:v4:case:propagation_future_institutional": refused(
    "syn:v4:case:propagation_future_institutional",
    ["required_evidence_missing"],
    { revocation_profile_disposition: "unknown_refuse" },
  ),
  "syn:v4:case:propagation_lag_pending": refused(
    "syn:v4:case:propagation_lag_pending",
    ["required_evidence_missing"],
    { revocation_profile_disposition: "pending_review" },
  ),
  "syn:v4:case:propagation_lag_refuse": refused(
    "syn:v4:case:propagation_lag_refuse",
    ["required_evidence_missing"],
    { revocation_profile_disposition: "unknown_refuse" },
  ),
  "syn:v4:case:propagation_unreferenced_institutional": refused(
    "syn:v4:case:propagation_unreferenced_institutional",
    ["required_evidence_missing"],
    { revocation_profile_disposition: "unknown_refuse" },
  ),
  "syn:v4:case:proposal_mutation": refused(
    "syn:v4:case:proposal_mutation",
    ["proposal_identity_collision", "proposal_version_mismatch", "required_evidence_missing"],
  ),
  "syn:v4:case:reserved": satisfied(
    "syn:v4:case:reserved",
    "reserved_disposition_and_step_satisfied_synthetically",
  ),
  "syn:v4:case:reserved_mismatch": refused(
    "syn:v4:case:reserved_mismatch",
    [
      "per_action_step_missing",
      "proposal_identity_collision",
      "required_evidence_missing",
      "reserved_matter_disposition_missing",
    ],
  ),
  "syn:v4:case:reserved_missing": refused(
    "syn:v4:case:reserved_missing",
    ["per_action_step_missing", "required_evidence_missing", "reserved_matter_disposition_missing"],
  ),
  "syn:v4:case:reserved_stale": refused(
    "syn:v4:case:reserved_stale",
    ["authority_expired", "reserved_matter_disposition_missing"],
  ),
  "syn:v4:case:revoked": refused("syn:v4:case:revoked", ["authority_revoked"]),
  "syn:v4:case:silent_fusion": refused(
    "syn:v4:case:silent_fusion",
    ["required_evidence_missing", "silent_proposition_fusion"],
  ),
  "syn:v4:case:stale_frame_constitutive": refused(
    "syn:v4:case:stale_frame_constitutive",
    ["authority_expired", "expired_frame_silent_use"],
  ),
  "syn:v4:case:stale_frame_nonconstitutive": satisfied(
    "syn:v4:case:stale_frame_nonconstitutive",
    "inspectability_narrowed_only",
    {
      inspectability_axes: {
        presence: "present",
        lineage: "current",
        freshness: "expired",
        contest: "no_contest_recorded",
      },
    },
  ),
  "syn:v4:case:standing": satisfied(
    "syn:v4:case:standing",
    "exercise_predicates_satisfied_synthetically",
  ),
});
