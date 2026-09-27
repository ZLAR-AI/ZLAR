import {
  CLAIM_TYPES,
  CLOSED_LIMITATIONS,
  KERNEL_VERSION,
} from "./constants.mjs";
import { analyzeGraph } from "./graph.mjs";
import { identifyDerived } from "./identity.mjs";
import { projectMaterialized } from "./projection.mjs";
import { refuse } from "./refusal.mjs";
import {
  assertCanonicalInstant,
  assertExactKeys,
  canonicalTextFromMaterialized,
} from "./safe-data.mjs";
import {
  evaluateMaterialized,
  publicTransitionResult,
} from "./transition.mjs";

function containsClaimCeiling(value) {
  if (value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      if (containsClaimCeiling(value[index])) return true;
    }
    return false;
  }
  for (const key of Object.keys(value)) {
    if (key === "claim_ceiling") return true;
    if (containsClaimCeiling(value[key])) return true;
  }
  return false;
}

function claim(claimType, result, evidenceRefs, asOf) {
  if (!CLAIM_TYPES.includes(claimType)) {
    refuse("claim_not_derivable", "$.claim_type", "closed_claim_registry");
  }
  return Object.freeze({
    claim_type: claimType,
    kernel_version: KERNEL_VERSION,
    derivation_rule: `derive_${claimType}_v1`,
    result,
    evidence_refs: Object.freeze([...evidenceRefs].sort()),
    as_of: asOf,
    limitations: CLOSED_LIMITATIONS,
    use_for: "private_synthetic_kernel_result_only",
    do_not_use_for: Object.freeze([
      "authority",
      "effect",
      "institutional_truth",
      "production",
      "public_attestation",
    ]),
    reset: "any_input_identity_or_projection_change_invalidates_claim",
    residue: "external_source_and_boundary_proof_remain_required",
  });
}

export function deriveClaimsMaterialized(input) {
  if (containsClaimCeiling(input)) {
    refuse("claim_ceiling_overreach", "$", "caller_authored_claim_ceiling");
  }
  assertExactKeys(input, [
    "as_of",
    "graph",
    "graph_validation",
    "projection",
    "transition_input",
    "transition_result",
  ], "$" );
  assertCanonicalInstant(input.as_of, "$.as_of");
  const analysis = analyzeGraph(input.graph);
  if (analysis.codes.length) {
    refuse(analysis.codes[0], "$.graph", "graph_validation_required");
  }
  if (
    canonicalTextFromMaterialized(input.graph_validation) !==
      canonicalTextFromMaterialized(analysis.result)
  ) refuse("identity_mismatch", "$.graph_validation", "validation_recomputation");
  const reprojection = projectMaterialized({
    graph: input.graph,
    as_of: input.as_of,
  });
  if (
    canonicalTextFromMaterialized(input.projection) !==
      canonicalTextFromMaterialized(reprojection)
  ) refuse("identity_mismatch", "$.projection", "projection_recomputation");

  const evidenceRefs = [
    analysis.result.validation_id,
    reprojection.projection_id,
    ...analysis.result.record_evidence_ids,
  ];
  const claims = [
    claim("canonical_bytes_verified", true, evidenceRefs, input.as_of),
    claim("evidence_identity_recomputed", true, evidenceRefs, input.as_of),
    claim("record_shape_validated", true, evidenceRefs, input.as_of),
    claim("cross_object_invariants_evaluated", true, evidenceRefs, input.as_of),
  ];
  if ((input.transition_input === null) !== (input.transition_result === null)) {
    refuse("claim_not_derivable", "$.transition_result", "transition_basis_pair");
  }
  if (input.transition_result !== null) {
    if (input.as_of !== input.transition_input.evaluation_time) {
      refuse(
        "claim_not_derivable",
        "$.as_of",
        "transition_evaluation_time_binding",
      );
    }
    if (
      input.transition_input.profile.profile_id !== input.graph.profile.profile_id ||
      input.transition_input.profile.profile_version !== input.graph.profile.profile_version ||
      input.transition_input.profile.rule_set_id !== input.graph.profile.rule_set_id ||
      input.transition_input.profile.rule_set_version !== input.graph.profile.rule_set_version
    ) refuse("identity_mismatch", "$.transition_input.profile", "cross_pipeline_profile_binding");
    const transitionProposal = input.transition_input.proposed_event.proposal_binding;
    if (transitionProposal !== null) {
      const proposalSourcePresent = input.graph.records.some((record) =>
        record.record_type === "proposal" &&
        canonicalTextFromMaterialized(record.record_body.proposal_binding) ===
          canonicalTextFromMaterialized(transitionProposal));
      if (!proposalSourcePresent) {
        refuse("required_evidence_missing", "$.transition_input.proposed_event", "proposal_source_binding");
      }
    }
    const reevaluation = evaluateMaterialized(input.transition_input);
    const exactTransitionResult = publicTransitionResult(reevaluation);
    if (
      canonicalTextFromMaterialized(input.transition_result) !==
        canonicalTextFromMaterialized(exactTransitionResult)
    ) refuse("identity_mismatch", "$.transition_result", "transition_recomputation");
    let transitionOutcome;
    if (reevaluation.codes.length) {
      transitionOutcome = "refused";
    } else {
      transitionOutcome = reevaluation.result.outcome;
    }
    if (transitionOutcome === "synthetic_transition_accepted") {
      claims.push(claim(
        "synthetic_transition_accepted",
        true,
        [...evidenceRefs, reevaluation.result.transition_receipt.event_id],
        input.as_of,
      ));
    } else if (transitionOutcome === "refused") {
      claims.push(claim(
        "synthetic_transition_refused",
        true,
        evidenceRefs,
        input.as_of,
      ));
    } else {
      refuse("claim_not_derivable", "$.transition_result", "transition_result");
    }
  }
  claims.sort((left, right) => left.claim_type < right.claim_type ? -1 : 1);
  const body = {
    as_of: input.as_of,
    claims,
    graph_identity: analysis.result.graph_identity,
    projection_id: reprojection.projection_id,
  };
  const identity = identifyDerived("proposition_assessment", body);
  return Object.freeze({
    outcome: "claims_derived",
    claims_id: identity.evidence_id,
    claims: Object.freeze(claims),
    claim_ceiling: "private_synthetic_source_evidence_only",
    external_evidence_required_for: Object.freeze([
      "consequence_incapability",
      "dependency_closure",
      "fixture_boundary",
      "privacy_and_secret_scan",
      "source_foundation_completion",
    ]),
  });
}
