import {
  AUTHORITY_RECORD_TYPES,
  FIXTURE_NAMESPACE,
  RECORD_TYPES,
  SCHEMA_VERSION,
} from "./constants.mjs";
import {
  assertReferenceArray,
  validateSyntheticProfile,
  validateRecordEnvelope,
} from "./contracts.mjs";
import {
  identifyDerived,
  identifyMaterialized,
} from "./identity.mjs";
import { RefusalSignal } from "./refusal.mjs";
import {
  assertExactKeys,
  canonicalTextFromMaterialized,
} from "./safe-data.mjs";

const selfMandateKeys = new Set([
  "claim_ceiling",
  "grant_enlargement",
  "profile_selector",
  "recognition_rule_selector",
  "restoration",
  "self_grant",
  "waiver",
]);

const promotionKeys = Object.freeze({
  credential: "credential_promoted_to_authority",
  effect: "effect_promoted_to_authority",
  identity: "identity_promoted_to_authority",
});

const fusionReferenceTypes = Object.freeze({
  authority_domain_owner_ref: "authority_domain_owner",
  change_authority_ref: "change_authority",
  constitutive_event_ref: "constitutive_event",
  revocation_authority_ref: "revocation_authority",
  source_rule_ref: "source_rule",
});

function scanInvariantKeys(value, codes) {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      scanInvariantKeys(value[index], codes);
    }
    return;
  }
  for (const key of Object.keys(value)) {
    if (selfMandateKeys.has(key)) codes.add("self_mandate_forbidden");
    if (Object.hasOwn(promotionKeys, key)) codes.add(promotionKeys[key]);
    if (["authorized", "allow", "approved", "crossed", "executed"].includes(key)) {
      codes.add("positive_crossing_state_forbidden");
    }
    scanInvariantKeys(value[key], codes);
  }
}

function addSignal(codes, error) {
  if (error instanceof RefusalSignal) codes.add(error.code);
  else codes.add("internal_contract_refusal");
}

export function analyzeGraph(graph) {
  const codes = new Set();
  const validRecords = [];
  const seenIdentities = new Set();
  const successorsByPredecessor = new Map();
  scanInvariantKeys(graph, codes);

  try {
    assertExactKeys(graph, [
      "expected_propositions",
      "fixture_namespace",
      "graph_type",
      "mode",
      "profile",
      "records",
      "schema_version",
    ], "$" );
  } catch (error) { addSignal(codes, error); }
  if (graph.mode !== "synthetic") codes.add("live_mode_forbidden");
  if (graph.fixture_namespace !== FIXTURE_NAMESPACE) {
    codes.add("fixture_namespace_forbidden");
  }
  if (graph.graph_type !== "synthetic_authority_graph") {
    codes.add("unknown_binding_field");
  }
  if (graph.schema_version !== SCHEMA_VERSION) codes.add("schema_version_unknown");
  try {
    assertReferenceArray(graph.expected_propositions, "$.expected_propositions");
    if (!graph.expected_propositions.length) codes.add("required_evidence_missing");
  } catch (error) { addSignal(codes, error); }
  let profileValid = false;
  try {
    validateSyntheticProfile(
      graph.profile,
      Array.isArray(graph.expected_propositions) ? graph.expected_propositions : [],
      "$.profile",
    );
    profileValid = true;
  } catch (error) { addSignal(codes, error); }
  if (!Array.isArray(graph.records)) {
    codes.add("canonical_value_outside_grammar");
    return { codes: [...codes].sort(), result: null };
  }

  const contractByProposition = new Map();
  if (profileValid) {
    for (const contract of graph.profile.proposition_contracts) {
      contractByProposition.set(contract.proposition_id, contract.record_type);
    }
  }

  for (let index = 0; index < graph.records.length; index += 1) {
    const record = graph.records[index];
    try {
      const validated = validateRecordEnvelope(record, `$.records[${index}]`);
      validRecords.push(record);
      if (seenIdentities.has(validated.evidence_id)) codes.add("identity_mismatch");
      seenIdentities.add(validated.evidence_id);
      const predecessor = record.record_body.predecessor_ref;
      if (predecessor === "latest") codes.add("transition_input_stale");
      if (predecessor !== null && predecessor !== undefined) {
        const count = successorsByPredecessor.get(predecessor) ?? 0;
        successorsByPredecessor.set(predecessor, count + 1);
      }
      if (
        AUTHORITY_RECORD_TYPES.includes(record.record_type) &&
        record.record_body.source_class !== "synthetic_fixture_external"
      ) codes.add("external_authority_reference_missing");
    } catch (error) {
      addSignal(codes, error);
    }
    if (record && typeof record === "object" && !Array.isArray(record)) {
      if (
        AUTHORITY_RECORD_TYPES.includes(record.record_type) &&
        record.record_body?.source_class !== "synthetic_fixture_external"
      ) codes.add("external_authority_reference_missing");
      if (
        RECORD_TYPES.includes(record.record_type) &&
        record.schema_version === SCHEMA_VERSION &&
        record.record_body &&
        typeof record.record_body === "object"
      ) {
        try {
          const recomputed = identifyMaterialized({
            record_type: record.record_type,
            schema_version: record.schema_version,
            record_body: record.record_body,
          });
          if (recomputed.evidence_id !== record.evidence_id) {
            codes.add("identity_mismatch");
          }
        } catch (error) { addSignal(codes, error); }
      }
    }
  }

  for (const count of successorsByPredecessor.values()) {
    if (count > 1) codes.add("lifecycle_fork");
  }

  const proposalBodies = new Map();
  const proposalRecords = [];
  for (const record of validRecords) {
    if (
      record.record_type !== "authoritative_head" &&
      !["closed_search", "negative_evidence", "proposal"].includes(record.record_type)
    ) {
      const requiredType = contractByProposition.get(
        record.record_body.proposition_id,
      );
      if (requiredType !== record.record_type) codes.add("record_role_mismatch");
    }
    if (["closed_search", "negative_evidence"].includes(record.record_type)) {
      const requiredType = contractByProposition.get(
        record.record_body.proposition_id,
      );
      if (requiredType !== record.record_body.subject_record_type) {
        codes.add("record_role_mismatch");
      }
    }
    if (record.record_type === "proposal") proposalRecords.push(record);
    const binding = record.record_body.proposal_binding;
    if (!binding) continue;
    const tupleKey = `${binding.proposal_id}\u0000${binding.proposal_version}`;
    const priorDigest = proposalBodies.get(tupleKey);
    if (priorDigest && priorDigest !== binding.proposal_digest) {
      codes.add("proposal_identity_collision");
    }
    proposalBodies.set(tupleKey, binding.proposal_digest);
  }

  const recordsByIdentity = new Map(
    validRecords.map((record) => [record.evidence_id, record]),
  );
  if (profileValid) {
    for (const record of validRecords) {
      if (["closed_search", "negative_evidence"].includes(record.record_type)) {
        continue;
      }
      if (
        record.record_body.profile_ref !== graph.profile.profile_id ||
        record.record_body.rule_set_ref !== graph.profile.rule_set_id
      ) codes.add("profile_rule_missing");
    }
  }
  for (const record of validRecords) {
    if (
      ["authoritative_head", "closed_search", "negative_evidence"].includes(
        record.record_type,
      )
    ) continue;
    const headRef = record.record_body.authoritative_head_evidence_ref;
    if (headRef !== null) {
      const head = recordsByIdentity.get(headRef);
      if (
        !head ||
        head.record_type !== "authoritative_head" ||
        head.record_body.proposition_id !== record.record_body.proposition_id ||
        canonicalTextFromMaterialized(head.record_body.payload.references) !==
          canonicalTextFromMaterialized([record.record_body.proposition_id])
      ) codes.add("required_evidence_missing");
    }
  }
  for (const revocation of validRecords.filter((record) =>
    record.record_type === "revocation")) {
    for (const reference of revocation.record_body.payload.references) {
      const milestone = recordsByIdentity.get(reference);
      if (!milestone) {
        codes.add("required_evidence_missing");
        continue;
      }
      if (milestone.record_type !== "revocation_milestone") {
        codes.add("record_role_mismatch");
        continue;
      }
      if (
        milestone.record_body.revocation_proposition_id !==
          revocation.record_body.proposition_id ||
        canonicalTextFromMaterialized(milestone.record_body.payload.references) !==
          canonicalTextFromMaterialized([revocation.record_body.proposition_id]) ||
        milestone.record_body.profile_ref !== revocation.record_body.profile_ref ||
        milestone.record_body.rule_set_ref !== revocation.record_body.rule_set_ref
      ) codes.add("required_evidence_missing");
    }
  }
  for (const attempt of validRecords.filter((record) =>
    record.record_type === "retroactive_legitimacy_attempt")) {
    const checkpoint = recordsByIdentity.get(
      attempt.record_body.target_checkpoint_evidence_ref,
    );
    if (
      !checkpoint ||
      checkpoint.record_type !== "checkpoint" ||
      checkpoint.record_body.profile_ref !== attempt.record_body.profile_ref ||
      checkpoint.record_body.rule_set_ref !== attempt.record_body.rule_set_ref ||
      canonicalTextFromMaterialized(checkpoint.record_body.proposal_binding) !==
        canonicalTextFromMaterialized(attempt.record_body.proposal_binding)
    ) codes.add("required_evidence_missing");
    codes.add("post_effect_retroactive_legitimacy");
  }

  const validProposalTuples = [];
  for (const proposalRecord of proposalRecords) {
    const binding = proposalRecord.record_body.proposal_binding;
    const content = proposalRecord.record_body.payload.proposal_content;
    if (!binding || !content) {
      codes.add("proposal_identity_collision");
      continue;
    }
    const contentIdentity = identifyMaterialized({
      record_type: "proposal",
      schema_version: SCHEMA_VERSION,
      record_body: content,
    });
    if (
      binding.proposal_id !== content.proposal_id ||
      binding.proposal_version !== content.proposal_version ||
      binding.proposal_digest !== contentIdentity.evidence_id.slice(-64)
    ) codes.add("proposal_identity_collision");
    else validProposalTuples.push(binding);
  }
  for (const record of validRecords) {
    const binding = record.record_body.proposal_binding;
    if (!binding || record.record_type === "proposal") continue;
    const exactSource = validProposalTuples.some((proposalBinding) =>
      canonicalTextFromMaterialized(proposalBinding) ===
        canonicalTextFromMaterialized(binding));
    if (!exactSource) codes.add("required_evidence_missing");
  }

  const expected = new Set(
    Array.isArray(graph.expected_propositions) ? graph.expected_propositions : [],
  );
  if (profileValid) {
    for (const rule of graph.profile.fusion_rules) {
      if (!expected.has(rule.result_proposition)) codes.add("silent_proposition_fusion");
      for (const proposition of rule.required_propositions) {
        if (!expected.has(proposition)) codes.add("silent_proposition_fusion");
      }
      if (rule.required_propositions.includes(rule.result_proposition)) {
        codes.add("silent_proposition_fusion");
      }
      if (graph.profile.source_ref !== rule.source_rule_ref) {
        codes.add("profile_rule_missing");
      }
      const resolvedFusionReferences = [];
      for (const [field, requiredRecordType] of Object.entries(fusionReferenceTypes)) {
        const record = recordsByIdentity.get(rule[field]);
        if (!record) {
          codes.add("required_evidence_missing");
          continue;
        }
        if (record.record_type !== requiredRecordType) {
          codes.add("record_role_mismatch");
          continue;
        }
        resolvedFusionReferences.push(record);
      }
      for (const proposition of rule.required_propositions) {
        for (const record of validRecords.filter((candidate) =>
          candidate.record_type !== "authoritative_head" &&
          candidate.record_body.proposition_id === proposition)) {
          if (
            record.record_body.proposal_binding !== null &&
            canonicalTextFromMaterialized(record.record_body.proposal_binding) !==
              canonicalTextFromMaterialized(rule.proposal_binding)
          ) codes.add("proposal_version_mismatch");
        }
      }
      const resultType = contractByProposition.get(rule.result_proposition);
      if ([
        "checkpoint",
        "constitutive_step",
        "exercise",
        "recognition",
        "reserved_matter_disposition",
      ].includes(resultType)) {
        if (rule.proposal_binding === null) {
          codes.add("proposal_version_mismatch");
        } else if (!validProposalTuples.some((proposalBinding) =>
          canonicalTextFromMaterialized(proposalBinding) ===
            canonicalTextFromMaterialized(rule.proposal_binding))) {
          codes.add("required_evidence_missing");
        }
        const constitutiveEvent = resolvedFusionReferences.find((record) =>
          record.record_type === "constitutive_event");
        if (
          !constitutiveEvent ||
          canonicalTextFromMaterialized(
            constitutiveEvent.record_body.proposal_binding,
          ) !== canonicalTextFromMaterialized(rule.proposal_binding)
        ) codes.add("proposal_version_mismatch");
      }
    }
  }

  const sortedCodes = [...codes].sort();
  if (sortedCodes.length) return { codes: sortedCodes, result: null };
  const identity = identifyDerived("graph_validation", graph);
  return {
    codes: [],
    result: Object.freeze({
      outcome: "graph_validated",
      validation_id: identity.evidence_id,
      graph_identity: identity.evidence_id,
      record_count: validRecords.length,
      record_evidence_ids: Object.freeze(
        validRecords.map((record) => record.evidence_id).sort(),
      ),
      expected_propositions: Object.freeze([...graph.expected_propositions]),
      invariant_refusal_codes: Object.freeze([]),
      claim_basis: "deterministic_synthetic_graph_validation_only",
    }),
  };
}
