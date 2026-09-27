import {
  AUTHORITY_RECORD_TYPES,
  DERIVED_RECORD_TYPES,
  FIXTURE_NAMESPACE,
  FORBIDDEN_DERIVED_AXIS_KEYS,
  RECORD_TYPES,
  SCHEMA_VERSION,
} from "./constants.mjs";
import { identifyMaterialized } from "./identity.mjs";
import { refuse } from "./refusal.mjs";
import {
  assertCanonicalInstant,
  assertExactKeys,
  assertSyntheticId,
  canonicalTextFromMaterialized,
} from "./safe-data.mjs";

const positiveRecordTypes = RECORD_TYPES.filter(
  (recordType) => ![
    "closed_search",
    "negative_evidence",
    "synthetic_transition_event",
  ].includes(recordType),
);

const sourceClasses = Object.freeze([
  "synthetic_fixture_external",
  "synthetic_fixture_observation",
]);

const payloadCategoryByRecordType = Object.freeze({
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
  lifecycle_snapshot: "lifecycle_snapshot_recorded",
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

const allowedUseFor = Object.freeze([
  "private_synthetic_source_evidence_only",
  "synthetic_authority_projection_input_only",
  "synthetic_discernment_input_only",
  "synthetic_transition_input_only",
]);

function assertClosedText(value, allowed, path, code = "unknown_binding_field") {
  if (typeof value !== "string" || !allowed.includes(value)) {
    refuse(code, path, "closed_value_registry");
  }
}

export function assertReference(value, path, nullable = false) {
  if (nullable && value === null) return;
  if (typeof value !== "string") {
    refuse("non_synthetic_identifier", path, "reference_string");
  }
  if (
    /^syn:v4:[a-z][a-z0-9_]*(?::[a-z0-9_]+)*$/u.test(value) ||
    /^zlar:v4:evidence:v1:sha256:[0-9a-f]{64}$/u.test(value)
  ) return;
  refuse("non_synthetic_identifier", path, "closed_reference_grammar");
}

export function assertReferenceArray(value, path) {
  if (!Array.isArray(value)) {
    refuse("canonical_value_outside_grammar", path, "reference_array");
  }
  const seen = new Set();
  let prior = null;
  for (let index = 0; index < value.length; index += 1) {
    const reference = value[index];
    assertReference(reference, `${path}[${index}]`);
    if (seen.has(reference)) {
      refuse("identity_mismatch", `${path}[${index}]`, "duplicate_reference");
    }
    if (prior !== null && prior > reference) {
      refuse("canonical_value_outside_grammar", path, "unsorted_reference_set");
    }
    seen.add(reference);
    prior = reference;
  }
}

function assertClosedTokenArray(value, path) {
  if (!Array.isArray(value)) {
    refuse("canonical_value_outside_grammar", path, "token_array");
  }
  const seen = new Set();
  let prior = null;
  for (let index = 0; index < value.length; index += 1) {
    const token = value[index];
    if (typeof token !== "string" || !/^[a-z][a-z0-9_]{0,63}$/u.test(token)) {
      refuse("unknown_binding_field", `${path}[${index}]`, "closed_token");
    }
    if (seen.has(token) || (prior !== null && prior > token)) {
      refuse("identity_mismatch", path, "duplicate_or_unsorted_token");
    }
    seen.add(token);
    prior = token;
  }
}

function assertNoDerivedAxisKeys(value, path = "$") {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      assertNoDerivedAxisKeys(value[index], `${path}[${index}]`);
    }
    return;
  }
  for (const key of Object.keys(value)) {
    if (FORBIDDEN_DERIVED_AXIS_KEYS.includes(key)) {
      refuse("derived_axis_input_forbidden", `${path}.${key}`, "source_axis");
    }
    assertNoDerivedAxisKeys(value[key], `${path}.${key}`);
  }
}

export function assertProposalBinding(value, path, nullable = true) {
  if (nullable && value === null) return;
  assertExactKeys(
    value,
    ["proposal_digest", "proposal_id", "proposal_version"],
    path,
  );
  assertSyntheticId(value.proposal_id, `${path}.proposal_id`);
  if (typeof value.proposal_version !== "string" || !/^v[1-9][0-9]*$/u.test(value.proposal_version)) {
    refuse("proposal_version_mismatch", `${path}.proposal_version`, "proposal_tuple");
  }
  if (typeof value.proposal_digest !== "string" || !/^[0-9a-f]{64}$/u.test(value.proposal_digest)) {
    refuse("proposal_identity_collision", `${path}.proposal_digest`, "proposal_tuple");
  }
}

function assertPayload(recordType, value, path) {
  assertExactKeys(
    value,
    ["category", "data_class", "proposal_content", "references"],
    path,
  );
  assertClosedText(
    value.data_class,
    ["synthetic_non_identifying"],
    `${path}.data_class`,
  );
  assertClosedText(
    value.category,
    [payloadCategoryByRecordType[recordType]],
    `${path}.category`,
  );
  assertReferenceArray(value.references, `${path}.references`);
  if (recordType === "proposal") {
    assertExactKeys(
      value.proposal_content,
      ["content_atoms", "proposal_id", "proposal_version"],
      `${path}.proposal_content`,
    );
    assertSyntheticId(
      value.proposal_content.proposal_id,
      `${path}.proposal_content.proposal_id`,
    );
    if (
      typeof value.proposal_content.proposal_version !== "string" ||
      !/^v[1-9][0-9]*$/u.test(value.proposal_content.proposal_version)
    ) refuse("proposal_version_mismatch", `${path}.proposal_content`, "proposal_content");
    assertClosedTokenArray(
      value.proposal_content.content_atoms,
      `${path}.proposal_content.content_atoms`,
    );
  } else if (value.proposal_content !== null) {
    refuse("proposal_identity_collision", `${path}.proposal_content`, "non_proposal_content");
  }
}

function assertLifecycleBounds(body, path) {
  if (body.valid_from === null && body.valid_until === null) return;
  assertCanonicalInstant(body.valid_from, `${path}.valid_from`);
  assertCanonicalInstant(body.valid_until, `${path}.valid_until`);
  if (body.valid_from >= body.valid_until) {
    refuse("canonical_instant_invalid", path, "invalid_validity_interval");
  }
}

function assertPositiveBody(recordType, body, path) {
  const exactKeys = [
    "authoritative_head_evidence_ref",
    "challenge_refs",
    "challenge_surface_closed",
    "do_not_use_for",
    "observed_at",
    "payload",
    "predecessor_ref",
    "profile_ref",
    "proposal_binding",
    "proposition_id",
    "reset",
    "residue",
    "rule_set_ref",
    "source_class",
    "source_ref",
    "superseded_by_refs",
    "use_for",
    "valid_from",
    "valid_until",
    "withdrawal_evidence_refs",
  ];
  if (recordType === "revocation_milestone") {
    exactKeys.push("effective_at", "milestone_kind", "revocation_proposition_id");
    exactKeys.sort();
  }
  if (recordType === "retroactive_legitimacy_attempt") {
    exactKeys.push("target_checkpoint_evidence_ref");
    exactKeys.sort();
  }
  assertExactKeys(body, exactKeys, path);
  assertSyntheticId(body.proposition_id, `${path}.proposition_id`);
  assertClosedText(body.source_class, sourceClasses, `${path}.source_class`);
  if (
    AUTHORITY_RECORD_TYPES.includes(recordType) &&
    body.source_class !== "synthetic_fixture_external"
  ) {
    refuse(
      "external_authority_reference_missing",
      `${path}.source_class`,
      "authority_provenance",
    );
  }
  assertReference(body.source_ref, `${path}.source_ref`);
  assertReference(body.profile_ref, `${path}.profile_ref`);
  assertReference(body.rule_set_ref, `${path}.rule_set_ref`);
  assertCanonicalInstant(body.observed_at, `${path}.observed_at`);
  if (recordType === "revocation_milestone") {
    assertCanonicalInstant(body.effective_at, `${path}.effective_at`);
    assertSyntheticId(
      body.revocation_proposition_id,
      `${path}.revocation_proposition_id`,
    );
    assertClosedText(body.milestone_kind, [
      "credential_disabled",
      "external_reliance_cutoff",
      "institutional_effective",
      "internal_decision",
      "notice_publication",
    ], `${path}.milestone_kind`);
    if (
      canonicalTextFromMaterialized(body.payload.references) !==
      canonicalTextFromMaterialized([body.revocation_proposition_id])
    ) {
      refuse(
        "required_evidence_missing",
        `${path}.payload.references`,
        "revocation_milestone_scope",
      );
    }
  }
  if (recordType === "retroactive_legitimacy_attempt") {
    assertReference(
      body.target_checkpoint_evidence_ref,
      `${path}.target_checkpoint_evidence_ref`,
    );
    if (
      canonicalTextFromMaterialized(body.payload.references) !==
      canonicalTextFromMaterialized([body.target_checkpoint_evidence_ref])
    ) {
      refuse(
        "required_evidence_missing",
        `${path}.payload.references`,
        "retroactive_attempt_checkpoint_scope",
      );
    }
  }
  assertLifecycleBounds(body, path);
  assertReference(
    body.authoritative_head_evidence_ref,
    `${path}.authoritative_head_evidence_ref`,
    true,
  );
  assertReference(body.predecessor_ref, `${path}.predecessor_ref`, true);
  assertReferenceArray(body.superseded_by_refs, `${path}.superseded_by_refs`);
  assertReferenceArray(
    body.withdrawal_evidence_refs,
    `${path}.withdrawal_evidence_refs`,
  );
  assertReferenceArray(body.challenge_refs, `${path}.challenge_refs`);
  if (typeof body.challenge_surface_closed !== "boolean") {
    refuse("required_evidence_missing", `${path}.challenge_surface_closed`, "challenge_surface");
  }
  assertProposalBinding(body.proposal_binding, `${path}.proposal_binding`);
  assertPayload(recordType, body.payload, `${path}.payload`);
  assertClosedText(body.use_for, allowedUseFor, `${path}.use_for`);
  assertClosedTokenArray(body.do_not_use_for, `${path}.do_not_use_for`);
  assertClosedText(body.reset, [
    "new_source_fact_requires_linked_successor",
    "source_identity_change_invalidates_record",
  ], `${path}.reset`);
  assertClosedText(body.residue, [
    "institutional_truth_remains_external",
    "synthetic_observation_remains_non_authoritative",
  ], `${path}.residue`);
}

function assertSearchBody(body, path) {
  assertExactKeys(body, [
    "challenge_refs",
    "challenge_surface_closed",
    "do_not_use_for",
    "matching_evidence_refs",
    "observed_at",
    "profile_ref",
    "proposition_id",
    "reset",
    "residue",
    "rule_set_ref",
    "search_closed",
    "search_surface_ref",
    "source_class",
    "source_ref",
    "subject_record_type",
    "use_for",
  ], path);
  assertSyntheticId(body.proposition_id, `${path}.proposition_id`);
  if (!positiveRecordTypes.includes(body.subject_record_type)) {
    refuse("record_type_unknown", `${path}.subject_record_type`, "search_subject");
  }
  assertClosedText(body.source_class, sourceClasses, `${path}.source_class`);
  assertReference(body.source_ref, `${path}.source_ref`);
  assertReference(body.profile_ref, `${path}.profile_ref`);
  assertReference(body.rule_set_ref, `${path}.rule_set_ref`);
  assertReference(body.search_surface_ref, `${path}.search_surface_ref`);
  assertCanonicalInstant(body.observed_at, `${path}.observed_at`);
  if (typeof body.search_closed !== "boolean" || typeof body.challenge_surface_closed !== "boolean") {
    refuse("required_evidence_missing", path, "search_closure");
  }
  assertReferenceArray(body.matching_evidence_refs, `${path}.matching_evidence_refs`);
  assertReferenceArray(body.challenge_refs, `${path}.challenge_refs`);
  assertClosedText(body.use_for, allowedUseFor, `${path}.use_for`);
  assertClosedTokenArray(body.do_not_use_for, `${path}.do_not_use_for`);
  assertClosedText(body.reset, ["search_scope_change_invalidates_absence"], `${path}.reset`);
  assertClosedText(body.residue, ["open_universe_remains_unknown"], `${path}.residue`);
}

export function validateRecordEnvelope(record, path) {
  assertExactKeys(
    record,
    ["evidence_id", "record_body", "record_type", "schema_version"],
    path,
  );
  if (DERIVED_RECORD_TYPES.includes(record.record_type)) {
    refuse("derived_view_used_as_source", `${path}.record_type`, "source_role");
  }
  if (!RECORD_TYPES.includes(record.record_type)) {
    refuse("record_type_unknown", `${path}.record_type`, "closed_record_registry");
  }
  if (record.schema_version !== SCHEMA_VERSION) {
    refuse("schema_version_unknown", `${path}.schema_version`, "closed_schema_registry");
  }
  if (record.record_type === "synthetic_transition_event") {
    refuse("record_type_unknown", `${path}.record_type`, "graph_source_record");
  }
  assertNoDerivedAxisKeys(record.record_body, `${path}.record_body`);
  if (["closed_search", "negative_evidence"].includes(record.record_type)) {
    assertSearchBody(record.record_body, `${path}.record_body`);
  } else {
    assertPositiveBody(record.record_type, record.record_body, `${path}.record_body`);
  }
  const identity = identifyMaterialized({
    record_type: record.record_type,
    schema_version: record.schema_version,
    record_body: record.record_body,
  });
  if (record.evidence_id !== identity.evidence_id) {
    refuse("identity_mismatch", `${path}.evidence_id`, "evidence_recomputation");
  }
  return Object.freeze({
    record,
    canonical_record: canonicalTextFromMaterialized(record),
    evidence_id: identity.evidence_id,
  });
}

function assertFusionRule(rule, path) {
  assertExactKeys(rule, [
    "authority_domain_owner_ref",
    "change_authority_ref",
    "constitutive_event_ref",
    "effective_time_rule",
    "freshness_rule",
    "proposal_binding",
    "required_propositions",
    "result_proposition",
    "revocation_authority_ref",
    "source_rule_ref",
    "unknown_disposition",
  ], path);
  assertSyntheticId(rule.result_proposition, `${path}.result_proposition`);
  assertProposalBinding(rule.proposal_binding, `${path}.proposal_binding`);
  assertReferenceArray(rule.required_propositions, `${path}.required_propositions`);
  if (rule.required_propositions.length === 0) {
    refuse(
      "silent_proposition_fusion",
      `${path}.required_propositions`,
      "empty_fusion_basis",
    );
  }
  for (const field of [
    "authority_domain_owner_ref",
    "change_authority_ref",
    "constitutive_event_ref",
    "revocation_authority_ref",
    "source_rule_ref",
  ]) assertReference(rule[field], `${path}.${field}`);
  assertClosedText(rule.effective_time_rule, ["explicit_canonical_instant"], `${path}.effective_time_rule`);
  assertClosedText(rule.freshness_rule, ["half_open_interval"], `${path}.freshness_rule`);
  assertClosedText(rule.unknown_disposition, ["pending_review", "unknown_refuse"], `${path}.unknown_disposition`);
}

export function validateSyntheticProfile(profile, expectedPropositions, path) {
  assertExactKeys(profile, [
    "constitutive_propositions",
    "do_not_use_for",
    "fixture_namespace",
    "frame_constitutive",
    "fusion_rules",
    "profile_id",
    "profile_type",
    "profile_version",
    "proposition_contracts",
    "reset",
    "residue",
    "rule_set_id",
    "rule_set_version",
    "source_class",
    "source_ref",
    "unknown_disposition",
    "use_for",
  ], path);
  if (
    profile.profile_type !== "synthetic_rule_set" ||
    profile.fixture_namespace !== FIXTURE_NAMESPACE ||
    profile.profile_version !== SCHEMA_VERSION ||
    profile.rule_set_version !== SCHEMA_VERSION ||
    profile.source_class !== "synthetic_fixture_external"
  ) refuse("synthetic_context_required", path, "synthetic_profile");
  assertSyntheticId(profile.profile_id, `${path}.profile_id`);
  assertSyntheticId(profile.rule_set_id, `${path}.rule_set_id`);
  assertReference(profile.source_ref, `${path}.source_ref`);
  if (!Array.isArray(profile.proposition_contracts)) {
    refuse("profile_rule_missing", `${path}.proposition_contracts`, "proposition_contracts");
  }
  const contractIds = new Set();
  for (let index = 0; index < profile.proposition_contracts.length; index += 1) {
    const contract = profile.proposition_contracts[index];
    assertExactKeys(
      contract,
      ["proposition_id", "record_type"],
      `${path}.proposition_contracts[${index}]`,
    );
    assertSyntheticId(
      contract.proposition_id,
      `${path}.proposition_contracts[${index}].proposition_id`,
    );
    if (
      !positiveRecordTypes.includes(contract.record_type) ||
      contract.record_type === "authoritative_head" ||
      contractIds.has(contract.proposition_id)
    ) refuse("profile_rule_missing", `${path}.proposition_contracts[${index}]`, "proposition_contract");
    contractIds.add(contract.proposition_id);
  }
  if (
    canonicalTextFromMaterialized([...contractIds].sort()) !==
      canonicalTextFromMaterialized([...expectedPropositions].sort())
  ) refuse("profile_rule_missing", `${path}.proposition_contracts`, "expected_proposition_contracts");
  assertReferenceArray(profile.constitutive_propositions, `${path}.constitutive_propositions`);
  if (typeof profile.frame_constitutive !== "boolean") {
    refuse("profile_rule_missing", `${path}.frame_constitutive`, "profile_rule");
  }
  if (!Array.isArray(profile.fusion_rules)) {
    refuse("profile_rule_missing", `${path}.fusion_rules`, "fusion_rules");
  }
  const fusionResults = new Set();
  for (let index = 0; index < profile.fusion_rules.length; index += 1) {
    const rule = profile.fusion_rules[index];
    assertFusionRule(rule, `${path}.fusion_rules[${index}]`);
    if (fusionResults.has(rule.result_proposition)) {
      refuse("silent_proposition_fusion", `${path}.fusion_rules`, "duplicate_fusion_result");
    }
    fusionResults.add(rule.result_proposition);
  }
  assertClosedText(profile.unknown_disposition, ["pending_review", "unknown_refuse"], `${path}.unknown_disposition`);
  assertClosedText(profile.use_for, ["private_synthetic_source_evidence_only"], `${path}.use_for`);
  assertClosedTokenArray(profile.do_not_use_for, `${path}.do_not_use_for`);
  assertClosedText(profile.reset, ["profile_identity_change_requires_new_evidence"], `${path}.reset`);
  assertClosedText(profile.residue, ["real_institutional_rules_remain_absent"], `${path}.residue`);
  if (
    canonicalTextFromMaterialized(profile.constitutive_propositions) !==
      canonicalTextFromMaterialized(
        profile.constitutive_propositions.filter((item) => expectedPropositions.includes(item)),
      )
  ) refuse("profile_rule_missing", `${path}.constitutive_propositions`, "unknown_proposition");
}

export function assertGraphEnvelope(graph) {
  assertExactKeys(graph, [
    "expected_propositions",
    "fixture_namespace",
    "graph_type",
    "mode",
    "profile",
    "records",
    "schema_version",
  ], "$" );
  if (graph.mode !== "synthetic") refuse("live_mode_forbidden", "$.mode", "mode");
  if (graph.fixture_namespace !== FIXTURE_NAMESPACE) {
    refuse("fixture_namespace_forbidden", "$.fixture_namespace", "fixture_namespace");
  }
  if (graph.graph_type !== "synthetic_authority_graph") {
    refuse("unknown_binding_field", "$.graph_type", "graph_type");
  }
  if (graph.schema_version !== SCHEMA_VERSION) {
    refuse("schema_version_unknown", "$.schema_version", "graph_schema");
  }
  assertReferenceArray(graph.expected_propositions, "$.expected_propositions");
  if (!graph.expected_propositions.length) {
    refuse("required_evidence_missing", "$.expected_propositions", "expected_propositions");
  }
  if (!Array.isArray(graph.records)) {
    refuse("canonical_value_outside_grammar", "$.records", "record_array");
  }
  validateSyntheticProfile(graph.profile, graph.expected_propositions, "$.profile");
}
