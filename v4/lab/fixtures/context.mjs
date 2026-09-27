import { FIXTURE_NAMESPACE } from "./registry.mjs";

export const SYNTHETIC_CONTEXT = Object.freeze({
  context_type: "synthetic_authority_context",
  fixture_namespace: FIXTURE_NAMESPACE,
  profile_id: "syn:v4:profile:validator",
  profile_version: "v1",
  rule_set_id: "syn:v4:rules:validator",
  rule_set_version: "v1",
  as_of: 50,
  use_for: "private_synthetic_source_evidence_only",
  do_not_use_for: Object.freeze([
    "authority",
    "effect",
    "partner_truth",
    "production",
    "public_claim",
    "recognition",
  ]),
});
