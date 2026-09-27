import { types } from "node:util";

import { canonicalize } from "../../kernel/src/index.mjs";
import { MISSING_EXTERNAL_BINDINGS } from "./registry.mjs";

export const AUTHORITY_DOMAIN_BINDING = Object.freeze({
  binding_type: "authority_domain_binding",
  state: "unbound_placeholder",
  authority_effect: "none",
  missing_external_bindings: MISSING_EXTERNAL_BINDINGS,
  use_for: "unfilled_partner_question_inventory_only",
  do_not_use_for: Object.freeze([
    "authority",
    "recognition",
    "effect",
    "execution",
    "partner_truth",
  ]),
  reset: "any_supplied_binding_value_invalidates_placeholder",
  residue: "all_external_authority_bindings_remain_absent",
});

export const EFFECT_ADAPTER_BINDING = Object.freeze({
  binding_type: "effect_adapter_binding",
  state: "unbound_placeholder",
  destination: "absent",
  adapter: "absent",
  effect_capability: "none",
  construction: "forbidden",
  use_for: "effect_absence_and_dependency_inventory_only",
  do_not_use_for: Object.freeze([
    "destination",
    "adapter",
    "effect",
    "execution",
    "transport",
  ]),
  reset: "any_supplied_effect_value_invalidates_placeholder",
  residue: "all_external_effect_bindings_remain_absent",
});

const authorityCanonical = canonicalize(AUTHORITY_DOMAIN_BINDING).canonical_text;
const effectCanonical = canonicalize(EFFECT_ADAPTER_BINDING).canonical_text;

function bindingRefusal(code) {
  return Object.freeze({
    outcome: "refused",
    refusal_codes: Object.freeze([code]),
    assessment_class: "private_synthetic_source_evidence_only",
    crossing: "structurally_unavailable",
    effect: "not_attempted",
    authority_domain_binding: "unbound_placeholder",
    effect_adapter_binding: "unbound_placeholder",
    claim_ceiling: "private_synthetic_source_evidence_only",
    state_unchanged: true,
  });
}

export function admitAuthorityDomainBinding(input) {
  if (types.isProxy(input)) return bindingRefusal("proxy_object_forbidden");
  const admitted = canonicalize(input);
  if (
    admitted.outcome !== "canonicalized" ||
    admitted.canonical_text !== authorityCanonical
  ) return bindingRefusal("real_authority_binding_forbidden");
  return AUTHORITY_DOMAIN_BINDING;
}

export function admitEffectAdapterBinding(input) {
  if (types.isProxy(input)) return bindingRefusal("proxy_object_forbidden");
  const admitted = canonicalize(input);
  if (
    admitted.outcome !== "canonicalized" ||
    admitted.canonical_text !== effectCanonical
  ) return bindingRefusal("real_effect_binding_forbidden");
  return EFFECT_ADAPTER_BINDING;
}
