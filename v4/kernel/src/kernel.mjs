import {
  FIXTURE_NAMESPACE,
  KERNEL_VERSION,
  PUBLIC_OPERATIONS,
} from "./constants.mjs";
import { refuse } from "./refusal.mjs";
import { assertExactKeys } from "./safe-data.mjs";

export function createKernelMaterialized(input) {
  assertExactKeys(input, ["fixture_namespace", "mode"], "$" );
  if (input.mode !== "synthetic") {
    refuse("live_mode_forbidden", "$.mode", "mode");
  }
  if (input.fixture_namespace !== FIXTURE_NAMESPACE) {
    refuse("fixture_namespace_forbidden", "$.fixture_namespace", "fixture_namespace");
  }
  return Object.freeze({
    outcome: "synthetic_kernel_constructed",
    kernel_type: "pure_in_memory_consequence_incapable_source_kernel",
    kernel_version: KERNEL_VERSION,
    mode: "synthetic",
    fixture_namespace: FIXTURE_NAMESPACE,
    operations: PUBLIC_OPERATIONS,
    effect_capability: "none",
    crossing: "structurally_unavailable",
    claim_ceiling: "private_synthetic_source_evidence_only",
    reset: "any_live_mode_effect_surface_or_dependency_drift_invalidates_kernel",
    residue: "host_and_institutional_boundaries_remain_external",
  });
}
