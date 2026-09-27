import assert from "node:assert/strict";
import test from "node:test";

import { CASE_CATALOG } from "../cases/catalog.mjs";
import { evaluateSyntheticCase } from "../cases/evaluate.mjs";
import { EXPECTED_ASSESSMENTS } from "./expected-assessments.mjs";

test("every committed case returns its exact bounded assessment", () => {
  assert.equal(CASE_CATALOG.length, 35);
  const observedFamilies = new Set();
  for (const entry of CASE_CATALOG) {
    const result = evaluateSyntheticCase(entry.request);
    assert.deepEqual(result, EXPECTED_ASSESSMENTS[entry.request.case_id]);
    assert.equal(result.assessment_class, "private_synthetic_source_evidence_only");
    assert.equal(result.crossing, "structurally_unavailable");
    assert.equal(result.effect, "not_attempted");
    assert.equal(result.authority_domain_binding, "unbound_placeholder");
    assert.equal(result.effect_adapter_binding, "unbound_placeholder");
    assert.equal(result.claim_ceiling, "private_synthetic_source_evidence_only");
    for (const forbidden of [
      "allow",
      "approved",
      "accepted",
      "authorized",
      "crossed",
      "effected",
      "delivered",
      "executed",
      "recognized",
      "valid",
    ]) assert.equal(Object.hasOwn(result, forbidden), false);
    observedFamilies.add(entry.request.case_id.split(":").at(-1));
  }
  for (const requiredPrefix of [
    "standing",
    "per_action",
    "reserved",
    "revoked",
    "expired",
    "propagation_lag",
    "disputed",
    "missing",
    "stale_frame",
    "fresh_eyes",
    "no_authority",
    "credential_laundering",
    "proposal_mutation",
    "silent_fusion",
    "forward_consequence",
  ]) {
    assert.equal(
      [...observedFamilies].some((family) => family.startsWith(requiredPrefix)),
      true,
      `missing family ${requiredPrefix}`,
    );
  }
});

test("unknown and mutated requests cannot extend the finite catalog", () => {
  const mutation = structuredClone(CASE_CATALOG[0].request);
  mutation.case_id = "syn:v4:case:unregistered";
  assert.deepEqual(
    evaluateSyntheticCase(mutation).refusal_codes,
    ["synthetic_context_required"],
  );
  const extra = structuredClone(CASE_CATALOG[0].request);
  extra.partner = "forbidden_sentinel";
  const result = evaluateSyntheticCase(extra);
  assert.equal(result.outcome, "refused");
  assert.equal(JSON.stringify(result).includes("forbidden_sentinel"), false);

  for (const injected of [
    "https://partner.invalid/path",
    "partner.invalid",
    "192.0.2.10",
    "owner@partner.invalid",
    "/tmp/partner.sock",
    "curl_partner",
    "-----BEGIN PRIVATE KEY-----",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.signature",
    "sk_live_forbidden_sentinel",
    "secret_forbidden_sentinel",
    { network: "forbidden_sentinel" },
    () => "forbidden_sentinel",
  ]) {
    const request = structuredClone(CASE_CATALOG[0].request);
    request.context.profile_id = injected;
    const injectionResult = evaluateSyntheticCase(request);
    assert.equal(injectionResult.outcome, "refused");
    assert.equal(JSON.stringify(injectionResult).includes("forbidden_sentinel"), false);
    if (typeof injected === "string") {
      assert.equal(JSON.stringify(injectionResult).includes(injected), false);
    }
  }
});
