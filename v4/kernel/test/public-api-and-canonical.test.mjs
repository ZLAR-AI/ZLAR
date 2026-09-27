import assert from "node:assert/strict";
import test from "node:test";

import * as kernel from "../src/index.mjs";

test("public export surface is exact", () => {
  assert.deepEqual(Object.keys(kernel).sort(), [
    "canonicalize",
    "createKernel",
    "deriveClaims",
    "evaluateTransition",
    "identifyEvidence",
    "projectAuthorityView",
    "validateGraph",
  ]);
});

test("kernel constructs only exact synthetic mode as data", () => {
  const result = kernel.createKernel({
    mode: "synthetic",
    fixture_namespace: "zlar_v4_formation_fixtures_v1",
  });
  assert.equal(result.outcome, "synthetic_kernel_constructed");
  assert.equal(result.effect_capability, "none");
  assert.equal(JSON.stringify(result).includes("function"), false);
  assert.equal(kernel.createKernel({
    mode: "live",
    fixture_namespace: "zlar_v4_formation_fixtures_v1",
  }).refusal_codes[0], "live_mode_forbidden");
});

test("canonicalization is deterministic and narrow", () => {
  assert.equal(
    kernel.canonicalize({ z: 1, a: [true, null, "x"] }).canonical_text,
    '{"a":[true,null,"x"],"z":1}',
  );
  assert.equal(
    kernel.canonicalize({ a: 1, z: 2 }).canonical_text,
    kernel.canonicalize({ z: 2, a: 1 }).canonical_text,
  );
  assert.notEqual(
    kernel.canonicalize([1, 2]).canonical_text,
    kernel.canonicalize([2, 1]).canonical_text,
  );
  for (const invalid of [-0, 1.5, Number.MAX_SAFE_INTEGER + 1, undefined, () => {}]) {
    assert.equal(kernel.canonicalize(invalid).outcome, "refused");
  }
  assert.equal(kernel.canonicalize("\ud800").outcome, "refused");
});

test("identity is domain separated and raw text ingress refuses", () => {
  const base = {
    record_type: "observation",
    schema_version: "v1",
    record_body: { category: "x" },
  };
  const first = kernel.identifyEvidence(base);
  const second = kernel.identifyEvidence({
    ...base,
    record_body: { category: "y" },
  });
  assert.match(first.evidence_id, /^zlar:v4:evidence:v1:sha256:[0-9a-f]{64}$/u);
  assert.notEqual(first.evidence_id, second.evidence_id);
  assert.equal(kernel.identifyEvidence("{}").refusal_codes[0], "raw_json_text_ingress_forbidden");
});
