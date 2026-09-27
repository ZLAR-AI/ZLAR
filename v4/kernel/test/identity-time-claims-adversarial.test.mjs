import assert from "node:assert/strict";
import test from "node:test";

import {
  deriveClaims,
  evaluateTransition,
  identifyEvidence,
  projectAuthorityView,
  validateGraph,
} from "../src/index.mjs";
import {
  graphFixture,
  transitionInput,
} from "./helpers/fixtures.mjs";

test("type/schema delimiter ambiguity and invalid time inputs refuse", () => {
  for (const input of [
    { record_type: "a", schema_version: "b\u0000c", record_body: {} },
    { record_type: "a\u0000b", schema_version: "c", record_body: {} },
    { record_type: "A", schema_version: "v1", record_body: {} },
    { record_type: "a".repeat(65), schema_version: "v1", record_body: {} },
  ]) assert.equal(identifyEvidence(input).outcome, "refused");

  const graph = graphFixture();
  for (const asOf of [-1, -0, 1.5, Number.MAX_SAFE_INTEGER + 1, "50", new Date(50)]) {
    assert.equal(projectAuthorityView({ graph, as_of: asOf }).outcome, "refused");
  }
  const transition = transitionInput({ evaluation_time: -0 });
  assert.deepEqual(
    evaluateTransition(transition).refusal_codes,
    ["canonical_value_outside_grammar"],
  );
});

test("claim derivation rejects a forged projection and caller ceiling", () => {
  const graph = graphFixture();
  const validation = validateGraph(graph);
  const projection = projectAuthorityView({ graph, as_of: 50 });
  const forged = structuredClone(projection);
  forged.assessments[0].presence = "absent";
  assert.deepEqual(
    deriveClaims({
      graph,
      as_of: 50,
      graph_validation: validation,
      projection: forged,
      transition_input: null,
      transition_result: null,
    }).refusal_codes,
    ["identity_mismatch"],
  );
  assert.deepEqual(
    deriveClaims({
      graph,
      as_of: 50,
      graph_validation: validation,
      projection,
      transition_input: null,
      transition_result: null,
      claim_ceiling: "v4_complete",
    }).refusal_codes,
    ["claim_ceiling_overreach"],
  );
});

test("claim derivation rejects a forged refused transition receipt", () => {
  const graph = graphFixture();
  const validation = validateGraph(graph);
  const projection = projectAuthorityView({ graph, as_of: 50 });
  const transitionBasis = transitionInput();
  transitionBasis.proposed_event = {
    ...transitionBasis.proposed_event,
    prior_snapshot_id: "syn:v4:snapshot:stale",
  };
  const exactRefusal = evaluateTransition(transitionBasis);
  const forged = structuredClone(exactRefusal);
  forged.state_unchanged = false;
  forged.unchanged_snapshot.state = "revoked";
  assert.deepEqual(
    deriveClaims({
      graph,
      as_of: 50,
      graph_validation: validation,
      projection,
      transition_input: transitionBasis,
      transition_result: forged,
    }).refusal_codes,
    ["identity_mismatch"],
  );
});
