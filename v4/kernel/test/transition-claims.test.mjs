import assert from "node:assert/strict";
import test from "node:test";

import {
  deriveClaims,
  evaluateTransition,
  projectAuthorityView,
  validateGraph,
} from "../src/index.mjs";
import {
  eventFixture,
  graphFixture,
  transitionInput,
} from "./helpers/fixtures.mjs";

test("pure transition is deterministic and receipt has no claim ceiling", () => {
  const input = transitionInput();
  const before = JSON.stringify(input.prior_snapshot);
  const first = evaluateTransition(input);
  const second = evaluateTransition(input);
  assert.equal(first.outcome, "synthetic_transition_accepted");
  assert.equal(JSON.stringify(first), JSON.stringify(second));
  assert.equal(JSON.stringify(input.prior_snapshot), before);
  assert.equal("claim_ceiling" in first.transition_receipt, false);
});

test("stale transition refuses and returns unchanged snapshot", () => {
  const input = transitionInput();
  input.proposed_event = eventFixture(input.prior_snapshot, {
    prior_snapshot_id: "syn:v4:snapshot:stale",
  });
  const result = evaluateTransition(input);
  assert.equal(result.outcome, "refused");
  assert.equal(result.refusal_codes.includes("transition_input_stale"), true);
  assert.equal(
    JSON.stringify(result.unchanged_snapshot),
    JSON.stringify(input.prior_snapshot),
  );
});

test("claims reproject graph and remain bounded mechanism claims", () => {
  const graph = graphFixture();
  const graphValidation = validateGraph(graph);
  const projection = projectAuthorityView({ graph, as_of: 50 });
  const transitionBasis = transitionInput();
  const transition = evaluateTransition(transitionBasis);
  const claims = deriveClaims({
    graph,
    as_of: 50,
    graph_validation: graphValidation,
    projection,
    transition_input: transitionBasis,
    transition_result: transition,
  });
  assert.equal(claims.outcome, "claims_derived");
  assert.equal(claims.claim_ceiling, "private_synthetic_source_evidence_only");
  assert.equal(
    claims.claims.some((item) => item.claim_type === "synthetic_transition_accepted"),
    true,
  );
  assert.equal(
    JSON.stringify(claims).includes("source_foundation_complete"),
    false,
  );
});

test("transition claims cannot predate their exact evaluation time", () => {
  const graph = graphFixture();
  const graphValidation = validateGraph(graph);
  const projection = projectAuthorityView({ graph, as_of: 0 });
  const transitionBasis = transitionInput();
  const transition = evaluateTransition(transitionBasis);
  const claims = deriveClaims({
    graph,
    as_of: 0,
    graph_validation: graphValidation,
    projection,
    transition_input: transitionBasis,
    transition_result: transition,
  });
  assert.equal(claims.outcome, "refused");
  assert.equal(claims.refusal_codes.includes("claim_not_derivable"), true);
});
