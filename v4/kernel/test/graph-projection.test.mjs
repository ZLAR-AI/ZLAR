import assert from "node:assert/strict";
import test from "node:test";

import {
  projectAuthorityView,
  validateGraph,
} from "../src/index.mjs";
import {
  graphFixture,
  searchRecord,
  sourceRecord,
} from "./helpers/fixtures.mjs";

test("valid graph recomputes identities and projects four axes", () => {
  const graph = graphFixture();
  const validation = validateGraph(graph);
  assert.equal(validation.outcome, "graph_validated");
  const projection = projectAuthorityView({ graph, as_of: 50 });
  assert.equal(projection.outcome, "authority_view_projected");
  const mandate = projection.assessments.find(
    (assessment) => assessment.proposition_id === "syn:v4:proposition:mandate",
  );
  assert.deepEqual(
    [mandate.presence, mandate.lineage, mandate.freshness, mandate.contest],
    ["present", "current", "current", "no_contest_recorded"],
  );
  assert.equal("claim_ceiling" in projection, false);
});

test("open missing stays unknown and closed search can establish absence", () => {
  const unknownGraph = graphFixture({
    expectedPropositions: ["syn:v4:proposition:mandate"],
    records: [],
  });
  const unknown = projectAuthorityView({ graph: unknownGraph, as_of: 50 });
  assert.equal(unknown.assessments[0].presence, "unknown");

  const absentGraph = graphFixture({
    expectedPropositions: ["syn:v4:proposition:mandate"],
    records: [searchRecord("syn:v4:proposition:mandate", "mandate")],
  });
  const absent = projectAuthorityView({ graph: absentGraph, as_of: 50 });
  assert.deepEqual(
    [absent.assessments[0].presence, absent.assessments[0].freshness, absent.assessments[0].lineage],
    ["absent", "not_applicable", "unknown"],
  );
});

test("expired disputed superseded axes coexist", () => {
  const record = sourceRecord("frame", "syn:v4:proposition:frame", {
    valid_until: 50,
    authoritative_head_evidence_ref: null,
    superseded_by_refs: ["syn:v4:evidence:frame_successor"],
    challenge_refs: ["syn:v4:evidence:frame_challenge"],
  });
  const graph = graphFixture({
    expectedPropositions: ["syn:v4:proposition:frame"],
    records: [record],
    profileOverrides: {
      constitutive_propositions: ["syn:v4:proposition:frame"],
      frame_constitutive: true,
    },
  });
  const projection = projectAuthorityView({ graph, as_of: 50 });
  assert.deepEqual(
    [projection.assessments[0].freshness, projection.assessments[0].lineage, projection.assessments[0].contest],
    ["expired", "superseded", "disputed"],
  );
  for (const code of [
    "authority_expired",
    "expired_frame_silent_use",
    "frame_lineage_not_current",
    "required_evidence_disputed",
  ]) assert.equal(projection.refusal_codes.includes(code), true);
});
