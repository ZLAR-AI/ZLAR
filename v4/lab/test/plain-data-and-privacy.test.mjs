import assert from "node:assert/strict";
import test from "node:test";

import { canonicalize } from "../../kernel/src/index.mjs";
import { CASE_CATALOG } from "../cases/catalog.mjs";
import { SYNTHETIC_CONTEXT } from "../fixtures/context.mjs";

test("fixtures are canonical plain data in the reserved namespace", () => {
  for (const value of [
    SYNTHETIC_CONTEXT,
    ...CASE_CATALOG.map((entry) => entry.request),
    ...CASE_CATALOG.map((entry) => entry.kernel_input),
  ]) assert.equal(canonicalize(value).outcome, "canonicalized");
});

test("fixture bytes contain no real-binding or identifying shapes", () => {
  const bytes = JSON.stringify({
    context: SYNTHETIC_CONTEXT,
    cases: CASE_CATALOG,
  });
  for (const forbiddenPattern of [
    /https?:\/\//iu,
    /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/iu,
    /-----BEGIN [A-Z ]+-----/u,
    /eyJ[a-zA-Z0-9_-]{20,}\./u,
    /sk_(?:live|test)_[a-zA-Z0-9]+/u,
    /\b(?:\d{1,3}\.){3}\d{1,3}\b/u,
  ]) assert.equal(forbiddenPattern.test(bytes), false);
});

function recursivelyFrozen(value, seen = new Set()) {
  if (value === null || typeof value !== "object" || seen.has(value)) return true;
  seen.add(value);
  if (!Object.isFrozen(value)) return false;
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && "value" in descriptor && !recursivelyFrozen(descriptor.value, seen)) {
      return false;
    }
  }
  return true;
}

test("committed runtime source inputs are recursively immutable", () => {
  for (const entry of CASE_CATALOG) {
    assert.equal(recursivelyFrozen(entry.kernel_input), true);
  }
  const firstRefs = CASE_CATALOG[0].kernel_input.graph.records[0].record_body.challenge_refs;
  assert.throws(() => firstRefs.push("syn:v4:evidence:mutation"), TypeError);
});
