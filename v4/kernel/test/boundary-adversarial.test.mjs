import assert from "node:assert/strict";
import test from "node:test";

import * as kernel from "../src/index.mjs";

const apis = [
  kernel.createKernel,
  kernel.canonicalize,
  kernel.identifyEvidence,
  kernel.validateGraph,
  kernel.evaluateTransition,
  kernel.projectAuthorityView,
  kernel.deriveClaims,
];

test("every public boundary refuses top-level Proxy before traps", () => {
  for (const api of apis) {
    let traps = 0;
    const proxy = new Proxy({}, {
      get() { traps += 1; return undefined; },
      ownKeys() { traps += 1; return []; },
      getOwnPropertyDescriptor() { traps += 1; return undefined; },
      getPrototypeOf() { traps += 1; return Object.prototype; },
    });
    const result = api(proxy);
    assert.deepEqual(result.refusal_codes, ["proxy_object_forbidden"]);
    assert.equal(traps, 0);
  }
});

test("every public boundary refuses nested Proxy and accessor without execution", () => {
  for (const api of apis) {
    let traps = 0;
    const proxy = new Proxy({}, {
      ownKeys() { traps += 1; return []; },
      getOwnPropertyDescriptor() { traps += 1; return undefined; },
    });
    const result = api({ nested: proxy });
    assert.deepEqual(result.refusal_codes, ["proxy_object_forbidden"]);
    assert.equal(traps, 0);

    let getters = 0;
    const nested = {};
    Object.defineProperty(nested, "value", {
      enumerable: true,
      get() { getters += 1; return "forbidden"; },
    });
    const accessorResult = api({ nested });
    assert.equal(accessorResult.outcome, "refused");
    assert.equal(getters, 0);
  }
});

test("canonical boundary rejects non-plain and extended values", () => {
  class Example {}
  const cycle = {};
  cycle.self = cycle;
  const sparse = [];
  sparse.length = 1;
  const hidden = [];
  hidden.partner = "forbidden";
  const symbol = { [Symbol("x")]: 1 };
  for (const value of [
    new Example(),
    new Date(0),
    cycle,
    sparse,
    hidden,
    symbol,
    { value: 1n },
    { value: undefined },
    { value() {} },
  ]) assert.equal(kernel.canonicalize(value).outcome, "refused");
});

test("inherited getters and toJSON do not execute", () => {
  const originalMode = Object.getOwnPropertyDescriptor(Object.prototype, "mode");
  const originalToJson = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
  let calls = 0;
  try {
    Object.defineProperty(Object.prototype, "mode", {
      configurable: true,
      get() { calls += 1; return "live"; },
    });
    Object.defineProperty(Object.prototype, "toJSON", {
      configurable: true,
      value() { calls += 1; return { compromised: true }; },
    });
    assert.equal(kernel.createKernel({}).outcome, "refused");
    assert.equal(kernel.canonicalize({ safe: true }).canonical_text, '{"safe":true}');
    assert.equal(calls, 0);
  } finally {
    if (originalMode) Object.defineProperty(Object.prototype, "mode", originalMode);
    else delete Object.prototype.mode;
    if (originalToJson) Object.defineProperty(Object.prototype, "toJSON", originalToJson);
    else delete Object.prototype.toJSON;
  }
});

test("refusal paths never echo caller property names", () => {
  const value = {};
  Object.defineProperty(value, "sk_live_supersecret", {
    enumerable: true,
    get() { throw new Error("must not execute"); },
  });
  const result = kernel.canonicalize(value);
  assert.equal(result.outcome, "refused");
  assert.equal(JSON.stringify(result).includes("sk_live_supersecret"), false);
});
