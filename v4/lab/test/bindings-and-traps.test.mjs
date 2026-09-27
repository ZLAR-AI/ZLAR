import assert from "node:assert/strict";
import test from "node:test";

import { CASE_CATALOG } from "../cases/catalog.mjs";
import { evaluateSyntheticCase } from "../cases/evaluate.mjs";
import {
  admitAuthorityDomainBinding,
  admitEffectAdapterBinding,
  AUTHORITY_DOMAIN_BINDING,
  EFFECT_ADAPTER_BINDING,
} from "../fixtures/bindings.mjs";

test("only the two exact unbound records admit", () => {
  assert.equal(
    admitAuthorityDomainBinding(AUTHORITY_DOMAIN_BINDING),
    AUTHORITY_DOMAIN_BINDING,
  );
  assert.equal(
    admitEffectAdapterBinding(EFFECT_ADAPTER_BINDING),
    EFFECT_ADAPTER_BINDING,
  );
  for (const field of [
    "active",
    "bound",
    "callback",
    "credential",
    "domain",
    "endpoint",
    "owner",
    "partner",
    "value",
  ]) {
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
      const authority = structuredClone(AUTHORITY_DOMAIN_BINDING);
      authority[field] = injected;
      const authorityResult = admitAuthorityDomainBinding(authority);
      assert.deepEqual(authorityResult.refusal_codes, ["real_authority_binding_forbidden"]);
      assert.equal(JSON.stringify(authorityResult).includes("forbidden_sentinel"), false);
      if (typeof injected === "string") {
        assert.equal(JSON.stringify(authorityResult).includes(injected), false);
      }

      const effect = structuredClone(EFFECT_ADAPTER_BINDING);
      effect[field] = injected;
      const effectResult = admitEffectAdapterBinding(effect);
      assert.deepEqual(effectResult.refusal_codes, ["real_effect_binding_forbidden"]);
      assert.equal(JSON.stringify(effectResult).includes("forbidden_sentinel"), false);
      if (typeof injected === "string") {
        assert.equal(JSON.stringify(effectResult).includes(injected), false);
      }
    }
  }
  const duplicate = structuredClone(AUTHORITY_DOMAIN_BINDING);
  duplicate.missing_external_bindings.push(duplicate.missing_external_bindings[0]);
  assert.deepEqual(
    admitAuthorityDomainBinding(duplicate).refusal_codes,
    ["real_authority_binding_forbidden"],
  );
});

test("Proxy and accessor traps remain at zero", () => {
  const boundaries = [
    {
      admit: admitAuthorityDomainBinding,
      base: AUTHORITY_DOMAIN_BINDING,
    },
    {
      admit: admitEffectAdapterBinding,
      base: EFFECT_ADAPTER_BINDING,
    },
    {
      admit: evaluateSyntheticCase,
      base: CASE_CATALOG[0].request,
    },
  ];
  for (const { admit, base } of boundaries) {
    let topProxyTraps = 0;
    const topProxy = new Proxy({}, {
      get() { topProxyTraps += 1; return undefined; },
      ownKeys() { topProxyTraps += 1; return []; },
      getOwnPropertyDescriptor() { topProxyTraps += 1; return undefined; },
      getPrototypeOf() { topProxyTraps += 1; return Object.prototype; },
    });
    assert.equal(admit(topProxy).outcome, "refused");
    assert.equal(topProxyTraps, 0);

    let nestedProxyTraps = 0;
    const nestedProxy = new Proxy({}, {
      get() { nestedProxyTraps += 1; return undefined; },
      ownKeys() { nestedProxyTraps += 1; return []; },
      getOwnPropertyDescriptor() { nestedProxyTraps += 1; return undefined; },
      getPrototypeOf() { nestedProxyTraps += 1; return Object.prototype; },
    });
    assert.equal(admit({ ...base, nested: nestedProxy }).outcome, "refused");
    assert.equal(nestedProxyTraps, 0);

    let topAccessorCalls = 0;
    const topAccessor = {};
    Object.defineProperty(topAccessor, "value", {
      enumerable: true,
      get() { topAccessorCalls += 1; return "forbidden"; },
    });
    assert.equal(admit(topAccessor).outcome, "refused");
    assert.equal(topAccessorCalls, 0);

    let nestedAccessorCalls = 0;
    const nestedAccessor = {};
    Object.defineProperty(nestedAccessor, "value", {
      enumerable: true,
      get() { nestedAccessorCalls += 1; return "forbidden"; },
    });
    assert.equal(admit({ ...base, nested: nestedAccessor }).outcome, "refused");
    assert.equal(nestedAccessorCalls, 0);
  }
});
