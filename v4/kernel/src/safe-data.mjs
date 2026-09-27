import { types } from "node:util";

import { refuse } from "./refusal.mjs";

const asciiKeyPattern = /^[a-z][a-z0-9_]*$/u;

export function isProxyValue(value) {
  return types.isProxy(value);
}

function assertString(value, path) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        refuse("canonical_value_outside_grammar", path, "unpaired_surrogate");
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      refuse("canonical_value_outside_grammar", path, "unpaired_surrogate");
    }
  }
}

function descriptorsUnchanged(before, after) {
  const beforeKeys = Reflect.ownKeys(before);
  const afterKeys = Reflect.ownKeys(after);
  if (beforeKeys.length !== afterKeys.length) return false;
  for (let index = 0; index < beforeKeys.length; index += 1) {
    const key = beforeKeys[index];
    if (key !== afterKeys[index]) return false;
    const left = before[key];
    const right = after[key];
    if (
      !right ||
      left.get !== right.get ||
      left.set !== right.set ||
      left.enumerable !== right.enumerable ||
      left.configurable !== right.configurable ||
      left.writable !== right.writable ||
      !Object.is(left.value, right.value)
    ) return false;
  }
  return true;
}

function materialize(value, path, ancestors) {
  if (isProxyValue(value)) {
    refuse("proxy_object_forbidden", path, "proxy_rejected_before_reflection");
  }
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    assertString(value, path);
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      refuse("canonical_value_outside_grammar", path, "number_outside_grammar");
    }
    return value;
  }
  if (typeof value !== "object") {
    refuse("canonical_value_outside_grammar", path, "type_outside_grammar");
  }
  if (ancestors.has(value)) {
    refuse("canonical_value_outside_grammar", path, "cyclic_value");
  }
  ancestors.add(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key === "symbol")) {
    refuse("canonical_value_outside_grammar", path, "symbol_key");
  }
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (descriptor.get || descriptor.set || !("value" in descriptor)) {
      refuse("executable_reference_forbidden", `${path}.*`, "accessor");
    }
  }

  let clone;
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      refuse("canonical_value_outside_grammar", path, "array_prototype");
    }
    const lengthDescriptor = descriptors.length;
    const length = lengthDescriptor?.value;
    if (!Number.isSafeInteger(length) || length < 0) {
      refuse("canonical_value_outside_grammar", path, "array_length");
    }
    const expectedKeys = [];
    for (let index = 0; index < length; index += 1) expectedKeys.push(String(index));
    expectedKeys.push("length");
    if (
      keys.length !== expectedKeys.length ||
      expectedKeys.some((key) => !Object.hasOwn(descriptors, key))
    ) {
      refuse("canonical_value_outside_grammar", path, "sparse_or_extended_array");
    }
    clone = [];
    for (let index = 0; index < length; index += 1) {
      clone.push(materialize(descriptors[String(index)].value, `${path}[${index}]`, ancestors));
    }
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      refuse("canonical_value_outside_grammar", path, "non_plain_object");
    }
    clone = Object.create(null);
    for (const key of keys) {
      if (!asciiKeyPattern.test(key)) {
        refuse("canonical_value_outside_grammar", `${path}.*`, "object_key");
      }
      clone[key] = materialize(descriptors[key].value, `${path}.*`, ancestors);
    }
  }
  const after = Object.getOwnPropertyDescriptors(value);
  if (!descriptorsUnchanged(descriptors, after)) {
    refuse("canonical_value_outside_grammar", path, "mutation_during_traversal");
  }
  ancestors.delete(value);
  return clone;
}

export function materializeCanonical(value) {
  return materialize(value, "$", new WeakSet());
}

function serializeMaterialized(value) {
  if (value === null) return "null";
  if (typeof value === "boolean" || typeof value === "number") return String(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => serializeMaterialized(item)).join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${serializeMaterialized(value[key])}`).join(",")}}`;
}

export function canonicalText(value) {
  return serializeMaterialized(materializeCanonical(value));
}

export function canonicalTextFromMaterialized(value) {
  return serializeMaterialized(value);
}

export function assertCanonicalInstant(value, path = "$.as_of") {
  if (
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < 0 ||
    value > 8640000000000000
  ) refuse("canonical_instant_invalid", path, "canonical_instant");
  return value;
}

export function assertExactKeys(value, expected, path = "$") {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    refuse("canonical_value_outside_grammar", path, "object_required");
  }
  const keys = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    keys.length !== wanted.length ||
    keys.some((key, index) => key !== wanted[index])
  ) refuse("unknown_binding_field", path, "exact_shape");
}

export function assertSyntheticId(value, path = "$.id") {
  if (
    typeof value !== "string" ||
    !/^syn:v4:[a-z][a-z0-9_]*(?::[a-z0-9_]+)*$/u.test(value)
  ) refuse("non_synthetic_identifier", path, "synthetic_registry_id");
  return value;
}

export function assertRegistryToken(value, path) {
  if (typeof value !== "string" || !/^[a-z][a-z0-9_]{0,63}$/u.test(value)) {
    refuse("schema_version_unknown", path, "closed_registry_token");
  }
  return value;
}
