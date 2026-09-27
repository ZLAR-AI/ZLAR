import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const v4Root = path.resolve(here, "../..");
const kernelSrc = path.join(v4Root, "kernel/src");
const labRuntimeRoots = [
  path.join(v4Root, "lab/cases"),
  path.join(v4Root, "lab/fixtures"),
];
const exactRuntimeEntries = [
  path.join(kernelSrc, "index.mjs"),
  path.join(v4Root, "lab/cases/evaluate.mjs"),
  path.join(v4Root, "lab/fixtures/bindings.mjs"),
];
const exactRuntimeSourceHashes = Object.freeze({
  "kernel/src/claims.mjs": "5ec2b5a3ebd0f713dee332d76026b6e884510127f4489fddf7457028a10e95d4",
  "kernel/src/constants.mjs": "436d0297828893d4fcd66ad9516a70fd5bc574ef9ac341328ac6ff1a3bb51d79",
  "kernel/src/contracts.mjs": "b228dad2f31b3c99b3bf1b4a993f6729ecedcda4da03f8dc3b7fc852f30a268f",
  "kernel/src/graph.mjs": "3eeb4497c4fac77de5cc1fdbd6ab7cb2709ee19459c2f88e612427d2398ce602",
  "kernel/src/identity.mjs": "0e0c66f871f0e81b437a98f5d2a9104277e02c21473e59f483695c7a04a63b74",
  "kernel/src/index.mjs": "ae64f79772b9738456b2bccbbe91eb914448ea0ab141617628bc7623f971bd5b",
  "kernel/src/kernel.mjs": "83d0346aa6b6047c1fa42baf5e9d85a743d012722b198b45066aa992d62867e9",
  "kernel/src/projection.mjs": "4006683133ec5e3fdc42ba6aacded11eee864a17b03bedd26f866ec64628c010",
  "kernel/src/refusal.mjs": "811918c66bde5df0115ee302e96772b8a98b33093f01cb0e3c370ceb4cf4eba1",
  "kernel/src/safe-data.mjs": "f80359908cc5c1023c991affd5c1c33813b3d2e6a373bf7adf874388c9eeb46a",
  "kernel/src/transition.mjs": "8bd281bfa9b41111bad695a24553fba85d509f1096f8686addd8b38d4c79c02d",
  "lab/cases/catalog.mjs": "414dd7b47a0145254dc923c539f0f5a120511283d75855c1b9e8c991e12c5bfe",
  "lab/cases/evaluate.mjs": "daae67d3107cc56afc839512b6df88acae9fe3cc5ef43f9d72416696c0027e78",
  "lab/fixtures/bindings.mjs": "196bac92d3ac2ddfd5b707a2abcb76ec872f93fa202fc192a60c9eb4cd7369b7",
  "lab/fixtures/context.mjs": "a3ccfa816cb1dc9d062babc13ba4532ca9a07f3ef01bfd8e5d159bfb97420a0a",
  "lab/fixtures/kernel-inputs.mjs": "7290a726c1f64da008035d35df88db87b144ebb2e882c8411ee6c57287294bbf",
  "lab/fixtures/registry.mjs": "9fbbf924e4c05311b8c5afb850bcaf38807eed96093c1ac19d0b5b61cac61268",
});

function filesUnder(root) {
  const files = [];
  for (const name of readdirSync(root)) {
    const absolute = path.join(root, name);
    if (statSync(absolute).isDirectory()) files.push(...filesUnder(absolute));
    else if (absolute.endsWith(".mjs")) files.push(absolute);
  }
  return files;
}

function moduleTokens(source) {
  const tokens = [];
  let index = 0;
  while (index < source.length) {
    const char = source[index];
    if (/\s/u.test(char)) { index += 1; continue; }
    if (char === "/" && source[index + 1] === "/") {
      index += 2;
      while (index < source.length && source[index] !== "\n") index += 1;
      continue;
    }
    if (char === "/" && source[index + 1] === "*") {
      index += 2;
      while (index < source.length && !(source[index] === "*" && source[index + 1] === "/")) {
        index += 1;
      }
      index += 2;
      continue;
    }
    if (["\"", "'", "`"].includes(char)) {
      const quote = char;
      let raw = "";
      index += 1;
      while (index < source.length) {
        if (source[index] === "\\") {
          raw += source.slice(index, index + 2);
          index += 2;
        } else if (source[index] === quote) {
          index += 1;
          break;
        } else {
          raw += source[index];
          index += 1;
        }
      }
      tokens.push({ type: quote === "`" ? "template" : "string", value: raw });
      continue;
    }
    if (/[A-Za-z_$]/u.test(char)) {
      let value = char;
      index += 1;
      while (index < source.length && /[A-Za-z0-9_$]/u.test(source[index])) {
        value += source[index];
        index += 1;
      }
      tokens.push({ type: "identifier", value });
      continue;
    }
    tokens.push({ type: "punctuator", value: char });
    index += 1;
  }
  return tokens;
}

function staticDependencies(source) {
  const tokens = moduleTokens(source);
  const dependencies = [];
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index].type !== "identifier" ||
      !["import", "export"].includes(tokens[index].value)
    ) continue;
    if (tokens[index].value === "import" && tokens[index + 1]?.value === "(") continue;
    if (tokens[index + 1]?.type === "string") {
      dependencies.push(tokens[index + 1].value);
      continue;
    }
    for (let cursor = index + 1; cursor < tokens.length; cursor += 1) {
      if ([";", "function", "class", "const", "let", "var"].includes(tokens[cursor].value)) {
        break;
      }
      if (
        tokens[cursor].type === "identifier" &&
        tokens[cursor].value === "from" &&
        tokens[cursor + 1]?.type === "string"
      ) {
        dependencies.push(tokens[cursor + 1].value);
        break;
      }
    }
  }
  return [...new Set(dependencies)];
}

function reachableRuntimeFiles() {
  const pending = [...exactRuntimeEntries];
  const visited = new Set();
  while (pending.length) {
    const file = pending.pop();
    if (visited.has(file)) continue;
    visited.add(file);
    const source = readFileSync(file, "utf8");
    for (const specifier of staticDependencies(source)) {
      if (!specifier.startsWith(".")) continue;
      const target = path.resolve(path.dirname(file), specifier);
      if (target.includes(`${path.sep}test${path.sep}`)) {
        throw new Error(`runtime reaches test file: ${path.relative(v4Root, target)}`);
      }
      if (!target.startsWith(v4Root)) {
        throw new Error(`runtime escapes v4: ${specifier}`);
      }
      pending.push(target);
    }
  }
  return [...visited].sort();
}

function boundaryFailures(file, source, kernel) {
  const failures = [];
  const relativeFile = path.relative(v4Root, file);
  const expectedSourceHash = exactRuntimeSourceHashes[relativeFile];
  if (expectedSourceHash === undefined) {
    failures.push(`unregistered runtime source ${relativeFile}`);
  } else if (
    createHash("sha256").update(source).digest("hex") !== expectedSourceHash
  ) {
    failures.push(`runtime source identity drift ${relativeFile}`);
  }
  for (const specifier of staticDependencies(source)) {
    if (specifier.startsWith("node:")) {
      if (![
        "node:crypto",
        "node:util",
      ].includes(specifier)) failures.push(`forbidden builtin ${specifier}`);
      if (!kernel && specifier !== "node:util") {
        failures.push(`forbidden lab builtin ${specifier}`);
      }
      if (
        kernel &&
        ((specifier === "node:crypto" && path.basename(file) !== "identity.mjs") ||
          (specifier === "node:util" && path.basename(file) !== "safe-data.mjs"))
      ) failures.push(`builtin in wrong kernel module ${specifier}`);
    } else if (!specifier.startsWith(".")) {
      failures.push(`package import ${specifier}`);
    } else {
      const target = path.resolve(path.dirname(file), specifier);
      if (kernel && !target.startsWith(kernelSrc)) failures.push(`kernel escape ${specifier}`);
      if (!kernel && !target.startsWith(v4Root)) failures.push(`v4 escape ${specifier}`);
      if (
        !kernel &&
        target.startsWith(kernelSrc) &&
        target !== path.join(kernelSrc, "index.mjs")
      ) failures.push(`lab bypasses public kernel index ${specifier}`);
      if (!kernel && target.includes(`${path.sep}test${path.sep}`)) {
        failures.push(`lab reaches test helper ${specifier}`);
      }
      if (!kernel && target.includes("ZLAR_Repo/") && !target.startsWith(v4Root)) {
        failures.push(`v3 reach ${specifier}`);
      }
    }
  }
  const forbiddenIdentifiers = Object.freeze({
    Function: "Function constructor",
    WebSocket: "WebSocket",
    eval: "eval",
    fetch: "fetch",
    process: "environment read",
    require: "require",
  });
  const forbiddenComputedKeys = new Set([
    "Function",
    "WebSocket",
    "__proto__",
    "constructor",
    "env",
    "eval",
    "fetch",
    "global",
    "globalThis",
    "process",
    "prototype",
    "require",
  ]);
  const tokens = moduleTokens(source);
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.type === "string" && forbiddenComputedKeys.has(token.value)) {
      failures.push(`forbidden computed capability ${token.value}`);
      continue;
    }
    if (token.type === "identifier") {
      if (Object.hasOwn(forbiddenIdentifiers, token.value)) {
        failures.push(forbiddenIdentifiers[token.value]);
      }
      if (["global", "globalThis"].includes(token.value)) {
        failures.push("global capability indirection");
      }
      if (token.value === "constructor" && path.basename(file) !== "refusal.mjs") {
        failures.push("constructor indirection");
      }
      if (token.value === "prototype" && path.basename(file) !== "safe-data.mjs") {
        failures.push("prototype indirection");
      }
      if (token.value === "import" && tokens[index + 1]?.value === "(") {
        failures.push("dynamic import");
      }
    }
  }
  if (
    kernel &&
    source.includes('from "node:crypto"') &&
    !source.includes('import { createHash } from "node:crypto"')
  ) failures.push("non-exact crypto import");
  if (
    source.includes('from "node:util"') &&
    !source.includes('import { types } from "node:util"')
  ) failures.push("non-exact util import");
  return failures;
}

function exportedNames(source) {
  return [...source.matchAll(/export\s+(?:async\s+)?(?:function|const|class)\s+([A-Za-z_$][A-Za-z0-9_$]*)/gu)]
    .map((match) => match[1])
    .sort();
}

test("package manifest and runtime imports are closed", () => {
  const manifest = JSON.parse(readFileSync(path.join(v4Root, "kernel/package.json"), "utf8"));
  assert.deepEqual(manifest, {
    private: true,
    type: "module",
    exports: { ".": "./src/index.mjs" },
  });

  const reachable = reachableRuntimeFiles();
  assert.deepEqual(
    Object.keys(exactRuntimeSourceHashes).sort(),
    reachable.map((file) => path.relative(v4Root, file)).sort(),
  );
  const files = reachable.map((file) => [file, file.startsWith(kernelSrc)]);
  const failures = [];
  for (const [file, kernel] of files) {
    failures.push(...boundaryFailures(file, readFileSync(file, "utf8"), kernel)
      .map((failure) => `${path.relative(v4Root, file)}: ${failure}`));
  }
  assert.deepEqual(failures, []);
  assert.deepEqual(
    filesUnder(kernelSrc).sort(),
    reachable.filter((file) => file.startsWith(kernelSrc)).sort(),
  );
  assert.deepEqual(
    labRuntimeRoots.flatMap((root) => filesUnder(root)).sort(),
    reachable.filter((file) => !file.startsWith(kernelSrc)).sort(),
  );
  const indexSource = readFileSync(path.join(kernelSrc, "index.mjs"), "utf8");
  assert.deepEqual(exportedNames(indexSource), [
    "canonicalize",
    "createKernel",
    "deriveClaims",
    "evaluateTransition",
    "identifyEvidence",
    "projectAuthorityView",
    "validateGraph",
  ]);
});

test("representative side-door mutations kill the boundary checker", () => {
  const fakeFile = path.join(kernelSrc, "mutation.mjs");
  for (const mutation of [
    'import fs from "node:fs";',
    'import childProcess from "node:child_process";',
    'import net from "node:net";',
    'import client from "partner-sdk";',
    'const value = process.env.TOKEN;',
    'const value = fetch("redacted");',
    'const value = import("redacted");',
    'const value = import/*closed*/("node:fs");',
    'const value = require("redacted");',
    'const value = require/*closed*/("redacted");',
    'const value = fetch/*closed*/("redacted");',
    'globalThis["fetch"]("https://example.com");',
    'globalThis["process"]["env"];',
    'globalThis["eval"]("1+1");',
    'new globalThis["WebSocket"]("wss://example.com");',
    '([]["filter"]["constructor"]("return this")())["fetch"]("https://example.com");',
  ]) assert.notDeepEqual(boundaryFailures(fakeFile, mutation, true), []);
  assert.notDeepEqual(
    boundaryFailures(
      path.join(v4Root, "lab/cases/mutation.mjs"),
      'import value from "../test/helper.mjs";',
      false,
    ),
    [],
  );
  for (const mutation of [
    'export * from "../test/helper.mjs";',
    'export { value } from "../test/helper.mjs";',
    'export * from "../../../lib/runtime.mjs";',
    'export * from "node:fs";',
    'export*from"node:fs";',
    'export/*closed*/ * /*closed*/from/*closed*/"node:fs";',
    'export { value } from "partner-sdk";',
    'import{value}from"partner-sdk";',
  ]) {
    assert.notDeepEqual(
      boundaryFailures(
        path.join(v4Root, "lab/cases/mutation.mjs"),
        mutation,
        false,
      ),
      [],
    );
  }
  assert.notDeepEqual(
    boundaryFailures(
      path.join(v4Root, "lab/cases/mutation.mjs"),
      'import value from "../../../lib/runtime.mjs";',
      false,
    ),
    [],
  );
  for (const mutation of [
    "export function execute() {}",
    "export const EffectPort = {};",
    "export class Client {}",
    "export function registerCallback() {}",
    "export function createLiveClient() {}",
    "export function persist() {}",
    "export function bindDestination() {}",
  ]) {
    assert.notDeepEqual(
      exportedNames(mutation).filter((name) => ![
        "canonicalize",
        "createKernel",
        "deriveClaims",
        "evaluateTransition",
        "identifyEvidence",
        "projectAuthorityView",
        "validateGraph",
      ].includes(name)),
      [],
    );
  }
});
