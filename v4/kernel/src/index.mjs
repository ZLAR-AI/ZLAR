import { deriveClaimsMaterialized } from "./claims.mjs";
import { analyzeGraph } from "./graph.mjs";
import { identifyMaterialized } from "./identity.mjs";
import { createKernelMaterialized } from "./kernel.mjs";
import { projectMaterialized } from "./projection.mjs";
import {
  refusalFromError,
  refusalResult,
} from "./refusal.mjs";
import {
  canonicalText,
  isProxyValue,
  materializeCanonical,
} from "./safe-data.mjs";
import {
  evaluateMaterialized,
  publicTransitionResult,
} from "./transition.mjs";

export function createKernel(input) {
  if (isProxyValue(input)) {
    return refusalResult(
      "createKernel",
      ["proxy_object_forbidden"],
      "$",
      "proxy_rejected_before_reflection",
    );
  }
  try {
    return createKernelMaterialized(materializeCanonical(input));
  } catch (error) {
    return refusalFromError("createKernel", error);
  }
}

export function canonicalize(value) {
  if (isProxyValue(value)) {
    return refusalResult(
      "canonicalize",
      ["proxy_object_forbidden"],
      "$",
      "proxy_rejected_before_reflection",
    );
  }
  try {
    return Object.freeze({
      outcome: "canonicalized",
      canonical_text: canonicalText(value),
    });
  } catch (error) {
    return refusalFromError("canonicalize", error);
  }
}

export function identifyEvidence(input) {
  if (isProxyValue(input)) {
    return refusalResult(
      "identifyEvidence",
      ["proxy_object_forbidden"],
      "$",
      "proxy_rejected_before_reflection",
    );
  }
  if (typeof input === "string") {
    return refusalResult(
      "identifyEvidence",
      ["raw_json_text_ingress_forbidden"],
      "$",
      "raw_json_text",
    );
  }
  try {
    return identifyMaterialized(materializeCanonical(input));
  } catch (error) {
    return refusalFromError("identifyEvidence", error);
  }
}

export function validateGraph(graph) {
  if (isProxyValue(graph)) {
    return refusalResult(
      "validateGraph",
      ["proxy_object_forbidden"],
      "$",
      "proxy_rejected_before_reflection",
    );
  }
  try {
    const analysis = analyzeGraph(materializeCanonical(graph));
    if (analysis.codes.length) {
      return refusalResult(
        "validateGraph",
        analysis.codes,
        "$.records",
        "graph_invariants",
      );
    }
    return analysis.result;
  } catch (error) {
    return refusalFromError("validateGraph", error);
  }
}

export function evaluateTransition(input) {
  if (isProxyValue(input)) {
    return refusalResult(
      "evaluateTransition",
      ["proxy_object_forbidden"],
      "$",
      "proxy_rejected_before_reflection",
    );
  }
  try {
    const materialized = materializeCanonical(input);
    const evaluation = evaluateMaterialized(materialized);
    return publicTransitionResult(evaluation);
  } catch (error) {
    return refusalFromError("evaluateTransition", error);
  }
}

export function projectAuthorityView(input) {
  if (isProxyValue(input)) {
    return refusalResult(
      "projectAuthorityView",
      ["proxy_object_forbidden"],
      "$",
      "proxy_rejected_before_reflection",
    );
  }
  try {
    return projectMaterialized(materializeCanonical(input));
  } catch (error) {
    return refusalFromError("projectAuthorityView", error);
  }
}

export function deriveClaims(input) {
  if (isProxyValue(input)) {
    return refusalResult(
      "deriveClaims",
      ["proxy_object_forbidden"],
      "$",
      "proxy_rejected_before_reflection",
    );
  }
  try {
    return deriveClaimsMaterialized(materializeCanonical(input));
  } catch (error) {
    return refusalFromError("deriveClaims", error);
  }
}
