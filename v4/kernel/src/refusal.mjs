import { REFUSAL_CODES } from "./constants.mjs";

const refusalCodeSet = new Set(REFUSAL_CODES);

export class RefusalSignal extends Error {
  constructor(code, path = "$", detailsClass = "contract_boundary") {
    super(code);
    this.name = "RefusalSignal";
    this.code = refusalCodeSet.has(code) ? code : "internal_contract_refusal";
    this.path = typeof path === "string" ? path : "$";
    this.detailsClass = typeof detailsClass === "string"
      ? detailsClass
      : "contract_boundary";
  }
}

export function refuse(code, path = "$", detailsClass = "contract_boundary") {
  throw new RefusalSignal(code, path, detailsClass);
}

export function refusalResult(
  operation,
  codes,
  path = "$",
  detailsClass = "contract_boundary",
  evidenceRefs = [],
) {
  const normalized = [...new Set(codes.filter((code) => refusalCodeSet.has(code)))]
    .sort();
  const refusalCodes = normalized.length
    ? normalized
    : ["internal_contract_refusal"];
  return Object.freeze({
    outcome: "refused",
    refusal_codes: Object.freeze(refusalCodes),
    operation,
    path: typeof path === "string" ? path : "$",
    evidence_refs: Object.freeze([...evidenceRefs].sort()),
    details_class: typeof detailsClass === "string"
      ? detailsClass
      : "contract_boundary",
    state_unchanged: true,
  });
}

export function refusalFromError(operation, error) {
  if (error instanceof RefusalSignal) {
    return refusalResult(
      operation,
      [error.code],
      error.path,
      error.detailsClass,
    );
  }
  return refusalResult(
    operation,
    ["internal_contract_refusal"],
    "$",
    "internal_fault_suppressed",
  );
}
