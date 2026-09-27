import { SYNTHETIC_CONTEXT } from "../fixtures/context.mjs";
import { CASE_KERNEL_INPUTS } from "../fixtures/kernel-inputs.mjs";
import { FIXTURE_IDS } from "../fixtures/registry.mjs";

export const CASE_CATALOG = Object.freeze(FIXTURE_IDS.map((caseId) =>
  Object.freeze({
    request: Object.freeze({
      case_id: caseId,
      context: SYNTHETIC_CONTEXT,
    }),
    kernel_input: CASE_KERNEL_INPUTS[caseId],
  })));
