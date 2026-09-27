import { createHash } from "node:crypto";

import {
  EVIDENCE_DOMAIN,
  DERIVED_RECORD_TYPES,
  RECORD_TYPES,
  SCHEMA_VERSION,
} from "./constants.mjs";
import { refuse } from "./refusal.mjs";
import {
  assertExactKeys,
  assertRegistryToken,
  canonicalTextFromMaterialized,
} from "./safe-data.mjs";

function identifyWithRegistry(input, allowedRecordTypes) {
  assertExactKeys(
    input,
    ["record_type", "record_body", "schema_version"],
    "$",
  );
  const recordType = assertRegistryToken(input.record_type, "$.record_type");
  const schemaVersion = assertRegistryToken(
    input.schema_version,
    "$.schema_version",
  );
  if (!allowedRecordTypes.includes(recordType)) {
    refuse("record_type_unknown", "$.record_type", "closed_record_registry");
  }
  if (schemaVersion !== SCHEMA_VERSION) {
    refuse("schema_version_unknown", "$.schema_version", "closed_schema_registry");
  }
  const canonicalBody = canonicalTextFromMaterialized(input.record_body);
  const digest = createHash("sha256")
    .update(`${EVIDENCE_DOMAIN}\u0000`, "utf8")
    .update(recordType, "utf8")
    .update("\u0000", "utf8")
    .update(schemaVersion, "utf8")
    .update("\u0000", "utf8")
    .update(canonicalBody, "utf8")
    .digest("hex");
  return Object.freeze({
    outcome: "evidence_identified",
    evidence_id: `${EVIDENCE_DOMAIN}:sha256:${digest}`,
    record_type: recordType,
    schema_version: schemaVersion,
    canonical_body: canonicalBody,
    identity_claim: "evidence_byte_identity_only",
  });
}

export function identifyMaterialized(input) {
  return identifyWithRegistry(input, RECORD_TYPES);
}

export function identifyDerived(recordType, recordBody) {
  return identifyWithRegistry(
    {
      record_type: recordType,
      schema_version: SCHEMA_VERSION,
      record_body: recordBody,
    },
    DERIVED_RECORD_TYPES,
  );
}
