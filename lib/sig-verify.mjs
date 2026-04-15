// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Ed25519 Signature Verification — Multi-Canonical
//
// Verifies an Ed25519 signature over the SHA-256 hex of a canonical JSON
// form. Accepts multiple canonical forms during the migration period
// documented in ADR-011.
//
// Background. The project currently has three canonical forms in active
// circulation:
//
//   (1) ZLAR spec form — compact, sorted, no trailing newline.
//       Matches `lib/canonicalize.mjs` and docs/canonicalization-spec.md.
//       Used by the MCP gate end-to-end and by `bin/zlar-receipt` CLI (the
//       latter by command-substitution \n-strip accident).
//
//   (2) Bash-pipeline form — compact, sorted, trailing newline.
//       Used by `bin/zlar-gate` internal receipt signing, audit entry
//       signing, and manifest verification — anywhere a `jq -S -c` output
//       is piped directly to `shasum -a 256`. jq appends the newline; the
//       pipeline preserves it into the hash input.
//
//   (3) Bash-pretty form — plain (unsorted) pretty-printed with 2-space
//       indent, trailing newline. Used by `bin/zlar-policy sign` and
//       `bin/zlar-constitution sign` (plain `jq '.signature.value = ""'`
//       on a file). The bash gate's runtime verification of policy /
//       standing approvals / constitution uses the same plain-jq form so
//       signer and verifier agree — but the form does not match the spec.
//
// The spec (docs/canonicalization-spec.md line 89) says "No trailing
// newline. The output is a single UTF-8 byte sequence with no padding."
// Forms (2) and (3) both violate the spec. Migration is tracked in
// ADR-011.
//
// For the MCP gate, this module supports verification under any of the
// three forms so the gate can verify currently-deployed signed files
// without breaking the audit chain or requiring a flag-day re-signing.
// When legacy forms are accepted, a warning is logged so operators see
// the migration need.
//
// An attacker cannot use the multi-form acceptance as a forgery primitive:
// verifying any form still requires a valid Ed25519 signature under the
// known public key, and the hash input for each form is uniquely
// determined by the object bytes.
// ═══════════════════════════════════════════════════════════════════════════════

import { createHash, verify as cryptoVerify } from 'crypto';
import { canonicalize } from './canonicalize.mjs';

export function sha256hex(data) {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

// Build the three canonical forms from a cleared-signature object.
// "Cleared" means the caller has already zeroed the signature-value
// field(s) per the signing convention for that file type.
//
// Returns an array ordered by preference:
//   [0] spec form — compact sorted, no trailing newline (ADR-011 target)
//   [1] bash-pipeline form — compact sorted, trailing newline
//   [2] bash-pretty form — plain pretty-printed with 2-space indent and
//       trailing newline; preserves input key order
export function canonicalFormVariants(clearedObj) {
  const compact = canonicalize(clearedObj);
  const pretty = JSON.stringify(clearedObj, null, 2) + '\n';
  return [compact, compact + '\n', pretty];
}

// Labels for the three forms in the order returned by canonicalFormVariants.
// Kept as a constant so test assertions and log messages cannot drift.
export const CANONICAL_FORM_LABELS = Object.freeze([
  'spec',
  'bash-pipeline',
  'bash-pretty',
]);

// Verify a signature against any of the supplied canonical forms.
// Returns { ok, form, reason } — form is one of CANONICAL_FORM_LABELS
// or null; reason is populated on failure.
export function verifyAnyCanonical(canonicalForms, pubKeyPem, sigBase64) {
  let sigBytes;
  try {
    sigBytes = Buffer.from(sigBase64, 'base64');
  } catch (e) {
    return { ok: false, form: null, reason: `signature not valid base64: ${e.message}` };
  }

  for (let i = 0; i < canonicalForms.length; i++) {
    const hashHex = sha256hex(canonicalForms[i]);
    try {
      if (cryptoVerify(null, Buffer.from(hashHex, 'utf8'), pubKeyPem, sigBytes)) {
        return { ok: true, form: CANONICAL_FORM_LABELS[i] || `form-${i}`, reason: null };
      }
    } catch (e) {
      // A malformed key or sigBytes throws here; keep trying remaining forms
      // rather than short-circuiting, so one bad candidate form doesn't mask
      // a good one later in the list.
      continue;
    }
  }
  return {
    ok: false,
    form: null,
    reason: `signature verification failed across ${canonicalForms.length} canonical forms (see ADR-011)`,
  };
}
