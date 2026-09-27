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
// They are described here by how the bytes are produced, because that is what
// an independent implementer needs in order to reproduce them. Which component
// produces which form is an internal detail and is deliberately not recorded in
// a published file.
//
//   (1) ZLAR spec form — compact, sorted, no trailing newline.
//       Matches `canonicalize.mjs` and the canonicalization spec. Produced
//       wherever a serializer writes the canonical bytes directly, and also
//       wherever a shell captures them by command substitution, which strips
//       a trailing newline as a side effect.
//
//   (2) Pipeline form — compact, sorted, WITH a trailing newline.
//       Produced wherever sorted compact JSON is piped straight into a hash
//       command. The JSON tool appends a newline and the pipeline carries it
//       into the hash input, so the digest differs from form (1) over
//       otherwise identical content.
//
//   (3) Pretty form — plain (unsorted) pretty-printed, 2-space indent, with a
//       trailing newline. Produced wherever a file is rewritten in place by a
//       pretty-printer before signing. Signer and verifier agree with each
//       other in that path, but the form does not match the spec.
//
// The spec (docs/canonicalization-spec.md line 89) says "No trailing
// newline. The output is a single UTF-8 byte sequence with no padding."
// Forms (2) and (3) both violate the spec. Migration is tracked in
// ADR-011.
//
// This module therefore verifies under any of the three forms, so that
// already-deployed signed files remain verifiable without breaking an audit
// chain or forcing a flag-day re-signing. When a legacy form is accepted, a
// warning is logged so operators can see the migration is still outstanding.
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
