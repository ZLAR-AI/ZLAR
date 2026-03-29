// ═══════════════════════════════════════════════════════════════════════════════
// Token Canonical Form — shared between daemon and membrane
//
// Single source of truth. Both chain.mjs (client-side signing/verification)
// and daemon.mjs (server-side signing/verification) import from here.
//
// If this function changes, both sides change together. No drift possible.
//
// Canonical string: "{jti}|{sub}|{pub}|{depth}|{iat}|{parent_jti_or_empty}"
//
// NOTE: The separator '|' is not escaped. Agent IDs (sub) containing '|'
// could produce canonical collisions. UUIDs and base64 keys do not contain
// '|' in practice. A future schema version should use a length-prefixed or
// escaped format.
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Deterministic canonical string for signing/verifying a delegation token.
 * @param {object} t — token object with jti, sub, pub, depth, iat, parent_jti
 * @returns {string} canonical form for hashing
 */
export function tokenCanonical(t) {
  return [
    t.jti,
    t.sub,
    t.pub,
    String(t.depth),
    String(t.iat),
    t.parent_jti ?? '',
  ].join('|');
}
