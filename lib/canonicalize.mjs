// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Canonicalization — Formal Implementation
//
// Implements the ZLAR Canonicalization Specification v1.0
// (docs/canonicalization-spec.md). Produces byte-identical output to:
//   - jq -S -c '.'  (bash gate)
//   - RFC 8785 (for ZLAR-constrained structures)
//
// This module is the single source of truth for canonical form.
// Receipt signing, verification, and audit entry hashing all use this.
//
// Dependencies: none. Node.js built-ins only.
// ═══════════════════════════════════════════════════════════════════════════════

const MAX_SAFE_INTEGER = 9007199254740991;   // 2^53 - 1
const MIN_SAFE_INTEGER = -9007199254740991;  // -(2^53 - 1)

// ─── Validation ─────────────────────────────────────────────────────────────

/**
 * Validate that a value conforms to ZLAR canonical constraints.
 * Throws if the value contains floats, non-ASCII keys, or unsafe integers.
 *
 * @param {*} value - JSON-serializable value to validate
 * @param {string} [path='$'] - JSON path for error messages
 * @throws {Error} if the value violates ZLAR canonical constraints
 */
export function validateCanonical(value, path = '$') {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return;
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error(`${path}: NaN and Infinity are not allowed in ZLAR canonical form`);
    }
    if (!Number.isInteger(value)) {
      throw new Error(`${path}: floating-point numbers are not allowed in ZLAR canonical form (got ${value}). Use integers or string-encoded values.`);
    }
    if (value > MAX_SAFE_INTEGER || value < MIN_SAFE_INTEGER) {
      throw new Error(`${path}: integer ${value} is outside safe range (-(2^53-1) to 2^53-1)`);
    }
    if (Object.is(value, -0)) {
      return; // -0 is valid input but serializes as 0
    }
    return;
  }

  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      validateCanonical(value[i], `${path}[${i}]`);
    }
    return;
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value);

    // Check for non-ASCII keys
    for (const key of keys) {
      if (key.length === 0) {
        throw new Error(`${path}: empty string keys are not allowed in ZLAR canonical form`);
      }
      for (let i = 0; i < key.length; i++) {
        if (key.charCodeAt(i) > 127) {
          throw new Error(`${path}.${key}: non-ASCII characters in property names are not allowed in ZLAR canonical form`);
        }
      }
    }

    // Check for duplicate keys (JS objects can't have true duplicates,
    // but parsed JSON with duplicate keys keeps the last value — check
    // is here for documentation and for use with parsed-then-validated flows)

    // Recurse into values
    for (const key of keys) {
      validateCanonical(value[key], `${path}.${key}`);
    }
    return;
  }

  throw new Error(`${path}: unsupported type ${typeof value} in ZLAR canonical form`);
}

// ─── Canonicalization ───────────────────────────────────────────────────────

/**
 * Recursively sort object keys by Unicode code point order.
 * Arrays preserve element order. Primitives pass through.
 *
 * @param {*} value - JSON value to sort
 * @returns {*} Value with all object keys sorted recursively
 */
function sortKeysRecursive(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(sortKeysRecursive);

  const sorted = {};
  // Object.keys returns keys as strings. String.prototype.sort() uses
  // UTF-16 code unit comparison by default, which for ASCII-only keys
  // is identical to Unicode code point order and byte order.
  for (const key of Object.keys(value).sort()) {
    sorted[key] = sortKeysRecursive(value[key]);
  }
  return sorted;
}

/**
 * Produce the ZLAR canonical form of a JSON-serializable value.
 *
 * This is the single function that defines canonical output.
 * It produces byte-identical results to:
 *   - jq -S -c '.' (for ZLAR-constrained input)
 *   - RFC 8785 canonicalization (for ZLAR-constrained input)
 *
 * @param {*} value - JSON-serializable value
 * @param {object} [opts]
 * @param {boolean} [opts.validate=true] - Whether to validate constraints before canonicalizing.
 *   Set to false only when you have already validated the input.
 * @returns {string} Canonical JSON string (UTF-8 when encoded to bytes)
 * @throws {Error} if validation is enabled and the value violates constraints
 */
export function canonicalize(value, opts = {}) {
  const validate = opts.validate !== false;
  if (validate) {
    validateCanonical(value);
  }
  return JSON.stringify(sortKeysRecursive(value));
}

/**
 * Produce the ZLAR canonical form as a UTF-8 Buffer.
 * Use this when you need the exact bytes for hashing or signing.
 *
 * @param {*} value - JSON-serializable value
 * @param {object} [opts] - Same options as canonicalize()
 * @returns {Buffer} Canonical JSON as UTF-8 bytes
 */
export function canonicalizeBytes(value, opts = {}) {
  return Buffer.from(canonicalize(value, opts), 'utf8');
}
