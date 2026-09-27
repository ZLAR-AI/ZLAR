// Canonical serialization. Two parties must produce byte-identical bytes for the
// same logical object or every signature check becomes a coin flip.
//
// Rules: object keys sorted by code unit, no insignificant whitespace, no
// floating point (integers only — a consequence measure expressed as a float is
// a rounding bug waiting to move money), undefined rejected rather than dropped.

export function canonical(value) {
  return JSON.stringify(prepare(value));
}

function prepare(v) {
  if (v === null) return null;
  if (Array.isArray(v)) return v.map(prepare);
  switch (typeof v) {
    case 'string':
    case 'boolean':
      return v;
    case 'number':
      if (!Number.isInteger(v)) {
        throw new Error(`non-integer number in canonical form: ${v} — express measures in smallest units`);
      }
      return v;
    case 'object': {
      const out = {};
      for (const k of Object.keys(v).sort()) {
        if (v[k] === undefined) throw new Error(`undefined value at key "${k}"`);
        out[k] = prepare(v[k]);
      }
      return out;
    }
    default:
      throw new Error(`unserializable type in canonical form: ${typeof v}`);
  }
}

export function canonicalBytes(value) {
  return Buffer.from(canonical(value), 'utf8');
}
