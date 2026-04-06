# ZLAR Canonicalization Specification v1.0

## Status

This document defines the canonical form for ZLAR Governed Action Receipts and audit trail entries. All implementations that produce or verify signatures over ZLAR JSON structures MUST follow this specification.

This specification adopts RFC 8785 (JSON Canonicalization Scheme) with a constrained schema that eliminates its known failure modes.

## Overview

ZLAR uses JSON structures for audit trail entries and governed action receipts. These structures are signed with Ed25519 over their SHA-256 hash. For signatures to verify across implementations (bash, Node.js, Python, Go, Rust), every implementation must produce byte-identical canonical output for the same logical data.

The canonical form is computed by:

1. Recursively sorting all object keys
2. Serializing as compact JSON with no whitespace between tokens
3. Encoding as UTF-8 bytes

The canonical bytes are then hashed with SHA-256 (lowercase hex output), and the hex string bytes are signed with Ed25519.

## Specification

### 1. Key Ordering

Object keys MUST be sorted recursively at all nesting levels.

Sort order: **Unicode code point order** of the key strings, treating each code point as an unsigned integer. For the constrained ZLAR schema (ASCII-only keys), this is identical to:

- Lexicographic byte order of UTF-8 encoding
- UTF-16 code unit order (as specified by RFC 8785)
- ASCII alphabetical order

All three sort orders produce identical results when keys are restricted to ASCII characters.

**Rationale:** RFC 8785 specifies sorting by UTF-16 code units. The Rust crate `serde_jcs` has a confirmed bug where it sorts by UTF-8 bytes instead, which diverges for keys containing characters above U+FFFF. By restricting ZLAR keys to ASCII, all sort orders converge and the bug class is eliminated.

### 2. Schema Constraints

ZLAR canonical form applies to JSON structures that conform to these type restrictions:

**Allowed types:**
- Strings (UTF-8, any content)
- Integers (no fractional part, within safe integer range: -(2^53 - 1) to 2^53 - 1)
- Booleans (`true`, `false`)
- Null (`null`)
- Arrays (preserving element order)
- Nested objects (keys recursively sorted)

**Prohibited types:**
- Floating-point numbers (numbers with fractional parts)

**Prohibited in property names:**
- Non-ASCII characters (U+0080 and above)
- Empty strings

**Rationale:** Floating-point serialization is the primary source of cross-language canonicalization failures. JavaScript's `JSON.stringify(100.0)` produces `"100"`. Python's `json.dumps(100.0)` produces `"100.0"`. Eliminating floats from the schema eliminates this entire vulnerability class. Integer serialization is trivial and consistent across all languages.

### 3. Number Representation

Integers MUST be serialized as decimal digits with no leading zeros, no trailing zeros, no decimal point, and no exponent notation within the safe integer range.

- `0` serializes as `0`
- `-1` serializes as `-1`
- `9007199254740991` (2^53 - 1) serializes as `9007199254740991`
- Negative zero MUST serialize as `0` (not `-0`)

Numbers outside the safe integer range (-(2^53 - 1) to 2^53 - 1) MUST NOT appear in ZLAR structures. Implementations MUST reject them.

### 4. String Serialization

Strings MUST be serialized following standard JSON escaping rules (RFC 8259):

- Characters that MUST be escaped: `"` (U+0022) as `\"`, `\` (U+005C) as `\\`, and control characters U+0000 through U+001F using `\uXXXX` notation
- The following shorthand escapes MUST be used when applicable: `\b` (U+0008), `\f` (U+000C), `\n` (U+000A), `\r` (U+000D), `\t` (U+0009)
- All other characters, including non-ASCII characters, MUST be output as literal UTF-8 bytes (not escaped to `\uXXXX`)

This matches the behavior of JavaScript's `JSON.stringify()` and RFC 8785.

**No Unicode normalization is performed.** The same logical character in NFC and NFD forms produces different canonical output. ZLAR structures SHOULD use NFC-normalized strings, but the canonicalization algorithm does not enforce this.

### 5. Boolean and Null Representation

- `true` serializes as the 4 bytes: `t`, `r`, `u`, `e`
- `false` serializes as the 5 bytes: `f`, `a`, `l`, `s`, `e`
- `null` serializes as the 4 bytes: `n`, `u`, `l`, `l`

### 6. Whitespace

No whitespace between tokens. No trailing newline. The output is a single UTF-8 byte sequence with no padding.

### 7. Arrays

Arrays preserve element order. Elements are canonicalized recursively.

### 8. Duplicate Keys

Duplicate keys within the same object MUST NOT appear. Implementations MUST reject input containing duplicate keys.

### 9. Output Encoding

The canonical output MUST be UTF-8 encoded. No byte order mark (BOM). No trailing newline.

## Signing Protocol

Given a ZLAR JSON structure to be signed:

1. **Neutralize the signature field.** The approach depends on the structure type:
   - **Receipts (v1 envelope):** Remove the `sig` field entirely before canonicalizing the envelope for chain hashing. For signing, the payload is canonicalized independently (the `sig` field is not part of the payload).
   - **Policy and manifest files (v0 inline signing):** Zero the signature value fields (set `signature.algorithm`, `signature.value`, and `signature.key_id` to empty strings `""`) but retain the `signature` object structure. This matches the behavior of `jq '.signature = {algorithm:"",value:"",key_id:""}'` used by both gates.

2. **Canonicalize.** Apply the canonicalization rules above to produce a UTF-8 byte sequence.

3. **Hash.** Compute SHA-256 over the canonical bytes. Output as lowercase hexadecimal string (64 characters).

4. **Sign.** Ed25519-sign the UTF-8 bytes of the hex string (not the binary hash, the hex string characters). This matches `openssl pkeyutl -rawin`.

5. **Encode.** Base64-encode the 64-byte Ed25519 signature.

## Verification Protocol

Given a signed ZLAR JSON structure and an Ed25519 public key:

1. Extract the `signature.value` field (base64-encoded signature).
2. Remove the `signature` field from the structure.
3. Canonicalize the remaining structure per this specification.
4. SHA-256 hash the canonical bytes, output as lowercase hex string.
5. Base64-decode the signature value to obtain the 64-byte Ed25519 signature.
6. Verify the Ed25519 signature against the UTF-8 bytes of the hex string using the public key.

## Compatibility Notes

### Relationship to RFC 8785

This specification is a strict subset of RFC 8785 (JSON Canonicalization Scheme). Any ZLAR-canonical JSON is also RFC 8785-canonical. However, not all RFC 8785-canonical JSON is ZLAR-canonical, because ZLAR prohibits floats and non-ASCII property names.

### Relationship to jq -S -c

The bash gate uses `jq -S -c '.'` for canonicalization. For ZLAR-constrained structures (no floats, ASCII keys), `jq -S -c` produces byte-identical output to this specification. This is by design — the constraint strategy ensures tool compatibility without depending on tool-specific behavior.

### Relationship to JSON.stringify with sorted keys

Node.js's `JSON.stringify(sortKeysRecursive(obj))` produces byte-identical output to this specification for ZLAR-constrained structures. JavaScript natively uses V8's number serialization and UTF-8 string encoding, both of which align with JCS.

## Implementation Guidance

| Language | Recommended Implementation |
|---|---|
| Node.js/TypeScript | `canonicalize` npm package (erdtman, RFC 8785 reference) or recursive key-sort + `JSON.stringify` |
| Python | `rfc8785` package (Trail of Bits) or recursive key-sort + `json.dumps(ensure_ascii=False, separators=(',', ':'))` |
| Go | `gowebpki/jcs` package |
| Java | `titanium-jcs` or `erdtman/java-json-canonicalization` |
| Rust | `serde_json_canonicalizer` (NOT `serde_jcs` — confirmed UTF-16 sorting bug) |
| Bash | `jq -S -c '.'` (only valid for ZLAR-constrained structures) |

## Test Vectors

See `tests/fixtures/canonicalization-vectors.json` for the complete test vector suite. Each vector contains an input JSON structure and the expected canonical UTF-8 byte sequence. Implementations MUST produce byte-identical output for every vector.
