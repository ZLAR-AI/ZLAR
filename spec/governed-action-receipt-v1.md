# Governed Action Receipt Specification — v1

**Status**: Published v1.0
**Version**: 1
**Date**: 2026-04-16
**License**: Apache 2.0
**Pinned signing key**: `spec/test-key.pub` (fingerprint `72735da8aebb8106`, Ed25519)

---

## Abstract

A Governed Action Receipt is a portable cryptographic artifact proving that a specific action by a specific AI agent was evaluated against policy, decided by a stated authority (policy or human), and recorded in a form that any party holding the verifier's public key can verify without access to the governance system that produced it.

This specification defines the v1 envelope format, canonical JSON form, signing algorithm, verification procedure, and semantic validation rules. A conforming implementation can be built from this specification alone, with no dependency on the ZLAR reference implementation. Test vectors are provided in Annex A. The Coupling Theorem in Annex B explains why the receipt's value depends on the invariants being enforced at the time of issuance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted per [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

Terminology:

- **Producer**: software that creates and signs a receipt.
- **Verifier**: software that checks a receipt's integrity and semantic validity.
- **Payload**: the set of governance fields that describe the decided action.
- **Envelope**: the outer wrapper that carries the payload, signature, and metadata.
- **Canonical form**: a deterministic byte sequence produced by the canonicalization rules in §4.

## 2. Envelope Format

A v1 receipt is a JSON object with exactly these fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `v` | integer | MUST | Version. MUST be the integer `1`. Strings are not permitted. |
| `id` | string | MUST | Receipt identifier. 44 lowercase hex characters (see §3.1). |
| `kid` | string | MUST | Key identifier. 16 lowercase hex characters (see §3.2). |
| `iat` | integer | MUST | Issued-at Unix epoch seconds. UTC. |
| `type` | string | MUST | Receipt type. MUST be the string `"governed-action"`. |
| `payload` | string | MUST | Base64url-encoded (no padding) canonical JSON payload (see §5). |
| `sig` | string | MUST | Base64url-encoded (no padding) Ed25519 signature (see §6). |
| `prev` | string or null | MUST | Previous receipt hash for chain linking (see §3.3), or `null` for a standalone or root receipt. |

No other fields are permitted at the envelope level. Verifiers MUST reject receipts with unknown envelope fields.

There is no algorithm negotiation field. The integer `v` determines the full cryptographic construction:

**v1 = Ed25519 signature over SHA-256 of canonical JSON payload, with canonical form defined in §4.**

A future v2 will use a different construction and be identified by a different integer in `v`.

## 3. Field Formats

### 3.1 Receipt ID (`id`)

44 lowercase hexadecimal characters representing at least 128 bits of cryptographic entropy. Producers MUST generate a fresh value for each receipt such that collisions are negligible for all practical purposes. The specific construction is not prescribed; a typical construction is a short timestamp prefix followed by at least 16 random bytes, with both portions expressed as hex.

Verifiers MUST NOT rely on the `id` field for ordering, timing, or any cryptographic purpose. It is an identifier for correlation and deduplication only.

### 3.2 Key ID (`kid`)

The first 16 lowercase hexadecimal characters of the SHA-256 hash of the **public key file** as stored on disk, PEM-encoded. This is a fingerprint of the key material, not of the raw key bytes. Verifiers use `kid` to select the correct public key from a keyring.

Producers and verifiers MUST agree on the exact fingerprinting procedure. The reference procedure is: `shasum -a 256 <public-key.pem> | awk '{print substr($1,1,16)}'`.

### 3.3 Previous Receipt Hash (`prev`)

For chain linking. Either `null` (for a standalone or root receipt) or a string containing the lowercase hex of the SHA-256 hash of the previous receipt's canonical envelope bytes.

A verifier presented with a chain of receipts MUST verify each receipt individually and, if `prev` is non-null, MUST verify that the hash matches the canonical envelope of the claimed predecessor. The verifier MAY compute the canonical envelope form by re-serializing with sorted keys per §4, or MAY rely on a byte-cached copy of the predecessor.

### 3.4 Issued-At (`iat`)

Unix epoch seconds as an integer. Verifiers MUST enforce a time window around their own current time:

- Default maximum future skew: **300 seconds** (for clock drift between producer and verifier).
- Default maximum age: **31,536,000 seconds** (one year).

Both bounds are configurable by the verifier. Receipts outside the configured window MUST be rejected.

## 4. Canonicalization

Canonical form is a deterministic byte sequence. Two conforming implementations MUST produce byte-identical canonical form for the same input.

The v1 canonical form is a subset of [RFC 8785 (JCS)](https://datatracker.ietf.org/doc/html/rfc8785) with the following additional constraints:

- **No floating-point numbers.** All numeric values MUST be integers in the range ±(2^53 − 1).
- **No NaN or Infinity.** These are not valid JSON in RFC 8259 either, and MUST be rejected at canonicalization time.
- **No non-ASCII characters in property keys.** All property key bytes MUST be in the range 0x20–0x7E.
- **No empty-string property keys.**
- **Object key ordering**: properties within each object MUST be sorted lexicographically by key (byte-wise comparison of UTF-8-encoded key bytes), recursively at every nesting level.
- **No whitespace.** The output MUST contain no whitespace between tokens.
- **UTF-8 throughout** for all string values.
- **Array order**: preserved as-is.
- **Booleans**: `true`, `false`.
- **Null**: `null`.

The reference implementation is the command `jq -S -c '.'` operating on a JSON input conforming to the constraints above. An implementer may verify their canonicalization implementation against `jq -S -c` output on the test vectors in Annex A.

## 5. Payload Format

The `payload` field of the envelope is the base64url-encoded (no padding) UTF-8 bytes of a JSON object with the following fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tool` | string | MUST | Tool name (e.g., `"Bash"`, `"Write"`, `"mcp__github__create_issue"`). |
| `domain` | string | MUST | Policy domain (e.g., `"bash"`, `"write"`, `"mcp"`, `"read"`). |
| `detail_hash` | string | MUST | 64 lowercase hex characters. SHA-256 of the canonical JSON of the action detail object (the detail is not in the payload — only its hash). |
| `outcome` | string | MUST | One of: `"allow"`, `"deny"`, `"authorized"`, `"denied"`, `"timeout"`. |
| `rule` | string | MUST | Matched policy rule identifier (e.g., `"R014"`, `"default"`, `"chain:verify"`). |
| `authorizer` | string | MUST | One of: `"policy"`, `"human"`, `"gate"`, `"timeout"`, `"manifest"`. |
| `ts` | string | MUST | ISO 8601 UTC timestamp in the form `YYYY-MM-DDTHH:mm:ss.sssZ`. |
| `policy_version` | string | MUST | The version of the policy that was evaluated. |
| `manifest_agent_id` | string or null | MUST | Agent ID from the capability manifest, or `null` if no manifest is in use. |
| `manifest_principal` | string or null | MUST | Human principal from the manifest, or `null`. |
| `delegation_chain` | array | MUST | Array of delegation tokens (MAY be empty). Each token is an object with a `depth` field; structural integrity checks are defined in §8.4. |
| `audit_event_id` | string | MUST | Audit trail entry identifier this receipt refers to. |
| `audit_prev_hash` | string | MUST | The `prev_hash` field from the referenced audit entry. |

No other fields are permitted at the payload level. Verifiers MUST reject payloads with unknown fields.

### 5.1 Outcome-Authorizer Coherence

The following `(authorizer, outcome)` pairs are the only valid combinations. Producers MUST NOT emit other combinations. Verifiers MUST reject receipts with invalid combinations.

| Authorizer | Valid Outcomes |
|------------|----------------|
| `policy` | `allow`, `deny` |
| `human` | `authorized`, `denied` |
| `timeout` | `timeout`, `denied`, `deny` |
| `gate` | `deny`, `allow` |
| `manifest` | `allow`, `deny` |

The distinction between `allow` and `authorized` is load-bearing. `allow` is a policy-rule decision ("this action matches a rule permitting it"). `authorized` is a human decision ("a specific human, identifiable through the audit trail, explicitly approved this action at the time of the action"). Conflating the two is the failure mode that makes governance theater indistinguishable from governance.

A verifier MUST treat an `authorized` receipt as stronger evidence of human oversight than an `allow` receipt.

## 6. Signing

The signing procedure:

1. Construct the payload JSON object per §5.
2. Canonicalize per §4. The result is a UTF-8 byte sequence `P`.
3. Compute `H = SHA-256(P)` and encode as lowercase hex (64 hex characters). This is the **hex hash string**.
4. Sign the UTF-8 bytes of the hex hash string with the Ed25519 private key. The signature is 64 bytes.
5. Base64url-encode (no padding) the 64-byte signature. This is the value of `sig`.
6. Base64url-encode (no padding) the original `P`. This is the value of `payload`.
7. Assemble the envelope per §2, with `kid` set to the fingerprint of the signing key's public key (§3.2).

**Note**: the signed input is the UTF-8 bytes of the 64-character lowercase hex string, not the 32 raw bytes of the SHA-256 hash. These are not equivalent at the byte level. A conforming implementation MUST sign the hex string for v1 compatibility.

## 7. Verification

The verification procedure:

1. Parse the envelope as JSON. If parsing fails, the receipt is **invalid**.
2. Check that `v === 1` (exact integer comparison) and `type === "governed-action"`. Failure on either → **invalid**.
3. Check that all required envelope fields per §2 are present. Missing fields → **invalid**.
4. Check that no unknown envelope fields are present. Unknown fields → **invalid**.
5. Retrieve the public key matching `kid` from the verifier's keyring. If no match → **unknown signer** (the receipt cannot be verified with the current keyring, which is distinct from being invalid).
6. Base64url-decode the `payload` field. Call the result `P`.
7. Compute `H = SHA-256(P)` as lowercase hex (64 characters).
8. Base64url-decode the `sig` field to a 64-byte signature.
9. Verify the Ed25519 signature against the UTF-8 bytes of `H` using the retrieved public key. Verification failure → **invalid**.
10. Parse `P` as JSON. Parse failure → **invalid**.
11. Run semantic validation per §8 on the parsed payload. Any check failure → **invalid**.
12. Check `iat` is within the verifier's accepted time window (see §3.4). Out of window → **invalid**.

If all twelve steps pass, the receipt is **valid** and the parsed payload can be trusted.

## 8. Semantic Validation

A receipt passes semantic validation if and only if all of the following checks pass.

### 8.1 Completeness

All required payload fields per §5 MUST be present. String fields MUST be non-empty unless explicitly nullable in §5.

`detail_hash` MUST match the regex `^[a-f0-9]{64}$`.

`ts` MUST parse as a valid ISO 8601 UTC timestamp in the form `YYYY-MM-DDTHH:mm:ss.sssZ`. The trailing `Z` is required.

### 8.2 Outcome-Authorizer Coherence

The `(authorizer, outcome)` pair MUST appear in the table in §5.1.

### 8.3 Deny-Only Rule Consistency

The following rule identifiers are **deny-only** in v1. A receipt claiming a rule in this set together with an approval outcome (`allow` or `authorized`) is semantically invalid regardless of signature validity.

**v1 deny-only rules:**
- `R002` — Recursive or forced deletion (e.g., `rm -rf`)
- `R003` — Privilege escalation (e.g., `sudo`, `visudo`)
- `R005` — Persistence mechanisms (e.g., `launchctl load`, `crontab`)
- `R006` — Resource amplification (e.g., fork bombs, `dd if=/dev/zero`)
- `R030` — Write to `.ssh`
- `R032` — Write to ZLAR infrastructure
- `R033` — Edit ZLAR infrastructure
- `R034` — Read signing key

A verifier MAY configure additional deny-only rules specific to its deployment. A verifier MUST include the above set at minimum for v1 compatibility.

### 8.4 Delegation Chain Integrity

If `delegation_chain` is non-empty, it MUST satisfy the following structural constraints:

- The first token MUST have `depth: 0`.
- Each subsequent token MUST have `depth` strictly greater than its predecessor.
- Depth values MUST be monotonically increasing.

Token-level cryptographic verification (each child signed by its parent's private key, with the parent's public key verifiable against the daemon's signing key or a self-signed root) is handled at the gate daemon layer. A receipt-level verifier need not verify the chain's internal signatures for the receipt to be valid, but MUST check the structural integrity above.

An application that needs to trace a delegation chain to a daemon-endorsed root MUST fetch the chain from the original gate daemon or from an audit store that preserves the signed tokens. The receipt carries only the structural record.

### 8.5 Temporal Bounds

Handled by §3.4 `iat` check during verification.

## 9. Versioning Policy

v1 is **frozen**. Any change to the envelope structure, payload structure, canonicalization rules, signing algorithm, or semantic validation rules MUST be published as v2 (or later) with a different integer in the `v` field.

v1 receipts and v2 receipts are mutually incompatible — a v2 verifier MUST reject v1 receipts unless it explicitly opts into legacy v1 support, and a v1 verifier MUST reject v2 receipts.

There is no `v1.1` or `v1.x` minor-version mechanism. Any semantic change is a major-version change.

The frozen-version policy is what makes v1 receipts safe to archive for years. A relying party holding a v1 receipt issued today can verify it in 2030 with a v1 verifier built in 2030, provided the public key remains available.

## 10. Security Considerations

### 10.1 Key Management

The Ed25519 private key used to sign receipts is the most sensitive artifact in the system. Compromise of the private key allows an attacker to forge receipts. Producers SHOULD keep the private key on hardware or in a storage location that the AI agent whose actions are being governed cannot read or modify. At minimum, the key file SHOULD be owned by a user account different from the account the agent runs under, with filesystem permissions preventing agent-side read access.

Key rotation is supported by rotating the keypair and adding the new public key to the verifier's keyring alongside the old one. Receipts signed by the old key remain verifiable as long as the old public key remains in the keyring. To retire an old key, remove it from the keyring; receipts signed by the retired key will thereafter verify as "unknown signer" rather than "valid."

### 10.2 Clock Skew

Producers and verifiers SHOULD synchronize clocks to within a few seconds using NTP or equivalent. The default `iat` acceptance window is ±300 seconds for future skew; receipts claiming an `iat` more than 300 seconds in the future relative to the verifier's clock MUST be rejected.

### 10.3 Replay

This specification does not prevent replay of a valid signed receipt — a receipt can be presented multiple times to the same verifier and each presentation will return valid. Applications that need replay protection MUST use the `prev` chain linking (§3.3) together with externally maintained nonces or sequence counters to establish an ordering and detect duplication.

### 10.4 Privacy

The payload includes `tool`, `domain`, `rule`, and `authorizer` in plaintext. These fields may reveal information about the structure of the governed system (what tools the agent has, what rule categories fire, who approves what). The full `detail` of the action is **not** in the payload — only its SHA-256 hash (`detail_hash`). This preserves the verifier's ability to prove that a specific action was governed, without requiring the receipt to carry the original action content.

Applications that need additional privacy (e.g., hiding tool names or rule identifiers from the verifier) SHOULD use a higher-level privacy wrapper. The design of such wrappers is out of scope for this specification.

---

## Annex A — Test Vectors

The test vectors below were produced with a fixed Ed25519 key pair pinned to this specification. The public component is at `spec/test-key.pub` in this repository, with fingerprint `72735da8aebb8106`. The private component is held by the spec maintainer in a hardware security module and is not published. The vectors are immutable for v1.

A conforming implementation verifies these vectors by loading the public key from `spec/test-key.pub`, decoding each receipt's `payload` field via base64url, hashing the result with SHA-256, and verifying the Ed25519 signature against the UTF-8 bytes of the lowercase hex hash. The reference verifier at `spec/verify-test-vectors.mjs` does this with no dependencies on the rest of the ZLAR codebase.

---

### Test Vector 1 — Minimal policy-allow receipt

**Input payload** (JSON, before canonicalization):
```json
{
  "audit_event_id": "018fa1d03b7c4a3c8e9f1b2d6e5a7c9f",
  "audit_prev_hash": "genesis",
  "authorizer": "policy",
  "delegation_chain": [],
  "detail_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "domain": "bash",
  "manifest_agent_id": "claude-code",
  "manifest_principal": "principal@example.com",
  "outcome": "allow",
  "policy_version": "2.7.2",
  "rule": "R001",
  "tool": "Bash",
  "ts": "2026-04-09T14:17:19.000Z"
}
```

**Canonical JSON form** (sorted keys, compact, UTF-8):
```
{"audit_event_id":"018fa1d03b7c4a3c8e9f1b2d6e5a7c9f","audit_prev_hash":"genesis","authorizer":"policy","delegation_chain":[],"detail_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","domain":"bash","manifest_agent_id":"claude-code","manifest_principal":"principal@example.com","outcome":"allow","policy_version":"2.7.2","rule":"R001","tool":"Bash","ts":"2026-04-09T14:17:19.000Z"}
```

**SHA-256 of canonical bytes (lowercase hex)**:
```
862157a24a5690f87212dcf1b14d3dfd0babcc4b92e7661e55b1c8c11db9c7a7
```

**Base64url-encoded payload (no padding)**:
```
eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwM2I3YzRhM2M4ZTlmMWIyZDZlNWE3YzlmIiwiYXVkaXRfcHJldl9oYXNoIjoiZ2VuZXNpcyIsImF1dGhvcml6ZXIiOiJwb2xpY3kiLCJkZWxlZ2F0aW9uX2NoYWluIjpbXSwiZGV0YWlsX2hhc2giOiJlM2IwYzQ0Mjk4ZmMxYzE0OWFmYmY0Yzg5OTZmYjkyNDI3YWU0MWU0NjQ5YjkzNGNhNDk1OTkxYjc4NTJiODU1IiwiZG9tYWluIjoiYmFzaCIsIm1hbmlmZXN0X2FnZW50X2lkIjoiY2xhdWRlLWNvZGUiLCJtYW5pZmVzdF9wcmluY2lwYWwiOiJ2aW5jZW50QHpsYXIuYWkiLCJvdXRjb21lIjoiYWxsb3ciLCJwb2xpY3lfdmVyc2lvbiI6IjIuNy4yIiwicnVsZSI6IlIwMDEiLCJ0b29sIjoiQmFzaCIsInRzIjoiMjAyNi0wNC0wOVQxNDoxNzoxOS4wMDBaIn0
```

**Signature (base64url, no padding)**:
```
yM7HxD2DVr5VZA2O9RDgie4NmYL2C2DygF--0Cvg2Caqr_6lErsRHRUqoDIWk8AHYleTx-iiHwI35csIL7OZAg
```

**Complete signed envelope**:
```json
{
  "v": 1,
  "id": "000069d7b4efff834d877dce56badf9aee2dfcfd8f33",
  "kid": "72735da8aebb8106",
  "iat": 1775744239,
  "type": "governed-action",
  "payload": "eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwM2I3YzRhM2M4ZTlmMWIyZDZlNWE3YzlmIiwiYXVkaXRfcHJldl9oYXNoIjoiZ2VuZXNpcyIsImF1dGhvcml6ZXIiOiJwb2xpY3kiLCJkZWxlZ2F0aW9uX2NoYWluIjpbXSwiZGV0YWlsX2hhc2giOiJlM2IwYzQ0Mjk4ZmMxYzE0OWFmYmY0Yzg5OTZmYjkyNDI3YWU0MWU0NjQ5YjkzNGNhNDk1OTkxYjc4NTJiODU1IiwiZG9tYWluIjoiYmFzaCIsIm1hbmlmZXN0X2FnZW50X2lkIjoiY2xhdWRlLWNvZGUiLCJtYW5pZmVzdF9wcmluY2lwYWwiOiJ2aW5jZW50QHpsYXIuYWkiLCJvdXRjb21lIjoiYWxsb3ciLCJwb2xpY3lfdmVyc2lvbiI6IjIuNy4yIiwicnVsZSI6IlIwMDEiLCJ0b29sIjoiQmFzaCIsInRzIjoiMjAyNi0wNC0wOVQxNDoxNzoxOS4wMDBaIn0",
  "sig": "yM7HxD2DVr5VZA2O9RDgie4NmYL2C2DygF--0Cvg2Caqr_6lErsRHRUqoDIWk8AHYleTx-iiHwI35csIL7OZAg",
  "prev": null
}
```

---

### Test Vector 2 — Human-authorized receipt with chain link

**Input payload** (JSON, before canonicalization):
```json
{
  "audit_event_id": "018fa1d040a08c4a3c8e9f1b2d6e5a7c",
  "audit_prev_hash": "862157a24a5690f87212dcf1b14d3dfd0babcc4b92e7661e55b1c8c11db9c7a7",
  "authorizer": "human",
  "delegation_chain": [],
  "detail_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "domain": "bash",
  "manifest_agent_id": "claude-code",
  "manifest_principal": "principal@example.com",
  "outcome": "authorized",
  "policy_version": "2.7.2",
  "rule": "R014",
  "tool": "Bash",
  "ts": "2026-04-09T14:18:30.000Z"
}
```

**Canonical JSON form** (sorted keys, compact, UTF-8):
```
{"audit_event_id":"018fa1d040a08c4a3c8e9f1b2d6e5a7c","audit_prev_hash":"862157a24a5690f87212dcf1b14d3dfd0babcc4b92e7661e55b1c8c11db9c7a7","authorizer":"human","delegation_chain":[],"detail_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","domain":"bash","manifest_agent_id":"claude-code","manifest_principal":"principal@example.com","outcome":"authorized","policy_version":"2.7.2","rule":"R014","tool":"Bash","ts":"2026-04-09T14:18:30.000Z"}
```

**SHA-256 of canonical bytes (lowercase hex)**:
```
44122fa452f90df9757563d5aa8dc3ea33d60ef12d213cf3d40fafac20d6deb6
```

**Base64url-encoded payload (no padding)**:
```
eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwNDBhMDhjNGEzYzhlOWYxYjJkNmU1YTdjIiwiYXVkaXRfcHJldl9oYXNoIjoiODYyMTU3YTI0YTU2OTBmODcyMTJkY2YxYjE0ZDNkZmQwYmFiY2M0YjkyZTc2NjFlNTViMWM4YzExZGI5YzdhNyIsImF1dGhvcml6ZXIiOiJodW1hbiIsImRlbGVnYXRpb25fY2hhaW4iOltdLCJkZXRhaWxfaGFzaCI6ImUzYjBjNDQyOThmYzFjMTQ5YWZiZjRjODk5NmZiOTI0MjdhZTQxZTQ2NDliOTM0Y2E0OTU5OTFiNzg1MmI4NTUiLCJkb21haW4iOiJiYXNoIiwibWFuaWZlc3RfYWdlbnRfaWQiOiJjbGF1ZGUtY29kZSIsIm1hbmlmZXN0X3ByaW5jaXBhbCI6InZpbmNlbnRAemxhci5haSIsIm91dGNvbWUiOiJhdXRob3JpemVkIiwicG9saWN5X3ZlcnNpb24iOiIyLjcuMiIsInJ1bGUiOiJSMDE0IiwidG9vbCI6IkJhc2giLCJ0cyI6IjIwMjYtMDQtMDlUMTQ6MTg6MzAuMDAwWiJ9
```

**Signature (base64url, no padding)**:
```
BNg38FC0OhZutgnpY4b8HolpLldRRr7PC3XCyyvYpyBlr31kAmkZDV5mYvl6xijBTgY5LCeqhc_k1IxF6zIaAQ
```

**Complete signed envelope**:
```json
{
  "v": 1,
  "id": "000069d7b5366f7df144bbacd4aa885851d767d688b0",
  "kid": "72735da8aebb8106",
  "iat": 1775744310,
  "type": "governed-action",
  "payload": "eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwNDBhMDhjNGEzYzhlOWYxYjJkNmU1YTdjIiwiYXVkaXRfcHJldl9oYXNoIjoiODYyMTU3YTI0YTU2OTBmODcyMTJkY2YxYjE0ZDNkZmQwYmFiY2M0YjkyZTc2NjFlNTViMWM4YzExZGI5YzdhNyIsImF1dGhvcml6ZXIiOiJodW1hbiIsImRlbGVnYXRpb25fY2hhaW4iOltdLCJkZXRhaWxfaGFzaCI6ImUzYjBjNDQyOThmYzFjMTQ5YWZiZjRjODk5NmZiOTI0MjdhZTQxZTQ2NDliOTM0Y2E0OTU5OTFiNzg1MmI4NTUiLCJkb21haW4iOiJiYXNoIiwibWFuaWZlc3RfYWdlbnRfaWQiOiJjbGF1ZGUtY29kZSIsIm1hbmlmZXN0X3ByaW5jaXBhbCI6InZpbmNlbnRAemxhci5haSIsIm91dGNvbWUiOiJhdXRob3JpemVkIiwicG9saWN5X3ZlcnNpb24iOiIyLjcuMiIsInJ1bGUiOiJSMDE0IiwidG9vbCI6IkJhc2giLCJ0cyI6IjIwMjYtMDQtMDlUMTQ6MTg6MzAuMDAwWiJ9",
  "sig": "BNg38FC0OhZutgnpY4b8HolpLldRRr7PC3XCyyvYpyBlr31kAmkZDV5mYvl6xijBTgY5LCeqhc_k1IxF6zIaAQ",
  "prev": "48133e92432a87a0bbeab6651fe38df1c2a54acbe23617937ff98e2d1471a8a8"
}
```

---

### Test Vector 3 — Receipt with delegation chain (depth 2)

**Input payload** (JSON, before canonicalization):
```json
{
  "audit_event_id": "018fa1d04ad08c4a3c8e9f1b2d6e5a7c",
  "audit_prev_hash": "44122fa452f90df9757563d5aa8dc3ea33d60ef12d213cf3d40fafac20d6deb6",
  "authorizer": "policy",
  "delegation_chain": [
    {
      "depth": 0,
      "iat": 1775744239,
      "jti": "root-token-id",
      "parent_jti": null,
      "pub": "AAAA",
      "sig": "sig-root",
      "sig_alg": "ed25519",
      "sub": "orchestrator-agent",
      "v": 1
    },
    {
      "depth": 1,
      "iat": 1775744249,
      "jti": "child-token-id",
      "parent_jti": "root-token-id",
      "pub": "BBBB",
      "sig": "sig-child",
      "sig_alg": "ed25519",
      "sub": "worker-agent",
      "v": 1
    }
  ],
  "detail_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "domain": "bash",
  "manifest_agent_id": "claude-code",
  "manifest_principal": "principal@example.com",
  "outcome": "allow",
  "policy_version": "2.7.2",
  "rule": "R001",
  "tool": "Bash",
  "ts": "2026-04-09T14:19:00.000Z"
}
```

**Canonical JSON form** (sorted keys, compact, UTF-8):
```
{"audit_event_id":"018fa1d04ad08c4a3c8e9f1b2d6e5a7c","audit_prev_hash":"44122fa452f90df9757563d5aa8dc3ea33d60ef12d213cf3d40fafac20d6deb6","authorizer":"policy","delegation_chain":[{"depth":0,"iat":1775744239,"jti":"root-token-id","parent_jti":null,"pub":"AAAA","sig":"sig-root","sig_alg":"ed25519","sub":"orchestrator-agent","v":1},{"depth":1,"iat":1775744249,"jti":"child-token-id","parent_jti":"root-token-id","pub":"BBBB","sig":"sig-child","sig_alg":"ed25519","sub":"worker-agent","v":1}],"detail_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","domain":"bash","manifest_agent_id":"claude-code","manifest_principal":"principal@example.com","outcome":"allow","policy_version":"2.7.2","rule":"R001","tool":"Bash","ts":"2026-04-09T14:19:00.000Z"}
```

**SHA-256 of canonical bytes (lowercase hex)**:
```
108a7fd999930349a5ff774f86d1a36b21d39380f90bfc0c23d309de64385480
```

**Base64url-encoded payload (no padding)**:
```
eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwNGFkMDhjNGEzYzhlOWYxYjJkNmU1YTdjIiwiYXVkaXRfcHJldl9oYXNoIjoiNDQxMjJmYTQ1MmY5MGRmOTc1NzU2M2Q1YWE4ZGMzZWEzM2Q2MGVmMTJkMjEzY2YzZDQwZmFmYWMyMGQ2ZGViNiIsImF1dGhvcml6ZXIiOiJwb2xpY3kiLCJkZWxlZ2F0aW9uX2NoYWluIjpbeyJkZXB0aCI6MCwiaWF0IjoxNzc1NzQ0MjM5LCJqdGkiOiJyb290LXRva2VuLWlkIiwicGFyZW50X2p0aSI6bnVsbCwicHViIjoiQUFBQSIsInNpZyI6InNpZy1yb290Iiwic2lnX2FsZyI6ImVkMjU1MTkiLCJzdWIiOiJvcmNoZXN0cmF0b3ItYWdlbnQiLCJ2IjoxfSx7ImRlcHRoIjoxLCJpYXQiOjE3NzU3NDQyNDksImp0aSI6ImNoaWxkLXRva2VuLWlkIiwicGFyZW50X2p0aSI6InJvb3QtdG9rZW4taWQiLCJwdWIiOiJCQkJCIiwic2lnIjoic2lnLWNoaWxkIiwic2lnX2FsZyI6ImVkMjU1MTkiLCJzdWIiOiJ3b3JrZXItYWdlbnQiLCJ2IjoxfV0sImRldGFpbF9oYXNoIjoiZTNiMGM0NDI5OGZjMWMxNDlhZmJmNGM4OTk2ZmI5MjQyN2FlNDFlNDY0OWI5MzRjYTQ5NTk5MWI3ODUyYjg1NSIsImRvbWFpbiI6ImJhc2giLCJtYW5pZmVzdF9hZ2VudF9pZCI6ImNsYXVkZS1jb2RlIiwibWFuaWZlc3RfcHJpbmNpcGFsIjoidmluY2VudEB6bGFyLmFpIiwib3V0Y29tZSI6ImFsbG93IiwicG9saWN5X3ZlcnNpb24iOiIyLjcuMiIsInJ1bGUiOiJSMDAxIiwidG9vbCI6IkJhc2giLCJ0cyI6IjIwMjYtMDQtMDlUMTQ6MTk6MDAuMDAwWiJ9
```

**Signature (base64url, no padding)**:
```
ePyb0BlBOPqi-J1WHKj4ECqhWhctILmKnRKMsBoOG8jmdLtWEBjFdI_FP6T3XwGP8wqKAqqWfVSS6nlSI12DAQ
```

**Complete signed envelope**:
```json
{
  "v": 1,
  "id": "000069d7b554f8ee1198f1bfc84470dc291c6d4ede08",
  "kid": "72735da8aebb8106",
  "iat": 1775744340,
  "type": "governed-action",
  "payload": "eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwNGFkMDhjNGEzYzhlOWYxYjJkNmU1YTdjIiwiYXVkaXRfcHJldl9oYXNoIjoiNDQxMjJmYTQ1MmY5MGRmOTc1NzU2M2Q1YWE4ZGMzZWEzM2Q2MGVmMTJkMjEzY2YzZDQwZmFmYWMyMGQ2ZGViNiIsImF1dGhvcml6ZXIiOiJwb2xpY3kiLCJkZWxlZ2F0aW9uX2NoYWluIjpbeyJkZXB0aCI6MCwiaWF0IjoxNzc1NzQ0MjM5LCJqdGkiOiJyb290LXRva2VuLWlkIiwicGFyZW50X2p0aSI6bnVsbCwicHViIjoiQUFBQSIsInNpZyI6InNpZy1yb290Iiwic2lnX2FsZyI6ImVkMjU1MTkiLCJzdWIiOiJvcmNoZXN0cmF0b3ItYWdlbnQiLCJ2IjoxfSx7ImRlcHRoIjoxLCJpYXQiOjE3NzU3NDQyNDksImp0aSI6ImNoaWxkLXRva2VuLWlkIiwicGFyZW50X2p0aSI6InJvb3QtdG9rZW4taWQiLCJwdWIiOiJCQkJCIiwic2lnIjoic2lnLWNoaWxkIiwic2lnX2FsZyI6ImVkMjU1MTkiLCJzdWIiOiJ3b3JrZXItYWdlbnQiLCJ2IjoxfV0sImRldGFpbF9oYXNoIjoiZTNiMGM0NDI5OGZjMWMxNDlhZmJmNGM4OTk2ZmI5MjQyN2FlNDFlNDY0OWI5MzRjYTQ5NTk5MWI3ODUyYjg1NSIsImRvbWFpbiI6ImJhc2giLCJtYW5pZmVzdF9hZ2VudF9pZCI6ImNsYXVkZS1jb2RlIiwibWFuaWZlc3RfcHJpbmNpcGFsIjoidmluY2VudEB6bGFyLmFpIiwib3V0Y29tZSI6ImFsbG93IiwicG9saWN5X3ZlcnNpb24iOiIyLjcuMiIsInJ1bGUiOiJSMDAxIiwidG9vbCI6IkJhc2giLCJ0cyI6IjIwMjYtMDQtMDlUMTQ6MTk6MDAuMDAwWiJ9",
  "sig": "ePyb0BlBOPqi-J1WHKj4ECqhWhctILmKnRKMsBoOG8jmdLtWEBjFdI_FP6T3XwGP8wqKAqqWfVSS6nlSI12DAQ",
  "prev": null
}
```

---

### Test Vector 4 — NEGATIVE — deny-only rule with approval outcome (R003 + allow)

**Input payload** (JSON, before canonicalization):
```json
{
  "audit_event_id": "018fa1d055a08c4a3c8e9f1b2d6e5a7c",
  "audit_prev_hash": "108a7fd999930349a5ff774f86d1a36b21d39380f90bfc0c23d309de64385480",
  "authorizer": "policy",
  "delegation_chain": [],
  "detail_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "domain": "bash",
  "manifest_agent_id": "claude-code",
  "manifest_principal": "principal@example.com",
  "outcome": "allow",
  "policy_version": "2.7.2",
  "rule": "R003",
  "tool": "Bash",
  "ts": "2026-04-09T14:20:00.000Z"
}
```

**Canonical JSON form** (sorted keys, compact, UTF-8):
```
{"audit_event_id":"018fa1d055a08c4a3c8e9f1b2d6e5a7c","audit_prev_hash":"108a7fd999930349a5ff774f86d1a36b21d39380f90bfc0c23d309de64385480","authorizer":"policy","delegation_chain":[],"detail_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","domain":"bash","manifest_agent_id":"claude-code","manifest_principal":"principal@example.com","outcome":"allow","policy_version":"2.7.2","rule":"R003","tool":"Bash","ts":"2026-04-09T14:20:00.000Z"}
```

**SHA-256 of canonical bytes (lowercase hex)**:
```
876e10b7eea243f987665902e5244b6a06ab7f4bbec695f65d440237e8a5317f
```

**Base64url-encoded payload (no padding)**:
```
eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwNTVhMDhjNGEzYzhlOWYxYjJkNmU1YTdjIiwiYXVkaXRfcHJldl9oYXNoIjoiMTA4YTdmZDk5OTkzMDM0OWE1ZmY3NzRmODZkMWEzNmIyMWQzOTM4MGY5MGJmYzBjMjNkMzA5ZGU2NDM4NTQ4MCIsImF1dGhvcml6ZXIiOiJwb2xpY3kiLCJkZWxlZ2F0aW9uX2NoYWluIjpbXSwiZGV0YWlsX2hhc2giOiJlM2IwYzQ0Mjk4ZmMxYzE0OWFmYmY0Yzg5OTZmYjkyNDI3YWU0MWU0NjQ5YjkzNGNhNDk1OTkxYjc4NTJiODU1IiwiZG9tYWluIjoiYmFzaCIsIm1hbmlmZXN0X2FnZW50X2lkIjoiY2xhdWRlLWNvZGUiLCJtYW5pZmVzdF9wcmluY2lwYWwiOiJ2aW5jZW50QHpsYXIuYWkiLCJvdXRjb21lIjoiYWxsb3ciLCJwb2xpY3lfdmVyc2lvbiI6IjIuNy4yIiwicnVsZSI6IlIwMDMiLCJ0b29sIjoiQmFzaCIsInRzIjoiMjAyNi0wNC0wOVQxNDoyMDowMC4wMDBaIn0
```

**Signature (base64url, no padding)**:
```
l59NvxIv9CSXhDVBXN2vNLNA-2okeDkM8EXz6K4hzGqma_tefFu1IEOrbXetPll1iRphB2ZfAeNQ9qj4a84bDA
```

**Complete signed envelope**:
```json
{
  "v": 1,
  "id": "000069d7b59044ea3c4693c50bec8caeb24f1c77161e",
  "kid": "72735da8aebb8106",
  "iat": 1775744400,
  "type": "governed-action",
  "payload": "eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwNTVhMDhjNGEzYzhlOWYxYjJkNmU1YTdjIiwiYXVkaXRfcHJldl9oYXNoIjoiMTA4YTdmZDk5OTkzMDM0OWE1ZmY3NzRmODZkMWEzNmIyMWQzOTM4MGY5MGJmYzBjMjNkMzA5ZGU2NDM4NTQ4MCIsImF1dGhvcml6ZXIiOiJwb2xpY3kiLCJkZWxlZ2F0aW9uX2NoYWluIjpbXSwiZGV0YWlsX2hhc2giOiJlM2IwYzQ0Mjk4ZmMxYzE0OWFmYmY0Yzg5OTZmYjkyNDI3YWU0MWU0NjQ5YjkzNGNhNDk1OTkxYjc4NTJiODU1IiwiZG9tYWluIjoiYmFzaCIsIm1hbmlmZXN0X2FnZW50X2lkIjoiY2xhdWRlLWNvZGUiLCJtYW5pZmVzdF9wcmluY2lwYWwiOiJ2aW5jZW50QHpsYXIuYWkiLCJvdXRjb21lIjoiYWxsb3ciLCJwb2xpY3lfdmVyc2lvbiI6IjIuNy4yIiwicnVsZSI6IlIwMDMiLCJ0b29sIjoiQmFzaCIsInRzIjoiMjAyNi0wNC0wOVQxNDoyMDowMC4wMDBaIn0",
  "sig": "l59NvxIv9CSXhDVBXN2vNLNA-2okeDkM8EXz6K4hzGqma_tefFu1IEOrbXetPll1iRphB2ZfAeNQ9qj4a84bDA",
  "prev": null
}
```

**Expected verifier outcome**: signature verifies as valid, semantic validation FAILS with code `RULE_OUTCOME_CONTRADICTION`. A conforming verifier MUST reject this receipt.

---

### Test Vector 5 — NEGATIVE — incoherent authorizer/outcome (policy + authorized)

**Input payload** (JSON, before canonicalization):
```json
{
  "audit_event_id": "018fa1d060a08c4a3c8e9f1b2d6e5a7c",
  "audit_prev_hash": "876e10b7eea243f987665902e5244b6a06ab7f4bbec695f65d440237e8a5317f",
  "authorizer": "policy",
  "delegation_chain": [],
  "detail_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "domain": "bash",
  "manifest_agent_id": "claude-code",
  "manifest_principal": "principal@example.com",
  "outcome": "authorized",
  "policy_version": "2.7.2",
  "rule": "R001",
  "tool": "Bash",
  "ts": "2026-04-09T14:21:00.000Z"
}
```

**Canonical JSON form** (sorted keys, compact, UTF-8):
```
{"audit_event_id":"018fa1d060a08c4a3c8e9f1b2d6e5a7c","audit_prev_hash":"876e10b7eea243f987665902e5244b6a06ab7f4bbec695f65d440237e8a5317f","authorizer":"policy","delegation_chain":[],"detail_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","domain":"bash","manifest_agent_id":"claude-code","manifest_principal":"principal@example.com","outcome":"authorized","policy_version":"2.7.2","rule":"R001","tool":"Bash","ts":"2026-04-09T14:21:00.000Z"}
```

**SHA-256 of canonical bytes (lowercase hex)**:
```
7af16c064d86cc2d8a8592fede5631e5c6a647ee3543587333bac2442172c8c5
```

**Base64url-encoded payload (no padding)**:
```
eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwNjBhMDhjNGEzYzhlOWYxYjJkNmU1YTdjIiwiYXVkaXRfcHJldl9oYXNoIjoiODc2ZTEwYjdlZWEyNDNmOTg3NjY1OTAyZTUyNDRiNmEwNmFiN2Y0YmJlYzY5NWY2NWQ0NDAyMzdlOGE1MzE3ZiIsImF1dGhvcml6ZXIiOiJwb2xpY3kiLCJkZWxlZ2F0aW9uX2NoYWluIjpbXSwiZGV0YWlsX2hhc2giOiJlM2IwYzQ0Mjk4ZmMxYzE0OWFmYmY0Yzg5OTZmYjkyNDI3YWU0MWU0NjQ5YjkzNGNhNDk1OTkxYjc4NTJiODU1IiwiZG9tYWluIjoiYmFzaCIsIm1hbmlmZXN0X2FnZW50X2lkIjoiY2xhdWRlLWNvZGUiLCJtYW5pZmVzdF9wcmluY2lwYWwiOiJ2aW5jZW50QHpsYXIuYWkiLCJvdXRjb21lIjoiYXV0aG9yaXplZCIsInBvbGljeV92ZXJzaW9uIjoiMi43LjIiLCJydWxlIjoiUjAwMSIsInRvb2wiOiJCYXNoIiwidHMiOiIyMDI2LTA0LTA5VDE0OjIxOjAwLjAwMFoifQ
```

**Signature (base64url, no padding)**:
```
9Rhrasz8uMkodCvRpyiXIXM8Df2A1tZWbzSiLaCB5RhnnK3fursSi8Pg2jzjpH1Uii7AuIpoiXQrArgtmoxeBw
```

**Complete signed envelope**:
```json
{
  "v": 1,
  "id": "000069d7b5cc935ec8e9744a8f05a77e615835e5c358",
  "kid": "72735da8aebb8106",
  "iat": 1775744460,
  "type": "governed-action",
  "payload": "eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwNjBhMDhjNGEzYzhlOWYxYjJkNmU1YTdjIiwiYXVkaXRfcHJldl9oYXNoIjoiODc2ZTEwYjdlZWEyNDNmOTg3NjY1OTAyZTUyNDRiNmEwNmFiN2Y0YmJlYzY5NWY2NWQ0NDAyMzdlOGE1MzE3ZiIsImF1dGhvcml6ZXIiOiJwb2xpY3kiLCJkZWxlZ2F0aW9uX2NoYWluIjpbXSwiZGV0YWlsX2hhc2giOiJlM2IwYzQ0Mjk4ZmMxYzE0OWFmYmY0Yzg5OTZmYjkyNDI3YWU0MWU0NjQ5YjkzNGNhNDk1OTkxYjc4NTJiODU1IiwiZG9tYWluIjoiYmFzaCIsIm1hbmlmZXN0X2FnZW50X2lkIjoiY2xhdWRlLWNvZGUiLCJtYW5pZmVzdF9wcmluY2lwYWwiOiJ2aW5jZW50QHpsYXIuYWkiLCJvdXRjb21lIjoiYXV0aG9yaXplZCIsInBvbGljeV92ZXJzaW9uIjoiMi43LjIiLCJydWxlIjoiUjAwMSIsInRvb2wiOiJCYXNoIiwidHMiOiIyMDI2LTA0LTA5VDE0OjIxOjAwLjAwMFoifQ",
  "sig": "9Rhrasz8uMkodCvRpyiXIXM8Df2A1tZWbzSiLaCB5RhnnK3fursSi8Pg2jzjpH1Uii7AuIpoiXQrArgtmoxeBw",
  "prev": null
}
```

**Expected verifier outcome**: signature verifies as valid, semantic validation FAILS with code `AUTHORIZER_OUTCOME_MISMATCH`. A conforming verifier MUST reject this receipt.

---

### Test Vector 6 — POSITIVE — policy-deny outcome (R002 + deny)

**Input payload** (JSON, before canonicalization):
```json
{
  "audit_event_id": "018fa1d06ba08c4a3c8e9f1b2d6e5a7c",
  "audit_prev_hash": "7af16c064d86cc2d8a8592fede5631e5c6a647ee3543587333bac2442172c8c5",
  "authorizer": "policy",
  "delegation_chain": [],
  "detail_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "domain": "bash",
  "manifest_agent_id": "claude-code",
  "manifest_principal": "principal@example.com",
  "outcome": "deny",
  "policy_version": "2.7.2",
  "rule": "R002",
  "tool": "Bash",
  "ts": "2026-04-09T14:22:00.000Z"
}
```

**Canonical JSON form** (sorted keys, compact, UTF-8):
```
{"audit_event_id":"018fa1d06ba08c4a3c8e9f1b2d6e5a7c","audit_prev_hash":"7af16c064d86cc2d8a8592fede5631e5c6a647ee3543587333bac2442172c8c5","authorizer":"policy","delegation_chain":[],"detail_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","domain":"bash","manifest_agent_id":"claude-code","manifest_principal":"principal@example.com","outcome":"deny","policy_version":"2.7.2","rule":"R002","tool":"Bash","ts":"2026-04-09T14:22:00.000Z"}
```

**SHA-256 of canonical bytes (lowercase hex)**:
```
07cb279d3dd7ae8d377327ee3913c4a6fa7851fc4afe6b6bec70cd76934b8358
```

**Base64url-encoded payload (no padding)**:
```
eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwNmJhMDhjNGEzYzhlOWYxYjJkNmU1YTdjIiwiYXVkaXRfcHJldl9oYXNoIjoiN2FmMTZjMDY0ZDg2Y2MyZDhhODU5MmZlZGU1NjMxZTVjNmE2NDdlZTM1NDM1ODczMzNiYWMyNDQyMTcyYzhjNSIsImF1dGhvcml6ZXIiOiJwb2xpY3kiLCJkZWxlZ2F0aW9uX2NoYWluIjpbXSwiZGV0YWlsX2hhc2giOiJlM2IwYzQ0Mjk4ZmMxYzE0OWFmYmY0Yzg5OTZmYjkyNDI3YWU0MWU0NjQ5YjkzNGNhNDk1OTkxYjc4NTJiODU1IiwiZG9tYWluIjoiYmFzaCIsIm1hbmlmZXN0X2FnZW50X2lkIjoiY2xhdWRlLWNvZGUiLCJtYW5pZmVzdF9wcmluY2lwYWwiOiJ2aW5jZW50QHpsYXIuYWkiLCJvdXRjb21lIjoiZGVueSIsInBvbGljeV92ZXJzaW9uIjoiMi43LjIiLCJydWxlIjoiUjAwMiIsInRvb2wiOiJCYXNoIiwidHMiOiIyMDI2LTA0LTA5VDE0OjIyOjAwLjAwMFoifQ
```

**Signature (base64url, no padding)**:
```
UCOqDRlpowx3RPIi7z2sXCiJ0CnKmTTgwjfmXvkGff3xIU6v27AAVCUL4lR5lxlPJFKg7th2YcKdKWVTatnIDg
```

**Complete signed envelope**:
```json
{
  "v": 1,
  "id": "000069d7b608a5c3f21d4ba5c01e68b3c927a41e7b2c",
  "kid": "72735da8aebb8106",
  "iat": 1775744520,
  "type": "governed-action",
  "payload": "eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwNmJhMDhjNGEzYzhlOWYxYjJkNmU1YTdjIiwiYXVkaXRfcHJldl9oYXNoIjoiN2FmMTZjMDY0ZDg2Y2MyZDhhODU5MmZlZGU1NjMxZTVjNmE2NDdlZTM1NDM1ODczMzNiYWMyNDQyMTcyYzhjNSIsImF1dGhvcml6ZXIiOiJwb2xpY3kiLCJkZWxlZ2F0aW9uX2NoYWluIjpbXSwiZGV0YWlsX2hhc2giOiJlM2IwYzQ0Mjk4ZmMxYzE0OWFmYmY0Yzg5OTZmYjkyNDI3YWU0MWU0NjQ5YjkzNGNhNDk1OTkxYjc4NTJiODU1IiwiZG9tYWluIjoiYmFzaCIsIm1hbmlmZXN0X2FnZW50X2lkIjoiY2xhdWRlLWNvZGUiLCJtYW5pZmVzdF9wcmluY2lwYWwiOiJ2aW5jZW50QHpsYXIuYWkiLCJvdXRjb21lIjoiZGVueSIsInBvbGljeV92ZXJzaW9uIjoiMi43LjIiLCJydWxlIjoiUjAwMiIsInRvb2wiOiJCYXNoIiwidHMiOiIyMDI2LTA0LTA5VDE0OjIyOjAwLjAwMFoifQ",
  "sig": "UCOqDRlpowx3RPIi7z2sXCiJ0CnKmTTgwjfmXvkGff3xIU6v27AAVCUL4lR5lxlPJFKg7th2YcKdKWVTatnIDg",
  "prev": null
}
```

**Expected verifier outcome**: signature verifies, semantic validation PASSES. Demonstrates a deny-only rule correctly emitting a deny outcome via policy authorization.

---

### Test Vector 7 — POSITIVE — timeout with denied outcome (fail-closed on no-response)

**Input payload** (JSON, before canonicalization):
```json
{
  "audit_event_id": "018fa1d076a08c4a3c8e9f1b2d6e5a7c",
  "audit_prev_hash": "07cb279d3dd7ae8d377327ee3913c4a6fa7851fc4afe6b6bec70cd76934b8358",
  "authorizer": "timeout",
  "delegation_chain": [],
  "detail_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "domain": "bash",
  "manifest_agent_id": "claude-code",
  "manifest_principal": "principal@example.com",
  "outcome": "denied",
  "policy_version": "2.7.2",
  "rule": "R014",
  "tool": "Bash",
  "ts": "2026-04-09T14:23:00.000Z"
}
```

**Canonical JSON form** (sorted keys, compact, UTF-8):
```
{"audit_event_id":"018fa1d076a08c4a3c8e9f1b2d6e5a7c","audit_prev_hash":"07cb279d3dd7ae8d377327ee3913c4a6fa7851fc4afe6b6bec70cd76934b8358","authorizer":"timeout","delegation_chain":[],"detail_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","domain":"bash","manifest_agent_id":"claude-code","manifest_principal":"principal@example.com","outcome":"denied","policy_version":"2.7.2","rule":"R014","tool":"Bash","ts":"2026-04-09T14:23:00.000Z"}
```

**SHA-256 of canonical bytes (lowercase hex)**:
```
93bb5fa8f35c1655b0bffa183c89e320a1ef3bde4b67daa57421c7b6732919bb
```

**Base64url-encoded payload (no padding)**:
```
eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwNzZhMDhjNGEzYzhlOWYxYjJkNmU1YTdjIiwiYXVkaXRfcHJldl9oYXNoIjoiMDdjYjI3OWQzZGQ3YWU4ZDM3NzMyN2VlMzkxM2M0YTZmYTc4NTFmYzRhZmU2YjZiZWM3MGNkNzY5MzRiODM1OCIsImF1dGhvcml6ZXIiOiJ0aW1lb3V0IiwiZGVsZWdhdGlvbl9jaGFpbiI6W10sImRldGFpbF9oYXNoIjoiZTNiMGM0NDI5OGZjMWMxNDlhZmJmNGM4OTk2ZmI5MjQyN2FlNDFlNDY0OWI5MzRjYTQ5NTk5MWI3ODUyYjg1NSIsImRvbWFpbiI6ImJhc2giLCJtYW5pZmVzdF9hZ2VudF9pZCI6ImNsYXVkZS1jb2RlIiwibWFuaWZlc3RfcHJpbmNpcGFsIjoidmluY2VudEB6bGFyLmFpIiwib3V0Y29tZSI6ImRlbmllZCIsInBvbGljeV92ZXJzaW9uIjoiMi43LjIiLCJydWxlIjoiUjAxNCIsInRvb2wiOiJCYXNoIiwidHMiOiIyMDI2LTA0LTA5VDE0OjIzOjAwLjAwMFoifQ
```

**Signature (base64url, no padding)**:
```
s-231hfbYugNSaQ9oPuZiBgUEt5SDENLeQ-1jcnEYNDLhN3VtdJY-A4v7qLOWYem6tuDxBZ6GrowMKkm6s6XDA
```

**Complete signed envelope**:
```json
{
  "v": 1,
  "id": "000069d7b644b7f806517cb6d432898cde38b52f8c3d",
  "kid": "72735da8aebb8106",
  "iat": 1775744580,
  "type": "governed-action",
  "payload": "eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwNzZhMDhjNGEzYzhlOWYxYjJkNmU1YTdjIiwiYXVkaXRfcHJldl9oYXNoIjoiMDdjYjI3OWQzZGQ3YWU4ZDM3NzMyN2VlMzkxM2M0YTZmYTc4NTFmYzRhZmU2YjZiZWM3MGNkNzY5MzRiODM1OCIsImF1dGhvcml6ZXIiOiJ0aW1lb3V0IiwiZGVsZWdhdGlvbl9jaGFpbiI6W10sImRldGFpbF9oYXNoIjoiZTNiMGM0NDI5OGZjMWMxNDlhZmJmNGM4OTk2ZmI5MjQyN2FlNDFlNDY0OWI5MzRjYTQ5NTk5MWI3ODUyYjg1NSIsImRvbWFpbiI6ImJhc2giLCJtYW5pZmVzdF9hZ2VudF9pZCI6ImNsYXVkZS1jb2RlIiwibWFuaWZlc3RfcHJpbmNpcGFsIjoidmluY2VudEB6bGFyLmFpIiwib3V0Y29tZSI6ImRlbmllZCIsInBvbGljeV92ZXJzaW9uIjoiMi43LjIiLCJydWxlIjoiUjAxNCIsInRvb2wiOiJCYXNoIiwidHMiOiIyMDI2LTA0LTA5VDE0OjIzOjAwLjAwMFoifQ",
  "sig": "s-231hfbYugNSaQ9oPuZiBgUEt5SDENLeQ-1jcnEYNDLhN3VtdJY-A4v7qLOWYem6tuDxBZ6GrowMKkm6s6XDA",
  "prev": null
}
```

**Expected verifier outcome**: signature verifies, semantic validation PASSES. Demonstrates the timeout authorizer emitting `denied` when the human does not respond within the decision window. Establishes fail-closed as a first-class outcome.

---

### Test Vector 8 — NEGATIVE — timeout with authorized outcome (AUTHORIZER_OUTCOME_MISMATCH)

**Input payload** (JSON, before canonicalization):
```json
{
  "audit_event_id": "018fa1d081a08c4a3c8e9f1b2d6e5a7c",
  "audit_prev_hash": "93bb5fa8f35c1655b0bffa183c89e320a1ef3bde4b67daa57421c7b6732919bb",
  "authorizer": "timeout",
  "delegation_chain": [],
  "detail_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "domain": "bash",
  "manifest_agent_id": "claude-code",
  "manifest_principal": "principal@example.com",
  "outcome": "authorized",
  "policy_version": "2.7.2",
  "rule": "R014",
  "tool": "Bash",
  "ts": "2026-04-09T14:24:00.000Z"
}
```

**Canonical JSON form** (sorted keys, compact, UTF-8):
```
{"audit_event_id":"018fa1d081a08c4a3c8e9f1b2d6e5a7c","audit_prev_hash":"93bb5fa8f35c1655b0bffa183c89e320a1ef3bde4b67daa57421c7b6732919bb","authorizer":"timeout","delegation_chain":[],"detail_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","domain":"bash","manifest_agent_id":"claude-code","manifest_principal":"principal@example.com","outcome":"authorized","policy_version":"2.7.2","rule":"R014","tool":"Bash","ts":"2026-04-09T14:24:00.000Z"}
```

**SHA-256 of canonical bytes (lowercase hex)**:
```
08f21db787578e9a81a149536b209bff6f0473ec871169eb51c19f828df8e2a1
```

**Base64url-encoded payload (no padding)**:
```
eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwODFhMDhjNGEzYzhlOWYxYjJkNmU1YTdjIiwiYXVkaXRfcHJldl9oYXNoIjoiOTNiYjVmYThmMzVjMTY1NWIwYmZmYTE4M2M4OWUzMjBhMWVmM2JkZTRiNjdkYWE1NzQyMWM3YjY3MzI5MTliYiIsImF1dGhvcml6ZXIiOiJ0aW1lb3V0IiwiZGVsZWdhdGlvbl9jaGFpbiI6W10sImRldGFpbF9oYXNoIjoiZTNiMGM0NDI5OGZjMWMxNDlhZmJmNGM4OTk2ZmI5MjQyN2FlNDFlNDY0OWI5MzRjYTQ5NTk5MWI3ODUyYjg1NSIsImRvbWFpbiI6ImJhc2giLCJtYW5pZmVzdF9hZ2VudF9pZCI6ImNsYXVkZS1jb2RlIiwibWFuaWZlc3RfcHJpbmNpcGFsIjoidmluY2VudEB6bGFyLmFpIiwib3V0Y29tZSI6ImF1dGhvcml6ZWQiLCJwb2xpY3lfdmVyc2lvbiI6IjIuNy4yIiwicnVsZSI6IlIwMTQiLCJ0b29sIjoiQmFzaCIsInRzIjoiMjAyNi0wNC0wOVQxNDoyNDowMC4wMDBaIn0
```

**Signature (base64url, no padding)**:
```
l7wLUK28zeAJ31CGqLv4T_pqbKOfOX9yK5eKhO-Vuaq_pi-lYK1rcnyfmT52sxI4wIdyInCFa_ug_xUkgxJeBA
```

**Complete signed envelope**:
```json
{
  "v": 1,
  "id": "000069d7b680c9f9ca856edcf8467ba9ea49c640ad4e",
  "kid": "72735da8aebb8106",
  "iat": 1775744640,
  "type": "governed-action",
  "payload": "eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwODFhMDhjNGEzYzhlOWYxYjJkNmU1YTdjIiwiYXVkaXRfcHJldl9oYXNoIjoiOTNiYjVmYThmMzVjMTY1NWIwYmZmYTE4M2M4OWUzMjBhMWVmM2JkZTRiNjdkYWE1NzQyMWM3YjY3MzI5MTliYiIsImF1dGhvcml6ZXIiOiJ0aW1lb3V0IiwiZGVsZWdhdGlvbl9jaGFpbiI6W10sImRldGFpbF9oYXNoIjoiZTNiMGM0NDI5OGZjMWMxNDlhZmJmNGM4OTk2ZmI5MjQyN2FlNDFlNDY0OWI5MzRjYTQ5NTk5MWI3ODUyYjg1NSIsImRvbWFpbiI6ImJhc2giLCJtYW5pZmVzdF9hZ2VudF9pZCI6ImNsYXVkZS1jb2RlIiwibWFuaWZlc3RfcHJpbmNpcGFsIjoidmluY2VudEB6bGFyLmFpIiwib3V0Y29tZSI6ImF1dGhvcml6ZWQiLCJwb2xpY3lfdmVyc2lvbiI6IjIuNy4yIiwicnVsZSI6IlIwMTQiLCJ0b29sIjoiQmFzaCIsInRzIjoiMjAyNi0wNC0wOVQxNDoyNDowMC4wMDBaIn0",
  "sig": "l7wLUK28zeAJ31CGqLv4T_pqbKOfOX9yK5eKhO-Vuaq_pi-lYK1rcnyfmT52sxI4wIdyInCFa_ug_xUkgxJeBA",
  "prev": null
}
```

**Expected verifier outcome**: signature verifies, semantic validation FAILS with code `AUTHORIZER_OUTCOME_MISMATCH`. The (timeout, authorized) pair is not in the §5.1 coherence table. A conforming verifier MUST reject this receipt.

---

### Test Vector 9 — NEGATIVE — delegation chain first depth != 0 (DELEGATION_MISSING_ROOT)

**Input payload** (JSON, before canonicalization):
```json
{
  "audit_event_id": "018fa1d08ca08c4a3c8e9f1b2d6e5a7c",
  "audit_prev_hash": "08f21db787578e9a81a149536b209bff6f0473ec871169eb51c19f828df8e2a1",
  "authorizer": "policy",
  "delegation_chain": [
    {
      "depth": 3,
      "iat": 1775744239,
      "jti": "forged-token-id",
      "parent_jti": null,
      "pub": "CCCC",
      "sig": "sig-forged",
      "sig_alg": "ed25519",
      "sub": "worker-agent",
      "v": 1
    }
  ],
  "detail_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "domain": "bash",
  "manifest_agent_id": "claude-code",
  "manifest_principal": "principal@example.com",
  "outcome": "allow",
  "policy_version": "2.7.2",
  "rule": "R001",
  "tool": "Bash",
  "ts": "2026-04-09T14:25:00.000Z"
}
```

**Canonical JSON form** (sorted keys, compact, UTF-8):
```
{"audit_event_id":"018fa1d08ca08c4a3c8e9f1b2d6e5a7c","audit_prev_hash":"08f21db787578e9a81a149536b209bff6f0473ec871169eb51c19f828df8e2a1","authorizer":"policy","delegation_chain":[{"depth":3,"iat":1775744239,"jti":"forged-token-id","parent_jti":null,"pub":"CCCC","sig":"sig-forged","sig_alg":"ed25519","sub":"worker-agent","v":1}],"detail_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","domain":"bash","manifest_agent_id":"claude-code","manifest_principal":"principal@example.com","outcome":"allow","policy_version":"2.7.2","rule":"R001","tool":"Bash","ts":"2026-04-09T14:25:00.000Z"}
```

**SHA-256 of canonical bytes (lowercase hex)**:
```
3d8fa9362190cd6c238c50d4e29511bda5537573f96d1a21ca86b0f6efe14c75
```

**Base64url-encoded payload (no padding)**:
```
eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwOGNhMDhjNGEzYzhlOWYxYjJkNmU1YTdjIiwiYXVkaXRfcHJldl9oYXNoIjoiMDhmMjFkYjc4NzU3OGU5YTgxYTE0OTUzNmIyMDliZmY2ZjA0NzNlYzg3MTE2OWViNTFjMTlmODI4ZGY4ZTJhMSIsImF1dGhvcml6ZXIiOiJwb2xpY3kiLCJkZWxlZ2F0aW9uX2NoYWluIjpbeyJkZXB0aCI6MywiaWF0IjoxNzc1NzQ0MjM5LCJqdGkiOiJmb3JnZWQtdG9rZW4taWQiLCJwYXJlbnRfanRpIjpudWxsLCJwdWIiOiJDQ0NDIiwic2lnIjoic2lnLWZvcmdlZCIsInNpZ19hbGciOiJlZDI1NTE5Iiwic3ViIjoid29ya2VyLWFnZW50IiwidiI6MX1dLCJkZXRhaWxfaGFzaCI6ImUzYjBjNDQyOThmYzFjMTQ5YWZiZjRjODk5NmZiOTI0MjdhZTQxZTQ2NDliOTM0Y2E0OTU5OTFiNzg1MmI4NTUiLCJkb21haW4iOiJiYXNoIiwibWFuaWZlc3RfYWdlbnRfaWQiOiJjbGF1ZGUtY29kZSIsIm1hbmlmZXN0X3ByaW5jaXBhbCI6InZpbmNlbnRAemxhci5haSIsIm91dGNvbWUiOiJhbGxvdyIsInBvbGljeV92ZXJzaW9uIjoiMi43LjIiLCJydWxlIjoiUjAwMSIsInRvb2wiOiJCYXNoIiwidHMiOiIyMDI2LTA0LTA5VDE0OjI1OjAwLjAwMFoifQ
```

**Signature (base64url, no padding)**:
```
Xtus7kYOaxwmDzbYPW2_NXyaox4pdjos-3QzdWzwqjxUwaSbMIt30ZDo2RyanUYpMcO9HC0e-mJHgcyvq9HoBw
```

**Complete signed envelope**:
```json
{
  "v": 1,
  "id": "000069d7b6bcdbebbcb980ede26c8d95f65adb51be5f",
  "kid": "72735da8aebb8106",
  "iat": 1775744700,
  "type": "governed-action",
  "payload": "eyJhdWRpdF9ldmVudF9pZCI6IjAxOGZhMWQwOGNhMDhjNGEzYzhlOWYxYjJkNmU1YTdjIiwiYXVkaXRfcHJldl9oYXNoIjoiMDhmMjFkYjc4NzU3OGU5YTgxYTE0OTUzNmIyMDliZmY2ZjA0NzNlYzg3MTE2OWViNTFjMTlmODI4ZGY4ZTJhMSIsImF1dGhvcml6ZXIiOiJwb2xpY3kiLCJkZWxlZ2F0aW9uX2NoYWluIjpbeyJkZXB0aCI6MywiaWF0IjoxNzc1NzQ0MjM5LCJqdGkiOiJmb3JnZWQtdG9rZW4taWQiLCJwYXJlbnRfanRpIjpudWxsLCJwdWIiOiJDQ0NDIiwic2lnIjoic2lnLWZvcmdlZCIsInNpZ19hbGciOiJlZDI1NTE5Iiwic3ViIjoid29ya2VyLWFnZW50IiwidiI6MX1dLCJkZXRhaWxfaGFzaCI6ImUzYjBjNDQyOThmYzFjMTQ5YWZiZjRjODk5NmZiOTI0MjdhZTQxZTQ2NDliOTM0Y2E0OTU5OTFiNzg1MmI4NTUiLCJkb21haW4iOiJiYXNoIiwibWFuaWZlc3RfYWdlbnRfaWQiOiJjbGF1ZGUtY29kZSIsIm1hbmlmZXN0X3ByaW5jaXBhbCI6InZpbmNlbnRAemxhci5haSIsIm91dGNvbWUiOiJhbGxvdyIsInBvbGljeV92ZXJzaW9uIjoiMi43LjIiLCJydWxlIjoiUjAwMSIsInRvb2wiOiJCYXNoIiwidHMiOiIyMDI2LTA0LTA5VDE0OjI1OjAwLjAwMFoifQ",
  "sig": "Xtus7kYOaxwmDzbYPW2_NXyaox4pdjos-3QzdWzwqjxUwaSbMIt30ZDo2RyanUYpMcO9HC0e-mJHgcyvq9HoBw",
  "prev": null
}
```

**Expected verifier outcome**: signature verifies, semantic validation FAILS with code `DELEGATION_MISSING_ROOT`. Delegation chains MUST begin at depth 0 (§8.4). A forged token claiming depth 3 without a chain to depth 0 MUST be rejected.

---

## Annex B — The Coupling Theorem

The Governed Action Receipt has legal and economic value only to the extent that the invariants it asserts were enforced at the time of issuance. This is a structural coupling, not a contractual convention.

### Definitions

Let:

- `R(t)` = receipt validity at time `t`, as determined by a conforming v1 verifier (binary: valid or invalid).
- `I(t)` = the state of invariant enforcement by the producing system at time `t` (binary: enforced or not).
- `V(t)` = the legal and economic value of the receipt at time `t` (continuous, ≥ 0), as realized in regulatory proceedings, insurance claims, contractual disputes, or any other context where the receipt is presented as evidence.

### Claim

`R(t)` requires `I(t)`. `V(t)` requires `R(t)`. Therefore `V(t)` requires `I(t)`.

### Argument

A receipt asserts that a specific governance event occurred: a named authorizer evaluated a specific action against a specific policy version and produced a specific outcome. The invariants (deliberation floor, capacity cap, rubber-stamp monitoring, delegation monotonicity, approval-hash binding, and so on) constrain what kinds of governance events are possible to record under the policy version named in the receipt.

If an invariant was not enforced at the time of issuance, the event described by the receipt may not have occurred as stated. The receipt's assertion becomes counterfactual: it claims a governance event that the system at the time may not have been capable of producing in the claimed form. The receipt's validity in the evidentiary sense is then a matter of trust in the producer rather than of evidence coupled to the enforcement state.

### Retroactive Invalidation

If invariant enforcement ceases at time `t*`, every receipt issued at `t < t*` is affected, even though those receipts were produced before the change. A verifier at `t > t*` examining an archived receipt cannot distinguish a receipt issued under enforcement from a receipt issued after enforcement was relaxed, unless the receipt carries an attestation of the enforcement state that the verifier can check against a trusted record.

In this specification, the `policy_version` field and the full `audit_prev_hash` chain provide the basis for such an attestation, but the attestation is only as strong as the verifier's ability to check that the policy named in `policy_version` at the time of issuance included the invariants the verifier expects. If an operator removes an invariant and then continues to issue receipts under the same `policy_version`, old and new receipts are indistinguishable at the receipt level. All receipts issued under that `policy_version` become evidentially ambiguous, regardless of when they were issued.

Therefore, removing an invariant has a cost that is not limited to future receipts. It affects the value of past receipts already in the archives of auditors, regulators, insurance underwriters, and relying parties.

### Rational Actors Maintain Invariants

Let:

- `c_m` = cost of maintaining invariant enforcement (recurring, bounded).
- `c_r` = cost of the reputation loss, legal exposure, and archive-value destruction caused by removing an invariant (one-time, potentially unbounded relative to the archive's value).

For any operator who has issued receipts that are valued by relying parties, `c_r > c_m` once the archive of issued receipts has reached a size where relying parties depend on it. The archive is a sunk asset whose value is coupled to the invariants. Removing an invariant destroys that asset.

Therefore, rational operators do not remove invariants once an archive exists, because removal is more expensive than maintenance. The longer the archive has existed and the more relying parties depend on it, the stronger the coupling becomes.

### Implication for Governance Architecture

This coupling is what makes the invariants **structurally protected** rather than **configurationally protected**. A governance system whose invariants can be removed without consequence is a system where invariants will be removed under pressure — from product teams seeking velocity, from executives seeking cost reductions, from lawyers seeking to avoid liability, from anyone for whom the invariants are friction rather than value. A governance system whose invariants are cryptographically coupled to an archive of already-issued receipts is a system where invariants persist because removal destroys the archive, and the archive is what the operator committed to protect when it began issuing receipts to relying parties.

This is the difference between a governance tool that works at launch and one that works five years after launch, when the inevitable pressure to relax the invariants meets the inevitable archive of receipts that depend on them.

---

*End of v1 specification.*
