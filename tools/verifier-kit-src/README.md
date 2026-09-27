# ZLAR Verifier Kit v0.1.0

Independently verify a ZLAR **Governed Action Receipt v1** envelope, walk
a ZLAR CC-gate audit hash chain, and evaluate a supplied trusted issuer
registry fixture. Four entry points, zero npm dependencies, Node.js >= 18
built-ins only.

This kit is the substrate for outside-party validation of ZLAR receipts.
It is not external attestation. It is not a Proof Pack. It is not a
coverage report. See **Limits** below.

---

## Status

- Kit version: `v0.1.0`
- Spec version: `v1.0.0` (Published)
- Conformance profile: see `spec/CONFORMANCE.md`
- Posture: **source-form internal**. The build script and source
  templates live in the ZLAR repository under `tools/`. Public
  distribution decision (D15') remains deferred.

The kit produces a verdict only after its own bundle integrity checks
pass. A broken kit refuses to verify (exit 4).

---

## Quick start

```bash
# 1. Build the kit (operator side, ZLAR repository working tree).
#    Generates an ephemeral publisher keypair for source-form tests
#    unless --publisher-key <PRIVATE_PEM> is supplied.
bash tools/build-verifier-kit.sh

# Optional source-build reproducibility proof. Builds twice with one
# temporary test publisher key and emits bounded JSON evidence.
bin/zlar verifier-kit-reproducibility --json-out zlar-verifier-kit-reproducibility-v1.json

# 2. Unpack the tarball anywhere.
tar xzf dist/zlar-verifier-kit-v0.1.0.tar.gz
cd zlar-verifier-kit-v0.1.0

# 3. Smoke test — verify the bundled Annex A vectors. Zero input
#    required; confirms the kit works end-to-end before any operator
#    receipt is in hand.
node verify-test-vectors.mjs

# 4. Verify a sample receipt. Ships in the kit (extracted from the
#    spec at build time); verifies against the bundled spec test key.
node verify.mjs examples/sample-receipt.json --pubkey spec/test-key.pub

# 5. Walk a sample audit chain. Ships in the kit (5-event synthetic
#    CC-shape chain).
node verify-chain.mjs examples/sample-chain.jsonl

# 6. Verify the bundled issuer-status fixture. This proves only the
#    fixture recognition boundary, not live issuer status or custody.
node verify-issuer-status.mjs

# 7. Evaluate the bundled trusted issuer registry fixture against the
#    bundled sample receipt. This proves only supplied fixture recognition,
#    not live trust-registry state, custody, or external attestation.
node verify-recognition.mjs --receipt examples/sample-receipt.json --registry examples/trusted-receipt-issuers-v1.json --scope verifier-kit-sample
```

To verify your own receipt or audit chain, substitute their paths
above. Receipts must be **Governed Action Receipt v1** envelopes;
the chain walker accepts any CC-shape JSONL where every event carries
`prev_hash = SHA-256(previous raw line)` and the genesis event's
`prev_hash` is the literal string `"genesis"`.

---

## Entry points

### `verify.mjs`

Verifies a Governed Action Receipt v1 envelope against an Ed25519 public
key (PEM). This proves signed content integrity under the supplied key. It does
not prove the key is an active recognized issuer. Discriminates
**UNKNOWN-SIGNER** from **INVALID** per the Conformance Profile §1.1 item 9.

Flags:

| Flag | Description |
|------|-------------|
| `<receipt.json>` | Receipt file (positional). Or pipe via stdin. |
| `--pubkey <key.pub>` | Public key PEM. **Required.** |
| `--json` | Machine-readable output. |
| `--verbose`, `-v` | Print receipt details alongside verdict. |
| `--allow-v0` | Accept legacy v0 receipts. Off by default. |
| `--strict-canonical` | Reject non-spec canonical forms (v0 multi-form fallback). |
| `--self-test-report` | Print self-test detail and exit. |
| `--help`, `-h` | Show usage. |

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | VALID — signature OK, semantic OK, kid matches. |
| 1 | INVALID — signature, semantic, bound, or strict-canonical failure. |
| 2 | ERROR — bad args, missing file, bad JSON, bad PEM. |
| 3 | UNKNOWN-SIGNER — receipt kid does not match provided pubkey. |
| 4 | BUNDLE-INTEGRITY-FAIL — kit self-test failed; verification NOT attempted. |

### `verify-chain.mjs`

Walks a ZLAR CC-gate audit JSONL. Each line carries
`prev_hash = SHA-256(previous line raw bytes)`. Reports breaks.

Flags:

| Flag | Description |
|------|-------------|
| `<audit.jsonl>` | Audit file (positional). |
| `--from <id>` | Start walking at this event id. |
| `--to <id>` | Stop walking at this event id. |
| `--all-breaks` | Enumerate every break (default: report first only). |
| `--json` | Machine-readable output. |

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | INTACT — chain walks cleanly. |
| 1 | BREAK — ≥1 prev_hash mismatch found. |
| 2 | ERROR — bad file, bad line, OC-shape chain refused. |
| 4 | BUNDLE-INTEGRITY-FAIL — kit self-test failed. |

OC-gate audit chains (no `prev_hash` field, no `authorizer` field) are
refused with exit 2. The OC gate is retired.

### `verify-issuer-status.mjs`

Runs a bundled hermetic issuer-status fixture. The fixture recognition rule
accepts one active issuer and refuses retired, compromised, missing-status,
unknown, and missing-key issuers before boarding.

This is a fixture boundary check. It does not inspect live registries, use
production signing keys, prove key custody, prove revocation truth, prove
downstream recognition in a real deployment, or create external attestation.

Flags:

| Flag | Description |
|------|-------------|
| `--json` | Machine-readable output. |
| `--self-test-report` | Print self-test detail and exit. |
| `--help`, `-h` | Show usage. |

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | ISSUER-STATUS-FIXTURE-VERIFIED — fixture boundary verified. |
| 1 | ISSUER-STATUS-FIXTURE-FAIL — fixture boundary failed. |
| 2 | ERROR — bad args. |
| 4 | BUNDLE-INTEGRITY-FAIL — kit self-test failed. |

### `verify-recognition.mjs`

Evaluates one Governed Action Receipt v1 envelope against one supplied
`trusted-receipt-issuers-v1` registry fixture. This is the scanner path:
the receipt must be signed by a known active issuer and match the configured
scope, policy version, domain, tool, outcome, audit event, and detail hash.
Refusal reasons include unknown issuer, retired issuer, compromised issuer,
wrong policy, wrong scope, and malformed registry input.
Malformed registry input includes schema-contract mismatches such as unsupported
fields, missing `evidence_model`, missing issuer `public_key_pem`, or bad
`required_detail_hash`.

This is supplied-fixture recognition only. It does not inspect live registries,
prove key custody, prove revocation truth, prove production downstream
recognition, or create external attestation.

Flags:

| Flag | Description |
|------|-------------|
| `--receipt <receipt.json>` | Governed Action Receipt v1 envelope. **Required.** |
| `--registry <trusted-receipt-issuers-v1.json>` | Trusted issuer registry fixture. **Required.** |
| `--scope <deployment-scope>` | Optional deployment scope; must match the registry scope. |
| `--json` | Machine-readable output. |
| `--self-test-report` | Print self-test detail and exit. |
| `--help`, `-h` | Show usage. |

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | RECOGNIZED — receipt recognized by the supplied registry fixture. |
| 1 | RECOGNITION-REFUSED — receipt not recognized by the supplied registry fixture. |
| 2 | ERROR — bad args, missing file, bad JSON, or bad registry. |
| 4 | BUNDLE-INTEGRITY-FAIL — kit self-test failed; recognition NOT attempted. |

---

## Bundle self-test

Every invocation runs a self-test **before** any verification work:

1. Read `MANIFEST.json` and `MANIFEST.sig`.
2. Verify `MANIFEST.sig` (Ed25519) against `MANIFEST.json` bytes using the
   publisher pubkey embedded in the verifier source.
3. Cross-check `kit-publisher.pub` on disk against the embedded const.
4. Recompute SHA-256 of every file listed in `MANIFEST.files`. Compare.
5. Run `verify-test-vectors.mjs` against the bundled Annex A vectors
   (positive vectors VALID; negative vectors INVALID with named codes).

Any failure → exit 4 with a specific message. The kit emits no
verification verdict before its integrity check completes.

---

## Limits — what this kit does NOT prove

Nine limits, every one named.

**L1. Does NOT prove the agent was actually routed through ZLAR.**
A signed receipt proves the **governed** action was governed. It does
not prove every action was governed. Coverage is the Interception
Surface Auditor question, not this kit.

**L2. Does NOT prove a human actually attended.**
`authorizer: "human:<id>"` proves the system recorded a human-authorizer
string. It does not prove the human read, understood, or acted
attentively. The Trust Lane attention check (v3.3.4) lives in the gate's
runtime state, not in the receipt.

**L3. Does NOT prove the timestamp is real.**
`iat` and the payload's `ts` come from the gate's local clock. v0.1
verifies the time field as well-formed and within bounds; it does not
verify external time anchoring (witnessed timestamping is future work).

**L4. Does NOT prove cross-gate canonicalization byte-parity.**
The bash gate and the MCP gate produce audit events in separate JSONLs.
Cross-gate byte-parity (X1 / GATE-50-A) is open at v0.1. The chain
walker handles whichever chain it is handed; pass each gate's chain
separately.

**L5. Does NOT verify Worker Receipts.**
Worker Receipt + /why v0.1 is design-ratified; implementation is queued.
This kit verifies the operator/auditor-facing receipt only.

**L6. Does NOT prove hardware-rooted signing.**
Ed25519 signatures verify regardless of where the private key lives.
The receipt has no field declaring software vs hardware signing.
Provenance is a documentation claim, not a wire-level claim.

**L7. Does NOT provide external attestation.**
Verification is what the operator or a chosen third party runs
themselves using this kit. Attestation is a social/legal act layered on
top — a named party publishing their verification result under their
own signature. v0.1 is the substrate, not the act.

**L8. Does NOT replay policy.**
The kit proves WHAT was decided, WHO authorized it, WHEN, signed. It
does not re-run the same input through the policy engine to confirm
the policy would still decide the same way today.

**L9. Does NOT prove live issuer recognition.**
A VALID receipt means the receipt verified under the supplied public key and
passed semantic checks. It does not prove the `kid` is currently active, that
the private key was held under a particular custody model, that the issuer was
not retired or compromised, or that a downstream system must accept the receipt
for boarding. `verify-issuer-status.mjs` demonstrates a bundled issuer-status
fixture. `verify-recognition.mjs` evaluates one supplied receipt against one
supplied `trusted-receipt-issuers-v1` registry fixture. Both remain fixture
recognition only; it creates no live trust-registry truth, custody proof,
revocation truth, production downstream-recognition proof, or external
attestation. See
`docs/trusted-receipt-issuer.md` in the source repository.

---

## Caveats called out in JSON output

The kit's `--json` output names two ongoing caveats so consumers see
them on every verdict, not buried in docs:

- `canonicalization_caveat`: v1 receipts sign `SHA-256(decoded payload
  bytes)` and do not re-canonicalize at verify time. v0 receipts may
  succeed under the multi-canonical fallback (`spec` / `bash-pipeline`
  / `bash-pretty`) documented in ADR-011. `--strict-canonical` rejects
  v0 success under non-spec forms.
- `cross_gate_caveat` (chain walker only): the kit walks a single
  JSONL. Cross-gate canonical-form parity (X1) is open at v0.1.

---

## Annex A test vectors

The kit's self-test exercises every Annex A vector embedded in the
spec markdown (`spec/governed-action-receipt-v1.md`). Five are pre-
ceremony-signed positive examples; four are pre-signed negative
examples that test semantic invariants (`RULE_OUTCOME_CONTRADICTION`,
`AUTHORIZER_OUTCOME_MISMATCH`, `DELEGATION_MISSING_ROOT`).

Annex A vectors 6–12 mentioned in CONFORMANCE.md §4.1 are at the spec's
ceremony stage. As of v0.1, the kit verifies the nine vectors present
in the spec's embedded envelopes; ceremony additions land in later kit
versions when the spec ships them.

---

## Reproducible builds

`tools/build-verifier-kit.sh` normalizes archive metadata so the kit is
deterministic for identical source inputs and the same publisher key.
`bin/zlar verifier-kit-reproducibility` generates a temporary test
publisher key, builds twice with that same key, and requires identical
tarball, manifest, and manifest-signature SHA-256 values.

The reproducibility report also lists public artifact hashes for the
tarball, the SHA-256 sidecar, `MANIFEST.json`, and `MANIFEST.sig`.
This proves source-build archive determinism for the tested inputs. It
does not prove production publisher key custody, production signing
identity, public release publication, external attestation, live trust-
registry state, revocation truth, enterprise readiness, or v3.4.0
readiness.

`bin/zlar verifier-kit-public-distribution` is the separate publication
posture audit. It consumes supplied release-asset JSON plus the
reproducibility report and can say the audit passed while the kit is still
not public-distribution-ready. It does not upload assets, read private
keys, create external attestation, prove production publisher key custody,
or prove v3.4.0 readiness.

---

## Provenance posture (Phase F parked)

v0.1 signing remains software-rooted. Phase F (hardware-rooted signing)
is parked indefinitely as of 2026-05-11. The kit verifies Ed25519
signatures regardless of where the private key lives; no claim in this
kit asserts hardware roots.

---

## License Boundary

Generated public/thin verifier-kit artifacts include Apache-2.0 license text
from `LICENSES/Apache-2.0-prior-public.txt` when intentionally packaged that
way. The verifier-kit source templates inside the current private-core ZLAR
repository remain governed by the repository root `LICENSE` unless separately
distributed under different written terms.
