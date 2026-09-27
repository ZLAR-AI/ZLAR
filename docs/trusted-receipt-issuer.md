# Trusted Receipt Issuer Boundary

ZLAR receipts are useful because a verifier can check them later. That check has
two layers:

A log records what happened. A ZLAR receipt records what counted as authorized
effect. The receipt does not reconstruct agent history after the fact; it binds
the decision that counted when a routed action tried to become consequence.

1. **Receipt verification** proves the receipt bytes match a signature under a
   supplied public key and pass the receipt schema and semantic checks.
2. **Issuer recognition** decides whether that key is an accepted, active
   issuer for the relying party's deployment, policy scope, action class, and
   time window.

Those are different claims. A valid signature is not production authority.

## Boundary

| Question | What answers it | What it does not prove |
| --- | --- | --- |
| Did these receipt bytes verify? | `bin/zlar-verify`, the verifier kit, or `lib/receipt.mjs` with a supplied public key | active issuer status, custody, revocation, downstream acceptance |
| Is this issuer recognized? | A downstream recognition rule or trust registry that accepts the `kid` and public key | that every route was governed, or that the decision was correct |
| Is this issuer active? | Explicit issuer status in the relying party's rule or registry | that the private key was never compromised |
| Can this action board? | Downstream recognition plus action-scope checks, freshness, replay policy, and receipt fields | coverage of unrouted paths |

If a verifier cannot identify the issuer key, the result is **unknown signer**;
`bin/zlar-verify` reports this as `UNKNOWN-SIGNER` for v1 receipt `kid`
mismatches and exits with code `3`.
If the issuer is known but retired, compromised, missing a public key, out of
scope, stale, or outside policy, the action is **not recognized for boarding**.
That is not the same as saying the receipt bytes are malformed.

## Current Product Evidence

`zlar issuer-status-proof`, `zlar local-proof-pack`, and the verifier kit's
`node verify-issuer-status.mjs` demonstrate issuer status with local hermetic
fixture keys. The fixture recognition rule accepts one active issuer and
refuses retired, compromised, missing-status, unknown, and key-missing issuers
before boarding.

`zlar runner-receipt-issuer-recognition-proof` demonstrates the same boundary
for the ZLAR-owned runner receipt scope. It uses proof-owned ephemeral fixture
keys to show that a `zlar run` governed-action receipt can have valid bytes, be
recognized by a local fixture issuer rule, and still carry zero production
issuer authority. A recognized deny receipt is a valid denial decision record,
not boarding.

Safe claim:

> ZLAR can demonstrate, in a local fixture proof path, that downstream
> recognition separates cryptographic receipt validity from active issuer
> recognition, including for the bounded `zlar run` runner receipt scope.

Non-claims:

- No live trust registry.
- No live key custody proof.
- No live rotation or revocation infrastructure.
- No compromise-response proof.
- No production downstream recognition.
- No Telegram approval-channel proof.
- No production deployment, external attestation, sovereign recognition, or
  coverage of unrouted surfaces.

## Operational Key Posture

The Governed Action Receipt v1 test-vector key is hardware-backed and scoped to
the published receipt specification. It signs spec vectors only.

Operational policy, manifest, constitution, and receipt signing are currently
software-rooted unless a later documented ceremony proves otherwise. Hardware
ceremony keys may be provisioned, but possession of a public key, a `kid`, or a
matching signature does not prove hardware custody.

`etc/keys/` and `etc/manifest.json` are per-install local state and are ignored
by git. Tracked policy and constitution files may embed public verifier material,
but embedded public material proves only what can be verified with that key. It
does not prove where the private key lived, who controlled it, or whether it
remains active.

Before any signing or authority ceremony, run:

```bash
bin/zlar-key-state
```

If the ceremony depends on a hardware device and the device row is absent or
misaligned, stop. Do not convert a software-rooted signature into a
hardware-rooted claim by wording.

## Recognition Rule Requirements

A production recognition rule or trust registry needs at least:

- accepted issuer `kid` and public key or trust anchor;
- explicit issuer status, such as `active`, `retired`, or `compromised`;
- accepted deployment scope, policy version, domain, tool, and outcome;
- receipt freshness and replay rules;
- action binding through audit event id, detail hash, or equivalent;
- refusal behavior for missing, invalid, unknown, retired, compromised,
  stale, wrong-policy, wrong-domain, wrong-tool, wrong-audit-event,
  wrong-detail, or non-boarding receipts.

The local protected-records adapter profile, `zlar protected-records-write`
fixture action, and direct factory remain historical implementations of one
concrete replay rule. Their current source surfaces fixed-refuse. Fresh
`zlar protected-records-adapter-conformance` and
`zlar protected-records-proof` generation are retired in current source; their
exact committed reports contribute historical evidence only through the pinned
local-proof-pack verifier. The retired
`zlar protected-records-service-proof` contributes only exact historical
service-boundary evidence through the pinned local-proof-pack verifier. Current
source no longer generates that service proof. The direct E2 request/factory
also fixed-refuses in current checked-out source and is omitted from future
installer copies. Future accepted repair, upgrade, and reinstall source plans
exact cleanup of the stale E1/E2 direct wrapper/module paths and refuses
unexpected leaf types or unsafe install-root/`bin`/`lib` parents before
installer writes. Same-user concurrent parent/leaf substitution remains open;
the shell sequence assumes a quiescent filesystem. No installer ran and no
current installation was inspected, so old installed/copied/mutated source
remains open. This is not a verifier-level issuer claim, installed-copy
retirement, concurrency safety, live production adapter/service evidence,
runtime unreachability, or E2 elimination.

For production recognition, an omitted issuer status is a configuration gap. The
downstream recognition helper reports `issuer_status_missing` for a known issuer
without explicit status. Do not rely on a default of active as a trust-registry
rule.

## Rotation, Retirement, And Compromise

Scheduled rotation:

1. Add the new issuer key as active for the intended scope.
2. Mark the old issuer according to the relying party's policy: active during a
   defined overlap window, then retired.
3. Preserve old public keys for historical verification.
4. Document which receipts remain recognizable for boarding and which remain
   only historically verifiable.

Compromise response:

1. Mark the affected issuer compromised or retired for recognition.
2. Bound the suspected exposure window.
3. Preserve old receipts and public keys for investigation.
4. Do not claim old receipts remain trustworthy merely because their signatures
   still verify.

Cryptographic verification can remain possible after retirement. Recognition
for new boarding should not.
