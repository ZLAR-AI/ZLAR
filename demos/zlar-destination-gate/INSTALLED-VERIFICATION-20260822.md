# Demo 1 Installed C-Backed Candidate Evidence — 2026-08-22

Status: **VERIFIED BOUNDED EVIDENCE**

Vincent directed preservation of this private installed-candidate proof on
2026-08-22. This record does not accept an outward demo, production architecture,
deployment readiness, or a public claim.

## Exact preserved inputs

| Input | Repository file | SHA-256 |
|---|---|---|
| Evidence bundle | `INSTALLED-EVIDENCE-20260822.json` | `77f96910cb6987d8dc24498113278d81360799acfb638147861be3df39188bb3` |
| Destination public key | `INSTALLED-DESTINATION-PUBLIC-20260822.pem` | `b0106d8d1f5b38b7e36cc15a64babcc946aa48b6f03431e3f47929aa9190388b` |
| Installation manifest | `INSTALLED-MANIFEST-20260822.json` | `f7edcb31511db012f9be556f4e0541fd5c414ac42b4daeb342908add797b8805` |

The installation manifest binds the installed profile to source commit
`2e3d9a57e7bc55e6dfda2f3443f1aa9f26e127a6`. The evidence verifier was given
two trust inputs independently of the bundle:

- recognition-policy digest
  `sha256:3d9292e5f329add6540ddc996ff12535f726cc5b4b166f8fec47a582865845b3`;
- destination public key
  `INSTALLED-DESTINATION-PUBLIC-20260822.pem`.

## Offline verification

From the repository root:

```sh
node demos/zlar-destination-gate/demo1-verify.mjs \
  --evidence demos/zlar-destination-gate/INSTALLED-EVIDENCE-20260822.json \
  --expected-policy-digest sha256:3d9292e5f329add6540ddc996ff12535f726cc5b4b166f8fec47a582865845b3 \
  --destination-public-key demos/zlar-destination-gate/INSTALLED-DESTINATION-PUBLIC-20260822.pem \
  --expected-claim-ceiling installed_c_backed_candidate_evidence_only
```

Verified output:

```json
{"status":"VERIFIED_BOUNDED_EVIDENCE","claim_ceiling":"installed_c_backed_candidate_evidence_only","challenge_count":3,"grant_count":1,"credential_count":1,"receipt_count":3,"receipt_head":"sha256:2e924ffcfb97bbdfb3b76c83760c67dbf6520896b66960a30fa3d8caa58b8b3c","commit_count":1,"executed_count":1,"refusal_count":2,"policy_digest":"sha256:3d9292e5f329add6540ddc996ff12535f726cc5b4b166f8fec47a582865845b3","destination_key_id":"spki-sha256:f4c43ae6baeccb029e881019eba6141c0bd06768a47dbd35427983b9527023a9","projection_digest":"sha256:06428cd6786d8dc25485f132e76e8db08f7a9b947362c970e20f62b5f0f012ce"}
```

The Node runtime also emitted its non-failing experimental SQLite warning.

## What the evidence establishes

The destination-owned receipt chain records:

1. sequence 1: `refused` / `missing_authority`, generation `0 -> 0`;
2. sequence 2: `executed`, one protected-promotion allocation consumed,
   generation `0 -> 1`;
3. sequence 3: `refused` / `grant_allocation_exhausted`, generation `1 -> 1`.

The executed action was exact `deployment.promote` of staged object
`demo-1-release.json`, artifact
`sha256:83764956027b8892a8f19d0a5b0c6ac85bfc504a83900a832c5053a3fa7a5f7c`,
under profile `zlar.demo1.c-backed.v1`. Grant G names YubiKey C's recorded
authority-root public identity and a maximum protected-effect allocation of one.
The bundle contains three challenges, one recognized grant, one derived
credential, one promotion commit, and three signed receipts.

## Prediction versus actual

The accepted paper contract predicted a destination refusal without authority,
one exact effect after fresh custody-bound authorization, and refusal of reuse.
The final destination evidence matches those three predictions.

The private run required three challenges. One expired without a destination
receipt. A second produced the recorded missing-authority refusal, then the
C-signed grant expired before credential derivation and was not recognized by
the destination. The third challenge produced the recognized Grant G,
Credential A, one effect, and the replay refusal. The recovery preserved the
failed residue; it did not reset or delete destination history.

The avoidable ceremony was delay between the fresh human authorization and
credential derivation. Future evidence runs should minimize work inside the
freshness window and treat the destination result—not redundant client-side
parsing—as the decisive structural assertion.

## Privacy inspection

Before preservation, the evidence bundle and public trust inputs were scanned
for usernames, personal filesystem paths, OAuth material, tokens, passwords,
private keys, PINs, PUKs, management keys, session identifiers, hostnames, and
HMAC-secret markers. No matches were found. This is a bounded pattern scan, not
a proof that no sensitive interpretation is possible. The failed raw recording
is not part of this repository evidence package.

## Claim ceiling

This package may establish only installed C-backed candidate evidence in which
the destination refused an exact harmless promotion without authority, accepted
one exact fresh bounded authority instance once, recorded generation `0 -> 1`,
and refused replay while generation remained `1`.

It does **not** establish production readiness, universal side-door closure,
malicious-administrator resistance, public evidence, outward-demo completion,
or general authority enforcement beyond this exact installed candidate.
