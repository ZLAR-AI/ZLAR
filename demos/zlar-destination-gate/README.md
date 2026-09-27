# ZLAR Demo 1 Destination Authority

This is the sole current Demo 1 source surface for one harmless local
`deployment.promote` consequence. Exact founder-originated Grant G and a
non-expanding Boarding Credential A are required inputs. The destination owns
the grant-level allocation, active bytes, PromotionCommit P, and terminal
receipt R inside one SQLite transaction.

The repository contains two deliberately separate profiles:

- `zlar.demo1.software-test.v1` is an authority-effect-none disposable-key
  profile for protocol, transaction, crash, and verifier testing.
- `zlar.demo1.c-backed.v1` is the fixed installed-source profile. It recognizes
  only YubiKey C's exact public key and has no software-root fallback. It is not
  installed merely because its source exists.

## Installed boundary encoded by the source

```text
Claude or Codex visibly running in Vincent's actual UID 501 session
  -> root-owned launchd AF_UNIX socket
  -> native getpeereid(3) broker deriving macos-euid:501
  -> one-request destination child as _zlar_demo1 UID/GID 450
  -> fixed root-owned runtime, modules, policy and keys
  -> /var/db/zlar-demo1/state.sqlite
```

The canonical installed principal is `macos-euid:501`. The request cannot
supply or override it. Kernel evidence identifies the macOS execution domain;
the visible application transcript identifies the Claude/Codex surface. The
client can stage arbitrary harmless bytes, request a
destination-signed N, transport exact signed G/A, and request promotion. It
cannot select a path, key, policy, database, clock, identity, fault hook, or
software profile.

The client surface is [demo1.mjs](demo1.mjs). In the current uninstalled source
checkout it refuses because no protected socket exists. It never opens the
destination in process.

## Source verification

Prerequisite: Node `v22.22.1` with `node:sqlite`. From the repository root:

```sh
node cyan/test-demo1-protocol.mjs
node cyan/test-demo1-destination.mjs
node cyan/test-demo1-receipts.mjs
node demos/zlar-destination-gate/test-demo1-e2e.mjs
node demos/zlar-destination-gate/test-demo1-installed.mjs
python3 -B demos/zlar-destination-gate/test_demo1_installation.py
python3 -B demos/zlar-destination-gate/product_identity.py --verify
```

These tests establish source and disposable-software plumbing only. They cover
strict schemas, exact G-to-A linkage, destination refusal, one grant-level
allocation across multiple A, atomic effect/P/R formation, concurrent and
restart replay refusal, fault rollback, abrupt process loss, exact signed
N/G/A preservation, offline evidence verification, fail-closed missing-state
startup, native broker compilation, kernel peer-credential availability, and a
read-only installation collision check.

They do not establish an installed service, actual visible Claude/Codex
execution under UID 501,
YubiKey C recognition at a live destination, fresh C-backed G, a protected
effect, or Demo PASS.

## Independent evidence verification

`demo1-verify.mjs` requires three independent trust inputs: destination public
key, recognition-policy digest, and intended claim ceiling. The v2 bundle
retains the exact signed N, G, and A beside P, R, and final allocation/state
projection. Evidence cannot supply the trust anchor used to recognize itself.

```sh
node demos/zlar-destination-gate/demo1-verify.mjs \
  --evidence <canonical-evidence.json> \
  --expected-policy-digest <sha256:...> \
  --destination-public-key <expected-destination-public.pem> \
  --expected-claim-ceiling <exact-claim-ceiling>
```

## Preserved installed candidate evidence

[INSTALLED-VERIFICATION-20260822.md](INSTALLED-VERIFICATION-20260822.md)
routes to the exact private installed C-backed candidate evidence preserved on
2026-08-22, its independent trust inputs, reproducible verifier command,
prediction-versus-actual closeout, and claim ceiling. The evidence establishes
one bounded installed-candidate result only. It is not an outward demo,
production acceptance, or a universal side-door claim.

## Installation remains a human/admin boundary

[demo1-install.py](demo1-install.py) has a read-only `--plan` mode and a
separate `--install` mode. Both require the exact accepted source commit and
product-manifest hash. `--install` additionally requires EUID 0 and refuses if
the service identities, numeric IDs, target paths, launchd label, Node digest,
source tree, or no-YubiKey precondition differ.

Do not run `--install` from this README. Control Tower must first freeze and
independently verify the successor source commit, confirm the intended visible
Claude/Codex surface actually runs under UID 501 with no unrestricted or
bypass-permissions mode, and then present Vincent one attended administrator
checkpoint with exact pins and rollback scope.

The later fresh G ceremony uses [demo1-authorize.py](demo1-authorize.py) from a
private UID-501 Terminal with only C connected. Before secret entry, Claude,
Codex, screen recording, and every other acting-AI process must be closed. The
root-owned ceremony program displays exact public G,
invokes PKCS#11 without a PIN argument, requires C's fresh PIN/touch interaction,
verifies the raw Ed25519 signature, and emits only signed public G at the fixed
`/var/tmp/zlar-demo1-authority/grant-g.json` transfer path. The public signed
record is integrity-protected by C's signature. The UID-501-owned `0700`
transfer directory excludes every other local account; exact file identity,
canonical bytes, destination signature, C signature, and exclusive creation
still fail closed on replacement or pre-creation. The launchd socket is
`root:admin 0660`, and the native broker independently admits only
kernel-observed UID 501; root and every other UID are refused as clients. No
other user account is part of this contract. The AI may be reopened only after
signed G exists and C is disconnected.

This is ordinary consequence capability, not unrestricted host authority. A
shared UID cannot cryptographically distinguish Vincent from an AI process, so
the claim is limited to the observed user execution domain plus the visible
application transcript and excludes malicious host compromise.

## Historical Product Cut 0.1

Git commit `9dab89ec16edd6009dc34f973361502eda35b73c` preserves the prior
Product Cut 0.1 route. Candidate 005 remains byte-identical with complete
13-file aggregate
`e037738dc7abe3b2c1d6c63e7103275ed73ce241ab0236f21f1feadee4914e2f`.
Current `run.py` fails closed, so the repository does not expose a second live
promotion system.

Read [CLAIM-CEILING.md](CLAIM-CEILING.md) before interpreting any result.
Builder checks, independent verification, installation, C-backed authority,
candidate execution, recording, and founder acceptance remain separate gates.
