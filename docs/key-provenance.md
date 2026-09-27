Key Provenance — ZLAR Pinned Keys

Correction on signing provenance (2026-04-17)

Operational signing of policy, manifest, and constitution artifacts is
software-rooted. Hardware-backed ceremony keys referenced in prior
documentation were provisioned but have not been used for signing these
artifacts.

The hardware-backed path for specification test-vector signing is in use
as documented.

Signed artifacts remain verifiable against the public keys pinned in the
repository.

Migration of policy, manifest, and constitution signing to a
hardware-backed path is under review.

For the CURRENT state of every signing key (what is on disk, what is on each YubiKey slot, what the manifest and active policy claim), run bin/zlar-key-state. That tool is the one source of truth for live alignment. This file is provenance HISTORY — how each key was generated and when — not a status dashboard. Anyone about to run a signing ceremony should check bin/zlar-key-state first. See docs/key-state.md for the one-page discipline.

Purpose. Every pinned key used by ZLAR governance should carry a provenance
entry recorded at the moment of generation. This closes the process gap surfaced
by an April 2026 incident record (kept in the private development history): a key whose generation
ceremony is not written down can be lost without an audit trail.

What this file publishes and what it does not. This file publishes the category of storage (e.g. "YubiKey PIV slot 9A"), the ceremony used to generate the key, the algorithm, and the public fingerprint. It does not publish serial numbers, locations, PINs, management keys, or anything that weakens the security of the stored private material. Secrecy of the private half remains the design; this file documents the ceremony around it.

Separation rule. Four signing concerns do not cross: policy, constitution,
spec test vectors, and the Demo 1 Founder Authority Root. The historical
hardware target for the first three concerns is three physical slots/devices: Policy
Signing mapped to the primary YubiKey slot 9C, Constitution Signing mapped to
the primary YubiKey slot 9D, and Spec test-vector signing mapped to the spare
YubiKey slot 9A. Today only spec test-vector signing is operationally
hardware-backed. Policy, manifest, and constitution signing remain
software-rooted under the correction above until a later ceremony proves and
documents migration. The Demo 1 root generated on 2026-08-22 is a separate
fourth concern on physical YubiKey C. It does not migrate, replace, or authorize
any of the first three concerns.

Provenance entries

ZLAR Founder Authority Root C v1

- Status: generated and privately verified on 2026-08-22; unrecognized by any
  destination; public half retained only in private ceremony evidence pending
  an exact later source placement and separately authorized installation.
- Fingerprint: `4260a266c255059b`.
- Fingerprint convention: first 16 hex of SHA-256 of the exact public-key PEM,
  including its trailing newline.
- Full public-key PEM SHA-256:
  `4260a266c255059b041b8af5805b89fdaa5dfb5c40a291a146842deda2b09890`.
- Full DER SubjectPublicKeyInfo SHA-256:
  `eb746072b61c1f21225e6504accf55ec99d5ba73f3117c80e0d092c1436ab07c`.
- Algorithm: Ed25519.
- Private half: generated on-device in PIV slot 9C on physical YubiKey C with
  PIN ALWAYS and TOUCH ALWAYS. Slot names are per device; this is not the older
  policy target in slot 9C on YubiKey A.
- Public half: private ceremony evidence only. It is not committed under the
  recursively frozen Product Cut 0.1 root, ignored per-install `etc/keys/`, the
  specification key path, or a competing registry.
- Later recognition boundary: an exact later implementation must select one
  source placement and separately install the full key in the destination-owned
  `/etc/zlar/demo1-authority-roots.json`. Repository presence, provenance,
  certificate possession, attestation, the physical label, slot number, and
  shortened fingerprint create neither recognition nor authority.
- Generation date: 2026-08-22.
- Generation ceremony:
  the YubiKey C provisioning runbook (kept in the private development history), first execution PASS within
  its provisioning claim ceiling. YubiKey C was the sole connected device; A,
  B, and D remained disconnected; C was disconnected at closeout.
- Management profile: C-only PIN and distinct C-only PUK changed from factory
  defaults; retries preserved at 3/3; random AES-192 management key stored
  PIN-protected on-device; no secret value was captured.
- Certificate subject and issuer:
  `CN=ZLAR Founder Authority Root C v1,O=ZLAR Inc.`.
- Certificate validity: 2026-08-22T19:57:29Z through
  2036-08-22T19:57:29Z.
- Certificate SHA-256 fingerprint:
  `a8256dcbff089baa9a5942b2e3cd1f69106a4ca28d8c518f23ab28c0711a040d`.
- Attestation: factory F9 verified through the hash-pinned official Yubico
  chain before mutation; 9C attestation verified through F9; firmware OID
  matched 5.7.4; usage-policy OID matched PIN ALWAYS and TOUCH ALWAYS;
  generated, exported, certificate, and attested public keys matched exactly.
- Toolchain: ykman 5.9.2, yubico-piv-tool 2.7.3, OpenSC/pkcs11-tool 0.27.1,
  OpenSSL 3.6.3, and isolated cryptography 50.0.0.
- Per-use mechanism check: two distinct authority-effect-none messages were
  signed in separate PKCS#11 processes. Vincent reported two PIN prompts and
  one touch for each; both signatures verified under the exact public key.
- Scope after later implementation: Vincent may use this root to originate an
  exact, destination-challenge-bound Demo 1 Grant G and name its authorized
  issuer. It does not sign policy, manifest, constitution, specification test
  vectors, Boarding Credential A, destination receipts, logins, or unrelated
  actions.
- Privacy: no hardware serial, PIN, PUK, management key, attestation
  certificate, private evidence, or private-key material enters the repository.
- Claim boundary: generation, private attestation, and the non-authority probes
  had no authority effect. No Grant G was created or authorized. This entry does
  not establish exclusive custody, Vincent identity, informed authorization,
  destination recognition, acting-AI prevention, or Demo 1 PASS.

ZLAR Push Key v1 — on YubiKey D

- Status: generated and verified 2026-08-23; ceremony first execution PASS
  within its claim ceiling, with one recorded deviation (registration route,
  below). Stub recorded earlier the same day per the process; generation
  followed it.
- Concern: SSH authentication for pushing `ZLAR-AI/ZLAR` over the
  `github.com-zlar` alias. A fifth signing concern; it does not cross the
  four above.
- Device: physical YubiKey **D**, confirmed factory-fresh at FIDO2 preflight.
  Device letters name hardware (A, B, C, D); roles name duties — D now
  carries the push role, decided by Vincent 2026-08-23. The GitHub-registered
  credential title `zlar-push-p-v1` and the stub filename are label strings
  chosen before the naming was settled; they do not rename the device. FIDO2
  discoverable credential, application id `ssh:zlar-push`; stub file
  `~/.ssh/zlar_push_p_v1` (regenerable from the hardware via `ssh-keygen -K`;
  include the stub in the next key backup).
- Compartment note: this credential lives in D's FIDO2 application, which has
  a PIN and no PUK. D's PIV application (the compartment type C uses) is
  empty and remains at factory state; it guards nothing and receives its own
  hardening ceremony only if a credential is ever placed there.
- Algorithm: Ed25519-SK, `verify-required` — the private half was generated
  on-device and is non-exportable.
- Fingerprint: `SHA256:qBFiQQWmw1zw4TJWtnTkhiU1FD6BkgulFdtXFKFhhvs` (OpenSSH
  SHA-256 convention for SSH keys; the PEM-hash convention above applies to
  PIV PEM keys and is not applicable to this key type).
- Generation date: 2026-08-23. Ceremony:
  the push-key provisioning runbook (kept in the private development history).
- Registration deviation, recorded: GitHub's deploy-key endpoint refused the
  sk key type (`422 Validation Failed`); P is registered as an **account SSH
  key** on VinnyNijjar (title `zlar-push-p-v1`), so the credential's reach is
  account-wide while the configured wiring is repo-scoped. A repo-scoped
  hardware alternative (PIV-slot key presenting as plain `ssh-ed25519`)
  remains open as a later refinement.
- Verification, same evening: positive proof — interactive authentication
  over the alias succeeded with user-presence confirmation ("Hi VinnyNijjar…
  successfully authenticated"), and Vincent confirmed the PIN was demanded
  before the touch, establishing that `verify-required` is live; negative
  proof — the identical attempt in a prompt-forbidden context
  (`BatchMode=yes`) was refused (`Permission denied (publickey)`), with the
  key connected, registered, and wired throughout.
- PIN custody: a D-only FIDO2 PIN set from factory state at the ceremony,
  distinct from C's; paper rule applies; no secret value captured anywhere.
- Scope: authenticates git/SSH as the account. It signs nothing else — no
  policy, constitution, evidence, spec vectors, grants, or commits.
- Claim boundary: this entry establishes hardware-bound push authentication
  for this machine's configured path only. It does not establish content
  binding, convergence of the token path (see the convergence plan's
  remaining steps), web-interface closure, or any ZLAR gate involvement.

Spec test-vector signing (v1)

- Fingerprint: 72735da8aebb8106
- Algorithm: Ed25519
- First 16 hex of SHA-256 of public-key PEM on disk (including trailing newline) — this is how kid is derived.
- Public half: spec/test-key.pub (Apache 2.0 repository, Published v1.0)
- Private half: PIV slot 9A (authentication) on a spare YubiKey dedicated to spec test-vector signing, self-signed certificate labeled "ZLAR Spec Signing"
- Generation date: 2026-04-16
- Generation ceremony: ykman piv keys generate (Ed25519) into slot 9A; ykman piv certificates generate self-signed; exported public half with ykman piv certificates export; captured PEM; committed public half at spec/test-key.pub.
- Access: pkcs11-tool via libykcs11 (module /usr/local/lib/libykcs11.dylib on macOS; libykcs11 equivalents on Linux/Windows), mechanism EDDSA, object ID 01, slot 9A. PIN gate on every use.
- Scope: signs governed-action receipt test vectors embedded in spec/governed-action-receipt-v1.md Annex A. Not used for anything else.
- Context: first pinned key under this provenance discipline. Replaced the pre-discipline key 42ba3e47c439f06c (lost before publication; see an April 2026 incident record (kept in the private development history)). That key was never used to sign a Published receipt and is permanently retired.

Policy Signing hardware target, not current operational signer

- Fingerprint: deea87cc7bb386a3
- Algorithm: Ed25519
- Private half: PIV slot 9C on the primary YubiKey.
- Scope after migration: signs operational policy bundles loaded by ZLAR gates.
- Provenance note: predates this provenance discipline; generation ceremony was not recorded at the time. This is a known gap. No action until next rotation; at that point a fresh entry gets recorded here.
- Correction (2026-04-17): Provisioned for this role, not used operationally to date. Migration under review.

Constitution Signing hardware target, not current operational signer

- Fingerprint: f3ddd075782c70a6
- Algorithm: Ed25519
- Private half: PIV slot 9D on the primary YubiKey.
- Scope after migration: signs the ZLAR constitution (Second Authority Law meta-policy).
- Provenance note: predates this provenance discipline; generation ceremony was not recorded at the time. This is a known gap. No action until next rotation; at that point a fresh entry gets recorded here.
- Correction (2026-04-17): Provisioned for this role, not used operationally to date. Migration under review.

Current operational policy, manifest, and constitution signatures verify against
the public material embedded in the relevant signed files and the local
per-install verifier files reported by bin/zlar-key-state. Those current
software-rooted pins are live state, not a hardware custody claim. Do not infer
operational hardware custody from the 9C or 9D provisioned-key entries above.

Process for future keys

1. Before generating a key, open a pull request adding a stub entry to this file. The stub names the concern, the algorithm, the intended device/slot, and the ceremony to be used. This is the scoping review.
2. Generate the key inside the device using the ceremony in the stub. Do not store any private material outside the device.
3. Export the public half only. Commit it to the public location named in the stub.
4. Update the stub in this file with the fingerprint (first 16 hex of SHA-256 of the public PEM) and the generation date. Close the PR.
5. If rotation is required later, retire the old fingerprint here with a one-line note pointing at the relevant incident doc, and add a fresh entry below it. Do not delete retired entries; they are the audit trail.

Device hygiene

2026-04-16 — Both YubiKeys (primary holding Policy 9C + Constitution 9D;
spare holding Spec Signing 9A) moved off factory defaults: PIN retry count
set to 8, PUK retry count set to 3, PUK rotated to a recorded value, and
Management Key regenerated with `--protect --generate` so the random
Management Key is stored PIN-protected on the device itself. No signing
key was touched; existing signatures and verifiers remain unaffected.

Retired entries

- `codex-local-zlar-2026-06-20` — Ed25519 software SSH deploy key for
  `ZLAR-AI/ZLAR` (GitHub key id 155011431, fingerprint
  `SHA256:rRgu1JBJ72rI6/8wVxJPhwzKQYYeG0BgbVl4iws9YJE`). Active 2026-06-20
  through 2026-08-23 — continuously, with no disable state, which is the
  exposure Demo 1.5 exists to end. Vincent deleted the GitHub entry
  2026-08-23; the local private/public pair was destroyed the same evening
  after the push key's positive and negative proofs passed. A revoked
  credential is destroyed, not archived; this entry is the record.

- 42ba3e47c439f06c — Ed25519, spec test-vector signing (Draft only, never reached Published v1.0). Private half unrecoverable as of 2026-04-16. See an April 2026 incident record (kept in the private development history). A verifier that encounters this kid in a receipt MUST reject the receipt: no valid Published receipt has ever been signed under this key.
