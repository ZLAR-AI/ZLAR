Key Provenance — ZLAR Pinned Keys

Purpose. Every pinned key used by ZLAR governance carries a provenance entry in this file, recorded at the moment of generation. This closes the process gap surfaced by docs/incidents/2026-04-16-spec-key-recovery.md: a key whose generation ceremony is not written down can be lost without an audit trail.

What this file publishes and what it does not. This file publishes the category of storage (e.g. "YubiKey PIV slot 9A"), the ceremony used to generate the key, the algorithm, and the public fingerprint. It does not publish serial numbers, locations, PINs, management keys, or anything that weakens the security of the stored private material. Secrecy of the private half remains the design; this file documents the ceremony around it.

Separation rule. Three concerns, three physical devices. Policy Signing on the primary YubiKey (slot 9C). Constitution Signing on the primary YubiKey (slot 9D). Spec test-vector signing on a separate spare YubiKey (slot 9A). Keys do not cross concerns. A new concern requires a new device.

Provenance entries

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
- Context: first pinned key under this provenance discipline. Replaced the pre-discipline key 42ba3e47c439f06c (lost before publication; see docs/incidents/2026-04-16-spec-key-recovery.md). That key was never used to sign a Published receipt and is permanently retired.

Policy Signing

- Fingerprint: deea87cc7bb386a3
- Algorithm: Ed25519
- Private half: PIV slot 9C on the primary YubiKey.
- Scope: signs operational policy bundles loaded by ZLAR gates.
- Provenance note: predates this provenance discipline; generation ceremony was not recorded at the time. This is a known gap. No action until next rotation; at that point a fresh entry gets recorded here.

Constitution Signing

- Fingerprint: f3ddd075782c70a6
- Algorithm: Ed25519
- Private half: PIV slot 9D on the primary YubiKey.
- Scope: signs the ZLAR constitution (Second Authority Law meta-policy).
- Provenance note: predates this provenance discipline; generation ceremony was not recorded at the time. This is a known gap. No action until next rotation; at that point a fresh entry gets recorded here.

Process for future keys

1. Before generating a key, open a pull request adding a stub entry to this file. The stub names the concern, the algorithm, the intended device/slot, and the ceremony to be used. This is the scoping review.
2. Generate the key inside the device using the ceremony in the stub. Do not store any private material outside the device.
3. Export the public half only. Commit it to the public location named in the stub.
4. Update the stub in this file with the fingerprint (first 16 hex of SHA-256 of the public PEM) and the generation date. Close the PR.
5. If rotation is required later, retire the old fingerprint here with a one-line note pointing at the relevant incident doc, and add a fresh entry below it. Do not delete retired entries; they are the audit trail.

Retired entries

- 42ba3e47c439f06c — Ed25519, spec test-vector signing (Draft only, never reached Published v1.0). Private half unrecoverable as of 2026-04-16. See docs/incidents/2026-04-16-spec-key-recovery.md. A verifier that encounters this kid in a receipt MUST reject the receipt: no valid Published receipt has ever been signed under this key.
