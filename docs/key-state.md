Key State — ZLAR Signing Keys

Run this at the start of any session that touches signing, keys, or anything that might trigger a ceremony:

    bin/zlar-key-state

Read-only. No PINs. No signing. No private material touched. Prints every pubkey fingerprint the repo cares about, every YubiKey slot that is plugged in, and what the manifest, active policy, and constitution claim they are signed under. Tells you in one screen whether ceremonies will work or where the alignment gap is.

Why this exists. AI sessions have no cross-session memory, and the repo previously did not describe its own key state. Every session rediscovered the key layout from scratch, often wrongly, and the errors propagated into signing ceremonies. One command. One snapshot. Full truth. No reasoning required.

Fingerprint convention. First 16 hex of SHA-256 of the PEM public key on disk, including trailing newline. Matches docs/key-provenance.md and the kid embedded in receipts.

The three signing concerns

Policy signing. Private half in PIV slot 9C on the primary YubiKey. Public half committed at etc/keys/policy-signing.pub. Pinned by etc/manifest.json .signature.key_id and embedded in etc/policies/active.policy.json .signature.public_key. All four fingerprints must match. Signing uses: bin/zlar-policy sign --yubikey.

Constitution signing. Private half in PIV slot 9D on the primary YubiKey. Public half committed at etc/keys/constitution-signing.pub. Embedded in etc/constitution.json .signature.public_key. All three fingerprints must match. Signing uses the constitution amendment ceremony, not the policy tool.

Spec test-vector signing. Private half in PIV slot 9A on the spare YubiKey dedicated to spec work. Public half committed at spec/test-key.pub. Signs test vectors embedded in spec/governed-action-receipt-v1.md. Used only for spec publication, never for operational policy or constitution.

Discipline

Before any ceremony, run bin/zlar-key-state and read it.

If every concern reports aligned, proceed.

If any concern reports misaligned, stop. Do not proceed with a workaround. Pick which fingerprint is authoritative (the one the maintainer intends to use going forward), update the others to match, then re-run the tool. Only proceed once the tool reports aligned.

If ~/.zlar-signing.key is present, the gate flags it. That legacy software key can sign without any YubiKey. It should not exist on a production operator machine; its presence means signing does not require hardware possession.

For historical provenance of each pinned key (who generated it, when, and how), read docs/key-provenance.md. That file is history. bin/zlar-key-state is the present.
