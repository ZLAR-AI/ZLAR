Key State — ZLAR Signing Keys

Run this at the start of any session that touches signing, keys, or anything that might trigger a ceremony:

    bin/zlar-key-state
    bin/zlar key-state
    bin/zlar key-state --json
    bin/zlar key-state --sample --json

Read-only. No PINs. No signing. No private material touched. Prints every
pubkey fingerprint the repo cares about, every observed YubiKey slot, and what
the manifest, active policy, and constitution claim they are signed under. The
JSON form emits `zlar-key-state-report-v1` for automation without serial
numbers, raw private paths, or private key material. It reports legacy software
private-key presence as a boolean only.

`bin/zlar key-state --sample --json` emits the deterministic fixture form used
by `zlar local-proof-pack` and `zlar proof-smoke`. It uses a fixture home
directory, fixed timestamp, no hardware observation, and no OpenSSL/YubiKey
tool availability. It exists so committed evaluator fixtures can carry the
key-state report shape and non-claims without looking at an operator's home
directory, hardware, private key paths, or current-machine custody state.
`--sample` is only valid with `--json`.

Why this exists. AI sessions have no cross-session memory, and the repo previously did not describe its own key state. Every session rediscovered the key layout from scratch, often wrongly, and the errors propagated into signing ceremonies. One command. One snapshot. Full truth. No reasoning required.

Fingerprint convention. First 16 hex of SHA-256 of the PEM public key on disk, including trailing newline. Matches docs/key-provenance.md and the kid embedded in receipts.

Current operational posture

Operational signing for policy, manifest, and constitution artifacts is
software-rooted unless a later ceremony and repo note say otherwise. Hardware
ceremony keys may be provisioned, but they are not operational custody proof by
themselves. The current Option B boundary is recorded in
docs/key-provenance.md.

The signing concerns

Policy signing. Local verifier material lives in etc/keys/policy-signing.pub,
is pinned by etc/manifest.json .signature.key_id when a local manifest exists,
and is embedded in etc/policies/active.policy.json .signature.public_key. The
private half is operationally software-rooted today. A future hardware migration
would require an explicit ceremony and fresh provenance entry.

Constitution signing. Local verifier material lives in
etc/keys/constitution-signing.pub and is embedded in etc/constitution.json
.signature.public_key. The private half is operationally software-rooted today.
A future hardware migration would require an explicit ceremony and fresh
provenance entry.

Spec test-vector signing. Private half in PIV slot 9A on the spare YubiKey
dedicated to spec work. Public half committed at spec/test-key.pub. Signs test
vectors embedded in spec/governed-action-receipt-v1.md. Used only for spec
publication, never for operational policy, manifest, constitution, or runtime
receipts.

Discipline

Before any ceremony, run bin/zlar-key-state and read it.

If every concern required for the ceremony reports aligned, proceed.

If a concern required for the ceremony reports misaligned, stop. Do not proceed
with a workaround. Pick which fingerprint is authoritative (the one the
maintainer intends to use going forward), update the others to match, then
re-run the tool. Only proceed once the tool reports aligned for that ceremony.

If a YubiKey row is absent during routine software-rooted operation, do not turn
that absence into a verifier failure or a hardware-custody claim. It means no
hardware ceremony was observed by this command. For policy, manifest, and
constitution signing, current readiness means the software-rooted verifier pins
line up. Hardware-slot alignment is a migration/ceremony observation, not a
current custody proof.

If a sample report says no hardware is observed or no legacy software signing
key is present, read that as fixture truth only. It does not say what is present
on the current operator machine.

If ~/.zlar-signing.key is present, the gate flags it. That legacy software key can sign without any YubiKey. It should not exist on a production operator machine; its presence means signing does not require hardware possession.

For historical provenance of each pinned key (who generated it, when, and how), read docs/key-provenance.md. That file is history. bin/zlar-key-state is the present.
