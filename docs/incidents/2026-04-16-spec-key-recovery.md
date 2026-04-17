Spec Test-Vector Key Recovery — 2026-04-16

Status: RESOLVED (rotation ceremony complete 2026-04-16)
Severity: Moderate (pre-publication; no external relying parties)
Incident owner: Vincent Nijjar (spec maintainer)
Governance: ZLAR CC gate ON during ceremony

Summary

On 2026-04-16, during Phase 2 work to expand Annex A test vectors from 5 to 9, the private half of the pinned spec test-vector key (fingerprint 42ba3e47c439f06c) was found to be unrecoverable. The public half is committed at spec/test-key.pub. Five existing test vectors (V1-V5) in spec/governed-action-receipt-v1.md were signed by this key on 2026-04-09 and remain verifiable against the public key, but no further receipts can be signed under this identity.

A password-manager entry from 2026-03-20 was initially thought to hold the private half, but inspection (fingerprint 35c73717e20a0e63, not matching the pinned kid) showed it to be a different Ed25519 key unrelated to the spec. No April 9 entry exists in the password manager. The spec test-vector private key was generated ad-hoc during spec drafting and its storage location was not recorded at the time — a process gap this incident closes.

Because v1 of the spec is still in Draft (staging) status — never Published — no external relying parties have yet taken a dependency on 42ba3e47c439f06c. The recovery window is narrow but clean: we rotate the pinned key at publication, re-sign all nine test vectors under the new identity, and Published v1.0 carries the new fingerprint as the permanent pinned identity for v1.

This file serves as the canonical reference for the question "what does ZLAR do when a pinned key is lost before publication?" It is also the process precedent for key-provenance recording going forward — every new pinned key generated from this point carries an entry in docs/key-provenance.md at generation time, so this kind of loss is not repeatable.

Timeline

2026-04-09 — Spec drafted. Pinned key 42ba3e47c439f06c generated (mechanism and storage location not recorded at the time — a gap this incident closes). V1-V5 signed by this key. Public half committed to spec/test-key.pub.

2026-04-16 morning — Phase 2 begins. Canonical payloads and SHA-256 hex hashes generated for V6-V9. Signing packet produced at ~/Desktop/ZLAR/vectors-6-9-signing-packet.md.

2026-04-16 afternoon — Diagnostic phase. Checked:
- Mac mini filesystem (common locations): no matching private key file.
- Primary YubiKey PIV slots: 9C holds ZLAR Policy Signing key (kid deea87cc7bb386a3), 9D holds ZLAR Constitution Signing key (kid f3ddd075782c70a6). Neither matches the pinned kid.
- ~/Desktop/ZLAR/Archive/: one spec/test-key.pub file found, but this is a public key (same as currently committed), not the private half.

Conclusion: the pinned private key material does not exist on any accessible device. It was either generated ad-hoc on a device that has since been cleared, or its storage location was not recorded. No evidence of compromise — the key is lost, not leaked.

Decision (2026-04-16, ~15:00 local) — Plan option B: Rotate at publication.

Rationale:
- The separation rule (memory: feedback_secrecy_is_design.md) disallows commingling the Policy Signing and Constitution Signing keys with spec test-vector signing. Reusing slot 9C or 9D would cross concerns.
- Publication is the correct rotation moment. Rotating a pinned key on a Draft specification with no external relying parties is a clean act. Rotating it after Published v1.0 would be a breaking change and an erosion of the archival-stability property.
- A spare YubiKey is available. It was originally intended for another ceremony role but is not yet committed. Dedicating it to spec test-vector signing preserves the three-purpose separation: Policy (primary), Constitution (primary), Spec (spare).

Recovery ceremony

Action 1 — (pending) Generate fresh Ed25519 keypair in spare YubiKey PIV slot 9A (authentication slot, currently empty). Self-signed cert labeled "ZLAR Spec Signing".

Action 2 — (pending) Export public half, replace spec/test-key.pub. New kid recorded here.

Action 3 — (pending) Re-sign V1-V5 under the new key. Signatures replaced in Annex A.

Action 4 — (pending) Sign V6-V9 under the new key. Full envelopes assembled and appended to Annex A.

Action 5 — (pending) Update spec prose (header, Annex A preamble pinned-kid reference), CONFORMANCE.md if needed, verify-test-vectors.mjs reads from test-key.pub — no code change.

Action 6 — (pending) Flip spec header to Status: Published v1.0 with date.

Action 7 — (pending) Full regression: node spec/verify-test-vectors.mjs passes all 9 vectors, bash tests/run-all.sh clean.

Lessons to bake into the spec and the process

1. Key provenance must be recorded at generation time. The spec will gain a prose note documenting how the pinned key was generated and where the private half lives. Not publishing the location — publishing the category (PIV slot 9A on spare YubiKey, serial redacted) and the ceremony used to generate it, so a future maintainer has a recoverable audit trail.

2. Test-vector signing is its own concern. It gets its own YubiKey (or equivalent), not shared with Policy or Constitution signing. The separation rule is now enforced by three physical devices.

3. "Lost pinned key before publication" is a recoverable condition. "Lost pinned key after publication" is not — the archived receipts become orphaned. This incident surfaced the distinction and documents the recovery procedure for the pre-publication case.

4. ZLAR governs its own ceremonies. The CC gate was ON throughout this recovery. Every filesystem change and signing command went through the gate. The audit trail is the second half of this document.

Outcome

Ceremony completed 2026-04-16 evening. Summary:

- Action 1: Ed25519 keypair generated in spare YubiKey PIV slot 9A (authentication slot), mechanism EDDSA via libykcs11/PKCS#11, self-signed certificate "ZLAR Spec Signing". Spare device serial 37175116.
- Action 2: Public half exported and replaces spec/test-key.pub. New pinned fingerprint: 72735da8aebb8106 (first 16 hex of SHA-256 of PEM on disk). Old fingerprint 42ba3e47c439f06c is retired; no receipts under it will ever be accepted by the published verifier.
- Action 3: V1-V5 re-signed under the new key. Canonical payloads, hashes, and ids preserved byte-for-byte from the 2026-04-09 draft; only the envelope signatures (and envelope-level kid) changed.
- Action 4: V6-V9 signed under the new key. V6 (policy-deny positive), V7 (timeout-denied positive), V8 (timeout+authorized negative — AUTHORIZER_OUTCOME_MISMATCH), V9 (delegation depth≠0 negative — DELEGATION_MISSING_ROOT). Full envelopes appended to Annex A. V2.prev chains to V1's envelope hash 48133e92432a87a0bbeab6651fe38df1c2a54acbe23617937ff98e2d1471a8a8; all other prev fields null per original spec convention.
- Action 5: spec/test-key.pub replaced. spec/verify-test-vectors.mjs updated to cover the 9-vector set (derives kid from PEM, no hardcoded fingerprint).
- Action 6: Spec header flipped to Status: Published v1.0, date 2026-04-16, with a "Pinned signing key" line naming the new fingerprint.
- Action 7: Full regression — node spec/verify-test-vectors.mjs reports "✓ ALL VECTORS MATCH SPEC EXPECTATIONS" (9/9). tests/run-all.sh status recorded in the session verification log.

Post-ceremony hardening items flagged (deferred, not part of this incident):
- Primary YubiKey (serial 37175059) and spare (serial 37175116) both still use default PUK and Management Key. Harden before either device leaves ceremony custody.
- docs/key-provenance.md to be written as the permanent process precedent so this class of loss is not repeatable.

The distinction that this incident made concrete: a pinned key lost before publication is a recoverable process event. A pinned key lost after publication orphans every receipt signed under it. ZLAR's v1 pinned identity is now the post-rotation key; everything published from 2026-04-16 forward verifies against 72735da8aebb8106, permanently.
