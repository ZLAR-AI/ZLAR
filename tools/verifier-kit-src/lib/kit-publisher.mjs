// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Verifier Kit — Publisher Key + Version Pins
//
// THIS FILE IS A SOURCE-TREE PLACEHOLDER.
//
// The real `lib/kit-publisher.mjs` is written into the BUILT kit by
// tools/build-verifier-kit.sh. It contains the publisher public key (PEM)
// that signs MANIFEST.sig, the kit version, and the spec version.
//
// Running the source-tree verifier directly (without building) is not
// supported — the runtime self-test will not find a MANIFEST.json next
// to this placeholder and will exit 4 (BUNDLE-INTEGRITY-FAIL) before any
// verification logic runs.
//
// To produce a runnable kit, invoke:
//   bash tools/build-verifier-kit.sh --publisher-key <PRIVATE_PEM>
// ═══════════════════════════════════════════════════════════════════════════════

export const PUBLISHER_PUBKEY_PEM = `-----BEGIN PUBLIC KEY-----
PLACEHOLDER-NOT-A-REAL-KEY-BUILD-SCRIPT-OVERWRITES-THIS-FILE-AT-BUILD-TIME
-----END PUBLIC KEY-----`;
export const KIT_VERSION = 'v0.1.0-source';
export const SPEC_VERSION = 'v1.0.0';
