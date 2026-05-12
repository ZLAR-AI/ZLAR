#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# build-verifier-kit.sh — assemble the ZLAR Verifier Kit v0.1.0 tarball.
#
# The kit is mostly a packaging exercise on top of code that already ships
# (lib/receipt.mjs, lib/canonicalize.mjs, lib/semantic-validator.mjs,
# lib/sig-verify.mjs, spec/*). This script copies those files into a
# self-contained directory, embeds the publisher pubkey into the verifier
# entry points, computes a SHA-256 manifest, signs the manifest with the
# publisher key, and tars the bundle.
#
# Usage:
#   bash tools/build-verifier-kit.sh
#   bash tools/build-verifier-kit.sh --publisher-key /path/to/priv.pem
#   bash tools/build-verifier-kit.sh --publisher-key /path/to/priv.pem --publisher-pub /path/to/pub.pem
#
# With no --publisher-key, the script generates an EPHEMERAL Ed25519
# keypair for this build only and discards the private key on exit. This
# is the source-form internal slice path — the kit is buildable and
# testable but the publisher key has no persistent identity. Production
# distribution builds use --publisher-key with the ZLAR signing key per
# the K-OPT-1 stamp; that is a separate governed event.
#
# Reproducible-build guarantee: NOT IN v0.1. The kit is deterministic for
# identical inputs + identical Node + identical pinned spec/lib files,
# but a "build twice and diff SHA-256" CI check is queued for v0.2.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

KIT_VERSION="v0.1.0"
SPEC_VERSION="v1.0.0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SRC_DIR="${SCRIPT_DIR}/verifier-kit-src"
DIST_DIR="${REPO_ROOT}/dist"
KIT_DIR_NAME="zlar-verifier-kit-${KIT_VERSION}"
KIT_DIR="${DIST_DIR}/${KIT_DIR_NAME}"
TARBALL="${DIST_DIR}/${KIT_DIR_NAME}.tar.gz"

PUBLISHER_KEY=""
PUBLISHER_PUB=""
EPHEMERAL_DIR=""
VERBOSE=0

cleanup() {
    if [ -n "${EPHEMERAL_DIR}" ] && [ -d "${EPHEMERAL_DIR}" ]; then
        rm -rf "${EPHEMERAL_DIR}"
    fi
}
trap cleanup EXIT

while [ $# -gt 0 ]; do
    case "$1" in
        --publisher-key)    PUBLISHER_KEY="$2"; shift 2 ;;
        --publisher-pub)    PUBLISHER_PUB="$2"; shift 2 ;;
        --verbose|-v)       VERBOSE=1; shift ;;
        -h|--help)
            sed -n '2,30p' "$0"
            exit 0
            ;;
        *) echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
    esac
done

log() {
    if [ "${VERBOSE}" -eq 1 ]; then
        echo "[build-verifier-kit] $*"
    fi
}

# ─── Tool checks ──────────────────────────────────────────────────────────────

for tool in node openssl shasum tar awk sed; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "ERROR: required tool not on PATH: ${tool}" >&2
        exit 2
    fi
done

# Ed25519 support check
if ! echo "" | openssl genpkey -algorithm ED25519 -out /dev/null 2>/dev/null; then
    echo "ERROR: openssl does not support Ed25519 (--algorithm ED25519). Upgrade OpenSSL." >&2
    exit 2
fi

# ─── Publisher key resolution ─────────────────────────────────────────────────

if [ -z "${PUBLISHER_KEY}" ]; then
    EPHEMERAL_DIR="$(mktemp -d -t zlar-verifier-kit-build.XXXXXX)"
    chmod 700 "${EPHEMERAL_DIR}"
    log "Generating ephemeral Ed25519 publisher keypair in ${EPHEMERAL_DIR}"
    openssl genpkey -algorithm ED25519 -out "${EPHEMERAL_DIR}/publisher.key" 2>/dev/null
    chmod 600 "${EPHEMERAL_DIR}/publisher.key"
    openssl pkey -in "${EPHEMERAL_DIR}/publisher.key" -pubout -out "${EPHEMERAL_DIR}/publisher.pub" 2>/dev/null
    PUBLISHER_KEY="${EPHEMERAL_DIR}/publisher.key"
    PUBLISHER_PUB="${EPHEMERAL_DIR}/publisher.pub"
    log "Ephemeral pub: ${PUBLISHER_PUB}"
fi

if [ ! -f "${PUBLISHER_KEY}" ]; then
    echo "ERROR: publisher private key not found: ${PUBLISHER_KEY}" >&2
    exit 2
fi

# Derive pubkey if not supplied
if [ -z "${PUBLISHER_PUB}" ]; then
    PUBLISHER_PUB="${EPHEMERAL_DIR:-/tmp}/publisher-derived.pub"
    openssl pkey -in "${PUBLISHER_KEY}" -pubout -out "${PUBLISHER_PUB}" 2>/dev/null
fi

if [ ! -f "${PUBLISHER_PUB}" ]; then
    echo "ERROR: publisher public key not found and could not be derived: ${PUBLISHER_PUB}" >&2
    exit 2
fi

# Validate keypair: derived pub must match supplied pub if both given
DERIVED_PUB_FP="$(openssl pkey -in "${PUBLISHER_KEY}" -pubout 2>/dev/null | shasum -a 256 | awk '{print substr($1, 1, 16)}')"
SUPPLIED_PUB_FP="$(shasum -a 256 "${PUBLISHER_PUB}" | awk '{print substr($1, 1, 16)}')"

# Note: shasum on file vs shasum on stdout content can differ if file has
# trailing whitespace or different encoding. Normalize by comparing the
# PEM content directly.
DERIVED_PEM="$(openssl pkey -in "${PUBLISHER_KEY}" -pubout 2>/dev/null)"
SUPPLIED_PEM="$(cat "${PUBLISHER_PUB}")"

if [ "$(echo "${DERIVED_PEM}" | tr -d '[:space:]')" != "$(echo "${SUPPLIED_PEM}" | tr -d '[:space:]')" ]; then
    echo "ERROR: --publisher-pub does not match private key." >&2
    echo "  derived: ${DERIVED_PUB_FP}" >&2
    echo "  supplied: ${SUPPLIED_PUB_FP}" >&2
    exit 2
fi

# Publisher kid: first 16 hex of SHA-256(pubkey PEM file bytes).
PUBLISHER_KID="${SUPPLIED_PUB_FP}"
log "Publisher kid: ${PUBLISHER_KID}"

# ─── Reset output directory ───────────────────────────────────────────────────

rm -rf "${KIT_DIR}" "${TARBALL}" "${TARBALL}.sha256"
mkdir -p "${KIT_DIR}/lib" "${KIT_DIR}/spec"

# ─── Copy source files ────────────────────────────────────────────────────────

log "Copying entry points and self-test"
cp "${SRC_DIR}/verify.mjs"               "${KIT_DIR}/verify.mjs"
cp "${SRC_DIR}/verify-chain.mjs"         "${KIT_DIR}/verify-chain.mjs"
cp "${SRC_DIR}/selftest.mjs"             "${KIT_DIR}/selftest.mjs"
cp "${SRC_DIR}/verify-test-vectors.mjs"  "${KIT_DIR}/verify-test-vectors.mjs"
cp "${SRC_DIR}/README.md"                "${KIT_DIR}/README.md"
cp "${SRC_DIR}/VERSION"                  "${KIT_DIR}/VERSION"

log "Copying bundled lib modules from repo (verbatim)"
cp "${REPO_ROOT}/lib/receipt.mjs"            "${KIT_DIR}/lib/receipt.mjs"
cp "${REPO_ROOT}/lib/canonicalize.mjs"       "${KIT_DIR}/lib/canonicalize.mjs"
cp "${REPO_ROOT}/lib/semantic-validator.mjs" "${KIT_DIR}/lib/semantic-validator.mjs"
cp "${REPO_ROOT}/lib/sig-verify.mjs"         "${KIT_DIR}/lib/sig-verify.mjs"

log "Copying spec files"
cp "${REPO_ROOT}/spec/governed-action-receipt-v1.md" "${KIT_DIR}/spec/governed-action-receipt-v1.md"
cp "${REPO_ROOT}/spec/CONFORMANCE.md"                "${KIT_DIR}/spec/CONFORMANCE.md"
cp "${REPO_ROOT}/spec/test-key.pub"                  "${KIT_DIR}/spec/test-key.pub"
cp "${REPO_ROOT}/docs/canonicalization-spec.md"      "${KIT_DIR}/spec/canonicalization-spec.md"

log "Copying LICENSE"
cp "${REPO_ROOT}/LICENSE" "${KIT_DIR}/LICENSE"

# ─── Write publisher pubkey embed (lib/kit-publisher.mjs) ─────────────────────

# The source-tree placeholder at tools/verifier-kit-src/lib/kit-publisher.mjs
# is NOT copied. The build script writes the real one with the publisher
# PEM, KIT_VERSION, and SPEC_VERSION pinned.

PUB_PEM_CONTENTS="$(cat "${PUBLISHER_PUB}")"

cat > "${KIT_DIR}/lib/kit-publisher.mjs" <<EOF
// Generated by tools/build-verifier-kit.sh — do not edit.
// Embeds the publisher public key (PEM) used to verify MANIFEST.sig.
export const PUBLISHER_PUBKEY_PEM = \`${PUB_PEM_CONTENTS}\`;
export const KIT_VERSION = '${KIT_VERSION}';
export const SPEC_VERSION = '${SPEC_VERSION}';
EOF

# Also drop a copy of the pubkey on disk for operator inspection. The
# runtime self-test cross-checks this file against the embedded const.
cp "${PUBLISHER_PUB}" "${KIT_DIR}/kit-publisher.pub"

# ─── Compute MANIFEST.json ────────────────────────────────────────────────────

log "Computing MANIFEST.json"

# Build a deterministic file list. MANIFEST.json and MANIFEST.sig are NOT
# included (they reference the bundle, not themselves).
MANIFEST_FILES=$(
    cd "${KIT_DIR}"
    find . -type f \
        ! -name 'MANIFEST.json' \
        ! -name 'MANIFEST.sig' \
        | sed 's|^\./||' \
        | LC_ALL=C sort
)

export MANIFEST_FILE_LIST="${MANIFEST_FILES}"
MANIFEST_JSON="$(
    cd "${KIT_DIR}"
    MANIFEST_FILE_LIST="${MANIFEST_FILES}" node --input-type=module -e "
        import { readFileSync, statSync } from 'node:fs';
        import { createHash } from 'node:crypto';

        const files = process.env.MANIFEST_FILE_LIST.split('\\n').filter(Boolean);
        const entries = files.map(p => {
            const bytes = readFileSync(p);
            return {
                path: p,
                sha256: createHash('sha256').update(bytes).digest('hex'),
                size: statSync(p).size
            };
        });
        const manifest = {
            kit_version: '${KIT_VERSION}',
            spec_version: '${SPEC_VERSION}',
            publisher_kid: '${PUBLISHER_KID}',
            files: entries
        };
        function sortKeys(v) {
            if (v === null || typeof v !== 'object') return v;
            if (Array.isArray(v)) return v.map(sortKeys);
            const out = {};
            for (const k of Object.keys(v).sort()) out[k] = sortKeys(v[k]);
            return out;
        }
        process.stdout.write(JSON.stringify(sortKeys(manifest), null, 2));
    "
)"

printf '%s' "${MANIFEST_JSON}" > "${KIT_DIR}/MANIFEST.json"

# ─── Sign MANIFEST.json → MANIFEST.sig ────────────────────────────────────────

log "Signing MANIFEST.json"

# Ed25519 signs the message directly (not a pre-hash). openssl pkeyutl
# with -rawin matches Node crypto.sign(null, data, key) exactly.
openssl pkeyutl -sign -inkey "${PUBLISHER_KEY}" -rawin -in "${KIT_DIR}/MANIFEST.json" 2>/dev/null \
    | base64 \
    | tr -d '\n' \
    > "${KIT_DIR}/MANIFEST.sig"

# ─── Build tarball ────────────────────────────────────────────────────────────

log "Packing tarball ${TARBALL}"
(
    cd "${DIST_DIR}"
    # --owner / --group flags force deterministic ownership labels.
    # GNU tar accepts --owner=0; macOS bsdtar uses --uid/--gid.
    if tar --version 2>/dev/null | grep -q GNU; then
        tar --owner=0 --group=0 --numeric-owner -czf "${TARBALL}" "${KIT_DIR_NAME}"
    else
        # bsdtar (macOS default)
        tar --uid 0 --gid 0 -czf "${TARBALL}" "${KIT_DIR_NAME}"
    fi
)

TARBALL_SHA256="$(shasum -a 256 "${TARBALL}" | awk '{print $1}')"
printf '%s  %s\n' "${TARBALL_SHA256}" "${KIT_DIR_NAME}.tar.gz" > "${TARBALL}.sha256"

# ─── Build-time consistency check ─────────────────────────────────────────────
# Confirm the publisher key embedded in the built kit-publisher.mjs matches
# the file at kit-publisher.pub on disk. Belt-and-suspenders: catches
# template-edit bugs at build time rather than at first verify.

EMBEDDED_PEM="$(node --input-type=module -e "
    import('file://${KIT_DIR}/lib/kit-publisher.mjs').then(m => process.stdout.write(m.PUBLISHER_PUBKEY_PEM));
")"
DISK_PEM="$(cat "${KIT_DIR}/kit-publisher.pub")"

if [ "$(echo "${EMBEDDED_PEM}" | tr -d '[:space:]')" != "$(echo "${DISK_PEM}" | tr -d '[:space:]')" ]; then
    echo "ERROR: build-time consistency check failed — embedded publisher pubkey does not match kit-publisher.pub on disk." >&2
    exit 1
fi

# ─── Summary ──────────────────────────────────────────────────────────────────

echo "Kit built: ${TARBALL}"
echo "  kit_version:    ${KIT_VERSION}"
echo "  spec_version:   ${SPEC_VERSION}"
echo "  publisher_kid:  ${PUBLISHER_KID}"
echo "  tarball_sha256: ${TARBALL_SHA256}"
echo "  directory:      ${KIT_DIR}"
if [ -n "${EPHEMERAL_DIR}" ]; then
    echo "  publisher_key:  EPHEMERAL (private key discarded on exit)"
else
    echo "  publisher_key:  ${PUBLISHER_KEY}"
fi
