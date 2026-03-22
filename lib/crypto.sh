#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR Cryptographic Abstraction Layer
#
# Provides algorithm-agnostic signing, verification, and key management.
# All crypto operations go through this library. Algorithm choice is
# configuration, not code.
#
# Supported algorithms:
#   ed25519   — Current default. Classical security only (128-bit).
#   ml-dsa-44 — NIST FIPS 204. Post-quantum (Level 2). Requires liboqs.
#   hybrid    — Ed25519 + ML-DSA-44 composite. Both must verify.
#
# Cryptographic agility: algorithms can be swapped via ZLAR_SIGN_ALGORITHM
# environment variable or crypto.json config without code changes.
# This satisfies GC ITSM.40.001 / ITSAP.40.018 cryptographic agility
# requirements (effective April 1, 2026).
#
# Design: every function returns 0 on success, non-zero on failure.
# No function calls exit. Callers decide what to do on failure.
# ═══════════════════════════════════════════════════════════════════════════════

# Guard against double-sourcing
[ -n "${_ZLAR_CRYPTO_LOADED:-}" ] && return 0
_ZLAR_CRYPTO_LOADED=1

# ─── Algorithm Resolution ─────────────────────────────────────────────────────
# Priority: env var > config file > default
# Config file location: $PROJECT_DIR/etc/crypto.json (optional)

_CRYPTO_PROJECT_DIR="${_CRYPTO_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
_CRYPTO_CONFIG="${_CRYPTO_PROJECT_DIR}/etc/crypto.json"

# Resolve the active signing algorithm
zlar_crypto_algorithm() {
    # 1. Environment variable override
    if [ -n "${ZLAR_SIGN_ALGORITHM:-}" ]; then
        echo "${ZLAR_SIGN_ALGORITHM}"
        return 0
    fi

    # 2. Config file
    if [ -f "${_CRYPTO_CONFIG}" ] && command -v jq &>/dev/null; then
        local algo
        algo=$(jq -r '.signing_algorithm // empty' "${_CRYPTO_CONFIG}" 2>/dev/null)
        if [ -n "${algo}" ]; then
            echo "${algo}"
            return 0
        fi
    fi

    # 3. Default
    echo "ed25519"
}

# Human-readable algorithm label for audit trails
zlar_crypto_label() {
    local algo
    algo=$(zlar_crypto_algorithm)
    case "${algo}" in
        ed25519)   echo "Ed25519" ;;
        ml-dsa-44) echo "ML-DSA-44" ;;
        hybrid)    echo "Ed25519+ML-DSA-44" ;;
        *)         echo "${algo}" ;;
    esac
}

# ─── Key Generation ───────────────────────────────────────────────────────────

# Generate a signing keypair for the active algorithm.
# Args: $1 = private key path, $2 = public key path
# Returns: 0 on success
zlar_crypto_keygen() {
    local privkey="$1" pubkey="$2"
    local algo
    algo=$(zlar_crypto_algorithm)

    case "${algo}" in
        ed25519)
            _keygen_ed25519 "${privkey}" "${pubkey}"
            ;;
        ml-dsa-44)
            _keygen_ml_dsa_44 "${privkey}" "${pubkey}"
            ;;
        hybrid)
            # Hybrid generates both keypairs. Private key is a directory.
            _keygen_hybrid "${privkey}" "${pubkey}"
            ;;
        *)
            echo "ERROR: Unknown signing algorithm: ${algo}" >&2
            return 1
            ;;
    esac
}

_keygen_ed25519() {
    local privkey="$1" pubkey="$2"
    openssl genpkey -algorithm Ed25519 -out "${privkey}" 2>/dev/null || return 1
    chmod 600 "${privkey}"
    local pubdir
    pubdir=$(dirname "${pubkey}")
    mkdir -p "${pubdir}" 2>/dev/null
    openssl pkey -in "${privkey}" -pubout -out "${pubkey}" 2>/dev/null || return 1
    chmod 644 "${pubkey}"
}

_keygen_ml_dsa_44() {
    local privkey="$1" pubkey="$2"
    # ML-DSA-44 (FIPS 204): native in OpenSSL 3.6+, or via liboqs/oqs-provider
    if ! openssl list -signature-algorithms 2>/dev/null | grep -qi "mldsa44\|ml-dsa-44\|dilithium2"; then
        echo "ERROR: ML-DSA-44 not available. Requires OpenSSL 3.6+ or liboqs." >&2
        return 1
    fi
    openssl genpkey -algorithm MLDSA44 -out "${privkey}" 2>/dev/null || return 1
    chmod 600 "${privkey}"
    local pubdir
    pubdir=$(dirname "${pubkey}")
    mkdir -p "${pubdir}" 2>/dev/null
    openssl pkey -in "${privkey}" -pubout -out "${pubkey}" 2>/dev/null || return 1
    chmod 644 "${pubkey}"
}

_keygen_hybrid() {
    local privkey_dir="$1" pubkey="$2"
    # Hybrid stores two keypairs. Private key path becomes a directory.
    mkdir -p "${privkey_dir}" 2>/dev/null
    chmod 700 "${privkey_dir}"

    _keygen_ed25519 "${privkey_dir}/ed25519.key" "${privkey_dir}/ed25519.pub" || return 1
    _keygen_ml_dsa_44 "${privkey_dir}/ml-dsa-44.key" "${privkey_dir}/ml-dsa-44.pub" || return 1

    # Combined public key: concatenated PEM
    local pubdir
    pubdir=$(dirname "${pubkey}")
    mkdir -p "${pubdir}" 2>/dev/null
    {
        echo "# ZLAR Hybrid Public Key (Ed25519 + ML-DSA-44)"
        echo "# Both signatures must verify for the composite to be valid."
        echo "--- ED25519 ---"
        cat "${privkey_dir}/ed25519.pub"
        echo "--- ML-DSA-44 ---"
        cat "${privkey_dir}/ml-dsa-44.pub"
    } > "${pubkey}"
    chmod 644 "${pubkey}"
}

# ─── Signing ──────────────────────────────────────────────────────────────────

# Sign a file (typically a SHA-256 hash file).
# Args: $1 = key path, $2 = input file, $3 = output sig file
# Returns: 0 on success
zlar_crypto_sign() {
    local key="$1" input="$2" output="$3"
    local algo
    algo=$(zlar_crypto_algorithm)

    case "${algo}" in
        ed25519)
            _sign_ed25519 "${key}" "${input}" "${output}"
            ;;
        ml-dsa-44)
            _sign_ml_dsa_44 "${key}" "${input}" "${output}"
            ;;
        hybrid)
            _sign_hybrid "${key}" "${input}" "${output}"
            ;;
        *)
            echo "ERROR: Unknown signing algorithm: ${algo}" >&2
            return 1
            ;;
    esac
}

_sign_ed25519() {
    local key="$1" input="$2" output="$3"
    openssl pkeyutl -sign -inkey "${key}" -rawin -in "${input}" -out "${output}" 2>/dev/null
}

_sign_ml_dsa_44() {
    local key="$1" input="$2" output="$3"
    openssl pkeyutl -sign -inkey "${key}" -rawin -in "${input}" -out "${output}" 2>/dev/null
}

_sign_hybrid() {
    local key_dir="$1" input="$2" output="$3"
    # Sign with both algorithms. Output is concatenated: ed25519_sig || ml-dsa-44_sig
    # Length-prefixed: 4-byte big-endian length of ed25519 sig, then sig, then rest is ml-dsa-44
    local ed_sig ml_sig
    ed_sig=$(mktemp)
    ml_sig=$(mktemp)

    _sign_ed25519 "${key_dir}/ed25519.key" "${input}" "${ed_sig}" || { rm -f "${ed_sig}" "${ml_sig}"; return 1; }
    _sign_ml_dsa_44 "${key_dir}/ml-dsa-44.key" "${input}" "${ml_sig}" || { rm -f "${ed_sig}" "${ml_sig}"; return 1; }

    # Concatenate with length prefix
    local ed_len
    ed_len=$(wc -c < "${ed_sig}" | tr -d ' ')
    printf '%08x' "${ed_len}" | xxd -r -p > "${output}"
    cat "${ed_sig}" >> "${output}"
    cat "${ml_sig}" >> "${output}"

    rm -f "${ed_sig}" "${ml_sig}"
}

# ─── Verification ─────────────────────────────────────────────────────────────

# Verify a signature.
# Args: $1 = public key path, $2 = input file (hash), $3 = signature file
# Optional: $4 = algorithm override (for verifying old entries under a different algo)
# Returns: 0 if valid, non-zero if invalid
zlar_crypto_verify() {
    local pubkey="$1" input="$2" sigfile="$3"
    local algo="${4:-$(zlar_crypto_algorithm)}"

    case "${algo}" in
        ed25519|Ed25519)
            _verify_ed25519 "${pubkey}" "${input}" "${sigfile}"
            ;;
        ml-dsa-44|ML-DSA-44)
            _verify_ml_dsa_44 "${pubkey}" "${input}" "${sigfile}"
            ;;
        hybrid|Ed25519+ML-DSA-44)
            _verify_hybrid "${pubkey}" "${input}" "${sigfile}"
            ;;
        *)
            echo "ERROR: Unknown algorithm for verification: ${algo}" >&2
            return 1
            ;;
    esac
}

_verify_ed25519() {
    local pubkey="$1" input="$2" sigfile="$3"
    openssl pkeyutl -verify -pubin -inkey "${pubkey}" -rawin -sigfile "${sigfile}" -in "${input}" &>/dev/null
}

_verify_ml_dsa_44() {
    local pubkey="$1" input="$2" sigfile="$3"
    openssl pkeyutl -verify -pubin -inkey "${pubkey}" -rawin -sigfile "${sigfile}" -in "${input}" &>/dev/null
}

_verify_hybrid() {
    local pubkey="$1" input="$2" sigfile="$3"
    # Both must verify. Extract ed25519 and ml-dsa-44 components.
    # Read 4-byte length prefix, split signatures.
    local ed_len_hex ed_len
    ed_len_hex=$(xxd -p -l 4 "${sigfile}")
    ed_len=$((16#${ed_len_hex}))

    local ed_sig ml_sig ed_pub ml_pub
    ed_sig=$(mktemp)
    ml_sig=$(mktemp)

    # Extract ed25519 and ml-dsa-44 public keys from combined pubkey file
    # Must preserve PEM headers. Only strip ZLAR marker lines (exactly 3 dashes),
    # not PEM delimiters (5 dashes).
    ed_pub=$(mktemp)
    ml_pub=$(mktemp)
    sed -n '/^--- ED25519 ---$/,/^--- ML-DSA-44 ---$/p' "${pubkey}" | grep -v '^#' | grep -v '^--- ' | grep -v '^$' > "${ed_pub}"
    sed -n '/^--- ML-DSA-44 ---$/,$ p' "${pubkey}" | grep -v '^#' | grep -v '^--- ' | grep -v '^$' > "${ml_pub}"

    # Split signature file
    dd if="${sigfile}" bs=1 skip=4 count="${ed_len}" of="${ed_sig}" 2>/dev/null
    dd if="${sigfile}" bs=1 skip=$((4 + ed_len)) of="${ml_sig}" 2>/dev/null

    local ed_ok=1 ml_ok=1
    _verify_ed25519 "${ed_pub}" "${input}" "${ed_sig}" && ed_ok=0
    _verify_ml_dsa_44 "${ml_pub}" "${input}" "${ml_sig}" && ml_ok=0

    rm -f "${ed_sig}" "${ml_sig}" "${ed_pub}" "${ml_pub}"

    # Both must pass
    if [ "${ed_ok}" -eq 0 ] && [ "${ml_ok}" -eq 0 ]; then
        return 0
    fi
    return 1
}

# ─── Public Key Utilities ─────────────────────────────────────────────────────

# Extract public key in DER-encoded base64 (for embedding in policy JSON)
# Args: $1 = private key path
# Outputs: base64-encoded public key on stdout
zlar_crypto_pubkey_b64() {
    local key="$1"
    local algo
    algo=$(zlar_crypto_algorithm)

    case "${algo}" in
        ed25519)
            openssl pkey -in "${key}" -pubout -outform DER 2>/dev/null | base64 | tr -d '\n'
            ;;
        ml-dsa-44)
            openssl pkey -in "${key}" -pubout -outform DER 2>/dev/null | base64 | tr -d '\n'
            ;;
        hybrid)
            # For hybrid, concatenate both public keys base64-encoded
            local ed_b64 ml_b64
            ed_b64=$(openssl pkey -in "${key}/ed25519.key" -pubout -outform DER 2>/dev/null | base64 | tr -d '\n')
            ml_b64=$(openssl pkey -in "${key}/ml-dsa-44.key" -pubout -outform DER 2>/dev/null | base64 | tr -d '\n')
            echo "${ed_b64}:${ml_b64}"
            ;;
    esac
}

# Compute public key fingerprint (first 16 chars of SHA-256)
# Args: $1 = public key file path
# Outputs: fingerprint on stdout
zlar_crypto_pubkey_fingerprint() {
    local pubkey="$1"
    shasum -a 256 "${pubkey}" 2>/dev/null | awk '{print substr($1,1,16)}'
}

# ─── Hash ─────────────────────────────────────────────────────────────────────

# Hash a file with the configured hash algorithm.
# Currently SHA-256 only. When SHA-3 or other algorithms are needed,
# this is the single place to change.
# Args: $1 = input file, $2 = output hash file
zlar_crypto_hash() {
    local input="$1" output="$2"
    shasum -a 256 "${input}" | awk '{print $1}' | tr -d '\n' > "${output}"
}

# Hash algorithm label for audit trails
zlar_crypto_hash_label() {
    echo "SHA-256"
}
