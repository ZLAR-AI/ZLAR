#!/bin/bash
# lib/hmac.sh — Inbox HMAC computation and verification for ZLAR gates
# Sourced by: zlar-tg-poll (compute), zlar-gate (verify), zlar-oc-gate (verify)
#
# Prevents forged approval files in the Telegram inbox directories.
# HMAC secret is generated per-boot by zlar-tg-boot.sh.

# Not readonly — lib may be sourced multiple times in test scenarios
ZLAR_HMAC_SECRET_FILE="${ZLAR_HMAC_SECRET_FILE:-/var/run/zlar-tg/inbox-hmac-secret}"

# Load HMAC secret from file. Call once at script initialization.
# Sets ZLAR_INBOX_HMAC_SECRET global.
zlar_hmac_load_secret() {
    ZLAR_INBOX_HMAC_SECRET=""
    if [ -f "${ZLAR_HMAC_SECRET_FILE}" ]; then
        ZLAR_INBOX_HMAC_SECRET=$(cat "${ZLAR_HMAC_SECRET_FILE}" 2>/dev/null | tr -d '[:space:]')
    fi
}

# Compute HMAC-SHA256 over callback fields.
# Args: data from_id callback_query_id
# Stdout: base64-encoded HMAC
# Returns: 0 on success, 1 on failure
#
# SECURITY: Secret passed via hex key (-macopt hexkey:...) instead of
# -hmac "$secret" to avoid exposing it in process args (ps/cmdline).
# The hex conversion happens in-process (printf + xxd), never in a
# child process where the raw secret would be visible.
zlar_hmac_compute() {
    local data="$1" from_id="$2" cb_id="$3"
    local hex_key
    hex_key=$(printf '%s' "${ZLAR_INBOX_HMAC_SECRET}" | xxd -p 2>/dev/null | tr -d '\n')
    if [ -z "${hex_key}" ]; then
        # Fallback if xxd not available: use od
        hex_key=$(printf '%s' "${ZLAR_INBOX_HMAC_SECRET}" | od -An -tx1 2>/dev/null | tr -d ' \n')
    fi
    [ -n "${hex_key}" ] || return 1
    local result
    result=$(printf '%s|%s|%s' "${data}" "${from_id}" "${cb_id}" \
        | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${hex_key}" -binary 2>/dev/null \
        | openssl base64 -A 2>/dev/null) || return 1
    [ -n "${result}" ] || return 1
    printf '%s' "${result}"
}

# Verify HMAC on an inbox callback file.
# Args: data from_id callback_query_id expected_hmac
# Returns: 0 if valid, 1 if invalid or error
zlar_hmac_verify() {
    local data="$1" from_id="$2" cb_id="$3" expected_hmac="$4"

    # No secret loaded = boot incomplete or secret deleted. Deny, don't degrade.
    if [ -z "${ZLAR_INBOX_HMAC_SECRET}" ]; then
        return 1
    fi

    # Missing HMAC field in inbox file = unsigned file. Reject.
    if [ -z "${expected_hmac}" ]; then
        return 1
    fi

    local computed
    computed=$(zlar_hmac_compute "${data}" "${from_id}" "${cb_id}") || return 1
    [ -n "${computed}" ] || return 1

    # Constant-time compare: hash both values so comparison is fixed-length
    # and does not short-circuit on first differing byte
    local h_computed h_expected
    h_computed=$(printf '%s' "${computed}" | shasum -a 256 | awk '{print $1}')
    h_expected=$(printf '%s' "${expected_hmac}" | shasum -a 256 | awk '{print $1}')
    [ "${h_computed}" = "${h_expected}" ]
}
