#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR State HMAC — Shared Tamper-Detection Helpers
#
# Parameterized HMAC sealing / verification / atomic sealed-write for state
# files owned by a single operator (human-state decision counters, gate-uptime
# streak counters, future state files). Extracted from near-duplicate helpers
# in lib/human-invariants.sh and lib/gate-uptime.sh.
#
# Threat model: an agent with filesystem access poisoning local state. HMAC
# detects the tamper; callers decide whether to rebuild (preserve availability,
# log the signal) or fail closed.
#
# Canonical form for hashing: `jq -cS 'del(._hmac)'` — sorted keys, compact,
# always excluding the _hmac field itself. This matches the Node
# canonicalJSON() serializer in lib/human-invariants.mjs so states written by
# either gate verify under the other.
#
# No key = unauthenticated mode (backward compat). Callers pass their own key
# on every call; the caller owns key lifecycle.
#
# Atomicity: every write is temp + POSIX rename. A crash mid-write leaves
# either the old file or the new file intact, never a truncated one.
# ═══════════════════════════════════════════════════════════════════════════════

# Guard against double-sourcing
[ -n "${_ZLAR_STATE_HMAC_LOADED:-}" ] && return 0
_ZLAR_STATE_HMAC_LOADED=1

# Compute HMAC over canonical form of payload-minus-hmac. Payload is read from
# stdin. Output (hex hmac) goes to stdout. Empty key → empty output (unkeyed).
#
# Defensive: strips any incoming _hmac before hashing. Callers that pipe the
# result of a prior load back through for update would otherwise hash with
# the stale _hmac in place, producing a signature the verify path (which uses
# `jq -cS 'del(._hmac)'`) would reject as tampered.
#
# Usage: printf '%s' "${payload}" | _state_hmac_compute "${key}"
_state_hmac_compute() {
    local key="$1"
    [ -z "${key}" ] && return 0
    jq -cS 'del(._hmac)' 2>/dev/null | \
        openssl dgst -sha256 -hmac "${key}" 2>/dev/null | \
        awk '{print $NF}'
}

# Verify HMAC on a state file. Returns "ok" | "tampered" | "unkeyed".
# "unkeyed" means no key is configured — caller treats as ok for backward
# compat with deployments that haven't provisioned the HMAC key.
#
# Usage: status=$(_state_hmac_verify "${key}" "${file}")
_state_hmac_verify() {
    local key="$1" file="$2"
    [ -z "${key}" ] && { echo "unkeyed"; return 0; }
    [ ! -f "${file}" ] && { echo "tampered"; return 1; }

    local stored
    stored=$(jq -r '._hmac // ""' "${file}" 2>/dev/null)
    if [ -z "${stored}" ]; then
        echo "tampered"
        return 1
    fi

    local computed
    computed=$(jq -cS 'del(._hmac)' "${file}" 2>/dev/null | \
        openssl dgst -sha256 -hmac "${key}" 2>/dev/null | \
        awk '{print $NF}')

    if [ "${computed}" = "${stored}" ]; then
        echo "ok"
        return 0
    fi
    echo "tampered"
    return 1
}

# Atomic sealed write. Reads payload JSON (without _hmac) from stdin, computes
# HMAC if a key is given, writes <file>.tmp with the _hmac field appended, then
# atomically renames into place. Empty key → writes payload unsealed.
#
# Creates the parent directory if missing. Returns nonzero on any write
# failure; caller decides whether that is recoverable.
#
# Usage: echo "${payload_json}" | _state_hmac_sealed_write "${key}" "${file}"
_state_hmac_sealed_write() {
    local key="$1" file="$2"
    local tmp="${file}.tmp"
    local payload
    payload=$(cat)
    [ -z "${payload}" ] && return 1
    mkdir -p "$(dirname "${file}")" 2>/dev/null || true

    if [ -n "${key}" ]; then
        local hmac
        hmac=$(printf '%s' "${payload}" | _state_hmac_compute "${key}")
        if [ -z "${hmac}" ]; then
            # HMAC computation failed — write unsealed rather than lose state.
            printf '%s' "${payload}" > "${tmp}" 2>/dev/null
        else
            printf '%s' "${payload}" | jq -c --arg h "${hmac}" '. + {_hmac: $h}' > "${tmp}" 2>/dev/null || {
                rm -f "${tmp}" 2>/dev/null
                return 1
            }
        fi
    else
        printf '%s' "${payload}" > "${tmp}" 2>/dev/null
    fi
    mv "${tmp}" "${file}" 2>/dev/null
}
