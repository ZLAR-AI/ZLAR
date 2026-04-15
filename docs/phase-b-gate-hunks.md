Phase B of ADR-011 — Manual hunks for bin/zlar-gate

R041 ("Edit ZLAR enforcement layer") correctly prevents an agent from modifying bin/zlar-gate. The human operator applies these four hunks manually.

Each hunk is a find-and-replace against the current bin/zlar-gate file. The line numbers are approximate (as of commit after this doc lands) — use the "FIND" block to locate the exact position. The NEW block is what replaces it.

Before applying: run "bash -n bin/zlar-gate" after each hunk so a syntax error is caught immediately rather than discovered at startup.

Verification after all four hunks:
1. bash -n bin/zlar-gate  (syntax clean)
2. Restart MCP gate and inspect startup log — should see "Signature verified" rather than "LEGACY" warnings for any artifact you subsequently re-sign under spec form
3. Until you re-sign, you will see per-artifact LEGACY warnings; those are expected until Phase B' (re-signing ceremony) runs

------------------------------------------------------------------------
HUNK 1 — Standing approvals verification (around line 303)
------------------------------------------------------------------------

FIND (the exact lines, including indentation):

            _sa_canon=$(mktemp "${GATE_TMP}/sa-canon.XXXXXX")
            _sa_hash=$(mktemp "${GATE_TMP}/sa-hash.XXXXXX")
            _sa_sig_bin=$(mktemp "${GATE_TMP}/sa-sig.XXXXXX")
            jq '.signature.value = ""' "${STANDING_APPROVALS_FILE}" > "${_sa_canon}" 2>/dev/null
            zlar_crypto_hash "${_sa_canon}" "${_sa_hash}"
            echo "${_sa_sig_value}" | base64 -d > "${_sa_sig_bin}" 2>/dev/null
            if ! zlar_crypto_verify "${POLICY_PUBKEY}" "${_sa_hash}" "${_sa_sig_bin}" "ed25519"; then
                _sa_sig_ok="false"
            fi
            rm -f "${_sa_canon}" "${_sa_hash}" "${_sa_sig_bin}"

REPLACE WITH:

            # Phase B of ADR-011 — dual canonical form verification.
            # Try spec form (compact, sorted, no trailing newline); fall
            # back to bash-pretty legacy form for artifacts signed before
            # Phase B.
            _sa_canon_spec=$(mktemp "${GATE_TMP}/sa-canon-spec.XXXXXX")
            _sa_canon_pretty=$(mktemp "${GATE_TMP}/sa-canon-pretty.XXXXXX")
            _sa_hash_spec=$(mktemp "${GATE_TMP}/sa-hash-spec.XXXXXX")
            _sa_hash_pretty=$(mktemp "${GATE_TMP}/sa-hash-pretty.XXXXXX")
            _sa_sig_bin=$(mktemp "${GATE_TMP}/sa-sig.XXXXXX")

            jq -S -c '.signature.value = ""' "${STANDING_APPROVALS_FILE}" | tr -d '\n' > "${_sa_canon_spec}" 2>/dev/null
            zlar_crypto_hash "${_sa_canon_spec}" "${_sa_hash_spec}"

            jq '.signature.value = ""' "${STANDING_APPROVALS_FILE}" > "${_sa_canon_pretty}" 2>/dev/null
            zlar_crypto_hash "${_sa_canon_pretty}" "${_sa_hash_pretty}"

            echo "${_sa_sig_value}" | base64 -d > "${_sa_sig_bin}" 2>/dev/null

            if zlar_crypto_verify "${POLICY_PUBKEY}" "${_sa_hash_spec}" "${_sa_sig_bin}" "ed25519"; then
                _sa_sig_ok="true"
            elif zlar_crypto_verify "${POLICY_PUBKEY}" "${_sa_hash_pretty}" "${_sa_sig_bin}" "ed25519"; then
                _sa_sig_ok="true"
                echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [gate] WARN: Standing approvals verified under LEGACY canonical form bash-pretty (ADR-011)" >> "${PROJECT_DIR}/var/log/gate.log" 2>/dev/null || true
            else
                _sa_sig_ok="false"
            fi

            rm -f "${_sa_canon_spec}" "${_sa_canon_pretty}" "${_sa_hash_spec}" "${_sa_hash_pretty}" "${_sa_sig_bin}"

------------------------------------------------------------------------
HUNK 2 — Manifest verification (around line 389)
------------------------------------------------------------------------

FIND:

        jq -S -c '.signature = {algorithm:"",value:"",key_id:""}' "${MANIFEST_FILE}" > "${_m_canon}" 2>/dev/null
        zlar_crypto_hash "${_m_canon}" "${_m_hash}"
        echo "${_manifest_sig}" | base64 -d > "${_m_sig_bin}" 2>/dev/null
        if ! zlar_crypto_verify "${POLICY_PUBKEY}" "${_m_hash}" "${_m_sig_bin}" "ed25519"; then
            _manifest_ok="false"
            echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [gate] CRITICAL: Manifest signature INVALID — manifest rejected" >> "${PROJECT_DIR}/var/log/gate.log" 2>/dev/null || true
            MANIFEST_HARD_DENY_REASON="manifest:tampered|Manifest signature INVALID — hard deny per invariant 8"
        fi
        rm -f "${_m_canon}" "${_m_hash}" "${_m_sig_bin}"

REPLACE WITH:

        # Phase B of ADR-011 — dual canonical form verification.
        # Spec form (compact sorted, NO trailing newline) OR legacy
        # bash-pipeline form (compact sorted, trailing newline).
        _m_canon_spec=$(mktemp "${GATE_TMP}/m-canon-spec.XXXXXX")
        _m_canon_pipe=$(mktemp "${GATE_TMP}/m-canon-pipe.XXXXXX")
        _m_hash_spec=$(mktemp "${GATE_TMP}/m-hash-spec.XXXXXX")
        _m_hash_pipe=$(mktemp "${GATE_TMP}/m-hash-pipe.XXXXXX")

        jq -S -c '.signature = {algorithm:"",value:"",key_id:""}' "${MANIFEST_FILE}" | tr -d '\n' > "${_m_canon_spec}" 2>/dev/null
        zlar_crypto_hash "${_m_canon_spec}" "${_m_hash_spec}"

        jq -S -c '.signature = {algorithm:"",value:"",key_id:""}' "${MANIFEST_FILE}" > "${_m_canon_pipe}" 2>/dev/null
        zlar_crypto_hash "${_m_canon_pipe}" "${_m_hash_pipe}"

        echo "${_manifest_sig}" | base64 -d > "${_m_sig_bin}" 2>/dev/null

        _m_verified=""
        if zlar_crypto_verify "${POLICY_PUBKEY}" "${_m_hash_spec}" "${_m_sig_bin}" "ed25519"; then
            _m_verified="spec"
        elif zlar_crypto_verify "${POLICY_PUBKEY}" "${_m_hash_pipe}" "${_m_sig_bin}" "ed25519"; then
            _m_verified="bash-pipeline"
            echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [gate] WARN: Manifest verified under LEGACY canonical form bash-pipeline (ADR-011)" >> "${PROJECT_DIR}/var/log/gate.log" 2>/dev/null || true
        fi

        rm -f "${_m_canon_spec}" "${_m_canon_pipe}" "${_m_hash_spec}" "${_m_hash_pipe}" "${_m_sig_bin}"

        if [ -z "${_m_verified}" ]; then
            _manifest_ok="false"
            echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [gate] CRITICAL: Manifest signature INVALID — manifest rejected" >> "${PROJECT_DIR}/var/log/gate.log" 2>/dev/null || true
            MANIFEST_HARD_DENY_REASON="manifest:tampered|Manifest signature INVALID — hard deny per invariant 8"
        fi

------------------------------------------------------------------------
HUNK 3 — Policy verification (around line 1231)
------------------------------------------------------------------------

FIND:

        # Private temp files (not world-readable /tmp)
        local canon_file hash_file sig_file
        canon_file=$(mktemp "${GATE_TMP}/canon.XXXXXX")
        hash_file=$(mktemp "${GATE_TMP}/hash.XXXXXX")
        sig_file=$(mktemp "${GATE_TMP}/sig.XXXXXX")

        jq '.signature.value = ""' "${POLICY_FILE}" > "${canon_file}" 2>/dev/null
        zlar_crypto_hash "${canon_file}" "${hash_file}"
        echo "${sig_value}" | base64 -d > "${sig_file}" 2>/dev/null

        # Verify using the algorithm declared in the policy file
        if ! zlar_crypto_verify "${POLICY_PUBKEY}" "${hash_file}" "${sig_file}" "${sig_algo}"; then
            rm -f "${canon_file}" "${hash_file}" "${sig_file}"
            log "FATAL: Policy signature INVALID"
            return 1
        fi
        rm -f "${canon_file}" "${hash_file}" "${sig_file}"
    }

REPLACE WITH:

        # Private temp files (not world-readable /tmp).
        # Phase B of ADR-011 — multi-canonical-form verification.
        # Accept spec form (compact sorted, no trailing newline, matches
        # lib/canonicalize.mjs) OR bash-pretty legacy form (plain jq
        # pretty-printed with trailing newline) during the migration.
        # New signatures are produced under spec form by zlar-policy sign.
        local canon_spec canon_pretty hash_spec hash_pretty sig_file
        canon_spec=$(mktemp "${GATE_TMP}/canon-spec.XXXXXX")
        canon_pretty=$(mktemp "${GATE_TMP}/canon-pretty.XXXXXX")
        hash_spec=$(mktemp "${GATE_TMP}/hash-spec.XXXXXX")
        hash_pretty=$(mktemp "${GATE_TMP}/hash-pretty.XXXXXX")
        sig_file=$(mktemp "${GATE_TMP}/sig.XXXXXX")

        jq -S -c '.signature.value = ""' "${POLICY_FILE}" | tr -d '\n' > "${canon_spec}" 2>/dev/null
        zlar_crypto_hash "${canon_spec}" "${hash_spec}"

        jq '.signature.value = ""' "${POLICY_FILE}" > "${canon_pretty}" 2>/dev/null
        zlar_crypto_hash "${canon_pretty}" "${hash_pretty}"

        echo "${sig_value}" | base64 -d > "${sig_file}" 2>/dev/null

        local _policy_verified=""
        if zlar_crypto_verify "${POLICY_PUBKEY}" "${hash_spec}" "${sig_file}" "${sig_algo}"; then
            _policy_verified="spec"
        elif zlar_crypto_verify "${POLICY_PUBKEY}" "${hash_pretty}" "${sig_file}" "${sig_algo}"; then
            _policy_verified="bash-pretty"
            log "WARN: Policy signature verified under LEGACY canonical form bash-pretty (ADR-011)"
        fi

        rm -f "${canon_spec}" "${canon_pretty}" "${hash_spec}" "${hash_pretty}" "${sig_file}"

        if [ -z "${_policy_verified}" ]; then
            log "FATAL: Policy signature INVALID (tried spec and bash-pretty canonical forms)"
            return 1
        fi
    }

------------------------------------------------------------------------
HUNK 4 — Constitution verification (around line 1094)
------------------------------------------------------------------------

FIND:

    local _c_canon _c_hash _c_sig
    _c_canon=$(mktemp "${GATE_TMP}/c-canon.XXXXXX")
    _c_hash=$(mktemp "${GATE_TMP}/c-hash.XXXXXX")
    _c_sig=$(mktemp "${GATE_TMP}/c-sig.XXXXXX")
    jq '.signature.value = ""' "${CONSTITUTION_FILE}" > "${_c_canon}" 2>/dev/null
    zlar_crypto_hash "${_c_canon}" "${_c_hash}"
    echo "${_c_sig_value}" | base64 -d > "${_c_sig}" 2>/dev/null
    if ! zlar_crypto_verify "${CONSTITUTION_PUBKEY}" "${_c_hash}" "${_c_sig}" "${_c_sig_algo}"; then
        rm -f "${_c_canon}" "${_c_hash}" "${_c_sig}"
        log "FATAL: Constitution signature INVALID"
        return 1
    fi
    rm -f "${_c_canon}" "${_c_hash}" "${_c_sig}"

REPLACE WITH:

    # Phase B of ADR-011 — dual canonical form verification.
    local _c_canon_spec _c_canon_pretty _c_hash_spec _c_hash_pretty _c_sig
    _c_canon_spec=$(mktemp "${GATE_TMP}/c-canon-spec.XXXXXX")
    _c_canon_pretty=$(mktemp "${GATE_TMP}/c-canon-pretty.XXXXXX")
    _c_hash_spec=$(mktemp "${GATE_TMP}/c-hash-spec.XXXXXX")
    _c_hash_pretty=$(mktemp "${GATE_TMP}/c-hash-pretty.XXXXXX")
    _c_sig=$(mktemp "${GATE_TMP}/c-sig.XXXXXX")

    jq -S -c '.signature.value = ""' "${CONSTITUTION_FILE}" | tr -d '\n' > "${_c_canon_spec}" 2>/dev/null
    zlar_crypto_hash "${_c_canon_spec}" "${_c_hash_spec}"

    jq '.signature.value = ""' "${CONSTITUTION_FILE}" > "${_c_canon_pretty}" 2>/dev/null
    zlar_crypto_hash "${_c_canon_pretty}" "${_c_hash_pretty}"

    echo "${_c_sig_value}" | base64 -d > "${_c_sig}" 2>/dev/null

    local _c_verified=""
    if zlar_crypto_verify "${CONSTITUTION_PUBKEY}" "${_c_hash_spec}" "${_c_sig}" "${_c_sig_algo}"; then
        _c_verified="spec"
    elif zlar_crypto_verify "${CONSTITUTION_PUBKEY}" "${_c_hash_pretty}" "${_c_sig}" "${_c_sig_algo}"; then
        _c_verified="bash-pretty"
        log "WARN: Constitution signature verified under LEGACY canonical form bash-pretty (ADR-011)"
    fi

    rm -f "${_c_canon_spec}" "${_c_canon_pretty}" "${_c_hash_spec}" "${_c_hash_pretty}" "${_c_sig}"

    if [ -z "${_c_verified}" ]; then
        log "FATAL: Constitution signature INVALID (tried spec and bash-pretty canonical forms)"
        return 1
    fi

------------------------------------------------------------------------
Post-application checklist
------------------------------------------------------------------------

[ ] bash -n bin/zlar-gate
[ ] Restart MCP gate; tail -f var/log/gate.log during startup
[ ] Expect: four "WARN: ... LEGACY canonical form bash-pretty/bash-pipeline" lines (policy, standing-approvals, manifest, constitution) — these are correct until Phase B' re-signs under spec form
[ ] Gate listens and accepts tool calls normally

If you see FATAL: Signature INVALID on any of the four verifiers, stop and check:
 - The hunk was pasted exactly (jq invocation, tr -d '\n', filenames)
 - The corresponding etc/keys/*.pub file exists
 - The deployed artifact has a .signature.value

Deferred to Phase B' (future session — chain-affecting):
 - bin/zlar-gate receipt signing pipeline (line ~694)
 - bin/zlar-gate audit entry signing (line ~793)
 - Re-signing deployed policy and constitution under spec form via zlar-policy sign / zlar-constitution sign (those tools now emit spec form after this Phase B commit)

Deferred to its own session (amendment ceremony):
 - bin/zlar-constitution amendment propose/ratify/withdraw signing paths (lines 1049, 1089, 1355)
