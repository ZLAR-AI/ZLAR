#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# ZLAR Cross-Gate Differential Test — Bash evaluator
#
# Evaluates a single fixture against the bash gate's policy evaluation logic.
# Called by test-cross-gate-differential.mjs per fixture.
#
# Args: $1 = domain, $2 = detail JSON, $3 = policy file path
# Stdout: {"rule":"...","action":"..."} JSON
# ─────────────────────────────────────────────────────────────────────────────

set -uo pipefail

domain="$1"
detail="$2"
policy_file="$3"

POLICY_DEFAULT_ACTION=$(jq -r '.default_action // "deny"' "${policy_file}" 2>/dev/null)
POLICY_RULES_JSON=$(jq -c '.rules' "${policy_file}" 2>/dev/null)

# ── match_detail_field (mirrors bin/zlar-gate exactly) ───────────────────────
match_detail_field() {
    local actual_value="$1"
    local matcher_json="$2"
    local val

    val=$(echo "${matcher_json}" | jq -r '.regex // empty' 2>/dev/null)
    if [ -n "${val}" ]; then
        if echo "${actual_value}" | grep -qE "${val}" 2>/dev/null; then return 0; fi
        return 1
    fi

    val=$(echo "${matcher_json}" | jq -r '.contains // empty' 2>/dev/null)
    if [ -n "${val}" ]; then
        if echo "${actual_value}" | grep -qF "${val}" 2>/dev/null; then return 0; fi
        return 1
    fi

    val=$(echo "${matcher_json}" | jq -r '.prefix // empty' 2>/dev/null)
    if [ -n "${val}" ]; then
        if [[ "${actual_value}" == "${val}"* ]]; then return 0; fi
        return 1
    fi

    val=$(echo "${matcher_json}" | jq -r '.eq // empty' 2>/dev/null)
    if [ -n "${val}" ]; then
        if [ "${actual_value}" = "${val}" ]; then return 0; fi
        return 1
    fi

    val=$(echo "${matcher_json}" | jq -r '.not_regex // empty' 2>/dev/null)
    if [ -n "${val}" ]; then
        if echo "${actual_value}" | grep -qE "${val}" 2>/dev/null; then return 1; fi
        return 0
    fi

    return 1
}

# ── _set_matched (mirrors bin/zlar-gate exactly) ──────────────────────────────
MATCHED_RULE=""
MATCHED_ACTION=""

_set_matched() {
    local rule="$1"
    MATCHED_RULE=$(echo "${rule}" | jq -r '.id // "unknown"' 2>/dev/null)
    MATCHED_ACTION=$(echo "${rule}" | jq -r '.action // "deny"' 2>/dev/null)
}

# ── evaluate_policy (mirrors bin/zlar-gate exactly) ───────────────────────────
evaluate_policy() {
    local dom="$1"
    local det="$2"

    MATCHED_RULE=""
    MATCHED_ACTION=""

    local rule_count
    rule_count=$(echo "${POLICY_RULES_JSON}" | jq 'length' 2>/dev/null || echo 0)

    local i=0
    while [ "${i}" -lt "${rule_count}" ]; do
        local rule
        rule=$(echo "${POLICY_RULES_JSON}" | jq -c ".[${i}]" 2>/dev/null)

        local enabled
        enabled=$(echo "${rule}" | jq -r '.enabled // true' 2>/dev/null)
        if [ "${enabled}" = "false" ]; then i=$((i + 1)); continue; fi

        local rule_domain
        rule_domain=$(echo "${rule}" | jq -r '.domain // ""' 2>/dev/null)
        if [ -n "${rule_domain}" ] && [ "${rule_domain}" != "${dom}" ]; then
            i=$((i + 1)); continue
        fi

        local match_json
        match_json=$(echo "${rule}" | jq -c '.match // {}' 2>/dev/null)

        # Domain-only catch-all (bash gate lines 1344-1353)
        local match_domain_only
        match_domain_only=$(echo "${match_json}" | jq -r '.domain // empty' 2>/dev/null)
        if [ -n "${match_domain_only}" ] && [ "${match_domain_only}" = "${dom}" ]; then
            local has_detail
            has_detail=$(echo "${match_json}" | jq 'has("detail")' 2>/dev/null)
            if [ "${has_detail}" != "true" ]; then
                _set_matched "${rule}"
                printf '{"rule":"%s","action":"%s"}\n' "${MATCHED_RULE}" "${MATCHED_ACTION}"
                return 0
            fi
        fi

        # Detail matchers
        local has_detail
        has_detail=$(echo "${match_json}" | jq 'has("detail")' 2>/dev/null)
        if [ "${has_detail}" = "true" ]; then
            local detail_match_json
            detail_match_json=$(echo "${match_json}" | jq -c '.detail' 2>/dev/null)
            local all_matched="true"

            local fields
            fields=$(echo "${detail_match_json}" | jq -r 'keys[]' 2>/dev/null)
            for field in ${fields}; do
                local actual_value matcher_json_field
                actual_value=$(echo "${det}" | jq -r --arg f "${field}" '.[$f] // ""' 2>/dev/null)
                matcher_json_field=$(echo "${detail_match_json}" | jq -c --arg f "${field}" '.[$f]' 2>/dev/null)

                if ! match_detail_field "${actual_value}" "${matcher_json_field}"; then
                    all_matched="false"
                    break
                fi
            done

            if [ "${all_matched}" = "true" ]; then
                # compound_guard check
                local has_guard
                has_guard=$(echo "${match_json}" | jq 'has("compound_guard")' 2>/dev/null)
                if [ "${has_guard}" = "true" ]; then
                    local guard_json guard_passed="true"
                    guard_json=$(echo "${match_json}" | jq -c '.compound_guard' 2>/dev/null)
                    local guard_fields
                    guard_fields=$(echo "${guard_json}" | jq -r 'keys[]' 2>/dev/null)
                    for gfield in ${guard_fields}; do
                        local gval gmatcher
                        gval=$(echo "${det}" | jq -r --arg f "${gfield}" '.[$f] // ""' 2>/dev/null)
                        gmatcher=$(echo "${guard_json}" | jq -c --arg f "${gfield}" '.[$f]' 2>/dev/null)
                        if ! match_detail_field "${gval}" "${gmatcher}"; then
                            guard_passed="false"; break
                        fi
                    done
                    if [ "${guard_passed}" = "false" ]; then i=$((i + 1)); continue; fi
                fi

                _set_matched "${rule}"
                printf '{"rule":"%s","action":"%s"}\n' "${MATCHED_RULE}" "${MATCHED_ACTION}"
                return 0
            fi
        fi

        i=$((i + 1))
    done

    printf '{"rule":"default","action":"%s"}\n' "${POLICY_DEFAULT_ACTION}"
    return 0
}

evaluate_policy "${domain}" "${detail}"
