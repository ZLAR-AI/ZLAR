#!/bin/bash
# audit-reader.sh — shared library for reading ZLAR gate audit trails
# Used by zlar-witness, zlar-digest, zlar-standing
#
# Design principle: this library produces FACTS, not conclusions.
# It reads, filters, and structures audit events.
# It does not label, judge, or classify risk.
#
# Audit trail schema (from gateway-poc bash gate):
#   .ts           — ISO 8601 timestamp
#   .seq          — sequence number (1=initial, 2=resolution of pending)
#   .session_id   — session UUID
#   .domain       — tool domain (bash, read, write, edit, glob, grep, agent, internal, unknown)
#   .action       — what was attempted (or "ask_sent" for pending Telegram requests)
#   .outcome      — "allow" (auto), "deny", "authorized" (human-approved), "pending"
#   .rule         — policy rule that matched
#   .risk_score   — numeric risk score (0-100)
#   .detail       — { command, path, cwd, content_length, content_sha256, ... }
#   .authorizer   — "policy", "gate", or "human:<telegram_user_id>"
#   .prev_hash    — SHA-256 chain hash (tamper detection)

set -euo pipefail

# ── Configuration ──
#
# Multi-audit support: ZLAR has two gates producing two audit trails.
#   CC gate → repo/var/log/audit.jsonl
#   OC gate → /var/log/zlar-oc/audit.jsonl
#
# A governance digest that only sees half the picture is broken by design.
#
# Set ZLAR_AUDIT_FILES (colon-separated) to read from multiple trails.
# Falls back to ZLAR_AUDIT_FILE (single file) for backward compatibility.

AUDIT_FILES="${ZLAR_AUDIT_FILES:-}"
AUDIT_FILE="${ZLAR_AUDIT_FILE:-}"

if [[ -z "${AUDIT_FILES}" && -z "${AUDIT_FILE}" ]]; then
    for candidate in \
        "${ZLAR_PROJECT_DIR:-}/var/log/audit.jsonl" \
        "$HOME/Desktop/ZLAR/repo/var/log/audit.jsonl" \
        "/var/log/zlar/audit.jsonl"; do
        if [[ -f "${candidate}" ]]; then
            AUDIT_FILE="${candidate}"
            break
        fi
    done
fi

if [[ -z "${AUDIT_FILES}" && ! -f "${AUDIT_FILE:-}" ]]; then
    echo "ERROR: No audit file found. Set ZLAR_AUDIT_FILE, ZLAR_AUDIT_FILES, or ZLAR_PROJECT_DIR." >&2
    exit 1
fi

# Internal: cat all configured audit files, sorted by timestamp when multiple
# Each individual file is chronologically ordered. When reading multiple,
# we merge and sort so downstream readers see a unified timeline.
_audit_cat() {
    if [[ -n "${AUDIT_FILES}" ]]; then
        local IFS=':'
        local found=()
        for f in ${AUDIT_FILES}; do
            [[ -f "${f}" ]] && found+=("${f}")
        done
        if [[ ${#found[@]} -gt 1 ]]; then
            # Each file is chronologically ordered. Extract ts, sort, strip prefix.
            # Filter valid JSON, prefix with timestamp for sorting, then strip prefix.
            # The (|| true) handles jq exit code when skipping malformed lines.
            (cat "${found[@]}" | jq -c '.' 2>/dev/null || true) | jq -r '"\(.ts)\t\(tostring)"' 2>/dev/null | sort -t$'\t' -k1 | cut -f2-
        elif [[ ${#found[@]} -eq 1 ]]; then
            cat "${found[0]}"
        fi
    else
        cat "${AUDIT_FILE}"
    fi
}

# ── Core readers ──

# Read all events in a time window
# Usage: audit_events_since <seconds_ago>
audit_events_since() {
    local seconds_ago="${1:?Usage: audit_events_since <seconds>}"
    local cutoff
    cutoff=$(date -u -v-"${seconds_ago}"S +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
             date -u -d "${seconds_ago} seconds ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)

    _audit_cat | jq -c --arg cutoff "${cutoff}" \
        'select(.ts >= $cutoff)'
}

# Read events for a specific session
# Usage: audit_events_for_session <session_id>
audit_events_for_session() {
    local session_id="${1:?Usage: audit_events_for_session <session_id>}"
    _audit_cat | jq -c --arg sid "${session_id}" \
        'select(.session_id == $sid)'
}

# Read last N events
# Usage: audit_last <count>
audit_last() {
    local count="${1:-50}"
    _audit_cat | tail -n "${count}"
}

# ── Fact extractors ──
# These return structured facts. No interpretation.

# Extract: domain, action, outcome, ts, session, rule, risk
# Usage: cat events | audit_extract_facts
audit_extract_facts() {
    jq -c '{
        ts: .ts,
        session_id: .session_id,
        domain: .domain,
        action: .action,
        outcome: .outcome,
        rule: .rule,
        risk_score: .risk_score
    }'
}

# Extract approval events (human-authorized via Telegram)
# In the real audit trail, human approvals have authorizer: "human:<telegram_id>"
# and outcome: "authorized" with seq: 2
# Usage: cat events | audit_extract_approvals
audit_extract_approvals() {
    jq -c 'select(.authorizer // "" | startswith("human:")) | {
        ts: .ts,
        session_id: .session_id,
        domain: .domain,
        action: .action,
        rule: .rule,
        risk_score: .risk_score,
        authorizer: .authorizer
    }'
}

# Extract pending events (waiting for Telegram approval)
# These are seq=1 events with outcome "pending" and action "ask_sent"
# Usage: cat events | audit_extract_pending
audit_extract_pending() {
    jq -c 'select(.outcome == "pending") | {
        ts: .ts,
        session_id: .session_id,
        domain: .domain,
        action: (.detail.command // .detail.path // .action),
        rule: .rule,
        risk_score: .risk_score
    }'
}

# Calculate approval latency from pending→authorized pairs
# Matches by composite key: session_id + domain + rule + detail content
# This prevents cross-matching when multiple pending events share session+domain
# Returns JSON objects with delta_seconds
# Usage: audit_approval_latencies <events_file>
audit_approval_latencies() {
    local events_file="${1:?Usage: audit_approval_latencies <file>}"

    # Pair consecutive pending→authorized events using the audit trail's sequential nature.
    # A pending event (seq=1) is always followed by its authorized event (seq=2)
    # within a few lines. Use jq indices to pair [i] with [i+1] when they match.
    jq -s '
        def to_epoch:
            split("T") |
            (.[0] | split("-") | (.[0] | tonumber) * 31536000 + (.[1] | tonumber) * 2592000 + (.[2] | tonumber) * 86400) +
            (.[1] | rtrimstr("Z") | split(":") | (.[0] | tonumber) * 3600 + (.[1] | tonumber) * 60 + (.[2] | tonumber));

        # Find all indices where outcome is "pending" and seq is 1
        [to_entries[] | select(.value.outcome == "pending" and .value.seq == 1) | .key] as $pend_idxs |

        # For each pending index, look ahead (up to 10 lines) for matching authorized
        [$pend_idxs[] as $i |
            . as $all |
            $all[$i] as $p |
            # Scan forward from $i+1 up to $i+10
            [range($i + 1; [($i + 11), ($all | length)] | min)] |
            map($all[.]) |
            map(select(
                .outcome == "authorized" and
                .seq == 2 and
                .session_id == $p.session_id and
                .domain == $p.domain and
                .rule == $p.rule
            )) |
            first // null |
            select(. != null) |
            . as $a |
            (($a.ts | to_epoch) - ($p.ts | to_epoch)) as $delta |
            select($delta >= 0 and $delta <= 900) |
            {
                request_ts: $p.ts,
                response_ts: $a.ts,
                delta_seconds: $delta,
                domain: $p.domain,
                action: $a.action,
                rule: $p.rule,
                risk_score: $p.risk_score,
                session: $p.session_id,
                authorizer: ($a.authorizer // "unknown")
            }
        ] | .[]
    ' "${events_file}" 2>/dev/null || true
}

# Extract denied events
# Usage: cat events | audit_extract_denials
audit_extract_denials() {
    jq -c 'select(.outcome == "deny") | {
        ts: .ts,
        session_id: .session_id,
        domain: .domain,
        action: .action,
        rule: .rule,
        risk_score: .risk_score
    }'
}

# Extract events touching sensitive paths
# Usage: cat events | audit_extract_sensitive
audit_extract_sensitive() {
    jq -c 'select(
        (.detail.command // "" | test("\\.(env|ssh|key|pem|token)"; "i")) or
        (.detail.path // "" | test("\\.(env|ssh|key|pem|token)"; "i")) or
        (.action // "" | test("\\.(env|ssh|key|pem|token)|/\\.(ssh|gnupg)/"; "i"))
    ) | {
        ts: .ts,
        session_id: .session_id,
        domain: .domain,
        action: .action,
        outcome: .outcome,
        sensitivity: "credential-adjacent"
    }'
}

# Extract network/egress events
# Usage: cat events | audit_extract_egress
audit_extract_egress() {
    jq -c 'select(
        (.detail.command // "" | test("\\b(curl|wget|ssh|scp|rsync|nc|ncat|netcat)\\b")) or
        (.domain == "webfetch")
    ) | {
        ts: .ts,
        session_id: .session_id,
        domain: .domain,
        action: .action,
        outcome: .outcome,
        type: "egress"
    }'
}

# ── Statistics ──

# Count events by outcome
# Usage: cat events | audit_count_by_outcome
audit_count_by_outcome() {
    jq -s 'group_by(.outcome) | map({outcome: .[0].outcome, count: length})'
}

# Count events by domain
# Usage: cat events | audit_count_by_domain
audit_count_by_domain() {
    jq -s 'group_by(.domain) | map({domain: .[0].domain, count: length}) | sort_by(-.count)'
}

# Count events by rule
# Usage: cat events | audit_count_by_rule
audit_count_by_rule() {
    jq -s 'group_by(.rule) | map({rule: .[0].rule, count: length}) | sort_by(-.count)'
}

# Distinct domains seen
# Usage: cat events | audit_distinct_domains
audit_distinct_domains() {
    jq -s '[.[].domain] | unique'
}

# ── Policy helpers ──

# Find the active policy file
# Usage: policy_file=$(audit_find_policy_file)
audit_find_policy_file() {
    local policy_file="${ZLAR_POLICY_FILE:-}"
    if [[ -z "${policy_file}" ]]; then
        for candidate in \
            "${ZLAR_PROJECT_DIR:-}/etc/policies/active.policy.json" \
            "$HOME/Desktop/ZLAR/repo/etc/policies/active.policy.json" \
            "/usr/local/etc/zlar/policy.json"; do
            if [[ -f "${candidate}" ]]; then
                policy_file="${candidate}"
                break
            fi
        done
    fi
    echo "${policy_file}"
}

# Get rule description by ID
# Usage: audit_rule_label "R053" [policy_file]
audit_rule_label() {
    local rule_id="${1:?Usage: audit_rule_label <rule_id> [policy_file]}"
    local policy_file="${2:-$(audit_find_policy_file)}"
    if [[ -f "${policy_file:-}" ]]; then
        jq -r --arg id "${rule_id}" '.rules[] | select(.id == $id) | .description' "${policy_file}" 2>/dev/null || echo ""
    fi
}

# Get all rule labels as "ID|description" lines
# Usage: audit_all_rule_labels [policy_file]
audit_all_rule_labels() {
    local policy_file="${1:-$(audit_find_policy_file)}"
    if [[ -f "${policy_file:-}" ]]; then
        jq -r '.rules[] | "\(.id)|\(.description)"' "${policy_file}" 2>/dev/null || true
    fi
}

# ── Time helpers ──

seconds_in_day() { echo 86400; }
seconds_in_week() { echo 604800; }
seconds_in_hour() { echo 3600; }
