#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# ZLAR — Preflight classifier regression
#
# Verifies bin/zlar-classify returns the expected {rule_id, action} for a
# small fixture set spanning bash, write, edit, read, and mcp domains.
#
# Also documents the bin/zlar coverage gap (G-1) by asserting R042 allow on
# Edit to bin/zlar — so any future tightening of that gap will trip this test
# and force a deliberate spec update.
#
# Usage: bash tests/test-zlar-classify.sh
# Spec:  docs/operator-loop.md
# ─────────────────────────────────────────────────────────────────────────────

set -uo pipefail

PROJECT_DIR="$(cd -P "$(dirname "$0")/.." && pwd)"
CLASSIFY="${PROJECT_DIR}/bin/zlar-classify"

PASS=0
FAIL=0

assert_classify() {
    local desc="$1"
    local input="$2"
    local want_rule="$3"
    local want_action="$4"

    local out
    out=$(printf '%s' "${input}" | bash "${CLASSIFY}" 2>&1)
    local rc=$?
    if [ "${rc}" -ne 0 ]; then
        FAIL=$((FAIL + 1))
        echo "  FAIL: ${desc}"
        echo "        classifier exit code ${rc}"
        echo "        output: ${out}"
        return
    fi

    local got_rule got_action
    got_rule=$(echo "${out}" | jq -r '.rule_id // ""')
    got_action=$(echo "${out}" | jq -r '.action // ""')

    if [ "${got_rule}" = "${want_rule}" ] && [ "${got_action}" = "${want_action}" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: ${desc}"
        echo "        want rule=${want_rule} action=${want_action}"
        echo "        got  rule=${got_rule}  action=${got_action}"
        echo "        full: ${out}"
    fi
}

echo "═══════════════════════════════════════════════════════════════"
echo "  ZLAR Preflight Classifier Regression"
echo "═══════════════════════════════════════════════════════════════"

assert_classify "Bash rm -rf → R002 deny" \
    '{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/test","cwd":""}}' \
    "R002" "deny"

assert_classify "Bash sudo → R003 deny" \
    '{"tool_name":"Bash","tool_input":{"command":"sudo ls /etc","cwd":""}}' \
    "R003" "deny"

assert_classify "Write docs/ → R032E ask" \
    '{"tool_name":"Write","tool_input":{"file_path":"/Users/x/Desktop/ZLAR/ZLAR_Repo/docs/new.md","content":"hi"}}' \
    "R032E" "ask"

assert_classify "Edit docs/ → R041E ask" \
    '{"tool_name":"Edit","tool_input":{"file_path":"/Users/x/Desktop/ZLAR/ZLAR_Repo/docs/new.md","old_string":"a","new_string":"b"}}' \
    "R041E" "ask"

# Documents coverage gap G-1: Edit on bin/zlar falls through to R042 catch-all.
# If this assertion ever flips to a deny/ask rule, G-1 has been closed —
# update docs/operator-loop.md G-1 section accordingly.
assert_classify "Edit bin/zlar → R042 allow (G-1 coverage gap)" \
    '{"tool_name":"Edit","tool_input":{"file_path":"/Users/x/Desktop/ZLAR/ZLAR_Repo/bin/zlar","old_string":"a","new_string":"b"}}' \
    "R042" "allow"

# Documents the Write-side mirror of G-1: Write to bin/zlar-classify also
# falls through to R036 catch-all.
assert_classify "Write bin/zlar-classify (under Desktop) → R035 allow (write-side mirror of G-1)" \
    '{"tool_name":"Write","tool_input":{"file_path":"/Users/x/Desktop/ZLAR/ZLAR_Repo/bin/zlar-classify","content":"#!/bin/bash"}}' \
    "R035" "allow"

assert_classify "Read /tmp file → R053 allow (read catch-all)" \
    '{"tool_name":"Read","tool_input":{"file_path":"/tmp/x"}}' \
    "R053" "allow"

assert_classify "MCP arbitrary tool → R095 allow" \
    '{"tool_name":"mcp__some_server__some_tool","tool_input":{}}' \
    "R095" "allow"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "═══════════════════════════════════════════════════════════════"

if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
exit 0
