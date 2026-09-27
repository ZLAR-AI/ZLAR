#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# count-assertions.sh — Source of truth for the "X+ assertions" README badge.
#
# Runs every current-active test file in the repository, records the reviewed
# authority-inactive historical inventory as skipped, parses the "passed" count
# from each active results line, and prints a total. This is the ONLY way the
# badge number is considered authoritative — grep-based static counts drift and
# undercount.
#
# Usage:
#   bash tests/count-assertions.sh                 # run current-active tests
#   bash tests/count-assertions.sh --detail        # also show per-file counts
#   bash tests/count-assertions.sh --badge         # print a shields.io badge URL
#
# Exit:
#   0 if all tests pass
#   1 if any test fails (the total is still printed)
#   77 if a required tool (node, openssl-ed25519) is missing (tests are skipped)
#
# Requirements: bash 3.2+, jq, openssl with Ed25519 support, node (optional —
# .mjs test files are counted only if node is on PATH).
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
AUTHORITY_INACTIVE_TEST_SUITES="${SCRIPT_DIR}/authority-inactive-test-suites.txt"
SUPERSEDED_SOURCE_BOUND_TEST_SUITES="${SCRIPT_DIR}/superseded-source-bound-test-suites.txt"
RETIRED_POSITIVE_GENERATOR_TEST_SUITES="${SCRIPT_DIR}/retired-positive-generator-test-suites.txt"
RETIRED_DIRECT_E2_TEST_SUITES="${SCRIPT_DIR}/retired-direct-e2-test-suites.txt"
RETIRED_DIRECT_E1_TEST_SUITES="${SCRIPT_DIR}/retired-direct-e1-test-suites.txt"
REQUIRES_PRIVATE_HISTORY_TEST_SUITES="${SCRIPT_DIR}/requires-private-history-test-suites.txt"
cd "${REPO_ROOT}"

DETAIL=0
BADGE=0
for arg in "$@"; do
    case "$arg" in
        --detail) DETAIL=1 ;;
        --badge)  BADGE=1  ;;
        -h|--help)
            sed -n '2,22p' "$0"
            exit 0
            ;;
    esac
done

TOTAL_FILES=0
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
FAILED_FILES=""

# Node availability for .mjs tests
HAS_NODE=0
if command -v node >/dev/null 2>&1; then
    HAS_NODE=1
fi

# Parse a test output for "X passed" / "passed: X" style count lines.
# Different test files use different result formats — this handles all of them.
extract_pass_count() {
    local output="$1"
    # Try several formats in order of specificity:
    # "Results: X/Y passed"
    # "Results: X passed, Y failed"
    # "X passed, Y failed out of Z tests"
    # "X/Y passed, Z failed"
    local n fraction passed total
    n=$(echo "$output" | grep -E "Results: [0-9]+/[0-9]+ passed" | tail -1 | grep -oE "[0-9]+/[0-9]+" | head -1 | cut -d/ -f1)
    [ -n "$n" ] && { echo "$n"; return; }
    n=$(echo "$output" | grep -E "Results: [0-9]+ passed" | tail -1 | grep -oE "[0-9]+" | head -1)
    [ -n "$n" ] && { echo "$n"; return; }
    n=$(echo "$output" | grep -E "^[0-9]+ passed" | tail -1 | grep -oE "^[0-9]+")
    [ -n "$n" ] && { echo "$n"; return; }
    # "X/Y assertions passed" — accept only an exact all-pass fraction.
    fraction=$(echo "$output" | grep -E "[0-9]+/[0-9]+ assertions passed[[:space:]]*$" | tail -1 | grep -oE "[0-9]+/[0-9]+" | tail -1)
    if [ -n "$fraction" ]; then
        passed="${fraction%/*}"
        total="${fraction#*/}"
        [ "$passed" -eq "$total" ] && { echo "$passed"; return; }
    fi
    # Prefixed summary such as "suite: X passed, 0 failed".
    n=$(echo "$output" | grep -E "(^|: )[0-9]+ passed, 0 failed[[:space:]]*$" | tail -1 | grep -oE "[0-9]+ passed, 0 failed[[:space:]]*$" | grep -oE "^[0-9]+")
    [ -n "$n" ] && { echo "$n"; return; }
    n=$(echo "$output" | grep -E "[0-9]+/[0-9]+ passed" | tail -1 | grep -oE "[0-9]+/[0-9]+" | head -1 | cut -d/ -f1)
    [ -n "$n" ] && { echo "$n"; return; }
    # TAP format: "# pass 21" (node:test runner)
    n=$(echo "$output" | grep -E "^# pass [0-9]+" | tail -1 | grep -oE "[0-9]+")
    [ -n "$n" ] && { echo "$n"; return; }
    echo "0"
}

run_test() {
    local file="$1" runner="$2"
    TOTAL_FILES=$((TOTAL_FILES + 1))

    # Exact source-snapshot suites stop being live-current once a later
    # additive source disposition intentionally changes one of their pinned
    # files. Their artifacts and validators remain immutable historical
    # evidence; the new disposition suite verifies the exact identities and
    # requires old live-source reconstruction to refuse as drift.
    local base="${file##*/}"

    # These success-expecting suites target positive E1/E2 proof generators
    # retired in current source. They remain historical test source; current
    # replacement suites prove fixed refusal and historical verification
    # without effect execution.
    if [ -f "${RETIRED_POSITIVE_GENERATOR_TEST_SUITES}" ] && \
       grep -Fqx "${base}" "${RETIRED_POSITIVE_GENERATOR_TEST_SUITES}"; then
        TOTAL_SKIP=$((TOTAL_SKIP + 1))
        [ "$DETAIL" -eq 1 ] && printf "  SKIP  %-50s (retired positive generator suite)\n" "$file"
        return 0
    fi

    # These success-expecting suites generate keys/receipts and targeted the
    # direct E2 request/factory surfaces retired in current source. They remain
    # historical source and must not be unskipped as refusal tests.
    if [ -f "${RETIRED_DIRECT_E2_TEST_SUITES}" ] && \
       grep -Fqx "${base}" "${RETIRED_DIRECT_E2_TEST_SUITES}"; then
        TOTAL_SKIP=$((TOTAL_SKIP + 1))
        [ "$DETAIL" -eq 1 ] && printf "  SKIP  %-50s (retired direct E2 suite)\n" "$file"
        return 0
    fi

    # These success-expecting suites generate keys/receipts and targeted the
    # direct E1 adapter/factory surfaces retired in current source. They remain
    # historical source and must not be unskipped as refusal tests.
    if [ -f "${RETIRED_DIRECT_E1_TEST_SUITES}" ] && \
       grep -Fqx "${base}" "${RETIRED_DIRECT_E1_TEST_SUITES}"; then
        TOTAL_SKIP=$((TOTAL_SKIP + 1))
        [ "$DETAIL" -eq 1 ] && printf "  SKIP  %-50s (retired direct E1 suite)\n" "$file"
        return 0
    fi
    if [ -f "${SUPERSEDED_SOURCE_BOUND_TEST_SUITES}" ] && \
       grep -Fqx "${base}" "${SUPERSEDED_SOURCE_BOUND_TEST_SUITES}"; then
        TOTAL_SKIP=$((TOTAL_SKIP + 1))
        [ "$DETAIL" -eq 1 ] && printf "  SKIP  %-50s (superseded source snapshot)\n" "$file"
        return 0
    fi

    # These legacy success-expecting suites predate the exhausted one-use
    # fixture grant and, in several cases, artifact-bound grant-SHA schemas.
    # They remain historical source but are not current executable evidence.
    # A replacement grant does not reactivate them; a new versioned suite must
    # remove its own basename from the reviewed source inventory.
    if [ -f "${AUTHORITY_INACTIVE_TEST_SUITES}" ] && \
       grep -Fqx "${base}" "${AUTHORITY_INACTIVE_TEST_SUITES}"; then
        TOTAL_SKIP=$((TOTAL_SKIP + 1))
        [ "$DETAIL" -eq 1 ] && printf "  SKIP  %-50s (authority inactive)\n" "$file"
        return 0
    fi

    # These suites need material this public repository does not contain:
    # commits and tags from the private development history, or the
    # founder's private workspace folders next to the repository. See
    # tests/REQUIRES-PRIVATE-HISTORY-SUITES.md.
    if [ -f "${REQUIRES_PRIVATE_HISTORY_TEST_SUITES}" ] && \
       grep -Fqx "${base}" "${REQUIRES_PRIVATE_HISTORY_TEST_SUITES}"; then
        TOTAL_SKIP=$((TOTAL_SKIP + 1))
        [ "$DETAIL" -eq 1 ] && printf "  SKIP  %-50s (needs private history or workspace)\n" "$file"
        return 0
    fi

    # Allow CI (or any caller) to skip specific test files via the
    # ZLAR_SKIP_TESTS env var. The value is a colon-separated list of
    # test file basenames or paths. Skipped tests are counted as SKIP
    # and do not affect the failure tally. Use sparingly — this is for
    # tests that have known environment-specific issues, not for muting
    # real regressions. Document each skip in the workflow comment.
    if [ -n "${ZLAR_SKIP_TESTS:-}" ]; then
        case ":${ZLAR_SKIP_TESTS}:" in
            *":${file}:"*|*":${base}:"*)
                TOTAL_SKIP=$((TOTAL_SKIP + 1))
                [ "$DETAIL" -eq 1 ] && printf "  SKIP  %-50s (ZLAR_SKIP_TESTS)\n" "$file"
                return 0
                ;;
        esac
    fi

    local output ec
    output=$($runner "$file" 2>&1)
    ec=$?
    if [ "$ec" -eq 77 ]; then
        TOTAL_SKIP=$((TOTAL_SKIP + 1))
        [ "$DETAIL" -eq 1 ] && printf "  SKIP  %-50s (preflight)\n" "$file"
        return 0
    fi
    local pass
    pass=$(extract_pass_count "$output")
    if [ "$ec" -eq 0 ] && [ "$pass" -gt 0 ]; then
        TOTAL_PASS=$((TOTAL_PASS + pass))
        [ "$DETAIL" -eq 1 ] && printf "  %-4s  %-50s %d assertions\n" "OK" "$file" "$pass"
    else
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
        FAILED_FILES="${FAILED_FILES} ${file}"
        [ "$DETAIL" -eq 1 ] && printf "  %-4s  %-50s (exit=%d, parsed=%d)\n" "FAIL" "$file" "$ec" "$pass"
        # Print the tail of the failing test's output to the log so CI
        # runs (and anyone else using --detail) can see WHY the test
        # failed without re-running it in isolation. 30 lines is usually
        # enough to capture the failing assertion and the Results line
        # if one was produced.
        if [ "$DETAIL" -eq 1 ]; then
            printf "  ───── last 30 lines of %s output ─────\n" "$file"
            printf '%s\n' "$output" | tail -30 | sed 's/^/    /'
            printf "  ───── end %s output ─────\n" "$file"
        fi
    fi
}

[ "$DETAIL" -eq 1 ] && [ "$BADGE" -eq 0 ] && echo "Running all test files..."

# Bash test files
for t in tests/test-*.sh; do
    [ -f "$t" ] || continue
    run_test "$t" "bash"
done

# Node test files
if [ "$HAS_NODE" -eq 1 ]; then
    for t in tests/test-*.mjs mcp-gate/test*.mjs cedar-poc/test*.mjs sdk/*/test.mjs packages/*/tests/test*.mjs; do
        [ -f "$t" ] || continue
        run_test "$t" "node"
    done
else
    [ "$DETAIL" -eq 1 ] && [ "$BADGE" -eq 0 ] && echo "  (skipping .mjs tests — node not found on PATH)"
fi

# Python test files
if command -v python3 >/dev/null 2>&1; then
    for t in tests/*.py; do
        [ -f "$t" ] || continue
        run_test "$t" "python3"
    done
fi

if [ "$BADGE" -eq 1 ]; then
    # Emit a shields.io badge URL using the rounded-down total.
    # Floor to the nearest hundred to avoid churn on small changes.
    ROUNDED=$(( (TOTAL_PASS / 100) * 100 ))
    printf "https://img.shields.io/badge/tests-%d%%2B_assertions-brightgreen\n" "$ROUNDED"
    exit 0
fi

echo ""
echo "───────────────────────────────────────────────────"
printf "Files: %d   Assertions: %d   Failed: %d   Skipped: %d\n" \
    "$TOTAL_FILES" "$TOTAL_PASS" "$TOTAL_FAIL" "$TOTAL_SKIP"
echo "───────────────────────────────────────────────────"
if [ "$TOTAL_FAIL" -gt 0 ]; then
    echo "FAILED:${FAILED_FILES}"
    echo "Known failures on a fresh copy are listed in tests/KNOWN-FAILURES.md."
    echo "A failure not listed there is new."
    exit 1
fi
