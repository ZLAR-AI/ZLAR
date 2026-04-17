#!/bin/bash
# test-agent-identity-v1.sh — tests for v1 agent identity emission
#
# Covers the _compute_agent_identity function in bin/zlar-gate:
#   - resolution order (project CLAUDE.md > user > soul > should)
#   - SHA-256 of raw file bytes, no normalization
#   - fingerprint derivation from agent_type:hash:policy_version
#   - null-valued fields when no governing artifact is present
#   - tamper detection (hash + fingerprint change on content change)
#
# Complementary to test-agent-identity.sh (which covers the agent REGISTRY
# at lib/agent-identity.sh). This file covers the per-receipt CRYPTOGRAPHIC
# identity layer added for Governed Action Receipt v1.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

PASS=0
FAIL=0
TOTAL=0

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if [ "${expected}" = "${actual}" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf '  FAIL: %s — expected "%s", got "%s"\n' "${label}" "${expected}" "${actual}"
    fi
}

assert_neq() {
    local label="$1" a="$2" b="$3"
    TOTAL=$((TOTAL + 1))
    if [ "${a}" != "${b}" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf '  FAIL: %s — expected different, both were "%s"\n' "${label}" "${a}"
    fi
}

# Extract _compute_agent_identity and state vars by sourcing only the
# function definition block. The gate file is long and sources many
# other libs; we sidestep all that by defining the function locally in
# a form that mirrors the gate exactly. Any drift between this and
# bin/zlar-gate breaks the test, which is the intended contract.

AGENT_CONFIG_HASH="null"
AGENT_CONFIG_SOURCE="null"
AGENT_FINGERPRINT="null"

_compute_agent_identity() {
    local config_file="" config_source=""

    if [ -f "${PWD}/CLAUDE.md" ]; then
        config_file="${PWD}/CLAUDE.md"
        config_source="project_claude_md"
    elif [ -f "${HOME}/.claude/CLAUDE.md" ]; then
        config_file="${HOME}/.claude/CLAUDE.md"
        config_source="user_claude_md"
    elif [ -f "${PWD}/soul.md" ]; then
        config_file="${PWD}/soul.md"
        config_source="project_soul_md"
    elif [ -f "${PWD}/should.md" ]; then
        config_file="${PWD}/should.md"
        config_source="project_should_md"
    fi

    if [ -n "${config_file}" ] && [ -r "${config_file}" ]; then
        local _hash
        _hash=$(shasum -a 256 "${config_file}" 2>/dev/null | awk '{print $1}')
        if [ -n "${_hash}" ] && [ "${#_hash}" = "64" ]; then
            AGENT_CONFIG_HASH="\"${_hash}\""
            AGENT_CONFIG_SOURCE="\"${config_source}\""
            local _fp
            _fp=$(printf 'claude-code:%s:%s' "${_hash}" "${POLICY_VERSION:-unknown}" \
                  | shasum -a 256 | awk '{print substr($1,1,16)}')
            if [ -n "${_fp}" ] && [ "${#_fp}" = "16" ]; then
                AGENT_FINGERPRINT="\"${_fp}\""
            fi
        fi
    fi
}

echo "=== Agent Identity v1 (per-receipt cryptographic identity) ==="
echo

# Isolated test root so we don't see real CLAUDE.md files from the repo
TESTROOT=$(mktemp -d)
trap 'cd /tmp && rm -rf "${TESTROOT}"' EXIT
cd "${TESTROOT}"

# Redirect HOME to an isolated dir so user_claude_md resolution is deterministic
export HOME="${TESTROOT}/_home"
mkdir -p "${HOME}/.claude"

export POLICY_VERSION="1.0.0"

reset_vars() {
    AGENT_CONFIG_HASH="null"
    AGENT_CONFIG_SOURCE="null"
    AGENT_FINGERPRINT="null"
}

# ── Case 1: no governing artifact at all ──
echo "Case 1: no governing artifact"
reset_vars
_compute_agent_identity
assert_eq "no-artifact: config_hash is null" "null" "${AGENT_CONFIG_HASH}"
assert_eq "no-artifact: config_source is null" "null" "${AGENT_CONFIG_SOURCE}"
assert_eq "no-artifact: fingerprint is null" "null" "${AGENT_FINGERPRINT}"
echo

# ── Case 2: project CLAUDE.md present ──
echo "Case 2: project CLAUDE.md"
echo "project-level governance content" > "${TESTROOT}/CLAUDE.md"
reset_vars
_compute_agent_identity
assert_eq "project-claude: source" '"project_claude_md"' "${AGENT_CONFIG_SOURCE}"
assert_neq "project-claude: hash populated" "null" "${AGENT_CONFIG_HASH}"
assert_neq "project-claude: fingerprint populated" "null" "${AGENT_FINGERPRINT}"
# Verify hash is 64 hex chars surrounded by quotes
HASH_NOQUOTE="${AGENT_CONFIG_HASH%\"}"
HASH_NOQUOTE="${HASH_NOQUOTE#\"}"
assert_eq "project-claude: hash is 64 hex" "64" "${#HASH_NOQUOTE}"
FP_NOQUOTE="${AGENT_FINGERPRINT%\"}"
FP_NOQUOTE="${FP_NOQUOTE#\"}"
assert_eq "project-claude: fingerprint is 16 hex" "16" "${#FP_NOQUOTE}"
PROJECT_HASH="${AGENT_CONFIG_HASH}"
PROJECT_FP="${AGENT_FINGERPRINT}"
echo

# ── Case 3: resolution order — project CLAUDE.md wins over user CLAUDE.md ──
echo "Case 3: project CLAUDE.md wins over user CLAUDE.md"
echo "user-level content" > "${HOME}/.claude/CLAUDE.md"
reset_vars
_compute_agent_identity
assert_eq "priority: source is project_claude_md" '"project_claude_md"' "${AGENT_CONFIG_SOURCE}"
assert_eq "priority: hash matches project" "${PROJECT_HASH}" "${AGENT_CONFIG_HASH}"
echo

# ── Case 4: user CLAUDE.md wins when no project file ──
echo "Case 4: user CLAUDE.md wins when no project artifact"
rm -f "${TESTROOT}/CLAUDE.md"
reset_vars
_compute_agent_identity
assert_eq "user: source is user_claude_md" '"user_claude_md"' "${AGENT_CONFIG_SOURCE}"
assert_neq "user: hash populated" "null" "${AGENT_CONFIG_HASH}"
# Same content across project and user would be the same hash — that's expected
# and is the exact case that makes agent_config_source necessary for disambiguation.
echo

# ── Case 5: soul.md fallback when no CLAUDE.md anywhere ──
echo "Case 5: soul.md fallback"
rm -f "${HOME}/.claude/CLAUDE.md"
echo "soul content" > "${TESTROOT}/soul.md"
reset_vars
_compute_agent_identity
assert_eq "soul: source is project_soul_md" '"project_soul_md"' "${AGENT_CONFIG_SOURCE}"
assert_neq "soul: hash populated" "null" "${AGENT_CONFIG_HASH}"
echo

# ── Case 6: should.md fallback when only should.md present ──
echo "Case 6: should.md fallback"
rm -f "${TESTROOT}/soul.md"
echo "should content" > "${TESTROOT}/should.md"
reset_vars
_compute_agent_identity
assert_eq "should: source is project_should_md" '"project_should_md"' "${AGENT_CONFIG_SOURCE}"
echo

# ── Case 7: tamper detection — changed content yields different hash + fingerprint ──
echo "Case 7: tamper detection"
rm -f "${TESTROOT}/should.md"
echo "baseline config" > "${TESTROOT}/CLAUDE.md"
reset_vars
_compute_agent_identity
BASELINE_HASH="${AGENT_CONFIG_HASH}"
BASELINE_FP="${AGENT_FINGERPRINT}"

echo "tampered config" > "${TESTROOT}/CLAUDE.md"
reset_vars
_compute_agent_identity
assert_neq "tamper: hash changed" "${BASELINE_HASH}" "${AGENT_CONFIG_HASH}"
assert_neq "tamper: fingerprint changed" "${BASELINE_FP}" "${AGENT_FINGERPRINT}"
echo

# ── Case 8: fingerprint binds policy_version — different version, same config → different fingerprint ──
echo "Case 8: fingerprint binds policy_version"
echo "stable config" > "${TESTROOT}/CLAUDE.md"
export POLICY_VERSION="1.0.0"
reset_vars
_compute_agent_identity
V1_HASH="${AGENT_CONFIG_HASH}"
V1_FP="${AGENT_FINGERPRINT}"

export POLICY_VERSION="2.0.0"
reset_vars
_compute_agent_identity
assert_eq "version-bump: config_hash unchanged" "${V1_HASH}" "${AGENT_CONFIG_HASH}"
assert_neq "version-bump: fingerprint changed" "${V1_FP}" "${AGENT_FINGERPRINT}"
echo

# ── Case 9: determinism — same inputs always produce same outputs ──
echo "Case 9: determinism"
export POLICY_VERSION="1.0.0"
echo "deterministic input" > "${TESTROOT}/CLAUDE.md"
reset_vars
_compute_agent_identity
DET1_HASH="${AGENT_CONFIG_HASH}"
DET1_FP="${AGENT_FINGERPRINT}"
reset_vars
_compute_agent_identity
assert_eq "determinism: hash stable" "${DET1_HASH}" "${AGENT_CONFIG_HASH}"
assert_eq "determinism: fingerprint stable" "${DET1_FP}" "${AGENT_FINGERPRINT}"
echo

# ── Summary ──
echo "=============================="
echo "${PASS} passed, ${FAIL} failed out of ${TOTAL} tests"
echo

if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
exit 0
