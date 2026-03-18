#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR-OC Telegram, Log Rotation, Watchdog Plist, and Scored Rules Tests
#
# Tests for:
#   - Telegram ask channel wiring in gate
#   - Log rotation config (newsyslog)
#   - Watchdog launchd plist in install-plist
#   - Risk scores on R020, R030-R032 deny rules
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'
PASSED=0; FAILED=0
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

check() {
    local desc="$1" result="$2"
    if [ "${result}" = "true" ]; then
        echo -e "  ${GREEN}PASS${NC} ${desc}"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} ${desc}"
        FAILED=$((FAILED + 1))
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Test 1: Telegram Ask Channel — Gate Structure
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}Test 1: Telegram ask channel structure in gate${NC}"

GATE="${REPO_ROOT}/bin/zlar-oc-gate"

# Telegram state variables
check "TELEGRAM_ENABLED variable exists" \
    "$(grep -c 'TELEGRAM_ENABLED="false"' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "TELEGRAM_BOT_TOKEN variable exists" \
    "$(grep -c 'TELEGRAM_BOT_TOKEN=""' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "TELEGRAM_CHAT_ID variable exists" \
    "$(grep -c 'TELEGRAM_CHAT_ID=""' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "TELEGRAM_LAST_UPDATE_ID initialized" \
    "$(grep -c 'TELEGRAM_LAST_UPDATE_ID=0' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# Core functions
check "load_telegram_config function exists" \
    "$(grep -c 'load_telegram_config()' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "telegram_api function exists" \
    "$(grep -c 'telegram_api()' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "telegram_ask function exists" \
    "$(grep -c 'telegram_ask()' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "resolve_ask function exists" \
    "$(grep -c 'resolve_ask()' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# ═══════════════════════════════════════════════════════════════════════════════
# Test 2: Telegram Config Loading
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}Test 2: Telegram config loading and env var override${NC}"

# Config loads from gate.json
check "Reads enabled from gate.json" \
    "$(grep -c 'telegram.enabled' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "Reads bot_token from gate.json" \
    "$(grep -c 'telegram.bot_token' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "Reads chat_id from gate.json" \
    "$(grep -c 'telegram.chat_id' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# Env var overrides
check "ZLAR_TELEGRAM_TOKEN env var override" \
    "$(grep -c 'ZLAR_TELEGRAM_TOKEN' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "ZLAR_TELEGRAM_CHAT_ID env var override" \
    "$(grep -c 'ZLAR_TELEGRAM_CHAT_ID' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# Validation
check "Validates token+chat_id when enabled" \
    "$(grep -c 'bot_token or chat_id missing' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# ═══════════════════════════════════════════════════════════════════════════════
# Test 3: Telegram wired into start_daemon
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}Test 3: Telegram wired into gate startup${NC}"

# load_telegram_config called in start_daemon
check "load_telegram_config called in start_daemon" \
    "$(grep -A5 'Load Telegram config' "${GATE}" | grep -c 'load_telegram_config' | awk '{print ($1 >= 1) ? "true" : "false"}')"

# GATE_CONFIG default defined
check "GATE_CONFIG default defined" \
    "$(grep -c 'GATE_CONFIG=' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# Telegram status in startup event
check "telegram_enabled in startup audit event" \
    "$(grep -c 'telegram_enabled' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# SIGHUP reloads telegram config
check "SIGHUP reloads telegram config" \
    "$(grep 'SIGHUP' "${GATE}" | grep -c 'load_telegram_config' | awk '{print ($1 >= 1) ? "true" : "false"}')"

# ═══════════════════════════════════════════════════════════════════════════════
# Test 4: Telegram Ask Flow
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}Test 4: Telegram ask message flow${NC}"

# Inline keyboard with Approve/Deny
check "Inline keyboard has Approve button" \
    "$(grep -c 'Approve' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "Inline keyboard has Deny button" \
    "$(grep -c 'Deny' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# Timeout defaults to deny
check "Timeout defaults to deny" \
    "$(grep -c 'timeout_s.*120' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# Polls getUpdates for callback_query
check "Polls getUpdates for callbacks" \
    "$(grep -c 'getUpdates' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "Handles callback_query responses" \
    "$(grep -c 'callback_query' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# answerCallbackQuery removes loading
check "Answers callback to remove loading indicator" \
    "$(grep -c 'answerCallbackQuery' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# Fail-closed: disabled Telegram → deny
check "Disabled Telegram defaults to deny" \
    "$(grep -c 'Telegram not enabled, defaulting ask to deny' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# resolve_ask wired into all three event processors
check "resolve_ask wired into event processors" \
    "$(grep -c 'resolve_ask' "${GATE}" | awk '{print ($1 >= 4) ? "true" : "false"}')"

# ═══════════════════════════════════════════════════════════════════════════════
# Test 5: Telegram Config in gate.json
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}Test 5: Telegram config in gate.json${NC}"

GATE_JSON="${REPO_ROOT}/etc/zlar-oc/gate.json"

check "gate.json has telegram section" \
    "$(jq 'has("telegram")' "${GATE_JSON}" 2>/dev/null || echo false)"

check "telegram.enabled is false by default" \
    "$(jq '.telegram.enabled == false' "${GATE_JSON}" 2>/dev/null || echo false)"

check "telegram.bot_token field exists" \
    "$(jq '.telegram | has("bot_token")' "${GATE_JSON}" 2>/dev/null || echo false)"

check "telegram.chat_id field exists" \
    "$(jq '.telegram | has("chat_id")' "${GATE_JSON}" 2>/dev/null || echo false)"

check "telegram._setup has BotFather instructions" \
    "$(jq '.telegram._setup | test("BotFather")' "${GATE_JSON}" 2>/dev/null || echo false)"

# ═══════════════════════════════════════════════════════════════════════════════
# Test 6: Risk Scores on Deny Rules (Stage 1 as Stage 2)
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}Test 6: Risk scores on critical deny rules${NC}"

POLICY="${REPO_ROOT}/etc/zlar-oc/policies/default.policy.json"

# R020 — LAN deny
check "R020 has risk_score" \
    "$(jq '[.rules[] | select(.id=="R020")][0].risk_score.enabled' "${POLICY}" 2>/dev/null || echo false)"

R020_SCORE=$(jq '[.rules[] | select(.id=="R020")][0].risk_score | [.irreversibility, .consequence, .blast_radius] | max' "${POLICY}" 2>/dev/null || echo 0)
check "R020 max score >= 80 (deny threshold)" \
    "$([ "${R020_SCORE}" -ge 80 ] && echo true || echo false)"

# R030 — admin home deny
check "R030 has risk_score" \
    "$(jq '[.rules[] | select(.id=="R030")][0].risk_score.enabled' "${POLICY}" 2>/dev/null || echo false)"

R030_SCORE=$(jq '[.rules[] | select(.id=="R030")][0].risk_score | [.irreversibility, .consequence, .blast_radius] | max' "${POLICY}" 2>/dev/null || echo 0)
check "R030 max score >= 80 (deny threshold)" \
    "$([ "${R030_SCORE}" -ge 80 ] && echo true || echo false)"

# R031 — ZLAR-OC config deny (regulatory erosion = cancer)
check "R031 has risk_score" \
    "$(jq '[.rules[] | select(.id=="R031")][0].risk_score.enabled' "${POLICY}" 2>/dev/null || echo false)"

R031_SCORE=$(jq '[.rules[] | select(.id=="R031")][0].risk_score | [.irreversibility, .consequence, .blast_radius] | max' "${POLICY}" 2>/dev/null || echo 0)
check "R031 max score = 100 (self-modification of containment)" \
    "$([ "${R031_SCORE}" -eq 100 ] && echo true || echo false)"

# R032 — SSH key deny
check "R032 has risk_score" \
    "$(jq '[.rules[] | select(.id=="R032")][0].risk_score.enabled' "${POLICY}" 2>/dev/null || echo false)"

R032_SCORE=$(jq '[.rules[] | select(.id=="R032")][0].risk_score | [.irreversibility, .consequence, .blast_radius] | max' "${POLICY}" 2>/dev/null || echo 0)
check "R032 max score = 100 (lateral movement via SSH)" \
    "$([ "${R032_SCORE}" -eq 100 ] && echo true || echo false)"

# Verify R010 still has scoring (backward compat)
check "R010 still has risk_score from previous build" \
    "$(jq '[.rules[] | select(.id=="R010")][0].risk_score.enabled' "${POLICY}" 2>/dev/null || echo false)"

# ═══════════════════════════════════════════════════════════════════════════════
# Test 7: Log Rotation Config (#13 Lysosomes)
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}Test 7: Log rotation config (newsyslog)${NC}"

LOGROTATE="${REPO_ROOT}/etc/zlar-oc/newsyslog.d/zlar-oc.conf"

check "newsyslog config file exists" \
    "$([ -f "${LOGROTATE}" ] && echo true || echo false)"

check "Rotates audit.jsonl" \
    "$(grep -c 'audit.jsonl' "${LOGROTATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "Rotates gate.log" \
    "$(grep -c 'gate.log' "${LOGROTATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "Rotates watchdog.log" \
    "$(grep -c 'watchdog.log' "${LOGROTATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "Rotates openclaw-stderr.log" \
    "$(grep -c 'openclaw-stderr.log' "${LOGROTATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "Audit trail keeps 90 rotations (longest retention)" \
    "$(grep 'audit.jsonl' "${LOGROTATE}" | awk '{print ($4 == 90) ? "true" : "false"}')"

check "Gate log keeps 30 rotations" \
    "$(grep 'gate.log' "${LOGROTATE}" | awk '{print ($4 == 30) ? "true" : "false"}')"

# Uses GJ flags (bzip compress + don't kill process)
check "Uses GJ compression flags" \
    "$(grep -c 'GJN' "${LOGROTATE}" | awk '{print ($1 >= 3) ? "true" : "false"}')"

# Gate log sends SIGHUP via pidfile
check "Gate log sends SIGHUP for reopen" \
    "$(grep 'gate.log' "${LOGROTATE}" | grep -c 'zlar-oc-gate.pid' | awk '{print ($1 >= 1) ? "true" : "false"}')"

# ═══════════════════════════════════════════════════════════════════════════════
# Test 8: Watchdog Plist in install-plist
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}Test 8: Watchdog launchd plist${NC}"

INSTALL_PLIST="${REPO_ROOT}/bin/zlar-oc-install-plist"

check "install-plist mentions watchdog" \
    "$(grep -c 'watchdog' "${INSTALL_PLIST}" | awk '{print ($1 >= 3) ? "true" : "false"}')"

check "Creates ai.zlar-oc.watchdog.plist" \
    "$(grep -c 'ai.zlar-oc.watchdog.plist' "${INSTALL_PLIST}" | awk '{print ($1 >= 2) ? "true" : "false"}')"

check "Watchdog plist runs as admin" \
    "$(grep -A20 'ai.zlar-oc.watchdog' "${INSTALL_PLIST}" | grep -c '<string>admin</string>' | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "Watchdog plist runs zlar-oc-watchdog start" \
    "$(grep -A20 'ai.zlar-oc.watchdog' "${INSTALL_PLIST}" | grep -c 'zlar-oc-watchdog' | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "Watchdog plist has gate pidfile arg" \
    "$(grep -A30 'ai.zlar-oc.watchdog' "${INSTALL_PLIST}" | grep -c 'gate-pidfile\|gate.pid' | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "Watchdog plist logs to watchdog.log" \
    "$(grep -A30 'ai.zlar-oc.watchdog' "${INSTALL_PLIST}" | grep -c 'watchdog.log' | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "Watchdog plist has KeepAlive" \
    "$(grep -A40 'ai.zlar-oc.watchdog' "${INSTALL_PLIST}" | grep -c 'KeepAlive' | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "launchctl load instructions include watchdog" \
    "$(grep 'launchctl load' "${INSTALL_PLIST}" | grep -c 'watchdog' | awk '{print ($1 >= 1) ? "true" : "false"}')"

# ═══════════════════════════════════════════════════════════════════════════════
# Results
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
TOTAL=$((PASSED + FAILED))
echo -e "${BOLD}Results: ${PASSED}/${TOTAL} passed${NC}"

if [ ${FAILED} -gt 0 ]; then
    echo -e "${RED}${FAILED} test(s) failed${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
fi
