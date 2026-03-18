#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR — Unified Setup
#
# One-command install for Claude Code, Cursor, and Windsurf users.
# Checks prerequisites, copies config templates, generates signing keys,
# signs the default policy, and configures hooks for the chosen framework.
#
# Usage: ./scripts/zlar-setup.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

cd "${PROJECT_DIR}"

# Colors
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; NC=''
fi

ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
fail() { echo -e "${RED}  ✗${NC} $*" >&2; }
warn() { echo -e "${YELLOW}  ⚠${NC} $*"; }
info() { echo -e "${BLUE}  ℹ${NC} $*"; }

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  ZLAR — Setup${NC}"
echo -e "${BOLD}  One gate. Your rules. Every agent framework.${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo ""

# ─── Step 0: Choose framework ───────────────────────────────────────────────

echo -e "${BOLD}Step 0: Which agent framework?${NC}"
echo ""
echo "  1) Claude Code"
echo "  2) Cursor"
echo "  3) Windsurf"
echo "  4) All of the above"
echo ""

FRAMEWORK=""
while [ -z "${FRAMEWORK}" ]; do
    read -p "  Enter choice [1-4]: " choice
    case "${choice}" in
        1) FRAMEWORK="claude-code" ;;
        2) FRAMEWORK="cursor" ;;
        3) FRAMEWORK="windsurf" ;;
        4) FRAMEWORK="all" ;;
        *) echo "  Invalid choice. Enter 1, 2, 3, or 4." ;;
    esac
done

echo ""
if [ "${FRAMEWORK}" = "all" ]; then
    ok "Setting up for: Claude Code + Cursor + Windsurf"
else
    ok "Setting up for: ${FRAMEWORK}"
fi

echo ""
ERRORS=0

# ─── Step 1: Prerequisites ──────────────────────────────────────────────────

echo -e "${BOLD}Step 1: Prerequisites${NC}"
echo ""

# jq
if command -v jq &>/dev/null; then
    ok "jq $(jq --version 2>/dev/null || echo '')"
else
    fail "jq is required but not installed"
    echo "       Install: brew install jq (macOS) or apt install jq (Linux)"
    ERRORS=$((ERRORS + 1))
fi

# openssl
if command -v openssl &>/dev/null; then
    OPENSSL_VERSION=$(openssl version 2>/dev/null || echo "unknown")
    ok "openssl (${OPENSSL_VERSION})"
    if openssl genpkey -algorithm ed25519 -out /dev/null 2>/dev/null; then
        ok "Ed25519 support confirmed"
    else
        fail "openssl does not support Ed25519"
        echo "       macOS users: brew install openssl && export PATH=\"\$(brew --prefix openssl)/bin:\$PATH\""
        ERRORS=$((ERRORS + 1))
    fi
else
    fail "openssl is required but not installed"
    ERRORS=$((ERRORS + 1))
fi

# curl
if command -v curl &>/dev/null; then
    ok "curl"
else
    fail "curl is required but not installed"
    ERRORS=$((ERRORS + 1))
fi

# bash version
BASH_MAJOR="${BASH_VERSINFO[0]:-0}"
if [ "${BASH_MAJOR}" -ge 4 ]; then
    ok "bash ${BASH_VERSION}"
else
    warn "bash ${BASH_VERSION} — bash 4+ recommended (macOS default is 3.x)"
    echo "       Install: brew install bash"
fi

echo ""

if [ "${ERRORS}" -gt 0 ]; then
    fail "Fix the ${ERRORS} error(s) above before continuing."
    exit 1
fi

# ─── Step 2: Config files ───────────────────────────────────────────────────

echo -e "${BOLD}Step 2: Configuration${NC}"
echo ""

# gate.json
if [ ! -f etc/gate.json ]; then
    cp etc/gate.example.json etc/gate.json
    ok "Created etc/gate.json from template"
else
    ok "etc/gate.json already exists"
fi

# policy
if [ ! -f etc/policies/active.policy.json ]; then
    cp etc/policies/default.policy.example.json etc/policies/active.policy.json
    ok "Created etc/policies/active.policy.json from template"
else
    ok "etc/policies/active.policy.json already exists"
fi

# .env
if [ ! -f .env ]; then
    cp .env.example .env
    ok "Created .env from template"
    warn "You need to edit .env — add your Telegram bot token"
else
    ok ".env already exists"
fi

# Ensure directories
mkdir -p var/log etc/keys var/log/sessions 2>/dev/null
ok "Log and key directories ready"

echo ""

# ─── Step 3: Telegram ───────────────────────────────────────────────────────

echo -e "${BOLD}Step 3: Telegram${NC}"
echo ""

if [ -f .env ]; then
    set -a; . .env; set +a
fi

TELEGRAM_TOKEN="${ZLAR_TELEGRAM_TOKEN:-${TELEGRAM_BOT_TOKEN:-}}"

if [ -z "${TELEGRAM_TOKEN}" ]; then
    warn "No Telegram bot token found in .env"
    echo ""
    echo "       To set up Telegram approval:"
    echo "       1. Message @BotFather on Telegram → /newbot → get your token"
    echo "       2. Message @userinfobot on Telegram → get your chat ID"
    echo "       3. Edit .env: TELEGRAM_BOT_TOKEN=your_token_here"
    echo "       4. Edit etc/gate.json: set telegram.chat_id to your chat ID"
    echo ""
    warn "ZLAR will work without Telegram — 'ask' actions will time out and deny"
else
    ok "Telegram token found"
    if curl -s --connect-timeout 3 "https://api.telegram.org/bot${TELEGRAM_TOKEN}/getMe" | jq -r '.ok' 2>/dev/null | grep -q "true"; then
        BOT_NAME=$(curl -s "https://api.telegram.org/bot${TELEGRAM_TOKEN}/getMe" | jq -r '.result.username // "unknown"' 2>/dev/null)
        ok "Telegram API reachable (bot: @${BOT_NAME})"
    else
        fail "Telegram token is invalid or API unreachable"
    fi
fi

CHAT_ID=$(jq -r '.telegram.chat_id // ""' etc/gate.json 2>/dev/null)
if [ -n "${CHAT_ID}" ] && [ "${CHAT_ID}" != "YOUR_TELEGRAM_CHAT_ID" ]; then
    ok "Telegram chat ID configured: ${CHAT_ID}"
else
    warn "Telegram chat ID not set in etc/gate.json"
    echo "       Get your chat ID: message @userinfobot on Telegram"
fi

echo ""

# ─── Step 4: Signing keys ───────────────────────────────────────────────────

echo -e "${BOLD}Step 4: Signing Keys${NC}"
echo ""

if [ -f etc/keys/policy-signing.pub ] && [ -f "${HOME}/.zlar-signing.key" ]; then
    ok "Signing keypair already exists"
    info "Private key: ~/.zlar-signing.key"
    info "Public key: etc/keys/policy-signing.pub"
else
    info "Generating Ed25519 signing keypair..."
    bin/zlar-policy keygen
fi

echo ""

# ─── Step 5: Sign policy ────────────────────────────────────────────────────

echo -e "${BOLD}Step 5: Sign Policy${NC}"
echo ""

if [ -f etc/keys/policy-signing.pub ] && [ -f "${HOME}/.zlar-signing.key" ]; then
    bin/zlar-policy sign --input etc/policies/active.policy.json --key "${HOME}/.zlar-signing.key"
    ok "Policy signed"
else
    warn "Cannot sign policy — keys not generated yet"
fi

echo ""

# ─── Step 6: Configure framework hooks ──────────────────────────────────────

echo -e "${BOLD}Step 6: Framework Hooks${NC}"
echo ""

# Make all adapters executable
chmod +x adapters/*/hook.sh bin/zlar-gate bin/zlar-policy 2>/dev/null
ok "Gate and adapter scripts marked executable"

# ── Claude Code ──────────────────────────────────────────────────────────

configure_claude_code() {
    local hooks_dir="${HOME}/.claude"
    local settings_file="${hooks_dir}/settings.json"
    local hook_cmd="${PROJECT_DIR}/adapters/claude-code/hook.sh"

    if [ -f "${settings_file}" ]; then
        if jq -e '.hooks.PreToolUse' "${settings_file}" &>/dev/null; then
            if grep -q "zlar" "${settings_file}" 2>/dev/null; then
                ok "Claude Code: hooks already configured"
            else
                warn "Claude Code: hooks exist but don't reference ZLAR"
                echo "       Add to ~/.claude/settings.json → hooks.PreToolUse:"
                echo "       {\"type\":\"command\",\"command\":\"${hook_cmd}\",\"timeout\":310}"
            fi
        else
            # Use .hooks.PreToolUse = [...] to set ONLY PreToolUse without
            # clobbering other hook types (PostToolUse, Notification, etc.)
            TEMP=$(mktemp)
            jq --arg cmd "${hook_cmd}" \
                '.hooks.PreToolUse = [{"matcher":".*","hooks":[{"type":"command","command":$cmd,"timeout":310}]}]' \
                "${settings_file}" > "${TEMP}" 2>/dev/null
            if [ -s "${TEMP}" ]; then
                mv "${TEMP}" "${settings_file}"
                ok "Claude Code: hooks configured in ~/.claude/settings.json"
            else
                rm -f "${TEMP}"
                warn "Claude Code: could not auto-configure — add manually"
            fi
        fi
    else
        mkdir -p "${hooks_dir}"
        jq -n --arg cmd "${hook_cmd}" \
            '{"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":$cmd,"timeout":310}]}]}}' \
            > "${settings_file}"
        ok "Claude Code: created ~/.claude/settings.json with ZLAR hooks"
    fi
}

# ── Cursor ───────────────────────────────────────────────────────────────

configure_cursor() {
    local hooks_file="${HOME}/.cursor/hooks.json"
    local hook_cmd="${PROJECT_DIR}/adapters/cursor/hook.sh"

    mkdir -p "${HOME}/.cursor"

    if [ -f "${hooks_file}" ]; then
        if grep -q "zlar" "${hooks_file}" 2>/dev/null; then
            ok "Cursor: hooks already configured"
        else
            warn "Cursor: hooks.json exists — adding ZLAR hooks"
            TEMP=$(mktemp)
            jq --arg cmd "${hook_cmd}" \
                '. + {
                    "beforeShellExecution": [{"command": $cmd, "timeout": 310}],
                    "beforeReadFile": [{"command": $cmd, "timeout": 310}],
                    "beforeMCPExecution": [{"command": $cmd, "timeout": 310}]
                }' "${hooks_file}" > "${TEMP}" 2>/dev/null
            if [ -s "${TEMP}" ]; then
                mv "${TEMP}" "${hooks_file}"
                ok "Cursor: ZLAR hooks added to existing hooks.json"
            else
                rm -f "${TEMP}"
                warn "Cursor: could not auto-configure — add manually"
            fi
        fi
    else
        jq -n --arg cmd "${hook_cmd}" '{
            "beforeShellExecution": [{"command": $cmd, "timeout": 310}],
            "beforeReadFile": [{"command": $cmd, "timeout": 310}],
            "beforeMCPExecution": [{"command": $cmd, "timeout": 310}]
        }' > "${hooks_file}"
        ok "Cursor: created ~/.cursor/hooks.json with ZLAR hooks"
    fi
}

# ── Windsurf ─────────────────────────────────────────────────────────────

configure_windsurf() {
    local hooks_file="${HOME}/.codeium/windsurf/hooks.json"
    local hook_cmd="${PROJECT_DIR}/adapters/windsurf/hook.sh"

    mkdir -p "${HOME}/.codeium/windsurf"

    if [ -f "${hooks_file}" ]; then
        if grep -q "zlar" "${hooks_file}" 2>/dev/null; then
            ok "Windsurf: hooks already configured"
        else
            warn "Windsurf: hooks.json exists — adding ZLAR hooks"
            TEMP=$(mktemp)
            jq --arg cmd "${hook_cmd}" \
                '. + {
                    "pre_run_command": [{"command": $cmd, "timeout": 310}],
                    "pre_write_code": [{"command": $cmd, "timeout": 310}],
                    "pre_read_code": [{"command": $cmd, "timeout": 310}],
                    "pre_mcp_tool_use": [{"command": $cmd, "timeout": 310}]
                }' "${hooks_file}" > "${TEMP}" 2>/dev/null
            if [ -s "${TEMP}" ]; then
                mv "${TEMP}" "${hooks_file}"
                ok "Windsurf: ZLAR hooks added to existing hooks.json"
            else
                rm -f "${TEMP}"
                warn "Windsurf: could not auto-configure — add manually"
            fi
        fi
    else
        jq -n --arg cmd "${hook_cmd}" '{
            "pre_run_command": [{"command": $cmd, "timeout": 310}],
            "pre_write_code": [{"command": $cmd, "timeout": 310}],
            "pre_read_code": [{"command": $cmd, "timeout": 310}],
            "pre_mcp_tool_use": [{"command": $cmd, "timeout": 310}]
        }' > "${hooks_file}"
        ok "Windsurf: created ~/.codeium/windsurf/hooks.json with ZLAR hooks"
    fi
}

# ── Run for selected framework(s) ───────────────────────────────────────

case "${FRAMEWORK}" in
    claude-code) configure_claude_code ;;
    cursor) configure_cursor ;;
    windsurf) configure_windsurf ;;
    all)
        configure_claude_code
        configure_cursor
        configure_windsurf
        ;;
esac

echo ""

# ─── Step 7: Verify ─────────────────────────────────────────────────────────

echo -e "${BOLD}Step 7: Verification${NC}"
echo ""

# Quick self-test: pipe a test tool call through the gate
TEST_INPUT='{"tool_name":"Read","tool_input":{"file_path":"/tmp/test"},"session_id":"setup-test"}'
TEST_RESULT=$(echo "${TEST_INPUT}" | bin/zlar-gate 2>/dev/null || echo "")

if [ -n "${TEST_RESULT}" ]; then
    TEST_DECISION=$(echo "${TEST_RESULT}" | jq -r '.hookSpecificOutput.permissionDecision // "unknown"' 2>/dev/null)
    if [ "${TEST_DECISION}" = "allow" ] || [ "${TEST_DECISION}" = "deny" ]; then
        ok "Gate self-test passed (decision: ${TEST_DECISION})"
    else
        warn "Gate self-test returned unexpected: ${TEST_DECISION}"
    fi
else
    fail "Gate self-test failed — gate did not produce output"
fi

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Setup complete.${NC}"
echo ""
echo "  Framework: ${FRAMEWORK}"
echo ""
echo "  Next steps:"
echo "    1. Edit etc/gate.json — set your Telegram chat ID"
echo "    2. Edit .env — add your Telegram bot token"
echo "    3. Review etc/policies/active.policy.json — customize rules"
echo "    4. Re-sign after changes:"
echo "       bin/zlar-policy sign --input etc/policies/active.policy.json --key ~/.zlar-signing.key"
echo ""

case "${FRAMEWORK}" in
    claude-code) echo "    5. Open Claude Code — ZLAR is gating every tool call" ;;
    cursor)      echo "    5. Open Cursor — ZLAR is gating shell, read, and MCP actions" ;;
    windsurf)    echo "    5. Open Windsurf — ZLAR is gating command, write, read, and MCP actions" ;;
    all)         echo "    5. Open any supported editor — ZLAR is gating tool calls across all three" ;;
esac

echo ""
echo "  One policy. One audit trail. Every framework."
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo ""
