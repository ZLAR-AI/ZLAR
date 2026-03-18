#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR — Zero-Config Install
#
# curl -fsSL https://zlar.ai/install.sh | bash
#
# Auto-detects Claude Code, Cursor, Windsurf.
# Generates keys. Signs a deny-heavy policy. Configures hooks.
# Governance running in under 60 seconds.
#
# This script must be bash-3.x compatible (macOS default ships 3.2).
# ═══════════════════════════════════════════════════════════════════════════════

# Strict mode (bash-3 safe: no pipefail in POSIX sh)
set -eu

ZLAR_VERSION="1.0.0"
INSTALL_DIR="${HOME}/.zlar"

# ─── Colors (bash-3 safe) ────────────────────────────────────────────────────

if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; DIM=''; NC=''
fi

ok()   { printf "${GREEN}  ✓${NC} %s\n" "$*"; }
fail() { printf "${RED}  ✗${NC} %s\n" "$*" >&2; }
warn() { printf "${YELLOW}  ⚠${NC} %s\n" "$*"; }
info() { printf "${BLUE}  ℹ${NC} %s\n" "$*"; }
step() { printf "\n${BOLD}%s${NC}\n\n" "$*"; }

# ─── Banner ──────────────────────────────────────────────────────────────────

printf "\n"
printf "${BOLD}═══════════════════════════════════════════════════${NC}\n"
printf "${BOLD}  ZLAR — Zero-Config Agent Governance${NC}\n"
printf "${BOLD}  One command. Your rules. Under 60 seconds.${NC}\n"
printf "${BOLD}═══════════════════════════════════════════════════${NC}\n"
printf "\n"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: Preflight
# ═══════════════════════════════════════════════════════════════════════════════

step "Phase 1: Preflight checks"

ERRORS=0
WARNINGS=0

# OS check
UNAME_S="$(uname -s)"
case "${UNAME_S}" in
    Darwin) ok "macOS detected" ;;
    Linux)  ok "Linux detected" ;;
    *)      fail "Unsupported OS: ${UNAME_S}"; ERRORS=$((ERRORS + 1)) ;;
esac

# bash version — gate itself needs bash 4+, but install.sh runs on 3.x
BASH_MAJOR="${BASH_VERSINFO:-0}"
if [ "${BASH_MAJOR}" = "0" ]; then
    BASH_MAJOR=$(echo "${BASH_VERSION:-0}" | cut -d. -f1)
fi
if [ "${BASH_MAJOR}" -ge 4 ] 2>/dev/null; then
    ok "bash ${BASH_VERSION} (gate compatible)"
else
    warn "bash ${BASH_VERSION:-unknown} — the gate engine needs bash 4+"
    case "${UNAME_S}" in
        Darwin) printf "       Install: ${BOLD}brew install bash${NC}\n" ;;
        Linux)  printf "       Install: ${BOLD}sudo apt install bash${NC} or equivalent\n" ;;
    esac
    WARNINGS=$((WARNINGS + 1))
fi

# jq
if command -v jq >/dev/null 2>&1; then
    ok "jq $(jq --version 2>/dev/null || echo '')"
else
    fail "jq is required but not installed"
    case "${UNAME_S}" in
        Darwin) printf "       Install: ${BOLD}brew install jq${NC}\n" ;;
        Linux)  printf "       Install: ${BOLD}sudo apt install jq${NC}\n" ;;
    esac
    ERRORS=$((ERRORS + 1))
fi

# openssl with Ed25519
if command -v openssl >/dev/null 2>&1; then
    ok "openssl $(openssl version 2>/dev/null | head -1 || echo 'found')"
    if openssl genpkey -algorithm ed25519 -out /dev/null 2>/dev/null; then
        ok "Ed25519 support confirmed"
    else
        fail "openssl does not support Ed25519"
        case "${UNAME_S}" in
            Darwin) printf "       Install: ${BOLD}brew install openssl${NC} && export PATH=\"\$(brew --prefix openssl)/bin:\$PATH\"\n" ;;
            Linux)  printf "       Upgrade openssl to 1.1.1+ for Ed25519 support\n" ;;
        esac
        ERRORS=$((ERRORS + 1))
    fi
else
    fail "openssl is required but not installed"
    ERRORS=$((ERRORS + 1))
fi

# curl
if command -v curl >/dev/null 2>&1; then
    ok "curl"
else
    fail "curl is required but not installed"
    ERRORS=$((ERRORS + 1))
fi

if [ "${ERRORS}" -gt 0 ]; then
    printf "\n"
    fail "Fix the ${ERRORS} error(s) above before continuing."
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: Check for existing ZLAR installs
# ═══════════════════════════════════════════════════════════════════════════════

step "Phase 2: Checking for existing ZLAR installs"

if [ -d "${INSTALL_DIR}" ]; then
    EXISTING_VERSION=""
    if [ -f "${INSTALL_DIR}/VERSION" ]; then
        EXISTING_VERSION=$(cat "${INSTALL_DIR}/VERSION" 2>/dev/null || echo "unknown")
    fi
    fail "ZLAR is already installed at ${INSTALL_DIR} (version: ${EXISTING_VERSION:-unknown})"
    printf "       To reinstall: ${BOLD}curl -fsSL https://zlar.ai/uninstall.sh | bash${NC} then re-run install\n"
    printf "       To upgrade: ${BOLD}~/.zlar/bin/zlar version${NC} to check current version\n"
    exit 1
fi

ok "No existing ZLAR installation found"

# Check if any framework already has ZLAR hooks (Gate or CC)
EXISTING_ZLAR=0
if [ -f "${HOME}/.claude/settings.json" ] && grep -q "zlar" "${HOME}/.claude/settings.json" 2>/dev/null; then
    warn "Claude Code already has ZLAR hooks configured — will skip hook setup for CC"
    EXISTING_ZLAR=$((EXISTING_ZLAR + 1))
fi
if [ -f "${HOME}/.cursor/hooks.json" ] && grep -q "zlar" "${HOME}/.cursor/hooks.json" 2>/dev/null; then
    warn "Cursor already has ZLAR hooks configured — will skip hook setup for Cursor"
    EXISTING_ZLAR=$((EXISTING_ZLAR + 1))
fi
if [ -f "${HOME}/.codeium/windsurf/hooks.json" ] && grep -q "zlar" "${HOME}/.codeium/windsurf/hooks.json" 2>/dev/null; then
    warn "Windsurf already has ZLAR hooks configured — will skip hook setup for Windsurf"
    EXISTING_ZLAR=$((EXISTING_ZLAR + 1))
fi

if [ "${EXISTING_ZLAR}" -eq 0 ]; then
    ok "No existing ZLAR hooks detected"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: Detect frameworks
# ═══════════════════════════════════════════════════════════════════════════════

step "Phase 3: Detecting installed frameworks"

HAS_CC=0; HAS_CURSOR=0; HAS_WINDSURF=0

# Claude Code — check for claude CLI or ~/.claude directory
if command -v claude >/dev/null 2>&1 || [ -d "${HOME}/.claude" ]; then
    ok "Claude Code detected"
    HAS_CC=1
else
    info "Claude Code not detected"
fi

# Cursor — check for cursor CLI or ~/.cursor directory
if command -v cursor >/dev/null 2>&1 || [ -d "${HOME}/.cursor" ]; then
    ok "Cursor detected"
    HAS_CURSOR=1
else
    info "Cursor not detected"
fi

# Windsurf — check for windsurf CLI or ~/.codeium/windsurf directory
if command -v windsurf >/dev/null 2>&1 || [ -d "${HOME}/.codeium/windsurf" ]; then
    ok "Windsurf detected"
    HAS_WINDSURF=1
else
    info "Windsurf not detected"
fi

TOTAL_FRAMEWORKS=$((HAS_CC + HAS_CURSOR + HAS_WINDSURF))
if [ "${TOTAL_FRAMEWORKS}" -eq 0 ]; then
    warn "No supported frameworks detected"
    printf "       ZLAR will install anyway. You can configure hooks manually later.\n"
    printf "       Supported: Claude Code, Cursor, Windsurf\n"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: Install
# ═══════════════════════════════════════════════════════════════════════════════

step "Phase 4: Installing to ${INSTALL_DIR}"

# Determine source — if running from repo clone, use local files.
# If running via curl | bash, we need to download.
SCRIPT_SOURCE_DIR=""
SELF_PATH="${BASH_SOURCE:-$0}"
if [ -f "${SELF_PATH}" ]; then
    SELF_DIR="$(cd "$(dirname "${SELF_PATH}")" && pwd)"
    if [ -f "${SELF_DIR}/bin/zlar-gate" ] && [ -f "${SELF_DIR}/bin/zlar-policy" ]; then
        SCRIPT_SOURCE_DIR="${SELF_DIR}"
        ok "Installing from local source: ${SELF_DIR}"
    fi
fi

if [ -z "${SCRIPT_SOURCE_DIR}" ]; then
    # Download from GitHub release
    GITHUB_REPO="ZLAR-AI/ZLAR"
    TARBALL_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/zlar-${ZLAR_VERSION}.tar.gz"

    info "Downloading ZLAR v${ZLAR_VERSION}..."

    TMPDIR_DL=$(mktemp -d)
    trap "rm -rf '${TMPDIR_DL}'" EXIT

    if curl -fsSL "${TARBALL_URL}" -o "${TMPDIR_DL}/zlar.tar.gz" 2>/dev/null; then
        tar xzf "${TMPDIR_DL}/zlar.tar.gz" -C "${TMPDIR_DL}" 2>/dev/null
        SCRIPT_SOURCE_DIR="${TMPDIR_DL}/zlar"
        ok "Downloaded and extracted"
    else
        # Fallback: clone repo
        info "Release tarball not found — cloning from GitHub..."
        if command -v git >/dev/null 2>&1; then
            git clone --depth 1 "https://github.com/${GITHUB_REPO}.git" "${TMPDIR_DL}/zlar" 2>/dev/null
            SCRIPT_SOURCE_DIR="${TMPDIR_DL}/zlar"
            ok "Cloned from GitHub"
        else
            fail "Cannot download ZLAR. Install git or download manually from:"
            printf "       https://github.com/${GITHUB_REPO}\n"
            exit 1
        fi
    fi
fi

# Create install directory structure
mkdir -p "${INSTALL_DIR}/bin"
mkdir -p "${INSTALL_DIR}/adapters/claude-code"
mkdir -p "${INSTALL_DIR}/adapters/cursor"
mkdir -p "${INSTALL_DIR}/adapters/windsurf"
mkdir -p "${INSTALL_DIR}/etc/policies"
mkdir -p "${INSTALL_DIR}/etc/keys"
mkdir -p "${INSTALL_DIR}/var/log/sessions"

# Copy core files
cp "${SCRIPT_SOURCE_DIR}/bin/zlar-gate"   "${INSTALL_DIR}/bin/zlar-gate"
cp "${SCRIPT_SOURCE_DIR}/bin/zlar-policy" "${INSTALL_DIR}/bin/zlar-policy"
cp "${SCRIPT_SOURCE_DIR}/bin/zlar"     "${INSTALL_DIR}/bin/zlar"

# Copy uninstall script
cp "${SCRIPT_SOURCE_DIR}/uninstall.sh"    "${INSTALL_DIR}/uninstall.sh"

# Copy adapters
cp "${SCRIPT_SOURCE_DIR}/adapters/claude-code/hook.sh" "${INSTALL_DIR}/adapters/claude-code/hook.sh"
cp "${SCRIPT_SOURCE_DIR}/adapters/cursor/hook.sh"      "${INSTALL_DIR}/adapters/cursor/hook.sh"
cp "${SCRIPT_SOURCE_DIR}/adapters/windsurf/hook.sh"    "${INSTALL_DIR}/adapters/windsurf/hook.sh"

# Copy config (gate.lt.json → gate.json — gate hardcodes etc/gate.json)
cp "${SCRIPT_SOURCE_DIR}/etc/gate.lt.json" "${INSTALL_DIR}/etc/gate.json"

# Copy default policy template
cp "${SCRIPT_SOURCE_DIR}/etc/policies/lt-default.policy.json" "${INSTALL_DIR}/etc/policies/lt-default.policy.json"

# Create .env (empty — Telegram disabled by default)
if [ ! -f "${INSTALL_DIR}/.env" ]; then
    printf "# ZLAR environment — Telegram is optional\n# Uncomment and fill in to enable Telegram approval:\n# ZLAR_TELEGRAM_TOKEN=your_bot_token_here\n" > "${INSTALL_DIR}/.env"
fi

# Version file
printf "%s\n" "${ZLAR_VERSION}" > "${INSTALL_DIR}/VERSION"

# Make scripts executable
chmod +x "${INSTALL_DIR}/bin/zlar-gate"
chmod +x "${INSTALL_DIR}/bin/zlar-policy"
chmod +x "${INSTALL_DIR}/bin/zlar"
chmod +x "${INSTALL_DIR}/adapters/claude-code/hook.sh"
chmod +x "${INSTALL_DIR}/adapters/cursor/hook.sh"
chmod +x "${INSTALL_DIR}/adapters/windsurf/hook.sh"
chmod +x "${INSTALL_DIR}/uninstall.sh"

ok "Core files installed to ${INSTALL_DIR}"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5: Generate keys and sign policy
# ═══════════════════════════════════════════════════════════════════════════════

step "Phase 5: Keys and policy"

# Generate Ed25519 keypair (if no existing key)
if [ -f "${HOME}/.zlar-signing.key" ] && [ -f "${INSTALL_DIR}/etc/keys/policy-signing.pub" ]; then
    ok "Signing keypair already exists — reusing"
elif [ -f "${HOME}/.zlar-signing.key" ]; then
    # Private key exists (from Gate or CC) but no pub key in LT — derive it
    info "Found existing signing key at ~/.zlar-signing.key — deriving public key"
    openssl pkey -in "${HOME}/.zlar-signing.key" -pubout -out "${INSTALL_DIR}/etc/keys/policy-signing.pub" 2>/dev/null
    ok "Public key derived from existing signing key"
else
    info "Generating Ed25519 signing keypair..."
    "${INSTALL_DIR}/bin/zlar-policy" keygen 2>/dev/null
    ok "Keypair generated"
    info "Private key: ~/.zlar-signing.key (keep this safe)"
    info "Public key:  ${INSTALL_DIR}/etc/keys/policy-signing.pub"
fi

# Copy default policy → active policy
cp "${INSTALL_DIR}/etc/policies/lt-default.policy.json" "${INSTALL_DIR}/etc/policies/active.policy.json"

# Sign the policy
if [ -f "${HOME}/.zlar-signing.key" ]; then
    "${INSTALL_DIR}/bin/zlar-policy" sign \
        --input "${INSTALL_DIR}/etc/policies/active.policy.json" \
        --key "${HOME}/.zlar-signing.key" 2>/dev/null
    ok "Default policy signed"
else
    fail "Could not sign policy — signing key not found"
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6: Configure framework hooks
# ═══════════════════════════════════════════════════════════════════════════════

step "Phase 6: Configuring hooks"

FRAMEWORKS_CONFIGURED=0

# ── Claude Code ──────────────────────────────────────────────────────────────

if [ "${HAS_CC}" -eq 1 ]; then
    CC_SETTINGS="${HOME}/.claude/settings.json"
    CC_HOOK="${INSTALL_DIR}/adapters/claude-code/hook.sh"

    # Skip if already has ZLAR hooks
    if [ -f "${CC_SETTINGS}" ] && grep -q "zlar" "${CC_SETTINGS}" 2>/dev/null; then
        ok "Claude Code: existing ZLAR hooks preserved (skipped)"
    else
        mkdir -p "${HOME}/.claude"
        if [ -f "${CC_SETTINGS}" ]; then
            # Merge into existing settings
            TEMP=$(mktemp)
            jq --arg cmd "${CC_HOOK}" \
                '.hooks.PreToolUse = [{"matcher":".*","hooks":[{"type":"command","command":$cmd,"timeout":310}]}]' \
                "${CC_SETTINGS}" > "${TEMP}" 2>/dev/null
            if [ -s "${TEMP}" ]; then
                mv "${TEMP}" "${CC_SETTINGS}"
                ok "Claude Code: hooks added to existing settings.json"
                FRAMEWORKS_CONFIGURED=$((FRAMEWORKS_CONFIGURED + 1))
            else
                rm -f "${TEMP}"
                warn "Claude Code: could not auto-configure — add manually"
                printf "       Add to ~/.claude/settings.json:\n"
                printf "       {\"hooks\":{\"PreToolUse\":[{\"matcher\":\".*\",\"hooks\":[{\"type\":\"command\",\"command\":\"${CC_HOOK}\",\"timeout\":310}]}]}}\n"
            fi
        else
            # Create new settings.json
            jq -n --arg cmd "${CC_HOOK}" \
                '{"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":$cmd,"timeout":310}]}]}}' \
                > "${CC_SETTINGS}"
            ok "Claude Code: created settings.json with ZLAR hooks"
            FRAMEWORKS_CONFIGURED=$((FRAMEWORKS_CONFIGURED + 1))
        fi
    fi
fi

# ── Cursor ───────────────────────────────────────────────────────────────────

if [ "${HAS_CURSOR}" -eq 1 ]; then
    CURSOR_HOOKS="${HOME}/.cursor/hooks.json"
    CURSOR_HOOK="${INSTALL_DIR}/adapters/cursor/hook.sh"

    if [ -f "${CURSOR_HOOKS}" ] && grep -q "zlar" "${CURSOR_HOOKS}" 2>/dev/null; then
        ok "Cursor: existing ZLAR hooks preserved (skipped)"
    else
        mkdir -p "${HOME}/.cursor"
        if [ -f "${CURSOR_HOOKS}" ]; then
            TEMP=$(mktemp)
            jq --arg cmd "${CURSOR_HOOK}" \
                '. + {
                    "beforeShellExecution": [{"command": $cmd, "timeout": 310}],
                    "beforeReadFile": [{"command": $cmd, "timeout": 310}],
                    "beforeMCPExecution": [{"command": $cmd, "timeout": 310}]
                }' "${CURSOR_HOOKS}" > "${TEMP}" 2>/dev/null
            if [ -s "${TEMP}" ]; then
                mv "${TEMP}" "${CURSOR_HOOKS}"
                ok "Cursor: ZLAR hooks added to existing hooks.json"
                FRAMEWORKS_CONFIGURED=$((FRAMEWORKS_CONFIGURED + 1))
            else
                rm -f "${TEMP}"
                warn "Cursor: could not auto-configure — add manually"
            fi
        else
            jq -n --arg cmd "${CURSOR_HOOK}" '{
                "beforeShellExecution": [{"command": $cmd, "timeout": 310}],
                "beforeReadFile": [{"command": $cmd, "timeout": 310}],
                "beforeMCPExecution": [{"command": $cmd, "timeout": 310}]
            }' > "${CURSOR_HOOKS}"
            ok "Cursor: created hooks.json with ZLAR hooks"
            FRAMEWORKS_CONFIGURED=$((FRAMEWORKS_CONFIGURED + 1))
        fi
    fi
fi

# ── Windsurf ─────────────────────────────────────────────────────────────────

if [ "${HAS_WINDSURF}" -eq 1 ]; then
    WS_HOOKS="${HOME}/.codeium/windsurf/hooks.json"
    WS_HOOK="${INSTALL_DIR}/adapters/windsurf/hook.sh"

    if [ -f "${WS_HOOKS}" ] && grep -q "zlar" "${WS_HOOKS}" 2>/dev/null; then
        ok "Windsurf: existing ZLAR hooks preserved (skipped)"
    else
        mkdir -p "${HOME}/.codeium/windsurf"
        if [ -f "${WS_HOOKS}" ]; then
            TEMP=$(mktemp)
            jq --arg cmd "${WS_HOOK}" \
                '. + {
                    "pre_run_command": [{"command": $cmd, "timeout": 310}],
                    "pre_write_code": [{"command": $cmd, "timeout": 310}],
                    "pre_read_code": [{"command": $cmd, "timeout": 310}],
                    "pre_mcp_tool_use": [{"command": $cmd, "timeout": 310}]
                }' "${WS_HOOKS}" > "${TEMP}" 2>/dev/null
            if [ -s "${TEMP}" ]; then
                mv "${TEMP}" "${WS_HOOKS}"
                ok "Windsurf: ZLAR hooks added to existing hooks.json"
                FRAMEWORKS_CONFIGURED=$((FRAMEWORKS_CONFIGURED + 1))
            else
                rm -f "${TEMP}"
                warn "Windsurf: could not auto-configure — add manually"
            fi
        else
            jq -n --arg cmd "${WS_HOOK}" '{
                "pre_run_command": [{"command": $cmd, "timeout": 310}],
                "pre_write_code": [{"command": $cmd, "timeout": 310}],
                "pre_read_code": [{"command": $cmd, "timeout": 310}],
                "pre_mcp_tool_use": [{"command": $cmd, "timeout": 310}]
            }' > "${WS_HOOKS}"
            ok "Windsurf: created hooks.json with ZLAR hooks"
            FRAMEWORKS_CONFIGURED=$((FRAMEWORKS_CONFIGURED + 1))
        fi
    fi
fi

if [ "${TOTAL_FRAMEWORKS}" -eq 0 ]; then
    info "No frameworks to configure — install ZLAR hooks when you install an editor"
    printf "       Run: ${BOLD}~/.zlar/bin/zlar status${NC} to see detected frameworks\n"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 7: Self-test
# ═══════════════════════════════════════════════════════════════════════════════

step "Phase 7: Self-test"

# Test: a Read should be allowed
TEST_INPUT='{"tool_name":"Read","tool_input":{"file_path":"/tmp/test"},"session_id":"lt-install-test"}'
TEST_RESULT=$(printf '%s' "${TEST_INPUT}" | "${INSTALL_DIR}/bin/zlar-gate" 2>/dev/null || echo "")

if [ -n "${TEST_RESULT}" ]; then
    TEST_DECISION=$(printf '%s' "${TEST_RESULT}" | jq -r '.hookSpecificOutput.permissionDecision // "unknown"' 2>/dev/null)
    if [ "${TEST_DECISION}" = "allow" ]; then
        ok "Gate self-test: Read → allow ✓"
    else
        warn "Gate self-test: Read returned '${TEST_DECISION}' (expected 'allow')"
    fi
else
    warn "Gate self-test: no output — gate may need bash 4+"
fi

# Test: rm -rf should be denied
TEST_INPUT2='{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/test"},"session_id":"lt-install-test"}'
TEST_RESULT2=$(printf '%s' "${TEST_INPUT2}" | "${INSTALL_DIR}/bin/zlar-gate" 2>/dev/null || echo "")

if [ -n "${TEST_RESULT2}" ]; then
    TEST_DECISION2=$(printf '%s' "${TEST_RESULT2}" | jq -r '.hookSpecificOutput.permissionDecision // "unknown"' 2>/dev/null)
    if [ "${TEST_DECISION2}" = "deny" ]; then
        ok "Gate self-test: rm -rf → deny ✓"
    else
        warn "Gate self-test: rm -rf returned '${TEST_DECISION2}' (expected 'deny')"
    fi
else
    warn "Gate self-test: no output for deny test"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 8: Summary
# ═══════════════════════════════════════════════════════════════════════════════

printf "\n"
printf "${BOLD}═══════════════════════════════════════════════════${NC}\n"
printf "${BOLD}  ZLAR installed.${NC}\n"
printf "${BOLD}═══════════════════════════════════════════════════${NC}\n"
printf "\n"
printf "  ${BOLD}Version:${NC}     ${ZLAR_VERSION}\n"
printf "  ${BOLD}Location:${NC}    ${INSTALL_DIR}\n"
printf "  ${BOLD}Frameworks:${NC}  ${FRAMEWORKS_CONFIGURED} configured\n"
printf "\n"
printf "  ${BOLD}What's allowed:${NC}\n"
printf "    ✓  File reads, writes, edits\n"
printf "    ✓  Glob and grep searches\n"
printf "    ✓  Safe shell commands (ls, cat, pwd, git status, ...)\n"
printf "    ✓  Web search\n"
printf "\n"
printf "  ${BOLD}What's blocked:${NC}\n"
printf "    ✗  rm, rm -rf (file deletion)\n"
printf "    ✗  sudo, privilege escalation\n"
printf "    ✗  curl, wget, ssh (network send)\n"
printf "    ✗  git push (code deployment)\n"
printf "    ✗  crontab, launchctl (persistence)\n"
printf "    ✗  .ssh writes, .env writes\n"
printf "    ✗  MCP tools (unknown domain)\n"
printf "    ✗  Unknown/compound commands\n"
printf "    ✗  Writes/edits to ~/.zlar/ (self-protection)\n"
printf "    ✗  Reading the signing key\n"
printf "\n"
printf "  ${BOLD}Upgrade path:${NC}\n"
printf "    Want case-by-case approval instead of blanket deny?\n"
printf "    Run: ${BOLD}~/.zlar/bin/zlar telegram${NC}\n"
printf "    This enables Telegram approval for denied actions.\n"
printf "\n"
printf "  ${BOLD}Commands:${NC}\n"
printf "    ${DIM}~/.zlar/bin/zlar status${NC}     — what's governed\n"
printf "    ${DIM}~/.zlar/bin/zlar audit${NC}      — recent decisions\n"
printf "    ${DIM}~/.zlar/bin/zlar policy${NC}     — current rules\n"
printf "    ${DIM}~/.zlar/bin/zlar uninstall${NC}  — clean removal\n"
printf "\n"
printf "  Open your editor. ZLAR is governing every tool call.\n"
printf "\n"
printf "${BOLD}═══════════════════════════════════════════════════${NC}\n"
printf "\n"
