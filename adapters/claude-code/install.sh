#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# ZLAR Claude Code Adapter — Install Script
#
# Installs the ZLAR gate as a Claude Code PreToolUse hook.
#
# What this does:
#   1. Generates ~/.claude/zlar-gate.sh from the template in this directory,
#      stamped with the absolute path to this repo.
#   2. Wires ~/.claude/settings.json PreToolUse hook to point at the wrapper.
#   3. Prints instructions for the /usr/local/bin/zlar symlink (requires sudo).
#
# Usage:
#   bash adapters/claude-code/install.sh
#
# Run from the repo root. Re-run after moving the repo to a new path.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Resolve repo root ──────────────────────────────────────────────────────
_self="${BASH_SOURCE[0]}"
while [ -L "${_self}" ]; do
    _dir="$(cd -P "$(dirname "${_self}")" && pwd)"
    _self="$(readlink "${_self}")"
    [[ "${_self}" != /* ]] && _self="${_dir}/${_self}"
done
ADAPTER_DIR="$(cd -P "$(dirname "${_self}")" && pwd)"
PROJECT_DIR="$(cd "${ADAPTER_DIR}/../.." && pwd)"
unset _self _dir

WRAPPER_SRC="${ADAPTER_DIR}/zlar-gate.sh"
WRAPPER_DST="${HOME}/.claude/zlar-gate.sh"
SETTINGS="${HOME}/.claude/settings.json"
GATE_BIN="${PROJECT_DIR}/bin/zlar-gate"

echo "ZLAR Claude Code Adapter — Install"
echo "Project root: ${PROJECT_DIR}"
echo ""

# ── Preflight ──────────────────────────────────────────────────────────────
if [ ! -f "${WRAPPER_SRC}" ]; then
    echo "ERROR: wrapper template not found at ${WRAPPER_SRC}" >&2
    exit 1
fi

if [ ! -x "${GATE_BIN}" ]; then
    echo "ERROR: gate binary not found or not executable at ${GATE_BIN}" >&2
    exit 1
fi

if [ ! -d "${HOME}/.claude" ]; then
    echo "ERROR: ~/.claude directory not found — is Claude Code installed?" >&2
    exit 1
fi

# ── Generate wrapper ───────────────────────────────────────────────────────
echo "Installing wrapper → ${WRAPPER_DST}"
sed "s|__ZLAR_PROJECT_DIR__|${PROJECT_DIR}|g" "${WRAPPER_SRC}" > "${WRAPPER_DST}"
chmod 700 "${WRAPPER_DST}"
echo "  ✓ wrapper written and marked executable"

# ── Wire settings.json ─────────────────────────────────────────────────────
if [ ! -f "${SETTINGS}" ]; then
    echo ""
    echo "NOTE: ${SETTINGS} not found."
    echo "  Claude Code has not been configured on this machine yet."
    echo "  Launch Claude Code once, then re-run this install script."
    echo ""
    echo "  Alternatively, create ${SETTINGS} manually with:"
    echo '  {"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"'"${WRAPPER_DST}"'","timeout":310}]}]}}'
else
    # Check if the hook is already wired to this wrapper path
    if python3 -c "
import json, sys
with open('${SETTINGS}') as f:
    s = json.load(f)
hooks = s.get('hooks', {}).get('PreToolUse', [])
for h in hooks:
    for entry in h.get('hooks', []):
        if entry.get('command') == '${WRAPPER_DST}':
            sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        echo "  ✓ settings.json already wired to this wrapper (no change needed)"
    else
        # Update or add the PreToolUse hook
        python3 - "${SETTINGS}" "${WRAPPER_DST}" <<'PYEOF'
import json, sys

settings_path = sys.argv[1]
wrapper_path = sys.argv[2]

with open(settings_path) as f:
    settings = json.load(f)

new_entry = {
    "matcher": ".*",
    "hooks": [{"type": "command", "command": wrapper_path, "timeout": 310}]
}

hooks = settings.setdefault("hooks", {})
pre_tool = hooks.setdefault("PreToolUse", [])

# Replace any existing ZLAR wrapper entry, or append
replaced = False
for i, h in enumerate(pre_tool):
    for entry in h.get("hooks", []):
        if "zlar-gate" in entry.get("command", ""):
            pre_tool[i] = new_entry
            replaced = True
            break
    if replaced:
        break

if not replaced:
    pre_tool.append(new_entry)

with open(settings_path, "w") as f:
    json.dump(settings, f, indent=2)
    f.write("\n")
PYEOF
        echo "  ✓ settings.json updated"
    fi
fi

# ── CLI symlink ────────────────────────────────────────────────────────────
echo ""
echo "Optional: CLI symlink"
if [ -L "/usr/local/bin/zlar" ]; then
    current_target=$(readlink "/usr/local/bin/zlar" 2>/dev/null || echo "unknown")
    expected_target="${PROJECT_DIR}/bin/zlar"
    if [ "${current_target}" = "${expected_target}" ]; then
        echo "  ✓ /usr/local/bin/zlar already points to ${expected_target}"
    else
        echo "  ! /usr/local/bin/zlar points to ${current_target}"
        echo "    To update: sudo ln -sfn ${expected_target} /usr/local/bin/zlar"
    fi
else
    echo "  To enable the 'zlar' CLI command:"
    echo "    sudo ln -sfn ${PROJECT_DIR}/bin/zlar /usr/local/bin/zlar"
fi

echo ""
echo "Done. ZLAR gate is installed."
echo "Restart Claude Code to activate (or it will pick up on next session start)."
