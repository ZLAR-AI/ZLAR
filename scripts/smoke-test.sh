#!/bin/bash
# ZLAR Linux smoke test — runs during Docker build.
# Exit on first failure.
set -euo pipefail

PASS=0
FAIL=0
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

echo "=== ZLAR Smoke Test ==="
echo ""

# ── 1. Bash syntax check on all shell scripts ──
echo "[1/4] Bash syntax check (bash -n)"
for f in bin/zlar-gate bin/zlar-registry bin/zlar-witness bin/zlar-digest bin/zlar-standing lib/audit-reader.sh; do
  if [ -f "$f" ]; then
    if bash -n "$f" 2>/dev/null; then
      pass "$f"
    else
      fail "$f — syntax error"
    fi
  else
    fail "$f — not found"
  fi
done
echo ""

# ── 2. Dependencies available ──
echo "[2/4] Dependency check"
for cmd in bash jq curl openssl date sha256sum node; do
  if command -v "$cmd" >/dev/null 2>&1; then
    pass "$cmd $(command -v "$cmd")"
  else
    fail "$cmd not found"
  fi
done
echo ""

# ── 3. Cedar PoC tests ──
echo "[3/4] Cedar PoC tests"
if [ -f cedar-poc/test.mjs ]; then
  if node cedar-poc/test.mjs 2>&1; then
    pass "cedar-poc/test.mjs"
  else
    fail "cedar-poc/test.mjs"
  fi
else
  fail "cedar-poc/test.mjs not found"
fi
echo ""

# ── 4. MCP gate tests ──
echo "[4/4] MCP gate tests"
if [ -f mcp-gate/test.mjs ]; then
  if node mcp-gate/test.mjs 2>&1; then
    pass "mcp-gate/test.mjs"
  else
    fail "mcp-gate/test.mjs"
  fi
else
  fail "mcp-gate/test.mjs not found"
fi
echo ""

# ── Summary ──
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
echo "All smoke tests passed on $(uname -s) $(uname -m)"
