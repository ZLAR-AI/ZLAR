#!/bin/bash
# ZLAR smoke test — a fast bash-and-optional-node sanity check.
# Runs during Docker build and as a local pre-commit check.
# Node-dependent phases skip gracefully if `node` is not on PATH.
set -uo pipefail

PASS=0
FAIL=0
SKIP=0
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
skip() { SKIP=$((SKIP + 1)); echo "  SKIP: $1"; }

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

# ── 2. Required dependencies ──
echo "[2/4] Dependency check"
for cmd in bash jq curl openssl date sha256sum; do
  if command -v "$cmd" >/dev/null 2>&1; then
    pass "$cmd $(command -v "$cmd")"
  else
    fail "$cmd not found"
  fi
done
# Node is optional — skip the node-dependent phases cleanly if missing.
if command -v node >/dev/null 2>&1; then
  pass "node $(command -v node) ($(node --version 2>/dev/null))"
  HAS_NODE=1
else
  skip "node not found (MCP gate and Cedar tests will be skipped)"
  HAS_NODE=0
fi
# Ed25519 support — the gate requires it. Test-crypto will fail silently
# without this, so surface it up front.
if openssl genpkey -algorithm ed25519 -out /dev/null 2>/dev/null; then
  pass "openssl supports Ed25519"
else
  fail "openssl does not support Ed25519 — gate and crypto tests will fail"
fi
echo ""

# ── 3. Cedar PoC tests ──
echo "[3/4] Cedar PoC tests"
if [ "$HAS_NODE" -eq 0 ]; then
  skip "cedar-poc tests (node not installed)"
elif [ -f cedar-poc/test.mjs ]; then
  if node cedar-poc/test.mjs >/dev/null 2>&1; then
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
if [ "$HAS_NODE" -eq 0 ]; then
  skip "mcp-gate tests (node not installed)"
elif [ -f mcp-gate/test.mjs ]; then
  if node mcp-gate/test.mjs >/dev/null 2>&1; then
    pass "mcp-gate/test.mjs"
  else
    fail "mcp-gate/test.mjs"
  fi
else
  fail "mcp-gate/test.mjs not found"
fi
echo ""

# ── Summary ──
if [ "$SKIP" -gt 0 ]; then
  echo "=== Results: $PASS passed, $FAIL failed, $SKIP skipped ==="
else
  echo "=== Results: $PASS passed, $FAIL failed ==="
fi
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
echo "Smoke tests passed on $(uname -s) $(uname -m)"
