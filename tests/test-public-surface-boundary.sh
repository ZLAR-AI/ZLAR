#!/bin/bash
# Refuse to publish anything the build does not declare.
#
# PUBLIC-SURFACE.md states the rule: the public repository is a build output, not
# a place anyone works. This test is the mechanism behind that sentence. Without
# it the boundary is a document asking people to behave, which is the thing ZLAR
# exists to say does not work.
#
# Three properties, and a failure of any one blocks publication:
#
#   1. INVENTORY — the built kit contains exactly the files recorded in the
#      expected inventory. Anything new refuses until a human reviews and
#      updates it. Refusal is the default; a file does not reach the public
#      surface by appearing.
#
#   2. NO PRIVATE REFERENCES — no published file names a private-core path,
#      candidate, worktree, helper, or signing artifact. Secrets are not the only
#      thing worth withholding; the shape of the private core is intelligence in
#      its own right, and it leaks through code comments long before it leaks
#      through code.
#
#   3. NO BUILD-MACHINE PATHS — no absolute path from the machine that ran the
#      build, and no private key material.
#
# This test does not decide what SHOULD be public. tools/build-verifier-kit.sh
# is the authority for that. This only enforces that what ships is what was
# declared.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
EXPECTED="${SCRIPT_DIR}/fixtures/public-surface/expected-kit-inventory.txt"

cd "${PROJECT_DIR}"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); }
fail() {
    FAIL=$((FAIL + 1))
    printf '  FAIL: %s\n' "$1"
    [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/    /'
    return 0
}

# ── Build ──────────────────────────────────────────────────────────────────
if ! BUILD_OUT=$(bash tools/build-verifier-kit.sh 2>&1); then
    printf 'FATAL: verifier kit build failed\n%s\n' "${BUILD_OUT}"
    exit 1
fi

KIT_DIR=$(printf '%s\n' "${BUILD_OUT}" | awk '/directory:/ {print $2}')
if [ -z "${KIT_DIR}" ] || [ ! -d "${KIT_DIR}" ]; then
    printf 'FATAL: could not locate built kit directory\n'
    exit 1
fi

# ── 1. Inventory ───────────────────────────────────────────────────────────
ACTUAL=$(cd "${KIT_DIR}" && find . -type f | sed 's|^\./||' | sort)

if [ ! -f "${EXPECTED}" ]; then
    fail "no expected inventory recorded" \
         "Create ${EXPECTED} from a reviewed build before publishing."
else
    if diff_out=$(diff <(printf '%s\n' "${ACTUAL}") "${EXPECTED}" 2>&1); then
        pass
    else
        fail "kit inventory does not match the reviewed inventory" \
             "$(printf '%s' "${diff_out}")
A file appearing here has NOT been reviewed for publication. Either remove it
from the build, or review it and update the expected inventory deliberately."
    fi
fi

# ── 2. No private-core references ───────────────────────────────────────────
# Deliberately broad. A false positive costs one line of review; a false
# negative publishes the shape of the private core.
PRIVATE_PATTERNS='\.worktrees|zlar-gate|zlar-orange|mcp-gate|PrivilegedHelperTools|zlar-signing|orange-c044|candidate-0[0-9][0-9]|/etc/zlar|\.zlar/|refs/salvage'

leaks=$(cd "${KIT_DIR}" && grep -rlE "${PRIVATE_PATTERNS}" . 2>/dev/null | sed 's|^\./||' | sort || true)
if [ -z "${leaks}" ]; then
    pass
else
    detail=""
    while IFS= read -r f; do
        [ -z "${f}" ] && continue
        hit=$(cd "${KIT_DIR}" && grep -nE "${PRIVATE_PATTERNS}" "${f}" | head -3)
        detail="${detail}${f}:
${hit}
"
    done <<< "${leaks}"
    fail "published files reference the private core" "${detail}"
fi

# ── 3. No build-machine paths or key material ───────────────────────────────
host_paths=$(cd "${KIT_DIR}" && grep -rlE '/Users/[a-zA-Z]|/home/[a-zA-Z]' . 2>/dev/null | sed 's|^\./||' | sort || true)
if [ -z "${host_paths}" ]; then
    pass
else
    fail "published files contain absolute build-machine paths" "${host_paths}"
fi

key_material=$(cd "${KIT_DIR}" && grep -rlE 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' . 2>/dev/null | sed 's|^\./||' | sort || true)
if [ -z "${key_material}" ]; then
    pass
else
    fail "published files contain private key material" "${key_material}"
fi

# ── Report ─────────────────────────────────────────────────────────────────
printf '\nPublic surface boundary: %d passed, %d failed\n' "${PASS}" "${FAIL}"
if [ "${FAIL}" -ne 0 ]; then
    printf 'The kit is NOT cleared for publication.\n'
    exit 1
fi
printf 'Kit contents match the reviewed public surface.\n'
