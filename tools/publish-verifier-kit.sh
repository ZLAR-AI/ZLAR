#!/bin/bash
# The only path from the private core to the public repository.
#
# PUBLIC-SURFACE.md states the rule: the public repository is a build output, not
# a place anyone works. This script is that path. It builds the kit, refuses to
# proceed unless the boundary check passes, refuses to write into anything that
# looks like a private-core checkout, syncs the kit into the public working copy,
# and stops before the push.
#
# It never pushes. Root and push are Vincent's; this prepares one command and
# hands it over.
#
# Usage:
#   tools/publish-verifier-kit.sh /path/to/zlar-verifier
#
# Typical first run:
#   1. Create the repository on GitHub (Vincent). Start it PRIVATE.
#   2. git clone <url> ~/Documents/ZLAR/zlar-verifier
#   3. tools/publish-verifier-kit.sh ~/Documents/ZLAR/zlar-verifier
#   4. Run the push command it prints.
#   5. Flip visibility to public only when every gate condition in
#      PUBLIC-SURFACE.md is met.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET="${1:-}"

die() { printf 'REFUSED: %s\n' "$1" >&2; exit 1; }

[ -n "${TARGET}" ] || die "no target given. Usage: $0 /path/to/zlar-verifier"
[ -d "${TARGET}" ] || die "target does not exist: ${TARGET}"
TARGET="$(cd "${TARGET}" && pwd)"

# ── Guard: never write into the private core ───────────────────────────────
# A mistyped path here would publish the machinery. Refuse anything that looks
# like this repository or any checkout of it, by three independent signals.
[ "${TARGET}" = "${PROJECT_DIR}" ] && die "target is the private core itself"
case "${TARGET}" in
    "${PROJECT_DIR}"/*) die "target is inside the private core" ;;
    */.worktrees/*)     die "target is inside .worktrees — those are private-core copies" ;;
esac
for marker in bin/zlar-gate lib/zlar-orange-evidence-store.py etc/policies adapters/claude-code v4 cyan; do
    [ -e "${TARGET}/${marker}" ] && die "target contains private-core content (${marker}) — this is not a clean public repo"
done
if [ -d "${TARGET}/.git" ] && git -C "${TARGET}" remote -v 2>/dev/null | grep -qiE 'ZLAR-AI/ZLAR(\.git)?[[:space:]]'; then
    die "target's remote is the private core repository"
fi

# ── Build and check ────────────────────────────────────────────────────────
printf 'Building verifier kit...\n'
BUILD_OUT=$(bash "${PROJECT_DIR}/tools/build-verifier-kit.sh" 2>&1) || {
    printf '%s\n' "${BUILD_OUT}" >&2
    die "kit build failed"
}
KIT_DIR=$(printf '%s\n' "${BUILD_OUT}" | awk '/directory:/ {print $2}')
[ -d "${KIT_DIR}" ] || die "could not locate built kit"

printf 'Checking the public surface boundary...\n'
if ! CHECK_OUT=$(bash "${PROJECT_DIR}/tests/test-public-surface-boundary.sh" 2>&1); then
    printf '%s\n' "${CHECK_OUT}" >&2
    die "boundary check failed — nothing was written to the target"
fi
printf '  boundary check passed\n'

# ── Sync ───────────────────────────────────────────────────────────────────
# Mirror: files removed from the kit are removed from the public repo, so the
# published tree is the build output and nothing else. .git is preserved.
printf 'Syncing kit into %s\n' "${TARGET}"
rsync -a --delete --exclude '.git' "${KIT_DIR}/" "${TARGET}/"

# ── Report ─────────────────────────────────────────────────────────────────
if [ ! -d "${TARGET}/.git" ]; then
    printf '\nSynced, but the target is not a git repository yet.\n'
    printf 'Initialize it, add the remote, commit, then push.\n'
    exit 0
fi

cd "${TARGET}"
if git diff --quiet && git diff --cached --quiet && [ -z "$(git status --porcelain)" ]; then
    printf '\nNo change: the published kit already matches this build.\n'
    exit 0
fi

printf '\nChanges staged for publication:\n'
git add -A
git status --short | sed 's/^/  /'

KIT_VERSION=$(cat "${KIT_DIR}/VERSION" 2>/dev/null || echo unknown)

# A repository that has never been pushed has no upstream and may have no branch
# at all. Print the command that actually works rather than the usual one.
if git rev-parse --abbrev-ref --symbolic-full-name '@{u}' >/dev/null 2>&1; then
    PUSH_CMD=$(printf 'git -C %s push' "${TARGET}")
else
    BRANCH=$(git symbolic-ref --short HEAD 2>/dev/null || echo main)
    PUSH_CMD=$(printf 'git -C %s push -u origin %s' "${TARGET}" "${BRANCH}")
fi

printf '\nNothing has been committed or pushed.\n'
printf 'To publish:\n\n'
printf '  git -C %s commit -m "Publish verifier kit %s"\n' "${TARGET}" "${KIT_VERSION}"
printf '  %s\n\n' "${PUSH_CMD}"
printf 'Before making that repository PUBLIC, confirm every gate condition in\n'
printf 'PUBLIC-SURFACE.md is met. Publishing is reversible; disclosure is not.\n'
