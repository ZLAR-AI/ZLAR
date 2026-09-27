#!/bin/bash
# Guard private-core source-boundary and prior Apache-2.0 non-clawback wording.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_DIR}"

PASS=0
FAIL=0
TOTAL=0

pass() {
    PASS=$((PASS + 1))
}

fail() {
    local label="$1"
    local detail="${2:-}"
    FAIL=$((FAIL + 1))
    printf '  FAIL: %s\n' "${label}"
    if [ -n "${detail}" ]; then
        printf '%s\n' "${detail}" | sed 's/^/    /'
    fi
}

assert_contains() {
    local label="$1"
    local file="$2"
    local needle="$3"
    TOTAL=$((TOTAL + 1))
    if grep -Fq -- "${needle}" "${file}"; then
        pass
    else
        fail "${label}" "${file} missing: ${needle}"
    fi
}

assert_not_contains() {
    local label="$1"
    local file="$2"
    local needle="$3"
    TOTAL=$((TOTAL + 1))
    if grep -Fq -- "${needle}" "${file}"; then
        fail "${label}" "${file} contains: ${needle}"
    else
        pass
    fi
}

assert_no_tracked_fixed() {
    local label="$1"
    local needle="$2"
    shift 2
    TOTAL=$((TOTAL + 1))

    local matches rc
    set +e
    matches=$(git grep -n -F "${needle}" -- "$@" 2>&1)
    rc=$?
    set -e

    if [ "${rc}" -eq 0 ]; then
        fail "${label}" "${matches}"
    elif [ "${rc}" -eq 1 ]; then
        pass
    else
        fail "${label}" "${matches}"
    fi
}

assert_json_field() {
    local label="$1"
    local file="$2"
    local expression="$3"
    TOTAL=$((TOTAL + 1))

    local output rc
    set +e
    output=$(node -e "const { readFileSync } = require('node:fs'); const p=JSON.parse(readFileSync(process.argv[1], 'utf8')); if (!(${expression})) { process.exit(1); }" "${file}" 2>&1)
    rc=$?
    set -e

    if [ "${rc}" -eq 0 ]; then
        pass
    else
        fail "${label}" "${file}: ${expression} failed ${output}"
    fi
}

assert_verifier_kit_license_copy_split() {
    TOTAL=$((TOTAL + 1))

    if grep -Fq 'VERIFIER_KIT_LICENSE="${REPO_ROOT}/LICENSES/Apache-2.0-prior-public.txt"' tools/build-verifier-kit.sh &&
       grep -Fq 'cp "${VERIFIER_KIT_LICENSE}" "${KIT_DIR}/LICENSE"' tools/build-verifier-kit.sh &&
       ! grep -Fq 'cp "${REPO_ROOT}/LICENSE" "${KIT_DIR}/LICENSE"' tools/build-verifier-kit.sh; then
        pass
    else
        fail "verifier kit copies explicit Apache boundary, not root private-core license"
    fi
}

echo "=== Private Core Source Boundary Guard ==="

assert_contains "root license marks private core" LICENSE "ZLAR PRIVATE CORE SOURCE LICENSE NOTICE"
assert_contains "root license says current private core is proprietary" LICENSE "current private-core ZLAR source tree is proprietary and commercial source"
assert_contains "root license preserves Apache non-clawback" LICENSE "does not revoke, narrow, claw back, or alter rights"
assert_contains "root license points to prior Apache text" LICENSE "LICENSES/Apache-2.0-prior-public.txt"
assert_not_contains "root license no longer carries Apache terms body" LICENSE "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION"

assert_contains "prior Apache text preserved" LICENSES/Apache-2.0-prior-public.txt "Apache License"
assert_contains "prior Apache version preserved" LICENSES/Apache-2.0-prior-public.txt "Version 2.0, January 2004"

# README rewritten for humans on 2026-09-26: it states the license truth in plain words
# and defers to LICENSE, which still carries the Apache non-clawback text (checked above).
assert_contains "README states use beyond evaluation needs permission" README.md "Using it for real work, building"
assert_contains "README points readers to the root license" README.md "[LICENSE](LICENSE)"
assert_not_contains "README does not claim to be open source" README.md "is open source"
assert_not_contains "README no Apache license badge" README.md "License-Apache_2.0"
assert_not_contains "README no public clone command" README.md "git clone https://github.com/ZLAR-AI/ZLAR.git"
assert_not_contains "README no public downloader install command" README.md "curl -fsSL https://zlar.ai/install.sh | bash"

assert_contains "LEGAL names current private core" LEGAL.md "Current private-core ZLAR source is proprietary/commercial source."
assert_contains "LEGAL preserves prior Apache public distribution" LEGAL.md "Prior ZLAR source distributions that were made public under the Apache License 2.0 remain under"
assert_contains "LEGAL disclaims counsel approval" LEGAL.md "no representation in this repository notice that any particular commercial"
assert_no_tracked_fixed "no stale free open-source core claim" "ZLAR is distributed as free, open source software" LICENSE README.md LEGAL.md CONTRIBUTING.md docs tools spec
assert_no_tracked_fixed "no stale current open-source software claim" "ZLAR is open source software" LICENSE README.md LEGAL.md CONTRIBUTING.md docs tools spec
assert_no_tracked_fixed "no stale project open source at GitHub claim" "open source at github.com/ZLAR-AI/ZLAR" LICENSE README.md LEGAL.md CONTRIBUTING.md docs tools spec
assert_no_tracked_fixed "no stale current Apache license sentence" "ZLAR is licensed under the Apache License 2.0" LICENSE README.md LEGAL.md CONTRIBUTING.md docs tools spec
assert_no_tracked_fixed "no stale public GitHub clone command" "git clone https://github.com/ZLAR-AI/ZLAR.git" README.md LEGAL.md CONTRIBUTING.md docs tools spec

assert_verifier_kit_license_copy_split
assert_contains "verifier kit README names license split" tools/verifier-kit-src/README.md "Generated public/thin verifier-kit artifacts include Apache-2.0 license text"
assert_contains "receipt spec names license boundary" spec/governed-action-receipt-v1.md "**License boundary**"

for package_file in \
    cedar-poc/package.json \
    mcp-gate/package.json \
    packages/zlar-restore/package.json \
    sdk/authzen/package.json \
    sdk/daemon/package.json \
    sdk/membrane/package.json
do
    assert_json_field "${package_file} is unlicensed" "${package_file}" "p.license === 'UNLICENSED'"
    assert_json_field "${package_file} is private" "${package_file}" "p.private === true"
done
assert_json_field "cedar package lock root is unlicensed" cedar-poc/package-lock.json "p.packages[''].license === 'UNLICENSED'"
assert_json_field "cedar package lock root is private" cedar-poc/package-lock.json "p.packages[''].private === true"
assert_json_field "vendored cedar package remains Apache" cedar-poc/vendor/@cedar-policy/cedar-wasm/package.json "p.license === 'Apache-2.0'"

echo
printf "Results: %d/%d passed" "${PASS}" "${TOTAL}"
if [ "${FAIL}" -gt 0 ]; then
    printf " (%d FAILED)" "${FAIL}"
    echo
    exit 1
fi
echo " ok"
