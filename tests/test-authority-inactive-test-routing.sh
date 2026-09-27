#!/bin/bash

set -u

PASS=0
FAIL=0
TOTAL=0

assert() {
  local label="$1"
  shift
  TOTAL=$((TOTAL + 1))
  if "$@"; then
    PASS=$((PASS + 1))
    printf '  PASS: %s\n' "$label"
  else
    FAIL=$((FAIL + 1))
    printf '  FAIL: %s\n' "$label"
  fi
}

LIST="tests/authority-inactive-test-suites.txt"
RETIRED_GENERATORS="tests/retired-positive-generator-test-suites.txt"
RETIRED_DIRECT_E2="tests/retired-direct-e2-test-suites.txt"
RETIRED_DIRECT_E1="tests/retired-direct-e1-test-suites.txt"
SUPERSEDED="tests/superseded-source-bound-test-suites.txt"
HARNESS="tests/count-assertions.sh"
LIVE_INSTALL="lib/protected-records-active-persistent-profile-live-installation.mjs"

assert 'authority-inactive inventory exists' test -f "$LIST"
assert 'authority-inactive inventory has 37 suites' test "$(wc -l < "$LIST" | tr -d ' ')" = '37'
assert 'authority-inactive inventory is sorted and unique' sh -c 'test "$(sort "$1")" = "$(cat "$1")"' _ "$LIST"
assert 'assertion harness syntax is valid' bash -n "$HARNESS"
assert 'assertion harness reads authority-inactive inventory' grep -Fq 'authority-inactive-test-suites.txt' "$HARNESS"
assert 'assertion harness exact-matches suite basenames' grep -Fq 'grep -Fqx "${base}"' "$HARNESS"
assert 'retired generator inventory exists' test -f "$RETIRED_GENERATORS"
assert 'retired generator inventory has 8 suites' test "$(wc -l < "$RETIRED_GENERATORS" | tr -d ' ')" = '8'
assert 'retired generator inventory is sorted and unique' sh -c 'test "$(sort "$1")" = "$(cat "$1")"' _ "$RETIRED_GENERATORS"
assert 'retired direct E2 inventory exists' test -f "$RETIRED_DIRECT_E2"
assert 'retired direct E2 inventory has 3 suites' test "$(wc -l < "$RETIRED_DIRECT_E2" | tr -d ' ')" = '3'
assert 'retired direct E2 inventory is sorted and unique' sh -c 'test "$(sort "$1")" = "$(cat "$1")"' _ "$RETIRED_DIRECT_E2"
assert 'retired direct E1 inventory exists' test -f "$RETIRED_DIRECT_E1"
assert 'retired direct E1 inventory has 2 suites' test "$(wc -l < "$RETIRED_DIRECT_E1" | tr -d ' ')" = '2'
assert 'retired direct E1 inventory is sorted and unique' sh -c 'test "$(sort "$1")" = "$(cat "$1")"' _ "$RETIRED_DIRECT_E1"
assert 'harness reads retired generator inventory' grep -Fq 'retired-positive-generator-test-suites.txt' "$HARNESS"
assert 'harness reads retired direct E2 inventory' grep -Fq 'retired-direct-e2-test-suites.txt' "$HARNESS"
assert 'harness reads retired direct E1 inventory' grep -Fq 'retired-direct-e1-test-suites.txt' "$HARNESS"
assert 'Stage 2 source-bound suite is superseded after Stage 3' grep -Fqx 'test-e2-positive-proof-generator-retirement-v0.mjs' "$SUPERSEDED"
assert 'Stage 3 source-bound suite is superseded after E1 generator retirement' grep -Fqx 'test-e2-direct-request-factory-source-retirement-v0.mjs' "$SUPERSEDED"
assert 'E1 generator source-bound suite is superseded after direct E1 retirement' grep -Fqx 'test-e1-positive-proof-generator-retirement-v0.mjs' "$SUPERSEDED"
assert 'direct E1 source-bound suite is superseded after installer residue cleanup' grep -Fqx 'test-e1-direct-adapter-factory-source-retirement-v0.mjs' "$SUPERSEDED"
assert 'assertion harness discovers only named Node tests' grep -Fq 'tests/test-*.mjs' "$HARNESS"
assert 'assertion harness does not glob every tests module' sh -c '! grep -Fq "for t in tests/*.mjs" "$1"' _ "$HARNESS"

while IFS= read -r suite; do
  assert "authority-inactive suite exists: ${suite}" test -f "tests/${suite}"
done < "$LIST"

while IFS= read -r suite; do
  assert "retired positive generator suite exists: ${suite}" test -f "tests/${suite}"
done < "$RETIRED_GENERATORS"

while IFS= read -r suite; do
  assert "retired direct E2 suite exists: ${suite}" test -f "tests/${suite}"
done < "$RETIRED_DIRECT_E2"

while IFS= read -r suite; do
  assert "retired direct E1 suite exists: ${suite}" test -f "tests/${suite}"
done < "$RETIRED_DIRECT_E1"

for active in \
  test-protected-records-fixture-authority-exhausted-routing.mjs \
  test-future-installer-retired-source-residue-cleanup-v0.mjs \
  test-governed-surface-coverage-map.mjs \
  test-governed-surface-coverage-map-cli.mjs \
  test-consequence-lifecycle-map.mjs \
  test-protected-records-named-deployment-profile-real-boundary.mjs \
  test-protected-records-named-deployment-profile-real-boundary-cli.mjs; do
  for inventory in "$LIST" "$RETIRED_GENERATORS" "$RETIRED_DIRECT_E2" "$RETIRED_DIRECT_E1" "$SUPERSEDED"; do
    assert "current refusal/static suite remains active: ${active} not in ${inventory}" \
      sh -c '! grep -Fqx "$1" "$2"' _ "$active" "$inventory"
  done
done

install_guard_line=$(grep -n 'Protected records active persistent profile live installation' "$LIVE_INSTALL" | head -1 | cut -d: -f1)
install_write_line=$(grep -n 'mkdirSync(activationRoot' "$LIVE_INSTALL" | head -1 | cut -d: -f1)
closeout_guard_line=$(grep -n 'Protected records active persistent profile closeout' "$LIVE_INSTALL" | head -1 | cut -d: -f1)
closeout_write_line=$(grep -n 'writeJsonAtomic(liveManifestPath(activationRoot), closeoutManifest)' "$LIVE_INSTALL" | head -1 | cut -d: -f1)
assert 'active persistent install authority guard precedes root creation' test "$install_guard_line" -lt "$install_write_line"
assert 'active persistent closeout authority guard precedes manifest mutation' test "$closeout_guard_line" -lt "$closeout_write_line"
assert 'release-forward suite self-skips before historical execution' sh -c 'test "$(grep -n "^exit 77$" "$1" | head -1 | cut -d: -f1)" -lt "$(grep -n "^set -euo pipefail$" "$1" | head -1 | cut -d: -f1)"' _ tests/test-release-forward-verifier-dry-run.sh
assert 'proof-smoke CLI suite self-skips before imports' sh -c 'test "$(grep -n "process.exit(77)" "$1" | head -1 | cut -d: -f1)" -lt "$(grep -n "^import " "$1" | head -1 | cut -d: -f1)"' _ tests/test-proof-smoke-cli.mjs

printf '\nResults: %d/%d passed, %d failed\n' "$PASS" "$TOTAL" "$FAIL"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
