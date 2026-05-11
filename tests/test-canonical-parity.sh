#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# test-canonical-parity.sh — X1 / GATE-50-A — Canonical-form byte parity.
#
# Verifies that ZLAR's three canonicalization implementations produce
# byte-identical output on ZLAR-constrained payloads:
#
#   IMPL-A  jq -cS                                (bash audit signing + state HMAC)
#   IMPL-B  lib/canonicalize.mjs canonicalize()   (MJS receipts + sig-verify)
#   IMPL-C  lib/human-invariants.mjs canonicalJSON() (MJS state HMAC)
#
# Two tiers of parity (per spec/audit-canonical-parity-spec-v0.1.md §A1):
#   TIER 1 — byte content (no trailing newline). Spec-form claim per
#            lib/sig-verify.mjs:11-15.
#   TIER 2 — raw bytes (with the trailing newline jq's pipeline preserves).
#            Bash-pipeline-form claim per lib/sig-verify.mjs:16-21 and ADR-011.
#
# Inputs: tests/fixtures/canonical-parity-cases.json — ~62 cases spanning
# primitives, key ordering, arrays, nesting, audit-event shapes, state-file
# shapes, HMAC-strip pipelines, and a synthetic single-event replay.
#
# IMPL-A is invoked as a subprocess from Node (jq -cS for ordinary cases;
# jq -cS 'del(._hmac)' for HMAC-STRIP cases so the bash strip pipeline is
# exercised faithfully). IMPL-B is imported from lib/canonicalize.mjs.
# IMPL-C is inlined from lib/human-invariants.mjs:49-54 — inlined because
# importing human-invariants.mjs has module-load side effects (reads the
# HMAC key file at parse time) that would couple this test to operator
# state.
#
# Accepted divergences: a case may set `accept_divergence: true` (with a
# documented `divergence_reason`) to mark a known cross-impl byte gap that
# the project has explicitly accepted as a stopgap pending a producer-side
# fix. Failing assertions for such a case are routed to the
# "Accepted Divergences" bucket — they remain visible in output with full
# byte-level hex, but they do not count toward `fail` and do not affect the
# process exit code. Currently used by case P021 (DEL 0x7F; Option 5b
# Phase 1 per ZLAR-Draft/build/x1-canonicalization-decision-memo-2026-05-11.md).
#
# Pure test, no production code touched. No R041 surface. Failure of any
# non-accepted assertion is informative — the divergence is the test's
# whole point. Per spec §10 boundary, fixing a discovered divergence is
# OUT OF SCOPE for this test; it would be a separate session with its own
# R041 evaluation.
#
# Exit codes:
#   0  — all non-accepted assertions passed
#   1  — one or more non-accepted assertions failed (new divergence discovered)
#   77 — preflight skip (jq or node missing)
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURE="${SCRIPT_DIR}/fixtures/canonical-parity-cases.json"

# Preflight: required tools.
if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not found on PATH (required for IMPL-A)" >&2
    exit 77
fi
if ! command -v node >/dev/null 2>&1; then
    echo "SKIP: node not found on PATH (required for IMPL-B and IMPL-C)" >&2
    exit 77
fi
if [ ! -f "${FIXTURE}" ]; then
    echo "FATAL: missing fixture at ${FIXTURE}" >&2
    exit 1
fi
if [ ! -f "${PROJECT_DIR}/lib/canonicalize.mjs" ]; then
    echo "FATAL: missing lib/canonicalize.mjs at ${PROJECT_DIR}/lib/canonicalize.mjs" >&2
    exit 1
fi

export ZLAR_PROJECT_DIR="${PROJECT_DIR}"
export ZLAR_FIXTURE_PATH="${FIXTURE}"

# Single Node process runs the whole suite — mitigates subprocess overhead
# called out in checklist S-RISK-3. Shells out to jq once per case for IMPL-A.
node --input-type=module - <<'NODE'
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const PROJECT_DIR = process.env.ZLAR_PROJECT_DIR;
const FIXTURE     = process.env.ZLAR_FIXTURE_PATH;

// IMPL-B: imported dynamically so the module path can come from the
// shell-resolved PROJECT_DIR (static import strings can't carry runtime
// state). --input-type=module gives us top-level await.
const { canonicalize } = await import(PROJECT_DIR + '/lib/canonicalize.mjs');

// IMPL-C: inlined verbatim from lib/human-invariants.mjs lines 49-54.
// Inlined (not imported) because importing human-invariants.mjs reads the
// state-HMAC key file at parse time — that side effect would couple this
// pure-test harness to operator key material. The inline copy is what is
// under test as a byte-producer; if the production canonicalJSON ever
// diverges from this inline copy, that itself is a finding.
function canonicalJSON(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
}

const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8'));
const cases = Array.isArray(fixture.cases) ? fixture.cases : [];
if (cases.length === 0) {
  console.error('FATAL: fixture has no cases');
  process.exit(1);
}

let pass  = 0;
let fail  = 0;
let total = 0;
let acceptedDivergences = 0;
const failures = [];
const acceptedList = [];
const acceptedReasonsById = {};

function hex(s) { return Buffer.from(String(s), 'utf8').toString('hex'); }
function blen(s) { return Buffer.byteLength(String(s), 'utf8'); }

// assertEq compares two byte-strings. When the case carries
// accept_divergence: true, a failing assertion is routed to the
// acceptedList bucket instead of the failures bucket — counted as an
// accepted divergence, NOT as a failure. Passing assertions on the same
// case still count as pass (no behavior change). The divergence remains
// visible in output via the dedicated Accepted Divergences section.
function assertEq(label, expected, actual, acceptDivergence) {
  total++;
  if (expected === actual) {
    pass++;
    return true;
  }
  const entry = {
    label,
    expected,
    expected_hex: hex(expected),
    expected_len: blen(expected),
    actual,
    actual_hex: hex(actual),
    actual_len: blen(actual),
  };
  if (acceptDivergence) {
    acceptedDivergences++;
    acceptedList.push(entry);
    return false;
  }
  fail++;
  failures.push(entry);
  return false;
}

function recordError(c, msg, oracleSupplied) {
  const inc = oracleSupplied ? 5 : 4;
  total += inc;
  fail  += inc;
  failures.push({ label: `${c.id} [${c.category}] ${msg}` });
}

console.log('=== X1 / GATE-50-A — canonical-form byte parity ===');
console.log(`  Fixture: ${cases.length} cases.`);
console.log('    IMPL-A  jq -cS                              (bash audit + state HMAC)');
console.log('    IMPL-B  lib/canonicalize.mjs canonicalize() (MJS receipts + sig-verify)');
console.log('    IMPL-C  lib/human-invariants.mjs canonicalJSON() (MJS state HMAC)');
console.log();

const categoryCounts = {};

for (const c of cases) {
  categoryCounts[c.category] = (categoryCounts[c.category] || 0) + 1;
  const oracleSupplied = c.expected_oracle !== undefined && c.expected_oracle !== null;
  const acceptDivergence = c.accept_divergence === true;
  if (acceptDivergence && typeof c.divergence_reason === 'string') {
    acceptedReasonsById[c.id] = c.divergence_reason;
  }

  // HMAC-STRIP cases use the production strip pipelines:
  //   bash : jq -cS 'del(._hmac)' on the full payload
  //   MJS  : destructure _hmac out before canonicalize / canonicalJSON
  // Non-HMAC cases use:
  //   bash : jq -cS '.'    on the payload as-is
  //   MJS  : pass through directly
  let bash_filter = '.';
  let mjs_payload = c.input;
  const bash_input_json = JSON.stringify(c.input);

  if (c.strip_hmac) {
    bash_filter = 'del(._hmac)';
    if (c.input && typeof c.input === 'object' && !Array.isArray(c.input)) {
      const { _hmac, ...rest } = c.input;
      mjs_payload = rest;
    }
  }

  // IMPL-A — jq subprocess.
  let bytes_jq_raw;
  try {
    bytes_jq_raw = execFileSync('jq', ['-cS', bash_filter], {
      input: bash_input_json,
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
      timeout: 5000,
    });
  } catch (e) {
    recordError(c, 'jq invocation FAILED: ' + (e.message || String(e)), oracleSupplied);
    continue;
  }

  // Tier 1: byte content (strip the trailing newline jq's pipeline appends).
  const bytes_jq_stripped = bytes_jq_raw.endsWith('\n')
    ? bytes_jq_raw.slice(0, -1)
    : bytes_jq_raw;

  // IMPL-B
  let bytes_b;
  try {
    bytes_b = canonicalize(mjs_payload, { validate: false });
  } catch (e) {
    recordError(c, 'canonicalize() threw: ' + (e.message || String(e)), oracleSupplied);
    continue;
  }

  // IMPL-C
  let bytes_c;
  try {
    bytes_c = canonicalJSON(mjs_payload);
  } catch (e) {
    recordError(c, 'canonicalJSON() threw: ' + (e.message || String(e)), oracleSupplied);
    continue;
  }

  // Tier 1: byte-content parity across all three implementations.
  assertEq(`${c.id} [${c.category}] Tier1: jq_stripped == IMPL-B`, bytes_jq_stripped, bytes_b, acceptDivergence);
  assertEq(`${c.id} [${c.category}] Tier1: jq_stripped == IMPL-C`, bytes_jq_stripped, bytes_c, acceptDivergence);
  assertEq(`${c.id} [${c.category}] Tier1: IMPL-B == IMPL-C`,      bytes_b,           bytes_c, acceptDivergence);

  // Tier 2: raw-byte invariant. bash-pipeline form = spec form + LF.
  assertEq(`${c.id} [${c.category}] Tier2: jq_raw == jq_stripped + LF`,
           bytes_jq_stripped + '\n', bytes_jq_raw, acceptDivergence);

  // ORACLE-A: hand-computed reference, when supplied. Compared against the
  // Tier-1 byte content (jq output after the newline strip).
  if (oracleSupplied) {
    assertEq(`${c.id} [${c.category}] Oracle: jq_stripped == expected_oracle`,
             c.expected_oracle, bytes_jq_stripped, acceptDivergence);
  }
}

// Failures — show up to MAX_DETAIL with byte-level hex so divergence positions
// are obvious. Everything past MAX_DETAIL is summarized as a count.
if (failures.length > 0) {
  console.log();
  console.log('=== Failures ===');
  const MAX_DETAIL = 25;
  for (const f of failures.slice(0, MAX_DETAIL)) {
    console.log('  FAIL: ' + f.label);
    if (f.expected_hex !== undefined) {
      console.log('    expected (' + f.expected_len + 'B): ' + JSON.stringify(f.expected));
      console.log('    expected hex:    ' + f.expected_hex);
      console.log('    actual   (' + f.actual_len + 'B): ' + JSON.stringify(f.actual));
      console.log('    actual hex:      ' + f.actual_hex);
    }
  }
  if (failures.length > MAX_DETAIL) {
    console.log('  ... and ' + (failures.length - MAX_DETAIL) + ' more failures (suppressed)');
  }
}

// Accepted divergences — named-and-recorded gaps the project has explicitly
// chosen not to gate the suite on. Printed in full with byte-level hex so
// the gap stays visible. The "reason" comes from each case's
// divergence_reason field in the fixture; it is intentionally verbose so a
// new reader can understand the gap without consulting external docs.
if (acceptedList.length > 0) {
  console.log();
  console.log('=== Accepted Divergences (named-and-recorded; not failures) ===');
  const MAX_DETAIL = 25;
  const seenIds = new Set();
  for (const a of acceptedList.slice(0, MAX_DETAIL)) {
    console.log('  ACCEPT: ' + a.label);
    if (a.expected_hex !== undefined) {
      console.log('    expected (' + a.expected_len + 'B): ' + JSON.stringify(a.expected));
      console.log('    expected hex:    ' + a.expected_hex);
      console.log('    actual   (' + a.actual_len + 'B): ' + JSON.stringify(a.actual));
      console.log('    actual hex:      ' + a.actual_hex);
    }
    const idMatch = a.label.match(/^([A-Z]+\d+)/);
    if (idMatch && acceptedReasonsById[idMatch[1]] && !seenIds.has(idMatch[1])) {
      console.log('    reason: ' + acceptedReasonsById[idMatch[1]]);
      seenIds.add(idMatch[1]);
    }
  }
  if (acceptedList.length > MAX_DETAIL) {
    console.log('  ... and ' + (acceptedList.length - MAX_DETAIL) + ' more accepted divergences (suppressed)');
  }
}

console.log();
console.log('  Cases by category: ' + Object.entries(categoryCounts).map(([k,v]) => `${k}=${v}`).join(', '));
console.log();
const accSuffix = acceptedDivergences > 0
  ? `, ${acceptedDivergences} accepted divergence${acceptedDivergences === 1 ? '' : 's'}`
  : '';
console.log(`=== Results: ${pass}/${total} passed, ${fail} failed${accSuffix} ===`);

process.exit(fail > 0 ? 1 : 0);
NODE
