#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Verifier Kit v0.1 — Audit Chain Walker
//
// Walks a ZLAR CC-gate audit JSONL. Each line carries a prev_hash field
// linking it to the SHA-256 of the previous line's raw bytes. The walker
// reports breaks but never interprets, classifies, or scores.
//
// Ported narrow from bin/zlar-audit:1259-1342 (cmd_verify_chain). No
// domain stats, no rule labels, no time-window filtering.
//
// Usage:
//   node verify-chain.mjs <audit.jsonl>
//
// Exit codes:
//   0 = INTACT                 chain walks cleanly
//   1 = BREAK                  ≥1 prev_hash mismatch found
//   2 = ERROR                  bad file, bad line, OC-shape chain
//   4 = BUNDLE-INTEGRITY-FAIL  kit self-test failed
// ═══════════════════════════════════════════════════════════════════════════════

import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

import { runSelfTest, selfTestReport } from './selftest.mjs';
import { PUBLISHER_PUBKEY_PEM, KIT_VERSION } from './lib/kit-publisher.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ─── Self-test FIRST ─────────────────────────────────────────────────────────

const selfTest = runSelfTest({ kitRoot: __dirname, publisherPubkeyPem: PUBLISHER_PUBKEY_PEM });
if (!selfTest.ok) {
  process.stderr.write(`BUNDLE-INTEGRITY-FAIL: ${selfTest.reason}\n`);
  if (selfTest.detail) {
    process.stderr.write(`${selfTest.detail}\n`);
  }
  process.exit(4);
}

// ─── Argument parsing ────────────────────────────────────────────────────────

const args = process.argv.slice(2);
let auditPath = null;
let fromId = null;
let toId = null;
let allBreaks = false;
let jsonOutput = false;

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--from' && i + 1 < args.length) {
    fromId = args[++i];
  } else if (a === '--to' && i + 1 < args.length) {
    toId = args[++i];
  } else if (a === '--all-breaks') {
    allBreaks = true;
  } else if (a === '--json') {
    jsonOutput = true;
  } else if (a === '--help' || a === '-h') {
    printUsage();
    process.exit(0);
  } else if (a === '--self-test-report') {
    process.stdout.write(selfTestReport(selfTest) + '\n');
    process.exit(0);
  } else if (!a.startsWith('-') && !auditPath) {
    auditPath = a;
  }
}

function printUsage() {
  process.stdout.write(`
ZLAR Verifier Kit v0.1 — Audit Chain Walker  (kit ${KIT_VERSION})

USAGE
  node verify-chain.mjs <audit.jsonl>

OPTIONS
  --from <id>          Start walking at this event id
  --to <id>            Stop walking at this event id
  --all-breaks         Enumerate every break (default: report first only)
  --json               Machine-readable output
  --self-test-report   Print self-test detail and exit 0
  --help, -h           Show this help

EXIT CODES
  0   INTACT                  chain walks cleanly
  1   BREAK                   ≥1 prev_hash mismatch found
  2   ERROR                   bad file, bad line, OC-shape chain
  4   BUNDLE-INTEGRITY-FAIL   kit self-test failed

WHAT THIS PROVES
  Internal consistency of one CC-gate audit JSONL. Every non-genesis line
  carries prev_hash = SHA-256(previous line's raw bytes). If every link
  holds, the file has not been edited mid-chain since it was written.

WHAT THIS DOES NOT PROVE
  Cross-gate canonicalization byte-parity (X1 / GATE-50-A open at v0.1).
  The kit walks whichever chain it is handed; if your deployment runs
  both bash and MCP gates with separate JSONLs, run the walker once per
  file.
`.trimEnd() + '\n');
}

// ─── Input validation ────────────────────────────────────────────────────────

if (!auditPath) {
  process.stderr.write('ERROR: audit.jsonl path is required.\n');
  process.stderr.write('Usage: node verify-chain.mjs <audit.jsonl>\n');
  process.exit(2);
}

let auditText;
try {
  auditText = readFileSync(resolve(auditPath), 'utf8');
} catch (err) {
  process.stderr.write(`ERROR: Cannot read audit file: ${auditPath}\n  ${err.message}\n`);
  process.exit(2);
}

// ─── Walk ────────────────────────────────────────────────────────────────────

function sha256hex(bytes) {
  return createHash('sha256').update(bytes, 'utf8').digest('hex');
}

// Split on newline but preserve raw bytes. The bash verifier hashes
// `printf '%s' "${prev_line}"` — line text without trailing newline.
// We match that: split on '\n' and the resulting elements are the raw
// line bytes minus the terminator.
const rawLines = auditText.split('\n');

// Trim trailing empty line if present (file ending with \n)
if (rawLines.length > 0 && rawLines[rawLines.length - 1] === '') {
  rawLines.pop();
}

const breaks = [];
let walked = 0;
let genesisOk = false;
let firstId = null;
let prevLineBytes = null;
let started = !fromId;
let lastEventId = null;
let canonicalForm = 'raw-line-bytes';

for (let i = 0; i < rawLines.length; i++) {
  const lineNum = i + 1;
  const line = rawLines[i];
  if (line.length === 0) continue;

  let event;
  try {
    event = JSON.parse(line);
  } catch (e) {
    process.stderr.write(`ERROR: Line ${lineNum} is not valid JSON.\n  ${e.message}\n`);
    process.exit(2);
  }

  // OC-shape refusal: non-genesis line missing prev_hash. Design H3.
  const hasPrev = Object.prototype.hasOwnProperty.call(event, 'prev_hash');
  if (!hasPrev) {
    if (lineNum === 1 || started) {
      process.stderr.write(`ERROR: OC-shape audit chain detected at line ${lineNum} (missing prev_hash). The kit walks only CC-shape chains; prev_hash is required on every event including genesis (value "genesis").\n`);
      process.exit(2);
    }
  }

  // Skip until --from id is seen
  if (!started) {
    if (event.id === fromId) {
      started = true;
      prevLineBytes = line;
      firstId = event.id;
      // We can't verify the link into --from anchor without a prior line;
      // treat as soft-genesis for the walk.
      genesisOk = true;
      walked++;
      lastEventId = event.id;
      if (toId && event.id === toId) break;
      continue;
    }
    continue;
  }

  if (prevLineBytes === null) {
    // First processed line. Expect prev_hash === "genesis".
    if (event.prev_hash === 'genesis') {
      genesisOk = true;
      walked++;
      firstId = event.id;
      lastEventId = event.id;
      prevLineBytes = line;
      if (toId && event.id === toId) break;
      continue;
    }
    // No genesis marker on line 1; report as ERROR (not a chain break — this
    // file lacks a valid head).
    process.stderr.write(`ERROR: Line ${lineNum} is the first processed event but prev_hash is "${event.prev_hash}" (expected "genesis"). Pass --from <id> to walk a slice instead of the whole file.\n`);
    process.exit(2);
  }

  // Subsequent line: compute SHA-256 of previous raw line bytes, compare to
  // current line's prev_hash. Matches bash verifier exactly:
  //   printf '%s' "${prev_line}" | shasum -a 256
  const expected = sha256hex(prevLineBytes);
  if (event.prev_hash !== expected) {
    const breakRecord = {
      line: lineNum,
      id: event.id || null,
      expected: expected.slice(0, 16),
      got: typeof event.prev_hash === 'string' ? event.prev_hash.slice(0, 16) : null
    };
    breaks.push(breakRecord);
    if (!allBreaks) {
      // Continue counting but stop recording detail
      walked++;
      lastEventId = event.id;
      prevLineBytes = line;
      // Count remaining breaks quietly
      for (let j = i + 1; j < rawLines.length; j++) {
        const nl = rawLines[j];
        if (nl.length === 0) continue;
        let ne;
        try { ne = JSON.parse(nl); } catch (e) { break; }
        const exp = sha256hex(prevLineBytes);
        if (ne.prev_hash !== exp) breaks.push({ line: j + 1, id: ne.id || null, expected: exp.slice(0, 16), got: typeof ne.prev_hash === 'string' ? ne.prev_hash.slice(0, 16) : null });
        prevLineBytes = nl;
        walked++;
        lastEventId = ne.id;
        if (toId && ne.id === toId) break;
      }
      break;
    }
  }

  walked++;
  lastEventId = event.id;
  prevLineBytes = line;
  if (toId && event.id === toId) break;
}

if (!started) {
  process.stderr.write(`ERROR: --from id "${fromId}" not found in audit file.\n`);
  process.exit(2);
}

// ─── Output ──────────────────────────────────────────────────────────────────

const intact = breaks.length === 0;
const firstBreak = breaks.length > 0 ? breaks[0] : null;
const subsequentBreaks = Math.max(0, breaks.length - 1);

if (jsonOutput) {
  const out = {
    events: walked,
    genesis_ok: genesisOk,
    intact,
    first_break: firstBreak,
    subsequent_breaks: subsequentBreaks,
    canonical_form: canonicalForm,
    last_event_id: lastEventId,
    self_test_passed: true,
    kit_version: KIT_VERSION,
    cross_gate_caveat: 'Walks one CC-shape JSONL. Cross-gate parity (X1 / GATE-50-A) is open; pass each gate\'s chain separately.'
  };
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
} else {
  process.stdout.write(`Chain check: ${walked} events.\n`);
  process.stdout.write(`Genesis: ${genesisOk ? (firstId || 'OK') : 'NOT MATCHED'}.\n`);
  if (intact) {
    process.stdout.write('Result: INTACT\n');
  } else {
    process.stdout.write('Result: BREAK\n');
    process.stdout.write(`  First break at line ${firstBreak.line}, event id ${firstBreak.id}.\n`);
    process.stdout.write(`  Expected prev_hash: ${firstBreak.expected}...\n`);
    process.stdout.write(`  Got prev_hash:      ${firstBreak.got}...\n`);
    if (subsequentBreaks > 0) {
      process.stdout.write(`  Subsequent breaks: ${subsequentBreaks}`);
      if (!allBreaks) process.stdout.write(' (run with --all-breaks to enumerate)');
      process.stdout.write('\n');
    }
    if (allBreaks) {
      for (let k = 1; k < breaks.length; k++) {
        const b = breaks[k];
        process.stdout.write(`  Break at line ${b.line} id ${b.id} expected ${b.expected}... got ${b.got}...\n`);
      }
    }
  }
}

process.exit(intact ? 0 : 1);
