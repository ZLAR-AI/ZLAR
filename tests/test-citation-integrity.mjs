// Every artifact a document cites must exist.
//
// This exists because ZLAR's documents have twice cited things that are not
// there, and both survived unnoticed until somebody happened to look:
//
//   * spec/CONFORMANCE.md cites "§5.2 optional identity fields" seven times.
//     The specification has §5 and §5.1. There is no §5.2 and there never was.
//     That citation was load-bearing — it was the stated reason certain payload
//     fields were permitted.
//   * docs/adr/ADR-012 rests its entire analysis on
//     mathematician-verification-v310.md, a property verification classifying
//     things as HOLDS or HOLDS WITH GAPS. That document exists nowhere in this
//     repository, nor in the 200 commits recovered by the 2026-08-16 salvage.
//
// A citation to a missing artifact is indistinguishable from evidence until
// somebody checks. Nobody had. That is the whole failure: not that the documents
// were wrong, but that being wrong was invisible.
//
// This is deliberately mechanical rather than a discipline anyone must remember,
// for the same reason the public-surface boundary is a check rather than a rule.

import { readFileSync, existsSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');

let broken = 0, checked = 0;
const findings = [];

const files = execFileSync('git', ['-C', REPO, 'ls-files', '*.md'], { encoding: 'utf8' })
  .split('\n').filter(Boolean)
  // Recovered history and preserved lanes are evidence, not maintained docs.
  // Holding them to current citation standards would be dishonest about what
  // they are.
  .filter((f) => !f.startsWith('v4/') && !f.includes('/fixtures/'))
  // Archived documents (docs/archive/) are kept as history, byte-for-byte, with
  // their original relative links. The same rule applies.
  .filter((f) => !f.startsWith('docs/archive/'))
  // CHANGELOG names generated release artifacts — verifier packets, dry-run
  // manifests, evidence bundles — which are produced by a build and are not
  // expected in the tree. Those are output names, not citations.
  .filter((f) => f !== 'CHANGELOG.md');

// Section numbers a document defines, from headings like "## 5. Payload Format"
// or "### 5.1 Outcome-Authorizer Coherence".
function sectionsOf(rel) {
  const abs = join(REPO, rel);
  if (!existsSync(abs)) return null;
  const out = new Set();
  for (const line of readFileSync(abs, 'utf8').split('\n')) {
    const m = /^#{1,6}\s+§?(\d+(?:\.\d+)*)/.exec(line);
    if (m) out.add(m[1]);
  }
  return out;
}

const sectionCache = new Map();
const sections = (rel) => {
  if (!sectionCache.has(rel)) sectionCache.set(rel, sectionsOf(rel));
  return sectionCache.get(rel);
};

for (const rel of files) {
  const text = readFileSync(join(REPO, rel), 'utf8');
  const here = dirname(rel);

  // A document may name the specification it is written against. CONFORMANCE.md
  // does exactly this, which is how a §-reference can be resolved to another
  // file rather than to itself.
  const applies = /\*\*Applies to\*\*:.*?`([^`]+\.md)`/.exec(text);
  const companion = applies ? join(here, applies[1]) : null;

  // ── Referenced files ─────────────────────────────────────────────────────
  // Backtick-quoted paths that look like repository files.
  for (const m of text.matchAll(/`([A-Za-z0-9._\/-]+\.(?:md|mjs|js|json|sh|py|c|txt|pub))`/g)) {
    const ref = m[1];
    if (ref.startsWith('http') || ref.includes('*')) continue;
    // A bare filename with no path is usually a generated artifact or an
    // example, not a citation — EXCEPT for .md, where a bare name is how
    // documents actually cite each other. That exception is what catches
    // ADR-012's missing verification document.
    if (!ref.includes('/') && !ref.endsWith('.md')) continue;
    checked++;
    // The estate is larger than this repository. Documents legitimately cite
    // ZLAR-STRATEGY-RULES.md at the workspace root and INVARIANTS.md in
    // Execution-Governance-Base-Layer. Resolving only inside the repo reported
    // those as broken, which would have taught the next reader that
    // cross-estate references are errors — the precise belief that caused eight
    // rediscoveries. Resolve against the workspace root too.
    const ESTATE = join(REPO, '..');
    const candidates = [
      join(REPO, ref), join(REPO, here, ref),
      join(ESTATE, ref), join(ESTATE, 'Execution-Governance-Base-Layer', ref),
    ];
    if (!candidates.some((c) => existsSync(c) && statSync(c).isFile())) {
      broken++;
      findings.push([rel, `references a file that does not exist: ${ref}`]);
    }
  }

  // ── Referenced ADRs ──────────────────────────────────────────────────────
  for (const m of text.matchAll(/\bADR-(\d{3})\b/g)) {
    checked++;
    const n = m[1];
    const adrs = execFileSync('bash', ['-c',
      `ls ${REPO}/docs/adr/ADR-${n}*.md 2>/dev/null || true`], { encoding: 'utf8' }).trim();
    if (!adrs) {
      broken++;
      findings.push([rel, `cites ADR-${n}, which does not exist in docs/adr/`]);
    }
  }

  // ── Referenced sections ──────────────────────────────────────────────────
  // Resolve against the document's declared companion spec if it has one,
  // otherwise against its own headings.
  const target = companion && existsSync(join(REPO, companion)) ? companion : rel;
  const known = sections(target);
  if (known && known.size > 0) {
    for (const m of text.matchAll(/§(\d+(?:\.\d+)*)/g)) {
      checked++;
      const num = m[1];
      // A reference to §5.2 is satisfied only by a §5.2 heading. A §5 heading
      // does not cover it — that leniency is exactly how the CONFORMANCE.md rot
      // survived.
      if (!known.has(num)) {
        broken++;
        findings.push([rel, `cites §${num}, absent from ${target}`]);
      }
    }
  }
}

const seen = new Set();
const unique = findings.filter(([f, m]) => {
  const k = `${f}::${m}`;
  if (seen.has(k)) return false;
  seen.add(k); return true;
});

console.log('\n  CITATION INTEGRITY — does every cited artifact exist\n');
if (unique.length === 0) {
  console.log(`  ${checked} citations checked across ${files.length} documents. All resolve.\n`);
  process.exit(0);
}
let current = '';
for (const [file, msg] of unique) {
  if (file !== current) { console.log(`  ${file}`); current = file; }
  console.log(`      ${msg}`);
}
console.log(`\n  ${checked} citations checked across ${files.length} documents`);
console.log(`  ${unique.length} do not resolve\n`);
console.log('  A citation to a missing artifact is indistinguishable from evidence');
console.log('  until somebody checks. Fix the citation or create the artifact.\n');
process.exit(1);
