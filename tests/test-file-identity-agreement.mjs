// Do the producer and the consumer agree on what a file's bytes ARE?
//
// This exists because the same defect has now bitten ZLAR three times, in three
// disguises, and each time it was diagnosed as a fresh problem:
//
//   * 2026-08 — the privileged helper published a guardian as root:wheel 0500
//     and the unprivileged installer could not then read the object it had just
//     asked root to create. Thirty-one successors were built for it. The fix was
//     two constants.
//   * 2026-04 — ADR-011 found three canonical JSON forms in circulation,
//     differing by a trailing newline that a shell pipeline adds and a
//     serializer does not.
//   * 2026-08-16 — candidate 044's Telegram token is pinned WITHOUT a trailing
//     newline in both its runtime manifest and its signed policy, and the file
//     on disk HAS one. One byte, blocking an activation.
//
// The common shape: a producer writes a file, a consumer hashes it, and nobody
// wrote down which bytes were meant. Then it lands on a path no ordinary test
// can reach — a privileged install, an attended run — and stays invisible.
//
// ── The rule this test enforces ─────────────────────────────────────────────
//
// A pinned file's identity is the SHA-256 of its exact bytes on disk, read
// through a descriptor, with nothing added and nothing stripped at either end.
//
// The consumer side of that discipline already exists and is good:
// `sha256_pinned()` in candidate 044's evidence store resolves the path, opens
// O_NOFOLLOW so a symlink cannot redirect it, verifies on the descriptor rather
// than the name, and hashes exactly what it read.
//
// What has never been written down is the PRODUCER side: if something else will
// pin this file, write the bytes you intend to be pinned and no others. In
// particular, a shell that ends a file with `echo` or a heredoc adds a newline
// the producer never meant and the consumer never expects.
//
// ADR-011 governs canonical JSON. It does not govern opaque files — tokens,
// keys, binaries — and that is exactly the gap the 2026-08-16 token fell into.
//
// ── What this test does ─────────────────────────────────────────────────────
//
// For every manifest in the repository that pins files by hash, verify each pin.
// A mismatch fails. But a mismatch that RESOLVES when a trailing newline is
// stripped is reported separately and loudly, because that is not a broken file
// — it is this defect class, wearing its third disguise.

import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');

let pass = 0, fail = 0, hazards = 0;
const lines = [];
const ok = (m) => { pass++; lines.push(['  OK    ', m]); };
const bad = (m) => { fail++; lines.push(['  FAIL  ', m]); };
const hazard = (m) => { hazards++; lines.push(['  HAZARD', m]); };

const sha = (buf) => createHash('sha256').update(buf).digest('hex');

// Manifests vary in shape. Rather than hardcode one, accept anything that
// yields {path, sha256} pairs, and say plainly when a manifest shape is not
// understood instead of silently passing it.
function pinsFrom(doc) {
  const out = [];
  const visit = (node) => {
    if (Array.isArray(node)) return node.forEach(visit);
    if (!node || typeof node !== 'object') return;
    const path = node.path ?? node.file ?? node.name;
    const digest = node.sha256 ?? node.hash ?? node.digest;
    if (typeof path === 'string' && typeof digest === 'string' && /^[0-9a-f]{64}$/.test(digest)) {
      out.push({ path, digest });
    }
    for (const v of Object.values(node)) visit(v);
  };
  visit(doc);
  return out;
}

const manifests = execFileSync('git', ['-C', REPO, 'ls-files'], { encoding: 'utf8' })
  .split('\n')
  .filter((f) => /manifest.*\.json$/i.test(f))
  .filter((f) => !f.includes('example'));

// The verifier kit's own manifest is the one manifest a stranger ever sees, and
// it lives under dist/, which is gitignored — so `git ls-files` cannot find it
// and nothing was checking it. If a kit has been built, check it too. An
// external verifier's first impression of ZLAR is whether this file is honest.
for (const kit of execFileSync('bash', ['-c',
  `ls -d ${REPO}/dist/zlar-verifier-kit-*/ 2>/dev/null || true`], { encoding: 'utf8' })
  .split('\n').filter(Boolean)) {
  const m = join(kit, 'MANIFEST.json');
  if (existsSync(m)) manifests.push(m.startsWith(REPO) ? m.slice(REPO.length + 1) : m);
}

if (manifests.length === 0) bad('no manifests found to check — this test is not exercising anything');

for (const rel of manifests) {
  const abs = join(REPO, rel);
  let doc;
  try { doc = JSON.parse(readFileSync(abs, 'utf8')); }
  catch { bad(`${rel}: unparseable`); continue; }

  const pins = pinsFrom(doc);
  if (pins.length === 0) { lines.push(['  SKIP  ', `${rel}: no path/hash pairs recognised`]); continue; }

  let checked = 0, missing = 0;
  for (const { path, digest } of pins) {
    // Manifests in this repo use both conventions: relative to the manifest, and
    // relative to the repository root. Resolving only one of them made this test
    // report "targets absent" and PASS — a detector built to catch false
    // assurance, providing false assurance. Try both, and treat an unresolvable
    // pin as a failure below rather than as a shrug.
    const candidates = path.startsWith('/')
      ? [path]
      : [join(dirname(abs), path), join(REPO, path)];
    const target = candidates.find((c) => existsSync(c));
    if (!target) { missing++; continue; }
    const raw = readFileSync(target);
    if (sha(raw) === digest) { checked++; continue; }

    // The tell. If stripping trailing whitespace makes it match, the file is not
    // corrupt — the producer added bytes the consumer never expected.
    const stripped = Buffer.from(raw.toString('binary').replace(/\s+$/, ''), 'binary');
    if (sha(stripped) === digest) {
      hazard(`${rel}: ${path} matches only after stripping trailing whitespace — producer/consumer disagree on the bytes`);
    } else {
      bad(`${rel}: ${path} does not match its pin`);
    }
  }
  // A manifest that pins files none of which can be found verifies nothing while
  // appearing to pass. That is worse than having no manifest, because it is
  // mistaken for assurance. Say so.
  if (checked === 0 && missing > 0) {
    bad(`${rel}: pins ${missing} files and NONE resolve — this manifest verifies nothing`);
  } else if (missing > 0) {
    bad(`${rel}: ${checked} pins verified but ${missing} targets could not be found`);
  } else if (checked > 0) {
    ok(`${rel}: ${checked} pins verified`);
  }
}

console.log('\n  FILE IDENTITY AGREEMENT — do producer and consumer agree on the bytes\n');
for (const [tag, text] of lines) console.log(`${tag} ${text}`);
console.log(`\n  ${pass} checks passed, ${fail} failed, ${hazards} newline-class hazards\n`);
if (hazards > 0) {
  console.log('  A hazard is not a corrupt file. It is a producer that wrote bytes the');
  console.log('  consumer did not expect — the defect class of ADR-011 and of the');
  console.log('  2026-08-16 token. Fix the producer, not the pin.\n');
}
console.log(`  Results: ${pass} passed, ${fail + hazards} failed`);
process.exit(fail === 0 && hazards === 0 ? 0 : 1);
