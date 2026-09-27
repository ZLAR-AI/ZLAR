// The light profile — propositions, and the number the demo needs.
//
// Two things are being proved here. That ZLAR can be the fast path: routine
// action decided locally, in microseconds, with no human and no network. And
// that being fast costs nothing structural: the floor is identical to the
// heaviest profile, and the attachment point cannot be reached by any tool.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Selector, FLOOR, DECISION, REFUSAL } from '../lib/orange-selector.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const PROFILE = JSON.parse(readFileSync(
  join(HERE, '../etc/policies/profiles/orange-light.policy.json'), 'utf8'));

let pass = 0, fail = 0;
const props = [];
function proves(p, fn) {
  try { fn(); pass++; props.push(['PROVEN ', p]); }
  catch (e) { fail++; props.push(['FAILED ', `${p}  → ${e.message}`]); }
}
const eq = (a, b, m) => { if (a !== b) throw new Error(`${m}: expected ${b}, got ${a}`); };
const sel = () => new Selector(PROFILE);

// ── The fast path ──────────────────────────────────────────────────────────

proves('routine action is ALLOWED — no human, no network, no model', () => {
  const s = sel();
  for (const tool of ['Read', 'Glob', 'Grep', 'TodoWrite', 'WebSearch']) {
    const r = s.decide(tool, { file_path: '/Users/x/project/src/main.js' });
    eq(r.decision, DECISION.ALLOW, `${tool} must be allowed`);
  }
});

proves('consequence ASKS — an accountable human decides, every time', () => {
  const s = sel();
  for (const tool of ['Bash', 'Write', 'Edit', 'Task', 'WebFetch']) {
    const r = s.decide(tool, { file_path: '/Users/x/project/src/main.js' });
    eq(r.decision, DECISION.ASK, `${tool} must ask`);
  }
});

proves('an unrecognised tool is REFUSED, not passed — novelty is where consequence lives', () => {
  const r = sel().decide('SomeBrandNewTool', {});
  eq(r.decision, DECISION.DENY, 'must deny');
  eq(r.domain, 'unknown_tool', 'named as a floor class');
});

// ── The floor is not on the dial ───────────────────────────────────────────

proves('THE ATTACHMENT POINT cannot be reached, by any tool', () => {
  const s = sel();
  // The exact attack that defeated the shipping gate on 2026-08-16.
  for (const tool of ['Edit', 'Write', 'Read', 'NotebookEdit']) {
    const r = s.decide(tool, { file_path: '/Users/example/.claude/settings.json' });
    eq(r.decision, DECISION.DENY, `${tool} on the wrapper must deny`);
    eq(r.domain, 'wrapper_mutation', 'named as wrapper mutation');
  }
});

proves('the gate, the policy, the audit and the keys are equally unreachable', () => {
  const s = sel();
  const cases = [
    ['/Users/v/.zlar/bin/zlar-gate', 'gate_mutation'],
    ['/etc/zlar/off-flag', 'gate_mutation'],
    ['/Users/v/.zlar/etc/policies/active.policy.json', 'policy_mutation'],
    ['/Users/v/.zlar/var/log/audit.jsonl', 'audit_mutation'],
    ['/Users/v/.ssh/id_ed25519', 'key_material'],
  ];
  for (const [path, cls] of cases) {
    const r = s.decide('Edit', { file_path: path });
    eq(r.decision, DECISION.DENY, `${path} must deny`);
    eq(r.domain, cls, `${path} class`);
  }
});

proves('a FAST tool cannot be used to reach a protected surface', () => {
  // Read is on the fast path. It is still refused on the wrapper, because the
  // floor is checked before the tool's own domain.
  const r = sel().decide('Read', { file_path: '/Users/v/.claude/settings.json' });
  eq(r.decision, DECISION.DENY, 'must deny');
});

proves('a profile that omits any floor class does not load', () => {
  for (const missing of FLOOR) {
    const broken = { ...PROFILE, immutable_deny_floor: FLOOR.filter((c) => c !== missing) };
    let threw = false;
    try { new Selector(broken); } catch (e) {
      threw = e.message.startsWith(REFUSAL.FLOOR_INCOMPLETE);
    }
    if (!threw) throw new Error(`omitting ${missing} was accepted`);
  }
});

proves('a profile that ALLOWS a floor class does not load, even if it also declares the floor', () => {
  const broken = {
    ...PROFILE,
    rules: [...PROFILE.rules, { id: 'SOFTER-COPY', action: 'allow', domains: ['wrapper_mutation'] }],
  };
  let threw = false;
  try { new Selector(broken); } catch (e) { threw = e.message.startsWith(REFUSAL.FLOOR_PERMITTED); }
  if (!threw) throw new Error('a second, softer copy of the fence was accepted');
});

proves('a profile whose default is not deny does not load', () => {
  let threw = false;
  try { new Selector({ ...PROFILE, default_action: 'allow' }); }
  catch (e) { threw = e.message === REFUSAL.NO_DEFAULT_DENY; }
  if (!threw) throw new Error('default allow was accepted');
});

proves('an unsigned profile does not load when a verifier is supplied', () => {
  let threw = false;
  try { new Selector(PROFILE, { verifySignature: () => false }); }
  catch (e) { threw = e.message === REFUSAL.UNSIGNED; }
  if (!threw) throw new Error('unsigned profile was accepted');
});

// ── The number ─────────────────────────────────────────────────────────────

const N = 100_000;
const s = sel();
const workload = [
  ['Read', { file_path: '/Users/x/project/src/a.js' }],
  ['Grep', { pattern: 'foo' }],
  ['Glob', { pattern: '**/*.ts' }],
  ['TodoWrite', {}],
  ['Read', { file_path: '/Users/x/project/README.md' }],
];
let allowed = 0, asked = 0, denied = 0;
const t0 = process.hrtime.bigint();
for (let i = 0; i < N; i++) {
  const [tool, input] = workload[i % workload.length];
  const d = s.decide(tool, input);
  if (d.decision === DECISION.ALLOW) allowed++;
  else if (d.decision === DECISION.ASK) asked++;
  else denied++;
}
const nanos = Number(process.hrtime.bigint() - t0);
const perCall = nanos / N;

proves('the fast path costs under 10 microseconds per decision', () => {
  if (perCall > 10_000) throw new Error(`${(perCall / 1000).toFixed(2)}µs per decision`);
});

proves('the fast path touches no human and no network', () => {
  eq(asked, 0, 'human interruptions during routine work');
  eq(denied, 0, 'refusals during routine work');
  eq(allowed, N, 'allowed');
});

// ── Report ─────────────────────────────────────────────────────────────────

console.log('\n  ORANGE LIGHT PROFILE — the fast path\n');
for (const [tag, text] of props) console.log(`  ${tag} ${text}`);
console.log(`\n  ${pass} proven, ${fail} failed`);
console.log(`\n  ${N.toLocaleString()} routine decisions`);
console.log(`  ${(perCall / 1000).toFixed(3)} µs per decision  (${(nanos / 1e6).toFixed(1)} ms total)`);
console.log(`  ${allowed.toLocaleString()} allowed · ${asked} human interruptions · ${denied} refused\n`);
console.log(`  Results: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
