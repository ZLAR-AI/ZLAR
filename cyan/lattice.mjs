// The consequence lattice.
//
// Invariant 3: composition is evaluated at the JOIN. A set of individually
// permitted steps has a combined consequence, and that combination can be
// stronger than any part of it. Four hundred innocent actions are how a capable
// loop gets what it wants.
//
// The join is NOT the maximum of the parts. It is:
//   1. per class, the SUM of measures        (volume)
//   2. plus any ELEVATIONS the combination triggers  (emergence)
//
// Elevations are declared, because emergent consequence is domain knowledge —
// only the destination knows that read-access plus disclose equals exfiltration.
// The mechanism is generic; the knowledge is local.

import { CONSEQUENCE_CLASSES } from './envelope.mjs';

// An effect: { class, scope, measure }
export function effectOf(envelope) {
  return {
    class: envelope.consequence,
    scope: envelope.params ?? {},
    measure: envelope.measure ?? 0,
  };
}

function scopeMatches(pattern, scope) {
  if (!pattern) return true;
  return Object.keys(pattern).every((k) => scope[k] === pattern[k]);
}

export function matches(selector, effect) {
  if (selector.class !== effect.class) return false;
  return scopeMatches(selector.scope, effect.scope);
}

// join(effects, rules) -> { totals, elevations, effects }
// totals: class -> summed measure across the set
// elevations: derived effects the combination produces that no member declared
export function join(effects, rules = { elevations: [] }) {
  const totals = {};
  for (const e of effects) {
    if (!CONSEQUENCE_CLASSES.includes(e.class)) throw new Error(`unknown class ${e.class}`);
    totals[e.class] = (totals[e.class] ?? 0) + (e.measure ?? 0);
  }

  const elevations = [];
  for (const rule of rules.elevations ?? []) {
    // Every selector in `when` must be satisfied by some distinct effect —
    // a single action cannot satisfy a two-part combination by itself.
    const used = new Set();
    const satisfied = rule.when.every((sel) => {
      const i = effects.findIndex((e, idx) => !used.has(idx) && matches(sel, e));
      if (i === -1) return false;
      used.add(i);
      return true;
    });
    if (satisfied) {
      elevations.push({
        class: rule.then.class,
        scope: rule.then.scope ?? {},
        measure: rule.then.measure ?? 0,
        because: rule.id,
        note: rule.note ?? null,
      });
    }
  }

  for (const el of elevations) totals[el.class] = (totals[el.class] ?? 0) + el.measure;
  return { totals, elevations, effects };
}

// Constitutional prohibitions. These are not budget ceilings a grant may raise —
// they are combinations that NO ordinary grant can permit. The only way past one
// is a change to the constitution itself, which is a protected action of a
// strictly higher class (invariant 4).
export function prohibited(joined, prohibitions = []) {
  for (const p of prohibitions) {
    const all = [...joined.effects, ...joined.elevations];
    const hit = (p.when ?? []).every((sel) => all.some((e) => matches(sel, e)));
    if (hit && (p.when ?? []).length > 0) return p;
    if (p.class && (joined.totals[p.class] ?? 0) > (p.ceiling ?? Infinity)) return p;
  }
  return null;
}
