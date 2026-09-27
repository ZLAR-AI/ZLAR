// Destination-side running state for a standing grant.
//
// Invariant 2: authority is a MEASURE THAT DEBITS, not a flag that is checked.
// A flag cannot be spent. This store is where the spending happens, and it lives
// at the destination — because a ceiling enforced anywhere else is advice.
//
// It also holds the composition window: the bounded recent history the guard
// joins against. Composition must be enforced over what actually executed, not
// over a plan the agent declared. An agent that simply never declares a plan
// must not thereby escape.
//
// Concurrency: exclusive lock, read-modify-write, release. A stale lock older
// than LOCK_STALE_MS is broken — a crashed holder must not wedge a destination
// permanently, and re-entering with a stale lock is safer than refusing forever.

import { mkdirSync, writeFileSync, readFileSync, renameSync, unlinkSync, statSync, existsSync } from 'node:fs';
import { join as pjoin } from 'node:path';

const LOCK_STALE_MS = 10_000;

export class GrantStore {
  constructor(dir) {
    this.dir = dir;
    mkdirSync(dir, { recursive: true });
  }

  #file(gid) { return pjoin(this.dir, `${gid}.json`); }
  #lock(gid) { return pjoin(this.dir, `${gid}.lock`); }

  #withLock(gid, fn) {
    const lock = this.#lock(gid);
    const deadline = Date.now() + LOCK_STALE_MS * 2;
    for (;;) {
      try {
        writeFileSync(lock, String(process.pid), { flag: 'wx' });
        break;
      } catch (err) {
        if (err.code !== 'EEXIST') throw err;
        try {
          if (Date.now() - statSync(lock).mtimeMs > LOCK_STALE_MS) unlinkSync(lock);
        } catch { /* someone else broke it first */ }
        if (Date.now() > deadline) throw new Error('grant store lock timeout');
      }
    }
    try { return fn(); } finally { try { unlinkSync(lock); } catch {} }
  }

  #read(gid) {
    try { return JSON.parse(readFileSync(this.#file(gid), 'utf8')); }
    catch { return { gid, executions: [] }; }
  }

  #write(gid, state) {
    const tmp = `${this.#file(gid)}.tmp`;
    writeFileSync(tmp, JSON.stringify(state));
    renameSync(tmp, this.#file(gid));   // atomic replace
  }

  // Effects inside the window, oldest evicted. This is what the guard joins
  // against — a bounded horizon, so state does not grow without limit and
  // ancient history does not forbid present action forever.
  recent(gid, windowSeconds, now) {
    const cutoff = now - windowSeconds;
    return this.#read(gid).executions.filter((e) => e.at >= cutoff);
  }

  // Commit is atomic with the decision: the caller passes a check that runs
  // INSIDE the lock against the current state. If it refuses, nothing is
  // written. Two concurrent actions cannot both pass a ceiling they jointly
  // exceed, because only one of them holds the lock when it decides.
  commitIfAllowed(gid, windowSeconds, now, effect, check) {
    return this.#withLock(gid, () => {
      const state = this.#read(gid);
      const cutoff = now - windowSeconds;
      state.executions = state.executions.filter((e) => e.at >= cutoff);

      const verdict = check(state.executions);
      if (!verdict.ok) return verdict;

      state.executions.push({ ...effect, at: now });
      this.#write(gid, state);
      return verdict;
    });
  }

  spent(gid, windowSeconds, now) {
    const totals = {};
    for (const e of this.recent(gid, windowSeconds, now)) {
      totals[e.class] = (totals[e.class] ?? 0) + (e.measure ?? 0);
    }
    return totals;
  }
}
