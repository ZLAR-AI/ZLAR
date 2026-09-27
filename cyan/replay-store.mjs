// What the guard holds so it can refuse a credential it has already honoured.
//
// Consumption is claimed with an exclusive file create (O_EXCL) — the kernel
// decides the winner, so two concurrent guards racing the same credential cannot
// both execute. The loser gets a refusal, not a second execution.
//
// Retention is bounded by the credential's own expiry: once a credential can no
// longer be presented, the record of it is no longer load-bearing.

import { mkdirSync, writeFileSync, readdirSync, readFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';

export class ReplayStore {
  constructor(dir) {
    this.dir = dir;
    mkdirSync(dir, { recursive: true });
  }

  // Returns true if THIS caller claimed it. False means already consumed.
  claim(cid, exp) {
    try {
      writeFileSync(join(this.dir, `${cid}.json`),
        JSON.stringify({ cid, exp, consumed_at: Math.floor(Date.now() / 1000) }),
        { flag: 'wx' });
      return true;
    } catch (err) {
      if (err.code === 'EEXIST') return false;
      throw err;
    }
  }

  consumed(cid) {
    try { readFileSync(join(this.dir, `${cid}.json`)); return true; } catch { return false; }
  }

  prune(now = Math.floor(Date.now() / 1000)) {
    let pruned = 0;
    for (const f of readdirSync(this.dir)) {
      try {
        const rec = JSON.parse(readFileSync(join(this.dir, f), 'utf8'));
        if (rec.exp < now) { unlinkSync(join(this.dir, f)); pruned++; }
      } catch { /* unreadable record stays — never prune what you cannot read */ }
    }
    return pruned;
  }
}
