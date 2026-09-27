// The destination's own receipt chain.
//
// It lives at the destination, like every other load-bearing part of Cyan. A
// receipt log held by the agent is the agent's account of itself; a receipt log
// held by a central service is that service's account. Neither is what an
// auditor needs when the question is "what did the destination actually do".
//
// Sequence and linkage are assigned INSIDE the lock, together with the
// signature. If they were assigned outside it, two concurrent crossings could
// take the same position, or link to the same predecessor, and the chain would
// fork — a fork being indistinguishable from a deletion to anyone checking it
// later. The lock is the same discipline the grant store uses, for the same
// reason: the ordering has to be decided by one party at a time.
//
// This is an append-only file. Nothing here prevents an operator with disk
// access from truncating it. That is not a gap in the design — it is the
// boundary of what a log can promise. What the chain gives is that any such
// truncation is VISIBLE to anyone holding a later receipt or an earlier head.

import { mkdirSync, writeFileSync, readFileSync, appendFileSync, statSync, unlinkSync } from 'node:fs';
import { join as pjoin } from 'node:path';
import { receiptHash } from './receipt.mjs';

const LOCK_STALE_MS = 10_000;

export class ReceiptLog {
  constructor(dir, destinationId = null) {
    this.dir = dir;
    this.destinationId = destinationId;
    mkdirSync(dir, { recursive: true });
  }

  #file() { return pjoin(this.dir, 'receipts.jsonl'); }
  #headFile() { return pjoin(this.dir, 'head.json'); }
  #lockFile() { return pjoin(this.dir, 'receipts.lock'); }

  #withLock(fn) {
    const lock = this.#lockFile();
    const deadline = Date.now() + LOCK_STALE_MS * 2;
    for (;;) {
      try {
        writeFileSync(lock, String(process.pid), { flag: 'wx' });
        break;
      } catch (err) {
        if (err.code !== 'EEXIST') throw err;
        // A crashed holder must not wedge a destination permanently. Re-entering
        // after a stale lock is safer than refusing to receipt anything forever —
        // an unreceipted execution is worse than a contended one.
        try {
          if (Date.now() - statSync(lock).mtimeMs > LOCK_STALE_MS) unlinkSync(lock);
        } catch { /* someone else broke it first */ }
        if (Date.now() > deadline) throw new Error('receipt log lock timeout');
      }
    }
    try { return fn(); } finally { try { unlinkSync(lock); } catch {} }
  }

  head() {
    try { return JSON.parse(readFileSync(this.#headFile(), 'utf8')); }
    catch { return { seq: 0, hash: null }; }
  }

  // makeBody(seq, prev) -> body. Signing happens inside the lock so the signed
  // bytes and the position they claim are decided in one indivisible step.
  append(makeBody, signFn) {
    return this.#withLock(() => {
      const { seq, hash } = this.head();
      const body = makeBody(seq + 1, hash);
      const record = { body, sig: signFn ? signFn(body) : null };

      appendFileSync(this.#file(), `${JSON.stringify(record)}\n`);
      writeFileSync(this.#headFile(), JSON.stringify({ seq: body.seq, hash: receiptHash(record) }));
      return record;
    });
  }

  // Publish a signed statement of how long this chain currently is. Taken under
  // the lock so the claim cannot straddle an append and describe a length that
  // never existed.
  publishHead(signFn, kid, now = Math.floor(Date.now() / 1000)) {
    return this.#withLock(() => {
      const { seq, hash } = this.head();
      const body = { v: 1, destination: this.destinationId ?? null, kid, seq, hash: hash ?? null, at: now };
      return { body, sig: signFn ? signFn(body) : null };
    });
  }

  // Every record, in order. An unparseable line is surfaced, never skipped —
  // silently dropping a corrupt entry is how a gap becomes invisible.
  read() {
    let raw;
    try { raw = readFileSync(this.#file(), 'utf8'); } catch { return []; }
    return raw.split('\n').filter(Boolean).map((line, i) => {
      try { return JSON.parse(line); }
      catch { return { body: null, sig: null, corrupt: true, line: i + 1 }; }
    });
  }
}
