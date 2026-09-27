// One destination-owned persistence and serialization domain for Demo 1.
// Allocation debit, challenge/A consumption, active bytes, P, and terminal R
// share one SQLite commit. Split JSON/file stores are intentionally ineligible.

import { existsSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

import { canonical } from './demo1-protocol.mjs';

export class StoreError extends Error {
  constructor(code, detail = '') {
    super(detail ? `${code}:${detail}` : code);
    this.name = 'StoreError';
    this.code = code;
  }
}

export class Demo1Store {
  constructor({
    databasePath,
    initialRelease,
    policyDigest,
    openingMode = 'initialize_or_open',
  }) {
    if (!['initialize_new', 'open_existing', 'initialize_or_open'].includes(openingMode)) {
      throw new StoreError('opening_mode_invalid');
    }
    const existed = existsSync(databasePath);
    if (openingMode === 'initialize_new' && existed) throw new StoreError('database_already_exists');
    if (openingMode === 'open_existing' && !existed) throw new StoreError('database_missing');
    this.databasePath = databasePath;
    this.db = new DatabaseSync(databasePath, { timeout: 5000 });
    this.db.exec('PRAGMA foreign_keys=ON');
    this.db.exec('PRAGMA journal_mode=WAL');
    this.db.exec('PRAGMA synchronous=FULL');
    this.db.exec('PRAGMA fullfsync=ON');
    this.db.exec('PRAGMA trusted_schema=OFF');
    this.#verifyPragmas();
    if (openingMode === 'open_existing') {
      this.#verifyExistingSchema();
    } else {
      this.#createSchema();
    }
    this.transaction(() => {
      const schemaVersion = this.getMeta('schema_version');
      if (openingMode === 'open_existing' && schemaVersion !== 'zlar.demo1.store.v2') {
        throw new StoreError('schema_identity_mismatch');
      }
      if (schemaVersion === null) this.setMeta('schema_version', 'zlar.demo1.store.v2');
      else if (schemaVersion !== 'zlar.demo1.store.v2') throw new StoreError('schema_identity_mismatch');
      const policy = this.getMeta('recognition_policy_sha256');
      if (policy !== null && policy !== policyDigest) throw new StoreError('recognition_policy_drift');
      if (policy === null) this.setMeta('recognition_policy_sha256', policyDigest);
      const active = this.activeRelease();
      if (active === null) {
        if (openingMode === 'open_existing') throw new StoreError('active_release_missing');
        this.db.prepare(`
          INSERT INTO active_release
            (singleton, generation, staged_object_id, artifact_sha256, artifact_bytes)
          VALUES (1, ?, ?, ?, ?)
        `).run(
          initialRelease.generation,
          initialRelease.stagedObjectId,
          initialRelease.artifactSha256,
          initialRelease.artifactBytes,
        );
      }
    });
  }

  #verifyPragmas() {
    const journal = String(this.db.prepare('PRAGMA journal_mode').get()?.journal_mode ?? '').toLowerCase();
    const synchronous = Number(this.db.prepare('PRAGMA synchronous').get()?.synchronous);
    const fullfsync = Number(this.db.prepare('PRAGMA fullfsync').get()?.fullfsync);
    const foreignKeys = Number(this.db.prepare('PRAGMA foreign_keys').get()?.foreign_keys);
    const trustedSchema = Number(this.db.prepare('PRAGMA trusted_schema').get()?.trusted_schema);
    if (journal !== 'wal') throw new StoreError('journal_mode_not_wal');
    if (synchronous !== 2) throw new StoreError('synchronous_not_full');
    if (fullfsync !== 1) throw new StoreError('fullfsync_not_enabled');
    if (foreignKeys !== 1) throw new StoreError('foreign_keys_not_enabled');
    if (trustedSchema !== 0) throw new StoreError('trusted_schema_enabled');
  }

  #verifyExistingSchema() {
    const expected = [
      'active_release', 'challenges', 'credentials', 'grants', 'metadata',
      'promotion_commits', 'receipts', 'requests',
    ];
    const actual = this.db.prepare(`
      SELECT name FROM sqlite_schema
      WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
      ORDER BY name
    `).all().map((row) => row.name);
    if (actual.length !== expected.length || actual.some((name, index) => name !== expected[index])) {
      throw new StoreError('schema_table_set_mismatch');
    }
  }

  #createSchema() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS challenges (
        challenge_id TEXT PRIMARY KEY,
        record_json TEXT NOT NULL,
        consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0, 1))
      ) STRICT;

      CREATE TABLE IF NOT EXISTS grants (
        grant_id TEXT PRIMARY KEY,
        record_json TEXT NOT NULL,
        maximum_allocation INTEGER NOT NULL CHECK(maximum_allocation = 1),
        spent_allocation INTEGER NOT NULL DEFAULT 0 CHECK(spent_allocation BETWEEN 0 AND maximum_allocation)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS credentials (
        credential_id TEXT PRIMARY KEY,
        grant_id TEXT NOT NULL,
        record_json TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0 CHECK(used IN (0, 1)),
        FOREIGN KEY(grant_id) REFERENCES grants(grant_id)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS active_release (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        generation INTEGER NOT NULL CHECK(generation >= 0),
        staged_object_id TEXT NOT NULL,
        artifact_sha256 TEXT NOT NULL,
        artifact_bytes BLOB NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS promotion_commits (
        commit_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        record_json TEXT NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS receipts (
        sequence INTEGER PRIMARY KEY CHECK(sequence >= 1),
        record_hash TEXT NOT NULL UNIQUE,
        request_id TEXT NOT NULL UNIQUE,
        record_json TEXT NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS requests (
        request_id TEXT PRIMARY KEY,
        outcome TEXT NOT NULL CHECK(outcome IN ('executed', 'refused')),
        receipt_json TEXT NOT NULL
      ) STRICT;
    `);
  }

  transaction(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const value = fn();
      this.db.exec('COMMIT');
      return value;
    } catch (error) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        // Preserve the original error. A failed rollback makes verification fail
        // closed when the connection is reopened.
      }
      throw error;
    }
  }

  close() {
    this.db.close();
  }

  getMeta(key) {
    return this.db.prepare('SELECT value FROM metadata WHERE key = ?').get(key)?.value ?? null;
  }

  setMeta(key, value) {
    this.db.prepare('INSERT INTO metadata(key, value) VALUES(?, ?)').run(key, value);
  }

  activeRelease() {
    const row = this.db.prepare(`
      SELECT generation, staged_object_id, artifact_sha256, artifact_bytes
      FROM active_release WHERE singleton = 1
    `).get();
    if (!row) return null;
    return {
      generation: Number(row.generation),
      stagedObjectId: row.staged_object_id,
      artifactSha256: row.artifact_sha256,
      artifactBytes: Buffer.from(row.artifact_bytes),
    };
  }

  updateActiveRelease({ generation, stagedObjectId, artifactSha256, artifactBytes }) {
    const result = this.db.prepare(`
      UPDATE active_release
      SET generation = ?, staged_object_id = ?, artifact_sha256 = ?, artifact_bytes = ?
      WHERE singleton = 1
    `).run(generation, stagedObjectId, artifactSha256, artifactBytes);
    if (result.changes !== 1) throw new StoreError('active_release_missing');
  }

  insertChallenge(challengeId, record) {
    this.db.prepare(`
      INSERT INTO challenges(challenge_id, record_json, consumed)
      VALUES(?, ?, 0)
    `).run(challengeId, canonical(record));
  }

  challenge(challengeId) {
    const row = this.db.prepare(`
      SELECT record_json, consumed FROM challenges WHERE challenge_id = ?
    `).get(challengeId);
    if (!row) return null;
    return { record: JSON.parse(row.record_json), consumed: Number(row.consumed) === 1 };
  }

  challenges() {
    return this.db.prepare(`
      SELECT challenge_id, record_json, consumed
      FROM challenges ORDER BY challenge_id
    `).all().map((row) => ({
      challengeId: row.challenge_id,
      record: JSON.parse(row.record_json),
      consumed: Number(row.consumed) === 1,
    }));
  }

  consumeChallenge(challengeId) {
    const result = this.db.prepare(`
      UPDATE challenges SET consumed = 1
      WHERE challenge_id = ? AND consumed = 0
    `).run(challengeId);
    if (result.changes !== 1) throw new StoreError('challenge_already_consumed');
  }

  grant(grantId) {
    const row = this.db.prepare(`
      SELECT record_json, maximum_allocation, spent_allocation
      FROM grants WHERE grant_id = ?
    `).get(grantId);
    if (!row) return null;
    return {
      record: JSON.parse(row.record_json),
      body: JSON.parse(row.record_json).body,
      maximumAllocation: Number(row.maximum_allocation),
      spentAllocation: Number(row.spent_allocation),
    };
  }

  insertGrant(grantId, record, maximumAllocation) {
    this.db.prepare(`
      INSERT INTO grants(grant_id, record_json, maximum_allocation, spent_allocation)
      VALUES(?, ?, ?, 0)
    `).run(grantId, canonical(record), maximumAllocation);
  }

  grants() {
    return this.db.prepare(`
      SELECT grant_id, record_json, maximum_allocation, spent_allocation
      FROM grants ORDER BY grant_id
    `).all().map((row) => ({
      grantId: row.grant_id,
      record: JSON.parse(row.record_json),
      maximumAllocation: Number(row.maximum_allocation),
      spentAllocation: Number(row.spent_allocation),
    }));
  }

  debitGrant(grantId, allocationDebit) {
    const result = this.db.prepare(`
      UPDATE grants
      SET spent_allocation = spent_allocation + ?
      WHERE grant_id = ?
        AND spent_allocation + ? <= maximum_allocation
    `).run(allocationDebit, grantId, allocationDebit);
    if (result.changes !== 1) throw new StoreError('grant_allocation_exhausted');
  }

  credential(credentialId) {
    const row = this.db.prepare(`
      SELECT grant_id, record_json, used FROM credentials WHERE credential_id = ?
    `).get(credentialId);
    if (!row) return null;
    return {
      grantId: row.grant_id,
      record: JSON.parse(row.record_json),
      used: Number(row.used) === 1,
    };
  }

  insertCredential(credentialId, grantId, record) {
    this.db.prepare(`
      INSERT INTO credentials(credential_id, grant_id, record_json, used)
      VALUES(?, ?, ?, 0)
    `).run(credentialId, grantId, canonical(record));
  }

  credentials() {
    return this.db.prepare(`
      SELECT credential_id, grant_id, record_json, used
      FROM credentials ORDER BY credential_id
    `).all().map((row) => ({
      credentialId: row.credential_id,
      grantId: row.grant_id,
      record: JSON.parse(row.record_json),
      used: Number(row.used) === 1,
    }));
  }

  consumeCredential(credentialId) {
    const result = this.db.prepare(`
      UPDATE credentials SET used = 1
      WHERE credential_id = ? AND used = 0
    `).run(credentialId);
    if (result.changes !== 1) throw new StoreError('credential_already_used');
  }

  insertCommit(commitId, requestId, record) {
    this.db.prepare(`
      INSERT INTO promotion_commits(commit_id, request_id, record_json)
      VALUES(?, ?, ?)
    `).run(commitId, requestId, canonical(record));
  }

  commits() {
    return this.db.prepare(`
      SELECT record_json FROM promotion_commits ORDER BY rowid
    `).all().map((row) => JSON.parse(row.record_json));
  }

  lastReceipt() {
    const row = this.db.prepare(`
      SELECT sequence, record_hash, record_json
      FROM receipts ORDER BY sequence DESC LIMIT 1
    `).get();
    if (!row) return null;
    return {
      sequence: Number(row.sequence),
      recordHash: row.record_hash,
      record: JSON.parse(row.record_json),
    };
  }

  request(requestId) {
    const row = this.db.prepare(`
      SELECT outcome, receipt_json FROM requests WHERE request_id = ?
    `).get(requestId);
    if (!row) return null;
    return { outcome: row.outcome, receipt: JSON.parse(row.receipt_json) };
  }

  insertReceipt({ record, recordHash, requestId, outcome }) {
    this.db.prepare(`
      INSERT INTO receipts(sequence, record_hash, request_id, record_json)
      VALUES(?, ?, ?, ?)
    `).run(record.body.sequence, recordHash, requestId, canonical(record));
    this.db.prepare(`
      INSERT INTO requests(request_id, outcome, receipt_json)
      VALUES(?, ?, ?)
    `).run(requestId, outcome, canonical(record));
  }

  receipts() {
    return this.db.prepare(`
      SELECT record_json FROM receipts ORDER BY sequence
    `).all().map((row) => JSON.parse(row.record_json));
  }

  projection() {
    const active = this.activeRelease();
    const grants = this.db.prepare(`
      SELECT grant_id, maximum_allocation, spent_allocation
      FROM grants ORDER BY grant_id
    `).all().map((row) => ({
      grantId: row.grant_id,
      maximumAllocation: Number(row.maximum_allocation),
      spentAllocation: Number(row.spent_allocation),
    }));
    const credentials = this.db.prepare(`
      SELECT credential_id, grant_id, used
      FROM credentials ORDER BY credential_id
    `).all().map((row) => ({
      credentialId: row.credential_id,
      grantId: row.grant_id,
      used: Number(row.used) === 1,
    }));
    return {
      active,
      grants,
      credentials,
      commitCount: Number(this.db.prepare('SELECT COUNT(*) AS n FROM promotion_commits').get().n),
      receiptCount: Number(this.db.prepare('SELECT COUNT(*) AS n FROM receipts').get().n),
    };
  }
}
