import { DatabaseSync } from "node:sqlite";
import { randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, statSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";

// One dedicated gateway replica; its durable database is never shared with WHOOP.
// SQLite transactions also coordinate separate handles to the same local file.
export class GatewayStore {
  constructor({ filename, now = Date.now }) {
    if (filename !== ":memory:") {
      if (typeof filename !== "string" || !isAbsolute(filename)) throw new Error("Invalid gateway database path");
      const parent = statSync(dirname(filename));
      if (!parent.isDirectory() || (parent.mode & 0o077) || parent.uid !== process.getuid()) throw new Error("Private gateway database directory required");
      const fd = openSync(filename, constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
      try {
        const file = fstatSync(fd);
        if (!file.isFile() || (file.mode & 0o077) || file.uid !== process.getuid()) throw new Error("Private gateway database file required");
      } finally { closeSync(fd); }
    }
    this.now = now;
    this.db = new DatabaseSync(filename);
    this.depth = 0;
    this.db.exec(`PRAGMA busy_timeout=1000; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS records (
        kind TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, expires INTEGER NOT NULL,
        PRIMARY KEY(kind,key));
      CREATE INDEX IF NOT EXISTS records_expiry ON records(expires);
      CREATE TABLE IF NOT EXISTS rate_events (bucket TEXT NOT NULL, at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS rate_bucket_time ON rate_events(bucket,at);
      CREATE TABLE IF NOT EXISTS tool_lease (id INTEGER PRIMARY KEY CHECK(id=1), token TEXT NOT NULL, expires INTEGER NOT NULL);`);
  }
  transaction(fn) {
    if (this.depth) return fn();
    this.db.exec("BEGIN IMMEDIATE"); this.depth++;
    try {
      const value = fn();
      if (value?.then) throw new Error("Gateway transactions must be synchronous");
      this.db.exec("COMMIT"); return value;
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
    finally { this.depth--; }
  }
  cleanup() {
    this.db.prepare("DELETE FROM records WHERE rowid IN (SELECT rowid FROM records WHERE expires <= ? LIMIT 100)").run(this.now());
  }
  get(kind, key) {
    const row = this.db.prepare("SELECT value, expires FROM records WHERE kind=? AND key=? AND expires>?").get(kind, key, this.now());
    return row ? { ...JSON.parse(row.value), expiresAt: row.expires } : null;
  }
  put(kind, key, value, expiresAt, cap = 100) {
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= this.now()) return false;
    return this.transaction(() => {
      this.cleanup();
      if (this.db.prepare("SELECT count(*) AS n FROM records WHERE kind=?").get(kind).n >= cap) return false;
      this.db.prepare("INSERT INTO records(kind,key,value,expires) VALUES(?,?,?,?)")
        .run(kind, key, JSON.stringify(value), expiresAt);
      return true;
    });
  }
  replace(kind, key, value) {
    return this.db.prepare("UPDATE records SET value=? WHERE kind=? AND key=? AND expires>?")
      .run(JSON.stringify(value), kind, key, this.now()).changes === 1;
  }
  delete(kind, key) { return this.db.prepare("DELETE FROM records WHERE kind=? AND key=?").run(kind, key).changes === 1; }
  list(kind) {
    return this.db.prepare("SELECT key,value,expires FROM records WHERE kind=? AND expires>? ORDER BY expires LIMIT 100")
      .all(kind, this.now()).map((row) => ({ key: row.key, ...JSON.parse(row.value), expiresAt: row.expires }));
  }
  deleteWhere(kind, predicate) {
    for (const row of this.list(kind)) if (predicate(row)) this.delete(kind, row.key);
  }
  takeRateLimit(bucket, limit, windowMs) {
    return this.transaction(() => {
      const now = this.now();
      this.db.prepare("DELETE FROM rate_events WHERE bucket=? AND at<=?").run(bucket, now - windowMs);
      if (this.db.prepare("SELECT count(*) AS n FROM rate_events WHERE bucket=?").get(bucket).n >= limit) return false;
      this.db.prepare("INSERT INTO rate_events(bucket,at) VALUES(?,?)").run(bucket, now);
      return true;
    });
  }
  acquireToolCall({ limit = 30, windowMs = 3600000, leaseMs = 15000 } = {}) {
    return this.transaction(() => {
      const current = this.db.prepare("SELECT expires FROM tool_lease WHERE id=1").get();
      if (current && current.expires > this.now()) return null;
      if (!this.takeRateLimit("tools-owner", limit, windowMs)) return null;
      const token = randomBytes(32).toString("base64url");
      this.db.prepare("INSERT OR REPLACE INTO tool_lease(id,token,expires) VALUES(1,?,?)").run(token, this.now() + leaseMs);
      return token;
    });
  }
  releaseToolCall(token) { this.db.prepare("DELETE FROM tool_lease WHERE id=1 AND token=?").run(token); }
  close() { this.db.close(); }
}
