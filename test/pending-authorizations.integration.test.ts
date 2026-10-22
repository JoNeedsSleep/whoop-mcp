import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import pg from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import * as schema from "../src/db/schema.js";
import { admitPendingAuthorization, MAX_PENDING_AUTHORIZATIONS, PENDING_CLEANUP_BATCH } from "../src/auth/pending-authorizations.js";

// Opt-in disposable PostgreSQL only, with reviewed migrations already applied.
// Each fixture clones the migrated pending table into its own temporary schema;
// it never modifies rows in the public/service tables or runs migrations itself.
const url = process.env.WHOOP_TEST_DB_DISPOSABLE === "true" ? process.env.WHOOP_TEST_DATABASE_URL : undefined;
const row = (expired = false) => ({ whoopState: randomUUID(), payload: { fixture: true },
  expiresAt: new Date(Date.now() + (expired ? -60000 : 60000)) });
function gate() {
  let open!: () => void;
  const promise = new Promise<void>((resolve) => { open = resolve; });
  return { open, promise };
}
async function fixture() {
  const pool = new pg.Pool({ connectionString: url!, max: 2,
    options: "-c statement_timeout=5000 -c lock_timeout=4000" });
  const [a, b] = await Promise.all([pool.connect(), pool.connect()]);
  const name = `pending_admission_${randomUUID().replaceAll("-", "")}`;
  try {
    // Identifier is generated locally from a UUID, never from connection/user input.
    await a.query(`CREATE SCHEMA "${name}"`);
    await a.query(`CREATE TABLE "${name}".pending_authorizations (LIKE public.pending_authorizations INCLUDING ALL)`);
    await Promise.all([a.query(`SET search_path TO "${name}"`), b.query(`SET search_path TO "${name}"`)]);
    const dbA = drizzle(a, { schema });
    const dbB = drizzle(b, { schema });
    return { dbA, dbB,
      async close() {
        try { await a.query(`DROP SCHEMA "${name}" CASCADE`); }
        finally { a.release(); b.release(); await pool.end(); }
      } };
  } catch (error) {
    try { await a.query(`DROP SCHEMA IF EXISTS "${name}" CASCADE`); }
    finally { a.release(); b.release(); await pool.end(); }
    throw error;
  }
}

describe.skipIf(!url)("pending authorization admission (real PostgreSQL)", () => {
  it("denies a concurrent writer while the last available slot is uncommitted", async () => {
    const f = await fixture();
    const inserted = gate(); const release = gate();
    const tasks: Promise<unknown>[] = [];
    try {
      await f.dbA.insert(schema.pendingAuthorizations).values(Array.from({ length: MAX_PENDING_AUTHORIZATIONS - 1 }, () => row()));
      const pausedDb = new Proxy(f.dbA, {
        get(target, property, receiver) {
          if (property === "transaction") return (fn: any, options?: Parameters<typeof target.transaction>[1]) => target.transaction(async (tx) => {
            const result = await fn(tx); inserted.open(); await release.promise; return result;
          }, options);
          return Reflect.get(target, property, receiver);
        },
      });
      const first = admitPendingAuthorization(pausedDb, row()); tasks.push(first);
      await Promise.race([inserted.promise, first.then(() => { throw new Error("Admission never reached the transaction gate"); })]);
      // Connection B cannot see A's pending insertion yet. Without the shared
      // lock both would observe 99 rows and admit a hundred-and-first state.
      expect(await admitPendingAuthorization(f.dbB, row())).toBe(false);
      release.open(); expect(await first).toBe(true);
      expect(await admitPendingAuthorization(f.dbB, row())).toBe(false);
      expect(await f.dbB.select().from(schema.pendingAuthorizations)).toHaveLength(MAX_PENDING_AUTHORIZATIONS);
    } finally { release.open(); await Promise.allSettled(tasks); await f.close(); }
  }, 15000);

  it("commits bounded expired cleanup even while an inherited backlog prevents admission", async () => {
    const f = await fixture();
    try {
      const legacyCount = MAX_PENDING_AUTHORIZATIONS + 2 * PENDING_CLEANUP_BATCH + 10;
      await f.dbA.insert(schema.pendingAuthorizations).values(Array.from({ length: legacyCount }, () => row(true)));
      expect(await admitPendingAuthorization(f.dbA, row())).toBe(false);
      expect(await f.dbA.select().from(schema.pendingAuthorizations)).toHaveLength(legacyCount - PENDING_CLEANUP_BATCH);
      expect(await admitPendingAuthorization(f.dbA, row())).toBe(false);
      expect(await f.dbA.select().from(schema.pendingAuthorizations)).toHaveLength(legacyCount - 2 * PENDING_CLEANUP_BATCH);
      expect(await admitPendingAuthorization(f.dbA, row())).toBe(true);
      expect(await f.dbA.select().from(schema.pendingAuthorizations)).toHaveLength(legacyCount - 3 * PENDING_CLEANUP_BATCH + 1);
    } finally { await f.close(); }
  });

  it("never cleans unexpired flows to make room and reclaims expired slots", async () => {
    const f = await fixture();
    try {
      const active = Array.from({ length: MAX_PENDING_AUTHORIZATIONS - 1 }, () => row());
      await f.dbA.insert(schema.pendingAuthorizations).values([...active, row(true)]);
      const next = row();
      expect(await admitPendingAuthorization(f.dbA, next)).toBe(true);
      const remaining = await f.dbA.select().from(schema.pendingAuthorizations);
      expect(new Set(remaining.map((pending) => pending.whoopState)))
        .toEqual(new Set([...active.map((pending) => pending.whoopState), next.whoopState]));
    } finally { await f.close(); }
  });
});
