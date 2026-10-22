import { createHash, randomUUID } from "node:crypto";
import { describe, it, expect, vi } from "vitest";
import pg from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import { eq } from "drizzle-orm";
import * as schema from "../src/db/schema.js";
import { TokenStore } from "../src/auth/token-store.js";

// This suite MUST only target an explicitly provisioned disposable database with
// migrations applied. It never reads the service's runtime DATABASE_URL.
const url = process.env.WHOOP_TEST_DB_DISPOSABLE === "true" ? process.env.WHOOP_TEST_DATABASE_URL : undefined;
const key = "a".repeat(64);
function gate() {
  let open!: () => void;
  const promise = new Promise<void>((resolve) => { open = resolve; });
  return { open, promise };
}
async function waitForLock(observer: pg.PoolClient, pid: number) {
  // Observe the competing transaction actually blocking in PostgreSQL, rather
  // than assuming that a sleep or promise start established the interleaving.
  for (let i = 0; i < 200; i++) {
    const r = await observer.query("SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1", [pid]);
    if (r.rows[0]?.wait_event_type === "Lock") return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("Expected concurrent transaction did not reach a database lock");
}
async function fixture() {
  const pool = new pg.Pool({ connectionString: url!, max: 3,
    options: "-c statement_timeout=5000 -c lock_timeout=4000" });
  const [a, b, observer] = await Promise.all([pool.connect(), pool.connect(), pool.connect()]);
  const dbA = drizzle(a, { schema });
  const dbB = drizzle(b, { schema });
  const [user] = await dbA.insert(schema.users).values({ whoopUserId: `concurrency-fixture-${randomUUID()}` }).returning();
  const codeHash = createHash("sha256").update(randomUUID()).digest("hex");
  await dbA.insert(schema.oauthAuthCodes).values({ codeHash, userId: user.id,
    clientId: "fixture-client", redirectUri: "https://client.example/cb", codeChallenge: "fixture-challenge",
    scopes: ["mcp"], expiresAt: new Date(Date.now() + 60000) });
  const pidA = (await a.query("SELECT pg_backend_pid() AS pid")).rows[0].pid as number;
  const pidB = (await b.query("SELECT pg_backend_pid() AS pid")).rows[0].pid as number;
  return { dbA, dbB, observer, pidA, pidB, userId: user.id, codeHash,
    async close() {
      try { await dbA.delete(schema.users).where(eq(schema.users.id, user.id)); }
      finally { a.release(); b.release(); observer.release(); await pool.end(); }
    } };
}

describe.skipIf(!url)("revoke-all vs OAuth issuance (real PostgreSQL)", () => {
  it("revokes the token when redemption consumes the code before revoke-all starts", async () => {
    const f = await fixture();
    const consumed = gate(); const release = gate();
    const storeA = new TokenStore(f.dbA, key, vi.fn());
    const storeB = new TokenStore(f.dbB, key, vi.fn());
    const tasks: Promise<unknown>[] = [];
    try {
      // Pause precisely between code consumption and token insertion, reproducing
      // the vulnerable window, while the new transaction still owns the user lock.
      const issuing = storeA.redeemAuthorizationCode(f.codeHash, async () => {
        consumed.open(); await release.promise;
      });
      tasks.push(issuing);
      await Promise.race([consumed.promise, issuing.then(() => {
        throw new Error("Redemption completed before reaching the test gate");
      })]);
      const revoking = storeB.revokeAllMcpTokens(f.userId); tasks.push(revoking);
      await waitForLock(f.observer, f.pidB);
      release.open();
      const token = await issuing;
      await revoking;
      expect(token).toBeTruthy();
      expect(await storeA.resolveMcpToken(token!)).toBeNull();
      expect(await storeA.listMcpTokens(f.userId)).toEqual([]);
    } finally { release.open(); await Promise.allSettled(tasks); await f.close(); }
  }, 15000);

  it("cannot mint a token from an old code when revoke-all wins the lock", async () => {
    const f = await fixture();
    const revoked = gate(); const release = gate();
    // Hold the real revoke transaction open after its SQL statements, so the
    // other connection can observe the old code under MVCC and then block.
    const pausedDb = new Proxy(f.dbB, {
      get(target, property, receiver) {
        if (property === "transaction") return (fn: any) => target.transaction(async (tx) => {
          const result = await fn(tx); revoked.open(); await release.promise; return result;
        });
        return Reflect.get(target, property, receiver);
      },
    });
    const storeA = new TokenStore(f.dbA, key, vi.fn());
    const storeB = new TokenStore(pausedDb, key, vi.fn());
    const tasks: Promise<unknown>[] = [];
    try {
      const revoking = storeB.revokeAllMcpTokens(f.userId); tasks.push(revoking);
      await Promise.race([revoked.promise, revoking.then(() => {
        throw new Error("Revocation completed before reaching the test gate");
      })]);
      const validate = vi.fn();
      const issuing = storeA.redeemAuthorizationCode(f.codeHash, validate); tasks.push(issuing);
      await waitForLock(f.observer, f.pidA);
      release.open(); await revoking;
      expect(await issuing).toBeNull();
      expect(validate).not.toHaveBeenCalled();
      expect(await storeA.listMcpTokens(f.userId)).toEqual([]);
    } finally { release.open(); await Promise.allSettled(tasks); await f.close(); }
  }, 15000);
});
