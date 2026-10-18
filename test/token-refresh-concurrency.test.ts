import { randomUUID } from "node:crypto";
import { describe, it, expect, vi } from "vitest";
import pg from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import { eq } from "drizzle-orm";
import * as schema from "../src/db/schema.js";
import { TokenStore } from "../src/auth/token-store.js";
import { decrypt } from "../src/crypto.js";
import { WhoopClient } from "../src/whoop/client.js";
import { healthSummary } from "../src/whoop/health-summary.js";

// No runtime DATABASE_URL fallback. Provision and migrate a disposable database
// separately before explicitly opting in to this suite.
const url = process.env.WHOOP_TEST_DB_DISPOSABLE === "true" ? process.env.WHOOP_TEST_DATABASE_URL : undefined;
const key = "a".repeat(64);
const tokens = (accessToken: string, refreshToken: string, expiresAt = new Date(Date.now() + 3600_000)) => ({
  accessToken, refreshToken, expiresAt, scopes: ["offline"],
});
function gate() {
  let open!: () => void;
  const promise = new Promise<void>((resolve) => { open = resolve; });
  return { open, promise };
}
async function waitForLock(observer: pg.PoolClient, pid: number) {
  for (let i = 0; i < 200; i++) {
    const result = await observer.query("SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1", [pid]);
    if (result.rows[0]?.wait_event_type === "Lock") return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("Competing refresh/login did not wait for the database lock");
}
async function fixture(expired = true, repeatableReadDefault = false) {
  const pool = new pg.Pool({ connectionString: url!, max: 4,
    options: "-c statement_timeout=10000 -c lock_timeout=8000" });
  const connections = await Promise.all([pool.connect(), pool.connect(), pool.connect(), pool.connect()]);
  const [a, b, c, observer] = connections;
  if (repeatableReadDefault) {
    // Refresh must override a database/role isolation default; otherwise waiting
    // on the unchanged users row can leave a stale whoop_tokens snapshot.
    await Promise.all([a, b, c].map((connection) => connection.query("SET default_transaction_isolation = 'repeatable read'")));
  }
  const dbs = [a, b, c].map((connection) => drizzle(connection, { schema }));
  const pids = await Promise.all([a, b, c].map(async (connection) =>
    (await connection.query("SELECT pg_backend_pid() AS pid")).rows[0].pid as number));
  const whoopUserId = `refresh-fixture-${randomUUID()}`;
  const userId = await new TokenStore(dbs[0], key, vi.fn()).upsertUserAndTokens(whoopUserId, null,
    tokens("old-access", "old-refresh", expired ? new Date(0) : new Date(Date.now() + 3600_000)));
  return { dbs, pids, observer, whoopUserId, userId,
    async storedTokens() {
      const [row] = await dbs[0].select().from(schema.whoopTokens).where(eq(schema.whoopTokens.userId, userId));
      return { access: decrypt(row.accessTokenEnc, key), refresh: decrypt(row.refreshTokenEnc, key) };
    },
    async close() {
      try { await dbs[0].delete(schema.users).where(eq(schema.users.id, userId)); }
      finally { connections.forEach((connection) => connection.release()); await pool.end(); }
    },
  };
}

describe.skipIf(!url)("WHOOP refresh serialization (real PostgreSQL)", () => {
  it("serves all three summary reads with one refresh despite a REPEATABLE READ database default", async () => {
    const f = await fixture(true, true);
    const started = gate(); const release = gate();
    let winner = -1;
    const refresh = vi.fn(async (old: string, connectionIndex: number) => {
      expect(old).toBe("old-refresh");
      // A second use would fail at WHOOP, so make that regression fail here too.
      if (winner !== -1) throw new Error("refresh token already consumed");
      winner = connectionIndex; started.open(); await release.promise;
      return tokens("new-access", "new-refresh");
    });
    const stores = f.dbs.map((db, index) => new TokenStore(db, key, (old) => refresh(old, index)));
    let nextStore = 0;
    const fetchImpl = vi.fn(async (_url: unknown, init?: RequestInit) => {
      expect((init?.headers as Record<string, string>).Authorization).toBe("Bearer new-access");
      return new Response(JSON.stringify({ records: [], next_token: null }), { status: 200 });
    });
    const client = new WhoopClient(() => stores[nextStore++].getValidAccessToken(f.userId),
      async () => { throw new Error("No forced refresh expected"); }, fetchImpl as typeof fetch);
    const tasks: Promise<unknown>[] = [];
    try {
      const summary = healthSummary(client, "2026-10-18"); tasks.push(summary);
      await Promise.race([started.promise, summary.then(() => { throw new Error("No refresh was reached"); })]);
      await Promise.all(f.pids.filter((_pid, index) => index !== winner).map((pid) => waitForLock(f.observer, pid)));
      release.open();
      expect(await summary).toMatchObject({ date: "2026-10-18", status: "NO_DATA" });
      expect(refresh).toHaveBeenCalledTimes(1);
      expect(fetchImpl).toHaveBeenCalledTimes(3);
      expect(await f.storedTokens()).toEqual({ access: "new-access", refresh: "new-refresh" });
    } finally { release.open(); await Promise.allSettled(tasks); await f.close(); }
  }, 15000);

  it("coalesces concurrent and delayed 401 refreshes for the same rejected token", async () => {
    const f = await fixture(false, true);
    const started = gate(); const release = gate();
    const refresh = vi.fn(async (old: string) => {
      expect(old).toBe("old-refresh"); started.open(); await release.promise;
      return tokens("new-access", "new-refresh");
    });
    const stores = f.dbs.map((db) => new TokenStore(db, key, refresh));
    const tasks: Promise<unknown>[] = [];
    try {
      const first = stores[0].forceRefreshAccessToken(f.userId, "old-access"); tasks.push(first);
      await Promise.race([started.promise, first.then(() => { throw new Error("No refresh was reached"); })]);
      const second = stores[1].forceRefreshAccessToken(f.userId, "old-access"); tasks.push(second);
      await waitForLock(f.observer, f.pids[1]);
      release.open();
      expect(await Promise.all([first, second])).toEqual(["new-access", "new-access"]);
      expect(await stores[2].forceRefreshAccessToken(f.userId, "old-access")).toBe("new-access");
      expect(refresh).toHaveBeenCalledTimes(1);
      expect(await f.storedTokens()).toEqual({ access: "new-access", refresh: "new-refresh" });
    } finally { release.open(); await Promise.allSettled(tasks); await f.close(); }
  }, 15000);

  it("does not overwrite a new login after an earlier refresh finishes", async () => {
    const f = await fixture();
    const started = gate(); const release = gate();
    const refresh = vi.fn(async () => {
      started.open(); await release.promise; return tokens("refreshed-access", "refreshed-refresh");
    });
    const stores = f.dbs.map((db) => new TokenStore(db, key, refresh));
    const tasks: Promise<unknown>[] = [];
    try {
      const first = stores[0].getValidAccessToken(f.userId); tasks.push(first);
      await Promise.race([started.promise, first.then(() => { throw new Error("No refresh was reached"); })]);
      const login = stores[1].upsertUserAndTokens(f.whoopUserId, null, tokens("login-access", "login-refresh")); tasks.push(login);
      await waitForLock(f.observer, f.pids[1]);
      release.open(); await first; await login;
      expect(await f.storedTokens()).toEqual({ access: "login-access", refresh: "login-refresh" });
      expect(await stores[2].forceRefreshAccessToken(f.userId, "refreshed-access")).toBe("login-access");
      expect(refresh).toHaveBeenCalledTimes(1);
    } finally { release.open(); await Promise.allSettled(tasks); await f.close(); }
  }, 15000);

  it("releases the transaction after refresh failure and preserves the original credentials", async () => {
    const f = await fixture();
    const failed = new TokenStore(f.dbs[0], key, async () => { throw new Error("upstream unavailable"); });
    const refresh = vi.fn(async (old: string) => {
      expect(old).toBe("old-refresh"); return tokens("new-access", "new-refresh");
    });
    try {
      await expect(failed.getValidAccessToken(f.userId)).rejects.toThrow("upstream unavailable");
      expect(await f.storedTokens()).toEqual({ access: "old-access", refresh: "old-refresh" });
      expect(await new TokenStore(f.dbs[1], key, refresh).getValidAccessToken(f.userId)).toBe("new-access");
      expect(refresh).toHaveBeenCalledTimes(1);
    } finally { await f.close(); }
  }, 15000);
});
