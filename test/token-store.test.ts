import { describe, it, expect, vi } from "vitest";
import { TokenStore } from "../src/auth/token-store.js";
import { encrypt, decrypt } from "../src/crypto.js";
import { getDb, schema } from "../src/db/client.js";
import type { WhoopTokenSet } from "../src/whoop/types.js";

const key = "a".repeat(64);

type FakeRow = {
  userId: string;
  accessTokenEnc: string;
  refreshTokenEnc: string;
  accessTokenExpiresAt: Date;
  scopes: string[];
  updatedAt: Date;
};

// Single-call fixture only; database locking is covered by the real PostgreSQL suite.
function fakeDb(row: FakeRow) {
  const db = {
    select: () => ({
      from: (table: unknown) => table === schema.users
        ? { where: () => ({ for: async () => [{ id: row.userId }] }) }
        : { where: async () => [row] },
    }),
    update: () => ({
      set: (patch: Partial<FakeRow>) => ({
        where: async () => {
          Object.assign(row, patch);
        },
      }),
    }),
  };
  return { ...db, transaction: vi.fn(async (fn: (tx: typeof db) => unknown, _config?: unknown) => fn(db)) };
}

describe("TokenStore.getValidAccessToken (fake db)", () => {
  it("returns stored token when not expired, without calling refresh", async () => {
    const row: FakeRow = {
      userId: "user-1",
      accessTokenEnc: encrypt("current-access", key),
      refreshTokenEnc: encrypt("some-refresh", key),
      accessTokenExpiresAt: new Date(Date.now() + 3600_000),
      scopes: ["offline"],
      updatedAt: new Date(),
    };
    const refresh = vi.fn();
    const store = new TokenStore(fakeDb(row) as any, key, refresh);

    const at = await store.getValidAccessToken("user-1");

    expect(at).toBe("current-access");
    expect(refresh).not.toHaveBeenCalled();
  });

  it("refreshes and persists re-encrypted tokens when expired", async () => {
    const row: FakeRow = {
      userId: "user-1",
      accessTokenEnc: encrypt("old-access", key),
      refreshTokenEnc: encrypt("old-refresh", key),
      accessTokenExpiresAt: new Date(Date.now() - 1000),
      scopes: ["offline"],
      updatedAt: new Date(),
    };
    const refresh = vi.fn(
      async (): Promise<WhoopTokenSet> => ({
        accessToken: "new-access",
        refreshToken: "new-refresh",
        expiresAt: new Date(Date.now() + 3600_000),
        scopes: ["offline"],
      }),
    );
    const db = fakeDb(row);
    const store = new TokenStore(db as any, key, refresh);

    const at = await store.getValidAccessToken("user-1");

    expect(at).toBe("new-access");
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(refresh).toHaveBeenCalledWith("old-refresh");
    expect(db.transaction).toHaveBeenCalledWith(expect.any(Function), { isolationLevel: "read committed" });
    expect(decrypt(row.refreshTokenEnc, key)).toBe("new-refresh");
    expect(row.accessTokenExpiresAt.getTime()).toBeGreaterThan(Date.now());
  });
});

describe("TokenStore.forceRefreshAccessToken (fake db)", () => {
  it("refreshes the exact rejected token even when it is not expired", async () => {
    const row: FakeRow = {
      userId: "user-1",
      accessTokenEnc: encrypt("current-access", key),
      refreshTokenEnc: encrypt("current-refresh", key),
      accessTokenExpiresAt: new Date(Date.now() + 3600_000), // far in the future, NOT expired
      scopes: ["offline"],
      updatedAt: new Date(),
    };
    const refresh = vi.fn(
      async (): Promise<WhoopTokenSet> => ({
        accessToken: "forced-new-access",
        refreshToken: "forced-new-refresh",
        expiresAt: new Date(Date.now() + 3600_000),
        scopes: ["offline"],
      }),
    );
    const store = new TokenStore(fakeDb(row) as any, key, refresh);

    const at = await store.forceRefreshAccessToken("user-1", "current-access");

    expect(at).toBe("forced-new-access");
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(refresh).toHaveBeenCalledWith("current-refresh");
    expect(decrypt(row.accessTokenEnc, key)).toBe("forced-new-access");
    expect(decrypt(row.refreshTokenEnc, key)).toBe("forced-new-refresh");
  });

  it("reuses a replacement token when a delayed 401 names the old token", async () => {
    const row: FakeRow = {
      userId: "user-1", accessTokenEnc: encrypt("replacement-access", key),
      refreshTokenEnc: encrypt("replacement-refresh", key),
      accessTokenExpiresAt: new Date(Date.now() + 3600_000), scopes: ["offline"], updatedAt: new Date(),
    };
    const refresh = vi.fn();
    const store = new TokenStore(fakeDb(row) as any, key, refresh);
    expect(await store.forceRefreshAccessToken("user-1", "old-access")).toBe("replacement-access");
    expect(refresh).not.toHaveBeenCalled();
    expect(decrypt(row.refreshTokenEnc, key)).toBe("replacement-refresh");
  });

  it("does not replace stored credentials when the upstream refresh fails", async () => {
    const row: FakeRow = {
      userId: "user-1", accessTokenEnc: encrypt("current-access", key),
      refreshTokenEnc: encrypt("current-refresh", key),
      accessTokenExpiresAt: new Date(0), scopes: ["offline"], updatedAt: new Date(),
    };
    const before = { ...row };
    const store = new TokenStore(fakeDb(row) as any, key, vi.fn(async () => { throw new Error("refresh failed"); }));
    await expect(store.forceRefreshAccessToken("user-1", "current-access")).rejects.toThrow("refresh failed");
    expect(row).toEqual(before);
  });
});

describe("TokenStore.upsertUserAndTokens (fake db, transactional)", () => {
  it("performs both the user and token writes inside a single transaction", async () => {
    const insertedTables: string[] = [];
    const makeChain = (): any => {
      const chain: any = {
        values: () => chain,
        onConflictDoUpdate: () => chain,
        returning: async () => [{ id: "user-xyz" }],
        then: (resolve: (v: unknown) => unknown) => Promise.resolve(undefined).then(resolve),
      };
      return chain;
    };
    const tx = {
      insert: (table: unknown) => {
        insertedTables.push(
          table === schema.users ? "users" : table === schema.whoopTokens ? "whoopTokens" : "other",
        );
        return makeChain();
      },
    };
    const transaction = vi.fn(async (cb: (t: unknown) => unknown) => cb(tx));
    const store = new TokenStore({ transaction } as any, key, vi.fn());

    const userId = await store.upsertUserAndTokens("whoop-1", "a@b.com", {
      accessToken: "a",
      refreshToken: "r",
      expiresAt: new Date(Date.now() + 3600_000),
      scopes: ["offline"],
    });

    expect(transaction).toHaveBeenCalledTimes(1);
    expect(insertedTables).toEqual(["users", "whoopTokens"]);
    expect(userId).toBe("user-xyz");
  });
});

describe("TokenStore.listMcpTokens / revokeMcpTokenById (fake db)", () => {
  it("listMcpTokens maps rows to TokenSummary (id = tokenHash, ISO dates)", async () => {
    const created = new Date("2026-08-01T10:00:00.000Z");
    const rows = [
      { tokenHash: "h1", userId: "u1", type: "pat", label: "cli", createdAt: created, expiresAt: created, lastUsedAt: null, revokedAt: null },
    ];
    const db = {
      select: () => ({ from: () => ({ where: () => ({ orderBy: async () => rows }) }) }),
    };
    const store = new TokenStore(db as any, key, vi.fn());
    const out = await store.listMcpTokens("u1");
    expect(out).toEqual([{ id: "h1", label: "cli", createdAt: created.toISOString(), expiresAt: created.toISOString(), type: "pat", lastUsedAt: null }]);
  });

  it("revokeMcpTokenById issues a scoped update (userId + tokenHash) setting revokedAt", async () => {
    let captured: any = null;
    const db = {
      update: () => ({
        set: (patch: any) => ({
          where: (cond: any) => {
            captured = { patch, cond };
            return Promise.resolve();
          },
        }),
      }),
    };
    const store = new TokenStore(db as any, key, vi.fn());
    await store.revokeMcpTokenById("u1", "h1");
    expect(captured.patch.revokedAt).toBeInstanceOf(Date);
    expect(captured.cond).toBeDefined();
  });

  it("updateMcpTokenLabel issues a scoped update (userId + tokenHash) setting label", async () => {
    let captured: any = null;
    const db = {
      update: () => ({
        set: (patch: any) => ({
          where: (cond: any) => {
            captured = { patch, cond };
            return Promise.resolve();
          },
        }),
      }),
    };
    const store = new TokenStore(db as any, key, vi.fn());
    await store.updateMcpTokenLabel("u1", "h1", "renamed");
    expect(captured.patch).toHaveProperty("label", "renamed");
    expect(captured.cond).toBeDefined();
  });
});

// Explicit disposable-test opt-in; never inherit a runtime DATABASE_URL.
const url = process.env.WHOOP_TEST_DB_DISPOSABLE === "true" ? process.env.WHOOP_TEST_DATABASE_URL : undefined;

describe.skipIf(!url)("TokenStore integration (real db)", () => {
  it("upsertUserAndTokens then getValidAccessToken round-trips through Postgres", async () => {
    const db = getDb(url!);
    const refresh = vi.fn();
    const store = new TokenStore(db, key, refresh);
    const whoopUserId = "whoop_" + Math.random().toString(36).slice(2);

    const userId = await store.upsertUserAndTokens(whoopUserId, "a@b.com", {
      accessToken: "access-1",
      refreshToken: "refresh-1",
      expiresAt: new Date(Date.now() + 3600_000),
      scopes: ["offline"],
    });

    const at = await store.getValidAccessToken(userId);
    expect(at).toBe("access-1");
    expect(refresh).not.toHaveBeenCalled();

    await store.deleteUser(userId);
  });

  it("issue/resolve/revoke mcp token round-trips through Postgres", async () => {
    const db = getDb(url!);
    const store = new TokenStore(db, key, vi.fn());
    const whoopUserId = "whoop_" + Math.random().toString(36).slice(2);
    const userId = await store.upsertUserAndTokens(whoopUserId, null, {
      accessToken: "access-1",
      refreshToken: "refresh-1",
      expiresAt: new Date(Date.now() + 3600_000),
      scopes: ["offline"],
    });

    const raw = await store.issueMcpToken(userId, "pat", "test token");
    const resolved = await store.resolveMcpToken(raw);
    expect(resolved).toMatchObject({ userId });

    await store.revokeMcpToken(raw);
    const afterRevoke = await store.resolveMcpToken(raw);
    expect(afterRevoke).toBeNull();

    const unknown = await store.resolveMcpToken("whoopmcp_pat_bogus");
    expect(unknown).toBeNull();

    await store.deleteUser(userId);
  });

  it("revokeMcpTokenById cannot revoke another user's token (cross-user isolation)", async () => {
    const db = getDb(url!);
    const store = new TokenStore(db, key, vi.fn());
    const whoopUserIdA = "whoop_" + Math.random().toString(36).slice(2);
    const whoopUserIdB = "whoop_" + Math.random().toString(36).slice(2);
    const userAId = await store.upsertUserAndTokens(whoopUserIdA, null, {
      accessToken: "access-a",
      refreshToken: "refresh-a",
      expiresAt: new Date(Date.now() + 3600_000),
      scopes: ["offline"],
    });
    const userBId = await store.upsertUserAndTokens(whoopUserIdB, null, {
      accessToken: "access-b",
      refreshToken: "refresh-b",
      expiresAt: new Date(Date.now() + 3600_000),
      scopes: ["offline"],
    });

    const rawB = await store.issueMcpToken(userBId, "pat");
    expect(await store.resolveMcpToken(rawB)).toMatchObject({ userId: userBId });

    const tokensB = await store.listMcpTokens(userBId);
    expect(tokensB).toHaveLength(1);
    const tokenBHash = tokensB[0].id;

    // User A attempts to revoke user B's token by id: must be a no-op.
    await store.revokeMcpTokenById(userAId, tokenBHash);
    expect(await store.resolveMcpToken(rawB)).toMatchObject({ userId: userBId });

    // Positive control: user B revoking their own token does work.
    await store.revokeMcpTokenById(userBId, tokenBHash);
    expect(await store.resolveMcpToken(rawB)).toBeNull();

    await store.deleteUser(userAId);
    await store.deleteUser(userBId);
  });

  it("updateMcpTokenLabel cannot rename another user's token (cross-user isolation)", async () => {
    const db = getDb(url!);
    const store = new TokenStore(db, key, vi.fn());
    const whoopUserIdA = "whoop_" + Math.random().toString(36).slice(2);
    const whoopUserIdB = "whoop_" + Math.random().toString(36).slice(2);
    const userAId = await store.upsertUserAndTokens(whoopUserIdA, null, {
      accessToken: "access-a",
      refreshToken: "refresh-a",
      expiresAt: new Date(Date.now() + 3600_000),
      scopes: ["offline"],
    });
    const userBId = await store.upsertUserAndTokens(whoopUserIdB, null, {
      accessToken: "access-b",
      refreshToken: "refresh-b",
      expiresAt: new Date(Date.now() + 3600_000),
      scopes: ["offline"],
    });

    await store.issueMcpToken(userAId, "pat", "a's token");
    await store.issueMcpToken(userBId, "pat", "b's token");

    const tokensB = await store.listMcpTokens(userBId);
    expect(tokensB).toHaveLength(1);
    const tokenBId = tokensB[0].id;

    // User A attempts to rename user B's token by id: must be a no-op.
    await store.updateMcpTokenLabel(userAId, tokenBId, "hacked");
    const tokensBAfterAttack = await store.listMcpTokens(userBId);
    expect(tokensBAfterAttack[0].label).toBe("b's token");

    // Positive control: user B renaming their own token does work.
    await store.updateMcpTokenLabel(userBId, tokenBId, "renamed");
    const tokensBAfterRename = await store.listMcpTokens(userBId);
    expect(tokensBAfterRename[0].label).toBe("renamed");

    await store.deleteUser(userAId);
    await store.deleteUser(userBId);
  });
});

describe("fixed bearer lifetime (fake db)", () => {
  it("does not resolve expired, missing-expiry or revoked credentials", async () => {
    for (const row of [
      { userId: "u", expiresAt: new Date(0), revokedAt: null },
      { userId: "u", expiresAt: undefined, revokedAt: null },
      { userId: "u", expiresAt: new Date(Date.now() + 10000), revokedAt: new Date() },
    ]) {
      const update = vi.fn();
      const db = { select: () => ({ from: () => ({ where: async () => [row] }) }), update };
      expect(await new TokenStore(db as any, key, vi.fn()).resolveMcpToken("expired")).toBeNull();
      expect(update).not.toHaveBeenCalled();
    }
  });
  it("issues one-hour OAuth and seven-day PAT credentials with stored expiry", async () => {
    const values = vi.fn(async (_row: any) => {});
    const tx = {
      select: () => ({ from: () => ({ where: () => ({ for: async () => [{ id: "u" }] }) }) }),
      insert: () => ({ values }),
    };
    const store = new TokenStore({ transaction: async (fn: any) => fn(tx) } as any, key, vi.fn());
    const before = Date.now();
    await store.issueMcpToken("u", "oauth", undefined, "client-1");
    await store.issueMcpToken("u", "pat");
    expect(values.mock.calls[0][0].expiresAt.getTime() - before).toBeGreaterThanOrEqual(3600000);
    expect(values.mock.calls[0][0].expiresAt.getTime() - before).toBeLessThan(3601000);
    expect(values.mock.calls[1][0].expiresAt.getTime() - before).toBeGreaterThanOrEqual(7 * 86400000);
    expect(values.mock.calls[0][0].clientId).toBe("client-1");
  });
});

it("holds the user lock across code validation, consumption and token insertion", async () => {
  const events: string[] = [];
  const row = { userId: "u", clientId: "client", codeHash: "hash" };
  const tx = {
    select: () => ({ from: () => ({ where: () => ({ for: async () => { events.push("lock"); return [{ id: "u" }]; } }) }) }),
    delete: () => ({ where: () => ({ returning: async () => { events.push("consume"); return [row]; } }) }),
    insert: () => ({ values: async () => { events.push("issue"); } }),
  };
  const db = {
    select: () => ({ from: () => ({ where: async () => [row] }) }),
    transaction: async (fn: any) => { events.push("begin"); const result = await fn(tx); events.push("commit"); return result; },
  };
  const store = new TokenStore(db as any, key, vi.fn());
  await store.redeemAuthorizationCode("hash", () => { events.push("validate"); });
  expect(events).toEqual(["begin", "lock", "consume", "validate", "issue", "commit"]);
});

it("revoke-all acquires the same user lock before touching tokens or codes", async () => {
  const events: string[] = [];
  const tx = {
    select: () => ({ from: () => ({ where: () => ({ for: async () => { events.push("lock"); return [{ id: "u" }]; } }) }) }),
    update: () => ({ set: () => ({ where: async () => { events.push("revoke"); } }) }),
    delete: () => ({ where: async () => { events.push("delete-codes"); } }),
  };
  const store = new TokenStore({ transaction: async (fn: any) => fn(tx) } as any, key, vi.fn());
  await store.revokeAllMcpTokens("u");
  expect(events).toEqual(["lock", "revoke", "delete-codes"]);
});
