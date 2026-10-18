import { createHash, randomBytes } from "node:crypto";
import { and, desc, eq, isNull, gt } from "drizzle-orm";
import { encrypt, decrypt } from "../crypto.js";
import { schema } from "../db/client.js";
import type { NodePgDatabase } from "drizzle-orm/node-postgres";
import type { WhoopTokenSet } from "../whoop/types.js";

export type RefreshFn = (refreshToken: string) => Promise<WhoopTokenSet>;
type Db = NodePgDatabase<typeof schema>;
type Transaction = Parameters<Parameters<Db["transaction"]>[0]>[0];
export type AuthorizationCode = typeof schema.oauthAuthCodes.$inferSelect;
const hashToken = (raw: string) => createHash("sha256").update(raw).digest("hex");
const EXPIRY_SKEW_MS = 60_000;
export const OAUTH_TOKEN_TTL_SECONDS = 3600;
export const PAT_TOKEN_TTL_SECONDS = 7 * 24 * 3600;

export interface TokenSummary {
  id: string;
  label: string | null;
  createdAt: string;
  lastUsedAt: string | null;
  expiresAt: string;
  type: "oauth" | "pat";
}

export class TokenStore {
  constructor(private db: Db, private keyHex: string, private refresh: RefreshFn, private allowedWhoopUserId?: string) {}

  async isAllowedUser(userId: string): Promise<boolean> {
    if (!this.allowedWhoopUserId) return false;
    const [user] = await this.db.select().from(schema.users).where(eq(schema.users.id, userId));
    return user?.whoopUserId === this.allowedWhoopUserId;
  }

  async upsertUserAndTokens(whoopUserId: string, email: string | null, t: WhoopTokenSet): Promise<string> {
    // Atomic: the user row and its token row must appear together. Without the transaction,
    // a crash between the two writes could leave a user with no token row (permanent
    // "WHOOP not connected"); the transaction rolls both back on any failure.
    return this.db.transaction(async (tx) => {
      const [user] = await tx.insert(schema.users)
        .values({ whoopUserId, email })
        .onConflictDoUpdate({ target: schema.users.whoopUserId, set: { email } })
        .returning();
      await tx.insert(schema.whoopTokens).values({
        userId: user.id,
        accessTokenEnc: encrypt(t.accessToken, this.keyHex),
        refreshTokenEnc: encrypt(t.refreshToken, this.keyHex),
        accessTokenExpiresAt: t.expiresAt, scopes: t.scopes,
      }).onConflictDoUpdate({
        target: schema.whoopTokens.userId,
        set: {
          accessTokenEnc: encrypt(t.accessToken, this.keyHex),
          refreshTokenEnc: encrypt(t.refreshToken, this.keyHex),
          accessTokenExpiresAt: t.expiresAt, scopes: t.scopes, updatedAt: new Date(),
        },
      });
      return user.id;
    });
  }

  async getValidAccessToken(userId: string): Promise<string> {
    const [row] = await this.db.select().from(schema.whoopTokens)
      .where(eq(schema.whoopTokens.userId, userId));
    if (!row) throw new Error("WHOOP not connected");
    if (row.accessTokenExpiresAt.getTime() - Date.now() > EXPIRY_SKEW_MS) {
      return decrypt(row.accessTokenEnc, this.keyHex);
    }
    return this.refreshAndStore(userId);
  }

  async forceRefreshAccessToken(userId: string, rejectedAccessToken: string): Promise<string> {
    return this.refreshAndStore(userId, rejectedAccessToken);
  }

  private async refreshAndStore(userId: string, rejectedAccessToken?: string): Promise<string> {
    // A REPEATABLE READ default could retain the snapshot from before the user
    // lock wait and read the previous refresh token even after the winner commits.
    return this.db.transaction(async (tx) => {
      // WHOOP rotates refresh tokens on use. Serialize across server processes,
      // using the same users -> whoop_tokens lock order as login/upsert. The
      // upstream refresh has a bounded timeout; keep the lock until persistence.
      await this.lockTokenUser(tx, userId, "WHOOP not connected");
      const [row] = await tx.select().from(schema.whoopTokens)
        .where(eq(schema.whoopTokens.userId, userId));
      if (!row) throw new Error("WHOOP not connected");
      const currentAccessToken = decrypt(row.accessTokenEnc, this.keyHex);
      if (rejectedAccessToken !== undefined) {
        // A delayed 401 for an old token must not invalidate the replacement
        // that another request (or a new login) has already stored.
        if (currentAccessToken !== rejectedAccessToken) return currentAccessToken;
      } else if (row.accessTokenExpiresAt.getTime() - Date.now() > EXPIRY_SKEW_MS) {
        return currentAccessToken;
      }
      const refreshed = await this.refresh(decrypt(row.refreshTokenEnc, this.keyHex));
      await tx.update(schema.whoopTokens).set({
        accessTokenEnc: encrypt(refreshed.accessToken, this.keyHex),
        refreshTokenEnc: encrypt(refreshed.refreshToken, this.keyHex),
        accessTokenExpiresAt: refreshed.expiresAt, scopes: refreshed.scopes, updatedAt: new Date(),
      }).where(eq(schema.whoopTokens.userId, userId));
      return refreshed.accessToken;
    }, { isolationLevel: "read committed" });
  }

  private async lockTokenUser(tx: Transaction, userId: string, missingMessage = "Account not allowed"): Promise<void> {
    // Every token issuer, WHOOP refresh and revoke-all uses this same row and lock order.
    const [user] = await tx.select().from(schema.users).where(eq(schema.users.id, userId)).for("update");
    if (!user) throw new Error(missingMessage);
    if (this.allowedWhoopUserId && user.whoopUserId !== this.allowedWhoopUserId) {
      throw new Error("Account not allowed");
    }
  }

  private async insertMcpToken(tx: Transaction, userId: string, type: "oauth" | "pat", label?: string, clientId?: string): Promise<string> {
    const raw = `whoopmcp_${type}_${randomBytes(32).toString("base64url")}`;
    const ttl = type === "oauth" ? OAUTH_TOKEN_TTL_SECONDS : PAT_TOKEN_TTL_SECONDS;
    await tx.insert(schema.mcpTokens).values({ tokenHash: hashToken(raw), userId, type, label,
      clientId: clientId ?? null, expiresAt: new Date(Date.now() + ttl * 1000) });
    return raw;
  }

  async issueMcpToken(userId: string, type: "oauth" | "pat", label?: string, clientId?: string): Promise<string> {
    return this.db.transaction(async (tx) => {
      await this.lockTokenUser(tx, userId);
      return this.insertMcpToken(tx, userId, type, label, clientId);
    });
  }

  async redeemAuthorizationCode(codeHash: string, validate: (row: AuthorizationCode) => void | Promise<void>): Promise<string | null> {
    // A non-locking read discovers the user; it never grants access. After taking
    // the user lock we re-read by atomically deleting the still-present code.
    const [candidate] = await this.db.select().from(schema.oauthAuthCodes)
      .where(eq(schema.oauthAuthCodes.codeHash, codeHash));
    if (!candidate) return null;
    return this.db.transaction(async (tx) => {
      await this.lockTokenUser(tx, candidate.userId);
      const [row] = await tx.delete(schema.oauthAuthCodes).where(and(
        eq(schema.oauthAuthCodes.codeHash, codeHash), eq(schema.oauthAuthCodes.userId, candidate.userId),
      )).returning();
      if (!row) return null; // revoke-all or another exchange won the user lock
      await validate(row);
      // Consumption and issuance commit together while the user lock is held.
      return this.insertMcpToken(tx, row.userId, "oauth", undefined, row.clientId);
    });
  }

  async resolveMcpToken(raw: string): Promise<{ userId: string; clientId: string; expiresAt: Date } | null> {
    const [row] = await this.db.select().from(schema.mcpTokens)
      .where(eq(schema.mcpTokens.tokenHash, hashToken(raw)));
    if (!row || row.revokedAt || !row.expiresAt || row.expiresAt.getTime() <= Date.now()) return null;
    if (this.allowedWhoopUserId && !await this.isAllowedUser(row.userId)) return null;
    await this.db.update(schema.mcpTokens).set({ lastUsedAt: new Date() })
      .where(eq(schema.mcpTokens.tokenHash, row.tokenHash));
    return { userId: row.userId, clientId: row.clientId ?? "pat", expiresAt: row.expiresAt };
  }

  async revokeMcpToken(raw: string): Promise<void> {
    await this.db.update(schema.mcpTokens).set({ revokedAt: new Date() })
      .where(eq(schema.mcpTokens.tokenHash, hashToken(raw)));
  }

  async listMcpTokens(userId: string): Promise<TokenSummary[]> {
    const rows = await this.db.select().from(schema.mcpTokens)
      .where(and(
        eq(schema.mcpTokens.userId, userId),
        gt(schema.mcpTokens.expiresAt, new Date()),
        isNull(schema.mcpTokens.revokedAt),
      ))
      .orderBy(desc(schema.mcpTokens.createdAt));
    return rows.map((r) => ({
      id: r.tokenHash,
      type: r.type,
      expiresAt: r.expiresAt.toISOString(),
      label: r.label,
      createdAt: r.createdAt.toISOString(),
      lastUsedAt: r.lastUsedAt ? r.lastUsedAt.toISOString() : null,
    }));
  }

  async revokeMcpTokenById(userId: string, tokenHash: string): Promise<void> {
    await this.db.update(schema.mcpTokens).set({ revokedAt: new Date() })
      .where(and(
        eq(schema.mcpTokens.tokenHash, tokenHash),
        eq(schema.mcpTokens.userId, userId),
      ));
  }

  async updateMcpTokenLabel(userId: string, tokenHash: string, label: string | null): Promise<void> {
    await this.db.update(schema.mcpTokens).set({ label })
      .where(and(
        eq(schema.mcpTokens.tokenHash, tokenHash),
        eq(schema.mcpTokens.userId, userId),
      ));
  }

  async revokeAllMcpTokens(userId: string): Promise<void> {
    await this.db.transaction(async (tx) => {
      await this.lockTokenUser(tx, userId);
      await tx.update(schema.mcpTokens).set({ revokedAt: new Date() })
        .where(eq(schema.mcpTokens.userId, userId));
      await tx.delete(schema.oauthAuthCodes).where(eq(schema.oauthAuthCodes.userId, userId));
    });
  }

  async deleteUser(userId: string): Promise<void> {
    await this.db.delete(schema.users).where(eq(schema.users.id, userId)); // cascades
  }
}
