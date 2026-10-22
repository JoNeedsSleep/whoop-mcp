import { inArray, sql } from "drizzle-orm";
import type { NodePgDatabase } from "drizzle-orm/node-postgres";
import { schema } from "../db/client.js";

type Db = NodePgDatabase<typeof schema>;
type PendingAuthorization = typeof schema.pendingAuthorizations.$inferInsert;
export const MAX_PENDING_AUTHORIZATIONS = 100;
export const PENDING_CLEANUP_BATCH = 25;
export const AUTHORIZATION_BUSY_MESSAGE = "Authorization temporarily unavailable. Please try again later.";

// All service instances share this admission lock in their dedicated database.
// It is nonblocking: a burst cannot queue transactions waiting for this lock.
const ADMISSION_LOCK = sql`select pg_try_advisory_xact_lock(2003332975, 1885695588) as locked`;

export async function admitPendingAuthorization(db: Db, row: PendingAuthorization): Promise<boolean> {
  try {
    return await db.transaction(async (tx) => {
      const lock = await tx.execute<{ locked: boolean }>(ADMISSION_LOCK);
      if (lock.rows[0]?.locked !== true) return false;
      await tx.execute(sql`set local lock_timeout = '1000ms'`);
      await tx.execute(sql`set local statement_timeout = '2000ms'`);

      // Do not COUNT or filter the entire inherited table for expired rows. Read
      // a bounded sample and delete at most one batch by primary key. Expired
      // rows not collected here still count against admission (fail closed).
      const sample = await tx.select({ whoopState: schema.pendingAuthorizations.whoopState,
        expiresAt: schema.pendingAuthorizations.expiresAt })
        .from(schema.pendingAuthorizations).limit(MAX_PENDING_AUTHORIZATIONS + 1);
      const now = Date.now();
      const expired = sample.filter((pending) => pending.expiresAt.getTime() <= now)
        .slice(0, PENDING_CLEANUP_BATCH).map((pending) => pending.whoopState);
      if (expired.length) await tx.delete(schema.pendingAuthorizations)
        .where(inArray(schema.pendingAuthorizations.whoopState, expired));

      const occupied = await tx.select({ whoopState: schema.pendingAuthorizations.whoopState })
        .from(schema.pendingAuthorizations).limit(MAX_PENDING_AUTHORIZATIONS);
      // Return instead of throwing: even a denied request commits its bounded
      // cleanup, so a legacy backlog can drain without allowing further growth.
      if (occupied.length >= MAX_PENDING_AUTHORIZATIONS) return false;
      await tx.insert(schema.pendingAuthorizations).values(row);
      return true;
    }, { isolationLevel: "read committed" });
  } catch {
    // Lock/storage errors also fail closed. Never expose database diagnostics.
    return false;
  }
}
