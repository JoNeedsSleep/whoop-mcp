import { describe, it, expect } from "vitest";
import { getDb, schema } from "../src/db/client.js";
import { eq } from "drizzle-orm";

// Explicit disposable-test opt-in; never inherit a runtime DATABASE_URL.
const url = process.env.WHOOP_TEST_DB_DISPOSABLE === "true" ? process.env.WHOOP_TEST_DATABASE_URL : undefined;
describe.skipIf(!url)("db users table", () => {
  it("inserts and reads a user", async () => {
    const db = getDb(url!);
    const wid = "whoop_" + Math.random().toString(36).slice(2);
    await db.insert(schema.users).values({ whoopUserId: wid });
    const [row] = await db.select().from(schema.users).where(eq(schema.users.whoopUserId, wid));
    expect(row.whoopUserId).toBe(wid);
  });
});
