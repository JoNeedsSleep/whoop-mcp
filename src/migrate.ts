import { migrate } from "drizzle-orm/node-postgres/migrator";
import { getDb } from "./db/client.js";

// Explicitly approved RUN_MIGRATIONS=true startup uses the production migrator
// before listening and reuses the application pool. Normal startup and the
// private Railway wrapper leave this disabled; provisioning or upgrading a
// database is a separate release operation.
export async function runMigrations(databaseUrl: string): Promise<void> {
  const db = getDb(databaseUrl);
  await migrate(db, { migrationsFolder: "drizzle" });
  console.log("migrations applied");
}
