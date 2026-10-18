import { loadConfig } from "./config.js";
import { createApp } from "./app.js";
import { runMigrations } from "./migrate.js";

// Never print validation inputs, database errors, URLs or secrets on startup failure.
try {
  const config = loadConfig(process.env);
  await runMigrations(config.databaseUrl);
  createApp(config).listen(config.port, () => console.log("WHOOP service listening"));
} catch {
  console.error("WHOOP service startup failed; check configuration and database availability.");
  process.exit(1);
}
