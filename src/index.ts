import { loadConfig } from "./config.js";
import { createApp } from "./app.js";
import { runMigrations } from "./migrate.js";

// Never print validation inputs, database errors, URLs or secrets on startup failure.
try {
  const config = loadConfig(process.env);
  // Schema changes are a separate operator-approved release step. Starting the
  // private runtime must never silently migrate an existing database.
  if (config.runMigrations) await runMigrations(config.databaseUrl);
  createApp(config).listen(config.port, config.bindHost, () => console.log("WHOOP service listening on loopback"));
} catch {
  console.error("WHOOP service startup failed; check configuration and database availability.");
  process.exit(1);
}
