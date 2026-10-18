import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { parseGatewayConfig, readPrivateToken, validateStorage } from "./config.mjs";
import { GatewayStore } from "./store.mjs";
import { createGatewayAuth } from "./auth.mjs";
import { createGatewayServer } from "./server.mjs";
import { createGateway } from "./gateway.mjs";

export function startGateway(raw) {
  process.umask(0o077);
  const config = parseGatewayConfig(raw);
  validateStorage(config.databaseFile);
  const whoopBearer = readPrivateToken(config.upstreamTokenFile);
  const store = new GatewayStore({ filename: config.databaseFile });
  try {
    const auth = createGatewayAuth({ store, publicOrigin: config.publicOrigin,
      resource: `${config.publicOrigin}/mcp`, ownerSecretHash: config.ownerSecretHash, clients: config.clients });
    const callTool = createGateway({ origin: config.upstreamOrigin, whoopBearer });
    const server = createGatewayServer({ publicOrigin: config.publicOrigin, auth, store, callTool });
    // The TLS ingress must share this network namespace and overwrite Host.
    // Never bind public ingress or trust forwarded identity headers here.
    server.listen(config.port, "127.0.0.1");
    return { server, store };
  } catch (error) { store.close(); throw error; }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let runtime;
  try {
    const filename = process.env.GATEWAY_CONFIG_FILE;
    if (!filename || !path.isAbsolute(filename)) throw new Error("INVALID_GATEWAY_CONFIG");
    const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    let config;
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.size > 16384 || (stat.mode & 0o022)) throw new Error("INVALID_GATEWAY_CONFIG");
      config = JSON.parse(fs.readFileSync(fd, "utf8"));
    } finally { fs.closeSync(fd); }
    runtime = startGateway(config);
    runtime.server.on("error", () => {
      console.error("Gateway failed to listen."); runtime.store.close(); process.exitCode = 1;
    });
    for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => {
      runtime.server.close(() => { runtime.store.close(); });
      runtime.server.closeIdleConnections();
      setTimeout(() => runtime.server.closeAllConnections(), 6000).unref();
    });
    runtime.server.on("listening", () => console.log("Gateway listening on loopback."));
  } catch {
    console.error("Gateway startup failed; check its dedicated configuration and storage.");
    process.exitCode = 1;
  }
}
