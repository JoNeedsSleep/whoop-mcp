import express from "express";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { AppConfig } from "./config.js";
import { getDb } from "./db/client.js";
import { TokenStore } from "./auth/token-store.js";
import { EnvCredentialProvider } from "./whoop/credentials.js";
import { refreshWhoopTokens } from "./whoop/oauth.js";
import { WhoopOAuthProvider } from "./auth/oauth-provider.js";
import { createWhoopCallbackRouter } from "./auth/whoop-callback.js";
import { createDashboardRouter } from "./dashboard/routes.js";
import { healthSummary, utcDay } from "./whoop/health-summary.js";
import { WhoopClient } from "./whoop/client.js";
import { buildMcpServer } from "./mcp/server.js";

export function createApp(config: AppConfig): express.Express {
  const app = express();
  app.disable("x-powered-by");
  // Only a loopback TLS reverse proxy may supply forwarding headers. A future
  // deployment must firewall direct access and overwrite forwarded headers.
  app.set("trust proxy", "loopback");
  app.use(express.json({ limit: "16kb" }));
  app.use(express.urlencoded({ extended: false, limit: "8kb" }));
  app.use((_req, res, next) => {
    res.set({ "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff" });
    next();
  });
  app.get("/healthz", (_req, res) => res.json({ ok: true }));

  const db = getDb(config.databaseUrl);
  const credentials = new EnvCredentialProvider(config.whoopClientId, config.whoopClientSecret);
  const creds = { clientId: config.whoopClientId, clientSecret: config.whoopClientSecret };
  const tokenStore = new TokenStore(db, config.encryptionKey, (rt) => refreshWhoopTokens(rt, creds), config.allowedWhoopUserId);
  const provider = new WhoopOAuthProvider({ tokenStore, credentials, db, publicBaseUrl: config.publicBaseUrl, approvedClientRedirectUris: config.approvedClientRedirectUris });

  app.use(provider.consentRouter());
  const issuerUrl = new URL(config.publicBaseUrl);
  app.use(mcpAuthRouter({ provider, issuerUrl, baseUrl: issuerUrl, scopesSupported: ["mcp"] }));
  app.use(createWhoopCallbackRouter({ db, tokenStore, credentials, publicBaseUrl: config.publicBaseUrl, allowedWhoopUserId: config.allowedWhoopUserId, approvedClientRedirectUris: config.approvedClientRedirectUris }));
  app.use("/dashboard", createDashboardRouter({ provider, tokenStore, sessionSecret: config.sessionSecret, publicBaseUrl: config.publicBaseUrl }));

  const auth = requireBearerAuth({ verifier: provider, requiredScopes: ["mcp"] });
  app.get("/internal/health-summary", auth, async (req, res) => {
    let date: string;
    try {
      if (Object.keys(req.query).length !== 1) throw new Error("Invalid query");
      date = utcDay(req.query.date);
    } catch { res.status(400).json({ error: "INVALID_DATE" }); return; }
    const userId = req.auth?.extra?.userId;
    if (typeof userId !== "string") { res.status(401).end(); return; }
    try {
      const client = new WhoopClient(() => tokenStore.getValidAccessToken(userId),
        () => tokenStore.forceRefreshAccessToken(userId));
      res.json(await healthSummary(client, date));
    } catch { res.status(502).json({ error: "HEALTH_DATA_UNAVAILABLE" }); }
  });
  app.all("/mcp", auth, async (req, res) => {
    try {
      const mcpServer = buildMcpServer({ tokenStore, credentials });
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on("close", () => {
        void transport.close();
        void mcpServer.close();
      });
      await mcpServer.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch {
      if (!res.headersSent) {
        res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
      }
    }
  });

  app.use((_error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    if (!res.headersSent) res.status(500).json({ error: "Request failed" });
  });
  return app;
}
