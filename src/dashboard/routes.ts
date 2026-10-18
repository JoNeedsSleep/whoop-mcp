import { createHash, randomBytes } from "node:crypto";
import path from "node:path";
import express, { Router, type Request, type Response } from "express";
import cookieSession from "cookie-session";
import type { OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { TokenStore } from "../auth/token-store.js";
import { createDashboardApiRouter } from "./api.js";

export interface DashboardDeps {
  provider: OAuthServerProvider;
  tokenStore: TokenStore;
  sessionSecret: string;
  publicBaseUrl: string;
  webDistDir?: string;
}

// Distinguishes the dashboard's own "login via WHOOP" round-trip from real, dynamically
// registered MCP clients (whose client_id values are CSPRNG-random) — this id is never
// registered in oauthClients, so it can never collide with one.
const DASHBOARD_CLIENT_ID = "whoop-mcp-dashboard";

function dashboardClient(redirectUri: string): OAuthClientInformationFull {
  return { client_id: DASHBOARD_CLIENT_ID, redirect_uris: [redirectUri] } as OAuthClientInformationFull;
}

export function createDashboardRouter(deps: DashboardDeps): Router {
  const router = Router();
  router.use(
    cookieSession({
      name: "__Host-whoop_dashboard_session",
      secret: deps.sessionSecret,
      httpOnly: true,
      secure: true,
      path: "/",
      sameSite: "lax",
      maxAge: 8 * 60 * 60 * 1000,
    }),
  );
  router.use(express.urlencoded({ extended: false }));

  // Starts the WHOOP OAuth flow for the dashboard by reusing the provider's own
  // authorize()/pending-authorization mechanism (Task 7), with a dashboard-specific
  // client id standing in for a real registered MCP client.
  router.get("/connect", async (req: Request, res: Response) => {
    try {
      const redirectUri = `${deps.publicBaseUrl}/dashboard/connected`;
      // CSRF/login-fixation guard: bind this login attempt to the initiating browser session.
      // The state travels through WHOOP and back to /connected, where it must match what we
      // stored here. An attacker's captured code carries a state the victim's session lacks.
      const oauthState = randomBytes(32).toString("base64url");
      const verifier = randomBytes(32).toString("base64url");
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      if (req.session) { req.session.oauthState = oauthState; req.session.pkceVerifier = verifier; }
      await deps.provider.authorize(
        dashboardClient(redirectUri),
        { redirectUri, state: oauthState, codeChallenge: challenge, scopes: ["mcp"] },
        res,
      );
    } catch {
      res.status(502).send("Could not start the WHOOP connection, please try again.");
    }
  });

  // Completion of the dashboard's own OAuth round-trip: /whoop/callback (Task 7) redirects
  // here with an authorization code once WHOOP + our token exchange succeed. We redeem it
  // through the same provider, then read the resulting token's userId to start a session.
  router.get("/connected", async (req: Request, res: Response) => {
    const code = typeof req.query.code === "string" ? req.query.code : undefined;
    if (!code) {
      res.status(400).send("Missing authorization code.");
      return;
    }
    // CSRF/login-fixation guard: the returned state must match the one bound to this browser
    // session at /connect. Reject before touching the code so a forged callback can't set a session.
    const state = typeof req.query.state === "string" ? req.query.state : undefined;
    const expectedState = req.session?.oauthState as string | undefined;
    if (!state || !expectedState || state !== expectedState) {
      if (req.session) req.session.oauthState = undefined;
      res.status(403).send("Invalid or missing state.");
      return;
    }
    const verifier = req.session?.pkceVerifier as string | undefined;
    if (req.session) { req.session.oauthState = undefined; req.session.pkceVerifier = undefined; }
    try {
      const redirectUri = `${deps.publicBaseUrl}/dashboard/connected`;
      const tokens = await deps.provider.exchangeAuthorizationCode(dashboardClient(redirectUri), code, verifier, redirectUri);
      const authInfo = await deps.provider.verifyAccessToken(tokens.access_token);
      await deps.tokenStore.revokeMcpToken(tokens.access_token);
      const userId = authInfo.extra?.userId;
      if (typeof userId !== "string" || !req.session) {
        res.status(502).send("WHOOP connection failed, please try again.");
        return;
      }
      req.session = { userId, expiresAt: Date.now() + 8 * 60 * 60 * 1000 };
      res.redirect(302, `${deps.publicBaseUrl}/dashboard`);
    } catch {
      res.status(502).send("WHOOP connection failed, please try again.");
    }
  });

  router.use(async (req, _res, next) => {
    if (req.session?.userId && (typeof req.session.expiresAt !== "number" || req.session.expiresAt <= Date.now())) {
      req.session = null;
    }
    if (typeof req.session?.userId === "string" && !await deps.tokenStore.isAllowedUser(req.session.userId)) req.session = null;
    next();
  });
  router.use("/api", createDashboardApiRouter({ tokenStore: deps.tokenStore }));

  // Serves the built shadcn SPA (Task 4). Registered after /connect, /connected, and /api,
  // so Express matches those first; this only handles real static assets and the SPA
  // fallback for the dashboard root and unknown client-side routes.
  const webDist = deps.webDistDir ?? path.resolve("web/dist"); // resolved from process.cwd() (repo root locally, /app on Railway)
  router.use(express.static(webDist));
  router.get(/.*/, (req, res, next) => {
    if (req.method !== "GET") return next();
    res.sendFile(path.join(webDist, "index.html"));
  });

  return router;
}
