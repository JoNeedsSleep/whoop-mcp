import { createHash, randomBytes } from "node:crypto";
import { Router, type Request, type Response } from "express";
import { and, eq, gt } from "drizzle-orm";
import { schema } from "../db/client.js";
import type { NodePgDatabase } from "drizzle-orm/node-postgres";
import type { TokenStore } from "./token-store.js";
import type { CredentialProvider } from "../whoop/credentials.js";
import { exchangeCodeForTokens } from "../whoop/oauth.js";
import { WhoopClient } from "../whoop/client.js";
import { BROWSER_COOKIE_OPTIONS, browserMatchesFlow, flowCookieName } from "./browser-binding.js";
import type { PendingPayload } from "./oauth-provider.js";

type Db = NodePgDatabase<typeof schema>;
type FetchImpl = typeof fetch;

export interface CallbackDeps {
  db: Db;
  tokenStore: TokenStore;
  credentials: CredentialProvider;
  publicBaseUrl: string;
  allowedWhoopUserId: string;
  approvedClientRedirectUris: string[];
  fetchImpl?: FetchImpl;
}

// Stable numeric identity, never email or trust-on-first-use enrollment.
export function isWhoopUserAllowed(value: unknown, expected: string): boolean {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 &&
    /^[1-9][0-9]{0,15}$/.test(expected) && String(value) === expected;
}

const sha256hex = (raw: string) => createHash("sha256").update(raw).digest("hex");
const AUTH_CODE_TTL_MS = 5 * 60_000;

export function createWhoopCallbackRouter(deps: CallbackDeps): Router {
  const router = Router();
  const fetchImpl = deps.fetchImpl;

  router.get("/whoop/callback", async (req: Request, res: Response) => {
    const state = typeof req.query.state === "string" ? req.query.state : undefined;
    const code = typeof req.query.code === "string" ? req.query.code : undefined;
    const error = typeof req.query.error === "string" ? req.query.error : undefined;

    if (!state || !/^[A-Za-z0-9_-]{43}$/.test(state) || (!error && (!code || code.length > 2048))) {
      res.status(400).send("Missing state or code."); return;
    }
    // Read first: an unrelated browser must not consume a legitimate pending flow.
    const [pending] = await deps.db.select().from(schema.pendingAuthorizations)
      .where(eq(schema.pendingAuthorizations.whoopState, state));
    if (!pending || pending.expiresAt.getTime() <= Date.now()) {
      res.status(400).send("Unknown or expired authorization request."); return;
    }

    const payload = pending.payload as PendingPayload;
    const approved = payload.clientId === "whoop-mcp-dashboard"
      ? payload.clientRedirectUri === `${deps.publicBaseUrl}/dashboard/connected`
      : deps.approvedClientRedirectUris.includes(payload.clientRedirectUri);
    if (payload.stage !== "whoop" || !approved) {
      res.status(400).send("Invalid authorization request."); return;
    }

    if (!browserMatchesFlow(req.headers.cookie, state, payload.browserBindingHash)) {
      res.status(403).send("Authorization browser mismatch."); return;
    }
    // Only the bound browser may consume state. DELETE RETURNING still ensures
    // concurrent callbacks can exchange the WHOOP code at most once.
    const consumed = await deps.db.delete(schema.pendingAuthorizations)
      .where(and(eq(schema.pendingAuthorizations.whoopState, state),
        gt(schema.pendingAuthorizations.expiresAt, new Date()))).returning();
    if (consumed.length !== 1) {
      res.status(400).send("Unknown or expired authorization request."); return;
    }
    // Sent with the callback's success/failure response, after binding verification.
    res.clearCookie(flowCookieName(state), BROWSER_COOKIE_OPTIONS);
    if (error) { res.status(400).send("WHOOP authorization failed."); return; }

    // Convert upstream failures to a fixed response. Never log token/code values.
    try {
      const creds = await deps.credentials.getClientCredentials();
      const redirectUri = `${deps.publicBaseUrl}/whoop/callback`;

      const tokenSet = await exchangeCodeForTokens(
        code!,
        redirectUri,
        creds,
        payload.whoopCodeVerifier,
        fetchImpl,
      );

      const client = new WhoopClient(
        async () => tokenSet.accessToken,
        async () => {
          throw new Error("WHOOP authorization failed — please reconnect your WHOOP account.");
        },
        fetchImpl,
      );
      const profile = await client.getProfile();
      const whoopUserId = String(profile.user_id);

      if (!isWhoopUserAllowed(profile.user_id, deps.allowedWhoopUserId)) {
        res.status(403).send("This WHOOP account is not allowed on this server.");
        return;
      }

      const userId = await deps.tokenStore.upsertUserAndTokens(whoopUserId, null, tokenSet);

      // Mint OUR authorization code, bound to the user + the client's PKCE challenge.
      const ourCode = randomBytes(32).toString("base64url");
      await deps.db.insert(schema.oauthAuthCodes).values({
        codeHash: sha256hex(ourCode),
        clientId: payload.clientId,
        userId,
        redirectUri: payload.clientRedirectUri,
        codeChallenge: payload.clientCodeChallenge,
        scopes: payload.scopes,
        expiresAt: new Date(Date.now() + AUTH_CODE_TTL_MS),
      });

      const redirect = new URL(payload.clientRedirectUri);
      redirect.searchParams.set("code", ourCode);
      if (payload.clientState !== undefined) redirect.searchParams.set("state", payload.clientState);
      res.redirect(302, redirect.toString());
    } catch {
      res.status(502).send("WHOOP connection failed, please try again.");
    }
  });

  return router;
}
