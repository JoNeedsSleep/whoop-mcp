import { createHash, randomBytes } from "node:crypto";
import { eq } from "drizzle-orm";
import { Router, type Response } from "express";
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { InvalidTokenError, InvalidGrantError, InvalidRequestError, UnsupportedGrantTypeError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthClientInformationFull, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { schema } from "../db/client.js";
import type { NodePgDatabase } from "drizzle-orm/node-postgres";
import { OAUTH_TOKEN_TTL_SECONDS, type TokenStore } from "./token-store.js";
import type { CredentialProvider } from "../whoop/credentials.js";
import { buildAuthorizeUrl } from "../whoop/oauth.js";
import { BROWSER_COOKIE_OPTIONS, FLOW_TTL_MS, flowCookieName, nonceHash } from "./browser-binding.js";
import { httpsCallback } from "../config.js";
import { admitPendingAuthorization, AUTHORIZATION_BUSY_MESSAGE } from "./pending-authorizations.js";

type Db = NodePgDatabase<typeof schema>;
export interface ProviderDeps {
  tokenStore: TokenStore;
  credentials: CredentialProvider;
  db: Db;
  publicBaseUrl: string;
  approvedClientRedirectUris: string[];
}
export const DASHBOARD_CLIENT_ID = "whoop-mcp-dashboard";
const sha256hex = (raw: string) => createHash("sha256").update(raw).digest("hex");
export const pkceChallenge = (verifier: string) => createHash("sha256").update(verifier).digest("base64url");
const random = () => randomBytes(32).toString("base64url");
const PENDING_TTL_MS = FLOW_TTL_MS;
const CONSENT_COOKIE = "__Host-whoop_consent";
const cookieOptions = BROWSER_COOKIE_OPTIONS;
const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export interface PendingPayload extends Record<string, unknown> {
  stage: "consent" | "whoop";
  clientId: string;
  clientRedirectUri: string;
  clientState?: string;
  clientCodeChallenge: string;
  scopes: string[];
  whoopCodeVerifier: string;
  consentHash?: string;
  browserBindingHash?: string;
}

export class WhoopOAuthProvider implements OAuthServerProvider {
  // SDK 1.30 passes code_verifier only in this mode. Validation is performed
  // mandatorily in exchangeAuthorizationCode, including dashboard/internal calls.
  readonly skipLocalPkceValidation = true;
  constructor(private deps: ProviderDeps) {}

  private approved(uri: string): boolean {
    return httpsCallback.safeParse(uri).success && this.deps.approvedClientRedirectUris.includes(uri);
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    const db = this.deps.db;
    const approved = (uri: string) => this.approved(uri);
    return {
      async getClient(clientId): Promise<OAuthClientInformationFull | undefined> {
        const [row] = await db.select().from(schema.oauthClients).where(eq(schema.oauthClients.clientId, clientId));
        // Revalidate stored registrations when the deployment allowlist changes.
        if (!row || !row.redirectUris.length || !row.redirectUris.every(approved)) return undefined;
        return { ...row.metadata, client_id: row.clientId, redirect_uris: row.redirectUris } as OAuthClientInformationFull;
      },
      async registerClient(client): Promise<OAuthClientInformationFull> {
        const full = client as OAuthClientInformationFull;
        if (full.client_id === DASHBOARD_CLIENT_ID || !full.redirect_uris.length ||
            full.redirect_uris.length > 8 || !full.redirect_uris.every(approved) ||
            full.token_endpoint_auth_method !== "none" ||
            full.grant_types?.some((g) => g !== "authorization_code") ||
            full.response_types?.some((r) => r !== "code") ||
            (full.scope && full.scope !== "mcp")) {
          throw new InvalidRequestError("Client registration is not approved");
        }
        // This single-user server supports public PKCE clients only; no other app secrets.
        const safe: OAuthClientInformationFull = {
          client_id: full.client_id,
          redirect_uris: full.redirect_uris,
          token_endpoint_auth_method: "none",
          grant_types: ["authorization_code"], response_types: ["code"], scope: "mcp",
          client_name: full.client_name?.slice(0, 100),
        };
        await db.insert(schema.oauthClients).values({ clientId: safe.client_id,
          clientSecretHash: null, redirectUris: safe.redirect_uris,
          metadata: safe as unknown as Record<string, unknown> });
        return safe;
      },
    };
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const dashboard = client.client_id === DASHBOARD_CLIENT_ID;
    const validRedirect = dashboard ? params.redirectUri === `${this.deps.publicBaseUrl}/dashboard/connected`
      : this.approved(params.redirectUri) && client.redirect_uris.includes(params.redirectUri);
    if (!validRedirect || !/^[A-Za-z0-9_-]{43}$/.test(params.codeChallenge) ||
        (params.scopes ?? []).some((s) => s !== "mcp") || (params.state?.length ?? 0) > 1024) {
      throw new InvalidRequestError("Invalid authorization request");
    }
    const payload: PendingPayload = {
      stage: dashboard ? "whoop" : "consent", clientId: client.client_id,
      clientRedirectUri: params.redirectUri, clientState: params.state,
      clientCodeChallenge: params.codeChallenge, scopes: ["mcp"], whoopCodeVerifier: random(),
    };
    if (dashboard) { await this.startWhoop(payload, res); return; }

    // WHOOP upstream consent alone is not consent to this particular MCP client.
    const state = random();
    const csrf = random();
    payload.consentHash = sha256hex(csrf);
    if (!await admitPendingAuthorization(this.deps.db, { whoopState: state, payload,
      expiresAt: new Date(Date.now() + PENDING_TTL_MS) })) {
      res.status(503).send(AUTHORIZATION_BUSY_MESSAGE); return;
    }
    res.cookie(CONSENT_COOKIE, csrf, { ...cookieOptions, maxAge: PENDING_TTL_MS });
    res.set({ "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
      "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" });
    res.type("html").send(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Approve WHOOP access</title>
      <h1>Allow this client to read WHOOP health data?</h1>
      <p>Client name (unverified): ${escapeHtml(client.client_name ?? "Unnamed client")}</p>
      <p>Client ID: ${escapeHtml(client.client_id)}</p>
      <p>Exact callback: ${escapeHtml(params.redirectUri)}</p><p>Scope: mcp. Access expires after one hour.</p>
      <form method="post" action="/oauth/consent"><input type="hidden" name="state" value="${state}">
      <input type="hidden" name="csrf" value="${csrf}"><button name="decision" value="allow">Allow</button>
      <button name="decision" value="deny">Deny</button></form></html>`);
  }

  consentRouter(): Router {
    const router = Router();
    router.post("/oauth/consent", async (req, res) => {
      const { state, csrf, decision } = req.body ?? {};
      const cookie = (req.headers.cookie ?? "").split(";").map((v) => v.trim())
        .find((v) => v.startsWith(`${CONSENT_COOKIE}=`))?.slice(CONSENT_COOKIE.length + 1);
      if (req.get("origin") !== this.deps.publicBaseUrl || typeof state !== "string" ||
          !/^[A-Za-z0-9_-]{43}$/.test(state) || typeof csrf !== "string" ||
          !/^[A-Za-z0-9_-]{43}$/.test(csrf) || csrf !== cookie || !["allow", "deny"].includes(decision)) {
        res.status(403).send("Invalid consent request."); return;
      }
      const [pending] = await this.deps.db.select().from(schema.pendingAuthorizations)
        .where(eq(schema.pendingAuthorizations.whoopState, state));
      const payload = pending?.payload as PendingPayload | undefined;
      if (!pending || pending.expiresAt.getTime() <= Date.now() || payload?.stage !== "consent" ||
          payload.consentHash !== sha256hex(csrf) || !this.approved(payload.clientRedirectUri)) {
        res.status(403).send("Invalid consent request."); return;
      }
      // One concurrent submit wins. The browser binding is checked before consumption.
      const consumed = await this.deps.db.delete(schema.pendingAuthorizations)
        .where(eq(schema.pendingAuthorizations.whoopState, state)).returning();
      if (consumed.length !== 1) { res.status(403).send("Consent already used."); return; }
      if (decision === "deny") {
        res.clearCookie(CONSENT_COOKIE, cookieOptions);
        const redirect = new URL(payload.clientRedirectUri);
        redirect.searchParams.set("error", "access_denied");
        if (payload.clientState !== undefined) redirect.searchParams.set("state", payload.clientState);
        res.redirect(302, redirect.toString()); return;
      }
      // Carry the same nonce from the validated consent browser into a cookie
      // specific to the WHOOP state. Do not drop the binding at this transition.
      res.clearCookie(CONSENT_COOKIE, cookieOptions);
      await this.startWhoop({ ...payload, stage: "whoop" }, res, csrf);
    });
    return router;
  }

  private async startWhoop(payload: PendingPayload, res: Response, browserNonce = random()): Promise<void> {
    const whoopState = random();
    const boundPayload: PendingPayload = { ...payload, browserBindingHash: nonceHash(browserNonce) };
    if (!await admitPendingAuthorization(this.deps.db, { whoopState, payload: boundPayload,
      expiresAt: new Date(Date.now() + PENDING_TTL_MS) })) {
      res.status(503).send(AUTHORIZATION_BUSY_MESSAGE); return;
    }
    const creds = await this.deps.credentials.getClientCredentials();
    // Dashboard login also gets a browser binding before the WHOOP leg.
    res.cookie(flowCookieName(whoopState), browserNonce, { ...cookieOptions, maxAge: PENDING_TTL_MS });
    res.redirect(302, buildAuthorizeUrl({ clientId: creds.clientId,
      redirectUri: `${this.deps.publicBaseUrl}/whoop/callback`, state: whoopState,
      codeChallenge: pkceChallenge(payload.whoopCodeVerifier) }));
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, code: string): Promise<string> {
    const [row] = await this.deps.db.select().from(schema.oauthAuthCodes)
      .where(eq(schema.oauthAuthCodes.codeHash, sha256hex(code)));
    if (!row || row.clientId !== client.client_id || row.expiresAt.getTime() <= Date.now()) {
      throw new InvalidGrantError("Invalid authorization code");
    }
    return row.codeChallenge;
  }

  async exchangeAuthorizationCode(client: OAuthClientInformationFull, code: string,
    codeVerifier?: string, redirectUri?: string): Promise<OAuthTokens> {
    const accessToken = await this.deps.tokenStore.redeemAuthorizationCode(sha256hex(code), (row) => {
      if (row.clientId !== client.client_id || row.expiresAt.getTime() <= Date.now() ||
          !codeVerifier || !/^[A-Za-z0-9._~-]{43,128}$/.test(codeVerifier) ||
          pkceChallenge(codeVerifier) !== row.codeChallenge) {
        throw new InvalidGrantError("Invalid authorization code or PKCE verifier");
      }
      if (redirectUri !== undefined && redirectUri !== row.redirectUri) throw new InvalidGrantError("redirect_uri does not match");
      if (client.client_id !== DASHBOARD_CLIENT_ID && !this.approved(row.redirectUri)) {
        throw new InvalidGrantError("Callback no longer approved");
      }
    });
    if (!accessToken) throw new InvalidGrantError("Invalid or revoked authorization code");
    return { access_token: accessToken, token_type: "bearer", expires_in: OAUTH_TOKEN_TTL_SECONDS, scope: "mcp" };
  }

  async exchangeRefreshToken(): Promise<OAuthTokens> {
    throw new UnsupportedGrantTypeError("refresh_token grant is not supported");
  }
  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const r = await this.deps.tokenStore.resolveMcpToken(token);
    if (!r) throw new InvalidTokenError("Invalid, expired or revoked token");
    return { token, clientId: r.clientId, scopes: ["mcp"],
      expiresAt: Math.floor(r.expiresAt.getTime() / 1000), extra: { userId: r.userId } };
  }
}
