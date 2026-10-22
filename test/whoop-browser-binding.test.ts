import { createHash } from "node:crypto";
import { it, expect, vi } from "vitest";
import express from "express";
import request from "supertest";
import { getGlobalDispatcher, MockAgent, setGlobalDispatcher } from "undici";
import { schema } from "../src/db/client.js";
import { WhoopOAuthProvider, pkceChallenge } from "../src/auth/oauth-provider.js";
import { createWhoopCallbackRouter } from "../src/auth/whoop-callback.js";
import { flowCookieName } from "../src/auth/browser-binding.js";

const origin = "https://whoop.example";
const callback = "https://client.example/cb";
function cookieFrom(res: any, name: string): string {
  return res.headers["set-cookie"].find((s: string) => s.startsWith(`${name}=`)).split(";")[0];
}

it("binds consent through the WHOOP callback and prevents a second browser from completing or consuming the flow", async () => {
  let pending: any;
  const codes: any[] = [];
  const consumed = vi.fn();
  const db: any = {
    transaction: async (fn: any) => fn(db),
    execute: async () => ({ rows: [{ locked: true }] }),
    select: () => ({ from: () => ({ where: async () => pending ? [pending] : [], limit: async () => pending ? [pending] : [] }) }),
    insert: (table: any) => ({ values: async (row: any) => {
      if (table === schema.pendingAuthorizations) pending = row;
      else if (table === schema.oauthAuthCodes) codes.push(row);
    } }),
    delete: () => ({ where: () => ({ returning: async () => {
      consumed(); const row = pending; pending = undefined; return row ? [row] : [];
    } }) }),
  };
  const credentials = { getClientCredentials: vi.fn(async () => ({ clientId: "fixture-id", clientSecret: "fixture-secret" })) };
  const tokenStore = { upsertUserAndTokens: vi.fn(async () => "fixture-user") } as any;
  const fetchImpl = vi.fn(async (url: any) => new Response(JSON.stringify(String(url).endsWith("/token")
    ? { access_token: "fixture-access", refresh_token: "fixture-refresh", expires_in: 3600, scope: "read:profile" }
    : { user_id: 42 }), { status: 200, headers: { "content-type": "application/json" } }));
  const provider = new WhoopOAuthProvider({ db, tokenStore, credentials, publicBaseUrl: origin, approvedClientRedirectUris: [callback] });
  const app = express(); app.use(express.urlencoded({ extended: false }));
  app.get("/begin", (_req, res) => provider.authorize({ client_id: "fixture-client", redirect_uris: [callback] } as any,
    { redirectUri: callback, codeChallenge: pkceChallenge("v".repeat(43)), state: "client-state" }, res));
  app.use(provider.consentRouter());
  app.use(createWhoopCallbackRouter({ db, tokenStore, credentials, publicBaseUrl: origin,
    approvedClientRedirectUris: [callback], allowedWhoopUserId: "42", fetchImpl: fetchImpl as any }));

  // First browser receives and submits its own consent form and cookie.
  const begin = await request(app).get("/begin");
  const consentCookie = cookieFrom(begin, "__Host-whoop_consent");
  const csrf = begin.text.match(/name="csrf" value="([^"]+)"/)![1];
  const state = begin.text.match(/name="state" value="([^"]+)"/)![1];
  const consent = await request(app).post("/oauth/consent").set("Origin", origin)
    .set("Cookie", consentCookie).type("form").send({ state, csrf, decision: "allow" });
  expect(consent.status).toBe(302);
  const whoopState = new URL(consent.headers.location).searchParams.get("state")!;
  const flowCookie = cookieFrom(consent, flowCookieName(whoopState));
  expect(flowCookie.split("=")[1]).toBe(csrf); // same browser nonce survives the transition
  expect(pending.payload.browserBindingHash).toBe(createHash("sha256").update(csrf).digest("hex"));
  const deletesBeforeCallback = consumed.mock.calls.length;

  // Knowing the URL/code/state is insufficient in a second browser. It also cannot
  // consume the first browser's flow, and no WHOOP request may occur on rejection.
  const callbackPath = `/whoop/callback?state=${whoopState}&code=fixture-code`;
  expect((await request(app).get(callbackPath)).status).toBe(403);
  expect((await request(app).get(callbackPath).set("Cookie", `${flowCookieName(whoopState)}=${"x".repeat(43)}`)).status).toBe(403);
  expect(consumed).toHaveBeenCalledTimes(deletesBeforeCallback);
  expect(pending.whoopState).toBe(whoopState);
  expect(fetchImpl).not.toHaveBeenCalled();
  expect(tokenStore.upsertUserAndTokens).not.toHaveBeenCalled();

  const completed = await request(app).get(callbackPath).set("Cookie", flowCookie);
  expect(completed.status).toBe(302);
  expect(new URL(completed.headers.location).origin).toBe("https://client.example");
  expect(fetchImpl).toHaveBeenCalledTimes(2);
  expect(codes).toHaveLength(1);
  expect(pending).toBeUndefined();
  expect(completed.headers["set-cookie"].join(";")).toContain(`${flowCookieName(whoopState)}=;`);
  expect((await request(app).get(callbackPath).set("Cookie", flowCookie)).status).toBe(400);
  expect(fetchImpl).toHaveBeenCalledTimes(2);
});

it("also gives internal dashboard login a flow-specific secure browser binding", async () => {
  let pending: any;
  const db: any = { transaction: async (fn: any) => fn(db),
    execute: async () => ({ rows: [{ locked: true }] }),
    select: () => ({ from: () => ({ limit: async () => [] }) }),
    insert: () => ({ values: async (row: any) => { pending = row; } }) };
  const provider = new WhoopOAuthProvider({ db, tokenStore: {} as any,
    credentials: { getClientCredentials: async () => ({ clientId: "fixture-id", clientSecret: "fixture-secret" }) },
    publicBaseUrl: origin, approvedClientRedirectUris: [] });
  const app = express();
  app.get("/begin", (_req, res) => provider.authorize({ client_id: "whoop-mcp-dashboard" } as any,
    { redirectUri: `${origin}/dashboard/connected`, codeChallenge: pkceChallenge("v".repeat(43)) }, res));
  const r = await request(app).get("/begin");
  expect(r.status).toBe(302);
  expect(pending.payload.browserBindingHash).toMatch(/^[a-f0-9]{64}$/);
  const cookies = r.headers["set-cookie"].join(";");
  expect(cookies).toContain(flowCookieName(pending.whoopState));
  expect(cookies).toContain("Secure");
  expect(cookies).toContain("HttpOnly");
  expect(cookies).not.toContain("Domain=");
});

it("uses the pinned HTTP client for both callback token exchange and profile lookup without a fetch override", async () => {
  const previous = getGlobalDispatcher();
  const agent = new MockAgent(); agent.disableNetConnect(); setGlobalDispatcher(agent);
  const bundledFetch = vi.fn(() => { throw new Error("Bundled fetch must not run"); });
  vi.stubGlobal("fetch", bundledFetch);
  try {
    const state = "s".repeat(43); const browser = "b".repeat(43);
    let pending: any = { whoopState: state, expiresAt: new Date(Date.now() + 60_000), payload: {
      stage: "whoop", clientId: "whoop-mcp-dashboard", clientRedirectUri: `${origin}/dashboard/connected`,
      clientState: "bound-dashboard-state", clientCodeChallenge: pkceChallenge("v".repeat(43)),
      whoopCodeVerifier: "w".repeat(43), scopes: ["mcp"],
      browserBindingHash: createHash("sha256").update(browser).digest("hex"),
    } };
    const codes: any[] = [];
    const db: any = {
      select: () => ({ from: () => ({ where: async () => pending ? [pending] : [] }) }),
      delete: () => ({ where: () => ({ returning: async () => {
        const row = pending; pending = undefined; return row ? [row] : [];
      } }) }),
      insert: () => ({ values: async (row: any) => { codes.push(row); } }),
    };
    const tokenStore = { upsertUserAndTokens: vi.fn(async () => "owner-user") } as any;
    const upstream = agent.get("https://api.prod.whoop.com");
    upstream.intercept({ path: "/oauth/oauth2/token", method: "POST", body: new URLSearchParams({
      grant_type: "authorization_code", code: "fixture-code", redirect_uri: `${origin}/whoop/callback`,
      client_id: "fixture-id", client_secret: "fixture-secret", code_verifier: "w".repeat(43),
    }).toString() }).reply(200, { access_token: "fixture-access", refresh_token: "fixture-refresh", expires_in: 3600, scope: "read:profile offline" });
    upstream.intercept({ path: "/developer/v2/user/profile/basic", method: "GET",
      headers: { authorization: "Bearer fixture-access" } }).reply(200, { user_id: 42, email: "discard@example.test" });
    const app = express();
    app.use(createWhoopCallbackRouter({ db, tokenStore, publicBaseUrl: origin, allowedWhoopUserId: "42",
      approvedClientRedirectUris: [], credentials: { getClientCredentials: async () => ({ clientId: "fixture-id", clientSecret: "fixture-secret" }) } }));
    const response = await request(app).get(`/whoop/callback?state=${state}&code=fixture-code`)
      .set("Cookie", `${flowCookieName(state)}=${browser}`);
    expect(response.status).toBe(302);
    expect(new URL(response.headers.location).pathname).toBe("/dashboard/connected");
    expect(tokenStore.upsertUserAndTokens).toHaveBeenCalledWith("42", null, expect.objectContaining({ accessToken: "fixture-access" }));
    expect(codes).toHaveLength(1); expect(codes[0].userId).toBe("owner-user");
    expect(bundledFetch).not.toHaveBeenCalled(); agent.assertNoPendingInterceptors();
  } finally {
    setGlobalDispatcher(previous); vi.unstubAllGlobals(); await agent.close();
  }
});
