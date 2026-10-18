import { createHash } from "node:crypto";
import { it, expect, vi } from "vitest";
import express from "express";
import request from "supertest";
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
    select: () => ({ from: () => ({ where: async () => pending ? [pending] : [] }) }),
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
  const db = { insert: () => ({ values: async (row: any) => { pending = row; } }) } as any;
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
