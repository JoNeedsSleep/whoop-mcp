import express from "express";
import request from "supertest";
import { tokenHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/token.js";
import { describe, it, expect, vi } from "vitest";
import { WhoopOAuthProvider, pkceChallenge } from "../src/auth/oauth-provider.js";
const uri = "https://client.example/cb";
const verifier = "v".repeat(43);
const client = { client_id: "client-1", redirect_uris: [uri], token_endpoint_auth_method: "none" } as any;
const base = { publicBaseUrl: "https://mcp.example.com", approvedClientRedirectUris: [uri], credentials: {} as any };
function withCode(patch = {}) {
  const row = { clientId: "client-1", userId: "u1", redirectUri: uri, codeChallenge: pkceChallenge(verifier), scopes: ["mcp"], expiresAt: new Date(Date.now() + 60000), ...patch };
  let available = true;
  const issueMcpToken = vi.fn(async () => "tok");
  const db = { delete: () => ({ where: () => ({ returning: async () => {
    if (!available) return []; available = false; return [row];
  } }) }) };
  return { issueMcpToken, p: new WhoopOAuthProvider({ ...base, tokenStore: { issueMcpToken } as any, db: db as any }) };
}
describe("authorization code redemption", () => {
  it("mints once under concurrent redemption and returns a fixed TTL", async () => {
    const { p, issueMcpToken } = withCode();
    const results = await Promise.allSettled([p.exchangeAuthorizationCode(client, "code", verifier, uri), p.exchangeAuthorizationCode(client, "code", verifier, uri)]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(issueMcpToken).toHaveBeenCalledTimes(1);
    expect((results.find((r) => r.status === "fulfilled") as any).value.expires_in).toBe(3600);
  });
  it("requires exact redirect, PKCE and correct client, including internal calls", async () => {
    for (const [who, proof, redirect] of [[client, verifier, uri + "/"], [client, "x".repeat(43), uri], [{ ...client, client_id: "other" }, verifier, uri]]) {
      const { p, issueMcpToken } = withCode();
      await expect(p.exchangeAuthorizationCode(who as any, "code", proof, redirect)).rejects.toThrow();
      expect(issueMcpToken).not.toHaveBeenCalled();
    }
  });
  it("supports OAuth token requests that omit redirect_uri, with mandatory PKCE", async () => {
    const { p } = withCode();
    expect(p.skipLocalPkceValidation).toBe(true);
    expect((await p.exchangeAuthorizationCode(client, "code", verifier)).access_token).toBe("tok");
  });
  it("rejects expired codes", async () => {
    const { p } = withCode({ expiresAt: new Date(0) });
    await expect(p.exchangeAuthorizationCode(client, "code", verifier, uri)).rejects.toThrow();
  });
});
describe("bearer expiry and registrations", () => {
  it("returns the persisted expiry without extending it at verification", async () => {
    const expiresAt = new Date(Date.now() + 60000);
    const p = new WhoopOAuthProvider({ ...base, db: {} as any,
      tokenStore: { resolveMcpToken: async () => ({ userId: "u", clientId: "client-1", expiresAt }) } as any });
    expect((await p.verifyAccessToken("tok")).expiresAt).toBe(Math.floor(expiresAt.getTime() / 1000));
  });
  it("rejects registrations outside the exact allowlist", async () => {
    const insert = vi.fn();
    const p = new WhoopOAuthProvider({ ...base, tokenStore: {} as any, db: { insert } as any });
    await expect(p.clientsStore.registerClient!({ ...client, redirect_uris: [uri + "/"] })).rejects.toThrow();
    expect(insert).not.toHaveBeenCalled();
  });
  it("renders browser-bound per-client consent before requesting WHOOP authorization", async () => {
    const values = vi.fn(async () => {});
    const res: any = { cookie: vi.fn(), set: vi.fn(), type: vi.fn(() => res), send: vi.fn(), redirect: vi.fn() };
    const p = new WhoopOAuthProvider({ ...base, tokenStore: {} as any, db: { insert: () => ({ values }) } as any });
    await p.authorize({ ...client, client_name: "<script>attack</script>" }, { redirectUri: uri, codeChallenge: pkceChallenge(verifier) }, res);
    expect(res.redirect).not.toHaveBeenCalled();
    expect(res.send.mock.calls[0][0]).toContain("&lt;script&gt;");
    expect(values.mock.calls[0][0].payload.stage).toBe("consent");
    expect(res.cookie.mock.calls[0][2]).toMatchObject({ secure: true, httpOnly: true, path: "/" });
  });
});

it("preserves the locked SDK token-handler PKCE handoff", async () => {
  const { p, issueMcpToken } = withCode();
  const provider = { skipLocalPkceValidation: p.skipLocalPkceValidation,
    clientsStore: { getClient: async () => client },
    exchangeAuthorizationCode: p.exchangeAuthorizationCode.bind(p) } as any;
  const app = express();
  app.use("/token", tokenHandler({ provider, rateLimit: false }));
  const r = await request(app).post("/token").type("form").send({
    grant_type: "authorization_code", client_id: client.client_id, code: "code", code_verifier: verifier,
  });
  expect(r.status).toBe(200);
  expect(r.body.expires_in).toBe(3600);
  expect(issueMcpToken).toHaveBeenCalledTimes(1);
});

it("rejects a forged consent POST before touching pending state", async () => {
  const select = vi.fn();
  const p = new WhoopOAuthProvider({ ...base, tokenStore: {} as any, db: { select } as any });
  const app = express(); app.use(express.urlencoded({ extended: false })); app.use(p.consentRouter());
  const r = await request(app).post("/oauth/consent").set("Origin", "https://evil.example")
    .type("form").send({ state: "s".repeat(43), csrf: "c".repeat(43), decision: "allow" });
  expect(r.status).toBe(403); expect(select).not.toHaveBeenCalled();
});
