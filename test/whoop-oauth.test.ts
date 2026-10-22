import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { getGlobalDispatcher, MockAgent, setGlobalDispatcher } from "undici";
import { exchangeCodeForTokens, refreshWhoopTokens } from "../src/whoop/oauth.js";
const creds = { clientId: "id", clientSecret: "secret" };
function mockFetch(json: any) {
  return vi.fn(async () => new Response(JSON.stringify(json), { status: 200 }));
}

describe("whoop oauth", () => {
  it("maps token response to WhoopTokenSet with absolute expiry", async () => {
    const f = mockFetch({ access_token: "a", refresh_token: "r", expires_in: 3600, scope: "offline read:sleep" });
    const before = Date.now();
    const t = await exchangeCodeForTokens("code", "https://cb", creds, "verifier", f as any);
    expect(t.accessToken).toBe("a");
    expect(t.refreshToken).toBe("r");
    expect(t.scopes).toContain("read:sleep");
    expect(t.expiresAt.getTime()).toBeGreaterThan(before + 3500_000);
  });
  it("throws on non-200", async () => {
    const f = vi.fn(async () => new Response("bad", { status: 400 }));
    await expect(refreshWhoopTokens("r", creds, f as any)).rejects.toThrow();
  });
});

describe("WHOOP OAuth default HTTP implementation", () => {
  let agent: MockAgent;
  let previous: ReturnType<typeof getGlobalDispatcher>;
  let bundledFetch: ReturnType<typeof vi.fn>;
  beforeEach(() => {
    previous = getGlobalDispatcher();
    agent = new MockAgent(); agent.disableNetConnect(); setGlobalDispatcher(agent);
    bundledFetch = vi.fn(() => { throw new Error("Bundled fetch must not run"); });
    vi.stubGlobal("fetch", bundledFetch);
  });
  afterEach(async () => {
    setGlobalDispatcher(previous); vi.unstubAllGlobals(); await agent.close();
  });

  it("exchanges a bound code through the pinned npm client with the unchanged credential and PKCE fields", async () => {
    const body = new URLSearchParams({ grant_type: "authorization_code", code: "fixture-code",
      redirect_uri: "https://whoop.example/whoop/callback", client_id: "id", client_secret: "secret",
      code_verifier: "fixture-verifier" }).toString();
    agent.get("https://api.prod.whoop.com").intercept({ path: "/oauth/oauth2/token", method: "POST", body,
      headers: { "content-type": "application/x-www-form-urlencoded" } })
      .reply(200, { access_token: "at", refresh_token: "rt", expires_in: 3600, scope: "read:profile offline" });
    const result = await exchangeCodeForTokens("fixture-code", "https://whoop.example/whoop/callback", creds, "fixture-verifier");
    expect(result.accessToken).toBe("at"); expect(result.refreshToken).toBe("rt");
    expect(result.scopes).toEqual(["read:profile", "offline"]);
    expect(bundledFetch).not.toHaveBeenCalled(); agent.assertNoPendingInterceptors();
  });

  it("refreshes through the same pinned client while retaining the offline refresh grant", async () => {
    const body = new URLSearchParams({ grant_type: "refresh_token", refresh_token: "old-rt",
      client_id: "id", client_secret: "secret", scope: "offline" }).toString();
    agent.get("https://api.prod.whoop.com").intercept({ path: "/oauth/oauth2/token", method: "POST", body })
      .reply(200, { access_token: "new-at", refresh_token: "new-rt", expires_in: 3600, scope: "offline read:sleep" });
    const result = await refreshWhoopTokens("old-rt", creds);
    expect(result.accessToken).toBe("new-at"); expect(result.refreshToken).toBe("new-rt");
    expect(bundledFetch).not.toHaveBeenCalled(); agent.assertNoPendingInterceptors();
  });

  it("does not follow a token-endpoint redirect or replay client credentials to it", async () => {
    agent.get("https://api.prod.whoop.com").intercept({ path: "/oauth/oauth2/token", method: "POST" })
      .reply(307, "", { headers: { location: "https://unapproved.example/token" } });
    const redirected = vi.fn(() => ({ statusCode: 200, data: { access_token: "bad" } }));
    agent.get("https://unapproved.example").intercept({ path: "/token", method: "POST" }).reply(redirected);
    await expect(refreshWhoopTokens("old-rt", creds)).rejects.toThrow();
    expect(redirected).not.toHaveBeenCalled(); expect(bundledFetch).not.toHaveBeenCalled();
  });
});
