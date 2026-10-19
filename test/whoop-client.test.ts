import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { getGlobalDispatcher, MockAgent, setGlobalDispatcher } from "undici";
import { WhoopClient } from "../src/whoop/client.js";

function res(status: number, body: any, headers: Record<string, string> = {}) {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers });
}

describe("WhoopClient", () => {
  it("paginates recovery collection", async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(res(200, { records: [{ id: 1 }], next_token: "t2" }))
      .mockResolvedValueOnce(res(200, { records: [{ id: 2 }], next_token: null }));
    const c = new WhoopClient(async () => "at", async () => "at", fetchImpl as any);
    const out = await c.getRecovery();
    expect(out.map((r: any) => r.id)).toEqual([1, 2]);
  });
  it("refreshes once on 401 then retries", async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(res(401, "unauthorized"))
      .mockResolvedValueOnce(res(200, { records: [{ id: 9 }], next_token: null }));
    const force = vi.fn(async () => "new-at");
    const c = new WhoopClient(async () => "old-at", force, fetchImpl as any);
    const out = await c.getRecovery();
    expect(out[0].id).toBe(9);
    expect(force).toHaveBeenCalledOnce();
    expect(force).toHaveBeenCalledWith("old-at");
    expect(fetchImpl.mock.calls[1][1].headers.Authorization).toBe("Bearer new-at");
  });

  it("passes the token actually rejected when another request has already replaced it", async () => {
    let current = "old-at";
    const getAccessToken = vi.fn(async () => current);
    const fetchImpl = vi.fn(async (_url: string, init: RequestInit) => {
      if ((init.headers as Record<string, string>).Authorization === "Bearer old-at") {
        current = "replacement-at";
        return res(401, "unauthorized");
      }
      return res(200, { user_id: 42 });
    });
    const force = vi.fn(async (rejected: string) => {
      expect(rejected).toBe("old-at");
      return current;
    });
    const c = new WhoopClient(getAccessToken, force, fetchImpl as any);
    expect((await c.getProfile()).user_id).toBe(42);
    expect(force).toHaveBeenCalledWith("old-at");
    expect(getAccessToken).toHaveBeenCalledTimes(1);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });
  it("throws a clear error after refresh still fails", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(res(401, "unauthorized"));
    const c = new WhoopClient(async () => "at", async () => "at2", fetchImpl as any);
    await expect(c.getProfile()).rejects.toThrow(/reconnect/i);
  });
});

describe("WhoopClient default HTTP implementation", () => {
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

  it("uses the pinned npm client for the initial request and the exact-token 401 retry", async () => {
    const upstream = agent.get("https://api.prod.whoop.com");
    const path = "/developer/v2/user/profile/basic";
    upstream.intercept({ path, method: "GET", headers: { authorization: "Bearer old-at" } }).reply(401, "unauthorized");
    upstream.intercept({ path, method: "GET", headers: { authorization: "Bearer new-at" } }).reply(200, { user_id: 42 });
    const refresh = vi.fn(async () => "new-at");
    const client = new WhoopClient(async () => "old-at", refresh);
    expect(await client.getProfile()).toEqual({ user_id: 42 });
    expect(refresh).toHaveBeenCalledExactlyOnceWith("old-at");
    expect(bundledFetch).not.toHaveBeenCalled();
    agent.assertNoPendingInterceptors();
  });

  it("still rejects an upstream redirect with the real pinned fetch implementation", async () => {
    agent.get("https://api.prod.whoop.com").intercept({ path: "/developer/v2/user/profile/basic", method: "GET" })
      .reply(302, "", { headers: { location: "https://api.prod.whoop.com/redirect-target" } });
    const redirected = vi.fn(() => ({ statusCode: 200, data: { user_id: 42 } }));
    agent.get("https://api.prod.whoop.com").intercept({ path: "/redirect-target", method: "GET" }).reply(redirected);
    const client = new WhoopClient(async () => "at", async () => "new-at");
    await expect(client.getProfile()).rejects.toThrow();
    expect(redirected).not.toHaveBeenCalled();
    expect(bundledFetch).not.toHaveBeenCalled();
  });
});
