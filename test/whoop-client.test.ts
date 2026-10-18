import { describe, it, expect, vi } from "vitest";
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
