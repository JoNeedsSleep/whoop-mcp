import { describe, it, expect, vi } from "vitest";
import request from "supertest";
import express from "express";
import cookieSession from "cookie-session";
import { createDashboardApiRouter } from "../src/dashboard/api.js";

function appWith(tokenStore: any, seedUserId?: string) {
  const a = express();
  a.use(cookieSession({ name: "s", secret: "x".repeat(20) }));
  if (seedUserId) a.use((req, _res, next) => { (req.session as any).userId = seedUserId; next(); });
  a.use("/api", createDashboardApiRouter({ tokenStore }));
  return a;
}

describe("dashboard API", () => {
  it("GET /api/session reports connected=false without a session user", async () => {
    const r = await request(appWith({})).get("/api/session");
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ connected: false });
  });

  it("GET /api/tokens is 401 without a session", async () => {
    const r = await request(appWith({})).get("/api/tokens");
    expect(r.status).toBe(401);
  });

  it("POST /api/tokens is 403 without X-Requested-With", async () => {
    const issueMcpToken = vi.fn();
    const r = await request(appWith({ issueMcpToken }, "u1")).post("/api/tokens");
    expect(r.status).toBe(403);
    expect(issueMcpToken).not.toHaveBeenCalled();
  });

  it("POST /api/tokens issues a pat and returns it once", async () => {
    const issueMcpToken = vi.fn(async () => "whoopmcp_pat_abc");
    const r = await request(appWith({ issueMcpToken }, "u1"))
      .post("/api/tokens").set("X-Requested-With", "fetch").send({ label: "cli" });
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ token: "whoopmcp_pat_abc" });
    expect(issueMcpToken).toHaveBeenCalledWith("u1", "pat", "cli");
  });

  it("GET /api/tokens lists summaries for the session user", async () => {
    const listMcpTokens = vi.fn(async () => [{ id: "h1", label: "cli", createdAt: "2026-08-01T10:00:00.000Z", lastUsedAt: null }]);
    const r = await request(appWith({ listMcpTokens }, "u1")).get("/api/tokens");
    expect(r.status).toBe(200);
    expect(r.body.tokens[0].id).toBe("h1");
    expect(listMcpTokens).toHaveBeenCalledWith("u1");
  });

  it("DELETE /api/tokens/:id revokes user-scoped (204)", async () => {
    const revokeMcpTokenById = vi.fn(async () => undefined);
    const r = await request(appWith({ revokeMcpTokenById }, "u1"))
      .delete("/api/tokens/h1").set("X-Requested-With", "fetch");
    expect(r.status).toBe(204);
    expect(revokeMcpTokenById).toHaveBeenCalledWith("u1", "h1");
  });

  it("DELETE /api/tokens/:id is 401 without a session", async () => {
    const revokeMcpTokenById = vi.fn();
    const r = await request(appWith({ revokeMcpTokenById }))
      .delete("/api/tokens/h1").set("X-Requested-With", "fetch");
    expect(r.status).toBe(401);
    expect(revokeMcpTokenById).not.toHaveBeenCalled();
  });

  it("DELETE /api/tokens/:id is 403 without X-Requested-With", async () => {
    const revokeMcpTokenById = vi.fn();
    const r = await request(appWith({ revokeMcpTokenById }, "u1")).delete("/api/tokens/h1");
    expect(r.status).toBe(403);
    expect(revokeMcpTokenById).not.toHaveBeenCalled();
  });

  it("DELETE /api/account deletes the user (204)", async () => {
    const deleteUser = vi.fn(async () => undefined);
    const r = await request(appWith({ deleteUser }, "u1"))
      .delete("/api/account").set("X-Requested-With", "fetch");
    expect(r.status).toBe(204);
    expect(deleteUser).toHaveBeenCalledWith("u1");
  });

  it("DELETE /api/account is 401 without a session", async () => {
    const deleteUser = vi.fn();
    const r = await request(appWith({ deleteUser })).delete("/api/account").set("X-Requested-With", "fetch");
    expect(r.status).toBe(401);
    expect(deleteUser).not.toHaveBeenCalled();
  });

  it("DELETE /api/account is 403 without X-Requested-With", async () => {
    const deleteUser = vi.fn();
    const r = await request(appWith({ deleteUser }, "u1")).delete("/api/account");
    expect(r.status).toBe(403);
    expect(deleteUser).not.toHaveBeenCalled();
  });

  it("PATCH /api/tokens/:id is 401 without a session", async () => {
    const updateMcpTokenLabel = vi.fn();
    const r = await request(appWith({ updateMcpTokenLabel }))
      .patch("/api/tokens/h1").set("X-Requested-With", "fetch").send({ label: "cli" });
    expect(r.status).toBe(401);
    expect(updateMcpTokenLabel).not.toHaveBeenCalled();
  });

  it("PATCH /api/tokens/:id is 403 without X-Requested-With", async () => {
    const updateMcpTokenLabel = vi.fn();
    const r = await request(appWith({ updateMcpTokenLabel }, "u1"))
      .patch("/api/tokens/h1").send({ label: "cli" });
    expect(r.status).toBe(403);
    expect(updateMcpTokenLabel).not.toHaveBeenCalled();
  });

  it("PATCH /api/tokens/:id renames the token (204)", async () => {
    const updateMcpTokenLabel = vi.fn(async () => undefined);
    const r = await request(appWith({ updateMcpTokenLabel }, "u1"))
      .patch("/api/tokens/h1").set("X-Requested-With", "fetch").send({ label: "cli" });
    expect(r.status).toBe(204);
    expect(updateMcpTokenLabel).toHaveBeenCalledWith("u1", "h1", "cli");
  });

  it("PATCH /api/tokens/:id is 400 for a label longer than 100 chars", async () => {
    const updateMcpTokenLabel = vi.fn();
    const r = await request(appWith({ updateMcpTokenLabel }, "u1"))
      .patch("/api/tokens/h1").set("X-Requested-With", "fetch").send({ label: "x".repeat(101) });
    expect(r.status).toBe(400);
    expect(r.body).toEqual({ error: "label too long" });
    expect(updateMcpTokenLabel).not.toHaveBeenCalled();
  });

  it("PATCH /api/tokens/:id normalizes a blank label to null", async () => {
    const updateMcpTokenLabel = vi.fn(async () => undefined);
    const r = await request(appWith({ updateMcpTokenLabel }, "u1"))
      .patch("/api/tokens/h1").set("X-Requested-With", "fetch").send({ label: "  " });
    expect(r.status).toBe(204);
    expect(updateMcpTokenLabel).toHaveBeenCalledWith("u1", "h1", null);
  });
});

it("revoke-all covers OAuth and personal tokens through the store", async () => {
  const revokeAllMcpTokens = vi.fn(async () => {});
  const r = await request(appWith({ revokeAllMcpTokens }, "u1"))
    .delete("/api/tokens").set("X-Requested-With", "fetch");
  expect(r.status).toBe(204);
  expect(revokeAllMcpTokens).toHaveBeenCalledWith("u1");
});
