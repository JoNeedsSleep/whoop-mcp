import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, vi } from "vitest";
import request from "supertest";
import express from "express";
import { createDashboardRouter } from "../src/dashboard/routes.js";
import { WhoopOAuthProvider } from "../src/auth/oauth-provider.js";
import { AUTHORIZATION_BUSY_MESSAGE, MAX_PENDING_AUTHORIZATIONS } from "../src/auth/pending-authorizations.js";

describe("dashboard", () => {
  it("rejects /connected when the state does not match the session (CSRF guard)", async () => {
    const exchangeAuthorizationCode = vi.fn();
    const a = express();
    a.use(
      createDashboardRouter({
        provider: { exchangeAuthorizationCode, verifyAccessToken: vi.fn() } as any,
        tokenStore: { issueMcpToken: vi.fn(), revokeMcpToken: vi.fn(), deleteUser: vi.fn() } as any,
        publicBaseUrl: "https://mcp.example.com", sessionSecret: "test-session-secret-1234567890",
      }),
    );
    // No prior /connect -> the session carries no oauthState, so a forged callback is rejected
    // before the code is ever redeemed.
    const r = await request(a).get("/connected?code=abc&state=forged");
    expect(r.status).toBe(403);
    expect(exchangeAuthorizationCode).not.toHaveBeenCalled();
  });

  it("serves the SPA index.html at the dashboard root", async () => {
    const dist = fs.mkdtempSync(path.join(os.tmpdir(), "whoop-dist-"));
    fs.writeFileSync(path.join(dist, "index.html"), "<!doctype html><title>WHOOP</title><div id=root></div>");
    const a = express();
    a.use(
      "/dashboard",
      createDashboardRouter({ provider: {} as any, tokenStore: {} as any, publicBaseUrl: "https://mcp.example.com", sessionSecret: "x".repeat(20), webDistDir: dist }),
    );
    const r = await request(a).get("/dashboard/");
    expect(r.status).toBe(200);
    expect(r.text).toMatch(/id=root/);
    fs.rmSync(dist, { recursive: true, force: true });
  });

  it("does not let the SPA fallback swallow /dashboard/api routes", async () => {
    const dist = fs.mkdtempSync(path.join(os.tmpdir(), "whoop-dist-"));
    fs.writeFileSync(path.join(dist, "index.html"), "<!doctype html><title>WHOOP</title><div id=root></div>");
    const a = express();
    a.use(
      "/dashboard",
      createDashboardRouter({
        provider: {} as any,
        tokenStore: { issueMcpToken: vi.fn(), revokeMcpToken: vi.fn(), deleteUser: vi.fn() } as any,
        publicBaseUrl: "https://mcp.example.com", sessionSecret: "x".repeat(20),
        webDistDir: dist,
      }),
    );
    const r = await request(a).get("/dashboard/api/session");
    expect(r.status).toBe(200);
    expect(r.headers["content-type"]).toMatch(/json/);
    expect(r.body).toEqual({ connected: false });
    fs.rmSync(dist, { recursive: true, force: true });
  });
});

it("ignores hostile Host/protocol when constructing callback and uses secure host-only cookies", async () => {
  const authorize = vi.fn(async (_client, _params, res) => res.redirect("https://whoop.example"));
  const a = express();
  a.set("trust proxy", "loopback");
  a.use("/dashboard", createDashboardRouter({ provider: { authorize } as any, tokenStore: {} as any,
    sessionSecret: "s".repeat(32), publicBaseUrl: "https://mcp.example.com" }));
  const r = await request(a).get("/dashboard/connect").set("Host", "evil.example").set("X-Forwarded-Proto", "https");
  expect(authorize.mock.calls[0][1].redirectUri).toBe("https://mcp.example.com/dashboard/connected");
  const cookies = r.headers["set-cookie"].join(";");
  expect(cookies).toContain("__Host-whoop_dashboard_session");
  expect(cookies).toMatch(/;\s*secure(?:;|$)/i);
  expect(cookies).toMatch(/;\s*httponly(?:;|$)/i);
  expect(cookies).not.toMatch(/Domain=/i);
});

it("applies global pending-state admission to dashboard login regardless of forwarded identity", async () => {
  const insert = vi.fn();
  const getClientCredentials = vi.fn();
  const rows = Array.from({ length: MAX_PENDING_AUTHORIZATIONS }, (_, i) => ({ whoopState: String(i), expiresAt: new Date(Date.now() + 60000) }));
  const tx = { execute: async () => ({ rows: [{ locked: true }] }),
    select: () => ({ from: () => ({ limit: async () => rows }) }), insert };
  const provider = new WhoopOAuthProvider({ db: { transaction: async (fn: any) => fn(tx) } as any,
    tokenStore: {} as any, credentials: { getClientCredentials },
    publicBaseUrl: "https://mcp.example.com", approvedClientRedirectUris: [] });
  const app = express();
  app.use("/dashboard", createDashboardRouter({ provider, tokenStore: {} as any,
    sessionSecret: "s".repeat(32), publicBaseUrl: "https://mcp.example.com" }));
  for (const forwarded of ["192.0.2.1", "198.51.100.2"]) {
    const r = await request(app).get("/dashboard/connect").set("X-Forwarded-For", forwarded);
    expect(r.status).toBe(503);
    expect(r.text).toBe(AUTHORIZATION_BUSY_MESSAGE);
    expect(r.headers.location).toBeUndefined();
  }
  expect(insert).not.toHaveBeenCalled();
  expect(getClientCredentials).not.toHaveBeenCalled();
});

it("keeps a completed login for seven days and rejects replay at its fixed deadline", async () => {
  const start = Date.UTC(2026, 9, 18, 12);
  const week = 7 * 86400000;
  vi.useFakeTimers({ toFake: ["Date"] });
  try {
    vi.setSystemTime(start);
    let state = "";
    const provider = {
      authorize: vi.fn(async (_client, params, res) => { state = params.state; res.redirect("https://whoop.example"); }),
      exchangeAuthorizationCode: vi.fn(async () => ({ access_token: "temporary-login-token" })),
      verifyAccessToken: vi.fn(async () => ({ extra: { userId: "u1" } })),
    };
    const revokeMcpToken = vi.fn(async () => {});
    const isAllowedUser = vi.fn(async () => true);
    const app = express(); app.set("trust proxy", "loopback");
    app.use("/dashboard", createDashboardRouter({ provider: provider as any,
      tokenStore: { revokeMcpToken, isAllowedUser } as any,
      sessionSecret: "s".repeat(32), publicBaseUrl: "https://mcp.example.com" }));
    const cookies = (response: request.Response) => (response.headers["set-cookie"] as unknown as string[])
      .map((cookie) => cookie.split(";", 1)[0]).join("; ");
    const begun = await request(app).get("/dashboard/connect").set("X-Forwarded-Proto", "https");
    const completed = await request(app).get("/dashboard/connected").query({ code: "code", state })
      .set("X-Forwarded-Proto", "https").set("Cookie", cookies(begun));
    expect(completed.status).toBe(302);
    expect(revokeMcpToken).toHaveBeenCalledWith("temporary-login-token");
    const cookie = cookies(completed);
    const headers = completed.headers["set-cookie"] as unknown as string[];
    for (const header of headers) {
      expect(new Date(/expires=([^;]+)/i.exec(header)![1]).getTime()).toBe(start + week);
      expect(header).toMatch(/;\s*secure(?:;|$)/i);
      expect(header).toMatch(/;\s*httponly(?:;|$)/i);
    }
    for (const offset of [86400000, week - 1]) {
      vi.setSystemTime(start + offset);
      const session = await request(app).get("/dashboard/api/session")
        .set("X-Forwarded-Proto", "https").set("Cookie", cookie);
      expect(session.body).toEqual({ connected: true });
      expect(session.headers["set-cookie"]).toBeUndefined();
    }
    vi.setSystemTime(start + week);
    // Replay the signed cookie even though a browser would have discarded it.
    const expired = await request(app).get("/dashboard/api/session")
      .set("X-Forwarded-Proto", "https").set("Cookie", cookie);
    expect(expired.body).toEqual({ connected: false });
    expect(isAllowedUser).toHaveBeenCalledTimes(2);
    expect(provider.exchangeAuthorizationCode).toHaveBeenCalledTimes(1);
  } finally { vi.useRealTimers(); }
});
