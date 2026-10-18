import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, vi } from "vitest";
import request from "supertest";
import express from "express";
import { createDashboardRouter } from "../src/dashboard/routes.js";

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
  expect(cookies).toContain("Secure");
  expect(cookies).toContain("HttpOnly");
  expect(cookies).not.toMatch(/Domain=/i);
});
