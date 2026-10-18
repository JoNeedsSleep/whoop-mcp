import { describe, it, expect } from "vitest";
import request from "supertest";
import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";

const cfg = loadConfig({
  ALLOWED_WHOOP_USER_ID: "42",
  DATABASE_URL: "postgres://x",
  ENCRYPTION_KEY: "a".repeat(64),
  WHOOP_CLIENT_ID: "id",
  WHOOP_CLIENT_SECRET: "s",
  PUBLIC_BASE_URL: "https://example.com",
  PORT: "8080",
  SESSION_SECRET: "test-session-secret-12345678901234567890",
} as any);

describe("app", () => {
  it("serves OAuth authorization-server metadata", async () => {
    const r = await request(createApp(cfg)).get("/.well-known/oauth-authorization-server");
    expect(r.status).toBe(200);
    expect(r.body.token_endpoint).toBeTruthy();
  });

  it("rejects /mcp without a bearer token", async () => {
    const r = await request(createApp(cfg))
      .post("/mcp")
      .send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    expect(r.status).toBe(401);
  });
});
