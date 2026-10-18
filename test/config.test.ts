import { describe, it, expect } from "vitest";
import { loadConfig } from "../src/config.js";
const base = { DATABASE_URL: "postgres://x", ENCRYPTION_KEY: "a".repeat(64),
  WHOOP_CLIENT_ID: "id", WHOOP_CLIENT_SECRET: "secret", PUBLIC_BASE_URL: "https://example.com",
  SESSION_SECRET: "s".repeat(32), ALLOWED_WHOOP_USER_ID: "42" };
describe("single-user configuration", () => {
  it("defaults to no approved MCP callbacks", () => {
    expect(loadConfig(base).enableLegacyDirectMcp).toBe(false);
    expect(loadConfig(base).approvedClientRedirectUris).toEqual([]);
    expect(loadConfig(base).allowedWhoopUserId).toBe("42");
    expect(loadConfig(base).bindHost).toBe("127.0.0.1");
    expect(loadConfig(base).runMigrations).toBe(false);
  });
  it("allows only loopback listeners and explicit migration opt-in", () => {
    for (const host of ["0.0.0.0", "::", "localhost", "100.80.0.1", ""]) {
      expect(() => loadConfig({ ...base, BIND_HOST: host })).toThrow();
    }
    expect(loadConfig({ ...base, BIND_HOST: "::1" }).bindHost).toBe("::1");
    expect(loadConfig({ ...base, RUN_MIGRATIONS: "true" }).runMigrations).toBe(true);
    expect(() => loadConfig({ ...base, RUN_MIGRATIONS: "yes" })).toThrow();
  });
  it("fails closed without the specific WHOOP identity", () => {
    expect(() => loadConfig({ ...base, ALLOWED_WHOOP_USER_ID: undefined })).toThrow();
    for (const id of ["", "0", "any", "042", "9007199254740992"]) {
      expect(() => loadConfig({ ...base, ALLOWED_WHOOP_USER_ID: id })).toThrow();
    }
  });
  it("requires a canonical HTTPS origin configured explicitly", () => {
    for (const origin of ["http://localhost", "https://example.com/", "https://example.com/path", "https://user:pass@example.com", "https://example.com?x=1", "https://example.com#x", ""]) {
      expect(() => loadConfig({ ...base, PUBLIC_BASE_URL: origin, RAILWAY_PUBLIC_DOMAIN: "fallback.example" })).toThrow();
    }
  });
  it("accepts exact callback URLs and rejects wildcards and HTTP", () => {
    expect(loadConfig({ ...base, APPROVED_CLIENT_REDIRECT_URIS: "https://client.example/cb" }).approvedClientRedirectUris).toEqual(["https://client.example/cb"]);
    for (const uri of ["https://*.example/cb", "http://client.example/cb", "https://client.example/cb#x"]) {
      expect(() => loadConfig({ ...base, APPROVED_CLIENT_REDIRECT_URIS: uri })).toThrow();
    }
  });
  it("requires explicit true to opt into legacy direct MCP", () => {
    expect(loadConfig({ ...base, ENABLE_LEGACY_DIRECT_MCP: "true" }).enableLegacyDirectMcp).toBe(true);
    expect(() => loadConfig({ ...base, ENABLE_LEGACY_DIRECT_MCP: "yes" })).toThrow();
  });
});
