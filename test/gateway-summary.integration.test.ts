import { describe, it, expect, vi, afterEach } from "vitest";
import { createHash } from "node:crypto";
import request from "supertest";
import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { TokenStore } from "../src/auth/token-store.js";
import { healthSummary } from "../src/whoop/health-summary.js";
vi.mock("../src/whoop/health-summary.js", async (original) => {
  const module = await original<typeof import("../src/whoop/health-summary.js")>();
  return { ...module, healthSummary: vi.fn() };
});
const token = `whoopgw_service_${"a".repeat(43)}`;
const cfg = loadConfig({ ALLOWED_WHOOP_USER_ID:"42", DATABASE_URL:"postgres://x", ENCRYPTION_KEY:"a".repeat(64),
  WHOOP_CLIENT_ID:"id", WHOOP_CLIENT_SECRET:"s", PUBLIC_BASE_URL:"https://whoop.example", SESSION_SECRET:"s".repeat(32),
  GATEWAY_SERVICE_TOKEN_SHA256:createHash("sha256").update(token).digest("hex") });
afterEach(() => vi.restoreAllMocks());
describe("summary gateway boundary", () => {
  it("rejects user PATs and missing/unconfigured machine credentials before database access", async () => {
    const lookup = vi.spyOn(TokenStore.prototype,"gatewayUserId");
    for (const bearer of ["", `whoopmcp_pat_${"a".repeat(43)}`, `whoopgw_service_${"b".repeat(43)}`]) {
      const res = await request(createApp(cfg)).get("/internal/health-summary?date=2026-10-18")
        .set("Authorization",`Bearer ${bearer}`);
      expect(res.status).toBe(401);
    }
    expect((await request(createApp({...cfg,gatewayServiceTokenSha256:undefined}))
      .get("/internal/health-summary?date=2026-10-18").set("Authorization",`Bearer ${token}`)).status).toBe(401);
    expect(lookup).not.toHaveBeenCalled();
  });
  it("only reads the preconfigured WHOOP identity and returns fixed failure when disconnected", async () => {
    const lookup = vi.spyOn(TokenStore.prototype,"gatewayUserId").mockResolvedValue(null);
    const req = () => request(createApp(cfg)).get("/internal/health-summary?date=2026-10-18")
      .set("Authorization",`Bearer ${token}`);
    expect((await req()).status).toBe(503);
    expect(lookup).toHaveBeenCalledWith();
    lookup.mockResolvedValue("allowed-user");
    vi.mocked(healthSummary).mockResolvedValue({ date:"2026-10-18", status:"NO_DATA", recovery_score:null,
      hrv_ms:null, resting_heart_rate:null, sleep_ms:null, sleep_performance:null, strain:null });
    const result = await req();
    expect(result.status).toBe(200);
    expect(result.body.status).toBe("NO_DATA");
    expect(healthSummary).toHaveBeenCalledWith(expect.anything(),"2026-10-18");
    expect((await request(createApp(cfg)).get("/internal/health-summary?date=2026-10-18&userId=other")
      .set("Authorization",`Bearer ${token}`)).status).toBe(400);
  });
  it("does not treat the machine secret as a browser or MCP login", async () => {
    const resolve = vi.spyOn(TokenStore.prototype,"resolveMcpToken").mockResolvedValue(null);
    const app = createApp({...cfg, enableLegacyDirectMcp:true});
    expect((await request(app).post("/mcp").set("Authorization",`Bearer ${token}`)
      .send({jsonrpc:"2.0", id:1, method:"tools/list"})).status).toBe(401);
    expect((await request(app).get("/dashboard/api/session").set("Authorization",`Bearer ${token}`)).body.connected).toBe(false);
    expect(resolve).toHaveBeenCalled();
  });
});
