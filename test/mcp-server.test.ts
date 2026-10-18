import { describe, it, expect } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerWhoopTools } from "../src/mcp/server.js";
import { WhoopClient } from "../src/whoop/client.js";

function fakeClient(): WhoopClient {
  // fetchImpl returns a fixed profile; token getters are no-ops.
  const fetchImpl = (async () =>
    new Response(JSON.stringify({ user_id: 42, email: "a@b.c" }), { status: 200 })) as any;
  return new WhoopClient(async () => "tok", async () => "tok", fetchImpl);
}

describe("registerWhoopTools", () => {
  it("registers only the 5 WHOOP tools on the server", () => {
    const server = new McpServer({ name: "t", version: "0" });
    registerWhoopTools(server, () => fakeClient(), () => "local");
    // McpServer keeps registered tools; assert the known names are present.
    const names = Object.keys((server as any)._registeredTools ?? {});
    for (const n of ["get_recovery","get_sleep","get_workouts","get_cycles","get_daily_summary"]) {
      expect(names).toContain(n);
    }
    expect(names).not.toContain("get_profile");
    expect(names).not.toContain("get_body_measurement");
  });
});
