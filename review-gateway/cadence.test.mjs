// Real HTTP/store/adapter composition, synthetic time and upstream data only.
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { GatewayStore } from "./store.mjs";
import { createGateway, MAX_SUMMARY_CALLS_PER_HOUR } from "./gateway.mjs";
import { createGatewayServer } from "./server.mjs";

const summary = date => ({ date, status: "AVAILABLE", recovery_score: 70, hrv_ms: 50,
  resting_heart_rate: 55, sleep_ms: 28000000, sleep_performance: 90, strain: 10 });

test("two quarter-hour clients survive rolling-edge overlap and restart; the shared70th call is the last admitted", async t => {
  assert.equal(MAX_SUMMARY_CALLS_PER_HOUR, 70);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gateway-cadence-")); fs.chmodSync(directory, 0o700);
  const filename = path.join(directory, "gateway.sqlite");
  const base = Date.parse("2026-10-18T12:00:00Z"); let time = base, delay = 0, upstreamCalls = 0;
  const now = () => time;
  let store = new GatewayStore({ filename, now });
  const callTool = createGateway({ origin: "https://fixture.example", whoopBearer: `whoopgw_service_${"a".repeat(43)}`, now,
    fetchImpl: async (url, init) => {
      const target = new URL(url); assert.equal(target.origin, "https://fixture.example");
      assert.equal(target.pathname, "/internal/health-summary"); assert.equal(init.redirect, "error");
      upstreamCalls++; time += delay;
      return new Response(JSON.stringify(summary(target.searchParams.get("date"))), { headers: { "Content-Type": "application/json" } });
    } });
  const tokens = { codex: `gw_${"a".repeat(43)}`, "claude-code": `gw_${"b".repeat(43)}` };
  const server = createGatewayServer({ publicOrigin: "https://gateway.example", now, callTool,
    auth: { handleAuth: async () => false, verifyBearer: async value => {
      const clientId = Object.keys(tokens).find(key => tokens[key] === value); return clientId ? { clientId } : null;
    } }, store: { acquireToolCall: () => store.acquireToolCall(), releaseToolCall: lease => store.releaseToolCall(lease) } });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  t.after(async () => { const closed = new Promise(resolve => server.close(resolve)); server.closeAllConnections(); await closed;
    store.close(); fs.rmSync(directory, { recursive: true, force: true }); });
  const request = (client, mcp = false) => new Promise((resolve, reject) => {
    const body = mcp ? JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call",
      params: { name: "get_health_summary", arguments: { date: "2026-10-18" } } }) : undefined;
    const req = http.request({ hostname: "127.0.0.1", port: server.address().port, agent: false,
      path: mcp ? "/mcp" : "/data/snapshot", method: mcp ? "POST" : "GET",
      headers: { Host: "gateway.example", Authorization: `Bearer ${tokens[client]}`,
        ...(mcp ? { "Content-Type": "application/json", Accept: "application/json, text/event-stream" } : {}) } }, res => {
      const chunks = []; res.on("data", chunk => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString()) }));
    }); req.on("error", reject); req.end(body);
  });
  const used = () => store.db.prepare("SELECT count(*) AS n FROM rate_events WHERE bucket='tools-owner'").get().n;
  for (let quarter = 0; quarter < 5; quarter++) {
    for (const client of ["codex", "claude-code"]) {
      time = base + quarter * 900000 + (client === "claude-code" ? 61000 : 0);
      // Only the first snapshot is slow. At the next hour's fast Codex snapshot,
      // six of its old summary charges still overlap the rolling window.
      delay = quarter === 0 && client === "codex" ? 4999 : 0;
      const response = await request(client); assert.equal(response.status, 200);
      assert.equal(response.body.summaries.length, 7);
      assert.deepEqual(response.body.summaries, Array.from({ length: 7 }, (_, i) => summary(`2026-10-${12 + i}`)));
      if (quarter === 4 && client === "codex") assert.equal(used(), 62, "A60-call cap would reject normal variable-duration traffic");
    }
    if (quarter === 1) { store.close(); store = new GatewayStore({ filename, now }); }
  }
  assert.equal(upstreamCalls, 70); assert.equal(used(), 56);
  for (let i = 0; i < 14; i++) assert.equal((await request(i % 2 ? "codex" : "claude-code", true)).status, 200);
  assert.equal(used(), 70); const before = upstreamCalls;
  assert.equal((await request("codex", true)).status, 429);
  assert.equal((await request("claude-code")).status, 429);
  assert.equal(upstreamCalls, before, "Denied requests never enter the adapter");
});
