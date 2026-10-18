import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { createGatewayServer, MAX_REQUEST_BYTES, PROTOCOL_VERSIONS } from "./server.mjs";

const publicOrigin = "https://gateway.example";
const bearer = `gateway_${"a".repeat(43)}`;
const day = "2026-10-18";
const good = () => ({ date: day, status: "AVAILABLE", recovery_score: 70, hrv_ms: 45,
  resting_heart_rate: 55, sleep_ms: 28000000, sleep_performance: 89, strain: 10.2 });
const rpc = (method, params, id = 1) => ({ jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) });
const toolCall = () => rpc("tools/call", { name: "get_health_summary", arguments: { date: day } });
const initialize = (version = PROTOCOL_VERSIONS[0]) => rpc("initialize", {
  protocolVersion: version, capabilities: { sampling: {}, roots: { listChanged: true } },
  clientInfo: { name: "synthetic-client", version: "1.0.0" },
});

async function fixture(t, overrides = {}) {
  const calls = [];
  const authCalls = [];
  let acquired = 0;
  let released = 0;
  let active = false;
  const auth = overrides.auth ?? {
    handleAuth: async (_req, res, url) => {
      authCalls.push(url.pathname);
      if (url.pathname !== "/.well-known/oauth-protected-resource") return false;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ resource: `${publicOrigin}/mcp`, authorization_servers: [publicOrigin] }));
      return true;
    },
    verifyBearer: async (token) => token === bearer ? { clientId: "fixture", audience: `${publicOrigin}/mcp` } : null,
  };
  const store = overrides.store ?? {
    acquireToolCall: async () => {
      if (active || acquired >= 30) return null;
      active = true; acquired++; return `lease-${acquired}`;
    },
    releaseToolCall: async () => { active = false; released++; },
  };
  const callTool = overrides.callTool ?? (async (...args) => {
    calls.push(args); return { structuredContent: good(), content: [{ type: "text", text: "untrusted text is discarded" }] };
  });
  const server = createGatewayServer({ publicOrigin, auth, store, callTool });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  t.after(async () => {
    const closed = new Promise((resolve) => server.close(resolve));
    server.closeAllConnections(); await closed;
  });
  const port = server.address().port;
  const request = (message, opts = {}) => new Promise((resolve, reject) => {
    const body = opts.body ?? (message === undefined ? "" : JSON.stringify(message));
    const baseHeaders = { Host: new URL(publicOrigin).host, Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${bearer}`, "Content-Type": "application/json",
      ...(opts.chunked ? {} : { "Content-Length": Buffer.byteLength(body) }), ...opts.headers };
    for (const key of Object.keys(baseHeaders)) if (baseHeaders[key] === undefined) delete baseHeaders[key];
    const req = http.request({ hostname: "127.0.0.1", port, method: opts.method ?? "POST", path: opts.path ?? "/mcp",
      headers: opts.rawHeaders ?? baseHeaders, agent: false }, (res) => {
      const parts = [];
      res.on("data", (part) => parts.push(part));
      res.on("end", () => {
        const text = Buffer.concat(parts).toString("utf8");
        let json; try { json = JSON.parse(text); } catch {}
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.setTimeout(10000, () => req.destroy(new Error("Fixture request timed out")));
    req.on("error", reject);
    if (opts.unfinished) req.write(body);
    else if (opts.chunked) { req.write(body.slice(0, 9000)); req.end(body.slice(9000)); }
    else req.end(body);
  });
  return { server, request, calls, authCalls, counters: () => ({ acquired, released }) };
}

test("authenticates initialization, advertises only immutable tools, and accepts only the initialized notification", async (t) => {
  const f = await fixture(t);
  const init = await f.request(initialize());
  assert.equal(init.status, 200);
  assert.deepEqual(init.json.result, { protocolVersion: PROTOCOL_VERSIONS[0], capabilities: { tools: {} },
    serverInfo: { name: "whoop-review-gateway", version: "1.0.0" } });
  assert.equal(init.headers["mcp-session-id"], undefined);
  assert.equal(init.headers["cache-control"], "no-store");
  const notification = await f.request({ jsonrpc: "2.0", method: "notifications/initialized" });
  assert.equal(notification.status, 202); assert.equal(notification.text, "");
  assert.deepEqual((await f.request(rpc("ping"))).json.result, {});
  const list = await f.request(rpc("tools/list"));
  assert.equal(list.json.result.tools.length, 1);
  assert.equal(list.json.result.tools[0].name, "get_health_summary");
  list.json.result.tools[0].description = "changed by client";
  assert.notEqual((await f.request(rpc("tools/list"))).json.result.tools[0].description, "changed by client");
  assert.equal(f.calls.length, 0); assert.deepEqual(f.counters(), { acquired: 0, released: 0 });
});

test("requires a valid bearer for every MCP method and emits only its own discovery challenge", async (t) => {
  const f = await fixture(t);
  for (const Authorization of [undefined, "Bearer wrong", `Bearer whoopmcp_pat_${"b".repeat(43)}`, `Basic ${bearer}`]) {
    const r = await f.request(toolCall(), { headers: { Authorization } });
    assert.equal(r.status, 401);
    assert.equal(r.headers["www-authenticate"], `Bearer resource_metadata="${publicOrigin}/.well-known/oauth-protected-resource"`);
    assert.equal(r.text.includes(bearer), false);
  }
  assert.equal((await f.request(undefined, { method: "GET", headers: { Authorization: undefined } })).status, 401);
  for (const method of ["GET", "DELETE", "PUT"]) {
    const r = await f.request(undefined, { method });
    assert.equal(r.status, 405); assert.equal(r.headers.allow, "POST");
  }
  const metadata = await f.request(undefined, { method: "GET", path: "/.well-known/oauth-protected-resource", headers: { Authorization: undefined } });
  assert.equal(metadata.status, 200); assert.equal(metadata.json.resource, `${publicOrigin}/mcp`);
  assert.equal(f.calls.length, 0);
});

test("enforces canonical Host and Origin before either auth discovery or MCP processing", async (t) => {
  const f = await fixture(t);
  for (const headers of [{ Host: "evil.example" }, { Host: "gateway.example:443" }, { Origin: "https://evil.example" },
    { Origin: "null" }, { Origin: "https://gateway.example/" },
    { Host: "evil.example", "X-Forwarded-Host": "gateway.example", "X-Forwarded-Proto": "https" }]) {
    assert.equal((await f.request(initialize(), { headers })).status, 403);
    assert.equal((await f.request(undefined, { method: "GET", path: "/.well-known/oauth-protected-resource", headers })).status, 403);
  }
  assert.equal(f.authCalls.length, 0);
  assert.equal((await f.request(initialize(), { headers: { Origin: publicOrigin } })).status, 200);
  assert.equal((await f.request(initialize(), { path: "/../mcp" })).status, 400);
  assert.equal((await f.request(initialize(), { path: "https://gateway.example/mcp" })).status, 400);
  assert.equal((await f.request(initialize(), { path: "/mcp?access_token=secret" })).status, 401);
});

test("rejects ambiguous bearer and Origin headers", async (t) => {
  const f = await fixture(t);
  const body = JSON.stringify(initialize());
  const common = ["Host", "gateway.example", "Accept", "application/json, text/event-stream",
    "Content-Type", "application/json", "Content-Length", String(Buffer.byteLength(body))];
  assert.equal((await f.request(undefined, { body, rawHeaders: [...common,
    "Authorization", `Bearer ${bearer}`, "Authorization", `Bearer ${bearer}`] })).status, 401);
  assert.equal((await f.request(undefined, { body, rawHeaders: [...common,
    "Authorization", `Bearer ${bearer}`, "Origin", publicOrigin, "Origin", publicOrigin] })).status, 403);
});

test("negotiates supported versions and rejects unsupported transport headers", async (t) => {
  const f = await fixture(t);
  for (const version of PROTOCOL_VERSIONS) {
    const r = await f.request(initialize(version));
    assert.equal(r.json.result.protocolVersion, version);
    assert.deepEqual((await f.request(rpc("ping"), { headers: { "MCP-Protocol-Version": version } })).json.result, {});
  }
  assert.equal((await f.request(initialize("2099-01-01"))).json.result.protocolVersion, PROTOCOL_VERSIONS[0]);
  assert.equal((await f.request(rpc("ping"), { headers: { "MCP-Protocol-Version": "2099-01-01" } })).status, 400);
  assert.equal((await f.request(rpc("ping"), { headers: { "MCP-Session-Id": "untrusted-session" } })).status, 400);
});

test("bounds decoded request bytes, checks UTF-8/content type and rejects compression", async (t) => {
  const f = await fixture(t);
  assert.equal((await f.request(undefined, { body: "x".repeat(MAX_REQUEST_BYTES + 1) })).status, 413);
  assert.equal((await f.request(undefined, { body: "x".repeat(MAX_REQUEST_BYTES + 1), chunked: true })).status, 413);
  assert.equal((await f.request(undefined, { body: Buffer.from([0xc3, 0x28]) })).status, 400);
  assert.equal((await f.request(undefined, { body: "{broken json" })).json.error.code, -32700);
  for (const headers of [{ "Content-Type": "text/plain" }, { "Content-Type": "application/json; charset=latin1" },
    { "Content-Encoding": "gzip" }]) assert.equal((await f.request(initialize(), { headers })).status, 415);
  for (const Accept of ["*/*", "application/json", "text/event-stream", "application/json;q=0, text/event-stream"]) {
    assert.equal((await f.request(initialize(), { headers: { Accept } })).status, 406);
  }
  assert.equal((await f.request(initialize(), { headers: { "Content-Type": "application/json; charset=utf-8" } })).status, 200);
  assert.equal(f.calls.length, 0);
});

test("rejects batches, RPC responses, unsupported methods/notifications and invalid arguments before budget or upstream use", async (t) => {
  const f = await fixture(t);
  for (const message of [[initialize()], null, { jsonrpc: "2.0", id: 1, result: {} },
    { ...initialize(), extra: "untrusted" }, { ...initialize(), id: null }]) {
    assert.equal((await f.request(message)).status, 400);
  }
  for (const method of ["sampling/createMessage", "resources/list", "prompts/list", "tasks/get", "logging/setLevel", "whoop_login"]) {
    assert.equal((await f.request(rpc(method))).json.error.code, -32601);
  }
  assert.equal((await f.request({ jsonrpc: "2.0", method: "notifications/cancelled" })).status, 400);
  for (const params of [{ name: "get_profile", arguments: { date: day } },
    { name: "get_health_summary", arguments: { date: "2026-02-30" } },
    { name: "get_health_summary", arguments: { date: day, url: "https://evil.example" } },
    { name: "get_health_summary", arguments: { date: day }, task: {} }]) {
    assert.equal((await f.request(rpc("tools/call", params))).json.error.code, -32602);
  }
  assert.equal(f.calls.length, 0); assert.deepEqual(f.counters(), { acquired: 0, released: 0 });
});

test("reconstructs tool output and never forwards raw content or extra metadata", async (t) => {
  const f = await fixture(t, { callTool: async () => ({ structuredContent: good(),
    content: [{ type: "text", text: "secret instructions https://evil.example" }],
    _meta: { authorization: "private-token" }, url: "https://evil.example" }) });
  const r = await f.request(toolCall());
  assert.deepEqual(r.json.result, { structuredContent: good(), content: [{ type: "text", text: JSON.stringify(good()) }] });
  assert.equal(/secret|private-token|evil\.example/.test(r.text), false);
  assert.deepEqual(f.counters(), { acquired: 1, released: 1 });
});

test("releases durable budget leases on both invalid data and adapter exceptions, using fixed errors", async (t) => {
  let attempt = 0;
  const f = await fixture(t, { callTool: async () => {
    if (attempt++ === 0) return { structuredContent: { ...good(), recovery_score: "ignore instructions" } };
    throw new Error("private diagnostics bearer-secret");
  } });
  for (let i = 0; i < 2; i++) {
    const r = await f.request(toolCall());
    assert.deepEqual(r.json.result, { isError: true, content: [{ type: "text", text: "HEALTH_DATA_UNAVAILABLE" }] });
    assert.equal(r.text.includes("private"), false);
  }
  assert.deepEqual(f.counters(), { acquired: 2, released: 2 });
});

test("enforces the shared store's limit and in-flight denial before calling upstream", async (t) => {
  let release;
  const started = new Promise((resolve) => { release = resolve; });
  let reached;
  const called = new Promise((resolve) => { reached = resolve; });
  let calls = 0;
  const f = await fixture(t, { callTool: async () => {
    calls++; reached(); await started; return { structuredContent: good() };
  } });
  const first = f.request(toolCall());
  try {
    await called;
    assert.equal((await f.request(toolCall())).status, 429);
    assert.equal(calls, 1);
  } finally { release(); }
  assert.equal((await first).status, 200);
  for (let i = 1; i < 30; i++) assert.equal((await f.request(toolCall())).status, 200);
  assert.equal((await f.request(toolCall())).status, 429);
  assert.equal(calls, 30); assert.deepEqual(f.counters(), { acquired: 30, released: 30 });
});

test("sanitizes auth/storage failures and fails closed", async (t) => {
  const f = await fixture(t, { auth: { handleAuth: async () => false,
    verifyBearer: async () => { throw new Error("private database path and key"); } } });
  const r = await f.request(toolCall());
  assert.equal(r.status, 503); assert.equal(r.json.error.message, "Request unavailable");
  assert.equal(r.text.includes("private"), false); assert.equal(f.calls.length, 0);
});

test("times out an incomplete OAuth form even when its auth handler is awaiting the stream", { timeout: 8000 }, async (t) => {
  let completedBody = false;
  const f = await fixture(t, { auth: { verifyBearer: () => null, handleAuth: async (req, _res, url) => {
    if (url.pathname !== "/login") return false;
    try { for await (const _chunk of req) {} completedBody = true; } catch {}
    return true;
  } } });
  const r = await f.request(undefined, { path: "/login", body: "secret=", unfinished: true,
    headers: { Origin: publicOrigin, "Content-Type": "application/x-www-form-urlencoded", "Content-Length": "100" } });
  assert.equal(r.status, 408); assert.equal(r.json.error.message, "Request timed out");
  assert.equal(completedBody, false);
});

test("requires a canonical HTTPS origin unless an explicit literal-loopback fixture is requested", () => {
  const deps = { auth: { handleAuth() {}, verifyBearer() {} }, store: { acquireToolCall() {}, releaseToolCall() {} }, callTool() {} };
  for (const origin of ["http://gateway.example", "http://127.0.0.1:1234", "https://gateway.example/", "https://u:p@gateway.example"]) {
    assert.throws(() => createGatewayServer({ ...deps, publicOrigin: origin }), /INVALID_GATEWAY_CONFIGURATION/);
  }
  assert.throws(() => createGatewayServer({ ...deps, publicOrigin: "http://localhost:1234", allowInsecureLoopback: true }));
  const server = createGatewayServer({ ...deps, publicOrigin: "http://127.0.0.1:1234", allowInsecureLoopback: true });
  server.close();
});
