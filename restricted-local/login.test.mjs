import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { createHash } from "node:crypto";
import { AUTH_TTL_MS, CALLBACKS, readPrivateJson } from "./config.mjs";
import { createLoginFlow, exchangeLoginCode, runLogin, startCallback, validateLoginCallback } from "./login.mjs";

function fixture(t, clientId = "codex") {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "restricted-login-")); fs.chmodSync(directory, 0o700); t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return { clientId, origin: "https://gateway.example", tokenFile: path.join(directory, "token.json"), cacheFile: path.join(directory, "cache.json"), stateFile: path.join(directory, "state.sqlite") };
}
const callback = (flow, config, extra = {}) => "/callback?" + new URLSearchParams({ code: "a".repeat(43), state: flow.state, iss: config.origin, ...extra });
const tokenResponse = (extra = {}) => new Response(JSON.stringify({ access_token: `gw_${"b".repeat(43)}`, token_type: "Bearer", expires_in: 604800, scope: "mcp", ...extra }), { headers: { "content-type": "application/json" } });
function get(url) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = http.get({ hostname: "127.0.0.1", port: parsed.port, path: parsed.pathname + parsed.search, headers: { Host: parsed.host }, agent: false }, (res) => {
      let text = ""; res.on("data", (chunk) => { text += chunk; }); res.on("end", () => resolve({ status: res.statusCode, text }));
    }); req.on("error", reject); req.setTimeout(2000, () => req.destroy(new Error("Fixture timeout")));
  });
}
test("login emits only the fixed trusted authorization endpoint and explicit state/S256/resource/callback", (t) => {
  for (const clientId of ["codex", "claude-code"]) {
    const config = fixture(t, clientId); const flow = createLoginFlow(config); const url = new URL(flow.authorizationUrl);
    assert.equal(url.origin + url.pathname, config.origin + "/oauth/authorize"); assert.equal(url.searchParams.get("redirect_uri"), CALLBACKS[clientId]);
    assert.equal(url.searchParams.get("client_id"), clientId); assert.equal(url.searchParams.get("resource"), config.origin + "/mcp");
    assert.equal(url.searchParams.get("state"), flow.state); assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    assert.equal(url.searchParams.get("code_challenge"), createHash("sha256").update(flow.verifier).digest("base64url"));
    assert(!flow.authorizationUrl.includes(flow.verifier));
  }
});
test("callback checks exact host/path, issuer, state, single parameters and denial without reflecting data", (t) => {
  const config = fixture(t); const flow = createLoginFlow(config); const host = new URL(flow.redirectUri).host;
  assert.deepEqual(validateLoginCallback(callback(flow, config), host, config, flow), { code: "a".repeat(43) });
  for (const request of [callback(flow, config, { state: "wrong" }), callback(flow, config, { iss: "https://evil.example" }), callback(flow, config) + "&code=duplicate",
    callback(flow, config) + "&error=access_denied", callback(flow, config).replace("/callback?", "/wrong?"), callback(flow, config) + "#fragment"]) assert.throws(() => validateLoginCallback(request, host, config, flow));
  assert.throws(() => validateLoginCallback(callback(flow, config), "localhost:17643", config, flow));
  assert.deepEqual(validateLoginCallback("/callback?" + new URLSearchParams({ state: flow.state, iss: config.origin, error: "access_denied" }), host, config, flow), { denied: true });
});
test("code exchange makes one fixed request and stores token only in a private locally bounded record", async (t) => {
  const config = fixture(t); const flow = createLoginFlow(config); const now = Date.UTC(2026, 9, 18); const calls = [];
  const result = await exchangeLoginCode(config, flow, "a".repeat(43), { now: () => now, fetchImpl: async (url, init) => { calls.push({ url, init }); return tokenResponse(); } });
  assert.deepEqual(result, { expiresAt: now + AUTH_TTL_MS }); assert.equal(calls.length, 1); assert.equal(calls[0].url, config.origin + "/oauth/token"); assert.equal(calls[0].init.redirect, "error");
  const posted = new URLSearchParams(calls[0].init.body); assert.equal(posted.get("resource"), config.origin + "/mcp"); assert.equal(posted.get("code_verifier"), flow.verifier); assert.equal(posted.get("redirect_uri"), flow.redirectUri);
  const stored = readPrivateJson(config.tokenFile); assert.equal(stored.accessToken, `gw_${"b".repeat(43)}`); assert.equal(stored.expiresAt, result.expiresAt); assert.equal(fs.statSync(config.tokenFile).mode & 0o777, 0o600);
});
test("exchange rejects remote authority extensions, refresh grants and invalid credentials without writing a file", async (t) => {
  const config = fixture(t); const flow = createLoginFlow(config);
  for (const extra of [{ expires_in: 604801 }, { expires_in: 0 }, { expires_in: "604800" }, { refresh_token: "remote-secret" },
    { access_token: "foreign-bearer" }, { scope: "mcp admin" }, { token_type: "other" }, { endpoint: "https://evil.example" }]) {
    await assert.rejects(exchangeLoginCode(config, flow, "a".repeat(43), { fetchImpl: async () => tokenResponse(extra) })); assert.equal(fs.existsSync(config.tokenFile), false);
  }
});
test("human-initiated login receives a real loopback callback then stores its grant without discovery", async (t) => {
  const config = fixture(t); let authorization; let calls = 0;
  const result = await runLogin(config, { fetchImpl: async (url) => { calls++; assert.equal(url, config.origin + "/oauth/token"); return tokenResponse(); },
    onAuthorizationUrl: async (url) => {
      authorization = new URL(url); const destination = new URL(authorization.searchParams.get("redirect_uri"));
      destination.search = new URLSearchParams({ code: "a".repeat(43), state: authorization.searchParams.get("state"), iss: config.origin }).toString();
      const response = await get(destination); assert.equal(response.status, 200); assert.doesNotMatch(response.text, /aaaa|state|gw_/);
    } });
  assert.equal(calls, 1); assert.equal(typeof result.expiresAt, "number"); assert.equal(authorization.origin, config.origin);
});
test("callback listener has a finite timeout and closes without accepting stale callbacks", async (t) => {
  const config = fixture(t, "claude-code"); const flow = createLoginFlow(config); const listener = await startCallback(config, flow, { timeoutMs: 20 });
  assert.equal(listener.address, "127.0.0.1");
  await assert.rejects(listener.code, /LOGIN_NOT_COMPLETED/); listener.close();
});
test("container callback binding requires the explicit mode and preserves the exact loopback redirect", async (t) => {
  const config = fixture(t, "claude-code"); const flow = createLoginFlow(config);
  const listener = await startCallback(config, flow, { timeoutMs: 20, containerCallback: true });
  assert.equal(listener.address, "0.0.0.0"); assert.equal(flow.redirectUri, "http://localhost:17644/callback");
  await assert.rejects(listener.code, /LOGIN_NOT_COMPLETED/); listener.close();
});
