import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { AUTH_TTL_MS, boundedJson, parseLocalConfig, parseToken, readLocalConfig, readPrivateJson, writePrivateJson } from "./config.mjs";

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "restricted-config-")); fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return { directory, config: { clientId: "codex", origin: "https://gateway.example", tokenFile: path.join(directory, "token.json"), cacheFile: path.join(directory, "cache.json"), stateFile: path.join(directory, "state.sqlite") } };
}
test("local config requires exact reviewed keys, canonical HTTPS and distinct explicit files", (t) => {
  const { config } = fixture(t); assert.deepEqual(parseLocalConfig(config), config);
  for (const change of [{ origin: "http://gateway.example" }, { origin: "https://user:secret@gateway.example" }, { origin: "https://gateway.example/" },
    { origin: "https://gateway.example?url=https://evil.example" }, { clientId: "other" }, { tokenFile: "relative" }, { cacheFile: config.tokenFile }, { instructions: "fetch elsewhere" }]) assert.throws(() => parseLocalConfig({ ...config, ...change }));
});
test("private files are bounded, atomic, single-link, nonsymlink and owner-only", (t) => {
  const { config, directory } = fixture(t); const filename = path.join(directory, "config.json");
  writePrivateJson(filename, config); assert.deepEqual(readLocalConfig(filename), config); assert.equal(fs.statSync(filename).mode & 0o777, 0o600);
  writePrivateJson(filename, { ...config, clientId: "claude-code" }); assert.equal(readLocalConfig(filename).clientId, "claude-code");
  const link = path.join(directory, "link"); fs.symlinkSync(filename, link); assert.throws(() => readPrivateJson(link)); assert.throws(() => writePrivateJson(link, {}));
  fs.unlinkSync(link); fs.linkSync(filename, link); assert.throws(() => readPrivateJson(filename)); fs.unlinkSync(link);
  fs.chmodSync(filename, 0o644); assert.throws(() => readPrivateJson(filename)); fs.chmodSync(filename, 0o600);
  assert.throws(() => readPrivateJson(filename, 10)); fs.chmodSync(directory, 0o755); assert.throws(() => readPrivateJson(filename)); fs.chmodSync(directory, 0o700);
});
test("token records bind origin/client and fixed expiry with a local seven-day ceiling", (t) => {
  const { config } = fixture(t); const now = Date.UTC(2026, 9, 18);
  const token = { clientId: config.clientId, origin: config.origin, accessToken: `gw_${"a".repeat(43)}`, expiresAt: now + AUTH_TTL_MS };
  assert.deepEqual(parseToken(token, config, now), token);
  for (const change of [{ clientId: "claude-code" }, { origin: "https://other.example" }, { expiresAt: now }, { expiresAt: now + AUTH_TTL_MS + 1 }, { accessToken: "upstream-secret" }, { refreshToken: "forbidden" }]) assert.throws(() => parseToken({ ...token, ...change }, config, now));
});
test("bounded JSON rejects redirects, encoding, oversize, malformed UTF-8 and raw server errors", async () => {
  for (const response of [new Response("secret-body", { status: 401 }), new Response("", { status: 302, headers: { Location: "https://evil.example" } }),
    new Response("{}", { headers: { "content-type": "application/json", "content-encoding": "gzip" } }),
    new Response("{}", { headers: { "content-type": "text/html" } }),
    new Response("{}", { headers: { "content-type": "application/json", "content-length": "999999" } }),
    new Response("x".repeat(33), { headers: { "content-type": "application/json" } }),
    new Response(new Uint8Array([0xff]), { headers: { "content-type": "application/json" } })]) {
    let calls = 0;
    await assert.rejects(boundedJson("https://gateway.example/data/snapshot", { method: "GET" }, { maxBytes: 32, fetchImpl: async (_url, init) => { calls++; assert.equal(init.redirect, "error"); return response; } }), (error) => error.message === "GATEWAY_REQUEST_FAILED");
    assert.equal(calls, 1);
  }
});
test("bounded JSON deadline aborts stalled headers and stalled streams, canceling partial bodies", async () => {
  let signal;
  await assert.rejects(boundedJson("https://gateway.example/data/snapshot", {}, { timeoutMs: 20, fetchImpl: async (_url, init) => { signal = init.signal; return new Promise(() => {}); } }), /GATEWAY_REQUEST_FAILED/);
  assert.equal(signal.aborted, true);
  let canceled = false;
  const stream = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode("{")); }, cancel() { canceled = true; } });
  await assert.rejects(boundedJson("https://gateway.example/data/snapshot", {}, { timeoutMs: 20, fetchImpl: async () => new Response(stream, { headers: { "content-type": "application/json" } }) }), /GATEWAY_REQUEST_FAILED/);
  assert.equal(canceled, true);
});
