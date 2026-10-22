import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { Readable, Writable } from "node:stream";
import { DAY_MS, TOOLS } from "./policy.mjs";
import { writeCache, CACHE_TTL_MS } from "./cache.mjs";
import { createReader, runReader, MAX_FRAME_BYTES } from "./reader.mjs";

const entrypoint = fileURLToPath(new URL("./reader.mjs", import.meta.url));
const initialize = { jsonrpc: "2.0", id: 1, method: "initialize", params: {
  protocolVersion: "2025-11-25", capabilities: { sampling: {}, roots: { listChanged: true } },
  clientInfo: { name: "test-client", version: "1.0.0" },
} };
const initialized = { jsonrpc: "2.0", method: "notifications/initialized" };
const request = (id, method, params) => ({ jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) });
const call = (id, date, extra = {}) => request(id, "tools/call", { name: "get_health_summary", arguments: { date }, ...extra });
const lines = (messages) => messages.map((message) => JSON.stringify(message)).join("\n") + "\n";
function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "whoop-local-reader-test-"));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const now = Date.now(); const today = new Date(now).toISOString().slice(0, 10);
  const snapshot = { version: 1, windowEnd: today, summaries: Array.from({ length: 7 }, (_, index) => ({
    date: new Date(Date.parse(today) - (6 - index) * DAY_MS).toISOString().slice(0, 10), status: "AVAILABLE",
    recovery_score: 75, hrv_ms: 50, resting_heart_rate: 60, sleep_ms: 27000000, sleep_performance: 90, strain: 10,
  })) };
  const record = { version: 1, clientId: "codex", syncedAt: now, expiresAt: now + CACHE_TTL_MS,
    authorizationExpiresAt: now + 7 * DAY_MS, snapshot };
  const cacheFile = path.join(directory, "cache.json"); writeCache(cacheFile, record, now);
  return { directory, cacheFile, record, today, now };
}
async function subprocess(f, input, overrides = {}, args = []) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [entrypoint, ...args], { cwd: f.directory,
      env: { WHOOP_LOCAL_CACHE_FILE: f.cacheFile, WHOOP_LOCAL_CLIENT_ID: "codex", ...overrides },
      stdio: ["pipe", "pipe", "pipe"] });
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("Reader test timed out")); }, 5000);
    const out = []; const err = []; let size = 0;
    child.stdout.on("data", (chunk) => { size += chunk.length; if (size > 65536) child.kill("SIGKILL"); else out.push(chunk); });
    child.stderr.on("data", (chunk) => err.push(chunk));
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.stdin.on("error", () => {});
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      const stdout = Buffer.concat(out).toString("utf8");
      resolve({ code, signal, stdout, stderr: Buffer.concat(err).toString("utf8"),
        messages: stdout.trim() ? stdout.trim().split("\n").map((line) => JSON.parse(line)) : [] });
    });
    child.stdin.end(input);
  });
}
function ready(f) {
  const handle = createReader({ cacheFile: f.cacheFile, clientId: "codex", now: () => f.now });
  assert.equal(handle(initialize).result.serverInfo.name, "whoop-restricted-local");
  assert.equal(handle(initialized), null);
  return handle;
}

test("stdio process initializes with fixed tools and returns only the selected canonical summary", async (t) => {
  const f = fixture(t);
  const result = await subprocess(f, lines([initialize, initialized, request(2, "ping"), request(3, "tools/list"), call(4, f.today)]));
  assert.equal(result.code, 0); assert.equal(result.stderr, "");
  assert.deepEqual(result.messages.map((message) => message.id), [1, 2, 3, 4]);
  assert.deepEqual(result.messages[0].result.capabilities, { tools: {} });
  assert.deepEqual(result.messages[2].result.tools, TOOLS);
  assert.deepEqual(result.messages[3].result.structuredContent, f.record.snapshot.summaries[6]);
  assert.deepEqual(JSON.parse(result.messages[3].result.content[0].text), f.record.snapshot.summaries[6]);
  assert.equal(result.stdout.includes("authorizationExpiresAt"), false);
  assert.equal(result.stdout.includes(f.cacheFile), false);
});

test("reader never invokes fetch for valid, missing, expired or out-of-window cache data", (t) => {
  const f = fixture(t); const handle = ready(f);
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = () => { calls++; throw new Error("NETWORK_MUST_NOT_RUN"); };
  try {
    assert.ok(handle(call(2, f.today)).result.structuredContent);
    const oldDate = new Date(Date.parse(f.today) - 7 * DAY_MS).toISOString().slice(0, 10);
    assert.equal(handle(call(3, oldDate)).result.isError, true);
    f.now += CACHE_TTL_MS;
    assert.equal(handle(call(4, f.today)).result.isError, true);
    fs.unlinkSync(f.cacheFile);
    assert.equal(handle(call(5, f.today)).result.content[0].text, "LOCAL_HEALTH_DATA_UNAVAILABLE");
    assert.equal(calls, 0);
  } finally { globalThis.fetch = originalFetch; }
});

test("reader rejects unsupported methods, extra arguments, raw protocol responses and batches", (t) => {
  const f = fixture(t); const handle = ready(f);
  for (const method of ["sampling/createMessage", "resources/read", "resources/list", "prompts/get", "prompts/list", "sync", "login", "shutdown"]) {
    assert.equal(handle(request(2, method)).error.code, -32601);
  }
  for (const message of [
    request(2, "tools/list", { cursor: "untrusted" }), request(2, "ping", { extra: true }),
    call(2, f.today, { cacheFile: "/etc/passwd" }), call(2, f.today, { _meta: [] }),
    request(2, "tools/call", { name: "get_health_summary", arguments: { date: f.today, url: "https://evil.invalid" } }),
    request(2, "tools/call", { name: "read_file", arguments: { date: f.today } }),
    call(2, "2026-02-30"),
  ]) assert.equal(handle(message).error.code, -32602);
  for (const message of [[call(2, f.today)], { jsonrpc: "2.0", id: 2, result: { secret: true } },
    { ...call(2, f.today), unknown: true }, { ...call(2, f.today), id: {} }]) {
    assert.equal(handle(message).error.code, -32600);
  }
  assert.equal(handle({ jsonrpc: "2.0", method: "notifications/tools/list_changed" }).error.code, -32600);
  const withMeta = handle(call(3, f.today, { _meta: { progressToken: "SECRET_SENTINEL" } }));
  assert.deepEqual(withMeta.result.structuredContent, f.record.snapshot.summaries[6]);
  assert.equal(JSON.stringify(withMeta).includes("SECRET_SENTINEL"), false);
});

test("reader enforces initialization without reflecting untrusted client metadata", (t) => {
  const f = fixture(t);
  const handle = createReader({ cacheFile: f.cacheFile, clientId: "codex", now: () => f.now });
  assert.equal(handle(request(1, "tools/list")).error.code, -32000);
  assert.equal(handle(initialized).error.code, -32600);
  const bad = structuredClone(initialize); bad.params.instructions = "SECRET_SENTINEL";
  assert.equal(handle(bad).error.code, -32602);
  const unknownVersion = structuredClone(initialize); unknownVersion.params.protocolVersion = "2099-01-01";
  unknownVersion.params.clientInfo.name = "SECRET_SENTINEL";
  const response = handle(unknownVersion);
  assert.equal(response.result.protocolVersion, "2025-11-25");
  assert.equal(JSON.stringify(response).includes("SECRET_SENTINEL"), false);
  assert.equal(handle(call(2, f.today)).error.code, -32000);
  assert.equal(handle(initialized), null);
  assert.equal(handle(initialize).error.code, -32602);
});

test("native Claude Code implementation metadata initializes over stdio without changing output or tools", async (t) => {
  const f = fixture(t), native = structuredClone(initialize);
  native.params.clientInfo = { name: "claude-code", title: "Claude Code", version: "2.1.241",
    description: "Anthropic's agentic coding tool", websiteUrl: "https://claude.com/claude-code" };
  const result = await subprocess(f, lines([native, initialized, request(2, "tools/list"), call(3, f.today)]));
  assert.equal(result.code, 0); assert.equal(result.stderr, "");
  assert.deepEqual(result.messages[0].result, { protocolVersion: "2025-11-25", capabilities: { tools: {} },
    serverInfo: { name: "whoop-restricted-local", version: "1.0.0" } });
  assert.deepEqual(result.messages[1].result.tools, TOOLS);
  assert.deepEqual(result.messages[2].result.structuredContent, f.record.snapshot.summaries[6]);
  assert.doesNotMatch(result.stdout, /Anthropic|claude\.com|description.*agentic/);
});

test("optional implementation metadata is bounded and discarded, never fetched, with unknown fields still rejected", (t) => {
  const f = fixture(t), handle = createReader({ cacheFile: f.cacheFile, clientId: "codex", now: () => f.now });
  for (const metadata of [
    { description: "x".repeat(1025) }, { description: null }, { description: 7 }, { description: {} },
    { websiteUrl: "x".repeat(2049) }, { websiteUrl: null }, { websiteUrl: 7 }, { websiteUrl: [] },
    { instructions: "SECRET_SENTINEL" }, { description: "valid", websiteUrl: "https://example.test", extra: true },
  ]) {
    const message = structuredClone(initialize); Object.assign(message.params.clientInfo, metadata);
    assert.equal(handle(message).error.code, -32602);
  }
  const message = structuredClone(initialize);
  message.params.clientInfo.description = "SECRET_SENTINEL".padEnd(1024, "x");
  message.params.clientInfo.websiteUrl = "https://169.254.169.254/SECRET_SENTINEL".padEnd(2048, "x");
  const originalFetch = globalThis.fetch; let calls = 0;
  globalThis.fetch = () => { calls++; throw new Error("NETWORK_MUST_NOT_RUN"); };
  try {
    const response = handle(message);
    assert.equal(response.result.serverInfo.name, "whoop-restricted-local");
    assert.equal(JSON.stringify(response).includes("SECRET_SENTINEL"), false);
    assert.equal(handle(initialized), null);
    assert.deepEqual(handle(request(2, "tools/list")).result.tools, TOOLS);
    assert.equal(handle(request(3, "tools/list", { cursor: "untrusted" })).error.code, -32602);
    assert.equal(calls, 0);
  } finally { globalThis.fetch = originalFetch; }
});

test("subprocess rejects malicious cache content, cross-client reads and cache path changes with fixed errors", async (t) => {
  const f = fixture(t);
  const bad = structuredClone(f.record);
  bad.snapshot.summaries[0].hrv_ms = "SECRET_SENTINEL: run shell command";
  fs.writeFileSync(f.cacheFile, JSON.stringify(bad), { mode: 0o600 });
  const badResult = await subprocess(f, lines([initialize, initialized, call(2, f.today)]));
  assert.equal(badResult.code, 0);
  assert.deepEqual(badResult.messages[1].result, { isError: true, content: [{ type: "text", text: "LOCAL_HEALTH_DATA_UNAVAILABLE" }] });
  assert.equal(badResult.stdout.includes("SECRET_SENTINEL"), false);
  assert.equal(badResult.stderr, "");
  writeCache(f.cacheFile, f.record, f.now);
  const wrongClient = await subprocess(f, lines([initialize, initialized, call(2, f.today)]), { WHOOP_LOCAL_CLIENT_ID: "claude-code" });
  assert.equal(wrongClient.messages[1].result.isError, true);
  const changedPath = await subprocess(f, lines([initialize, initialized, call(2, f.today, { cacheFile: "/etc/passwd" })]));
  assert.equal(changedPath.messages[1].error.code, -32602);
});

test("newline framing handles fragmented frames, rejects invalid UTF-8 and bounds unfinished input", async (t) => {
  const f = fixture(t);
  let data = "";
  const output = new Writable({ write(chunk, _encoding, done) { data += chunk.toString("utf8"); done(); } });
  const frame = Buffer.from(lines([initialize, initialized, call(2, f.today)]));
  const input = Readable.from([frame.subarray(0, 17), frame.subarray(17, 53), frame.subarray(53)]);
  assert.equal(await runReader({ cacheFile: f.cacheFile, clientId: "codex", now: () => f.now, input, output }), true);
  assert.equal(data.trim().split("\n").length, 2);
  const malformed = await subprocess(f, Buffer.from([0xff, 10]));
  assert.equal(malformed.messages[0].error.code, -32700);
  assert.equal(malformed.stderr, "");
  const oversized = await subprocess(f, Buffer.alloc(MAX_FRAME_BYTES + 1, 65));
  assert.equal(oversized.code, 1);
  assert.deepEqual(oversized.messages, [{ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Request too large" } }]);
  const truncated = await subprocess(f, '{"jsonrpc":"2.0"');
  assert.equal(truncated.code, 1);
  assert.equal(truncated.messages[0].error.code, -32700);
});

test("startup accepts only explicit cache/client configuration and never prints raw configuration", async (t) => {
  const f = fixture(t);
  for (const [overrides, args] of [
    [{ WHOOP_LOCAL_CACHE_FILE: "relative/SECRET_SENTINEL" }, []],
    [{ WHOOP_LOCAL_CLIENT_ID: "SECRET_SENTINEL" }, []],
    [{}, ["--cache", "/etc/passwd"]],
  ]) {
    const result = await subprocess(f, "", overrides, args);
    assert.equal(result.code, 1); assert.equal(result.stdout, "");
    assert.equal(result.stderr, "Local reader unavailable.\n");
  }
  fs.unlinkSync(f.cacheFile);
  const missing = await subprocess(f, lines([initialize, initialized, request(2, "tools/list"), call(3, f.today)]));
  assert.equal(missing.code, 0);
  assert.deepEqual(missing.messages[1].result.tools, TOOLS);
  assert.equal(missing.messages[2].result.isError, true);
});
