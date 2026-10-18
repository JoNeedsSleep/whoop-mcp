// Synthetic, dependency-free Node 22 tests. Execute only in approved isolation.
import test from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { mkdtempSync, readFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GatewayStore } from "./store.mjs";
import { ACCESS_TTL_MS, OWNER_TTL_MS, createGatewayAuth, pkceChallenge, sha256, validateCallback } from "./auth.mjs";

const ORIGIN = "https://gateway.example";
const RESOURCE = `${ORIGIN}/mcp`;
const SECRET = Buffer.alloc(32, 17).toString("base64url");
const VERIFIER = "a".repeat(43);
const CLIENTS = [
  { clientId: "codex", name: "Codex", redirectUris: ["http://127.0.0.1:17643/callback"] },
  { clientId: "claude-code", name: "Claude Code", redirectUris: ["http://localhost:17644/callback"] },
];
function fixture(t, filename = ":memory:") {
  const f = { time: Date.UTC(2026, 9, 18), jar: new Map(), initialTime: Date.UTC(2026, 9, 18) };
  f.store = new GatewayStore({ filename, now: () => f.time });
  f.options = { store: f.store, publicOrigin: ORIGIN, resource: RESOURCE, ownerSecretHash: sha256(SECRET), clients: CLIENTS, now: () => f.time };
  f.auth = createGatewayAuth(f.options);
  t.after(() => f.store.close());
  return f;
}
class Response {
  constructor() { this.headers = new Map(); this.headersSent = false; this.status = 0; this.body = ""; }
  setHeader(name, value) { this.headers.set(name.toLowerCase(), value); }
  getHeader(name) { return this.headers.get(name.toLowerCase()); }
  writeHead(status, headers = {}) { this.status = status; for (const [name, value] of Object.entries(headers)) this.setHeader(name, value); this.headersSent = true; }
  end(body = "") { this.body += body; }
  json() { return JSON.parse(this.body); }
}
async function request(f, path, { method = "GET", fields, body, headers = {}, jar = f.jar, update = true } = {}) {
  const bytes = Buffer.from(body ?? (fields ? new URLSearchParams(fields).toString() : ""));
  const req = Readable.from(bytes.length ? [bytes] : []);
  req.method = method; req.url = path;
  req.headers = { ...(jar?.size ? { cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; ") } : {}),
    ...(fields ? { "content-type": "application/x-www-form-urlencoded", "content-length": String(bytes.length) } : {}), ...headers };
  const res = new Response();
  res.handled = await f.auth.handleAuth(req, res, new URL(path, ORIGIN));
  if (update && jar) for (const cookie of res.getHeader("set-cookie") ?? []) {
    const [pair] = cookie.split(";"); const index = pair.indexOf("=");
    const name = pair.slice(0, index); const value = pair.slice(index + 1);
    if (/Max-Age=0(?:;|$)/i.test(cookie)) jar.delete(name); else jar.set(name, value);
  }
  return res;
}
const post = (f, path, fields, options = {}) => request(f, path, { method: "POST", fields, headers: { origin: ORIGIN, ...options.headers }, ...options });
function hidden(response, name) {
  const value = new RegExp(`name="${name}" value="([^"]+)"`).exec(response.body)?.[1];
  assert(value, `Missing ${name}`); return value;
}
function fields(response) { return { flow: hidden(response, "flow"), csrf: hidden(response, "csrf") }; }
function authorization(client = CLIENTS[0], overrides = {}) {
  return "/oauth/authorize?" + new URLSearchParams({ client_id: client.clientId, redirect_uri: client.redirectUris[0],
    response_type: "code", code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256", resource: RESOURCE, state: "synthetic-state", scope: "mcp", ...overrides });
}
async function approval(f, client = CLIENTS[0], decision = "allow") {
  let res = await request(f, authorization(client));
  assert.equal(res.status, 200);
  if (res.body.includes('name="secret"')) {
    res = await post(f, "/login", { ...fields(res), secret: SECRET });
    assert.equal(res.status, 200);
  }
  const consent = fields(res);
  const redirect = await post(f, "/consent", { ...consent, decision });
  assert.equal(redirect.status, 302);
  return { code: new URL(redirect.getHeader("location")).searchParams.get("code"), consent, redirect };
}
function exchange(f, code, client = CLIENTS[0], overrides = {}) {
  return post(f, "/oauth/token", { grant_type: "authorization_code", client_id: client.clientId,
    code, code_verifier: VERIFIER, redirect_uri: client.redirectUris[0], resource: RESOURCE, ...overrides });
}
async function grant(f, client = CLIENTS[0]) {
  const approved = await approval(f, client); const response = await exchange(f, approved.code, client);
  assert.equal(response.status, 200); return response.json().access_token;
}

test("metadata advertises only exact preregistered public-client OAuth with issuer and resource", async (t) => {
  const f = fixture(t);
  const metadata = await request(f, "/.well-known/oauth-authorization-server");
  assert.equal(metadata.status, 200);
  assert.equal(metadata.json().issuer, ORIGIN);
  assert.equal(metadata.json().authorization_response_iss_parameter_supported, true);
  assert.equal(metadata.json().registration_endpoint, undefined);
  assert.deepEqual(metadata.json().grant_types_supported, ["authorization_code"]);
  assert.deepEqual(metadata.json().code_challenge_methods_supported, ["S256"]);
  assert.deepEqual(metadata.json().token_endpoint_auth_methods_supported, ["none"]);
  for (const path of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]) {
    const response = await request(f, path); assert.equal(response.json().resource, RESOURCE);
    assert.equal(response.getHeader("cache-control"), "no-store");
  }
  assert.equal((await request(f, "/oauth/register")).handled, false);
});

test("callback configuration rejects aliases, wildcards, normalization, fragments and non-loopback HTTP", (t) => {
  const f = fixture(t);
  for (const callback of CLIENTS.flatMap((c) => c.redirectUris).concat("https://approved.example/callback")) assert(validateCallback(callback));
  for (const callback of ["http://127.0.0.1/callback", "http://localhost:80/callback", "http://[::1]:17643/callback",
    "http://127.0.0.2:17643/callback", "http://2130706433:17643/callback", "http://localhost.evil:17643/callback",
    "http://user@localhost:17643/callback", "http://localhost:17643/a/../callback", "http://localhost:17643/callback?x=1",
    "http://localhost:17643/callback#x", "http://localhost:*/callback", "https://approved.example/callback#x",
    "https://approved.example;script-src/callback", "https://approved.example%3Bscript-src/callback"]) assert.equal(validateCallback(callback), false, callback);
  assert.throws(() => createGatewayAuth({ ...f.options, publicOrigin: "http://gateway.example", resource: "http://gateway.example/mcp" }));
  assert.throws(() => createGatewayAuth({ ...f.options, ownerSecretHash: "not-a-hash" }));
  assert.throws(() => createGatewayAuth({ ...f.options, clients: [CLIENTS[0], CLIENTS[0]] }));
});

test("invalid authorization never sets cookies or redirects, including duplicate parameters and missing audience", async (t) => {
  const f = fixture(t);
  for (const overrides of [{ redirect_uri: CLIENTS[0].redirectUris[0].replace("17643", "17645") },
    { redirect_uri: CLIENTS[0].redirectUris[0].replace("127.0.0.1", "localhost") }, { client_id: "https://evil.example/metadata" },
    { resource: "" }, { resource: "https://whoop.example/mcp" }, { code_challenge_method: "plain" },
    { code_challenge: "invalid" }, { state: "" }, { scope: "mcp admin" }]) {
    const response = await request(f, authorization(CLIENTS[0], overrides));
    assert.equal(response.status, 400); assert.equal(response.getHeader("location"), undefined); assert.equal(response.getHeader("set-cookie"), undefined);
  }
  assert.equal((await request(f, authorization() + "&client_id=codex")).status, 400);
  assert.equal(f.store.list("flow").length, 0);
});

test("only consent permits its active callback origin in form-action; login and owner stay self-only", async (t) => {
  const f = fixture(t);
  const defaultPolicy = "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
  const policyFor = (origin) => `default-src 'none'; form-action 'self' ${origin}; frame-ancestors 'none'; base-uri 'none'`;
  const login = await request(f, authorization());
  assert.equal(login.getHeader("content-security-policy"), defaultPolicy);
  const consent = await post(f, "/login", { ...fields(login), secret: SECRET });
  assert.equal(consent.getHeader("content-security-policy"), policyFor("http://127.0.0.1:17643"));
  assert.equal((await request(f, authorization(CLIENTS[1]))).getHeader("content-security-policy"), policyFor("http://localhost:17644"));
  assert.equal((await request(f, "/owner")).getHeader("content-security-policy"), defaultPolicy);
  // Delimiters in an explicitly configured path never become CSP directives.
  const callback = "https://approved.example/callback;script-src%20%27unsafe-inline%27";
  assert(validateCallback(callback));
  const clients = [{ ...CLIENTS[0], redirectUris: [callback, "https://unused.example/callback"] }, CLIENTS[1]];
  const httpsAuth = createGatewayAuth({ ...f.options, clients });
  const httpsConsent = await request({ ...f, auth: httpsAuth }, authorization(clients[0]));
  assert.equal(httpsConsent.status, 200);
  assert.equal(httpsConsent.getHeader("content-security-policy"), policyFor("https://approved.example"));
  assert.doesNotMatch(httpsConsent.getHeader("content-security-policy"), /script-src|unsafe-inline|unused|localhost|127\.0\.0\.1/);
  assert.throws(() => createGatewayAuth({ ...f.options, clients: [{ ...CLIENTS[0], redirectUris: ["https://approved.example;script-src/callback"] }, CLIENTS[1]] }), /Invalid gateway client configuration/);
});

test("owner login requires exact Origin, dedicated secret and same-browser CSRF; consent is separate and single-use", async (t) => {
  const f = fixture(t);
  const initial = await request(f, authorization()); const login = fields(initial);
  assert.equal((await post(f, "/consent", { ...login, decision: "allow" })).status, 400);
  assert.equal((await post(f, "/login", { ...login, secret: SECRET }, { headers: { origin: "https://evil.example" } })).status, 400);
  assert.equal((await post(f, "/login", { ...login, secret: SECRET }, { jar: new Map() })).status, 403);
  assert.equal((await post(f, "/login", { ...login, csrf: Buffer.alloc(32, 8).toString("base64url"), secret: SECRET })).status, 403);
  assert.equal((await post(f, "/login", { ...login, secret: "whoop-or-model-credential" })).status, 403);
  const logged = await post(f, "/login", { ...login, secret: SECRET });
  assert.equal(logged.status, 200); assert.match(logged.body, /Approve WHOOP gateway access/);
  assert.equal(logged.getHeader("location"), undefined); assert.equal(f.store.list("code").length, 0);
  for (const value of [...initial.getHeader("set-cookie"), ...logged.getHeader("set-cookie")]) {
    assert.match(value, /^__Host-/); assert.match(value, /; Secure;/); assert.match(value, /; HttpOnly;/); assert.match(value, /; SameSite=Lax;/); assert.match(value, /; Path=\//); assert.doesNotMatch(value, /Domain=/i);
  }
  const ownerCookie = f.jar.get("__Host-gw_owner");
  assert.equal((await post(f, "/login", { ...login, secret: SECRET })).status, 403);
  assert.equal(f.jar.get("__Host-gw_owner"), ownerCookie);
  const response = await post(f, "/consent", { ...fields(logged), decision: "allow" });
  const callback = new URL(response.getHeader("location"));
  assert.equal(callback.origin + callback.pathname, CLIENTS[0].redirectUris[0]);
  assert.equal(callback.searchParams.get("state"), "synthetic-state"); assert.equal(callback.searchParams.get("iss"), ORIGIN);
  assert.equal((await post(f, "/consent", { ...fields(logged), decision: "allow" })).status, 400);
});

test("denial produces only access_denied on the approved callback and no redeemable code", async (t) => {
  const f = fixture(t); const denied = await approval(f, CLIENTS[1], "deny");
  assert.equal(denied.code, null); assert.equal(new URL(denied.redirect.getHeader("location")).searchParams.get("error"), "access_denied");
  assert.equal(f.store.list("code").length, 0); assert.equal(f.store.list("flow").length, 0);
});

test("code redemption is mandatory S256/resource/client/callback bound and one-use without consuming invalid attempts", async (t) => {
  const f = fixture(t); const { code } = await approval(f);
  for (const overrides of [{ code_verifier: "b".repeat(43) }, { code_verifier: "" }, { resource: "" },
    { resource: "https://other.example/mcp" }, { client_id: "claude-code" }, { redirect_uri: CLIENTS[1].redirectUris[0] }]) {
    const response = await exchange(f, code, CLIENTS[0], overrides); assert.equal(response.status, 400); assert.equal(response.json().error, "invalid_grant");
  }
  const response = await exchange(f, code); assert.equal(response.status, 200);
  assert.equal(response.json().expires_in, 604800); assert.equal(response.json().refresh_token, undefined);
  assert.equal((await exchange(f, code)).status, 400);
  assert.equal((await exchange(f, code, CLIENTS[0], { grant_type: "refresh_token" })).json().error, "unsupported_grant_type");
  const rows = JSON.stringify(f.store.db.prepare("SELECT * FROM records").all());
  for (const secret of [SECRET, code, response.json().access_token, f.jar.get("__Host-gw_owner")]) assert(!rows.includes(secret), "Raw credentials must not be persisted");
});

test("fixed seven-day token/owner deadlines do not slide; five-minute code and ten-minute flow expire exactly", async (t) => {
  const f = fixture(t); const token = await grant(f); const owner = f.jar.get("__Host-gw_owner");
  const original = f.auth.verifyBearer(token);
  f.time += 2 * 86400000;
  assert.deepEqual(f.auth.verifyBearer(token), original);
  assert(!((await request(f, "/owner")).body.includes('name="secret"')));
  const { code } = await approval(f); f.time += 5 * 60000;
  assert.equal((await exchange(f, code)).status, 400);
  const pending = await request(f, authorization()); const consent = fields(pending); f.time += 10 * 60000;
  assert.equal((await post(f, "/consent", { ...consent, decision: "allow" })).status, 400);
  f.time = f.initialTime + ACCESS_TTL_MS - 1; assert(f.auth.verifyBearer(token));
  assert(f.auth.verifyOwnerSession({ headers: { cookie: `__Host-gw_owner=${owner}` } }));
  f.time++; assert.equal(f.auth.verifyBearer(token), null);
  assert.equal(f.auth.verifyOwnerSession({ headers: { cookie: `__Host-gw_owner=${owner}` } }), null);
  assert.equal(ACCESS_TTL_MS, OWNER_TTL_MS);
});

test("independent revocation cancels client tokens and unredeemed flows/codes; revoke-all also invalidates owner sessions", async (t) => {
  const f = fixture(t); const codex = await grant(f); const claude = await grant(f, CLIENTS[1]);
  const pendingCode = await approval(f); const pendingFlow = fields(await request(f, authorization()));
  const page = await request(f, "/owner"); assert.match(page.body, /Codex: 1 active authorization/); assert.match(page.body, /Claude Code: 1 active authorization/);
  assert(!page.body.includes(codex)); assert(!page.body.includes(sha256(codex)));
  const csrf = hidden(page, "csrf");
  assert.equal((await post(f, "/owner/revoke", { csrf: "wrong", client_id: "codex" })).status, 400);
  assert(f.auth.verifyBearer(codex));
  assert.equal((await post(f, "/owner/revoke", { csrf, client_id: "codex" })).status, 303);
  assert.equal(f.auth.verifyBearer(codex), null); assert(f.auth.verifyBearer(claude));
  assert.equal((await exchange(f, pendingCode.code)).status, 400);
  assert.equal((await post(f, "/consent", { ...pendingFlow, decision: "allow" })).status, 400);
  const owner = f.jar.get("__Host-gw_owner");
  assert.equal((await post(f, "/owner/revoke", { csrf, client_id: "all" })).status, 303);
  assert.equal(f.auth.verifyBearer(claude), null); assert.equal(f.auth.verifyOwnerSession({ headers: { cookie: `__Host-gw_owner=${owner}` } }), null);
});

test("session fixation, duplicate cookies and rotated owner secret cannot authorize consent", async (t) => {
  const f = fixture(t);
  const planted = Buffer.alloc(32, 1).toString("base64url"); f.jar.set("__Host-gw_owner", planted);
  const initial = await request(f, authorization()); const logged = await post(f, "/login", { ...fields(initial), secret: SECRET });
  assert.equal(logged.status, 200); assert.notEqual(f.jar.get("__Host-gw_owner"), planted);
  const raw = f.jar.get("__Host-gw_owner");
  assert.equal(f.auth.verifyOwnerSession({ headers: { cookie: `__Host-gw_owner=${raw}; __Host-gw_owner=${raw}` } }), null);
  const rotated = createGatewayAuth({ ...f.options, ownerSecretHash: sha256(Buffer.alloc(32, 18).toString("base64url")) });
  assert.equal(rotated.verifyOwnerSession({ headers: { cookie: `__Host-gw_owner=${raw}` } }), null);
});

test("bounded forms and state admission fail closed with fixed errors", async (t) => {
  const f = fixture(t);
  for (const [body, headers] of [["x".repeat(8193), { "content-type": "application/x-www-form-urlencoded" }],
    ["csrf=x", { "content-type": "application/json" }], ["csrf=x&csrf=y", { "content-type": "application/x-www-form-urlencoded" }]]) {
    const response = await request(f, "/login", { method: "POST", body, headers: { origin: ORIGIN, ...headers } });
    assert.equal(response.status, 400); assert.deepEqual(response.json(), { error: "invalid_request" });
  }
  for (let i = 0; i < 100; i++) assert(f.store.put("flow", `synthetic-${i}`, { marker: i }, f.time + 600000));
  const full = await request(f, authorization()); assert.equal(full.status, 503); assert.equal(full.getHeader("set-cookie"), undefined);
  assert.equal(f.store.list("flow").length, 100);
  f.time += 600000;
  assert.equal((await request(f, authorization())).status, 200); assert.equal(f.store.list("flow").length, 1);
});

test("durable owner-login attempt budget is shared across handles and does not allocate sessions on failure", async (t) => {
  const directory = mkdtempSync(join(tmpdir(), "gateway-auth-budget-")); t.after(() => rmSync(directory, { recursive: true, force: true }));
  const filename = join(directory, "gateway.sqlite"); const f = fixture(t, filename);
  const initial = await request(f, authorization()); const login = fields(initial);
  for (let i = 0; i < 20; i++) assert.equal((await post(f, "/login", { ...login, secret: "wrong" })).status, 403);
  const other = new GatewayStore({ filename, now: () => f.time }); t.after(() => other.close());
  const auth = createGatewayAuth({ ...f.options, store: other });
  const response = await post({ ...f, auth }, "/login", { ...login, secret: SECRET });
  assert.equal(response.status, 429); assert.equal(other.list("session").length, 0);
  f.time += 3600000;
  const fresh = await request(f, authorization());
  assert.equal((await post(f, "/login", { ...fields(fresh), secret: SECRET })).status, 200);
});

test("durable global quota and single-flight lease survive new handles; failures spend budget and stale releases cannot unlock a new lease", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "gateway-tool-budget-"));
  const filename = join(directory, "gateway.sqlite"); let time = Date.UTC(2026, 9, 18);
  const first = new GatewayStore({ filename, now: () => time }); const second = new GatewayStore({ filename, now: () => time });
  t.after(() => { first.close(); second.close(); rmSync(directory, { recursive: true, force: true }); });
  const old = first.acquireToolCall(); assert(old); assert.equal(second.acquireToolCall(), null);
  time += 15000; const current = second.acquireToolCall(); assert(current); first.releaseToolCall(old);
  assert.equal(first.acquireToolCall(), null); second.releaseToolCall(current);
  for (let i = 2; i < 30; i++) { const store = i % 2 ? first : second; const lease = store.acquireToolCall(); assert(lease); store.releaseToolCall(lease); }
  assert.equal(first.acquireToolCall(), null); assert.equal(second.acquireToolCall(), null);
  time += 3600000; const lease = second.acquireToolCall(); assert(lease); second.releaseToolCall(lease);
});

test("database is private and rolls back issuance on storage failure without burning its code", async (t) => {
  const directory = mkdtempSync(join(tmpdir(), "gateway-auth-durable-")); const filename = join(directory, "gateway.sqlite");
  const f = fixture(t, filename); t.after(() => rmSync(directory, { recursive: true, force: true }));
  const { code } = await approval(f);
  for (let i = 0; i < 100; i++) f.store.put("token", `synthetic-${i}`, { clientId: "codex", audience: RESOURCE }, f.time + ACCESS_TTL_MS);
  assert.equal((await exchange(f, code)).status, 400); assert(f.store.get("code", sha256(code)));
  f.store.delete("token", "synthetic-0"); const response = await exchange(f, code); assert.equal(response.status, 200);
  const bytes = readFileSync(filename); for (const raw of [SECRET, code, response.json().access_token]) assert(!bytes.includes(Buffer.from(raw)));
  chmodSync(filename, 0o644); assert.throws(() => new GatewayStore({ filename }), /Private gateway database file required/); chmodSync(filename, 0o600);
});
