// Run only in the approved offline container. This exercises a synthetic TLS
// proxy and the real runtime entrypoint, not a browser or deployed ingress.
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import { createHash, randomBytes } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { startGateway } from "./index.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const random = () => randomBytes(32).toString("base64url");
const entrypoint = fileURLToPath(new URL("./index.mjs", import.meta.url));
async function listen(server, port = 0) {
  server.listen(port, "127.0.0.1"); await once(server, "listening"); return server.address().port;
}
async function close(server) {
  if (!server?.listening) return;
  const closed = new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  server.closeAllConnections(); await closed;
}
async function freePort() { const probe = http.createServer(); const port = await listen(probe); await close(probe); return port; }
function privateFixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gateway-runtime-"));
  fs.chmodSync(directory, 0o700);
  const storage = path.join(directory, "storage"); fs.mkdirSync(storage, { mode: 0o700 });
  const owner = random(); const service = `whoopgw_service_${random()}`;
  fs.writeFileSync(path.join(directory, "owner-key"), owner + "\n", { mode: 0o600, flag: "wx" });
  const upstreamTokenFile = path.join(directory, "service-key");
  fs.writeFileSync(upstreamTokenFile, service + "\n", { mode: 0o600, flag: "wx" });
  const config = (publicOrigin, port) => ({ publicOrigin, port, upstreamOrigin: "https://unconnected-whoop.invalid",
    ownerSecretHash: sha256(owner), upstreamTokenFile, databaseFile: path.join(storage, "gateway.sqlite"),
    clients: [
      { clientId: "codex", name: "Codex fixture", redirectUris: ["http://127.0.0.1:1455/auth/callback"] },
      { clientId: "claude-code", name: "Claude Code fixture", redirectUris: ["http://localhost:1456/callback"] },
    ] });
  return { directory, storage, owner, service, config,
    cleanup: () => fs.rmSync(directory, { recursive: true, force: true }) };
}
function certificates(directory) {
  const supplied = process.env.GATEWAY_TEST_TLS_DIR;
  if (supplied !== undefined) {
    // Explicitly supplied synthetic fixtures may be generated in a separate
    // verified offline helper when the pinned runtime omits the openssl CLI.
    // Trust remains scoped to this test's CA; hostname verification stays on.
    assert(path.isAbsolute(supplied), "GATEWAY_TEST_TLS_DIR must be an absolute synthetic fixture directory.");
    const info = fs.lstatSync(supplied);
    assert(info.isDirectory() && !info.isSymbolicLink(), "Synthetic TLS fixture directory must be a real directory.");
    const read = (name, privateKey = false) => {
      const fd = fs.openSync(path.join(supplied, name), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      try {
        const stat = fs.fstatSync(fd);
        assert(stat.isFile() && stat.size > 0 && stat.size <= 65536, "Invalid synthetic TLS fixture file.");
        if (privateKey) assert.equal(stat.mode & 0o077, 0, "Synthetic TLS private key must not be group/world accessible.");
        return fs.readFileSync(fd);
      } finally { fs.closeSync(fd); }
    };
    return { ca: read("ca.pem"), cert: read("server.pem"), key: read("server-key.pem", true) };
  }
  const env = { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: directory, TMPDIR: directory, LC_ALL: "C" };
  const openssl = (...args) => {
    const result = spawnSync("openssl", args, { cwd: directory, env, encoding: "utf8", timeout: 15000 });
    if (result.error?.code === "ENOENT") assert.fail("Runtime TLS tests require openssl or explicit synthetic fixtures in GATEWAY_TEST_TLS_DIR inside the approved offline container; no test was skipped.");
    assert.equal(result.status, 0, "Synthetic TLS certificate generation failed inside the test container.");
  };
  openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca-key.pem", "-out", "ca.pem",
    "-subj", "/CN=WHOOP Runtime Fixture CA", "-days", "1", "-sha256",
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign");
  openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "server-key.pem", "-out", "server.csr", "-subj", "/CN=127.0.0.1");
  fs.writeFileSync(path.join(directory, "leaf.cnf"),
    "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n", { mode: 0o600 });
  openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca-key.pem", "-CAcreateserial",
    "-out", "server.pem", "-days", "1", "-sha256", "-extfile", "leaf.cnf");
  return { ca: fs.readFileSync(path.join(directory, "ca.pem")), cert: fs.readFileSync(path.join(directory, "server.pem")),
    key: fs.readFileSync(path.join(directory, "server-key.pem")) };
}
function request(client, options, body = "") {
  return new Promise((resolve, reject) => {
    const req = client.request({ agent: false, ...options }, (res) => {
      const chunks = []; res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString("utf8") }));
    });
    req.setTimeout(10000, () => req.destroy(new Error("Runtime fixture request timed out")));
    req.once("error", reject); req.end(body);
  });
}
function hidden(html, name) {
  const value = new RegExp(`name="${name}" value="([^"]+)"`).exec(html)?.[1];
  assert(value, `Missing synthetic ${name} field`); return value;
}

test("real runtime works behind a certificate-verified loopback TLS proxy with secure OAuth cookies", { timeout: 30000 }, async (t) => {
  const f = privateFixture();
  const oldUmask = process.umask(0o077);
  let runtime; let proxy;
  t.after(async () => {
    try { await close(proxy); await close(runtime?.server); runtime?.store.close(); }
    finally { process.umask(oldUmask); f.cleanup(); }
  });
  const tls = certificates(f.directory);
  const backendPort = await freePort();
  let publicOrigin;
  proxy = https.createServer({ key: tls.key, cert: tls.cert, minVersion: "TLSv1.2" }, (req, res) => {
    const expectedHost = new URL(publicOrigin).host;
    // This fixture checks the public authority before overwriting proxy headers.
    // The backend never trusts a client-supplied forwarded host or protocol.
    if (req.headers.host !== expectedHost) { res.writeHead(403); res.end("Forbidden"); return; }
    const headers = { ...req.headers, host: expectedHost, "x-forwarded-proto": "https", "x-forwarded-host": expectedHost };
    for (const name of ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "forwarded"]) delete headers[name];
    const upstream = http.request({ host: "127.0.0.1", port: backendPort, path: req.url, method: req.method, headers, agent: false }, (reply) => {
      res.writeHead(reply.statusCode, reply.headers); reply.pipe(res);
    });
    upstream.setTimeout(10000, () => upstream.destroy());
    upstream.on("error", () => { if (!res.headersSent) res.writeHead(502); res.end("Proxy unavailable"); });
    req.pipe(upstream);
  });
  const tlsPort = await listen(proxy);
  publicOrigin = `https://127.0.0.1:${tlsPort}`;
  const config = f.config(publicOrigin, backendPort);
  runtime = startGateway(config); await once(runtime.server, "listening");
  assert.equal(runtime.server.address().address, "127.0.0.1");
  assert.equal(fs.statSync(path.join(f.directory, "owner-key")).mode & 0o777, 0o600);
  assert.equal(fs.statSync(f.storage).mode & 0o777, 0o700);
  assert.equal(fs.statSync(config.databaseFile).mode & 0o777, 0o600);

  const jar = new Map();
  const send = async (route, { method = "GET", body = "", headers = {}, browser = false, servername } = {}) => {
    // Keep TLS identity independent of the HTTP Host under test. An explicit
    // wrong-name override below still exercises certificate hostname rejection.
    const r = await request(https, { hostname: "127.0.0.1", servername: servername ?? "127.0.0.1", port: tlsPort, path: route, method, ca: tls.ca,
      headers: { ...(browser && jar.size ? { Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; ") } : {}), ...headers } }, body);
    if (browser) for (const value of r.headers["set-cookie"] ?? []) {
      assert.match(value, /;\s*Secure(?:;|$)/i); assert.match(value, /;\s*HttpOnly(?:;|$)/i);
      assert.match(value, /;\s*SameSite=Lax(?:;|$)/i); assert.match(value, /;\s*Path=\/(?:;|$)/i);
      assert.doesNotMatch(value, /;\s*Domain=/i);
      const pair = value.split(";")[0]; const i = pair.indexOf("=");
      if (/;\s*Max-Age=0(?:;|$)/i.test(value)) jar.delete(pair.slice(0, i));
      else jar.set(pair.slice(0, i), pair.slice(i + 1));
    }
    return r;
  };
  const post = (route, fields, browser = false) => send(route, { method: "POST", browser,
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...(browser ? { Origin: publicOrigin } : {}) }, body: new URLSearchParams(fields).toString() });
  const metadata = await send("/.well-known/oauth-authorization-server");
  assert.equal(metadata.status, 200); assert.equal(JSON.parse(metadata.text).issuer, publicOrigin);
  assert.equal((await send("/.well-known/oauth-authorization-server", { headers: { Host: "evil.example" } })).status, 403);
  assert.equal((await send("/owner", { headers: { Origin: "https://evil.example" } })).status, 403);
  await assert.rejects(send("/owner", { servername: "wrong.example" }), (error) => error.code === "ERR_TLS_CERT_ALTNAME_INVALID");
  await assert.rejects(request(https, { hostname: "127.0.0.1", port: tlsPort, path: "/owner" }),
    (error) => ["UNABLE_TO_VERIFY_LEAF_SIGNATURE", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "SELF_SIGNED_CERT_IN_CHAIN", "DEPTH_ZERO_SELF_SIGNED_CERT"].includes(error.code));

  const verifier = random(); const state = random(); const redirectUri = config.clients[0].redirectUris[0];
  const authorization = new URLSearchParams({ client_id: "codex", redirect_uri: redirectUri, response_type: "code",
    code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256",
    resource: `${publicOrigin}/mcp`, state, scope: "mcp" });
  const loginPage = await send(`/oauth/authorize?${authorization}`, { browser: true });
  assert.equal(loginPage.status, 200);
  const signedIn = await post("/login", { flow: hidden(loginPage.text, "flow"), csrf: hidden(loginPage.text, "csrf"),
    secret: fs.readFileSync(path.join(f.directory, "owner-key"), "utf8").trim() }, true);
  assert.equal(signedIn.status, 200);
  assert((signedIn.headers["set-cookie"] ?? []).some((value) => /__Host-gw_owner=/.test(value) && /Max-Age=604800/.test(value)));
  const consent = await post("/consent", { flow: hidden(signedIn.text, "flow"), csrf: hidden(signedIn.text, "csrf"), decision: "allow" }, true);
  assert.equal(consent.status, 302);
  const callback = new URL(consent.headers.location);
  assert.equal(`${callback.origin}${callback.pathname}`, redirectUri);
  assert.equal(callback.searchParams.get("state"), state); assert.equal(callback.searchParams.get("iss"), publicOrigin);
  // Do not follow or contact an installed native client; exchange its synthetic code here.
  const granted = await post("/oauth/token", { grant_type: "authorization_code", client_id: "codex",
    code: callback.searchParams.get("code"), code_verifier: verifier, redirect_uri: redirectUri, resource: `${publicOrigin}/mcp` });
  assert.equal(granted.status, 200); const tokens = JSON.parse(granted.text);
  assert.equal(tokens.expires_in, 604800);
  const listBody = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  const mcpHeaders = { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25" };
  assert.equal((await send("/mcp", { method: "POST", body: listBody, headers: mcpHeaders, browser: true })).status, 401,
    "A secure owner cookie must not substitute for an MCP bearer");
  const listed = await send("/mcp", { method: "POST", body: listBody, headers: { ...mcpHeaders, Authorization: `Bearer ${tokens.access_token}` } });
  assert.equal(listed.status, 200);
  assert.deepEqual(JSON.parse(listed.text).result.tools.map((tool) => tool.name), ["get_health_summary"]);
  assert.equal(listed.text.includes(f.owner), false); assert.equal(listed.text.includes(f.service), false);
});

test("CLI entrypoint starts on loopback and closes cleanly on SIGTERM without logging credentials", { timeout: 20000 }, async (t) => {
  const f = privateFixture(); const port = await freePort(); const config = f.config("https://gateway.example", port);
  const filename = path.join(f.directory, "config.json"); fs.writeFileSync(filename, JSON.stringify(config), { mode: 0o600, flag: "wx" });
  const child = spawn(process.execPath, [entrypoint], { cwd: f.directory,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", GATEWAY_CONFIG_FILE: filename }, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = ""; let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; }); child.stderr.on("data", (chunk) => { stderr += chunk; });
  const exited = once(child, "exit");
  t.after(async () => {
    try { if (child.exitCode === null && child.signalCode === null) { child.kill("SIGKILL"); await exited; } }
    finally { f.cleanup(); }
  });
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Gateway CLI did not start in the fixture deadline")), 10000);
    const finish = (failure) => {
      clearTimeout(timeout); child.stdout.off("data", ready); child.off("error", failed); child.off("exit", earlyExit);
      if (failure) reject(failure); else resolve();
    };
    const ready = () => { if (stdout.includes("Gateway listening on loopback.")) finish(); };
    const failed = () => finish(new Error("Gateway CLI could not start"));
    const earlyExit = () => finish(new Error("Gateway CLI exited before listening"));
    child.stdout.on("data", ready); child.once("error", failed); child.once("exit", earlyExit);
  });
  const response = await request(http, { hostname: "127.0.0.1", port, path: "/mcp", headers: { Host: "gateway.example" } });
  assert.equal(response.status, 401);
  child.kill("SIGTERM");
  const [code, signal] = await exited; assert.equal(code, 0); assert.equal(signal, null);
  assert.equal(stdout.includes(f.owner) || stderr.includes(f.owner), false);
  assert.equal(stdout.includes(f.service) || stderr.includes(f.service), false);
  await assert.rejects(request(http, { hostname: "127.0.0.1", port, path: "/mcp" }), (error) => error.code === "ECONNREFUSED");
});

test("CLI rejects malformed startup configuration with a fixed message", () => {
  const result = spawnSync(process.execPath, [entrypoint], { env: { PATH: process.env.PATH ?? "/usr/bin:/bin", GATEWAY_CONFIG_FILE: "relative.json" }, encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Gateway startup failed; check its dedicated configuration and storage\./);
  assert.doesNotMatch(result.stderr, /ENOENT|relative\.json|at startGateway/);
});
