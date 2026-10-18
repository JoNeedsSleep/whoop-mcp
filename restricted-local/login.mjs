import http from "node:http";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { pathToFileURL } from "node:url";
import { AUTH_TTL_MS, CALLBACKS, boundedJson, configuredFetch, exact, parseLocalConfig, parseToken, privateParent, readLocalConfig, writePrivateJson } from "./config.mjs";

const random = () => randomBytes(32).toString("base64url");
const matches = (a, b) => typeof a === "string" && typeof b === "string" && Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));
export function createLoginFlow(rawConfig) {
  const config = parseLocalConfig(rawConfig);
  const state = random(); const verifier = random(); const redirectUri = CALLBACKS[config.clientId];
  const url = new URL(`${config.origin}/oauth/authorize`);
  url.search = new URLSearchParams({ client_id: config.clientId, redirect_uri: redirectUri, response_type: "code", state,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", resource: `${config.origin}/mcp`, scope: "mcp" }).toString();
  return { state, verifier, redirectUri, authorizationUrl: url.href };
}
export function validateLoginCallback(requestUrl, host, config, flow) {
  const expected = new URL(flow.redirectUri);
  if (host !== expected.host || typeof requestUrl !== "string" || !requestUrl.startsWith("/callback?") || requestUrl.includes("#")) throw new Error("LOGIN_CALLBACK_INVALID");
  const url = new URL(requestUrl, flow.redirectUri);
  if (url.origin !== expected.origin || url.pathname !== expected.pathname || `${url.pathname}${url.search}` !== requestUrl) throw new Error("LOGIN_CALLBACK_INVALID");
  const result = {};
  for (const [key, value] of url.searchParams) {
    if (!["code", "state", "iss", "error"].includes(key) || Object.hasOwn(result, key)) throw new Error("LOGIN_CALLBACK_INVALID"); result[key] = value;
  }
  if (!matches(result.state, flow.state) || result.iss !== config.origin ||
      (Object.hasOwn(result, "code") === Object.hasOwn(result, "error"))) throw new Error("LOGIN_CALLBACK_INVALID");
  if (result.error !== undefined) { if (result.error !== "access_denied") throw new Error("LOGIN_CALLBACK_INVALID"); return { denied: true }; }
  if (!/^[A-Za-z0-9_-]{43}$/.test(result.code ?? "")) throw new Error("LOGIN_CALLBACK_INVALID");
  return { code: result.code };
}
export async function startCallback(config, flow, { timeoutMs = 5 * 60000, containerCallback = false } = {}) {
  if (typeof containerCallback !== "boolean") throw new Error("LOGIN_CALLBACK_UNAVAILABLE");
  let resolveCode; let rejectCode; let settled = false; let timer;
  const code = new Promise((resolve, reject) => { resolveCode = resolve; rejectCode = reject; });
  // An exception in the URL presentation hook must not leave an unhandled
  // callback rejection while runLogin closes its listener.
  void code.catch(() => {});
  const finish = (error, value) => {
    if (settled) return; settled = true; clearTimeout(timer); server.close(); server.closeIdleConnections();
    if (error) rejectCode(new Error("LOGIN_NOT_COMPLETED")); else resolveCode(value);
  };
  const server = http.createServer({ maxHeaderSize: 8192, requestTimeout: 10000, headersTimeout: 10000, keepAliveTimeout: 1000 }, (req, res) => {
    const headers = { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
      "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'", Connection: "close" };
    try {
      let hostCount = 0; for (let i = 0; i < req.rawHeaders.length; i += 2) if (req.rawHeaders[i].toLowerCase() === "host") hostCount++;
      if (settled || req.method !== "GET" || hostCount !== 1 || req.headers["transfer-encoding"] ||
          (req.headers["content-length"] && req.headers["content-length"] !== "0")) throw new Error();
      const result = validateLoginCallback(req.url, req.headers.host, config, flow);
      res.once("finish", () => finish(result.denied ? new Error() : null, result.code));
      res.writeHead(200, headers); res.end(result.denied ? "Authorization declined. You may close this window." : "Authorization received. Return to the local sign-in tool.");
    } catch { res.writeHead(400, headers); res.end("Authorization request rejected."); }
  });
  server.maxConnections = 8; server.maxRequestsPerSocket = 1;
  server.setTimeout(10000, (socket) => socket.destroy());
  server.on("clientError", (_error, socket) => socket.destroy());
  await new Promise((resolve, reject) => {
    server.once("error", () => { clearTimeout(timer); reject(new Error("LOGIN_CALLBACK_UNAVAILABLE")); });
    // Container mode is explicit and requires the launcher to publish this port
    // ONLY on host 127.0.0.1, with no host network. Standalone stays loopback.
    // Claude's localhost URL remains exact; no callback aliases are accepted.
    server.listen(Number(new URL(flow.redirectUri).port), containerCallback ? "0.0.0.0" : "127.0.0.1", resolve);
  });
  timer = setTimeout(() => { finish(new Error()); server.closeAllConnections(); }, timeoutMs);
  return { code, address: server.address().address, close: () => { finish(new Error()); server.closeAllConnections(); } };
}
export async function exchangeLoginCode(rawConfig, flow, code, { fetchImpl, now = Date.now } = {}) {
  const config = parseLocalConfig(rawConfig);
  fetchImpl ??= configuredFetch(config);
  if (!/^[A-Za-z0-9_-]{43}$/.test(code) || flow.redirectUri !== CALLBACKS[config.clientId] || !/^[A-Za-z0-9_-]{43}$/.test(flow.verifier)) throw new Error("LOGIN_NOT_COMPLETED");
  const startedAt = now();
  const token = await boundedJson(`${config.origin}/oauth/token`, { method: "POST", headers: { Accept: "application/json", "Accept-Encoding": "identity", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", client_id: config.clientId, code, code_verifier: flow.verifier,
      redirect_uri: flow.redirectUri, resource: `${config.origin}/mcp` }).toString() }, { fetchImpl, maxBytes: 4096 });
  if (!exact(token, ["access_token", "token_type", "expires_in", "scope"]) || token.token_type !== "Bearer" || token.scope !== "mcp" ||
      !Number.isSafeInteger(token.expires_in) || token.expires_in <= 0 || token.expires_in > AUTH_TTL_MS / 1000 || now() < startedAt) throw new Error("LOGIN_NOT_COMPLETED");
  // Anchor to the request start, never a remote timestamp or the end of an
  // arbitrarily delayed response; no refresh token is requested or accepted.
  const record = parseToken({ clientId: config.clientId, origin: config.origin, accessToken: token.access_token, expiresAt: startedAt + token.expires_in * 1000 }, config, now());
  writePrivateJson(config.tokenFile, record, 4096);
  return { expiresAt: record.expiresAt };
}
export async function runLogin(rawConfig, { fetchImpl, now = Date.now, containerCallback = false, onAuthorizationUrl = (url) => console.log(`Open this trusted gateway sign-in URL in your browser:\n${url}`) } = {}) {
  const config = parseLocalConfig(rawConfig); privateParent(config.tokenFile);
  const flow = createLoginFlow(config); const callback = await startCallback(config, flow, { containerCallback });
  try {
    await onAuthorizationUrl(flow.authorizationUrl);
    const code = await callback.code;
    return await exchangeLoginCode(config, flow, code, { fetchImpl, now });
  } finally { callback.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 3 && !(process.argv.length === 4 && process.argv[3] === "--container-callback")) throw new Error();
    await runLogin(readLocalConfig(process.argv[2]), { containerCallback: process.argv[3] === "--container-callback" });
    console.log("Gateway authorization saved privately for up to seven days.");
  } catch { console.error("Gateway sign-in did not complete. Restart it manually when ready."); process.exitCode = 1; }
}
