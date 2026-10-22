import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export const ACCESS_TTL_MS = 7 * 86400000;
export const OWNER_TTL_MS = ACCESS_TTL_MS;
const FLOW_TTL_MS = 10 * 60000;
const CODE_TTL_MS = 5 * 60000;
const OWNER_COOKIE = "__Host-gw_owner";
const random = () => randomBytes(32).toString("base64url");
export const sha256 = (value) => createHash("sha256").update(value).digest("hex");
export const pkceChallenge = (value) => createHash("sha256").update(value).digest("base64url");
const nonce = (value) => typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value) && Buffer.from(value, "base64url").toString("base64url") === value;
const equal = (a, b) => typeof a === "string" && typeof b === "string" && Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const escape = (value) => String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const flowCookie = (id) => `__Host-gw_flow_${id}`;
function cookie(req, name) {
  const values = String(req.headers.cookie ?? "").split(";").map((s) => s.trim()).filter((s) => s.startsWith(`${name}=`));
  if (values.length !== 1) return null;
  const value = values[0].slice(name.length + 1);
  return nonce(value) ? value : null;
}
function setCookie(res, name, value, seconds) {
  const previous = res.getHeader("Set-Cookie") ?? [];
  res.setHeader("Set-Cookie", [...(Array.isArray(previous) ? previous : [previous]),
    `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${seconds}`]);
}
function callbackCspSource(raw) {
  const source = new URL(raw).origin;
  // Serialize only a canonical authority, never an OAuth callback's raw path.
  // Reject CSP delimiters even if a URL parser accepts them in an HTTPS host.
  if (!/^https?:\/\/(?:[a-z0-9.-]+|\[[a-f0-9:]+\])(?::[0-9]+)?$/.test(source)) throw new Error("Invalid callback origin");
  return source;
}
function headers(res, formCallback) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  const formSources = formCallback ? `'self' ${callbackCspSource(formCallback)}` : "'self'";
  res.setHeader("Content-Security-Policy", `default-src 'none'; form-action ${formSources}; frame-ancestors 'none'; base-uri 'none'`);
}
function json(res, status, value) { headers(res); res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(value)); }
function html(res, title, body, status = 200, formCallback) {
  headers(res, formCallback);
  // no-referrer makes browser navigation POSTs send Origin: null. Preserve the
  // origin for our same-origin forms, never paths/query strings or HTTPS downgrades.
  res.setHeader("Referrer-Policy", "strict-origin");
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(`<!doctype html><html lang="en"><meta charset="utf-8"><title>${escape(title)}</title><h1>${escape(title)}</h1>${body}</html>`);
}
function params(input, allowed) {
  const result = {};
  for (const [key, value] of input) {
    if (!allowed.includes(key) || Object.hasOwn(result, key)) throw new Error("Invalid request");
    result[key] = value;
  }
  return result;
}
async function form(req, allowed) {
  if (String(req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase() !== "application/x-www-form-urlencoded" ||
      (req.headers["content-encoding"] && req.headers["content-encoding"] !== "identity")) throw new Error("Invalid request");
  const declared = req.headers["content-length"];
  if (declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > 8192)) throw new Error("Invalid request");
  let size = 0; const chunks = [];
  for await (const chunk of req) {
    size += chunk.length; if (size > 8192) throw new Error("Invalid request"); chunks.push(chunk);
  }
  return params(new URLSearchParams(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks))), allowed);
}
export function validateCallback(raw) {
  try {
    const url = new URL(raw);
    if (raw.length > 2048 || url.href !== raw || url.username || url.password || url.hash || url.search || raw.includes("*")) return false;
    callbackCspSource(raw);
    if (url.protocol === "https:") return true;
    // Native clients must choose an explicitly reviewed fixed port and exact path.
    return url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname) &&
      /^\d+$/.test(url.port) && Number(url.port) >= 1024 && Number(url.port) <= 65535;
  } catch { return false; }
}

export function createGatewayAuth({ store, publicOrigin, resource, ownerSecretHash, clients, now = Date.now, allowInsecureLoopback = false }) {
  const origin = new URL(publicOrigin);
  if (origin.origin !== publicOrigin || origin.username || origin.password ||
      (origin.protocol !== "https:" && !(allowInsecureLoopback && origin.protocol === "http:" && ["localhost", "127.0.0.1"].includes(origin.hostname))) ||
      resource !== `${publicOrigin}/mcp` || !/^[a-f0-9]{64}$/.test(ownerSecretHash) || !Array.isArray(clients) || clients.length !== 2) {
    throw new Error("Invalid gateway authentication configuration");
  }
  const configured = new Map();
  for (const client of clients) {
    if (!["codex", "claude-code"].includes(client.clientId) || configured.has(client.clientId) ||
        typeof client.name !== "string" || client.name.length < 1 || client.name.length > 80 ||
        !Array.isArray(client.redirectUris) || client.redirectUris.length < 1 || client.redirectUris.length > 4 || !client.redirectUris.every(validateCallback)) {
      throw new Error("Invalid gateway client configuration");
    }
    configured.set(client.clientId, { ...client, redirectUris: [...client.redirectUris] });
  }
  const sessionFor = (req) => {
    const raw = cookie(req, OWNER_COOKIE);
    const record = raw && store.get("session", sha256(raw));
    // Rotating the configured owner secret invalidates existing owner sessions.
    return record && record.ownerVersion === ownerSecretHash ? { ...record, hash: sha256(raw), csrf: sha256(`${raw}:owner`) } : null;
  };
  const verifyBearer = (raw) => {
    if (typeof raw !== "string" || !/^gw_[A-Za-z0-9_-]{43}$/.test(raw)) return null;
    const record = store.get("token", sha256(raw));
    return record && configured.has(record.clientId) && record.audience === resource
      ? { clientId: record.clientId, audience: resource, expiresAt: record.expiresAt } : null;
  };
  const revokeClient = (clientId) => store.transaction(() => {
    for (const kind of ["token", "code", "flow"]) store.deleteWhere(kind, (r) => r.clientId === clientId);
  });
  const revokeAll = () => store.transaction(() => {
    for (const kind of ["token", "code", "flow", "session"]) store.deleteWhere(kind, () => true);
  });
  function flowFor(req, id, csrf) {
    if (!nonce(id) || !nonce(csrf)) return null;
    const browserNonce = cookie(req, flowCookie(id));
    const flow = store.get("flow", sha256(id));
    return browserNonce && equal(csrf, browserNonce) && flow && equal(flow.binding, sha256(browserNonce)) ? flow : null;
  }
  function renderLogin(res, id, csrf) {
    html(res, "Sign in to the WHOOP gateway", `<p>Use your dedicated gateway owner secret. Never enter an OpenAI, Anthropic or WHOOP credential here.</p>
      <form method="post" action="/login"><input type="hidden" name="flow" value="${id}"><input type="hidden" name="csrf" value="${csrf}">
      <label>Gateway owner secret <input type="password" name="secret" autocomplete="current-password" required></label><button>Sign in</button></form>`);
  }
  function renderConsent(res, id, csrf, flow) {
    const client = configured.get(flow.clientId);
    if (!client?.redirectUris.includes(flow.redirectUri)) throw new Error("Invalid callback");
    // Browsers can enforce form-action through the POST's redirect chain.
    // Only this flow's registered callback origin may receive the redirect;
    // exact callback path/port validation remains enforced by the server.
    html(res, "Approve WHOOP gateway access", `<p>Configured client: ${escape(client.name)} (${escape(client.clientId)}).</p>
      <p>Native client names identify a configuration, not verified application software.</p>
      <p>Exact callback: ${escape(flow.redirectUri)}</p><p>Resource: ${escape(resource)}</p>
      <p>Read one bounded WHOOP health summary per request. Access lasts seven days and can be revoked independently.</p>
      <form method="post" action="/consent"><input type="hidden" name="flow" value="${id}"><input type="hidden" name="csrf" value="${csrf}">
      <button name="decision" value="allow">Allow</button><button name="decision" value="deny">Deny</button></form>`, 200, flow.redirectUri);
  }
  function begin(req, res, request) {
    const id = random(); const csrf = random(); const session = sessionFor(req);
    const flow = { ...request, binding: sha256(csrf), sessionHash: session?.hash ?? null, stage: session ? "consent" : "login" };
    if (!store.put("flow", sha256(id), flow, now() + FLOW_TTL_MS)) return json(res, 503, { error: "temporarily_unavailable" });
    setCookie(res, flowCookie(id), csrf, FLOW_TTL_MS / 1000);
    if (!session || request.kind === "owner") renderLogin(res, id, csrf);
    else renderConsent(res, id, csrf, flow);
  }
  function redirect(res, flow, values) {
    const destination = new URL(flow.redirectUri);
    for (const [key, value] of Object.entries({ ...values, state: flow.state, iss: publicOrigin })) destination.searchParams.set(key, value);
    headers(res); res.writeHead(302, { Location: destination.href }); res.end();
  }
  const routes = new Set(["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp",
    "/.well-known/oauth-authorization-server", "/oauth/authorize", "/oauth/token", "/oauth/revoke", "/login", "/consent", "/owner", "/owner/revoke", "/owner/logout"]);
  async function handleAuth(req, res, url) {
    if (!routes.has(url.pathname)) return false;
    headers(res);
    try {
      const route = url.pathname; const method = req.method;
      if (route.startsWith("/.well-known/") && method === "GET") {
        if (route.includes("oauth-protected-resource")) json(res, 200, { resource, authorization_servers: [publicOrigin], scopes_supported: ["mcp"], bearer_methods_supported: ["header"] });
        else json(res, 200, { issuer: publicOrigin, authorization_endpoint: `${publicOrigin}/oauth/authorize`, token_endpoint: `${publicOrigin}/oauth/token`,
          revocation_endpoint: `${publicOrigin}/oauth/revoke`, response_types_supported: ["code"], grant_types_supported: ["authorization_code"],
          token_endpoint_auth_methods_supported: ["none"], code_challenge_methods_supported: ["S256"], scopes_supported: ["mcp"],
          authorization_response_iss_parameter_supported: true });
        return true;
      }
      if (route === "/oauth/authorize" && method === "GET") {
        if (!store.takeRateLimit("authorization", 120, 3600000)) { json(res, 429, { error: "temporarily_unavailable" }); return true; }
        const p = params(url.searchParams, ["client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "resource", "state", "scope"]);
        const client = configured.get(p.client_id);
        if (!client || !client.redirectUris.includes(p.redirect_uri) || p.response_type !== "code" || p.resource !== resource ||
            p.code_challenge_method !== "S256" || !nonce(p.code_challenge) || !p.state || p.state.length > 1024 || /[\x00-\x1f\x7f]/.test(p.state) ||
            (p.scope !== undefined && p.scope !== "mcp")) throw new Error("Invalid request");
        begin(req, res, { kind: "oauth", clientId: p.client_id, redirectUri: p.redirect_uri, challenge: p.code_challenge, state: p.state, audience: resource });
        return true;
      }
      if ((route === "/owner" || route === "/login") && method === "GET") {
        const session = sessionFor(req);
        if (!session) {
          if (!store.takeRateLimit("authorization", 120, 3600000)) json(res, 429, { error: "temporarily_unavailable" });
          else begin(req, res, { kind: "owner" });
        } else {
          const tokens = store.list("token");
          const forms = [...configured.values()].map((c) => {
            const active = tokens.filter((token) => token.clientId === c.clientId && token.audience === resource);
            const deadlines = active.map((token) => token.expiresAt);
            const status = active.length ? `${active.length} active authorization(s); latest expiry ${new Date(Math.max(...deadlines)).toISOString()}.` : "No active authorizations.";
            return `<p>${escape(c.name)}: ${escape(status)}</p><form method="post" action="/owner/revoke"><input type="hidden" name="csrf" value="${session.csrf}">
            <input type="hidden" name="client_id" value="${c.clientId}"><button>Revoke ${escape(c.name)}</button></form>`;
          }).join("");
          html(res, "WHOOP gateway authorizations", `<p>Owner sign-in and client access have fixed seven-day deadlines. Revocation stops subsequent checks, not requests already running.</p>${forms}
            <form method="post" action="/owner/revoke"><input type="hidden" name="csrf" value="${session.csrf}"><input type="hidden" name="client_id" value="all"><button>Revoke all and sign out</button></form>
            <form method="post" action="/owner/logout"><input type="hidden" name="csrf" value="${session.csrf}"><button>Sign out</button></form>`);
        }
        return true;
      }
      if (route === "/login" && method === "POST") {
        if (req.headers.origin !== publicOrigin) throw new Error("Invalid request");
        if (!store.takeRateLimit("owner-login", 20, 3600000)) { json(res, 429, { error: "temporarily_unavailable" }); return true; }
        const p = await form(req, ["flow", "csrf", "secret"]); const flow = flowFor(req, p.flow, p.csrf);
        if (!flow || flow.stage !== "login" || !nonce(p.secret) || !equal(sha256(p.secret), ownerSecretHash)) { json(res, 403, { error: "access_denied" }); return true; }
        const raw = random(); const sessionHash = sha256(raw);
        const accepted = store.transaction(() => {
          if (store.get("flow", sha256(p.flow))?.stage !== "login") return false;
          const old = cookie(req, OWNER_COOKIE); if (old) store.delete("session", sha256(old));
          if (!store.put("session", sessionHash, { ownerVersion: ownerSecretHash }, now() + OWNER_TTL_MS, 20)) throw new Error("Unavailable");
          if (!store.replace("flow", sha256(p.flow), { ...flow, sessionHash, stage: "consent" })) throw new Error("Unavailable");
          return true;
        });
        if (!accepted) throw new Error("Invalid request");
        setCookie(res, OWNER_COOKIE, raw, OWNER_TTL_MS / 1000);
        if (flow.kind === "owner") {
          store.delete("flow", sha256(p.flow)); setCookie(res, flowCookie(p.flow), "", 0);
          res.writeHead(303, { Location: `${publicOrigin}/owner` }); res.end();
        } else renderConsent(res, p.flow, p.csrf, flow);
        return true;
      }
      if (route === "/consent" && method === "POST") {
        if (req.headers.origin !== publicOrigin) throw new Error("Invalid request");
        const p = await form(req, ["flow", "csrf", "decision"]); const flow = flowFor(req, p.flow, p.csrf); const session = sessionFor(req);
        if (!flow || flow.kind !== "oauth" || flow.stage !== "consent" || !session || session.hash !== flow.sessionHash || !["allow", "deny"].includes(p.decision) ||
            !configured.get(flow.clientId)?.redirectUris.includes(flow.redirectUri)) throw new Error("Invalid request");
        const code = random();
        const accepted = store.transaction(() => {
          if (!store.delete("flow", sha256(p.flow))) return false;
          if (p.decision === "allow" && !store.put("code", sha256(code), { clientId: flow.clientId, redirectUri: flow.redirectUri,
            audience: resource, challenge: flow.challenge }, now() + CODE_TTL_MS)) throw new Error("Unavailable");
          return true;
        });
        if (!accepted) throw new Error("Invalid request");
        setCookie(res, flowCookie(p.flow), "", 0);
        redirect(res, flow, p.decision === "allow" ? { code } : { error: "access_denied" }); return true;
      }
      if (route === "/oauth/token" && method === "POST") {
        if (!store.takeRateLimit("token-exchange", 120, 3600000)) { json(res, 429, { error: "temporarily_unavailable" }); return true; }
        const p = await form(req, ["grant_type", "client_id", "code", "code_verifier", "redirect_uri", "resource"]);
        if (p.grant_type !== "authorization_code") { json(res, 400, { error: "unsupported_grant_type" }); return true; }
        const client = configured.get(p.client_id);
        if (!client || !nonce(p.code) || !/^[A-Za-z0-9._~-]{43,128}$/.test(p.code_verifier ?? "") ||
            p.resource !== resource || !client.redirectUris.includes(p.redirect_uri)) { json(res, 400, { error: "invalid_grant" }); return true; }
        const token = `gw_${random()}`; const expiresAt = now() + ACCESS_TTL_MS;
        const redeemed = store.transaction(() => {
          const code = store.get("code", sha256(p.code));
          if (!code || code.clientId !== p.client_id || code.redirectUri !== p.redirect_uri || code.audience !== resource || !equal(code.challenge, pkceChallenge(p.code_verifier))) return false;
          store.delete("code", sha256(p.code));
          if (!store.put("token", sha256(token), { clientId: p.client_id, audience: resource }, expiresAt, 100)) throw new Error("Unavailable");
          return true;
        });
        if (!redeemed) json(res, 400, { error: "invalid_grant" });
        else json(res, 200, { access_token: token, token_type: "Bearer", expires_in: ACCESS_TTL_MS / 1000, scope: "mcp" });
        return true;
      }
      if (route === "/oauth/revoke" && method === "POST") {
        if (!store.takeRateLimit("token-revoke", 120, 3600000)) { json(res, 429, { error: "temporarily_unavailable" }); return true; }
        const p = await form(req, ["token", "client_id", "token_type_hint"]);
        if (typeof p.token === "string" && p.token.length <= 128 && configured.has(p.client_id)) {
          const record = store.get("token", sha256(p.token)); if (record?.clientId === p.client_id) store.delete("token", sha256(p.token));
        }
        json(res, 200, {}); return true;
      }
      if (["/owner/revoke", "/owner/logout"].includes(route) && method === "POST") {
        if (req.headers.origin !== publicOrigin) throw new Error("Invalid request");
        const p = await form(req, route === "/owner/revoke" ? ["csrf", "client_id"] : ["csrf"]); const session = sessionFor(req);
        if (!session || !equal(p.csrf, session.csrf)) throw new Error("Invalid request");
        if (route === "/owner/logout") { store.delete("session", session.hash); setCookie(res, OWNER_COOKIE, "", 0); }
        else if (p.client_id === "all") { revokeAll(); setCookie(res, OWNER_COOKIE, "", 0); }
        else if (configured.has(p.client_id)) revokeClient(p.client_id);
        else throw new Error("Invalid request");
        res.writeHead(303, { Location: `${publicOrigin}/owner` }); res.end(); return true;
      }
      json(res, 405, { error: "invalid_request" }); return true;
    } catch {
      if (!res.headersSent) json(res, 400, { error: "invalid_request" }); else res.end();
      return true;
    }
  }
  return { handleAuth, handle: (req, res, url = new URL(req.url, publicOrigin)) => handleAuth(req, res, url),
    verifyBearer, verifyOwnerSession: sessionFor, revokeClient, revokeAll,
    reserveToolCall: (principal) => principal?.audience === resource && configured.has(principal.clientId) ? store.acquireToolCall() : null,
    releaseToolCall: (reservation) => store.releaseToolCall(reservation) };
}
