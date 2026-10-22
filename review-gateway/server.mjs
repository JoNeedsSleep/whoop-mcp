import http from "node:http";
import { TOOLS, validateInput, validateSummary } from "./gateway.mjs";

export const MAX_REQUEST_BYTES = 16 * 1024;
export const PROTOCOL_VERSIONS = Object.freeze(["2025-11-25", "2025-06-18", "2025-03-26"]);
const TOOL_FAILURE = Object.freeze({ isError: true, content: Object.freeze([
  Object.freeze({ type: "text", text: "HEALTH_DATA_UNAVAILABLE" }),
]) });
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const fields = (value, required, optional = []) => isObject(value) &&
  required.every((key) => Object.hasOwn(value, key)) &&
  Object.keys(value).every((key) => required.includes(key) || optional.includes(key));
const validId = (id) => (typeof id === "string" && id.length <= 128) || Number.isSafeInteger(id);
const validMeta = (params) => !Object.hasOwn(params, "_meta") || isObject(params._meta);
const emptyParams = (params) => params === undefined || (fields(params, [], ["_meta"]) && validMeta(params));

class BodyError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

function headers(res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
}
function json(res, status, value, close = false) {
  if (res.headersSent || res.destroyed) return;
  if (close) res.setHeader("Connection", "close");
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(value));
}
function error(res, status, code, message, id = null, close = false) {
  json(res, status, { jsonrpc: "2.0", id, error: { code, message } }, close);
}
function occurrences(req, name) {
  let count = 0;
  for (let i = 0; i < req.rawHeaders.length; i += 2) if (req.rawHeaders[i].toLowerCase() === name) count++;
  return count;
}
function acceptsMcp(value) {
  if (typeof value !== "string") return false;
  const accepted = new Set();
  for (const item of value.split(",")) {
    const [type, ...parameters] = item.trim().toLowerCase().split(";").map((part) => part.trim());
    const quality = parameters.find((part) => part.startsWith("q="));
    if (quality && (!/^q=(?:0(?:\.\d{1,3})?|1(?:\.0{1,3})?)$/.test(quality) || Number(quality.slice(2)) === 0)) continue;
    accepted.add(type);
  }
  return accepted.has("application/json") && accepted.has("text/event-stream");
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    const timer = setTimeout(() => finish(new BodyError(408, -32600, "Request timed out")), 5000);
    timer.unref();
    const finish = (failure, value) => {
      clearTimeout(timer);
      req.off("data", onData); req.off("end", onEnd); req.off("error", onError); req.off("aborted", onAborted);
      if (failure) { req.pause(); reject(failure); } else resolve(value);
    };
    const onData = (chunk) => {
      size += chunk.byteLength;
      if (size > MAX_REQUEST_BYTES) { finish(new BodyError(413, -32600, "Request too large")); return; }
      chunks.push(chunk);
    };
    const onEnd = () => {
      try {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, size));
        finish(null, JSON.parse(text));
      } catch { finish(new BodyError(400, -32700, "Parse error")); }
    };
    const onError = () => finish(new BodyError(400, -32600, "Invalid request"));
    const onAborted = () => finish(new BodyError(400, -32600, "Invalid request"));
    req.on("data", onData); req.once("end", onEnd); req.once("error", onError); req.once("aborted", onAborted);
  });
}

function safeToolResult(result, date) {
  try {
    if (!isObject(result) || result.isError === true) return TOOL_FAILURE;
    const data = validateSummary(result.structuredContent, date);
    // Recreate both representations, including when a trusted adapter is wrapped.
    // Never forward adapter/upstream text, URLs, metadata, headers or diagnostics.
    return { content: [{ type: "text", text: JSON.stringify(data) }], structuredContent: data };
  } catch { return TOOL_FAILURE; }
}

// Stateless Streamable HTTP: no session IDs, SSE, server-initiated requests or
// advertised sampling/resources/prompts/tasks. Public HTTPS is terminated by the
// separately reviewed proxy. Never infer the origin from forwarded headers.
export function createGatewayServer({ publicOrigin, auth, store, callTool, now = Date.now, allowInsecureLoopback = false }) {
  const origin = new URL(publicOrigin);
  const fixtureOrigin = allowInsecureLoopback === true && origin.protocol === "http:" &&
    ["127.0.0.1", "[::1]"].includes(origin.hostname);
  if (origin.origin !== publicOrigin || origin.username || origin.password ||
      (origin.protocol !== "https:" && !fixtureOrigin) ||
      typeof auth?.handleAuth !== "function" || typeof auth?.verifyBearer !== "function" ||
      typeof store?.acquireToolCall !== "function" || typeof store?.releaseToolCall !== "function" ||
      typeof callTool !== "function") throw new Error("INVALID_GATEWAY_CONFIGURATION");

  async function handle(req, res) {
    headers(res);
    // Apply the same absolute body deadline to OAuth forms and MCP JSON. Node's
    // inactivity timer alone can be kept alive by a client trickling bytes.
    const bodyDeadline = setTimeout(() => {
      if (!req.complete && !res.writableEnded) {
        req.pause(); error(res, 408, -32600, "Request timed out", null, true);
      }
    }, 5000);
    bodyDeadline.unref();
    const clearBodyDeadline = () => clearTimeout(bodyDeadline);
    req.once("end", clearBodyDeadline);
    res.once("finish", clearBodyDeadline);
    res.once("close", clearBodyDeadline);
    try {
      if (occurrences(req, "host") !== 1 || req.headers.host !== origin.host) {
        error(res, 403, -32600, "Forbidden", null, true); return;
      }
      if (occurrences(req, "origin") > 1 || (req.headers.origin !== undefined && req.headers.origin !== publicOrigin)) {
        error(res, 403, -32600, "Forbidden", null, true); return;
      }
      if (typeof req.url !== "string" || !req.url.startsWith("/") || req.url.startsWith("//") || req.url.includes("#")) {
        error(res, 400, -32600, "Invalid request", null, true); return;
      }
      const url = new URL(req.url, publicOrigin);
      if (url.origin !== publicOrigin || `${url.pathname}${url.search}` !== req.url) {
        error(res, 400, -32600, "Invalid request", null, true); return;
      }
      if (url.pathname !== "/mcp" && url.pathname !== "/data/snapshot") {
        if (await auth.handleAuth(req, res, url)) return;
        error(res, 404, -32600, "Not found", null, true); return;
      }
      if (url.search || occurrences(req, "authorization") !== 1) {
        res.setHeader("WWW-Authenticate", `Bearer resource_metadata="${publicOrigin}/.well-known/oauth-protected-resource"`);
        error(res, 401, -32001, "Unauthorized", null, true); return;
      }
      const bearer = typeof req.headers.authorization === "string" && /^Bearer ([A-Za-z0-9._~-]{20,512})$/i.exec(req.headers.authorization);
      const principal = bearer ? await auth.verifyBearer(bearer[1]) : null;
      if (!principal) {
        res.setHeader("WWW-Authenticate", `Bearer resource_metadata="${publicOrigin}/.well-known/oauth-protected-resource"`);
        error(res, 401, -32001, "Unauthorized", null, true); return;
      }
      if (url.pathname === "/data/snapshot") {
        if (req.method !== "GET") {
          res.setHeader("Allow", "GET"); error(res, 405, -32600, "Method not allowed", null, true); return;
        }
        if (req.headers["transfer-encoding"] !== undefined ||
            (req.headers["content-length"] !== undefined && req.headers["content-length"] !== "0")) {
          error(res, 400, -32600, "Invalid request", null, true); return;
        }
        // A fixed window is independent of prompts and tool calls on the laptop.
        // This endpoint uses the existing summary grant (/mcp audience), but
        // sends only data. The local reader never contacts the remote MCP API.
        const windowEnd = new Date(now()).toISOString().slice(0, 10);
        const end = Date.parse(windowEnd);
        const summaries = [];
        req.socket.setTimeout(40000);
        const deadline = setTimeout(() => error(res, 503, -32603, "Snapshot unavailable", null, true), 37000);
        deadline.unref();
        try {
          for (let offset = 6; offset >= 0; offset--) {
            if (res.destroyed || res.writableEnded) return;
            if (!await auth.verifyBearer(bearer[1])) {
              error(res, 401, -32001, "Unauthorized", null, true); return;
            }
            const lease = await store.acquireToolCall();
            if (!lease) { error(res, 429, -32000, "Request limit reached", null, true); return; }
            const date = new Date(end - offset * 86400000).toISOString().slice(0, 10);
            try {
              const result = safeToolResult(await callTool(TOOLS[0].name, { date }), date);
              if (result.isError) { error(res, 503, -32603, "Snapshot unavailable", null, true); return; }
              summaries.push(result.structuredContent);
            } finally { await store.releaseToolCall(lease); }
          }
          if (!await auth.verifyBearer(bearer[1])) {
            error(res, 401, -32001, "Unauthorized", null, true); return;
          }
          json(res, 200, { version: 1, windowEnd, summaries });
        } finally { clearTimeout(deadline); }
        return;
      }
      if (req.method !== "POST") {
        res.setHeader("Allow", "POST"); error(res, 405, -32600, "Method not allowed", null, true); return;
      }
      if (occurrences(req, "mcp-protocol-version") > 1 ||
          !PROTOCOL_VERSIONS.includes(req.headers["mcp-protocol-version"] ?? "2025-03-26") ||
          req.headers["mcp-session-id"] !== undefined) {
        error(res, 400, -32600, "Unsupported protocol", null, true); return;
      }
      if (!acceptsMcp(req.headers.accept)) {
        error(res, 406, -32600, "Unsupported response type", null, true); return;
      }
      if (occurrences(req, "content-type") !== 1 ||
          !/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?\s*$/i.test(req.headers["content-type"]) ||
          (req.headers["content-encoding"] !== undefined && req.headers["content-encoding"] !== "identity")) {
        error(res, 415, -32600, "Unsupported request type", null, true); return;
      }
      const length = req.headers["content-length"];
      if (length !== undefined && (!/^\d+$/.test(length) || Number(length) > MAX_REQUEST_BYTES)) {
        error(res, 413, -32600, "Request too large", null, true); return;
      }
      let message;
      try { message = await readJson(req); }
      catch (failure) {
        const known = failure instanceof BodyError;
        error(res, known ? failure.status : 400, known ? failure.code : -32600,
          known ? failure.message : "Invalid request", null, true); return;
      }
      if (!fields(message, ["jsonrpc", "method"], ["id", "params"]) || message.jsonrpc !== "2.0" ||
          typeof message.method !== "string" || message.method.length > 128 ||
          (Object.hasOwn(message, "id") && !validId(message.id))) {
        error(res, 400, -32600, "Invalid request"); return;
      }
      const hasId = Object.hasOwn(message, "id");
      const id = hasId ? message.id : null;
      const params = message.params;
      if (message.method === "notifications/initialized" && !hasId && emptyParams(params)) {
        res.writeHead(202); res.end(); return;
      }
      if (!hasId) { error(res, 400, -32600, "Unsupported notification"); return; }
      let result;
      if (message.method === "initialize") {
        if (!fields(params, ["protocolVersion", "capabilities", "clientInfo"], ["_meta"]) || !validMeta(params) ||
            typeof params.protocolVersion !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(params.protocolVersion) ||
            !isObject(params.capabilities) || !isObject(params.clientInfo) ||
            typeof params.clientInfo.name !== "string" || params.clientInfo.name.length > 128 ||
            typeof params.clientInfo.version !== "string" || params.clientInfo.version.length > 128) {
          error(res, 200, -32602, "Invalid params", id); return;
        }
        result = { protocolVersion: PROTOCOL_VERSIONS.includes(params.protocolVersion) ? params.protocolVersion : PROTOCOL_VERSIONS[0],
          capabilities: { tools: {} }, serverInfo: { name: "whoop-review-gateway", version: "1.0.0" } };
      } else if (message.method === "ping" || message.method === "tools/list") {
        if (!emptyParams(params)) { error(res, 200, -32602, "Invalid params", id); return; }
        result = message.method === "ping" ? {} : { tools: TOOLS };
      } else if (message.method === "tools/call") {
        let args;
        try {
          if (!fields(params, ["name", "arguments"], ["_meta"]) || !validMeta(params) || params.name !== TOOLS[0].name) throw new Error();
          args = validateInput(params.arguments);
        } catch { error(res, 200, -32602, "Invalid params", id); return; }
        // Quota and in-flight state belong to the gateway's shared durable store;
        // neither the client identity nor a new server process can reset them.
        const lease = await store.acquireToolCall();
        if (!lease) { error(res, 429, -32000, "Request limit reached", id); return; }
        try { result = safeToolResult(await callTool(TOOLS[0].name, args), args.date); }
        catch { result = TOOL_FAILURE; }
        finally { await store.releaseToolCall(lease); }
      } else { error(res, 200, -32601, "Method not found", id); return; }
      json(res, 200, { jsonrpc: "2.0", id, result });
    } catch { error(res, 503, -32603, "Request unavailable", null, true); }
  }
  const server = http.createServer({ maxHeaderSize: 8192, requestTimeout: 10000, headersTimeout: 10000, keepAliveTimeout: 5000 },
    (req, res) => { void handle(req, res); });
  server.maxConnections = 64;
  server.maxRequestsPerSocket = 100;
  server.setTimeout(15000, (socket) => socket.destroy());
  server.on("checkContinue", (req, res) => { headers(res); error(res, 417, -32600, "Expectation not supported", null, true); });
  server.on("checkExpectation", (req, res) => { headers(res); error(res, 417, -32600, "Expectation not supported", null, true); });
  server.on("clientError", (_error, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    else socket.destroy();
  });
  return server;
}
