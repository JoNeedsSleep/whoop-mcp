import path from "node:path";
import { pathToFileURL } from "node:url";
import { TOOLS, validateInput } from "./policy.mjs";
import { readCache } from "./cache.mjs";

export const MAX_FRAME_BYTES = 16384;
export const PROTOCOL_VERSIONS = Object.freeze(["2025-11-25", "2025-06-18", "2025-03-26"]);
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const fields = (value, required, optional = []) => object(value) &&
  required.every((key) => Object.hasOwn(value, key)) &&
  Object.keys(value).every((key) => required.includes(key) || optional.includes(key));
const validMeta = (value) => !Object.hasOwn(value, "_meta") ||
  (object(value._meta) && Object.getPrototypeOf(value._meta) === Object.prototype);
const empty = (value) => value === undefined || (fields(value, [], ["_meta"]) && validMeta(value));
const validId = (value) => (typeof value === "string" && value.length <= 128) || Number.isSafeInteger(value);
const error = (code, message, id = null) => ({ jsonrpc: "2.0", id, error: { code, message } });
const failure = () => ({ isError: true, content: [{ type: "text", text: "LOCAL_HEALTH_DATA_UNAVAILABLE" }] });

function config(cacheFile, clientId) {
  if (typeof cacheFile !== "string" || !path.isAbsolute(cacheFile) || path.normalize(cacheFile) !== cacheFile ||
      cacheFile.includes("\0") || cacheFile.endsWith(path.sep) || !["codex", "claude-code"].includes(clientId)) {
    throw new Error("INVALID_LOCAL_READER_CONFIG");
  }
  return { cacheFile, clientId };
}

export function createReader({ cacheFile, clientId, now = Date.now }) {
  const fixed = config(cacheFile, clientId);
  let initialized = false;
  let ready = false;
  return (message) => {
    if (!fields(message, ["jsonrpc", "method"], ["id", "params"]) || message.jsonrpc !== "2.0" ||
        typeof message.method !== "string" || message.method.length > 128 ||
        (Object.hasOwn(message, "id") && !validId(message.id))) return error(-32600, "Invalid request");
    const hasId = Object.hasOwn(message, "id");
    const id = hasId ? message.id : null;
    const params = message.params;
    if (message.method === "notifications/initialized" && !hasId && initialized && empty(params)) {
      ready = true; return null;
    }
    if (!hasId) return error(-32600, "Unsupported notification");
    let result;
    if (message.method === "initialize") {
      if (initialized || !fields(params, ["protocolVersion", "capabilities", "clientInfo"], ["_meta"]) || !validMeta(params) ||
          typeof params.protocolVersion !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(params.protocolVersion) ||
          !object(params.capabilities) || !fields(params.clientInfo, ["name", "version"], ["title"]) ||
          typeof params.clientInfo.name !== "string" || params.clientInfo.name.length > 128 ||
          typeof params.clientInfo.version !== "string" || params.clientInfo.version.length > 128 ||
          (params.clientInfo.title !== undefined && (typeof params.clientInfo.title !== "string" || params.clientInfo.title.length > 128))) {
        return error(-32602, "Invalid params", id);
      }
      initialized = true;
      result = { protocolVersion: PROTOCOL_VERSIONS.includes(params.protocolVersion) ? params.protocolVersion : PROTOCOL_VERSIONS[0],
        capabilities: { tools: {} }, serverInfo: { name: "whoop-restricted-local", version: "1.0.0" } };
    } else if (message.method === "ping") {
      if (!empty(params)) return error(-32602, "Invalid params", id);
      result = {};
    } else if (message.method === "tools/list") {
      if (!ready) return error(-32000, "Reader not initialized", id);
      if (!empty(params)) return error(-32602, "Invalid params", id);
      result = { tools: TOOLS };
    } else if (message.method === "tools/call") {
      if (!ready) return error(-32000, "Reader not initialized", id);
      let args;
      try {
        if (!fields(params, ["name", "arguments"], ["_meta"]) || !validMeta(params) || params.name !== TOOLS[0].name) throw new Error();
        args = validateInput(params.arguments);
      } catch { return error(-32602, "Invalid params", id); }
      try {
        const cache = readCache(fixed.cacheFile, fixed.clientId, now());
        const summary = cache.snapshot.summaries.find((value) => value.date === args.date);
        result = summary ? { content: [{ type: "text", text: JSON.stringify(summary) }], structuredContent: summary } : failure();
      } catch { result = failure(); }
    } else return error(-32601, "Method not found", id);
    return { jsonrpc: "2.0", id, result };
  };
}

export async function runReader({ cacheFile, clientId, input = process.stdin, output = process.stdout, now = Date.now }) {
  const handle = createReader({ cacheFile, clientId, now });
  let pending = Buffer.alloc(0);
  let outputFailed = false;
  const onOutputError = () => { outputFailed = true; };
  output.on("error", onOutputError);
  async function send(value) {
    if (value === null) return;
    if (outputFailed) throw new Error("LOCAL_READER_UNAVAILABLE");
    await new Promise((resolve, reject) => output.write(`${JSON.stringify(value)}\n`, (failure) => failure ? reject(failure) : resolve()));
  }
  try {
    for await (const raw of input) {
      const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
      let start = 0;
      while (start < chunk.length) {
        const newline = chunk.indexOf(10, start);
        const end = newline === -1 ? chunk.length : newline;
        if (pending.length + end - start > MAX_FRAME_BYTES) {
          await send(error(-32600, "Request too large")); return false;
        }
        pending = Buffer.concat([pending, chunk.subarray(start, end)]);
        if (newline === -1) break;
        let response;
        try {
          const message = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(pending));
          response = handle(message);
        } catch { response = error(-32700, "Parse error"); }
        pending = Buffer.alloc(0);
        await send(response);
        start = newline + 1;
      }
    }
    if (pending.length) { await send(error(-32700, "Parse error")); return false; }
    return true;
  } finally { output.off("error", onOutputError); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 2) throw new Error("INVALID_LOCAL_READER_CONFIG");
    const clean = config(process.env.WHOOP_LOCAL_CACHE_FILE, process.env.WHOOP_LOCAL_CLIENT_ID);
    if (!await runReader(clean)) process.exitCode = 1;
  } catch {
    process.stderr.write("Local reader unavailable.\n"); process.exitCode = 1;
  }
}
