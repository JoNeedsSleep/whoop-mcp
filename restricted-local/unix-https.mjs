// HTTPS over a fixed private Unix byte stream. No DNS, proxy environment,
// destination negotiation or network fallback exists in this client.
import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import tls from "node:tls";
import https from "node:https";

const fail = () => new Error("PRIVATE_HTTPS_UNAVAILABLE");
const PATHS = new Set(["/data/snapshot", "/oauth/token", "/internal/health-summary"]);
const MAX_BODY = 32768;
function privateSocket(filename) {
  if (typeof filename !== "string" || !path.isAbsolute(filename) || path.normalize(filename) !== filename || filename.includes("\0")) throw fail();
  const parent = fs.lstatSync(path.dirname(filename)); const socket = fs.lstatSync(filename);
  if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== process.getuid() || (parent.mode & 0o077) ||
      !socket.isSocket() || socket.isSymbolicLink() || socket.uid !== process.getuid() || (socket.mode & 0o077)) throw fail();
}
export function createUnixFetch({ origin, socketPath, allowedPaths = ["/data/snapshot", "/oauth/token"], ca }) {
  const canonical = new URL(origin);
  if (canonical.protocol !== "https:" || canonical.origin !== origin || canonical.port || canonical.username || canonical.password ||
      !Array.isArray(allowedPaths) || !allowedPaths.length || new Set(allowedPaths).size !== allowedPaths.length ||
      allowedPaths.some((value) => !PATHS.has(value))) throw fail();
  const approved = new Set(allowedPaths);
  // `ca` exists for synthetic certificate tests. No production config/env path
  // exposes it; certificate and hostname checks remain mandatory in either case.
  return async (rawUrl, options = {}) => {
    let agent; let request; let unixSocket; let secureSocket;
    try {
      if (!options || typeof options !== "object" || Array.isArray(options) ||
          Object.keys(options).some((key) => !["method", "headers", "body", "redirect", "signal"].includes(key))) throw fail();
      const url = new URL(rawUrl);
      const method = options.method ?? "GET";
      if (url.origin !== origin || url.hash || url.username || url.password || !approved.has(url.pathname) ||
          options.redirect !== "error" || (options.signal !== undefined && !(options.signal instanceof AbortSignal))) throw fail();
      if (url.pathname === "/internal/health-summary") {
        const date = url.searchParams.get("date");
        if (method !== "GET" || [...url.searchParams.keys()].length !== 1 || !/^20\d{2}-\d{2}-\d{2}$/.test(date ?? "") ||
            !Number.isFinite(Date.parse(date)) || new Date(date).toISOString().slice(0, 10) !== date) throw fail();
      } else if (url.search || method !== (url.pathname === "/oauth/token" ? "POST" : "GET")) throw fail();
      if (method === "GET" ? options.body !== undefined : typeof options.body !== "string" || Buffer.byteLength(options.body) > 8192) throw fail();
      const headers = new Headers(options.headers);
      if ([...headers.keys()].some((key) => !["accept", "accept-encoding", "authorization", "content-type"].includes(key)) ||
          (headers.has("accept-encoding") && headers.get("accept-encoding") !== "identity") || options.signal?.aborted) throw fail();
      privateSocket(socketPath);
      agent = new https.Agent({ keepAlive: false, maxSockets: 1, maxCachedSessions: 0 });
      agent.createConnection = () => {
        unixSocket = net.createConnection({ path: socketPath });
        secureSocket = tls.connect({ socket: unixSocket,
          servername: canonical.hostname, rejectUnauthorized: true, checkServerIdentity: tls.checkServerIdentity,
          minVersion: "TLSv1.2", ALPNProtocols: ["http/1.1"], ...(ca === undefined ? {} : { ca }) });
        return secureSocket;
      };
      return await new Promise((resolve, reject) => {
        let finished = false;
        let timer;
        const finish = (value) => {
          if (finished) return; finished = true; clearTimeout(timer);
          if (value instanceof Response) resolve(value); else reject(fail());
        };
        request = https.request({ hostname: canonical.hostname, port: 443, servername: canonical.hostname,
          path: `${url.pathname}${url.search}`, method, headers: Object.fromEntries(headers), agent,
          signal: options.signal, maxHeaderSize: 8192, rejectUnauthorized: true, checkServerIdentity: tls.checkServerIdentity }, (response) => {
          try {
            const status = response.statusCode;
            if (!Number.isInteger(status) || status < 200 || status > 599 || (status >= 300 && status < 400)) {
              response.destroy(); finish(null); return;
            }
            const responseHeaders = new Headers();
            for (const [key, value] of Object.entries(response.headers)) {
              if (value !== undefined) responseHeaders.set(key, Array.isArray(value) ? value.join(", ") : value);
            }
            if (status !== 200) {
              response.destroy(); finish(new Response(null, { status, headers: responseHeaders })); return;
            }
            const length = responseHeaders.get("content-length");
            if ((length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_BODY)) ||
                (responseHeaders.has("content-encoding") && responseHeaders.get("content-encoding") !== "identity")) {
              response.destroy(); finish(null); return;
            }
            const chunks = []; let size = 0;
            response.on("data", (chunk) => {
              size += chunk.length;
              if (size > MAX_BODY) { response.destroy(); finish(null); }
              else chunks.push(chunk);
            });
            response.once("end", () => {
              try { finish(new Response(Buffer.concat(chunks, size), { status, headers: responseHeaders })); }
              catch { finish(null); }
            });
            response.once("error", () => finish(null));
            response.once("aborted", () => finish(null));
          } catch { response.destroy(); finish(null); }
        });
        request.once("error", () => finish(null));
        request.once("upgrade", (_response, socket) => { socket.destroy(); finish(null); });
        timer = setTimeout(() => { request.destroy(); finish(null); }, 45000);
        request.end(options.body);
      });
    } catch { throw fail(); }
    finally { request?.destroy(); agent?.destroy(); secureSocket?.destroy(); unixSocket?.destroy(); }
  };
}
