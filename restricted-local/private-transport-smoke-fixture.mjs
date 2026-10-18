// Test-only container fixture. Never include this module in a release image.
// Its mock SOCKS server records a fixed synthetic tailnet destination but dials
// only the TLS server in this same network:none container. No Tailscale login.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import https from "node:https";
import { once } from "node:events";
import { startRelay } from "./fixed-relay.mjs";

assert.equal(process.env.WHOOP_PRIVATE_TRANSPORT_SYNTHETIC_ONLY, "true");
assert.equal(process.argv.length, 2);
const tlsDirectory = process.env.GATEWAY_TEST_TLS_DIR;
assert.ok(tlsDirectory && path.isAbsolute(tlsDirectory));
const read = (name) => {
  const fd = fs.openSync(path.join(tlsDirectory, name), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try { const stat = fs.fstatSync(fd); assert.ok(stat.isFile() && stat.size > 0 && stat.size < 65536); return fs.readFileSync(fd); }
  finally { fs.closeSync(fd); }
};
const records = { synthetic: true, socks: [], http: [] };
const statsFile = "/tmp/private-transport-fixture-state.json";
function save() {
  assert.ok(records.socks.length <= 100 && records.http.length <= 100);
  const temporary = `${statsFile}.next`;
  fs.writeFileSync(temporary, JSON.stringify(records), { mode: 0o600 }); fs.renameSync(temporary, statsFile);
}
const sockets = new Set();
function track(socket) { sockets.add(socket); socket.on("error", () => {}); socket.once("close", () => sockets.delete(socket)); return socket; }
const endpoint = https.createServer({ key: read("server-key.pem"), cert: read("server.pem"), minVersion: "TLSv1.2" }, (req, res) => {
  // Record authority/shape only, never a bearer, cookie or response body.
  records.http.push({ method: req.method, path: req.url, host: req.headers.host,
    authorizationPresent: /^Bearer gw_[A-Za-z0-9_-]{43}$/.test(req.headers.authorization ?? ""),
    cookiePresent: req.headers.cookie !== undefined }); save();
  res.setHeader("Connection", "close"); res.setHeader("Content-Type", "application/json");
  if (req.method !== "GET" || req.url !== "/data/snapshot" || req.headers.host !== "gateway.test-tailnet.ts.net" ||
      !records.http.at(-1).authorizationPresent) { res.writeHead(400); res.end('{"error":"FIXTURE_REQUEST_REJECTED"}'); return; }
  const windowEnd = new Date().toISOString().slice(0, 10); const end = Date.parse(windowEnd);
  res.end(JSON.stringify({ version: 1, windowEnd, summaries: Array.from({ length: 7 }, (_, index) => ({
    date: new Date(end - (6 - index) * 86400000).toISOString().slice(0, 10), status: "AVAILABLE",
    recovery_score: 73, hrv_ms: 44.25, resting_heart_rate: 53, sleep_ms: 28000000, sleep_performance: 92, strain: 8.25,
  })) }));
});
endpoint.on("connection", track); endpoint.on("tlsClientError", () => {});
const socks = net.createServer((socket) => {
  track(socket); let phase = "greeting"; let buffer = Buffer.alloc(0);
  socket.on("data", function receive(chunk) {
    buffer = Buffer.concat([buffer, chunk]);
    if (buffer.length > 1024) { socket.destroy(); return; }
    if (phase === "greeting") {
      if (buffer.length < 3) return;
      if (!buffer.subarray(0, 3).equals(Buffer.from([5, 1, 0]))) { socket.destroy(); return; }
      buffer = buffer.subarray(3); phase = "connect"; socket.write(Buffer.from([5, 0]));
    }
    if (phase !== "connect" || buffer.length < 10) return;
    if (!buffer.subarray(0, 4).equals(Buffer.from([5, 1, 0, 1]))) { socket.destroy(); return; }
    const target = { host: [...buffer.subarray(4, 8)].join("."), port: buffer.readUInt16BE(8) };
    records.socks.push(target); save();
    if (target.host !== "100.101.102.103" || target.port !== 443) { socket.destroy(); return; }
    const remainder = buffer.subarray(10); phase = "tunnel"; socket.removeListener("data", receive); socket.pause();
    const upstream = track(net.connect({ host: "127.0.0.1", port: endpoint.address().port }));
    upstream.once("connect", () => {
      socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
      if (remainder.length) upstream.write(remainder);
      socket.pipe(upstream); upstream.pipe(socket); socket.resume();
    });
    socket.once("close", () => upstream.destroy()); upstream.once("close", () => socket.destroy());
  });
});
let relay; let closing;
const close = () => closing ??= (async () => {
  clearTimeout(deadline);
  for (const socket of sockets) socket.destroy();
  if (relay) await relay.close();
  await Promise.all([endpoint, socks].filter((server) => server.listening).map((server) => new Promise((resolve) => server.close(resolve))));
})();
const deadline = setTimeout(() => { process.exitCode = 1; void close(); }, 300000);
for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => void close());
try {
  endpoint.listen(0, "127.0.0.1"); await once(endpoint, "listening");
  socks.listen(1055, "127.0.0.1"); await once(socks, "listening");
  relay = await startRelay({ socketPath: "/transport/gateway.sock", targetIpv4: "100.101.102.103" });
  save();
  console.log(JSON.stringify({ ready: true, syntheticOnly: true, socketPath: "/transport/gateway.sock", statsFile }));
} catch {
  process.exitCode = 1; await close(); console.error("Synthetic private-transport fixture unavailable.");
}
