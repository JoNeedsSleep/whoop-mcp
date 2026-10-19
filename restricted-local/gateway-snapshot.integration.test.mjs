// Full synthetic gateway composition; run only in the approved offline sandbox.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import http from "node:http";
import https from "node:https";
import { once } from "node:events";
import { createHash } from "node:crypto";
import { startRelay } from "./fixed-relay.mjs";
import { createUnixFetch } from "./unix-https.mjs";
import { createGateway } from "../review-gateway/gateway.mjs";
import { createGatewayServer } from "../review-gateway/server.mjs";
import { GatewayStore } from "../review-gateway/store.mjs";
import { createSyntheticService, syntheticSummary } from "../deploy/staging/service.mjs";

const ORIGIN = "https://backend.test-tailnet.ts.net";
const GATEWAY = "https://gateway.test-tailnet.ts.net";
const TARGET = "100.101.102.103";
const MACHINE = `whoopgw_service_${"x".repeat(43)}`;
const BEARER = `gw_${"y".repeat(43)}`;
const NOW = Date.UTC(2026, 9, 18, 12);
const DAY = 86400000;

test("normal gateway snapshot composes seven rapid verified Unix HTTPS requests including oldest NO_DATA", { timeout: 30000 }, async (t) => {
  const tlsDirectory = process.env.GATEWAY_TEST_TLS_DIR;
  assert.ok(tlsDirectory && path.isAbsolute(tlsDirectory), "Approved synthetic TLS fixture is required");
  const read = (name) => {
    const fd = fs.openSync(path.join(tlsDirectory, name), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    try { const info = fs.fstatSync(fd); assert.ok(info.isFile() && info.size > 0 && info.size < 65536); return fs.readFileSync(fd); }
    finally { fs.closeSync(fd); }
  };
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gateway-snapshot-")); fs.chmodSync(directory, 0o700);
  const socketPath = path.join(directory, "backend.sock");
  const sockets = new Set(); const requested = []; const httpDates = [];
  const track = (socket) => { sockets.add(socket); socket.on("error", () => {}); socket.once("close", () => sockets.delete(socket)); return socket; };
  const fixture = createSyntheticService({ mode: "synthetic-fixture-only", hostname: new URL(ORIGIN).hostname,
    serviceTokenSha256: createHash("sha256").update(MACHINE).digest("hex") }, { now: () => NOW });
  const tlsServer = https.createServer({ key: read("server-key.pem"), cert: read("server.pem"), minVersion: "TLSv1.2" }, (req, res) => {
    httpDates.push(new URL(req.url, ORIGIN).searchParams.get("date")); fixture.emit("request", req, res);
  });
  tlsServer.on("connection", track); tlsServer.on("tlsClientError", () => {});
  const socks = net.createServer((socket) => {
    track(socket); let buffer = Buffer.alloc(0); let greeting = true;
    socket.on("data", function handshake(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      if (greeting) {
        if (buffer.length < 3) return;
        assert.deepEqual([...buffer.subarray(0, 3)], [5, 1, 0]); buffer = buffer.subarray(3); greeting = false;
        socket.write(Buffer.from([5, 0]));
      }
      if (buffer.length < 10) return;
      assert.deepEqual([...buffer.subarray(0, 4)], [5, 1, 0, 1]);
      const target = { host: [...buffer.subarray(4, 8)].join("."), port: buffer.readUInt16BE(8) };
      assert.deepEqual(target, { host: TARGET, port: 443 }); requested.push(target);
      const remainder = buffer.subarray(10); buffer = Buffer.alloc(0); socket.removeListener("data", handshake); socket.pause();
      // The fixture always dials its own loopback server, regardless of input.
      const upstream = track(net.connect({ host: "127.0.0.1", port: tlsServer.address().port }));
      upstream.once("connect", () => {
        socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
        if (remainder.length) upstream.write(remainder);
        socket.pipe(upstream); upstream.pipe(socket); socket.resume();
      });
      socket.once("close", () => upstream.destroy()); upstream.once("close", () => socket.destroy());
    });
  });
  let relay; let server;
  const store = new GatewayStore({ filename: ":memory:", now: () => NOW });
  t.after(async () => {
    server?.closeAllConnections();
    for (const socket of sockets) socket.destroy();
    if (relay) await relay.close();
    await Promise.all([server, socks, tlsServer].filter((item) => item?.listening).map((item) => new Promise((resolve) => item.close(resolve))));
    store.close(); fs.rmSync(directory, { recursive: true, force: true });
  });
  tlsServer.listen(0, "127.0.0.1"); await once(tlsServer, "listening");
  socks.listen(0, "127.0.0.1"); await once(socks, "listening");
  relay = await startRelay({ socketPath, targetIpv4: TARGET, socksPort: socks.address().port });
  const fetchImpl = createUnixFetch({ origin: ORIGIN, socketPath, allowedPaths: ["/internal/health-summary"], ca: read("ca.pem") });
  const callTool = createGateway({ origin: ORIGIN, whoopBearer: MACHINE, fetchImpl, now: () => NOW });
  const auth = { handleAuth: async () => false,
    verifyBearer: async (value) => value === BEARER ? { clientId: "codex", audience: `${GATEWAY}/mcp`, expiresAt: NOW + 7 * DAY } : null };
  server = createGatewayServer({ publicOrigin: GATEWAY, auth, store, callTool, now: () => NOW });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const expectedDates = Array.from({ length: 7 }, (_, index) => new Date(NOW - (6 - index) * DAY).toISOString().slice(0, 10));
  for (let round = 0; round < 3; round++) {
    const result = await new Promise((resolve, reject) => {
      const req = http.get({ host: "127.0.0.1", port: server.address().port, path: "/data/snapshot", agent: false,
        headers: { Host: new URL(GATEWAY).host, Authorization: `Bearer ${BEARER}`, Accept: "application/json" } }, (res) => {
        const chunks = []; res.on("data", (chunk) => chunks.push(chunk)); res.on("error", reject);
        res.on("end", () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) }));
      }); req.on("error", reject);
    });
    assert.equal(result.status, 200, `Snapshot round ${round + 1} must use the normal adapter successfully`);
    assert.deepEqual(result.body, { version: 1, windowEnd: "2026-10-18", summaries: expectedDates.map((date) => syntheticSummary(date, NOW)) });
    assert.equal(result.body.summaries[0].status, "NO_DATA");
  }
  assert.deepEqual(httpDates, [...expectedDates, ...expectedDates, ...expectedDates]);
  assert.equal(requested.length, 21);
});
