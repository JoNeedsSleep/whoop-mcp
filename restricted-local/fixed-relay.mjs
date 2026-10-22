// The Unix peer supplies only encrypted bytes, never a target. Tailscale state,
// control socket and SOCKS server remain exclusively in this relay's namespace.
import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import { Transform } from "node:stream";

const fail = () => new Error("PRIVATE_RELAY_UNAVAILABLE");
export function isTailnetTarget(value) {
  if (typeof value !== "string" || !/^100\.(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){2}$/.test(value) || value === "100.100.100.100") return false;
  const [a, b, c, d] = value.split(".").map(Number);
  return a === 100 && b >= 64 && b <= 127 && c <= 255 && d <= 255;
}
function readExactly(socket, size) {
  return new Promise((resolve, reject) => {
    if (socket.destroyed || socket.readableEnded) { reject(fail()); return; }
    let bytes = Buffer.alloc(0);
    const clean = () => {
      socket.pause(); socket.off("data", data); socket.off("error", error); socket.off("end", error); socket.off("close", error);
    };
    const error = () => { clean(); reject(fail()); };
    const data = (chunk) => {
      if (bytes.length + chunk.length > 262) { error(); return; }
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length >= size) {
        clean();
        if (bytes.length > size) socket.unshift(bytes.subarray(size));
        resolve(bytes.subarray(0, size));
      }
    };
    socket.on("data", data); socket.once("error", error); socket.once("end", error); socket.once("close", error); socket.resume();
  });
}
async function connectFixed(targetIpv4, socksPort, peer) {
  const upstream = net.createConnection({ host: "127.0.0.1", port: socksPort });
  peer.upstream = upstream;
  // A permanent error listener avoids an unhandled error between protocol steps.
  upstream.on("error", () => {});
  const timer = setTimeout(() => upstream.destroy(), 5000);
  try {
    await new Promise((resolve, reject) => {
      upstream.once("connect", resolve); upstream.once("error", () => reject(fail()));
      upstream.once("close", () => reject(fail()));
    });
    const greeting = readExactly(upstream, 2); upstream.write(Buffer.from([5, 1, 0]));
    if (!(await greeting).equals(Buffer.from([5, 0]))) throw fail();
    const reply = readExactly(upstream, 4);
    upstream.write(Buffer.from([5, 1, 0, 1, ...targetIpv4.split(".").map(Number), 1, 187]));
    const header = await reply;
    if (header[0] !== 5 || header[1] !== 0 || header[2] !== 0) throw fail();
    if (header[3] === 1) await readExactly(upstream, 6);
    else if (header[3] === 4) await readExactly(upstream, 18);
    else if (header[3] === 3) {
      const [length] = await readExactly(upstream, 1); if (length === 0) throw fail();
      await readExactly(upstream, length + 2);
    } else throw fail();
    return upstream;
  } catch { upstream.destroy(); throw fail(); }
  finally { clearTimeout(timer); }
}

export async function startRelay({ socketPath, targetIpv4, socksPort = 1055 }) {
  if (!isTailnetTarget(targetIpv4) || !Number.isInteger(socksPort) || socksPort < 1 || socksPort > 65535 ||
      typeof socketPath !== "string" || !path.isAbsolute(socketPath) || path.normalize(socketPath) !== socketPath || socketPath.includes("\0")) throw fail();
  const directory = fs.lstatSync(path.dirname(socketPath));
  if (!directory.isDirectory() || directory.isSymbolicLink() || directory.uid !== process.getuid() || (directory.mode & 0o077)) throw fail();
  try { fs.lstatSync(socketPath); throw fail(); } catch (error) { if (error?.code !== "ENOENT") throw fail(); }
  const peers = new Set(); let owned;
  const server = net.createServer((socket) => {
    if (peers.size >= 2) { socket.destroy(); return; }
    const peer = { socket, upstream: null }; peers.add(peer);
    const stop = () => { socket.destroy(); peer.upstream?.destroy(); };
    const timer = setTimeout(stop, 45000);
    // Consume a small TLS ClientHello while SOCKS negotiates so a peer's FIN
    // can cancel a stalled handshake. Never buffer arbitrary unlimited input.
    const pending = []; let pendingBytes = 0;
    const earlyData = (chunk) => {
      pendingBytes += chunk.length;
      if (pendingBytes > 16384) stop(); else pending.push(chunk);
    };
    socket.on("data", earlyData); socket.once("end", stop);
    socket.on("error", stop);
    socket.once("close", () => { clearTimeout(timer); pending.length = 0; peers.delete(peer); peer.upstream?.destroy(); });
    void connectFixed(targetIpv4, socksPort, peer).then((upstream) => {
      if (socket.destroyed) { upstream.destroy(); return; }
      socket.pause(); socket.off("data", earlyData);
      let size = 0;
      const bounded = () => {
        const stream = new Transform({ transform(chunk, _encoding, callback) {
          size += chunk.length;
          if (size > 128 * 1024) callback(fail()); else callback(null, chunk);
        } });
        stream.on("error", stop); return stream;
      };
      const outgoing = bounded(); const incoming = bounded();
      socket.once("close", () => { outgoing.destroy(); incoming.destroy(); });
      upstream.on("error", stop); upstream.once("close", () => socket.destroy());
      outgoing.pipe(upstream); upstream.pipe(incoming).pipe(socket);
      for (const chunk of pending) outgoing.write(chunk);
      pending.length = 0;
      socket.pipe(outgoing); socket.resume(); upstream.resume();
    }).catch(stop);
  });
  server.maxConnections = 3;
  server.on("error", () => {});
  try {
    await new Promise((resolve, reject) => {
      server.once("error", () => reject(fail())); server.listen(socketPath, resolve);
    });
    fs.chmodSync(socketPath, 0o600); owned = fs.lstatSync(socketPath);
  } catch { server.close(); throw fail(); }
  return { server, async close() {
    for (const peer of peers) { peer.socket.destroy(); peer.upstream?.destroy(); }
    await new Promise((resolve) => server.close(resolve));
    // Node normally unlinks its socket on close. The shared directory must have
    // one trusted writer; only our own leftover inode is explicitly removed.
    try {
      const current = fs.lstatSync(socketPath);
      if (current.isSocket() && current.uid === process.getuid() && current.ino === owned.ino && current.dev === owned.dev) fs.unlinkSync(socketPath);
    } catch (error) { if (error?.code !== "ENOENT") throw fail(); }
  } };
}
