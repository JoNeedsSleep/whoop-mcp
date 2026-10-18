import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { DAY_MS, validateSnapshot } from "./policy.mjs";

export const MAX_CACHE_BYTES = 16384;
export const CACHE_TTL_MS = 90 * 60000;
const unavailable = () => { throw new Error("LOCAL_CACHE_UNAVAILABLE"); };
const clients = new Set(["codex", "claude-code"]);

function location(filename) {
  if (typeof filename !== "string" || !path.isAbsolute(filename) || path.normalize(filename) !== filename ||
      filename.includes("\0") || filename.endsWith(path.sep) || typeof process.getuid !== "function") unavailable();
  const directory = path.dirname(filename);
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077)) unavailable();
  return directory;
}
function regular(stat, bounded = true) {
  if (!stat.isFile() || stat.uid !== process.getuid() || stat.nlink !== 1 || (stat.mode & 0o077) ||
      (bounded && (stat.size < 1 || stat.size > MAX_CACHE_BYTES))) unavailable();
}
function record(raw, clientId, now) {
  const keys = ["version", "clientId", "syncedAt", "expiresAt", "authorizationExpiresAt", "snapshot"];
  if (!raw || typeof raw !== "object" || Array.isArray(raw) || Object.getPrototypeOf(raw) !== Object.prototype ||
      Reflect.ownKeys(raw).length !== keys.length || keys.some((key) => !Object.hasOwn(raw, key)) ||
      raw.version !== 1 || !clients.has(clientId) || raw.clientId !== clientId) unavailable();
  for (const value of [now, raw.syncedAt, raw.expiresAt, raw.authorizationExpiresAt]) {
    if (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) unavailable();
  }
  if (raw.syncedAt > now || raw.expiresAt <= now || raw.authorizationExpiresAt <= now ||
      raw.expiresAt > raw.syncedAt + CACHE_TTL_MS || raw.expiresAt > raw.authorizationExpiresAt ||
      raw.authorizationExpiresAt > raw.syncedAt + 7 * DAY_MS) unavailable();
  // A snapshot records its sync day's fixed window. Its short freshness deadline
  // still applies after UTC midnight; never relabel yesterday's cached values.
  return { version: 1, clientId, syncedAt: raw.syncedAt, expiresAt: raw.expiresAt,
    authorizationExpiresAt: raw.authorizationExpiresAt, snapshot: validateSnapshot(raw.snapshot, raw.syncedAt) };
}

export function readCache(filename, clientId, now = Date.now()) {
  let fd;
  try {
    location(filename);
    // NONBLOCK ensures a substituted FIFO cannot hang the reader before fstat.
    fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    regular(fs.fstatSync(fd));
    const bytes = Buffer.alloc(MAX_CACHE_BYTES + 1);
    let count = 0;
    for (;;) {
      const size = fs.readSync(fd, bytes, count, bytes.length - count, null);
      count += size;
      if (count > MAX_CACHE_BYTES) unavailable();
      if (size === 0) break;
    }
    regular(fs.fstatSync(fd));
    const raw = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, count)));
    return record(raw, clientId, now);
  } catch { unavailable(); }
  finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch {} } }
}

export function writeCache(filename, raw, now = Date.now()) {
  let fd;
  let temporary;
  try {
    const clean = record(raw, raw?.clientId, now);
    const bytes = Buffer.from(JSON.stringify(clean));
    if (bytes.length > MAX_CACHE_BYTES) unavailable();
    const directory = location(filename);
    try { regular(fs.lstatSync(filename), false); }
    catch (error) { if (error?.code !== "ENOENT") throw error; }
    temporary = path.join(directory, `.cache-${randomBytes(16).toString("hex")}.tmp`);
    fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
    fs.closeSync(fd); fd = undefined;
    fs.renameSync(temporary, filename); temporary = undefined;
    // Persist the rename as well as the complete file where directory fsync is
    // supported. This code targets the reviewed Linux runtime.
    fd = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    fs.fsyncSync(fd);
    fs.closeSync(fd); fd = undefined;
    return clean;
  } catch { unavailable(); }
  finally {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch {} }
    if (temporary !== undefined) { try { fs.unlinkSync(temporary); } catch {} }
  }
}
