import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { createUnixFetch } from "./unix-https.mjs";

export const AUTH_TTL_MS = 7 * 86400000;
export const CALLBACKS = Object.freeze({ codex: "http://127.0.0.1:17643/callback", "claude-code": "http://localhost:17644/callback" });
const fail = () => { throw new Error("LOCAL_CONFIGURATION_INVALID"); };
export function exact(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
export function parseLocalConfig(value) {
  const keys = ["clientId", "origin", "tokenFile", "cacheFile", "stateFile"];
  if (!value || !exact(value, Object.hasOwn(value, "transport") ? [...keys, "transport"] : keys) ||
      (Object.hasOwn(value, "transport") && value.transport !== "unix") || !Object.hasOwn(CALLBACKS, value.clientId)) fail();
  const origin = new URL(value.origin);
  if (origin.protocol !== "https:" || origin.origin !== value.origin || origin.username || origin.password) fail();
  const files = [value.tokenFile, value.cacheFile, value.stateFile];
  if (new Set(files).size !== files.length || files.some((file) => typeof file !== "string" || !path.isAbsolute(file) || path.normalize(file) !== file || file.includes("\0"))) fail();
  if (value.transport === "unix" && origin.port) fail();
  return { clientId: value.clientId, origin: value.origin, tokenFile: value.tokenFile, cacheFile: value.cacheFile, stateFile: value.stateFile,
    ...(value.transport === "unix" ? { transport: "unix" } : {}) };
}
// Only trusted startup configuration chooses this transport. There is no
// socket-path, CA override or proxy supplied by the model or remote response.
export function configuredFetch(config) {
  return config.transport === "unix" ? createUnixFetch({ origin: config.origin, socketPath: "/transport/gateway.sock" }) : fetch;
}
export function privateParent(filename) {
  if (typeof filename !== "string" || !path.isAbsolute(filename) || path.normalize(filename) !== filename) fail();
  const stat = fs.lstatSync(path.dirname(filename));
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077)) fail();
}
export function privateStat(stat, limit = Infinity) {
  if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077) || stat.nlink !== 1 || stat.size > limit) fail();
}
export function readPrivateJson(filename, limit = 16384) {
  privateParent(filename);
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    privateStat(fs.fstatSync(fd), limit);
    const bytes = Buffer.alloc(limit + 1); let size = 0; let read;
    do { read = fs.readSync(fd, bytes, size, bytes.length - size, null); size += read; } while (read && size < bytes.length);
    if (size > limit) fail();
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, size)));
  } finally { fs.closeSync(fd); }
}
export function writePrivateJson(filename, value, limit = 16384) {
  privateParent(filename);
  try { privateStat(fs.lstatSync(filename), limit); } catch (error) { if (error.code !== "ENOENT") throw error; }
  const bytes = Buffer.from(JSON.stringify(value)); if (bytes.length > limit) fail();
  const temporary = `${filename}.${randomBytes(16).toString("hex")}.tmp`;
  let fd;
  try {
    fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    fs.renameSync(temporary, filename);
    const directory = fs.openSync(path.dirname(filename), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(temporary); } catch (error) { if (error.code !== "ENOENT") throw error; }
  }
}
export function readLocalConfig(filename) { return parseLocalConfig(readPrivateJson(filename)); }
export function parseToken(value, config, now = Date.now()) {
  if (!exact(value, ["clientId", "origin", "accessToken", "expiresAt"]) || value.clientId !== config.clientId || value.origin !== config.origin ||
      typeof value.accessToken !== "string" || !/^gw_[A-Za-z0-9_-]{43}$/.test(value.accessToken) ||
      !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= now || value.expiresAt > now + AUTH_TTL_MS) fail();
  return { clientId: value.clientId, origin: value.origin, accessToken: value.accessToken, expiresAt: value.expiresAt };
}
export class RemoteFailure extends Error {
  constructor(status = 0) { super("GATEWAY_REQUEST_FAILED"); this.status = status; }
}
// Only callers choose the fixed endpoint. Remote JSON never supplies a URL,
// header, request body, filesystem path or a follow-up request.
export async function boundedJson(url, options, { fetchImpl = fetch, maxBytes = 32768, timeoutMs = 5000 } = {}) {
  const controller = new AbortController(); let reader; let response; let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => { controller.abort(); reject(new RemoteFailure()); }, timeoutMs);
  });
  const operation = async () => {
    response = await fetchImpl(url, { ...options, redirect: "error", signal: controller.signal });
    if (response.status !== 200 || response.redirected) throw new RemoteFailure(response.status);
    if (!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?\s*$/i.test(response.headers.get("content-type") ?? "") ||
        (response.headers.get("content-encoding") && response.headers.get("content-encoding") !== "identity")) throw new RemoteFailure();
    const length = response.headers.get("content-length");
    if (length !== null && (!/^\d+$/.test(length) || Number(length) > maxBytes)) throw new RemoteFailure();
    reader = response.body?.getReader(); if (!reader) throw new RemoteFailure();
    let size = 0; const chunks = [];
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.byteLength; if (size > maxBytes) throw new RemoteFailure(); chunks.push(value);
    }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, size)));
  };
  try { return await Promise.race([operation(), timeout]); }
  catch (error) { throw error instanceof RemoteFailure ? error : new RemoteFailure(); }
  finally {
    clearTimeout(timer); controller.abort();
    try {
      const cancellation = reader ? reader.cancel() : response?.body?.cancel();
      if (cancellation) void cancellation.catch(() => {});
    } catch { /* Cancellation must not disclose a remote stream error. */ }
  }
}
