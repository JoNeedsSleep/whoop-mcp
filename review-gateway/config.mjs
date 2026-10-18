import fs from "node:fs";
import path from "node:path";

const invalid = () => { throw new Error("INVALID_GATEWAY_CONFIG"); };
function origin(value) {
  try {
    const u = new URL(value);
    if (typeof value !== "string" || value !== u.origin || u.protocol !== "https:" || u.username || u.password) invalid();
    return value;
  } catch { invalid(); }
}
export function parseGatewayConfig(raw) {
  const keys = ["publicOrigin", "upstreamOrigin", "upstreamTokenFile", "ownerSecretHash", "databaseFile", "port", "clients"];
  if (!raw || typeof raw !== "object" || Array.isArray(raw) ||
      Object.keys(raw).some(k => !keys.includes(k)) || keys.some(k => !Object.hasOwn(raw, k))) invalid();
  origin(raw.publicOrigin); origin(raw.upstreamOrigin);
  if (raw.publicOrigin === raw.upstreamOrigin || typeof raw.ownerSecretHash !== "string" || !/^[a-f0-9]{64}$/.test(raw.ownerSecretHash) ||
      !Number.isSafeInteger(raw.port) || raw.port < 1024 || raw.port > 65535) invalid();
  for (const value of [raw.upstreamTokenFile, raw.databaseFile]) {
    if (typeof value !== "string" || !path.isAbsolute(value) || path.normalize(value) !== value || value.includes("\0")) invalid();
  }
  if (!Array.isArray(raw.clients) || raw.clients.length !== 2 ||
      raw.clients.map(c => c?.clientId).sort().join(",") !== "claude-code,codex") invalid();
  return structuredClone(raw);
}
export function readPrivateToken(filename) {
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > 128 || (stat.mode & 0o077) !== 0) invalid();
    const token = fs.readFileSync(fd, "utf8").trimEnd();
    if (!/^whoopgw_service_[A-Za-z0-9_-]{43}$/.test(token)) invalid();
    return token;
  } finally { fs.closeSync(fd); }
}
export function validateStorage(filename) {
  const directory = fs.lstatSync(path.dirname(filename));
  if (!directory.isDirectory() || directory.isSymbolicLink() || (directory.mode & 0o077) !== 0 ||
      directory.uid !== process.getuid()) invalid();
  if (fs.existsSync(filename)) {
    const file = fs.lstatSync(filename);
    if (!file.isFile() || file.isSymbolicLink() || (file.mode & 0o077) !== 0 || file.uid !== process.getuid()) invalid();
  }
}
