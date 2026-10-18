import fs from 'node:fs';
import path from 'node:path';

export const fail = () => { throw new Error('PRIVATE_RUNTIME_UNAVAILABLE'); };
export const TS_VERSION = '1.104.1';
export function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
export function exact(value, keys) {
  if (!object(value) || Object.keys(value).length !== keys.length || keys.some(k => !Object.hasOwn(value, k))) fail();
}
export function tailnetHostname(value) {
  if (typeof value !== 'string' || value.length > 253 ||
      !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.ts\.net$/.test(value)) fail();
  return value;
}
export function tailnetIpv4(value) {
  if (typeof value !== 'string' || !/^100\.(?:[0-9]{1,3})\.(?:[0-9]{1,3})\.(?:[0-9]{1,3})$/.test(value)) fail();
  const octets = value.split('.').map(Number);
  if (octets.join('.') !== value || octets[1] < 64 || octets[1] > 127 || octets.some(v => v > 255) || value === '100.100.100.100') fail();
  return value;
}
export function privateDirectory(directory) {
  if (!path.isAbsolute(directory) || path.normalize(directory) !== directory) fail();
  const st = fs.lstatSync(directory);
  if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== process.getuid() || (st.mode & 0o077)) fail();
}
export function readPrivateJson(filename, maxBytes = 16384) {
  privateDirectory(path.dirname(filename));
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1 || st.uid !== process.getuid() || (st.mode & 0o077) || st.size < 2 || st.size > maxBytes) fail();
    const bytes = Buffer.alloc(maxBytes + 1); const size = fs.readSync(fd, bytes);
    if (size > maxBytes) fail();
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, size)));
  } finally { fs.closeSync(fd); }
}
export function parseDeploymentConfig(raw) {
  const gateway = raw?.role === 'gateway';
  exact(raw, ['role', 'hostname', 'stateDirectory', 'appConfigFile', ...(gateway ? ['backendIpv4'] : [])]);
  if (!['gateway', 'backend'].includes(raw.role) || raw.stateDirectory !== '/data/tailscale' || raw.appConfigFile !== '/data/config/app.json') fail();
  tailnetHostname(raw.hostname);
  if (gateway) tailnetIpv4(raw.backendIpv4);
  return structuredClone(raw);
}
const BACKEND_KEYS = ['DATABASE_URL', 'ENCRYPTION_KEY', 'WHOOP_CLIENT_ID', 'WHOOP_CLIENT_SECRET',
  'PUBLIC_BASE_URL', 'SESSION_SECRET', 'ALLOWED_WHOOP_USER_ID', 'GATEWAY_SERVICE_TOKEN_SHA256'];
export function backendEnvironment(raw, hostname) {
  exact(raw, BACKEND_KEYS); tailnetHostname(hostname);
  if (BACKEND_KEYS.some(k => typeof raw[k] !== 'string' || raw[k].length < 1 || raw[k].length > 8192 || raw[k].includes('\0')) ||
      raw.PUBLIC_BASE_URL !== `https://${hostname}`) fail();
  return { ...raw, PATH: '/usr/local/bin:/usr/bin:/bin', NODE_ENV: 'production',
    BIND_HOST: '127.0.0.1', PORT: '8080', RUN_MIGRATIONS: 'false', ENABLE_LEGACY_DIRECT_MCP: 'false',
    APPROVED_CLIENT_REDIRECT_URIS: '' };
}
