// One-attempt delivery to the existing backend identity volume. No application,
// database, HTTP, Tailscale, enrollment or remote client is imported or started.
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, X509Certificate } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { backendEnvironment, exact, parseDeploymentConfig, privateDirectory, readBackendDatabaseCa, readPrivateJson } from '../railway/config.mjs';
import { requireNoNewPrivileges } from '../staging/runtime-check.mjs';

const fail = () => { throw new Error('BACKEND_PROVISION_UNAVAILABLE'); };
const ENV = Object.freeze({ PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', NODE_ENV: 'production' });
const MAXIMUM = 16384;
const ownerId = value => typeof value === 'string' && /^[1-9][0-9]{0,15}$/.test(value) && Number.isSafeInteger(Number(value));
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);

export function guard({ identity = process, environment = process.env, noNewPrivileges = requireNoNewPrivileges } = {}) {
  if ([identity.getuid(), identity.getgid(), identity.geteuid(), identity.getegid()].some(id => id !== 1000)) fail();
  noNewPrivileges();
  if (Object.keys(environment).some(key => !(Object.hasOwn(ENV, key) && environment[key] === ENV[key]) &&
    !(key === 'UV_USE_IO_URING' && environment[key] === '0'))) fail();
}
function caText(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value) > 16384 ||
    !/^(?:-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\n?)+$/.test(value)) fail();
  const blocks = value.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!blocks || blocks.length > 4) fail();
  for (const block of blocks) {
    const ca = new X509Certificate(block);
    if (!ca.ca || Date.now() < Date.parse(ca.validFrom) || Date.now() >= Date.parse(ca.validTo)) fail();
  }
  return value;
}
export function parseEnvelope(raw, runtimeRaw, identityRaw) {
  try {
    exact(raw, ['mode', 'verifiedOwnerId', 'app', 'caCertificate']);
    if (raw.mode !== 'whoop-backend-config' || !ownerId(raw.verifiedOwnerId)) fail();
    const runtime = parseDeploymentConfig(runtimeRaw);
    if (runtime.role !== 'backend') fail();
    exact(identityRaw, ['mode', 'hostname', 'clientId', 'clientSecret']);
    if (identityRaw.mode !== 'whoop-owner-identity' || identityRaw.hostname !== runtime.hostname) fail();
    for (const key of ['clientId', 'clientSecret']) if (typeof identityRaw[key] !== 'string' || !/^[\x21-\x7e]{1,2048}$/.test(identityRaw[key])) fail();
    // Use the exact ordinary backend schema/host/TLS-URI guard. Stronger
    // provisioning restrictions exclude migration/admin credentials entirely.
    backendEnvironment(raw.app, runtime.hostname);
    const app = structuredClone(raw.app); const uri = new URL(app.DATABASE_URL);
    if (uri.username !== 'whoop_runtime' || uri.pathname !== '/whoop' || !hex(decodeURIComponent(uri.password)) ||
      app.WHOOP_CLIENT_ID !== identityRaw.clientId || app.WHOOP_CLIENT_SECRET !== identityRaw.clientSecret ||
      app.ALLOWED_WHOOP_USER_ID !== raw.verifiedOwnerId || !hex(app.ENCRYPTION_KEY) || !hex(app.SESSION_SECRET) ||
      !hex(app.GATEWAY_SERVICE_TOKEN_SHA256) || new Set([app.ENCRYPTION_KEY, app.SESSION_SECRET, decodeURIComponent(uri.password)]).size !== 3) fail();
    // This explicit ID is the operator's independently confirmed input. The
    // helper never learns/sets identity from a callback or first login.
    return { app, caCertificate: caText(raw.caCertificate) };
  } catch { fail(); }
}
async function readInput(input, timeoutMs, signal) {
  if (input.isTTY || signal?.aborted || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000) fail();
  const chunks = []; let size = 0;
  try {
    return await new Promise((resolve, reject) => {
      let timer; let ended = false;
      const finish = error => {
        if (ended) return; ended = true; clearTimeout(timer);
        input.off('data', data); input.off('end', end); input.off('error', failed); input.off('close', failed);
        signal?.removeEventListener('abort', failed); input.pause();
        if (error) reject(new Error('BACKEND_PROVISION_UNAVAILABLE'));
        else resolve(Buffer.concat(chunks));
      };
      const data = chunk => { if (!Buffer.isBuffer(chunk)) { finish(true); return; } size += chunk.length; if (size > MAXIMUM) { finish(true); return; } chunks.push(chunk); };
      const end = () => finish(size < 2); const failed = () => finish(true);
      timer = setTimeout(failed, timeoutMs);
      input.on('data', data); input.once('end', end); input.once('error', failed); input.once('close', failed);
      signal?.addEventListener('abort', failed, { once: true }); if (signal?.aborted) failed();
    });
  } finally { for (const chunk of chunks) chunk.fill(0); }
}
function exclusive(filename, data) {
  const fd = fs.openSync(filename, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function syncDirectory(directory) {
  const fd = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function publish(directory, name, data, validate) {
  const temporary = path.join(directory, '.backend-config-' + randomBytes(12).toString('hex'));
  exclusive(temporary, data); validate?.(temporary);
  fs.linkSync(temporary, path.join(directory, name)); // atomic, refuses overwrite
  fs.unlinkSync(temporary); syncDirectory(directory);
}
// Alternate root/dependencies exist only for isolated tests. The CLI admits no
// arguments and fixes /data; neither payload nor environment selects paths.
export async function provisionBackend({ input = process.stdin, root = '/data', identity = process,
  environment = process.env, noNewPrivileges = requireNoNewPrivileges, timeoutMs = 5000, signal } = {}) {
  try {
    guard({ identity, environment, noNewPrivileges });
    if (!path.isAbsolute(root) || path.normalize(root) !== root) fail();
    process.umask(0o077);
    const rootInfo = fs.lstatSync(root);
    if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink() || ![0, 1000].includes(rootInfo.uid) || (rootInfo.mode & 0o022)) fail();
    const directory = path.join(root, 'config'); privateDirectory(directory); privateDirectory(path.join(root, 'tailscale'));
    const names = fs.readdirSync(directory).sort();
    if (JSON.stringify(names) !== JSON.stringify(['identity.json', 'runtime.json'])) fail();
    const state = fs.lstatSync(path.join(root, 'tailscale', 'tailscaled.state'));
    if (!state.isFile() || state.isSymbolicLink() || state.nlink !== 1 || state.uid !== 1000 || (state.mode & 0o077) || state.size < 1) fail();
    const runtime = readPrivateJson(path.join(directory, 'runtime.json'));
    const identityConfig = readPrivateJson(path.join(directory, 'identity.json'), 8192);
    const bytes = await readInput(input, timeoutMs, signal); let parsed;
    try { parsed = parseEnvelope(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)), runtime, identityConfig); }
    finally { bytes.fill(0); }
    if (signal?.aborted) fail();
    // Exclusive claim precedes all new secret writes. Partial files/claim are
    // preserved for inspection; there is no retry, replace or cleanup command.
    exclusive(path.join(directory, '.backend-config-attempt'), '{"version":1}\n'); syncDirectory(directory);
    publish(directory, 'db-ca.pem', parsed.caCertificate, filename => {
      if (readBackendDatabaseCa(filename) !== parsed.caCertificate) fail();
    });
    // app.json is the final commit: ordinary runtime paths remain unchanged.
    publish(directory, 'app.json', JSON.stringify(parsed.app) + '\n', filename => {
      backendEnvironment(readPrivateJson(filename), runtime.hostname);
    });
    return { phase: 'backend-configured-awaiting-clean-redeploy' };
  } catch { fail(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const controller = new AbortController();
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => controller.abort());
  try {
    if (process.argv.length !== 2) fail();
    await provisionBackend({ signal: controller.signal });
    console.log('Backend configuration prepared. Remove provisioning variable and deploy the normal runtime.');
    const hold = setInterval(() => {}, 60000);
    for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => clearInterval(hold));
  } catch { console.error('Backend configuration unavailable.'); process.exitCode = 1; }
}
