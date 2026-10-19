// One stopped-gateway cutover. No daemon, application, database or network code.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { exact, tailnetHostname, tailnetIpv4, parseDeploymentConfig } from '../railway/config.mjs';
import { parseGatewayConfig } from '../../review-gateway/config.mjs';
import { requireNoNewPrivileges } from '../staging/runtime-check.mjs';

const fail = () => { throw new Error('GATEWAY_CONFIGURATION_UNAVAILABLE'); };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const files = ['app.json', 'runtime.json', 'service-token', 'staging-gateway.json'];
const expectedKeys = ['appSha256', 'runtimeSha256', 'tokenFileSha256', 'stagingMarkerSha256'];
const fileKeys = ['appSha256', 'runtimeSha256', 'tokenFileSha256', 'stagingMarkerSha256'];
const ids = identity => [identity.getuid(), identity.geteuid(), identity.getgid(), identity.getegid()];
function guard(identity, nnp) { if (ids(identity).some(id => id !== 1000)) fail(); nnp(); }
function token(value) {
  if (typeof value !== 'string' || !/^whoopgw_service_[A-Za-z0-9_-]{43}$/.test(value) ||
      Buffer.from(value.slice(16), 'base64url').toString('base64url') !== value.slice(16)) fail();
  return value;
}
export function parseCutover(raw) {
  try {
    exact(raw, ['mode', 'hostname', 'backendHostname', 'backendIpv4', 'serviceToken', 'expected']);
    if (raw.mode !== 'whoop-gateway-backend-cutover') fail();
    tailnetHostname(raw.hostname); tailnetHostname(raw.backendHostname); tailnetIpv4(raw.backendIpv4); token(raw.serviceToken);
    if (raw.hostname === raw.backendHostname) fail();
    exact(raw.expected, expectedKeys);
    if (Object.values(raw.expected).some(value => typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value))) fail();
    return structuredClone(raw);
  } catch { fail(); }
}
function directory(filename, uid = 1000) {
  const s = fs.lstatSync(filename);
  if (!s.isDirectory() || s.isSymbolicLink() || s.uid !== uid || (s.mode & 0o777) !== 0o700) fail();
}
function read(filename, maximum = 16384) {
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const s = fs.fstatSync(fd);
    if (!s.isFile() || s.nlink !== 1 || s.uid !== 1000 || (s.mode & 0o077) || s.size < 1 || s.size > maximum) fail();
    const bytes = Buffer.alloc(maximum + 1); const size = fs.readSync(fd, bytes);
    const after = fs.fstatSync(fd);
    if (size !== s.size || size > maximum || after.size !== s.size || after.mtimeMs !== s.mtimeMs || after.ctimeMs !== s.ctimeMs) fail();
    return bytes.subarray(0, size);
  } finally { fs.closeSync(fd); }
}
function json(bytes) { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
function syncDir(filename) { const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
function write(filename, bytes) {
  const fd = fs.openSync(filename, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
function clients(value) {
  if (!Array.isArray(value) || value.length !== 2) fail();
  const wanted = [ ['codex', 'Codex', 'http://127.0.0.1:17643/callback'], ['claude-code', 'Claude Code', 'http://localhost:17644/callback'] ];
  for (let i = 0; i < wanted.length; i++) {
    const [id, name, uri] = wanted[i]; const client = value[i];
    exact(client, ['clientId', 'name', 'redirectUris']);
    if (client.clientId !== id || client.name !== name || !Array.isArray(client.redirectUris) ||
        client.redirectUris.length !== 1 || client.redirectUris[0] !== uri) fail();
  }
}
function current(config, payload) {
  const bytes = files.map(name => read(path.join(config, name), name === 'service-token' ? 128 : 16384));
  if (payload) bytes.forEach((data, i) => { if (hash(data) !== payload.expected[fileKeys[i]]) fail(); });
  const app = parseGatewayConfig(json(bytes[0])); const runtime = parseDeploymentConfig(json(bytes[1]));
  const oldToken = new TextDecoder('utf-8', { fatal: true }).decode(bytes[2]);
  const marker = json(bytes[3]);
  exact(marker, ['mode', 'hostname', 'fixtureHostname', 'fixtureIpv4', 'ownerSecretHash', 'serviceTokenSha256']);
  tailnetHostname(marker.hostname); tailnetHostname(marker.fixtureHostname); tailnetIpv4(marker.fixtureIpv4);
  if (marker.mode !== 'synthetic-fixture-only' ||
      (payload && (marker.hostname !== payload.hostname || marker.fixtureHostname === payload.backendHostname || marker.fixtureIpv4 === payload.backendIpv4)) ||
      !/^[a-f0-9]{64}$/.test(marker.ownerSecretHash) || !/^[a-f0-9]{64}$/.test(marker.serviceTokenSha256) ||
      runtime.role !== 'gateway' || runtime.hostname !== marker.hostname || runtime.backendIpv4 !== marker.fixtureIpv4 ||
      app.publicOrigin !== `https://${marker.hostname}` || app.upstreamOrigin !== `https://${marker.fixtureHostname}` ||
      app.upstreamTokenFile !== '/data/config/service-token' || app.databaseFile !== '/data/app/gateway.sqlite' ||
      app.port !== 8787 || app.ownerSecretHash !== marker.ownerSecretHash || !oldToken.endsWith('\n') ||
      (payload && token(oldToken.slice(0, -1)) === payload.serviceToken) || hash(oldToken.slice(0, -1)) !== marker.serviceTokenSha256) fail();
  token(oldToken.slice(0, -1));
  clients(app.clients);
  return { bytes, app, runtime };
}
function locations(root) {
  if (!path.isAbsolute(root) || path.normalize(root) !== root) fail();
  const base = fs.lstatSync(root);
  if (!base.isDirectory() || base.isSymbolicLink() || ![0, 1000].includes(base.uid) || (base.mode & 0o022)) fail();
  const config = path.join(root, 'config'), state = path.join(root, 'tailscale'), appDir = path.join(root, 'app');
  for (const dir of [config, state, appDir]) directory(dir);
  if (fs.readdirSync(config).sort().join('\0') !== files.toSorted().join('\0')) fail();
  return { config, state };
}
export function inspectGateway({ root = '/data', identity = process, noNewPrivileges = requireNoNewPrivileges } = {}) {
  try {
    guard(identity, noNewPrivileges);
    const { config } = locations(root); const { bytes } = current(config);
    return { event: 'gateway-configuration-hashes', ...Object.fromEntries(bytes.map((value, i) => [fileKeys[i], hash(value)])) };
  } catch { fail(); }
}

// Non-default root/checkpoint/identity are isolated-test injections, never CLI inputs.
export function provisionGateway(raw, { root = '/data', identity = process,
  noNewPrivileges = requireNoNewPrivileges, checkpoint = () => {} } = {}) {
  let lockFd;
  try {
    guard(identity, noNewPrivileges);
    const payload = parseCutover(raw);
    const { config, state } = locations(root);
    const prior = current(config, payload); // validate everything before first write
    const lockFile = path.join(state, 'runtime.lock');
    lockFd = fs.openSync(lockFile, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    const lock = fs.fstatSync(lockFd); fs.fsyncSync(lockFd); fs.closeSync(lockFd); lockFd = undefined; syncDir(state);
    const ownLock = () => {
      const s = fs.lstatSync(lockFile);
      if (!s.isFile() || s.isSymbolicLink() || s.uid !== 1000 || s.nlink !== 1 || s.ino !== lock.ino || s.dev !== lock.dev || (s.mode & 0o077)) fail();
    };
    const attempt = path.join(config, 'gateway-cutover');
    fs.mkdirSync(attempt, { mode: 0o700 });
    const previous = path.join(attempt, 'previous'), next = path.join(attempt, 'next');
    fs.mkdirSync(previous, { mode: 0o700 }); fs.mkdirSync(next, { mode: 0o700 });
    for (let i = 0; i < files.length; i++) write(path.join(previous, files[i]), prior.bytes[i]);
    const newApp = { ...prior.app, upstreamOrigin: `https://${payload.backendHostname}` };
    const newRuntime = { ...prior.runtime, backendIpv4: payload.backendIpv4 };
    parseGatewayConfig(newApp); parseDeploymentConfig(newRuntime); clients(newApp.clients);
    const newBytes = { 'app.json': encode(newApp), 'service-token': Buffer.from(payload.serviceToken + '\n'), 'runtime.json': encode(newRuntime) };
    for (const [name, bytes] of Object.entries(newBytes)) write(path.join(next, name), bytes);
    for (const dir of [previous, next, attempt, config]) syncDir(dir);
    const phase = value => {
      const temporary = path.join(attempt, 'phase-next.json');
      write(temporary, encode({ mode: 'whoop-gateway-backend-cutover', phase: value }));
      fs.renameSync(temporary, path.join(attempt, 'phase.json')); syncDir(attempt);
    };
    phase('prepared'); checkpoint('prepared'); ownLock(); current(config, payload);
    // The provider must already be stopped. The lock also excludes a fresh
    // supervisor, but cannot recall config read by an overlapping old startup.
    fs.renameSync(path.join(config, 'runtime.json'), path.join(previous, 'runtime-active.json'));
    syncDir(config); syncDir(previous); phase('runtime-disabled'); checkpoint('runtime-disabled');
    for (const name of ['app.json', 'service-token']) {
      ownLock(); fs.renameSync(path.join(next, name), path.join(config, name)); syncDir(config);
      checkpoint(name === 'app.json' ? 'app-published' : 'token-published');
    }
    ownLock(); fs.renameSync(path.join(next, 'runtime.json'), path.join(config, 'runtime.json')); syncDir(config);
    checkpoint('runtime-published');
    for (const [name, bytes] of Object.entries(newBytes)) if (hash(read(path.join(config, name))) !== hash(bytes)) fail();
    if (hash(read(path.join(config, 'staging-gateway.json'))) !== payload.expected.stagingMarkerSha256) fail();
    phase('committed'); checkpoint('committed'); ownLock(); fs.unlinkSync(lockFile); syncDir(state);
    return { phase: 'configured-awaiting-clean-redeploy' };
  } catch { fail(); }
  finally { if (lockFd !== undefined) fs.closeSync(lockFd); }
  // Failures before final lock release retain the lock/backups; never auto-retry.
  // A failed directory fsync after unlink can report failure after release, but
  // all committed configuration files were already verified and synchronized.
}
export async function provisionGatewayInput(input, options = {}) {
  try {
    guard(options.identity ?? process, options.noNewPrivileges ?? requireNoNewPrivileges);
    if (input.isTTY) fail();
    let timer; const chunks = []; let size = 0;
    const readInput = (async () => {
      for await (const chunk of input) {
        if (!Buffer.isBuffer(chunk) && !(chunk instanceof Uint8Array)) fail();
        size += chunk.byteLength; if (size > 8192) fail(); chunks.push(Buffer.from(chunk));
      }
      if (!size) fail();
      return json(Buffer.concat(chunks));
    })();
    let raw;
    try { raw = await Promise.race([readInput, new Promise((_, reject) => {
      timer = setTimeout(() => { input.destroy(); reject(new Error('GATEWAY_CONFIGURATION_UNAVAILABLE')); }, 5000);
    })]); } finally { clearTimeout(timer); }
    return provisionGateway(raw, options);
  } catch { fail(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 3 || !['configure-stdin', 'inspect'].includes(process.argv[2]) ||
        Object.keys(process.env).some(key => key !== 'PATH' && !(key === 'UV_USE_IO_URING' && process.env[key] === '0'))) fail();
    if (process.argv[2] === 'inspect') console.log(JSON.stringify(inspectGateway()));
    else {
      await provisionGatewayInput(process.stdin);
      console.log('Gateway configuration prepared; remove bootstrap and perform a clean normal redeploy. No service started.');
    }
    const hold = setInterval(() => {}, 60000);
    for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => clearInterval(hold));
  } catch { console.error('WHOOP gateway configuration unavailable.'); process.exitCode = 1; }
}
