// Temporary backend identity preparation only. No application, database or
// WHOOP API client is imported or started; a clean redeploy is a separate action.
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { exact, privateDirectory, tailnetHostname } from '../railway/config.mjs';
import { startTailscale } from '../railway/tailscale-supervisor.mjs';
import { emitRuntimeCheck, requireNoNewPrivileges } from '../staging/runtime-check.mjs';

export const BOOTSTRAP_VARIABLE = 'WHOOP_BACKEND_IDENTITY_BOOTSTRAP';
const fail = () => { throw new Error('BACKEND_IDENTITY_PROVISIONING_UNAVAILABLE'); };
const privileged = identity => [identity.getuid(), identity.getgid(), identity.geteuid(), identity.getegid()];
function environmentKeys(env, allowBootstrap = false) {
  if (Object.keys(env).some(key => !(allowBootstrap && key === BOOTSTRAP_VARIABLE) &&
      (/^(?:WHOOP_|PG|DATABASE|TS_AUTH)/.test(key) || ['NODE_OPTIONS', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'SSLKEYLOGFILE', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'].includes(key)))) fail();
}
function location(root) { if (!path.isAbsolute(root) || path.normalize(root) !== root) fail(); }

// Injection is solely for isolated unit tests. CLI paths and UIDs are fixed.
export function initializeIdentityVolume({ root = '/data', identity = process, filesystem = fs,
  environment = process.env, noNewPrivileges = requireNoNewPrivileges } = {}) {
  try {
    if (privileged(identity).some(id => id !== 0)) fail();
    noNewPrivileges(); environmentKeys(environment); location(root);
    const base = filesystem.lstatSync(root);
    if (!base.isDirectory() || base.isSymbolicLink() || base.uid !== 0 || (base.mode & 0o022)) fail();
    const names = filesystem.readdirSync(root);
    if (names.some(name => !['config', 'tailscale', 'lost+found'].includes(name))) fail();
    if (names.includes('lost+found')) {
      const info = filesystem.lstatSync(path.join(root, 'lost+found'));
      if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== 0 || (info.mode & 0o077)) fail();
    }
    // Validate all existing paths before the first mkdir/chown. Never recurse,
    // replace an entry, inspect secret contents or alter a populated directory.
    for (const name of ['config', 'tailscale']) {
      if (!names.includes(name)) continue;
      const dir = path.join(root, name); const info = filesystem.lstatSync(dir);
      if (!info.isDirectory() || info.isSymbolicLink() || ![0, 1000].includes(info.uid) ||
          (info.mode & 0o777) !== 0o700 || filesystem.readdirSync(dir).length) fail();
    }
    for (const name of ['config', 'tailscale']) {
      const dir = path.join(root, name);
      if (!names.includes(name)) filesystem.mkdirSync(dir, { mode: 0o700 });
      filesystem.chownSync(dir, 1000, 1000);
    }
  } catch { fail(); }
}

export function parseIdentityProvision(raw) {
  try {
    exact(raw, ['mode', 'identity', 'enrollmentKey']);
    if (raw.mode !== 'whoop-owner-identity-bootstrap') fail();
    exact(raw.identity, ['mode', 'hostname', 'clientId', 'clientSecret']);
    if (raw.identity.mode !== 'whoop-owner-identity') fail();
    tailnetHostname(raw.identity.hostname);
    for (const key of ['clientId', 'clientSecret']) if (typeof raw.identity[key] !== 'string' || !/^[\x21-\x7e]{1,2048}$/.test(raw.identity[key])) fail();
    if (typeof raw.enrollmentKey !== 'string' || !/^tskey-auth-[A-Za-z0-9_-]{20,220}$/.test(raw.enrollmentKey)) fail();
    return structuredClone(raw);
  } catch { fail(); }
}
function writeExclusive(filename, value) {
  const directory = path.dirname(filename); privateDirectory(directory);
  const data = JSON.stringify(value) + '\n'; if (Buffer.byteLength(data) > 8192) fail();
  const temporary = path.join(directory, '.identity-provision-' + randomBytes(12).toString('hex'));
  let fd; let created = false;
  try {
    fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    created = true; fs.writeFileSync(fd, data); fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    fs.linkSync(temporary, filename); // atomic claim; never overwrite a prior attempt
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    if (created) fs.unlinkSync(temporary);
  }
}

export async function provisionIdentity({ env = process.env, identity = process, root = '/data',
  noNewPrivileges = requireNoNewPrivileges, runtimeCheck = emitRuntimeCheck, enroll = startTailscale } = {}) {
  try {
    if (privileged(identity).some(id => id !== 1000)) fail();
    noNewPrivileges(); environmentKeys(env, true); location(root);
    let encoded;
    try { encoded = env[BOOTSTRAP_VARIABLE]; } finally { delete env[BOOTSTRAP_VARIABLE]; }
    if (Object.hasOwn(env, BOOTSTRAP_VARIABLE) || typeof encoded !== 'string' || !encoded.isWellFormed() || Buffer.byteLength(encoded) > 8192) fail();
    const payload = parseIdentityProvision(JSON.parse(encoded));
    process.umask(0o077);
    for (const name of ['config', 'tailscale']) {
      const dir = path.join(root, name); privateDirectory(dir);
      if (fs.readdirSync(dir).length) fail();
    }
    runtimeCheck();
    // The first exclusive file is the one-attempt claim. Any partial failure
    // leaves private evidence and requires operator inspection, never retry.
    writeExclusive(path.join(root, 'config', 'identity.json'), payload.identity);
    writeExclusive(path.join(root, 'config', 'runtime.json'), { role: 'backend', hostname: payload.identity.hostname,
      stateDirectory: '/data/tailscale', appConfigFile: '/data/config/app.json' });
    const node = await enroll({ stateDirectory: path.join(root, 'tailscale'), tag: 'tag:whoop-backend',
      hostname: payload.identity.hostname, port: 8080, enrollmentKey: payload.enrollmentKey });
    await node.close();
    return { phase: 'identity-enrolled-awaiting-clean-redeploy' };
  } catch { fail(); }
}
export async function provisionIdentityInput(input, options = {}) {
  try {
    const identity = options.identity ?? process;
    if (privileged(identity).some(id => id !== 1000) || input.isTTY) fail();
    (options.noNewPrivileges ?? requireNoNewPrivileges)();
    let timer;
    const read = (async () => {
      const chunks = []; let size = 0;
      for await (const chunk of input) {
        if (!Buffer.isBuffer(chunk) && !(chunk instanceof Uint8Array)) fail();
        size += chunk.byteLength; if (size > 8192) fail(); chunks.push(Buffer.from(chunk));
      }
      if (!size) fail();
      return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
    })();
    let encoded;
    try { encoded = await Promise.race([read, new Promise((_, reject) => {
      timer = setTimeout(() => { input.destroy(); reject(new Error('BACKEND_IDENTITY_PROVISIONING_UNAVAILABLE')); }, 5000);
    })]); } finally { clearTimeout(timer); }
    return await provisionIdentity({ ...options, env: { [BOOTSTRAP_VARIABLE]: encoded } });
  } catch { fail(); }
}
function hold() {
  if (privileged(process).some(id => id !== 1000)) fail();
  const timer = setInterval(() => {}, 60000);
  for (const name of ['SIGINT', 'SIGTERM']) process.once(name, () => clearInterval(timer));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 1) fail();
    if (args[0] === 'init-volume') {
      initializeIdentityVolume();
      process.setgroups([]); process.setgid(1000); process.setuid(1000);
      emitRuntimeCheck(); hold();
      console.log('Empty backend identity volume prepared; non-root hold. No service or enrollment started.');
    } else if (args[0] === 'provision-identity-stdin') {
      environmentKeys(process.env);
      await provisionIdentityInput(process.stdin); hold();
      console.log('Backend identity node enrolled; revoke the one-use key, remove bootstrap, and redeploy identity verification. No application or database started.');
    } else fail();
  } catch { console.error('Backend identity provisioning unavailable; inspect the stopped attempt before retrying.'); process.exitCode = 1; }
}
