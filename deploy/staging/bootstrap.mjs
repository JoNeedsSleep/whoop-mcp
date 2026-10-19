// Explicit staging-only provisioning. No environment secrets, app startup,
// Tailscale enrollment, recursively changed ownership or arbitrary target paths.
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { privateDirectory } from '../railway/config.mjs';
import { assertSyntheticEnvironment, parseStagingConfig } from './service.mjs';
import { emitRuntimeCheck, requireNoNewPrivileges } from './runtime-check.mjs';

const fail = () => { throw new Error('STAGING_PROVISIONING_UNAVAILABLE'); };
const UID = 1000;
const GID = 1000;
const MAX_INPUT = 4096;

// fs/identity/root injection is for isolated unit tests, never CLI input.
export function initializeVolume({ root = '/data', role = 'fixture', filesystem = fs, identity = process } = {}) {
  if (identity.getuid() !== 0 || !path.isAbsolute(root) || path.normalize(root) !== root) fail();
  if (!['fixture', 'gateway'].includes(role)) fail();
  const children = ['config', 'tailscale', ...(role === 'gateway' ? ['app'] : [])];
  const base = filesystem.lstatSync(root);
  if (!base.isDirectory() || base.isSymbolicLink() || base.uid !== 0 || (base.mode & 0o022)) fail();
  const names = filesystem.readdirSync(root);
  if (names.some(name => ![...children, 'lost+found'].includes(name))) fail();
  if (names.includes('lost+found')) {
    const info = filesystem.lstatSync(path.join(root, 'lost+found'));
    if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== 0 || (info.mode & 0o077)) fail();
  }
  // Validate every existing directory before changing any ownership. A repeat
  // is allowed only while these dedicated directories are still empty.
  for (const name of children) {
    if (!names.includes(name)) continue;
    const directory = path.join(root, name);
    const info = filesystem.lstatSync(directory);
    if (!info.isDirectory() || info.isSymbolicLink() || ![0, UID].includes(info.uid) ||
        (info.mode & 0o777) !== 0o700 || filesystem.readdirSync(directory).length) fail();
  }
  for (const name of children) {
    const directory = path.join(root, name);
    if (!names.includes(name)) filesystem.mkdirSync(directory, { mode: 0o700 });
    filesystem.chownSync(directory, UID, GID);
  }
}

export async function readProvisioningJson(input, { timeoutMs = 5000 } = {}) {
  if (input.isTTY) fail();
  let timer;
  const read = (async () => {
    const chunks = []; let size = 0;
    for await (const chunk of input) {
      if (!Buffer.isBuffer(chunk) && !(chunk instanceof Uint8Array)) fail();
      size += chunk.byteLength;
      if (size > MAX_INPUT) fail();
      chunks.push(Buffer.from(chunk));
    }
    if (!size) fail();
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
  })();
  try {
    return await Promise.race([read, new Promise((_, reject) => {
      timer = setTimeout(() => { input.destroy(); reject(new Error('STAGING_PROVISIONING_UNAVAILABLE')); }, timeoutMs);
    })]);
  } catch { fail(); } finally { clearTimeout(timer); }
}

export function provisionFixture(raw, { root = '/data' } = {}) {
  if (process.getuid() !== UID || process.getgid() !== GID) fail();
  const config = parseStagingConfig(raw);
  const directory = path.join(root, 'config');
  privateDirectory(directory); privateDirectory(path.join(root, 'tailscale'));
  writePrivateExclusive(path.join(directory, 'staging.json'), JSON.stringify(config) + '\n');
}

export function writePrivateExclusive(filename, contents) {
  if (process.getuid() !== UID || process.getgid() !== GID || typeof contents !== 'string' ||
      Buffer.byteLength(contents) > MAX_INPUT || !path.isAbsolute(filename) || path.normalize(filename) !== filename) fail();
  const directory = path.dirname(filename);
  privateDirectory(directory);
  const temporary = path.join(directory, `.provision-${randomBytes(12).toString('hex')}`);
  let fd; let created = false;
  try {
    fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    created = true;
    fs.writeFileSync(fd, contents); fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    // Atomic and exclusive: an existing config, symlink or other entry wins.
    // Runtime starts only after the separately approved normal-start action.
    fs.linkSync(temporary, filename);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    if (created) fs.unlinkSync(temporary);
  }
}

export function holdForProvisioning() {
  if (process.getuid() !== UID || process.getgid() !== GID) fail();
  const timer = setInterval(() => {}, 60000);
  const stop = () => clearInterval(timer);
  process.once('SIGTERM', stop); process.once('SIGINT', stop);
  return stop;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.umask(0o077); requireNoNewPrivileges(); assertSyntheticEnvironment(process.env);
    const args = process.argv.slice(2);
    if (args.length !== 1) fail();
    if (args[0] === 'init-volume') {
      initializeVolume();
      process.setgroups([]); process.setgid(GID); process.setuid(UID);
      emitRuntimeCheck();
      holdForProvisioning();
      console.log('Empty staging volume prepared; non-root provisioning hold. No service or enrollment started.');
    } else if (args[0] === 'hold') {
      holdForProvisioning();
      console.log('Staging provisioning hold. No service or enrollment started.');
    } else if (args[0] === 'configure-fixture') {
      provisionFixture(await readProvisioningJson(process.stdin));
      console.log('Synthetic staging configuration created.');
    } else fail();
  } catch { console.error('Staging provisioning unavailable.'); process.exitCode = 1; }
}
