// One-time private volume preparation. No HTTP server, Tailscale or caller SQL.
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash, createPrivateKey, X509Certificate, randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const ROOT = '/var/lib/postgresql/data';
const SOURCE = '/opt/whoop-postgres';
const PGDATA = ROOT + '/pgdata';
const STATE = ROOT + '/provision-state.json';
const ENV = Object.freeze({ PATH: '/usr/local/bin:/usr/lib/postgresql/17/bin:/usr/bin:/bin', HOME: '/tmp', TMPDIR: '/tmp', LANG: 'C' });
const PINS = Object.freeze({
  'postgresql.conf.template': '387ce608c87aff8c2671b583ac03a8a3c2923610d3c1adcd8f50e68b3710bbf3',
  'pg_hba.conf': 'f98fe30e1e18b2982f3fbaa5dfd2f20d008c532edce8b8b65d2fa45b45b797c9',
  'pg_ident.conf': '930d43e93b863fda9fdaa1fd8ac073a25a08d7e41b579c977d4f8401531dd562',
  '00-provision.sql': '3f1fa3ae67ffb48ead6c9470a7952d26915863a93ed4f49296317b1c3c6bbf9e',
  '10-enable-migration.sql': '4b74a4a044f4480d5daae1f17aa5aed488b0ca1af8a28399b1862191158abf59',
  '20-finalize.sql': '7f05f8ab483c8da92253d483ec5def28c6a1b5c911f83a3c0e4af3e7a10c889f',
});
const fail = () => { throw new Error('POSTGRES_PROVISION_UNAVAILABLE'); };
const hostValid = value => typeof value === 'string' && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.railway\.internal$/.test(value);
const exact = (raw, keys) => raw && typeof raw === 'object' && !Array.isArray(raw) &&
  Object.keys(raw).length === keys.length && keys.every(key => Object.hasOwn(raw, key));
const hash = value => createHash('sha256').update(value).digest('hex');

function kernelGuard() {
  const fd = fs.openSync('/proc/self/status', fs.constants.O_RDONLY);
  try {
    const bytes = Buffer.alloc(16385); const length = fs.readSync(fd, bytes, 0, bytes.length, 0);
    if (length === bytes.length || !/^NoNewPrivs:\s+1$/m.test(bytes.subarray(0, length).toString())) fail();
  } finally { fs.closeSync(fd); }
}

export function guardInvocation(phase, { identity = process, environment = process.env, guard = kernelGuard } = {}) {
  const required = phase === 'init' ? 0 : 999;
  if (!['init', 'configure', 'enable', 'finalize'].includes(phase) ||
      [identity.getuid(), identity.getgid(), identity.geteuid(), identity.getegid()].some(value => value !== required)) fail();
  guard();
  if (Object.keys(environment).some(key => !(Object.hasOwn(ENV, key) && environment[key] === ENV[key]) &&
      !(key === 'UV_USE_IO_URING' && environment[key] === '0'))) fail();
}

function pem(value, label, maximum) {
  if (typeof value !== 'string' || Buffer.byteLength(value) > maximum ||
      !new RegExp('^-----BEGIN ' + label + '-----\\n[A-Za-z0-9+/=\\r\\n]+-----END ' + label + '-----\\n?$').test(value)) fail();
}
export function validateTls(host, caCertificate, serverCertificate, serverKey, now = Date.now()) {
  try {
    if (!hostValid(host) || !Number.isSafeInteger(now)) fail();
    pem(caCertificate, 'CERTIFICATE', 16384); pem(serverCertificate, 'CERTIFICATE', 16384); pem(serverKey, 'PRIVATE KEY', 8192);
    const ca = new X509Certificate(caCertificate); const cert = new X509Certificate(serverCertificate);
    const key = createPrivateKey(serverKey);
    if (!ca.ca || cert.ca || !cert.verify(ca.publicKey) || !cert.checkPrivateKey(key) ||
        cert.subjectAltName !== 'DNS:' + host || cert.checkHost(host, { subject: 'never', wildcards: false }) !== host ||
        key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails.modulusLength < 2048 || key.asymmetricKeyDetails.modulusLength > 4096 ||
        !cert.keyUsage?.includes('1.3.6.1.5.5.7.3.1') ||
        [ca, cert].some(value => !Number.isFinite(Date.parse(value.validFrom)) || !Number.isFinite(Date.parse(value.validTo)) ||
          Date.parse(value.validFrom) > now || Date.parse(value.validTo) <= now)) fail();
    return { host, caCertificate, serverCertificate, serverKey };
  } catch { fail(); }
}
export function parseEnvelope(raw, now = Date.now()) {
  try {
    if (!exact(raw, ['version', 'host', 'caCertificate', 'serverCertificate', 'serverKey', 'runtimePassword', 'migrationPassword']) || raw.version !== 1 ||
        typeof raw.runtimePassword !== 'string' || typeof raw.migrationPassword !== 'string' ||
        !/^[a-f0-9]{64}$/.test(raw.runtimePassword) || !/^[a-f0-9]{64}$/.test(raw.migrationPassword) || raw.runtimePassword === raw.migrationPassword) fail();
    return { version: 1, ...validateTls(raw.host, raw.caCertificate, raw.serverCertificate, raw.serverKey, now),
      runtimePassword: raw.runtimePassword, migrationPassword: raw.migrationPassword };
  } catch { fail(); }
}
export function parseState(raw) {
  if (!exact(raw, ['version', 'phase', 'host']) || raw.version !== 1 ||
      !['initialized', 'configuring', 'configured', 'enabling', 'enabled', 'finalizing', 'finalized'].includes(raw.phase) ||
      (raw.phase === 'initialized' ? raw.host !== null : !hostValid(raw.host))) fail();
  return { version: 1, phase: raw.phase, host: raw.host };
}
function directory(filename, uid = 999) {
  const st = fs.lstatSync(filename);
  if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== uid || st.gid !== uid || (st.mode & 0o777) !== 0o700) fail();
}
function readFile(filename, maximum, uid = 999, privateFile = true) {
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1 || st.uid !== uid || st.size < 1 || st.size > maximum || (privateFile && (st.mode & 0o777) !== 0o600)) fail();
    const data = Buffer.alloc(maximum + 1); let length = 0;
    while (length < data.length) { const read = fs.readSync(fd, data, length, data.length - length, null); if (read === 0) break; length += read; }
    if (length !== st.size || length > maximum) fail();
    return new TextDecoder('utf-8', { fatal: true }).decode(data.subarray(0, length));
  } finally { fs.closeSync(fd); }
}
function absent(filename) {
  try { fs.lstatSync(filename); return false; } catch (error) { if (error?.code === 'ENOENT') return true; throw error; }
}
function entries(filename, expected) {
  const names = fs.readdirSync(filename).sort();
  if (names.length !== expected.length || names.some((name, index) => name !== [...expected].sort()[index])) fail();
}
function exclusive(filename, value) {
  const fd = fs.openSync(filename, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, value); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function stateWrite(value, initial = false) {
  const text = JSON.stringify(parseState(value)) + '\n';
  if (initial) exclusive(STATE, text);
  else {
    const temp = ROOT + '/.state-' + randomBytes(12).toString('hex');
    exclusive(temp, text); fs.renameSync(temp, STATE);
  }
  const fd = fs.openSync(ROOT, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function checkedSources() {
  const data = {};
  for (const [name, digest] of Object.entries(PINS)) {
    data[name] = readFile(SOURCE + '/' + name, 32768, 0, false);
    if (hash(data[name]) !== digest) fail();
  }
  return data;
}
async function boundedInput(input, maximum) {
  if (input.isTTY) fail();
  let size = 0; const chunks = [];
  const timer = setTimeout(() => input.destroy(new Error('POSTGRES_PROVISION_UNAVAILABLE')), 5000);
  try {
    for await (const chunk of input) { size += chunk.length; if (size > maximum) fail(); chunks.push(chunk); }
    return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
  } finally { clearTimeout(timer); }
}

export async function runProvision(phase, { input = process.stdin } = {}) {
  guardInvocation(phase); process.umask(0o077);
  const sources = checkedSources(); let lock; let lockStat; let started = false;
  let cancel; let childUnconfirmed = false;
  const interrupted = () => { cancel?.(); };
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, interrupted);
  const command = (binary, args, data, timeout = 15000) => new Promise((resolve, reject) => {
    let size = 0; const chunks = []; let child; let timer; let killTimer; let complete = false; let failed = false;
    const finish = code => {
      if (complete) return; complete = true; clearTimeout(timer); clearTimeout(killTimer);
      if (failed || code !== 0) reject(new Error('POSTGRES_PROVISION_UNAVAILABLE'));
      else resolve(Buffer.concat(chunks).toString('utf8'));
    };
    const unavailable = () => {
      if (complete || failed) return; failed = true; clearTimeout(timer);
      if (!child?.pid) { finish(1); return; }
      child.kill('SIGKILL');
      // Confirm child exit before releasing the volume lock. Never call a kill
      // request proof of termination; an unresolved child preserves the lock.
      killTimer = setTimeout(() => { childUnconfirmed = true; finish(1); }, 2000);
    };
    cancel = unavailable;
    try {
      child = spawn(binary, args, { env: ENV, stdio: ['pipe', 'pipe', 'pipe'] });
      for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => { size += chunk.length; if (size > 65536) unavailable(); else if (stream === child.stdout) chunks.push(chunk); });
      child.on('error', unavailable); child.stdin.on('error', () => {});
      child.on('close', finish);
      timer = setTimeout(unavailable, timeout); child.stdin.end(data);
    } catch { unavailable(); }
  });
  const ctl = action => command('/usr/lib/postgresql/17/bin/pg_ctl', ['-D', PGDATA, '-l', '/tmp/provision-postgres.log', '-w', '-t', '10', '-m', 'fast',
    '-o', '-c config_file=/var/lib/postgresql/data/config/postgresql.conf -c listen_addresses=', action]);
  const sql = (database, value, file = false) => command('/usr/lib/postgresql/17/bin/psql', ['-X', '-qAt', '-h', ROOT + '/run', '-U', 'whoop_admin',
    '-d', database, '-v', 'ON_ERROR_STOP=1', ...(file ? ['-f', SOURCE + '/' + value] : [])], file ? undefined : value);
  try {
    if (phase === 'init') {
      // No input read in this branch. Reject every existing file/directory.
      const st = fs.lstatSync(ROOT);
      if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== 0 || fs.readdirSync(ROOT).length !== 0) fail();
      lock = fs.openSync(ROOT + '/.provision.lock', fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      lockStat = fs.fstatSync(lock); fs.fchownSync(lock, 999, 999);
      for (const name of ['pgdata', 'config', 'tls', 'run']) { fs.mkdirSync(ROOT + '/' + name, { mode: 0o700 }); fs.chownSync(ROOT + '/' + name, 999, 999); }
      fs.chmodSync(ROOT, 0o700); fs.chownSync(ROOT, 999, 999);
      process.setgroups([]); process.setgid(999); process.setuid(999);
      guardInvocation('configure');
      await command('/usr/lib/postgresql/17/bin/initdb', ['-D', PGDATA, '-U', 'whoop_admin', '--encoding=UTF8', '--locale=C',
        '--auth-local=peer', '--auth-host=reject', '--data-checksums'], undefined, 30000);
      stateWrite({ version: 1, phase: 'initialized', host: null }, true);
      return { phase: 'initialized' };
    }
    for (const name of ['', '/pgdata', '/config', '/tls', '/run']) directory(ROOT + name);
    entries(ROOT, ['pgdata', 'config', 'tls', 'run', 'provision-state.json']);
    entries(ROOT + '/run', []);
    lock = fs.openSync(ROOT + '/.provision.lock', fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    lockStat = fs.fstatSync(lock);
    if (readFile(PGDATA + '/PG_VERSION', 8) !== '17\n' || !absent(PGDATA + '/postmaster.pid')) fail();
    const state = parseState(JSON.parse(readFile(STATE, 1024)));
    if (state.phase !== ({ configure: 'initialized', enable: 'configured', finalize: 'enabled' })[phase]) fail();
    let envelope; let host = state.host;
    if (phase === 'configure') {
      if (fs.readdirSync(ROOT + '/config').length || fs.readdirSync(ROOT + '/tls').length) fail();
      cancel = () => input.destroy(new Error('POSTGRES_PROVISION_UNAVAILABLE'));
      envelope = parseEnvelope(JSON.parse(await boundedInput(input, 32768))); host = envelope.host;
      stateWrite({ version: 1, phase: 'configuring', host });
      exclusive(ROOT + '/tls/server.pem', envelope.serverCertificate);
      exclusive(ROOT + '/tls/server-key.pem', envelope.serverKey);
      exclusive(ROOT + '/tls/ca.pem', envelope.caCertificate);
      exclusive(ROOT + '/config/postgresql.conf', sources['postgresql.conf.template'].replaceAll('@DATABASE_HOST@', host));
    } else {
      entries(ROOT + '/config', ['postgresql.conf']);
      entries(ROOT + '/tls', ['ca.pem', 'server.pem', 'server-key.pem']);
      cancel = () => input.destroy(new Error('POSTGRES_PROVISION_UNAVAILABLE'));
      if (await boundedInput(input, 0) !== '') fail();
      validateTls(host, readFile(ROOT + '/tls/ca.pem', 16384), readFile(ROOT + '/tls/server.pem', 16384), readFile(ROOT + '/tls/server-key.pem', 8192));
      if (readFile(ROOT + '/config/postgresql.conf', 16384) !== sources['postgresql.conf.template'].replaceAll('@DATABASE_HOST@', host)) fail();
      stateWrite({ version: 1, phase: phase === 'enable' ? 'enabling' : 'finalizing', host });
    }
    const log = fs.openSync('/tmp/provision-postgres.log', fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW, 0o600);
    try {
      const st = fs.fstatSync(log);
      if (!st.isFile() || st.nlink !== 1 || st.uid !== 999 || (st.mode & 0o777) !== 0o600) fail();
    } finally { fs.closeSync(log); }
    // A start timeout is ambiguous; always attempt bounded shutdown afterward.
    started = true; await ctl('start');
    if (await sql('postgres', "SELECT current_user || '|' || current_setting('listen_addresses');") !== 'whoop_admin|\n') fail();
    if (phase === 'configure') {
      await sql('postgres', '00-provision.sql', true);
      // Exactly 64 lowercase hex characters per password; neither can inject SQL.
      // The plaintext exists only in the private pipe and server memory, not argv.
      await sql('whoop', `ALTER ROLE whoop_migrate PASSWORD '${envelope.migrationPassword}'; ALTER ROLE whoop_runtime PASSWORD '${envelope.runtimePassword}';`);
      envelope = undefined;
    } else await sql('whoop', phase === 'enable' ? '10-enable-migration.sql' : '20-finalize.sql', true);
    await ctl('stop'); started = false;
    const done = ({ configure: 'configured', enable: 'enabled', finalize: 'finalized' })[phase];
    stateWrite({ version: 1, phase: done, host });
    return { phase: done };
  } catch { fail(); }
  finally {
    try { if (started) { await ctl('stop'); started = false; } }
    finally {
      for (const signal of ['SIGINT', 'SIGTERM']) process.removeListener(signal, interrupted);
      try {
        if (lock !== undefined) {
          fs.closeSync(lock);
          if (started || childUnconfirmed) fail();
          const current = fs.lstatSync(ROOT + '/.provision.lock');
          if (current.dev !== lockStat.dev || current.ino !== lockStat.ino) fail();
          fs.unlinkSync(ROOT + '/.provision.lock');
        }
      } catch { fail(); }
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const watchdog = setTimeout(() => { console.error('PostgreSQL preparation unavailable.'); process.exit(1); }, 90000);
  try {
    if (process.argv.length !== 3) fail();
    await runProvision(process.argv[2]); clearTimeout(watchdog);
    console.log('PostgreSQL preparation phase completed.');
    // Provider-safe inert success: no listener, no automatic phase/restart loop.
    setInterval(() => {}, 3600000);
    for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => process.exit(0));
  } catch { clearTimeout(watchdog); console.error('PostgreSQL preparation unavailable.'); process.exitCode = 1; }
}
