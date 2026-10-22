import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { guardInvocation, parseEnvelope, parseState, validateTls, validateVolumeRoot } from './provision.mjs';

const identity = (uid = 999) => ({ getuid: () => uid, getgid: () => uid, geteuid: () => uid, getegid: () => uid });
const environment = { PATH: '/usr/local/bin:/usr/lib/postgresql/17/bin:/usr/bin:/bin', HOME: '/tmp', TMPDIR: '/tmp', LANG: 'C' };
const failure = error => error instanceof Error && error.message === 'POSTGRES_PROVISION_UNAVAILABLE';
const tlsDir = process.env.GATEWAY_TEST_TLS_DIR;
const fixture = () => ({ version: 1, host: 'whoop-db.railway.internal',
  caCertificate: fs.readFileSync(tlsDir + '/ca.pem', 'utf8'),
  serverCertificate: fs.readFileSync(tlsDir + '/server.pem', 'utf8'), serverKey: fs.readFileSync(tlsDir + '/server-key.pem', 'utf8'),
  runtimePassword: 'a'.repeat(64), migrationPassword: 'b'.repeat(64) });
const volumeRoot = '/var/lib/postgresql/data';
const preparedNames = ['pgdata', 'config', 'tls', 'run', 'provision-state.json'];
function volumeFixture({ phase = 'init', names = ['lost+found'], root = {}, lost = {}, opened = {}, after = {}, children = [] } = {}) {
  const stat = (owner, mode, extra = {}) => ({ uid: owner, gid: owner, mode, dev: 1, ino: 2,
    isDirectory: () => true, isSymbolicLink: () => false, ...extra });
  const rootStat = stat(phase === 'init' ? 0 : 999, phase === 'init' ? 0o755 : 0o700, root);
  const lostStat = stat(0, 0o700, lost); const calls = []; let lostReads = 0;
  return { calls, filesystem: {
    lstatSync(filename) {
      calls.push(['lstat', filename]);
      if (filename === volumeRoot) return rootStat;
      assert.equal(filename, volumeRoot + '/lost+found');
      return ++lostReads === 1 ? lostStat : { ...lostStat, ...after };
    },
    readdirSync(filename) {
      calls.push(['readdir', filename]);
      if (filename === volumeRoot) return [...names];
      assert.equal(filename, '/proc/self/fd/42'); return [...children];
    },
    openSync(filename, flags) {
      calls.push(['open', filename]); assert.equal(filename, volumeRoot + '/lost+found');
      assert.equal(flags, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW); return 42;
    },
    fstatSync(fd) { calls.push(['fstat', fd]); assert.equal(fd, 42); return { ...lostStat, ...opened }; },
    closeSync(fd) { calls.push(['close', fd]); assert.equal(fd, 42); },
  } };
}

test('root init allows only an empty volume or exact protected empty lost+found', () => {
  for (const names of [[], ['lost+found']]) for (const mode of [0o700, 0o755]) {
    const fixture = volumeFixture({ names, root: { mode } });
    validateVolumeRoot('init', fixture);
    assert.equal(fixture.calls.filter(([call]) => call === 'open').length, names.length);
    assert.equal(fixture.calls.filter(([call]) => call === 'close').length, names.length);
  }
  for (const names of [['other'], ['lost+found', 'other'], ['pgdata'], ['lost+found', '.provision.lock'],
    ['lost+found', ...preparedNames]]) {
    const fixture = volumeFixture({ names });
    assert.throws(() => validateVolumeRoot('init', fixture), failure);
    assert.equal(fixture.calls.some(([call]) => call === 'open'), false);
  }
});
test('unsafe root or lost+found metadata is refused before opening or any writes', () => {
  for (const field of ['root', 'lost']) {
    const invalid = [{ uid: 999 }, { gid: 999 }, { isDirectory: () => false }, { isSymbolicLink: () => true },
      { mode: 0o777 }, { mode: 0o1700 }, { mode: 0o2700 }, { mode: 0o4700 }];
    if (field === 'lost') invalid.push({ mode: 0o755 }, { mode: 0o750 });
    for (const metadata of invalid) {
      const fixture = volumeFixture({ [field]: metadata });
      assert.throws(() => validateVolumeRoot('init', fixture), failure);
      assert.equal(fixture.calls.some(([call]) => call === 'open'), false);
    }
  }
});
test('nonempty and replaced lost+found fail and close the nofollow directory descriptor', () => {
  for (const options of [{ children: ['recovered-file'] }, { opened: { ino: 3 } }, { opened: { dev: 3 } },
    { opened: { uid: 999 } }, { after: { ino: 3 } }, { after: { mode: 0o755 } }]) {
    const fixture = volumeFixture(options);
    assert.throws(() => validateVolumeRoot('init', fixture), failure);
    assert.equal(fixture.calls.filter(([call]) => call === 'close').length, 1);
  }
});
test('all later phases retain exact root entries and inspect only protected lost+found metadata', () => {
  for (const phase of ['configure', 'enable', 'finalize']) {
    for (const names of [preparedNames, [...preparedNames, 'lost+found']]) {
      const fixture = volumeFixture({ phase, names, children: ['cannot-be-read-by-uid999'] });
      validateVolumeRoot(phase, fixture);
      assert.equal(fixture.calls.some(([call]) => call === 'open'), false);
      assert.deepEqual(fixture.calls.filter(([call]) => call === 'readdir'), [['readdir', volumeRoot]]);
    }
    for (const options of [{ names: [...preparedNames, 'lost+found', 'other'] }, { names: ['lost+found'] },
      { root: { uid: 0 } }, { root: { mode: 0o755 } }, { lost: { uid: 999 } }, { lost: { gid: 999 } },
      { lost: { mode: 0o755 } }, { lost: { isSymbolicLink: () => true } }, { lost: { isDirectory: () => false } }]) {
      const fixture = volumeFixture({ phase, names: [...preparedNames, 'lost+found'], ...options });
      assert.throws(() => validateVolumeRoot(phase, fixture), failure);
      assert.equal(fixture.calls.some(([call]) => call === 'open'), false);
    }
  }
});
test('volume validation exposes only fixed errors and no alternate phase', () => {
  assert.throws(() => validateVolumeRoot('unknown', { filesystem: new Proxy({}, { get() { assert.fail('filesystem read'); } }) }), failure);
  assert.throws(() => validateVolumeRoot('init', { filesystem: { lstatSync() { throw new Error('private filesystem details'); } } }), failure);
});

test('identity and kernel checks precede any environment value access', () => {
  const env = Object.defineProperty({}, 'SECRET', { enumerable: true, get() { assert.fail('read secret'); } });
  assert.throws(() => guardInvocation('configure', { identity: identity(0), environment: env, guard() { assert.fail('kernel after wrong identity'); } }), failure);
  assert.throws(() => guardInvocation('configure', { identity: identity(), environment: env, guard() { throw new Error('kernel blocked'); } }), /kernel blocked/);
  assert.throws(() => guardInvocation('configure', { identity: identity(), environment: env, guard() {} }), failure);
});
test('only explicit root init and nonroot remaining phases with cleared environment', () => {
  guardInvocation('init', { identity: identity(0), environment, guard() {} });
  for (const phase of ['configure', 'enable', 'finalize']) guardInvocation(phase, { identity: identity(), environment, guard() {} });
  for (const phase of ['init', 'start', 'migrate', '', null]) assert.throws(() => guardInvocation(phase, { identity: identity(), environment, guard() {} }), failure);
  for (const key of ['NODE_OPTIONS', 'POSTGRES_PASSWORD', 'WHOOP_STAGING_BOOTSTRAP', 'PGPASSWORD', 'HTTP_PROXY'])
    assert.throws(() => guardInvocation('configure', { identity: identity(), environment: { ...environment, [key]: 'sentinel' }, guard() {} }), failure);
  guardInvocation('configure', { identity: identity(), environment: { ...environment, UV_USE_IO_URING: '0' }, guard() {} });
  assert.throws(() => guardInvocation('configure', { identity: identity(), environment: { ...environment, UV_USE_IO_URING: '1' }, guard() {} }), failure);
});
test('effective identity mismatch and wrong fixed environment values fail', () => {
  for (const field of ['getuid', 'getgid', 'geteuid', 'getegid'])
    assert.throws(() => guardInvocation('configure', { identity: { ...identity(), [field]: () => 0 }, environment, guard() {} }), failure);
  assert.throws(() => guardInvocation('configure', { identity: identity(), environment: { ...environment, PATH: '/tmp' }, guard() {} }), failure);
});
test('state parser recreates only exact phase metadata', () => {
  const initial = { version: 1, phase: 'initialized', host: null };
  assert.deepEqual(parseState(initial), initial); assert.notEqual(parseState(initial), initial);
  for (const phase of ['configuring', 'configured', 'enabling', 'enabled', 'finalizing', 'finalized'])
    assert.deepEqual(parseState({ version: 1, phase, host: 'whoop-db.railway.internal' }), { version: 1, phase, host: 'whoop-db.railway.internal' });
  for (const raw of [{ ...initial, secret: 'sentinel' }, { ...initial, phase: 'ready' }, { ...initial, host: 'localhost' },
    { version: 1, phase: 'configured', host: 'public.example' }, { version: 1, phase: 'configured', host: null }])
    assert.throws(() => parseState(raw), failure);
});
test('synthetic exact private SAN and matching CA/key validate before secret writes', () => {
  assert(tlsDir, 'Synthetic certificate fixture is required');
  const raw = fixture(); const parsed = parseEnvelope(raw);
  assert.deepEqual(parsed, raw); assert.notEqual(parsed, raw);
  assert.deepEqual(validateTls(raw.host, raw.caCertificate, raw.serverCertificate, raw.serverKey),
    { host: raw.host, caCertificate: raw.caCertificate, serverCertificate: raw.serverCertificate, serverKey: raw.serverKey });
});
test('unknown fields, weak/coercible/equal passwords and invalid host fail', () => {
  const raw = fixture();
  for (const bad of [{ ...raw, sql: 'SELECT 1' }, { ...raw, runtimePassword: [raw.runtimePassword] },
    { ...raw, migrationPassword: raw.runtimePassword }, { ...raw, migrationPassword: 'short' },
    { ...raw, runtimePassword: "x';ALTER ROLE whoop_runtime SUPERUSER;--" }, { ...raw, host: 'host.example' },
    { ...raw, host: '*.railway.internal' }, { ...raw, host: 'host.other.railway.internal' }])
    assert.throws(() => parseEnvelope(bad), failure);
});
test('wrong CA/host, CA-as-leaf, expired certificates and extra PEM content fail', () => {
  const raw = fixture();
  for (const bad of [{ ...raw, caCertificate: fs.readFileSync(tlsDir + '/wrong-ca.pem', 'utf8') },
    { ...raw, host: 'other.railway.internal' }, { ...raw, serverCertificate: raw.caCertificate },
    { ...raw, serverCertificate: raw.serverCertificate + raw.caCertificate }, { ...raw, serverKey: raw.serverKey + 'sentinel' }])
    assert.throws(() => parseEnvelope(bad), failure);
  assert.throws(() => parseEnvelope(raw, Date.now() + 7 * 86400000), failure);
  assert.throws(() => parseEnvelope(raw, 1), failure);
});
