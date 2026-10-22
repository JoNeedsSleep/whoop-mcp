import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { backendDatabaseUri, backendEnvironment, readBackendDatabaseCa } from './config.mjs';
import { startDeployment } from './runtime.mjs';

const HOST = 'db-fixture.railway.internal';
const suffix = '?sslmode=verify-full&sslrootcert=%2Fdata%2Fconfig%2Fdb-ca.pem';
const uri = (host = HOST, password = 'synthetic') => `postgresql://whoop_runtime:${password}@${host}:5432/whoop${suffix}`;
const failure = { message: 'PRIVATE_RUNTIME_UNAVAILABLE' };
const config = { role: 'backend', hostname: 'backend.test-tailnet.ts.net', stateDirectory: '/data/tailscale', appConfigFile: '/data/config/app.json' };
const app = () => ({ DATABASE_HOST: HOST, DATABASE_URL: uri(), ENCRYPTION_KEY: 'synthetic', WHOOP_CLIENT_ID: 'synthetic',
  WHOOP_CLIENT_SECRET: 'synthetic', PUBLIC_BASE_URL: 'https://' + config.hostname, SESSION_SECRET: 'synthetic',
  ALLOWED_WHOOP_USER_ID: '123', GATEWAY_SERVICE_TOKEN_SHA256: 'a'.repeat(64) });
const forbidden = () => assert.fail('unexpected startup action');
const component = () => ({ failed: new Promise(() => {}), close: async () => {} });

test('backend database URI accepts only canonical private host binding and strips config-only host', () => {
  for (const password of ['synthetic', encodeURIComponent('synthetic:@/ ?&+é')]) assert.equal(backendDatabaseUri(uri(HOST, password), HOST), uri(HOST, password));
  const env = backendEnvironment(app(), config.hostname);
  assert.equal(env.DATABASE_URL, uri()); assert.equal(Object.hasOwn(env, 'DATABASE_HOST'), false);
  assert.equal(env.RUN_MIGRATIONS, 'false'); assert.equal(env.BIND_HOST, '127.0.0.1');
});

test('backend database URI rejects alternate destinations, credentials, schemes and every query override', () => {
  const values = [uri('127.0.0.1'), uri('public.example'), uri('other.railway.internal'), uri().replace('postgresql:', 'postgres:'),
    uri().replace(':5432', ''), uri().replace(':5432', ':5433'), uri() + '#fragment', uri() + '&sslmode=no-verify',
    uri().replace('verify-full', 'require'), uri().replace('verify-full', 'disable'), uri().replace('sslmode', '%73slmode'),
    uri().replace('%2Fdata%2Fconfig%2Fdb-ca.pem', '/data/config/db-ca.pem'), uri().replace('db-ca.pem', 'other.pem'),
    uri().replace('?sslmode=verify-full&', '?'), uri().replace('whoop_runtime:', 'whoop%5Fruntime:'),
    uri().replace('/whoop?', '/whoop%2Fother?'), uri(HOST, ''), uri(HOST, '%00'), uri(HOST, '%0A'), uri(HOST, '%zz'),
    uri(HOST, 'syn%74hetic'), uri(HOST, 'a'.repeat(1025)), uri().replace(HOST, HOST.toUpperCase())];
  for (const name of ['ssl', 'sslcert', 'sslkey', 'sslrootcert', 'host', 'hostaddr', 'port', 'user', 'password', 'database', 'uselibpqcompat', 'options']) values.push(uri() + '&' + name + '=override');
  for (const value of values) assert.throws(() => backendDatabaseUri(value, HOST), failure);
  for (const host of ['db.nested.railway.internal', '*.railway.internal', 'db.railway.internal.', '-db.railway.internal', 'db-.railway.internal', 'DB.railway.internal', '127.0.0.1', '', null]) assert.throws(() => backendDatabaseUri(uri(host), host), failure);
});

function caFixture(t) {
  assert(process.env.GATEWAY_TEST_TLS_DIR, 'isolated synthetic TLS fixture required');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'backend-ca-')); fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'ca.pem');
  const ca = fs.readFileSync(path.join(process.env.GATEWAY_TEST_TLS_DIR, 'ca.pem'));
  fs.writeFileSync(file, ca, { mode: 0o600 }); return { dir, file, ca };
}

test('CA reader accepts a private CA bundle and refuses non-CA, key, malformed or oversized content', t => {
  const f = caFixture(t); assert.equal(readBackendDatabaseCa(f.file), f.ca.toString());
  for (const data of [Buffer.alloc(16385, 65), Buffer.from([255, 254]), Buffer.from('secret sentinel'),
    fs.readFileSync(path.join(process.env.GATEWAY_TEST_TLS_DIR, 'server.pem')),
    fs.readFileSync(path.join(process.env.GATEWAY_TEST_TLS_DIR, 'server-key.pem')),
    Buffer.concat([f.ca, Buffer.from('unapproved text')]), Buffer.concat(Array(5).fill(f.ca))]) {
    fs.writeFileSync(f.file, data); assert.throws(() => readBackendDatabaseCa(f.file), failure);
  }
});

test('CA reader rejects public permissions, symlink, hardlink and directory before content use', t => {
  const f = caFixture(t); fs.chmodSync(f.file, 0o644); assert.throws(() => readBackendDatabaseCa(f.file), failure);
  fs.chmodSync(f.file, 0o600); fs.chmodSync(f.dir, 0o755); assert.throws(() => readBackendDatabaseCa(f.file), failure);
  fs.chmodSync(f.dir, 0o700); const other = path.join(f.dir, 'other'); fs.linkSync(f.file, other);
  assert.throws(() => readBackendDatabaseCa(f.file), failure); fs.unlinkSync(other);
  fs.symlinkSync(f.file, other); assert.throws(() => readBackendDatabaseCa(other), failure); fs.unlinkSync(other);
  fs.mkdirSync(other, 0o700); assert.throws(() => readBackendDatabaseCa(other), failure);
});

test('invalid URI and missing CA fail before starting either daemon or backend', async () => {
  const actions = []; const raw = app(); raw.DATABASE_URL += '&sslmode=disable';
  await assert.rejects(startDeployment(config, { readAppConfig: () => raw, readDatabaseCa: () => actions.push('ca'), tailscale: forbidden, backend: forbidden }), failure);
  assert.deepEqual(actions, []);
  await assert.rejects(startDeployment(config, { readAppConfig: app, readDatabaseCa: (...args) => { assert.deepEqual(args, []); throw Error('private CA detail'); }, tailscale: forbidden, backend: forbidden }));
});

test('normal backend checks fixed CA before daemon and child; enrollment never reads database config or CA', async () => {
  const actions = []; const service = await startDeployment(config, { readAppConfig: app,
    readDatabaseCa: (...args) => { assert.deepEqual(args, []); actions.push('ca'); },
    tailscale: async () => { actions.push('daemon'); return component(); }, backend: async env => { actions.push('backend'); assert.equal(env.DATABASE_URL, uri()); return component(); } });
  assert.deepEqual(actions, ['ca', 'daemon', 'backend']); await service.close();
  await startDeployment(config, { enrollmentKey: 'synthetic', readAppConfig: forbidden, readDatabaseCa: forbidden, backend: forbidden, tailscale: async () => component() });
});

test('gateway startup never reads a backend database CA', async () => {
  const raw = { publicOrigin: 'https://gateway.test-tailnet.ts.net', port: 8787, databaseFile: '/data/app/gateway.sqlite', upstreamTokenFile: '/data/config/service-token', upstreamOrigin: 'https://backend.test-tailnet.ts.net' };
  const service = await startDeployment({ ...config, role: 'gateway', hostname: 'gateway.test-tailnet.ts.net', backendIpv4: '100.70.0.1' },
    { readAppConfig: () => raw, readDatabaseCa: forbidden, backend: forbidden, tailscale: async () => component(), gateway: async () => component() });
  await service.close();
});
