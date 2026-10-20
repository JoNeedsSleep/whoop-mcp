import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import { EventEmitter } from 'node:events';
import { PassThrough, Readable } from 'node:stream';
import { parseProbeConfig, probeFromStdin, runProbe } from './probe.mjs';

const ca = fs.readFileSync(`${process.env.GATEWAY_TEST_TLS_DIR}/ca.pem`, 'utf8');
const identity = { getuid: () => 1000, geteuid: () => 1000, getgid: () => 1000, getegid: () => 1000 };
const config = { host: 'whoop-db.railway.internal', port: 5432, database: 'whoop', user: 'whoop_runtime',
  password: 'a'.repeat(64), caCertificate: ca };
const base = { identity, environment: {}, noNewPrivileges() {} };
const tables = ['mcp_tokens', 'oauth_auth_codes', 'oauth_clients', 'pending_authorizations', 'users', 'whoop_tokens'];
const crud = ['DELETE', 'INSERT', 'SELECT', 'UPDATE'];
const privileges = [...crud, 'MAINTAIN', 'REFERENCES', 'TRIGGER', 'TRUNCATE'].sort();
const success = { version: 1, event: 'whoop-runtime-database-probe', passed: true, crudPrivileges: 24 };
const input = value => Readable.from([Buffer.from(typeof value === 'string' ? value : JSON.stringify(value))]);
function rows() {
  return [
    [{ one: 1, login: 'whoop_runtime', current: 'whoop_runtime', database: 'whoop', readonly: 'on' }],
    ['whoop_migrate', 'whoop_owner', 'whoop_runtime'].map(rolname => ({ rolname, rolcanlogin: rolname === 'whoop_runtime', privileged: false, membership: false })),
    [{ connect: true, create_temp: false, owner_create: false, migrate_connect: false, owned: false }],
    ['drizzle', 'public'].map(nspname => ({ nspname, owner: 'whoop_owner', usage: nspname === 'public', create: false })),
    tables.map(relname => ({ relname, owner: 'whoop_owner' })),
    tables.flatMap(relname => privileges.map(privilege => ({ relname, privilege, allowed: crud.includes(privilege), grantable: false }))),
    tables.flatMap(table_name => crud.map(privilege_type => ({ table_name, privilege_type, is_grantable: 'NO' }))),
    [{ owner: 'whoop_owner', allowed: false }],
  ];
}
function fixture(results = rows(), change = {}) {
  const state = { queries: [], released: 0, ended: 0, options: null };
  const client = new EventEmitter();
  client.connection = { stream: { authorized: true, getProtocol: () => 'TLSv1.3' } };
  client.query = async (sql, values) => { state.queries.push({ sql, values }); return { rows: results[state.queries.length - 1] }; };
  client.release = destroy => { assert.equal(destroy, true); state.released++; };
  const pool = new EventEmitter(); pool.connect = async () => client; pool.end = async () => { state.ended++; };
  Object.assign(client, change.client); Object.assign(pool, change.pool);
  const createPool = async options => { state.options = options; return pool; };
  return { state, client, pool, createPool };
}

test('valid runtime-only metadata passes all fixed SELECTs and destroys its connection', async () => {
  const f = fixture();
  assert.deepEqual(await runProbe({ ...base, config, createPool: f.createPool }), success);
  assert.equal(f.state.queries.length, 8); assert.equal(f.state.released, 1); assert.equal(f.state.ended, 1);
  assert(f.state.queries.every(({ sql }) => /^SELECT\s/.test(sql)));
  assert(!JSON.stringify(f.state.queries).includes(config.password));
  const options = f.state.options;
  assert.equal(options.host, config.host); assert.equal(options.user, 'whoop_runtime'); assert.equal(options.max, 1);
  assert.equal(options.ssl.rejectUnauthorized, true); assert.equal(options.ssl.ca, ca); assert.equal(options.ssl.minVersion, 'TLSv1.2');
  assert.equal(options.options, '-c default_transaction_read_only=on -c search_path=pg_catalog');
  assert.equal(options.statement_timeout, 3000); assert.equal(options.connectionTimeoutMillis, 5000);
  assert(options.ssl.checkServerIdentity('ignored.example', { subjectaltname: 'DNS:wrong.railway.internal' }) instanceof Error);
});

test('schema and credential configuration cannot select another role, database or public target', () => {
  assert.deepEqual(parseProbeConfig(config), config);
  for (const change of [{ host: 'example.com' }, { host: 'a.b.railway.internal' }, { host: '127.0.0.1' },
    { user: 'whoop_migrate' }, { database: 'postgres' }, { port: 5433 }, { password: 'a'.repeat(63) },
    { caCertificate: null }, { caCertificate: ca + ca }, { sql: 'SELECT 1' }])
    assert.throws(() => parseProbeConfig({ ...config, ...change }), /^Error: DATABASE_PROBE_UNAVAILABLE$/);
  assert.throws(() => parseProbeConfig(config, 0), /DATABASE_PROBE_UNAVAILABLE/);
});

test('privilege drift, incomplete metadata and unexpected rows fail without later queries', async () => {
  const mutations = [
    [0, r => { r[0].readonly = 'off'; }], [0, r => { r[0].current = 'whoop_owner'; }],
    [1, r => { r[0].rolcanlogin = true; }], [1, r => { r[2].privileged = true; }],
    [1, r => { r[2].membership = true; }], [2, r => { r[0].owner_create = true; }],
    [2, r => { r[0].migrate_connect = true; }], [2, r => { r[0].create_temp = true; }],
    [3, r => { r[0].usage = true; }], [3, r => { r[1].create = true; }],
    [4, r => { r[0].owner = 'whoop_runtime'; }], [4, r => { r.push({ relname: 'extra', owner: 'whoop_owner' }); }],
    [5, r => { r[0].allowed = false; }], [5, r => { r.find(x => x.privilege === 'TRUNCATE').allowed = true; }],
    [5, r => { r[0].grantable = true; }], [5, r => { r.pop(); }],
    [6, r => { r[0].is_grantable = 'YES'; }], [6, r => { r[1] = r[0]; }],
    [7, r => { r[0].allowed = true; }], [7, r => { r.pop(); }],
  ];
  for (const [index, mutate] of mutations) {
    const values = rows(); mutate(values[index]); const f = fixture(values);
    await assert.rejects(runProbe({ ...base, config, createPool: f.createPool }), /^Error: DATABASE_PROBE_UNAVAILABLE$/);
    assert.equal(f.state.queries.length, index + 1); assert.equal(f.state.released, 1); assert.equal(f.state.ended, 1);
  }
});

test('unverified TLS and dependency failures are fixed errors with cleanup', async () => {
  const f = fixture(); f.client.connection.stream.authorized = false;
  await assert.rejects(runProbe({ ...base, config, createPool: f.createPool }), /^Error: DATABASE_PROBE_UNAVAILABLE$/);
  assert.equal(f.state.queries.length, 0); assert.equal(f.state.released, 1);
  const bad = fixture(); bad.client.query = async () => { throw Error(config.password); };
  await assert.rejects(runProbe({ ...base, config, createPool: bad.createPool }), /^Error: DATABASE_PROBE_UNAVAILABLE$/);
  assert.equal(bad.state.released, 1); assert.equal(bad.state.ended, 1);
});

test('deadline and cancellation cannot turn a late connection into an observation', async () => {
  const f = fixture(); let connected;
  f.pool.connect = () => new Promise(resolve => { connected = resolve; });
  await assert.rejects(runProbe({ ...base, config, createPool: f.createPool, deadlineMs: 5 }), /^Error: DATABASE_PROBE_UNAVAILABLE$/);
  connected(f.client); await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.queries.length, 0); assert.equal(f.state.released, 1); assert.equal(f.state.ended, 1);
  const g = fixture(); const controller = new AbortController();
  g.client.query = () => new Promise(() => {});
  const pending = runProbe({ ...base, config, createPool: g.createPool, signal: controller.signal });
  await new Promise(resolve => setImmediate(resolve)); controller.abort();
  await assert.rejects(pending, /^Error: DATABASE_PROBE_UNAVAILABLE$/);
  assert.equal(g.state.released, 1); assert.equal(g.state.ended, 1);
});

test('stdin admission checks privilege, NNP, environment and arguments before reading', async () => {
  for (const change of [{ identity: { ...identity, getuid: () => 0 } }, { identity: { ...identity, getegid: () => 0 } },
    { environment: { NODE_OPTIONS: '--inspect' } }, { environment: { UV_USE_IO_URING: '1' } },
    { args: ['sql'] }, { noNewPrivileges() { throw Error('private details'); } }]) {
    const stream = new PassThrough(); let calls = 0;
    await assert.rejects(probeFromStdin({ ...base, ...change, input: stream, probe: async () => { calls++; } }), /^Error: DATABASE_PROBE_UNAVAILABLE$/);
    assert.equal(stream.listenerCount('data'), 0); assert.equal(calls, 0); stream.destroy();
  }
});

test('bounded stdin forwards only validated config and never stores a credential', async () => {
  let calls = 0;
  assert.deepEqual(await probeFromStdin({ ...base, input: input(config), probe: async options => {
    calls++; assert.deepEqual(options.config, config); assert.deepEqual(options.args, []); return success;
  } }), success);
  assert.equal(calls, 1);
  for (const stream of [input('{'), input('x'.repeat(32769)), Readable.from([Buffer.from([0xff])]), input({ ...config, user: 'whoop_admin' })]) {
    await assert.rejects(probeFromStdin({ ...base, input: stream, probe: async () => assert.fail('unexpected pool') }), /^Error: DATABASE_PROBE_UNAVAILABLE$/);
    assert.equal(stream.listenerCount('data'), 0);
  }
  const stalled = new PassThrough();
  await assert.rejects(probeFromStdin({ ...base, input: stalled, timeoutMs: 5 }), /^Error: DATABASE_PROBE_UNAVAILABLE$/);
  stalled.destroy();
  const cancelled = new PassThrough(); const controller = new AbortController();
  const pending = probeFromStdin({ ...base, input: cancelled, signal: controller.signal }); controller.abort();
  await assert.rejects(pending, /^Error: DATABASE_PROBE_UNAVAILABLE$/); cancelled.destroy();
});

test('a cleanup failure never returns the success record', async () => {
  const f = fixture(); f.pool.end = async () => { throw Error('private cleanup details'); };
  await assert.rejects(runProbe({ ...base, config, createPool: f.createPool }), /^Error: DATABASE_PROBE_UNAVAILABLE$/);
});
