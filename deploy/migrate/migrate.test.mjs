import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseMigrationConfig, runMigration } from './migrate.mjs';
import { readPrivateJson } from '../railway/config.mjs';

const config = { host: 'db.fixture.test', port: 5432, database: 'whoop_fixture', user: 'migration_login',
  password: 'synthetic-password-sentinel', ownerRole: 'migration_owner', caCertificate: null };
const failure = { message: 'MIGRATION_UNAVAILABLE' };
const identity = { getuid: () => 1000, getgid: () => 1000, geteuid: () => 1000, getegid: () => 1000 };
const ledger = [
  { hash: '7845b3ce01a5bbfbbad0af50a48aa73222e37eae05b3eec9b3be4e41790b5671', created_at: '1785498994215' },
  { hash: 'f8c6cab011368359f4b1c834074635f2ab1511222cae17c536693f30225d1d9d', created_at: '1785502357731' },
  { hash: '4b3b433350aa219334e61688c5abf407a1f77e7707b18eef2b66d538259d3a11', created_at: '1792324800000' },
];
function fixture(overrides = {}) {
  const events = []; let done = false;
  const client = { on: () => {}, release: destroy => { assert.equal(destroy, true); events.push('release'); },
    query: async (sql, values) => {
      events.push(sql);
      if (sql.includes('FROM pg_roles')) return { rows: [config.user, config.ownerRole].map(rolname => ({ rolname, rolcanlogin: rolname === config.user,
        rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolbypassrls: false })) };
      if (sql.includes('session_user')) return { rows: [{ login: config.user, current: config.user }] };
      if (sql.includes('pg_namespace')) return { rows: [{ nspname: 'public' }, { nspname: 'drizzle' }] };
      if (sql.includes('pg_try_advisory_lock')) return { rows: [{ acquired: true }] };
      if (sql.includes('to_regclass')) return { rows: [{ ledger: done ? '__drizzle_migrations' : null }] };
      if (sql.startsWith('SELECT hash')) return { rows: ledger };
      return { rows: [] };
    } };
  const pool = { on: () => {}, connect: async () => { events.push('connect'); return client; }, end: async () => { events.push('end'); } };
  const options = { identity, environment: {}, noNewPrivileges: () => events.push('nnp'), readConfig: filename => {
    assert.equal(filename, '/migration/config.json'); events.push('config'); return config; },
    verifyFiles: () => events.push('files'), createPool: async params => { events.push('pool'); pool.config = params; return pool; },
    migrate: async () => { events.push('migrate'); done = true; }, ...overrides };
  return { events, client, pool, options };
}

test('exact structured connection rejects override fields, URLs, unsafe identifiers and disabled TLS options', () => {
  assert.deepEqual(parseMigrationConfig(config), config); assert.notEqual(parseMigrationConfig(config), config);
  for (const raw of [{ ...config, ssl: false }, { ...config, connectionString: 'postgres://secret@other' },
    { ...config, host: '/tmp/socket' }, { ...config, host: 'db:5432' }, { ...config, port: 5433 }, { ...config, user: null },
    { ...config, ownerRole: 'x"; SELECT 1' }, { ...config, ownerRole: config.user }, { ...config, user: 'postgres' },
    { ...config, user: 'pg_read_all_data' }, { ...config, password: '' }, { ...config, caCertificate: 'untrusted text' }]) {
    assert.throws(() => parseMigrationConfig(raw), failure);
  }
});

test('identity, NNP, env and argv fail before private input or pool creation', async () => {
  for (const key of Object.keys(identity)) for (const id of [0, 1001]) {
    const f = fixture({ identity: { ...identity, [key]: () => id } });
    await assert.rejects(runMigration(f.options), failure); assert.deepEqual(f.events, []);
  }
  const f = fixture({ noNewPrivileges: () => { throw Error('private kernel'); } });
  await assert.rejects(runMigration(f.options), failure); assert.deepEqual(f.events, []);
  for (const key of ['WHOOP_CLIENT_SECRET', 'PGHOST', 'PGOPTIONS', 'PGSSLMODE', 'DATABASE_URL', 'NODE_OPTIONS', 'SSLKEYLOGFILE']) {
    const f = fixture({ environment: Object.defineProperty({}, key, { enumerable: true, get() { assert.fail('secret getter read'); } }) });
    await assert.rejects(runMigration(f.options), failure); assert.deepEqual(f.events, ['nnp']);
  }
  const args = fixture({ args: ['/tmp/secret.json'] });
  await assert.rejects(runMigration(args.options), failure); assert.deepEqual(args.events, ['nnp']);
});

test('fixed pool, role, ledger and lock order; success destroys only its own client and ends pool', async () => {
  const f = fixture(); assert.deepEqual(await runMigration(f.options), { completed: true });
  assert.deepEqual(f.events.slice(0, 5), ['nnp', 'config', 'files', 'pool', 'connect']);
  assert(f.events.indexOf('SET ROLE "migration_owner"') < f.events.findIndex(sql => sql.includes('pg_try_advisory_lock')));
  assert(f.events.findIndex(sql => sql.includes('pg_try_advisory_lock')) < f.events.indexOf('migrate'));
  assert.deepEqual(f.events.slice(-2), ['release', 'end']);
  assert.equal(f.pool.config.max, 1); assert.equal(f.pool.config.connectionTimeoutMillis, 5000);
  assert.equal(f.pool.config.statement_timeout, 15000); assert.equal(f.pool.config.lock_timeout, 3000);
  assert.equal(f.pool.config.ssl.rejectUnauthorized, true); assert.equal(f.pool.config.ssl.minVersion, 'TLSv1.2');
  assert.equal(f.pool.config.ssl.checkServerIdentity('attacker.example', { subjectaltname: 'DNS:db.fixture.test' }), undefined);
  assert(f.pool.config.ssl.checkServerIdentity('db.fixture.test', { subjectaltname: 'DNS:attacker.example' }) instanceof Error);
  assert.equal(f.pool.config.connectionString, undefined);
});

test('database role, schema, advisory lock and non-prefix ledger failures prevent migration and close pool', async () => {
  for (const fault of ['role', 'login', 'schema', 'lock', 'ledger']) {
    const f = fixture(); const query = f.client.query;
    f.client.query = async (sql, values) => {
      const response = await query(sql, values);
      if (fault === 'role' && sql.includes('FROM pg_roles')) response.rows[0].rolsuper = true;
      if (fault === 'login' && sql.includes('session_user')) response.rows[0].login = 'other';
      if (fault === 'schema' && sql.includes('pg_namespace')) response.rows.pop();
      if (fault === 'lock' && sql.includes('pg_try_advisory_lock')) response.rows[0].acquired = false;
      if (fault === 'ledger' && sql.includes('to_regclass')) response.rows[0].ledger = '__drizzle_migrations';
      if (fault === 'ledger' && sql.startsWith('SELECT hash')) response.rows = [{ ...ledger[0], hash: 'unreviewed' }];
      return response;
    };
    await assert.rejects(runMigration(f.options), failure);
    assert(!f.events.includes('migrate')); assert.deepEqual(f.events.slice(-2), ['release', 'end']);
  }
});

test('migration/connection failures have fixed errors and close the dedicated pool', async () => {
  const f = fixture({ migrate: async () => { throw Error('database-password-sentinel'); } });
  await assert.rejects(runMigration(f.options), failure); assert.deepEqual(f.events.slice(-2), ['release', 'end']);
  const connection = fixture(); connection.pool.connect = async () => { throw Error('postgres://password-sentinel'); };
  await assert.rejects(runMigration(connection.options), failure); assert.equal(connection.events.at(-1), 'end');
  const release = fixture(); release.client.release = () => { throw Error('private socket'); };
  await assert.rejects(runMigration(release.options), failure); assert.equal(release.events.at(-1), 'end');
});

test('deadline and explicit cancellation destroy client, end pool and reject with fixed error', async () => {
  for (const cancel of [false, true]) {
    const controller = new AbortController();
    const f = fixture({ deadlineMs: 25, signal: controller.signal, migrate: async () => {
      if (cancel) controller.abort(); return new Promise(() => {});
    } });
    await assert.rejects(runMigration(f.options), failure); assert.deepEqual(f.events.slice(-2), ['release', 'end']);
  }
});

test('private file parser errors, unsafe modes and symlinks cannot reach database or leak contents', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'migration-unit-')); fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true })); const file = path.join(dir, 'config.json');
  for (const bytes of ['{"password":"secret-sentinel"', JSON.stringify(config)]) {
    fs.writeFileSync(file, bytes, { mode: 0o600 });
    if (bytes.startsWith('{"host"')) fs.chmodSync(file, 0o644);
    const f = fixture({ readConfig: () => readPrivateJson(file) });
    await assert.rejects(runMigration(f.options), failure); assert(!f.events.includes('pool'));
  }
  fs.chmodSync(file, 0o600); fs.symlinkSync(file, file + '-link');
  await assert.rejects(runMigration(fixture({ readConfig: () => readPrivateJson(file + '-link') }).options), failure);
});

test('actual no-argument CLI rejects inherited credential and never emits its value', () => {
  assert.equal(process.getuid(), 1000, 'run only in approved isolated environment');
  const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url).replace('.test.mjs', '.mjs')], {
    env: { PATH: '/usr/local/bin:/usr/bin:/bin', DATABASE_URL: 'password-sentinel' }, encoding: 'utf8', timeout: 5000,
  });
  assert.equal(child.status, 1); assert.equal(child.stdout, ''); assert.equal(child.stderr, 'Migration unavailable.\n');
});
