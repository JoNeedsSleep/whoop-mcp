// Requires the approved disposable PostgreSQL/TLS fixture. No real credentials.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import tls from 'node:tls';
import pg from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { runMigration } from './migrate.mjs';

const ca = fs.readFileSync(path.join(process.env.GATEWAY_TEST_TLS_DIR, 'ca.pem'), 'utf8');
const password = 'synthetic-migration-test-only';
const base = { host: '127.0.0.1', port: 5432, user: 'migration_login', password, ownerRole: 'migration_owner', caCertificate: ca };
const connection = { host: base.host, port: base.port, user: 'whoop_test', password,
  ssl: { rejectUnauthorized: true, ca, checkServerIdentity: (_hostname, certificate) => tls.checkServerIdentity('127.0.0.1', certificate) },
  connectionTimeoutMillis: 3000, max: 1 };
const admin = new pg.Pool({ ...connection, database: 'whoop_test' });
const directory = fileURLToPath(new URL('../../drizzle/', import.meta.url));
const failure = { message: 'MIGRATION_UNAVAILABLE' };
let index = 0;
const options = (config, extra = {}) => ({ readConfig: () => config, environment: {}, ...extra });

before(async () => {
  assert.equal(process.getuid(), 1000, 'run only in the approved isolated fixture');
  const result = await admin.query('SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()');
  assert.equal(result.rows[0].ssl, true);
  await admin.query('CREATE ROLE migration_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS');
  await admin.query(`CREATE ROLE migration_login LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${password}'`);
  await admin.query('GRANT migration_owner TO migration_login');
});
after(async () => { await admin.end(); });

async function fixture(t) {
  const database = 'migration_case_' + (++index);
  await admin.query(`CREATE DATABASE ${database}`);
  const inspect = new pg.Pool({ ...connection, database });
  t.after(async () => {
    await inspect.end();
    // pg.Pool.end can resolve before PostgreSQL observes the socket closing.
    // Do not terminate that closing TLS session with DROP DATABASE ... FORCE.
    for (let attempt = 0; attempt < 100; attempt++) {
      const active = await admin.query('SELECT count(*)::integer AS count FROM pg_stat_activity WHERE datname = $1', [database]);
      if (active.rows[0].count === 0) { await admin.query(`DROP DATABASE ${database}`); return; }
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.fail('fixture database still has sessions after pool shutdown');
  });
  // Drizzle's CREATE SCHEMA IF NOT EXISTS checks database CREATE even when the
  // schema already exists. This is scoped to this disposable database; the
  // role retains NOCREATEDB and the application role receives no such grant.
  await inspect.query(`GRANT CREATE ON DATABASE ${database} TO migration_owner`);
  await inspect.query('REVOKE ALL ON SCHEMA public FROM PUBLIC');
  await inspect.query('ALTER SCHEMA public OWNER TO migration_owner');
  await inspect.query('CREATE SCHEMA drizzle AUTHORIZATION migration_owner');
  return { config: { ...base, database }, inspect };
}

async function noMigrationSessions(inspect) {
  for (let attempt = 0; attempt < 100; attempt++) {
    const result = await inspect.query("SELECT count(*)::integer AS count FROM pg_stat_activity WHERE datname = current_database() AND application_name = 'whoop-migration-only'");
    if (result.rows[0].count === 0) return;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.fail('migration session did not close within fixture bound');
}

test('strict TLS migration applies exact three ledger entries, owns all tables, repeats safely and closes sessions', async t => {
  const f = await fixture(t);
  const privileges = await f.inspect.query("SELECT rolcreatedb, has_database_privilege('migration_owner', current_database(), 'CREATE') AS fixture_create, has_database_privilege('migration_owner', 'postgres', 'CREATE') AS other_create FROM pg_roles WHERE rolname = 'migration_owner'");
  assert.deepEqual(privileges.rows, [{ rolcreatedb: false, fixture_create: true, other_create: false }]);
  for (let attempt = 0; attempt < 2; attempt++) assert.deepEqual(await runMigration(options(f.config)), { completed: true });
  fs.writeFileSync('/migration/config.json', JSON.stringify(f.config), { mode: 0o600, flag: 'wx' });
  try {
    const cli = spawnSync(process.execPath, [fileURLToPath(new URL('./migrate.mjs', import.meta.url))], {
      env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', NODE_ENV: 'production' }, encoding: 'utf8', timeout: 10000,
    });
    assert.equal(cli.status, 0); assert.equal(cli.stdout, 'Migrations completed.\n'); assert.equal(cli.stderr, '');
  } finally { fs.unlinkSync('/migration/config.json'); }
  await f.inspect.query(`REVOKE CREATE ON DATABASE ${f.config.database} FROM migration_owner`);
  assert.equal((await f.inspect.query("SELECT has_database_privilege('migration_owner', current_database(), 'CREATE') AS allowed")).rows[0].allowed, false);
  const tables = await f.inspect.query("SELECT tablename, tableowner FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename");
  assert.deepEqual(tables.rows.map(row => row.tablename), ['mcp_tokens', 'oauth_auth_codes', 'oauth_clients', 'pending_authorizations', 'users', 'whoop_tokens']);
  assert(tables.rows.every(row => row.tableowner === 'migration_owner'));
  assert.equal((await f.inspect.query('SELECT count(*)::integer AS count FROM drizzle.__drizzle_migrations')).rows[0].count, 3);
  await noMigrationSessions(f.inspect);
  assert.equal((await f.inspect.query("SELECT is_nullable FROM information_schema.columns WHERE table_name = 'mcp_tokens' AND column_name = 'expires_at'")).rows[0].is_nullable, 'NO');
});

test('untrusted CA, wrong hostname and wrong password fail before schema writes', async t => {
  const f = await fixture(t);
  for (const config of [{ ...f.config, caCertificate: null }, { ...f.config, password: 'wrong-synthetic-password' }]) {
    await assert.rejects(runMigration(options(config)), failure);
  }
  // Connect to the same live server while retaining the production verifier's
  // configured hostname, so a DNS/IPv6 failure cannot impersonate TLS rejection.
  await assert.rejects(runMigration(options({ ...f.config, host: 'wrong.fixture.test' }, {
    createPool: params => new pg.Pool({ ...params, host: '127.0.0.1' }),
  })), failure);
  assert.equal((await f.inspect.query("SELECT to_regclass('public.users') AS table")).rows[0].table, null);
});

test('a concurrent run refuses advisory lock immediately and original completes; no automatic retry', async t => {
  const f = await fixture(t); let entered; let release;
  const ready = new Promise(resolve => { entered = resolve; });
  const hold = new Promise(resolve => { release = resolve; });
  const first = runMigration(options(f.config, { migrate: async client => { entered(); await hold; await migrate(drizzle(client), { migrationsFolder: directory }); } }));
  try { await ready; await assert.rejects(runMigration(options(f.config)), failure); }
  finally { release(); }
  assert.deepEqual(await first, { completed: true });
});

test('migration transaction failure rolls back application DDL and permits a clean later run', async t => {
  const f = await fixture(t);
  await assert.rejects(runMigration(options(f.config, { migrate: async client => {
    await client.query('BEGIN'); await client.query('CREATE TABLE public.rollback_probe (id integer)');
    await client.query('SELECT nonexistent_migration_test_function()');
  } })), failure);
  assert.equal((await f.inspect.query("SELECT to_regclass('public.rollback_probe') AS table")).rows[0].table, null);
  assert.deepEqual(await runMigration(options(f.config)), { completed: true });
});

test('real Drizzle failure in migration 0001 rolls back migration 0000 and leaves only empty ledger scaffolding', async t => {
  const f = await fixture(t);
  await f.inspect.query('SET ROLE migration_owner; CREATE TABLE public.pending_authorizations (conflict integer); RESET ROLE');
  await assert.rejects(runMigration(options(f.config)), failure);
  await noMigrationSessions(f.inspect);
  assert.equal((await f.inspect.query("SELECT to_regclass('public.users') AS table")).rows[0].table, null);
  assert.equal((await f.inspect.query('SELECT count(*)::integer AS count FROM drizzle.__drizzle_migrations')).rows[0].count, 0);
  await f.inspect.query('DROP TABLE public.pending_authorizations');
  assert.deepEqual(await runMigration(options(f.config)), { completed: true });
});

test('deadline closes active connection; server statement timeout bounds rollback and releases its advisory lock', async t => {
  const f = await fixture(t);
  await assert.rejects(runMigration(options(f.config, { deadlineMs: 150,
    migrate: async client => {
      // Shorten the server bound only in this synthetic fixture. Closing a TCP
      // socket does not itself guarantee instant cancellation of server work.
      await client.query('SET statement_timeout = 300');
      await client.query('BEGIN; CREATE TABLE public.timeout_probe (id integer); SELECT pg_sleep(10)');
    } })), failure);
  await noMigrationSessions(f.inspect);
  assert.equal((await f.inspect.query("SELECT to_regclass('public.timeout_probe') AS table")).rows[0].table, null);
  assert.deepEqual(await runMigration(options(f.config)), { completed: true });
});

test('unreviewed ledger blocks further migrations without modifying existing rows', async t => {
  const f = await fixture(t); await runMigration(options(f.config));
  await f.inspect.query("UPDATE drizzle.__drizzle_migrations SET hash = 'tampered-synthetic-ledger' WHERE id = 1");
  await assert.rejects(runMigration(options(f.config)), failure);
  assert.equal((await f.inspect.query('SELECT hash FROM drizzle.__drizzle_migrations WHERE id = 1')).rows[0].hash, 'tampered-synthetic-ledger');
});
