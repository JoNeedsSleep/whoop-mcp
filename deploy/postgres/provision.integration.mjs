// Explicit disposable-fixture phases, never a production/operator command.
// Same role/TLS assertions as the package fixture, with the actual stdin migration bridge.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import tls from 'node:tls';
import pg from 'pg';
import { Readable } from 'node:stream';
import { migrationFromStdin } from '../migrate/bootstrap.mjs';

const host = 'whoop-db.railway.internal';
const runtimePassword = 'a'.repeat(64);
const migrationPassword = 'b'.repeat(64);
const ca = fs.readFileSync('/work/test-tls/ca.pem', 'utf8');
const stage = process.argv[2];
const ssl = { ca, rejectUnauthorized: true, minVersion: 'TLSv1.2',
  checkServerIdentity: (_hostname, cert) => tls.checkServerIdentity(host, cert) };
const config = (user, overrides = {}) => ({ host, port: 5432, database: 'whoop', user, password: user === 'whoop_migrate' ? migrationPassword : runtimePassword,
  ssl, connectionTimeoutMillis: 3000, query_timeout: 5000, ...overrides });

async function withClient(options, body) {
  const client = new pg.Client(options);
  client.on('error', () => {});
  try { await client.connect(); return await body(client); }
  finally { await client.end(); }
}
async function refused(options, codes = ['28000']) {
  await assert.rejects(withClient(options, () => assert.fail('Unexpected connection')),
    error => codes.includes(error?.code));
}
async function denied(client, sql) { await assert.rejects(client.query(sql), error => error?.code === '42501'); }

const phases = {
  async disabled() {
    await refused(config('whoop_runtime'));
    await refused(config('whoop_migrate'));
  },
  async migrate() {
    await refused(config('whoop_runtime'));
    await withClient(config('whoop_migrate'), async client => {
      const { rows: [row] } = await client.query(`SELECT rolcanlogin,
        rolvaliduntil > now() AS current, rolvaliduntil <= now() + interval '1 hour' AS bounded,
        rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls AS privileged
        FROM pg_roles WHERE rolname = current_user`);
      assert.deepEqual(row, { rolcanlogin: true, current: true, bounded: true, privileged: false });
      await client.query('SET ROLE whoop_owner');
      const { rows: [scope] } = await client.query(`SELECT has_database_privilege(current_user,'whoop','CREATE') AS own,
        has_database_privilege(current_user,'postgres','CREATE') AS other`);
      assert.deepEqual(scope, { own: true, other: false });
    });
    await migrationFromStdin({ input: Readable.from([Buffer.from(JSON.stringify({ host, port: 5432, database: 'whoop', user: 'whoop_migrate',
      password: migrationPassword, ownerRole: 'whoop_owner', caCertificate: ca }))]) });
  },
  async hold() {
    await withClient(config('whoop_migrate'), async client => {
      await client.query('SELECT 1');
      fs.writeFileSync('/work/migrator-held', 'ready', { mode: 0o600, flag: 'wx' });
      const until = Date.now() + 45000;
      while (!fs.existsSync('/work/release-migrator') && Date.now() < until)
        await new Promise(resolve => setTimeout(resolve, 100));
    });
    fs.writeFileSync('/work/migrator-closed', 'closed', { mode: 0o600, flag: 'wx' });
  },
  async runtime() {
    await refused(config('whoop_migrate'), ['28P01', '28000']);
    await withClient(config('whoop_runtime'), async client => {
      assert.equal(client.connection.stream.authorized, true);
      assert.match(client.connection.stream.getProtocol(), /^TLSv1\.[23]$/);
      const { rows: [role] } = await client.query(`SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls AS privileged,
        EXISTS(SELECT 1 FROM pg_auth_members WHERE member=current_user::regrole) AS membership,
        has_database_privilege(current_user,'whoop','CREATE,TEMP') AS db_create,
        has_schema_privilege(current_user,'public','CREATE') AS schema_create,
        has_schema_privilege(current_user,'drizzle','USAGE') AS ledger
        FROM pg_roles WHERE rolname=current_user`);
      assert.deepEqual(role, { privileged: false, membership: false, db_create: false, schema_create: false, ledger: false });
      const id = '00000000-0000-4000-8000-000000000001';
      await client.query('BEGIN');
      try {
        await client.query('INSERT INTO users(id,whoop_user_id) VALUES($1,$2)', [id,'synthetic-only']);
        await client.query(`INSERT INTO whoop_tokens(user_id,access_token_enc,refresh_token_enc,access_token_expires_at,scopes)
          VALUES($1,'synthetic','synthetic',now()+interval '1 hour','[]')`, [id]);
        await client.query(`INSERT INTO mcp_tokens(token_hash,user_id,type,expires_at) VALUES('synthetic',$1,'access',now()+interval '1 hour')`, [id]);
        await client.query(`INSERT INTO oauth_clients(client_id,redirect_uris,metadata) VALUES('synthetic','[]','{}')`);
        await client.query(`INSERT INTO oauth_auth_codes(code_hash,client_id,user_id,redirect_uri,code_challenge,scopes,expires_at)
          VALUES('synthetic','synthetic',$1,'https://synthetic.invalid/','synthetic','[]',now()+interval '1 hour')`, [id]);
        await client.query(`INSERT INTO pending_authorizations(whoop_state,payload,expires_at) VALUES('synthetic','{}',now()+interval '1 hour')`);
        for (const table of ['users','whoop_tokens','mcp_tokens','oauth_clients','oauth_auth_codes','pending_authorizations']) {
          assert.equal((await client.query('SELECT count(*)::int AS n FROM ' + table)).rows[0].n, 1);
          const column = table === 'users' ? 'whoop_user_id' : table === 'whoop_tokens' ? 'access_token_enc' :
            table === 'mcp_tokens' ? 'token_hash' : table === 'oauth_clients' ? 'client_id' : table === 'oauth_auth_codes' ? 'code_hash' : 'whoop_state';
          assert.equal((await client.query('UPDATE ' + table + ' SET ' + column + '=' + column)).rowCount, 1);
        }
        for (const table of ['pending_authorizations','oauth_auth_codes','oauth_clients','mcp_tokens','whoop_tokens','users'])
          assert.equal((await client.query('DELETE FROM ' + table)).rowCount, 1);
      } finally { await client.query('ROLLBACK'); }
      for (const sql of [
        'CREATE SCHEMA forbidden', 'CREATE TABLE public.forbidden(id int)', 'CREATE TEMP TABLE forbidden(id int)',
        'CREATE DATABASE forbidden', 'CREATE ROLE forbidden', 'SET ROLE whoop_owner', 'SET ROLE whoop_admin',
        'SELECT * FROM drizzle.__drizzle_migrations', "INSERT INTO drizzle.__drizzle_migrations(hash,created_at) VALUES('bad',0)",
        'TRUNCATE public.users', "SELECT pg_read_file('/etc/passwd')", "COPY (SELECT 1) TO PROGRAM 'true'",
      ]) await denied(client, sql);
      const { rows } = await client.query(`SELECT table_name,privilege_type,is_grantable FROM information_schema.role_table_grants
        WHERE grantee=current_user AND table_schema='public' ORDER BY table_name,privilege_type`);
      assert.equal(rows.length, 24);
      assert(rows.every(row => ['SELECT','INSERT','UPDATE','DELETE'].includes(row.privilege_type) && row.is_grantable === 'NO'));
    });
  },
  async tls_negative() {
    await withClient(config('whoop_runtime'), client => client.query('SELECT 1'));
    await refused(config('whoop_runtime', { ssl: false }));
    await refused(config('whoop_runtime', { password: 'synthetic-wrong' }), ['28P01']);
    await refused(config('whoop_runtime', { ssl: { ...ssl, ca: fs.readFileSync('/work/test-tls/wrong-ca.pem', 'utf8') } }), ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'SELF_SIGNED_CERT_IN_CHAIN']);
    await refused(config('whoop_runtime', { ssl: { ...ssl, checkServerIdentity: (_hostname, cert) => tls.checkServerIdentity('wrong.railway.internal', cert) } }), ['ERR_TLS_CERT_ALTNAME_INVALID']);
    await refused(config('whoop_admin'));
    await refused(config('whoop_runtime', { database: 'postgres' }));
    await withClient(config('whoop_runtime'), client => client.query('SELECT 1'));
  },
};
try {
  assert.equal(process.getuid(), 1000); assert.equal(process.getgid(), 1000);
  assert(Object.hasOwn(phases, stage));
  await phases[stage]();
  console.log(JSON.stringify({ phase: stage, passed: true }));
} catch {
  console.error(JSON.stringify({ phase: Object.hasOwn(phases, stage) ? stage : 'invalid', passed: false }));
  process.exitCode = 1;
}
