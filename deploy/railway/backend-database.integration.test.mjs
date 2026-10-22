import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns';
import net from 'node:net';
import tls from 'node:tls';
import pg from 'pg';
import { sql } from 'drizzle-orm';
import { backendDatabaseUri, readBackendDatabaseCa, BACKEND_DATABASE_CA_FILE } from './config.mjs';

const HOST = 'db-fixture.railway.internal';
const PASSWORD = 'synthetic-runtime-test-only';
const tlsDir = process.env.GATEWAY_TEST_TLS_DIR;
assert(tlsDir, 'isolated synthetic TLS fixture required');
const ca = fs.readFileSync(path.join(tlsDir, 'ca.pem'), 'utf8');
const uri = host => `postgresql://whoop_runtime:${PASSWORD}@${host}:5432/whoop_test?sslmode=verify-full&sslrootcert=%2Fdata%2Fconfig%2Fdb-ca.pem`;
let serial = 0;

function fixture(t) {
  fs.mkdirSync('/data/config', { recursive: true, mode: 0o700 });
  fs.writeFileSync(BACKEND_DATABASE_CA_FILE, ca, { mode: 0o600 });
  fs.chmodSync(BACKEND_DATABASE_CA_FILE, 0o600);
  t.after(() => fs.unlinkSync(BACKEND_DATABASE_CA_FILE));
  const original = dns.lookup; const lookups = [];
  t.mock.method(dns, 'lookup', (hostname, options, callback) => {
    if (typeof options === 'function') { callback = options; options = {}; }
    const allowed = { [HOST]: '127.0.0.1', 'wrong-fixture.railway.internal': '127.0.0.1', 'plain-fixture.railway.internal': '127.0.0.2' };
    if (!Object.hasOwn(allowed, hostname)) return original(hostname, options, callback);
    lookups.push(hostname); const address = allowed[hostname];
    queueMicrotask(() => options?.all ? callback(null, [{ address, family: 4 }]) : callback(null, address, 4));
  });
  return lookups;
}
async function applicationDb(host) {
  const value = backendDatabaseUri(uri(host), host); readBackendDatabaseCa();
  // Execute the previously built, unchanged application Pool construction, not
  // a test-specific replacement TLS configuration. Fresh URL isolates singleton.
  const module = await import(new URL(`../../dist/db/client.js?tls-case=${++serial}`, import.meta.url).href);
  return module.getDb(value);
}
async function close(db) { await db.$client.end(); }
async function prepareRole() {
  const pool = new pg.Pool({ host: '127.0.0.1', port: 5432, database: 'whoop_test', user: 'whoop_test', password: 'synthetic-migration-test-only',
    connectionTimeoutMillis: 3000, ssl: { ca, rejectUnauthorized: true, checkServerIdentity: (_host, cert) => tls.checkServerIdentity('127.0.0.1', cert) } });
  try {
    await pool.query(`CREATE ROLE whoop_runtime LOGIN PASSWORD '${PASSWORD}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT`);
    await pool.query('GRANT CONNECT ON DATABASE whoop_test TO whoop_runtime');
  } finally { await pool.end(); }
}

test('unchanged compiled backend pg Pool verifies private-host SAN, CA and encrypted SCRAM session', { timeout: 10000 }, async t => {
  const lookups = fixture(t); await prepareRole(); const db = await applicationDb(HOST);
  try {
    const response = await db.execute(sql`SELECT current_user AS role, current_database() AS database, ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()`);
    assert.deepEqual(response.rows, [{ role: 'whoop_runtime', database: 'whoop_test', ssl: true }]);
    assert.deepEqual(lookups, [HOST]);
  } finally { await close(db); }
});

test('compiled backend refuses a live server whose SAN does not match its approved private hostname', { timeout: 10000 }, async t => {
  const lookups = fixture(t); const db = await applicationDb('wrong-fixture.railway.internal');
  try { await assert.rejects(db.execute(sql`SELECT 1`), error => error.cause?.code === 'ERR_TLS_CERT_ALTNAME_INVALID'); }
  finally { await close(db); }
  assert.deepEqual(lookups, ['wrong-fixture.railway.internal']);
});

test('compiled backend refuses an untrusted live-server issuer even with a valid private CA file', { timeout: 10000 }, async t => {
  fixture(t); fs.writeFileSync(BACKEND_DATABASE_CA_FILE, fs.readFileSync(path.join(tlsDir, 'other-ca.pem')));
  readBackendDatabaseCa(); const db = await applicationDb(HOST);
  try { await assert.rejects(db.execute(sql`SELECT 1`), error => ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'SELF_SIGNED_CERT_IN_CHAIN'].includes(error.cause?.code)); }
  finally { await close(db); }
});

test('compiled backend refuses PostgreSQL plaintext fallback before sending startup or password', { timeout: 10000 }, async t => {
  fixture(t); const received = []; const sockets = new Set();
  const server = net.createServer(socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket));
    socket.on('data', bytes => { received.push(Buffer.from(bytes)); socket.write('N'); }); });
  await new Promise(resolve => server.listen(5432, '127.0.0.2', resolve));
  const db = await applicationDb('plain-fixture.railway.internal');
  try { await assert.rejects(db.execute(sql`SELECT 1`), error => error.cause?.message === 'The server does not support SSL connections'); }
  finally { await close(db); for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); }
  assert.equal(received.length, 1); assert.equal(received[0].toString('hex'), '0000000804d2162f');
});
