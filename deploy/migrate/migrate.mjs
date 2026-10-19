// One-off migration process. Never imports the application or any transport.
import fs from 'node:fs';
import path from 'node:path';
import tls from 'node:tls';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readPrivateJson } from '../railway/config.mjs';
import { requireNoNewPrivileges } from '../staging/runtime-check.mjs';

const fail = () => { throw new Error('MIGRATION_UNAVAILABLE'); };
const CONFIG = '/migration/config.json';
const DIRECTORY = fileURLToPath(new URL('../../drizzle/', import.meta.url));
const MIGRATIONS = Object.freeze([
  ['0000_lively_speedball', 1785498994215, '7845b3ce01a5bbfbbad0af50a48aa73222e37eae05b3eec9b3be4e41790b5671'],
  ['0001_white_komodo', 1785502357731, 'f8c6cab011368359f4b1c834074635f2ab1511222cae17c536693f30225d1d9d'],
  ['0002_fixed_token_expiry', 1792324800000, '4b3b433350aa219334e61688c5abf407a1f77e7707b18eef2b66d538259d3a11'],
]);
const IDENTIFIER = /^[a-z_][a-z0-9_]{0,62}$/;

export function parseMigrationConfig(raw) {
  try {
    const keys = ['host', 'port', 'database', 'user', 'password', 'ownerRole', 'caCertificate'];
    if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).length !== keys.length ||
        keys.some(key => !Object.hasOwn(raw, key))) fail();
    if (typeof raw.host !== 'string' || raw.host.length > 253 ||
        !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(raw.host) ||
        raw.host.split('.').some(label => label.length < 1 || label.length > 63 || label.startsWith('-') || label.endsWith('-')) ||
        raw.port !== 5432 || ['database', 'user', 'ownerRole'].some(key => typeof raw[key] !== 'string' || !IDENTIFIER.test(raw[key])) ||
        raw.user === raw.ownerRole || [raw.user, raw.ownerRole].some(value => value === 'postgres' || value.startsWith('pg_')) ||
        typeof raw.password !== 'string' || raw.password.length < 1 || raw.password.length > 1024 || raw.password.includes('\0') ||
        !(raw.caCertificate === null || (typeof raw.caCertificate === 'string' && raw.caCertificate.length <= 16384 &&
          /^(?:-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\n?)+$/.test(raw.caCertificate)))) fail();
    return Object.fromEntries(keys.map(key => [key, raw[key]]));
  } catch { fail(); }
}

function checkedMigrations() {
  const files = [['meta/_journal.json', '5b1bfd3a0e715e877b971776d139a5a4e3c06318d3aa6821034462c52016a665'],
    ...MIGRATIONS.map(([tag, , hash]) => [tag + '.sql', hash])];
  for (const [name, expected] of files) {
    const fd = fs.openSync(path.join(DIRECTORY, name), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    try {
      const st = fs.fstatSync(fd);
      if (!st.isFile() || st.nlink !== 1 || st.size < 1 || st.size > 65536) fail();
      if (createHash('sha256').update(fs.readFileSync(fd)).digest('hex') !== expected) fail();
    } finally { fs.closeSync(fd); }
  }
}

async function checkedLedger(client, complete = false) {
  const exists = await client.query("SELECT to_regclass('drizzle.__drizzle_migrations') AS ledger");
  if (exists.rows[0]?.ledger === null) { if (complete) fail(); return; }
  const { rows } = await client.query('SELECT hash, created_at FROM drizzle.__drizzle_migrations ORDER BY created_at, id LIMIT 4');
  if (rows.length > MIGRATIONS.length || (complete && rows.length !== MIGRATIONS.length)) fail();
  for (let index = 0; index < rows.length; index++) {
    if (rows[index].hash !== MIGRATIONS[index][2] || String(rows[index].created_at) !== String(MIGRATIONS[index][1])) fail();
  }
}

async function productionPool(config) {
  const { default: pg } = await import('pg');
  return new pg.Pool(config);
}
async function productionMigrate(client) {
  const [{ drizzle }, { migrate }] = await Promise.all([import('drizzle-orm/node-postgres'), import('drizzle-orm/node-postgres/migrator')]);
  await migrate(drizzle(client), { migrationsFolder: DIRECTORY });
}

// Test injection is module-only. The CLI accepts no options, paths, URLs or SQL.
export async function runMigration({ args = [], identity = process, environment = process.env,
  noNewPrivileges = requireNoNewPrivileges, readConfig = readPrivateJson, verifyFiles = checkedMigrations,
  createPool = productionPool, migrate = productionMigrate, signal, deadlineMs = 60000 } = {}) {
  let pool; let client; let timer; let stop; let cancelled = false; let released = false;
  const closeClient = () => { if (client && !released) { released = true; client.release(true); } };
  try {
    if ([identity.getuid(), identity.getgid(), identity.geteuid(), identity.getegid()].some(id => id !== 1000)) fail();
    noNewPrivileges();
    if (!Array.isArray(args) || args.length !== 0 ||
        Object.keys(environment).some(key => !['PATH', 'HOME', 'TMPDIR', 'LANG', 'NODE_ENV', 'UV_USE_IO_URING'].includes(key))) fail();
    if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > 60000 || signal?.aborted) fail();
    process.umask(0o077);
    const config = parseMigrationConfig(readConfig(CONFIG, 32768));
    verifyFiles();
    pool = await createPool({ host: config.host, port: config.port, database: config.database,
      user: config.user, password: config.password, ssl: { rejectUnauthorized: true, minVersion: 'TLSv1.2',
        checkServerIdentity: (_hostname, certificate) => tls.checkServerIdentity(config.host, certificate),
        ...(config.caCertificate === null ? {} : { ca: config.caCertificate }) },
      max: 1, min: 0, allowExitOnIdle: true, connectionTimeoutMillis: 5000, idleTimeoutMillis: 1000,
      statement_timeout: 15000, lock_timeout: 3000, idle_in_transaction_session_timeout: 15000,
      query_timeout: 20000, application_name: 'whoop-migration-only', sslnegotiation: 'postgres' });
    // Idle pool errors are never printed; an active connection failure is caught
    // by its query, and destroying the client rolls back any open transaction.
    pool.on('error', () => {});
    const stopped = new Promise((_, reject) => {
      stop = () => { cancelled = true; try { closeClient(); } catch {} reject(new Error('MIGRATION_UNAVAILABLE')); };
      timer = setTimeout(stop, deadlineMs);
      signal?.addEventListener('abort', stop, { once: true });
      if (signal?.aborted) stop();
    });
    const operation = (async () => {
      client = await pool.connect();
      if (cancelled) { closeClient(); fail(); }
      client.on('error', stop);
      const { rows } = await client.query(`SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
        FROM pg_roles WHERE rolname = ANY($1::text[])`, [[config.user, config.ownerRole]]);
      if (rows.length !== 2 || rows.some(row => row.rolsuper || row.rolcreatedb || row.rolcreaterole || row.rolreplication || row.rolbypassrls) ||
          rows.find(row => row.rolname === config.user)?.rolcanlogin !== true ||
          rows.find(row => row.rolname === config.ownerRole)?.rolcanlogin !== false) fail();
      const login = await client.query('SELECT session_user AS login, current_user AS current');
      if (login.rows[0]?.login !== config.user || login.rows[0]?.current !== config.user) fail();
      await client.query(`SET ROLE "${config.ownerRole}"`);
      await client.query('SET search_path TO public, pg_catalog');
      const schemas = await client.query("SELECT nspname FROM pg_namespace WHERE nspname IN ('public', 'drizzle') AND nspowner = current_user::regrole");
      if (schemas.rows.length !== 2) fail();
      const lock = await client.query('SELECT pg_try_advisory_lock(174812392, 189736091) AS acquired');
      if (lock.rows[0]?.acquired !== true) fail();
      await checkedLedger(client);
      await migrate(client);
      await checkedLedger(client, true);
    })();
    await Promise.race([operation, stopped]);
    return { completed: true };
  } catch { fail(); }
  finally {
    clearTimeout(timer); if (stop) signal?.removeEventListener('abort', stop);
    try {
      let releaseFailed = false;
      try { closeClient(); } catch { releaseFailed = true; }
      if (pool) {
        let closingTimer;
        try { await Promise.race([pool.end(), new Promise((_, reject) => { closingTimer = setTimeout(() => reject(new Error('MIGRATION_UNAVAILABLE')), 5000); })]); }
        finally { clearTimeout(closingTimer); }
      }
      if (releaseFailed) fail();
    } catch { fail(); }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const controller = new AbortController();
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => controller.abort());
  // Last-resort process bound also covers a broken dependency's pool shutdown.
  const watchdog = setTimeout(() => { process.stderr.write('Migration unavailable.\n'); process.exit(1); }, 70000);
  watchdog.unref();
  try { await runMigration({ args: process.argv.slice(2), signal: controller.signal }); console.log('Migrations completed.'); clearTimeout(watchdog); }
  catch { console.error('Migration unavailable.'); process.exitCode = 1; }
}
