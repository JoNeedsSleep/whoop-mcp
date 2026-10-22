// One-shot runtime-role metadata probe. No application, migrations or table data.
import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { requireNoNewPrivileges } from '../staging/runtime-check.mjs';

const fail = () => { throw new Error('DATABASE_PROBE_UNAVAILABLE'); };
const TABLES = Object.freeze(['mcp_tokens', 'oauth_auth_codes', 'oauth_clients', 'pending_authorizations', 'users', 'whoop_tokens']);
const CRUD = Object.freeze(['DELETE', 'INSERT', 'SELECT', 'UPDATE']);
const DENIED = Object.freeze(['MAINTAIN', 'REFERENCES', 'TRIGGER', 'TRUNCATE']);
const RESULT = Object.freeze({ version: 1, event: 'whoop-runtime-database-probe', passed: true, crudPrivileges: 24 });

export function parseProbeConfig(raw, now = Date.now()) {
  try {
    const keys = ['host', 'port', 'database', 'user', 'password', 'caCertificate'];
    if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).length !== keys.length ||
        keys.some(key => !Object.hasOwn(raw, key)) || typeof raw.host !== 'string' ||
        !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.railway\.internal$/.test(raw.host) ||
        raw.port !== 5432 || raw.database !== 'whoop' || raw.user !== 'whoop_runtime' ||
        typeof raw.password !== 'string' || !/^[a-f0-9]{64}$/.test(raw.password) ||
        typeof raw.caCertificate !== 'string' || raw.caCertificate.length > 16384 ||
        !/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\n?$/.test(raw.caCertificate)) fail();
    const certificate = new X509Certificate(raw.caCertificate);
    if (!certificate.ca || !Number.isSafeInteger(now) || now < Date.parse(certificate.validFrom) || now >= Date.parse(certificate.validTo)) fail();
    return Object.fromEntries(keys.map(key => [key, raw[key]]));
  } catch { fail(); }
}

function guards({ identity, environment, args, noNewPrivileges }) {
  if ([identity.getuid(), identity.geteuid(), identity.getgid(), identity.getegid()].some(id => id !== 1000) ||
      !Array.isArray(args) || args.length ||
      Object.keys(environment).some(key => !['PATH', 'HOME', 'NODE_ENV', 'UV_USE_IO_URING'].includes(key)) ||
      (Object.hasOwn(environment, 'UV_USE_IO_URING') && environment.UV_USE_IO_URING !== '0')) fail();
  noNewPrivileges();
}

async function productionPool(config) {
  const { default: pg } = await import('pg');
  return new pg.Pool(config);
}

// Injection points are module-only. The CLI has no URL, SQL, path or mode selector.
export async function runProbe({ config: raw, identity = process, environment = process.env, args = [],
  noNewPrivileges = requireNoNewPrivileges, createPool = productionPool, signal, deadlineMs = 15000 } = {}) {
  let pool; let client; let timer; let stop; let released = false; let cancelled = false;
  const release = () => { if (client && !released) { released = true; client.release(true); } };
  try {
    guards({ identity, environment, args, noNewPrivileges });
    if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > 15000 || signal?.aborted) fail();
    const config = parseProbeConfig(raw);
    pool = await createPool({ host: config.host, port: config.port, database: config.database,
      user: config.user, password: config.password,
      ssl: { ca: config.caCertificate, rejectUnauthorized: true, minVersion: 'TLSv1.2',
        checkServerIdentity: (_hostname, certificate) => tls.checkServerIdentity(config.host, certificate) },
      max: 1, min: 0, allowExitOnIdle: true, connectionTimeoutMillis: 5000, idleTimeoutMillis: 1000,
      statement_timeout: 3000, query_timeout: 5000, lock_timeout: 1000,
      options: '-c default_transaction_read_only=on -c search_path=pg_catalog',
      application_name: 'whoop-runtime-metadata-probe', sslnegotiation: 'postgres' });
    pool.on('error', () => {});
    const stopped = new Promise((_, reject) => {
      stop = () => { cancelled = true; try { release(); } catch {} reject(new Error('DATABASE_PROBE_UNAVAILABLE')); };
      timer = setTimeout(stop, deadlineMs);
      signal?.addEventListener('abort', stop, { once: true });
      if (signal?.aborted) stop();
    });
    const operation = (async () => {
      client = await pool.connect();
      if (cancelled) { release(); fail(); }
      client.on('error', stop);
      const stream = client.connection?.stream;
      if (stream?.authorized !== true || !['TLSv1.2', 'TLSv1.3'].includes(stream.getProtocol())) fail();
      const query = async (sql, values) => {
        if (cancelled) fail();
        const result = await client.query(sql, values);
        if (cancelled) fail();
        return result.rows;
      };
      const identityRows = await query(`SELECT 1 AS one, session_user AS login, current_user AS current,
        current_database() AS database, current_setting('transaction_read_only') AS readonly`);
      if (identityRows.length !== 1 || identityRows[0].one !== 1 || identityRows[0].login !== 'whoop_runtime' ||
          identityRows[0].current !== 'whoop_runtime' || identityRows[0].database !== 'whoop' || identityRows[0].readonly !== 'on') fail();
      const roles = await query(`SELECT rolname, rolcanlogin,
        rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls AS privileged,
        EXISTS(SELECT 1 FROM pg_auth_members WHERE member = r.oid) AS membership
        FROM pg_roles r WHERE rolname IN ('whoop_runtime','whoop_owner','whoop_migrate') ORDER BY rolname LIMIT 4`);
      if (roles.length !== 3 || roles.some((row, index) => row.rolname !== ['whoop_migrate', 'whoop_owner', 'whoop_runtime'][index] ||
        row.rolcanlogin !== (row.rolname === 'whoop_runtime') || row.privileged !== false || row.membership !== false)) fail();
      const database = await query(`SELECT
        has_database_privilege(current_user,'whoop','CONNECT') AS connect,
        has_database_privilege(current_user,'whoop','CREATE,TEMP') AS create_temp,
        has_database_privilege('whoop_owner','whoop','CREATE') AS owner_create,
        has_database_privilege('whoop_migrate','whoop','CONNECT') AS migrate_connect,
        datdba = current_user::regrole AS owned FROM pg_database WHERE datname='whoop' LIMIT 2`);
      if (database.length !== 1 || database[0].connect !== true ||
          ['create_temp', 'owner_create', 'migrate_connect', 'owned'].some(key => database[0][key] !== false)) fail();
      const schemas = await query(`SELECT nspname, pg_get_userbyid(nspowner) AS owner,
        has_schema_privilege(current_user,oid,'USAGE') AS usage,
        has_schema_privilege(current_user,oid,'CREATE') AS create
        FROM pg_namespace WHERE nspname IN ('public','drizzle') ORDER BY nspname LIMIT 3`);
      if (schemas.length !== 2 || schemas.some((row, index) => row.nspname !== ['drizzle', 'public'][index] ||
          row.owner !== 'whoop_owner' || row.usage !== (row.nspname === 'public') || row.create !== false)) fail();
      const tables = await query(`SELECT c.relname, pg_get_userbyid(c.relowner) AS owner
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f') ORDER BY c.relname LIMIT 7`);
      if (tables.length !== 6 || tables.some((row, index) => row.relname !== TABLES[index] || row.owner !== 'whoop_owner')) fail();
      // This reads catalog ACLs only, never a row from an application table.
      const privileges = await query(`SELECT c.relname, p.privilege,
        has_table_privilege(current_user,c.oid,p.privilege) AS allowed,
        has_table_privilege(current_user,c.oid,p.privilege || ' WITH GRANT OPTION') AS grantable
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        CROSS JOIN unnest($1::text[]) AS p(privilege)
        WHERE n.nspname='public' AND c.relname=ANY($2::text[])
        ORDER BY c.relname,p.privilege LIMIT 49`, [[...CRUD, ...DENIED].sort(), TABLES]);
      const all = [...CRUD, ...DENIED].sort();
      if (privileges.length !== 48 || privileges.some((row, index) => row.relname !== TABLES[Math.floor(index / 8)] ||
          row.privilege !== all[index % 8] || row.allowed !== CRUD.includes(row.privilege) || row.grantable !== false)) fail();
      const grants = await query(`SELECT table_name,privilege_type,is_grantable FROM information_schema.role_table_grants
        WHERE grantee=current_user AND table_schema='public' ORDER BY table_name,privilege_type LIMIT 25`);
      if (grants.length !== 24 || grants.some((row, index) => row.table_name !== TABLES[Math.floor(index / 4)] ||
          row.privilege_type !== CRUD[index % 4] || row.is_grantable !== 'NO')) fail();
      const ledger = await query(`SELECT pg_get_userbyid(c.relowner) AS owner,
        has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') AS allowed
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='drizzle' AND c.relname='__drizzle_migrations' AND c.relkind='r' LIMIT 2`);
      if (ledger.length !== 1 || ledger[0].owner !== 'whoop_owner' || ledger[0].allowed !== false) fail();
    })();
    await Promise.race([operation, stopped]);
    return { ...RESULT };
  } catch { fail(); }
  finally {
    clearTimeout(timer); if (stop) signal?.removeEventListener('abort', stop);
    let failed = false;
    try { release(); } catch { failed = true; }
    if (pool) {
      let closingTimer;
      try { await Promise.race([pool.end(), new Promise((_, reject) => {
        closingTimer = setTimeout(() => reject(new Error('DATABASE_PROBE_UNAVAILABLE')), 3000);
      })]); } catch { failed = true; }
      finally { clearTimeout(closingTimer); }
    }
    if (failed) fail();
  }
}

export async function probeFromStdin({ input = process.stdin, identity = process, environment = process.env, args = [],
  noNewPrivileges = requireNoNewPrivileges, probe = runProbe, signal, timeoutMs = 5000 } = {}) {
  let timer;
  try {
    guards({ identity, environment, args, noNewPrivileges });
    if (input.isTTY || signal?.aborted || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000) fail();
    const bytes = await new Promise((resolve, reject) => {
      const chunks = []; let size = 0; let settled = false;
      const finish = error => {
        if (settled) return; settled = true;
        clearTimeout(timer); input.off('data', data); input.off('end', end); input.off('error', bad); input.off('close', bad);
        signal?.removeEventListener('abort', bad); input.pause();
        const buffer = Buffer.concat(chunks); chunks.forEach(chunk => chunk.fill(0));
        if (error) { buffer.fill(0); reject(new Error('DATABASE_PROBE_UNAVAILABLE')); } else resolve(buffer);
      };
      const data = chunk => {
        if (!Buffer.isBuffer(chunk)) { finish(true); return; }
        size += chunk.length;
        if (size > 32768) { finish(true); return; }
        chunks.push(Buffer.from(chunk));
      };
      const end = () => finish(size < 2); const bad = () => finish(true);
      timer = setTimeout(bad, timeoutMs);
      input.on('data', data); input.once('end', end); input.once('error', bad); input.once('close', bad);
      signal?.addEventListener('abort', bad, { once: true }); if (signal?.aborted) bad();
    });
    let config;
    try { config = parseProbeConfig(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))); }
    finally { bytes.fill(0); }
    return await probe({ config, identity, environment, args: [], noNewPrivileges, signal });
  } catch { fail(); }
  finally { clearTimeout(timer); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const controller = new AbortController();
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => controller.abort());
  const watchdog = setTimeout(() => { process.stderr.write('Database probe unavailable.\n'); process.exit(1); }, 25000);
  watchdog.unref();
  try { console.log(JSON.stringify(await probeFromStdin({ args: process.argv.slice(2), signal: controller.signal }))); clearTimeout(watchdog); }
  catch { process.stderr.write('Database probe unavailable.\n'); process.exitCode = 1; }
}
