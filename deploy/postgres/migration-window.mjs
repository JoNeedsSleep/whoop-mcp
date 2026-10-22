// Fixed one-off migration password-window inspection/renewal. No network client,
// caller SQL, role selector, password input, grant or application startup.
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { guardInvocation, parseState, validateVolumeRoot } from './provision.mjs';

const ROOT = '/var/lib/postgresql/data';
const SOURCE = '/opt/whoop-postgres';
const PGDATA = ROOT + '/pgdata';
export const HARD_STOP = '2026-10-21T01:16:00.000000Z';
// The original login was already expired at this recorded setup checkpoint.
// A renewed expiry is later, so supplying a newly inspected timestamp cannot renew twice.
export const ORIGINAL_EXPIRY_CEILING = '2026-10-20T04:49:00.000000Z';
const ENV = Object.freeze({
  PATH: '/usr/local/bin:/usr/lib/postgresql/17/bin:/usr/bin:/bin',
  HOME: '/tmp', TMPDIR: '/tmp', LANG: 'C',
});
const PINS = Object.freeze({
  'postgresql.conf.template': '387ce608c87aff8c2671b583ac03a8a3c2923610d3c1adcd8f50e68b3710bbf3',
  'pg_hba.conf': 'f98fe30e1e18b2982f3fbaa5dfd2f20d008c532edce8b8b65d2fa45b45b797c9',
  'pg_ident.conf': '930d43e93b863fda9fdaa1fd8ac073a25a08d7e41b579c977d4f8401531dd562',
});
const fail = () => { throw new Error('MIGRATION_WINDOW_UNAVAILABLE'); };
const hash = value => createHash('sha256').update(value).digest('hex');
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
function timestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$/.test(value)) fail();
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value.slice(0, 23) + 'Z') fail();
  return value;
}

export function parseArguments(args) {
  if (!Array.isArray(args) || !['inspect', 'renew'].includes(args[0]) ||
      args.length !== (args[0] === 'inspect' ? 1 : 2)) fail();
  const expectedExpiry = args[0] === 'renew' ? timestamp(args[1]) : null;
  if (expectedExpiry !== null && expectedExpiry > ORIGINAL_EXPIRY_CEILING) fail();
  return { operation: args[0], expectedExpiry };
}

// The privileged local session reads only role/catalog metadata. rolpassword is
// tested inside PostgreSQL but is never selected into output or changed.
const GUARDS = `
DO $$ BEGIN
  IF session_user <> 'whoop_admin' OR current_user <> 'whoop_admin' OR
     current_database() <> 'whoop' OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999 OR
     current_setting('listen_addresses') <> '' OR clock_timestamp() < TIMESTAMPTZ '${ORIGINAL_EXPIRY_CEILING}' OR
     clock_timestamp() >= TIMESTAMPTZ '${HARD_STOP}' OR
     NOT pg_try_advisory_xact_lock(174812392, 189736091) OR
     EXISTS (SELECT 1 FROM pg_stat_activity WHERE backend_type = 'client backend' AND pid <> pg_backend_pid()) OR
     (SELECT count(*) FROM pg_roles WHERE rolname IN ('whoop_owner','whoop_migrate','whoop_runtime')) <> 3 OR
     EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('whoop_owner','whoop_migrate','whoop_runtime') AND
       (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit)) OR
     NOT EXISTS (SELECT 1 FROM pg_authid WHERE rolname = 'whoop_migrate' AND rolcanlogin AND rolconnlimit = 2
       AND rolpassword LIKE 'SCRAM-SHA-256$%' AND rolvaliduntil IS NOT NULL
       AND isfinite(rolvaliduntil) AND rolvaliduntil <= TIMESTAMPTZ '${HARD_STOP}') OR
     NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'whoop_owner' AND NOT rolcanlogin) OR
     NOT EXISTS (SELECT 1 FROM pg_authid WHERE rolname = 'whoop_runtime' AND NOT rolcanlogin
       AND rolconnlimit = 12 AND rolpassword LIKE 'SCRAM-SHA-256$%') OR
     (SELECT count(*) FROM pg_auth_members
       WHERE member IN ('whoop_owner'::regrole,'whoop_migrate'::regrole,'whoop_runtime'::regrole)
          OR roleid IN ('whoop_owner'::regrole,'whoop_migrate'::regrole,'whoop_runtime'::regrole)) <> 1 OR
     NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE roleid = 'whoop_owner'::regrole
       AND member = 'whoop_migrate'::regrole AND grantor = 'whoop_admin'::regrole
       AND NOT admin_option AND NOT inherit_option AND set_option) OR
     NOT has_database_privilege('whoop_owner','whoop','CREATE') OR
     has_database_privilege('whoop_owner','whoop','CONNECT,TEMP') OR
     NOT has_database_privilege('whoop_migrate','whoop','CONNECT') OR
     has_database_privilege('whoop_migrate','whoop','CREATE,TEMP') OR
     NOT has_database_privilege('whoop_runtime','whoop','CONNECT') OR
     has_database_privilege('whoop_runtime','whoop','CREATE,TEMP') OR
     EXISTS (SELECT 1 FROM pg_database d, LATERAL aclexplode(d.datacl) a
       WHERE d.datname = 'whoop' AND (
         a.grantee NOT IN ('whoop_admin'::regrole,'whoop_owner'::regrole,'whoop_migrate'::regrole,'whoop_runtime'::regrole)
         OR (a.grantee <> 'whoop_admin'::regrole AND a.is_grantable)
         OR (a.grantee = 'whoop_owner'::regrole AND a.privilege_type <> 'CREATE')
         OR (a.grantee IN ('whoop_migrate'::regrole,'whoop_runtime'::regrole) AND a.privilege_type <> 'CONNECT'))) OR
     (SELECT count(*) FROM pg_namespace WHERE nspname IN ('public','drizzle') AND nspowner = 'whoop_owner'::regrole) <> 2 OR
     EXISTS (SELECT 1 FROM pg_namespace n, LATERAL aclexplode(n.nspacl) a
       WHERE n.nspname IN ('public','drizzle') AND a.grantee <> 'whoop_owner'::regrole) OR
     EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid WHERE n.nspname IN ('public','drizzle')) OR
     EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid WHERE n.nspname IN ('public','drizzle')) OR
     EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON t.typnamespace = n.oid WHERE n.nspname IN ('public','drizzle')) OR
     to_regclass('drizzle.__drizzle_migrations') IS NOT NULL THEN
    RAISE EXCEPTION 'MIGRATION_WINDOW_UNAVAILABLE';
  END IF;
END $$;
`;
const SQL_TIME = `to_char(rolvaliduntil AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;

export function buildSql(args) {
  const { operation, expectedExpiry } = parseArguments(args);
  const mutation = operation === 'renew' ? `
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_authid WHERE rolname = 'whoop_migrate'
      AND rolvaliduntil = TIMESTAMPTZ '${expectedExpiry}'
      AND rolvaliduntil < clock_timestamp()
      AND rolvaliduntil <= TIMESTAMPTZ '${ORIGINAL_EXPIRY_CEILING}') THEN
    RAISE EXCEPTION 'MIGRATION_WINDOW_UNAVAILABLE';
  END IF;
  EXECUTE format('ALTER ROLE whoop_migrate VALID UNTIL %L',
    least(clock_timestamp() + interval '1 hour', TIMESTAMPTZ '${HARD_STOP}'));
END $$;
` : '';
  return `\\set ON_ERROR_STOP on
BEGIN${operation === 'inspect' ? ' READ ONLY' : ''};
SET LOCAL statement_timeout = '10s';
SET LOCAL lock_timeout = '3s';
SET LOCAL idle_in_transaction_session_timeout = '10s';
${GUARDS}
${mutation}
SELECT json_build_object(
 'version',1,'event','whoop-migration-window','operation','${operation}',
 'previousValidUntil',${operation === 'renew' ? "'" + expectedExpiry + "'" : SQL_TIME},
 'validUntil',${SQL_TIME},
 'observedAt',to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
 'hardStop','${HARD_STOP}') FROM pg_authid WHERE rolname = 'whoop_migrate';
COMMIT;
`;
}

export function validateReport(text, args) {
  const { operation, expectedExpiry } = parseArguments(args);
  try {
    if (typeof text !== 'string' || Buffer.byteLength(text) > 2048) fail();
    const report = JSON.parse(text);
    if (!exact(report, ['version','event','operation','previousValidUntil','validUntil','observedAt','hardStop']) ||
        report.version !== 1 || report.event !== 'whoop-migration-window' || report.operation !== operation ||
        report.hardStop !== HARD_STOP) fail();
    for (const key of ['previousValidUntil', 'validUntil', 'observedAt']) timestamp(report[key]);
    if (report.observedAt < ORIGINAL_EXPIRY_CEILING || report.observedAt >= HARD_STOP ||
        report.validUntil > HARD_STOP ||
        (operation === 'inspect' && report.validUntil !== report.previousValidUntil) ||
        (operation === 'renew' && (report.previousValidUntil !== expectedExpiry ||
          report.previousValidUntil > ORIGINAL_EXPIRY_CEILING || report.previousValidUntil >= report.observedAt ||
          report.validUntil <= report.observedAt || report.validUntil > HARD_STOP ||
          Date.parse(report.validUntil) - Date.parse(report.observedAt) > 3600000))) fail();
    return { version: 1, event: 'whoop-migration-window', operation,
      previousValidUntil: report.previousValidUntil, validUntil: report.validUntil,
      observedAt: report.observedAt, hardStop: HARD_STOP };
  } catch { fail(); }
}

function readPrivate(filename, maximum, uid = 999, privateFile = true, content = true) {
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1 || st.uid !== uid || st.size < 1 || st.size > maximum ||
        (privateFile && (st.mode & 0o7777) !== 0o600)) fail();
    if (!content) return;
    const bytes = Buffer.alloc(st.size + 1);
    let length = 0;
    while (length < bytes.length) {
      const n = fs.readSync(fd, bytes, length, bytes.length - length, null);
      if (!n) break;
      length += n;
    }
    if (length !== st.size) fail();
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length));
  } finally { fs.closeSync(fd); }
}
function directory(filename, names) {
  const st = fs.lstatSync(filename);
  if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== 999 || st.gid !== 999 || (st.mode & 0o7777) !== 0o700) fail();
  if (names && fs.readdirSync(filename).sort().join(',') !== [...names].sort().join(',')) fail();
}
function absent(filename) {
  try { fs.lstatSync(filename); return false; }
  catch (error) { if (error?.code === 'ENOENT') return true; throw error; }
}
function checkedVolume() {
  validateVolumeRoot('enable');
  directory(ROOT + '/pgdata'); directory(ROOT + '/run', []);
  directory(ROOT + '/config', ['postgresql.conf']);
  directory(ROOT + '/tls', ['ca.pem','server.pem','server-key.pem']);
  const state = parseState(JSON.parse(readPrivate(ROOT + '/provision-state.json', 1024)));
  if (state.phase !== 'enabled' || readPrivate(PGDATA + '/PG_VERSION', 8) !== '17\n' || !absent(PGDATA + '/postmaster.pid')) fail();
  const sources = {};
  for (const [name, digest] of Object.entries(PINS)) {
    sources[name] = readPrivate(SOURCE + '/' + name, 32768, 0, false);
    if (hash(sources[name]) !== digest) fail();
  }
  if (readPrivate(ROOT + '/config/postgresql.conf', 16384) !==
      sources['postgresql.conf.template'].replaceAll('@DATABASE_HOST@', state.host)) fail();
  // Confirm private file metadata only; renewal never reads the TLS key.
  for (const [name, maximum] of [['ca.pem',16384],['server.pem',16384],['server-key.pem',8192]]) {
    readPrivate(ROOT + '/tls/' + name, maximum, 999, true, false);
  }
}

export async function runWindow(args) {
  guardInvocation('enable'); // Exact UID/GID999 + kernel NNP + clean environment.
  parseArguments(args);
  process.umask(0o077);
  let lock; let lockStat; let started = false; let childUnconfirmed = false; let cancel; let cancelled = false;
  const interrupted = () => { cancelled = true; cancel?.(); };
  for (const name of ['SIGINT','SIGTERM']) process.on(name, interrupted);
  const command = (binary, argv, input, timeout = 15000, cleanup = false) => new Promise((resolve, reject) => {
    if (cancelled && !cleanup) { reject(new Error('MIGRATION_WINDOW_UNAVAILABLE')); return; }
    let child; let timer; let killTimer; let ended = false; let failed = false; let size = 0; const chunks = [];
    const finish = code => {
      if (ended) return; ended = true; clearTimeout(timer); clearTimeout(killTimer);
      if (failed || code !== 0) reject(new Error('MIGRATION_WINDOW_UNAVAILABLE'));
      else resolve(Buffer.concat(chunks).toString('utf8'));
    };
    const stop = () => {
      if (ended || failed) return; failed = true; clearTimeout(timer);
      if (!child?.pid) { finish(1); return; }
      child.kill('SIGKILL');
      killTimer = setTimeout(() => { childUnconfirmed = true; finish(1); }, 2000);
    };
    cancel = stop;
    try {
      child = spawn(binary, argv, { env: ENV, stdio: ['pipe','pipe','pipe'] });
      for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => {
        size += chunk.length;
        if (size > 16384) stop(); else if (stream === child.stdout) chunks.push(chunk);
      });
      child.on('error', stop); child.on('close', finish); child.stdin.on('error', () => {});
      timer = setTimeout(stop, timeout); child.stdin.end(input);
    } catch { stop(); }
  });
  const ctl = action => command('/usr/lib/postgresql/17/bin/pg_ctl', ['-D', PGDATA, '-l', '/tmp/migration-window-postgres.log',
    '-w','-t','10','-m','fast','-o',
    '-c config_file=/var/lib/postgresql/data/config/postgresql.conf -c listen_addresses=', action], undefined, 15000, action === 'stop');
  try {
    checkedVolume();
    lock = fs.openSync(ROOT + '/.provision.lock', fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    lockStat = fs.fstatSync(lock);
    const log = fs.openSync('/tmp/migration-window-postgres.log', fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    fs.closeSync(log);
    started = true;
    await ctl('start');
    const output = await command('/usr/lib/postgresql/17/bin/psql',
      ['-X','-qAt','-h',ROOT + '/run','-U','whoop_admin','-d','whoop','-v','ON_ERROR_STOP=1'], buildSql(args));
    const report = validateReport(output, args);
    await ctl('stop'); started = false;
    if (cancelled) fail();
    return report;
  } catch { fail(); }
  finally {
    try { if (started) { await ctl('stop'); started = false; } }
    finally {
      for (const name of ['SIGINT','SIGTERM']) process.removeListener(name, interrupted);
      if (lock !== undefined) {
        fs.closeSync(lock);
        if (started || childUnconfirmed) fail();
        const current = fs.lstatSync(ROOT + '/.provision.lock');
        if (current.dev !== lockStat.dev || current.ino !== lockStat.ino) fail();
        fs.unlinkSync(ROOT + '/.provision.lock');
      }
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const watchdog = setTimeout(() => { console.error('Migration window unavailable.'); process.exit(1); }, 60000);
  try {
    const report = await runWindow(process.argv.slice(2));
    clearTimeout(watchdog);
    console.log(JSON.stringify(report)); // Fixed metadata, emitted only after confirmed shutdown.
    setInterval(() => {}, 3600000); // No automatic renewal/restart loop.
    for (const name of ['SIGINT','SIGTERM']) process.once(name, () => process.exit(0));
  } catch { clearTimeout(watchdog); console.error('Migration window unavailable.'); process.exitCode = 1; }
}
