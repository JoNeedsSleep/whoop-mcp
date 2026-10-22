// Explicit temporary deployment entrypoint. The database credential stays in
// memory; this module never creates a config file or starts the application.
import { pathToFileURL } from 'node:url';
import { parseMigrationConfig, runMigration } from './migrate.mjs';
import { requireNoNewPrivileges } from '../staging/runtime-check.mjs';

const fail = () => { throw new Error('MIGRATION_UNAVAILABLE'); };
const MAXIMUM = 32768;

export async function migrationFromStdin({ input = process.stdin, identity = process,
  environment = process.env, args = [], noNewPrivileges = requireNoNewPrivileges,
  migrate = runMigration, timeoutMs = 5000, signal } = {}) {
  let timer;
  try {
    if ([identity.getuid(), identity.getgid(), identity.geteuid(), identity.getegid()].some(id => id !== 1000) ||
        !Array.isArray(args) || args.length !== 0 ||
        Object.keys(environment).some(key => !['PATH', 'HOME', 'NODE_ENV', 'UV_USE_IO_URING'].includes(key)) ||
        (Object.hasOwn(environment, 'UV_USE_IO_URING') && environment.UV_USE_IO_URING !== '0') ||
        !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000 || signal?.aborted) fail();
    noNewPrivileges();
    if (input.isTTY) fail();
    const raw = await new Promise((resolve, reject) => {
      const chunks = []; let size = 0; let settled = false;
      const finish = (error) => {
        if (settled) return; settled = true;
        clearTimeout(timer); input.off('data', data); input.off('end', end); input.off('error', errorEvent); input.off('close', closed);
        signal?.removeEventListener('abort', aborted);
        input.pause();
        if (error) reject(new Error('MIGRATION_UNAVAILABLE'));
        else resolve(Buffer.concat(chunks));
      };
      const data = chunk => {
        if (!Buffer.isBuffer(chunk)) { finish(true); return; }
        size += chunk.length;
        if (size > MAXIMUM) { finish(true); return; }
        chunks.push(chunk);
      };
      const end = () => finish(size < 2);
      const errorEvent = () => finish(true);
      const closed = () => finish(true);
      const aborted = () => finish(true);
      timer = setTimeout(() => finish(true), timeoutMs);
      input.on('data', data); input.once('end', end); input.once('error', errorEvent); input.once('close', closed);
      signal?.addEventListener('abort', aborted, { once: true });
      if (signal?.aborted) aborted();
    });
    let config;
    try { config = parseMigrationConfig(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw))); }
    finally { raw.fill(0); }
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.railway\.internal$/.test(config.host) ||
        config.database !== 'whoop' || config.user !== 'whoop_migrate' || config.ownerRole !== 'whoop_owner' ||
        config.caCertificate === null) fail();
    // Only the fixed file-read boundary is supplied from bounded private stdin.
    // All migration/TLS/role/ledger checks remain the ordinary implementation.
    return await migrate({ args: [], identity, environment, noNewPrivileges, signal,
      readConfig: filename => { if (filename !== '/migration/config.json') fail(); return config; } });
  } catch { fail(); }
  finally { clearTimeout(timer); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const controller = new AbortController();
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => controller.abort());
  const watchdog = setTimeout(() => { process.stderr.write('Migration unavailable.\n'); process.exit(1); }, 75000);
  watchdog.unref();
  try { await migrationFromStdin({ args: process.argv.slice(2), signal: controller.signal }); console.log('Migrations completed.'); clearTimeout(watchdog); }
  catch { console.error('Migration unavailable.'); process.exitCode = 1; }
}
