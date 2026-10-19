import { pathToFileURL } from 'node:url';
import { readPrivateJson } from '../railway/config.mjs';
import { startTailscale, readEnrollmentKey } from '../railway/tailscale-supervisor.mjs';
import { assertSyntheticEnvironment, createSyntheticService, parseStagingConfig } from './service.mjs';
import { requireNoNewPrivileges } from './runtime-check.mjs';

const fail = () => { throw new Error('SYNTHETIC_STAGING_UNAVAILABLE'); };
export async function startSyntheticStaging(raw, { enrollmentKey, tailscale = startTailscale, service = createSyntheticService } = {}) {
  process.umask(0o077);
  const config = parseStagingConfig(raw);
  // Dedicated staging identity uses the existing backend role and exact pinned
  // destination policy. It must never share a production node/state volume.
  const node = await tailscale({ stateDirectory: '/data/tailscale', tag: 'tag:whoop-backend', hostname: config.hostname, port: 8080, enrollmentKey });
  let server; let closing; let resolveFailure;
  const appFailed = new Promise(resolve => { resolveFailure = resolve; });
  const close = () => closing ??= (async () => {
    try {
      if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
    } finally { await node.close(); }
  })();
  try {
    if (enrollmentKey !== undefined) { await close(); return { close, failed: node.failed }; }
    server = service(config);
    server.once('error', () => resolveFailure());
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(8080, '127.0.0.1', resolve); });
    const failed = Promise.race([node.failed, appFailed]);
    failed.then(() => close().catch(() => {}));
    return { server, failed, close };
  } catch { await close(); fail(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let runtime;
  const stop = () => { runtime?.close().catch(() => { console.error('Synthetic staging shutdown failed.'); process.exitCode = 1; }); };
  try {
    const args = process.argv.slice(2);
    if (args[0] !== '/data/config/staging.json' || (args.length !== 1 && !(args.length === 2 && args[1] === '--enroll'))) fail();
    if (process.getuid() !== 1000 || process.getgid() !== 1000) fail();
    requireNoNewPrivileges();
    if (Object.hasOwn(process.env, 'WHOOP_STAGING_BOOTSTRAP')) fail();
    assertSyntheticEnvironment(process.env);
    const config = readPrivateJson(args[0]);
    const enrollmentKey = args[1] ? await readEnrollmentKey(process.stdin) : undefined;
    runtime = await startSyntheticStaging(config, { enrollmentKey });
    if (enrollmentKey === undefined) {
      for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, stop);
      runtime.failed.then(() => { process.exitCode = 1; });
      console.log('Synthetic fixture service ready on loopback. No WHOOP connection.');
    } else console.log('Synthetic staging node enrollment completed.');
  } catch {
    try { await runtime?.close(); } catch {}
    console.error('Synthetic staging unavailable.'); process.exitCode = 1;
  }
}
