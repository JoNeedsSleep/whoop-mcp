import { pathToFileURL } from 'node:url';
import { readPrivateJson } from '../railway/config.mjs';
import { startTailscale } from '../railway/tailscale-supervisor.mjs';
import { requireNoNewPrivileges } from '../staging/runtime-check.mjs';
import { createIdentityServer, parseIdentityConfig } from './verify.mjs';

const fail = () => { throw new Error('IDENTITY_UNAVAILABLE'); };
export async function startIdentityVerification({ args = [], identity = process, environment = process.env,
  noNewPrivileges = requireNoNewPrivileges, readConfig = readPrivateJson, tailscale = startTailscale,
  createService = createIdentityServer } = {}) {
  let node; let service; let closing;
  const close = () => closing ??= (async () => { try { return await service?.close(); } finally { await node?.close(); } })();
  try {
    if ([identity.getuid(), identity.getgid(), identity.geteuid(), identity.getegid()].some(id => id !== 1000)) fail();
    noNewPrivileges();
    if (!Array.isArray(args) || args.length !== 0 || Object.keys(environment).some(key =>
      /^(?:WHOOP_|PG|DATABASE|TS_AUTH)/.test(key) || ['NODE_OPTIONS', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'SSLKEYLOGFILE', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'].includes(key))) fail();
    process.umask(0o077);
    const config = parseIdentityConfig(readConfig('/data/config/identity.json', 8192));
    // Reuse only the existing exact backend node. No enrollment capability.
    node = await tailscale({ stateDirectory: '/data/tailscale', tag: 'tag:whoop-backend', hostname: config.hostname, port: 8080 });
    service = createService(config);
    await new Promise((resolve, reject) => {
      service.server.once('error', reject); service.server.listen(8080, '127.0.0.1', resolve);
    });
    const serverFailure = new Promise(resolve => service.server.once('error', () => resolve(false)));
    const done = Promise.race([service.done, node.failed.then(() => false), serverFailure]);
    return { close, done };
  } catch { try { await close(); } catch {} fail(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let runtime;
  const stop = () => { void runtime?.close().catch(() => { process.exitCode = 1; }); };
  try {
    runtime = await startIdentityVerification({ args: process.argv.slice(2) });
    for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, stop);
    console.log('Temporary profile-only verification is ready on the approved private origin.');
    const completed = await runtime.done; const cleanup = await runtime.close();
    if (!completed || cleanup?.revoked !== true) fail();
    console.log('Profile-only verification completed and temporary grant revoked.');
  } catch { try { await runtime?.close(); } catch {} console.error('Identity verification unavailable.'); process.exitCode = 1; }
}
