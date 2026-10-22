import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { requireNoNewPrivileges } from '../staging/runtime-check.mjs';
import { createLocalViewServer, parseLocalViewConfig } from './session.mjs';
import { createLoopbackIngress } from '../identity/loopback-ingress.mjs';

const fail = () => { throw new Error('LOCAL_VIEW_UNAVAILABLE'); };
function guards(identity, environment, args, noNewPrivileges) {
  if ([identity.getuid(), identity.geteuid(), identity.getgid(), identity.getegid()].some(id => id !== 1000)) fail();
  noNewPrivileges();
  if (!Array.isArray(args) || !(args.length === 0 || (args.length === 1 && args[0] === 'container-edge')) || Object.keys(environment).length !== 1 ||
      environment.PATH !== '/usr/local/bin:/usr/bin:/bin') fail();
}
async function readInput(input, signal) {
  if (input.isTTY || signal?.aborted) fail();
  let size = 0; const chunks = [];
  const abort = () => input.destroy(new Error('LOCAL_VIEW_UNAVAILABLE'));
  const timer = setTimeout(abort, 5000); signal?.addEventListener('abort', abort, { once: true });
  try {
    for await (const chunk of input) {
      const bytes = Buffer.from(chunk); size += bytes.length; if (size > 8192) fail(); chunks.push(bytes);
    }
    if (signal?.aborted || size < 2) fail();
    return parseLocalViewConfig(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))));
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
}

// No config files, Tailscale daemon, enrollment, database or persistence. The
// external entrypoint strips inherited configuration before Node starts.
export async function startLocalView({ input = process.stdin, args = [], identity = process,
  environment = process.env, noNewPrivileges = requireNoNewPrivileges, signal,
  serviceOptions = {} } = {}) {
  let service; let ingress; let closing;
  const close = () => closing ??= (async () => {
    try { await ingress?.close(); } finally { return await service?.close(); }
  })();
  const stop = () => { void close(); };
  try {
    guards(identity, environment, args, noNewPrivileges);
    const config = await readInput(input, signal); if (signal?.aborted) fail();
    const marker = randomBytes(32).toString('base64url');
    service = createLocalViewServer(config, { ...serviceOptions, loopbackMarker: marker });
    await new Promise((resolve, reject) => { service.server.once('error', reject); service.server.listen(0, '127.0.0.1', resolve); });
    // Explicit container-only mode is paired with independently verified
    // host-127.0.0.1 publication and namespace firewall. It is never the default.
    const containerEdge = args[0] === 'container-edge';
    ingress = createLoopbackIngress(service.server, marker, { containerEdge });
    await new Promise((resolve, reject) => { ingress.server.once('error', reject); ingress.server.listen(17645, containerEdge ? '0.0.0.0' : '127.0.0.1', resolve); });
    signal?.addEventListener('abort', stop, { once: true });
    if (signal?.aborted) { await close(); fail(); }
    const failed = new Promise(resolve => {
      service.server.once('error', () => resolve(false)); ingress.server.once('error', () => resolve(false));
    });
    const done = Promise.race([service.done, failed]);
    return { server: ingress.server, core: service.server, done, close: async () => {
      signal?.removeEventListener('abort', stop); return close();
    } };
  } catch { signal?.removeEventListener('abort', stop); await close(); fail(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let runtime; const controller = new AbortController(); const stop = () => controller.abort();
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  try {
    runtime = await startLocalView({ args: process.argv.slice(2), signal: controller.signal });
    console.log('Temporary local WHOOP viewer is ready.');
    const completed = await runtime.done; const cleanup = await runtime.close();
    if (!completed || cleanup?.revoked !== true) fail();
    console.log('Temporary local WHOOP view completed and grant revoked.');
  } catch { try { await runtime?.close(); } catch {} console.error('Local WHOOP viewer unavailable.'); process.exitCode = 1; }
  finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
