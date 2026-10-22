import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { backendEnvironment, fail, parseDeploymentConfig, privateDirectory, readBackendDatabaseCa, readPrivateJson, tailnetHostname } from './config.mjs';
import { startTailscale, readEnrollmentKey } from './tailscale-supervisor.mjs';

async function startBackend(env) {
  const child = spawn('/usr/local/bin/node', ['/app/backend/dist/index.js'], {
    cwd: '/app/backend', env, stdio: 'ignore',
  });
  let ended = false;
  const failed = new Promise(resolve => {
    child.once('error', () => { ended = true; resolve(); });
    child.once('exit', () => { ended = true; resolve(); });
  });
  const close = async () => {
    if (ended) return;
    child.kill('SIGTERM'); const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
    await failed; clearTimeout(timer);
  };
  return { failed, close };
}
async function startPrivateGateway(raw, backendIpv4) {
  const [{ startGateway }, { startRelay }, { createUnixFetch }] = await Promise.all([
    import('../../review-gateway/index.mjs'), import('../../restricted-local/fixed-relay.mjs'), import('../../restricted-local/unix-https.mjs'),
  ]);
  // A per-process scratch directory avoids reviving a stale persistent socket
  // after an abrupt process exit. It contains no credential or node state.
  const directory = fs.mkdtempSync('/tmp/whoop-backend-relay-');
  privateDirectory(directory);
  const socketPath = path.join(directory, 'backend.sock');
  const relay = await startRelay({ socketPath, targetIpv4: backendIpv4, socksPort: 1055 });
  let gateway;
  try {
    gateway = startGateway(raw, { fetchImpl: createUnixFetch({ origin: raw.upstreamOrigin, socketPath, allowedPaths: ['/internal/health-summary'] }) });
  } catch { await relay.close(); fs.rmdirSync(directory); fail(); }
  const failed = new Promise(resolve => { gateway.server.once('error', resolve); });
  let closing;
  const close = () => closing ??= (async () => {
    gateway.server.closeAllConnections();
    await new Promise(resolve => gateway.server.close(resolve));
    gateway.store.close(); await relay.close(); fs.rmdirSync(directory);
  })();
  return { failed, close };
}
export function validateAppConfig(config, raw) {
  if (config.role === 'backend') return backendEnvironment(raw, config.hostname);
  if (raw?.publicOrigin !== `https://${config.hostname}` || raw.port !== 8787 || raw.databaseFile !== '/data/app/gateway.sqlite' ||
      raw.upstreamTokenFile !== '/data/config/service-token' || typeof raw.upstreamOrigin !== 'string') fail();
  let upstream;
  try { upstream = new URL(raw.upstreamOrigin); } catch { fail(); }
  tailnetHostname(upstream.hostname);
  if (raw.upstreamOrigin !== `https://${upstream.hostname}` || upstream.hostname === config.hostname) fail();
  return raw;
}
export async function startDeployment(raw, { enrollmentKey, gatewayRelayOnly = false, tailscale = startTailscale,
  readAppConfig = readPrivateJson, readDatabaseCa = readBackendDatabaseCa, backend = startBackend, gateway = startPrivateGateway } = {}) {
  process.umask(0o077);
  const config = parseDeploymentConfig(raw);
  if (typeof gatewayRelayOnly !== 'boolean' || (gatewayRelayOnly && config.role !== 'gateway')) fail();
  const appConfig = enrollmentKey === undefined ? validateAppConfig(config, readAppConfig(config.appConfigFile)) : undefined;
  if (enrollmentKey === undefined && config.role === 'backend') readDatabaseCa();
  const node = await tailscale({ stateDirectory: config.stateDirectory, tag: `tag:whoop-${config.role}`, hostname: config.hostname,
    port: config.role === 'gateway' ? 8787 : 8080, enrollmentKey,
    ...(gatewayRelayOnly ? { gatewayRelayOnly: true } : {}) });
  let app; let closing;
  const close = () => closing ??= (async () => { try { await app?.close(); } finally { await node.close(); } })();
  try {
    if (enrollmentKey !== undefined) { await close(); return { close, failed: node.failed }; }
    app = config.role === 'gateway' ? await gateway(appConfig, config.backendIpv4) : await backend(appConfig);
    const failed = Promise.race([node.failed, app.failed]);
    failed.then(() => close().catch(() => {}));
    return { close, failed };
  } catch { await close(); fail(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let runtime;
  try {
    const args = process.argv.slice(2);
    if (args[0] !== '/data/config/runtime.json' || (args.length !== 1 && !(args.length === 2 && args[1] === '--enroll'))) fail();
    const config = readPrivateJson(args[0]);
    const enrollmentKey = args[1] ? await readEnrollmentKey(process.stdin) : undefined;
    runtime = await startDeployment(config, { enrollmentKey });
    if (enrollmentKey === undefined) {
      for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => runtime.close());
      runtime.failed.then(() => { process.exitCode = 1; });
      console.log('Private service runtime started.');
    } else console.log('Dedicated service enrollment completed.');
  } catch { await runtime?.close(); console.error('Private service runtime unavailable.'); process.exitCode = 1; }
}
