import fs from 'node:fs';
import path from 'node:path';
import { createHash, timingSafeEqual } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { pathToFileURL } from 'node:url';
import { privateDirectory, readPrivateJson } from '../railway/config.mjs';
import { startDeployment } from '../railway/runtime.mjs';
import { readEnrollmentKey } from '../railway/tailscale-supervisor.mjs';
import { assertSyntheticEnvironment } from './service.mjs';
import { gatewayConfiguration } from './gateway-bootstrap.mjs';
import { requireNoNewPrivileges } from './runtime-check.mjs';

const fail = () => { throw new Error('STAGING_GATEWAY_UNAVAILABLE'); };
export function readStagingGateway({ root = '/data', identity = process } = {}) {
  if (identity.getuid() !== 1000 || identity.getgid() !== 1000) fail();
  for (const name of ['config', 'tailscale', 'app']) privateDirectory(path.join(root, name));
  const directory = path.join(root, 'config');
  const expected = gatewayConfiguration(readPrivateJson(path.join(directory, 'staging-gateway.json')));
  if (!isDeepStrictEqual(readPrivateJson(path.join(directory, 'runtime.json')), expected.runtime) ||
      !isDeepStrictEqual(readPrivateJson(path.join(directory, 'app.json')), expected.app)) fail();
  const fd = fs.openSync(path.join(directory, 'service-token'), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.uid !== 1000 || st.nlink !== 1 || (st.mode & 0o077) || st.size > 128) fail();
    const buffer = Buffer.alloc(129); const count = fs.readSync(fd, buffer);
    const value = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, count));
    if (!/^whoopgw_service_[A-Za-z0-9_-]{43}\n$/.test(value) ||
        !timingSafeEqual(createHash('sha256').update(value.slice(0, -1)).digest(), Buffer.from(expected.marker.serviceTokenSha256, 'hex'))) fail();
  } finally { fs.closeSync(fd); }
  return expected;
}

export async function startStagingGateway({ enrollmentKey, root = '/data', identity = process, deploy = startDeployment } = {}) {
  const expected = readStagingGateway({ root, identity });
  // The verified synthetic wrapper alone enables this pinned-vendor workaround.
  // Real deployments and local transports keep the ordinary default transport.
  return deploy(expected.runtime, { enrollmentKey, syntheticStagingRelayOnly: true, readAppConfig: filename => {
    if (filename !== '/data/config/app.json') fail();
    return structuredClone(expected.app);
  } });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let runtime;
  try {
    process.umask(0o077);
    const args = process.argv.slice(2);
    if (process.getuid() !== 1000 || process.getgid() !== 1000 || args[0] !== '/data/config/staging-gateway.json' ||
        (args.length !== 1 && !(args.length === 2 && args[1] === '--enroll'))) fail();
    requireNoNewPrivileges();
    assertSyntheticEnvironment(process.env);
    if (Object.hasOwn(process.env, 'WHOOP_STAGING_BOOTSTRAP')) fail();
    const enrollmentKey = args[1] ? await readEnrollmentKey(process.stdin) : undefined;
    runtime = await startStagingGateway({ enrollmentKey });
    if (enrollmentKey === undefined) {
      const stop = () => runtime.close().catch(() => { console.error('Staging gateway shutdown failed.'); process.exitCode = 1; });
      for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, stop);
      runtime.failed.then(() => { process.exitCode = 1; });
      console.log('Staging gateway started with synthetic fixture configuration.');
    } else console.log('Dedicated staging gateway node enrollment completed.');
  } catch {
    try { await runtime?.close(); } catch {}
    console.error('Staging gateway unavailable.'); process.exitCode = 1;
  }
}
