import { pathToFileURL } from 'node:url';
import { parseDeploymentConfig, readPrivateJson } from './config.mjs';
import { startDeployment } from './runtime.mjs';
import { readEnrollmentKey } from './tailscale-supervisor.mjs';
import { requireNoNewPrivileges } from '../staging/runtime-check.mjs';

const fail = () => { throw new Error('GATEWAY_RUNTIME_UNAVAILABLE'); };
const CONFIG_FILE = '/data/config/runtime.json';

// Injection is for isolated tests only. The production CLI supplies just its
// arguments; neither configuration nor environment can select dependencies.
export async function startGatewayRuntime({ args = [CONFIG_FILE], identity = process, environment = process.env,
  noNewPrivileges = requireNoNewPrivileges, readConfig = readPrivateJson, readKey = readEnrollmentKey,
  input = process.stdin, deploy = startDeployment } = {}) {
  try {
    if ([identity.getuid(), identity.getgid(), identity.geteuid(), identity.getegid()].some(id => id !== 1000)) fail();
    noNewPrivileges();
    // Reject presence without reading values or forwarding inherited environment.
    if (Object.keys(environment).some(name => /^WHOOP_(?:[A-Z0-9_]+_)?BOOTSTRAP$/.test(name))) fail();
    if (!Array.isArray(args) || args[0] !== CONFIG_FILE ||
        (args.length !== 1 && !(args.length === 2 && args[1] === '--enroll'))) fail();
    process.umask(0o077);
    const config = parseDeploymentConfig(readConfig(CONFIG_FILE));
    if (config.role !== 'gateway') fail();
    const enrolled = args.length === 2;
    const enrollmentKey = enrolled ? await readKey(input) : undefined;
    // Keep the shared runtime's fixed gateway role, private TLS upstream and
    // enrollment-without-app behavior. No backend can be selected by this image.
    const runtime = await deploy(config, { enrollmentKey });
    return { runtime, enrolled };
  } catch { fail(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let runtime;
  try {
    const started = await startGatewayRuntime({ args: process.argv.slice(2) });
    runtime = started.runtime;
    if (started.enrolled) console.log('Dedicated WHOOP gateway node enrollment completed.');
    else {
      const stop = () => runtime.close().catch(() => { console.error('WHOOP gateway shutdown failed.'); process.exitCode = 1; });
      for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, stop);
      runtime.failed.then(() => { process.exitCode = 1; });
      console.log('Private WHOOP gateway runtime started.');
    }
  } catch {
    try { await runtime?.close(); } catch {}
    console.error('Private WHOOP gateway runtime unavailable.'); process.exitCode = 1;
  }
}
