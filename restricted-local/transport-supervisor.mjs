import { pathToFileURL } from 'node:url';
import { fail, tailnetIpv4 } from '../deploy/railway/config.mjs';
import { startTailscale, readEnrollmentKey } from '../deploy/railway/tailscale-supervisor.mjs';
import { startRelay } from './fixed-relay.mjs';

export async function startLocalTransport(clientId, gatewayIpv4, { enrollmentKey, stateDirectory = '/state',
  socketPath = '/transport/gateway.sock', tailscale = startTailscale, relay = startRelay } = {}) {
  if (!['codex', 'claude-code'].includes(clientId)) fail();
  tailnetIpv4(gatewayIpv4);
  const node = await tailscale({ stateDirectory, tag: `tag:whoop-local-${clientId}`, enrollmentKey });
  let transport;
  let closing;
  const close = () => closing ??= (async () => { try { await transport?.close(); } finally { await node.close(); } })();
  try {
    if (enrollmentKey !== undefined) { await close(); return { close, failed: node.failed }; }
    transport = await relay({ socketPath, targetIpv4: gatewayIpv4, socksPort: 1055 });
    node.failed.then(() => close().catch(() => {}));
    return { close, failed: node.failed };
  } catch { await close(); fail(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let runtime;
  try {
    const args = process.argv.slice(2);
    if (args.length !== 2 && !(args.length === 3 && args[2] === '--enroll')) fail();
    const enrollmentKey = args[2] ? await readEnrollmentKey(process.stdin) : undefined;
    runtime = await startLocalTransport(args[0], args[1], { enrollmentKey });
    if (enrollmentKey === undefined) {
      for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => runtime.close());
      runtime.failed.then(() => { process.exitCode = 1; });
      console.log('Private transport ready.');
    } else console.log('Dedicated transport enrollment completed.');
  } catch {
    await runtime?.close(); console.error('Private transport unavailable.'); process.exitCode = 1;
  }
}
