// Temporary staging variable bootstrap. The per-image entrypoint fixes the role.
// This never starts an application; completion waits for an operator redeploy.
import path from 'node:path';
import { exact } from '../railway/config.mjs';
import { startTailscale } from '../railway/tailscale-supervisor.mjs';
import { assertSyntheticEnvironment, parseStagingConfig } from './service.mjs';
import { holdForProvisioning, provisionFixture } from './bootstrap.mjs';
import { emitRuntimeCheck, requireNoNewPrivileges } from './runtime-check.mjs';

export const BOOTSTRAP_VARIABLE = 'WHOOP_STAGING_BOOTSTRAP';
const fail = () => { throw new Error('STAGING_BOOTSTRAP_UNAVAILABLE'); };
export async function provisionFromEnvironment(role, { env = process.env, identity = process, root = '/data', enroll = startTailscale,
  runtimeCheck = emitRuntimeCheck, noNewPrivileges = requireNoNewPrivileges } = {}) {
  // Do not read secret-bearing input while privileged, even if malformed.
  if (identity.getuid() !== 1000 || identity.getgid() !== 1000 || !['fixture', 'gateway'].includes(role)) fail();
  noNewPrivileges();
  const encoded = env[BOOTSTRAP_VARIABLE];
  delete env[BOOTSTRAP_VARIABLE];
  assertSyntheticEnvironment(env);
  if (typeof encoded !== 'string' || !encoded.isWellFormed() || Buffer.byteLength(encoded) > 8192) fail();
  let payload;
  try { payload = JSON.parse(encoded); } catch { fail(); }
  exact(payload, ['mode', 'role', 'config', 'enrollmentKey']);
  if (payload.mode !== 'synthetic-fixture-only' || payload.role !== role || typeof payload.enrollmentKey !== 'string' ||
      !/^tskey-auth-[A-Za-z0-9_-]{20,220}$/.test(payload.enrollmentKey)) fail();

  // Complete pure validation before any file can be created. The existing
  // exclusive configuration is the durable one-attempt marker: a retry after
  // partial enrollment or a used key cannot reach the daemon again.
  let hostname; let provision;
  if (role === 'fixture') {
    hostname = parseStagingConfig(payload.config).hostname;
    provision = () => provisionFixture(payload.config, { root });
  } else {
    const { parseGatewayProvision, provisionGateway } = await import('./gateway-bootstrap.mjs');
    hostname = parseGatewayProvision(payload.config).config.marker.hostname;
    provision = () => provisionGateway(payload.config, { root });
  }
  runtimeCheck();
  provision();
  const node = await enroll({ stateDirectory: path.join(root, 'tailscale'),
    tag: role === 'fixture' ? 'tag:whoop-backend' : 'tag:whoop-gateway',
    hostname, port: role === 'fixture' ? 8080 : 8787, enrollmentKey: payload.enrollmentKey });
  await node.close();
  return { role, phase: 'enrolled-awaiting-clean-redeploy' };
}

export async function runProvisioner(role) {
  try {
    process.umask(0o077);
    if (process.argv.length !== 2) fail();
    await provisionFromEnvironment(role);
    holdForProvisioning();
    console.log('Staging node enrolled; revoke the one-use key, remove the bootstrap variable, and redeploy normally. No application started.');
  } catch {
    console.error('Staging bootstrap unavailable; inspect the stopped staging configuration before retrying.');
    process.exitCode = 1;
  }
}
