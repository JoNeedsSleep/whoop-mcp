// Staging-only gateway provisioning; the production runtime/schema are unchanged.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { exact, privateDirectory, tailnetHostname, tailnetIpv4 } from '../railway/config.mjs';
import { parseGatewayConfig } from '../../review-gateway/config.mjs';
import { assertSyntheticEnvironment } from './service.mjs';
import { holdForProvisioning, initializeVolume, readProvisioningJson, writePrivateExclusive } from './bootstrap.mjs';
import { emitRuntimeCheck, requireNoNewPrivileges } from './runtime-check.mjs';

const fail = () => { throw new Error('STAGING_PROVISIONING_UNAVAILABLE'); };
const TOKEN = /^whoopgw_service_[A-Za-z0-9_-]{43}$/;
const MARKER_KEYS = ['mode', 'hostname', 'fixtureHostname', 'fixtureIpv4', 'ownerSecretHash', 'serviceTokenSha256'];
export function gatewayConfiguration(raw) {
  exact(raw, MARKER_KEYS);
  if (raw.mode !== 'synthetic-fixture-only' || raw.hostname === raw.fixtureHostname ||
      ![raw.ownerSecretHash, raw.serviceTokenSha256].every(value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value))) fail();
  tailnetHostname(raw.hostname); tailnetHostname(raw.fixtureHostname); tailnetIpv4(raw.fixtureIpv4);
  const runtime = { role: 'gateway', hostname: raw.hostname, stateDirectory: '/data/tailscale',
    appConfigFile: '/data/config/app.json', backendIpv4: raw.fixtureIpv4 };
  const app = parseGatewayConfig({ publicOrigin: `https://${raw.hostname}`, upstreamOrigin: `https://${raw.fixtureHostname}`,
    upstreamTokenFile: '/data/config/service-token', ownerSecretHash: raw.ownerSecretHash,
    databaseFile: '/data/app/gateway.sqlite', port: 8787,
    clients: [
      { clientId: 'codex', name: 'Codex', redirectUris: ['http://127.0.0.1:17643/callback'] },
      { clientId: 'claude-code', name: 'Claude Code', redirectUris: ['http://localhost:17644/callback'] },
    ] });
  return { marker: structuredClone(raw), runtime, app };
}

export function parseGatewayProvision(raw) {
  exact(raw, ['mode', 'hostname', 'fixtureHostname', 'fixtureIpv4', 'ownerSecretHash', 'serviceToken']);
  if (typeof raw.serviceToken !== 'string' || !TOKEN.test(raw.serviceToken)) fail();
  const { serviceToken, ...fields } = raw;
  const config = gatewayConfiguration({ ...fields, serviceTokenSha256: createHash('sha256').update(serviceToken).digest('hex') });
  return { serviceToken, config };
}

export function provisionGateway(raw, { root = '/data' } = {}) {
  if (process.getuid() !== 1000 || process.getgid() !== 1000) fail();
  const { serviceToken, config } = parseGatewayProvision(raw);
  for (const name of ['config', 'tailscale', 'app']) {
    const directory = path.join(root, name);
    privateDirectory(directory);
    if (fs.readdirSync(directory).length !== 0) fail();
  }
  const directory = path.join(root, 'config');
  // Marker is last. Partial provisioning remains private and cannot start this
  // staging runtime; explicit inspection is required instead of overwriting it.
  writePrivateExclusive(path.join(directory, 'service-token'), serviceToken + '\n');
  writePrivateExclusive(path.join(directory, 'app.json'), JSON.stringify(config.app) + '\n');
  writePrivateExclusive(path.join(directory, 'runtime.json'), JSON.stringify(config.runtime) + '\n');
  writePrivateExclusive(path.join(directory, 'staging-gateway.json'), JSON.stringify(config.marker) + '\n');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.umask(0o077); requireNoNewPrivileges(); assertSyntheticEnvironment(process.env);
    const args = process.argv.slice(2);
    if (args.length !== 1) fail();
    if (args[0] === 'init-volume') {
      initializeVolume({ role: 'gateway' });
      process.setgroups([]); process.setgid(1000); process.setuid(1000);
      emitRuntimeCheck();
      holdForProvisioning();
      console.log('Empty staging gateway volume prepared; non-root hold. No service or enrollment started.');
    } else if (args[0] === 'hold') {
      holdForProvisioning();
      console.log('Staging gateway provisioning hold. No service or enrollment started.');
    } else if (args[0] === 'configure-gateway') {
      provisionGateway(await readProvisioningJson(process.stdin));
      console.log('Synthetic staging gateway configuration created.');
    } else fail();
  } catch { console.error('Staging gateway provisioning unavailable.'); process.exitCode = 1; }
}
