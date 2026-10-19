import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { provisionGateway, gatewayConfiguration } from './gateway-bootstrap.mjs';
import { readStagingGateway, startStagingGateway } from './gateway-runtime.mjs';
import { readPrivateJson } from '../railway/config.mjs';

const TOKEN = `whoopgw_service_${'S'.repeat(43)}`;
const INPUT = { mode: 'synthetic-fixture-only', hostname: 'staging-gateway.test-tailnet.ts.net',
  fixtureHostname: 'staging-backend.test-tailnet.ts.net', fixtureIpv4: '100.72.0.9', ownerSecretHash: 'a'.repeat(64), serviceToken: TOKEN };
const { serviceToken: _token, ...FIELDS } = INPUT;
const MARKER = { ...FIELDS, serviceTokenSha256: createHash('sha256').update(TOKEN).digest('hex') };
function temporary(t, configure = true) {
  assert.equal(process.getuid(), 1000, 'run only in the approved non-root fixture'); assert.equal(process.getgid(), 1000);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'synthetic-gateway-provision-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const name of ['config', 'tailscale', 'app']) fs.mkdirSync(path.join(root, name), { mode: 0o700 });
  if (configure) provisionGateway(INPUT, { root });
  return root;
}
const rewrite = (root, name, value) => fs.writeFileSync(path.join(root, 'config', name), JSON.stringify(value) + '\n');

test('gateway provisioner constructs only fixed gateway role, paths, native callbacks and private token file', t => {
  const root = temporary(t); const { marker, runtime, app } = readStagingGateway({ root });
  assert.deepEqual(marker, MARKER); assert.equal(runtime.role, 'gateway');
  assert.equal(runtime.stateDirectory, '/data/tailscale'); assert.equal(runtime.backendIpv4, '100.72.0.9');
  assert.equal(runtime.appConfigFile, '/data/config/app.json');
  assert.equal(app.databaseFile, '/data/app/gateway.sqlite'); assert.equal(app.port, 8787);
  assert.equal(app.upstreamTokenFile, '/data/config/service-token');
  assert.equal(app.upstreamOrigin, 'https://staging-backend.test-tailnet.ts.net');
  assert.deepEqual(app.clients, [
    { clientId: 'codex', name: 'Codex', redirectUris: ['http://127.0.0.1:17643/callback'] },
    { clientId: 'claude-code', name: 'Claude Code', redirectUris: ['http://localhost:17644/callback'] },
  ]);
  const directory = path.join(root, 'config');
  assert.deepEqual(fs.readdirSync(directory).sort(), ['app.json', 'runtime.json', 'service-token', 'staging-gateway.json']);
  for (const name of fs.readdirSync(directory)) {
    assert.equal(fs.statSync(path.join(directory, name)).mode & 0o777, 0o600);
    assert.equal(fs.statSync(path.join(directory, name)).nlink, 1);
    if (name !== 'service-token') assert.ok(!fs.readFileSync(path.join(directory, name), 'utf8').includes(TOKEN));
  }
  assert.equal(fs.readFileSync(path.join(directory, 'service-token'), 'utf8'), TOKEN + '\n');
  assert.deepEqual(fs.readdirSync(path.join(root, 'tailscale')), []);
  assert.deepEqual(fs.readdirSync(path.join(root, 'app')), []);
  assert.throws(() => provisionGateway(INPUT, { root }));
  assert.deepEqual(readStagingGateway({ root }).marker, MARKER);
});

test('gateway provisioning rejects credential/config injection before any file is written', t => {
  const invalid = [
    { ...INPUT, mode: 'production' }, { ...INPUT, role: 'backend' }, { ...INPUT, ownerSecret: 'secret-sentinel' },
    { ...INPUT, WHOOP_CLIENT_SECRET: 'secret-sentinel' }, { ...INPUT, DATABASE_URL: 'secret-sentinel' },
    { ...INPUT, clients: [{ clientId: 'evil' }] }, { ...INPUT, callback: 'https://evil.test' },
    { ...INPUT, fixtureHostname: INPUT.hostname }, { ...INPUT, fixtureHostname: 'api.prod.whoop.com' },
    { ...INPUT, fixtureIpv4: '100.100.100.100' }, { ...INPUT, fixtureIpv4: '169.254.169.254' },
    { ...INPUT, serviceToken: TOKEN + '\nsecret-sentinel' }, { ...INPUT, ownerSecretHash: 'secret-sentinel' },
  ];
  for (const raw of invalid) {
    const root = temporary(t, false); assert.throws(() => provisionGateway(raw, { root }));
    assert.deepEqual(fs.readdirSync(path.join(root, 'config')), []);
  }
  assert.throws(() => gatewayConfiguration({ ...MARKER, role: 'backend' }));
});

test('partial provisioning and tampered marker, role, callbacks or token fail before runtime/enrollment', async t => {
  const mutations = [
    root => fs.unlinkSync(path.join(root, 'config/staging-gateway.json')),
    root => rewrite(root, 'staging-gateway.json', { ...MARKER, mode: 'production' }),
    root => rewrite(root, 'staging-gateway.json', { ...MARKER, role: 'backend' }),
    root => { const raw = readPrivateJson(path.join(root, 'config/runtime.json')); raw.role = 'backend'; rewrite(root, 'runtime.json', raw); },
    root => { const raw = readPrivateJson(path.join(root, 'config/app.json')); raw.clients[0].redirectUris = ['http://127.0.0.1:17643/evil']; rewrite(root, 'app.json', raw); },
    root => { const raw = readPrivateJson(path.join(root, 'config/app.json')); raw.upstreamOrigin = 'https://other.test-tailnet.ts.net'; rewrite(root, 'app.json', raw); },
    root => fs.writeFileSync(path.join(root, 'config/service-token'), `whoopgw_service_${'T'.repeat(43)}\n`),
  ];
  for (const mutate of mutations) {
    const root = temporary(t); mutate(root); let called = false;
    await assert.rejects(startStagingGateway({ root, enrollmentKey: 'synthetic-injected-enrollment', deploy: async () => { called = true; } }));
    assert.equal(called, false);
  }
});

test('gateway wrapper refuses root, wrong GID, symlinked configs and multiply-linked token before startup', async t => {
  const root = temporary(t);
  for (const [uid, gid] of [[0, 0], [0, 1000], [1000, 0], [1001, 1000]]) {
    let called = false;
    await assert.rejects(startStagingGateway({ root, identity: { getuid: () => uid, getgid: () => gid }, deploy: async () => { called = true; } }));
    assert.equal(called, false);
  }
  const app = path.join(root, 'config/app.json'); const moved = path.join(root, 'config/old-app.json');
  fs.renameSync(app, moved); fs.symlinkSync(moved, app);
  assert.throws(() => readStagingGateway({ root }));
  fs.unlinkSync(app); fs.renameSync(moved, app);
  const token = path.join(root, 'config/service-token'); const copy = path.join(root, 'config/other-token');
  fs.linkSync(token, copy); assert.throws(() => readStagingGateway({ root }));
  fs.unlinkSync(copy); assert.deepEqual(readStagingGateway({ root }).marker, MARKER);
});

test('verified synthetic wrapper alone enables gateway relay mode with separate enrollment', async t => {
  const root = temporary(t); const expected = gatewayConfiguration(MARKER); const calls = [];
  const deploy = async (runtime, options) => {
    calls.push(options.enrollmentKey); assert.deepEqual(runtime, expected.runtime);
    assert.equal(options.syntheticStagingRelayOnly, true);
    assert.deepEqual(options.readAppConfig('/data/config/app.json'), expected.app);
    assert.throws(() => options.readAppConfig('/data/config/other.json'));
    return { close: async () => {}, failed: new Promise(() => {}) };
  };
  await startStagingGateway({ root, deploy });
  await startStagingGateway({ root, deploy, enrollmentKey: 'synthetic-injected-enrollment' });
  assert.deepEqual(calls, [undefined, 'synthetic-injected-enrollment']);
});
