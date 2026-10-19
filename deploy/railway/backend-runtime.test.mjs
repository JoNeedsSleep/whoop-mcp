import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { startBackendRuntime } from './backend-runtime.mjs';
import { startDeployment } from './runtime.mjs';
import { readPrivateJson } from './config.mjs';

const CONFIG = { role: 'backend', hostname: 'backend.test-tailnet.ts.net',
  stateDirectory: '/data/tailscale', appConfigFile: '/data/config/app.json' };
const identity = values => Object.fromEntries(['getuid', 'getgid', 'geteuid', 'getegid'].map((key, index) => [key, () => values?.[index] ?? 1000]));
const failure = { message: 'BACKEND_RUNTIME_UNAVAILABLE' };
const forbidden = () => { assert.fail('unexpected operation'); };
const runtime = () => ({ close: async () => {}, failed: new Promise(() => {}) });
const options = overrides => ({ identity: identity(), environment: {}, noNewPrivileges: () => {},
  readConfig: () => CONFIG, readKey: forbidden, deploy: async () => runtime(), ...overrides });

test('backend requires real and effective UID/GID1000 before kernel, environment, config or input access', async () => {
  for (let index = 0; index < 4; index++) for (const invalid of [0, 1001]) {
    const ids = [1000, 1000, 1000, 1000]; ids[index] = invalid;
    const events = [];
    const result = options({ identity: identity(ids), noNewPrivileges: () => events.push('kernel'),
      environment: new Proxy({}, { ownKeys() { events.push('environment'); return []; } }),
      readConfig: () => events.push('config'), readKey: () => events.push('input'), deploy: () => events.push('deploy') });
    await assert.rejects(startBackendRuntime(result), failure);
    assert.deepEqual(events, []);
  }
});

test('missing no-new-privileges fails before environment values, files, input or runtime', async () => {
  const events = [];
  await assert.rejects(startBackendRuntime(options({ noNewPrivileges: () => { throw Error('private kernel diagnostic'); },
    environment: new Proxy({}, { ownKeys() { events.push('environment'); return []; } }),
    readConfig: () => events.push('config'), readKey: () => events.push('input'), deploy: () => events.push('deploy') })), failure);
  assert.deepEqual(events, []);
});

test('backend refuses bootstrap presence without evaluating secret getters', async () => {
  for (const name of ['WHOOP_BOOTSTRAP', 'WHOOP_STAGING_BOOTSTRAP', 'WHOOP_BACKEND_BOOTSTRAP']) {
    let valueRead = false; let fileRead = false;
    const environment = Object.defineProperty({}, name, { enumerable: true, get() { valueRead = true; throw Error('secret sentinel'); } });
    await assert.rejects(startBackendRuntime(options({ environment, readConfig: () => { fileRead = true; } })), failure);
    assert.equal(valueRead, false); assert.equal(fileRead, false);
    await assert.rejects(startBackendRuntime(options({ environment: { [name]: '' }, readConfig: forbidden })), failure);
  }
});

test('only fixed config path and explicit enrollment flag are accepted', async () => {
  for (const args of [[], ['/tmp/config.json'], ['/data/config/runtime.json', '--gateway'],
    ['/data/config/runtime.json', '--enroll', 'extra'], '/data/config/runtime.json', null]) {
    await assert.rejects(startBackendRuntime(options({ args, readConfig: forbidden })), failure);
  }
});

test('gateway, unknown role and extra config fields fail before consuming enrollment input', async () => {
  for (const config of [{ ...CONFIG, role: 'gateway', backendIpv4: '100.72.0.9' },
    { ...CONFIG, role: 'fixture' }, { ...CONFIG, backendIpv4: '100.72.0.9' },
    { ...CONFIG, stateDirectory: '/host' }]) {
    let called = false;
    await assert.rejects(startBackendRuntime(options({ args: ['/data/config/runtime.json', '--enroll'],
      readConfig: () => config, readKey: () => { called = true; }, deploy: () => { called = true; } })), failure);
    assert.equal(called, false);
  }
});

test('normal backend dispatch follows guards and passes no inherited environment or enrollment input', async () => {
  const events = []; const started = runtime();
  const result = await startBackendRuntime(options({ environment: { NODE_OPTIONS: 'secret sentinel', HTTP_PROXY: 'secret sentinel' },
    noNewPrivileges: () => events.push('kernel'), readConfig: filename => { events.push('config'); assert.equal(filename, '/data/config/runtime.json'); return CONFIG; },
    deploy: async (config, settings) => { events.push('deploy'); assert.deepEqual(config, CONFIG); assert.notEqual(config, CONFIG);
      assert.deepEqual(settings, { enrollmentKey: undefined }); return started; } }));
  assert.deepEqual(events, ['kernel', 'config', 'deploy']);
  assert.deepEqual(result, { runtime: started, enrolled: false });
});

test('enrollment remains explicit, reads only injected input after role checks, and never starts backend', async () => {
  const events = []; const input = {}; const key = 'synthetic-enrollment'; let closed = false;
  const result = await startBackendRuntime(options({ args: ['/data/config/runtime.json', '--enroll'], input,
    readKey: async stream => { events.push('input'); assert.equal(stream, input); return key; },
    deploy: (config, settings) => startDeployment(config, { ...settings, readAppConfig: forbidden, backend: forbidden, gateway: forbidden,
      tailscale: async node => { events.push('node'); assert.deepEqual(node, { stateDirectory: '/data/tailscale', tag: 'tag:whoop-backend',
        hostname: CONFIG.hostname, port: 8080, enrollmentKey: key }); return { failed: new Promise(() => {}), close: async () => { closed = true; } }; } }) }));
  assert.deepEqual(events, ['input', 'node']); assert.equal(result.enrolled, true); assert.equal(closed, true);
});

test('shared backend dispatch fixes child environment, role, port and disabled migrations without gateway dispatch', async () => {
  let nodeClosed = false; let appClosed = false;
  const raw = Object.fromEntries(['DATABASE_URL', 'ENCRYPTION_KEY', 'WHOOP_CLIENT_ID', 'WHOOP_CLIENT_SECRET', 'SESSION_SECRET',
    'ALLOWED_WHOOP_USER_ID', 'GATEWAY_SERVICE_TOKEN_SHA256'].map(key => [key, 'synthetic']));
  raw.PUBLIC_BASE_URL = 'https://' + CONFIG.hostname;
  const started = await startBackendRuntime(options({ deploy: (config, settings) => startDeployment(config, { ...settings,
    readAppConfig: filename => { assert.equal(filename, CONFIG.appConfigFile); return raw; }, gateway: forbidden,
    tailscale: async node => { assert.equal(node.tag, 'tag:whoop-backend'); assert.equal(node.port, 8080);
      return { failed: new Promise(() => {}), close: async () => { nodeClosed = true; } }; },
    backend: async env => { assert.deepEqual(env, { ...raw, PATH: '/usr/local/bin:/usr/bin:/bin', NODE_ENV: 'production',
      BIND_HOST: '127.0.0.1', PORT: '8080', RUN_MIGRATIONS: 'false', ENABLE_LEGACY_DIRECT_MCP: 'false', APPROVED_CLIENT_REDIRECT_URIS: '' });
      return { failed: new Promise(() => {}), close: async () => { appClosed = true; } }; } }) }));
  await started.runtime.close(); assert.equal(nodeClosed, true); assert.equal(appClosed, true);
});

test('unsafe real config files and malformed private content become fixed errors before dispatch', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'backend-role-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.chmodSync(directory, 0o700); const filename = path.join(directory, 'runtime.json');
  const readConfig = () => readPrivateJson(filename);
  for (const raw of ['{"secret-sentinel":', JSON.stringify(CONFIG) + 'secret-sentinel']) {
    fs.writeFileSync(filename, raw, { mode: 0o600 });
    await assert.rejects(startBackendRuntime(options({ readConfig, deploy: forbidden })), failure);
  }
  fs.writeFileSync(filename, JSON.stringify(CONFIG)); fs.chmodSync(filename, 0o644);
  await assert.rejects(startBackendRuntime(options({ readConfig, deploy: forbidden })), failure);
  fs.chmodSync(filename, 0o600); const link = path.join(directory, 'link.json'); fs.symlinkSync(filename, link);
  await assert.rejects(startBackendRuntime(options({ readConfig: () => readPrivateJson(link), deploy: forbidden })), failure);
  await assert.rejects(startBackendRuntime(options({ deploy: async () => { throw Error('private deployment secret sentinel'); } })), failure);
});

test('actual CLI rejects bootstrap before missing private config and never prints the value', () => {
  assert.equal(process.getuid(), 1000, 'run only in the approved isolated fixture');
  assert.equal(process.getgid(), 1000);
  const filename = fileURLToPath(new URL('./backend-runtime.mjs', import.meta.url));
  const child = spawnSync(process.execPath, [filename, '/data/config/runtime.json'], {
    env: { PATH: '/usr/local/bin:/usr/bin:/bin', WHOOP_STAGING_BOOTSTRAP: 'secret-sentinel' }, encoding: 'utf8', timeout: 5000,
  });
  assert.equal(child.status, 1); assert.equal(child.stdout, '');
  assert.equal(child.stderr, 'Private WHOOP backend runtime unavailable.\n');
});
