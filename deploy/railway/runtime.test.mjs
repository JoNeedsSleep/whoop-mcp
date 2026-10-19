import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { backendEnvironment, parseDeploymentConfig, readPrivateJson, tailnetHostname, tailnetIpv4 } from './config.mjs';
import { childEnvironment, daemonEnvironment, expectedServe, readEnrollmentKey, runCommand, startTailscale, validatePersistedState, validateServe } from './tailscale-supervisor.mjs';
import { startDeployment, validateAppConfig } from './runtime.mjs';
import { startLocalTransport } from '../../restricted-local/transport-supervisor.mjs';

const remote = { role: 'gateway', hostname: 'gateway.test-tailnet.ts.net', stateDirectory: '/data/tailscale', appConfigFile: '/data/config/app.json', backendIpv4: '100.72.0.9' };
const prefs = local => ({ ControlURL: 'https://controlplane.tailscale.com', RouteAll: false, CorpDNS: false,
  RunSSH: false, RunWebClient: false, RemoteConfig: false, ShieldsUp: local, ExitNodeID: '', ExitNodeIP: null,
  AutoExitNode: '', AdvertiseRoutes: null, AdvertiseServices: null, DriveShares: [], RelayServerPort: null,
  AppConnector: { Advertise: false }, AutoUpdate: { Check: false, Apply: false }, WantRunning: true });
const status = (tag, hostname) => ({ BackendState: 'Running', Self: { Online: true, Tags: [tag], DNSName: `${hostname}.` } });
function fixture(t, local = true, serve = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'whoop-ts-test-'));
  fs.chmodSync(directory, 0o700); t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const state = { _machinekey: Buffer.from('SYNTHETIC_ONLY').toString('base64'),
    'profile-test': Buffer.from(JSON.stringify(prefs(local))).toString('base64'),
    '_serve/test': Buffer.from(JSON.stringify(serve)).toString('base64') };
  const filename = path.join(directory, 'tailscaled.state');
  fs.writeFileSync(filename, JSON.stringify(state), { mode: 0o600 });
  return { directory, filename, state };
}
function fakeNode({ tag = 'tag:whoop-local-codex', hostname, serving = {}, enrolled = true, poisonPrefs, failAt, statusSequence = [] } = {}) {
  const calls = []; let current = enrolled ? status(tag, hostname) : { BackendState: 'NeedsLogin' }; let serve = serving;
  const statuses = structuredClone(statusSequence);
  const child = new EventEmitter(); child.exitCode = null; child.signalCode = null;
  child.kill = signal => { child.signalCode = signal; child.emit('exit', null, signal); child.emit('close', null, signal); };
  const spawnFn = (binary, args, options) => { calls.push({ binary, args, options }); return child; };
  const command = async (binary, args) => {
    calls.push({ binary, args });
    if (failAt?.(args)) throw new Error('SYNTHETIC SECRET MUST NOT ESCAPE');
    if (args[0] === 'version') return '1.104.1\n';
    const cmd = args.slice(1);
    if (cmd[0] === 'up') { current = status(tag, hostname); return ''; }
    if (cmd[0] === 'status') { if (statuses.length) current = statuses.shift(); return JSON.stringify(current); }
    if (cmd[0] === 'debug') return JSON.stringify(poisonPrefs ?? prefs(tag.startsWith('tag:whoop-local-')));
    if (cmd[0] === 'serve' && cmd[1] === 'reset') serve = {};
    if (cmd[0] === 'serve' && cmd[1] === '--bg') serve = expectedServe(hostname, tag === 'tag:whoop-gateway' ? 8787 : 8080);
    if (cmd[0] === 'serve' && cmd[1] === 'status') return JSON.stringify(serve);
    return '';
  };
  return { calls, child, command, spawnFn };
}

test('deployment config pins private origins, paths, role and tailnet destination', () => {
  assert.deepEqual(parseDeploymentConfig(remote), remote);
  for (const raw of [{ ...remote, role: 'shell' }, { ...remote, stateDirectory: '/host' }, { ...remote, shell: 'x' }, { ...remote, hostname: 'gateway.example.com' }]) assert.throws(() => parseDeploymentConfig(raw));
  for (const value of ['127.0.0.1', '100.100.100.100', '100.063.1.1', '100.128.0.1', '::1', '169.254.169.254']) assert.throws(() => tailnetIpv4(value));
  for (const value of ['gateway.x.ts.net;evil', 'gateway.x.ts.net:443', 'gateway.x.ts.net/']) assert.throws(() => tailnetHostname(value));
});
test('backend secrets are the only copied env and bind/migration/MCP policy is forced', () => {
  const raw = Object.fromEntries(['DATABASE_URL', 'ENCRYPTION_KEY', 'WHOOP_CLIENT_ID', 'WHOOP_CLIENT_SECRET', 'SESSION_SECRET', 'ALLOWED_WHOOP_USER_ID', 'GATEWAY_SERVICE_TOKEN_SHA256'].map(k => [k, 'synthetic']));
  raw.PUBLIC_BASE_URL = 'https://backend.test-tailnet.ts.net';
  const env = backendEnvironment(raw, 'backend.test-tailnet.ts.net');
  assert.equal(env.BIND_HOST, '127.0.0.1'); assert.equal(env.RUN_MIGRATIONS, 'false'); assert.equal(env.ENABLE_LEGACY_DIRECT_MCP, 'false');
  for (const key of ['TS_AUTHKEY', 'NODE_OPTIONS', 'HTTP_PROXY', 'SSH_AUTH_SOCK', 'HOME']) assert.equal(env[key], undefined);
  assert.throws(() => backendEnvironment({ ...raw, NODE_OPTIONS: '--require=evil' }, 'backend.test-tailnet.ts.net'));
  assert.throws(() => backendEnvironment({ ...raw, PUBLIC_BASE_URL: 'https://evil.test-tailnet.ts.net' }, 'backend.test-tailnet.ts.net'));
});
test('private JSON rejects unsafe permissions, symlinks, malformed UTF8 and oversized input', t => {
  const { directory, filename } = fixture(t);
  assert.ok(readPrivateJson(filename));
  fs.chmodSync(filename, 0o644); assert.throws(() => readPrivateJson(filename)); fs.chmodSync(filename, 0o600);
  const link = path.join(directory, 'link'); fs.symlinkSync(filename, link); assert.throws(() => readPrivateJson(link));
  fs.writeFileSync(filename, Buffer.from([0xc3, 0x28])); assert.throws(() => readPrivateJson(filename));
  fs.writeFileSync(filename, 'a'.repeat(17000)); assert.throws(() => readPrivateJson(filename));
});
test('stale persisted Funnel, file serving and routing are rejected before any daemon can start', t => {
  const { filename, state } = fixture(t);
  const expected = expectedServe(remote.hostname, 8787);
  for (const serve of [{ ...expected, AllowFunnel: { [`${remote.hostname}:443`]: true } },
    { ...expected, Web: { [`${remote.hostname}:443`]: { Handlers: { '/': { Path: '/data' } } } } },
    { TCP: { '22': { TCPForward: '127.0.0.1:22' } } }]) {
    assert.throws(() => validateServe(serve, expected));
    fs.writeFileSync(filename, JSON.stringify({ ...state, '_serve/test': Buffer.from(JSON.stringify(serve)).toString('base64') }));
    assert.throws(() => validatePersistedState(filename, expected, true));
  }
  fs.writeFileSync(filename, JSON.stringify({ ...state, 'profile-test': Buffer.from(JSON.stringify({ ...prefs(true), RunSSH: true })).toString('base64') }));
  assert.throws(() => validatePersistedState(filename, {}, true));
});
test('userspace daemon gets fixed commands, stripped env, private admin socket and no serve', async t => {
  const { directory } = fixture(t); const fake = fakeNode();
  const runtime = await startTailscale({ stateDirectory: directory, tag: 'tag:whoop-local-codex' }, fake);
  const daemon = fake.calls.find(c => c.binary.endsWith('tailscaled'));
  assert.deepEqual(daemon.options.env, daemonEnvironment); assert.equal(daemon.options.stdio, 'ignore');
  assert.ok(daemon.args.includes('--tun=userspace-networking')); assert.ok(daemon.args.includes('--socks5-server=127.0.0.1:1055'));
  assert.ok(daemon.args.includes(`--socket=${directory}/tailscaled.sock`)); assert.ok(daemon.args.includes('--no-logs-no-support'));
  assert.ok(!fake.calls.some(c => c.args.includes('up') || c.args.includes('funnel') || c.args.includes('--bg')));
  await runtime.close(); assert.equal(fake.child.signalCode, 'SIGTERM');
});
test('daemon HTTP2 mitigation is fixed despite inherited overrides and never changes CLI environment', async t => {
  const inherited = { GODEBUG: 'http2server=1,http2debug=2,x509usefallbackroots=1',
    SSLKEYLOGFILE: '/tmp/synthetic-secret-log', TS_AUTHKEY: 'synthetic-secret-sentinel' };
  const previous = Object.fromEntries(Object.keys(inherited).map(key => [key, process.env[key]]));
  Object.assign(process.env, inherited);
  try {
    assert.deepEqual(daemonEnvironment, { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp',
      TS_NO_LOGS_NO_SUPPORT: 'true', GODEBUG: 'http2server=0' });
    assert.ok(Object.isFrozen(daemonEnvironment));
    assert.equal(childEnvironment.GODEBUG, undefined);
    const { directory } = fixture(t, false);
    const fake = fakeNode({ tag: 'tag:whoop-gateway', hostname: remote.hostname });
    const runtime = await startTailscale({ stateDirectory: directory, tag: 'tag:whoop-gateway', hostname: remote.hostname, port: 8787 }, fake);
    try {
      const daemon = fake.calls.find(call => call.binary.endsWith('tailscaled'));
      assert.deepEqual(daemon.options.env, daemonEnvironment);
      for (const key of ['SSLKEYLOGFILE', 'TS_AUTHKEY', 'SSH_AUTH_SOCK', 'HTTP_PROXY', 'HTTPS_PROXY']) assert.equal(daemon.options.env[key], undefined);
      assert.ok(fake.calls.some(call => call.args.includes('--https=443')));
    } finally { await runtime.close(); }
    let cliOptions;
    const result = await runCommand('/usr/local/bin/tailscale', ['version'], { spawnFn: (_binary, _args, options) => {
      cliOptions = options; const child = new EventEmitter(); child.stdout = new EventEmitter(); child.kill = () => {};
      queueMicrotask(() => { child.stdout.emit('data', Buffer.from('1.104.1\n')); child.emit('close', 0); });
      return child;
    } });
    assert.equal(result, '1.104.1\n'); assert.deepEqual(cliOptions.env, childEnvironment);
    assert.equal(cliOptions.env.GODEBUG, undefined); assert.equal(cliOptions.env.TS_AUTHKEY, undefined);
  } finally {
    for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
  }
});
test('remote Serve exposes exactly HTTPS443 and loopback target after verified settings', async t => {
  const { directory } = fixture(t, false);
  const fake = fakeNode({ tag: 'tag:whoop-gateway', hostname: remote.hostname });
  const runtime = await startTailscale({ stateDirectory: directory, tag: 'tag:whoop-gateway', hostname: remote.hostname, port: 8787 }, fake);
  const serve = fake.calls.find(c => c.args.includes('--bg'));
  assert.deepEqual(serve.args.slice(1), ['serve', '--bg', '--yes', '--https=443', 'http://127.0.0.1:8787']);
  assert.ok(fake.calls.findIndex(c => c.args.includes('prefs')) < fake.calls.indexOf(serve));
  await runtime.close();
});
test('normal startup waits for both Running and online before configuring or serving', async t => {
  const { directory } = fixture(t, false);
  const ready = status('tag:whoop-gateway', remote.hostname);
  const fake = fakeNode({ tag: 'tag:whoop-gateway', hostname: remote.hostname, statusSequence: [
    { ...ready, Self: { ...ready.Self, Online: false } },
    { ...ready, BackendState: 'Starting' }, ready,
  ] });
  let waits = 0;
  const runtime = await startTailscale({ stateDirectory: directory, tag: 'tag:whoop-gateway', hostname: remote.hostname, port: 8787 }, {
    ...fake, startupAttempts: 4, wait: async milliseconds => {
      waits++; assert.equal(milliseconds, 500);
      assert.ok(!fake.calls.some(call => ['set', 'debug', 'serve', 'up'].includes(call.args[1])));
    },
  });
  assert.equal(waits, 2);
  assert.equal(fake.calls.filter(call => call.args[1] === 'status').length, 4);
  assert.ok(fake.calls.some(call => call.args.includes('--bg')));
  await runtime.close();
  assert.equal(fs.existsSync(path.join(directory, 'runtime.lock')), false);
});
test('permanently offline saved node exhausts bounded attempts without configuring or serving', async t => {
  const { directory } = fixture(t, false);
  const ready = status('tag:whoop-gateway', remote.hostname);
  const fake = fakeNode({ tag: 'tag:whoop-gateway', hostname: remote.hostname,
    statusSequence: [{ ...ready, Self: { ...ready.Self, Online: false } }] });
  let waits = 0;
  await assert.rejects(startTailscale({ stateDirectory: directory, tag: 'tag:whoop-gateway', hostname: remote.hostname, port: 8787 }, {
    ...fake, startupAttempts: 3, wait: async () => { waits++; },
  }), /PRIVATE_RUNTIME_UNAVAILABLE/);
  assert.equal(waits, 3);
  assert.equal(fake.calls.filter(call => call.args[1] === 'status').length, 3);
  assert.ok(!fake.calls.some(call => ['set', 'debug', 'serve', 'up'].includes(call.args[1])));
  assert.equal(fake.child.signalCode, 'SIGTERM');
  assert.equal(fs.existsSync(path.join(directory, 'runtime.lock')), false);
});
test('online readiness still rejects a wrong tag or DNS name before configuring or serving', async t => {
  const { directory } = fixture(t, false);
  const ready = status('tag:whoop-gateway', remote.hostname);
  for (const self of [{ ...ready.Self, Tags: ['tag:unrelated'] },
    { ...ready.Self, DNSName: 'other.test-tailnet.ts.net.' }]) {
    const fake = fakeNode({ tag: 'tag:whoop-gateway', hostname: remote.hostname, statusSequence: [{ ...ready, Self: self }] });
    let waits = 0;
    await assert.rejects(startTailscale({ stateDirectory: directory, tag: 'tag:whoop-gateway', hostname: remote.hostname, port: 8787 }, {
      ...fake, startupAttempts: 3, wait: async () => { waits++; },
    }), /PRIVATE_RUNTIME_UNAVAILABLE/);
    assert.equal(waits, 0);
    assert.ok(!fake.calls.some(call => ['set', 'debug', 'serve', 'up'].includes(call.args[1])));
    assert.equal(fake.child.signalCode, 'SIGTERM');
    assert.equal(fs.existsSync(path.join(directory, 'runtime.lock')), false);
  }
});
test('wrong identity or unsafe effective settings stops daemon without publishing relay', async t => {
  const { directory } = fixture(t);
  for (const fake of [fakeNode({ tag: 'tag:unrelated' }), fakeNode({ poisonPrefs: { ...prefs(true), RemoteConfig: true } }), fakeNode({ failAt: a => a.includes('set') })]) {
    await assert.rejects(startTailscale({ stateDirectory: directory, tag: 'tag:whoop-local-codex' }, fake), /PRIVATE_RUNTIME_UNAVAILABLE/);
    assert.equal(fake.child.signalCode, 'SIGTERM');
  }
});
test('explicit enrollment uses a private file argument only and deletes key on success/failure', async t => {
  const { directory, filename } = fixture(t); fs.unlinkSync(filename);
  const key = `tskey-auth-${'S'.repeat(40)}`;
  assert.equal(await readEnrollmentKey(Readable.from([Buffer.from(`${key}\n`)])), key);
  await assert.rejects(readEnrollmentKey(Readable.from([Buffer.from('x'.repeat(257))])));
  for (const failAt of [undefined, a => a.includes('up')]) {
    const fake = fakeNode({ enrolled: false, failAt });
    const run = startTailscale({ stateDirectory: directory, tag: 'tag:whoop-local-codex', enrollmentKey: key }, fake);
    if (failAt) await assert.rejects(run, /PRIVATE_RUNTIME_UNAVAILABLE/); else await (await run).close();
    assert.equal(fs.existsSync(path.join(directory, 'enrollment.key')), false);
    assert.equal(JSON.stringify(fake.calls).includes(key), false);
    assert.ok(fake.calls.some(c => c.args.includes(`--auth-key=file:${directory}/enrollment.key`)));
  }
});
test('daemon spawn error without exit event fails and cleanup settles', async t => {
  const { directory } = fixture(t);
  const fake = fakeNode();
  fake.spawnFn = () => { queueMicrotask(() => fake.child.emit('error', new Error('synthetic ENOENT'))); return fake.child; };
  await assert.rejects(startTailscale({ stateDirectory: directory, tag: 'tag:whoop-local-codex' }, fake), /PRIVATE_RUNTIME_UNAVAILABLE/);
});
test('shared state lock denies concurrent daemon/enrollment before any spawn and releases on clean stop', async t => {
  const { directory } = fixture(t);
  const first = await startTailscale({ stateDirectory: directory, tag: 'tag:whoop-local-codex' }, fakeNode());
  const second = fakeNode();
  await assert.rejects(startTailscale({ stateDirectory: directory, tag: 'tag:whoop-local-codex' }, second));
  assert.equal(second.calls.length, 0);
  await first.close();
  const third = await startTailscale({ stateDirectory: directory, tag: 'tag:whoop-local-codex' }, fakeNode());
  await third.close(); assert.equal(fs.existsSync(path.join(directory, 'runtime.lock')), false);
});
test('partial enrollment-key write failure removes only the new key and releases state lock', async t => {
  const { directory, filename } = fixture(t); fs.unlinkSync(filename);
  const write = fs.writeFileSync;
  t.mock.method(fs, 'writeFileSync', (target, value, options) => {
    if (typeof target === 'number') { write(target, String(value).slice(0, 12)); throw new Error('synthetic disk full'); }
    return write(target, value, options);
  });
  const fake = fakeNode({ enrolled: false });
  await assert.rejects(startTailscale({ stateDirectory: directory, tag: 'tag:whoop-local-codex', enrollmentKey: `tskey-auth-${'S'.repeat(40)}` }, fake), /PRIVATE_RUNTIME_UNAVAILABLE/);
  assert.equal(fs.existsSync(path.join(directory, 'enrollment.key')), false);
  assert.equal(fs.existsSync(path.join(directory, 'runtime.lock')), false);
  assert.equal(fake.calls.length, 0);
});
test('local relay is started only after node readiness and closes when daemon dies', async () => {
  let failNode; const events = [];
  const tailscale = async () => { events.push('node'); return { failed: new Promise(r => { failNode = r; }), close: async () => { events.push('node close'); } }; };
  const relay = async options => { events.push('relay'); assert.deepEqual(options, { socketPath: '/transport/gateway.sock', targetIpv4: '100.72.0.9', socksPort: 1055 }); return { close: async () => { events.push('relay close'); } }; };
  const runtime = await startLocalTransport('claude-code', '100.72.0.9', { tailscale, relay });
  assert.deepEqual(events, ['node', 'relay']); failNode(); await runtime.failed; await runtime.close();
  assert.deepEqual(events, ['node', 'relay', 'relay close', 'node close']);
});
test('enrollment never starts local relay or remote app; runtime closes peers on startup failure', async () => {
  let closed = 0; let appCalled = 0;
  const tailscale = async () => ({ failed: new Promise(() => {}), close: async () => { closed++; } });
  const forbidden = async () => { appCalled++; throw new Error('unexpected app'); };
  await startLocalTransport('codex', '100.72.0.9', { enrollmentKey: 'synthetic', tailscale, relay: forbidden });
  await startDeployment(remote, { enrollmentKey: 'synthetic', tailscale, gateway: forbidden, readAppConfig: forbidden });
  assert.equal(appCalled, 0); assert.equal(closed, 2);
  const gatewayConfig = { publicOrigin: `https://${remote.hostname}`, upstreamOrigin: 'https://backend.test-tailnet.ts.net', port: 8787,
    databaseFile: '/data/app/gateway.sqlite', upstreamTokenFile: '/data/config/service-token' };
  assert.throws(() => validateAppConfig(remote, { ...gatewayConfig, upstreamOrigin: 'http://backend.test-tailnet.ts.net' }));
  await assert.rejects(startDeployment(remote, { tailscale, gateway: forbidden, readAppConfig: () => gatewayConfig }), /PRIVATE_RUNTIME_UNAVAILABLE/);
  assert.equal(closed, 3);
});
