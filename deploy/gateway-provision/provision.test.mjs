import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseCutover, provisionGateway, provisionGatewayInput, inspectGateway } from './provision.mjs';
const hash = b => createHash('sha256').update(b).digest('hex');
const encode = o => JSON.stringify(o) + '\n';
const oldToken = 'whoopgw_service_' + Buffer.alloc(32, 1).toString('base64url');
const newToken = 'whoopgw_service_' + Buffer.alloc(32, 2).toString('base64url');
const unavailable = /GATEWAY_CONFIGURATION_UNAVAILABLE/;
const identity = { getuid: () => 1000, geteuid: () => 1000, getgid: () => 1000, getegid: () => 1000 };
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gateway-cutover-')); fs.chmodSync(root, 0o700);
  for (const dir of ['config', 'tailscale', 'app']) fs.mkdirSync(path.join(root, dir), { mode: 0o700 });
  const app = { publicOrigin: 'https://gateway.fixture.ts.net', upstreamOrigin: 'https://fixture.fixture.ts.net',
    upstreamTokenFile: '/data/config/service-token', ownerSecretHash: 'a'.repeat(64), databaseFile: '/data/app/gateway.sqlite', port: 8787,
    clients: [{ clientId: 'codex', name: 'Codex', redirectUris: ['http://127.0.0.1:17643/callback'] },
      { clientId: 'claude-code', name: 'Claude Code', redirectUris: ['http://localhost:17644/callback'] }] };
  const runtime = { role: 'gateway', hostname: 'gateway.fixture.ts.net', stateDirectory: '/data/tailscale',
    appConfigFile: '/data/config/app.json', backendIpv4: '100.95.83.95' };
  const marker = { mode: 'synthetic-fixture-only', hostname: runtime.hostname, fixtureHostname: 'fixture.fixture.ts.net',
    fixtureIpv4: runtime.backendIpv4, ownerSecretHash: app.ownerSecretHash, serviceTokenSha256: hash(oldToken) };
  const initial = { 'app.json': encode(app), 'runtime.json': encode(runtime), 'service-token': oldToken + '\n', 'staging-gateway.json': encode(marker) };
  for (const [name, value] of Object.entries(initial)) fs.writeFileSync(path.join(root, 'config', name), value, { mode: 0o600 });
  fs.writeFileSync(path.join(root, 'app', 'gateway.sqlite'), 'SYNTHETIC SQLITE GRANTS AND QUOTAS', { mode: 0o600 });
  fs.writeFileSync(path.join(root, 'tailscale', 'tailscaled.state'), 'SYNTHETIC NODE STATE', { mode: 0o600 });
  const expected = { appSha256: hash(initial['app.json']), runtimeSha256: hash(initial['runtime.json']),
    tokenFileSha256: hash(initial['service-token']), stagingMarkerSha256: hash(initial['staging-gateway.json']) };
  const payload = { mode: 'whoop-gateway-backend-cutover', hostname: runtime.hostname, backendHostname: 'backend.fixture.ts.net',
    backendIpv4: '100.90.80.70', serviceToken: newToken, expected };
  const opts = { root };
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, initial, payload, opts, app, runtime, marker,
    config: name => path.join(root, 'config', name), lock: path.join(root, 'tailscale', 'runtime.lock') };
}
function unchanged(f) { for (const [name, data] of Object.entries(f.initial)) assert.equal(fs.readFileSync(f.config(name), 'utf8'), data); }
test('fixed read-only inspector returns four hashes only without reading node or SQLite files', t => {
  const f = fixture(t);
  // Unreadable sentinels prove the inspector does not consume their contents.
  fs.chmodSync(path.join(f.root, 'app', 'gateway.sqlite'), 0);
  fs.chmodSync(path.join(f.root, 'tailscale', 'tailscaled.state'), 0);
  const before = fs.readdirSync(f.config(''));
  assert.deepEqual(inspectGateway(f.opts), { event: 'gateway-configuration-hashes', ...f.payload.expected });
  unchanged(f); assert.deepEqual(fs.readdirSync(f.config('')), before); assert.equal(fs.existsSync(f.lock), false);
  assert.throws(() => inspectGateway({ ...f.opts, identity: { ...identity, getuid: () => 0 } }), unavailable);
  const app = { ...f.app, port: 9999 }; fs.writeFileSync(f.config('app.json'), encode(app));
  assert.throws(() => inspectGateway(f.opts), unavailable);
});
test('successful stopped cutover preserves exact owner, clients, marker, database and node bytes', t => {
  const f = fixture(t); const beforeDb = fs.readFileSync(path.join(f.root, 'app', 'gateway.sqlite')); const beforeNode = fs.readFileSync(path.join(f.root, 'tailscale', 'tailscaled.state'));
  assert.deepEqual(provisionGateway(f.payload, f.opts), { phase: 'configured-awaiting-clean-redeploy' });
  assert.deepEqual(JSON.parse(fs.readFileSync(f.config('app.json'))), { ...f.app, upstreamOrigin: 'https://backend.fixture.ts.net' });
  assert.deepEqual(JSON.parse(fs.readFileSync(f.config('runtime.json'))), { ...f.runtime, backendIpv4: '100.90.80.70' });
  assert.equal(fs.readFileSync(f.config('service-token'), 'utf8'), newToken + '\n');
  assert.equal(fs.readFileSync(f.config('staging-gateway.json'), 'utf8'), f.initial['staging-gateway.json']);
  assert.deepEqual(fs.readFileSync(path.join(f.root, 'app', 'gateway.sqlite')), beforeDb);
  assert.deepEqual(fs.readFileSync(path.join(f.root, 'tailscale', 'tailscaled.state')), beforeNode);
  assert.equal(fs.existsSync(f.lock), false);
  assert.equal(JSON.parse(fs.readFileSync(f.config('gateway-cutover/phase.json'))).phase, 'committed');
  for (const [name, bytes] of Object.entries(f.initial)) {
    const backup = f.config('gateway-cutover/previous/' + name);
    assert.equal(fs.readFileSync(backup, 'utf8'), bytes); assert.equal(fs.statSync(backup).mode & 0o777, 0o600);
  }
  assert.throws(() => provisionGateway(f.payload, f.opts), unavailable);
});
test('all four identity and NNP checks precede payload access', () => {
  const raw = new Proxy({}, { ownKeys() { throw new Error('payload accessed'); } });
  for (const method of Object.keys(identity)) assert.throws(() => provisionGateway(raw, { identity: { ...identity, [method]: () => 0 }, noNewPrivileges: () => assert.fail('NNP reached') }), unavailable);
  assert.throws(() => provisionGateway(raw, { identity, noNewPrivileges: () => { throw Error('NNP absent'); } }), unavailable);
});
test('strict envelope denies callbacks, owner rotation, path/host/IP and token overrides', t => {
  const f = fixture(t);
  for (const edit of [p => p.extra = 1, p => p.ownerSecretHash = 'b'.repeat(64), p => p.backendHostname = 'example.com',
    p => p.backendHostname = p.hostname, p => p.backendIpv4 = '127.0.0.1', p => p.backendIpv4 = '100.100.100.100',
    p => p.backendIpv4 = '100.090.80.70', p => p.serviceToken += '=', p => p.expected.extra = 'a'.repeat(64),
    p => p.expected.appSha256 = 'x'.repeat(64)]) {
    const p = structuredClone(f.payload); edit(p); assert.throws(() => parseCutover(p), unavailable);
  }
  unchanged(f); assert.equal(fs.existsSync(f.lock), false);
});
test('all prior file hashes bind before first write', t => {
  const f = fixture(t);
  for (const key of Object.keys(f.payload.expected)) {
    const p = structuredClone(f.payload); p.expected[key] = '0'.repeat(64);
    assert.throws(() => provisionGateway(p, f.opts), unavailable); unchanged(f); assert.equal(fs.existsSync(f.lock), false);
  }
});
test('even hash-attested callback, marker and runtime changes are rejected', t => {
  const f = fixture(t);
  const changes = [ ['app.json', 'appSha256', value => value.clients[0].redirectUris[0] = 'http://127.0.0.1:9999/callback'],
    ['app.json', 'appSha256', value => value.ownerSecretHash = 'b'.repeat(64)],
    ['runtime.json', 'runtimeSha256', value => value.stateDirectory = '/tmp/state'],
    ['staging-gateway.json', 'stagingMarkerSha256', value => value.fixtureIpv4 = '100.90.70.60'] ];
  for (const [name, key, edit] of changes) {
    const value = JSON.parse(f.initial[name]); edit(value); const bytes = encode(value); fs.writeFileSync(f.config(name), bytes);
    const p = structuredClone(f.payload); p.expected[key] = hash(bytes);
    assert.throws(() => provisionGateway(p, f.opts), unavailable); assert.equal(fs.existsSync(f.lock), false);
    fs.writeFileSync(f.config(name), f.initial[name]);
  }
});
test('unchanged synthetic target or machine credential is rejected', t => {
  const f = fixture(t);
  for (const edit of [p => p.backendHostname = f.marker.fixtureHostname, p => p.backendIpv4 = f.marker.fixtureIpv4, p => p.serviceToken = oldToken]) {
    const p = structuredClone(f.payload); edit(p); assert.throws(() => provisionGateway(p, f.opts), unavailable);
  }
  unchanged(f); assert.equal(fs.existsSync(f.lock), false);
});
test('existing runtime lock is retained exactly, never stale-cleared', t => {
  const f = fixture(t); fs.writeFileSync(f.lock, 'EXISTING OWNER', { mode: 0o600 });
  assert.throws(() => provisionGateway(f.payload, f.opts), unavailable);
  assert.equal(fs.readFileSync(f.lock, 'utf8'), 'EXISTING OWNER'); unchanged(f);
});
test('private regular single-link inputs reject symlinks, hardlinks and broad modes', t => {
  const f = fixture(t); const file = f.config('service-token'); const original = f.config('saved-token');
  // An unexpected entry also fails closed before input consumption.
  fs.renameSync(file, original); fs.symlinkSync(original, file);
  assert.throws(() => provisionGateway(f.payload, f.opts), unavailable); fs.unlinkSync(file); fs.renameSync(original, file);
  const external = path.join(f.root, 'hardlink'); fs.linkSync(file, external);
  assert.throws(() => provisionGateway(f.payload, f.opts), unavailable); fs.unlinkSync(external);
  fs.chmodSync(file, 0o644); assert.throws(() => provisionGateway(f.payload, f.opts), unavailable);
  assert.equal(fs.existsSync(f.lock), false);
});
test('symlinked state directory is rejected without touching its contents', t => {
  const f = fixture(t); fs.renameSync(path.join(f.root, 'tailscale'), path.join(f.root, 'state-original'));
  fs.symlinkSync(path.join(f.root, 'state-original'), path.join(f.root, 'tailscale'));
  assert.throws(() => provisionGateway(f.payload, f.opts), unavailable); unchanged(f);
});
for (const point of ['prepared', 'runtime-disabled', 'app-published', 'token-published', 'runtime-published', 'committed']) {
  test(`failure at ${point} retains owned lock/backups and refuses automatic retry`, t => {
    const f = fixture(t);
    assert.throws(() => provisionGateway(f.payload, { ...f.opts, checkpoint: phase => { if (phase === point) throw Error('synthetic interruption'); } }), unavailable);
    assert.equal(fs.statSync(f.lock).mode & 0o777, 0o600);
    for (const [name, bytes] of Object.entries(f.initial)) assert.equal(fs.readFileSync(f.config('gateway-cutover/previous/' + name), 'utf8'), bytes);
    if (['runtime-disabled', 'app-published', 'token-published'].includes(point)) assert.equal(fs.existsSync(f.config('runtime.json')), false);
    assert.throws(() => provisionGateway(f.payload, f.opts), unavailable);
  });
}
test('lock inode replacement cannot cause another owner lock to be removed', t => {
  const f = fixture(t);
  assert.throws(() => provisionGateway(f.payload, { ...f.opts, checkpoint: phase => {
    if (phase === 'committed') { fs.renameSync(f.lock, path.join(f.root, 'own-lock')); fs.writeFileSync(f.lock, 'FOREIGN OWNER', { mode: 0o600 }); }
  } }), unavailable);
  assert.equal(fs.readFileSync(f.lock, 'utf8'), 'FOREIGN OWNER');
});
test('second concurrent attempt cannot claim state or alter first attempt', t => {
  const f = fixture(t);
  provisionGateway(f.payload, { ...f.opts, checkpoint: phase => { if (phase === 'prepared') assert.throws(() => provisionGateway(f.payload, f.opts), unavailable); } });
  assert.equal(fs.existsSync(f.lock), false);
});
test('bounded stdin accepts valid bytes but rejects oversized, invalid UTF8, empty and terminal input', async t => {
  const f = fixture(t);
  for (const bytes of [Buffer.alloc(8193, 65), Buffer.from([0xff]), Buffer.alloc(0)]) {
    await assert.rejects(provisionGatewayInput(Readable.from([bytes]), f.opts), unavailable); unchanged(f);
  }
  const terminal = Readable.from([Buffer.from('{}')]); terminal.isTTY = true;
  await assert.rejects(provisionGatewayInput(terminal, f.opts), unavailable);
  assert.deepEqual(await provisionGatewayInput(Readable.from([Buffer.from(JSON.stringify(f.payload))]), f.opts), { phase: 'configured-awaiting-clean-redeploy' });
});
test('stdin deadline destroys an unfinished input without writing', async t => {
  const f = fixture(t); const input = new Readable({ read() {} });
  await assert.rejects(provisionGatewayInput(input, f.opts), unavailable);
  assert.equal(input.destroyed, true); unchanged(f); assert.equal(fs.existsSync(f.lock), false);
});
test('fixed shell rejects leftover bootstrap and arbitrary mode before Node startup', () => {
  const shell = fileURLToPath(new URL('./entrypoint.sh', import.meta.url));
  for (const [args, extra] of [[['normal'], { WHOOP_GATEWAY_CONFIG_BOOTSTRAP: '' }], [['inspect'], { WHOOP_GATEWAY_CONFIG_BOOTSTRAP: '' }], [['normal'], { WHOOP_STAGING_BOOTSTRAP: 'SYNTHETIC SECRET' }], [['eval'], {}], [[], {}]]) {
    const r = spawnSync('/bin/sh', [shell, ...args], { env: { PATH: '/usr/bin:/bin', NODE_OPTIONS: '--require=/tmp/MUST-NOT-RUN', ...extra }, encoding: 'utf8', timeout: 5000 });
    assert.equal(r.status, 1); assert.equal(r.stdout, ''); assert.equal(r.stderr, 'WHOOP gateway configuration unavailable.\n');
  }
});
test('CLI rejects arbitrary arguments with only a fixed error', () => {
  const r = spawnSync(process.execPath, [fileURLToPath(new URL('./provision.mjs', import.meta.url)), 'SYNTHETIC SECRET'], {
    env: { PATH: '/usr/local/bin:/usr/bin:/bin' }, encoding: 'utf8', timeout: 5000 });
  assert.equal(r.status, 1); assert.equal(r.stdout, ''); assert.equal(r.stderr, 'WHOOP gateway configuration unavailable.\n');
});
