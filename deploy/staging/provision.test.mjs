import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { BOOTSTRAP_VARIABLE, provisionFromEnvironment } from './provision.mjs';
import { assertSyntheticEnvironment } from './service.mjs';
import { readPrivateJson } from '../railway/config.mjs';

const KEY = `tskey-auth-${'K'.repeat(40)}`;
const TOKEN = `whoopgw_service_${'S'.repeat(43)}`;
const FIXTURE = { mode: 'synthetic-fixture-only', hostname: 'staging-backend.test-tailnet.ts.net', serviceTokenSha256: 'a'.repeat(64) };
const GATEWAY = { mode: 'synthetic-fixture-only', hostname: 'staging-gateway.test-tailnet.ts.net',
  fixtureHostname: FIXTURE.hostname, fixtureIpv4: '100.72.0.9', ownerSecretHash: 'b'.repeat(64), serviceToken: TOKEN };
const envelope = (role, config = role === 'fixture' ? FIXTURE : GATEWAY) => ({ mode: 'synthetic-fixture-only', role, config, enrollmentKey: KEY });
const environment = payload => ({ PATH: '/usr/bin', [BOOTSTRAP_VARIABLE]: JSON.stringify(payload) });
function directory(t, role) {
  assert.equal(process.getuid(), 1000); assert.equal(process.getgid(), 1000);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'staging-variable-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const name of ['config', 'tailscale', ...(role === 'gateway' ? ['app'] : [])]) fs.mkdirSync(path.join(root, name), { mode: 0o700 });
  return root;
}

test('temporary bootstrap refuses privileged identity before reading the secret value', async () => {
  for (const [uid, gid] of [[0, 0], [0, 1000], [1000, 0]]) {
    let accessed = false; const env = {};
    Object.defineProperty(env, BOOTSTRAP_VARIABLE, { configurable: true, get() { accessed = true; throw new Error('must not read'); } });
    await assert.rejects(provisionFromEnvironment('fixture', { env, identity: { getuid: () => uid, getgid: () => gid } }), /STAGING_BOOTSTRAP_UNAVAILABLE/);
    assert.equal(accessed, false);
  }
});

test('temporary bootstrap refuses missing no-new-privileges before reading input or starting work', async () => {
  let accessed = false; let work = false; const env = {};
  Object.defineProperty(env, BOOTSTRAP_VARIABLE, { configurable: true, get() { accessed = true; throw new Error('must not read'); } });
  await assert.rejects(provisionFromEnvironment('fixture', { env,
    noNewPrivileges: () => { throw new Error('STAGING_RUNTIME_CHECK_UNAVAILABLE'); },
    runtimeCheck: () => { work = true; }, enroll: async () => { work = true; },
  }), /STAGING_RUNTIME_CHECK_UNAVAILABLE/);
  assert.equal(accessed, false); assert.equal(work, false);
});

test('fixed fixture entrypoint consumes variable before enrollment and never starts an application', async t => {
  const root = directory(t, 'fixture'); const env = environment(envelope('fixture')); const calls = [];
  const result = await provisionFromEnvironment('fixture', { root, env, runtimeCheck: (...args) => {
    assert.deepEqual(args, []);
    assert.equal(Object.hasOwn(env, BOOTSTRAP_VARIABLE), false);
    assert.deepEqual(fs.readdirSync(path.join(root, 'config')), []);
    calls.push('runtime-check');
  }, enroll: async options => {
    assert.equal(Object.hasOwn(env, BOOTSTRAP_VARIABLE), false);
    assert.deepEqual(options, { stateDirectory: path.join(root, 'tailscale'), tag: 'tag:whoop-backend',
      hostname: FIXTURE.hostname, port: 8080, enrollmentKey: KEY });
    assert.deepEqual(readPrivateJson(path.join(root, 'config/staging.json')), FIXTURE);
    calls.push('enroll'); return { close: async () => { calls.push('close'); } };
  } });
  assert.deepEqual(result, { role: 'fixture', phase: 'enrolled-awaiting-clean-redeploy' });
  assert.deepEqual(calls, ['runtime-check', 'enroll', 'close']); assert.deepEqual(env, { PATH: '/usr/bin' });
  assert.deepEqual(fs.readdirSync(path.join(root, 'config')), ['staging.json']);
  assert.ok(!JSON.stringify(result).includes(KEY));
});

test('gateway variable provisioning fixes its own role and writes secrets only to dedicated private files', async t => {
  const root = directory(t, 'gateway'); const env = environment(envelope('gateway')); let closed = 0;
  await provisionFromEnvironment('gateway', { root, env, enroll: async options => {
    assert.equal(Object.hasOwn(env, BOOTSTRAP_VARIABLE), false);
    assert.equal(options.tag, 'tag:whoop-gateway'); assert.equal(options.hostname, GATEWAY.hostname); assert.equal(options.port, 8787);
    assert.equal(options.enrollmentKey, KEY);
    assert.equal(readPrivateJson(path.join(root, 'config/runtime.json')).role, 'gateway');
    return { close: async () => { closed++; } };
  } });
  assert.equal(closed, 1); assert.equal(fs.readFileSync(path.join(root, 'config/service-token'), 'utf8'), TOKEN + '\n');
  for (const name of fs.readdirSync(path.join(root, 'config'))) {
    const file = path.join(root, 'config', name);
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.ok(!fs.readFileSync(file, 'utf8').includes(KEY));
  }
});

test('entire variable envelope, role, config and key validate before files or daemon work', async t => {
  const invalid = [
    { ...envelope('fixture'), role: 'gateway' }, { ...envelope('fixture'), mode: 'production' },
    { ...envelope('fixture'), command: 'secret-sentinel' }, { ...envelope('fixture'), enrollmentKey: 'secret-sentinel' },
    { ...envelope('fixture'), enrollmentKey: KEY + '\n' }, { ...envelope('fixture'), config: { ...FIXTURE, WHOOP_CLIENT_SECRET: 'secret-sentinel' } },
  ];
  for (const payload of invalid) {
    const root = directory(t, 'fixture'); const env = environment(payload); let called = false;
    await assert.rejects(provisionFromEnvironment('fixture', { root, env, enroll: async () => { called = true; } }));
    assert.equal(called, false); assert.equal(Object.hasOwn(env, BOOTSTRAP_VARIABLE), false);
    assert.deepEqual(fs.readdirSync(path.join(root, 'config')), []); assert.deepEqual(fs.readdirSync(path.join(root, 'tailscale')), []);
  }
  for (const encoded of ['', '{', 'x'.repeat(8193), '\ud800']) {
    const root = directory(t, 'fixture'); const env = { [BOOTSTRAP_VARIABLE]: encoded };
    await assert.rejects(provisionFromEnvironment('fixture', { root, env }));
    assert.equal(Object.hasOwn(env, BOOTSTRAP_VARIABLE), false); assert.deepEqual(fs.readdirSync(path.join(root, 'config')), []);
  }
  const root = directory(t, 'gateway');
  await assert.rejects(provisionFromEnvironment('gateway', { root, env: environment(envelope('gateway', { ...GATEWAY, ownerSecret: 'secret-sentinel' })) }));
  assert.deepEqual(fs.readdirSync(path.join(root, 'config')), []);
});

test('success or partial enrollment cannot reuse config or trigger a second enrollment', async t => {
  for (const role of ['fixture', 'gateway']) for (const failure of [false, true]) {
    const root = directory(t, role); let attempts = 0;
    const enroll = async () => { attempts++; if (failure) throw new Error('synthetic enrollment failure'); return { close: async () => {} }; };
    const first = provisionFromEnvironment(role, { root, env: environment(envelope(role)), enroll });
    if (failure) await assert.rejects(first); else await first;
    await assert.rejects(provisionFromEnvironment(role, { root, env: environment(envelope(role)), enroll }));
    assert.equal(attempts, 1);
  }
});

test('normal startup/root initialization reject even an empty bootstrap variable and unrelated WHOOP credentials', () => {
  for (const env of [{ [BOOTSTRAP_VARIABLE]: '' }, { WHOOP_CLIENT_SECRET: 'secret-sentinel' }]) assert.throws(() => assertSyntheticEnvironment(env));
  for (const [file, args] of [['runtime.mjs', ['/data/config/staging.json']],
    ['gateway-runtime.mjs', ['/data/config/staging-gateway.json']], ['bootstrap.mjs', ['init-volume']],
    ['gateway-bootstrap.mjs', ['init-volume']]]) {
    const result = spawnSync(process.execPath, [fileURLToPath(new URL(file, import.meta.url)), ...args], {
      env: { PATH: '/usr/bin', [BOOTSTRAP_VARIABLE]: '' }, encoding: 'utf8', timeout: 3000,
    });
    assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.doesNotMatch(result.stderr, /Error:| at |secret-sentinel/);
  }
});

test('fixed provisioning entrypoints reject the other role without printing input or secrets', () => {
  for (const role of ['fixture', 'gateway']) {
    const other = role === 'fixture' ? 'gateway' : 'fixture';
    const result = spawnSync(process.execPath, [fileURLToPath(new URL(`provision-${role}.mjs`, import.meta.url))], {
      env: environment(envelope(other)), encoding: 'utf8', timeout: 3000,
    });
    assert.equal(result.status, 1); assert.equal(result.stdout, '');
    assert.equal(result.stderr, 'Staging bootstrap unavailable; inspect the stopped staging configuration before retrying.\n');
    assert.ok(!result.stderr.includes(KEY)); assert.ok(!result.stderr.includes(TOKEN));
  }
});
