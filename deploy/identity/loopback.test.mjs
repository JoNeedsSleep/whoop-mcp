import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Readable, PassThrough } from 'node:stream';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseIdentityConfig, parseLoopbackIdentityConfig, LOOPBACK_ORIGIN } from './verify.mjs';
import { startIdentityVerification } from './runtime.mjs';
import { startLoopbackIdentity } from './loopback-runtime.mjs';

const config = { mode: 'whoop-owner-identity-loopback', clientId: 'synthetic-client', clientSecret: 'synthetic-secret' };
const environment = { PATH: '/usr/local/bin:/usr/bin:/bin' };
const identity = Object.fromEntries(['getuid', 'geteuid', 'getgid', 'getegid'].map(key => [key, () => 1000]));
const failure = { message: 'IDENTITY_UNAVAILABLE' };
const token = { access_token: 'synthetic-token', scope: 'read:profile', token_type: 'bearer', expires_in: 3600 };
const profile = { user_id: 1234567, email: 'owner@example.test', first_name: '<Owner>', last_name: 'Account' };
const forbidden = () => assert.fail('unexpected operation');
const csrf = text => text.match(/name="csrf" value="([A-Za-z0-9_-]{43})"/)?.[1];
const link = text => text.match(/<a href="([^"]+)" rel="noreferrer">/)?.[1].replaceAll('&amp;', '&');

function call(server, path, { method = 'GET', body, cookie, headers = {}, localAddress } = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: '127.0.0.1', port: server.address().port, path, method, localAddress, agent: false,
      headers: Array.isArray(headers) ? headers : { Host: 'localhost:17645', ...(cookie ? { Cookie: cookie } : {}),
        ...(body !== undefined ? { Origin: LOOPBACK_ORIGIN, 'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(body) } : {}), ...headers } }, response => {
      const chunks = []; response.on('error', reject); response.on('data', b => chunks.push(b));
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, text: Buffer.concat(chunks).toString() }));
    }); request.on('error', reject); request.end(body);
  });
}
async function fixture(t, serviceOptions = {}, args = []) {
  const calls = [];
  const runtime = await startLoopbackIdentity({ input: Readable.from([JSON.stringify(config)]), environment, args,
    serviceOptions: { upstream: async (kind, fields) => { calls.push({ kind, fields }); return kind === 'token' ? token : kind === 'profile' ? profile : null; }, ...serviceOptions } });
  t.after(() => runtime.close()); return { ...runtime, calls };
}
async function begin(f) {
  const page = await call(f.server, '/'); assert.equal(page.status, 200);
  const cookie = page.headers['set-cookie'][0].split(';')[0];
  const started = await call(f.server, '/start', { method: 'POST', body: new URLSearchParams({ csrf: csrf(page.text) }).toString(), cookie });
  assert.equal(started.status, 303); assert.equal(started.headers.location, '/authorize');
  const authorize = await call(f.server, '/authorize', { cookie }); assert.equal(authorize.status, 200);
  const url = new URL(link(authorize.text));
  return { page, cookie, authorize, url, callback: '/whoop/callback?' + new URLSearchParams({ state: url.searchParams.get('state'), code: 'synthetic-code' }) };
}
async function confirmPage(f, flow) {
  const callback = await call(f.server, flow.callback, { cookie: flow.cookie });
  assert.equal(callback.status, 303); assert.equal(callback.headers.location, '/confirm');
  const page = await call(f.server, '/confirm', { cookie: flow.cookie }); assert.equal(page.status, 200); return page;
}
const confirmation = (page, cookie, confirmed = 'yes') => ({ method: 'POST', cookie,
  body: new URLSearchParams({ csrf: csrf(page.text), confirmed }).toString() });

test('local schema has no destination selector and existing production parser/runtime reject it', async () => {
  assert.deepEqual(parseLoopbackIdentityConfig(config), config);
  for (const value of [{ ...config, hostname: 'backend.test.ts.net' }, { ...config, origin: LOOPBACK_ORIGIN },
    { ...config, redirectUri: LOOPBACK_ORIGIN + '/whoop/callback' }, { ...config, mode: 'whoop-owner-identity' },
    { ...config, clientSecret: '' }, { ...config, databaseUrl: 'synthetic' }]) assert.throws(() => parseLoopbackIdentityConfig(value), failure);
  assert.throws(() => parseIdentityConfig(config), failure);
  await assert.rejects(startIdentityVerification({ identity, environment: {}, noNewPrivileges: () => {}, readConfig: () => config, tailscale: forbidden }), failure);
});

test('actual loopback ingress/core flow keeps fixed redirect, Secure cookie and revokes before delivering ID on close', async t => {
  const f = await fixture(t); assert.equal(f.server.address().address, '127.0.0.1'); assert.equal(f.server.address().port, 17645);
  assert.equal(f.core.address().address, '127.0.0.1'); assert.notEqual(f.core.address().port, 17645);
  const flow = await begin(f);
  assert.match(flow.page.headers['set-cookie'][0], /^__Host-whoop_identity=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=300$/);
  assert.equal(flow.url.origin, 'https://api.prod.whoop.com'); assert.equal(flow.url.pathname, '/oauth/oauth2/auth');
  assert.equal(flow.url.searchParams.get('redirect_uri'), 'http://localhost:17645/whoop/callback');
  assert.equal(flow.url.searchParams.get('scope'), 'read:profile'); assert.equal(flow.url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(flow.page.headers['x-whoop-local-ingress'], undefined); assert.doesNotMatch(flow.authorize.text, /synthetic-secret|synthetic-token/);
  const page = await confirmPage(f, flow); assert.match(page.text, /&lt;Owner&gt;/); assert.doesNotMatch(page.text, /1234567/);
  assert.equal(f.calls[0].fields.redirectUri, 'http://localhost:17645/whoop/callback');
  const closing = f.done.then(() => f.close());
  const result = await call(f.server, '/confirm', confirmation(page, flow.cookie));
  assert.equal(result.status, 200); assert.match(result.text, /Temporary grant revoked/); assert.match(result.text, /<strong>1234567<\/strong>/);
  assert(result.text.endsWith('</html>')); assert.deepEqual(await closing, { revoked: true });
  assert.deepEqual(f.calls.map(v => v.kind), ['token', 'profile', 'revoke']);
});

test('ingress rejects host aliases, all supplied forwarding markers, duplicate headers and nonbrowser methods', async t => {
  const f = await fixture(t);
  for (const headers of [{ Host: '127.0.0.1:17645' }, { Host: 'localhost' }, { Host: 'localhost:17646' }, { Host: 'localhost:17645.evil' },
    { Forwarded: 'proto=https' }, { 'X-Forwarded-Proto': 'https' }, { 'x-forwarded-for': '127.0.0.1' },
    { 'X-Forwarded-Host': 'localhost:17645' }, { 'x-whoop-local-ingress': 'a'.repeat(43) },
    ['Host', 'localhost:17645', 'Host', 'localhost:17645'],
    ['Host', 'localhost:17645', 'Origin', LOOPBACK_ORIGIN, 'Origin', LOOPBACK_ORIGIN]]) {
    const result = await call(f.server, '/', { headers }); assert.equal(result.status, 400); assert.doesNotMatch(result.text, /synthetic/);
  }
  for (const method of ['PUT', 'DELETE', 'OPTIONS']) assert.equal((await call(f.server, '/', { method })).status, 400);
  assert.deepEqual(f.calls, []); assert.equal((await call(f.server, '/')).status, 200);
});

test('direct core access cannot replace the private marker with proxy headers or a forged marker', async t => {
  const f = await fixture(t);
  for (const headers of [{}, { 'X-Forwarded-Proto': 'http' }, { 'X-Forwarded-Proto': 'https' },
    { 'x-whoop-local-ingress': 'a'.repeat(43) },
    ['Host', 'localhost:17645', 'x-whoop-local-ingress', 'a'.repeat(43), 'x-whoop-local-ingress', 'a'.repeat(43)]]) {
    assert.equal((await call(f.core, '/', { headers })).status, 400);
  }
  assert.equal((await call(f.server, '/')).status, 200); assert.deepEqual(f.calls, []);
});

test('local Origin, browser cookie and single-use state remain mandatory through real relay requests', async t => {
  const f = await fixture(t); const flow = await begin(f);
  for (const options of [{}, { cookie: '__Host-whoop_identity=other' }, { cookie: flow.cookie, headers: { Origin: 'null' } },
    { cookie: flow.cookie, headers: { Origin: 'https://localhost:17645' } }]) assert.equal((await call(f.server, flow.callback, options)).status, 400);
  assert.equal((await call(f.server, flow.callback + '&state=duplicate', { cookie: flow.cookie })).status, 400);
  assert.deepEqual(f.calls, []);
  const page = await confirmPage(f, flow);
  assert.equal((await call(f.server, flow.callback, { cookie: flow.cookie })).status, 400);
  for (const origin of ['', 'null', 'http://127.0.0.1:17645', 'https://localhost:17645']) {
    assert.equal((await call(f.server, '/confirm', { ...confirmation(page, flow.cookie), headers: { Origin: origin } })).status, 400);
  }
  assert.equal((await call(f.server, '/confirm', { ...confirmation(page, flow.cookie), body: 'csrf=wrong&confirmed=yes' })).status, 400);
  assert.deepEqual(f.calls.map(v => v.kind), ['token', 'profile']);
});

test('relay body bound and original five-minute expiry fail closed without extending state on reload', async t => {
  let time = 1000000; const f = await fixture(t, { now: () => time }); const flow = await begin(f);
  assert.equal((await call(f.server, '/start', { method: 'POST', cookie: flow.cookie, body: 'x'.repeat(1025) })).status, 400);
  const retry = await call(f.server, '/authorize', { cookie: flow.cookie }); assert.equal(link(retry.text), flow.url.href);
  time += 300000; assert.equal((await call(f.server, flow.callback, { cookie: flow.cookie })).status, 400);
  assert.deepEqual(f.calls, []);
});

test('closing during actual relay callback revokes a late token and never returns an ID', async t => {
  let release; let entered; const ready = new Promise(r => { entered = r; }); const hold = new Promise(r => { release = r; }); const calls = [];
  const f = await fixture(t, { upstream: async kind => { calls.push(kind); if (kind === 'token') { entered(); await hold; return token; } return null; } });
  const flow = await begin(f); const pending = call(f.server, flow.callback, { cookie: flow.cookie }).catch(() => null); await ready;
  const closing = f.close(); release(); assert.equal((await closing).revoked, true);
  const result = await pending; if (result) assert.doesNotMatch(result.text, /1234567/);
  assert(calls.includes('revoke')); assert.equal(await f.done, false);
});

test('cancel and failed revocation never report completed identity through the relay', async t => {
  for (const condition of ['cancel', 'revocation-failure']) {
    const f = await fixture(t, { upstream: async kind => {
      if (kind === 'revoke' && condition === 'revocation-failure') throw new Error('synthetic-private-detail');
      return kind === 'token' ? token : kind === 'profile' ? profile : null;
    } });
    const flow = await begin(f); const page = await confirmPage(f, flow);
    const result = await call(f.server, '/confirm', confirmation(page, flow.cookie, condition === 'cancel' ? 'no' : 'yes'));
    assert.doesNotMatch(result.text, /1234567|synthetic-private-detail/); assert.equal(await f.done, false);
    assert.equal((await f.close()).revoked, condition === 'cancel');
  }
});

test('explicit container-edge mode changes only ingress bind and keeps direct core inaccessible', async t => {
  const f = await fixture(t, {}, ['container-edge']);
  assert.equal(f.server.address().address, '0.0.0.0'); assert.equal(f.server.address().port, 17645); assert.equal(f.core.address().address, '127.0.0.1');
  assert.equal((await call(f.server, '/', { localAddress: '127.0.0.2' })).status, 200);
  assert.equal((await call(f.core, '/', { localAddress: '127.0.0.2' })).status, 400);
  assert.equal((await call(f.server, '/', { headers: { 'X-Forwarded-Proto': 'https' } })).status, 400);
  await f.close();
  const local = await fixture(t); assert.equal((await call(local.server, '/', { localAddress: '127.0.0.2' })).status, 400);
});

test('privilege, NNP, argv and environment checks precede stdin access', async () => {
  const input = Object.defineProperty({}, 'isTTY', { get: forbidden });
  for (const key of Object.keys(identity)) await assert.rejects(startLoopbackIdentity({ identity: { ...identity, [key]: () => 0 },
    environment, input, noNewPrivileges: forbidden }), failure);
  await assert.rejects(startLoopbackIdentity({ identity, environment, input, noNewPrivileges: () => { throw new Error('private'); } }), failure);
  for (const args of [['other'], ['container-edge', 'extra']]) await assert.rejects(startLoopbackIdentity({ identity, environment, input, args, noNewPrivileges: () => {} }), failure);
  await assert.rejects(startLoopbackIdentity({ identity, input, environment: { ...environment, NODE_OPTIONS: 'malicious' }, noNewPrivileges: () => {} }), failure);
});

test('stdin is bounded, strict UTF-8, noninteractive and abortable before opening a listener', async () => {
  for (const bytes of ['{', '{}', 'x'.repeat(8193), Buffer.from([0xff]), JSON.stringify({ ...config, hostname: 'example.test' })]) {
    await assert.rejects(startLoopbackIdentity({ input: Readable.from([bytes]), identity, environment, noNewPrivileges: () => {} }), failure);
  }
  const tty = new PassThrough(); tty.isTTY = true;
  await assert.rejects(startLoopbackIdentity({ input: tty, identity, environment, noNewPrivileges: () => {} }), failure);
  const pendingInput = new PassThrough(); const controller = new AbortController();
  const pending = startLoopbackIdentity({ input: pendingInput, identity, environment, noNewPrivileges: () => {}, signal: controller.signal });
  controller.abort(); await assert.rejects(pending, failure);
});

test('clean pre-Node command strips hostile inherited configuration and produces only the fixed error', () => {
  const result = spawnSync('/usr/bin/setpriv', ['--no-new-privs', '--', '/usr/bin/env', '-i', 'PATH=' + environment.PATH,
    process.execPath, fileURLToPath(new URL('./loopback-runtime.mjs', import.meta.url)), 'container-edge'], {
    input: '{', encoding: 'utf8', timeout: 10000,
    env: { ...environment, NODE_OPTIONS: '--require=/must-not-load-synthetic-hook', OPENSSL_CONF: '/must-not-load', SSL_CERT_FILE: '/must-not-load' },
  });
  assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.equal(result.stderr, 'Local identity verification unavailable.\n');
});
