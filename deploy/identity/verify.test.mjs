import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createIdentityServer, parseIdentityConfig, requestWhoop } from './verify.mjs';
import { startIdentityVerification } from './runtime.mjs';

const config = { mode: 'whoop-owner-identity', hostname: 'backend.test-tailnet.ts.net', clientId: 'synthetic-client', clientSecret: 'synthetic-client-secret' };
const origin = 'https://' + config.hostname;
const token = { access_token: 'synthetic-access-token', token_type: 'bearer', scope: 'read:profile', expires_in: 3600 };
const profile = { user_id: 1234567, first_name: '<Owner>', last_name: 'Account', email: 'owner@example.test' };
const failure = { message: 'IDENTITY_UNAVAILABLE' };
const csrf = text => text.match(/name="csrf" value="([A-Za-z0-9_-]{43})"/)?.[1];
function call(server, path, { method = 'GET', cookie, body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: server.address().port, path, method,
      headers: { Host: config.hostname, 'X-Forwarded-Proto': 'https', ...(cookie ? { Cookie: cookie } : {}),
        ...(body !== undefined ? { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } : {}), ...headers } }, res => {
      const chunks = []; res.on('data', b => chunks.push(b)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString() }));
    }); req.on('error', reject); req.end(body);
  });
}
async function fixture(t, options = {}) {
  const calls = [];
  const service = createIdentityServer(config, { upstream: async (kind, fields) => {
    calls.push({ kind, fields }); return kind === 'token' ? token : kind === 'profile' ? profile : null;
  }, ...options });
  await new Promise(resolve => service.server.listen(0, '127.0.0.1', resolve));
  t.after(() => service.close());
  return { ...service, calls };
}
async function begin(service) {
  const page = await call(service.server, '/'); assert.equal(page.status, 200);
  const cookie = page.headers['set-cookie'][0].split(';')[0];
  assert.match(page.headers['set-cookie'][0], /Secure; HttpOnly; SameSite=Lax/);
  assert.equal(page.headers['cache-control'], 'no-store'); assert.equal(page.headers['referrer-policy'], 'strict-origin');
  const redirect = await call(service.server, '/start', { method: 'POST', cookie, body: new URLSearchParams({ csrf: csrf(page.text) }).toString() });
  assert.equal(redirect.status, 303); const url = new URL(redirect.headers.location);
  assert.equal(url.origin, 'https://api.prod.whoop.com'); assert.equal(url.pathname, '/oauth/oauth2/auth');
  assert.equal(url.searchParams.get('scope'), 'read:profile'); assert.equal(url.searchParams.get('redirect_uri'), origin + '/whoop/callback');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  return { cookie, callback: '/whoop/callback?' + new URLSearchParams({ code: 'synthetic-code', state: url.searchParams.get('state') }), page, redirect };
}

test('exact identity-only config rejects generic services, destinations and extra secrets', () => {
  assert.deepEqual(parseIdentityConfig(config), config);
  for (const raw of [{ ...config, mode: 'backend' }, { ...config, hostname: 'public.example' }, { ...config, databaseUrl: 'secret' }, { ...config, clientSecret: '' }]) assert.throws(() => parseIdentityConfig(raw), failure);
});

test('one browser completes profile-only flow, confirms escaped account, then sees ID only after revoke', async t => {
  const f = await fixture(t); const flow = await begin(f);
  const callback = await call(f.server, flow.callback, { cookie: flow.cookie });
  assert.equal(callback.status, 303); assert.equal(callback.headers.location, '/confirm');
  assert.deepEqual(f.calls.map(v => v.kind), ['token', 'profile']);
  const page = await call(f.server, '/confirm', { cookie: flow.cookie });
  assert.equal(page.status, 200); assert(page.text.includes('&lt;Owner&gt;')); assert(!page.text.includes('<Owner>'));
  assert(!page.text.includes('1234567')); assert(!page.text.includes('synthetic-access-token'));
  const completed = await call(f.server, '/confirm', { method: 'POST', cookie: flow.cookie, body: new URLSearchParams({ csrf: csrf(page.text), confirmed: 'yes' }).toString() });
  assert.equal(completed.status, 200); assert(completed.text.includes('<strong>1234567</strong>'));
  assert.deepEqual(f.calls.map(v => v.kind), ['token', 'profile', 'revoke']); assert.equal(await f.done, true);
  assert.equal((await f.close()).revoked, true);
});

test('exact host/proxy/origin/CSRF/browser checks and callback replay deny without a second exchange', async t => {
  const f = await fixture(t); const flow = await begin(f);
  for (const headers of [{ Host: 'evil.example' }, { 'X-Forwarded-Proto': 'http' }, { Origin: 'null' }]) assert.equal((await call(f.server, flow.callback, { cookie: flow.cookie, headers })).status, 400);
  assert.equal((await call(f.server, flow.callback)).status, 400);
  assert.equal((await call(f.server, flow.callback + '&state=duplicate', { cookie: flow.cookie })).status, 400);
  assert.equal(f.calls.length, 0);
  assert.equal((await call(f.server, flow.callback, { cookie: flow.cookie })).status, 303);
  assert.equal((await call(f.server, flow.callback, { cookie: flow.cookie })).status, 400);
  const page = await call(f.server, '/confirm', { cookie: flow.cookie });
  for (const headers of [{ Origin: 'null' }, { Origin: 'https://evil.example' }, { Origin: '' }]) {
    assert.equal((await call(f.server, '/confirm', { method: 'POST', cookie: flow.cookie, body: new URLSearchParams({ csrf: csrf(page.text), confirmed: 'yes' }).toString(), headers })).status, 400);
  }
  assert.equal((await call(f.server, '/confirm', { method: 'POST', cookie: flow.cookie, body: 'csrf=wrong&confirmed=yes' })).status, 400);
  assert.deepEqual(f.calls.map(v => v.kind), ['token', 'profile']);
});

test('unrelated browser during token exchange cannot consume or abort the legitimate flow', async t => {
  let release; let entered; const ready = new Promise(r => { entered = r; }); const hold = new Promise(r => { release = r; }); const calls = [];
  const f = await fixture(t, { upstream: async kind => { calls.push(kind); if (kind === 'token') { entered(); await hold; return token; } return kind === 'profile' ? profile : null; } });
  const flow = await begin(f); const pending = call(f.server, flow.callback, { cookie: flow.cookie });
  await ready; assert.equal((await call(f.server, '/confirm')).status, 400); release();
  assert.equal((await pending).status, 303); assert.deepEqual(calls, ['token', 'profile']);
});

test('stop during token exchange revokes a late-arriving token before clearing state', async t => {
  let release; let entered; const ready = new Promise(r => { entered = r; }); const hold = new Promise(r => { release = r; }); const calls = [];
  const f = await fixture(t, { upstream: async kind => { calls.push(kind); if (kind === 'token') { entered(); await hold; return token; } return null; } });
  const flow = await begin(f); const pending = call(f.server, flow.callback, { cookie: flow.cookie });
  // This rejection is expected if a peer outlives the graceful shutdown bound.
  const observed = pending.catch(() => null); await ready;
  const closing = f.close(); release();
  assert.deepEqual(await closing, { revoked: true });
  const result = await observed; if (result) assert(!result.text.includes('1234567'));
  assert.deepEqual(calls, ['token', 'revoke']); assert.equal(await f.done, false);
});

test('expired in-flight exchange also revokes and never fetches profile', async t => {
  let time = 1000000; let release; let entered; const ready = new Promise(r => { entered = r; }); const hold = new Promise(r => { release = r; }); const calls = [];
  const f = await fixture(t, { now: () => time, upstream: async kind => { calls.push(kind); if (kind === 'token') { entered(); await hold; return token; } return null; } });
  const flow = await begin(f); const pending = call(f.server, flow.callback, { cookie: flow.cookie });
  await ready; time += 300001; release(); assert.equal((await pending).status, 400);
  assert.deepEqual(calls, ['token', 'revoke']); assert.equal(await f.done, false);
});

test('concurrent callbacks and confirmations perform each upstream action once', async t => {
  let release; let entered; const ready = new Promise(r => { entered = r; }); const hold = new Promise(r => { release = r; }); const calls = [];
  const f = await fixture(t, { upstream: async kind => { calls.push(kind); if (kind === 'token') { entered(); await hold; return token; } return kind === 'profile' ? profile : null; } });
  const flow = await begin(f); const first = call(f.server, flow.callback, { cookie: flow.cookie }); await ready;
  assert.equal((await call(f.server, flow.callback, { cookie: flow.cookie })).status, 400); release(); assert.equal((await first).status, 303);
  const page = await call(f.server, '/confirm', { cookie: flow.cookie });
  const values = { method: 'POST', cookie: flow.cookie, body: new URLSearchParams({ csrf: csrf(page.text), confirmed: 'yes' }).toString() };
  const results = await Promise.all([call(f.server, '/confirm', values), call(f.server, '/confirm', values)]);
  assert.deepEqual(results.map(v => v.status).sort(), [200, 400]); assert.deepEqual(calls, ['token', 'profile', 'revoke']);
});

test('immediate runtime-style close after finish still delivers the complete final HTTP page', async t => {
  const f = await fixture(t); const flow = await begin(f); await call(f.server, flow.callback, { cookie: flow.cookie });
  const page = await call(f.server, '/confirm', { cookie: flow.cookie });
  const shutdown = f.done.then(() => f.close());
  const result = await call(f.server, '/confirm', { method: 'POST', cookie: flow.cookie, body: new URLSearchParams({ csrf: csrf(page.text), confirmed: 'yes' }).toString() });
  assert.equal(result.status, 200); assert(result.text.endsWith('</html>')); assert(result.text.includes('<strong>1234567</strong>'));
  assert.deepEqual(await shutdown, { revoked: true });
});

test('scope escalation or refresh token triggers revocation before any profile request', async t => {
  for (const changed of [{ ...token, scope: 'read:profile read:recovery' }, { ...token, refresh_token: 'synthetic-refresh' }]) {
    const calls = []; const f = await fixture(t, { upstream: async kind => { calls.push(kind); return kind === 'token' ? changed : null; } });
    const flow = await begin(f); const result = await call(f.server, flow.callback, { cookie: flow.cookie });
    assert.equal(result.status, 400); assert.deepEqual(calls, ['token', 'revoke']); assert(!result.text.includes('synthetic-')); await f.close();
  }
});

test('cancel, expiry and failed revocation never produce an approved numeric ID', async t => {
  for (const condition of ['cancel', 'expire', 'revoke-failure']) {
    let time = 1000000; const calls = [];
    const f = await fixture(t, { now: () => time, upstream: async kind => {
      calls.push(kind); if (kind === 'revoke' && condition === 'revoke-failure') throw Error('secret upstream detail');
      return kind === 'token' ? token : kind === 'profile' ? profile : null;
    } });
    const flow = await begin(f); await call(f.server, flow.callback, { cookie: flow.cookie });
    const page = await call(f.server, '/confirm', { cookie: flow.cookie });
    if (condition === 'expire') time += 300001;
    const result = await call(f.server, '/confirm', { method: 'POST', cookie: flow.cookie, body: new URLSearchParams({ csrf: csrf(page.text), confirmed: condition === 'cancel' ? 'no' : 'yes' }).toString() });
    assert(!result.text.includes('1234567')); assert(!result.text.includes('secret upstream detail'));
    const cleanup = await f.close(); assert.equal(cleanup.revoked, condition !== 'revoke-failure'); assert(calls.includes('revoke'));
  }
});

test('fixed WHOOP transport enforces TLS, destinations, redirect refusal and response bounds', async () => {
  for (const kind of ['token', 'profile', 'revoke']) {
    let observed;
    const result = await requestWhoop(kind, { token: 'synthetic-token', code: 'synthetic-code', clientId: 'id', clientSecret: 'secret', verifier: 'verifier', redirectUri: origin + '/whoop/callback' }, { request: (options, callback) => {
      observed = options; const req = new EventEmitter(); req.destroy = () => {}; req.end = () => queueMicrotask(() => {
        const response = new PassThrough(); response.statusCode = kind === 'revoke' ? 204 : 200; response.headers = { 'content-type': 'application/json' };
        callback(response); response.end(kind === 'revoke' ? undefined : '{"ok":true}');
      }); return req;
    } });
    assert.equal(observed.hostname, 'api.prod.whoop.com'); assert.equal(observed.servername, 'api.prod.whoop.com'); assert.equal(observed.port, 443);
    assert.equal(observed.rejectUnauthorized, true); assert.equal(observed.agent, false); assert.equal(observed.minVersion, 'TLSv1.2');
    assert.equal(observed.checkServerIdentity('other', { subjectaltname: 'DNS:api.prod.whoop.com' }), undefined);
    assert(observed.checkServerIdentity('api.prod.whoop.com', { subjectaltname: 'DNS:evil.test' }) instanceof Error);
    assert.deepEqual(result, kind === 'revoke' ? null : { ok: true });
  }
  for (const fault of ['redirect', 'compressed', 'oversized', 'malformed']) {
    await assert.rejects(requestWhoop('profile', { token: 'synthetic' }, { request: (_options, callback) => {
      const req = new EventEmitter(); req.destroy = () => {}; req.end = () => queueMicrotask(() => {
        const response = new PassThrough(); response.statusCode = fault === 'redirect' ? 302 : 200;
        response.headers = { 'content-type': 'application/json', ...(fault === 'compressed' ? { 'content-encoding': 'gzip' } : {}) };
        callback(response); response.end(fault === 'oversized' ? 'x'.repeat(8193) : '{');
      }); return req;
    } }), failure);
  }
});

test('runtime identity/NNP/env/argv guards precede credentials and never enable enrollment', async () => {
  const identity = { getuid: () => 1000, getgid: () => 1000, geteuid: () => 1000, getegid: () => 1000 };
  const forbidden = () => assert.fail('private input or daemon reached');
  const base = { identity, environment: {}, noNewPrivileges: () => {}, readConfig: forbidden, tailscale: forbidden };
  for (const key of Object.keys(identity)) await assert.rejects(startIdentityVerification({ ...base, identity: { ...identity, [key]: () => 0 } }), failure);
  await assert.rejects(startIdentityVerification({ ...base, noNewPrivileges: () => { throw Error('kernel'); } }), failure);
  await assert.rejects(startIdentityVerification({ ...base, args: ['--enroll'] }), failure);
  for (const key of ['WHOOP_STAGING_BOOTSTRAP', 'DATABASE_URL', 'PGHOST', 'NODE_OPTIONS', 'TS_AUTHKEY']) {
    await assert.rejects(startIdentityVerification({ ...base, environment: Object.defineProperty({}, key, { enumerable: true, get: forbidden }) }), failure);
  }
});

test('actual packaged CLI guard emits only a fixed error for inherited credentials', () => {
  assert.equal(process.getuid(), 1000, 'run only in the verified isolated fixture');
  const child = spawnSync(process.execPath, [fileURLToPath(new URL('./runtime.mjs', import.meta.url))], {
    env: { PATH: '/usr/local/bin:/usr/bin:/bin', WHOOP_CLIENT_SECRET: 'synthetic-secret-sentinel' }, encoding: 'utf8', timeout: 5000,
  });
  assert.equal(child.status, 1); assert.equal(child.stdout, ''); assert.equal(child.stderr, 'Identity verification unavailable.\n');
});
