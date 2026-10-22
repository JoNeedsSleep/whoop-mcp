import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import { createLocalLoginServer, parseLocalLoginConfig, SCOPES } from './login.mjs';
import { createLoopbackIngress } from '../identity/loopback-ingress.mjs';
import { LOOPBACK_MARKER_HEADER, AUTHORIZATION_TTL_MS } from './oauth.mjs';

const config = { mode: 'whoop-local-sync', clientId: 'synthetic-local-client', clientSecret: 'synthetic-local-secret' };
const marker = 'm'.repeat(43); const origin = 'http://localhost:17645';
const NOW = Date.parse('2026-10-22T12:00:00Z');
const profile = { user_id: 1234, first_name: '<Local owner>', last_name: 'Account', email: 'owner@example.test' };
const token = { access_token: 'synthetic-access', refresh_token: 'synthetic-refresh', token_type: 'bearer', expires_in: 3600, scope: SCOPES };
const unavailable = { message: 'LOCAL_SYNC_UNAVAILABLE' };
const csrf = page => page.match(/name="csrf" value="([A-Za-z0-9_-]{43})"/)?.[1];
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
function request(f, route, { method = 'GET', cookie, body, headers = {}, throughIngress = false } = {}) {
  const target = throughIngress ? f.ingress.server : f.server;
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: target.address().port, path: route, method, agent: false,
      headers: { Host: 'localhost:17645', ...(throughIngress ? {} : { [LOOPBACK_MARKER_HEADER]: marker }),
        ...(cookie ? { Cookie: cookie } : {}), ...(body === undefined ? {} : { Origin: origin,
          'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }), ...headers } }, res => {
      const parts = []; res.on('data', b => parts.push(b)); res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(parts).toString(), headers: res.headers }));
    }); req.on('error', reject); req.end(body);
  });
}
async function fixture(t, options = {}) {
  const calls = []; const grants = [];
  const service = createLocalLoginServer(config, { now: () => NOW, loopbackMarker: marker,
    upstream: async (kind, fields) => { calls.push({ kind, fields }); return kind === 'token' ? token : kind === 'profile' ? profile : null; },
    onAuthorize: async (grant, options) => { grants.push({ grant, options }); }, ...options });
  await new Promise(resolve => service.server.listen(0, '127.0.0.1', resolve));
  const ingress = createLoopbackIngress(service.server, marker);
  await new Promise(resolve => ingress.server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { await ingress.close(); await service.close(); });
  return { ...service, ingress, calls, grants };
}
async function begin(f, throughIngress = false) {
  const page = await request(f, '/', { throughIngress }); assert.equal(page.status, 200);
  const cookie = page.headers['set-cookie'][0].split(';')[0];
  assert.match(cookie, /^__Host-whoop_identity=/); assert.match(page.headers['set-cookie'][0], /Secure; HttpOnly; SameSite=Lax/);
  assert.equal(page.headers['cache-control'], 'no-store');
  const start = await request(f, '/start', { method: 'POST', cookie, body: 'csrf=' + csrf(page.text), throughIngress });
  assert.equal(start.status, 303); assert.equal(start.headers.location, '/authorize');
  const navigation = await request(f, '/authorize', { cookie, throughIngress });
  const auth = new URL(navigation.text.match(/<a href="([^"]+)" rel="noreferrer">/)[1].replaceAll('&amp;', '&'));
  assert.equal(auth.origin, 'https://api.prod.whoop.com'); assert.equal(auth.pathname, '/oauth/oauth2/auth');
  assert.equal(auth.searchParams.get('scope'), SCOPES); assert(auth.searchParams.get('scope').includes('offline'));
  assert.equal(auth.searchParams.get('redirect_uri'), origin + '/whoop/callback');
  assert.equal(auth.searchParams.get('code_challenge_method'), 'S256');
  assert.match(auth.searchParams.get('state'), /^[A-Za-z0-9_-]{43}$/);
  assert.doesNotMatch(navigation.text, /synthetic-local-secret|<script/);
  return { cookie, callback: '/whoop/callback?' + new URLSearchParams({ code: 'synthetic-code', state: auth.searchParams.get('state') }), throughIngress };
}
async function confirmation(f, flow) {
  assert.equal((await request(f, flow.callback, flow)).status, 303);
  const page = await request(f, '/confirm', flow); assert.equal(page.status, 200);
  assert.match(page.text, /&lt;Local owner&gt;/); assert.doesNotMatch(page.text, /<Local owner>|synthetic-access|72\.125/);
  return { ...flow, body: 'csrf=' + csrf(page.text) + '&confirmed=yes', method: 'POST' };
}

test('separate exact local-sync config rejects remote/local-view modes, destination overrides and missing store callback', () => {
  assert.deepEqual(parseLocalLoginConfig(config), config);
  for (const value of [{ ...config, mode: 'whoop-local-view' }, { ...config, mode: 'whoop-owner-identity-loopback' },
    { ...config, hostname: 'other' }, { ...config, redirectUri: 'https://evil.invalid' }, { ...config, clientSecret: '' }])
    assert.throws(() => parseLocalLoginConfig(value), unavailable);
  assert.throws(() => createLocalLoginServer(config, { loopbackMarker: marker }), unavailable);
  assert.throws(() => createLocalLoginServer(config, { loopbackMarker: marker, onAuthorize() {}, ttlMs: 300001 }), unavailable);
});

test('actual ingress confirms owner before exact seven-day durable handoff and success never revokes', async t => {
  const entered = deferred(), release = deferred(); let grant;
  const f = await fixture(t, { onAuthorize: async (value, { signal }) => { grant = value; assert.equal(signal.aborted, false); entered.resolve(); await release.promise; } });
  const flow = await begin(f, true); flow.callback += '&scope=' + encodeURIComponent(SCOPES);
  const confirm = await confirmation(f, flow); assert.equal(grant, undefined);
  const pending = request(f, '/confirm', confirm); await entered.promise;
  assert.deepEqual(grant, { clientId: config.clientId, clientSecret: config.clientSecret, userId: '1234',
    accessToken: token.access_token, refreshToken: token.refresh_token, accessExpiresAt: NOW + 3600000,
    authorizedAt: NOW, authorizationExpiresAt: NOW + AUTHORIZATION_TTL_MS });
  assert.equal((await request(f, '/confirm', confirm)).status, 400);
  const shutdown = f.done.then(async () => { await f.ingress.close(); return f.close(); });
  release.resolve(); const page = await pending;
  assert.equal(page.status, 200); assert.match(page.text, /connection saved/); assert.match(page.text, /15 minutes/);
  assert.doesNotMatch(page.text, /synthetic-|1234|owner@example|<script|<img|refresh_token/);
  assert(Buffer.byteLength(page.text) < 16384); assert.equal(await f.done, true);
  assert.deepEqual(await shutdown, { authorized: true, revoked: false });
  assert.deepEqual(f.calls.map(v => v.kind), ['token', 'profile']);
});

test('cancel revokes once, never saves a grant, and contains no health endpoint', async t => {
  const f = await fixture(t), flow = await begin(f), confirm = await confirmation(f, flow);
  const page = await request(f, '/confirm', { ...confirm, body: confirm.body.replace('confirmed=yes', 'confirmed=no') });
  assert.equal(page.status, 200); assert.match(page.text, /No connection was saved/); assert.equal(f.grants.length, 0);
  assert.deepEqual(f.calls.map(v => v.kind), ['token', 'profile', 'revoke']); assert.equal(await f.done, false);
  assert.deepEqual(await f.close(), { authorized: false, revoked: true });
});

test('failed storage revokes and failed revocation remains explicit with no secret error or retry', async t => {
  for (const revokeFails of [false, true]) {
    let revokes = 0;
    const f = await fixture(t, { onAuthorize: async () => { throw Error('private disk contents'); },
      upstream: async kind => { if (kind === 'revoke') { revokes++; if (revokeFails) throw Error('private token'); return null; } return kind === 'token' ? token : profile; } });
    const flow = await begin(f), confirm = await confirmation(f, flow), page = await request(f, '/confirm', confirm);
    assert.equal(page.status, 400); assert.doesNotMatch(page.text, /connection saved|private disk|private token|synthetic-/);
    assert.equal(await f.done, false); assert.deepEqual(await f.close(), { authorized: false, revoked: !revokeFails }); assert.equal(revokes, 1);
  }
});

test('marker, exact Host/Origin, browser cookie, CSRF, state and callback replay gates precede side effects', async t => {
  const f = await fixture(t), flow = await begin(f);
  for (const headers of [{ Host: '127.0.0.1:17645' }, { Origin: 'null' }, { Forwarded: 'for=127.0.0.1' },
    { 'X-Forwarded-Proto': 'http' }, { [LOOPBACK_MARKER_HEADER]: 'wrong' }])
    assert.equal((await request(f, flow.callback, { ...flow, headers })).status, 400);
  assert.equal((await request(f, flow.callback)).status, 400);
  assert.equal((await request(f, flow.callback + '&state=duplicate', flow)).status, 400); assert.equal(f.calls.length, 0);
  const confirm = await confirmation(f, flow); assert.equal((await request(f, flow.callback, flow)).status, 400);
  assert.equal((await request(f, '/confirm', { ...confirm, headers: { Origin: 'https://evil.invalid' } })).status, 400);
  assert.equal((await request(f, '/confirm', { ...confirm, body: 'csrf=wrong&confirmed=yes' })).status, 400);
  assert.equal(f.grants.length, 0);
});

test('optional callback scope accepts exactly the six-scope set before exchange through actual ingress', async t => {
  const f = await fixture(t), flow = await begin(f, true);
  for (const scope of ['', 'offline', SCOPES.replace(' offline', ''), SCOPES + ' offline', SCOPES + ' read:body_measurement',
    SCOPES.replace(' ', ','), SCOPES.replace(' ', '\u00a0'), ' '.repeat(257)]) {
    assert.equal((await request(f, flow.callback + '&scope=' + encodeURIComponent(scope), flow)).status, 400); assert.equal(f.calls.length, 0);
  }
  const scope = encodeURIComponent(SCOPES);
  assert.equal((await request(f, flow.callback + '&scope=' + scope + '&scope=' + scope, flow)).status, 400);
  assert.equal(f.calls.length, 0);
  assert.equal((await request(f, flow.callback + '&scope=' + encodeURIComponent('\t' + SCOPES.split(' ').reverse().join(' \r\n')), flow)).status, 303);
  assert.deepEqual(f.calls.map(v => v.kind), ['token', 'profile']); assert.equal(f.grants.length, 0);
});

test('strict token/profile rejection revokes usable access tokens without saving', async t => {
  for (const bad of [{ ...token, scope: 'offline' }, { ...token, refresh_token: '' }, { ...token, expires_in: 0 }, { ...token, token_type: 'MAC' }]) {
    const calls = [];
    const f = await fixture(t, { upstream: async kind => { calls.push(kind); return kind === 'token' ? bad : null; } });
    const flow = await begin(f); assert.equal((await request(f, flow.callback, flow)).status, 400);
    assert.deepEqual(calls, ['token', 'revoke']); assert.equal(f.grants.length, 0);
  }
  const f = await fixture(t, { upstream: async kind => kind === 'token' ? token : kind === 'profile' ? { ...profile, user_id: 0 } : null });
  const flow = await begin(f); assert.equal((await request(f, flow.callback, flow)).status, 400); assert.equal(f.grants.length, 0);
});

test('concurrent confirmations consume the handoff once; duplicate unrelated requests cannot revoke it', async t => {
  const entered = deferred(), release = deferred(); let saved = 0;
  const f = await fixture(t, { onAuthorize: async () => { saved++; entered.resolve(); await release.promise; } });
  const flow = await begin(f), confirm = await confirmation(f, flow);
  const first = request(f, '/confirm', confirm); await entered.promise;
  assert.equal((await request(f, '/confirm', confirm)).status, 400);
  assert.equal((await request(f, '/confirm')).status, 400); release.resolve(); assert.equal((await first).status, 200);
  assert.equal(saved, 1); assert.deepEqual(f.calls.map(v => v.kind), ['token', 'profile']);
});

test('closing or expiring during exchange revokes a late token without profile or persistence', async t => {
  for (const expire of [false, true]) {
    let time = NOW; const entered = deferred(), release = deferred(), calls = [];
    const f = await fixture(t, { now: () => time, upstream: async kind => { calls.push(kind); if (kind === 'token') { entered.resolve(); await release.promise; return token; } return null; } });
    const flow = await begin(f), pending = request(f, flow.callback, flow).catch(() => null); await entered.promise;
    if (expire) time += 300000;
    const closing = expire ? null : f.close(); release.resolve(); const page = await pending;
    if (expire) assert.equal(page.status, 400);
    assert.deepEqual(await (closing ?? f.close()), { authorized: false, revoked: true }); assert.equal(await f.done, false);
    assert.deepEqual(calls, ['token', 'revoke']); assert.equal(f.grants.length, 0);
  }
});

test('close aborts an uncommitted handoff; storage rejects and grant is revoked', async t => {
  const entered = deferred(); let aborted = false;
  const f = await fixture(t, { onAuthorize: async (_grant, { signal }) => {
    entered.resolve(); await new Promise(resolve => signal.addEventListener('abort', () => { aborted = true; resolve(); }, { once: true }));
    throw Error('aborted before atomic commit');
  } });
  const flow = await begin(f), confirm = await confirmation(f, flow), pending = request(f, '/confirm', confirm).catch(() => null);
  await entered.promise; assert.deepEqual(await f.close(), { authorized: false, revoked: true }); await pending;
  assert.equal(aborted, true); assert.equal(await f.done, false); assert.deepEqual(f.calls.map(v => v.kind), ['token', 'profile', 'revoke']);
});

test('a durable commit wins a simultaneous close or lost response and is never revoked', async t => {
  const entered = deferred(), resolveCommit = deferred();
  const f = await fixture(t, { onAuthorize: async (_grant, { signal }) => { assert.equal(signal.aborted, false); entered.resolve(); await resolveCommit.promise; } });
  const flow = await begin(f), confirm = await confirmation(f, flow), pending = request(f, '/confirm', confirm).catch(() => null);
  await entered.promise;
  // Commit has happened; its resolved notification races process shutdown.
  resolveCommit.resolve(); const closing = f.close(); await pending;
  assert.deepEqual(await closing, { authorized: true, revoked: false }); assert.equal(await f.done, true);
  assert.deepEqual(f.calls.map(v => v.kind), ['token', 'profile']);
});

test('access-token expiry before human confirmation refuses storage without an implicit refresh', async t => {
  let time = NOW;
  const f = await fixture(t, { now: () => time, upstream: async kind => kind === 'token' ? { ...token, expires_in: 1 } : kind === 'profile' ? profile : null });
  const flow = await begin(f), confirm = await confirmation(f, flow); time += 1000;
  assert.equal((await request(f, '/confirm', confirm)).status, 400); assert.equal(f.grants.length, 0);
  assert.deepEqual(await f.close(), { authorized: false, revoked: true });
});
