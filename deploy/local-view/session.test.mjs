import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import { createLocalViewServer, parseLocalViewConfig, SCOPES } from './session.mjs';
import { createLoopbackIngress } from '../identity/loopback-ingress.mjs';
import { LOOPBACK_MARKER_HEADER } from '../identity/verify.mjs';

const config = { mode: 'whoop-local-view', clientId: 'synthetic-local-client', clientSecret: 'synthetic-local-secret' };
const marker = 'm'.repeat(43); const origin = 'http://localhost:17645';
const NOW = Date.parse('2026-10-22T12:00:00Z');
const profile = { user_id: 1234, first_name: '<Local owner>', last_name: 'Account', email: 'owner@example.test' };
const token = { access_token: 'synthetic-access', token_type: 'bearer', expires_in: 3600, scope: SCOPES };
const unavailable = { message: 'LOCAL_VIEW_UNAVAILABLE' };
const snapshot = () => ({ version: 1, windowEnd: '2026-10-22', summaries: Array.from({ length: 7 }, (_, i) => ({
  date: new Date(NOW - (6 - i) * 86400000).toISOString().slice(0, 10), status: 'AVAILABLE',
  recovery_score: 72.125, hrv_ms: 45.5, resting_heart_rate: 55, sleep_ms: 28800000, sleep_performance: 90, strain: 12.5,
})) });
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
  const calls = []; const collections = [];
  const service = createLocalViewServer(config, { now: () => NOW, loopbackMarker: marker,
    upstream: async (kind, fields) => { calls.push({ kind, fields }); return kind === 'token' ? token : kind === 'profile' ? profile : null; },
    collect: async options => { collections.push(options); return snapshot(); }, ...options });
  await new Promise(resolve => service.server.listen(0, '127.0.0.1', resolve));
  const ingress = createLoopbackIngress(service.server, marker);
  await new Promise(resolve => ingress.server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { await ingress.close(); await service.close(); });
  return { ...service, ingress, calls, collections };
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
  assert.equal(auth.searchParams.get('scope'), SCOPES); assert(!auth.searchParams.get('scope').includes('offline'));
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
async function finalPage(f, flow) {
  for (let i = 0; i < 20; i++) {
    const page = await request(f, '/confirm', flow);
    if (page.status !== 200 || !page.text.includes('http-equiv="refresh"')) return page;
    await new Promise(resolve => setImmediate(resolve));
  }
  assert.fail('synthetic operation did not settle');
}

test('local-view config is a separate exact mode with fixed destination', () => {
  assert.deepEqual(parseLocalViewConfig(config), config);
  for (const value of [{ ...config, mode: 'whoop-owner-identity-loopback' }, { ...config, hostname: 'other' },
    { ...config, redirectUri: 'https://other.invalid' }, { ...config, clientSecret: '' }, { ...config, databaseUrl: 'sentinel' }])
    assert.throws(() => parseLocalViewConfig(value), unavailable);
  assert.throws(() => createLocalViewServer(config), unavailable);
  assert.throws(() => createLocalViewServer(config, { loopbackMarker: marker, ttlMs: 300001 }), unavailable);
});

test('actual relay flow confirms owner before collection and displays only after successful revocation', async t => {
  const collecting = deferred(), releaseCollection = deferred(), revoking = deferred(), releaseRevoke = deferred();
  const calls = []; let count = 0;
  const f = await fixture(t, {
    upstream: async (kind, fields) => { calls.push(kind); if (kind === 'revoke') { assert.equal(fields.token, token.access_token); revoking.resolve(); await releaseRevoke.promise; return null; } return kind === 'token' ? token : profile; },
    collect: async options => { count++; assert.equal(options.token, token.access_token); assert.equal(options.now, NOW); assert.equal(options.signal.aborted, false); collecting.resolve(); await releaseCollection.promise; return snapshot(); },
  });
  const flow = await begin(f, true);
  // WHOOP's observed callback includes code, scope and state. Scope is optional
  // metadata, independently checked before exchange and again in token output.
  flow.callback += '&scope=' + encodeURIComponent(SCOPES);
  const confirm = await confirmation(f, flow);
  assert.equal(count, 0); assert.deepEqual(calls, ['token', 'profile']);
  const pending = await request(f, '/confirm', confirm); assert.equal(pending.status, 200); await collecting.promise;
  assert.match(pending.text, /http-equiv="refresh"/); assert.doesNotMatch(pending.text, /72\.125/);
  releaseCollection.resolve(); await revoking.promise;
  assert.doesNotMatch((await request(f, '/confirm', flow)).text, /72\.125/);
  // Match the runtime: core response finish immediately starts ingress/core
  // cleanup. The browser must still receive the entire final table.
  const shutdown = f.done.then(async () => { await f.ingress.close(); return f.close(); });
  releaseRevoke.resolve(); const page = await finalPage(f, flow);
  assert.equal(page.status, 200); assert.match(page.text, /72\.125/); assert.match(page.text, /<td>8<\/td>/);
  assert(Buffer.byteLength(page.text) < 16384); assert.doesNotMatch(page.text, /owner@example|1234|synthetic-|<script|<img/);
  assert.equal((page.text.match(/<tr>/g) ?? []).length, 8); assert.equal(count, 1);
  assert.equal(await f.done, true); assert.deepEqual(await shutdown, { revoked: true });
  assert.deepEqual(calls, ['token', 'profile', 'revoke']);
});

test('cancel revokes without collecting any health records', async t => {
  const f = await fixture(t); const flow = await begin(f); const confirm = await confirmation(f, flow);
  const page = await request(f, '/confirm', { ...confirm, body: confirm.body.replace('confirmed=yes', 'confirmed=no') });
  assert.equal(page.status, 200); assert.match(page.text, /No health records were collected/);
  assert.equal(f.collections.length, 0); assert.deepEqual(f.calls.map(v => v.kind), ['token', 'profile', 'revoke']);
  assert.equal(await f.done, false);
});

test('failed revocation withholds collected data and never reports success or retries', async t => {
  let revocations = 0;
  const f = await fixture(t, { upstream: async kind => { if (kind === 'revoke') { revocations++; throw Error('secret upstream diagnostic'); } return kind === 'token' ? token : profile; } });
  const flow = await begin(f); const confirm = await confirmation(f, flow);
  await request(f, '/confirm', confirm); const page = await finalPage(f, flow);
  assert.equal(page.status, 400); assert.doesNotMatch(page.text, /72\.125|secret upstream|synthetic-access/);
  assert.equal(await f.done, false); assert.deepEqual(await f.close(), { revoked: false }); assert.equal(revocations, 1);
});

test('collection failure or noncanonical data still revokes and never displays partial values', async t => {
  for (const collect of [async () => { throw Error('private health'); }, async () => ({ ...snapshot(), url: 'https://evil.invalid' })]) {
    const f = await fixture(t, { collect }); const flow = await begin(f); const confirm = await confirmation(f, flow);
    await request(f, '/confirm', confirm); const page = await finalPage(f, flow);
    assert.equal(page.status, 400); assert.doesNotMatch(page.text, /72\.125|private health|evil/);
    assert.deepEqual(f.calls.map(v => v.kind), ['token', 'profile', 'revoke']); assert.equal(await f.done, false);
  }
});

test('marker, host, Origin, browser, CSRF and callback replay all fail closed', async t => {
  const f = await fixture(t); const flow = await begin(f);
  for (const headers of [{ Host: '127.0.0.1:17645' }, { Origin: 'null' }, { Forwarded: 'for=127.0.0.1' },
    { 'X-Forwarded-Proto': 'http' }, { [LOOPBACK_MARKER_HEADER]: 'wrong' }])
    assert.equal((await request(f, flow.callback, { ...flow, headers })).status, 400);
  assert.equal((await request(f, flow.callback)).status, 400);
  assert.equal((await request(f, flow.callback + '&state=duplicate', flow)).status, 400);
  assert.equal(f.calls.length, 0); const confirm = await confirmation(f, flow);
  assert.equal((await request(f, flow.callback, flow)).status, 400);
  for (const headers of [{ Origin: 'null' }, { Origin: 'https://evil.invalid' }, { Origin: '' }])
    assert.equal((await request(f, '/confirm', { ...confirm, headers })).status, 400);
  assert.equal((await request(f, '/confirm', { ...confirm, body: 'csrf=wrong&confirmed=yes' })).status, 400);
  assert.equal(f.collections.length, 0);
});

test('optional callback scope accepts only the exact whitespace-separated set before exchange through ingress', async t => {
  const f = await fixture(t); const flow = await begin(f, true);
  for (const scope of ['', 'read:profile', SCOPES + ' offline', SCOPES + ' read:profile',
    SCOPES.replace('read:workout', 'read:body_measurement'), SCOPES.replace(' ', ','),
    SCOPES.replace(' ', '\u00a0'), ' '.repeat(257)]) {
    const page = await request(f, flow.callback + '&scope=' + encodeURIComponent(scope), flow);
    assert.equal(page.status, 400); assert.doesNotMatch(page.text, /synthetic-access|72\.125/);
    assert.deepEqual(f.calls, []); assert.equal(f.collections.length, 0);
  }
  const scope = encodeURIComponent(SCOPES);
  assert.equal((await request(f, flow.callback + '&scope=' + scope + '&scope=' + scope, flow)).status, 400);
  assert.deepEqual(f.calls, []);
  const reordered = '\t' + SCOPES.split(' ').reverse().join(' \t\r\n') + ' ';
  assert.equal((await request(f, flow.callback + '&scope=' + encodeURIComponent(reordered), flow)).status, 303);
  assert.deepEqual(f.calls.map(value => value.kind), ['token', 'profile']); assert.equal(f.collections.length, 0);
  assert.equal((await request(f, flow.callback + '&scope=' + scope, flow)).status, 400);
  assert.deepEqual(f.calls.map(value => value.kind), ['token', 'profile']);
});

test('unexpected scopes, offline/refresh grant or malformed profile revoke before confirmation', async t => {
  for (const badToken of [{ ...token, scope: SCOPES + ' offline' }, { ...token, scope: 'read:profile' },
    { ...token, refresh_token: 'unexpected-refresh' }]) {
    const calls = []; const f = await fixture(t, { upstream: async kind => { calls.push(kind); return kind === 'token' ? badToken : null; } });
    const flow = await begin(f, true); flow.callback += '&scope=' + encodeURIComponent(SCOPES);
    assert.equal((await request(f, flow.callback, flow)).status, 400);
    assert.deepEqual(calls, ['token', 'revoke']); assert.equal(f.collections.length, 0);
  }
  const f = await fixture(t, { upstream: async kind => kind === 'token' ? token : kind === 'profile' ? { ...profile, user_id: 0 } : null });
  const flow = await begin(f); assert.equal((await request(f, flow.callback, flow)).status, 400);
  assert.equal(f.collections.length, 0);
});

test('duplicate confirmation races collect only once and unrelated requests do not cancel it', async t => {
  const entered = deferred(), release = deferred(); let count = 0;
  const f = await fixture(t, { collect: async () => { count++; entered.resolve(); await release.promise; return snapshot(); } });
  const flow = await begin(f); const confirm = await confirmation(f, flow);
  const results = await Promise.all([request(f, '/confirm', confirm), request(f, '/confirm', confirm)]);
  assert.deepEqual(results.map(v => v.status).sort(), [200, 400]); await entered.promise;
  assert.equal((await request(f, '/confirm')).status, 400); release.resolve();
  assert.match((await finalPage(f, flow)).text, /72\.125/); assert.equal(count, 1);
});

test('closing during exchange revokes a late token without profile or health access', async t => {
  const entered = deferred(), release = deferred(); const calls = [];
  const f = await fixture(t, { upstream: async kind => { calls.push(kind); if (kind === 'token') { entered.resolve(); await release.promise; return token; } return null; } });
  const flow = await begin(f); const callback = request(f, flow.callback, flow).catch(() => null);
  await entered.promise; const closing = f.close(); release.resolve();
  assert.deepEqual(await closing, { revoked: true }); await callback;
  assert.deepEqual(calls, ['token', 'revoke']); assert.equal(f.collections.length, 0); assert.equal(await f.done, false);
});

test('closing during collection aborts it, revokes and clears data before completing', async t => {
  const entered = deferred(); let aborted = false;
  const f = await fixture(t, { collect: async ({ signal }) => {
    entered.resolve(); await new Promise(resolve => signal.addEventListener('abort', () => { aborted = true; resolve(); }, { once: true }));
    return snapshot();
  } });
  const flow = await begin(f); const confirm = await confirmation(f, flow); await request(f, '/confirm', confirm); await entered.promise;
  assert.deepEqual(await f.close(), { revoked: true }); assert.equal(aborted, true);
  assert.deepEqual(f.calls.map(v => v.kind), ['token', 'profile', 'revoke']); assert.equal(await f.done, false);
});

test('expiry during token exchange revokes the token and does not extend the session', async t => {
  let time = NOW; const entered = deferred(), release = deferred(); const calls = [];
  const f = await fixture(t, { now: () => time, upstream: async kind => { calls.push(kind); if (kind === 'token') { entered.resolve(); await release.promise; return token; } return null; } });
  const flow = await begin(f); const pending = request(f, flow.callback, flow); await entered.promise;
  time += 300000; release.resolve(); assert.equal((await pending).status, 400);
  assert.deepEqual(calls, ['token', 'revoke']); assert.equal((await request(f, '/authorize', flow)).status, 400);
  assert.equal(f.collections.length, 0); assert.equal(await f.done, false);
});
