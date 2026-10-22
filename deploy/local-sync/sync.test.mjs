import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { authorizeGrant, withLockedState, AUTHORIZATION_TTL_MS, SYNC_INTERVAL_MS } from './state.mjs';
import { syncOnce, revokeAuthorization } from './sync.mjs';
import { SCOPES } from './oauth.mjs';
import { readCache, CACHE_TTL_MS } from '../../restricted-local/cache.mjs';

const NOW = Date.parse('2026-10-22T12:00:00Z');
const snapshot = time => ({ version: 1, windowEnd: new Date(time).toISOString().slice(0, 10), summaries: Array.from({ length: 7 }, (_, index) => ({
  date: new Date(Date.parse(new Date(time).toISOString().slice(0, 10)) - (6 - index) * 86400000).toISOString().slice(0, 10), status: 'AVAILABLE',
  recovery_score: 80, hrv_ms: 45, resting_heart_rate: 55, sleep_ms: 28800000, sleep_performance: 90, strain: 12,
})) });
async function fixture(t, overrides = {}, initialTime = NOW) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'local-sync-job-')); const authDir = path.join(root, 'auth');
  fs.mkdirSync(authDir, { mode: 0o700 }); const cachePaths = {};
  for (const client of ['codex', 'claude-code']) { const dir = path.join(root, client); fs.mkdirSync(dir, { mode: 0o700 }); cachePaths[client] = path.join(dir, 'cache.json'); }
  t.after(() => fs.rmSync(root, { recursive: true, force: true })); let time = initialTime;
  const options = { authDir, cachePaths, now: () => time };
  const grant = { clientId: 'synthetic-client', clientSecret: 'synthetic-secret', userId: '1234', accessToken: 'old-access', refreshToken: 'old-refresh',
    authorizedAt: NOW, accessExpiresAt: NOW + 3600000, authorizationExpiresAt: NOW + AUTHORIZATION_TTL_MS, ...overrides };
  await authorizeGrant(grant, options);
  return { ...options, grant, setTime: value => { time = value; } };
}
const freshToken = (overrides = {}) => ({ access_token: 'rotated-access', refresh_token: 'rotated-refresh', expires_in: 3600, token_type: 'Bearer', scope: SCOPES, ...overrides });

test('one admitted collection writes two credential-free caches with90min ceiling and no duplicate fetch', async t => {
  const f = await fixture(t); let count = 0;
  const options = { ...f, upstream: () => assert.fail('no OAuth request needed'), collect: async ({ token, now }) => { count++; assert.equal(token, 'old-access'); return snapshot(now); } };
  assert.deepEqual(await syncOnce(options), { status: 'updated' }); assert.equal(count, 1);
  for (const [client, filename] of Object.entries(f.cachePaths)) {
    const cached = readCache(filename, client, NOW); assert.equal(cached.expiresAt, NOW + CACHE_TTL_MS);
    assert.equal(cached.authorizationExpiresAt, f.grant.authorizationExpiresAt);
    assert.doesNotMatch(fs.readFileSync(filename, 'utf8'), /synthetic|refresh|accessToken|clientSecret|userId/);
  }
  assert.deepEqual(await syncOnce(options), { status: 'limited' }); assert.equal(count, 1);
  f.setTime(NOW + SYNC_INTERVAL_MS - 1); assert.equal((await syncOnce(options)).status, 'limited');
  f.setTime(NOW + SYNC_INTERVAL_MS); assert.equal((await syncOnce(options)).status, 'updated'); assert.equal(count, 2);
});

test('failed collection remains charged across reopen and cannot extend original cached bytes/deadline', async t => {
  const f = await fixture(t);
  assert.equal((await syncOnce({ ...f, collect: async ({ now }) => snapshot(now) })).status, 'updated');
  const bytes = Object.values(f.cachePaths).map(filename => fs.readFileSync(filename));
  f.setTime(NOW + SYNC_INTERVAL_MS); let calls = 0;
  const failing = { ...f, collect: async () => { calls++; throw Error('private error'); } };
  assert.equal((await syncOnce(failing)).status, 'unavailable'); assert.equal((await syncOnce(failing)).status, 'limited');
  f.setTime(NOW - 1); assert.equal((await syncOnce(failing)).status, 'limited'); assert.equal(calls, 1);
  Object.values(f.cachePaths).forEach((filename, i) => assert.deepEqual(fs.readFileSync(filename), bytes[i]));
  assert.throws(() => readCache(f.cachePaths.codex, 'codex', NOW + CACHE_TTL_MS));
});

test('rotated access+refresh are durable before health call and fixed7day deadline never moves', async t => {
  const f = await fixture(t, { accessExpiresAt: NOW + 1000 }); const events = [];
  const result = await syncOnce({ ...f, upstream: async (kind, fields) => {
    events.push(kind); assert.equal(kind, 'refresh'); assert.equal(fields.refreshToken, 'old-refresh'); return freshToken();
  }, collect: async ({ token, now }) => {
    events.push('collect'); assert.equal(token, 'rotated-access');
    const db = new DatabaseSync(path.join(f.authDir, 'state.sqlite'), { readOnly: true });
    const state = JSON.parse(db.prepare('SELECT value FROM durable_state WHERE id=1').get().value); db.close();
    assert.equal(state.grant.refreshToken, 'rotated-refresh'); assert.equal(state.phase, 'active');
    assert.equal(fs.existsSync(path.join(f.authDir, 'refresh.pending')), false); return snapshot(now);
  } });
  assert.equal(result.status, 'updated'); assert.deepEqual(events, ['refresh', 'collect']);
  assert.equal(await withLockedState(store => store.read().grant.authorizationExpiresAt, f), f.grant.authorizationExpiresAt);
});

test('parallel refresh/sync/revoke is excluded across independent state handles', async t => {
  const f = await fixture(t, { accessExpiresAt: NOW + 1000 }); let release; let entered;
  const start = new Promise(resolve => { entered = resolve; }), wait = new Promise(resolve => { release = resolve; }); let refreshes = 0;
  const options = { ...f, upstream: async () => { refreshes++; entered(); await wait; return freshToken(); }, collect: async ({ now }) => snapshot(now) };
  const first = syncOnce(options); await start;
  assert.equal((await syncOnce(options)).status, 'busy'); assert.equal((await revokeAuthorization(options)).status, 'busy');
  release(); assert.equal((await first).status, 'updated'); assert.equal(refreshes, 1);
});

test('real SQLite rejection after rotation forces reauthorization and revokes newtoken before any health', async t => {
  const f = await fixture(t, { accessExpiresAt: NOW + 1000 });
  const db = new DatabaseSync(path.join(f.authDir, 'state.sqlite'));
  db.exec("CREATE TRIGGER reject_rotation BEFORE UPDATE ON durable_state WHEN json_extract(NEW.value,'$.grant.accessToken')='rotated-access' BEGIN SELECT RAISE(FAIL,'synthetic write failure'); END;"); db.close();
  const calls = [];
  assert.equal((await syncOnce({ ...f, upstream: async (kind, fields) => { calls.push({ kind, fields }); return kind === 'refresh' ? freshToken() : null; }, collect: () => assert.fail('health after failed persistence') })).status, 'reauthorize');
  assert.deepEqual(calls.map(value => value.kind), ['refresh', 'revoke']); assert.equal(calls[1].fields.token, 'rotated-access');
  assert.equal(await withLockedState(store => store.read().grant, f), null);
  assert.equal(fs.existsSync(path.join(f.authDir, 'refresh.pending')), true);
  assert(Object.values(f.cachePaths).every(filename => !fs.existsSync(filename)));
});

test('invalid rotated scope or abort still revokes newly returned access token without reuse', async t => {
  for (const abort of [false, true]) {
    const f = await fixture(t, { accessExpiresAt: NOW + 1000 }); const controller = new AbortController(); const calls = [];
    const result = await syncOnce({ ...f, signal: controller.signal, upstream: async (kind, fields) => {
      calls.push({ kind, fields }); if (kind === 'refresh') { if (abort) controller.abort(); return freshToken(abort ? {} : { scope: 'offline read:profile' }); } return null;
    }, collect: () => assert.fail('health after invalid refresh') });
    assert.equal(result.status, 'reauthorize'); assert.equal(calls[1].fields.token, 'rotated-access');
    assert.equal(await withLockedState(store => store.read().grant, f), null);
  }
});

test('crash marker forces one cleanup attempt, never a second refresh or health call', async t => {
  const f = await fixture(t); await withLockedState(store => store.beginRefresh(), f); const calls = [];
  const options = { ...f, upstream: async kind => { calls.push(kind); throw Error('revocation unavailable'); }, collect: () => assert.fail('interrupted refresh reused') };
  assert.equal((await syncOnce(options)).status, 'reauthorize'); assert.equal((await syncOnce(options)).status, 'reauthorize');
  assert.deepEqual(calls, ['revoke']); assert.equal(await withLockedState(store => store.read().grant, f), null);
});

test('day7 denies before refresh/health, removes both caches/auth and attempts revoke once', async t => {
  const f = await fixture(t); await syncOnce({ ...f, collect: async ({ now }) => snapshot(now) });
  f.setTime(f.grant.authorizationExpiresAt); const calls = [];
  const options = { ...f, upstream: async kind => { calls.push(kind); return null; }, collect: () => assert.fail('expired health request') };
  assert.equal((await syncOnce(options)).status, 'reauthorize'); assert.deepEqual(calls, ['revoke']);
  assert.equal(await withLockedState(store => store.read().grant, f), null); assert(Object.values(f.cachePaths).every(filename => !fs.existsSync(filename)));
  assert.equal((await syncOnce(options)).status, 'reauthorize'); assert.deepEqual(calls, ['revoke']);
});

test('cache expiry is capped at grant and collection is aborted at actual authorization deadline', async t => {
  const f = await fixture(t); f.setTime(f.grant.authorizationExpiresAt - 300000);
  assert.equal((await syncOnce({ ...f, upstream: async () => freshToken(), collect: async ({ now }) => snapshot(now) })).status, 'updated');
  assert.equal(readCache(f.cachePaths.codex, 'codex', f.now()).expiresAt, f.grant.authorizationExpiresAt);
  const liveNow = Date.now(), g = await fixture(t, { authorizedAt: liveNow - AUTHORIZATION_TTL_MS + 500, accessExpiresAt: liveNow + 3600000, authorizationExpiresAt: liveNow + 500 }, liveNow);
  let aborted = false; const calls = [];
  const result = await syncOnce({ ...g, now: Date.now, upstream: async kind => { calls.push(kind); return null; }, collect: ({ signal }) => new Promise((resolve, reject) => {
    signal.addEventListener('abort', () => { aborted = true; reject(Error('expired')); }, { once: true });
  }) });
  assert.equal(result.status, 'reauthorize'); assert.equal(aborted, true); assert.deepEqual(calls, ['revoke']);
});

test('explicit revoke clears both caches and credentials even when provider revocation fails', async t => {
  const f = await fixture(t); await syncOnce({ ...f, collect: async ({ now }) => snapshot(now) });
  assert.equal((await revokeAuthorization({ ...f, upstream: async () => { throw Error('private error'); } })).status, 'revocation-unconfirmed');
  assert.equal(await withLockedState(store => store.read().grant, f), null);
  assert(Object.values(f.cachePaths).every(filename => !fs.existsSync(filename)));
});
