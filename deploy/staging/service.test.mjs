// Execute only in the approved offline Node22 test container.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { assertSyntheticEnvironment, createSyntheticService, parseStagingConfig, syntheticSummary } from './service.mjs';
import { createGateway, validateSummary } from '../../review-gateway/gateway.mjs';

const TOKEN = `whoopgw_service_${'S'.repeat(43)}`;
const NOW = Date.UTC(2026, 9, 18, 12);
const CONFIG = { mode: 'synthetic-fixture-only', hostname: 'staging-backend.test-tailnet.ts.net', serviceTokenSha256: createHash('sha256').update(TOKEN).digest('hex') };
async function fixture(t) {
  const server = createSyntheticService(CONFIG, { now: () => NOW });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const port = server.address().port;
  const request = (route, { headers = {}, method = 'GET', body = '' } = {}) => new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: route, method, agent: false,
      headers: Array.isArray(headers) ? headers : { Host: CONFIG.hostname, Authorization: `Bearer ${TOKEN}`, ...headers } }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject); req.end(body);
  });
  return { request, server };
}
test('synthetic configuration rejects production credentials, public names and unknown options', () => {
  assert.deepEqual(parseStagingConfig(CONFIG), CONFIG);
  for (const raw of [{ ...CONFIG, mode: 'production' }, { ...CONFIG, hostname: 'whoop.example.com' },
    { ...CONFIG, serviceTokenSha256: 'secret' }, { ...CONFIG, WHOOP_CLIENT_SECRET: 'synthetic' },
    { ...CONFIG, DATABASE_URL: 'synthetic' }, { ...CONFIG, source: 'https://api.prod.whoop.com' }]) assert.throws(() => parseStagingConfig(raw));
  assert.doesNotThrow(() => assertSyntheticEnvironment({ PATH: '/usr/bin', PORT: '8080', RAILWAY_ENVIRONMENT_NAME: 'staging' }));
  for (const key of ['WHOOP_CLIENT_ID', 'WHOOP_CLIENT_SECRET', 'DATABASE_URL', 'PGPASSWORD', 'ENCRYPTION_KEY', 'SESSION_SECRET']) assert.throws(() => assertSyntheticEnvironment({ [key]: 'synthetic' }));
});
test('fixtures reconstruct only bounded numeric summaries for seven UTC dates, including missing data', () => {
  for (let offset = 0; offset < 7; offset++) {
    const date = new Date(NOW - offset * 86400000).toISOString().slice(0, 10);
    const value = syntheticSummary(date, NOW);
    assert.deepEqual(validateSummary(value, date), value);
    assert.equal(Object.keys(value).length, 8);
    assert.equal(value.status, offset === 6 ? 'NO_DATA' : 'AVAILABLE');
  }
  assert.equal(syntheticSummary('2026-10-18', NOW).recovery_score, 74);
  for (const date of ['2026-10-19', '2026-10-11', '2026-02-30', '../../secret', 'https://api.prod.whoop.com', '2026-10-18T00:00:00Z']) assert.throws(() => syntheticSummary(date, NOW));
});
test('real HTTP fixture enforces exact Host and dedicated machine bearer without leaks', async t => {
  const { request, server } = await fixture(t);
  assert.equal(server.address().address, '127.0.0.1');
  const route = '/internal/health-summary?date=2026-10-18';
  const ok = await request(route); assert.equal(ok.status, 200);
  assert.deepEqual(JSON.parse(ok.text), syntheticSummary('2026-10-18', NOW));
  assert.equal(ok.headers['cache-control'], 'no-store'); assert.equal(ok.headers['x-whoop-data-source'], 'synthetic-fixtures');
  for (const authorization of ['', `Bearer gw_${'S'.repeat(43)}`, `Bearer whoopgw_service_${'T'.repeat(43)}`, 'Bearer secret-sentinel']) {
    const r = await request(route, { headers: { Authorization: authorization } });
    assert.equal(r.status, 401); assert.equal(r.text, '{"error":"STAGING_DATA_UNAVAILABLE"}');
    if (authorization) assert.ok(!r.text.includes(authorization));
  }
  assert.equal((await request(route, { headers: { Host: 'evil.test', 'X-Forwarded-Host': CONFIG.hostname } })).status, 403);
  assert.equal((await request(route, { headers: ['Host', CONFIG.hostname, 'Authorization', `Bearer ${TOKEN}`, 'Authorization', `Bearer ${TOKEN}`] })).status, 401);
  assert.equal(ok.headers['set-cookie'], undefined); assert.equal(ok.headers.location, undefined);
});
test('staging has no login, WHOOP callback, database, proxy or body-bearing route', async t => {
  const { request } = await fixture(t);
  for (const route of ['/dashboard/connect', '/whoop/callback', '/oauth/authorize', '/owner', '/mcp',
    '/internal/health-summary?date=2026-10-18&url=https://api.prod.whoop.com',
    '/internal/health-summary?date=2026-10-18&date=2026-10-17', '/internal/health-summary?date=2026-10-19']) {
    const r = await request(route); assert.equal(r.status, 400); assert.equal(r.headers.location, undefined);
    assert.equal(r.text, '{"error":"STAGING_DATA_UNAVAILABLE"}');
  }
  assert.equal((await request('/internal/health-summary?date=2026-10-18', { method: 'POST', body: 'secret-sentinel' })).status, 405);
  assert.equal((await request('/internal/health-summary?date=2026-10-18', { headers: { 'Content-Length': '1' }, body: 'x' })).status, 400);
  const health = await request('/healthz', { headers: { Authorization: '' } });
  assert.equal(health.status, 200); assert.deepEqual(JSON.parse(health.text), { status: 'ok', data: 'synthetic-fixtures-only' });
});
test('unchanged gateway adapter accepts synthetic backend without any WHOOP fetch', async t => {
  const { request } = await fixture(t); const calls = [];
  const callTool = createGateway({ origin: `https://${CONFIG.hostname}`, whoopBearer: TOKEN, now: () => NOW,
    fetchImpl: async (rawUrl, options) => {
      const url = new URL(rawUrl); calls.push(url.href);
      assert.equal(url.origin, `https://${CONFIG.hostname}`); assert.equal(options.method, 'GET'); assert.equal(options.redirect, 'error');
      const r = await request(`${url.pathname}${url.search}`, { headers: options.headers });
      return new Response(r.text, { status: r.status, headers: r.headers });
    } });
  for (let offset = 0; offset < 7; offset++) {
    const date = new Date(NOW - offset * 86400000).toISOString().slice(0, 10);
    const r = await callTool('get_health_summary', { date });
    assert.equal(r.isError, undefined); assert.deepEqual(r.structuredContent, syntheticSummary(date, NOW));
  }
  assert.equal(calls.length, 7);
  assert.ok(calls.every(url => url.startsWith(`https://${CONFIG.hostname}/internal/health-summary?date=`)));
});
