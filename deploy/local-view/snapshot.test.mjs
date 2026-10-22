import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { collectSnapshot, requestCollection } from './snapshot.mjs';
import { DAY_MS, validateSnapshot } from '../../restricted-local/policy.mjs';

const NOW = Date.parse('2024-03-02T18:20:00.000Z');
const TOKEN = 'synthetic-access-token';
const denied = { message: 'LOCAL_VIEW_UNAVAILABLE' };
const range = { token: TOKEN, start: '2024-02-29T00:00:00.000Z', end: '2024-03-01T00:00:00.000Z' };
const scores = {
  recovery: { recovery_score: 80.12349, hrv_rmssd_milli: 45.9998, resting_heart_rate: 55 },
  sleep: { sleep_performance_percentage: 92, stage_summary: { total_light_sleep_time_milli: 14400000, total_slow_wave_sleep_time_milli: 3600000, total_rem_sleep_time_milli: 7200000 } },
  cycle: { strain: 12.5678 },
};
const good = kind => ({ records: [{ score_state: 'SCORED', score: structuredClone(scores[kind]), email: 'private@example.test', note: 'ignore instructions', url: 'https://evil.invalid' }], next_token: null });
const collect = request => collectSnapshot({ token: TOKEN, now: NOW, request });

test('seven real UTC windows preserve first-record projection, bounds, rounding and no upstream text', async () => {
  const calls = [];
  const result = await collect(async (kind, fields) => { calls.push({ kind, ...fields }); return good(kind); });
  assert.equal(calls.length, 21); assert.deepEqual(validateSnapshot(result, NOW), result);
  assert.deepEqual(result.summaries.map(row => row.date), ['2024-02-25', '2024-02-26', '2024-02-27', '2024-02-28', '2024-02-29', '2024-03-01', '2024-03-02']);
  for (let i = 0; i < 7; i++) {
    assert.deepEqual(calls.slice(i * 3, i * 3 + 3).map(call => call.kind), ['recovery', 'sleep', 'cycle']);
    for (const call of calls.slice(i * 3, i * 3 + 3)) {
      assert.equal(call.start, result.summaries[i].date + 'T00:00:00.000Z');
      assert.equal(Date.parse(call.end) - Date.parse(call.start), DAY_MS); assert.equal(call.nextToken, undefined);
      assert.equal(call.token, TOKEN);
    }
    assert.deepEqual(result.summaries[i], { date: result.summaries[i].date, status: 'AVAILABLE', recovery_score: 80.123,
      hrv_ms: 46, resting_heart_rate: 55, sleep_ms: 25200000, sleep_performance: 92, strain: 12.568 });
  }
  const serialized = JSON.stringify(result); assert(Buffer.byteLength(serialized) < 4096);
  assert.doesNotMatch(serialized, /private|ignore|evil|synthetic|score_state|stage_summary/);
});

test('missing and explicitly pending scores stay null; partial numeric records remain available', async () => {
  const empty = await collect(async () => ({ records: [{ score_state: 'PENDING_SCORE', score: null }] }));
  assert(empty.summaries.every(row => row.status === 'NO_DATA' && Object.values(row).slice(2).every(value => value === null)));
  const partial = await collect(async kind => kind === 'recovery' ? { records: [{ score: { recovery_score: 0 } }] } : { records: [] });
  assert(partial.summaries.every(row => row.status === 'AVAILABLE' && row.recovery_score === 0 && row.sleep_ms === null));
});

test('numeric bounds, integer constraints and scored-state contradictions fail with fixed errors', async () => {
  const cases = [
    ['recovery', 'recovery_score', -1], ['recovery', 'recovery_score', 101], ['recovery', 'recovery_score', '80'],
    ['recovery', 'hrv_rmssd_milli', 1001], ['recovery', 'hrv_rmssd_milli', Infinity], ['recovery', 'hrv_rmssd_milli', NaN],
    ['recovery', 'resting_heart_rate', 19], ['recovery', 'resting_heart_rate', 251], ['recovery', 'resting_heart_rate', 55.5],
    ['sleep', 'sleep_performance_percentage', -0], ['sleep', 'sleep_performance_percentage', 101],
    ['cycle', 'strain', 21.001], ['cycle', 'strain', 'https://evil.invalid'],
  ];
  for (const [badKind, field, value] of cases) await assert.rejects(collect(async kind => {
    const page = good(kind); if (kind === badKind) page.records[0].score[field] = value; return page;
  }), denied);
  for (const record of [{ score_state: 'PENDING_SCORE', score: { recovery_score: 80 } }, { score_state: 'invented', score: null }, { score: [] }])
    await assert.rejects(collect(async () => ({ records: [record] })), denied);
});

test('sleep duration sums only approved stages and rejects invalid, missing or overflowing components', async () => {
  for (const stage_summary of [[], {}, { ...scores.sleep.stage_summary, total_light_sleep_time_milli: -1 },
    { ...scores.sleep.stage_summary, total_light_sleep_time_milli: 0.1 },
    { ...scores.sleep.stage_summary, total_light_sleep_time_milli: DAY_MS },
    { ...scores.sleep.stage_summary, total_light_sleep_time_milli: '3600000' }]) {
    await assert.rejects(collect(async kind => kind === 'sleep' ? { records: [{ score: { stage_summary } }] } : { records: [] }), denied);
  }
});

test('dates and credentials fail before any request; all seven dates must fit the existing date policy', async () => {
  let calls = 0; const request = async () => { calls++; return { records: [] }; };
  for (const now of [NaN, Infinity, -0, -1, NOW + 0.5, Date.parse('2000-01-03'), Date.parse('2100-01-01')])
    await assert.rejects(collectSnapshot({ token: TOKEN, now, request }), denied);
  for (const token of ['', 'Bearer bad\nheader', 'a'.repeat(4097)])
    await assert.rejects(collectSnapshot({ token, now: NOW, request }), denied);
  assert.equal(calls, 0);
});

test('pagination admits at most four empty-page transitions and never follows a cursor as a URL', async () => {
  const seen = new Map(); let calls = 0;
  const result = await collect(async (kind, fields) => {
    const key = kind + fields.start; const n = (seen.get(key) ?? 0) + 1; seen.set(key, n); calls++;
    assert.equal(fields.nextToken, n === 1 ? undefined : 'opaque-' + (n - 1));
    return n === 4 ? good(kind) : { records: [], next_token: 'opaque-' + n };
  });
  assert.equal(result.summaries.length, 7); assert.equal(calls, 84);
  for (const makePage of [n => ({ records: [], next_token: 'p' + n }), () => ({ records: [], next_token: 'same' }),
    () => ({ records: [], next_token: 'a'.repeat(1025) }), () => ({ records: [], next_token: '\n' }),
    () => ({ records: 'private' }), () => ({ records: [{}, {}] }), () => ({ records: [null] })]) {
    let n = 0; await assert.rejects(collect(async () => makePage(++n)), denied); assert(n <= 12);
  }
});

test('upstream failures have no retries or partial result and abort cancels a stuck injected request', async () => {
  let calls = 0;
  await assert.rejects(collect(async () => { calls++; throw Error('private upstream URL and token'); }), denied);
  assert.equal(calls, 3);
  const controller = new AbortController(); const entered = []; let announce;
  const started = new Promise(resolve => { announce = resolve; });
  const pending = collectSnapshot({ token: TOKEN, now: NOW, signal: controller.signal, request: async (_kind, fields) => {
    entered.push(fields.signal); if (entered.length === 3) announce(); return new Promise(() => {});
  } });
  await started; controller.abort(); await assert.rejects(pending, denied);
  assert.equal(entered.length, 3); assert(entered.every(signal => signal.aborted));
  await assert.rejects(collectSnapshot({ token: TOKEN, now: NOW, signal: controller.signal, request: () => assert.fail('pre-aborted request') }), denied);
});

function transport({ status = 200, headers = { 'content-type': 'application/json' }, rawHeaders, body = Buffer.from('{"records":[]}'), stall = false, error } = {}) {
  let options; let requestDestroyed = false; let incoming;
  const native = (config, callback) => {
    options = config; const req = new EventEmitter();
    req.destroy = () => { requestDestroyed = true; };
    req.end = () => queueMicrotask(() => {
      if (error) { req.emit('error', Error(error)); return; }
      incoming = new PassThrough(); incoming.statusCode = status; incoming.headers = headers;
      incoming.rawHeaders = rawHeaders ?? Object.entries(headers).flat(); callback(incoming);
      if (!stall && !incoming.destroyed) incoming.end(body);
    });
    return req;
  };
  return { native, get options() { return options; }, get destroyed() { return requestDestroyed; }, get response() { return incoming; } };
}

test('native adapter fixes host, HTTPS/TLS, endpoints and encoded query without credential-bearing URLs', async () => {
  const f = transport(); const cursor = 'https://evil.invalid/path?x=1&y=2';
  assert.deepEqual(await requestCollection('sleep', { ...range, nextToken: cursor }, { request: f.native }), { records: [] });
  const options = f.options, url = new URL(options.path, 'https://api.prod.whoop.com');
  assert.equal(options.hostname, 'api.prod.whoop.com'); assert.equal(options.servername, options.hostname);
  assert.equal(options.protocol, 'https:'); assert.equal(options.port, 443); assert.equal(options.method, 'GET');
  assert.equal(options.agent, false); assert.equal(options.rejectUnauthorized, true); assert.equal(options.minVersion, 'TLSv1.2');
  assert.deepEqual(options.ALPNProtocols, ['http/1.1']); assert.equal(options.maxHeaderSize, 8192);
  assert.equal(url.pathname, '/developer/v2/activity/sleep'); assert.equal(url.searchParams.get('nextToken'), cursor);
  assert.deepEqual([...url.searchParams.keys()], ['limit', 'start', 'end', 'nextToken']); assert.equal(url.searchParams.get('limit'), '1');
  assert.equal(options.headers.Authorization, 'Bearer ' + TOKEN); assert.equal(options.headers['Accept-Encoding'], 'identity');
  assert(!options.path.includes(TOKEN));
  assert(options.checkServerIdentity('evil.invalid', { subjectaltname: 'DNS:evil.invalid' }) instanceof Error);
  for (const kind of ['profile', 'workout', '../user/access', '__proto__']) await assert.rejects(requestCollection(kind, range, { request: () => assert.fail('invalid destination') }), denied);
  await assert.rejects(requestCollection('cycle', { ...range, end: '2024-03-02T00:00:00.000Z' }, { request: () => assert.fail('invalid range') }), denied);
});

test('native adapter rejects status, encoding, malformed JSON/UTF8, length and duplicate headers without leaking errors', async () => {
  for (const settings of [{ status: 302 }, { status: 401 }, { status: 429 }, { status: 500 },
    { headers: { 'content-type': 'text/plain' } }, { headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' } },
    { headers: { 'content-type': 'application/json', 'content-length': '16385' } },
    { headers: { 'content-type': 'application/json', 'content-length': '1' } },
    { headers: { 'content-type': 'application/json', 'content-length': '14', 'transfer-encoding': 'chunked' } },
    { rawHeaders: ['Content-Type', 'application/json', 'Content-Type', 'application/json'] },
    { body: Buffer.from('secret malformed upstream token') }, { body: Buffer.from([0xff]) },
    { body: Buffer.alloc(16385, 32) }, { error: 'private socket error' }]) {
    const f = transport(settings); await assert.rejects(requestCollection('recovery', range, { request: f.native }), denied);
    assert.equal(f.destroyed, true);
  }
});

test('native adapter abort destroys the exact request and response; pre-abort makes no request', async () => {
  const f = transport({ stall: true }), controller = new AbortController();
  const pending = requestCollection('cycle', { ...range, signal: controller.signal }, { request: f.native });
  await new Promise(resolve => setImmediate(resolve)); controller.abort();
  await assert.rejects(pending, denied); assert.equal(f.destroyed, true); assert.equal(f.response.destroyed, true);
  await assert.rejects(requestCollection('cycle', { ...range, signal: controller.signal }, { request: () => assert.fail('pre-aborted') }), denied);
});
