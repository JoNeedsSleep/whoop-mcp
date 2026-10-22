import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { collectSnapshot, requestCollection } from './snapshot.mjs';
import { DAY_MS, localDate, validateSnapshot } from '../../restricted-local/policy.mjs';

const NOW = Date.parse('2024-03-12T04:30:00.000Z'); // Still March 11 in Chicago.
const TOKEN = 'synthetic-access';
const denied = { message: 'LOCAL_SYNC_UNAVAILABLE' };
const uuid = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const updated = '2024-03-12T04:00:00.000Z';
function sleep(n, start, end, nap = false) {
  const duration = Date.parse(end) - Date.parse(start);
  return { id: uuid(n), cycle_id: n, start, end, nap, updated_at: updated, score_state: 'SCORED',
    score: { sleep_performance_percentage: 90, stage_summary: {
      total_in_bed_time_milli: duration, total_awake_time_milli: 0, total_no_data_time_milli: 0,
      total_light_sleep_time_milli: duration / 2, total_slow_wave_sleep_time_milli: duration / 4, total_rem_sleep_time_milli: duration / 4 } } };
}
const recovery = (n, sleepId = uuid(n)) => ({ cycle_id: n, sleep_id: sleepId, updated_at: updated, score_state: 'SCORED',
  score: { recovery_score: 80, hrv_rmssd_milli: 45.1234, resting_heart_rate: 55 } });
const cycle = (n, start, strain = 10) => ({ id: n, start, end: null, updated_at: updated, score_state: 'SCORED', score: { strain } });
const fixture = () => ({ sleep: [sleep(1, '2024-03-11T03:00:00Z', '2024-03-11T11:00:00Z'),
  sleep(2, '2024-03-11T19:00:00Z', '2024-03-11T20:00:00Z', true)], recovery: [recovery(1), recovery(2)],
  cycle: [cycle(1, '2024-03-11T11:00:00Z')] });
const collect = (data, options = {}) => collectSnapshot({ token: TOKEN, now: NOW,
  request: async kind => ({ records: data[kind] ?? [] }), ...options });

test('Chicago end dates include whole overnight sleep and naps; recovery never comes from a nap', async () => {
  const data = fixture(); data.recovery[1].score.recovery_score = 1;
  data.sleep[1].score.sleep_performance_percentage = 10;
  data.sleep[0].email = 'private@example.test'; data.sleep[0].instructions = 'SECRET_SENTINEL';
  const calls = [], snapshot = await collect(data, { request: async (kind, fields) => { calls.push(fields); return { records: data[kind] }; } });
  assert.deepEqual(validateSnapshot(snapshot, NOW), snapshot);
  assert.equal(snapshot.version, 2); assert.equal(snapshot.timeZone, 'America/Chicago'); assert.equal(snapshot.windowEnd, '2024-03-11');
  assert.equal(calls.length, 3);
  assert(calls.every(f => f.start === '2024-03-04T00:00:00.000Z' && f.end === '2024-03-13T00:00:00.000Z'));
  const row = snapshot.summaries[6]; assert.equal(row.sleep_ms, 9 * 3600000); assert.equal(row.sleep_complete, true);
  assert.equal(row.sleep_sessions.length, 2); assert.equal(row.sleep_sessions[0].start_ms, Date.parse(data.sleep[0].start));
  assert.equal(row.sleep_sessions[1].nap, true); assert.equal(row.recovery_score, 80); assert.equal(row.sleep_performance, 90);
  assert.equal(row.hrv_ms, 45.123); assert.equal(row.strain, 10);
  assert(snapshot.summaries.slice(0, 6).every(r => r.status === 'NO_DATA' && r.sleep_complete === false && r.sleep_ms === null));
  assert.doesNotMatch(JSON.stringify(snapshot), /private|SECRET|cycle_id|sleep_id|updated_at|00000000/);
});

test('UTC midnight and exact Chicago midnight map by sleep end, with no future sessions', async () => {
  const data = { sleep: [sleep(1, '2024-03-11T01:00:00Z', '2024-03-11T04:00:00Z'),
    sleep(2, '2024-03-11T04:00:00Z', '2024-03-11T05:00:00Z', true),
    sleep(3, '2024-03-12T05:00:00Z', '2024-03-12T06:00:00Z')] };
  const s = await collect(data);
  assert.equal(s.summaries[5].date, '2024-03-10'); assert.equal(s.summaries[5].sleep_ms, 3 * 3600000);
  assert.equal(s.summaries[6].sleep_ms, 3600000); assert.equal(s.summaries[6].sleep_performance, null);
});

test('both DST transitions use elapsed timestamps and retain a whole overnight session', async () => {
  for (const [start, end, now, hours, date] of [
    ['2024-03-10T04:00:00Z', '2024-03-10T12:00:00Z', '2024-03-10T20:00:00Z', 8, '2024-03-10'],
    ['2024-11-03T03:00:00Z', '2024-11-03T13:00:00Z', '2024-11-03T20:00:00Z', 10, '2024-11-03'],
  ]) {
    const s = await collect({ sleep: [sleep(1, start, end)] }, { now: Date.parse(now) });
    assert.equal(s.windowEnd, date); assert.equal(s.summaries[6].sleep_ms, hours * 3600000);
    assert.equal(localDate(s.summaries[6].sleep_sessions[0].end_ms), date);
  }
});

test('all pages are consumed even after records; newer duplicate updates win independently of page order', async () => {
  const data = fixture(), old = structuredClone(data.sleep[0]); old.updated_at = '2024-03-11T12:00:00Z'; old.score.sleep_performance_percentage = 1;
  for (const pages of [[old, data.sleep[0]], [data.sleep[0], old]]) {
    const seen = [];
    const result = await collect(data, { request: async (kind, fields) => {
      if (kind !== 'sleep') return { records: data[kind] };
      seen.push(fields.nextToken);
      return fields.nextToken === undefined ? { records: [pages[0]], next_token: 'opaque-not-a-url' } : { records: [pages[1], data.sleep[1]] };
    } });
    assert.deepEqual(seen, [undefined, 'opaque-not-a-url']); assert.equal(result.summaries[6].sleep_ms, 9 * 3600000);
    assert.equal(result.summaries[6].sleep_performance, 90);
  }
  data.sleep.push(structuredClone(data.sleep[0]));
  assert.equal((await collect(data)).summaries[6].sleep_sessions.length, 2);
});

test('conflicting duplicate versions, different IDs overlapping, and truncated/repeated pagination fail closed', async () => {
  const data = fixture(), conflict = structuredClone(data.sleep[0]); conflict.score.sleep_performance_percentage = 1;
  await assert.rejects(collect({ ...data, sleep: [...data.sleep, conflict] }), denied);
  conflict.id = uuid(99); await assert.rejects(collect({ ...data, sleep: [...data.sleep, conflict] }), denied);
  for (const cursor of [n => `p${n}`, () => 'same', () => '\n', () => 'a'.repeat(1025)]) {
    let calls = 0;
    await assert.rejects(collect({}, { request: async kind => kind === 'sleep' ? { records: [], next_token: cursor(++calls) } : { records: [] } }), denied);
    assert(calls <= 8);
  }
  await assert.rejects(collect({}, { request: async () => ({ records: Array(26).fill(data.sleep[0]) }) }), denied);
});

test('pending sessions remain visible, suppress the complete total, and latest main performance can be null', async () => {
  const data = fixture(); data.sleep[1].score_state = 'PENDING_SCORE'; data.sleep[1].score = null;
  let row = (await collect(data)).summaries[6]; assert.equal(row.status, 'AVAILABLE'); assert.equal(row.sleep_complete, false);
  assert.equal(row.sleep_ms, null); assert.equal(row.sleep_performance, 90); assert.equal(row.sleep_sessions[1].asleep_ms, null);
  data.sleep[1].nap = false;
  row = (await collect(data)).summaries[6]; assert.equal(row.sleep_performance, null);
  delete data.sleep[0].score.sleep_performance_percentage;
  assert.equal((await collect({ sleep: [data.sleep[0]] })).summaries[6].sleep_complete, true);
});

test('sleep_id joins take precedence, absent IDs can join a main cycle, and latest starting cycle strain is not summed', async () => {
  const data = fixture(); data.recovery = [recovery(1, uuid(2))];
  assert.equal((await collect(data)).summaries[6].recovery_score, null);
  delete data.recovery[0].sleep_id;
  assert.equal((await collect(data)).summaries[6].recovery_score, 80);
  data.cycle.push(cycle(2, '2024-03-11T21:00:00Z', 3), cycle(3, '2024-03-12T06:00:00Z', 21));
  assert.equal((await collect(data)).summaries[6].strain, 3);
});

test('only bounded projected fields survive; malformed scores, timestamps, IDs and stages reject', async () => {
  const mutations = [s => { s.id = 'https://evil.invalid'; }, s => { s.updated_at = 'not a date'; },
    s => { s.start = '2024-03-10T24:00:00Z'; }, s => { s.end = '2024-03-11T12:00:00+15:00'; },
    s => { s.end = s.start; }, s => { s.nap = 'false'; }, s => { s.score_state = 'unknown'; },
    s => { s.score_state = 'UNSCORABLE'; }, s => { s.score.stage_summary.total_light_sleep_time_milli = '1'; },
    s => { s.score.stage_summary.total_no_data_time_milli = -1; }, s => { s.score.stage_summary.total_in_bed_time_milli = 1; },
    s => { s.score.sleep_performance_percentage = NaN; }, s => { s.cycle_id = Number.MAX_SAFE_INTEGER + 1; }];
  for (const mutate of mutations) { const data = fixture(); mutate(data.sleep[0]); await assert.rejects(collect(data), denied); }
  // Official examples do not promise arithmetic equality between in-bed and stages.
  const data = fixture(); data.sleep[0].score.stage_summary.total_in_bed_time_milli += 1000;
  assert.equal((await collect(data)).summaries[6].sleep_ms, 9 * 3600000);
});

test('invalid inputs make no request; caller cancellation aborts stuck work and errors stay fixed', async () => {
  let calls = 0; const request = async () => { calls++; throw Error('SECRET_SENTINEL'); };
  for (const now of [-0, -1, Infinity, NOW + 0.1, Date.parse('2000-01-03')])
    await assert.rejects(collectSnapshot({ token: TOKEN, now, request }), denied);
  await assert.rejects(collectSnapshot({ token: 'bad\n', now: NOW, request }), denied); assert.equal(calls, 0);
  const controller = new AbortController(); let enter; const started = new Promise(resolve => { enter = resolve; });
  const signals = [];
  const pending = collectSnapshot({ token: TOKEN, now: NOW, signal: controller.signal, request: async (_kind, fields) => {
    signals.push(fields.signal); if (signals.length === 3) enter(); return new Promise(() => {});
  } });
  await started; controller.abort(); await assert.rejects(pending, denied); assert(signals.every(s => s.aborted));
  await assert.rejects(collect({}, { request }), denied); assert.equal(calls, 3);
});

test('fixed60second total deadline aborts every collection without a caller or production timeout override', async () => {
  const original = globalThis.setTimeout; const signals = []; let deadlines = 0;
  globalThis.setTimeout = (fn, ms, ...args) => {
    if (ms === 60000) { deadlines++; return original(fn, 0, ...args); }
    return original(fn, ms, ...args);
  };
  try {
    await assert.rejects(collect({}, { request: async (_kind, fields) => { signals.push(fields.signal); return new Promise(() => {}); } }), denied);
    assert.equal(deadlines, 1); assert.equal(signals.length, 3); assert(signals.every(s => s.aborted));
  } finally { globalThis.setTimeout = original; }
});

function transport({ status = 200, headers = { 'content-type': 'application/json' }, rawHeaders, body = Buffer.from('{"records":[]}'), stall = false } = {}) {
  let options, destroyed = false, incoming;
  const native = (config, callback) => {
    options = config; const req = new EventEmitter(); req.destroy = () => { destroyed = true; };
    req.end = () => queueMicrotask(() => { incoming = new PassThrough(); incoming.statusCode = status; incoming.headers = headers;
      incoming.rawHeaders = rawHeaders ?? Object.entries(headers).flat(); callback(incoming); if (!stall && !incoming.destroyed) incoming.end(body); });
    return req;
  };
  return { native, get options() { return options; }, get destroyed() { return destroyed; }, get response() { return incoming; } };
}
const range = { token: TOKEN, start: '2024-03-04T00:00:00.000Z', end: '2024-03-13T00:00:00.000Z' };
test('native transport fixes HTTPS target, full-page limit and query; no credential URL or TLS relaxation', async () => {
  const f = transport(), cursor = 'https://evil.invalid/?x=1';
  await requestCollection('sleep', { ...range, nextToken: cursor }, { request: f.native });
  const o = f.options, url = new URL(o.path, 'https://api.prod.whoop.com');
  assert.equal(url.pathname, '/developer/v2/activity/sleep'); assert.equal(url.searchParams.get('limit'), '25');
  assert.equal(url.searchParams.get('nextToken'), cursor); assert.equal(o.hostname, 'api.prod.whoop.com');
  assert.equal(o.servername, o.hostname); assert.equal(o.rejectUnauthorized, true); assert.equal(o.minVersion, 'TLSv1.2');
  assert.equal(o.agent, false); assert.equal(o.headers.Authorization, `Bearer ${TOKEN}`); assert(!o.path.includes(TOKEN));
  assert(o.checkServerIdentity('evil.invalid', { subjectaltname: 'DNS:evil.invalid' }) instanceof Error);
  for (const kind of ['profile', 'workout', '__proto__']) await assert.rejects(requestCollection(kind, range, { request: () => assert.fail('request') }), denied);
});

test('native response bounds, framing, redirects and malformed JSON fail; abort destroys exact sockets', async () => {
  for (const settings of [{ status: 302 }, { status: 429 }, { headers: { 'content-type': 'text/plain' } },
    { headers: { 'content-type': 'application/json', 'content-length': '65537' } },
    { headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' } },
    { headers: { 'content-type': 'application/json', 'content-length': '14', 'transfer-encoding': 'chunked' } },
    { rawHeaders: ['Content-Type', 'application/json', 'Content-Type', 'application/json'] },
    { body: Buffer.from([255]) }, { body: Buffer.from('SECRET_SENTINEL') }, { body: Buffer.alloc(65537, 32) }]) {
    const f = transport(settings); await assert.rejects(requestCollection('sleep', range, { request: f.native }), denied); assert(f.destroyed);
  }
  const f = transport({ stall: true }), controller = new AbortController();
  const p = requestCollection('sleep', { ...range, signal: controller.signal }, { request: f.native });
  await new Promise(resolve => setImmediate(resolve)); controller.abort(); await assert.rejects(p, denied);
  assert(f.destroyed); assert(f.response.destroyed);
});

test('abort after listener registration but during native request construction still destroys the returned request', async () => {
  const controller = new AbortController(); let destroyed = false, ended = false;
  await assert.rejects(requestCollection('sleep', { ...range, signal: controller.signal }, { request: () => {
    const req = new EventEmitter(); req.destroy = () => { destroyed = true; }; req.end = () => { ended = true; };
    controller.abort(); return req;
  } }), denied);
  assert.equal(destroyed, true); assert.equal(ended, false);
  await assert.rejects(requestCollection('sleep', { ...range, signal: controller.signal }, { request: () => assert.fail('pre-aborted') }), denied);
});
