// One temporary grant, seven UTC API windows, fixed numeric projection only.
// This preserves health-summary.ts's first-record semantics; it does not join
// physiological cycles or reinterpret provider timestamps as local calendar days.
import https from 'node:https';
import tls from 'node:tls';
import { DAY_MS, utcDate, validateSnapshot, validateSummary } from '../../restricted-local/policy.mjs';

const HOST = 'api.prod.whoop.com';
const PATHS = Object.freeze({ recovery: '/developer/v2/recovery', sleep: '/developer/v2/activity/sleep', cycle: '/developer/v2/cycle' });
const BODY_LIMIT = 16384;
const failure = () => new Error('LOCAL_VIEW_UNAVAILABLE');
const invalid = () => { throw failure(); };
const plain = value => value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
const tokenValid = value => typeof value === 'string' && /^[\x21-\x7e]{1,4096}$/.test(value);
const cursorValid = value => typeof value === 'string' && /^[\x21-\x7e]{1,1024}$/.test(value);

function range(start, end) {
  if (typeof start !== 'string' || typeof end !== 'string') invalid();
  const date = utcDate(start.slice(0, 10));
  if (start !== `${date}T00:00:00.000Z` || end !== new Date(Date.parse(start) + DAY_MS).toISOString()) invalid();
}

// Tests may replace the native request primitive; production has no URL, proxy,
// redirect, retry, refresh, TLS override or environment-derived destination.
export async function requestCollection(kind, fields, { request = https.request } = {}) {
  try {
    if (!Object.hasOwn(PATHS, kind) || !tokenValid(fields.token) ||
        (fields.nextToken !== undefined && !cursorValid(fields.nextToken)) ||
        (fields.signal !== undefined && !(fields.signal instanceof AbortSignal))) invalid();
    range(fields.start, fields.end);
    if (fields.signal?.aborted) invalid();
    const query = new URLSearchParams({ limit: '1', start: fields.start, end: fields.end });
    if (fields.nextToken !== undefined) query.set('nextToken', fields.nextToken);
    return await new Promise((resolve, reject) => {
      let req; let response; let timer; let settled = false;
      const cleanup = () => { clearTimeout(timer); fields.signal?.removeEventListener('abort', fail); };
      const fail = () => {
        if (settled) return;
        settled = true; cleanup(); response?.destroy(); req?.destroy(); reject(failure());
      };
      try {
        fields.signal?.addEventListener('abort', fail, { once: true });
        timer = setTimeout(fail, 5000);
        req = request({ protocol: 'https:', hostname: HOST, port: 443, servername: HOST,
          path: PATHS[kind] + '?' + query.toString(), method: 'GET', agent: false,
          headers: { Authorization: `Bearer ${fields.token}`, Accept: 'application/json', 'Accept-Encoding': 'identity', Connection: 'close' },
          maxHeaderSize: 8192, rejectUnauthorized: true, minVersion: 'TLSv1.2', ALPNProtocols: ['http/1.1'],
          checkServerIdentity: (_host, cert) => tls.checkServerIdentity(HOST, cert) }, incoming => {
          response = incoming;
          if (settled) { response.destroy(); return; }
          response.on('error', fail); response.on('aborted', fail);
          try {
            const duplicates = new Set();
            for (let i = 0; i < response.rawHeaders.length; i += 2) {
              const name = response.rawHeaders[i].toLowerCase();
              if (['content-type', 'content-length', 'content-encoding', 'transfer-encoding'].includes(name)) {
                if (duplicates.has(name)) invalid(); duplicates.add(name);
              }
            }
            const length = response.headers['content-length'];
            const encoding = response.headers['content-encoding'];
            if (response.statusCode !== 200 ||
                String(response.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase() !== 'application/json' ||
                (encoding !== undefined && encoding !== 'identity') ||
                (length !== undefined && (typeof length !== 'string' || !/^(0|[1-9][0-9]{0,5})$/.test(length) || Number(length) > BODY_LIMIT)) ||
                (length !== undefined && response.headers['transfer-encoding'] !== undefined)) invalid();
            let size = 0; const chunks = [];
            response.on('data', chunk => {
              if (settled) return;
              size += chunk.length;
              if (size > BODY_LIMIT) fail(); else chunks.push(chunk);
            });
            response.on('end', () => {
              if (settled) return;
              try {
                if (length !== undefined && size !== Number(length)) invalid();
                const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
                settled = true; cleanup(); resolve(parsed);
              } catch { fail(); }
            });
          } catch { fail(); }
        });
        req.on('error', fail);
        if (fields.signal?.aborted) fail(); else req.end();
      } catch { fail(); }
    });
  } catch { throw failure(); }
}

function abortable(signal, operation) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) { reject(failure()); return; }
    const abort = () => reject(failure());
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve().then(() => { if (signal.aborted) invalid(); return operation(); }).then(resolve, reject)
      .finally(() => signal.removeEventListener('abort', abort));
  });
}

async function firstRecord(kind, fields, request) {
  let nextToken; const seen = new Set();
  for (let pageNumber = 0; pageNumber < 4; pageNumber++) {
    const page = await abortable(fields.signal, () => request(kind, { ...fields, nextToken }));
    if (!plain(page) || !Array.isArray(page.records) || page.records.length > 1 ||
        Reflect.ownKeys(page.records).length !== page.records.length + 1) invalid();
    const cursor = page.next_token;
    if (cursor !== undefined && cursor !== null && cursor !== '' && !cursorValid(cursor)) invalid();
    if (page.records.length) {
      if (!plain(page.records[0])) invalid();
      return page.records[0];
    }
    if (cursor === undefined || cursor === null || cursor === '') return undefined;
    if (seen.has(cursor)) invalid(); seen.add(cursor); nextToken = cursor;
  }
  invalid();
}

function score(record) {
  if (record === undefined) return undefined;
  // Absent score_state retains the existing summary adapter's compatibility;
  // an explicitly unscored record must not carry apparently scored values.
  if (record.score_state !== undefined && !['SCORED', 'PENDING_SCORE', 'UNSCORABLE'].includes(record.score_state)) invalid();
  const value = record.score;
  if (value === undefined || value === null) return undefined;
  if (!plain(value) || (record.score_state !== undefined && record.score_state !== 'SCORED')) invalid();
  return value;
}

function project(date, recovery, sleep, cycle) {
  const r = score(recovery), s = score(sleep), c = score(cycle);
  let sleepMs = null;
  if (s?.stage_summary !== undefined && s.stage_summary !== null) {
    const stages = s.stage_summary;
    if (!plain(stages)) invalid();
    const values = ['total_light_sleep_time_milli', 'total_slow_wave_sleep_time_milli', 'total_rem_sleep_time_milli'].map(key => stages[key]);
    if (values.some(value => !Number.isSafeInteger(value) || Object.is(value, -0) || value < 0 || value > DAY_MS)) invalid();
    sleepMs = values.reduce((sum, value) => sum + value, 0);
  }
  const data = {
    recovery_score: r?.recovery_score ?? null, hrv_ms: r?.hrv_rmssd_milli ?? null,
    resting_heart_rate: r?.resting_heart_rate ?? null, sleep_ms: sleepMs,
    sleep_performance: s?.sleep_performance_percentage ?? null, strain: c?.strain ?? null,
  };
  return validateSummary({ date, status: Object.values(data).some(value => value !== null) ? 'AVAILABLE' : 'NO_DATA', ...data }, date);
}

export async function collectSnapshot({ token, signal, now = Date.now(), request = requestCollection } = {}) {
  let timer; let relayAbort; let controller;
  try {
    if (!tokenValid(token) || !Number.isSafeInteger(now) || now < 0 || Object.is(now, -0) ||
        typeof request !== 'function' || (signal !== undefined && !(signal instanceof AbortSignal)) || signal?.aborted) invalid();
    const windowEnd = utcDate(new Date(now).toISOString().slice(0, 10));
    const dates = Array.from({ length: 7 }, (_, index) => utcDate(new Date(Date.parse(windowEnd) - (6 - index) * DAY_MS).toISOString().slice(0, 10)));
    controller = new AbortController(); relayAbort = () => controller.abort();
    signal?.addEventListener('abort', relayAbort, { once: true });
    timer = setTimeout(relayAbort, 60000);
    const summaries = [];
    for (const date of dates) {
      const fields = { token, signal: controller.signal, start: `${date}T00:00:00.000Z`, end: new Date(Date.parse(date) + DAY_MS).toISOString() };
      const records = await Promise.all(Object.keys(PATHS).map(kind => firstRecord(kind, fields, request)));
      if (controller.signal.aborted) invalid();
      summaries.push(project(date, ...records));
    }
    return validateSnapshot({ version: 1, windowEnd, summaries }, now);
  } catch { throw failure(); }
  finally { clearTimeout(timer); signal?.removeEventListener?.('abort', relayAbort); controller?.abort(); }
}
