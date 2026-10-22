// Fixed Chicago calendar projection for persistent local sync only.
// Query a UTC margin, consume every bounded page, then group complete sleeps
// by their Chicago end date. Physiological cycle strain is not a day total.
import https from 'node:https';
import tls from 'node:tls';
import { DAY_MS, utcDate, LOCAL_TIME_ZONE, localDate, validateSnapshot, validateLocalSummary } from '../../restricted-local/policy.mjs';

const HOST = 'api.prod.whoop.com';
const PATHS = Object.freeze({ recovery: '/developer/v2/recovery', sleep: '/developer/v2/activity/sleep', cycle: '/developer/v2/cycle' });
const BODY_LIMIT = 65536;
const PAGE_LIMIT = 25;
const MAX_PAGES = 8;
const MAX_RECORDS = PAGE_LIMIT * MAX_PAGES;
const failure = () => new Error('LOCAL_SYNC_UNAVAILABLE');
const invalid = () => { throw failure(); };
const plain = value => value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
const tokenValid = value => typeof value === 'string' && /^[\x21-\x7e]{1,4096}$/.test(value);
const cursorValid = value => typeof value === 'string' && /^[\x21-\x7e]{1,1024}$/.test(value);

function range(start, end) {
  if (typeof start !== 'string' || typeof end !== 'string') invalid();
  const date = utcDate(start.slice(0, 10));
  if (start !== `${date}T00:00:00.000Z` || end !== new Date(Date.parse(start) + 9 * DAY_MS).toISOString()) invalid();
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
    const query = new URLSearchParams({ limit: String(PAGE_LIMIT), start: fields.start, end: fields.end });
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
        if (settled) { req.destroy(); return; }
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

function timestamp(value) {
  if (typeof value !== 'string' || !/^20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) invalid();
  utcDate(value.slice(0, 10));
  if (Number(value.slice(11, 13)) > 23 || Number(value.slice(14, 16)) > 59 || Number(value.slice(17, 19)) > 59) invalid();
  if (!value.endsWith('Z')) {
    const offset = value.slice(-6), hours = Number(offset.slice(1, 3)), minutes = Number(offset.slice(4));
    if (hours > 14 || minutes > 59 || (hours === 14 && minutes !== 0)) invalid();
  }
  const time = Date.parse(value);
  if (!Number.isSafeInteger(time) || time < Date.parse('2000-01-01') || time >= Date.parse('2100-01-01')) invalid();
  return time;
}
function activityId(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(value)) invalid();
  return value.toLowerCase();
}
function cycleId(value) {
  if (!Number.isSafeInteger(value) || value <= 0) invalid();
  return value;
}
function number(value, max, min = 0, integer = false) {
  if (typeof value !== 'number' || !Number.isFinite(value) || Object.is(value, -0) || value < min || value > max || (integer && !Number.isSafeInteger(value))) invalid();
  return Math.round(value * 1000) / 1000;
}
function score(record) {
  if (!['SCORED', 'PENDING_SCORE', 'UNSCORABLE'].includes(record.score_state)) invalid();
  if (record.score_state === 'SCORED') { if (!plain(record.score)) invalid(); return record.score; }
  if (record.score !== undefined && record.score !== null) invalid();
  return null;
}
// Reconstruct only fields needed for selection and the final numeric projection.
// Identifiers and update times are RAM-only join/dedup keys, never returned.
function normalize(kind, raw) {
  if (!plain(raw)) invalid();
  const updated = timestamp(raw.updated_at), s = score(raw);
  if (kind === 'sleep') {
    const start = timestamp(raw.start), end = timestamp(raw.end);
    if (end <= start || end - start > DAY_MS || typeof raw.nap !== 'boolean') invalid();
    const session = { start_ms: start, end_ms: end, nap: raw.nap, score_state: raw.score_state,
      asleep_ms: null, in_bed_ms: null, awake_ms: null, light_ms: null, deep_ms: null, rem_ms: null, no_data_ms: null, sleep_performance: null };
    if (s) {
      const stages = s.stage_summary; if (!plain(stages)) invalid();
      for (const [key, source] of Object.entries({ in_bed_ms: 'total_in_bed_time_milli', awake_ms: 'total_awake_time_milli',
        light_ms: 'total_light_sleep_time_milli', deep_ms: 'total_slow_wave_sleep_time_milli', rem_ms: 'total_rem_sleep_time_milli', no_data_ms: 'total_no_data_time_milli' })) {
        session[key] = number(stages[source], DAY_MS, 0, true);
      }
      session.asleep_ms = session.light_ms + session.deep_ms + session.rem_ms;
      if (session.asleep_ms > session.in_bed_ms) invalid();
      // WHOOP may omit performance while it learns the user's Sleep Need.
      session.sleep_performance = s.sleep_performance_percentage == null ? null : number(s.sleep_performance_percentage, 100);
    }
    return { id: activityId(raw.id), updated, cycle: cycleId(raw.cycle_id), session };
  }
  if (kind === 'recovery') return { id: cycleId(raw.cycle_id), updated,
    sleep: raw.sleep_id === undefined || raw.sleep_id === null ? null : activityId(raw.sleep_id),
    recovery_score: s ? number(s.recovery_score, 100) : null,
    hrv_ms: s ? number(s.hrv_rmssd_milli, 1000) : null,
    resting_heart_rate: s ? number(s.resting_heart_rate, 250, 20, true) : null };
  const start = timestamp(raw.start), end = raw.end == null ? null : timestamp(raw.end);
  if (end !== null && end <= start) invalid();
  return { id: cycleId(raw.id), updated, start, end, strain: s ? number(s.strain, 21) : null };
}

async function allRecords(kind, fields, request) {
  let nextToken; let count = 0; const cursors = new Set(), records = new Map();
  for (let n = 0; n < MAX_PAGES; n++) {
    const page = await abortable(fields.signal, () => request(kind, { ...fields, nextToken }));
    if (!plain(page) || !Array.isArray(page.records) || page.records.length > PAGE_LIMIT ||
        Reflect.ownKeys(page.records).length !== page.records.length + 1) invalid();
    count += page.records.length; if (count > MAX_RECORDS) invalid();
    for (const raw of page.records) {
      const row = normalize(kind, raw), previous = records.get(row.id);
      if (previous && previous.updated === row.updated && JSON.stringify(previous) !== JSON.stringify(row)) invalid();
      if (!previous || row.updated > previous.updated) records.set(row.id, row);
    }
    const cursor = page.next_token;
    if (cursor === undefined || cursor === null || cursor === '') return [...records.values()];
    if (!cursorValid(cursor) || cursors.has(cursor)) invalid();
    cursors.add(cursor); nextToken = cursor;
  }
  invalid(); // An outstanding cursor is truncation, never a partial success.
}

export async function collectSnapshot({ token, signal, now = Date.now(), request = requestCollection } = {}) {
  let timer; let controller; let abort;
  try {
    if (!tokenValid(token) || !Number.isSafeInteger(now) || now < 0 || Object.is(now, -0) ||
        typeof request !== 'function' || (signal !== undefined && !(signal instanceof AbortSignal)) || signal?.aborted) invalid();
    const windowEnd = localDate(now);
    const dates = Array.from({ length: 7 }, (_, i) => utcDate(new Date(Date.parse(windowEnd) - (6 - i) * DAY_MS).toISOString().slice(0, 10)));
    // Chicago is UTC-5/-6. One extra UTC day before the first date covers a
    // complete <=24h overnight sleep, including both daylight-saving changes.
    const start = new Date(Date.parse(dates[0]) - DAY_MS).toISOString();
    const end = new Date(Date.parse(windowEnd) + 2 * DAY_MS).toISOString();
    range(start, end);
    controller = new AbortController(); abort = () => controller.abort();
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    timer = setTimeout(abort, 60000);
    const fields = { token, signal: controller.signal, start, end };
    const [sleep, recovery, cycles] = await Promise.all(['sleep', 'recovery', 'cycle'].map(kind => allRecords(kind, fields, request)));
    if (controller.signal.aborted) invalid();
    const selected = sleep.filter(row => row.session.end_ms <= now && dates.includes(localDate(row.session.end_ms)))
      .sort((a, b) => a.session.start_ms - b.session.start_ms || a.session.end_ms - b.session.end_ms);
    if (selected.length > 64) invalid();
    for (let i = 1; i < selected.length; i++) if (selected[i].session.start_ms < selected[i - 1].session.end_ms) invalid();
    const summaries = dates.map(date => {
      const day = selected.filter(row => localDate(row.session.end_ms) === date), sessions = day.map(row => row.session);
      const main = day.filter(row => !row.session.nap).at(-1);
      // Exact sleep association takes precedence. Only an absent sleep_id may
      // fall back to the same cycle; a recovery attached to a nap is never used.
      const exact = main ? recovery.filter(row => row.sleep === main.id) : [];
      const fallback = main ? recovery.filter(row => row.sleep === null && row.id === main.cycle) : [];
      const matches = exact.length ? exact : fallback; if (matches.length > 1) invalid();
      const r = matches[0];
      const dayCycles = cycles.filter(row => row.start <= now && localDate(row.start) === date).sort((a, b) => a.start - b.start);
      if (dayCycles.length > 1 && dayCycles.at(-1).start === dayCycles.at(-2).start) invalid();
      const c = dayCycles.at(-1);
      const complete = sessions.length > 0 && sessions.every(row => row.score_state === 'SCORED');
      const metrics = { recovery_score: r?.recovery_score ?? null, hrv_ms: r?.hrv_ms ?? null,
        resting_heart_rate: r?.resting_heart_rate ?? null,
        sleep_ms: complete ? sessions.reduce((sum, row) => sum + row.asleep_ms, 0) : null,
        sleep_performance: main?.session.sleep_performance ?? null, strain: c?.strain ?? null };
      return validateLocalSummary({ date, status: sessions.length || Object.values(metrics).some(value => value !== null) ? 'AVAILABLE' : 'NO_DATA',
        ...metrics, time_zone: LOCAL_TIME_ZONE, sleep_complete: complete, sleep_sessions: sessions }, date);
    });
    return validateSnapshot({ version: 2, timeZone: LOCAL_TIME_ZONE, windowEnd, summaries }, now);
  } catch { throw failure(); }
  finally { clearTimeout(timer); if (abort) signal?.removeEventListener('abort', abort); controller?.abort(); }
}
