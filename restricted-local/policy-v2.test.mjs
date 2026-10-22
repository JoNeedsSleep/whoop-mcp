import test from "node:test";
import assert from "node:assert/strict";
import { DAY_MS, LOCAL_TIME_ZONE, localDate, validateLocalSummary, validateSnapshot } from "./policy.mjs";

const NOW = Date.parse("2026-10-23T04:30:00Z"); // October 22, 23:30 in Chicago.
const DATE = "2026-10-22";
function session(start, minutes = 60, nap = false, performance = 90) {
  const start_ms = typeof start === "number" ? start : Date.parse(start), elapsed = minutes * 60000;
  return { start_ms, end_ms: start_ms + elapsed, nap, score_state: "SCORED", asleep_ms: elapsed * 0.8,
    in_bed_ms: elapsed, awake_ms: elapsed * 0.1, light_ms: elapsed * 0.4, deep_ms: elapsed * 0.2,
    rem_ms: elapsed * 0.2, no_data_ms: elapsed * 0.1, sleep_performance: performance };
}
function summary(date, sessions = []) {
  const complete = sessions.length > 0 && sessions.every(value => value.score_state === "SCORED");
  return { date, status: sessions.length ? "AVAILABLE" : "NO_DATA", recovery_score: null, hrv_ms: null, resting_heart_rate: null,
    sleep_ms: complete ? sessions.reduce((sum, value) => sum + value.asleep_ms, 0) : null,
    sleep_performance: sessions.filter(value => !value.nap).at(-1)?.sleep_performance ?? null, strain: null,
    time_zone: LOCAL_TIME_ZONE, sleep_complete: complete, sleep_sessions: sessions };
}
function snapshot(now = NOW) {
  const windowEnd = localDate(now);
  return { version: 2, timeZone: LOCAL_TIME_ZONE, windowEnd, summaries: Array.from({ length: 7 }, (_, i) =>
    summary(new Date(Date.parse(windowEnd) - (6 - i) * DAY_MS).toISOString().slice(0, 10))) };
}
const invalid = { message: "INVALID_LOCAL_HEALTH_DATA" };

test("Chicago dates handle UTC midnight, spring-forward and fall-back with no caller timezone", () => {
  for (const [timestamp, date] of [
    ["2026-10-23T04:59:59.999Z", "2026-10-22"], ["2026-10-23T05:00:00Z", "2026-10-23"],
    ["2026-03-08T07:59:59Z", "2026-03-08"], ["2026-03-08T08:00:00Z", "2026-03-08"],
    ["2026-11-01T06:30:00Z", "2026-11-01"], ["2026-11-01T07:30:00Z", "2026-11-01"],
    ["2026-11-02T05:59:59Z", "2026-11-01"], ["2026-11-02T06:00:00Z", "2026-11-02"],
  ]) assert.equal(localDate(Date.parse(timestamp)), date);
  for (const value of [-0, -1, NaN, Infinity, 0.5, "2026-10-22", Number.MAX_SAFE_INTEGER]) assert.throws(() => localDate(value));
});

test("all naps contribute asleep stages while performance belongs to latest main sleep", () => {
  const sessions = [session("2026-10-22T01:00:00Z", 480, false, 92), session("2026-10-22T19:00:00Z", 60, true, 30)];
  const raw = summary(DATE, sessions), clean = validateLocalSummary(raw, DATE);
  assert.equal(clean.sleep_ms, 25920000); assert.equal(clean.sleep_performance, 92); assert.equal(clean.sleep_complete, true);
  assert.notEqual(clean.sleep_sessions[0], raw.sleep_sessions[0]); raw.sleep_sessions[0].light_ms = 0;
  assert.equal(clean.sleep_sessions[0].light_ms, 11520000);
  const secondMain = session("2026-10-22T21:00:00Z", 60, false, 70);
  assert.equal(validateLocalSummary(summary(DATE, [...sessions.map((s, i) => i ? s : clean.sleep_sessions[0]), secondMain]), DATE).sleep_performance, 70);
});

test("official scored sample permits optional performance and independent in-bed total", () => {
  const sample = { start_ms: Date.parse("2022-04-24T02:25:44.774Z"), end_ms: Date.parse("2022-04-24T10:25:44.774Z"),
    nap: false, score_state: "SCORED", in_bed_ms: 30272735, awake_ms: 1403507, no_data_ms: 0,
    light_ms: 14905851, deep_ms: 6630370, rem_ms: 5879573, asleep_ms: 27415794, sleep_performance: null };
  assert.equal(validateLocalSummary(summary("2022-04-24", [sample]), "2022-04-24").sleep_ms, 27415794);
  assert(sample.in_bed_ms > sample.end_ms - sample.start_ms);
  assert.notEqual(sample.in_bed_ms, sample.asleep_ms + sample.awake_ms + sample.no_data_ms);
});

test("pending and unscorable sessions cannot masquerade as zero or complete sleep", () => {
  for (const score_state of ["PENDING_SCORE", "UNSCORABLE"]) {
    const pending = session("2026-10-22T19:00:00Z", 30, true);
    pending.score_state = score_state;
    for (const key of ["asleep_ms", "in_bed_ms", "awake_ms", "light_ms", "deep_ms", "rem_ms", "no_data_ms", "sleep_performance"]) pending[key] = null;
    const raw = summary(DATE, [session("2026-10-22T06:00:00Z"), pending]);
    assert.equal(validateLocalSummary(raw, DATE).sleep_ms, null); assert.equal(raw.sleep_complete, false); assert.equal(raw.status, "AVAILABLE");
    assert.throws(() => validateLocalSummary({ ...raw, sleep_ms: 0 }, DATE), invalid);
    assert.throws(() => validateLocalSummary({ ...raw, sleep_complete: true }, DATE), invalid);
    pending.awake_ms = 0; assert.throws(() => validateLocalSummary(raw, DATE), invalid);
  }
  assert.deepEqual(validateLocalSummary(summary(DATE), DATE), summary(DATE));
  assert.equal(summary(DATE).sleep_complete, false);
});

test("session and summary exact fields, bounds and derived totals reject hostile values", () => {
  const good = summary(DATE, [session("2026-10-22T06:00:00Z")]);
  for (const mutate of [
    r => { r.time_zone = "UTC"; }, r => { r.instructions = "SECRET_SENTINEL"; }, r => { r.sleep_ms++; },
    r => { r.sleep_performance = 80; }, r => { r.sleep_complete = 1; }, r => { r.status = "NO_DATA"; },
    r => { r.sleep_sessions[0].url = "https://evil.invalid"; }, r => { r.sleep_sessions[0].nap = "false"; },
    r => { r.sleep_sessions[0].score_state = "UNKNOWN"; }, r => { r.sleep_sessions[0].asleep_ms++; },
    r => { r.sleep_sessions[0].in_bed_ms = 1; }, r => { r.sleep_sessions[0].light_ms = null; },
    r => { r.sleep_sessions[0].awake_ms = -0; }, r => { r.sleep_sessions[0].no_data_ms = DAY_MS + 1; },
    r => { r.sleep_sessions[0].rem_ms = "30"; }, r => { r.sleep_sessions[0].deep_ms = 0.5; },
    r => { r.sleep_sessions[0].sleep_performance = 101; }, r => { r.sleep_sessions[0].end_ms = Infinity; },
    r => { r.sleep_sessions[0].start_ms = -1; }, r => { r.sleep_sessions[0].start_ms = r.sleep_sessions[0].end_ms; },
    r => { r.sleep_sessions[0].start_ms = r.sleep_sessions[0].end_ms - DAY_MS - 1; },
    r => { r.sleep_sessions[0].end_ms += DAY_MS; }, r => { delete r.sleep_sessions[0]; },
    r => { r.sleep_sessions.extra = "SECRET_SENTINEL"; },
  ]) { const value = structuredClone(good); mutate(value); assert.throws(() => validateLocalSummary(value, DATE), invalid); }
});

test("strict chronological order rejects duplicates and overlaps including across local dates", () => {
  const first = session("2026-10-22T06:00:00Z"), second = session("2026-10-22T07:00:00Z", 30, true);
  assert.equal(validateLocalSummary(summary(DATE, [first, second]), DATE).sleep_sessions.length, 2);
  for (const sessions of [[second, first], [first, first], [first, { ...second, start_ms: second.start_ms - 1 }]])
    assert.throws(() => validateLocalSummary(summary(DATE, sessions), DATE), invalid);
  const raw = snapshot();
  raw.summaries[5] = summary("2026-10-21", [session("2026-10-22T03:30:00Z", 60)]);
  raw.summaries[6] = summary(DATE, [session("2026-10-22T04:00:00Z", 120)]);
  assert.throws(() => validateSnapshot(raw, NOW), invalid);
});

test("end-date grouping can total more than24hours without overlapping sessions", () => {
  const sessions = [session("2026-10-21T05:01:00Z", 1440), session("2026-10-22T05:01:00Z", 1438)];
  for (const s of sessions) { s.light_ms = s.asleep_ms = s.in_bed_ms; s.deep_ms = s.rem_ms = s.awake_ms = s.no_data_ms = 0; }
  const raw = summary(DATE, sessions);
  assert(raw.sleep_ms > DAY_MS); assert(raw.sleep_ms < 2 * DAY_MS);
  assert.equal(validateLocalSummary(raw, DATE).sleep_ms, raw.sleep_ms);
});

test("v2 snapshot enforces Chicago window, future end rejection and perday/window counts", () => {
  const raw = snapshot();
  for (let day = 0; day < 7; day++) {
    const date = raw.summaries[day].date, count = day === 6 ? 4 : 10;
    raw.summaries[day] = summary(date, Array.from({ length: count }, (_, i) => session(Date.parse(date) + (6 + i) * 3600000, 30, i > 0)));
  }
  assert.equal(validateSnapshot(raw, NOW).summaries.flatMap(s => s.sleep_sessions).length, 64);
  assert.throws(() => validateSnapshot(raw, Date.parse("2026-10-23T05:00:00Z")), invalid);
  for (const mutate of [
    r => { r.timeZone = "America/New_York"; }, r => { r.windowEnd = "2026-10-23"; },
    r => { r.summaries[6] = summary(DATE, [...r.summaries[6].sleep_sessions, session("2026-10-22T19:00:00Z", 30, true)]); },
    r => { r.summaries[0] = summary(r.summaries[0].date, Array.from({ length: 17 }, (_, i) => session(Date.parse(r.summaries[0].date) + (6 + i) * 3600000, 10, true))); },
    r => { r.summaries[6] = summary(DATE, [session("2026-10-23T04:29:00Z", 2)]); },
    r => { r.summaries.reverse(); }, r => { r.summaries[0].date = "2026-02-30"; },
  ]) { const value = structuredClone(raw); mutate(value); assert.throws(() => validateSnapshot(value, NOW), invalid); }
});

test("spring23hour and autumn25hour dates use calendar windows and real epoch durations", () => {
  for (const now of [Date.parse("2026-03-09T04:30:00Z"), Date.parse("2026-11-02T05:30:00Z")]) {
    const raw = snapshot(now); assert.deepEqual(validateSnapshot(raw, now), raw);
    assert.equal(raw.summaries.length, 7);
  }
  const raw = snapshot(Date.parse("2026-11-02T05:30:00Z"));
  raw.summaries[6] = summary("2026-11-01", [session("2026-11-01T06:15:00Z", 30), session("2026-11-01T07:15:00Z", 30, true)]);
  assert.equal(validateSnapshot(raw, Date.parse("2026-11-02T05:30:00Z")).summaries[6].sleep_sessions.length, 2);
});
