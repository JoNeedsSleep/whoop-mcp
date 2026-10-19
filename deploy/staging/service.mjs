// Deliberately separate synthetic upstream. No WHOOP client, OAuth route,
// database driver, user profile, network client or production app import.
import http from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { exact, tailnetHostname } from '../railway/config.mjs';

const invalid = () => { throw new Error('SYNTHETIC_STAGING_UNAVAILABLE'); };
const DAY = 86400000;
export function parseStagingConfig(raw) {
  exact(raw, ['mode', 'hostname', 'serviceTokenSha256']);
  if (raw.mode !== 'synthetic-fixture-only' || typeof raw.serviceTokenSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(raw.serviceTokenSha256)) invalid();
  tailnetHostname(raw.hostname);
  return structuredClone(raw);
}
export function assertSyntheticEnvironment(env) {
  if (Object.keys(env).some(key => /^(?:WHOOP_|DATABASE_URL$|ENCRYPTION_KEY$|SESSION_SECRET$|PG(?:HOST|USER|PASSWORD|DATABASE|PORT)$)/.test(key))) invalid();
}
export function syntheticSummary(date, now = Date.now()) {
  if (typeof date !== 'string' || !/^20\d{2}-\d{2}-\d{2}$/.test(date) || !Number.isSafeInteger(now) ||
      !Number.isFinite(Date.parse(date)) || new Date(date).toISOString().slice(0, 10) !== date) invalid();
  const today = Math.floor(now / DAY) * DAY;
  const offset = (today - Date.parse(date)) / DAY;
  if (!Number.isInteger(offset) || offset < 0 || offset > 6) invalid();
  if (offset === 6) return { date, status: 'NO_DATA', recovery_score: null, hrv_ms: null, resting_heart_rate: null,
    sleep_ms: null, sleep_performance: null, strain: null };
  const rows = [
    [74, 52.5, 54, 28200000, 91, 8.2], [68, 48.75, 56, 26400000, 84, 11.4],
    [82, 57.125, 52, 30000000, 96, 6.1], [45, 39.5, 61, 22200000, 72, 14.8],
    [91, 61.25, 50, 31200000, 98, 4.3], [64, 50, 57, 25200000, 81, 10.6],
  ];
  const [recovery_score, hrv_ms, resting_heart_rate, sleep_ms, sleep_performance, strain] = rows[offset];
  return { date, status: 'AVAILABLE', recovery_score, hrv_ms, resting_heart_rate, sleep_ms, sleep_performance, strain };
}
function headerCount(req, name) {
  let count = 0;
  for (let i = 0; i < req.rawHeaders.length; i += 2) if (req.rawHeaders[i].toLowerCase() === name) count++;
  return count;
}
function authorized(req, hash) {
  const value = req.headers.authorization;
  if (headerCount(req, 'authorization') !== 1 || typeof value !== 'string' || !/^Bearer whoopgw_service_[A-Za-z0-9_-]{43}$/.test(value)) return false;
  return timingSafeEqual(createHash('sha256').update(value.slice(7)).digest(), Buffer.from(hash, 'hex'));
}
function reply(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text),
    'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'X-WHOOP-Data-Source': 'synthetic-fixtures',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'", Connection: 'close' });
  res.end(text);
}
const deny = (res, status) => reply(res, status, { error: 'STAGING_DATA_UNAVAILABLE' });
export function createSyntheticService(raw, { now = Date.now } = {}) {
  const config = parseStagingConfig(raw);
  const server = http.createServer({ maxHeaderSize: 8192, requestTimeout: 5000, headersTimeout: 5000, keepAliveTimeout: 2000 }, (req, res) => {
    try {
      if (headerCount(req, 'host') !== 1 || req.headers.host !== config.hostname) { deny(res, 403); return; }
      if (req.method !== 'GET') { deny(res, 405); return; }
      if (req.headers['transfer-encoding'] !== undefined || (req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0')) { deny(res, 400); return; }
      if (req.url === '/healthz') { reply(res, 200, { status: 'ok', data: 'synthetic-fixtures-only' }); return; }
      if (!authorized(req, config.serviceTokenSha256)) { deny(res, 401); return; }
      const date = /^\/internal\/health-summary\?date=(20\d{2}-\d{2}-\d{2})$/.exec(req.url ?? '')?.[1];
      if (!date) { deny(res, 400); return; }
      reply(res, 200, syntheticSummary(date, now()));
    } catch { if (!res.headersSent) deny(res, 400); else res.destroy(); }
  });
  server.maxConnections = 16;
  server.setTimeout(5000, socket => socket.destroy());
  server.on('checkContinue', (_req, res) => deny(res, 400));
  server.on('checkExpectation', (_req, res) => deny(res, 400));
  server.on('upgrade', (_req, socket) => socket.destroy());
  server.on('connect', (_req, socket) => socket.destroy());
  server.on('clientError', (_error, socket) => socket.destroy());
  return server;
}
