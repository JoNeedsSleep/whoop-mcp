// Separate one-time local viewing session. Profile-only identity verification
// remains unchanged. This service writes no data files and calls no model API;
// the browser and any tools reading that browser can see the displayed result.
import http from 'node:http';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { exact } from '../railway/config.mjs';
import { requestWhoop, LOOPBACK_ORIGIN, LOOPBACK_MARKER_HEADER } from '../identity/verify.mjs';
import { validateSnapshot } from '../../restricted-local/policy.mjs';
import { collectSnapshot } from './snapshot.mjs';

const HOST = 'api.prod.whoop.com';
const COOKIE = '__Host-whoop_identity';
const TTL = 300000;
export const SCOPES = 'read:profile read:recovery read:sleep read:workout read:cycles';
const unavailable = () => { throw new Error('LOCAL_VIEW_UNAVAILABLE'); };
const random = () => randomBytes(32).toString('base64url');
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const escape = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const tokenString = value => typeof value === 'string' && /^[\x21-\x7e]{1,4096}$/.test(value);

export function parseLocalViewConfig(raw) {
  try {
    exact(raw, ['mode', 'clientId', 'clientSecret']);
    if (raw.mode !== 'whoop-local-view') unavailable();
    for (const key of ['clientId', 'clientSecret']) if (typeof raw[key] !== 'string' || !/^[\x21-\x7e]{1,2048}$/.test(raw[key])) unavailable();
    return { ...raw };
  } catch { unavailable(); }
}

function parameters(raw, allowed) {
  const values = {};
  for (const [key, value] of new URLSearchParams(raw)) {
    if (!allowed.includes(key) || Object.hasOwn(values, key)) unavailable(); values[key] = value;
  }
  return values;
}
function callbackScopes(value) {
  if (typeof value !== 'string' || value.length > 256 || /[^\x20-\x7e\t\r\n]/.test(value)) unavailable();
  const scopes = value.trim().split(/[ \t\r\n]+/);
  const expected = SCOPES.split(' ');
  if (scopes.length !== expected.length || new Set(scopes).size !== scopes.length ||
      scopes.some(scope => !expected.includes(scope))) unavailable();
}
function browserCookie(req) {
  const values = String(req.headers.cookie ?? '').split(';').map(v => v.trim()).filter(v => v.startsWith(COOKIE + '='));
  return values.length === 1 ? values[0].slice(COOKIE.length + 1) : null;
}
function response(res, status, body, { html = false, location, cookie } = {}) {
  res.setHeader('Cache-Control', 'no-store'); res.setHeader('Pragma', 'no-cache');
  res.setHeader('Referrer-Policy', html ? 'strict-origin' : 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
  if (cookie !== undefined) res.setHeader('Set-Cookie', `${COOKIE}=${cookie}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${cookie ? 300 : 0}`);
  if (location) res.setHeader('Location', location);
  res.writeHead(status, { 'Content-Type': html ? 'text/html; charset=utf-8' : 'text/plain; charset=utf-8', Connection: 'close' });
  res.end(html ? '<!doctype html><html lang="en"><meta charset="utf-8"><title>Local WHOOP snapshot</title>' + body + '</html>' : body);
}
async function form(req) {
  if (String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase() !== 'application/x-www-form-urlencoded' ||
      (req.headers['content-encoding'] && req.headers['content-encoding'] !== 'identity')) unavailable();
  let size = 0; const chunks = [];
  for await (const chunk of req) { size += chunk.length; if (size > 1024) unavailable(); chunks.push(chunk); }
  return parameters(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)), ['csrf', 'confirmed']);
}

export function createLocalViewServer(raw, { upstream = requestWhoop, collect = collectSnapshot, now = Date.now, ttlMs = TTL, loopbackMarker } = {}) {
  const config = parseLocalViewConfig(raw);
  if (typeof loopbackMarker !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(loopbackMarker)) unavailable();
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > TTL) unavailable();
  const origin = LOOPBACK_ORIGIN; const redirectUri = origin + '/whoop/callback';
  const expectedHost = 'localhost:17645';
  const started = now(); let phase = 'intro'; let binding; let csrf; let state; let verifier; let profile;
  let accessToken; let revokePending; let closing; let stopped = false; let completed = false; let finish; let snapshot;
  const collectionAbort = new AbortController();
  const active = new Set(); const done = new Promise(resolve => { finish = resolve; });
  const live = () => !stopped && now() >= started && now() - started < ttlMs;
  const revoke = async () => {
    if (!accessToken) return;
    if (!revokePending) revokePending = upstream('revoke', { token: accessToken }).then(() => { accessToken = undefined; });
    await revokePending;
  };
  const hidden = () => `<input type="hidden" name="csrf" value="${csrf}">`;
  const checkBrowser = req => { if (!binding || !equal(browserCookie(req), binding)) unavailable(); };
  const finishAfterResponse = (res, success) => res.once('finish', () => { completed = success; finish(success); });
  const waiting = '<meta http-equiv="refresh" content="2;url=/confirm"><h1>Preparing your local snapshot</h1><p>Collecting seven UTC days, then revoking this temporary grant. No values are displayed before revocation succeeds.</p><p><a href="/confirm">Check progress</a></p>';
  const render = data => {
    const headings = ['UTC date', 'Status', 'Recovery (%)', 'HRV (ms)', 'Resting heart rate (bpm)', 'Sleep (hours)', 'Sleep performance (%)', 'Strain'];
    const rows = data.summaries.map(row => [row.date, row.status, row.recovery_score, row.hrv_ms, row.resting_heart_rate,
      row.sleep_ms === null ? null : Math.round(row.sleep_ms / 36000) / 100, row.sleep_performance, row.strain]);
    return '<h1>Your seven-day WHOOP snapshot</h1><p>The temporary WHOOP grant has been revoked. Values are provider data, not independently verified measurements. A dash means unavailable.</p><table><thead><tr>' +
      headings.map(value => '<th>' + value + '</th>').join('') + '</tr></thead><tbody>' +
      rows.map(row => '<tr>' + row.map(value => '<td>' + escape(value === null ? '—' : value) + '</td>').join('') + '</tr>').join('') +
      '</tbody></table><p>This page is local and has no external assets. Nothing was written to the database or local cache. Close this tab when finished; browser memory or screenshots may retain displayed data.</p>';
  };
  const beginCollection = () => {
    const task = (async () => {
      try {
        const capturedNow = now();
        const result = validateSnapshot(await collect({ token: accessToken, signal: collectionAbort.signal, now: capturedNow }), capturedNow);
        if (!live()) unavailable();
        phase = 'revoking'; await revoke(); if (!live()) unavailable();
        snapshot = result; profile = undefined; phase = 'complete';
      } catch {
        snapshot = undefined; profile = undefined; phase = 'failed';
        try { await revoke(); } catch { /* Fixed UI requires manual provider revocation. */ }
      }
    })();
    active.add(task); void task.finally(() => active.delete(task));
  };
  async function route(req, res) {
    let ownsOperation = false;
    try {
      let hosts = 0; let origins = 0; let forwarded = 0; let markers = 0; let untrustedForwarding = false;
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        const name = req.rawHeaders[i].toLowerCase(); if (name === 'host') hosts++; if (name === 'origin') origins++; if (name === 'x-forwarded-proto') forwarded++;
        if (name === LOOPBACK_MARKER_HEADER) markers++;
        if (name === 'forwarded' || name.startsWith('x-forwarded-')) untrustedForwarding = true;
      }
      const transportValid = !untrustedForwarding && markers === 1 && equal(req.headers[LOOPBACK_MARKER_HEADER], loopbackMarker);
      if (!live() || !['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress) ||
          hosts !== 1 || req.headers.host !== expectedHost || !transportValid ||
          origins > 1 || (origins === 1 && req.headers.origin !== origin) ||
          typeof req.url !== 'string' || req.url.length > 4096 || !req.url.startsWith('/') || req.url.startsWith('//') || req.url.includes('#')) unavailable();
      const url = new URL(req.url, origin);
      if (url.origin !== origin || url.pathname + url.search !== req.url) unavailable();
      if (req.method === 'POST' && (origins !== 1 || req.headers.origin !== origin)) unavailable();
      if (req.method === 'GET' && (req.headers['transfer-encoding'] || (req.headers['content-length'] && req.headers['content-length'] !== '0'))) unavailable();
      if (req.method === 'GET' && req.url === '/' && phase === 'intro') {
        if (binding) checkBrowser(req);
        else { binding = random(); csrf = random(); state = random(); verifier = random(); }
        response(res, 200, `<h1>View your WHOOP data locally</h1><p>This five-minute session requests your profile and health-read permissions, without offline access. After you confirm the account, it reads seven UTC days of recovery, sleep and cycle summaries, revokes the temporary grant, then displays the values here. This service writes no database or cache and makes no model API calls. The browser and any assistant tools reading it can see the displayed values.</p><p>Revocation disconnects this developer app from your WHOOP account; use the intended temporary app.</p><form method="post" action="/start">${hidden()}<button>Continue to WHOOP</button></form>`, { html: true, cookie: binding }); return;
      }
      checkBrowser(req);
      if (req.method === 'POST' && req.url === '/start' && phase === 'intro') {
        const values = await form(req); if (!live() || phase !== 'intro' || !equal(values.csrf, csrf) || Object.keys(values).length !== 1) unavailable();
        phase = 'authorizing';
        // End the form navigation on this origin. A separate, explicit link
        // avoids applying our form-action policy to WHOOP's login redirects.
        response(res, 303, '', { location: '/authorize' }); return;
      }
      if (req.method === 'GET' && req.url === '/authorize' && phase === 'authorizing') {
        const url = new URL(`https://${HOST}/oauth/oauth2/auth`);
        url.search = new URLSearchParams({ response_type: 'code', client_id: config.clientId, redirect_uri: redirectUri,
          scope: SCOPES, state, code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }).toString();
        response(res, 200, `<h1>Continue on WHOOP</h1><p>Sign in and authorize profile and health-read access on WHOOP. Offline access is not requested. You will confirm the returned account before any health records are collected.</p><p><a href="${escape(url.href)}" rel="noreferrer">Open WHOOP sign-in</a></p>`, { html: true }); return;
      }
      if (req.method === 'GET' && url.pathname === '/whoop/callback' && phase === 'authorizing') {
        const values = parameters(url.searchParams, ['state', 'code', 'error', 'scope']);
        if (Object.hasOwn(values, 'scope')) callbackScopes(values.scope);
        if (!equal(values.state, state) || (Object.hasOwn(values, 'code') === Object.hasOwn(values, 'error')) ||
            (values.code !== undefined && !/^[\x21-\x7e]{1,2048}$/.test(values.code))) unavailable();
        phase = 'exchanging'; ownsOperation = true; // consume before the first await
        if (values.error !== undefined) unavailable();
        const token = await upstream('token', { ...config, code: values.code, redirectUri, verifier });
        if (tokenString(token?.access_token)) accessToken = token.access_token;
        if (!live() || !accessToken || typeof token.token_type !== 'string' || token.token_type.toLowerCase() !== 'bearer' ||
            typeof token.scope !== 'string' || token.scope.split(' ').sort().join(' ') !== SCOPES.split(' ').sort().join(' ') ||
            (token.refresh_token !== undefined && token.refresh_token !== null && token.refresh_token !== '') ||
            !Number.isSafeInteger(token.expires_in) || token.expires_in < 1 || token.expires_in > 86400) unavailable();
        const value = await upstream('profile', { token: accessToken });
        if (!live() || !value || typeof value !== 'object' || Array.isArray(value) ||
            !Number.isSafeInteger(value.user_id) || value.user_id < 1 || String(value.user_id).length > 16 ||
            ['email', 'first_name', 'last_name'].some(key => typeof value[key] !== 'string' || value[key].length > 320 || /[\u0000-\u001f\u007f]/.test(value[key]))) unavailable();
        profile = { userId: String(value.user_id), email: value.email, firstName: value.first_name, lastName: value.last_name };
        csrf = random(); phase = 'confirm';
        response(res, 303, '', { location: '/confirm' }); return;
      }
      if (req.method === 'GET' && req.url === '/confirm' && phase === 'confirm') {
        response(res, 200, `<h1>Confirm your own account</h1><p>Name: ${escape(profile.firstName)} ${escape(profile.lastName)}</p><p>Email: ${escape(profile.email)}</p><p>Only confirm if this is your intended WHOOP account. Confirmation starts the seven-day health summary read. The temporary grant must be revoked successfully before any values are displayed.</p><form method="post" action="/confirm">${hidden()}<button name="confirmed" value="yes">This is my account</button><button name="confirmed" value="no">Cancel</button></form>`, { html: true }); return;
      }
      if (req.method === 'POST' && req.url === '/confirm' && phase === 'confirm') {
        const values = await form(req);
        if (!live() || phase !== 'confirm' || !equal(values.csrf, csrf) || !['yes', 'no'].includes(values.confirmed) || Object.keys(values).length !== 2) unavailable();
        if (values.confirmed === 'yes') {
          phase = 'collecting'; beginCollection(); response(res, 200, waiting, { html: true }); return;
        }
        phase = 'revoking'; ownsOperation = true; await revoke(); if (!live()) unavailable();
        phase = 'cancelled'; profile = undefined; finishAfterResponse(res, false);
        response(res, 200, '<h1>Cancelled</h1><p>The temporary grant was revoked. No health records were collected.</p>', { html: true, cookie: '' }); return;
      }
      if (req.method === 'GET' && req.url === '/confirm' && ['collecting', 'revoking'].includes(phase)) {
        response(res, 200, waiting, { html: true }); return;
      }
      if (req.method === 'GET' && req.url === '/confirm' && phase === 'complete') {
        const html = render(snapshot); snapshot = undefined; phase = 'displayed';
        finishAfterResponse(res, true); response(res, 200, html, { html: true, cookie: '' }); return;
      }
      if (req.method === 'GET' && req.url === '/confirm' && phase === 'failed') {
        finishAfterResponse(res, false); unavailable();
      }
      unavailable();
    } catch {
      // Invalid unrelated requests cannot consume a live authorization flow.
      if (ownsOperation && ['exchanging', 'revoking'].includes(phase)) {
        phase = 'failed'; profile = undefined; try { await revoke(); } catch {}
        finishAfterResponse(res, false);
      }
      if (!res.headersSent) response(res, 400, 'Local viewing unavailable. If consent was granted, revoke the temporary app connection in WHOOP before retrying.');
      else res.destroy();
    }
  }
  const server = http.createServer({ maxHeaderSize: 8192, headersTimeout: 5000, requestTimeout: 5000, keepAliveTimeout: 1 }, (req, res) => {
    const deadline = setTimeout(() => { if (!req.complete) req.destroy(); }, 5000);
    req.once('end', () => clearTimeout(deadline)); req.once('close', () => clearTimeout(deadline));
    const task = route(req, res); active.add(task); void task.finally(() => active.delete(task));
  });
  server.maxConnections = 4; server.maxRequestsPerSocket = 1; server.setTimeout(15000, socket => socket.destroy());
  server.on('clientError', (_error, socket) => socket.destroy());
  const close = () => closing ??= (async () => {
    stopped = true; clearTimeout(timer); collectionAbort.abort();
    // Let the confirmation response finish on the wire; forced teardown is a
    // bounded fallback for a stalled peer, not the ordinary success path.
    if (server.listening) await new Promise(resolve => {
      const grace = setTimeout(() => { server.closeAllConnections(); }, 2000);
      server.close(() => { clearTimeout(grace); resolve(); }); server.closeIdleConnections();
    });
    await Promise.allSettled([...active]); let revoked = true;
    try { await revoke(); } catch { revoked = false; }
    profile = undefined; snapshot = undefined; accessToken = undefined; binding = undefined; verifier = undefined; finish(completed);
    return { revoked };
  })();
  const timer = setTimeout(() => { void close(); }, ttlMs);
  return { server, done, close };
}
