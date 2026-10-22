// Separate local seven-day authorization. This module does not persist tokens,
// collect health data, or alter the one-time viewer. The trusted onAuthorize
// callback owns durable storage and must reject without publishing on abort.
// Resolution means the atomic commit succeeded, including if shutdown raced it.
import http from 'node:http';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { requestOAuth, parseLocalSyncConfig, validateTokenResponse, validateScopes, tokenString,
  LOOPBACK_ORIGIN, LOOPBACK_MARKER_HEADER, SCOPES, AUTHORIZATION_TTL_MS } from './oauth.mjs';
export { parseLocalSyncConfig as parseLocalLoginConfig, SCOPES } from './oauth.mjs';

const HOST = 'api.prod.whoop.com';
const COOKIE = '__Host-whoop_identity';
const TTL = 300000;
const unavailable = () => { throw new Error('LOCAL_SYNC_UNAVAILABLE'); };
const random = () => randomBytes(32).toString('base64url');
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const escape = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function parameters(raw, allowed) {
  const values = {};
  for (const [key, value] of new URLSearchParams(raw)) {
    if (!allowed.includes(key) || Object.hasOwn(values, key)) unavailable(); values[key] = value;
  }
  return values;
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
  res.end(html ? '<!doctype html><html lang="en"><meta charset="utf-8"><title>Local WHOOP sync</title>' + body + '</html>' : body);
}
async function form(req) {
  if (String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase() !== 'application/x-www-form-urlencoded' ||
      (req.headers['content-encoding'] && req.headers['content-encoding'] !== 'identity')) unavailable();
  let size = 0; const chunks = [];
  for await (const chunk of req) { size += chunk.length; if (size > 1024) unavailable(); chunks.push(chunk); }
  return parameters(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)), ['csrf', 'confirmed']);
}

export function createLocalLoginServer(raw, { onAuthorize, upstream = requestOAuth, now = Date.now, ttlMs = TTL, loopbackMarker } = {}) {
  const config = parseLocalSyncConfig(raw);
  if (typeof onAuthorize !== 'function') unavailable();
  if (typeof loopbackMarker !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(loopbackMarker)) unavailable();
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > TTL) unavailable();
  const origin = LOOPBACK_ORIGIN; const redirectUri = origin + '/whoop/callback';
  const expectedHost = 'localhost:17645';
  const started = now(); let phase = 'intro'; let binding; let csrf; let state; let verifier; let profile;
  if (!Number.isSafeInteger(started) || started < 1) unavailable();
  let accessToken, refreshToken, accessExpiresAt, revokePending, closing, finish;
  let stopped = false, authorized = false;
  const handoffAbort = new AbortController();
  const active = new Set(); const done = new Promise(resolve => { finish = resolve; });
  const live = () => !stopped && now() >= started && now() - started < ttlMs;
  const revoke = async () => {
    if (authorized || !accessToken) return;
    if (!revokePending) revokePending = upstream('revoke', { token: accessToken }).then(() => { accessToken = undefined; refreshToken = undefined; });
    await revokePending;
  };
  const hidden = () => `<input type="hidden" name="csrf" value="${csrf}">`;
  const checkBrowser = req => { if (!binding || !equal(browserCookie(req), binding)) unavailable(); };
  const finishAfterResponse = (res, success) => res.once('finish', () => { finish(success); });
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
        response(res, 200, `<h1>Connect local WHOOP sync</h1><p>This five-minute login requests profile, health-read and offline access. After you confirm your account, the local worker securely stores the grant for seven days and may fetch seven-day summaries every 15 minutes for Codex and Claude Code. Refresh does not extend that seven-day login. This login page collects no health records and calls no model APIs.</p><p>Use the intended local app. Cancelling revokes its WHOOP grant.</p><form method="post" action="/start">${hidden()}<button>Continue to WHOOP</button></form>`, { html: true, cookie: binding }); return;
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
        response(res, 200, `<h1>Continue on WHOOP</h1><p>Sign in and authorize profile, health-read and offline access on WHOOP. You will confirm the returned account before the local grant is saved. No health records are collected during login.</p><p><a href="${escape(url.href)}" rel="noreferrer">Open WHOOP sign-in</a></p>`, { html: true }); return;
      }
      if (req.method === 'GET' && url.pathname === '/whoop/callback' && phase === 'authorizing') {
        const values = parameters(url.searchParams, ['state', 'code', 'error', 'scope']);
        if (Object.hasOwn(values, 'scope')) validateScopes(values.scope);
        if (!equal(values.state, state) || (Object.hasOwn(values, 'code') === Object.hasOwn(values, 'error')) ||
            (values.code !== undefined && !/^[\x21-\x7e]{1,2048}$/.test(values.code))) unavailable();
        phase = 'exchanging'; ownsOperation = true; // consume before the first await
        if (values.error !== undefined) unavailable();
        const token = await upstream('token', { clientId: config.clientId, clientSecret: config.clientSecret, code: values.code, redirectUri, verifier });
        // Capture a usable access token before validating the remaining response
        // so a malformed scope/refresh token still receives cleanup revocation.
        if (tokenString(token?.access_token)) accessToken = token.access_token;
        if (!live()) unavailable();
        const normalized = validateTokenResponse(token, now());
        ({ accessToken, refreshToken, accessExpiresAt } = normalized);
        const value = await upstream('profile', { token: accessToken });
        if (!live() || !value || typeof value !== 'object' || Array.isArray(value) ||
            !Number.isSafeInteger(value.user_id) || value.user_id < 1 || String(value.user_id).length > 16 ||
            ['email', 'first_name', 'last_name'].some(key => typeof value[key] !== 'string' || value[key].length > 320 || /[\u0000-\u001f\u007f]/.test(value[key]))) unavailable();
        profile = { userId: String(value.user_id), email: value.email, firstName: value.first_name, lastName: value.last_name };
        csrf = random(); phase = 'confirm';
        response(res, 303, '', { location: '/confirm' }); return;
      }
      if (req.method === 'GET' && req.url === '/confirm' && phase === 'confirm') {
        response(res, 200, `<h1>Confirm your own account</h1><p>Name: ${escape(profile.firstName)} ${escape(profile.lastName)}</p><p>Email: ${escape(profile.email)}</p><p>Only confirm if this is your intended WHOOP account. Confirmation saves this account for local syncing for exactly seven days. No health records are fetched by this login page.</p><form method="post" action="/confirm">${hidden()}<button name="confirmed" value="yes">This is my account</button><button name="confirmed" value="no">Cancel</button></form>`, { html: true }); return;
      }
      if (req.method === 'POST' && req.url === '/confirm' && phase === 'confirm') {
        const values = await form(req);
        if (!live() || phase !== 'confirm' || !equal(values.csrf, csrf) || !['yes', 'no'].includes(values.confirmed) || Object.keys(values).length !== 2) unavailable();
        ownsOperation = true;
        if (values.confirmed === 'yes') {
          phase = 'saving';
          const authorizedAt = now();
          if (!Number.isSafeInteger(authorizedAt) || authorizedAt >= accessExpiresAt ||
              !Number.isSafeInteger(authorizedAt + AUTHORIZATION_TTL_MS)) unavailable();
          const grant = { clientId: config.clientId, clientSecret: config.clientSecret, userId: profile.userId,
            accessToken, refreshToken, accessExpiresAt, authorizedAt, authorizationExpiresAt: authorizedAt + AUTHORIZATION_TTL_MS };
          await onAuthorize(grant, { signal: handoffAbort.signal });
          // The trusted storage callback checks signal/deadline immediately
          // before a synchronous atomic commit. A resolved commit owns the grant;
          // a later abort or lost response must not revoke the published tokens.
          authorized = true; phase = 'complete'; profile = undefined;
          accessToken = undefined; refreshToken = undefined; config.clientSecret = undefined;
          finishAfterResponse(res, true);
          response(res, 200, '<h1>Local WHOOP connection saved</h1><p>The local worker may sync every 15 minutes for seven days. This login page has not fetched health records. Close this tab when finished.</p>', { html: true, cookie: '' }); return;
        }
        phase = 'revoking'; await revoke(); if (!live()) unavailable();
        phase = 'cancelled'; profile = undefined; finishAfterResponse(res, false);
        response(res, 200, '<h1>Cancelled</h1><p>The grant was revoked. No connection was saved and no health records were collected.</p>', { html: true, cookie: '' }); return;
      }
      unavailable();
    } catch {
      // Invalid unrelated requests cannot consume a live authorization flow.
      if (ownsOperation && ['exchanging', 'saving', 'revoking'].includes(phase)) {
        phase = 'failed'; profile = undefined; try { await revoke(); } catch {}
        finishAfterResponse(res, false);
      }
      if (!res.headersSent) response(res, 400, 'Local connection unavailable. If consent was granted and no connection was saved, revoke this app connection in WHOOP before retrying.');
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
    stopped = true; clearTimeout(timer); handoffAbort.abort();
    // Let the confirmation response finish on the wire; forced teardown is a
    // bounded fallback for a stalled peer, not the ordinary success path.
    if (server.listening) await new Promise(resolve => {
      const grace = setTimeout(() => { server.closeAllConnections(); }, 2000);
      server.close(() => { clearTimeout(grace); resolve(); }); server.closeIdleConnections();
    });
    await Promise.allSettled([...active]); let revoked = !authorized;
    try { await revoke(); } catch { revoked = false; }
    profile = undefined; accessToken = undefined; refreshToken = undefined; config.clientSecret = undefined;
    binding = undefined; verifier = undefined; finish(authorized);
    return { authorized, revoked };
  })();
  const timer = setTimeout(() => { void close(); }, ttlMs);
  return { server, done, close };
}
