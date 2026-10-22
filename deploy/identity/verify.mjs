// Temporary owner verification only. No database, health endpoint or allowlist write.
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { exact, tailnetHostname } from '../railway/config.mjs';

const HOST = 'api.prod.whoop.com';
export const LOOPBACK_ORIGIN = 'http://localhost:17645';
export const LOOPBACK_MARKER_HEADER = 'x-whoop-local-ingress';
const COOKIE = '__Host-whoop_identity';
const TTL = 300000;
const unavailable = () => { throw new Error('IDENTITY_UNAVAILABLE'); };
const random = () => randomBytes(32).toString('base64url');
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const escape = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const tokenString = value => typeof value === 'string' && /^[\x21-\x7e]{1,4096}$/.test(value);

export function parseIdentityConfig(raw) {
  try {
    exact(raw, ['mode', 'hostname', 'clientId', 'clientSecret']);
    if (raw.mode !== 'whoop-owner-identity') unavailable();
    tailnetHostname(raw.hostname);
    for (const key of ['clientId', 'clientSecret']) if (typeof raw[key] !== 'string' || !/^[\x21-\x7e]{1,2048}$/.test(raw[key])) unavailable();
    return { ...raw };
  } catch { unavailable(); }
}

// A separate explicit schema keeps production provisioning and runtime parsing
// restricted to their existing HTTPS hostname contract.
export function parseLoopbackIdentityConfig(raw) {
  try {
    exact(raw, ['mode', 'clientId', 'clientSecret']);
    if (raw.mode !== 'whoop-owner-identity-loopback') unavailable();
    for (const key of ['clientId', 'clientSecret']) if (typeof raw[key] !== 'string' || !/^[\x21-\x7e]{1,2048}$/.test(raw[key])) unavailable();
    return { ...raw };
  } catch { unavailable(); }
}

// Fixed WHOOP destinations; no proxy/env options, redirects or remote URL inputs.
export function requestWhoop(kind, fields, { request = https.request } = {}) {
  const paths = { token: '/oauth/oauth2/token', profile: '/developer/v2/user/profile/basic', revoke: '/developer/v2/user/access' };
  if (!Object.hasOwn(paths, kind)) unavailable();
  const body = kind === 'token' ? new URLSearchParams({ grant_type: 'authorization_code', code: fields.code,
    redirect_uri: fields.redirectUri, client_id: fields.clientId, client_secret: fields.clientSecret, code_verifier: fields.verifier }).toString() : undefined;
  if (kind !== 'token' && !tokenString(fields.token)) unavailable();
  const headers = { Accept: 'application/json', 'Accept-Encoding': 'identity', Connection: 'close',
    ...(body === undefined ? { Authorization: `Bearer ${fields.token}` } : { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }) };
  return new Promise((resolve, reject) => {
    let req; let timer; let settled = false;
    const fail = () => { if (settled) return; settled = true; clearTimeout(timer); req?.destroy(); reject(new Error('IDENTITY_UNAVAILABLE')); };
    try {
      req = request({ protocol: 'https:', hostname: HOST, port: 443, servername: HOST, path: paths[kind],
        method: kind === 'token' ? 'POST' : kind === 'profile' ? 'GET' : 'DELETE', headers, agent: false,
        rejectUnauthorized: true, minVersion: 'TLSv1.2', ALPNProtocols: ['http/1.1'],
        checkServerIdentity: (_host, cert) => tls.checkServerIdentity(HOST, cert) }, response => {
        let size = 0; const chunks = [];
        const encoding = response.headers['content-encoding']; const length = response.headers['content-length'];
        if ((encoding !== undefined && encoding !== 'identity') ||
            (length !== undefined && (!/^\d+$/.test(length) || Number(length) > 8192)) ||
            response.statusCode !== (kind === 'revoke' ? 204 : 200) ||
            (kind !== 'revoke' && String(response.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase() !== 'application/json')) {
          response.destroy(); fail(); return;
        }
        response.on('error', fail); response.on('aborted', fail);
        response.on('data', chunk => { size += chunk.length; if (size > 8192 || (kind === 'revoke' && size > 0)) { response.destroy(); fail(); } else chunks.push(chunk); });
        response.on('end', () => {
          if (settled) return;
          try {
            const result = kind === 'revoke' ? null : JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
            settled = true; clearTimeout(timer); resolve(result);
          } catch { fail(); }
        });
      });
      req.on('error', fail); timer = setTimeout(fail, 5000); req.end(body);
    } catch { fail(); }
  });
}

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
  res.end(html ? '<!doctype html><html lang="en"><meta charset="utf-8"><title>WHOOP owner verification</title>' + body + '</html>' : body);
}
async function form(req) {
  if (String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase() !== 'application/x-www-form-urlencoded' ||
      (req.headers['content-encoding'] && req.headers['content-encoding'] !== 'identity')) unavailable();
  let size = 0; const chunks = [];
  for await (const chunk of req) { size += chunk.length; if (size > 1024) unavailable(); chunks.push(chunk); }
  return parameters(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)), ['csrf', 'confirmed']);
}

export function createIdentityServer(raw, { upstream = requestWhoop, now = Date.now, ttlMs = TTL, loopbackMarker } = {}) {
  const loopback = raw?.mode === 'whoop-owner-identity-loopback';
  const config = loopback ? parseLoopbackIdentityConfig(raw) : parseIdentityConfig(raw);
  if (loopback && (typeof loopbackMarker !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(loopbackMarker))) unavailable();
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > TTL) unavailable();
  const origin = loopback ? LOOPBACK_ORIGIN : `https://${config.hostname}`; const redirectUri = origin + '/whoop/callback';
  const expectedHost = loopback ? 'localhost:17645' : config.hostname;
  const started = now(); let phase = 'intro'; let binding; let csrf; let state; let verifier; let profile;
  let accessToken; let revokePending; let closing; let stopped = false; let completed = false; let finish;
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
  async function route(req, res) {
    let ownsOperation = false;
    try {
      let hosts = 0; let origins = 0; let forwarded = 0; let markers = 0; let untrustedForwarding = false;
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        const name = req.rawHeaders[i].toLowerCase(); if (name === 'host') hosts++; if (name === 'origin') origins++; if (name === 'x-forwarded-proto') forwarded++;
        if (name === LOOPBACK_MARKER_HEADER) markers++;
        if (name === 'forwarded' || name.startsWith('x-forwarded-')) untrustedForwarding = true;
      }
      const transportValid = loopback
        ? !untrustedForwarding && markers === 1 && equal(req.headers[LOOPBACK_MARKER_HEADER], loopbackMarker)
        : forwarded === 1 && req.headers['x-forwarded-proto'] === 'https';
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
        response(res, 200, `<h1>Verify your WHOOP account</h1><p>This temporary check reads only your account profile. It does not read health data, request offline access, or configure the backend.</p><form method="post" action="/start">${hidden()}<button>Continue to WHOOP</button></form>`, { html: true, cookie: binding }); return;
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
          scope: 'read:profile', state, code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }).toString();
        response(res, 200, `<h1>Continue on WHOOP</h1><p>The next page is WHOOP's sign-in and consent page. This check requests only your account profile, without health data or offline access.</p><p><a href="${escape(url.href)}" rel="noreferrer">Open WHOOP sign-in</a></p>`, { html: true }); return;
      }
      if (req.method === 'GET' && url.pathname === '/whoop/callback' && phase === 'authorizing') {
        const values = parameters(url.searchParams, ['state', 'code', 'error']);
        if (!equal(values.state, state) || (Object.hasOwn(values, 'code') === Object.hasOwn(values, 'error')) ||
            (values.code !== undefined && !/^[\x21-\x7e]{1,2048}$/.test(values.code))) unavailable();
        phase = 'exchanging'; ownsOperation = true; // consume before the first await
        if (values.error !== undefined) unavailable();
        const token = await upstream('token', { ...config, code: values.code, redirectUri, verifier });
        if (tokenString(token?.access_token)) accessToken = token.access_token;
        if (!live() || !accessToken || typeof token.token_type !== 'string' || token.token_type.toLowerCase() !== 'bearer' ||
            token.scope !== 'read:profile' || (token.refresh_token !== undefined && token.refresh_token !== null && token.refresh_token !== '') ||
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
        response(res, 200, `<h1>Confirm your own account</h1><p>Name: ${escape(profile.firstName)} ${escape(profile.lastName)}</p><p>Email: ${escape(profile.email)}</p><p>Only confirm if this is your intended WHOOP account. The server will revoke this temporary grant before displaying the numeric ID.</p><form method="post" action="/confirm">${hidden()}<button name="confirmed" value="yes">This is my account</button><button name="confirmed" value="no">Cancel</button></form>`, { html: true }); return;
      }
      if (req.method === 'POST' && req.url === '/confirm' && phase === 'confirm') {
        const values = await form(req);
        if (!live() || phase !== 'confirm' || !equal(values.csrf, csrf) || !['yes', 'no'].includes(values.confirmed) || Object.keys(values).length !== 2) unavailable();
        phase = 'revoking'; ownsOperation = true; await revoke(); if (!live()) unavailable();
        phase = 'complete'; const id = profile.userId; profile = undefined;
        finishAfterResponse(res, values.confirmed === 'yes');
        response(res, 200, values.confirmed === 'yes' ? `<h1>Temporary grant revoked</h1><p>Confirmed WHOOP numeric user ID: <strong>${id}</strong></p><p>Record this ID through the approved private operator process. This page has not changed the backend allowlist.</p>` : '<h1>Verification cancelled</h1><p>The temporary grant was revoked. No backend configuration was changed.</p>', { html: true, cookie: '' }); return;
      }
      unavailable();
    } catch {
      // Invalid unrelated requests cannot consume a live authorization flow.
      if (ownsOperation && ['exchanging', 'revoking'].includes(phase)) {
        phase = 'failed'; profile = undefined; try { await revoke(); } catch {}
        finishAfterResponse(res, false);
      }
      if (!res.headersSent) response(res, 400, 'Verification unavailable. If consent was granted, revoke the temporary app connection in WHOOP before retrying.');
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
    stopped = true; clearTimeout(timer);
    // Let the confirmation response finish on the wire; forced teardown is a
    // bounded fallback for a stalled peer, not the ordinary success path.
    if (server.listening) await new Promise(resolve => {
      const grace = setTimeout(() => { server.closeAllConnections(); }, 2000);
      server.close(() => { clearTimeout(grace); resolve(); }); server.closeIdleConnections();
    });
    await Promise.allSettled([...active]); let revoked = true;
    try { await revoke(); } catch { revoked = false; }
    profile = undefined; accessToken = undefined; binding = undefined; verifier = undefined; finish(completed);
    return { revoked };
  })();
  const timer = setTimeout(() => { void close(); }, ttlMs);
  return { server, done, close };
}
