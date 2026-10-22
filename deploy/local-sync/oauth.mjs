import https from 'node:https';
import tls from 'node:tls';

export const SCOPES = 'read:profile read:recovery read:sleep read:workout read:cycles offline';
export const AUTHORIZATION_TTL_MS = 7 * 86400000;
export const LOOPBACK_ORIGIN = 'http://localhost:17645';
export const LOOPBACK_MARKER_HEADER = 'x-whoop-local-ingress';
const HOST = 'api.prod.whoop.com';
const fail = () => { throw new Error('LOCAL_SYNC_UNAVAILABLE'); };
export const tokenString = value => typeof value === 'string' && /^[\x21-\x7e]{1,4096}$/.test(value);
export function exact(value, keys) {
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype ||
      Reflect.ownKeys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key) ||
        !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'))) fail();
}
export function validateScopes(value) {
  if (typeof value !== 'string' || value.length > 256 || /[^\x20-\x7e\t\r\n]/.test(value)) fail();
  const scopes = value.trim().split(/[ \t\r\n]+/), expected = SCOPES.split(' ');
  if (scopes.length !== expected.length || new Set(scopes).size !== scopes.length || scopes.some(scope => !expected.includes(scope))) fail();
}
export function parseLocalSyncConfig(raw) {
  exact(raw, ['mode', 'clientId', 'clientSecret']);
  if (raw.mode !== 'whoop-local-sync') fail();
  for (const key of ['clientId', 'clientSecret']) if (typeof raw[key] !== 'string' || !/^[\x21-\x7e]{1,2048}$/.test(raw[key])) fail();
  return { ...raw };
}
export function validateTokenResponse(raw, receivedAt) {
  exact(raw, ['access_token', 'refresh_token', 'expires_in', 'scope', 'token_type']);
  validateScopes(raw.scope);
  if (!tokenString(raw.access_token) || !tokenString(raw.refresh_token) ||
      typeof raw.token_type !== 'string' || raw.token_type.toLowerCase() !== 'bearer' ||
      !Number.isSafeInteger(raw.expires_in) || raw.expires_in < 1 || raw.expires_in > 86400 ||
      !Number.isSafeInteger(receivedAt) || receivedAt < 1 || !Number.isSafeInteger(receivedAt + raw.expires_in * 1000)) fail();
  return { accessToken: raw.access_token, refreshToken: raw.refresh_token, accessExpiresAt: receivedAt + raw.expires_in * 1000 };
}

// No retries, redirects, refresh fallback, arbitrary URL, or credential-bearing
// query strings. Refresh rotates both tokens; the caller must commit both under
// its single-writer lock without extending the seven-day authorization deadline.
export async function requestOAuth(kind, fields, { request = https.request, signal } = {}) {
  const paths = { token: '/oauth/oauth2/token', refresh: '/oauth/oauth2/token', profile: '/developer/v2/user/profile/basic', revoke: '/developer/v2/user/access' };
  if (!Object.hasOwn(paths, kind)) fail();
  let body;
  if (kind === 'token' || kind === 'refresh') {
    exact(fields, kind === 'token' ? ['clientId', 'clientSecret', 'code', 'redirectUri', 'verifier'] : ['clientId', 'clientSecret', 'refreshToken']);
    parseLocalSyncConfig({ mode: 'whoop-local-sync', clientId: fields.clientId, clientSecret: fields.clientSecret });
    if (kind === 'token') {
      if (fields.redirectUri !== LOOPBACK_ORIGIN + '/whoop/callback' ||
          typeof fields.code !== 'string' || !/^[\x21-\x7e]{1,2048}$/.test(fields.code) ||
          typeof fields.verifier !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(fields.verifier)) fail();
      body = new URLSearchParams({ grant_type: 'authorization_code', code: fields.code, redirect_uri: fields.redirectUri,
        client_id: fields.clientId, client_secret: fields.clientSecret, code_verifier: fields.verifier }).toString();
    } else {
      if (!tokenString(fields.refreshToken)) fail();
      body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: fields.refreshToken,
        client_id: fields.clientId, client_secret: fields.clientSecret, scope: 'offline' }).toString();
    }
  } else { exact(fields, ['token']); if (!tokenString(fields.token)) fail(); }
  if (signal?.aborted) fail();
  const headers = { Accept: 'application/json', 'Accept-Encoding': 'identity', Connection: 'close',
    ...(body === undefined ? { Authorization: `Bearer ${fields.token}` } : { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }) };
  return new Promise((resolve, reject) => {
    let req, incoming, timer, settled = false;
    const cleanup = () => { clearTimeout(timer); signal?.removeEventListener('abort', failed); };
    const failed = () => { if (settled) return; settled = true; cleanup(); incoming?.destroy(); req?.destroy(); reject(new Error('LOCAL_SYNC_UNAVAILABLE')); };
    try {
      signal?.addEventListener('abort', failed, { once: true });
      if (signal?.aborted) { failed(); return; }
      req = request({ protocol: 'https:', hostname: HOST, port: 443, servername: HOST, path: paths[kind],
        method: body !== undefined ? 'POST' : kind === 'profile' ? 'GET' : 'DELETE', headers, agent: false,
        rejectUnauthorized: true, minVersion: 'TLSv1.2', ALPNProtocols: ['http/1.1'], maxHeaderSize: 8192,
        checkServerIdentity: (_host, cert) => tls.checkServerIdentity(HOST, cert) }, response => {
        incoming = response; let size = 0; const chunks = [];
        const names = response.rawHeaders.filter((_, i) => i % 2 === 0).map(name => name.toLowerCase());
        const encoding = response.headers['content-encoding'], length = response.headers['content-length'];
        if (['content-length', 'content-type', 'content-encoding', 'transfer-encoding'].some(name => names.filter(n => n === name).length > 1) ||
            (encoding !== undefined && encoding !== 'identity') ||
            (length !== undefined && (!/^\d+$/.test(length) || Number(length) > 16384 || response.headers['transfer-encoding'] !== undefined)) ||
            response.statusCode !== (kind === 'revoke' ? 204 : 200) ||
            (kind !== 'revoke' && String(response.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase() !== 'application/json')) { failed(); return; }
        response.on('error', failed); response.on('aborted', failed);
        response.on('data', chunk => { size += chunk.length; if (size > 16384 || (kind === 'revoke' && size > 0)) failed(); else chunks.push(chunk); });
        response.on('end', () => {
          if (settled) return;
          try {
            if (length !== undefined && size !== Number(length)) fail();
            const value = kind === 'revoke' ? null : JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
            settled = true; cleanup(); resolve(value);
          } catch { failed(); }
        });
      });
      req.on('error', failed); timer = setTimeout(failed, 5000); req.end(body);
    } catch { failed(); }
  });
}
