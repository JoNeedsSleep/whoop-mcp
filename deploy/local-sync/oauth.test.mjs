import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { SCOPES, requestOAuth, validateTokenResponse, validateScopes, parseLocalSyncConfig } from './oauth.mjs';

const NOW = 1792670400000;
const denied = { message: 'LOCAL_SYNC_UNAVAILABLE' };
const config = { mode: 'whoop-local-sync', clientId: 'synthetic-client', clientSecret: 'synthetic-secret' };
const token = { access_token: 'synthetic-access', refresh_token: 'synthetic-refresh', expires_in: 3600, token_type: 'bearer', scope: SCOPES };
const refresh = { clientId: config.clientId, clientSecret: config.clientSecret, refreshToken: token.refresh_token };
function transport({ status = 200, headers = { 'content-type': 'application/json' }, rawHeaders, body = Buffer.from(JSON.stringify(token)), stall = false, error } = {}) {
  let options, sent, incoming, destroyed = false;
  const native = (config, callback) => {
    options = config; const req = new EventEmitter(); req.destroy = () => { destroyed = true; };
    req.end = value => { sent = value; queueMicrotask(() => {
      if (error) { req.emit('error', Error(error)); return; }
      incoming = new PassThrough(); incoming.statusCode = status; incoming.headers = headers;
      incoming.rawHeaders = rawHeaders ?? Object.entries(headers).flat(); callback(incoming);
      if (!stall && !incoming.destroyed) incoming.end(body);
    }); }; return req;
  };
  return { native, get options() { return options; }, get sent() { return sent; }, get destroyed() { return destroyed; }, get incoming() { return incoming; } };
}

test('login config and token output are exact plain schemas without getters or destination selectors', () => {
  assert.deepEqual(parseLocalSyncConfig(config), config);
  for (const value of [{ ...config, mode: 'whoop-local-view' }, { ...config, redirectUri: 'https://evil.invalid' },
    { ...config, clientSecret: '' }, Object.assign(Object.create(null), config),
    { ...config, get clientSecret() { assert.fail('getter executed'); } }]) assert.throws(() => parseLocalSyncConfig(value), denied);
  assert.deepEqual(validateTokenResponse(token, NOW), { accessToken: token.access_token, refreshToken: token.refresh_token, accessExpiresAt: NOW + 3600000 });
  for (const bad of [{ ...token, refresh_token: '' }, { ...token, access_token: 'bad\n' }, { ...token, token_type: 'MAC' },
    { ...token, expires_in: 0 }, { ...token, expires_in: 86401 }, { ...token, expires_in: 1.5 },
    { ...token, privateMetadata: 'never retained' }, { ...token, get scope() { assert.fail('getter executed'); } }]) assert.throws(() => validateTokenResponse(bad, NOW), denied);
  for (const time of [0, -1, NaN, Infinity, NOW + 0.5, Number.MAX_SAFE_INTEGER]) assert.throws(() => validateTokenResponse(token, time), denied);
});

test('callback and token scopes require all six permissions exactly, accepting only ASCII whitespace and reordering', () => {
  validateScopes(SCOPES); validateScopes('\t' + SCOPES.split(' ').reverse().join(' \r\n') + ' ');
  for (const scope of ['', 'offline', SCOPES.replace(' offline', ''), SCOPES + ' offline', SCOPES + ' read:body_measurement',
    SCOPES.replace(' ', ','), SCOPES.replace(' ', '\u00a0'), ' '.repeat(257)]) {
    assert.throws(() => validateScopes(scope), denied); assert.throws(() => validateTokenResponse({ ...token, scope }, NOW), denied);
  }
});

test('refresh rotates through the fixed verified TLS endpoint using form-only credentials and offline scope', async () => {
  const f = transport(); assert.deepEqual(await requestOAuth('refresh', refresh, { request: f.native }), token);
  const options = f.options, fields = new URLSearchParams(f.sent);
  assert.equal(options.hostname, 'api.prod.whoop.com'); assert.equal(options.servername, options.hostname);
  assert.equal(options.protocol, 'https:'); assert.equal(options.port, 443); assert.equal(options.path, '/oauth/oauth2/token');
  assert.equal(options.method, 'POST'); assert.equal(options.agent, false); assert.equal(options.rejectUnauthorized, true);
  assert.equal(options.minVersion, 'TLSv1.2'); assert.deepEqual(options.ALPNProtocols, ['http/1.1']); assert.equal(options.maxHeaderSize, 8192);
  assert.deepEqual(Object.fromEntries(fields), { grant_type: 'refresh_token', refresh_token: token.refresh_token, client_id: config.clientId, client_secret: config.clientSecret, scope: 'offline' });
  assert.equal(options.headers['Content-Length'], Buffer.byteLength(f.sent)); assert.equal(options.headers.Authorization, undefined);
  assert.doesNotMatch(options.path, /synthetic/); assert(options.checkServerIdentity('evil.invalid', { subjectaltname: 'DNS:evil.invalid' }) instanceof Error);
});

test('authorization exchange, profile and revoke have fixed methods and reject unknown inputs before a request', async () => {
  const fields = { clientId: config.clientId, clientSecret: config.clientSecret, code: 'synthetic-code', redirectUri: 'http://localhost:17645/whoop/callback', verifier: 'v'.repeat(43) };
  const f = transport(); await requestOAuth('token', fields, { request: f.native });
  assert.deepEqual(Object.fromEntries(new URLSearchParams(f.sent)), { grant_type: 'authorization_code', code: fields.code, redirect_uri: fields.redirectUri, client_id: fields.clientId, client_secret: fields.clientSecret, code_verifier: fields.verifier });
  const p = transport({ body: Buffer.from('{}') }); await requestOAuth('profile', { token: token.access_token }, { request: p.native });
  assert.equal(p.options.method, 'GET'); assert.equal(p.options.path, '/developer/v2/user/profile/basic'); assert.equal(p.sent, undefined);
  assert.equal(p.options.headers.Authorization, 'Bearer ' + token.access_token);
  const r = transport({ status: 204, headers: {}, body: Buffer.alloc(0) }); assert.equal(await requestOAuth('revoke', { token: token.access_token }, { request: r.native }), null);
  assert.equal(r.options.method, 'DELETE'); assert.equal(r.options.path, '/developer/v2/user/access');
  for (const [kind, input] of [['other', {}], ['__proto__', {}], ['refresh', { ...refresh, url: 'https://evil.invalid' }],
    ['refresh', { ...refresh, refreshToken: '' }], ['token', { ...fields, redirectUri: 'http://127.0.0.1:17645/whoop/callback' }],
    ['token', { ...fields, verifier: 'x' }], ['profile', { token: 'bad\n' }]])
    await assert.rejects(requestOAuth(kind, input, { request: () => assert.fail('invalid request emitted') }), denied);
});

test('response framing/status/size/encoding/JSON failures remain fixed and never retry', async () => {
  for (const settings of [{ status: 302 }, { status: 429 }, { status: 500 }, { headers: { 'content-type': 'text/plain' } },
    { headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' } },
    { headers: { 'content-type': 'application/json', 'content-length': '16385' } },
    { headers: { 'content-type': 'application/json', 'content-length': '1' } },
    { headers: { 'content-type': 'application/json', 'content-length': '1', 'transfer-encoding': 'chunked' } },
    { rawHeaders: ['Content-Type', 'application/json', 'Content-Type', 'application/json'] },
    { body: Buffer.from('private upstream failure') }, { body: Buffer.from([0xff]) }, { body: Buffer.alloc(16385, 32) }, { error: 'private socket' }]) {
    const f = transport(settings); let calls = 0;
    await assert.rejects(requestOAuth('refresh', refresh, { request: (...args) => { calls++; return f.native(...args); } }), denied);
    assert.equal(calls, 1); assert.equal(f.destroyed, true);
  }
  const r = transport({ status: 204, headers: {}, body: Buffer.from('not empty') });
  await assert.rejects(requestOAuth('revoke', { token: token.access_token }, { request: r.native }), denied);
});

test('cancellation tears down the owned request/response and a pre-aborted request performs no I/O', async () => {
  const f = transport({ stall: true }), controller = new AbortController();
  const pending = requestOAuth('refresh', refresh, { request: f.native, signal: controller.signal });
  await new Promise(resolve => setImmediate(resolve)); controller.abort();
  await assert.rejects(pending, denied); assert.equal(f.destroyed, true); assert.equal(f.incoming.destroyed, true);
  await assert.rejects(requestOAuth('refresh', refresh, { signal: controller.signal, request: () => assert.fail('preabort') }), denied);
});
