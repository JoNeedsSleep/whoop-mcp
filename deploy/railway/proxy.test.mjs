// Synthetic proxy contract from pinned Tailscale v1.104.1 serve.go:904-1050.
// This does not start Serve, enroll a node, or claim deployed ACL/browser proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import express from 'express';
import cookieSession from 'cookie-session';
import { startGateway } from '../../review-gateway/index.mjs';

async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function close(server) { if (!server?.listening) return; server.closeAllConnections(); await new Promise(r => server.close(r)); }
function tlsFixture() {
  const dir = process.env.GATEWAY_TEST_TLS_DIR;
  assert(dir && path.isAbsolute(dir), 'Explicit offline synthetic TLS fixture required');
  return { ca: fs.readFileSync(path.join(dir, 'ca.pem')), key: fs.readFileSync(path.join(dir, 'server-key.pem')), cert: fs.readFileSync(path.join(dir, 'server.pem')) };
}
function serveProxy(tls, port) {
  return https.createServer({ key: tls.key, cert: tls.cert, minVersion: 'TLSv1.2' }, (req, res) => {
    const headers = { ...req.headers };
    // Go ReverseProxy Rewrite drops untrusted forwarding headers, then Serve
    // restores the input Host (only TCP HTTP target; Unix targets differ).
    for (const key of Object.keys(headers)) if (key.startsWith('x-forwarded-') || key.startsWith('tailscale-') ||
      ['forwarded', 'connection', 'keep-alive', 'proxy-authorization', 'proxy-authenticate', 'te', 'trailer', 'transfer-encoding', 'upgrade'].includes(key)) delete headers[key];
    headers.host = req.headers.host;
    headers['x-forwarded-host'] = req.headers.host;
    headers['x-forwarded-proto'] = 'https';
    headers['x-forwarded-for'] = '100.72.0.11';
    const upstream = http.request({ hostname: '127.0.0.1', port, method: req.method, path: req.url, headers, agent: false }, reply => {
      res.writeHead(reply.statusCode, reply.headers); reply.pipe(res);
    });
    upstream.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
    req.pipe(upstream);
  });
}
function request(tls, port, hostname, route, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname: '127.0.0.1', port, servername: hostname, path: route, ca: tls.ca, agent: false,
      headers: { Host: hostname, ...headers } }, res => {
      const chunks = []; res.on('data', b => chunks.push(b)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.setTimeout(5000, () => req.destroy()); req.on('error', reject); req.end();
  });
}

test('Serve TCP proxy contract preserves canonical Host and overwrites forwarding before secure-cookie middleware', async t => {
  const tls = tlsFixture(); const hostname = 'backend.test-tailnet.ts.net';
  const app = express(); app.set('trust proxy', 'loopback');
  app.use(cookieSession({ name: '__Host-whoop_dashboard_session', secret: 'synthetic-session-secret-for-offline-test', secure: true, httpOnly: true, sameSite: 'lax', maxAge: 604800000 }));
  app.get('/fixture', (req, res) => { req.session.fixture = true; res.json({ secure: req.secure, hostname: req.hostname,
    host: req.headers.host, client: req.ip, spoof: req.headers['tailscale-user-login'] ?? null }); });
  const backend = http.createServer(app); const backendPort = await listen(backend);
  const proxy = serveProxy(tls, backendPort); const proxyPort = await listen(proxy);
  t.after(async () => { await close(proxy); await close(backend); });
  const r = await request(tls, proxyPort, hostname, '/fixture', { 'X-Forwarded-Proto': 'http', 'X-Forwarded-Host': 'evil.example',
    'X-Forwarded-For': '127.0.0.1', 'Tailscale-User-Login': 'spoof@example.test' });
  assert.equal(r.status, 200); assert.deepEqual(JSON.parse(r.body), { secure: true, hostname, host: hostname, client: '100.72.0.11', spoof: null });
  assert.ok(r.headers['set-cookie'].every(v => /; secure/i.test(v) && /; httponly/i.test(v) && /; samesite=lax/i.test(v)));
});
test('real gateway accepts preserved canonical Host and rejects forged Host despite forwarded host through Serve contract', async t => {
  const tls = tlsFixture(); const hostname = 'gateway.test-tailnet.ts.net';
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'whoop-serve-test-')); fs.chmodSync(directory, 0o700);
  const upstreamTokenFile = path.join(directory, 'service-token'); fs.writeFileSync(upstreamTokenFile, `whoopgw_service_${'S'.repeat(43)}`, { mode: 0o600 });
  const probe = http.createServer(); const port = await listen(probe); await close(probe);
  const runtime = startGateway({ publicOrigin: `https://${hostname}`, upstreamOrigin: 'https://backend.test-tailnet.ts.net', upstreamTokenFile,
    databaseFile: path.join(directory, 'gateway.sqlite'), ownerSecretHash: 'a'.repeat(64), port,
    clients: [{ clientId: 'codex', name: 'Codex', redirectUris: ['http://127.0.0.1:17643/callback'] },
      { clientId: 'claude-code', name: 'Claude Code', redirectUris: ['http://localhost:17644/callback'] }] });
  await once(runtime.server, 'listening');
  const proxy = serveProxy(tls, port); const proxyPort = await listen(proxy);
  t.after(async () => { await close(proxy); await close(runtime.server); runtime.store.close(); fs.rmSync(directory, { recursive: true, force: true }); });
  const metadata = await request(tls, proxyPort, hostname, '/.well-known/oauth-authorization-server', { 'X-Forwarded-Host': 'evil.example' });
  assert.equal(metadata.status, 200); assert.equal(JSON.parse(metadata.body).issuer, `https://${hostname}`);
  assert.equal((await request(tls, proxyPort, hostname, '/owner', { Host: 'evil.example', 'X-Forwarded-Host': hostname })).status, 403);
  await assert.rejects(request(tls, proxyPort, 'wrong.test-tailnet.ts.net', '/owner'), { code: 'ERR_TLS_CERT_ALTNAME_INVALID' });
});
