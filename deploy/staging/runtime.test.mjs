import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { startSyntheticStaging } from './runtime.mjs';

const config = { mode: 'synthetic-fixture-only', hostname: 'staging-backend.test-tailnet.ts.net', serviceTokenSha256: 'a'.repeat(64) };
test('staging waits for approved backend node and binds synthetic server on loopback8080 only', async () => {
  const events = []; let failNode;
  const tailscale = async options => {
    events.push('node'); assert.deepEqual(options, { stateDirectory: '/data/tailscale', tag: 'tag:whoop-backend', hostname: config.hostname, port: 8080, enrollmentKey: undefined });
    return { failed: new Promise(r => { failNode = r; }), close: async () => { events.push('node close'); } };
  };
  const server = new EventEmitter();
  server.listen = (port, host, ready) => { events.push('listen'); assert.equal(port, 8080); assert.equal(host, '127.0.0.1'); queueMicrotask(ready); };
  server.closeAllConnections = () => { events.push('connections close'); };
  server.close = done => { events.push('server close'); done(); };
  const runtime = await startSyntheticStaging(config, { tailscale, service: raw => { assert.deepEqual(raw, config); return server; } });
  assert.deepEqual(events, ['node', 'listen']);
  failNode(); await runtime.failed; await runtime.close();
  assert.deepEqual(events, ['node', 'listen', 'connections close', 'server close', 'node close']);
});
test('staging enrollment never starts fixture service and startup failure closes node', async () => {
  let called = 0; let closed = 0;
  const tailscale = async () => ({ failed: new Promise(() => {}), close: async () => { closed++; } });
  const service = () => { called++; throw new Error('synthetic failure'); };
  await startSyntheticStaging(config, { enrollmentKey: 'synthetic-key-for-injected-node-only', tailscale, service });
  assert.equal(called, 0); assert.equal(closed, 1);
  await assert.rejects(startSyntheticStaging(config, { tailscale, service }), /SYNTHETIC_STAGING_UNAVAILABLE/);
  assert.equal(called, 1); assert.equal(closed, 2);
});
