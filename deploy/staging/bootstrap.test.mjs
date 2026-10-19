import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable, PassThrough } from 'node:stream';
import { initializeVolume, provisionFixture, readProvisioningJson } from './bootstrap.mjs';
import { readPrivateJson } from '../railway/config.mjs';

const CONFIG = { mode: 'synthetic-fixture-only', hostname: 'staging-backend.test-tailnet.ts.net', serviceTokenSha256: 'a'.repeat(64) };
const stat = (uid, mode, { directory = true, symlink = false } = {}) => ({ uid, mode, isDirectory: () => directory, isSymbolicLink: () => symlink });
function fakeVolume(entries = {}) {
  const records = { '/data': stat(0, 0o755), ...entries }; const changes = [];
  return {
    records, changes,
    identity: { getuid: () => 0 },
    filesystem: {
      lstatSync: name => { if (!records[name]) throw new Error('absent'); return records[name]; },
      readdirSync: name => Object.keys(records).filter(key => path.dirname(key) === name).map(key => path.basename(key)),
      mkdirSync: (name, options) => { changes.push(['mkdir', name, options.mode]); records[name] = stat(0, options.mode); },
      chownSync: (name, uid, gid) => { changes.push(['chown', name, uid, gid]); records[name].uid = uid; },
    },
  };
}
test('volume initialization changes only fixed empty directories and rejects unexpected state before mutation', () => {
  const fresh = fakeVolume(); initializeVolume(fresh);
  assert.deepEqual(fresh.changes, [['mkdir', '/data/config', 0o700], ['chown', '/data/config', 1000, 1000],
    ['mkdir', '/data/tailscale', 0o700], ['chown', '/data/tailscale', 1000, 1000]]);
  for (const entries of [
    { '/data/secrets': stat(0, 0o700) },
    { '/data/config': stat(0, 0o700, { symlink: true }) },
    { '/data/config': stat(0, 0o755) },
    { '/data/tailscale': stat(1000, 0o700), '/data/tailscale/tailscaled.state': stat(1000, 0o600, { directory: false }) },
    { '/data/lost+found': stat(1000, 0o700) },
  ]) {
    const bad = fakeVolume(entries); assert.throws(() => initializeVolume(bad)); assert.deepEqual(bad.changes, []);
  }
  const nonroot = fakeVolume(); nonroot.identity.getuid = () => 1000;
  assert.throws(() => initializeVolume(nonroot)); assert.deepEqual(nonroot.changes, []);
  const gateway = fakeVolume(); initializeVolume({ ...gateway, role: 'gateway' });
  assert.deepEqual(gateway.changes.slice(-2), [['mkdir', '/data/app', 0o700], ['chown', '/data/app', 1000, 1000]]);
  const wrongRole = fakeVolume(); assert.throws(() => initializeVolume({ ...wrongRole, role: 'backend' }));
  assert.deepEqual(wrongRole.changes, []);
});
test('configuration input rejects interactive, oversized, invalid UTF8 and stalled streams', async () => {
  assert.deepEqual(await readProvisioningJson(Readable.from([Buffer.from(JSON.stringify(CONFIG))])), CONFIG);
  const terminal = new PassThrough(); terminal.isTTY = true;
  await assert.rejects(readProvisioningJson(terminal), /STAGING_PROVISIONING_UNAVAILABLE/);
  for (const bytes of [Buffer.alloc(4097, 97), Buffer.from([0xff]), Buffer.from(''), Buffer.from('{')]) {
    await assert.rejects(readProvisioningJson(Readable.from([bytes])), /STAGING_PROVISIONING_UNAVAILABLE/);
  }
  const stalled = new PassThrough();
  await assert.rejects(readProvisioningJson(stalled, { timeoutMs: 10 }), /STAGING_PROVISIONING_UNAVAILABLE/);
  assert.equal(stalled.destroyed, true);
});
test('configuration is created atomically/private, refuses replacement and leaves no temporary or secret file', t => {
  assert.equal(process.getuid(), 1000, 'run only in the approved non-root fixture');
  assert.equal(process.getgid(), 1000);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'synthetic-staging-provision-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const name of ['config', 'tailscale']) fs.mkdirSync(path.join(root, name), { mode: 0o700 });
  provisionFixture(CONFIG, { root });
  const filename = path.join(root, 'config/staging.json');
  assert.deepEqual(readPrivateJson(filename), CONFIG);
  assert.equal(fs.statSync(filename).mode & 0o777, 0o600); assert.equal(fs.statSync(filename).nlink, 1);
  assert.throws(() => provisionFixture({ ...CONFIG, serviceTokenSha256: 'b'.repeat(64) }, { root }));
  assert.deepEqual(readPrivateJson(filename), CONFIG);
  assert.deepEqual(fs.readdirSync(path.join(root, 'config')), ['staging.json']);
  assert.deepEqual(fs.readdirSync(path.join(root, 'tailscale')), []);
  assert.throws(() => provisionFixture({ ...CONFIG, WHOOP_CLIENT_SECRET: 'secret-sentinel' }, { root }));
  assert.ok(!fs.readFileSync(filename, 'utf8').includes('secret-sentinel'));
});
