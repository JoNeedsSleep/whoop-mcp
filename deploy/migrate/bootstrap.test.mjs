import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Readable, PassThrough } from 'node:stream';
import { migrationFromStdin } from './bootstrap.mjs';

const identity = { getuid: () => 1000, getgid: () => 1000, geteuid: () => 1000, getegid: () => 1000 };
const config = { host: 'whoop-db.railway.internal', port: 5432, database: 'whoop', user: 'whoop_migrate',
  ownerRole: 'whoop_owner', password: 'synthetic-not-a-real-secret', caCertificate: '-----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----\n' };
const input = value => Readable.from([Buffer.from(typeof value === 'string' ? value : JSON.stringify(value))]);
const options = { identity, environment: {}, noNewPrivileges() {} };

test('fixed private migration config reaches only the ordinary guarded migrator', async () => {
  let calls = 0;
  const result = await migrationFromStdin({ ...options, input: input(config), migrate: async supplied => {
    calls++; assert.deepEqual(supplied.readConfig('/migration/config.json'), config);
    assert.throws(() => supplied.readConfig('/different'), /MIGRATION_UNAVAILABLE/);
    assert.deepEqual(Object.keys(supplied).sort(), ['args', 'environment', 'identity', 'noNewPrivileges', 'readConfig', 'signal']);
    return { completed: true };
  } });
  assert.equal(calls, 1); assert.deepEqual(result, { completed: true });
});

test('root, unexpected environment/args and missing NNP fail before input is read', async () => {
  for (const change of [{ identity: { ...identity, getuid: () => 0 } }, { environment: { NODE_OPTIONS: '--inspect' } },
    { args: ['extra'] }, { args: '' }, { environment: { UV_USE_IO_URING: '1' } },
    { noNewPrivileges() { throw Error('private details'); } }]) {
    const stream = new PassThrough(); let migrations = 0;
    await assert.rejects(migrationFromStdin({ ...options, input: stream, ...change, migrate: async () => { migrations++; } }), /^Error: MIGRATION_UNAVAILABLE$/);
    assert.equal(stream.listenerCount('data'), 0); assert.equal(migrations, 0); stream.destroy();
  }
});

test('only the fixed private database and roles with an explicit CA are admitted', async () => {
  for (const change of [{ host: 'example.com' }, { host: 'a.b.railway.internal' }, { user: 'other' },
    { user: 'whoop_migrator' }, { ownerRole: 'other' }, { database: 'other' }, { caCertificate: null }, { arbitrary: true }]) {
    let calls = 0;
    await assert.rejects(migrationFromStdin({ ...options, input: input({ ...config, ...change }), migrate: async () => { calls++; } }), /MIGRATION_UNAVAILABLE/);
    assert.equal(calls, 0);
  }
});

test('malformed, oversized, invalid UTF8 and incomplete streams are bounded', async () => {
  for (const stream of [input('{'), input('x'.repeat(32769)), Readable.from([Buffer.from([0xff, 0xfe])]), input('')]) {
    await assert.rejects(migrationFromStdin({ ...options, input: stream, migrate: async () => assert.fail('unexpected migration') }), /MIGRATION_UNAVAILABLE/);
    assert.equal(stream.listenerCount('data'), 0);
  }
  const stalled = new PassThrough();
  await assert.rejects(migrationFromStdin({ ...options, input: stalled, timeoutMs: 10 }), /MIGRATION_UNAVAILABLE/);
  assert.equal(stalled.listenerCount('data'), 0); stalled.destroy();
});

test('migration failures remain fixed errors without secret details', async () => {
  await assert.rejects(migrationFromStdin({ ...options, input: input(config), migrate: async () => { throw Error(config.password); } }), /^Error: MIGRATION_UNAVAILABLE$/);
});

test('cancellation stops stdin admission and reaches the ordinary migration cancellation boundary', async () => {
  const pending = new PassThrough(); const reading = new AbortController(); let calls = 0;
  const stopped = migrationFromStdin({ ...options, input: pending, signal: reading.signal,
    migrate: async () => { calls++; } });
  reading.abort(); await assert.rejects(stopped, /^Error: MIGRATION_UNAVAILABLE$/);
  assert.equal(calls, 0); assert.equal(pending.listenerCount('data'), 0); pending.destroy();
  const controller = new AbortController();
  await assert.rejects(migrationFromStdin({ ...options, environment: { UV_USE_IO_URING: '0' },
    input: input(config), signal: controller.signal, migrate: async supplied => {
      assert.equal(supplied.signal, controller.signal); controller.abort();
      assert.equal(supplied.signal.aborted, true); throw Error('private cancellation detail');
    } }), /^Error: MIGRATION_UNAVAILABLE$/);
});
