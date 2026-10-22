import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { authorizeGrant, validateGrant, withLockedState, AUTHORIZATION_TTL_MS, SYNC_INTERVAL_MS } from './state.mjs';

const NOW = Date.parse('2026-10-22T12:00:00Z');
const denied = { message: 'LOCAL_SYNC_UNAVAILABLE' };
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'local-sync-state-'));
  const authDir = path.join(root, 'auth'), codex = path.join(root, 'codex'), claude = path.join(root, 'claude');
  for (const dir of [authDir, codex, claude]) fs.mkdirSync(dir, { mode: 0o700 });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  let time = NOW;
  return { root, authDir, cachePaths: { codex: path.join(codex, 'cache.json'), 'claude-code': path.join(claude, 'cache.json') },
    now: () => time, setTime: value => { time = value; } };
}
const grant = () => ({ clientId: 'synthetic-client', clientSecret: 'synthetic-secret', userId: '1234', accessToken: 'old-access', refreshToken: 'old-refresh',
  authorizedAt: NOW, accessExpiresAt: NOW + 3600000, authorizationExpiresAt: NOW + AUTHORIZATION_TTL_MS });

test('exact credential schema forbids extra identity/text, invalid times and deadline extension', () => {
  assert.deepEqual(validateGrant(grant()), grant());
  for (const value of [{ ...grant(), email: 'private@example.test' }, { ...grant(), userId: '01234' },
    { ...grant(), userId: '9007199254740993' }, { ...grant(), authorizationExpiresAt: NOW + AUTHORIZATION_TTL_MS + 1 },
    { ...grant(), accessToken: 'bad\nheader' }, { ...grant(), refreshToken: '' }, { ...grant(), authorizedAt: -0 }])
    assert.throws(() => validateGrant(value), denied);
});

test('authorization commits private exact state; abort-before-commit rejects and commit wins later abort', async t => {
  const f = fixture(t), controller = new AbortController(); controller.abort();
  await assert.rejects(authorizeGrant(grant(), { ...f, signal: controller.signal }), denied);
  assert.equal(await withLockedState(store => store.read().grant, f), null);
  const later = new AbortController();
  await authorizeGrant(grant(), { ...f, signal: later.signal }); later.abort();
  assert.deepEqual(await withLockedState(store => store.read().grant, f), grant());
  await assert.rejects(authorizeGrant(grant(), f), denied);
  for (const name of ['state.sqlite', 'writer.sqlite']) {
    const st = fs.lstatSync(path.join(f.authDir, name)); assert.equal(st.mode & 0o777, 0o600); assert.equal(st.nlink, 1); assert.equal(st.uid, process.getuid());
  }
  assert.equal(fs.readdirSync(path.dirname(f.cachePaths.codex)).length, 0);
});

test('durable admission survives reopened handles, exact15min boundary, failures and rollback', async t => {
  const f = fixture(t); await authorizeGrant(grant(), f);
  await assert.rejects(withLockedState(store => { assert.equal(store.admit(), true); throw Error('synthetic downstream failure'); }, f), denied);
  assert.equal(await withLockedState(store => store.admit(), f), false);
  f.setTime(NOW - 1); assert.equal(await withLockedState(store => store.admit(), f), false);
  f.setTime(NOW + SYNC_INTERVAL_MS - 1); assert.equal(await withLockedState(store => store.admit(), f), false);
  f.setTime(NOW + SYNC_INTERVAL_MS); assert.equal(await withLockedState(store => store.admit(), f), true);
  f.setTime(NOW + 10 * SYNC_INTERVAL_MS); assert.equal(await withLockedState(store => store.admit(), f), true);
  assert.equal(await withLockedState(store => store.admit(), f), false);
});

test('writer lock excludes actual separate process and releases after exception', async t => {
  const f = fixture(t); await authorizeGrant(grant(), f);
  await withLockedState(async () => {
    const code = `import{withLockedState}from${JSON.stringify(new URL('./state.mjs', import.meta.url).href)};try{await withLockedState(()=>{},${JSON.stringify({ authDir: f.authDir, cachePaths: f.cachePaths })});process.exit(2)}catch(e){if(e.message!=='LOCAL_SYNC_BUSY')process.exit(3);process.stdout.write('busy')}`;
    const output = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ['--input-type=module', '-e', code], { env: { PATH: '/usr/local/bin:/usr/bin:/bin' }, stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = ''; child.stdout.on('data', part => { stdout += part; }); child.stderr.resume();
      child.on('error', reject); child.on('exit', code => code === 0 ? resolve(stdout) : reject(Error('child lock rejection failed')));
    }); assert.equal(output, 'busy');
  }, f);
  assert.equal(await withLockedState(store => store.read().phase, f), 'active');
});

test('refresh marker survives interrupted operation and blocks reuse even after successful-looking DB write', async t => {
  const f = fixture(t); await authorizeGrant(grant(), f);
  await withLockedState(store => store.beginRefresh(), f);
  const interrupted = await withLockedState(store => store.read(), f);
  assert.equal(interrupted.phase, 'refreshing'); assert.equal(interrupted.interruptedRefresh, true);
  const db = new DatabaseSync(path.join(f.authDir, 'state.sqlite'));
  const row = JSON.parse(db.prepare('SELECT value FROM durable_state WHERE id=1').get().value); row.phase = 'active';
  db.prepare('UPDATE durable_state SET value=? WHERE id=1').run(JSON.stringify(row)); db.close();
  assert.equal(await withLockedState(store => store.read().interruptedRefresh, f), true);
  await assert.rejects(withLockedState(store => store.beginRefresh(), f), denied);
  await withLockedState(store => store.discard(), f);
  await authorizeGrant({ ...grant(), accessToken: 'new-login-access', refreshToken: 'new-login-refresh' }, f);
  assert.equal(await withLockedState(store => store.read().interruptedRefresh, f), false);
});

test('rotation persists both tokens together, preserves fixed grant deadline and removes only own marker', async t => {
  const f = fixture(t); await authorizeGrant(grant(), f); f.setTime(NOW + 1000);
  await withLockedState(store => {
    store.beginRefresh(); store.replaceTokens('old-refresh', { accessToken: 'new-access', refreshToken: 'new-refresh', accessExpiresAt: NOW + 3601000 });
  }, f);
  const value = await withLockedState(store => store.read(), f);
  assert.equal(value.grant.accessToken, 'new-access'); assert.equal(value.grant.refreshToken, 'new-refresh');
  assert.equal(value.grant.authorizationExpiresAt, grant().authorizationExpiresAt); assert.equal(value.interruptedRefresh, false);
  assert.equal(fs.existsSync(path.join(f.authDir, 'refresh.pending')), false);
});

test('symlink, hardlink, public directory and unsafe cache substitutions fail before credential changes', async t => {
  const f = fixture(t); const outside = path.join(f.root, 'outside'); fs.writeFileSync(outside, 'sentinel', { mode: 0o600 });
  fs.symlinkSync(outside, path.join(f.authDir, 'writer.sqlite'));
  await assert.rejects(authorizeGrant(grant(), f), denied); assert.equal(fs.readFileSync(outside, 'utf8'), 'sentinel'); fs.unlinkSync(path.join(f.authDir, 'writer.sqlite'));
  fs.linkSync(outside, path.join(f.authDir, 'state.sqlite'));
  await assert.rejects(authorizeGrant(grant(), f), denied); fs.unlinkSync(path.join(f.authDir, 'state.sqlite'));
  fs.chmodSync(f.authDir, 0o755); await assert.rejects(authorizeGrant(grant(), f), denied); fs.chmodSync(f.authDir, 0o700);
  fs.symlinkSync(outside, f.cachePaths.codex); await assert.rejects(authorizeGrant(grant(), f), denied);
  assert.equal(fs.readFileSync(outside, 'utf8'), 'sentinel');
});

test('discard removes durable credentials and both caches without deleting admission history', async t => {
  const f = fixture(t); await authorizeGrant(grant(), f);
  for (const filename of Object.values(f.cachePaths)) fs.writeFileSync(filename, 'synthetic', { mode: 0o600 });
  await withLockedState(store => { store.admit(); store.discard(); }, f);
  const value = await withLockedState(store => store.read(), f);
  assert.equal(value.grant, null); assert.equal(value.phase, 'reauthorize'); assert.equal(value.lastAttemptAt, NOW);
  assert(Object.values(f.cachePaths).every(filename => !fs.existsSync(filename)));
});
