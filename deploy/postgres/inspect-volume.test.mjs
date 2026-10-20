import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { inspectVolume, guard } from './inspect-volume.mjs';

function fixture(t) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'pg-inspect-'));
  const root = parent + '/volume'; fs.mkdirSync(root, { mode: 0o700 });
  t.after(() => fs.rmSync(parent, { recursive: true })); return { parent, root };
}
test('empty fixed fixture reports metadata without creating any files', t => {
  const { root } = fixture(t); const before = fs.statSync(root);
  const value = inspectVolume({ rootPath: root });
  assert.deepEqual(value.rootEntries, { empty: true, onlyLostFound: false, knownEntriesOnly: true, scanComplete: true });
  assert.equal(value.paths.root.uid, process.getuid()); assert.equal(value.paths.root.mode, '0700');
  assert.deepEqual(value.paths.state, { observed: true, present: false });
  assert.deepEqual(fs.readdirSync(root), []); assert.equal(fs.statSync(root).mtimeMs, before.mtimeMs);
  assert(!JSON.stringify(value).includes(root));
});
test('a sole lost+found is distinguished and its emptiness observed', t => {
  const { root } = fixture(t); fs.mkdirSync(root + '/lost+found', { mode: 0o700 });
  const value = inspectVolume({ rootPath: root });
  assert.equal(value.rootEntries.onlyLostFound, true); assert.equal(value.paths.lostFound.type, 'directory');
  assert.equal(value.paths.lostFound.empty, true); assert.equal(value.paths.lostFound.mode, '0700');
  fs.writeFileSync(root + '/lost+found/private-name', 'private-body');
  const next = inspectVolume({ rootPath: root }); assert.equal(next.paths.lostFound.empty, false);
  assert(!JSON.stringify(next).includes('private'));
});
test('unknown entry names and directory contents never leave the report; scanning is bounded', t => {
  const { root } = fixture(t); fs.writeFileSync(root + '/DO-NOT-PRINT-THIS', 'secret-body');
  assert.equal(inspectVolume({ rootPath: root }).rootEntries.knownEntriesOnly, false);
  for (let n = 0; n < 70; n++) fs.writeFileSync(root + '/arbitrary-' + n, '');
  const report = inspectVolume({ rootPath: root }); assert.equal(report.rootEntries.scanComplete, false);
  assert.equal(report.rootEntries.knownEntriesOnly, false); assert(!JSON.stringify(report).includes('DO-NOT-PRINT'));
  assert(!JSON.stringify(report).includes('secret-body')); assert(!JSON.stringify(report).includes('arbitrary'));
});
test('root and child symlinks are classified without following their targets', t => {
  const { root, parent } = fixture(t); const outside = parent + '/outside-secret'; fs.mkdirSync(outside);
  fs.writeFileSync(outside + '/PG_VERSION', '17\n');
  fs.symlinkSync(outside, root + '/pgdata'); fs.symlinkSync(outside + '/PG_VERSION', root + '/provision-state.json');
  let value = inspectVolume({ rootPath: root });
  assert.equal(value.paths.pgdata.type, 'symlink'); assert.equal(value.paths.pgdata.empty, null);
  assert.equal(value.pgVersion, 'unavailable'); assert.equal(value.statePhase, 'unavailable');
  assert(!JSON.stringify(value).includes('outside-secret'));
  fs.symlinkSync(root, parent + '/root-link'); value = inspectVolume({ rootPath: parent + '/root-link' });
  assert.equal(value.paths.root.type, 'symlink'); assert.equal(value.rootEntries, null);
  assert.deepEqual(value.paths.state, { observed: false, present: null });
});
test('only fixed PG17 and validated phase enums are emitted, never host or lock content', t => {
  const { root } = fixture(t); fs.mkdirSync(root + '/pgdata', { mode: 0o700 });
  fs.writeFileSync(root + '/pgdata/PG_VERSION', '17\n', { mode: 0o600 });
  fs.writeFileSync(root + '/pgdata/postmaster.pid', 'secret-pid-content');
  fs.writeFileSync(root + '/.provision.lock', 'secret-lock-content', { mode: 0o600 });
  for (const phase of ['initialized', 'configuring', 'configured', 'enabling', 'enabled', 'finalizing', 'finalized']) {
    const text = JSON.stringify({ version: 1, phase, host: phase === 'initialized' ? null : 'secret-host.railway.internal' });
    fs.writeFileSync(root + '/provision-state.json', text, { mode: 0o600 });
    const value = inspectVolume({ rootPath: root }); assert.equal(value.pgVersion, '17'); assert.equal(value.statePhase, phase);
    assert.equal(fs.readFileSync(root + '/provision-state.json', 'utf8'), text);
    assert.equal(value.paths.lock.type, 'file'); assert.equal(value.paths.postmaster.type, 'file');
    assert(!JSON.stringify(value).includes('secret'));
  }
});
test('oversized, malformed, extra-field and multiply-linked marker files remain fixed unknowns', t => {
  const { root, parent } = fixture(t);
  for (const body of ['x'.repeat(1025), 'private-raw-string', '{', JSON.stringify({ version: 1, phase: 'initialized', host: null, secret: 'value' })]) {
    fs.writeFileSync(root + '/provision-state.json', body);
    assert.equal(inspectVolume({ rootPath: root }).statePhase, 'unrecognized');
  }
  fs.writeFileSync(root + '/provision-state.json', JSON.stringify({ version: 1, phase: 'initialized', host: null }));
  fs.linkSync(root + '/provision-state.json', parent + '/hardlink');
  assert.equal(inspectVolume({ rootPath: root }).statePhase, 'unrecognized');
  fs.mkdirSync(root + '/pgdata'); fs.writeFileSync(root + '/pgdata/PG_VERSION', '18\n');
  assert.equal(inspectVolume({ rootPath: root }).pgVersion, 'unrecognized');
});
test('missing roots and special fixed-path types never imply an empty safe volume', t => {
  const { root } = fixture(t); const absent = inspectVolume({ rootPath: root + '/absent' });
  assert.deepEqual(absent.paths.root, { observed: true, present: false }); assert.equal(absent.rootEntries, null);
  fs.writeFileSync(root + '/pgdata', 'private-body'); fs.mkdirSync(root + '/provision-state.json');
  const value = inspectVolume({ rootPath: root }); assert.equal(value.paths.pgdata.type, 'file');
  assert.equal(value.statePhase, 'unavailable'); assert.equal(value.pgVersion, 'unavailable');
});
test('CLI guard requires root real/effective IDs, NNP, clean fixed environment and no arguments', () => {
  const identity = { getuid: () => 0, geteuid: () => 0, getgid: () => 0, getegid: () => 0 };
  const base = { identity, environment: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', LANG: 'C' }, args: [], readStatus: () => 'NoNewPrivs:\t1\n' };
  guard(base);
  for (const change of [{ identity: { ...identity, geteuid: () => 999 } }, { args: ['other-path'] },
    { environment: { NODE_OPTIONS: '--inspect' } }, { environment: { UV_USE_IO_URING: '1' } }, { readStatus: () => 'NoNewPrivs:\t0\n' }])
    assert.throws(() => guard({ ...base, ...change }), /^Error: POSTGRES_VOLUME_INSPECTION_UNAVAILABLE$/);
});
