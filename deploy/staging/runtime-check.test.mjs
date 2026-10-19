import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { collectRuntimeCheck, requireNoNewPrivileges } from './runtime-check.mjs';

const identity = { getuid: () => 1000, getgid: () => 1000, geteuid: () => 1000, getegid: () => 1000, getgroups: () => [1000, 1000] };
const status = 'Name:\tsecret-sentinel\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n';
const mountinfo = '1 0 0:1 / / ro,relatime - overlay overlay rw,lowerdir=/secret-sentinel\n2 1 0:2 / /data rw,nosuid,nodev - ext4 /secret-sentinel rw\n3 1 0:3 / /sys/fs/cgroup ro,nosuid,nodev,noexec - cgroup2 cgroup rw\n';
function fixture(overrides = {}) {
  const files = { '/proc/self/status': status, '/proc/self/mountinfo': mountinfo, '/proc/self/cgroup': '0::/\n',
    '/sys/fs/cgroup/memory.max': '536870912\n', '/sys/fs/cgroup/memory.high': 'max\n', '/sys/fs/cgroup/memory.swap.max': '0\n',
    '/sys/fs/cgroup/pids.max': '128\n', '/sys/fs/cgroup/cpu.max': '100000 100000\n', ...overrides };
  const readPaths = []; const statPaths = []; const closed = []; const handles = new Map(); let next = 1;
  const filesystem = {
    openSync(filename, flags) {
      readPaths.push(filename); assert.equal(flags, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
      if (!Object.hasOwn(files, filename)) throw new Error('secret-sentinel');
      const fd = next++; handles.set(fd, { bytes: Buffer.from(files[filename]), offset: 0 }); return fd;
    },
    fstatSync: () => ({ isFile: () => true }),
    readSync(fd, output, offset, count) { const handle = handles.get(fd); const n = Math.min(count, handle.bytes.length - handle.offset);
      handle.bytes.copy(output, offset, handle.offset, handle.offset + n); handle.offset += n; return n; },
    closeSync(fd) { handles.delete(fd); closed.push(fd); },
    lstatSync(filename) { statPaths.push(filename); return { uid: 1000, gid: 1000, mode: 0o40700,
      isDirectory: () => true, isSymbolicLink: () => false, isFile: () => false }; },
  };
  return { filesystem, identity, files, readPaths, statPaths, closed, handles };
}

test('runtime report emits a fixed sanitized schema and reads only approved kernel files and directory metadata', () => {
  const f = fixture(); const report = collectRuntimeCheck(f);
  assert.deepEqual(Object.keys(report), ['event', 'schemaVersion', 'identity', 'capabilities', 'noNewPrivileges', 'seccomp', 'seccompFilters', 'cgroup', 'mounts', 'directories']);
  assert.deepEqual(report.identity, { uid: 1000, gid: 1000, effectiveUid: 1000, effectiveGid: 1000, groups: [1000] });
  assert.equal(report.noNewPrivileges, true); assert.equal(report.seccomp, 2);
  assert.deepEqual(report.cgroup, { version: 2, visibility: 'current-visible-cgroup-only', memoryMax: '536870912', memoryHigh: 'max',
    memorySwapMax: '0', pidsMax: '128', cpuMax: { quotaMicroseconds: '100000', periodMicroseconds: '100000' } });
  assert.equal(report.mounts.root.readOnly, true); assert.equal(report.mounts.data.readOnly, false);
  assert.equal(report.mounts.data.noSuid, true); assert.equal(report.mounts.data.separateMount, true);
  assert.deepEqual(f.statPaths, ['/data', '/data/config', '/data/tailscale', '/data/app']);
  assert.ok(f.readPaths.every(filename => filename.startsWith('/proc/self/') || filename.startsWith('/sys/fs/cgroup/')));
  assert.equal(f.handles.size, 0); assert.equal(f.closed.length, f.readPaths.length);
  assert.ok(!JSON.stringify(report).includes('secret-sentinel'));
});

test('root or invalid identity fails before any filesystem access or report', () => {
  for (const key of ['getuid', 'getgid', 'geteuid', 'getegid']) {
    for (const value of [0, -1, '1000', 2 ** 40]) {
      const f = fixture(); assert.throws(() => collectRuntimeCheck({ ...f, identity: { ...identity, [key]: () => value } }), /STAGING_RUNTIME_CHECK_UNAVAILABLE/);
      assert.deepEqual(f.readPaths, []); assert.deepEqual(f.statPaths, []);
    }
  }
  for (const groups of [[NaN], ['secret-sentinel'], Array(129).fill(1)]) {
    const f = fixture(); assert.throws(() => collectRuntimeCheck({ ...f, identity: { ...identity, getgroups: () => groups } }), /STAGING_RUNTIME_CHECK_UNAVAILABLE/);
    assert.deepEqual(f.readPaths, []);
  }
});

test('missing or weaker provider controls remain visible without reporting a false pass', () => {
  const f = fixture({ '/proc/self/status': 'CapEff:\t0000000000000400\nNoNewPrivs:\t0\nSeccomp:\t0\n',
    '/proc/self/mountinfo': mountinfo.replace(' / ro,relatime ', ' / rw,relatime '), '/sys/fs/cgroup/memory.max': 'max', '/sys/fs/cgroup/pids.max': 'max' });
  const report = collectRuntimeCheck({ ...f, identity: { ...identity, getgroups: () => [0, 1000] } });
  assert.equal(report.noNewPrivileges, false); assert.equal(report.seccomp, 0);
  assert.equal(report.capabilities.effective, '0000000000000400'); assert.equal(report.capabilities.ambient, null);
  assert.equal(report.mounts.root.readOnly, false); assert.equal(report.cgroup.memoryMax, 'max');
  assert.deepEqual(report.identity.groups, [0, 1000]);
});

test('unknown, malformed, duplicate and overlong kernel fields never escape into logs', () => {
  for (const text of [status + 'CapEff:\tsecret-sentinel\nNoNewPrivs:\t1\n', 'CapEff:\tsecret-sentinel\nSeccomp:\t99\n', 'x'.repeat(262145), Buffer.from([0xff])]) {
    const f = fixture({ '/proc/self/status': text }); const report = collectRuntimeCheck(f);
    assert.equal(report.capabilities.effective, null); assert.ok(!JSON.stringify(report).includes('secret-sentinel'));
    assert.equal(f.handles.size, 0);
  }
  const f = fixture({ '/sys/fs/cgroup/memory.max': 'secret-sentinel', '/sys/fs/cgroup/cpu.max': 'max secret-sentinel' });
  const report = collectRuntimeCheck(f); assert.equal(report.cgroup.memoryMax, null); assert.equal(report.cgroup.cpuMax, null);
});

test('cgroup paths are kernel-derived, bounded and confined; v1 or ambiguous membership is unknown', () => {
  for (const value of ['0::/../../data/config\n', '0::/data//secret\n', '0::/\n0::/other\n', '1:memory:/\n', '0::/secret sentinel\n']) {
    const f = fixture({ '/proc/self/cgroup': value }); const report = collectRuntimeCheck(f);
    assert.equal(report.cgroup.version, null); assert.equal(report.cgroup.memoryMax, null);
    assert.ok(f.readPaths.every(filename => !filename.startsWith('/sys/fs/cgroup/')));
  }
  const f = fixture({ '/proc/self/cgroup': '0::/job/leaf\n',
    '/proc/self/mountinfo': mountinfo.replace('0:3 / /sys/fs/cgroup', '0:3 /job /sys/fs/cgroup'), '/sys/fs/cgroup/leaf/memory.max': '268435456' });
  const report = collectRuntimeCheck(f); assert.equal(report.cgroup.memoryMax, '268435456');
  assert.equal(report.cgroup.visibility, 'current-visible-cgroup-only');
  assert.ok(f.readPaths.includes('/sys/fs/cgroup/leaf/memory.max'));
});

test('directory symlinks, absent metadata and mount absence are reported without following config files', () => {
  const f = fixture({ '/proc/self/mountinfo': '' });
  f.filesystem.lstatSync = filename => {
    f.statPaths.push(filename);
    if (filename === '/data/app') throw new Error('secret-sentinel');
    return { uid: 0, gid: 0, mode: 0o120777, isSymbolicLink: () => true, isDirectory: () => false, isFile: () => false };
  };
  const report = collectRuntimeCheck(f);
  assert.deepEqual(report.directories.config, { observed: true, type: 'symlink', uid: 0, gid: 0, mode: '0777' });
  assert.equal(report.directories.app.observed, false); assert.equal(report.mounts.data.observed, false);
  assert.ok(!JSON.stringify(report).includes('secret-sentinel')); assert.ok(!f.readPaths.some(filename => filename.startsWith('/data')));
});

test('actual isolated provider observation is sanitized and cannot inspect caller-selected paths', () => {
  assert.equal(process.getuid(), 1000, 'run only inside the approved non-root fixture');
  assert.equal(requireNoNewPrivileges(), undefined);
  const report = collectRuntimeCheck();
  assert.equal(report.identity.uid, 1000); assert.equal(report.event, 'staging-runtime-check');
  assert.equal(report.capabilities.effective, '0000000000000000'); assert.equal(report.noNewPrivileges, true);
  assert.equal(report.mounts.root.readOnly, true);
  assert.ok(JSON.stringify(report).length < 4096);
});

test('the no-new-privileges gate accepts only an unambiguous kernel value of one', () => {
  const good = fixture(); assert.equal(requireNoNewPrivileges(good), undefined);
  assert.deepEqual(good.readPaths, ['/proc/self/status']); assert.deepEqual(good.statPaths, []);
  for (const value of ['NoNewPrivs:\t0\n', '', 'NoNewPrivs:\tsecret-sentinel\n',
    'NoNewPrivs:\t1\nNoNewPrivs:\t1\n', 'NoNewPrivs:\t2\n', 'NoNewPrivs:\t1\n' + 'x'.repeat(262145)]) {
    const f = fixture({ '/proc/self/status': value });
    assert.throws(() => requireNoNewPrivileges(f), { message: 'STAGING_RUNTIME_CHECK_UNAVAILABLE' });
    assert.equal(f.handles.size, 0); assert.deepEqual(f.statPaths, []);
  }
  const missing = fixture(); delete missing.files['/proc/self/status'];
  assert.throws(() => requireNoNewPrivileges(missing), { message: 'STAGING_RUNTIME_CHECK_UNAVAILABLE' });
});
