// Fixed, staging-only startup diagnostics. These are observations by the running
// process, not post-compromise attestation or a substitute for provider controls.
import fs from 'node:fs';
import path from 'node:path';

const fail = () => { throw new Error('STAGING_RUNTIME_CHECK_UNAVAILABLE'); };
const MAX_PROC = 256 * 1024;
const CGROUP_ROOT = '/sys/fs/cgroup';
const id = value => Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff ? value : null;
const integer = text => /^(?:0|[1-9][0-9]{0,9})$/.test(text ?? '') && Number.isSafeInteger(Number(text)) ? Number(text) : null;
const limit = text => text === 'max' || /^(?:0|[1-9][0-9]{0,19})$/.test(text ?? '') ? text : null;

function readBounded(filesystem, filename, maximum = MAX_PROC) {
  let fd;
  try {
    fd = filesystem.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    if (!filesystem.fstatSync(fd).isFile()) return null;
    const buffer = Buffer.alloc(maximum + 1);
    let used = 0;
    while (used <= maximum) {
      const count = filesystem.readSync(fd, buffer, used, buffer.length - used, null);
      if (count === 0) return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, used));
      used += count;
    }
  } catch { /* Never return filesystem errors, paths or unvalidated contents. */ }
  finally { if (fd !== undefined) { try { filesystem.closeSync(fd); } catch {} } }
  return null;
}

function statusFields(text) {
  const fields = new Map();
  for (const line of (text ?? '').split('\n')) {
    const match = /^(CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp|Seccomp_filters):\s*([^\r\n]*)$/.exec(line);
    if (!match) continue;
    // Duplicates are ambiguous, not a reason to pick the favorable value.
    fields.set(match[1], fields.has(match[1]) ? null : match[2].trim());
  }
  const caps = key => /^[0-9a-fA-F]{1,16}$/.test(fields.get(key) ?? '') ? fields.get(key).toLowerCase().padStart(16, '0') : null;
  const nnp = fields.get('NoNewPrivs'); const seccomp = fields.get('Seccomp');
  return {
    capabilities: { inheritable: caps('CapInh'), permitted: caps('CapPrm'), effective: caps('CapEff'), bounding: caps('CapBnd'), ambient: caps('CapAmb') },
    noNewPrivileges: nnp === '1' ? true : nnp === '0' ? false : null,
    seccomp: ['0', '1', '2'].includes(seccomp) ? Number(seccomp) : null,
    seccompFilters: integer(fields.get('Seccomp_filters')),
  };
}

function mounts(text) {
  const records = [];
  for (const line of (text ?? '').split('\n')) {
    const split = line.indexOf(' - ');
    if (split < 0) continue;
    const left = line.slice(0, split).split(' '); const right = line.slice(split + 3).split(' ');
    if (left.length < 6 || right.length < 3 || !left[4].startsWith('/')) continue;
    // Paths containing escapes cannot be our fixed ASCII targets or cgroup root.
    if (left[4].includes('\\')) continue;
    records.push({ root: left[3], target: left[4], options: left[5].split(','), filesystem: right[0], superOptions: right[2].split(',') });
  }
  return records;
}

function mountFlags(records, target) {
  const candidates = records.filter(record => record.target === '/' || record.target === target || target.startsWith(record.target + '/'));
  candidates.sort((a, b) => b.target.length - a.target.length);
  const selected = candidates[0];
  if (!selected || candidates.filter(record => record.target === selected.target).length !== 1) return { observed: false, separateMount: null, readOnly: null, noSuid: null, noDev: null, noExec: null };
  const flags = [...selected.options, ...selected.superOptions];
  return { observed: true, separateMount: selected.target === target,
    readOnly: flags.includes('ro') ? true : flags.includes('rw') ? false : null,
    noSuid: flags.includes('nosuid'), noDev: flags.includes('nodev'), noExec: flags.includes('noexec') };
}

function cgroup(filesystem, records) {
  const result = { version: null, visibility: 'current-visible-cgroup-only', memoryMax: null, memoryHigh: null,
    memorySwapMax: null, pidsMax: null, cpuMax: null };
  const membership = readBounded(filesystem, '/proc/self/cgroup', 16384);
  const entries = (membership ?? '').trim().split('\n').filter(line => line.startsWith('0::'));
  const roots = records.filter(record => record.filesystem === 'cgroup2' && record.target === CGROUP_ROOT);
  if (entries.length !== 1 || roots.length !== 1) return result;
  const current = entries[0].slice(3); const root = roots[0].root;
  const safePath = value => /^\/(?:[A-Za-z0-9_.:@-]+\/?)*$/.test(value) && path.posix.normalize(value) === value && !value.split('/').some(part => part === '.' || part === '..');
  if (!safePath(current) || !safePath(root) || !(root === '/' || current === root || current.startsWith(root + '/'))) return result;
  const relative = root === '/' ? current.slice(1) : current.slice(root.length).replace(/^\//, '');
  if (relative.split('/').length > 32) return result;
  const directory = path.posix.join(CGROUP_ROOT, relative);
  if (directory !== CGROUP_ROOT && !directory.startsWith(CGROUP_ROOT + '/')) return result;
  const read = name => readBounded(filesystem, path.posix.join(directory, name), 128)?.trim();
  result.version = 2;
  result.memoryMax = limit(read('memory.max')); result.memoryHigh = limit(read('memory.high'));
  result.memorySwapMax = limit(read('memory.swap.max')); result.pidsMax = limit(read('pids.max'));
  const cpu = /^(max|[0-9]{1,20}) ([1-9][0-9]{0,19})$/.exec(read('cpu.max') ?? '');
  if (cpu && limit(cpu[1]) !== null && limit(cpu[2]) !== null) result.cpuMax = { quotaMicroseconds: cpu[1], periodMicroseconds: cpu[2] };
  return result;
}

function directoryInfo(filesystem, filename) {
  try {
    const st = filesystem.lstatSync(filename);
    return { observed: true, type: st.isSymbolicLink() ? 'symlink' : st.isDirectory() ? 'directory' : st.isFile() ? 'file' : 'other',
      uid: id(st.uid), gid: id(st.gid), mode: Number.isInteger(st.mode) ? (st.mode & 0o7777).toString(8).padStart(4, '0') : null };
  } catch { return { observed: false, type: null, uid: null, gid: null, mode: null }; }
}

// Dependency injection exists only for isolated tests. Production callers use no
// arguments; no CLI path, environment, command or file-content interface exists.
export function collectRuntimeCheck({ filesystem = fs, identity = process } = {}) {
  let uid; let gid; let effectiveUid; let effectiveGid; let groups;
  try {
    uid = id(identity.getuid()); gid = id(identity.getgid());
    effectiveUid = id(identity.geteuid()); effectiveGid = id(identity.getegid());
    groups = identity.getgroups();
  } catch { fail(); }
  if ([uid, gid, effectiveUid, effectiveGid].some(value => value === null || value === 0) ||
      !Array.isArray(groups) || groups.length > 128 || groups.some(value => id(value) === null)) fail();
  const status = statusFields(readBounded(filesystem, '/proc/self/status'));
  const records = mounts(readBounded(filesystem, '/proc/self/mountinfo'));
  return { event: 'staging-runtime-check', schemaVersion: 1,
    identity: { uid, gid, effectiveUid, effectiveGid, groups: [...new Set(groups)].sort((a, b) => a - b) },
    ...status, cgroup: cgroup(filesystem, records), mounts: { root: mountFlags(records, '/'), data: mountFlags(records, '/data') },
    directories: { data: directoryInfo(filesystem, '/data'), config: directoryInfo(filesystem, '/data/config'),
      tailscale: directoryInfo(filesystem, '/data/tailscale'), app: directoryInfo(filesystem, '/data/app') } };
}

export function emitRuntimeCheck() {
  const record = collectRuntimeCheck();
  console.log(JSON.stringify(record));
  return record;
}

// Staging launch commands set this with the image's existing setpriv utility
// before Node starts. Reject overrides that bypass that wrapper before reading
// bootstrap credentials or private configuration. This check also applies to
// the root-only empty-volume phase; it grants no capabilities or privileges.
export function requireNoNewPrivileges({ filesystem = fs } = {}) {
  if (statusFields(readBounded(filesystem, '/proc/self/status')).noNewPrivileges !== true) fail();
}
