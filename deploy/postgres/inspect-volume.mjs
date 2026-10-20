// Temporary, read-only, fixed-path volume observation. No PostgreSQL execution.
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';

const ROOT = '/var/lib/postgresql/data';
const OPTIONS = fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK;
const PHASES = ['initialized', 'configuring', 'configured', 'enabling', 'enabled', 'finalizing', 'finalized'];
const fail = () => { throw new Error('POSTGRES_VOLUME_INSPECTION_UNAVAILABLE'); };
const kind = st => st.isSymbolicLink() ? 'symlink' : st.isDirectory() ? 'directory' : st.isFile() ? 'file' : 'other';
function metadata(filename) {
  try {
    const st = fs.lstatSync(filename);
    return { observed: true, present: true, type: kind(st), uid: st.uid, gid: st.gid,
      mode: (st.mode & 0o7777).toString(8).padStart(4, '0') };
  } catch (error) {
    return { observed: error?.code === 'ENOENT', present: error?.code === 'ENOENT' ? false : null };
  }
}
function directory(filename) {
  const fd = fs.openSync(filename, OPTIONS | fs.constants.O_DIRECTORY);
  if (!fs.fstatSync(fd).isDirectory()) { fs.closeSync(fd); fail(); }
  return fd;
}
function empty(fd) {
  const dir = fs.opendirSync('/proc/self/fd/' + fd);
  try { return dir.readSync() === null; } finally { dir.closeSync(); }
}
function readEnum(filename, maximum, parse) {
  let fd;
  try {
    fd = fs.openSync(filename, OPTIONS); const st = fs.fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1 || st.size < 1 || st.size > maximum) return 'unrecognized';
    const bytes = Buffer.alloc(maximum + 1); let count = 0;
    while (count < bytes.length) {
      const n = fs.readSync(fd, bytes, count, bytes.length - count, null);
      if (n === 0) break; count += n;
    }
    if (count !== st.size || count > maximum) return 'unrecognized';
    return parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, count)));
  } catch { return 'unavailable'; }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
function phase(text) {
  try {
    const value = JSON.parse(text);
    if (!value || typeof value !== 'object' || Array.isArray(value) || value.version !== 1 ||
        Object.keys(value).sort().join(',') !== 'host,phase,version' || !PHASES.includes(value.phase) ||
        (value.phase === 'initialized' ? value.host !== null : typeof value.host !== 'string' ||
          !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.railway\.internal$/.test(value.host))) return 'unrecognized';
    return value.phase;
  } catch { return 'unrecognized'; }
}

// rootPath is an import-only synthetic-fixture injection; the CLI has no options.
export function inspectVolume({ rootPath = ROOT } = {}) {
  if (typeof rootPath !== 'string' || !rootPath.startsWith('/')) fail();
  const report = { version: 1, event: 'whoop-postgres-volume-inspection',
    paths: Object.fromEntries(['root', 'lostFound', 'pgdata', 'config', 'tls', 'run', 'pgVersion', 'postmaster', 'state', 'lock']
      .map(key => [key, { observed: false, present: null }])),
    rootEntries: null, pgVersion: 'unavailable', statePhase: 'unavailable' };
  report.paths.root = metadata(rootPath);
  let root;
  try {
    root = directory(rootPath);
    const names = new Set(['lost+found', 'pgdata', 'config', 'tls', 'run', 'provision-state.json', '.provision.lock']);
    const scan = fs.opendirSync('/proc/self/fd/' + root);
    let count = 0; let onlyLostFound = true; let knownOnly = true; let complete = false;
    try {
      for (; count <= 64; count++) {
        const entry = scan.readSync();
        if (entry === null) { complete = true; break; }
        onlyLostFound &&= entry.name === 'lost+found'; knownOnly &&= names.has(entry.name);
      }
    } finally { scan.closeSync(); }
    report.rootEntries = { empty: complete && count === 0, onlyLostFound: complete && count === 1 && onlyLostFound,
      knownEntriesOnly: complete && knownOnly, scanComplete: complete };
    const prefix = '/proc/self/fd/' + root;
    for (const [key, name] of [['lostFound', 'lost+found'], ['pgdata', 'pgdata'], ['config', 'config'], ['tls', 'tls'], ['run', 'run']]) {
      const filename = prefix + '/' + name; const row = metadata(filename); row.empty = null; report.paths[key] = row;
      let child;
      try {
        child = directory(filename); row.empty = empty(child);
        if (key === 'pgdata') {
          const pg = '/proc/self/fd/' + child;
          report.paths.pgVersion = metadata(pg + '/PG_VERSION');
          report.paths.postmaster = metadata(pg + '/postmaster.pid');
          if (report.paths.pgVersion.type === 'file') report.pgVersion = readEnum(pg + '/PG_VERSION', 8, text => text === '17\n' ? '17' : 'unrecognized');
        }
      } catch { /* Missing, unreadable or unsafe paths remain explicit unknowns. */ }
      finally { if (child !== undefined) fs.closeSync(child); }
    }
    report.paths.state = metadata(prefix + '/provision-state.json');
    report.paths.lock = metadata(prefix + '/.provision.lock');
    if (report.paths.state.type === 'file') report.statePhase = readEnum(prefix + '/provision-state.json', 1024, phase);
  } catch { /* A missing/unreadable/symlink root is observed without following it. */ }
  finally { if (root !== undefined) fs.closeSync(root); }
  return report;
}

export function guard({ identity = process, environment = process.env, args = process.argv.slice(2), readStatus = () => {
  const fd = fs.openSync('/proc/self/status', OPTIONS);
  try { const b = Buffer.alloc(16385); const n = fs.readSync(fd, b, 0, b.length, 0); if (n === b.length) fail(); return b.subarray(0, n).toString('utf8'); }
  finally { fs.closeSync(fd); }
} } = {}) {
  if ([identity.getuid(), identity.geteuid(), identity.getgid(), identity.getegid()].some(id => id !== 0) || args.length ||
      Object.entries(environment).some(([key, value]) => !({ PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', LANG: 'C', UV_USE_IO_URING: '0' }[key] === value)) ||
      !/^NoNewPrivs:\s+1$/m.test(readStatus())) fail();
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { guard(); console.log(JSON.stringify(inspectVolume())); }
  catch { console.error('PostgreSQL volume inspection unavailable.'); process.exitCode = 1; }
}
