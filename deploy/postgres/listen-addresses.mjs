import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import { pathToFileURL } from 'node:url';

const fail = () => { throw new Error('POSTGRES_LISTENER_UNAVAILABLE'); };
export const ENVIRONMENT = Object.freeze({
  PATH: '/usr/lib/postgresql/17/bin:/usr/bin:/bin', HOME: '/tmp', LANG: 'C', UV_USE_IO_URING: '0',
});

function kernelGuard() {
  const fd = fs.openSync('/proc/self/status', fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const bytes = Buffer.alloc(16385);
    const length = fs.readSync(fd, bytes, 0, bytes.length, 0);
    if (length === bytes.length || !/^NoNewPrivs:\s+1$/m.test(bytes.subarray(0, length).toString())) fail();
  } finally { fs.closeSync(fd); }
}

export function guardSelector({ identity = process, environment = process.env, guard = kernelGuard } = {}) {
  if ([identity.getuid(), identity.geteuid(), identity.getgid(), identity.getegid()].some(value => value !== 999)) fail();
  guard();
  if (!environment || Object.keys(environment).sort().join(',') !== Object.keys(ENVIRONMENT).sort().join(',') ||
      Object.keys(ENVIRONMENT).some(key => environment[key] !== ENVIRONMENT[key])) fail();
}

function classify(row) {
  if (!row || typeof row.address !== 'string' || row.address.length > 45 || row.address.includes('%') ||
      typeof row.internal !== 'boolean') fail();
  const family = row.family === 'IPv4' ? 4 : row.family === 'IPv6' ? 6 : 0;
  if (!family || net.isIP(row.address) !== family) fail();
  const ip = family === 6 ? new URL(`http://[${row.address}]/`).hostname.slice(1, -1) : row.address;
  if (ip !== row.address) fail();
  let kind;
  if (family === 4) {
    const [a, b] = ip.split('.').map(Number);
    if (ip === '127.0.0.1') kind = 'loopback4';
    else if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) kind = 'private4';
  } else if (ip === '::1') kind = 'loopback6';
  else if (/^f[cd][0-9a-f]{2}:/.test(ip)) kind = 'private6';
  else if (/^fe[89ab][0-9a-f]:/.test(ip)) kind = 'linklocal6';
  if (!kind) fail();
  return { ip, kind, internal: row.internal };
}

export function selectListenAddresses(raw) {
  // This interface layout was observed on the approved database service.
  // Any additional interface/address fails closed pending another review.
  if (!raw || Object.getPrototypeOf(raw) !== Object.prototype ||
      Object.keys(raw).sort().join(',') !== 'lo,railnet0' ||
      !Array.isArray(raw.lo) || raw.lo.length !== 2 ||
      !Array.isArray(raw.railnet0) || raw.railnet0.length !== 3) fail();
  const loopback = raw.lo.map(classify);
  if (loopback.some(row => !row.internal) || loopback.map(row => row.kind).sort().join(',') !== 'loopback4,loopback6') fail();
  const railnet = raw.railnet0.map(classify);
  if (railnet.some(row => row.internal) ||
      railnet.map(row => row.kind).sort().join(',') !== 'linklocal6,private4,private6') fail();
  return railnet.find(row => row.kind === 'private4').ip + ',' + railnet.find(row => row.kind === 'private6').ip;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 2) fail();
    guardSelector();
    process.stdout.write(selectListenAddresses(os.networkInterfaces()) + '\n');
  } catch {
    process.stderr.write('PostgreSQL listener unavailable.\n');
    process.exitCode = 1;
  }
}
