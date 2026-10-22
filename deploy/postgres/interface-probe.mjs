import os from 'node:os';
import net from 'node:net';
import { Resolver } from 'node:dns';

export const HOST = 'whoopindividualpostgreskill-2026.railway.internal';
export const ENVIRONMENT = Object.freeze({
  PATH: '/usr/local/bin:/usr/lib/postgresql/17/bin:/usr/bin:/bin',
  HOME: '/tmp', LANG: 'C', UV_USE_IO_URING: '0',
});
const EVENT = 'whoop-postgres-network-metadata';
const fail = () => { throw new Error('POSTGRES_NETWORK_METADATA_UNAVAILABLE'); };

function address(value, family) {
  if (typeof value !== 'string' || value.length > 45 || value.includes('%') ||
      ![4, 6].includes(family) || net.isIP(value) !== family) fail();
  const canonical = family === 6 ? new URL(`http://[${value}]/`).hostname.slice(1, -1) : value;
  let scope = 'OTHER';
  if (family === 4) {
    const [a, b] = canonical.split('.').map(Number);
    if (a === 127) scope = 'LOOPBACK';
    else if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) scope = 'PRIVATE';
    else if (a === 169 && b === 254) scope = 'LINK_LOCAL';
    else if (canonical === '0.0.0.0') scope = 'UNSPECIFIED';
  } else if (canonical === '::1') scope = 'LOOPBACK';
  else if (canonical === '::') scope = 'UNSPECIFIED';
  else if (canonical.startsWith('::ffff:')) scope = 'MAPPED';
  else if (/^f[cd][0-9a-f]{2}:/.test(canonical)) scope = 'PRIVATE';
  else if (/^fe[89ab][0-9a-f]:/.test(canonical)) scope = 'LINK_LOCAL';
  return { address: canonical, family, scope };
}

export function projectInterfaces(raw) {
  if (!raw || Object.getPrototypeOf(raw) !== Object.prototype) fail();
  const names = Object.keys(raw).sort();
  if (!names.length || names.length > 8) fail();
  let total = 0;
  return names.map(name => {
    if (!/^[A-Za-z0-9_.:-]{1,15}$/.test(name)) fail();
    const rows = raw[name];
    if (!Array.isArray(rows) || !rows.length || (total += rows.length) > 16) fail();
    const addresses = rows.map(row => {
      if (!row || typeof row.internal !== 'boolean') fail();
      const family = row.family === 'IPv4' ? 4 : row.family === 'IPv6' ? 6 : 0;
      return { ...address(row.address, family), internal: row.internal };
    }).sort((a, b) => a.family - b.family || a.address.localeCompare(b.address));
    if (new Set(addresses.map(row => row.address)).size !== addresses.length) fail();
    return { name, addresses };
  });
}

// Fixed system-DNS queries only. No application connection or file/secret read.
export function resolveHost({ signal } = {}) {
  const resolver = new Resolver({ timeout: 2000, tries: 1 });
  return new Promise(resolve => {
    const dns = { a: 'UNKNOWN', aaaa: 'UNKNOWN' };
    const addresses = []; let remaining = 2; let ended = false;
    const finish = () => {
      if (ended) return;
      ended = true; clearTimeout(timer); signal?.removeEventListener('abort', finish); resolver.cancel();
      resolve({ dns, addresses });
    };
    const timer = setTimeout(finish, 3000);
    signal?.addEventListener('abort', finish, { once: true });
    if (signal?.aborted) { finish(); return; }
    for (const [method, key, family] of [['resolve4', 'a', 4], ['resolve6', 'aaaa', 6]]) {
      try {
        resolver[method](HOST, (error, values) => {
          if (ended) return;
          if (error) dns[key] = ['ENODATA', 'ENOTFOUND'].includes(error.code) ? 'NOT_FOUND' : 'UNKNOWN';
          else if (Array.isArray(values) && values.length <= 4) {
            dns[key] = values.length ? 'RESOLVED' : 'EMPTY';
            for (const value of values) addresses.push({ address: value, family });
          }
          if (--remaining === 0) finish();
        });
      } catch { if (--remaining === 0) finish(); }
    }
  });
}

export async function inspectNetwork({ identity = process, environment = process.env,
  interfaces = os.networkInterfaces, resolve = resolveHost, now = Date.now, signal } = {}) {
  if ([identity.getuid(), identity.geteuid(), identity.getgid(), identity.getegid()].some(value => value !== 999)) fail();
  if (!environment || Object.keys(environment).sort().join(',') !== Object.keys(ENVIRONMENT).sort().join(',') ||
      Object.keys(ENVIRONMENT).some(key => environment[key] !== ENVIRONMENT[key])) fail();
  const local = projectInterfaces(interfaces());
  const resolved = await resolve({ signal });
  if (!resolved || !resolved.dns || Object.keys(resolved.dns).sort().join(',') !== 'a,aaaa' ||
      Object.values(resolved.dns).some(value => !['RESOLVED', 'EMPTY', 'NOT_FOUND', 'UNKNOWN'].includes(value)) ||
      !Array.isArray(resolved.addresses) || resolved.addresses.length > 8) fail();
  const dnsAddresses = resolved.addresses.map(row => {
    const projected = address(row?.address, row?.family);
    return { ...projected, localInterfaces: local.filter(iface => iface.addresses.some(item =>
      item.address === projected.address && item.family === projected.family)).map(iface => iface.name) };
  }).sort((a, b) => a.family - b.family || a.address.localeCompare(b.address));
  if (new Set(dnsAddresses.map(row => row.address)).size !== dnsAddresses.length) fail();
  for (const [key, family] of [['a', 4], ['aaaa', 6]]) {
    if ((resolved.dns[key] === 'RESOLVED') !== dnsAddresses.some(row => row.family === family)) fail();
  }
  const observedAt = now();
  if (!Number.isSafeInteger(observedAt) || observedAt < 0) fail();
  return { version: 1, event: EVENT, host: HOST, observedAt,
    dns: { a: resolved.dns.a, aaaa: resolved.dns.aaaa }, dnsAddresses, interfaces: local,
    outcome: !signal?.aborted && !Object.values(resolved.dns).includes('UNKNOWN') && dnsAddresses.length ? 'COMPLETE' : 'UNKNOWN' };
}

// Invoked only from the reviewed public command, never automatically on import.
export async function main() {
  const controller = new AbortController();
  const abort = () => controller.abort();
  process.once('SIGINT', abort); process.once('SIGTERM', abort);
  const timer = setTimeout(abort, 5000);
  let report;
  try { report = await inspectNetwork({ signal: controller.signal }); }
  catch { report = { version: 1, event: EVENT, outcome: 'UNKNOWN' }; }
  clearTimeout(timer); process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort);
  const code = report.outcome === 'COMPLETE' ? 0 : 1;
  const last = setTimeout(() => process.exit(code), 1000);
  process.stdout.write(JSON.stringify(report) + '\n', () => { clearTimeout(last); process.exit(code); });
}
