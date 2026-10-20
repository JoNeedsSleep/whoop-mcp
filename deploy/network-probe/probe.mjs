import { Resolver } from 'node:dns';
import net from 'node:net';

export const HOST = 'whoopindividualpostgreskill-2026.railway.internal';
export const PORT = 5432;
export const ENVIRONMENT = Object.freeze({
  PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', NODE_ENV: 'production', UV_USE_IO_URING: '0',
});
const EVENT = 'whoop-database-reachability';
const MAX_TARGETS = 4;
const MAX_AGE = 15 * 60_000;
const fail = () => { throw new Error('NETWORK_PROBE_UNAVAILABLE'); };
const exact = (value, keys) => {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype ||
      Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) fail();
  for (const key of keys) if (!Object.getOwnPropertyDescriptor(value, key)?.hasOwnProperty('value')) fail();
};
function target(raw) {
  exact(raw, ['address', 'family']);
  const { address, family } = raw;
  if (typeof address !== 'string' || address.length > 45 || ![4, 6].includes(family) || net.isIP(address) !== family) fail();
  if (family === 4) {
    const [a, b] = address.split('.').map(Number);
    if (!(a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168))) fail();
  } else if (!/^f[cd][0-9a-f]{2}:/i.test(address) ||
      new URL(`http://[${address}]/`).hostname.slice(1, -1) !== address) fail();
  return { address, family };
}
function targets(raw) {
  if (!Array.isArray(raw) || raw.length < 1 || raw.length > MAX_TARGETS) fail();
  const result = raw.map(target).sort((a, b) => a.family - b.family || a.address.localeCompare(b.address));
  if (new Set(result.map(row => row.address)).size !== result.length) fail();
  return result;
}
const dnsComplete = dns => ['RESOLVED', 'EMPTY', 'NOT_FOUND'].includes(dns.a) &&
  ['RESOLVED', 'EMPTY', 'NOT_FOUND'].includes(dns.aaaa);
export function validateRequest(raw, now = Date.now()) {
  if (!Number.isSafeInteger(now) || now < 0) fail();
  if (raw?.mode === 'production-positive') {
    exact(raw, ['mode']);
    return { mode: raw.mode };
  }
  exact(raw, ['mode', 'positive']);
  if (raw.mode !== 'staging-negative') fail();
  const p = raw.positive;
  exact(p, ['version', 'event', 'mode', 'host', 'port', 'observedAt', 'dns', 'targets', 'outcome']);
  exact(p.dns, ['a', 'aaaa']);
  if (p.version !== 1 || p.event !== EVENT || p.mode !== 'production-positive' || p.host !== HOST ||
      p.port !== PORT || p.outcome !== 'POSITIVE_CONFIRMED' || !dnsComplete(p.dns) ||
      !Number.isSafeInteger(p.observedAt) || p.observedAt > now || now - p.observedAt > MAX_AGE) fail();
  if (!Array.isArray(p.targets) || p.targets.length < 1 || p.targets.length > MAX_TARGETS) fail();
  const approved = targets(p.targets.map(row => {
    exact(row, ['address', 'family', 'outcome']);
    if (row.outcome !== 'CONNECTED') fail();
    return { address: row.address, family: row.family };
  }));
  for (const [key, family] of [['a', 4], ['aaaa', 6]]) {
    if ((p.dns[key] === 'RESOLVED') !== approved.some(row => row.family === family)) fail();
  }
  return { mode: raw.mode, approved };
}

// Uses system DNS, never Tailscale SOCKS or a caller-selected resolver/hostname.
// Both queries and cancellation have independent bounds; raw errors are discarded.
export function resolveTargets({ signal } = {}) {
  const resolver = new Resolver({ timeout: 2000, tries: 1 });
  return new Promise(resolve => {
    const statuses = { a: 'UNKNOWN', aaaa: 'UNKNOWN' };
    const found = []; let remaining = 2; let ended = false;
    const finish = () => {
      if (ended) return;
      ended = true; clearTimeout(timer); signal?.removeEventListener('abort', finish); resolver.cancel();
      resolve({ dns: statuses, targets: found });
    };
    const timer = setTimeout(finish, 3000);
    signal?.addEventListener('abort', finish, { once: true });
    if (signal?.aborted) { finish(); return; }
    for (const [method, key, family] of [['resolve4', 'a', 4], ['resolve6', 'aaaa', 6]]) {
      try {
        resolver[method](HOST, (error, addresses) => {
          if (ended) return;
          if (error) statuses[key] = ['ENODATA', 'ENOTFOUND'].includes(error.code) ? 'NOT_FOUND' : 'UNKNOWN';
          else if (Array.isArray(addresses) && addresses.length <= MAX_TARGETS) {
            statuses[key] = addresses.length ? 'RESOLVED' : 'EMPTY';
            for (const address of addresses) found.push({ address, family });
          }
          if (--remaining === 0) finish();
        });
      } catch { if (--remaining === 0) finish(); }
    }
  });
}

// TCP connect only: no writes, PostgreSQL StartupMessage, TLS handshake, or data listener.
// Tests can inject the socket constructor; production uses the built-in connector.
export function connectTarget(destination, { signal, connect = net.createConnection, timeoutMs = 5000 } = {}) {
  return new Promise(resolve => {
    let socket; let ended = false;
    const finish = outcome => {
      if (ended) return;
      ended = true; clearTimeout(timer); signal?.removeEventListener('abort', abort);
      socket?.destroy(); resolve(outcome);
    };
    const abort = () => finish('UNKNOWN');
    const timer = setTimeout(() => finish('TIMEOUT'), timeoutMs);
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) { abort(); return; }
    try {
      socket = connect({ host: destination.address, family: destination.family, port: PORT,
        autoSelectFamily: false });
      socket.once('connect', () => finish('CONNECTED'));
      socket.once('error', error => finish(error.code === 'ECONNREFUSED' ? 'REFUSED' :
        ['ENETUNREACH', 'EHOSTUNREACH', 'EACCES', 'EPERM'].includes(error.code) ? 'UNREACHABLE' : 'UNKNOWN'));
      socket.once('close', () => finish('UNKNOWN'));
    } catch { finish('UNKNOWN'); }
  });
}

export async function runProbe(raw, { identity = process, environment = process.env, now = Date.now,
  resolve = resolveTargets, connect = connectTarget, signal } = {}) {
  if ([identity.getuid(), identity.geteuid(), identity.getgid(), identity.getegid()].some(id => id !== 1000)) fail();
  if (!environment || Object.keys(environment).sort().join(',') !== Object.keys(ENVIRONMENT).sort().join(',') ||
      Object.keys(ENVIRONMENT).some(key => environment[key] !== ENVIRONMENT[key])) fail();
  const request = validateRequest(raw, now());
  const resolved = await resolve({ signal });
  exact(resolved, ['dns', 'targets']); exact(resolved.dns, ['a', 'aaaa']);
  if (Object.values(resolved.dns).some(value => !['RESOLVED', 'EMPTY', 'NOT_FOUND', 'UNKNOWN'].includes(value))) fail();
  if (!Array.isArray(resolved.targets) || resolved.targets.length > MAX_TARGETS) fail();
  const observed = resolved.targets.length ? targets(resolved.targets) : [];
  for (const [key, family] of [['a', 4], ['aaaa', 6]]) {
    if ((resolved.dns[key] === 'RESOLVED') !== observed.some(row => row.family === family)) fail();
  }
  const chosen = request.approved ?? observed;
  const rows = await Promise.all(chosen.map(async row => {
    const outcome = await connect(row, { signal });
    if (!['CONNECTED', 'TIMEOUT', 'REFUSED', 'UNREACHABLE', 'UNKNOWN'].includes(outcome)) fail();
    return { ...row, outcome };
  }));
  let outcome = 'UNKNOWN';
  if (request.mode === 'production-positive') {
    if (dnsComplete(resolved.dns) && rows.length && rows.every(row => row.outcome === 'CONNECTED')) outcome = 'POSITIVE_CONFIRMED';
  } else if (rows.some(row => row.outcome === 'CONNECTED')) outcome = 'REACHABLE';
  else if (dnsComplete(resolved.dns) && rows.length &&
      rows.every(row => ['TIMEOUT', 'REFUSED', 'UNREACHABLE'].includes(row.outcome)) &&
      observed.every(row => chosen.some(other => row.address === other.address && row.family === other.family))) {
    outcome = 'UNREACHABLE_OBSERVED';
  }
  if (signal?.aborted) outcome = 'UNKNOWN';
  const observedAt = now();
  if (!Number.isSafeInteger(observedAt) || observedAt < 0) fail();
  return { version: 1, event: EVENT, mode: request.mode, host: HOST, port: PORT, observedAt,
    dns: { a: resolved.dns.a, aaaa: resolved.dns.aaaa }, targets: rows, outcome };
}

// Called only by the reviewed generated `node -e` command. No auto-run on import.
export async function main(request) {
  const controller = new AbortController();
  const abort = () => controller.abort();
  process.once('SIGINT', abort); process.once('SIGTERM', abort);
  const timer = setTimeout(abort, 12_000);
  let report;
  try { report = await runProbe(request, { signal: controller.signal }); }
  catch { report = { version: 1, event: EVENT, outcome: 'UNKNOWN' }; }
  clearTimeout(timer); process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort);
  const code = ['POSITIVE_CONFIRMED', 'UNREACHABLE_OBSERVED'].includes(report.outcome) ? 0 :
    report.outcome === 'REACHABLE' ? 2 : 1;
  const last = setTimeout(() => process.exit(code), 1000);
  process.stdout.write(`${JSON.stringify(report)}\n`, () => { clearTimeout(last); process.exit(code); });
}
