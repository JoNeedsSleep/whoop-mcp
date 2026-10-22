import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import { EventEmitter } from 'node:events';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { HOST, PORT, ENVIRONMENT, validateRequest, runProbe, connectTarget } from './probe.mjs';
import { buildCommand } from './command.mjs';

const NOW = 1_600_000_000_000;
const ID = { getuid: () => 1000, geteuid: () => 1000, getgid: () => 1000, getegid: () => 1000 };
const PAIR = [{ address: '10.22.33.44', family: 4 }, { address: 'fd12:3456::9', family: 6 }];
const resolution = () => ({ dns: { a: 'RESOLVED', aaaa: 'RESOLVED' }, targets: structuredClone(PAIR) });
const options = extra => ({ identity: ID, environment: { ...ENVIRONMENT }, now: () => NOW,
  resolve: async () => resolution(), connect: async () => 'CONNECTED', ...extra });
const positive = () => ({ version: 1, event: 'whoop-database-reachability', mode: 'production-positive',
  host: HOST, port: PORT, observedAt: NOW, dns: { a: 'RESOLVED', aaaa: 'RESOLVED' },
  targets: PAIR.map(row => ({ ...row, outcome: 'CONNECTED' })), outcome: 'POSITIVE_CONFIRMED' });

test('negative binds the exact successful fresh positive receipt; malformed, stale and public targets are rejected', () => {
  assert.deepEqual(validateRequest({ mode: 'production-positive' }, NOW), { mode: 'production-positive' });
  assert.deepEqual(validateRequest({ mode: 'staging-negative', positive: positive() }, NOW).approved, PAIR);
  const changes = [
    p => { p.host = 'other.railway.internal'; }, p => { p.port = 22; },
    p => { p.observedAt = NOW + 1; }, p => { p.observedAt = NOW - 900_001; },
    p => { p.targets[0].outcome = 'REFUSED'; }, p => { p.targets = []; },
    p => { p.targets.push(p.targets[0]); }, p => { p.targets[0].address = '169.254.169.254'; },
    p => { p.targets[0].address = '1.1.1.1'; }, p => { p.targets[1].address = '::ffff:127.0.0.1'; },
    p => { p.dns.aaaa = 'UNKNOWN'; }, p => { p.token = 'SECRET_SENTINEL'; },
  ];
  for (const mutate of changes) {
    const p = positive(); mutate(p);
    assert.throws(() => validateRequest({ mode: 'staging-negative', positive: p }, NOW), /NETWORK_PROBE_UNAVAILABLE/);
  }
});

test('identity and exact clean environment fail before DNS', async () => {
  let called = 0;
  const resolve = async () => { called++; return resolution(); };
  for (const identity of [{ ...ID, geteuid: () => 0 }, { ...ID, getegid: () => 0 }]) {
    await assert.rejects(runProbe({ mode: 'production-positive' }, options({ identity, resolve })), /NETWORK_PROBE_UNAVAILABLE/);
  }
  await assert.rejects(runProbe({ mode: 'production-positive' }, options({
    resolve, environment: { ...ENVIRONMENT, NODE_OPTIONS: '--import SECRET_SENTINEL' },
  })), /NETWORK_PROBE_UNAVAILABLE/);
  assert.equal(called, 0);
});

test('positive requires successful connections to every observed family and does not truncate DNS results', async () => {
  const seen = [];
  const report = await runProbe({ mode: 'production-positive' }, options({ connect: async row => {
    seen.push(row); return 'CONNECTED';
  } }));
  assert.equal(report.outcome, 'POSITIVE_CONFIRMED'); assert.deepEqual(seen, PAIR);
  assert.deepEqual(Object.keys(report).sort(), Object.keys(positive()).sort());
  const incomplete = await runProbe({ mode: 'production-positive' }, options({
    connect: async row => row.family === 4 ? 'CONNECTED' : 'TIMEOUT',
  }));
  assert.equal(incomplete.outcome, 'UNKNOWN');
  let connections = 0;
  for (const result of [
    { dns: { a: 'RESOLVED', aaaa: 'EMPTY' }, targets: Array.from({ length: 5 }, (_, i) => ({ address: `10.0.0.${i + 1}`, family: 4 })) },
    { dns: { a: 'RESOLVED', aaaa: 'EMPTY' }, targets: [{ address: '127.0.0.1', family: 4 }] },
    { dns: { a: 'SECRET_SENTINEL', aaaa: 'EMPTY' }, targets: [] },
  ]) {
    await assert.rejects(runProbe({ mode: 'production-positive' }, options({
      resolve: async () => result, connect: async () => { connections++; return 'CONNECTED'; },
    })), /NETWORK_PROBE_UNAVAILABLE/);
  }
  assert.equal(connections, 0);
});

test('negative still tests copied A/AAAA when DNS is isolated; any connection defeats isolation', async () => {
  const request = { mode: 'staging-negative', positive: positive() };
  const seen = [];
  const resolve = async () => ({ dns: { a: 'NOT_FOUND', aaaa: 'NOT_FOUND' }, targets: [] });
  const denied = await runProbe(request, options({ resolve, connect: async row => { seen.push(row); return 'UNREACHABLE'; } }));
  assert.deepEqual(seen, PAIR); assert.equal(denied.outcome, 'UNREACHABLE_OBSERVED');
  const reached = await runProbe(request, options({ resolve, connect: async row => row.family === 6 ? 'CONNECTED' : 'TIMEOUT' }));
  assert.equal(reached.outcome, 'REACHABLE');
});

test('unknown DNS, unknown socket failure, abort and DNS drift never become an isolation success', async () => {
  const request = { mode: 'staging-negative', positive: positive() };
  for (const extra of [
    { resolve: async () => ({ dns: { a: 'UNKNOWN', aaaa: 'NOT_FOUND' }, targets: [] }), connect: async () => 'TIMEOUT' },
    { connect: async () => 'UNKNOWN' },
    { resolve: async () => ({ dns: { a: 'RESOLVED', aaaa: 'EMPTY' }, targets: [{ address: '10.22.33.99', family: 4 }] }),
      connect: async () => 'REFUSED' },
    { signal: AbortSignal.abort(), connect: async () => 'UNREACHABLE' },
  ]) assert.equal((await runProbe(request, options(extra))).outcome, 'UNKNOWN');
});

test('socket timeout, cancellation and fixed errors destroy their connection without writing', async () => {
  for (const mode of ['timeout', 'abort', 'refused', 'unreachable', 'other']) {
    let destroyed = 0; let writes = 0;
    const socket = new EventEmitter();
    socket.destroy = () => { destroyed++; };
    socket.write = () => { writes++; throw new Error('No application data allowed'); };
    const controller = new AbortController();
    const outcome = connectTarget(PAIR[0], { timeoutMs: 15, signal: controller.signal, connect: settings => {
      assert.deepEqual(settings, { host: PAIR[0].address, family: 4, port: 5432, autoSelectFamily: false });
      queueMicrotask(() => {
        if (mode === 'abort') controller.abort();
        if (['refused', 'unreachable', 'other'].includes(mode)) {
          socket.emit('error', { code: { refused: 'ECONNREFUSED', unreachable: 'ENETUNREACH', other: 'SECRET_SENTINEL' }[mode] });
        }
      });
      return socket;
    } });
    assert.equal(await outcome, { timeout: 'TIMEOUT', abort: 'UNKNOWN', refused: 'REFUSED', unreachable: 'UNREACHABLE', other: 'UNKNOWN' }[mode]);
    assert.equal(destroyed, 1); assert.equal(writes, 0);
  }
});

test('actual loopback TCP success transmits zero application bytes, then closed port is refused', { timeout: 10_000 }, async () => {
  let received = 0; let accepted = 0; let acceptedResolve; let closedResolve;
  const acceptedPromise = new Promise(resolve => { acceptedResolve = resolve; });
  const closedPromise = new Promise(resolve => { closedResolve = resolve; });
  const server = net.createServer(socket => {
    accepted++;
    socket.on('data', chunk => { received += chunk.length; });
    socket.once('close', closedResolve);
    acceptedResolve();
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(PORT, '127.0.0.1', resolve); });
  try {
    assert.equal(await connectTarget({ address: '127.0.0.1', family: 4 }), 'CONNECTED');
    await acceptedPromise; await closedPromise;
    assert.equal(accepted, 1); assert.equal(received, 0);
  } finally { await new Promise(resolve => server.close(resolve)); }
  assert.equal(await connectTarget({ address: '127.0.0.1', family: 4 }), 'REFUSED');
});

function shell(command) {
  return new Promise((resolve, reject) => {
    const child = spawn('/bin/sh', ['-c', command], { env: {
      PATH: '/usr/local/bin:/usr/bin:/bin', NODE_OPTIONS: '--import=/tmp/NETWORK_PROBE_SECRET_SENTINEL',
      SSL_CERT_FILE: '/tmp/NETWORK_PROBE_SECRET_SENTINEL', OPENSSL_CONF: '/tmp/NETWORK_PROBE_SECRET_SENTINEL',
    }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = ''; let stderr = '';
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Fixture deadline')); }, 15_000);
    child.stdout.on('data', chunk => { stdout += chunk; if (stdout.length > 8192) child.kill('SIGKILL'); });
    child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 8192) child.kill('SIGKILL'); });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', code => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}

test('actual generated command clears hostile pre-main environment and emits only fixed UNKNOWN for stale input', async () => {
  const source = fs.readFileSync(new URL('./probe.mjs', import.meta.url), 'utf8');
  const digest = createHash('sha256').update(source).digest('hex');
  const request = { mode: 'staging-negative', positive: positive() };
  const command = buildCommand(source, digest, request, NOW);
  assert.ok(command.startsWith('/usr/bin/setpriv --no-new-privs -- /usr/bin/env -i '));
  assert.equal(/[\r\n]/.test(command), false);
  const encoded = command.match(/await import\("data:text\/javascript;base64,([A-Za-z0-9+/=]+)"\);/);
  assert.ok(encoded);
  assert.equal(Buffer.from(encoded[1], 'base64').toString('utf8'), `${source}\nawait main(${JSON.stringify(request)});\n`);
  // The synthetic receipt is old at actual execution, so no DNS/socket is admitted.
  const result = await shell(command);
  assert.equal(result.code, 1); assert.equal(result.stderr, '');
  assert.deepEqual(JSON.parse(result.stdout), { version: 1, event: 'whoop-database-reachability', outcome: 'UNKNOWN' });
  assert.throws(() => buildCommand(source, '0'.repeat(64), request, NOW), /NETWORK_PROBE_COMMAND_UNAVAILABLE/);
});

test('same fixed wrapper retains NNP and the exact environment in a child', async () => {
  const expression = `(async()=>{const fs=require("node:fs");const ok=fs.readFileSync("/proc/self/status","utf8").split(String.fromCharCode(10)).some(x=>x.startsWith("NoNewPrivs:")&&x.slice(11).trim()==="1");const{runProbe}=await import(${JSON.stringify(new URL('./probe.mjs', import.meta.url).href)});const report=await runProbe({mode:"production-positive"},{resolve:async()=>({dns:{a:"RESOLVED",aaaa:"EMPTY"},targets:[{address:"10.1.2.3",family:4}]}),connect:async()=>"CONNECTED"});process.stdout.write(JSON.stringify({ok,ids:[process.getuid(),process.geteuid(),process.getgid(),process.getegid()],environment:process.env,outcome:report.outcome}));})().catch(()=>process.exit(1));`;
  const result = await shell('/usr/bin/setpriv --no-new-privs -- /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp NODE_ENV=production UV_USE_IO_URING=0 /usr/local/bin/node -e ' +
    `'${expression.replaceAll("'", "'\\''")}'`);
  assert.equal(result.code, 0); assert.equal(result.stderr, '');
  const observed = JSON.parse(result.stdout);
  assert.equal(observed.ok, true); assert.deepEqual(observed.ids, [1000, 1000, 1000, 1000]);
  assert.deepEqual(observed.environment, ENVIRONMENT);
  assert.equal(observed.outcome, 'POSITIVE_CONFIRMED');
});
