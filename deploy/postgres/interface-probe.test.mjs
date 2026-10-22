import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { ENVIRONMENT, inspectNetwork, projectInterfaces } from './interface-probe.mjs';
import { buildCommand } from './interface-probe-command.mjs';

const ID = { getuid: () => 999, geteuid: () => 999, getgid: () => 999, getegid: () => 999 };
const local = () => ({
  lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true, mac: 'SECRET_MAC', netmask: 'SECRET_NETMASK', cidr: 'SECRET_CIDR' }],
  eth0: [{ address: '10.1.2.3', family: 'IPv4', internal: false },
    { address: 'fd12:3456::1', family: 'IPv6', internal: false },
    { address: 'fe80::1', family: 'IPv6', internal: false }],
});
const resolution = () => ({ dns: { a: 'RESOLVED', aaaa: 'RESOLVED' },
  addresses: [{ address: '10.1.2.3', family: 4 }, { address: 'fd12:9999::1', family: 6 }] });
const options = extra => ({ identity: ID, environment: { ...ENVIRONMENT },
  interfaces: local, resolve: async () => resolution(), now: () => 1234, ...extra });

test('interface projection reconstructs only bounded names, addresses and fixed classification', () => {
  const rows = projectInterfaces(local());
  assert.deepEqual(rows.map(row => row.name), ['eth0', 'lo']);
  assert.deepEqual(rows[0].addresses.map(row => row.scope), ['PRIVATE', 'PRIVATE', 'LINK_LOCAL']);
  assert.equal(rows[1].addresses[0].scope, 'LOOPBACK');
  assert(!JSON.stringify(rows).includes('SECRET'));
  assert.deepEqual(Object.keys(rows[0]).sort(), ['addresses', 'name']);
  assert.deepEqual(Object.keys(rows[0].addresses[0]).sort(), ['address', 'family', 'internal', 'scope']);
  const others = projectInterfaces({ eth0: [
    { address: '0.0.0.0', family: 'IPv4', internal: false },
    { address: '1.1.1.1', family: 'IPv4', internal: false },
    { address: '::ffff:127.0.0.1', family: 'IPv6', internal: false },
  ] });
  assert.deepEqual(others[0].addresses.map(row => row.scope), ['UNSPECIFIED', 'OTHER', 'MAPPED']);
});

test('unexpected interface names, addresses, family, metadata and excess cardinality fail closed', () => {
  const row = { address: '10.1.2.3', family: 'IPv4', internal: false };
  for (const input of [
    {}, [], { 'bad\nname': [row] }, { ['a'.repeat(16)]: [row] }, { eth0: [] }, { eth0: [row, row] },
    { eth0: [{ ...row, address: 'hostname.example' }] }, { eth0: [{ ...row, family: 'IPv6' }] },
    { eth0: [{ ...row, internal: 'false' }] }, { eth0: [{ address: 'fe80::1%eth0', family: 'IPv6', internal: false }] },
    Object.fromEntries(Array.from({ length: 9 }, (_, n) => ['eth' + n, [row]])),
    { eth0: Array.from({ length: 17 }, (_, n) => ({ ...row, address: '10.0.0.' + (n + 1) })) },
  ]) assert.throws(() => projectInterfaces(input), /POSTGRES_NETWORK_METADATA_UNAVAILABLE/);
});

test('UID and exact clean environment checks precede interface or DNS access', async () => {
  let reads = 0;
  const interfaces = () => { reads++; return local(); };
  const resolve = async () => { reads++; return resolution(); };
  for (const name of Object.keys(ID)) await assert.rejects(inspectNetwork(options({
    identity: { ...ID, [name]: () => 0 }, interfaces, resolve,
  })), /POSTGRES_NETWORK_METADATA_UNAVAILABLE/);
  const environment = Object.defineProperty({ ...ENVIRONMENT }, 'SECRET', {
    enumerable: true, get() { assert.fail('secret read'); },
  });
  await assert.rejects(inspectNetwork(options({ environment, interfaces, resolve })), /POSTGRES_NETWORK_METADATA_UNAVAILABLE/);
  assert.equal(reads, 0);
});

test('DNS and local addresses stay distinct and match only exact normalized addresses', async () => {
  const report = await inspectNetwork(options());
  assert.equal(report.outcome, 'COMPLETE');
  assert.deepEqual(report.dnsAddresses[0].localInterfaces, ['eth0']);
  assert.deepEqual(report.dnsAddresses[1].localInterfaces, []);
  assert.deepEqual(Object.keys(report).sort(),
    ['version', 'event', 'host', 'observedAt', 'dns', 'dnsAddresses', 'interfaces', 'outcome'].sort());
  assert(!JSON.stringify(report).includes('SECRET'));
  const both = local(); both.eth1 = [{ address: '10.1.2.3', family: 'IPv4', internal: false }];
  const ambiguous = await inspectNetwork(options({ interfaces: () => both }));
  assert.deepEqual(ambiguous.dnsAddresses[0].localInterfaces, ['eth0', 'eth1']);
  // The diagnostic reports ambiguity; it never selects an address or starts PG.
});

test('failed or cancelled DNS remains unknown, malformed and excessive results never truncate', async () => {
  const unavailable = await inspectNetwork(options({ resolve: async () =>
    ({ dns: { a: 'UNKNOWN', aaaa: 'NOT_FOUND' }, addresses: [] }) }));
  assert.equal(unavailable.outcome, 'UNKNOWN'); assert.equal(unavailable.interfaces.length, 2);
  assert.equal((await inspectNetwork(options({ signal: AbortSignal.abort() }))).outcome, 'UNKNOWN');
  for (const resolved of [
    { dns: { a: 'SECRET', aaaa: 'NOT_FOUND' }, addresses: [] },
    { dns: { a: 'RESOLVED', aaaa: 'NOT_FOUND' }, addresses: [] },
    { dns: { a: 'RESOLVED', aaaa: 'NOT_FOUND' }, addresses: [{ address: 'bad', family: 4 }] },
    { dns: { a: 'RESOLVED', aaaa: 'NOT_FOUND' }, addresses: Array.from({ length: 9 }, (_, n) => ({ address: '10.0.0.' + n, family: 4 })) },
  ]) await assert.rejects(inspectNetwork(options({ resolve: async () => resolved })), /POSTGRES_NETWORK_METADATA_UNAVAILABLE/);
});

function shell(command) {
  return new Promise((resolve, reject) => {
    const child = spawn('/bin/sh', ['-c', command], { env: { PATH: '/usr/local/bin:/usr/bin:/bin',
      NODE_OPTIONS: '--import=/tmp/SECRET_SENTINEL', OPENSSL_CONF: '/tmp/SECRET_SENTINEL' },
      stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = ''; let stderr = '';
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Fixture deadline')); }, 8000);
    for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => {
      if (stream === child.stdout) stdout += chunk; else stderr += chunk;
      if (stdout.length + stderr.length > 16384) child.kill('SIGKILL');
    });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', code => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}

test('single-line public command preserves exact pinned source and rejects mismatched hash', () => {
  const source = fs.readFileSync(new URL('./interface-probe.mjs', import.meta.url), 'utf8');
  const digest = createHash('sha256').update(source).digest('hex');
  const command = buildCommand(source, digest);
  assert(!/[\r\n]/.test(command));
  assert(command.startsWith('/usr/bin/setpriv --no-new-privs -- /usr/bin/env -i '));
  const encoded = command.match(/await import\("data:text\/javascript;base64,([A-Za-z0-9+/=]+)"\);/);
  assert(encoded);
  assert.equal(Buffer.from(encoded[1], 'base64').toString('utf8'), source + '\nawait main();\n');
  assert.throws(() => buildCommand(source, '0'.repeat(64)), /POSTGRES_NETWORK_COMMAND_UNAVAILABLE/);
});

test('actual fixed wrapper clears hostile pre-main env and retains UID999/NNP before metadata', async () => {
  const expression = `(async()=>{const fs=require("node:fs");const nnp=fs.readFileSync("/proc/self/status","utf8").split(String.fromCharCode(10)).some(x=>x.startsWith("NoNewPrivs:")&&x.slice(11).trim()==="1");const{inspectNetwork}=await import(${JSON.stringify(new URL('./interface-probe.mjs', import.meta.url).href)});const report=await inspectNetwork({interfaces:()=>({lo:[{address:"127.0.0.1",family:"IPv4",internal:true}]}),resolve:async()=>({dns:{a:"NOT_FOUND",aaaa:"NOT_FOUND"},addresses:[]})});process.stdout.write(JSON.stringify({nnp,ids:[process.getuid(),process.geteuid(),process.getgid(),process.getegid()],environment:process.env,report}));})().catch(()=>process.exit(1));`;
  const command = '/usr/bin/setpriv --no-new-privs -- /usr/bin/env -i ' +
    'PATH=/usr/local/bin:/usr/lib/postgresql/17/bin:/usr/bin:/bin HOME=/tmp LANG=C UV_USE_IO_URING=0 ' +
    `/usr/local/bin/node -e '${expression.replaceAll("'", "'\\''")}'`;
  const result = await shell(command);
  assert.equal(result.code, 0); assert.equal(result.stderr, '');
  const observed = JSON.parse(result.stdout);
  assert.equal(observed.nnp, true); assert.deepEqual(observed.ids, [999, 999, 999, 999]);
  assert.deepEqual(observed.environment, ENVIRONMENT); assert.equal(observed.report.outcome, 'UNKNOWN');
});

test('actual generated command reports bounded local metadata in the offline fixture', async () => {
  const source = fs.readFileSync(new URL('./interface-probe.mjs', import.meta.url), 'utf8');
  const result = await shell(buildCommand(source, createHash('sha256').update(source).digest('hex')));
  assert.equal(result.code, 1); assert.equal(result.stderr, '');
  const report = JSON.parse(result.stdout);
  assert.equal(report.event, 'whoop-postgres-network-metadata');
  assert.equal(report.host, 'whoopindividualpostgreskill-2026.railway.internal');
  assert.equal(report.outcome, 'UNKNOWN');
  assert(report.interfaces.length >= 1 && report.interfaces.length <= 8);
  assert(report.interfaces.flatMap(row => row.addresses).length <= 16);
  assert(!result.stdout.includes('SECRET_SENTINEL'));
  assert(!result.stdout.includes('"mac"')); assert(!result.stdout.includes('NODE_OPTIONS'));
});
