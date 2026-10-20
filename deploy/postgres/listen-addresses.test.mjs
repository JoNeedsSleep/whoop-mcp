import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { ENVIRONMENT, guardSelector, selectListenAddresses } from './listen-addresses.mjs';

const fixture = () => ({
  lo: [
    { address: '127.0.0.1', family: 'IPv4', internal: true },
    { address: '::1', family: 'IPv6', internal: true },
  ],
  railnet0: [
    { address: '10.140.88.149', family: 'IPv4', internal: false },
    { address: 'fd12:2c32:c8ad:1:3000:b4:af0c:5895', family: 'IPv6', internal: false },
    { address: 'fe80::a0aa:afff:fe0c:5895', family: 'IPv6', internal: false },
  ],
});
const identity = { getuid: () => 999, geteuid: () => 999, getgid: () => 999, getegid: () => 999 };
const failure = error => error instanceof Error && error.message === 'POSTGRES_LISTENER_UNAVAILABLE';

test('only exact railnet0 private IPv4 and ULA addresses are selected, independent of ordering', () => {
  const expected = '10.140.88.149,fd12:2c32:c8ad:1:3000:b4:af0c:5895';
  assert.equal(selectListenAddresses(fixture()), expected);
  const reversed = fixture(); reversed.lo.reverse(); reversed.railnet0.reverse();
  assert.equal(selectListenAddresses(reversed), expected);
  assert(!expected.includes('fe80'));
});

test('valid local address changes are selected without DNS or fixed service-IP fallback', () => {
  for (const ipv4 of ['10.1.2.3', '172.16.2.3', '172.31.2.3', '192.168.2.3']) {
    const raw = fixture(); raw.railnet0[0].address = ipv4; raw.railnet0[1].address = 'fd12:3456::abcd';
    assert.equal(selectListenAddresses(raw), ipv4 + ',fd12:3456::abcd');
  }
});

test('unknown, missing or ambiguous interface layouts are rejected', () => {
  for (const mutate of [
    raw => { delete raw.railnet0; }, raw => { raw.eth0 = raw.railnet0; },
    raw => { raw.railnet1 = raw.railnet0; delete raw.railnet0; },
    raw => { raw.lo.push(raw.lo[0]); }, raw => { raw.railnet0.pop(); },
    raw => { raw.railnet0.push(raw.railnet0[0]); }, raw => { raw.railnet0[2] = raw.railnet0[0]; },
    raw => { raw.railnet0[0].internal = true; }, raw => { raw.lo[0].internal = false; },
    raw => { raw.lo[0].address = '127.0.0.2'; }, raw => { raw.lo[1] = raw.lo[0]; },
  ]) {
    const raw = fixture(); mutate(raw); assert.throws(() => selectListenAddresses(raw), failure);
  }
  for (const raw of [null, [], {}, Object.create(fixture())]) assert.throws(() => selectListenAddresses(raw), failure);
});

test('public, unspecified, mapped, link-local IPv4 and injected addresses cannot enter PG argv', () => {
  for (const ip of ['0.0.0.0', '*', '127.0.0.1', '169.254.169.254', '172.15.0.1', '172.32.0.1',
    '1.1.1.1', '224.0.0.1', '255.255.255.255', '010.0.0.1', 'db.railway.internal', '10.0.0.1,-c',
    "'; touch /tmp/sentinel; '", '10.0.0.1\n']) {
    const raw = fixture(); raw.railnet0[0].address = ip;
    assert.throws(() => selectListenAddresses(raw), failure);
  }
  for (const ip of ['::', '::1', '::ffff:10.1.2.3', '2001:db8::1', 'ff02::1',
    'fd12::1%railnet0', 'FD12::1', 'fd12:0:0:0:0:0:0:1', 'fe80::1']) {
    const raw = fixture(); raw.railnet0[1].address = ip;
    assert.throws(() => selectListenAddresses(raw), failure);
  }
});

test('invalid family, internal values and duplicate private address classes fail', () => {
  for (const patch of [{ family: 4 }, { family: 'IPv6' }, { internal: 'false' }, { address: ['10.1.2.3'] }]) {
    const raw = fixture(); Object.assign(raw.railnet0[0], patch);
    assert.throws(() => selectListenAddresses(raw), failure);
  }
  const duplicate = fixture(); duplicate.railnet0[2] = { ...duplicate.railnet0[1], address: 'fd12:3456::1' };
  assert.throws(() => selectListenAddresses(duplicate), failure);
});

test('identity and NNP checks precede environment values; only the fixed selector environment is accepted', () => {
  const secret = Object.defineProperty({}, 'SECRET', { enumerable: true, get() { assert.fail('secret read'); } });
  for (const name of Object.keys(identity)) assert.throws(() => guardSelector({
    identity: { ...identity, [name]: () => 0 }, environment: secret, guard() { assert.fail('kernel after wrong identity'); },
  }), failure);
  assert.throws(() => guardSelector({ identity, environment: secret, guard() { throw new Error('kernel blocked'); } }), /kernel blocked/);
  assert.throws(() => guardSelector({ identity, environment: secret, guard() {} }), failure);
  guardSelector({ identity, environment: { ...ENVIRONMENT }, guard() {} });
  for (const environment of [{ ...ENVIRONMENT, NODE_OPTIONS: '--import=/tmp/secret' },
    { ...ENVIRONMENT, PGOPTIONS: '-c listen_addresses=*' }, { ...ENVIRONMENT, PATH: '/tmp' },
    { ...ENVIRONMENT, UV_USE_IO_URING: '1' }]) assert.throws(() => guardSelector({ identity, environment, guard() {} }), failure);
});

test('actual child retains UID999 and kernel NNP while hostile pre-main options are stripped', async () => {
  const script = `const{guardSelector,selectListenAddresses}=await import(${JSON.stringify(new URL('./listen-addresses.mjs', import.meta.url).href)});guardSelector();process.stdout.write(selectListenAddresses(${JSON.stringify(fixture())}));`;
  const args = ['--no-new-privs', '--', '/usr/bin/env', '-i',
    ...Object.entries(ENVIRONMENT).map(([key, value]) => key + '=' + value),
    '/usr/local/bin/node', '--input-type=module', '-e', script];
  const result = await new Promise((resolve, reject) => {
    const child = spawn('/usr/bin/setpriv', args, { env: {
      PATH: '/usr/bin:/bin', NODE_OPTIONS: '--import=/tmp/SECRET_SENTINEL', OPENSSL_CONF: '/tmp/SECRET_SENTINEL',
    }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = ''; let stderr = '';
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Fixture deadline')); }, 5000);
    for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => {
      if (stream === child.stdout) stdout += chunk; else stderr += chunk;
      if (stdout.length + stderr.length > 4096) child.kill('SIGKILL');
    });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', code => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
  assert.equal(result.code, 0); assert.equal(result.stderr, '');
  assert.equal(result.stdout, '10.140.88.149,fd12:2c32:c8ad:1:3000:b4:af0c:5895');
});
