import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { guardInvocation, parseEnvelope, parseState, validateTls } from './provision.mjs';

const identity = (uid = 999) => ({ getuid: () => uid, getgid: () => uid, geteuid: () => uid, getegid: () => uid });
const environment = { PATH: '/usr/local/bin:/usr/lib/postgresql/17/bin:/usr/bin:/bin', HOME: '/tmp', TMPDIR: '/tmp', LANG: 'C' };
const failure = error => error instanceof Error && error.message === 'POSTGRES_PROVISION_UNAVAILABLE';
const tlsDir = process.env.GATEWAY_TEST_TLS_DIR;
const fixture = () => ({ version: 1, host: 'whoop-db.railway.internal',
  caCertificate: fs.readFileSync(tlsDir + '/ca.pem', 'utf8'),
  serverCertificate: fs.readFileSync(tlsDir + '/server.pem', 'utf8'), serverKey: fs.readFileSync(tlsDir + '/server-key.pem', 'utf8'),
  runtimePassword: 'a'.repeat(64), migrationPassword: 'b'.repeat(64) });

test('identity and kernel checks precede any environment value access', () => {
  const env = Object.defineProperty({}, 'SECRET', { enumerable: true, get() { assert.fail('read secret'); } });
  assert.throws(() => guardInvocation('configure', { identity: identity(0), environment: env, guard() { assert.fail('kernel after wrong identity'); } }), failure);
  assert.throws(() => guardInvocation('configure', { identity: identity(), environment: env, guard() { throw new Error('kernel blocked'); } }), /kernel blocked/);
  assert.throws(() => guardInvocation('configure', { identity: identity(), environment: env, guard() {} }), failure);
});
test('only explicit root init and nonroot remaining phases with cleared environment', () => {
  guardInvocation('init', { identity: identity(0), environment, guard() {} });
  for (const phase of ['configure', 'enable', 'finalize']) guardInvocation(phase, { identity: identity(), environment, guard() {} });
  for (const phase of ['init', 'start', 'migrate', '', null]) assert.throws(() => guardInvocation(phase, { identity: identity(), environment, guard() {} }), failure);
  for (const key of ['NODE_OPTIONS', 'POSTGRES_PASSWORD', 'WHOOP_STAGING_BOOTSTRAP', 'PGPASSWORD', 'HTTP_PROXY'])
    assert.throws(() => guardInvocation('configure', { identity: identity(), environment: { ...environment, [key]: 'sentinel' }, guard() {} }), failure);
  guardInvocation('configure', { identity: identity(), environment: { ...environment, UV_USE_IO_URING: '0' }, guard() {} });
  assert.throws(() => guardInvocation('configure', { identity: identity(), environment: { ...environment, UV_USE_IO_URING: '1' }, guard() {} }), failure);
});
test('effective identity mismatch and wrong fixed environment values fail', () => {
  for (const field of ['getuid', 'getgid', 'geteuid', 'getegid'])
    assert.throws(() => guardInvocation('configure', { identity: { ...identity(), [field]: () => 0 }, environment, guard() {} }), failure);
  assert.throws(() => guardInvocation('configure', { identity: identity(), environment: { ...environment, PATH: '/tmp' }, guard() {} }), failure);
});
test('state parser recreates only exact phase metadata', () => {
  const initial = { version: 1, phase: 'initialized', host: null };
  assert.deepEqual(parseState(initial), initial); assert.notEqual(parseState(initial), initial);
  for (const phase of ['configuring', 'configured', 'enabling', 'enabled', 'finalizing', 'finalized'])
    assert.deepEqual(parseState({ version: 1, phase, host: 'whoop-db.railway.internal' }), { version: 1, phase, host: 'whoop-db.railway.internal' });
  for (const raw of [{ ...initial, secret: 'sentinel' }, { ...initial, phase: 'ready' }, { ...initial, host: 'localhost' },
    { version: 1, phase: 'configured', host: 'public.example' }, { version: 1, phase: 'configured', host: null }])
    assert.throws(() => parseState(raw), failure);
});
test('synthetic exact private SAN and matching CA/key validate before secret writes', () => {
  assert(tlsDir, 'Synthetic certificate fixture is required');
  const raw = fixture(); const parsed = parseEnvelope(raw);
  assert.deepEqual(parsed, raw); assert.notEqual(parsed, raw);
  assert.deepEqual(validateTls(raw.host, raw.caCertificate, raw.serverCertificate, raw.serverKey),
    { host: raw.host, caCertificate: raw.caCertificate, serverCertificate: raw.serverCertificate, serverKey: raw.serverKey });
});
test('unknown fields, weak/coercible/equal passwords and invalid host fail', () => {
  const raw = fixture();
  for (const bad of [{ ...raw, sql: 'SELECT 1' }, { ...raw, runtimePassword: [raw.runtimePassword] },
    { ...raw, migrationPassword: raw.runtimePassword }, { ...raw, migrationPassword: 'short' },
    { ...raw, runtimePassword: "x';ALTER ROLE whoop_runtime SUPERUSER;--" }, { ...raw, host: 'host.example' },
    { ...raw, host: '*.railway.internal' }, { ...raw, host: 'host.other.railway.internal' }])
    assert.throws(() => parseEnvelope(bad), failure);
});
test('wrong CA/host, CA-as-leaf, expired certificates and extra PEM content fail', () => {
  const raw = fixture();
  for (const bad of [{ ...raw, caCertificate: fs.readFileSync(tlsDir + '/wrong-ca.pem', 'utf8') },
    { ...raw, host: 'other.railway.internal' }, { ...raw, serverCertificate: raw.caCertificate },
    { ...raw, serverCertificate: raw.serverCertificate + raw.caCertificate }, { ...raw, serverKey: raw.serverKey + 'sentinel' }])
    assert.throws(() => parseEnvelope(bad), failure);
  assert.throws(() => parseEnvelope(raw, Date.now() + 7 * 86400000), failure);
  assert.throws(() => parseEnvelope(raw, 1), failure);
});
