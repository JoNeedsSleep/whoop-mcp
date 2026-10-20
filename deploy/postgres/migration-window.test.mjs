import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { HARD_STOP, ORIGINAL_EXPIRY_CEILING, parseArguments, buildSql, validateReport } from './migration-window.mjs';

const OLD = '2026-10-20T03:32:01.123456Z';
const NOW = '2026-10-20T05:00:00.123456Z';
const NEW = '2026-10-20T06:00:00.123450Z';
const report = (operation = 'inspect') => ({
  version: 1, event: 'whoop-migration-window', operation,
  previousValidUntil: OLD, validUntil: operation === 'inspect' ? OLD : NEW,
  observedAt: NOW, hardStop: HARD_STOP,
});
const unavailable = /MIGRATION_WINDOW_UNAVAILABLE/;

test('only fixed operations and an exact microsecond UTC expiry are accepted', () => {
  assert.deepEqual(parseArguments(['inspect']), { operation: 'inspect', expectedExpiry: null });
  assert.deepEqual(parseArguments(['renew', OLD]), { operation: 'renew', expectedExpiry: OLD });
  for (const args of [[], ['inspect', OLD], ['enable'], ['renew'], ['renew', OLD, 'extra'],
    ['renew', "2026-10-20T03:32:01.123456Z';ALTER ROLE other SUPERUSER;--"],
    ['renew', 'infinity'], ['renew', '2026-02-30T03:32:01.123456Z'],
    ['renew', '2026-10-20T24:00:00.123456Z'], ['renew', '2026-10-20T03:32:01.123Z'],
    ['renew', '2026-10-20T03:32:01.123456+00:00'], ['renew', NEW], ['renew', null]]) {
    assert.throws(() => parseArguments(args), unavailable);
  }
});

test('inspection is a read-only transaction and never alters any role or grants', () => {
  const sql = buildSql(['inspect']);
  assert.match(sql, /BEGIN READ ONLY;/);
  assert.doesNotMatch(sql, /\b(?:ALTER|GRANT|REVOKE|CREATE|DROP|INSERT|UPDATE|DELETE)\s+(?:ROLE|TABLE|SCHEMA|DATABASE|ON|INTO|FROM)/);
  assert.match(sql, /rolpassword LIKE 'SCRAM-SHA-256\$%'/); // Internal boolean check only.
  const output = sql.slice(sql.indexOf('SELECT json_build_object'));
  assert.doesNotMatch(output, /rolpassword/);
  assert.match(sql, /pg_stat_activity/);
  assert.match(sql, /pg_class/);
  assert.match(sql, /pg_proc/);
  assert.match(sql, /pg_type/);
});

test('renewal changes only the fixed role expiry, with old-value guard and one-hour/hard-stop caps', () => {
  const sql = buildSql(['renew', OLD]);
  assert.equal((sql.match(/ALTER ROLE/g) ?? []).length, 1);
  assert.match(sql, /ALTER ROLE whoop_migrate VALID UNTIL %L/);
  assert(sql.includes(`rolvaliduntil = TIMESTAMPTZ '${OLD}'`));
  assert(sql.includes(`rolvaliduntil <= TIMESTAMPTZ '${ORIGINAL_EXPIRY_CEILING}'`));
  assert(sql.includes(`clock_timestamp() < TIMESTAMPTZ '${ORIGINAL_EXPIRY_CEILING}'`));
  assert(sql.includes(`least(clock_timestamp() + interval '1 hour', TIMESTAMPTZ '${HARD_STOP}')`));
  assert.doesNotMatch(sql, /ALTER ROLE whoop_migrate (?:LOGIN|PASSWORD|SUPERUSER|CREATEDB|CREATEROLE)/);
  assert.doesNotMatch(sql, /^\s*(?:GRANT|REVOKE|CREATE|DROP|INSERT|UPDATE|DELETE)\b/m);
  assert.match(sql, /SET LOCAL statement_timeout = '10s'/);
  assert.match(sql, /SET LOCAL lock_timeout = '3s'/);
});

test('validated output contains only exact reconstructed expiry metadata', () => {
  for (const operation of ['inspect','renew']) {
    const args = operation === 'inspect' ? ['inspect'] : ['renew', OLD];
    assert.deepEqual(validateReport(JSON.stringify(report(operation)), args), report(operation));
    for (const patch of [{ password: 'SECRET' }, { event: 'other' }, { version: '1' },
      { operation: 'enable' }, { hardStop: 'infinity' }, { validUntil: 'infinity' },
      { previousValidUntil: '2026-10-20T05:00:01.123456Z' }]) {
      assert.throws(() => validateReport(JSON.stringify({ ...report(operation), ...patch }), args), unavailable);
    }
  }
  // Inspection can report a successful renewal immediately, including after an
  // uncertain client result; the returned future expiry cannot be renewed again.
  const renewed = { ...report(), previousValidUntil: NEW, validUntil: NEW };
  assert.deepEqual(validateReport(JSON.stringify(renewed), ['inspect']), renewed);
  assert.throws(() => parseArguments(['renew', renewed.validUntil]), unavailable);
  assert.throws(() => validateReport('x'.repeat(2049), ['inspect']), unavailable);
});

test('renewal metadata refuses stale comparisons, excessive durations and hard-stop overflow', () => {
  for (const patch of [
    { previousValidUntil: '2026-10-20T03:32:01.123457Z' },
    { validUntil: NOW }, { validUntil: '2026-10-20T06:00:01.123456Z' },
    { observedAt: HARD_STOP }, { validUntil: '2026-10-21T01:16:00.000001Z' },
    { observedAt: '2026-10-20T04:48:59.999999Z' },
  ]) assert.throws(() => validateReport(JSON.stringify({ ...report('renew'), ...patch }), ['renew', OLD]), unavailable);
  const capped = { ...report('renew'), observedAt: '2026-10-21T01:00:00.000000Z', validUntil: HARD_STOP };
  assert.deepEqual(validateReport(JSON.stringify(capped), ['renew', OLD]), capped);
  assert.throws(() => validateReport(JSON.stringify({ ...report(), validUntil: NEW }), ['inspect']), unavailable);
});

function child(binary, args, environment) {
  return new Promise((resolve, reject) => {
    const proc = spawn(binary, args, { env: environment, stdio: ['ignore','pipe','pipe'] });
    let stdout = ''; let stderr = '';
    const timer = setTimeout(() => { proc.kill('SIGKILL'); reject(new Error('Fixture timeout')); }, 5000);
    for (const stream of [proc.stdout,proc.stderr]) stream.on('data', data => {
      if (stream === proc.stdout) stdout += data; else stderr += data;
      if (stdout.length + stderr.length > 4096) proc.kill('SIGKILL');
    });
    proc.once('error', error => { clearTimeout(timer); reject(error); });
    proc.once('close', code => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}

test('actual fixed shell refuses bootstrap presence and unknown operations before Node', async () => {
  const shell = fileURLToPath(new URL('./migration-window-entrypoint.sh', import.meta.url));
  for (const [args, extra] of [[[], {}], [['unknown'], {}], [['inspect', OLD], {}],
    [['inspect'], { WHOOP_POSTGRES_PROVISION: '' }], [['renew', OLD], { WHOOP_MIGRATION_BOOTSTRAP: 'SECRET' }],
    [['inspect'], { PGPASSWORD: 'SECRET' }]]) {
    const result = await child('/bin/sh', [shell, ...args], {
      PATH: '/usr/bin:/bin', NODE_OPTIONS: '--import=/tmp/SECRET_SENTINEL', ...extra,
    });
    assert.deepEqual(result, { code: 1, stdout: '', stderr: 'Migration window unavailable.\n' });
  }
});

test('cleared actual Node process rejects bad operation before fixed volume access', async () => {
  const expression = `const{runWindow}=await import(${JSON.stringify(new URL('./migration-window.mjs', import.meta.url).href)});
try{await runWindow(['other']);process.exit(2)}catch(e){if(e.message!=='MIGRATION_WINDOW_UNAVAILABLE')throw e;process.stdout.write('GUARD_PASSED');}`;
  const result = await child('/usr/bin/setpriv', ['--no-new-privs','--','/usr/bin/env','-i',
    'PATH=/usr/local/bin:/usr/lib/postgresql/17/bin:/usr/bin:/bin','HOME=/tmp','TMPDIR=/tmp','LANG=C','UV_USE_IO_URING=0',
    '/usr/local/bin/node','--input-type=module','-e',expression], {
    PATH: '/usr/bin:/bin', NODE_OPTIONS: '--import=/tmp/SECRET_SENTINEL', OPENSSL_CONF: '/tmp/SECRET_SENTINEL',
  });
  assert.deepEqual(result, { code: 0, stdout: 'GUARD_PASSED', stderr: '' });
  // The operation never writes the phase marker; existing finalize remains valid.
  const source = fs.readFileSync(new URL('./migration-window.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /stateWrite|renameSync/);
});
