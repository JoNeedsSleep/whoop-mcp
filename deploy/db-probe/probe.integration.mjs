// Disposable synthetic PostgreSQL fixture only; never a live operator command.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import pg from 'pg';
import { runProbe } from './probe.mjs';

const config = { host: 'whoop-db.railway.internal', port: 5432, database: 'whoop',
  user: 'whoop_runtime', password: 'a'.repeat(64),
  caCertificate: fs.readFileSync('/work/test-tls/ca.pem', 'utf8') };
const modes = ['valid', 'deny', 'tls-negative', 'plaintext'];
const mode = process.argv[2];
const result = { version: 1, event: 'whoop-runtime-database-probe', passed: true, crudPrivileges: 24 };
const rejected = value => assert.rejects(value, /^Error: DATABASE_PROBE_UNAVAILABLE$/);
try {
  assert.equal(process.getuid(), 1000); assert.equal(process.getgid(), 1000);
  assert(modes.includes(mode));
  if (mode === 'valid') {
    // Exercise the actual default pg.Pool factory, hostname lookup and verifier.
    assert.deepEqual(await runProbe({ config }), result);
  } else if (mode === 'deny' || mode === 'plaintext') {
    await rejected(runProbe({ config }));
  } else {
    for (const [kind, changes, expected] of [
      ['ca', { caCertificate: fs.readFileSync('/work/test-tls/wrong-ca.pem', 'utf8') },
        ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'SELF_SIGNED_CERT_IN_CHAIN']],
      ['san', { host: 'wrong.railway.internal' }, ['ERR_TLS_CERT_ALTNAME_INVALID']],
    ]) {
      let observed; let called = false;
      await rejected(runProbe({ config: { ...config, ...changes }, createPool: async options => {
        // Only fixture TCP routing changes for the wrong-SAN case. The production
        // CA, rejectUnauthorized and configured-host certificate checks remain.
        if (kind === 'san') options.host = '127.0.0.1';
        const pool = new pg.Pool(options); const connect = pool.connect.bind(pool);
        pool.connect = async () => {
          called = true;
          try { return await connect(); } catch (error) { observed = error.code; throw error; }
        };
        return pool;
      } }));
      assert(called); assert(expected.includes(observed));
    }
    assert.deepEqual(await runProbe({ config }), result);
  }
  console.log(JSON.stringify({ mode, passed: true }));
} catch {
  console.error(JSON.stringify({ mode: modes.includes(mode) ? mode : 'invalid', passed: false }));
  process.exitCode = 1;
}
