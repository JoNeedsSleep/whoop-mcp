// Credentials live only in the private auth volume. Readers mount cache volumes
// only. A separate SQLite writer lock permits durable admission/token commits
// while excluding other cooperating processes throughout an asynchronous job.
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { MAX_CACHE_BYTES } from '../../restricted-local/cache.mjs';

export const AUTHORIZATION_TTL_MS = 7 * 86400000;
export const SYNC_INTERVAL_MS = 15 * 60000;
export const DEFAULT_CACHE_PATHS = Object.freeze({ codex: '/cache-codex/cache.json', 'claude-code': '/cache-claude/cache.json' });
const failure = () => new Error('LOCAL_SYNC_UNAVAILABLE');
const invalid = () => { throw failure(); };
const integer = n => Number.isSafeInteger(n) && n >= 0 && !Object.is(n, -0);
const plain = v => v !== null && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype;
function exact(value, keys) { if (!plain(value) || Reflect.ownKeys(value).length !== keys.length || keys.some(k => !Object.hasOwn(value, k))) invalid(); }
function text(value, max) { if (typeof value !== 'string' || value.length > max || !/^[\x21-\x7e]+$/.test(value)) invalid(); return value; }
function privateDirectory(directory) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || path.normalize(directory) !== directory || directory.includes('\0')) invalid();
  const st = fs.lstatSync(directory);
  if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== process.getuid() || st.gid !== process.getgid() || (st.mode & 0o7777) !== 0o700) invalid();
}
function privateFile(st, max) {
  if (!st.isFile() || st.nlink !== 1 || st.uid !== process.getuid() || st.gid !== process.getgid() || (st.mode & 0o7777) !== 0o600 || st.size > max) invalid();
}
function syncDirectory(directory) {
  const fd = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function openDatabase(filename) {
  const fd = fs.openSync(filename, fs.constants.O_CREAT | fs.constants.O_RDWR | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o600);
  try { privateFile(fs.fstatSync(fd), 1048576); } finally { fs.closeSync(fd); }
  const db = new DatabaseSync(filename);
  try { db.exec('PRAGMA busy_timeout=0; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA trusted_schema=OFF;'); return db; }
  catch (error) { db.close(); throw error; }
}
export function validateGrant(raw) {
  try {
    exact(raw, ['clientId', 'clientSecret', 'userId', 'accessToken', 'refreshToken', 'accessExpiresAt', 'authorizedAt', 'authorizationExpiresAt']);
    const value = { clientId: text(raw.clientId, 2048), clientSecret: text(raw.clientSecret, 2048), userId: raw.userId,
      accessToken: text(raw.accessToken, 4096), refreshToken: text(raw.refreshToken, 4096),
      accessExpiresAt: raw.accessExpiresAt, authorizedAt: raw.authorizedAt, authorizationExpiresAt: raw.authorizationExpiresAt };
    if (typeof value.userId !== 'string' || !/^[1-9][0-9]{0,15}$/.test(value.userId) || !Number.isSafeInteger(Number(value.userId)) || String(Number(value.userId)) !== value.userId ||
        ![value.accessExpiresAt, value.authorizedAt, value.authorizationExpiresAt].every(integer) ||
        value.authorizationExpiresAt !== value.authorizedAt + AUTHORIZATION_TTL_MS || value.accessExpiresAt <= value.authorizedAt) invalid();
    return value;
  } catch { throw failure(); }
}
function parseState(raw) {
  exact(raw, ['version', 'generation', 'phase', 'grant', 'lastAttemptAt', 'lastSeenAt']);
  if (raw.version !== 1 || !['empty', 'active', 'refreshing', 'reauthorize'].includes(raw.phase) ||
      (raw.generation !== null && (typeof raw.generation !== 'string' || !/^[a-f0-9]{32}$/.test(raw.generation))) ||
      [raw.lastAttemptAt, raw.lastSeenAt].some(v => v !== null && !integer(v))) invalid();
  const grant = raw.grant === null ? null : validateGrant(raw.grant);
  if ((['active', 'refreshing'].includes(raw.phase)) !== (grant !== null) || (grant && !raw.generation)) invalid();
  return { ...raw, grant };
}
function caches(paths) {
  exact(paths, ['codex', 'claude-code']);
  const values = Object.values(paths);
  if (new Set(values).size !== 2 || new Set(values.map(v => typeof v === 'string' ? path.dirname(v) : '')).size !== 2) invalid();
  for (const filename of values) {
    if (typeof filename !== 'string' || !path.isAbsolute(filename) || path.normalize(filename) !== filename || path.basename(filename) !== 'cache.json') invalid();
    privateDirectory(path.dirname(filename));
  }
  return { ...paths };
}
function removeCaches(paths) {
  // Validate both before removing either. Never follow a substituted link/FIFO.
  const present = [];
  for (const filename of Object.values(paths)) {
    privateDirectory(path.dirname(filename));
    try { privateFile(fs.lstatSync(filename), MAX_CACHE_BYTES); present.push(filename); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  for (const filename of present) { fs.unlinkSync(filename); syncDirectory(path.dirname(filename)); }
}

export async function withLockedState(action, { authDir = '/auth', cachePaths = DEFAULT_CACHE_PATHS, now = Date.now } = {}) {
  let lock; let db; let locked = false; let open = true;
  try {
    if (typeof action !== 'function' || typeof now !== 'function') invalid();
    privateDirectory(authDir); const paths = caches(cachePaths);
    if (Object.values(paths).some(filename => path.dirname(filename) === authDir)) invalid();
    lock = openDatabase(path.join(authDir, 'writer.sqlite'));
    lock.exec('CREATE TABLE IF NOT EXISTS writer(id INTEGER PRIMARY KEY CHECK(id=1));');
    try { lock.exec('BEGIN IMMEDIATE'); locked = true; }
    catch (error) { if (error?.errcode === 5 || error?.errcode === 6 || /locked|busy/i.test(error?.message ?? '')) throw new Error('LOCAL_SYNC_BUSY'); throw error; }
    db = openDatabase(path.join(authDir, 'state.sqlite'));
    db.exec('CREATE TABLE IF NOT EXISTS durable_state(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL);');
    const empty = { version: 1, generation: null, phase: 'empty', grant: null, lastAttemptAt: null, lastSeenAt: null };
    db.prepare('INSERT OR IGNORE INTO durable_state(id,value) VALUES(1,?)').run(JSON.stringify(empty));
    syncDirectory(authDir);
    const marker = path.join(authDir, 'refresh.pending');
    const checkOpen = () => { if (!open) invalid(); };
    const time = () => { const value = now(); if (!integer(value)) invalid(); return value; };
    const read = () => {
      checkOpen(); const row = db.prepare('SELECT value FROM durable_state WHERE id=1').get();
      if (!row || typeof row.value !== 'string' || Buffer.byteLength(row.value) > 16384) invalid();
      return parseState(JSON.parse(row.value));
    };
    const transaction = (change, signal) => {
      checkOpen(); if (signal?.aborted) invalid(); db.exec('BEGIN IMMEDIATE');
      try {
        const clean = parseState(change(read())); const serialized = JSON.stringify(clean);
        if (Buffer.byteLength(serialized) > 16384 || signal?.aborted) invalid();
        db.prepare('UPDATE durable_state SET value=? WHERE id=1').run(serialized);
        if (signal?.aborted) invalid(); db.exec('COMMIT'); return clean;
      } catch (error) { try { db.exec('ROLLBACK'); } catch {} throw error; }
    };
    const pending = () => {
      let fd;
      try {
        fd = fs.openSync(marker, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
        const st = fs.fstatSync(fd); privateFile(st, 33);
        const value = fs.readFileSync(fd, 'utf8'); if (!/^[a-f0-9]{32}\n$/.test(value)) invalid(); return value.trim();
      } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
      finally { if (fd !== undefined) fs.closeSync(fd); }
    };
    const writeMarker = generation => {
      pending(); // Existing marker must itself be a safe private regular file.
      const temp = path.join(authDir, '.refresh-' + randomBytes(16).toString('hex'));
      let fd;
      try {
        fd = fs.openSync(temp, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW, 0o600);
        fs.writeFileSync(fd, generation + '\n'); fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
        fs.renameSync(temp, marker); syncDirectory(authDir);
      } finally { if (fd !== undefined) fs.closeSync(fd); try { fs.unlinkSync(temp); } catch (error) { if (error.code !== 'ENOENT') throw error; } }
    };
    const store = {
      cachePaths: paths,
      read() { const state = read(); return { ...state, interruptedRefresh: state.generation !== null && pending() === state.generation }; },
      requireLoginEligible() { if (read().grant !== null) invalid(); pending(); },
      authorize(grant, { signal } = {}) {
        checkOpen(); const clean = validateGrant(grant); const current = time();
        store.requireLoginEligible();
        if (signal?.aborted || current < clean.authorizedAt || current >= clean.authorizationExpiresAt || clean.accessExpiresAt <= current ||
            clean.accessExpiresAt > current + 86400000 || (read().lastSeenAt !== null && current < read().lastSeenAt)) invalid();
        removeCaches(paths);
        transaction(state => {
          if (state.grant !== null || signal?.aborted || time() >= clean.authorizationExpiresAt) invalid();
          return { ...state, generation: randomBytes(16).toString('hex'), phase: 'active', grant: clean, lastSeenAt: current };
        }, signal);
        // Nothing fallible follows commit: durable publication wins cancellation.
      },
      admit() {
        let admitted = false;
        transaction(state => {
          const current = time();
          if ((state.lastSeenAt !== null && current < state.lastSeenAt) ||
              (state.lastAttemptAt !== null && current - state.lastAttemptAt < SYNC_INTERVAL_MS)) return state;
          admitted = true; return { ...state, lastAttemptAt: current, lastSeenAt: current };
        }); return admitted;
      },
      beginRefresh() {
        const state = read(); if (state.phase !== 'active' || !state.grant || pending() === state.generation) invalid();
        writeMarker(state.generation);
        transaction(value => ({ ...value, phase: 'refreshing' }));
      },
      replaceTokens(expectedRefreshToken, tokens, { signal } = {}) {
        exact(tokens, ['accessToken', 'refreshToken', 'accessExpiresAt']);
        text(tokens.accessToken, 4096); text(tokens.refreshToken, 4096);
        const current = time(); if (!integer(tokens.accessExpiresAt) || tokens.accessExpiresAt <= current || tokens.accessExpiresAt > current + 86400000) invalid();
        const updated = transaction(state => {
          if (state.phase !== 'refreshing' || !state.grant || state.grant.refreshToken !== expectedRefreshToken ||
              pending() !== state.generation || current < state.lastSeenAt || current >= state.grant.authorizationExpiresAt) invalid();
          return { ...state, phase: 'active', grant: { ...state.grant, ...tokens }, lastSeenAt: current };
        }, signal);
        // The generation marker survives ambiguous commit/rename/crash outcomes.
        // No health request may follow until both durable operations succeed.
        if (pending() !== updated.generation) invalid(); fs.unlinkSync(marker); syncDirectory(authDir);
      },
      discard() {
        transaction(state => ({ ...state, phase: 'reauthorize', grant: null }));
        removeCaches(paths);
      },
      removeCaches() { checkOpen(); removeCaches(paths); },
    };
    return await action(store);
  } catch (error) { if (error?.message === 'LOCAL_SYNC_BUSY') throw error; throw failure(); }
  finally {
    open = false;
    try { db?.close(); } finally { if (locked) { try { lock.exec('ROLLBACK'); } catch {} } lock?.close(); }
  }
}

export async function authorizeGrant(grant, options = {}) {
  return withLockedState(store => store.authorize(grant, { signal: options.signal }), options);
}
