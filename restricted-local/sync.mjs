import fs from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { pathToFileURL } from "node:url";
import { boundedJson, configuredFetch, parseLocalConfig, parseToken, privateParent, privateStat, readLocalConfig, readPrivateJson, RemoteFailure } from "./config.mjs";
import { validateSnapshot } from "./policy.mjs";
import { CACHE_TTL_MS, writeCache } from "./cache.mjs";

export const SYNC_INTERVAL_MS = 15 * 60000;
// Seven gateway summaries execute sequentially, each with a five-second bound.
export const SNAPSHOT_TIMEOUT_MS = 40000;
export function acquireSyncAttempt(filename, now) {
  if (!Number.isSafeInteger(now) || now < 0) throw new Error("LOCAL_SYNC_UNAVAILABLE");
  privateParent(filename);
  const fd = fs.openSync(filename, fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o600);
  try { privateStat(fs.fstatSync(fd), 1048576); } finally { fs.closeSync(fd); }
  const db = new DatabaseSync(filename);
  try {
    db.exec("PRAGMA busy_timeout=1000; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY CHECK(id=1),at INTEGER NOT NULL)");
    db.exec("BEGIN IMMEDIATE");
    const row = db.prepare("SELECT at FROM attempts WHERE id=1").get();
    if (row && (!Number.isSafeInteger(row.at) || row.at < 0)) throw new Error("LOCAL_SYNC_UNAVAILABLE");
    // Charge before networking. Restart, failure or a wall-clock rollback must
    // not turn repeated local invocations into a remote request channel.
    if (row && now - row.at < SYNC_INTERVAL_MS) { db.exec("COMMIT"); return false; }
    db.prepare("INSERT OR REPLACE INTO attempts(id,at) VALUES(1,?)").run(now);
    db.exec("COMMIT"); return true;
  } finally { db.close(); }
}
function invalidate(filename) {
  privateParent(filename);
  try { privateStat(fs.lstatSync(filename), 16384); fs.unlinkSync(filename); }
  catch (error) { if (error.code !== "ENOENT") throw error; }
}
export async function syncOnce(rawConfig, { fetchImpl, now = Date.now } = {}) {
  try {
    const config = parseLocalConfig(rawConfig); const startedAt = now();
    fetchImpl ??= configuredFetch(config);
    const token = parseToken(readPrivateJson(config.tokenFile, 4096), config, startedAt);
    if (!acquireSyncAttempt(config.stateFile, startedAt)) return { status: "limited" };
    let raw;
    try {
      raw = await boundedJson(`${config.origin}/data/snapshot`, { method: "GET", headers: { Accept: "application/json", "Accept-Encoding": "identity", Authorization: `Bearer ${token.accessToken}` } }, { fetchImpl, timeoutMs: SNAPSHOT_TIMEOUT_MS });
    } catch (error) {
      if (error instanceof RemoteFailure && error.status === 401) { invalidate(config.cacheFile); return { status: "reauthorize" }; }
      return { status: "unavailable" };
    }
    const finishedAt = now();
    if (finishedAt < startedAt || finishedAt - startedAt > SNAPSHOT_TIMEOUT_MS || token.expiresAt <= finishedAt) return { status: "unavailable" };
    const snapshot = validateSnapshot(raw, finishedAt);
    writeCache(config.cacheFile, { version: 1, clientId: config.clientId, syncedAt: finishedAt,
      expiresAt: Math.min(finishedAt + CACHE_TTL_MS, token.expiresAt), authorizationExpiresAt: token.expiresAt, snapshot }, finishedAt);
    return { status: "updated" };
  } catch { return { status: "unavailable" }; }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 3) throw new Error();
    const result = await syncOnce(readLocalConfig(process.argv[2]));
    const messages = { updated: "Local snapshot updated.", limited: "Local sync is limited to once every 15 minutes.",
      reauthorize: "Gateway authorization expired or was revoked. Sign in again separately.", unavailable: "Local snapshot unavailable." };
    console.log(messages[result.status]); if (!["updated", "limited"].includes(result.status)) process.exitCode = 1;
  } catch { console.error("Local sync configuration unavailable."); process.exitCode = 1; }
}
