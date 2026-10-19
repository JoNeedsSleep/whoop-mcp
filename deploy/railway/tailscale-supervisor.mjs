import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { isDeepStrictEqual } from 'node:util';
import { fail, object, privateDirectory, readPrivateJson, tailnetHostname, TS_VERSION } from './config.mjs';

export const TS_BIN = '/usr/local/bin/tailscale';
export const DAEMON_BIN = '/usr/local/bin/tailscaled';
export const childEnvironment = Object.freeze({ PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', TS_NO_LOGS_NO_SUPPORT: 'true' });
// Pinned Tailscale Serve uses Go's ordinary http.Server without a custom HTTP/2
// handler. Disable its HTTP/2 server paths while retaining HTTPS and HTTP/1.1.
// This is a literal daemon-only setting, never inherited from the operator.
export const daemonEnvironment = Object.freeze({ ...childEnvironment, GODEBUG: 'http2server=0' });
// Temporary synthetic staging workaround for the pinned vendor's direct-path
// failure. This debug setting is not a stable production transport API.
const stagingRelayEnvironment = Object.freeze({ ...daemonEnvironment, TS_DEBUG_ALWAYS_USE_DERP: 'true' });
export function expectedServe(hostname, port) {
  if (hostname === undefined && port === undefined) return {};
  tailnetHostname(hostname);
  if (![8080, 8787].includes(port)) fail();
  return { TCP: { '443': { HTTPS: true } }, Web: { [`${hostname}:443`]: { Handlers: { '/': { Proxy: `http://127.0.0.1:${port}` } } } } };
}
export function validateServe(raw, expected) {
  // Empty, disabled maps are equivalent to omission. Any active extra handler,
  // Funnel grant, filesystem path, TCP forwarder or service is rejected.
  if (raw === null && Object.keys(expected).length === 0) return;
  if (!object(raw)) fail();
  const copy = structuredClone(raw);
  for (const key of ['AllowFunnel', 'Foreground', 'Services']) {
    if (Object.hasOwn(copy, key) && object(copy[key]) && Object.keys(copy[key]).length === 0) delete copy[key];
  }
  if (!isDeepStrictEqual(copy, expected)) fail();
}
export function validateIdentity(status, { tag, hostname }) {
  if (!object(status) || status.BackendState !== 'Running' || status.Self?.Online !== true ||
      !Array.isArray(status.Self.Tags) || status.Self.Tags.length !== 1 || status.Self.Tags[0] !== tag ||
      (hostname && status.Self.DNSName !== `${hostname}.`)) fail();
}
export function validatePreferences(p, local) {
  if (!object(p) || p.ControlURL !== 'https://controlplane.tailscale.com' || p.RouteAll !== false || p.CorpDNS !== false ||
      p.RunSSH !== false || p.RunWebClient !== false || p.RemoteConfig !== false || p.ShieldsUp !== local ||
      p.ExitNodeID || (p.ExitNodeIP && p.ExitNodeIP !== 'invalid IP') || p.AutoExitNode ||
      (p.AdvertiseRoutes?.length ?? 0) !== 0 || (p.AdvertiseServices?.length ?? 0) !== 0 ||
      (p.DriveShares?.length ?? 0) !== 0 || p.RelayServerPort != null ||
      p.AppConnector?.Advertise === true || p.AutoUpdate?.Apply === true || p.AutoUpdate?.Apply === 'true') fail();
}
export function validatePersistedState(filename, expected, local) {
  // The pinned daemon's file store is a JSON map of base64 values. Check any
  // saved ingress before daemon startup, so stale Funnel/file serving cannot
  // briefly become active while startup validation runs.
  const state = readPrivateJson(filename, 1024 * 1024);
  if (!object(state) || typeof state._machinekey !== 'string' || !state._machinekey) fail();
  for (const [key, value] of Object.entries(state)) {
    if (typeof value !== 'string') fail();
    let parsed;
    try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(value, 'base64'))); }
    catch { if (key.startsWith('_serve/')) fail(); continue; }
    if (key.startsWith('_serve/')) {
      if (parsed !== null && Object.keys(parsed).length !== 0) validateServe(parsed, expected);
    }
    if (object(parsed) && ['WantRunning', 'RunSSH', 'Config'].some(k => Object.hasOwn(parsed, k))) validatePreferences(parsed, local);
  }
}
export function runCommand(binary, args, { spawnFn = spawn, timeoutMs = 5000, maxBytes = 65536 } = {}) {
  return new Promise((resolve, reject) => {
    let done = false; let output = Buffer.alloc(0);
    const child = spawnFn(binary, args, { env: childEnvironment, stdio: ['ignore', 'pipe', 'ignore'] });
    const finish = (ok) => { if (done) return; done = true; clearTimeout(timer); ok ? resolve(output.toString('utf8')) : reject(new Error('PRIVATE_RUNTIME_UNAVAILABLE')); };
    const timer = setTimeout(() => { child.kill('SIGKILL'); finish(false); }, timeoutMs);
    child.on('error', () => finish(false));
    child.stdout.on('data', chunk => { output = Buffer.concat([output, chunk]); if (output.length > maxBytes) { child.kill('SIGKILL'); finish(false); } });
    child.once('close', code => finish(code === 0));
  });
}
export function settings(local) {
  return ['--accept-dns=false', '--accept-routes=false', '--ssh=false', '--webclient=false', '--remote-config=false',
    '--advertise-routes=', '--advertise-exit-node=false', '--advertise-connector=false', '--exit-node=',
    '--exit-node-allow-lan-access=false', '--auto-update=false', '--update-check=false', '--report-posture=false',
    `--shields-up=${local}`, '--relay-server-port=', '--relay-server-static-endpoints='];
}
export async function readEnrollmentKey(input) {
  let bytes = Buffer.alloc(0);
  const read = (async () => { for await (const chunk of input) { bytes = Buffer.concat([bytes, chunk]); if (bytes.length > 256) fail(); } })();
  let timer;
  try { await Promise.race([read, new Promise((_, reject) => { timer = setTimeout(() => { input.destroy(); reject(new Error('PRIVATE_RUNTIME_UNAVAILABLE')); }, 30000); })]); }
  finally { clearTimeout(timer); }
  const key = bytes.toString('utf8').trimEnd(); bytes.fill(0);
  if (!/^tskey-auth-[A-Za-z0-9_-]{20,220}$/.test(key)) fail();
  return key;
}
export async function startTailscale({ stateDirectory, tag, hostname, port, enrollmentKey, syntheticStagingRelayOnly = false }, {
  command = runCommand, spawnFn = spawn, wait = delay, startupAttempts = 60,
} = {}) {
  if (typeof syntheticStagingRelayOnly !== 'boolean' || (syntheticStagingRelayOnly && tag !== 'tag:whoop-gateway')) fail();
  process.umask(0o077); privateDirectory(stateDirectory);
  if (!/^tag:whoop-(?:local-codex|local-claude-code|gateway|backend)$/.test(tag)) fail();
  const local = tag.startsWith('tag:whoop-local-');
  if (local !== (hostname === undefined && port === undefined)) fail();
  const serve = expectedServe(hostname, port);
  const stateFile = path.join(stateDirectory, 'tailscaled.state');
  const socket = path.join(stateDirectory, 'tailscaled.sock');
  const keyFile = path.join(stateDirectory, 'enrollment.key');
  // O_EXCL is shared across containers using this dedicated state volume. Never
  // infer that a lock is stale from a PID in another PID namespace.
  const lockFile = path.join(stateDirectory, 'runtime.lock');
  const lockFd = fs.openSync(lockFile, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  const lockStat = fs.fstatSync(lockFd); fs.closeSync(lockFd);
  const releaseLock = () => {
    const st = fs.lstatSync(lockFile);
    if (!st.isFile() || st.isSymbolicLink() || st.ino !== lockStat.ino || st.dev !== lockStat.dev || st.uid !== process.getuid()) fail();
    fs.unlinkSync(lockFile);
  };
  let keyCreated = false;
  let daemon; let daemonEnded = false; let closed = false; let closing; let resolveFailure;
  const failed = new Promise(resolve => { resolveFailure = resolve; });
  const cli = args => command(TS_BIN, [`--socket=${socket}`, ...args], { timeoutMs: args[0] === 'up' ? 35000 : 5000 });
  const close = () => closing ??= (async () => {
    closed = true;
    if (daemon && !daemonEnded) {
      const stopped = new Promise(resolve => {
        if (daemon.exitCode !== null || daemon.signalCode) resolve();
        else { daemon.once('exit', resolve); daemon.once('close', resolve); daemon.once('error', () => { if (daemon.pid === undefined) resolve(); }); }
      });
      daemon.kill('SIGTERM'); const timer = setTimeout(() => daemon.kill('SIGKILL'), 3000);
      let deadline;
      try {
        await Promise.race([stopped, new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('PRIVATE_RUNTIME_UNAVAILABLE')), 4000); })]);
      } finally { clearTimeout(timer); clearTimeout(deadline); }
    }
    releaseLock();
  })();
  try {
    if (enrollmentKey === undefined) validatePersistedState(stateFile, serve, local);
    else {
      if (!/^tskey-auth-[A-Za-z0-9_-]{20,220}$/.test(enrollmentKey) || fs.existsSync(stateFile)) fail();
      const keyFd = fs.openSync(keyFile, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      keyCreated = true;
      try { fs.writeFileSync(keyFd, enrollmentKey); } finally { fs.closeSync(keyFd); }
    }
    const version = await command(TS_BIN, ['version']);
    if (version.trim().split('\n')[0] !== TS_VERSION) fail();
    daemon = spawnFn(DAEMON_BIN, ['--tun=userspace-networking', `--state=${stateFile}`, `--statedir=${stateDirectory}`,
      `--socket=${socket}`, '--socks5-server=127.0.0.1:1055', '--no-logs-no-support'],
    { env: syntheticStagingRelayOnly ? stagingRelayEnvironment : daemonEnvironment, stdio: 'ignore' });
    daemon.on('error', () => { if (daemon.pid === undefined) daemonEnded = true; resolveFailure(); });
    daemon.once('exit', () => { daemonEnded = true; if (!closed) resolveFailure(); });
    daemon.once('close', () => { daemonEnded = true; if (!closed) resolveFailure(); });
    let status;
    for (let i = 0; i < startupAttempts; i++) {
      try { status = JSON.parse(await cli(['status', '--json'])); } catch { status = undefined; }
      // Running and control-plane connectivity are separate Tailscale status
      // signals. A saved node can briefly be Running while Self.Online is false.
      // Wait for both before applying the unchanged exact identity checks.
      if (enrollmentKey !== undefined) {
        if (status?.BackendState === 'NeedsLogin' || status?.BackendState === 'Running') break;
      } else if (status?.BackendState === 'Running' && status.Self?.Online === true) break;
      if (daemonEnded || daemon.exitCode !== null || daemon.signalCode) fail();
      await wait(500);
    }
    if (enrollmentKey !== undefined) {
      if (status?.BackendState !== 'NeedsLogin') fail();
      // A one-use, pre-tagged key is provisioned separately. The key itself is
      // never a process argument or environment variable.
      await cli(['up', '--reset', '--accept-dns=false', '--accept-routes=false', '--ssh=false',
        `--shields-up=${local}`, `--hostname=${hostname?.split('.')[0] ?? `whoop-individual-${tag.slice('tag:whoop-local-'.length)}-transport`}`,
        `--auth-key=file:${keyFile}`, '--timeout=30s']);
    } else validateIdentity(status, { tag, hostname });
    await cli(['set', ...settings(local)]);
    validatePreferences(JSON.parse(await cli(['debug', 'prefs'])), local);
    await cli(['serve', 'reset']);
    if (!local && enrollmentKey === undefined) await cli(['serve', '--bg', '--yes', '--https=443', `http://127.0.0.1:${port}`]);
    validateServe(JSON.parse(await cli(['serve', 'status', '--json'])), enrollmentKey === undefined ? serve : {});
    validateIdentity(JSON.parse(await cli(['status', '--json'])), { tag, hostname });
    if (daemonEnded || daemon.exitCode !== null || daemon.signalCode) fail();
    return { daemon, failed, close };
  } catch { await close(); fail(); }
  finally { if (keyCreated) { try { fs.unlinkSync(keyFile); } catch {} } }
}
