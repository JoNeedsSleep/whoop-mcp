// Operator-controlled Docker orchestration. Never import this module into the
// MCP reader; MCP requests cannot select its command, configuration or network.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";

export const DOCKER = "/usr/local/bin/docker";
export const DOCKER_HOST = "unix:///Users/obsidian-gateway/.orbstack/run/docker.sock";
export const FIREWALL_IMAGE = "sha256:66d292e5c26bd33a6f6f61cacb880de2186339a524ecba1ce098dbbaceed6515";
const REVIEW_DATE = "2026-11-17";
const unavailable = () => { throw new Error("RESTRICTED_LAUNCH_UNAVAILABLE"); };
const imageId = (value) => typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
const clients = new Set(["codex", "claude-code"]);
const clientPort = (clientId) => clientId === "codex" ? 17643 : 17644;
const metadata = { rr_project_id: "whoop", rr_owner_id: "individual", rr_kill_date: REVIEW_DATE, rr_purpose: "restricted-local" };
const labels = Object.entries(metadata).flatMap(([key, value]) => ["--label", `${key}=${value}`]);
export function volumeNames(clientId) {
  if (!clients.has(clientId)) unavailable();
  const prefix = `whoop_individual_sub-restricted-${clientId}`;
  return { auth: `${prefix}_auth_kill-${REVIEW_DATE}`, cache: `${prefix}_cache_kill-${REVIEW_DATE}` };
}
function publicIpv4(raw) {
  if (typeof raw !== "string" || !/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(raw)) return false;
  const [a, b, c, d] = raw.split(".").map(Number);
  if ([a, b, c, d].some((value) => value > 255) || a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113)) return false;
  return true;
}
export function parseOperatorConfig(raw) {
  try {
    const keys = ["origin", "approvedIpv4", "readerImage", "syncImage"];
    if (!raw || typeof raw !== "object" || Array.isArray(raw) || Object.keys(raw).length !== keys.length ||
        keys.some((key) => !Object.hasOwn(raw, key))) unavailable();
    const url = new URL(raw.origin);
    if (url.origin !== raw.origin || url.protocol !== "https:" || url.port || url.username || url.password ||
        !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(url.hostname) ||
        !publicIpv4(raw.approvedIpv4) || !imageId(raw.readerImage) || !imageId(raw.syncImage)) unavailable();
    return { origin: raw.origin, approvedIpv4: raw.approvedIpv4, readerImage: raw.readerImage, syncImage: raw.syncImage };
  } catch { unavailable(); }
}
function readOperatorConfig(filename) {
  let fd;
  try {
    if (typeof filename !== "string" || !path.isAbsolute(filename) || path.normalize(filename) !== filename || filename.includes("\0")) unavailable();
    const directory = fs.lstatSync(path.dirname(filename));
    if (!directory.isDirectory() || directory.isSymbolicLink() || directory.uid !== process.getuid() || (directory.mode & 0o077)) unavailable();
    fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.uid !== process.getuid() || stat.nlink !== 1 || (stat.mode & 0o077) || stat.size < 1 || stat.size > 4096) unavailable();
    const bytes = Buffer.alloc(4097); const count = fs.readSync(fd, bytes, 0, bytes.length, 0);
    if (count > 4096) unavailable();
    return parseOperatorConfig(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, count))));
  } catch { unavailable(); }
  finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch {} } }
}
function same(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
const sorted = (values) => [...(values ?? [])].sort();
function capabilities(values) {
  if (values == null) return [];
  if (!Array.isArray(values) || values.some((value) => typeof value !== "string")) unavailable();
  // Docker inspection canonicalizes Linux capabilities to CAP_* on some
  // daemon versions. Normalize spelling only; retain the exact count/set.
  return values.map((value) => value.replace(/^CAP_/, "")).sort();
}
const noValues = (value) => !value || (Array.isArray(value) ? value.length === 0 : Object.keys(value).length === 0);

export function firewallScript(ip, port) {
  if (!publicIpv4(ip) || (port !== undefined && ![17643, 17644].includes(port))) unavailable();
  return [
    "iptables -P INPUT DROP", "iptables -P OUTPUT DROP", "iptables -P FORWARD DROP",
    "ip6tables -P INPUT DROP", "ip6tables -P OUTPUT DROP", "ip6tables -P FORWARD DROP",
    "iptables -F", "ip6tables -F",
    "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    "iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    `iptables -A OUTPUT -p tcp -d ${ip}/32 --dport 443 -m conntrack --ctstate NEW -j ACCEPT`,
    ...(port === undefined ? [] : [`iptables -A INPUT -p tcp --dport ${port} -m conntrack --ctstate NEW -j ACCEPT`]),
    `iptables -C OUTPUT -p tcp -d ${ip}/32 --dport 443 -m conntrack --ctstate NEW -j ACCEPT`,
    'test "$(ip6tables -S)" = "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT DROP"',
  ].join("\n");
}

export function createLauncher(raw, { docker }) {
  const config = parseOperatorConfig(raw);
  if (typeof docker !== "function") unavailable();
  const active = new Set();
  async function run(args, options = {}) {
    const result = await docker(args, options);
    if (!result || result.code !== 0 || typeof result.stdout !== "string") unavailable();
    return result.stdout.trim();
  }
  async function one(args) {
    const rows = JSON.parse(await run(args));
    if (!Array.isArray(rows) || rows.length !== 1) unavailable();
    return rows[0];
  }
  async function image(id) {
    const value = await one(["image", "inspect", id]);
    if (value.Id !== id || value.Os !== "linux" || !Array.isArray(value.Config?.Env)) unavailable();
    return value;
  }
  async function volume(name, create = false) {
    if (create) await run(["volume", "create", ...labels, name]);
    const value = await one(["volume", "inspect", name]);
    if (value.Name !== name || value.Driver !== "local" || !noValues(value.Options) ||
        Object.entries(metadata).some(([key, expected]) => value.Labels?.[key] !== expected)) unavailable();
  }
  function options(image, network, volumes = [], caps = [], port) {
    return { image, network, volumes, caps, port, user: caps.length ? "0:0" : "1000:1000",
      tmpfs: image === FIREWALL_IMAGE ? ["/tmp", "/var/lib/docker"] : ["/tmp"] };
  }
  function verify(value, spec, baseline) {
    const h = value.HostConfig; const c = value.Config;
    const mounts = value.Mounts ?? [];
    const expectedPorts = spec.port === undefined ? {} : { [`${spec.port}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: String(spec.port) }] };
    if (value.Image !== spec.image || c?.User !== spec.user || h?.Privileged !== false || h.ReadonlyRootfs !== true ||
        !same(sorted(h.CapDrop), ["ALL"]) || !same(capabilities(h.CapAdd), capabilities(spec.caps)) ||
        !same(sorted(h.SecurityOpt), ["no-new-privileges:true"]) || h.NetworkMode !== spec.network ||
        h.IpcMode !== "none" || h.CgroupnsMode !== "private" || h.PidsLimit !== 64 ||
        h.Memory !== 134217728 || h.MemorySwap !== 134217728 || h.NanoCpus !== 500000000 || !noValues(h.Binds) ||
        !noValues(h.VolumesFrom) || !noValues(h.Devices) || !noValues(h.DeviceRequests) || h.PidMode || h.UTSMode ||
        !same(h.PortBindings ?? {}, expectedPorts) || !same(sorted(Object.keys(h.Tmpfs ?? {})), sorted(spec.tmpfs)) ||
        Object.values(h.Tmpfs ?? {}).some((value) => value !== "rw,noexec,nosuid,nodev,size=16m,mode=1777") ||
        !same(sorted(c.Env), sorted(baseline.Config.Env)) || !same(c.Entrypoint, [spec.entrypoint]) ||
        !same(c.Cmd, spec.args)) unavailable();
    const volumeMounts = mounts.filter((mount) => mount.Type === "volume");
    if (volumeMounts.length !== spec.volumes.length || volumeMounts.some((mount) => !spec.volumes.some((expected) =>
      mount.Name === expected.name && mount.Destination === expected.target && mount.RW === !expected.readonly)) ||
      mounts.some((mount) => mount.Type !== "volume" && !(mount.Type === "tmpfs" && spec.tmpfs.includes(mount.Destination)))) unavailable();
    if (spec.network === "bridge" && (!same(h.Dns, ["0.0.0.0"]) ||
        !same(h.ExtraHosts, [`${new URL(config.origin).hostname}:${config.approvedIpv4}`]))) unavailable();
  }
  async function create(spec, entrypoint, args, interactive = false) {
    spec = { ...spec, entrypoint, args };
    const baseline = await image(spec.image);
    const name = `whoop_individual_sub-restricted_run-${randomBytes(8).toString("hex")}_kill-${REVIEW_DATE}`;
    const argv = ["create", "--pull=never", "--name", name, ...labels, "--read-only", "--user", spec.user,
      "--network", spec.network, "--ipc", "none", "--cgroupns", "private", "--cap-drop", "ALL",
      ...spec.caps.flatMap((cap) => ["--cap-add", cap]), "--security-opt", "no-new-privileges:true",
      "--pids-limit", "64", "--memory", "128m", "--memory-swap", "128m", "--cpus", "0.5",
      ...spec.tmpfs.flatMap((target) => ["--tmpfs", `${target}:rw,noexec,nosuid,nodev,size=16m,mode=1777`]),
      ...spec.volumes.flatMap((mount) => ["--mount", `type=volume,source=${mount.name},target=${mount.target}${mount.readonly ? ",readonly" : ""}`]),
      ...(spec.network === "bridge" ? ["--dns", "0.0.0.0", "--add-host", `${new URL(config.origin).hostname}:${config.approvedIpv4}`] : []),
      ...(spec.port === undefined ? [] : ["--publish", `127.0.0.1:${spec.port}:${spec.port}/tcp`]),
      ...(interactive ? ["--interactive"] : []), "--entrypoint", entrypoint, spec.image, ...args];
    const id = await run(argv);
    if (!/^[a-f0-9]{64}$/.test(id)) unavailable();
    active.add(id);
    try {
      const stopped = await one(["inspect", id]);
      verify(stopped, spec, baseline);
      if (stopped.State?.Running) unavailable();
    }
    catch {
      try { await remove(id); } catch {} // dispose() can retry failed cleanup.
      unavailable();
    }
    return { id, spec, baseline };
  }
  async function remove(id) {
    await run(["rm", "--force", id]); active.delete(id);
  }
  async function using(spec, entrypoint, args, interactive, work) {
    let created;
    try { created = await create(spec, entrypoint, args, interactive); return await work(created); }
    finally { if (created) await remove(created.id); }
  }
  async function initialize(clientId) {
    const names = volumeNames(clientId);
    await volume(names.auth, true); await volume(names.cache, true);
    const spec = options(FIREWALL_IMAGE, "none", [{ name: names.auth, target: "/auth" }, { name: names.cache, target: "/cache" }], ["CHOWN", "FOWNER"]);
    const script = 'umask 077\nfor d in /auth /cache; do test -z "$(ls -A "$d")"; done\ncat > /auth/config.json\nchmod 700 /auth /cache\nchmod 600 /auth/config.json\nchown 1000:1000 /auth /cache /auth/config.json';
    const appConfig = { clientId, origin: config.origin, tokenFile: "/auth/token.json", stateFile: "/auth/state.sqlite", cacheFile: "/cache/cache.json" };
    return using(spec, "/bin/sh", ["-eu", "-c", script], true, async ({ id }) => {
      await run(["start", "--attach", "--interactive", id], { input: JSON.stringify(appConfig) });
      const value = await one(["inspect", id]);
      if (value.State?.Running || value.State?.ExitCode !== 0) unavailable();
    });
  }
  async function read(clientId) {
    const names = volumeNames(clientId); await volume(names.cache);
    const spec = options(config.readerImage, "none", [{ name: names.cache, target: "/cache", readonly: true }]);
    return using(spec, "/usr/bin/env", ["-i", "WHOOP_LOCAL_CACHE_FILE=/cache/cache.json", `WHOOP_LOCAL_CLIENT_ID=${clientId}`,
      "/usr/local/bin/node", "/app/reader.mjs"], true,
    ({ id }) => run(["start", "--attach", "--interactive", id], { interactive: true, persistent: true }));
  }
  async function networked(clientId, login) {
    const names = volumeNames(clientId); await volume(names.auth); await volume(names.cache);
    const spec = options(config.syncImage, "bridge", [{ name: names.auth, target: "/auth" }, { name: names.cache, target: "/cache" }], [], login ? clientPort(clientId) : undefined);
    return using(spec, "/usr/bin/env", ["-i", "/usr/local/bin/node", "-e", "setInterval(() => {}, 3600000)"], false, async (created) => {
      await run(["start", created.id]);
      const running = await one(["inspect", created.id]); verify(running, created.spec, created.baseline);
      if (!running.State?.Running) unavailable();
      const firewall = options(FIREWALL_IMAGE, `container:${created.id}`, [], ["NET_ADMIN"]);
      await using(firewall, "/bin/sh", ["-eu", "-c", firewallScript(config.approvedIpv4, spec.port)], false, async ({ id }) => {
        await run(["start", "--attach", id]);
        const finished = await one(["inspect", id]);
        if (finished.State?.Running || finished.State?.ExitCode !== 0) unavailable();
      });
      // No application module is loaded before the firewall helper succeeds.
      return run(["exec", "--interactive", created.id, "/usr/bin/env", "-i", "/usr/local/bin/node",
        login ? "/app/login.mjs" : "/app/sync.mjs", "/auth/config.json", ...(login ? ["--container-callback"] : [])], { interactive: true });
    });
  }
  return { init: initialize, read, sync: (clientId) => networked(clientId, false), login: (clientId) => networked(clientId, true),
    async dispose() { for (const id of [...active]) { try { await remove(id); } catch {} } } };
}

export function createDockerRunner(directory) {
  return (args, { input, interactive = false, persistent = false } = {}) => new Promise((resolve, reject) => {
    const child = spawn(DOCKER, ["--config", directory, "--host", DOCKER_HOST, ...args], {
      env: { PATH: "/usr/local/bin:/usr/bin:/bin" },
      stdio: [interactive ? "inherit" : "pipe", interactive ? "inherit" : "pipe", "pipe"],
    });
    let bytes = 0; const stdout = [];
    // A reader stays attached for the client's lifetime. Login and sync retain
    // an operator-facing deadline; cache authorization is checked on every read.
    const timer = persistent ? undefined : setTimeout(() => { child.kill("SIGKILL"); reject(new Error("RESTRICTED_LAUNCH_UNAVAILABLE")); }, interactive ? 10 * 60000 : 30000);
    child.stdout?.on("data", (chunk) => { bytes += chunk.length; if (bytes > 1048576) child.kill("SIGKILL"); else stdout.push(chunk); });
    child.stderr.on("data", () => {}); // Never print daemon/configuration details.
    child.once("error", () => { clearTimeout(timer); reject(new Error("RESTRICTED_LAUNCH_UNAVAILABLE")); });
    child.once("close", (code) => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(stdout).toString("utf8") }); });
    if (!interactive) { child.stdin.on("error", () => {}); child.stdin.end(input ?? ""); }
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let directory; let launcher;
  try {
    const [command, clientId, filename, ...extra] = process.argv.slice(2);
    if (!["init", "read", "sync", "login", "watch"].includes(command) || !clients.has(clientId) || extra.length) unavailable();
    const config = readOperatorConfig(filename);
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "whoop-empty-docker-")); fs.chmodSync(directory, 0o700);
    fs.writeFileSync(path.join(directory, "config.json"), '{"auths":{}}', { flag: "wx", mode: 0o600 });
    launcher = createLauncher(config, { docker: createDockerRunner(directory) });
    for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => {
      void launcher.dispose().finally(() => { fs.rmSync(directory, { recursive: true, force: true }); process.exit(1); });
    });
    if (command === "watch") {
      if (clientId === "claude-code") await new Promise((resolve) => setTimeout(resolve, 61000));
      for (;;) {
        try { await launcher.sync(clientId); } catch { process.stderr.write("Restricted sync unavailable.\n"); }
        await new Promise((resolve) => setTimeout(resolve, 3600000));
      }
    } else await launcher[command](clientId);
  } catch { process.stderr.write("Restricted launcher unavailable.\n"); process.exitCode = 1; }
  finally {
    if (launcher) await launcher.dispose();
    if (directory) fs.rmSync(directory, { recursive: true, force: true });
  }
}
