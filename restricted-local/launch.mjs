// Operator-controlled Docker orchestration. Never import this module into the
// MCP reader; MCP requests cannot select its command, configuration or network.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";
import { isTailnetTarget } from "./fixed-relay.mjs";

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
// OrbStack otherwise injects its public CA at start, including into read-only
// containers. Keep this container setting separate from persistent volume labels.
const CA_INJECTION_LABEL = "dev.orbstack.add-ca-certificates";
export function volumeNames(clientId) {
  if (!clients.has(clientId)) unavailable();
  const prefix = `whoop_individual_sub-restricted-${clientId}`;
  return { auth: `${prefix}_auth_kill-${REVIEW_DATE}`, cache: `${prefix}_cache_kill-${REVIEW_DATE}`,
    transportState: `${prefix}_transport-state_kill-${REVIEW_DATE}`, transportSocket: `${prefix}_transport-socket_kill-${REVIEW_DATE}` };
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
    const privateMode = raw && Object.hasOwn(raw, "privateTransport");
    const keys = ["origin", privateMode ? "privateTransport" : "approvedIpv4", "readerImage", "syncImage"];
    if (!raw || typeof raw !== "object" || Array.isArray(raw) || Object.keys(raw).length !== keys.length ||
        keys.some((key) => !Object.hasOwn(raw, key))) unavailable();
    const url = new URL(raw.origin);
    if (url.origin !== raw.origin || url.protocol !== "https:" || url.port || url.username || url.password ||
        !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(url.hostname) ||
        !imageId(raw.readerImage) || !imageId(raw.syncImage)) unavailable();
    if (privateMode) {
      const transport = raw.privateTransport;
      if (!transport || typeof transport !== "object" || Array.isArray(transport) || Object.keys(transport).length !== 2 ||
          !Object.hasOwn(transport, "image") || !Object.hasOwn(transport, "gatewayIpv4") ||
          !imageId(transport.image) || !isTailnetTarget(transport.gatewayIpv4)) unavailable();
      return { origin: raw.origin, privateTransport: { image: transport.image, gatewayIpv4: transport.gatewayIpv4 },
        readerImage: raw.readerImage, syncImage: raw.syncImage };
    }
    if (!publicIpv4(raw.approvedIpv4)) unavailable();
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

export function callbackFirewallScript(port) {
  if (![17643, 17644].includes(port)) unavailable();
  return [
    "iptables -P INPUT DROP", "iptables -P OUTPUT DROP", "iptables -P FORWARD DROP",
    "ip6tables -P INPUT DROP", "ip6tables -P OUTPUT DROP", "ip6tables -P FORWARD DROP",
    "iptables -F", "ip6tables -F",
    "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    "iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    `iptables -A INPUT -p tcp --dport ${port} -m conntrack --ctstate NEW -j ACCEPT`,
    `iptables -C INPUT -p tcp --dport ${port} -m conntrack --ctstate NEW -j ACCEPT`,
    'test "$(ip6tables -S)" = "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT DROP"',
  ].join("\n");
}

export function transportFirewallScript() {
  // Only this credential-isolated Tailscale process gets public control/DERP
  // HTTPS and one DNS resolver. It cannot reach LAN/host/metadata addresses;
  // its virtual tailnet traffic is carried inside the authenticated tunnel.
  const denied = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/16", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"];
  return [
    "iptables -P INPUT DROP", "iptables -P OUTPUT DROP", "iptables -P FORWARD DROP",
    "ip6tables -P INPUT DROP", "ip6tables -P OUTPUT DROP", "ip6tables -P FORWARD DROP",
    "iptables -F", "ip6tables -F",
    "iptables -A INPUT -i lo -j ACCEPT", "iptables -A OUTPUT -o lo -j ACCEPT",
    "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    "iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ...denied.map((range) => `iptables -A OUTPUT -d ${range} -j DROP`),
    "iptables -A OUTPUT -p udp -d 1.1.1.1/32 --dport 53 -m conntrack --ctstate NEW -j ACCEPT",
    "iptables -A OUTPUT -p tcp -d 1.1.1.1/32 --dport 53 -m conntrack --ctstate NEW -j ACCEPT",
    "iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT",
    "iptables -C OUTPUT -d 100.64.0.0/10 -j DROP", "iptables -C OUTPUT -d 169.254.0.0/16 -j DROP",
    'test "$(ip6tables -S)" = "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT DROP"',
  ].join("\n");
}

export function createLauncher(raw, { docker }) {
  const config = parseOperatorConfig(raw);
  if (typeof docker !== "function") unavailable();
  const active = new Set(); const graceful = new Set();
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
      dns: network === "bridge" ? ["0.0.0.0"] : [],
      hosts: network === "bridge" && !config.privateTransport ? [`${new URL(config.origin).hostname}:${config.approvedIpv4}`] : [],
      tmpfs: image === FIREWALL_IMAGE ? ["/tmp", "/var/lib/docker"] : ["/tmp"] };
  }
  function verify(value, spec, baseline) {
    const h = value.HostConfig; const c = value.Config;
    const mounts = value.Mounts ?? [];
    const expectedPorts = spec.port === undefined ? {} : { [`${spec.port}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: String(spec.port) }] };
    if ((spec.name !== undefined && value.Name !== `/${spec.name}`) || value.Image !== spec.image || c?.User !== spec.user || h?.Privileged !== false || h.ReadonlyRootfs !== true ||
        !same(sorted(h.CapDrop), ["ALL"]) || !same(capabilities(h.CapAdd), capabilities(spec.caps)) ||
        !same(sorted(h.SecurityOpt), ["no-new-privileges:true"]) || h.NetworkMode !== spec.network ||
        h.IpcMode !== "none" || h.CgroupnsMode !== "private" || h.PidsLimit !== 64 ||
        h.Memory !== 134217728 || h.MemorySwap !== 134217728 || h.NanoCpus !== 500000000 || !noValues(h.Binds) ||
        !noValues(h.VolumesFrom) || !noValues(h.Devices) || !noValues(h.DeviceRequests) || h.PidMode || h.UTSMode ||
        !same(h.PortBindings ?? {}, expectedPorts) || !same(sorted(Object.keys(h.Tmpfs ?? {})), sorted(spec.tmpfs)) ||
        Object.values(h.Tmpfs ?? {}).some((value) => value !== "rw,noexec,nosuid,nodev,size=16m,mode=1777") ||
        !same(sorted(c.Env), sorted(baseline.Config.Env)) || !same(c.Entrypoint, [spec.entrypoint]) ||
        !same(c.Cmd, spec.args) || c.Labels?.[CA_INJECTION_LABEL] !== "false") unavailable();
    const volumeMounts = mounts.filter((mount) => mount.Type === "volume");
    if (volumeMounts.length !== spec.volumes.length || volumeMounts.some((mount) => !spec.volumes.some((expected) =>
      mount.Name === expected.name && mount.Destination === expected.target && mount.RW === !expected.readonly)) ||
      mounts.some((mount) => mount.Type !== "volume" && !(mount.Type === "tmpfs" && spec.tmpfs.includes(mount.Destination)))) unavailable();
    if (!same(h.Dns ?? [], spec.dns) || !same(h.ExtraHosts ?? [], spec.hosts)) unavailable();
  }
  async function create(spec, entrypoint, args, interactive = false) {
    spec = { ...spec, entrypoint, args };
    const baseline = await image(spec.image);
    const name = spec.name ?? `whoop_individual_sub-restricted_run-${randomBytes(8).toString("hex")}_kill-${REVIEW_DATE}`;
    const argv = ["create", "--pull=never", "--name", name, ...labels, "--label", `${CA_INJECTION_LABEL}=false`, "--read-only", "--user", spec.user,
      "--network", spec.network, "--ipc", "none", "--cgroupns", "private", "--cap-drop", "ALL",
      ...spec.caps.flatMap((cap) => ["--cap-add", cap]), "--security-opt", "no-new-privileges:true",
      "--pids-limit", "64", "--memory", "128m", "--memory-swap", "128m", "--cpus", "0.5",
      ...spec.tmpfs.flatMap((target) => ["--tmpfs", `${target}:rw,noexec,nosuid,nodev,size=16m,mode=1777`]),
      ...spec.volumes.flatMap((mount) => ["--mount", `type=volume,source=${mount.name},target=${mount.target}${mount.readonly ? ",readonly" : ""}`]),
      ...spec.dns.flatMap((address) => ["--dns", address]), ...spec.hosts.flatMap((entry) => ["--add-host", entry]),
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
    if (graceful.has(id)) {
      // Linux kill(-1) here reaches only this isolated PID namespace's other
      // same-UID processes, excluding PID 1 and this short-lived helper. Give
      // the supervisor time to unlink its socket and flush its own node state.
      try { await run(["exec", "--interactive", id, "/usr/bin/env", "-i", "/usr/local/bin/node", "-e",
        'try { process.kill(-1, "SIGTERM"); } catch (error) { if (error.code !== "ESRCH") throw error; } setTimeout(() => {}, 5000)']); } catch {}
    }
    await run(["rm", "--force", id]); active.delete(id); graceful.delete(id);
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
    const appConfig = { clientId, origin: config.origin, tokenFile: "/auth/token.json", stateFile: "/auth/state.sqlite", cacheFile: "/cache/cache.json",
      ...(config.privateTransport ? { transport: "unix" } : {}) };
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
    const mounts = [{ name: names.auth, target: "/auth" }, { name: names.cache, target: "/cache" }];
    if (config.privateTransport) { await volume(names.transportSocket); mounts.push({ name: names.transportSocket, target: "/transport", readonly: true }); }
    const spec = options(config.syncImage, config.privateTransport && !login ? "none" : "bridge", mounts, [], login ? clientPort(clientId) : undefined);
    return using(spec, "/usr/bin/env", ["-i", "/usr/local/bin/node", "-e", "setInterval(() => {}, 3600000)"], false, async (created) => {
      await run(["start", created.id]);
      const running = await one(["inspect", created.id]); verify(running, created.spec, created.baseline);
      if (!running.State?.Running) unavailable();
      if (spec.network !== "none") await installFirewall(created.id,
        config.privateTransport ? callbackFirewallScript(spec.port) : firewallScript(config.approvedIpv4, spec.port));
      // No application module is loaded before the firewall helper succeeds.
      return run(["exec", "--interactive", created.id, "/usr/bin/env", "-i", "/usr/local/bin/node",
        login ? "/app/login.mjs" : "/app/sync.mjs", "/auth/config.json", ...(login ? ["--container-callback"] : [])], { interactive: true });
    });
  }
  async function installFirewall(containerId, script) {
    const spec = options(FIREWALL_IMAGE, `container:${containerId}`, [], ["NET_ADMIN"]);
    await using(spec, "/bin/sh", ["-eu", "-c", script], false, async ({ id }) => {
      await run(["start", "--attach", id]);
      const finished = await one(["inspect", id]);
      if (finished.State?.Running || finished.State?.ExitCode !== 0) unavailable();
    });
  }
  async function initializeTransport(clientId) {
    if (!config.privateTransport) unavailable();
    const names = volumeNames(clientId);
    await volume(names.transportState, true); await volume(names.transportSocket, true);
    const spec = options(FIREWALL_IMAGE, "none", [{ name: names.transportState, target: "/state" },
      { name: names.transportSocket, target: "/transport" }], ["CHOWN", "FOWNER"]);
    const script = 'umask 077\nfor d in /state /transport; do test -z "$(ls -A "$d")"; done\nchmod 700 /state /transport\nchown 1000:1000 /state /transport';
    return using(spec, "/bin/sh", ["-eu", "-c", script], false, async ({ id }) => {
      await run(["start", "--attach", id]);
      const value = await one(["inspect", id]);
      if (value.State?.Running || value.State?.ExitCode !== 0) unavailable();
    });
  }
  async function transport(clientId, enroll) {
    if (!config.privateTransport) unavailable();
    const names = volumeNames(clientId); await volume(names.transportState); await volume(names.transportSocket);
    const spec = options(config.privateTransport.image, "bridge", [{ name: names.transportState, target: "/state" },
      { name: names.transportSocket, target: "/transport" }]);
    // Docker's atomic name reservation serializes start/enroll before either
    // mounts a writable state directory. Never remove a preexisting owner.
    spec.name = `whoop_individual_sub-restricted-${clientId}_transport_kill-${REVIEW_DATE}`;
    spec.dns = ["1.1.1.1"]; spec.hosts = [];
    return using(spec, "/usr/bin/env", ["-i", "/usr/local/bin/node", "-e", "setInterval(() => {}, 3600000)"], false, async (created) => {
      await run(["start", created.id]);
      const running = await one(["inspect", created.id]); verify(running, created.spec, created.baseline);
      if (!running.State?.Running) unavailable();
      await installFirewall(created.id, transportFirewallScript());
      graceful.add(created.id);
      // Enrollment is a separate manual stdin-only command. The launcher never
      // reads a key, and the reader/sync/login path cannot start or enroll nodes.
      return run(["exec", ...(enroll ? ["--interactive"] : []), created.id, "/usr/bin/env", "-i", "/usr/local/bin/node",
        "/app/restricted-local/transport-supervisor.mjs", clientId, config.privateTransport.gatewayIpv4,
        ...(enroll ? ["--enroll"] : [])], { interactive: true, persistent: !enroll });
    });
  }
  return { init: initialize, read, sync: (clientId) => networked(clientId, false), login: (clientId) => networked(clientId, true),
    "transport-init": initializeTransport, "transport-start": (clientId) => transport(clientId, false),
    "transport-enroll": (clientId) => transport(clientId, true),
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
    if (!["init", "read", "sync", "login", "watch", "transport-init", "transport-start", "transport-enroll"].includes(command) || !clients.has(clientId) || extra.length) unavailable();
    if (command === "transport-enroll" && process.stdin.isTTY) unavailable();
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
