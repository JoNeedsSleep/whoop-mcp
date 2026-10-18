// These tests use an in-memory Docker model. They exercise orchestration and
// fail-closed decisions; actual daemon/kernel isolation is verified separately.
import assert from "node:assert/strict";
import test from "node:test";
import { createLauncher, firewallScript, FIREWALL_IMAGE, parseOperatorConfig, volumeNames } from "./launch.mjs";

const config = Object.freeze({ origin: "https://health.example.test", approvedIpv4: "104.16.0.34",
  readerImage: `sha256:${"1".repeat(64)}`, syncImage: `sha256:${"2".repeat(64)}` });
const BASE_ENV = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "NODE_VERSION=22.23.3"];
const META = { rr_project_id: "whoop", rr_owner_id: "individual", rr_kill_date: "2026-11-17", rr_purpose: "restricted-local" };
const clone = (value) => JSON.parse(JSON.stringify(value));
const values = (args, key) => args.flatMap((value, index) => value === key ? [args[index + 1]] : []);
const value = (args, key) => values(args, key)[0];

function fakeDocker({ mutateInspect, mutateVolume, mutateImage, intercept } = {}) {
  const calls = []; const containers = new Map(); let sequence = 0;
  const api = { calls, containers };
  api.docker = async (args, options = {}) => {
    calls.push({ args: [...args], options: { ...options } });
    const replacement = await intercept?.(args, options, api);
    if (replacement !== undefined) return replacement;
    const ok = (stdout = "") => ({ code: 0, stdout });
    if (args[0] === "volume" && args[1] === "create") return ok(args.at(-1));
    if (args[0] === "volume" && args[1] === "inspect") {
      const row = { Name: args[2], Driver: "local", Options: null, Labels: clone(META) };
      mutateVolume?.(row, args[2]); return ok(JSON.stringify([row]));
    }
    if (args[0] === "image" && args[1] === "inspect") {
      const row = { Id: args[2], Os: "linux", Config: { Env: [...BASE_ENV] } };
      mutateImage?.(row, args[2]); return ok(JSON.stringify([row]));
    }
    if (args[0] === "create") {
      const imageIndex = args.indexOf("--entrypoint") + 2;
      const id = (++sequence).toString(16).padStart(64, "0");
      const tmpfs = Object.fromEntries(values(args, "--tmpfs").map((mount) => {
        const split = mount.indexOf(":"); return [mount.slice(0, split), mount.slice(split + 1)];
      }));
      const mounts = values(args, "--mount").map((mount) => {
        const fields = Object.fromEntries(mount.split(",").map((field) => field.split("=")));
        return { Type: fields.type, Name: fields.source, Destination: fields.target, RW: !Object.hasOwn(fields, "readonly") };
      });
      const portBindings = {};
      for (const publish of values(args, "--publish")) {
        const [HostIp, HostPort, target] = publish.split(":"); portBindings[target] = [{ HostIp, HostPort }];
      }
      const row = {
        Id: id, Image: args[imageIndex], Config: { User: value(args, "--user"), Env: [...BASE_ENV],
          Entrypoint: [value(args, "--entrypoint")], Cmd: args.slice(imageIndex + 1) },
        HostConfig: { Privileged: args.includes("--privileged"), ReadonlyRootfs: args.includes("--read-only"),
          CapDrop: values(args, "--cap-drop"), CapAdd: values(args, "--cap-add").map((cap) => `CAP_${cap}`), SecurityOpt: values(args, "--security-opt"),
          NetworkMode: value(args, "--network"), IpcMode: value(args, "--ipc"), CgroupnsMode: value(args, "--cgroupns"),
          PidsLimit: Number(value(args, "--pids-limit")), Memory: value(args, "--memory") === "128m" ? 134217728 : 0,
          MemorySwap: value(args, "--memory-swap") === "128m" ? 134217728 : 0, NanoCpus: Number(value(args, "--cpus")) * 1e9,
          Binds: [], VolumesFrom: [], Devices: [], DeviceRequests: [], PidMode: "", UTSMode: "",
          PortBindings: portBindings, Tmpfs: tmpfs, Dns: values(args, "--dns"), ExtraHosts: values(args, "--add-host") },
        Mounts: [...mounts, ...Object.keys(tmpfs).map((Destination) => ({ Type: "tmpfs", Destination, RW: true }))],
        State: { Running: false, ExitCode: 0 },
      };
      containers.set(id, { row, inspected: 0, removed: false }); return ok(id);
    }
    if (args[0] === "inspect") {
      const container = containers.get(args[1]); assert.ok(container, "Inspect must name a created container ID");
      const row = clone(container.row); mutateInspect?.(row, ++container.inspected, api);
      return ok(JSON.stringify([row]));
    }
    if (args[0] === "start") {
      const container = containers.get(args.at(-1)); assert.ok(container);
      container.row.State.Running = !args.includes("--attach"); return ok();
    }
    if (args[0] === "exec") { assert.ok(containers.get(args[2])?.row.State.Running); return ok(); }
    if (args[0] === "rm") {
      assert.deepEqual(args.slice(0, 2), ["rm", "--force"]);
      const container = containers.get(args[2]); assert.ok(container, "Cleanup must name an exact created ID");
      container.row.State.Running = false; container.removed = true; return ok(args[2]);
    }
    assert.fail(`Unexpected Docker operation: ${args[0]} ${args[1]}`);
  };
  return api;
}
const commandCalls = (fake, command) => fake.calls.filter(({ args }) => args[0] === command);
function assertNoHostAccess(fake) {
  for (const { args } of commandCalls(fake, "create")) {
    assert.ok(args.includes("--pull=never"));
    assert.ok(!args.includes("--privileged")); assert.ok(!args.includes("--env")); assert.ok(!args.includes("--env-file"));
    assert.ok(!args.includes("--volume")); assert.ok(!args.includes("-v"));
    assert.ok(values(args, "--mount").every((mount) => mount.startsWith("type=volume,source=whoop_individual_sub-restricted-")));
    assert.ok(values(args, "--mount").every((mount) => !mount.includes("docker.sock") && !mount.includes(".ssh")));
    assert.equal(value(args, "--ipc"), "none"); assert.equal(value(args, "--cgroupns"), "private");
    assert.deepEqual(values(args, "--cap-drop"), ["ALL"]);
  }
  assert.equal(commandCalls(fake, "pull").length, 0);
  assert.equal(fake.calls.filter(({ args }) => args[0] === "volume" && args[1] === "rm").length, 0);
}
function assertDisposed(fake) { assert.ok([...fake.containers.values()].every(({ removed }) => removed)); }

test("operator configuration rejects alternate destinations, mutable images and extra authority", () => {
  assert.deepEqual(parseOperatorConfig(config), config);
  for (const change of [
    { origin: "http://health.example.test" }, { origin: "https://health.example.test/" },
    { origin: "https://health.example.test:8443" }, { origin: "https://user:secret@health.example.test" },
    { origin: "https://127.0.0.1" }, { origin: "https://health.example.test/?url=https://attacker.test" },
    { approvedIpv4: "127.0.0.1" }, { approvedIpv4: "10.0.0.1" }, { approvedIpv4: "172.16.0.1" },
    { approvedIpv4: "192.168.1.1" }, { approvedIpv4: "169.254.169.254" }, { approvedIpv4: "100.64.0.1" },
    { approvedIpv4: "0.0.0.0" }, { approvedIpv4: "224.0.0.1" }, { approvedIpv4: "::1" },
    { approvedIpv4: "104.16.0.34;echo forbidden" }, { approvedIpv4: "104.016.0.34" },
    { readerImage: "node:22" }, { syncImage: "sha256:123" }, { dockerHost: "tcp://attacker.test:2375" },
  ]) assert.throws(() => parseOperatorConfig({ ...config, ...change }), /RESTRICTED_LAUNCH_UNAVAILABLE/);
  assert.throws(() => volumeNames("../codex"));
  assert.throws(() => firewallScript("127.0.0.1"));
  assert.throws(() => firewallScript(config.approvedIpv4, 22));
});

test("reader gets only its read-only cache, no network, no auth volume, and a persistent stdio attachment", async () => {
  const fake = fakeDocker(); const launcher = createLauncher(config, { docker: fake.docker });
  await launcher.read("codex");
  const [created] = commandCalls(fake, "create"); assert.equal(commandCalls(fake, "create").length, 1);
  assert.equal(value(created.args, "--network"), "none"); assert.equal(value(created.args, "--user"), "1000:1000");
  assert.deepEqual(values(created.args, "--mount"), [`type=volume,source=${volumeNames("codex").cache},target=/cache,readonly`]);
  assert.equal(values(created.args, "--publish").length, 0); assert.equal(values(created.args, "--cap-add").length, 0);
  assert.ok(created.args.includes("WHOOP_LOCAL_CLIENT_ID=codex")); assert.ok(created.args.includes("/app/reader.mjs"));
  const started = commandCalls(fake, "start")[0]; assert.deepEqual(started.options, { interactive: true, persistent: true });
  assert.ok(fake.calls.findIndex(({ args }) => args[0] === "inspect") < fake.calls.indexOf(started));
  assert.equal(commandCalls(fake, "exec").length, 0); assertNoHostAccess(fake); assertDisposed(fake);
});

test("initialization provisions only empty private named volumes while offline", async () => {
  const fake = fakeDocker(); await createLauncher(config, { docker: fake.docker }).init("claude-code");
  const created = commandCalls(fake, "create")[0];
  assert.equal(value(created.args, "--network"), "none"); assert.equal(value(created.args, "--user"), "0:0");
  assert.deepEqual(values(created.args, "--cap-add"), ["CHOWN", "FOWNER"]);
  assert.ok(created.args.includes(FIREWALL_IMAGE)); assert.equal(values(created.args, "--mount").length, 2);
  const script = created.args.at(-1); assert.match(script, /test -z/); assert.match(script, /chmod 700 \/auth \/cache/);
  const provision = JSON.parse(commandCalls(fake, "start")[0].options.input);
  assert.deepEqual(provision, { clientId: "claude-code", origin: config.origin, tokenFile: "/auth/token.json",
    stateFile: "/auth/state.sqlite", cacheFile: "/cache/cache.json" });
  assert.equal(commandCalls(fake, "exec").length, 0); assertNoHostAccess(fake); assertDisposed(fake);
});

test("sync loads application code only after verified firewall success and helper removal", async () => {
  const fake = fakeDocker(); await createLauncher(config, { docker: fake.docker }).sync("codex");
  const [app, helper] = commandCalls(fake, "create"); assert.equal(commandCalls(fake, "create").length, 2);
  const [appId, helperId] = [...fake.containers.keys()];
  assert.equal(value(app.args, "--network"), "bridge"); assert.equal(value(app.args, "--dns"), "0.0.0.0");
  assert.equal(value(app.args, "--add-host"), `health.example.test:${config.approvedIpv4}`);
  assert.deepEqual(app.args.slice(-4), ["-i", "/usr/local/bin/node", "-e", "setInterval(() => {}, 3600000)"]);
  assert.equal(value(helper.args, "--network"), `container:${appId}`);
  assert.deepEqual(values(helper.args, "--cap-add"), ["NET_ADMIN"]); assert.equal(values(helper.args, "--mount").length, 0);
  assert.equal(values(app.args, "--publish").length, 0); assert.equal(values(helper.args, "--publish").length, 0);
  const script = helper.args.at(-1);
  assert.match(script, /iptables -P OUTPUT DROP/); assert.match(script, /ip6tables -P OUTPUT DROP/);
  assert.match(script, /-d 104\.16\.0\.34\/32 --dport 443/); assert.doesNotMatch(script, /--dport 53|--dport 1764[34]/);
  const execIndex = fake.calls.findIndex(({ args }) => args[0] === "exec");
  const helperStart = fake.calls.findIndex(({ args }) => args[0] === "start" && args.at(-1) === helperId);
  const helperExitInspection = fake.calls.findIndex(({ args }, index) => index > helperStart && args[0] === "inspect" && args[1] === helperId);
  const helperRemoval = fake.calls.findIndex(({ args }) => args[0] === "rm" && args[2] === helperId);
  assert.ok(helperStart < helperExitInspection && helperExitInspection < helperRemoval && helperRemoval < execIndex);
  assert.deepEqual(fake.calls[execIndex].args, ["exec", "--interactive", appId, "/usr/bin/env", "-i", "/usr/local/bin/node", "/app/sync.mjs", "/auth/config.json"]);
  assertNoHostAccess(fake); assertDisposed(fake);
});

test("login publishes only the client's fixed loopback callback and explicitly selects container binding", async () => {
  for (const [clientId, port] of [["codex", 17643], ["claude-code", 17644]]) {
    const fake = fakeDocker(); await createLauncher(config, { docker: fake.docker }).login(clientId);
    const [app, helper] = commandCalls(fake, "create");
    assert.deepEqual(values(app.args, "--publish"), [`127.0.0.1:${port}:${port}/tcp`]);
    assert.equal(values(helper.args, "--publish").length, 0);
    assert.match(helper.args.at(-1), new RegExp(`iptables -A INPUT -p tcp --dport ${port} -m conntrack --ctstate NEW -j ACCEPT`));
    assert.deepEqual(commandCalls(fake, "exec")[0].args.slice(-3), ["/app/login.mjs", "/auth/config.json", "--container-callback"]);
    assertNoHostAccess(fake); assertDisposed(fake);
  }
});

test("capability spelling normalization accepts the same allowlist and rejects added, duplicate or substituted capabilities", async () => {
  const bare = fakeDocker({ mutateInspect: (row) => {
    row.HostConfig.CapAdd = row.HostConfig.CapAdd.map((cap) => cap.replace(/^CAP_/, ""));
  } });
  await createLauncher(config, { docker: bare.docker }).init("codex");
  await createLauncher(config, { docker: bare.docker }).sync("codex");
  assertDisposed(bare);
  for (const caps of [["CAP_NET_ADMIN", "CAP_SYS_ADMIN"], ["CAP_NET_ADMIN", "NET_ADMIN"], ["CAP_SYS_ADMIN"], ["CAP_CAP_NET_ADMIN"]]) {
    const fake = fakeDocker({ mutateInspect: (row) => {
      if (row.Image === FIREWALL_IMAGE) row.HostConfig.CapAdd = caps;
    } });
    await assert.rejects(createLauncher(config, { docker: fake.docker }).sync("codex"), /RESTRICTED_LAUNCH_UNAVAILABLE/);
    assert.equal(commandCalls(fake, "exec").length, 0); assertDisposed(fake);
  }
});

test("unapproved volumes and image inspection fail before any container is created", async () => {
  const changes = [
    { mutateVolume: (row) => { row.Driver = "nfs"; } },
    { mutateVolume: (row) => { row.Options = { type: "none", device: "/Users/sensitive", o: "bind" }; } },
    { mutateVolume: (row) => { delete row.Labels.rr_owner_id; } },
    { mutateImage: (row) => { row.Id = `sha256:${"a".repeat(64)}`; } },
    { mutateImage: (row) => { row.Os = "windows"; } },
  ];
  for (const change of changes) {
    const fake = fakeDocker(change); await assert.rejects(createLauncher(config, { docker: fake.docker }).read("codex"));
    assert.equal(commandCalls(fake, "create").length, 0);
  }
});

test("container inspection rejects credential mounts, extra authority and isolation drift before starting", async () => {
  const mutations = [
    (r) => { r.Config.User = "0:0"; }, (r) => { r.Config.Env.push("SSH_AUTH_SOCK=/ssh-agent"); },
    (r) => { r.Config.Entrypoint = ["/bin/sh"]; }, (r) => { r.Config.Cmd = ["attacker.mjs"]; },
    (r) => { r.HostConfig.Privileged = true; }, (r) => { r.HostConfig.ReadonlyRootfs = false; },
    (r) => { r.HostConfig.CapAdd = ["NET_ADMIN"]; }, (r) => { r.HostConfig.CapDrop = []; },
    (r) => { r.HostConfig.SecurityOpt = []; }, (r) => { r.HostConfig.NetworkMode = "host"; },
    (r) => { r.HostConfig.IpcMode = "host"; }, (r) => { r.HostConfig.CgroupnsMode = "host"; },
    (r) => { r.HostConfig.PidMode = "host"; }, (r) => { r.HostConfig.UTSMode = "host"; },
    (r) => { r.HostConfig.Binds = ["/Users:/host:ro"]; }, (r) => { r.HostConfig.VolumesFrom = ["other"]; },
    (r) => { r.HostConfig.Devices = [{ PathOnHost: "/dev/disk0" }]; }, (r) => { r.HostConfig.DeviceRequests = [{}]; },
    (r) => { r.HostConfig.PortBindings = { "80/tcp": [{ HostIp: "0.0.0.0", HostPort: "80" }] }; },
    (r) => { r.HostConfig.MemorySwap = -1; }, (r) => { r.HostConfig.Tmpfs["/tmp"] = "rw,exec"; },
    (r) => { r.Mounts.push({ Type: "bind", Source: "/var/run/docker.sock", Destination: "/socket", RW: true }); },
    (r) => { r.Mounts.find((m) => m.Type === "volume").RW = true; },
    (r) => { r.Mounts.push({ Type: "volume", Name: volumeNames("codex").auth, Destination: "/auth", RW: false }); },
    (r) => { r.State.Running = true; },
  ];
  for (const [index, mutation] of mutations.entries()) {
    const fake = fakeDocker({ mutateInspect: mutation });
    await assert.rejects(createLauncher(config, { docker: fake.docker }).read("codex"), /RESTRICTED_LAUNCH_UNAVAILABLE/, `Mutation ${index}`);
    assert.equal(commandCalls(fake, "start").length, 0, `Mutation ${index} must fail before start`);
    assert.equal(commandCalls(fake, "exec").length, 0); assertDisposed(fake);
  }
});

test("firewall failure, unverifiable exit and namespace drift prevent application execution and clean up", async () => {
  const failures = [
    { intercept: (args) => args[0] === "start" && args.includes("--attach") ? { code: 1, stdout: "" } : undefined },
    { mutateInspect: (row, count) => { if (row.Image === FIREWALL_IMAGE && count === 2) row.State.Running = true; } },
    { mutateInspect: (row, count) => { if (row.Image === FIREWALL_IMAGE && count === 2) row.State.ExitCode = 1; } },
    { mutateInspect: (row, count) => { if (row.Image === config.syncImage && count === 2) row.HostConfig.ExtraHosts = ["health.example.test:127.0.0.1"]; } },
    { mutateInspect: (row, count) => { if (row.Image === config.syncImage && count === 2) row.HostConfig.Dns = ["1.1.1.1"]; } },
    { mutateInspect: (row) => { if (row.Image === FIREWALL_IMAGE) row.HostConfig.NetworkMode = "host"; } },
  ];
  for (const failure of failures) {
    const fake = fakeDocker(failure); await assert.rejects(createLauncher(config, { docker: fake.docker }).sync("codex"));
    assert.equal(commandCalls(fake, "exec").length, 0); assertDisposed(fake);
  }
});

test("application failure still removes both created containers and cleanup can retry an exact failed ID", async () => {
  const appFailure = fakeDocker({ intercept: (args) => args[0] === "exec" ? { code: 1, stdout: "" } : undefined });
  await assert.rejects(createLauncher(config, { docker: appFailure.docker }).sync("codex")); assertDisposed(appFailure);
  let failedOnce = false;
  const fake = fakeDocker({ intercept: (args) => {
    if (args[0] === "rm" && !failedOnce) { failedOnce = true; return { code: 1, stdout: "" }; }
    return undefined;
  } });
  const launcher = createLauncher(config, { docker: fake.docker });
  await assert.rejects(launcher.sync("codex")); assert.equal(commandCalls(fake, "exec").length, 0);
  await launcher.dispose(); assertDisposed(fake);
  assert.ok(commandCalls(fake, "rm").every(({ args }) => /^[a-f0-9]{64}$/.test(args[2])));
  assertNoHostAccess(fake);
});
