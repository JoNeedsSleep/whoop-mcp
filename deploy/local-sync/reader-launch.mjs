// Host-side operator bridge for the two dedicated local WHOOP cache volumes.
// It has no authorization, sync, enrollment, volume-management or network path.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const READER_IMAGE = 'sha256:a1b4280ff3a0d418e642408f2e7c9941b1eddd4179141a7b9a562bc97e906758';
export const DOCKER = '/usr/local/bin/docker';
export const DOCKER_HOST = `unix://${os.homedir()}/.orbstack/run/docker.sock`;
// Exact immutable generation labels; no authorization or config is read here.
export const CACHE_GENERATION = '20261022a';
const ID = /^[a-f0-9]{64}$/;
const ERROR = 'Offline WHOOP reader unavailable.';
const fail = () => { throw new Error(ERROR); };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const sorted = (a) => [...(a ?? [])].sort();
const empty = (a) => a == null || (Array.isArray(a) ? a.length === 0 : Object.keys(a).length === 0);
const TMPFS = 'rw,noexec,nosuid,nodev,size=16m,mode=1777';
// Independent fallback when the native client kills this host bridge before its
// finally block can remove the container. This also ends healthy sessions.
export const READER_LIFETIME_MS = 86400000;
export const READER_LIFETIME_SCRIPT = 'setTimeout(() => process.exit(0), 86400000)';
const INERT = ['-i', '/usr/local/bin/node', '-e', READER_LIFETIME_SCRIPT];
export function cacheSpec(client) {
  if (!['codex', 'claude-code'].includes(client)) fail();
  return { name: `whoop_individual_sub-local-${client}_cache_kill-2026-11-18`, labels: {
    rr_project_id: 'whoop', rr_owner_id: 'individual', rr_kill_date: '2026-11-18',
    rr_purpose: 'local-whoop-sync', rr_client_id: client, rr_local_generation: CACHE_GENERATION,
  } };
}
function verifyVolume(value, spec) {
  if (value.Name !== spec.name || value.Driver !== 'local' || !empty(value.Options) ||
      !same(Object.entries(value.Labels ?? {}).sort(), Object.entries(spec.labels).sort())) fail();
}
function verifyImage(image) {
  if (image.Id !== READER_IMAGE || image.Os !== 'linux' || image.Architecture !== 'arm64' ||
      !empty(image.Config?.Volumes) || !empty(image.Config?.OnBuild) ||
      !same(sorted(image.Config?.Env), sorted(['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'NODE_VERSION=22.23.3', 'YARN_VERSION=1.22.22']))) fail();
}
function verifyContainer(value, spec, image, running) {
  const h = value.HostConfig; const c = value.Config;
  if (!h || !c || value.Id !== spec.id || value.Name !== `/${spec.name}` || value.Image !== READER_IMAGE ||
      c.User !== '1000:1000' || c.Entrypoint?.length !== 1 || c.Entrypoint[0] !== '/usr/bin/env' ||
      !same(c.Cmd, INERT) || !same(sorted(c.Env), sorted(image.Config.Env)) ||
      !same(Object.entries(c.Labels ?? {}).sort(), Object.entries(spec.labels).sort()) ||
      value.State?.Running !== running || h.Privileged !== false || h.ReadonlyRootfs !== true || h.AutoRemove !== true ||
      !same(h.CapDrop, ['ALL']) || !empty(h.CapAdd) ||
      ![['no-new-privileges=true'], ['no-new-privileges:true']].some((x) => same(x, h.SecurityOpt)) ||
      h.NetworkMode !== 'none' || h.IpcMode !== 'none' || h.CgroupnsMode !== 'private' ||
      h.Memory !== 134217728 || h.MemorySwap !== 134217728 || h.NanoCpus !== 500000000 || h.PidsLimit !== 64 ||
      h.PublishAllPorts !== false || !same(h.Tmpfs, { '/tmp': TMPFS }) ||
      ['Binds','VolumesFrom','Devices','DeviceRequests','PidMode','UTSMode','UsernsMode','PortBindings','ExtraHosts','Dns']
        .some((key) => !empty(h[key])) ||
      !same((h.Ulimits ?? []).map(({Name,Soft,Hard}) => [Name,Soft,Hard]).sort(), [['core',0,0],['nofile',512,512]])) fail();
  const mounts = value.Mounts ?? [];
  if (mounts.filter((m) => m.Type === 'volume').length !== 1 || mounts.some((m) =>
    m.Type === 'volume' ? m.Name !== spec.cache.name || m.Destination !== '/cache' || m.RW !== false || m.Driver !== 'local' :
    m.Type !== 'tmpfs' || m.Destination !== '/tmp')) fail();
}
const PREFLIGHT = `const fs=require('node:fs'),a=require('node:assert/strict');
 a.deepEqual([process.getuid(),process.geteuid(),process.getgid(),process.getegid()],[1000,1000,1000,1000]);
 a.equal(Object.keys(process.env).length,0);const s=fs.readFileSync('/proc/self/status','utf8');
 for(const k of ['CapInh','CapPrm','CapEff','CapAmb'])a.match(s,new RegExp('^'+k+':\\\\s+0+$','m'));
 a.match(s,/^NoNewPrivs:\\s+1$/m);a.match(s,/^Seccomp:\\s+2$/m);
 a.equal(fs.readFileSync('/proc/net/route','utf8').trim().split('\\n').length,1);
 for(const p of ['/auth','/state','/transport','/var/run/docker.sock','/run/host-services/ssh-auth.sock'])a.equal(fs.existsSync(p),false);`;

// Test injection only: the CLI never accepts an executable, socket or driver.
export function createDockerDriver(directory, { spawnImpl = spawn } = {}) {
  const prefix = ['--config', directory, '--host', DOCKER_HOST];
  function child(args) {
    return spawnImpl(DOCKER, [...prefix, ...args], { env: { PATH: '/usr/local/bin:/usr/bin:/bin' }, stdio: ['pipe','pipe','pipe'] });
  }
  function run(args, { signal } = {}) {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) { reject(new Error(ERROR)); return; }
      const p = child(args); const chunks = [[],[]]; let bytes = 0; let failed = false; let killTimer;
      const abort = () => { failed = true; p.kill('SIGKILL'); killTimer ??= setTimeout(() => finish(null), 2000); };
      const timer = setTimeout(abort, 30000);
      const finish = (code) => { clearTimeout(timer); clearTimeout(killTimer); signal?.removeEventListener('abort', abort);
        if (failed || code === null) reject(new Error(ERROR));
        else resolve({ code, stdout: Buffer.concat(chunks[0]).toString('utf8'), stderr: Buffer.concat(chunks[1]).toString('utf8') }); };
      p.once('error', abort); p.once('close', finish);
      [p.stdout,p.stderr].forEach((s,i) => s.on('data', (b) => { bytes += b.length; if (bytes > 1048576) abort(); else chunks[i].push(b); }));
      p.stdin.on('error', () => {}); p.stdin.end(); signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) abort();
    });
  }
  function stream(args, { input, output, signal }) {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) { reject(new Error(ERROR)); return; }
      const p = child(args); let failed = false; let eofTimer; let killTimer;
      const abort = () => { failed = true; p.kill('SIGKILL'); killTimer ??= setTimeout(() => finish(null), 2000); };
      const ended = () => { eofTimer ??= setTimeout(abort, 5000); };
      const finish = (code) => { clearTimeout(eofTimer); clearTimeout(killTimer);
        input.unpipe(p.stdin); p.stdout.unpipe(output); signal?.removeEventListener('abort', abort);
        input.removeListener('end', ended); input.removeListener('error', abort); output.removeListener('error', abort);
        if (failed || code !== 0) reject(new Error(ERROR)); else resolve(); };
      p.once('error', abort); p.once('close', finish);
      p.stdin.on('error', () => {}); p.stderr.resume(); // Never copy daemon/app diagnostics or data to logs.
      input.once('end', ended); input.once('error', abort); output.once('error', abort);
      signal?.addEventListener('abort', abort, { once: true });
      input.pipe(p.stdin); p.stdout.pipe(output, { end: false });
      if (input.readableEnded) { p.stdin.end(); ended(); }
      if (signal?.aborted) abort();
    });
  }
  return { run, stream };
}
export async function runReaderBridge(client, { docker, input = process.stdin, output = process.stdout, signal } = {}) {
  const cache = cacheSpec(client); const nonce = randomBytes(16).toString('hex');
  const spec = { cache, name: `whoop_individual_sub-reader-${client}_${nonce}_kill-2026-11-18`, labels: {
    rr_project_id:'whoop', rr_owner_id:'individual', rr_purpose:'offline-reader-bridge', rr_client_id:client,
    rr_reader_attempt:nonce, rr_kill_date:'2026-11-18', 'dev.orbstack.add-ca-certificates':'false',
  } };
  let directory; let owned; let uncertain = false;
  if (!docker) {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), 'whoop-reader-docker-')); fs.chmodSync(directory,0o700);
    fs.writeFileSync(path.join(directory,'config.json'),'{"auths":{}}',{mode:0o600,flag:'wx'});
    docker = createDockerDriver(directory);
  }
  const checked = async (args, options) => { const r = await docker.run(args,options); if (r.code !== 0) fail(); return r; };
  const one = async (args, options) => { const v=JSON.parse((await checked(args,options)).stdout);
    if (!Array.isArray(v) || v.length!==1 || !v[0] || typeof v[0] !== 'object') fail(); return v[0]; };
  const options = { signal };
  try {
    verifyVolume(await one(['volume','inspect',cache.name],options),cache);
    const image = await one(['image','inspect',READER_IMAGE],options); verifyImage(image);
    const labels = Object.entries(spec.labels).flatMap(([k,v])=>['--label',`${k}=${v}`]);
    const args = ['create','--pull=never','--rm','--name',spec.name,...labels,'--read-only','--user','1000:1000',
      '--network','none','--ipc','none','--cgroupns','private','--cap-drop','ALL','--security-opt','no-new-privileges=true',
      '--memory','128m','--memory-swap','128m','--cpus','0.5','--pids-limit','64','--ulimit','core=0:0','--ulimit','nofile=512:512',
      '--tmpfs',`/tmp:${TMPFS}`,'--mount',`type=volume,source=${cache.name},target=/cache,readonly`,
      '--entrypoint','/usr/bin/env',READER_IMAGE,...INERT];
    const belongs = (obj) => obj && ID.test(obj.Id) && obj.Name === `/${spec.name}` && obj.Image === READER_IMAGE &&
      // These are ownership fields; the CA policy is verified separately as a
      // security control so a proven-owned container with that drift is removed.
      same(Object.entries(obj.Config?.Labels ?? {}).filter(([k]) => k !== 'dev.orbstack.add-ca-certificates').sort(),
        Object.entries(spec.labels).filter(([k]) => k !== 'dev.orbstack.add-ca-certificates').sort());
    uncertain = true;
    let initial;
    try {
      const candidate=(await checked(args,options)).stdout.trim(); if (!ID.test(candidate)) fail();
      initial=await one(['inspect',candidate],options);
      if (initial.Id !== candidate || !belongs(initial)) fail();
      owned=candidate; uncertain=false;
    } catch {
      // A create can time out or return a mismatched ID. Recover only this
      // random attempt, never acquire cleanup authority from a reply ID alone.
      const r=await docker.run(['inspect',spec.name]);
      if (r.code===0) { const v=JSON.parse(r.stdout); const obj=Array.isArray(v)&&v.length===1?v[0]:null;
        if (belongs(obj)) { owned=obj.Id; uncertain=false; } }
      throw new Error(ERROR);
    }
    spec.id=owned; verifyContainer(initial,spec,image,false);
    await checked(['start',owned],options);
    verifyContainer(await one(['inspect',owned],options),spec,image,true);
    verifyVolume(await one(['volume','inspect',cache.name],options),cache);
    await checked(['exec',owned,'/usr/bin/env','-i','/usr/local/bin/node','-e',PREFLIGHT],options);
    await docker.stream(['exec','--interactive',owned,'/usr/bin/env','-i','WHOOP_LOCAL_CACHE_FILE=/cache/cache.json',
      `WHOOP_LOCAL_CLIENT_ID=${client}`,'/usr/local/bin/node','/app/reader.mjs'],{input,output,signal});
  } finally {
    try {
      if (owned) {
        await docker.run(['rm','--force',owned]);
        const r=await docker.run(['inspect',owned]);
        if (r.code===0 || !r.stderr.toLowerCase().includes(owned) || !/no such (object|container)/i.test(r.stderr)) fail();
      }
      if (uncertain) fail(); // An ambiguous create is never reported as successful cleanup.
    } finally { if (directory) fs.rmSync(directory,{recursive:true,force:true}); }
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const controller=new AbortController(); const stop=()=>controller.abort();
  process.on('SIGINT',stop); process.on('SIGTERM',stop);
  try { if (process.argv.length!==3) fail(); await runReaderBridge(process.argv[2],{signal:controller.signal}); }
  catch { process.stderr.write(`${ERROR}\n`); process.exitCode=1; }
  finally { process.removeListener('SIGINT',stop); process.removeListener('SIGTERM',stop); }
}
