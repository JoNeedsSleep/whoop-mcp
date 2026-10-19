import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable, PassThrough } from 'node:stream';
import test from 'node:test';
import { guard, parseEnvelope, provisionBackend } from './provision.mjs';
import { backendEnvironment, readBackendDatabaseCa, readPrivateJson } from '../railway/config.mjs';
const environment = { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', NODE_ENV: 'production' };
const identity = { getuid: () => 1000, getgid: () => 1000, geteuid: () => 1000, getegid: () => 1000 };
const runtime = { role: 'backend', hostname: 'backend.test-tailnet.ts.net', stateDirectory: '/data/tailscale', appConfigFile: '/data/config/app.json' };
const whoop = { mode: 'whoop-owner-identity', hostname: runtime.hostname, clientId: 'synthetic-client', clientSecret: 'synthetic-client-secret' };
const fail = /^Error: BACKEND_PROVISION_UNAVAILABLE$/;
const ca = () => fs.readFileSync(process.env.GATEWAY_TEST_TLS_DIR + '/ca.pem', 'utf8');
const envelope = () => ({ mode: 'whoop-backend-config', verifiedOwnerId: '123', caCertificate: ca(), app: {
  DATABASE_HOST: 'whoop-db.railway.internal', DATABASE_URL: 'postgresql://whoop_runtime:' + 'a'.repeat(64) + '@whoop-db.railway.internal:5432/whoop?sslmode=verify-full&sslrootcert=%2Fdata%2Fconfig%2Fdb-ca.pem',
  ENCRYPTION_KEY: 'b'.repeat(64), SESSION_SECRET: 'c'.repeat(64), WHOOP_CLIENT_ID: whoop.clientId, WHOOP_CLIENT_SECRET: whoop.clientSecret,
  PUBLIC_BASE_URL: 'https://' + runtime.hostname, ALLOWED_WHOOP_USER_ID: '123', GATEWAY_SERVICE_TOKEN_SHA256: 'd'.repeat(64) } });
const input = value => Readable.from([Buffer.from(typeof value === 'string' ? value : JSON.stringify(value))]);
function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'backend-provision-test-'));
  for (const name of ['config','tailscale']) fs.mkdirSync(path.join(root, name), { mode: 0o700 });
  for (const [name,value] of [['runtime.json',runtime],['identity.json',whoop]]) fs.writeFileSync(path.join(root,'config',name), JSON.stringify(value), { mode: 0o600 });
  fs.writeFileSync(path.join(root,'tailscale','tailscaled.state'), 'synthetic-node-state', { mode: 0o600 });
  return { root, clean: () => fs.rmSync(root,{recursive:true,force:true}), options: { root, environment } };
}

test('identity and NNP guard run before environment values or private input', async () => {
  const env = Object.defineProperty({}, 'WHOOP_BACKEND_APP_BOOTSTRAP', { enumerable: true, get() { assert.fail('read secret'); } });
  for (const field of ['getuid','getgid','geteuid','getegid']) assert.throws(() => guard({ identity: {...identity,[field]:()=>0}, environment: env, noNewPrivileges() { assert.fail('wrong identity'); } }), fail);
  assert.throws(() => guard({ identity, environment:env,noNewPrivileges(){throw Error('blocked');} }), /blocked/);
  assert.throws(() => guard({ identity, environment:env,noNewPrivileges(){} }), fail);
  const stream = new PassThrough();
  await assert.rejects(provisionBackend({ identity:{...identity,getuid:()=>0},environment:env,input:stream }), fail);
  assert.equal(stream.listenerCount('data'),0);stream.destroy();
});
test('only the fixed cleared environment is admitted', () => {
  guard({identity,environment,noNewPrivileges(){}});
  guard({identity,environment:{...environment,UV_USE_IO_URING:'0'},noNewPrivileges(){}});
  for (const patch of [{NODE_OPTIONS:'--inspect'},{HTTP_PROXY:'https://bad.invalid'},{UV_USE_IO_URING:'1'},{HOME:'/root'},{WHOOP_BACKEND_APP_BOOTSTRAP:'sentinel'}])
    assert.throws(()=>guard({identity,environment:{...environment,...patch},noNewPrivileges(){}}),fail);
});
test('exact existing backend identity, approved numeric owner and runtime-only TLS credentials are required', () => {
  const raw=envelope();assert.deepEqual(parseEnvelope(raw,runtime,whoop),{app:raw.app,caCertificate:raw.caCertificate});
  for(const patch of [{verifiedOwnerId:'124'},{verifiedOwnerId:123},{verifiedOwnerId:'01'},{verifiedOwnerId:'9007199254740992'},{mode:'gateway'},{enrollmentKey:'no'}])
    assert.throws(()=>parseEnvelope({...raw,...patch},runtime,whoop),fail);
  for(const app of [{...raw.app,ALLOWED_WHOOP_USER_ID:'124'},{...raw.app,WHOOP_CLIENT_ID:'other'},{...raw.app,WHOOP_CLIENT_SECRET:'other'},
    {...raw.app,PUBLIC_BASE_URL:'https://other.test-tailnet.ts.net'},{...raw.app,RUN_MIGRATIONS:'true'},
    {...raw.app,DATABASE_URL:raw.app.DATABASE_URL.replace('whoop_runtime','whoop_migrate')},{...raw.app,DATABASE_URL:raw.app.DATABASE_URL.replace('/whoop?','/postgres?')},
    {...raw.app,DATABASE_URL:raw.app.DATABASE_URL.replace('verify-full','require')},{...raw.app,SESSION_SECRET:'short'},
    {...raw.app,SESSION_SECRET:raw.app.ENCRYPTION_KEY},{...raw.app,GATEWAY_SERVICE_TOKEN_SHA256:'raw-secret'}])
    assert.throws(()=>parseEnvelope({...raw,app},runtime,whoop),fail);
  assert.throws(()=>parseEnvelope(raw,{...runtime,role:'gateway',backendIpv4:'100.64.1.2'},whoop),fail);
  assert.throws(()=>parseEnvelope(raw,runtime,{...whoop,hostname:'other.test-tailnet.ts.net'}),fail);
});
test('CA input rejects leaf certificates, private keys, garbage and excessive PEM chains', () => {
  const raw=envelope();
  for(const value of ['sentinel',raw.caCertificate+'sentinel',raw.caCertificate.repeat(5),
    fs.readFileSync(process.env.GATEWAY_TEST_TLS_DIR+'/server.pem','utf8'),fs.readFileSync(process.env.GATEWAY_TEST_TLS_DIR+'/server-key.pem','utf8')])
    assert.throws(()=>parseEnvelope({...raw,caCertificate:value},runtime,whoop),fail);
});
test('successful file delivery preserves identity/node state and satisfies ordinary loaders; duplicate refuses', async () => {
  const f=fixture();try {
    const originals=Object.fromEntries(['config/identity.json','config/runtime.json','tailscale/tailscaled.state'].map(n=>[n,fs.readFileSync(path.join(f.root,n))]));
    const raw=envelope();assert.deepEqual(await provisionBackend({...f.options,input:input(raw)}),{phase:'backend-configured-awaiting-clean-redeploy'});
    const directory=path.join(f.root,'config');assert.deepEqual(fs.readdirSync(directory).sort(),['.backend-config-attempt','app.json','db-ca.pem','identity.json','runtime.json']);
    assert.deepEqual(readPrivateJson(path.join(directory,'app.json')),raw.app);
    assert.equal(readBackendDatabaseCa(path.join(directory,'db-ca.pem')),raw.caCertificate);
    const env=backendEnvironment(readPrivateJson(path.join(directory,'app.json')),runtime.hostname);
    assert.equal(env.RUN_MIGRATIONS,'false');assert.equal(env.ENABLE_LEGACY_DIRECT_MCP,'false');assert.equal(env.BIND_HOST,'127.0.0.1');
    for(const name of ['app.json','db-ca.pem','.backend-config-attempt']) {const st=fs.lstatSync(path.join(directory,name));assert(st.isFile()&&st.nlink===1&&st.uid===1000&&(st.mode&511)===384);}
    for(const [name,bytes]of Object.entries(originals))assert.deepEqual(fs.readFileSync(path.join(f.root,name)),bytes);
    await assert.rejects(provisionBackend({...f.options,input:input(raw)}),fail);
  }finally{f.clean();}
});
test('invalid/oversized/UTF8/stalled/canceled input leaves the existing config untouched', async () => {
  const f=fixture();try {
    for(const stream of [input('{"secret":"sentinel"'),input('x'.repeat(16385)),Readable.from([Buffer.from([255])]),input({...envelope(),verifiedOwnerId:'0'})])
      await assert.rejects(provisionBackend({...f.options,input:stream}),fail);
    const pending=new PassThrough();await assert.rejects(provisionBackend({...f.options,input:pending,timeoutMs:10}),fail);assert.equal(pending.listenerCount('data'),0);pending.destroy();
    const cancel=new AbortController(),stream=new PassThrough();const result=provisionBackend({...f.options,input:stream,signal:cancel.signal});cancel.abort();await assert.rejects(result,fail);stream.destroy();
    assert.deepEqual(fs.readdirSync(path.join(f.root,'config')).sort(),['identity.json','runtime.json']);
  }finally{f.clean();}
});
test('unsafe existing modes, symlinks, missing state and partial claims refuse without overwrite', async () => {
  for(const mutate of [f=>fs.chmodSync(path.join(f.root,'config'),0o755),f=>fs.chmodSync(path.join(f.root,'config','identity.json'),0o644),
    f=>fs.unlinkSync(path.join(f.root,'tailscale','tailscaled.state')),f=>{fs.unlinkSync(path.join(f.root,'config','identity.json'));fs.symlinkSync('/etc/passwd',path.join(f.root,'config','identity.json'));},
    f=>fs.writeFileSync(path.join(f.root,'config','.backend-config-attempt'),'prior',{mode:0o600}),
    f=>fs.writeFileSync(path.join(f.root,'config','app.json'),'prior',{mode:0o600})]) {
    const f=fixture();try{mutate(f);await assert.rejects(provisionBackend({...f.options,input:input(envelope())}),fail);assert(!fs.existsSync(path.join(f.root,'config','db-ca.pem')));}finally{f.clean();}
  }
});
test('concurrent attempts publish exactly once without replacing existing bindings', async () => {
  const f=fixture();try{
    const outcomes=await Promise.allSettled([provisionBackend({...f.options,input:input(envelope())}),provisionBackend({...f.options,input:input(envelope())})]);
    assert.equal(outcomes.filter(v=>v.status==='fulfilled').length,1);assert.equal(outcomes.filter(v=>v.status==='rejected').length,1);
    assert.deepEqual(readPrivateJson(path.join(f.root,'config','runtime.json')),runtime);
  }finally{f.clean();}
});
test('a destination appearing during input admission is never overwritten and app stays unpublished', async () => {
  const f=fixture();try {
    const stream=new PassThrough();const pending=provisionBackend({...f.options,input:stream});
    fs.writeFileSync(path.join(f.root,'config','db-ca.pem'),'prior-marker',{mode:0o600});
    stream.end(Buffer.from(JSON.stringify(envelope())));
    await assert.rejects(pending,fail);
    assert.equal(fs.readFileSync(path.join(f.root,'config','db-ca.pem'),'utf8'),'prior-marker');
    assert(!fs.existsSync(path.join(f.root,'config','app.json')));
    assert(fs.existsSync(path.join(f.root,'config','.backend-config-attempt')));
    await assert.rejects(provisionBackend({...f.options,input:input(envelope())}),fail);
  }finally{f.clean();}
});
