import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { BOOTSTRAP_VARIABLE, initializeIdentityVolume, parseIdentityProvision, provisionIdentity, provisionIdentityInput } from './provision.mjs';
import { parseIdentityConfig } from './verify.mjs';

const identity = values => Object.fromEntries(['getuid','getgid','geteuid','getegid'].map((key,index) => [key,() => values?.[index] ?? 1000]));
const failure = { message: 'BACKEND_IDENTITY_PROVISIONING_UNAVAILABLE' };
const forbidden = () => assert.fail('unexpected operation');
const config = { mode: 'whoop-owner-identity', hostname: 'backend.test-tailnet.ts.net', clientId: 'synthetic-client', clientSecret: 'synthetic-secret-sentinel' };
const payload = () => ({ mode: 'whoop-owner-identity-bootstrap', identity: { ...config }, enrollmentKey: 'tskey-auth-' + 's'.repeat(32) });
function fixture(t) {
  assert.equal(process.getuid(),1000, 'approved isolated fixture required');
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'identity-provision-'));fs.chmodSync(root,0o700);
  for(const name of ['config','tailscale'])fs.mkdirSync(path.join(root,name),0o700);
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  return {root,env:{[BOOTSTRAP_VARIABLE]:JSON.stringify(payload())},identity:identity(),noNewPrivileges:()=>{},runtimeCheck:()=>{},enroll:forbidden};
}
function fakeVolume({names=[],badPath,badInfo,children={}}={}) {
  const actions=[];
  const filesystem={lstatSync:p=>p===badPath?badInfo:{isDirectory:()=>true,isSymbolicLink:()=>false,uid:0,mode:p==='/data'?0o755:0o700},
    readdirSync:p=>p==='/data'?names:children[p]??[],mkdirSync:(...args)=>actions.push(['mkdir',...args]),chownSync:(...args)=>actions.push(['chown',...args])};
  return {filesystem,actions,root:'/data',identity:identity([0,0,0,0]),environment:{},noNewPrivileges:()=>{}};
}

test('root initialization touches only empty fixed directories after validating every existing path',()=>{
  const f=fakeVolume();initializeIdentityVolume(f);assert.deepEqual(f.actions,[['mkdir','/data/config',{mode:0o700}],['chown','/data/config',1000,1000],['mkdir','/data/tailscale',{mode:0o700}],['chown','/data/tailscale',1000,1000]]);
  for(const options of [{names:['unrelated']},{names:['config','tailscale'],children:{'/data/tailscale':['tailscaled.state']}},
    {names:['config'],badPath:'/data/config',badInfo:{isDirectory:()=>true,isSymbolicLink:()=>true,uid:0,mode:0o700}},
    {names:['config'],badPath:'/data/config',badInfo:{isDirectory:()=>true,isSymbolicLink:()=>false,uid:0,mode:0o755}}]){
    const f=fakeVolume(options);assert.throws(()=>initializeIdentityVolume(f),failure);assert.deepEqual(f.actions,[]);
  }
});

test('root initialization rejects privilege/kernel/bootstrap problems without secret getters or filesystem access',()=>{
  for(let index=0;index<4;index++){
    const ids=[0,0,0,0];ids[index]=1000;
    assert.throws(()=>initializeIdentityVolume({...fakeVolume(),identity:identity(ids),filesystem:new Proxy({},{get:forbidden})}),failure);
  }
  const environment=Object.defineProperty({},BOOTSTRAP_VARIABLE,{enumerable:true,get:forbidden});
  assert.throws(()=>initializeIdentityVolume({...fakeVolume(),environment,filesystem:new Proxy({},{get:forbidden})}),failure);
  assert.throws(()=>initializeIdentityVolume({...fakeVolume(),noNewPrivileges:()=>{throw Error('private detail');},environment:new Proxy({},{ownKeys:forbidden}),filesystem:new Proxy({},{get:forbidden})}),failure);
});

test('identity provisioning requires real/effective UID/GID1000 and NNP before reading any bootstrap',async()=>{
  for(let index=0;index<4;index++)for(const bad of [0,1001]){
    const ids=[1000,1000,1000,1000];ids[index]=bad;
    await assert.rejects(provisionIdentity({identity:identity(ids),env:new Proxy({},{get:forbidden,ownKeys:forbidden}),noNewPrivileges:forbidden}),failure);
  }
  await assert.rejects(provisionIdentity({identity:identity(),env:new Proxy({},{get:forbidden,ownKeys:forbidden}),noNewPrivileges:()=>{throw Error('private detail');}}),failure);
});

test('envelope permits identity-only exact config and rejects app, database, role or endpoint additions',()=>{
  assert.deepEqual(parseIdentityConfig(parseIdentityProvision(payload()).identity),config);
  for(const raw of [{...payload(),mode:'synthetic-fixture-only'},{...payload(),role:'gateway'},{...payload(),DATABASE_URL:'secret'},
    {...payload(),identity:{...config,mode:'backend'}},{...payload(),identity:{...config,hostname:'public.example'}},
    {...payload(),identity:{...config,ALLOWED_WHOOP_USER_ID:'123'}},{...payload(),identity:{...config,clientSecret:'line\nbreak'}},
    {...payload(),identity:{...config,clientId:'x'.repeat(2049)}},{...payload(),enrollmentKey:'wrong'}])assert.throws(()=>parseIdentityProvision(raw),failure);
});

test('malformed, oversized and foreign environment inputs fail without writes or enrollment',async t=>{
  for(const value of ['{', 'x'.repeat(8193), '\ud800', JSON.stringify({...payload(),extra:true})]){
    const f=fixture(t);f.env[BOOTSTRAP_VARIABLE]=value;
    await assert.rejects(provisionIdentity(f),failure);assert.equal(Object.hasOwn(f.env,BOOTSTRAP_VARIABLE),false);
    assert.deepEqual(fs.readdirSync(path.join(f.root,'config')),[]);
  }
  for(const key of ['WHOOP_CLIENT_SECRET','DATABASE_URL','PGPASSWORD','TS_AUTHKEY','NODE_OPTIONS','HTTPS_PROXY']){
    const f=fixture(t);Object.defineProperty(f.env,key,{enumerable:true,get:forbidden});
    await assert.rejects(provisionIdentity(f),failure);assert.deepEqual(fs.readdirSync(path.join(f.root,'config')),[]);
  }
});

test('successful one-use provisioning deletes bootstrap, writes only two private files and enrolls exact backend',async t=>{
  const f=fixture(t);const actions=[];let closed=false;
  f.runtimeCheck=(...args)=>{assert.deepEqual(args,[]);assert.equal(Object.hasOwn(f.env,BOOTSTRAP_VARIABLE),false);assert.deepEqual(fs.readdirSync(path.join(f.root,'config')),[]);actions.push('report');};
  f.enroll=async options=>{actions.push('enroll');assert.deepEqual(options,{stateDirectory:path.join(f.root,'tailscale'),tag:'tag:whoop-backend',hostname:config.hostname,port:8080,enrollmentKey:payload().enrollmentKey});return{close:async()=>{closed=true;}};};
  assert.deepEqual(await provisionIdentity(f),{phase:'identity-enrolled-awaiting-clean-redeploy'});assert.deepEqual(actions,['report','enroll']);assert.equal(closed,true);
  assert.deepEqual(fs.readdirSync(path.join(f.root,'config')).sort(),['identity.json','runtime.json']);
  for(const name of ['identity.json','runtime.json']){const st=fs.lstatSync(path.join(f.root,'config',name));assert(st.isFile());assert.equal(st.mode&0o777,0o600);assert.equal(st.uid,1000);assert.equal(st.nlink,1);}
  assert.deepEqual(parseIdentityConfig(JSON.parse(fs.readFileSync(path.join(f.root,'config','identity.json')))),config);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(f.root,'config','runtime.json'))),{role:'backend',hostname:config.hostname,stateDirectory:'/data/tailscale',appConfigFile:'/data/config/app.json'});
  f.env[BOOTSTRAP_VARIABLE]=JSON.stringify(payload());f.enroll=forbidden;await assert.rejects(provisionIdentity(f),failure);
});

test('used, partial, symlinked or populated state cannot be overwritten or re-enrolled',async t=>{
  for(const which of ['config','tailscale']){
    const f=fixture(t);const file=path.join(f.root,which,'prior');fs.writeFileSync(file,'prior-owned-content');
    await assert.rejects(provisionIdentity(f),failure);assert.equal(fs.readFileSync(file,'utf8'),'prior-owned-content');
  }
  const linked=fixture(t);fs.renameSync(path.join(linked.root,'config'),path.join(linked.root,'original'));fs.symlinkSync(path.join(linked.root,'original'),path.join(linked.root,'config'));
  await assert.rejects(provisionIdentity(linked),failure);assert.deepEqual(fs.readdirSync(path.join(linked.root,'original')),[]);
  const f=fixture(t);f.enroll=async()=>{throw Error('private enrollment detail');};
  await assert.rejects(provisionIdentity(f),failure);assert.equal(fs.existsSync(path.join(f.root,'config','identity.json')),true);
  f.env[BOOTSTRAP_VARIABLE]=JSON.stringify(payload());f.enroll=forbidden;await assert.rejects(provisionIdentity(f),failure);
});

test('concurrent attempts cannot create two enrollments or replace the first identity',async t=>{
  const f=fixture(t);let calls=0;let release;const blocked=new Promise(resolve=>{release=resolve;});
  const first=provisionIdentity({...f,enroll:async()=>{calls++;await blocked;return{close:async()=>{}};}});
  try{await assert.rejects(provisionIdentity({...f,env:{[BOOTSTRAP_VARIABLE]:JSON.stringify(payload())}}),failure);assert.equal(calls,1);}finally{release();}
  await first;assert.deepEqual(parseIdentityConfig(JSON.parse(fs.readFileSync(path.join(f.root,'config','identity.json')))),config);
});

test('actual unprivileged CLI rejects root init and malformed provisioning without printing input',()=>{
  for(const args of [['init-volume'],['provision-identity'],['unknown'],[]]){
    const child=spawnSync(process.execPath,[fileURLToPath(new URL('./provision.mjs',import.meta.url)),...args],{env:{PATH:'/usr/local/bin:/usr/bin:/bin',[BOOTSTRAP_VARIABLE]:'private-secret-sentinel-invalid'},encoding:'utf8',timeout:5000});
    assert.equal(child.status,1);assert.equal(child.stdout,'');assert.equal(child.stderr,'Backend identity provisioning unavailable; inspect the stopped attempt before retrying.\n');assert(!child.stderr.includes('sentinel'));
  }
});


test('clean stdin bridge rechecks identity before input and enforces byte/type/UTF-8 bounds',async t=>{
  const input={get isTTY(){return false;},[Symbol.asyncIterator]:forbidden};
  await assert.rejects(provisionIdentityInput(input,{identity:identity([0,0,0,0]),noNewPrivileges:forbidden}),failure);
  for(const chunks of [[Buffer.alloc(8193,65)],[Buffer.from([255,254])],[],['not-bytes']]){
    const f=fixture(t);await assert.rejects(provisionIdentityInput(Readable.from(chunks),f),failure);
    assert.deepEqual(fs.readdirSync(path.join(f.root,'config')),[]);
  }
  const f=fixture(t);let enrolled=false;f.enroll=async()=>{enrolled=true;return{close:async()=>{}};};
  await provisionIdentityInput(Readable.from([Buffer.from(JSON.stringify(payload()))]),f);assert.equal(enrolled,true);
});
