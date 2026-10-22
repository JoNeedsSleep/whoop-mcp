import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Readable, PassThrough } from 'node:stream';
import { spawnSync } from 'node:child_process';
import { runLocalSyncRuntime, SYNC_ABORT_MS } from './runtime.mjs';

const identity=Object.fromEntries(['getuid','geteuid','getgid','getegid'].map(key=>[key,()=>1000]));
const environment={PATH:'/usr/local/bin:/usr/bin:/bin'};
const config={mode:'whoop-local-sync',clientId:'synthetic-client',clientSecret:'synthetic-secret'};
const failure={message:'LOCAL_SYNC_RUNTIME_UNAVAILABLE'};
const fail=()=>{throw Error('must not access');};
const options={identity,environment,noNewPrivileges:()=>{}};
const request=(port,headers={})=>new Promise((resolve,reject)=>{
 const req=http.get({host:'127.0.0.1',port,headers:{Host:'localhost:17645',...headers},agent:false},res=>{res.resume();res.once('end',()=>resolve(res.statusCode));});
 req.once('error',reject);req.setTimeout(2000,()=>req.destroy(Error('deadline')));
});
const stripSQLite=value=>value.replace(/^\(node:\d+\) ExperimentalWarning: SQLite is an experimental feature and might change at any time\n\(Use `node --trace-warnings \.\.\.` to show where the warning was created\)\n/m,'');

test('all four IDs, NNP, environment and exact mode guards precede input/state',async()=>{
 const input=Object.defineProperty({},'isTTY',{get:fail});
 for(const key of Object.keys(identity))await assert.rejects(runLocalSyncRuntime({...options,args:['login'],input,identity:{...identity,[key]:()=>0},locked:fail}),failure);
 await assert.rejects(runLocalSyncRuntime({...options,args:['login'],input,noNewPrivileges:fail,locked:fail}),/must not access/);
 for(const args of [[],['other'],['sync','extra']])await assert.rejects(runLocalSyncRuntime({...options,args,input,locked:fail}),failure);
 await assert.rejects(runLocalSyncRuntime({...options,args:['login'],input,environment:{...environment,NODE_OPTIONS:'synthetic'},locked:fail}),failure);
});
test('login bounded strict input rejects before lock or any listener',async()=>{
 for(const value of ['{}','{','x'.repeat(8193),Buffer.from([255]),JSON.stringify({...config,mode:'whoop-local-view'}),JSON.stringify({...config,extra:'secret'})])
  await assert.rejects(runLocalSyncRuntime({...options,args:['login'],input:Readable.from([value]),locked:fail}));
 const input=new PassThrough();input.isTTY=true;await assert.rejects(runLocalSyncRuntime({...options,args:['login'],input,locked:fail}),failure);
});
test('sync reads no login input and reconstructs only fixed statuses',async()=>{
 const input=Object.defineProperty({},'isTTY',{get:fail});
 for(const status of ['updated','limited','reauthorize','unavailable','busy']){
  const result=await runLocalSyncRuntime({...options,args:['sync'],input,synchronize:async({signal})=>{assert.equal(signal.aborted,false);return {status,secret:'must not return'};}});
  assert.deepEqual(result,{status});
 }
 await assert.rejects(runLocalSyncRuntime({...options,args:['sync'],input,synchronize:async()=>({status:'secret'})}),failure);
 assert.equal(SYNC_ABORT_MS,115000);
});
test('sync propagates cancellation to current operation without a retry',async()=>{
 const controller=new AbortController();let calls=0;let ready;
 const entered=new Promise(resolve=>ready=resolve);
 const pending=runLocalSyncRuntime({...options,args:['sync'],signal:controller.signal,synchronize:({signal})=>new Promise(resolve=>{calls++;ready();signal.addEventListener('abort',()=>resolve({status:'unavailable'}),{once:true});})});
 await entered;controller.abort();assert.deepEqual(await pending,{status:'unavailable'});assert.equal(calls,1);
});
test('login holds writer exclusion throughout actual local ingress and cancellation cleanup',async()=>{
 const controller=new AbortController();let locked=false,finished=false,ready;
 const entered=new Promise(resolve=>ready=resolve);
 const pending=runLocalSyncRuntime({args:['login'],input:Readable.from([JSON.stringify(config)]),environment,signal:controller.signal,
  locked:async action=>{locked=true;try{return await action({requireLoginEligible:()=>assert.equal(locked,true),authorize:fail});}finally{locked=false;finished=true;}},
  onReady:runtime=>ready(runtime)});
 const runtime=await entered;assert.equal(locked,true);assert.equal(runtime.core.address().address,'127.0.0.1');assert.equal(runtime.server.address().address,'0.0.0.0');
 assert.equal(await request(runtime.core.address().port),400);assert.equal(await request(17645,{Forwarded:'for=127.0.0.1'}),400);assert.equal(await request(17645),200);
 controller.abort();await assert.rejects(pending,failure);assert.equal(locked,false);assert.equal(finished,true);await assert.rejects(request(17645));
});
test('ineligible durable state prevents server construction',async()=>{
 await assert.rejects(runLocalSyncRuntime({...options,args:['login'],input:Readable.from([JSON.stringify(config)]),createLogin:fail,
  locked:action=>action({requireLoginEligible:()=>{throw Error('existing grant');}})}),/existing grant/);
});
test('actual fixed shell strips hostile pre-main environment and never echoes malformed login input',()=>{
 const p=spawnSync('/bin/sh',['/app/deploy/local-sync/entrypoint.sh','login'],{input:'synthetic-secret-invalid',encoding:'utf8',timeout:10000,
  env:{PATH:environment.PATH,NODE_OPTIONS:'--require=/must-not-load',OPENSSL_CONF:'/must-not-load',SSL_CERT_FILE:'/must-not-load'}});
 assert.equal(p.status,1);assert.equal(p.stdout,'');assert.equal(stripSQLite(p.stderr),'Local WHOOP sync unavailable.\n');
});
test('actual fixed shell rejects aliases and extra arguments without input/state',()=>{
 for(const args of [[],['other'],['sync','extra']]){
  const p=spawnSync('/bin/sh',['/app/deploy/local-sync/entrypoint.sh',...args],{input:'synthetic-secret',encoding:'utf8',timeout:10000,env:environment});
  assert.equal(p.status,1);assert.equal(p.stdout,'');assert.equal(p.stderr,'Local WHOOP sync unavailable.\n');
 }
});
