import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Readable, PassThrough } from 'node:stream';
import { spawnSync } from 'node:child_process';
import { startLocalView } from './runtime.mjs';

const identity = Object.fromEntries(['getuid','geteuid','getgid','getegid'].map(k=>[k,()=>1000]));
const environment={PATH:'/usr/local/bin:/usr/bin:/bin'};
const config={mode:'whoop-local-view',clientId:'synthetic-local-client',clientSecret:'synthetic-local-secret'};
const forbidden=()=>{throw new Error('must not access input');};
const failure={message:'LOCAL_VIEW_UNAVAILABLE'};
const request=(port,path='/',headers={})=>new Promise((resolve,reject)=>{
  const req=http.get({host:'127.0.0.1',port,path,headers:{Host:'localhost:17645',...headers},agent:false},res=>{
    const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>resolve({status:res.statusCode,text:Buffer.concat(chunks).toString()}));
  });req.on('error',reject);req.setTimeout(3000,()=>req.destroy(new Error('test deadline')));
});

test('all identity, NNP, argument and inherited-environment guards precede stdin',async()=>{
  const input=Object.defineProperty({},'isTTY',{get:forbidden});
  for(const name of Object.keys(identity))await assert.rejects(startLocalView({identity:{...identity,[name]:()=>0},environment,input,noNewPrivileges:forbidden}),failure);
  await assert.rejects(startLocalView({identity,environment,input,noNewPrivileges:forbidden}),failure);
  for(const args of [['other'],['container-edge','extra']])await assert.rejects(startLocalView({identity,environment,input,args,noNewPrivileges:()=>{}}),failure);
  await assert.rejects(startLocalView({identity,environment:{...environment,NODE_OPTIONS:'synthetic-hostile'},input,noNewPrivileges:()=>{}}),failure);
});

test('strict bounded input rejects malformed, oversized, foreign mode and extra secrets',async()=>{
  for(const input of ['{','{}','x'.repeat(8193),Buffer.from([0xff]),JSON.stringify({...config,hostname:'foreign.test'}),JSON.stringify({...config,mode:'whoop-owner-identity-loopback'})]){
    await assert.rejects(startLocalView({identity,environment,input:Readable.from([input]),noNewPrivileges:()=>{}}),failure);
  }
  const input=new PassThrough();input.isTTY=true;
  await assert.rejects(startLocalView({identity,environment,input,noNewPrivileges:()=>{}}),failure);
});

test('aborted input never opens either listener',async()=>{
  const controller=new AbortController(),input=new PassThrough();
  const pending=startLocalView({identity,environment,input,noNewPrivileges:()=>{},signal:controller.signal});
  controller.abort();await assert.rejects(pending,failure);
});

test('actual core and ingress enforce the marker and reject forwarded browser headers',async t=>{
  let calls=0;
  const runtime=await startLocalView({input:Readable.from([JSON.stringify(config)]),environment,args:['container-edge'],
    serviceOptions:{upstream:async()=>{calls++;throw new Error('synthetic');},collect:async()=>{calls++;throw new Error('synthetic');}}});
  t.after(()=>runtime.close());
  assert.equal(runtime.server.address().address,'0.0.0.0');assert.equal(runtime.server.address().port,17645);
  assert.equal(runtime.core.address().address,'127.0.0.1');
  assert.equal((await request(runtime.core.address().port)).status,400);
  for(const headers of [{Host:'foreign.test'},{Forwarded:'for=127.0.0.1'},{'X-Forwarded-Proto':'https'},{'x-whoop-local-ingress':'a'.repeat(43)}]){
    assert.equal((await request(17645,'/',headers)).status,400);
  }
  assert.equal((await request(17645)).status,200);assert.equal(calls,0);
  assert.equal((await runtime.close()).revoked,true);assert.equal(await runtime.done,false);
});

test('signal cancellation closes real listeners and leaves no usable local endpoint',async()=>{
  const controller=new AbortController();
  const runtime=await startLocalView({input:Readable.from([JSON.stringify(config)]),environment,signal:controller.signal,
    serviceOptions:{upstream:async()=>{throw new Error('unused');}}});
  assert.equal(runtime.server.address().address,'127.0.0.1');controller.abort();
  assert.equal((await runtime.close()).revoked,true);assert.equal(await runtime.done,false);
  await assert.rejects(request(17645));
});

test('actual fixed shell clears hostile pre-main configuration and rejects invalid stdin with no secret output',()=>{
  const result=spawnSync('/bin/sh',['/app/deploy/local-view/entrypoint.sh'],{
    input:'synthetic-secret-invalid-json',encoding:'utf8',timeout:10000,
    env:{PATH:environment.PATH,NODE_OPTIONS:'--require=/must-not-load-synthetic-hook',OPENSSL_CONF:'/must-not-load',SSL_CERT_FILE:'/must-not-load'},
  });
  assert.equal(result.status,1);assert.equal(result.stdout,'');assert.equal(result.stderr,'Local WHOOP viewer unavailable.\n');
});

test('fixed shell rejects extra arguments before any input is used',()=>{
  const result=spawnSync('/bin/sh',['/app/deploy/local-view/entrypoint.sh','other'],{input:'synthetic-secret',encoding:'utf8',timeout:10000,env:environment});
  assert.equal(result.status,1);assert.equal(result.stdout,'');assert.equal(result.stderr,'Local WHOOP viewer unavailable.\n');
});
