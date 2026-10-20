import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { PassThrough } from 'node:stream';
import { once } from 'node:events';
import { READER_IMAGE, READER_LIFETIME_MS, READER_LIFETIME_SCRIPT, DOCKER, DOCKER_HOST, cacheSpec, createDockerDriver, runReaderBridge } from './reader-launch.mjs';
import { writeCache, CACHE_TTL_MS } from './cache.mjs';
import { DAY_MS } from './policy.mjs';
const CID='a'.repeat(64);
const ENV=['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','NODE_VERSION=22.23.3','YARN_VERSION=1.22.22'];
const reader=fileURLToPath(new URL('./reader.mjs',import.meta.url));
function fake(client='codex', mutate=()=>{}) {
  const calls=[]; let container; let volume={Name:cacheSpec(client).name,Driver:'local',Options:null,Labels:cacheSpec(client).labels};
  const response=(obj)=>({code:0,stdout:JSON.stringify([obj]),stderr:''});
  const image={Id:READER_IMAGE,Os:'linux',Architecture:'arm64',Config:{Env:[...ENV]}};
  const f={calls,get container(){return container;},volume,image,stream:async()=>{},async run(args) {
    calls.push(args); const key=args[0];
    if(key==='volume'){assert.deepEqual(args,['volume','inspect',volume.Name]);mutate('volume',volume);return response(volume);}
    if(key==='image'){mutate('image',image);return response(image);}
    if(key==='create'){
      const value=(name)=>args[args.indexOf(name)+1];const labels={};for(let i=0;i<args.length;i++)if(args[i]==='--label'){const [k,...v]=args[++i].split('=');labels[k]=v.join('=');}
      container={Id:CID,Name:'/'+value('--name'),Image:READER_IMAGE,Config:{User:'1000:1000',Env:[...ENV],Entrypoint:['/usr/bin/env'],Cmd:args.slice(args.indexOf(READER_IMAGE)+1),Labels:labels},State:{Running:false},
        Mounts:[{Type:'volume',Name:volume.Name,Destination:'/cache',RW:false,Driver:'local'}],HostConfig:{Privileged:false,ReadonlyRootfs:true,AutoRemove:args.includes('--rm'),CapDrop:['ALL'],CapAdd:null,SecurityOpt:['no-new-privileges=true'],NetworkMode:'none',IpcMode:'none',CgroupnsMode:'private',Memory:134217728,MemorySwap:134217728,NanoCpus:500000000,PidsLimit:64,PublishAllPorts:false,Tmpfs:{'/tmp':'rw,noexec,nosuid,nodev,size=16m,mode=1777'},Ulimits:[{Name:'nofile',Soft:512,Hard:512},{Name:'core',Soft:0,Hard:0}]}};
      mutate('create',container);return {code:0,stdout:CID,stderr:''};
    }
    if(key==='inspect'){if(!container)return {code:1,stdout:'',stderr:'Error: No such object: '+args[1]};mutate('inspect',container);return response(container);}
    if(key==='start'){container.State.Running=true;return {code:0,stdout:'',stderr:''};}
    if(key==='exec'){assert.equal(args[5],'-e');return {code:0,stdout:'',stderr:''};}
    if(key==='rm'){assert.deepEqual(args,['rm','--force',CID]);container=undefined;return {code:0,stdout:'',stderr:''};}
    throw Error('Unexpected Docker verb');
  }};return f;
}
function cache(t,client='codex') {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'reader-bridge-'));fs.chmodSync(dir,0o700);t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const now=Date.now(),today=new Date(now).toISOString().slice(0,10),file=path.join(dir,'cache.json');
  writeCache(file,{version:1,clientId:client,syncedAt:now,expiresAt:now+CACHE_TTL_MS,authorizationExpiresAt:now+7*DAY_MS,
    snapshot:{version:1,windowEnd:today,summaries:Array.from({length:7},(_,i)=>({date:new Date(Date.parse(today)-(6-i)*DAY_MS).toISOString().slice(0,10),status:'AVAILABLE',recovery_score:75,hrv_ms:50,resting_heart_rate:60,sleep_ms:27000000,sleep_performance:90,strain:10}))}},now);
  return {file,dir,today};
}
function realStream(fixture, childProgram, children=[]) {
  return createDockerDriver('/tmp/empty-fixture-config',{spawnImpl(executable,args,options){
    assert.equal(executable,DOCKER);assert.deepEqual(args.slice(0,4),['--config','/tmp/empty-fixture-config','--host',DOCKER_HOST]);
    assert.deepEqual(options.env,{PATH:'/usr/local/bin:/usr/bin:/bin'});
    assert.deepEqual(args.slice(4),['exec','--interactive',CID,'/usr/bin/env','-i','WHOOP_LOCAL_CACHE_FILE=/cache/cache.json','WHOOP_LOCAL_CLIENT_ID=codex','/usr/local/bin/node','/app/reader.mjs']);
    const p=spawn(process.execPath,childProgram??[reader],{env:{WHOOP_LOCAL_CACHE_FILE:fixture.file,WHOOP_LOCAL_CLIENT_ID:'codex'},stdio:['pipe','pipe','pipe']});children.push(p);return p;
  }}).stream;
}
const init={jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-06-18',capabilities:{},clientInfo:{name:'fixture',version:'1'}}};
const frame=(value)=>JSON.stringify(value)+'\n';
async function readLine(stream) {
  let value='';for(;;){const chunk=stream.read();if(chunk){value+=chunk.toString();if(value.includes('\n'))return value;}else await once(stream,'readable');}
}

test('fixed cache provenance and immutable image; invalid client rejected before Docker',async()=>{
  const f=fake();await assert.rejects(runReaderBridge('../codex',{docker:f}));assert.equal(f.calls.length,0);
  assert.equal(cacheSpec('claude-code').name,'whoop_individual_sub-staging-claude-code_cache_kill-2026-10-19');
  for(const change of [v=>v.Labels.rr_operator_config_sha256='0'.repeat(64),v=>v.Labels.extra='unexpected',v=>v.Driver='nfs',v=>v.Options={device:'/host'}]){
    const d=fake('codex',(stage,v)=>{if(stage==='volume')change(v);});await assert.rejects(runReaderBridge('codex',{docker:d}));assert.equal(d.calls.some(x=>x[0]==='create'),false);
  }
  const d=fake('codex',(stage,v)=>{if(stage==='image')v.Id='sha256:'+'0'.repeat(64);});await assert.rejects(runReaderBridge('codex',{docker:d}));assert.equal(d.calls.some(x=>x[0]==='create'),false);
});

test('container drift refuses application execution and cleans only owned exact ID',async()=>{
  for(const change of [v=>v.HostConfig.NetworkMode='bridge',v=>v.HostConfig.CapAdd=['CAP_SYS_ADMIN'],v=>v.Mounts[0].RW=true,v=>v.Mounts.push({Type:'bind',Destination:'/host'}),v=>v.Config.Labels['dev.orbstack.add-ca-certificates']='true',v=>v.HostConfig.ReadonlyRootfs=false,v=>v.HostConfig.AutoRemove=false,v=>v.Config.Cmd[3]='setInterval(()=>{},1000)',v=>v.HostConfig.PidMode='host',v=>v.Config.Env.push('SECRET=forbidden')]){
    const d=fake('codex',(stage,v)=>{if(stage==='create')change(v);});let streamed=false;d.stream=async()=>{streamed=true;};
    await assert.rejects(runReaderBridge('codex',{docker:d}));assert.equal(streamed,false);assert.equal(d.calls.some(x=>x[0]==='start'),false);assert.ok(d.calls.some(x=>x[0]==='rm'&&x[2]===CID));
  }
});

test('post-start cache/container drift cannot reach reader',async()=>{
  let volumeCalls=0;const d=fake('codex',(stage,v)=>{if(stage==='volume'&&++volumeCalls===2)v.Labels.rr_client_id='claude-code';});
  await assert.rejects(runReaderBridge('codex',{docker:d}));assert.equal(d.calls.some(x=>x[0]==='exec'),false);assert.equal(d.container,undefined);
  const e=fake('codex',(stage,v)=>{if(stage==='inspect'&&v.State.Running)v.HostConfig.NetworkMode='host';});
  await assert.rejects(runReaderBridge('codex',{docker:e}));assert.equal(e.calls.some(x=>x[0]==='exec'),false);assert.equal(e.container,undefined);
});

test('persistent stdio runs actual reader, handles split frames/second request, EOF and exact cleanup without cache writes', {timeout:10000},async(t)=>{
  const f=cache(t),before=fs.readFileSync(f.file),d=fake(),input=new PassThrough(),output=new PassThrough(),children=[];
  d.stream=realStream(f,undefined,children);const done=runReaderBridge('codex',{docker:d,input,output});
  const first=frame(init);input.write(first.slice(0,19));input.write(first.slice(19));
  const response=JSON.parse((await readLine(output)).trim());assert.equal(response.id,1);assert.equal(d.container.State.Running,true);
  input.write(frame({jsonrpc:'2.0',method:'notifications/initialized'}));input.write(frame({jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'get_health_summary',arguments:{date:f.today}}}));
  const second=JSON.parse((await readLine(output)).trim());assert.equal(second.id,2);assert.equal(second.result.structuredContent.recovery_score,75);
  input.end();await done;assert.equal(children[0].exitCode,0);assert.equal(d.container,undefined);assert.deepEqual(fs.readFileSync(f.file),before);
  assert.equal(d.calls.filter(x=>x[0]==='volume').length,2);assert.equal(d.calls.some(x=>x[0]==='volume'&&x[1]!=='inspect'),false);
});

test('missing and expired cache return fixed errors without sync or authorization access', {timeout:10000},async(t)=>{
  for(const expired of [false,true]){
    const f=cache(t);if(expired){const raw=JSON.parse(fs.readFileSync(f.file));raw.expiresAt=Date.now()-1;fs.writeFileSync(f.file,JSON.stringify(raw));}else fs.unlinkSync(f.file);
    const d=fake(),input=new PassThrough(),output=new PassThrough();d.stream=realStream(f);
    let bytes='';output.on('data',b=>bytes+=b);const done=runReaderBridge('codex',{docker:d,input,output});
    input.end(frame(init)+frame({jsonrpc:'2.0',method:'notifications/initialized'})+frame({jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'get_health_summary',arguments:{date:f.today}}}));await done;
    const response=bytes.trim().split('\n').map(JSON.parse)[1];assert.equal(response.result.isError,true);assert.equal(response.result.content[0].text,'LOCAL_HEALTH_DATA_UNAVAILABLE');
    assert.equal(d.calls.filter(x=>x[0]==='exec').length,1);assert.equal(d.calls.some(x=>x[0]==='volume'&&x[2]!==cacheSpec('codex').name),false);
  }
});

test('cancellation kills real attached child, suppresses stderr and removes owned container', {timeout:10000},async(t)=>{
  const f=cache(t),d=fake(),input=new PassThrough(),output=new PassThrough(),children=[],controller=new AbortController();
  d.stream=realStream(f,['-e',"process.stdout.write('ready\\n');process.stderr.write('PRIVATE_DIAGNOSTIC');setInterval(()=>{},1000)"],children);
  const done=runReaderBridge('codex',{docker:d,input,output,signal:controller.signal});const rejected=assert.rejects(done,/Offline WHOOP reader unavailable/);
  assert.equal(await readLine(output),'ready\n');controller.abort();await rejected;assert.equal(children[0].signalCode,'SIGKILL');assert.equal(d.container,undefined);assert.equal(output.read(),null);input.destroy();
});

test('attach failure still removes the remote container even after local process exits', {timeout:10000},async(t)=>{
  const f=cache(t),d=fake(),input=new PassThrough(),output=new PassThrough();d.stream=realStream(f,['-e',"process.stderr.write('PRIVATE');process.exit(9)"]);
  await assert.rejects(runReaderBridge('codex',{docker:d,input,output}));assert.equal(d.container,undefined);assert.equal(output.read(),null);input.destroy();
});

test('ambiguous create recovers only exact owned name/labels and always refuses startup',async()=>{
  for(const foreign of [false,true]){const d=fake(),run=d.run;d.run=async(args)=>{const r=await run(args);if(args[0]==='create'){if(foreign)d.container.Config.Labels.rr_reader_attempt='foreign';throw Error('lost reply');}return r;};
    await assert.rejects(runReaderBridge('codex',{docker:d}));assert.equal(d.calls.some(x=>x[0]==='start'),false);
    assert.equal(d.calls.some(x=>x[0]==='rm'),!foreign);
  }
});

test('a successful create reply cannot authorize removal of a foreign object',async()=>{
  const d=fake(),run=d.run,foreign='b'.repeat(64);d.run=async(args)=>{
    if(args[0]==='create'){await run(args);return {code:0,stdout:foreign,stderr:''};}
    if(args[0]==='inspect'&&args[1]===foreign)return {code:0,stdout:JSON.stringify([{...d.container,Id:foreign,Name:'/preexisting',Config:{Labels:{rr_reader_attempt:'foreign'}}}]),stderr:''};
    return run(args);
  };
  await assert.rejects(runReaderBridge('codex',{docker:d}));
  assert.equal(d.calls.some(x=>x[0]==='start'),false);
  assert.deepEqual(d.calls.filter(x=>x[0]==='rm'),[['rm','--force',CID]]);
  assert.equal(d.container,undefined);
});

test('cleanup uncertainty is an error, never silent success',async()=>{
  const d=fake(),run=d.run;d.run=async(args)=>args[0]==='rm'?{code:1,stdout:'',stderr:'denied'}:run(args);
  await assert.rejects(runReaderBridge('codex',{docker:d}));assert.ok(d.container);
});

test('runtime built-in preflight really validates current isolated kernel with empty environment', {timeout:10000},async()=>{
  const d=fake(),run=d.run;let ran=false;d.run=async(args)=>{if(args[0]!=='exec')return run(args);ran=true;
    const p=spawn(process.execPath,['-e',args[6]],{env:{},stdio:['ignore','pipe','pipe']});let stderr='';p.stderr.on('data',b=>stderr+=b);const [code]=await once(p,'close');assert.equal(code,0,stderr);return {code,stdout:'',stderr:''};};
  await runReaderBridge('codex',{docker:d});assert.equal(ran,true);assert.equal(d.container,undefined);
});

test('fixed lifetime exits an actual child independently of attached stdin and is verified in Docker command', {timeout:10000},async()=>{
  assert.equal(READER_LIFETIME_MS,86400000);
  assert.equal(READER_LIFETIME_SCRIPT,'setTimeout(() => process.exit(0), 86400000)');
  // Only this fixture substitutes a shorter literal; production has no duration option.
  const p=spawn(process.execPath,['-e',READER_LIFETIME_SCRIPT.replace('86400000','40')],{env:{},stdio:['pipe','pipe','pipe']});
  let stdout='',stderr='';p.stdout.on('data',b=>stdout+=b);p.stderr.on('data',b=>stderr+=b);
  const [code,signal]=await once(p,'close');
  assert.equal(code,0);assert.equal(signal,null);assert.equal(stdout,'');assert.equal(stderr,'');
  const d=fake();await runReaderBridge('codex',{docker:d});
  const create=d.calls.find(x=>x[0]==='create');
  assert.equal(create.filter(x=>x==='--rm').length,1);
  assert.deepEqual(create.slice(create.indexOf(READER_IMAGE)+1),['-i','/usr/local/bin/node','-e',READER_LIFETIME_SCRIPT]);
});

test('already auto-removed container is accepted only with exact absence proof and never removes its named cache',async()=>{
  const d=fake(),run=d.run;
  d.stream=async()=>{await run(['rm','--force',CID]);};
  d.run=async(args)=>args[0]==='rm'&&!d.container
    ?{code:1,stdout:'',stderr:'Error: No such container: '+CID}:run(args);
  await runReaderBridge('codex',{docker:d});
  assert.equal(d.container,undefined);
  assert.equal(d.calls.some(x=>x[0]==='volume'&&x[1]!=='inspect'),false);
});
