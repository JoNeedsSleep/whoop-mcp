import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { requireNoNewPrivileges } from '../staging/runtime-check.mjs';
import { createLoopbackIngress } from '../identity/loopback-ingress.mjs';
import { createLocalLoginServer, parseLocalLoginConfig } from './login.mjs';
import { withLockedState } from './state.mjs';
import { syncOnce } from './sync.mjs';

export const SYNC_ABORT_MS = 115000;
const PATH = '/usr/local/bin:/usr/bin:/bin';
const fail = () => { throw new Error('LOCAL_SYNC_RUNTIME_UNAVAILABLE'); };
function guard(identity, environment, args, noNewPrivileges) {
  if ([identity.getuid(),identity.geteuid(),identity.getgid(),identity.getegid()].some(id=>id!==1000)) fail();
  noNewPrivileges();
  if (Object.keys(environment).length!==1 || environment.PATH!==PATH || !Array.isArray(args) ||
      args.length!==1 || !['login','sync'].includes(args[0])) fail();
}
async function readInput(input, signal) {
  if (input.isTTY || signal?.aborted) fail();
  const chunks=[];let size=0;
  const abort=()=>input.destroy(new Error('LOCAL_SYNC_RUNTIME_UNAVAILABLE'));
  const timer=setTimeout(abort,5000);signal?.addEventListener('abort',abort,{once:true});
  try {
    for await(const chunk of input){const bytes=Buffer.from(chunk);size+=bytes.length;if(size>8192)fail();chunks.push(bytes);}
    if(signal?.aborted||size<2)fail();
    return parseLocalLoginConfig(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks))));
  } finally {clearTimeout(timer);signal?.removeEventListener('abort',abort);}
}

// Injection points are for offline tests only. The CLI has two literal modes,
// fixed mounted paths and no caller-selected module, address, clock or timeout.
export async function runLocalSyncRuntime({args=[],input=process.stdin,identity=process,environment=process.env,
  noNewPrivileges=requireNoNewPrivileges,signal,onReady=()=>{},locked=withLockedState,
  synchronize=syncOnce,createLogin=createLocalLoginServer}={}) {
  guard(identity,environment,args,noNewPrivileges);
  if(signal?.aborted)fail();
  if(args[0]==='sync') {
    const controller=new AbortController();const abort=()=>controller.abort();
    signal?.addEventListener('abort',abort,{once:true});const timer=setTimeout(abort,SYNC_ABORT_MS);
    try {
      if(signal?.aborted)controller.abort();
      const result=await synchronize({signal:controller.signal});
      if(!result || !['updated','limited','reauthorize','unavailable','busy'].includes(result.status))fail();
      return {status:result.status};
    } finally {clearTimeout(timer);signal?.removeEventListener('abort',abort);}
  }
  const config=await readInput(input,signal);
  return locked(async store=>{
    if(signal?.aborted)fail();
    store.requireLoginEligible();
    let service,ingress,closing;
    const close=()=>closing??=(async()=>{try{await ingress?.close();}finally{return await service?.close();}})();
    const abort=()=>{void close().catch(()=>{});};
    try {
      const marker=randomBytes(32).toString('base64url');
      service=createLogin(config,{loopbackMarker:marker,onAuthorize:(grant,options)=>store.authorize(grant,options)});
      await new Promise((resolve,reject)=>{service.server.once('error',reject);service.server.listen(0,'127.0.0.1',resolve);});
      ingress=createLoopbackIngress(service.server,marker,{containerEdge:true});
      await new Promise((resolve,reject)=>{ingress.server.once('error',reject);ingress.server.listen(17645,'0.0.0.0',resolve);});
      signal?.addEventListener('abort',abort,{once:true});
      if(signal?.aborted){await close();fail();}
      onReady({server:ingress.server,core:service.server});
      const broken=new Promise(resolve=>{service.server.once('error',()=>resolve(false));ingress.server.once('error',()=>resolve(false));});
      const completed=await Promise.race([service.done,broken]);const cleanup=await close();
      if(completed!==true||cleanup?.authorized!==true)fail();
      return {status:'authorized'};
    } finally {signal?.removeEventListener('abort',abort);await close();}
  });
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const controller=new AbortController();const stop=()=>controller.abort();process.on('SIGINT',stop);process.on('SIGTERM',stop);
  try {
    const result=await runLocalSyncRuntime({args:process.argv.slice(2),signal:controller.signal,
      onReady:()=>console.log(JSON.stringify({event:'local_whoop_login',status:'ready'}))});
    console.log(JSON.stringify({event:process.argv[2]==='login'?'local_whoop_login':'local_whoop_sync',status:result.status}));
  } catch {console.error('Local WHOOP sync unavailable.');process.exitCode=1;}
  finally {process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);}
}
