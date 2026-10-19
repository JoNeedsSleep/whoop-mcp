// Synthetic persistent SOCKS/TLS lifecycle tests. Approved offline runner only.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import {once} from 'node:events';
import {startRelay} from './fixed-relay.mjs';
import {createUnixFetch} from './unix-https.mjs';

const ORIGIN='https://backend.test-tailnet.ts.net';
const TARGET='100.101.102.103';
const BODY=JSON.stringify({value:73});
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(fn,label){const end=Date.now()+1500;while(!fn()){assert(Date.now()<end,label);await sleep(5);}}
function certificates(){
  const dir=process.env.GATEWAY_TEST_TLS_DIR;assert(dir&&path.isAbsolute(dir));
  const read=name=>{const fd=fs.openSync(path.join(dir,name),fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
    try{const st=fs.fstatSync(fd);assert(st.isFile()&&st.size>0&&st.size<8192);return fs.readFileSync(fd);}finally{fs.closeSync(fd);}};
  return{ca:read('ca.pem'),cert:read('server.pem'),key:read('server-key.pem')};
}
async function fixture(t,{reply='ipv4',tlsEnd=false,delayedSocks=0}={}){
  const certs=certificates();const dir=fs.mkdtempSync(path.join(os.tmpdir(),'relay-lifecycle-'));fs.chmodSync(dir,0o700);
  const sockets=new Set();const relayOpen=new Set();const counts={socksAccepted:0,socksConnect:0,socksEnd:0,upstreamEnd:0,tlsRequests:0,tlsEnd:0,relayAccepted:0,relayEnd:0,relayClose:0,drops:0};
  const f={counts,relayOpen,mode:'normal',reply};
  const track=s=>{sockets.add(s);s.on('error',()=>{});s.once('close',()=>sockets.delete(s));return s;};
  const server=tls.createServer({...certs,allowHalfOpen:true,minVersion:'TLSv1.2',ALPNProtocols:['http/1.1']},socket=>{
    track(socket);let pending=Buffer.alloc(0),answered=false;
    socket.on('end',()=>counts.tlsEnd++);
    socket.on('data',bytes=>{
      pending=Buffer.concat([pending,bytes]);assert(pending.length<=8192);
      if(answered||!pending.includes('\r\n\r\n'))return;
      answered=true;counts.tlsRequests++;
      assert.match(pending.toString('ascii'),/^GET \/internal\/health-summary\?date=2026-10-18 HTTP\/1\.1\r\n/);
      const output=`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(BODY)}\r\nConnection: keep-alive\r\nKeep-Alive: timeout=60\r\n\r\n${BODY}`;
      // Explicitly retain the TLS writable half after incoming FIN. The other
      // mode sends EOF but never forcibly destroys the proxy's opposite half.
      if(tlsEnd)socket.end(output);else socket.write(output);
    });
  });
  server.on('connection',track);server.on('tlsClientError',()=>{});
  const socks=net.createServer({allowHalfOpen:true},socket=>{
    track(socket);counts.socksAccepted++;let pending=Buffer.alloc(0),phase=0;
    socket.on('data',function handshake(chunk){
      pending=Buffer.concat([pending,chunk]);assert(pending.length<=16384);
      if(phase===0){if(pending.length<3)return;assert.deepEqual([...pending.subarray(0,3)],[5,1,0]);pending=pending.subarray(3);phase=1;socket.write(Buffer.from([5,0]));}
      if(phase!==1||pending.length<10)return;
      assert.deepEqual([...pending.subarray(0,4)],[5,1,0,1]);assert.equal([...pending.subarray(4,8)].join('.'),TARGET);assert.equal(pending.readUInt16BE(8),443);
      const remainder=pending.subarray(10);pending=Buffer.alloc(0);phase=2;counts.socksConnect++;
      socket.removeListener('data',handshake);socket.pause();
      if(f.mode==='malformed'){socket.end(Buffer.from([5,2,0,1,0,0,0,0,0,0]));return;}
      const upstream=track(net.connect({host:'127.0.0.1',port:server.address().port,allowHalfOpen:true}));
      let clientEnded=false,serverEnded=false;
      const done=()=>{if(clientEnded&&serverEnded){socket.destroy();upstream.destroy();}};
      // Match the pinned Go SOCKS two-pump rule: EOF closes only the opposite
      // writable half, then waits for both directions before full close.
      socket.once('end',()=>{counts.socksEnd++;clientEnded=true;upstream.end();done();});
      upstream.once('end',()=>{counts.upstreamEnd++;serverEnded=true;socket.end();done();});
      socket.on('error',()=>{socket.destroy();upstream.destroy();});upstream.on('error',()=>{socket.destroy();upstream.destroy();});
      upstream.once('connect',async()=>{
        if(delayedSocks)await sleep(delayedSocks);
        if(socket.destroyed){upstream.destroy();return;}
        const replyBytes=f.reply==='ipv6'?Buffer.from([5,0,0,4,...Array(16).fill(0),0,0]):
          f.reply==='domain'?Buffer.concat([Buffer.from([5,0,0,3,255]),Buffer.alloc(255,97),Buffer.from([0,0])]):Buffer.from([5,0,0,1,127,0,0,1,0,0]);
        if(f.reply==='fragmented'){for(const byte of replyBytes){socket.write(Buffer.from([byte]));await new Promise(r=>setImmediate(r));}}
        else socket.write(replyBytes);
        if(remainder.length)upstream.write(remainder);
        socket.pipe(upstream,{end:false});upstream.pipe(socket,{end:false});socket.resume();
      });
    });
  });
  let relay;
  t.after(async()=>{
    for(const socket of sockets)socket.destroy();
    if(relay)await relay.close();
    await Promise.all([socks,server].filter(s=>s.listening).map(s=>new Promise(r=>s.close(r))));
    fs.rmSync(dir,{recursive:true,force:true});
  });
  server.listen(0,'127.0.0.1');await once(server,'listening');socks.listen(0,'127.0.0.1');await once(socks,'listening');
  const socketPath=path.join(dir,'backend.sock');relay=await startRelay({socketPath,targetIpv4:TARGET,socksPort:socks.address().port});
  relay.server.on('connection',socket=>{counts.relayAccepted++;relayOpen.add(socket);socket.once('end',()=>counts.relayEnd++);socket.once('close',()=>{counts.relayClose++;relayOpen.delete(socket);});});
  relay.server.on('drop',()=>counts.drops++);
  const fetch=createUnixFetch({origin:ORIGIN,socketPath,allowedPaths:['/internal/health-summary'],ca:certs.ca});
  f.get=async()=>{const c=new AbortController();const timer=setTimeout(()=>c.abort(),1200);try{
    const res=await fetch(`${ORIGIN}/internal/health-summary?date=2026-10-18`,{method:'GET',redirect:'error',headers:{Accept:'application/json'},signal:c.signal});
    assert.equal(res.status,200);assert.deepEqual(await res.json(),{value:73});
  }finally{clearTimeout(timer);}};
  f.socketPath=socketPath;return f;
}

for(const reply of ['ipv4','ipv6','domain','fragmented'])test(`persistent SOCKS ${reply} reply and retained TLS half-close release every sequential relay slot`,{timeout:15000},async t=>{
  const f=await fixture(t,{reply});
  for(let i=0;i<21;i++)await f.get();
  await until(()=>f.relayOpen.size===0,JSON.stringify(f.counts));
  assert.equal(f.counts.tlsRequests,21);assert.equal(f.counts.socksConnect,21);assert.equal(f.counts.drops,0);
  assert.equal(f.counts.relayAccepted,f.counts.relayClose);
  t.diagnostic(JSON.stringify(f.counts));
});

test('upstream EOF with SOCKS half-close does not retain the two relay slots',{timeout:15000},async t=>{
  const f=await fixture(t,{tlsEnd:true});for(let i=0;i<21;i++)await f.get();
  await until(()=>f.relayOpen.size===0,JSON.stringify(f.counts));assert.equal(f.counts.tlsRequests,21);assert.equal(f.counts.drops,0);
  t.diagnostic(JSON.stringify(f.counts));
});

test('two rejected SOCKS handshakes leave capacity for persistent TLS requests',{timeout:15000},async t=>{
  const f=await fixture(t);f.mode='malformed';await assert.rejects(f.get());await assert.rejects(f.get());
  f.mode='normal';for(let i=0;i<7;i++)await f.get();
  await until(()=>f.relayOpen.size===0,JSON.stringify(f.counts));assert.equal(f.counts.tlsRequests,7);assert.equal(f.counts.drops,0);
  t.diagnostic(JSON.stringify(f.counts));
});

test('early Unix FIN during delayed SOCKS negotiation leaves capacity for the next caller',{timeout:15000},async t=>{
  const f=await fixture(t,{delayedSocks:40});
  for(let i=0;i<2;i++){const socket=net.connect(f.socketPath);socket.on('error',()=>{});await once(socket,'connect');socket.end('synthetic-clienthello');await once(socket,'close');}
  for(let i=0;i<7;i++)await f.get();
  await until(()=>f.relayOpen.size===0,JSON.stringify(f.counts));assert.equal(f.counts.tlsRequests,7);assert.equal(f.counts.drops,0);
  t.diagnostic(JSON.stringify(f.counts));
});
