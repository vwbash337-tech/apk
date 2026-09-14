/*
 * selftest_real_so.js — runs rpc.exports.selfTest() and rpc.exports.signature()
 * with the agent's MOD resolved against the REAL libtopfollow.so bytes on disk,
 * under Node, with no phone and no Frida.
 *
 *   node frida/selftest_real_so.js            (from the repository root)
 *
 * test_agent_offline.js covers the pure-JS logic; this file covers the other half:
 * every `live` check in selfTest (the XOR-0x5A decode of the AES-192 key and the two
 * GCM nonces at 0x17428/0x17448/0x17458, the plaintext key at 0x161ca, the S-box at
 * 0x128b0 and the Rcon at 0x13b10) plus signature(), which reads the 120-char
 * double-Base64 pin blob live from 0x15084 and compares it with SHA-256 of the
 * original signer certificate.
 *
 * Process.findModuleByName is stubbed so the agent resolves MOD through its OWN
 * code path (findModule()), and NativePointer.read* are backed by the file buffer,
 * so `A(off)` arithmetic is exercised exactly as it would be on a device.
 *
 * Needs work/apk_extracted/ — rebuild it with `unzip -o TopFollow_v845-Beta.apk
 * -d work/apk_extracted` (see work/REPRODUCE.md step 2).
 */
/* Run rpc.exports.selfTest() with MOD pointed at the real libtopfollow.so bytes. */
'use strict';
const fs=require('fs'), path=require('path'), vm=require('vm');
const HERE=__dirname, ROOT=path.resolve(HERE,'..');
const SRC=fs.readFileSync(path.join(HERE,'topfollow_agent.js'),'utf8');
const SOPATH=path.join(ROOT,'work','apk_extracted','lib','arm64-v8a','libtopfollow.so');
if(!fs.existsSync(SOPATH)){console.error('missing '+SOPATH+'\n  run: unzip -o TopFollow_v845-Beta.apk -d work/apk_extracted');process.exit(2);}
const real=fs.readFileSync(SOPATH);
const BASE=0x7000000000n;
function P(v){const n=typeof v==='string'?(v.startsWith('0x')?BigInt(v):BigInt(parseInt(v,10))):BigInt(v||0);
 return {_v:n,add(o){return P(this._v+ (o&&o._v!==undefined?o._v:BigInt(o||0)))},
  sub(o){return P(this._v-(o&&o._v!==undefined?o._v:BigInt(o||0)))},
  and(m){return P(this._v & BigInt(m))},shr(b){return P(this._v>>BigInt(b))},
  compare(o){return this._v<o._v?-1:this._v>o._v?1:0},isNull(){return this._v===0n},
  toInt32(){return Number(this._v)|0},toString(){return '0x'+this._v.toString(16)},
  readU8(){const o=Number(this._v-BASE);return real[o]},
  readU32(){const o=Number(this._v-BASE);return real.readUInt32LE(o)},
  readPointer(){return P(0)},
  readByteArray(n){const o=Number(this._v-BASE);return real.slice(o,o+n).buffer.slice(real.byteOffset+o,real.byteOffset+o+n)},
  readUtf8String(){const o=Number(this._v-BASE);let e=o;while(e<real.length&&real[e]!==0)e++;return real.slice(o,e).toString('utf8')},
  readCString(){return this.readUtf8String()},
  writeU8(){},writeUtf8String(){},writeByteArray(){}};}
const noop=()=>{};
const sandbox={console:{log:noop,info:noop,warn:noop,error:noop,debug:noop},
 setTimeout,setInterval,clearInterval,clearTimeout,TextEncoder,TextDecoder,Uint8Array,ArrayBuffer,Date,Math,JSON,Object,Array,String,Number,BigInt,parseInt,parseFloat,isNaN,RegExp,Error,TypeError,
 ptr:P,Process:{id:1,arch:'arm64',platform:'android',pageSize:4096,pointerSize:8,
   findModuleByName:(n)=>n==='libtopfollow.so'?{name:'libtopfollow.so',base:P(BASE),size:real.length,path:'/data/app/libtopfollow.so'}:null,
   findModuleByAddress:()=>null,enumerateModules:()=>[]},
 Module:{findExportByName:()=>null,findBaseAddress:()=>P(BASE),
   load:noop,getExportByName:()=>null,
   enumerateExports:()=>[{name:'JNI_OnLoad',address:P(BASE+0x3e1d4n),type:'function'}]},
 Interceptor:{attach:noop,replace:noop,detachAll:noop},
 NativeFunction:function(){return noop},NativeCallback:function(){return P(0)},
 Memory:{alloc:()=>P(0x1000),protect:noop,scanSync:()=>[]},
 Thread:{backtrace:()=>[]},Backtracer:{FUZZY:0,ACCURATE:1},
 DebugSymbol:{fromAddress:a=>({toString:()=>String(a)})},
 Frida:{version:'17.18.0'},Java:{available:false,perform:noop,vm:null,
   use:()=>{throw new Error('no java')},registerClass:()=>({$new:()=>({})})},
 hexdump:()=>'',rpc:{exports:{}},globalThis:null};
sandbox.globalThis=sandbox; vm.createContext(sandbox);
sandbox.TOPFOLLOW_NO_AUTOBOOT=true;
vm.runInContext(SRC,sandbox,{filename:'agent'});
/* resolve MOD through the agent's own path (Process.findModuleByName is stubbed) */
vm.runInContext('MOD = findModule();', sandbox);
vm.runInContext('globalThis.__x={rpc:rpc.exports,OFF:OFF};',sandbox);
const r = sandbox.__x.rpc.selfTest();
console.log('selfTest: allOk=%s  passed=%d/%d  failed=%d  skipped=%d',
            r.allOk, r.passed, r.total, r.failed.length, r.skipped);
r.results.filter(x => x.ok === false).forEach(x =>
    console.log('   FAIL ' + x.what + '\n        got    ' + x.got + '\n        expect ' + x.expect));
r.results.filter(x => x.ok === null).forEach(x =>
    console.log('   SKIP ' + x.what + ' (' + x.got + ')'));

const sig = sandbox.__x.rpc.signature();
console.log('signature: liveMatchesPin=%s  blobLen=%d  certLen=%d',
            sig.liveMatchesPin, (sig.liveBlob || '').length, sig.originalCertLen);
console.log('   pinned      %s', sig.pinnedSha256);
console.log('   cert sha256 %s', sig.originalCertSha256);
console.log('   live @%s -> %s', sig.blobOffset, sig.liveDecoded);

const ok = r.allOk && r.skipped === 0 && sig.liveMatchesPin === true &&
           sig.originalCertSha256 === sig.pinnedSha256;
console.log(ok ? '\nALL LIVE CHECKS PASS' : '\nSOMETHING FAILED');
process.exit(ok ? 0 : 1);
