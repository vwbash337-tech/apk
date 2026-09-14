/*
 * test_agent_offline.js — runs topfollow_agent.js's PURE logic under Node,
 * with the Frida API stubbed out, and asserts every known-answer vector.
 *
 *   node frida/test_agent_offline.js
 *
 * This does NOT need a phone. It proves the JS AES, the libc++ std::string
 * reader, the XOR-0x5A decoder, the Base64 helpers and rpc.exports.decrypt
 * all agree with work/analysis/aesref.py and with the emulated func#85/#94/#30.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SRC = fs.readFileSync(path.join(__dirname, 'topfollow_agent.js'), 'utf8');

/* ---------- minimal Frida API stubs ---------- */
function P(v) {
    const n = typeof v === 'string' ? parseInt(v.replace(/^0x/, ''), v.startsWith('0x') ? 16 : 10) : (v || 0);
    return {
        _v: BigInt(n),
        add(o) { return P(Number(this._v + BigInt(o && o._v !== undefined ? Number(o._v) : o))); },
        sub(o) { return P(Number(this._v - BigInt(o && o._v !== undefined ? Number(o._v) : o))); },
        and(m) { return P(Number(this._v & BigInt(m))); },
        shr(b) { return P(Number(this._v >> BigInt(b))); },
        compare(o) { return this._v < o._v ? -1 : this._v > o._v ? 1 : 0; },
        isNull() { return this._v === 0n; },
        toInt32() { return Number(this._v) | 0; },
        toString() { return '0x' + this._v.toString(16); },
        readU8() { return 0; }, readU32() { return 0; }, readPointer() { return P(0); },
        readByteArray() { return new ArrayBuffer(0); }, readUtf8String() { return ''; },
        readCString() { return ''; }, writeU8() {}, writeUtf8String() {}, writeByteArray() {}
    };
}
const noop = () => {};
const sandbox = {
    console,
    setTimeout, setInterval, clearInterval, clearTimeout,
    TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, Date, Math, JSON, Object, Array, String, Number, BigInt,
    parseInt, parseFloat, isNaN, RegExp, Error, TypeError,
    ptr: P,
    Process: { id: 1, arch: 'arm64', platform: 'android', pageSize: 4096, pointerSize: 8,
               findModuleByName: () => null, findModuleByAddress: () => null },
    Module: { findExportByName: () => null },
    Interceptor: { attach: noop, replace: noop, detachAll: noop },
    NativeFunction: function () { return noop; },
    NativeCallback: function () { return P(0); },
    Memory: { alloc: () => P(0x1000), protect: noop },
    Thread: { backtrace: () => [] },
    Backtracer: { FUZZY: 0, ACCURATE: 1 },
    DebugSymbol: { fromAddress: a => ({ toString: () => String(a) }) },
    Frida: { version: 'test' },
    Java: { available: false, perform: noop, vm: null, use: () => { throw new Error('no java'); },
            registerClass: () => ({ $new: () => ({}) }) },
    hexdump: () => '',
    rpc: { exports: {} },
    globalThis: null
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);

/* define everything but do NOT arm any hook (the bootstrap is guarded by
   TOPFOLLOW_NO_AUTOBOOT, which we set before the script runs) */
sandbox.TOPFOLLOW_NO_AUTOBOOT = true;
vm.runInContext(SRC, sandbox, { filename: 'topfollow_agent.js' });

/* top-level `const`/`let` in a vm script live in the script scope, not on the
   context object, so re-export them explicitly for the assertions below. */
vm.runInContext(
  'globalThis.__x = { AES: AES, OFF: OFF, rpc: rpc, b64decode: b64decode, b64encode: b64encode,' +
  ' xorBytes: xorBytes, toStr: toStr, readStdString: readStdString, JNI_EXPECT: JNI_EXPECT, rpc: rpc,' +
  ' KNOWN_KEYS: KNOWN_KEYS, utf8OrHex: utf8OrHex, CONFIG: CONFIG,' +
  ' MAPS_NOISE: MAPS_NOISE, mapsLineIsSuspicious: mapsLineIsSuspicious,' +
  ' filterMapsBuffer: filterMapsBuffer };',
  sandbox, { filename: 'export-step' });

const AES = sandbox.__x.AES, rpc = sandbox.rpc.exports, OFF = sandbox.__x.OFF;
const b64decode = sandbox.__x.b64decode;
const enc = s => Array.from(Buffer.from(s, 'utf8'));
const hx = b => Buffer.from(b).toString('hex');

let pass = 0, fail = 0;
function t(name, got, exp) {
    const ok = String(got) === String(exp);
    ok ? pass++ : fail++;
    console.log((ok ? '  ok   ' : '  FAIL ') + name + (ok ? '' : '\n         got    ' + got + '\n         expect ' + exp));
}

console.log('\n== 1. FIPS-197 standard vectors (proves the JS AES itself) ==');
const ks128 = AES.expand(AES.fromHex('000102030405060708090a0b0c0d0e0f'));
t('AES-128 enc', hx(AES.encBlock(AES.fromHex('00112233445566778899aabbccddeeff'), ks128)),
                  '69c4e0d86a7b0430d8cdb78070b4c55a');
t('AES-128 dec round-trip', hx(AES.decBlock(AES.fromHex('69c4e0d86a7b0430d8cdb78070b4c55a'), ks128)),
                  '00112233445566778899aabbccddeeff');
const k256 = AES.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
t('AES-256 enc', hx(AES.encBlock(AES.fromHex('00112233445566778899aabbccddeeff'), AES.expand(k256))),
                  '8ea2b7ca516745bfeafc49904b496089');
t('AES-256 dec round-trip', hx(AES.decBlock(AES.fromHex('8ea2b7ca516745bfeafc49904b496089'), AES.expand(k256))),
                  '00112233445566778899aabbccddeeff');
const k192 = AES.fromHex('000102030405060708090a0b0c0d0e0f1011121314151617');
t('AES-192 enc', hx(AES.encBlock(AES.fromHex('00112233445566778899aabbccddeeff'), AES.expand(k192))),
                  'dda97ca4864cdfe06eaf70a0ec0d7191');

console.log('\n== 2. func#85 (AES-ECB/PKCS7/hex) vectors from report §11.2 ==');
const K = enc('0123456789abcdef');
t('#85("hello")',      hx(AES.ecbEnc(enc('hello'), K)),      '674c7ef38e78cabd9cec9c125823a639');
t('#85("A"*15)',       hx(AES.ecbEnc(enc('A'.repeat(15)), K)), '8c22b46ae5492fada678b79e2bdbd0eb');
t('#85("A"*16)',       hx(AES.ecbEnc(enc('A'.repeat(16)), K)),
   '3bfd04cc0d7ed55358e2cbe19de21383377222e061a924c591cd9c27ea163ed4');
t('#85("A"*31)',       hx(AES.ecbEnc(enc('A'.repeat(31)), K)),
   '3bfd04cc0d7ed55358e2cbe19de213838c22b46ae5492fada678b79e2bdbd0eb');
t('#85("A"*32) ECB leak', hx(AES.ecbEnc(enc('A'.repeat(32)), K)),
   '3bfd04cc0d7ed55358e2cbe19de213833bfd04cc0d7ed55358e2cbe19de21383377222e061a924c591cd9c27ea163ed4');
t('#85(json)',         hx(AES.ecbEnc(enc('{"user":"abc","pass":"xyz"}'), K)),
   '473f9aa1dd7694a1f39c613225cce529a588c9e9d7c7f8f9cb801491e4a2acd5');
t('#85(fox,43B)',      hx(AES.ecbEnc(enc('The quick brown fox jumps over the lazy dog'), K)),
   '08eaec72a2775e8a412e92731f4a4a2e4d8b9161a0f6411f4f7d0970100abbb0fba1ae2433a9674ca3f58a8f2efdfba9');
t('#85(pad-only block)', hx(AES.ecbEnc(new Array(16).fill(0x10), K)),
   '377222e061a924c591cd9c27ea163ed4377222e061a924c591cd9c27ea163ed4');
t('#85("hello",24B key)', hx(AES.ecbEnc(enc('hello'), k192)), '12056740635d5dd4124b24264bb8a00a');
t('#85("hello",32B key)', hx(AES.ecbEnc(enc('hello'), k256)), '91684487c34c3456eb4e901cef884a1e');
t('#85(256B pt) first block', hx(AES.ecbEnc(AES.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b'), K)).slice(0, 32),
   'a07999f0e2bfbe16f99593e984a449b7');

console.log('\n== 3. func#94 (exact inverse) round-trips ==');
['hello', 'A'.repeat(16), 'A'.repeat(32), '{"user":"abc","pass":"xyz"}',
 'The quick brown fox jumps over the lazy dog'].forEach(pt => {
    const ct = AES.ecbEnc(enc(pt), K);
    t('#94(#85("' + pt.slice(0, 18) + '…"))',
      Buffer.from(AES.unpad(AES.ecbDec(ct, K)).data).toString('utf8'), pt);
});

console.log('\n== 4. func#30 (AES-128-CBC, key=0, iv=0) vectors from §11.3 ==');
t('#30("")',       hx(AES.zeroCbcEnc([])),            '0143db63ee66b0cdff9f69917680151e');
t('#30("hello")',  hx(AES.zeroCbcEnc(enc('hello'))),  '9834ed518cbc8fbe9af3c6ecb75eb8c0');
t('#30("A"*16)',   hx(AES.zeroCbcEnc(enc('A'.repeat(16)))),
   'b49cbf19d357e6e1f6845c30fd5b63e30c747680a9e9970389a2bdd752b4b1c3');
t('#30(order json)', hx(AES.zeroCbcEnc(enc('{"order_id":12345,"type":"follower"}'))),
   'f49288051d7d9decc641ea07eb7ff32cbde7e2be9f3006617f3938a20f63549cfc144d3ce97d67ecc55475f0dfeec781');
t('#30 decrypt round-trip',
   Buffer.from(AES.zeroCbcDec('9834ed518cbc8fbe9af3c6ecb75eb8c0').data).toString('utf8'), 'hello');

console.log('\n== 5. rpc.exports.decrypt() on real captured ciphertext ==');
let d = rpc.decrypt('9834ed518cbc8fbe9af3c6ecb75eb8c0');
t('decrypt(#30 ct) finds plaintext', JSON.stringify(d.some(x => x.text === 'hello')), 'true');
d = rpc.decrypt('674c7ef38e78cabd9cec9c125823a639');
t('decrypt(#85 ct) finds plaintext', JSON.stringify(d.some(x => x.text === 'hello')), 'true');
t('decrypt(#85 ct) names the verified key',
   JSON.stringify(d.some(x => x.text === 'hello' && x.key.indexOf('plaintext .rodata key') === 0)), 'true');
/* the getter keys are 12 raw bytes — not a legal AES length — so they are only
   offered as explicitly-flagged guesses. Feed the ASCII key to prove the
   user-supplied path works end to end. */
d = rpc.decrypt(hx(AES.ecbEnc(enc('SECRET-PAYLOAD'), enc('5VEJK9Uk4d0elpVT'))),
                  '5VEJK9Uk4d0elpVT');
t('decrypt(ct, user-supplied 16B key)', JSON.stringify(d.some(x => x.text === 'SECRET-PAYLOAD')), 'true');
t('decrypt marks derived-key guesses',
   JSON.stringify(rpc.decrypt('00'.repeat(16), null, true)
        .filter(x => x.key && x.key.indexOf('[guess') >= 0)
        .every(x => x.guessed === true)), 'true');
t('decrypt never flags the verified 16/24/32B keys as guesses',
   JSON.stringify(rpc.decrypt('674c7ef38e78cabd9cec9c125823a639', null, true)
        .filter(x => x.cipher.indexOf('func#85') === 0 && x.key.indexOf('[guess') < 0)
        .every(x => !x.guessed)), 'true');

console.log('\n== 6. XOR-0x5A + Base64 = the 3-layer secret decoding (§4.2) ==');
const real = fs.readFileSync(path.join(__dirname, '..', 'work', 'apk_extracted', 'lib', 'arm64-v8a', 'libtopfollow.so'));
function dec(off, len) {
    const b = Array.from(real.slice(off, off + len));
    return Buffer.from(b.map(x => x ^ 0x5a)).toString('latin1');
}
t('KEY_CT  @0x17428', dec(OFF.rodata_key192_ct, 32), 'At91IxVnRSbFppV0UxNFdUSnplTW5ONA');
t('nonce1  @0x17448', dec(OFF.rodata_nonce1_ct, 16), 'WMVEwVG02eGFlVmR');
t('nonce2  @0x17458', dec(OFF.rodata_nonce2_ct, 16), 'M0VEwVGt0aVJuQjF');
t('plain key @0x161ca', real.slice(OFF.rodata_plain_key, OFF.rodata_plain_key + 16).toString('latin1'),
   '0123456789abcdef');
t('AES-192 key bytes', hx(b64decode('At91IxVnRSbFppV0UxNFdUSnplTW5ONA')),
   '02df752315674526c5a695745313457544a7a654d6e4e340');
t('nonce1 bytes (12)', hx(b64decode('WMVEwVG02eGFlVmR')), '58c544c151b4d9e185955991');
t('nonce2 bytes (12)', hx(b64decode('M0VEwVGt0aVJuQjF')), '334544c151add1a549b908c5');
t('#86 key bytes (12)', hx(b64decode('5VEJK9Uk4d0elpVT')), 'e551092bd524e1dd1e969553');
t('#159 key bytes',     hx(b64decode('OVmx02wMFR6WaGtW')), '3959b1d36c0c151e96686b56');
t('#160 key bytes',     hx(b64decode('V0V4V2pOa1ptZGsl')), '574578576a4e6b5a6d646b25');
t('#161 key bytes',     hx(b64decode('xV2xKTlZsBUVk1He')), 'c55db1293959b015159351de');
t('b64encode round-trip', sandbox.__x.b64encode(b64decode('At91IxVnRSbFppV0UxNFdUSnplTW5ONA')),
   'At91IxVnRSbFppV0UxNFdUSnplTW5ONA');

console.log('\n== 7. AES table anchors inside the real .so ==');
const SBOX_REF = Buffer.from(
 '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0' +
 'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275' +
 '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf' +
 'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2' +
 'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb' +
 'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08' +
 'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e' +
 'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16', 'hex');
t('S-box @0x128b0 == FIPS-197', real.slice(OFF.rodata_sbox, OFF.rodata_sbox + 256).equals(SBOX_REF), true);
const RSBOX = Buffer.alloc(256); for (let i = 0; i < 256; i++) RSBOX[SBOX_REF[i]] = i;
t('RS-box @0x139b0 == inverse', real.slice(0x139b0, 0x139b0 + 256).equals(RSBOX), true);
t('Rcon @0x13b10', real.slice(OFF.rodata_rcon, OFF.rodata_rcon + 14).toString('hex'),
   '01020408102040801b366cd8ab4d');
const te0 = Buffer.from('a56363c6', 'hex');
t('Te0 @0x118b0 first word', real.slice(0x118b0, 0x118b0 + 4).equals(te0), true);

console.log('\n== 8. JNI table + offsets sanity ==');
t('22 JNI natives declared', sandbox.__x.JNI_EXPECT.length, 22);
t('JNI_OnLoad offset', '0x' + OFF.jni_onload.toString(16), '0x3e1d4');
/* .data.rel.ro: va 0x1b6160 == file offset 0x1b2160 (delta 0x4000).
   The JNINativeMethod table is stored as ZEROES in the file and filled in by
   R_AARCH64_RELATIVE relocations (addend = the target VA), so we must apply
   them here — exactly like emu.py does, and exactly like the dynamic linker
   does on the phone before the agent's selfCalibrate() reads it. */
const RELVA = 0x1b6160, RELFO = 0x1b2160, DELTA = RELVA - RELFO;
const relocs = JSON.parse(fs.readFileSync(
    path.join(__dirname, '..', 'work', 'analysis', 'relocs.json'), 'utf8'));
const resolved = new Map();
relocs.forEach(r => { if (r.type === 268436483) resolved.set(r.addr, r.add); });

const cstrAt = va => { let o = va, out = '';
    while (o < real.length && real[o] !== 0 && out.length < 512) out += String.fromCharCode(real[o++]);
    return out; };

let names = [];
for (let i = 0; i < 22; i++) {
    const slotVA = OFF.jni_table_first_slot + i * 0x18;
    const nameVA = resolved.get(slotVA + 0x00);
    const sigVA  = resolved.get(slotVA + 0x08);
    const fn     = resolved.get(slotVA + 0x10);
    names.push([nameVA === undefined ? '<no reloc>' : cstrAt(nameVA),
                sigVA  === undefined ? '<no reloc>' : cstrAt(sigVA),
                fn     === undefined ? '<no reloc>' : '0x' + fn.toString(16)]);
}
t('JNI slot count readable', names.length, 22);
t('every slot has all 3 relocations',
   JSON.stringify(names.every(n => n[0] !== '<no reloc>' && n[1] !== '<no reloc>' && n[2] !== '<no reloc>')), 'true');
names.forEach((n, i) => {
    const E = sandbox.__x.JNI_EXPECT[i];
    t('JNI #' + String(i).padStart(2) + ' ' + n[0] + ' ' + n[1].slice(0, 34),
      n[0] + '|' + n[1] + '|' + n[2],
      E[0] + '|' + E[1] + '|0x' + E[2].toString(16));
});

/* the fnPtr offsets must point INSIDE the RX segment (v_addr 0, size 0x1b2160) */
t('all 22 fnPtr offsets inside .text segment',
   JSON.stringify(names.every(n => { const v = parseInt(n[2], 16); return v > 0x2d2ac && v < 0x1b2160; })), 'true');

console.log('\n== 9. rpc.exports.vectors() / knownKeys() ==');
const vec = rpc.vectors();
t('vectors()["func#30(\"\")"]', vec['func#30("")'], '0143db63ee66b0cdff9f69917680151e');
t('knownKeys() count', rpc.knownKeys().length, 9);
t('knownKeys has AES-192', JSON.stringify(rpc.knownKeys().some(k => k.hex === '02df752315674526c5a695745313457544a7a654d6e4e340')), 'true');

/* ===================================================================== */
console.log('\n== 10. detection-token coverage (rev 4) ==');
/* The scanners store their tokens as PLAIN Base64 C strings in .rodata, so the
   literals never appear in the binary.  Decode every Base64 C string in the
   .rodata window straight out of the real .so and require the agent's
   suppression list to cover each decoded detection token. */
const B64SET = new Set(Buffer.from(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=', 'ascii'));
const B64IDX = {};
'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.split('')
    .forEach((ch, i) => { B64IDX[ch] = i; });
/* Buffer.from(x,'base64') is lenient and silently skips bad characters, which
   produces phantom "decodes". Node's Buffer has no strict mode, so decode by hand. */
function b64Strict(str) {
    if (!str.length || str.length % 4) return null;
    for (const ch of str) if (!B64SET.has(ch.charCodeAt(0))) return null;
    let pad = 0;
    while (pad < 2 && str[str.length - 1 - pad] === '=') pad++;
    const body = str.slice(0, str.length - pad);
    for (const ch of body) if (B64IDX[ch] === undefined) return null;
    const out = [];
    for (let i = 0; i + 1 < body.length; i += 4) {
        const n = (B64IDX[body[i]] << 18) | (B64IDX[body[i + 1]] << 12) |
                  ((i + 2 < body.length ? B64IDX[body[i + 2]] : 0) << 6) |
                   (i + 3 < body.length ? B64IDX[body[i + 3]] : 0);
        out.push((n >> 16) & 0xff);
        if (i + 2 < body.length) out.push((n >> 8) & 0xff);
        if (i + 3 < body.length) out.push(n & 0xff);
    }
    return Buffer.from(out);
}
function b64CStrings(buf, lo, hi) {
    const out = [];
    let i = lo;
    while (i < hi) {
        const z = buf.indexOf(0, i);
        const end = (z < 0 || z > hi) ? hi : z;
        const slice = buf.slice(i, end);
        if (slice.length >= 4 && slice.length % 4 === 0 &&
            slice.every(c => B64SET.has(c))) out.push([i, slice.toString('ascii')]);
        i = end + 1;
    }
    return out;
}
const decodedTokens = [];
b64CStrings(real, 0x13000, 0x1c000).forEach(([off, str]) => {
    let cur = str;
    for (let layer = 0; layer < 3; layer++) {
        const nxt = b64Strict(cur);
        if (!nxt || nxt.length < 3) break;
        if (!nxt.every(c => c >= 32 && c < 127)) break;
        const txt = nxt.toString('ascii');
        decodedTokens.push([off, layer + 1, txt]);
        cur = txt;
    }
});
t('decoded at least 30 Base64-hidden strings from the real .so',
   JSON.stringify(decodedTokens.length >= 30), 'true');

const MAPS_NOISE = sandbox.__x.MAPS_NOISE;
/* every decoded token that is a detection token must be in the suppression list */
const MUST_COVER = ['libbridge.so', 'riru', 'libcso_substrate', 'substrate', 'edxposed',
                    'lsposed', 'xposed', 'ygsik', 'frida', 're.frida.server',
                    'gum-js-loop', 'libfrida-gadget', '/proc/self/maps', 'rwxp',
                    'libart.so (deleted)', 'libc.so (deleted)'];
MUST_COVER.forEach(tok => {
    const present = decodedTokens.some(d => d[2] === tok);
    t('token ' + JSON.stringify(tok) + ' really is in the .so (Base64-hidden)',
      JSON.stringify(present), 'true');
    const covered = MAPS_NOISE.some(n => tok.toLowerCase().indexOf(n.toLowerCase()) >= 0);
    t('  ...and is covered by MAPS_NOISE', JSON.stringify(covered), 'true');
});

/* the endpoints must decode too (they are the request/response evidence) */
[['https://i.instagram.com/api/v2/', 0x159ec], ['https://www.instagram.com/', 0x15c02],
 ['create_note/v2/', 0x14bf4], ['seen/', 0x16b60], ['/save/', 0x14de8],
 ['d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e', 0x15084]
].forEach(([want, off]) => {
    const got = decodedTokens.filter(d => d[0] === off).map(d => d[2]);
    t('endpoint/pin @0x' + off.toString(16) + ' decodes to ' + JSON.stringify(want),
      JSON.stringify(got.indexOf(want) >= 0), 'true');
});

console.log('\n== 11. filterMapsBuffer — length-preserving read() rewrite (rev 4) ==');
/* libtopfollow.so imports no fgets and no strstr: its maps readers
   (#129/#198/#213) use __open_2 + __read_chk/read.  filterMapsBuffer is what
   cleans the buffer between read() returning and the inline scanner running. */
function fakeBuf(str) {
    const b = Buffer.from(str, 'latin1');
    return {
        _b: b,
        readByteArray(n) { return b.slice(0, n).buffer.slice(b.byteOffset, b.byteOffset + Math.min(n, b.length)); },
        writeByteArray(arr) { for (let i = 0; i < arr.length; i++) b[i] = arr[i]; }
    };
}
const MAPS = [
    '7a1b000000-7a1b021000 r--p 00000000 fd:00 1234   /apex/com.android/runtime/lib64/bionic/libc.so',
    '7b2c000000-7b2c004000 r-xp 00000000 00:00 0      [anon:libfrida-gadget.so]',
    '7b3d000000-7b3d001000 rwxp 00000000 00:00 0      [anon:frida-gum-js-loop]',
    '7b4e000000-7b4e002000 r--p 00000000 fd:00 999    /data/adb/modules/riru_core/libbridge.so',
    '7b5f000000-7b5f009000 r-xp 00000000 fd:00 777    /system/lib64/libcso_substrate.so',
    '7b60000000-7b6000a000 r--p 00000000 fd:00 555    /data/app/~~x/com.nivaroid.topfollow/lib/arm64/libtopfollow.so',
    '7b71000000-7b71001000 r--p 00000000 00:00 0      /memfd:jit-cache (deleted)',
    '7b82000000-7b82010000 r-xp 00000000 fd:00 444    /apex/com.android.art/lib64/libart.so (deleted)'
].join('\n') + '\n';
const fb = fakeBuf(MAPS);
const nChanged = sandbox.__x.filterMapsBuffer(fb, Buffer.byteLength(MAPS, 'latin1'));
const after = fb._b.toString('latin1');
t('rewrote the suspicious lines', JSON.stringify(nChanged >= 5), 'true');
t('buffer LENGTH PRESERVED (read() return value stays valid)',
   JSON.stringify(after.length === MAPS.length), 'true');
t('line count preserved', JSON.stringify(after.split('\n').length === MAPS.split('\n').length), 'true');
['libfrida-gadget', 'frida-gum-js-loop', 'rwxp', 'riru', 'libbridge.so',
 'libcso_substrate', 'libart.so (deleted)'].forEach(tok => {
    t('  token ' + JSON.stringify(tok) + ' no longer present',
      JSON.stringify(after.toLowerCase().indexOf(tok.toLowerCase()) < 0), 'true');
});
/* and the innocent lines must survive untouched */
['/apex/com.android/runtime/lib64/bionic/libc.so',
 'libtopfollow.so'].forEach(keep => {
    t('  innocent line kept: ' + keep.slice(-34), JSON.stringify(after.indexOf(keep) >= 0), 'true');
});
/* no newline in the chunk -> must be a no-op */
const fb2 = fakeBuf('7b2c000000-7b2c004000 r-xp 00000000 00:00 0 [anon:libfrida');
t('partial line (no \\n) is left alone',
   JSON.stringify(sandbox.__x.filterMapsBuffer(fb2, 58)), '0');

console.log('\n== 12. func#36 / GCM claims recorded by the agent ==');
t('OFF has the three maps readers',
   JSON.stringify([OFF.maps_reader_129, OFF.maps_reader_198, OFF.maps_reader_213]),
   JSON.stringify([0x11deb0, 0x143694, 0x151e68]));
t('OFF.big_scanner_60', JSON.stringify(OFF.big_scanner_60), JSON.stringify(0x081c58));
t('func#36 offset renamed to aes256_ecb_dechex',
   JSON.stringify(OFF.aes256_ecb_dechex), JSON.stringify(0x03a838));
t('pin blob key renamed to rodata_pin_b64x2',
   JSON.stringify(OFF.rodata_pin_b64x2), JSON.stringify(0x15084));
/* the reader offsets must be real functions in the .so (non-zero, inside .text) */
[OFF.maps_reader_129, OFF.maps_reader_198, OFF.maps_reader_213, OFF.big_scanner_60].forEach(o => {
    t('  offset 0x' + o.toString(16) + ' is inside the RX segment',
      JSON.stringify(o > 0x2d2ac && o < 0x1b2160), 'true');
});

console.log('\n=====================================');
console.log('  PASS ' + pass + '   FAIL ' + fail);
console.log('=====================================');
process.exit(fail ? 1 : 0);
