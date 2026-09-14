/*
 * test_capture_offline.js — runs topfollow_capture.js under Node with the Frida
 * API stubbed and the REAL libtopfollow.so bytes as the module's memory.
 *
 *   node frida/test_capture_offline.js        (from the repository root)
 *
 * What this proves without a phone:
 *   1. the script parses and boots;
 *   2. calibrate() passes every anchor against the real bytes — all eleven
 *      Rijndael tables, the literal AES key, the 120-char pin blob, the "AES"
 *      name string, JNI_OnLoad's export offset AND its four `blr x8` sites;
 *   3. calibrate() rebuilds all 22 RegisterNatives slots. The table at
 *      0x1b6198 is ZERO in the file and is filled by 66 R_AARCH64_RELATIVE
 *      relocations, so this only passes if the offsets, the relocation
 *      handling AND the .data.rel.ro address→file-offset delta (-0x4000) are
 *      all right;
 *   4. every slot's name/signature/fnPtr agrees with the plaintext "x00NNNNNN"
 *      string in .rodata that its relocation points at;
 *   5. the XOR-0x5A key blob decodes to the AES-192 key and both GCM nonces;
 *   6. the pin blob double-Base64-decodes to SHA-256 of the signer cert;
 *   7. the 21 Base64 blobs in B64_BLOBS really are in the file at the stated
 *      offsets and really decode, recursively, to the stated plaintext;
 *   8. the JSONL sink writes one valid JSON object per event;
 *   9. the read-only contract holds — no retval.replace, no
 *      Interceptor.replace, and func#224 is not in any hook list;
 *  10. the pure helpers (strict Base64, JNI signature parser, std::string
 *      reader, KNOWN_KEYS labelling) behave.
 *
 * Needs work/apk_extracted/ and work/analysis/relocs.json — see
 * work/REPRODUCE.md steps 2 and 5.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const HERE = __dirname, ROOT = path.resolve(HERE, '..');
const SRC = fs.readFileSync(path.join(HERE, 'topfollow_capture.js'), 'utf8');
const SOPATH = path.join(ROOT, 'work', 'apk_extracted', 'lib', 'arm64-v8a', 'libtopfollow.so');
const RELPATH = path.join(ROOT, 'work', 'analysis', 'relocs.json');
if (!fs.existsSync(SOPATH)) {
    console.error('missing ' + SOPATH + '\n  run: unzip -o TopFollow_v845-Beta.apk -d work/apk_extracted');
    process.exit(2);
}
if (!fs.existsSync(RELPATH)) {
    console.error('missing ' + RELPATH + '\n  run: cd work && python analysis/xref.py  (see REPRODUCE.md)');
    process.exit(2);
}

let pass = 0, fail = 0;
function t(name, got, want) {
    const g = String(got), w = String(want);
    if (g === w) { pass++; console.log('  ok   ' + name); }
    else { fail++; console.log('  FAIL ' + name + '\n         got    ' + g + '\n         expect ' + w); }
}

/* ---------------- the fake module image ---------------- */
const raw = fs.readFileSync(SOPATH);
const img = Buffer.from(raw);                       /* mutable copy */
const BASE = 0x7000000000n;

/* .rodata / .text have file offset == virtual address. Everything from
   .data.rel.ro (VA 0x1b6160) onwards is shifted: its file offset is 0x1b2160.
   Getting this wrong makes the whole JNI table look zeroed. */
const RELRO_VA = 0x1b6160, RELRO_DELTA = 0x4000;
const off = a => (a >= RELRO_VA ? a - RELRO_DELTA : a);

/* Apply R_AARCH64_RELATIVE (268436483) exactly like the dynamic linker would,
   so the RegisterNatives table at 0x1b6198 is populated. */
const rels = JSON.parse(fs.readFileSync(RELPATH, 'utf8'));
const R_RELATIVE = 268436483;
let applied = 0, tableRels = 0;
rels.forEach(r => {
    if (r.type !== R_RELATIVE) return;
    const o = off(r.addr);
    if (o < 0 || o + 8 > img.length) return;
    img.writeBigUInt64LE(BASE + BigInt(r.add), o);
    applied++;
    if (r.addr >= 0x1b6198 && r.addr < 0x1b6198 + 22 * 0x18) tableRels++;
});

/* ---------------- NativePointer backed by that image ---------------- */
function P(v) {
    const n = typeof v === 'string'
        ? (v.startsWith('0x') ? BigInt(v) : BigInt(parseInt(v, 10)))
        : (typeof v === 'bigint' ? v : BigInt(v || 0));
    /* A runtime address maps back into the file through the section that
       contains it. .rodata and .text have offset == VA; everything from
       .data.rel.ro (VA 0x1b6160) on is shifted by -0x4000. Applying the delta
       only while relocating is NOT enough: the script dereferences the table at
       its VA, so the delta has to live in the pointer itself — which is exactly
       what the kernel does when it maps the segments. */
    const o = () => off(Number(n - BASE));
    const api = {
        _v: n,
        add(x) { return P(n + (x && x._v !== undefined ? x._v : BigInt(x || 0))); },
        sub(x) { return P(n - (x && x._v !== undefined ? x._v : BigInt(x || 0))); },
        and(m) { return P(n & BigInt(m)); },
        shr(b) { return P(n >> BigInt(b)); },
        compare(x) { return n < x._v ? -1 : n > x._v ? 1 : 0; },
        isNull() { return n === 0n; },
        toInt32() { return Number(BigInt.asIntN(32, n)) | 0; },
        toUInt32() { return Number(n & 0xffffffffn); },
        toString() { return '0x' + n.toString(16); },
        readU8() { return img[o()]; },
        readU32() { return img.readUInt32LE(o()); },
        readULong() { return img.readBigUInt64LE(o()); },
        readPointer() { return P(img.readBigUInt64LE(o())); },
        readByteArray(k) {
            const a = o();
            return img.buffer.slice(img.byteOffset + a, img.byteOffset + a + k);
        },
        readUtf8String(k) {
            const a = o(); let e = a;
            const lim = k ? Math.min(a + k, img.length) : img.length;
            while (e < lim && img[e] !== 0) e++;
            return img.slice(a, e).toString('utf8');
        },
        readCString() { return api.readUtf8String(); },
        /* Real writers. The no-op stubs these replace would have let a broken
           length-preserving maps rewrite pass silently — the buffer would
           simply never change and nothing would notice. */
        writeU8(v) { img[o()] = v & 0xff; },
        writeUtf8String(str) {
            const b = Buffer.from(String(str), 'utf8');
            b.copy(img, o());
            return api;
        },
        writeByteArray(bytes) {
            const b = Buffer.isBuffer(bytes) ? bytes
                    : Buffer.from(Array.from(bytes, x => Number(x) & 0xff));
            b.copy(img, o());
            return api;
        },
        writePointer(v) {
            img.writeBigUInt64LE(typeof v === 'bigint' ? v : BigInt(v._v || v), o());
            return api;
        }
    };
    return api;
}

/* ---------------- the fake libc, and the JSONL it "writes" -------------- */
const WRITTEN = [];
const FD = 7;
let failOpen = false;
function mkNativeFunction(addr) {
    const a = String(addr);
    return function () {
        const args = Array.prototype.slice.call(arguments);
        if (a === '0x1001') {                                   /* open  */
            if (failOpen) return -1;
            SINKPATHS.push(args[0] && args[0]._s ? args[0]._s : '<?>');
            return FD;
        }
        if (a === '0x1002') {                                   /* write */
            const p = args[1], cnt = Number(args[2]);
            const text = (p && p._s !== undefined) ? p._s : '<binary ' + cnt + 'B>';
            WRITTEN.push(text);
            return cnt;
        }
        if (a === '0x1003') return 0;                           /* close */
        return 0;
    };
}
const SINKPATHS = [];
const EXPORT_ADDR = { open: '0x1001', write: '0x1002', close: '0x1003' };
let exportCounter = 0x1100;

const attached = [];       /* every address Interceptor.attach was given */
const replaced = [];       /* must stay empty */
const noop = () => {};

const sandbox = {
    console: { log: noop, info: noop, warn: noop, error: noop, debug: noop },
    setTimeout, setInterval, clearInterval, clearTimeout,
    TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, Buffer, Date, Math, JSON,
    Object, Array, String, Number, BigInt, Set, Map, RegExp, Error, TypeError,
    parseInt, parseFloat, isNaN,
    ptr: P,
    send: noop, recv: noop,
    Process: {
        id: 4242, arch: 'arm64', platform: 'android', pageSize: 4096, pointerSize: 8,
        getCurrentThreadId: () => 4242,
        findModuleByName: nm => nm === 'libtopfollow.so'
            ? { name: 'libtopfollow.so', base: P(BASE), size: img.length, path: '/data/app/libtopfollow.so' }
            : null,
        findModuleByAddress: () => null,
        enumerateModules: () => []
    },
    Module: {
        findExportByName: (m, nm) => (nm === 'JNI_OnLoad' ? P(BASE + 0x3e1d4n) : P(0x1000n)),
        getExportByName: (m, nm) => {
            if (EXPORT_ADDR[nm]) return P(BigInt(EXPORT_ADDR[nm]));
            exportCounter += 4;
            return P(BigInt(exportCounter));
        },
        findBaseAddress: () => P(BASE),
        load: noop, enumerateExports: () => [], enumerateRanges: () => []
    },
    Interceptor: {
        attach: (target, cb) => { attached.push(target.toString()); return { detach: noop }; },
        replace: (target, fn) => { replaced.push(target.toString()); },
        detachAll: noop
    },
    NativeFunction: function (addr) { return mkNativeFunction(addr); },
    NativeCallback: function () { return P(0); },
    Memory: {
        alloc: () => P(0x9000n),
        allocUtf8String: str => { const p = P(0x9000n); p._s = String(str); return p; },
        protect: noop, scanSync: () => []
    },
    Thread: { backtrace: () => [] },
    Backtracer: { FUZZY: 0, ACCURATE: 1 },
    DebugSymbol: { fromAddress: a => ({ toString: () => String(a) }) },
    Frida: { version: '17.18.0' },
    Script: { unload: noop, pin: noop },
    Java: { available: false, perform: noop, vm: null,
            use: () => { throw new Error('no java in the offline harness'); },
            registerClass: () => ({ $new: () => ({}) }), scheduleOnMainThread: noop },
    hexdump: () => '',
    rpc: { exports: {} },
    globalThis: null
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
sandbox.TOPFOLLOW_CAPTURE_NO_AUTOBOOT = true;
vm.runInContext(SRC, sandbox, { filename: 'topfollow_capture.js' });

console.log('== 1. source-level read-only contract ==');
/* Two things have to be removed before this check means anything:
     (a) comments and string literals — the script legitimately *mentions*
         retval.replace() in its header and in rpc.exports.help(), documenting
         the contract rather than breaking it;
     (b) the region between the BEGIN/END BYPASS MODE markers, which is the
         one place in the file allowed to write, and which is dead code unless
         CFG.bypass.enabled is set.
   Section 15 then proves that (b) really is where ALL of the mutation lives:
   strip it and the rest of the file must be clean, and with it in place the
   default configuration must still not call a single one of them. */
/* The markers come in pairs: `>>>>>` opens a region, `<<<<<` closes it. There
   is one large region (section 7B, the whole bypass implementation) and six
   small inline ones, each wrapping a single `if (BYPASS_ON …)` fragment inside
   an otherwise read-only hook. Balanced pairs are asserted first — an unpaired
   marker would silently strip or keep the wrong half of the file. */
const N_OPEN  = (SRC.match(/>>>>>/g) || []).length;
const N_CLOSE = (SRC.match(/<<<<</g) || []).length;
t('the bypass markers are balanced', String(N_OPEN), String(N_CLOSE));
t('there are 7 marked regions (1 implementation block + 6 inline fragments)',
  String(N_OPEN), '7');
const REGION_RE = />[>]{4}[\s\S]*?<[<]{4}/g;
const marked = SRC.match(REGION_RE) || [];
t('every marked region is non-trivial code', String(marked.every(m => m.length > 40)), 'true');
t('the big region really holds the bypass implementation',
  String(marked.some(m => m.indexOf('function bypassSignatureForgery') >= 0)), 'true');
const INLINE = marked.filter(m => m.indexOf('function bypassSignatureForgery') < 0);
/* Four of the six inline regions contain the mutation itself and must be gated
   on BYPASS_ON. The other two are only the `retvalNote` label — they report
   whether a write happened (`filtered > 0`, `forced`), which is what keeps the
   JSONL self-describing, so they carry no gate of their own. */
const MUTATING = INLINE.filter(m => /retval\s*\.\s*replace\s*\(|bypassReplace\s*\(|filterMapsBuffer\s*\(|bypassSignatureForgery\s*\(/
                                 .test(m));
t('four inline regions actually mutate', String(MUTATING.length), '4');
t('every mutating inline region is gated on BYPASS_ON',
  String(MUTATING.every(m => m.indexOf('BYPASS_ON') >= 0)), 'true');
t('the two non-mutating inline regions are the retvalNote labels',
  String(INLINE.length - MUTATING.length), '2');
t('no retval.replace / Interceptor.replace hides OUTSIDE a marked region',
  JSON.stringify(/retval\s*\.\s*replace\s*\(|Interceptor\s*\.\s*replace\s*\(/
      .test(SRC.replace(REGION_RE, ' ')
               .replace(/\/\*[\s\S]*?\*\//g, ' ')
               .replace(/(^|[^:'"\\])\/\/[^\n]*/g, '$1 ')
               .replace(/'(?:[^'\\\n]|\\.)*'/g, "''")
               .replace(/"(?:[^"\\\n]|\\.)*"/g, '""')
               .replace(/`(?:[^`\\]|\\.)*`/g, '``'))), 'false');
const SRC_NO_BYPASS = SRC.replace(REGION_RE, ' ');
const CODE_ONLY = SRC_NO_BYPASS
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:'"\\])\/\/[^\n]*/g, '$1 ')
    .replace(/'(?:[^'\\\n]|\\.)*'/g, "''")
    .replace(/"(?:[^"\\\n]|\\.)*"/g, '""')
    .replace(/`(?:[^`\\]|\\.)*`/g, '``');
t('no Interceptor.replace CALL in the code',
  JSON.stringify(/Interceptor\s*\.\s*replace\s*\(/.test(CODE_ONLY)), 'false');
t('no retval.replace CALL in the code',
  JSON.stringify(/retval\s*\.\s*replace\s*\(/.test(CODE_ONLY)), 'false');
t('no returnValue.replace CALL in the code',
  JSON.stringify(/returnValue\s*\.\s*replace\s*\(/.test(CODE_ONLY)), 'false');
t('no retval*.replace( on any InvocationReturnValue in the code',
  JSON.stringify(/\bretval\w*\s*\.\s*replace\s*\(/.test(CODE_ONLY)), 'false');
t('the source DOES document the contract in prose (so the strip really ran)',
  String(SRC.indexOf('retval.replace') >= 0), 'true');
t('outside the marked regions there is no write of any kind',
  JSON.stringify(/\.(writeUtf8String|writeByteArray|writeU8|writeU32|writePointer)\s*\(/
      .test(SRC_NO_BYPASS
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/(^|[^:'"\\])\/\/[^\n]*/g, '$1 ')
      .replace(/'(?:[^'\\\n]|\\.)*'/g, "''")
      .replace(/"(?:[^"\\\n]|\\.)*"/g, '""')
      .replace(/`(?:[^`\\]|\\.)*`/g, '``')
      /* the JSONL sink legitimately writes to ITS OWN log file */
      .replace(/function sinkWrite[\s\S]*?\n}/g, ' ')
      .replace(/function sinkOpen[\s\S]*?\n}/g, ' ')
      .replace(/function sinkInit[\s\S]*?\n}/g, ' '))), 'false');
t('BYPASS_ON is false with the shipped defaults',
  JSON.stringify(vm.runInContext('BYPASS_ON()', sandbox)), 'false');
t('CFG.bypass.enabled is false with the shipped defaults',
  JSON.stringify(vm.runInContext('CFG.bypass.enabled', sandbox)), 'false');
t('CFG.bypass is still fully specified when off (so turning it on needs one flag)',
  JSON.stringify(vm.runInContext(
      'Object.keys(CFG.bypass).sort().join(",")', sandbox)),
  '"enabled,fakeClock,forceReturn,hideMaps,hideSuPaths,spoofSignature"');
t('Interceptor.replace was never invoked at runtime', String(replaced.length), '0');
t('CFG.hookTrapFunc224 defaults to false',
  JSON.stringify(vm.runInContext('CFG.hookTrapFunc224', sandbox)), 'false');
t('CFG.captureAesLayer defaults to false (one event per 16-byte block)',
  JSON.stringify(vm.runInContext('CFG.captureAesLayer', sandbox)), 'false');
t('CFG.captureStrings defaults to true',
  JSON.stringify(vm.runInContext('CFG.captureStrings', sandbox)), 'true');

console.log('\n== 2. relocations: the JNI table only exists after them ==');
t('R_AARCH64_RELATIVE relocations applied', String(applied > 1000), 'true');
t('exactly 66 of them fill the 22x3 RegisterNatives table', String(tableRels), '66');
t('.data.rel.ro needs a -0x4000 address to file-offset delta',
  String(off(0x1b6198) === 0x1b2198), 'true');
t('.text and .rodata need no delta', String(off(0x128b0) === 0x128b0 && off(0x3e1d4) === 0x3e1d4), 'true');

console.log('\n== 3. calibrate() against the real bytes ==');
vm.runInContext('MOD = findModule();', sandbox);
const cal = vm.runInContext('calibrate()', sandbox);
const C = name => { const c = cal.checks.find(x => x.name === name); return c ? c.got : '<no such check: ' + name + '>'; };
t('calibrate().ok', JSON.stringify(cal.ok), 'true');
t('module size', C('module size'), '1805400');
t('Te0 @0x118b0', C('Te0   @0x118b0'), 'a56363c6847c7cf8');
t('Td0 @0x129b0', C('Td0   @0x129b0'), '50a7f4515365417e');
t('S-box @0x128b0', C('S-box @0x128b0'), '637c777bf26b6fc5');
t('RSbox @0x139b0', C('RSbox @0x139b0'), '52096ad53036a538');
t('Rcon @0x13b10', C('Rcon  @0x13b10'), '0102040810204080');
t('Te1 = Te0 rotated right 1 byte', C('Te1 is Te0 rotated right 1 byte'), '6363c6a5');
t('Te3 = Te0 rotated right 3 bytes', C('Te3 is Te0 rotated right 3 bytes'), 'c6a56363');
t('Td3 = Td0 rotated right 3 bytes', C('Td3 is Td0 rotated right 3 bytes'), '5150a7f4');
t('"AES" @0x14b31', C('"AES" @0x14b31 is the only cipher name in .rodata'), 'AES');
t('plain key @0x161ca', C('plain key @0x161ca'), '0123456789abcdef');
t('pin blob is 120 chars', C('pin blob is 120 chars'), '120');
t('JNI_OnLoad export @0x3e1d4', C('JNI_OnLoad export @0x3e1d4'), '0x3e1d4');
t('JNI_OnLoad GetEnv site is blr x8',
  C('JNI_OnLoad GetEnv          @0x3e308 is blr x8'), '0xd63f0100');
t('JNI_OnLoad FindClass site is blr x8',
  C('JNI_OnLoad FindClass       @0x3e860 is blr x8'), '0xd63f0100');
t('JNI_OnLoad RegisterNatives site is blr x8',
  C('JNI_OnLoad RegisterNatives @0x3e93c is blr x8'), '0xd63f0100');
t('JNI_OnLoad RegisterNatives duplicate site is blr x8',
  C('JNI_OnLoad RegisterNatives @0x3e988 is blr x8'), '0xd63f0100');
t('FindClass argument is the helper class',
  C('FindClass argument is the helper class'), 'com/nivaroid/topfollow/helper/q');
t('RegisterNatives nMethods immediate is 22',
  C('RegisterNatives nMethods immediate is 22'), '0x528002c3');
t('  ...and it really is the word at 0x3e928', img.readUInt32LE(0x3e928).toString(16), '528002c3');
t('key blob XOR-0x5A is ASCII', C('key blob @0x17428 XOR-0x5A is ASCII'), 'yes');
t('AES-192 key decoded from the blob', cal.aes192key, '02df752315674526c5a695745313457544a7a654d6e4e340');
t('GCM nonce 1 decoded', cal.nonce1, '58c544c151b4d9e185955991');
t('GCM nonce 2 decoded', cal.nonce2, '334544c151add1a549b908c5');
t('pin blob double-Base64 -> SHA-256 of the signer cert', cal.pinDecoded,
  'd845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e');
t('all 22 JNI slots match the report', String(cal.jniGood), '22');
t('all 22 .rodata name strings match the table',
  C('.rodata name strings match the table'), '22');
t('no drift', JSON.stringify(cal.drift), '[]');
t('every calibrate() check passed (list of failures is empty)',
  JSON.stringify(cal.checks.filter(x => !x.ok).map(x => x.name + ': got ' + x.got + ' want ' + x.want)), '[]');

console.log('\n== 4. the 22 slots, name by name, with the DEX wrapper letter ==');
const EXPECT = [
    [0, 'q.j', 'x0011a4c2', '()J', '0x3eab4', 51, '0x15315'],
    [1, 'q.e', 'x0014e2e9', '()Ljava/lang/String;', '0x3f034', 52, '0x15b2c'],
    [2, 'q.d', 'x0016d3b9', '()Ljava/lang/String;', '0x3f3c8', 53, '0x16607'],
    [3, 'q.o', 'x0012d3e0', '(Ljava/lang/String;)Ljava/lang/String;', '0x3f688', 54, '0x161db'],
    [4, 'q.n', 'x0011e28b', '(Ljava/lang/String;)Ljava/lang/String;', '0x4110c', 55, '0x1547c'],
    [5, 'q.i', 'x00120b1e', '(Lcom/google/gson/JsonObject;Ljava/lang/String;)V', '0x435b8', 56, '0x16cca'],
    [6, 'q.v', 'x0012e5a1', '(Lcom/google/gson/JsonObject;)V', '0x4f078', 57, '0x16b3a'],
    [7, 'q.u', 'x00135e2a', '(Lcom/google/gson/JsonObject;Lcom/nivaroid/topfollow/models/InstagramAccount;Ljava/lang/String;)V', '0x76508', 58, '0x16cd4'],
    [8, 'q.c', 'x00105e9b', '(Ljava/lang/String;)Ljava/lang/String;', '0x7f82c', 59, '0x1705c'],
    [9, 'q.r', 'x0015b1e9', '(Lcom/google/gson/JsonObject;Ljava/lang/String;Ljava/lang/String;)V', '0x81c58', 60, '0x1685d'],
    [10, 'q.t', 'x0015a3b7', '(Lcom/google/gson/JsonObject;Lcom/nivaroid/topfollow/models/InstagramAccount;Lcom/nivaroid/topfollow/models/Order;)V', '0xadacc', 61, '0x15ed0'],
    [11, 'q.s', 'x0017b62c', '(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;', '0xbf7fc', 62, '0x15b36'],
    [12, 'q.m', 'x0011f42b', '()Ljava/lang/String;', '0xc67a4', 63, '0x16a45'],
    [13, 'q.b', 'x0012f5b7', '()Ljava/lang/String;', '0xcbeac', 64, '0x16a4f'],
    [14, 'q.a', 'x0014b4f3', '(Ljava/lang/String;)Ljava/lang/String;', '0xd46a8', 65, '0x16867'],
    [15, 'q.h', 'x0011f1a2', '(Lcom/nivaroid/topfollow/models/Order;)Ljava/lang/String;', '0xd80e8', 66, '0x16400'],
    [16, 'q.p', 'x0015e49c', '(Lretrofit2/Response;Lcom/nivaroid/topfollow/models/Order;Lcom/nivaroid/topfollow/models/InstagramAccount;)Ljava/lang/String;', '0xe01e4', 67, '0x16871'],
    [17, 'q.f', 'x0010e27f', '()Ljava/lang/String;', '0xfcd60', 68, '0x162d7'],
    [18, 'q.g', 'x00113f7a', '()Ljava/lang/String;', '0xfd010', 69, '0x16a59'],
    [19, 'q.q', 'x0014c1f9', '(Lretrofit2/Response;)Ljava/lang/String;', '0xfd540', 70, '0x1687b'],
    [20, 'q.k', 'x00126f7c', '(ZLjava/lang/String;)Lretrofit2/Retrofit;', '0xfe268', 71, '0x15da9'],
    [21, 'q.l', 'x0018d3f7', '(I)Lretrofit2/Retrofit;', '0x1013b8', 72, '0x15334']
];
cal.jniSlots.forEach((s, i) => {
    const e = EXPECT[i];
    t('slot ' + String(i).padStart(2) + ' ' + e[1] + ' ' + e[2],
      [s.name, s.sig, s.fnPtr, s.wrapper, s.funcNo, s.nameStrOff].join('|'),
      [e[2], e[3], e[4], e[1], e[5], e[6]].join('|'));
});
t('slot 6 fnPtr == func#57 (the 160,912-byte hub)', cal.jniSlots[6].fnPtr, '0x4f078');
t('slot 9 fnPtr == func#60 (the 179,828-byte scanner)', cal.jniSlots[9].fnPtr, '0x81c58');
t('slot 13 fnPtr == func#64 (the GCM-context native)', cal.jniSlots[13].fnPtr, '0xcbeac');
t('slot 16 fnPtr == func#67 (the response handler)', cal.jniSlots[16].fnPtr, '0xe01e4');
t('slot 20 fnPtr == func#71 (the cert pinner)', cal.jniSlots[20].fnPtr, '0xfe268');
t('the 22 wrapper letters are exactly a..v',
  cal.jniSlots.map(s => s.wrapper.slice(2)).sort().join(''), 'abcdefghijklmnopqrstuv');
t('the 22 func numbers are exactly 51..72',
  cal.jniSlots.map(s => s.funcNo).sort((a, b) => a - b).join(','),
  Array.from({ length: 22 }, (_, k) => 51 + k).join(','));

console.log('\n== 5. the randomised native names carry no arithmetic relation to fnPtr ==');
vm.runInContext(`globalThis.__c = {
    b64decodeStrict: b64decodeStrict, printable: printable, bytesToHex: bytesToHex,
    parseSigParams: parseSigParams, jtypeToJava: jtypeToJava, xorBytes: xorBytes,
    readStdString: readStdString, readStd: readStd, keyLabel: keyLabel,
    KNOWN_KEYS: KNOWN_KEYS, JNI_EXPECT: JNI_EXPECT, OFF: OFF, CFG: CFG, SINK: SINK,
    B64_BLOBS: B64_BLOBS, emit: emit, noteKey: noteKey, trunc: trunc,
    SIGNATURE_PIN_SHA256: SIGNATURE_PIN_SHA256,
    /* --- bypass mode (revision 7) --- */
    BYPASS_ON: BYPASS_ON, BYPASS: BYPASS, MAPS_NOISE: MAPS_NOISE, SU_PATHS: SU_PATHS,
    mapsLineIsSuspicious: mapsLineIsSuspicious, filterMapsBuffer: filterMapsBuffer,
    isSuPath: isSuPath, bypassReplace: bypassReplace,
    bypassSignatureForgery: bypassSignatureForgery,
    ORIGINAL_SIGNER_CERT_B64: ORIGINAL_SIGNER_CERT_B64,
    hookDetection: hookDetection
};`, sandbox);
const H = sandbox.__c;
const b2s = a => String.fromCharCode.apply(null, a);
const deltas = H.JNI_EXPECT.map(e => parseInt(e[1].slice(1), 16) - e[3]);
t('all 22 (name value - fnPtr) deltas are different',
  String(new Set(deltas).size), '22');
t('no delta is 0 (the name is not the offset)', String(deltas.filter(d => d === 0).length), '0');
t('the names are NOT sorted in the .so table',
  JSON.stringify(H.JNI_EXPECT.map(e => e[1]) === H.JNI_EXPECT.map(e => e[1]).slice().sort()), 'false');
t('but they ARE all of the form x00 + 6 hex digits',
  String(H.JNI_EXPECT.every(e => /^x00[0-9a-f]{6}$/.test(e[1]))), 'true');

console.log('\n== 6. pure helpers ==');
t('b64decodeStrict rejects a bad length', JSON.stringify(H.b64decodeStrict('abc')), 'null');
t('b64decodeStrict rejects invalid chars', JSON.stringify(H.b64decodeStrict('ab!d')), 'null');
t('b64decodeStrict("ZnJpZGE=") == "frida"', b2s(H.b64decodeStrict('ZnJpZGE=')), 'frida');
t('b64decodeStrict("L3Byb2Mvc2VsZi9tYXBz") == "/proc/self/maps"',
  b2s(H.b64decodeStrict('L3Byb2Mvc2VsZi9tYXBz')), '/proc/self/maps');
t('b64decodeStrict 2-layer pin', b2s(H.b64decodeStrict(b2s(H.b64decodeStrict(
    'WkRnME5UVTVNV1V3T0RZd016TmhPVEF6Tldaa05tSTJObU16WXpOa056TmhZVE16WVdZNU1EYzVOR1EyWWprNE5tVTJORGMzT1dWbFlUWmlaV00xWlE9PQ==')))),
  'd845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e');
t('printable returns null on a control byte', JSON.stringify(H.printable([0x41, 0x01])), 'null');
t('bytesToHex pads', H.bytesToHex([0, 1, 255]), '0001ff');
t('xorBytes 0x5A round-trip', b2s(H.xorBytes(H.xorBytes([1, 2, 3], 0x5a), 0x5a)), b2s([1, 2, 3]));

console.log('\n== 7. JNI signature parser (drives the Java overloads) ==');
t('()J', JSON.stringify(H.parseSigParams('()J')), '[]');
t('(Ljava/lang/String;)Ljava/lang/String;',
  JSON.stringify(H.parseSigParams('(Ljava/lang/String;)Ljava/lang/String;')), '["java/lang/String"]');
t('(Lcom/google/gson/JsonObject;Ljava/lang/String;)V',
  JSON.stringify(H.parseSigParams('(Lcom/google/gson/JsonObject;Ljava/lang/String;)V')),
  '["com/google/gson/JsonObject","java/lang/String"]');
/* parseSigParams returns RAW JNI descriptors; jtypeToJava turns them into the
   names Java.use(...).overload() wants. The pipeline is what hookJava runs. */
t('(ZLjava/lang/String;)Lretrofit2/Retrofit; -> raw descriptors',
  JSON.stringify(H.parseSigParams('(ZLjava/lang/String;)Lretrofit2/Retrofit;')),
  '["Z","java/lang/String"]');
t('  ...and through jtypeToJava -> overload names',
  JSON.stringify(H.parseSigParams('(ZLjava/lang/String;)Lretrofit2/Retrofit;').map(H.jtypeToJava)),
  '["boolean","java.lang.String"]');
t('every JNI primitive descriptor maps to a Java type',
  JSON.stringify(['Z','B','C','S','I','J','F','D'].map(H.jtypeToJava)),
  '["boolean","byte","char","short","int","long","float","double"]');
t('all 22 signatures survive parseSigParams + jtypeToJava',
  String(H.JNI_EXPECT.every(e => H.parseSigParams(e[2]).map(H.jtypeToJava).every(x => typeof x === 'string' && x.length > 0))), 'true');
t('the 3-model slot 10 signature',
  JSON.stringify(H.parseSigParams('(Lcom/google/gson/JsonObject;Lcom/nivaroid/topfollow/models/InstagramAccount;Lcom/nivaroid/topfollow/models/Order;)V')),
  '["com/google/gson/JsonObject","com/nivaroid/topfollow/models/InstagramAccount","com/nivaroid/topfollow/models/Order"]');
t('jtypeToJava maps primitives', H.jtypeToJava('int') + ',' + H.jtypeToJava('boolean'), 'int,boolean');
t('jtypeToJava maps a class', H.jtypeToJava('com/google/gson/JsonObject'), 'com.google.gson.JsonObject');
t('jtypeToJava maps an array', H.jtypeToJava('java/lang/String[]'), 'java.lang.String[]');
t('all 22 expected signatures parse without throwing',
  String(H.JNI_EXPECT.every(e => { H.parseSigParams(e[2]); return true; })), 'true');

console.log('\n== 8. KNOWN_KEYS labelling ==');
t('the literal AES key is labelled',
  H.keyLabel('30313233343536373839616263646566').indexOf('0123456789abcdef') >= 0, true);
t('the zero key is labelled', H.keyLabel('00'.repeat(16)).indexOf('all-zero') >= 0, true);
t('the AES-192 key is labelled', H.keyLabel('02df752315674526c5a695745313457544a7a654d6e4e340').indexOf('AES-192') >= 0, true);
t('the label carries the kind, not just the name',
  String(H.keyLabel('02df752315674526c5a695745313457544a7a654d6e4e340').indexOf('GCM key') >= 0), 'true');
t('a GCM nonce is labelled', H.keyLabel('58c544c151b4d9e185955991').indexOf('nonce') >= 0, true);
t('the 12-byte getter secrets are labelled',
  String(H.keyLabel('e551092bd524e1dd1e969553') !== null && H.keyLabel('3959b1d36c0c151e96686b56') !== null), 'true');
t('an unknown key is not labelled', JSON.stringify(H.keyLabel('11'.repeat(16))), 'null');
t('every KNOWN_KEYS hex is valid lowercase hex',
  String(H.KNOWN_KEYS.every(k => /^[0-9a-f]+$/.test(k.hex) && k.hex.length % 2 === 0)), 'true');

console.log('\n== 9. the 21 Base64 blobs are really in the file and really decode ==');
const blobKeys = Object.keys(H.B64_BLOBS);
t('B64_BLOBS has 21 entries', String(blobKeys.length), '21');
let blobOk = 0, blobDecodeOk = 0, layerMax = 0;
blobKeys.forEach(k => {
    const e = H.B64_BLOBS[k];
    const at = e.off;
    const inFile = img.slice(at, at + k.length).toString('latin1');
    if (inFile === k) blobOk++;
    else { fail++; console.log('  FAIL blob @0x' + at.toString(16) + '\n         file   ' + inFile.slice(0, 60) + '\n         table  ' + k.slice(0, 60)); }
    /* walk the chain with the script's own strict decoder */
    let cur = k, ok = true;
    for (let i = 0; i < e.chain.length; i++) {
        const d = H.b64decodeStrict(cur);
        if (!d) { ok = false; break; }
        const txt = b2s(d);
        if (txt !== e.chain[i]) { ok = false; break; }
        cur = txt;
    }
    if (ok && cur === e.decoded) blobDecodeOk++;
    else { fail++; console.log('  FAIL chain for @0x' + at.toString(16) + ' ended at ' + JSON.stringify(cur) + ' want ' + JSON.stringify(e.decoded)); }
    if (e.layers > layerMax) layerMax = e.layers;
});
t('every blob is byte-identical in the file at its stated offset', String(blobOk), '21');
t('every blob decodes through its whole chain to the stated plaintext', String(blobDecodeOk), '21');
t('the deepest blob is 4 layers (0x14eae -> "https://")', String(layerMax), '4');
t('the 4-layer blob decodes to "https://"', H.B64_BLOBS['V1ZWb1UwMUhUa2xVVkZwTlpWUm5PUT09'].decoded, 'https://');
t('the pin blob decodes to the cert SHA-256',
  H.B64_BLOBS[Object.keys(H.B64_BLOBS).find(k => H.B64_BLOBS[k].off === 0x15084)].decoded,
  'd845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e');
t('0x1606a decodes to "HbF0Nh5lp", NOT to the Base64 text\'s own bytes',
  H.B64_BLOBS['U0dKR01FNW9OV3h3'].decoded, 'HbF0Nh5lp');
t('the frida tokens are present',
  String(['cmUuZnJpZGEuc2VydmVy', 'Z3VtLWpzLWxvb3A=', 'bGliZnJpZGEtZ2FkZ2V0'].every(k => H.B64_BLOBS[k] !== undefined)), 'true');
t('the three endpoints are present',
  String(['https://i.instagram.com/api/v2/', 'https://www.instagram.com/',
          'https://www.instagram.com/graphql/query']
      .every(u => blobKeys.some(k => H.B64_BLOBS[k].decoded === u))), 'true');

console.log('\n== 10. libc++ std::string reader (short and long form) ==');
const mkShort = P(BASE + 0x100n);
img[0x100] = 5 * 2; Buffer.from('hello').copy(img, 0x101);
t('short-form std::string', H.readStdString(mkShort), 'hello');
const mkEmpty = P(BASE + 0x120n); img[0x120] = 0;
t('empty short-form std::string', H.readStdString(mkEmpty), '');
const mkLong = P(BASE + 0x140n);
img[0x140] = 0x31;
img.writeBigUInt64LE(0x21n, 0x140);           /* cap, odd -> long form */
img.writeBigUInt64LE(11n, 0x148);             /* size */
img.writeBigUInt64LE(BASE + 0x200n, 0x150);   /* data */
Buffer.from('hello world').copy(img, 0x200);
t('long-form std::string', H.readStdString(mkLong), 'hello world');
t('null pointer -> null', JSON.stringify(H.readStdString(P(0))), 'null');

/* Regression for the revision-6 bug: readULong() hands back a UInt64 OBJECT in
   Frida (modelled here as a BigInt), and Math.min() on one throws. Add a second
   stub whose readULong returns a valueOf()-able object, the way frida's UInt64
   does, so BOTH shapes are covered. Also pin the SSO boundary: libc++ keeps up
   to 22 bytes inline, so the 22-byte string is short-form and the 23-byte one is
   heap-allocated — and the heap one is exactly the case that used to be null. */
function UInt64Like(v) { return { valueOf: () => v, toString: () => String(v) }; }
const P64 = (n) => {
    const o = () => off(Number(n - BASE));
    return {
        isNull: () => o() === 0,
        add: (k) => P64(n + BigInt(k)),
        readU8: () => img[o()],
        readULong: () => UInt64Like(Number(img.readBigUInt64LE(o()))),
        readPointer: () => P64(img.readBigUInt64LE(o())),
        readUtf8String: (k) => img.toString('utf8', o(), o() + k),
        toString: () => '0x' + o().toString(16)
    };
};
const sso22 = 'x'.repeat(22), heap23 = 'y'.repeat(23);
const shortP = P(BASE + 0x300n);
img[0x300] = 22 * 2; Buffer.from(sso22).copy(img, 0x301);
t('22-byte string is short-form (SSO limit)', H.readStdString(shortP), sso22);
const longP = P(BASE + 0x340n);
img.writeBigUInt64LE(0x71n, 0x340);            /* cap, odd -> long form */
img.writeBigUInt64LE(23n, 0x348);              /* size */
img.writeBigUInt64LE(BASE + 0x400n, 0x350);    /* data */
Buffer.from(heap23).copy(img, 0x400);
t('23-byte string is heap-form and reads back', H.readStdString(longP), heap23);
const longObj = P64(BASE + 0x340n);
t('  ...also when readULong returns a UInt64 OBJECT, not a BigInt',
  H.readStdString(longObj), heap23);
img.writeBigUInt64LE(0n, 0x348);
t('heap-form with size 0 -> empty string', H.readStdString(longP), '');
img.writeBigUInt64LE(99999999n, 0x348);
t('implausible size is reported, not followed',
  String(H.readStdString(longP).indexOf('implausible') >= 0), 'true');

/* Regression for the other revision-6 bug: jtypeToJava() used to pass raw JNI
   descriptors through unchanged, so Java.use(...).overload('Z', ...) would throw
   and hookJava() would silently skip that native. Slots 0, 20 and 21 all have a
   'Z' in their signature. */
const PRIM_SIGS = H.JNI_EXPECT.filter(e => /[ZBCSIJFD]/.test(e[2]));
t('some JNI signatures really do contain primitive descriptors',
  String(PRIM_SIGS.length > 0), 'true');
t('none of them would produce a raw descriptor as an overload name',
  String(PRIM_SIGS.every(e => H.parseSigParams(e[2]).map(H.jtypeToJava)
        .every(x => !/^[ZBCSIJFD]$/.test(x)))), 'true');
/* parseSigParams turns '[Ljava/lang/String;' into 'java/lang/String[]' and '[B'
   into 'B[]'; jtypeToJava has to carry the dimensions over AND map the element. */
t('a String array survives parse + map',
  H.jtypeToJava(H.parseSigParams('([Ljava/lang/String;)V')[0]), 'java.lang.String[]');
t('a byte array survives parse + map',
  H.jtypeToJava(H.parseSigParams('([B)V')[0]), 'byte[]');
t('a 2-D int array survives parse + map',
  H.jtypeToJava(H.parseSigParams('([[I)V')[0]), 'int[][]');

console.log('\n== 11. the event sink writes valid JSONL ==');
H.SINK.ring.length = 0; WRITTEN.length = 0;
const wrBefore = WRITTEN.length;
H.emit('crypto', { fn: 'func#85', plaintext: 'hello', key: '0123456789abcdef' });
H.emit('aeslayer', { fn: 'func#14', keylen: 16, aes: 'AES-128', roundKeys: ['00'.repeat(16)] });
H.emit('strings', { fn: 'func#21', input: 'L3Byb2Mvc2VsZi9tYXBz', output: '/proc/self/maps', furtherBase64LayersStillEncoded: 0 });
H.noteKey('02df752315674526c5a695745313457544a7a654d6e4e340', 24, 'test');
t('three events landed in the ring', String(H.SINK.ring.length), '3');
t('sequence numbers increment',
  H.SINK.ring.map(e => e.s).join(','), [1, 2, 3].map((v, i) => H.SINK.ring[0].s + i).join(','));
t('kind is recorded', H.SINK.ring.map(e => e.k).join(','), 'crypto,aeslayer,strings');
t('payload is recorded', H.SINK.ring[0].d.fn, 'func#85');
t('every ring entry serialises to valid JSON',
  String(H.SINK.ring.every(e => { try { JSON.parse(JSON.stringify(e)); return true; } catch (x) { return false; } })), 'true');
t('the sink opened a file', String(H.SINK.fd), String(FD));
t('the sink path is the app-writable fallback or /data/local/tmp',
  String(/topfollow_capture\.jsonl$/.test(H.SINK.path || '')), 'true');
t('every emitted event was write()n synchronously',
  String(WRITTEN.length > wrBefore), 'true');
t('each written line is one valid JSON object',
  String(WRITTEN.slice(wrBefore).every(l => { try { JSON.parse(l); return true; } catch (x) { return false; } })), 'true');
t('bytesWritten tracks the writes', String(H.SINK.bytesWritten > 0), 'true');
t('noteKey labelled the AES-192 key',
  H.SINK.keys['02df752315674526c5a695745313457544a7a654d6e4e340'].label.indexOf('AES-192') >= 0, true);
t('noteKey derived the AES width',
  H.SINK.keys['02df752315674526c5a695745313457544a7a654d6e4e340'].aes, 'AES-192');
t('trunc caps long fields', String(H.trunc('x'.repeat(40000), 100).length <= 130), 'true');

console.log('\n== 12. ring-buffer-only degradation when open() fails ==');
failOpen = true;
vm.runInContext('SINK.fd = -1; SINK.tried = []; sinkInit();', sandbox);
t('sinkInit() survives a failing open()', String(H.SINK.fd), '-1');
t('and records why', String((H.SINK.tried || []).length > 0), 'true');
const ringBefore = H.SINK.ring.length;
H.emit('warn', { what: 'still captured into the ring with no file' });
t('events still land in the ring with no file',
  String(H.SINK.ring.length === ringBefore + 1), 'true');
failOpen = false;

console.log('\n== 13. rpc surface ==');
const rpc = sandbox.rpc.exports;
const RPC_EXPECT = ['cfg', 'stats', 'keys', 'endpoints', 'events', 'tail', 'find', 'crypto',
                    'jni', 'net', 'gcm', 'detect', 'secrets', 'calibrate', 'flush', 'dumpAll',
                    'clear', 'help', 'strings', 'nestedStrings', 'keyschedule', 'cbc', 'blocks',
                    'regNatives', 'onload', 'blobs', 'jniMap'];
RPC_EXPECT.forEach(nm => t('rpc.exports.' + nm + ' exists', typeof rpc[nm], 'function'));
t('stats() reports the new kinds',
  String(rpc.stats().byKind.aeslayer >= 1 && rpc.stats().byKind.strings >= 1), 'true');
t('keys() returns the labelled key', String(rpc.keys().some(k => k.aes === 'AES-192')), 'true');
t("find('func#85') hits", String(rpc.find('func#85').length >= 1), 'true');
t("events('crypto') filters", String(rpc.events('crypto').every(e => e.k === 'crypto')), 'true');
t('blobs() returns 21 entries with the stored text', String(rpc.blobs().length), '21');
t('jniMap() returns 22 rows with wrapper letters',
  String(rpc.jniMap().length === 22 && rpc.jniMap()[6].wrapper === 'q.v' && rpc.jniMap()[6].func === 'func#57'), 'true');
t('keyschedule() filters to func#14 events',
  String(rpc.keyschedule(10).every(e => e.d.fn === 'func#14')), 'true');
t('cbc() filters to func#15/#16 events', String(rpc.cbc(10).length), '0');
t('secrets() carries the pin', rpc.secrets().signaturePin,
  'd845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e');
t('dumpAll() is line-delimited JSON', String(rpc.dumpAll().split('\n').length >= 2), 'true');
t('help() mentions the read-only contract', String(rpc.help().indexOf('retval.replace') >= 0), 'true');
t('help() documents the new commands', String(rpc.help().indexOf('keyschedule(n)') >= 0), 'true');
t('clear() empties the ring',
  String((rpc.clear(), H.SINK.ring.length === 0)), 'true');

console.log('\n== 14. the offset table is consistent with the real ELF ==');
const O = H.OFF;
const inText = o => o > 0x2d2ac && o < 0x1b1bbc;
const inRodata = o => o >= 0x118b0 && o < 0x1ab5b;
const inRelro = o => o >= 0x1b6160 && o < 0x1ba5f0;
const CODE = [['ecb_enc_hex', 0x10c470], ['ecb_dec_hex', 0x110b70], ['cbc0_enc_hex', 0x038fa4],
    ['aes256_dec_hex', 0x03a838], ['rijndael_setup', 0x032158], ['xor5a_decode', 0x14193c],
    ['cbc_encrypt', 0x034424], ['cbc_decrypt', 0x035518], ['ecb_enc_block', 0x02fdcc],
    ['ecb_enc_leaf', 0x02dc00], ['ecb_dec_block', 0x030f18], ['ecb_dec_leaf', 0x02eb94],
    ['str_from_cstr', 0x035d58], ['str_empty', 0x03820c], ['b64_decode_21', 0x03712c],
    ['gcm_ctx_157', 0x131d58], ['gcm_ctx_158', 0x133970], ['gcm_core', 0x13ffb4],
    ['opaque_172', 0x13c488], ['sig_check_226', 0x159c10], ['scanner_60', 0x081c58],
    ['scanner_99', 0x115770], ['scanner_162', 0x136cb8], ['scanner_200', 0x145f88],
    ['root_169', 0x13ba30], ['timing_98', 0x114fbc], ['reader_129', 0x11deb0],
    ['reader_198', 0x143694], ['reader_213', 0x151e68], ['pinner_253', 0x172460],
    ['retrofit_254', 0x173c40], ['fixedkey_252', 0x171884], ['trap_224', 0x157628],
    ['jni_onload', 0x03e1d4], ['jni_reg1', 0x03e93c], ['jni_reg2', 0x03e988],
    ['jni_findclass', 0x03e860], ['jni_getenv', 0x03e308], ['pin_blob_245', 0x16bbdc],
    ['sha256_compress', 0x1509cc], ['sha256_pipeline', 0x148bf4], ['maps_225', 0x157f38],
    ['memcmp_75', 0x1086b8], ['sig_check_73', 0x103ad8], ['root_154', 0x12a068],
    ['getter_86', 0x10de0c], ['getter_87', 0x10df84], ['getter_159', 0x134d40],
    ['getter_160', 0x13571c], ['getter_161', 0x136134]];
CODE.forEach(([k, v]) => {
    t('OFF.' + k, '0x' + O[k].toString(16), '0x' + v.toString(16));
    t('  ...is inside .text', String(inText(O[k])), 'true');
});
[['ro_te0', 0x118b0], ['ro_te1', 0x11cb0], ['ro_te2', 0x120b0], ['ro_te3', 0x124b0],
 ['ro_sbox', 0x128b0], ['ro_td0', 0x129b0], ['ro_td1', 0x12db0], ['ro_td2', 0x131b0],
 ['ro_td3', 0x135b0], ['ro_rsbox', 0x139b0], ['ro_rcon', 0x13b10], ['ro_aes_name', 0x14b31],
 ['ro_plainkey', 0x161ca], ['ro_pinblob', 0x15084], ['ro_keyblob', 0x17428],
 ['jni_class_name', 0x14da2]].forEach(([k, v]) => {
    t('OFF.' + k, '0x' + O[k].toString(16), '0x' + v.toString(16));
    t('  ...is inside .rodata', String(inRodata(O[k])), 'true');
});
t('OFF.jni_table_va', '0x' + O.jni_table_va.toString(16), '0x1b6198');
t('  ...is inside .data.rel.ro', String(inRelro(O.jni_table_va)), 'true');
t('OFF.jni_entries', String(O.jni_entries), '22');
t('the whole AES table block fits in .rodata',
  String(inRodata(0x118b0) && inRodata(0x13c10 - 1)), 'true');
t('func#224\'s trap instruction is really at 0x1576ac',
  img.readUInt32LE(0x1576ac).toString(16), '14000000');      /* b . */
t('func#224\'s entry is a real prologue (sub sp, sp, #0xb0)',
  img.readUInt32LE(0x157628).toString(16), 'd102c3ff');
t('the capture script never hooks func#224 by default', String(H.CFG.hookTrapFunc224), 'false');
t('func#172 is present in OFF but renamed away from "GF core"',
  String(O.opaque_172 === 0x13c488 && O.gcm_gf === undefined), 'true');
t('func#172\'s two GOT loads resolve into .bss, not .rodata',
  String(inRodata(0x1c28a0) === false && inRodata(0x1c2d2c) === false), 'true');

console.log('\n== 15. bypass mode (off by default, and it has to actually work when on) ==');
/* The whole point of the marked regions: a read-only capture on a defended
   device gets you nothing, because the repacked APK fails func#226/#73's
   SHA-256(signer cert) pin and func#99/#162/#200/#225/#60/#169 see Frida, the
   maps lines and root. So the bypass has to be real — but it must stay OFF
   unless asked for, and it must never touch a cipher. */

t('BYPASS_ON() is false in the loaded script', JSON.stringify(H.BYPASS_ON()), 'false');

/* --- the stub set: exactly the seven leaves whose polarity was measured --- */
const FORCED = Object.keys(H.BYPASS.forceReturn).map(Number).sort((a, b) => a - b);
t('seven detection leaves are stubbed in bypass mode', String(FORCED.length), '7');
t('  func#60  Xposed/Riru/Substrate scanner',
  String(FORCED.indexOf(0x081c58) >= 0), 'true');
t('  func#99  anti-Frida (XOR-0x37 tokens)',
  String(FORCED.indexOf(0x115770) >= 0), 'true');
t('  func#162 anti-Frida (Base64 tokens)',
  String(FORCED.indexOf(0x136cb8) >= 0), 'true');
t('  func#200 anti-hook maps scan',
  String(FORCED.indexOf(0x145f88) >= 0), 'true');
t('  func#225 maps integrity',
  String(FORCED.indexOf(0x157f38) >= 0), 'true');
t('  func#169 root check (access() x9)',
  String(FORCED.indexOf(0x13ba30) >= 0), 'true');
t('  func#154 root-check parent',
  String(FORCED.indexOf(0x12a068) >= 0), 'true');
t('all seven force 0, i.e. "nothing found"',
  String(FORCED.every(k => H.BYPASS.forceReturn[k] === 0)), 'true');
t('all seven offsets are real entries in OFF',
  String(FORCED.every(k => Object.keys(H.OFF).some(n => H.OFF[n] === k))), 'true');

/* --- and the three that must NOT be stubbed --- */
t('func#224 is NOT stubbed (reachable `b .` trap @0x1576ac)',
  String(FORCED.indexOf(0x157628) < 0), 'true');
t('func#98 clock() is NOT stubbed (polarity never proven)',
  String(FORCED.indexOf(0x114fbc) < 0), 'true');
t('func#226 / func#73 are NOT stubbed — the pin is beaten on the Java side',
  String(FORCED.indexOf(0x159c10) < 0 && FORCED.indexOf(0x103ad8) < 0), 'true');

/* --- no cipher is ever replaced, in any mode --- */
const CIPHERS = [H.OFF.ecb_enc_hex, H.OFF.ecb_dec_hex, H.OFF.cbc0_enc_hex,
                 H.OFF.aes256_dec_hex, H.OFF.rijndael_setup, H.OFF.xor5a_decode,
                 H.OFF.cbc_encrypt, H.OFF.cbc_decrypt, H.OFF.ecb_enc_block,
                 H.OFF.ecb_dec_block, H.OFF.ecb_enc_leaf, H.OFF.ecb_dec_leaf,
                 H.OFF.gcm_core, H.OFF.gcm_ctx_157, H.OFF.gcm_ctx_158,
                 H.OFF.str_from_cstr, H.OFF.b64_decode_21, H.OFF.str_empty];
t('not one cipher, AES-layer or string-layer function is in the stub set',
  String(CIPHERS.every(c => FORCED.indexOf(c) < 0)), 'true');
t('the stub set and the cipher set are disjoint',
  String(FORCED.filter(f => CIPHERS.indexOf(f) >= 0).length), '0');

/* --- maps filtering: length-preserving, and it must not shred a clean file --- */
const MAPS_OFF = 0x1000;
const clean = [
  '7a1c000000-7a1c021000 r--p 00000000 fd:00 1234  /system/lib64/libc.so',
  '7a1c021000-7a1c0b8000 r-xp 00021000 fd:00 1234  /system/lib64/libc.so',
  '7a1d000000-7a1d001000 rw-p 00000000 00:00 0     [anon:libc_malloc]',
  '7ffcc00000-7ffcc21000 r--p 00000000 00:00 0     [vdso]'
].join('\n') + '\n';
const dirty = [
  '7a1c000000-7a1c021000 r--p 00000000 fd:00 1234  /system/lib64/libc.so',
  '7a2b000000-7a2b038000 r-xp 00000000 00:00 0     /data/local/tmp/re.frida.server/frida-agent-64.so',
  '7a2c000000-7a2c004000 rwxp 00000000 00:00 0     [anon:gum-js-loop]',
  '7a2d000000-7a2d011000 r--p 00000000 fd:00 999   /apex/com.android.runtime/lib64/bionic/libc.so (deleted)',
  '7a1d000000-7a1d001000 rw-p 00000000 00:00 0     [anon:libc_malloc]'
].join('\n') + '\n';

Buffer.from(clean).copy(img, MAPS_OFF);
const pClean = P(BASE + BigInt(MAPS_OFF));
t('a clean maps file is left completely alone',
  String(H.filterMapsBuffer(pClean, Buffer.byteLength(clean))), '0');
t('  ...and the bytes are untouched',
  img.toString('utf8', MAPS_OFF, MAPS_OFF + Buffer.byteLength(clean)), clean);

Buffer.from(dirty).copy(img, MAPS_OFF);
const nDirty = Buffer.byteLength(dirty);
const changed = H.filterMapsBuffer(P(BASE + BigInt(MAPS_OFF)), nDirty);
const after = img.toString('utf8', MAPS_OFF, MAPS_OFF + nDirty);
t('three suspicious lines were rewritten', String(changed), '3');
t('the rewrite is LENGTH-PRESERVING (the scanner counts bytes)',
  String(after.length), String(nDirty));
t('no frida token survives', String(/frida|gum-js-loop/i.test(after)), 'false');
t('no rwxp survives', String(after.indexOf('rwxp') >= 0), 'false');
t('no "(deleted)" survives', String(after.indexOf('(deleted)') >= 0), 'false');
t('the clean lines are byte-identical afterwards',
  String(after.indexOf('/system/lib64/libc.so') >= 0 &&
         after.indexOf('[anon:libc_malloc]') >= 0), 'true');
t('the replacement still looks like a maps line',
  String(/^7f000000-7f001000 r--p 00000000 00:00 0/m.test(after)), 'true');
t('line count is unchanged',
  String(after.split('\n').length), String(dirty.split('\n').length));
t('mapsLineIsSuspicious catches every token the library actually searches for',
  String(['frida', 're.frida.server', 'gum-js-loop', 'libfrida-gadget', 'rwxp',
          '(deleted)', 'riru', 'ygsik', 'xposed', 'lsposed', 'edxposed',
          'substrate', 'libcso_substrate', 'libbridge.so', 'zygisk', 'magisk']
      .every(tok => H.mapsLineIsSuspicious('7a0-7b0 r-xp 0 00:00 0  ' + tok))), 'true');

/* --- every decoded Base64 detection token is covered by MAPS_NOISE --- */
const DETECTION_TOKENS = ['frida', 're.frida.server', 'gum-js-loop', 'libfrida-gadget',
                          '/proc/self/maps', 'libbridge.so', 'riru', 'libcso_substrate',
                          'substrate', 'edxposed', 'lsposed', 'xposed', 'ygsik', 'rwxp',
                          'libart.so (deleted)', 'libc.so (deleted)'];
const noise = H.MAPS_NOISE.map(x => x.toLowerCase());
t('MAPS_NOISE covers every token decoded out of .rodata in §11.13(e)',
  String(DETECTION_TOKENS.filter(tok =>
      !noise.some(n => tok.toLowerCase().indexOf(n) >= 0 || n.indexOf(tok.toLowerCase()) >= 0)
  ).join(',') || 'none-missing'), 'none-missing');

/* --- su paths --- */
['/system/bin/su', '/system/xbin/su', '/sbin/su', '/su/bin/su', '/data/local/su',
 '/data/local/bin/su', '/data/local/xbin/su', '/system/app/Superuser.apk',
 '/system/bin/.ext/.su'].forEach(sp => {
    t('func#169 path ' + sp + ' is recognised', String(H.isSuPath(sp)), 'true');
});
t('a normal path is not mistaken for su', String(H.isSuPath('/system/lib64/libc.so')), 'false');
t('null is handled', String(H.isSuPath(null)), 'false');

/* --- the signature forgery: the cert it hands back is THE pinned one --- */
const certB64 = H.ORIGINAL_SIGNER_CERT_B64.replace(/\s+/g, '');
const certDer = Buffer.from(certB64, 'base64');
t('the forged certificate is 864 bytes of DER', String(certDer.length), '864');
t('SHA-256(that DER) == the pin blob @0x15084',
  crypto.createHash('sha256').update(certDer).digest('hex'), H.SIGNATURE_PIN_SHA256);
t('the pin blob in .rodata decodes to exactly that hash',
  H.B64_BLOBS[Object.keys(H.B64_BLOBS).find(k => H.B64_BLOBS[k].off === 0x15084)].decoded,
  H.SIGNATURE_PIN_SHA256);
t('so a repacked APK can pass func#226/#73 with NO native patch at all',
  String(certDer.length === 864 &&
         crypto.createHash('sha256').update(certDer).digest('hex') === H.SIGNATURE_PIN_SHA256), 'true');

/* --- bypassReplace really replaces, and only what it is given --- */
replaced.length = 0;
const r1 = vm.runInContext('bypassReplace("test detector", 0x145f88, 0)', sandbox);
t('bypassReplace returns true', JSON.stringify(r1), 'true');
t('bypassReplace called Interceptor.replace exactly once', String(replaced.length), '1');
t('  ...on the right address',
  replaced[0], '0x' + (Number(BASE) + 0x145f88).toString(16));
t('it emitted a bypass event, so the JSONL records that the app was lied to',
  String(H.SINK.ring.some(e => e.k === 'bypass')), 'true');

/* --- in the DEFAULT configuration hookDetection replaces NOTHING --- */
replaced.length = 0; attached.length = 0;
vm.runInContext('hookDetection()', sandbox);
t('hookDetection with the shipped defaults replaces nothing', String(replaced.length), '0');
t('  ...and attaches to every watcher instead', String(attached.length >= 17), 'true');
t('  ...and func#224 is not among them',
  String(attached.indexOf('0x' + (Number(BASE) + 0x157628).toString(16)) < 0), 'true');

/* --- and with bypass on, it stubs exactly the seven --- */
replaced.length = 0; attached.length = 0;
vm.runInContext('CFG.bypass.enabled = true; hookDetection(); CFG.bypass.enabled = false;', sandbox);
const stubbedAddrs = replaced.map(x => Number(x) - Number(BASE));
t('with bypass on, hookDetection replaces exactly seven leaves', String(replaced.length), '7');
t('  and they are exactly the measured forceReturn set',
  stubbedAddrs.slice().sort((a, b) => a - b).map(x => '0x' + x.toString(16)).join(','),
  FORCED.map(x => '0x' + x.toString(16)).join(','));
t('  func#226 is still watched, not replaced (the Java side handles it)',
  String(stubbedAddrs.indexOf(0x159c10) < 0), 'true');
t('  and the remaining watchers are still attached', String(attached.length >= 10), 'true');

/* --- the CFG plumbing a runner actually uses --- */
t('TF_CONFIG (what run_frida.py injects) reaches CFG.bypass.enabled',
  JSON.stringify(vm.runInContext(`(function () {
      const c = Object.assign({}, DEFAULT_CFG, { bypass: Object.assign({}, DEFAULT_CFG.bypass, { enabled: true }) });
      return c.bypass.enabled;
  })()`, sandbox)), 'true');
t('the script honours TF_CONFIG as well as TF_CAPTURE_CFG',
  String(SRC.indexOf('globalThis.TF_CONFIG') >= 0), 'true');


console.log('\n== 16. Java hook self-recursion (the bug class that kills the net + signature capture) ==');
/* Three separate Frida gotchas, all of which silently destroy the capture:

   (a) `Foo.bar.implementation = impl;` then, INSIDE impl, restoring with
       `Foo.bar.implementation = Foo.bar`. A method wrapper's `.implementation`
       GETTER returns the JS function currently installed, so from inside the
       hook the wrapper IS the hook, and assigning it back re-hooks the hook.
       The first call works; the second recurses. Restore with `null`.

   (b) `this.bar()` inside bar's own implementation. This one Frida DOES guard:
       frida-java-bridge keeps a per-replacement Set of thread ids (pendingCalls)
       and routes a call made from inside the replacement straight to the
       original with STRATEGY_DIRECT. So it works — but it dispatches through
       overload resolution, which is the documented IncompatibleClassChangeError
       gotcha. The capture script therefore uses captured wrappers instead.

   (c) Hooking a STATIC factory (MessageDigest.getInstance, Base64.decode) and
       then calling `Class.method(...)`: that always re-dispatches, guard or no
       guard, because it is a fresh call from the same thread only while the
       hook is installed — hence the drop-hook / call / restore-null idiom. */

/* ---- (a) static: nothing restores a wrapper to itself ---- */
const RESTORE = /(\w+)\.implementation\s*=\s*(\w+)\s*;/g;
const badRestore = [];
let rm;
while ((rm = RESTORE.exec(SRC)) !== null) if (rm[1] === rm[2]) badRestore.push(rm[0]);
t('no "impl.implementation = impl" anywhere (that re-hooks the hook)',
  JSON.stringify(badRestore), '[]');
t('the three drop-call-restore sites all restore null',
  String((SRC.match(/\.implementation = null;/g) || []).length), '6');

/* ---- (b) static: the three receiver-sensitive hooks use captured wrappers ---- */
const SRC_CODE = SRC
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:'"\\])\/\/[^\n]*/g, '$1 ');
[['chProceed', 'okhttp3 RealInterceptorChain.proceed', 'chProceed.apply(this, [req])'],
 ['sigToByteArray', 'android.content.pm.Signature.toByteArray', 'sigToByteArray.call(this)'],
 ['sigHashCode', 'android.content.pm.Signature.hashCode', 'sigHashCode.call(this)']
].forEach(spec => {
    const [w, what, call] = spec;
    const decl = SRC_CODE.indexOf('const ' + w + ' =');
    const inst = SRC_CODE.indexOf(w + '.implementation = function');
    t(what + ': wrapper captured BEFORE the hook is installed',
      String(decl > 0 && inst > decl), 'true');
    t(what + ': the hook calls through that wrapper', String(SRC_CODE.indexOf(call) > 0), 'true');
});
t('no bare this.proceed() / this.toByteArray() / this.hashCode() left in the code',
  String(!/\bthis\.(proceed|toByteArray|hashCode)\s*\(/.test(SRC_CODE)), 'true');
t('the only this.X() calls left are on methods nothing hooks',
  JSON.stringify(Array.from(new Set(
      Array.from(SRC_CODE.matchAll(/\bthis\.([A-Za-z_$][\w$]*)\s*\(/g)).map(m => m[1])
  )).sort()), '["command","getAlgorithm","update"]');
t('  ...update being the drop-hook/restore-null case, and getAlgorithm/command unhooked',
  String(SRC_CODE.indexOf('mdUpdate.implementation = null') <
         SRC_CODE.indexOf('try { r = this.update(b); }')), 'true');

/* ---- dynamic: a mock Java that behaves like frida-java-bridge ---- */
function makeJavaMock() {
    const classes = {};
    const hookLog = [];          /* 'Class.method' for every hook installed    */
    const realHits = [];         /* 'Class.method' for every ORIGINAL reached  */
    function mkClass(fqcn, methods) {
        const C = {};
        (methods || []).forEach(mname => {
            const real = function () {
                realHits.push(fqcn + '.' + mname);
                /* Return something the hooks can actually consume. The capture
                   script calls .toString() (via j()), .length and
                   new Uint8Array(...) on results, and a bare {} fails all
                   three — which would look exactly like a recursion bug and
                   is not one. Modelled per method shape: */
                if (mname === 'toByteArray') return new Uint8Array([1, 2, 3, 4]);
                if (mname === 'getAlgorithm') return 'SHA-256';
                if (mname === 'command') return ['sh', '-c', 'id'];
                if (mname === 'update' || mname === 'init') return this;
                if (mname === 'digest' || mname === 'doFinal') return new Uint8Array(32);
                if (mname === 'getInstance') return {};
                return { __real: fqcn + '.' + mname,
                         toString: () => fqcn + '.' + mname + '()',
                         args: Array.prototype.slice.call(arguments) };
            };
            let impl = null;
            const pendingCalls = new Set();     /* frida-java-bridge recursion guard */
            const TID = 4242;
            const wrapper = function () {
                if (impl && !pendingCalls.has(TID)) {
                    pendingCalls.add(TID);
                    try { return impl.apply(this, arguments); }
                    finally { pendingCalls.delete(TID); }
                }
                return real.apply(this, arguments);      /* STRATEGY_DIRECT */
            };
            Object.defineProperty(wrapper, 'implementation', {
                /* Frida's getter returns the installed JS function, which is
                   exactly why `impl.implementation = impl` is a bug. */
                get: () => impl,
                set: fn => { if (typeof fn === 'function') { impl = fn; hookLog.push(fqcn + '.' + mname); } else { impl = null; } }
            });
            wrapper.overloads = [wrapper];
            wrapper.overload = () => wrapper;
            C[mname] = wrapper;
        });
        C.class = { getDeclaredMethods: () => [] };
        classes[fqcn] = C;
        return C;
    }
    return {
        available: true, perform: fn => fn(), performNow: fn => fn(),
        use: fqcn => classes[fqcn] || mkClass(fqcn, []),
        array: (ty, arr) => arr, choose: () => {}, enumerateLoadedClassesSync: () => [],
        vm: null, registerClass: () => ({}), scheduleOnMainThread: fn => fn(),
        _mk: mkClass, _hookLog: hookLog, _realHits: realHits
    };
}

const javaMock = makeJavaMock();
javaMock._mk('okhttp3.internal.http.RealInterceptorChain', ['proceed']);
javaMock._mk('okhttp3.Request', ['url', 'method', 'headers', 'body']);
javaMock._mk('okhttp3.Response', ['code', 'body', 'headers', 'request', 'message', 'isSuccessful']);
javaMock._mk('android.content.pm.Signature', ['toByteArray', 'hashCode']);
javaMock._mk('android.content.pm.PackageInfo', []);
javaMock._mk('android.app.ApplicationPackageManager', ['getPackageInfo', 'getPackageInfoAsUser']);
javaMock._mk('android.content.pm.PackageManager', ['getPackageInfo']);
javaMock._mk('java.security.MessageDigest', ['getInstance', 'digest', 'update', 'getAlgorithm']);
javaMock._mk('javax.crypto.Cipher', ['getInstance', 'doFinal', 'init', 'getAlgorithm']);
javaMock._mk('android.util.Base64', ['decode', 'encodeToString']);
javaMock._mk('java.lang.Runtime', ['loadLibrary0', 'exec']);
javaMock._mk('java.lang.ProcessBuilder', ['start', 'command']);

const sb2 = Object.assign({}, sandbox);
sb2.Java = javaMock;
sb2.TOPFOLLOW_CAPTURE_NO_AUTOBOOT = true;
vm.createContext(sb2);
let threw = null;
try {
    vm.runInContext(SRC, sb2, { filename: 'topfollow_capture.js (java-mock run)' });
    vm.runInContext('hookJava()', sb2);
} catch (e) { threw = e; }
t('the script loads AND hookJava() installs against the mock without throwing',
  threw === null ? 'null' : String(threw && threw.message), 'null');
t('hookJava() installed a real set of hooks', String(javaMock._hookLog.length >= 8), 'true');
t('  including okhttp3 RealInterceptorChain.proceed (the request/response capture)',
  String(javaMock._hookLog.indexOf('okhttp3.internal.http.RealInterceptorChain.proceed') >= 0), 'true');
t('  including Signature.toByteArray (the signature-pin capture)',
  String(javaMock._hookLog.indexOf('android.content.pm.Signature.toByteArray') >= 0), 'true');
t('  including MessageDigest.getInstance and digest',
  String(javaMock._hookLog.indexOf('java.security.MessageDigest.getInstance') >= 0 &&
         javaMock._hookLog.indexOf('java.security.MessageDigest.digest') >= 0), 'true');

/* Now call EVERY hooked method, twice each. Under (a) the second call would
   recurse; under (b)/(c) with a bare this.X() the guard saves it but the
   wrapper route is what the script actually uses. Either way: no throw, and
   the real method must be reached. */
const byClass = {};
javaMock._hookLog.forEach(fq => {
    const i = fq.lastIndexOf('.');
    (byClass[fq.slice(0, i)] = byClass[fq.slice(0, i)] || []).push(fq.slice(i + 1));
});
let recursed = [], missed = [];
Object.keys(byClass).forEach(fqcn => {
    const C = javaMock.use(fqcn);
    byClass[fqcn].forEach(mname => {
        const w = C[mname];
        if (!w) { missed.push(fqcn + '.' + mname); return; }
        /* the receiver has to look like the real object: ProcessBuilder.start's
           hook calls this.command(), and on a device `this` IS the
           ProcessBuilder. Handing it {} would be a mock artefact, not a bug. */
        const self = Object.assign({}, C);
        javaMock._realHits.length = 0;
        for (let round = 0; round < 2; round++) {
            try { w.call(self, new Uint8Array(8), 0); }
            catch (e) { recursed.push(fqcn + '.' + mname + ' -> ' + e.constructor.name + ': ' + e.message); break; }
        }
        if (javaMock._realHits.indexOf(fqcn + '.' + mname) < 0) missed.push(fqcn + '.' + mname);
    });
});
t('no hooked method overflows the stack when called twice',
  JSON.stringify(recursed), '[]');
t('every hooked method still reaches the ORIGINAL implementation',
  JSON.stringify(missed), '[]');
t('RealInterceptorChain.proceed specifically survives repeated calls',
  (function () {
      const w = javaMock.use('okhttp3.internal.http.RealInterceptorChain').proceed;
      javaMock._realHits.length = 0;
      for (let i = 0; i < 10; i++) { try { w.call({}); } catch (e) { return 'threw ' + e.constructor.name; } }
      return String(javaMock._realHits.filter(x => x.indexOf('proceed') >= 0).length);
  })(), '10');
t('Signature.toByteArray specifically survives repeated calls',
  (function () {
      const w = javaMock.use('android.content.pm.Signature').toByteArray;
      javaMock._realHits.length = 0;
      for (let i = 0; i < 10; i++) { try { w.call({}); } catch (e) { return 'threw ' + e.constructor.name; } }
      return String(javaMock._realHits.filter(x => x.indexOf('toByteArray') >= 0).length);
  })(), '10');

console.log('\n=====================================');
console.log('  PASS ' + pass + '   FAIL ' + fail);
console.log('=====================================');
process.exit(fail ? 1 : 0);
