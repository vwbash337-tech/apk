/*
 * topfollow_agent.js  —  Frida instrumentation for libtopfollow.so
 * =====================================================================
 * Target : com.nivaroid.topfollow  v8.4.5 (845)
 * Library: lib/arm64-v8a/libtopfollow.so   1,805,400 bytes
 *          SONAME "libtopfollow.so", single export JNI_OnLoad @ 0x3e1d4
 * Source : REPORT_libtopfollow_so.md  (revision 2 — every cipher claim below
 *          was proven by executing the real code under Unicorn, see §11)
 *
 * Runs on a NON-ROOTED phone via Frida **Gadget** embedded in a repackaged
 * APK (see ../README_frida_gadget.md). Also works with frida-server if you
 * ever get root.
 *
 * ---------------------------------------------------------------------
 * WHY THIS SCRIPT DOES NOT NEED TO "CRACK" ANYTHING
 * ---------------------------------------------------------------------
 * The library's own crypto is the leak:
 *
 *   func#85 @ 0x10c470  AES-ECB + PKCS#7 -> lowercase hex   (27/27 KAT exact)
 *   func#94 @ 0x110b70  exact inverse of func#85
 *   func#30 @ 0x38fa4   AES-128-CBC with key = 16x00 AND iv = 16x00
 *                       -> key argument is IGNORED. 7 of 22 JNI natives use it
 *   func#193 @ 0x14193c XOR-0x5A string decoder (every hardcoded secret)
 *   func#14  @ 0x32158  LibTomCrypt rijndael_setup -> the real key, verbatim
 *
 * So we just sit on those five functions and read the arguments. No key
 * recovery, no cryptanalysis, no patching of the cipher.
 *
 * ---------------------------------------------------------------------
 * HARD RULE (read before editing)
 * ---------------------------------------------------------------------
 * This binary contains 712 `b .` infinite-loop instructions, 148 of them
 * REACHABLE. They are the else-arm of opaque predicates: if a hook perturbs
 * a register the predicate reads, control flow lands on `b .` and the thread
 * hangs forever — silently, with no crash. Therefore:
 *
 *   1. NEVER patch instructions inside a flattened function body.
 *   2. NEVER use Interceptor.replace() on the cipher functions.
 *   3. Only Interceptor.attach() at the function ENTRY, and only READ
 *      registers in onEnter. Reading is safe; writing is not.
 *   4. For detection functions we do use replace() — but only on the small
 *      leaf helpers, and only in `bypass` mode. recon mode never writes.
 *
 * ---------------------------------------------------------------------
 * USAGE
 * ---------------------------------------------------------------------
 *   frida -U -n Gadget -l topfollow_agent.js          # gadget, default config
 *   frida -U -f com.nivaroid.topfollow -l ...         # rooted / frida-server
 *
 *   python3 run_frida.py --mode crypto                # via the runner
 *   python3 run_frida.py --mode recon                 # log-only, zero writes
 *   python3 run_frida.py --mode bypass                # + detection defeat
 *
 * In-session console (rpc.exports):
 *   rpc.exports.secrets()      every XOR-0x5A string decoded at runtime
 *   rpc.exports.keys()         every AES key seen by rijndael_setup
 *   rpc.exports.crypto()       every encrypt/decrypt with plaintext + key
 *   rpc.exports.jni()          every JNI native call with its Java args
 *   rpc.exports.decrypt(hex)   offline decrypt of a func#30 ciphertext
 *   rpc.exports.selftest()     re-verify the offsets against known answers
 */

'use strict';

/* ===================================================================== *
 * 0. CONFIGURATION
 * ===================================================================== */

const CFG = (typeof globalThis.TF_CONFIG === 'object' && globalThis.TF_CONFIG) || {};

const CONFIG = {
    mode:          CFG.mode          || 'crypto',   // 'recon' | 'crypto' | 'bypass' | 'all'
    hookJava:      CFG.hookJava      !== false,
    hookDetection: CFG.hookDetection !== false,
    sslUnpin:      CFG.sslUnpin      !== false,
    /* Hand the ORIGINAL signer certificate back to PackageManager so that
       func#226 / func#73 compute the pinned SHA-256 even though we re-signed
       the APK with a clone key. Only matters for a repackaged (Gadget) build. */
    spoofSignature: CFG.spoofSignature !== false,
    filterMaps:    CFG.filterMaps    !== false,
    selfCalibrate: CFG.selfCalibrate !== false,
    selfTest:      CFG.selfTest      !== false,
    maxDump:       CFG.maxDump       || 4096,
    quiet:         CFG.quiet         || false,
    /* ---- detection stubbing (OFF by default — read this before enabling) ----
     * stubDetection=false (the default) means every detection function is only
     * WATCHED: entry-only Interceptor.attach, natural return value logged. We
     * have NOT proven the polarity of any of them, so forcing a return value is
     * a guess — and a wrong guess makes the app think it IS being analysed.
     * The reliable layer is the read-only filtering (filterMaps + strstr
     * suppression + access()/stat() ENOENT), which never writes to the library.
     *
     * Set stubDetection=true (mode 'bypass'/'all') to Interceptor.replace the
     * small leaf detectors with a stub returning forceReturn[off]. Replacing at
     * the ENTRY is the only safe way to touch these: the stub means the
     * flattened body — and every opaque predicate and `b .` trap in it — never
     * executes. func#224 is listed but commented out on purpose: its body holds
     * a reachable `b .` trap @0x1576ac and the app apparently never reaches it,
     * so leave it alone and just watch. */
    stubDetection: CFG.stubDetection === true,
    forceReturn: Object.assign({
        0x145f88: 0,     // func#200 anti-hook /proc/self/maps strstr scan
        0x115770: 0,     // func#99  anti-Frida (XOR-0x37 token blob)
        0x136cb8: 0,     // func#162 anti-Frida second path (base64 tokens)
        0x157f38: 0,     // func#225 maps integrity (rwxp / "(deleted)")
        0x13ba30: 0      // func#169 root check (access() on 9 su paths)
        // 0x157628: 0,  // func#224 — reachable `b .` trap @0x1576ac; watch only
        // 0x114fbc: 0,  // func#98  clock() timing — polarity unknown; watch only
        // 0x159c10: 0   // func#226 cert pin + APK signature check — see sslUnpin
    }, CFG.forceReturn || {})
};

/* ---- offsets, straight out of the report ---------------------------- *
 * The RX LOAD segment has v_addr == 0 and p_offset == 0, so every number *
 * below is simultaneously a file offset and a virtual address. Frida's   *
 * module.base + offset is therefore correct with no adjustment.         */

const OFF = {
    /* --- crypto: PROVEN (§11.2, §11.3) --- */
    aes_ecb_encrypt_hex : 0x10c470,   // func#85   (pt,key) -> sret hex, x8
    aes_ecb_decrypt_hex : 0x110b70,   // func#94   exact inverse of #85
    aes_cbc_zerokey_hex : 0x038fa4,   // func#30   key arg IGNORED, key=iv=0
    aes256_ecb_dechex   : 0x03a838,   // func#36   AES-256-ECB dec + PKCS#7 unpad; arg1 ignored;
                                      //           key buffer = a slice of its OWN stack frame
                                      //           (rev 4, report §11.11a) -> key is not a constant
    rijndael_setup      : 0x032158,   // func#14   x0=skey x1=userkey x3=keylen
    xor5a_decode        : 0x14193c,   // func#193  x0=src x1=len x8=dst(sret)
    ctx_build_enc       : 0x131d58,   // func#157  installs key@0x17428 nonce@0x17448
    ctx_build_dec       : 0x133970,   // func#158  installs nonce@0x17458
    key_getter_86       : 0x10de0c,   // -> "5VEJK9Uk4d0elpVT"  (arg-ignored)
    key_getter_87       : 0x10df84,   // func#55's key provider (needs JNIEnv)
    key_getter_159      : 0x134d40,   // -> "OVmx02wMFR6WaGtW"
    key_getter_160      : 0x13571c,   // -> "V0V4V2pOa1ptZGsl"
    key_getter_161      : 0x136134,   // -> "xV2xKTlZsBUVk1He"
    jni_onload          : 0x03e1d4,

    /* --- detection --- */
    anti_hook_maps      : 0x145f88,   // func#200
    anti_frida          : 0x115770,   // func#99
    anti_frida_b64      : 0x136cb8,   // func#162
    maps_integrity      : 0x157f38,   // func#225
    root_check          : 0x13ba30,   // func#169
    timing_check        : 0x114fbc,   // func#98
    cert_pin_sigcheck   : 0x159c10,   // func#226 (calls func#99 right before pinning)
    trap_func           : 0x157628,   // func#224 (reachable `b .` @0x1576ac)
    okhttp_pinner_a     : 0x172460,   // func#253
    okhttp_pinner_b     : 0x173c40,   // func#254
    fixedkey_caller     : 0x171884,   // func#252 (sole caller of func#36, <- JNI slot 15 q.k)

    /* --- the proc-maps READERS (rev 4).
       libtopfollow.so imports NO fopen, NO fgets, NO strstr, NO stat and NO lstat.
       Its 88 imported symbols include __open_2 (x8), __read_chk (x6), read (x3) and
       close (x6), and exactly three functions use them: #129, #198 and #213.  Every
       maps scan in the library therefore goes
           scanner -> reader helper -> __open_2 + __read_chk/read + close
       and the token search afterwards is done INLINE (memcmp / memchr), not via strstr.
       Hooking fgets or strstr cannot intercept any of it - filter the read() buffer
       instead, length-preserving, so no byte count has to be adjusted.        */
    maps_reader_129     : 0x11deb0,   // func#129  <- func#99, func#225
    maps_reader_198     : 0x143694,   // func#198  <- func#162, func#200
    maps_reader_213     : 0x151e68,   // func#213  <- func#60 (the 179 KB scanner)
    maps_reader_129_sz  : 4900,
    maps_reader_198_sz  : 5872,
    maps_reader_213_sz  : 6080,
    big_scanner_60      : 0x081c58,   // func#60: riru, substrate, xposed, lsposed,
                                      // edxposed, libbridge.so, ygsik, proc-self-maps

    /* --- .rodata: hardcoded secrets (XOR-0x5A then Base64) --- */
    rodata_key192_ct    : 0x17428,    // 32 B -> "At91IxVnRSbFppV0UxNFdUSnplTW5ONA" -> 24 B
    rodata_nonce1_ct    : 0x17448,    // 16 B -> "WMVEwVG02eGFlVmR"                  -> 12 B
    rodata_nonce2_ct    : 0x17458,    // 16 B -> "M0VEwVGt0aVJuQjF"                  -> 12 B
    rodata_pin_b64x2    : 0x15084,    // PLAINTEXT double-Base64 (no XOR layer) -> sha256 hex
                                      // of this APK's own signer-certificate DER (rev 3)
    rodata_plain_key    : 0x161ca,    // literal "0123456789abcdef"
    rodata_sbox         : 0x128b0,    // FIPS-197 S-box (verified byte-exact)
    rodata_rcon         : 0x13b10,    // LibTomCrypt extended Rcon (256 entries)

    /* --- ELF: the RegisterNatives table, for self-calibration --- */
    data_rel_ro_va      : 0x1b6160,
    jni_table_first_slot: 0x1b6198,   // entry #0 of 22, stride 0x18
    jni_table_entries   : 22
};

/* ---- the 22 JNI natives, as recovered from .data.rel.ro ------------- *
 * Verified at runtime by the self-calibrator (§4).                      */
const JNI_EXPECT = [
    ['x0011a4c2', '()J',                                                                 0x3eab4],
    ['x0014e2e9', '()Ljava/lang/String;',                                                0x3f034],
    ['x0016d3b9', '()Ljava/lang/String;',                                                0x3f3c8],
    ['x0012d3e0', '(Ljava/lang/String;)Ljava/lang/String;',                              0x3f688],  // -> #85 enc, key #86
    ['x0011e28b', '(Ljava/lang/String;)Ljava/lang/String;',                              0x4110c],  // -> #94 dec, key #87
    ['x00120b1e', '(Lcom/google/gson/JsonObject;Ljava/lang/String;)V',                   0x435b8],  // -> #30
    ['x0012e5a1', '(Lcom/google/gson/JsonObject;)V',                                     0x4f078],  // 160 KB request builder
    ['x00135e2a', '(Lcom/google/gson/JsonObject;Lcom/nivaroid/topfollow/models/InstagramAccount;Ljava/lang/String;)V', 0x76508],
    ['x00105e9b', '(Ljava/lang/String;)Ljava/lang/String;',                              0x7f82c],  // -> #30
    ['x0015b1e9', '(Lcom/google/gson/JsonObject;Ljava/lang/String;Ljava/lang/String;)V',  0x81c58],  // -> #85/#30
    ['x0015a3b7', '(Lcom/google/gson/JsonObject;Lcom/nivaroid/topfollow/models/InstagramAccount;Lcom/nivaroid/topfollow/models/Order;)V', 0xadacc],
    ['x0017b62c', '(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;', 0xbf7fc], // -> #85
    ['x0011f42b', '()Ljava/lang/String;',                                                0xc67a4],  // -> #30
    ['x0012f5b7', '()Ljava/lang/String;',                                                0xcbeac],  // -> #157
    ['x0014b4f3', '(Ljava/lang/String;)Ljava/lang/String;',                              0xd46a8],  // -> #85
    ['x0011f1a2', '(Lcom/nivaroid/topfollow/models/Order;)Ljava/lang/String;',           0xd80e8],
    ['x0015e49c', '(Lretrofit2/Response;Lcom/nivaroid/topfollow/models/Order;Lcom/nivaroid/topfollow/models/InstagramAccount;)Ljava/lang/String;', 0xe01e4],
    ['x0010e27f', '()Ljava/lang/String;',                                                0xfcd60],
    ['x00113f7a', '()Ljava/lang/String;',                                                0xfd010],
    ['x0014c1f9', '(Lretrofit2/Response;)Ljava/lang/String;',                            0xfd540],  // -> #30 RESPONSE HANDLER
    ['x00126f7c', '(ZLjava/lang/String;)Lretrofit2/Retrofit;',                           0xfe268],  // cert pin
    ['x0018d3f7', '(I)Lretrofit2/Retrofit;',                                             0x1013b8]
];

const JNI_CLASS = 'com.nivaroid.topfollow.helper.q';
const MODULE    = 'libtopfollow.so';

/* ===================================================================== *
 * 1. UTILITIES
 * ===================================================================== */

const LOG = {
    store: { secrets: [], keys: [], crypto: [], jni: [], detection: [], notes: [] },
    _ts() { return new Date().toISOString().substr(11, 12); },
    tag(t, msg, obj) {
        const rec = { t: LOG._ts(), tag: t, msg: msg };
        if (obj !== undefined) rec.data = obj;
        console.log('[' + LOG._ts() + '][' + t + '] ' + msg +
                    (obj === undefined ? '' : '\n' + JSON.stringify(obj, null, 2)));
        return rec;
    },
    secret(v)  { const r = LOG.tag('SECRET', v.decoded, v); LOG.store.secrets.push(r); },
    key(v)     { const r = LOG.tag('KEY', v.hex + ' (' + v.len + ' B)', v); LOG.store.keys.push(r); },
    crypto(v)  { const r = LOG.tag('CRYPTO', v.what + '  ' + v.summary, v); LOG.store.crypto.push(r); },
    jni(v)     { const r = LOG.tag('JNI', v.name + v.sig, v); LOG.store.jni.push(r); },
    det(v)     { const r = LOG.tag('DETECT', v.what + ' -> ' + v.ret, v); LOG.store.detection.push(r); },
    note(m)    { LOG.tag('NOTE', m); LOG.store.notes.push({ t: LOG._ts(), msg: m }); },
    warn(m)    { console.log('[!][' + LOG._ts() + '] ' + m); }
};

function hex(ptr, n) {
    if (ptr === null || ptr.isNull() || n <= 0) return '';
    try { return Array.prototype.map.call(new Uint8Array(ptr.readByteArray(n)),
                                          b => ('0' + b.toString(16)).slice(-2)).join(''); }
    catch (e) { return '<unreadable>'; }
}

function hexdumpShort(ptr, n) {
    try { return hexdump(ptr, { length: Math.min(n, 128), ansi: false }); }
    catch (e) { return '<unreadable>'; }
}

function cstr(ptr, max) {
    if (ptr === null || ptr.isNull()) return null;
    try { return ptr.readUtf8String(max || 512); } catch (e) { return null; }
}

/** libc++ std::string reader.
 *  short form : byte0 = size << 1          (bit0 clear), data at +1, SSO cap 22
 *  long  form : (+0)=cap|1, (+8)=size, (+16)=data pointer
 *  This is the exact ABI the emulator implements (emu.py mkstring/getstring),
 *  and it is what func#85/#94/#30/#193 were proven against. */
function readStdString(p) {
    if (p === null || p.isNull()) return null;
    let b0;
    try { b0 = p.readU8(); } catch (e) { return null; }
    if ((b0 & 1) === 0) {
        const n = b0 >> 1;
        if (n === 0) return '';
        try { return p.add(1).readUtf8String(n); } catch (e) { return null; }
    }
    try {
        /* readULong() hands back a UInt64 OBJECT, not a JS number: Math.min()
           on it throws "Cannot convert a BigInt value to a number", which made
           every long-form std::string — i.e. every plaintext longer than the
           22-byte SSO limit — come back as null. Fixed in revision 5. */
        const rawSize = p.add(8).readULong();
        const size = Number(typeof rawSize === 'bigint' ? rawSize
                            : (rawSize && rawSize.valueOf ? rawSize.valueOf() : rawSize));
        const data = p.add(16).readPointer();
        if (!(size > 0) || data.isNull()) return '';
        if (size > 8 * 1024 * 1024) return '<implausible size ' + size + '>';
        try { return data.readUtf8String(Math.min(size, CONFIG.maxDump)); }
        catch (e) { return data.readByteArray(Math.min(size, CONFIG.maxDump)); }
    } catch (e) { return null; }
}

/** readStdString but always returns a printable string (binary -> hex) */
function readStd(p) {
    const v = readStdString(p);
    if (v === null) return '<null>';
    if (typeof v === 'string') return v;
    if (v instanceof ArrayBuffer) {
        const u = new Uint8Array(v);
        return Array.prototype.map.call(u, b => ('0' + b.toString(16)).slice(-2)).join('');
    }
    return String(v);
}

function trunc(s, n) {
    if (s === null || s === undefined) return s;
    s = String(s);
    return s.length > (n || CONFIG.maxDump) ? s.slice(0, n || CONFIG.maxDump) + '…(+' + (s.length - (n || CONFIG.maxDump)) + ')' : s;
}

/* ---- base64 / xor helpers (pure JS, no deps) ----------------------- */
const B64A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function b64decode(s) {
    s = String(s).replace(/[^A-Za-z0-9+/=]/g, '');
    const out = [];
    let buf = 0, bits = 0;
    for (let i = 0; i < s.length; i++) {
        const c = s[i];
        if (c === '=') break;
        const v = B64A.indexOf(c);
        if (v < 0) continue;
        buf = (buf << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xff); }
    }
    return out;
}
function b64encode(bytes) {
    let s = '', i = 0;
    for (; i + 2 < bytes.length; i += 3)
        s += B64A[bytes[i] >> 2] + B64A[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)] +
             B64A[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)] + B64A[bytes[i + 2] & 63];
    const rem = bytes.length - i;
    if (rem === 1) s += B64A[bytes[i] >> 2] + B64A[(bytes[i] & 3) << 4] + '==';
    if (rem === 2) s += B64A[bytes[i] >> 2] + B64A[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)] +
                       B64A[(bytes[i + 1] & 15) << 2] + '=';
    return s;
}
function xorBytes(bytes, k) { return bytes.map(b => b ^ k); }
function toStr(bytes) {
    let s = '';
    for (const b of bytes) if (b >= 32 && b < 127) s += String.fromCharCode(b); else return null;
    return s;
}

/* ---- Java interop byte helpers (used by the §7.4 signature forgery) ---- */
function b64ToJavaBytes(b64str) {
    /* decode in JS, then hand Frida a real Java byte[] */
    const arr = b64decode(b64str);
    const jarr = Java.array('byte', arr.map(x => (x > 127 ? x - 256 : x)));
    return jarr;
}

function javaBytesToArray(jbytes) {
    if (!jbytes) return [];
    const out = [];
    for (let i = 0; i < jbytes.length; i++) { const v = jbytes[i] | 0; out.push(v < 0 ? v + 256 : v); }
    return out;
}

function hexOfJavaBytes(jbytes) { return AES.toHex(javaBytesToArray(jbytes)); }

/* ---- SHA-256 (FIPS 180-4), pure JS ---------------------------------- *
 * Needed at runtime to PROVE the signature-pin story without trusting a
 * comment: sha256Hex(ORIGINAL_SIGNER_CERT) must equal the value the library
 * decoded out of its Base64(Base64(hex)) blob at 0x15084. Also lets
 * rpc.exports.signature() report the digest of any certificate bytes you feed
 * it. Verified against the standard "abc" and empty-string vectors in
 * frida/test_agent_offline.js.                                          */
const SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

function sha256(bytes) {
    const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;
    let H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const msg = Array.prototype.slice.call(bytes);
    const bitLen = msg.length * 8;
    msg.push(0x80);
    while (msg.length % 64 !== 56) msg.push(0);
    /* 64-bit big-endian length; JS bit ops are 32-bit so split it */
    const hi = Math.floor(bitLen / 4294967296) >>> 0;
    const lo = bitLen >>> 0;
    msg.push((hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff);
    msg.push((lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);

    const w = new Array(64);
    for (let off = 0; off < msg.length; off += 64) {
        for (let i = 0; i < 16; i++)
            w[i] = ((msg[off + 4 * i] << 24) | (msg[off + 4 * i + 1] << 16) |
                    (msg[off + 4 * i + 2] << 8) | msg[off + 4 * i + 3]) >>> 0;
        for (let i = 16; i < 64; i++) {
            const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
            const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
        }
        let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
        for (let i = 0; i < 64; i++) {
            const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const ch = (e & f) ^ (~e & g);
            const t1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
            const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const mj = (a & b) ^ (a & c) ^ (b & c);
            const t2 = (S0 + mj) >>> 0;
            h = g; g = f; f = e; e = (d + t1) >>> 0;
            d = c; c = b; b = a; a = (t1 + t2) >>> 0;
        }
        H = [(H[0] + a) >>> 0, (H[1] + b) >>> 0, (H[2] + c) >>> 0, (H[3] + d) >>> 0,
             (H[4] + e) >>> 0, (H[5] + f) >>> 0, (H[6] + g) >>> 0, (H[7] + h) >>> 0];
    }
    const out = [];
    H.forEach(x => out.push((x >>> 24) & 0xff, (x >>> 16) & 0xff, (x >>> 8) & 0xff, x & 0xff));
    return out;
}
function sha256Hex(bytes) { return AES.toHex(sha256(bytes)); }

/* ---- reference AES (FIPS-197, table-free) -------------------------- *
 * Same implementation as work/analysis/aesref.py, which was checked
 * against the standard vectors and against the real func#85 27/27 times.
 * Used for offline decryption of captured ciphertext (rpc.exports.decrypt)
 * and for the runtime self-test.                                        */
const AES = (function () {
    const SBOX = new Uint8Array([
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]);
    const RSBOX = new Uint8Array(256);
    for (let i = 0; i < 256; i++) RSBOX[SBOX[i]] = i;
    const RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d];
    const xt = a => (a & 0x80) ? ((a << 1) ^ 0x1b) & 0xff : (a << 1) & 0xff;

    function expand(key) {
        const nk = key.length >> 2, nr = nk + 6, w = [];
        for (let i = 0; i < nk; i++) w.push([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]);
        for (let i = nk, r = 0; i < 4 * (nr + 1); i++) {
            let t = w[i - 1].slice();
            if (i % nk === 0) {
                t = t.slice(1).concat(t.slice(0, 1)).map(b => SBOX[b]);
                t[0] ^= RCON[(i / nk | 0) - 1];
                r = 1;
            } else if (nk > 6 && i % nk === 4) { t = t.map(b => SBOX[b]); r = 2; } else r = 0;
            w.push(w[i - nk].map((b, j) => b ^ t[j]));
        }
        return { w: w, nr: nr };
    }

    function encBlock(pt, ks) {
        const s = [[], [], [], []];
        for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) s[r][c] = pt[r + 4 * c];
        const addRK = rnd => { for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) s[r][c] ^= ks.w[rnd * 4 + c][r]; };
        addRK(0);
        for (let rnd = 1; rnd <= ks.nr; rnd++) {
            for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) s[r][c] = SBOX[s[r][c]];
            for (let r = 1; r < 4; r++) s[r] = s[r].slice(r).concat(s[r].slice(0, r));
            if (rnd !== ks.nr) {
                for (let c = 0; c < 4; c++) {
                    const a = [s[0][c], s[1][c], s[2][c], s[3][c]];
                    s[0][c] = xt(a[0]) ^ (xt(a[1]) ^ a[1]) ^ a[2] ^ a[3];
                    s[1][c] = a[0] ^ xt(a[1]) ^ (xt(a[2]) ^ a[2]) ^ a[3];
                    s[2][c] = a[0] ^ a[1] ^ xt(a[2]) ^ (xt(a[3]) ^ a[3]);
                    s[3][c] = (xt(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ xt(a[3]);
                }
            }
            addRK(rnd);
        }
        const out = new Uint8Array(16);
        for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) out[r + 4 * c] = s[r][c];
        return out;
    }

    /* GF(2^8) multiply, used only by InvMixColumns */
    const gmul = (x, k) => { let r = 0; for (let i = 7; i >= 0; i--) { r = xt(r); if ((k >> i) & 1) r ^= x; } return r & 0xff; };

    function decBlock(ct, ks) {
        const s = [[], [], [], []];
        for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) s[r][c] = ct[r + 4 * c];
        const addRK = rnd => { for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) s[r][c] ^= ks.w[rnd * 4 + c][r]; };
        addRK(ks.nr);
        for (let rnd = ks.nr - 1; rnd >= 0; rnd--) {
            /* InvShiftRows: rotate each row right by its index */
            for (let r = 1; r < 4; r++) s[r] = s[r].slice(4 - r).concat(s[r].slice(0, 4 - r));
            /* InvSubBytes */
            for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) s[r][c] = RSBOX[s[r][c]];
            addRK(rnd);
            /* InvMixColumns (skipped on the last, i.e. rnd==0, pass) */
            if (rnd !== 0) {
                for (let c = 0; c < 4; c++) {
                    const a = [s[0][c], s[1][c], s[2][c], s[3][c]];
                    s[0][c] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3],  9);
                    s[1][c] = gmul(a[0],  9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13);
                    s[2][c] = gmul(a[0], 13) ^ gmul(a[1],  9) ^ gmul(a[2], 14) ^ gmul(a[3], 11);
                    s[3][c] = gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2],  9) ^ gmul(a[3], 14);
                }
            }
        }
        const out = new Uint8Array(16);
        for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) out[r + 4 * c] = s[r][c];
        return out;
    }

    function pkcs7(b) { const n = 16 - (b.length % 16); const o = Array.prototype.slice.call(b);
                        for (let i = 0; i < n; i++) o.push(n); return o; }
    function unpad(b) { if (!b.length) return b; const n = b[b.length - 1];
                        if (n < 1 || n > 16) return { data: b, bad: true };
                        for (let i = b.length - n; i < b.length; i++) if (b[i] !== n) return { data: b, bad: true };
                        return { data: b.slice(0, b.length - n), bad: false }; }
    function fromHex(s) { s = String(s).replace(/[^0-9a-fA-F]/g, '');
                          const o = []; for (let i = 0; i + 1 < s.length; i += 2) o.push(parseInt(s.substr(i, 2), 16));
                          return o; }
    function toHex(b) { return Array.prototype.map.call(b, x => ('0' + (x & 255).toString(16)).slice(-2)).join(''); }

    return {
        expand: expand, encBlock: encBlock, decBlock: decBlock, pkcs7: pkcs7, unpad: unpad,
        fromHex: fromHex, toHex: toHex, SBOX: SBOX, RSBOX: RSBOX, RCON: RCON,
        ecbEnc(pt, key) { const ks = expand(key); const p = pkcs7(pt); const o = [];
                          for (let i = 0; i < p.length; i += 16) o.push.apply(o, encBlock(p.slice(i, i + 16), ks));
                          return o; },
        ecbDec(ct, key) { const ks = expand(key); const o = [];
                          for (let i = 0; i < ct.length; i += 16) o.push.apply(o, decBlock(ct.slice(i, i + 16), ks));
                          return o; },
        cbcEnc(pt, key, iv) { const ks = expand(key); const p = pkcs7(pt); let prev = iv.slice(); const o = [];
                          for (let i = 0; i < p.length; i += 16) {
                              const blk = p.slice(i, i + 16).map((b, j) => b ^ prev[j]);
                              const c = encBlock(blk, ks); o.push.apply(o, c); prev = c; }
                          return o; },
        cbcDec(ct, key, iv) { const ks = expand(key); let prev = iv.slice(); const o = [];
                          for (let i = 0; i < ct.length; i += 16) {
                              const blk = ct.slice(i, i + 16);
                              const d = decBlock(blk, ks).map((b, j) => b ^ prev[j]);
                              o.push.apply(o, d); prev = blk; }
                          return o; },
        /* the func#30 cipher: AES-128-CBC, all-zero key AND all-zero iv */
        zeroCbcDec(hexstr) { const ct = fromHex(hexstr); const z = new Array(16).fill(0);
                             return AES.unpad(AES.cbcDec(ct, z, z)); },
        zeroCbcEnc(bytes)    { const z = new Array(16).fill(0); return AES.cbcEnc(bytes, z, z); }
    };
})();

/* ---- known hardcoded secrets, for offline correlation -------------- */
const KNOWN_KEYS = [
    { name: 'plaintext .rodata key @0x161ca / 0x17ae0', b64: '0123456789abcdef',
      raw: AES.fromHex('30313233343536373839616263646566') },
    { name: 'func#86 getter (JNI m3/m4 key)',            b64: '5VEJK9Uk4d0elpVT',
      raw: b64decode('5VEJK9Uk4d0elpVT') },
    { name: 'func#159 getter',                           b64: 'OVmx02wMFR6WaGtW',
      raw: b64decode('OVmx02wMFR6WaGtW') },
    { name: 'func#160 getter',                           b64: 'V0V4V2pOa1ptZGsl',
      raw: b64decode('V0V4V2pOa1ptZGsl') },
    { name: 'func#161 getter',                           b64: 'xV2xKTlZsBUVk1He',
      raw: b64decode('xV2xKTlZsBUVk1He') },
    { name: 'func#157 AES-192 key @0x17428',             b64: 'At91IxVnRSbFppV0UxNFdUSnplTW5ONA',
      raw: b64decode('At91IxVnRSbFppV0UxNFdUSnplTW5ONA') },
    { name: 'func#157 GCM nonce @0x17448',               b64: 'WMVEwVG02eGFlVmR',
      raw: b64decode('WMVEwVG02eGFlVmR') },
    { name: 'func#158 GCM nonce @0x17458',               b64: 'M0VEwVGt0aVJuQjF',
      raw: b64decode('M0VEwVGt0aVJuQjF') },
    { name: 'AES-128 zero key (func#30)',                b64: '00*16',
      raw: new Array(16).fill(0) }
];
/* ===================================================================== *
 * APK SIGNATURE PIN  (§6.5)  —  byte-verified, not inferred
 * ===================================================================== *
 * func#226 @0x159c10 and func#73 @0x103ad8 both upcall
 *     ctx.getPackageManager().getPackageInfo(pkg, GET_SIGNATURES)
 *     -> Signature.toByteArray()
 *     -> MessageDigest.getInstance("SHA-256").digest(...)
 * and compare the digest against the blob stored at .rodata 0x15084.
 *
 * That blob is 120 chars of PLAINTEXT Base64 (it is NOT XOR-0x5A encoded):
 *     WkRnME5UVTVNV1V3T0RZd016TmhPVEF6Tldaa05tSTJObU16WXpOa056TmhZVE16WVdZNU1E...
 * Base64-decoding it TWICE yields
 *     d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e
 * and that is exactly SHA-256(original signer certificate DER, 864 bytes),
 * extracted from this APK's v2 Signing Block.  Verified with
 * frida/clone_signer.py, which re-reads both the APK and the .so and asserts
 * the match.  So repackaging + re-signing is guaranteed to break this check
 * unless we hand the ORIGINAL certificate bytes back to the native code —
 * which is precisely what the §7.4 hook below does.
 *
 * Subject : CN=Maryam Ahmadi, OU=Android Developer, O=NivaRoid,
 *           L=Shiraz, ST=Fars, C=IR      (self-signed, serial 1,
 *           valid 2023-12-15T17:44:33Z .. 2048-12-08T17:44:33Z)
 * ===================================================================== */
const SIGNATURE_PIN_SHA256 = 'd845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e';
const SIGNATURE_PIN_BLOB_OFF = 0x15084;   // plaintext base64(base64(hexdigest))
const ORIGINAL_SIGNER_CERT_B64 =
    'MIIDXDCCAkQCAQEwDQYJKoZIhvcNAQELBQAwdDEWMBQGA1UEAwwNTWFyeWFtIEFobWFkaTEa' +
    'MBgGA1UECwwRQW5kcm9pZCBEZXZlbG9wZXIxETAPBgNVBAoMCE5pdmFSb2lkMQ8wDQYDVQQH' +
    'DAZTaGlyYXoxDTALBgNVBAgMBEZhcnMxCzAJBgNVBAYTAklSMB4XDTIzMTIxNTE3NDQzM1oX' +
    'DTQ4MTIwODE3NDQzM1owdDEWMBQGA1UEAwwNTWFyeWFtIEFobWFkaTEaMBgGA1UECwwRQW5k' +
    'cm9pZCBEZXZlbG9wZXIxETAPBgNVBAoMCE5pdmFSb2lkMQ8wDQYDVQQHDAZTaGlyYXoxDTAL' +
    'BgNVBAgMBEZhcnMxCzAJBgNVBAYTAklSMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC' +
    'AQEAi/269b1INF5Skw5rIyOK5pxMo4MikftNxHGz6MV3/StA/296zXWMND35vdcIR0i3HZ+d' +
    'r2FIagZBOyo5rgF1pnlAwocuzLutEUdS9gEWyp/SfLGWp1LKx5zRclHAgE47BlOCApJ+7BX8' +
    '/s7k0hda5aYmhPYFUBniZ8cmnHH9l+H2F6XJZuyhzRSWgZlLoIm3Y36rjKlXllnD5tOTKF0u' +
    'gHx1jV6UagJ5bzjy4e4eOMmxPslcp2fDt3w6V7daECrRmBWGh1PikQgbV2W8qi9mtx8NUZoS' +
    'xNVcCLA9kyoR6TduACOtB379GdTgu8irEwge/v1ChEWKafw/aA/w2cQh3QIDAQABMA0GCSqG' +
    'SIb3DQEBCwUAA4IBAQAH666jLbCTDshkgo2G6QTkUtArzfHmI2HiozoljfXW3FHgxv6abfH3' +
    '9v03c5lfPLyQT3DcTI413ZddNNtLsJRC4D40gX/hqqe6PRt/xi0xPsPZZ2InwptNEYv94iLh' +
    'Ll80PFsNu4ORD+4VmysijRcGOZFb5hHud7advS4n1NzltowmyZC2Skl4PrznEjhqDZ+3Rz+n' +
    'S68vRflPvsw91KXIktk0npzK0whtHZNAg8XJkdsGuPtrCv8o6jgqJtotCTuK1H3TNEUrzAmf' +
    '24Uzt6hIT5PKjYDRll7kdQlqH7H+/bKgdE0nWIYiy807rmjXMpgJQRXWQAythbTkWPtWLAeT';

const KEY_BY_HEX = {};
KNOWN_KEYS.forEach(k => { KEY_BY_HEX[AES.toHex(k.raw)] = k.name; });

/* ===================================================================== *
 * 2. MODULE WAIT — the library is loaded lazily by System.loadLibrary
 * ===================================================================== */

let MOD = null;

function findModule() {
    try { const m = Process.findModuleByName(MODULE); if (m) return m; } catch (e) {}
    try { const m = Process.findModuleByAddress(Module.findExportByName(null, 'JNI_OnLoad')); if (m && m.name === MODULE) return m; } catch (e) {}
    return null;
}

function waitForModule(cb) {
    MOD = findModule();
    if (MOD) { cb(MOD); return; }

    LOG.note(MODULE + ' not loaded yet — arming dlopen watchers');

    const candidates = ['android_dlopen_ext', 'dlopen', '__loader_android_dlopen_ext', '__loader_dlopen'];
    const armed = [];
    candidates.forEach(name => {
        const p = Module.findExportByName(null, name);
        if (!p) return;
        armed.push(name);
        Interceptor.attach(p, {
            onEnter(args) { this.path = cstr(args[0]); },
            onLeave() {
                if (!this.path) return;
                if (this.path.indexOf('topfollow') < 0) return;
                const m = findModule();
                if (m && !MOD) {
                    LOG.note('dlopen watcher (' + name + ') saw "' + this.path + '" -> module base ' + m.base);
                    MOD = m;
                    setTimeout(() => cb(m), 0);
                }
            }
        });
    });
    LOG.note('armed dlopen watchers on: ' + (armed.join(', ') || 'none'));

    /* fallback poll — cheap, and covers the case where the library was
       already mapped before we attached */
    let tries = 0;
    const iv = setInterval(() => {
        tries++;
        const m = findModule();
        if (m) { clearInterval(iv); if (!MOD) { MOD = m; cb(m); } return; }
        if (tries > 600) { clearInterval(iv); LOG.warn('gave up waiting for ' + MODULE); }
    }, 200);
}

/* ===================================================================== *
 * 3. SANITY / SELF-CALIBRATION
 * ===================================================================== */

function A(off) { return MOD.base.add(off); }

function sanityCheck() {
    const info = {
        name: MOD.name, base: MOD.base.toString(), size: MOD.size, path: MOD.path
    };
    LOG.tag('MODULE', MOD.name + ' @ ' + MOD.base + ' size=' + MOD.size, info);

    /* the RX LOAD segment has v_addr == 0 and p_offset == 0, so
       base + <any offset used in the report> is directly addressable.
       Verify with three independent anchors. */
    const checks = [];

    // (a) the only export
    const jniOnLoad = Module.findExportByName(MODULE, 'JNI_OnLoad');
    checks.push(['JNI_OnLoad export == base+0x3e1d4',
                 jniOnLoad !== null && jniOnLoad.equals(A(OFF.jni_onload))]);

    // (b) the FIPS-197 S-box at .rodata 0x128b0
    let sboxOk = false;
    try { sboxOk = hex(A(OFF.rodata_sbox), 16) === '637c777bf26b6fc53001672bfed7ab76'; } catch (e) {}
    checks.push(['S-box @0x128b0 == 637c777bf26b6fc5…', sboxOk]);

    // (c) the extended LibTomCrypt Rcon at 0x13b10
    let rconOk = false;
    try { rconOk = hex(A(OFF.rodata_rcon), 14) === '01020408102040801b366cd8ab4d'; } catch (e) {}
    checks.push(['Rcon  @0x13b10 == 01020408…ab4d', rconOk]);

    // (d) the literal plaintext AES key
    let keyOk = false;
    try { keyOk = cstr(A(OFF.rodata_plain_key), 16) === '0123456789abcdef'; } catch (e) {}
    checks.push(['"0123456789abcdef" @0x161ca', keyOk]);

    // (e) the XOR-0x5A decode loop must start with `cbz x20, …`
    let loopOk = false;
    try { loopOk = A(OFF.xor5a_decode).add(0x300).readU32() === 0xb4000174 || true; } catch (e) {}
    // instruction-level check: 0x141ccc must be `ldrb w8,[x21]`  == 0x394006a8
    try { loopOk = A(0x141ccc).readU32() === 0x394006a8; } catch (e) { loopOk = false; }
    checks.push(['func#193 decode loop @0x141ccc == ldrb w8,[x21]', loopOk]);

    let allOk = true;
    checks.forEach(c => { if (!c[1]) allOk = false;
        console.log('   [' + (c[1] ? ' OK ' : 'FAIL') + '] ' + c[0]); });

    if (!allOk) {
        LOG.warn('=========================================================');
        LOG.warn(' ANCHOR CHECK FAILED. The loaded libtopfollow.so is NOT the');
        LOG.warn(' build these offsets were derived from (v8.4.5 / 845).');
        LOG.warn(' Offsets will be WRONG. Run rpc.exports.selfCalibrate() and');
        LOG.warn(' re-derive them, or use --mode recon only.');
        LOG.warn('=========================================================');
    }
    info.anchors = checks.map(c => ({ check: c[0], ok: c[1] }));
    return allOk;
}

/** Read the 22-entry JNINativeMethod table out of .data.rel.ro and
 *  compare it with the table recovered statically from the APK.
 *  This is the strongest possible confirmation that our offsets are live,
 *  because the table only exists AFTER RegisterNatives has run. */
function selfCalibrate() {
    const out = [];
    if (!MOD) {
        LOG.warn('selfCalibrate: ' + MODULE + ' is not mapped yet - call it again after the library loads');
        return { ok: false, reason: 'module not loaded', entries: [] };
    }
    const slot = A(OFF.jni_table_first_slot);
    for (let i = 0; i < OFF.jni_table_entries; i++) {
        try {
            const namePtr = slot.add(i * 0x18 + 0x00).readPointer();
            const sigPtr  = slot.add(i * 0x18 + 0x08).readPointer();
            const fnPtr   = slot.add(i * 0x18 + 0x10).readPointer();
            const name = cstr(namePtr, 64), sig = cstr(sigPtr, 256);
            let off = null;
            if (!fnPtr.isNull()) off = '0x' + fnPtr.sub(MOD.base).toString(16);
            out.push({ i: i, name: name, sig: sig, fnPtr: fnPtr.toString(), off: off,
                       expect: JNI_EXPECT[i] ? { name: JNI_EXPECT[i][0], sig: JNI_EXPECT[i][1],
                                                 off: '0x' + JNI_EXPECT[i][2].toString(16) } : null });
        } catch (e) { out.push({ i: i, error: String(e) }); }
    }
    const live = out.filter(o => o.name);
    const matched = live.filter(o => o.expect && o.expect.name === o.name && o.expect.off === o.off).length;
    LOG.tag('CALIBRATE', matched + '/' + out.length + ' JNI table slots match the static recovery',
            { matched: matched, total: out.length, table: out });
    return { ok: matched === out.length, matched: matched, total: out.length, table: out };
}

/** Runtime self-test: recompute every known-answer vector from §11 of the
 *  report with the JS AES above, and decode the three live .rodata secrets
 *  out of the mapped module. Nothing here calls into the library, so it is
 *  safe to run at any time and cannot trip a `b .` trap. */
function selfTest() {
    const res = [];
    const enc = s => Array.from(new TextEncoder().encode(s));

    /* (a) FIPS-197 standard vectors — proves the JS AES itself */
    const FIPS_PT  = AES.fromHex('00112233445566778899aabbccddeeff');
    const FIPS_K16 = AES.fromHex('000102030405060708090a0b0c0d0e0f');
    const FIPS_K32 = AES.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    /* encBlock(pt, ks) — ks comes from expand(key) */
    res.push(v('FIPS-197 AES-128 enc',
        AES.toHex(AES.encBlock(FIPS_PT, AES.expand(FIPS_K16))),
        '69c4e0d86a7b0430d8cdb78070b4c55a'));
    res.push(v('FIPS-197 AES-128 dec (inverse)',
        AES.toHex(AES.decBlock(AES.fromHex('69c4e0d86a7b0430d8cdb78070b4c55a'), AES.expand(FIPS_K16))),
        '00112233445566778899aabbccddeeff'));
    res.push(v('FIPS-197 AES-256 enc',
        AES.toHex(AES.encBlock(FIPS_PT, AES.expand(FIPS_K32))),
        '8ea2b7ca516745bfeafc49904b496089'));
    res.push(v('FIPS-197 AES-256 dec (inverse)',
        AES.toHex(AES.decBlock(AES.fromHex('8ea2b7ca516745bfeafc49904b496089'), AES.expand(FIPS_K32))),
        '00112233445566778899aabbccddeeff'));
    res.push(v('FIPS-197 AES-192 enc',
        AES.toHex(AES.encBlock(FIPS_PT, AES.expand(AES.fromHex('000102030405060708090a0b0c0d0e0f1011121314151617')))),
        'dda97ca4864cdfe06eaf70a0ec0d7191'));

    /* (a2) the APK-signature pin: SHA-256 of the original cert must equal the
          value the library stores as Base64(Base64(hex)) at 0x15084 (§6.5) */
    res.push(v('SHA-256(original signer cert DER) == pin',
        sha256Hex(b64decode(ORIGINAL_SIGNER_CERT_B64)), SIGNATURE_PIN_SHA256));
    res.push(v('SHA-256 FIPS vector "abc"', sha256Hex(enc('abc')),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'));
    res.push(v('SHA-256 FIPS vector ""', sha256Hex([]),
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'));
    res.push(v('original cert DER is 864 bytes', String(b64decode(ORIGINAL_SIGNER_CERT_B64).length), '864'));

    /* (b) the func#85 / func#30 vectors captured under emulation (§11.2, §11.3) */
    res.push(v('func#85("hello", "0123456789abcdef")  AES-128-ECB',
        AES.toHex(AES.ecbEnc(enc('hello'), enc('0123456789abcdef'))),
        '674c7ef38e78cabd9cec9c125823a639'));
    res.push(v('func#85("hello", bytes(range(24)))    AES-192-ECB',
        AES.toHex(AES.ecbEnc(enc('hello'), AES.fromHex('000102030405060708090a0b0c0d0e0f1011121314151617'))),
        '12056740635d5dd4124b24264bb8a00a'));
    res.push(v('func#85("hello", bytes(range(32)))    AES-256-ECB',
        AES.toHex(AES.ecbEnc(enc('hello'), AES.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'))),
        '91684487c34c3456eb4e901cef884a1e'));
    res.push(v('func#85("A"*32) block0 == block1 (ECB leak)',
        AES.toHex(AES.ecbEnc(enc('A'.repeat(32)), enc('0123456789abcdef'))).slice(0, 64),
        '3bfd04cc0d7ed55358e2cbe19de213833bfd04cc0d7ed55358e2cbe19de21383'));
    res.push(v('func#85 PKCS#7 pad-block constant',
        AES.toHex(AES.ecbEnc(new Array(16).fill(0x10), enc('0123456789abcdef'))),
        '377222e061a924c591cd9c27ea163ed4377222e061a924c591cd9c27ea163ed4'));
    res.push(v('func#30("hello")  zero-key AES-128-CBC',
        AES.toHex(AES.zeroCbcEnc(enc('hello'))),
        '9834ed518cbc8fbe9af3c6ecb75eb8c0'));
    res.push(v('func#30("")       == AES-ECB(0x10*16, key 0)',
        AES.toHex(AES.zeroCbcEnc([])),
        '0143db63ee66b0cdff9f69917680151e'));
    res.push(v('func#30("A"*16)',
        AES.toHex(AES.zeroCbcEnc(enc('A'.repeat(16)))),
        'b49cbf19d357e6e1f6845c30fd5b63e30c747680a9e9970389a2bdd752b4b1c3'));
    res.push(v('func#30(order JSON, 36 B)',
        AES.toHex(AES.zeroCbcEnc(enc('{"order_id":12345,"type":"follower"}'))),
        'f49288051d7d9decc641ea07eb7ff32cbde7e2be9f3006617f3938a20f63549cfc144d3ce97d67ecc55475f0dfeec781'));
    res.push(v('func#94(func#85("hello")) round-trip',
        utf8OrHex(AES.unpad(AES.ecbDec(AES.fromHex('674c7ef38e78cabd9cec9c125823a639'),
                                       enc('0123456789abcdef'))).data),
        'hello'));
    res.push(v('func#94(func#30("hello")) round-trip',
        utf8OrHex(AES.unpad(AES.zeroCbcDec('9834ed518cbc8fbe9af3c6ecb75eb8c0')).data),
        'hello'));

    /* (c) live .rodata: decode the three hardcoded secrets with XOR 0x5A */
    if (MOD) {
        [['AES-192 key  @0x17428', OFF.rodata_key192_ct, 32, 'At91IxVnRSbFppV0UxNFdUSnplTW5ONA'],
         ['GCM nonce 1 @0x17448', OFF.rodata_nonce1_ct, 16, 'WMVEwVG02eGFlVmR'],
         ['GCM nonce 2 @0x17458', OFF.rodata_nonce2_ct, 16, 'M0VEwVGt0aVJuQjF'],
         ['plaintext key @0x161ca', OFF.rodata_plain_key, 16, '0123456789abcdef']].forEach(l => {
            let got = '<err>';
            try {
                const b = Array.from(new Uint8Array(A(l[1]).readByteArray(l[2])));
                got = (l[1] === OFF.rodata_plain_key) ? toStr(b) : toStr(xorBytes(b, 0x5a));
                if (got === null) got = '<binary>';
            } catch (e) { got = '<' + e + '>'; }
            res.push(v('live XOR/plain ' + l[0], got, l[3]));
        });
        /* (d) the AES tables must be where the report says */
        res.push(v('live S-box @0x128b0', hex(A(OFF.rodata_sbox), 16), '637c777bf26b6fc53001672bfed7ab76'));
        res.push(v('live Rcon  @0x13b10', hex(A(OFF.rodata_rcon), 14), '01020408102040801b366cd8ab4d'));
    } else {
        res.push({ what: 'live .rodata checks (6 of them)', got: 'module not mapped',
                   expect: 'libtopfollow.so loaded', ok: null, skipped: true });
    }

    const failed  = res.filter(r => r.ok === false);
    const skipped = res.filter(r => r.ok === null);
    const passed  = res.filter(r => r.ok === true);
    const allOk = failed.length === 0;
    LOG.tag('SELFTEST', allOk ? ('ALL ' + passed.length + ' VECTORS PASS' +
            (skipped.length ? ' (' + skipped.length + ' skipped)' : '')) : (failed.length + ' FAILURES'),
            failed);
    res.forEach(r => console.log('   [' + (r.ok === true ? ' OK ' : r.ok === null ? 'SKIP' : 'FAIL') + '] ' + r.what +
                                 (r.ok === true ? '' : '\n          got    ' + r.got + '\n          expect ' + r.expect)));
    return { allOk: allOk, total: res.length, passed: passed.length,
             failed: failed, skipped: skipped.length, results: res };
}
function v(what, got, expect) { return { what: what, got: String(got), expect: String(expect), ok: String(got) === String(expect) }; }

/* ===================================================================== *
 * 4. JNI LAYER — hook RegisterNatives, then every registered native
 * ===================================================================== */

const JNI_HOOKED = {};

function hookRegisterNatives() {
    /* libart.so exports RegisterNatives only through the JNIEnv vtable, so
       the portable way is to hook the vtable slot. Slot index 215 for
       RegisterNatives in JNINativeInterface. */
    try {
        const art = Process.findModuleByName('libart.so');
        if (!art) { LOG.warn('libart.so not found — RegisterNatives hook skipped'); return; }
        // Find an existing JNIEnv: use Java.vm.getEnv() when the Java VM is up.
        if (!Java.available) { LOG.warn('Java VM not available yet — deferring RegisterNatives hook'); return; }
        Java.perform(() => {
            try {
                const env = Java.vm.getEnv();
                const envPtr = env.handle;                  // JNIEnv**
                const vtable = envPtr.readPointer();        // JNINativeInterface*
                const slot = vtable.add(215 * Process.pointerSize).readPointer();
                LOG.note('RegisterNatives @ ' + slot + ' (libart.so range ' +
                         art.base + '-' + art.base.add(art.size) + ')');
                Interceptor.attach(slot, {
                    onEnter(args) {
                        // (JNIEnv*, jclass, const JNINativeMethod*, jint n)
                        const clazz = args[1], methods = args[2], n = args[3].toInt32();
                        let cname = null;
                        try {
                            const callObjectMethod = new NativeFunction(
                                vtable.add(34 * Process.pointerSize).readPointer(),
                                'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
                            void callObjectMethod;
                        } catch (e) {}
                        const list = [];
                        for (let i = 0; i < n && i < 64; i++) {
                            const e = methods.add(i * 3 * Process.pointerSize);
                            const nm = cstr(e.readPointer(), 64);
                            const sg = cstr(e.add(Process.pointerSize).readPointer(), 256);
                            const fp = e.add(2 * Process.pointerSize).readPointer();
                            let off = null;
                            try { off = fp.sub(MOD.base); } catch (x) {}
                            list.push({ name: nm, sig: sg, fnPtr: fp.toString(),
                                        off: off ? '0x' + off.toString(16) : null,
                                        inModule: off ? (off.compare(ptr(0)) >= 0 && off.compare(ptr(MOD.size)) < 0) : false });
                        }
                        LOG.tag('REGNAT', n + ' natives registered', { jclass: clazz.toString(), methods: list });
                        list.filter(m => m.inModule).forEach(m => hookJniFn(m.name, m.sig, m.fnPtr, m.off));
                    }
                });
            } catch (e) { LOG.warn('RegisterNatives hook failed: ' + e); }
        });
    } catch (e) { LOG.warn('hookRegisterNatives: ' + e); }
}

function hookJniFn(name, sig, fnPtr, off) {
    const key = name + sig;
    if (JNI_HOOKED[key]) return;
    JNI_HOOKED[key] = true;
    try {
        Interceptor.attach(fnPtr, {
            onEnter(args) {
                this.name = name; this.sig = sig; this.off = off ? off.toString() : null;
                this.java = [];
                if (!Java.available) return;
                try {
                    const env = Java.vm.getEnv();
                    // args[0]=JNIEnv*, args[1]=jobject/jclass, args[2..]=java params
                    const params = parseSigParams(sig);
                    params.forEach((t, i) => {
                        const p = args[2 + i];
                        if (p === undefined || p.isNull()) { this.java.push(null); return; }
                        if (t === 'Ljava/lang/String;') {
                            try { this.java.push(env.getStringUtfChars(p, null).readUtf8String()); }
                            catch (e) { this.java.push('<' + e + '>'); }
                        } else {
                            this.java.push({ type: t, ref: p.toString() });
                        }
                    });
                } catch (e) { this.java.push('<env err ' + e + '>'); }
            },
            onLeave(retval) {
                let out = null;
                if (this.sig.indexOf(')Ljava/lang/String;') > 0 && !retval.isNull()) {
                    try { out = Java.vm.getEnv().getStringUtfChars(retval, null).readUtf8String(); }
                    catch (e) { out = '<' + e + '>'; }
                } else if (this.sig.indexOf(')J') > 0) {
                    out = retval.toString();
                }
                LOG.jni({ name: this.name, sig: this.sig, off: this.off,
                          args: this.java, ret: trunc(out, 2048),
                          summary: trunc(out, 120) });
            }
        });
    } catch (e) { LOG.warn('hookJniFn(' + name + '): ' + e); }
}

function parseSigParams(sig) {
    const inner = sig.slice(1, sig.indexOf(')'));
    const out = []; let i = 0;
    while (i < inner.length) {
        const c = inner[i];
        if (c === 'L') { const j = inner.indexOf(';', i); out.push(inner.slice(i, j + 1)); i = j + 1; }
        else if (c === '[') { let j = i; while (inner[j] === '[') j++;
                              if (inner[j] === 'L') { const k = inner.indexOf(';', j); out.push(inner.slice(i, k + 1)); i = k + 1; }
                              else { out.push(inner.slice(i, j + 1)); i = j + 1; } }
        else { out.push(c); i++; }
    }
    return out;
}

/* Fallback: if RegisterNatives was already called before we attached,
 * hook the 22 natives directly from the statically recovered table. */
function hookJniFromStaticTable() {
    let done = 0;
    JNI_EXPECT.forEach(e => {
        try { hookJniFn(e[0], e[1], A(e[2]), ptr(e[2])); done++; } catch (x) {}
    });
    LOG.note('static JNI table: hooked ' + done + '/' + JNI_EXPECT.length + ' natives');
    return done;
}

/* ===================================================================== *
 * 5. NATIVE CRYPTO HOOKS  (read-only; see the HARD RULE at the top)
 * ===================================================================== */

function hookCrypto() {

    /* ---- 5.1 func#85 : AES-ECB encrypt -> lowercase hex ------------- *
     *   x0 = const std::string& plaintext
     *   x1 = const std::string& key   (used VERBATIM, no KDF)
     *   x8 = std::string* sret        (hex ciphertext, or the literal "null")
     * Returns "null" when pt or key is empty, or key len is not 16/24/32. */
    Interceptor.attach(A(OFF.aes_ecb_encrypt_hex), {
        onEnter(args) {
            this.pt  = readStd(args[0]);
            this.key = readStd(args[1]);
            this.sret = this.context.x8;
        },
        onLeave() {
            const ct = readStd(this.sret);
            const keyHex = AES.toHex(Array.from(new TextEncoder().encode(this.key || '')));
            LOG.crypto({
                what: 'func#85 AES-ECB ENCRYPT (hex out)',
                fn: '#85', off: '0x10c470',
                plaintext: trunc(this.pt), plaintextLen: (this.pt || '').length,
                key: this.key, keyHex: keyHex, keyLen: (this.key || '').length,
                keyKnownAs: KEY_BY_HEX[keyHex] || null,
                cipherHex: trunc(ct), cipherLen: (ct || '').length,
                mode: 'ECB/PKCS7', encoding: 'lowercase-hex',
                summary: 'pt=' + trunc(this.pt, 60) + ' -> ct=' + trunc(ct, 60)
            });
            if (ct === 'null')
                LOG.warn('func#85 returned "null" — empty pt, empty key, or key length not in {16,24,32}');
        }
    });

    /* ---- 5.2 func#94 : exact inverse of func#85 --------------------- */
    Interceptor.attach(A(OFF.aes_ecb_decrypt_hex), {
        onEnter(args) {
            this.ct  = readStd(args[0]);
            this.key = readStd(args[1]);
            this.sret = this.context.x8;
        },
        onLeave() {
            const pt = readStd(this.sret);
            LOG.crypto({
                what: 'func#94 AES-ECB DECRYPT (hex in)',
                fn: '#94', off: '0x110b70',
                cipherHex: trunc(this.ct), key: this.key, keyLen: (this.key || '').length,
                plaintext: trunc(pt), plaintextLen: (pt || '').length,
                mode: 'ECB/PKCS7', encoding: 'lowercase-hex',
                summary: 'ct=' + trunc(this.ct, 60) + ' -> pt=' + trunc(pt, 60)
            });
        }
    });

    /* ---- 5.3 func#30 : AES-128-CBC, ZERO key, ZERO iv --------------- *
     *   x0 = plaintext, x1 = key argument (ACCEPTED THEN DISCARDED),
     *   x8 = sret hex. Proven over 5 different key args -> identical out.
     * Used by 7 of the 22 JNI natives, including the response handler. */
    Interceptor.attach(A(OFF.aes_cbc_zerokey_hex), {
        onEnter(args) {
            this.pt = readStd(args[0]);
            this.keyArg = readStd(args[1]);
            this.sret = this.context.x8;
        },
        onLeave() {
            const ct = readStd(this.sret);
            const ptBytes = Array.from(new TextEncoder().encode(this.pt || ''));
            let verified = null;
            try { verified = AES.toHex(AES.zeroCbcEnc(ptBytes)) === ct.replace(/[^0-9a-f]/g, ''); }
            catch (e) { verified = 'err:' + e; }
            LOG.crypto({
                what: 'func#30 AES-128-CBC ZERO-KEY ENCRYPT (hex out)',
                fn: '#30', off: '0x38fa4',
                plaintext: trunc(this.pt), plaintextLen: ptBytes.length,
                keyArgIgnored: this.keyArg,
                effectiveKey: '00'.repeat(16), effectiveIv: '00'.repeat(16),
                cipherHex: trunc(ct), cipherLen: (ct || '').length,
                mode: 'CBC/PKCS7', encoding: 'lowercase-hex',
                matchesZeroKeyCbc: verified,
                over220BytesWarning: ptBytes.length > 220
                    ? 'plaintext > 220 bytes: report §10 item 27 — func#30 diverges from CBC past ciphertext offset 208'
                    : null,
                summary: 'pt=' + trunc(this.pt, 60) + ' -> ct=' + trunc(ct, 60)
            });
        }
    });

    /* ---- 5.4 func#36 : hex-in / binary-out, fixed internal key ------ */
    Interceptor.attach(A(OFF.aes256_ecb_dechex), {
        onEnter(args) {
            this.in = readStd(args[0]);
            this.keyArg = readStd(args[1]);
            this.sret = this.context.x8;
        },
        onLeave() {
            const out = readStd(this.sret);
            LOG.crypto({ what: 'func#36 fixed-key AES decrypt (hex in -> raw out)',
                         fn: '#36', off: '0x3a838',
                         input: trunc(this.in), keyArgIgnored: this.keyArg,
                         output: trunc(out), outputLen: (out || '').length,
                         note: 'sole caller is func#252 on the CertificatePinner path; NOT the inverse of func#30',
                         summary: trunc(this.in, 40) + ' -> ' + trunc(out, 40) });
        }
    });

    /* ---- 5.5 func#14 : rijndael_setup — the REAL key, verbatim ------ *
     *   x0 = symmetric_key*   x1 = userkey   x3 = keylen in BYTES
     * Proven: *x1 IS the key; round keys land at x0+0x0c, stride 32, LE. */
    Interceptor.attach(A(OFF.rijndael_setup), {
        onEnter(args) {
            this.skey = args[0]; this.userkey = args[1];
            this.keylen = args[3].toInt32();
            let kb = null;
            try { kb = new Uint8Array(this.userkey.readByteArray(this.keylen)); } catch (e) {}
            if (!kb) return;
            const h = AES.toHex(kb);
            LOG.key({ hex: h, len: this.keylen,
                      aes: this.keylen === 16 ? 'AES-128' : this.keylen === 24 ? 'AES-192' :
                           this.keylen === 32 ? 'AES-256' : 'INVALID(non-16/24/32)',
                      ascii: toStr(Array.from(kb)),
                      knownAs: KEY_BY_HEX[h] || null,
                      from: 'func#14 rijndael_setup', backtrace: shortBt(this.context) });
        },
        onLeave() {
            /* dump the expanded schedule straight out of the struct */
            if (this.keylen !== 16 && this.keylen !== 24 && this.keylen !== 32) return;
            try {
                const nr = this.keylen === 16 ? 10 : this.keylen === 24 ? 12 : 14;
                const rows = [];
                for (let r = 0; r <= nr; r++)
                    rows.push(hex(this.skey.add(0x0c + 32 * r), 16));
                LOG.note('func#14 expanded schedule (' + (nr + 1) + ' rows @ +0x0c stride 32): ' + rows[0] + ' …');
                LOG.store.keys.push({ t: LOG._ts(), tag: 'KEYSCHED', rows: rows });
            } catch (e) {}
        }
    });

    /* ---- 5.6 func#193 : XOR-0x5A string decoder --------------------- *
     *   x0 = src (.rodata)   x1 = length   x8 = std::string* dst
     * This ONE hook recovers every hardcoded secret in the library. */
    Interceptor.attach(A(OFF.xor5a_decode), {
        onEnter(args) {
            this.src = args[0]; this.len = args[1].toInt32(); this.dst = this.context.x8;
            try { this.ct = hex(this.src, Math.min(this.len, 256)); } catch (e) { this.ct = null; }
            let off = null;
            try { off = '0x' + this.src.sub(MOD.base).toString(16); } catch (e) {}
            this.off = off;
        },
        onLeave() {
            if (this.len <= 0 || this.len > 4096) return;
            const dec = readStd(this.dst);
            let b64 = null, rawHex = null, rawLen = null;
            if (dec && /^[A-Za-z0-9+/=]+$/.test(dec) && dec.length % 4 === 0) {
                const d = b64decode(dec);
                if (d.length) { rawHex = AES.toHex(d); rawLen = d.length; b64 = dec; }
            }
            LOG.secret({ from: this.off, len: this.len, ct: this.ct, decoded: trunc(dec),
                         base64: b64, rawHex: rawHex, rawLen: rawLen,
                         knownAs: rawHex ? KEY_BY_HEX[rawHex] : null,
                         summary: dec });
        }
    });

    /* ---- 5.7 the constant key/nonce getters ------------------------ */
    [['func#86', OFF.key_getter_86], ['func#159', OFF.key_getter_159],
     ['func#160', OFF.key_getter_160], ['func#161', OFF.key_getter_161],
     ['func#87', OFF.key_getter_87]].forEach(g => {
        try {
            Interceptor.attach(A(g[1]), {
                onEnter() { this.sret = this.context.x8; },
                onLeave() {
                    const v = readStd(this.sret);
                    const d = v && /^[A-Za-z0-9+/=]+$/.test(v) ? b64decode(v) : null;
                    LOG.key({ hex: d ? AES.toHex(d) : null, len: d ? d.length : null,
                              ascii: null, b64: v, from: g[0] + ' (argument-independent getter)',
                              knownAs: d ? (KEY_BY_HEX[AES.toHex(d)] || null) : null });
                }
            });
        } catch (e) { LOG.warn('getter hook ' + g[0] + ': ' + e); }
    });

    /* ---- 5.8 cipher-context builders (key + nonce install) ---------- */
    [['func#157 ctx_build_enc', OFF.ctx_build_enc],
     ['func#158 ctx_build_dec', OFF.ctx_build_dec]].forEach(g => {
        try {
            Interceptor.attach(A(g[1]), {
                onEnter(args) { this.in = readStd(args[0]); this.sret = this.context.x8; },
                onLeave() {
                    LOG.crypto({ what: g[0] + ' (installs key@0x17428 + nonce@0x17448/0x17458)',
                                 input: trunc(this.in), output: trunc(readStd(this.sret)),
                                 note: 'watch the func#193 lines immediately before this one — they carry the key material',
                                 summary: g[0] });
                }
            });
        } catch (e) {}
    });

    LOG.note('crypto hooks installed: func#85 #94 #30 #36 #14 #193 + 5 getters + 2 ctx builders');
}

function shortBt(ctx) {
    try {
        return Thread.backtrace(ctx, Backtracer.FUZZY)
            .slice(0, 6)
            .map(a => {
                if (!MOD) return a.toString();
                const d = a.sub(MOD.base);
                return (d.compare(ptr(0)) >= 0 && d.compare(ptr(MOD.size)) < 0)
                    ? MODULE + '+0x' + d.toString(16) : DebugSymbol.fromAddress(a).toString();
            });
    } catch (e) { return []; }
}

/* ===================================================================== *
 * 6. DETECTION BYPASS
 * ===================================================================== */

/* Every token the library actually looks for, taken from the decoded .rodata
   (report §5.2 / §6).  The scanners store these as PLAIN Base64 C strings — e.g.
   'bGliZnJpZGEtZ2FkZ2V0' @0x16d97 = 'libfrida-gadget', 'eWdzaWs=' @0x16f60 =
   'ygsik', 'Y3Vic3RyYXRl'/'c3Vic3RyYXRl' = 'substrate' — so the literal strings
   never appear in the binary and a `strings`-based allowlist misses them.
   func#162 owns the Frida set, func#60 the Xposed/Substrate/Riru set, func#225
   the maps-integrity set. */
const MAPS_NOISE = [
    /* func#162 — Frida, from Base64 @0x15be1/0x1607f/0x161eb/0x16d97 */
    'frida', 're.frida.server', 're.frida', 'gum-js-loop', 'libfrida-gadget',
    'frida-gadget', 'frida-agent', 'pool-frida', 'gmain', 'linjector', 'gadget',
    /* func#60 — Xposed / Substrate / Riru, from Base64
       @0x15541/0x156df/0x156e8/0x15dd4/0x16204/0x167a9/0x16c11/0x16f60 */
    'libbridge.so', 'riru', 'libcso_substrate', 'substrate', 'edxposed',
    'lsposed', 'xposed', 'ygsik', 'zygisk',
    /* func#225 — maps integrity, from Base64
       @0x15db5/0x16336/0x16b75/0x16f69 */
    'rwxp', '(deleted)', 'libart.so', 'libc.so (deleted)',
    /* root / general */
    'magisk', 'supolicy', 'daemonsu', 'busybox', 'superuser', '/sbin/su',
    'libffi',
    /* the path itself: func#99/#162/#225/#60 all compare against it */
    '/proc/self/maps', 'proc/self/maps', '/proc/', 'smaps'
];

function mapsLineIsSuspicious(line) {
    const l = line.toLowerCase();
    return MAPS_NOISE.some(t => l.indexOf(t) >= 0);
}

/* File descriptors the library has open on a /proc/... maps file. Filled by the
   __open_2/open hooks below and consumed by the read/__read_chk hooks. */
const MAP_FDS = new Set();

/* Length-preserving rewrite of one read() chunk of a maps file: every suspicious
   line is replaced by an innocuous one of EXACTLY the same byte length, so the
   return value of read() stays valid and no caller-side counter has to be patched.
   Returns the number of lines rewritten. */
function filterMapsBuffer(buf, n) {
    if (n <= 0) return 0;
    let raw;
    try { raw = buf.readByteArray(n); } catch (e) { return 0; }
    if (!raw) return 0;
    const text = new Uint8Array(raw).reduce((a, b) => a + String.fromCharCode(b), '');
    if (text.indexOf('\n') < 0) return 0;
    const parts = text.split('\n');
    let changed = 0;
    for (let i = 0; i < parts.length - 1; i++) {
        const line = parts[i];
        if (!line || !mapsLineIsSuspicious(line)) continue;
        let rep = '7f000000-7f001000 r--p 00000000 00:00 0';
        if (rep.length > line.length) rep = rep.slice(0, line.length);
        while (rep.length < line.length) rep += ' ';
        parts[i] = rep;
        changed++;
        LOG.det({ what: 'maps line filtered (read buffer, length preserved)',
                  ret: 'rewritten', line: line.trim().slice(0, 120) });
    }
    if (!changed) return 0;
    const out = parts.join('\n');
    const bytes = [];
    for (let i = 0; i < out.length && i < n; i++) bytes.push(out.charCodeAt(i) & 0xff);
    try { buf.writeByteArray(bytes); } catch (e) { return 0; }
    return changed;
}

function hookMapsFiltering() {
    /* REV 4 — this is the layer that actually matters.

       libtopfollow.so imports NO fopen, NO fgets, NO strstr, NO stat and NO lstat.
       Its complete 88-symbol import list contains __open_2 (8 call sites),
       __read_chk (6), read (3) and close (6), and exactly three functions use
       them — the maps readers:

           func#129 @0x11deb0  <- func#99 (anti-Frida), func#225 (maps integrity)
           func#198 @0x143694  <- func#162 (anti-Frida b64), func#200 (anti-hook)
           func#213 @0x151e68  <- func#60 (the 179,828-byte Xposed/Riru scanner)

       So the scanners read /proc/self/maps with open()+read() and then search the
       buffer with their own inlined byte loops (memcmp/memchr, no PLT strstr).
       An fgets or strstr hook therefore intercepts NOTHING here — the buffer has
       to be cleaned between read() returning and the scanner looking at it.

       The rewrite is length-preserving, which keeps it safe: no count, no register
       and no flattened function body is touched. */

    const isMapsPath = p => !!p && p.indexOf('/proc/') === 0 &&
                            (p.indexOf('maps') >= 0 || p.indexOf('smaps') >= 0 ||
                             p.indexOf('task/') >= 0);

    /* 1. track which fds point at a maps file */
    ['__open_2', 'open', 'open64', 'openat'].forEach(fn => {
        const p = Module.findExportByName('libc.so', fn);
        if (!p) return;
        Interceptor.attach(p, {
            onEnter(args) { this.path = cstr(args[0], 256); },
            onLeave(retval) {
                if (!this.path) return;
                const fd = retval.toInt32();
                if (fd >= 0 && isMapsPath(this.path)) {
                    MAP_FDS.add(fd);
                    LOG.det({ what: fn + '("' + this.path + '") -> fd ' + fd,
                              ret: 'tracked for read() filtering' });
                }
            }
        });
    });

    /* 2. clean every chunk read from a tracked fd */
    [['read', 0, 1], ['__read_chk', 1, 2], ['pread', 0, 1], ['pread64', 0, 1]].forEach(spec => {
        const fn = spec[0], fdArg = spec[1], lenArg = spec[2];
        const p = Module.findExportByName('libc.so', fn);
        if (!p) return;
        Interceptor.attach(p, {
            onEnter(args) {
                this.active = false;
                try { this.active = MAP_FDS.has(args[fdArg].toInt32()); } catch (e) {}
                if (this.active) { this.buf = args[fdArg + 1]; this.len = args[lenArg].toInt32(); }
            },
            onLeave(retval) {
                if (!this.active) return;
                const got = retval.toInt32();
                if (got <= 0) return;
                const n = (this.len > 0 && this.len < got) ? this.len : got;
                filterMapsBuffer(this.buf, n);
            }
        });
        LOG.note('maps filter: ' + fn + ' hooked (buffer rewrite)');
    });

    /* 3. stop tracking on close */
    const cl = Module.findExportByName('libc.so', 'close');
    if (cl) Interceptor.attach(cl, {
        onEnter(args) { try { MAP_FDS.delete(args[0].toInt32()); } catch (e) {} }
    });

    /* 4. entry-only watches on the three readers and on func#60. Log-only: these
          are flattened bodies and must never be replaced. */
    [['func#129 maps reader (used by #99, #225)', OFF.maps_reader_129],
     ['func#198 maps reader (used by #162, #200)', OFF.maps_reader_198],
     ['func#213 maps reader (used by #60)',        OFF.maps_reader_213],
     ['func#60  179 KB Xposed/Riru/Substrate scanner', OFF.big_scanner_60]
    ].forEach(d => {
        try {
            Interceptor.attach(A(d[1]), {
                onEnter() { LOG.det({ what: d[0] + ' entered', ret: '(log-only)' }); }
            });
        } catch (e) { LOG.warn('reader hook ' + d[0] + ': ' + e); }
    });

    /* 5. DEFENCE IN DEPTH ONLY — kept for other builds, but this library never
          calls either function, so on TopFollow v8.4.5 these two hooks fire 0 times.
          Do not rely on them. */
    const fgets = Module.findExportByName('libc.so', 'fgets');
    if (fgets) {
        Interceptor.attach(fgets, {
            onEnter(args) { this.buf = args[0]; this.n = args[1].toInt32(); },
            onLeave(retval) {
                if (retval.isNull()) return;
                let line;
                try { line = this.buf.readCString(); } catch (e) { return; }
                if (!line || !mapsLineIsSuspicious(line)) return;
                const repl = '7f000000-7f001000 r--p 00000000 00:00 0   [filtered]\n';
                try { this.buf.writeUtf8String(repl.slice(0, Math.max(0, this.n - 1))); } catch (e) {}
                LOG.det({ what: 'fgets(maps) line filtered', ret: 'rewritten', line: line.trim() });
            }
        });
        LOG.note('maps filter: fgets hooked (defence in depth — NOT imported by this .so)');
    }

    const strstr = Module.findExportByName('libc.so', 'strstr');
    if (strstr) {
        Interceptor.attach(strstr, {
            onEnter(args) { this.needle = cstr(args[1], 64); },
            onLeave(retval) {
                if (!this.needle) return;
                const n = this.needle;
                /* exact-match only: 'libc.so' and 'libart.so' are legitimate
                   substrings of half the lines in a real maps file, so suppressing
                   them by substring would shred the file and is itself a signal. */
                const isToken = MAPS_NOISE.some(t => t.length >= 6 && n === t) ||
                                n.indexOf('/proc/self/maps') >= 0 ||
                                n === 'su' || n === 'rwxp' || n === '(deleted)';
                if (isToken && !retval.isNull()) {
                    retval.replace(ptr(0));
                    LOG.det({ what: 'strstr token suppressed', ret: 'NULL', needle: n });
                }
            }
        });
        LOG.note('maps filter: strstr hooked (defence in depth — NOT imported by this .so)');
    }

    /* fopen/open path logging (fopen is not imported by this .so either) */
    ['fopen', 'fopen64', '__open_2', 'open', 'open64'].forEach(fn => {
        const p = Module.findExportByName('libc.so', fn);
        if (!p) return;
        Interceptor.attach(p, {
            onEnter(args) {
                const path = cstr(args[0], 256);
                if (!path) return;
                if (path.indexOf('/proc/') === 0 || path.indexOf('maps') >= 0 ||
                    path.indexOf('su') >= 0 || path.indexOf('magisk') >= 0 ||
                    path.indexOf('frida') >= 0) {
                    LOG.det({ what: fn + '("' + path + '")', ret: 'allowed',
                              bt: shortBt(this.context) });
                }
            }
        });
    });

    /* access()/stat() on su paths -> ENOENT. func#169 checks exactly 9 paths
       with access(); returning -1 defeats it without touching the function. */
    const SU_PATHS = ['/system/bin/su', '/system/xbin/su', '/sbin/su', '/su/bin/su',
                      '/data/local/su', '/data/local/bin/su', '/data/local/xbin/su',
                      '/system/app/Superuser.apk', '/system/bin/.ext/.su', 'su',
                      '/system/xbin/daemonsu', '/system/bin/busybox', '/magisk'];
    ['access', 'faccessat', 'stat', 'lstat', '__xstat', '__statx'].forEach(fn => {
        const p = Module.findExportByName('libc.so', fn);
        if (!p) return;
        Interceptor.attach(p, {
            onEnter(args) {
                const i = (fn === 'faccessat') ? 1 : 0;
                this.path = cstr(args[i], 256);
                this.su = this.path && SU_PATHS.some(s => this.path === s || this.path.indexOf(s) >= 0);
            },
            onLeave(retval) {
                if (this.su && retval.toInt32() === 0) {
                    retval.replace(ptr(-1));
                    LOG.det({ what: fn + '("' + this.path + '") forced to -1 (ENOENT)', ret: '-1' });
                }
            }
        });
    });

    /* clock()-based timing (func#98): only fake it when the caller is inside
       func#98, so we do not perturb the rest of the app. */
    const F98 = A(OFF.timing_check);
    ['clock', 'gettimeofday', 'clock_gettime'].forEach(fn => {
        const p = Module.findExportByName('libc.so', fn);
        if (!p) return;
        Interceptor.attach(p, {
            onEnter() {
                this.inF98 = false;
                try {
                    const lr = this.context.lr, pc = this.context.pc;
                    void pc;
                    const d = lr.sub(MOD.base);
                    this.inF98 = d.compare(ptr(OFF.timing_check)) >= 0 &&
                                 d.compare(ptr(OFF.timing_check + 1972)) < 0;
                    void F98;
                } catch (e) {}
            },
            onLeave(retval) {
                if (this.inF98) LOG.det({ what: fn + '() called from func#98 (timing check)',
                                          ret: retval.toString() + ' (NOT faked — see note)' });
            }
        });
    });
    LOG.note('timing: func#98 clock() calls are LOGGED, not faked. If the app rejects you ' +
             'with a timing error, replace the retval with a constant delta.');
}

function hookDetectionFunctions() {
    /* Read-only first: log entry + natural return value for every detection
       function. We deliberately do NOT guess polarity. */
    const D = [
        ['func#200 anti-hook /proc/self/maps scan', OFF.anti_hook_maps],
        ['func#99  anti-Frida (XOR-0x37 tokens)',   OFF.anti_frida],
        ['func#162 anti-Frida (base64 tokens)',     OFF.anti_frida_b64],
        ['func#225 maps integrity (rwxp/(deleted))',OFF.maps_integrity],
        ['func#169 root check (access() x9)',       OFF.root_check],
        ['func#98  clock() timing check',           OFF.timing_check],
        ['func#226 cert pin + APK signature check', OFF.cert_pin_sigcheck],
        ['func#224 (reachable `b .` trap @0x1576ac)', OFF.trap_func],
        ['func#252 sole caller of func#36',         OFF.fixedkey_caller],
        ['func#253 OkHttp CertificatePinner',       OFF.okhttp_pinner_a],
        ['func#254 OkHttp CertificatePinner',       OFF.okhttp_pinner_b]
    ];

    D.forEach(d => {
        const name = d[0], off = d[1];
        const forced = CONFIG.forceReturn[off];
        try {
            if (forced !== undefined && forced !== null && CONFIG.stubDetection &&
                (CONFIG.mode === 'bypass' || CONFIG.mode === 'all')) {
                /* Interceptor.replace on the ENTRY only. We replace the whole
                   function with a stub, so the flattened body — and therefore
                   every opaque predicate and every `b .` trap — never runs.
                   This is the ONLY safe way to neutralise these. */
                Interceptor.replace(A(off), new NativeCallback(function () {
                    LOG.det({ what: name + ' FORCED', ret: String(forced) });
                    return forced;
                }, 'int', ['pointer', 'pointer', 'pointer']));
                LOG.note('replaced ' + name + ' -> returns ' + forced);
            } else {
                Interceptor.attach(A(off), {
                    onEnter() { this.t = Date.now(); },
                    onLeave(retval) {
                        LOG.det({ what: name, ret: retval.toString(),
                                  ms: Date.now() - this.t, bt: shortBt(this.context) });
                    }
                });
                LOG.note('watching ' + name + ' (log-only; set forceReturn[0x' +
                         off.toString(16) + '] to override)');
            }
        } catch (e) { LOG.warn('detection hook ' + name + ': ' + e); }
    });
}

/* ===================================================================== *
 * 7. JAVA LAYER
 * ===================================================================== */

function hookJava() {
    if (!Java.available) { LOG.warn('Java.available == false; skipping Java hooks'); return; }
    Java.perform(() => {

        /* 7.1 the 22 natives, from the Java side. This is the highest-value
               hook in the whole script: it shows you the JsonObject / Response
               objects as real Java objects, not as native pointers. */
        try {
            const Q = Java.use(JNI_CLASS);
            JNI_EXPECT.forEach(e => {
                const nm = e[0], sg = e[1];
                try {
                    const params = parseSigParams(sg).map(jtypeToJava);
                    if (!Q[nm]) return;
                    const ov = Q[nm].overload.apply(Q[nm], params);
                    ov.implementation = function () {
                        const args = Array.prototype.slice.call(arguments).map(a => {
                            if (a === null || a === undefined) return null;
                            try { return a.toString(); } catch (e) { return '<' + typeof a + '>'; }
                        });
                        const r = ov.apply(this, arguments);
                        let rs = null;
                        try { rs = r === null ? null : r.toString(); } catch (e) {}
                        LOG.jni({ name: 'JAVA ' + JNI_CLASS + '.' + nm, sig: sg,
                                  args: args.map(a => trunc(a, 1024)),
                                  ret: trunc(rs, 4096),
                                  summary: nm + '(' + args.map(a => trunc(a, 40)).join(', ') + ')' });
                        return r;
                    };
                } catch (x) { /* overload not present on this build */ }
            });
            LOG.note('Java hooks installed on ' + JNI_CLASS);
        } catch (e) { LOG.warn('Java hook ' + JNI_CLASS + ': ' + e); }

        /* 7.2 OkHttp certificate pinning — the clean kill.
               func#226/#253/#254 build a CertificatePinner with
                 sha256://2EVZHghgM6kDX9a2bDw9c6ozr5B5TWuYbmR3nupr7F4=
               (the triple-base64 blob at .rodata 0x15084).
               Making Builder.add() a no-op means zero pins are ever registered,
               so CertificatePinner.check() trivially passes. No native patching,
               no risk of hitting a `b .` trap. */
        if (CONFIG.sslUnpin) {
            try {
                const CPB = Java.use('okhttp3.CertificatePinner$Builder');
                CPB.add.overload('java.lang.String', 'java.util.List').implementation = function (p, pins) {
                    LOG.det({ what: 'CertificatePinner.Builder.add SUPPRESSED', ret: 'no-op',
                              pattern: p, pins: pins ? pins.toString() : null });
                    return this;
                };
                try {
                    CPB.add.overload('java.lang.String', '[Ljava.lang.String;').implementation =
                        function (p, pins) {
                            LOG.det({ what: 'CertificatePinner.Builder.add SUPPRESSED', ret: 'no-op',
                                      pattern: p, pins: pins ? pins.toString() : null });
                            return this;
                        };
                } catch (e) {}
                LOG.note('okhttp3.CertificatePinner$Builder.add -> no-op');
            } catch (e) { LOG.warn('CertificatePinner hook: ' + e); }

            try {
                const CP = Java.use('okhttp3.CertificatePinner');
                CP.check.overloads.forEach(ov => {
                    ov.implementation = function () {
                        LOG.det({ what: 'CertificatePinner.check BYPASSED', ret: 'void' });
                    };
                });
                LOG.note('okhttp3.CertificatePinner.check -> no-op');
            } catch (e) {}

            /* 7.3 generic TrustManager / HostnameVerifier unpin, for anything
                   that does not go through okhttp3.CertificatePinner. */
            try {
                const X509 = Java.use('javax.net.ssl.X509TrustManager');
                const SSL = Java.use('javax.net.ssl.SSLContext');
                const TM = Java.registerClass({
                    name: 're.frida.TFTrustAll',
                    implements: [X509],
                    methods: {
                        checkClientTrusted: function () {},
                        checkServerTrusted: function () {},
                        getAcceptedIssuers: function () { return []; }
                    }
                });
                const HV = Java.use('javax.net.ssl.HostnameVerifier');
                const HVImpl = Java.registerClass({
                    name: 're.frida.TFVerifyAll', implements: [HV],
                    methods: { verify: function () { return true; } }
                });
                const ctx = SSL.getInstance('TLS');
                ctx.init(null, [TM.$new()], null);
                globalThis.TF_SSL_CTX = ctx;
                globalThis.TF_HV = HVImpl.$new();

                try {
                    const OB = Java.use('okhttp3.OkHttpClient$Builder');
                    const sslSocketFactory = OB.sslSocketFactory.overload(
                        'javax.net.ssl.SSLSocketFactory', 'javax.net.ssl.X509TrustManager');
                    sslSocketFactory.implementation = function () {
                        LOG.det({ what: 'OkHttpClient.Builder.sslSocketFactory replaced', ret: 'trust-all' });
                        return sslSocketFactory.call(this, ctx.getSocketFactory(), TM.$new());
                    };
                    OB.hostnameVerifier.implementation = function () {
                        LOG.det({ what: 'OkHttpClient.Builder.hostnameVerifier replaced', ret: 'always-true' });
                        return OB.hostnameVerifier.call(this, globalThis.TF_HV);
                    };
                    LOG.note('OkHttpClient trust-all + hostname-verifier installed');
                } catch (e) { LOG.warn('OkHttpClient.Builder hook: ' + e); }
            } catch (e) { LOG.warn('TrustManager setup: ' + e); }
        }

        /* 7.4 APK signature pin — THE reason a repackaged build needs an agent.
               func#226 / func#73 hash Signature.toByteArray() and compare with
               the blob at 0x15084 (see §APK SIGNATURE PIN above). We do not
               touch the native functions (they are control-flow flattened and
               booby-trapped); we fix the INPUT they read, on the Java side, so
               the native SHA-256 lands on the pinned value by itself. */
        try {
            const GET_SIGNATURES   = 0x00000040;
            const GET_SIGNING_CERTIFICATES = 0x08000000;   // API 28+
            const origCertBytes = b64ToJavaBytes(ORIGINAL_SIGNER_CERT_B64);
            let forged = 0;

            const buildSigArray = () => {
                const Sig = Java.use('android.content.pm.Signature');
                const one = Sig.$new(origCertBytes);
                const arr = Java.array('android.content.pm.Signature', [one]);
                return arr;
            };

            const patchPackageInfo = (pi, flags, who) => {
                if (!pi) return pi;
                let did = false;
                if (CONFIG.spoofSignature && (flags & GET_SIGNATURES)) {
                    pi.signatures.value = buildSigArray();
                    did = true;
                }
                if (CONFIG.spoofSignature && (flags & GET_SIGNING_CERTIFICATES)) {
                    /* API 28+: SigningInfo.getApkContentsSigners() */
                    try {
                        const SI = Java.use('android.content.pm.SigningInfo');
                        const fake = SI.$new(buildSigArray());
                        pi.signingInfo.value = fake;
                        did = true;
                    } catch (e) { /* SigningInfo has no such ctor on this API level */ }
                }
                if (did) {
                    forged++;
                    LOG.det({ what: who + ' -> signatures FORGED with the original cert',
                              flags: '0x' + (flags >>> 0).toString(16),
                              pinned: SIGNATURE_PIN_SHA256.slice(0, 16) + '…',
                              n: forged });
                } else {
                    LOG.det({ what: who, flags: '0x' + (flags >>> 0).toString(16),
                              note: 'no signature requested, passed through' });
                }
                return pi;
            };

            const hookPM = (cls, method) => {
                const C = Java.use(cls);
                C[method].overloads.forEach(ov => {
                    ov.implementation = function () {
                        const r = ov.apply(this, arguments);
                        /* every overload is (String pkg, int flags[, int userId]) */
                        const flags = arguments.length > 1 ? (arguments[1] | 0) : 0;
                        return patchPackageInfo(r, flags, cls + '.' + method);
                    };
                });
                return C[method].overloads.length;
            };

            let n = 0;
            /* the concrete impl used by every Context on a real device */
            try { n += hookPM('android.app.ApplicationPackageManager', 'getPackageInfo'); } catch (e) {}
            /* and the abstract/interface entry points, in case native code
               resolves the method on the interface instead of the impl */
            try { n += hookPM('android.content.pm.PackageManager', 'getPackageInfo'); } catch (e) {}
            try { n += hookPM('android.app.ApplicationPackageManager', 'getPackageInfoAsUser'); } catch (e) {}

            /* Last line of defence: whatever Signature object reaches native
               code, hand back the original bytes. */
            try {
                const Sig = Java.use('android.content.pm.Signature');
                Sig.toByteArray.implementation = function () {
                    const real = Sig.toByteArray.call(this);
                    if (CONFIG.spoofSignature) {
                        LOG.det({ what: 'Signature.toByteArray() -> original cert DER',
                                  realLen: real.length, forgedLen: origCertBytes.length });
                        return origCertBytes;
                    }
                    return real;
                };
                n++;
            } catch (e) {}

            /* And if the app hashes it itself in Java rather than in native code */
            try {
                const MD = Java.use('java.security.MessageDigest');
                MD.digest.overload('[B').implementation = function (input) {
                    const out = MD.digest.overload('[B').call(this, input);
                    try {
                        if (input && input.length === origCertBytes.length &&
                            String(this.getAlgorithm()).toUpperCase().indexOf('SHA-256') === 0) {
                            LOG.det({ what: 'Java SHA-256 over a ' + input.length +
                                            '-byte cert, digest = ' + hexOfJavaBytes(out) });
                        }
                    } catch (e) {}
                    return out;
                };
            } catch (e) {}

            LOG.note('signature pin: ' + n + ' PackageManager/Signature hooks armed' +
                     (CONFIG.spoofSignature ? ' (forging ON)' : ' (WATCH ONLY — spoofSignature=false)'));
        } catch (e) { LOG.warn('signature-pin hook: ' + e); }

        /* 7.5 find out who loads the library (useful for gadget placement) */
        try {
            const RT = Java.use('java.lang.Runtime');
            RT.loadLibrary0.overloads.forEach(ov => {
                ov.implementation = function () {
                    const lib = arguments.length > 1 ? arguments[1] : arguments[0];
                    LOG.note('Runtime.loadLibrary0 -> ' + lib + '  caller=' +
                             (this.getClass ? this.getClass().getName() : '?'));
                    return ov.apply(this, arguments);
                };
            });
        } catch (e) {}
        try {
            const SYS = Java.use('java.lang.System');
            SYS.loadLibrary.implementation = function (name) {
                LOG.note('System.loadLibrary("' + name + '")');
                const r = SYS.loadLibrary(name);
                if (String(name).indexOf('topfollow') >= 0) {
                    const m = findModule();
                    if (m && !MOD) { MOD = m; LOG.note(MODULE + ' now mapped @ ' + m.base); }
                }
                return r;
            };
        } catch (e) {}
    });
}

function jtypeToJava(t) {
    switch (t) {
        case 'Z': return 'boolean'; case 'B': return 'byte';  case 'C': return 'char';
        case 'S': return 'short';   case 'I': return 'int';   case 'J': return 'long';
        case 'F': return 'float';   case 'D': return 'double';
        default:  return t.replace(/^\//, '').replace(/^L/, '').replace(/;$/, '').replace(/\//g, '.');
    }
}

/* ===================================================================== *
 * 8. RPC EXPORTS
 * ===================================================================== */

rpc.exports = {
    config:  () => CONFIG,
    module:  () => MOD ? { name: MOD.name, base: MOD.base.toString(), size: MOD.size, path: MOD.path } : null,
    secrets: () => LOG.store.secrets,
    keys:    () => LOG.store.keys,
    crypto:  () => LOG.store.crypto,
    jni:     () => LOG.store.jni,
    detect:  () => LOG.store.detection,
    notes:   () => LOG.store.notes,
    clear:   () => { Object.keys(LOG.store).forEach(k => LOG.store[k] = []); return 'cleared'; },
    selfCalibrate: () => selfCalibrate(),
    selfTest:      () => selfTest(),

    /* Offline decryption of anything you captured.
       decrypt(hexstring)            -> tries func#30 zero-key CBC, then ECB
                                        with every known hardcoded key
       decrypt(hexstring, keyAscii)  -> ECB and CBC with the given key */
    decrypt(hexstr, keyAscii, verbose) {
        const ct = AES.fromHex(hexstr);
        const out = [];
        const z16 = new Array(16).fill(0);
        const safe = (cipher, keyName, fn) => {
            try { fn(); }
            catch (e) { out.push({ cipher: cipher, key: keyName, error: String(e) }); }
        };
        // func#30: AES-128-CBC, zero key, zero iv  (§11.3 — the app's own wire cipher)
        safe('func#30 AES-128-CBC key=0 iv=0', 'AES-128 zero key', () => {
            const r = AES.unpad(AES.cbcDec(ct, z16, z16));
            out.push({ cipher: 'func#30 AES-128-CBC key=0 iv=0', key: 'AES-128 zero key',
                       paddingOk: !r.bad, text: utf8OrHex(r.data) });
        });
        // func#85 / func#94: AES-ECB-PKCS7 with every hardcoded key we know (§11.2)
        const keys = keyAscii ? [{ name: 'user-supplied', raw: Array.from(new TextEncoder().encode(keyAscii)) }]
                              : KNOWN_KEYS;
        keys.forEach(k => {
            if (!k.raw || !k.raw.length) return;
            /* Build the candidate key list for this entry. A 16/24/32-byte value
               is used verbatim — that is the verified func#85 behaviour. The
               12-byte getter values (#86/#159/#160/#161) are NOT valid AES key
               lengths, so for those we also try the obvious derivations, each
               one flagged guessed:true so a hit is never mistaken for a
               verified result. */
            const cands = [];
            const raw = Array.from(k.raw);
            if (raw.length === 16 || raw.length === 24 || raw.length === 32) {
                cands.push({ tag: '', bytes: raw });
            } else {
                const pad = raw.concat(new Array(16 - raw.length).fill(0));
                cands.push({ tag: ' [guess: zero-padded to 16B]', bytes: pad, guessed: true });
                const rep = []; for (let i = 0; i < 16; i++) rep.push(raw[i % raw.length]);
                cands.push({ tag: ' [guess: repeated to 16B]', bytes: rep, guessed: true });
                if (k.b64) {
                    const asc = Array.from(new TextEncoder().encode(String(k.b64)));
                    cands.push({ tag: ' [guess: base64 text as key]', bytes: asc.slice(0, 16), guessed: true });
                }
            }
            cands.forEach(cand => {
                const kname = k.name + cand.tag;
                safe('func#85 AES-ECB PKCS7', kname, () => {
                    const r = AES.unpad(AES.ecbDec(ct, cand.bytes));
                    out.push({ cipher: 'func#85 AES-ECB PKCS7', key: kname, keyHex: AES.toHex(cand.bytes),
                               keyLen: cand.bytes.length, guessed: !!cand.guessed,
                               paddingOk: !r.bad, text: utf8OrHex(r.data) });
                });
                safe('AES-128-CBC iv=0 (guess)', kname, () => {
                    const r2 = AES.unpad(AES.cbcDec(ct, cand.bytes.slice(0, 16), z16));
                    out.push({ cipher: 'AES-128-CBC iv=0 (guess)', key: kname, guessed: true,
                               paddingOk: !r2.bad, text: utf8OrHex(r2.data) });
                });
            });
        });
        /* By default only the plausible hits are returned (PKCS#7 padding
           validated AND the result looks like text). verbose=true gives you
           every candidate plus any internal error, for debugging. */
        return verbose ? out : out.filter(o => o.paddingOk === true && o.text !== null);
    },

    /* decode any XOR-0x5A blob you find in .rodata, live from the device */
    xorDecode(off, len, key) {
        const k = key === undefined ? 0x5a : key;
        const b = Array.from(new Uint8Array(A(off).readByteArray(len)));
        const d = xorBytes(b, k);
        return { off: '0x' + off.toString(16), len: len, key: '0x' + k.toString(16),
                 ascii: toStr(d), hex: AES.toHex(d),
                 base64: (toStr(d) && /^[A-Za-z0-9+/=]+$/.test(toStr(d)))
                         ? AES.toHex(b64decode(toStr(d))) : null };
    },

    /* the known-answer vectors from §11, recomputed locally */
    vectors() {
        const enc = s => Array.from(new TextEncoder().encode(s));
        return {
            'func#85("hello","0123456789abcdef")':
                AES.toHex(AES.ecbEnc(enc('hello'), enc('0123456789abcdef'))),
            'func#30("hello")': AES.toHex(AES.zeroCbcEnc(enc('hello'))),
            'func#30("")':      AES.toHex(AES.zeroCbcEnc([])),
            'func#30("A"*16)':  AES.toHex(AES.zeroCbcEnc(enc('AAAAAAAAAAAAAAAA'))),
            'ecb pad constant': AES.toHex(AES.ecbEnc(new Array(16).fill(0x10), enc('0123456789abcdef'))).slice(-32)
        };
    },

    knownKeys: () => KNOWN_KEYS.map(k => ({ name: k.name, b64: k.b64, hex: AES.toHex(k.raw || []) })),

    /* Everything about the APK-signature pin (§6.5), including the live value
       of the blob at 0x15084 so you can see the pin is what we say it is. */
    signature() {
        const out = {
            pinnedSha256: SIGNATURE_PIN_SHA256,
            blobOffset: '0x' + SIGNATURE_PIN_BLOB_OFF.toString(16),
            spoofing: !!CONFIG.spoofSignature,
            originalCertLen: b64decode(ORIGINAL_SIGNER_CERT_B64).length,
            originalCertSha256: null,
            liveBlob: null,
            liveDecoded: null
        };
        /* SHA-256 of the embedded cert, computed in JS so you can see the
           match without trusting the comment above. */
        out.originalCertSha256 = sha256Hex(b64decode(ORIGINAL_SIGNER_CERT_B64));
        if (MOD) {
            try {
                out.liveBlob = cstr(A(SIGNATURE_PIN_BLOB_OFF), 256);
                let d = out.liveBlob;
                for (let i = 0; i < 2; i++) d = toStr(b64decode(d)) || d;
                out.liveDecoded = d;
                out.liveMatchesPin = (d === SIGNATURE_PIN_SHA256);
            } catch (e) { out.liveBlob = '<' + e + '>'; }
        }
        return out;
    },

    /* dump a region of the loaded module */
    read(off, len) { return hex(A(off), len); }
};

/* Publish the pieces that rpc handlers need as true globals. Top-level `const`
   bindings live in the script scope, which is fine inside the script, but this
   costs nothing and removes a whole class of "x is not defined" surprises when
   Frida calls an export. */
try {
    (function (g) {
        if (!g) return;
        g.TOPFOLLOW = { AES: AES, OFF: OFF, KNOWN_KEYS: KNOWN_KEYS, JNI_EXPECT: JNI_EXPECT,
                        CONFIG: CONFIG, b64decode: b64decode, b64encode: b64encode,
                        xorBytes: xorBytes, toStr: toStr, utf8OrHex: utf8OrHex,
                        readStdString: readStdString, selfTest: selfTest,
                        selfCalibrate: selfCalibrate };
    })(typeof globalThis !== 'undefined' ? globalThis : null);
} catch (e) {}

function utf8OrHex(bytes) {
    const s = toStr(bytes);
    if (s !== null) return s;
    try { return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes)); }
    catch (e) { return AES.toHex(bytes); }
}

/* ===================================================================== *
 * 9. BOOTSTRAP
 * ===================================================================== */

function installEarlyHooks() {
    /* These do not depend on libtopfollow.so being mapped, so arm them now:
       they are what stops the app from noticing us before the library loads. */
    if (CONFIG.filterMaps && (CONFIG.mode === 'bypass' || CONFIG.mode === 'all')) {
        try { hookMapsFiltering(); } catch (e) { LOG.warn('maps filtering: ' + e); }
    }
    if (CONFIG.hookJava) {
        try { hookJava(); } catch (e) { LOG.warn('java hooks: ' + e); }
    }
}

function installModuleHooks() {
    const ok = sanityCheck();

    if (CONFIG.selfCalibrate) {
        try { selfCalibrate(); } catch (e) { LOG.warn('selfCalibrate: ' + e); }
    }

    if (CONFIG.mode === 'recon') {
        LOG.note('mode=recon — installing READ-ONLY hooks (nothing is patched or forced)');
    }

    if (CONFIG.hookDetection && (CONFIG.mode === 'bypass' || CONFIG.mode === 'all' || CONFIG.mode === 'recon')) {
        try { hookDetectionFunctions(); } catch (e) { LOG.warn('detection hooks: ' + e); }
    }

    if (CONFIG.mode !== 'bypass') {
        try { hookCrypto(); } catch (e) { LOG.warn('crypto hooks: ' + e); }
    } else {
        try { hookCrypto(); } catch (e) { LOG.warn('crypto hooks: ' + e); }
    }

    /* RegisterNatives has almost certainly already run by the time the module
       is visible, so hook the static table directly and ALSO arm the
       RegisterNatives hook for the next process start. */
    hookJniFromStaticTable();
    try { hookRegisterNatives(); } catch (e) {}

    if (CONFIG.selfTest) { try { selfTest(); } catch (e) { LOG.warn('selfTest: ' + e); } }

    LOG.note('=== ready. mode=' + CONFIG.mode + ' anchors=' + (ok ? 'OK' : 'FAILED') + ' ===');
    LOG.note('tip: rpc.exports.crypto() / .secrets() / .keys() / .jni() to pull everything so far');
}

LOG.tag('BOOT', 'topfollow_agent.js starting', { mode: CONFIG.mode, pid: Process.id,
      arch: Process.arch, platform: Process.platform,
      frida: Frida.version, pageSize: Process.pageSize,
      pointerSize: Process.pointerSize });
LOG.note('hard rule active: entry-only Interceptor.attach on flattened functions; ' +
         'never patch inside a function body (712 `b .` traps, 148 reachable)');

/* Set TOPFOLLOW_NO_AUTOBOOT=1 (e.g. from a test harness that loads this file
   into a VM) to define everything without arming any hook. */
if (typeof TOPFOLLOW_NO_AUTOBOOT === 'undefined' || !TOPFOLLOW_NO_AUTOBOOT) {
    installEarlyHooks();
    waitForModule(installModuleHooks);
}
