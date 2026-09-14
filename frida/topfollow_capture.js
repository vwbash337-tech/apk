/* ===================================================================== *
 * topfollow_capture.js  —  DATA CAPTURE ONLY
 * ---------------------------------------------------------------------
 * Target : com.nivaroid.topfollow 8.4.5 (845)
 *          lib/arm64-v8a/libtopfollow.so  (1,805,400 B, AArch64, NDK r23c)
 *
 * This script CAPTURES. It does not bypass, does not spoof, does not hide
 * anything, and does not patch a single byte of the target library.
 *
 *   READ-ONLY RULES (these are load-bearing, not stylistic)
 *   -------------------------------------------------------
 *   1. Interceptor.attach ONLY. Interceptor.replace is never called, and
 *      retval.replace() is never called anywhere in this file, except inside
 *      the marked BYPASS-ONLY regions, all of which are dead code unless you
 *      set CFG.bypass.enabled (see §7B and the bypass block in DEFAULT_CFG).
 *      Every mutation in this file sits inside a region delimited by the
 *      paired five-angle-bracket BYPASS-ONLY markers (see section 7B), which
 *      is what lets the offline test PROVE the default is read-only instead of
 *      merely claiming it: frida/test_capture_offline.js strips every marked
 *      region, then asserts that nothing outside them ever writes.
 *   2. Every hook only READS arguments in onEnter and READS results in
 *      onLeave. Nothing is written into the target's memory, registers or
 *      return values, so the app behaves exactly as it would unhooked.
 *   3. libtopfollow.so is control-flow flattened and contains 712 `b .`
 *      infinite-loop instructions, 148 of them reachable (§3.8 of the
 *      report). func#224 @0x157628 has one at 0x1576ac. It is NOT hooked
 *      here at all — not even entry-only.
 *   4. Detection functions are hooked entry-only and their return value is
 *      RECORDED, never altered. You want to know what the app concluded,
 *      not change its mind. (To change its mind, use topfollow_agent.js.)
 *
 *   WHY CAPTURE-FIRST
 *   -----------------
 *   The three secrets this app protects traffic with are all static
 *   (§0 of the report): a literal `0123456789abcdef` AES key, an all-zero
 *   AES-128-CBC key + IV inside func#30, and a Base64 AES-192 key + two
 *   12-byte GCM nonces behind one XOR byte. So one clean capture run gives
 *   you every plaintext, every key and every request/response pair without
 *   ever needing to defeat the signature check or the pinning — and without
 *   risking the anti-tamper traps telling the server you are there.
 *
 *   OUTPUT
 *   ------
 *   Every event is a single JSON line, appended synchronously to
 *       /data/local/tmp/topfollow_capture.jsonl
 *   (override with TF_CAPTURE_PATH or cfg.path) and mirrored to the console
 *   only if cfg.console is on. A synchronous POSIX write() per event means a
 *   dropped USB link, a detached session or a crash loses nothing already
 *   captured. Everything also lands in an in-memory ring so rpc.exports can
 *   query it.
 *
 *   RUN IT
 *   ------
 *   Gadget (non-rooted, repacked APK — see frida/README_frida_gadget.md):
 *       adb forward tcp:27042 tcp:27042
 *       frida -H 127.0.0.1:27042 Gadget -l frida/topfollow_capture.js
 *   Rooted phone with frida-server:
 *       frida -U -f com.nivaroid.topfollow -l frida/topfollow_capture.js
 *   Through the bundled runner (adds a REPL over the rpc exports):
 *       python frida/run_frida.py --script frida/topfollow_capture.js
 *
 *   In the REPL:
 *       cfg()                      what is on, where the file is
 *       stats()                    event counts per kind
 *       keys()                     every AES key observed, deduplicated
 *       events('crypto', 40)       last 40 crypto events
 *       find('order_id')           grep the whole capture
 *       tail(20)                   last 20 events of any kind
 *       flush()                    force the ring out to the JSONL file
 * ===================================================================== */
'use strict';

/* ===================================================================== *
 * 0. CONFIGURATION
 * ===================================================================== */

const DEFAULT_CFG = {
    /* where the JSONL goes. The app cannot usually write /data/local/tmp, so
       the default is the app's own external files dir, resolved at runtime;
       this value is the fallback and the root-friendly choice. */
    path: '/data/local/tmp/topfollow_capture.jsonl',
    pathFallbacks: ['/data/local/tmp/topfollow_capture.jsonl',
                    '/sdcard/Android/data/com.nivaroid.topfollow/files/topfollow_capture.jsonl',
                    '/data/data/com.nivaroid.topfollow/files/topfollow_capture.jsonl'],

    maxDump: 16384,        /* per-field cap for captured buffers            */
    maxBodyDump: 262144,   /* per-field cap for HTTP bodies                 */
    ringSize: 20000,       /* in-memory events kept for rpc.exports         */
    console: false,        /* mirror events to send()/console — noisy       */
    consoleKinds: ['crypto', 'key', 'net', 'warn'],

    /* capture layers — turn OFF only if a layer misbehaves on your build */
    captureCrypto: true,   /* func#85/#94/#30/#36/#14/#193 + getters + GCM  */
    captureAesLayer: false,/* func#15/#16/#12/#13/#10/#11 — the CBC + ECB
                              block primitives UNDER the public ciphers.
                              Off by default: #12 and #13 fire once per 16-byte
                              block, so a 16 KB payload produces 1,000 events.
                              Turn on when you need per-block IV chaining.     */
    captureStrings: true,  /* func#17/#21/#23 — the Base64 string layer.
                              Every detection token and every endpoint is
                              fetched through here, so this is where the
                              runtime string picture comes from.              */
    captureJniOnload: true,/* the three JNI calls inside JNI_OnLoad, incl. the
                              live RegisterNatives table as the VM sees it     */
    captureJni:    true,   /* all 22 natives, native side AND Java side     */
    captureNet:    true,   /* okhttp3 Request/Response/Headers, retrofit2   */
    captureJson:   true,   /* Gson toJson / fromJson                        */
    captureDigest: true,   /* MessageDigest, Mac, Cipher, Base64            */
    captureDetect: true,   /* scanners + maps readers: entry/exit + retval  */
    captureFile:   true,   /* __open_2/open/read/access — LOG ONLY          */
    capturePkg:    true,   /* getPackageInfo / Signature / SigningInfo      */
    capturePrefs:  false,  /* SharedPreferences writes (noisy, off by default) */
    captureExec:   true,   /* Runtime.exec / ProcessBuilder                 */

    /* func#224 @0x157628 is EXCLUDED ON PURPOSE (reachable `b .` @0x1576ac).
       Set this to true only if you have read §3.8 and accept a hung thread. */
    hookTrapFunc224: false,

    /* ------------------------------------------------------------------ *
     * BYPASS MODE — OFF BY DEFAULT, and that default is the whole point.
     *
     * With this off the script is strictly read-only: it attaches, records
     * and never writes to the app or to libc. That is what makes the capture
     * trustworthy as evidence.
     *
     * But a read-only script on a defended device gets you exactly nothing:
     * the repacked APK fails func#226/#73's SHA-256(signer cert) pin, and
     * func#99/#162/#200/#225/#60/#169 see Frida, the maps lines and root.
     * The app refuses to run, so there is no traffic to capture. Set
     *     --set bypass='{"enabled":true}'        (run_frida.py --script capture)
     * or edit the literal below, and every mutation in this file switches on.
     * All of it lives between the BEGIN/END BYPASS MODE markers so the
     * offline test can strip it and still PROVE the default is read-only.
     * ------------------------------------------------------------------ */
    bypass: {
        enabled: false,
        /* Interceptor.replace on the ENTRY only, so the flattened body — and
           every opaque predicate and `b .` trap inside it — never executes.
           That is the only safe way to touch these (report §8, step 3).
           Polarity was measured, not guessed: 0 = "nothing found". */
        forceReturn: {
            0x081c58: 0,     /* func#60  Xposed/Riru/Substrate scanner (179,828 B) */
            0x115770: 0,     /* func#99  anti-Frida (XOR-0x37 tokens)              */
            0x136cb8: 0,     /* func#162 anti-Frida (Base64 tokens)                */
            0x145f88: 0,     /* func#200 anti-hook /proc/self/maps scan            */
            0x157f38: 0,     /* func#225 maps integrity (rwxp / "(deleted)")       */
            0x13ba30: 0,     /* func#169 root check (access() x9 su paths)         */
            0x12a068: 0      /* func#154 root-check parent (reached from slot 6)   */
            /* NOT stubbed, on purpose:
               0x157628 func#224 — reachable `b .` trap @0x1576ac (§3.8)
               0x114fbc func#98  — clock() timing, polarity unproven
               0x159c10 func#226 / 0x103ad8 func#73 — the signature pin is beaten
                        on the JAVA side instead (spoofSignature), which needs no
                        patch and cannot desync the native compare (§6.5)
               0x172460/0x173c40 #253/#254 — TLS pinning; that blocks a MITM proxy,
                        not app startup, so it stays out of the default set      */
        },
        spoofSignature: true,   /* hand the ORIGINAL signer cert back out of
                                   PackageManager.getPackageInfo — the repacked
                                   APK then passes func#226/#73 with no native
                                   patch at all (§6.5, §10 item 31)            */
        hideMaps: true,         /* length-preserving rewrite of the read() buffer,
                                   which is how this library actually reads maps
                                   (§10 item 39: no fopen/fgets/strstr imported) */
        hideSuPaths: true,      /* access()/stat() on su paths -> -1 (ENOENT)    */
        fakeClock: false        /* func#98 clock() delta — unproven, off by default */
    }
};

/* Two override names are honoured: TF_CAPTURE_CFG (what `frida -e` / a loader
   preamble sets for this script specifically) and TF_CONFIG (what the bundled
   runner frida/run_frida.py injects for BOTH scripts, via --mode / --set). */
const _TF_CFG_OVERRIDE =
    (typeof TF_CAPTURE_CFG !== 'undefined' && TF_CAPTURE_CFG) ||
    (typeof globalThis !== 'undefined' && globalThis.TF_CAPTURE_CFG) ||
    (typeof globalThis !== 'undefined' && globalThis.TF_CONFIG) ||
    null;
const CFG = Object.assign({}, DEFAULT_CFG, _TF_CFG_OVERRIDE || {});

const MODULE     = 'libtopfollow.so';
const JNI_CLASS  = 'helper.q';
const PKG        = 'com.nivaroid.topfollow';

/* ===================================================================== *
 * 1. OFFSETS
 *    File offsets == RVAs for this library (the RX segment has
 *    p_vaddr = 0 and p_offset = 0), so A(off) = MOD.base + off.
 *    Every value here is byte-verified in REPORT_libtopfollow_so.md §9
 *    and re-checked at runtime by calibrate().
 * ===================================================================== */

const OFF = {
    /* --- ciphers (all control-flow flattened: attach, never replace) --- */
    ecb_enc_hex    : 0x10c470,  /* func#85   AES-ECB   enc -> lowercase hex  */
    ecb_dec_hex    : 0x110b70,  /* func#94   exact inverse of #85            */
    cbc0_enc_hex   : 0x038fa4,  /* func#30   AES-128-CBC key=0 iv=0 -> hex   */
    aes256_dec_hex : 0x03a838,  /* func#36   hex in -> AES-256-ECB dec+unpad */
    rijndael_setup : 0x032158,  /* func#14   x0=skey x1=userkey x3=keylen    */
    xor5a_decode   : 0x14193c,  /* func#193  x0=src x1=len x8=sret           */

    /* --- key / nonce getters: argument-independent, return 16-char B64 --- */
    getter_86      : 0x10de0c,  /* -> "5VEJK9Uk4d0elpVT"  (12 B decoded)     */
    getter_87      : 0x10df84,  /* needs a live JNIEnv                       */
    getter_159     : 0x134d40,  /* -> "OVmx02wMFR6WaGtW"                     */
    getter_160     : 0x13571c,  /* -> "V0V4V2pOa1ptZGsl"                     */
    getter_161     : 0x136134,  /* -> "xV2xKTlZsBUVk1He"                     */

    /* --- GCM contexts (native; the .so imports no javax.crypto at all) --- */
    gcm_ctx_157    : 0x131d58,  /* key @0x17428, nonce1 @0x17448             */
    gcm_ctx_158    : 0x133970,  /* nonce2 @0x17458                           */
    gcm_core       : 0x13ffb4,  /* func#191 — references NO AES table        */
    /* func#172 was reported in revision 4 as "the GF(2^128) core loading the
       S-box through GOT 0x1bb638/0x1bb640". That is WRONG and withdrawn: those
       two GOT slots are R_AARCH64_RELATIVE with addends 0x1c28a0 / 0x1c2d2c,
       which are in .bss — they are control-flow-flattening state globals, and
       func#172's 149 instructions are one MBA tautology ((v+~k+k)*v == v*v and
       w < 10). It is NOT hooked here: attaching a 596-byte pure-predicate leaf
       that both func#191 and func#241 call would only add noise. */
    opaque_172     : 0x13c488,  /* func#172 — opaque predicate, NOT crypto   */

    /* --- the AES layer UNDER the four public ciphers (report §11.13).
           Exactly five functions in the whole library reference the Rijndael
           tables; these are the block primitives and the CBC mode layer. --- */
    cbc_encrypt    : 0x034424,  /* func#15 (cbc*, pt, ct, len, idx) <- #30 #85 */
    cbc_decrypt    : 0x035518,  /* func#16 (cbc*, ct, pt, len, idx) <- #36 #94 */
    ecb_enc_block  : 0x02fdcc,  /* func#12 dispatcher   <- #15, #16          */
    ecb_enc_leaf   : 0x02dc00,  /* func#10 Nr-specific  <- #12               */
    ecb_dec_block  : 0x030f18,  /* func#13 dispatcher   <- #16               */
    ecb_dec_leaf   : 0x02eb94,  /* func#11 Nr-specific  <- #13               */

    /* --- the string layer: how every secret is fetched at runtime -------- */
    str_from_cstr  : 0x035d58,  /* func#17  std::string(const char*), 188 sites */
    str_empty      : 0x03820c,  /* func#23  empty std::string, 371 sites        */
    b64_decode_21  : 0x03712c,  /* func#21  Base64 -> std::string, 43 sites,
                                    13 callers incl. #162 and #245 (the pin)   */

    /* --- hashes --- */
    sha1_round     : 0x000000,  /* func#201 — filled by calibrate() if found */
    sha256_compress: 0x1509cc,  /* func#212                                  */
    sha256_pipeline: 0x148bf4,  /* func#204                                  */

    /* --- signature / pin path --- */
    sig_check_226  : 0x159c10,  /* getPackageInfo + SHA-256(cert) + pin      */
    sig_check_73   : 0x103ad8,  /* same job, reached from slots 5 and 6      */
    pin_blob_245   : 0x16bbdc,  /* sole referrer of .rodata 0x15084          */
    maps_225       : 0x157f38,  /* rwxp / libart.so (deleted) / libc.so      */
    memcmp_75      : 0x1086b8,  /* <- #51 #57 #67 #221 #226                  */

    /* --- detection: WATCH ONLY, return value recorded, never changed --- */
    scanner_60     : 0x081c58,  /* 179,828 B Xposed/Riru/Substrate scanner   */
    scanner_99     : 0x115770,  /* anti-Frida, XOR-0x37 tokens               */
    scanner_162    : 0x136cb8,  /* anti-Frida, Base64 tokens                 */
    scanner_200    : 0x145f88,  /* anti-hook scan                            */
    root_169       : 0x13ba30,  /* access() x9 su paths                      */
    root_154       : 0x12a068,  /* <- func#57 only                           */
    timing_98      : 0x114fbc,  /* clock()                                   */

    /* --- the maps READERS. The library imports no fopen/fgets/strstr;
           these three are how it reads /proc/self/maps (§10 item 39). --- */
    reader_129     : 0x11deb0,  /* <- func#99, func#225                      */
    reader_198     : 0x143694,  /* <- func#162, func#200                     */
    reader_213     : 0x151e68,  /* <- func#60                                */

    /* --- network builders --- */
    pinner_253     : 0x172460,  /* okhttp3 CertificatePinner$Builder         */
    retrofit_254   : 0x173c40,  /* retrofit2 Retrofit$Builder baseUrl/client */
    fixedkey_252   : 0x171884,  /* sole caller of func#36                    */

    /* --- JNI glue --- */
    jni_onload     : 0x03e1d4,  /* func#50, 2,272 B, the library's ONLY export */
    /* JNI_OnLoad does exactly three JNI calls:
         0x3e308  (*vm)->GetEnv(vm, &env, 0x10006)          index 0x30/8   = 6
         0x3e860  (*env)->FindClass(env, "com/nivaroid/topfollow/helper/q")
                                                            index 0x30/8   = 6
                                                            class name @0x14da2
         0x3e93c  (*env)->RegisterNatives(env, cls, 0x1b6198, 22)
                                                            index 0x6b8/8  = 215
       (a CFF duplicate of the RegisterNatives block sits at 0x3e988)
       and then returns 0x10006. No dynamic Java_... lookup exists. */
    jni_reg1       : 0x03e93c,  /* blr RegisterNatives — primary site        */
    jni_reg2       : 0x03e988,  /* blr RegisterNatives — CFF duplicate site  */
    jni_findclass  : 0x03e860,  /* blr FindClass                             */
    jni_getenv     : 0x03e308,  /* blr GetEnv                                */
    jni_class_name : 0x014da2,  /* "com/nivaroid/topfollow/helper/q"         */
    jni_table_va   : 0x1b6198,  /* static JNINativeMethod[22] in .data.rel.ro.
                                   ZERO in the file; filled by 66
                                   R_AARCH64_RELATIVE relocations at load, so
                                   it is only readable from the LIVE image.
                                   NOTE .data.rel.ro file offset = VA - 0x4000 */
    jni_entries    : 22,

    /* --- .rodata anchors, used by calibrate() to prove the mapping.
           .rodata STARTS with the AES tables: 0x118b0..0x13c10 is one
           contiguous 8,960-byte LibTomCrypt table block (§11.13a). --- */
    ro_te0         : 0x118b0,   /* 1024 B, first word 0xc66363a5             */
    ro_te1         : 0x11cb0,   /* Te0 rotated right 1 byte                  */
    ro_te2         : 0x120b0,   /* Te0 rotated right 2 bytes                 */
    ro_te3         : 0x124b0,   /* Te0 rotated right 3 bytes                 */
    ro_sbox        : 0x128b0,   /* FIPS-197 S-box, 637c777bf26b6fc5...       */
    ro_td0         : 0x129b0,   /* 1024 B, first word 0x51f4a750             */
    ro_td1         : 0x12db0,
    ro_td2         : 0x131b0,
    ro_td3         : 0x135b0,
    ro_rsbox       : 0x139b0,   /* inverse S-box, 52096ad53036a538...        */
    ro_rcon        : 0x13b10,   /* LibTomCrypt EXTENDED Rcon, 256 entries:
                                   powers of 3 in GF(2^8). OpenSSL ships 10  */
    ro_aes_name    : 0x14b31,   /* "AES" — the ONLY occurrence of the cipher's
                                   name in .rodata (no "rijndael", no "aes") */
    ro_plainkey    : 0x161ca,   /* literal "0123456789abcdef"                */
    ro_pinblob     : 0x15084,   /* 120-char plaintext double-Base64 pin      */
    ro_keyblob     : 0x17428,   /* XOR-0x5A, 64 B: key + nonce1 + nonce2     */

    /* --- deliberately NOT hooked anywhere in this file --- */
    trap_224       : 0x157628   /* reachable `b .` at 0x1576ac — see header  */
};

/* The 22 RegisterNatives entries, in slot order, as re-derived from the
   R_AARCH64_RELATIVE relocations at 0x1b6198 (report §2.2, §10 item 29).
   [slot, javaName, jniSignature, fnPtrOffset, funcNo, whatItReaches] */
/* The 22 RegisterNatives entries, recovered from the LIVE image and cross-checked
   three ways: the relocated table at 0x1b6198, the plaintext name strings in
   .rodata, and the invoke-static target inside each of the 22 public one-line
   wrappers a..v of com.nivaroid.topfollow.helper.q in classes.dex (report §11.13d).
   Column order: [slot, native name, signature, fnPtr offset, func#, wrapper, name
   string offset, role].  The names are randomised per build and carry no
   arithmetic relation to fnPtr; they are sorted ascending in the DEX but NOT in
   this table, so match by name, never by position. */
const JNI_EXPECT = [
    [ 0, 'x0011a4c2', '()J', 0x03eab4, 51, 'q.j', 0x15315,
         'id/timestamp getter -> func#73'],
    [ 1, 'x0014e2e9', '()Ljava/lang/String;', 0x03f034, 52, 'q.e', 0x15b2c,
         'string getter (688-1,328 B leaves: #52/#53)'],
    [ 2, 'x0016d3b9', '()Ljava/lang/String;', 0x03f3c8, 53, 'q.d', 0x16607,
         'string getter'],
    [ 3, 'x0012d3e0', '(Ljava/lang/String;)Ljava/lang/String;', 0x03f688, 54, 'q.o', 0x161db,
         'ENCRYPT: func#85 with keys from func#86 AND func#87'],
    [ 4, 'x0011e28b', '(Ljava/lang/String;)Ljava/lang/String;', 0x04110c, 55, 'q.n', 0x1547c,
         'DECRYPT: func#94 with keys from func#86 AND func#87'],
    [ 5, 'x00120b1e', '(Lcom/google/gson/JsonObject;Ljava/lang/String;)V', 0x0435b8, 56, 'q.i', 0x16cca,
         'request builder (47,808 B): func#30 + func#94'],
    [ 6, 'x0012e5a1', '(Lcom/google/gson/JsonObject;)V', 0x04f078, 57, 'q.v', 0x16b3a,
         'THE HUB (160,912 B): func#85 #30 #153 #154 #157 #158 #159 #160 #161 #162 #200 #73'],
    [ 7, 'x00135e2a', '(Lcom/google/gson/JsonObject;Lcom/nivaroid/topfollow/models/InstagramAccount;Ljava/lang/String;)V', 0x076508, 58, 'q.u', 0x16cd4,
         'order builder (37,668 B) -> func#85'],
    [ 8, 'x00105e9b', '(Ljava/lang/String;)Ljava/lang/String;', 0x07f82c, 59, 'q.c', 0x1705c,
         '-> func#30'],
    [ 9, 'x0015b1e9', '(Lcom/google/gson/JsonObject;Ljava/lang/String;Ljava/lang/String;)V', 0x081c58, 60, 'q.r', 0x1685d,
         'IS the 179,828-B Xposed/Riru/Substrate scanner -> func#85 #30 #153 #204 #21'],
    [10, 'x0015a3b7', '(Lcom/google/gson/JsonObject;Lcom/nivaroid/topfollow/models/InstagramAccount;Lcom/nivaroid/topfollow/models/Order;)V', 0x0adacc, 61, 'q.t', 0x15ed0,
         'order+account builder (73,008 B) -> func#30 #153 #200 #204'],
    [11, 'x0017b62c', '(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;', 0x0bf7fc, 62, 'q.s', 0x15b36,
         '-> func#85'],
    [12, 'x0011f42b', '()Ljava/lang/String;', 0x0c67a4, 63, 'q.m', 0x16a45,
         '-> func#30'],
    [13, 'x0012f5b7', '()Ljava/lang/String;', 0x0cbeac, 64, 'q.b', 0x16a4f,
         '-> func#157 (GCM context builder)'],
    [14, 'x0014b4f3', '(Ljava/lang/String;)Ljava/lang/String;', 0x0d46a8, 65, 'q.a', 0x16867,
         '-> func#85 #159 #160 #161 #162'],
    [15, 'x0011f1a2', '(Lcom/nivaroid/topfollow/models/Order;)Ljava/lang/String;', 0x0d80e8, 66, 'q.h', 0x16400,
         'Order -> string (33,020 B, no direct crypto)'],
    [16, 'x0015e49c', '(Lretrofit2/Response;Lcom/nivaroid/topfollow/models/Order;Lcom/nivaroid/topfollow/models/InstagramAccount;)Ljava/lang/String;', 0x0e01e4, 67, 'q.p', 0x16871,
         'THE RESPONSE HANDLER (117,628 B): func#226 sig+pin, func#225 maps, func#241 -> GCM core #191, func#85, func#30, func#21'],
    [17, 'x0010e27f', '()Ljava/lang/String;', 0x0fcd60, 68, 'q.f', 0x162d7,
         'string getter (688 B)'],
    [18, 'x00113f7a', '()Ljava/lang/String;', 0x0fd010, 69, 'q.g', 0x16a59,
         'string getter (1,328 B)'],
    [19, 'x0014c1f9', '(Lretrofit2/Response;)Ljava/lang/String;', 0x0fd540, 70, 'q.q', 0x1687b,
         'RESPONSE -> string (3,368 B)'],
    [20, 'x00126f7c', '(ZLjava/lang/String;)Lretrofit2/Retrofit;', 0x0fe268, 71, 'q.k', 0x15da9,
         'CERT PINNER: func#253 + func#254 + func#252 -> func#36'],
    [21, 'x0018d3f7', '(I)Lretrofit2/Retrofit;', 0x1013b8, 72, 'q.l', 0x15334,
         'retrofit builder: func#254'],
];

/* Known static key material, so a captured key is LABELLED instead of just
   dumped. All of these are byte-verified in the report (§4.2, §11.5, §11.6). */
const KNOWN_KEYS = [
    { hex: '30313233343536373839616263646566', name: 'literal "0123456789abcdef" @0x161ca / @0x17ae0', kind: 'AES-128 plaintext key' },
    { hex: '00000000000000000000000000000000', name: 'all-zero key', kind: 'func#30 hardwired AES-128 key (its key argument is discarded)' },
    { hex: '02df752315674526c5a695745313457544a7a654d6e4e340', name: 'XOR-0x5A @0x17428 -> Base64', kind: 'AES-192 GCM key (24 B)' },
    { hex: '58c544c151b4d9e185955991', name: 'XOR-0x5A @0x17448 -> Base64', kind: 'GCM nonce 1 (12 B)' },
    { hex: '334544c151add1a549b908c5', name: 'XOR-0x5A @0x17458 -> Base64', kind: 'GCM nonce 2 (12 B)' },
    { hex: 'e551092bd524e1dd1e969553', name: 'func#86 getter "5VEJK9Uk4d0elpVT"', kind: '12 B secret' },
    { hex: '3959b1d36c0c151e96686b56', name: 'func#159 getter "OVmx02wMFR6WaGtW"', kind: '12 B secret' }
];

/* The 21 Base64 blobs in .rodata, decoded recursively (report §11.13e).
   Keyed by the FULL STORED TEXT — which is exactly what func#17 hands to
   func#21 — so a captured call can be labelled on sight, including how many
   more layers are still encoded. Every detection token and every endpoint is
   here. The three tokens `riru`, `ygsik` and `rwxp` are NOT, because those
   are stored in plaintext: the library mixes both conventions inside the
   same scanner, so an allowlist built from only one of them leaks. */
const B64_BLOBS = {
    "V1ROS2JGbFlVbXhZTWpWMlpFZFZkbVJxU1hZPQ==": { off: 0x14bf4, len: 40, layers: 3, decoded: "create_note/v2/", chain: ["WTNKbFlYUmxYMjV2ZEdVdmRqSXY=", "Y3JlYXRlX25vdGUvdjIv", "create_note/v2/"] },
    "TDNOaGRtVXY=": { off: 0x14de8, len: 12, layers: 2, decoded: "/save/", chain: ["L3NhdmUv", "/save/"] },
    "V1ZWb1UwMUhUa2xVVkZwTlpWUm5PUT09": { off: 0x14eae, len: 32, layers: 4, decoded: "https://", chain: ["WVVoU01HTklUVFpNZVRnOQ==", "YUhSMGNITTZMeTg9", "aHR0cHM6Ly8=", "https://"] },
    "WkRnME5UVTVNV1V3T0RZd016TmhPVEF6Tldaa05tSTJObU16WXpOa056TmhZVE16WVdZNU1EYzVOR1EyWWprNE5tVTJORGMzT1dWbFlUWmlaV00xWlE9PQ==": { off: 0x15084, len: 120, layers: 2, decoded: "d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e", chain: ["ZDg0NTU5MWUwODYwMzNhOTAzNWZkNmI2NmMzYzNkNzNhYTMzYWY5MDc5NGQ2Yjk4NmU2NDc3OWVlYTZiZWM1ZQ==", "d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e"] },
    "bGliYnJpZGdlLnNv": { off: 0x15541, len: 16, layers: 1, decoded: "libbridge.so", chain: ["libbridge.so"] },
    "bGliY3NvX3N1YnN0cmF0ZQ==": { off: 0x156e8, len: 24, layers: 1, decoded: "libcso_substrate", chain: ["libcso_substrate"] },
    "WVVoU01HTklUVFpNZVRsd1RHMXNkV016VW1oYU0wcG9ZbE0xYW1JeU1IWlpXRUp3VEROWmVVeDNQVDA9": { off: 0x159ec, len: 80, layers: 3, decoded: "https://i.instagram.com/api/v2/", chain: ["YUhSMGNITTZMeTlwTG1sdWMzUmhaM0poYlM1amIyMHZZWEJwTDNZeUx3PT0=", "aHR0cHM6Ly9pLmluc3RhZ3JhbS5jb20vYXBpL3YyLw==", "https://i.instagram.com/api/v2/"] },
    "YUhSMGNITTZMeTkzZDNjdWFXNXpkR0ZuY21GdExtTnZiUzg9": { off: 0x15c02, len: 48, layers: 2, decoded: "https://www.instagram.com/", chain: ["aHR0cHM6Ly93d3cuaW5zdGFncmFtLmNvbS8=", "https://www.instagram.com/"] },
    "L3Byb2Mvc2VsZi9tYXBz": { off: 0x15db5, len: 20, layers: 1, decoded: "/proc/self/maps", chain: ["/proc/self/maps"] },
    "c3Vic3RyYXRl": { off: 0x15dd4, len: 12, layers: 1, decoded: "substrate", chain: ["substrate"] },
    "WVVoU01HTklUVFpNZVRrelpETmpkV0ZYTlhwa1IwWnVZMjFHZEV4dFRuWmlVemx1WTIxR2QyRklSbk5NTTBZeFdsaEtOUT09": { off: 0x15de3, len: 96, layers: 3, decoded: "https://www.instagram.com/graphql/query", chain: ["YUhSMGNITTZMeTkzZDNjdWFXNXpkR0ZuY21GdExtTnZiUzluY21Gd2FIRnNMM0YxWlhKNQ==", "aHR0cHM6Ly93d3cuaW5zdGFncmFtLmNvbS9ncmFwaHFsL3F1ZXJ5", "https://www.instagram.com/graphql/query"] },
    "U0dKR01FNW9OV3h3": { off: 0x1606a, len: 16, layers: 2, decoded: "HbF0Nh5lp", chain: ["SGJGME5oNWxw", "HbF0Nh5lp"] },
    "cmUuZnJpZGEuc2VydmVy": { off: 0x1607f, len: 20, layers: 1, decoded: "re.frida.server", chain: ["re.frida.server"] },
    "Z3VtLWpzLWxvb3A=": { off: 0x161eb, len: 16, layers: 1, decoded: "gum-js-loop", chain: ["gum-js-loop"] },
    "ZWR4cG9zZWQ=": { off: 0x16204, len: 12, layers: 1, decoded: "edxposed", chain: ["edxposed"] },
    "bHNwb3NlZA==": { off: 0x167a9, len: 12, layers: 1, decoded: "lsposed", chain: ["lsposed"] },
    "WXpKV2JHSnBPRDA9": { off: 0x16b60, len: 16, layers: 3, decoded: "seen/", chain: ["YzJWbGJpOD0=", "c2Vlbi8=", "seen/"] },
    "bGliYXJ0LnNvIChkZWxldGVkKQ==": { off: 0x16b75, len: 28, layers: 1, decoded: "libart.so (deleted)", chain: ["libart.so (deleted)"] },
    "eHBvc2Vk": { off: 0x16c11, len: 8, layers: 1, decoded: "xposed", chain: ["xposed"] },
    "bGliZnJpZGEtZ2FkZ2V0": { off: 0x16d97, len: 20, layers: 1, decoded: "libfrida-gadget", chain: ["libfrida-gadget"] },
    "bGliYy5zbyAoZGVsZXRlZCk=": { off: 0x16f69, len: 24, layers: 1, decoded: "libc.so (deleted)", chain: ["libc.so (deleted)"] },
};

/* The signature pin, so a captured digest can be labelled on sight. */
const SIGNATURE_PIN_SHA256 = 'd845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e';

/* ===================================================================== *
 * 2. SMALL UTILITIES
 * ===================================================================== */

let MOD = null;
function A(off) { return MOD.base.add(off); }

function hexOf(p, n) {
    if (p === null || p === undefined || p.isNull() || n <= 0) return '';
    try {
        const u = new Uint8Array(p.readByteArray(n));
        let s = '';
        for (let i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2);
        return s;
    } catch (e) { return '<unreadable:' + e + '>'; }
}

function bytesToHex(u) {
    let s = '';
    for (let i = 0; i < u.length; i++) s += ('0' + (u[i] & 0xff).toString(16)).slice(-2);
    return s;
}

function cstr(p, max) {
    if (p === null || p === undefined || p.isNull()) return null;
    try { return p.readUtf8String(max || 512); } catch (e) { return null; }
}

/* libc++ std::string, both the short (SSO, cap 22) and the long form. */
function readStdString(p) {
    if (p === null || p === undefined || p.isNull()) return null;
    let b0;
    try { b0 = p.readU8(); } catch (e) { return null; }
    if ((b0 & 1) === 0) {                       /* short form: len<<1 in byte 0 */
        const n = b0 >> 1;
        if (n === 0) return '';
        try { return p.add(1).readUtf8String(n); } catch (e) { return null; }
    }
    try {                                       /* long form: {cap, size, data} */
        /* readULong() returns a UInt64 OBJECT in Frida, not a JS number, so it
           must be normalised before any arithmetic: Math.min() on it throws
           "Cannot convert a BigInt value to a number" and every long string —
           i.e. every plaintext longer than the 22-byte SSO limit, which is most
           of them — would silently come back as null. */
        const rawSize = p.add(8).readULong();
        const size = Number(typeof rawSize === 'bigint' ? rawSize
                            : (rawSize && rawSize.valueOf ? rawSize.valueOf() : rawSize));
        const data = p.add(16).readPointer();
        if (!(size > 0) || data.isNull()) return '';
        if (size > 64 * 1024 * 1024) return '<implausible size ' + size + '>';
        const n = Math.min(size, CFG.maxDump);
        try { return data.readUtf8String(n); }
        catch (e) { const ab = data.readByteArray(n); return bytesToHex(new Uint8Array(ab)); }
    } catch (e) { return null; }
}

function readStd(p) {
    const v = readStdString(p);
    return v === null ? '<null>' : v;
}

function trunc(s, n) {
    if (s === null || s === undefined) return s;
    s = String(s);
    const lim = n || CFG.maxDump;
    return s.length > lim ? s.slice(0, lim) + '…(+' + (s.length - lim) + ' more)' : s;
}

function printable(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        if (b < 32 || b > 126) return null;
        s += String.fromCharCode(b);
    }
    return s;
}

function xorBytes(bytes, k) {
    const out = new Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ k;
    return out;
}

const B64A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function b64decodeStrict(str) {
    /* Buffer/atob style decoding is lenient and silently skips bad characters,
       which produces phantom decodes. This one is strict, on purpose. */
    if (!str || str.length % 4) return null;
    const idx = {};
    for (let i = 0; i < 64; i++) idx[B64A[i]] = i;
    let pad = 0;
    while (pad < 2 && str[str.length - 1 - pad] === '=') pad++;
    const body = str.slice(0, str.length - pad);
    const out = [];
    for (let i = 0; i < body.length; i++) {
        if (body[i] === '=' || idx[body[i]] === undefined) return null;
    }
    for (let i = 0; i + 1 < body.length; i += 4) {
        const n = (idx[body[i]] << 18) | (idx[body[i + 1]] << 12) |
                  ((i + 2 < body.length ? idx[body[i + 2]] : 0) << 6) |
                  (i + 3 < body.length ? idx[body[i + 3]] : 0);
        out.push((n >> 16) & 0xff);
        if (i + 2 < body.length) out.push((n >> 8) & 0xff);
        if (i + 3 < body.length) out.push(n & 0xff);
    }
    return out;
}

function shortBt(ctx, depth) {
    try {
        return Thread.backtrace(ctx, Backtracer.FUZZY).slice(0, depth || 8).map(a => {
            if (!MOD) return a.toString();
            const d = a.sub(MOD.base);
            return (d.compare(ptr(0)) >= 0 && d.compare(ptr(MOD.size)) < 0)
                ? MODULE + '+0x' + d.toString(16)
                : DebugSymbol.fromAddress(a).toString();
        });
    } catch (e) { return []; }
}

function keyLabel(hexStr) {
    /* name AND kind, so a captured event is self-describing without having to
       look the hex up in the report */
    for (const k of KNOWN_KEYS) if (k.hex === hexStr) return k.name + '  [' + k.kind + ']';
    return null;
}

/* ===================================================================== *
 * 3. THE EVENT SINK — synchronous append + in-memory ring
 * ===================================================================== */

const SINK = {
    fd: -1,
    path: null,
    tried: [],
    ring: [],
    seq: 0,
    bytesWritten: 0,
    writeErrors: 0,
    byKind: {},
    keys: {},          /* hex -> {count, firstSeen, label, len, sources} */
    endpoints: {},     /* url  -> count */
    natives: {},       /* name -> {calls, lastRet, totalMs} */
    detections: {},    /* fn   -> {calls, returns: {value: count}} */
    started: Date.now()
};

const O_WRONLY = 1, O_CREAT = 0x40, O_APPEND = 0x400, O_TRUNC = 0x200;
let _open = null, _write = null, _close = null;
function sinkBindLibc() {
    /* Bound lazily and defensively: if any of these is missing the capture
       degrades to ring-buffer-only instead of throwing at load time. */
    try {
        const o = Module.getExportByName(null, 'open');
        const w = Module.getExportByName(null, 'write');
        const c = Module.getExportByName(null, 'close');
        if (o) _open  = new NativeFunction(o, 'int',  ['pointer', 'int', 'int']);
        if (w) _write = new NativeFunction(w, 'long', ['int', 'pointer', 'int']);
        if (c) _close = new NativeFunction(c, 'int',  ['int']);
    } catch (e) { /* ring-only */ }
    return !!(_open && _write);
}

function sinkOpen(path, truncate) {
    if (!_open) return -1;
    const buf = Memory.allocUtf8String(path);
    const flags = O_WRONLY | O_CREAT | O_APPEND | (truncate ? O_TRUNC : 0);
    const fd = _open(buf, flags, 0x1a4).valueOf();   /* 0644 */
    if (fd < 0) { SINK.tried.push([path, 'open() -> ' + fd]); return -1; }
    SINK.fd = fd;
    SINK.path = path;
    return fd;
}

function sinkInit() {
    if (!sinkBindLibc()) {
        SINK.tried.push(['<libc>', 'open/write unavailable — ring-buffer-only capture']);
        return;
    }
    /* Prefer the app-writable dir; fall back through the list. */
    const candidates = [];
    if (CFG.path) candidates.push(CFG.path);
    CFG.pathFallbacks.forEach(p => { if (candidates.indexOf(p) < 0) candidates.push(p); });
    try {
        if (Java.available) {
            Java.perform(() => {
                try {
                    const AT = Java.use('android.app.ActivityThread');
                    const ctx = AT.currentApplication().getApplicationContext();
                    const f = Java.use('java.io.File');
                    const dir = ctx.getExternalFilesDir(null);
                    if (dir !== null) {
                        candidates.unshift(dir.getAbsolutePath() + '/topfollow_capture.jsonl');
                    }
                    candidates.push(ctx.getFilesDir().getAbsolutePath() + '/topfollow_capture.jsonl');
                } catch (e) { /* no context yet — the static list is enough */ }
            });
        }
    } catch (e) {}
    for (const p of candidates) {
        if (sinkOpen(p, false) >= 0) break;
    }
    if (SINK.fd < 0) {
        sinkLog('warn', { what: 'no writable capture path — events stay in the ring only',
                          tried: SINK.tried });
    }
}

function sinkWrite(line) {
    if (SINK.fd < 0) return false;
    try {
        const buf = Memory.allocUtf8String(line);
        const n = _write(SINK.fd, buf, line.length).valueOf();
        if (n < 0) { SINK.writeErrors++; return false; }
        SINK.bytesWritten += n;
        return true;
    } catch (e) { SINK.writeErrors++; return false; }
}

function sinkClose() { if (_close && SINK.fd >= 0) { try { _close(SINK.fd); } catch (e) {} SINK.fd = -1; } }

/* The one and only way an event enters the capture. */
function emit(kind, obj) {
    const ev = {
        s: ++SINK.seq,
        t: Date.now(),
        iso: new Date().toISOString(),
        tid: Process.getCurrentThreadId(),
        k: kind,
        d: obj || {}
    };
    SINK.ring.push(ev);
    if (SINK.ring.length > CFG.ringSize) SINK.ring.splice(0, SINK.ring.length - CFG.ringSize);
    SINK.byKind[kind] = (SINK.byKind[kind] || 0) + 1;

    let line;
    try { line = JSON.stringify(ev); } catch (e) { line = '{"s":' + ev.s + ',"k":"' + kind + ',"d":{"jsonError":"' + e + '"}}'; }
    sinkWrite(line + '\n');

    if (CFG.console && (CFG.consoleKinds.indexOf(kind) >= 0 || CFG.consoleKinds.indexOf('*') >= 0)) {
        send({ kind: kind, ev: ev });
    }
    return ev;
}
const sinkLog = (kind, obj) => emit(kind, obj);

function noteKey(hexStr, len, source) {
    if (!hexStr) return null;
    const e = SINK.keys[hexStr] || (SINK.keys[hexStr] = {
        hex: hexStr, len: len || hexStr.length / 2, count: 0,
        firstSeen: new Date().toISOString(), sources: [],
        label: keyLabel(hexStr),
        aes: (hexStr.length / 2) === 16 ? 'AES-128' : (hexStr.length / 2) === 24 ? 'AES-192'
             : (hexStr.length / 2) === 32 ? 'AES-256' : null
    });
    e.count++;
    if (source && e.sources.indexOf(source) < 0) e.sources.push(source);
    return e;
}

/* ===================================================================== *
 * 4. MODULE RESOLUTION + CALIBRATION
 *    Nothing is hooked until the anchors below match, so a different build
 *    produces a loud failure instead of silently wrong captures.
 * ===================================================================== */

function findModule() {
    try { const m = Process.findModuleByName(MODULE); if (m) return m; } catch (e) {}
    try {
        const m = Process.findModuleByAddress(Module.findExportByName(null, 'JNI_OnLoad'));
        if (m && m.name === MODULE) return m;
    } catch (e) {}
    return null;
}

function waitForModule(cb) {
    MOD = findModule();
    if (MOD) { cb(MOD); return; }

    emit('boot', { what: 'waiting for ' + MODULE, pid: Process.id, arch: Process.arch,
                   frida: Frida.version, platform: Process.platform });

    /* (a) the loader hooks: catch the module the instant it is mapped */
    ['android_dlopen_ext', 'dlopen', '__loader_android_dlopen_ext', '__loader_dlopen']
        .forEach(fn => {
            let p = null;
            try { p = Module.findExportByName(null, fn); } catch (e) {}
            if (!p) return;
            try {
                Interceptor.attach(p, {
                    onEnter(args) { this.path = cstr(args[0], 256); },
                    onLeave() {
                        if (!MOD && this.path && this.path.indexOf('topfollow') >= 0) {
                            const m = findModule();
                            if (m) { MOD = m; emit('boot', { what: MODULE + ' mapped via ' + fn, base: m.base.toString(), size: m.size }); cb(m); }
                        }
                    }
                });
            } catch (e) {}
        });

    /* (b) polling as a backstop */
    const iv = setInterval(() => {
        const m = findModule();
        if (m) { clearInterval(iv); if (!MOD) { MOD = m; cb(m); } }
    }, 25);
}

function calibrate() {
    const r = { ok: true, checks: [], jniSlots: null, drift: [] };
    const chk = (name, got, want) => {
        const pass = got === want;
        r.checks.push({ name: name, got: got, want: want, ok: pass });
        if (!pass) r.ok = false;
        return pass;
    };

    chk('module size', MOD.size, 1805400);
    /* .rodata opens with the LibTomCrypt AES table block: 0x118b0..0x13c10,
       8,960 bytes. Anchoring all of it proves the mapping in one shot. */
    chk('Te0   @0x118b0', hexOf(A(OFF.ro_te0), 8),   'a56363c6847c7cf8');
    chk('Td0   @0x129b0', hexOf(A(OFF.ro_td0), 8),   '50a7f4515365417e');
    chk('S-box @0x128b0', hexOf(A(OFF.ro_sbox), 8),  '637c777bf26b6fc5');
    chk('RSbox @0x139b0', hexOf(A(OFF.ro_rsbox), 8), '52096ad53036a538');
    chk('Rcon  @0x13b10', hexOf(A(OFF.ro_rcon), 8),  '0102040810204080');
    chk('Te1 is Te0 rotated right 1 byte', hexOf(A(OFF.ro_te1), 4), '6363c6a5');
    chk('Te3 is Te0 rotated right 3 bytes', hexOf(A(OFF.ro_te3), 4), 'c6a56363');
    chk('Td3 is Td0 rotated right 3 bytes', hexOf(A(OFF.ro_td3), 4), '5150a7f4');
    chk('"AES" @0x14b31 is the only cipher name in .rodata', cstr(A(OFF.ro_aes_name), 8), 'AES');
    chk('plain key @0x161ca', cstr(A(OFF.ro_plainkey), 32), '0123456789abcdef');
    chk('pin blob is 120 chars', (cstr(A(OFF.ro_pinblob), 200) || '').length, 120);
    chk('JNI_OnLoad export @0x3e1d4',
        (Module.findExportByName(MODULE, 'JNI_OnLoad') || ptr(0)).sub(MOD.base).toString(), '0x3e1d4');

    /* JNI_OnLoad makes exactly three JNI calls and no others. Verifying the
       instruction words at those three sites is a cheap, very strong build
       check: 0xd63f0100 is `blr x8`. */
    try {
        [['GetEnv          @0x3e308', OFF.jni_getenv],
         ['FindClass       @0x3e860', OFF.jni_findclass],
         ['RegisterNatives @0x3e93c', OFF.jni_reg1],
         ['RegisterNatives @0x3e988', OFF.jni_reg2]].forEach(pair => {
            chk('JNI_OnLoad ' + pair[0] + ' is blr x8',
                '0x' + A(pair[1]).readU32().toString(16), '0xd63f0100');
        });
        chk('FindClass argument is the helper class',
            cstr(A(OFF.jni_class_name), 64), 'com/nivaroid/topfollow/helper/q');
        /* the RegisterNatives block loads nMethods = 22 into w3 five
           instructions before the blr: `mov w3, #0x16` == 0x528002c3 at
           0x3e928, with the `adrp x2, #0x1b6000` / `add x2, x2, #0x198`
           pair that forms the table address sitting between them */
        chk('RegisterNatives nMethods immediate is 22',
            '0x' + A(OFF.jni_reg1 - 0x14).readU32().toString(16), '0x528002c3');
    } catch (e) {
        r.checks.push({ name: 'JNI_OnLoad instruction anchors', got: String(e), want: 'blr x8', ok: false });
    }

    /* XOR-0x5A decode the 64-byte key/nonce blob live, to prove func#193's key
       and to label every key we capture later. */
    try {
        const blob = new Uint8Array(A(OFF.ro_keyblob).readByteArray(64));
        const ascii = printable(Array.from(xorBytes(Array.from(blob), 0x5a)));
        r.checks.push({ name: 'key blob @0x17428 XOR-0x5A is ASCII', got: ascii ? 'yes' : 'no', want: 'yes', ok: !!ascii });
        if (ascii) {
            r.blobAscii = ascii;
            const k = b64decodeStrict(ascii.slice(0, 32));
            const n1 = b64decodeStrict(ascii.slice(32, 48));
            const n2 = b64decodeStrict(ascii.slice(48, 64));
            if (k)  { r.aes192key = bytesToHex(k);  chk('AES-192 key decodes', r.aes192key, '02df752315674526c5a695745313457544a7a654d6e4e340'); }
            if (n1) { r.nonce1 = bytesToHex(n1);    chk('GCM nonce 1 decodes', r.nonce1, '58c544c151b4d9e185955991'); }
            if (n2) { r.nonce2 = bytesToHex(n2);    chk('GCM nonce 2 decodes', r.nonce2, '334544c151add1a549b908c5'); }
        }
    } catch (e) { r.checks.push({ name: 'key blob read', got: String(e), want: 'readable', ok: false }); r.ok = false; }

    /* the pin blob: plaintext double-Base64 -> the pinned SHA-256 */
    try {
        let s = cstr(A(OFF.ro_pinblob), 200) || '';
        for (let i = 0; i < 2; i++) {
            const d = b64decodeStrict(s);
            if (!d) break;
            const t = printable(d);
            if (!t) break;
            s = t;
        }
        r.pinDecoded = s;
        chk('pin @0x15084 double-Base64 == SHA-256(signer cert)', s, SIGNATURE_PIN_SHA256);
    } catch (e) {}

    /* the RegisterNatives table. The file bytes at 0x1b6198 are all zero — the
       pointers only exist after the R_AARCH64_RELATIVE relocations are applied,
       i.e. only in the LOADED image. That makes this the strongest possible
       check that our offsets match the running build. */
    try {
        const slots = [];
        let good = 0;
        for (let i = 0; i < OFF.jni_entries; i++) {
            const e = A(OFF.jni_table_va + i * 0x18);
            const nameP = e.readPointer(), sigP = e.add(8).readPointer(), fnP = e.add(16).readPointer();
            const nm = cstr(nameP, 64), sg = cstr(sigP, 256);
            const off = fnP.isNull() ? null : fnP.sub(MOD.base).toInt32();
            const exp = JNI_EXPECT[i];
            const match = (nm === exp[1]) && (sg === exp[2]) && (off === exp[3]);
            if (match) good++;
            else r.drift.push({ slot: i, got: [nm, sg, off && '0x' + off.toString(16)], want: [exp[1], exp[2], '0x' + exp[3].toString(16)] });
            slots.push({ slot: i, name: nm, sig: sg, fnPtr: off === null ? null : '0x' + off.toString(16),
                         wrapper: exp[5] || null, funcNo: exp[4] || null,
                         nameStrOff: '0x' + exp[6].toString(16), matchesReport: match });
        }
        r.jniSlots = slots;
        r.jniGood = good;
        chk('JNI table slots matching the report', good, OFF.jni_entries);

        /* Each name field must point at the plaintext "x00NNNNNN" C string we
           located in .rodata. This catches a build where the names were
           re-randomised: the offsets stay valid but the strings change, so
           the two must agree. */
        let namesGood = 0;
        JNI_EXPECT.forEach((e, i) => {
            try { if (cstr(A(e[6]), 16) === e[1]) namesGood++; } catch (x) {}
        });
        chk('.rodata name strings match the table', namesGood, OFF.jni_entries);
    } catch (e) {
        r.checks.push({ name: 'JNI table readable', got: String(e), want: '22 slots', ok: false });
        r.ok = false;
    }

    emit('calibrate', r);
    return r;
}

/* ===================================================================== *
 * 5. NATIVE CRYPTO CAPTURE
 * ===================================================================== */

function hookCrypto() {

    /* ---- func#85 : AES-ECB encrypt -> lowercase hex ------------------- *
     * x0 = const std::string& plaintext
     * x1 = const std::string& key   (used VERBATIM, no KDF)
     * x8 = std::string* sret        (hex ciphertext, or the literal "null")
     * Accepts 16/24/32-byte keys. Returns "null" on empty pt/key or a bad
     * key length. Nine callers, including the response-path natives.      */
    Interceptor.attach(A(OFF.ecb_enc_hex), {
        onEnter(args) {
            this.pt = readStd(args[0]);
            this.key = readStd(args[1]);
            this.sret = this.context.x8;
            this.t0 = Date.now();
            this.bt = shortBt(this.context, 5);
        },
        onLeave() {
            const ct = readStd(this.sret);
            const keyBytes = [];
            for (let i = 0; i < (this.key || '').length && i < 64; i++) keyBytes.push(this.key.charCodeAt(i) & 0xff);
            const keyHex = bytesToHex(keyBytes);
            noteKey(keyHex, keyBytes.length, 'func#85 arg1');
            emit('crypto', {
                fn: 'func#85', off: '0x10c470', op: 'AES-ECB ENCRYPT',
                mode: 'ECB/PKCS7', outEncoding: 'lowercase-hex',
                plaintext: trunc(this.pt), plaintextLen: (this.pt || '').length,
                key: trunc(this.key, 128), keyHex: keyHex, keyLen: keyBytes.length,
                keyLabel: keyLabel(keyHex),
                cipherHex: trunc(ct), cipherLen: (ct || '').length,
                returnedNullLiteral: ct === 'null',
                ms: Date.now() - this.t0, bt: this.bt
            });
        }
    });

    /* ---- func#94 : exact inverse of func#85 --------------------------- */
    Interceptor.attach(A(OFF.ecb_dec_hex), {
        onEnter(args) {
            this.ct = readStd(args[0]);
            this.key = readStd(args[1]);
            this.sret = this.context.x8;
            this.bt = shortBt(this.context, 5);
        },
        onLeave() {
            const pt = readStd(this.sret);
            const kb = [];
            for (let i = 0; i < (this.key || '').length && i < 64; i++) kb.push(this.key.charCodeAt(i) & 0xff);
            noteKey(bytesToHex(kb), kb.length, 'func#94 arg1');
            emit('crypto', {
                fn: 'func#94', off: '0x110b70', op: 'AES-ECB DECRYPT',
                mode: 'ECB/PKCS7', inEncoding: 'lowercase-hex',
                cipherHex: trunc(this.ct), cipherLen: (this.ct || '').length,
                key: trunc(this.key, 128), keyHex: bytesToHex(kb), keyLen: kb.length,
                keyLabel: keyLabel(bytesToHex(kb)),
                plaintext: trunc(pt), plaintextLen: (pt || '').length,
                bt: this.bt
            });
        }
    });

    /* ---- func#30 : AES-128-CBC, key = 0^16, IV = 0^16, hex out -------- *
     * The key argument is ACCEPTED THEN DISCARDED — proven over five
     * different values. Used by 7 of the 22 JNI natives including the
     * response handler, so this single hook sees most app payloads.
     * Known divergence: past ciphertext offset 208 (plaintext > ~220 B)
     * func#30 stops matching textbook CBC (report §10 item 27) — the flag
     * below marks those captures instead of hiding them.                  */
    Interceptor.attach(A(OFF.cbc0_enc_hex), {
        onEnter(args) {
            this.pt = readStd(args[0]);
            this.keyArg = readStd(args[1]);
            this.sret = this.context.x8;
            this.bt = shortBt(this.context, 5);
        },
        onLeave() {
            const ct = readStd(this.sret);
            const n = (this.pt || '').length;
            emit('crypto', {
                fn: 'func#30', off: '0x38fa4', op: 'AES-128-CBC ENCRYPT (hardwired zero key)',
                mode: 'CBC/PKCS7', outEncoding: 'lowercase-hex',
                effectiveKey: '00'.repeat(16), effectiveIv: '00'.repeat(16),
                keyArgDiscarded: trunc(this.keyArg, 128),
                plaintext: trunc(this.pt), plaintextLen: n,
                cipherHex: trunc(ct), cipherLen: (ct || '').length,
                past220Divergence: n > 220 ? 'plaintext > 220 B: report §10 item 27 — func#30 diverges from textbook CBC past ciphertext offset 208' : null,
                bt: this.bt
            });
        }
    });

    /* ---- func#36 : hex in -> AES-256-ECB decrypt + PKCS#7 unpad ------- *
     * IMPORTANT FOR INTERPRETATION: its key is NOT a constant. func#14 is
     * entered with keylen=32 and a user-key pointer that lands inside
     * func#36's own stack frame, so the effective key depends on the stack
     * layout (report §11.11a, §10 item 34). Capture the pair, do not assume
     * you can replay it offline.
     * Behaviour: non-hex input -> empty (func#14 never called);
     *            len % 16 != 0 -> input echoed verbatim;
     *            valid PKCS#7  -> unpadded plaintext.
     * That makes it a padding oracle. Reachable as q.k(slot 15) -> #252 -> #36. */
    Interceptor.attach(A(OFF.aes256_dec_hex), {
        onEnter(args) {
            this.in = readStd(args[0]);
            this.keyArg = readStd(args[1]);
            this.sret = this.context.x8;
            this.bt = shortBt(this.context, 5);
        },
        onLeave() {
            const out = readStd(this.sret);
            const inLen = (this.in || '').length;
            emit('crypto', {
                fn: 'func#36', off: '0x3a838', op: 'AES-256-ECB DECRYPT + PKCS#7 unpad (hex in)',
                mode: 'ECB/PKCS7', inEncoding: 'lowercase-hex',
                input: trunc(this.in), inputHexChars: inLen, inputRawBytes: inLen / 2,
                keyArgDiscarded: trunc(this.keyArg, 128),
                output: trunc(out), outputLen: (out || '').length,
                interpretation: out === this.in ? 'ECHOED — decoded length not a multiple of 16, or padding invalid'
                                : (out === '' ? 'EMPTY — input was not valid lowercase hex'
                                : 'decrypted' + ((out || '').length < inLen / 2 ? ' and PKCS#7-unpadded' : '')),
                note: 'key is derived from func#36\'s own stack frame, not a constant — do not replay offline',
                bt: this.bt
            });
        }
    });

    /* ---- func#14 : rijndael_setup — THE REAL KEY, verbatim ------------ *
     * x0 = symmetric_key*   x1 = userkey   x3 = keylen in BYTES
     * Every cipher in the library goes through this one function (#30, #36,
     * #85, #94), so this hook is the single most reliable key capture in the
     * whole script. Round keys land at x0+0x0c, stride 32, LE words.       */
    Interceptor.attach(A(OFF.rijndael_setup), {
        onEnter(args) {
            this.skey = args[0];
            this.userkey = args[1];
            this.keylen = args[3].toInt32();
            this.bt = shortBt(this.context, 6);
            let kb = null;
            if (this.keylen > 0 && this.keylen <= 64) {
                try { kb = new Uint8Array(this.userkey.readByteArray(this.keylen)); } catch (e) {}
            }
            if (!kb) {
                emit('key', { fn: 'func#14', keylen: this.keylen, hex: null,
                              note: 'userkey unreadable — x1 may point at a std::string struct (func#36 case)',
                              bt: this.bt });
                return;
            }
            const h = bytesToHex(kb);
            const e = noteKey(h, this.keylen, 'func#14 rijndael_setup');
            emit('key', {
                fn: 'func#14', off: '0x32158', what: 'rijndael_setup',
                keylen: this.keylen,
                aes: this.keylen === 16 ? 'AES-128' : this.keylen === 24 ? 'AES-192'
                     : this.keylen === 32 ? 'AES-256' : 'INVALID (not 16/24/32)',
                hex: h, ascii: printable(Array.from(kb)),
                label: keyLabel(h), seenCount: e ? e.count : 1,
                skey: this.skey.toString(), bt: this.bt
            });
        },
        onLeave() {
            /* dump the expanded schedule straight out of the struct, so the
               key can be recovered from a capture even if x1 was ambiguous */
            if (this.keylen !== 16 && this.keylen !== 24 && this.keylen !== 32) return;
            try {
                const nr = this.keylen === 16 ? 10 : this.keylen === 24 ? 12 : 14;
                const rows = [];
                for (let r = 0; r <= nr; r++) rows.push(hexOf(this.skey.add(0x0c + 32 * r), 16));
                emit('key', { fn: 'func#14', what: 'expanded round-key schedule',
                              keylen: this.keylen, rows: rows, rk0: rows[0],
                              note: 'rk0 == the first 16 bytes of the user key (FIPS-197)' });
            } catch (e) {}
        }
    });

    /* ---- func#193 : XOR-0x5A string decoder --------------------------- *
     * x0 = src, x1 = len, x8 = sret. This is how EVERY packed string in the
     * library is unpacked at runtime, including the AES-192 key, both GCM
     * nonces and all the detection tokens. Capturing it means you never have
     * to decode a blob by hand again.                                      */
    Interceptor.attach(A(OFF.xor5a_decode), {
        onEnter(args) {
            this.src = args[0];
            this.len = args[1].toInt32();
            this.sret = this.context.x8;
            this.rawHex = (this.len > 0 && this.len <= 4096) ? hexOf(this.src, this.len) : null;
        },
        onLeave() {
            const out = readStd(this.sret);
            emit('decode', {
                fn: 'func#193', off: '0x14193c', what: 'XOR-0x5A string decode',
                srcLen: this.len, srcHex: trunc(this.rawHex, 512),
                decoded: trunc(out), decodedLen: (out || '').length,
                looksLikeB64: !!out && /^[A-Za-z0-9+/=]+$/.test(out),
                b64Layer1: (() => {
                    if (!out || !/^[A-Za-z0-9+/=]+$/.test(out)) return null;
                    const d = b64decodeStrict(out);
                    if (!d) return null;
                    const t = printable(d);
                    return t ? { ascii: t } : { hex: bytesToHex(d), len: d.length };
                })()
            });
        }
    });

    /* ---- the five argument-independent getters ------------------------ *
     * Each returns a fixed 16-char Base64 string whose decode is 12 bytes.
     * Capture the return, decode it, and label it.                         */
    const GETTERS = [
        ['func#86',  OFF.getter_86,  '5VEJK9Uk4d0elpVT'],
        ['func#87',  OFF.getter_87,  null],
        ['func#159', OFF.getter_159, 'OVmx02wMFR6WaGtW'],
        ['func#160', OFF.getter_160, 'V0V4V2pOa1ptZGsl'],
        ['func#161', OFF.getter_161, 'xV2xKTlZsBUVk1He']
    ];
    GETTERS.forEach(g => {
        try {
            Interceptor.attach(A(g[1]), {
                onEnter() { this.bt = shortBt(this.context, 4); },
                onLeave() {
                    /* the value comes back through the sret in x8 for the
                       std::string ABI; read both x0-as-string and x8-as-sret */
                    let v = null;
                    try { v = readStd(this.context.x8); } catch (e) {}
                    if (!v || v === '<null>') { try { v = readStd(this.returnValue); } catch (e) {} }
                    const d = v ? b64decodeStrict(v) : null;
                    if (d) noteKey(bytesToHex(d), d.length, g[0] + ' getter');
                    emit('key', {
                        fn: g[0], off: '0x' + g[1].toString(16), what: 'constant getter',
                        returned: trunc(v, 128), expectedConstant: g[2],
                        matchesKnownConstant: g[2] === null ? null : (v === g[2]),
                        decodedHex: d ? bytesToHex(d) : null, decodedLen: d ? d.length : null,
                        bt: this.bt
                    });
                }
            });
        } catch (e) { emit('warn', { what: 'getter hook failed', fn: g[0], err: String(e) }); }
    });

    /* ---- GCM contexts ------------------------------------------------- *
     * Native GCM: the .so imports no javax.crypto, Cipher, AES/GCM or
     * doFinal at all (report §10 item 35). func#157 stages the XOR-0x5A
     * decode of 0x17428 (key) and 0x17448 (nonce1); func#158 stages 0x17458.
     * Capture the arguments AND a hexdump of the first bytes of x0, because
     * the plaintext arrives through a struct field set by the caller, not
     * through x0's std::string (report §11.9 / §11.11c).                   */
    [['func#157', OFF.gcm_ctx_157, 'GCM ctx: key @0x17428 + nonce1 @0x17448'],
     ['func#158', OFF.gcm_ctx_158, 'GCM ctx: nonce2 @0x17458']].forEach(g => {
        try {
            Interceptor.attach(A(g[1]), {
                onEnter(args) {
                    this.x0 = args[0];
                    this.arg0str = readStd(args[0]);
                    this.t0 = Date.now();
                    this.bt = shortBt(this.context, 6);
                    emit('gcm', { fn: g[0], off: '0x' + g[1].toString(16), phase: 'enter',
                                  what: g[2], x0: this.x0.toString(),
                                  x0AsStdString: trunc(this.arg0str, 512),
                                  x0Hexdump: hexOf(this.x0, 64),
                                  x1: args[1].toString(), x2: args[2].toString(),
                                  bt: this.bt });
                },
                onLeave() {
                    /* dump the context after the call: the key/nonce land in it */
                    emit('gcm', { fn: g[0], phase: 'leave', ms: Date.now() - this.t0,
                                  x0HexdumpAfter: hexOf(this.x0, 128),
                                  retvalHex: hexOf(this.returnValue, 32) });
                }
            });
        } catch (e) { emit('warn', { what: 'GCM hook failed', fn: g[0], err: String(e) }); }
    });

    /* the GCM core and its GF(2^128) helper: entry/exit + a dump of the
       first argument, which is where the block data lives */
    [['func#191 GCM core', OFF.gcm_core, 96], ['func#172 GF(2^128)', OFF.gcm_gf, 64]].forEach(g => {
        try {
            Interceptor.attach(A(g[1]), {
                onEnter(args) {
                    this.x0 = args[0]; this.t0 = Date.now();
                    emit('gcm', { fn: g[0], phase: 'enter', x0: args[0].toString(),
                                  x0Hexdump: hexOf(args[0], g[2]),
                                  x1: args[1].toString(), x1Hexdump: hexOf(args[1], 32),
                                  x2: args[2].toInt32 ? args[2].toInt32() : null });
                },
                onLeave() {
                    emit('gcm', { fn: g[0], phase: 'leave', ms: Date.now() - this.t0,
                                  x0HexdumpAfter: hexOf(this.x0, g[2]) });
                }
            });
        } catch (e) {}
    });

    /* ---- hashes ------------------------------------------------------- */
    [['func#212 sha256_compress', OFF.sha256_compress],
     ['func#204 sha256 pipeline', OFF.sha256_pipeline]].forEach(h => {
        try {
            Interceptor.attach(A(h[1]), {
                onEnter(args) {
                    emit('hash', { fn: h[0], off: '0x' + h[1].toString(16), phase: 'enter',
                                   x0: args[0].toString(), blockHexdump: hexOf(args[1], 64),
                                   bt: shortBt(this.context, 4) });
                }
            });
        } catch (e) {}
    });

    /* ---- memcmp on the signature path --------------------------------- *
     * func#75 is called by #51, #57, #67, #221 and #226. Capturing what it
     * compares shows you the expected digest without patching anything.    */
    try {
        Interceptor.attach(A(OFF.memcmp_75), {
            onEnter(args) {
                this.a = args[0]; this.b = args[1];
                this.n = args[2].toInt32();
                this.bt = shortBt(this.context, 5);
            },
            onLeave(retval) {
                if (this.n <= 0 || this.n > 4096) return;
                const ah = hexOf(this.a, this.n), bh = hexOf(this.b, this.n);
                emit('compare', {
                    fn: 'func#75', off: '0x1086b8', what: 'memcmp', n: this.n,
                    a: trunc(ah, 512), b: trunc(bh, 512), equal: ah === bh,
                    retval: retval.toInt32(),
                    aAscii: (() => { try { return printable(Array.from(new Uint8Array(this.a.readByteArray(this.n)))); } catch (e) { return null; } })(),
                    pinRelated: ah === SIGNATURE_PIN_SHA256 || bh === SIGNATURE_PIN_SHA256 ||
                                (ah || '').indexOf(SIGNATURE_PIN_SHA256.slice(0, 16)) >= 0,
                    bt: this.bt
                });
            }
        });
    } catch (e) {}

    emit('boot', { what: 'native crypto hooks armed',
                   list: 'func#85 #94 #30 #36 #14 #193 + 5 getters + #157/#158/#191/#172 + #212/#204 + #75' });
}

/* ===================================================================== *
 * 6. JNI CAPTURE — native side, from the RegisterNatives table
 * ===================================================================== */

function hookJniNative() {
    let slots = [];
    try {
        for (let i = 0; i < OFF.jni_entries; i++) {
            const e = A(OFF.jni_table_va + i * 0x18);
            slots.push({
                slot: i,
                name: cstr(e.readPointer(), 64),
                sig: cstr(e.add(8).readPointer(), 256),
                fnPtr: e.add(16).readPointer()
            });
        }
    } catch (err) {
        emit('warn', { what: 'JNI table unreadable — falling back to the static offsets', err: String(err) });
        slots = JNI_EXPECT.map(x => ({ slot: x[0], name: x[1], sig: x[2], fnPtr: A(x[3]) }));
    }

    /* NOTE: slot 9 (q.j) IS func#60 — the 179,828-byte scanner — so that one
       address is attached twice, once here and once in hookDetection(). Frida
       supports several listeners on one address and both fire, which is what we
       want: you see the JNI entry AND the scanner's own enter/leave + retval. */
    let armed = 0;
    slots.forEach(s => {
        if (!s.fnPtr || s.fnPtr.isNull()) return;
        const exp = JNI_EXPECT[s.slot] || [];
        const label = 'slot ' + s.slot + ' ' + JNI_CLASS + '.' + s.name + ' ' + s.sig +
                      (exp[5] ? '  (DEX wrapper ' + exp[5] + ', func#' + exp[4] + ')' : '');
        try {
            Interceptor.attach(s.fnPtr, {
                onEnter(args) {
                    this.t0 = Date.now();
                    /* args[0]=JNIEnv*, args[1]=jclass/jobject, then the real ones */
                    this.jniArgs = [];
                    for (let i = 2; i < 8; i++) {
                        const p = args[i];
                        if (p === undefined) break;
                        this.jniArgs.push(p.toString());
                    }
                    this.bt = shortBt(this.context, 6);
                    emit('jni', {
                        phase: 'enter', slot: s.slot, name: s.name, sig: s.sig,
                        label: label, funcNo: exp[4] || null, wrapper: exp[5] || null,
                        nameStrOff: exp[6] ? '0x' + exp[6].toString(16) : null,
                        role: exp[7] || null,
                        fnPtrOffset: '0x' + s.fnPtr.sub(MOD.base).toString(16),
                        rawArgs: this.jniArgs, tid: Process.getCurrentThreadId(), bt: this.bt
                    });
                },
                onLeave(retval) {
                    const ms = Date.now() - this.t0;
                    const st = SINK.natives[s.name] || (SINK.natives[s.name] = { calls: 0, totalMs: 0, lastRet: null });
                    st.calls++; st.totalMs += ms;
                    /* for a String-returning native the jstring is in retval;
                       we cannot cheaply stringify it here, so record the pointer
                       and let the Java-side hook record the value. */
                    st.lastRet = retval.toString();
                    emit('jni', { phase: 'leave', slot: s.slot, name: s.name, sig: s.sig,
                                  label: label, ms: ms, retval: retval.toString(),
                                  callsSoFar: st.calls });
                }
            });
            armed++;
        } catch (e) {
            emit('warn', { what: 'JNI hook failed', label: label, err: String(e) });
        }
    });
    emit('boot', { what: 'JNI native hooks armed', armed: armed, of: slots.length });
}

/* ===================================================================== *
 * 7. DETECTION — WATCH ONLY
 * ===================================================================== */

function hookDetection() {
    const D = [
        ['func#60  scanner (179,828 B): xposed/edxposed/lsposed/substrate/libcso_substrate/riru/libbridge.so/ygsik', OFF.scanner_60],
        ['func#99  anti-Frida (XOR-0x37 tokens)',                             OFF.scanner_99],
        ['func#162 anti-Frida (Base64 tokens)',                               OFF.scanner_162],
        ['func#200 anti-hook scan',                                           OFF.scanner_200],
        ['func#225 maps integrity (rwxp / libart.so (deleted) / libc.so)',    OFF.maps_225],
        ['func#169 root check (access() x9 su paths)',                        OFF.root_169],
        ['func#154 root-check parent (reached from slot 6 only)',             OFF.root_154],
        ['func#98  clock() timing check',                                     OFF.timing_98],
        ['func#226 APK signature check + certificate pin',                    OFF.sig_check_226],
        ['func#73  APK signature check (reached from slots 5 and 6)',         OFF.sig_check_73],
        ['func#245 sole referrer of the pin blob @0x15084',                   OFF.pin_blob_245],
        ['func#253 okhttp3 CertificatePinner$Builder',                        OFF.pinner_253],
        ['func#254 retrofit2 Retrofit$Builder (baseUrl/client)',              OFF.retrofit_254],
        ['func#252 sole caller of func#36',                                   OFF.fixedkey_252],
        ['func#129 maps READER (used by #99, #225)',                          OFF.reader_129],
        ['func#198 maps READER (used by #162, #200)',                         OFF.reader_198],
        ['func#213 maps READER (used by #60)',                                OFF.reader_213]
    ];

    if (CFG.hookTrapFunc224) D.push(['func#224 — DANGEROUS, reachable `b .` @0x1576ac', OFF.trap_224]);

    let stubbed = 0;
    D.forEach(d => {
        /* In bypass mode the leaf detectors whose polarity we measured are
           REPLACED at the entry, so the flattened body never runs. Everything
           else — including func#226/#73 (beaten on the Java side instead),
           func#98 (unproven) and func#224 (trap) — stays watch-only even then. */
        /* >>>>> BYPASS-ONLY */
        if (BYPASS_ON()) {
            const forced = BYPASS.forceReturn[d[1]];
            if (forced !== undefined && forced !== null) {
                if (bypassReplace(d[0], d[1], forced)) { stubbed++; return; }
            }
        }
        /* <<<<< BYPASS-ONLY */
        try {
            Interceptor.attach(A(d[1]), {
                onEnter(args) {
                    this.t0 = Date.now();
                    this.bt = shortBt(this.context, 6);
                    emit('detect', { phase: 'enter', what: d[0], off: '0x' + d[1].toString(16),
                                     rawArgs: [args[0].toString(), args[1].toString(), args[2].toString()],
                                     bt: this.bt });
                },
                onLeave(retval) {
                    let v = null;
                    try { v = retval.toInt32(); } catch (e) { v = retval.toString(); }
                    const key = d[0].split(' ')[0];
                    const st = SINK.detections[key] || (SINK.detections[key] = { calls: 0, returns: {} });
                    st.calls++;
                    st.returns[String(v)] = (st.returns[String(v)] || 0) + 1;
                    /* RECORDED, NEVER CHANGED. retval.replace() is not called. */
                    emit('detect', { phase: 'leave', what: d[0], off: '0x' + d[1].toString(16),
                                     ms: Date.now() - this.t0, retval: v,
                                     retvalNote: 'observed, not altered — this script does not bypass',
                                     callsSoFar: st.calls, returnHistogram: st.returns });
                }
            });
        } catch (e) { emit('warn', { what: 'detection hook failed', fn: d[0], err: String(e) }); }
    });

    emit('boot', { what: BYPASS_ON() ? 'detection layer: some leaves REPLACED, the rest watched'
                                 : 'detection watchers armed (log-only)',
                   count: D.length,
                   stubbed: stubbed,
                   watched: D.length - stubbed,
                   bypass: BYPASS_ON(),
                   excluded: CFG.hookTrapFunc224 ? 'none' : 'func#224 @0x157628 (reachable `b .` trap @0x1576ac)' });
}

/* ===================================================================== *
 * 7B. >>>>> BEGIN BYPASS MODE — DEAD UNLESS CFG.bypass.enabled
 *
 * Everything between this marker and the matching END marker is the only
 * code in this file that writes to the app. frida/test_capture_offline.js
 * strips the whole region before asserting the read-only contract, so
 * "the default is read-only" stays a tested property, not a promise.
 * ===================================================================== */

/* A function, not a const: the hooks are installed once but a runner may flip
   CFG.bypass.enabled at any point through rpc.exports.cfg(), and reading the
   flag at call time means the marked regions come alive (or go dead) without a
   reload. It also keeps this declaration independent of hookDetection(), which
   is defined earlier in the file and would otherwise sit in a TDZ. */
function BYPASS_ON() { return !!(CFG.bypass && CFG.bypass.enabled); }
const BYPASS = Object.assign({
    forceReturn: {}, spoofSignature: true, hideMaps: true, hideSuPaths: true, fakeClock: false
}, CFG.bypass || {});

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
        emit('bypass', { what: 'maps line filtered in the read buffer (length preserved)',
                     action: 'rewritten', line: line.trim().slice(0, 120) });
    }
    if (!changed) return 0;
    const out = parts.join('\n');
    const bytes = [];
    for (let i = 0; i < out.length && i < n; i++) bytes.push(out.charCodeAt(i) & 0xff);
    try { buf.writeByteArray(bytes); } catch (e) { return 0; }
    return changed;
}

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

const SU_PATHS = ['/system/bin/su', '/system/xbin/su', '/sbin/su', '/su/bin/su',
                  '/data/local/su', '/data/local/bin/su', '/data/local/xbin/su',
                  '/system/app/Superuser.apk', '/system/bin/.ext/.su', 'su',
                  '/system/xbin/daemonsu', '/system/bin/busybox', '/magisk'];

function isSuPath(p) {
    return !!p && SU_PATHS.some(x => p === x || p.indexOf(x) >= 0);
}

/* Replace a detection leaf with a stub. ENTRY-only replacement is what keeps
   this safe: the CFF body never runs, so none of its opaque predicates can be
   perturbed into one of the 148 reachable `b .` traps (§3.8). */
function bypassReplace(name, off, ret) {
    try {
        Interceptor.replace(A(off), new NativeCallback(function () {
            emit('bypass', { what: name + ' FORCED', action: 'Interceptor.replace(entry)',
                             off: '0x' + off.toString(16), forcedRet: ret });
            return ret;
        }, 'int', ['pointer', 'pointer', 'pointer']));
        emit('bypass', { what: 'replaced ' + name, action: 'returns ' + ret,
                         off: '0x' + off.toString(16) });
        return true;
    } catch (e) {
        emit('warn', { what: 'bypass replace failed', fn: name, err: String(e) });
        return false;
    }
}

/* The repackaged APK is signed with a different key, so SHA-256(its cert) no
   longer equals the pin at 0x15084 and func#226/#73 reject it. Handing the
   ORIGINAL cert back out of PackageManager defeats that on the Java side —
   the native compare runs unmodified and passes (§6.5). */
function bypassSignatureForgery() {
    try {
        const GET_SIGNATURES = 0x00000040;
        const GET_SIGNING_CERTIFICATES = 0x08000000;      /* API 28+ */
        const Sig = Java.use('android.content.pm.Signature');
        const cert = b64decodeStrict(ORIGINAL_SIGNER_CERT_B64
                        .replace(/\s+/g, ''));
        const origBytes = Java.array('byte', cert.map(x => (x > 127 ? x - 256 : x)));
        const buildArr = () => Java.array('android.content.pm.Signature', [Sig.$new(origBytes)]);
        let forged = 0;

        const patch = (pi, flags, who) => {
            if (!pi) return pi;
            let did = false;
            if (flags & GET_SIGNATURES) { pi.signatures.value = buildArr(); did = true; }
            if (flags & GET_SIGNING_CERTIFICATES) {
                try {
                    const SI = Java.use('android.content.pm.SigningInfo');
                    pi.signingInfo.value = SI.$new(buildArr());
                    did = true;
                } catch (e) { /* no such ctor on this API level */ }
            }
            if (did) {
                forged++;
                emit('bypass', { what: who + ' -> signatures FORGED with the original cert',
                                 action: 'PackageManager spoof',
                                 flags: '0x' + (flags >>> 0).toString(16),
                                 pinned: SIGNATURE_PIN_SHA256.slice(0, 16) + '…', n: forged });
            }
            return pi;
        };

        let n = 0;
        [['android.app.ApplicationPackageManager', 'getPackageInfo'],
         ['android.content.pm.PackageManager',    'getPackageInfo'],
         ['android.app.ApplicationPackageManager', 'getPackageInfoAsUser']].forEach(spec => {
            try {
                const C = Java.use(spec[0]);
                C[spec[1]].overloads.forEach(ov => {
                    /* ov.apply, never C[spec[1]](...) — calling the method inside
                       its own hook re-dispatches and recurses. */
                    ov.implementation = function () {
                        const r = ov.apply(this, arguments);
                        const flags = arguments.length > 1 ? (arguments[1] | 0) : 0;
                        return patch(r, flags, spec[0] + '.' + spec[1]);
                    };
                });
                n += C[spec[1]].overloads.length;
            } catch (e) { emit('warn', { what: 'sig-forgery hook failed', fn: spec[0], err: String(e) }); }
        });

        try {
            Sig.toByteArray.implementation = function () {
                emit('bypass', { what: 'Signature.toByteArray() -> original cert DER',
                                 action: 'last line of defence', len: origBytes.length });
                return origBytes;
            };
            n++;
        } catch (e) {}

        emit('boot', { what: 'signature forgery armed', count: n,
                       pin: SIGNATURE_PIN_SHA256,
                       certBytes: origBytes.length });
        return n;
    } catch (e) {
        emit('warn', { what: 'bypassSignatureForgery failed', err: String(e) });
        return 0;
    }
}

/* <<<<< END BYPASS MODE — everything above was dead unless CFG.bypass.enabled */

/* ===================================================================== *
 * 8. LIBC FILE / LOADER CAPTURE  — LOG ONLY, nothing is hidden
 * ===================================================================== */

function hookLibc() {
    const TRACK = {};   /* fd -> path, for reads on /proc */

    ['__open_2', 'open', 'open64', 'openat'].forEach(fn => {
        let p = null;
        try { p = Module.findExportByName('libc.so', fn); } catch (e) {}
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter(args) { this.path = cstr(args[0], 512); },
                onLeave(retval) {
                    if (!this.path) return;
                    const fd = retval.toInt32();
                    if (fd >= 0) TRACK[fd] = this.path;
                    const interesting = this.path.indexOf('/proc/') === 0 ||
                                        this.path.indexOf('maps') >= 0 ||
                                        this.path.indexOf('su') >= 0 ||
                                        this.path.indexOf('magisk') >= 0 ||
                                        this.path.indexOf('frida') >= 0 ||
                                        this.path.indexOf('topfollow') >= 0 ||
                                        this.path.indexOf('.so') >= 0;
                    if (interesting) {
                        emit('file', { what: fn, path: this.path, fd: fd,
                                       retvalNote: 'logged, NOT redirected' });
                    }
                }
            });
        } catch (e) {}
    });

    ['read', '__read_chk', 'pread', 'pread64'].forEach(fn => {
        let p = null;
        try { p = Module.findExportByName('libc.so', fn); } catch (e) {}
        if (!p) return;
        const fdArg = fn === '__read_chk' ? 1 : 0;
        const bufArg = fdArg + 1;
        try {
            Interceptor.attach(p, {
                onEnter(args) {
                    this.fd = args[fdArg].toInt32();
                    this.buf = args[bufArg];
                    this.path = TRACK[this.fd] || null;
                },
                onLeave(retval) {
                    if (!this.path) return;
                    if (this.path.indexOf('/proc/') !== 0 && this.path.indexOf('maps') < 0) return;
                    const n = retval.toInt32();
                    if (n <= 0) return;
                    /* BYPASS: rewrite the maps buffer BEFORE reading it back,
                       length-preserved, so the scanner's own byte loop finds
                       nothing. This library imports no fopen/fgets/strstr — the
                       read() buffer IS the detection surface (§10 item 39). */
                    let filtered = 0;
                    /* >>>>> BYPASS-ONLY */
                    if (BYPASS_ON() && BYPASS.hideMaps) {
                        filtered = filterMapsBuffer(this.buf, n);
                    }
                    /* <<<<< BYPASS-ONLY */
                    const dump = hexOf(this.buf, Math.min(n, 4096));
                    let text = null;
                    try { text = this.buf.readUtf8String(Math.min(n, 4096)); } catch (e) {}
                    /* Which of the library's own tokens appear in this chunk?
                       That tells you what the scanner is about to find. */
                    const TOKENS = ['frida', 'gadget', 'gum-js-loop', 're.frida', 'rwxp',
                                    '(deleted)', 'magisk', 'xposed', 'substrate', 'riru',
                                    'libbridge', 'ygsik', 'lsposed', 'pool-frida', 'gmain',
                                    'linjector'];
                    const low = (text || '').toLowerCase();
                    const hits = TOKENS.filter(t => low.indexOf(t) >= 0);
                    emit('file', {
                        what: fn + ' on ' + this.path, fd: this.fd, bytes: n,
                        tokensPresent: hits,
                        wouldBeDetected: hits.length > 0,
                        text: text ? trunc(text, 8192) : null,
                        hex: dump ? trunc(dump, 4096) : null,
                        linesFiltered: filtered,
                        /* >>>>> BYPASS-ONLY */
                        retvalNote: filtered > 0
                            ? 'BYPASS ON — ' + filtered + ' maps line(s) rewritten in place, length preserved'
                            : 'buffer UNMODIFIED — this script captures, it does not hide'
                        /* <<<<< BYPASS-ONLY */
                    });
                }
            });
        } catch (e) {}
    });

    const cl = Module.findExportByName('libc.so', 'close');
    if (cl) { try { Interceptor.attach(cl, { onEnter(args) { delete TRACK[args[0].toInt32()]; } }); } catch (e) {} }

    ['access', 'faccessat', 'stat', 'lstat', '__xstat', '__statx'].forEach(fn => {
        let p = null;
        try { p = Module.findExportByName('libc.so', fn); } catch (e) {}
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter(args) { this.path = cstr(args[fn === 'faccessat' ? 1 : 0], 512); },
                onLeave(retval) {
                    if (!this.path) return;
                    let r = retval.toInt32();
                    /* BYPASS: func#169 checks exactly 9 fixed paths with
                       access(); -1/ENOENT defeats it without touching the
                       function, so no CFF body and no trap is involved. */
                    let forced = false;
                    /* >>>>> BYPASS-ONLY */
                    if (BYPASS_ON() && BYPASS.hideSuPaths && r === 0 && isSuPath(this.path)) {
                        retval.replace(ptr(-1));
                        r = -1;
                        forced = true;
                        emit('bypass', { what: fn + '("' + this.path + '") forced to -1 (ENOENT)',
                                         action: 'retval.replace', rootCheck: 'func#169 defeated' });
                    }
                    /* <<<<< BYPASS-ONLY */
                    /* only the security-relevant ones, otherwise this drowns */
                    if (forced || /su|magisk|superuser|busybox|daemonsu|frida|xposed|substrate|riru|\/proc\//i.test(this.path)) {
                        emit('file', { what: fn, path: this.path, retval: r,
                                       exists: r === 0, forced: forced,
                                       /* >>>>> BYPASS-ONLY */
                                       retvalNote: forced
                                           ? 'BYPASS ON — forced to ENOENT'
                                           : 'logged, NOT forced to ENOENT'
                                       /* <<<<< BYPASS-ONLY */ });
                    }
                }
            });
        } catch (e) {}
    });

    ['clock', 'gettimeofday', 'clock_gettime'].forEach(fn => {
        let p = null;
        try { p = Module.findExportByName('libc.so', fn); } catch (e) {}
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter() {
                    const lr = this.context.lr;
                    this.fromF98 = false;
                    if (MOD) {
                        const d = lr.sub(MOD.base).toInt32();
                        this.fromF98 = d >= OFF.timing_98 && d < OFF.timing_98 + 1972;
                    }
                },
                onLeave(retval) {
                    if (!this.fromF98) return;
                    emit('timing', { what: fn + ' called from inside func#98', retval: retval.toString(),
                                     retvalNote: 'logged, NOT faked' });
                }
            });
        } catch (e) {}
    });

    emit('boot', { what: 'libc file/timing capture armed (log-only)' });
}

/* ===================================================================== *
 * 9. JAVA CAPTURE
 * ===================================================================== */

function j(v, n) { try { return v === null || v === undefined ? null : trunc(v.toString(), n || 4096); } catch (e) { return '<' + e + '>'; } }

function hookJava() {
    if (!Java.available) { emit('warn', { what: 'Java.available == false — Java capture skipped' }); return; }
    Java.perform(() => {

        /* ---- 9.0 BYPASS: the signature pin, beaten on the Java side.
               Armed FIRST, before anything else, because func#226/#73 run
               early and a repackaged APK fails them outright. No-op unless
               CFG.bypass.enabled && CFG.bypass.spoofSignature. ---------- */
        /* >>>>> BYPASS-ONLY */
        if (BYPASS_ON() && BYPASS.spoofSignature) bypassSignatureForgery();
        /* <<<<< BYPASS-ONLY */

        /* ---- 9.1 the 22 natives from the Java side. This is the highest
               value capture in the script: JsonObject / Response / Order /
               InstagramAccount arrive as real Java objects and toString()
               into readable JSON instead of native pointers. ---------- */
        try {
            const Q = Java.use(JNI_CLASS);
            JNI_EXPECT.forEach(e => {
                const nm = e[1], sg = e[2], slot = e[0];
                try {
                    if (!Q[nm]) return;
                    const params = parseSigParams(sg).map(jtypeToJava);
                    const ov = Q[nm].overload.apply(Q[nm], params);
                    ov.implementation = function () {
                        const t0 = Date.now();
                        const argsIn = Array.prototype.slice.call(arguments).map(a => j(a, CFG.maxBodyDump));
                        let r = ov.apply(this, arguments);      /* the real call, untouched */
                        const rs = j(r, CFG.maxBodyDump);
                        emit('jniJava', {
                            slot: slot, name: nm, sig: sg, funcNo: e[4], wrapper: e[5],
                            role: e[7],
                            args: argsIn, ret: rs, ms: Date.now() - t0,
                            note: 'return value passed through unmodified'
                        });
                        return r;
                    };
                } catch (x) { /* overload absent on this build */ }
            });
            emit('boot', { what: 'Java hooks armed on ' + JNI_CLASS });
        } catch (e) { emit('warn', { what: 'Java hook ' + JNI_CLASS + ' failed', err: String(e) }); }

        /* ---- 9.2 okhttp3: the actual request and response ------------- *
         * RealInterceptorChain.proceed is the single funnel every request
         * passes through, and Response.body is read with peekBody() so the
         * app still gets an unconsumed stream.                            */
        if (CFG.captureNet) {
            try {
                const CH = Java.use('okhttp3.internal.http.RealInterceptorChain');
                const chProceed = CH.proceed.overload('okhttp3.Request');
                chProceed.implementation = function (req) {
                    const t0 = Date.now();
                    let reqInfo = null;
                    try { reqInfo = dumpRequest(req); } catch (e) { reqInfo = { err: String(e) }; }
                    /* chProceed.apply, NEVER this.proceed(req): calling the
                       method on `this` re-dispatches into this very hook, so
                       the first HTTP request the app makes blows the stack.
                       This is the request/response capture the whole net layer
                       depends on. */
                    const resp = chProceed.apply(this, [req]);   /* untouched */
                    let respInfo = null;
                    try { respInfo = dumpResponse(resp); } catch (e) { respInfo = { err: String(e) }; }
                    const url = reqInfo && reqInfo.url ? reqInfo.url : '<unknown>';
                    SINK.endpoints[url] = (SINK.endpoints[url] || 0) + 1;
                    emit('net', {
                        phase: 'roundtrip', url: url, hits: SINK.endpoints[url],
                        ms: Date.now() - t0, request: reqInfo, response: respInfo
                    });
                    return resp;
                };
                emit('boot', { what: 'okhttp3 RealInterceptorChain.proceed captured' });
            } catch (e) { emit('warn', { what: 'okhttp3 chain hook failed', err: String(e) }); }

            /* Request/Response bodies that never go through the chain */
            [['okhttp3.Request$Builder', 'build'], ['okhttp3.Response$Builder', 'build']].forEach(b => {
                try {
                    const C = Java.use(b[0]);
                    C[b[1]].overloads.forEach(ov => {
                        ov.implementation = function () {
                            const r = ov.apply(this, arguments);   /* forwards to the ORIGINAL */
                            try {
                                if (b[0].indexOf('Request') === 0) emit('net', { phase: 'request built', request: dumpRequest(r) });
                                else emit('net', { phase: 'response built', response: dumpResponse(r) });
                            } catch (e) {}
                            return r;
                        };
                    });
                } catch (e) {}
            });

            /* Request bodies are captured inside dumpRequest() via a scratch
               okio.Buffer, which does not consume the real stream. Hooking
               RequestBody.writeTo itself is NOT done here: the obvious
               implementation re-enters the hook and recurses forever. */
        }

        /* ---- 9.3 Gson: every serialised/deserialised object ----------- */
        if (CFG.captureJson) {
            try {
                const G = Java.use('com.google.gson.Gson');
                G.toJson.overloads.forEach(ov => {
                    ov.implementation = function () {
                        const r = ov.apply(this, arguments);
                        emit('json', { phase: 'toJson', arg0: j(arguments[0], CFG.maxBodyDump),
                                       result: trunc(r, CFG.maxBodyDump) });
                        return r;
                    };
                });
                ['fromJson'].forEach(m => {
                    G[m].overloads.forEach(ov => {
                        ov.implementation = function () {
                            const r = ov.apply(this, arguments);
                            emit('json', { phase: m, src: j(arguments[0], CFG.maxBodyDump),
                                           type: j(arguments.length > 1 ? arguments[1] : null, 256),
                                           result: j(r, CFG.maxBodyDump) });
                            return r;
                        };
                    });
                });
                emit('boot', { what: 'Gson toJson/fromJson captured' });
            } catch (e) { emit('warn', { what: 'Gson hook failed', err: String(e) }); }
        }

        /* ---- 9.4 crypto on the Java side ------------------------------ */
        if (CFG.captureDigest) {
            try {
                const MD = Java.use('java.security.MessageDigest');
                /* getInstance is STATIC: calling MD.getInstance(...) inside its
                   own implementation dispatches back into the hook. Drop the
                   hook, call through, then re-arm.

                   Re-arm with `null`, NOT with the wrapper object: in Frida a
                   method wrapper's `.implementation` getter returns the JS
                   function currently installed, so once we are inside our own
                   hook that wrapper IS our hook, and assigning it back re-hooks
                   the hook. The first call would work and the second would
                   recurse. Same idiom for mdUpdate and b64dec below. */
                const mdGetInst = MD.getInstance.overload('java.lang.String');
                mdGetInst.implementation = function (alg) {
                    emit('javacrypto', { phase: 'MessageDigest.getInstance', algorithm: j(alg) });
                    mdGetInst.implementation = null;
                    let r;
                    try { r = MD.getInstance(alg); } finally { mdGetInst.implementation = null; }
                    return r;
                };
                MD.digest.overloads.forEach(ov => {
                    ov.implementation = function () {
                        const r = ov.apply(this, arguments);
                        const h = bytesToHex(new Uint8Array(r));
                        emit('javacrypto', {
                            phase: 'MessageDigest.digest', algorithm: j(this.getAlgorithm()),
                            input: ov === MD.digest.overload('[B') ? trunc(bytesToHex(new Uint8Array(arguments[0])), 1024) : null,
                            inputLen: arguments.length ? (arguments[0] ? arguments[0].length : 0) : 0,
                            digestHex: h,
                            isTheSignaturePin: h === SIGNATURE_PIN_SHA256,
                            pinNote: h === SIGNATURE_PIN_SHA256
                                ? 'THIS IS THE PINNED VALUE — SHA-256 of the APK signer certificate DER (.rodata 0x15084)' : null
                        });
                        return r;
                    };
                });
                const mdUpdate = MD.update.overload('[B');
                mdUpdate.implementation = function (b) {
                    emit('javacrypto', { phase: 'MessageDigest.update', algorithm: j(this.getAlgorithm()),
                                         len: b ? b.length : 0, hex: trunc(bytesToHex(new Uint8Array(b || [])), 2048) });
                    mdUpdate.implementation = null;
                    let r;
                    try { r = this.update(b); } finally { mdUpdate.implementation = null; }
                    return r;
                };
            } catch (e) { emit('warn', { what: 'MessageDigest hook failed', err: String(e) }); }

            try {
                const C = Java.use('javax.crypto.Cipher');
                C.getInstance.overloads.forEach(ov => {
                    /* static factory: ov.apply(this, arguments) forwards to the
                       ORIGINAL, so there is no recursion here */
                    ov.implementation = function () {
                        emit('javacrypto', { phase: 'Cipher.getInstance', transformation: j(arguments[0]),
                                             note: 'the .so itself contains NO javax/crypto reference — if this fires it is the DEX, not the native GCM' });
                        return ov.apply(this, arguments);
                    };
                });
                C.doFinal.overloads.forEach(ov => {
                    ov.implementation = function () {
                        const inp = arguments.length && arguments[0] && arguments[0].length !== undefined
                            ? trunc(bytesToHex(new Uint8Array(arguments[0])), 2048) : null;
                        const r = ov.apply(this, arguments);
                        emit('javacrypto', { phase: 'Cipher.doFinal', transformation: j(this.getAlgorithm()),
                                             inputHex: inp, outputHex: r ? trunc(bytesToHex(new Uint8Array(r)), 2048) : null,
                                             outputLen: r ? r.length : null });
                        return r;
                    };
                });
                C.init.overloads.forEach(ov => {
                    ov.implementation = function () {
                        emit('javacrypto', { phase: 'Cipher.init', opmode: j(arguments[0]),
                                             key: j(arguments.length > 1 ? arguments[1] : null, 512),
                                             keyEncoded: (() => { try { return arguments[1] ? trunc(bytesToHex(new Uint8Array(arguments[1].getEncoded())), 256) : null; } catch (e) { return null; } })() });
                        return ov.apply(this, arguments);
                    };
                });
            } catch (e) { emit('warn', { what: 'Cipher hook failed', err: String(e) }); }

            try {
                const B = Java.use('android.util.Base64');
                B.encodeToString.overloads.forEach(ov => {
                    ov.implementation = function () {
                        const r = ov.apply(this, arguments);
                        emit('javacrypto', { phase: 'Base64.encodeToString',
                                             inputHex: arguments[0] ? trunc(bytesToHex(new Uint8Array(arguments[0])), 1024) : null,
                                             result: trunc(r, 1024) });
                        return r;
                    };
                });
                const b64dec = B.decode.overload('java.lang.String', 'int');
                b64dec.implementation = function (s, f) {
                    b64dec.implementation = null;
                    let r;
                    try { r = B.decode(s, f); } finally { b64dec.implementation = null; }
                    emit('javacrypto', { phase: 'Base64.decode', input: trunc(s, 512),
                                         outputHex: trunc(bytesToHex(new Uint8Array(r || [])), 512) });
                    return r;
                };
            } catch (e) {}
        }

        /* ---- 9.5 package / signature inspection ----------------------- */
        if (CFG.capturePkg) {
            try {
                const PM = Java.use('android.app.ApplicationPackageManager');
                PM.getPackageInfo.overloads.forEach(ov => {
                    ov.implementation = function () {
                        const r = ov.apply(this, arguments);
                        let sigs = null;
                        try {
                            if (r && r.signatures) {
                                sigs = r.signatures.value.map(sg => {
                                    const b = sg.toByteArray();
                                    const h = bytesToHex(new Uint8Array(b));
                                    return { len: b.length, derSha256Input: trunc(h, 4096) };
                                });
                            }
                        } catch (e) { sigs = '<' + e + '>'; }
                        emit('pkg', { phase: 'getPackageInfo', name: j(arguments[0]),
                                      flags: arguments.length > 1 ? String(arguments[1]) : null,
                                      signatures: sigs,
                                      note: 'the native side SHA-256s signature[0].toByteArray() and compares it with the pin @0x15084' });
                        return r;
                    };
                });
            } catch (e) { emit('warn', { what: 'PackageManager hook failed', err: String(e) }); }

            try {
                const Sig = Java.use('android.content.pm.Signature');
                /* Grab the wrapper BEFORE installing and call through it.
                   this.toByteArray() would re-dispatch into this hook — and
                   this is exactly the method the signature-pin story depends
                   on, so it has to survive being called twice. */
                const sigToByteArray = Sig.toByteArray;
                sigToByteArray.implementation = function () {
                    const r = sigToByteArray.call(this);
                    emit('pkg', { phase: 'Signature.toByteArray', len: r ? r.length : 0,
                                  hex: trunc(bytesToHex(new Uint8Array(r || [])), 4096),
                                  note: 'SHA-256 of these bytes must equal ' + SIGNATURE_PIN_SHA256 });
                    return r;
                };
                const sigHashCode = Sig.hashCode;
                sigHashCode.implementation = function () {
                    const r = sigHashCode.call(this);
                    emit('pkg', { phase: 'Signature.hashCode', ret: r });
                    return r;
                };
            } catch (e) {}

            try {
                const SI = Java.use('android.content.pm.SigningInfo');
                ['getApkContentsSigners', 'getSigningCertificateHistory'].forEach(m => {
                    if (!SI[m]) return;
                    SI[m].implementation = function () {
                        const r = this[m]();
                        emit('pkg', { phase: 'SigningInfo.' + m, count: r ? r.length : 0 });
                        return r;
                    };
                });
            } catch (e) {}
        }

        /* ---- 9.6 shell-outs ------------------------------------------- */
        if (CFG.captureExec) {
            try {
                const RT = Java.use('java.lang.Runtime');
                RT.exec.overloads.forEach(ov => {
                    ov.implementation = function () {
                        emit('exec', { phase: 'Runtime.exec', cmd: j(arguments[0], 1024) });
                        return ov.apply(this, arguments);
                    };
                });
            } catch (e) {}
            try {
                const PB = Java.use('java.lang.ProcessBuilder');
                const pbStart = PB.start.overload();
                pbStart.implementation = function () {
                    emit('exec', { phase: 'ProcessBuilder.start', command: j(this.command(), 1024) });
                    return pbStart.apply(this, arguments);
                };
            } catch (e) {}
        }

        /* ---- 9.7 SharedPreferences (off by default: very noisy) ------- */
        if (CFG.capturePrefs) {
            try {
                const SPE = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
                ['putString', 'putInt', 'putLong', 'putBoolean', 'putFloat'].forEach(m => {
                    if (!SPE[m]) return;
                    SPE[m].overloads.forEach(ov => {
                        ov.implementation = function () {
                            emit('prefs', { phase: m, key: j(arguments[0]), value: j(arguments[1], 2048) });
                            return ov.apply(this, arguments);
                        };
                    });
                });
            } catch (e) {}
        }
    });
}

/* dump an okhttp3.Request without consuming anything */
function dumpRequest(req) {
    const out = {};
    try { out.method = j(req.method(), 32); } catch (e) {}
    try { out.url = j(req.url(), 512); } catch (e) {}
    try {
        const h = req.headers();
        const hs = {};
        for (let i = 0; i < h.size(); i++) hs[j(h.name(i), 128)] = j(h.value(i), 2048);
        out.headers = hs;
    } catch (e) { out.headersErr = String(e); }
    try {
        const b = req.body();
        if (b !== null) {
            const B = Java.use('okio.Buffer');
            const buf = B.$new();
            b.writeTo(buf);
            out.body = trunc(buf.readUtf8(), CFG.maxBodyDump);
            out.contentType = j(b.contentType(), 128);
        }
    } catch (e) { out.bodyErr = String(e); }
    return out;
}

/* dump an okhttp3.Response using peekBody so the app's stream survives */
function dumpResponse(resp) {
    const out = {};
    try { out.code = resp.code(); } catch (e) {}
    try { out.message = j(resp.message(), 256); } catch (e) {}
    try { out.successful = resp.isSuccessful(); } catch (e) {}
    try {
        const rq = resp.request();
        out.url = j(rq.url(), 512);
        out.method = j(rq.method(), 32);
    } catch (e) {}
    try {
        const h = resp.headers();
        const hs = {};
        for (let i = 0; i < h.size(); i++) hs[j(h.name(i), 128)] = j(h.value(i), 2048);
        out.headers = hs;
    } catch (e) { out.headersErr = String(e); }
    try {
        const peek = resp.peekBody(CFG.maxBodyDump);
        out.body = trunc(peek.string(), CFG.maxBodyDump);
        out.bodyPeeked = true;
    } catch (e) {
        out.bodyErr = String(e) + ' — peekBody unavailable; the body was NOT consumed';
    }
    return out;
}

/* ---- JNI signature parsing, for the Java-side overloads ---- */
function parseSigParams(sig) {
    const inner = sig.slice(sig.indexOf('(') + 1, sig.indexOf(')'));
    const out = [];
    let i = 0;
    while (i < inner.length) {
        let dims = 0;
        while (inner[i] === '[') { dims++; i++; }
        let t;
        if (inner[i] === 'L') { const e = inner.indexOf(';', i); t = inner.slice(i + 1, e); i = e + 1; }
        else { t = inner[i]; i++; }
        out.push(t + '[]'.repeat(dims));
    }
    return out;
}
/* parseSigParams yields RAW JNI field descriptors ('Z', 'I', 'java/lang/String',
   and 'java/lang/String[]' for arrays). Java.use(...).overload() wants Java type
   NAMES, so 'Z' has to become 'boolean'. Getting this wrong makes overload()
   throw, and hookJava() would silently skip every native whose signature
   contains a primitive — which is slots 0, 20 and 21. */
const JNI_PRIMITIVE = { Z: 'boolean', B: 'byte', C: 'char', S: 'short',
                        I: 'int',    J: 'long', F: 'float', D: 'double',
                        V: 'void' };
function jtypeToJava(t) {
    if (t === null || t === undefined) return t;
    let s = String(t), dims = 0;
    while (s.slice(-2) === '[]') { dims++; s = s.slice(0, -2); }
    if (JNI_PRIMITIVE[s] !== undefined) s = JNI_PRIMITIVE[s];
    else s = s.replace(/^\//, '').replace(/^L/, '').replace(/;$/, '').replace(/\//g, '.');
    return s + '[]'.repeat(dims);
}

/* ===================================================================== *
 * 10. RPC EXPORTS
 * ===================================================================== */

rpc.exports = {
    /* what is armed, and where the file is */
    cfg() {
        return { cfg: CFG, module: MOD ? { name: MOD.name, base: MOD.base.toString(), size: MOD.size, path: MOD.path } : null,
                 sink: { path: SINK.path, fd: SINK.fd, bytesWritten: SINK.bytesWritten,
                         writeErrors: SINK.writeErrors, ringLen: SINK.ring.length, seq: SINK.seq,
                         tried: SINK.tried, uptimeMs: Date.now() - SINK.started } };
    },

    /* event counts per kind — the first thing to look at */
    stats() {
        return { byKind: SINK.byKind, total: SINK.seq,
                 distinctKeys: Object.keys(SINK.keys).length,
                 distinctEndpoints: Object.keys(SINK.endpoints).length,
                 natives: SINK.natives, detections: SINK.detections,
                 bytesWritten: SINK.bytesWritten, path: SINK.path };
    },

    /* every AES key/nonce seen, deduplicated and labelled */
    keys() { return Object.keys(SINK.keys).map(k => SINK.keys[k]); },

    /* every endpoint hit, with counts */
    endpoints() { return Object.keys(SINK.endpoints).map(u => ({ url: u, hits: SINK.endpoints[u] })); },

    /* raw event access */
    events(kind, n) {
        const lim = n || 100;
        const all = kind && kind !== '*' ? SINK.ring.filter(e => e.k === kind) : SINK.ring;
        return all.slice(-lim);
    },
    tail(n) { return SINK.ring.slice(-(n || 20)); },
    find(needle, n) {
        const lim = n || 50;
        const s = String(needle).toLowerCase();
        return SINK.ring.filter(e => { try { return JSON.stringify(e).toLowerCase().indexOf(s) >= 0; } catch (x) { return false; } }).slice(-lim);
    },

    /* the interesting subsets */
    crypto(n) { return rpc.exports.events('crypto', n || 100); },
    jni(n)    { return rpc.exports.events('jniJava', n || 100).concat(rpc.exports.events('jni', n || 100)); },
    net(n)    { return rpc.exports.events('net', n || 100); },
    gcm(n)    { return rpc.exports.events('gcm', n || 100); },
    detect(n) { return rpc.exports.events('detect', n || 100); },

    /* --- revision-5 layers ------------------------------------------------ */

    /* every Base64 blob func#21 decoded at runtime, with the layer count */
    strings(n) { return rpc.exports.events('strings', n || 200); },

    /* the decoded strings that are STILL Base64, i.e. the multi-layer blobs.
       This is how you find a 4-layer endpoint without any static analysis. */
    nestedStrings(n) {
        return rpc.exports.events('strings', 5000)
            .filter(e => e.d && e.d.fn === 'func#21' && e.d.furtherBase64LayersStillEncoded > 0)
            .slice(-(n || 100));
    },

    /* func#14 key-schedule calls: the authoritative AES-128/192/256 decision,
       with the round keys dumped AFTER the return (they do not exist before) */
    keyschedule(n) {
        return rpc.exports.events('aeslayer', 5000)
            .filter(e => e.d && e.d.fn === 'func#14').slice(-(n || 50));
    },

    /* the CBC layer: func#15 / func#16, one event per call, with the running IV */
    cbc(n) {
        return rpc.exports.events('aeslayer', 5000)
            .filter(e => e.d && (e.d.fn === 'func#15' || e.d.fn === 'func#16')).slice(-(n || 100));
    },

    /* the per-16-byte-block ECB primitives (only if CFG.captureAesLayer) */
    blocks(n) { return rpc.exports.events('aesblock', n || 200); },

    /* the live RegisterNatives table exactly as the VM received it */
    regNatives() {
        const ev = rpc.exports.events('jniOnload', 500).filter(e => e.d && e.d.entries);
        return ev.length ? ev[ev.length - 1].d : null;
    },

    /* everything JNI_OnLoad did: GetEnv, FindClass, RegisterNatives, return */
    onload(n) { return rpc.exports.events('jniOnload', n || 50); },

    /* the 21 statically decoded .rodata Base64 blobs, for cross-referencing
       against what func#21 actually decoded at runtime */
    blobs() {
        return Object.keys(B64_BLOBS).map(k => Object.assign({ storedText: k }, B64_BLOBS[k]));
    },

    /* the full slot -> wrapper -> native -> fnPtr -> func# mapping */
    jniMap() {
        return JNI_EXPECT.map(e => ({ slot: e[0], native: e[1], sig: e[2],
            fnPtr: '0x' + e[3].toString(16), func: 'func#' + e[4],
            wrapper: e[5], nameStrOff: '0x' + e[6].toString(16), role: e[7] }));
    },
    secrets() {
        return { keys: rpc.exports.keys(),
                 staticKeyMaterial: KNOWN_KEYS,
                 signaturePin: SIGNATURE_PIN_SHA256,
                 decoded: rpc.exports.events('decode', 200) };
    },

    /* re-run the anchor checks against the live mapping */
    calibrate() { return calibrate(); },

    /* write() is unbuffered, so this is informational rather than necessary */
    flush() { return { fd: SINK.fd, path: SINK.path, bytesWritten: SINK.bytesWritten,
                       writeErrors: SINK.writeErrors, pendingInRing: SINK.ring.length,
                       note: 'every event is write()n synchronously as it happens; nothing is buffered in userspace' }; },

    /* dump the whole ring as JSONL text, for piping straight into a file */
    dumpAll() { return SINK.ring.map(e => { try { return JSON.stringify(e); } catch (x) { return ''; } }).join('\n'); },

    /* forget the ring (the JSONL file is NOT touched) */
    clear() { const n = SINK.ring.length; SINK.ring = []; return { dropped: n }; },

    help() {
        return [
            'cfg()                  what is armed + where the JSONL is',
            'stats()                event counts per kind, per native, per detector',
            'keys()                 every AES key/nonce observed, deduplicated + labelled',
            'endpoints()            every URL hit, with counts',
            'events(kind, n)        last n events of one kind (crypto|key|aeslayer|aesblock|',
            '                       strings|gcm|hash|decode|jni|jniJava|jniOnload|net|json|',
            '                       javacrypto|pkg|exec|prefs|file|timing|detect|compare|',
            '                       calibrate|boot|warn)',
            'tail(n)                last n events of any kind',
            'find("order_id", n)    grep the ring',
            'crypto(n) jni(n) net(n) gcm(n) detect(n)   shortcuts',
            'strings(n)             every Base64 blob func#21 decoded at runtime',
            'nestedStrings(n)       only the ones STILL Base64 -> finds the 4-layer blobs',
            'keyschedule(n)         func#14 calls: AES-128/192/256 + the round keys',
            'cbc(n)                 func#15/#16 with the running IV, per call not per block',
            'blocks(n)              func#12/#13/#10/#11, one event per 16-byte block',
            'regNatives()           the live RegisterNatives table as the VM received it',
            'onload(n)              GetEnv / FindClass / RegisterNatives / return value',
            'blobs()                the 21 statically decoded .rodata Base64 blobs',
            'jniMap()               slot -> q.a..q.v -> native name -> fnPtr -> func#',
            'secrets()              keys + static key material + the pin + XOR decodes',
            'calibrate()            re-check every anchor against the live mapping',
            'flush()                file/byte counters',
            'dumpAll()              the whole ring as JSONL text',
            'clear()                empty the ring (the file is untouched)',
            '',
            'This script never calls retval.replace() and never calls Interceptor.replace.',
            'func#224 @0x157628 is not hooked (reachable `b .` at 0x1576ac).'
        ].join('\n');
    }
};

/* ===================================================================== *
 * 11. BOOTSTRAP
 * ===================================================================== */

/* ===================================================================== *
 * 6a. THE AES LAYER UNDER THE PUBLIC CIPHERS  (report §11.13)
 *
 * Exactly five functions in the library reference the Rijndael tables:
 *   func#10 0x2dc00   func#11 0x2eb94   func#12 0x2fdcc
 *   func#13 0x30f18   func#14 0x32158
 * and two more implement the CBC mode on top of them:
 *   func#15 0x34424 = cbc_encrypt(cbc*, pt, ct, len, cipher_idx)
 *   func#16 0x35518 = cbc_decrypt(cbc*, ct, pt, len, cipher_idx)
 *
 * Why hook these at all when #85/#94/#30/#36 already give you hex in/out:
 *   - func#85 is NOT really ECB. It routes through cbc_encrypt with a zero
 *     IV, so block 1 equals ECB and later blocks do not. The public-layer
 *     hook shows you the final hex; only this layer shows you the chaining.
 *   - func#14 is the ONE place every key length is decided, so its x3 gives
 *     you AES-128/192/256 per call without guessing from the key length.
 *   - func#36's key is a slice of its own stack frame (rev 4). Reading the
 *     skey struct AFTER func#14 returns is the only way to get the round
 *     keys, hence the onLeave dump below.
 *
 * All of it is Interceptor.attach. Nothing is replaced.
 * ===================================================================== */
function hookAesLayer() {

    /* func#14 — rijndael_setup(skey*, userkey*, unused, keylen, 16).
       The round keys only exist AFTER the return, so dump in onLeave.
       Layout (LibTomCrypt symmetric_key): Nr at +8, round keys at +0x0c,
       row stride 32 bytes, 11/13/15 rows for keylen 16/24/32. */
    try {
        Interceptor.attach(A(OFF.rijndael_setup), {
            onEnter(args) {
                this.skey = args[0];
                this.userkey = args[1];
                this.keylen = args[3].toInt32();
                this.bt = shortBt(this.context, 8);
                /* x2 is a .rodata string pointer that the function ignores —
                   captured because "ignored argument" is itself a finding */
                this.ignoredX2 = args[2].isNull() ? null : cstr(args[2], 32);
            },
            onLeave() {
                if (this.skey.isNull()) return;
                const nr = { 16: 10, 24: 12, 32: 14 }[this.keylen];
                let rows = [];
                try {
                    const nRow = nr === undefined ? 15 : nr;
                    for (let i = 0; i <= nRow && i < 15; i++)
                        rows.push(hexOf(this.skey.add(0x0c + 32 * i), 16));
                } catch (e) { rows = ['<unreadable>']; }
                const keyHex = hexOf(this.userkey, this.keylen > 0 && this.keylen <= 32 ? this.keylen : 32);
                noteKey(keyHex, this.keylen, 'func#14 userkey');
                emit('aeslayer', {
                    fn: 'func#14', off: '0x32158', op: 'rijndael_setup',
                    keylen: this.keylen, aes: this.keylen === 16 ? 'AES-128' : this.keylen === 24 ? 'AES-192' : this.keylen === 32 ? 'AES-256' : 'UNKNOWN',
                    userKeyHex: keyHex, keyLabel: keyLabel(keyHex),
                    ignoredArg2: this.ignoredX2,
                    skeyPtr: this.skey.toString(),
                    nrByte: this.skey.add(8).readU8 ? this.skey.add(8).readU8() : null,
                    roundKeys: rows, bt: this.bt
                });
            }
        });
    } catch (e) { emit('warn', { what: 'func#14 hook failed', err: String(e) }); }

    /* func#15 / func#16 — the CBC mode layer. len is x3, so one event per
       call, not per block: cheap enough to leave on. */
    [['func#15', OFF.cbc_encrypt, 'cbc_encrypt', 'pt', 'ct'],
     ['func#16', OFF.cbc_decrypt, 'cbc_decrypt', 'ct', 'pt']].forEach(spec => {
        try {
            Interceptor.attach(A(spec[1]), {
                onEnter(args) {
                    this.cbc = args[0]; this.inBuf = args[1]; this.outBuf = args[2];
                    this.len = args[3].toInt32(); this.idx = args[4].toInt32();
                    this.t0 = Date.now();
                    this.inHex = hexOf(args[1], Math.min(this.len, CFG.maxDump));
                    /* the IV lives at cbc+0x458 (LibTomCrypt symmetric_CBC.pt
                       member, which CBC uses as the running IV) */
                    this.ivBefore = hexOf(args[0].add(0x458), 16);
                },
                onLeave() {
                    emit('aeslayer', {
                        fn: spec[0], off: '0x' + spec[1].toString(16), op: spec[2],
                        cipherIdx: this.idx, len: this.len,
                        inHex: trunc(this.inHex), inLen: this.len,
                        outHex: trunc(hexOf(this.outBuf, Math.min(this.len, CFG.maxDump))),
                        ivBefore: this.ivBefore,
                        ivAfter: hexOf(this.cbc.add(0x458), 16),
                        nrByte: this.cbc.add(8).readU8 ? this.cbc.add(8).readU8() : null,
                        ms: Date.now() - this.t0
                    });
                }
            });
        } catch (e) { emit('warn', { what: spec[0] + ' hook failed', err: String(e) }); }
    });

    /* func#12/#13 (dispatchers) and func#10/#11 (Nr-specific leaves).
       ONE EVENT PER 16-BYTE BLOCK — this is the noisy layer, off by default. */
    [['func#12', OFF.ecb_enc_block, 'ECB encrypt block (dispatcher)'],
     ['func#13', OFF.ecb_dec_block, 'ECB decrypt block (dispatcher)'],
     ['func#10', OFF.ecb_enc_leaf,  'ECB encrypt leaf (Nr-specific)'],
     ['func#11', OFF.ecb_dec_leaf,  'ECB decrypt leaf (Nr-specific)']].forEach(spec => {
        try {
            Interceptor.attach(A(spec[1]), {
                onEnter(args) {
                    this.inBuf = args[0]; this.outBuf = args[1]; this.skey = args[2];
                    this.inHex = hexOf(args[0], 16);
                },
                onLeave() {
                    emit('aesblock', {
                        fn: spec[0], off: '0x' + spec[1].toString(16), op: spec[2],
                        inHex: this.inHex, outHex: hexOf(this.outBuf, 16),
                        nrByte: this.skey.add(8).readU8 ? this.skey.add(8).readU8() : null
                    });
                }
            });
        } catch (e) { emit('warn', { what: spec[0] + ' hook failed', err: String(e) }); }
    });
}

/* ===================================================================== *
 * 6b. THE STRING LAYER — func#17, func#21, func#23  (report §11.13e)
 *
 * func#17 0x35d58 = std::string(const char*)      460 B, 188 call sites
 * func#23 0x3820c = empty std::string             428 B, 371 call sites
 * func#21 0x3712c = Base64 -> std::string       3,636 B,  43 call sites,
 *                   13 callers including func#162 (anti-Frida) and
 *                   func#245 (the signature pin)
 *
 * Every detection token and every endpoint is fetched through this path, and
 * the blobs are up to FOUR Base64 layers deep (0x14eae -> "https://"). This
 * is where the runtime string picture comes from.
 *
 * func#17 and func#23 are the two hottest functions in the library. They are
 * hooked ONLY when CFG.captureStrings is on, and func#23 (the empty-string
 * constructor, 371 sites, no information content) is left out entirely.
 * ===================================================================== */
function hookStrings() {

    /* func#21: x0 = const std::string& (the Base64 text), x8 = std::string*
       sret (the decoded value). Proven at the call sites:
         0x136e1c  adrp/add x1 = 0x15db5 "L3Byb2Mvc2VsZi9tYXBz"
         0x136e24  bl func#17            -> std::string(b64 text)
         0x136e34  bl func#21            -> "/proc/self/maps"
       and func#245 at 0x16bc04 does the same with the 120-char pin at
       0x15084, twice, matching the pin's two layers. */
    try {
        Interceptor.attach(A(OFF.b64_decode_21), {
            onEnter(args) {
                this.inStr = readStd(args[0]);
                this.sret = this.context.x8;
                this.bt = shortBt(this.context, 8);
            },
            onLeave() {
                const out = readStd(this.sret);
                /* how many more Base64 layers does the OUTPUT still have?
                   That is what tells you whether this blob is 1, 2, 3 or 4
                   layers deep without any static analysis. */
                let layers = 0, probe = out;
                for (let i = 0; i < 6; i++) {
                    const d = b64decodeStrict(probe);
                    if (!d) break;
                    const t = printable(d);
                    if (!t) break;
                    probe = t; layers++;
                }
                emit('strings', {
                    fn: 'func#21', off: '0x3712c', op: 'Base64 -> std::string',
                    input: trunc(this.inStr, 512), inputLen: (this.inStr || '').length,
                    output: trunc(out, 512), outputLen: (out || '').length,
                    furtherBase64LayersStillEncoded: layers,
                    fullyDecoded: trunc(probe, 512),
                    knownBlob: B64_BLOBS[this.inStr] || null,
                    bt: this.bt
                });
            }
        });
    } catch (e) { emit('warn', { what: 'func#21 hook failed', err: String(e) }); }

    /* func#17: x0 = std::string* sret, x1 = const char*. 188 sites — this is
       how every .rodata literal becomes a std::string, so it is the single
       best place to see which encoded blob is being fetched right now. */
    try {
        Interceptor.attach(A(OFF.str_from_cstr), {
            onEnter(args) {
                this.sret = args[0];
                this.src = args[1];
                this.text = args[1].isNull() ? null : cstr(args[1], 256);
                this.srcOff = (MOD && !args[1].isNull())
                    ? args[1].sub(MOD.base).toString() : null;
            },
            onLeave() {
                if (this.text === null) return;
                const known = B64_BLOBS[this.text];
                /* Only emit for literals that matter: a known Base64 blob, or
                   anything that is not plain ASCII (XOR-0x5A encoded). Emitting
                   all 188 sites' worth of ordinary strings would drown the
                   capture file. */
                const isAscii = printable(Array.from(new Uint8Array(
                    this.src.readByteArray(Math.min(this.text.length, 64)))));
                if (!known && isAscii) return;
                emit('strings', {
                    fn: 'func#17', off: '0x35d58', op: 'std::string(const char*)',
                    srcRva: this.srcOff === null ? null : '0x' + this.srcOff,
                    text: trunc(this.text, 256), textLen: this.text.length,
                    knownBlob: known || null,
                    ascii: !!isAscii,
                    xor5aDecoded: isAscii ? null : (function (self) {
                        try {
                            const raw = new Uint8Array(self.src.readByteArray(
                                Math.min(self.text.length, 256)));
                            return trunc(printable(Array.from(xorBytes(Array.from(raw), 0x5a))) || '', 512);
                        } catch (e) { return null; }
                    })(this),
                    sretValue: trunc(readStd(this.sret), 256)
                });
            }
        });
    } catch (e) { emit('warn', { what: 'func#17 hook failed', err: String(e) }); }
}

/* ===================================================================== *
 * 6c. JNI_OnLoad's three JNI calls  (report §11.13c)
 *
 * JNI_OnLoad = func#50 @0x3e1d4 is the library's ONLY export. It makes
 * exactly three indirect JNI calls:
 *   0x3e308  (*vm)->GetEnv(vm, &env, 0x10006)                  index   6
 *   0x3e860  (*env)->FindClass(env, "com/nivaroid/…/helper/q")   index   6
 *   0x3e93c  (*env)->RegisterNatives(env, cls, 0x1b6198, 22)     index 215
 *   0x3e988  (the CFF duplicate of the RegisterNatives block)
 * and returns 0x10006. There is no dynamic Java_... lookup in the library.
 *
 * Hooking the two RegisterNatives call sites is the most robust way to get
 * the table, because at that instant x2 and w3 are live in registers and the
 * table has just been relocated — no pointer arithmetic against 0x1b6198 is
 * needed, so it keeps working if a future build moves the table.
 * ===================================================================== */
function hookJniOnload() {
    [OFF.jni_reg1, OFF.jni_reg2].forEach((site, k) => {
        try {
            Interceptor.attach(A(site), {
                onEnter(args) {
                    /* at a `blr x8` the arguments are already in x0..x3 */
                    const env = this.context.x0, cls = this.context.x1;
                    const table = this.context.x2;
                    const nMethods = this.context.x3.toInt32();
                    const entries = [];
                    for (let i = 0; i < nMethods && i < 64; i++) {
                        try {
                            const e = table.add(i * 0x18);
                            entries.push({
                                slot: i,
                                name: cstr(e.readPointer(), 64),
                                sig: cstr(e.add(8).readPointer(), 256),
                                fnPtr: e.add(16).readPointer().toString(),
                                fnPtrRva: '0x' + e.add(16).readPointer().sub(MOD.base).toString(16)
                            });
                        } catch (x) { entries.push({ slot: i, error: String(x) }); }
                    }
                    /* cross-check every entry against the static recovery */
                    let good = 0;
                    const drift = [];
                    entries.forEach(en => {
                        const exp = JNI_EXPECT[en.slot];
                        if (exp && en.name === exp[1] && en.sig === exp[2] &&
                            en.fnPtrRva === '0x' + exp[3].toString(16)) good++;
                        else if (exp) drift.push({ slot: en.slot, got: [en.name, en.fnPtrRva],
                                                   want: [exp[1], '0x' + exp[3].toString(16)] });
                    });
                    emit('jniOnload', {
                        site: '0x' + site.toString(16), which: k === 0 ? 'primary' : 'CFF duplicate',
                        op: 'RegisterNatives (JNINativeInterface index 215)',
                        env: env.toString(), clazz: cls.toString(),
                        tablePtr: table.toString(),
                        tableRva: MOD ? '0x' + table.sub(MOD.base).toString() : null,
                        nMethods: nMethods, matchesStaticRecovery: good, drift: drift,
                        entries: entries,
                        note: 'the table bytes are ZERO in the file; 66 R_AARCH64_RELATIVE relocations fill them at load time'
                    });
                }
            });
        } catch (e) { emit('warn', { what: 'RegisterNatives site 0x' + site.toString(16) + ' hook failed', err: String(e) }); }
    });

    try {
        Interceptor.attach(A(OFF.jni_findclass), {
            onEnter() {
                const p = this.context.x1;
                emit('jniOnload', { site: '0x' + OFF.jni_findclass.toString(16),
                                    op: 'FindClass (index 6)', className: cstr(p, 128) });
            }
        });
    } catch (e) {}

    try {
        Interceptor.attach(A(OFF.jni_getenv), {
            onEnter() {
                emit('jniOnload', { site: '0x' + OFF.jni_getenv.toString(16),
                                    op: 'GetEnv (index 6)',
                                    version: '0x' + this.context.x2.toInt32().toString(16),
                                    note: '0x10006 = JNI_VERSION_1_6' });
            }
        });
    } catch (e) {}

    /* and JNI_OnLoad itself, so you can see the whole thing bracket the calls */
    try {
        Interceptor.attach(A(OFF.jni_onload), {
            onEnter() { this.t0 = Date.now(); emit('jniOnload', { op: 'JNI_OnLoad enter', vm: this.context.x0.toString() }); },
            onLeave(retval) {
                emit('jniOnload', { op: 'JNI_OnLoad leave',
                                    returnedVersion: '0x' + retval.toInt32().toString(16),
                                    expected: '0x10006', ms: Date.now() - this.t0 });
            }
        });
    } catch (e) {}
}

function install() {
    const cal = calibrate();

    if (!cal.ok) {
        emit('warn', {
            what: 'CALIBRATION FAILED — this is not the build the offsets were derived from',
            drift: cal.drift, checks: cal.checks.filter(c => !c.ok),
            advice: 'captures below may be attributed to the wrong function. Fix the offsets before trusting them.'
        });
    }

    hookLibc();                                  /* safe before anything else */
    if (CFG.captureJniOnload) hookJniOnload();   /* fires once, at load        */
    if (CFG.captureDetect) hookDetection();
    if (CFG.captureCrypto) hookCrypto();
    if (CFG.captureAesLayer) hookAesLayer();     /* noisy: one event per block */
    if (CFG.captureStrings) hookStrings();
    if (CFG.captureJni)    hookJniNative();
    hookJava();

    emit('boot', {
        what: BYPASS_ON() ? 'capture ready — BYPASS MODE ON, the app is being lied to'
                        : 'capture ready',
        calibrationOk: cal.ok, jniSlotsMatching: cal.jniGood,
        file: SINK.path,
        readOnly: !BYPASS_ON(),
        bypass: BYPASS_ON() ? {
            forceReturn: Object.keys(BYPASS.forceReturn)
                             .map(k => '0x' + Number(k).toString(16)),
            spoofSignature: !!BYPASS.spoofSignature,
            hideMaps: !!BYPASS.hideMaps,
            hideSuPaths: !!BYPASS.hideSuPaths,
            fakeClock: !!BYPASS.fakeClock,
            warning: 'events captured in this mode are the app behaviour UNDER BYPASS. ' +
                     'Every bypass event is tagged kind="bypass", so bypassed and ' +
                     'unbypassed captures can never be confused after the fact.'
        } : null,
        replacedNothing: BYPASS_ON()
            ? 'BYPASS ON — detection leaves replaced at the entry; ciphers and strings still attach-only'
            : 'no Interceptor.replace and no retval.replace anywhere in this script',
        excludedOnPurpose: 'func#224 @0x157628 (reachable `b .` trap @0x1576ac)',
        tip: BYPASS_ON() ? 'rpc.exports.stats() then rpc.exports.events("bypass", 50)'
                       : 'rpc.exports.stats() then rpc.exports.keys() then rpc.exports.net(20)'
    });
}

sinkInit();

emit('boot', {
    what: 'topfollow_capture.js starting',
    pid: Process.id, arch: Process.arch, platform: Process.platform,
    frida: Frida.version, pointerSize: Process.pointerSize, pageSize: Process.pageSize,
    javaAvailable: Java.available,
    sinkPath: SINK.path, sinkTried: SINK.tried,
    mode: 'CAPTURE ONLY — no bypass, no spoofing, no hiding, no patching'
});

/* Set TOPFOLLOW_CAPTURE_NO_AUTOBOOT=1 to define everything without arming
   (that is what a Node test harness wants). */
if (typeof TOPFOLLOW_CAPTURE_NO_AUTOBOOT === 'undefined' || !TOPFOLLOW_CAPTURE_NO_AUTOBOOT) {
    waitForModule(install);
}

/* every event is write()n synchronously, so an abrupt detach loses nothing that
   already happened; closing the fd on unload is just hygiene */
try {
    if (typeof Script !== 'undefined' && Script.unload)
        Script.unload(() => { emit('boot', { what: 'unloading — closing capture file', bytesWritten: SINK.bytesWritten }); sinkClose(); });
} catch (e) {}
